package buildgates

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const devcontainerDockerfile = "build/docker/devcontainer/Dockerfile"

// dockerfileStage is one FROM ... AS name of the devcontainer Dockerfile, with
// the sources of its COPY instructions that read the build context and the
// stages its COPY --from instructions read.
type dockerfileStage struct {
	name, from string
	copies     []string
	copiesFrom []string
}

func readDockerfileStages(t *testing.T) []dockerfileStage {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(devcontainerDockerfile)))
	if err != nil {
		t.Fatalf("read the Dockerfile: %v", err)
	}
	from := regexp.MustCompile(`^FROM\s+(\S+)\s+AS\s+(\S+)\s*$`)
	var stages []dockerfileStage
	for _, line := range strings.Split(string(b), "\n") {
		if m := from.FindStringSubmatch(line); m != nil {
			stages = append(stages, dockerfileStage{name: m[2], from: m[1]})
			continue
		}
		if strings.HasPrefix(line, "FROM ") {
			t.Fatalf("a FROM without AS <stage>: %q", line)
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "COPY" {
			continue
		}
		if len(stages) == 0 {
			t.Fatalf("COPY before the first FROM: %q", line)
		}
		var args []string
		fromStage := ""
		for _, f := range fields[1:] {
			if v, ok := strings.CutPrefix(f, "--from="); ok {
				fromStage = v
			}
			if !strings.HasPrefix(f, "--") {
				args = append(args, f)
			}
		}
		s := &stages[len(stages)-1]
		if fromStage != "" {
			s.copiesFrom = append(s.copiesFrom, fromStage)
			continue
		}
		if len(args) < 2 || strings.HasSuffix(line, "\\") {
			t.Fatalf("a COPY this gate cannot read (one line, sources then destination): %q", line)
		}
		s.copies = append(s.copies, args[:len(args)-1]...)
	}
	return stages
}

// TestScriptsDevcontainer_ToolsStayOutOfTheIntegrationImage pins the stage
// shape: toolchain and integration are both FROM base, so the suite runs on
// the Go the other gates run on, and integration takes nothing from the tools
// stage or the toolchain's inputs. The suite scans its own image, and
// developer tool binaries do not ship into it.
func TestScriptsDevcontainer_ToolsStayOutOfTheIntegrationImage(t *testing.T) {
	byName := map[string]dockerfileStage{}
	for _, s := range readDockerfileStages(t) {
		byName[s.name] = s
	}
	for _, name := range []string{"toolchain", "integration"} {
		if got := byName[name].from; got != "base" {
			t.Fatalf("the %s stage is FROM %q, want base; stages: %v", name, got, byName)
		}
	}
	it := byName["integration"]
	if len(it.copiesFrom) != 0 {
		t.Fatalf("the integration stage copies from the stages %v", it.copiesFrom)
	}
	// lib.sh is the integration suite's too: coverage-gate.sh sources it.
	toolchainOnly := map[string]bool{}
	for _, name := range []string{"tools", "toolchain"} {
		for _, c := range byName[name].copies {
			toolchainOnly[c] = c != "scripts/lib.sh"
		}
	}
	for _, c := range it.copies {
		if c == "." || toolchainOnly[c] {
			t.Errorf("the integration stage COPYs %q, which carries the toolchain's inputs into the scanned image", c)
		}
	}
}

// TestScriptsDevcontainer_ToolchainTagCoversEveryInput pins that the content
// tag `make toolchain-image` prints hashes every file the tools, base and
// toolchain stages COPY from the context: an input left out would let two
// different toolchains share a tag, and lane-verify run the stale one.
func TestScriptsDevcontainer_ToolchainTagCoversEveryInput(t *testing.T) {
	root := repoRoot(t)
	want := []string{devcontainerDockerfile, devcontainerDockerfile + ".dockerignore"}
	for _, s := range readDockerfileStages(t) {
		if s.name == "integration" {
			continue
		}
		want = append(want, s.copies...)
	}
	got := toolchainTagInputs(t, root)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the toolchain tag's inputs are not the toolchain's COPY sources.\n tag hashes: %v\n COPY reads: %v", got, want)
	}
}

// toolchainTagInputs lists the files scripts/devcontainer.sh hashes into the
// toolchain tag.
func toolchainTagInputs(t *testing.T, root string) []string {
	t.Helper()
	cmd := exec.Command("sh", "scripts/devcontainer.sh", "inputs")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("devcontainer.sh inputs: %v\n%s", err, out)
	}
	return strings.Fields(string(out))
}

// TestScriptsDevcontainer_AllowlistAdmitsEveryToolchainInput pins the build
// context against the tag: every file the toolchain tag hashes, other than the
// Dockerfile and its allowlist (which BuildKit reads outside the context), is
// a COPY source, so the allowlist must admit it or the build fails with
// "not found".
func TestScriptsDevcontainer_AllowlistAdmitsEveryToolchainInput(t *testing.T) {
	for _, name := range toolchainTagInputs(t, repoRoot(t)) {
		if name == devcontainerDockerfile || name == devcontainerDockerfile+".dockerignore" {
			continue
		}
		if !dockerignoreAdmits(t, name) {
			t.Errorf("%s.dockerignore excludes %s: the toolchain tag hashes it, so the toolchain stage COPYs it, and the build cannot find it",
				devcontainerDockerfile, name)
		}
	}
}

// TestScriptsDevcontainer_TagIsContentAddressed drives `devcontainer.sh tag`
// on a copy of its inputs: the same files give the same tag wherever it runs
// from, a changed input gives another, and a missing one is refused.
func TestScriptsDevcontainer_TagIsContentAddressed(t *testing.T) {
	root := repoRoot(t)
	list := exec.Command("sh", "scripts/devcontainer.sh", "inputs")
	list.Dir = root
	out, err := list.Output()
	if err != nil {
		t.Fatalf("devcontainer.sh inputs: %v", err)
	}
	inputs := strings.Fields(string(out))

	tree := t.TempDir()
	for _, f := range append([]string{"scripts/devcontainer.sh", "scripts/lib.sh"}, inputs...) {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f)))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		p := filepath.Join(tree, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	tag := func() (string, bool) {
		t.Helper()
		cmd := exec.Command("sh", filepath.Join(tree, "scripts", "devcontainer.sh"), "tag")
		cmd.Dir = t.TempDir()
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), err == nil
	}

	first, ok := tag()
	if !ok || !regexp.MustCompile(`^go-enclave-toolchain:[0-9a-f]{12}$`).MatchString(first) {
		t.Fatalf("tag = %q (ok=%v), want go-enclave-toolchain:<12 hex>", first, ok)
	}
	if again, _ := tag(); again != first {
		t.Fatalf("the same inputs tagged %q, then %q", first, again)
	}
	pins := filepath.Join(tree, "scripts", "tool-pins.sh")
	if err := os.WriteFile(pins, []byte("GOLANGCI_VERSION=v0.0.1\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if changed, ok := tag(); !ok || changed == first {
		t.Fatalf("a changed tool-pins.sh kept the tag %q (ok=%v)", changed, ok)
	}
	if err := os.Remove(pins); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if out, ok := tag(); ok || !strings.Contains(out, "scripts/tool-pins.sh is missing") {
		t.Fatalf("tagged with an input missing (ok=%v): %s", ok, out)
	}
}

// TestScriptsDevcontainer_ITTagIsContentAddressed drives `devcontainer.sh
// it-tag` in a scratch repository: one tree gives one go-enclave-ci-it:<12 hex>
// tag, and a diff against the commit or an untracked file gives another, while
// an ignored file does not. `make -s it-image` prints the same tag.
func TestScriptsDevcontainer_ITTagIsContentAddressed(t *testing.T) {
	root := repoRoot(t)
	tree := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(tree, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	for _, f := range []string{"scripts/devcontainer.sh", "scripts/lib.sh"} {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f)))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		write(f, string(b))
	}
	write(".gitignore", "ignored.txt\n")
	write("a.txt", "one\n")
	// A hermetic git: no user or system config, a fixed identity.
	gitEnv := map[string]string{
		"GIT_CONFIG_GLOBAL":   os.DevNull,
		"GIT_CONFIG_NOSYSTEM": "1",
		"GIT_AUTHOR_NAME":     "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
		"GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "-A"}, {"commit", "-q", "-m", "tree"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = tree
		cmd.Env = layerEnv(os.Environ(), gitEnv)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	tag := func() string {
		t.Helper()
		cmd := exec.Command("sh", filepath.Join(tree, "scripts", "devcontainer.sh"), "it-tag")
		cmd.Dir = t.TempDir()
		cmd.Env = layerEnv(os.Environ(), gitEnv)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("devcontainer.sh it-tag: %v\n%s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	itTag := regexp.MustCompile(`^go-enclave-ci-it:[0-9a-f]{12}$`)

	first := tag()
	if !itTag.MatchString(first) {
		t.Fatalf("it-tag = %q, want go-enclave-ci-it:<12 hex>", first)
	}
	if again := tag(); again != first {
		t.Fatalf("one tree tagged %q, then %q", first, again)
	}
	write("a.txt", "two\n")
	if dirty := tag(); dirty == first {
		t.Fatalf("a diff against the commit kept the tag %q", dirty)
	}
	write("a.txt", "one\n")
	if back := tag(); back != first {
		t.Fatalf("the clean tree again tagged %q, want %q", back, first)
	}
	write("ignored.txt", "x\n")
	if ignored := tag(); ignored != first {
		t.Fatalf("an ignored file changed the tag to %q", ignored)
	}
	write("new.txt", "x\n")
	if untracked := tag(); untracked == first {
		t.Fatalf("an untracked file kept the tag %q", untracked)
	}

	mk := exec.Command("make", "-s", "it-image")
	mk.Dir = root
	out, err := mk.Output()
	if err != nil {
		t.Fatalf("make -s it-image: %v", err)
	}
	direct := exec.Command("sh", "scripts/devcontainer.sh", "it-tag")
	direct.Dir = root
	want, err := direct.Output()
	if err != nil {
		t.Fatalf("devcontainer.sh it-tag: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != strings.TrimSpace(string(want)) || !itTag.MatchString(got) {
		t.Fatalf("make -s it-image printed %q, want the it-tag %q", got, strings.TrimSpace(string(want)))
	}
}

// dockerignoreAdmits evaluates the devcontainer allowlist for one slash-separated
// path in the build context: the last pattern that matches decides, and a
// leading ! admits. A pattern matches the path or any of its parent
// directories (so `*` excludes everything below the root, as BuildKit does),
// segment by segment with path.Match, where a `**` segment matches zero or
// more segments. That covers every pattern the file uses: literal paths, `*`,
// `*.go`, `dir/*.go` and `dir/**/*.go`.
func dockerignoreAdmits(t *testing.T, name string) bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(devcontainerDockerfile+".dockerignore")))
	if err != nil {
		t.Fatalf("read the Dockerfile's dockerignore: %v", err)
	}
	segs := strings.Split(name, "/")
	admitted := true // no pattern matches: the file is in the context
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		negated, pattern := dockerignorePattern(line)
		for n := 1; n <= len(segs); n++ {
			ok, err := matchSegments(pattern, segs[:n])
			if err != nil {
				t.Fatalf("dockerignore pattern %q: %v", line, err)
			}
			if ok {
				admitted = negated
				break
			}
		}
	}
	return admitted
}

// dockerignorePattern parses one non-comment dockerignore line as Docker does:
// a leading ! negates, the rest is cleaned (so a leading ./ and a trailing /
// change nothing), a leading / is dropped, and the result is split into
// segments.
func dockerignorePattern(line string) (negated bool, pattern []string) {
	negated = strings.HasPrefix(line, "!")
	p := path.Clean(strings.TrimPrefix(line, "!"))
	if len(p) > 1 && p[0] == '/' {
		p = p[1:]
	}
	return negated, strings.Split(p, "/")
}

// matchSegments matches a split dockerignore pattern against a split path:
// path.Match per segment, and a `**` segment matches zero or more segments.
func matchSegments(pattern, segs []string) (bool, error) {
	if len(pattern) == 0 {
		return len(segs) == 0, nil
	}
	if pattern[0] == "**" {
		for i := 0; i <= len(segs); i++ {
			if ok, err := matchSegments(pattern[1:], segs[i:]); err != nil || ok {
				return ok, err
			}
		}
		return false, nil
	}
	if len(segs) == 0 {
		return false, nil
	}
	ok, err := path.Match(pattern[0], segs[0])
	if err != nil || !ok {
		return false, err
	}
	return matchSegments(pattern[1:], segs[1:])
}

// TestScriptsDevcontainer_UsernsImageCarriesTheRootTests pins the cause of a
// `userns` service that ran no tests: the allowlist excluded the root
// package's *_test.go, so `go test -tags=userns .` printed "[no test files]".
// Every root .go file, tests included, must arrive in the build context; the
// userns test uses helpers from the other root test files.
func TestScriptsDevcontainer_UsernsImageCarriesTheRootTests(t *testing.T) {
	root := repoRoot(t)
	files, err := filepath.Glob(filepath.Join(root, "*.go"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	sawUserns := false
	for _, f := range files {
		name := filepath.Base(f)
		if name == "memlock_userns_linux_test.go" {
			sawUserns = true
		}
		if !dockerignoreAdmits(t, name) {
			t.Errorf("%s.dockerignore excludes %s: the integration image, and the userns service built from it, would not carry it",
				devcontainerDockerfile, name)
		}
	}
	if !sawUserns {
		t.Fatal("memlock_userns_linux_test.go is not in the root package: the userns gate has nothing to run")
	}
}

// TestScriptsDevcontainer_UsernsServiceRunsItsTest pins the wiring around the
// image: the compose service builds the integration stage, the Dockerfile
// proves at build time that the tagged test files compile, the script runs the
// test with -tags=userns, anchored, from the root package, and still fails
// when nothing ran, and `make integration-test-userns` runs that script.
func TestScriptsDevcontainer_UsernsServiceRunsItsTest(t *testing.T) {
	root := repoRoot(t)
	read := func(rel string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return string(b)
	}
	const testName = "TestMemlockRLimit_EnforcedInsideAnUnprivilegedUserNamespace"

	test := read("memlock_userns_linux_test.go")
	if !strings.Contains(test, "func "+testName+"(") {
		t.Errorf("memlock_userns_linux_test.go no longer defines %s", testName)
	}
	if !strings.Contains(test, "//go:build userns") {
		t.Error("memlock_userns_linux_test.go is not built with the userns tag the script passes")
	}
	if !regexp.MustCompile(`(?m)^RUN go vet -tags=userns \.\s*$`).MatchString(read(devcontainerDockerfile)) {
		t.Error("the Dockerfile does not `go vet -tags=userns .` in the integration stage: a context without the root tests would build")
	}
	if !regexp.MustCompile(`(?m)^  userns:\n    <<: \*integration_service\n`).MatchString(read("build/docker/devcontainer/compose.yaml")) {
		t.Error("compose.yaml's userns service is not the integration service (the image that carries the root tests)")
	}

	script := read("scripts/userns-test.sh")
	for _, want := range []string{
		`test_name=` + testName,
		`go test -tags=userns `,
		`-run "^${test_name}\$" .`,
		`grep -q -- "^--- PASS: $test_name " "$out" || die "$test_name did not pass: nothing ran"`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("scripts/userns-test.sh lacks %q", want)
		}
	}

	if !regexp.MustCompile(`(?m)^integration-test-userns:\n\t@sh scripts/userns-test\.sh$`).MatchString(read("Makefile")) {
		t.Error("the Makefile's integration-test-userns does not run scripts/userns-test.sh")
	}
}
