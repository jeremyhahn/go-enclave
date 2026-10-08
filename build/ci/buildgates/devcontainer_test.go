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
	cmd := exec.Command("sh", "scripts/devcontainer.sh", "inputs")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("devcontainer.sh inputs: %v\n%s", err, out)
	}
	got := strings.Fields(string(out))
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the toolchain tag's inputs are not the toolchain's COPY sources.\n tag hashes: %v\n COPY reads: %v", got, want)
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

// dockerignoreAdmits evaluates the devcontainer allowlist for one file at the
// root of the build context: the last pattern that matches decides, and a
// leading ! admits. Root-level names are all the userns gate needs.
func dockerignoreAdmits(t *testing.T, name string) bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(devcontainerDockerfile+".dockerignore")))
	if err != nil {
		t.Fatalf("read the Dockerfile's dockerignore: %v", err)
	}
	admitted := true // no pattern matches: the file is in the context
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		negated := strings.HasPrefix(line, "!")
		pattern := strings.TrimPrefix(line, "!")
		if ok, err := path.Match(pattern, name); err != nil {
			t.Fatalf("dockerignore pattern %q: %v", line, err)
		} else if ok {
			admitted = negated
		}
	}
	return admitted
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
