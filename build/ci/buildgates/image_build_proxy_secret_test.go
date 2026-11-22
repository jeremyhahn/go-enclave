package buildgates

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The image build's module proxy is a BuildKit secret, never a build
// argument: Docker records a build argument a RUN reads in the image
// history, and ci.yml's image-history check refuses an image whose history
// holds a private address. The secret is mounted for the RUN that reads it
// and leaves no trace in the image or its metadata.
const (
	proxySecretID   = "goproxy"
	proxySecretFlag = `--secret id=goproxy,env=GO_BUILD_PROXY`
	proxySecretRun  = `--mount=type=secret,id=goproxy`
)

var (
	proxyBuildArgDecl = regexp.MustCompile(`(?m)^\s*ARG\s+GO_BUILD_PROXY\b`)
	proxyBuildArgFlag = regexp.MustCompile(`--build-arg\s+"?GO_BUILD_PROXY`)
)

// dockerfileInstructions joins each instruction's continuation lines and
// drops comment lines, so one entry is one instruction.
func dockerfileInstructions(src string) []string {
	var out []string
	var cur strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if s, ok := strings.CutSuffix(strings.TrimRight(line, " \t"), `\`); ok {
			cur.WriteString(s)
			cur.WriteString(" ")
			continue
		}
		cur.WriteString(line)
		if strings.TrimSpace(cur.String()) != "" {
			out = append(out, strings.TrimSpace(cur.String()))
		}
		cur.Reset()
	}
	return out
}

// dockerfileProxyViolations lists what is wrong with how the toolchain
// Dockerfile takes the module proxy.
func dockerfileProxyViolations(src string) []string {
	var bad []string
	if proxyBuildArgDecl.MatchString(src) {
		bad = append(bad, "declares ARG GO_BUILD_PROXY; the proxy is the goproxy BuildKit secret")
	}
	mounts := 0
	for _, ins := range dockerfileInstructions(src) {
		if strings.Contains(ins, "GO_BUILD_PROXY") {
			bad = append(bad, "an instruction reads GO_BUILD_PROXY: "+ins)
		}
		if !strings.HasPrefix(ins, "RUN ") {
			continue
		}
		mounted := strings.Contains(ins, proxySecretRun)
		if mounted {
			mounts++
		}
		if strings.Contains(ins, "GOPROXY=") && !strings.Contains(ins, "GOPROXY=off") && !mounted {
			bad = append(bad, "a RUN sets GOPROXY without mounting the goproxy secret: "+ins)
		}
	}
	if mounts == 0 {
		bad = append(bad, "no RUN mounts the goproxy secret ("+proxySecretRun+")")
	}
	return bad
}

// buildScriptProxyViolations lists what is wrong with how a build path (the
// Makefile's docker-build-toolchain recipe or scripts/devcontainer.sh)
// passes the module proxy to docker build.
func buildScriptProxyViolations(src string) []string {
	var bad []string
	if proxyBuildArgFlag.MatchString(src) {
		bad = append(bad, "passes GO_BUILD_PROXY as --build-arg; Docker records it in the image history")
	}
	if !strings.Contains(src, proxySecretFlag) {
		bad = append(bad, "does not pass GO_BUILD_PROXY as the BuildKit secret ("+proxySecretFlag+")")
	}
	return bad
}

func toolchainRecipe(t *testing.T, mk string) string {
	t.Helper()
	_, rest, ok := strings.Cut(mk, "\ndocker-build-toolchain:\n")
	if !ok {
		t.Fatal("Makefile: no docker-build-toolchain target")
	}
	var recipe []string
	for _, line := range strings.Split(rest, "\n") {
		if !strings.HasPrefix(line, "\t") {
			break
		}
		recipe = append(recipe, line)
	}
	return strings.Join(recipe, "\n")
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(repoRoot(t), rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(src)
}

// composeBuildArgProxy matches a module proxy among the build args of a
// compose file's build: section.
var composeBuildArgProxy = regexp.MustCompile(`(?m)^\s+-?\s*"?(GO_BUILD_PROXY|GOPROXY)\b[^\n]*$`)

// composeBuildArgs returns the lines of every `args:` map under a `build:`
// key in a compose file.
func composeBuildArgs(src string) string {
	var out []string
	lines := strings.Split(src, "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) != "args:" {
			continue
		}
		ind := len(l) - len(strings.TrimLeft(l, " "))
		for _, m := range lines[i+1:] {
			if strings.TrimSpace(m) == "" || strings.HasPrefix(strings.TrimSpace(m), "#") {
				continue
			}
			if len(m)-len(strings.TrimLeft(m, " ")) <= ind {
				break
			}
			out = append(out, m)
		}
	}
	return strings.Join(out, "\n")
}

// proxyTextViolations lists where the workflow or the compose file still
// passes, or says it passes, the module proxy as a build argument.
func proxyTextViolations(ci, compose string) []string {
	var bad []string
	if proxyBuildArgFlag.MatchString(ci) {
		bad = append(bad, ".github/workflows/ci.yml says the image build takes GO_BUILD_PROXY as --build-arg; it is the goproxy BuildKit secret")
	}
	if composeBuildArgProxy.MatchString(composeBuildArgs(compose)) {
		bad = append(bad, "build/docker/devcontainer/compose.yaml passes a module proxy as a build argument; Docker records it in the image history")
	}
	return bad
}

func TestNoBuildTakesTheProxyAsABuildArg(t *testing.T) {
	ci := readRepoFile(t, ".github/workflows/ci.yml")
	compose := readRepoFile(t, "build/docker/devcontainer/compose.yaml")
	for _, b := range proxyTextViolations(ci, compose) {
		t.Error(b)
	}
	if composeBuildArgs(compose) == "" {
		t.Error("compose.yaml: the parse found no build args; the check no longer reads the file")
	}
}

func TestNoBuildTakesTheProxyAsABuildArg_RefusesWhatItMustRefuse(t *testing.T) {
	good := "services:\n  it:\n    build:\n      args:\n        APK_INDEX_SUM: ${APK_INDEX_SUM:-}\n    environment:\n      GOPROXY: \"off\"\n"
	if b := proxyTextViolations("# the proxy is the goproxy secret\n", good); len(b) != 0 {
		t.Fatalf("the good shape is refused: %v", b)
	}
	for _, c := range []struct{ name, ci, compose string }{
		{"comment names the build arg", "# (`--build-arg \"GO_BUILD_PROXY=$(GO_BUILD_PROXY)\"`)\n", good},
		{"compose map arg", "", strings.Replace(good, "        APK", "        GO_BUILD_PROXY: ${GO_BUILD_PROXY:-}\n        APK", 1)},
		{"compose list arg", "", strings.Replace(good, "        APK_INDEX_SUM: ${APK_INDEX_SUM:-}", "        - GOPROXY=${GOPROXY}", 1)},
	} {
		if len(proxyTextViolations(c.ci, c.compose)) == 0 {
			t.Errorf("%s: passes", c.name)
		}
	}
}

func TestImageBuildProxyIsABuildKitSecret(t *testing.T) {
	const dockerfile = "build/docker/devcontainer/Dockerfile"
	for _, b := range dockerfileProxyViolations(readRepoFile(t, dockerfile)) {
		t.Errorf("%s: %s", dockerfile, b)
	}
	for _, b := range buildScriptProxyViolations(toolchainRecipe(t, readRepoFile(t, "Makefile"))) {
		t.Errorf("Makefile docker-build-toolchain: %s", b)
	}
	for _, b := range buildScriptProxyViolations(readRepoFile(t, "scripts/devcontainer.sh")) {
		t.Errorf("scripts/devcontainer.sh: %s", b)
	}
}

// TestImageBuildProxyIsABuildKitSecret_RefusesWhatItMustRefuse pins the
// check against edits that bring the build argument back.
func TestImageBuildProxyIsABuildKitSecret_RefusesWhatItMustRefuse(t *testing.T) {
	df := `FROM x AS tools
RUN --mount=type=secret,id=goproxy set -eu; \
    GOPROXY="$proxy" go mod download
ENV GOPROXY=off
`
	if b := dockerfileProxyViolations(df); len(b) != 0 {
		t.Fatalf("a good Dockerfile is refused: %v", b)
	}
	for _, tc := range []struct{ name, src string }{
		{"argument declared", "ARG GO_BUILD_PROXY\n" + df},
		{"argument read", strings.Replace(df, `"$proxy"`, `"$GO_BUILD_PROXY"`, 1)},
		{"secret not mounted", strings.Replace(df, proxySecretRun+" ", "", 1)},
		{"other secret", strings.Replace(df, "id="+proxySecretID, "id=other", 1)},
	} {
		if len(dockerfileProxyViolations(tc.src)) == 0 {
			t.Errorf("Dockerfile %s: no violation; want a refusal", tc.name)
		}
	}
	sh := `[ -z "${GO_BUILD_PROXY:-}" ] || set -- "$@" ` + proxySecretFlag
	if b := buildScriptProxyViolations(sh); len(b) != 0 {
		t.Fatalf("a good build path is refused: %v", b)
	}
	for _, tc := range []struct{ name, src string }{
		{"build argument", sh + "\nset -- \"$@\" --build-arg \"GO_BUILD_PROXY=$GO_BUILD_PROXY\""},
		{"bare build argument", sh + "\nset -- \"$@\" --build-arg GO_BUILD_PROXY"},
		{"secret dropped", strings.Replace(sh, proxySecretFlag, "--label x=y", 1)},
	} {
		if len(buildScriptProxyViolations(tc.src)) == 0 {
			t.Errorf("build path %s: no violation; want a refusal", tc.name)
		}
	}
}
