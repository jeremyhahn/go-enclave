package buildgates

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// The toolchain image build fetches backends/armtrustzone's modules, whose
// root module is public (#293): the jobs run on GitHub-hosted runners, which
// carry no GOPROXY, so each make docker-build passes the empty inherited
// GOPROXY as GO_BUILD_PROXY and the Dockerfile's default public proxy serves
// the build. No workflow sets the module variables or rewrites module URLs,
// and no forge credential reaches the build as the gomodauth secret.
//
// toolchainBuildMakeCall is the same call for the toolchain image alone,
// which the lint and lint-gates jobs build (#277); it passes the same proxy.
const (
	imageBuildRunner       = hostedRunner
	imageBuildMakeCall     = `make docker-build GO_BUILD_PROXY="${GOPROXY:-}"`
	toolchainBuildMakeCall = `make docker-build-toolchain GO_BUILD_PROXY="${GOPROXY:-}"`
)

// hostedRunner is the one runner label every job in hostedWorkflows takes;
// the self-hosted pools serve only the code review.
const hostedRunner = "ubuntu-latest"

// goEnvSet matches a workflow line that sets one of the module variables, as
// an env: key or a shell assignment or export.
var goEnvSet = regexp.MustCompile(`^\s*(?:-\s*)?(?:GOPROXY|GOPRIVATE|GONOPROXY|GONOSUMDB)\s*:|(?:^|[\s;&|(])(?:GOPROXY|GOPRIVATE|GONOPROXY|GONOSUMDB)=`)

var imageBuildWorkflows = []string{".github/workflows/ci.yml", ".github/workflows/release.yml"}

var hostedWorkflows = []string{".github/workflows/ci.yml", ".github/workflows/release.yml"}

// hostedRunnerViolations lists every job in one workflow whose runs-on is
// not the GitHub-hosted runner.
func hostedRunnerViolations(src []byte) ([]string, error) {
	var wf proxyWorkflow
	if err := yaml.Unmarshal(src, &wf); err != nil {
		return nil, err
	}
	var bad []string
	for name, job := range wf.Jobs {
		if job.RunsOn != hostedRunner {
			bad = append(bad, fmt.Sprintf("job %s: runs-on %v, want %s", name, job.RunsOn, hostedRunner))
		}
	}
	if len(wf.Jobs) == 0 {
		bad = append(bad, "no jobs; the check would check nothing")
	}
	slices.Sort(bad)
	return bad, nil
}

func TestEveryJobRunsOnAHostedRunner(t *testing.T) {
	for _, f := range hostedWorkflows {
		src, err := os.ReadFile(filepath.Join(repoRoot(t), f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		bad, err := hostedRunnerViolations(src)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, b := range bad {
			t.Errorf("%s: %s", f, b)
		}
	}
}

// TestEveryJobRunsOnAHostedRunner_RefusesWhatItMustRefuse pins the check
// against edits of the real workflows.
func TestEveryJobRunsOnAHostedRunner_RefusesWhatItMustRefuse(t *testing.T) {
	for _, f := range hostedWorkflows {
		src, err := os.ReadFile(filepath.Join(repoRoot(t), f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		wf := string(src)
		for _, tc := range []struct{ name, new string }{
			{"job on a self-hosted label", "runs-on: bigdisk\n"},
			{"job on a server_url choice", "runs-on: ${{ github.server_url == 'https://github.com' && 'ubuntu-latest' || 'batch' }}\n"},
		} {
			t.Run(filepath.Base(f)+"/"+tc.name, func(t *testing.T) {
				old := "runs-on: " + hostedRunner + "\n"
				i := strings.Index(wf, old)
				if i < 0 {
					t.Fatalf("%s no longer contains %q; update this case", f, old)
				}
				bad, err := hostedRunnerViolations([]byte(wf[:i] + tc.new + wf[i+len(old):]))
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				if len(bad) == 0 {
					t.Fatal("no violation; want a refusal")
				}
			})
		}
	}
}

type proxyWorkflow struct {
	Jobs map[string]struct {
		RunsOn any `yaml:"runs-on"`
		Steps  []struct {
			Env map[string]any `yaml:"env"`
			Run string         `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// imageBuildProxyViolations lists what in one workflow would keep the image
// build off the hosted runner or its default module proxy.
func imageBuildProxyViolations(src []byte) ([]string, error) {
	var bad []string
	if strings.Contains(string(src), "gomodauth") {
		bad = append(bad, "names gomodauth; the image build takes GO_BUILD_PROXY, not the forge credentials")
	}
	if strings.Contains(string(src), "vars.GO_BUILD_PROXY") {
		bad = append(bad, "names vars.GO_BUILD_PROXY; the proxy comes from the inherited GOPROXY, not a repository variable")
	}
	for i, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if goEnvSet.MatchString(line) {
			bad = append(bad, fmt.Sprintf("line %d: %q sets a module variable; the image build takes the Dockerfile's default proxy", i+1, strings.TrimSpace(line)))
		}
		if strings.Contains(line, "insteadOf") {
			bad = append(bad, fmt.Sprintf("line %d: %q rewrites module URLs; the public module proxy serves the modules", i+1, strings.TrimSpace(line)))
		}
	}
	var wf proxyWorkflow
	if err := yaml.Unmarshal(src, &wf); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(wf.Jobs))
	for name := range wf.Jobs {
		names = append(names, name)
	}
	slices.Sort(names)
	builds := 0
	for _, name := range names {
		job := wf.Jobs[name]
		for _, st := range job.Steps {
			if !strings.Contains(st.Run, "make docker-build") {
				continue
			}
			builds++
			if job.RunsOn != imageBuildRunner {
				bad = append(bad, fmt.Sprintf("job %s: builds the image on runs-on %v, want %s", name, job.RunsOn, imageBuildRunner))
			}
			for _, line := range strings.Split(st.Run, "\n") {
				if strings.Contains(line, "make docker-build") && !strings.Contains(line, imageBuildMakeCall) && !strings.Contains(line, toolchainBuildMakeCall) {
					bad = append(bad, fmt.Sprintf("job %s: %q does not pass GO_BUILD_PROXY; want %s or %s", name, strings.TrimSpace(line), imageBuildMakeCall, toolchainBuildMakeCall))
				}
			}
		}
	}
	if builds == 0 {
		bad = append(bad, "no step runs make docker-build; the check would check nothing")
	}
	return bad, nil
}

func TestImageBuildUsesTheModuleProxy(t *testing.T) {
	for _, f := range imageBuildWorkflows {
		src, err := os.ReadFile(filepath.Join(repoRoot(t), f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		bad, err := imageBuildProxyViolations(src)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, b := range bad {
			t.Errorf("%s: %s", f, b)
		}
	}
}

// TestImageBuildUsesTheModuleProxy_RefusesAToolchainBuildWithoutTheProxy pins
// the check on the toolchain-only build of ci.yml's lint and lint-gates jobs
// (#277): the call without GO_BUILD_PROXY, or with another proxy, is refused.
func TestImageBuildUsesTheModuleProxy_RefusesAToolchainBuildWithoutTheProxy(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), ".github/workflows/ci.yml"))
	if err != nil {
		t.Fatalf("read ci.yml: %v", err)
	}
	wf := string(src)
	if !strings.Contains(wf, toolchainBuildMakeCall) {
		t.Fatalf("ci.yml no longer contains %q; update this test", toolchainBuildMakeCall)
	}
	for _, repl := range []string{"make docker-build-toolchain", `make docker-build-toolchain GO_BUILD_PROXY="${{ vars.GO_BUILD_PROXY }}"`} {
		bad, err := imageBuildProxyViolations([]byte(strings.ReplaceAll(wf, toolchainBuildMakeCall, repl)))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if len(bad) == 0 {
			t.Errorf("%q: no violation; want a refusal", repl)
		}
	}
}

// toolchainTargetViolations lists what is wrong with the Makefile's
// docker-build-toolchain recipe (#277): it builds the toolchain stage alone
// the way `scripts/devcontainer.sh build` builds it, with GO_BUILD_PROXY as a
// build argument when it is set and with no forge credential.
func toolchainTargetViolations(mk string) []string {
	_, rest, ok := strings.Cut(mk, "\ndocker-build-toolchain:\n")
	if !ok {
		return []string{"no docker-build-toolchain target"}
	}
	var recipe []string
	for _, line := range strings.Split(rest, "\n") {
		if !strings.HasPrefix(line, "\t") {
			break
		}
		recipe = append(recipe, line)
	}
	r := strings.Join(recipe, "\n")
	var bad []string
	if !strings.Contains(r, "--target toolchain") {
		bad = append(bad, "the recipe does not build the toolchain stage (--target toolchain)")
	}
	if !strings.Contains(r, `if [ -n "$${GO_BUILD_PROXY:-}" ]; then set -- "$$@" --build-arg "GO_BUILD_PROXY=$$GO_BUILD_PROXY"; fi`) {
		bad = append(bad, "the recipe does not pass a set GO_BUILD_PROXY as a build argument")
	}
	for _, s := range []string{"gomodauth", "--secret", "MODULE_ENV_FILE"} {
		if strings.Contains(r, s) {
			bad = append(bad, fmt.Sprintf("the recipe names %s; the image build takes GO_BUILD_PROXY, not the forge credentials", s))
		}
	}
	return bad
}

func TestToolchainBuildTargetUsesTheModuleProxy(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	mk := string(src)
	for _, b := range toolchainTargetViolations(mk) {
		t.Errorf("Makefile: %s", b)
	}
	for _, tc := range []struct{ name, old, new string }{
		{"proxy dropped", `--build-arg "GO_BUILD_PROXY=$$GO_BUILD_PROXY"`, `--label x=y`},
		{"credential staged again", "\ndocker-build-toolchain:\n", "\ndocker-build-toolchain:\n\t@true --secret id=gomodauth\n"},
		{"target renamed away", "\ndocker-build-toolchain:\n", "\ndocker-build-tools:\n"},
	} {
		if !strings.Contains(mk, tc.old) {
			t.Errorf("%s: the Makefile no longer contains %q; update this case", tc.name, tc.old)
			continue
		}
		if len(toolchainTargetViolations(strings.Replace(mk, tc.old, tc.new, 1))) == 0 {
			t.Errorf("%s: no violation; want a refusal", tc.name)
		}
	}
}

// TestImageBuildUsesTheModuleProxy_RefusesWhatItMustRefuse pins the check
// against edits of the real workflows.
func TestImageBuildUsesTheModuleProxy_RefusesWhatItMustRefuse(t *testing.T) {
	for _, f := range imageBuildWorkflows {
		src, err := os.ReadFile(filepath.Join(repoRoot(t), f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		wf := string(src)
		for _, tc := range []struct{ name, old, new string }{
			{"gomodauth staged again", "      - name: ", "      - name: gomodauth\n        run: \"true\"\n      - name: "},
			{"proxy from the repository variable", imageBuildMakeCall, `make docker-build GO_BUILD_PROXY="${{ vars.GO_BUILD_PROXY }}"`},
			{"proxy from a secret", imageBuildMakeCall, `make docker-build GO_BUILD_PROXY="${{ secrets.GO_BUILD_PROXY }}"`},
			{"GOPROXY set as an env key", "      - name: ", "      - name: x\n        env:\n          GOPROXY: direct\n        run: \"true\"\n      - name: "},
			{"GOPRIVATE set as an env key", "      - name: ", "      - name: x\n        env:\n          GOPRIVATE: example.com/*\n        run: \"true\"\n      - name: "},
			{"GONOPROXY set in the shell", "      - name: ", "      - name: x\n        run: GONOPROXY=none go mod download\n      - name: "},
			{"GONOSUMDB exported", "      - name: ", "      - name: x\n        run: export GONOSUMDB=example.com/*\n      - name: "},
			{"url insteadOf rewrite", "      - name: ", "      - name: x\n        run: git config --global url.https://example.com/.insteadOf https://github.com/\n      - name: "},
			{"make call drops the proxy", imageBuildMakeCall, "make docker-build"},
			{"image job on a self-hosted label", "runs-on: " + imageBuildRunner + "\n", "runs-on: bigdisk\n"},
			{"image job back on the server_url choice", "runs-on: " + imageBuildRunner + "\n", "runs-on: ${{ github.server_url == 'https://github.com' && 'ubuntu-latest' || 'bigdisk' }}\n"},
		} {
			t.Run(filepath.Base(f)+"/"+tc.name, func(t *testing.T) {
				if !strings.Contains(wf, tc.old) {
					t.Fatalf("%s no longer contains %q; update this case", f, tc.old)
				}
				bad, err := imageBuildProxyViolations([]byte(strings.ReplaceAll(wf, tc.old, tc.new)))
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				if len(bad) == 0 {
					t.Fatal("no violation; want a refusal")
				}
			})
		}
	}
}
