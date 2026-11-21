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
	imageBuildMakeCall     = `make docker-build GO_BUILD_PROXY="${GOPROXY:-}"`
	toolchainBuildMakeCall = `make docker-build-toolchain GO_BUILD_PROXY="${GOPROXY:-}"`
)

// hostedRunner is the runner label every job in hostedWorkflows takes unless
// templateRunners names the job: no self-hosted label, no label list and no
// expression that picks a runner by event.
const hostedRunner = "ubuntu-latest"

// The runs-on expressions of the CI template's own jobs (v1.48, v1.49). On
// github.com preflight picks the runner: GitHub-hosted, or the bigdisk pool
// when the hosted pool is full; off github.com each takes its forge label.
const (
	preflightRunner = `${{ github.server_url == 'https://github.com' && fromJSON(vars.CI_PREFLIGHT_RUNS_ON || '["self-hosted","linux","x64","bigdisk"]') || 'ubuntu-latest' }}`
	dockerRunner    = `${{ github.server_url == 'https://github.com' && fromJSON(needs.preflight.outputs.runner_docker) || 'bigdisk' }}`
	gateRunner      = `${{ github.server_url == 'https://github.com' && fromJSON(needs.preflight.outputs.runner || '"ubuntu-latest"') || 'ci-gate' }}`
	// releaseRunner is publish-images' label list; its if runs it on
	// github.com only when RELEASE_RUNNER is true (ci_tiers_test.go).
	releaseRunner = "[self-hosted linux x64 release]"
)

// templateRunners names, per workflow, the jobs that take the template's
// runs-on rather than hostedRunner, each with the one value it must have.
var templateRunners = map[string]map[string]string{
	".github/workflows/ci.yml": {
		"preflight": preflightRunner, "ci-gate": gateRunner, "publish-images": releaseRunner,
		"lint": dockerRunner, "lint-gates": dockerRunner, "image": dockerRunner,
		"integration": dockerRunner, "soak": dockerRunner,
	},
}

// wantRunsOn is the one runs-on a job of a workflow whose template jobs are
// runners may take.
func wantRunsOn(runners map[string]string, job string) string {
	if r, ok := runners[job]; ok {
		return r
	}
	return hostedRunner
}

// goEnvSet matches a workflow line that sets one of the module variables, as
// an env: key or a shell assignment or export.
var goEnvSet = regexp.MustCompile(`^\s*(?:-\s*)?(?:GOPROXY|GOPRIVATE|GONOPROXY|GONOSUMDB)\s*:|(?:^|[\s;&|(])(?:GOPROXY|GOPRIVATE|GONOPROXY|GONOSUMDB)=`)

var imageBuildWorkflows = []string{".github/workflows/ci.yml", ".github/workflows/release.yml"}

var hostedWorkflows = []string{".github/workflows/ci.yml", ".github/workflows/release.yml"}

// hostedRunnerViolations lists every job in one workflow whose runs-on is
// not the GitHub-hosted runner, or for a job runners names, not that value.
func hostedRunnerViolations(src []byte, runners map[string]string) ([]string, error) {
	var wf proxyWorkflow
	if err := yaml.Unmarshal(src, &wf); err != nil {
		return nil, err
	}
	var bad []string
	for name, job := range wf.Jobs {
		if want := wantRunsOn(runners, name); fmt.Sprint(job.RunsOn) != want {
			bad = append(bad, fmt.Sprintf("job %s: runs-on %v, want %s", name, job.RunsOn, want))
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
		bad, err := hostedRunnerViolations(src, templateRunners[f])
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
			{"job on a self-hosted label", "runs-on: self-hosted\n"},
			{"job on the event-picked pool", "runs-on: " + poolRunner + "\n"},
			{"job on a server_url choice", "runs-on: ${{ github.server_url == 'https://github.com' && 'ubuntu-latest' || 'batch' }}\n"},
		} {
			t.Run(filepath.Base(f)+"/"+tc.name, func(t *testing.T) {
				old := "runs-on: " + hostedRunner + "\n"
				i := strings.Index(wf, old)
				if i < 0 {
					t.Fatalf("%s no longer contains %q; update this case", f, old)
				}
				bad, err := hostedRunnerViolations([]byte(wf[:i]+tc.new+wf[i+len(old):]), templateRunners[f])
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

// TestEveryJobRunsOnAHostedRunner_RefusesATemplateJobOffItsRunner pins the
// template jobs of ci.yml to their one runs-on each: another label, the
// event-picked pool or another job's expression is refused.
func TestEveryJobRunsOnAHostedRunner_RefusesATemplateJobOffItsRunner(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), ciWorkflowFile))
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflowFile, err)
	}
	wf := string(src)
	for _, tc := range []struct{ name, old, new string }{
		{"preflight on a bare self-hosted label", preflightRunner, "self-hosted"},
		{"preflight on the docker runner", preflightRunner, dockerRunner},
		{"image jobs on the pool", dockerRunner, poolRunner},
		{"image jobs on a bare self-hosted label", dockerRunner, "self-hosted"},
		{"image jobs on the hosted label", dockerRunner, hostedRunner},
		{"gate on the docker runner", gateRunner, dockerRunner},
		{"publish-images off the release label", "[self-hosted, linux, x64, release]", "[self-hosted, linux, x64]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(wf, tc.old) {
				t.Fatalf("%s no longer contains %q; update this case", ciWorkflowFile, tc.old)
			}
			bad, err := hostedRunnerViolations([]byte(strings.ReplaceAll(wf, tc.old, tc.new)), templateRunners[ciWorkflowFile])
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(bad) == 0 {
				t.Fatal("no violation; want a refusal")
			}
		})
	}
}

// poolRunner is the event-picked self-hosted form ci.yml's lint and
// lint-gates jobs once took: the check refuses it on every job.
const poolRunner = `${{ ((github.event_name == 'push' && github.ref == 'refs/heads/main') || (github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository)) && fromJSON('["self-hosted","linux","x64"]') || 'ubuntu-latest' }}`

// TestEveryJobRunsOnAHostedRunner_NoPoolException pins that no job, lint and
// lint-gates included, may take a self-hosted runner in any form.
func TestEveryJobRunsOnAHostedRunner_NoPoolException(t *testing.T) {
	workflow := func(lint, lintGates, image any) []byte {
		src, err := yaml.Marshal(map[string]any{"jobs": map[string]any{
			"lint":       map[string]any{"runs-on": lint},
			"lint-gates": map[string]any{"runs-on": lintGates},
			"image":      map[string]any{"runs-on": image},
		}})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return src
	}
	for _, tc := range []struct {
		name                   string
		lint, lintGates, image any
		want                   []string
	}{
		{"every job hosted", hostedRunner, hostedRunner, hostedRunner, nil},
		{"lint on the pool", poolRunner, hostedRunner, hostedRunner, []string{"job lint:"}},
		{"lint-gates on the pool", hostedRunner, poolRunner, hostedRunner, []string{"job lint-gates:"}},
		{"lint and lint-gates on the pool", poolRunner, poolRunner, hostedRunner, []string{"job lint-gates:", "job lint:"}},
		{"another job on the pool", hostedRunner, hostedRunner, poolRunner, []string{"job image:"}},
		{"bare self-hosted label", "self-hosted", hostedRunner, hostedRunner, []string{"job lint:"}},
		{"self-hosted label list", []any{"self-hosted", "linux", "x64"}, hostedRunner, hostedRunner, []string{"job lint:"}},
		{"hosted label in a list", []any{hostedRunner}, hostedRunner, hostedRunner, []string{"job lint:"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad, err := hostedRunnerViolations(workflow(tc.lint, tc.lintGates, tc.image), nil)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(bad) != len(tc.want) {
				t.Fatalf("violations %q, want %d starting %q", bad, len(tc.want), tc.want)
			}
			for i, w := range tc.want {
				if !strings.HasPrefix(bad[i], w) {
					t.Errorf("violation %q, want it to start %q", bad[i], w)
				}
			}
		})
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
func imageBuildProxyViolations(src []byte, runners map[string]string) ([]string, error) {
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
			if want := wantRunsOn(runners, name); fmt.Sprint(job.RunsOn) != want {
				bad = append(bad, fmt.Sprintf("job %s: builds the image on runs-on %v, want %s", name, job.RunsOn, want))
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
		bad, err := imageBuildProxyViolations(src, templateRunners[f])
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
		bad, err := imageBuildProxyViolations([]byte(strings.ReplaceAll(wf, toolchainBuildMakeCall, repl)), templateRunners[ciWorkflowFile])
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
// the way `scripts/devcontainer.sh build` builds it, with GO_BUILD_PROXY as
// the goproxy BuildKit secret when it is set and with no forge credential.
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
	if !strings.Contains(r, `if [ -n "$${GO_BUILD_PROXY:-}" ]; then set -- "$$@" `+proxySecretFlag+`; fi`) {
		bad = append(bad, "the recipe does not pass a set GO_BUILD_PROXY as the goproxy build secret ("+proxySecretFlag+")")
	}
	if strings.Contains(r, "--build-arg") && strings.Contains(r, "GO_BUILD_PROXY=") {
		bad = append(bad, "the recipe passes GO_BUILD_PROXY as a build argument, which the image history records")
	}
	if strings.Count(r, "--secret") != strings.Count(r, proxySecretFlag) {
		bad = append(bad, "the recipe passes a build secret other than "+proxySecretFlag)
	}
	for _, s := range []string{"gomodauth", "MODULE_ENV_FILE"} {
		if strings.Contains(r, s) {
			bad = append(bad, fmt.Sprintf("the recipe names %s; the image build takes GO_BUILD_PROXY, not the forge credentials", s))
		}
	}
	return bad
}

const (
	// proxySecretFlag passes GO_BUILD_PROXY to the image build as a BuildKit
	// secret: unlike a build argument, its value never enters the image
	// history, which scripts/ci-image-history.sh refuses an address in.
	proxySecretFlag = "--secret id=goproxy,env=GO_BUILD_PROXY"
	// proxySecretMount and proxyFromSecret are how each Dockerfile RUN that
	// fetches modules reads the proxy: the mounted secret, or the public
	// proxy when the build was given none.
	proxySecretMount = "RUN --mount=type=secret,id=goproxy "
	proxyFromSecret  = `GOPROXY="$(cat /run/secrets/goproxy 2>/dev/null || echo https://proxy.golang.org)"`
)

// dockerfileProxyViolations lists what is wrong with how the Dockerfile takes
// the build proxy: no GO_BUILD_PROXY build argument at all, and every RUN that
// sets GOPROXY mounts the goproxy secret and reads it, the public proxy its
// fallback.
func dockerfileProxyViolations(df string) []string {
	var bad []string
	if strings.Contains(df, "GO_BUILD_PROXY") {
		for i, line := range strings.Split(df, "\n") {
			if strings.Contains(line, "GO_BUILD_PROXY") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				bad = append(bad, fmt.Sprintf("line %d names GO_BUILD_PROXY (%s); a build argument's value is recorded in the image history", i+1, strings.TrimSpace(line)))
			}
		}
	}
	// One instruction per entry: continuation lines joined.
	var instrs []string
	cur := ""
	for line := range strings.SplitSeq(df, "\n") {
		if cur == "" && (strings.HasPrefix(strings.TrimSpace(line), "#") || strings.TrimSpace(line) == "") {
			continue
		}
		cur += line + "\n"
		if !strings.HasSuffix(strings.TrimRight(line, " \t"), "\\") {
			instrs = append(instrs, cur)
			cur = ""
		}
	}
	fetching := 0
	for _, in := range instrs {
		if !strings.HasPrefix(in, "RUN ") || !strings.Contains(in, "GOPROXY=") {
			continue
		}
		fetching++
		first, _, _ := strings.Cut(in, "\n")
		if !strings.HasPrefix(in, proxySecretMount) {
			bad = append(bad, fmt.Sprintf("%q sets GOPROXY without mounting the goproxy secret (%s)", first, strings.TrimSpace(proxySecretMount)))
		}
		if strings.Count(in, "GOPROXY=") != strings.Count(in, proxyFromSecret) {
			bad = append(bad, fmt.Sprintf("%q sets GOPROXY other than from the secret: want %s", first, proxyFromSecret))
		}
	}
	if fetching == 0 {
		bad = append(bad, "no RUN sets GOPROXY; the module downloads moved?")
	}
	return bad
}

// TestImageBuildProxyStaysOutOfTheHistory holds the image build to passing
// the proxy as a BuildKit secret: the Dockerfile declares no GO_BUILD_PROXY
// argument and reads the mounted secret, and neither the Makefile nor
// scripts/devcontainer.sh passes it with --build-arg. A private proxy address
// then never reaches the image history ci-image-history.sh checks.
func TestImageBuildProxyStaysOutOfTheHistory(t *testing.T) {
	root := repoRoot(t)
	df := readFile(t, filepath.Join(root, "build", "docker", "devcontainer", "Dockerfile"))
	for _, b := range dockerfileProxyViolations(df) {
		t.Errorf("Dockerfile: %s", b)
	}
	for _, tc := range []struct{ name, old, new string }{
		{"argument back", "FROM ${GO_IMAGE} AS tools\n", "FROM ${GO_IMAGE} AS tools\nARG GO_BUILD_PROXY\n"},
		{"mount dropped", proxySecretMount, "RUN "},
		{"proxy from the environment", proxyFromSecret, `GOPROXY="$GO_BUILD_PROXY"`},
	} {
		if !strings.Contains(df, tc.old) {
			t.Errorf("%s: the Dockerfile no longer contains %q; update this case", tc.name, tc.old)
			continue
		}
		if len(dockerfileProxyViolations(strings.Replace(df, tc.old, tc.new, 1))) == 0 {
			t.Errorf("%s: no violation; want a refusal", tc.name)
		}
	}
	for _, f := range []string{"Makefile", filepath.Join("scripts", "devcontainer.sh")} {
		src := readFile(t, filepath.Join(root, f))
		if strings.Contains(src, "--build-arg \"GO_BUILD_PROXY") || strings.Contains(src, "--build-arg GO_BUILD_PROXY") {
			t.Errorf("%s passes GO_BUILD_PROXY with --build-arg; want %s", f, proxySecretFlag)
		}
		if !strings.Contains(src, proxySecretFlag) {
			t.Errorf("%s does not pass GO_BUILD_PROXY as %s", f, proxySecretFlag)
		}
	}
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
		{"proxy dropped", proxySecretFlag, `--label x=y`},
		{"proxy as a build argument", proxySecretFlag, `--build-arg "GO_BUILD_PROXY=$$GO_BUILD_PROXY"`},
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
			{"image job on a self-hosted label", "runs-on: " + wantRunsOn(templateRunners[f], "integration"), "runs-on: self-hosted"},
			{"image job back on the server_url choice", "runs-on: " + wantRunsOn(templateRunners[f], "integration"), "runs-on: ${{ github.server_url == 'https://github.com' && 'ubuntu-latest' || 'self-hosted' }}"},
			{"image job on the pool", "runs-on: " + wantRunsOn(templateRunners[f], "integration"), "runs-on: " + poolRunner},
		} {
			t.Run(filepath.Base(f)+"/"+tc.name, func(t *testing.T) {
				if !strings.Contains(wf, tc.old) {
					t.Fatalf("%s no longer contains %q; update this case", f, tc.old)
				}
				bad, err := imageBuildProxyViolations([]byte(strings.ReplaceAll(wf, tc.old, tc.new)), templateRunners[f])
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
