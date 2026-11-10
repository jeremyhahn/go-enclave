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
const (
	imageBuildRunner   = hostedRunner
	imageBuildMakeCall = `make docker-build GO_BUILD_PROXY="${GOPROXY:-}"`
)

// hostedRunner is the one runner label every job in hostedWorkflows takes,
// but for dockerPoolJobs; the other self-hosted pools serve only the code
// review.
const hostedRunner = "ubuntu-latest"

// dockerPoolRunner is the runs-on a job in dockerPoolJobs may carry instead of
// hostedRunner (ruling 442): the bigdisk-docker pool, a throwaway guest per
// job with its own Docker daemon, for a push to main and a same-repository
// pull request, and ubuntu-latest for every other event, a fork's pull
// request among them.
const dockerPoolRunner = `${{ ((github.event_name == 'push' && github.ref == 'refs/heads/main') || (github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository)) && fromJSON('["self-hosted","linux","x64","bigdisk-docker"]') || 'ubuntu-latest' }}`

// dockerPoolJobs are the jobs, per workflow, that may run on
// dockerPoolRunner: ci.yml's Docker jobs. release.yml's jobs stay on
// hostedRunner.
var dockerPoolJobs = map[string]map[string]bool{
	".github/workflows/ci.yml": {"image": true, "lint-gates": true, "fips": true, "integration": true, "soak": true, "optee": true},
}

// runsOnAllowed reports whether a job may carry runsOn: hostedRunner, or
// exactly dockerPoolRunner when pool lists the job.
func runsOnAllowed(runsOn any, pool map[string]bool, name string) bool {
	return runsOn == hostedRunner || (pool[name] && runsOn == dockerPoolRunner)
}

// goEnvSet matches a workflow line that sets one of the module variables, as
// an env: key or a shell assignment or export.
var goEnvSet = regexp.MustCompile(`^\s*(?:-\s*)?(?:GOPROXY|GOPRIVATE|GONOPROXY|GONOSUMDB)\s*:|(?:^|[\s;&|(])(?:GOPROXY|GOPRIVATE|GONOPROXY|GONOSUMDB)=`)

var imageBuildWorkflows = []string{".github/workflows/ci.yml", ".github/workflows/release.yml"}

var hostedWorkflows = []string{".github/workflows/ci.yml", ".github/workflows/release.yml"}

// hostedRunnerViolations lists every job in one workflow whose runs-on is
// not the GitHub-hosted runner, or dockerPoolRunner for a job in pool, and
// every job in pool the workflow does not have.
func hostedRunnerViolations(src []byte, pool map[string]bool) ([]string, error) {
	var wf proxyWorkflow
	if err := yaml.Unmarshal(src, &wf); err != nil {
		return nil, err
	}
	var bad []string
	for name, job := range wf.Jobs {
		switch {
		case runsOnAllowed(job.RunsOn, pool, name):
		case pool[name]:
			bad = append(bad, fmt.Sprintf("job %s: runs-on %v, want %s or exactly dockerPoolRunner (ruling 442)", name, job.RunsOn, hostedRunner))
		default:
			bad = append(bad, fmt.Sprintf("job %s: runs-on %v, want %s", name, job.RunsOn, hostedRunner))
		}
	}
	for name := range pool {
		if _, ok := wf.Jobs[name]; !ok {
			bad = append(bad, fmt.Sprintf("job %s: in dockerPoolJobs, but the workflow has no such job", name))
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
		bad, err := hostedRunnerViolations(src, dockerPoolJobs[f])
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
			{"job not in dockerPoolJobs on the pool", "runs-on: " + dockerPoolRunner + "\n"},
		} {
			t.Run(filepath.Base(f)+"/"+tc.name, func(t *testing.T) {
				old := "runs-on: " + hostedRunner + "\n"
				i := strings.Index(wf, old)
				if i < 0 {
					t.Fatalf("%s no longer contains %q; update this case", f, old)
				}
				bad, err := hostedRunnerViolations([]byte(wf[:i]+tc.new+wf[i+len(old):]), dockerPoolJobs[f])
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				if len(bad) == 0 {
					t.Fatal("no violation; want a refusal")
				}
			})
		}
		if len(dockerPoolJobs[f]) == 0 {
			continue
		}
		// A pool job takes dockerPoolRunner exactly, and the list names only
		// jobs the workflow has.
		for _, tc := range []struct{ name, old, new string }{
			{"pool job on the retired bigdisk label", `"bigdisk-docker"]`, `"bigdisk"]`},
			{"pool job on another pool", `"bigdisk-docker"]`, `"batch"]`},
			{"pool job on any push", "(github.event_name == 'push' && github.ref == 'refs/heads/main')", "github.event_name == 'push'"},
			{"pool job for a fork's pull request", " && github.event.pull_request.head.repo.full_name == github.repository", ""},
			{"pool job with no hosted fallback", " || 'ubuntu-latest'", ""},
			{"pool job on the bare label", dockerPoolRunner, "bigdisk-docker"},
		} {
			t.Run(filepath.Base(f)+"/"+tc.name, func(t *testing.T) {
				runner := strings.Replace(dockerPoolRunner, tc.old, tc.new, 1)
				if runner == dockerPoolRunner {
					t.Fatalf("dockerPoolRunner no longer contains %q; update this case", tc.old)
				}
				old := "runs-on: " + dockerPoolRunner + "\n"
				i := strings.Index(wf, old)
				if i < 0 {
					t.Fatalf("%s no longer contains %q; update this case", f, old)
				}
				bad, err := hostedRunnerViolations([]byte(wf[:i]+"runs-on: "+runner+"\n"+wf[i+len(old):]), dockerPoolJobs[f])
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				if len(bad) == 0 {
					t.Fatal("no violation; want a refusal")
				}
			})
		}
		t.Run(filepath.Base(f)+"/pool lists a job the workflow lacks", func(t *testing.T) {
			pool := map[string]bool{"no-such-job": true}
			for name := range dockerPoolJobs[f] {
				pool[name] = true
			}
			bad, err := hostedRunnerViolations(src, pool)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(bad) == 0 {
				t.Fatal("no violation; want a refusal")
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
// build off the hosted runner (or, for a job in pool, dockerPoolRunner) or
// its default module proxy.
func imageBuildProxyViolations(src []byte, pool map[string]bool) ([]string, error) {
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
			if !runsOnAllowed(job.RunsOn, pool, name) {
				bad = append(bad, fmt.Sprintf("job %s: builds the image on runs-on %v, want %s", name, job.RunsOn, imageBuildRunner))
			}
			for _, line := range strings.Split(st.Run, "\n") {
				if strings.Contains(line, "make docker-build") && !strings.Contains(line, imageBuildMakeCall) {
					bad = append(bad, fmt.Sprintf("job %s: %q does not pass GO_BUILD_PROXY; want %s", name, strings.TrimSpace(line), imageBuildMakeCall))
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
		bad, err := imageBuildProxyViolations(src, dockerPoolJobs[f])
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, b := range bad {
			t.Errorf("%s: %s", f, b)
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
		// The runs-on the workflow's image builds carry.
		buildRunsOn := "runs-on: " + imageBuildRunner + "\n"
		if len(dockerPoolJobs[f]) > 0 {
			buildRunsOn = "runs-on: " + dockerPoolRunner + "\n"
		}
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
			{"image job on a self-hosted label", buildRunsOn, "runs-on: bigdisk\n"},
			{"image job back on the server_url choice", buildRunsOn, "runs-on: ${{ github.server_url == 'https://github.com' && 'ubuntu-latest' || 'bigdisk' }}\n"},
		} {
			t.Run(filepath.Base(f)+"/"+tc.name, func(t *testing.T) {
				if !strings.Contains(wf, tc.old) {
					t.Fatalf("%s no longer contains %q; update this case", f, tc.old)
				}
				bad, err := imageBuildProxyViolations([]byte(strings.ReplaceAll(wf, tc.old, tc.new)), dockerPoolJobs[f])
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
