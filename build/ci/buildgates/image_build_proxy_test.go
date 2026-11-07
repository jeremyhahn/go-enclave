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
// private root module comes through a LAN Go module proxy (#293, DS-7350):
// the jobs run on the self-hosted label whose pool environment carries
// GOPROXY, GOPRIVATE, GONOPROXY and GONOSUMDB, each make docker-build passes
// the inherited GOPROXY to the build as GO_BUILD_PROXY, no workflow sets
// those variables or rewrites module URLs, and no forge credential reaches
// the build as the gomodauth secret.
const (
	imageBuildRunner   = "bigdisk"
	imageBuildMakeCall = `make docker-build GO_BUILD_PROXY="${GOPROXY:-}"`
)

// goEnvSet matches a workflow line that sets one of the module variables the
// pool environment owns, as an env: key or a shell assignment or export.
var goEnvSet = regexp.MustCompile(`^\s*(?:-\s*)?(?:GOPROXY|GOPRIVATE|GONOPROXY|GONOSUMDB)\s*:|(?:^|[\s;&|(])(?:GOPROXY|GOPRIVATE|GONOPROXY|GONOSUMDB)=`)

var imageBuildWorkflows = []string{".github/workflows/ci.yml", ".github/workflows/release.yml"}

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
// build off the LAN proxy.
func imageBuildProxyViolations(src []byte) ([]string, error) {
	var bad []string
	if strings.Contains(string(src), "gomodauth") {
		bad = append(bad, "names gomodauth; the image build takes GO_BUILD_PROXY, not the forge credentials")
	}
	if strings.Contains(string(src), "vars.GO_BUILD_PROXY") {
		bad = append(bad, "names vars.GO_BUILD_PROXY; the proxy comes from the pool's GOPROXY, not a repository variable")
	}
	for i, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if goEnvSet.MatchString(line) {
			bad = append(bad, fmt.Sprintf("line %d: %q sets a module variable the pool environment owns", i+1, strings.TrimSpace(line)))
		}
		if strings.Contains(line, "insteadOf") {
			bad = append(bad, fmt.Sprintf("line %d: %q rewrites module URLs; the pool's proxy serves the private modules", i+1, strings.TrimSpace(line)))
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
		if s, ok := job.RunsOn.(string); ok && strings.Contains(s, "github.server_url") {
			bad = append(bad, fmt.Sprintf("job %s: runs-on %q picks a GitHub-hosted runner, which cannot reach the module proxy; want %s", name, s, imageBuildRunner))
		}
		for _, st := range job.Steps {
			if !strings.Contains(st.Run, "make docker-build") {
				continue
			}
			builds++
			if job.RunsOn != imageBuildRunner {
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
		bad, err := imageBuildProxyViolations(src)
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
			{"image job on a hosted runner", "runs-on: " + imageBuildRunner + "\n", "runs-on: ubuntu-latest\n"},
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
