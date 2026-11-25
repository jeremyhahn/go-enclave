package buildgates

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// amdsevWorkflowFile is the AMD SEV hardware workflow, relative to the
// repository root.
const amdsevWorkflowFile = ".github/workflows/amd-sev.yml"

// sevSNPParam is the kvm_amd parameter that says whether the host runs SNP.
const sevSNPParam = "/sys/module/kvm_amd/parameters/sev_snp"

type amdsevStep struct {
	Name string            `yaml:"name"`
	If   string            `yaml:"if"`
	Run  string            `yaml:"run"`
	Env  map[string]string `yaml:"env"`
}

type amdsevJob struct {
	If     string            `yaml:"if"`
	RunsOn []string          `yaml:"runs-on"`
	Env    map[string]string `yaml:"env"`
	Steps  []amdsevStep      `yaml:"steps"`
}

func readAMDSEVWorkflow(t *testing.T) map[string]amdsevJob {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(repoRoot(t), amdsevWorkflowFile))
	if err != nil {
		t.Fatalf("read %s: %v", amdsevWorkflowFile, err)
	}
	var wf struct {
		Jobs map[string]amdsevJob `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(src, &wf); err != nil {
		t.Fatalf("parse %s: %v", amdsevWorkflowFile, err)
	}
	return wf.Jobs
}

// guestsOf returns the AMDSEV_GUESTS modes a step runs, from the step's env,
// an inline assignment in its run, or the job's env.
func guestsOf(job amdsevJob, s amdsevStep) []string {
	if g, ok := s.Env["AMDSEV_GUESTS"]; ok {
		return strings.Fields(g)
	}
	if i := strings.Index(s.Run, "AMDSEV_GUESTS="); i >= 0 {
		rest := s.Run[i+len("AMDSEV_GUESTS="):]
		if f := strings.Fields(rest); len(f) > 0 {
			return []string{strings.Trim(f[0], `"'`)}
		}
	}
	return strings.Fields(job.Env["AMDSEV_GUESTS"])
}

// The SEV and SEV-ES job runs no SNP step: a runner without SNP must not turn
// an SNP step green by skipping it.
func TestAMDSEVWorkflow_SEVJobRunsNoSNP(t *testing.T) {
	jobs := readAMDSEVWorkflow(t)
	job, ok := jobs["amd-sev"]
	if !ok {
		t.Fatalf("%s has no amd-sev job", amdsevWorkflowFile)
	}
	if !strings.Contains(job.If, "vars.AMD_SEV_RUNNER == 'online'") {
		t.Errorf("amd-sev job if %q is not gated on AMD_SEV_RUNNER", job.If)
	}
	if slices.Contains(strings.Fields(job.Env["AMDSEV_GUESTS"]), "snp") {
		t.Errorf("amd-sev job env AMDSEV_GUESTS lists snp")
	}
	for _, s := range job.Steps {
		if strings.Contains(s.Run, "sev_snp") || strings.Contains(strings.ToUpper(s.Name), "SNP") ||
			slices.Contains(guestsOf(job, s), "snp") || strings.Contains(s.Run, `"-snp/`) ||
			strings.Contains(s.Env["AMDSEV_RESULTS"], "-snp") {
			t.Errorf("amd-sev job step %q runs SNP; SNP belongs to the amd-sev-snp job", s.Name)
		}
	}
}

// The SNP job runs only on a registered SNP runner, runs the SNP guest with
// its plain-KVM control (the kit always boots the control), and fails when the
// host does not run SNP.
func TestAMDSEVWorkflow_SNPJobIsGatedAndRequiresSNP(t *testing.T) {
	jobs := readAMDSEVWorkflow(t)
	job, ok := jobs["amd-sev-snp"]
	if !ok {
		t.Fatalf("%s has no amd-sev-snp job", amdsevWorkflowFile)
	}
	if !strings.Contains(job.If, "vars.AMD_SEV_SNP_RUNNER == 'online'") {
		t.Errorf("amd-sev-snp job if %q is not gated on AMD_SEV_SNP_RUNNER", job.If)
	}
	if !strings.Contains(job.If, "github.event.pull_request.head.repo.full_name == github.repository") {
		t.Errorf("amd-sev-snp job if %q lets a fork's head reach the hardware runner", job.If)
	}
	if !slices.Contains(job.RunsOn, "self-hosted") || !slices.Contains(job.RunsOn, "amd-sev-snp") {
		t.Errorf("amd-sev-snp job runs-on %v, want [self-hosted, amd-sev-snp]", job.RunsOn)
	}
	if sev := jobs["amd-sev"].RunsOn; slices.Equal(sev, job.RunsOn) {
		t.Errorf("amd-sev-snp job shares the SEV job's runner labels %v", sev)
	}

	check, target, consoles, record := -1, -1, -1, -1
	for i, s := range job.Steps {
		switch {
		case strings.Contains(s.Run, sevSNPParam):
			check = i
		case strings.Contains(s.Run, "make integration-test-amd-sev"):
			target = i
			if g := guestsOf(job, s); !slices.Equal(g, []string{"snp"}) {
				t.Errorf("amd-sev-snp target step runs AMDSEV_GUESTS %v, want [snp]", g)
			}
		case strings.Contains(s.Run, "host-record.sh"):
			record = i
		case strings.Contains(s.Run, "::group::"):
			consoles = i
			if s.If != "always()" {
				t.Errorf("amd-sev-snp guest-console step if %q, want always()", s.If)
			}
		}
	}
	if record < 0 {
		t.Errorf("amd-sev-snp job does not record the host")
	}
	if check < 0 {
		t.Fatalf("amd-sev-snp job has no step that checks %s", sevSNPParam)
	}
	if target < 0 || target < check {
		t.Errorf("amd-sev-snp job runs no make integration-test-amd-sev after the SNP check")
	}
	if consoles < 0 {
		t.Errorf("amd-sev-snp job prints no guest consoles")
	}
	runSNPCheck(t, job.Steps[check].Run)
}

// runSNPCheck runs the SNP check step's script with the kvm_amd parameter
// pointed at a scratch file: it passes only for Y or 1, and otherwise exits
// non-zero with an error annotation.
func runSNPCheck(t *testing.T, script string) {
	t.Helper()
	for _, tc := range []struct {
		name, value string
		present     bool
		wantOK      bool
	}{
		{"Y", "Y\n", true, true},
		{"1", "1\n", true, true},
		{"N", "N\n", true, false},
		{"0", "0\n", true, false},
		{"absent", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "sev_snp")
			if tc.present {
				if err := os.WriteFile(p, []byte(tc.value), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			out, err := exec.Command("sh", "-c", strings.ReplaceAll(script, sevSNPParam, p)).CombinedOutput()
			if tc.wantOK {
				if err != nil {
					t.Errorf("SNP check with sev_snp %q failed: %v\n%s", tc.value, err, out)
				}
				return
			}
			if err == nil {
				t.Errorf("SNP check with sev_snp %q (present %v) exited 0; it must fail the job\n%s", tc.value, tc.present, out)
			}
			if !strings.Contains(string(out), "::error") {
				t.Errorf("SNP check without SNP wrote no ::error annotation\n%s", out)
			}
		})
	}
}

// No step of either job exits 0 when SNP is missing.
func TestAMDSEVWorkflow_NoStepPassesOnMissingSNP(t *testing.T) {
	for name, job := range readAMDSEVWorkflow(t) {
		for _, s := range job.Steps {
			if strings.Contains(s.Run, "sev_snp") && strings.Contains(s.Run, "exit 0") {
				t.Errorf("%s job step %q exits 0 on a sev_snp check", name, s.Name)
			}
		}
	}
}
