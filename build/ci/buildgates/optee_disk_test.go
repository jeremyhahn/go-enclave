package buildgates

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	// opteeJob is ci.yml's OP-TEE harness job, and opteeStepIf the path gate
	// every one of its steps after the select step carries.
	opteeJob    = "optee"
	opteeStepIf = "steps.select.outputs.run == 'true'"
	// opteeRoomIf is the room step's if: the path gate, on the hosted runner
	// only. The job can run on the bigdisk-docker pool (ruling 442), whose
	// guest needs no room made and whose Docker daemon the step must not
	// restart; the disk check still runs there.
	opteeRoomIf = opteeStepIf + " && runner.environment == 'github-hosted'"
	// opteeFixtureGB is the fixture image's unpacked size, rounded up (the
	// fixture image contract in docs/backend-conformance/engineering.md). The
	// disk check's NEED_GB must exceed it: the pull and the toolchain image
	// come on top.
	opteeFixtureGB = 28
	// dockerRootDir is how the disk check finds Docker's data root.
	dockerRootDir = "docker info --format '{{.DockerRootDir}}'"
)

// pullsAnImage reports whether a step's command pulls or runs an image.
func pullsAnImage(run string) bool {
	for _, s := range []string{"make integration-test-", "docker pull", "docker run", "docker create", "in-toolchain-image.sh"} {
		if strings.Contains(run, s) {
			return true
		}
	}
	return false
}

// makesRoom reports whether a step frees runner disk or moves Docker's data
// root.
func makesRoom(run string) bool {
	return strings.Contains(run, "sudo rm -rf ") || strings.Contains(run, `"data-root"`)
}

// opteeDiskViolations returns what is wrong with the room the optee job makes
// for its images: a step frees disk or moves Docker's data root before the
// first step that pulls or runs an image, and a later step, still before the
// harness, fails the job when Docker's data root has less than NEED_GB free.
func opteeDiskViolations(src []byte) ([]string, error) {
	jobs, err := workflowJobs(src)
	if err != nil {
		return nil, err
	}
	job, ok := jobs[opteeJob]
	if !ok {
		return []string{fmt.Sprintf("no %s job", opteeJob)}, nil
	}
	steps := jobSteps(job)
	room, check, pull := -1, -1, -1
	var bad []string
	for i, s := range steps {
		run, _ := s["run"].(string)
		switch {
		case pull < 0 && pullsAnImage(run):
			pull = i
		case room < 0 && makesRoom(run):
			room = i
		case room >= 0 && check < 0 && strings.Contains(run, dockerRootDir):
			check = i
			env, _ := s["env"].(map[string]any)
			need, err := strconv.Atoi(fmt.Sprint(env["NEED_GB"]))
			switch {
			case err != nil:
				bad = append(bad, fmt.Sprintf("job %s step %d: env NEED_GB is %v, want a whole number of GB", opteeJob, i+1, env["NEED_GB"]))
			case need <= opteeFixtureGB:
				bad = append(bad, fmt.Sprintf("job %s step %d: NEED_GB is %d, want more than the fixture image's %d GB", opteeJob, i+1, need, opteeFixtureGB))
			}
			for _, w := range []string{"$NEED_GB", "::error::", "exit 1", "df "} {
				if !strings.Contains(run, w) {
					bad = append(bad, fmt.Sprintf("job %s step %d: the disk check does not contain %q", opteeJob, i+1, w))
				}
			}
		}
	}
	switch {
	case pull < 0:
		bad = append(bad, fmt.Sprintf("job %s: no step pulls or runs an image", opteeJob))
	case room < 0 || room > pull:
		bad = append(bad, fmt.Sprintf("job %s: no step frees disk or moves Docker's data root before the first pull (step %d)", opteeJob, pull+1))
	case check < 0 || check > pull:
		bad = append(bad, fmt.Sprintf("job %s: no step after the room is made and before the first pull (step %d) checks the free space on `%s` against NEED_GB", opteeJob, pull+1, dockerRootDir))
	}
	for _, c := range []struct {
		i    int
		want string
	}{{room, opteeRoomIf}, {check, opteeStepIf}} {
		if c.i >= 0 && fmt.Sprint(steps[c.i]["if"]) != c.want {
			bad = append(bad, fmt.Sprintf("job %s step %d: if is %v, want %s", opteeJob, c.i+1, steps[c.i]["if"], c.want))
		}
	}
	return bad, nil
}

func TestOPTEEJobMakesRoomForTheFixtureImage(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), ciWorkflowFile))
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflowFile, err)
	}
	bad, err := opteeDiskViolations(src)
	if err != nil {
		t.Fatalf("parse %s: %v", ciWorkflowFile, err)
	}
	for _, b := range bad {
		t.Errorf("%s: %s", ciWorkflowFile, b)
	}
}

func TestOPTEEDiskGate_RefusesWhatItMustRefuse(t *testing.T) {
	const head = "jobs:\n  optee:\n    steps:\n      - id: select\n        run: echo run=true\n"
	const room = "      - if: " + opteeRoomIf + "\n        run: |\n          sudo rm -rf /opt/ghc\n"
	const check = "      - if: steps.select.outputs.run == 'true'\n        env:\n          NEED_GB: 45\n        run: |\n          root=$(docker info --format '{{.DockerRootDir}}')\n          df -h \"$root\"\n          echo \"::error::under $NEED_GB GB\"; exit 1\n"
	const harness = "      - if: steps.select.outputs.run == 'true'\n        run: make integration-test-arm-trustzone\n"
	for _, tc := range []struct {
		name  string
		steps string
		want  bool // acceptable
	}{
		{"room, check, harness", room + check + harness, true},
		{"no room", check + harness, false},
		{"no check", room + harness, false},
		{"room after the pull", check + harness + room, false},
		{"check after the pull", room + harness + check, false},
		{"check before the room", check + room + harness, false},
		{"need below the image", room + strings.Replace(check, "NEED_GB: 45", "NEED_GB: 20", 1) + harness, false},
		{"need not a number", room + strings.Replace(check, "NEED_GB: 45", "NEED_GB: lots", 1) + harness, false},
		{"check never fails", room + strings.Replace(check, "exit 1", "true", 1) + harness, false},
		{"check without the error line", room + strings.Replace(check, "::error::", "", 1) + harness, false},
		{"room ungated", strings.Replace(room, "if: "+opteeRoomIf, "if: always()", 1) + check + harness, false},
		{"room on the pool too", strings.Replace(room, opteeRoomIf, opteeStepIf, 1) + check + harness, false},
		{"check ungated", room + strings.Replace(check, "if: steps.select.outputs.run == 'true'", "if: always()", 1) + harness, false},
		{"room moves the data root", strings.Replace(room, "sudo rm -rf /opt/ghc", `jq '. + {"data-root": "/mnt/docker"}' daemon.json`, 1) + check + harness, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad, err := opteeDiskViolations([]byte(head + tc.steps))
			if err != nil {
				t.Fatal(err)
			}
			if (len(bad) == 0) != tc.want {
				t.Errorf("acceptable=%v, violations %v", tc.want, bad)
			}
		})
	}
}
