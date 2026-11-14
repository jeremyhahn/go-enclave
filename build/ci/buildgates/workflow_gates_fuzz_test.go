package buildgates

import (
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// jobFromYAML decodes one job's YAML body the way workflowJobs does.
func jobFromYAML(t *testing.T, src string) map[string]any {
	t.Helper()
	var job map[string]any
	if err := yaml.Unmarshal([]byte(src), &job); err != nil {
		t.Fatal(err)
	}
	if job == nil {
		job = map[string]any{}
	}
	return job
}

func TestJobIsWriteCapable_Table(t *testing.T) {
	for _, tc := range []struct {
		name string
		job  string
		want bool
	}{
		{"no permissions", "runs-on: x\n", false},
		{"read-all", "permissions: read-all\n", false},
		{"write-all", "permissions: write-all\n", true},
		{"contents write", "permissions: {contents: write}\n", true},
		{"packages write", "permissions: {packages: write}\n", true},
		{"one write among reads", "permissions: {contents: read, id-token: write}\n", true},
		{"reads only", "permissions: {contents: read, packages: read}\n", false},
		{"none level", "permissions: {contents: none}\n", false},
		{"explicit empty map", "permissions: {}\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := jobIsWriteCapable(jobFromYAML(t, tc.job)); got != tc.want {
				t.Errorf("jobIsWriteCapable = %v, want %v", got, tc.want)
			}
		})
	}
}

// A job with no permissions block takes the workflow's; an explicit block,
// even an empty one, replaces it.
func TestWriteCheckoutGate_WorkflowLevelPermissions(t *testing.T) {
	const ck = "    steps:\n      - uses: actions/checkout@abc\n"
	for _, tc := range []struct {
		name string
		yaml string
		want bool // acceptable
	}{
		{"job inherits workflow write-all", "permissions: write-all\njobs:\n  p:\n" + ck, false},
		{"job inherits workflow contents write", "permissions: {contents: write}\njobs:\n  p:\n" + ck, false},
		{"job inherits workflow read-all", "permissions: read-all\njobs:\n  p:\n" + ck, true},
		{"job empty map overrides workflow write-all", "permissions: write-all\njobs:\n  p:\n    permissions: {}\n" + ck, true},
		{"job read overrides workflow write-all", "permissions: write-all\njobs:\n  p:\n    permissions: {contents: read}\n" + ck, true},
		{"inherited write does not persist", "permissions: write-all\njobs:\n  p:\n" + ck + "        with: {persist-credentials: false}\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad, err := writeCheckoutViolations([]byte(tc.yaml))
			if err != nil {
				t.Fatal(err)
			}
			if (len(bad) == 0) != tc.want {
				t.Errorf("acceptable=%v, violations %v", tc.want, bad)
			}
		})
	}
}

func TestIsCheckout_Table(t *testing.T) {
	for _, tc := range []struct {
		uses any
		want bool
	}{
		{"actions/checkout@0123456789abcdef0123456789abcdef01234567", true},
		{"actions/checkout@v4", true},
		{"actions/checkout@v4.2.2", true},
		{"actions/checkout", false},
		{"actions/checkout-extra@v1", false},
		{"actions/checkoutx@v1", false},
		{"someone/actions/checkout@v4", false},
		{"my-actions/checkout@v4", false},
		{"./actions/checkout", false},
		{"", false},
		{nil, false},
		{42, false},
	} {
		step := map[string]any{}
		if tc.uses != nil {
			step["uses"] = tc.uses
		}
		if got := isCheckout(step); got != tc.want {
			t.Errorf("isCheckout(uses=%v) = %v, want %v", tc.uses, got, tc.want)
		}
	}
}

func FuzzWorkflowGates(f *testing.F) {
	const ck = "      - uses: actions/checkout@abc # v7\n        with:\n          persist-credentials: false\n"
	const check = "      - name: gate\n        env:\n          R: verify=${{ needs.verify.result }} lint=${{ needs.lint.result }}\n        run: |\n          case $R in *=success) ;; *) exit 1 ;; esac\n"
	for _, steps := range []string{check + ck, ck + check, ck, "      - run: sh build/ci/summary.sh\n" + ck, "      - uses: some/action@abc\n" + ck} {
		f.Add(publishWorkflowHead + steps)
	}
	for _, s := range []string{
		"jobs:\n  p:\n    permissions: {contents: write}\n    steps:\n      - uses: actions/checkout@abc\n",
		"jobs:\n  p:\n    permissions: {contents: write}\n    steps:\n      - uses: actions/checkout@abc\n        with: {persist-credentials: true}\n",
		"jobs:\n  p:\n    permissions: write-all\n    steps:\n      - uses: actions/checkout@abc\n",
		"jobs:\n  p:\n    permissions: {contents: read}\n    steps:\n      - uses: actions/checkout@abc\n",
		"permissions: write-all\njobs:\n  p:\n    steps:\n      - uses: actions/checkout@abc\n",
		"permissions: write-all\njobs:\n  p:\n    permissions: {}\n    steps:\n      - uses: actions/checkout@abc\n",
		"jobs: {}\n",
		"jobs:\n",
		"",
		"on: push\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		jobs, jobsErr := workflowJobs([]byte(src))
		bad, err := writeCheckoutViolations([]byte(src))
		if (err == nil) != (jobsErr == nil) {
			t.Fatalf("writeCheckoutViolations err %v, workflowJobs err %v", err, jobsErr)
		}
		if err == nil && len(jobs) == 0 && len(bad) != 0 {
			t.Fatalf("a workflow with no jobs yields violations: %v", bad)
		}
		pub, err := publishGateViolations([]byte(src), "publish")
		if err == nil && len(jobs) == 0 && (len(pub) != 1 || !strings.Contains(pub[0], "no job")) {
			t.Fatalf("a workflow with no jobs must report only the missing job: %v", pub)
		}
	})
}
