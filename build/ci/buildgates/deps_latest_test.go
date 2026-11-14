package buildgates

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const depsSelf = "github.com/jeremyhahn/go-enclave"

// depsFake is one fake go command for deps-latest.sh: the modules go list -m
// all prints, what go list -m -versions prints for each, and the modules whose
// -versions query fails.
type depsFake struct {
	mods     []string
	versions map[string]string
	fail     map[string]bool
}

// install writes the fake GOCMD and returns its path and the call log path.
// Each call logs one line: the GOWORK it saw, then its arguments.
func (f depsFake) install(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	modList := fakeTool(t, filepath.Join(dir, "bin"), "modlist", strings.Join(f.mods, "\n"))
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("echo \"GOWORK=${GOWORK-unset} $*\" >> '" + log + "'\n")
	b.WriteString("case \"$*\" in\n")
	b.WriteString("\"list -m\") echo " + depsSelf + " ;;\n")
	b.WriteString("\"list -m -f \"*\" all\") exec '" + modList + "' ;;\n")
	for m, v := range f.versions {
		b.WriteString("\"list -m -versions " + m + "\") echo '" + v + "' ;;\n")
	}
	for m := range f.fail {
		b.WriteString("\"list -m -versions " + m + "\") echo 'no such module' >&2; exit 1 ;;\n")
	}
	b.WriteString("\"get \"*|\"mod tidy\") ;;\n")
	b.WriteString("*) echo \"fake go: unexpected call: $*\" >&2; exit 2 ;;\n")
	b.WriteString("esac\n")
	goCmd := filepath.Join(dir, "go")
	writeExecutable(t, goCmd, []byte(b.String()))
	return goCmd, log
}

// runDepsLatest runs deps-latest.sh against the fake on a PATH that holds only
// the shell utilities it uses, so no real go can answer.
func runDepsLatest(t *testing.T, f depsFake) (string, bool, []string) {
	t.Helper()
	goCmd, log := f.install(t)
	path := isolatedPath(t)
	for _, u := range []string{"tr", "tail", "printf"} {
		if p, err := exec.LookPath(u); err == nil {
			if err := os.Symlink(p, filepath.Join(path, u)); err != nil {
				t.Fatalf("symlink %s: %v", u, err)
			}
		}
	}
	out, ok := runScript(t, t.TempDir(), map[string]string{
		"GOCMD":  goCmd,
		"PATH":   path,
		"GOWORK": filepath.Join(t.TempDir(), "go.work"),
	}, "deps-latest.sh")
	raw, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("read call log: %v\n%s", err, out)
	}
	return out, ok, strings.Split(strings.TrimSpace(string(raw)), "\n")
}

// depsCalls strips the GOWORK field from each logged call, failing the test
// when a call saw anything but GOWORK=off.
func depsCalls(t *testing.T, log []string) []string {
	t.Helper()
	calls := make([]string, 0, len(log))
	for _, l := range log {
		c, ok := strings.CutPrefix(l, "GOWORK=off ")
		if !ok {
			t.Errorf("call without GOWORK=off: %q", l)
		}
		calls = append(calls, c)
	}
	return calls
}

func TestDepsLatestBumpsInternalModulesToLastVersion(t *testing.T) {
	a := "github.com/jeremyhahn/go-a"
	none := "github.com/jeremyhahn/go-none"
	f := depsFake{
		mods: []string{
			depsSelf,
			a,
			"github.com/other/x",
			"golang.org/x/sys",
			"github.com/jeremyhahnx/y",
			none,
		},
		versions: map[string]string{
			a:    a + " v0.1.0 v0.2.0 v0.10.0",
			none: none,
		},
	}
	out, ok, log := runDepsLatest(t, f)
	if !ok {
		t.Fatalf("deps-latest.sh failed:\n%s", out)
	}
	got := depsCalls(t, log)
	want := []string{
		"list -m",
		"list -m -f {{if not .Indirect}}{{.Path}}{{end}} all",
		"list -m -versions " + a,
		"get " + a + "@v0.10.0",
		"list -m -versions " + none,
		"mod tidy",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestDepsLatestNoInternalModulesOnlyTidies(t *testing.T) {
	f := depsFake{mods: []string{depsSelf, "github.com/other/x"}}
	out, ok, log := runDepsLatest(t, f)
	if !ok {
		t.Fatalf("deps-latest.sh failed:\n%s", out)
	}
	got := depsCalls(t, log)
	want := []string{
		"list -m",
		"list -m -f {{if not .Indirect}}{{.Path}}{{end}} all",
		"mod tidy",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestDepsLatestVersionsFailureNamesModule(t *testing.T) {
	bad := "github.com/jeremyhahn/go-bad"
	f := depsFake{
		mods: []string{depsSelf, bad},
		fail: map[string]bool{bad: true},
	}
	out, ok, log := runDepsLatest(t, f)
	if ok {
		t.Fatalf("succeeded although go list -m -versions failed:\n%s", out)
	}
	if !strings.Contains(out, "go list -m -versions "+bad+" failed") {
		t.Fatalf("failure does not name %s:\n%s", bad, out)
	}
	for _, c := range depsCalls(t, log) {
		if strings.HasPrefix(c, "get ") || c == "mod tidy" {
			t.Fatalf("ran %q after the -versions failure", c)
		}
	}
}
