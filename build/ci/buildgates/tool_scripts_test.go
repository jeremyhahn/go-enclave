package buildgates

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// runToolScript runs scripts/<name> in dir with env layered over the test's
// environment and every key in unset removed, and returns the combined output
// and the exit code.
func runToolScript(t *testing.T, dir string, env map[string]string, unset []string, name string, args ...string) (string, int) {
	t.Helper()
	script := filepath.Join(repoRoot(t), "scripts", name)
	cmd := exec.Command("sh", append([]string{script}, args...)...)
	cmd.Dir = dir
	base := slices.DeleteFunc(os.Environ(), func(kv string) bool {
		k, _, _ := strings.Cut(kv, "=")
		return slices.Contains(unset, k)
	})
	cmd.Env = layerEnv(base, env)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("running %s: %v", script, err)
		}
		return string(out), exitErr.ExitCode()
	}
	return string(out), 0
}

// fakeRmPath is an isolated PATH whose rm only appends its argv to the
// returned log, so a broken guard in clean-tools.sh cannot delete anything.
func fakeRmPath(t *testing.T) (string, string) {
	t.Helper()
	dir := isolatedPath(t)
	rm := filepath.Join(dir, "rm")
	if err := os.Remove(rm); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remove rm link: %v", err)
	}
	log := filepath.Join(t.TempDir(), "rm.log")
	writeExecutable(t, rm, []byte("#!/bin/sh\necho \"$*\" >> '"+log+"'\n"))
	return dir, log
}

func symlinkTo(t *testing.T, target string) string {
	t.Helper()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	return link
}

func TestCleanToolsRefusals(t *testing.T) {
	work := t.TempDir()
	home := t.TempDir()
	// A HOME that is itself a symlink: the resolved TOOLS_DIR must still
	// match it.
	homeReal := t.TempDir()
	homeLink := symlinkTo(t, homeReal)
	cases := []struct {
		name  string
		tools *string
		home  string
	}{
		{"unset", nil, home},
		{"empty", ptr(""), home},
		{"relative", ptr("rel/dir"), home},
		{"root", ptr("/"), home},
		{"working directory", ptr(work), home},
		{"home", ptr(home), home},
		{"symlink to root", ptr(symlinkTo(t, "/")), home},
		{"symlink to working directory", ptr(symlinkTo(t, work)), home},
		{"symlink to home", ptr(symlinkTo(t, home)), home},
		{"home through a symlink", ptr(homeReal), homeLink},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, log := fakeRmPath(t)
			env := map[string]string{"PATH": path, "HOME": tc.home}
			var unset []string
			if tc.tools == nil {
				unset = []string{"TOOLS_DIR"}
			} else {
				env["TOOLS_DIR"] = *tc.tools
			}
			out, code := runToolScript(t, work, env, unset, "clean-tools.sh")
			if code == 0 {
				t.Fatalf("clean-tools.sh accepted TOOLS_DIR (%s): %s", tc.name, out)
			}
			if !strings.Contains(out, "clean-tools: TOOLS_DIR") || !strings.Contains(out, "refusing to delete it") {
				t.Errorf("refusal text missing: %s", out)
			}
			if b, err := os.ReadFile(log); err == nil {
				t.Fatalf("rm was called: %s", b)
			}
		})
	}
}

func ptr(s string) *string { return &s }

func TestCleanToolsRemoves(t *testing.T) {
	work := t.TempDir()
	tools := filepath.Join(t.TempDir(), "tools")
	if err := os.MkdirAll(filepath.Join(tools, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tools, "bin", "tool"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"PATH": isolatedPath(t), "HOME": t.TempDir(), "TOOLS_DIR": tools}
	if out, code := runToolScript(t, work, env, nil, "clean-tools.sh"); code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if _, err := os.Stat(tools); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("tools dir still there: %v", err)
	}
	env["TOOLS_DIR"] = filepath.Join(t.TempDir(), "absent")
	if out, code := runToolScript(t, work, env, nil, "clean-tools.sh"); code != 0 {
		t.Fatalf("absent dir: exit %d: %s", code, out)
	}
}

// fakeGofmt makes a GOCMD that prints a temp GOROOT whose bin/gofmt logs its
// argv and prints fixture.
func fakeGofmt(t *testing.T, fixture string) (map[string]string, string) {
	t.Helper()
	root := t.TempDir()
	goroot := filepath.Join(root, "goroot")
	log := filepath.Join(root, "gofmt.log")
	body := "#!/bin/sh\necho \"$*\" >> '" + log + "'\n"
	if fixture != "" {
		body += "printf '%s\\n' '" + fixture + "'\n"
	}
	if err := os.MkdirAll(filepath.Join(goroot, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(goroot, "bin", "gofmt"), []byte(body))
	gocmd := fakeTool(t, filepath.Join(root, "gobin"), "go", goroot)
	return map[string]string{"GOCMD": gocmd}, log
}

func readToolLog(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return string(b)
}

func TestFmtScript(t *testing.T) {
	t.Run("write", func(t *testing.T) {
		env, log := fakeGofmt(t, "")
		if out, code := runToolScript(t, t.TempDir(), env, nil, "fmt.sh", "write"); code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		if got := readToolLog(t, log); got != "-w .\n" {
			t.Errorf("gofmt argv = %q, want -w .", got)
		}
	})
	t.Run("check clean", func(t *testing.T) {
		env, log := fakeGofmt(t, "")
		out, code := runToolScript(t, t.TempDir(), env, nil, "fmt.sh", "check")
		if code != 0 || strings.Contains(out, "Not formatted") {
			t.Fatalf("exit %d: %s", code, out)
		}
		if got := readToolLog(t, log); got != "-l .\n" {
			t.Errorf("gofmt argv = %q, want -l .", got)
		}
	})
	t.Run("check dirty", func(t *testing.T) {
		env, _ := fakeGofmt(t, "a.go\nsub/b.go")
		out, code := runToolScript(t, t.TempDir(), env, nil, "fmt.sh", "check")
		if code != 1 {
			t.Fatalf("exit %d, want 1: %s", code, out)
		}
		for _, want := range []string{"Not formatted:", "a.go", "sub/b.go"} {
			if !strings.Contains(out, want) {
				t.Errorf("output lacks %q: %s", want, out)
			}
		}
	})
	for _, args := range [][]string{nil, {"fix"}} {
		t.Run("usage "+strings.Join(args, ""), func(t *testing.T) {
			env, log := fakeGofmt(t, "")
			out, code := runToolScript(t, t.TempDir(), env, nil, "fmt.sh", args...)
			if code != 1 || !strings.Contains(out, "fmt: usage:") || !strings.Contains(out, "write|check") {
				t.Fatalf("exit %d: %s", code, out)
			}
			if got := readToolLog(t, log); got != "" {
				t.Errorf("gofmt ran: %q", got)
			}
		})
	}
}

// scanFixture makes a root with module dirs a and b and a fake scanner that
// logs its working directory and exits with $SCAN_RC.
func scanFixture(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"a", "b"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	log := filepath.Join(t.TempDir(), "scan.log")
	scanner := filepath.Join(t.TempDir(), "scanner")
	writeExecutable(t, scanner, []byte("#!/bin/sh\necho \"${PWD##*/}\" >> '"+log+"'\nexit \"$SCAN_RC\"\n"))
	return root, scanner, log
}

func TestScanScript(t *testing.T) {
	t.Run("usage", func(t *testing.T) {
		for _, args := range [][]string{nil, {"x"}, {"x", "a finding"}} {
			out, code := runToolScript(t, t.TempDir(), nil, nil, "scan.sh", args...)
			if code != 1 || !strings.Contains(out, "scan: usage:") {
				t.Errorf("%q: exit %d: %s", args, code, out)
			}
		}
	})
	t.Run("all modules pass", func(t *testing.T) {
		root, scanner, log := scanFixture(t)
		env := map[string]string{"SCAN_MODULES": "a b", "SCAN_RC": "0"}
		if out, code := runToolScript(t, root, env, nil, "scan.sh", "fake", "a finding", scanner); code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		if got := readToolLog(t, log); got != "a\nb\n" {
			t.Errorf("ran in %q, want a then b", got)
		}
	})
	t.Run("finding stops at first module", func(t *testing.T) {
		root, scanner, log := scanFixture(t)
		env := map[string]string{"SCAN_MODULES": "a b", "SCAN_RC": "3"}
		out, code := runToolScript(t, root, env, nil, "scan.sh", "fake", "a finding", scanner)
		if code != 3 || strings.Contains(out, "KILLED") {
			t.Fatalf("exit %d: %s", code, out)
		}
		if got := readToolLog(t, log); got != "a\n" {
			t.Errorf("ran in %q, want only a", got)
		}
	})
	t.Run("killed by signal", func(t *testing.T) {
		out, code := runToolScript(t, t.TempDir(), nil, []string{"SCAN_MODULES"}, "scan.sh",
			"fake", "a finding", "sh", "-c", "kill -9 $$")
		if code != 137 {
			t.Fatalf("exit %d, want 137: %s", code, out)
		}
		for _, want := range []string{"fake was KILLED by signal 9", "this is NOT a finding"} {
			if !strings.Contains(out, want) {
				t.Errorf("output lacks %q: %s", want, out)
			}
		}
	})
}
