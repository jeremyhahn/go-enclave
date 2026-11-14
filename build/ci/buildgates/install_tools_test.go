package buildgates

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// install-tools.sh

// installTools are the tools scripts/install-tools.sh installs, in order,
// with the tool-pins.sh variable that pins each.
var installTools = []struct{ name, pin string }{
	{"golangci-lint", "GOLANGCI_VERSION"},
	{"gosec", "GOSEC_VERSION"},
	{"govulncheck", "GOVULNCHECK_VERSION"},
	{"actionlint", "ACTIONLINT_VERSION"},
	{"trivy", "TRIVY_VERSION"},
	{"shellcheck", "SHELLCHECK_VERSION"},
}

// fakeToolSh is a stand-in for scripts/tool.sh: it logs its arguments,
// TOOL_INSTALL, TOOLS_DIR and whether TOOLS_DIR exists, fails for the tool
// named by FAIL_TOOL, and otherwise prints the path of STUB_BIN.
const fakeToolSh = `#!/bin/sh
d=no
[ -d "$TOOLS_DIR" ] && d=yes
echo "$1 $2 TOOL_INSTALL=$TOOL_INSTALL TOOLS_DIR=$TOOLS_DIR exists=$d" >> "$INSTALL_LOG"
if [ "$1" = "${FAIL_TOOL-}" ]; then
	echo "fake tool.sh: $1 failed" >&2
	exit 1
fi
echo "$STUB_BIN"
`

// installFixture is a scripts directory holding copies of install-tools.sh,
// lib.sh and tool-pins.sh beside a fake tool.sh, and the environment to run
// it with.
type installFixture struct {
	scripts string
	log     string
	tmp     string
	env     map[string]string
}

func newInstallFixture(t *testing.T) installFixture {
	t.Helper()
	root := t.TempDir()
	scripts := filepath.Join(root, "scripts")
	if err := os.MkdirAll(scripts, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, name := range []string{"install-tools.sh", "lib.sh", "tool-pins.sh"} {
		b, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		writeExecutable(t, filepath.Join(scripts, name), b)
	}
	writeExecutable(t, filepath.Join(scripts, "tool.sh"), []byte(fakeToolSh))
	stub := fakeTool(t, filepath.Join(root, "stubs"), "stub", "stub tool")
	if err := os.Chmod(stub, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	path := isolatedPath(t)
	cp, err := exec.LookPath("cp")
	if err != nil {
		t.Fatalf("cp is required: %v", err)
	}
	if err := os.Symlink(cp, filepath.Join(path, "cp")); err != nil {
		t.Fatalf("symlink cp: %v", err)
	}
	tmp := filepath.Join(root, "tmp")
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	log := filepath.Join(root, "install.log")
	return installFixture{
		scripts: scripts,
		log:     log,
		tmp:     tmp,
		env: map[string]string{
			"PATH":         path,
			"TMPDIR":       tmp,
			"INSTALL_LOG":  log,
			"STUB_BIN":     stub,
			"FAIL_TOOL":    "",
			"TOOL_INSTALL": "",
			"TOOLS_DIR":    "",
		},
	}
}

// run runs the fixture's install-tools.sh with args.
func (f installFixture) run(t *testing.T, args ...string) (string, bool) {
	t.Helper()
	cmd := exec.Command("sh", append([]string{filepath.Join(f.scripts, "install-tools.sh")}, args...)...)
	cmd.Dir = t.TempDir()
	cmd.Env = layerEnv(os.Environ(), f.env)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("running install-tools.sh: %v", err)
		}
		return string(out), false
	}
	return string(out), true
}

// calls returns the fake tool.sh's log lines.
func (f installFixture) calls(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(f.log)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

// requireScratchGone fails unless the scratch TOOLS_DIR every call logged,
// and anything else under TMPDIR, has been removed.
func (f installFixture) requireScratchGone(t *testing.T, calls []string) {
	t.Helper()
	for _, c := range calls {
		_, rest, _ := strings.Cut(c, "TOOLS_DIR=")
		dir, _, _ := strings.Cut(rest, " ")
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("TOOLS_DIR %s survived the run (stat: %v)", dir, err)
		}
	}
	left, err := os.ReadDir(f.tmp)
	if err != nil {
		t.Fatalf("read TMPDIR: %v", err)
	}
	if len(left) != 0 {
		t.Errorf("TMPDIR still holds %d entries after the run", len(left))
	}
}

// toolPins reads the NAME=value pins from the repository's tool-pins.sh.
func toolPins(t *testing.T) map[string]string {
	t.Helper()
	fh, err := os.Open(filepath.Join(repoRoot(t), "scripts", "tool-pins.sh"))
	if err != nil {
		t.Fatalf("open tool-pins.sh: %v", err)
	}
	defer func() { _ = fh.Close() }()
	pins := map[string]string{}
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			pins[k] = v
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan tool-pins.sh: %v", err)
	}
	return pins
}

func TestInstallToolsUsage(t *testing.T) {
	for name, args := range map[string][]string{
		"no argument":   nil,
		"two arguments": {"/tmp/a", "/tmp/b"},
	} {
		t.Run(name, func(t *testing.T) {
			out, ok := runScript(t, t.TempDir(), nil, "install-tools.sh", args...)
			if ok {
				t.Fatalf("install-tools.sh %v passed:\n%s", args, out)
			}
			if !strings.Contains(out, "install-tools: usage: ") || !strings.Contains(out, "<bindir>") {
				t.Errorf("want the usage, got:\n%s", out)
			}
		})
	}
}

func TestInstallToolsRefusesRelativeBindir(t *testing.T) {
	dir := t.TempDir()
	out, ok := runScript(t, dir, nil, "install-tools.sh", "bin")
	if ok {
		t.Fatalf("a relative bindir passed:\n%s", out)
	}
	if !strings.Contains(out, "<bindir> 'bin' is not an absolute path") {
		t.Errorf("want the absolute-path refusal, got:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "bin")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the refused bindir was created (stat: %v)", err)
	}
}

func TestInstallToolsInstallsEveryPinnedTool(t *testing.T) {
	f := newInstallFixture(t)
	dest := filepath.Join(t.TempDir(), "not", "yet", "bin")
	out, ok := f.run(t, dest)
	if !ok {
		t.Fatalf("install-tools.sh failed:\n%s", out)
	}
	pins := toolPins(t)
	calls := f.calls(t)
	if len(calls) != len(installTools) {
		t.Fatalf("tool.sh ran %d times, want %d: %q", len(calls), len(installTools), calls)
	}
	for i, tool := range installTools {
		version := pins[tool.pin]
		if version == "" {
			t.Fatalf("tool-pins.sh has no %s", tool.pin)
		}
		want := tool.name + " " + version + " TOOL_INSTALL=1 TOOLS_DIR="
		if !strings.HasPrefix(calls[i], want) || !strings.HasSuffix(calls[i], " exists=yes") {
			t.Errorf("call %d = %q, want %q... with an existing TOOLS_DIR", i, calls[i], want)
		}
		if strings.Contains(calls[i], "TOOLS_DIR= ") {
			t.Errorf("call %d had an empty TOOLS_DIR: %q", i, calls[i])
		}
		fi, err := os.Stat(filepath.Join(dest, tool.name))
		if err != nil {
			t.Errorf("%s not installed: %v", tool.name, err)
			continue
		}
		if mode := fi.Mode().Perm(); mode != 0o755 {
			t.Errorf("%s mode = %o, want 755", tool.name, mode)
		}
		if !strings.Contains(out, "installed "+tool.name+" "+version+" into "+dest) {
			t.Errorf("no install line for %s in:\n%s", tool.name, out)
		}
	}
	f.requireScratchGone(t, calls)
}

func TestInstallToolsStopsAtAFailingTool(t *testing.T) {
	f := newInstallFixture(t)
	f.env["FAIL_TOOL"] = installTools[2].name
	dest := filepath.Join(t.TempDir(), "bin")
	out, ok := f.run(t, dest)
	if ok {
		t.Fatalf("install-tools.sh passed with a failing tool:\n%s", out)
	}
	if !strings.Contains(out, "fake tool.sh: "+installTools[2].name+" failed") {
		t.Errorf("want the tool's failure, got:\n%s", out)
	}
	calls := f.calls(t)
	if len(calls) != 3 {
		t.Errorf("tool.sh ran %d times, want 3 (stop at the failure): %q", len(calls), calls)
	}
	for i, tool := range installTools {
		_, err := os.Stat(filepath.Join(dest, tool.name))
		switch {
		case i < 2 && err != nil:
			t.Errorf("%s, before the failure, not installed: %v", tool.name, err)
		case i >= 2 && !errors.Is(err, os.ErrNotExist):
			t.Errorf("%s, at or after the failure, was installed (stat: %v)", tool.name, err)
		}
	}
	f.requireScratchGone(t, calls)
}
