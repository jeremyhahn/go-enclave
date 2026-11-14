package buildgates

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// libDriver is a script that sources scripts/lib.sh the way every script in
// scripts/ does, then runs one helper. Its name is probe.sh, so die() prefixes
// "probe: ".
const libDriver = `set -eu
. "$LIB"
cmd=$1
shift
case $cmd in
re) eval "re=\$$1"; matches "$2" "$re" ;;
anchor) a=$(version_anchor "$1"); printf '%s\n' "$2" | grep -Eq "$a" ;;
vars) printf '%s|%s|%s|%s' "$prog" "$LC_ALL" "$NL" "$here" ;;
*) "$cmd" "$@" ;;
esac
`

// runLib runs the driver with args under env layered over the test's
// environment, and returns its combined output and whether it exited 0.
func runLib(t *testing.T, env map[string]string, args ...string) (string, bool) {
	t.Helper()
	out, code := runLibCode(t, env, args...)
	return out, code == 0
}

// runLibCode is runLib returning the driver's exit status.
func runLibCode(t *testing.T, env map[string]string, args ...string) (string, int) {
	t.Helper()
	dir := t.TempDir()
	driver := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(driver, []byte(libDriver), 0o644); err != nil {
		t.Fatalf("write driver: %v", err)
	}
	over := map[string]string{"LIB": filepath.Join(repoRoot(t), "scripts", "lib.sh")}
	for k, v := range env {
		over[k] = v
	}
	cmd := exec.Command("sh", append([]string{driver}, args...)...)
	cmd.Dir = dir
	cmd.Env = layerEnv(os.Environ(), over)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("running driver: %v", err)
		}
		return string(out), exitErr.ExitCode()
	}
	return string(out), 0
}

func TestLibDie(t *testing.T) {
	out, code := runLibCode(t, nil, "die", "the", "thing broke")
	if code != 1 {
		t.Fatalf("die exited %d, want 1", code)
	}
	if out != "probe: the thing broke\n" {
		t.Fatalf("die printed %q, want %q", out, "probe: the thing broke\n")
	}
}

func TestLibRequireScannedImage(t *testing.T) {
	const image = "go-enclave-it:test"
	const id = "sha256:1111"
	present := t.TempDir()
	fakeTool(t, present, "docker", id)
	other := t.TempDir()
	fakeTool(t, other, "docker", "sha256:2222")
	missing := t.TempDir()
	writeExecutable(t, filepath.Join(missing, "docker"), []byte("#!/bin/sh\necho 'no such image' >&2\nexit 1\n"))
	base := isolatedPath(t)

	cases := []struct {
		name   string
		env    map[string]string
		bin    string
		ok     bool
		output string
	}{
		{"image unset", map[string]string{"GO_ENCLAVE_IT_IMAGE": "", "GO_ENCLAVE_IT_IMAGE_ID": id}, present, false,
			"probe: GO_ENCLAVE_IT_IMAGE and GO_ENCLAVE_IT_IMAGE_ID are required: the suite runs on the image scripts/integration-image.sh scanned\n"},
		{"id unset", map[string]string{"GO_ENCLAVE_IT_IMAGE": image, "GO_ENCLAVE_IT_IMAGE_ID": ""}, present, false,
			"probe: GO_ENCLAVE_IT_IMAGE and GO_ENCLAVE_IT_IMAGE_ID are required: the suite runs on the image scripts/integration-image.sh scanned\n"},
		{"image missing", map[string]string{"GO_ENCLAVE_IT_IMAGE": image, "GO_ENCLAVE_IT_IMAGE_ID": id}, missing, false,
			"probe: the integration image " + image + " does not exist\n"},
		{"different id", map[string]string{"GO_ENCLAVE_IT_IMAGE": image, "GO_ENCLAVE_IT_IMAGE_ID": id}, other, false,
			"probe: the integration image " + image + " is sha256:2222, not the " + id + " that was scanned\n"},
		{"scanned id", map[string]string{"GO_ENCLAVE_IT_IMAGE": image, "GO_ENCLAVE_IT_IMAGE_ID": id}, present, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{"PATH": tc.bin + string(os.PathListSeparator) + base}
			for k, v := range tc.env {
				env[k] = v
			}
			out, ok := runLib(t, env, "require_scanned_image")
			if ok != tc.ok || out != tc.output {
				t.Fatalf("require_scanned_image = (%v, %q), want (%v, %q)", ok, out, tc.ok, tc.output)
			}
		})
	}
}

func TestLibMatches(t *testing.T) {
	cases := []struct {
		name, value, ere string
		want             bool
	}{
		{"whole value", "abc", "^abc$", true},
		{"no match", "abd", "^abc$", false},
		{"embedded newline, one line matches", "abc\nxyz", "^abc$", false},
		{"embedded newline, any-line pattern", "abc\nabc", "abc", false},
		{"empty value", "", "^.+$", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := runLib(t, nil, "matches", tc.value, tc.ere); ok != tc.want {
				t.Fatalf("matches %q %q = %v, want %v", tc.value, tc.ere, ok, tc.want)
			}
		})
	}
}

func TestLibVersionAndReleaseTagRE(t *testing.T) {
	cases := []struct {
		tag              string
		version, release bool
	}{
		{"v0.6.2", true, true},
		{"v1.0.0", true, true},
		{"v10.20.30", true, true},
		{"v0.0.0", true, true},
		{"v01.2.3", true, false},
		{"v1.02.3", true, false},
		{"v1.2.03", true, false},
		{"v0.10.0-alpha", true, true},
		{"v0.10.0-alpha.1", true, false},
		{"v0.10.0-beta", true, false},
		{"v1.0.0-rc.1", true, true},
		{"v1.0.0-rc.12", true, true},
		{"v1.0.0-rc.0", true, false},
		{"v1.0.0-rc.01", true, false},
		{"v1.0.0-rc", true, false},
		{"v1.0.0\n", false, false},
		{"v1.0.0\nv1.0.0", false, false},
		{"1.0.0", false, false},
		{"v1.0", false, false},
		{"v1.0.0-", false, false},
		{"v1.0.0+build", false, false},
		{"", false, false},
	}
	for _, tc := range cases {
		for _, re := range []struct {
			name string
			want bool
		}{{"VERSION_RE", tc.version}, {"RELEASE_TAG_RE", tc.release}} {
			if _, ok := runLib(t, nil, "re", re.name, tc.tag); ok != re.want {
				t.Errorf("%s matches %q = %v, want %v", re.name, tc.tag, ok, re.want)
			}
		}
	}
}

func TestLibVersionAnchor(t *testing.T) {
	out, ok := runLib(t, nil, "version_anchor", "v0.6.2")
	if !ok || out != `^## +\[?v0\.6\.2\]?( |$)`+"\n" {
		t.Fatalf("version_anchor v0.6.2 = (%v, %q)", ok, out)
	}
	cases := []struct {
		heading string
		want    bool
	}{
		{"## v0.6.2", true},
		{"## [v0.6.2]", true},
		{"## [v0.6.2] - 2026-10-01", true},
		{"## v0.6.2 - 2026-10-01", true},
		{"##   [v0.6.2]", true},
		{"## v0.6.20", false},
		{"## [v0.6.20]", false},
		{"## [v0.6.20] - 2026-10-01", false},
		{"## v0.6.2-rc.1", false},
		{"## v0x6x2", false},
		{"### v0.6.2", false},
		{"##v0.6.2", false},
	}
	for _, tc := range cases {
		if _, ok := runLib(t, nil, "anchor", "v0.6.2", tc.heading); ok != tc.want {
			t.Errorf("anchor v0.6.2 on %q = %v, want %v", tc.heading, ok, tc.want)
		}
	}
}

func TestLibUnreleasedPending(t *testing.T) {
	cases := []struct {
		name, changelog, want string
	}{
		{"empty sections", "# Changelog\n\n## [Unreleased]\n\n### Added\n\n### Fixed\n   \n\t\n## [v0.6.2] - 2026-10-01\n\n- shipped\n", ""},
		{"entry", "## [Unreleased]\n\n### Added\n\n- a new gate\n- another\n\n## [v0.6.2]\n", "- a new gate\n"},
		{"stray text", "## [Unreleased]\nsome note\n", "some note\n"},
		{"stops at next heading", "## [Unreleased]\n\n## [v0.6.2]\n- shipped\n", ""},
		{"stops at unbracketed heading", "## [Unreleased]\n### Added\n## v0.6.2\n- shipped\n", ""},
		{"trailing blanks on heading", "##  [Unreleased] \t\n- pending\n", "- pending\n"},
		{"no unreleased section", "# Changelog\n\n## [v0.6.2]\n- shipped\n", ""},
		{"empty file", "", ""},
		{"unreleased at end", "# Changelog\n## [Unreleased]\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "CHANGELOG.md")
			if err := os.WriteFile(file, []byte(tc.changelog), 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}
			out, ok := runLib(t, nil, "unreleased_pending", file)
			if !ok || out != tc.want {
				t.Fatalf("unreleased_pending = (%v, %q), want (true, %q)", ok, out, tc.want)
			}
		})
	}
	if out, ok := runLib(t, nil, "unreleased_pending", filepath.Join(t.TempDir(), "absent.md")); ok {
		t.Fatalf("unreleased_pending on a missing file exited 0: %q", out)
	}
}

// TestLibDefinitions checks the variables lib.sh sets for the sourcing script.
func TestLibDefinitions(t *testing.T) {
	out, ok := runLib(t, nil, "vars")
	if !ok {
		t.Fatalf("vars failed: %q", out)
	}
	prefix := "probe|C|\n|"
	if !strings.HasPrefix(out, prefix) {
		t.Fatalf("vars = %q, want prefix %q", out, prefix)
	}
	here := strings.TrimPrefix(out, prefix)
	if !filepath.IsAbs(here) {
		t.Fatalf("here = %q, want an absolute path", here)
	}
	if _, err := os.Stat(filepath.Join(here, "probe.sh")); err != nil {
		t.Fatalf("here = %q does not hold the driver: %v", here, err)
	}
}
