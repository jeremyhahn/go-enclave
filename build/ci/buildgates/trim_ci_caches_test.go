package buildgates

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Tests for scripts/trim-ci-caches.sh, which removes cache volumes on a
// runner host. Each case runs the script with bash against a fake docker
// first on PATH: it logs every call and answers from fixture files, so no
// case reaches a real Docker daemon.

const gib = 1024 * 1024 // KiB

// trimFakeDocker answers the calls trim-ci-caches.sh makes:
//   - volume ls: the lines of $FAKE_DOCKER/volumes;
//   - run ... -v <vol>:/c:ro ...: du output from $FAKE_DOCKER/sizes
//     ("<vol> <kib>" lines), nothing for a volume not listed;
//   - ps -aq --filter volume=<vol>: an id when <vol> is in $FAKE_DOCKER/inuse;
//   - volume rm <vol>: fails when <vol> is in $FAKE_DOCKER/unremovable.
//
// Every call's arguments are appended to $FAKE_DOCKER/log.
const trimFakeDocker = `#!/bin/sh
d=$FAKE_DOCKER
printf '%s\n' "$*" >> "$d/log"
case $1 in
volume)
  case $2 in
  ls) cat "$d/volumes" ;;
  rm) if grep -qx -- "$3" "$d/unremovable"; then echo "volume is in use" >&2; exit 1; fi ;;
  esac
  ;;
run)
  v=
  for a; do case $a in *:/c:ro) v=${a%:/c:ro} ;; esac; done
  while read -r name kib; do
    if [ "$name" = "$v" ]; then printf '%s\t/c\n' "$kib"; fi
  done < "$d/sizes"
  ;;
ps)
  v=
  for a; do case $a in volume=*) v=${a#volume=} ;; esac; done
  if grep -qx -- "$v" "$d/inuse"; then echo 0123456789ab; fi
  ;;
esac
exit 0
`

type trimWorld struct {
	dir  string // fixture files and the log
	path string // PATH with the fake docker first
}

type trimVolume struct {
	name        string
	kib         int // 0: no size entry, du prints nothing
	inUse       bool
	unremovable bool
}

func newTrimWorld(t *testing.T, vols []trimVolume) *trimWorld {
	t.Helper()
	w := &trimWorld{dir: t.TempDir()}
	bin := t.TempDir()
	writeExecutable(t, filepath.Join(bin, "docker"), []byte(trimFakeDocker))
	w.path = bin + string(os.PathListSeparator) + os.Getenv("PATH")
	var ls, sizes, inuse, unremovable strings.Builder
	for _, v := range vols {
		ls.WriteString(v.name + "\n")
		if v.kib > 0 {
			sizes.WriteString(v.name + " " + strconv.Itoa(v.kib) + "\n")
		}
		if v.inUse {
			inuse.WriteString(v.name + "\n")
		}
		if v.unremovable {
			unremovable.WriteString(v.name + "\n")
		}
	}
	for name, body := range map[string]string{
		"volumes": ls.String(), "sizes": sizes.String(),
		"inuse": inuse.String(), "unremovable": unremovable.String(),
	} {
		if err := os.WriteFile(filepath.Join(w.dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return w
}

// log returns the fake docker's calls, one per line ("" when none).
func (w *trimWorld) log(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(w.dir, "log"))
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	return string(b)
}

// runTrim runs scripts/trim-ci-caches.sh with bash (it uses process
// substitution, which sh cannot run) and returns its output and exit code.
func (w *trimWorld) runTrim(t *testing.T, env map[string]string, args ...string) (string, int) {
	t.Helper()
	return runBashScript(t, mergeEnv(map[string]string{
		"PATH":             w.path,
		"FAKE_DOCKER":      w.dir,
		"REAP_DRY_RUN":     "",
		"IN_IMAGE_UID":     "",
		"CI_CACHE_MAX_GIB": "",
	}, env), "trim-ci-caches.sh", args...)
}

// runBashScript runs scripts/<name> with bash in a scratch directory, with
// env layered over the process environment, and returns its combined output
// and exit code.
func runBashScript(t *testing.T, env map[string]string, name string, args ...string) (string, int) {
	t.Helper()
	script := filepath.Join(repoRoot(t), "scripts", name)
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Dir = t.TempDir()
	cmd.Env = layerEnv(os.Environ(), env)
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

func requireLines(t *testing.T, out string, want ...string) {
	t.Helper()
	lines := strings.Split(out, "\n")
	for _, w := range want {
		found := false
		for _, l := range lines {
			if l == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("output lacks line %q:\n%s", w, out)
		}
	}
}

func requireNoSubstring(t *testing.T, what, s string, bad ...string) {
	t.Helper()
	for _, b := range bad {
		if strings.Contains(s, b) {
			t.Errorf("%s contains %q:\n%s", what, b, s)
		}
	}
}

func TestTrimCICaches_RefusesBadArgumentsWithoutDocker(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		args []string
	}{
		{"no arguments", nil, nil},
		{"empty prefix", nil, []string{"", "img"}},
		{"prefix with slash", nil, []string{"a/b-", "img"}},
		{"empty image", nil, []string{"p-", ""}},
		{"no image", nil, []string{"p-"}},
		{"max-gib not a number", nil, []string{"p-", "img", "x"}},
		{"CI_CACHE_MAX_GIB not a number", map[string]string{"CI_CACHE_MAX_GIB": "1g"}, []string{"p-", "img"}},
		{"root uid", map[string]string{"IN_IMAGE_UID": "0"}, []string{"p-", "img", "1"}},
		{"uid not numeric", map[string]string{"IN_IMAGE_UID": "abc"}, []string{"p-", "img", "1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newTrimWorld(t, []trimVolume{{name: "p-cache-a", kib: 64 * gib}})
			out, code := w.runTrim(t, tc.env, tc.args...)
			if code != 2 {
				t.Errorf("exit %d, want 2:\n%s", code, out)
			}
			if l := w.log(t); l != "" {
				t.Errorf("docker was called:\n%s", l)
			}
		})
	}
}

func TestTrimCICaches_UnderTheBoundRemovesNothing(t *testing.T) {
	w := newTrimWorld(t, []trimVolume{
		{name: "p-cache-a", kib: 20 * gib},
		{name: "p-cache-b", kib: 12 * gib},
	})
	// max-gib from the default, 32: 32 GiB is at the bound, not over it.
	out, code := w.runTrim(t, nil, "p-", "img")
	if code != 0 {
		t.Fatalf("exit %d, want 0:\n%s", code, out)
	}
	requireLines(t, out,
		"caches: 32 GiB of 32 GiB for prefix 'p-'",
		"trim: 0 volume(s), 32 GiB left for prefix 'p-'")
	requireNoSubstring(t, "output", out, "keep ", "trim  ", "dry ", "warn ")
	requireNoSubstring(t, "docker log", w.log(t), "volume rm", "ps ")
}

// overBound is 10.5 GiB of volumes against an 8 GiB bound: the largest is in
// use, the next cannot be removed, and the two after it bring the total under.
func overBound(t *testing.T) *trimWorld {
	return newTrimWorld(t, []trimVolume{
		{name: "p-cache-d", kib: 1 * gib},
		{name: "p-cache-a", kib: 4 * gib, inUse: true},
		{name: "p-other", kib: 50 * gib},
		{name: "p-cache-x"},
		{name: "p-cache-c", kib: 2 * gib},
		{name: "p-cache-e", kib: gib / 2},
		{name: "p-cache-b", kib: 3 * gib, unremovable: true},
	})
}

func TestTrimCICaches_OverTheBoundRemovesLargestUnusedFirst(t *testing.T) {
	w := overBound(t)
	out, code := w.runTrim(t, nil, "p-", "img", "8")
	if code != 0 {
		t.Fatalf("exit %d, want 0:\n%s", code, out)
	}
	requireLines(t, out,
		"warn  p-cache-x: size not read",
		"caches: 10 GiB of 8 GiB for prefix 'p-'",
		"keep  p-cache-a (4096 MiB, in use)",
		"warn  p-cache-b not removed",
		"trim  p-cache-c (2048 MiB)",
		"trim  p-cache-d (1024 MiB)",
		"trim: 2 volume(s), 7 GiB left for prefix 'p-'")
	requireNoSubstring(t, "output", out, "p-other", "p-cache-e", "dry ")
	if i, j := strings.Index(out, "trim  p-cache-c"), strings.Index(out, "trim  p-cache-d"); i < 0 || j < i {
		t.Errorf("p-cache-c (larger) not trimmed before p-cache-d:\n%s", out)
	}

	log := w.log(t)
	var rms []string
	for _, l := range strings.Split(log, "\n") {
		if strings.HasPrefix(l, "volume rm ") {
			rms = append(rms, strings.TrimPrefix(l, "volume rm "))
		}
	}
	if got, want := strings.Join(rms, ","), "p-cache-b,p-cache-c,p-cache-d"; got != want {
		t.Errorf("volume rm calls %q, want %q:\n%s", got, want, log)
	}
	// p-other is not a cache volume: never measured. p-cache-e is never
	// reached: the loop stops at the bound.
	requireNoSubstring(t, "docker log", log, "p-other", "volume=p-cache-e")
}

func TestTrimCICaches_DryRunPrintsAndRemovesNothing(t *testing.T) {
	w := overBound(t)
	out, code := w.runTrim(t, map[string]string{"REAP_DRY_RUN": "1"}, "p-", "img", "8")
	if code != 0 {
		t.Fatalf("exit %d, want 0:\n%s", code, out)
	}
	// Without a removal to fail, p-cache-b counts, and the total is under
	// the bound at once: p-cache-c is not taken.
	requireLines(t, out,
		"warn  p-cache-x: size not read",
		"keep  p-cache-a (4096 MiB, in use)",
		"dry   docker volume rm p-cache-b (3072 MiB)",
		"trim: 1 volume(s), 7 GiB left for prefix 'p-'")
	requireNoSubstring(t, "output", out, "trim  ", "p-cache-c", "p-cache-d", "p-cache-e", "not removed")
	requireNoSubstring(t, "docker log", w.log(t), "volume rm")
}

func TestTrimCICaches_MeasuresInALockedDownReadOnlyContainer(t *testing.T) {
	for _, tc := range []struct {
		uid, want string
	}{{"", "10001"}, {"4242", "4242"}} {
		w := newTrimWorld(t, []trimVolume{{name: "p-cache-a", kib: gib}})
		out, code := w.runTrim(t, map[string]string{"IN_IMAGE_UID": tc.uid}, "p-", "toolchain:1")
		if code != 0 {
			t.Fatalf("exit %d, want 0:\n%s", code, out)
		}
		var run string
		for _, l := range strings.Split(w.log(t), "\n") {
			if strings.HasPrefix(l, "run ") {
				run = " " + l + " "
			}
		}
		for _, want := range []string{
			" --rm ", " --network none ", " --cap-drop ALL ",
			" --security-opt no-new-privileges:true ",
			" --user " + tc.want + ":" + tc.want + " ",
			" -v p-cache-a:/c:ro ", " --entrypoint du toolchain:1 -sk /c ",
		} {
			if !strings.Contains(run, want) {
				t.Errorf("uid %q: du call lacks %q: %q", tc.uid, want, run)
			}
		}
	}
}
