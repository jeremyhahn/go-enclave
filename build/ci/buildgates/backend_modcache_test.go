package buildgates

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The toolchain image runs with GOPROXY=off: its module cache holds the graphs
// of the modules the Dockerfile copies a go.mod and go.sum for and downloads.
// A backend module the Dockerfile does not preload builds offline only when
// every module its go.sum names is already in that cache, so a backend that
// selects a version no preloaded module selects fails test, lint and
// cross-build in the image.

// preloadCopy matches the Dockerfile's `COPY <dir>/go.mod <dir>/go.sum ./`.
var preloadCopy = regexp.MustCompile(`^COPY\s+(\S*)go\.mod\s+(\S*)go\.sum\s+\./\s*$`)

// preloadedModuleDirs returns the module directories, relative to the
// repository root ("." for the root), whose graphs the Dockerfile downloads.
func preloadedModuleDirs(dockerfile string) []string {
	var dirs []string
	for _, line := range strings.Split(dockerfile, "\n") {
		m := preloadCopy.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil || m[1] != m[2] {
			continue
		}
		dir := strings.TrimSuffix(m[1], "/")
		if dir == "" {
			dir = "."
		}
		dirs = append(dirs, dir)
	}
	return dirs
}

// goSumEntries returns the "<module> <version>[/go.mod]" keys of a go.sum.
func goSumEntries(sum string) []string {
	var keys []string
	sc := bufio.NewScanner(strings.NewReader(sum))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 3 {
			continue
		}
		keys = append(keys, f[0]+" "+f[1])
	}
	return keys
}

// uncachedEntries returns the entries of sum that no cached go.sum carries.
func uncachedEntries(cached map[string]bool, sum string) []string {
	var missing []string
	for _, k := range goSumEntries(sum) {
		if !cached[k] {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	return missing
}

func readRepoFile(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func TestBackendModules_GraphInToolchainImageCache(t *testing.T) {
	root := repoRoot(t)
	dirs := preloadedModuleDirs(readRepoFile(t, root, devcontainerDockerfile))
	if len(dirs) == 0 {
		t.Fatalf("%s: no `COPY <dir>/go.mod <dir>/go.sum ./` line found", devcontainerDockerfile)
	}
	preloaded := map[string]bool{}
	cached := map[string]bool{}
	for _, d := range dirs {
		preloaded[d] = true
		for _, k := range goSumEntries(readRepoFile(t, root, filepath.Join(d, "go.sum"))) {
			cached[k] = true
		}
	}

	mods, err := filepath.Glob(filepath.Join(root, "backends", "*", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) == 0 {
		t.Fatal("no backends/*/go.mod found")
	}
	for _, mod := range mods {
		rel, err := filepath.Rel(root, filepath.Dir(mod))
		if err != nil {
			t.Fatal(err)
		}
		rel = filepath.ToSlash(rel)
		if preloaded[rel] {
			continue
		}
		sum := filepath.Join(rel, "go.sum")
		if _, err := os.Stat(filepath.Join(root, sum)); err != nil {
			t.Errorf("%s: no go.sum: %v", rel, err)
			continue
		}
		if missing := uncachedEntries(cached, readRepoFile(t, root, sum)); len(missing) > 0 {
			t.Errorf("%s selects modules the toolchain image does not cache (GOPROXY=off there); "+
				"align them with a preloaded module (%s) or preload %s in %s:\n  %s",
				rel, strings.Join(dirs, ", "), rel, devcontainerDockerfile, strings.Join(missing, "\n  "))
		}
	}
}

func TestBackendModules_UncachedEntriesNamesAStaleVersion(t *testing.T) {
	cached := map[string]bool{}
	for _, k := range goSumEntries("golang.org/x/sys v0.50.0 h1:a=\ngolang.org/x/sys v0.50.0/go.mod h1:b=\n") {
		cached[k] = true
	}
	got := uncachedEntries(cached, "golang.org/x/sys v0.49.0 h1:c=\ngolang.org/x/sys v0.49.0/go.mod h1:d=\ngolang.org/x/sys v0.50.0 h1:a=\n")
	want := []string{"golang.org/x/sys v0.49.0", "golang.org/x/sys v0.49.0/go.mod"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("uncachedEntries = %q, want %q", got, want)
	}
}

func TestBackendModules_PreloadedModuleDirsReadsCopyLines(t *testing.T) {
	df := "COPY go.mod go.sum ./\nCOPY build/ci/buildgates/go.mod build/ci/buildgates/go.sum ./\n" +
		"COPY backends/a/go.mod backends/b/go.sum ./\nCOPY --chown=root:root go.mod go.sum *.go ./\n"
	got := preloadedModuleDirs(df)
	want := []string{".", "build/ci/buildgates"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("preloadedModuleDirs = %q, want %q", got, want)
	}
}
