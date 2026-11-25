package buildgates

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestBackendModules_TheOfflineImagePreparesEach holds every module of the
// Makefile's BACKEND_MODULES to what the offline gates need from the
// toolchain image: the Dockerfile copies its go.mod and go.sum and downloads
// its dependencies, the build context's allowlist admits both files, the
// image's content key covers them, and it selects the golang.org/x/sys
// version the root does, so no gate asks GOPROXY=off for an archive the
// image never fetched.
func TestBackendModules_TheOfflineImagePreparesEach(t *testing.T) {
	root := repoRoot(t)
	read := func(rel string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	m := regexp.MustCompile(`(?m)^BACKEND_MODULES := (.+)$`).FindStringSubmatch(read("Makefile"))
	if m == nil {
		t.Fatal("Makefile: no BACKEND_MODULES := line")
	}
	modules := strings.Fields(m[1])
	if len(modules) == 0 {
		t.Fatal("Makefile: BACKEND_MODULES is empty")
	}
	sysVersion := func(gomod string) string {
		v := regexp.MustCompile(`(?m)^\s*(?:require\s+)?golang\.org/x/sys (v\S+)`).FindStringSubmatch(gomod)
		if v == nil {
			return ""
		}
		return v[1]
	}
	want := sysVersion(read("go.mod"))
	if want == "" {
		t.Fatal("go.mod: the root requires no golang.org/x/sys")
	}

	dockerfile := read("build/docker/devcontainer/Dockerfile")
	ignore := read("build/docker/devcontainer/Dockerfile.dockerignore")
	key := read("scripts/devcontainer.sh")
	for _, mod := range modules {
		t.Run(mod, func(t *testing.T) {
			if !strings.Contains(dockerfile, "WORKDIR /build/"+mod+"\nCOPY "+mod+"/go.mod "+mod+"/go.sum ./\nRUN ") {
				t.Errorf("Dockerfile: no WORKDIR /build/%s step that copies its go.mod and go.sum and downloads", mod)
			}
			for _, f := range []string{mod + "/go.mod", mod + "/go.sum"} {
				if !strings.Contains(ignore, "\n!"+f+"\n") {
					t.Errorf("Dockerfile.dockerignore: %s is not allowed into the build context", f)
				}
				if !strings.Contains(key, "\n    "+f+" \\\n") {
					t.Errorf("scripts/devcontainer.sh: %s is not in the image's content key", f)
				}
			}
			if got := sysVersion(read(mod + "/go.mod")); got != "" && got != want {
				t.Errorf("%s/go.mod selects golang.org/x/sys %s; the root and the image use %s", mod, got, want)
			}
		})
	}
}
