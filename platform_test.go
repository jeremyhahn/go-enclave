// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"errors"
	"go/build"
	"os"
	"slices"
	"strings"
	"testing"
)

// knownGOOS is every GOOS go/build accepts. hurd and zos are not ports but
// are listed because hurd satisfies the unix meta-tag.
var knownGOOS = []string{
	"aix", "android", "darwin", "dragonfly", "freebsd", "hurd", "illumos", "ios",
	"js", "linux", "netbsd", "openbsd", "plan9", "solaris", "wasip1", "windows", "zos",
}

// supportedGOOS is every GOOS where x/sys provides the memory primitives.
// android, ios and illumos are implied by linux, darwin and solaris.
var supportedGOOS = []string{
	"aix", "android", "darwin", "dragonfly", "freebsd", "illumos", "ios",
	"linux", "netbsd", "openbsd", "solaris", "windows",
}

// runtimeSecretTag is the tag GOEXPERIMENT=runtimesecret adds to a build.
const runtimeSecretTag = "goexperiment.runtimesecret"

// platformBuild is one build the layer must resolve: a GOOS, a GOARCH and the
// extra build tags.
type platformBuild struct {
	goos, goarch string
	tags         []string
}

func (b platformBuild) String() string {
	return b.goos + "/" + b.goarch + " tags=" + strings.Join(b.tags, ",")
}

// matchingFiles reports which of files go/build would compile for b, applying
// build lines, file-name suffixes and GOOS implications. The toolchain's own
// experiment tags are cleared, so the result does not depend on how the test
// was started.
func matchingFiles(t *testing.T, b platformBuild, files []string) []string {
	t.Helper()
	ctxt := build.Default
	ctxt.GOOS, ctxt.GOARCH, ctxt.CgoEnabled = b.goos, b.goarch, false
	ctxt.ToolTags, ctxt.BuildTags = nil, b.tags
	var matched []string
	for _, f := range files {
		ok, err := ctxt.MatchFile(".", f)
		if err != nil {
			t.Fatalf("MatchFile(%s) for %s: %v", f, b, err)
		}
		if ok {
			matched = append(matched, f)
		}
	}
	return matched
}

// globGo lists the non-test .go files in the package directory whose names
// start with prefix.
func globGo(prefix string) ([]string, error) {
	entries, err := os.ReadDir(".")
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			files = append(files, name)
		}
	}
	return files, nil
}

// platformFamily is one concern of the platform layer. Every build compiles
// exactly one of its implementation files, chosen by want; shared, when set,
// holds the code those implementations have in common and is compiled exactly
// when the implementation is not the catch-all.
type platformFamily struct {
	// concern is the file-name prefix, without the underscore.
	concern string
	// shared is the file the real implementations have in common, or "".
	shared string
	// catchAll is the file compiled where no named platform file is.
	catchAll string
	// want names the one implementation file the build must compile.
	want func(platformBuild) string
}

// platformFamilies is the whole layer: a file named <concern>_*.go that is not
// listed here is an implementation of that concern and is held to the rule.
var platformFamilies = []platformFamily{
	{
		concern:  "osmem",
		catchAll: "osmem_unsupported.go",
		want: func(b platformBuild) string {
			switch {
			case b.goos == "windows":
				return "osmem_windows.go"
			case slices.Contains(supportedGOOS, b.goos):
				return "osmem_unix.go"
			}
			return "osmem_unsupported.go"
		},
	},
	{
		concern:  "madvise",
		shared:   "madvise_unix.go",
		catchAll: "madvise_unsupported.go",
		want: func(b platformBuild) string {
			switch b.goos {
			case "linux", "android":
				return "madvise_linux.go"
			case "dragonfly", "freebsd":
				return "madvise_bsd.go"
			case "openbsd":
				return "madvise_openbsd.go"
			}
			return "madvise_unsupported.go"
		},
	},
	{
		concern:  "memlock",
		shared:   "memlock_unix.go",
		catchAll: "memlock_unsupported.go",
		want: func(b platformBuild) string {
			switch b.goos {
			case "linux", "android":
				return "memlock_linux.go"
			case "darwin", "ios", "dragonfly", "freebsd", "netbsd", "openbsd":
				return "memlock_bsd.go"
			}
			return "memlock_unsupported.go"
		},
	},
	{
		concern:  "harden",
		catchAll: "harden_unsupported.go",
		want: func(b platformBuild) string {
			if b.goos == "linux" || b.goos == "android" {
				return "harden_linux.go"
			}
			return "harden_unsupported.go"
		},
	},
	{
		// The Makefile's test-runtimesecret target names these two files, so
		// they keep their names; the erasing build is linux, not android, on
		// amd64 or arm64, with the experiment on.
		concern:  "secret",
		catchAll: "secret_noerase.go",
		want: func(b platformBuild) string {
			erases := b.goos == "linux" &&
				(b.goarch == "amd64" || b.goarch == "arm64") &&
				slices.Contains(b.tags, runtimeSecretTag)
			if erases {
				return "secret_erase.go"
			}
			return "secret_noerase.go"
		},
	},
}

// platformBuilds is every GOOS with and without the experiment, on the two
// architectures the erasing build names and one it does not.
func platformBuilds() []platformBuild {
	var builds []platformBuild
	for _, goos := range knownGOOS {
		for _, goarch := range []string{"amd64", "arm64", "386"} {
			builds = append(builds,
				platformBuild{goos: goos, goarch: goarch},
				platformBuild{goos: goos, goarch: goarch, tags: []string{runtimeSecretTag}})
		}
	}
	return builds
}

// TestPlatformLayer_EveryGOOSHasExactlyOneImplementation pins that, for every
// concern of the platform layer and every GOOS, exactly one implementation file
// is compiled, and it is the one the contract names: a real one for the
// supported set, the _unsupported catch-all otherwise. A family's shared file
// is compiled with every real implementation and never with the catch-all.
func TestPlatformLayer_EveryGOOSHasExactlyOneImplementation(t *testing.T) {
	for _, fam := range platformFamilies {
		t.Run(fam.concern, func(t *testing.T) {
			files, err := globGo(fam.concern + "_")
			if err != nil {
				t.Fatalf("listing the %s files: %v", fam.concern, err)
			}
			impls := slices.DeleteFunc(slices.Clone(files), func(f string) bool { return f == fam.shared })
			if len(impls) < 2 {
				t.Fatalf("found %d %s implementations %v; the test would be vacuous", len(impls), fam.concern, impls)
			}
			if !slices.Contains(impls, fam.catchAll) {
				t.Fatalf("the catch-all %s is missing from %v", fam.catchAll, impls)
			}
			if fam.shared != "" && !slices.Contains(files, fam.shared) {
				t.Fatalf("the shared file %s is missing from %v", fam.shared, files)
			}

			for _, b := range platformBuilds() {
				want := fam.want(b)
				if !slices.Contains(impls, want) {
					t.Errorf("%s: the contract names %s, which is not among %v", b, want, impls)
					continue
				}
				got := matchingFiles(t, b, impls)
				if len(got) != 1 || got[0] != want {
					t.Errorf("%s compiles %v, want exactly [%s]", b, got, want)
				}
				if fam.shared == "" {
					continue
				}
				compiled := len(matchingFiles(t, b, []string{fam.shared})) == 1
				if compiled != (want != fam.catchAll) {
					t.Errorf("%s: %s compiled = %v with implementation %s", b, fam.shared, compiled, want)
				}
			}
		})
	}
}

// TestPlatformLayer_NoRetiredNames pins the one naming scheme: a file's platform
// is its suffix (_linux, _bsd, _openbsd, _unix, _windows), and the only
// catch-all is _unsupported. _other and _nocore, which each meant something
// different from file to file, do not return, in this package or its
// subpackages.
func TestPlatformLayer_NoRetiredNames(t *testing.T) {
	for _, dir := range []string{".", "providertest"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		for _, e := range entries {
			name := strings.TrimSuffix(strings.TrimSuffix(e.Name(), ".go"), "_test")
			for _, retired := range []string{"_other", "_nocore"} {
				if strings.HasSuffix(name, retired) {
					t.Errorf("%s/%s uses the retired suffix %s; name it by platform, or _unsupported for the catch-all", dir, e.Name(), retired)
				}
			}
		}
	}
}

// TestProtectionTable_TranslatesEachProtectionAndRefusesTheRest pins the one
// switch every platform's table goes through.
func TestProtectionTable_TranslatesEachProtectionAndRefusesTheRest(t *testing.T) {
	table := protectionTable[string]{noAccess: "none", readOnly: "ro", readWrite: "rw"}
	for p, want := range map[protection]string{protNoAccess: "none", protReadOnly: "ro", protReadWrite: "rw"} {
		if got, err := table.translate(p); err != nil || got != want {
			t.Errorf("translate(%d) = %q, %v, want %q", p, got, err, want)
		}
	}
	for _, p := range []protection{0, protReadWrite + 1, 0xFF} {
		if got, err := table.translate(p); !errors.Is(err, errInvalidProtection) || got != "" {
			t.Errorf("translate(%d) = %q, %v, want errInvalidProtection and the zero value", p, got, err)
		}
	}
}
