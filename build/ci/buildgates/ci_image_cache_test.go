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

// Tests for scripts/ci-image-cache.sh, the toolchain image's registry cache.
// In CI it logs in to the forge registry and pushes there; here it runs with
// bash against a fake make and a fake docker first on PATH. Both log every
// call (argv, DOCKER_CONFIG, whether that directory exists, and docker
// login's stdin) to a file, and per-case FAKE_* variables choose their
// answers, so no case reaches a real daemon or registry.

const (
	cacheServer = "https://forge.example"
	cacheNS     = "ci-images"
	cacheTag    = "go-enclave-toolchain:abc123"
	cacheRemote = "forge.example/" + cacheNS + "/" + cacheTag + "-main"
	cacheDigest = "forge.example/ci-images/go-enclave-toolchain@sha256:feed"
	cacheToken  = "s3cret-token-value"
)

const fakeCacheDocker = `#!/bin/sh
dir=no
if [ -n "${DOCKER_CONFIG:-}" ] && [ -d "$DOCKER_CONFIG" ]; then dir=yes; fi
printf 'docker\tcfg=%s\tdir=%s\t%s\n' "${DOCKER_CONFIG-<unset>}" "$dir" "$*" >> "$FAKE_LOG"
case "$1 $2" in
  "image inspect")
    if [ "$3" = --format ]; then
      [ "${FAKE_DIGEST_RC:-0}" = 0 ] || exit "$FAKE_DIGEST_RC"
      printf '%s\n' "$FAKE_DIGEST"
      exit 0
    fi
    exit "${FAKE_HAS_LOCAL:-1}" ;;
  "pull "*) exit "${FAKE_PULL_RC:-0}" ;;
  "manifest inspect") exit "${FAKE_MANIFEST_RC:-1}" ;;
  "login "*)
    stdin=$(cat)
    printf 'docker-stdin\t%s\n' "$stdin" >> "$FAKE_LOG"
    [ -z "${DOCKER_CONFIG:-}" ] || printf '{}' > "$DOCKER_CONFIG/config.json"
    exit 0 ;;
esac
exit 0
`

const fakeCacheMake = `#!/bin/sh
printf 'make\t%s\n' "$*" >> "$FAKE_LOG"
if [ "$1 $2" = "-s toolchain-image" ]; then
  [ "${FAKE_MAKE_RC:-0}" = 0 ] || exit "$FAKE_MAKE_RC"
  printf '%s\n' "$FAKE_TAG"
fi
exit 0
`

// cacheRun is one run of the script: its combined output, exit code and the
// fakes' log lines.
type cacheRun struct {
	out  string
	code int
	log  []string
}

// cacheEnvDrop are the variables the script reads; the runner's own values
// never leak into a case.
var cacheEnvDrop = []string{
	"GITHUB_SERVER_URL", "GITHUB_EVENT_NAME", "GITHUB_REF", "CI_IMAGE_NAMESPACE",
	"RELEASE_REGISTRY", "RELEASE_REGISTRY_USER", "RELEASE_REGISTRY_TOKEN",
	"DOCKER_CONFIG", "TMPDIR",
}

// cacheBase is the environment of a run that reaches the verb: a forge, a
// namespace and a tag.
func cacheBase() map[string]string {
	return map[string]string{
		"GITHUB_SERVER_URL":  cacheServer,
		"CI_IMAGE_NAMESPACE": cacheNS,
		"FAKE_TAG":           cacheTag,
		"FAKE_DIGEST":        cacheDigest,
	}
}

// cachePublishEnv adds the release runner's contract to cacheBase.
func cachePublishEnv() map[string]string {
	env := cacheBase()
	env["GITHUB_EVENT_NAME"] = "push"
	env["GITHUB_REF"] = "refs/heads/main"
	env["RELEASE_REGISTRY_USER"] = "release-bot"
	env["RELEASE_REGISTRY_TOKEN"] = cacheToken
	return env
}

func runImageCache(t *testing.T, env map[string]string, args ...string) cacheRun {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("bash is not on PATH: %v", err)
	}
	work := t.TempDir()
	bin := filepath.Join(work, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeExecutable(t, filepath.Join(bin, "docker"), []byte(fakeCacheDocker))
	writeExecutable(t, filepath.Join(bin, "make"), []byte(fakeCacheMake))
	tmp := filepath.Join(work, "tmp")
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	logPath := filepath.Join(work, "calls.log")

	base := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "FAKE_") || slices.Contains(cacheEnvDrop, k) {
			continue
		}
		base = append(base, kv)
	}
	over := map[string]string{
		"PATH":     bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"TMPDIR":   tmp,
		"FAKE_LOG": logPath,
	}
	for k, v := range env {
		over[k] = v
	}

	script := filepath.Join(repoRoot(t), "scripts", "ci-image-cache.sh")
	cmd := exec.Command(bash, append([]string{script}, args...)...)
	cmd.Dir = work
	cmd.Env = layerEnv(base, over)
	out, err := cmd.CombinedOutput()
	run := cacheRun{out: string(out)}
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("running %s: %v", script, err)
		}
		run.code = exitErr.ExitCode()
	}
	if data, err := os.ReadFile(logPath); err == nil {
		run.log = strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read log: %v", err)
	}

	// The throwaway DOCKER_CONFIG lives under TMPDIR; it is gone after
	// every run, whatever the exit.
	left, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatalf("read tmp: %v", err)
	}
	if len(left) != 0 {
		t.Errorf("the script left %d entries in TMPDIR (first %q); the DOCKER_CONFIG cleanup failed", len(left), left[0].Name())
	}
	// No docker call reaching the registry runs without the throwaway
	// DOCKER_CONFIG, and the token never sits in an argv.
	for _, line := range run.log {
		if strings.HasPrefix(line, "docker-stdin\t") {
			continue
		}
		if strings.Contains(line, cacheToken) {
			t.Errorf("the token appears in a logged argv: %q", line)
		}
		f := strings.SplitN(line, "\t", 4)
		if f[0] != "docker" || len(f) < 4 {
			continue
		}
		verb := f[3]
		if strings.HasPrefix(verb, "pull ") || strings.HasPrefix(verb, "push ") ||
			strings.HasPrefix(verb, "login ") || strings.HasPrefix(verb, "manifest ") {
			if !strings.HasPrefix(f[1], "cfg="+tmp+string(os.PathSeparator)) || f[2] != "dir=yes" {
				t.Errorf("registry call without the throwaway DOCKER_CONFIG under %s: %q", tmp, line)
			}
		}
	}
	return run
}

// dockerCalls returns the argv of every docker call, in order.
func (r cacheRun) dockerCalls() []string {
	var calls []string
	for _, line := range r.log {
		f := strings.SplitN(line, "\t", 4)
		if f[0] == "docker" && len(f) == 4 {
			calls = append(calls, f[3])
		}
	}
	return calls
}

// makeCalls returns the argv of every make call, in order.
func (r cacheRun) makeCalls() []string {
	var calls []string
	for _, line := range r.log {
		if rest, ok := strings.CutPrefix(line, "make\t"); ok {
			calls = append(calls, rest)
		}
	}
	return calls
}

func (r cacheRun) expect(t *testing.T, code int, wantOut string) {
	t.Helper()
	if r.code != code {
		t.Errorf("exit %d, want %d; output:\n%s", r.code, code, r.out)
	}
	if !strings.Contains(r.out, wantOut) {
		t.Errorf("output lacks %q:\n%s", wantOut, r.out)
	}
}

func (r cacheRun) expectDocker(t *testing.T, want ...string) {
	t.Helper()
	got := r.dockerCalls()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("docker calls:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

func TestImageCacheNoForge(t *testing.T) {
	for name, url := range map[string]string{"unset": "", "github.com": "https://github.com"} {
		t.Run(name, func(t *testing.T) {
			env := map[string]string{"CI_IMAGE_NAMESPACE": cacheNS, "FAKE_TAG": cacheTag}
			if url != "" {
				env["GITHUB_SERVER_URL"] = url
			}
			for _, verb := range []string{"pull", "publish"} {
				r := runImageCache(t, env, verb)
				r.expect(t, 0, "ci-image-cache: no forge registry on this host; nothing to do")
				if len(r.log) != 0 {
					t.Errorf("%s on %q called a tool: %q", verb, url, r.log)
				}
			}
		})
	}
}

func TestImageCacheDies(t *testing.T) {
	cases := []struct {
		name string
		env  func(map[string]string)
		args []string
		want string
	}{
		{"no namespace", func(e map[string]string) { delete(e, "CI_IMAGE_NAMESPACE") }, []string{"pull"},
			"ci-image-cache: CI_IMAGE_NAMESPACE is not set (the repository Actions variable)"},
		{"make fails", func(e map[string]string) { e["FAKE_MAKE_RC"] = "2" }, []string{"pull"},
			"ci-image-cache: make -s toolchain-image failed"},
		{"tag without colon", func(e map[string]string) { e["FAKE_TAG"] = "go-enclave-toolchain" }, []string{"pull"},
			"ci-image-cache: make -s toolchain-image printed 'go-enclave-toolchain', not <name>:<tag>"},
		{"no verb", func(map[string]string) {}, nil,
			"ci-image-cache: usage: ci-image-cache.sh pull | publish [make args]"},
		{"unknown verb", func(map[string]string) {}, []string{"push"},
			"ci-image-cache: usage: ci-image-cache.sh pull | publish [make args]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := cacheBase()
			c.env(env)
			r := runImageCache(t, env, c.args...)
			r.expect(t, 1, c.want)
			r.expectDocker(t)
		})
	}
}

func TestImageCachePull(t *testing.T) {
	t.Run("daemon holds the tag", func(t *testing.T) {
		env := cacheBase()
		env["FAKE_HAS_LOCAL"] = "0"
		r := runImageCache(t, env, "pull")
		r.expect(t, 0, "ci-image-cache: the daemon holds "+cacheTag+"; no pull")
		r.expectDocker(t, "image inspect "+cacheTag)
		if got := r.makeCalls(); len(got) != 1 || got[0] != "-s toolchain-image" {
			t.Errorf("make calls %q, want only -s toolchain-image", got)
		}
	})
	t.Run("pull fails", func(t *testing.T) {
		env := cacheBase()
		env["FAKE_PULL_RC"] = "1"
		r := runImageCache(t, env, "pull")
		r.expect(t, 1, "ci-image-cache: "+cacheRemote+" is not in the registry (or the pull failed); the job builds it")
		r.expectDocker(t, "image inspect "+cacheTag, "pull -q "+cacheRemote)
	})
	t.Run("pull works", func(t *testing.T) {
		r := runImageCache(t, cacheBase(), "pull")
		r.expect(t, 0, "ci-image-cache: pulled "+cacheDigest+" as "+cacheTag)
		r.expectDocker(t,
			"image inspect "+cacheTag,
			"pull -q "+cacheRemote,
			"image inspect --format {{index .RepoDigests 0}} "+cacheRemote,
			"tag "+cacheRemote+" "+cacheTag,
			"image rm "+cacheRemote)
	})
	t.Run("digest unknown", func(t *testing.T) {
		env := cacheBase()
		env["FAKE_DIGEST_RC"] = "1"
		r := runImageCache(t, env, "pull")
		r.expect(t, 0, "ci-image-cache: pulled unknown as "+cacheTag)
	})
	t.Run("server URL with a port and path", func(t *testing.T) {
		env := cacheBase()
		env["GITHUB_SERVER_URL"] = "https://forge.example:3000/sub"
		env["FAKE_PULL_RC"] = "1"
		r := runImageCache(t, env, "pull")
		r.expectDocker(t, "image inspect "+cacheTag, "pull -q forge.example:3000/"+cacheNS+"/"+cacheTag+"-main")
	})
}

func TestImageCachePublishRefused(t *testing.T) {
	cases := []struct {
		name string
		env  func(map[string]string)
		want string
	}{
		{"pull request", func(e map[string]string) { e["GITHUB_EVENT_NAME"] = "pull_request" },
			"ci-image-cache: publish runs on a push to main only"},
		{"no event", func(e map[string]string) { delete(e, "GITHUB_EVENT_NAME") },
			"ci-image-cache: publish runs on a push to main only"},
		{"other branch", func(e map[string]string) { e["GITHUB_REF"] = "refs/heads/dev" },
			"ci-image-cache: publish runs on a push to main only"},
		{"no user", func(e map[string]string) { delete(e, "RELEASE_REGISTRY_USER") },
			"ci-image-cache: RELEASE_REGISTRY_USER is not set (the release runner's env file exports it)"},
		{"no token", func(e map[string]string) { delete(e, "RELEASE_REGISTRY_TOKEN") },
			"ci-image-cache: RELEASE_REGISTRY_TOKEN is not set (the release runner's env file exports it)"},
		{"other registry", func(e map[string]string) { e["RELEASE_REGISTRY"] = "registry.example" },
			"ci-image-cache: RELEASE_REGISTRY is not this forge's registry; refusing the push"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := cachePublishEnv()
			c.env(env)
			r := runImageCache(t, env, "publish")
			r.expect(t, 1, c.want)
			r.expectDocker(t)
			if len(r.makeCalls()) != 1 {
				t.Errorf("make calls %q, want only the tag lookup", r.makeCalls())
			}
		})
	}
}

func TestImageCachePublish(t *testing.T) {
	t.Run("registry holds the manifest", func(t *testing.T) {
		env := cachePublishEnv()
		env["FAKE_MANIFEST_RC"] = "0"
		r := runImageCache(t, env, "publish", "EXTRA=1")
		r.expect(t, 0, "ci-image-cache: the registry holds "+cacheRemote+"; nothing to publish")
		r.expectDocker(t, "manifest inspect "+cacheRemote)
		if len(r.makeCalls()) != 1 {
			t.Errorf("make calls %q: a held manifest builds nothing", r.makeCalls())
		}
	})
	for _, registry := range []string{"", "forge.example"} {
		t.Run("builds and pushes, RELEASE_REGISTRY="+registry, func(t *testing.T) {
			env := cachePublishEnv()
			if registry != "" {
				env["RELEASE_REGISTRY"] = registry
			}
			r := runImageCache(t, env, "publish", "TOOLCHAIN_ARGS=--pull", "V=1")
			r.expect(t, 0, "ci-image-cache: published "+cacheTag+" as "+cacheDigest)
			if got := r.makeCalls(); len(got) != 2 || got[1] != "docker-build-toolchain TOOLCHAIN_ARGS=--pull V=1" {
				t.Errorf("make calls %q, want the build with the extra args", got)
			}
			r.expectDocker(t,
				"manifest inspect "+cacheRemote,
				"login forge.example -u release-bot --password-stdin",
				"tag "+cacheTag+" "+cacheRemote,
				"push -q "+cacheRemote,
				"image inspect --format {{index .RepoDigests 0}} "+cacheRemote,
				"image rm "+cacheRemote)
			var stdin []string
			for _, line := range r.log {
				if s, ok := strings.CutPrefix(line, "docker-stdin\t"); ok {
					stdin = append(stdin, s)
				}
			}
			if len(stdin) != 1 || stdin[0] != cacheToken {
				t.Errorf("login stdin %q, want the token once", stdin)
			}
			if strings.Contains(r.out, cacheToken) {
				t.Errorf("the token appears in the output:\n%s", r.out)
			}
		})
	}
}
