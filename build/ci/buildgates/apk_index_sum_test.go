package buildgates

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// fakeDockerScript stands in for docker in scripts/apk-index-sum.sh. It logs
// the image of each run (the word before -c) to FAKE_DOCKER_LOG and the whole
// command line to FAKE_DOCKER_LOG.args, then answers from FAKE_DOCKER_FIXTURE,
// one "image kind" line per image: kind "none" prints none, "fail" exits 3,
// any other word prints a repository line and an index checksum line built
// from it. An image the fixture does not list prints none.
const fakeDockerScript = `#!/bin/sh
prev=
img=
for a do
  if [ "$a" = -c ]; then img=$prev; break; fi
  prev=$a
done
printf '%s\n' "$img" >> "$FAKE_DOCKER_LOG"
printf '%s\n' "$*" >> "$FAKE_DOCKER_LOG.args"
if [ -f "${FAKE_DOCKER_FIXTURE:-}" ]; then
  while read -r name kind; do
    [ "$name" = "$img" ] || continue
    case $kind in
      none) echo none; exit 0 ;;
      fail) exit 3 ;;
      *) echo "https://dl.example/alpine/main"; echo "$kind APKINDEX.0.tar.gz"; exit 0 ;;
    esac
  done < "$FAKE_DOCKER_FIXTURE"
fi
echo none
`

type apkRun struct {
	stdout, stderr string
	code           int
	log            string // the fake docker's image log path
}

// images returns the images the fake docker was asked to run, in order.
func (r apkRun) images(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(r.log)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(b))
}

// runApkIndexSum runs scripts/apk-index-sum.sh with bash in dir, with the
// fake docker first on PATH answering from fixture ("" for none).
func runApkIndexSum(t *testing.T, dir, fixture string, env map[string]string, args ...string) apkRun {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Fatalf("bash is required to run scripts/apk-index-sum.sh: %v", err)
	}
	bin := t.TempDir()
	writeExecutable(t, filepath.Join(bin, "docker"), []byte(fakeDockerScript))
	logPath := filepath.Join(t.TempDir(), "docker.log")
	over := map[string]string{
		"PATH":            bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"FAKE_DOCKER_LOG": logPath,
		"APK_BASE_IMAGES": "",
		"APK_DOCKERFILE":  "",
	}
	if fixture != "" {
		fp := filepath.Join(t.TempDir(), "fixture")
		if err := os.WriteFile(fp, []byte(fixture), 0o644); err != nil {
			t.Fatal(err)
		}
		over["FAKE_DOCKER_FIXTURE"] = fp
	}
	for k, v := range env {
		over[k] = v
	}
	script := filepath.Join(repoRoot(t), "scripts", "apk-index-sum.sh")
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Dir = dir
	cmd.Env = layerEnv(os.Environ(), over)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("running %s: %v", script, err)
		}
		code = exitErr.ExitCode()
	}
	return apkRun{stdout: stdout.String(), stderr: stderr.String(), code: code, log: logPath}
}

// writeDockerfile writes content as a Dockerfile in a new directory and
// returns its path.
func writeDockerfile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "Dockerfile")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestApkIndexSumParsesFromLines(t *testing.T) {
	df := writeDockerfile(t, `# syntax=docker/dockerfile:1
ARG X=img:1
ARG Q="img:4" UNUSED
FROM $X
FROM ${X}
FROM ${Y:-img:2}
FROM --platform=$BUILDPLATFORM img:3 AS build
FROM build
FROM scratch
FROM img:3
FROM \
  img:5
# FROM img:commented
   # FROM img:indented-comment
ARG X=img:6
FROM $X
FROM ${Q}
from img:8 as Base
FROM base
`)
	r := runApkIndexSum(t, t.TempDir(), "", nil, df)
	if r.code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", r.code, r.stderr)
	}
	want := []string{"img:1", "img:2", "img:3", "img:5", "img:4", "img:8"}
	if got := r.images(t); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("probed %q, want %q", got, want)
	}
	if r.stdout != "none\n" {
		t.Fatalf("stdout %q, want none", r.stdout)
	}
}

func TestApkIndexSumDockerfileFromEnv(t *testing.T) {
	df := writeDockerfile(t, "FROM img:env\n")
	r := runApkIndexSum(t, t.TempDir(), "", map[string]string{"APK_DOCKERFILE": df})
	if r.code != 0 || strings.Join(r.images(t), " ") != "img:env" {
		t.Fatalf("exit %d, probed %q, stderr:\n%s", r.code, r.images(t), r.stderr)
	}
}

func TestApkIndexSumRefusals(t *testing.T) {
	cases := []struct {
		name, dockerfile, msg string
	}{
		{"no dockerfile", "", "no Dockerfile at"},
		{"from without image", "FROM\n", "names no image"},
		{"from with only flags", "FROM --platform=linux/amd64\n", "names no image"},
		{"arg without default", "ARG BASE\nFROM ${BASE}\n", "names $BASE, which has no global ARG default"},
		{"arg after from", "FROM img:1\nARG LATE=img:2\nFROM $LATE\n", "names $LATE, which has no global ARG default"},
		{"only scratch", "FROM scratch\n", "no base image found"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			df := filepath.Join(t.TempDir(), "missing", "Dockerfile")
			if c.dockerfile != "" {
				df = writeDockerfile(t, c.dockerfile)
			}
			r := runApkIndexSum(t, t.TempDir(), "", nil, df)
			if r.code != 1 {
				t.Fatalf("exit %d, want 1; stderr:\n%s", r.code, r.stderr)
			}
			if !strings.Contains(r.stderr, "::error::apk-index-sum: ") || !strings.Contains(r.stderr, c.msg) {
				t.Fatalf("stderr %q lacks the error line %q", r.stderr, c.msg)
			}
			if got := r.images(t); len(got) != 0 {
				t.Fatalf("docker ran %q before the refusal", got)
			}
			if r.stdout != "" {
				t.Fatalf("stdout %q on a refusal", r.stdout)
			}
		})
	}
}

func TestApkIndexSumBaseImagesSkipParser(t *testing.T) {
	// A Dockerfile the parser would refuse: APK_BASE_IMAGES must win.
	df := writeDockerfile(t, "FROM ${NODEFAULT}\n")
	r := runApkIndexSum(t, t.TempDir(), "", map[string]string{"APK_BASE_IMAGES": "a b"}, df)
	if r.code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", r.code, r.stderr)
	}
	if got := strings.Join(r.images(t), " "); got != "a b" {
		t.Fatalf("probed %q, want \"a b\"", got)
	}
	// And no Dockerfile at all.
	r = runApkIndexSum(t, t.TempDir(), "", map[string]string{"APK_BASE_IMAGES": "c"}, filepath.Join(t.TempDir(), "nope"))
	if r.code != 0 || strings.Join(r.images(t), " ") != "c" {
		t.Fatalf("exit %d, probed %q, stderr:\n%s", r.code, r.images(t), r.stderr)
	}
}

func TestApkIndexSumOutput(t *testing.T) {
	df := writeDockerfile(t, "FROM img:a\nFROM img:b\n")
	sum := func(t *testing.T, fixture string) apkRun {
		t.Helper()
		r := runApkIndexSum(t, t.TempDir(), fixture, nil, df)
		if r.code != 0 {
			t.Fatalf("exit %d, stderr:\n%s", r.code, r.stderr)
		}
		return r
	}

	t.Run("all none", func(t *testing.T) {
		if r := sum(t, "img:a none\nimg:b none\n"); r.stdout != "none\n" {
			t.Fatalf("stdout %q, want none", r.stdout)
		}
	})

	t.Run("one alpine", func(t *testing.T) {
		r := sum(t, "img:a none\nimg:b aaaa\n")
		hexSum := regexp.MustCompile(`^[0-9a-f]{64}\n$`)
		if !hexSum.MatchString(r.stdout) {
			t.Fatalf("stdout %q, want one sha256", r.stdout)
		}
		input := "img:a\nnone\nimg:b\nhttps://dl.example/alpine/main\naaaa APKINDEX.0.tar.gz\n"
		h := sha256.Sum256([]byte(input))
		if want := hex.EncodeToString(h[:]) + "\n"; r.stdout != want {
			t.Fatalf("stdout %q, want %q", r.stdout, want)
		}
		if !strings.Contains(r.stderr, "apk-index-sum: img:b: 1 index file(s)") ||
			!strings.Contains(r.stderr, "apk-index-sum: img:a: 0 index file(s)") {
			t.Fatalf("stderr lacks the per-image index counts:\n%s", r.stderr)
		}
		if again := sum(t, "img:a none\nimg:b aaaa\n"); again.stdout != r.stdout {
			t.Fatalf("sum not stable: %q then %q", r.stdout, again.stdout)
		}
		if changed := sum(t, "img:a none\nimg:b bbbb\n"); changed.stdout == r.stdout {
			t.Fatalf("sum %q did not change with the index", r.stdout)
		}
	})

	t.Run("failing probe", func(t *testing.T) {
		r := runApkIndexSum(t, t.TempDir(), "img:a fail\nimg:b aaaa\n", nil, df)
		if r.code != 1 {
			t.Fatalf("exit %d, want 1", r.code)
		}
		if !strings.Contains(r.stderr, "::error::apk-index-sum: reading the Alpine package index of img:a failed (exit 3)") {
			t.Fatalf("stderr does not name the image:\n%s", r.stderr)
		}
		if r.stdout != "" {
			t.Fatalf("stdout %q on a failure", r.stdout)
		}
		if got := strings.Join(r.images(t), " "); got != "img:a" {
			t.Fatalf("probed %q after the failure, want only img:a", got)
		}
	})
}

func TestApkIndexSumDockerRunFlags(t *testing.T) {
	r := runApkIndexSum(t, t.TempDir(), "", map[string]string{"APK_BASE_IMAGES": "img:x"})
	if r.code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", r.code, r.stderr)
	}
	b, err := os.ReadFile(r.log + ".args")
	if err != nil {
		t.Fatal(err)
	}
	args := string(b)
	if !strings.HasPrefix(args, "run --rm ") {
		t.Fatalf("docker was not asked to run: %q", args)
	}
	for _, flag := range []string{
		"--network bridge",
		"--cap-drop ALL",
		"--security-opt no-new-privileges",
		"--entrypoint /bin/sh img:x -c ",
	} {
		if !strings.Contains(args, flag) {
			t.Errorf("docker run lacks %q: %q", flag, args)
		}
	}
}
