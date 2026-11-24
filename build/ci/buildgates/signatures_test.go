package buildgates

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// The commit signature gate: .github/workflows/signatures.yml. These tests run
// its verify step, as written, on scratch repositories. The toolchain image
// that runs the gates has no ssh-keygen and no network, so a stand-in
// ssh-keygen and a stand-in curl sit first on PATH (signaturesFakeKeygen,
// signaturesFakeCurl). The workflow's own logic, which commit's registry it
// trusts and which commits it checks against it, is what runs.
const (
	signaturesWorkflowFile = ".github/workflows/signatures.yml"
	signaturesStep         = "Verify commit signatures against .github/allowed_signers"
	signaturesRegistry     = ".github/allowed_signers"
)

type signaturesWorkflow struct {
	Jobs map[string]struct {
		Steps []struct {
			Name string `yaml:"name"`
			Run  string `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// signaturesScript returns the run: block of the verify step.
func signaturesScript(src []byte) (string, error) {
	var wf signaturesWorkflow
	if err := yaml.Unmarshal(src, &wf); err != nil {
		return "", err
	}
	for _, job := range wf.Jobs {
		for _, st := range job.Steps {
			if st.Name == signaturesStep {
				return st.Run, nil
			}
		}
	}
	return "", fmt.Errorf("no step named %q", signaturesStep)
}

// signaturesFakeKeygen stands in for `ssh-keygen -Y`. A key file holds a key
// id; a signature names that id and the sha256 of what it signs. An
// allowed-signers line is `principal keytype <id>`. find-principals lists
// the principals registered to the signature's id; verify accepts when the
// payload's hash matches and the principal is registered to that id, and
// prints the line git parses for %GS.
const signaturesFakeKeygen = `#!/usr/bin/env bash
set -u
op= f= s= I= last=
for a in "$@"; do last=$a; done
while [ $# -gt 0 ]; do
  case $1 in
    -Y) op=$2; shift 2 ;;
    -f) f=$2; shift 2 ;;
    -s) s=$2; shift 2 ;;
    -I) I=$2; shift 2 ;;
    -n|-O) shift 2 ;;
    *) shift ;;
  esac
done
sig_id() { local l n=0; while IFS= read -r l; do n=$((n+1)); [ $n = 2 ] && { printf '%s' "${l%% *}"; return; }; done < "$s"; }
sig_hash() { local l n=0; while IFS= read -r l; do n=$((n+1)); [ $n = 2 ] && { printf '%s' "${l#* }"; return; }; done < "$s"; }
registered() { # principal id: is the principal registered to the id (empty principal: any)
  local p t k
  while read -r p t k; do
    case $p in ''|'#'*) continue ;; esac
    [ "$k" = "$2" ] || continue
    if [ -z "$1" ]; then printf '%s\n' "$p"; found=1; elif [ "$p" = "$1" ]; then return 0; fi
  done < "$f"
  [ -n "${found:-}" ]
}
case $op in
  sign)
    h=$(sha256sum < "$last"); h=${h%% *}
    printf -- '-----BEGIN SSH SIGNATURE-----\n%s %s\n-----END SSH SIGNATURE-----\n' "$(cat "$f")" "$h" > "$last.sig" ;;
  find-principals)
    registered "" "$(sig_id)" ;;
  verify)
    h=$(sha256sum); h=${h%% *}
    if [ "$h" = "$(sig_hash)" ] && registered "$I" "$(sig_id)"; then
      printf 'Good "git" signature for %s with ED25519 key SHA256:%s\n' "$I" "$(sig_id)"; exit 0
    fi
    echo "Could not verify signature." >&2; exit 255 ;;
  *) exit 255 ;;
esac
`

// signaturesFakeCurl stands in for the commits API: a commit listed in
// $SIG_VERIFIED is verified and committed by web-flow, any other is not.
const signaturesFakeCurl = `#!/usr/bin/env bash
url=
for a in "$@"; do url=$a; done
c=${url##*/commits/}
while IFS= read -r v; do
  if [ "$v" = "$c" ]; then
    echo '{"commit":{"verification":{"verified":true,"reason":"valid"}},"committer":{"login":"web-flow"}}'; exit 0
  fi
done < "$SIG_VERIFIED"
echo '{"commit":{"verification":{"verified":false,"reason":"unsigned"}},"committer":{"login":"web-flow"}}'
`

const (
	sigAlice   = "alice@example.com"
	sigMallory = "mallory@example.com"
	sigGitHub  = "noreply@github.com"
	sigKeyA    = "KEYA"
	sigKeyM    = "KEYM"
)

// A registry naming alice's key only, and one naming mallory's only.
var (
	sigRegistryA = sigAlice + " ssh-ed25519 " + sigKeyA + "\n"
	sigRegistryM = sigMallory + " ssh-ed25519 " + sigKeyM + "\n"
)

type sigRepo struct {
	dir, bin, verified string
	keys               map[string]string // key id -> key file
	env                []string
}

func newSigRepo(t *testing.T) *sigRepo {
	t.Helper()
	root := t.TempDir()
	r := &sigRepo{dir: filepath.Join(root, "repo"), bin: filepath.Join(root, "bin"), verified: filepath.Join(root, "verified"), keys: map[string]string{}}
	for _, d := range []string{r.dir, r.bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"ssh-keygen": signaturesFakeKeygen, "curl": signaturesFakeCurl} {
		if err := os.WriteFile(filepath.Join(r.bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(r.verified, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{sigKeyA, sigKeyM} {
		r.keys[k] = filepath.Join(root, k)
		if err := os.WriteFile(r.keys[k], []byte(k), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r.env = []string{
		"PATH=" + r.bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + root, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"SIG_VERIFIED=" + r.verified,
	}
	r.git(t, nil, "init", "-q", "-b", "main")
	return r
}

func (r *sigRepo) git(t *testing.T, extra []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = r.dir
	cmd.Env = append(append([]string{}, r.env...), extra...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// commit writes files (path, content pairs; an empty content removes the
// path) and commits them as committer, signed with key, or unsigned when key
// is empty. A commit by GitHub is listed as verified when verified is set.
func (r *sigRepo) commit(t *testing.T, committer, key string, verified bool, files ...string) string {
	t.Helper()
	for i := 0; i+1 < len(files); i += 2 {
		p := filepath.Join(r.dir, files[i])
		if files[i+1] == "" {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(files[i+1]), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r.git(t, nil, "add", "-A")
	who := []string{"GIT_AUTHOR_NAME=a", "GIT_AUTHOR_EMAIL=" + sigAlice, "GIT_COMMITTER_NAME=c", "GIT_COMMITTER_EMAIL=" + committer}
	args := []string{"-c", "gpg.format=ssh", "commit", "-q", "--allow-empty", "-m", "change"}
	if key != "" {
		args = append([]string{"-c", "user.signingkey=" + r.keys[key]}, append(args, "-S")...)
	} else {
		args = append(args, "--no-gpg-sign")
	}
	r.git(t, who, args...)
	sha := r.git(t, nil, "rev-parse", "HEAD")
	if verified {
		f, err := os.OpenFile(r.verified, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = fmt.Fprintln(f, sha)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return sha
}

// run runs the step for an event: before and head are the push's before and
// sha, or the pull request's base and head.
func (r *sigRepo) run(t *testing.T, script, event, before, head string) (string, bool) {
	t.Helper()
	env := append([]string{}, r.env...)
	env = append(env, "EVENT="+event, "HEAD_SHA="+head, "RUNNER_TEMP="+t.TempDir(),
		"REPO=example/repo", "API=http://api.invalid", "GH_TOKEN=token")
	if event == "push" {
		env = append(env, "BEFORE="+before, "PR=", "BASE_SHA=")
	} else {
		env = append(env, "BEFORE=", "PR=1", "BASE_SHA="+before)
	}
	cmd := exec.Command("bash", "-e", "-c", script)
	cmd.Dir = r.dir
	cmd.Env = env
	b, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatalf("bash: %v", err)
	}
	return string(b), err != nil
}

type sigCase struct {
	name     string
	event    string
	build    func(t *testing.T, r *sigRepo) (before, head string)
	wantFail bool
	want     string
}

var sigCases = []sigCase{
	{
		name: "adoption: the squash merge that adds the registry, verified as GitHub's",
		build: func(t *testing.T, r *sigRepo) (string, string) {
			before := r.commit(t, sigAlice, "", false, "README", "x")
			return before, r.commit(t, sigGitHub, "", true, signaturesRegistry, sigRegistryA, "ci.yml", "y")
		},
		want: "OK",
	},
	{
		name: "adoption: a commit signed by a key the registry it adds names",
		build: func(t *testing.T, r *sigRepo) (string, string) {
			before := r.commit(t, sigAlice, "", false, "README", "x")
			return before, r.commit(t, sigAlice, sigKeyA, false, signaturesRegistry, sigRegistryA)
		},
		want: "OK",
	},
	{
		name: "adoption: two commits, both signed by registered keys",
		build: func(t *testing.T, r *sigRepo) (string, string) {
			before := r.commit(t, sigAlice, "", false, "README", "x")
			r.commit(t, sigAlice, sigKeyA, false, signaturesRegistry, sigRegistryA)
			return before, r.commit(t, sigAlice, sigKeyA, false, "README", "z")
		},
		want: "OK",
	},
	{
		name: "adoption: signed by a key the registry it adds does not name",
		build: func(t *testing.T, r *sigRepo) (string, string) {
			before := r.commit(t, sigAlice, "", false, "README", "x")
			return before, r.commit(t, sigMallory, sigKeyM, false, signaturesRegistry, sigRegistryA)
		},
		wantFail: true, want: "signed by a key not in the registry",
	},
	{
		name: "adoption: an unsigned commit",
		build: func(t *testing.T, r *sigRepo) (string, string) {
			before := r.commit(t, sigAlice, "", false, "README", "x")
			return before, r.commit(t, sigAlice, "", false, signaturesRegistry, sigRegistryA)
		},
		wantFail: true, want: "unsigned",
	},
	{
		name: "adoption: a GitHub commit the API does not verify",
		build: func(t *testing.T, r *sigRepo) (string, string) {
			before := r.commit(t, sigAlice, "", false, "README", "x")
			return before, r.commit(t, sigGitHub, "", false, signaturesRegistry, sigRegistryA)
		},
		wantFail: true, want: "not verified",
	},
	{
		name: "adoption: a later commit of the push signed by an unregistered key",
		build: func(t *testing.T, r *sigRepo) (string, string) {
			before := r.commit(t, sigAlice, "", false, "README", "x")
			r.commit(t, sigAlice, sigKeyA, false, signaturesRegistry, sigRegistryA)
			return before, r.commit(t, sigMallory, sigKeyM, false, "README", "z")
		},
		wantFail: true, want: "signed by a key not in the registry",
	},
	{
		name: "no adoption after a removal: the before's history had a registry",
		build: func(t *testing.T, r *sigRepo) (string, string) {
			r.commit(t, sigAlice, "", false, "README", "x")
			r.commit(t, sigAlice, sigKeyA, false, signaturesRegistry, sigRegistryA)
			before := r.commit(t, sigAlice, sigKeyA, false, signaturesRegistry, "")
			return before, r.commit(t, sigMallory, sigKeyM, false, signaturesRegistry, sigRegistryM)
		},
		wantFail: true, want: "FAIL no .github/allowed_signers",
	},
	{
		name: "the registry at the before: a registered key passes",
		build: func(t *testing.T, r *sigRepo) (string, string) {
			before := r.commit(t, sigAlice, sigKeyA, false, signaturesRegistry, sigRegistryA)
			return before, r.commit(t, sigAlice, sigKeyA, false, "README", "z")
		},
		want: "OK",
	},
	{
		name: "the registry at the before: a key the push adds does not pass",
		build: func(t *testing.T, r *sigRepo) (string, string) {
			before := r.commit(t, sigAlice, sigKeyA, false, signaturesRegistry, sigRegistryA)
			return before, r.commit(t, sigMallory, sigKeyM, false, signaturesRegistry, sigRegistryA+sigRegistryM)
		},
		wantFail: true, want: "signed by a key not in the registry",
	},
	{
		name: "the registry at the before: a registered key under another committer fails",
		build: func(t *testing.T, r *sigRepo) (string, string) {
			before := r.commit(t, sigAlice, sigKeyA, false, signaturesRegistry, sigRegistryA)
			return before, r.commit(t, sigMallory, sigKeyA, false, "README", "z")
		},
		wantFail: true, want: "principal mismatch: the key is registered to " + sigAlice + ", the committer is an address not in the registry",
	},
	{
		name:  "a pull request whose base has no registry fails: no head fallback",
		event: "pull_request_target",
		build: func(t *testing.T, r *sigRepo) (string, string) {
			base := r.commit(t, sigAlice, "", false, "README", "x")
			return base, r.commit(t, sigAlice, sigKeyA, false, signaturesRegistry, sigRegistryA)
		},
		wantFail: true, want: "FAIL no .github/allowed_signers",
	},
}

// TestSignaturesWorkflow_AdoptsTheRegistryOnlyFromACommitThatPassesIt pins
// the registry the verify step trusts. A push reads it from its before
// commit. When the before has never had one (the push that adopts the
// gate), it reads it from the first pushed commit that adds it, and that
// commit, like every commit of the push, must pass against it: signed by a
// key the registry names to its committer, or made by GitHub and verified.
// A pull request never falls back to its head.
func TestSignaturesWorkflow_AdoptsTheRegistryOnlyFromACommitThatPassesIt(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), signaturesWorkflowFile))
	if err != nil {
		t.Fatalf("read %s: %v", signaturesWorkflowFile, err)
	}
	script, err := signaturesScript(src)
	if err != nil {
		t.Fatalf("%s: %v", signaturesWorkflowFile, err)
	}
	for _, c := range sigCases {
		t.Run(c.name, func(t *testing.T) {
			r := newSigRepo(t)
			before, head := c.build(t, r)
			event := c.event
			if event == "" {
				event = "push"
			}
			out, failed := r.run(t, script, event, before, head)
			if failed != c.wantFail {
				t.Errorf("%s: the step failed: %v, want %v; output:\n%s", signaturesWorkflowFile, failed, c.wantFail, out)
			}
			if !strings.Contains(out, c.want) {
				t.Errorf("%s: the output lacks %q:\n%s", signaturesWorkflowFile, c.want, out)
			}
		})
	}
}
