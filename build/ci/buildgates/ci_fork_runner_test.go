package buildgates

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// A pull_request from a fork runs code its author controls: the checkout and
// every script it sources. No job of ci.yml may take a self-hosted runner for
// one. The test resolves each job's runs-on for a fork pull_request on
// github.com (the only place a fork's pull_request runs) over every value
// a repository variable and the preflight runner selection can take.

// forkSelfHosted is a self-hosted label list a variable or the runner
// selection can name.
const forkSelfHosted = `["self-hosted","linux","x64","bigdisk"]`

// forkGuardExpr is the condition a fork-guard env value must hold.
const forkGuardExpr = "github.event.pull_request.head.repo.full_name != github.repository"

var (
	hostedLabelRE  = regexp.MustCompile(`^(ubuntu|windows|macos)-[a-z0-9.-]+$`)
	errUnknownExpr = errors.New("unknown in a fork pull_request")
)

// forkContext is a fork pull_request's known context values.
var forkContext = map[string]any{
	"github.server_url": "https://github.com",
	"github.event_name": "pull_request",
	"github.repository": "o/r",
	"github.ref":        "refs/pull/1/merge",
	"github.event.pull_request.head.repo.full_name": "fork/r",
	"github.event.pull_request.draft":               false,
}

// --- a small evaluator of GitHub Actions expressions ---

type exprNode struct {
	kind string // lit, ref, call, not, op
	val  any
	name string
	args []*exprNode
}

type exprParser struct {
	toks []string
	pos  int
}

func tokenizeExpr(s string) ([]string, error) {
	var toks []string
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			i++
		case c == '\'':
			j := i + 1
			var b strings.Builder
			for {
				if j >= len(s) {
					return nil, fmt.Errorf("unterminated string in %q", s)
				}
				if s[j] == '\'' {
					if j+1 < len(s) && s[j+1] == '\'' {
						b.WriteByte('\'')
						j += 2
						continue
					}
					break
				}
				b.WriteByte(s[j])
				j++
			}
			toks = append(toks, "'"+b.String())
			i = j + 1
		case strings.ContainsRune("=!<>&|", rune(c)) && i+1 < len(s) && strings.Contains("== != <= >= && ||", s[i:i+2]):
			toks = append(toks, s[i:i+2])
			i += 2
		case strings.ContainsRune("!<>(),", rune(c)):
			toks = append(toks, string(c))
			i++
		case c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9':
			j := i
			for j < len(s) && (s[j] == '_' || s[j] == '.' || s[j] == '-' || s[j] >= 'a' && s[j] <= 'z' || s[j] >= 'A' && s[j] <= 'Z' || s[j] >= '0' && s[j] <= '9') {
				j++
			}
			toks = append(toks, s[i:j])
			i = j
		default:
			return nil, fmt.Errorf("unexpected %q in %q", c, s)
		}
	}
	return toks, nil
}

func parseExpr(s string) (*exprNode, error) {
	toks, err := tokenizeExpr(s)
	if err != nil {
		return nil, err
	}
	p := &exprParser{toks: toks}
	n, err := p.binary(0)
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("trailing %q in %q", p.toks[p.pos], s)
	}
	return n, nil
}

var exprLevels = [][]string{{"||"}, {"&&"}, {"==", "!="}, {"<", ">", "<=", ">="}}

func (p *exprParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *exprParser) binary(level int) (*exprNode, error) {
	if level == len(exprLevels) {
		return p.unary()
	}
	l, err := p.binary(level + 1)
	if err != nil {
		return nil, err
	}
	for {
		op := p.peek()
		found := false
		for _, o := range exprLevels[level] {
			found = found || o == op
		}
		if !found {
			return l, nil
		}
		p.pos++
		r, err := p.binary(level + 1)
		if err != nil {
			return nil, err
		}
		l = &exprNode{kind: "op", name: op, args: []*exprNode{l, r}}
	}
}

func (p *exprParser) unary() (*exprNode, error) {
	if p.peek() == "!" {
		p.pos++
		n, err := p.unary()
		if err != nil {
			return nil, err
		}
		return &exprNode{kind: "not", args: []*exprNode{n}}, nil
	}
	return p.primary()
}

func (p *exprParser) primary() (*exprNode, error) {
	t := p.peek()
	p.pos++
	switch {
	case t == "":
		return nil, errors.New("unexpected end of expression")
	case t == "(":
		n, err := p.binary(0)
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, errors.New("missing )")
		}
		p.pos++
		return n, nil
	case strings.HasPrefix(t, "'"):
		return &exprNode{kind: "lit", val: t[1:]}, nil
	case t == "true" || t == "false":
		return &exprNode{kind: "lit", val: t == "true"}, nil
	case t == "null":
		return &exprNode{kind: "lit", val: nil}, nil
	case t[0] >= '0' && t[0] <= '9':
		return &exprNode{kind: "lit", val: t}, nil
	case p.peek() == "(":
		p.pos++
		n := &exprNode{kind: "call", name: strings.ToLower(t)}
		for p.peek() != ")" {
			a, err := p.binary(0)
			if err != nil {
				return nil, err
			}
			n.args = append(n.args, a)
			if p.peek() == "," {
				p.pos++
			}
		}
		p.pos++
		return n, nil
	default:
		return &exprNode{kind: "ref", name: strings.ToLower(t)}, nil
	}
}

func exprRefs(n *exprNode, out map[string]bool) {
	if n.kind == "ref" {
		out[n.name] = true
	}
	for _, a := range n.args {
		exprRefs(a, out)
	}
}

func truthy(v any) bool {
	switch v := v.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return v != ""
	case float64:
		return v != 0
	}
	return true
}

func exprString(v any) string {
	switch v := v.(type) {
	case nil:
		return ""
	case string:
		return v
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func evalExpr(n *exprNode, env map[string]any) (any, error) {
	switch n.kind {
	case "lit":
		return n.val, nil
	case "ref":
		v, ok := env[n.name]
		if !ok {
			return nil, fmt.Errorf("%s: %w", n.name, errUnknownExpr)
		}
		return v, nil
	case "not":
		v, err := evalExpr(n.args[0], env)
		return !truthy(v), err
	case "op":
		l, err := evalExpr(n.args[0], env)
		if err != nil {
			return nil, err
		}
		switch n.name {
		case "&&":
			if !truthy(l) {
				return l, nil
			}
			return evalExpr(n.args[1], env)
		case "||":
			if truthy(l) {
				return l, nil
			}
			return evalExpr(n.args[1], env)
		}
		r, err := evalExpr(n.args[1], env)
		if err != nil {
			return nil, err
		}
		eq := strings.EqualFold(exprString(l), exprString(r))
		switch n.name {
		case "==":
			return eq, nil
		case "!=":
			return !eq, nil
		}
		return nil, fmt.Errorf("%s: %w", n.name, errUnknownExpr)
	case "call":
		switch n.name {
		case "always", "success":
			return true, nil
		case "cancelled", "failure": //nolint:misspell // the GitHub Actions function's name
			return false, nil
		}
		var args []any
		for _, a := range n.args {
			v, err := evalExpr(a, env)
			if err != nil {
				return nil, err
			}
			args = append(args, v)
		}
		switch {
		case n.name == "fromjson" && len(args) == 1:
			var v any
			if err := json.Unmarshal([]byte(exprString(args[0])), &v); err != nil {
				return nil, fmt.Errorf("fromJSON(%q): %w", exprString(args[0]), err)
			}
			return v, nil
		case n.name == "startswith" && len(args) == 2:
			return strings.HasPrefix(strings.ToLower(exprString(args[0])), strings.ToLower(exprString(args[1]))), nil
		case n.name == "contains" && len(args) == 2:
			if l, ok := args[0].([]any); ok {
				for _, x := range l {
					if strings.EqualFold(exprString(x), exprString(args[1])) {
						return true, nil
					}
				}
				return false, nil
			}
			return strings.Contains(strings.ToLower(exprString(args[0])), strings.ToLower(exprString(args[1]))), nil
		}
		return nil, fmt.Errorf("%s(): %w", n.name, errUnknownExpr)
	}
	return nil, fmt.Errorf("node %s", n.kind)
}

// evalAll evaluates an expression over every combination of the candidate
// values of the references it reads. A reference with no candidates is left
// out of env, so reading it fails with errUnknownExpr.
func evalAll(expr string, cands func(ref string) []any) ([]any, error) {
	n, err := parseExpr(expr)
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	exprRefs(n, set)
	refs := make([]string, 0, len(set))
	for r := range set {
		refs = append(refs, r)
	}
	sort.Strings(refs)
	var out []any
	var walk func(i int, env map[string]any) error
	walk = func(i int, env map[string]any) error {
		if i == len(refs) {
			v, err := evalExpr(n, env)
			if err != nil {
				return err
			}
			out = append(out, v)
			return nil
		}
		cs := cands(refs[i])
		if cs == nil {
			return walk(i+1, env)
		}
		for _, c := range cs {
			e := map[string]any{}
			for k, v := range env {
				e[k] = v
			}
			e[refs[i]] = c
			if err := walk(i+1, e); err != nil {
				return err
			}
		}
		return nil
	}
	err = walk(0, map[string]any{})
	return out, err
}

var exprSpanRE = regexp.MustCompile(`\$\{\{(.*?)\}\}`)

// evalField resolves a workflow field: a whole `${{ }}` gives the
// expression's value, and any other string has its spans put in as text.
func evalField(field string, cands func(string) []any) ([]any, error) {
	s := strings.TrimSpace(field)
	if m := exprSpanRE.FindStringSubmatchIndex(s); m != nil && m[0] == 0 && m[1] == len(s) {
		return evalAll(s[m[2]:m[3]], cands)
	}
	outs := []string{s}
	for _, m := range exprSpanRE.FindAllStringSubmatch(s, -1) {
		vs, err := evalAll(m[1], cands)
		if err != nil {
			return nil, err
		}
		var next []string
		for _, o := range outs {
			for _, v := range vs {
				next = append(next, strings.Replace(o, m[0], exprString(v), 1))
			}
		}
		outs = next
	}
	res := make([]any, len(outs))
	for i, o := range outs {
		res[i] = o
	}
	return res, nil
}

// --- the gate ---

type forkStep struct {
	ID  string            `yaml:"id"`
	Env map[string]string `yaml:"env"`
	Run string            `yaml:"run"`
}

type forkJob struct {
	If     any        `yaml:"if"`
	RunsOn any        `yaml:"runs-on"`
	Steps  []forkStep `yaml:"steps"`
}

// selectionRefusesForks reports whether the preflight job's runner step
// emits the hosted default for a fork pull_request before any self-hosted
// label: a shell test that is true for a fork (see forkGuards), outside any
// case arm a pull_request cannot take, whose branch emits "$HOSTED"
// "$HOSTED" and exits ahead of the first self-hosted label.
func selectionRefusesForks(pre forkJob) bool {
	for _, st := range pre.Steps {
		if st.ID != "runner" {
			continue
		}
		over := strings.Index(st.Run, `emit "$(selfhosted`)
		for _, g := range forkGuards(st.Env) {
			guard := strings.Index(st.Run, g)
			if guard < 0 || over >= 0 && guard > over || !armTakesPullRequest(st.Run[:guard]) {
				continue
			}
			rest := st.Run[guard:]
			if end := strings.Index(rest, "\nfi"); end >= 0 {
				rest = rest[:end]
			} else if end := strings.Index(rest, "fi\n"); end >= 0 {
				rest = rest[:end]
			}
			if strings.Contains(rest, `emit "$HOSTED" "$HOSTED"`) && strings.Contains(rest, "exit 0") {
				return true
			}
		}
	}
	return false
}

// forkGuards lists the shell tests on a step's env that hold for every fork
// pull_request: `[ "$K" = true ]` for a value that holds forkGuardExpr and is
// true for a fork, and `[ "$H" != "$R" ]` for a value that is the head
// repository and one that is this repository.
func forkGuards(env map[string]string) []string {
	only := func(v string) (string, bool) {
		vs, err := evalField(v, forkCands(true))
		if err != nil || len(vs) != 1 {
			return "", false
		}
		return exprString(vs[0]), true
	}
	var out, heads, repos []string
	for k, v := range env {
		got, ok := only(v)
		switch {
		case !ok:
		case strings.Contains(v, forkGuardExpr) && got == "true":
			out = append(out, `[ "$`+k+`" = true ]`)
		case got == forkContext["github.event.pull_request.head.repo.full_name"]:
			heads = append(heads, k)
		case got == forkContext["github.repository"]:
			repos = append(repos, k)
		}
	}
	for _, h := range heads {
		for _, r := range repos {
			out = append(out, `[ "$`+h+`" != "$`+r+`" ]`, `[ "$`+r+`" != "$`+h+`" ]`)
		}
	}
	sort.Strings(out)
	return out
}

// armTakesPullRequest reports whether a shell test after the script text
// before runs for a pull_request: it sits in no open `case`, or in an arm
// whose patterns name pull_request or match anything.
func armTakesPullRequest(before string) bool {
	open := strings.LastIndex(before, "case ")
	if open < 0 || strings.LastIndex(before, "esac") > open {
		return true
	}
	arm := ""
	for _, line := range strings.Split(before[open:], "\n")[1:] {
		line = strings.TrimSpace(line)
		if pats, ok := strings.CutSuffix(line, ")"); ok && !strings.ContainsAny(pats, " ;") {
			arm = pats
		}
	}
	for _, p := range strings.Split(arm, "|") {
		if p == "pull_request" || p == "*" {
			return true
		}
	}
	return false
}

// forkCands gives the candidate values of a reference in a fork
// pull_request. guarded says whether the runner selection refuses forks.
func forkCands(guarded bool) func(string) []any {
	return func(ref string) []any {
		if v, ok := forkContext[ref]; ok {
			return []any{v}
		}
		switch {
		case strings.HasPrefix(ref, "vars."):
			return []any{nil, forkSelfHosted}
		case ref == "needs.preflight.outputs.runner" || ref == "needs.preflight.outputs.runner_docker":
			if guarded {
				return []any{`"ubuntu-latest"`}
			}
			return []any{`"ubuntu-latest"`, forkSelfHosted}
		}
		return nil
	}
}

// labelsOf turns a resolved runs-on value into its labels.
func labelsOf(v any) []string {
	switch v := v.(type) {
	case []any:
		var out []string
		for _, x := range v {
			out = append(out, exprString(x))
		}
		return out
	}
	return []string{exprString(v)}
}

// forkRunnerViolations lists each job of the workflow that a fork
// pull_request can run on a self-hosted runner, or whose runs-on cannot be
// resolved for one.
func forkRunnerViolations(src []byte) ([]string, error) {
	var wf struct {
		Jobs map[string]forkJob `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(src, &wf); err != nil {
		return nil, err
	}
	cands := forkCands(selectionRefusesForks(wf.Jobs["preflight"]))
	var bad []string
	for name, job := range wf.Jobs {
		// A job whose if: is false for every fork value never runs; one
		// that cannot be read is taken to run.
		if cond, ok := job.If.(string); ok && cond != "" {
			expr := cond
			if !strings.Contains(expr, "${{") {
				expr = "${{ " + expr + " }}"
			}
			vs, err := evalField(expr, cands)
			if err == nil && !anyTruthy(vs) {
				continue
			}
		}
		var fields []any
		switch ro := job.RunsOn.(type) {
		case string:
			vs, err := evalField(ro, cands)
			if err != nil {
				bad = append(bad, fmt.Sprintf("job %s: runs-on cannot be resolved for a fork pull_request: %v", name, err))
				continue
			}
			fields = vs
		case []any:
			var labels []any
			for _, l := range ro {
				vs, err := evalField(exprString(l), cands)
				if err != nil || len(vs) != 1 {
					bad = append(bad, fmt.Sprintf("job %s: runs-on label %v cannot be resolved for a fork pull_request", name, l))
					continue
				}
				labels = append(labels, vs[0])
			}
			fields = []any{labels}
		default:
			bad = append(bad, fmt.Sprintf("job %s: runs-on %T cannot be read", name, job.RunsOn))
			continue
		}
		for _, f := range fields {
			labels := labelsOf(f)
			if len(labels) != 1 || !hostedLabelRE.MatchString(labels[0]) {
				bad = append(bad, fmt.Sprintf("job %s: a fork pull_request can run on %s", name, strings.Join(labels, ",")))
				break
			}
		}
	}
	sort.Strings(bad)
	return bad, nil
}

func anyTruthy(vs []any) bool {
	for _, v := range vs {
		if truthy(v) {
			return true
		}
	}
	return false
}

func TestCIForkPullRequestsNeverReachSelfHosted(t *testing.T) {
	src := readFile(t, filepath.Join(repoRoot(t), ciWorkflowFile))
	bad, err := forkRunnerViolations([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bad {
		t.Error(b)
	}
}

func TestCIForkRunner_RefusesWhatItMustRefuse(t *testing.T) {
	guarded := `  preflight:
    runs-on: ubuntu-latest
    steps:
      - id: runner
        env:
          FORK: ${{ github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name != github.repository }}
        run: |
          if [ "$FORK" = true ]; then
            emit "$HOSTED" "$HOSTED"
            exit 0
          fi
          emit "$(selfhosted bigdisk)" "$(selfhosted bigdisk-docker)"
`
	unguarded := `  preflight:
    runs-on: ubuntu-latest
    steps:
      - id: runner
        run: |
          emit "$(selfhosted bigdisk)" "$(selfhosted bigdisk-docker)"
`
	template := func(arm string) string {
		return `  preflight:
    runs-on: ubuntu-latest
    steps:
      - id: runner
        env:
          EVENT: ${{ github.event_name }}
          HEAD_REPO: ${{ github.event.pull_request.head.repo.full_name }}
          REPO: ${{ github.repository }}
        run: |
          case "$EVENT" in
            ` + arm + `)
              if [ "$HEAD_REPO" != "$REPO" ]; then
                emit "$HOSTED" "$HOSTED"
                exit 0
              fi ;;
          esac
          emit "$(selfhosted bigdisk)" "$(selfhosted bigdisk-docker)"
`
	}
	late := `  preflight:
    runs-on: ubuntu-latest
    steps:
      - id: runner
        env:
          HEAD_REPO: ${{ github.event.pull_request.head.repo.full_name }}
          REPO: ${{ github.repository }}
        run: |
          emit "$(selfhosted bigdisk)" "$(selfhosted bigdisk-docker)"
          if [ "$HEAD_REPO" != "$REPO" ]; then
            emit "$HOSTED" "$HOSTED"
            exit 0
          fi
`
	docker := `  build:
    runs-on: ${{ github.server_url == 'https://github.com' && fromJSON(needs.preflight.outputs.runner_docker) || 'bigdisk' }}
`
	cases := []struct {
		name, jobs string
		want       int
	}{
		{"hosted literal", "  a:\n    runs-on: ubuntu-latest\n", 0},
		{"self-hosted list", "  a:\n    runs-on: [self-hosted, linux, x64, bigdisk]\n", 1},
		{"self-hosted list, push only", "  a:\n    if: ${{ github.event_name == 'push' }}\n    runs-on: [self-hosted, release]\n", 0},
		{"variable default self-hosted", "  a:\n    runs-on: ${{ fromJSON(vars.X || '[\"self-hosted\",\"bigdisk\"]') }}\n", 1},
		{"variable, forks hosted", "  a:\n    runs-on: ${{ github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name != github.repository && 'ubuntu-latest' || fromJSON(vars.X || '[\"self-hosted\"]') }}\n", 0},
		{"selection without a fork guard", unguarded + docker, 1},
		{"selection with a fork guard", guarded + docker, 0},
		{"selection with the template's fork guard", template("pull_request|pull_request_target") + docker, 0},
		{"template guard on pull_request_target only", template("pull_request_target") + docker, 1},
		{"template guard after the self-hosted emit", late + docker, 1},
		{"template preflight on the variable for a fork", "  preflight:\n    runs-on: ${{ github.server_url == 'https://github.com' && (!startsWith(github.event_name, 'pull_request') || github.event.pull_request.head.repo.full_name == github.repository) && fromJSON(vars.X || '[\\\"self-hosted\\\"]') || 'ubuntu-latest' }}\n", 0},
		{"preflight on the variable without the fork clause", "  preflight:\n    runs-on: ${{ github.server_url == 'https://github.com' && fromJSON(vars.X || '[\\\"self-hosted\\\"]') || 'ubuntu-latest' }}\n", 1},
		{"unknown reference", "  a:\n    runs-on: ${{ needs.other.outputs.runner }}\n", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bad, err := forkRunnerViolations([]byte("jobs:\n" + c.jobs))
			if err != nil {
				t.Fatal(err)
			}
			if len(bad) != c.want {
				t.Fatalf("got %d findings, want %d: %q", len(bad), c.want, bad)
			}
		})
	}
}

func TestCIForkRunner_EvalAllReturnsEveryResult(t *testing.T) {
	cands := func(ref string) []any {
		if ref == "github.event_name" {
			return []any{"push", "pull_request"}
		}
		return nil
	}
	got, err := evalAll("github.event_name == 'push' && 'self-hosted' || 'ubuntu-latest'", cands)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"self-hosted", "ubuntu-latest"}
	if len(got) != len(want) {
		t.Fatalf("got %d results %v, want %v", len(got), got, want)
	}
	for i, w := range want {
		if exprString(got[i]) != w {
			t.Fatalf("result %d: got %v, want %q", i, got[i], w)
		}
	}
}
