package buildgates

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

// Every container image a workflow pulls must be named by digest:
//
//	container: golang:1.27.1-alpine3.24@sha256:<64 hex>
//	services:
//	  db:
//	    image: postgres:18@sha256:<64 hex>
//
// A tag is as movable as an action's tag (see action_pins_test.go) and these
// containers run the job's steps or sit beside them with the job's secrets in
// reach. The gate covers the two places a workflow names an image:
// jobs.<id>.container (a string, or a mapping with `image`) and
// jobs.<id>.services.<name>.image. Like the action gate it parses the YAML, and
// a shape it cannot read is an error, not a pass.

// digestPinnedImage is a name (no `$`, so no ${{ expression }}) and exactly 64
// lowercase hex, whatever tag stands in front of the digest.
var digestPinnedImage = regexp.MustCompile(`^[^@\s$]+@sha256:[0-9a-f]{64}$`)

// imageRef is one discovered image with its location. err is set when the
// value could not be resolved; it is kept rather than dropped so the gate fails
// on it.
type imageRef struct {
	file  string // repo-relative
	line  int
	where string // "jobs.build.container", "jobs.test.services.db.image"
	value string
	err   error
}

func TestWorkflowImagesArePinnedToDigests(t *testing.T) {
	root := repoRoot(t)
	files := workflowFiles(t, root)
	if len(files) < minWorkflowFiles {
		t.Fatalf("discovery floor: found %d workflow file(s) under %v, want at least %d", len(files), workflowDirs, minWorkflowFiles)
	}
	var refs []imageRef
	for _, f := range files {
		src, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		got, err := extractImages(f, src)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		refs = append(refs, got...)
	}
	for _, r := range refs {
		t.Run(fmt.Sprintf("%s:%d", r.file, r.line), func(t *testing.T) {
			if err := validateImage(r); err != nil {
				t.Error(err)
			}
		})
	}
	t.Logf("checked %d container image(s) across %d workflow file(s)", len(refs), len(files))
}

func validateImage(r imageRef) error {
	if r.err != nil {
		return fmt.Errorf("could not resolve %s at %s:%d: %w\n\n"+
			"This gate refuses to pass an image it cannot read. Write it as a plain\n"+
			"scalar: <image>@sha256:<64-hex>.", r.where, r.file, r.line, r.err)
	}
	if !digestPinnedImage.MatchString(r.value) {
		return fmt.Errorf("unpinned container image %q (%s) at %s:%d\n\n"+
			"Name every workflow container and service image by digest, with the tag\n"+
			"kept for the reader:\n\n"+
			"    image: <name>:<tag>@sha256:<64-hex>\n\n"+
			"A tag is moved by its owner, and an expression (${{ ... }}) is resolved at\n"+
			"run time, so neither records what this repository executed. Resolve the\n"+
			"digest with `docker buildx imagetools inspect <name>:<tag>`.",
			r.value, r.where, r.file, r.line)
	}
	return nil
}

// extractImages returns every container and service image in one workflow.
func extractImages(file string, src []byte) ([]imageRef, error) {
	f, err := parser.ParseBytes(src, 0)
	if err != nil {
		return nil, err
	}
	var refs []imageRef
	for _, doc := range f.Docs {
		if doc.Body == nil {
			continue
		}
		anchors := map[string]ast.Node{}
		ast.Walk(&anchorVisitor{anchors: anchors}, doc.Body)
		w := &imageWalker{file: file, anchors: anchors}
		w.workflow(doc.Body)
		refs = append(refs, w.refs...)
	}
	return refs, nil
}

type imageWalker struct {
	file    string
	anchors map[string]ast.Node
	refs    []imageRef
}

func (w *imageWalker) fail(where string, n ast.Node, format string, args ...any) {
	line := 0
	if n != nil {
		line = n.GetToken().Position.Line
	}
	w.refs = append(w.refs, imageRef{file: w.file, line: line, where: where, err: fmt.Errorf(format, args...)})
}

// pairs reads a block or flow mapping, through anchors and aliases.
func (w *imageWalker) pairs(where string, n ast.Node) ([]*ast.MappingValueNode, bool) {
	n, err := w.deref(n, 0)
	if err != nil {
		w.fail(where, n, "%v", err)
		return nil, false
	}
	var out []*ast.MappingValueNode
	switch t := n.(type) {
	case *ast.MappingNode:
		out = t.Values
	case *ast.MappingValueNode:
		out = []*ast.MappingValueNode{t}
	default:
		w.fail(where, n, "want a mapping, got %T", n)
		return nil, false
	}
	for _, mv := range out {
		if mv.Key.GetToken().Value == "<<" {
			w.fail(where, mv, "a merge key is not read by this gate; write the keys out")
			return nil, false
		}
	}
	return out, true
}

func (w *imageWalker) deref(n ast.Node, depth int) (ast.Node, error) {
	if depth > maxAliasDepth {
		return n, fmt.Errorf("alias chain deeper than %d — cyclic anchor?", maxAliasDepth)
	}
	switch t := n.(type) {
	case *ast.AnchorNode:
		return w.deref(t.Value, depth+1)
	case *ast.AliasNode:
		target, ok := w.anchors[t.Value.GetToken().Value]
		if !ok {
			return n, fmt.Errorf("alias *%s has no anchor definition in this document", t.Value.GetToken().Value)
		}
		return w.deref(target, depth+1)
	}
	return n, nil
}

func (w *imageWalker) workflow(body ast.Node) {
	top, ok := w.pairs("the workflow", body)
	if !ok {
		return
	}
	for _, kv := range top {
		if kv.Key.GetToken().Value != "jobs" {
			continue
		}
		jobs, ok := w.pairs("jobs", kv.Value)
		if !ok {
			return
		}
		for _, job := range jobs {
			w.job("jobs."+job.Key.GetToken().Value, job.Value)
		}
	}
}

func (w *imageWalker) job(where string, n ast.Node) {
	fields, ok := w.pairs(where, n)
	if !ok {
		return
	}
	for _, kv := range fields {
		switch kv.Key.GetToken().Value {
		case "container":
			w.container(where+".container", kv.Value)
		case "services":
			services, ok := w.pairs(where+".services", kv.Value)
			if !ok {
				continue
			}
			for _, svc := range services {
				at := where + ".services." + svc.Key.GetToken().Value
				attrs, ok := w.pairs(at, svc.Value)
				if !ok {
					continue
				}
				found := false
				for _, a := range attrs {
					if a.Key.GetToken().Value == "image" {
						found = true
						w.image(at+".image", a.Value)
					}
				}
				if !found {
					w.fail(at, svc, "a service with no image")
				}
			}
		}
	}
}

// container reads both spellings: a string, or a mapping with `image`.
func (w *imageWalker) container(where string, n ast.Node) {
	d, err := w.deref(n, 0)
	if err != nil {
		w.fail(where, n, "%v", err)
		return
	}
	switch d.(type) {
	case *ast.MappingNode, *ast.MappingValueNode:
		attrs, ok := w.pairs(where, d)
		if !ok {
			return
		}
		for _, a := range attrs {
			if a.Key.GetToken().Value == "image" {
				w.image(where+".image", a.Value)
				return
			}
		}
		w.fail(where, d, "a container mapping with no image")
	default:
		w.image(where, n)
	}
}

func (w *imageWalker) image(where string, n ast.Node) {
	value, err := resolveRef(n, w.anchors, 0)
	line := 0
	if n != nil {
		line = n.GetToken().Position.Line
	}
	w.refs = append(w.refs, imageRef{file: w.file, line: line, where: where, value: value, err: err})
}

const (
	pinnedImage  = "golang:1.27.1-alpine3.24@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414"
	mutableImage = "golang:1.27.1-alpine3.24"
)

// imageSpellings renders one workflow holding exactly one image in each way a
// workflow can name one. As for actions, the pinned control keeps a gate that
// rejects the spelling outright from satisfying the mutable test, and the
// exactly-one check catches a spelling that is silently dropped.
var imageSpellings = []struct {
	name   string
	render func(image string) string
}{
	{"container-string", func(i string) string {
		return "jobs:\n  build:\n    container: " + i + "\n    steps: []\n"
	}},
	{"container-quoted", func(i string) string {
		return "jobs:\n  build:\n    container: \"" + i + "\"\n    steps: []\n"
	}},
	{"container-mapping", func(i string) string {
		return "jobs:\n  build:\n    container:\n      image: " + i + "\n      options: --cpus 1\n    steps: []\n"
	}},
	{"container-quoted-key", func(i string) string {
		return "jobs:\n  build:\n    \"container\":\n      \"image\": " + i + "\n    steps: []\n"
	}},
	{"container-flow-mapping", func(i string) string {
		return "jobs:\n  build:\n    container: {image: " + i + "}\n    steps: []\n"
	}},
	{"container-alias", func(i string) string {
		return "x-image: &img " + i + "\njobs:\n  build:\n    container: *img\n    steps: []\n"
	}},
	{"service-image", func(i string) string {
		return "jobs:\n  build:\n    services:\n      db:\n        image: " + i + "\n        ports: [\"5432:5432\"]\n    steps: []\n"
	}},
	{"service-image-block-scalar", func(i string) string {
		return "jobs:\n  build:\n    services:\n      db:\n        image: >-\n          " + i + "\n    steps: []\n"
	}},
	{"service-flow-mapping", func(i string) string {
		return "jobs:\n  build:\n    services: {db: {image: " + i + "}}\n    steps: []\n"
	}},
}

func TestEveryImageSpellingYieldsExactlyOneRef(t *testing.T) {
	for _, sp := range imageSpellings {
		t.Run(sp.name, func(t *testing.T) {
			src := sp.render(pinnedImage)
			refs, err := extractImages("fixture.yml", []byte(src))
			if err != nil {
				t.Fatalf("parse: %v\nyaml:\n%s", err, src)
			}
			if len(refs) != 1 || refs[0].err != nil || refs[0].value != pinnedImage {
				t.Fatalf("got %+v, want exactly one ref resolving to %q — a dropped image is a skipped pin\nyaml:\n%s", refs, pinnedImage, src)
			}
			if err := validateImage(refs[0]); err != nil {
				t.Errorf("validateImage rejected a digest-pinned image:\n%v", err)
			}
		})
	}
}

func TestMutableImageFailsInEverySpelling(t *testing.T) {
	for _, sp := range imageSpellings {
		t.Run(sp.name, func(t *testing.T) {
			src := sp.render(mutableImage)
			refs, err := extractImages("fixture.yml", []byte(src))
			if err != nil {
				t.Fatalf("parse: %v\nyaml:\n%s", err, src)
			}
			if len(refs) != 1 {
				t.Fatalf("got %d ref(s), want exactly 1 — a mutable image that is never collected cannot fail\nyaml:\n%s", len(refs), src)
			}
			err = validateImage(refs[0])
			if err == nil {
				t.Fatalf("validateImage accepted the MUTABLE image %q — the gate is not gating\nyaml:\n%s", mutableImage, src)
			}
			if !strings.Contains(err.Error(), "unpinned container image") {
				t.Errorf("failed for the wrong reason:\n%v", err)
			}
		})
	}
}

// Several images in one workflow are each reported, and the shapes the gate
// cannot read fail instead of vanishing.
func TestImageGateReportsEveryImageAndRefusesWhatItCannotRead(t *testing.T) {
	const many = "jobs:\n" +
		"  a:\n    container: " + pinnedImage + "\n    services:\n      db:\n        image: " + mutableImage + "\n      cache:\n        image: " + pinnedImage + "\n" +
		"  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo \"container: not/an-image\"\n"
	refs, err := extractImages("fixture.yml", []byte(many))
	if err != nil {
		t.Fatal(err)
	}
	var bad int
	for _, r := range refs {
		if validateImage(r) != nil {
			bad++
		}
	}
	if len(refs) != 3 || bad != 1 {
		t.Fatalf("got %d ref(s) with %d failing, want 3 with 1 (the unpinned service): %+v", len(refs), bad, refs)
	}

	for name, src := range map[string]string{
		"an expression":         "jobs:\n  a:\n    container: ${{ matrix.image }}\n",
		"a service with none":   "jobs:\n  a:\n    services:\n      db:\n        ports: []\n",
		"a container, no image": "jobs:\n  a:\n    container:\n      options: --cpus 1\n",
		"a merge key":           "x: &j\n  container: " + pinnedImage + "\njobs:\n  a:\n    <<: *j\n",
		"an unreadable image":   "jobs:\n  a:\n    services:\n      db:\n        image: [a, b]\n",
	} {
		t.Run(name, func(t *testing.T) {
			refs, err := extractImages("fixture.yml", []byte(src))
			if err != nil {
				return // a parse error is also loud
			}
			if len(refs) == 0 {
				t.Fatalf("no ref reported for a shape the gate cannot read:\n%s", src)
			}
			for _, r := range refs {
				if validateImage(r) == nil {
					t.Fatalf("validateImage passed %+v\n%s", r, src)
				}
			}
		})
	}
}
