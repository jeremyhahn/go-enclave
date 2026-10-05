// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package buildgates

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// shippedSourceDirs are the published packages whose comments render on
// pkg.go.dev, relative to the repository root. Not recursive.
var shippedSourceDirs = []string{".", "providertest"}

// issueRefPattern matches a tracker citation: a bare "#123" (not "PKCS#11"),
// "go-enclave#123", or an issue/pull URL path.
var issueRefPattern = regexp.MustCompile(`(^|[^\w#])#[0-9]+\b|go-enclave#[0-9]+|/(issues|pulls?)/[0-9]+`)

// issueRefsIn returns "line: text" for every comment line in src that cites
// the issue tracker.
func issueRefsIn(t *testing.T, name string, src []byte) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	var hits []string
	for _, group := range f.Comments {
		for _, c := range group.List {
			for i, line := range strings.Split(c.Text, "\n") {
				if issueRefPattern.MatchString(line) {
					pos := fset.Position(c.Slash)
					hits = append(hits, strings.TrimSpace(line)+" (line "+strconv.Itoa(pos.Line+i)+")")
				}
			}
		}
	}
	return hits
}

// TestShippedSourceCitesNoIssues pins that comments in the published,
// non-test Go files carry no issue or pull-request references: history belongs
// in commits and CHANGELOG.md, rationale in docs/.
func TestShippedSourceCitesNoIssues(t *testing.T) {
	root := repoRoot(t)
	checked := 0
	for _, dir := range shippedSourceDirs {
		matches, err := filepath.Glob(filepath.Join(root, dir, "*.go"))
		if err != nil {
			t.Fatalf("glob %s: %v", dir, err)
		}
		for _, path := range matches {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			rel, _ := filepath.Rel(root, path)
			for _, hit := range issueRefsIn(t, rel, src) {
				t.Errorf("%s cites the issue tracker in a comment: %s", rel, hit)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no shipped Go files found; the gate checked nothing")
	}
}

// TestIssueRefPattern pins what counts as a citation.
func TestIssueRefPattern(t *testing.T) {
	cites := []string{
		"see #83", "(#102)", "#7 at line start", "go-enclave#12",
		"https://git.example.com/o/go-enclave/issues/5", "/pulls/66", "/pull/9",
	}
	for _, s := range cites {
		if !issueRefPattern.MatchString(s) {
			t.Errorf("%q should count as an issue citation", s)
		}
	}
	plain := []string{"PKCS#11 token", "C# code", "a ## heading", "x#1y", "no reference here"}
	for _, s := range plain {
		if issueRefPattern.MatchString(s) {
			t.Errorf("%q should not count as an issue citation", s)
		}
	}
}
