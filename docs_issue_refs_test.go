package enclave

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The guard for issue #65: package documentation must not tell a reader that
// something already shipped, or already ruled out, is still a tracked plan.
//
// The defect it exists for is subtle because the text stays grammatical while
// it rots. doc.go said "an admitted variant, OpenWith, is tracked as issue
// #17" for two releases after OpenWith shipped, and "an explicit openability
// probe (Openable) is tracked as issue #33" after Openable shipped. These are
// package docs, so they reach go doc and pkg.go.dev: a reader was told a
// method they can call right now was a future plan, and the only signal was an
// issue number whose state lives on a server.
//
// # Why this is not "fail when the docs cite a closed issue"
//
// The obvious check does not work here. Every one of this package's citations
// resolves to a CLOSED issue — all 13 distinct local numbers of them — because
// the docs earn their keep by explaining WHY the code is shaped as it is, and
// that reasoning is mostly a record of decisions already taken: "Option B (#2)
// deleted memguard's process-global registry", "the sweep will NOT be extended
// to cover them (#33, decided)". A guard that fired on a closed citation would
// fire on all of them, be suppressed within the day, and catch nothing.
//
// The thing that actually goes stale is not the citation, it is the CLAIM the
// prose makes around it. So each citation is classified, in a ledger checked
// in beside the docs, as one of:
//
//   - classHistorical — the prose describes a decision already taken or work
//     already done. Its truth does not depend on the issue's state, so no
//     state is queried.
//   - classPending — the prose presents the issue as unresolved future work.
//     This is a claim about the world that CAN rot, and it is checked: the
//     issue must be OPEN.
//   - classExternal — the citation belongs to another repository. Not checked
//     here; recorded so it is visibly accounted for rather than silently
//     dropped by the extractor.
//
// # The ledger is keyed by the SENTENCE, not by the file and number
//
// This is the correction that matters, and it was not the first design. The
// first version keyed the ledger at "<file>#<number>" granularity, and review
// on PR #66 killed it with the obvious mutation: reword doc.go's
// "SealedEnclave.Openable is the explicit probe (issue #33)" into "An
// openability probe is tracked as issue #33" — the exact defect #65 exists to
// prevent — and the guard PASSED, because doc.go#33 was already in the ledger
// as classHistorical and nothing looked at the prose. A second sentence in the
// same file presenting the same issue as pending slipped through the same hole.
//
// So the key is a digest of the NORMALIZED CITING SENTENCE. A classification
// therefore covers exactly the words that were classified: reword the sentence
// and its digest changes, the old entry orphans, the new one is undeclared, and
// the test fails twice over until someone re-reads the sentence and says what
// it now claims. Rewrapping a paragraph changes nothing, because the digest is
// taken after whitespace and comment markers are normalized away.
//
// # Two halves, and each one has teeth on its own
//
// The offline half compares the citations found in the tree against the ledger
// and fails on ANY difference in either direction. A sentence nobody classified
// fails; a ledger entry whose sentence no longer exists fails. It needs no
// network, runs everywhere, and is what forces the classification decision to
// be made by whoever writes the sentence.
//
// The online half resolves every classPending entry against the Gitea API and
// fails if the issue is closed — the exact shape of #65, for the case where a
// legitimately-open reference is written today and the issue closes next month.
// It skips only for GENUINE TRANSPORT UNAVAILABILITY, because a build that
// fails when a private git server is down is worse than the problem it guards.
// It does NOT skip for an HTTP status, a rejected token, a malformed endpoint
// or an answer from the wrong repository: those are configuration failures and
// they fail, because setting ENCLAVE_ISSUE_API is what asks for the check.
// That was the second finding on PR #66, and it is the silent-instrument
// pattern this repository has caught repeatedly — a probe that cannot answer
// reports exactly what a clean probe reports. See onlineFailurePolicy for the
// decision table and for why the middle "warn" state it used to have was
// removed rather than kept.
//
// # What this guard CANNOT catch
//
// A reader who sees a thorough test infers coverage it does not have. Stated
// plainly, so nobody has to find these out the hard way:
//
//   - It does not read the prose. classHistorical on a sentence that actually
//     says "tracked as issue #33" is invisible to it, because the ledger
//     records the claim a human made about the sentence, not the claim the
//     sentence makes. What the sentence-level key buys is that the decision
//     must be MADE, and re-made whenever the wording changes; whether the
//     answer is RIGHT is still human judgment, and a careless classHistorical
//     defeats it completely.
//   - It cannot see a forward reference carrying no issue number. "A future
//     variant will take an Allocator" rots identically and has nothing to
//     resolve.
//   - Its scope is the file list in docIssueRefFiles and nothing else.
//     CHANGELOG.md, *_test.go, the Makefile and .github/ are excluded by
//     choice, for the reasons given there. A stale claim in those is not
//     caught.
//   - The online half is opt-in through the environment. Where
//     ENCLAVE_ISSUE_API is never set — which is every default local run and
//     this repository's CI today, since the repository is private — only the
//     offline half runs. Unsetting it is a way to switch the state check off,
//     and no test can prevent that; the offline half is what carries the
//     invariant everywhere.
//   - Nothing this file could do would make a PASSING test say anything in a
//     non-verbose run. Measured: t.Log, os.Stdout and os.Stderr are all
//     discarded for a package that passes without -v. So there is no such
//     thing here as a warning that is heard — a condition either fails or it
//     is silent, which is why onlineFailurePolicy has no warn state.
//   - It has no opinion on an issue that is open but abandoned. "Open" is
//     taken at face value.
//   - Sentence splitting is a heuristic (a period followed by whitespace).
//     A citation can land in a fragment rather than a grammatical sentence.
//     That is harmless for keying — the unit is stable either way — but the
//     quoted text in a failure message may read oddly.

// refClass is what the prose around a citation CLAIMS, which is the thing that
// can rot — not the issue's state, which is merely evidence about the claim.
type refClass int

const (
	// classHistorical: the sentence describes something already done or
	// already decided. True regardless of the issue's state.
	classHistorical refClass = iota
	// classPending: the sentence presents the issue as unresolved future
	// work. Requires the issue to be OPEN.
	classPending
	// classExternal: the citation names an issue in another repository.
	classExternal
)

func (c refClass) String() string {
	switch c {
	case classHistorical:
		return "classHistorical"
	case classPending:
		return "classPending"
	case classExternal:
		return "classExternal"
	default:
		return "refClass(" + strconv.Itoa(int(c)) + ")"
	}
}

// docIssueRef is one classified citation.
//
// Digest is the first 12 hex digits of SHA-256 over the normalized citing
// sentence, and it is the identity: change the sentence, get a different entry.
// Quote is a human-readable excerpt of that same sentence, centered on the
// citation, and the test verifies it really occurs in what was hashed — a
// comment beside a digest can drift into describing something else, a checked
// substring cannot.
type docIssueRef struct {
	File   string
	Issue  int
	Class  refClass
	Digest string
	Quote  string
}

// docIssueRefLedger classifies every issue citation in the documented surface.
//
// Adding a classPending entry is a claim that the issue is OPEN, and the online
// half of this test will hold you to it.
//
// Nothing is classPending today. Every forward reference this package had was
// resolved by #65: #17 (OpenWith) and #33 (Openable) shipped, and #50 was ruled
// will-not-ship. The docs now describe what is there.
//
// When a citation is added or a citing sentence is reworded, the failure
// message prints the exact line to paste here. Read the sentence before you
// paste it; the classification is the whole point, and see "What this guard
// CANNOT catch" above for what a careless one costs.
var docIssueRefLedger = []docIssueRef{
	// doc.go — the package overview, the text that reaches pkg.go.dev.
	{"doc.go", 2, classHistorical, "bb4ba84cacb0", "the lock that made the first hazard survivable (issue #2)."},
	{"doc.go", 17, classHistorical, "8717c0e85f04", "is the admitted variant (issue #17): it takes the destination"},
	{"doc.go", 33, classHistorical, "b314e65b07e6", "is the explicit probe (issue #33), and it exists precisely"},
	{"doc.go", 34, classHistorical, "1dcbdd445ab4", "This is a REFUSAL, not a gap, and it will not be \"fixed\" (#34)."},
	{"doc.go", 50, classHistorical, "e418c60f0f70", "decided, not pending, on issue #50, and decided on SCOPE rather"},

	// README.md — the same story for a reader who never runs go doc.
	{"README.md", 17, classHistorical, "f58ce4a9862b", "is the admitted variant (#17): it takes the destination"},
	{"README.md", 33, classHistorical, "02c7543b895c", "is the explicit probe (#33): `nil` when nothing this"},

	// Implementation comments that carry decision history. Every one of these
	// describes a decision already taken; none presents work as pending.
	{"admission.go", 2, classHistorical, "edda89f9cc92", "That is gone (issue #2): go-enclave maps its own memory, and"},
	{"admission.go", 20, classHistorical, "feb54c3869b1", "was until Codex caught it on PR #20 — published a"},
	{"admission.go", 46, classHistorical, "0441b32ef947", "which is the inconsistency #46 was filed about; a"},
	{"admission.go", 46, classHistorical, "ca8316721e57", "SetLimit — which was issue #46 — and one that lived on"},
	{"enclave.go", 29, classHistorical, "5c1a5bb9794b", "hand-rolled composition in consumers was heading for (#29)."},
	{"enclave.go", 40, classHistorical, "3e861305c5dc", "refused and the mapping is kept so Destroy can be retried (#40)."},
	{"mapping.go", 3, classHistorical, "29046fdb9cc5", "admission fail-open fixed in PR #3, and it would reach mmap with"},
	{"mapping.go", 9, classHistorical, "6dff7778c0c8", "memory (Codex round 3 on PR #9); doing it here means the"},
	{"mapping.go", 12, classHistorical, "1106633cdd0d", "The mprotect seam is what #12 is about: without the unmap"},
	{"mapping.go", 33325, classExternal, "a73a92c526c7", "store to memory nothing reads afterwards — golang/go#33325."},
	{"memlock.go", 46, classHistorical, "5fa7bc53792b", "disagreed about whether the kernel ceiling applied (issue #46)."},
	{"provider.go", 50, classHistorical, "b2ac93fb6c24", "composition, and that is settled rather than pending (issue #50)."},
	{"registry.go", 2, classHistorical, "df0e1f9aa49f", "Option B (#2) deleted memguard's process-global registry because"},
	{"registry.go", 20, classHistorical, "99e173cd6f5b", "on the one guarantee this function makes (Codex, PR #20)."},
	{"registry.go", 33, classHistorical, "7cc13ef4b8e8", "NOT be extended to cover them (#33, decided), for three reasons"},
	{"sealed.go", 33, classHistorical, "30c3a6a7d81a", "and will not cover this type (#33, decided): its count means"},
	{"sealed.go", 34, classHistorical, "08a2e0f591db", "instead, so this call fails on every seal (#34, closed)."},
	{"sealer.go", 50, classHistorical, "2460085c0048", "(the Decrypter/Signer adapter, since split out to issue #50)."},
	{"sealer.go", 50, classHistorical, "7ae0030527d1", "split out of the initial seam PR to its own decision (issue #50)."},

	// #83 — the release-readiness review fixes: a negative BudgetError.InUse,
	// Destroy panicking on a refused release, corruption lost across a retried
	// release, constructor refunds for pages still locked, and a second
	// UnsealRoot after a failed KEK mint.
	{"admission.go", 83, classHistorical, "4b2b25d03852", "had no handle left to release (#83) — so an allocator sized"},
	{"admission.go", 83, classHistorical, "484e8e1660b7", "(free < 0) and reported that -2 pages as the bytes in use (#83)."},
	{"enclave.go", 83, classHistorical, "653549ee0dff", "and the constructors' refund depends on the difference (#83)."},
	{"registry.go", 83, classHistorical, "43aec9096d4b", "— the memory-safety event this error exists to surface (#83)."},
	{"admission.go", 83, classHistorical, "c85d9f81b7c3", "against and the difference is negative without wrapping (#83)."},
	{"enclave.go", 83, classHistorical, "82c2bdc4fc96", "the caller can act on by retrying, and until #83 it panicked too."},
	{"enclave.go", 83, classHistorical, "97ad0733c40d", "failure too, contrary to every statement of the contract (#83)."},
	{"enclave.go", 83, classHistorical, "00281b3a6391", "Since #83 a release that detects corruption and is then refused"},
	{"enclave.go", 83, classHistorical, "135e07374702", "— so the reservation behind them cannot be returned (#83)."},
	{"mapping.go", 83, classHistorical, "5b7d3eb07943", "Before #83 that retry re-verified and reported a clean release;"},
	{"mapping.go", 83, classHistorical, "070f60205562", "[pagesHeldError] whenever nothing could unmap the region (#83)."},
	{"mapping.go", 83, classHistorical, "e911311e30e0", "A retried release must not unlock again (#83)."},
	{"mapping.go", 83, classHistorical, "47c6509f858a", "as abandon's own rollback does (#83): munmap drops the lock"},
	{"admission.go", 83, classHistorical, "f675c1026c13", "Before #83 the mapping was dropped instead, and the charge was"},
	{"enclave.go", 83, classHistorical, "fe9f3986f6ad", "And the mark carries the MAPPING (#83)."},
	{"registry.go", 83, classHistorical, "6132c9fe7336", "ledger, of orphans, that WipeAll retries the same way (#83)."},
	{"registry.go", 83, classHistorical, "6ce9bfdcf9fe", "hand back to the kernel, kept so [WipeAll] can retry it (#83)."},
	{"registry.go", 83, classHistorical, "2962738fb8a3", "failed constructions whose release is still being refused (#83)."},
	{"mapping.go", 83, classHistorical, "93155c342373", "a fresh comparison of the zeroes that run left behind (#83)."},
	{"mapping.go", 83, classHistorical, "f63c87effc61", "as leaving the pages held (#83): dropping the refusal would"},
	{"sealer.go", 83, classHistorical, "81b218859bb5", "root (a consumed unseal handle) cannot be asked again (#83)."},
	{"sealer.go", 83, classHistorical, "b4d203577ea8", "again — what this did until #83 — called UnsealRoot a"},

	// #86 — go-enclave's own OS memory layer over golang.org/x/sys, replacing
	// memcall: one system call per primitive, one unmap, and an honest
	// CoreDumpsDisabled on Windows.
	{"README.md", 86, classHistorical, "7243c4763bdb", "maps its own memory, and since #86 it does so directly over"},
	{"mapping.go", 86, classHistorical, "880801b2fa85", "told, as memcall told it before #86, that the hardening had"},
	{"osmem.go", 86, classHistorical, "85a2203e82db", "That is the reason this layer exists (#86)."},
	{"osmem_unix.go", 86, classHistorical, "e1a3017ced32", "hardening a consumer had before #86 is the hardening it has now."},

	// providertest — the conformance suite added by #64, in its own package.
	// Scanned because the file walk is recursive; a root-only scan would have
	// missed a whole package's docs, silently.
	{"providertest/providertest.go", 45, classHistorical, "af42f5722bd4", "Both were measured in this repository (#45)."},
	{"providertest/residue.go", 45, classHistorical, "f31ce514c0c4", "measured in this repository (#45), are the reason that"},
}

// docIssueRefFiles is the documented surface this guard covers: the package
// docs, the README a consumer actually reads, and the implementation comments
// that carry decision history.
//
// Deliberately NOT covered:
//   - CLAUDE.md, which is untracked (#80): agent working notes are kept out of
//     the published tree. A file some checkouts have and others lack cannot be
//     in a ledger that fails on an orphaned entry.
//   - CHANGELOG.md, which is a historical record by construction. Every entry
//     cites the issue it closed, and every one of those is closed; classifying
//     them would be noise that teaches readers to add classHistorical without
//     thinking, which is how a ledger stops being read.
//   - *_test.go, which document tests rather than the API. They are read by
//     people changing the tests, not by consumers, and they cite PRs and
//     review rounds far more than open work. This file is one of them, which
//     is also why its own many citations do not appear in the ledger.
//   - the Makefile and .github/workflows, which are build configuration. Their
//     citations (#61, #49, go-luks2 #21) explain why a flag is not optional.
func docIssueRefFiles(t *testing.T) []string {
	t.Helper()

	var files []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// .git, .github and any other dot directory hold no package docs.
			if path != "." && strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir
			}
			if d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		switch {
		case strings.HasSuffix(name, "_test.go"):
			return nil
		case strings.HasSuffix(name, ".go"):
			files = append(files, filepath.ToSlash(path))
		case name == "README.md":
			files = append(files, filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk package tree: %v", err)
	}
	sort.Strings(files)

	// Slash-separated, always. WalkDir hands back the platform separator, and
	// the ledger is checked-in text that cannot depend on who ran the test —
	// on Windows a backslash would make every subpackage citation read as
	// unclassified AND every subpackage ledger entry as orphaned, which is a
	// failure, but a baffling one. filepath.Join in extractCitations converts
	// back on the way to the filesystem.

	// An empty scan set reports exactly what a clean scan reports. Refuse it.
	if len(files) == 0 {
		t.Fatal("scanned no files: the extractor is pointed at nothing and " +
			"would report a clean tree no matter what the docs say")
	}
	// The walk exists because #64 added the providertest subpackage on the same
	// day this guard landed, and a scanner that read only the root directory
	// would have excluded a whole new package's docs — silently, which is the
	// one failure mode this file is not allowed to have.
	return files
}

// issueRef matches "#123" and captures the number, and qualifiedRef matches the
// same thing carrying another repository's name — "golang/go#33325".
//
// The bare form is NOT enough on its own. "PKCS#11" is not a citation of issue
// 11, and treating it as one is a false positive that lands on whoever next
// writes about a cryptographic token standard — which happened the day this
// guard was written, when #64 added providertest and its docs mention PKCS#11
// twice. So a "#" preceded by a letter or digit is part of a word, not a
// citation, unless the token before it looks like owner/repo.
var (
	issueRef     = regexp.MustCompile(`#(\d+)`)
	qualifiedRef = regexp.MustCompile(`[A-Za-z0-9._-]+/[A-Za-z0-9._-]+#(\d+)`)
)

// isWordChar reports whether b would make a preceding "#" part of a word.
func isWordChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// citation is one classified-or-not occurrence: a single issue number in a
// single sentence.
type citation struct {
	file     string
	issue    int
	line     int
	sentence string
	// at is the byte offset of the "#" within sentence, so a quote can be
	// centered on the claim rather than on the sentence's opening words.
	at     int
	digest string
}

func (c citation) key() string {
	return fmt.Sprintf("%s#%d@%s", c.file, c.issue, c.digest)
}

// ledgerLine renders the entry a maintainer must paste to classify this
// citation. Printing it is what keeps the ledger maintainable by hand.
func (c citation) ledgerLine() string {
	class := "classHistorical /* or classPending / classExternal */"
	return fmt.Sprintf("{%q, %d, %s, %q, %q},",
		c.file, c.issue, class, c.digest, excerptAround(c.sentence, c.at))
}

// paragraph is a normalized block of prose plus a mapping back to source
// lines, so a failure can name the line the citation is actually on.
type paragraph struct {
	text string
	// lineAt[i] is the source line the normalized rune at offset i came from.
	lineAt []int
}

func (p paragraph) lineFor(offset int) int {
	if len(p.lineAt) == 0 {
		return 0
	}
	if offset >= len(p.lineAt) {
		return p.lineAt[len(p.lineAt)-1]
	}
	return p.lineAt[offset]
}

// paragraphsOf splits a file into normalized paragraphs.
//
// Go files are PARSED and only their comments are scanned, so a "#1" inside a
// string literal is not a doc claim and is not treated as one. A paragraph ends
// at a blank comment line, which is what makes rewrapping invisible to the
// digest while a genuine wording change is not.
func paragraphsOf(t *testing.T, file string, src []byte) []paragraph {
	t.Helper()

	type sourceLine struct {
		text string
		num  int
	}
	var lines []sourceLine

	if strings.HasSuffix(file, ".go") {
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, file, src, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		var all []sourceLine
		for _, group := range parsed.Comments {
			for _, c := range group.List {
				all = append(all, sourceLine{
					text: stripCommentMarkers(c.Text),
					num:  fset.Position(c.Pos()).Line,
				})
			}
			// A comment group boundary is a paragraph boundary.
			all = append(all, sourceLine{text: "", num: 0})
		}
		lines = all
	} else {
		for i, l := range strings.Split(string(src), "\n") {
			lines = append(lines, sourceLine{text: l, num: i + 1})
		}
	}

	var (
		out     []paragraph
		current paragraph
	)
	flush := func() {
		if strings.TrimSpace(current.text) != "" {
			out = append(out, current)
		}
		current = paragraph{}
	}
	for _, l := range lines {
		if strings.TrimSpace(l.text) == "" {
			flush()
			continue
		}
		for _, field := range strings.Fields(l.text) {
			if current.text != "" {
				current.text += " "
				current.lineAt = append(current.lineAt, l.num)
			}
			current.text += field
			for range field {
				current.lineAt = append(current.lineAt, l.num)
			}
		}
	}
	flush()
	return out
}

// stripCommentMarkers removes the syntax that carries no meaning, so that
// moving a sentence between a // comment and a /* */ one, or rewrapping it,
// does not change its digest.
func stripCommentMarkers(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "//")
	s = strings.TrimPrefix(s, "/*")
	s = strings.TrimSuffix(s, "*/")
	s = strings.TrimSpace(s)
	// A list bullet is layout, not content.
	s = strings.TrimPrefix(s, "- ")
	return s
}

// sentencesOf splits normalized prose at a period followed by whitespace. It is
// a heuristic — see "What this guard CANNOT catch" — but it is a STABLE one,
// which is all the digest needs.
func sentencesOf(p paragraph) []struct {
	text   string
	offset int
} {
	type sentence = struct {
		text   string
		offset int
	}
	var out []sentence
	start := 0
	for i := 0; i < len(p.text)-1; i++ {
		if p.text[i] == '.' && p.text[i+1] == ' ' {
			out = append(out, sentence{text: strings.TrimSpace(p.text[start : i+1]), offset: start})
			start = i + 2
		}
	}
	if start < len(p.text) {
		out = append(out, sentence{text: strings.TrimSpace(p.text[start:]), offset: start})
	}
	return out
}

// extractCitations finds every issue citation in the documented surface, one
// per (sentence, issue number).
func extractCitations(t *testing.T, root string, files []string) []citation {
	t.Helper()

	var out []citation
	for _, file := range files {
		src, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		for _, p := range paragraphsOf(t, file, src) {
			for _, s := range sentencesOf(p) {
				// Positions where another repository's name qualifies the
				// number; those ARE citations even though a letter precedes
				// the "#", and they are classified as classExternal.
				qualified := map[int]bool{}
				for _, q := range qualifiedRef.FindAllStringSubmatchIndex(s.text, -1) {
					qualified[q[2]-1] = true // the "#" itself
				}
				for _, loc := range issueRef.FindAllStringSubmatchIndex(s.text, -1) {
					// "PKCS#11" is a standard, not issue 11.
					if loc[0] > 0 && isWordChar(s.text[loc[0]-1]) && !qualified[loc[0]] {
						continue
					}
					n, err := strconv.Atoi(s.text[loc[2]:loc[3]])
					if err != nil {
						continue
					}
					out = append(out, citation{
						file:     file,
						issue:    n,
						line:     p.lineFor(s.offset + loc[0]),
						sentence: s.text,
						at:       loc[0],
						digest:   digestOf(s.text),
					})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].file != out[j].file {
			return out[i].file < out[j].file
		}
		if out[i].line != out[j].line {
			return out[i].line < out[j].line
		}
		return out[i].issue < out[j].issue
	})
	return out
}

// digestOf is the citation identity: the first 12 hex digits of SHA-256 over
// the normalized sentence. Twelve is 48 bits, which is far more than a corpus
// of a few dozen sentences needs, and short enough to read in a diff.
func digestOf(sentence string) string {
	sum := sha256.Sum256([]byte(sentence))
	return hex.EncodeToString(sum[:])[:12]
}

// excerptAround shortens a sentence for the Quote field, centered on the
// citation itself so the quote shows the CLAIM rather than whatever the
// sentence happened to open with. It cuts on word boundaries and returns a
// genuine substring of what was hashed, which is what the test verifies.
func excerptAround(sentence string, at int) string {
	const want = 66
	if len(sentence) <= want {
		return sentence
	}
	start := at - want/2
	if start < 0 {
		start = 0
	}
	end := start + want
	if end > len(sentence) {
		end = len(sentence)
		start = end - want
	}
	if start > 0 {
		if adv := strings.IndexByte(sentence[start:end], ' '); adv >= 0 {
			start += adv + 1
		}
	}
	if end < len(sentence) {
		if cut := strings.LastIndexByte(sentence[start:end], ' '); cut > 0 {
			end = start + cut
		}
	}
	return sentence[start:end]
}

// TestDocIssueRefsAreClassified is the offline half. It has teeth with no
// network at all: every citing sentence in the documented surface must appear
// in the ledger, and every ledger entry must still have a sentence behind it.
func TestDocIssueRefsAreClassified(t *testing.T) {
	files := docIssueRefFiles(t)
	citations := extractCitations(t, ".", files)

	// A scan that found nothing is indistinguishable from a clean scan, and
	// this package cites dozens of issues. Refuse the silent instrument.
	if len(citations) == 0 {
		t.Fatalf("found no issue citations across %d files (%v): the extractor "+
			"is broken, not the docs", len(files), files)
	}
	t.Logf("scanned %d files, found %d citing sentences, ledger has %d entries",
		len(files), len(citations), len(docIssueRefLedger))

	byKey := map[string]docIssueRef{}
	for _, e := range docIssueRefLedger {
		key := fmt.Sprintf("%s#%d@%s", e.File, e.Issue, e.Digest)
		if _, dup := byKey[key]; dup {
			t.Errorf("docIssueRefLedger has two entries for %s; one sentence is "+
				"classified once", key)
		}
		byKey[key] = e
	}

	seen := map[string]bool{}
	for _, c := range citations {
		seen[c.key()] = true
		entry, ok := byKey[c.key()]
		if !ok {
			t.Errorf("%s:%d cites issue #%d in a sentence that is not classified "+
				"in docIssueRefLedger.\n"+
				"  sentence: %s\n"+
				"  paste this, after deciding which class it is:\n"+
				"      %s\n"+
				"  classHistorical if the sentence describes something already done "+
				"or decided; classPending if it presents the issue as unresolved "+
				"future work, which this test will then verify is OPEN; "+
				"classExternal if the number belongs to another repository.",
				c.file, c.line, c.issue, c.sentence, c.ledgerLine())
			continue
		}
		// The digest is the identity; the quote is what a human reads instead
		// of the digest. A quote that is not really in the sentence would let
		// the ledger describe one thing while classifying another.
		if !strings.Contains(c.sentence, entry.Quote) {
			t.Errorf("%s:%d — ledger entry for issue #%d quotes %q, which does "+
				"not appear in the sentence it classifies.\n  sentence: %s",
				c.file, c.line, c.issue, entry.Quote, c.sentence)
		}
	}

	var orphans []string
	for key, entry := range byKey {
		if !seen[key] {
			orphans = append(orphans, fmt.Sprintf("%s (%s, quoting %q)", key, entry.Class, entry.Quote))
		}
	}
	sort.Strings(orphans)
	for _, o := range orphans {
		t.Errorf("docIssueRefLedger declares %s but no sentence in the docs "+
			"hashes to it — the citation was deleted, or its sentence was "+
			"reworded and now needs classifying again. Remove or replace the "+
			"entry: a ledger nobody prunes stops describing the tree it is "+
			"supposed to describe.", o)
	}
}

// # The online half, and why its policy is a value rather than a t.Fatalf
//
// Review on PR #66 found the third defect in this file, and it was the same
// class as the two before it: the failure policy below was decided inline with
// t.Skipf and t.Fatalf calls, so the only way to exercise it was to have a
// real Gitea, real credentials and a classPending entry. There are none, the
// default run skips, and every branch — the control lookup, the pending
// lookup, HTTP and auth failure, a malformed response, a closed pending issue,
// and the fatal branch of the policy itself — was covered by nothing. A
// regression turning any of them fail-open would have left go test green.
// That is the defect this whole file exists to prevent, living inside the
// guard.
//
// So the decision is now a VALUE. evaluateIssueState returns what should
// happen and why; the test function's only job is to translate that into a
// skip, a log or a failure. Everything above it is exercised in the default
// run by TestIssueStatePolicy against a stubbed http.RoundTripper: hermetic,
// no network, no Gitea, no credentials, and not even a loopback port.

// TestCitationExtraction pins the two extractor rules that a false positive or
// a false negative would quietly rot.
//
// Both were found by merging #64, not by inspection: its providertest package
// writes "PKCS#11" twice, which a bare `#(\d+)` reads as a citation of issue
// 11, and it lives in a subdirectory, which a root-only file scan never reads.
// A guard that invents citations gets its ledger padded with nonsense until
// someone deletes the check; a guard that misses a whole package reports what
// a clean scan reports.
func TestCitationExtraction(t *testing.T) {
	tests := []struct {
		name string
		text string
		want []int
	}{
		{"plain citation", "That is gone (issue #2): it maps its own memory.", []int{2}},
		{"parenthesised", "The sweep will not cover them (#33, decided).", []int{33}},
		{"two in one sentence", "Between #17 and #33 the gap closed.", []int{17, 33}},
		{"standard, not an issue", "the PKCS#11 wrappers return a slice.", nil},
		{"standard mid-word with more digits", "SHA#256 and PKCS#11 are not issues.", nil},
		{"another repository keeps its citation", "a store nothing reads — golang/go#33325.", []int{33325}},
		{"no digits is not a citation", "the #nosec annotation and a # alone.", nil},
		{"issue number at the very start", "#61 made the core count part of the oracle.", []int{61}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			file := filepath.Join(dir, "README.md")
			if err := os.WriteFile(file, []byte(tc.text), 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			// The root is passed rather than reached by os.Chdir: chdir is
			// process-global, and a test that moves the working directory
			// out from under a sibling is a defect waiting for the first
			// t.Parallel in this package.
			var got []int
			for _, c := range extractCitations(t, dir, []string{"README.md"}) {
				got = append(got, c.issue)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("extracted %v, want %v (from %q)", got, tc.want, tc.text)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("citation %d = #%d, want #%d", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestDocIssueRefFilesReachesSubpackages is the other half of the same lesson:
// the scan must follow the tree, not just the root directory.
func TestDocIssueRefFilesReachesSubpackages(t *testing.T) {
	files := docIssueRefFiles(t)

	var sawRoot, sawSub bool
	for _, f := range files {
		if f == "doc.go" {
			sawRoot = true
		}
		if strings.Contains(f, "/") && strings.HasSuffix(f, ".go") {
			sawSub = true
		}
		if strings.HasSuffix(f, "_test.go") {
			t.Errorf("%s is a test file and should not be in the documented surface", f)
		}
		if strings.ContainsRune(f, '\\') {
			t.Errorf("%s carries a platform separator; ledger keys are "+
				"slash-separated on every host or the same tree classifies "+
				"differently depending on who ran the test", f)
		}
		if filepath.Base(f) == "CHANGELOG.md" {
			t.Errorf("%s is excluded by design; see docIssueRefFiles", f)
		}
	}
	if !sawRoot {
		t.Error("doc.go is not in the scan set: the root package docs are the whole point")
	}
	if !sawSub {
		t.Error("no file in a subdirectory is in the scan set. If this package " +
			"genuinely has no subpackages any more, delete this check; while it " +
			"has one (providertest, added by #64), a scan that cannot see it " +
			"reports exactly what a clean scan reports.")
	}
}

// onlineAction is what the online half decided to do. It exists so the policy
// can be asserted in a table rather than observed through a t.Fatalf.
type onlineAction int

const (
	// actionVerified: the check ran. Problems, if any, are real findings.
	actionVerified onlineAction = iota
	// actionSkip: the check could not run for a reason that is not anyone's
	// fault — no configuration, or the server is genuinely unreachable.
	actionSkip
	// actionFail: the check must fail. Either it found a stale reference, or
	// it could not run for a reason that WOULD hide one.
	actionFail
)

func (a onlineAction) String() string {
	switch a {
	case actionVerified:
		return "verified"
	case actionSkip:
		return "skip"
	case actionFail:
		return "fail"
	default:
		return "onlineAction(" + strconv.Itoa(int(a)) + ")"
	}
}

// onlineResult is the decision plus everything needed to explain it.
type onlineResult struct {
	Action onlineAction
	// Reason explains the Action for any outcome except a clean verification.
	Reason string
	// Problems are stale references found, one message each.
	Problems []string
	// Checked is how many classPending entries had their state resolved. Zero
	// with actionVerified means the ledger claims nothing pending — vacuous by
	// construction, and said so out loud rather than passed over.
	Checked int
}

// onlineFailurePolicy decides what an issue-API failure means, and it exists as
// a named thing because getting it wrong is how a guard goes quiet.
//
//	                       | ENCLAVE_ISSUE_API unset | ENCLAVE_ISSUE_API set
//	-----------------------+-------------------------+----------------------
//	 nothing else wrong    | skip                    | verify
//	 transport failure     | (cannot arise)          | skip
//	 HTTP status / auth    | (cannot arise)          | FAIL
//	 malformed config      | (cannot arise)          | FAIL
//	 malformed response    | (cannot arise)          | FAIL
//	 wrong state reported  | (cannot arise)          | FAIL
//	 wrong repository      | (cannot arise)          | FAIL
//	 pending issue closed  | (cannot arise)          | FAIL
//
// Setting ENCLAVE_ISSUE_API IS the opt-in. A developer without credentials
// leaves it unset and gets the skip; a developer who sets it has asked for the
// check, so a rejected token or a wrong endpoint is their bug and fails.
//
// This used to have a third state — warn, rather than fail, when the endpoint
// was broken but nothing was classPending, on the reasoning that a credential
// nobody needs should not break a build. Review on PR #66 asked whether that
// warning was actually visible, and it is not: MEASURED, a passing test in a
// non-verbose run emits nothing at all — not t.Log, not os.Stderr, not
// os.Stdout — and neither this repository's CI (ci.yml runs `go test` without
// -v) nor `make test` is verbose. The warning was invisible in every context
// it existed for, which is the silent-instrument pattern one level up from the
// one this file guards. A state nobody can observe is not a state, so it is
// gone. The reasoning behind it was also thinner than it looked: nobody is
// forced to set the variable.
//
// The row that could never be a skip, and still cannot, is a probe reporting
// the WRONG state or the WRONG repository. That is not unavailability, it is
// an instrument that lies, and every verdict below it would be worthless.
//
// misconfigured is the SINGLE place a misconfiguration is turned into a
// verdict. Expressing it here and again in its caller would let the two drift,
// and the drift would be silent — which is the failure mode of everything else
// in this file.
func misconfigured(reason string) onlineResult {
	return onlineResult{
		Action: actionFail,
		Reason: fmt.Sprintf("the issue-state half is configured but cannot run: "+
			"%s. Setting ENCLAVE_ISSUE_API is what asks for this check, so this is "+
			"a configuration failure rather than unavailability — skipping it "+
			"would make a stale forward reference read as green, and warning "+
			"about it would print nothing a non-verbose run can see. Unset "+
			"ENCLAVE_ISSUE_API to opt out deliberately.", reason),
	}
}

// controlIssue is the instrument check: an issue whose state is KNOWN, and
// known to be the failing one. #17 is closed — it shipped as OpenWith in PR
// #54, which is how this test came to exist. If it ever comes back open, the
// probe is lying or aimed at the wrong repository, and nothing it says may be
// believed.
const controlIssue = 17

// wantRepository is the owner/name every lookup must come from. It is spelled
// out rather than derived, because the point is to catch an endpoint that
// resolves successfully against the WRONG repository — deriving it from the
// same configuration that is under suspicion would prove nothing.
const wantRepository = "jeremyhahn/go-enclave"

// issueAPI is the endpoint the online half talks to. The token is carried here
// rather than read from the environment inside the request, so the policy can
// be tested without setting process-wide state, and so a missing token is an
// input to the decision instead of a hidden one.
type issueAPI struct {
	base   string
	token  string
	client *http.Client
}

// evaluateIssueState runs the online half and returns what should happen. It
// makes every decision; the caller only reports it.
func evaluateIssueState(ctx context.Context, api issueAPI, pending []docIssueRef) onlineResult {
	if api.base == "" {
		return onlineResult{
			Action: actionSkip,
			Reason: fmt.Sprintf("ENCLAVE_ISSUE_API is not set, so the issue-state "+
				"half did not run (%d classPending entries would have been "+
				"checked). The classification half still ran.", len(pending)),
		}
	}

	// A base URL that cannot address anything is a MISCONFIGURATION, and it is
	// checked here rather than left to surface as a request failure, so the
	// message names the actual problem.
	if u, err := url.Parse(api.base); err != nil {
		return misconfigured(fmt.Sprintf("ENCLAVE_ISSUE_API=%q is not a URL: %v",
			api.base, err))
	} else if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return misconfigured(fmt.Sprintf("ENCLAVE_ISSUE_API=%q is not an http or "+
			"https URL with a host; a value like \"gitea.local/api/v1/...\" is "+
			"accepted by the request builder and then refused by the client, "+
			"which would read as unavailability rather than as the "+
			"misconfiguration it is", api.base))
	}

	// A configured endpoint with no token is a MISCONFIGURATION, not an absent
	// configuration, and it is exactly the shape that used to read as green.
	if api.token == "" {
		return misconfigured(fmt.Sprintf("ENCLAVE_ISSUE_API is set to %s but "+
			"ENCLAVE_ISSUE_TOKEN is empty; this repository is private, so every "+
			"lookup would be refused", api.base))
	}

	// Instrument check, before any verdict is drawn from this probe.
	facts, err := fetchIssue(ctx, api, controlIssue)
	state := facts.state
	switch {
	case err != nil && isTransport(err):
		return onlineResult{
			Action: actionSkip,
			Reason: fmt.Sprintf("issue API at %s is not reachable (%v), so the "+
				"issue-state half did not run (%d classPending entries would have "+
				"been checked). The classification half still ran.",
				api.base, err, len(pending)),
		}
	case err != nil:
		return misconfigured(fmt.Sprintf("the issue API at %s answered, but the "+
			"control lookup failed: %v", api.base, err))
	case state != "closed":
		// Never a skip and never a warning: an instrument that lies invalidates
		// every verdict, including the verdict that there is nothing to check.
		return onlineResult{
			Action: actionFail,
			Reason: fmt.Sprintf("instrument check failed: issue #%d reports state "+
				"%q, want \"closed\". This probe cannot tell a closed issue from an "+
				"open one, so a pass from it would mean nothing. Check that "+
				"ENCLAVE_ISSUE_API=%s points at this repository.",
				controlIssue, state, api.base),
		}
	case facts.repo != wantRepository:
		// The state alone does not identify the tracker. Same reasoning, same
		// verdict: an instrument aimed at the wrong repository is lying about
		// which questions it is answering.
		return onlineResult{
			Action: actionFail,
			Reason: fmt.Sprintf("instrument check failed: issue #%d is closed, but "+
				"it belongs to %q and this package's issues live in %q. Issue "+
				"numbers are not unique across a Gitea instance, so a probe aimed "+
				"at another repository would resolve classPending entries against "+
				"unrelated issues whose numbers happen to collide. Check that "+
				"ENCLAVE_ISSUE_API=%s points at this repository.",
				controlIssue, facts.repo, wantRepository, api.base),
		}
	}

	if len(pending) == 0 {
		return onlineResult{
			Action: actionVerified,
			Reason: fmt.Sprintf("instrument check passed (#%d reports %q via %s), "+
				"and no classPending citations are in the ledger: the docs make no "+
				"claim about unresolved work, so there is no issue state to verify. "+
				"This half is vacuous BY CONSTRUCTION here, not by accident.",
				controlIssue, state, api.base),
		}
	}

	sorted := make([]docIssueRef, len(pending))
	copy(sorted, pending)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].File != sorted[j].File {
			return sorted[i].File < sorted[j].File
		}
		return sorted[i].Issue < sorted[j].Issue
	})

	result := onlineResult{
		Action: actionVerified,
		Reason: fmt.Sprintf("instrument check passed: #%d reports %q via %s",
			controlIssue, state, api.base),
	}
	for _, e := range sorted {
		got, err := fetchIssue(ctx, api, e.Issue)
		if err != nil {
			// Past the control, even a transport blip is a failure: the
			// endpoint answered moments ago, so an unresolvable pending entry
			// is a real unknown and must not read as verified.
			result.Problems = append(result.Problems, fmt.Sprintf(
				"%s (issue #%d, %q): cannot resolve its state: %v",
				e.File, e.Issue, e.Quote, err))
			continue
		}
		// The control proved the endpoint answers for THIS repository; it did
		// not prove it does so for every number. A proxy, a redirect or a
		// mistyped base that serves the control correctly and a pending issue
		// from somewhere else would otherwise report the docs as verified
		// against the wrong tracker — the same asymmetry the control check
		// closed, one level down, found by review on PR #66. Checked is NOT
		// incremented here: an answer from the wrong repository resolved
		// nothing.
		if got.repo != wantRepository {
			result.Problems = append(result.Problems, fmt.Sprintf(
				"%s classifies issue #%d as classPending, and the endpoint answered "+
					"for it — but the answer came from %q, not %q. Issue numbers are "+
					"not unique across a Gitea instance, so this says nothing about "+
					"the issue the docs actually cite.",
				e.File, e.Issue, got.repo, wantRepository))
			continue
		}
		result.Checked++
		if got.state != "open" {
			result.Problems = append(result.Problems, fmt.Sprintf(
				"%s classifies issue #%d as classPending — the docs present it as "+
					"unresolved future work — but the issue is %s.\n"+
					"  sentence: %s...\n"+
					"  Either the work landed and the prose should describe what is "+
					"THERE, or it was ruled out and the prose should say so as "+
					"settled. Then reclassify the entry.",
				e.File, e.Issue, got.state, e.Quote))
		}
	}
	if len(result.Problems) > 0 {
		result.Action = actionFail
	}
	return result
}

// pendingRefs returns the ledger entries claiming unresolved work.
func pendingRefs() []docIssueRef {
	var pending []docIssueRef
	for _, e := range docIssueRefLedger {
		if e.Class == classPending {
			pending = append(pending, e)
		}
	}
	return pending
}

// TestDocIssueRefsPendingAreStillOpen is the online half: the shape of #65
// itself, for a reference that is honest when written and rots later.
//
// It decides nothing. evaluateIssueState decides, and this reports — which is
// what lets TestIssueStatePolicy exercise the decisions without a network.
func TestDocIssueRefsPendingAreStillOpen(t *testing.T) {
	api := issueAPI{
		base:   strings.TrimRight(os.Getenv("ENCLAVE_ISSUE_API"), "/"),
		token:  os.Getenv("ENCLAVE_ISSUE_TOKEN"),
		client: &http.Client{Timeout: 10 * time.Second},
	}

	res := evaluateIssueState(t.Context(), api, pendingRefs())
	switch res.Action {
	case actionSkip:
		t.Skip(res.Reason)
	case actionVerified:
		t.Log(res.Reason)
		if res.Checked > 0 {
			t.Logf("resolved %d classPending citations, all open", res.Checked)
		}
	case actionFail:
		if res.Reason != "" {
			t.Error(res.Reason)
		}
		for _, p := range res.Problems {
			t.Error(p)
		}
	}
}

// fetchIssueState returns the Gitea state ("open" or "closed") of one issue.
// Failures to REACH the endpoint are wrapped in transportError; failures that
// came back FROM it are not, because a server that answers is a server that is
// configured wrong rather than one that is down.
func fetchIssue(ctx context.Context, api issueAPI, num int) (issueFacts, error) {
	endpoint := api.base + "/issues/" + strconv.Itoa(num)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return issueFacts{}, fmt.Errorf("malformed endpoint: %w", err)
	}
	req.Header.Set("Authorization", "token "+api.token)

	resp, err := api.client.Do(req)
	if err != nil {
		// Not every Do error is the network being down. A scheme-less or
		// otherwise unusable URL fails inside the client BEFORE any dial —
		// "unsupported protocol scheme" — and blanketing that as transport
		// would make a misconfigured endpoint take the SKIP path under the
		// very policy that exists to stop it (found by review on PR #66,
		// reproduced: NewRequestWithContext accepts "gitea.local/api/..."
		// happily and Do rejects it).
		//
		// A real network failure implements net.Error — dial refusals, DNS
		// failures and client timeouts all do. The trap is that *url.Error,
		// which http.Client wraps EVERY failure in, implements net.Error
		// itself, so errors.As on the outer error matches unconditionally and
		// classifies everything as transport. That is not hypothetical: it is
		// what the first attempt at this fix did, and the table row for a
		// non-network client error is what caught it. Unwrap the url.Error and
		// ask about what is inside.
		inner := err
		var ue *url.Error
		if errors.As(err, &ue) {
			inner = ue.Err
		}
		var ne net.Error
		if errors.As(inner, &ne) {
			return issueFacts{}, &transportError{err: err}
		}
		return issueFacts{}, fmt.Errorf("issue #%d: the request failed before reaching the "+
			"endpoint (%w) — this is the configuration, not the network", num, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return issueFacts{}, fmt.Errorf("GET issue #%d: HTTP %d (a rejected token, a wrong "+
			"repository or a missing issue — the endpoint answered)", num, resp.StatusCode)
	}
	var payload struct {
		State      string `json:"state"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return issueFacts{}, fmt.Errorf("issue #%d: response was not the expected JSON: %w", num, err)
	}
	if payload.State == "" {
		return issueFacts{}, fmt.Errorf("issue #%d: response carried no state field", num)
	}
	return issueFacts{state: payload.State, repo: payload.Repository.FullName}, nil
}

// issueFacts is what one lookup establishes: the state, and WHOSE issue it is.
//
// The repository matters because issue numbers are not unique across a Gitea
// instance. Review on PR #66 pointed out that a control asserting only
// "#17 is closed" passes against any repository that also happens to have a
// closed #17 — and measured on this server, go-blockstore, go-luks2,
// go-quicbaas and go-qrdb all do. A probe aimed at the wrong tracker would
// then resolve classPending entries against unrelated issues whose numbers
// merely collide.
type issueFacts struct {
	state string
	repo  string
}

// transportError marks a failure to reach the endpoint at all, as opposed to
// reaching it and being refused. Only the former is a clean skip.
type transportError struct{ err error }

func (e *transportError) Error() string { return e.err.Error() }
func (e *transportError) Unwrap() error { return e.err }

func isTransport(err error) bool {
	var te *transportError
	return errors.As(err, &te)
}

// ---------------------------------------------------------------------------
// The policy's own tests. These are the ones that run by default.
// ---------------------------------------------------------------------------

// issueStub is a stand-in Gitea whose answers are scripted per issue number,
// so every row of onlineFailurePolicy can be reached without a network, a
// server or a credential.
//
// It is an http.RoundTripper rather than an httptest.Server deliberately.
// Review on PR #66 pointed out that httptest.NewServer opens a loopback
// listener, which a sandboxed or socket-restricted runner can refuse — and a
// guard whose own tests cannot run everywhere is the thing this file is about.
// A RoundTripper still exercises everything fetchIssueState does (URL
// construction, the Authorization header, status handling, body decoding) and
// opens no port, and it lets a transport failure be produced exactly rather
// than arranged by closing a server.
type issueStub struct {
	// bodies maps issue number to the exact response body.
	bodies map[int]string
	// status maps issue number to a non-200 status. Takes precedence.
	status map[int]int
	// err, when set, is returned instead of any response: a transport failure,
	// the one condition that is legitimately a skip.
	err error
	// gotAuth records the Authorization header of the last request, so the
	// test can prove the token is actually sent rather than assumed.
	gotAuth string
}

func (s *issueStub) RoundTrip(r *http.Request) (*http.Response, error) {
	s.gotAuth = r.Header.Get("Authorization")
	if s.err != nil {
		return nil, s.err
	}
	num := 0
	if i := strings.LastIndex(r.URL.Path, "/"); i >= 0 {
		num, _ = strconv.Atoi(r.URL.Path[i+1:])
	}
	resp := &http.Response{
		Header:  make(http.Header),
		Request: r,
		Body:    io.NopCloser(strings.NewReader("")),
	}
	if code, ok := s.status[num]; ok {
		resp.StatusCode = code
		return resp, nil
	}
	body, ok := s.bodies[num]
	if !ok {
		resp.StatusCode = http.StatusNotFound
		return resp, nil
	}
	resp.StatusCode = http.StatusOK
	resp.Header.Set("Content-Type", "application/json")
	resp.Body = io.NopCloser(strings.NewReader(body))
	return resp, nil
}

// api wires the stub into an issueAPI. The base URL is never resolved — the
// RoundTripper intercepts before any DNS or dial happens — but it is a real
// URL so request construction is exercised for real.
func (s *issueStub) api() issueAPI {
	return issueAPI{
		base:   "http://issues.example/api/v1/repos/jeremyhahn/go-enclave",
		token:  "test-token",
		client: &http.Client{Transport: s},
	}
}

func closedControl() map[int]string {
	return map[int]string{controlIssue: controlBody(wantRepository)}
}

func controlBody(repo string) string {
	return issueBody("closed", repo)
}

// issueBody is one Gitea issue response. The repository is always present
// because a real one always is (verified against the live API), and because a
// stub that omitted it would let the repository checks pass by accident.
func issueBody(state, repo string) string {
	return `{"state":"` + state + `","repository":{"full_name":"` + repo + `"}}`
}

func pendingLedger(issue int) []docIssueRef {
	return []docIssueRef{{"doc.go", issue, classPending, "0123456789ab", "a sentence claiming issue #" + strconv.Itoa(issue) + " is pending"}}
}

// TestIssueStatePolicy walks every row of onlineFailurePolicy against a stub
// server. It is the answer to the third finding on PR #66: before it, the
// entire online half — including the fatal branch that is the only thing
// standing between a stale forward reference and a green build — was reachable
// only with a live Gitea and a classPending entry, so nothing exercised it.
func TestIssueStatePolicy(t *testing.T) {
	// A dial that never completes: the one failure that is legitimately a skip.
	// Produced exactly rather than arranged, so the case cannot quietly become
	// something else (a refused connection is not the same as a DNS failure,
	// and both must read as transport).
	unreachable := func(*testing.T) issueAPI {
		return (&issueStub{err: &net.OpError{
			Op:  "dial",
			Net: "tcp",
			Err: errors.New("connect: connection refused"),
		}}).api()
	}

	tests := []struct {
		name    string
		api     func(t *testing.T) issueAPI
		pending []docIssueRef
		want    onlineAction
		// wantIn is a fragment the Reason or a Problem must contain, so a case
		// cannot pass by producing the right action for the wrong reason.
		wantIn      string
		wantChecked int
	}{
		{
			name:   "not configured, nothing pending, skips",
			api:    func(*testing.T) issueAPI { return issueAPI{} },
			want:   actionSkip,
			wantIn: "ENCLAVE_ISSUE_API is not set",
		},
		{
			name:    "not configured, pending present, still skips",
			api:     func(*testing.T) issueAPI { return issueAPI{} },
			pending: pendingLedger(99),
			want:    actionSkip,
			wantIn:  "1 classPending entries would have been checked",
		},
		{
			// The exact value review on PR #66 reproduced: accepted by the
			// request builder, refused by the client, and formerly a SKIP.
			name: "scheme-less base URL, pending present, FAILS as misconfiguration",
			api: func(*testing.T) issueAPI {
				return issueAPI{
					base:   "gitea.local/api/v1/repos/jeremyhahn/go-enclave",
					token:  "test-token",
					client: &http.Client{},
				}
			},
			pending: pendingLedger(99),
			want:    actionFail,
			wantIn:  "not an http or https URL with a host",
		},
		{
			name: "scheme-less base URL, nothing pending, FAILS anyway",
			api: func(*testing.T) issueAPI {
				return issueAPI{
					base:   "gitea.local/api/v1/repos/jeremyhahn/go-enclave",
					token:  "test-token",
					client: &http.Client{},
				}
			},
			want:   actionFail,
			wantIn: "not an http or https URL with a host",
		},
		{
			name: "non-http scheme, pending present, FAILS",
			api: func(*testing.T) issueAPI {
				return issueAPI{base: "ftp://gitea.local/api", token: "t", client: &http.Client{}}
			},
			pending: pendingLedger(99),
			want:    actionFail,
			wantIn:  "not an http or https URL with a host",
		},
		{
			name: "client error that is NOT a network error, pending present, FAILS",
			api: func(*testing.T) issueAPI {
				return (&issueStub{err: errors.New("unsupported protocol scheme \"\"")}).api()
			},
			pending: pendingLedger(99),
			want:    actionFail,
			wantIn:  "this is the configuration, not the network",
		},
		{
			name: "token empty, nothing pending, FAILS anyway",
			api: func(t *testing.T) issueAPI {
				api := (&issueStub{bodies: closedControl()}).api()
				api.token = ""
				return api
			},
			want:   actionFail,
			wantIn: "ENCLAVE_ISSUE_TOKEN is empty",
		},
		{
			name: "token empty, pending present, FAILS",
			api: func(t *testing.T) issueAPI {
				api := (&issueStub{bodies: closedControl()}).api()
				api.token = ""
				return api
			},
			pending: pendingLedger(99),
			want:    actionFail,
			wantIn:  "a configuration failure rather than unavailability",
		},
		{
			name: "control rejected 401, nothing pending, FAILS anyway",
			api: func(t *testing.T) issueAPI {
				return (&issueStub{status: map[int]int{controlIssue: http.StatusUnauthorized}}).api()
			},
			want:   actionFail,
			wantIn: "HTTP 401",
		},
		{
			name: "control rejected 401, pending present, FAILS",
			api: func(t *testing.T) issueAPI {
				return (&issueStub{status: map[int]int{controlIssue: http.StatusUnauthorized}}).api()
			},
			pending: pendingLedger(99),
			want:    actionFail,
			wantIn:  "HTTP 401",
		},
		{
			name: "control 404 (wrong repository), pending present, FAILS",
			api: func(t *testing.T) issueAPI {
				return (&issueStub{status: map[int]int{controlIssue: http.StatusNotFound}}).api()
			},
			pending: pendingLedger(99),
			want:    actionFail,
			wantIn:  "HTTP 404",
		},
		{
			name: "control returns malformed JSON, pending present, FAILS",
			api: func(t *testing.T) issueAPI {
				return (&issueStub{bodies: map[int]string{controlIssue: `{"state":`}}).api()
			},
			pending: pendingLedger(99),
			want:    actionFail,
			wantIn:  "not the expected JSON",
		},
		{
			name: "control response carries no state field, pending present, FAILS",
			api: func(t *testing.T) issueAPI {
				return (&issueStub{bodies: map[int]string{controlIssue: `{"title":"x"}`}}).api()
			},
			pending: pendingLedger(99),
			want:    actionFail,
			wantIn:  "carried no state field",
		},
		{
			// Measured on this Gitea: go-blockstore, go-luks2, go-quicbaas and
			// go-qrdb all have a closed #17 too, so "closed" alone identifies
			// nothing.
			name: "control closed but in the WRONG repository, pending present, FAILS",
			api: func(*testing.T) issueAPI {
				return (&issueStub{bodies: map[int]string{
					controlIssue: controlBody("jeremyhahn/go-blockstore"),
					99:           issueBody("open", "jeremyhahn/go-blockstore"),
				}}).api()
			},
			pending: pendingLedger(99),
			want:    actionFail,
			wantIn:  "it belongs to \"jeremyhahn/go-blockstore\"",
		},
		{
			name: "control closed but in the WRONG repository, nothing pending, still FAILS",
			api: func(*testing.T) issueAPI {
				return (&issueStub{bodies: map[int]string{
					controlIssue: controlBody("jeremyhahn/go-blockstore"),
				}}).api()
			},
			want:   actionFail,
			wantIn: "Issue numbers are not unique",
		},
		{
			name: "control response names no repository at all, pending present, FAILS",
			api: func(*testing.T) issueAPI {
				return (&issueStub{bodies: map[int]string{
					controlIssue: `{"state":"closed"}`,
				}}).api()
			},
			pending: pendingLedger(99),
			want:    actionFail,
			wantIn:  "instrument check failed",
		},
		{
			name: "instrument lies (control reports open), nothing pending, FAILS",
			api: func(t *testing.T) issueAPI {
				return (&issueStub{bodies: map[int]string{controlIssue: issueBody("open", wantRepository)}}).api()
			},
			want:   actionFail,
			wantIn: "instrument check failed",
		},
		{
			name: "instrument lies, pending present, FAILS",
			api: func(t *testing.T) issueAPI {
				return (&issueStub{bodies: map[int]string{controlIssue: issueBody("open", wantRepository)}}).api()
			},
			pending: pendingLedger(99),
			want:    actionFail,
			wantIn:  "instrument check failed",
		},
		{
			name:   "transport failure, nothing pending, skips",
			api:    unreachable,
			want:   actionSkip,
			wantIn: "is not reachable",
		},
		{
			name:    "transport failure, pending present, still skips",
			api:     unreachable,
			pending: pendingLedger(99),
			want:    actionSkip,
			wantIn:  "is not reachable",
		},
		{
			name: "control closed, nothing pending, verified and says it is vacuous",
			api: func(t *testing.T) issueAPI {
				return (&issueStub{bodies: closedControl()}).api()
			},
			want:        actionVerified,
			wantIn:      "vacuous BY CONSTRUCTION",
			wantChecked: 0,
		},
		{
			name: "control closed, pending issue is OPEN, verified",
			api: func(t *testing.T) issueAPI {
				b := closedControl()
				b[99] = issueBody("open", wantRepository)
				return (&issueStub{bodies: b}).api()
			},
			pending:     pendingLedger(99),
			want:        actionVerified,
			wantIn:      "instrument check passed",
			wantChecked: 1,
		},
		{
			// The control proves the endpoint answers for this repository. It
			// does not prove it does so for every number, which is the
			// asymmetry review on PR #66 found in the pending loop.
			name: "control right, pending issue answered from the WRONG repository, FAILS",
			api: func(*testing.T) issueAPI {
				b := closedControl()
				b[99] = issueBody("open", "jeremyhahn/go-blockstore")
				return (&issueStub{bodies: b}).api()
			},
			pending:     pendingLedger(99),
			want:        actionFail,
			wantIn:      "the answer came from \"jeremyhahn/go-blockstore\"",
			wantChecked: 0,
		},
		{
			name: "control right, pending answer names no repository, FAILS",
			api: func(*testing.T) issueAPI {
				b := closedControl()
				b[99] = `{"state":"open"}`
				return (&issueStub{bodies: b}).api()
			},
			pending:     pendingLedger(99),
			want:        actionFail,
			wantIn:      "not unique across a Gitea instance",
			wantChecked: 0,
		},
		{
			// A wrong-repository answer must not merely be reported, it must
			// not count as resolved: Checked is what says how much was
			// actually verified.
			name: "one pending from this repository and one from another, only the good one is Checked",
			api: func(*testing.T) issueAPI {
				b := closedControl()
				b[98] = issueBody("open", wantRepository)
				b[99] = issueBody("open", "jeremyhahn/go-qrdb")
				return (&issueStub{bodies: b}).api()
			},
			pending:     append(pendingLedger(98), pendingLedger(99)...),
			want:        actionFail,
			wantIn:      "jeremyhahn/go-qrdb",
			wantChecked: 1,
		},
		{
			name: "control closed, pending issue is CLOSED, FAILS",
			api: func(t *testing.T) issueAPI {
				b := closedControl()
				b[99] = issueBody("closed", wantRepository)
				return (&issueStub{bodies: b}).api()
			},
			pending:     pendingLedger(99),
			want:        actionFail,
			wantIn:      "but the issue is closed",
			wantChecked: 1,
		},
		{
			name: "control closed, pending lookup 500, FAILS as unresolved",
			api: func(t *testing.T) issueAPI {
				return (&issueStub{
					bodies: closedControl(),
					status: map[int]int{99: http.StatusInternalServerError},
				}).api()
			},
			pending: pendingLedger(99),
			want:    actionFail,
			wantIn:  "cannot resolve its state",
		},
		{
			name: "one pending open and one pending closed, FAILS naming only the closed one",
			api: func(t *testing.T) issueAPI {
				b := closedControl()
				b[98] = issueBody("open", wantRepository)
				b[99] = issueBody("closed", wantRepository)
				return (&issueStub{bodies: b}).api()
			},
			pending:     append(pendingLedger(98), pendingLedger(99)...),
			want:        actionFail,
			wantIn:      "issue #99",
			wantChecked: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := evaluateIssueState(t.Context(), tc.api(t), tc.pending)
			if res.Action != tc.want {
				t.Errorf("action = %v, want %v\n  reason: %s\n  problems: %v",
					res.Action, tc.want, res.Reason, res.Problems)
			}
			// The action alone is a weak oracle: several rows produce the same
			// action for different reasons, and a policy that failed for the
			// wrong reason would still be broken.
			haystack := res.Reason + "\n" + strings.Join(res.Problems, "\n")
			if !strings.Contains(haystack, tc.wantIn) {
				t.Errorf("explanation does not mention %q\n  reason: %s\n  problems: %v",
					tc.wantIn, res.Reason, res.Problems)
			}
			if res.Checked != tc.wantChecked {
				t.Errorf("Checked = %d, want %d", res.Checked, tc.wantChecked)
			}
			if tc.want == actionFail && res.Reason == "" && len(res.Problems) == 0 {
				t.Error("actionFail with nothing to print: a failure nobody can " +
					"read is not much better than no failure")
			}
		})
	}
}

// TestIssueStatePolicySendsTheToken pins the thing an httptest table would
// otherwise let rot: that the Authorization header is actually built and sent.
// Every row above would pass identically against a stub that ignores auth, so
// without this the token plumbing is asserted by nobody.
func TestIssueStatePolicySendsTheToken(t *testing.T) {
	stub := &issueStub{bodies: closedControl()}
	api := stub.api()
	api.token = "s3cr3t-value"

	if res := evaluateIssueState(t.Context(), api, nil); res.Action != actionVerified {
		t.Fatalf("action = %v, want verified: %s", res.Action, res.Reason)
	}
	if got, want := stub.gotAuth, "token s3cr3t-value"; got != want {
		t.Errorf("Authorization header = %q, want %q", got, want)
	}
}

// TestMisconfiguredIsTheOnlyVerdict guards the property the refactor was asked
// to preserve: a misconfiguration becomes a verdict in exactly one function. If
// a second copy of the rule appears, this stops being the whole truth and the
// copies drift silently.
func TestMisconfiguredIsTheOnlyVerdict(t *testing.T) {
	if got := misconfigured("because").Action; got != actionFail {
		t.Errorf("misconfigured: action = %v, want fail", got)
	}
	// Every misconfiguration path in evaluateIssueState routes through it,
	// which is what makes the line above cover them all. Each is checked with
	// and without a classPending entry, because the pending count used to
	// change the verdict and must no longer.
	for _, tc := range []struct {
		name string
		api  func(t *testing.T) issueAPI
	}{
		{"empty token", func(t *testing.T) issueAPI {
			api := (&issueStub{bodies: closedControl()}).api()
			api.token = ""
			return api
		}},
		{"unparseable base URL", func(*testing.T) issueAPI {
			return issueAPI{base: "gitea.local/api", token: "t", client: &http.Client{}}
		}},
		{"control refused", func(*testing.T) issueAPI {
			return (&issueStub{status: map[int]int{controlIssue: http.StatusUnauthorized}}).api()
		}},
		{"control unparseable", func(*testing.T) issueAPI {
			return (&issueStub{bodies: map[int]string{controlIssue: `{`}}).api()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := tc.api(t)
			if got := evaluateIssueState(t.Context(), api, nil).Action; got != actionFail {
				t.Errorf("nothing pending: action = %v, want fail", got)
			}
			if got := evaluateIssueState(t.Context(), api, pendingLedger(99)).Action; got != actionFail {
				t.Errorf("pending present: action = %v, want fail", got)
			}
		})
	}
}
