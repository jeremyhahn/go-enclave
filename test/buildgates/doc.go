// Package buildgates holds checks that assert properties of the REPOSITORY
// rather than of the library — things that are true of the files on disk and
// that no amount of exercising MemoryEnclave would ever notice.
//
// # Why this is a separate Go module
//
// go-enclave's dependency invariant is flat and deliberate: golang.org/x/sys,
// nothing else, because this library sits underneath other
// libraries, so anything added here lands in the build graph of everything
// that imports it. The action-pin gate needs a real YAML parser
// — see action_pins_test.go for why a regex will not do — and that parser has
// no business anywhere near the root module's requirements, not even as a
// test-only dependency that a reader of go.mod has to be told to discount.
//
// So this directory carries its OWN go.mod. The root module is untouched and
// still requires exactly one thing. The cost is that `go test ./...` at the
// root does not reach these tests. `make check-action-pins` runs the pin gate,
// `make check-releasability` the public-releasability gate
// (releasability_test.go), `make check-changelog-assembly` the fragment
// assembly (changelog_assemble_test.go) and `make check-scripts` the release
// and tooling scripts (scripts_test.go); `make ci` depends on all four, and
// the Lint jobs in ci.yml and release.yml run them too.
//
// The releasability gate needs nothing beyond the standard library and could
// have lived at the root. It lives here because it is the same kind of check —
// a property of the tracked tree, not of the library — and because a root
// test would ship in the module zip and run inside every consumer's
// `go test all`, where there is no git index to read.
//
// The directory is `test/` for a second reason: gosec is configured with
// `-exclude-dir=test` (the Makefile's GOSEC_FLAGS), so non-shipping code
// placed here is not reported as shipping code. trivy does scan test/: these
// gates' dependencies run in CI jobs that hold a token, so a vulnerable one
// matters even though it never reaches a consumer.
package buildgates
