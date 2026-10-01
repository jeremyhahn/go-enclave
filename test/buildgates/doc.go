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
// root does not reach these tests. `make check-action-pins` runs the pin gate
// and `make check-releasability` runs the public-releasability gate
// (releasability_test.go); `make ci` depends on both targets, and the Lint job
// in ci.yml runs both too.
//
// The releasability gate needs nothing beyond the standard library and could
// have lived at the root. It lives here because it is the same kind of check —
// a property of the tracked tree, not of the library — and because a root
// test would ship in the module zip and run inside every consumer's
// `go test all`, where there is no git index to read.
//
// The directory is `test/` for a second reason: gosec and trivy are already
// configured repo-wide with `-exclude-dir=test` and `skip-dirs: test`, so
// non-shipping code placed here is scanned as non-shipping code without any
// new configuration.
package buildgates
