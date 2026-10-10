// Package buildgates holds checks on the repository itself (workflows,
// scripts, the tracked tree) rather than on the library.
//
// It is a separate Go module because the root module requires only
// golang.org/x/sys, and anything it requires lands in every importer's build
// graph. The action-pin gate needs a real YAML parser, which must not appear in
// the root go.mod even as a test dependency. A separate module also keeps these
// tests out of the published module zip, so they never run inside a consumer's
// `go test all`, where there is no git index to read.
//
// `go test ./...` at the root does not reach this module. The make targets
// that run it, all part of `make ci-fast`:
//
//   - check-releasability: TestReleasability* (releasability_test.go)
//   - check-changelog-assembly: TestChangelogAssemble* (changelog_assemble_test.go)
//   - check-scripts: TestScripts* (scripts_test.go)
//   - check-buildgates: every other test (action_pins_test.go
//     and the rest); check-action-pins is its deprecated alias
//
// gosec's ./... never reaches this module, and trivy still scans it: these
// dependencies run in CI jobs that hold a token.
package buildgates
