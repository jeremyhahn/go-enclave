### Changed

- **Package documentation states contracts, not history** (#112). Godoc comments now give each identifier's behaviour, errors, concurrency and platform caveats; design rationale lives in `docs/*/engineering.md`, and links to unexported identifiers no longer render broken on pkg.go.dev.
- **The module no longer ships a repository-walking test** (#112). The root package's `doc_test.go`, which read the source tree and queried the issue tracker, is gone, so `go test all` in a consuming module no longer runs it. An offline gate in `test/buildgates` keeps issue citations out of shipped source.
