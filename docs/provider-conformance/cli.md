# Provider conformance — CLI

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-01
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

No CLI surface: the suite is a Go function, `providertest.TestProvider`, that a provider author calls from their own `go test` ([api.md](api.md), [user.md](user.md)).
