# go-enclave — foundational locked-memory primitive.
# Pure library, single package: no binaries, no container image.

# Release tooling. MAINTAINER-ONLY: nothing in the build or test targets needs
# any of this, and a contributor never invokes it.
#
# AGENT_GIT points at a wrapper that supplies the committing identity and SSH
# signing for release writes. It has NO DEFAULT ON PURPOSE — a hardcoded path
# would publish one machine's directory layout to everyone who reads this file,
# and the release target fails closed with an explanatory message rather than
# silently doing the wrong thing. Set it in the environment, or in a gitignored
# local.mk.
#
# REPO_NAME must be the LITERAL repo name and never $(notdir $(CURDIR)): that
# derives the SIGNING IDENTITY from the checkout directory, so a worktree, a CI
# workspace or a clone named anything else signs and attributes the release
# under the wrong name (measured: a directory named `mk` signed as `mk`).
-include local.mk
AGENT_GIT ?=
REPO_NAME ?= go-enclave

GOCMD    ?= go
GOTEST   := $(GOCMD) test
GOVET    := $(GOCMD) vet
GOMOD    := $(GOCMD) mod
PKG      := ./...
COVERAGE_PROFILE := coverage.out
# v2.13.2 is the floor for linting Go 1.27: v2.12.2's vendored analysis tools
# cannot parse the 1.27 stdlib and the whole metalinter dies ("unexpected
# expr: *ast.KeyValueExpr" in internal/poll). CI pins the same version baked
# into the runner image; raise the two together (ci.yml explains why the
# workflow refuses to network-install over the baked copy).
GOLANGCI_VERSION := v2.13.2

.PHONY: all
all: ci

.PHONY: help
## help: List targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'

## fmt: Format the tree (gofmt)
.PHONY: fmt
fmt:
	@gofmt -w .

## fmt-check: Fail if anything is unformatted
.PHONY: fmt-check
fmt-check:
	@UNFORMATTED=$$(gofmt -l .); \
	if [ -n "$$UNFORMATTED" ]; then echo "Not formatted:"; echo "$$UNFORMATTED"; exit 1; fi

## vet: go vet
.PHONY: vet
vet:
	$(GOVET) $(PKG)

## check-action-pins: every `uses:` in a workflow names a 40-hex commit
# Its own module under test/ (see test/buildgates/doc.go): the gate needs a
# YAML parser and the root module's two-dependency invariant is not negotiable
# for a test helper. That is why this cannot be a plain `go test ./...` target.
.PHONY: check-action-pins
check-action-pins:
	@cd test/buildgates && $(GOVET) $(PKG) && $(GOTEST) -count=1 $(PKG)

## tidy: go mod tidy
.PHONY: tidy
tidy:
	$(GOMOD) tidy

## lint: golangci-lint (pinned)
.PHONY: lint
lint:
	@go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)
	@$$(go env GOPATH)/bin/golangci-lint run --timeout=5m $(PKG)

## staticcheck: honnef.co staticcheck
.PHONY: staticcheck
staticcheck:
	@go install honnef.co/go/tools/cmd/staticcheck@latest
	@$$(go env GOPATH)/bin/staticcheck $(PKG)

## gosec: security static analysis
.PHONY: gosec
gosec:
	@go install github.com/securego/gosec/v2/cmd/gosec@latest
	@$$(go env GOPATH)/bin/gosec -quiet -exclude-dir=test -severity=medium -confidence=medium $(PKG)

## govulncheck: known-vuln scan (also the toolchain-currency forcing function)
.PHONY: govulncheck
govulncheck:
	@go install golang.org/x/vuln/cmd/govulncheck@latest
	@$$(go env GOPATH)/bin/govulncheck $(PKG)

## modverify: verify module integrity
.PHONY: modverify
modverify:
	$(GOMOD) verify

## trivy: filesystem vulnerability + secret scan
# --ignorefile matches the nightly job, so a suppression recorded in
# .trivyignore applies in both places. Without it the two scans disagree, which
# is how a red nightly hid behind a green `make security`.
.PHONY: trivy
trivy:
	@trivy fs --scanners vuln,secret --severity CRITICAL,HIGH --exit-code 1 --ignorefile .trivyignore .

## security: full local security suite (no container image to scan)
.PHONY: security
security: gosec govulncheck modverify trivy
	@echo "Security suite passed"

# The flags CI runs the suite with, in one place so a local run and the pipeline
# cannot drift apart — a check that passes locally and fails in CI (or worse,
# the reverse) is its own defect class.
#
# -race IS NOT OPTIONAL. It is the sole detector for the publication-ordering
# defect class in the shutdown registry: measured 10/10 against the restored
# defect with the detector on, 0/10 with it off.
#
# -cpu=1,2,8 IS NOT OPTIONAL EITHER (#61). The retune-versus-admission race in
# `reserve` has no test seam and cannot be given one without putting a branch on
# the lock-free admission path, so it is caught by contention — which makes the
# CORE COUNT part of the oracle. Measured on an 8-core host against `reserve`
# regressed to read-then-subtract, 10 whole-package runs per setting:
#     -cpu=1  ->  0/10 killed the mutant   (single core CANNOT see it)
#     -cpu=2  ->  6/10
#     -cpu=8  -> 10/10
# Trimming the list to one value retires that; the run costs ~3x, which for this
# package is seconds.
TESTFLAGS ?= -race -count=1 -cpu=1,2,8

## test: unit tests with the race detector, across the CPU matrix
.PHONY: test
test:
	$(GOTEST) $(TESTFLAGS) -timeout=900s $(PKG)

## coverage: coverage report + threshold
.PHONY: coverage
# Same shape as the CI step, matrix included: coverage is measured on the run
# that actually gates, not on a cheaper one that exercises less.
coverage:
	$(GOTEST) $(TESTFLAGS) -covermode=atomic -timeout=900s -coverprofile=$(COVERAGE_PROFILE) $(PKG)
	$(GOCMD) tool cover -func=$(COVERAGE_PROFILE) | tail -1

## test-fips: build + unit tests under Go native FIPS 140-3 strict mode
# Mirrors the `test` scope exactly; only the FIPS env differs (security-review.md
# §6, nightly.yml). The sealing surface performs real cryptography chosen to
# pass this mode (NewGCMWithRandomNonce et al.), so this gate is load-bearing:
# strict mode is what caught the NewGCM arbitrary-IV refusal in the first place.
.PHONY: test-fips
test-fips:
	GOFIPS140=latest GODEBUG=fips140=only $(GOCMD) build $(PKG)
	GOFIPS140=latest GODEBUG=fips140=only $(GOTEST) -count=1 -timeout=300s $(PKG)

## build: compile all packages
.PHONY: build
build:
	$(GOCMD) build $(PKG)

## ci: the full local gate
.PHONY: ci
ci: tidy fmt-check vet check-action-pins lint staticcheck security test build
	@echo "CI pipeline completed successfully"

## deps-latest: bump internal dependencies to their latest tags (none today)
.PHONY: deps-latest
deps-latest:
	@GOWORK=off sh -c ' \
	SELF=$$(go list -m); \
	for m in $$(go list -m -f "{{if not .Indirect}}{{.Path}}{{end}}" all 2>/dev/null | grep "^github.com/jeremyhahn/" | grep -vx "$$SELF"); do \
	  V=$$(go list -m -versions "$$m" 2>/dev/null | tr " " "\n" | tail -1); \
	  if [ -n "$$V" ] && [ "$$V" != "$$m" ]; then go get "$$m@$$V" || exit 1; fi; \
	done; go mod tidy'

## release-alpha: cut a signed release — make release-alpha VERSION=vX.Y.Z-alpha
# The version is stated EXPLICITLY rather than derived. An earlier recipe
# auto-incremented the PATCH component, which would have named an additive
# v0.2.0-alpha release as v0.1.1-alpha; it also created LIGHTWEIGHT UNSIGNED
# tags, pushed every local tag rather than the named one, and let `|| true`
# swallow a failed VERSION commit so a tag could disagree with its own VERSION
# file. Releases cut from this repo so far were done by hand for exactly
# those reasons.
#
# One deviation from the template as published, and it is a fix not a fork: v2.2
# writes the branch-guard message with BACKTICKS inside a double-quoted string,
# which the shell reads as command substitution — measured, it prints
# "/bin/sh: 1: push: not found" and drops the phrase from the message, sending a
# reader chasing a missing command at the exact moment a release just failed.
# Single-quoted here. Reported upstream so the template can take the same change
# before the other fifteen repos adopt it.
.PHONY: release-alpha
release-alpha:
	@test -n '$(AGENT_GIT)' || { echo 'ERROR: AGENT_GIT is unset - point it at your commit-signing/release wrapper (maintainer tooling; not needed to build or test)'; exit 1; }
	@test -n "$(VERSION)" || { echo "ERROR: state the version explicitly: make release-alpha VERSION=vX.Y.Z-alpha (release-versioning.md decides patch/minor/major — the recipe refuses to guess)"; exit 1; }
	@test "$$(git rev-parse --abbrev-ref HEAD)" = main || { echo "ERROR: releases are cut from main; you are on $$(git rev-parse --abbrev-ref HEAD). 'push dev HEAD' would publish this branch to dev."; exit 1; }
	@echo "$(VERSION)" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+-alpha$$' || { echo "ERROR: '$(VERSION)' is not vX.Y.Z-alpha"; exit 1; }
	@test -n "$(REPO_NAME)" || { echo "ERROR: REPO_NAME is empty — set it to the literal repo name in the Makefile, never \$$(notdir \$$(CURDIR))"; exit 1; }
	@! git rev-parse -q --verify "refs/tags/$(VERSION)" >/dev/null || { echo "ERROR: tag $(VERSION) already exists locally"; exit 1; }
	@! git ls-remote --exit-code --tags dev "refs/tags/$(VERSION)" >/dev/null 2>&1 || { echo "ERROR: tag $(VERSION) already exists on dev (a local check alone would miss this and fail the push AFTER committing VERSION)"; exit 1; }
	@test -z "$$(git status --porcelain)" || { echo "ERROR: working tree not clean"; exit 1; }
	@grep -Eq '^#+ +\[?'"$(VERSION)"'\]?' CHANGELOG.md || { echo "ERROR: CHANGELOG.md has no release SECTION heading for $(VERSION) (an unanchored prose mention does not count)"; exit 1; }
	@echo "$(VERSION)" > VERSION
	$(AGENT_GIT) $(REPO_NAME) add VERSION
	$(AGENT_GIT) $(REPO_NAME) commit -m "chore(release): $(VERSION)"
	$(AGENT_GIT) $(REPO_NAME) tag -a "$(VERSION)" -m "$(VERSION)"
	$(AGENT_GIT) $(REPO_NAME) push dev HEAD "refs/tags/$(VERSION)"
	@echo "Released $(VERSION) (signed, annotated, single tag pushed)"

## clean: remove build/test artifacts
.PHONY: clean
clean:
	@rm -f $(COVERAGE_PROFILE) gosec.sarif
