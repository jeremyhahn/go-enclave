# go-enclave — foundational locked-memory primitive.
# Pure library, single package: no binaries, no container image.

# Release tooling. agent-git.sh supplies the acting agent's identity and SSH
# signing for every git write; REPO_NAME is what it maps to agent-<repo>.
#
# REPO_NAME is the LITERAL repo name and must never be $(notdir $(CURDIR)):
# that derives the SIGNING IDENTITY from the checkout directory, so a worktree,
# a CI workspace or a clone named anything else signs and attributes the release
# as a different agent (reviewer-enclave-9 measured a directory named `mk`
# producing agent-mk). Template v2.2.
AGENT_GIT ?= /home/jhahn/sources/automatethethings/software/scripts/agent-git.sh
REPO_NAME ?= go-enclave

GOCMD    ?= go
GOTEST   := $(GOCMD) test
GOVET    := $(GOCMD) vet
GOMOD    := $(GOCMD) mod
PKG      := ./...
COVERAGE_PROFILE := coverage.out
GOLANGCI_VERSION := v2.12.2

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

## tidy: go mod tidy
.PHONY: tidy
tidy:
	$(GOMOD) tidy

## lint: golangci-lint (pinned; devops.md §9)
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

## security: full local security suite (devops.md §8; no container image to scan)
.PHONY: security
security: gosec govulncheck modverify trivy
	@echo "Security suite passed"

## test: unit tests with the race detector
.PHONY: test
# -race IS NOT OPTIONAL HERE. It is the sole detector for the
# publication-ordering defect class in the shutdown registry: measured 10/10
# against the restored defect with the detector on, 0/10 with it off. Dropping
# the flag to speed the suite up would retire that guarantee silently — every
# test would still pass.
test:
	$(GOTEST) -race -count=1 -timeout=300s $(PKG)

## coverage: coverage report + threshold (testing-guidelines.md)
.PHONY: coverage
coverage:
	$(GOTEST) -race -covermode=atomic -coverprofile=$(COVERAGE_PROFILE) $(PKG)
	$(GOCMD) tool cover -func=$(COVERAGE_PROFILE) | tail -1

## test-fips: build + unit tests under Go native FIPS 140-3 strict mode
# Mirrors the `test` scope exactly; only the FIPS env differs (security-review.md
# §6, nightly.yml). This package performs no cryptography, so it must pass.
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
ci: tidy fmt-check vet lint staticcheck security test build
	@echo "CI pipeline completed successfully"

## deps-latest: bump first-party deps to their latest Gitea tags (none today)
.PHONY: deps-latest
deps-latest:
	@GOWORK=off sh -c ' \
	SELF=$$(go list -m); \
	for m in $$(go list -m -f "{{if not .Indirect}}{{.Path}}{{end}}" all 2>/dev/null | grep "^github.com/jeremyhahn/" | grep -vx "$$SELF"); do \
	  V=$$(go list -m -versions "$$m" 2>/dev/null | tr " " "\n" | tail -1); \
	  if [ -n "$$V" ] && [ "$$V" != "$$m" ]; then go get "$$m@$$V" || exit 1; fi; \
	done; go mod tidy'

## release-alpha: cut a signed release — make release-alpha VERSION=vX.Y.Z-alpha
# Company template v2.2 (software/templates/make/release-alpha.mk), adopted per
# go-enclave #10. v1 auto-incremented PATCH only — it would have named the
# additive v0.2.0-alpha as v0.1.1-alpha — and created LIGHTWEIGHT UNSIGNED tags
# under the OWNER's local identity, pushed every local tag, and let `|| true`
# swallow a failed VERSION commit so a tag could disagree with its own VERSION
# file. Both releases cut from this repo so far were done by hand for exactly
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
