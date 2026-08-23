# go-enclave — foundational locked-memory primitive.
# Pure library, single package: no binaries, no container image.

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
.PHONY: trivy
trivy:
	@trivy fs --scanners vuln,secret --severity CRITICAL,HIGH --exit-code 1 .

## security: full local security suite (devops.md §8; no container image to scan)
.PHONY: security
security: gosec govulncheck modverify trivy
	@echo "Security suite passed"

## test: unit tests with the race detector
.PHONY: test
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

## release-alpha: bump VERSION, tag, push to dev
.PHONY: release-alpha
release-alpha:
	@V=$$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || echo v0.0.0-alpha); \
	NEXT=$$(echo $$V | awk -F'[.-]' '{printf "v%s.%s.%d-alpha", substr($$1,2), $$2, $$3+1}'); \
	echo $$NEXT > VERSION && git add VERSION && git commit -q -m "chore(release): $$NEXT" || true; \
	git tag $$NEXT; \
	git push dev HEAD --tags && echo "Tagged $$NEXT"

## clean: remove build/test artifacts
.PHONY: clean
clean:
	@rm -f $(COVERAGE_PROFILE) gosec.sarif
