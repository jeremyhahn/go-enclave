# go-enclave: locked-memory library. No binaries, no image, no protobuf, so no
# docker-build/docker-run/proto targets.
#
# The Makefile is the contract: CI calls these targets and carries no commands
# or flags of its own, so a red CI reproduces with the same `make` line locally.

# Release tooling (maintainer-only). AGENT_GIT is the commit/signing wrapper; it
# has no default on purpose and release-alpha fails closed without it. Set it in
# the environment or a gitignored local.mk.
#
# REPO_NAME must be the LITERAL repo name, never $(notdir $(CURDIR)): it selects
# the signing identity, which must not depend on the checkout directory name.
#
# HELP_MAKEFILE is captured before any include, so `make help` reads this file.
export HELP_MAKEFILE := $(firstword $(MAKEFILE_LIST))

-include local.mk
AGENT_GIT ?=
REPO_NAME ?= go-enclave

# Dependencies resolve from published tags; a stray go.work is ignored.
export GOWORK := off

GOCMD    ?= go
PKG      := ./...
COVERAGE_PROFILE := coverage.out
COVERAGE_HTML    := coverage/coverage.html

# raw_bind VARS: re-bind each variable to its raw, unexpanded text and export
# it. Recipes read it as "$$VAR", so tag/CLI/path values are never parsed as
# shell or make source. See EXTERNAL_VARS.
raw_bind = $(foreach v,$(1),$(eval override $(v) := $$(value $(v)))$(eval export $(v)))

# sq TEXT: TEXT as one single-quoted shell word, for $(shell ...), which does
# not see exported variables in GNU Make 4.3.
sq = '$(subst ','\'',$(1))'

# Paths may hold spaces or quotes: bind raw, read as "$$VAR".
$(call raw_bind,GOCMD AGENT_GIT REPO_NAME COVERAGE_PROFILE COVERAGE_HTML)

# ---------------------------------------------------------------------------
# PINNED TOOLS
#
# Pins match the CI runner image, which runs with TOOL_INSTALL=0 and rejects
# any other version: raise a pin in the image first, then here. Never @latest.
#
# Raise with the runner image: `go list -m github.com/golangci/golangci-lint/v2@latest`.
# v2.13.2 is the floor for linting Go 1.27.
GOLANGCI_VERSION    := v2.13.2
# Raise with the runner image: `go list -m honnef.co/go/tools@latest` (v0.8.1 is release 2026.2.1).
STATICCHECK_VERSION := v0.8.1
# Raise with the runner image: `go list -m github.com/securego/gosec/v2@latest`.
GOSEC_VERSION       := v2.29.0
# Raise with the runner image: `go list -m golang.org/x/vuln@latest`.
GOVULNCHECK_VERSION := v1.7.0
# Raise with the runner image: `go list -m github.com/rhysd/actionlint@latest`.
ACTIONLINT_VERSION  := v1.7.7
#
# trivy and shellcheck are release archives pinned by four SHA-256s each: the
# archive per Linux arch and the binary inside it (see scripts/tool.sh).
# Raise a version and all four of its hashes together, or not at all.
#
# trivy is not in the runner image. Held at v0.74.0 so a scanner release ages
# before it runs here; re-evaluate v0.75.0 from 2026-10-08.
TRIVY_VERSION                  := v0.74.0
TRIVY_SHA256_LINUX_AMD64       := 2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a
TRIVY_SHA256_LINUX_ARM64       := b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5
TRIVY_BIN_SHA256_LINUX_AMD64   := d89bcc6510a267f11b773398cbf1be5520ce39f9e8b6633178c4487f05b7d791
TRIVY_BIN_SHA256_LINUX_ARM64   := fed2c9ca7d27191ada34524b5eaf5216a845c6d6f3246143c3b475552ffe5358
# shellcheck (actionlint and lint-scripts): the runner image's Ubuntu 24.04
# package version; raise with the image's base. Upstream publishes no
# checksums; these match the koalaman/shellcheck:v0.9.0 image's binaries.
SHELLCHECK_VERSION             := v0.9.0
SHELLCHECK_SHA256_LINUX_AMD64  := 700324c6dd0ebea0117591c6cc9d7350d9c7c5c287acbad7630fa17b1d4d9e2f
SHELLCHECK_SHA256_LINUX_ARM64  := 179c579ef3481317d130adebede74a34dbbc2df961a70916dd4039ebf0735fae
SHELLCHECK_BIN_SHA256_LINUX_AMD64 := 7087178d54de6652b404c306233264463cb9e7a9afeb259bb663cc4dbfd64149
SHELLCHECK_BIN_SHA256_LINUX_ARM64 := ef4c0f06039f2034dfba012251ddfeb1edba88e049fc5edfbc289fef179daaa0

# TOOL_INSTALL=1 installs missing pins into TOOLS_DIR (inside the repo, keyed by
# version and toolchain). TOOL_INSTALL=0 (CI) installs nothing: a missing or
# mismatched tool fails closed, with no fallback install.
TOOL_INSTALL ?= 1
TOOLS_DIR    := $(CURDIR)/bin/tools
# TOOLS_DIR derives from the checkout path, so it is raw-bound.
$(call raw_bind,TOOLS_DIR)

# This module's toolchain, passed to every tool install so `go install` builds
# the tools with it rather than with the tool's own go.mod floor.
TOOLCHAIN := $(shell $(call sq,$(GOCMD)) env GOVERSION)

# `bin=$$($(TOOL) <name> <version>)` prints the pinned binary's path or fails
# closed. Its inputs are exported, never spliced into recipe source.
export TOOLCHAIN
export GO := $(GOCMD)
export TRIVY_SHA256_LINUX_AMD64 TRIVY_SHA256_LINUX_ARM64 TRIVY_BIN_SHA256_LINUX_AMD64 TRIVY_BIN_SHA256_LINUX_ARM64
export SHELLCHECK_SHA256_LINUX_AMD64 SHELLCHECK_SHA256_LINUX_ARM64 SHELLCHECK_BIN_SHA256_LINUX_AMD64 SHELLCHECK_BIN_SHA256_LINUX_ARM64
TOOL = sh scripts/tool.sh

# gosec flags live only here; CI runs `make gosec`.
#   -concurrency=4: gosec sizes workers from host cores, ignoring cgroup limits.
#   -exclude-dir=test: test/ is never shipped; shipped packages are always scanned.
#   SARIF for code scanning, plus text on stdout for Gitea logs.
#   No -exclude rules: fix the finding or annotate `#nosec G### -- why`.
GOSEC_FLAGS := -concurrency=4 -severity=medium -confidence=medium -exclude-dir=test \
	-fmt=sarif -out=gosec.sarif -stdout -verbose=text

# trivy fs flags for every target and workflow. bin/ is the third-party tool
# cache; the pin decides the version, so the version check is skipped.
TRIVY_FS_FLAGS := --skip-dirs bin --ignorefile .trivyignore --skip-version-check

# Coverage floor. `:=` so the environment cannot lower it; only the command line can.
COVERAGE_THRESHOLD := 90

# VALUES FROM OUTSIDE ARE DATA, NEVER SHELL OR MAKE SOURCE.
#
# TAG/SHA/MAIN_REF come from a pushed tag (git allows v`id`), VERSION from a
# maintainer, the rest from a workflow or command line. $(TAG) in a recipe is
# pasted into shell source before any validator runs, and a command-line
# variable is recursively expanded on export, so $(shell ...) in it runs inside
# make. raw_bind stores each unexpanded and exports it; recipes read only
# "$$TAG" and the scripts validate the whole string. Never write $(TAG),
# $(SHA), $(MAIN_REF), $(VERSION), $(TOOL_INSTALL) or $(COVERAGE_THRESHOLD) in
# a recipe.
#
# Paths are raw-bound the same way. Only operator flag lists (TESTFLAGS,
# GOSEC_FLAGS, TRIVY_FS_FLAGS, INTEGRATION_TESTFLAGS, CROSS_TARGETS) and
# constants defined here are spliced into recipes.
EXTERNAL_VARS := TAG SHA MAIN_REF VERSION TOOL_INSTALL COVERAGE_THRESHOLD
$(call raw_bind,$(EXTERNAL_VARS))

# Every GOOS/GOARCH a consumer may build for; 32-bit targets catch uintptr
# comparisons that do not compile there.
CROSS_TARGETS := linux/amd64 linux/arm64 linux/386 linux/arm \
	darwin/amd64 darwin/arm64 freebsd/amd64 openbsd/amd64 netbsd/amd64 dragonfly/amd64 \
	illumos/amd64 solaris/amd64 aix/ppc64 windows/amd64 windows/386 \
	android/arm64

# Per-package targets (test-, coverage-, bench-<pkg>). The root package is enclave.
PACKAGES          := enclave providertest
PKGDIR_enclave      := .
PKGDIR_providertest := ./providertest

.PHONY: all
all: ci

.PHONY: help
## help: List targets
help:
	@test -f "$$HELP_MAKEFILE" || { echo "help: cannot locate this Makefile (make splits a -f path containing spaces); run make from the checkout"; exit 1; }
	@grep -E '^## ' "$$HELP_MAKEFILE" | sed 's/## //'

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
	"$$GOCMD" vet $(PKG)

## tidy: go mod tidy
.PHONY: tidy
tidy:
	"$$GOCMD" mod tidy

## tidy-check: fail if go.mod/go.sum (root or test/buildgates) are not tidy
# Reports the diff and changes nothing: a gate must not repair what it checks.
.PHONY: tidy-check
tidy-check:
	@"$$GOCMD" mod tidy -diff || { echo "go.mod/go.sum are not tidy: run 'make tidy'"; exit 1; }
	@cd test/buildgates && "$$GOCMD" mod tidy -diff || { echo "test/buildgates/go.mod is not tidy: run 'go mod tidy' there"; exit 1; }

## lint: gofmt, go vet, golangci-lint, actionlint, shellcheck (devops §4)
.PHONY: lint
lint: fmt-check vet lint-go lint-actions lint-scripts

## lint-go: golangci-lint (pinned) over .golangci.yml
# .golangci.yml must enable staticcheck, errcheck, unused, ineffassign,
# misspell and gocritic. --allow-serial-runners waits for golangci-lint's
# host-wide lock instead of failing. test/buildgates is a separate module, so
# lint-go, staticcheck and govulncheck also run there.
.PHONY: lint-go
lint-go:
	@bin=$$($(TOOL) golangci-lint $(GOLANGCI_VERSION)) && "$$bin" run --allow-serial-runners --timeout=5m $(PKG) && \
	cd test/buildgates && "$$bin" run --allow-serial-runners --timeout=5m $(PKG)

## lint-actions: actionlint (pinned) over .github/workflows, with the pinned shellcheck on every run: block
# The pinned shellcheck is passed explicitly: actionlint silently skips shell
# checks when it finds none on PATH.
.PHONY: lint-actions
lint-actions:
	@sc=$$($(TOOL) shellcheck $(SHELLCHECK_VERSION)) && \
	bin=$$($(TOOL) actionlint $(ACTIONLINT_VERSION)) && "$$bin" -shellcheck "$$sc"

## lint-scripts: shellcheck (pinned) over scripts/*.sh
# The scripts are POSIX sh, and release.yml runs them with a write token.
.PHONY: lint-scripts
lint-scripts:
	@sc=$$($(TOOL) shellcheck $(SHELLCHECK_VERSION)) && \
	echo "shellcheck $(SHELLCHECK_VERSION) --shell=sh scripts/*.sh build/docker/devcontainer/*.sh" && "$$sc" --shell=sh scripts/*.sh build/docker/devcontainer/*.sh

## staticcheck: honnef.co staticcheck (pinned)
.PHONY: staticcheck
staticcheck:
	@bin=$$($(TOOL) staticcheck $(STATICCHECK_VERSION)) && "$$bin" $(PKG) && \
	cd test/buildgates && "$$bin" $(PKG)

## gosec: security static analysis (pinned; writes gosec.sarif)
# Exit >128 means killed by a signal (e.g. OOM), not findings; say which.
.PHONY: gosec
gosec:
	@bin=$$($(TOOL) gosec $(GOSEC_VERSION)) || exit 1; \
	rc=0; "$$bin" $(GOSEC_FLAGS) $(PKG) || rc=$$?; \
	if [ $$rc -gt 128 ]; then \
	  echo "gosec was KILLED by signal $$((rc - 128)) - this is NOT a security finding. Memory pressure; re-run when the host is quieter."; \
	fi; exit $$rc

## govulncheck: known-vuln scan (pinned; also the toolchain-currency forcing function)
# Same signal-exit triage as gosec.
.PHONY: govulncheck
govulncheck:
	@bin=$$($(TOOL) govulncheck $(GOVULNCHECK_VERSION)) || exit 1; \
	rc=0; "$$bin" $(PKG) || rc=$$?; \
	if [ $$rc -eq 0 ]; then (cd test/buildgates && "$$bin" $(PKG)) || rc=$$?; fi; \
	if [ $$rc -gt 128 ]; then \
	  echo "govulncheck was KILLED by signal $$((rc - 128)) - this is NOT a vulnerability finding. Memory pressure, not a CVE; confirm with an uncapped run."; \
	fi; exit $$rc

## vuln: alias for govulncheck
.PHONY: vuln
vuln: govulncheck

## modverify: verify module integrity
.PHONY: modverify
modverify:
	"$$GOCMD" mod verify

## trivy: filesystem vulnerability + secret scan, CRITICAL/HIGH fail (pinned)
# TRIVY_FS_FLAGS carries --ignorefile, so suppressions apply to every scan.
.PHONY: trivy
trivy:
	@bin=$$($(TOOL) trivy $(TRIVY_VERSION)) && \
	"$$bin" fs --scanners vuln,secret --severity CRITICAL,HIGH --exit-code 1 --format table $(TRIVY_FS_FLAGS) .

## trivy-misconfig: misconfiguration scan, ADVISORY (reports, never fails on findings)
# Advisory until the misconfiguration baseline is clean.
.PHONY: trivy-misconfig
trivy-misconfig:
	@bin=$$($(TOOL) trivy $(TRIVY_VERSION)) && \
	"$$bin" fs --scanners misconfig --exit-code 0 --format table $(TRIVY_FS_FLAGS) .

## trivy-sarif: vulnerability + secret scan as SARIF (trivy-results.sarif), for code scanning
.PHONY: trivy-sarif
trivy-sarif:
	@bin=$$($(TOOL) trivy $(TRIVY_VERSION)) && \
	"$$bin" fs --scanners vuln,secret --exit-code 0 --format sarif --output trivy-results.sarif $(TRIVY_FS_FLAGS) .

## security: full local security suite — gosec, govulncheck, modverify, trivy
# No image to scan. CI runs the first three per push and trivy nightly; release.yml runs all four.
.PHONY: security
security: gosec govulncheck modverify trivy
	@echo "Security suite passed"

# CI's test flags, defined once so local and CI runs cannot drift; `:=` so an
# exported TESTFLAGS cannot drop them. Neither flag is optional:
#   -race is the only detector for publication-ordering bugs in the shutdown registry.
#   -cpu=1,2,8: the reserve retune-vs-admission race is caught only by
#   contention, so core count is part of the oracle (one core never sees it).
TESTFLAGS := -race -count=1 -cpu=1,2,8

## test: unit tests with the race detector, across the CPU matrix
.PHONY: test
test:
	"$$GOCMD" test $(TESTFLAGS) -timeout=900s $(PKG)

# Profile for coverage and coverage-report, measured with the full TESTFLAGS.
.PHONY: coverage-profile
coverage-profile:
	"$$GOCMD" test $(TESTFLAGS) -covermode=atomic -timeout=900s -coverprofile="$$COVERAGE_PROFILE" $(PKG)

## coverage: unit tests with coverage; FAILS below COVERAGE_THRESHOLD, in total AND per package
# The floor binds the total AND every package (a statement-weighted total can
# hide a small package below it). Exact comparison, no rounding.
.PHONY: coverage
coverage: coverage-threshold coverage-profile
	@TOTAL=$$("$$GOCMD" tool cover -func="$$COVERAGE_PROFILE" | awk '/^total:/ {sub("%","",$$3); print $$3}'); \
	test -n "$$TOTAL" || { echo "FAIL: no total in $$COVERAGE_PROFILE"; exit 1; }; \
	echo "Total coverage: $$TOTAL% (floor $$COVERAGE_THRESHOLD%)"; \
	awk -v t="$$TOTAL" -v f="$$COVERAGE_THRESHOLD" 'BEGIN { exit !(t+0 >= f+0) }' || { echo "FAIL: coverage $$TOTAL% is below the $$COVERAGE_THRESHOLD% floor"; exit 1; }
	@awk -v f="$$COVERAGE_THRESHOLD" ' \
	  NR > 1 && NF == 3 { file = $$1; sub(/:[^:]*$$/, "", file); pkg = file; sub(/\/[^\/]*$$/, "", pkg); \
	    if (!(pkg in stmts)) pkgs++; stmts[pkg] += $$2; if ($$3 > 0) hit[pkg] += $$2 } \
	  END { if (pkgs == 0) { print "FAIL: no package in " FILENAME; exit 1 } \
	    bad = 0; \
	    for (p in stmts) { pct = 100 * hit[p] / stmts[p]; \
	      printf "%s coverage: %.1f%% (floor %s%%)\n", p, pct, f | "sort"; \
	      if (100 * hit[p] < (f + 0) * stmts[p]) { below[p] = pct; bad = 1 } } \
	    close("sort"); \
	    for (p in below) printf "FAIL: %s coverage %.1f%% is below the %s%% floor\n", p, below[p], f; \
	    exit bad }' "$$COVERAGE_PROFILE"

# The floor is checked to be a number BEFORE the suite spends minutes running.
.PHONY: coverage-threshold
coverage-threshold:
	@case "$$COVERAGE_THRESHOLD" in \
	  ''|*[!0-9.]*|*.*.*|.*|*.) echo "ERROR: COVERAGE_THRESHOLD must be a number (got a value that is not)"; exit 1 ;; \
	esac

## coverage-report: HTML coverage report at coverage/coverage.html (no threshold)
# Separate from coverage so the report is produced even when the floor is missed.
.PHONY: coverage-report
coverage-report: coverage-profile
	@mkdir -p -- "$$(dirname -- "$$COVERAGE_HTML")"
	"$$GOCMD" tool cover -html="$$COVERAGE_PROFILE" -o "$$COVERAGE_HTML"
	@"$$GOCMD" tool cover -func="$$COVERAGE_PROFILE" | awk '/^total:/ {print "Total coverage: " $$3}'
	@echo "Wrote $$COVERAGE_HTML"

## test-fips: build + unit tests under Go native FIPS 140-3 strict mode
# Runs once, without -race or the CPU matrix: it hunts non-approved crypto.
# STRICT mode (fips140=only), never `on`, which still permits non-approved
# algorithms. A failure here is the finding: fix the call site.
.PHONY: test-fips
test-fips:
	GOFIPS140=latest GODEBUG=fips140=only "$$GOCMD" build $(PKG)
	GOFIPS140=latest GODEBUG=fips140=only "$$GOCMD" test -count=1 -timeout=900s $(PKG)

## test-runtimesecret: unit tests built with GOEXPERIMENT=runtimesecret (key-schedule erasure, #98)
# Checks per-platform erasure file selection, then runs the suite with
# GOEXPERIMENT=runtimesecret on the module's own toolchain (resolved with the
# experiment unset; an older go cannot parse it). The erasure proof runs
# without -race, whose allocator would blind its control.
ERASURE_PROOF := ^TestWithAEAD_ErasesTheKeyScheduleUnderRuntimeSecret$$
.PHONY: test-runtimesecret
test-runtimesecret:
	@gobin=$$(GOEXPERIMENT= "$$GOCMD" env GOROOT)/bin/go || exit 1; \
	for t in linux/amd64=secret_erase.go linux/arm64=secret_erase.go linux/386=secret_noerase.go \
	  android/amd64=secret_noerase.go android/arm64=secret_noerase.go darwin/arm64=secret_noerase.go; do \
	  target=$${t%=*}; want=$${t#*=}; \
	  files=$$(GOEXPERIMENT=runtimesecret GOOS=$${target%/*} GOARCH=$${target#*/} CGO_ENABLED=0 "$$gobin" list -f '{{join .GoFiles " "}}' .) || exit 1; \
	  case " $$files " in *" $$want "*) echo "erasure selection $$target: $$want";; \
	    *) echo "ERROR: GOEXPERIMENT=runtimesecret on $$target does not build $$want (KeyScheduleErasure would lie)"; exit 1;; esac; \
	done; \
	echo "GOEXPERIMENT=runtimesecret $$gobin test $(TESTFLAGS) -skip '$(ERASURE_PROOF)' -timeout=900s $(PKG)"; \
	GOEXPERIMENT=runtimesecret "$$gobin" test $(TESTFLAGS) -skip '$(ERASURE_PROOF)' -timeout=900s $(PKG) || exit 1; \
	echo "GOEXPERIMENT=runtimesecret $$gobin test -count=5 -cpu=1,2,8 -run '$(ERASURE_PROOF)' ."; \
	GOEXPERIMENT=runtimesecret "$$gobin" test -count=5 -cpu=1,2,8 -run '$(ERASURE_PROOF)' .

## bench: every benchmark, with allocation counts (no unit tests)
.PHONY: bench
bench:
	"$$GOCMD" test -run '^$$' -bench . -benchmem $(PKG)

## test-<pkg>, coverage-<pkg>, bench-<pkg>: one package (enclave, providertest)
.PHONY: $(addprefix test-,$(PACKAGES)) $(addprefix coverage-,$(PACKAGES)) $(addprefix bench-,$(PACKAGES))
$(addprefix test-,$(PACKAGES)): test-%:
	"$$GOCMD" test $(TESTFLAGS) -timeout=900s $(PKGDIR_$*)
$(addprefix coverage-,$(PACKAGES)): coverage-%:
	"$$GOCMD" test $(TESTFLAGS) -covermode=atomic -timeout=900s -coverprofile=coverage-$*.out $(PKGDIR_$*)
	@"$$GOCMD" tool cover -func=coverage-$*.out | awk '/^total:/ {print "$* coverage: " $$3}'
$(addprefix bench-,$(PACKAGES)): bench-%:
	"$$GOCMD" test -run '^$$' -bench . -benchmem $(PKGDIR_$*)

# INTEGRATION SUITE. Each package's suite (test/integration/<pkg>/) runs in the
# devcontainer, never on the host. The image bakes the source because on CI
# runners compose talks to the host daemon, where bind-mount paths do not exist.
# Each run uses a unique compose project, torn down on every exit. The package
# is named exactly (no /...) so a wrong build tag errors instead of passing
# vacuously. Every precondition fails rather than skips.
INTEGRATION_PACKAGES  := enclave providertest
DEVCONTAINER_COMPOSE  := build/docker/devcontainer/compose.yaml
DEVCONTAINER_SERVICE  := devcontainer
INTEGRATION_TESTFLAGS := -tags=integration -race -count=1 -v -timeout=1800s

# GO_ENCLAVE_IT_PROFILE_OUT: where to write the merged integration profile
# ("-" prints it). Caller-supplied, so raw-bound.
GO_ENCLAVE_IT_PROFILE_OUT ?=
$(call raw_bind,GO_ENCLAVE_IT_PROFILE_OUT)
# Integration coverage is gated per suite on the package it is FOR, against
# COVERAGE_THRESHOLD.
INTEGRATION_COVERPKG_enclave      := github.com/jeremyhahn/go-enclave
INTEGRATION_COVERPKG_providertest := github.com/jeremyhahn/go-enclave/providertest
# FIPS strict run: same suite with GOFIPS140=latest and fips140=only. The suite
# fails unless the runtime reports the promised GO_ENCLAVE_IT_FIPS_MODE.
INTEGRATION_FIPS_ENV  := -e GOFIPS140=latest -e GODEBUG=fips140=only -e GO_ENCLAVE_IT_FIPS_MODE=only
$(call raw_bind,DEVCONTAINER_COMPOSE DEVCONTAINER_SERVICE)

# run_integration PKG, EXTRA_RUN_FLAGS: the one recipe both variants share.
define run_integration
	@test -n "$(INTEGRATION_COVERPKG_$(1))" || { echo "ERROR: no INTEGRATION_COVERPKG_$(1): every integration suite names the package its coverage floor applies to"; exit 1; }
	@test -d test/integration/$(1) || { echo "ERROR: test/integration/$(1) does not exist. Refusing to report a suite that did not run as passed."; exit 1; }
	@ls test/integration/$(1)/*_test.go >/dev/null 2>&1 || { echo "ERROR: test/integration/$(1) holds no _test.go files; refusing to pass with nothing to run."; exit 1; }
	@test -f "$$DEVCONTAINER_COMPOSE" || { echo "ERROR: $$DEVCONTAINER_COMPOSE not found. Integration tests run in the project devcontainer, never on the host (integration-testing §4)."; exit 1; }
	@command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 || { echo "ERROR: 'docker compose' (Compose v2) is required to run the integration suite in the devcontainer."; exit 1; }
	@docker version --format '{{.Server.Version}}' >/dev/null 2>&1 || { echo "ERROR: the Docker daemon is not reachable (docker version cannot read the server). The integration suite runs in the devcontainer and cannot run without it."; exit 1; }
	@trivy=$$($(TOOL) trivy $(TRIVY_VERSION)) || exit 1; \
	project="go-enclave-it-$(1)-$$(date +%s)-$$$$-$$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"; \
	echo "compose project: $$project"; \
	cleanup() { \
	  rc=$$?; \
	  if ! docker compose -f "$$DEVCONTAINER_COMPOSE" -p "$$project" down --volumes --remove-orphans --rmi local >/dev/null 2>&1; then \
	    echo "ERROR: teardown of compose project $$project failed; remove it with: docker compose -f '$$DEVCONTAINER_COMPOSE' -p '$$project' down --volumes --remove-orphans --rmi local" >&2; \
	    [ "$$rc" -ne 0 ] || rc=1; \
	  fi; \
	  exit $$rc; \
	}; \
	trap cleanup EXIT; trap 'exit 130' INT; trap 'exit 143' TERM; \
	docker compose -f "$$DEVCONTAINER_COMPOSE" -p "$$project" build "$$DEVCONTAINER_SERVICE" || exit 1; \
	echo "trivy image $$project-$$DEVCONTAINER_SERVICE (CRITICAL,HIGH, fixable only — devops §8)"; \
	"$$trivy" image --scanners vuln --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 \
	  --ignorefile .trivyignore --skip-version-check --format table "$$project-$$DEVCONTAINER_SERVICE" || exit 1; \
	docker compose -f "$$DEVCONTAINER_COMPOSE" -p "$$project" run --rm \
	  -e GO_ENCLAVE_IT_TESTFLAGS="$(INTEGRATION_TESTFLAGS)" \
	  -e GO_ENCLAVE_IT_COVERAGE_FLOOR="$$COVERAGE_THRESHOLD" \
	  -e GO_ENCLAVE_IT_COVERPKG="$(INTEGRATION_COVERPKG_$(1))" \
	  -e GO_ENCLAVE_IT_PROFILE_OUT="$$GO_ENCLAVE_IT_PROFILE_OUT" \
	  $(2) "$$DEVCONTAINER_SERVICE" sh build/docker/devcontainer/run-integration-tests.sh $(1)
endef

## integration-test: every integration suite, in the devcontainer
.PHONY: integration-test
integration-test: $(addprefix integration-test-,$(INTEGRATION_PACKAGES))

## integration-test-<pkg>: one package's integration suite, in the devcontainer (enclave)
.PHONY: $(addprefix integration-test-,$(INTEGRATION_PACKAGES))
$(addprefix integration-test-,$(INTEGRATION_PACKAGES)): integration-test-%:
	$(call run_integration,$*,)

## integration-test-fips: every integration suite under FIPS 140-3 strict mode, in the devcontainer
.PHONY: integration-test-fips
integration-test-fips: $(addprefix integration-test-fips-,$(INTEGRATION_PACKAGES))

## integration-test-fips-<pkg>: one package's integration suite under FIPS 140-3 strict mode (enclave)
.PHONY: $(addprefix integration-test-fips-,$(INTEGRATION_PACKAGES))
$(addprefix integration-test-fips-,$(INTEGRATION_PACKAGES)): integration-test-fips-%:
	$(call run_integration,$*,$(INTEGRATION_FIPS_ENV))

## lint-integration: vet, golangci-lint and staticcheck over the integration suite, WITH its build tag
# `make lint` runs without the integration tag and never sees the suite. This
# first proves the tag selects the test files and nothing builds without it.
.PHONY: lint-integration
lint-integration:
	@for p in $(INTEGRATION_PACKAGES); do \
	  with=$$("$$GOCMD" list -tags=integration -f '{{len .TestGoFiles}}{{len .XTestGoFiles}}' ./test/integration/$$p) || exit 1; \
	  without=$$("$$GOCMD" list -e -f '{{len .TestGoFiles}}{{len .XTestGoFiles}}' ./test/integration/$$p 2>/dev/null); \
	  case "$$with" in 00|'') echo "ERROR: -tags=integration selects no test files in test/integration/$$p"; exit 1;; esac; \
	  case "$$without" in 00|'') ;; *) echo "ERROR: test/integration/$$p has test files that build WITHOUT the integration tag ($$without)"; exit 1;; esac; \
	done
	"$$GOCMD" vet -tags=integration ./test/integration/...
	@bin=$$($(TOOL) golangci-lint $(GOLANGCI_VERSION)) && "$$bin" run --allow-serial-runners --timeout=5m --build-tags=integration ./test/integration/...
	@bin=$$($(TOOL) staticcheck $(STATICCHECK_VERSION)) && "$$bin" -tags=integration ./test/integration/...

## build: compile all packages
.PHONY: build
build:
	"$$GOCMD" build $(PKG)

## cross-build: compile (and vet) every package for every supported GOOS/GOARCH
.PHONY: cross-build
cross-build:
	@set -e; for t in $(CROSS_TARGETS); do \
	  echo "cross-build $$t"; \
	  GOOS=$${t%/*} GOARCH=$${t#*/} "$$GOCMD" build $(PKG); \
	  GOOS=$${t%/*} GOARCH=$${t#*/} "$$GOCMD" vet $(PKG); \
	done

# BUILD GATES: their own module under test/buildgates (it needs a YAML parser
# the root module must not depend on). check-action-pins runs every test the
# other gates do not claim.
BUILDGATES_OTHER := ^(TestReleasability|TestChangelogAssemble|TestScripts)

## check-action-pins: every `uses:` in a workflow names a 40-hex commit
.PHONY: check-action-pins
check-action-pins:
	@cd test/buildgates && "$$GOCMD" vet $(PKG) && "$$GOCMD" test -count=1 -skip '$(BUILDGATES_OTHER)' $(PKG)

## check-releasability: no tracked file names the lab fleet or is agent-only
# Every tracked file is published, so the scrub happens here. Rules and
# waivers: test/buildgates/releasability_test.go.
.PHONY: check-releasability
check-releasability:
	@cd test/buildgates && "$$GOCMD" vet $(PKG) && "$$GOCMD" test -count=1 -run '^TestReleasability' $(PKG)

## check-changelog-assembly: the release step folds every fragment in exactly once
# Tests scripts/changelog-assemble.sh, which release-alpha runs, on scratch trees.
.PHONY: check-changelog-assembly
check-changelog-assembly:
	@cd test/buildgates && "$$GOCMD" vet $(PKG) && "$$GOCMD" test -count=1 -run '^TestChangelogAssemble' $(PKG)

## check-scripts: the release and tooling scripts, driven on scratch inputs
# Drives the release and tooling scripts offline on scratch trees, a fake forge
# API and a local module proxy, since most run for real only on a tag push.
.PHONY: check-scripts
check-scripts:
	@cd test/buildgates && "$$GOCMD" vet $(PKG) && "$$GOCMD" test -count=1 -run '^TestScripts' $(PKG)

## ci-fast: everything `ci` runs that does not need Docker (devops §4)
# lint-integration needs no container, so it runs here.
.PHONY: ci-fast
ci-fast: tidy-check lint lint-integration check-action-pins check-releasability check-changelog-assembly check-scripts staticcheck security coverage test-runtimesecret build cross-build
	@echo "ci-fast completed successfully"

## ci: the full local gate — what a PR must pass, security included (devops §4)
# Adds both integration variants; Docker is required (fails, never skips).
.PHONY: ci
ci: ci-fast integration-test integration-test-fips
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
# The version is explicit, never derived. Before anything is written: VERSION
# must move forward (release-version-check.sh), the tag must be free locally
# and on dev (ls-remote exit 2 is the only "free"; anything else fails closed),
# and the assembled tree must pass release-check-tag.sh. VERSION is written
# unprefixed, and changelog.d/ fragments fold into CHANGELOG.md in the same
# commit. Pushing the tag hands off to release.yml.
.PHONY: release-alpha
release-alpha:
	@case "$$VERSION" in \
	  '') echo "ERROR: state the version explicitly: make release-alpha VERSION=vX.Y.Z-alpha (release-versioning.md decides patch/minor/major — the recipe refuses to guess)"; exit 1 ;; \
	  *[!0-9A-Za-z.-]*) echo "ERROR: VERSION holds characters no vX.Y.Z-alpha version does; refusing it"; exit 1 ;; \
	esac; \
	printf '%s\n' "$$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+-alpha$$' || { echo "ERROR: '$$VERSION' is not vX.Y.Z-alpha"; exit 1; }
	@test -n "$$AGENT_GIT" || { echo 'ERROR: AGENT_GIT is unset - point it at your commit-signing/release wrapper (maintainer tooling; not needed to build or test)'; exit 1; }
	@test "$$(git rev-parse --abbrev-ref HEAD)" = main || { echo "ERROR: releases are cut from main; you are on $$(git rev-parse --abbrev-ref HEAD). 'push dev HEAD' would publish this branch to dev."; exit 1; }
	@test -n "$$REPO_NAME" || { echo "ERROR: REPO_NAME is empty — set it to the literal repo name in the Makefile, never \$$(notdir \$$(CURDIR))"; exit 1; }
	@! git rev-parse -q --verify "refs/tags/$$VERSION" >/dev/null || { echo "ERROR: tag $$VERSION already exists locally"; exit 1; }
	@git remote get-url dev >/dev/null 2>&1 || { echo "ERROR: no 'dev' remote. The Gitea remote is named dev (version-control.md §2): git remote rename origin dev"; exit 1; }
	@rc=0; git ls-remote --exit-code --tags dev "refs/tags/$$VERSION" >/dev/null 2>&1 || rc=$$?; \
	case $$rc in \
	  0) echo "ERROR: tag $$VERSION already exists on dev (a local check alone would miss this and fail the push AFTER committing VERSION)"; exit 1 ;; \
	  2) ;; \
	  *) echo "ERROR: could not query dev for tag $$VERSION (git ls-remote exit $$rc) — refusing to release on an unanswered check"; exit 1 ;; \
	esac
	@test -z "$$(git status --porcelain)" || { echo "ERROR: working tree not clean"; exit 1; }
	@sh scripts/release-version-check.sh "$$VERSION"
	sh scripts/changelog-assemble.sh "$$VERSION" "$$(date -u +%Y-%m-%d)"
	@printf '%s\n' "$${VERSION#v}" > VERSION
	@sh scripts/release-check-tag.sh "$$VERSION" || { echo "ERROR: the assembled tree would be refused by release.yml; nothing was committed (git checkout -- VERSION CHANGELOG.md changelog.d to start over)"; exit 1; }
	"$$AGENT_GIT" "$$REPO_NAME" add -A -- VERSION CHANGELOG.md changelog.d
	"$$AGENT_GIT" "$$REPO_NAME" commit -m "chore(release): $$VERSION"
	"$$AGENT_GIT" "$$REPO_NAME" tag -a "$$VERSION" -m "$$VERSION"
	"$$AGENT_GIT" "$$REPO_NAME" push dev HEAD "refs/tags/$$VERSION"
	@echo "Released $$VERSION (signed, annotated, single tag pushed); release.yml gates it and publishes the Gitea release"

# RELEASE TARGETS: release.yml calls these, never the scripts directly. Each
# takes TAG=vX.Y.Z[-pre].

## release-verify: TAG=vX.Y.Z[-pre] [MAIN_REF=<ref>] — the tag agrees with VERSION and CHANGELOG.md (and is on MAIN_REF)
# See scripts/release-check-tag.sh. With MAIN_REF, HEAD must be an ancestor of it.
.PHONY: release-verify
release-verify:
	@test -n "$$TAG" || { echo "ERROR: TAG=vX.Y.Z[-pre] is required"; exit 1; }
	@if [ -n "$$MAIN_REF" ]; then \
	  case "$$MAIN_REF" in \
	    -*|*[!A-Za-z0-9._/-]*) echo "ERROR: MAIN_REF is not a plain ref name; refusing it"; exit 1 ;; \
	  esac; \
	fi
	sh scripts/release-check-tag.sh "$$TAG"
	@if [ -n "$$MAIN_REF" ]; then \
	  main=$$(git rev-parse --verify --quiet --end-of-options "$$MAIN_REF^{commit}") || { echo "ERROR: MAIN_REF '$$MAIN_REF' does not name a commit"; exit 1; }; \
	  git merge-base --is-ancestor HEAD "$$main" || { echo "ERROR: HEAD $$(git rev-parse HEAD) is not on $$MAIN_REF"; exit 1; }; \
	  echo "release-verify: HEAD is on $$MAIN_REF"; \
	fi

## consumer-check: TAG=vX.Y.Z[-pre] — build and run a throwaway consumer of this module at TAG (GOWORK=off)
# Module resolution comes from the environment (GOPRIVATE, insteadOf, proxy).
.PHONY: consumer-check
consumer-check:
	@test -n "$$TAG" || { echo "ERROR: TAG=vX.Y.Z[-pre] is required"; exit 1; }
	sh scripts/consumer-check.sh "$$("$$GOCMD" list -m)" "$$TAG"

## release-publish: TAG=vX.Y.Z[-pre] SHA=<commit> — publish the Gitea release for TAG (FORGE_API_URL, FORGE_REPOSITORY, FORGE_TOKEN)
# Refuses GitHub; see scripts/release-publish.sh.
.PHONY: release-publish
release-publish:
	@test -n "$$TAG" || { echo "ERROR: TAG=vX.Y.Z[-pre] is required"; exit 1; }
	@test -n "$$SHA" || { echo "ERROR: SHA=<the gated commit> is required"; exit 1; }
	sh scripts/release-publish.sh "$$TAG" "$$SHA"

## clean: remove build/test artifacts (the pinned-tool cache stays: clean-tools)
# Removes files, and the report directory only if empty (never rm -rf).
.PHONY: clean
clean:
	@rm -f -- "$$COVERAGE_PROFILE" "$$COVERAGE_HTML" coverage-*.out gosec.sarif trivy-results.sarif || exit $$?; \
	d=$$(dirname -- "$$COVERAGE_HTML"); \
	if [ "$$d" != . ]; then rmdir -- "$$d" 2>/dev/null || true; fi

## clean-tools: remove the repository-local pinned-tool cache (bin/tools)
# Refuses a relative TOOLS_DIR, or one resolving to /, the checkout or $HOME.
.PHONY: clean-tools
clean-tools:
	@case "$$TOOLS_DIR" in \
	  /*) ;; \
	  *) echo "ERROR: TOOLS_DIR must be an absolute path; refusing to delete it"; exit 1 ;; \
	esac; \
	if [ -d "$$TOOLS_DIR" ]; then \
	  real=$$(cd -P -- "$$TOOLS_DIR" && pwd) || exit 1; \
	  repo=$$(pwd -P); \
	  case "$$real" in \
	    /|"$$repo"|"$${HOME:-/}") echo "ERROR: TOOLS_DIR resolves to $$real; refusing to delete it"; exit 1 ;; \
	  esac; \
	fi; \
	rm -rf -- "$$TOOLS_DIR"
