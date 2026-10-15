# go-enclave: locked-memory library. The Makefile is the contract (handbook
# project-scaffold §4): CI calls these targets and carries no commands or flags
# of its own, so a red CI reproduces with the same `make` line locally. It stays
# thin: the logic lives in scripts/, which share scripts/lib.sh.
#
# There is no binary and no protobuf: `proto` is a no-op, and docker-build /
# docker-run build the devcontainer and run a gate in its toolchain stage.

# Release tooling (maintainer-only). AGENT_GIT is the commit/signing wrapper; it
# has no default on purpose and release fails closed without it. Set it in
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

# $(,): a comma inside a $(call) argument.
, := ,

# Paths may hold spaces or quotes: bind raw, read as "$$VAR".
$(call raw_bind,GOCMD AGENT_GIT REPO_NAME COVERAGE_PROFILE COVERAGE_HTML)

# ---------------------------------------------------------------------------
# PINNED TOOLS: versions and SHA-256s live only in scripts/tool-pins.sh, which the
# devcontainer's toolchain stage installs from too.
include scripts/tool-pins.sh

# TOOL_INSTALL=1 installs missing pins into TOOLS_DIR (inside the repo, keyed by
# version and toolchain). TOOL_INSTALL=0 (CI) installs nothing: a missing or
# mismatched tool fails closed, with no fallback install. actionlint alone
# ignores TOOL_INSTALL=0: a verified PATH copy is used, else it is built into
# TOOLS_DIR at its pin (#146).
TOOL_INSTALL ?= 1
TOOLS_DIR    := $(CURDIR)/bin/tools
# TOOLS_DIR derives from the checkout path, so it is raw-bound.
$(call raw_bind,TOOLS_DIR)

# tool NAME,PREFIX: the pinned binary's path (NAME at $(PREFIX)_VERSION), or a
# failed closed lookup. scripts/tool.sh reads the pins below from the
# environment, and resolves the module's toolchain itself when it builds a tool.
#   bin=$(call tool,trivy,TRIVY) && "$$bin" ...
export GO := $(GOCMD)
export TRIVY_VERSION
export TRIVY_SHA256_LINUX_AMD64 TRIVY_SHA256_LINUX_ARM64 TRIVY_BIN_SHA256_LINUX_AMD64 TRIVY_BIN_SHA256_LINUX_ARM64
export SHELLCHECK_SHA256_LINUX_AMD64 SHELLCHECK_SHA256_LINUX_ARM64 SHELLCHECK_BIN_SHA256_LINUX_AMD64 SHELLCHECK_BIN_SHA256_LINUX_ARM64
tool = $$(sh scripts/tool.sh $(1) $($(2)_VERSION))

# gosec flags live only here; CI runs `make gosec`. golangci-lint runs gosec
# too (lint-go), but cannot write the SARIF code scanning reads.
#   -concurrency=4: gosec sizes workers from host cores, ignoring cgroup limits.
#   -exclude-dir=test: test/ is never shipped; shipped packages are always scanned.
#     build/ci/buildgates is its own module, which `./...` from the root never
#     reaches, so it needs no exclusion; trivy and govulncheck still cover it.
#   SARIF for code scanning, plus text on stdout for Gitea logs.
#   No -exclude rules: fix the finding or annotate `#nosec G### -- why`.
GOSEC_FLAGS := -concurrency=4 -severity=medium -confidence=medium -exclude-dir=test \
	-fmt=sarif -out=gosec.sarif -stdout -verbose=text

# The same rules for the GOEXPERIMENT=runtimesecret pass: no SARIF (the
# default pass writes it), the build differs only by secret_erase.go.
GOSEC_RUNTIMESECRET_FLAGS := -concurrency=4 -severity=medium -confidence=medium -exclude-dir=test \
	-fmt=text -stdout -verbose=text

# golangci-lint flags. --allow-serial-runners waits for golangci-lint's
# host-wide lock instead of failing.
GOLANGCI_FLAGS := run --allow-serial-runners --timeout=5m

# trivy fs flags for every target and workflow. bin/ is the third-party tool
# cache; the pin decides the version, so the version check is skipped.
TRIVY_FS_FLAGS := --skip-dirs bin --ignorefile .trivyignore --skip-version-check

# trivy_fs SCAN-FLAGS: `trivy fs` of the tree with the shared flags.
trivy_fs = bin=$(call tool,trivy,TRIVY) && "$$bin" fs $(1) $(TRIVY_FS_FLAGS) .

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

# Per-package targets (test-, coverage-, bench-<pkg>). The root package is enclave;
# memscan is internal/memscan, the process-memory sweep the Linux tests share.
PACKAGES          := enclave providertest backendtest memscan
PKGDIR_enclave      := .
PKGDIR_providertest := ./providertest
PKGDIR_backendtest  := ./backendtest
PKGDIR_memscan      := ./internal/memscan

# FEATURE MAPPING (local-software-factory §7). A feature is a directory
# docs/<feature>/, mapped in scripts/features.map to its package, its
# integration suite, the name prefix of its integration tests and its source
# globs; scripts/features.sh <base> <tip> prints the features a change touches,
# which the factory reads as FEATURES_CMD. Each feature runs as test-<feature>,
# its package's test-<pkg>, and integration-test-<feature>, which runs only the
# tests named with the feature's prefix. A new docs/<feature>/ is mapped there;
# build/ci/buildgates fails until it is.
FEATURES := $(shell sh scripts/features.sh list)
# The feature whose integration run also runs the user-namespace test.
USERNS_FEATURE := locked-memory-budget
ifeq ($(strip $(FEATURES)),)
$(error scripts/features.map maps no feature)
endif
$(foreach f,$(FEATURES),$(eval FEATURE_PKG_$(f) := $(shell sh scripts/features.sh field $(f) unit-package)))
$(foreach f,$(FEATURES),$(eval FEATURE_SUITE_$(f) := $(shell sh scripts/features.sh field $(f) suite)))
$(foreach f,$(FEATURES),$(eval FEATURE_PREFIX_$(f) := $(shell sh scripts/features.sh field $(f) test-prefix)))

.PHONY: all
## all: Same as ci
all: ci

.PHONY: help
## help: List targets
help:
	@test -f "$$HELP_MAKEFILE" || { echo "help: cannot locate this Makefile (make splits a -f path containing spaces); run make from the checkout"; exit 1; }
	@grep -E '^## ' "$$HELP_MAKEFILE" | sed 's/## //'

## proto: No-op, this library has no .proto
.PHONY: proto
proto:
	@echo "proto: nothing to generate (go-enclave has no .proto)"

## fmt: Format the tree (gofmt)
.PHONY: fmt
fmt:
	@sh scripts/fmt.sh write

## fmt-check: Fail if anything is unformatted
.PHONY: fmt-check
fmt-check:
	@sh scripts/fmt.sh check

## vet: go vet (golangci-lint's govet, the one implementation, lint-go)
.PHONY: vet
vet: lint-go

## tidy: go mod tidy
.PHONY: tidy
tidy:
	"$$GOCMD" mod tidy

## tidy-check: fail if go.mod/go.sum (root or build/ci/buildgates) are not tidy
# Reports the diff and changes nothing: a gate must not repair what it checks.
.PHONY: tidy-check
tidy-check:
	@"$$GOCMD" mod tidy -diff || { echo "go.mod/go.sum are not tidy: run 'make tidy'"; exit 1; }
	@cd build/ci/buildgates && "$$GOCMD" mod tidy -diff || { echo "build/ci/buildgates/go.mod is not tidy: run 'go mod tidy' there"; exit 1; }

## lint: gofmt, golangci-lint (vet, staticcheck, gosec), actionlint, shellcheck (devops §4)
.PHONY: lint
lint: fmt-check lint-go lint-actions lint-scripts

## lint-go: golangci-lint (pinned) over .golangci.yml: vet, staticcheck, gosec and the rest
# .golangci.yml must enable staticcheck, errcheck, unused, ineffassign,
# misspell and gocritic. build/ci/buildgates is a separate module, so it is
# linted there too.
.PHONY: lint-go
lint-go:
	@bin=$(call tool,golangci-lint,GOLANGCI) && "$$bin" $(GOLANGCI_FLAGS) $(PKG) && \
	cd build/ci/buildgates && "$$bin" $(GOLANGCI_FLAGS) $(PKG)

## lint-actions: actionlint (pinned) over .github/workflows, with the pinned shellcheck on every run: block
# The pinned shellcheck is passed explicitly: actionlint silently skips shell
# checks when it finds none on PATH.
.PHONY: lint-actions
lint-actions:
	@sc=$(call tool,shellcheck,SHELLCHECK) && \
	bin=$(call tool,actionlint,ACTIONLINT) && "$$bin" -shellcheck "$$sc"

## lint-scripts: shellcheck (pinned) over scripts/*.sh, build/docker/devcontainer/*.sh and build/ci/*.sh
# The scripts are POSIX sh, and release.yml runs them with a write token. -x
# follows the `. lib.sh` every script sources. build/ci/*.sh are the workflows'
# scripts; each names its own shell on its first line.
.PHONY: lint-scripts
lint-scripts:
	@sc=$(call tool,shellcheck,SHELLCHECK) && \
	echo "shellcheck $(SHELLCHECK_VERSION) -x --shell=sh scripts/*.sh build/docker/devcontainer/*.sh; build/ci/*.sh" && \
	"$$sc" -x --source-path=SCRIPTDIR --shell=sh scripts/*.sh build/docker/devcontainer/*.sh && \
	"$$sc" -x --source-path=SCRIPTDIR build/ci/*.sh

## staticcheck: staticcheck (golangci-lint's, the one implementation, lint-go)
.PHONY: staticcheck
staticcheck: lint-go

## gosec: gosec (pinned; writes gosec.sarif for code scanning; lint-go runs the same rules)
.PHONY: gosec
gosec:
	@bin=$(call tool,gosec,GOSEC) && sh scripts/scan.sh gosec "a security finding" "$$bin" $(GOSEC_FLAGS) $(PKG)

## govulncheck: known-vuln scan (pinned; also the toolchain-currency forcing function)
.PHONY: govulncheck
govulncheck:
	@bin=$(call tool,govulncheck,GOVULNCHECK) && SCAN_MODULES=". build/ci/buildgates" sh scripts/scan.sh govulncheck "a vulnerability (a CVE)" "$$bin" $(PKG)

## lint-runtimesecret: golangci-lint under GOEXPERIMENT=runtimesecret, which builds secret_erase.go (#136)
# The default build never compiles the key-erasure file, so no other lint sees it.
# The experiment needs the module's own toolchain, so it runs on that go.
.PHONY: lint-runtimesecret
lint-runtimesecret:
	@bin=$(call tool,golangci-lint,GOLANGCI) && GOEXPERIMENT=runtimesecret "$$bin" $(GOLANGCI_FLAGS) $(PKG)

## gosec-runtimesecret: gosec under GOEXPERIMENT=runtimesecret (text only; gosec writes the SARIF)
.PHONY: gosec-runtimesecret
gosec-runtimesecret:
	@bin=$(call tool,gosec,GOSEC) && GOEXPERIMENT=runtimesecret sh scripts/scan.sh gosec "a security finding" "$$bin" $(GOSEC_RUNTIMESECRET_FLAGS) $(PKG)

## govulncheck-runtimesecret: govulncheck under GOEXPERIMENT=runtimesecret
.PHONY: govulncheck-runtimesecret
govulncheck-runtimesecret:
	@bin=$(call tool,govulncheck,GOVULNCHECK) && GOEXPERIMENT=runtimesecret sh scripts/scan.sh govulncheck "a vulnerability (a CVE)" "$$bin" $(PKG)

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
	@$(call trivy_fs,--scanners vuln$(,)secret --severity CRITICAL$(,)HIGH --exit-code 1 --format table)

## trivy-misconfig: misconfiguration scan, ADVISORY (reports, never fails on findings)
# Advisory until the misconfiguration baseline is clean.
.PHONY: trivy-misconfig
trivy-misconfig:
	@$(call trivy_fs,--scanners misconfig --exit-code 0 --format table)

## trivy-sarif: vulnerability + secret scan as SARIF (trivy-results.sarif), for code scanning
.PHONY: trivy-sarif
trivy-sarif:
	@$(call trivy_fs,--scanners vuln$(,)secret --exit-code 0 --format sarif --output trivy-results.sarif)

## security: full local security suite — golangci-lint's gosec, govulncheck, modverify, trivy
# No image to scan. CI runs gosec (SARIF), govulncheck and modverify per push
# and trivy nightly; release.yml runs all four.
.PHONY: security
security: lint-go govulncheck modverify trivy
	@echo "Security suite passed"

# CI's test flags, defined once so local and CI runs cannot drift; `:=` so an
# exported TESTFLAGS cannot drop them. None is optional:
#   -race (TEST_RACE) is the only detector for publication-ordering bugs in the shutdown registry.
#   -cpu=1,2,8: the reserve retune-vs-admission race is caught only by
#   contention, so core count is part of the oracle (one core never sees it).
#   TEST_RACE is its own variable so a TESTFLAGS given on the command line
#   (`make test TESTFLAGS=-run=X`) cannot drop -race.
TEST_TIMEOUT := -timeout=900s
TEST_RACE    := -race
TESTFLAGS    := -count=1 -cpu=1,2,8 $(TEST_TIMEOUT)

# Per-package targets; the aggregates below only depend on them.
TEST_TARGETS     := $(addprefix test-,$(PACKAGES))
COVERAGE_TARGETS := $(addprefix coverage-,$(PACKAGES))
PROFILE_TARGETS  := $(addprefix coverage-profile-,$(PACKAGES))
# Only the root package has benchmarks; providertest, backendtest and memscan have none, so
# a bench target for them ran zero benchmarks.
BENCH_PACKAGES   := enclave
BENCH_TARGETS    := $(addprefix bench-,$(BENCH_PACKAGES))

## test: unit tests with the race detector, across the CPU matrix
.PHONY: test
test: $(TEST_TARGETS)

## test-<pkg>, coverage-<pkg>: one package (enclave, providertest, backendtest, memscan); coverage-<pkg> FAILS below COVERAGE_THRESHOLD; bench-enclave: the root package's benchmarks
.PHONY: $(TEST_TARGETS) $(COVERAGE_TARGETS) $(PROFILE_TARGETS) $(BENCH_TARGETS)
$(TEST_TARGETS): test-%:
	"$$GOCMD" test $(TEST_RACE) $(TESTFLAGS) $(PKGDIR_$*)

# The floor is checked to be a number BEFORE the suite spends minutes running.
$(PROFILE_TARGETS): coverage-profile-%: coverage-threshold
	"$$GOCMD" test $(TEST_RACE) $(TESTFLAGS) -covermode=atomic -coverprofile=coverage-$*.out $(PKGDIR_$*)

# The floor binds every package, in total and exactly (no rounding), which also
# bounds the total: a statement-weighted total cannot hide a small package.
$(COVERAGE_TARGETS): coverage-%: coverage-profile-%
	@sh scripts/coverage-gate.sh "$$COVERAGE_THRESHOLD" coverage-$*.out

$(BENCH_TARGETS): bench-%:
	"$$GOCMD" test -run '^$$' -bench . -benchmem $(PKGDIR_$*)

## coverage: unit tests with coverage; FAILS below COVERAGE_THRESHOLD, in total AND per package
.PHONY: coverage
coverage: $(COVERAGE_TARGETS)

.PHONY: coverage-threshold
coverage-threshold:
	@sh scripts/coverage-gate.sh "$$COVERAGE_THRESHOLD"

# One profile ($(COVERAGE_PROFILE)) for coverage-report, from the per-package ones.
.PHONY: coverage-profile
coverage-profile: $(PROFILE_TARGETS)
	@sh scripts/coverage-gate.sh merge "$$COVERAGE_PROFILE" $(foreach p,$(PACKAGES),coverage-$(p).out)

## coverage-report: HTML coverage report at coverage/coverage.html (no threshold)
# Separate from coverage so the report is produced even when the floor is missed.
.PHONY: coverage-report
coverage-report: coverage-profile
	@mkdir -p -- "$$(dirname -- "$$COVERAGE_HTML")"
	"$$GOCMD" tool cover -html="$$COVERAGE_PROFILE" -o "$$COVERAGE_HTML"
	@"$$GOCMD" tool cover -func="$$COVERAGE_PROFILE" | tail -n 1
	@echo "Wrote $$COVERAGE_HTML"

## test-fips: build + unit tests under Go native FIPS 140-3 strict mode
# Runs once, without -race or the CPU matrix: it hunts non-approved crypto.
# STRICT mode (fips140=only), never `on`, which still permits non-approved
# algorithms. A failure here is the finding: fix the call site.
.PHONY: test-fips
test-fips:
	GOFIPS140=latest GODEBUG=fips140=only "$$GOCMD" build $(PKG)
	GOFIPS140=latest GODEBUG=fips140=only "$$GOCMD" test -count=1 $(TEST_TIMEOUT) $(PKG)

## test-runtimesecret: unit tests built with GOEXPERIMENT=runtimesecret (key-schedule erasure, #98)
# See scripts/test-runtimesecret.sh.
.PHONY: test-runtimesecret
test-runtimesecret:
	@sh scripts/test-runtimesecret.sh $(TEST_RACE) $(TESTFLAGS)

## bench: every benchmark, with allocation counts (no unit tests)
.PHONY: bench
bench: $(BENCH_TARGETS)

## test-<feature>, integration-test-<feature>: one feature's unit and integration suites (see FEATURES)
# integration-test-<feature> runs the suite's tests named with the feature's
# prefix and nothing else, so it cannot meet the whole suite's coverage floor:
# the floor is 0 here, and integration-test-<pkg> and ci-integration keep it.
.PHONY: $(addprefix test-,$(FEATURES)) $(addprefix integration-test-,$(FEATURES))
$(foreach f,$(FEATURES),$(eval test-$(f): test-$(FEATURE_PKG_$(f))))
define FEATURE_INTEGRATION_RULE
integration-test-$(1): $(if $(filter $(1),$(USERNS_FEATURE)),integration-test-userns)
	@INTEGRATION_TESTFLAGS="$$$$INTEGRATION_TESTFLAGS -run ^$(FEATURE_PREFIX_$(1))" COVERAGE_THRESHOLD=0 \
		sh scripts/integration-test.sh $(FEATURE_SUITE_$(1)) "$$(INTEGRATION_COVERPKG_$(FEATURE_SUITE_$(1)))"
endef
$(foreach f,$(FEATURES),$(eval $(call FEATURE_INTEGRATION_RULE,$(f))))

# INTEGRATION SUITE. Each package's suite (test/integration/<pkg>/) runs in the
# devcontainer, never on the host: scripts/integration-test.sh, on an image that
# scripts/integration-image.sh builds once and scans (ci-integration shares it).
INTEGRATION_PACKAGES  := enclave
DEVCONTAINER_COMPOSE  := build/docker/devcontainer/compose.yaml
DEVCONTAINER_SERVICE  := integration
INTEGRATION_TESTFLAGS := -tags=integration -race -count=1 -v -timeout=1800s
export INTEGRATION_TESTFLAGS

# GO_ENCLAVE_IT_PROFILE_OUT: where to write the merged integration profile
# ("-" prints it). Caller-supplied, so raw-bound.
GO_ENCLAVE_IT_PROFILE_OUT ?=
$(call raw_bind,GO_ENCLAVE_IT_PROFILE_OUT)
# Integration coverage is gated per suite on the packages it is FOR, against
# COVERAGE_THRESHOLD, each package on its own. providertest has no suite of its
# own: the enclave suite drives it in the devcontainer, so that suite is gated on
# it too (comma-separated import paths, as run-integration-tests.sh takes them).
INTEGRATION_COVERPKG_enclave := github.com/jeremyhahn/go-enclave,github.com/jeremyhahn/go-enclave/providertest
# FIPS strict run: same suite with GOFIPS140=latest and fips140=only. The suite
# fails unless the runtime reports the promised GO_ENCLAVE_IT_FIPS_MODE.
INTEGRATION_FIPS_ENV  := -e GOFIPS140=latest -e GODEBUG=fips140=only -e GO_ENCLAVE_IT_FIPS_MODE=only
$(call raw_bind,DEVCONTAINER_COMPOSE DEVCONTAINER_SERVICE)

IT_TARGETS      := $(addprefix integration-test-,$(INTEGRATION_PACKAGES))
IT_FIPS_TARGETS := $(addprefix integration-test-fips-,$(INTEGRATION_PACKAGES))

## integration-test: every integration suite, in the devcontainer
.PHONY: integration-test
integration-test: $(IT_TARGETS)

## integration-test-<pkg>: one package's integration suite, in the devcontainer (enclave)
.PHONY: $(IT_TARGETS)
$(IT_TARGETS): integration-test-%: integration-test-userns
	@sh scripts/integration-test.sh $* "$(INTEGRATION_COVERPKG_$*)"

## integration-test-userns: the root package's user-namespace test, in the devcontainer under a seccomp profile that permits CLONE_NEWUSER
# It is built with the userns tag, so `make test` does not run it (the default
# toolchain container refuses user namespaces and the test fails there, it does
# not skip). scripts/userns-test.sh runs it in the `userns` compose service.
.PHONY: integration-test-userns
integration-test-userns:
	@sh scripts/userns-test.sh

## integration-test-fips: every integration suite under FIPS 140-3 strict mode, in the devcontainer
.PHONY: integration-test-fips
integration-test-fips: $(IT_FIPS_TARGETS)

## integration-test-fips-<pkg>: one package's integration suite under FIPS 140-3 strict mode (enclave)
.PHONY: $(IT_FIPS_TARGETS)
$(IT_FIPS_TARGETS): integration-test-fips-%:
	@sh scripts/integration-test.sh $* "$(INTEGRATION_COVERPKG_$*)" $(INTEGRATION_FIPS_ENV)

## lint-integration: golangci-lint over the integration suite, WITH its build tag
# `make lint` runs without the integration tag and never sees the suite. This
# first proves the tag selects the test files and nothing builds without it.
.PHONY: lint-integration
lint-integration:
	@sh scripts/lint-integration.sh $(INTEGRATION_PACKAGES)
	@bin=$(call tool,golangci-lint,GOLANGCI) && "$$bin" $(GOLANGCI_FLAGS) --build-tags=integration ./test/integration/...

# THE DEVCONTAINER (build/docker/devcontainer/): one Dockerfile, two stages.
# `toolchain` is Go plus every pin in scripts/tool-pins.sh, and runs every gate
# with the checkout mounted; `integration`, from the same base stage and
# without the tools, has the source baked in and runs only the integration suite. scripts/devcontainer.sh does the work.
#
# CMD: the command docker-run runs, one string for bash -c. It is the caller's
# command by design, so it is raw-bound (never parsed as make source) and
# handed to the script as one argument.
CMD ?=
$(call raw_bind,CMD)

## docker-build: Build both devcontainer stages: go-enclave-toolchain:<content tag> and :latest, and the integration image
.PHONY: docker-build
docker-build:
	@sh scripts/devcontainer.sh build

## docker-run: Run CMD in the toolchain image, checkout mounted, offline, as you: make docker-run CMD='make lint'
.PHONY: docker-run
docker-run: docker-build
	@sh scripts/devcontainer.sh run "$$CMD"

## toolchain-image: Print the toolchain image's content-addressed tag (lane-verify's VERIFY_IMAGE)
.PHONY: toolchain-image
toolchain-image:
	@sh scripts/devcontainer.sh tag

## build: compile all packages
.PHONY: build
build:
	"$$GOCMD" build $(PKG)

## cross-build: compile, vet and link the test binaries of every package for every supported GOOS/GOARCH
.PHONY: cross-build
cross-build:
	@sh scripts/cross-build.sh $(CROSS_TARGETS) -- $(PKG)

# BUILD GATES: their own module under build/ci/buildgates (it needs a YAML parser
# the root module must not depend on). check-buildgates runs every test the
# other gates do not claim.
BUILDGATES_OTHER := ^(TestReleasability|TestChangelogAssemble|TestScripts)
# gates TEST-FLAGS: run the gates module's tests. Every check-* target depends
# on vet-buildgates, which make runs once per invocation.
gates = cd build/ci/buildgates && "$$GOCMD" test -count=1 $(1) $(PKG)

.PHONY: vet-buildgates
vet-buildgates:
	@cd build/ci/buildgates && "$$GOCMD" vet $(PKG)

## check-buildgates: the repository's own checks: workflow action pins, issue citations, the merge workflow, the feature map, the devcontainer inputs
.PHONY: check-buildgates
check-buildgates: vet-buildgates
	@$(call gates,-skip '$(BUILDGATES_OTHER)')

## check-releasability: no tracked file names the lab fleet or is agent-only
# Every tracked file is published, so the scrub happens here. Rules and
# waivers: build/ci/buildgates/releasability_test.go.
.PHONY: check-releasability
check-releasability: vet-buildgates
	@$(call gates,-run '^TestReleasability')

## check-changelog-assembly: the release step folds every fragment in exactly once
# Tests scripts/changelog-assemble.sh, which release runs, on scratch trees.
.PHONY: check-changelog-assembly
check-changelog-assembly: vet-buildgates
	@$(call gates,-run '^TestChangelogAssemble')

## check-scripts: the release and tooling scripts, driven on scratch inputs
# Drives the release and tooling scripts offline on scratch trees, a fake forge
# API and a local module proxy, since most run for real only on a tag push.
.PHONY: check-scripts
check-scripts: vet-buildgates
	@$(call gates,-run '^TestScripts')

# CI AGGREGATES. ci.yml and release.yml each call these, one per job, so a job
# is one `make` line and the two workflows cannot drift apart. Each target runs
# once per invocation, however many others depend on it: lint-go carries vet,
# staticcheck and gosec for lint and security alike.

## ci-lint: every static check: tidy, lint (staticcheck included), the integration suite's lint, the build gates, releasability, changelog assembly, the scripts
.PHONY: ci-lint
ci-lint: tidy-check lint lint-runtimesecret lint-integration check-buildgates check-releasability check-changelog-assembly check-scripts
	@echo "ci-lint completed successfully"

## ci-build: compile all packages, then for every supported GOOS/GOARCH
.PHONY: ci-build
ci-build: build cross-build
	@echo "ci-build completed successfully"

## ci-security: gosec (SARIF), govulncheck and module verification; trivy runs nightly and on release
.PHONY: ci-security
ci-security: gosec gosec-runtimesecret govulncheck govulncheck-runtimesecret modverify
	@echo "ci-security completed successfully"

## ci-test: unit tests with coverage (race, CPU matrix, threshold) and the key-schedule erasure build
.PHONY: ci-test
ci-test: coverage test-runtimesecret
	@echo "ci-test completed successfully"

## ci-integration: both integration variants (default and FIPS 140-3 strict) in the devcontainer
# One image serves the userns, default and FIPS suites (FIPS is a run-time
# flag): scripts/integration-image.sh builds it once, trivy-scans that exact
# image ID, runs both targets against it with no rebuild, and removes it last.
# The recipe names make through a variable, so `make -n ci-integration` prints it
# instead of running it (a line with a literal $(MAKE) runs even under -n).
IT_MAKE = $(MAKE) --no-print-directory
.PHONY: ci-integration
ci-integration:
	@sh scripts/integration-image.sh $(IT_MAKE) integration-test integration-test-fips
	@echo "ci-integration completed successfully"

## ci-fast: everything `ci` runs that does not need Docker (devops §4)
.PHONY: ci-fast
ci-fast: ci-lint ci-security trivy ci-test ci-build
	@echo "ci-fast completed successfully"

## ci: the full local gate — what a PR must pass, security included (devops §4)
# Adds both integration variants; Docker is required (fails, never skips).
.PHONY: ci
ci: ci-fast ci-integration
	@echo "CI pipeline completed successfully"

## deps-latest: bump internal dependencies to their latest tags (none today)
.PHONY: deps-latest
deps-latest:
	@sh scripts/deps-latest.sh

## release: Tag and push a production release (VERSION=vX.Y.Z; refuses -alpha and -rc.N)
# The version is explicit, never derived. The three release targets run the one
# scripts/release.sh with their kind: every check runs before anything is
# written, and pushing the tag hands off to release.yml.
.PHONY: release
release:
	@sh scripts/release.sh release

## release-candidate: Tag and push a release candidate (VERSION=vX.Y.Z-rc.N; refuses the other kinds)
.PHONY: release-candidate
release-candidate:
	@sh scripts/release.sh candidate

## release-alpha: Tag and push an alpha release (VERSION=vX.Y.Z-alpha; refuses the other kinds)
.PHONY: release-alpha
release-alpha:
	@sh scripts/release.sh alpha

# RELEASE TARGETS: release.yml calls these, never the scripts directly. Each
# takes TAG=vX.Y.Z[-pre].

## release-verify: TAG=vX.Y.Z[-pre] [MAIN_REF=<ref>] — the tag agrees with VERSION and CHANGELOG.md (and is on MAIN_REF)
# See scripts/release-verify.sh. With MAIN_REF, HEAD must be an ancestor of it.
.PHONY: release-verify
release-verify:
	@sh scripts/release-verify.sh "$$TAG" "$$MAIN_REF"

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
	@rm -f -- "$$COVERAGE_PROFILE" "$$COVERAGE_HTML" coverage-*.out gosec.sarif trivy-results.sarif
	@rmdir -- "$$(dirname -- "$$COVERAGE_HTML")" 2>/dev/null || true

## clean-tools: remove the repository-local pinned-tool cache (bin/tools)
.PHONY: clean-tools
clean-tools:
	@sh scripts/clean-tools.sh
