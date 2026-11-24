# go-enclave: locked-memory library. CI calls these targets only; the logic lives in scripts/.

# AGENT_GIT has no default, so release fails closed without it; REPO_NAME is literal because it selects the signing identity.
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

# Pinned tool versions and SHA-256s live only in scripts/tool-pins.sh.
include scripts/tool-pins.sh

# TOOL_INSTALL=1 installs missing pins into TOOLS_DIR; TOOL_INSTALL=0 fails closed on a missing or mismatched tool.
TOOL_INSTALL ?= 1
TOOLS_DIR    := $(CURDIR)/bin/tools
# TOOLS_DIR derives from the checkout path, so it is raw-bound.
$(call raw_bind,TOOLS_DIR)

# tool NAME,PREFIX: the pinned binary's path, or a failed lookup.
export GO := $(GOCMD)
export TRIVY_VERSION
export TRIVY_SHA256_LINUX_AMD64 TRIVY_SHA256_LINUX_ARM64 TRIVY_BIN_SHA256_LINUX_AMD64 TRIVY_BIN_SHA256_LINUX_ARM64
export SHELLCHECK_SHA256_LINUX_AMD64 SHELLCHECK_SHA256_LINUX_ARM64 SHELLCHECK_BIN_SHA256_LINUX_AMD64 SHELLCHECK_BIN_SHA256_LINUX_ARM64
export XTOOLS_VERSION
tool = $$(sh scripts/tool.sh $(1) $($(2)_VERSION))

# gosec flags live only here; findings are fixed or annotated with #nosec, never excluded.
GOSEC_FLAGS := -concurrency=4 -severity=medium -confidence=medium -exclude-dir=test \
	-fmt=sarif -out=gosec.sarif -stdout -verbose=text

# The same rules for the GOEXPERIMENT=runtimesecret pass, without SARIF.
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

# Caller-supplied values are raw-bound and read only as "$$VAR" in recipes; never write $(TAG), $(SHA), $(VERSION) and the like in a recipe.
EXTERNAL_VARS := TAG SHA MAIN_REF REF VERSION TOOL_INSTALL COVERAGE_THRESHOLD
$(call raw_bind,$(EXTERNAL_VARS))

# CI variables, raw-bound like EXTERNAL_VARS.
## MODULE_ENV_FILE=<file>: integration-test: the forge module variables; never read here or printed
## GO_BUILD_PROXY=<url>: docker-build: the Go module proxy the image build fetches through, passed as the BuildKit secret goproxy when set (never a build argument: the image history keeps those) (CI: the hosted runner's GOPROXY, unset, #293); default the Dockerfile's public proxy
## IT_IMAGE=<tag>: docker-build, ci-integration: the integration image's tag (default `make -s it-image`)
## APK_INDEX_SUM=<sum>: docker-build, it-image: the Alpine package index checksum (scripts/apk-index-sum.sh); it-image hashes it, docker-build passes it as --build-arg
## IT_PROJECT=<name>: integration-test: accepted; each suite names its own compose project (go-enclave-it-*, go-enclave-userns-*)
## GO_BUILD_TAGS=<tags>: lint, build, coverage, security: must stay empty, no package is tag-gated (userns, integration and optee are their suites' tags)
# GO_BUILD_TAGS is refused rather than ignored, so nothing reads as analysed that was not.
ifneq ($(strip $(value GO_BUILD_TAGS)),)
$(error GO_BUILD_TAGS must be empty: no go-enclave package is gated by a build tag)
endif
CI_VARS := MODULE_ENV_FILE GO_BUILD_PROXY IT_IMAGE IT_PROJECT GO_BUILD_TAGS
$(call raw_bind,$(CI_VARS))

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

# Backend modules under backends/<name>, each requiring a released root; the coverage floor measures the root packages only.
BACKEND_MODULES := backends/armtrustzone backends/tpm

# Features map in scripts/features.map to package, suite, test prefix and sources; build/ci/buildgates fails on an unmapped docs/<feature>/.
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
	@for m in $(BACKEND_MODULES); do (cd "$$m" && "$$GOCMD" mod tidy -diff) || { echo "$$m/go.mod is not tidy: run 'go mod tidy' there"; exit 1; }; done

## lint: gofmt, golangci-lint (vet, staticcheck, gosec), actionlint, shellcheck (devops §4)
.PHONY: lint
lint: fmt-check lint-go lint-actions lint-scripts

## lint-go: golangci-lint (pinned) over .golangci.yml: vet, staticcheck, gosec and the rest
# build/ci/buildgates is a separate module, so it is linted there too.
.PHONY: lint-go
lint-go:
	@bin=$(call tool,golangci-lint,GOLANGCI) && "$$bin" $(GOLANGCI_FLAGS) $(PKG) && \
	(cd build/ci/buildgates && "$$bin" $(GOLANGCI_FLAGS) $(PKG)) && \
	for m in $(BACKEND_MODULES); do (cd "$$m" && "$$bin" $(GOLANGCI_FLAGS) $(PKG)) || exit 1; done

## lint-actions: actionlint (pinned) over .github/workflows, with the pinned shellcheck on every run: block
# The pinned shellcheck is passed explicitly: actionlint silently skips shell
# checks when it finds none on PATH.
.PHONY: lint-actions
lint-actions:
	@sc=$(call tool,shellcheck,SHELLCHECK) && \
	bin=$(call tool,actionlint,ACTIONLINT) && "$$bin" -shellcheck "$$sc"

## lint-scripts: shellcheck (pinned) over scripts/*.sh, build/docker/devcontainer/*.sh, build/fuzz/*.sh and build/ci/*.sh
# Each script names its own shell on its first line; -x follows the sourced lib.sh.
CI_BASH_SCRIPTS := scripts/apk-index-sum.sh scripts/ci-image-cache.sh scripts/ci-image-history.sh scripts/ci-mask-lan.sh scripts/in-toolchain-image.sh scripts/in-toolchain-image_test.sh scripts/reap-stale-ci-stacks.sh scripts/trim-ci-caches.sh
.PHONY: lint-scripts
lint-scripts:
	@sc=$(call tool,shellcheck,SHELLCHECK) && \
	echo "shellcheck $(SHELLCHECK_VERSION) -x --shell=sh scripts/*.sh build/docker/devcontainer/*.sh build/fuzz/*.sh; $(CI_BASH_SCRIPTS) build/ci/*.sh" && \
	"$$sc" -x --source-path=SCRIPTDIR --shell=sh $(filter-out $(CI_BASH_SCRIPTS),$(sort $(wildcard scripts/*.sh))) build/docker/devcontainer/*.sh build/fuzz/*.sh && \
	"$$sc" -x --source-path=SCRIPTDIR $(CI_BASH_SCRIPTS) build/ci/*.sh

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
	@bin=$(call tool,govulncheck,GOVULNCHECK) && SCAN_MODULES=". build/ci/buildgates $(BACKEND_MODULES)" sh scripts/scan.sh govulncheck "a vulnerability (a CVE)" "$$bin" $(PKG)

## lint-runtimesecret: golangci-lint under GOEXPERIMENT=runtimesecret, which builds secret_erase.go (#136)
# Only this lint sees the key-erasure file; it needs the module's own toolchain.
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
.PHONY: trivy-misconfig
trivy-misconfig:
	@$(call trivy_fs,--scanners misconfig --exit-code 0 --format table)

## trivy-sarif: vulnerability + secret scan as SARIF (trivy-results.sarif), for code scanning
.PHONY: trivy-sarif
trivy-sarif:
	@$(call trivy_fs,--scanners vuln$(,)secret --exit-code 0 --format sarif --output trivy-results.sarif)

## security: the security stage — golangci-lint's gosec, gosec and govulncheck (default and runtimesecret builds), modverify, trivy fs
.PHONY: security
security: lint-go gosec gosec-runtimesecret govulncheck govulncheck-runtimesecret modverify trivy
	@echo "Security suite passed"

# Test flags shared by local and CI runs: -race and -cpu=1,2,8 are required to catch the shutdown and reserve races.
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
test: $(TEST_TARGETS) test-backends

## test-backends: unit tests of each backend module (BACKEND_MODULES)
.PHONY: test-backends
test-backends:
	@for m in $(BACKEND_MODULES); do (cd "$$m" && "$$GOCMD" test $(TEST_RACE) $(TESTFLAGS) $(PKG)) || exit 1; done

## test-<pkg>, coverage-<pkg>: one package (enclave, providertest, backendtest, memscan); coverage-<pkg> FAILS below COVERAGE_THRESHOLD; bench-enclave: the root package's benchmarks
.PHONY: $(TEST_TARGETS) $(COVERAGE_TARGETS) $(PROFILE_TARGETS) $(BENCH_TARGETS)
$(TEST_TARGETS): test-%:
	"$$GOCMD" test $(TEST_RACE) $(TESTFLAGS) $(PKGDIR_$*)

# The floor is checked to be a number before the suite runs.
$(PROFILE_TARGETS): coverage-profile-%: coverage-threshold
	"$$GOCMD" test $(TEST_RACE) $(TESTFLAGS) -covermode=atomic -coverprofile=coverage-$*.out $(PKGDIR_$*)

# The floor binds every package, in total and exactly (no rounding), which also
# bounds the total: a statement-weighted total cannot hide a small package.
$(COVERAGE_TARGETS): coverage-%: coverage-profile-%
	@sh scripts/coverage-gate.sh "$$COVERAGE_THRESHOLD" coverage-$*.out

$(BENCH_TARGETS): bench-%:
	"$$GOCMD" test -run '^$$' -bench . -benchmem $(PKGDIR_$*)

## coverage: unit tests with coverage; FAILS below COVERAGE_THRESHOLD, in total AND per package; then test-backends
.PHONY: coverage
coverage: $(COVERAGE_TARGETS) test-backends

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
# Strict mode (fips140=only), run once without -race; a failure is a non-approved algorithm call.
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
# The per-feature integration floor is 0; integration-test-<pkg> and ci-integration keep it.
.PHONY: $(addprefix test-,$(FEATURES)) $(addprefix integration-test-,$(FEATURES))
$(foreach f,$(FEATURES),$(eval test-$(f): test-$(FEATURE_PKG_$(f))))
define FEATURE_INTEGRATION_RULE
integration-test-$(1): $(if $(filter $(1),$(USERNS_FEATURE)),integration-test-userns)
	@INTEGRATION_TESTFLAGS="$$$$INTEGRATION_TESTFLAGS -run ^$(FEATURE_PREFIX_$(1))" COVERAGE_THRESHOLD=0 \
		sh scripts/integration-test.sh $(FEATURE_SUITE_$(1)) "$$(INTEGRATION_COVERPKG_$(FEATURE_SUITE_$(1)))"
endef
$(foreach f,$(FEATURES),$(eval $(call FEATURE_INTEGRATION_RULE,$(f))))

# Each package's integration suite runs in the devcontainer, on an image scripts/integration-image.sh builds once and scans.
INTEGRATION_PACKAGES  := enclave
DEVCONTAINER_COMPOSE  := build/docker/devcontainer/compose.yaml
DEVCONTAINER_SERVICE  := integration
INTEGRATION_TESTFLAGS := -tags=integration -race -count=1 -v -timeout=1800s
export INTEGRATION_TESTFLAGS

# GO_ENCLAVE_IT_PROFILE_OUT: where to write the merged integration profile
# ("-" prints it). Caller-supplied, so raw-bound.
GO_ENCLAVE_IT_PROFILE_OUT ?=
$(call raw_bind,GO_ENCLAVE_IT_PROFILE_OUT)
# Integration coverage is gated per suite on the packages it covers; the enclave suite also gates providertest.
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
# Built with the userns tag; scripts/userns-test.sh runs it in the userns compose service.
.PHONY: integration-test-userns
integration-test-userns:
	@sh scripts/userns-test.sh

## TRUSTED_FIRMWARE_TAG=<tag>: optee-fixture-check, integration-test-arm-trustzone: the trusted-firmware release whose `make optee-run` is the fixture (pinned in scripts/tool-pins.sh); empty refuses
## TRUSTED_FIRMWARE_COMMIT=<sha>: optee-fixture-check, integration-test-arm-trustzone: the commit the tag peels to (pinned); a checkout at any other commit is refused
## TRUSTED_FIRMWARE_CACHE=<dir>: optee-fixture-check, integration-test-arm-trustzone: where the checkout lives, one directory per tag (default ~/.cache/go-enclave/trusted-firmware)
## GO_ENCLAVE_OPTEE_ENDPOINT=<endpoint>: integration-test-arm-trustzone: the TEE client device in the fixture's guest (default /dev/tee0)
## GO_ENCLAVE_OPTEE_SEAL=required: integration-test-arm-trustzone: fail, rather than skip, the KeyProtector test when the trusted application has no SEAL; empty (default) makes the fixture declare absent:<TRUSTED_FIRMWARE_TAG>, the pinned release lacking SEAL, which the test skips on; any other value is refused
## TRUSTED_FIRMWARE_URL=<url>: optee-fixture-check, integration-test-arm-trustzone: the forge's trusted-firmware clone URL; empty refuses a clone (the pinned commit, not the URL, is what is trusted)
## OPTEE_FIXTURE_IMAGE=<image@digest>: integration-test-arm-trustzone: run the harness in this OP-TEE fixture image, on its prebuilt stack (pinned in scripts/tool-pins.sh; empty runs it on the host); the CI optee job refuses an empty pin
# The fixture image contract: docs/backend-conformance/engineering.md#fixture-image-contract.
TRUSTED_FIRMWARE_URL      ?=
TRUSTED_FIRMWARE_CACHE    ?=
GO_ENCLAVE_OPTEE_ENDPOINT ?= /dev/tee0
GO_ENCLAVE_OPTEE_SEAL     ?=
$(call raw_bind,TRUSTED_FIRMWARE_URL TRUSTED_FIRMWARE_TAG TRUSTED_FIRMWARE_COMMIT TRUSTED_FIRMWARE_CACHE GO_ENCLAVE_OPTEE_ENDPOINT GO_ENCLAVE_OPTEE_SEAL OPTEE_FIXTURE_IMAGE)
# The fixture image's trusted-firmware cache: the checkout is
# OPTEE_FIXTURE_CACHE/<tag> (the contract's path).
OPTEE_FIXTURE_CACHE := /opt/go-enclave/trusted-firmware

## optee-fixture-image: print the pinned OP-TEE fixture image (OPTEE_FIXTURE_IMAGE, pinned by digest)
.PHONY: optee-fixture-image
optee-fixture-image:
	@echo "$$OPTEE_FIXTURE_IMAGE"

## optee-fixture-check: boot the pinned trusted-firmware OP-TEE fixture and run its xtest and TA check (no go-enclave code; host packages, several GB)
# scripts/optee-fixture.sh clones the tag outside the tree, refuses a checkout
# whose HEAD is not TRUSTED_FIRMWARE_COMMIT, and runs its make integration-test-optee.
.PHONY: optee-fixture-check
optee-fixture-check:
	@sh scripts/optee-fixture.sh check

## integration-test-arm-trustzone: backendtest against the arm-trustzone backend on OP-TEE: backends/armtrustzone's optee-tagged conformance test, built for linux/arm64 in the toolchain image, run in the pinned fixture's guest
# scripts/optee-fixture.sh runs the arm64 test binary in the guest under make optee-run; a missing endpoint fails, and containers get a copy of the checkout, never a bind mount.
ARM_TRUSTZONE_MODULE := backends/armtrustzone
# The test binary, compiled in the toolchain image into the ignored bin/.
ARM_TRUSTZONE_BIN := bin/optee/armtrustzone.test
.PHONY: integration-test-arm-trustzone
integration-test-arm-trustzone: docker-build
	@[ -n "$$TRUSTED_FIRMWARE_TAG" ] || { echo "integration-test-arm-trustzone: TRUSTED_FIRMWARE_TAG is empty; set it to the trusted-firmware release whose make optee-run is the fixture (scripts/tool-pins.sh pins it)" >&2; exit 2; }
	@mkdir -p $(dir $(ARM_TRUSTZONE_BIN))
	@bash scripts/in-toolchain-image.sh "$$($(MAKE) -s toolchain-image)" 'cd $(ARM_TRUSTZONE_MODULE) && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -tags=optee -o /tmp/$(notdir $(ARM_TRUSTZONE_BIN)) . >&2 && cat /tmp/$(notdir $(ARM_TRUSTZONE_BIN))' > $(ARM_TRUSTZONE_BIN)
	@chmod 0755 $(ARM_TRUSTZONE_BIN)
	@if [ -z "$$OPTEE_FIXTURE_IMAGE" ]; then \
	  ARM_TRUSTZONE_BIN=$(ARM_TRUSTZONE_BIN) OPTEE_TEST_BIN=$(notdir $(ARM_TRUSTZONE_BIN)) sh scripts/optee-fixture.sh harness; \
	else \
	  name=go-enclave-optee-$$$$-$$(date +%s); \
	  trap 'docker rm -f -v "$$name" >/dev/null 2>&1 || true' EXIT; \
	  docker create --name "$$name" -w /src \
	    -e TRUSTED_FIRMWARE_TAG -e TRUSTED_FIRMWARE_COMMIT -e GO_ENCLAVE_OPTEE_ENDPOINT -e GO_ENCLAVE_OPTEE_SEAL \
	    -e TRUSTED_FIRMWARE_CACHE=$(OPTEE_FIXTURE_CACHE) -e OPTEE_FIXTURE_PREBUILT=1 \
	    -e ARM_TRUSTZONE_BIN=$(ARM_TRUSTZONE_BIN) -e OPTEE_TEST_BIN=$(notdir $(ARM_TRUSTZONE_BIN)) \
	    "$$OPTEE_FIXTURE_IMAGE" sh scripts/optee-fixture.sh harness >/dev/null && \
	  tar -C "$$PWD" --owner=1000 --group=1000 --numeric-owner -cf - . | docker cp -a - "$$name:/src" && \
	  docker start -a "$$name"; \
	fi

## SWTPM_PORT=<port>: integration-test-tpm: the swtpm command port on 127.0.0.1 (default 2321)
## SWTPM_CTRL_PORT=<port>: integration-test-tpm: the swtpm control port on 127.0.0.1 (default 2322)
SWTPM_PORT      ?= 2321
SWTPM_CTRL_PORT ?= 2322
$(call raw_bind,SWTPM_PORT SWTPM_CTRL_PORT)

## integration-test-tpm: providertest against the TPM provider on a throwaway swtpm: backends/tpm's swtpm-tagged conformance and blob-length tests, under -race, on the host (swtpm and swtpm-tools installed)
# scripts/swtpm-fixture.sh runs swtpm on loopback TCP and removes its state on exit; without swtpm the target fails.
.PHONY: integration-test-tpm
integration-test-tpm:
	@sh scripts/swtpm-fixture.sh

## integration-test-fips: every integration suite under FIPS 140-3 strict mode, in the devcontainer
.PHONY: integration-test-fips
integration-test-fips: $(IT_FIPS_TARGETS)

## integration-test-fips-<pkg>: one package's integration suite under FIPS 140-3 strict mode (enclave)
.PHONY: $(IT_FIPS_TARGETS)
$(IT_FIPS_TARGETS): integration-test-fips-%:
	@sh scripts/integration-test.sh $* "$(INTEGRATION_COVERPKG_$*)" $(INTEGRATION_FIPS_ENV)

## lint-integration: golangci-lint over the integration suite, WITH its build tag
# First proves the tag selects the test files and nothing builds without it.
.PHONY: lint-integration
lint-integration:
	@sh scripts/lint-integration.sh $(INTEGRATION_PACKAGES)
	@"$(GO)" test -count=1 -tags=integration ./test/internal/devcontainer/
	@bin=$(call tool,golangci-lint,GOLANGCI) && "$$bin" $(GOLANGCI_FLAGS) --build-tags=integration ./test/integration/... ./test/internal/...

# Devcontainer: a toolchain stage that runs every gate on the mounted checkout, and an integration stage with the source baked in; CMD is raw-bound and passed as one argument.
CMD ?=
$(call raw_bind,CMD)

## docker-build: Build both devcontainer stages: go-enclave-toolchain:<content tag> and :latest, and the integration image
.PHONY: docker-build
docker-build:
	@GO_ENCLAVE_IT_IMAGE="$$IT_IMAGE" sh scripts/devcontainer.sh build

## docker-build-toolchain: Build the toolchain stage alone, go-enclave-toolchain:<content tag> and :latest, skipped when the tag is held (ci-template v1.30)
.PHONY: docker-build-toolchain
docker-build-toolchain:
	@ref=$$(sh scripts/devcontainer.sh tag) && repo=$${ref%%:*} && \
	set -- -f build/docker/devcontainer/Dockerfile --target toolchain -t "$$ref" -t "$$repo:latest" && \
	if [ -n "$${GO_BUILD_PROXY:-}" ]; then set -- "$$@" --secret id=goproxy,env=GO_BUILD_PROXY; fi && \
	if docker image inspect "$$ref" >/dev/null 2>&1; then docker tag "$$ref" "$$repo:latest" && echo "$$ref is already held; tagged $$repo:latest"; \
	elif ! DOCKER_BUILDKIT=1 docker build "$$@" .; then docker image inspect "$$ref" >/dev/null 2>&1 || { echo "building $$ref failed" >&2; exit 1; }; docker tag "$$ref" "$$repo:latest"; fi

## it-image: Print the integration image's content-addressed tag, go-enclave-ci-it:<hash> of the build context (ci.yml's IT_IMAGE)
.PHONY: it-image
it-image:
	@sh scripts/devcontainer.sh it-tag

## docker-run: Run CMD in the toolchain image, checkout mounted, offline, as you: make docker-run CMD='make lint'
.PHONY: docker-run
docker-run: docker-build
	@sh scripts/devcontainer.sh run "$$CMD"

## toolchain-image: Print the toolchain image's content-addressed tag
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
	@for m in $(BACKEND_MODULES); do (cd "$$m" && sh ../../scripts/cross-build.sh $(CROSS_TARGETS) -- $(PKG)) || exit 1; done

# Build gates are their own module under build/ci/buildgates; check-buildgates runs the tests no other gate claims.
BUILDGATES_OTHER := ^(TestReleasability|TestChangelogAssemble|TestScripts)
# gates TEST-FLAGS: run the gates module's tests.
gates = cd build/ci/buildgates && "$$GOCMD" test -count=1 $(1) $(PKG)

.PHONY: vet-buildgates
vet-buildgates:
	@cd build/ci/buildgates && "$$GOCMD" vet $(PKG)

## check-buildgates: the repository's own checks: workflow action pins, issue citations, the merge workflow, the feature map, the devcontainer inputs
.PHONY: check-buildgates
check-buildgates: vet-buildgates
	@$(call gates,-skip '$(BUILDGATES_OTHER)')

## check-releasability: no tracked file names the lab fleet or is agent-only
# Rules and waivers: build/ci/buildgates/releasability_test.go.
.PHONY: check-releasability
check-releasability: vet-buildgates
	@$(call gates,-run '^TestReleasability')

## check-changelog-assembly: the release step folds every fragment in exactly once
# Tests scripts/changelog-assemble.sh, which release runs, on scratch trees.
.PHONY: check-changelog-assembly
check-changelog-assembly: vet-buildgates
	@$(call gates,-run '^TestChangelogAssemble')

## changelog-check: each changelog.d/ fragment is named for a docs/SPEC.md feature and every queued entry keeps the entry form
# Runs scripts/changelog-assemble.sh --check on the working tree; it changes nothing.
.PHONY: changelog-check
changelog-check:
	@sh scripts/changelog-assemble.sh --check

## check-scripts: the release and tooling scripts, driven on scratch inputs
# Drives the release and tooling scripts offline on scratch trees, a fake forge
# API and a local module proxy, since most run for real only on a tag push.
.PHONY: check-scripts
check-scripts: vet-buildgates
	@$(call gates,-run '^TestScripts')

## check-in-toolchain-image: scripts/in-toolchain-image.sh caps the stage's CPU bound at the daemon's NCPU
# A stub docker on PATH; no daemon, no network.
.PHONY: check-in-toolchain-image
check-in-toolchain-image:
	@bash scripts/in-toolchain-image_test.sh

## check-project-scripts: swtpm-fixture, test-runtimesecret, cross-build, lint-integration and release-verify pass and fail as they should
# Stub go, swtpm and swtpm_ioctl on PATH and a scratch git tree; no toolchain,
# TPM, network or Docker.
.PHONY: check-project-scripts
check-project-scripts:
	@sh scripts/project-scripts_test.sh

## check-it-runner: build/docker/devcontainer/run-integration-tests.sh refuses bad input with 2 and gates the merged profile at the floor
# A stub go on PATH and the real scripts/coverage-gate.sh; no Docker, no network.
.PHONY: check-it-runner
check-it-runner:
	@sh build/docker/devcontainer/run-integration-tests_test.sh

## fuzz: fuzz every Fuzz target of the root and each BACKEND_MODULES module for FUZZTIME, one at a time; stops at the first failure
## FUZZTIME=<d>: fuzz: how long each target fuzzes, a Go duration or Nx (default 30s)
## FUZZ=<regexp>: fuzz: only the targets whose name matches (extended regexp)
## FUZZ_PKG=<regexp>: fuzz: only the packages whose import path matches (extended regexp)
# A failing input is written under testdata/fuzz/; commit it with the fix as a seed.
FUZZTIME ?= 30s
$(call raw_bind,FUZZ FUZZ_PKG FUZZTIME)
.PHONY: fuzz
fuzz:
	@sh build/fuzz/fuzz.sh . $(BACKEND_MODULES)

## check-fuzz-runner: build/fuzz/fuzz.sh finds, selects and fuzzes every target, and stops at the first failure
# A stub go on PATH; no module is built and nothing is fuzzed.
.PHONY: check-fuzz-runner
check-fuzz-runner:
	@sh build/fuzz/fuzz_test.sh

## check-ci-python-suites: the CI template's carried Python suites: the LAN mask and the job-output handoff, with the mask step's placement
# Go does not discover Python under testdata/, so this target runs each suite,
# isolated (python3 -I), against the tree's ci.yml and scripts; no network.
.PHONY: check-ci-python-suites
check-ci-python-suites:
	@python3 -I testdata/ci-mask-lan-tests.py
	@python3 -I testdata/job-output-handoff-tests.py
	@python3 -I testdata/runner-select-tests.py
	@python3 -I testdata/code-review-v51213-tests.py .github/workflows/code-review.yml
	@python3 -I testdata/code-review-v51214-tests.py .github/workflows/code-review.yml

## lint-gates: the repository's own gates beside lint: check-buildgates, check-releasability, check-changelog-assembly, check-scripts, check-in-toolchain-image, check-project-scripts, check-it-runner, check-fuzz-runner, check-ci-python-suites (CI's lint-gates job)
# CI runs this as its own job beside make lint.
.PHONY: lint-gates
lint-gates: check-buildgates check-releasability check-changelog-assembly check-scripts check-in-toolchain-image check-project-scripts check-it-runner check-fuzz-runner check-ci-python-suites
	@echo "lint-gates completed successfully"

# CI aggregates: one per workflow job, shared by ci.yml and release.yml so they cannot drift.

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
# One content-addressed image, built once and trivy-scanned, serves every suite; $(MAKE) is named through a variable so make -n only prints it.
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

## deps-check: fail on any module a go.mod requires that is behind its latest release without a "// held: <reason>" comment on its require or replace line, except one whose latest release is under 7 days old, which is reported (needs the module proxy)
.PHONY: deps-check
deps-check:
	@sh scripts/deps-check.sh

## release: Prepare a production release on release/<version> (VERSION=vX.Y.Z; refuses -alpha and -rc.N)
# scripts/release.sh checks everything first and pushes only release/<version>; release-tag tags the merged commit.
.PHONY: release
release:
	@sh scripts/release.sh release

## release-candidate: Prepare a release candidate on release/<version> (VERSION=vX.Y.Z-rc.N; refuses the other kinds)
.PHONY: release-candidate
release-candidate:
	@sh scripts/release.sh candidate

## release-alpha: Prepare an alpha release on release/<version> (VERSION=vX.Y.Z-alpha; refuses the other kinds)
.PHONY: release-alpha
release-alpha:
	@sh scripts/release.sh alpha

## release-tag: After the release pull request merged, tag main's HEAD and push only the tag (VERSION=vX.Y.Z[-alpha|-rc.N])
# See scripts/release-tag.sh.
.PHONY: release-tag
release-tag:
	@sh scripts/release-tag.sh

# Release targets release.yml calls; each takes TAG=vX.Y.Z[-pre].

## release-verify: TAG=vX.Y.Z[-pre] [MAIN_REF=<ref>] — the tag agrees with VERSION and CHANGELOG.md (and is on MAIN_REF)
.PHONY: release-verify
release-verify:
	@sh scripts/release-verify.sh "$$TAG" "$$MAIN_REF"

## release-tree-check: TAG=vX.Y.Z[-pre] REF=<published ref> — the published commit's tree is the tag's tree (offline)
# See scripts/release-tree-check.sh. Resolves both trees in the local clone; writes nothing.
.PHONY: release-tree-check
release-tree-check:
	@sh scripts/release-tree-check.sh "$$TAG" "$$REF"

## consumer-check: TAG=vX.Y.Z[-pre] — build and run a throwaway consumer of this module at TAG (GOWORK=off)
# Module resolution comes from the environment (GOPRIVATE, insteadOf, proxy).
.PHONY: consumer-check
consumer-check:
	@test -n "$$TAG" || { echo "ERROR: TAG=vX.Y.Z[-pre] is required"; exit 1; }
	sh scripts/consumer-check.sh "$$("$$GOCMD" list -m)" "$$TAG"

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
