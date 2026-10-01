# go-enclave — foundational locked-memory primitive.
# Pure library, single package: no binaries, no container image.
#
# THE MAKEFILE IS THE CONTRACT (handbook devops §4). Every check CI runs is a
# target here, and the workflows call the targets rather than carrying their
# own commands or flags, so a red CI reproduces with the same `make` line on a
# workstation. A check that exists only in a workflow file is debugged by
# pushing commits.
#
# Not applicable here, deliberately (project-scaffold §4 lists them for every
# repository): `docker-build` and `docker-run` — the library ships no binary and
# no image, so there is nothing to containerise or to scan with `trivy image`;
# `proto` — there is no protobuf and no generated code. They are absent rather
# than stubbed, because a target that succeeds by doing nothing reports work
# that was never done.

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
# The file `make help` reads, captured before anything is included (it is the
# only entry in MAKEFILE_LIST here).
export HELP_MAKEFILE := $(firstword $(MAKEFILE_LIST))

-include local.mk
AGENT_GIT ?=
REPO_NAME ?= go-enclave

# Dependencies resolve from published tags, never from a workspace
# (dependency-resolution §2): a stray go.work is inert for every target.
export GOWORK := off

GOCMD    ?= go
PKG      := ./...
COVERAGE_PROFILE := coverage.out
COVERAGE_HTML    := coverage/coverage.html

# raw_bind VARS: re-bind each variable to its RAW text and export it, so a
# recipe reads it as a quoted shell variable ("$$VAR") and nothing in it — a
# space, a quote, `$`, a backtick, `;` — is ever parsed as shell or make
# source. The full reasoning is at EXTERNAL_VARS below. A path is data like
# any other: the checkout directory, a tool path, an output file.
raw_bind = $(foreach v,$(1),$(eval override $(v) := $$(value $(v)))$(eval export $(v)))

# sq TEXT: TEXT as one single-quoted shell word, for the one place a value
# must be spliced into shell source — $(shell …), which in GNU Make 4.3 does
# not see the variables this Makefile exports.
sq = '$(subst ','\'',$(1))'

# GOCMD is the go command — a PATH, possibly with spaces in it, so it is one
# quoted word ("$$GOCMD"), never spliced. AGENT_GIT and REPO_NAME likewise.
$(call raw_bind,GOCMD AGENT_GIT REPO_NAME COVERAGE_PROFILE COVERAGE_HTML)

# ---------------------------------------------------------------------------
# PINNED TOOLS
#
# Every analyser runs at exactly the version below, here and in CI. The pins
# are the versions the CI runner image bakes (its versions.conf is the single
# source of CI tool versions, owner-approved 2026-09-25), because CI runs with
# TOOL_INSTALL=0 and refuses any other version — so raising a pin is a
# two-step change: the image first, then this line. Each line says where the
# next version comes from. This is a pin "specifically documented, in place,
# with the reason" (devops §9, the clause permitting one), not the `@latest`
# installs it replaced: `@latest` changed underneath the repository without a
# commit and once produced unattributable "Version: dev" scans (go-luks2 #21).
#
# Raise with the runner image: `go list -m github.com/golangci/golangci-lint/v2@latest`.
# v2.13.2 is also the floor for linting Go 1.27: v2.12.2's vendored analysis
# tools cannot parse the 1.27 stdlib ("unexpected expr: *ast.KeyValueExpr").
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
# The two tools below are release ARCHIVES, not `go install` builds, and each
# carries four SHA-256s pinned here: the archive per Linux architecture
# (checked before anything is unpacked) and the binary inside it (checked
# after unpacking, and again before a cached copy is reused — a self-reported
# version is not a trust anchor). scripts/tool.sh says why not `go install`
# and why never a checksum file fetched beside the archive. Raise a version
# and all four of its hashes together, or not at all.
#
# trivy is NOT in the runner image, so every job that scans installs it. The
# archive hashes match upstream's trivy_0.74.0_checksums.txt, and the amd64
# binary is byte-identical to a copy acquired independently on 2026-08-27.
# Raise by reading the new release's checksums file, downloading both
# archives and confirming each hash. Held at v0.74.0 (2026-08-14), not
# v0.75.0: v0.75.0 was published on 2026-10-01, the day this pin was set, and a
# security scanner's release channel is a supply-chain target — a release gets
# to age before it runs on our runners. Re-evaluate from 2026-10-08.
TRIVY_VERSION                  := v0.74.0
TRIVY_SHA256_LINUX_AMD64       := 2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a
TRIVY_SHA256_LINUX_ARM64       := b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5
TRIVY_BIN_SHA256_LINUX_AMD64   := d89bcc6510a267f11b773398cbf1be5520ce39f9e8b6633178c4487f05b7d791
TRIVY_BIN_SHA256_LINUX_ARM64   := fed2c9ca7d27191ada34524b5eaf5216a845c6d6f3246143c3b475552ffe5358
# shellcheck, which actionlint runs over every workflow `run:` block and
# lint-scripts runs over scripts/. Pinned to what the runner image carries:
# the image installs the distro package from its Ubuntu 24.04 base, and
# Ubuntu 24.04 ships 0.9.0 (0.9.0-1); the image asserts that version and
# records it in its tool manifest. Raise with the runner image's base, not
# ahead of it. Upstream publishes NO checksums, so these hashes were computed
# from the release archives and corroborated against upstream's other
# channel: both extracted binaries are byte-identical to /bin/shellcheck in the
# koalaman/shellcheck:v0.9.0 image (amd64 and arm64).
SHELLCHECK_VERSION             := v0.9.0
SHELLCHECK_SHA256_LINUX_AMD64  := 700324c6dd0ebea0117591c6cc9d7350d9c7c5c287acbad7630fa17b1d4d9e2f
SHELLCHECK_SHA256_LINUX_ARM64  := 179c579ef3481317d130adebede74a34dbbc2df961a70916dd4039ebf0735fae
SHELLCHECK_BIN_SHA256_LINUX_AMD64 := 7087178d54de6652b404c306233264463cb9e7a9afeb259bb663cc4dbfd64149
SHELLCHECK_BIN_SHA256_LINUX_ARM64 := ef4c0f06039f2034dfba012251ddfeb1edba88e049fc5edfbc289fef179daaa0

# TOOL_INSTALL=1 (the default) installs a missing pinned tool into TOOLS_DIR,
# inside the repository and version-addressed, so a `make lint` never touches
# the developer's GOPATH/bin (devops §4: targets do not mutate the machine
# outside the repository). TOOL_INSTALL=0 installs NOTHING: each tool must
# already be on PATH at exactly its pin, and an absent or different one fails
# closed. CI on our runners sets 0 — the image bakes every tool but trivy, and
# a workflow that network-installs over the baked copy is how v2.12.2 once
# silently replaced the v2.13.2 that could lint Go 1.27. A fallback install on
# mismatch would reintroduce that substitution at exactly the moment the guard
# exists for, so there is none.
TOOL_INSTALL ?= 1
TOOLS_DIR    := $(CURDIR)/bin/tools
# The checkout directory is whatever its owner named it — spaces, quotes, `$`
# and `;` included — so TOOLS_DIR is data: exported, read as "$$TOOLS_DIR".
$(call raw_bind,TOOLS_DIR)
#
# A Go tool's cache directory is keyed by version AND toolchain
# (bin/tools/<tool>-<version>-<toolchain>/), and a cached binary is reused
# only when its embedded build metadata names that toolchain: keyed by version
# alone, raising the module's toolchain silently kept the analyser the old
# compiler built.

# The toolchain this module selects (go.mod's go/toolchain line), resolved HERE,
# inside the module, and handed to every tool install (#83).
#
# Without it the installs are built by whatever toolchain the TOOL's go.mod asks
# for: `go install pkg@version` runs outside this module's context, so under
# GOTOOLCHAIN=auto it switches to the tool's own floor. Measured on a host
# whose PATH go is 1.24.3: golangci-lint and staticcheck were both built with
# go1.26.8, and both then refused this go 1.27.0 module — "the Go language
# version (go1.26) used to build golangci-lint is lower than the targeted Go
# version (1.27.0)", and staticcheck died parsing the 1.27 stdlib. `make ci`
# failed at lint on a tree CI passes, which is the drift TESTFLAGS exists to
# prevent.
TOOLCHAIN := $(shell $(call sq,$(GOCMD)) env GOVERSION)

# `bin=$$($(TOOL) <name> <version>) && "$$bin" ...` — scripts/tool.sh prints
# the path of the pinned binary, or fails closed explaining why it cannot. Its
# inputs travel in the ENVIRONMENT (exported below), never spliced into the
# recipe's shell source, so no value — a checkout path with a quote in it, a
# TOOL_INSTALL from a workflow — is ever parsed as shell.
export TOOLCHAIN
export GO := $(GOCMD)
export TRIVY_SHA256_LINUX_AMD64 TRIVY_SHA256_LINUX_ARM64 TRIVY_BIN_SHA256_LINUX_AMD64 TRIVY_BIN_SHA256_LINUX_ARM64
export SHELLCHECK_SHA256_LINUX_AMD64 SHELLCHECK_SHA256_LINUX_ARM64 SHELLCHECK_BIN_SHA256_LINUX_AMD64 SHELLCHECK_BIN_SHA256_LINUX_ARM64
TOOL = sh scripts/tool.sh

# gosec's flags exist HERE ONLY; CI runs `make gosec` (devops §8: "CI invokes
# gosec via the same make target developers use, never its own flag set, or
# the two scans rule on different findings").
#
#   -concurrency 4: gosec sizes its worker pool from runtime.NumCPU(), which
#     reports the HOST's cores regardless of GOMAXPROCS or a cgroup limit, so
#     on a 24-core host in a 16 GB job container it analysed 24 packages' SSA
#     at once and the LIVE heap alone passed the cap — GOMEMLIMIT cannot
#     collect live memory. Concurrency changes how fast the scan runs, never
#     what it finds, so the same bound applies on a workstation: one flag set.
#   -exclude-dir=test: test/ holds the build gates (their own module, never
#     shipped) and the integration suite (#91), neither of which reaches a
#     consumer. Shipped code — the root package and providertest — is always
#     scanned. CI also excluded `examples`, which does not exist; an exclusion
#     waiting for a directory is a blind spot pre-declared for whatever lands
#     there, so it is gone.
#   -fmt=sarif -out + -stdout -verbose=text: the SARIF is what github.com's
#     code scanning ingests; the text copy is what a Gitea log shows, since
#     Gitea has no code-scanning API and a failure would otherwise exit 1 with
#     the findings buried in a file nobody can see.
#   No -exclude rules: every finding is fixed or carries `#nosec G### -- why`
#     at the line (the one annotation both gosec and golangci-lint honour).
GOSEC_FLAGS := -concurrency=4 -severity=medium -confidence=medium -exclude-dir=test \
	-fmt=sarif -out=gosec.sarif -stdout -verbose=text

# trivy fs, one flag set for every target and both workflows. --skip-dirs bin:
# the repository-local tool cache holds third-party binaries this library does
# not ship. test/ is scanned: nothing that could ever be shipped is skipped,
# and the build gates' dependencies are dependencies of a job holding a token.
# --skip-version-check: the pin decides the version, so the scan does not call
# home to ask whether a newer one exists.
TRIVY_FS_FLAGS := --skip-dirs bin --ignorefile .trivyignore --skip-version-check

# The coverage floor (project-scaffold §6, testing-guidelines: 90%). `:=`, not
# `?=`: a floor an environment variable can lower is not a floor. Lowering it
# takes an explicit `make COVERAGE_THRESHOLD=…` on the command line.
COVERAGE_THRESHOLD := 90

# VALUES FROM OUTSIDE ARE DATA, NEVER SHELL OR MAKE SOURCE (#89).
#
# TAG, SHA and MAIN_REF come from release.yml, which takes them from the pushed
# tag — and git accepts a tag named v`id` or v$(id), which the `v*` trigger
# matches. VERSION is what a maintainer types for release-alpha;
# TOOL_INSTALL and COVERAGE_THRESHOLD can arrive from a workflow or a command
# line. Two separate ways such a value used to become code:
#
#   - a recipe wrote "$(TAG)": make pastes the text into the recipe's shell
#     source BEFORE the shell runs, so backticks, $(...), `;` or a quote in
#     the value executed before any validator saw it (reproduced:
#     `make release-verify 'TAG=v`id`'` handed the validator "vuid=1000…");
#   - a variable given on the make COMMAND LINE is recursively expanded when
#     make exports it to a recipe, so `$(shell …)` in the value runs inside
#     make itself, even when no recipe mentions it (measured, GNU Make 4.3;
#     a value from the environment is passed through untouched).
#
# So each is re-bound here, once, to its RAW text — `$(value X)` reads it
# without expanding it, `:=` stores it without expanding it again — and
# exported. Recipes read them only as quoted shell variables ("$$TAG"), and
# the scripts validate them, whole-string, before using them. Never write
# $(TAG), $(SHA), $(MAIN_REF), $(VERSION), $(TOOL_INSTALL) or
# $(COVERAGE_THRESHOLD) in a recipe.
#
# PATHS are bound the same way (raw_bind): GOCMD, AGENT_GIT, REPO_NAME,
# TOOLS_DIR (derived from the checkout directory), COVERAGE_PROFILE,
# COVERAGE_HTML, DEVCONTAINER_COMPOSE and DEVCONTAINER_SERVICE. A checkout at
# "/home/me/projects/go enclave" once turned `rm -rf $(TOOLS_DIR)` into
# `rm -rf /home/me/projects/go enclave/bin/tools`, deleting a sibling
# directory. The only values still spliced into recipes are FLAG LISTS an
# operator sets on purpose and which must word-split — TESTFLAGS, GOSEC_FLAGS,
# TRIVY_FS_FLAGS, INTEGRATION_TESTFLAGS, CROSS_TARGETS — and constants this
# file defines (PKG, the package directories, the pinned versions).
EXTERNAL_VARS := TAG SHA MAIN_REF VERSION TOOL_INSTALL COVERAGE_THRESHOLD
$(call raw_bind,$(EXTERNAL_VARS))

# Every GOOS/GOARCH pair a consumer may build this library for. 386 and arm are
# here because a 32-bit target is where a uintptr comparison against
# math.MaxInt64 stops compiling (security-review.md §5), and that is exactly how
# providertest shipped unbuildable on 32-bit Linux through v0.6.1-alpha: nothing
# built it.
CROSS_TARGETS := linux/amd64 linux/arm64 linux/386 linux/arm \
	darwin/amd64 darwin/arm64 freebsd/amd64 openbsd/amd64 netbsd/amd64 dragonfly/amd64 \
	illumos/amd64 solaris/amd64 aix/ppc64 windows/amd64 windows/386

# Packages, for the per-package targets (project-scaffold §4: test-<pkg>,
# coverage-<pkg>, bench-<pkg>, integration-test-<pkg>). The root package is
# `enclave`, its Go name.
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
# `make ci` used to run `tidy`, which REWRITES go.mod: a gate that repairs what
# it checks passes locally on a tree CI would have to reject, and CI never ran
# it at all. This reports the diff and changes nothing.
.PHONY: tidy-check
tidy-check:
	@"$$GOCMD" mod tidy -diff || { echo "go.mod/go.sum are not tidy: run 'make tidy'"; exit 1; }
	@cd test/buildgates && "$$GOCMD" mod tidy -diff || { echo "test/buildgates/go.mod is not tidy: run 'go mod tidy' there"; exit 1; }

## lint: gofmt, go vet, golangci-lint, actionlint, shellcheck (devops §4)
.PHONY: lint
lint: fmt-check vet lint-go lint-actions lint-scripts

## lint-go: golangci-lint (pinned) over .golangci.yml
# .golangci.yml must enable staticcheck, errcheck, unused, ineffassign,
# misspell and gocritic (devops §8) — the umbrella with the security linters
# off does not satisfy the gate.
# --allow-serial-runners: golangci-lint takes a host-wide lock and, by default,
# FAILS ("parallel golangci-lint is running") when another run holds it — on
# a machine with several worktrees, an unrelated lint elsewhere turned this
# gate red. It now waits for the lock instead; the result is unchanged.
.PHONY: lint-go
lint-go:
	@bin=$$($(TOOL) golangci-lint $(GOLANGCI_VERSION)) && "$$bin" run --allow-serial-runners --timeout=5m $(PKG)

## lint-actions: actionlint (pinned) over .github/workflows, with the pinned shellcheck on every run: block
# actionlint runs shellcheck over the shell in each step only when it finds
# it, and skips that half SILENTLY otherwise — so the pinned shellcheck is
# resolved here and handed to it explicitly, never discovered on PATH.
.PHONY: lint-actions
lint-actions:
	@sc=$$($(TOOL) shellcheck $(SHELLCHECK_VERSION)) && \
	bin=$$($(TOOL) actionlint $(ACTIONLINT_VERSION)) && "$$bin" -shellcheck "$$sc"

## lint-scripts: shellcheck (pinned) over scripts/*.sh
# The scripts are POSIX sh, and release.yml runs them with a write token.
.PHONY: lint-scripts
lint-scripts:
	@sc=$$($(TOOL) shellcheck $(SHELLCHECK_VERSION)) && \
	echo "shellcheck $(SHELLCHECK_VERSION) --shell=sh scripts/*.sh" && "$$sc" --shell=sh scripts/*.sh

## staticcheck: honnef.co staticcheck (pinned)
.PHONY: staticcheck
staticcheck:
	@bin=$$($(TOOL) staticcheck $(STATICCHECK_VERSION)) && "$$bin" $(PKG)

## gosec: security static analysis (pinned; writes gosec.sarif)
# A scanner killed by a signal exits 128+N — 137 for the OOM killer — which in
# a job summary is indistinguishable from "findings". The recipe still fails
# either way; it only says WHICH, so nobody hunts a finding that does not exist.
.PHONY: gosec
gosec:
	@bin=$$($(TOOL) gosec $(GOSEC_VERSION)) || exit 1; \
	rc=0; "$$bin" $(GOSEC_FLAGS) $(PKG) || rc=$$?; \
	if [ $$rc -gt 128 ]; then \
	  echo "gosec was KILLED by signal $$((rc - 128)) - this is NOT a security finding. Memory pressure; re-run when the host is quieter."; \
	fi; exit $$rc

## govulncheck: known-vuln scan (pinned; also the toolchain-currency forcing function)
# Same exit triage as gosec: govulncheck holds the whole package graph and its
# SSA live, so in a memory-capped container it can be SIGKILLed, and a bare
# non-zero reads exactly like "vulnerabilities found".
.PHONY: govulncheck
govulncheck:
	@bin=$$($(TOOL) govulncheck $(GOVULNCHECK_VERSION)) || exit 1; \
	rc=0; "$$bin" $(PKG) || rc=$$?; \
	if [ $$rc -gt 128 ]; then \
	  echo "govulncheck was KILLED by signal $$((rc - 128)) - this is NOT a vulnerability finding. Memory pressure, not a CVE; confirm with an uncapped run."; \
	fi; exit $$rc

## modverify: verify module integrity
.PHONY: modverify
modverify:
	"$$GOCMD" mod verify

## trivy: filesystem vulnerability + secret scan, CRITICAL/HIGH fail (pinned)
# --ignorefile matches every other trivy target and the workflows, so a
# suppression recorded in .trivyignore applies everywhere. Without it the scans
# disagree, which is how a red nightly hid behind a green `make security`.
.PHONY: trivy
trivy:
	@bin=$$($(TOOL) trivy $(TRIVY_VERSION)) && \
	"$$bin" fs --scanners vuln,secret --severity CRITICAL,HIGH --exit-code 1 --format table $(TRIVY_FS_FLAGS) .

## trivy-misconfig: misconfiguration scan, ADVISORY (reports, never fails on findings)
# Owner direction: misconfiguration scanning is enabled, advisory until its
# baseline is clean (devops §8 records portfolio-wide enablement as an open
# decision; this repository runs it without blocking anything).
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
# No container image to scan. CI runs the first three per push and trivy
# nightly (devops §8a, alpha phase); release.yml runs all four.
.PHONY: security
security: gosec govulncheck modverify trivy
	@echo "Security suite passed"

# The flags CI runs the suite with, in one place so a local run and the pipeline
# cannot drift apart — a check that passes locally and fails in CI (or worse,
# the reverse) is its own defect class. `:=`, so an exported TESTFLAGS cannot
# quietly drop the two flags below.
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
TESTFLAGS := -race -count=1 -cpu=1,2,8

## test: unit tests with the race detector, across the CPU matrix
.PHONY: test
test:
	"$$GOCMD" test $(TESTFLAGS) -timeout=900s $(PKG)

# The profile `coverage` gates and `coverage-report` renders. Same flags as
# `test`, matrix included: coverage is measured on the run that actually
# gates, not on a cheaper one that exercises less.
.PHONY: coverage-profile
coverage-profile:
	"$$GOCMD" test $(TESTFLAGS) -covermode=atomic -timeout=900s -coverprofile="$$COVERAGE_PROFILE" $(PKG)

## coverage: unit tests with coverage; FAILS below COVERAGE_THRESHOLD, in total AND per package
# The threshold is enforced HERE, and CI runs this target (project-scaffold §6,
# devops §4): a floor that exists only in a workflow cannot be reproduced
# locally, and two copies of it drift.
#
# The floor binds EVERY PACKAGE, not only the total (testing-guidelines: "ALL
# packages have at least 90%"; #90). A total is a statement-weighted average,
# and the root package is several times providertest's size, so providertest
# sat at 84.6% for releases while the total read green. Each package's figure
# is computed from the same profile the total is — covered statements over
# statements, exactly what `go tool cover -func` totals — so one run gates both.
# The comparison is exact — covered*100 against floor*statements, no rounding
# and no tolerance — so a package a hair below the floor fails.
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
# Separate from `coverage` so the report is produced exactly when it is most
# wanted — when the floor is missed.
.PHONY: coverage-report
coverage-report: coverage-profile
	@mkdir -p -- "$$(dirname -- "$$COVERAGE_HTML")"
	"$$GOCMD" tool cover -html="$$COVERAGE_PROFILE" -o "$$COVERAGE_HTML"
	@"$$GOCMD" tool cover -func="$$COVERAGE_PROFILE" | awk '/^total:/ {print "Total coverage: " $$3}'
	@echo "Wrote $$COVERAGE_HTML"

## test-fips: build + unit tests under Go native FIPS 140-3 strict mode
# Covers the same packages as `test`, but it is NOT the same run with only the
# FIPS env added: it runs once, without -race and without the -cpu=1,2,8
# matrix (security-review.md §6). Its job is to find non-approved cryptography
# on a tested path, which neither the race detector nor the CPU matrix bears
# on; the race and contention defects stay with `test`/`coverage`. nightly.yml
# and release.yml run this target. The sealing surface performs real
# cryptography chosen to pass this mode (NewGCMWithRandomNonce et al.), so this
# gate is load-bearing: strict mode is what caught the NewGCM arbitrary-IV
# refusal in the first place.
#
# STRICT mode, `fips140=only`, not `on`: `on` loads the Go Cryptographic Module
# but still PERMITS non-approved algorithms, so a test exercising MD5 or SHA-1
# passes and the gate reports green while a regulated path uses prohibited
# cryptography. `only` makes non-approved operations error or panic. If this
# fails, that failure IS the finding — fix the call site, never weaken it to
# `on`. GOFIPS140=latest selects the newest validated module snapshot at build
# time; GODEBUG is a runtime setting and cannot cause a compile error.
.PHONY: test-fips
test-fips:
	GOFIPS140=latest GODEBUG=fips140=only "$$GOCMD" build $(PKG)
	GOFIPS140=latest GODEBUG=fips140=only "$$GOCMD" test -count=1 -timeout=900s $(PKG)

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

# INTEGRATION SUITE (integration-testing §3-§4). Each package's suite lives in
# test/integration/<pkg>/ and runs in the project devcontainer, NEVER on the
# host: a suite that passes only on a workstation measures the workstation.
#
# The contract the suite (#91) must meet, stated here because this is where it
# is enforced: build/docker/devcontainer/compose.yaml defines a service named
# `devcontainer` whose working directory is the repository root, so that
# `go test ./test/integration/<pkg>/...` runs inside it. Each run gets its own
# compose project (integration-testing §7: two runs on one host must not claim
# each other's containers, networks or volumes) and is torn down with its
# volumes on any exit.
#
# Every precondition FAILS rather than skips. Until the suite and the
# devcontainer land, these targets fail saying so: a target that passes with
# nothing to run reports a suite that never ran as green, and such a target is
# then wired into CI as a gate that gates nothing.
INTEGRATION_PACKAGES  := enclave
DEVCONTAINER_COMPOSE  := build/docker/devcontainer/compose.yaml
DEVCONTAINER_SERVICE  := devcontainer
INTEGRATION_TESTFLAGS := -race -count=1 -timeout=1800s
$(call raw_bind,DEVCONTAINER_COMPOSE DEVCONTAINER_SERVICE)

## integration-test: every integration suite, in the devcontainer
.PHONY: integration-test
integration-test: $(addprefix integration-test-,$(INTEGRATION_PACKAGES))

## integration-test-<pkg>: one package's integration suite, in the devcontainer (enclave)
.PHONY: $(addprefix integration-test-,$(INTEGRATION_PACKAGES))
$(addprefix integration-test-,$(INTEGRATION_PACKAGES)): integration-test-%:
	@test -d test/integration/$* || { echo "ERROR: test/integration/$* does not exist: the $* integration suite has not landed (#91). Refusing to report a suite that did not run as passed."; exit 1; }
	@ls test/integration/$*/*_test.go >/dev/null 2>&1 || { echo "ERROR: test/integration/$* holds no _test.go files; refusing to pass with nothing to run."; exit 1; }
	@test -f "$$DEVCONTAINER_COMPOSE" || { echo "ERROR: $$DEVCONTAINER_COMPOSE not found. Integration tests run in the project devcontainer, never on the host (integration-testing §4)."; exit 1; }
	@command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 || { echo "ERROR: 'docker compose' is required to run the integration suite in the devcontainer."; exit 1; }
	@project="go-enclave-it-$*-$$(date +%s)-$$$$"; \
	trap 'docker compose -f "$$DEVCONTAINER_COMPOSE" -p "$$project" down --volumes --remove-orphans >/dev/null 2>&1' EXIT INT TERM; \
	docker compose -f "$$DEVCONTAINER_COMPOSE" -p "$$project" run --rm --build "$$DEVCONTAINER_SERVICE" \
	  go test $(INTEGRATION_TESTFLAGS) ./test/integration/$*/...

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

# BUILD GATES. Their own module under test/ (see test/buildgates/doc.go): the
# pin gate needs a YAML parser and the root module's minimal-dependency invariant is
# not negotiable for a test helper. That is why these cannot be plain
# `go test ./...` targets. Each gate selects its tests by name; every test the
# other gates do not claim runs under check-action-pins.
BUILDGATES_OTHER := ^(TestReleasability|TestChangelogAssemble|TestScripts)

## check-action-pins: every `uses:` in a workflow names a 40-hex commit
.PHONY: check-action-pins
check-action-pins:
	@cd test/buildgates && "$$GOCMD" vet $(PKG) && "$$GOCMD" test -count=1 -skip '$(BUILDGATES_OTHER)' $(PKG)

## check-releasability: no tracked file names the lab fleet or is agent-only
# The public GitHub tree is byte-identical to the Gitea release tag (handbook
# version-control §5a), so every tracked file is published and a scrub has to
# happen here, in the source, before tagging. The gate reads the git index —
# what is published — and fails naming the file, the line and what to use
# instead. Rules, waivers and the rationale: test/buildgates/releasability_test.go.
.PHONY: check-releasability
check-releasability:
	@cd test/buildgates && "$$GOCMD" vet $(PKG) && "$$GOCMD" test -count=1 -run '^TestReleasability' $(PKG)

## check-changelog-assembly: the release step folds every fragment in exactly once
# scripts/changelog-assemble.sh is what `make release-alpha` runs before
# tagging; its tests (test/buildgates/changelog_assemble_test.go) drive it on
# scratch trees, so a defect in it is found here rather than in a tag.
.PHONY: check-changelog-assembly
check-changelog-assembly:
	@cd test/buildgates && "$$GOCMD" vet $(PKG) && "$$GOCMD" test -count=1 -run '^TestChangelogAssemble' $(PKG)

## check-scripts: the release and tooling scripts, driven on scratch inputs
# scripts/release-notes.sh, release-check-tag.sh, release-publish.sh,
# consumer-check.sh and tool.sh run with a write token or decide what a gate
# trusts, and most of them run for real only when a tag is pushed — too late to
# find a defect. test/buildgates/scripts_test.go drives each one on scratch
# trees, a local fake of the forge API and a local module proxy, offline.
.PHONY: check-scripts
check-scripts:
	@cd test/buildgates && "$$GOCMD" vet $(PKG) && "$$GOCMD" test -count=1 -run '^TestScripts' $(PKG)

## ci-fast: everything `ci` runs that does not need Docker (devops §4)
# Today that is all of it — nothing in the gate needs Docker — so the two are
# the same set. `integration-test` joins `ci`, and only `ci`, when the
# devcontainer suite lands (#91).
.PHONY: ci-fast
ci-fast: tidy-check lint check-action-pins check-releasability check-changelog-assembly check-scripts staticcheck security coverage build cross-build
	@echo "ci-fast completed successfully"

## ci: the full local gate — what a PR must pass, security included (devops §4)
.PHONY: ci
ci: ci-fast
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
#
# A second fix, the one release-alpha.mk v2.3 made (its defect 1): VERSION is
# written UNPREFIXED, `$${VERSION#v}`. The tag is `v0.6.0-alpha`; the file is
# `0.6.0-alpha` (release-versioning §2). Writing the tag string verbatim is how
# v0.6.0-alpha shipped a VERSION reading `v0.6.0-alpha` (#80).
#
# Third, CHANGELOG fragments (release-versioning §5, adopted in #80): before
# VERSION is written, scripts/changelog-assemble.sh folds every changelog.d/
# fragment, and whatever [Unreleased] still holds, into the new version's
# section and deletes the fragments; the release commit carries CHANGELOG.md,
# the deletions and VERSION together, so the tag's CHANGELOG has every entry
# exactly once. The assembly is committed here, before tagging, because
# release.yml only reads the tagged tree. If the section was written by hand
# and a fragment is still waiting, the script refuses rather than tag a
# CHANGELOG that leaves it out.
#
# Fourth, the remote-tag guard fails CLOSED. It used to read
# `! git ls-remote ... dev ...`, and `!` turns EVERY failure into a pass —
# including exit 128 from a clone with no `dev` remote at all, measured passing
# for the already-published v0.6.1-alpha. The recipe then committed VERSION,
# tagged locally and died at the push. Exit 2 (no such ref) is the only answer
# that means "free"; anything else is an unanswered question.
#
# Fifth (#89), the version must move FORWARD before anything is written:
# scripts/release-version-check.sh refuses a VERSION that is not strictly
# greater, by SemVer 2.0.0 precedence, than the current VERSION and every
# existing v* tag (release-versioning §3 — never lower VERSION, never
# supersede a tag with a lower one). The checks above refuse a version that
# already exists; this one refuses a version that would go backwards.
#
# Sixth (#89), the tree is checked with scripts/release-check-tag.sh — the
# check release.yml runs first on the pushed tag — before anything is
# committed, so the recipe cannot tag what the release workflow would refuse.
# Pushing the tag is the last manual step: release.yml then gates the tagged
# commit, builds a throwaway consumer from the published tag, and publishes the
# Gitea release with the version's CHANGELOG section as its body. Nothing is
# created by hand on the forge any more.
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

# RELEASE TARGETS (#89). release.yml calls these, never the scripts directly,
# so the release workflow is as reproducible from a shell as CI is. Each takes
# the tag as TAG=vX.Y.Z[-pre].

## release-verify: TAG=vX.Y.Z[-pre] [MAIN_REF=<ref>] — the tag agrees with VERSION and CHANGELOG.md (and is on MAIN_REF)
# scripts/release-check-tag.sh: VERSION is the tag unprefixed, CHANGELOG.md has
# exactly one non-empty section for it, no changelog.d/ fragment or
# [Unreleased] entry was left out. With MAIN_REF, HEAD must also be an
# ancestor of it: both release kinds are tags on main (release-versioning §1a).
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
# Resolution comes from the environment (dependency-resolution §1/§6), so on
# a Gitea runner the injected GOPRIVATE/insteadOf fetch it from the forge and
# elsewhere it comes from the public proxy.
.PHONY: consumer-check
consumer-check:
	@test -n "$$TAG" || { echo "ERROR: TAG=vX.Y.Z[-pre] is required"; exit 1; }
	sh scripts/consumer-check.sh "$$("$$GOCMD" list -m)" "$$TAG"

## release-publish: TAG=vX.Y.Z[-pre] SHA=<commit> — publish the Gitea release for TAG (FORGE_API_URL, FORGE_REPOSITORY, FORGE_TOKEN)
# Refuses GitHub on its own (release-versioning §5); see scripts/release-publish.sh.
.PHONY: release-publish
release-publish:
	@test -n "$$TAG" || { echo "ERROR: TAG=vX.Y.Z[-pre] is required"; exit 1; }
	@test -n "$$SHA" || { echo "ERROR: SHA=<the gated commit> is required"; exit 1; }
	sh scripts/release-publish.sh "$$TAG" "$$SHA"

## clean: remove build/test artifacts (the pinned-tool cache stays: clean-tools)
# Removes FILES, and the report's directory only if it is then empty. It used
# to `rm -rf $(dir $(COVERAGE_HTML))`, which for a report path with no
# directory part is `rm -rf ./` — the checkout. A failed rm fails the target;
# only the empty-directory rmdir is best effort.
.PHONY: clean
clean:
	@rm -f -- "$$COVERAGE_PROFILE" "$$COVERAGE_HTML" coverage-*.out gosec.sarif trivy-results.sarif || exit $$?; \
	d=$$(dirname -- "$$COVERAGE_HTML"); \
	if [ "$$d" != . ]; then rmdir -- "$$d" 2>/dev/null || true; fi

## clean-tools: remove the repository-local pinned-tool cache (bin/tools)
# One quoted operand, never the bare expansion: an unquoted path with a space
# in it is two paths. Refuses a relative TOOLS_DIR, and one that resolves to
# /, the checkout itself or $HOME.
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
