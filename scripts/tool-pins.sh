# shellcheck shell=sh disable=SC2034
# tool-pins.sh — THE pins of every analysis tool, and nowhere else. Sourced,
# never run, like lib.sh.
#
# Read by the Makefile (`include`) and by the devcontainer's tools stage
# (scripts/install-tools.sh sources it), so the version a gate runs on a
# developer's machine, in CI and in go-enclave-toolchain is the same one.
# NAME=value lines only, comments on their own lines: the file is both make
# and sh, and make would keep a trailing comment's leading space in the value.
#
# Every pin tracks the tool's latest upstream release; a pin exists only so a
# build is reproducible. Never @latest, never an older version than upstream's.
#
# Raise with `go list -m github.com/golangci/golangci-lint/v2@latest`.
# golangci-lint runs vet, staticcheck and gosec (.golangci.yml), so they have
# no pin of their own.
GOLANGCI_VERSION=v2.14.0
# Raise with `go list -m github.com/securego/gosec/v2@latest`.
GOSEC_VERSION=v2.29.0
# gosec is built against this x/tools: the v0.49.0 its go.mod names cannot read
# the export data (version 5) Go 1.27 writes, so every import fails to type-check.
XTOOLS_VERSION=v0.52.0
# Raise with `go list -m golang.org/x/vuln@latest`.
GOVULNCHECK_VERSION=v1.8.0
# Raise with `go list -m github.com/rhysd/actionlint@latest`.
ACTIONLINT_VERSION=v1.7.12
#
# trivy and shellcheck are release archives pinned by four SHA-256s each: the
# archive per Linux arch and the binary inside it (see scripts/tool.sh).
# Raise a version and all four of its hashes together, or not at all.
#
# trivy's archive hashes are from the release's trivy_0.75.0_checksums.txt.
TRIVY_VERSION=v0.75.0
TRIVY_SHA256_LINUX_AMD64=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f
TRIVY_SHA256_LINUX_ARM64=a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3
TRIVY_BIN_SHA256_LINUX_AMD64=93f9da8e4ba5e0c1c76d8234ed2494cf9afb0a96fd21953e424bb795f3299b8e
TRIVY_BIN_SHA256_LINUX_ARM64=869e310e208f0f2e3e90e4f842cc6adaa2b2c046fecbaade481e6b23fcc8f2a9
# The shellcheck pin (actionlint and lint-scripts). Upstream publishes no
# checksums; these are the SHA-256s of the v0.11.0 release archives and of the
# binaries inside them, computed from the downloads.
SHELLCHECK_VERSION=v0.11.0
SHELLCHECK_SHA256_LINUX_AMD64=8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198
SHELLCHECK_SHA256_LINUX_ARM64=12b331c1d2db6b9eb13cfca64306b1b157a86eb69db83023e261eaa7e7c14588
SHELLCHECK_BIN_SHA256_LINUX_AMD64=4da528ddb3a4d1b7b24a59d4e16eb2f5fd960f4bd9a3708a15baddbdf1d5a55b
SHELLCHECK_BIN_SHA256_LINUX_ARM64=127f13925eadd52c341bca0ebaf9ab0dbd78c6468f30a8f262a528bf8de47546
#
# The OP-TEE fixture (#250): trusted-firmware's `make optee-run` at a release
# tag, run by scripts/optee-fixture.sh. The tag is pinned with the commit it
# peels to; a checkout at any other commit is refused, so a moved tag is never
# followed. Raise the tag and its commit together, by an ordinary PR. The clone
# URL is the forge's and caller-supplied (TRUSTED_FIRMWARE_URL, Makefile).
TRUSTED_FIRMWARE_TAG=v0.4.2-alpha
TRUSTED_FIRMWARE_COMMIT=48d7c9f4817aaef1cbdbc034ffc2d2110cf16687
# The OP-TEE QEMU fixture image the CI optee job runs the arm-trustzone harness
# in (ruling 274(9)): an agent-ci-image Infra builds, publishes and keeps,
# holding the stack prebuilt at TRUSTED_FIRMWARE_COMMIT. Pinned by digest
# (<registry>/<name>@sha256:<64 hex>); raise it with the trusted-firmware pins.
# Infra published it 2026-11-01 (tag v0.4.2-alpha-optee-4.11.0, #254 comment 184877); the optee job fails if it is emptied.
# The contract: docs/backend-conformance/engineering.md#fixture-image-contract.
# lab-string-ok: the optee job pulls this image from the lab registry by digest (ruling 274(9)); ci.yml has no registry-host source
OPTEE_FIXTURE_IMAGE=git.example.internal/agent-ci-images/go-enclave-optee-fixture@sha256:7c618b5fb7d0bcdbd0f63b15878e3653c0f46ea0d880a9c1f20fb11c7e2edbd6
