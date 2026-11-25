# shellcheck shell=sh disable=SC2034
# tool-pins.sh: the pin of every analysis tool, read by the Makefile and install-tools.sh; NAME=value lines only, comments on their own lines.
GOLANGCI_VERSION=v2.15.0
# Raise with `go list -m github.com/securego/gosec/v2@latest`.
GOSEC_VERSION=v2.30.0
# gosec is built against this x/tools: the latest release, never older than the
# v0.52.0 gosec's go.mod names. An old x/tools such as v0.49.0 cannot read the
# export data (version 5) Go 1.27 writes, so every import fails to type-check.
XTOOLS_VERSION=v0.53.0
# Raise with `go list -m golang.org/x/vuln@latest`.
GOVULNCHECK_VERSION=v1.10.0
# Raise with `go list -m github.com/rhysd/actionlint@latest`.
ACTIONLINT_VERSION=v1.7.12
#
# trivy and shellcheck are release archives pinned by four SHA-256s each: the
# archive per Linux arch and the binary inside it (see scripts/tool.sh).
# Raise a version and all four of its hashes together, or not at all.
#
# trivy's archive hashes are from the release's trivy_0.76.2_checksums.txt.
TRIVY_VERSION=v0.76.2
TRIVY_SHA256_LINUX_AMD64=bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf
TRIVY_SHA256_LINUX_ARM64=ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3
TRIVY_BIN_SHA256_LINUX_AMD64=6a972c69606c7b3ea4c6bdcc6fc9332ea9ad38381624310c1e85cc77345909f3
TRIVY_BIN_SHA256_LINUX_ARM64=7844c3851b28470b6d7f0975fa0b3262c5b2272c9a54a91f522801bb8926f51f
# The shellcheck pin (actionlint and lint-scripts). Upstream publishes no
# checksums; these are the SHA-256s of the v0.11.0 release archives and of the
# binaries inside them, computed from the downloads.
SHELLCHECK_VERSION=v0.11.0
SHELLCHECK_SHA256_LINUX_AMD64=8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198
SHELLCHECK_SHA256_LINUX_ARM64=12b331c1d2db6b9eb13cfca64306b1b157a86eb69db83023e261eaa7e7c14588
SHELLCHECK_BIN_SHA256_LINUX_AMD64=4da528ddb3a4d1b7b24a59d4e16eb2f5fd960f4bd9a3708a15baddbdf1d5a55b
SHELLCHECK_BIN_SHA256_LINUX_ARM64=127f13925eadd52c341bca0ebaf9ab0dbd78c6468f30a8f262a528bf8de47546
# The OP-TEE fixture's trusted-firmware tag and the commit it peels to; raise both together.
TRUSTED_FIRMWARE_TAG=v0.4.2-alpha
TRUSTED_FIRMWARE_COMMIT=e0ae83d062b45dccc0e4cf08c87bf6def80a946c
# The OP-TEE QEMU fixture image, pinned by manifest digest; see docs/backend-conformance/engineering.md#fixture-image-contract.
OPTEE_FIXTURE_IMAGE=ghcr.io/jeremyhahn/go-enclave-optee-fixture@sha256:107175c7463eddbe14bd9feca741e9ba6b29a18d5412cd04e92bdbf7a7d6a012
