# go-enclave devcontainer: one Dockerfile, the shipped stages built FROM base
# (handbook devcontainer.md §1).
#
#   tools        build-only: the pinned tools, built or downloaded into /out
#   base         the Go toolchain by digest, the C compiler -race needs, a
#                non-root user and the verified module cache; GOPROXY=off
#   toolchain    base + every tool the Makefile calls. `make build`, `make test`,
#                `make security` and `make deps-check` run here, in CI too
#                (scripts/in-toolchain-image.sh). The checkout is MOUNTED or
#                COPIED in, never baked: every gate runs in it as any non-root
#                uid, offline. `make docker-run CMD='make lint'`;
#                `make toolchain-image` prints its content-addressed tag.
#   integration  base + the source only, BAKED IN: the ONLY place the
#                integration suite runs (handbook integration-testing §4,
#                testing-guidelines). `make integration-test` builds it
#                through compose.yaml beside this file; nothing else should.
#
# Build with `make docker-build`. There is no modules stage: the one
# dependency resolves from the public proxy, so base downloads it with no forge
# credentials. GO_IMAGE keeps its default here, the pin
# build/ci/buildgates holds to go.mod, so a plain `docker build` of a stage
# builds the pinned toolchain.
#
# integration is deliberately NOT built FROM toolchain: the suite scans its
# own image (`trivy image`, devops §8), and the hardened runtime image ships
# no developer tool binaries for that scan to find. Only the tools stage's
# binaries leave it, and only into toolchain.
#
# WHAT IS IN BASE, AND WHY NOTHING ELSE IS
#
#   * The Go toolchain the module declares (go.mod: `go 1.27.3`), from the
#     official image PINNED BY DIGEST. The digest is the multi-arch index, so
#     amd64 and arm64 runners resolve the same release; a tag alone is an
#     unpinned toolchain (devops §9a: how the Go 1.27.0/swiss breakage entered
#     release builds). Alpine, per the 2026-08-20 base-image ruling.
#     Raise: `docker buildx imagetools inspect golang:<ver>-alpine<branch>` and replace
#     the tag AND the digest together, in the same change that moves go.mod.
#   * gcc + musl-dev: `-race` is the suite's concurrency oracle (the shutdown
#     sweep's waits, the admission CAS) and the race runtime requires cgo on
#     linux. The library itself is pure Go. Pinned to the Alpine 3.24 branch's
#     major.minor with `~`, which takes that branch's security rebuilds and
#     never a new compiler; an exact `=x.y.z-rN` pin stops building the day
#     Alpine supersedes the revision, which turns a distro security fix into a
#     red gate.
#   * The user `dev` (10001), and /src owned by it: CI copies the checkout in
#     with `docker cp` (scripts/in-toolchain-image.sh), which keeps an existing
#     directory's owner, and runs as 10001. A bind mount hides it.
#   * The root module's dependencies, downloaded and VERIFIED against go.sum
#     at build time into /gomodcache, so a run needs no network (GOPROXY=off).
#     A mounted GOMODCACHE replaces it whole.
#   * A build cache at /gocache pre-warmed with the race-instrumented standard
#     library, plain and FIPS 140-3 (GOFIPS140=latest), so a cold run compiles
#     only this module. Writable by every uid: the toolchain's user is
#     whoever runs it (`docker run --user <host uid>`). compose mounts a volume
#     over it; Docker seeds an empty named volume from the image, so a run
#     starts warm.
#
# FETCHING happens only at build time and only through GO_BUILD_PROXY (default
# the public proxy, then direct), passed explicitly to each step that
# downloads. The images' ENV is GOPROXY=off, so a gate or the suite that
# reaches for a module fails instead of fetching it.
#
# THE TOOLCHAIN adds, for the Makefile and scripts/:
#   * bash, make, git, curl, jq, node, and the GNU userland (coreutils, grep,
#     sed, gawk, findutils, diffutils, tar, xz) the CI runners have, so a
#     script behaves here as it does there. The base digest fixes the Alpine
#     branch, and a branch moves a package only by security rebuilds, so these
#     follow the branch rather than a revision.
#   * Every tool scripts/tool-pins.sh pins, in /usr/local/bin, installed by
#     scripts/install-tools.sh through scripts/tool.sh: the same pins, hashes
#     and verification `make lint` uses, and no second copy of either.
#     tool.sh uses a verified copy on PATH, so a gate here builds and downloads
#     nothing. gosec builds in a throwaway module against XTOOLS_VERSION: the
#     x/tools its go.mod names cannot read the export data Go 1.27 writes.
#   * build/ci/buildgates' dependencies, beside the root module's.
#   * HOME=/tmp: nothing a gate needs lives under a home directory.
#
# BOTH STAGES carry node, git, bash and tar: CI runs each stage's jobs with
# `container:` set to this image, so the runner's JavaScript actions
# (checkout, cache, upload) execute inside it (handbook ci-standard.md §2).
#
# THE INTEGRATION STAGE adds the source, BAKED IN rather than bind-mounted. On
# our runners `docker compose` reaches the HOST daemon through the job
# container's socket, so a bind-mount source is resolved on the host — where
# the checkout does not exist — and the daemon silently mounts an empty
# directory (measured on the CI runners in four repositories, 2026-08-14). The
# build context, by contrast, is sent by the client, so it is correct on a
# laptop and on a runner alike. Dockerfile.dockerignore is an ALLOWLIST of
# what any stage reads — never .git, a local.mk, a credentials file or the
# repository-local tool cache — and the stage COPYs by name only its own part
# of it, so the toolchain's inputs stay out.
#
# Both run as an unprivileged user with every capability dropped (compose.yaml
# says why each setting is what it is). Nothing here needs root at run time.
#
# There is deliberately no `# syntax=` directive: it would make every build
# pull a frontend image by a floating tag — an unpinned input, and a network
# dependency on an otherwise offline rebuild. BuildKit's built-in Dockerfile
# frontend supports everything used here, Dockerfile.dockerignore included.
#
# Every file a COPY in the tools, base or toolchain stage reads is an input of
# the toolchain's content tag (scripts/devcontainer.sh inputs); build/ci/buildgates
# fails when the two disagree.

ARG GO_IMAGE=golang:1.27.3-alpine3.24@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c
ARG GO_BUILD_PROXY=https://proxy.golang.org,direct

# ---------------------------------------------------------------------------
FROM ${GO_IMAGE} AS tools
ARG GO_BUILD_PROXY

# GOTOOLCHAIN=local: the Go tools are built by THIS toolchain, the one
# tool.sh then requires them to name. CGO_ENABLED=0: static binaries.
ENV GOTOOLCHAIN=local \
    CGO_ENABLED=0 \
    GOFLAGS=-mod=readonly

# Build-time only, and nothing of them ships: tool.sh downloads with curl and
# unpacks with tar/xz, and trusts what it fetched only through the SHA-256s
# pinned in scripts/tool-pins.sh.
RUN apk add --no-cache curl tar xz

WORKDIR /build
COPY scripts/lib.sh scripts/tool.sh scripts/tool-pins.sh scripts/install-tools.sh scripts/
RUN GOPROXY="$GO_BUILD_PROXY" sh scripts/install-tools.sh /out

# ---------------------------------------------------------------------------
FROM ${GO_IMAGE} AS base
ARG GO_BUILD_PROXY

# The toolchain in this image is the toolchain, full stop: GOTOOLCHAIN=local
# makes a go.mod asking for a newer one FAIL rather than download it.
# CGO_ENABLED=1 is for -race only (see above). The caches sit at fixed paths
# outside any home, the ones lane-verify passes (-e GOMODCACHE=/gomodcache
# -e GOCACHE=/gocache), so a mounted cache replaces the baked one.
ENV GOTOOLCHAIN=local \
    CGO_ENABLED=1 \
    GOFLAGS=-mod=readonly \
    GOMODCACHE=/gomodcache \
    GOCACHE=/gocache \
    GOTMPDIR=/tmp

# `apk upgrade` first: the base is pinned by digest for a reproducible
# toolchain, but a digest also freezes its OS packages, and the image gate
# (`trivy image --ignore-unfixed`, devops §8) correctly refuses a known-fixable
# HIGH/CRITICAL advisory in them — measured on this base: libcrypto3/libssl3
# 3.5.7-r0, fixed in 3.5.8-r0. Applying the distribution's security updates at
# build time keeps the Go toolchain pinned while the OS layer carries every
# published fix; the scan then verifies the result rather than trusting it.
RUN set -eux; \
    apk upgrade --no-cache; \
    apk add --no-cache 'gcc~15.2' 'musl-dev~1.2.6'; \
    addgroup -S -g 10001 dev; \
    adduser -S -D -H -u 10001 -G dev -h /home/dev -s /sbin/nologin dev; \
    install -d -o root -g root -m 0755 /gomodcache; \
    install -d -m 0755 -o 10001 -g 10001 /src; \
    install -d -o root -g root -m 0777 /gocache

# Dependencies first: a source-only change reuses this layer. The module
# files are copied to a scratch directory and removed. The cache is read-only
# to everyone but root, as Go leaves it; the download directory's lock files
# are the exception.
WORKDIR /build
COPY go.mod go.sum ./
# The download retries: a transient proxy error must not fail the image (m850).
RUN set -eux; \
    n=0; until GOPROXY="$GO_BUILD_PROXY" go mod download -x; do n=$((n + 1)); [ "$n" -lt 3 ] || exit 1; sleep $((n * 10)); done; \
    go mod verify; \
    chmod -R a+rX /gomodcache; \
    find /gomodcache/cache -type d -exec chmod a+w {} +

# Pre-warm the build cache: the race-instrumented standard library, in both
# FIPS configurations the suites run under. GOFIPS140 selects a different
# Go Cryptographic Module build, which is a different cache key. Then open it
# to every uid (see above).
RUN set -eux; \
    go build -race std; \
    GOFIPS140=latest go build -race std; \
    chmod -R a+rwX /gocache

WORKDIR /src
RUN rm -rf /build

# From here on, and in both images, nothing fetches a module.
ENV GOPROXY=off

# ---------------------------------------------------------------------------
FROM base AS toolchain
ARG GO_BUILD_PROXY

ENV HOME=/tmp

# safe.directory: a checkout copied or mounted in is owned by whoever ran it,
# and the releasability gates read its .git as any uid.
RUN apk add --no-cache \
        bash make git curl jq nodejs \
        coreutils grep sed gawk findutils diffutils tar xz; \
    git config --system --add safe.directory '*'

COPY --from=tools /out/ /usr/local/bin/

WORKDIR /build
COPY build/ci/buildgates/go.mod build/ci/buildgates/go.sum ./
# The download retries: a transient proxy error must not fail the image (m850).
RUN set -eux; \
    n=0; until GOPROXY="$GO_BUILD_PROXY" go mod download -x; do n=$((n + 1)); [ "$n" -lt 3 ] || exit 1; sleep $((n * 10)); done; \
    go mod verify; \
    chmod -R a+rX /gomodcache; \
    find /gomodcache/cache -type d -exec chmod a+w {} +

WORKDIR /src
RUN rm -rf /build
USER dev:dev

CMD ["go", "version"]

# ---------------------------------------------------------------------------
FROM base AS integration

# Today's integration posture, unchanged: the user `dev` with its own home,
# the source baked in and owned by root.
ENV HOME=/home/dev
RUN install -d -o dev -g dev -m 0700 /home/dev
# For the CI `container:` job's actions only (see the header); the suite's
# scripts are /bin/sh and use none of them.
RUN apk add --no-cache bash git tar nodejs
USER dev:dev
WORKDIR /src

# By name, not `COPY . .`: the context also carries the toolchain's inputs.
COPY --chown=root:root go.mod go.sum *.go ./
COPY --chown=root:root backendtest/ backendtest/
COPY --chown=root:root providertest/ providertest/
COPY --chown=root:root internal/ internal/
COPY --chown=root:root test/integration/ test/integration/
COPY --chown=root:root scripts/lib.sh scripts/coverage-gate.sh scripts/
COPY --chown=root:root build/docker/devcontainer/run-integration-tests.sh build/docker/devcontainer/

# Fail the BUILD, not the run, if the tree that arrived cannot be compiled for
# the suite — e.g. the allowlist stopped admitting a file the module needs.
# `go vet` with the tag also proves the integration files are selected by it.
RUN go vet -tags=integration ./test/integration/...
# The same for the `userns` service: the root package's test files must have
# arrived and compile under -tags=userns, or `go test` there runs nothing.
RUN go vet -tags=userns .

# A marker the suite checks, so `go test -tags=integration` run on a host
# fails saying where it must run instead of measuring the host.
ENV GO_ENCLAVE_IT_DEVCONTAINER=1

CMD ["go", "version"]
