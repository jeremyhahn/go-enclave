# go-enclave devcontainer: the ONLY place the integration suite runs
# (handbook integration-testing §4, testing-guidelines). `make integration-test`
# builds it through compose.yaml beside this file; nothing else should.
#
# WHAT IS IN IT, AND WHY NOTHING ELSE IS
#
#   * The Go toolchain the module declares (go.mod: `go 1.27.0`), from the
#     official image PINNED BY DIGEST. The digest is the multi-arch index, so
#     amd64 and arm64 runners resolve the same release; a tag alone is an
#     unpinned toolchain (devops §9a: how the Go 1.27.0/swiss breakage entered
#     release builds). Alpine, per the 2026-08-20 base-image ruling.
#     Raise: `docker buildx imagetools inspect golang:<ver>-alpine` and replace
#     the tag AND the digest together, in the same change that moves go.mod.
#   * gcc + musl-dev, and nothing more: `-race` is the suite's concurrency
#     oracle (the shutdown sweep's waits, the admission CAS) and the race
#     runtime requires cgo on linux. The library itself is pure Go. Pinned to
#     the Alpine 3.24 branch's major.minor with `~`, which takes that branch's
#     security rebuilds and never a new compiler; an exact `=x.y.z-rN` pin
#     stops building the day Alpine supersedes the revision, which turns a
#     distro security fix into a red integration gate.
#   * The module's dependencies, downloaded and VERIFIED against go.sum at
#     build time, so a run needs no network (compose runs it with
#     network_mode: none and GOPROXY=off).
#   * A build cache pre-warmed with the race-instrumented standard library,
#     plain and FIPS 140-3 (GOFIPS140=latest), so a cold run compiles only
#     this module. compose mounts a fresh per-run volume over the cache path;
#     Docker seeds an empty named volume from the image, so every run starts
#     warm AND isolated.
#   * The source, BAKED IN rather than bind-mounted. On our runners `docker
#     compose` reaches the HOST daemon through the job container's socket, so
#     a bind-mount source is resolved on the host — where the checkout does not
#     exist — and the daemon silently mounts an empty directory (measured on
#     the CI runners in four repositories, 2026-08-14). The build context, by
#     contrast, is sent by the client, so it is correct on a laptop and on a
#     runner alike. Dockerfile.dockerignore is an ALLOWLIST: only the module's
#     Go sources and the integration suite enter the image — never .git, a
#     local.mk, a credentials file or the repository-local tool cache.
#
# It runs as an unprivileged user with every capability dropped (compose.yaml
# says why each setting is what it is). Nothing here needs root at run time.
#
# There is deliberately no `# syntax=` directive: it would make every build
# pull a frontend image by a floating tag — an unpinned input, and a network
# dependency on an otherwise offline rebuild. BuildKit's built-in Dockerfile
# frontend supports everything used here, Dockerfile.dockerignore included.

ARG GO_IMAGE=golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc

FROM ${GO_IMAGE}

# The toolchain in this image is the toolchain, full stop: GOTOOLCHAIN=local
# makes a go.mod asking for a newer one FAIL rather than download it.
# CGO_ENABLED=1 is for -race only (see above).
ENV GOTOOLCHAIN=local \
    CGO_ENABLED=1 \
    GOFLAGS=-mod=readonly \
    GOPATH=/home/dev/go \
    GOMODCACHE=/home/dev/go/pkg/mod \
    GOCACHE=/home/dev/.cache/go-build \
    GOTMPDIR=/tmp \
    HOME=/home/dev

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
    install -d -o dev -g dev -m 0700 /home/dev /home/dev/go /home/dev/.cache /home/dev/.cache/go-build; \
    install -d -o root -g root -m 0755 /src

USER dev:dev
WORKDIR /src

# Dependencies first, so a source-only change reuses this layer — the build is
# offline from here on whenever go.mod and go.sum are unchanged.
COPY --chown=root:root go.mod go.sum ./
RUN set -eux; \
    go mod download -x; \
    go mod verify

# Pre-warm the build cache: the race-instrumented standard library, in both
# FIPS configurations the suite runs under. GOFIPS140 selects a different
# Go Cryptographic Module build, which is a different cache key.
RUN set -eux; \
    go build -race std; \
    GOFIPS140=latest go build -race std

COPY --chown=root:root . .

# Fail the BUILD, not the run, if the tree that arrived cannot be compiled for
# the suite — e.g. the allowlist stopped admitting a file the module needs.
# `go vet` with the tag also proves the integration files are selected by it.
RUN go vet -tags=integration ./test/integration/...

# A marker the suite checks, so `go test -tags=integration` run on a host
# fails saying where it must run instead of measuring the host.
ENV GO_ENCLAVE_IT_DEVCONTAINER=1

CMD ["go", "version"]
