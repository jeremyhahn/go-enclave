# go-enclave devcontainer stages: tools (build-only), base (pinned Go, verified module cache, non-root, GOPROXY off), toolchain (every pinned tool), integration (source baked in).
# No syntax directive: it would pull an unpinned frontend image.

ARG GO_IMAGE=golang:1.27.4-alpine3.24@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf

# The module proxy is the BuildKit secret goproxy, never a build argument, so it stays out of the image history.

# ---------------------------------------------------------------------------
FROM ${GO_IMAGE} AS tools

# Tools are built by this toolchain, statically.
ENV GOTOOLCHAIN=local \
    CGO_ENABLED=0 \
    GOFLAGS=-mod=readonly

# Build-time only, and nothing of them ships: tool.sh downloads with curl and
# unpacks with tar/xz, and trusts what it fetched only through the SHA-256s
# pinned in scripts/tool-pins.sh.
RUN apk add --no-cache curl tar xz

WORKDIR /build
COPY scripts/lib.sh scripts/tool.sh scripts/tool-pins.sh scripts/install-tools.sh scripts/
RUN --mount=type=secret,id=goproxy set -eu; \
    proxy=https://proxy.golang.org; [ ! -s /run/secrets/goproxy ] || proxy=$(cat /run/secrets/goproxy); \
    GOPROXY="$proxy" sh scripts/install-tools.sh /out

# ---------------------------------------------------------------------------
FROM ${GO_IMAGE} AS base

# GOTOOLCHAIN=local refuses a newer toolchain; CGO is for -race only; caches sit at fixed paths a mount can replace.
ENV GOTOOLCHAIN=local \
    CGO_ENABLED=1 \
    GOFLAGS=-mod=readonly \
    GOMODCACHE=/gomodcache \
    GOCACHE=/gocache \
    GOTMPDIR=/tmp

# apk upgrade applies distribution security fixes to the digest-pinned base.
RUN set -eux; \
    apk upgrade --no-cache; \
    apk add --no-cache 'gcc~15.2' 'musl-dev~1.2.6'; \
    addgroup -S -g 10001 dev; \
    adduser -S -D -H -u 10001 -G dev -h /home/dev -s /sbin/nologin dev; \
    install -d -o root -g root -m 0755 /gomodcache; \
    install -d -m 0755 -o 10001 -g 10001 /src; \
    install -d -o root -g root -m 0777 /gocache

# Dependencies first, so a source-only change reuses this layer.
WORKDIR /build
COPY go.mod go.sum ./
# The download retries: a transient proxy error must not fail the image (m850).
RUN --mount=type=secret,id=goproxy set -eux; \
    proxy=https://proxy.golang.org; [ ! -s /run/secrets/goproxy ] || proxy=$(cat /run/secrets/goproxy); \
    n=0; until GOPROXY="$proxy" go mod download -x; do n=$((n + 1)); [ "$n" -lt 3 ] || exit 1; sleep $((n * 10)); done; \
    go mod verify; \
    chmod -R a+rX /gomodcache; \
    find /gomodcache/cache -type d -exec chmod a+w {} +

# Pre-warm the race-instrumented standard library in both FIPS configurations, then open the cache to every uid.
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

ENV HOME=/tmp

# safe.directory: a checkout copied or mounted in is owned by whoever ran it,
# and the releasability gates read its .git as any uid.
RUN apk add --no-cache \
        bash make git curl jq nodejs python3 \
        coreutils grep sed gawk findutils diffutils tar xz; \
    git config --system --add safe.directory '*'

COPY --from=tools /out/ /usr/local/bin/

WORKDIR /build
COPY build/ci/buildgates/go.mod build/ci/buildgates/go.sum ./
# The download retries: a transient proxy error must not fail the image (m850).
RUN --mount=type=secret,id=goproxy set -eux; \
    proxy=https://proxy.golang.org; [ ! -s /run/secrets/goproxy ] || proxy=$(cat /run/secrets/goproxy); \
    n=0; until GOPROXY="$proxy" go mod download -x; do n=$((n + 1)); [ "$n" -lt 3 ] || exit 1; sleep $((n * 10)); done; \
    go mod verify; \
    chmod -R a+rX /gomodcache; \
    find /gomodcache/cache -type d -exec chmod a+w {} +

# The backend modules' dependencies, through the goproxy secret; GONOSUMDB skips only the root for this RUN.
WORKDIR /build/backends/armtrustzone
COPY backends/armtrustzone/go.mod backends/armtrustzone/go.sum ./
RUN --mount=type=secret,id=goproxy set -eu; \
    proxy=https://proxy.golang.org; [ ! -s /run/secrets/goproxy ] || proxy=$(cat /run/secrets/goproxy); \
    n=0; until GOPROXY="$proxy" GONOSUMDB=github.com/jeremyhahn/go-enclave go mod download; do n=$((n + 1)); [ "$n" -lt 3 ] || exit 1; sleep $((n * 10)); done; \
    GONOSUMDB=github.com/jeremyhahn/go-enclave go mod verify; \
    chmod -R a+rX /gomodcache; \
    find /gomodcache/cache -type d -exec chmod a+w {} +
# The TPM backend downloads all: go mod tidy there loads go-tpm's simulator
# test dependency, which the bare download leaves out of the cache.
WORKDIR /build/backends/tpm
COPY backends/tpm/go.mod backends/tpm/go.sum ./
RUN --mount=type=secret,id=goproxy set -eu; \
    proxy=https://proxy.golang.org; [ ! -s /run/secrets/goproxy ] || proxy=$(cat /run/secrets/goproxy); \
    n=0; until GOPROXY="$proxy" GONOSUMDB=github.com/jeremyhahn/go-enclave go mod download all; do n=$((n + 1)); [ "$n" -lt 3 ] || exit 1; sleep $((n * 10)); done; \
    GONOSUMDB=github.com/jeremyhahn/go-enclave go mod verify; \
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
# Packages for the CI container job's actions; APK_INDEX_SUM busts the cache when the Alpine index changes.
ARG APK_INDEX_SUM
RUN set -eux; \
    apk upgrade --no-cache; \
    apk add --no-cache bash git tar nodejs
USER dev:dev
WORKDIR /src

# By name, not `COPY . .`: the context also carries the toolchain's inputs.
COPY --chown=root:root go.mod go.sum *.go ./
COPY --chown=root:root backendtest/ backendtest/
COPY --chown=root:root providertest/ providertest/
COPY --chown=root:root internal/ internal/
COPY --chown=root:root test/integration/ test/integration/
COPY --chown=root:root test/internal/ test/internal/
COPY --chown=root:root scripts/lib.sh scripts/coverage-gate.sh scripts/
COPY --chown=root:root build/docker/devcontainer/run-integration-tests.sh build/docker/devcontainer/

# Fail the build if the tree cannot compile for the suite; vet with the tag proves the files are selected.
RUN go vet -tags=integration ./test/integration/...
# The same for the `userns` service: the root package's test files must have
# arrived and compile under -tags=userns, or `go test` there runs nothing.
RUN go vet -tags=userns .

# A marker the suite checks, so `go test -tags=integration` run on a host
# fails saying where it must run instead of measuring the host.
ENV GO_ENCLAVE_IT_DEVCONTAINER=1

CMD ["go", "version"]
