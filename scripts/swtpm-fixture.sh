#!/bin/sh
# swtpm-fixture.sh: run backends/tpm's swtpm-tagged tests against a throwaway swtpm, failing when swtpm is absent.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

go=${GOCMD:-go}
port=${SWTPM_PORT:-2321}
ctrl=${SWTPM_CTRL_PORT:-2322}
module=backends/tpm

for p in "$port" "$ctrl"; do
  case $p in
    '' | *[!0-9]* | 0*) die "port '$p' is not a port number; set SWTPM_PORT and SWTPM_CTRL_PORT to 1-65535" ;;
  esac
  [ "${#p}" -le 5 ] && [ "$p" -le 65535 ] || die "port '$p' is out of range; set SWTPM_PORT and SWTPM_CTRL_PORT to 1-65535"
done
[ "$port" != "$ctrl" ] || die "SWTPM_PORT and SWTPM_CTRL_PORT are both $port; the command and control ports must differ"
command -v swtpm >/dev/null 2>&1 || die "swtpm is not on PATH; install swtpm and swtpm-tools (apt install swtpm swtpm-tools) to run the TPM conformance suite"
command -v swtpm_ioctl >/dev/null 2>&1 || die "swtpm_ioctl is not on PATH; install swtpm-tools (apt install swtpm-tools) to run the TPM conformance suite"
[ -f "$module/go.mod" ] || die "no $module/go.mod; run from the repository root"

state=$(mktemp -d "${TMPDIR:-/tmp}/go-enclave-swtpm.XXXXXX")
pid=
trap 'if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi; rm -rf "$state"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

swtpm socket --tpm2 \
  --tpmstate dir="$state" \
  --server type=tcp,port="$port",bindaddr=127.0.0.1 \
  --ctrl type=tcp,port="$ctrl",bindaddr=127.0.0.1 \
  --flags not-need-init,startup-clear \
  --log file="$state/swtpm.log",level=1 &
pid=$!

# The TPM answers once the control port returns the established flag.
n=0
until swtpm_ioctl --tcp "127.0.0.1:$ctrl" -g >/dev/null 2>&1; do
  if ! kill -0 "$pid" 2>/dev/null; then
    pid=
    cat "$state/swtpm.log" >&2 2>/dev/null || true
    die "swtpm exited before it answered (is port $port or $ctrl in use?)"
  fi
  n=$((n + 1))
  [ "$n" -lt 30 ] || die "swtpm did not answer on 127.0.0.1:$ctrl within 30 s"
  sleep 1
done
echo "swtpm on 127.0.0.1:$port (control $ctrl), state $state"

rc=0
(cd "$module" && GO_ENCLAVE_SWTPM="tcp:127.0.0.1:$port" "$go" test -race -count=1 -tags swtpm -run 'OnSWTPM' -v ./...) || rc=$?
exit "$rc"
