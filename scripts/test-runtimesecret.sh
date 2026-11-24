#!/bin/sh
# test-runtimesecret.sh <go test flag>...: unit tests built with GOEXPERIMENT=runtimesecret.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

go=${GOCMD:-go}
proof='^TestWithAEAD_ErasesTheKeyScheduleUnderRuntimeSecret$'
gobin=$(GOEXPERIMENT='' "$go" env GOROOT)/bin/go

for t in linux/amd64=secret_erase.go linux/arm64=secret_erase.go linux/386=secret_noerase.go \
  android/amd64=secret_noerase.go android/arm64=secret_noerase.go darwin/arm64=secret_noerase.go; do
  target=${t%=*}
  want=${t#*=}
  files=$(GOEXPERIMENT=runtimesecret GOOS=${target%/*} GOARCH=${target#*/} CGO_ENABLED=0 "$gobin" list -f '{{join .GoFiles " "}}' .)
  case " $files " in
    *" $want "*) echo "erasure selection $target: $want" ;;
    *) die "GOEXPERIMENT=runtimesecret on $target does not build $want (KeyScheduleErasure would lie)" ;;
  esac
done

echo "GOEXPERIMENT=runtimesecret $gobin test $* -skip '$proof' ./..."
GOEXPERIMENT=runtimesecret "$gobin" test "$@" -skip "$proof" ./...
echo "GOEXPERIMENT=runtimesecret $gobin test -count=5 -cpu=1,2,8 -run '$proof' ."
GOEXPERIMENT=runtimesecret "$gobin" test -count=5 -cpu=1,2,8 -run "$proof" .
