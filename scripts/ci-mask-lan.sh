#!/usr/bin/env bash
# ci-mask-lan.sh: prints ::add-mask:: for every internal host in the runner's cache, proxy and *_REGISTRY variables.
set -euo pipefail

private() {
	case $1 in
	10.* | 192.168.* | 172.1[6-9].* | 172.2[0-9].* | 172.3[01].*) return 0 ;;
	'' | direct | off) return 1 ;;
	*.internal | *.lan | *.local | *.localdomain | *.home.arpa | *.corp) return 0 ;;
	*.*) return 1 ;;
	esac
	return 0
}

for v in $(compgen -e); do
	case $v in
	DEVCACHE_* | GOPROXY | *_REGISTRY | GITHUB_SERVER_URL) ;;
	*) continue ;;
	esac
	IFS='|, ' read -ra entries <<<"${!v}"
	for entry in "${entries[@]}"; do
		hostport=${entry#*://}
		hostport=${hostport%%/*}
		host=${hostport%%:*}
		private "$host" || continue
		echo "::add-mask::$entry"
		[ "$hostport" = "$entry" ] || echo "::add-mask::$hostport"
		[ "$host" = "$hostport" ] || echo "::add-mask::$host"
	done
done
