#!/usr/bin/env bash
# Check that every service in the core stack answers. Exit code 0 means all of them do.
#
#   scripts/setup/smoke_test.sh [seconds to wait per service, default 600]
set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1
wait_seconds="${1:-600}"
failed=0

check() {  # check <name> <url> [text expected in the body]. Without text, HTTP 200 is enough.
    local name="$1" url="$2" expect="${3:-}" deadline=$((SECONDS + wait_seconds)) body=""
    while [ "$SECONDS" -lt "$deadline" ]; do
        if body="$(curl -fsS --max-time 10 "$url" 2>/dev/null)" && grep -q -- "$expect" <<<"$body"; then
            printf 'ok    %-18s %s\n' "$name" "$url"
            return 0
        fi
        sleep 5
    done
    printf 'FAIL  %-18s %s (no HTTP 200 answer%s within %ss)\n' "$name" "$url" \
        "${expect:+ containing \"$expect\"}" "$wait_seconds"
    failed=1
}

check "TheHive"          "http://127.0.0.1:9000/api/v1/status/public" '"version"'
check "Cortex"           "http://127.0.0.1:9001/api/status"          '"versions"'
# Shuffle answers its health route with an empty body once it can reach its database.
check "Shuffle backend"  "http://127.0.0.1:5001/api/v1/_ah/health"
check "Shuffle frontend" "http://127.0.0.1:3001/"                    '<'

echo
docker compose ps --format '{{.Service}}: {{.State}} {{.Health}}'

for service in cassandra elasticsearch shuffle-opensearch thehive cortex; do
    health="$(docker compose ps --format '{{.Health}}' "$service" 2>/dev/null)"
    if [ "$health" != "healthy" ]; then
        echo "FAIL  $service is ${health:-not running}"
        failed=1
    fi
done
for service in shuffle-backend shuffle-frontend shuffle-orborus; do
    state="$(docker compose ps --format '{{.State}}' "$service" 2>/dev/null)"
    if [ "$state" != "running" ]; then
        echo "FAIL  $service is ${state:-not running}"
        failed=1
    fi
done

[ "$failed" -eq 0 ] && echo && echo "All services answer."
exit "$failed"
