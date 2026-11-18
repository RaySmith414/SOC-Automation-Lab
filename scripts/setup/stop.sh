#!/usr/bin/env bash
# Stop the lab and remove the containers Shuffle started for workflow runs.
#
#   scripts/setup/stop.sh        stop the lab and keep the data
#   scripts/setup/stop.sh -v     stop the lab and delete the data volumes
#
# Shuffle's Orborus starts a worker container for every workflow run and the
# worker starts one container per step. They are not part of the compose
# project, so `docker compose down` does not touch them. One that is still
# running when the stack goes down would stay until it times out.
set -euo pipefail

cd "$(dirname "$0")/../.."

# Stop Orborus first so that no new worker starts while the rest shuts down.
docker compose stop shuffle-orborus >/dev/null 2>&1 || true

# Workers are named worker-<run ID>. Step containers end in _<step ID>_<run ID>.
uuid='[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
leftover="$(docker ps -a --format '{{.ID}} {{.Names}}' \
    | grep -E "^[0-9a-f]+ (worker-${uuid}(-${uuid})?|.+_${uuid}_${uuid}(-${uuid})?(-nonetwork)?)\$" || true)"
if [ -n "$leftover" ]; then
    echo "Removing containers Shuffle left from workflow runs:"
    echo "$leftover" | cut -d' ' -f2 | while read -r name; do echo "  $name"; done
    echo "$leftover" | cut -d' ' -f1 | xargs docker rm -f >/dev/null
fi

docker compose down "$@"
