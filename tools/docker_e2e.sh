#!/usr/bin/env bash
# End to end inside the image: start the web app (read-only root, no capabilities), use the API,
# restart it on the same volume to prove the data survives, run the CLI from the same image.
# Needs Docker and curl. Usage: tools/docker_e2e.sh [image]
set -euo pipefail
IMAGE="${1:-subnetplan}"
VOL="subnetplan-e2e-$$"
NAME="subnetplan-e2e-$$"
BASE=""
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true; docker volume rm -f "$VOL" >/dev/null 2>&1 || true' EXIT

start() {
  docker run -d --name "$NAME" --read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp \
    -v "$VOL":/data -p "127.0.0.1::8080" "$IMAGE" >/dev/null
  BASE="http://127.0.0.1:$(docker port "$NAME" 8080/tcp | head -1 | sed 's/.*://')"   # a free port, chosen by Docker
  for _ in $(seq 1 60); do
    curl -fsS "$BASE/api/audit" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  docker logs "$NAME"; echo "the server did not come up" >&2; return 1
}
api() { curl -fsS -H 'content-type: application/json' "$@"; }

[ "$(docker run --rm --entrypoint id "$IMAGE" -u)" != 0 ]   # not root

start
api -X POST "$BASE/api/prefixes" -d '{"cidr":"10.0.0.0/22","name":"site","status":"container"}' | tee /dev/stderr | grep -q '"id":1'
api -X POST "$BASE/api/prefixes/1/allocate" -d '{"name":"office","hosts":200}' | grep -q '"cidr":"10.0.0.0/24"'
api -X POST "$BASE/api/plan" -d '{"network":"10.9.0.0/24","requests":[{"name":"a","hosts":100},{"name":"b","hosts":50}]}' | grep -q '10.9.0.128/26'
curl -fsS -D - -o /dev/null "$BASE/" | tr -d '\r' | grep -qi '^content-security-policy: default-src .self.'
curl -fsS "$BASE/" | grep -q '<title>'
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/static/../api.py")" = 404 ]
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' "$BASE/api/prefixes" -d '{"cidr":"10.0.0.0/33"}')" = 422 ]
[ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME")" != "unhealthy" ]

# restart on the same volume: the data is still there
docker rm -f "$NAME" >/dev/null
start
api "$BASE/api/prefixes" | grep -q '10.0.0.0/24'
api "$BASE/api/audit" | grep -q '^\[\]$'
docker rm -f "$NAME" >/dev/null

# the CLI in the same image, on the same volume
docker run --rm --read-only --cap-drop ALL -v "$VOL":/data "$IMAGE" ipam --db /data/ipam.db ls | tee /dev/stderr | grep -q office
docker run --rm "$IMAGE" plan 10.0.0.0/24 --need lan=100 --need wifi=50 | grep -q '10.0.0.128/26'
echo "docker end-to-end: OK"
