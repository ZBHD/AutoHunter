#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
SERVICE="${SERVICE:-autohunter}"
GRACE="${AUTOHUNTER_UPDATE_STOP_GRACE:-60}"
PORT="${AUTOHUNTER_HOST_PORT:-$(grep -E '^AUTOHUNTER_HOST_PORT=' .env 2>/dev/null | tail -1 | cut -d= -f2)}"
[ -n "$PORT" ] || PORT="18800"
HEALTH_URL="${AUTOHUNTER_HEALTH_URL:-http://127.0.0.1:${PORT}/health}"
IMAGE_TAG="${IMAGE_TAG:-autohunter:latest}"

cd "$ROOT_DIR"

if ! git diff --quiet || ! git diff --cached --quiet; then
  printf '%s\n' "Refusing to update with uncommitted server changes." >&2
  exit 1
fi

git fetch origin main
git pull --ff-only origin main
docker compose -f "$COMPOSE_FILE" config --quiet

PREVIOUS_IMAGE_ID="$(docker inspect "$SERVICE" --format '{{.Image}}' 2>/dev/null || true)"
STOPPED=0

restart_previous_container() {
  if [ "$STOPPED" -eq 1 ]; then
    docker compose -f "$COMPOSE_FILE" up -d --no-build "$SERVICE" >/dev/null 2>&1 || true
  fi
}
trap restart_previous_container EXIT

# Build while the current container is still serving traffic. A failed build
# therefore leaves the running release untouched.
docker compose -f "$COMPOSE_FILE" build "$SERVICE"
docker compose -f "$COMPOSE_FILE" stop -t "$GRACE" "$SERVICE"
STOPPED=1

"$ROOT_DIR/scripts/backup-data.sh"

docker compose -f "$COMPOSE_FILE" up -d --no-build "$SERVICE"
STOPPED=0

ready=0
for _ in $(seq 1 30); do
  if curl -fsS --max-time 5 "$HEALTH_URL" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 2
done

if [ "$ready" -ne 1 ]; then
  printf '%s\n' "New release did not become healthy; attempting image rollback." >&2
  docker compose -f "$COMPOSE_FILE" logs --tail=120 "$SERVICE" >&2 || true
  if [ -n "$PREVIOUS_IMAGE_ID" ]; then
    docker image tag "$PREVIOUS_IMAGE_ID" "$IMAGE_TAG"
    docker compose -f "$COMPOSE_FILE" up -d --no-build --force-recreate "$SERVICE"
    for _ in $(seq 1 30); do
      if curl -fsS --max-time 5 "$HEALTH_URL" >/dev/null 2>&1; then
        printf '%s\n' "Previous release restored successfully." >&2
        exit 1
      fi
      sleep 2
    done
  fi
  exit 1
fi

docker compose -f "$COMPOSE_FILE" ps "$SERVICE"
printf '%s\n' "Server update completed; persistent data remains in the Docker volume."
