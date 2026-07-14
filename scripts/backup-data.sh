#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE="${SERVICE:-autohunter}"
BACKUP_DIR="${BACKUP_DIR:-$ROOT_DIR/backups}"
BACKUP_KEEP="${BACKUP_KEEP:-10}"

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR" 2>/dev/null || true

if ! docker inspect "$SERVICE" >/dev/null 2>&1; then
  printf '%s\n' "No $SERVICE container exists; data backup is not needed yet."
  exit 0
fi

DATA_VOLUME="$(docker inspect "$SERVICE" --format '{{range .Mounts}}{{if eq .Destination "/app/data"}}{{.Name}}{{end}}{{end}}')"
if [ -z "$DATA_VOLUME" ]; then
  printf '%s\n' "The $SERVICE container has no /app/data volume; refusing to continue." >&2
  exit 1
fi

IMAGE="$(docker inspect "$SERVICE" --format '{{.Config.Image}}')"
[ -n "$IMAGE" ] || IMAGE="autohunter:latest"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARCHIVE="autohunter-data-${STAMP}.tar.gz"

docker run --rm --pull=never \
  -e "ARCHIVE=$ARCHIVE" \
  -v "$DATA_VOLUME:/source:ro" \
  -v "$BACKUP_DIR:/backup" \
  "$IMAGE" sh -ec '
    tar -czf "/backup/${ARCHIVE}" -C /source .
    tar -tzf "/backup/${ARCHIVE}" >/dev/null
  '

sha256sum "$BACKUP_DIR/$ARCHIVE" > "$BACKUP_DIR/$ARCHIVE.sha256"
chmod 600 "$BACKUP_DIR/$ARCHIVE" "$BACKUP_DIR/$ARCHIVE.sha256" 2>/dev/null || true

if [ -f "$ROOT_DIR/.env" ]; then
  cp "$ROOT_DIR/.env" "$BACKUP_DIR/autohunter-env-${STAMP}.backup"
  chmod 600 "$BACKUP_DIR/autohunter-env-${STAMP}.backup" 2>/dev/null || true
fi

find "$BACKUP_DIR" -maxdepth 1 -type f -name 'autohunter-data-*.tar.gz' \
  -printf '%T@ %p\n' | sort -rn | tail -n +$((BACKUP_KEEP + 1)) \
  | cut -d' ' -f2- | while IFS= read -r old_archive; do
      [ -n "$old_archive" ] || continue
      rm -f -- "$old_archive" "$old_archive.sha256"
    done

printf '%s\n' "Created and verified $BACKUP_DIR/$ARCHIVE"
