from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _source(name: str) -> str:
    return (ROOT / "scripts" / name).read_text(encoding="utf-8")


def test_server_update_builds_before_stopping_and_backs_up_before_recreate() -> None:
    source = _source("update-server.sh")

    build = source.index('docker compose -f "$COMPOSE_FILE" build "$SERVICE"')
    stop = source.index('docker compose -f "$COMPOSE_FILE" stop -t "$GRACE" "$SERVICE"')
    backup = source.index('"$ROOT_DIR/scripts/backup-data.sh"')
    recreate = source.index(
        'docker compose -f "$COMPOSE_FILE" up -d --no-build "$SERVICE"',
        backup,
    )

    assert build < stop < backup < recreate
    assert "git pull --ff-only origin" in source
    assert "git fetch \"$SOURCE_BUNDLE\" main" in source
    assert "git reset --ff-only FETCH_HEAD" in source
    assert "restart_previous_container" in source
    assert "trap restart_previous_container EXIT" in source
    assert 'curl -fsS --max-time 5 "$HEALTH_URL"' in source


def test_server_backup_archives_the_persistent_data_volume_read_only() -> None:
    source = _source("backup-data.sh")

    assert 'eq .Destination "/app/data"' in source
    assert '"$DATA_VOLUME:/source:ro"' in source
    assert '"$BACKUP_DIR:/backup"' in source
    assert "tar -czf" in source
    assert "tar -tzf" in source
    assert "sha256sum" in source
    assert "BACKUP_KEEP" in source
