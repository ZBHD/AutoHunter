from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.config import FofaKeyConfig


def test_fofa_key_config_normalizes_name_and_runtime_defaults() -> None:
    item = FofaKeyConfig(name="  主账号  ", key="secret-a")

    assert item.name == "主账号"
    assert item.enabled is True
    assert item.runtime_state == "ready"
    assert item.failure_kind == ""
    assert item.failure_count == 0
    assert item.cooldown_until is None


@pytest.mark.parametrize("state", ["unknown", "disabled", "cooling"])
def test_fofa_key_config_rejects_unknown_runtime_state(state: str) -> None:
    with pytest.raises(ValidationError):
        FofaKeyConfig(name="A", key="secret-a", runtime_state=state)


def test_fofa_key_config_accepts_utc_cooldown() -> None:
    cooldown = datetime(2026, 7, 16, 1, 0, tzinfo=timezone.utc)
    item = FofaKeyConfig(
        name="A",
        key="secret-a",
        runtime_state="rate_limited",
        failure_kind="rate_limit",
        failure_count=1,
        cooldown_until=cooldown,
    )

    assert item.cooldown_until == cooldown


@pytest.mark.parametrize("name", ["", "  ", "A/B", r"A\B", " Order ", "ORDER"])
def test_fofa_key_config_rejects_invalid_name(name: str) -> None:
    with pytest.raises(ValidationError):
        FofaKeyConfig(name=name, key="secret-a")


def test_fofa_key_config_rejects_negative_failure_count() -> None:
    with pytest.raises(ValidationError):
        FofaKeyConfig(name="A", key="secret-a", failure_count=-1)


def test_fofa_key_config_rejects_unknown_failure_kind() -> None:
    with pytest.raises(ValidationError):
        FofaKeyConfig(name="A", key="secret-a", failure_kind="unknown")
