from __future__ import annotations

from datetime import datetime, timedelta, timezone

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


def test_fofa_key_config_defaults_official_base_url() -> None:
    item = FofaKeyConfig(name="A", key="secret-a")

    assert item.base_url == "https://fofa.info"


def test_fofa_key_config_accepts_private_http_path() -> None:
    item = FofaKeyConfig(
        name="Private",
        key="secret-a",
        base_url="  http://fofa.internal:8080/api/v1  ",
    )

    assert item.base_url == "http://fofa.internal:8080/api/v1"


def test_fofa_key_config_accepts_private_https_path() -> None:
    item = FofaKeyConfig(
        name="Private HTTPS",
        key="secret-a",
        base_url="https://fofa.internal/private/api",
    )

    assert item.base_url == "https://fofa.internal/private/api"


@pytest.mark.parametrize(
    "base_url",
    [
        "https://user:password@fofa.example",
        "https://fofa.example/api?token=secret",
        "https://fofa.example/api#fragment",
        "https://fofa.example:bad/api",
        "https://fofa.example:99999/api",
        "file:///tmp/fofa",
        "//fofa.example/api",
        "https:///api",
    ],
)
def test_fofa_key_config_rejects_unsafe_base_url(base_url: str) -> None:
    with pytest.raises(ValidationError):
        FofaKeyConfig(name="A", key="secret-a", base_url=base_url)


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


def test_fofa_key_config_repr_hides_key() -> None:
    secret = "fofa-secret-that-must-not-leak"

    item = FofaKeyConfig(name="A", key=secret)

    assert secret not in repr(item)
    assert secret not in str(item)


@pytest.mark.parametrize(
    "cooldown",
    [
        datetime(2026, 7, 16, 1, 0),
        "2026-07-16T01:00:00",
    ],
)
def test_fofa_key_config_rejects_naive_cooldown(cooldown) -> None:
    with pytest.raises(ValidationError):
        FofaKeyConfig(name="A", key="secret-a", cooldown_until=cooldown)


def test_fofa_key_config_normalizes_cooldown_to_utc() -> None:
    item = FofaKeyConfig(
        name="A",
        key="secret-a",
        cooldown_until=datetime(
            2026, 7, 16, 1, 0, tzinfo=timezone(timedelta(hours=8))
        ),
    )

    assert item.cooldown_until == datetime(2026, 7, 15, 17, 0, tzinfo=timezone.utc)
    assert item.cooldown_until.tzinfo is timezone.utc


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
