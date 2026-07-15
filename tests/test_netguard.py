from __future__ import annotations

import socket

import pytest

from app.tools.netguard import SsrfBlocked, assert_safe_outbound_url


def test_domain_resolving_to_benchmark_network_is_allowed(monkeypatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.18.0.1", 443))],
    )

    assert assert_safe_outbound_url("https://fixture.example/api") == "https://fixture.example/api"


def test_literal_benchmark_network_ip_is_blocked() -> None:
    with pytest.raises(SsrfBlocked):
        assert_safe_outbound_url("https://198.18.0.1/api")


def test_public_literal_ip_remains_allowed() -> None:
    assert assert_safe_outbound_url("https://8.8.8.8/api") == "https://8.8.8.8/api"


def test_extra_host_does_not_bypass_literal_private_ip_or_metadata() -> None:
    with pytest.raises(SsrfBlocked):
        assert_safe_outbound_url(
            "https://198.18.0.1/api",
            allow_extra_hosts={"198.18.0.1"},
        )
    with pytest.raises(SsrfBlocked):
        assert_safe_outbound_url(
            "https://169.254.169.254/latest/meta-data",
            allow_extra_hosts={"169.254.169.254"},
        )


def test_metadata_host_is_blocked() -> None:
    with pytest.raises(SsrfBlocked):
        assert_safe_outbound_url("https://169.254.169.254/latest/meta-data")


def test_domain_resolving_to_real_private_address_is_blocked(monkeypatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443))],
    )

    with pytest.raises(SsrfBlocked):
        assert_safe_outbound_url("https://private.fixture.example/api")
