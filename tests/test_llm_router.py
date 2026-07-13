from __future__ import annotations

import random
from collections import Counter

import pytest

from app.config import LLMProviderConfig
from app.llm.client import LLMError
from app.llm.protocols import LLMResponse
from app.llm.router import AllProvidersExhaustedError, LLMRouter


class ScriptedClient:
    def __init__(self, config: LLMProviderConfig, scripts: dict[str, list[object]], calls: list[str]):
        self.config = config
        self._scripts = scripts
        self._calls = calls

    def chat(self, **_kwargs) -> LLMResponse:
        self._calls.append(self.config.name)
        script = self._scripts.setdefault(self.config.name, [])
        outcome = script.pop(0) if script else LLMResponse(content=self.config.name)
        if isinstance(outcome, Exception):
            raise outcome
        assert isinstance(outcome, LLMResponse)
        return outcome


def provider(name: str, *, weight: int = 1, enabled: bool = True, key: str | None = None):
    return LLMProviderConfig(
        name=name,
        base_url=f"https://{name.lower()}.example/v1",
        api_key=key if key is not None else f"sk-{name.lower()}-secret-123456",
        model=f"model-{name.lower()}",
        weight=weight,
        enabled=enabled,
    )


def make_router(
    providers: list[LLMProviderConfig],
    scripts: dict[str, list[object]] | None = None,
    *,
    rng: random.Random | None = None,
    callback=None,
):
    calls: list[str] = []
    scripts = scripts or {}

    def factory(*, config, usage_key=None):
        assert usage_key in (None, "task-1")
        return ScriptedClient(config, scripts, calls)

    router = LLMRouter(
        providers,
        usage_key="task-1",
        on_provider_disabled=callback,
        client_factory=factory,
        rng=rng,
    )
    return router, calls


def test_weighted_selection_favors_higher_weight() -> None:
    router, _calls = make_router(
        [provider("A", weight=9), provider("B", weight=1)],
        rng=random.Random(20260713),
    )

    counts = Counter(router.chat([{"role": "user", "content": "hi"}]).content for _ in range(2000))

    assert 1700 <= counts["A"] <= 1900
    assert 100 <= counts["B"] <= 300


class OneShotTicketRng:
    def __init__(self, ticket: int):
        self.ticket = ticket
        self.calls = 0

    def randint(self, _start: int, _end: int) -> int:
        self.calls += 1
        if self.calls > 1:
            raise AssertionError("weight must be sampled only once per chat request")
        return self.ticket


class TicketSequenceRng:
    def __init__(self, tickets: list[int]):
        self.tickets = list(tickets)

    def randint(self, _start: int, _end: int) -> int:
        if not self.tickets:
            raise AssertionError("unexpected extra weight sample")
        return self.tickets.pop(0)


def test_failure_uses_stable_ring_order_after_weighted_start() -> None:
    scripts = {
        "A": [LLMError("timeout", "A timeout")],
        "B": [LLMError("network", "B network")],
        "C": [LLMResponse(content="ok")],
    }
    router, calls = make_router(
        [provider("A", weight=50), provider("B", weight=1), provider("C", weight=1)],
        scripts,
        rng=OneShotTicketRng(1),
    )

    response = router.chat([{"role": "user", "content": "hi"}])

    assert response.content == "ok"
    assert calls == ["A", "B", "C"]


def test_auth_failure_disables_provider_and_calls_callback_once() -> None:
    disabled: list[tuple[str, str]] = []
    scripts = {
        "A": [LLMError("auth", "bad key")],
        "B": [LLMResponse(content="fallback"), LLMResponse(content="again")],
    }
    router, calls = make_router(
        [provider("A", weight=50), provider("B")],
        scripts,
        rng=TicketSequenceRng([1, 1]),
        callback=lambda name, reason: disabled.append((name, reason)),
    )

    assert router.chat([]).content == "fallback"
    assert router.chat([]).content == "again"

    assert calls == ["A", "B", "B"]
    assert router.enabled_providers == ["B"]
    assert disabled == [("A", "auth: bad key")]


def test_timeout_does_not_disable_provider() -> None:
    scripts = {
        "A": [LLMError("timeout", "slow"), LLMError("timeout", "slow again")],
        "B": [LLMResponse(content="one"), LLMResponse(content="two")],
    }
    router, calls = make_router(
        [provider("A", weight=50), provider("B")],
        scripts,
        rng=TicketSequenceRng([1, 1]),
    )

    assert router.chat([]).content == "one"
    assert router.chat([]).content == "two"

    assert calls == ["A", "B", "A", "B"]
    assert router.enabled_providers == ["A", "B"]


def test_callback_failure_does_not_block_failover() -> None:
    def broken_callback(_name, _reason):
        raise RuntimeError("persistence unavailable")

    router, calls = make_router(
        [provider("A", weight=50), provider("B")],
        {"A": [LLMError("quota", "empty")], "B": [LLMResponse(content="ok")]},
        rng=OneShotTicketRng(1),
        callback=broken_callback,
    )

    assert router.chat([]).content == "ok"
    assert calls == ["A", "B"]


def test_all_failures_preserve_structured_causes() -> None:
    router, calls = make_router(
        [provider("A", weight=50), provider("B")],
        {
            "A": [LLMError("network", "offline")],
            "B": [LLMError("rate_limit", "busy")],
        },
        rng=OneShotTicketRng(1),
    )

    with pytest.raises(AllProvidersExhaustedError) as exc_info:
        router.chat([])

    assert calls == ["A", "B"]
    assert [failure.provider_name for failure in exc_info.value.failures] == ["A", "B"]
    assert [failure.error.kind for failure in exc_info.value.failures] == ["network", "rate_limit"]
    assert "sk-a-secret" not in str(exc_info.value)


def test_failover_wraps_from_middle_and_samples_weight_once() -> None:
    rng = OneShotTicketRng(2)
    router, calls = make_router(
        [provider("A"), provider("B"), provider("C")],
        {
            "B": [LLMError("network", "B offline")],
            "C": [LLMError("network", "C offline")],
            "A": [LLMResponse(content="wrapped")],
        },
        rng=rng,
    )

    assert router.chat([]).content == "wrapped"
    assert calls == ["B", "C", "A"]
    assert rng.calls == 1


def test_failure_and_callback_redact_provider_key(caplog) -> None:
    secret = "opaque-provider-token-VERYSECRET"
    disabled: list[tuple[str, str]] = []
    leaking = LLMError(
        "auth",
        f"invalid credential {secret}",
        RuntimeError(f"original {secret}"),
        detail=f"response echoed {secret}",
    )
    router, _calls = make_router(
        [provider("A", weight=50, key=secret), provider("B")],
        {"A": [leaking], "B": [LLMError("network", "offline")]},
        rng=OneShotTicketRng(1),
        callback=lambda name, reason: disabled.append((name, reason)),
    )

    with pytest.raises(AllProvidersExhaustedError) as exc_info:
        router.chat([])

    failure = exc_info.value.failures[0]
    assert failure.error.original is None
    assert secret not in str(exc_info.value)
    assert secret not in repr(exc_info.value.errors)
    assert secret not in str(failure.error)
    assert secret not in repr(disabled)
    assert secret not in caplog.text


def test_client_initialization_error_redacts_provider_key(caplog) -> None:
    secret = "opaque-init-token-VERYSECRET"

    def factory(*, config, usage_key=None):
        if config.name == "A":
            raise RuntimeError(f"could not initialize with {secret}")
        return ScriptedClient(config, {}, [])

    router = LLMRouter(
        [provider("A", key=secret), provider("B")],
        client_factory=factory,
        rng=OneShotTicketRng(1),
    )

    assert router.enabled_providers == ["B"]
    assert secret not in caplog.text


def test_unknown_runtime_error_is_redacted_before_classification_log(caplog) -> None:
    secret = "opaque-runtime-token-VERYSECRET"
    router, _calls = make_router(
        [provider("A", key=secret)],
        {"A": [RuntimeError(f"gateway echoed {secret}")]},
        rng=OneShotTicketRng(1),
    )

    with pytest.raises(AllProvidersExhaustedError) as exc_info:
        router.chat([])

    assert secret not in str(exc_info.value)
    assert secret not in caplog.text


def test_disabled_and_keyless_providers_are_not_loaded() -> None:
    router, calls = make_router(
        [provider("A", enabled=False), provider("B", key=""), provider("C")],
        rng=OneShotTicketRng(1),
    )

    assert router.chat([]).content == "C"
    assert calls == ["C"]
