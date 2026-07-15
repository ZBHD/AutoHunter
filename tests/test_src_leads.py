from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from app.agents.src_leads import (
    Lead,
    SrcCandidate,
    finalize_leads,
    lead_key,
    merge_candidate,
    resolve_lead,
)


def _candidate(
    *,
    kind: str = "endpoint",
    endpoint_key: str = "GET https://a.test/api",
    value: str = "/api",
    method: str = "GET",
    parameter: str = "",
    location: str = "path",
    status_code: int | None = 200,
    confidence: float = 0.8,
    priority: int = 8,
    reason: str = "katana",
) -> SrcCandidate:
    return SrcCandidate(
        kind,
        endpoint_key,
        value,
        method,
        parameter,
        location,
        status_code,
        confidence,
        priority,
        reason,
    )


def test_candidate_normalizes_and_bounds_identity_fields() -> None:
    candidate = _candidate(
        kind=" PARAMETER ",
        endpoint_key="  get   https://A.TEST/search?q=secret  ",
        value=" https://A.TEST/search?q=secret ",
        method=" get ",
        parameter=" q ",
        location=" QUERY ",
        status_code=999,
        confidence=4.2,
        priority=99,
        reason=" arjun " + "x" * 300,
    )

    assert candidate.kind == "parameter"
    assert candidate.method == "GET"
    assert candidate.location == "query"
    assert candidate.endpoint_key == "GET https://a.test/search?q="
    assert candidate.value == "https://a.test/search?q="
    assert candidate.status_code is None
    assert candidate.confidence == 1.0
    assert candidate.priority == 10
    assert len(candidate.reason) <= 160
    with pytest.raises(FrozenInstanceError):
        candidate.value = "changed"  # type: ignore[misc]


def test_candidate_redacts_malformed_and_scheme_relative_urls() -> None:
    secret = "TOPSECRET"
    malformed = _candidate(
        endpoint_key=f"GET https://user:pass@a.test:bad/path?token={secret}",
        value=f"https://user:pass@a.test:bad/path?token={secret}",
    )
    relative = _candidate(
        endpoint_key=f"GET //user:pass@a.test/path?token={secret}",
        value=f"//user:pass@a.test/path?token={secret}",
    )

    for candidate in (malformed, relative):
        assert secret not in repr(candidate)
        assert "user:pass" not in repr(candidate)
        assert "token=" in candidate.value
        assert candidate.value.endswith("?token=")


def test_candidate_parses_before_bounding_long_userinfo() -> None:
    secret = "LONGSECRET"
    userinfo = "u" * 240
    candidate = _candidate(
        value=f"https://{userinfo}:pass@a.test/path?token={secret}",
    )

    assert candidate.value == "https://a.test/path?token="
    assert len(candidate.value) <= 160
    assert secret not in repr(candidate)
    assert "pass@" not in repr(candidate)


def test_method_prefixed_value_is_sanitized_before_bounding() -> None:
    secret = "METHODSECRET"
    candidate = _candidate(
        value=f"GET https://user:pass@a.test/path?token={secret}",
    )

    assert candidate.value == "https://a.test/path?token="
    assert secret not in repr(candidate)
    assert "user:pass" not in repr(candidate)


def test_bare_userinfo_is_removed_from_relative_url_values() -> None:
    candidate = _candidate(value="user:pass@a.test/path?token=BARESECRET")

    assert candidate.value == "a.test/path?token="
    assert "user:pass" not in repr(candidate)
    assert "BARESECRET" not in repr(candidate)


@pytest.mark.parametrize(
    "value",
    [
        "https:user:pass@host/path?token=OPAQUESECRET",
        "https:////user:pass@host/path?token=SLASHSECRET",
    ],
)
def test_opaque_scheme_authority_is_sanitized(value: str) -> None:
    candidate = _candidate(value=value)

    assert candidate.value == "https://host/path?token="
    assert "user:pass" not in repr(candidate)
    assert "SECRET" not in repr(candidate)


@pytest.mark.parametrize(
    "value",
    [
        "https:/user:pass@host/path?token=ONESLASHSECRET",
        "GET https:/user:pass@host/path?token=METHODSLASHSECRET",
    ],
)
def test_single_slash_opaque_authority_is_sanitized(value: str) -> None:
    candidate = _candidate(value=value)

    assert candidate.value == "https://host/path?token="
    assert "user:pass" not in repr(candidate)
    assert "SECRET" not in repr(candidate)


@pytest.mark.parametrize("value", ["https:/user@host/path?token=USERSECRET", "user@host/path?token=RELSECRET"])
def test_username_only_authority_is_sanitized(value: str) -> None:
    candidate = _candidate(value=value)

    assert "user@" not in repr(candidate)
    assert "SECRET" not in repr(candidate)


@pytest.mark.parametrize("method", ["GET", "PROPFIND", "LOCK", "CUSTOMVERB"])
def test_url_shaped_targets_accept_extended_method_tokens(method: str) -> None:
    candidate = _candidate(method=method, value=f"{method} https://host/path?token=METHODSECRET")

    assert candidate.value == "https://host/path?token="
    assert "METHODSECRET" not in repr(candidate)


@pytest.mark.parametrize("value", ["Apache /server", "Foo http://bar/path", "POST https://host/path"])
def test_mismatched_or_descriptive_method_tokens_are_preserved(value: str) -> None:
    candidate = _candidate(method="GET", kind="fingerprint", value=value, endpoint_key=value)

    assert candidate.value.startswith(value.split("?")[0])
    assert candidate.value.startswith(value.split(" ", 1)[0])


@pytest.mark.parametrize("value", ["OpenSSH 8.2", "Apache httpd 2.4", "Potential SSRF hypothesis"])
def test_non_http_leading_tokens_are_not_treated_as_methods(value: str) -> None:
    candidate = _candidate(kind="fingerprint", value=value, endpoint_key=value)

    assert candidate.value == value


def test_malformed_bracket_authority_scrubs_path_userinfo() -> None:
    candidate = _candidate(value="https://[bad/user:pass@host/path?token=BRACKETSECRET")

    assert "user:pass" not in repr(candidate)
    assert "BRACKETSECRET" not in repr(candidate)
    assert len(candidate.value) <= 160


def test_malformed_port_path_userinfo_is_scrubbed() -> None:
    candidate = _candidate(value="https://host:bad/user:pass@host/path?token=PORTSECRET")

    assert "user:pass" not in repr(candidate)
    assert "PORTSECRET" not in repr(candidate)


def test_userinfo_longer_than_input_budget_is_sanitized_before_bounding() -> None:
    userinfo = "u" * (1_048_576 + 128)
    candidate = _candidate(value=f"https://{userinfo}:pass@host/path?token=HUGESECRET")

    assert candidate.value == "https://host/path?token="
    assert "HUGESECRET" not in repr(candidate)
    assert "pass@" not in repr(candidate)


def test_parameter_normalization_drops_assignment_values() -> None:
    candidate = _candidate(
        kind="parameter",
        value="token",
        parameter="token=TOPSECRET&other=ignored",
        location="query",
    )

    assert candidate.parameter == "token"
    assert "TOPSECRET" not in repr(candidate)


def test_query_names_are_sorted_and_deduplicated_for_identity() -> None:
    first = _candidate(value="https://a.test/api?b=1&a=2&a=3")
    second = _candidate(value="https://a.test/api?a=9&b=8")

    assert first.value == second.value == "https://a.test/api?a=&b="
    assert lead_key(first) == lead_key(second)


def test_parameter_identity_includes_endpoint_method_and_location() -> None:
    base = _candidate(
        kind="parameter",
        endpoint_key="GET https://a.test/users",
        value="id",
        parameter="id",
        location="query",
    )
    other_endpoint = _candidate(
        kind="parameter",
        endpoint_key="GET https://a.test/orders",
        value="id",
        parameter="id",
        location="query",
    )
    other_method = _candidate(
        kind="parameter",
        endpoint_key="GET https://a.test/users",
        value="id",
        method="POST",
        parameter="id",
        location="query",
    )
    other_location = _candidate(
        kind="parameter",
        endpoint_key="GET https://a.test/users",
        value="id",
        parameter="id",
        location="body",
    )

    assert len({lead_key(base), lead_key(other_endpoint), lead_key(other_method), lead_key(other_location)}) == 4


def test_lead_starts_pending_with_bounded_private_references() -> None:
    lead = Lead.from_candidate(_candidate(), round_no=1, capture_id="cap-1")

    assert lead.status == "pending"
    assert lead.sources == ("katana",)
    assert lead.capture_ids == ("cap-1",)
    assert lead.evidence_ids == ()
    assert lead.attempt_count == 0
    assert lead.created_round == 1
    assert lead.last_attempt_round is None
    assert lead.resolution_reason == ""
    assert lead.vulnerability_confirmed is False
    assert 0 < len(lead.id) <= 64
    assert 0 < len(lead.verify_action) <= 160


def test_merge_candidate_deduplicates_sources_and_capture_ids() -> None:
    lead = Lead.from_candidate(_candidate(confidence=0.5, priority=5), round_no=1, capture_id="cap-1")
    duplicate = _candidate(confidence=0.95, priority=9, reason="ffuf")

    returned = merge_candidate(lead, duplicate, "cap-2", "ffuf")
    merge_candidate(lead, duplicate, "cap-2", "ffuf")

    assert returned is lead
    assert lead.sources == ("katana", "ffuf")
    assert lead.capture_ids == ("cap-1", "cap-2")
    assert lead.confidence == 0.95
    assert lead.priority == 9


def test_timeout_and_network_retry_then_skip() -> None:
    lead = Lead.from_candidate(_candidate(priority=9), round_no=1, capture_id="cap-1")

    resolve_lead(lead, outcome="timeout", round_no=2, evidence_id="cap-2")
    assert lead.status == "inconclusive"
    assert lead.attempt_count == 1
    assert lead.resolution_reason == "timeout"

    resolve_lead(lead, outcome="network", round_no=3, evidence_id="cap-2", reason="connection reset")
    assert lead.status == "skipped"
    assert lead.attempt_count == 2
    assert lead.last_attempt_round == 3
    assert lead.resolution_reason == "connection reset"
    assert lead.evidence_ids == ("cap-2",)


def test_resolve_rejects_pending_as_an_outcome() -> None:
    lead = Lead.from_candidate(_candidate(), round_no=1, capture_id="cap-1")

    with pytest.raises(ValueError, match="outcome"):
        resolve_lead(lead, outcome="pending", round_no=2)

    assert lead.status == "pending"
    assert lead.attempt_count == 0


@pytest.mark.parametrize("outcome", ["verified", "failed"])
def test_explicit_resolution_reaches_terminal_state_without_confirming_vulnerability(outcome: str) -> None:
    lead = Lead.from_candidate(
        _candidate(value="/admin", status_code=403, reason="ffuf"),
        round_no=1,
        capture_id="cap-1",
    )

    resolve_lead(lead, outcome=outcome, round_no=2, evidence_id="cap-2")

    assert lead.status == outcome
    assert lead.vulnerability_confirmed is False
    assert lead.resolution_reason == outcome


def test_finalize_marks_unresolved_and_returns_bounded_summary() -> None:
    low = Lead.from_candidate(_candidate(value="/low", priority=3), round_no=1, capture_id="private-low")
    high = Lead.from_candidate(_candidate(value="/highest", priority=10), round_no=1, capture_id="private-high")
    medium = Lead.from_candidate(_candidate(value="/medium", priority=8), round_no=1, capture_id="private-medium")
    verified = Lead.from_candidate(_candidate(value="/verified", priority=7), round_no=1, capture_id="private-ok")
    extra = Lead.from_candidate(_candidate(value="/" + "x" * 300, priority=1), round_no=1, capture_id="private-extra")
    resolve_lead(high, outcome="insufficient", round_no=2)
    resolve_lead(verified, outcome="verified", round_no=2)

    summary = finalize_leads(
        [low, medium, high, verified, extra],
        reason="round budget exhausted " + "r" * 300,
        round_no=9,
    )

    assert low.status == medium.status == high.status == extra.status == "skipped"
    assert verified.status == "verified"
    assert all(lead.last_attempt_round == 9 for lead in (low, medium, high, extra))
    assert all(len(lead.resolution_reason) <= 160 for lead in (low, medium, high, extra))
    assert summary.counts == {"skipped": 4, "verified": 1}
    assert summary.deepen_lead == high.verify_action
    assert len(summary.deepen_lead) <= 160
    assert len(summary.samples) == 3
    assert all(len(sample) <= 160 for sample in summary.samples)
    assert "private-" not in repr(summary)
