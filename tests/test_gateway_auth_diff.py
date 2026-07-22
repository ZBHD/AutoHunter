from __future__ import annotations

import pytest

from app.gateway_hunt.auth_diff import ResponseSample, compare_auth_variants


def _sample(
    status_code: int,
    body: str,
    content_type: str = "application/json",
) -> ResponseSample:
    return ResponseSample(status_code, content_type, body)


def test_auth_diff_distinguishes_anonymous_models() -> None:
    result = compare_auth_variants(
        no_auth=_sample(200, '{"data":[{"id":"gpt"}]}'),
        invalid_auth=_sample(401, '{"error":"invalid"}'),
        candidate=None,
        public_by_design=False,
    )

    assert result.kind == "anonymous_models"
    assert result.no_auth_schema == "models"
    assert result.model_ids == ("gpt",)
    assert result.status_changed is True


def test_auth_diff_requires_strict_openai_chat_shape() -> None:
    valid_chat = (
        '{"id":"chatcmpl-1","model":"gpt",'
        '"choices":[{"message":{"role":"assistant","content":"ok"}}]}'
    )

    result = compare_auth_variants(
        no_auth=_sample(200, valid_chat),
        invalid_auth=_sample(401, '{"error":{"message":"invalid key"}}'),
        candidate=None,
        public_by_design=False,
    )
    incomplete = compare_auth_variants(
        no_auth=_sample(200, '{"choices":[{"message":{"content":"ok"}}]}'),
        invalid_auth=_sample(401, '{"error":"invalid"}'),
        candidate=None,
        public_by_design=False,
    )

    assert result.kind == "anonymous_inference"
    assert incomplete.kind == "inconclusive"


def test_candidate_is_valid_only_when_business_schema_differs_from_controls() -> None:
    candidate = _sample(
        200,
        '{"object":"list","data":[{"id":"gpt","object":"model"}]}',
    )

    valid = compare_auth_variants(
        no_auth=_sample(401, '{"error":"missing"}'),
        invalid_auth=_sample(403, '{"error":"invalid"}'),
        candidate=candidate,
        public_by_design=False,
    )
    control_also_valid = compare_auth_variants(
        no_auth=candidate,
        invalid_auth=_sample(401, '{"error":"invalid"}'),
        candidate=candidate,
        public_by_design=False,
    )

    assert valid.kind == "candidate_valid"
    assert valid.candidate_schema == "models"
    assert control_also_valid.kind == "anonymous_models"


def test_auth_failures_are_protected_but_missing_routes_are_inconclusive() -> None:
    protected = compare_auth_variants(
        no_auth=_sample(401, '{"error":"missing"}'),
        invalid_auth=_sample(403, '{"error":"invalid"}'),
        candidate=None,
        public_by_design=False,
    )
    absent = compare_auth_variants(
        no_auth=_sample(404, '{"detail":"Not Found"}'),
        invalid_auth=_sample(404, '{"detail":"Not Found"}'),
        candidate=None,
        public_by_design=False,
    )

    assert protected.kind == "protected"
    assert absent.kind == "inconclusive"
    assert absent.body_similarity == pytest.approx(1.0)
    assert absent.content_type_changed is False


@pytest.mark.parametrize(
    ("body", "content_type"),
    [
        ("", "application/json"),
        ("<html>Access denied</html>", "text/html"),
        ("web application firewall: request blocked", "text/plain"),
        (
            '{"object":"list","data":[{"id":"gpt","object":"model"}],'
            '"message":"request blocked by web application firewall"}',
            "application/json",
        ),
        ('{"error":{"message":"upstream failed"}}', "application/json"),
        ('{"data":[{"id":"gpt"}]}', "text/html"),
    ],
)
def test_non_business_and_wrong_content_type_responses_are_not_successes(
    body: str,
    content_type: str,
) -> None:
    response = _sample(200, body, content_type)

    result = compare_auth_variants(
        no_auth=response,
        invalid_auth=response,
        candidate=response,
        public_by_design=False,
    )

    assert result.kind == "inconclusive"


def test_public_routes_are_baselines_not_exposures() -> None:
    result = compare_auth_variants(
        no_auth=_sample(200, "I'm alive!", "text/plain; charset=utf-8"),
        invalid_auth=_sample(200, "I'm alive!", "text/plain"),
        candidate=None,
        public_by_design=True,
    )

    assert result.kind == "public_baseline"
