"""LiteLLM 鉴权变体的确定性差异判定，不执行任何请求。"""
from __future__ import annotations

import json
from difflib import SequenceMatcher

from app.gateway_hunt.profiles.litellm import LiteLLMProfile
from app.gateway_hunt.profiles.response_matchers import WAF_MARKERS, response_content_type
from app.gateway_hunt.schemas import (
    AuthDiffResult,
    AuthSchemaKind,
    HttpObservation,
    ResponseSample,
)


_PROFILE = LiteLLMProfile()
_MODEL_PROBES = _PROFILE.model_routes()
_INFERENCE_PROBE = _PROFILE.inference_routes()[0]
_MANAGEMENT_PROBES = _PROFILE.management_routes()


def _observation(sample: ResponseSample, path: str) -> HttpObservation:
    return HttpObservation(
        path=path,
        status_code=sample.status_code,
        content_type=sample.content_type,
        body=sample.body,
    )


def _business_schema(
    sample: ResponseSample | None,
) -> tuple[AuthSchemaKind, tuple[str, ...]]:
    if sample is None:
        return "invalid", ()

    for probe in _MODEL_PROBES:
        classification = _PROFILE.classify_response(
            probe,
            _observation(sample, probe.path),
        )
        if classification.valid or classification.category == "models_compatible":
            return "models", classification.model_ids

    inference = _PROFILE.classify_response(
        _INFERENCE_PROBE,
        _observation(sample, _INFERENCE_PROBE.path),
    )
    if inference.valid:
        return "inference", ()

    for probe in _MANAGEMENT_PROBES:
        classification = _PROFILE.classify_response(
            probe,
            _observation(sample, probe.path),
        )
        if classification.valid:
            return "management", ()
    return "invalid", ()


def _canonical_body(body: str) -> str:
    stripped = body.strip()
    try:
        return json.dumps(
            json.loads(stripped),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        return " ".join(stripped.split())


def _similarity(left: str, right: str) -> float:
    return SequenceMatcher(
        None,
        _canonical_body(left),
        _canonical_body(right),
        autojunk=False,
    ).ratio()


def _is_control_catchall(sample: ResponseSample) -> bool:
    """识别统一错误页、WAF 或缺失路由，不把它当作鉴权差异。"""

    body = sample.body.strip().lower()
    content_type = sample.content_type.partition(";")[0].strip().lower()
    if content_type == "text/html" or sample.status_code == 404:
        return True
    return any(marker in body for marker in WAF_MARKERS)


def compare_auth_variants(
    *,
    no_auth: ResponseSample,
    invalid_auth: ResponseSample,
    candidate: ResponseSample | None,
    public_by_design: bool,
) -> AuthDiffResult:
    """比较无 Key、无效 Key、候选 Key 响应并返回单一确定性结论。"""

    no_schema, no_models = _business_schema(no_auth)
    invalid_schema, _ = _business_schema(invalid_auth)
    candidate_schema, candidate_models = _business_schema(candidate)
    no_content_type = response_content_type(
        _observation(no_auth, "/auth-diff/no-auth")
    )
    invalid_content_type = response_content_type(
        _observation(invalid_auth, "/auth-diff/invalid-auth")
    )
    common = {
        "no_auth_schema": no_schema,
        "invalid_auth_schema": invalid_schema,
        "candidate_schema": candidate_schema,
        "status_changed": no_auth.status_code != invalid_auth.status_code,
        "content_type_changed": no_content_type != invalid_content_type,
        "body_similarity": _similarity(no_auth.body, invalid_auth.body),
        "control_catchall": (
            _is_control_catchall(no_auth)
            and _is_control_catchall(invalid_auth)
            and _similarity(no_auth.body, invalid_auth.body) >= 0.99
        ),
    }

    if public_by_design:
        return AuthDiffResult(
            kind="public_baseline",
            reason="route is explicitly public by design",
            **common,
        )

    if no_schema == "models":
        return AuthDiffResult(
            kind="anonymous_models",
            model_ids=no_models,
            reason="no-auth response matches a supported model schema",
            **common,
        )
    if no_schema == "inference":
        return AuthDiffResult(
            kind="anonymous_inference",
            reason="no-auth response matches the OpenAI chat schema",
            **common,
        )
    if common["control_catchall"]:
        return AuthDiffResult(
            kind="inconclusive",
            reason="both control responses are an identical catch-all page",
            **common,
        )
    if (
        candidate_schema != "invalid"
        and no_schema == "invalid"
        and invalid_schema == "invalid"
    ):
        return AuthDiffResult(
            kind="candidate_valid",
            model_ids=candidate_models,
            reason="only the candidate response matches a business schema",
            **common,
        )
    if no_auth.status_code in {401, 403} and invalid_auth.status_code in {401, 403}:
        return AuthDiffResult(
            kind="protected",
            reason="both control variants were rejected by authentication",
            **common,
        )
    return AuthDiffResult(
        kind="inconclusive",
        reason="responses do not establish an authenticated business-path difference",
        **common,
    )


__all__ = ["AuthDiffResult", "ResponseSample", "compare_auth_variants"]
