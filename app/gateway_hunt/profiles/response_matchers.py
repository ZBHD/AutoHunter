"""Profile 响应的确定性 schema 判定，不包含任何传输行为。"""
from __future__ import annotations

import json
from collections.abc import Callable
from typing import cast

from app.gateway_hunt.schemas import (
    HttpObservation,
    JsonValue,
    ModelParseResult,
    ProbeSpec,
    ResponseClassification,
    SuccessMatcher,
)


WAF_MARKERS = (
    "web application firewall",
    "access denied",
    "request blocked",
    "cf-ray",
)


def response_content_type(response: HttpObservation) -> str:
    return response.content_type.partition(";")[0].strip().lower()


def response_identity(response: HttpObservation) -> tuple[int, str, str]:
    """用于已知路径与 control path 比较的稳定响应身份。"""

    return (
        response.status_code,
        response_content_type(response),
        response.body.strip(),
    )


def _json_value(body: str) -> JsonValue | None:
    try:
        return cast(JsonValue, json.loads(body))
    except (TypeError, ValueError):
        return None


def _deduplicate(values: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def parse_models_response(response: HttpObservation) -> ModelParseResult:
    content_type = response_content_type(response)
    if not 200 <= response.status_code < 300:
        return ModelParseResult(valid=False, reason="non-success status")
    if content_type != "application/json" and not content_type.endswith("+json"):
        return ModelParseResult(valid=False, reason="response is not JSON")

    payload = _json_value(response.body)
    if not isinstance(payload, dict) or "error" in payload:
        return ModelParseResult(
            valid=False,
            reason="JSON object is missing or contains error",
        )
    records = payload.get("data")
    if not isinstance(records, list) or not records:
        return ModelParseResult(
            valid=False,
            reason="model data must be a non-empty list",
        )

    # LiteLLM /model/info has a product-specific schema distinct from OpenAI.
    if all(
        isinstance(record, dict)
        and isinstance(record.get("model_name"), str)
        and bool(str(record["model_name"]).strip())
        and isinstance(record.get("litellm_params"), dict)
        and isinstance(record.get("model_info"), dict)
        for record in records
    ):
        return ModelParseResult(
            valid=True,
            schema_kind="litellm_model_info",
            model_ids=_deduplicate(
                [str(record["model_name"]).strip() for record in records]
            ),
        )

    # Official LiteLLM model_list emits the OpenAI discriminators at both levels.
    if payload.get("object") == "list" and all(
        isinstance(record, dict)
        and record.get("object") == "model"
        and isinstance(record.get("id"), str)
        and bool(str(record["id"]).strip())
        for record in records
    ):
        return ModelParseResult(
            valid=True,
            schema_kind="openai_models",
            model_ids=_deduplicate(
                [str(record["id"]).strip() for record in records]
            ),
        )

    return ModelParseResult(
        valid=False,
        reason="model records do not match a supported schema",
    )


def _is_int(value: object, *, minimum: int = 0) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def _valid_key_info(payload: JsonValue) -> bool:
    return (
        isinstance(payload, dict)
        and isinstance(payload.get("key"), str)
        and bool(str(payload["key"]).strip())
        and isinstance(payload.get("info"), dict)
    )


def _valid_key_record(record: object) -> bool:
    if isinstance(record, str):
        return bool(record.strip())
    if not isinstance(record, dict):
        return False
    return any(
        isinstance(record.get(field), str) and bool(str(record[field]).strip())
        for field in ("token", "api_key", "key_alias")
    )


def _valid_key_list(payload: JsonValue) -> bool:
    if not isinstance(payload, dict):
        return False
    keys = payload.get("keys")
    return (
        isinstance(keys, list)
        and all(_valid_key_record(record) for record in keys)
        and _is_int(payload.get("total_count"))
        and _is_int(payload.get("current_page"), minimum=1)
        and _is_int(payload.get("total_pages"))
    )


def _valid_routes(payload: JsonValue) -> bool:
    if not isinstance(payload, dict):
        return False
    routes = payload.get("routes")
    return (
        isinstance(routes, list)
        and bool(routes)
        and all(
            isinstance(route, dict)
            and isinstance(route.get("path"), str)
            and bool(str(route["path"]).strip())
            and (
                route.get("methods") is None
                or (
                    isinstance(route.get("methods"), list)
                    and all(
                        isinstance(method, str) and bool(method.strip())
                        for method in route["methods"]
                    )
                )
            )
            for route in routes
        )
    )


def _valid_config_list(payload: JsonValue) -> bool:
    return (
        isinstance(payload, list)
        and bool(payload)
        and all(
            isinstance(field, dict)
            and isinstance(field.get("field_name"), str)
            and bool(str(field["field_name"]).strip())
            and isinstance(field.get("field_type"), str)
            and bool(str(field["field_type"]).strip())
            for field in payload
        )
    )


def _valid_callback_record(record: object) -> bool:
    return (
        isinstance(record, dict)
        and isinstance(record.get("name"), str)
        and bool(str(record["name"]).strip())
        and record.get("type") in {"success", "failure", "success_and_failure"}
        and isinstance(record.get("variables"), dict)
    )


def _valid_callbacks(payload: JsonValue) -> bool:
    if not isinstance(payload, dict):
        return False
    callbacks = payload.get("callbacks")
    return (
        payload.get("status") == "success"
        and isinstance(callbacks, list)
        and all(_valid_callback_record(record) for record in callbacks)
        and isinstance(payload.get("alerts"), list)
        and isinstance(payload.get("router_settings"), dict)
        and isinstance(payload.get("available_callbacks"), dict)
    )


_ADMIN_MATCHERS: dict[str, Callable[[JsonValue], bool]] = {
    "key_info": _valid_key_info,
    "key_list": _valid_key_list,
    "routes": _valid_routes,
    "config_list": _valid_config_list,
    "config_callbacks": _valid_callbacks,
}


def classify_probe_response(
    probe: ProbeSpec,
    response: HttpObservation,
) -> ResponseClassification:
    content_type = response_content_type(response)
    body = response.body.strip()
    body_lower = body.lower()
    if any(marker in body_lower for marker in WAF_MARKERS):
        return ResponseClassification(
            category="waf_response",
            valid=False,
            reason="response contains a WAF marker",
        )
    if content_type == "text/html" or body_lower.startswith(
        ("<!doctype html", "<html")
    ):
        return ResponseClassification(
            category="html_response",
            valid=False,
            reason="HTML does not satisfy a gateway API matcher",
        )
    if response.status_code in {401, 403}:
        return ResponseClassification(
            category="auth_required",
            valid=False,
            reason="route requires authentication",
        )
    if response.status_code == 429:
        return ResponseClassification(
            category="rate_limited",
            valid=False,
            reason="route is rate limited",
        )
    if response.status_code == 404:
        return ResponseClassification(
            category="not_found",
            valid=False,
            reason="route was not found",
        )
    if response.status_code >= 500:
        return ResponseClassification(
            category="server_error",
            valid=False,
            reason="gateway returned a server error",
        )
    if not 200 <= response.status_code < 300:
        return ResponseClassification(
            category="error_response",
            valid=False,
            reason="route returned a non-success status",
        )

    is_json = content_type == "application/json" or content_type.endswith("+json")
    payload = _json_value(body) if is_json else None
    if isinstance(payload, dict) and "error" in payload:
        return ResponseClassification(
            category="error_response",
            valid=False,
            reason="successful status contains an error object",
        )

    if probe.success_matcher == SuccessMatcher.EXACT_ALIVE_TEXT:
        valid = content_type == "text/plain" and body == "I'm alive!"
        return ResponseClassification(
            category="public_baseline" if valid else "invalid_response",
            valid=valid,
            reason=(
                "exact health response matched"
                if valid
                else "health response mismatch"
            ),
        )

    if probe.success_matcher in {
        SuccessMatcher.MODELS_JSON,
        SuccessMatcher.MODEL_INFO_JSON,
    }:
        parsed = parse_models_response(response)
        expected_schema = (
            "litellm_model_info"
            if probe.success_matcher == SuccessMatcher.MODEL_INFO_JSON
            else "openai_models"
        )
        valid = parsed.valid and parsed.schema_kind == expected_schema
        category = "model_info" if probe.category == "model_info" else "models"
        return ResponseClassification(
            category=category if valid else "invalid_response",
            valid=valid,
            reason=(
                "model schema matched"
                if valid
                else parsed.reason or "unexpected model schema"
            ),
            model_ids=parsed.model_ids if valid else (),
        )

    if probe.success_matcher == SuccessMatcher.OPENAI_CHAT_JSON:
        choices = payload.get("choices") if isinstance(payload, dict) else None
        first_choice = choices[0] if isinstance(choices, list) and choices else None
        message = (
            first_choice.get("message")
            if isinstance(first_choice, dict)
            else None
        )
        valid = (
            isinstance(payload, dict)
            and isinstance(payload.get("id"), str)
            and bool(str(payload["id"]).strip())
            and isinstance(payload.get("model"), str)
            and bool(str(payload["model"]).strip())
            and isinstance(message, dict)
            and isinstance(message.get("content"), str)
        )
        return ResponseClassification(
            category="inference" if valid else "invalid_response",
            valid=valid,
            reason=(
                "OpenAI chat schema matched"
                if valid
                else "OpenAI chat schema mismatch"
            ),
        )

    if probe.success_matcher == SuccessMatcher.ADMIN_JSON:
        matcher = _ADMIN_MATCHERS.get(probe.probe_id)
        valid = matcher(payload) if matcher is not None and payload is not None else False
        return ResponseClassification(
            category="management" if valid else "invalid_response",
            valid=valid,
            reason=(
                "endpoint-specific admin schema matched"
                if valid
                else "endpoint-specific admin schema mismatch"
            ),
        )

    return ResponseClassification(
        category="invalid_response",
        valid=False,
        reason="unsupported response matcher",
    )


__all__ = [
    "WAF_MARKERS",
    "classify_probe_response",
    "parse_models_response",
    "response_content_type",
    "response_identity",
]
