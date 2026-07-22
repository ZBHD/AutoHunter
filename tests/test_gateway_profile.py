from __future__ import annotations

from copy import deepcopy

import pytest

from app.gateway_hunt.fingerprinter import (
    gateway_target_source,
    normalize_base_url,
    normalize_mount_path,
    origin_key,
)
from app.gateway_hunt.profiles.base import GatewayProfile
from app.gateway_hunt.profiles.litellm import LiteLLMProfile
from app.gateway_hunt.query_planner import QueryPlanner
from app.gateway_hunt.registry import UnknownGatewayProfileError, get_profile, list_profiles
from app.gateway_hunt.schemas import (
    HttpObservation,
    QueryFamilyState,
    ScopeAnchor,
    SecretPattern,
)


def test_litellm_profile_exposes_versioned_structured_contract() -> None:
    profile = LiteLLMProfile()

    assert isinstance(profile, GatewayProfile)
    assert profile.profile_id == "litellm"
    assert profile.version == "1"
    assert profile.search_signatures()
    assert all(signature.engine_clauses for signature in profile.search_signatures())

    probes = {probe.probe_id: probe for probe in profile.probes()}
    assert {probe_id: probe.path for probe_id, probe in probes.items()} == {
        "health_liveliness": "/health/liveliness",
        "health_liveness": "/health/liveness",
        "health_readiness": "/health/readiness",
        "v1_models": "/v1/models",
        "models": "/models",
        "model_info": "/model/info",
        "v1_model_info": "/v1/model/info",
        "v1_chat_completions": "/v1/chat/completions",
        "chat_completions": "/chat/completions",
        "key_info": "/key/info",
        "key_list": "/key/list",
        "routes": "/routes",
        "config_list": "/config/list",
        "config_callbacks": "/get/config/callbacks",
    }
    assert all(
        probes[probe_id].public_by_design
        and not probes[probe_id].finding_eligible
        for probe_id in ("health_liveliness", "health_liveness", "health_readiness")
    )
    assert probes["v1_chat_completions"].method == "POST"
    assert probes["key_info"].category == "readonly_admin"


def test_profile_callers_cannot_mutate_shared_signature_templates() -> None:
    profile = LiteLLMProfile()
    returned = profile.search_signatures()
    original_clause = returned[0].engine_clauses["fofa"]

    returned[0].engine_clauses["fofa"] = "changed-by-caller"

    assert profile.search_signatures()[0].engine_clauses["fofa"] == original_clause


def test_litellm_probes_define_complete_request_and_success_contracts() -> None:
    probes = {probe.probe_id: probe for probe in LiteLLMProfile().probes()}

    assert all(probe.headers_template for probe in probes.values())
    assert all(probe.expected_content_types for probe in probes.values())
    assert all(probe.request_cost >= 1 for probe in probes.values())
    assert all(probe.success_matcher for probe in probes.values())
    assert all(
        probe.headers_template.get("Authorization") == "Bearer {auth_token}"
        for probe in probes.values()
        if not probe.public_by_design
    )
    assert all(
        "Authorization" not in probe.headers_template
        for probe in probes.values()
        if probe.public_by_design
    )
    assert all(
        probes[probe_id].success_matcher == "exact_alive_text"
        for probe_id in ("health_liveliness", "health_liveness", "health_readiness")
    )
    assert probes["v1_models"].success_matcher == "models_json"
    assert probes["model_info"].success_matcher == "model_info_json"
    assert probes["v1_chat_completions"].success_matcher == "openai_chat_json"
    assert probes["key_info"].success_matcher == "admin_json"
    assert probes["v1_chat_completions"].body_template == {
        "model": "{model}",
        "messages": [{"role": "user", "content": "{nonce}"}],
        "stream": False,
        "max_tokens": 1,
    }
    assert probes["v1_chat_completions"].request_json == probes[
        "v1_chat_completions"
    ].body_template


def test_profile_exposes_auditable_probe_groups() -> None:
    profile = LiteLLMProfile()
    public_ids = {probe.probe_id for probe in profile.public_routes()}
    fingerprint_ids = {probe.probe_id for probe in profile.fingerprint_probes()}

    assert public_ids == {
        "health_liveliness",
        "health_liveness",
        "health_readiness",
    }
    assert public_ids < fingerprint_ids
    assert {"model_info", "v1_model_info"} <= fingerprint_ids
    assert {probe.probe_id for probe in profile.model_routes()} == {
        "v1_models",
        "models",
        "model_info",
        "v1_model_info",
    }
    assert {probe.probe_id for probe in profile.inference_routes()} == {
        "v1_chat_completions",
        "chat_completions",
    }
    assert {probe.probe_id for probe in profile.management_routes()} == {
        "key_info",
        "key_list",
        "routes",
        "config_list",
        "config_callbacks",
    }


def test_litellm_secret_patterns_are_structured_metadata_only() -> None:
    patterns = {pattern.pattern_id: pattern for pattern in LiteLLMProfile().secret_patterns()}

    assert all(isinstance(pattern, SecretPattern) for pattern in patterns.values())
    assert set(patterns) == {"litellm_master_key", "litellm_virtual_key"}
    assert "LITELLM_MASTER_KEY" in patterns["litellm_master_key"].variable_names
    assert "LITELLM_VIRTUAL_KEY" in patterns["litellm_virtual_key"].variable_names
    assert "sk-" in patterns["litellm_master_key"].value_prefixes
    assert "sk-" in patterns["litellm_virtual_key"].value_prefixes


def test_parse_models_accepts_openai_and_explicit_litellm_shapes() -> None:
    profile = LiteLLMProfile()
    openai = profile.parse_models(
        HttpObservation(
            path="/v1/models",
            status_code=200,
            content_type="application/json",
            body='{"object":"list","data":[{"id":"model-a"},{"id":"model-b"}]}',
        )
    )
    litellm = profile.parse_models(
        HttpObservation(
            path="/model/info",
            status_code=200,
            content_type="application/json",
            body=(
                '{"data":[{"model_name":"proxy-model",'
                '"litellm_params":{},"model_info":{}}]}'
            ),
        )
    )

    assert openai.valid is True
    assert openai.schema_kind == "openai_models"
    assert openai.model_ids == ("model-a", "model-b")
    assert litellm.valid is True
    assert litellm.schema_kind == "litellm_model_info"
    assert litellm.model_ids == ("proxy-model",)


@pytest.mark.parametrize(
    "response",
    [
        HttpObservation(
            path="/v1/models",
            status_code=200,
            content_type="application/json",
            body='{"data":[{"id":"valid"},{}]}',
        ),
        HttpObservation(
            path="/v1/models",
            status_code=200,
            content_type="application/json",
            body='{"error":{"message":"upstream failed"}}',
        ),
        HttpObservation(
            path="/v1/models",
            status_code=200,
            content_type="text/html",
            body="<html>single page app</html>",
        ),
    ],
)
def test_parse_models_rejects_partial_error_and_html_shapes(
    response: HttpObservation,
) -> None:
    parsed = LiteLLMProfile().parse_models(response)

    assert parsed.valid is False
    assert parsed.model_ids == ()


def test_classify_response_uses_probe_matcher_and_returns_structured_result() -> None:
    profile = LiteLLMProfile()
    probes = {probe.probe_id: probe for probe in profile.probes()}

    health = profile.classify_response(
        probes["health_liveliness"],
        HttpObservation(
            path="/health/liveliness",
            status_code=200,
            content_type="text/plain",
            body="I'm alive!",
        ),
    )
    inference = profile.classify_response(
        probes["v1_chat_completions"],
        HttpObservation(
            path="/v1/chat/completions",
            status_code=200,
            content_type="application/json",
            body=(
                '{"id":"chatcmpl-fixture","model":"fixture-model",'
                '"choices":[{"message":{"role":"assistant","content":"ok"}}]}'
            ),
            method="POST",
        ),
    )

    assert health.valid is True
    assert health.category == "public_baseline"
    assert inference.valid is True
    assert inference.category == "inference"


@pytest.mark.parametrize(
    ("status_code", "content_type", "body", "category"),
    [
        (200, "text/html", "<html>LiteLLM dashboard</html>", "html_response"),
        (200, "application/json", '{"error":{"message":"quota"}}', "error_response"),
        (200, "text/plain", "Web Application Firewall: request blocked", "waf_response"),
        (401, "application/json", '{"error":"unauthorized"}', "auth_required"),
        (429, "application/json", '{"error":"rate limit"}', "rate_limited"),
    ],
)
def test_classify_response_rejects_non_business_success(
    status_code: int,
    content_type: str,
    body: str,
    category: str,
) -> None:
    profile = LiteLLMProfile()
    probe = {probe.probe_id: probe for probe in profile.probes()}["v1_models"]

    result = profile.classify_response(
        probe,
        HttpObservation(
            path=probe.path,
            status_code=status_code,
            content_type=content_type,
            body=body,
        ),
    )

    assert result.valid is False
    assert result.category == category


def test_litellm_health_is_fingerprint_not_finding() -> None:
    profile = LiteLLMProfile()
    result = profile.match_fingerprint(
        [
            HttpObservation(
                path="/health/liveliness",
                status_code=200,
                content_type="text/plain; charset=utf-8",
                body="I'm alive!",
            )
        ]
    )

    assert result.status == "confirmed"
    assert result.public_only is True
    assert result.finding_eligible is False
    assert [signal.probe_id for signal in result.signals] == ["health_liveliness"]


def test_catch_all_alive_response_does_not_confirm_litellm() -> None:
    result = LiteLLMProfile().match_fingerprint(
        [
            HttpObservation(
                path="/health/liveliness",
                status_code=200,
                content_type="text/plain",
                body="I'm alive!",
            ),
            HttpObservation(
                path="/definitely-not-a-litellm-route",
                status_code=200,
                content_type="text/plain",
                body="I'm alive!",
            ),
        ]
    )

    assert result.status != "confirmed"
    assert result.signals == ()


@pytest.mark.parametrize(
    "observations",
    [
        [
            HttpObservation(
                path="/health/liveliness",
                status_code=200,
                content_type="text/html",
                body="<html><title>Dashboard</title><div>I'm alive!</div></html>",
            )
        ],
        [
            HttpObservation(
                path="/health/liveliness",
                status_code=200,
                content_type="text/html",
                body="<html><title>Access denied</title>Web Application Firewall</html>",
            ),
            HttpObservation(
                path="/v1/models",
                status_code=200,
                content_type="text/html",
                body="<html><title>Access denied</title>Web Application Firewall</html>",
            ),
        ],
        [
            HttpObservation(
                path="/health/liveliness",
                status_code=200,
                content_type="application/json",
                body='{"status":"ok"}',
            )
        ],
    ],
)
def test_spa_waf_and_arbitrary_200_do_not_confirm_litellm(
    observations: list[HttpObservation],
) -> None:
    result = LiteLLMProfile().match_fingerprint(observations)

    assert result.status != "confirmed"
    assert result.signals == ()


def test_registry_lists_litellm_and_unknown_profile_is_explicit() -> None:
    assert get_profile("litellm").profile_id == "litellm"
    assert [profile.profile_id for profile in list_profiles()] == ["litellm"]

    with pytest.raises(UnknownGatewayProfileError, match="missing"):
        get_profile("missing")


def test_targeted_query_combines_profile_signature_and_typed_anchors() -> None:
    plans = QueryPlanner().plan(
        scope_mode="targeted",
        anchors=[
            ScopeAnchor(kind="domain", value="example.test"),
            ScopeAnchor(kind="organization", value='Example "Lab"'),
        ],
        engine="fofa",
        profile_id="litellm",
        state={},
    )

    assert plans
    assert all(plan.query.startswith("(") for plan in plans)
    assert all(
        ') && (domain="example.test" || org="Example \\"Lab\\"")'
        in plan.query
        for plan in plans
    )
    assert all(plan.profile_id == "litellm" and plan.profile_version == "1" for plan in plans)
    assert all(
        plan.cursor_key
        == f"fofa:litellm:1:{plan.signature_id}:{plan.scope_hash}"
        for plan in plans
    )


def test_global_query_uses_only_high_strength_signatures() -> None:
    profile = LiteLLMProfile()
    strengths = {
        signature.signature_id: signature.strength
        for signature in profile.search_signatures()
    }

    plans = QueryPlanner().plan(
        scope_mode="global",
        anchors=[],
        engine="fofa",
        profile_id="litellm",
        state={},
    )

    assert plans
    assert all(strengths[plan.signature_id] == "high" for plan in plans)
    assert all("domain=" not in plan.query and "org=" not in plan.query for plan in plans)


def test_query_family_cursors_are_independent_and_input_state_is_unchanged() -> None:
    planner = QueryPlanner()
    initial_plans = planner.plan(
        scope_mode="global",
        anchors=[],
        engine="fofa",
        profile_id="litellm",
        state={},
    )
    assert len(initial_plans) >= 2

    input_state = {
        initial_plans[0].cursor_key: QueryFamilyState(cursor=7, empty_streak=2),
        initial_plans[1].cursor_key: {
            "cursor": 3,
            "failure_count": 1,
            "opaque_engine_cursor": "fixture-token",
        },
    }
    original = deepcopy(input_state)

    plans = planner.plan(
        scope_mode="global",
        anchors=[],
        engine="fofa",
        profile_id="litellm",
        state=input_state,
    )

    assert input_state == original
    assert plans[0].cursor == 8
    assert plans[0].next_state.cursor == 8
    assert plans[0].next_state.empty_streak == 2
    assert plans[1].cursor == 4
    assert plans[1].next_state.failure_count == 1
    assert plans[1].next_state.opaque_engine_cursor == "fixture-token"
    assert all(plan.cursor_key != plans[0].cursor_key for plan in plans[1:])


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("HTTPS://Example.TEST:443//proxy///", "https://example.test/proxy"),
        ("http://Example.TEST:80/", "http://example.test"),
        ("http://Example.TEST:8080///llm/?x=1#frag", "http://example.test:8080/llm"),
        ("https://[2001:DB8::1]:443//gateway/", "https://[2001:db8::1]/gateway"),
        ("https://[2001:db8::1]:8443/", "https://[2001:db8::1]:8443"),
    ],
)
def test_normalize_base_url_handles_authority_and_path_edges(raw: str, expected: str) -> None:
    assert normalize_base_url(raw) == expected
    assert origin_key(raw) == expected


def test_same_origin_redirect_and_explicit_mount_path_are_normalized() -> None:
    assert normalize_base_url(
        "https://EXAMPLE.test/start",
        redirect_url="/proxy//gateway/?from=start#section",
    ) == "https://example.test/proxy/gateway"
    assert normalize_base_url(
        "https://example.test/start",
        redirect_url="https://other.test/proxy",
    ) == "https://example.test/start"
    assert normalize_base_url(
        "https://example.test/ignored",
        mount_path="//mounted///llm/",
    ) == "https://example.test/mounted/llm"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", "/"),
        ("/", "/"),
        ("proxy///llm/", "/proxy/llm"),
        ("//proxy/./v1/../llm//", "/proxy/llm"),
    ],
)
def test_normalize_mount_path(raw: str, expected: str) -> None:
    assert normalize_mount_path(raw) == expected


def test_different_mounts_have_stable_distinct_target_sources() -> None:
    proxy_key = origin_key("https://example.test/proxy")
    api_key = origin_key("https://example.test/api")
    proxy_source = gateway_target_source(proxy_key)

    assert proxy_key != api_key
    assert proxy_source != gateway_target_source(api_key)
    assert proxy_source == gateway_target_source(proxy_key)
    assert proxy_source.startswith("gw:llm:")
    assert len(proxy_source) <= 20


@pytest.mark.parametrize(
    "raw",
    [
        "ftp://example.test/proxy",
        "https://user:password@example.test/proxy",
        "https://example.test:70000/proxy",
        "https:///missing-host",
    ],
)
def test_origin_key_rejects_invalid_gateway_urls(raw: str) -> None:
    with pytest.raises(ValueError):
        origin_key(raw)
