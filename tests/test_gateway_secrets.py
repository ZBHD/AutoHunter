from __future__ import annotations

import hashlib

from app.gateway_hunt.secret_extractor import extract_secrets


def _by_name(text: str, **kwargs: str):
    return {artifact.name: artifact for artifact in extract_secrets(text, **kwargs)}


def test_extractor_keeps_plaintext_and_groups_bedrock_parts() -> None:
    text = (
        "AWS_ACCESS_KEY_ID=AKIA_TEST\n"
        "AWS_SECRET_ACCESS_KEY=SECRET\n"
        "AWS_SESSION_TOKEN=session-fixture\n"
        "AWS_REGION=us-east-1"
    )

    first = _by_name(text, source_url="https://gateway.test/.env")
    second = _by_name(text, source_url="https://gateway.test/.env")

    assert first["AWS_ACCESS_KEY_ID"].value == "AKIA_TEST"
    assert first["AWS_ACCESS_KEY_ID"].sha256 == hashlib.sha256(b"AKIA_TEST").hexdigest()
    assert first["AWS_SECRET_ACCESS_KEY"].value == "SECRET"
    assert {item.provider for item in first.values()} == {"bedrock"}
    assert len({item.credential_group_id for item in first.values()}) == 1
    assert first["AWS_ACCESS_KEY_ID"].credential_group_id == second[
        "AWS_ACCESS_KEY_ID"
    ].credential_group_id
    assert first["AWS_ACCESS_KEY_ID"].validation_context["region"] == "us-east-1"


def test_extractor_supports_env_quotes_comments_and_provider_types() -> None:
    artifacts = _by_name(
        "\n".join(
            [
                'export LITELLM_MASTER_KEY="sk-master-value" # deployed key',
                "LITELLM_VIRTUAL_KEY='sk-virtual-value'",
                "OPENAI_API_KEY=sk-test-real-value",
                "ANTHROPIC_API_KEY=sk-ant-real-value",
                "GEMINI_API_KEY=AIza-real-value",
            ]
        ),
        source_location="response.body",
    )

    assert artifacts["LITELLM_MASTER_KEY"].secret_type == "master_key"
    assert artifacts["LITELLM_VIRTUAL_KEY"].secret_type == "virtual_key"
    assert artifacts["OPENAI_API_KEY"].provider == "openai"
    assert artifacts["ANTHROPIC_API_KEY"].provider == "anthropic"
    assert artifacts["GEMINI_API_KEY"].provider == "gemini"
    assert artifacts["LITELLM_MASTER_KEY"].source_location == "response.body"


def test_extractor_supports_json_yaml_bearer_and_dsns() -> None:
    text = "\n".join(
        [
            '{"OPENAI_API_KEY":"sk-json-value","nested":{"JWT_SECRET":"jwt-json-value"}}',
            "DATABASE_URL: postgresql://user:pass@db.internal/app",
            "REDIS_URL: redis://:pass@redis.internal:6379/0",
            "Authorization: Bearer opaque-bearer-token-value",
        ]
    )

    artifacts = _by_name(text, source_url="https://gateway.test/config")

    assert artifacts["OPENAI_API_KEY"].value == "sk-json-value"
    assert artifacts["JWT_SECRET"].secret_type == "jwt_secret"
    assert artifacts["DATABASE_URL"].secret_type == "database_dsn"
    assert artifacts["REDIS_URL"].secret_type == "redis_url"
    assert artifacts["Authorization"].value == "opaque-bearer-token-value"
    assert all(item.source_url == "https://gateway.test/config" for item in artifacts.values())


def test_extractor_groups_azure_context_without_joining_separate_blocks() -> None:
    text = "\n".join(
        [
            "AZURE_OPENAI_API_KEY=azure-key-one",
            "AZURE_OPENAI_ENDPOINT=https://one.openai.azure.com",
            "AZURE_OPENAI_DEPLOYMENT=gpt-one",
            "",
            "AZURE_OPENAI_API_KEY=azure-key-two",
            "AZURE_OPENAI_ENDPOINT=https://two.openai.azure.com",
            "AZURE_OPENAI_DEPLOYMENT=gpt-two",
        ]
    )

    artifacts = extract_secrets(text)
    groups = {}
    for artifact in artifacts:
        groups.setdefault(artifact.credential_group_id, []).append(artifact)

    assert len(groups) == 2
    assert sorted(len(group) for group in groups.values()) == [3, 3]
    assert {
        group[0].validation_context["endpoint"] for group in groups.values()
    } == {
        "https://one.openai.azure.com",
        "https://two.openai.azure.com",
    }


def test_extractor_filters_placeholders_but_not_fixture_substrings() -> None:
    text = "\n".join(
        [
            "OPENAI_API_KEY=***",
            "OPENAI_API_KEY=sk-****",
            "OPENAI_API_KEY=sk-example",
            "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}",
            "ANTHROPIC_API_KEY=dummy-secret-value",
            "GEMINI_API_KEY=YOUR_KEY_HERE",
            "JWT_SECRET=changeme",
            "DATABASE_URL=postgresql://${DB_USER}:${DB_PASSWORD}@db/app",
            "LITELLM_MASTER_KEY=sk-test-real-value",
            "AWS_ACCESS_KEY_ID=AKIA_TEST",
            "AWS_SECRET_ACCESS_KEY=SECRET",
        ]
    )

    artifacts = _by_name(text)

    assert set(artifacts) == {
        "LITELLM_MASTER_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
    }


def test_extractor_deduplicates_name_and_value_and_redacts_bounded_context() -> None:
    text = "\n".join(
        [
            "OPENAI_API_KEY=sk-first-sensitive-value",
            "OPENAI_API_KEY=sk-first-sensitive-value",
            "ANTHROPIC_API_KEY=sk-ant-neighbor-sensitive-value",
            "NOTE=" + "x" * 400,
        ]
    )

    artifacts = extract_secrets(text)

    assert [(item.name, item.value) for item in artifacts].count(
        ("OPENAI_API_KEY", "sk-first-sensitive-value")
    ) == 1
    for artifact in artifacts:
        assert len(artifact.context) <= 240
        assert artifact.value not in artifact.context
        assert "sk-first-sensitive-value" not in artifact.context
        assert "sk-ant-neighbor-sensitive-value" not in artifact.context


def test_context_redacts_untracked_adjacent_sensitive_values() -> None:
    artifacts = extract_secrets(
        '{"OPENAI_API_KEY":"sk-visible-value",'
        '"UNTRACKED_SECRET":"must-not-enter-context"}'
    )

    assert len(artifacts) == 1
    assert "must-not-enter-context" not in artifacts[0].context
    assert "UNTRACKED_SECRET" in artifacts[0].context
