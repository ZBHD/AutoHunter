"""从调用方提供的文本中提取 Secret；模块不包含任何网络行为。"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from app.gateway_hunt.schemas import JsonValue, SecretArtifact


_CONTEXT_LIMIT = 240
_JSON_ASSIGNMENT = re.compile(
    r'"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"\s*:\s*'
    r'"(?P<value>(?:\\.|[^"\\])*)"'
)
_LINE_ASSIGNMENT = re.compile(
    r"^\s*(?:(?:export\s+)?(?:const|let|var)\s+|export\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?:=|:)\s*(?P<value>.*?)\s*$",
    re.IGNORECASE,
)
_BEARER = re.compile(
    r"(?i)(?:\bAuthorization\b\s*(?:=|:)\s*)?\bBearer\s+"
    r"(?P<value>[A-Za-z0-9._~+\-/=]{8,})"
)
_MASK = re.compile(r"^[*xX\u2022.\-]{3,}$")
_MASK_FRAGMENT = re.compile(r"(?:\*{3,}|[xX]{4,}|\u2022{3,})")
_VARIABLE_REFERENCE = re.compile(
    r"^(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|%[A-Za-z_][A-Za-z0-9_]*%|"
    r"\{\{[^{}]+\}\}|<[^<>]+>)$"
)
_VARIABLE_REFERENCE_FRAGMENT = re.compile(
    r"(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|"
    r"%[A-Za-z_][A-Za-z0-9_]*%|\{\{[^{}]+\}\})"
)
_SENSITIVE_CONTEXT_VALUE = re.compile(
    r"(?i)(?P<prefix>[\"']?[A-Za-z_][A-Za-z0-9_]*"
    r"(?:KEY|TOKEN|SECRET|PASSWORD|AUTHORIZATION|DATABASE_URL|REDIS_URL)"
    r"[\"']?\s*(?:=|:)\s*)"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,}]+)"
)
_BARE_PATTERNS = (
    ("anthropic", "sk-ant-[A-Za-z0-9_-]{20,}", "provider_key"),
    ("gemini", "AIza[A-Za-z0-9_-]{20,}", "provider_key"),
    ("openai", "sk-(?:proj-)?[A-Za-z0-9_-]{20,}", "provider_key"),
    ("bedrock", "AKIA[A-Z0-9]{16}", "provider_key"),
    ("unknown", r"postgres(?:ql)?://[^\s'\"<>]+", "database_dsn"),
    ("unknown", r"redis://[^\s'\"<>]+", "redis_url"),
)


@dataclass(frozen=True, slots=True)
class _SecretSpec:
    secret_type: str
    provider: str
    context_key: str = ""


@dataclass(frozen=True, slots=True)
class _Candidate:
    name: str
    value: str
    line_number: int
    block_number: int
    spec: _SecretSpec


_SPECS = {
    "LITELLM_MASTER_KEY": _SecretSpec("master_key", "litellm"),
    "LITELLM_PROXY_MASTER_KEY": _SecretSpec("master_key", "litellm"),
    "MASTER_KEY": _SecretSpec("master_key", "litellm"),
    "LITELLM_VIRTUAL_KEY": _SecretSpec("virtual_key", "litellm"),
    "LITELLM_API_KEY": _SecretSpec("virtual_key", "litellm"),
    "OPENAI_API_KEY": _SecretSpec("provider_key", "openai"),
    "ANTHROPIC_API_KEY": _SecretSpec("provider_key", "anthropic"),
    "GEMINI_API_KEY": _SecretSpec("provider_key", "gemini"),
    "GOOGLE_API_KEY": _SecretSpec("provider_key", "gemini"),
    "AZURE_OPENAI_API_KEY": _SecretSpec("provider_key", "azure_openai"),
    "AZURE_OPENAI_KEY": _SecretSpec("provider_key", "azure_openai"),
    "AZURE_OPENAI_ENDPOINT": _SecretSpec("other", "azure_openai", "endpoint"),
    "AZURE_API_BASE": _SecretSpec("other", "azure_openai", "endpoint"),
    "AZURE_OPENAI_DEPLOYMENT": _SecretSpec("other", "azure_openai", "deployment"),
    "AZURE_OPENAI_DEPLOYMENT_NAME": _SecretSpec(
        "other", "azure_openai", "deployment"
    ),
    "AWS_ACCESS_KEY_ID": _SecretSpec("provider_key", "bedrock"),
    "AWS_SECRET_ACCESS_KEY": _SecretSpec("provider_key", "bedrock"),
    "AWS_SESSION_TOKEN": _SecretSpec("provider_key", "bedrock"),
    "AWS_REGION": _SecretSpec("other", "bedrock", "region"),
    "AWS_DEFAULT_REGION": _SecretSpec("other", "bedrock", "region"),
    "DATABASE_URL": _SecretSpec("database_dsn", "unknown"),
    "REDIS_URL": _SecretSpec("redis_url", "unknown"),
    "JWT_SECRET": _SecretSpec("jwt_secret", "unknown"),
    "JWT_SECRET_KEY": _SecretSpec("jwt_secret", "unknown"),
    "JWT_SIGNING_KEY": _SecretSpec("jwt_secret", "unknown"),
}
_GROUP_PROVIDERS = {"azure_openai", "bedrock"}
_PLACEHOLDERS = {
    "changeme",
    "dummy",
    "dummy_key",
    "example",
    "example_key",
    "masked",
    "placeholder",
    "redacted",
    "replace_me",
    "test",
    "test_api_key",
    "test_key",
    "your_api_key",
    "your_key",
    "your_key_here",
}


def _spec_for(name: str) -> _SecretSpec | None:
    return _SPECS.get(name.upper())


def _inferred_spec(name: str, value: str) -> _SecretSpec | None:
    """Infer only a provider category from an explicit field name or key format."""

    known = _spec_for(name)
    if known is not None:
        return known
    lowered = name.lower()
    value_lower = value.lower()
    if "anthropic" in lowered or value.startswith("sk-ant-"):
        return _SecretSpec("provider_key", "anthropic")
    if "gemini" in lowered or "google" in lowered or value.startswith("AIza"):
        return _SecretSpec("provider_key", "gemini")
    if "openai" in lowered or "apikey" in lowered or value.startswith("sk-"):
        return _SecretSpec("provider_key", "openai")
    if "azure" in lowered:
        return _SecretSpec("provider_key", "azure_openai")
    return None


def _decode_json_string(value: str) -> str:
    try:
        decoded = json.loads(f'"{value}"')
    except (TypeError, ValueError):
        return value
    return str(decoded)


def _clean_assignment_value(raw: str) -> str:
    value = raw.strip().rstrip(",").strip()
    if not value:
        return ""
    if value[0] in {'"', "'"}:
        quote = value[0]
        escaped = False
        end = None
        for index, character in enumerate(value[1:], start=1):
            if character == quote and not escaped:
                end = index
                break
            escaped = character == "\\" and not escaped
            if character != "\\":
                escaped = False
        if end is not None:
            inner = value[1:end]
            return _decode_json_string(inner) if quote == '"' else inner
    return re.split(r"\s+#", value, maxsplit=1)[0].strip()


def _is_placeholder(name: str, value: str) -> bool:
    stripped = value.strip()
    if (
        not stripped
        or _MASK.fullmatch(stripped)
        or _MASK_FRAGMENT.search(stripped)
        or _VARIABLE_REFERENCE.fullmatch(stripped)
        or _VARIABLE_REFERENCE_FRAGMENT.search(stripped)
    ):
        return True
    normalized = re.sub(r"[^a-z0-9]+", "_", stripped.lower()).strip("_")
    if normalized in _PLACEHOLDERS:
        return not (name == "AWS_SECRET_ACCESS_KEY" and normalized == "secret")
    if normalized == "secret":
        return name != "AWS_SECRET_ACCESS_KEY"
    if normalized.startswith(("your_key_", "your_api_key_", "replace_with_")):
        return True
    if {"dummy", "example"} & set(normalized.split("_")):
        return True
    return stripped.lower() in {"null", "none", "undefined"}


def _provider_for_bearer(value: str) -> str:
    if value.startswith("sk-ant-"):
        return "anthropic"
    if value.startswith("AIza"):
        return "gemini"
    return "unknown"


def _collect_candidates(text: str) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    block_number = 0
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            block_number += 1
            continue

        json_names: set[str] = set()
        for match in _JSON_ASSIGNMENT.finditer(line):
            name = match.group("name")
            value = _decode_json_string(match.group("value"))
            spec = _inferred_spec(name, value)
            if spec is None:
                continue
            if _is_placeholder(name, value):
                continue
            json_names.add(name.lower())
            candidates.append(_Candidate(name, value, line_number, block_number, spec))

        assignment = _LINE_ASSIGNMENT.match(line)
        if assignment is not None:
            name = assignment.group("name")
            spec = _inferred_spec(name, "")
            if spec is not None and name.lower() not in json_names:
                value = _clean_assignment_value(assignment.group("value"))
                spec = _inferred_spec(name, value)
                if not _is_placeholder(name, value):
                    if spec is not None:
                        candidates.append(
                            _Candidate(name, value, line_number, block_number, spec)
                        )

        for match in _BEARER.finditer(line):
            value = _clean_assignment_value(match.group("value"))
            if _is_placeholder("AUTHORIZATION", value):
                continue
            candidates.append(
                _Candidate(
                    "Authorization",
                    value,
                    line_number,
                    block_number,
                    _SecretSpec("provider_key", _provider_for_bearer(value)),
                )
            )
    named_values = {candidate.value for candidate in candidates}
    bare_values: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        for provider, pattern, secret_type in _BARE_PATTERNS:
            for match in re.finditer(pattern, line):
                value = match.group(0)
                if (
                    value in named_values
                    or value in bare_values
                    or _is_placeholder("detected", value)
                ):
                    continue
                if provider == "openai" and value.startswith("sk-ant-"):
                    continue
                if provider == "unknown" and (
                    "localhost" in value.lower() or "127.0.0.1" in value.lower()
                ):
                    continue
                digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
                candidates.append(
                    _Candidate(
                        f"detected_{provider}_{digest}",
                        value,
                        line_number,
                        block_number=line_number,
                        spec=_SecretSpec(secret_type, provider),
                    )
                )
                bare_values.add(value)
    return candidates


def _group_id(
    provider: str,
    block_number: int,
    candidates: list[_Candidate],
    source_url: str,
    source_location: str,
) -> str:
    first_line = min(candidate.line_number for candidate in candidates)
    names = ",".join(sorted({candidate.name for candidate in candidates}))
    material = (
        f"{provider}\0{source_url}\0{source_location}\0{block_number}\0"
        f"{first_line}\0{names}"
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _validation_context(candidates: list[_Candidate]) -> dict[str, JsonValue]:
    context: dict[str, JsonValue] = {
        "provider": candidates[0].spec.provider,
        "credential_names": sorted({candidate.name for candidate in candidates}),
    }
    for candidate in candidates:
        if candidate.spec.context_key:
            context[candidate.spec.context_key] = candidate.value
    return context


def _redacted_context(
    candidate: _Candidate,
    lines: list[str],
    all_values: tuple[str, ...],
) -> str:
    context = lines[candidate.line_number - 1].strip()
    for value in sorted(all_values, key=len, reverse=True):
        context = context.replace(value, "<redacted>")
        encoded = json.dumps(value, ensure_ascii=False)[1:-1]
        if encoded != value:
            context = context.replace(encoded, "<redacted>")
    context = _SENSITIVE_CONTEXT_VALUE.sub(
        lambda match: f'{match.group("prefix")}<redacted>',
        context,
    )
    return context[:_CONTEXT_LIMIT]


def extract_secrets(
    text: str,
    *,
    source_url: str = "",
    source_location: str = "",
) -> tuple[SecretArtifact, ...]:
    """只分析传入文本并返回去重后的结构化 SecretArtifact。"""

    if not isinstance(text, str) or not text:
        return ()
    collected = _collect_candidates(text)
    unique: list[_Candidate] = []
    seen: dict[tuple[str, str], int] = {}
    seen_values: dict[str, int] = {}
    for candidate in collected:
        identity = (candidate.name, candidate.value)
        if identity in seen:
            continue
        value_index = seen_values.get(candidate.value)
        if value_index is not None:
            # A canonical environment variable beats an inferred JS/bare name.
            if _spec_for(candidate.name) is not None and _spec_for(
                unique[value_index].name
            ) is None:
                unique[value_index] = candidate
            seen[identity] = value_index
            continue
        seen[identity] = len(unique)
        seen_values[candidate.value] = len(unique)
        unique.append(candidate)

    groups: dict[tuple[str, int], list[_Candidate]] = {}
    for candidate in unique:
        if candidate.spec.provider in _GROUP_PROVIDERS:
            groups.setdefault(
                (candidate.spec.provider, candidate.block_number), []
            ).append(candidate)
    group_metadata: dict[tuple[str, int], tuple[str, dict[str, JsonValue]]] = {}
    for key, members in groups.items():
        group_metadata[key] = (
            _group_id(
                key[0], key[1], members, source_url, source_location
            ),
            _validation_context(members),
        )

    lines = text.splitlines()
    all_values = tuple(candidate.value for candidate in unique)
    artifacts: list[SecretArtifact] = []
    for candidate in unique:
        group = group_metadata.get(
            (candidate.spec.provider, candidate.block_number)
        )
        validation_context: dict[str, JsonValue] = (
            group[1]
            if group is not None
            else {"provider": candidate.spec.provider}
        )
        artifacts.append(
            SecretArtifact(
                name=candidate.name,
                value=candidate.value,
                sha256=hashlib.sha256(candidate.value.encode("utf-8")).hexdigest(),
                secret_type=candidate.spec.secret_type,
                provider=candidate.spec.provider,
                source_url=source_url,
                source_location=(
                    source_location
                    if not candidate.name.startswith("detected_")
                    else f"{source_location or 'text'}:line:{candidate.line_number}"
                ),
                context=_redacted_context(candidate, lines, all_values),
                credential_group_id=group[0] if group is not None else None,
                validation_context=validation_context,
            )
        )
    return tuple(artifacts)


__all__ = ["SecretArtifact", "extract_secrets"]
