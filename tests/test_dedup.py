from __future__ import annotations

import pytest

from app.dedup import is_duplicate, normalize_vuln_type, vuln_type_alias_set


BACKDOOR_ALIASES = (
    "backdoor_compromised",
    "backdoorcompromised",
    "疑似后门",
    "疑似被黑",
    "服务器被攻陷",
    "被攻陷",
    "被挂马",
    "挂马",
    "网页被篡改",
    "被篡改",
    "后门",
    "webshell",
    "compromised",
    "hacked",
    "defaced",
    "被黑",
    "植入后门",
    "web后门",
    "网页挂马",
    "暗链",
)


@pytest.mark.parametrize("raw", BACKDOOR_ALIASES)
def test_backdoor_aliases_normalize_to_canonical_type(raw: str) -> None:
    assert normalize_vuln_type(raw) == "backdoor_compromised"


def test_backdoor_alias_set_contains_database_spellings() -> None:
    aliases = vuln_type_alias_set("网页被篡改")

    assert "backdoor_compromised" in aliases
    assert "webshell" in aliases
    assert "暗链" in aliases


def test_backdoor_aliases_deduplicate_the_same_endpoint() -> None:
    candidate = {
        "vuln_type": "backdoor_compromised",
        "title": "Example University - 首页被篡改",
        "target_url": "https://example.test/index.php",
        "raw_request": "GET /index.php HTTP/1.1\r\nHost: example.test\r\n\r\n",
    }
    history = [{
        "vuln_type": "webshell",
        "title": "Example University - 首页发现后门",
        "target_url": "https://example.test/index.php",
        "raw_request": "GET /index.php HTTP/1.1\r\nHost: example.test\r\n\r\n",
    }]

    duplicate, matches = is_duplicate(candidate, history)

    assert duplicate is True
    assert "同系统同 endpoint 同漏洞类型" in matches[0]["reason"]
