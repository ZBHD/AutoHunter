from __future__ import annotations

import pytest

from app.engines.translator import (
    fofa_to_censys,
    fofa_to_hunter,
    fofa_to_quake,
    fofa_to_shodan,
    fofa_to_zoomeye,
    parse_fofa_query,
    translate_fofa_query,
)


def test_parse_preserves_boolean_joins() -> None:
    tokens, joins = parse_fofa_query('title="A" || title="B" && domain=".edu.cn"')

    assert len(tokens) == 3
    assert joins == ["||", "&&"]


def test_quake_uses_domain_and_boolean_words() -> None:
    query = fofa_to_quake('title="统一身份认证" && domain=".edu.cn"')

    assert 'title:"统一身份认证"' in query
    assert 'domain:"edu.cn"' in query
    assert " AND " in query
    assert "hostname" not in query
    assert " OR " in fofa_to_quake('title="A" || title="B"')


def test_hunter_uses_native_fields_and_strips_domain_dot() -> None:
    query = fofa_to_hunter('title="login" && domain=".example.com" && port="443"')

    assert 'web.title="login"' in query
    assert 'domain.suffix="example.com"' in query
    assert 'port="443"' in query
    assert "&&" in query


def test_zoomeye_uses_v2_fofa_style() -> None:
    assert fofa_to_zoomeye('title="cisco vpn" && country="CN"') == (
        'title="cisco vpn" && country="CN"'
    )
    assert 'hostname="www.example.com"' in fofa_to_zoomeye(
        'host="www.example.com"'
    )
    assert 'domain="edu.cn"' in fofa_to_zoomeye('domain=".edu.cn"')


def test_shodan_and_censys_use_native_filters() -> None:
    shodan = fofa_to_shodan('title="nginx" && domain=".edu.cn" && port="443"')
    assert "http.title:" in shodan
    assert 'hostname:"edu.cn"' in shodan
    assert "port:443" in shodan

    censys = fofa_to_censys('title="Login" && port="80"')
    assert "services.http.response.html_title" in censys
    assert "services.port:80" in censys
    assert " and " in censys


@pytest.mark.parametrize(
    ("engine", "native"),
    [
        ("quake", 'title:"already quake" AND port:80'),
        ("hunter", 'domain.suffix="edu.cn" && web.status_code="200"'),
        ("zoomeye", 'domain="edu.cn" && service="https"'),
        ("shodan", 'hostname:"edu.cn" port:443'),
        ("censys", 'services.port:443 and dns.names:"edu.cn"'),
    ],
)
def test_native_queries_are_passed_through(engine: str, native: str) -> None:
    assert translate_fofa_query(native, engine) == native


def test_fofa_and_unknown_text_are_unchanged() -> None:
    fofa = 'title="x" && domain=".edu.cn"'
    assert translate_fofa_query(fofa, "fofa") == fofa
    assert translate_fofa_query("find university login pages", "hunter") == (
        "find university login pages"
    )
