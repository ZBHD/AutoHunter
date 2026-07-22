"""FOFA 语法解析器：将 FOFA 查询语法解析为结构化中间表示，再翻译成各引擎语法。"""
from __future__ import annotations

import re
from typing import Any


# ── FOFA 词法分析 ─────────────────────────────────────────────

_TOKEN_RE = re.compile(
    r'([a-zA-Z_][\w.]*)\s*(!=~|!=|=~|==|=)\s*'
    r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^\s&|()]+)'
)

class FofaToken:
    """单个 FOFA 查询条件。"""
    def __init__(self, field: str, op: str, value: str):
        self.field = field.lower().strip()   # title, body, domain, host, ip, port, org, ...
        self.op = op                          # = , !=, =~, !=~
        self.value = value.strip().strip('"').strip("'")

    def __repr__(self) -> str:
        return f"{self.field}{self.op}\"{self.value}\""


class FofaGroup:
    """一组用 && 或 || 连接的 FOFA 条件。"""
    def __init__(self):
        self.tokens: list[FofaToken | FofaGroup] = []
        self.op: str = "&&"  # 连接符


def parse_fofa_query(query: str) -> tuple[list[dict[str, str]], list[str]]:
    """解析常见 FOFA 条件，并保留条件间的逻辑连接。"""
    matches = list(_TOKEN_RE.finditer((query or "").strip()))
    if not matches:
        return [], []

    tokens: list[dict[str, str]] = []
    joins: list[str] = []
    for index, match in enumerate(matches):
        raw_value = match.group(3)
        if raw_value[:1] in {'"', "'"} and raw_value[-1:] == raw_value[:1]:
            value = raw_value[1:-1]
        else:
            value = raw_value
        tokens.append({
            "field": match.group(1).lower().strip(),
            "op": match.group(2),
            "value": value.replace(r'\"', '"').replace(r"\'", "'"),
        })
        if index:
            between = query[matches[index - 1].end():match.start()]
            joins.append("||" if "||" in between else "&&")
    return tokens, joins


def _tokenize_fofa(query: str) -> list[dict[str, Any]]:
    return list(parse_fofa_query(query)[0])


def _join_parts(parts: list[str], joins: list[str], and_word: str, or_word: str) -> str:
    if not parts:
        return ""
    output = [parts[0]]
    for index, part in enumerate(parts[1:]):
        join = joins[index] if index < len(joins) else "&&"
        output.extend((f" {or_word if join == '||' else and_word} ", part))
    return "".join(output)


def _render_parenthesized_query(
    query: str,
    token_pieces: list[str | None],
    and_word: str,
    or_word: str,
) -> str | None:
    """Render explicit FOFA parentheses without changing their precedence.

    The legacy flat renderer intentionally remains the fast path for ordinary
    queries.  This parser is used only when parentheses are present, where a
    flat join can turn ``(a || b) && c`` into ``a || (b && c)``.
    """
    if "(" not in query and ")" not in query:
        return None
    matches = list(_TOKEN_RE.finditer((query or "").strip()))
    if len(matches) != len(token_pieces):
        return None

    units: list[tuple[str, int | str]] = []
    previous = 0
    for index, match in enumerate(matches):
        between = query[previous:match.start()]
        cursor = 0
        for separator in re.finditer(r"\s*(\&\&|\|\||[()])", between):
            if between[cursor:separator.start()].strip():
                return None
            units.append(("op", separator.group(1)))
            cursor = separator.end()
        if between[cursor:].strip():
            return None
        units.append(("term", index))
        previous = match.end()
    tail = query[previous:]
    cursor = 0
    for separator in re.finditer(r"\s*(\&\&|\|\||[()])", tail):
        if tail[cursor:separator.start()].strip():
            return None
        units.append(("op", separator.group(1)))
        cursor = separator.end()
    if tail[cursor:].strip():
        return None

    position = 0

    def parse_primary():
        nonlocal position
        if position >= len(units):
            return None
        kind, value = units[position]
        if kind == "term":
            position += 1
            return ("term", int(value))
        if value != "(":
            return None
        position += 1
        node = parse_or()
        if position >= len(units) or units[position] != ("op", ")"):
            return None
        position += 1
        return node

    def parse_and():
        nonlocal position
        node = parse_primary()
        while node is not None and position < len(units) and units[position] == ("op", "&&"):
            position += 1
            right = parse_primary()
            if right is None:
                return None
            node = ("and", node, right)
        return node

    def parse_or():
        nonlocal position
        node = parse_and()
        while node is not None and position < len(units) and units[position] == ("op", "||"):
            position += 1
            right = parse_and()
            if right is None:
                return None
            node = ("or", node, right)
        return node

    tree = parse_or()
    if tree is None or position != len(units):
        return None

    def render(node):
        if node[0] == "term":
            return token_pieces[node[1]]
        left = render(node[1])
        right = render(node[2])
        if left is None:
            return right
        if right is None:
            return left
        word = or_word if node[0] == "or" else and_word
        return f"({left} {word} {right})"

    return render(tree)


def _strip_domain_dot(value: str) -> str:
    return (value or "").strip().lstrip(".")


# ── 各引擎翻译 ────────────────────────────────────────────────

# FOFA 字段 → Quake 字段映射
_FOFA_TO_QUAKE = {
    "title": "title",
    "body": "body",
    "domain": "domain",
    "host": "hostname",
    "ip": "ip",
    "port": "port",
    "org": "org",
    "protocol": "service",
    "server": "server",
    "country": "country",
    "city": "city",
    "header": "headers",
    "app": "app",
    "os": "os",
    "cert.subject.org": "cert",
    # 以下字段 Quake 不直接支持，用近似字段
    "icon_hash": "",
    "after": "",
    "before": "",
}


def fofa_to_quake(query: str) -> str:
    """将 FOFA 语法翻译为 360 Quake 语法。"""
    tokens, joins = parse_fofa_query(query)
    if not tokens:
        return query

    parts: list[str] = []
    kept_joins: list[str] = []
    token_pieces: list[str | None] = []
    for index, t in enumerate(tokens):
        f = _FOFA_TO_QUAKE.get(t["field"], t["field"])
        if not f:
            token_pieces.append(None)
            continue
        op = t["op"]
        v = t["value"]
        if t["field"] in {"domain", "host"}:
            v = _strip_domain_dot(v)
        if t["field"] == "port":
            v = v.lstrip("0") or "0"
            piece = f"{f}:{v}"
        elif op in ("=", "=~"):
            piece = f'{f}:"{v}"'
        elif op in ("!=", "!=~"):
            piece = f'NOT {f}:"{v}"'
        else:
            token_pieces.append(None)
            continue
        token_pieces.append(piece)
        if parts:
            kept_joins.append(joins[index - 1] if index - 1 < len(joins) else "&&")
        parts.append(piece)
    grouped = _render_parenthesized_query(query, token_pieces, "AND", "OR")
    return grouped or _join_parts(parts, kept_joins, "AND", "OR") or query


# FOFA 字段 → Hunter 字段映射
_FOFA_TO_HUNTER = {
    "title": "web.title",
    "body": "web.body",
    "domain": "domain.suffix",
    "host": "host",
    "ip": "ip",
    "port": "port",
    "org": "ip.company",
    "protocol": "protocol",
    "server": "header.server",
    "country": "ip.country",
    "city": "ip.city",
    "app": "web.app",
    "header": "header",
    "cert.subject.org": "cert.subject",
}


def fofa_to_hunter(query: str) -> str:
    """将 FOFA 语法翻译为 Hunter (鹰图) 语法。"""
    tokens, joins = parse_fofa_query(query)
    if not tokens:
        return query

    parts: list[str] = []
    kept_joins: list[str] = []
    token_pieces: list[str | None] = []
    for index, t in enumerate(tokens):
        f = _FOFA_TO_HUNTER.get(t["field"], t["field"])
        op = t["op"]
        v = t["value"]
        if t["field"] in {"domain", "host"}:
            v = _strip_domain_dot(v)
        if t["field"] == "port":
            piece = f'{f}="{v}"' if op not in ("!=", "!=~") else f'{f}!="{v}"'
        elif op == "==":
            piece = f'{f}=="{v}"'
        elif op in ("=", "=~"):
            piece = f'{f}="{v}"'
        elif op in ("!=", "!=~"):
            piece = f'{f}!="{v}"'
        else:
            token_pieces.append(None)
            continue
        token_pieces.append(piece)
        if parts:
            kept_joins.append(joins[index - 1] if index - 1 < len(joins) else "&&")
        parts.append(piece)
    grouped = _render_parenthesized_query(query, token_pieces, "&&", "||")
    return grouped or _join_parts(parts, kept_joins, "&&", "||") or query


# FOFA 字段 → ZoomEye 字段映射
_FOFA_TO_ZOOMEYE = {
    "title": "title",
    "body": "body",
    "domain": "domain",
    "host": "hostname",
    "ip": "ip",
    "port": "port",
    "org": "org",
    "protocol": "service",
    "server": "server",
    "country": "country",
    "city": "city",
    "app": "app",
    "header": "header",
    "os": "os",
}


def fofa_to_zoomeye(query: str) -> str:
    """将 FOFA 语法翻译为 ZoomEye 语法。"""
    tokens, joins = parse_fofa_query(query)
    if not tokens:
        return query

    parts: list[str] = []
    kept_joins: list[str] = []
    token_pieces: list[str | None] = []
    for index, t in enumerate(tokens):
        f = _FOFA_TO_ZOOMEYE.get(t["field"], t["field"])
        op = t["op"]
        v = t["value"]
        if t["field"] in {"domain", "host"}:
            v = _strip_domain_dot(v)
        if t["field"] == "port":
            piece = f'{f}={v}' if op not in ("!=", "!=~") else f'{f}!={v}'
        elif op == "==":
            piece = f'{f}=="{v}"'
        elif op in ("=", "=~"):
            piece = f'{f}="{v}"'
        elif op in ("!=", "!=~"):
            piece = f'{f}!="{v}"'
        else:
            token_pieces.append(None)
            continue
        token_pieces.append(piece)
        if parts:
            kept_joins.append(joins[index - 1] if index - 1 < len(joins) else "&&")
        parts.append(piece)
    grouped = _render_parenthesized_query(query, token_pieces, "&&", "||")
    return grouped or _join_parts(parts, kept_joins, "&&", "||") or query


# FOFA 字段 → Shodan 字段映射
_FOFA_TO_SHODAN = {
    "title": "http.title",
    "body": "http.html",
    "domain": "hostname",
    "host": "hostname",
    "ip": "net",
    "port": "port",
    "org": "org",
    "protocol": "",
    "server": "product",
    "country": "country",
    "city": "city",
    "app": "product",
    "os": "os",
    "header": "http.component",
    "cert.subject.org": "ssl.cert.subject.cn",
    "cert.issuer.org": "ssl.cert.issuer.cn",
}


def fofa_to_shodan(query: str) -> str:
    """将 FOFA 语法翻译为 Shodan 语法。"""
    tokens, joins = parse_fofa_query(query)
    if not tokens:
        return query

    groups: list[list[str]] = [[]]
    token_pieces: list[str | None] = []
    for index, t in enumerate(tokens):
        if index and joins[index - 1] == "||":
            groups.append([])
        f = _FOFA_TO_SHODAN.get(t["field"], t["field"])
        if not f:
            token_pieces.append(None)
            continue
        op = t["op"]
        v = t["value"]
        if t["field"] in {"domain", "host"}:
            v = _strip_domain_dot(v)
        if t["field"] == "port":
            piece = f'{f}:{v}'
        elif op in ("=", "=~"):
            piece = f'{f}:"{v}"'
        elif op in ("!=", "!=~"):
            piece = f'-{f}:"{v}"'
        else:
            token_pieces.append(None)
            continue
        token_pieces.append(piece)
        groups[-1].append(piece)
    grouped = _render_parenthesized_query(query, token_pieces, "", "OR")
    if grouped:
        return re.sub(r"\s{2,}", " ", grouped)
    rendered = [" ".join(group) for group in groups if group]
    return " OR ".join(rendered) or query


# FOFA 字段 → Censys 字段映射
_FOFA_TO_CENSYS = {
    "title": "services.http.response.html_title",
    "body": "services.http.response.body",
    "domain": "dns.names",
    "host": "dns.names",
    "ip": "ip",
    "port": "services.port",
    "org": "autonomous_system.name",
    "protocol": "services.service_name",
    "server": "services.http.response.headers.server",
    "country": "location.country",
    "city": "location.city",
    "app": "services.software.product",
    "os": "services.software.operating_system",
    "cert.subject.org": "services.tls.certificates.leaf_data.subject.organization",
    "cert.issuer.org": "services.tls.certificates.leaf_data.issuer.organization",
}


def fofa_to_censys(query: str) -> str:
    """将 FOFA 语法翻译为 Censys 语法。"""
    tokens, joins = parse_fofa_query(query)
    if not tokens:
        return query

    parts: list[str] = []
    kept_joins: list[str] = []
    token_pieces: list[str | None] = []
    for index, t in enumerate(tokens):
        f = _FOFA_TO_CENSYS.get(t["field"], t["field"])
        op = t["op"]
        v = t["value"]
        if t["field"] in {"domain", "host"}:
            v = _strip_domain_dot(v)
        if t["field"] == "port":
            v = v.lstrip("0") or "0"
            piece = f'{f}:{v}'
        elif op in ("=", "=~"):
            piece = f'{f}:"{v}"'
        elif op in ("!=", "!=~"):
            piece = f'not {f}:"{v}"'
        else:
            token_pieces.append(None)
            continue
        token_pieces.append(piece)
        if parts:
            kept_joins.append(joins[index - 1] if index - 1 < len(joins) else "&&")
        parts.append(piece)
    grouped = _render_parenthesized_query(query, token_pieces, "and", "or")
    return grouped or _join_parts(parts, kept_joins, "and", "or") or query


# ── 引擎分发表 ────────────────────────────────────────────────

_FOFA_TRANSLATORS = {
    "quake": fofa_to_quake,
    "hunter": fofa_to_hunter,
    "zoomeye": fofa_to_zoomeye,
    "shodan": fofa_to_shodan,
    "censys": fofa_to_censys,
}


_NATIVE_MARKERS: dict[str, tuple[str, ...]] = {
    "quake": (" AND ", " OR ", "title:", "domain:", "hostname:", "service:"),
    "hunter": ("web.", "domain.suffix", "ip.company", "header.server", "icp.number"),
    "zoomeye": ("service=", "hostname=", "iconhash=", "ssl="),
    "shodan": ("http.title:", "hostname:", "port:", "country:", "net:"),
    "censys": ("services.", "dns.", "autonomous_system.", " and ", " or "),
}


def looks_like_native_syntax(engine: str, query: str) -> bool:
    text = query or ""
    return any(marker in text for marker in _NATIVE_MARKERS.get(engine, ()))


def looks_like_fofa_syntax(query: str) -> bool:
    return bool(parse_fofa_query(query)[0])


def translate_fofa_query(query: str, target_engine: str) -> str:
    """将 FOFA 语法翻译为目标引擎语法。若目标引擎为 fofa 则原样返回。"""
    engine = (target_engine or "fofa").strip().lower()
    if not query or engine in {"", "fofa"}:
        return query
    if looks_like_native_syntax(engine, query) or not looks_like_fofa_syntax(query):
        return query
    translator = _FOFA_TRANSLATORS.get(engine)
    if translator is None:
        return query
    try:
        return translator(query)
    except Exception:
        return query
