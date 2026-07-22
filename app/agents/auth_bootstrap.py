"""Task-bound authentication parsing, matching, and worker bootstrap helpers."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote_plus, urljoin, urlparse


_AUTH_HEADER_RE = re.compile(r"(?im)^\s*Authorization\s*:\s*(.+)$")
_COOKIE_HEADER_RE = re.compile(r"(?im)^\s*Cookie\s*:\s*(.+)$")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+(\S+)")
_USER_PASS_RE = re.compile(
    r"(?i)(?:用户名|账号|帐号|账户|username|user)\s*[:=：]\s*(\S+).{0,40}?"
    r"(?:密码|password|passwd|pwd)\s*[:=：]\s*(\S+)"
)
_SLASH_PAIR_RE = re.compile(r"^\s*([^\s/]{1,64})\s*/\s*([^\s]{1,128})\s*$")
_COOKIE_PAIR_RE = re.compile(r"^[A-Za-z0-9_.-]+=\S+")


def _strip(value: Any) -> str:
    return str(value or "").strip()


def parse_cookie_string(raw: str) -> dict[str, str]:
    text = re.sub(r"(?i)^Cookie\s*:\s*", "", _strip(raw)).strip()
    cookies: dict[str, str] = {}
    for part in text.split(";"):
        if "=" not in part:
            continue
        name, _, value = part.strip().partition("=")
        if name.strip():
            cookies[name.strip()] = value.strip()
    return cookies


def normalize_binding(raw: dict | None) -> dict[str, Any]:
    source = dict(raw or {})
    target = _strip(source.get("target")) or "*"
    username = _strip(source.get("username"))
    password = _strip(source.get("password"))
    cookie = _strip(source.get("cookie"))
    authorization = _strip(source.get("authorization") or source.get("Authorization"))
    login_url = _strip(source.get("login_url"))
    note = _strip(source.get("note"))
    blob = _strip(source.get("raw"))

    if blob:
        match = _AUTH_HEADER_RE.search(blob)
        if match and not authorization:
            authorization = match.group(1).strip()
        match = _COOKIE_HEADER_RE.search(blob)
        if match and not cookie:
            cookie = match.group(1).strip()
        match = _BEARER_RE.search(blob)
        if match and not authorization:
            authorization = f"Bearer {match.group(1)}"
        match = _USER_PASS_RE.search(blob)
        if match and not (username and password):
            username, password = match.group(1), match.group(2)
        first_line = blob.splitlines()[0].strip() if blob else ""
        pair = _SLASH_PAIR_RE.match(first_line)
        if pair and "=" not in first_line and not (username and password):
            username, password = pair.group(1), pair.group(2)
        if not cookie and _COOKIE_PAIR_RE.match(blob.split(";", 1)[0].strip()):
            cookie = blob

    cookies = parse_cookie_string(cookie)
    headers: dict[str, str] = {}
    if authorization:
        if not re.match(r"(?i)^\w+\s+", authorization):
            authorization = f"Bearer {authorization}"
        headers["Authorization"] = authorization

    kinds: list[str] = []
    if cookies:
        kinds.append("cookie")
    if headers:
        kinds.append("bearer")
    if username and password:
        kinds.append("password")
    return {
        "target": target,
        "username": username,
        "password": password,
        "cookie": cookie,
        "authorization": authorization,
        "login_url": login_url,
        "note": note,
        "cookies": cookies,
        "headers": headers,
        "kinds": kinds,
    }


def normalize_bindings(raw_list: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_list, list):
        return []
    return [
        binding
        for item in raw_list
        if isinstance(item, dict)
        for binding in [normalize_binding(item)]
        if binding["kinds"]
    ]


def has_any_bindings(raw_list: Any) -> bool:
    return bool(normalize_bindings(raw_list))


def _parsed_url(value: str):
    text = _strip(value)
    if not text:
        return urlparse("")
    return urlparse(text if "://" in text else f"http://{text}")


def _normalized_url(value: str) -> str:
    parsed = _parsed_url(value)
    if not parsed.hostname:
        return ""
    path = parsed.path.rstrip("/")
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"


def _host(value: str) -> str:
    return (_parsed_url(value).hostname or "").lower()


def _hostport(value: str) -> str:
    parsed = _parsed_url(value)
    host = (parsed.hostname or "").lower()
    if not host:
        return ""
    return f"{host}:{parsed.port}" if parsed.port else host


@dataclass
class MatchResult:
    matched: bool
    matched_by: str = ""
    binding_target: str = ""
    context: dict[str, Any] = field(default_factory=dict)


def _merge_contexts(bindings: list[dict[str, Any]]) -> dict[str, Any]:
    cookies: dict[str, str] = {}
    headers: dict[str, str] = {}
    kinds: list[str] = []
    username = password = login_url = ""
    for binding in bindings:
        cookies.update(binding.get("cookies") or {})
        headers.update(binding.get("headers") or {})
        if binding.get("username") and binding.get("password"):
            username = binding["username"]
            password = binding["password"]
        if binding.get("login_url"):
            login_url = binding["login_url"]
        for kind in binding.get("kinds") or []:
            if kind not in kinds:
                kinds.append(kind)
    return {
        "username": username,
        "password": password,
        "cookies": cookies,
        "headers": headers,
        "login_url": login_url,
        "kinds": kinds,
        "cookie_names": sorted(cookies),
        "header_names": sorted(headers),
    }


def match_auth_to_target(
    url: str,
    bindings: list[dict[str, Any]] | Any,
    manual_lines: list[str] | None = None,
) -> MatchResult:
    normalized = normalize_bindings(bindings)
    if not normalized:
        return MatchResult(matched=False)

    target_url = _normalized_url(url)
    target_host = _host(url)
    target_hostport = _hostport(url)
    lines = [_strip(line) for line in (manual_lines or []) if _strip(line)]
    line_urls = {_normalized_url(line) for line in lines}
    buckets: dict[str, list[dict[str, Any]]] = {
        "url": [], "line": [], "hostport": [], "host": [], "default": [],
    }
    has_explicit = any(binding.get("target") != "*" for binding in normalized)
    for binding in normalized:
        key = _strip(binding.get("target")) or "*"
        if key == "*":
            if not has_explicit:
                buckets["default"].append(binding)
            continue
        normalized_key = _normalized_url(key)
        if normalized_key == target_url:
            buckets["url"].append(binding)
        elif normalized_key in line_urls and _host(key) == target_host:
            buckets["line"].append(binding)
        elif _hostport(key) == target_hostport:
            buckets["hostport"].append(binding)
        elif _host(key) == target_host:
            buckets["host"].append(binding)

    for label in ("url", "line", "hostport", "host", "default"):
        chosen = buckets[label]
        if chosen:
            return MatchResult(
                matched=True,
                matched_by=label,
                binding_target=_strip(chosen[0].get("target")) or "*",
                context=_merge_contexts(chosen),
            )
    return MatchResult(matched=False)


def resolve_auth_context_for_target(
    task_bindings: Any,
    url: str,
    manual_lines: list[str] | None = None,
) -> dict[str, Any] | None:
    match = match_auth_to_target(url, task_bindings, manual_lines)
    if not match.matched:
        return None
    return {
        **match.context,
        "matched": True,
        "matched_by": match.matched_by,
        "binding_target": match.binding_target,
    }


@dataclass
class AuthAttemptResult:
    used: bool
    matched: bool
    status: str
    kinds: list[str] = field(default_factory=list)
    matched_by: str = ""
    binding_target: str = ""
    reason: str = ""
    cookie_names: list[str] = field(default_factory=list)
    header_names: list[str] = field(default_factory=list)

    def as_event(self) -> dict[str, Any]:
        return {
            "used": bool(self.used),
            "matched": bool(self.matched),
            "status": self.status,
            "kinds": list(self.kinds),
            "matched_by": self.matched_by,
            "binding_target": self.binding_target,
            "reason": self.reason[:300],
            "cookie_names": list(self.cookie_names),
            "header_names": list(self.header_names),
        }

    def as_status(self) -> dict[str, Any]:
        return self.as_event()


def _same_origin(left: str, right: str) -> bool:
    a, b = _parsed_url(left), _parsed_url(right)
    if not a.hostname or not b.hostname:
        return False

    def port(parsed):
        return parsed.port or (443 if parsed.scheme.lower() == "https" else 80)

    try:
        return (
            a.scheme.lower(), a.hostname.lower(), port(a)
        ) == (
            b.scheme.lower(), b.hostname.lower(), port(b)
        )
    except ValueError:
        return False


def _extract_login_form(html: str, page_url: str) -> dict[str, Any] | None:
    for form_html in re.findall(r"(?is)<form\b[^>]*>.*?</form>", html or ""):
        if not re.search(r"(?i)type=[\"']?password", form_html):
            continue
        action_match = re.search(
            r"(?is)<form\b[^>]*\baction=[\"']([^\"']*)[\"']", form_html
        )
        action = urljoin(page_url, (action_match.group(1) if action_match else "") or page_url)
        fields: dict[str, str] = {}
        for input_match in re.finditer(r"(?is)<input\b[^>]*>", form_html):
            tag = input_match.group(0)
            name_match = re.search(r"\bname=[\"']([^\"']+)[\"']", tag, re.I)
            if not name_match:
                continue
            value_match = re.search(r"\bvalue=[\"']([^\"']*)[\"']", tag, re.I)
            fields[name_match.group(1)] = value_match.group(1) if value_match else ""
        return {"action": action, "fields": fields}
    return None


def _judge_login_success(executor: Any, result: dict, form_url: str) -> dict[str, Any]:
    if not result.get("ok"):
        return {"ok": False, "reason": "登录请求失败"}
    status = int(result.get("status_code") or 0)
    body = _strip(result.get("body") or result.get("response_body")).lower()
    final_url = _strip(result.get("final_url") or result.get("url"))
    if status in {401, 403} or re.search(
        r"验证码|captcha|密码错误|用户名或密码|login failed|invalid (user|password)|认证失败",
        body,
    ):
        return {"ok": False, "reason": f"登录失败（HTTP {status}）"}
    cookies = getattr(executor, "_session_cookies", {}) or {}
    session_cookie = any(
        re.search(r"(?i)session|token|jwt|auth", str(name)) for name in cookies
    )
    redirected = bool(final_url and final_url.rstrip("/") != form_url.rstrip("/"))
    structured_success = bool(
        re.search(r'"(?:code|status|success)"\s*:\s*(?:200|0|true|"ok")', body)
    )
    if session_cookie or redirected or structured_success:
        return {"ok": True, "reason": "已观察到登录后的会话或跳转"}
    return {"ok": False, "reason": "登录后未观察到有效会话或跳转"}


def try_user_login(
    executor: Any,
    base_url: str,
    username: str,
    password: str,
    login_url: str = "",
) -> dict[str, Any]:
    base = _strip(base_url)
    if not base:
        return {"ok": False, "reason": "无目标 URL"}
    if "://" not in base:
        base = f"http://{base}"
    page_url = urljoin(base, login_url) if login_url else base
    if login_url and not _same_origin(base, page_url):
        return {"ok": False, "reason": "登录 URL 与目标不同源"}

    try:
        page = executor.http_request(
            page_url, method="GET", follow_redirects=True, timeout=15
        )
    except Exception:
        return {"ok": False, "reason": "打开登录页失败"}
    if not page.get("ok"):
        return {"ok": False, "reason": "打开登录页失败"}
    form = _extract_login_form(
        _strip(page.get("body") or page.get("response_body")), page_url
    )
    if not form:
        return {"ok": False, "reason": "目标入口页未发现密码表单"}
    if not _same_origin(base, form["action"]):
        return {"ok": False, "reason": "登录表单提交目标与任务目标不同源"}

    data = dict(form["fields"])
    user_fields = [
        key for key in data if re.search(r"(?i)user|account|login|email|name", key)
    ]
    password_fields = [key for key in data if re.search(r"(?i)pass|pwd", key)]
    user_field = user_fields[0] if user_fields else "username"
    password_field = password_fields[0] if password_fields else "password"
    data[user_field] = username
    data[password_field] = password
    encoded = "&".join(
        f"{quote_plus(str(key))}={quote_plus(str(value))}" for key, value in data.items()
    )
    try:
        response = executor.http_request(
            form["action"],
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=encoded,
            follow_redirects=True,
            timeout=20,
        )
    except Exception:
        return {"ok": False, "reason": "登录请求失败"}
    return _judge_login_success(executor, response, page_url)


def bootstrap_auth(
    executor: Any,
    auth_context: dict | None,
    base_url: str,
) -> AuthAttemptResult:
    context = dict(auth_context or {})
    kinds = list(context.get("kinds") or [])
    cookies = dict(context.get("cookies") or {})
    headers = dict(context.get("headers") or {})
    username = _strip(context.get("username"))
    password = _strip(context.get("password"))
    matched_by = _strip(context.get("matched_by"))
    binding_target = _strip(context.get("binding_target"))
    if not kinds:
        kinds.extend(kind for kind, present in (
            ("cookie", bool(cookies)),
            ("bearer", bool(headers)),
            ("password", bool(username and password)),
        ) if present)
    if context.get("matched") is False or not kinds:
        return AuthAttemptResult(
            used=False,
            matched=False,
            status="unused",
            reason="凭据未匹配或为空",
            matched_by=matched_by,
            binding_target=binding_target,
        )

    if cookies or headers:
        try:
            set_result = executor.session_set(
                cookies=cookies or None, headers=headers or None
            )
        except Exception:
            set_result = {"ok": False}
        if not set_result.get("ok"):
            return AuthAttemptResult(
                used=True,
                matched=True,
                status="login_fail",
                kinds=kinds,
                matched_by=matched_by,
                binding_target=binding_target,
                reason="会话注入失败",
                cookie_names=sorted(cookies),
                header_names=sorted(headers),
            )
    if not (username and password):
        return AuthAttemptResult(
            used=True,
            matched=True,
            status="injected",
            kinds=kinds,
            matched_by=matched_by,
            binding_target=binding_target,
            reason="已注入任务提供的会话信息",
            cookie_names=sorted(cookies),
            header_names=sorted(headers),
        )

    login = try_user_login(
        executor, base_url, username, password, _strip(context.get("login_url"))
    )
    return AuthAttemptResult(
        used=True,
        matched=True,
        status="login_ok" if login.get("ok") else "login_fail",
        kinds=kinds,
        matched_by=matched_by,
        binding_target=binding_target,
        reason=_strip(login.get("reason"))[:300],
        cookie_names=sorted(getattr(executor, "_session_cookies", {}) or {}),
        header_names=sorted(getattr(executor, "_session_headers", {}) or {}),
    )


def format_auth_status_message(result: AuthAttemptResult | dict) -> str:
    data = result.as_event() if isinstance(result, AuthAttemptResult) else dict(result)
    kinds = ",".join(data.get("kinds") or []) or "-"
    status = data.get("status") or "unused"
    return f"凭据[{kinds}]：{status}；{data.get('reason') or ''}".strip("；")


def user_auth_prompt_block(auth_context: dict | None, attempt: dict | None = None) -> str:
    context = dict(auth_context or {})
    if not context and not attempt:
        return ""
    lines = ["# 用户提供的登录上下文（登录成功本身不构成漏洞）"]
    if context.get("kinds"):
        lines.append(f"- 类型：{', '.join(context['kinds'])}")
    if context.get("binding_target"):
        lines.append(
            f"- 绑定：{context['binding_target']}（{context.get('matched_by') or '-'}）"
        )
    if context.get("cookie_names"):
        lines.append(f"- Cookie 名：{', '.join(context['cookie_names'])}")
    if context.get("header_names"):
        lines.append(f"- Header 名：{', '.join(context['header_names'])}")
    if context.get("username"):
        lines.append(f"- 账号：{context['username']}（密码由系统持有，禁止回显）")
    if attempt:
        lines.append(f"- 启动状态：{attempt.get('status') or 'unused'}")
    lines.append("使用现有登录态继续验证鉴权边界和实际业务影响。")
    return "\n".join(lines) + "\n\n"
