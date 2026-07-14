"""Bounded HTML/HTTP surface extraction for targeted follow-up validation."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin


_MAX_BODY = 1_000_000
_MAX_ITEMS = 80
_PATH_RE = re.compile(
    r"(?P<path>/(?:api|admin|manage|auth|oauth|user|account|file|upload|download|export|import|swagger|v[1-9])"
    r"[A-Za-z0-9_./{}?=&%:-]{0,240})",
    re.IGNORECASE,
)


class _SurfaceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.comments: list[str] = []
        self.generator = ""

    @staticmethod
    def _attrs(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
        return {str(key).lower(): str(value or "") for key, value in attrs}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = self._attrs(attrs)
        tag = tag.lower()
        if tag == "form":
            self._current_form = {
                "action": values.get("action", ""),
                "method": values.get("method", "GET").upper(),
                "enctype": values.get("enctype", "application/x-www-form-urlencoded"),
                "fields": [],
                "has_password": False,
                "has_file_input": False,
            }
            self.forms.append(self._current_form)
            return
        if tag in {"input", "select", "textarea", "button"} and self._current_form is not None:
            field_type = values.get("type", tag).lower()
            name = values.get("name") or values.get("id") or ""
            if name and len(self._current_form["fields"]) < 40:
                self._current_form["fields"].append({"name": name[:120], "type": field_type[:40]})
            self._current_form["has_password"] |= field_type == "password"
            self._current_form["has_file_input"] |= field_type == "file"
            return
        if tag == "script" and values.get("src"):
            self.scripts.append(values["src"])
        elif tag in {"a", "link", "iframe"} and values.get("href"):
            self.links.append(values["href"])
        elif tag == "iframe" and values.get("src"):
            self.links.append(values["src"])
        elif tag == "meta" and values.get("name", "").lower() == "generator":
            self.generator = values.get("content", "")[:160]

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._current_form = None

    def handle_comment(self, data: str) -> None:
        if len(self.comments) < 30:
            self.comments.append(data[:1000])


def _absolute(value: str, base_url: str) -> str:
    value = str(value or "").strip()
    if not value:
        return base_url
    return urljoin(base_url or "http://placeholder.invalid/", value) if base_url else value


def _candidate_score(url: str, method: str = "GET", *, file_input: bool = False) -> tuple[int, list[str]]:
    text = url.lower()
    score = 8 if method == "GET" else 20
    reasons: list[str] = []
    groups = (
        (("admin", "manage", "role", "permission"), 28, "管理/权限入口"),
        (("login", "auth", "oauth", "token", "password", "reset"), 22, "认证或凭证入口"),
        (("upload", "import", "file", "attachment"), 25, "文件处理入口"),
        (("export", "download", "backup", "report"), 20, "批量读取入口"),
        (("api/", "swagger", "openapi", "/v1", "/v2", "/v3"), 12, "API 入口"),
    )
    for markers, weight, reason in groups:
        if any(marker in text for marker in markers):
            score += weight
            reasons.append(reason)
    if file_input:
        score += 25
        reasons.append("包含文件选择字段")
    if "{" in text or re.search(r"[/=?](?:id|uid|user_id|tenant_id)=?", text):
        score += 12
        reasons.append("对象标识入口")
    return min(score, 100), list(dict.fromkeys(reasons))


def _headers(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key).lower(): str(item) for key, item in value.items()}


def extract_http_surface(
    body: str,
    base_url: str = "",
    response_headers: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Extract forms, assets, and prioritized endpoint candidates from HTML."""
    if not isinstance(body, str) or not body.strip():
        return {"ok": False, "error": "body 不能为空"}
    if len(body) > _MAX_BODY:
        return {"ok": False, "error": f"HTML 正文超过 {_MAX_BODY} 字符上限"}

    parser = _SurfaceParser()
    try:
        parser.feed(body)
        parser.close()
    except Exception as exc:
        return {"ok": False, "error": f"HTML 解析失败: {type(exc).__name__}: {exc}"}

    forms: list[dict[str, Any]] = []
    candidate_map: dict[tuple[str, str], dict[str, Any]] = {}
    for form in parser.forms[:_MAX_ITEMS]:
        item = dict(form)
        item["action"] = _absolute(item["action"], base_url)
        score, reasons = _candidate_score(
            item["action"], item["method"], file_input=item["has_file_input"]
        )
        item["risk_score"] = score
        item["risk_reasons"] = reasons
        forms.append(item)
        candidate_map[(item["method"], item["action"])] = {
            "method": item["method"],
            "url": item["action"],
            "source": "form",
            "risk_score": score,
            "risk_reasons": reasons,
        }

    links = list(dict.fromkeys(_absolute(item, base_url) for item in parser.links if item))[:_MAX_ITEMS]
    scripts = list(dict.fromkeys(_absolute(item, base_url) for item in parser.scripts if item))[:_MAX_ITEMS]
    for url in links:
        score, reasons = _candidate_score(url)
        if reasons:
            candidate_map.setdefault(("GET", url), {
                "method": "GET",
                "url": url,
                "source": "link",
                "risk_score": score,
                "risk_reasons": reasons,
            })

    discovery_text = body + "\n" + "\n".join(parser.comments)
    for match in _PATH_RE.finditer(discovery_text):
        url = _absolute(match.group("path"), base_url)
        score, reasons = _candidate_score(url)
        candidate_map.setdefault(("GET", url), {
            "method": "GET",
            "url": url,
            "source": "body",
            "risk_score": score,
            "risk_reasons": reasons,
        })
        if len(candidate_map) >= _MAX_ITEMS:
            break

    candidates = sorted(
        candidate_map.values(),
        key=lambda item: (-item["risk_score"], item["url"], item["method"]),
    )[:_MAX_ITEMS]
    headers = _headers(response_headers)
    present_security_headers = sorted(
        name for name in (
            "content-security-policy",
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy",
        )
        if name in headers
    )
    return {
        "ok": True,
        "content_type": headers.get("content-type", ""),
        "generator": parser.generator,
        "forms": forms,
        "links": links,
        "scripts": scripts,
        "candidates": candidates,
        "security_headers_present": present_security_headers,
        "guidance": (
            "优先从高分表单和候选路径选择一个最小验证点。脚本资源继续交给 analyze_javascript；"
            "API 文档正文交给 analyze_api_schema；页面或响应头现象本身不作为漏洞。"
        ),
    }
