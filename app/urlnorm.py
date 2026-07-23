"""URL/host helpers that keep malformed and bare IPv6 inputs non-fatal."""
from __future__ import annotations

import ipaddress
from urllib.parse import ParseResult, urlparse


def _looks_like_ipv6(host: str) -> bool:
    value = (host or "").strip()
    if value.count(":") < 2 or "/" in value or "@" in value:
        return False
    if "." in value.split(":", 1)[0]:
        return False
    for segment in value.split(":"):
        if not segment:
            continue
        if len(segment) > 4:
            return False
        try:
            int(segment, 16)
        except ValueError:
            return False
    return True


def is_bare_ipv6(host: str) -> bool:
    value = (host or "").strip()
    if not value or value.startswith("["):
        return False
    try:
        ipaddress.IPv6Address(value)
        return True
    except Exception:
        return _looks_like_ipv6(value)


def is_valid_ipv6(host: str) -> bool:
    value = (host or "").strip().lstrip("[").rstrip("]")
    try:
        ipaddress.IPv6Address(value)
        return True
    except Exception:
        return False


def bracket_ipv6_host(host: str) -> str:
    value = (host or "").strip()
    return f"[{value}]" if is_bare_ipv6(value) else value


_EMPTY_PARSE = ParseResult("", "", "", "", "", "")


def ensure_scheme(url_or_host: str, default_scheme: str = "http") -> str:
    value = (url_or_host or "").strip()
    if not value or "://" in value:
        return value
    # Only valid IPv6 gets brackets.  Bracketing malformed values makes Python's
    # parser raise while the caller still needs a safe, inspectable result.
    host = f"[{value}]" if is_valid_ipv6(value) else value
    return f"{default_scheme}://{host}"


def safe_urlparse(url_or_host: str) -> ParseResult:
    try:
        return urlparse(ensure_scheme(url_or_host))
    except (TypeError, ValueError):
        return _EMPTY_PARSE


def safe_hostname(parsed_or_url) -> str:
    parsed = parsed_or_url if isinstance(parsed_or_url, ParseResult) else safe_urlparse(str(parsed_or_url))
    try:
        return (parsed.hostname or "").lower()
    except (TypeError, ValueError):
        return ""


def safe_port(parsed_or_url) -> int | None:
    parsed = parsed_or_url if isinstance(parsed_or_url, ParseResult) else safe_urlparse(str(parsed_or_url))
    try:
        return parsed.port
    except (TypeError, ValueError):
        return None


def has_invalid_port(parsed_or_url) -> bool:
    parsed = parsed_or_url if isinstance(parsed_or_url, ParseResult) else safe_urlparse(str(parsed_or_url))
    try:
        parsed.port
        return False
    except (TypeError, ValueError):
        return True


def is_unusable_host(url_or_host: str) -> bool:
    value = (url_or_host or "").strip()
    if not value:
        return True
    bare = value.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].strip("[]")
    if _looks_like_ipv6(bare) and not is_valid_ipv6(bare):
        return True
    return not bool(safe_hostname(value))


def normalize_host(url_or_host: str) -> str:
    parsed = safe_urlparse(url_or_host)
    host = safe_hostname(parsed)
    if not host:
        value = (url_or_host or "").strip().lower()
        return value.split("://", 1)[-1].split("/", 1)[0]
    display = f"[{host}]" if is_bare_ipv6(host) else host
    port = safe_port(parsed)
    return f"{display}:{port}" if port and port not in (80, 443) else display
