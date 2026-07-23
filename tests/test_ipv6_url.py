"""裸/畸形 IPv6 目标不应触发 urlparse 的 ValueError。"""
from __future__ import annotations

import importlib
import unittest

from app.urlnorm import (
    bracket_ipv6_host,
    ensure_scheme,
    is_bare_ipv6,
    is_unusable_host,
    is_valid_ipv6,
    normalize_host,
    safe_hostname,
    safe_port,
    safe_urlparse,
)

CRASH_IP = "250:4809:3:fcfc:feff:febc:b092"
GOOD_IP = "2001:db8::1"


class UrlNormTests(unittest.TestCase):
    def test_bare_ipv6_detection_and_validation(self):
        self.assertTrue(is_bare_ipv6(CRASH_IP))
        self.assertTrue(is_bare_ipv6(GOOD_IP))
        self.assertTrue(is_bare_ipv6("::1"))
        self.assertFalse(is_bare_ipv6("example.com"))
        self.assertFalse(is_bare_ipv6("1.2.3.4"))
        self.assertFalse(is_bare_ipv6("host:8080"))
        self.assertFalse(is_bare_ipv6("[::1]"))
        self.assertTrue(is_valid_ipv6(GOOD_IP))
        self.assertFalse(is_valid_ipv6(CRASH_IP))

    def test_malformed_ipv6_is_safe_and_unusable(self):
        parsed = safe_urlparse(CRASH_IP)
        self.assertIsNone(safe_port(parsed))
        safe_hostname(parsed)
        self.assertTrue(is_unusable_host(CRASH_IP))
        self.assertTrue(is_unusable_host(f"http://{CRASH_IP}"))

    def test_valid_ipv6_and_normal_hosts(self):
        self.assertFalse(is_unusable_host(GOOD_IP))
        self.assertEqual(normalize_host(f"http://[{GOOD_IP}]:8080/x"), f"[{GOOD_IP}]:8080")
        self.assertFalse(is_unusable_host("example.com"))
        self.assertFalse(is_unusable_host("1.2.3.4:9000"))
        self.assertEqual(normalize_host("Example.COM:8080"), "example.com:8080")
        self.assertEqual(normalize_host("http://example.com/a"), "example.com")

    def test_bracket_and_scheme_helpers(self):
        self.assertEqual(bracket_ipv6_host(CRASH_IP), f"[{CRASH_IP}]")
        self.assertEqual(bracket_ipv6_host("example.com"), "example.com")
        self.assertEqual(ensure_scheme("example.com"), "http://example.com")
        self.assertEqual(ensure_scheme("https://x.com/a"), "https://x.com/a")

    def test_hot_paths_do_not_raise(self):
        specs = (
            ("app.agents.collector", "normalize_host"),
            ("app.dedup", "normalize_host"),
            ("app.agents.killsweep", "_normalize_host"),
            ("app.agents.target_cluster", "_host_only"),
            ("app.orchestrator", "_with_scheme"),
            ("app.orchestrator", "_bracket_ipv6_host"),
            ("app.agents.auth_bootstrap", "_host"),
            ("app.agents.auth_bootstrap", "_hostport"),
        )
        for module_name, function_name in specs:
            try:
                function = getattr(importlib.import_module(module_name), function_name)
            except Exception:
                continue
            for value in (CRASH_IP, f"http://{CRASH_IP}", GOOD_IP):
                try:
                    function(value)
                except Exception as exc:  # pragma: no cover - failure detail
                    self.fail(f"{module_name}.{function_name} raised for {value!r}: {exc!r}")


if __name__ == "__main__":
    unittest.main()
