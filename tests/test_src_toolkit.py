from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.config import worker_config
from app.agents.escalate import EscalateHunter
from app.agents.history import bounded_tool_content
from app.agents.worker import Worker
from app.tools.executor import ToolExecutor
from app.tools.schemas import ESCALATE_TOOL_SCHEMAS, TOOL_SCHEMAS
from app.tools.src_toolkit import (
    SRC_TOOL_NAMES,
    SRC_TOOL_CATALOG,
    SrcParseResult,
    SrcToolError,
    ToolSpec,
    build_src_plan,
    parse_src_capture,
    parse_src_output,
)


def _tool_names(schemas: list[dict]) -> set[str]:
    return {item["function"]["name"] for item in schemas}


def test_src_tool_schemas_are_available_to_worker_and_escalation() -> None:
    assert SRC_TOOL_NAMES <= _tool_names(TOOL_SCHEMAS)
    assert SRC_TOOL_NAMES <= _tool_names(ESCALATE_TOOL_SCHEMAS)


def test_http_probe_builds_bounded_same_host_argv() -> None:
    plan = build_src_plan(
        "probe_http",
        {
            "url": "https://app.example.test/login?next=/home;marker=1",
            "follow_redirects": True,
            "rate_limit": 999,
            "request_timeout": 999,
            "headers": {"Authorization": "Bearer top-secret"},
        },
        scope_target="https://app.example.test",
    )

    assert plan.binary == "httpx"
    assert plan.argv[0] == "httpx"
    assert "https://app.example.test/login?next=/home;marker=1" in plan.argv
    assert plan.argv[plan.argv.index("-rate-limit") + 1] == "50"
    assert plan.argv[plan.argv.index("-timeout") + 1] == "30"
    assert "-follow-redirects" not in plan.argv
    assert plan.follow_redirects is True
    assert "Authorization: Bearer top-secret" in plan.argv
    assert "Bearer top-secret" not in plan.display_argv
    assert plan.timeout <= 180


def test_src_catalog_covers_tools_and_scanners_are_worker_only() -> None:
    assert SRC_TOOL_NAMES <= set(SRC_TOOL_CATALOG)
    assert all(isinstance(spec, ToolSpec) for spec in SRC_TOOL_CATALOG.values())
    for name in ("scan_nuclei", "verify_xss"):
        spec = SRC_TOOL_CATALOG[name]
        assert spec.roles == ("worker",)
        assert spec.enterprise_allowed is False


def test_src_parsers_normalize_all_supported_formats() -> None:
    httpx = parse_src_output(
        "probe_http",
        json.dumps({"url": "https://a.test/login?token=secret", "status_code": 200, "title": "Login"}),
    )
    assert httpx.parse_ok is True
    assert httpx.count == 1
    assert "secret" not in httpx.head_candidates[0].value
    assert httpx.head_candidates[0].kind == "fingerprint"

    katana = parse_src_output(
        "crawl_endpoints",
        "\n".join(
            [
                json.dumps({"request": {"endpoint": "https://a.test/api/users?id=1", "method": "GET"}}),
                json.dumps({"url": "https://a.test/assets/app.js", "status_code": 200}),
            ]
        ),
    )
    assert katana.count == 2
    assert all("id=1" not in candidate.value for candidate in katana.head_candidates)

    ffuf = parse_src_output(
        "discover_content",
        json.dumps({"results": [{"url": "https://a.test/admin?x=1", "status": 403}]}),
    )
    assert ffuf.count == 1
    assert ffuf.head_candidates[0].status_code == 403

    arjun = parse_src_output("discover_parameters", "GET https://a.test/api?id\nFound: page, sort")
    assert arjun.count >= 2
    assert any(candidate.kind == "parameter" for candidate in arjun.head_candidates)

    waf = parse_src_output(
        "fingerprint_waf",
        json.dumps({"url": "https://a.test", "firewall": "Example WAF", "detected": True}),
    )
    assert waf.count == 1
    assert waf.head_candidates[0].kind == "fingerprint"

    nmap = parse_src_output(
        "scan_web_ports",
        "80/tcp open http Apache httpd\n443/tcp open ssl/http nginx",
    )
    assert nmap.count == 2
    assert all(candidate.kind == "service" for candidate in nmap.head_candidates)


def test_src_parser_reports_empty_and_malformed_output() -> None:
    empty = parse_src_output("crawl_endpoints", "")
    assert isinstance(empty, SrcParseResult)
    assert empty.parse_ok is False
    assert empty.failure_kind == "empty"

    malformed = parse_src_output("crawl_endpoints", "{not json}")
    assert malformed.parse_ok is False
    assert malformed.failure_kind == "parse_error"
    assert malformed.parse_errors

    malformed_array = parse_src_output(
        "crawl_endpoints",
        '[{"url":"https://a.test/prefix"}',
    )
    assert malformed_array.parse_ok is True
    assert malformed_array.parse_errors

    malformed_ffuf_wrapper = parse_src_output(
        "discover_content",
        '{"results":[{"url":"https://a.test/admin"}]',
    )
    assert malformed_ffuf_wrapper.parse_ok is True
    assert malformed_ffuf_wrapper.parse_errors


def test_src_parser_preserves_head_tail_priority_and_scan_limit() -> None:
    output = "\n".join(
        json.dumps(
            {
                "url": f"https://a.test/api/{index}",
                "status_code": 200,
                "content_length": 1000 if index == 49999 else 10,
            }
        )
        for index in range(50010)
    )
    parsed = parse_src_output("crawl_endpoints", output)
    assert parsed.count == 50000
    assert parsed.head_candidates[0].value.endswith("/0")
    assert parsed.tail_candidates[-1].value.endswith("/49999")
    assert parsed.priority_candidates
    assert parsed.remaining_unknown is True
    assert parsed.omitted >= 10
    assert parsed.partial is True


def test_src_parser_omitted_counts_duplicate_occurrences_by_index() -> None:
    record = json.dumps({"url": "https://a.test/repeated", "status_code": 200})
    parsed = parse_src_output("crawl_endpoints", "\n".join([record] * 8))
    assert parsed.count == 8
    assert parsed.omitted == 2


@pytest.mark.parametrize("count,trailing,expected_count,partial", [
    (2, False, 2, False),
    (3, True, 3, False),
    (4, False, 3, True),
    (4, True, 3, True),
])
def test_src_parser_line_limit_treats_trailing_newline_as_terminator(
    monkeypatch, count: int, trailing: bool, expected_count: int, partial: bool,
) -> None:
    from app.tools import src_toolkit

    monkeypatch.setattr(src_toolkit, "_MAX_PARSE_LINES", 3)
    records = "\n".join(
        json.dumps({"url": f"https://a.test/line/{index}"})
        for index in range(count)
    )
    parsed = parse_src_output("crawl_endpoints", records + ("\n" if trailing else ""))
    assert parsed.count == expected_count
    assert parsed.partial is partial


def test_src_capture_reads_private_output_and_filters_scope(tmp_path: Path, monkeypatch) -> None:
    worker_root = tmp_path / "worker-root"
    monkeypatch.setattr(worker_config, "work_root", str(worker_root))
    capture_dir = worker_root / ".captures" / "cap-1"
    capture_dir.mkdir(parents=True)
    output_path = capture_dir / "stdout"
    output_path.write_text(
        "\n".join(
            [
                json.dumps({"url": "https://a.test/in-scope?secret=x", "status_code": 200}),
                json.dumps({"url": "https://other.test/out-of-scope", "status_code": 200}),
            ]
        ),
        encoding="utf-8",
    )
    capture = {
        "id": "cap-1",
        "directory": str(capture_dir),
        "channels": [{"name": "output", "path": str(output_path)}],
    }
    parsed = parse_src_capture("crawl_endpoints", capture, "https://a.test")
    assert parsed.count == 1
    assert parsed.head_candidates[0].value == "https://a.test/in-scope?secret="
    assert any("scope" in error for error in parsed.parse_errors)


def test_src_capture_requires_private_output_channel() -> None:
    parsed = parse_src_capture(
        "crawl_endpoints",
        {"output": json.dumps({"url": "https://a.test/preview"})},
        "https://a.test",
    )
    assert parsed.parse_ok is False
    assert parsed.failure_kind == "capture_unavailable"
    assert parsed.partial is True
    assert parsed.remaining_unknown is True


def test_src_capture_rejects_channel_outside_owned_directory(tmp_path: Path, monkeypatch) -> None:
    worker_root = tmp_path / "worker-root"
    monkeypatch.setattr(worker_config, "work_root", str(worker_root))
    owned = worker_root / ".captures" / "cap-2"
    owned.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.write_text(json.dumps({"url": "https://a.test/outside"}), encoding="utf-8")
    parsed = parse_src_capture(
        "crawl_endpoints",
        {
            "id": "cap-2",
            "directory": str(owned),
            "channels": [{"name": "output", "path": str(outside)}],
        },
        "https://a.test",
    )
    assert parsed.failure_kind == "capture_unavailable"


def test_arjun_scanning_output_keeps_url_scope_for_parameters() -> None:
    parsed = parse_src_output(
        "discover_parameters",
        "Scanning [1/1]: https://a.test/api/users\n[+] Valid parameter found: id",
    )
    assert parsed.count == 2
    parameter = next(item for item in parsed.head_candidates if item.kind == "parameter")
    assert "https://a.test/api/users" in parameter.endpoint_key
    assert parameter.parameter == "id"


def test_src_plan_rejects_cross_host_target() -> None:
    with pytest.raises(SrcToolError, match="当前目标") as exc:
        build_src_plan(
            "crawl_endpoints",
            {"url": "https://other.example.test/"},
            scope_target="https://app.example.test/",
        )
    assert exc.value.blocked is True


def test_katana_plan_is_same_host_and_resource_bounded() -> None:
    plan = build_src_plan(
        "crawl_endpoints",
        {"url": "https://app.example.test/", "depth": 9, "concurrency": 99, "rate_limit": 999},
        scope_target="https://app.example.test/",
    )

    assert plan.argv[:3] == ("katana", "-u", "https://app.example.test/")
    assert plan.argv[plan.argv.index("-depth") + 1] == "3"
    assert plan.argv[plan.argv.index("-concurrency") + 1] == "10"
    assert plan.argv[plan.argv.index("-rate-limit") + 1] == "50"
    assert plan.argv[plan.argv.index("-field-scope") + 1] == "fqdn"
    assert plan.argv[plan.argv.index("-crawl-scope") + 1].startswith("^https?://app\\.example\\.test")
    assert plan.argv[plan.argv.index("-max-domain-pages") + 1] == "200"
    assert "-jsonl" in plan.argv


def test_ffuf_plan_requires_fuzz_and_uses_curated_wordlist(tmp_path: Path) -> None:
    with pytest.raises(SrcToolError, match="FUZZ"):
        build_src_plan(
            "discover_content",
            {"url": "https://app.example.test/admin"},
            scope_target="https://app.example.test",
            wordlist_root=tmp_path,
        )

    plan = build_src_plan(
        "discover_content",
        {"url": "https://app.example.test/FUZZ", "wordlist": "api", "rate_limit": 500, "follow_redirects": True},
        scope_target="https://app.example.test",
        wordlist_root=tmp_path,
    )
    assert plan.binary == "ffuf"
    assert plan.argv[plan.argv.index("-w") + 1] == str(tmp_path / "src-api.txt")
    assert plan.argv[plan.argv.index("-rate") + 1] == "50"
    assert plan.argv[plan.argv.index("-maxtime") + 1] == "180"
    assert "-noninteractive" in plan.argv
    assert "-json" in plan.argv
    assert "-r" not in plan.argv


def test_arjun_plan_uses_small_wordlist_and_stable_limits(tmp_path: Path) -> None:
    plan = build_src_plan(
        "discover_parameters",
        {
            "url": "https://app.example.test/api/users",
            "method": "JSON",
            "threads": 99,
            "rate_limit": 999,
            "follow_redirects": True,
        },
        scope_target="https://app.example.test",
        wordlist_root=tmp_path,
    )
    assert plan.argv[0] == "arjun"
    assert plan.argv[plan.argv.index("-w") + 1] == str(tmp_path / "src-params.txt")
    assert plan.argv[plan.argv.index("-m") + 1] == "JSON"
    assert plan.argv[plan.argv.index("-t") + 1] == "5"
    assert plan.argv[plan.argv.index("--rate-limit") + 1] == "20"
    assert "--stable" in plan.argv
    assert "--disable-redirects" in plan.argv


def test_nuclei_requires_explicit_selector_and_builds_targeted_plan() -> None:
    with pytest.raises(SrcToolError, match="template/tags/template_id"):
        build_src_plan(
            "scan_nuclei",
            {"url": "https://app.example.test"},
            scope_target="https://app.example.test",
        )

    plan = build_src_plan(
        "scan_nuclei",
        {
            "url": "https://app.example.test",
            "tags": ["exposure", "misconfig"],
            "severity": ["medium", "high"],
            "rate_limit": 999,
        },
        scope_target="https://app.example.test",
    )
    assert plan.argv[plan.argv.index("-tags") + 1] == "exposure,misconfig"
    assert plan.argv[plan.argv.index("-severity") + 1] == "medium,high"
    assert plan.argv[plan.argv.index("-rate-limit") + 1] == "50"
    assert "-jsonl" in plan.argv
    assert "-disable-update-check" in plan.argv


def test_dalfox_requires_known_parameter_and_caps_payloads() -> None:
    with pytest.raises(SrcToolError, match="params"):
        build_src_plan(
            "verify_xss",
            {"url": "https://app.example.test/search?q=test"},
            scope_target="https://app.example.test",
        )

    plan = build_src_plan(
        "verify_xss",
        {"url": "https://app.example.test/search?q=test", "params": ["q"], "workers": 50},
        scope_target="https://app.example.test",
    )
    assert plan.argv[:3] == ("dalfox", "url", "--url")
    assert plan.argv[plan.argv.index("--workers") + 1] == "5"
    assert plan.argv[plan.argv.index("--max-payloads-per-param") + 1] == "200"
    assert "--skip-discovery" in plan.argv
    assert "--skip-mining" in plan.argv
    assert plan.timeout <= 240


def test_waf_and_web_port_plans_are_narrow() -> None:
    waf = build_src_plan(
        "fingerprint_waf",
        {"url": "https://app.example.test"},
        scope_target="https://app.example.test",
    )
    assert waf.argv == ("wafw00f", "https://app.example.test", "-a", "--no-colors", "-f", "json")

    ports = build_src_plan(
        "scan_web_ports",
        {"host": "app.example.test", "ports": [80, 443, 8080, 8443]},
        scope_target="https://app.example.test",
    )
    assert ports.argv[0] == "nmap"
    assert ports.argv[ports.argv.index("-p") + 1] == "80,443,8080,8443"
    assert "-sT" in ports.argv
    assert "-sV" in ports.argv
    assert "--host-timeout" in ports.argv

    with pytest.raises(SrcToolError, match="20"):
        build_src_plan(
            "scan_web_ports",
            {"host": "app.example.test", "ports": list(range(1, 22))},
            scope_target="https://app.example.test",
        )


def test_executor_runs_src_plan_without_shell_and_reports_missing_binary(monkeypatch, tmp_path: Path) -> None:
    executor = ToolExecutor("https://app.example.test", work_dir=str(tmp_path))
    monkeypatch.setattr("app.tools.executor.shutil.which", lambda _binary: "/usr/local/bin/httpx")
    captured: dict = {}

    def fake_run_process(command, **kwargs):
        captured["command"] = command
        captured.update(kwargs)
        return {"ok": True, "output": "{}"}

    monkeypatch.setattr(executor, "_run_process", fake_run_process)
    result = executor.run_src_tool(
        "probe_http",
        {"url": "https://app.example.test/?q=1;touch+/tmp/pwn"},
    )

    assert result["ok"] is False
    assert result["process_ok"] is True
    assert result["parse_ok"] is False
    assert result["failure_kind"] == "capture_unavailable"
    assert isinstance(captured["command"], list)
    assert captured["shell"] is False
    assert "https://app.example.test/?q=1;touch+/tmp/pwn" in captured["command"]

    monkeypatch.setattr("app.tools.executor.shutil.which", lambda _binary: None)
    missing = executor.run_src_tool(
        "crawl_endpoints",
        {"url": "https://app.example.test"},
    )
    assert missing["ok"] is False
    assert missing["missing_tool"] is True
    assert missing["tool"] == "crawl_endpoints"


def test_enterprise_src_hides_and_blocks_nuclei(monkeypatch, tmp_path: Path) -> None:
    from app.agents import worker as worker_module

    monkeypatch.setattr(worker_module.worker_config, "work_root", str(tmp_path))
    executor = ToolExecutor(
        "https://corp.example.test",
        work_dir=str(tmp_path),
        enterprise=True,
    )
    blocked = executor.run_src_tool(
        "scan_nuclei",
        {"url": "https://corp.example.test", "tags": ["exposure"]},
    )
    assert blocked["ok"] is False
    assert blocked["blocked"] is True
    assert blocked["kind"] == "enterprise_policy"

    worker = Worker(
        target="https://corp.example.test",
        llm=SimpleNamespace(),
        src_type="enterprise",
    )
    assert "scan_nuclei" not in _tool_names(worker._available_tool_schemas())

    hunter = EscalateHunter(
        {"target_url": "https://corp.example.test", "severity": "高危"},
        llm=SimpleNamespace(),
        src_type="enterprise",
    )
    assert "scan_nuclei" not in _tool_names(hunter._tools)


def test_worker_and_escalation_dispatch_src_tools(monkeypatch, tmp_path: Path) -> None:
    from app.agents import worker as worker_module

    monkeypatch.setattr(worker_module.worker_config, "work_root", str(tmp_path))
    worker = Worker(
        target="https://app.example.test",
        llm=SimpleNamespace(),
    )
    calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        worker.executor,
        "run_src_tool",
        lambda name, args: calls.append((name, args)) or {"ok": True},
    )
    result = worker._dispatch(
        "crawl_endpoints",
        {"url": "https://app.example.test"},
        rnd=2,
    )
    assert result["ok"] is True
    assert calls[-1][0] == "crawl_endpoints"

    hunter = EscalateHunter(
        {"target_url": "https://app.example.test", "severity": "高危"},
        llm=SimpleNamespace(),
    )
    monkeypatch.setattr(
        hunter.executor,
        "run_src_tool",
        lambda name, args: calls.append((name, args)) or {"ok": True},
    )
    result = hunter._dispatch(
        "scan_nuclei",
        {"url": "https://app.example.test", "tags": ["exposure"]},
    )
    assert result["ok"] is True
    assert calls[-1][0] == "scan_nuclei"


def test_recent_src_tool_output_is_bounded(monkeypatch) -> None:
    from app.agents import history as history_module

    monkeypatch.setattr(history_module.worker_config, "output_truncate", 700)
    monkeypatch.setattr(history_module.worker_config, "llm_tool_output_truncate", 700)
    result = {
        "ok": True,
        "tool": "crawl_endpoints",
        "return_code": 0,
        "output": "\n".join(
            json.dumps({"url": f"https://app.example.test/api/{index}", "raw": "x" * 80})
            for index in range(200)
        ),
    }
    content = bounded_tool_content(result, "crawl_endpoints")
    assert len(content) <= 700
    assert "crawl_endpoints" in content or "return_code" in content


def test_bundled_src_wordlists_are_small_and_present() -> None:
    root = Path(__file__).resolve().parents[1] / "wordlists"
    expected = {"src-common.txt", "src-api.txt", "src-params.txt"}
    assert expected <= {path.name for path in root.glob("src-*.txt")}
    for name in expected:
        entries = [
            line.strip()
            for line in (root / name).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        assert 20 <= len(entries) <= 250
        assert len(entries) == len(set(entries))


def test_docker_image_pins_new_src_cli_dependencies() -> None:
    root = Path(__file__).resolve().parents[1]
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    tool_requirements = (root / "requirements-tools.txt").read_text(encoding="utf-8")

    for marker in (
        "KATANA_VER=1.6.1",
        "FFUF_VER=2.2.1",
        "DALFOX_VER=3.1.2",
        "/usr/local/bin/katana",
        "/usr/local/bin/ffuf",
        "/usr/local/bin/dalfox",
    ):
        assert marker in dockerfile
    assert "arjun==2.2.7" in tool_requirements
    assert "wafw00f==2.4.2" in tool_requirements
    assert "requirements-tools.txt" in dockerfile


def test_docker_installs_projectdiscovery_httpx_after_python_httpx() -> None:
    """The Python httpx console script must not overwrite ProjectDiscovery httpx."""
    dockerfile = (
        Path(__file__).resolve().parents[1] / "Dockerfile"
    ).read_text(encoding="utf-8")

    pip_install = dockerfile.index("pip install --no-cache-dir")
    projectdiscovery_install = dockerfile.index(
        'unzip -oq "$HTTPX_ASSET" httpx -d /usr/local/bin/'
    )
    assert pip_install < projectdiscovery_install
    assert "RUN httpx -version" in dockerfile
