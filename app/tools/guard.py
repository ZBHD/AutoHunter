"""命令安全防护：拦截运行环境破坏和企业模式不允许的扫描命令。

设计原则（对应设计文档 §11.1）：
- EduSRC/靶场保留原有攻击验证能力，只拦会搞垮容器/本机的自毁操作。
- 企业 SRC 额外拦截 Nuclei 类自动化漏洞扫描器，要求回到单请求和响应差异验证。
"""
from __future__ import annotations

import math
import re
import shlex
from collections.abc import Mapping
from urllib.parse import urlsplit


_MAX_ENTERPRISE_VALUE = 16 * 1024
ENTERPRISE_ALLOWED_PARSERS: dict[str, tuple[str, ...]] = {
    mode: ("python", "-m", "app.tools.local_parsers", mode)
    for mode in ("json", "headers", "urlencode")
}

# 会自毁运行环境的命令模式（大小写不敏感）。仅拦这些，不拦攻击。
_SELF_DESTRUCT_PATTERNS = [
    r"\brm\s+-rf\s+(/|/\*|~|\$HOME)\b",          # 删根目录/家目录
    r"\brm\s+-rf\s+--no-preserve-root",
    r":\(\)\s*\{\s*:\|:&\s*\}\s*;",               # fork 炸弹
    r"\bmkfs\b",                                   # 格式化
    r"\bdd\s+if=.*of=/dev/(sd|disk|nvme)",        # 覆写磁盘
    r">\s*/dev/(sd|disk|nvme)",
    r"\bshutdown\b", r"\breboot\b", r"\bhalt\b", r"\bpoweroff\b",
    r"\binit\s+0\b", r"\binit\s+6\b",
    # 关闭本机/容器内的依赖服务（会让平台自身挂掉）
    r"\b(systemctl|service)\s+(stop|disable)\s+(redis|postgres|postgresql)\b",
    r"\b(redis-cli\s+shutdown)\b",
    r"\bpg_ctl\s+stop\b",
    r"\bkillall\b", r"\bpkill\s+-9\s+-1\b",
    # 篡改系统认证/配置
    r">\s*/etc/(passwd|shadow|sudoers|hosts)\b",
    r"\bchmod\s+-R\s+000\s+/\b",
]

_COMPILED = [re.compile(p, re.IGNORECASE) for p in _SELF_DESTRUCT_PATTERNS]

# 企业模式专属：拦截对【目标生产环境】的破坏性/不可逆操作。
# 企业是真实生产资产，证明漏洞存在即可，绝不实际造成数据/业务/服务损害。
# 仅在 src_type=enterprise 时启用；edu/靶场不受此限。
_ENTERPRISE_DANGER_PATTERNS = [
    # 企业项目使用单请求手工验证，不运行自动化漏洞扫描器。
    (r"\b(nuclei|sqlmap(?:\.py)?|dalfox|nikto|xray|afrog|vulmap|wpscan|arachni|zap-baseline(?:\.py)?|zaproxy|nessus|openvas|gvm-cli|pocsuite(?:3)?|poc-suite|jaeles|wapiti|skipfish|commix|xsser|acunetix|awvs|appscan|invicti|netsparker|goby)\b",
     "禁止自动化漏洞扫描；企业模式使用单请求和响应差异完成最小验证。"),
    (r"\bnmap\b[\s\S]*(?:--script(?:=|\s+)[^\s]*vuln|--script(?:=|\s+)[^\s]*vulners|-sC\b)",
     "禁止用 Nmap NSE 做自动化漏洞扫描；企业模式只允许少量 TCP connect 服务确认。"),
    # SQL 写/删/库结构破坏（拦截 sqlmap dump 全库 + 直接 DML/DDL）
    (r"\bsqlmap\b.*--(dump-all|dump\b|os-shell|file-write|sql-shell)",
     "禁止 sqlmap --dump/--dump-all/--os-shell/--file-write/--sql-shell：企业生产库只做存在性验证（布尔/延时/读单条），不批量拖库、不写入。"),
    (r"\b(drop|truncate)\s+(table|database)\b", "禁止 DROP/TRUNCATE：不破坏企业生产库结构。"),
    (r"\bdelete\s+from\b", "禁止 DELETE FROM：不删除企业生产数据。"),
    (r"\b(insert\s+into|update\s+\w+\s+set)\b", "禁止 INSERT/UPDATE 写操作：企业生产数据只读验证，不写入篡改。"),
    # 改密码/重置凭证（铁律：拿到只读不动）
    (r"\b(set\s+password|alter\s+user|update\s+.*\bpassword\b\s*=)", "禁止修改任何密码/凭证：企业模式只读取记录，绝不改密。"),
    (r"\bpasswd\b\s+\w+", "禁止 passwd 改密。"),
    # 持久化/落 webshell（只做无害探针，不留后门）
    (r"(weevely|antsword|behinder|冰蝎|哥斯拉|godzilla)", "禁止上传/连接 webshell 管理工具：企业模式不落持久后门。"),
    (r"\b(crontab|/etc/cron|systemctl\s+enable|nohup)\b.*(curl|wget|bash|sh\s)", "禁止植入定时任务/开机自启后门。"),
    # 大规模爆破/压测（点到为止，不伤害服务）
    (r"\bhydra\b", "禁止 hydra 大规模爆破：企业模式弱口令尝试点到为止（少量高命中组合）。"),
    (r"\bmedusa\b", "禁止 medusa 大规模爆破。"),
    (r"\b(ab|wrk|siege)\s+-", "禁止压测工具（ab/wrk/siege）：不对企业生产服务做压力/DoS。"),
    (r"-w\s+\S*(rockyou|big\.txt|10k|100k|million)", "禁止超大字典爆破：企业模式不跑大字典暴力。"),
]

_ENTERPRISE_COMPILED = [(re.compile(p, re.IGNORECASE), msg) for p, msg in _ENTERPRISE_DANGER_PATTERNS]


class CommandBlocked(Exception):
    pass


def _tokenize_command(command: str) -> list[str]:
    text = str(command or "")
    if not text.strip() or len(text) > _MAX_ENTERPRISE_VALUE + 4096:
        raise CommandBlocked("企业命令为空或超过长度上限")
    quote = ""
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote != "'":
            escaped = True
            continue
        if char in {"'", '"'}:
            if not quote:
                quote = char
            elif quote == char:
                quote = ""
            continue
        if char in {"`", "\r", "\n"} or text[index : index + 2] == "$(":
            raise CommandBlocked("企业命令包含 shell 控制语法")
        if not quote and char in {"|", ";", "&", "<", ">"}:
            raise CommandBlocked("企业命令包含 shell 控制语法")
    try:
        return shlex.split(text, posix=True)
    except ValueError as exc:
        raise CommandBlocked(f"企业命令引号格式错误: {exc}") from exc


def _command_host(value: str) -> str:
    text = str(value or "").strip()
    parsed = urlsplit(text if "://" in text else f"//{text}")
    return str(parsed.hostname or "").rstrip(".").lower()


def _validate_curl_tokens(tokens: list[str], scope_target: str) -> None:
    urls: list[str] = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token.startswith("-"):
            if token in {"-s", "-S", "-i", "-I"} or (
                token.startswith("-")
                and not token.startswith("--")
                and len(token) > 2
                and set(token[1:]) <= {"s", "S", "i", "I"}
            ):
                index += 1
                continue
            if token not in {
                "-X", "-H", "--data", "--data-raw", "--max-time", "--connect-timeout"
            }:
                raise CommandBlocked(f"企业 curl 参数未登记: {token}")
            if index + 1 >= len(tokens):
                raise CommandBlocked(f"企业 curl 参数缺少值: {token}")
            value = tokens[index + 1]
            if token == "-X" and not re.fullmatch(r"[A-Za-z]{3,12}", value):
                raise CommandBlocked("企业 curl 请求方法格式错误")
            if token == "-H":
                if (
                    value.startswith("@")
                    or ":" not in value
                    or len(value) > 4096
                    or any(c in value for c in "\r\n")
                ):
                    raise CommandBlocked("企业 curl Header 格式错误")
                header_name = value.split(":", 1)[0].strip().lower()
                blocked_headers = {
                    "host", "proxy", "forwarded", "x-forwarded-host", "x-forwarded-for",
                    "x-original-url", "x-rewrite-url", "x-http-method-override",
                }
                if header_name in blocked_headers or "proxy" in header_name:
                    raise CommandBlocked(f"企业 curl Header 不允许覆盖路由: {header_name}")
            elif token in {"--data", "--data-raw"}:
                if token == "--data" and value.startswith("@"):
                    raise CommandBlocked("企业 curl 请求体不得从文件读取")
                if len(value.encode("utf-8")) > _MAX_ENTERPRISE_VALUE:
                    raise CommandBlocked("企业 curl 请求体超过 16 KiB")
            elif token in {"--max-time", "--connect-timeout"}:
                try:
                    seconds = float(value)
                except ValueError as exc:
                    raise CommandBlocked(f"企业 curl 超时格式错误: {token}") from exc
                if not math.isfinite(seconds) or seconds <= 0 or seconds > 30:
                    raise CommandBlocked("企业 curl 超时必须在 0 到 30 秒之间")
            index += 2
            continue
        parsed = urlsplit(token)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise CommandBlocked(f"企业 curl 仅接受一个完整 HTTP URL: {token}")
        urls.append(token)
        index += 1

    if len(urls) != 1:
        raise CommandBlocked("企业 curl 必须且只能包含一个 URL")
    expected = _command_host(scope_target)
    actual = _command_host(urls[0])
    if not expected or actual != expected:
        raise CommandBlocked(f"企业 curl URL 超出当前目标范围: {actual or '<empty>'}")


def _validate_parser_tokens(
    tokens: list[str],
    allowed_parsers: Mapping[str, tuple[str, ...]],
) -> None:
    for prefix in allowed_parsers.values():
        fixed = tuple(str(item) for item in prefix)
        if tuple(tokens[: len(fixed)]) != fixed:
            continue
        suffix = tokens[len(fixed) :]
        if len(suffix) != 2 or suffix[0] != "--value":
            raise CommandBlocked("本地解析器只接受固定的 --value 参数")
        if len(suffix[1].encode("utf-8")) > _MAX_ENTERPRISE_VALUE:
            raise CommandBlocked("本地解析器输入超过 16 KiB")
        return
    raise CommandBlocked("企业命令未登记，只允许 curl 或固定本地解析器")


def check_enterprise_command(
    command: str,
    *,
    scope_target: str,
    allowed_parsers: Mapping[str, tuple[str, ...]],
) -> tuple[str, ...]:
    """Return one validated argv for the enterprise shell execution path."""

    tokens = _tokenize_command(command)
    executable = tokens[0].lower() if tokens else ""
    if executable in {"curl", "curl.exe"}:
        _validate_curl_tokens(tokens, scope_target)
    else:
        _validate_parser_tokens(tokens, allowed_parsers)
    return tuple(tokens)


def check_command(cmd: str, enterprise: bool = False) -> None:
    """命中自毁模式则抛 CommandBlocked，否则放行。
    enterprise=True 时额外拦截对企业生产环境的破坏性/不可逆操作。"""
    for pat in _COMPILED:
        if pat.search(cmd):
            raise CommandBlocked(
                f"命令被安全防护拦截（疑似自毁运行环境，非攻击限制）：匹配模式 {pat.pattern}"
            )
    if enterprise:
        for pat, msg in _ENTERPRISE_COMPILED:
            if pat.search(cmd):
                raise CommandBlocked(
                    f"企业生产环境危险操作被拦截：{msg} 请改为非破坏性的存在性验证。"
                )
