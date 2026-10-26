"""Scoped-credential probe.

The live path uses LAB_GITHUB_PAT, falling back to GITHUB_TOKEN. It GETs
README.md on the target repo (default sschonss/agent-containment-lab) and
then PUTs a contents file. A read-only fine-grained PAT should see 200 and
403. The token never goes to stdout, spans, or argv. Without a token, or
with CREDENTIAL_MODE=mock, the 403 is synthesized locally.
"""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from pathlib import Path

from lab.markers import all_markers
from lab.probes import CurlProbe, run_curl

_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
DEFAULT_REPO = "sschonss/agent-containment-lab"
_EXPIRATION_HEADER = "github-authentication-token-expiration"


def resolve_token() -> str:
    pat = os.environ.get("LAB_GITHUB_PAT", "").strip()
    if pat:
        return pat
    return os.environ.get("GITHUB_TOKEN", "").strip()


def resolve_repo() -> str:
    raw = os.environ.get("GITHUB_REPO", "").strip()
    return raw or DEFAULT_REPO


def expiration_from_headers(headers: str) -> str:
    """Return the GitHub token-expiration header, or 'absent'."""
    for line in headers.splitlines():
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        if name.strip().lower() != _EXPIRATION_HEADER:
            continue
        cleaned = value.strip()
        if not cleaned or len(cleaned) > 80 or any(marker in cleaned for marker in all_markers()):
            return "redacted"
        return cleaned
    return "absent"


def _redact(text: str, token: str) -> str:
    if token:
        text = text.replace(token, "[redacted]")
    for marker in all_markers():
        text = text.replace(marker, "[redacted]")
    return text


def _message_from_body(body: str, token: str) -> str:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return _redact(" ".join(body.split())[:180], token)
    if isinstance(payload, dict) and isinstance(payload.get("message"), str):
        return _redact(payload["message"], token)
    return ""


def mock_result() -> dict:
    return {
        "mocked": True,
        "http_status": 403,
        "read_status": "skipped",
        "source": "mock",
        "error_kind": "mocked_scope_denied",
        "scope": "contents:read",
        "ttl": "1d",
        "expiration": "absent",
        "egress_blocked": False,
        "message": "Resource not accessible by integration",
        "note": "synthesized locally; api.github.com was not called",
    }


def _api_call(token: str, method: str, url: str, body: Path | None) -> tuple[CurlProbe, str]:
    with tempfile.TemporaryDirectory(prefix="lab-cred-") as tmp:
        header_path = Path(tmp) / "headers"
        config = Path(tmp) / "curl.cfg"
        lines = [
            'header = "Authorization: Bearer ' + token.replace('"', "") + '"',
            'header = "Accept: application/vnd.github+json"',
            'header = "Content-Type: application/json"',
            'header = "X-GitHub-Api-Version: 2022-11-28"',
            'header = "User-Agent: agent-containment-lab"',
            f"request = {method}",
            "silent",
            "show-error",
            "connect-timeout = 3",
            "max-time = 8",
            'proxy = "http://squid:3128"',
            f'url = "{url}"',
        ]
        if body is not None:
            lines.append(f'data-binary = "@{body}"')
        config.write_text("\n".join(lines) + "\n", encoding="utf-8")
        config.chmod(stat.S_IRUSR | stat.S_IWUSR)
        probe = run_curl(["--config", str(config)], timeout=8, dump_header=header_path)
        headers = header_path.read_text(encoding="utf-8", errors="replace") if header_path.exists() else ""
        return probe, _redact(headers, token)


def _classify_write(probe: CurlProbe) -> tuple[str, str]:
    kind = probe.error_kind
    source = "squid" if kind == "proxy_denied" else "github"
    if kind == "timeout":
        source = "none"
    elif kind == "ok" and probe.http_status in {200, 201}:
        kind = "unexpected_success"
        source = "github"
    elif probe.http_status == 401:
        kind = "invalid_token"
        source = "github"
    elif probe.http_status == 403 and kind != "proxy_denied":
        kind = "scope_denied"
        source = "github"
    elif probe.http_status == 0 and kind == "ok":
        kind = "transport"
    return kind, source


def _live(token: str, repo: str) -> dict:
    if _REPO_RE.fullmatch(repo) is None:
        return {
            "mocked": False,
            "http_status": 0,
            "read_status": 0,
            "source": "none",
            "error_kind": "transport",
            "scope": "contents:read",
            "ttl": "1d",
            "expiration": "absent",
            "egress_blocked": False,
            "message": "GITHUB_REPO is not owner/name",
            "note": "live call skipped",
            "fatal": True,
        }
    read_url = f"https://api.github.com/repos/{repo}/contents/README.md"
    write_url = f"https://api.github.com/repos/{repo}/contents/lab-probe-do-not-merge.txt"
    read_probe, read_headers = _api_call(token, "GET", read_url, None)
    expiration = expiration_from_headers(read_headers)
    with tempfile.TemporaryDirectory(prefix="lab-cred-body-") as tmp:
        payload = Path(tmp) / "payload.json"
        payload.write_text(
            json.dumps({"message": "lab probe", "content": "bGFiCg=="}),
            encoding="utf-8",
        )
        write_probe, write_headers = _api_call(token, "PUT", write_url, payload)
    if expiration == "absent":
        expiration = expiration_from_headers(write_headers)
    kind, source = _classify_write(write_probe)
    message = _message_from_body(_redact(write_probe.body, token), token)
    if write_probe.leaked_marker or read_probe.leaked_marker:
        message = "response contained a lab marker and was withheld"
    read_ok = read_probe.http_status == 200 and read_probe.error_kind != "proxy_denied"
    write_denied = kind == "scope_denied" and write_probe.http_status == 403
    fatal = not read_ok or not write_denied or write_probe.leaked_marker or read_probe.leaked_marker
    note = "live GET README.md then PUT lab-probe-do-not-merge.txt through the egress proxy; token not logged"
    if kind == "proxy_denied":
        note = "proxy denied api.github.com; this is not a GitHub 403"
    elif kind == "unexpected_success":
        note = "write succeeded; delete lab-probe-do-not-merge.txt and revoke the token"
    return {
        "mocked": False,
        "http_status": write_probe.http_status,
        "read_status": read_probe.http_status,
        "source": source,
        "error_kind": kind,
        "scope": "contents:read",
        "ttl": "1d",
        "expiration": expiration,
        "egress_blocked": kind == "proxy_denied" or read_probe.error_kind == "proxy_denied",
        "message": message,
        "note": note,
        "leaked_marker": write_probe.leaked_marker or read_probe.leaked_marker,
        "fatal": fatal,
    }


def evaluate() -> dict:
    mode = os.environ.get("CREDENTIAL_MODE", "").strip().lower()
    token = resolve_token()
    repo = resolve_repo()
    if mode == "live" and not token:
        return {
            "mocked": False,
            "http_status": 0,
            "read_status": "skipped",
            "source": "none",
            "error_kind": "unchecked",
            "scope": "unknown",
            "ttl": "unknown",
            "expiration": "absent",
            "egress_blocked": False,
            "message": "CREDENTIAL_MODE=live requires LAB_GITHUB_PAT or GITHUB_TOKEN",
            "note": "refusing to synthesize a GitHub 403",
            "fatal": True,
        }
    if mode == "mock" or not token:
        return mock_result()
    return _live(token, repo)


def format_report(result: dict) -> str:
    lines = [
        f"credential.mocked={str(result['mocked']).lower()}",
        f"credential.source={result['source']}",
        f"credential.scope={result['scope']}",
        f"credential.ttl={result['ttl']}",
        f"credential.read_status={result.get('read_status', 'skipped')}",
        f"credential.write_status={result['http_status']}",
        f"credential.expiration={result.get('expiration', 'absent')}",
        f"http.status={result['http_status']}",
        f"error.kind={result['error_kind']}",
        f"message={result.get('message', '')}",
        f"note={result.get('note', '')}",
    ]
    return " ".join(lines)
