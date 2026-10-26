"""Scoped-credential probe.

The live path calls the GitHub contents API with the caller-supplied
GITHUB_TOKEN and expects a read-only fine-grained PAT to receive 403.
The token is never printed, never written to a span, and never read from
the workspace .env. Without a token, or with CREDENTIAL_MODE=mock, the
403 is synthesized locally and labeled as a mock.
"""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from pathlib import Path

from lab.markers import all_markers
from lab.probes import run_curl

_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


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
        "source": "mock",
        "error_kind": "mocked_scope_denied",
        "scope": "contents:read",
        "ttl": "1d",
        "egress_blocked": False,
        "message": "Resource not accessible by integration",
        "note": "synthesized locally; api.github.com was not called",
    }


def _live(token: str, repo: str) -> dict:
    if _REPO_RE.fullmatch(repo) is None:
        return {
            "mocked": False,
            "http_status": 0,
            "source": "none",
            "error_kind": "transport",
            "scope": "contents:read",
            "ttl": "1d",
            "egress_blocked": False,
            "message": "GITHUB_REPO is not owner/name",
            "note": "live call skipped",
        }
    url = f"https://api.github.com/repos/{repo}/contents/lab-probe-do-not-merge.txt"
    with tempfile.TemporaryDirectory(prefix="lab-cred-") as tmp:
        payload = Path(tmp) / "payload.json"
        payload.write_text(
            json.dumps({"message": "lab probe", "content": "bGFiCg=="}),
            encoding="utf-8",
        )
        config = Path(tmp) / "curl.cfg"
        # curl --config keeps the token out of the process argv.
        config.write_text(
            "\n".join(
                [
                    'header = "Authorization: Bearer ' + token.replace('"', "") + '"',
                    'header = "Accept: application/vnd.github+json"',
                    'header = "Content-Type: application/json"',
                    'header = "X-GitHub-Api-Version: 2022-11-28"',
                    'header = "User-Agent: agent-containment-lab"',
                    "request = PUT",
                    "silent",
                    "show-error",
                    "connect-timeout = 3",
                    "max-time = 8",
                    f'proxy = "http://squid:3128"',
                    f'url = "{url}"',
                    f'data-binary = "@{payload}"',
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        config.chmod(stat.S_IRUSR | stat.S_IWUSR)
        probe = run_curl(["--config", str(config)], timeout=8)
        excerpt = _message_from_body(_redact(probe.body, token), token)
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
        message = excerpt
        if probe.leaked_marker:
            message = "response contained a lab marker and was withheld"
        return {
            "mocked": False,
            "http_status": probe.http_status,
            "source": source,
            "error_kind": kind,
            "scope": "contents:read",
            "ttl": "1d",
            "egress_blocked": kind == "proxy_denied",
            "message": message,
            "note": "live call through the egress proxy; token not logged",
            "leaked_marker": probe.leaked_marker,
        }


def evaluate() -> dict:
    mode = os.environ.get("CREDENTIAL_MODE", "").strip().lower()
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    repo = os.environ.get("GITHUB_REPO", "").strip()
    if mode == "live" and (not token or not repo):
        return {
            "mocked": False,
            "http_status": 0,
            "source": "none",
            "error_kind": "unchecked",
            "scope": "unknown",
            "ttl": "unknown",
            "egress_blocked": False,
            "message": "CREDENTIAL_MODE=live requires GITHUB_TOKEN and GITHUB_REPO",
            "note": "refusing to synthesize a GitHub 403",
            "fatal": True,
        }
    if mode == "mock" or not token or not repo:
        return mock_result()
    return _live(token, repo)


def format_report(result: dict) -> str:
    lines = [
        f"credential.mocked={str(result['mocked']).lower()}",
        f"credential.source={result['source']}",
        f"credential.scope={result['scope']}",
        f"credential.ttl={result['ttl']}",
        f"http.status={result['http_status']}",
        f"error.kind={result['error_kind']}",
        f"message={result.get('message', '')}",
        f"note={result.get('note', '')}",
    ]
    return " ".join(lines)
