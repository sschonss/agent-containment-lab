"""Allowlist span attributes. Drop anything that could carry a secret or a prompt."""

from __future__ import annotations

import os
import re

from lab.markers import all_markers

ALLOWED_KEYS = {
    "tool.name",
    "tool.allowed",
    "egress.blocked",
    "principal.id",
    "lab.mode",
    "mcp.method",
    "error.kind",
    "http.status_code",
    "http.host",
    "network.mode",
    "file.path",
    "credential.mocked",
    "credential.scope",
    "credential.ttl",
    "credential.source",
}

_ERROR_KINDS = {
    "ok",
    "not_allowed",
    "proxy_denied",
    "network_unreachable",
    "name_resolution",
    "timeout",
    "transport",
    "unchecked",
    "path_denied",
    "mocked_scope_denied",
    "scope_denied",
    "unexpected_success",
    "invalid_token",
}

_HOSTS = {"attacker.example", "api.github.com", "example.com"}
_SCOPES = {"contents:read", "unbounded", "unknown"}
_TTLS = {"1d", "none", "unknown"}
_SOURCES = {"mock", "github", "squid", "none"}
_MODES = {"insecure", "contained", "unknown"}
_NETWORKS = {"open", "proxy", "none", "compose-isolated", "not-sent"}
_PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,120}$")


def _contains_marker(value: str) -> bool:
    return any(marker in value for marker in all_markers())


def principal_id() -> str:
    raw = os.environ.get("PRINCIPAL_ID", "schons").strip() or "schons"
    if _contains_marker(raw) or _PRINCIPAL_RE.fullmatch(raw) is None:
        return "redacted-principal"
    return raw


def _clean_string(key: str, value: str) -> str | None:
    if _contains_marker(value):
        return None
    if key == "principal.id":
        return value if _PRINCIPAL_RE.fullmatch(value) else None
    if key == "error.kind":
        return value if value in _ERROR_KINDS else None
    if key == "http.host":
        return value if value in _HOSTS else None
    if key == "network.mode":
        return value if value in _NETWORKS else None
    if key == "lab.mode":
        return value if value in _MODES else None
    if key == "file.path":
        return value if _PATH_RE.fullmatch(value) and ".." not in value else None
    if key == "credential.scope":
        return value if value in _SCOPES else None
    if key == "credential.ttl":
        return value if value in _TTLS else None
    if key == "credential.source":
        return value if value in _SOURCES else None
    if key == "mcp.method":
        return value if value in {"tools/list", "tools/call"} else None
    if key == "tool.name":
        return value if _PRINCIPAL_RE.fullmatch(value) else None
    return None


def sanitize(attributes: dict) -> dict:
    """Return a closed set of attributes that is safe to export."""
    clean: dict = {
        "tool.name": "unknown",
        "tool.allowed": False,
        "egress.blocked": False,
        "principal.id": principal_id(),
        "lab.mode": os.environ.get("MODE", "unknown") if os.environ.get("MODE") in _MODES else "unknown",
    }
    for key, value in attributes.items():
        if key not in ALLOWED_KEYS:
            continue
        if isinstance(value, bool) and key in {"tool.allowed", "egress.blocked", "credential.mocked"}:
            clean[key] = value
            continue
        if isinstance(value, int) and not isinstance(value, bool) and key == "http.status_code":
            if 0 <= value <= 599:
                clean[key] = value
            continue
        if isinstance(value, str):
            cleaned = _clean_string(key, value)
            if cleaned is not None:
                clean[key] = cleaned
    if _contains_marker(str(clean.get("principal.id", ""))):
        clean["principal.id"] = "redacted-principal"
    return clean
