"""Minimal MCP server. Allowlist: read_file and list_dir.

Any other tool returns a JSON-RPC error with a single message and no traceback.
The refusal is also a sanitized span.
"""

from __future__ import annotations

import os
import sys
from typing import Any

from lab.errors import ToolError
from lab.framing import read_message, write_message
from lab.telemetry import init_telemetry, record_span, shutdown_telemetry
from lab.tools import list_dir, read_file
from lab.workspace import Workspace

ALLOWLIST = ("list_dir", "read_file")
_PROTOCOL = "2024-11-05"


def _workspace() -> Workspace:
    return Workspace(os.environ.get("WORKSPACE", "/workspace"))


def _span(tool: str, allowed: bool, error_kind: str, file_path: str | None = None) -> None:
    attributes: dict[str, Any] = {
        "tool.name": tool or "unknown",
        "tool.allowed": allowed,
        "egress.blocked": False,
        "error.kind": error_kind,
        "mcp.method": "tools/call",
        "network.mode": "not-sent",
    }
    if file_path:
        attributes["file.path"] = file_path
    record_span("tool.call", attributes)


def _error(message_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "error": {"code": code, "message": message}}


def _ok(message_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "result": result}


def _tool_catalog() -> dict[str, Any]:
    return {
        "tools": [
            {
                "name": "list_dir",
                "description": "List entry names in a workspace directory.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "read_file",
                "description": "Read a UTF-8 file inside the workspace.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                    "additionalProperties": False,
                },
            },
        ]
    }


def _call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name not in ALLOWLIST:
        _span(name, False, "not_allowed")
        raise ToolError(f"tool not allowed: {name}")
    workspace = _workspace()
    raw_path = arguments.get("path", "")
    if not isinstance(raw_path, str):
        _span(name, True, "path_denied")
        raise ToolError("path is invalid")
    try:
        if name == "list_dir":
            names = list_dir(workspace, raw_path)
            text = "\n".join(names)
        else:
            text = read_file(workspace, raw_path).decode("utf-8", errors="replace")
    except ToolError as exc:
        kind = "path_denied" if "escape" in exc.message or "invalid" in exc.message else "transport"
        _span(name, True, kind, raw_path if kind != "path_denied" else None)
        raise
    _span(name, True, "ok", raw_path)
    return {"content": [{"type": "text", "text": text}], "isError": False}


def handle(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    message_id = message.get("id")
    if method == "initialize":
        return _ok(
            message_id,
            {
                "protocolVersion": _PROTOCOL,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "lab-mcp", "version": "0.1.0"},
            },
        )
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return _ok(message_id, _tool_catalog())
    if method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return _error(message_id, -32602, "invalid tool call")
        try:
            result = _call_tool(name, arguments)
        except ToolError as exc:
            return _error(message_id, -32001, exc.message)
        return _ok(message_id, result)
    if message_id is None:
        return None
    return _error(message_id, -32601, "method not found")


def serve() -> int:
    init_telemetry()
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    try:
        while True:
            try:
                message = read_message(stdin)
            except EOFError:
                return 0
            except (ValueError, UnicodeError, json_error()):
                write_message(stdout, _error(None, -32700, "parse error"))
                continue
            try:
                response = handle(message)
            except Exception:
                # Unexpected faults stay off the wire. LAB_DEBUG prints a traceback to stderr.
                if os.environ.get("LAB_DEBUG") == "1":
                    import traceback

                    traceback.print_exc(file=sys.stderr)
                write_message(stdout, _error(message.get("id"), -32603, "internal error"))
                continue
            if response is not None:
                write_message(stdout, response)
    finally:
        shutdown_telemetry()


def json_error() -> type[BaseException]:
    import json

    return json.JSONDecodeError


def main() -> None:
    try:
        raise SystemExit(serve())
    except BrokenPipeError:
        raise SystemExit(0)


if __name__ == "__main__":
    main()
