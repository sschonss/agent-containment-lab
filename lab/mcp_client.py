"""Synchronous MCP client for the scripted agent."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from dataclasses import dataclass
from typing import Any

from lab.framing import read_message, write_message


@dataclass
class ToolOutcome:
    allowed: bool
    message: str
    text: str = ""


class McpClient:
    def __init__(self) -> None:
        self._proc: subprocess.Popen | None = None
        self._stderr = bytearray()
        self._next_id = 1

    def __enter__(self) -> "McpClient":
        env = os.environ.copy()
        env.setdefault("WORKSPACE", "/workspace")
        self._proc = subprocess.Popen(
            [sys.executable, "-m", "lab.mcp_server"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        threading.Thread(target=self._drain_stderr, daemon=True).start()
        self._request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "lab-agent", "version": "0.1.0"},
            },
        )
        self._notify("notifications/initialized")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._proc is None or self._proc.stdin is None:
            return
        self._proc.stdin.close()
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait(timeout=5)
        if self._proc.stdout is not None:
            self._proc.stdout.close()
        if self._proc.stderr is not None:
            self._proc.stderr.close()
        stderr = self.stderr_text()
        if "Traceback (most recent call last)" in stderr:
            print(stderr, file=sys.stderr)
            raise SystemExit(1)

    def _drain_stderr(self) -> None:
        assert self._proc is not None and self._proc.stderr is not None
        for chunk in iter(lambda: self._proc.stderr.read(4096), b""):
            self._stderr.extend(chunk)

    def stderr_text(self) -> str:
        return self._stderr.decode("utf-8", errors="replace")

    def _send(self, message: dict[str, Any]) -> None:
        assert self._proc is not None and self._proc.stdin is not None
        write_message(self._proc.stdin, message)

    def _read(self) -> dict[str, Any]:
        assert self._proc is not None and self._proc.stdout is not None
        return read_message(self._proc.stdout)

    def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        message_id = self._next_id
        self._next_id += 1
        self._send({"jsonrpc": "2.0", "id": message_id, "method": method, "params": params})
        while True:
            message = self._read()
            if message.get("id") == message_id:
                return message

    def _notify(self, method: str) -> None:
        self._send({"jsonrpc": "2.0", "method": method})

    def list_tools(self) -> list[str]:
        response = self._request("tools/list", {})
        tools = response.get("result", {}).get("tools", [])
        return [tool.get("name", "") for tool in tools if isinstance(tool, dict)]

    def call(self, name: str, arguments: dict[str, Any]) -> ToolOutcome:
        response = self._request("tools/call", {"name": name, "arguments": arguments})
        if "error" in response:
            error = response["error"]
            message = error.get("message", "tool not allowed") if isinstance(error, dict) else "tool not allowed"
            if not isinstance(message, str):
                message = "tool not allowed"
            return ToolOutcome(allowed=False, message=message)
        result = response.get("result", {})
        content = result.get("content", []) if isinstance(result, dict) else []
        text = ""
        if content and isinstance(content, list) and isinstance(content[0], dict):
            raw = content[0].get("text", "")
            text = raw if isinstance(raw, str) else ""
        return ToolOutcome(allowed=True, message="ok", text=text)
