"""LSP-style Content-Length framing used by the minimal MCP server."""

from __future__ import annotations

import json
from typing import Any, BinaryIO


def read_exact(stream: BinaryIO, size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        chunk = stream.read(size - len(buf))
        if not chunk:
            raise EOFError("short read")
        buf.extend(chunk)
    return bytes(buf)


def read_message(stream: BinaryIO) -> dict[str, Any]:
    headers: dict[str, str] = {}
    while True:
        line = stream.readline()
        if line == b"":
            raise EOFError("eof before headers")
        if line in (b"\n", b"\r\n"):
            break
        decoded = line.decode("utf-8").strip()
        if ":" not in decoded:
            raise ValueError("malformed header")
        key, value = decoded.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    if "content-length" not in headers:
        raise ValueError("missing content-length")
    length = int(headers["content-length"])
    if length < 0 or length > 1_000_000:
        raise ValueError("invalid content-length")
    payload = read_exact(stream, length)
    message = json.loads(payload.decode("utf-8"))
    if not isinstance(message, dict):
        raise ValueError("message must be an object")
    return message


def write_message(stream: BinaryIO, message: dict[str, Any]) -> None:
    payload = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    header = f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii")
    stream.write(header)
    stream.write(payload)
    stream.flush()
