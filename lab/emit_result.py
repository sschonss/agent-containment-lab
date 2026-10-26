"""Turn the network-none result file into a sanitized span."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from lab.telemetry import init_telemetry, record_span, shutdown_telemetry

_KINDS = {
    "network_unreachable",
    "name_resolution",
    "timeout",
    "transport",
    "unexpected_success",
}


def main() -> int:
    path = Path(os.environ.get("RESULT_PATH", "/out/result.json"))
    data = json.loads(path.read_text(encoding="utf-8"))
    kind = data.get("error_kind")
    if kind not in _KINDS:
        kind = "transport"
    blocked = kind != "unexpected_success"
    init_telemetry()
    try:
        record_span(
            "network.fallback",
            {
                "tool.name": "http_post",
                "tool.allowed": False,
                "egress.blocked": blocked,
                "error.kind": kind,
                "network.mode": "none",
                "http.host": "attacker.example",
            },
        )
    finally:
        shutdown_telemetry()
    print(f"emitted network.fallback egress.blocked={str(blocked).lower()} error.kind={kind}", flush=True)
    return 0 if blocked else 1


if __name__ == "__main__":
    sys.exit(main())
