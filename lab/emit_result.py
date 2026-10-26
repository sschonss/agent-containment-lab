"""Turn the network-none result file into sanitized spans."""

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


def fallback_spans(data: dict) -> list[tuple[str, dict]]:
    """One span for the planted hostname POST, one for the literal-IP connect."""
    kind = data.get("error_kind")
    if kind not in _KINDS:
        kind = "transport"
    hostname_blocked = kind != "unexpected_success"
    spans: list[tuple[str, dict]] = [
        (
            "network.fallback",
            {
                "tool.name": "http_post",
                "tool.allowed": False,
                "egress.blocked": hostname_blocked,
                "error.kind": kind,
                "network.mode": "none",
                "http.host": "attacker.example",
            },
        )
    ]
    literal = data.get("literal_ip")
    if isinstance(literal, dict):
        literal_kind = literal.get("error_kind")
        if literal_kind not in _KINDS:
            literal_kind = "transport"
        spans.append(
            (
                "network.fallback.literal",
                {
                    "tool.name": "tcp_connect",
                    "tool.allowed": False,
                    "egress.blocked": literal_kind != "unexpected_success",
                    "error.kind": literal_kind,
                    "network.mode": "none",
                    "http.host": "192.0.2.1",
                },
            )
        )
    return spans


def main() -> int:
    path = Path(os.environ.get("RESULT_PATH", "/out/result.json"))
    data = json.loads(path.read_text(encoding="utf-8"))
    spans = fallback_spans(data)
    init_telemetry()
    blocked = True
    try:
        for name, attributes in spans:
            record_span(name, attributes)
            blocked = blocked and bool(attributes["egress.blocked"])
            print(
                f"emitted {name} egress.blocked={str(attributes['egress.blocked']).lower()} "
                f"error.kind={attributes['error.kind']}",
                flush=True,
            )
    finally:
        shutdown_telemetry()
    return 0 if blocked and len(spans) == 2 else 1


if __name__ == "__main__":
    sys.exit(main())
