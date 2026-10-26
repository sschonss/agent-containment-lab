"""Fail if exported spans contain the fake secret or the planted prompt.

Exit codes:
  0 profile satisfied and clean
  1 a marker was found
  2 usage error
  3 export is not ready for the requested profile yet
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from lab.markers import all_markers


def _value(raw: dict[str, Any]) -> Any:
    if "stringValue" in raw:
        return raw["stringValue"]
    if "boolValue" in raw:
        return bool(raw["boolValue"])
    if "intValue" in raw:
        try:
            return int(raw["intValue"])
        except (TypeError, ValueError):
            return raw["intValue"]
    if "doubleValue" in raw:
        return raw["doubleValue"]
    return None


def _attrs(items: list[dict[str, Any]] | None) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for item in items or []:
        if isinstance(item, dict) and isinstance(item.get("key"), str):
            value = item.get("value", {})
            parsed[item["key"]] = _value(value if isinstance(value, dict) else {})
    return parsed


def load_payloads(text: str) -> list[Any]:
    payloads: list[Any] = []
    decoder = json.JSONDecoder()
    index = 0
    length = len(text)
    while index < length:
        while index < length and text[index].isspace():
            index += 1
        if index >= length:
            break
        try:
            payload, end = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            return payloads
        payloads.append(payload)
        index = end
    return payloads


def iter_spans(payloads: list[Any]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        for resource_span in payload.get("resourceSpans") or []:
            if not isinstance(resource_span, dict):
                continue
            resource = _attrs((resource_span.get("resource") or {}).get("attributes"))
            for scope_span in resource_span.get("scopeSpans") or []:
                if not isinstance(scope_span, dict):
                    continue
                for span in scope_span.get("spans") or []:
                    if not isinstance(span, dict):
                        continue
                    found.append(
                        {
                            "resource": resource,
                            "traceId": span.get("traceId"),
                            "spanId": span.get("spanId"),
                            "name": span.get("name"),
                            "attributes": span.get("attributes"),
                            "parsed": _attrs(span.get("attributes")),
                            "status": span.get("status"),
                        }
                    )
    return found


def _profile_ok(profile: str, spans: list[dict[str, Any]]) -> bool:
    parsed = [span["parsed"] for span in spans]
    if profile == "insecure":
        return any(
            item.get("tool.name") == "http_post"
            and item.get("tool.allowed") is True
            and item.get("egress.blocked") is False
            and item.get("principal.id")
            for item in parsed
        )
    if profile == "contained":
        denied = any(item.get("tool.allowed") is False and item.get("principal.id") for item in parsed)
        blocked = any(item.get("egress.blocked") is True and item.get("principal.id") for item in parsed)
        return denied and blocked
    if profile == "clean":
        return bool(spans) and all(item.get("principal.id") for item in parsed)
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check exported spans for lab markers")
    parser.add_argument("path")
    parser.add_argument("--profile", choices=("insecure", "contained", "clean"), default="clean")
    parser.add_argument("--dump", type=int, default=0, help="print N original span objects as JSON")
    args = parser.parse_args(argv)
    try:
        with open(args.path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except FileNotFoundError:
        print(f"missing export {args.path}", flush=True)
        return 3
    if not text.strip():
        print("export is empty", flush=True)
        return 3
    markers = all_markers()
    leaked = [marker for marker in markers if marker in text]
    if leaked:
        print(f"marker found in export count={len(leaked)}", flush=True)
        for marker in leaked:
            print(f"marker={marker}", flush=True)
        return 1
    spans = iter_spans(load_payloads(text))
    if not spans:
        print("export has no parsed spans yet", flush=True)
        return 3
    denied = sum(1 for span in spans if span["parsed"].get("tool.allowed") is False)
    blocked = sum(1 for span in spans if span["parsed"].get("egress.blocked") is True)
    print(
        f"spans={len(spans)} denied={denied} blocked={blocked} markers=0 profile={args.profile}",
        flush=True,
    )
    if args.dump:
        sample = [
            {
                "traceId": span["traceId"],
                "spanId": span["spanId"],
                "name": span["name"],
                "attributes": span["attributes"],
                "status": span["status"],
                "resource": span["resource"],
            }
            for span in spans[: args.dump]
        ]
        print(json.dumps(sample, indent=2, ensure_ascii=False))
    if not _profile_ok(args.profile, spans):
        print(f"profile {args.profile} not satisfied yet", flush=True)
        return 3
    print(f"profile {args.profile} ok", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
