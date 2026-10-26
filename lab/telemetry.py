"""Export sanitized spans over OTLP/HTTP. A local sink exists for unit tests."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from lab.sanitize import sanitize

_provider: Any = None
_tracer: Any = None
_ready = False


def init_telemetry() -> str:
    """Initialize exporters once. Returns 'otlp', 'sink', 'otlp+sink', or 'disabled'."""
    global _provider, _tracer, _ready
    if _ready:
        return _status()

    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
    sink = os.environ.get("SPAN_SINK", "").strip()
    if endpoint:
        # urllib honors HTTP(S)_PROXY. Telemetry must reach the collector directly.
        extra = "otel-collector,ollama,localhost,127.0.0.1"
        current = os.environ.get("NO_PROXY", "")
        merged = ",".join(part for part in (current, extra) if part)
        os.environ["NO_PROXY"] = merged
        os.environ["no_proxy"] = merged
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor

        # This SDK treats `endpoint` as the full signal URL. The env var is the base.
        base = endpoint.rstrip("/")
        if not base.endswith("/v1/traces"):
            base = base + "/v1/traces"
        resource = Resource.create(
            {
                "service.name": "coding-agent",
                "service.version": "0.1.0",
            }
        )
        _provider = TracerProvider(resource=resource)
        _provider.add_span_processor(
            SimpleSpanProcessor(OTLPSpanExporter(endpoint=base, timeout=3))
        )
        trace.set_tracer_provider(_provider)
        _tracer = trace.get_tracer("lab.containment")
    _ready = True
    return _status()


def _status() -> str:
    endpoint = bool(os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip())
    sink = bool(os.environ.get("SPAN_SINK", "").strip())
    if endpoint and sink:
        return "otlp+sink"
    if endpoint:
        return "otlp"
    if sink:
        return "sink"
    return "disabled"


def shutdown_telemetry() -> None:
    global _provider
    if _provider is not None:
        _provider.shutdown()
        _provider = None


def record_span(name: str, attributes: dict) -> dict:
    """Sanitize, optionally mirror to SPAN_SINK, and export via OTLP when configured."""
    if not _ready:
        init_telemetry()
    safe = sanitize(attributes)
    sink = os.environ.get("SPAN_SINK", "").strip()
    if sink:
        path = Path(sink)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"name": name, "attributes": safe}, sort_keys=True) + "\n")
    if _tracer is not None:
        from opentelemetry.trace import Status, StatusCode

        with _tracer.start_as_current_span(name) as span:
            for key, value in safe.items():
                span.set_attribute(key, value)
            kind = str(safe.get("error.kind", "ok"))
            if kind not in {"ok", "unchecked"}:
                span.set_status(Status(StatusCode.ERROR, kind))
    return safe
