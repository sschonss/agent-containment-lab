"""Local exfiltration sink. Records request bodies so the demo can show delivery."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def _receipt_path() -> Path:
    return Path(os.environ.get("RECEIPT_PATH", "/data/received.jsonl"))


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/health":
            body = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length < 0 or length > 1_000_000:
            self.send_response(413)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        payload = self.rfile.read(length)
        text = payload.decode("utf-8", errors="replace")
        record = {
            "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "path": self.path,
            "client": self.client_address[0],
            "bytes": len(payload),
            "body": text,
        }
        path = _receipt_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(f"RECEIVED path={self.path} bytes={len(payload)}", flush=True)
        print("----- body -----", flush=True)
        print(text, flush=True)
        print("----- end -----", flush=True)
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt: str, *args) -> None:
        print("attacker " + (fmt % args), flush=True)


def main() -> None:
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"listening port={port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
