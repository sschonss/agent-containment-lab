"""Curl probes for the egress controls. Bodies stay in files, never in argv or spans."""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from lab.markers import all_markers


@dataclass
class CurlProbe:
    label: str
    argv: list[str]
    exit_code: int
    http_status: int
    error_kind: str
    body_excerpt: str
    body: str
    leaked_marker: bool


def _excerpt(text: str) -> str:
    flattened = " ".join(text.split())
    return flattened[:180]


def run_curl(argv: list[str], timeout: int = 5, dump_header: Path | None = None) -> CurlProbe:
    """Run curl. argv must already include URL and proxy flags. Do not pass secrets in argv."""
    with tempfile.TemporaryDirectory(prefix="lab-curl-") as tmp:
        body_path = Path(tmp) / "body"
        command = [
            "curl",
            "-sS",
            "--max-time",
            str(timeout),
            "--connect-timeout",
            "3",
            "-o",
            str(body_path),
            "-w",
            "%{http_code}",
        ]
        if dump_header is not None:
            command.extend(["-D", str(dump_header)])
        command.extend(argv)
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                timeout=timeout + 2,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return CurlProbe(
                label="",
                argv=command,
                exit_code=28,
                http_status=0,
                error_kind="timeout",
                body_excerpt="",
                body="",
                leaked_marker=False,
            )
        status_text = completed.stdout.decode("utf-8", errors="replace").strip()
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        body = body_path.read_text(encoding="utf-8", errors="replace") if body_path.exists() else ""
        http_status = int(status_text) if status_text.isdigit() else 0
        leaked = any(marker in body or marker in stderr for marker in all_markers())
        error_kind = _classify(completed.returncode, http_status, body, stderr)
        excerpt_source = stderr if stderr and http_status == 0 else body
        return CurlProbe(
            label="",
            argv=command,
            exit_code=int(completed.returncode),
            http_status=http_status,
            error_kind=error_kind,
            body_excerpt="" if leaked else _excerpt(excerpt_source),
            body="" if leaked else body[:4000],
            leaked_marker=leaked,
        )


def _classify(exit_code: int, http_status: int, body: str, stderr: str) -> str:
    combined = (body + " " + stderr).lower()
    # A GitHub 403 is a JSON API body. Only the Squid error page is an egress deny.
    if "err_access_denied" in combined or (http_status == 403 and "squid" in combined):
        return "proxy_denied"
    if exit_code == 28 or "timed out" in combined or "operation timed out" in combined:
        return "timeout"
    if "could not resolve host" in combined or "name resolution" in combined or "temporary failure in name" in combined:
        return "name_resolution"
    if "network is unreachable" in combined:
        return "network_unreachable"
    if exit_code != 0 and http_status == 0:
        return "transport"
    return "ok"


def command_for_log(probe: CurlProbe) -> str:
    """Render the curl invocation without the temp output path noise where possible."""
    interesting = []
    skip_next = False
    for arg in probe.argv:
        if skip_next:
            skip_next = False
            continue
        if arg in {"-o", "-w", "-D"}:
            skip_next = True
            continue
        if arg in {"-sS"}:
            interesting.append(arg)
            continue
        interesting.append(arg)
    return " ".join(interesting)
