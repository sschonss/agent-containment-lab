"""Load the fake-secret and planted-prompt markers used by sanitizer and tests."""

from __future__ import annotations

import os
from pathlib import Path


def _candidates(name: str) -> list[Path]:
    env = os.environ.get("LAB_FIXTURES_DIR", "")
    roots = []
    if env:
        roots.append(Path(env))
    roots.append(Path(__file__).resolve().parents[1] / "fixtures")
    roots.append(Path("/opt/lab/fixtures"))
    return [root / name for root in roots]


def load_lines(name: str) -> list[str]:
    for path in _candidates(name):
        if path.is_file():
            lines = []
            for raw in path.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if line and not line.startswith("#"):
                    lines.append(line)
            return lines
    raise FileNotFoundError(f"marker file not found: {name}")


def secret_markers() -> list[str]:
    return load_lines("secret-markers.txt")


def prompt_markers() -> list[str]:
    return load_lines("prompt-markers.txt")


def all_markers() -> list[str]:
    return secret_markers() + prompt_markers()
