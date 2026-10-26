"""Workspace path resolution. Rejects paths that leave the fixture root."""

from __future__ import annotations

from pathlib import Path

from lab.errors import ToolError


class Workspace:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise ToolError("workspace is not a directory")

    def resolve(self, raw: str) -> Path:
        if raw is None or raw.strip() == "":
            raise ToolError("path is required")
        if "\x00" in raw:
            raise ToolError("path is invalid")
        candidate = (self.root / raw).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise ToolError("path escapes workspace")
        return candidate
