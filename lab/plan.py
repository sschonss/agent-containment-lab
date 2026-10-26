"""Load the deterministic plan embedded in the planted AGENTS.md."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from lab.errors import ToolError

_PLAN_RE = re.compile(r"<!--\s*lab-plan\s*(\{.*?\})\s*-->", re.DOTALL)


def load_plan(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    match = _PLAN_RE.search(text)
    if match is None:
        raise ToolError("AGENTS.md is missing a lab-plan block")
    try:
        payload = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        raise ToolError("lab-plan block is not valid JSON") from exc
    steps = payload.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ToolError("lab-plan has no steps")
    normalized: list[dict[str, Any]] = []
    for step in steps:
        if not isinstance(step, dict) or not isinstance(step.get("tool"), str):
            raise ToolError("lab-plan step is invalid")
        args = step.get("args", {})
        if not isinstance(args, dict):
            raise ToolError("lab-plan args are invalid")
        normalized.append({"tool": step["tool"], "args": args})
    return normalized
