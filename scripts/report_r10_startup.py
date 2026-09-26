"""Restore durable R10 readiness before refreshing report routing on startup."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable


def restore_r10_then_refresh_report_routing(
    scratchpad: Path,
    config: dict[str, Any],
    *,
    establish_ready: Callable[[Path, dict[str, Any]], list[str]],
    refresh_routing: Callable[
        [Path, dict[str, Any]], tuple[dict[str, dict], list[str]]
    ],
) -> list[str]:
    """Replay committed R10 authority before any report-routing consumer."""

    issues = list(establish_ready(Path(scratchpad), config))
    if issues:
        return list(dict.fromkeys(issues))
    _manifests, issues = refresh_routing(Path(scratchpad), config)
    return list(dict.fromkeys(issues))


__all__ = ["restore_r10_then_refresh_report_routing"]
