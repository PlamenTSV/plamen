"""Closed report-output routing shared by the driver and POSIX supervisor."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping


REPORT_OUTPUT_CONFIG_KEY = "_report_output_path"
STAGED_REPORT_ARTIFACT = "project/AUDIT_REPORT.md"
GUEST_REPORT_PATH = "/workspace/scratch/AUDIT_REPORT.md"
PUBLISHED_REPORT_PATH = "AUDIT_REPORT.md"


def resolve_report_output_path(config: Mapping[str, Any]) -> Path:
    """Return the public report path or the exact native scratch staging slot."""

    project_root = Path(str(config["project_root"]))
    configured = config.get(REPORT_OUTPUT_CONFIG_KEY)
    if configured in (None, ""):
        return project_root / PUBLISHED_REPORT_PATH
    if not isinstance(configured, str):
        raise ValueError("internal report output path must be text")
    report = Path(configured)
    scratchpad = Path(str(config["scratchpad"]))
    if (
        not report.is_absolute()
        or report.name != PUBLISHED_REPORT_PATH
        or report.parent != scratchpad
    ):
        raise ValueError(
            "internal report output path must be the exact scratchpad report slot"
        )
    return report


__all__ = [
    "GUEST_REPORT_PATH",
    "PUBLISHED_REPORT_PATH",
    "REPORT_OUTPUT_CONFIG_KEY",
    "STAGED_REPORT_ARTIFACT",
    "resolve_report_output_path",
]
