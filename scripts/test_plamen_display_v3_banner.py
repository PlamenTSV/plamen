"""User-facing pipeline banner version regression."""

from __future__ import annotations

from io import StringIO

from rich.console import Console

import plamen_display as display


def test_rich_pipeline_banner_identifies_plamen_v3(monkeypatch) -> None:
    stream = StringIO()
    monkeypatch.setattr(
        display,
        "console",
        Console(file=stream, force_terminal=False, color_system=None, width=80),
    )
    monkeypatch.setattr(display, "RICH_AVAILABLE", True)

    display.print_banner(
        "sc", "thorough", "/workspace/project", 75, 0,
        "/workspace/project/.scratchpad", "Codex / gpt-5.6-sol", "evm",
    )

    rendered = stream.getvalue()
    assert "PLAMEN V3" in rendered
    assert "PLAMEN V2" not in rendered
    assert "SC / THOROUGH" in rendered
