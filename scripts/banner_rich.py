#!/usr/bin/env python3
"""PLAMEN startup banner — rich 256-color version for Claude Code testing."""
import sys, io, os

# Windows: enable VT100 escape processing + force UTF-8 stdout
if sys.platform == "win32":
    os.system("")
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

from rich.console import Console
from rich.text import Text
from rich.table import Table
from rich import box
from rich.rule import Rule
from rich.panel import Panel

console = Console(file=sys.stdout, force_terminal=True, force_jupyter=False, highlight=False, legacy_windows=False)

# ── Brand gradient: green #22C72E → purple #7030FF ──────────
_GRAD_COLORS = ["#22C72E", "#32A958", "#418B82", "#516CAB", "#604ED5", "#7030FF"]

_ART = [
    " ██████╗ ██╗      █████╗ ███╗   ███╗███████╗███╗   ██╗",
    " ██╔══██╗██║     ██╔══██╗████╗ ████║██╔════╝████╗  ██║",
    " ██████╔╝██║     ███████║██╔████╔██║█████╗  ██╔██╗ ██║",
    " ██╔═══╝ ██║     ██╔══██║██║╚██╔╝██║██╔══╝  ██║╚██╗██║",
    " ██║     ███████╗██║  ██║██║ ╚═╝ ██║███████╗██║ ╚████║",
    " ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═══╝",
]

# ── Pre-build banner rows ────────────────────────────────────
BANNER = []
for row, hex_color in zip(_ART, _GRAD_COLORS):
    t = Text(row)
    t.stylize(f"bold {hex_color}")
    BANNER.append(t)

# ── Subtitle ─────────────────────────────────────────────────
SUBTITLE = Text()
SUBTITLE.append("  ⬡ ", style="#22C72E")
SUBTITLE.append("Web3 Security Auditor", style="bold white")
SUBTITLE.append("  v1.0", style="color(240)")

# ── Mode table ───────────────────────────────────────────────
MODE_TABLE = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), expand=False)
MODE_TABLE.add_column("#", width=3, style="bold #7030FF")
MODE_TABLE.add_column("Mode", width=18, style="bold white")
MODE_TABLE.add_column("Agents", width=14, style="color(75)")
MODE_TABLE.add_column("Scope", width=18, style="#22C72E")
MODE_TABLE.add_column("Needs", style="color(240)")

MODE_TABLE.add_row("1", "Light Audit", "18–22 agents", "fast review", "contract path or 0x address")
MODE_TABLE.add_row("2", "Core Audit", "30–50 agents", "deep review", "contract + optional docs")
MODE_TABLE.add_row("3", "Thorough Audit", "40–100 agents", "ALL severities", "contract + optional docs")

# ── Footer ───────────────────────────────────────────────────
FOOTER = Text("  you'll provide →  target (path/address)  ·  scope.txt (optional)")
FOOTER.stylize("color(245)")

PROMPT_LINE = Text()
PROMPT_LINE.append("  › ", style="bold #7030FF")
PROMPT_LINE.append("Select mode ", style="white")
PROMPT_LINE.append("[1]", style="color(240)")

# ── Render ───────────────────────────────────────────────────
def show_menu():
    console.print()
    for row in BANNER:
        console.print(row)
    console.print()
    console.print(Rule(style="color(238)"))
    console.print(SUBTITLE)
    console.print()
    console.print(MODE_TABLE)
    console.print(Rule(style="color(238)"))
    console.print(FOOTER)
    console.print()
    console.print(PROMPT_LINE)
    console.print()

if __name__ == "__main__":
    show_menu()
