#!/usr/bin/env python3
"""PLAMEN startup banner — single-flush truecolor ANSI output."""
import sys, shutil, io, os

# Windows: enable VT100 escape processing + force UTF-8 stdout
if sys.platform == "win32":
    os.system("")  # enables ANSI escape processing on Windows 10+
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

# ── constants (pre-computed at import time) ──────────────────
_RST  = "\x1b[0m"
_BOLD = "\x1b[1m"
_DIM  = "\x1b[38;2;100;100;100m"
_MUT  = "\x1b[38;2;120;120;120m"
_DCLR = "\x1b[38;2;60;60;60m"
_ACCENT = "\x1b[38;2;112;48;255m"  # #7030FF purple
_GRN  = "\x1b[38;2;34;199;46m"  # #22C72E green
_BLUE = "\x1b[38;2;100;149;237m"
_WHT  = "\x1b[38;2;255;255;255m"

_ART = [
    "\u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2557      \u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2557   \u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2557   \u2588\u2588\u2557",
    "\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2551     \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2551",
    "\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551     \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2554\u2588\u2588\u2588\u2588\u2554\u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2554\u2588\u2588\u2557 \u2588\u2588\u2551",
    "\u2588\u2588\u2554\u2550\u2550\u2550\u255d \u2588\u2588\u2551     \u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2551\u255a\u2588\u2588\u2554\u255d\u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u255d  \u2588\u2588\u2551\u255a\u2588\u2588\u2557\u2588\u2588\u2551",
    "\u2588\u2588\u2551     \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2551 \u255a\u2550\u255d \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551 \u255a\u2588\u2588\u2588\u2588\u2551",
    "\u255a\u2550\u255d     \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u255d  \u255a\u2550\u255d\u255a\u2550\u255d     \u255a\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u255d  \u255a\u2550\u2550\u2550\u255d",
]

_GRAD = [
    ( 34, 199,  46),  # #22C72E green
    ( 50, 169,  88),  # #32A958
    ( 65, 139, 130),  # #418B82
    ( 81, 108, 171),  # #516CAB
    ( 96,  78, 213),  # #604ED5
    (112,  48, 255),  # #7030FF purple
]

def _paint_row(text, r, g, b):
    n = len(text)
    if n <= 1:
        return f"\x1b[38;2;{r};{g};{b}m{text}{_RST}"
    parts = []
    for i, ch in enumerate(text):
        t = i / (n - 1)
        cr = min(255, int(r + (255 - r) * 0.15 * t))
        cg = min(255, int(g + (255 - g) * 0.15 * t))
        cb = min(255, int(b + (255 - b) * 0.15 * t))
        parts.append(f"\x1b[38;2;{cr};{cg};{cb}m{ch}")
    parts.append(_RST)
    return "".join(parts)

# pre-compute colored banner rows
_BANNER = [_paint_row(row, *g) for row, g in zip(_ART, _GRAD)]

# ── render ───────────────────────────────────────────────────
def _build():
    w = min(shutil.get_terminal_size().columns, 62)
    div = f"  {_DCLR}{'─' * w}{_RST}"
    return "\n".join([
        "",
        *_BANNER,
        "",
        div,
        f"  {_GRN}⬡{_RST} {_WHT}Web3 Security Auditor{_RST}  {_DIM}v1.0{_RST}",
        "",
        f"  {_ACCENT}1{_RST}  {_BOLD}{_WHT}Light{_RST}       {_BLUE}~18-22 agents{_RST}  {_GRN}fast review{_RST}       {_DIM}needs: project path{_RST}",
        f"  {_ACCENT}2{_RST}  {_BOLD}{_WHT}Core{_RST}        {_BLUE}~30-50 agents{_RST}  {_GRN}deep review{_RST}       {_DIM}needs: project path{_RST}",
        f"  {_ACCENT}3{_RST}  {_BOLD}{_WHT}Thorough{_RST}    {_BLUE}~40-100 agents{_RST} {_GRN}all severities{_RST}    {_DIM}needs: project path{_RST}",
        "",
        div,
        f"  {_MUT}you'll provide →  target (path/address)  ·  scope.txt (optional){_RST}",
        "",
        f"  {_ACCENT}›{_RST}  Select mode {_DIM}[1]{_RST}",
        "",
    ])

sys.stdout.write(_build())
sys.stdout.flush()
