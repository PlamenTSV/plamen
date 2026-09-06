"""Plamen V2 driver -- terminal display layer.

Provides rich-formatted output for the pipeline driver: colored status,
phase progress panels, failure diagnosis, and timing information.

Drop-in replacement for raw print() calls in plamen_driver.py.
Falls back to plain text if rich is unavailable.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import threading
from pathlib import Path
from typing import Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.style import Style
    from rich.markup import escape
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class _LifecycleSafeTextStream:
    """Best-effort terminal stream that cannot terminate an audit.

    Codex, Claude, CI runners, and SSH sessions may close their captured output
    pipes while the independently useful audit process is still running.  A
    later ``print(..., flush=True)`` would otherwise raise ``BrokenPipeError``
    (or a Windows invalid-handle ``OSError``) and unwind the orchestrator before
    its next durable phase checkpoint.  Terminal output is observational, not
    authoritative, so detach that channel after its first write/flush failure.
    """

    def __init__(self, stream):
        self._stream = stream
        self._detached = False
        self._lock = threading.Lock()

    @property
    def detached(self) -> bool:
        return self._detached

    def write(self, value):
        if self._detached:
            return len(value) if value is not None else 0
        with self._lock:
            if self._detached:
                return len(value) if value is not None else 0
            try:
                return self._stream.write(value)
            except (BrokenPipeError, OSError, ValueError):
                self._detached = True
                return len(value) if value is not None else 0

    def flush(self):
        if self._detached:
            return None
        with self._lock:
            if self._detached:
                return None
            try:
                return self._stream.flush()
            except (BrokenPipeError, OSError, ValueError):
                self._detached = True
                return None

    def isatty(self):
        if self._detached:
            return False
        try:
            return bool(self._stream.isatty())
        except Exception:
            return False

    def __getattr__(self, name):
        return getattr(self._stream, name)


def install_detached_output_guards() -> None:
    """Make stdout/stderr loss non-fatal for the process lifetime.

    This is deliberately explicit instead of running at import time: the
    installed-package admission handshake uses stdout as a security protocol
    before the driver imports this module, and protocol failures must remain
    fail-closed.  The audit entrypoint enables these guards after admission and
    CLI discovery have completed.
    """

    if not isinstance(sys.stdout, _LifecycleSafeTextStream):
        sys.stdout = _LifecycleSafeTextStream(sys.stdout)
    if not isinstance(sys.stderr, _LifecycleSafeTextStream):
        sys.stderr = _LifecycleSafeTextStream(sys.stderr)


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


_FORCE_RICH_OUTPUT = _env_truthy("PLAMEN_FORCE_RICH")
_PLAIN_OUTPUT = _env_truthy("PLAMEN_PLAIN_OUTPUT")
_NO_COLOR = "NO_COLOR" in os.environ
_CAPTURED_OUTPUT = (
    not bool(getattr(sys.stderr, "isatty", lambda: False)())
    or os.environ.get("TERM", "").strip().lower() == "dumb"
    or os.environ.get("CI", "").strip().lower() in {"1", "true", "yes"}
    or any(os.environ.get(name) for name in (
        "CLAUDECODE",
        "CLAUDE_CODE",
        "CLAUDE_SESSION_ID",
        "CODEX_SANDBOX",
    ))
)

# Rich panels and carriage-return spinners render badly in captured shell
# panes such as Claude Code's Shell details view. Default to plain, line-safe
# output whenever stderr is not an interactive terminal. Operators can still
# force Rich in a real terminal with PLAMEN_FORCE_RICH=1.
RICH_AVAILABLE = RICH_AVAILABLE and (
    _FORCE_RICH_OUTPUT or (not _PLAIN_OUTPUT and not _CAPTURED_OUTPUT)
)

# Brand colors: green #22C72E → purple #7030FF
_BRAND_GREEN = (0x22, 0xC7, 0x2E)
_BRAND_PURPLE = (0x70, 0x30, 0xFF)


def _gradient_text(text: str, bold: bool = True) -> "Text":
    """Create a Text object with per-character green→purple gradient."""
    result = Text(text, end="")
    chars = [i for i, c in enumerate(text) if c != " "]
    n = max(len(chars) - 1, 1)
    for step, idx in enumerate(chars):
        t = step / n
        r = int(_BRAND_GREEN[0] + (_BRAND_PURPLE[0] - _BRAND_GREEN[0]) * t)
        g = int(_BRAND_GREEN[1] + (_BRAND_PURPLE[1] - _BRAND_GREEN[1]) * t)
        b = int(_BRAND_GREEN[2] + (_BRAND_PURPLE[2] - _BRAND_GREEN[2]) * t)
        style = Style(color=f"#{r:02x}{g:02x}{b:02x}", bold=bold)
        result.stylize(style, idx, idx + 1)
    return result

# Module-level console -- always stderr (driver output channel)
console = Console(stderr=True, highlight=False, no_color=_NO_COLOR) if RICH_AVAILABLE else None


def _extract_agent_text_from_event_stream(text: str) -> str:
    """Extract human-readable text from Codex/Claude JSONL event output."""
    if not text or not text.lstrip().startswith("{"):
        return text
    parts: list[str] = []
    saw_event = False
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("{"):
            continue
        try:
            event = json.loads(s)
        except Exception:
            continue
        if not isinstance(event, dict) or "type" not in event:
            continue
        saw_event = True
        item = event.get("item")
        if isinstance(item, dict):
            item_type = item.get("type")
            item_text = item.get("text")
            if item_type in {"agent_message", "message"} and isinstance(item_text, str):
                parts.append(item_text)
                continue
        event_text = event.get("text")
        if isinstance(event_text, str):
            parts.append(event_text)
    if parts:
        return "\n\n".join(parts).strip()
    return text if not saw_event else "[Diagnosis produced only non-message JSON events]"


# Track timing state
_pipeline_start: float = 0.0
_phase_start: float = 0.0
_total_phases: int = 0
_completed_phases: int = 0

# Inline spinner — shows the terminal is alive between heartbeat prints
_SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
_spinner_idx: int = 0
_spinner_active: bool = False
_last_spinner_draw: float = 0.0
# Keep the live terminal visibly alive without adding log lines. Default brisk;
# override with PLAMEN_SPINNER_INTERVAL_S if a terminal renders too aggressively.
try:
    _SPINNER_REDRAW_INTERVAL_S = max(
        0.05,
        float(os.environ.get("PLAMEN_SPINNER_INTERVAL_S", "0.10")),
    )
except Exception:
    _SPINNER_REDRAW_INTERVAL_S = 0.10


def spin(elapsed_s: int):
    """Update inline spinner with elapsed time. Overwrites current line via \\r."""
    global _spinner_idx, _spinner_active, _last_spinner_draw
    if not RICH_AVAILABLE:
        return
    now = time.time()
    if now - _last_spinner_draw < _SPINNER_REDRAW_INTERVAL_S:
        return
    _last_spinner_draw = now
    _spinner_idx = (_spinner_idx + 1) % len(_SPINNER_FRAMES)
    frame = _SPINNER_FRAMES[_spinner_idx]
    mins, secs = divmod(elapsed_s, 60)
    sys.stderr.write(f"\r         {frame} {mins}:{secs:02d} | working")
    sys.stderr.flush()
    _spinner_active = True


def _clear_spinner():
    """Clear the spinner line before printing a full output line."""
    global _spinner_active
    if _spinner_active:
        sys.stderr.write("\r" + " " * 40 + "\r")
        sys.stderr.flush()
        _spinner_active = False


def _elapsed_str(start: float) -> str:
    """Format elapsed time since start as M:SS or H:MM:SS."""
    elapsed = int(time.time() - start)
    if elapsed >= 3600:
        h, rem = divmod(elapsed, 3600)
        m, s = divmod(rem, 60)
        return f"{h}:{m:02d}:{s:02d}"
    m, s = divmod(elapsed, 60)
    return f"{m}:{s:02d}"


# ─── Banner ─────────────────────────────────────────────────────────────


def print_banner(pipeline: str, mode: str, project_root: str,
                 remaining: int, completed: int, scratchpad: str,
                 ai_model: str = "", ecosystem: str = ""):
    """Print the startup banner with pipeline info.

    `ecosystem` is the detected language/ecosystem (e.g. "evm", "solana") from
    config["language"]; shown as a dedicated row when provided. Purely UI/UX.
    """
    global _pipeline_start, _total_phases, _completed_phases
    _pipeline_start = time.time()
    _total_phases = remaining + completed
    _completed_phases = completed
    eco = (ecosystem or "").strip().upper()

    if not RICH_AVAILABLE:
        ai_line = f"  AI Model: {ai_model}\n" if ai_model else ""
        eco_line = f"  Ecosystem: {eco}\n" if eco else ""
        print(
            f"\n{'=' * 60}\n"
            f"  PLAMEN V2 DRIVER -- {pipeline.upper()} / {mode.upper()}\n"
            f"{eco_line}"
            f"  Project:  {project_root}\n"
            f"{ai_line}"
            f"  Phases:   {remaining + completed} total ({remaining} remaining)\n"
            f"  Esc:      halt (kills subprocess, choose resume or exit)\n"
            f"  Ctrl+P:   pause/unpause between phases\n"
            f"  On rate limit: auto-waits with countdown, Enter to retry\n"
            f"{'=' * 60}\n",
            file=sys.stderr, flush=True,
        )
        return

    table = Table(show_header=False, show_edge=False, padding=(0, 1),
                  border_style="dim")
    table.add_column(style="dim", width=12)
    table.add_column()
    table.add_row("Pipeline", f"[bold]{pipeline.upper()}[/] / [bold]{mode.upper()}[/]")
    if eco:
        table.add_row("Ecosystem", f"[bold #7030FF]{eco}[/]")
    table.add_row("Project", f"[white]{project_root}[/]")
    if ai_model:
        table.add_row("AI Model", f"[white]{escape(ai_model)}[/]")
    total = remaining + completed
    table.add_row("Phases", f"[bold #22C72E]{total}[/] total ({remaining} remaining)")
    table.add_row("Esc", "[bold red]halt[/] [dim]-- kills subprocess, choose resume or exit[/]")
    table.add_row("Ctrl+P", "[bold yellow]pause/unpause[/] [dim]-- waits between phases[/]")
    table.add_row("Rate limit", "[dim]auto-waits with countdown, ENTER to retry early[/]")

    title = _gradient_text(" PLAMEN V2 ")
    console.print()
    console.print(Panel(table, title=title, border_style="#7030FF",
                        width=min(console.width, 72)))
    console.print()


# ─── Phase lifecycle ────────────────────────────────────────────────────


def print_phase_start(phase_idx: int, total: int, phase_name: str,
                      model: str, attempt: int = 1):
    """Print phase start indicator."""
    _clear_spinner()
    global _phase_start, _total_phases
    _phase_start = time.time()
    _total_phases = max(_total_phases, total)

    if not RICH_AVAILABLE:
        suffix = f" (retry #{attempt})" if attempt > 1 else ""
        print(
            f"[{phase_idx}/{total}] {phase_name} -- starting "
            f"(model={model}){suffix}...",
            file=sys.stderr, flush=True,
        )
        return

    progress_pct = int(((phase_idx - 1) / total) * 100) if total else 0
    bar_width = 20
    filled = int(bar_width * progress_pct / 100)
    bar = f"[#22C72E]{'━' * filled}[/][dim]{'╌' * (bar_width - filled)}[/]"

    retry_tag = f" [yellow](retry #{attempt})[/]" if attempt > 1 else ""

    console.print(
        f"  {bar} [bold]{phase_idx}[/]/{total}  "
        f"[bold white]{phase_name}[/] [dim]({model})[/]"
        f"{retry_tag}"
    )


def print_phase_heartbeat(phase_name: str, elapsed_s: int,
                          new_artifacts: Optional[list[str]] = None,
                          updated_artifacts: Optional[list[str]] = None,
                          status: Optional[str] = None,
                          status_style: str = "warning",
                          tool_calls_delta_kb: Optional[float] = None):
    """Print heartbeat progress line."""
    _clear_spinner()
    mins, secs = divmod(elapsed_s, 60)
    time_str = f"{mins}:{secs:02d}"

    if not RICH_AVAILABLE:
        if new_artifacts:
            names = ", ".join(new_artifacts[:4])
            extra = f" +{len(new_artifacts) - 4} more" if len(new_artifacts) > 4 else ""
            print(f"         ... {time_str} | +{names}{extra}",
                  file=sys.stderr, flush=True)
        elif updated_artifacts:
            names = ", ".join(updated_artifacts[:4])
            extra = f" +{len(updated_artifacts) - 4} more" if len(updated_artifacts) > 4 else ""
            print(f"         ... {time_str} | ~{names}{extra}",
                  file=sys.stderr, flush=True)
        elif status:
            print(f"         ... {time_str} | {status}",
                  file=sys.stderr, flush=True)
        elif tool_calls_delta_kb is not None:
            print(f"         ... {time_str} | working (+{tool_calls_delta_kb:.0f}KB tool calls)",
                  file=sys.stderr, flush=True)
        else:
            print(f"         ... {time_str} | waiting",
                  file=sys.stderr, flush=True)
        return

    if new_artifacts:
        names = ", ".join(new_artifacts[:4])
        extra = f" [dim]+{len(new_artifacts) - 4} more[/]" if len(new_artifacts) > 4 else ""
        console.print(
            f"         [dim]{time_str}[/] | [#22C72E]+{escape(names)}[/]{extra}"
        )
    elif updated_artifacts:
        names = ", ".join(updated_artifacts[:4])
        extra = f" [dim]+{len(updated_artifacts) - 4} more[/]" if len(updated_artifacts) > 4 else ""
        console.print(
            f"         [dim]{time_str}[/] | [#E6B800]~{escape(names)}[/]{extra}"
        )
    elif status:
        color = "#66A3FF" if status_style == "info" else "#E6B800"
        console.print(
            f"         [dim]{time_str}[/] | [{color}]{escape(status)}[/]"
        )
    elif tool_calls_delta_kb is not None:
        console.print(
            f"         [dim]{time_str}[/] | [#7030FF]working[/] [dim](+{tool_calls_delta_kb:.0f}KB tool calls)[/]"
        )
    else:
        console.print(
            f"         [dim]{time_str}[/] | [dim]waiting[/]"
        )


def print_phase_done(phase_idx: int, total: int, phase_name: str,
                     gate_summary: str = ""):
    """Print phase completion line."""
    _clear_spinner()
    global _completed_phases, _total_phases
    _total_phases = max(_total_phases, total)
    _completed_phases += 1

    phase_elapsed = _elapsed_str(_phase_start) if _phase_start else ""
    pipeline_elapsed = _elapsed_str(_pipeline_start) if _pipeline_start else ""
    remaining = max(0, _total_phases - _completed_phases)

    if not RICH_AVAILABLE:
        print(f"    + {phase_name}  ({remaining} remaining, {pipeline_elapsed} elapsed)",
              file=sys.stderr, flush=True)
        if gate_summary:
            print(f"         {gate_summary}", file=sys.stderr, flush=True)
        return

    console.print(
        f"    [#22C72E]+[/] [bold]{phase_name}[/]"
        f"  [dim]{phase_elapsed}[/]"
        f"  [dim]({remaining} remaining, {pipeline_elapsed} total)[/]"
    )
    if gate_summary:
        # Wrap long gate summaries to keep indentation clean
        import shutil as _shutil
        term_w = _shutil.get_terminal_size((80, 24)).columns
        prefix = "         gate: "
        max_line = term_w - len(prefix) - 2
        if len(gate_summary) > term_w - 10:
            # Split after "gate: " and wrap artifact list
            body = gate_summary.removeprefix("gate: ") if gate_summary.startswith("gate: ") else gate_summary
            items = [s.strip() for s in body.split(",")]
            lines = []
            cur = ""
            for item in items:
                candidate = f"{cur}, {item}" if cur else item
                if len(candidate) > max_line and cur:
                    lines.append(cur)
                    cur = item
                else:
                    cur = candidate
            if cur:
                lines.append(cur)
            console.print(f"         [dim]gate: {lines[0]}[/]")
            for line in lines[1:]:
                console.print(f"               [dim]{line}[/]")
        else:
            console.print(f"         [dim]{gate_summary}[/]")


def print_phase_skipped(phase_idx: int, total: int, phase_name: str,
                        reason: str):
    """Print phase skip indicator."""
    global _completed_phases
    _completed_phases += 1

    if not RICH_AVAILABLE:
        print(f"[{phase_idx}/{total}] {phase_name} -- skipped ({reason})",
              file=sys.stderr, flush=True)
        return

    console.print(
        f"    [dim]- {phase_name} -- {reason}[/]"
    )


def print_phase_retry(phase_idx: int, total: int, phase_name: str,
                      missing: list):
    """Print retry indicator after gate failure."""
    if not RICH_AVAILABLE:
        print(
            f"[{phase_idx}/{total}] {phase_name} -- "
            f"gate FAILED (attempt 1), retrying...",
            file=sys.stderr, flush=True,
        )
        return

    missing_str = ", ".join(str(m) for m in missing[:3])
    if len(missing) > 3:
        missing_str += f" +{len(missing) - 3} more"
    console.print(
        f"    [yellow]~[/] [bold]{phase_name}[/] -- "
        f"[yellow]gate failed[/], retrying  [dim]({missing_str})[/]"
    )


# ─── Failure & Halt ─────────────────────────────────────────────────────


def print_phase_degraded(phase_name: str, missing: list, critical: bool):
    """Print degraded phase indicator."""
    if not RICH_AVAILABLE:
        if critical:
            print(f"\nPipeline HALTED -- critical phase '{phase_name}' failed.",
                  file=sys.stderr)
            print(f"Missing: {missing}", file=sys.stderr)
        else:
            print(f"[{phase_name}] degraded after 2 attempts: {missing}",
                  file=sys.stderr)
        return

    missing_str = "\n".join(f"  * {m}" for m in missing)
    if critical:
        content = (
            f"[bold red]Critical phase failed -- pipeline halted[/]\n\n"
            f"[bold]Phase:[/] {phase_name}\n"
            f"[bold]Missing artifacts:[/]\n{missing_str}"
        )
        console.print()
        console.print(Panel(content, title="[bold red]! HALT[/]",
                            border_style="red", width=min(console.width, 72)))
    else:
        console.print(
            f"    [red]x[/] [bold]{phase_name}[/] -- "
            f"[red]degraded[/] after 2 attempts"
        )
        console.print(f"         [dim]{missing_str}[/]")


def print_halt_diagnostics(phase_name: str, scratchpad: str,
                           config_path: str):
    """Print diagnostic info box after a critical phase halt."""
    sp = Path(scratchpad)
    logs = sorted(sp.glob(f"_stdio_{phase_name}.attempt*.log"))
    prompts = sorted(sp.glob(f"_prompt_{phase_name}.attempt*.md"))

    if not RICH_AVAILABLE:
        print(f"\nDiagnostic logs: {', '.join(str(l) for l in logs)}",
              file=sys.stderr)
        print(f"Prompt snapshots: {', '.join(str(p) for p in prompts)}",
              file=sys.stderr)
        print(f"\nResume: python ~/.claude/scripts/plamen_driver.py \"{config_path}\"",
              file=sys.stderr)
        return

    table = Table(show_header=False, show_edge=False, padding=(0, 1))
    table.add_column(style="dim", width=12)
    table.add_column()
    for l in logs:
        size_kb = l.stat().st_size / 1024 if l.exists() else 0
        table.add_row("Log", f"[white]{l.name}[/] [dim]({size_kb:.0f}KB)[/]")
    for p in prompts:
        size_kb = p.stat().st_size / 1024 if p.exists() else 0
        table.add_row("Prompt", f"[white]{p.name}[/] [dim]({size_kb:.0f}KB)[/]")
    table.add_row("", "")
    table.add_row("Resume", f"[bold]python ~/.claude/scripts/plamen_driver.py \"{config_path}\"[/]")

    console.print(Panel(table, title="[dim]Diagnostics[/]", border_style="dim",
                        width=min(console.width, 72)))


def print_failure_diagnosis(phase_name: str, scratchpad: str,
                            missing: list, config: dict):
    """Generate a deterministic local diagnosis of a failed phase.

    Reads the stdio log + prompt snapshot and produces a structured
    diagnosis that can be passed directly into a fixing session.
    Writes the diagnosis to {scratchpad}/_diagnosis_{phase_name}.md for
    persistence across sessions.
    """
    sp = Path(scratchpad)

    # Find the most recent attempt log
    logs = sorted(sp.glob(f"_stdio_{phase_name}.attempt*.log"), reverse=True)
    if not logs:
        logs = [sp / f"_stdio_{phase_name}.log"]
    log_path = logs[0]
    if not log_path.exists():
        return

    try:
        log_content = log_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return

    # Read the prompt snapshot for context on what was asked
    prompt_content = ""
    prompts = sorted(sp.glob(f"_prompt_{phase_name}.attempt*.md"), reverse=True)
    if prompts and prompts[0].exists():
        try:
            raw = prompts[0].read_text(encoding="utf-8", errors="replace")
            # First 4000 chars of prompt for context on what was expected
            prompt_content = raw[:4000]
        except Exception:
            pass

    # Take last ~20000 chars of log for deep analysis
    log_tail = log_content[-20000:] if len(log_content) > 20000 else log_content

    # For Codex backend: read --output-last-message file if it exists.
    # This captures the Codex agent's final message independently of JSONL
    # parsing, which can be more readable for diagnosis.
    codex_output_content = ""
    if config.get("cli_backend") == "codex":
        codex_outputs = sorted(
            sp.glob(f"_codex_output_{phase_name}.attempt*.md"), reverse=True
        )
        for co in codex_outputs:
            if co.exists() and co.stat().st_size > 0:
                try:
                    raw_co = co.read_text(encoding="utf-8", errors="replace")
                    codex_output_content = raw_co[-5000:]
                except Exception:
                    pass
                break

    # Read gate expectations from phase config
    missing_str = "\n".join(f"  - {m}" for m in missing)

    is_codex = config.get("cli_backend") == "codex"
    diagnosis_prompt = (
        f"You are a pipeline failure diagnostician for the Plamen V2 security "
        f"audit driver. A phase named '{phase_name}' failed its gate check "
        f"after 2 attempts.\n\n"
        f"## Required artifacts that are MISSING:\n{missing_str}\n\n"
        f"## Pipeline context:\n"
        f"- Pipeline: {config.get('pipeline', '?')}\n"
        f"- Mode: {config.get('mode', '?')}\n"
        f"- Language: {config.get('language', '?')}\n"
        f"- Backend: {config.get('cli_backend', 'claude')}\n"
        f"- Scratchpad: {scratchpad}\n\n"
    )
    if is_codex and phase_name == "depth":
        diagnosis_prompt += (
            "## IMPORTANT: Codex driver-side synthesis\n"
            "For the Codex backend, the driver auto-generates `depth_exit.md` "
            "and `never_cut_checkpoint.md` BEFORE running validators (via "
            "`_synthesize_depth_lifecycle_artifacts` with `force=True`). "
            "If those files still fail validation, the cause is a bug in the "
            "synthesis function or the validator — NOT in the LLM prompt or "
            "LLM output. Do NOT recommend prompt changes for these files. "
            "Focus on what SUBSTANTIVE finding artifacts the LLM failed to "
            "produce (depth_*_findings.md, confidence_scores.md, etc.).\n\n"
        )

    if prompt_content:
        diagnosis_prompt += (
            f"## Prompt given to the subprocess (first 4000 chars):\n"
            f"```\n{prompt_content}\n```\n\n"
        )

    diagnosis_prompt += (
        f"## Subprocess output log (last ~20KB):\n"
        f"```\n{log_tail}\n```\n\n"
    )

    if codex_output_content:
        diagnosis_prompt += (
            f"## Codex final agent message (--output-last-message, last ~5KB):\n"
            f"```\n{codex_output_content}\n```\n\n"
        )

    diagnosis_prompt += (
        f"## Your task:\n"
        f"Produce a structured diagnosis in this EXACT format:\n\n"
        f"### What Happened\n"
        f"[2-3 sentences: what the subprocess was doing, how far it got, "
        f"what the last meaningful action was]\n\n"
        f"### Root Cause\n"
        f"[The specific reason it failed to produce the required artifacts. "
        f"Cite exact error messages, function names, or behavioral patterns "
        f"from the log. Be concrete -- 'the LLM ran out of context' vs "
        f"'the gate regex didn't match' vs 'the subprocess timed out at "
        f"X minutes while spawning agent Y' etc.]\n\n"
        f"### Classification\n"
        f"[One of: TIMEOUT | RATE_LIMIT | GATE_MISMATCH | LLM_NONCOMPLIANCE "
        f"| PROMPT_ERROR | MISSING_INPUT | CONTEXT_EXHAUSTION | "
        f"SUBPROCESS_CRASH | UNKNOWN]\n\n"
        f"### Fix Guidance\n"
        f"[Specific, actionable guidance for a follow-up session. Reference "
        f"the driver code (plamen_driver.py, plamen_prompt.py, "
        f"plamen_validators.py, plamen_types.py) where relevant. If a gate "
        f"regex is too strict, say which one. If a timeout is too short, "
        f"say what value to increase. If the LLM produced wrong format, "
        f"quote the format it produced vs what was expected.]\n\n"
        f"Be specific and technical. This diagnosis will be read by a "
        f"developer fixing the pipeline code."
    )

    def _local_diagnosis(reason: str) -> str:
        missing_preview = "\n".join(f"- {m}" for m in missing[:12])
        classification = "GATE_MISMATCH"
        low = (reason + "\n" + missing_str + "\n" + log_tail[-4000:]).lower()
        if "rate limit" in low or "429" in low:
            classification = "RATE_LIMIT"
        elif "timeout" in low or "timed out" in low:
            classification = "TIMEOUT"
        elif "containment" in low or "out-of-scope" in low:
            classification = "LLM_NONCOMPLIANCE"
        elif "queue receipt" in low or "marker" in low or "structural" in low:
            classification = "GATE_MISMATCH"
        fix = (
            "Inspect the named phase gate in plamen_validators.py and the latest "
            "phase artifact/log. If the artifact is substantively complete but "
            "uses a reasonable alternate format, normalize the parser or retry "
            "hint without weakening artifact existence, path citation, or "
            "phase-containment checks."
        )
        if phase_name == "attention_repair" or "attention repair" in low:
            fix = (
                "For attention_repair, verify attention_repair_summary.md has one "
                "receipt per attention_repair_queue.md row. If rows are present "
                "but marked with a synonym such as COVERED/REVIEWED/CLOSED, this "
                "is a validator vocabulary mismatch rather than lost audit work. "
                "Patch _validate_attention_repair in plamen_validators.py to "
                "accept the synonym while keeping path and asset-binding closure "
                "checks intact."
            )
        return (
            "### What Happened\n"
            f"The {phase_name} phase failed its artifact gate after retry exhaustion. "
            f"The advisory LLM diagnosis did not complete cleanly ({reason}), so "
            "the driver generated this deterministic local diagnosis from the "
            "gate error and latest log.\n\n"
            "### Root Cause\n"
            "The gate reported these blocking issue(s):\n"
            f"{missing_preview}\n\n"
            "### Classification\n"
            f"{classification}\n\n"
            "### Fix Guidance\n"
            f"{fix}"
        )

    # Failure diagnosis is advisory and must not create an unexpected paid
    # provider call after the audit phase has failed.  Old configs may still
    # contain allow_paid_failure_diagnosis=true, but it grants no authority
    # until this path is wired through the canonical contained provider.
    if True:  # unconditional until canonical contained-provider wiring exists
        diagnosis = _local_diagnosis(
            "paid provider diagnosis is disabled until the canonical "
            "contained provider is wired"
        )
        diagnosis_path = sp / f"_diagnosis_{phase_name}.md"
        try:
            header = (
                f"# Failure Diagnosis: {phase_name}\n\n"
                f"**Generated**: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"**Missing**: {', '.join(str(m) for m in missing)}\n"
                f"**Log**: {log_path.name} ({len(log_content)} bytes)\n\n---\n\n"
            )
            diagnosis_path.write_text(header + diagnosis, encoding="utf-8")
        except Exception:
            pass
        if not RICH_AVAILABLE:
            print(f"\n{diagnosis}\n", file=sys.stderr)
        else:
            console.print(Panel(diagnosis, title="[bold red]Failure Diagnosis[/]",
                                border_style="red", width=min(console.width, 90)))
        return

    backend = config.get("cli_backend", "claude")

    if backend == "codex":
        codex_bin = None
        if not codex_bin:
            return
    else:
        claude_bin = None
        if not claude_bin:
            return

    _label = "codex" if backend == "codex" else "sonnet"
    if RICH_AVAILABLE:
        console.print(f"\n    [dim]Running failure diagnosis ({_label})...[/]")
    else:
        print(f"\n    Running failure diagnosis ({_label})...", file=sys.stderr, flush=True)

    # Write prompt to a temp file — stdin pipe deadlocks on payloads >4-64KB
    # depending on OS pipe buffer size (v2.1.3 lesson).
    diagnosis_prompt_path = sp / f"_diagnosis_prompt_{phase_name}.md"
    try:
        diagnosis_prompt_path.write_text(diagnosis_prompt, encoding="utf-8")
    except Exception as e:
        if RICH_AVAILABLE:
            console.print(f"    [dim red]Diagnosis skipped: can't write prompt ({e})[/]")
        return

    if backend == "codex":
        from plamen_types import _CODEX_MODEL_MAP
        diag_model = _CODEX_MODEL_MAP.get("sonnet", "gpt-5.6-terra")
        cmd = [
            codex_bin, "exec",
            "--model", diag_model,
            "--json",
            "--ephemeral",
            "--disabled-direct-provider-path",
            "--skip-git-repo-check",
            "--ignore-user-config",
            "--ignore-rules",
            "-",
        ]
    else:
        from plamen_types import PLAMEN_SONNET_MODEL
        cmd = [
            claude_bin, "-p", "--model", PLAMEN_SONNET_MODEL,
            "--output-format", "text",
            "--no-session-persistence",
            "--disabled-direct-provider-path",
            "--disallowedTools", "mcp__*,Task,Agent",
        ]
        # Apply plugin/hook/MCP isolation via --settings overlay
        isolation_path = sp / "_subprocess_isolation.json"
        if isolation_path.exists():
            iso = isolation_path.as_posix()
            cmd.extend([
                "--settings", iso,
                "--strict-mcp-config", "--mcp-config", iso,
            ])

    parent_claude_identity_env_keys = {
        "CLAUDECODE",
        "CLAUDE_CODE_SESSION_ID",
        "CLAUDE_CODE_ENTRYPOINT",
        "CLAUDE_CODE_EXECPATH",
        "AI_AGENT",
    }
    base_env = {
        k: v for k, v in os.environ.items()
        if k not in parent_claude_identity_env_keys
    }
    subprocess_env = {
        **base_env,
        "ANTHROPIC_DISABLE_AUTOUPDATE": "1",
    }
    popen_kwargs: dict = {}
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = (
            subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
        )

    def _disabled_paid_diagnosis_process(*_args, **_kwargs):
        raise RuntimeError(
            "direct paid diagnosis is disabled; canonical provider required"
        )

    def _terminate_diagnosis_process(proc):
        try:
            if proc.poll() is not None:
                return
            if sys.platform == "win32":
                try:
                    _disabled_paid_diagnosis_process(
                        ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=2,
                    )
                    return
                except Exception:
                    pass
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
        except Exception:
            pass

    try:
        if graceful_stop.requested:
            diagnosis = _local_diagnosis(
                "diagnosis skipped because user requested stop"
            )
        else:
            # Advisory-diagnosis subprocess budget for a COLD `claude -p` /
            # `codex exec` spawn. 30s (Claude) / 60s (Codex) was too tight — a
            # cold LLM start routinely exceeded it, so almost every failure
            # diagnosis fell back to the deterministic local one instead of the
            # richer LLM explanation. Bumped, and made env-overridable
            # (PLAMEN_DIAGNOSIS_TIMEOUT_CEILING_S) mirroring the other timeout
            # ceilings. Purely advisory: this subprocess's result never affects
            # the halt/degrade decision, and a timeout still yields a safe
            # _local_diagnosis fallback — so raising it carries zero correctness
            # risk, only diagnosis-quality upside.
            _default_diag_timeout = 150 if backend == "codex" else 90
            try:
                timeout_s = max(1, int(float(os.environ.get(
                    "PLAMEN_DIAGNOSIS_TIMEOUT_CEILING_S",
                    str(_default_diag_timeout),
                ))))
            except Exception:
                timeout_s = _default_diag_timeout
            deadline = time.time() + timeout_s
            proc = None
            with diagnosis_prompt_path.open("rb") as stdin_file:
                proc = _disabled_paid_diagnosis_process(
                    cmd,
                    stdin=stdin_file,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=subprocess_env,
                    **popen_kwargs,
                )
                while proc.poll() is None:
                    if graceful_stop.requested:
                        _terminate_diagnosis_process(proc)
                        diagnosis = _local_diagnosis(
                            "diagnosis cancelled because user requested stop"
                        )
                        break
                    if time.time() >= deadline:
                        _terminate_diagnosis_process(proc)
                        diagnosis = _local_diagnosis(
                            f"diagnosis subprocess timed out after {timeout_s}s"
                        )
                        break
                    time.sleep(0.1)
                else:
                    diagnosis = ""

                if not diagnosis:
                    stdout, stderr = proc.communicate(timeout=2)
                    stdout = stdout or b""
                    stderr = stderr or b""
                    if isinstance(stdout, bytes):
                        raw_out = stdout.decode("utf-8", errors="replace").strip()
                    else:
                        raw_out = str(stdout).strip()

                    diagnosis = _extract_agent_text_from_event_stream(raw_out)

                    if not diagnosis and stderr:
                        if isinstance(stderr, bytes):
                            err_text = stderr.decode("utf-8", errors="replace").strip()
                        else:
                            err_text = str(stderr).strip()
                        err_text = _extract_agent_text_from_event_stream(err_text)
                        diagnosis = f"[Diagnosis subprocess produced no stdout]\n\n{err_text}"
    except subprocess.TimeoutExpired:
        if 'proc' in locals() and proc is not None:
            _terminate_diagnosis_process(proc)
        diagnosis = _local_diagnosis("diagnosis subprocess cleanup timed out")
    except KeyboardInterrupt:
        if 'proc' in locals() and proc is not None:
            _terminate_diagnosis_process(proc)
        diagnosis = _local_diagnosis("diagnosis cancelled by keyboard interrupt")
    except (FileNotFoundError, Exception) as e:
        if 'proc' in locals() and proc is not None:
            _terminate_diagnosis_process(proc)
        diagnosis = _local_diagnosis(f"diagnosis failed: {e}")

    diagnosis = _extract_agent_text_from_event_stream(diagnosis)
    if not diagnosis or len(diagnosis) < 20:
        diagnosis = _local_diagnosis("diagnosis subprocess produced no usable output")

    # Write diagnosis to disk for persistence
    diagnosis_path = sp / f"_diagnosis_{phase_name}.md"
    try:
        header = (
            f"# Failure Diagnosis: {phase_name}\n\n"
            f"**Generated**: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"**Missing**: {', '.join(str(m) for m in missing)}\n"
            f"**Log**: {log_path.name} ({len(log_content)} bytes)\n\n---\n\n"
        )
        diagnosis_path.write_text(header + diagnosis, encoding="utf-8")
    except Exception:
        pass

    if not RICH_AVAILABLE:
        print(f"\n{diagnosis}\n", file=sys.stderr)
        print(f"  (Saved to: {diagnosis_path})", file=sys.stderr)
        return

    console.print()
    console.print(Panel(
        f"[white]{escape(diagnosis)}[/]",
        title="[bold yellow]Failure Diagnosis[/]",
        border_style="yellow",
        width=min(console.width, 78),
        padding=(1, 1),
    ))
    console.print(f"    [dim]Saved to: {diagnosis_path}[/]")


# ─── Rate limit ─────────────────────────────────────────────────────────


def print_rate_limit_pause(config_path: str):
    """Print rate limit pause message with resume instructions."""
    resume_cmd = f"python ~/.claude/scripts/plamen_driver.py {config_path}"

    if not RICH_AVAILABLE:
        print("\n" + "=" * 60, file=sys.stderr)
        print("Pipeline HALTED -- Anthropic rate limit or usage cap hit.",
              file=sys.stderr)
        print("", file=sys.stderr)
        print("  All progress is saved. The pipeline resumes from the",
              file=sys.stderr)
        print("  last completed phase -- nothing is lost or re-run.",
              file=sys.stderr)
        print("", file=sys.stderr)
        print("HOW TO RESUME:", file=sys.stderr)
        print(f"  Wait a few minutes, then re-run:", file=sys.stderr)
        print(f"    {resume_cmd}", file=sys.stderr)
        print("", file=sys.stderr)
        print("  If it says HIBERNATING and you want to skip the wait:",
              file=sys.stderr)
        print(f"    {resume_cmd} --force", file=sys.stderr)
        print("", file=sys.stderr)
        print("WAIT TIMES:", file=sys.stderr)
        print("  Burst/concurrency cap:  5-10 min", file=sys.stderr)
        print("  Daily usage cap:        ~5 hours", file=sys.stderr)
        print("=" * 60 + "\n", file=sys.stderr)
        return

    content = (
        "[bold yellow]Rate limit or usage cap hit[/]\n\n"
        "All progress is saved. The pipeline resumes from the last\n"
        "completed phase -- nothing is lost or re-run.\n\n"
        "[bold]How to resume:[/]\n"
        f"  Wait a few minutes, then re-run:\n"
        f"  [bold #7030FF]{resume_cmd}[/]\n\n"
        "  If it says HIBERNATING and you want to skip the wait:\n"
        f"  [bold #7030FF]{resume_cmd} --force[/]\n\n"
        "[bold]Wait times:[/]\n"
        "  Burst/concurrency cap:  [bold]5-10 min[/]\n"
        "  Daily usage cap:        [bold]~5 hours[/]"
    )
    console.print()
    console.print(Panel(content, title="[bold yellow]|| RATE LIMITED[/]",
                        border_style="yellow", width=min(console.width, 72)))


# ─── Pipeline completion ────────────────────────────────────────────────


def print_pipeline_complete(degraded: list[str], report_path: Optional[str] = None,
                            snapshot_path: Optional[str] = None,
                            no_ship: bool = False):
    """Print pipeline completion summary."""
    total_elapsed = _elapsed_str(_pipeline_start) if _pipeline_start else "?"

    if not RICH_AVAILABLE:
        if no_ship or not report_path:
            print(
                f"\n{'=' * 60}\n"
                "  PIPELINE FINISHED -- NO DELIVERABLE\n"
                "  The report was withheld or quarantined; review runtime debt and resume.\n"
                f"{'=' * 60}",
                file=sys.stderr, flush=True,
            )
        elif degraded:
            print(
                f"\n{'=' * 60}\n"
                f"  PIPELINE COMPLETE -- {len(degraded)} degraded phase(s)\n"
                f"  Degraded: {', '.join(degraded)}\n"
                f"{'=' * 60}",
                file=sys.stderr, flush=True,
            )
        else:
            print(
                f"\n{'=' * 60}\n"
                f"  PIPELINE COMPLETE -- all phases passed\n"
                f"{'=' * 60}",
                file=sys.stderr, flush=True,
            )
        return

    console.print()
    if no_ship or not report_path:
        content = (
            "[bold red]No deliverable was released[/]\n\n"
            "[dim]The report was withheld or quarantined because terminal "
            "integrity/debt checks did not clear. Review the scratchpad and resume.[/]"
        )
        console.print(Panel(content, title="[bold red]! NO SHIP[/]",
                            border_style="red", width=min(console.width, 72)))
    elif degraded:
        degraded_list = ", ".join(degraded)
        content = (
            f"[bold yellow]Completed with {len(degraded)} degraded phase(s)[/]\n\n"
            f"[dim]Degraded:[/] {degraded_list}\n"
            f"[dim]Elapsed:[/] {total_elapsed}"
        )
        if report_path:
            content += f"\n[dim]Report:[/] [white]{report_path}[/]"
        console.print(Panel(content, title="[bold yellow]! DONE[/]",
                            border_style="yellow", width=min(console.width, 72)))
    else:
        content = (
            f"[bold #22C72E]All phases passed[/]\n\n"
            f"[dim]Elapsed:[/] {total_elapsed}"
        )
        if report_path:
            content += f"\n[bold]Report:[/] [white]{report_path}[/]"
        if snapshot_path:
            content += f"\n[dim]Snapshot:[/] {snapshot_path}"
        complete_title = _gradient_text(" + COMPLETE ")
        console.print(Panel(content, title=complete_title,
                            border_style="#22C72E", width=min(console.width, 72)))
    console.print()


def print_interrupt():
    """Print Ctrl+C interrupt message (hard kill)."""
    if not RICH_AVAILABLE:
        print(
            "\n  Pipeline INTERRUPTED -- checkpoint saved.\n"
            "  Resume: re-run the same command.\n",
            file=sys.stderr, flush=True,
        )
        return
    console.print()
    console.print(Panel(
        "[bold]Pipeline interrupted.[/]\n"
        "Progress is saved -- re-run the same command to resume.",
        title="[bold red]X INTERRUPTED[/]",
        border_style="dim",
        width=min(console.width, 72),
    ))


def print_halt_acknowledged():
    """Print halt acknowledgement (Esc pressed)."""
    _clear_spinner()
    if not RICH_AVAILABLE:
        print(
            "\n  Esc received. Cleaning up the active subprocess; options will follow.\n",
            file=sys.stderr, flush=True,
        )
        return
    console.print()
    console.print(
        "  [bold yellow]Esc received.[/] Cleaning up the active subprocess; options will follow."
    )


def print_halt_prompt(phase_name: str, config_path: str):
    """Print interactive halt menu — Enter to resume, Esc to stop."""
    if not RICH_AVAILABLE:
        print(
            f"\n  Halted during: {phase_name}\n"
            f"  Press ENTER to resume  |  Esc to stop and choose keep/purge\n",
            file=sys.stderr, flush=True,
        )
        return
    console.print()
    content = (
        f"Halted during [bold]{phase_name}[/]. Subprocess terminated.\n\n"
        f"  [bold #22C72E]ENTER[/]  resume (retry this phase)\n"
        f"  [bold red]Esc[/]    stop pipeline, then choose keep/purge"
    )
    console.print(Panel(content, title="[bold red]|| HALTED[/]",
                        border_style="red", width=min(console.width, 72)))


def wait_halt_choice() -> bool:
    """Block until user presses Enter (resume) or Esc (exit).

    Returns True to resume, False to exit.
    Suspends the background key listener so it doesn't steal keypresses.

    Non-interactive safety net (mirrors wait_critical_halt_choice, v2.8.13).
    This prompt is reached via rc==-3 (an Esc-initiated halt). It must NEVER
    block the driver forever: the observed wedge was a long unattended audit
    sitting here at 0 CPU after a stray Esc, because the bare `while True`
    keypress loop has no exit when nobody answers. The driver is haltless by
    design; an unanswered resume/exit prompt is a freeze, not a halt.
      - An explicit env choice wins: PLAMEN_AUTO_HALT_CHOICE in {resume,retry}
        -> resume (True); {exit,stop,skip} -> exit (False).
      - A non-TTY stdin (headless/redirected — where graceful_stop can only come
        from SIGINT) auto-exits cleanly (False), resumable via rerun. Matches
        wait_critical_halt_choice's non-TTY convention.
      - On a TTY the keypress loop is bounded by PLAMEN_HALT_PROMPT_TIMEOUT_S
        (default 300s). If nobody answers, default to RESUME (True) so a healthy
        run that was paused-and-abandoned is never stranded (haltless floor);
        the user can press Esc again and actually answer to stop. This differs
        from the critical-failure prompt (which exits) ON PURPOSE: there the
        phase genuinely failed, here the run is healthy and merely paused.
    A prompt answered within the window behaves exactly as before.
    """
    _auto = os.environ.get("PLAMEN_AUTO_HALT_CHOICE", "").strip().lower()
    if _auto in ("resume", "retry"):
        return True
    if _auto in ("exit", "stop", "skip"):
        return False
    try:
        if not sys.stdin.isatty():
            return False
    except Exception:
        return False
    try:
        _timeout_s = float(os.environ.get("PLAMEN_HALT_PROMPT_TIMEOUT_S", "300"))
    except Exception:
        _timeout_s = 300.0
    _deadline = (time.time() + _timeout_s) if _timeout_s > 0 else None

    def _on_timeout() -> bool:
        try:
            print(
                f"\n  [halt prompt] no response in {int(_timeout_s)}s - "
                f"auto-resuming so the run is not stranded "
                f"(set PLAMEN_AUTO_HALT_CHOICE=exit to stop instead).",
                file=sys.stderr, flush=True,
            )
        except Exception:
            pass
        return True

    pause_toggle._suspended = True
    try:
        if sys.platform == "win32":
            import msvcrt
            while True:
                if msvcrt.kbhit():
                    ch = msvcrt.getch()
                    if ch == b"\r" or ch == b"\n":  # Enter
                        return True
                    if ch == b"\x1b":  # Esc
                        return False
                if _deadline is not None and time.time() >= _deadline:
                    return _on_timeout()
                time.sleep(0.05)
        else:
            import select
            while True:
                ready, _, _ = select.select([sys.stdin], [], [], 0.1)
                if ready:
                    ch = sys.stdin.read(1)
                    if ch in ("\r", "\n"):
                        return True
                    if ch == "\x1b":
                        return False
                if _deadline is not None and time.time() >= _deadline:
                    return _on_timeout()
    finally:
        pause_toggle._suspended = False


def print_critical_halt_prompt(phase_name: str, config_path: str):
    """Print interactive menu after a critical phase exhausts retries."""
    if not RICH_AVAILABLE:
        print(
            f"\n  Critical phase failed: {phase_name}\n"
            f"  Press ENTER to retry  |  S to skip (degrade + continue)  |  Esc to stop\n",
            file=sys.stderr, flush=True,
        )
        return
    content = (
        f"Critical phase [bold]{phase_name}[/] exhausted retries.\n\n"
        f"  [bold #22C72E]ENTER[/]  retry this phase (attempt 3)\n"
        f"  [bold yellow]S[/]      skip & degrade (continue pipeline)\n"
        f"  [bold red]Esc[/]    stop pipeline"
    )
    console.print(Panel(content, title="[bold red]! CRITICAL PHASE FAILED[/]",
                        border_style="red", width=min(console.width, 72)))


def wait_critical_halt_choice() -> str:
    """Block until user presses Enter (retry), S (skip), or Esc (exit).

    Returns "retry", "skip", or "exit".
    Suspends the background key listener so it doesn't steal keypresses.

    v2.8.13 non-interactive safety net: an UNATTENDED run must never block
    forever here. An explicit env choice wins (set PLAMEN_AUTO_HALT_CHOICE to
    skip/exit/retry for headless/unattended runs); otherwise a non-TTY stdin
    (CI/headless) auto-exits cleanly (degraded) rather than hanging on the
    `while True` keypress loop. Interactive TTY behavior is unchanged.
    """
    _auto = os.environ.get("PLAMEN_AUTO_HALT_CHOICE", "").strip().lower()
    if _auto in ("skip", "exit", "retry"):
        return _auto
    try:
        if not sys.stdin.isatty():
            return "exit"
    except Exception:
        return "exit"
    pause_toggle._suspended = True
    try:
        if sys.platform == "win32":
            import msvcrt
            while True:
                if msvcrt.kbhit():
                    ch = msvcrt.getch()
                    if ch == b"\r" or ch == b"\n":
                        return "retry"
                    if ch in (b"s", b"S"):
                        return "skip"
                    if ch == b"\x1b":
                        return "exit"
                time.sleep(0.05)
        else:
            import select
            while True:
                ready, _, _ = select.select([sys.stdin], [], [], 0.1)
                if ready:
                    ch = sys.stdin.read(1)
                    if ch in ("\r", "\n"):
                        return "retry"
                    if ch in ("s", "S"):
                        return "skip"
                    if ch == "\x1b":
                        return "exit"
    finally:
        pause_toggle._suspended = False


def print_halt_resume():
    """Print message when user resumes after halt."""
    if not RICH_AVAILABLE:
        print("  Resuming...\n", file=sys.stderr, flush=True)
        return
    console.print(f"  [bold #22C72E]> Resuming...[/]")


def print_purge_prompt(scratchpad_path: str):
    """Ask whether to purge scratchpad artifacts before exiting."""
    if not RICH_AVAILABLE:
        print(
            f"\n  Scratchpad: {scratchpad_path}\n"
            f"  Press ENTER to purge artifacts  |  Esc to keep them\n",
            file=sys.stderr, flush=True,
        )
        return
    console.print()
    content = (
        f"Scratchpad: [dim]{scratchpad_path}[/]\n\n"
        f"  [bold #22C72E]ENTER[/]  purge all artifacts (clean slate)\n"
        f"  [bold yellow]Esc[/]    keep artifacts on disk"
    )
    console.print(Panel(content, title="[bold yellow]Purge artifacts?[/]",
                        border_style="yellow", width=min(console.width, 72)))


def wait_purge_choice() -> bool:
    """Block until user presses Enter (purge) or Esc (keep).

    Returns True to purge, False to keep.

    Non-interactive guard (cross-OS, mirrors wait_halt_choice /
    wait_critical_halt_choice): an explicit ``PLAMEN_AUTO_HALT_CHOICE`` env value
    or a non-TTY stdin never blocks on a keypress. The safe auto-answer for a
    destructive purge prompt is always KEEP (return False) — we never auto-purge
    artifacts. This is what lets the test suite / CI / agent shells run
    ``test_driver_smoke`` to completion instead of hanging forever on the
    ``kbhit``/``select`` loop below when ``stdin.isatty()`` is True under a pty.
    """
    if os.environ.get("PLAMEN_AUTO_HALT_CHOICE", "").strip():
        return False
    try:
        if not sys.stdin.isatty():
            return False
    except Exception:
        return False
    pause_toggle._suspended = True
    try:
        if sys.platform == "win32":
            import msvcrt
            while True:
                if msvcrt.kbhit():
                    ch = msvcrt.getch()
                    if ch == b"\r" or ch == b"\n":
                        return True
                    if ch == b"\x1b":
                        return False
                time.sleep(0.05)
        else:
            import select
            while True:
                ready, _, _ = select.select([sys.stdin], [], [], 0.1)
                if ready:
                    ch = sys.stdin.read(1)
                    if ch in ("\r", "\n"):
                        return True
                    if ch == "\x1b":
                        return False
    finally:
        pause_toggle._suspended = False


def print_purge_done(scratchpad_path: str):
    """Print confirmation that artifacts were purged."""
    if not RICH_AVAILABLE:
        print(f"  Purged: {scratchpad_path}\n", file=sys.stderr, flush=True)
        return
    console.print(f"  [bold red]✗[/] Purged: [dim]{scratchpad_path}[/]")


def print_exit_clean(config_path: str = "", scratchpad_path: str = ""):
    """Print final exit message when user chooses to stop completely."""
    if not RICH_AVAILABLE:
        print("  Stopped safely; audit artifacts were preserved.", file=sys.stderr, flush=True)
        if config_path:
            print(f"  Resume: plamen resume \"{config_path}\"", file=sys.stderr, flush=True)
        if scratchpad_path:
            print(f"  Scratchpad: {scratchpad_path}", file=sys.stderr, flush=True)
        return
    console.print()
    console.print("  [bold]Stopped safely.[/] Audit artifacts were preserved.")
    if config_path:
        console.print(f"  Resume: [bold]plamen resume \"{config_path}\"[/]")
    if scratchpad_path:
        console.print(f"  Scratchpad: [dim]{scratchpad_path}[/]")
    console.print()


def print_paused():
    """Print pause toggle message."""
    if not RICH_AVAILABLE:
        print(
            "\n  PAUSED -- will pause after current phase finishes. "
            "Ctrl+P to resume.\n",
            file=sys.stderr, flush=True,
        )
        return
    console.print()
    console.print(
        "  [bold yellow]|| PAUSED[/] -- will pause after current phase. "
        "[dim]Ctrl+P to resume.[/]"
    )


def print_resumed():
    """Print resume toggle message."""
    if not RICH_AVAILABLE:
        print("\n  RESUMED -- continuing pipeline.\n",
              file=sys.stderr, flush=True)
        return
    console.print(
        "  [bold #22C72E]> RESUMED[/] -- continuing pipeline."
    )


def print_stopping():
    """Legacy alias for halt acknowledgement."""
    print_halt_acknowledged()


def print_stopped(phase_name: str, config_path: str):
    """Print clean exit after graceful stop."""
    resume_cmd = f"python ~/.claude/scripts/plamen_driver.py \"{config_path}\""
    if not RICH_AVAILABLE:
        print(
            f"\n  Pipeline stopped during: {phase_name}\n"
            f"  Progress saved. Resume: {resume_cmd}\n",
            file=sys.stderr, flush=True,
        )
        return
    console.print()
    console.print(Panel(
        f"Stopped during [bold]{phase_name}[/]. Progress saved.\n\n"
        f"Resume: [bold #7030FF]{resume_cmd}[/]",
        title="[bold yellow]|| STOPPED[/]",
        border_style="yellow",
        width=min(console.width, 72),
    ))


def print_skipped_summary(skipped_names: list[str]):
    """Print a single-line summary of skipped (already completed) phases."""
    n = len(skipped_names)
    if n == 0:
        return
    if not RICH_AVAILABLE:
        print(f"  Skipping {n} completed phases", file=sys.stderr, flush=True)
        return
    console.print(f"  [dim]Skipping {n} completed phases[/]")


def rate_limit_wait_interactive(wait_s: int, phase_name: str) -> bool:
    """Countdown with keyboard shortcut to retry early.

    Returns True if the user pressed Enter to retry, False if the
    countdown expired naturally. Raises KeyboardInterrupt on Ctrl+C.
    """
    import select
    import threading

    mins = max(1, wait_s // 60)
    if not RICH_AVAILABLE:
        print(
            f"  Rate limited at {phase_name} -- waiting ~{mins}min before retry.\n"
            f"  Press ENTER to retry now, or Ctrl+C to halt.",
            file=sys.stderr, flush=True,
        )
    else:
        console.print(
            f"  [yellow]Rate limited[/] at [bold]{phase_name}[/] "
            f"-- waiting [bold]~{mins}min[/] before retry.\n"
            f"  [bold #22C72E]Press ENTER to retry now[/], "
            f"or [dim]Ctrl+C to halt[/]"
        )

    deadline = time.time() + wait_s
    early_resume = threading.Event()
    # The global keyboard listener also consumes msvcrt.getch() bytes. Suspend
    # it while this countdown owns Enter/Ctrl+C handling, otherwise Enter can
    # be swallowed before the local watcher sees it.
    pause_toggle._suspended = True

    def _stdin_watcher():
        """Read stdin in a daemon thread; set event on any input."""
        try:
            if sys.platform == "win32":
                import msvcrt
                # Try msvcrt first for real console handles. In wrapped
                # terminals, stdin can be a PTY/pipe even while the user is
                # visibly typing, so the outer caller starts this watcher
                # regardless of isatty() and this branch falls back to
                # blocking readline() when needed.
                if sys.stdin.isatty():
                    while not early_resume.is_set():
                        if msvcrt.kbhit():
                            msvcrt.getch()
                            # Drain any remaining bytes (e.g. \n after \r)
                            while msvcrt.kbhit():
                                msvcrt.getch()
                            early_resume.set()
                            return
                        time.sleep(0.05)
                else:
                    # Pipe/PTY: blocking read is fine in daemon thread
                    line = sys.stdin.readline()
                    if line != "":
                        early_resume.set()
                    return
            else:
                while not early_resume.is_set():
                    ready, _, _ = select.select([sys.stdin], [], [], 0.2)
                    if ready:
                        line = sys.stdin.readline()
                        if line != "":
                            early_resume.set()
                        return
        except Exception:
            pass

    watcher = None
    if sys.stdin is not None:
        watcher = threading.Thread(target=_stdin_watcher, daemon=True)
        watcher.start()

    try:
        while time.time() < deadline:
            remaining = int(deadline - time.time())
            if remaining <= 0:
                break
            m, s = divmod(remaining, 60)
            msg = f"\r  Retrying in {m}:{s:02d} ...  "
            sys.stderr.write(msg)
            sys.stderr.flush()
            if early_resume.wait(timeout=0.15):
                sys.stderr.write("\r" + " " * 40 + "\r")
                sys.stderr.flush()
                return True
            if graceful_stop.requested:
                raise KeyboardInterrupt
    except KeyboardInterrupt:
        sys.stderr.write("\n")
        sys.stderr.flush()
        raise
    finally:
        pause_toggle._suspended = False

    sys.stderr.write("\r" + " " * 40 + "\r")
    sys.stderr.flush()
    return False


def print_rate_limit_retry(phase_name: str):
    """Print rate-limit retry message."""
    if not RICH_AVAILABLE:
        print(f"  Retrying {phase_name}...", file=sys.stderr, flush=True)
        return
    console.print(f"  [#22C72E]Retrying[/] [bold]{phase_name}[/]...")


# ─── Graceful stop ──────────────────────────────────────────────────────


class GracefulStop:
    """Legacy compatibility shim — kept for test and driver references.

    Ctrl+C is no longer intercepted (it kills the entire Windows process
    group).  Halt is triggered by the Esc key via KeyboardController.
    This class just holds the ``requested`` flag that the heartbeat loop
    and rate-limit countdown check.
    """

    def __init__(self):
        self.requested = False
        self.finalizing = False

    def install(self):
        """No-op — we no longer override SIGINT."""

    def request_halt(self):
        if self.finalizing:
            return
        if not self.requested:
            self.requested = True
            print_halt_acknowledged()


graceful_stop = GracefulStop()


class PauseToggle:
    """Keyboard controller: Esc = halt, Ctrl+P = pause/unpause.

    A single daemon thread watches for both keys.  The driver checks
    ``.paused`` between phases and ``.halt_requested`` in the heartbeat
    loop and rate-limit countdown.
    """

    def __init__(self):
        self.paused = False
        self._thread = None
        self._suspended = False
        self._term_fd = None
        self._term_old_settings = None

    @property
    def halt_requested(self) -> bool:
        return graceful_stop.requested

    def start(self):
        import threading
        self._thread = threading.Thread(target=self._listen, daemon=True)
        self._thread.start()

    def _handle_key(self, ch_bytes: bytes):
        if ch_bytes == b"\x1b":  # Esc
            graceful_stop.request_halt()
        elif ch_bytes == b"\x10":  # Ctrl+P
            self.paused = not self.paused
            if self.paused:
                print_paused()
            else:
                print_resumed()

    def _listen(self):
        try:
            if sys.platform == "win32":
                import msvcrt
                while True:
                    if self._suspended:
                        time.sleep(0.05)
                        continue
                    if msvcrt.kbhit():
                        ch = msvcrt.getch()
                        self._handle_key(ch)
                    time.sleep(0.05)
            else:
                import tty, termios, select as _sel
                fd = sys.stdin.fileno()
                old_settings = termios.tcgetattr(fd)
                self._term_fd = fd
                self._term_old_settings = old_settings
                try:
                    tty.setcbreak(fd)
                    while True:
                        if self._suspended:
                            time.sleep(0.1)
                            continue
                        r, _, _ = _sel.select([sys.stdin], [], [], 0.1)
                        if r:
                            ch = sys.stdin.read(1)
                            self._handle_key(ch.encode("latin-1"))
                finally:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                    self._term_fd = None
                    self._term_old_settings = None
        except Exception:
            pass

    def restore_terminal(self):
        """Best-effort POSIX terminal restore before hard os._exit paths."""
        if sys.platform == "win32":
            return
        fd = self._term_fd
        settings = self._term_old_settings
        if fd is None or settings is None:
            return
        try:
            import termios
            termios.tcsetattr(fd, termios.TCSADRAIN, settings)
        except Exception:
            pass

    def wait_if_paused(self):
        """Block until unpaused. Called between phases."""
        while self.paused:
            time.sleep(0.2)


pause_toggle = PauseToggle()


def _find_claude_bin() -> Optional[str]:
    """Find the claude binary path."""
    import shutil
    for name in ("claude", "claude.cmd", "claude.exe"):
        path = shutil.which(name)
        if path:
            return path
    return None


def _find_codex_bin() -> Optional[str]:
    """Find the codex binary path."""
    import shutil
    for name in ("codex", "codex.cmd", "codex.exe"):
        path = shutil.which(name)
        if path:
            return path
    return None
