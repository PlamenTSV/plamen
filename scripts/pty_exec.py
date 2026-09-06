"""PTY-backed Claude Code execution helpers."""
from __future__ import annotations

import hashlib
import json
import os
import re
import select
import signal
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, TextIO


_DONE_RE = re.compile(r"\bDONE\s*:", re.IGNORECASE)
_RATE_LIMIT_STATUSES = {429, 529}
# Transient 5xx server errors (Internal Server Error / Bad Gateway / Service
# Unavailable / Gateway Timeout). Same RETRY class as 529 overloaded — short
# backoff + retries, NOT a usage-cap pause. Without handling these, a 500 from
# the API is not recognized and the worker stalls waiting for a completion
# marker that never arrives (instead of retrying or surfacing halt/resume).
_SERVER_ERROR_STATUSES = {500, 502, 503, 504}
_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07]*(?:\x07|\x1b\\)")
_USAGE_CAP_TEXT_RE = re.compile(
    r"(?:"
    r"you(?:'|')?ve\s+hit\s+your\s+(?:weekly|daily|monthly)\s+limit"
    r"|hit\s+your\s+(?:weekly|daily|monthly)\s+limit"
    r"|usage\s+cap\s+(?:hit|reached|exceeded)"
    r"|switch\s+to\s+team\s+plan"
    r"|upgrade\s+to\s+(?:the\s+)?team\s+plan"
    r")",
    re.IGNORECASE,
)

# Claude Code emits this hard error when a single turn's response exceeds the
# model output-token cap (e.g. 'Claude's response exceeded the 32000 output
# token maximum'). The turn cannot make further progress: it produces no new
# transcript events yet the PTY UI keeps spinning. Number-agnostic so it
# survives model cap changes. Detecting it lets the wait loop stop early and
# run the disk gate immediately instead of blocking the full phase timeout.
_OUTPUT_CAP_TEXT_RE = re.compile(
    r"response\s+exceeded\s+the\s+\d[\d,]*\s+output\s+token\s+maximum",
    re.IGNORECASE,
)

# Cap-LOOP window. The quiescence gate below catches the common case where a
# turn hits the output cap and then goes silent. But Claude can also
# auto-continue PAST the cap, generating a fresh response that hits the cap
# again (observed: a single dedup turn ran 32 min and logged the cap error
# twice). In that loop the transcript keeps emitting events, so last_event_time
# never goes stale and the quiescence gate never trips. A PRODUCTIVE turn moves
# past one cap and the error scrolls out of the recent-output buffer (resetting
# the latch); only a stuck generate-until-cap loop keeps the cap text recurring
# across a sustained window. If it persists this long, the turn will never
# finish productively -> stop early and let the disk gate / recovery take over.
_OUTPUT_CAP_LOOP_S = 120.0

# Ship 8.17: context-overflow / autocompact-thrash fingerprint. Distinct from
# the OUTPUT cap (model can't emit more) -- this is the INPUT side: the turn's
# context has grown so large that Claude Code is stuck auto-compacting (or has
# explicitly given up). The pathology: the transcript KEEPS emitting events
# (compaction summaries, file re-reads) so `last_event_time` never goes stale
# and the quiescence gate never trips; the process stays alive; and it is NOT
# the output-token cap. Without a dedicated exit the ONLY terminator is the
# full scaled phase deadline (observed: 3.6h burn on a 144K-finding report
# index). Number-agnostic so it survives Claude Code wording changes.
_CONTEXT_OVERFLOW_TEXT_RE = re.compile(
    r"(?:"
    r"autocompact\s+is\s+thrashing"
    r"|auto-?compact\s+is\s+thrashing"
    r"|a\s+file\s+being\s+read\s+is\s+too\s+large"
    r"|the\s+file\s+(?:is|being\s+read\s+is)\s+too\s+large"
    r"|prompt\s+is\s+too\s+long"
    r"|input\s+is\s+too\s+long"
    r"|exceeds?\s+(?:the\s+)?(?:maximum\s+)?context\s+window"
    r"|context\s+(?:window\s+)?(?:is\s+)?(?:too\s+)?(?:full|exceeded)"
    r")",
    re.IGNORECASE,
)

# Context-thrash LOOP window. A NORMAL auto-compaction is frequent and benign:
# Claude compacts a long turn and then RESUMES producing tool_use / assistant
# text. We must never cut THAT off. We fire only when (a) the thrash/overflow
# fingerprint is present (explicit text OR a sustained compaction signature)
# AND (b) NO new productive event (assistant text or tool_use) has advanced for
# this long -- i.e. the turn is emitting compaction churn while producing zero
# forward progress. The `first_thrash_seen_at` latch is reset on every genuine
# productive event, so a compact-then-resume turn is recall-safe.
# A three-minute window proved too aggressive for large, but healthy, Claude
# compactions.  Ten minutes still bounds the observed multi-hour zero-progress
# failure while giving an ordinary compact-and-resume turn substantially more
# room than the prior detector.  Tests may replace the constant directly; an
# operator override remains available for unusually small/large contexts.
_CONTEXT_THRASH_LOOP_S = float(
    os.environ.get("PLAMEN_CONTEXT_THRASH_LOOP_S", "600") or 600
)

# Ship 8.10: the subprocess-isolation overlay payload. SINGLE source of
# truth shared by plamen_driver (production) and preflight_pty_transports
# (probe). Empty enabledPlugins/hooks/mcpServers disables those subsystems
# (plugin / hook / MCP cold-start hangs) without touching the user's real
# settings.json -- so OAuth keychain auth keeps working.
#
# `skipDangerousModePermissionPrompt: true` suppresses the one-time interactive
# "Bypass Permissions mode" acceptance dialog that `--dangerously-skip-permissions`
# triggers. Per the CLI's own gate
# `(dangerouslySkipPermissions) && !skipDangerousModePermissionPrompt()`
# (anthropics/claude-code#25503), this is the AUTHORITATIVE key/file — a PTY
# worker has no stdin to answer that dialog, so without it the worker produces
# 0 bytes and hangs until the phase budget (observed: 98-min bake hang on macOS).
# Platform-agnostic and version-robust (it is the actual code condition), so no
# keystroke simulation is needed. `--settings` overlays this onto the base
# config; the driver ALSO writes it to the global ~/.claude/settings.json for
# MCP phases that do not pass `--settings`.
SUBPROCESS_ISOLATION_PAYLOAD = (
    '{"enabledPlugins":{},"hooks":{},"mcpServers":{},'
    '"skipDangerousModePermissionPrompt":true}'
)


# Ship 8.13: auto-compaction fingerprint. When Claude Code auto-compacts a
# long PTY coordinator turn, the transcript carries one of these phrases.
# Paired (by the caller) with a DONE-then-gate-miss, this is the verified
# premature-DONE signature observed in a prior run. Detection is DIAGNOSTIC
# ONLY -- it never gates a phase.
_COMPACTION_MARKERS = (
    "conversation compacted",
    "compacting conversation",
    "until auto-compact",
    "before compaction",
    "continue the conversation from where it left off",
)


def transcript_shows_compaction(
    transcript_path: str | Path | None, extra_text: str = "",
) -> bool:
    """Return True iff the transcript (and optional extra stdio text)
    carries an auto-compaction fingerprint: an explicit compaction phrase,
    or 'compact' appearing repeatedly (>=3x, the summary-block pattern).

    Conservative: any read error returns False. Never raises.
    """
    blob = ""
    try:
        if transcript_path and Path(transcript_path).exists():
            blob = Path(transcript_path).read_text(
                encoding="utf-8", errors="replace"
            )
    except Exception:
        blob = ""
    blob = (blob + "\n" + (extra_text or "")).lower()
    if any(marker in blob for marker in _COMPACTION_MARKERS):
        return True
    return blob.count("compact") >= 3


def _normalized_pty_text(text: str) -> str:
    """Normalize PTY/control-sequence text for status phrase detection."""
    text = _ANSI_RE.sub(" ", text or "")
    text = text.replace("\x00", " ")
    text = re.sub(r"\s+", " ", text)
    return text.strip().lower()


def _status_code(value: Any) -> int | None:
    try:
        if isinstance(value, str):
            value = value.strip()
            if not value:
                return None
        return int(value)
    except Exception:
        return None


def text_shows_rate_limit(text: str) -> bool:
    """Detect Claude Code interactive usage-cap/rate-limit UI text.

    This intentionally looks for Claude UI/account-cap phrases, not generic
    audit prose about a protocol's rate limits. It covers PTY screens that do
    not cleanly terminate with a structured JSON error, such as the "weekly
    limit / Switch to Team plan" prompt.
    """
    normalized = _normalized_pty_text(text)
    if not normalized:
        return False
    if _USAGE_CAP_TEXT_RE.search(normalized):
        return True
    if re.search(r"\b(?:apierrorstatus|api error status)\b[^\n\r]{0,80}\b(?:429|529)\b", normalized):
        return True
    if re.search(r"\b(?:429)\b[^\n\r]{0,80}\btoo many requests\b", normalized):
        return True
    if re.search(r"\b(?:529)\b[^\n\r]{0,80}\boverloaded\b", normalized):
        return True
    if re.search(r"\b(?:type|code|error)\s*[:=]\s*(?:rate_limit_error|overloaded_error)\b", normalized):
        return True
    return False


def text_shows_overloaded(text: str) -> bool:
    """Detect a 529 / `overloaded_error` (transient provider overload).

    This is DISTINCT from `text_shows_rate_limit`: a 529 is Anthropic being
    temporarily overloaded provider-wide, NOT the user's account hitting a
    rate/usage cap (429 / "weekly limit" / "Switch to Team plan"). The two
    require different recovery: 529 → short exponential backoff + more retries
    before any pause; 429 → long wait + usage-cap pause panel. We deliberately
    do NOT match the 429 usage-cap phrases here.
    """
    normalized = _normalized_pty_text(text)
    if not normalized:
        return False
    if re.search(r"\b529\b[^\n\r]{0,80}\boverloaded\b", normalized):
        return True
    if re.search(r"\b(?:type|code|error)\"?\s*[:=]\s*\"?overloaded_error\b", normalized):
        return True
    if re.search(
        r"\b(?:apierrorstatus|api error status)\b[^\n\r]{0,80}\b529\b", normalized
    ):
        return True
    if re.search(r"\bstatus[_ ]?code\b[^\n\r]{0,20}\b529\b", normalized):
        return True
    # Transient 5xx server errors — same retry class as 529. Keyed on the
    # API-error CONTEXT (apiErrorStatus / status_code / explicit phrase) so a
    # bare "500" in audited prose does not trip it.
    if re.search(
        r"\b(?:apierrorstatus|api error status)\b[^\n\r]{0,80}\b50[0234]\b",
        normalized,
    ):
        return True
    if re.search(r"\bstatus[_ ]?code\b[^\n\r]{0,20}\b50[0234]\b", normalized):
        return True
    if re.search(
        r"\b50[0234]\b[^\n\r]{0,80}"
        r"\b(?:internal server error|bad gateway|service unavailable|gateway timeout)\b",
        normalized,
    ):
        return True
    if re.search(
        r"\b(?:type|code|error)\"?\s*[:=]\s*\"?(?:api_error|internal_server_error)\b",
        normalized,
    ):
        return True
    return False


def event_is_overloaded(event: dict[str, Any]) -> bool:
    """Return True iff a transcript event carries a 529 / overloaded signal.

    Mirrors `event_is_rate_limited` but matches ONLY the overload class (529 /
    `overloaded_error` / stop_reason `overloaded`), never the 429 usage-cap
    class. Used to give transient provider overloads short-backoff retries
    before the rate-limit pause path is ever surfaced.
    """
    status = event.get("api_error_status") or event.get("apiErrorStatus")
    if _status_code(status) in (_SERVER_ERROR_STATUSES | {529}):
        return True
    event_type = str(event.get("type") or "").lower()
    if event_type == "user":
        # Tool-result/prompt echoes may contain audited prose; never trust them.
        return False
    for source in (event, _event_message(event), event.get("error")):
        if isinstance(source, str):
            if source.lower() == "overloaded":
                return True
            if text_shows_overloaded(source):
                return True
            continue
        if not isinstance(source, dict):
            continue
        status = (
            source.get("api_error_status")
            or source.get("apiErrorStatus")
            or source.get("status")
        )
        if _status_code(status) in (_SERVER_ERROR_STATUSES | {529}):
            return True
        err = source.get("error")
        if isinstance(err, str) and err.lower() == "overloaded":
            return True
        if isinstance(err, dict):
            typ = str(err.get("type") or err.get("code") or "").lower()
            if ("overloaded" in typ or "server_error" in typ
                    or typ in ("api_error", "internal_server_error")):
                return True
        typ = str(source.get("type") or source.get("code") or "").lower()
        if ("overloaded" in typ or "server_error" in typ
                or typ in ("api_error", "internal_server_error")):
            return True
        stop = str(source.get("stop_reason") or "").lower()
        if stop == "overloaded":
            return True
        message = source.get("message") or source.get("content") or ""
        if isinstance(message, str) and text_shows_overloaded(message):
            return True
    return False


def isolation_overlay_hash(payload: str | None) -> str:
    """Short stable hash of the isolation overlay payload. Part of the
    preflight cache key so a probe taken under a different overlay is not
    reused."""
    return hashlib.sha256(
        (payload or "").encode("utf-8")
    ).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Ship 8.10: canonical interactive (PTY) claude argv builder.
#
# SINGLE source of truth for the production PTY argv shape. Both
# plamen_driver.run_phase and preflight_pty_transports' probes call this
# so the probe exercises the SAME flag structure + isolation set as
# production. The historical false-negative class -- the probe omitted the
# subprocess-isolation flags and therefore hit the plugin/MCP cold-start
# hang it was meant to avoid, producing "first file never written" -> a
# bogus live_pty_continue=False -- is eliminated when both paths share this
# builder.
#
# The byte sequence reproduces production's prior inline construction
# EXACTLY (model, session-id, dangerously-skip, the add-dirs, then the
# non-MCP isolation set), so wiring production to this builder is a
# refactor with zero argv drift.
# ---------------------------------------------------------------------------

# Volatile argv tokens whose VALUE differs run-to-run (or probe-vs-prod) but
# whose PRESENCE/ORDER is the "shape". Used by claude_pty_argv_shape to
# normalize so probe(haiku, tmp dirs) and production(sonnet, project dirs)
# hash identically when their flag STRUCTURE matches.
_PTY_SHAPE_VALUE_FLAGS = {
    "--model": "<MODEL>",
    "--session-id": "<SID>",
    "--add-dir": "<DIR>",
    "--settings": "<ISO>",
    "--mcp-config": "<ISO>",
}


def build_claude_pty_argv(
    *,
    claude_bin: str,
    model: str,
    session_id: str,
    add_dirs: list[str] | tuple[str, ...],
    disallow_mcp: bool = True,
    isolation_path: str | Path | None = None,
    dangerously_skip_permissions: bool = True,
) -> list[str]:
    """Build the canonical interactive (PTY) claude argv.

    Order mirrors production exactly:
      ``[bin, --model M, --session-id S, --dangerously-skip-permissions,
         (--add-dir D)*, (--disallowedTools mcp__*
         [, --settings ISO, --strict-mcp-config, --mcp-config ISO])?]``

    - ``disallow_mcp`` gates the whole isolation block (production adds it
      only for ``not phase.needs_mcp`` phases).
    - ``isolation_path`` adds the settings/strict-mcp set; pass ``None`` to
      replicate production's "isolation overlay write failed" fallback,
      which keeps ``--disallowedTools mcp__*`` but drops the settings flags.
    """
    argv: list[str] = [
        claude_bin,
        "--model", model,
        "--session-id", session_id,
    ]
    if dangerously_skip_permissions:
        argv.append("--dangerously-skip-permissions")
    for d in add_dirs:
        argv.extend(["--add-dir", str(d)])
    if disallow_mcp:
        argv.extend(["--disallowedTools", "mcp__*"])
        if isolation_path is not None:
            iso = Path(isolation_path).as_posix()
            argv.extend([
                "--settings", iso,
                "--strict-mcp-config", "--mcp-config", iso,
            ])
    return argv


def append_claude_pty_prompt_arg(argv: list[str], prompt: str) -> list[str]:
    """Return ``argv`` with ``prompt`` appended as Claude Code's normal
    positional prompt argument.

    Claude's help documents ``claude [options] [prompt]``. Do not put a bare
    ``--`` before the prompt here: in interactive PTY mode that can leave the
    text sitting in the prompt box instead of executing it. Also avoid placing
    the prompt immediately after variadic options such as ``--mcp-config`` or
    ``--disallowedTools``; append a harmless boolean flag first so option
    parsing is closed before the positional prompt.
    """
    out = list(argv)
    if "--no-chrome" not in out:
        out.append("--no-chrome")
    out.append(prompt)
    return out


def claude_pty_argv_shape(argv: list[str]) -> list[str]:
    """Return the argv with volatile token VALUES normalized to stable
    placeholders, so two argvs with the same flag STRUCTURE compare equal
    regardless of bin path, model, session-id, add-dir, or isolation paths.
    """
    out: list[str] = []
    i = 0
    n = len(argv)
    while i < n:
        tok = argv[i]
        if i == 0:
            out.append("<CLAUDE_BIN>")
            i += 1
            continue
        placeholder = _PTY_SHAPE_VALUE_FLAGS.get(tok)
        if placeholder is not None and i + 1 < n:
            out.append(tok)
            out.append(placeholder)
            i += 2
            continue
        if tok.startswith(
            "Read and fully execute every instruction in "
        ):
            out.append("<PROMPT>")
        else:
            out.append(tok)
        i += 1
    return out


def claude_pty_shape_hash(argv: list[str]) -> str:
    """Stable short hash of the normalized argv shape. Used as part of the
    preflight cache key so a probe taken under a DIFFERENT argv/isolation
    shape (e.g. an old false-negative cache from before Ship 8.10) is
    ignored and re-probed."""
    shape = claude_pty_argv_shape(argv)
    return hashlib.sha256(
        json.dumps(shape, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]


def encode_claude_project_dir(cwd: str | Path) -> str:
    """Return Claude Code's project-directory encoding for a working dir.

    Claude Code's real slugifier converts EVERY character that is not an ASCII
    letter, digit, or hyphen to a hyphen -- including underscores. The
    keep-class is ``[A-Za-z0-9-]`` (note: NO underscore). A path segment like
    ``foo_bar`` therefore maps on disk to ``foo-bar``. The prior keep-class
    erroneously preserved ``_``, producing a project-dir slug that did not
    exist on disk for any underscore-containing path (e.g. non-EVM crate
    directories), so the transcript poll watched a file that was never written
    and the worker hung until timeout. Match the real slugifier exactly.
    """
    return re.sub(r"[^A-Za-z0-9-]", "-", str(Path(cwd).resolve()))


def claude_transcript_path(
    session_id: str,
    cwd: str | Path,
    claude_home: str | Path | None = None,
) -> Path:
    """Resolve the on-disk transcript file for a Claude PTY session.

    The encoded project-dir slug is the PRIMARY candidate. The session_id is
    the ``.jsonl`` filename and is globally unique, so when the primary slug
    does not exist on disk we self-heal by globbing recursively for
    ``{session_id}.jsonl`` under ``projects/``. A SINGLE match is unambiguous
    and is returned. Zero or multiple matches are ambiguous, so we return the
    primary candidate unchanged -- behaviour identical to before the glob, and
    never a guess. This makes completion detection resilient to ANY future
    slug-encoding divergence across every ecosystem and role-name shape.
    """
    home = Path(claude_home) if claude_home else Path.home() / ".claude"
    primary = (
        home / "projects" / encode_claude_project_dir(cwd) / f"{session_id}.jsonl"
    )
    if primary.exists():
        return primary
    try:
        matches = sorted(home.glob(f"projects/**/{session_id}.jsonl"))
    except Exception:
        matches = []
    if len(matches) == 1:
        return matches[0]
    return primary


def _event_message(event: dict[str, Any]) -> dict[str, Any]:
    msg = event.get("message")
    return msg if isinstance(msg, dict) else {}


def _event_text(event: dict[str, Any]) -> str:
    msg = _event_message(event)
    content = msg.get("content")
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for item in content:
        if isinstance(item, dict) and item.get("type") == "text":
            parts.append(str(item.get("text") or ""))
    return "\n".join(parts)


def event_is_productive(event: dict[str, Any]) -> bool:
    """Return True iff this assistant event represents FORWARD PROGRESS:
    it carries a tool_use block, or non-trivial text that is not merely a
    compaction summary. Used by the context-thrash gate to tell a
    compact-then-resume turn (productive) from a stuck-thrashing turn (only
    compaction churn). Conservative: anything ambiguous counts as productive
    so a genuinely working turn is never starved of its forward-progress
    signal (recall-safe — we would rather wait than cut off real work)."""
    if event.get("type") != "assistant":
        return False
    msg = _event_message(event)
    content = msg.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("type") == "tool_use":
                return True
    text = _event_text(event).strip()
    if not text:
        return False
    # A compaction summary block is not forward progress. Match the same
    # fingerprints used by transcript_shows_compaction.
    low = text.lower()
    if any(marker in low for marker in _COMPACTION_MARKERS):
        return False
    return True


def event_is_compaction_summary(event: dict[str, Any]) -> bool:
    """Return True only for an assistant event that is compaction telemetry."""

    if event.get("type") != "assistant":
        return False
    text = _event_text(event).strip().lower()
    return bool(text) and any(marker in text for marker in _COMPACTION_MARKERS)


def event_is_turn_end(event: dict[str, Any]) -> bool:
    if event.get("type") != "assistant":
        return False
    msg = _event_message(event)
    stop_reason = (msg.get("stop_reason") or "").lower()
    if stop_reason == "end_turn":
        return True
    content = msg.get("content")
    if stop_reason in ("", "stop", "complete", "completed") and isinstance(content, list):
        return any(isinstance(i, dict) and i.get("type") == "text" for i in content)
    return False


def event_has_done(event: dict[str, Any]) -> bool:
    return bool(_DONE_RE.search(_event_text(event)))


def event_is_rate_limited(event: dict[str, Any]) -> bool:
    status = event.get("api_error_status") or event.get("apiErrorStatus")
    if _status_code(status) in _RATE_LIMIT_STATUSES:
        return True
    # Claude transcripts store tool results and prompt echoes as `type=user`.
    # Those payloads often contain audited source/prose, line numbers, and
    # vulnerability text. Never classify arbitrary user/tool-result content as
    # a transport/account rate limit; only structured API/error envelopes and
    # live PTY UI text are authoritative.
    event_type = str(event.get("type") or "").lower()
    if event_type == "user":
        return False
    if event_type == "rate_limit_event":
        # Claude Code emits this telemetry on successful subscription turns
        # too.  ``allowed`` and ``allowed_warning`` describe utilization; they
        # are not a rejected request and must never trigger a phase replay.
        info = event.get("rate_limit_info")
        return isinstance(info, dict) and info.get("status") == "rejected"
    for source in (event, _event_message(event), event.get("error")):
        if isinstance(source, str):
            if source.lower() in ("rate_limit", "rate_limited", "overloaded"):
                return True
            if text_shows_rate_limit(source):
                return True
            continue
        if not isinstance(source, dict):
            continue
        status = (
            source.get("api_error_status")
            or source.get("apiErrorStatus")
            or source.get("status")
        )
        if _status_code(status) in _RATE_LIMIT_STATUSES:
            return True
        err = source.get("error")
        if isinstance(err, str):
            if err.lower() in ("rate_limit", "rate_limited", "overloaded"):
                return True
            if text_shows_rate_limit(err):
                return True
        if isinstance(err, dict):
            typ = str(err.get("type") or err.get("code") or "").lower()
            if "rate_limit" in typ or "overloaded" in typ:
                return True
        typ = str(source.get("type") or source.get("code") or "").lower()
        if "rate_limit" in typ or "overloaded" in typ:
            return True
        stop = str(source.get("stop_reason") or "").lower()
        if stop in ("rate_limited", "rate_limit", "overloaded"):
            return True
        message = source.get("message") or source.get("content") or ""
        if isinstance(message, str) and text_shows_rate_limit(message):
            return True
    return False


@dataclass
class TurnCompleteState:
    complete: bool
    done_seen: bool = False
    rate_limited: bool = False
    # 529 / overloaded_error: a transient, provider-wide overload — NOT a 429
    # account/usage cap. Tracked separately (it's a subset of rate_limited,
    # which matches both) so worker-pool phases can give a 529 retriable
    # short-backoff handling instead of escalating to the usage-cap pause.
    overloaded: bool = False
    output_truncated: bool = False
    context_thrash: bool = False
    line_count: int = 0
    # Count of PRODUCTIVE assistant events (those carrying a tool_use block or
    # non-trivial text). Used by the context-thrash gate to distinguish a turn
    # that is making forward progress (productive_event_count keeps rising)
    # from one that is only emitting compaction churn (count frozen). Pure
    # compaction-summary / re-read events do not advance this counter.
    productive_event_count: int = 0
    # Any parsed transcript event other than pure compaction telemetry is
    # meaningful activity.  This deliberately includes user/tool-result and
    # transport events: a long-running tool or reasoning turn must reset the
    # zero-progress window even when it has not emitted another assistant
    # message yet.
    meaningful_event_count: int = 0
    compaction_event_count: int = 0
    last_event_time: float | None = None
    last_assistant: dict[str, Any] | None = None


def inspect_transcript(path: Path) -> TurnCompleteState:
    state = TurnCompleteState(complete=False)
    if not path.exists():
        return state
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except Exception:
                    continue
                state.line_count += 1
                if event_is_compaction_summary(event):
                    state.compaction_event_count += 1
                else:
                    state.meaningful_event_count += 1
                if event_is_rate_limited(event):
                    state.rate_limited = True
                if event_is_overloaded(event):
                    state.overloaded = True
                if event.get("type") == "assistant":
                    state.last_assistant = event
                    if event_is_productive(event):
                        state.productive_event_count += 1
                    if event_has_done(event):
                        state.done_seen = True
                    if event_is_turn_end(event):
                        state.complete = True
                        try:
                            state.last_event_time = path.stat().st_mtime
                        except OSError:
                            state.last_event_time = time.time()
    except OSError:
        return state
    return state


def parse_transcript_usage(path: Path) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "num_turns": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_input_tokens": 0,
        "cache_creation_input_tokens": 0,
        "stop_reason": "?",
        "is_error": False,
    }
    if not path.exists():
        return fields
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    event = json.loads(line)
                except Exception:
                    continue
                if event_is_rate_limited(event):
                    fields["is_error"] = True
                    fields["api_error_status"] = 429
                    fields["stop_reason"] = "rate_limited"
                if event.get("type") != "assistant":
                    continue
                msg = _event_message(event)
                stop = msg.get("stop_reason")
                if stop:
                    fields["stop_reason"] = stop
                if event_is_turn_end(event):
                    fields["num_turns"] = int(fields.get("num_turns") or 0) + 1
                usage = msg.get("usage")
                if not isinstance(usage, dict):
                    continue
                for key in (
                    "input_tokens",
                    "output_tokens",
                    "cache_read_input_tokens",
                    "cache_creation_input_tokens",
                ):
                    try:
                        fields[key] = int(fields.get(key) or 0) + int(usage.get(key) or 0)
                    except Exception:
                        pass
    except OSError:
        pass
    if not fields.get("num_turns"):
        fields["num_turns"] = 1
    return fields


_AGENT_ROW_RE = re.compile(r"AGENT_ROW:\s*([^\s\-<>]+)")
_EXPECTED_OUTPUT_RE = re.compile(r"EXPECTED_OUTPUT:\s*([^\s\-<>]+)")
_AGENTID_HANDLE_RE = re.compile(
    r"agentId:\s*([A-Za-z0-9_-]+)\s*\(use SendMessage",
)


def parse_transcript_agentids(transcript_path: Path) -> dict[str, dict[str, str]]:
    """Parse a Claude Code session transcript and correlate each
    Agent/Task subagent dispatch with the ``agentId`` handle that came
    back in its tool_result.

    Ship 5 of the artifact-complete PTY supervision plan. Consumed by
    Ship 6 to build a continuation message that addresses paused
    subagents by their manifest row (e.g. "B3 / analysis_access_control.md"),
    not by the opaque handle string.

    Args:
        transcript_path: ``.jsonl`` transcript file written by Claude
            Code under ``~/.claude/projects/<encoded_cwd>/<session_id>.jsonl``.

    Returns:
        ``{agent_row: {"agent_id": agent_row, "expected_output": str,
        "handle": str, "description": str}}`` mapping ONE row per
        subagent dispatch that carried an ``AGENT_ROW:`` marker in its
        dispatch prompt. Dispatches without an AGENT_ROW marker are
        skipped (we do not fabricate a row name from the handle alone).
        Dispatches that have not yet returned a handle are still
        included with ``handle == ""`` so the continuation message can
        still name the row -- the caller decides whether to attempt
        SendMessage or fall back to respawn based on handle emptiness.

        Returns ``{}`` on every failure mode: missing file, unreadable
        file, JSON parse errors line-by-line (the parser continues
        past corrupt lines), empty transcript, transcript with no
        Agent/Task dispatches, or transcript whose dispatches all
        lacked the AGENT_ROW marker.

    Marker format. The orchestrator's dispatch prompt MUST contain
    a line of the form::

        AGENT_ROW: B3
        EXPECTED_OUTPUT: analysis_access_control.md

    The Subagent Prompt Template in
    ``~/.plamen/prompts/shared/v2/phase3-breadth.md`` injects these
    lines verbatim in every Task/Agent dispatch prompt the breadth
    orchestrator builds, exactly so this parser can correlate.
    """
    try:
        if not transcript_path.exists():
            return {}
    except Exception:
        return {}

    # Per-tool_use_id state. We scan the transcript once, in order,
    # because tool_use and its matching tool_result are typically on
    # different lines. Correlate by ``id`` <-> ``tool_use_id``.
    dispatches: dict[str, dict[str, str]] = {}
    results: dict[str, str] = {}

    try:
        with transcript_path.open("r", encoding="utf-8", errors="replace") as fp:
            for raw_line in fp:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    # Skip corrupt lines; do not fail the whole parse.
                    continue
                msg = obj.get("message") if isinstance(obj, dict) else None
                if not isinstance(msg, dict):
                    continue
                content = msg.get("content")
                if not isinstance(content, list):
                    continue
                for item in content:
                    if not isinstance(item, dict):
                        continue
                    itype = item.get("type")
                    if itype == "tool_use" and item.get("name") in ("Agent", "Task"):
                        tu_id = item.get("id")
                        if not isinstance(tu_id, str) or not tu_id:
                            continue
                        inp = item.get("input")
                        if not isinstance(inp, dict):
                            continue
                        prompt_text = inp.get("prompt") or ""
                        description = inp.get("description") or ""
                        if not isinstance(prompt_text, str):
                            prompt_text = ""
                        if not isinstance(description, str):
                            description = ""
                        row_m = _AGENT_ROW_RE.search(prompt_text)
                        exp_m = _EXPECTED_OUTPUT_RE.search(prompt_text)
                        dispatches[tu_id] = {
                            "agent_row": (row_m.group(1).strip() if row_m else ""),
                            "expected_output": (
                                exp_m.group(1).strip() if exp_m else ""
                            ),
                            "description": description.strip(),
                        }
                    elif itype == "tool_result":
                        tu_id = item.get("tool_use_id")
                        if not isinstance(tu_id, str) or not tu_id:
                            continue
                        result_content = item.get("content")
                        text = ""
                        if isinstance(result_content, list):
                            for rc in result_content:
                                if (
                                    isinstance(rc, dict)
                                    and rc.get("type") == "text"
                                ):
                                    t = rc.get("text")
                                    if isinstance(t, str):
                                        text += t
                        elif isinstance(result_content, str):
                            text = result_content
                        handle_m = _AGENTID_HANDLE_RE.search(text)
                        if handle_m:
                            results[tu_id] = handle_m.group(1).strip()
    except OSError:
        return {}
    except Exception:
        # Any unforeseen parse failure -> empty mapping (conservative).
        return {}

    out: dict[str, dict[str, str]] = {}
    for tu_id, d in dispatches.items():
        agent_row = d.get("agent_row") or ""
        if not agent_row:
            # The plan's contract: do NOT fabricate a row mapping for
            # dispatches that lacked the AGENT_ROW marker. Such dispatches
            # cannot be correlated to a manifest row and so cannot be
            # named precisely in a continuation message; the caller must
            # respawn that row from scratch.
            continue
        out[agent_row] = {
            "agent_id": agent_row,
            "expected_output": d.get("expected_output") or "",
            "handle": results.get(tu_id, ""),
            "description": d.get("description") or "",
        }
    return out


class ClaudePtySession:
    def __init__(
        self,
        argv: list[str],
        cwd: str | Path,
        env: dict[str, str],
        session_id: str,
        prompt_path: str | Path,
        log_file: TextIO,
        claude_home: str | Path | None = None,
    ) -> None:
        self.argv = argv
        self.cwd = str(cwd)
        self.env = env
        self.session_id = session_id
        self.prompt_path = Path(prompt_path)
        # Lazy transcript resolution: the on-disk transcript file may not exist
        # at spawn time (Claude Code creates it shortly after the session
        # starts). Store the resolver inputs and resolve on first access via
        # the ``transcript_path`` property, which re-resolves until the real
        # file materialises (then caches it). This guarantees the completion
        # poll reads the real end_turn-bearing transcript for every ecosystem.
        self._session_id = session_id
        self._claude_home = claude_home
        self._resolved_transcript_path: Path | None = None
        self.log_file = log_file
        self.proc: Any = None
        self._child_pid: int | None = None
        self._child_pgid: int | None = None
        self._master_fd: int | None = None
        self._reader_stop = threading.Event()
        self._reader_thread: threading.Thread | None = None
        self._recent_output = ""
        self._recent_output_lock = threading.Lock()

    @property
    def transcript_path(self) -> Path:
        """Lazily resolve the session's on-disk transcript file.

        Returns a cached Path once the real file has been found to exist.
        Otherwise re-runs ``claude_transcript_path`` every access: if that
        resolves to an existing file it is cached and returned; if not, the
        primary encoded candidate is returned so the poll keeps watching the
        same stable path until the file materialises, then auto-upgrades to
        the real (possibly glob-resolved) path. Never guesses.
        """
        if (
            self._resolved_transcript_path is not None
            and self._resolved_transcript_path.exists()
        ):
            return self._resolved_transcript_path
        candidate = claude_transcript_path(
            self._session_id, self.cwd, self._claude_home
        )
        if candidate.exists():
            self._resolved_transcript_path = candidate
        return candidate

    def spawn(self) -> None:
        if sys.platform == "win32":
            import winpty  # type: ignore

            self.proc = winpty.PtyProcess.spawn(
                self.argv,
                cwd=self.cwd,
                env=self.env,
                dimensions=(40, 120),
            )
        else:
            import pty
            import fcntl
            import termios

            # When Plamen is launched from inside Claude Code on POSIX, the
            # Python driver may inherit process-level signal state from the
            # parent session. A raw POSIX fork plus manual child wait is fragile:
            # inherited SIGCHLD disposition can make children appear reaped
            # immediately. Use Popen ownership and reset SIGCHLD before spawn.
            try:
                if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
                    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
            except Exception:
                pass

            master_fd, slave_fd = pty.openpty()
            try:
                fcntl.ioctl(
                    slave_fd,
                    termios.TIOCSWINSZ,
                    struct.pack("HHHH", 40, 120, 0, 0),
                )
            except Exception:
                pass

            try:
                # ``start_new_session`` asks the subprocess implementation to
                # perform setsid using its native spawn path.  No Python runs
                # between fork and exec, so this remains safe when PTY workers
                # are launched concurrently from the threaded orchestrator.
                # The PTY slave is still the child's exact stdin/out/err and
                # the session leader is also its process-group leader, which
                # preserves group-scoped supervision and termination.
                self.proc = subprocess.Popen(
                    self.argv,
                    stdin=slave_fd,
                    stdout=slave_fd,
                    stderr=slave_fd,
                    cwd=self.cwd,
                    env=self.env,
                    close_fds=True,
                    start_new_session=True,
                    restore_signals=True,
                )
            except Exception:
                try:
                    os.close(master_fd)
                except Exception:
                    pass
                raise
            finally:
                try:
                    os.close(slave_fd)
                except Exception:
                    pass
            self._child_pid = self.proc.pid
            try:
                self._child_pgid = os.getpgid(self._child_pid)
            except Exception:
                self._child_pgid = self._child_pid
            self._master_fd = master_fd
        self._start_reader()

    def send_bootstrap(self) -> None:
        if self.env.get("PLAMEN_BOOTSTRAP_IN_ARGV") == "1":
            return
        prompt = (
            "Read and fully execute every instruction in "
            f"{self.prompt_path.as_posix()}. When done, output your one-line "
            "DONE summary."
        )
        if sys.platform == "win32":
            self.write(prompt)
            time.sleep(0.75)
            try:
                self.proc.sendcontrol("m")
            except Exception:
                self.write("\r\n")
        else:
            self.write(prompt + "\n")

    def send_continuation(self, message: str) -> None:
        """Send a continuation user-message into the live PTY.

        Ship 5 of the artifact-complete PTY supervision plan. Mirrors
        ``send_bootstrap``'s platform-conditional CR/CRLF handling
        exactly: on Windows we write the prompt body, idle 0.75s for
        the prompt box to settle, then send a Carriage Return via
        ``sendcontrol("m")`` (with a ``\\r\\n`` fallback if the winpty
        control method is unavailable); on POSIX we append ``\\n`` to
        the body and write it in one shot.

        Caller MUST verify ``self.is_alive()`` before invoking. Ship 6
        wraps this call in the supervised PTY loop so a dead PTY
        triggers the ``--resume`` fallback instead.

        No new lifecycle, no new threads, no reader-stop handling --
        the existing reader thread captures Claude's response on the
        same channel it captured the bootstrap turn.
        """
        if sys.platform == "win32":
            self.write(message)
            time.sleep(0.75)
            try:
                self.proc.sendcontrol("m")
            except Exception:
                self.write("\r\n")
        else:
            self.write(message + "\n")

    def write(self, text: str) -> None:
        if sys.platform == "win32":
            self.proc.write(text)
        else:
            if self._master_fd is None:
                return
            os.write(self._master_fd, text.encode("utf-8", errors="replace"))

    def is_alive(self) -> bool:
        if self.proc is None:
            return False
        if sys.platform == "win32":
            return bool(self.proc.isalive())
        return self.proc.poll() is None

    def terminate(self, grace_s: float = 5.0) -> None:
        self._reader_stop.set()
        try:
            if self.proc is None:
                return
            if sys.platform == "win32":
                try:
                    self.proc.terminate(force=False)
                    deadline = time.time() + grace_s
                    while time.time() < deadline and self.proc.isalive():
                        time.sleep(0.1)
                    if self.proc.isalive():
                        self.proc.kill()
                except Exception:
                    try:
                        self.proc.kill()
                    except Exception:
                        pass
                try:
                    pid = getattr(self.proc, "pid", None)
                    if pid:
                        subprocess.run(
                            ["taskkill", "/PID", str(pid), "/T", "/F"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=max(1.0, grace_s + 0.5),
                            check=False,
                        )
                except Exception:
                    pass
            else:
                pgid = self._child_pgid
                pid = self._child_pid
                try:
                    if pgid is not None:
                        os.killpg(pgid, signal.SIGTERM)
                except Exception:
                    try:
                        if pid is not None:
                            os.kill(pid, signal.SIGTERM)
                    except Exception:
                        pass
                deadline = time.time() + grace_s
                while time.time() < deadline and self.is_alive():
                    time.sleep(0.1)
                if self.is_alive():
                    try:
                        if pgid is not None:
                            os.killpg(pgid, signal.SIGKILL)
                    except Exception:
                        try:
                            if pid is not None:
                                os.kill(pid, signal.SIGKILL)
                        except Exception:
                            pass
                try:
                    self.proc.wait(timeout=1.0)
                except Exception:
                    pass
        finally:
            if self._reader_thread and self._reader_thread.is_alive():
                self._reader_thread.join(timeout=1.0)
            if self._master_fd is not None:
                try:
                    os.close(self._master_fd)
                except Exception:
                    pass
                self._master_fd = None

    def wait_for_turn_complete(
        self,
        timeout_s: float,
        quiescence_s: float = 8.0,
        poll_s: float = 0.1,
        transcript_poll_s: float = 0.5,
        on_poll: Any = None,
    ) -> TurnCompleteState:
        started_mono = time.monotonic()
        deadline = started_mono + timeout_s
        state = inspect_transcript(self.transcript_path)
        last_transcript_poll = started_mono - max(0.0, transcript_poll_s)
        # Sticky timestamp of the FIRST output-cap sighting in the current
        # cap episode. Reset whenever the cap text is no longer present (a
        # productive turn scrolled past it). Used by the cap-LOOP gate below.
        first_output_cap_seen_at: Optional[float] = None
        # Context-thrash latches (Ship 8.17).  Authority is DELTA-based: a
        # compaction marker already present when this wait begins is historical
        # and cannot arm the breaker.  Any non-compaction transcript event or
        # ordinary PTY stream delta resets the episode and establishes a new
        # baseline.  Quiet compaction requires at least two post-baseline
        # summary events; a single compact-then-slow-tool interval is healthy.
        first_thrash_seen_at: Optional[float] = None
        episode_has_explicit_overflow = False
        episode_compaction_start: Optional[int] = None
        last_meaningful_count = int(state.meaningful_event_count)
        compaction_baseline = int(state.compaction_event_count)
        with self._recent_output_lock:
            last_recent_norm = _normalized_pty_text(self._recent_output)
        overflow_baseline_active = bool(
            _CONTEXT_OVERFLOW_TEXT_RE.search(last_recent_norm)
        )
        while True:
            now = time.monotonic()
            wall_now = time.time()
            if now - last_transcript_poll >= transcript_poll_s:
                state = inspect_transcript(self.transcript_path)
                last_transcript_poll = now
                with self._recent_output_lock:
                    _recent_norm = _normalized_pty_text(self._recent_output)
                    if _USAGE_CAP_TEXT_RE.search(_recent_norm):
                        state.rate_limited = True
                    elif _OUTPUT_CAP_TEXT_RE.search(_recent_norm):
                        # The turn hit the model output-token cap and cannot
                        # emit more. Two terminal signatures:
                        #   (a) quiescence -- the turn went silent after the
                        #       cap (no new transcript events for
                        #       quiescence_s). Fast path for the common case.
                        #   (b) cap LOOP -- the turn auto-continues past the
                        #       cap and hits it again, so events keep flowing
                        #       and (a) never trips. If the cap text persists
                        #       across _OUTPUT_CAP_LOOP_S, the turn is stuck
                        #       generating-until-cap and will never finish.
                        # A self-recovering turn scrolls past the cap (the
                        # text leaves the recent-output buffer), resetting the
                        # latch in the else branch -- so neither path cuts off
                        # a productive turn prematurely.
                        if first_output_cap_seen_at is None:
                            first_output_cap_seen_at = now
                        if (
                            state.last_event_time is not None
                            and wall_now - state.last_event_time >= quiescence_s
                        ):
                            state.output_truncated = True
                        elif now - first_output_cap_seen_at >= _OUTPUT_CAP_LOOP_S:
                            state.output_truncated = True
                    else:
                        first_output_cap_seen_at = None

                    # Context-overflow / autocompact zero-progress breaker.
                    # Only evidence NEWER than the current activity baseline
                    # can arm it.  Whole-transcript historical markers are not
                    # authority.  A normal stream delta (tool output/thinking)
                    # is activity unless that delta itself is only a new
                    # overflow/compaction signal.
                    meaningful_count = int(state.meaningful_event_count)
                    meaningful_advanced = meaningful_count > last_meaningful_count
                    recent_changed = _recent_norm != last_recent_norm
                    if recent_changed:
                        if _recent_norm.startswith(last_recent_norm):
                            recent_delta = _recent_norm[len(last_recent_norm):]
                        else:
                            recent_delta = _recent_norm
                        delta_is_signature = bool(
                            _CONTEXT_OVERFLOW_TEXT_RE.search(recent_delta)
                        ) or any(
                            marker in recent_delta.lower()
                            for marker in _COMPACTION_MARKERS
                        )
                        stream_activity = bool(recent_delta.strip()) and not delta_is_signature
                    else:
                        stream_activity = False

                    overflow_now = bool(
                        _CONTEXT_OVERFLOW_TEXT_RE.search(_recent_norm)
                    )
                    if meaningful_advanced or stream_activity:
                        last_meaningful_count = meaningful_count
                        compaction_baseline = int(state.compaction_event_count)
                        overflow_baseline_active = overflow_now
                        first_thrash_seen_at = None
                        episode_has_explicit_overflow = False
                        episode_compaction_start = None
                    else:
                        new_explicit_overflow = (
                            overflow_now and not overflow_baseline_active
                        )
                        compaction_count = int(state.compaction_event_count)
                        new_compaction = compaction_count > compaction_baseline
                        if new_explicit_overflow:
                            episode_has_explicit_overflow = True
                            overflow_baseline_active = True
                        if new_compaction and episode_compaction_start is None:
                            episode_compaction_start = compaction_count
                        repeated_compaction = (
                            episode_compaction_start is not None
                            and compaction_count > episode_compaction_start
                        )
                        if episode_has_explicit_overflow or repeated_compaction:
                            if first_thrash_seen_at is None:
                                first_thrash_seen_at = now
                            elif (
                                now - first_thrash_seen_at
                                >= _CONTEXT_THRASH_LOOP_S
                            ):
                                state.context_thrash = True
                    last_recent_norm = _recent_norm
            if on_poll:
                on_poll(wall_now, state)
            if state.rate_limited:
                return state
            if state.output_truncated:
                return state
            if state.context_thrash:
                return state
            if state.complete and state.last_event_time is not None:
                if wall_now - state.last_event_time >= quiescence_s:
                    return state
            if not self.is_alive():
                return state
            if now >= deadline:
                return state
            time.sleep(poll_s)

    def _start_reader(self) -> None:
        def _reader() -> None:
            while not self._reader_stop.is_set():
                try:
                    if sys.platform == "win32":
                        if not self.proc or not self.proc.isalive():
                            break
                        chunk = self.proc.read(4096)
                    else:
                        if self._master_fd is None:
                            break
                        readable, _, _ = select.select([self._master_fd], [], [], 0.25)
                        if not readable:
                            if not self.is_alive():
                                break
                            continue
                        if self._master_fd is None:
                            break
                        data = os.read(self._master_fd, 4096)
                        if not data:
                            break
                        chunk = data.decode("utf-8", errors="replace")
                    if chunk:
                        with self._recent_output_lock:
                            self._recent_output = (
                                self._recent_output + chunk
                            )[-65536:]
                        self.log_file.write(chunk)
                        self.log_file.flush()
                except Exception:
                    time.sleep(0.1)

        self._reader_thread = threading.Thread(target=_reader, daemon=True)
        self._reader_thread.start()
