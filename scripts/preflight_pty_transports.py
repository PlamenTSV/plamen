"""Empirical preflight tests for Claude Code PTY transports.

Ship 4 of the artifact-complete PTY supervision plan.

This module discovers which continuation mechanisms the installed
Claude Code binary supports for the PTY supervision loop:

  - ``live_pty_continue_supported`` -- the interactive PTY-spawned
    Claude session remains alive after the first ``end_turn`` and
    accepts a continuation user-message that produces another turn.

  - ``agentid_resume_supported`` -- an ``agentId`` handle returned by
    the Agent tool can be resumed via ``SendMessage`` across a fresh
    ``claude --resume <session_id>`` subprocess.

Results are cached keyed by ``claude --version`` so the test runs once
per Claude Code version. The cache auto-invalidates on version bump.
Ship 6 will invoke ``ensure_preflight_cache`` from inside the supervised
PTY branch, gated by ``should_run_preflight``. Ship 4 does NOT wire the
module into ``run_phase`` -- it is standalone, importable, and
testable in isolation.

Conservative-on-uncertainty rule: every probe and every cache read
returns ``False`` / ``None`` on any exception. The driver always has a
working fallback (whole-phase retry, respawn-only), so the worst case
of a probe returning ``False`` is "we use the existing slower path".
"""
from __future__ import annotations

import datetime as _dt
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from owned_process_runner import run_owned_process
from pty_exec import (  # noqa: E402
    SUBPROCESS_ISOLATION_PAYLOAD,
    append_claude_pty_prompt_arg,
    build_claude_pty_argv,
    claude_pty_shape_hash,
    isolation_overlay_hash,
)

log = logging.getLogger("plamen.preflight")

# Bump this when the cache schema changes in a way callers must
# re-derive. Cache files written with an older schema are ignored.
# v2 (Ship 8.10): added argv_shape_hash + isolation_overlay_hash to the
# cache. Bumping 1->2 also invalidates every pre-8.10 false-negative cache
# whose probe ran without the production isolation flags.
# v3: child Claude probes strip parent Claude Code session identity vars.
# Invalidates any false-negative cache written from inside `/plamen` before
# the env isolation fix.
_SCHEMA_VERSION = 3
_CACHE_FILENAME_TMPL = "preflight_pty_{ver}.json"

# Per-probe wall-clock timeouts. The PTY probes are intentionally
# bounded -- if Claude does not respond within the window, the probe
# returns False conservatively and the driver falls to the respawn
# transport.
_PREFLIGHT_TURN_TIMEOUT_S = 180.0
_PREFLIGHT_TURN_QUIESCENCE_S = 4.0

# Phases that participate in PTY supervision. Ship 8 may expand this
# to depth/niche/verify/report. Ship 4 ships breadth only because that
# is the failure class closed by the plan.
_DEFAULT_SUPERVISED_PHASES = frozenset({"breadth"})

_PARENT_CLAUDE_IDENTITY_ENV_KEYS = frozenset({
    "CLAUDECODE",
    "CLAUDE_CODE_SESSION_ID",
    "CLAUDE_CODE_ENTRYPOINT",
    "CLAUDE_CODE_EXECPATH",
    "AI_AGENT",
})


def _filtered_child_subprocess_environ(
    source_env: dict[str, str] | None = None,
) -> dict[str, str]:
    env = dict(os.environ if source_env is None else source_env)
    for key in _PARENT_CLAUDE_IDENTITY_ENV_KEYS:
        env.pop(key, None)
    return env


# ---------------------------------------------------------------------------
# Version detection and cache I/O
# ---------------------------------------------------------------------------


def get_claude_version(claude_bin: str) -> str:
    """Return the trimmed ``claude --version`` output token (e.g.
    ``"2.1.146"``).

    Falls back to ``"unknown"`` when the binary is missing, the call
    times out, or the output is empty. The fallback is sticky -- two
    runs that both yield ``"unknown"`` share the same cache slot, which
    is the intended degenerate behavior (no version means we cannot
    safely re-run the probe).
    """
    try:
        result = run_owned_process(
            [claude_bin, "--version"],
            timeout=15,
            encoding="utf-8",
            errors="replace",
        )
    except Exception as exc:
        log.warning(f"[preflight] '{claude_bin} --version' failed: {exc}")
        return "unknown"
    raw = (result.stdout or "").strip()
    if not raw:
        return "unknown"
    # Claude --version output is "2.1.146 (Claude Code)" or similar;
    # take the leading whitespace-separated token.
    return raw.split()[0]


def _slugify_version(ver: str) -> str:
    """Return a filesystem-safe filename component for ``ver``.
    Collapses any non-[A-Za-z0-9._-] run to a single underscore."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", ver) or "unknown"


def _cache_path(cache_dir: Path, claude_version: str) -> Path:
    return cache_dir / _CACHE_FILENAME_TMPL.format(
        ver=_slugify_version(claude_version)
    )


def _read_cache(path: Path) -> Optional[dict]:
    """Return parsed cache contents iff the file exists, is readable,
    is valid JSON, and carries the current ``_SCHEMA_VERSION``. Returns
    ``None`` otherwise (a stale or corrupt cache forces a re-probe)."""
    try:
        if not path.exists():
            return None
        with path.open("r", encoding="utf-8") as fp:
            data = json.load(fp)
    except Exception as exc:
        log.warning(f"[preflight] cache read failed at {path}: {exc}")
        return None
    if not isinstance(data, dict):
        return None
    if data.get("schema_version") != _SCHEMA_VERSION:
        log.info(
            f"[preflight] cache at {path} has schema_version "
            f"{data.get('schema_version')!r} != {_SCHEMA_VERSION}; "
            f"ignoring and re-probing"
        )
        return None
    return data


def _write_cache(path: Path, data: dict) -> None:
    """Atomic-rename write of cache JSON. Best-effort: failures are
    logged but never raised -- the driver still has the probe result
    in-memory and can proceed."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(data, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        tmp.replace(path)
    except Exception as exc:
        log.warning(f"[preflight] cache write failed at {path}: {exc}")


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_probe_argv(
    claude_bin: str,
    session_id: str,
    tmp_dir: Path,
    isolation_payload: str,
    prompt: str | None = None,
) -> list[str]:
    """Ship 8.10: build a probe argv that matches the PRODUCTION PTY shape.

    Writes the SAME `_subprocess_isolation.json` overlay production writes
    into the throwaway scratchpad, then builds via the shared
    `build_claude_pty_argv` with the production structure: two `--add-dir`
    (the temp scratchpad + plamen_home, mirroring project + plamen_home)
    and the full non-MCP isolation set. The historical false negative came
    from the probe OMITTING this isolation set and hitting the plugin/MCP
    cold-start hang it was meant to avoid.

    The exact pinned Haiku model is intentional: the PTY-continuation / agentId-resume
    capability is a CLI transport property, independent of the model, and
    haiku keeps the probe cheap. `claude_pty_argv_shape` normalizes the
    model value, so the probe and production shape hashes still match.
    """
    from plamen_types import (  # late import: avoid import cycle
        PLAMEN_HAIKU_MODEL,
        plamen_home,
    )

    iso_path = tmp_dir / "_subprocess_isolation.json"
    try:
        iso_path.write_text(isolation_payload, encoding="utf-8")
        iso_arg: Optional[str] = str(iso_path)
    except Exception:
        iso_arg = None  # mirror production's overlay-write-failed fallback
    argv = build_claude_pty_argv(
        claude_bin=claude_bin,
        model=PLAMEN_HAIKU_MODEL,
        session_id=session_id,
        add_dirs=[str(tmp_dir), plamen_home().as_posix()],
        disallow_mcp=True,
        isolation_path=iso_arg,
    )
    if prompt is not None:
        argv = append_claude_pty_prompt_arg(argv, prompt)
    return argv


def _probe_shape_hash() -> str:
    """The argv shape hash the probe produces in the normal (overlay-write-
    succeeds) case. Built directly -- no filesystem writes -- since
    `claude_pty_argv_shape` normalizes the volatile session-id / dir / iso
    values away. Mirrors `_build_probe_argv`'s success-case structure: two
    `--add-dir` + the full isolation set."""
    from plamen_types import (  # late import: avoid import cycle
        PLAMEN_HAIKU_MODEL,
        plamen_home,
    )

    canonical = build_claude_pty_argv(
        claude_bin="claude",
        model=PLAMEN_HAIKU_MODEL,
        session_id="probe",
        add_dirs=["probe-dir", plamen_home().as_posix()],
        disallow_mcp=True,
        isolation_path="probe-iso",
    )
    canonical = append_claude_pty_prompt_arg(
        canonical,
        "Read and fully execute every instruction in "
        "probe-prompt.md. When done, output your one-line DONE summary.",
    )
    return claude_pty_shape_hash(canonical)


# ---------------------------------------------------------------------------
# Empirical probes (production code; tests mock these)
# ---------------------------------------------------------------------------


def _test_live_pty_continue(
    claude_bin: str, isolation_payload: str = SUBPROCESS_ISOLATION_PAYLOAD,
) -> tuple[bool, str]:
    """Probe whether a PTY-spawned Claude session accepts a continuation
    after the first ``end_turn``.

    Methodology:
      1. Build a throwaway scratchpad in ``tempfile.mkdtemp``.
      2. Spawn ``ClaudePtySession`` with a tiny bootstrap prompt asking
         Claude to ``Write`` a stub file ``first.txt``.
      3. Wait for ``end_turn`` (bounded by
         ``_PREFLIGHT_TURN_TIMEOUT_S``).
      4. If the first file is missing OR the PTY process exited,
         return ``(False, reason)``.
      5. Otherwise, write a continuation user-message asking for a
         second file ``second.txt``.
      6. Wait for a second ``end_turn``.
      7. Return ``(True, ...)`` iff ``second.txt`` is on disk.

    Conservative: any exception returns ``(False, reason)``. The
    throwaway scratchpad is cleaned up in ``finally`` regardless.
    """
    # Late import: pty_exec is only needed at probe time, not at module
    # import time, so unit tests that monkeypatch this function never
    # need a working pty_exec dependency.
    try:
        from pty_exec import ClaudePtySession  # noqa: WPS433
    except Exception as exc:  # pragma: no cover - environment failure
        return False, f"pty_exec unavailable: {exc}"

    tmp_dir = Path(tempfile.mkdtemp(prefix="plamen_preflight_live_"))
    log_path = tmp_dir / "log.txt"
    first_target = tmp_dir / "first.txt"
    second_target = tmp_dir / "second.txt"
    prompt_path = tmp_dir / "prompt.md"
    try:
        prompt_path.write_text(
            "You are a preflight probe for a PTY transport test. Use the "
            "Write tool exactly once to create the file at "
            f"{first_target.as_posix()} with the content 'first'. "
            "When the file exists on disk, output the one-line summary "
            "'DONE: first' and STOP. Do not perform any other action.",
            encoding="utf-8",
        )
        session_id = str(uuid.uuid4())
        # Ship 8.10: production-shaped argv (two --add-dir + isolation set)
        # via the shared builder, so the probe exercises the SAME shape
        # production runs and no longer hits the plugin/MCP cold-start hang
        # that produced the historical false negative.
        bootstrap_prompt = (
            "Read and fully execute every instruction in "
            f"{prompt_path.as_posix()}. When done, output your one-line "
            "DONE summary."
        )
        argv = _build_probe_argv(
            claude_bin, session_id, tmp_dir, isolation_payload,
            prompt=bootstrap_prompt,
        )
        env = {
            **_filtered_child_subprocess_environ(),
            "PLAMEN_PREFLIGHT": "1",
            "PLAMEN_BOOTSTRAP_IN_ARGV": "1",
        }

        with log_path.open("w", encoding="utf-8") as log_fp:
            session = ClaudePtySession(
                argv,
                cwd=str(tmp_dir),
                env=env,
                session_id=session_id,
                prompt_path=prompt_path,
                log_file=log_fp,
            )
            try:
                session.spawn()
                session.send_bootstrap()
                session.wait_for_turn_complete(
                    timeout_s=_PREFLIGHT_TURN_TIMEOUT_S,
                    quiescence_s=_PREFLIGHT_TURN_QUIESCENCE_S,
                )
                if not first_target.exists():
                    return (
                        False,
                        "first file never written; PTY produced no observable result",
                    )
                if not session.is_alive():
                    return (
                        False,
                        "PTY process exited after first end_turn; "
                        "live continuation unavailable",
                    )
                # Send a continuation as a fresh user message into the
                # still-alive PTY. Inline the platform-conditional CR/LF
                # handling so this probe does not depend on Ship 5's
                # `send_continuation` helper.
                continuation = (
                    "Use the Write tool exactly once to create the file "
                    f"at {second_target.as_posix()} with the content "
                    "'second'. When the file exists, output 'DONE: "
                    "second' and STOP."
                )
                if sys.platform == "win32":
                    session.write(continuation)
                    time.sleep(0.75)
                    try:
                        session.proc.sendcontrol("m")
                    except Exception:
                        session.write("\r\n")
                else:
                    session.write(continuation + "\n")
                session.wait_for_turn_complete(
                    timeout_s=_PREFLIGHT_TURN_TIMEOUT_S,
                    quiescence_s=_PREFLIGHT_TURN_QUIESCENCE_S,
                )
                if second_target.exists():
                    return (
                        True,
                        "PTY accepted continuation and produced second file",
                    )
                return (
                    False,
                    "second file missing after continuation; "
                    "live PTY did not process follow-up message",
                )
            finally:
                try:
                    session.terminate(grace_s=4)
                except Exception:
                    pass
    except Exception as exc:
        return False, f"preflight error: {type(exc).__name__}: {exc}"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


_AGENTID_RE = re.compile(
    r"agentId:\s*([A-Za-z0-9_-]+)\s*\(use SendMessage",
)


def _test_agentid_resume(
    claude_bin: str, isolation_payload: str = SUBPROCESS_ISOLATION_PAYLOAD,
) -> tuple[bool, str]:
    """Probe whether an ``agentId`` handle returned by the Agent tool
    can be resumed via ``SendMessage`` across a fresh
    ``claude --resume <session_id>`` subprocess.

    Methodology:
      1. Build a throwaway scratchpad.
      2. Session 1: spawn a Claude PTY session whose prompt instructs
         Claude to dispatch ONE Agent subagent. Capture the agentId from
         the transcript.
      3. Terminate session 1.
      4. Session 2: spawn ``claude --resume <session_id>`` with a
         prompt asking ``SendMessage`` to that agentId with instructions
         to ``Write`` a target file.
      5. Return ``(True, ...)`` iff the target file exists on disk
         after session 2 reaches ``end_turn``.

    Conservative: any failure to capture the agentId, any exception, or
    any timeout returns ``(False, reason)``.
    """
    try:
        from pty_exec import ClaudePtySession  # noqa: WPS433
    except Exception as exc:  # pragma: no cover
        return False, f"pty_exec unavailable: {exc}"

    tmp_dir = Path(tempfile.mkdtemp(prefix="plamen_preflight_resume_"))
    resume_target = tmp_dir / "resumed.txt"
    try:
        # ---- Session 1: dispatch one subagent, capture agentId ----
        prompt1 = tmp_dir / "prompt1.md"
        prompt1.write_text(
            "You are a preflight probe. Use the Agent tool exactly once "
            "to dispatch ONE general-purpose subagent. The subagent's "
            "task is to return the literal string 'subagent ready' and "
            "stop. After the Agent tool returns, output 'DONE: agent dispatched' "
            "and STOP.",
            encoding="utf-8",
        )
        session_id = str(uuid.uuid4())
        # Ship 8.10: production-shaped argv via the shared builder.
        bootstrap1 = (
            "Read and fully execute every instruction in "
            f"{prompt1.as_posix()}. When done, output your one-line "
            "DONE summary."
        )
        argv1 = _build_probe_argv(
            claude_bin, session_id, tmp_dir, isolation_payload,
            prompt=bootstrap1,
        )
        env = {
            **_filtered_child_subprocess_environ(),
            "PLAMEN_PREFLIGHT": "1",
            "PLAMEN_BOOTSTRAP_IN_ARGV": "1",
        }
        log1_path = tmp_dir / "log1.txt"
        captured_agentid: Optional[str] = None
        transcript_path: Optional[Path] = None

        with log1_path.open("w", encoding="utf-8") as log_fp1:
            session1 = ClaudePtySession(
                argv1,
                cwd=str(tmp_dir),
                env=env,
                session_id=session_id,
                prompt_path=prompt1,
                log_file=log_fp1,
            )
            try:
                session1.spawn()
                session1.send_bootstrap()
                session1.wait_for_turn_complete(
                    timeout_s=_PREFLIGHT_TURN_TIMEOUT_S,
                    quiescence_s=_PREFLIGHT_TURN_QUIESCENCE_S,
                )
                transcript_path = session1.transcript_path
            finally:
                try:
                    session1.terminate(grace_s=4)
                except Exception:
                    pass

        if transcript_path is None or not transcript_path.exists():
            return (
                False,
                "session 1 produced no transcript; agentId cannot be captured",
            )
        try:
            transcript_text = transcript_path.read_text(
                encoding="utf-8", errors="replace"
            )
        except Exception as exc:
            return False, f"transcript read failed: {exc}"
        match = _AGENTID_RE.search(transcript_text)
        if not match:
            return (
                False,
                "no agentId returned by subagent in session 1; "
                "Agent tool may not use pause-handle semantics",
            )
        captured_agentid = match.group(1)

        # ---- Session 2: --resume the same session, SendMessage agentId ----
        prompt2 = tmp_dir / "prompt2.md"
        prompt2.write_text(
            f"Use the SendMessage tool with `to: '{captured_agentid}'` to "
            "instruct the previously-dispatched subagent to Use the Write "
            f"tool to create the file at {resume_target.as_posix()} with "
            "the content 'resumed'. When the file exists, output "
            "'DONE: resumed' and STOP.",
            encoding="utf-8",
        )
        bootstrap2 = (
            "Read and fully execute every instruction in "
            f"{prompt2.as_posix()}. When done, output your one-line "
            "DONE summary."
        )
        # Resume command: strip --session-id; insert --resume <id>.
        argv2 = []
        skip_next = False
        for tok in argv1:
            if skip_next:
                skip_next = False
                continue
            if tok == "--session-id":
                skip_next = True
                continue
            argv2.append(tok)
        argv2 = [argv2[0], "--resume", session_id] + argv2[1:]
        if argv2 and str(argv2[-1]).startswith(
            "Read and fully execute every instruction in "
        ):
            argv2[-1] = bootstrap2
        else:
            argv2 = append_claude_pty_prompt_arg(argv2, bootstrap2)

        log2_path = tmp_dir / "log2.txt"
        with log2_path.open("w", encoding="utf-8") as log_fp2:
            session2 = ClaudePtySession(
                argv2,
                cwd=str(tmp_dir),
                env=env,
                session_id=session_id,
                prompt_path=prompt2,
                log_file=log_fp2,
            )
            try:
                session2.spawn()
                session2.send_bootstrap()
                session2.wait_for_turn_complete(
                    timeout_s=_PREFLIGHT_TURN_TIMEOUT_S,
                    quiescence_s=_PREFLIGHT_TURN_QUIESCENCE_S,
                )
                if resume_target.exists():
                    return (
                        True,
                        f"agentId {captured_agentid} resumed via --resume; "
                        "SendMessage produced target file",
                    )
                return (
                    False,
                    "resumed target file missing; SendMessage to "
                    f"agentId {captured_agentid} did not execute the "
                    "follow-up task",
                )
            finally:
                try:
                    session2.terminate(grace_s=4)
                except Exception:
                    pass
    except Exception as exc:
        return False, f"preflight error: {type(exc).__name__}: {exc}"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def ensure_preflight_cache(
    claude_bin: str,
    plamen_cache_dir: Path,
    *,
    force: bool = False,
    expected_shape_hash: Optional[str] = None,
    isolation_overlay_payload: str = SUBPROCESS_ISOLATION_PAYLOAD,
) -> dict:
    """Return the cached preflight result for the installed Claude Code
    version. Runs the probes on cache miss (or ``force=True``) and
    writes the result to disk for future invocations.

    Cache file: ``{plamen_cache_dir}/preflight_pty_<version>.json``.
    Version slug is filesystem-safe per ``_slugify_version``.

    Schema (``_SCHEMA_VERSION == 1``)::

      {
        "schema_version": 1,
        "claude_version": "2.1.146",
        "tested_at": "<iso>",
        "tested_on_platform": "win32" | "darwin" | "linux",
        "live_pty_continue_supported": bool,
        "agentid_resume_supported": bool,
        "test_details": {
          "live_pty_continue": "<one-line outcome>",
          "agentid_resume":    "<one-line outcome>"
        }
      }

    Conservative: probe errors are caught, returning ``False`` for the
    affected transport. The driver always has a working fallback.
    """
    claude_version = get_claude_version(claude_bin)
    cache_dir = Path(plamen_cache_dir)
    cache_file = _cache_path(cache_dir, claude_version)

    # Ship 8.10: the cache key is (version, platform, argv shape, isolation
    # overlay). A cached result is reused ONLY when ALL four match. Old
    # pre-8.10 caches (no argv_shape_hash, or one taken under a different
    # shape / overlay) are ignored -> re-probe under the aligned shape.
    overlay_hash = isolation_overlay_hash(isolation_overlay_payload)
    probe_shape = _probe_shape_hash()

    if not force:
        cached = _read_cache(cache_file)
        if cached is not None:
            mismatches = []
            if cached.get("claude_version") != claude_version:
                mismatches.append("version")
            if cached.get("tested_on_platform") != sys.platform:
                mismatches.append("platform")
            if (expected_shape_hash is not None
                    and cached.get("argv_shape_hash") != expected_shape_hash):
                mismatches.append("argv_shape")
            if cached.get("isolation_overlay_hash") != overlay_hash:
                mismatches.append("isolation_overlay")
            if not mismatches:
                return cached
            log.info(
                f"[preflight] ignoring cache at {cache_file} "
                f"(mismatch: {', '.join(mismatches)}); re-probing under "
                f"the aligned argv/isolation shape"
            )

    live_ok, live_detail = _test_live_pty_continue(
        claude_bin, isolation_overlay_payload
    )
    aid_ok, aid_detail = _test_agentid_resume(
        claude_bin, isolation_overlay_payload
    )

    data = {
        "schema_version": _SCHEMA_VERSION,
        "claude_version": claude_version,
        "tested_at": _now_iso(),
        "tested_on_platform": sys.platform,
        "argv_shape_hash": probe_shape,
        "isolation_overlay_hash": overlay_hash,
        "live_pty_continue_supported": bool(live_ok),
        "agentid_resume_supported": bool(aid_ok),
        "test_details": {
            "live_pty_continue": live_detail,
            "agentid_resume": aid_detail,
        },
    }
    # Ship 8.10 diagnosability: when a probe STILL returns false after the
    # shape alignment, surface the exact reason so it is debuggable rather
    # than a silent slow-path fall-through.
    if not live_ok:
        log.info(f"[preflight] live_pty_continue=False: {live_detail}")
    if not aid_ok:
        log.info(f"[preflight] agentid_resume=False: {aid_detail}")
    _write_cache(cache_file, data)
    return data


def should_run_preflight(
    backend: str,
    is_claude_pty: bool,
    phase_name: str,
    supervised_phases: Optional[Any] = None,
) -> bool:
    """Gating helper called by the driver at the supervised-PTY branch
    entry point (Ship 6) to decide whether to invoke
    ``ensure_preflight_cache``.

    Returns True only when ALL three conditions hold:

      - ``backend == "claude"`` (Codex / other backends do not
        participate in the supervision plan).
      - ``is_claude_pty`` is True (the interactive PTY transport is in
        use; the deprecated ``claude -p --no-session-persistence``
        path is explicitly out of scope per the plan's hard constraint
        #2).
      - ``phase_name`` is in ``supervised_phases`` (default:
        ``{"breadth"}`` -- Ship 8 may broaden this set).

    Putting the gate logic here means Ship 6's driver call site can be
    a single ``if should_run_preflight(...): preflight = ensure_preflight_cache(...)``
    without re-deriving the contract. It also lets Ship 4 test the
    gate without driver state.
    """
    if backend != "claude":
        return False
    if not is_claude_pty:
        return False
    if not phase_name:
        return False
    sup = (
        supervised_phases
        if supervised_phases is not None
        else _DEFAULT_SUPERVISED_PHASES
    )
    try:
        return phase_name in sup
    except TypeError:
        return False
