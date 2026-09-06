"""Tests for graceful stop, subprocess termination, and rate-limit detection.

Covers:
  1. GracefulStop: request_halt sets flag, install() is no-op
  2. PauseToggle: Esc triggers halt, Ctrl+P toggles pause, _handle_key dispatch
  3. _wait_with_heartbeat: terminates subprocess on halt (returns -3)
  4. detect_rate_limit: JSON envelope path, text-fallback path, false-positive resistance
  5. rate_limit_wait_interactive: countdown exits on early_resume event
  6. estimate_rate_limit_wait_seconds: parses retry-after / reset-time patterns
  7. wait_halt_choice: Enter → True, Esc → False

Run: python -m pytest test_signal_and_ratelimit.py -v
"""
from __future__ import annotations

import json
import inspect
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_driver as D
import plamen_display as display


# ─── GracefulStop ──────────────────────────────────────────────────────


def test_graceful_stop_starts_unrequested():
    """GracefulStop starts with requested=False."""
    gs = display.GracefulStop()
    assert gs.requested is False


def test_graceful_stop_request_halt_sets_flag():
    """request_halt() sets .requested=True."""
    gs = display.GracefulStop()
    with patch.object(display, "print_halt_acknowledged"):
        gs.request_halt()
    assert gs.requested is True


def test_graceful_stop_request_halt_idempotent():
    """Second request_halt() is a no-op (no duplicate message)."""
    gs = display.GracefulStop()
    with patch.object(display, "print_halt_acknowledged") as mock_print:
        gs.request_halt()
        gs.request_halt()
    mock_print.assert_called_once()


def test_graceful_stop_install_is_noop():
    """install() no longer overrides SIGINT."""
    original = signal.getsignal(signal.SIGINT)
    gs = display.GracefulStop()
    gs.install()
    assert signal.getsignal(signal.SIGINT) == original


# ─── PauseToggle / KeyboardController ────────────────────────────────


def test_pause_toggle_starts_unpaused():
    """PauseToggle starts in unpaused state."""
    pt = display.PauseToggle()
    assert pt.paused is False


def test_pause_toggle_halt_requested_reflects_graceful_stop():
    """halt_requested property reflects graceful_stop.requested."""
    old = display.graceful_stop.requested
    try:
        display.graceful_stop.requested = False
        pt = display.PauseToggle()
        assert pt.halt_requested is False
        display.graceful_stop.requested = True
        assert pt.halt_requested is True
    finally:
        display.graceful_stop.requested = old


def test_pause_toggle_wait_if_paused_returns_immediately_when_unpaused():
    """wait_if_paused returns immediately when not paused."""
    pt = display.PauseToggle()
    start = time.time()
    pt.wait_if_paused()
    assert time.time() - start < 0.5


def test_handle_key_esc_triggers_halt():
    """Esc key (0x1b) sets halt via graceful_stop."""
    old = display.graceful_stop.requested
    display.graceful_stop.requested = False
    pt = display.PauseToggle()
    try:
        with patch.object(display, "print_halt_acknowledged"):
            pt._handle_key(b"\x1b")
        assert display.graceful_stop.requested is True
    finally:
        display.graceful_stop.requested = old


def test_handle_key_ctrl_p_toggles_pause():
    """Ctrl+P (0x10) toggles paused state."""
    pt = display.PauseToggle()
    assert pt.paused is False
    with patch.object(display, "print_paused"):
        pt._handle_key(b"\x10")
    assert pt.paused is True
    with patch.object(display, "print_resumed"):
        pt._handle_key(b"\x10")
    assert pt.paused is False


def test_handle_key_other_ignored():
    """Other keys are silently ignored."""
    pt = display.PauseToggle()
    pt._handle_key(b"a")
    assert pt.paused is False


# ─── _wait_with_heartbeat: subprocess termination ──────────────────────


def test_heartbeat_returns_minus3_on_halt():
    """When halt is requested, subprocess gets terminated and -3 is returned."""
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    sp = Path(tempfile.mkdtemp(prefix="plamen_hb_"))

    old_requested = display.graceful_stop.requested
    def _set_halt():
        time.sleep(0.5)
        display.graceful_stop.requested = True

    t = threading.Thread(target=_set_halt, daemon=True)
    t.start()

    start = time.time()
    try:
        rc = D._wait_with_heartbeat(proc, timeout=30, scratchpad=sp,
                                    phase_name="test", start_time=start)
        assert rc == -3, f"Expected -3, got {rc}"
        elapsed = time.time() - start
        assert elapsed < 12, f"Took {elapsed:.1f}s — too slow"
    finally:
        display.graceful_stop.requested = old_requested
        try:
            proc.kill()
        except Exception:
            pass
        import shutil
        shutil.rmtree(sp, ignore_errors=True)


def test_heartbeat_returns_on_process_exit():
    """Normal subprocess exit returns the exit code."""
    proc = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.exit(42)"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    sp = Path(tempfile.mkdtemp(prefix="plamen_hb2_"))
    start = time.time()
    rc = D._wait_with_heartbeat(proc, timeout=30, scratchpad=sp,
                                phase_name="test", start_time=start)
    assert rc == 42
    import shutil
    shutil.rmtree(sp, ignore_errors=True)


def test_heartbeat_timeout():
    """Process exceeding timeout raises TimeoutExpired."""
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    sp = Path(tempfile.mkdtemp(prefix="plamen_hb3_"))
    start = time.time()
    try:
        D._wait_with_heartbeat(proc, timeout=2, scratchpad=sp,
                               phase_name="test", start_time=start)
        assert False, "Should have raised TimeoutExpired"
    except subprocess.TimeoutExpired:
        pass
    finally:
        proc.kill()
        proc.wait()
        import shutil
        shutil.rmtree(sp, ignore_errors=True)


def test_run_phase_launches_isolated_process_group():
    """Phase subprocesses must be killable as a tree on halt/timeout."""
    src = inspect.getsource(D._run_phase_once)
    wait_src = inspect.getsource(D._wait_with_heartbeat)
    helper_src = inspect.getsource(D._terminate_process_tree)

    assert "CREATE_NEW_PROCESS_GROUP" in src
    assert "start_new_session" in src
    assert "_terminate_process_tree(proc" in wait_src
    assert "taskkill" in helper_src
    assert "killpg" in helper_src


def test_halt_message_does_not_promise_fake_three_seconds(capsys):
    display.print_halt_acknowledged()
    out = capsys.readouterr()
    combined = out.out + out.err
    assert "within 3s" not in combined
    assert "options will follow" in combined


def test_worker_pool_halt_cancels_pending_futures():
    class _Executor:
        def __init__(self):
            self.shutdown_args = None

        def shutdown(self, **kwargs):
            self.shutdown_args = kwargs

    fut = MagicMock()
    executor = _Executor()
    D._cancel_pending_worker_futures({fut}, executor)
    fut.cancel.assert_called_once()
    assert executor.shutdown_args["wait"] is True
    assert executor.shutdown_args["cancel_futures"] is True


# ─── detect_rate_limit ─────────────────────────────────────────────────


def _write_log(content: str) -> Path:
    """Write content to a temp file and return its Path."""
    p = Path(tempfile.mktemp(suffix=".log", prefix="plamen_rl_"))
    p.write_text(content, encoding="utf-8")
    return p


def test_rate_limit_json_429():
    """JSON envelope with api_error_status=429 → detected."""
    envelope = json.dumps({
        "is_error": True,
        "api_error_status": 429,
        "error": {"type": "rate_limit_error", "message": "too many requests"},
    })
    p = _write_log(f"some preamble\n{envelope}\n")
    assert D.detect_rate_limit(p) is True
    p.unlink()


def test_rate_limit_json_529():
    """JSON envelope with api_error_status=529 → detected."""
    envelope = json.dumps({
        "is_error": True,
        "api_error_status": 529,
        "error": {"type": "overloaded_error", "message": "overloaded"},
    })
    p = _write_log(f"{envelope}\n")
    assert D.detect_rate_limit(p) is True
    p.unlink()


def test_rate_limit_json_stop_reason():
    """JSON envelope with stop_reason=rate_limited → detected."""
    envelope = json.dumps({
        "is_error": False,
        "stop_reason": "rate_limited",
    })
    p = _write_log(f"{envelope}\n")
    assert D.detect_rate_limit(p) is True
    p.unlink()


def test_rate_limit_json_clean_exit_not_detected():
    """JSON envelope with is_error=False, stop_reason=end_turn → NOT detected."""
    envelope = json.dumps({
        "is_error": False,
        "stop_reason": "end_turn",
        "total_cost_usd": 0.05,
    })
    p = _write_log(f"{envelope}\n")
    assert D.detect_rate_limit(p) is False
    p.unlink()


def test_rate_limit_text_fallback_429():
    """No JSON envelope, but structured 429 error → detected via text regex."""
    content = "Error: 429 Too Many Requests\nPlease wait and try again."
    p = _write_log(content)
    assert D.detect_rate_limit(p) is True
    p.unlink()


def test_rate_limit_text_fallback_529():
    """No JSON envelope, but structured 529 error → detected via text regex."""
    content = "Error: 529 overloaded\nServer is overloaded."
    p = _write_log(content)
    assert D.detect_rate_limit(p) is True
    p.unlink()


def test_rate_limit_prose_false_positive_resistance():
    """LLM prose mentioning 'quota exhausted' without structured prefix → NOT detected."""
    content = (
        "The analysis showed that the rate limit quota was exhausted until Apr 23.\n"
        "This is because the protocol's internal throttle mechanism prevents abuse.\n"
    )
    p = _write_log(content)
    assert D.detect_rate_limit(p) is False
    p.unlink()


def test_rate_limit_missing_file():
    """Non-existent file → NOT detected."""
    p = Path(tempfile.mktemp(suffix=".log"))
    assert D.detect_rate_limit(p) is False


def test_rate_limit_empty_file():
    """Empty file → NOT detected."""
    p = _write_log("")
    assert D.detect_rate_limit(p) is False
    p.unlink()


# ─── estimate_rate_limit_wait_seconds ──────────────────────────────────


def test_rate_limit_worker_pool_sentinel_detected_after_clean_json():
    """Worker-pool sentinel overrides a clean transcript JSON envelope."""
    envelope = json.dumps({
        "is_error": False,
        "stop_reason": "end_turn",
        "total_cost_usd": 0.01,
    })
    p = _write_log(f"{envelope}\n")
    D._append_rate_limit_sentinel(
        p,
        phase_name="depth",
        source="depth_worker_pool",
    )
    try:
        assert D.detect_rate_limit(p) is True
    finally:
        p.unlink()


def test_worker_pool_rate_limit_sentinel_is_structured():
    """The sentinel carries a structured 429 marker for fallback parsers."""
    p = _write_log("")
    D._append_rate_limit_sentinel(
        p,
        phase_name="breadth",
        source="breadth_worker_pool",
    )
    try:
        text = p.read_text(encoding="utf-8")
        assert "PLAMEN_RATE_LIMIT_DETECTED=1" in text
        assert "api_error_status=429" in text
        assert "type=rate_limit_error" in text
        assert D.detect_rate_limit(p) is True
    finally:
        p.unlink()


def test_all_claude_pty_worker_pools_stamp_rate_limit_sentinel():
    src = inspect.getsource(D._run_phase_once)
    for source in (
        "recon_worker_pool",
        "breadth_worker_pool",
        "rescan_worker_pool",
        "depth_worker_pool",
    ):
        assert source in src
    assert "PLAMEN_RATE_LIMIT_DETECTED=1" in src


def test_worker_pools_fail_fast_on_child_rate_limit():
    for fn in (
        D._run_recon_worker_pool_pty,
        # Wave-4 M3 split the breadth pool into a thin wave-gating wrapper
        # (`_run_breadth_worker_pool_pty`) over the unchanged roster runner
        # (`_run_breadth_worker_pool_pty_core`). The child-rate-limit
        # fail-fast loop lives in the core; the wrapper forwards the core's
        # rc unchanged (wave extension runs only on rc==0), so the guard must
        # inspect the core for the breadth pool.
        D._run_breadth_worker_pool_pty_core,
        D._run_rescan_worker_pool_pty,
        D._run_depth_worker_batch,
    ):
        src = inspect.getsource(fn)
        assert 'result.get("status") == "rate_limited"' in src
        assert "hit rate limit; stopping" in src
        assert "_cancel_pending_worker_futures" in src


def test_rate_limit_recovery_preserves_normal_gate_retry_budget():
    src = inspect.getsource(D.main)
    assert "if False and not passed and rate_limit_consumed_retry" not in src
    assert "gate failed after rate-limit recovery" in src
    assert "preserving normal retry budget" in src
    assert "rate_limit_consumed_retry = False" in src


def test_estimate_retry_after_seconds():
    p = _write_log("Error 429. Retry-After: 120 seconds")
    result = D.estimate_rate_limit_wait_seconds(p)
    assert result == 120
    p.unlink()


def test_estimate_retry_after_minutes():
    p = _write_log("Error 429. try again in 5 minutes")
    result = D.estimate_rate_limit_wait_seconds(p)
    assert result == 300
    p.unlink()


def test_estimate_no_hint():
    """No parseable time hint → None (caller defaults to 300)."""
    p = _write_log("Error 429. Please wait.")
    result = D.estimate_rate_limit_wait_seconds(p)
    assert result is None
    p.unlink()


def test_failure_diagnosis_paid_claude_opt_in_still_uses_local_result(tmp_path):
    """A legacy paid opt-in cannot launch the disabled direct Claude path."""
    (tmp_path / "_stdio_breadth.attempt2.log").write_text(
        "timed out after 3600s\n", encoding="utf-8"
    )
    (tmp_path / "_prompt_breadth.attempt2.md").write_text(
        "prompt", encoding="utf-8"
    )

    with patch.object(
        display.subprocess, "Popen",
        side_effect=AssertionError("direct provider spawn is disabled"),
    ), patch.object(
        display, "_find_claude_bin",
        side_effect=AssertionError("ambient provider discovery is disabled"),
    ):
        display.print_failure_diagnosis(
            "breadth",
            str(tmp_path),
            ["analysis_token_flow.md"],
            {"pipeline": "sc", "mode": "thorough", "language": "evm",
             "allow_paid_failure_diagnosis": True},
        )

    out = (tmp_path / "_diagnosis_breadth.md").read_text(encoding="utf-8")
    assert "### What Happened" in out
    assert "deterministic local diagnosis" in out
    assert "canonical contained provider" in out
    assert "TIMEOUT" in out


def test_failure_diagnosis_paid_codex_opt_in_still_uses_local_result(tmp_path):
    """A legacy paid opt-in cannot launch the disabled direct Codex path."""
    (tmp_path / "_stdio_depth.attempt2.log").write_text(
        "missing never_cut_checkpoint.md\n", encoding="utf-8"
    )
    (tmp_path / "_prompt_depth.attempt2.md").write_text(
        "prompt", encoding="utf-8"
    )

    with patch.object(
        display.subprocess, "Popen",
        side_effect=AssertionError("direct provider spawn is disabled"),
    ), patch.object(
        display, "_find_codex_bin",
        side_effect=AssertionError("ambient provider discovery is disabled"),
    ):
        display.print_failure_diagnosis(
            "depth",
            str(tmp_path),
            ["depth_exit.md"],
            {
                "pipeline": "sc",
                "mode": "thorough",
                "language": "evm",
                "cli_backend": "codex",
                "allow_paid_failure_diagnosis": True,
            },
        )

    out = (tmp_path / "_diagnosis_depth.md").read_text(encoding="utf-8")
    assert "### What Happened" in out
    assert "deterministic local diagnosis" in out
    assert "canonical contained provider" in out
    assert "depth_exit.md" in out


def test_failure_diagnosis_never_starts_process_for_second_esc_to_cancel(tmp_path):
    """Local diagnosis has no advisory child process for a second Esc to cancel."""
    (tmp_path / "_stdio_depth.attempt2.log").write_text(
        "missing depth_token_flow_findings.md\n", encoding="utf-8"
    )
    (tmp_path / "_prompt_depth.attempt2.md").write_text("prompt", encoding="utf-8")

    with patch.object(
        display.subprocess, "Popen",
        side_effect=AssertionError("direct provider spawn is disabled"),
    ), patch.object(
        display, "_find_claude_bin",
        side_effect=AssertionError("ambient provider discovery is disabled"),
    ):
        display.print_failure_diagnosis(
            "depth",
            str(tmp_path),
            ["depth_token_flow_findings.md"],
            {"pipeline": "sc", "mode": "thorough", "language": "evm",
             "allow_paid_failure_diagnosis": True},
        )

    out = (tmp_path / "_diagnosis_depth.md").read_text(encoding="utf-8")
    assert "deterministic local diagnosis" in out
    assert "canonical contained provider" in out


def test_estimate_missing_file():
    p = Path(tempfile.mktemp(suffix=".log"))
    result = D.estimate_rate_limit_wait_seconds(p)
    assert result is None


# ─── rate_limit_wait_interactive ───────────────────────────────────────


def test_rate_limit_interactive_countdown_expires():
    """Short countdown expires naturally → returns False."""
    old = display.graceful_stop.requested
    display.graceful_stop.requested = False
    try:
        result = display.rate_limit_wait_interactive(2, "test_phase")
        assert result is False
    finally:
        display.graceful_stop.requested = old


def test_rate_limit_interactive_halt_interrupts():
    """Setting halt during countdown → raises KeyboardInterrupt."""
    old = display.graceful_stop.requested
    display.graceful_stop.requested = False

    def _trigger():
        time.sleep(0.5)
        display.graceful_stop.requested = True

    t = threading.Thread(target=_trigger, daemon=True)
    t.start()

    try:
        display.rate_limit_wait_interactive(30, "test_phase")
        assert False, "Should have raised KeyboardInterrupt"
    except KeyboardInterrupt:
        pass
    finally:
        display.graceful_stop.requested = old


# ─── _extract_json_envelope ────────────────────────────────────────────


def test_extract_envelope_valid():
    """Well-formed JSON at end of log → parsed."""
    data = {"is_error": False, "stop_reason": "end_turn", "cost": 0.05}
    tail = f"lots of text\n{json.dumps(data)}\n"
    result = D._extract_json_envelope(tail)
    assert result == data


def test_extract_envelope_prefers_stream_result_before_trailing_progress():
    result_event = {
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "stop_reason": "end_turn",
        "total_cost_usd": 0.05,
    }
    trailing = {
        "type": "prompt_suggestion",
        "suggestion": "continue",
    }
    tail = "\n".join(
        (
            json.dumps({"type": "system", "subtype": "init"}),
            json.dumps(result_event),
            json.dumps(trailing),
            "",
        )
    )
    assert D._extract_json_envelope(tail) == result_event


def test_extract_envelope_missing():
    """No JSON in log → None."""
    result = D._extract_json_envelope("just plain text\nno json here\n")
    assert result is None


def test_extract_envelope_malformed():
    """Truncated JSON → None."""
    result = D._extract_json_envelope('{"is_error": true, "incomplete')
    assert result is None
