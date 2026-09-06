import io
import inspect
import json
import sys
import time
import concurrent.futures
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pty_exec import (  # noqa: E402
    ClaudePtySession,
    claude_transcript_path,
    encode_claude_project_dir,
    event_is_rate_limited,
    inspect_transcript,
    parse_transcript_usage,
    text_shows_rate_limit,
    transcript_shows_compaction,
)
import plamen_driver as D  # noqa: E402


def _write_jsonl(path: Path, *events: dict) -> None:
    path.write_text(
        "".join(json.dumps(e) + "\n" for e in events),
        encoding="utf-8",
    )


def _assistant(stop_reason: str, text: str = "", usage: dict | None = None) -> dict:
    content = [{"type": "text", "text": text}] if text else [
        {"type": "tool_use", "name": "Read", "id": "toolu_1", "input": {}}
    ]
    return {
        "type": "assistant",
        "message": {
            "role": "assistant",
            "content": content,
            "stop_reason": stop_reason,
            "usage": usage or {},
        },
    }


def test_project_dir_encoding_matches_local_claude_shape():
    encoded = encode_claude_project_dir(r"C:\Users\tester\.claude")
    assert encoded.endswith("C--Users-tester--claude")


def test_project_dir_encoding_converts_underscore_to_hyphen(tmp_path):
    """Claude Code's slugifier converts `_` to `-` (keep-class is
    [A-Za-z0-9-], no underscore). A two-word underscore path segment must map
    to the hyphenated form, matching the on-disk projects dir."""
    p = tmp_path / "foo_bar" / "baz_qux"
    p.mkdir(parents=True)
    encoded = encode_claude_project_dir(p)
    assert "_" not in encoded
    assert encoded.endswith("foo-bar-baz-qux")


def test_transcript_path_self_heals_via_session_id_glob(tmp_path):
    """When the encoded primary path does NOT exist but the
    `{session_id}.jsonl` file exists under a DIFFERENT projects subdir, the
    single-match glob resolves it to the real file."""
    home = tmp_path / ".claude"
    session_id = "11111111-2222-3333-4444-555555555555"
    # Real transcript lives under SOME projects subdir whose slug differs from
    # the one the primary candidate would encode for the given cwd (simulating
    # a slug-encoding divergence). Use a short manual slug to stay within
    # Windows path limits.
    real_dir = home / "projects" / "real-on-disk-slug"
    real_dir.mkdir(parents=True)
    real_file = real_dir / f"{session_id}.jsonl"
    real_file.write_text("{}\n", encoding="utf-8")

    # cwd encodes to a primary candidate dir that does NOT exist on disk.
    cwd = tmp_path / "proj_underscore" / "src"
    cwd.mkdir(parents=True)
    primary = (
        home / "projects" / encode_claude_project_dir(cwd) / f"{session_id}.jsonl"
    )
    assert not primary.exists()

    resolved = claude_transcript_path(session_id, cwd, home)
    assert resolved == real_file
    assert resolved.exists()


def test_transcript_path_returns_primary_when_glob_ambiguous(tmp_path):
    """Zero or two glob matches => return the primary encoded candidate
    unchanged (no guessing)."""
    home = tmp_path / ".claude"
    session_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    cwd = tmp_path / "proj" / "src"
    cwd.mkdir(parents=True)
    primary = (
        home / "projects" / encode_claude_project_dir(cwd) / f"{session_id}.jsonl"
    )

    # Zero matches: primary does not exist, no file anywhere -> primary.
    assert claude_transcript_path(session_id, cwd, home) == primary

    # Two matches: ambiguous -> still primary unchanged.
    d1 = home / "projects" / "slug-one"
    d2 = home / "projects" / "slug-two"
    d1.mkdir(parents=True)
    d2.mkdir(parents=True)
    (d1 / f"{session_id}.jsonl").write_text("{}\n", encoding="utf-8")
    (d2 / f"{session_id}.jsonl").write_text("{}\n", encoding="utf-8")
    assert claude_transcript_path(session_id, cwd, home) == primary


def test_inspect_transcript_does_not_complete_on_mid_tool_loop(tmp_path):
    transcript = tmp_path / "session.jsonl"
    _write_jsonl(transcript, _assistant("tool_use"))

    state = inspect_transcript(transcript)

    assert state.complete is False
    assert state.line_count == 1


def test_inspect_transcript_completes_on_end_turn_and_records_done(tmp_path):
    transcript = tmp_path / "session.jsonl"
    _write_jsonl(
        transcript,
        _assistant("tool_use"),
        {"type": "user", "message": {"role": "user", "content": "tool result"}},
        _assistant("end_turn", "DONE: recon_summary.md written"),
    )

    state = inspect_transcript(transcript)

    assert state.complete is True
    assert state.done_seen is True


def test_stub_artifact_without_end_turn_is_not_completion_signal(tmp_path):
    (tmp_path / "analysis_1.md").write_text("# reserved\n", encoding="utf-8")
    transcript = tmp_path / "session.jsonl"
    _write_jsonl(transcript, _assistant("tool_use"))

    state = inspect_transcript(transcript)

    assert state.complete is False


def test_wait_for_turn_complete_timeout_without_transcript(tmp_path):
    session = ClaudePtySession(
        ["claude"],
        cwd=tmp_path,
        env={},
        session_id="missing",
        prompt_path=tmp_path / "prompt.md",
        log_file=io.StringIO(),
        claude_home=tmp_path,
    )
    session.is_alive = lambda: True  # type: ignore[method-assign]

    start = time.time()
    state = session.wait_for_turn_complete(timeout_s=0.1, quiescence_s=0.01, poll_s=0.01)

    assert state.complete is False
    assert time.time() - start < 1.0


def test_parse_transcript_usage_accumulates_assistant_usage(tmp_path):
    transcript = tmp_path / "session.jsonl"
    _write_jsonl(
        transcript,
        _assistant(
            "tool_use",
            usage={
                "input_tokens": 1,
                "output_tokens": 2,
                "cache_read_input_tokens": 3,
                "cache_creation_input_tokens": 4,
            },
        ),
        _assistant(
            "end_turn",
            "DONE: complete",
            usage={
                "input_tokens": 10,
                "output_tokens": 20,
                "cache_read_input_tokens": 30,
                "cache_creation_input_tokens": 40,
            },
        ),
    )

    usage = parse_transcript_usage(transcript)

    assert usage["num_turns"] == 1
    assert usage["input_tokens"] == 11
    assert usage["output_tokens"] == 22
    assert usage["cache_read_input_tokens"] == 33
    assert usage["cache_creation_input_tokens"] == 44


def test_transcript_shows_compaction_from_claude_ui_markers(tmp_path):
    log = tmp_path / "stdio.log"
    log.write_text(
        "13% until auto-compact\nConversation compacted (ctrl+o for history)\n",
        encoding="utf-8",
    )

    assert transcript_shows_compaction(log) is True


def test_driver_rate_limit_detection_accepts_claude_session_jsonl(tmp_path):
    log = tmp_path / "stdio.log"
    _write_jsonl(
        log,
        {
            "type": "assistant",
            "message": {
                "role": "assistant",
                "stop_reason": "rate_limited",
                "content": [],
            },
        },
    )

    assert D.detect_rate_limit(log) is True


def test_claude_pty_usage_cap_json_shape_is_rate_limited():
    event = {
        "type": "assistant",
        "apiErrorStatus": 429,
        "error": "rate_limit",
        "message": {
            "content": [
                {
                    "type": "text",
                    "text": "You've hit your weekly limit · resets May 30, 6am",
                }
            ],
        },
    }

    assert event_is_rate_limited(event) is True


def test_claude_pty_rate_limit_accepts_string_status_codes():
    for key in ("api_error_status", "apiErrorStatus", "status"):
        event = {
            "type": "assistant",
            key: "429",
            "message": {"content": []},
        }
        assert event_is_rate_limited(event) is True


@pytest.mark.parametrize("status", ["allowed", "allowed_warning"])
def test_claude_rate_limit_telemetry_does_not_trigger_replay(
    tmp_path, status
):
    event = {
        "type": "rate_limit_event",
        "rate_limit_info": {
            "status": status,
            "resetsAt": 1788452400,
            "rateLimitType": "five_hour",
        },
    }
    log = tmp_path / "stdio.log"
    _write_jsonl(log, event, {"type": "result", "subtype": "success"})

    assert event_is_rate_limited(event) is False
    assert D.detect_rate_limit(log) is False


def test_claude_rejected_rate_limit_telemetry_triggers_replay(tmp_path):
    event = {
        "type": "rate_limit_event",
        "rate_limit_info": {
            "status": "rejected",
            "resetsAt": 1788452400,
            "rateLimitType": "five_hour",
        },
    }
    log = tmp_path / "stdio.log"
    _write_jsonl(log, event)

    assert event_is_rate_limited(event) is True
    assert D.detect_rate_limit(log) is True


def test_claude_pty_usage_cap_screen_text_is_rate_limited(tmp_path):
    log = tmp_path / "stdio.log"
    log.write_text(
        "\x1b[5GYou've hit your weekly limit · resets May 30, 6am\n"
        "\x1b[5G3. Switch to Team plan\n",
        encoding="utf-8",
    )

    assert text_shows_rate_limit(log.read_text(encoding="utf-8")) is True
    assert D.detect_rate_limit(log) is True


def test_protocol_rate_limiter_prose_with_line_429_is_not_rate_limited():
    """Audit content can contain "rate limiter" prose and markdown line 429."""
    event = {
        "type": "user",
        "message": {
            "role": "user",
            "content": [{
                "type": "tool_result",
                "content": (
                    "416 **Description**: If a V2 upgrade introduces a rate "
                    "limiter address, there is an exploit window.\n"
                    "429 ### Finding [INV-042]: Single-Step Ownership Transfer"
                ),
            }],
        },
    }

    assert text_shows_rate_limit(
        "rate limiter address\n429 ### Finding [INV-042]"
    ) is False
    assert event_is_rate_limited(event) is False


def test_assistant_audit_text_with_rate_limit_error_is_not_rate_limited():
    event = _assistant(
        "end_turn",
        "The audited protocol emits rate_limit_error and handles HTTP status 429.",
    )

    assert event_is_rate_limited(event) is False
    assert text_shows_rate_limit(
        "The audited protocol handles HTTP status 429 rate limit behavior."
    ) is False


def test_wait_for_turn_complete_ignores_live_protocol_rate_limit_output(tmp_path):
    session = ClaudePtySession(
        ["claude"],
        cwd=tmp_path,
        env={},
        session_id="live-protocol-rate-limit",
        prompt_path=tmp_path / "prompt.md",
        log_file=io.StringIO(),
        claude_home=tmp_path,
    )
    session.is_alive = lambda: True  # type: ignore[method-assign]
    with session._recent_output_lock:
        session._recent_output = "Protocol test: HTTP status 429 rate limit handling"

    state = session.wait_for_turn_complete(
        timeout_s=0.05,
        quiescence_s=0.01,
        poll_s=0.01,
        transcript_poll_s=0.01,
    )

    assert state.rate_limited is False


def test_wait_for_turn_complete_detects_live_usage_cap_output(tmp_path):
    session = ClaudePtySession(
        ["claude"],
        cwd=tmp_path,
        env={},
        session_id="live-cap",
        prompt_path=tmp_path / "prompt.md",
        log_file=io.StringIO(),
        claude_home=tmp_path,
    )
    session.is_alive = lambda: True  # type: ignore[method-assign]
    with session._recent_output_lock:
        session._recent_output = "You've hit your weekly limit · resets May 30, 6am"

    state = session.wait_for_turn_complete(
        timeout_s=2,
        quiescence_s=0.01,
        poll_s=0.01,
        transcript_poll_s=0.01,
    )

    assert state.rate_limited is True


def test_checkpoint_mark_completed_clears_matching_rate_limit_marker():
    cp = D.Checkpoint(completed=[], degraded=[], rate_limited_at="depth")

    cp.mark_completed("depth")

    assert cp.rate_limited_at is None


def test_worker_pool_halt_terminates_registered_active_sessions():
    class DummySession:
        def __init__(self):
            self.terminated = False
            self.grace_s = None

        def terminate(self, grace_s=5.0):
            self.terminated = True
            self.grace_s = grace_s

    class DummyExecutor:
        def __init__(self):
            self.shutdown_args = None

        def shutdown(self, wait=True, cancel_futures=False):
            self.shutdown_args = (wait, cancel_futures)

    session = DummySession()
    future = concurrent.futures.Future()
    executor = DummyExecutor()

    D._register_active_worker_session(session)
    try:
        D._cancel_pending_worker_futures({future}, executor)  # type: ignore[arg-type]
    finally:
        D._unregister_active_worker_session(session)

    assert session.terminated is True
    assert future.cancelled() is True
    assert executor.shutdown_args == (True, True)


def test_worker_pool_context_exit_waits_until_running_future_is_terminal():
    release = threading.Event()

    def _blocked():
        release.wait(timeout=5)

    timer = threading.Timer(0.15, release.set)
    timer.start()
    start = time.time()
    try:
        with pytest.raises(RuntimeError, match="abort pool"):
            with D._JoiningWorkerPool(max_workers=1) as executor:
                executor.submit(_blocked)
                raise RuntimeError("abort pool")
        assert time.time() - start >= 0.10
    finally:
        release.set()
        timer.cancel()


def test_worker_pool_cancellation_token_reaches_started_worker_before_join():
    started = threading.Event()
    observed_cancel = threading.Event()

    def _worker():
        token = D._current_worker_cancel_token()
        assert token is not None
        started.set()
        assert token.wait(timeout=2)
        observed_cancel.set()

    executor = D._JoiningWorkerPool(max_workers=1)
    future = executor.submit(_worker)
    assert started.wait(timeout=1)
    D._cancel_pending_worker_futures({future}, executor)

    assert future.done()
    assert observed_cancel.is_set()


def test_posix_pty_spawn_uses_popen_not_raw_fork_waitpid():
    """POSIX PTY launch must not use raw pty.fork()+waitpid.

    Launching from inside Claude Code can inherit parent process signal state;
    Popen ownership plus SIGCHLD reset is the durable path for macOS/Linux.
    """
    spawn_src = inspect.getsource(ClaudePtySession.spawn)
    alive_src = inspect.getsource(ClaudePtySession.is_alive)

    assert "pty.fork()" not in spawn_src
    assert "subprocess.Popen" in spawn_src
    assert "signal.SIGCHLD" in spawn_src
    assert "os.waitpid" not in alive_src
    assert ".poll()" in alive_src
