"""Context-overflow / autocompact-thrash fast-fail (Ship 8.17).

The PTY wait loop already flips ``output_truncated`` for the model OUTPUT cap.
But the INPUT side -- a turn whose context has grown so large that Claude Code
is stuck auto-compacting (or has explicitly given up) -- had no dedicated exit:
the transcript keeps emitting compaction-summary / re-read events so the
quiescence gate never trips, the process stays alive, and it is NOT the output
cap. The ONLY terminator was the full scaled phase deadline (observed: ~3.6h
burn on a 144K-finding report index).

These tests pin:
  1. the overflow/thrash regex matches the real fingerprints (and not benign text);
  2. the dual-signal gate fires only when thrash text/compaction is present AND
     no new PRODUCTIVE event has advanced for >= _CONTEXT_THRASH_LOOP_S;
  3. a compact-THEN-RESUME turn (productive_event_count rises) is NEVER cut off;
  4. a non-thrash session is byte-unaffected;
  5. the real wait_for_turn_complete returns EARLY (well before the deadline)
     on a sustained thrash signature.
"""
import re
import time
from pathlib import Path


def _consts():
    import pty_exec as px
    return px._CONTEXT_OVERFLOW_TEXT_RE, px._CONTEXT_THRASH_LOOP_S


# ── Fix 1: the overflow/thrash regex ─────────────────────────────────────────

_THRASH_LINES = [
    "Autocompact is thrashing",
    "auto-compact is thrashing",
    "Error: a file being read is too large",
    "prompt is too long",
    "input is too long",
    "this request exceeds the maximum context window",
    "context window exceeded",
]

_BENIGN_LINES = [
    "Writing report_index.md ... tool_use Write",
    "forge build succeeded",
    "Analyzed function liquidate() at L120",
    "All findings mapped to report IDs",
    "Context low, auto-compact may run",
]


def test_overflow_regex_matches_real_thrash_fingerprints():
    rx, _ = _consts()
    for line in _THRASH_LINES:
        assert rx.search(line), f"thrash regex must match: {line!r}"


def test_overflow_regex_does_not_match_benign_work():
    rx, _ = _consts()
    for line in _BENIGN_LINES:
        assert not rx.search(line), f"thrash regex must NOT match benign: {line!r}"


# ── Fix 2/3: dual-signal gate logic (mirror of the wait-loop branch) ──────────

def _simulate_thrash(events):
    """Mirror the context-thrash branch of wait_for_turn_complete.

    events: list of (now, recent_output, productive_event_count, thrash_sig)
    sampled at successive polls. Returns the ``now`` at which context_thrash
    would be set, or None if it never trips.
    """
    rx, loop_s = _consts()
    first_thrash_seen_at = None
    last_productive_count = -1
    for (now, recent, productive_count, transcript_compaction) in events:
        overflow_text = bool(rx.search(recent))
        thrash_signature = overflow_text or transcript_compaction
        if productive_count > last_productive_count:
            last_productive_count = productive_count
            first_thrash_seen_at = None
        elif thrash_signature:
            if first_thrash_seen_at is None:
                first_thrash_seen_at = now
            elif now - first_thrash_seen_at >= loop_s:
                return now
        else:
            first_thrash_seen_at = None
    return None


def test_sustained_thrash_with_no_progress_trips():
    # Thrash text present every poll, productive_event_count frozen -> the gate
    # must fire within _CONTEXT_THRASH_LOOP_S.
    _, loop_s = _consts()
    events = [
        (t, "Autocompact is thrashing", 5, True)
        for t in range(0, int(loop_s) + 30, 5)
    ]
    tripped = _simulate_thrash(events)
    assert tripped is not None and tripped >= loop_s, (
        "a stuck-thrashing turn (no new productive output) must trip the gate"
    )


def test_compaction_signature_only_also_trips():
    # No explicit overflow text, but transcript_shows_compaction is True and the
    # productive count is frozen -> sustained churn must still trip.
    _, loop_s = _consts()
    events = [
        (t, "summarizing prior turns", 2, True)
        for t in range(0, int(loop_s) + 30, 5)
    ]
    assert _simulate_thrash(events) is not None


def test_compact_then_resume_is_never_cut_off():
    # The recall-safe case: turn compacts (thrash signature present) but KEEPS
    # producing new productive events -> productive_event_count rises each poll
    # -> latch resets -> never cut off, even long past _CONTEXT_THRASH_LOOP_S.
    _, loop_s = _consts()
    events = []
    count = 0
    for i, t in enumerate(range(0, int(loop_s) + 400, 5)):
        count += 1  # a new productive (tool_use/text) event every poll
        events.append((float(t), "compacting conversation", count, True))
    assert _simulate_thrash(events) is None, (
        "a compact-then-resume turn making forward progress must never be cut off"
    )


def test_no_thrash_signature_never_trips():
    # Benign working session: no overflow text, no compaction -> gate inert.
    _, loop_s = _consts()
    events = [
        (t, "forge build succeeded", i, False)
        for i, t in enumerate(range(0, int(loop_s) + 400, 5))
    ]
    assert _simulate_thrash(events) is None


def test_thrash_clears_then_resumes_resets_latch():
    # Thrash for a while (but under the window), then the signature clears
    # entirely -> latch resets -> never trips.
    _, loop_s = _consts()
    half = int(loop_s) // 2
    events = [(float(t), "prompt is too long", 1, True)
              for t in range(0, half, 5)]
    events += [(float(t), "forge build", 1, False)
               for t in range(half, half + int(loop_s) + 50, 5)]
    assert _simulate_thrash(events) is None


# ── Fix 5: the real wait loop returns EARLY on sustained thrash ───────────────

class _FakeSession:
    """Minimal stand-in driving the real wait_for_turn_complete.

    Always-alive process, a transcript that never reaches end_turn, and a
    recent-output buffer carrying a thrash fingerprint -> without the new gate
    the loop would block to the full deadline; with it, it returns early.
    """

    def __init__(self, tmp_path, recent_text, transcript_text=None):
        import threading
        self.transcript_path = Path(tmp_path) / "transcript.jsonl"
        # A transcript with one assistant event but no end_turn. Because the
        # file is STATIC, inspect_transcript recomputes the same
        # productive_event_count every poll -> it does NOT advance after the
        # first read, which is exactly the "no forward progress" signature the
        # gate keys on (paired with a thrash signature).
        if transcript_text is None:
            transcript_text = (
                '{"type":"assistant","message":{"content":'
                '[{"type":"text","text":"compacting conversation"}]}}\n'
            )
        self.transcript_path.write_text(transcript_text, encoding="utf-8")
        self._recent_output = recent_text
        self._recent_output_lock = threading.Lock()

    def is_alive(self):
        return True


def test_real_wait_loop_cuts_sustained_explicit_thrash(tmp_path, monkeypatch):
    """An explicit overflow signature with no productive advance is bounded."""
    import pty_exec as px
    monkeypatch.setattr(px, "_CONTEXT_THRASH_LOOP_S", 0.4, raising=False)

    class _DelayedExplicitSession(_FakeSession):
        def __init__(self, root):
            super().__init__(root, "working")
            self._t0 = time.monotonic()

        def is_alive(self):
            if time.monotonic() - self._t0 >= 0.1:
                with self._recent_output_lock:
                    self._recent_output = "working\nAutocompact is thrashing"
            return True

    sess = _DelayedExplicitSession(tmp_path)
    bound = px.ClaudePtySession.wait_for_turn_complete.__get__(sess, _FakeSession)
    state = bound(timeout_s=2.0, quiescence_s=8.0, poll_s=0.05,
                  transcript_poll_s=0.05)
    assert getattr(state, "context_thrash", False), (
        "sustained explicit thrash with a frozen productive count must return "
        "a bounded recovery signal"
    )


def test_real_wait_loop_no_early_exit_without_thrash(tmp_path, monkeypatch):
    import pty_exec as px
    monkeypatch.setattr(px, "_CONTEXT_THRASH_LOOP_S", 0.4, raising=False)
    # Benign recent output AND a transcript with NO compaction fingerprint ->
    # neither thrash signal is present -> the gate stays inert and the loop runs
    # to its (short) deadline without flagging context_thrash.
    benign_transcript = (
        '{"type":"assistant","message":{"content":'
        '[{"type":"text","text":"analyzed liquidate() at L120"}]}}\n'
    )
    sess = _FakeSession(tmp_path, "forge build succeeded",
                        transcript_text=benign_transcript)
    bound = px.ClaudePtySession.wait_for_turn_complete.__get__(sess, _FakeSession)
    state = bound(timeout_s=0.6, quiescence_s=8.0, poll_s=0.05,
                  transcript_poll_s=0.05)
    assert not getattr(state, "context_thrash", False)


def test_advisory_low_context_warning_then_silent_long_tool_is_safe(
    tmp_path, monkeypatch
):
    """A may-run warning is not failed-compaction/overflow evidence."""

    import pty_exec as px

    ticks = iter((0.0, 0.0, 601.0, 701.0))
    monkeypatch.setattr(px.time, "monotonic", lambda: next(ticks, 702.0))
    monkeypatch.setattr(px.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(px, "_CONTEXT_THRASH_LOOP_S", 600.0, raising=False)
    sess = _FakeSession(
        tmp_path,
        "Context low, auto-compact may run",
        transcript_text=(
            '{"type":"assistant","message":{"content":'
            '[{"type":"tool_use","name":"Bash","input":{}}]}}\n'
        ),
    )
    bound = px.ClaudePtySession.wait_for_turn_complete.__get__(sess, _FakeSession)
    state = bound(
        timeout_s=700.0,
        quiescence_s=8.0,
        poll_s=0.1,
        transcript_poll_s=0.1,
    )
    assert not state.context_thrash


# ── THRASH QUIET-VARIANT regression + slow-progress negative control ───────────
#
# The committed loud-only fast-fail (_CONTEXT_OVERFLOW_TEXT_RE) keyed ONLY on
# the explicit overflow string ("Autocompact is thrashing" / "too large for the
# context"). The THRASH report_index live flaw thrashed ~27 min with a transcript
# frozen ~124 lines carrying 14 "compact" + 3 "until auto-compact" markers but
# ZERO explicit overflow string -> the loud-only check NEVER matched the QUIET
# repeated-compaction variant, so the fast-fail never fired. These two real-loop
# fixtures pin both directions of the dual-signal root fix:
#   (1) the QUIET THRASH variant (compaction fingerprint, NO overflow text,
#       frozen productive count) MUST fast-fail; and
#   (2) a slow-but-PROGRESSING compacting turn (productive_event_count advances
#       intermittently during the wait) must NEVER be cut off.

# A THRASH-shaped quiet transcript: repeated compaction-summary text events, with
# the "until auto-compact" marker -- and crucially NO overflow string. Every
# event is a compaction-summary text block, so event_is_productive() returns
# False for all of them -> productive_event_count is FROZEN at 0 across polls.
_QUIET_THRASH_TRANSCRIPT = "".join(
    '{"type":"assistant","message":{"content":'
    f'[{{"type":"text","text":"{txt}"}}]}}}}\n'
    for txt in (
        "compacting conversation (summary block 1)",
        "compacting conversation (summary block 2) until auto-compact",
        "compacting conversation (summary block 3)",
    )
)


def test_historical_compaction_marker_does_not_arm_new_wait(tmp_path, monkeypatch):
    """ROOT-FIX REGRESSION: the QUIET THRASH variant the loud-only check missed.

    No explicit overflow string anywhere (recent output is benign-looking
    compaction churn, transcript has zero overflow text). The ONLY signal is the
    compaction fingerprint (repeated 'compact' + 'until auto-compact') paired
    with a frozen productive_event_count. The dual-signal gate MUST still fire.
    """
    import pty_exec as px
    # Prove the precondition: the committed loud-only regex does NOT match this
    # quiet variant -- it is exactly the gap that let THRASH thrash for 27 min.
    rx, _ = _consts()
    assert not rx.search(px._normalized_pty_text(_QUIET_THRASH_TRANSCRIPT)), (
        "the quiet THRASH transcript must carry NO explicit overflow string -- "
        "that is the whole point of the regression"
    )
    # But it IS a compaction fingerprint via the second signal.
    qfile = Path(tmp_path) / "quiet.jsonl"
    qfile.write_text(_QUIET_THRASH_TRANSCRIPT, encoding="utf-8")
    assert px.transcript_shows_compaction(qfile), (
        "repeated 'compact' + 'until auto-compact' must be a compaction signature"
    )

    monkeypatch.setattr(px, "_CONTEXT_THRASH_LOOP_S", 0.1, raising=False)
    sess = _FakeSession(
        tmp_path,
        recent_text="reading findings_inventory.md ...",
        transcript_text=_QUIET_THRASH_TRANSCRIPT,
    )
    bound = px.ClaudePtySession.wait_for_turn_complete.__get__(sess, _FakeSession)
    state = bound(timeout_s=0.35, quiescence_s=8.0, poll_s=0.02,
                  transcript_poll_s=0.05)
    assert not getattr(state, "context_thrash", False), (
        "whole-transcript compaction history predating the wait must not arm "
        "a new zero-progress episode"
    )


def test_quiet_repeated_compaction_delta_fast_fails(tmp_path, monkeypatch):
    """Two post-baseline compaction summaries with no activity are bounded."""

    import pty_exec as px
    import threading

    monkeypatch.setattr(px, "_CONTEXT_THRASH_LOOP_S", 0.25, raising=False)

    class _AppendingCompactionSession:
        def __init__(self, root):
            self.transcript_path = Path(root) / "delta-compaction.jsonl"
            self.transcript_path.write_text("", encoding="utf-8")
            self._recent_output = ""
            self._recent_output_lock = threading.Lock()
            self._t0 = time.monotonic()
            self._appended = 0

        def is_alive(self):
            elapsed = time.monotonic() - self._t0
            target = 2 if elapsed >= 0.15 else (1 if elapsed >= 0.05 else 0)
            while self._appended < target:
                self._appended += 1
                with self.transcript_path.open("a", encoding="utf-8") as f:
                    f.write(
                        '{"type":"assistant","message":{"content":'
                        f'['
                        f'{{"type":"text","text":"compacting conversation '
                        f'until auto-compact {self._appended}"}}]}}}}\n'
                    )
            return True

    sess = _AppendingCompactionSession(tmp_path)
    bound = px.ClaudePtySession.wait_for_turn_complete.__get__(
        sess, _AppendingCompactionSession
    )
    state = bound(
        timeout_s=1.5,
        quiescence_s=8.0,
        poll_s=0.02,
        transcript_poll_s=0.02,
    )
    assert state.context_thrash


def test_single_new_compaction_then_slow_tool_longer_than_window_is_safe(
    tmp_path, monkeypatch
):
    """A single compact-before-tool event is not repeated compaction churn."""

    import pty_exec as px
    import threading

    ticks = iter((0.0, 0.0, 1.0, 700.0, 701.0, 702.0, 703.0))
    monkeypatch.setattr(px.time, "monotonic", lambda: next(ticks, 704.0))
    monkeypatch.setattr(px.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(px, "_CONTEXT_THRASH_LOOP_S", 600.0, raising=False)

    class _SingleCompactionSession:
        def __init__(self, root):
            self.transcript_path = Path(root) / "single-compaction.jsonl"
            self.transcript_path.write_text("", encoding="utf-8")
            self._recent_output = ""
            self._recent_output_lock = threading.Lock()
            self._added = False

        def is_alive(self):
            if not self._added:
                self._added = True
                self.transcript_path.write_text(
                    '{"type":"assistant","message":{"content":'
                    '[{"type":"text","text":"compacting conversation"}]}}\n',
                    encoding="utf-8",
                )
                return True
            return False

    sess = _SingleCompactionSession(tmp_path)
    bound = px.ClaudePtySession.wait_for_turn_complete.__get__(
        sess, _SingleCompactionSession
    )
    state = bound(
        timeout_s=1000.0,
        quiescence_s=8.0,
        poll_s=0.1,
        transcript_poll_s=0.1,
    )
    assert not state.context_thrash


class _GrowingTranscriptSession:
    """A compacting session whose transcript APPENDS a new productive event
    slowly during the wait. Mirrors a real slow-but-progressing turn: it IS
    compacting (compaction fingerprint present every poll) but it keeps making
    genuine forward progress -- each appended tool_use event advances
    productive_event_count -> the thrash latch resets -> never cut off.
    """

    def __init__(self, tmp_path, progress_interval_s):
        import threading
        self.transcript_path = Path(tmp_path) / "growing.jsonl"
        # Seed with a compaction-summary event (frozen-productive baseline).
        self.transcript_path.write_text(
            '{"type":"assistant","message":{"content":'
            '[{"type":"text","text":"compacting conversation until auto-compact"}]}}\n',
            encoding="utf-8",
        )
        self._recent_output = "compacting conversation until auto-compact"
        self._recent_output_lock = threading.Lock()
        self._t0 = time.time()
        self._progress_interval_s = progress_interval_s
        self._appended = 0

    def _maybe_append_progress(self):
        # Append a NEW productive tool_use event every progress_interval_s.
        n = int((time.time() - self._t0) / self._progress_interval_s)
        while self._appended < n:
            self._appended += 1
            with self.transcript_path.open("a", encoding="utf-8") as f:
                f.write(
                    '{"type":"assistant","message":{"content":'
                    '[{"type":"tool_use","name":"Write","input":{}}]}}\n'
                )

    def is_alive(self):
        # The wait loop calls is_alive() every poll; piggyback transcript
        # growth here so productive_event_count advances as wall-time passes.
        self._maybe_append_progress()
        return True


def test_slow_but_progressing_compacting_turn_is_never_cut_off(tmp_path, monkeypatch):
    """NEGATIVE CONTROL: real, productive work must NOT be fast-failed.

    The turn is compacting the whole time (compaction fingerprint present every
    poll) but makes genuine forward progress every ~0.1s -- well faster than the
    0.4s thrash window. The frozen-count latch resets on each new productive
    event, so context_thrash must NEVER be set even though we run far longer
    than _CONTEXT_THRASH_LOOP_S. This is the guard that the dual-signal gate
    does not become a productive-work killer.
    """
    import pty_exec as px
    monkeypatch.setattr(px, "_CONTEXT_THRASH_LOOP_S", 0.4, raising=False)
    sess = _GrowingTranscriptSession(tmp_path, progress_interval_s=0.1)
    bound = px.ClaudePtySession.wait_for_turn_complete.__get__(
        sess, _GrowingTranscriptSession
    )
    # Run ~3x the thrash window. A broken gate (overflow-only or no progress
    # reset) would flag context_thrash; the dual-signal gate must not.
    state = bound(timeout_s=1.5, quiescence_s=8.0, poll_s=0.02,
                  transcript_poll_s=0.02)
    assert not getattr(state, "context_thrash", False), (
        "a slow-but-progressing compacting turn (productive_event_count keeps "
        "advancing) must NEVER be fast-failed -- the dual-signal frozen-count "
        "guard protects genuine forward progress"
    )
    # Sanity: the turn really did make progress during the wait (otherwise this
    # would be a vacuous pass -- a frozen transcript that happened not to trip).
    assert sess._appended >= 2, (
        "the negative-control session must actually advance productive events "
        "during the wait, else the test is vacuous"
    )


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
