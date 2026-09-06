"""Codex usage-cap errors are NATURAL LANGUAGE, not structured tokens, and MUST
be classified as a rate-limit (auto-wait + preserve state via
checkpoint.rate_limited_at), NOT a generic phase failure that burns the retry
budget and HALTS.

Fixture = the verbatim message from a live SC Thorough Codex halt
(account out of credits, reset 5:46 PM). Before the fix the regex looked only
for structured tokens (usage_limit_reached / 429 / "type":"usage_limit") and
missed this, so the run halted instead of auto-waiting.
"""
import json
from pathlib import Path

import plamen_driver as d
from plamen_mechanical import estimate_rate_limit_wait_seconds

_REAL_USAGE_LIMIT = (
    '{"type":"thread.started","thread_id":"019e92ed-5538-74f3-80ee-5a79649d3c7a"}\n'
    '{"type":"turn.started"}\n'
    '{"type":"error","message":"You\'ve hit your usage limit. Visit '
    'https://chatgpt.com/codex/settings/usage to purchase more credits or try '
    'again at 5:46 PM."}\n'
    '{"type":"turn.failed","error":{"message":"You\'ve hit your usage limit. '
    'Visit https://chatgpt.com/codex/settings/usage to purchase more credits or '
    'try again at 5:46 PM."}}\n'
)


def _codex_rate_limit_stream(message: str) -> str:
    import json

    return "\n".join((
        json.dumps({"type": "thread.started", "thread_id": "test-thread"}),
        json.dumps({"type": "turn.started"}),
        json.dumps({"type": "error", "message": message}),
        json.dumps({"type": "turn.failed", "error": {"message": message}}),
    )) + "\n"


def _claude_rate_limit_event(*, text: str, resets_at=None) -> dict:
    event = {
        "type": "assistant",
        "message": {"content": [{"type": "text", "text": text}]},
        "quotaLimits": {"status": "rejected", "rateLimitType": "seven_day"},
        "error": "rate_limit",
        "apiErrorStatus": 429,
        "requestId": "req_test",
        "session_id": "session-test",
    }
    if resets_at is not None:
        event["quotaLimits"]["resetsAt"] = resets_at
    return event


def test_real_codex_usage_limit_is_rate_limited(tmp_path: Path):
    log = tmp_path / "_stdio_recon.attempt2.log"
    log.write_text(_REAL_USAGE_LIMIT, encoding="utf-8")
    assert d._CODEX_RATE_LIMIT_RE.search(_REAL_USAGE_LIMIT), (
        "regex must match the verbatim Codex usage-cap message"
    )
    # rc=1 (turn.failed) AND rc=0 (Codex can graceful-stop with the error
    # in-stream) both classify as rate-limited -> auto-wait, never a failure.
    assert d._detect_codex_rate_limit(log, returncode=1) is True
    assert d._detect_codex_rate_limit(log, returncode=0) is True


def test_codex_credit_phrase_variants_match():
    for msg in (
        "You've hit your usage limit.",
        "You have reached your rate limit, try again later.",
        "Please purchase more credits to continue.",
        "see https://chatgpt.com/codex/settings/usage",
    ):
        assert d._CODEX_RATE_LIMIT_RE.search(msg), f"should match: {msg!r}"


def test_codex_normal_output_not_rate_limited(tmp_path: Path):
    log = tmp_path / "_stdio_recon.attempt1.log"
    log.write_text(
        '{"type":"item.completed","item":{"type":"agent_message",'
        '"text":"Using the plamen skill; writing recon artifacts."}}\n',
        encoding="utf-8",
    )
    assert d._detect_codex_rate_limit(log, returncode=0) is False


def test_codex_auth_error_not_misclassified_as_rate_limit(tmp_path: Path):
    # Auth errors need re-auth, not backoff — the new usage-cap patterns must
    # NOT swallow a 401 into the rate-limit path.
    log = tmp_path / "_stdio_recon.attempt1.log"
    log.write_text(
        '{"type":"error","message":"401 unauthorized: invalid_api_key"}\n',
        encoding="utf-8",
    )
    assert d._detect_codex_rate_limit(log, returncode=1) is False


def test_codex_auth_detector_ignores_audited_source_inside_command_event(
    tmp_path: Path,
):
    log = tmp_path / "_stdio_depth.log"
    log.write_text(
        '{"type":"item.completed","item":{"type":"command_execution",'
        '"aggregated_output":"contract X { error Unauthorized(); }",'
        '"status":"completed"}}\n'
        '{"type":"turn.completed","usage":{"input_tokens":1}}\n',
        encoding="utf-8",
    )
    assert d._detect_codex_auth_error(log) is False


def test_codex_auth_detector_accepts_provider_error_event(tmp_path: Path):
    log = tmp_path / "_stdio_depth.log"
    log.write_text(
        '{"type":"item.completed","item":{"type":"error",'
        '"message":"HTTP 401 Unauthorized: invalid_api_key"}}\n',
        encoding="utf-8",
    )
    assert d._detect_codex_auth_error(log) is True


# --- Codex daily-cap reset-window parsing (estimate_rate_limit_wait_seconds) ---
# The verbatim Spectra-run breadth halt: a Codex usage cap whose reset is phrased
# as an ABSOLUTE date+time ("try again at <Mon> <day>, <year> <HH>:<MM> <am/pm>").
# Before the fix the estimator returned None -> caller spun a useless 5-min wait +
# burned a retry that re-hit the same cap.
_SPECTRA_USAGE_LIMIT = (
    '{"type":"turn.started"}\n'
    '{"type":"error","message":"You\'ve hit your usage limit. Upgrade to Pro '
    '(https://chatgpt.com/explore/pro), visit '
    'https://chatgpt.com/codex/settings/usage to purchase more credits or try '
    'again at Jul 11th, 2026 2:46 AM."}\n'
    '{"type":"turn.failed","error":{"message":"You\'ve hit your usage limit. '
    'Upgrade to Pro (https://chatgpt.com/explore/pro), visit '
    'https://chatgpt.com/codex/settings/usage to purchase more credits or try '
    'again at Jul 11th, 2026 2:46 AM."}}\n'
)


def test_absolute_date_reset_window_is_parsed(tmp_path: Path):
    # Time-robust: build the same Codex "try again at <Mon> <day>, <year> <time>"
    # shape as the verbatim Spectra halt, but with a date ~2 days out computed
    # from now, so the test never expires as real time passes the fixture date.
    from datetime import datetime, timedelta

    target = datetime.now().astimezone() + timedelta(days=2)
    mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][target.month - 1]
    hour12 = ((target.hour - 1) % 12) + 1
    ampm = "AM" if target.hour < 12 else "PM"
    stamp = f"{mon} {target.day}, {target.year} {hour12}:{target.minute:02d} {ampm}"
    log = tmp_path / "_stdio_breadth.log"
    message = "You've hit your usage limit. try again at " + stamp + "."
    log.write_text(_codex_rate_limit_stream(message), encoding="utf-8")
    secs = estimate_rate_limit_wait_seconds(log)
    # A concrete far-future window must be returned (not None -> not the 5-min
    # default), and it must exceed the resume threshold so the caller preserves
    # state for resume instead of spin-waiting.
    assert secs is not None, "absolute 'try again at <date> <time>' must parse"
    assert secs > d._RATE_LIMIT_RESUME_THRESHOLD_S, secs
    assert secs <= 3 * 24 * 3600, secs


def test_claude_structured_weekly_reset_epoch_is_parsed(tmp_path: Path):
    """Regression for the exact Claude Code 2.1.250 weekly-limit envelope."""
    from datetime import datetime, timedelta, timezone
    import json

    target = datetime.now(timezone.utc) + timedelta(days=2)
    log = tmp_path / "_stdio_recon.log"
    log.write_text(
        json.dumps(_claude_rate_limit_event(
            text="You've hit your weekly limit · resets Sep 2, 5am",
            resets_at=int(target.timestamp()),
        )) + "\n",
        encoding="utf-8",
    )
    secs = estimate_rate_limit_wait_seconds(log)
    assert secs is not None
    assert 47 * 3600 <= secs <= 48 * 3600
    assert secs > d._RATE_LIMIT_RESUME_THRESHOLD_S


def test_structured_reset_epoch_requires_rate_limit_evidence(tmp_path: Path):
    """Do not let arbitrary model/project JSON control the retry scheduler."""
    from datetime import datetime, timedelta, timezone
    import json

    target = datetime.now(timezone.utc) + timedelta(days=2)
    log = tmp_path / "_stdio_recon.log"
    log.write_text(
        json.dumps({
            "quotaLimits": {"status": "rejected", "resetsAt": int(target.timestamp())},
            "error": "none",
            "apiErrorStatus": 200,
        }) + "\n",
        encoding="utf-8",
    )
    assert estimate_rate_limit_wait_seconds(log) is None


def test_assistant_text_cannot_spoof_yearless_reset(tmp_path: Path):
    log = tmp_path / "_stdio_recon.log"
    log.write_text(
        '{"type":"assistant","message":"Audit note: resets Sep 2, 5am"}\n',
        encoding="utf-8",
    )
    assert estimate_rate_limit_wait_seconds(log) is None


def test_real_429_does_not_authorize_unrelated_assistant_reset(tmp_path: Path):
    """Bind reset advice to the exact provider envelope that carries the 429."""
    log = tmp_path / "_stdio_recon.log"
    log.write_text(
        '{"type":"assistant","message":"Project text: resets Dec 31, 5am"}\n'
        '{"type":"assistant","error":"rate_limit","apiErrorStatus":429}\n',
        encoding="utf-8",
    )
    assert estimate_rate_limit_wait_seconds(log) is None


def test_unframed_huge_retry_after_cannot_promote_to_long_pause(tmp_path: Path):
    log = tmp_path / "_stdio_recon.log"
    log.write_text(
        "HTTP 429; retry-after: 999999999 seconds\n",
        encoding="utf-8",
    )
    assert estimate_rate_limit_wait_seconds(log) is None


def test_codex_reverse_event_order_does_not_authenticate_reset(tmp_path: Path):
    from datetime import datetime, timedelta

    target = datetime.now().astimezone() + timedelta(days=2)
    mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][target.month - 1]
    hour12 = ((target.hour - 1) % 12) + 1
    ampm = "AM" if target.hour < 12 else "PM"
    message = (f"You've hit your usage limit. try again at {mon} {target.day}, "
               f"{target.year} {hour12}:{target.minute:02d} {ampm}.")
    events = [
        {"type": "turn.failed", "error": {"message": message}},
        {"type": "error", "message": message},
        {"type": "turn.started"},
        {"type": "thread.started", "thread_id": "thread-reverse"},
    ]
    log = tmp_path / "_stdio_recon.log"
    log.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    assert estimate_rate_limit_wait_seconds(log) is None


def test_codex_cross_turn_events_do_not_authenticate_reset(tmp_path: Path):
    from datetime import datetime, timedelta

    target = datetime.now().astimezone() + timedelta(days=2)
    mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][target.month - 1]
    hour12 = ((target.hour - 1) % 12) + 1
    ampm = "AM" if target.hour < 12 else "PM"
    message = (f"You've hit your usage limit. try again at {mon} {target.day}, "
               f"{target.year} {hour12}:{target.minute:02d} {ampm}.")
    events = [
        {"type": "thread.started", "thread_id": "thread-cross"},
        {"type": "turn.started"},
        {"type": "turn.failed", "error": {"message": message}},
        {"type": "turn.started"},
        {"type": "error", "message": message},
    ]
    log = tmp_path / "_stdio_recon.log"
    log.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    assert estimate_rate_limit_wait_seconds(log) is None


def test_malformed_thread_boundary_clears_pending_codex_error(tmp_path: Path):
    message = "You've hit your usage limit. try again at Dec 31, 2099 5:00 AM."
    for case, malformed_id in (("missing", None), ("empty", ""), ("nonstr", [])):
        events = [
            {"type": "thread.started", "thread_id": "valid-thread"},
            {"type": "turn.started"},
            {"type": "error", "message": message},
            ({"type": "thread.started"} if case == "missing" else
             {"type": "thread.started", "thread_id": malformed_id}),
            {"type": "turn.failed", "error": {"message": message}},
        ]
        log = tmp_path / f"_stdio_recon_{case}.log"
        log.write_text(
            "\n".join(json.dumps(e) for e in events) + "\n",
            encoding="utf-8",
        )
        assert estimate_rate_limit_wait_seconds(log) is None, case


def test_structured_reset_epoch_milliseconds_are_parsed(tmp_path: Path):
    from datetime import datetime, timedelta, timezone
    import json

    target = datetime.now(timezone.utc) + timedelta(days=2)
    log = tmp_path / "_stdio_recon.log"
    log.write_text(json.dumps(_claude_rate_limit_event(
        text="You've hit your weekly limit",
        resets_at=int(target.timestamp() * 1000),
    )) + "\n", encoding="utf-8")
    secs = estimate_rate_limit_wait_seconds(log)
    assert secs is not None and 47 * 3600 <= secs <= 48 * 3600


def test_retry_after_precedes_far_future_structured_reset(tmp_path: Path):
    from datetime import datetime, timedelta, timezone
    import json

    target = datetime.now(timezone.utc) + timedelta(days=2)
    log = tmp_path / "_stdio_recon.log"
    log.write_text(json.dumps(_claude_rate_limit_event(
        text="HTTP 429; retry-after: 45 seconds",
        resets_at=int(target.timestamp()),
    )) + "\n", encoding="utf-8")
    assert estimate_rate_limit_wait_seconds(log) == 45


def test_claude_yearless_weekly_reset_text_is_parsed(tmp_path: Path):
    from datetime import datetime, timedelta

    target = datetime.now().astimezone() + timedelta(days=2)
    mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][target.month - 1]
    hour12 = ((target.hour - 1) % 12) + 1
    ampm = "am" if target.hour < 12 else "pm"
    log = tmp_path / "_stdio_recon.log"
    text = (f"You've hit your weekly limit · resets "
            f"{mon} {target.day}, {hour12}:{target.minute:02d}{ampm}")
    log.write_text(
        json.dumps(_claude_rate_limit_event(text=text)) + "\n",
        encoding="utf-8",
    )
    secs = estimate_rate_limit_wait_seconds(log)
    assert secs is not None
    assert secs > d._RATE_LIMIT_RESUME_THRESHOLD_S
    assert secs <= 3 * 24 * 3600


def test_yearless_reset_rolls_across_december_to_january(tmp_path: Path):
    log = tmp_path / "_stdio_recon.log"
    import json
    log.write_text(json.dumps(_claude_rate_limit_event(
        text="You've hit your weekly limit; resets Jan 1, 5am",
    )) + "\n", encoding="utf-8")
    secs = estimate_rate_limit_wait_seconds(log)
    assert secs is not None and secs > 0
    assert secs <= 367 * 24 * 3600


def test_yearless_feb_29_searches_for_next_valid_leap_year(tmp_path: Path):
    log = tmp_path / "_stdio_recon.log"
    import json
    log.write_text(json.dumps(_claude_rate_limit_event(
        text="You've hit your weekly limit; resets Feb 29, 5am",
    )) + "\n", encoding="utf-8")
    secs = estimate_rate_limit_wait_seconds(log)
    assert secs is not None and secs > 0
    assert secs <= 8 * 366 * 24 * 3600


def test_verbatim_spectra_message_parses_or_defaults(tmp_path: Path):
    # The exact Spectra fixture. Once real time passes Jul 11 2026 the absolute
    # date is in the past, so parsing returns None (cap already reset) — both
    # outcomes are correct, so assert only that it never raises and, when it
    # does parse, the window is a far-future daily-cap window.
    log = tmp_path / "_stdio_breadth.log"
    log.write_text(_SPECTRA_USAGE_LIMIT, encoding="utf-8")
    secs = estimate_rate_limit_wait_seconds(log)
    assert secs is None or secs > d._RATE_LIMIT_RESUME_THRESHOLD_S, secs


def test_time_only_reset_window_is_parsed(tmp_path: Path):
    # The docstring's own example form ("try again at 5:46 PM") — time only, no
    # date. Must parse to a positive window < 24h (next occurrence of that time).
    log = tmp_path / "_stdio_recon.log"
    log.write_text(_REAL_USAGE_LIMIT, encoding="utf-8")
    secs = estimate_rate_limit_wait_seconds(log)
    assert secs is not None and 0 < secs <= 24 * 3600, secs


def test_unstructured_absolute_reset_does_not_control_scheduler(tmp_path: Path):
    log = tmp_path / "_stdio_recon.log"
    log.write_text("HTTP 429 rate limited; resets 5:46 PM\n", encoding="utf-8")
    assert estimate_rate_limit_wait_seconds(log) is None


def test_retry_after_delta_still_wins(tmp_path: Path):
    # Regression: an explicit minutes-scale retry-after (Anthropic shape) still
    # parses to its small window and stays UNDER the resume threshold.
    log = tmp_path / "_stdio_breadth.log"
    log.write_text("HTTP 429; retry-after: 45 seconds\n", encoding="utf-8")
    secs = estimate_rate_limit_wait_seconds(log)
    assert secs == 45
    assert secs <= d._RATE_LIMIT_RESUME_THRESHOLD_S


def test_no_window_returns_none(tmp_path: Path):
    log = tmp_path / "_stdio_breadth.log"
    log.write_text('{"type":"item.completed"}\n', encoding="utf-8")
    assert estimate_rate_limit_wait_seconds(log) is None


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
