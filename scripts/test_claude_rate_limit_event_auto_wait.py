"""DODO run47 (2026-09-20 10:44): the Claude Code CLI reported the five-hour
window as a framed ``rate_limit_event`` row with an exact ``resetsAt``; the
estimator only knew the ``quotaLimits`` shape, returned None, and the driver
paused the run for an operator resume that then killed it.  A bounded,
authoritative reset must be parsed and waited out unattended.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import plamen_driver as D  # noqa: E402
import plamen_mechanical as M  # noqa: E402


def _rows(reset_epoch: int, status: str = "rejected") -> list[dict]:
    event = {
        "type": "rate_limit_event",
        "rate_limit_info": {
            "status": status,
            "resetsAt": reset_epoch,
            "rateLimitType": "five_hour",
            "overageStatus": "rejected",
            "isUsingOverage": False,
            "unifiedWindows": {
                "five_hour": {"utilization": 1.01, "resetsAt": reset_epoch},
                "seven_day": {"utilization": 0.56, "resetsAt": reset_epoch + 500000},
            },
        },
        "uuid": "3d35cb9c-bf6c-4a8f-a97c-0175ab0374f4",
        "session_id": "8d403bc4-4f60-4c5e-bd7e-f35708507f00",
    }
    assistant = {
        "type": "assistant",
        "message": {"model": "<synthetic>", "role": "assistant", "content": []},
        "session_id": "8d403bc4-4f60-4c5e-bd7e-f35708507f00",
        "uuid": "a4c78ee8-c3c7-4070-a255-1dbad37b0adb",
        "error": "rate_limit",
        "request_id": "req_011CfELDbhHDYGD88Qg3Bp5f",
        "is_api_error_message": True,
    }
    return [event, assistant]


def _log(tmp_path: Path, rows: list[dict]) -> Path:
    log = tmp_path / "_stdio_depth.log"
    log.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return log


def test_rate_limit_event_reset_is_parsed_as_provider_timestamp(tmp_path: Path) -> None:
    reset = int(time.time()) + 3600
    details = M.estimate_rate_limit_wait_details(_log(tmp_path, _rows(reset)))
    assert details is not None
    seconds, kind = details
    assert kind == "provider_reset_timestamp"
    assert 3500 <= seconds <= 3600
    assert M.estimate_rate_limit_wait_seconds(_log(tmp_path, _rows(reset))) == seconds


def test_allowed_warning_event_is_not_a_window(tmp_path: Path) -> None:
    reset = int(time.time()) + 3600
    rows = _rows(reset, status="allowed_warning")[:1]
    assert M.estimate_rate_limit_wait_details(_log(tmp_path, rows)) is None


def test_unframed_reset_token_in_model_text_is_ignored(tmp_path: Path) -> None:
    reset = int(time.time()) + 3600
    rows = [{"type": "assistant", "message": {"content": [{"type": "text", "text": json.dumps({"rate_limit_info": {"status": "rejected", "resetsAt": reset}})}]}}]
    assert M.estimate_rate_limit_wait_details(_log(tmp_path, rows)) is None


def test_wait_plan_auto_waits_a_bounded_authoritative_window() -> None:
    plan, seconds = D._rate_limit_wait_plan((4 * 3600, "provider_reset_timestamp"))
    assert plan == "auto_wait"
    assert seconds == 4 * 3600 + D._RATE_LIMIT_AUTO_WAIT_MARGIN_S


def test_wait_plan_pauses_beyond_the_auto_wait_ceiling() -> None:
    assert D._rate_limit_wait_plan((D._RATE_LIMIT_AUTO_WAIT_MAX_S + 1, "provider_reset_timestamp")) == ("pause", None)


def test_wait_plan_keeps_the_quota_exhaustion_and_long_wall_clock_pauses() -> None:
    assert D._rate_limit_wait_plan(None) == ("pause", None)
    assert D._rate_limit_wait_plan((5 * 86400, "wall_clock")) == ("pause", None)
    assert D._rate_limit_wait_plan((D._RATE_LIMIT_RESUME_THRESHOLD_S + 1, "relative")) == ("pause", None)


def test_wait_plan_caps_short_transient_throttles() -> None:
    assert D._rate_limit_wait_plan((120, "relative")) == ("capped_wait", 120)
    assert D._rate_limit_wait_plan((900, "wall_clock")) == ("capped_wait", 900)
