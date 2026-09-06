from __future__ import annotations

import hashlib
import json
from pathlib import Path
import time

import pytest

import pty_completion_codec as C


def _assistant(stop_reason: str, text: str = "") -> dict[str, object]:
    return {
        "type": "assistant",
        "message": {
            "role": "assistant",
            "stop_reason": stop_reason,
            "content": ([{"type": "text", "text": text}] if text else []),
        },
    }


def _write_jsonl(path: Path, *events: dict[str, object]) -> None:
    path.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )


def _output_validator(_path: Path, raw: bytes) -> str:
    if not raw.strip() or b"substantive" not in raw:
        raise ValueError("output is not semantically acceptable")
    return hashlib.sha256(raw.strip()).hexdigest()


def test_turn_end_is_provisional_until_final_prefix_replay(tmp_path: Path) -> None:
    transcript = tmp_path / "session.jsonl"
    codec = C.ClaudePtyCodec()
    codec.arm(transcript_path=transcript)
    _write_jsonl(transcript, _assistant("end_turn", "DONE: output written"))
    codec.feed(b"screen bytes")

    observation = codec.observe(transcript_path=transcript)

    assert observation is not None
    assert observation.signal == C.TURN_END
    assert observation.pty_byte_position == len(b"screen bytes")
    replay = codec.final_replay(observation, transcript_path=transcript)
    assert replay.signal == C.TURN_END


def test_late_rate_limit_event_invalidates_provisional_turn_end(
    tmp_path: Path,
) -> None:
    transcript = tmp_path / "session.jsonl"
    codec = C.ClaudePtyCodec()
    codec.arm(transcript_path=transcript)
    _write_jsonl(transcript, _assistant("end_turn", "DONE"))
    observation = codec.observe(transcript_path=transcript)
    assert observation is not None
    with transcript.open("a", encoding="utf-8") as handle:
        handle.write(
            json.dumps(
                {
                    "type": "assistant",
                    "apiErrorStatus": 429,
                    "message": {"role": "assistant", "content": []},
                }
            )
            + "\n"
        )

    with pytest.raises(C.PtyCompletionError, match="rate"):
        codec.final_replay(observation, transcript_path=transcript)


def test_rewritten_transcript_prefix_invalidates_observation(tmp_path: Path) -> None:
    transcript = tmp_path / "session.jsonl"
    codec = C.ClaudePtyCodec()
    codec.arm(transcript_path=transcript)
    _write_jsonl(transcript, _assistant("end_turn", "DONE"))
    observation = codec.observe(transcript_path=transcript)
    assert observation is not None
    _write_jsonl(transcript, _assistant("end_turn", "different"))

    with pytest.raises(C.PtyCompletionError, match="prefix"):
        codec.final_replay(observation, transcript_path=transcript)


def test_output_ready_requires_opt_in_quiescence_and_exact_final_bytes(
    tmp_path: Path,
) -> None:
    transcript = tmp_path / "session.jsonl"
    _write_jsonl(transcript, _assistant("tool_use"))
    output = tmp_path / "result.md"
    codec = C.ClaudePtyCodec(
        output_quiescence_seconds=0.02,
        output_validator=_output_validator,
    )
    codec.arm(
        transcript_path=transcript,
        expected_outputs=(output,),
    )
    output.write_text("# Result\nsubstantive\n", encoding="utf-8")

    assert (
        codec.observe(
            transcript_path=transcript,
            expected_outputs=(output,),
            allow_output_ready=True,
        )
        is None
    )
    time.sleep(0.03)
    observation = codec.observe(
        transcript_path=transcript,
        expected_outputs=(output,),
        allow_output_ready=True,
    )
    assert observation is not None
    assert observation.signal == C.OUTPUT_READY

    output.write_text("# Result\nsubstantive changed later\n", encoding="utf-8")
    with pytest.raises(C.PtyCompletionError, match="output changed"):
        codec.final_replay(
            observation,
            transcript_path=transcript,
            expected_outputs=(output,),
        )


def test_output_file_without_explicit_opt_in_is_not_completion(
    tmp_path: Path,
) -> None:
    transcript = tmp_path / "session.jsonl"
    _write_jsonl(transcript, _assistant("tool_use"))
    output = tmp_path / "result.md"
    codec = C.ClaudePtyCodec(output_quiescence_seconds=0)
    codec.arm(transcript_path=transcript, expected_outputs=(output,))
    output.write_text("# reserved\n", encoding="utf-8")

    assert codec.observe(
        transcript_path=transcript,
        expected_outputs=(output,),
    ) is None


def test_live_usage_cap_text_is_debt_not_completion(tmp_path: Path) -> None:
    transcript = tmp_path / "session.jsonl"
    _write_jsonl(transcript, _assistant("tool_use"))
    codec = C.ClaudePtyCodec()
    codec.arm(transcript_path=transcript)
    codec.feed(b"You've hit your weekly limit")

    with pytest.raises(C.PtyCompletionError, match="rate"):
        codec.observe(transcript_path=transcript)


def test_prelaunch_turn_end_cannot_certify_new_invocation(tmp_path: Path) -> None:
    transcript = tmp_path / "session.jsonl"
    _write_jsonl(transcript, _assistant("end_turn", "old invocation"))
    codec = C.ClaudePtyCodec()
    codec.arm(transcript_path=transcript)

    assert codec.observe(transcript_path=transcript) is None
    with transcript.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(_assistant("tool_use", "new invocation")) + "\n")
    assert codec.observe(transcript_path=transcript) is None
    with transcript.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(_assistant("end_turn", "new complete")) + "\n")
    assert codec.observe(transcript_path=transcript).signal == C.TURN_END


def test_rate_limit_latch_survives_recent_window_eviction(tmp_path: Path) -> None:
    transcript = tmp_path / "session.jsonl"
    codec = C.ClaudePtyCodec(recent_byte_limit=64)
    codec.arm(transcript_path=transcript)
    codec.feed(b"You've hit your weekly limit")
    codec.feed(b"x" * 4096)

    with pytest.raises(C.PtyCompletionError, match="rate"):
        codec.observe(transcript_path=transcript)


def test_output_ready_rejects_empty_unparsed_and_unchanged_baseline(
    tmp_path: Path,
) -> None:
    transcript = tmp_path / "session.jsonl"
    _write_jsonl(transcript, _assistant("tool_use"))
    output = tmp_path / "result.md"

    no_parser = C.ClaudePtyCodec(output_quiescence_seconds=0)
    no_parser.arm(transcript_path=transcript, expected_outputs=(output,))
    output.write_text("substantive", encoding="utf-8")
    with pytest.raises(C.PtyCompletionError, match="validator"):
        no_parser.observe(
            transcript_path=transcript,
            expected_outputs=(output,),
            allow_output_ready=True,
        )

    output.unlink()
    parsed = C.ClaudePtyCodec(
        output_quiescence_seconds=0,
        output_validator=_output_validator,
    )
    parsed.arm(transcript_path=transcript, expected_outputs=(output,))
    output.write_bytes(b"")
    assert parsed.observe(
        transcript_path=transcript,
        expected_outputs=(output,),
        allow_output_ready=True,
    ) is None

    output.write_text("substantive baseline", encoding="utf-8")
    baseline = C.ClaudePtyCodec(
        output_quiescence_seconds=0,
        output_validator=_output_validator,
    )
    baseline.arm(transcript_path=transcript, expected_outputs=(output,))
    assert baseline.observe(
        transcript_path=transcript,
        expected_outputs=(output,),
        allow_output_ready=True,
    ) is None
    assert baseline.observe(
        transcript_path=transcript,
        expected_outputs=(output,),
        allow_output_ready=True,
    ) is None


def test_transcript_ceiling_is_enforced_during_incremental_poll(
    tmp_path: Path,
) -> None:
    transcript = tmp_path / "session.jsonl"
    codec = C.ClaudePtyCodec(transcript_limit_bytes=128)
    codec.arm(transcript_path=transcript)
    transcript.write_bytes(b"x" * 129)

    with pytest.raises(C.PtyCompletionError, match="ceiling"):
        codec.observe(transcript_path=transcript)


def test_end_turn_followed_by_malformed_jsonl_is_debt(tmp_path: Path) -> None:
    transcript = tmp_path / "session.jsonl"
    codec = C.ClaudePtyCodec()
    codec.arm(transcript_path=transcript)
    transcript.write_bytes(
        (json.dumps(_assistant("end_turn", "done")) + "\n").encode("utf-8")
        + b"{not-json}\n"
    )

    with pytest.raises(C.PtyCompletionError, match="malformed"):
        codec.observe(transcript_path=transcript)


def test_permissive_stop_text_is_not_exact_turn_end(tmp_path: Path) -> None:
    transcript = tmp_path / "session.jsonl"
    codec = C.ClaudePtyCodec()
    codec.arm(transcript_path=transcript)
    _write_jsonl(transcript, _assistant("stop", "looks complete"))

    assert codec.observe(transcript_path=transcript) is None


def test_529_is_overload_debt_not_account_rate_limit(tmp_path: Path) -> None:
    transcript = tmp_path / "session.jsonl"
    codec = C.ClaudePtyCodec()
    codec.arm(transcript_path=transcript)
    transcript.write_text(
        json.dumps(
            {
                "type": "assistant",
                "apiErrorStatus": 529,
                "message": {"role": "assistant", "content": []},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(C.PtyCompletionError, match="overloaded"):
        codec.observe(transcript_path=transcript)
