from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import pty_completion_codec as C
import pty_completion_observer as O


def _assistant(stop_reason: str, text: str = "") -> dict[str, object]:
    return {
        "type": "assistant",
        "message": {
            "role": "assistant",
            "stop_reason": stop_reason,
            "content": ([{"type": "text", "text": text}] if text else []),
        },
    }


def _jsonl(*events: dict[str, object]) -> bytes:
    return b"".join(
        (json.dumps(event, separators=(",", ":")) + "\n").encode("utf-8")
        for event in events
    )


def _configuration(
    *,
    evidence_id: str = "transcript",
    root_index: int = 0,
    relative_path: str = "session.jsonl",
    recent_limit: int = 4096,
    transcript_limit: int = 64 * 1024,
) -> dict[str, object]:
    return {
        "schema": O.OBSERVER_SCHEMA,
        "transcript_evidence_id": evidence_id,
        "transcript_root_index": root_index,
        "transcript_relative_path": relative_path,
        "recent_pty_byte_limit": recent_limit,
        "transcript_limit_bytes": transcript_limit,
    }


def _prepare(
    root: Path,
    *,
    configuration: dict[str, object] | None = None,
) -> object:
    return O.prepare_claude_turn(
        {
            "observer_configuration": (
                _configuration() if configuration is None else configuration
            ),
            "auxiliary_writable_roots": (root,),
        }
    )


def _probe(runtime: object, stdout: bytes = b"") -> dict[str, object] | None:
    result = O.probe_claude_turn(
        {
            "observer_runtime_state": runtime,
            "stdout": stdout,
        }
    )
    return None if result is None else dict(result)


def _replay(
    observation: dict[str, object],
    raw: bytes,
    *,
    stdout: bytes = b"",
    configuration: dict[str, object] | None = None,
    evidence: dict[str, bytes] | None = None,
    replay_digest: str = "a" * 64,
) -> dict[str, object]:
    return dict(
        O.replay_claude_turn(
            observation,
            {
                "observer_configuration": configuration or _configuration(),
                "completion_evidence": (
                    {"transcript": raw} if evidence is None else evidence
                ),
                "stdout": stdout,
                "evidence_replay_digest": replay_digest,
            },
        )
    )


def test_prepare_arms_an_absent_transcript_before_launch(tmp_path: Path) -> None:
    transcript = tmp_path / "session.jsonl"
    assert not transcript.exists()

    runtime = _prepare(tmp_path)

    assert not transcript.exists()
    assert _probe(runtime) is None


def test_exact_new_end_turn_is_provisional_then_cas_replay_accepted(
    tmp_path: Path,
) -> None:
    runtime = _prepare(tmp_path)
    transcript = tmp_path / "session.jsonl"
    raw = _jsonl(_assistant("end_turn", "new invocation complete"))
    transcript.write_bytes(raw)

    observation = _probe(runtime, b"exact PTY bytes")

    assert observation is not None
    assert observation["signal"] == "TURN_END"
    assert observation["transcript_size"] == len(raw)
    assert observation["transcript_prefix_sha256"] == hashlib.sha256(raw).hexdigest()
    accepted = _replay(
        observation,
        raw,
        stdout=b"exact PTY bytes",
        replay_digest="b" * 64,
    )
    assert accepted == {
        "accepted": True,
        "signal": "TURN_END",
        "replay_digest": "b" * 64,
    }


def test_prelaunch_end_turn_is_stale_and_cannot_certify_new_work(
    tmp_path: Path,
) -> None:
    transcript = tmp_path / "session.jsonl"
    transcript.write_bytes(_jsonl(_assistant("end_turn", "old invocation")))
    runtime = _prepare(tmp_path)

    assert _probe(runtime) is None
    with transcript.open("ab") as handle:
        handle.write(_jsonl(_assistant("tool_use", "new invocation still active")))
    assert _probe(runtime) is None


@pytest.mark.parametrize(
    ("raw", "error"),
    [
        (b"{not-json}\n", "malformed"),
        (
            _jsonl(
                {
                    "type": "assistant",
                    "apiErrorStatus": 429,
                    "message": {"role": "assistant", "content": []},
                }
            ),
            "rate",
        ),
        (
            _jsonl(
                {
                    "type": "assistant",
                    "apiErrorStatus": 529,
                    "message": {"role": "assistant", "content": []},
                }
            ),
            "overloaded",
        ),
    ],
)
def test_malformed_rate_limit_and_overload_are_debt_during_probe(
    tmp_path: Path,
    raw: bytes,
    error: str,
) -> None:
    runtime = _prepare(tmp_path)
    (tmp_path / "session.jsonl").write_bytes(raw)

    with pytest.raises(C.PtyCompletionError, match=error):
        _probe(runtime)


@pytest.mark.parametrize(
    "relative_path",
    [
        "../escape.jsonl",
        "nested/../../escape.jsonl",
        "C:/escape.jsonl",
        "/escape.jsonl",
        "nested:stream/session.jsonl",
    ],
)
def test_transcript_path_escape_and_alias_syntax_are_rejected(
    tmp_path: Path,
    relative_path: str,
) -> None:
    with pytest.raises(O.ClaudeTurnObserverError, match="configuration is invalid"):
        _prepare(
            tmp_path,
            configuration=_configuration(relative_path=relative_path),
        )


def test_existing_reparse_component_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alias = tmp_path / "alias"
    alias.mkdir()
    original = O._codec_module._is_reparse
    monkeypatch.setattr(
        O._codec_module,
        "_is_reparse",
        lambda path: Path(path) == alias or original(Path(path)),
    )

    with pytest.raises(
        O.ClaudeTurnObserverError,
        match="alias/reparse component",
    ):
        _prepare(
            tmp_path,
            configuration=_configuration(relative_path="alias/session.jsonl"),
        )


@pytest.mark.parametrize(
    "configuration",
    [
        {},
        {**_configuration(), "unknown": True},
        {**_configuration(), "schema": "foreign"},
        _configuration(evidence_id="../not-an-id"),
        _configuration(root_index=1),
        _configuration(recent_limit=0),
        _configuration(transcript_limit=0),
    ],
)
def test_configuration_and_root_denominator_mismatch_is_rejected(
    tmp_path: Path,
    configuration: dict[str, object],
) -> None:
    with pytest.raises(O.ClaudeTurnObserverError):
        _prepare(tmp_path, configuration=configuration)

    with pytest.raises(O.ClaudeTurnObserverError, match="denominator"):
        O.prepare_claude_turn(
            {
                "observer_configuration": _configuration(),
                "auxiliary_writable_roots": [tmp_path],
            }
        )


def test_replay_is_bound_to_exact_cas_evidence_id_and_bytes(
    tmp_path: Path,
) -> None:
    runtime = _prepare(tmp_path)
    raw = _jsonl(_assistant("end_turn", "complete"))
    (tmp_path / "session.jsonl").write_bytes(raw)
    observation = _probe(runtime)
    assert observation is not None

    with pytest.raises(O.ClaudeTurnObserverError, match="evidence is missing"):
        _replay(observation, raw, evidence={"different": raw})

    mutated = _jsonl(_assistant("end_turn", "mutated"))
    with pytest.raises(O.ClaudeTurnObserverError, match="prefix"):
        _replay(observation, mutated)

    mismatched_config = _configuration(evidence_id="different")
    with pytest.raises(O.ClaudeTurnObserverError, match="evidence is missing"):
        _replay(
            observation,
            raw,
            configuration=mismatched_config,
            evidence={"transcript": raw},
        )


def test_replay_rejects_a_forged_provisional_prefix(tmp_path: Path) -> None:
    runtime = _prepare(tmp_path)
    raw = _jsonl(_assistant("end_turn", "complete"))
    (tmp_path / "session.jsonl").write_bytes(raw)
    observation = _probe(runtime)
    assert observation is not None
    observation["transcript_prefix_sha256"] = "0" * 64

    with pytest.raises(O.ClaudeTurnObserverError, match="prefix"):
        _replay(observation, raw)


@pytest.mark.parametrize(
    "late_debt",
    [
        b"{not-json}\n",
        _jsonl(
            {
                "type": "assistant",
                "apiErrorStatus": 429,
                "message": {"role": "assistant", "content": []},
            }
        ),
        _jsonl(
            {
                "type": "assistant",
                "apiErrorStatus": 529,
                "message": {"role": "assistant", "content": []},
            }
        ),
    ],
)
def test_final_cas_replay_rejects_late_malformed_or_provider_debt(
    tmp_path: Path,
    late_debt: bytes,
) -> None:
    runtime = _prepare(tmp_path)
    prefix = _jsonl(_assistant("end_turn", "complete"))
    transcript = tmp_path / "session.jsonl"
    transcript.write_bytes(prefix)
    observation = _probe(runtime)
    assert observation is not None

    with pytest.raises(C.PtyCompletionError):
        _replay(observation, prefix + late_debt)


def test_fixed_observer_deliberately_rejects_output_ready_signal(
    tmp_path: Path,
) -> None:
    runtime = _prepare(tmp_path)
    raw = _jsonl(_assistant("end_turn", "complete"))
    (tmp_path / "session.jsonl").write_bytes(raw)
    observation = _probe(runtime)
    assert observation is not None
    observation["signal"] = C.OUTPUT_READY

    with pytest.raises(O.ClaudeTurnObserverError, match="TURN_END"):
        _replay(observation, raw)


def test_implementation_files_are_exact_existing_unique_source_closure() -> None:
    files = O.implementation_files()

    assert files == (
        Path(O.__file__).resolve(strict=True),
        Path(O._codec_module.__file__).resolve(strict=True),
        Path(O._pty_exec_module.__file__).resolve(strict=True),
        Path(O._pty_protocol_module.__file__).resolve(strict=True),
    )
    assert len(set(files)) == len(files)
    assert all(path.is_absolute() and path.is_file() for path in files)
