"""Fixed Claude JSONL completion-observer package for WorkerExecutionReceipts.

The package has three source-bound functions:

* ``prepare_claude_turn`` arms the incremental codec before child launch;
* ``probe_claude_turn`` emits a provisional exact ``TURN_END`` observation;
* ``replay_claude_turn`` deterministically replays CAS-retained final bytes.

It deliberately does not implement output-file-only completion yet.  That state
requires the assigned-output parser and CAS denominator to be part of the same
final replay authority; accepting a touched file here would be precision-unsafe.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
from typing import Any, Mapping

import pty_completion_codec as _codec_module
from pty_completion_codec import ClaudePtyCodec, PtyCompletionError
import pty_exec as _pty_exec_module
from pty_exec import text_shows_overloaded, text_shows_rate_limit
import pty_worker_protocol as _pty_protocol_module


OBSERVER_SCHEMA = "plamen.claude_jsonl_turn_observer.v1"
_CONFIG_FIELDS = {
    "schema",
    "transcript_evidence_id",
    "transcript_root_index",
    "transcript_relative_path",
    "recent_pty_byte_limit",
    "transcript_limit_bytes",
}


class ClaudeTurnObserverError(RuntimeError):
    """The fixed observer configuration or evidence was invalid."""


@dataclass
class _ClaudeTurnRuntime:
    codec: ClaudePtyCodec
    transcript_path: Path
    stdout_position: int = 0


def _configuration(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _CONFIG_FIELDS:
        raise ClaudeTurnObserverError("Claude observer configuration is malformed")
    if value.get("schema") != OBSERVER_SCHEMA:
        raise ClaudeTurnObserverError("Claude observer schema is unsupported")
    evidence_id = value.get("transcript_evidence_id")
    relative = value.get("transcript_relative_path")
    root_index = value.get("transcript_root_index")
    recent_limit = value.get("recent_pty_byte_limit")
    transcript_limit = value.get("transcript_limit_bytes")
    if (
        not isinstance(evidence_id, str)
        or not evidence_id
        or not evidence_id.replace("_", "").replace("-", "").isalnum()
        or not isinstance(relative, str)
        or not relative
        or Path(relative).is_absolute()
        or any(
            part in {"", ".", ".."} or ":" in part
            for part in relative.replace("\\", "/").split("/")
        )
        or isinstance(root_index, bool)
        or not isinstance(root_index, int)
        or root_index < 0
        or isinstance(recent_limit, bool)
        or not isinstance(recent_limit, int)
        or recent_limit <= 0
        or isinstance(transcript_limit, bool)
        or not isinstance(transcript_limit, int)
        or transcript_limit <= 0
    ):
        raise ClaudeTurnObserverError("Claude observer configuration is invalid")
    return {
        "schema": OBSERVER_SCHEMA,
        "transcript_evidence_id": evidence_id,
        "transcript_root_index": root_index,
        "transcript_relative_path": relative.replace("\\", "/"),
        "recent_pty_byte_limit": recent_limit,
        "transcript_limit_bytes": transcript_limit,
    }


def _transcript_path(
    configuration: Mapping[str, Any],
    auxiliary_roots: Any,
) -> Path:
    if not isinstance(auxiliary_roots, tuple):
        raise ClaudeTurnObserverError("auxiliary-root denominator is invalid")
    index = configuration["transcript_root_index"]
    if index >= len(auxiliary_roots):
        raise ClaudeTurnObserverError("transcript root index is out of range")
    root = Path(auxiliary_roots[index]).resolve(strict=True)
    candidate = root / Path(configuration["transcript_relative_path"])
    try:
        candidate.absolute().relative_to(root)
    except ValueError as exc:
        raise ClaudeTurnObserverError("transcript path escapes its leased root") from exc
    current = root
    for part in Path(configuration["transcript_relative_path"]).parts:
        current = current / part
        if os.path.lexists(current) and (
            current.is_symlink() or _codec_module._is_reparse(current)
        ):
            raise ClaudeTurnObserverError(
                "transcript path contains an alias/reparse component"
            )
    return candidate


def prepare_claude_turn(context: Mapping[str, Any]) -> object:
    configuration = _configuration(context.get("observer_configuration"))
    transcript = _transcript_path(
        configuration,
        context.get("auxiliary_writable_roots"),
    )
    codec = ClaudePtyCodec(
        recent_byte_limit=configuration["recent_pty_byte_limit"],
        transcript_limit_bytes=configuration["transcript_limit_bytes"],
    )
    codec.arm(transcript_path=transcript)
    return _ClaudeTurnRuntime(codec=codec, transcript_path=transcript)


def probe_claude_turn(
    context: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    runtime = context.get("observer_runtime_state")
    if type(runtime) is not _ClaudeTurnRuntime:
        raise ClaudeTurnObserverError("Claude observer runtime state is invalid")
    stdout = context.get("stdout")
    if not isinstance(stdout, bytes) or len(stdout) < runtime.stdout_position:
        raise ClaudeTurnObserverError("PTY stdout snapshot is invalid")
    runtime.codec.feed(stdout[runtime.stdout_position :])
    runtime.stdout_position = len(stdout)
    observation = runtime.codec.observe(
        transcript_path=runtime.transcript_path,
    )
    if observation is None:
        return None
    if observation.signal != "TURN_END":
        raise ClaudeTurnObserverError("fixed Claude observer emitted a foreign signal")
    return {
        "signal": observation.signal,
        "observed_at_monotonic_ns": observation.observed_at_monotonic_ns,
        "transcript_size": observation.transcript_size,
        "transcript_prefix_sha256": observation.transcript_prefix_sha256,
        "transcript_line_count": observation.transcript_line_count,
        "pty_byte_position": observation.pty_byte_position,
    }


def replay_claude_turn(
    observation: Mapping[str, Any],
    context: Mapping[str, Any],
) -> Mapping[str, Any]:
    if not isinstance(observation, Mapping):
        raise ClaudeTurnObserverError("provisional observation is malformed")
    if observation.get("signal") != "TURN_END":
        raise ClaudeTurnObserverError(
            "fixed Claude observer accepts only exact TURN_END"
        )
    configuration = _configuration(context.get("observer_configuration"))
    evidence = context.get("completion_evidence")
    if not isinstance(evidence, Mapping):
        raise ClaudeTurnObserverError("completion evidence is malformed")
    raw = evidence.get(configuration["transcript_evidence_id"])
    if not isinstance(raw, bytes):
        raise ClaudeTurnObserverError("exact transcript evidence is missing")
    if len(raw) > configuration["transcript_limit_bytes"]:
        raise ClaudeTurnObserverError("exact transcript exceeds its bound ceiling")
    size = observation.get("transcript_size")
    prefix_sha = observation.get("transcript_prefix_sha256")
    if (
        isinstance(size, bool)
        or not isinstance(size, int)
        or size < 0
        or size > len(raw)
        or not isinstance(prefix_sha, str)
        or hashlib.sha256(raw[:size]).hexdigest() != prefix_sha
    ):
        raise ClaudeTurnObserverError(
            "provisional transcript prefix does not replay"
        )
    state = _codec_module._event_state(raw)
    stdout = context.get("stdout")
    if not isinstance(stdout, bytes):
        raise ClaudeTurnObserverError("final PTY bytes are missing")
    text = stdout.decode("utf-8", errors="replace")
    if state["overloaded"] or text_shows_overloaded(text):
        raise PtyCompletionError("PTY execution reached an overloaded state")
    if state["rate_limited"] or text_shows_rate_limit(text):
        raise PtyCompletionError("PTY execution reached a rate-limit state")
    if not state["turn_end"]:
        raise ClaudeTurnObserverError(
            "final invocation transcript lacks exact end_turn"
        )
    replay_digest = context.get("evidence_replay_digest")
    if not isinstance(replay_digest, str) or len(replay_digest) != 64:
        raise ClaudeTurnObserverError("WER evidence replay digest is invalid")
    return {
        "accepted": True,
        "signal": "TURN_END",
        "replay_digest": replay_digest,
    }


def implementation_files() -> tuple[Path, ...]:
    """Return the exact non-stdlib implementation closure WER must bind."""

    return (
        Path(__file__).resolve(strict=True),
        Path(_codec_module.__file__).resolve(strict=True),
        Path(_pty_exec_module.__file__).resolve(strict=True),
        Path(_pty_protocol_module.__file__).resolve(strict=True),
    )


__all__ = [
    "ClaudeTurnObserverError",
    "OBSERVER_SCHEMA",
    "implementation_files",
    "prepare_claude_turn",
    "probe_claude_turn",
    "replay_claude_turn",
]
