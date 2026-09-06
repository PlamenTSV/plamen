"""Lossless, resumable authority for real-signal chain-composition tails.

The model-facing Markdown packet is deliberately bounded.  The authoritative
denominator, every pair-level disposition, and all unresolved work live in
typed JSON sidecars whose digests are checked independently.  This module is a
recall control plane: it may nominate a composed chain for ordinary
verification, but it never grants proof or report authority.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any, Callable, Iterable, Mapping


MANIFEST_NAME = "chain_candidate_pairs_iter2.json"
LEDGER_NAME = "chain_tail_disposition_ledger.json"
RECEIPT_NAME = "chain_tail_coverage_receipt.json"
PROJECTION_NAME = "chain_composition_coverage_gaps.md"
COMPOSITION_CANDIDATES_NAME = "chain_composition_verification_candidates.json"
SHARD_PROJECTION_NAME = "chain_candidate_pairs_iter2.md"
SHARD_ARCHIVE_DIR = "_chain_tail_shards"
CONTROL_DIR = "_chain_tail_control"
CONTROL_JOURNAL_NAME = "scheduler_journal.json"
CONTROL_LOCK_NAME = "scheduler.lock"
PUBLICATION_ARMED_NAME = "final_publication.armed"
PRIMARY_RECEIPT_NAME = "chain_tail_primary_receipt.json"
TERMINAL_SNAPSHOT_NAME = "chain_tail_terminal_snapshot.json"
CONTROL_MANIFEST_PATH = f"{CONTROL_DIR}/{MANIFEST_NAME}"

# Every evidence-bearing scheduler mutation rolls this complete set forward as
# one DRIVER generation.  Immutable shard packets/receipts are intentionally
# excluded: coupling either class to mutable control state would make their
# producer authority stale as soon as the next shard advances.
MUTABLE_CONTROL_PATHS = (
    f"{CONTROL_DIR}/{LEDGER_NAME}",
    f"{CONTROL_DIR}/{RECEIPT_NAME}",
    f"{CONTROL_DIR}/{COMPOSITION_CANDIDATES_NAME}",
    f"{CONTROL_DIR}/{PROJECTION_NAME}",
    f"{CONTROL_DIR}/{CONTROL_JOURNAL_NAME}",
)

MANIFEST_SCHEMA = "plamen.chain_tail_manifest.v2"
LEDGER_SCHEMA = "plamen.chain_tail_disposition_ledger.v2"
RECEIPT_SCHEMA = "plamen.chain_tail_coverage_receipt.v2"
CANDIDATE_SCHEMA = "plamen.chain_composition_candidates.v1"
TERMINAL_SNAPSHOT_SCHEMA = "plamen.chain_tail.terminal_snapshot.v2"
MAX_TERMINAL_GENERATION_COMPONENT = 9999

DEFAULT_SHARD_SIZE = 15
DEFAULT_PROJECTION_SAMPLE_ROWS = 12
DEFAULT_PROJECTION_BYTE_CEILING = 12_000

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FINDING_ID_FALLBACK_RE = re.compile(r"^[A-Z][A-Z0-9_-]{1,95}$", re.I | re.ASCII)
_CHAIN_ID_RE = re.compile(r"\bCH-\d+\b", re.I)
_CHAIN_HEADING_RE = re.compile(
    r"(?im)^#{2,4}\s+(?:Chain\s+Hypothesis\s+)?(CH-\d+)\b[^\r\n]*$"
)
_TAIL_HEADING_RE = re.compile(
    r"(?im)^##\s+(?:(?:\d+(?:\.\d+)*)[.)]?\s+)?"
    r"Tail\s+Pair\s+Dispositions\s*$"
)
_WORKER_COUNT_RES = (
    re.compile(r"(?i)\b(\d+)\s*/\s*(\d+)\s+(?:pairs?\s+)?(?:covered|evaluated|processed|complete)\b"),
    re.compile(r"(?i)\b(?:covered|evaluated|processed)\s+(\d+)\s*/\s*(\d+)\b"),
)

_TERMINAL = frozenset({"EXPLORED", "REJECTED", "COMPOSED"})
_HEADER_ALIASES = {
    "pair_id": {"pairid", "pair", "manifestpairid"},
    "a": {"findinga", "a", "left", "sourcefinding"},
    "b": {"findingb", "b", "right", "targetfinding"},
    "disposition": {"disposition", "result", "outcome"},
    "evidence": {"evidence", "rationale", "reason", "analysis"},
}

_DURABLE_TRANSITION_OBSERVER: Callable[[str, str, Path], None] | None = None


class ChainTailAuthorityError(ValueError):
    pass


def chain_tail_generation_id(pass_index: int, shard_count: int) -> str:
    """Render one exact bounded terminal-generation identity."""

    if (
        type(pass_index) is not int
        or type(shard_count) is not int
        or not 0 <= pass_index <= MAX_TERMINAL_GENERATION_COMPONENT
        or not 0 <= shard_count <= MAX_TERMINAL_GENERATION_COMPONENT
    ):
        raise ChainTailAuthorityError(
            "chain-tail terminal generation components must be integers "
            "between 0 and 9999"
        )
    return f"p{pass_index:04d}.s{shard_count:04d}"


def _ledger_terminal_generation(
    ledger: Mapping[str, Any],
) -> tuple[int, int]:
    """Read G from one validated ledger without consulting directory order."""

    if not isinstance(ledger, Mapping):
        raise ChainTailAuthorityError("chain-tail generation ledger is malformed")
    pass_index = ledger.get("pass_index")
    shards = ledger.get("shards")
    if type(pass_index) is not int or not isinstance(shards, list):
        raise ChainTailAuthorityError(
            "chain-tail terminal generation fields are malformed"
        )
    shard_count = len(shards)
    chain_tail_generation_id(pass_index, shard_count)
    return pass_index, shard_count


def _terminal_snapshot_generation(
    snapshot: Mapping[str, Any],
) -> tuple[int, int]:
    """Validate and return the exact G sealed by a terminal snapshot v2."""

    generation = snapshot.get("terminal_generation")
    semantic_ledger = snapshot.get("semantic_ledger")
    if (
        snapshot.get("schema_version") != TERMINAL_SNAPSHOT_SCHEMA
        or not isinstance(generation, Mapping)
        or set(generation)
        != {"pass_index", "shard_count", "generation_id"}
        or not isinstance(semantic_ledger, Mapping)
    ):
        raise ChainTailAuthorityError(
            "CHAIN_TAIL_LEGACY_FIXED_GENERATION: chain-tail terminal "
            "snapshot generation is missing or malformed"
        )
    pass_index = generation.get("pass_index")
    shard_count = generation.get("shard_count")
    generation_id = chain_tail_generation_id(pass_index, shard_count)
    if generation.get("generation_id") != generation_id:
        raise ChainTailAuthorityError(
            "chain-tail terminal snapshot generation identity mismatch"
        )
    semantic_generation = _ledger_terminal_generation(semantic_ledger)
    if semantic_generation != (pass_index, shard_count):
        raise ChainTailAuthorityError(
            "chain-tail terminal snapshot semantic generation mismatch"
        )
    return pass_index, shard_count


def _terminal_producer_prefix(
    work_unit_key: str,
    *,
    role: str,
    generation_id: str,
) -> tuple[str, str, str, str, str]:
    """Parse an exact six-segment terminal producer key, never a suffix."""

    if role not in {"tail_snapshot", "tail_reconcile", "driver_merge"}:
        raise ChainTailAuthorityError("unsupported terminal producer role")
    if not re.fullmatch(r"p\d{4}\.s\d{4}", generation_id):
        raise ChainTailAuthorityError("terminal producer generation is invalid")
    if not isinstance(work_unit_key, str):
        raise ChainTailAuthorityError("terminal producer key is not a string")
    parts = work_unit_key.split("/")
    component = re.compile(r"^[a-z0-9][a-z0-9_.-]*$", re.ASCII)
    if (
        len(parts) != 6
        or any(component.fullmatch(part) is None for part in parts[:4])
        or parts[4] != "chain_iter2"
        or parts[5] != f"{role}.{generation_id}"
    ):
        raise ChainTailAuthorityError(
            "terminal producer key is not the exact generation-scoped key"
        )
    return tuple(parts[:5])  # type: ignore[return-value]


def _canonical_bytes(payload: object) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _render_json_postimage(payload: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(payload, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _digest(payload: Mapping[str, Any], digest_field: str) -> str:
    return hashlib.sha256(
        _canonical_bytes({k: v for k, v in payload.items() if k != digest_field})
    ).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _observe_durable_transition(
    operation: str,
    edge: str,
    path: Path,
) -> None:
    observer = _DURABLE_TRANSITION_OBSERVER
    if observer is not None:
        observer(operation, edge, Path(path))


@contextmanager
def observe_chain_tail_durable_transitions(
    observer: Callable[[str, str, Path], None],
):
    """Expose the exact transition denominator to deterministic fault tests.

    The observer is process-local and has no environment/config control, so
    production callers cannot weaken or skip writes. Nested observers are
    rejected because two fault authorities would make occurrence ordering
    ambiguous.
    """

    global _DURABLE_TRANSITION_OBSERVER
    if not callable(observer):
        raise TypeError("chain-tail durable transition observer must be callable")
    if _DURABLE_TRANSITION_OBSERVER is not None:
        raise ChainTailAuthorityError(
            "chain-tail durable transition observer is already active"
        )
    _DURABLE_TRANSITION_OBSERVER = observer
    try:
        yield
    finally:
        _DURABLE_TRANSITION_OBSERVER = None


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    _observe_durable_transition("TEMP_WRITE", "BEFORE", temporary)
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    _observe_durable_transition("TEMP_WRITE", "AFTER", temporary)
    _observe_durable_transition("ATOMIC_REPLACE", "BEFORE", path)
    temporary.replace(path)
    _observe_durable_transition("ATOMIC_REPLACE", "AFTER", path)


def _atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    _observe_durable_transition("TEMP_WRITE", "BEFORE", temporary)
    temporary.write_text(text, encoding="utf-8", newline="\n")
    _observe_durable_transition("TEMP_WRITE", "AFTER", temporary)
    _observe_durable_transition("ATOMIC_REPLACE", "BEFORE", path)
    temporary.replace(path)
    _observe_durable_transition("ATOMIC_REPLACE", "AFTER", path)


def _atomic_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    _observe_durable_transition("TEMP_WRITE", "BEFORE", temporary)
    temporary.write_bytes(data)
    _observe_durable_transition("TEMP_WRITE", "AFTER", temporary)
    _observe_durable_transition("ATOMIC_REPLACE", "BEFORE", path)
    temporary.replace(path)
    _observe_durable_transition("ATOMIC_REPLACE", "AFTER", path)


def _safe_relative_path(
    root: Path,
    raw: object,
    *,
    field: str,
    required_prefix: str = "",
) -> tuple[str, Path]:
    normalized = str(raw or "").replace("\\", "/").strip("/")
    candidate = Path(normalized)
    if (
        not normalized
        or candidate.is_absolute()
        or ":" in normalized
        or ".." in candidate.parts
        or "." in candidate.parts
        or candidate.is_reserved()
    ):
        raise ChainTailAuthorityError(f"invalid {field}: {raw!r}")
    if required_prefix and not (
        normalized == required_prefix
        or normalized.startswith(required_prefix.rstrip("/") + "/")
    ):
        raise ChainTailAuthorityError(f"{field} escapes its authority namespace")
    root_resolved = Path(root).resolve()
    resolved = (root_resolved / candidate).resolve()
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise ChainTailAuthorityError(f"{field} escapes scratchpad") from exc
    return normalized, resolved


@contextmanager
def _scheduler_lock(scratchpad: Path):
    """Serialize the mutable scheduler journal without granting evidence authority."""

    control = Path(scratchpad) / CONTROL_DIR
    control.mkdir(parents=True, exist_ok=True)
    lock = control / CONTROL_LOCK_NAME
    descriptor: int | None = None
    owner_token = os.urandom(24).hex().encode("ascii")
    written_token = bytearray()
    owns_lock = False
    acquisition_complete = False
    try:
        descriptor = os.open(
            str(lock),
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
        )
        owns_lock = True
        while len(written_token) < len(owner_token):
            remainder = owner_token[len(written_token):]
            written = os.write(descriptor, remainder)
            if written <= 0:
                raise ChainTailAuthorityError(
                    "cannot persist chain-tail scheduler ownership token"
                )
            written_token.extend(remainder[:written])
        os.close(descriptor)
        descriptor = None
        acquisition_complete = True
        yield
    except FileExistsError as exc:
        raise ChainTailAuthorityError(
            "chain-tail scheduler mutation is already locked"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if owns_lock:
            try:
                lock_stat = lock.lstat()
            except FileNotFoundError as exc:
                raise ChainTailAuthorityError(
                    "owned chain-tail scheduler lock is missing during release"
                ) from exc
            except OSError as exc:
                raise ChainTailAuthorityError(
                    "cannot inspect owned chain-tail scheduler lock"
                ) from exc
            if not stat.S_ISREG(lock_stat.st_mode):
                raise ChainTailAuthorityError(
                    "owned chain-tail scheduler lock is not a regular file"
                )
            try:
                observed_token = lock.read_bytes()
            except OSError as exc:
                raise ChainTailAuthorityError(
                    "cannot read owned chain-tail scheduler lock"
                ) from exc
            expected_token = (
                owner_token if acquisition_complete else bytes(written_token)
            )
            if observed_token != expected_token:
                raise ChainTailAuthorityError(
                    "owned chain-tail scheduler lock ownership token changed"
                )
            try:
                lock.unlink()
            except OSError as exc:
                raise ChainTailAuthorityError(
                    "cannot release owned chain-tail scheduler lock"
                ) from exc


def _read_scheduler_journal(scratchpad: Path) -> dict[str, Any]:
    path = Path(scratchpad) / CONTROL_DIR / CONTROL_JOURNAL_NAME
    if not path.is_file():
        return {
            "schema_version": "plamen.chain_tail.scheduler_journal.v1",
            "authority": "NONE",
            "sequence": 0,
            "started_shards": {},
            "events": [],
        }
    payload = _read_json(path)
    if payload.get("schema_version") != "plamen.chain_tail.scheduler_journal.v1":
        raise ChainTailAuthorityError("chain-tail scheduler journal schema mismatch")
    if payload.get("authority") != "NONE":
        raise ChainTailAuthorityError("scheduler journal cannot claim evidence authority")
    return payload


def _write_scheduler_journal(scratchpad: Path, payload: Mapping[str, Any]) -> None:
    normalized = dict(payload)
    normalized["schema_version"] = "plamen.chain_tail.scheduler_journal.v1"
    normalized["authority"] = "NONE"
    _atomic_json(
        Path(scratchpad) / CONTROL_DIR / CONTROL_JOURNAL_NAME,
        normalized,
    )


def _publication_is_armed(scratchpad: Path) -> bool:
    marker = Path(scratchpad) / CONTROL_DIR / PUBLICATION_ARMED_NAME
    if not marker.is_file():
        return False
    try:
        payload = _read_json(marker)
    except (OSError, UnicodeError, json.JSONDecodeError, ChainTailAuthorityError):
        return False
    return bool(
        payload.get("schema_version")
        == "plamen.chain_tail.final_publication.v1"
        and payload.get("authority") == "CONTROL_ONLY"
        and payload.get("state") == "ARMED"
        and payload.get("marker_sha256") == _digest(payload, "marker_sha256")
    )


def begin_isolated_chain_tail_scheduler(scratchpad: Path) -> None:
    """Enter isolation before the first cursor/root-compatibility mutation."""

    root = Path(scratchpad)
    with _scheduler_lock(root):
        journal_path = root / CONTROL_DIR / CONTROL_JOURNAL_NAME
        if journal_path.is_file():
            _read_scheduler_journal(root)
            return
        _write_scheduler_journal(root, _read_scheduler_journal(root))


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    if not isinstance(value, dict):
        raise ChainTailAuthorityError(f"{path.name} root must be an object")
    return value


def _terminal_publication_is_complete(scratchpad: Path) -> bool:
    """Recognize only the fully materialized immutable terminal generation."""

    from artifact_ledger import (
        ArtifactLedgerError,
        _replay_output_commit_authority,
        active_committed_work_unit_authority_issues,
        read_artifact_ledger,
    )

    root = Path(scratchpad)
    try:
        snapshot = _read_json(root / TERMINAL_SNAPSHOT_NAME)
        ledger = _read_json(root / LEDGER_NAME)
        control_ledger = _read_json(
            root / CONTROL_DIR / LEDGER_NAME
        )
        receipt = _read_json(root / RECEIPT_NAME)
        candidates = _read_json(root / COMPOSITION_CANDIDATES_NAME)
        semantic_ledger = snapshot.get("semantic_ledger")
        terminal_generation = _terminal_snapshot_generation(snapshot)
        generation_id = chain_tail_generation_id(*terminal_generation)
        artifact_state = read_artifact_ledger(root)
        candidate_identity = (
            "scratchpad:chain_composition_verification_candidates.json"
        )
        candidate_binding = (
            artifact_state.get("artifact_bindings", {}).get(
                candidate_identity
            )
        )
        owner = (
            str(candidate_binding.get("owner_key") or "")
            if isinstance(candidate_binding, Mapping)
            else ""
        )
        final_unit = (
            artifact_state.get("work_units", {}).get(owner)
            if owner
            else None
        )
        snapshot_identity = (
            "scratchpad:chain_tail_terminal_snapshot.json"
        )
        snapshot_binding = (
            final_unit.get("input_bindings", {}).get(snapshot_identity)
            if isinstance(final_unit, Mapping)
            else None
        )
        final_run_id = (
            str(final_unit.get("run_id") or "")
            if isinstance(final_unit, Mapping)
            else ""
        )
        final_outputs = {
            "scratchpad:chain_tail_disposition_ledger.json",
            "scratchpad:chain_tail_coverage_receipt.json",
            candidate_identity,
            "scratchpad:chain_composition_coverage_gaps.md",
            "scratchpad:chain_iteration2.md",
            *(
                f"scratchpad:{relative}"
                for relative in MUTABLE_CONTROL_PATHS
            ),
        }
        final_authority_issues = (
            active_committed_work_unit_authority_issues(
                artifact_state,
                work_unit_key=owner,
                run_id=final_run_id,
                expected_artifact_identities=tuple(sorted(final_outputs)),
            )
            if owner and final_run_id
            else ["final publication producer authority is absent"]
        )
        if isinstance(final_unit, Mapping):
            final_authority_issues.extend(
                _replay_output_commit_authority(
                    root,
                    root.parent,
                    final_unit,
                    require_live_bytes=True,
                )
            )
        snapshot_owner = (
            str(snapshot_binding.get("producer_work_unit_key") or "")
            if isinstance(snapshot_binding, Mapping)
            else ""
        )
        final_producer_prefix = _terminal_producer_prefix(
            owner,
            role="tail_reconcile",
            generation_id=generation_id,
        )
        snapshot_producer_prefix = _terminal_producer_prefix(
            snapshot_owner,
            role="tail_snapshot",
            generation_id=generation_id,
        )
        snapshot_unit = (
            artifact_state.get("work_units", {}).get(snapshot_owner)
            if snapshot_owner
            else None
        )
        snapshot_authority_issues = (
            active_committed_work_unit_authority_issues(
                artifact_state,
                work_unit_key=snapshot_owner,
                run_id=final_run_id,
                expected_artifact_identities=(snapshot_identity,),
            )
            if snapshot_owner and final_run_id
            else ["terminal snapshot producer authority is absent"]
        )
        if isinstance(snapshot_unit, Mapping):
            snapshot_authority_issues.extend(
                _replay_output_commit_authority(
                    root,
                    root.parent,
                    snapshot_unit,
                    require_live_bytes=True,
                )
            )
        snapshot_artifact = (
            snapshot_unit.get("artifacts", {}).get(snapshot_identity)
            if isinstance(snapshot_unit, Mapping)
            else None
        )
        snapshot_commit = (
            snapshot_unit.get("commit_authority")
            if isinstance(snapshot_unit, Mapping)
            else None
        )
        committed_artifacts = (
            final_unit.get("artifacts")
            if isinstance(final_unit, Mapping)
            else None
        )
        committed_output_set_ok = bool(
            isinstance(committed_artifacts, Mapping)
            and set(committed_artifacts) == final_outputs
            and all(
                isinstance(committed_artifacts.get(identity), Mapping)
                and committed_artifacts[identity].get("status") == "ACTIVE"
                and (
                    path := root / identity.split(":", 1)[1]
                ).is_file()
                and committed_artifacts[identity].get("sha256")
                == _sha256_bytes(path.read_bytes())
                for identity in final_outputs
            )
        )
        return bool(
            snapshot.get("schema_version") == TERMINAL_SNAPSHOT_SCHEMA
            and snapshot.get("snapshot_sha256")
            == _digest(snapshot, "snapshot_sha256")
            and isinstance(semantic_ledger, Mapping)
            and _ledger_terminal_generation(ledger) == terminal_generation
            and _ledger_terminal_generation(control_ledger)
            == terminal_generation
            and ledger.get("ledger_sha256")
            == semantic_ledger.get("ledger_sha256")
            and ledger.get("ledger_sha256")
            == _digest(ledger, "ledger_sha256")
            and receipt.get("ledger_sha256") == ledger.get("ledger_sha256")
            and receipt.get("authority_digest")
            == _digest(receipt, "authority_digest")
            and candidates.get("ledger_sha256") == ledger.get("ledger_sha256")
            and candidates.get("candidate_digest")
            == _digest(candidates, "candidate_digest")
            and (root / PROJECTION_NAME).is_file()
            # A terminal publication is current only for the exact mutable
            # control generation from which it was committed.  Cursor and
            # shard history are part of that generation; normalizing either
            # would let a mutate-and-rehash control successor re-bless an
            # older root publication.
            and ledger == control_ledger
            and not (root / CONTROL_DIR / PUBLICATION_ARMED_NAME).exists()
            and isinstance(candidate_binding, Mapping)
            and final_producer_prefix == snapshot_producer_prefix
            and candidate_binding.get("writer") == "DRIVER"
            and candidate_binding.get("status") == "ACTIVE"
            and isinstance(final_unit, Mapping)
            and final_unit.get("execution_state") == "OUTPUT_COMMITTED"
            and final_unit.get("semantic_status") == "ACTIVE"
            and committed_output_set_ok
            and not final_authority_issues
            and isinstance(snapshot_binding, Mapping)
            and snapshot_binding.get("status") == "ACTIVE"
            and snapshot_binding.get("sha256")
            == _sha256_bytes((root / TERMINAL_SNAPSHOT_NAME).read_bytes())
            and snapshot_binding.get("size")
            == (root / TERMINAL_SNAPSHOT_NAME).stat().st_size
            and isinstance(snapshot_unit, Mapping)
            and snapshot_unit.get("run_id") == final_run_id
            and isinstance(snapshot_artifact, Mapping)
            and snapshot_artifact.get("sha256")
            == snapshot_binding.get("sha256")
            and snapshot_artifact.get("size")
            == snapshot_binding.get("size")
            and snapshot_binding.get("producer_run_id") == final_run_id
            and snapshot_binding.get("producer_contract_digest")
            == snapshot_unit.get("contract_digest")
            and snapshot_binding.get("producer_launch_digest")
            == snapshot_unit.get("launch_digest")
            and isinstance(snapshot_commit, Mapping)
            and snapshot_binding.get("producer_commit_receipt_digest")
            == snapshot_commit.get("receipt_digest")
            and not snapshot_authority_issues
        )
    except (
        ArtifactLedgerError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
        ChainTailAuthorityError,
    ):
        return False


def _read_progress_receipt(scratchpad: Path) -> dict[str, Any]:
    root = Path(scratchpad)
    if _terminal_publication_is_complete(root):
        return _read_json(root / RECEIPT_NAME)
    control = root / CONTROL_DIR / RECEIPT_NAME
    return _read_json(control if control.is_file() else root / RECEIPT_NAME)


def _clean_text(value: object, *, limit: int = 1000) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def _finding_id(value: object) -> str:
    result = _clean_text(value, limit=80).upper()
    try:
        from plamen_parsers import _INTERNAL_FINDING_ID_RE

        valid = bool(_INTERNAL_FINDING_ID_RE.fullmatch(result))
    except (ImportError, AttributeError):
        # Isolated migration tooling fallback. Live runs always consume the
        # canonical registry-owned grammar; the fallback grants no semantic or
        # proof authority.
        valid = bool(_FINDING_ID_FALLBACK_RE.fullmatch(result))
    if not valid:
        raise ChainTailAuthorityError(f"invalid finding identity: {value!r}")
    return result


def _finding_ids_in_text(value: object) -> list[str]:
    text = str(value or "")
    try:
        from plamen_parsers import _INTERNAL_FINDING_ID_RE

        return list(dict.fromkeys(
            match.group(1).upper()
            for match in _INTERNAL_FINDING_ID_RE.finditer(text)
        ))
    except (ImportError, AttributeError):
        return list(dict.fromkeys(
            match.group(0).upper()
            for match in re.finditer(
                r"(?<![A-Za-z0-9_-])[A-Z][A-Z0-9_-]{1,95}(?![A-Za-z0-9_-])",
                text,
                re.I | re.ASCII,
            )
            if _FINDING_ID_FALLBACK_RE.fullmatch(match.group(0))
        ))


def _signal_family(row: Mapping[str, Any]) -> str:
    explicit = re.sub(
        r"[^a-z0-9_-]+", "-", _clean_text(row.get("signal_family"), limit=80).lower()
    ).strip("-")
    if explicit:
        return explicit
    signal = _clean_text(row.get("signal"), limit=1000).lower()
    for prefix, family in (
        ("state-graph:", "state-graph"),
        ("state-fallback:", "state-fallback"),
        ("role:", "semantic-role"),
        ("ident:", "identifier"),
        ("discovery:", "discovery"),
        ("co-located", "proximity"),
    ):
        if signal.startswith(prefix):
            return family
    return "other-real-signal"


def _stable_graph_identities(row: Mapping[str, Any]) -> tuple[str, ...]:
    explicit = row.get("graph_identities")
    if isinstance(explicit, list):
        return tuple(sorted({_clean_text(value, limit=200) for value in explicit if _clean_text(value)}))
    signal = _clean_text(row.get("signal"), limit=1000)
    if signal.lower().startswith("state-graph:"):
        values = signal.split(":", 1)[1]
        return tuple(sorted({_clean_text(value, limit=200) for value in values.split(",") if _clean_text(value)}))
    return ()


def _normalize_pair_rows(rows: Iterable[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    result: list[dict[str, Any]] = []
    occurrences: Counter[str] = Counter()
    family_members: dict[str, list[str]] = defaultdict(list)
    family_meta: dict[str, dict[str, Any]] = {}
    for ordinal, source in enumerate(rows):
        if not isinstance(source, Mapping):
            raise ChainTailAuthorityError(f"pair row {ordinal} is not an object")
        a = _finding_id(source.get("a"))
        b = _finding_id(source.get("b"))
        if a == b:
            raise ChainTailAuthorityError(f"self-pair is not a composition pair: {a}")
        signal = _clean_text(source.get("signal"), limit=1000)
        if not signal:
            raise ChainTailAuthorityError(f"pair {a}/{b} lacks a real signal")
        signal_family = _signal_family(source)
        graph_ids = _stable_graph_identities(source)
        base_payload = {
            "a": a,
            "b": b,
            "a_sev": _clean_text(source.get("a_sev"), limit=40),
            "b_sev": _clean_text(source.get("b_sev"), limit=40),
            "signal": signal,
            "signal_family": signal_family,
            "graph_identities": list(graph_ids),
        }
        base_digest = _sha256_bytes(_canonical_bytes(base_payload))[:16].upper()
        occurrence = occurrences[base_digest]
        occurrences[base_digest] += 1
        pair_id = f"CP-{base_digest}-{occurrence:03d}"
        canonical_endpoints = tuple(sorted((a, b)))
        explicit_family = _clean_text(source.get("equivalence_key"), limit=300)
        family_seed = {
            "equivalence_key": explicit_family,
            # Compiler/AST graph identities are the stable equivalence-family
            # key across distinct endpoint pairs. Endpoint identity is retained
            # only for lower-confidence non-graph signals. Every pair remains a
            # ledger member and is still independently dispositioned, so this
            # work-family relation never becomes semantic disposition authority.
            "endpoints": (
                [] if explicit_family or graph_ids else list(canonical_endpoints)
            ),
            "signal_family": signal_family,
            "graph_identities": list(graph_ids),
        }
        family_id = "CF-" + _sha256_bytes(_canonical_bytes(family_seed))[:16].upper()
        normalized = {
            "pair_id": pair_id,
            "ordinal": ordinal,
            "a": a,
            "b": b,
            "canonical_endpoints": list(canonical_endpoints),
            "a_sev": _clean_text(source.get("a_sev"), limit=40),
            "b_sev": _clean_text(source.get("b_sev"), limit=40),
            "signal": signal,
            "signal_family": signal_family,
            "graph_identities": list(graph_ids),
            "graph_backed": bool(source.get("graph_backed") or graph_ids),
            "score": float(source.get("score", 0.0) or 0.0),
            "family_id": family_id,
            "initial_route": _clean_text(
                source.get("initial_route"), limit=80
            ).upper() or "CHAIN_ITER2",
        }
        result.append(normalized)
        family_members[family_id].append(pair_id)
        family_meta.setdefault(
            family_id,
            {
                "family_id": family_id,
                "signal_family": signal_family,
                "graph_identities": list(graph_ids),
                "member_pair_ids": [],
            },
        )
    for family_id, members in family_members.items():
        family_meta[family_id]["member_pair_ids"] = members
    return result, dict(sorted(family_meta.items()))


def _manifest_from_rows(rows: Iterable[Mapping[str, Any]], shard_size: int) -> dict[str, Any]:
    if not isinstance(shard_size, int) or not 1 <= shard_size <= 100:
        raise ChainTailAuthorityError("shard_size must be between 1 and 100")
    pairs, families = _normalize_pair_rows(rows)
    manifest: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA,
        "denominator": len(pairs),
        "shard_size": shard_size,
        "pairs": pairs,
        "families": families,
        # Compatibility views are non-authoritative.  They keep older prompt
        # builders/readers functional during the v1 -> v2 cutover.
        "packet": pairs[:shard_size],
        "overflow": pairs[shard_size:],
    }
    manifest["manifest_sha256"] = _digest(manifest, "manifest_sha256")
    return manifest


def _initial_ledger(manifest: Mapping[str, Any]) -> dict[str, Any]:
    pairs = [
        {
            "pair_id": row["pair_id"],
            "ordinal": row["ordinal"],
            "a": row["a"],
            "b": row["b"],
            "signal_family": row["signal_family"],
            "family_id": row["family_id"],
            "resolved_family_id": row["family_id"],
            "disposition": "UNRESOLVED_COMPOSITION",
            "reason": "PENDING_ANALYSIS",
            "evidence": "",
            "chain_id": "",
            "attempts": 0,
            "last_shard_index": None,
            "output_sha256": "",
            "initial_route": row.get("initial_route", "CHAIN_ITER2"),
        }
        for row in manifest.get("pairs", [])
    ]
    ledger: dict[str, Any] = {
        "schema_version": LEDGER_SCHEMA,
        "manifest_sha256": manifest["manifest_sha256"],
        "denominator": manifest["denominator"],
        "shard_size": manifest["shard_size"],
        "cursor": 0,
        "pass_index": 0,
        "active_shard": None,
        "retry_pair_ids": [],
        "retry_cursor": 0,
        "pairs": pairs,
        "shards": [],
        "issues": [],
        "budget_stop_reason": "",
    }
    ledger["ledger_sha256"] = _digest(ledger, "ledger_sha256")
    return ledger


def _write_ledger(path: Path, ledger: dict[str, Any]) -> None:
    ledger["ledger_sha256"] = _digest(ledger, "ledger_sha256")
    root = path.parent
    control_path = root / CONTROL_DIR / LEDGER_NAME
    _atomic_json(control_path, ledger)
    if (
        not (root / CONTROL_DIR / CONTROL_JOURNAL_NAME).is_file()
        or _publication_is_armed(root)
    ):
        _atomic_json(path, ledger)


def _load_manifest_ledger(scratchpad: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    root = Path(scratchpad)
    root_manifest_path = root / MANIFEST_NAME
    control_manifest_path = root / CONTROL_MANIFEST_PATH
    manifest_path = (
        control_manifest_path
        if control_manifest_path.is_file()
        else root_manifest_path
    )
    manifest = _read_json(manifest_path)
    if control_manifest_path.is_file():
        if not root_manifest_path.is_file():
            raise ChainTailAuthorityError(
                "chain-tail root manifest compatibility projection is missing"
            )
        if root_manifest_path.read_bytes() != control_manifest_path.read_bytes():
            raise ChainTailAuthorityError(
                "chain-tail root/control manifest byte parity mismatch"
            )
    control_ledger = root / CONTROL_DIR / LEDGER_NAME
    isolated_shard_parent = root / SHARD_ARCHIVE_DIR
    isolated_shard_dirs = bool(
        isolated_shard_parent.is_dir()
        and any(
            candidate.is_dir()
            and re.fullmatch(r"shard_\d{4}", candidate.name)
            for candidate in isolated_shard_parent.iterdir()
        )
    )
    isolated_scheduler = (
        root / CONTROL_DIR / CONTROL_JOURNAL_NAME
    ).is_file() or _publication_is_armed(root) or isolated_shard_dirs
    ledger = _read_json(
        root / LEDGER_NAME
        if _terminal_publication_is_complete(root)
        else (
            control_ledger
            if isolated_scheduler and control_ledger.is_file()
            else root / LEDGER_NAME
        )
    )
    if manifest.get("schema_version") != MANIFEST_SCHEMA:
        raise ChainTailAuthorityError("chain-tail manifest schema mismatch")
    if manifest.get("manifest_sha256") != _digest(manifest, "manifest_sha256"):
        raise ChainTailAuthorityError("chain-tail manifest digest mismatch")
    if ledger.get("schema_version") != LEDGER_SCHEMA:
        raise ChainTailAuthorityError("chain-tail ledger schema mismatch")
    if ledger.get("ledger_sha256") != _digest(ledger, "ledger_sha256"):
        raise ChainTailAuthorityError("chain-tail ledger digest mismatch")
    if ledger.get("manifest_sha256") != manifest.get("manifest_sha256"):
        raise ChainTailAuthorityError("chain-tail ledger is stale for manifest")
    return manifest, ledger


def chain_tail_control_generation(scratchpad: Path) -> tuple[int, int]:
    """Return terminal-ready authoritative control G=(pass, shards)."""

    manifest, ledger = _load_manifest_ledger(Path(scratchpad))
    pairs = ledger.get("pairs")
    retry_ids = ledger.get("retry_pair_ids")
    cursor = ledger.get("cursor")
    retry_cursor = ledger.get("retry_cursor")
    denominator = manifest.get("denominator")
    if (
        ledger.get("active_shard") is not None
        or not isinstance(pairs, list)
        or type(denominator) is not int
        or denominator != len(pairs)
        or type(cursor) is not int
        or not 0 <= cursor <= denominator
        or not isinstance(retry_ids, list)
        or type(retry_cursor) is not int
        or not 0 <= retry_cursor <= len(retry_ids)
    ):
        raise ChainTailAuthorityError(
            "chain-tail terminal generation is not quiescent and bounded"
        )
    return _ledger_terminal_generation(ledger)


def _write_shard_projection(
    scratchpad: Path, manifest: Mapping[str, Any], active: Mapping[str, Any]
) -> tuple[str, str]:
    by_id = {row["pair_id"]: row for row in manifest.get("pairs", [])}
    rows = [by_id[pair_id] for pair_id in active.get("pair_ids", [])]
    lines = [
        "# Chain Candidate Pairs — Iteration 2 Bounded Shard",
        "",
        "**Status**: MECHANICAL_TAIL_SHARD",
        f"**Authoritative manifest SHA-256**: `{manifest['manifest_sha256']}`",
        f"**Exact denominator**: {manifest['denominator']}",
        f"**Shard index**: {active['shard_index']}",
        f"**Cursor**: {active['cursor_start']}..{active['cursor_end']}",
        f"**Shard pairs**: {len(rows)}",
        "",
        "Analyze every row. Pair ID is the exact join key. Emit one row under",
        "`## Tail Pair Dispositions` with columns `Pair ID | Finding A | Finding B | Disposition | Evidence`.",
        "A COMPOSED row must cite the new `CH-N` identity; it remains unproven and routes to ordinary verification.",
        "",
        "| Pair ID | Finding A | A Severity | Finding B | B Severity | Signal Family | Real Signal | Family ID |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        signal = str(row["signal"]).replace("|", "/")
        lines.append(
            f"| {row['pair_id']} | {row['a']} | {row['a_sev']} | {row['b']} | "
            f"{row['b_sev']} | {row['signal_family']} | {signal} | {row['family_id']} |"
        )
    if not rows:
        lines.append("| (none) | - | - | - | - | - | - | - |")
    rendered = "\n".join(lines) + "\n"
    root = Path(scratchpad)
    # The root file is a compatibility projection owned by the initialization
    # generation and, later, final publication.  Isolated scheduling uses only
    # immutable shard-local packets, so advancing a cursor must not mutate the
    # root predecessor behind PhaseIO's back.
    if (
        not (root / CONTROL_DIR / CONTROL_JOURNAL_NAME).is_file()
        or _publication_is_armed(root)
    ):
        _atomic_text(root / SHARD_PROJECTION_NAME, rendered)
    archive_relative = (
        f"{SHARD_ARCHIVE_DIR}/shard_{int(active['shard_index']):04d}.input.md"
    )
    _atomic_text(root / archive_relative, rendered)
    return archive_relative, _sha256_bytes(rendered.encode("utf-8"))


def _summary_counts(ledger: Mapping[str, Any]) -> tuple[Counter[str], Counter[str], Counter[str]]:
    dispositions: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    signals: Counter[str] = Counter()
    for row in ledger.get("pairs", []):
        dispositions[str(row.get("disposition") or "UNKNOWN")] += 1
        if row.get("disposition") == "UNRESOLVED_COMPOSITION":
            reasons[str(row.get("reason") or "UNKNOWN")] += 1
        signals[str(row.get("signal_family") or "unknown")] += 1
    return dispositions, reasons, signals


def _semantic_status(
    manifest: Mapping[str, Any], ledger: Mapping[str, Any]
) -> str:
    """Derive phase truth from typed state, never from a receipt assertion."""
    denominator = int(manifest.get("denominator") or 0)
    dispositions, _, _ = _summary_counts(ledger)
    unresolved = int(dispositions["UNRESOLVED_COMPOSITION"])
    cursor = int(ledger.get("cursor") or 0)
    retry_cursor = int(ledger.get("retry_cursor") or 0)
    retry_ids = list(ledger.get("retry_pair_ids") or [])
    active = ledger.get("active_shard")
    issues = {str(value) for value in ledger.get("issues", []) if value}

    # A budget stop is an explicit persistent state, not an optional receipt
    # label. It takes precedence over cursor-derived continuation because the
    # driver deliberately stopped scheduling more shards for this run.
    if str(ledger.get("budget_stop_reason") or ""):
        status = "BUDGET_STOP"
    elif denominator == 0:
        status = "COMPLETE"
    elif isinstance(active, Mapping):
        status = "PENDING"
    elif cursor < denominator or retry_cursor < len(retry_ids):
        status = "CONTINUE"
    elif unresolved:
        status = "DEGRADED_UNRESOLVED"
    else:
        status = "COMPLETE"
    if status == "COMPLETE" and "WORKER_MECHANICAL_COUNT_MISMATCH" in issues:
        return "DEGRADED_ASSURANCE_MISMATCH"
    return status


def _receipt_from_state(
    manifest: Mapping[str, Any],
    ledger: Mapping[str, Any],
    *,
    status_override: str = "",
    last_mechanical_count: int | None = None,
    last_worker_claim: int | None = None,
) -> dict[str, Any]:
    dispositions, reasons, signals = _summary_counts(ledger)
    terminal = sum(dispositions[value] for value in _TERMINAL)
    unresolved = dispositions["UNRESOLVED_COMPOSITION"]
    attempted = sum(1 for row in ledger.get("pairs", []) if int(row.get("attempts") or 0) > 0)
    cursor = int(ledger.get("cursor") or 0)
    active = ledger.get("active_shard")
    issues = list(dict.fromkeys(str(value) for value in ledger.get("issues", []) if value))
    worker_mechanical_mismatch = bool(
        "WORKER_MECHANICAL_COUNT_MISMATCH" in issues
        or (
            last_worker_claim is not None
            and last_worker_claim != (last_mechanical_count or 0)
        )
    )
    status = status_override or _semantic_status(manifest, ledger)
    if status == "COMPLETE" and worker_mechanical_mismatch:
        status = "DEGRADED_ASSURANCE_MISMATCH"
    if last_worker_claim is None:
        last_worker_claim = None
    if last_mechanical_count is None:
        last_mechanical_count = 0
    receipt: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA,
        "status": status,
        "manifest_sha256": manifest["manifest_sha256"],
        "ledger_sha256": ledger["ledger_sha256"],
        "ledger_path": LEDGER_NAME,
        "denominator": manifest["denominator"],
        "cursor": cursor,
        "active_shard_index": (
            active.get("shard_index") if isinstance(active, Mapping) else None
        ),
        "processed_pairs": attempted,
        "terminal_pairs": terminal,
        "unresolved_pairs": unresolved,
        "remaining_unattempted_pairs": sum(
            1 for row in ledger.get("pairs", []) if int(row.get("attempts") or 0) == 0
        ),
        "family_count": len(manifest.get("families", {})),
        "disposition_counts": dict(sorted(dispositions.items())),
        "unresolved_reason_counts": dict(sorted(reasons.items())),
        "signal_family_counts": dict(sorted(signals.items())),
        "worker_claimed_pairs": last_worker_claim,
        "mechanical_consumed_pairs": last_mechanical_count,
        "worker_mechanical_mismatch": worker_mechanical_mismatch,
        "budget_stop_reason": str(ledger.get("budget_stop_reason") or ""),
        "budget_stop_unexamined_pair_ids": [
            str(row.get("pair_id") or "")
            for row in ledger.get("pairs", [])
            if str(row.get("reason") or "") == "BUDGET_STOP_UNEXAMINED"
        ],
        "pass_index": int(ledger.get("pass_index") or 0),
        "retry_pair_ids": [
            str(value) for value in ledger.get("retry_pair_ids", [])
        ],
        "retry_cursor": int(ledger.get("retry_cursor") or 0),
        "issues": issues,
        "proof_authority": "NONE",
        "new_compositions_route": "ORDINARY_VERIFICATION",
    }
    receipt["authority_digest"] = _digest(receipt, "authority_digest")
    return receipt


def _projection_mark(receipt: Mapping[str, Any]) -> str:
    projection = {
        "schema": "plamen.chain_tail_client_projection.v1",
        "authority_digest": receipt.get("authority_digest"),
        "manifest_sha256": receipt.get("manifest_sha256"),
        "ledger_sha256": receipt.get("ledger_sha256"),
        "denominator": receipt.get("denominator"),
        "terminal_pairs": receipt.get("terminal_pairs"),
        "unresolved_pairs": receipt.get("unresolved_pairs"),
        "status": receipt.get("status"),
    }
    return json.dumps(projection, sort_keys=True, separators=(",", ":"))


def _render_projection(
    receipt: Mapping[str, Any], ledger: Mapping[str, Any] | None
) -> str:
    status = str(receipt.get("status") or "UNKNOWN")
    denominator = int(receipt.get("denominator") or 0)
    terminal = int(receipt.get("terminal_pairs") or 0)
    unresolved = int(receipt.get("unresolved_pairs") or 0)
    lines = [
        "# Chain Composition Coverage Assurance",
        "",
        f"**Status**: {status}",
        f"**Exact denominator**: {denominator}",
        f"**Terminal semantic dispositions**: {terminal}",
        f"**Explicit unresolved-composition candidates**: {unresolved}",
        f"**Full ledger**: `{LEDGER_NAME}`",
        f"**Ledger SHA-256**: `{receipt.get('ledger_sha256', '')}`",
        f"**Manifest SHA-256**: `{receipt.get('manifest_sha256', '')}`",
        f"**Authority digest**: `{receipt.get('authority_digest', '')}`",
        "",
        "The machine ledger is the lossless authority. This client projection is",
        "bounded and reports aggregate debt plus representative samples; omission",
        "from the sample is not a safe/no-signal disposition.",
    ]
    if receipt.get("worker_mechanical_mismatch"):
        lines.extend((
            "",
            "**Worker/mechanical mismatch**: the worker claimed "
            f"{receipt.get('worker_claimed_pairs')} covered while the manifest-bound "
            f"consumer accepted {receipt.get('mechanical_consumed_pairs')}. "
            "Delivered assurance remains degraded.",
        ))
    if receipt.get("budget_stop_reason"):
        lines.extend((
            "",
            "**Assurance limitation**: deterministic processing stopped at the "
            f"declared budget (`{receipt.get('budget_stop_reason')}`); exact remaining "
            "identities remain unresolved in the full ledger.",
        ))
    reasons = receipt.get("unresolved_reason_counts") or {}
    lines.extend(("", "## Aggregate unresolved debt", "", "| Reason | Count |", "|---|---:|"))
    if reasons:
        for reason, count in sorted(reasons.items()):
            lines.append(f"| {str(reason).replace('|', '/')} | {int(count)} |")
    else:
        lines.append("| (none) | 0 |")
    signals = receipt.get("signal_family_counts") or {}
    lines.extend(("", "## Signal-family denominator", "", "| Signal family | Count |", "|---|---:|"))
    if signals:
        for family, count in sorted(signals.items()):
            lines.append(f"| {str(family).replace('|', '/')} | {int(count)} |")
    else:
        lines.append("| (none) | 0 |")
    samples: list[Mapping[str, Any]] = []
    if ledger:
        samples = [
            row for row in ledger.get("pairs", [])
            if row.get("disposition") == "UNRESOLVED_COMPOSITION"
        ][:DEFAULT_PROJECTION_SAMPLE_ROWS]
    lines.extend((
        "",
        f"## Representative unresolved samples (max {DEFAULT_PROJECTION_SAMPLE_ROWS})",
        "",
        "| Pair ID | Finding A | Finding B | Signal family | Reason |",
        "|---|---|---|---|---|",
    ))
    if samples:
        for row in samples:
            lines.append(
                f"| {row.get('pair_id')} | {row.get('a')} | {row.get('b')} | "
                f"{str(row.get('signal_family') or '').replace('|', '/')} | "
                f"{str(row.get('reason') or '').replace('|', '/')} |"
            )
    else:
        lines.append("| (none) | - | - | - | - |")
    lines.extend(("", f"<!-- PLAMEN_CHAIN_TAIL_SUMMARY {_projection_mark(receipt)} -->", ""))
    rendered = "\n".join(lines)
    if len(rendered.encode("utf-8")) > DEFAULT_PROJECTION_BYTE_CEILING:
        raise ChainTailAuthorityError("bounded chain-tail projection exceeds byte ceiling")
    return rendered


def _write_receipt_and_projection(
    scratchpad: Path,
    manifest: Mapping[str, Any],
    ledger: Mapping[str, Any],
    *,
    status_override: str = "",
    last_mechanical_count: int | None = None,
    last_worker_claim: int | None = None,
) -> dict[str, Any]:
    receipt = _receipt_from_state(
        manifest,
        ledger,
        status_override=status_override,
        last_mechanical_count=last_mechanical_count,
        last_worker_claim=last_worker_claim,
    )
    root = Path(scratchpad)
    rendered = _render_projection(receipt, ledger)
    _atomic_json(root / CONTROL_DIR / RECEIPT_NAME, receipt)
    _atomic_text(root / CONTROL_DIR / PROJECTION_NAME, rendered)
    if (
        not (root / CONTROL_DIR / CONTROL_JOURNAL_NAME).is_file()
        or _publication_is_armed(root)
    ):
        _atomic_json(root / RECEIPT_NAME, receipt)
        _atomic_text(root / PROJECTION_NAME, rendered)
    return receipt


def initialize_chain_tail(
    scratchpad: Path,
    rows: Iterable[Mapping[str, Any]],
    *,
    shard_size: int = DEFAULT_SHARD_SIZE,
    activate_first_shard: bool = True,
) -> dict[str, Any]:
    scratchpad = Path(scratchpad)
    manifest = _manifest_from_rows(rows, shard_size)
    ledger = _initial_ledger(manifest)
    _atomic_json(scratchpad / MANIFEST_NAME, manifest)
    # This byte-identical, single-output authority is immutable for the entire
    # tail lifecycle.  Downstream work binds it instead of the root
    # compatibility manifest whose initialization producer also owns root
    # presentation outputs that final publication will replace.
    _atomic_json(scratchpad / CONTROL_MANIFEST_PATH, manifest)
    _write_ledger(scratchpad / LEDGER_NAME, ledger)
    candidate_payload: dict[str, Any] = {
        "schema_version": CANDIDATE_SCHEMA,
        "manifest_sha256": manifest["manifest_sha256"],
        "ledger_sha256": ledger["ledger_sha256"],
        "proof_authority": "NONE",
        "candidates": [],
    }
    candidate_payload["candidate_digest"] = _digest(
        candidate_payload, "candidate_digest"
    )
    _atomic_json(
        scratchpad / CONTROL_DIR / COMPOSITION_CANDIDATES_NAME,
        candidate_payload,
    )
    if manifest["denominator"] and activate_first_shard:
        prepare_next_chain_tail_shard(scratchpad)
        manifest, ledger = _load_manifest_ledger(scratchpad)
    else:
        _write_shard_projection(
            scratchpad,
            manifest,
            {"shard_index": 0, "cursor_start": 0, "cursor_end": 0, "pair_ids": []},
        )
    receipt = _write_receipt_and_projection(scratchpad, manifest, ledger)
    # One conservative compatibility snapshot is published at initialization.
    # It remains visibly unresolved/CONTINUE and is never mutated by shard
    # scheduling.  Final publication replaces it only after PhaseIO pre-arm.
    _atomic_json(scratchpad / LEDGER_NAME, ledger)
    _atomic_json(scratchpad / RECEIPT_NAME, receipt)
    _atomic_text(scratchpad / PROJECTION_NAME, _render_projection(receipt, ledger))
    _atomic_json(scratchpad / COMPOSITION_CANDIDATES_NAME, candidate_payload)
    return receipt


def ingest_primary_chain_coverage(
    scratchpad: Path,
    *,
    activate_next_shard: bool = True,
) -> dict[str, Any]:
    """Consume Chain Agent 2's bounded coverage without trusting prose scope.

    Only manifest rows explicitly routed to ``CHAIN_AGENT2`` are eligible.
    Exact endpoint matching is required; duplicate rows, missing evidence, NO,
    and schema drift remain unresolved for the normal typed shard loop.
    """
    scratchpad = Path(scratchpad)
    manifest, ledger = _load_manifest_ledger(scratchpad)
    coverage_path = scratchpad / "composition_coverage.md"
    chain_path = scratchpad / "chain_hypotheses.md"
    # Provenance is byte-exact.  Decode only a parsing view; never re-encode it
    # for authority because universal-newline translation would make an
    # unchanged CRLF producer disagree with the later raw-byte snapshot gate.
    coverage_bytes = coverage_path.read_bytes() if coverage_path.exists() else b""
    chain_bytes = chain_path.read_bytes() if chain_path.exists() else b""
    # Parsing may use a newline-normalized view; authority hashes stay over
    # the untouched producer bytes above.
    coverage_text = coverage_bytes.decode(
        "utf-8", errors="replace"
    ).replace("\r\n", "\n").replace("\r", "\n")
    chain_text = chain_bytes.decode(
        "utf-8", errors="replace"
    ).replace("\r\n", "\n").replace("\r", "\n")
    source_sha = _sha256_bytes(coverage_bytes)
    chain_sha = _sha256_bytes(chain_bytes)
    prior_primary = ledger.get("primary_coverage")
    if (
        isinstance(prior_primary, Mapping)
        and prior_primary.get("input_sha256") == source_sha
        and prior_primary.get("chain_hypotheses_sha256") == chain_sha
    ):
        receipt = _read_progress_receipt(scratchpad)
        if (
            receipt.get("manifest_sha256") == manifest.get("manifest_sha256")
            and receipt.get("ledger_sha256") == ledger.get("ledger_sha256")
            and receipt.get("authority_digest") == _digest(receipt, "authority_digest")
        ):
            if (
                activate_next_shard
                and
                receipt.get("status") == "CONTINUE"
                and not isinstance(ledger.get("active_shard"), dict)
            ):
                prepare_next_chain_tail_shard(scratchpad)
                return _read_progress_receipt(scratchpad)
            return receipt
    chain_ids = {match.group(1).upper() for match in _CHAIN_HEADING_RE.finditer(chain_text)}
    table_rows: list[dict[str, str]] = []
    lines = [line.strip() for line in coverage_text.splitlines() if line.strip().startswith("|")]
    header: dict[str, int] | None = None
    for line in lines:
        cells = [cell.strip().strip("`*") for cell in line.strip("|").split("|")]
        normalized = [_normalize_header(cell) for cell in cells]
        if header is None and all(
            name in normalized for name in ("findinga", "findingb", "explored", "result")
        ):
            header = {
                "a": normalized.index("findinga"),
                "b": normalized.index("findingb"),
                "explored": normalized.index("explored"),
                "result": normalized.index("result"),
                "notes": normalized.index("notes") if "notes" in normalized else -1,
            }
            continue
        if header is None or (cells and all(not cell or set(cell) <= {"-", ":", " "} for cell in cells)):
            continue
        if max(value for value in header.values() if value >= 0) >= len(cells):
            continue
        table_rows.append({
            "a": cells[header["a"]],
            "b": cells[header["b"]],
            "explored": cells[header["explored"]],
            "result": cells[header["result"]],
            "notes": cells[header["notes"]] if header["notes"] >= 0 else "",
        })
    eligible = [
        row for row in manifest.get("pairs", [])
        if row.get("initial_route") == "CHAIN_AGENT2"
    ]
    if not eligible:
        receipt = _read_progress_receipt(scratchpad)
        if (
            activate_next_shard
            and
            receipt.get("status") == "CONTINUE"
            and not isinstance(ledger.get("active_shard"), dict)
        ):
            prepare_next_chain_tail_shard(scratchpad)
            return _read_progress_receipt(scratchpad)
        return receipt
    matches: dict[str, list[dict[str, str]]] = defaultdict(list)
    for parsed in table_rows:
        # Primary Markdown predates Pair IDs, so bind only an unambiguous exact
        # endpoint pair.  Ambiguous aliases remain typed unresolved work.
        left_ids = _finding_ids_in_text(parsed["a"])
        right_ids = _finding_ids_in_text(parsed["b"])
        if len(left_ids) != 1 or len(right_ids) != 1:
            continue
        endpoints = {left_ids[0], right_ids[0]}
        candidates = [
            row for row in eligible
            if set((row["a"], row["b"])) == endpoints
        ]
        if len(candidates) == 1:
            matches[candidates[0]["pair_id"]].append(parsed)
    by_id = {row["pair_id"]: row for row in ledger.get("pairs", [])}
    consumed = 0
    issues: list[str] = []
    for manifest_row in eligible:
        row = by_id[manifest_row["pair_id"]]
        if row.get("disposition") in _TERMINAL:
            continue
        candidates = matches.get(row["pair_id"], [])
        if len(candidates) != 1:
            row["reason"] = (
                "PRIMARY_COVERAGE_DUPLICATE_ROWS" if len(candidates) > 1
                else "PRIMARY_COVERAGE_MISSING_ROW"
            )
            continue
        parsed = candidates[0]
        explored = _normalize_disposition(parsed["explored"])
        evidence = _clean_text(
            f"{parsed['result']}; {parsed['notes']}", limit=1000
        ).strip("; ")
        if explored not in {"YES", "TRUE", "EXPLORED"} or not evidence or evidence in {"-", "—", "n/a", "N/A"}:
            row["reason"] = "PRIMARY_COVERAGE_NOT_TERMINAL"
            continue
        chain_match = _CHAIN_ID_RE.search(parsed["result"] + " " + parsed["notes"])
        if chain_match:
            chain_id = chain_match.group(0).upper()
            if chain_id not in chain_ids:
                row["reason"] = "PRIMARY_COMPOSED_CHAIN_MISSING"
                issues.append("PRIMARY_COMPOSED_CHAIN_MISSING")
                continue
            disposition = "COMPOSED"
        else:
            chain_id = ""
            disposition = (
                "REJECTED"
                if re.search(r"(?i)\b(?:no\s+(?:chain|match|composition)|invalid|rejected|independent)\b", evidence)
                else "EXPLORED"
            )
        row.update({
            "disposition": disposition,
            "reason": "",
            "evidence": evidence,
            "chain_id": chain_id,
            "attempts": max(1, int(row.get("attempts") or 0)),
            "last_shard_index": -1,
            "output_sha256": source_sha,
        })
        consumed += 1
    # Manifest order starts with the primary bounded set. Advance past every
    # exact terminal row; the first unresolved identity becomes shard zero.
    cursor = 0
    for row in ledger.get("pairs", []):
        if row.get("disposition") not in _TERMINAL:
            break
        cursor += 1
    ledger["cursor"] = cursor
    ledger["issues"] = list(dict.fromkeys([*ledger.get("issues", []), *issues]))
    ledger["primary_coverage"] = {
        "input_path": "composition_coverage.md",
        "input_sha256": source_sha,
        "chain_hypotheses_sha256": chain_sha,
        "eligible_pairs": len(eligible),
        "consumed_pairs": consumed,
    }
    _split_divergent_families(ledger)
    _write_ledger(scratchpad / LEDGER_NAME, ledger)
    manifest, ledger = _load_manifest_ledger(scratchpad)
    _write_composition_candidates(scratchpad, manifest, ledger)
    receipt = _write_receipt_and_projection(
        scratchpad, manifest, ledger, last_mechanical_count=consumed
    )
    if (
        activate_next_shard
        and not isinstance(ledger.get("active_shard"), dict)
        and receipt.get("status") == "CONTINUE"
    ):
        prepare_next_chain_tail_shard(scratchpad)
        receipt = _read_progress_receipt(scratchpad)
    return receipt


def write_primary_chain_tail_receipt(
    scratchpad: Path,
    *,
    chain_agent2_model_binding: Mapping[str, Any],
) -> dict[str, Any]:
    """Project primary reconciliation into a typed DRIVER-owned output."""

    root = Path(scratchpad)
    if not isinstance(chain_agent2_model_binding, Mapping) or not (
        chain_agent2_model_binding.get("work_unit_key")
        and chain_agent2_model_binding.get("contract_digest")
        and chain_agent2_model_binding.get("input_set_digest")
        and chain_agent2_model_binding.get("output_digests")
    ):
        raise ChainTailAuthorityError(
            "primary receipt requires exact ChainAgent2 MODEL producer binding"
        )
    manifest, ledger = _load_manifest_ledger(root)
    primary = ledger.get("primary_coverage")
    if not isinstance(primary, Mapping):
        primary = {
            "input_path": "composition_coverage.md",
            "input_sha256": _sha256_bytes(
                (root / "composition_coverage.md").read_bytes()
            ),
            "chain_hypotheses_sha256": _sha256_bytes(
                (root / "chain_hypotheses.md").read_bytes()
            ),
            "eligible_pairs": 0,
            "consumed_pairs": 0,
        }
    eligible_ids = {
        str(row.get("pair_id"))
        for row in manifest.get("pairs") or []
        if isinstance(row, Mapping)
        and row.get("initial_route") == "CHAIN_AGENT2"
    }
    pair_results = [
        {
            key: row.get(key)
            for key in (
                "pair_id",
                "disposition",
                "reason",
                "evidence",
                "chain_id",
                "attempts",
                "last_shard_index",
                "output_sha256",
            )
        }
        for row in ledger.get("pairs") or []
        if isinstance(row, Mapping)
        and str(row.get("pair_id")) in eligible_ids
        and row.get("disposition") in _TERMINAL
        and int(row.get("last_shard_index") if row.get("last_shard_index") is not None else -1) == -1
    ]
    payload: dict[str, Any] = {
        "schema_version": "plamen.chain_tail.primary_receipt.v1",
        "authority": "DRIVER_RECONCILIATION",
        "manifest_sha256": manifest["manifest_sha256"],
        "composition_coverage_sha256": str(primary.get("input_sha256") or ""),
        "chain_hypotheses_sha256": str(
            primary.get("chain_hypotheses_sha256") or ""
        ),
        "eligible_pair_ids": sorted(eligible_ids),
        "pair_results": pair_results,
        "consumed_pairs": len(pair_results),
        "chain_agent2_model_binding": dict(chain_agent2_model_binding),
    }
    payload["receipt_sha256"] = _digest(payload, "receipt_sha256")
    _atomic_json(root / PRIMARY_RECEIPT_NAME, payload)
    return payload


def build_chain_tail_terminal_snapshot(scratchpad: Path) -> dict[str, Any]:
    """Freeze final semantics from committed-receipt inputs, never control bytes.

    PhaseIO producer validation is deliberately performed by the driver before
    this renderer runs.  This function accepts no ancestry claims from the
    receipts themselves; it only reconstructs pair semantics and transcript
    lineage from their digest-bound contents.
    """

    root = Path(scratchpad)
    manifest, control_ledger = _load_manifest_ledger(root)
    terminal_pass_index, terminal_shard_count = (
        _ledger_terminal_generation(control_ledger)
    )
    reconstructed = _initial_ledger(manifest)
    reconstructed["active_shard"] = None
    reconstructed["cursor"] = 0
    # Pass identity is scheduler state rather than pair semantics. Preserve it
    # for every terminal status, not only BUDGET_STOP, so a successful retry
    # can never publish itself again as generation zero.
    reconstructed["pass_index"] = terminal_pass_index
    reconstructed["issues"] = []
    reconstructed["shards"] = []
    by_id = {
        str(row.get("pair_id")): row
        for row in reconstructed.get("pairs") or []
    }
    terminal_records: list[dict[str, Any]] = []
    progress_receipt = _read_progress_receipt(root)
    if (
        type(progress_receipt.get("pass_index")) is not int
        or progress_receipt.get("pass_index") != terminal_pass_index
    ):
        raise ChainTailAuthorityError(
            "chain-tail progress receipt terminal generation mismatch"
        )

    primary_path = root / PRIMARY_RECEIPT_NAME
    primary_digest = ""
    if primary_path.is_file():
        primary = _read_json(primary_path)
        if (
            primary.get("schema_version")
            != "plamen.chain_tail.primary_receipt.v1"
            or primary.get("receipt_sha256")
            != _digest(primary, "receipt_sha256")
            or primary.get("manifest_sha256")
            != manifest.get("manifest_sha256")
        ):
            raise ChainTailAuthorityError(
                "chain-tail primary receipt is invalid or stale"
            )
        if (
            _sha256_bytes((root / "composition_coverage.md").read_bytes())
            != primary.get("composition_coverage_sha256")
            or _sha256_bytes((root / "chain_hypotheses.md").read_bytes())
            != primary.get("chain_hypotheses_sha256")
        ):
            raise ChainTailAuthorityError(
                "chain-tail primary source binding changed"
            )
        for result in primary.get("pair_results") or []:
            if not isinstance(result, Mapping):
                raise ChainTailAuthorityError(
                    "chain-tail primary pair result is malformed"
                )
            pair_id = str(result.get("pair_id") or "")
            row = by_id.get(pair_id)
            if row is None:
                raise ChainTailAuthorityError(
                    "chain-tail primary result is outside manifest"
                )
            for key in (
                "disposition",
                "reason",
                "evidence",
                "chain_id",
                "attempts",
                "last_shard_index",
                "output_sha256",
            ):
                row[key] = result.get(key)
        reconstructed["primary_coverage"] = {
            "input_path": "composition_coverage.md",
            "input_sha256": primary["composition_coverage_sha256"],
            "chain_hypotheses_sha256": primary[
                "chain_hypotheses_sha256"
            ],
            "eligible_pairs": len(primary.get("eligible_pair_ids") or []),
            "consumed_pairs": int(primary.get("consumed_pairs") or 0),
            "chain_agent2_model_binding": dict(
                primary.get("chain_agent2_model_binding") or {}
            ),
        }
        primary_digest = str(primary.get("receipt_sha256") or "")

    shard_parent = root / SHARD_ARCHIVE_DIR
    dirs = sorted(
        (
            candidate
            for candidate in shard_parent.glob("shard_[0-9][0-9][0-9][0-9]")
            if candidate.is_dir()
        ),
        key=lambda value: value.name,
    ) if shard_parent.is_dir() else []
    for shard_dir in dirs:
        shard_index = int(shard_dir.name.rsplit("_", 1)[1])
        work = _read_json(shard_dir / "work_unit.json")
        plan = _validated_terminal_plan(shard_dir / "terminal_plan.json")
        disposition = _read_json(shard_dir / "disposition_receipt.json")
        if (
            disposition.get("receipt_sha256")
            != _digest(disposition, "receipt_sha256")
            or disposition != plan.get("disposition_receipt")
            or int(disposition.get("shard_index") or 0) != shard_index
            or disposition.get("manifest_sha256")
            != manifest.get("manifest_sha256")
            or list(disposition.get("pair_ids") or [])
            != list(work.get("pair_ids") or [])
        ):
            raise ChainTailAuthorityError(
                f"chain-tail shard {shard_index:04d} terminal receipt drift"
            )
        current_pair_ids = set(str(value) for value in work.get("pair_ids") or [])
        results = disposition.get("pair_results") or []
        if {
            str(result.get("pair_id") or "")
            for result in results
            if isinstance(result, Mapping)
        } != current_pair_ids:
            raise ChainTailAuthorityError(
                "chain-tail terminal receipt pair denominator mismatch"
            )
        for result in results:
            if not isinstance(result, Mapping):
                raise ChainTailAuthorityError(
                    "chain-tail terminal pair result is malformed"
                )
            row = by_id.get(str(result.get("pair_id") or ""))
            if row is None:
                raise ChainTailAuthorityError(
                    "chain-tail terminal pair result is outside manifest"
                )
            for key in (
                "disposition",
                "reason",
                "evidence",
                "chain_id",
                "attempts",
                "last_shard_index",
                "output_sha256",
            ):
                row[key] = result.get(key)
        transcript_path = str(disposition.get("transcript_path") or "")
        reconstructed["shards"].append(
            {
                "shard_index": shard_index,
                "pass_index": int(work.get("pass_index") or 0),
                "cursor_start": min(
                    (
                        int(by_id[pair_id].get("ordinal") or 0)
                        for pair_id in current_pair_ids
                    ),
                    default=0,
                ),
                "cursor_end": max(
                    (
                        int(by_id[pair_id].get("ordinal") or 0) + 1
                        for pair_id in current_pair_ids
                    ),
                    default=0,
                ),
                "pair_ids": list(work.get("pair_ids") or []),
                "input_path": str(work.get("packet_path") or ""),
                "input_sha256": str(work.get("packet_sha256") or ""),
                "output_path": transcript_path,
                "output_sha256": str(
                    disposition.get("transcript_sha256") or ""
                ),
                "worker_claimed_pairs": disposition.get(
                    "worker_claimed_pairs"
                ),
                "mechanical_consumed_pairs": int(
                    disposition.get("mechanical_consumed_pairs") or 0
                ),
                "issues": list(disposition.get("issues") or []),
                "terminal_status": str(
                    disposition.get("terminal_status") or ""
                ),
            }
        )
        reconstructed["issues"] = list(dict.fromkeys([
            *reconstructed.get("issues", []),
            *(disposition.get("issues") or []),
        ]))
        for proposal in disposition.get("unresolved_chain_proposals") or []:
            if (
                not isinstance(proposal, Mapping)
                or proposal.get("reason") != "ORPHAN_CHAIN_SECTION"
                or int(proposal.get("shard_index") or 0) != shard_index
                or not str(proposal.get("chain_id") or "")
                or not str(proposal.get("section") or "")
            ):
                raise ChainTailAuthorityError(
                    "chain-tail unresolved proposal receipt is malformed"
                )
            reconstructed.setdefault(
                "unresolved_chain_proposals", []
            ).append(dict(proposal))
        terminal_records.append(
            {
                "shard_index": shard_index,
                "work_unit_sha256": str(work.get("work_unit_sha256") or ""),
                "terminal_plan_sha256": str(plan.get("plan_sha256") or ""),
                "disposition_receipt_sha256": str(
                    disposition.get("receipt_sha256") or ""
                ),
                "transcript_path": transcript_path,
                "transcript_sha256": str(
                    disposition.get("transcript_sha256") or ""
                ),
                "terminal_status": str(
                    disposition.get("terminal_status") or ""
                ),
            }
        )
    budget_stopped = progress_receipt.get("status") == "BUDGET_STOP"
    if budget_stopped:
        if (
            progress_receipt.get("schema_version") != RECEIPT_SCHEMA
            or progress_receipt.get("authority_digest")
            != _digest(progress_receipt, "authority_digest")
            or progress_receipt.get("manifest_sha256")
            != manifest.get("manifest_sha256")
            or progress_receipt.get("ledger_sha256")
            != control_ledger.get("ledger_sha256")
        ):
            raise ChainTailAuthorityError(
                "chain-tail budget-stop receipt is invalid or stale"
            )
        budget_pair_ids = [
            str(value)
            for value in (
                progress_receipt.get("budget_stop_unexamined_pair_ids") or []
            )
        ]
        if (
            len(budget_pair_ids) != len(set(budget_pair_ids))
            or set(budget_pair_ids) != {
                str(row.get("pair_id") or "")
                for row in control_ledger.get("pairs") or []
                if isinstance(row, Mapping)
                and row.get("reason") == "BUDGET_STOP_UNEXAMINED"
            }
        ):
            raise ChainTailAuthorityError(
                "chain-tail budget-stop pair denominator drift"
            )
        for pair_id in budget_pair_ids:
            row = by_id.get(pair_id)
            if row is None or row.get("disposition") != "UNRESOLVED_COMPOSITION":
                raise ChainTailAuthorityError(
                    "chain-tail budget-stop pair is not unresolved"
                )
            row["reason"] = "BUDGET_STOP_UNEXAMINED"
        retry_pair_ids = [
            str(value)
            for value in (progress_receipt.get("retry_pair_ids") or [])
        ]
        if (
            len(retry_pair_ids) != len(set(retry_pair_ids))
            or any(pair_id not in by_id for pair_id in retry_pair_ids)
        ):
            raise ChainTailAuthorityError(
                "chain-tail budget-stop retry denominator drift"
            )
        retry_cursor = int(progress_receipt.get("retry_cursor") or 0)
        if not 0 <= retry_cursor <= len(retry_pair_ids):
            raise ChainTailAuthorityError(
                "chain-tail budget-stop retry cursor drift"
            )
        reconstructed["budget_stop_reason"] = str(
            progress_receipt.get("budget_stop_reason") or ""
        )
        if not reconstructed["budget_stop_reason"]:
            raise ChainTailAuthorityError(
                "chain-tail budget-stop reason is absent"
            )
        reconstructed["issues"] = list(dict.fromkeys([
            *reconstructed.get("issues", []),
            *(progress_receipt.get("issues") or []),
        ]))
        reconstructed["retry_pair_ids"] = retry_pair_ids
        reconstructed["retry_cursor"] = retry_cursor
        reconstructed["cursor"] = int(progress_receipt.get("cursor") or 0)
    else:
        reconstructed["cursor"] = int(manifest.get("denominator") or 0)
    _split_divergent_families(reconstructed)
    reconstructed["ledger_sha256"] = _digest(reconstructed, "ledger_sha256")

    semantic_fields = (
        "pair_id",
        "disposition",
        "reason",
        "evidence",
        "chain_id",
        "attempts",
        "last_shard_index",
        "output_sha256",
    )
    control_semantics = [
        {key: row.get(key) for key in semantic_fields}
        for row in control_ledger.get("pairs") or []
        if isinstance(row, Mapping)
    ]
    frozen_semantics = [
        {key: row.get(key) for key in semantic_fields}
        for row in reconstructed.get("pairs") or []
        if isinstance(row, Mapping)
    ]
    if control_semantics != frozen_semantics:
        raise ChainTailAuthorityError(
            "mutable chain-tail control ledger diverges from committed receipts"
        )
    if list(control_ledger.get("unresolved_chain_proposals") or []) != list(
        reconstructed.get("unresolved_chain_proposals") or []
    ):
        raise ChainTailAuthorityError(
            "mutable chain-tail unresolved proposals diverge from receipts"
        )
    if _ledger_terminal_generation(reconstructed) != (
        terminal_pass_index,
        terminal_shard_count,
    ):
        raise ChainTailAuthorityError(
            "chain-tail reconstructed terminal generation differs from control"
        )
    snapshot: dict[str, Any] = {
        "schema_version": TERMINAL_SNAPSHOT_SCHEMA,
        "authority": "DRIVER_FROZEN_TERMINAL_SEMANTICS",
        "manifest_sha256": manifest["manifest_sha256"],
        "primary_receipt_sha256": primary_digest,
        "terminal_records": terminal_records,
        "terminal_generation": {
            "pass_index": terminal_pass_index,
            "shard_count": terminal_shard_count,
            "generation_id": chain_tail_generation_id(
                terminal_pass_index,
                terminal_shard_count,
            ),
        },
        "semantic_ledger": reconstructed,
    }
    snapshot["snapshot_sha256"] = _digest(snapshot, "snapshot_sha256")
    _atomic_json(root / TERMINAL_SNAPSHOT_NAME, snapshot)
    return snapshot


def initialize_failed_chain_tail(scratchpad: Path, error: object) -> dict[str, Any]:
    scratchpad = Path(scratchpad)
    clean_error = _clean_text(error, limit=1000) or "unknown generator failure"
    receipt: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA,
        "status": "FAILED_GENERATOR",
        "manifest_sha256": "",
        "ledger_sha256": "",
        "ledger_path": LEDGER_NAME,
        "denominator": None,
        "cursor": 0,
        "processed_pairs": 0,
        "terminal_pairs": 0,
        "unresolved_pairs": None,
        "remaining_unattempted_pairs": None,
        "family_count": 0,
        "disposition_counts": {},
        "unresolved_reason_counts": {"PAIR_GENERATOR_FAILURE": 1},
        "signal_family_counts": {},
        "worker_claimed_pairs": None,
        "mechanical_consumed_pairs": 0,
        "worker_mechanical_mismatch": False,
        "budget_stop_reason": "",
        "issues": ["PAIR_GENERATOR_FAILURE", clean_error],
        "proof_authority": "NONE",
        "new_compositions_route": "ORDINARY_VERIFICATION",
    }
    receipt["authority_digest"] = _digest(receipt, "authority_digest")
    # Invalidate every older generation before publishing the failure.  A
    # generator error must never leave a stale successful manifest/ledger as a
    # competing authority.
    _atomic_json(
        scratchpad / MANIFEST_NAME,
        {
            "schema_version": MANIFEST_SCHEMA,
            "status": "FAILED_GENERATOR",
            "error": clean_error,
        },
    )
    for stale_name in (LEDGER_NAME, COMPOSITION_CANDIDATES_NAME):
        try:
            (scratchpad / stale_name).unlink(missing_ok=True)
        except OSError:
            pass
    _atomic_json(scratchpad / RECEIPT_NAME, receipt)
    _atomic_text(scratchpad / PROJECTION_NAME, _render_projection(receipt, None))
    _atomic_text(
        scratchpad / SHARD_PROJECTION_NAME,
        "# Chain Candidate Pairs — Generation Failed\n\n"
        "**Status**: FAILED_GENERATOR\n\n"
        f"**Error**: {clean_error}\n",
    )
    return receipt


def current_chain_tail_shard(scratchpad: Path) -> dict[str, Any]:
    manifest, ledger = _load_manifest_ledger(Path(scratchpad))
    active = ledger.get("active_shard")
    if not isinstance(active, dict):
        return {
            "shard_index": len(ledger.get("shards", [])),
            "cursor_start": ledger.get("cursor", 0),
            "cursor_end": ledger.get("cursor", 0),
            "pair_ids": [],
            "rows": [],
            "manifest_sha256": manifest["manifest_sha256"],
        }
    by_id = {row["pair_id"]: row for row in manifest.get("pairs", [])}
    return {
        **active,
        "rows": [by_id[pair_id] for pair_id in active.get("pair_ids", [])],
        "manifest_sha256": manifest["manifest_sha256"],
    }


def prepare_next_chain_tail_shard(scratchpad: Path) -> dict[str, Any]:
    scratchpad = Path(scratchpad)
    manifest, ledger = _load_manifest_ledger(scratchpad)
    if isinstance(ledger.get("active_shard"), dict):
        return current_chain_tail_shard(scratchpad)
    cursor = int(ledger.get("cursor") or 0)
    denominator = int(manifest.get("denominator") or 0)
    retry_ids = list(ledger.get("retry_pair_ids") or [])
    retry_cursor = int(ledger.get("retry_cursor") or 0)
    retry_mode = retry_cursor < len(retry_ids)
    if retry_mode:
        end = min(len(retry_ids), retry_cursor + int(manifest["shard_size"]))
        pair_ids = retry_ids[retry_cursor:end]
        cursor_start = retry_cursor
        cursor_end = end
    else:
        # The primary bounded pass may have terminal rows interleaved with a
        # missing/schema-drift row.  Advance over already-terminal identities
        # and shard only exact unresolved work; do not make successful primary
        # coverage pay for another model pass.
        ledger_rows = list(ledger.get("pairs", []))
        while cursor < denominator and ledger_rows[cursor].get("disposition") in _TERMINAL:
            cursor += 1
        # Cursor is the authoritative primary-pass frontier. Pre-resolved rows
        # may sit between bounded shards (for example, Chain Agent 2 consumed
        # them first), so publish the monotonic skip before binding the next
        # active shard. A receipt must not need to infer this hidden movement.
        ledger["cursor"] = cursor
        end = cursor
        pair_ids = []
        shard_size = int(manifest["shard_size"])
        while end < denominator and len(pair_ids) < shard_size:
            if ledger_rows[end].get("disposition") not in _TERMINAL:
                pair_ids.append(str(ledger_rows[end]["pair_id"]))
            end += 1
        cursor_start = cursor
        cursor_end = end
    active = {
        "shard_index": len(ledger.get("shards", [])),
        "pass_index": int(ledger.get("pass_index") or 0),
        "cursor_start": cursor_start,
        "cursor_end": cursor_end,
        "retry_mode": retry_mode,
        "pair_ids": pair_ids,
    }
    ledger["active_shard"] = active if pair_ids else None
    if pair_ids:
        input_path, input_sha = _write_shard_projection(
            scratchpad, manifest, active
        )
        active["input_path"] = input_path
        active["input_sha256"] = input_sha
        ledger["active_shard"] = active
    _write_ledger(scratchpad / LEDGER_NAME, ledger)
    manifest, ledger = _load_manifest_ledger(scratchpad)
    _write_composition_candidates(scratchpad, manifest, ledger)
    _write_receipt_and_projection(scratchpad, manifest, ledger)
    return current_chain_tail_shard(scratchpad)


def isolated_chain_tail_materialization_paths(
    shard_index: int,
    *,
    source_names: Iterable[str],
) -> dict[str, Any]:
    """Return the exact immutable output denominator for one shard packet."""

    index = int(shard_index)
    if index < 0:
        raise ChainTailAuthorityError("chain-tail shard index cannot be negative")
    relative_root = f"{SHARD_ARCHIVE_DIR}/shard_{index:04d}"
    normalized_sources: list[str] = []
    source_copy_paths: list[str] = []
    for raw_name in source_names:
        name = str(raw_name or "").replace("\\", "/").strip("/")
        candidate = Path(name)
        if (
            not name
            or candidate.is_absolute()
            or ".." in candidate.parts
            or name in normalized_sources
        ):
            raise ChainTailAuthorityError(
                f"invalid isolated chain-tail source identity: {raw_name!r}"
            )
        normalized_sources.append(name)
        source_copy_paths.append(f"{relative_root}/{name}")
    return {
        "shard_index": index,
        "shard_root": relative_root,
        "archive_packet_path": (
            f"{SHARD_ARCHIVE_DIR}/shard_{index:04d}.input.md"
        ),
        "work_unit_path": f"{relative_root}/work_unit.json",
        "packet_path": f"{relative_root}/{SHARD_PROJECTION_NAME}",
        "source_copy_paths": source_copy_paths,
        "authoritative_source_paths": normalized_sources,
        "transcript_path": f"{relative_root}/chain_iteration2.md",
        "terminal_plan_path": f"{relative_root}/terminal_plan.json",
        "disposition_receipt_path": (
            f"{relative_root}/disposition_receipt.json"
        ),
    }


def load_materialized_isolated_chain_tail_shard(
    scratchpad: Path,
    shard: Mapping[str, Any],
    *,
    source_names: Iterable[str],
) -> dict[str, Any]:
    """Replay one committed immutable shard packet without mutating control."""

    root = Path(scratchpad)
    descriptor = isolated_chain_tail_materialization_paths(
        int(shard.get("shard_index") or 0),
        source_names=source_names,
    )
    work = load_isolated_chain_tail_work_unit(
        root,
        descriptor,
        expected_source_names=descriptor["authoritative_source_paths"],
    )
    pair_ids = [str(value) for value in shard.get("pair_ids") or []]
    if pair_ids != [str(value) for value in work.get("pair_ids") or []]:
        raise ChainTailAuthorityError(
            "committed isolated shard pair denominator changed on replay"
        )
    if str(shard.get("manifest_sha256") or "") != str(
        work.get("manifest_sha256") or ""
    ):
        raise ChainTailAuthorityError(
            "committed isolated shard manifest changed on replay"
        )
    return {
        **descriptor,
        "pair_ids": pair_ids,
        "rows": [
            dict(row)
            for row in work.get("rows") or []
            if isinstance(row, Mapping)
        ],
        "manifest_sha256": str(work.get("manifest_sha256") or ""),
        "work_unit_sha256": str(work.get("work_unit_sha256") or ""),
    }


def materialize_isolated_chain_tail_shard(
    scratchpad: Path,
    shard: Mapping[str, Any],
    *,
    source_names: Iterable[str],
) -> dict[str, Any]:
    """Create one immutable, path-isolated model work packet.

    Source copies are transport only.  ``work_unit.json`` retains both each
    original scratchpad identity/digest and the byte-identical copy identity so
    the later model contract cannot mistake a private copy for source authority.
    The scheduler journal is mutable control state with ``authority=NONE``.
    """

    root = Path(scratchpad)
    requested_sources = tuple(source_names)
    manifest, ledger = _load_manifest_ledger(root)
    active = ledger.get("active_shard")
    if not isinstance(active, Mapping):
        raise ChainTailAuthorityError("no active chain-tail shard to materialize")
    shard_index = int(active.get("shard_index") or 0)
    supplied_index = int(shard.get("shard_index") or 0)
    if supplied_index != shard_index:
        raise ChainTailAuthorityError("chain-tail shard index changed before materialization")
    active_ids = [str(value) for value in active.get("pair_ids") or []]
    if active_ids != [str(value) for value in shard.get("pair_ids") or []]:
        raise ChainTailAuthorityError("chain-tail shard pair roster changed")
    if str(shard.get("manifest_sha256") or "") != str(
        manifest.get("manifest_sha256") or ""
    ):
        raise ChainTailAuthorityError("chain-tail shard manifest binding changed")

    descriptor = isolated_chain_tail_materialization_paths(
        shard_index,
        source_names=requested_sources,
    )
    relative_root = str(descriptor["shard_root"])
    shard_root = root / relative_root
    work_unit_path = str(descriptor["work_unit_path"])
    packet_path = str(descriptor["packet_path"])
    transcript_path = str(descriptor["transcript_path"])
    terminal_plan_path = str(descriptor["terminal_plan_path"])
    disposition_path = str(descriptor["disposition_receipt_path"])
    source_bindings: dict[str, dict[str, str]] = {}
    normalized_sources: list[str] = []
    for raw_name in requested_sources:
        name = str(raw_name or "").replace("\\", "/").strip("/")
        candidate = Path(name)
        if (
            not name
            or candidate.is_absolute()
            or ".." in candidate.parts
            or name in normalized_sources
        ):
            raise ChainTailAuthorityError(
                f"invalid isolated chain-tail source identity: {raw_name!r}"
            )
        source = root / candidate
        if not source.is_file():
            raise ChainTailAuthorityError(
                f"isolated chain-tail source is unavailable: {name}"
            )
        data = source.read_bytes()
        copy_path = f"{relative_root}/{name}"
        normalized_sources.append(name)
        source_bindings[name] = {
            "authority_identity": f"scratchpad:{name}",
            "authority_sha256": _sha256_bytes(data),
            "copy_path": copy_path,
            "copy_sha256": _sha256_bytes(data),
        }

    archived_packet = str(active.get("input_path") or "")
    archived_packet_path = root / archived_packet
    if not archived_packet or not archived_packet_path.is_file():
        raise ChainTailAuthorityError("active chain-tail shard lacks its immutable packet")
    packet_bytes = archived_packet_path.read_bytes()
    by_id = {
        str(row.get("pair_id")): row
        for row in manifest.get("pairs") or []
        if isinstance(row, Mapping)
    }
    rows = [dict(by_id[pair_id]) for pair_id in active_ids]
    work: dict[str, Any] = {
        "schema_version": "plamen.chain_tail.shard_work_unit.v1",
        "authority": "WORK_DEFINITION_ONLY",
        "shard_index": shard_index,
        "pass_index": int(active.get("pass_index") or 0),
        "manifest_identity": f"scratchpad:{CONTROL_MANIFEST_PATH}",
        "manifest_sha256": manifest["manifest_sha256"],
        "denominator": int(manifest.get("denominator") or 0),
        "pair_ids": active_ids,
        "rows": rows,
        "packet_path": packet_path,
        "packet_sha256": _sha256_bytes(packet_bytes),
        "authoritative_sources": dict(sorted(source_bindings.items())),
        "transcript_path": transcript_path,
        "terminal_plan_path": terminal_plan_path,
        "disposition_receipt_path": disposition_path,
    }
    work["work_unit_sha256"] = _digest(work, "work_unit_sha256")

    with _scheduler_lock(root):
        if shard_root.exists():
            existing_path = root / work_unit_path
            if not existing_path.is_file():
                raise ChainTailAuthorityError(
                    "isolated shard directory exists without immutable work unit"
                )
            existing = _read_json(existing_path)
            if existing != work:
                raise ChainTailAuthorityError(
                    "isolated chain-tail work unit changed on resume"
                )
        else:
            shard_root.mkdir(parents=True, exist_ok=False)
            _atomic_bytes(root / packet_path, packet_bytes)
            for name, binding in source_bindings.items():
                _atomic_bytes(
                    root / binding["copy_path"],
                    (root / name).read_bytes(),
                )
            _atomic_json(root / work_unit_path, work)

        journal = _read_scheduler_journal(root)
        started = dict(journal.get("started_shards") or {})
        shard_key = f"{shard_index:04d}"
        expected_started = {
            "shard_index": shard_index,
            "pair_ids": active_ids,
            "work_unit_path": work_unit_path,
            "work_unit_sha256": work["work_unit_sha256"],
            "transcript_path": transcript_path,
            "terminal_plan_path": terminal_plan_path,
            "disposition_receipt_path": disposition_path,
            "terminal_status": "",
        }
        existing_started = started.get(shard_key)
        if existing_started is not None:
            for field in (
                "shard_index",
                "pair_ids",
                "work_unit_path",
                "work_unit_sha256",
                "transcript_path",
                "terminal_plan_path",
                "disposition_receipt_path",
            ):
                if existing_started.get(field) != expected_started[field]:
                    raise ChainTailAuthorityError(
                        "chain-tail scheduler journal changed an existing shard"
                    )
            expected_started["terminal_status"] = str(
                existing_started.get("terminal_status") or ""
            )
        else:
            sequence = int(journal.get("sequence") or 0) + 1
            journal["sequence"] = sequence
            journal.setdefault("events", []).append(
                {
                    "sequence": sequence,
                    "event": "SHARD_STARTED",
                    "shard_index": shard_index,
                    "work_unit_sha256": work["work_unit_sha256"],
                }
            )
        started[shard_key] = expected_started
        journal["started_shards"] = started
        _write_scheduler_journal(root, journal)

    return {
        "shard_index": shard_index,
        "pair_ids": active_ids,
        "rows": rows,
        "manifest_sha256": manifest["manifest_sha256"],
        "shard_root": relative_root,
        "work_unit_path": work_unit_path,
        "work_unit_sha256": work["work_unit_sha256"],
        "packet_path": packet_path,
        "source_copy_paths": [
            binding["copy_path"] for binding in source_bindings.values()
        ],
        "authoritative_source_paths": normalized_sources,
        "transcript_path": transcript_path,
        "terminal_plan_path": terminal_plan_path,
        "disposition_receipt_path": disposition_path,
    }


def load_isolated_chain_tail_work_unit(
    scratchpad: Path,
    isolated: Mapping[str, Any],
    *,
    expected_source_names: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Load a shard work definition only after proving every byte binding.

    The work unit is a definition, not evidence authority.  This loader is the
    shared pre-arm boundary used by MODEL, DRIVER disposition, resume, and final
    reconciliation.  Rehashing a forged private copy or changing an original
    after materialization cannot manufacture a valid launch denominator.
    """

    root = Path(scratchpad)
    manifest, _ledger = _load_manifest_ledger(root)
    try:
        shard_index = int(isolated.get("shard_index"))
    except (TypeError, ValueError) as exc:
        raise ChainTailAuthorityError("isolated shard index is malformed") from exc
    shard_prefix = f"{SHARD_ARCHIVE_DIR}/shard_{shard_index:04d}"
    expected_work_path = f"{shard_prefix}/work_unit.json"
    work_name, work_path = _safe_relative_path(
        root,
        isolated.get("work_unit_path"),
        field="isolated work-unit path",
        required_prefix=shard_prefix,
    )
    if work_name != expected_work_path or not work_path.is_file():
        raise ChainTailAuthorityError("isolated work-unit identity is not canonical")
    work = _read_json(work_path)
    if work.get("schema_version") != "plamen.chain_tail.shard_work_unit.v1":
        raise ChainTailAuthorityError("isolated work-unit schema mismatch")
    if work.get("authority") != "WORK_DEFINITION_ONLY":
        raise ChainTailAuthorityError("isolated work unit claimed invalid authority")
    if work.get("work_unit_sha256") != _digest(work, "work_unit_sha256"):
        raise ChainTailAuthorityError("isolated work-unit digest mismatch")
    if int(work.get("shard_index", -1)) != shard_index:
        raise ChainTailAuthorityError("isolated work-unit shard index mismatch")
    if str(work.get("manifest_sha256") or "") != str(
        manifest.get("manifest_sha256") or ""
    ):
        raise ChainTailAuthorityError("isolated work-unit manifest is stale")
    if int(work.get("denominator") or -1) != int(
        manifest.get("denominator") or 0
    ):
        raise ChainTailAuthorityError("isolated work-unit denominator mismatch")

    pair_ids = [str(value) for value in work.get("pair_ids") or []]
    if not pair_ids or len(pair_ids) != len(set(pair_ids)):
        raise ChainTailAuthorityError("isolated work-unit pair roster is invalid")
    supplied_ids = [str(value) for value in isolated.get("pair_ids") or []]
    if supplied_ids != pair_ids:
        raise ChainTailAuthorityError("isolated work-unit supplied pair roster changed")
    by_id = {
        str(row.get("pair_id")): row
        for row in manifest.get("pairs") or []
        if isinstance(row, Mapping)
    }
    try:
        expected_rows = [dict(by_id[pair_id]) for pair_id in pair_ids]
    except KeyError as exc:
        raise ChainTailAuthorityError(
            "isolated work-unit pair is absent from manifest"
        ) from exc
    if work.get("rows") != expected_rows:
        raise ChainTailAuthorityError("isolated work-unit rows changed from manifest")

    expected_packet = f"{shard_prefix}/{SHARD_PROJECTION_NAME}"
    packet_name, packet_path = _safe_relative_path(
        root,
        work.get("packet_path"),
        field="isolated packet path",
        required_prefix=shard_prefix,
    )
    if (
        packet_name != expected_packet
        or packet_name != str(isolated.get("packet_path") or "").replace("\\", "/")
        or not packet_path.is_file()
        or _sha256_bytes(packet_path.read_bytes()) != work.get("packet_sha256")
    ):
        raise ChainTailAuthorityError("isolated packet binding mismatch")

    expected_transcript = f"{shard_prefix}/chain_iteration2.md"
    expected_plan = f"{shard_prefix}/terminal_plan.json"
    expected_disposition = f"{shard_prefix}/disposition_receipt.json"
    for key, expected, field in (
        ("transcript_path", expected_transcript, "transcript"),
        ("terminal_plan_path", expected_plan, "terminal plan"),
        ("disposition_receipt_path", expected_disposition, "disposition"),
    ):
        work_value, _ = _safe_relative_path(
            root,
            work.get(key),
            field=f"isolated {field} path",
            required_prefix=shard_prefix,
        )
        supplied = str(isolated.get(key) or "").replace("\\", "/").strip("/")
        if work_value != expected or supplied != expected:
            raise ChainTailAuthorityError(
                f"isolated {field} identity is not canonical"
            )

    bindings = work.get("authoritative_sources")
    if not isinstance(bindings, Mapping):
        raise ChainTailAuthorityError("isolated source denominator is malformed")
    actual_names = tuple(sorted(str(name) for name in bindings))
    if expected_source_names is not None:
        normalized_expected = tuple(sorted(
            str(value or "").replace("\\", "/").strip("/")
            for value in expected_source_names
        ))
        if (
            not normalized_expected
            or len(normalized_expected) != len(set(normalized_expected))
            or actual_names != normalized_expected
        ):
            raise ChainTailAuthorityError(
                "isolated authoritative source denominator mismatch"
            )
    observed_copy_paths: set[str] = set()
    for name in actual_names:
        source_name, source_path = _safe_relative_path(
            root, name, field="authoritative source path"
        )
        binding = bindings.get(name)
        if not isinstance(binding, Mapping):
            raise ChainTailAuthorityError("isolated source binding is malformed")
        if binding.get("authority_identity") != f"scratchpad:{source_name}":
            raise ChainTailAuthorityError("isolated source authority identity changed")
        copy_name, copy_path = _safe_relative_path(
            root,
            binding.get("copy_path"),
            field="isolated source copy path",
            required_prefix=shard_prefix,
        )
        expected_copy = f"{shard_prefix}/{source_name}"
        if (
            copy_name != expected_copy
            or copy_name in observed_copy_paths
            or copy_path == source_path
        ):
            raise ChainTailAuthorityError("isolated source copy identity is invalid")
        observed_copy_paths.add(copy_name)
        if not source_path.is_file() or not copy_path.is_file():
            raise ChainTailAuthorityError("isolated source or copy is missing")
        source_bytes = source_path.read_bytes()
        copy_bytes = copy_path.read_bytes()
        try:
            if source_path.samefile(copy_path):
                raise ChainTailAuthorityError(
                    "isolated source copy aliases its authority file"
                )
        except OSError as exc:
            raise ChainTailAuthorityError(
                "isolated source/copy physical identity is unavailable"
            ) from exc
        source_sha = _sha256_bytes(source_bytes)
        copy_sha = _sha256_bytes(copy_bytes)
        if (
            source_sha != binding.get("authority_sha256")
            or copy_sha != binding.get("copy_sha256")
            or source_sha != copy_sha
            or source_bytes != copy_bytes
        ):
            raise ChainTailAuthorityError("isolated source/copy byte binding mismatch")
    return work


def _worker_claim(text: str) -> int | None:
    for pattern in _WORKER_COUNT_RES:
        match = pattern.search(text)
        if match:
            return int(match.group(1))
    return None


def _normalize_header(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _header_roles(cells: list[str]) -> dict[str, int] | None:
    roles: dict[str, int] = {}
    for index, cell in enumerate(cells):
        normalized = _normalize_header(cell)
        for role, aliases in _HEADER_ALIASES.items():
            if normalized in aliases and role not in roles:
                roles[role] = index
                break
    if all(role in roles for role in ("a", "b", "disposition", "evidence")):
        return roles
    return None


def _tail_table_rows(text: str) -> tuple[list[dict[str, str]], list[str]]:
    heading = _TAIL_HEADING_RE.search(text)
    if not heading:
        return [], ["TAIL_DISPOSITION_HEADING_MISSING"]
    section_end = len(text)
    next_heading = re.search(r"(?m)^##\s+", text[heading.end():])
    if next_heading:
        section_end = heading.end() + next_heading.start()
    section = text[heading.end():section_end]
    table_lines = [
        line.strip() for line in section.splitlines()
        if line.strip().startswith("|") and line.strip().endswith("|")
    ]
    if not table_lines:
        return [], ["TAIL_DISPOSITION_TABLE_MISSING"]
    header_index = -1
    roles: dict[str, int] | None = None
    for index, line in enumerate(table_lines):
        cells = [cell.strip().strip("`*") for cell in line.strip("|").split("|")]
        candidate = _header_roles(cells)
        if candidate:
            header_index = index
            roles = candidate
            break
    if roles is None:
        return [], ["TABLE_SCHEMA_DRIFT"]
    parsed: list[dict[str, str]] = []
    max_index = max(roles.values())
    for line in table_lines[header_index + 1:]:
        cells = [cell.strip().strip("`*") for cell in line.strip("|").split("|")]
        if cells and all(not cell or set(cell) <= {"-", ":", " "} for cell in cells):
            continue
        if len(cells) <= max_index:
            continue
        parsed.append({role: cells[index] for role, index in roles.items()})
    return parsed, []


def _manifest_pair_match(
    parsed: Mapping[str, str], active_rows: list[Mapping[str, Any]]
) -> tuple[str | None, str | None]:
    supplied = _clean_text(parsed.get("pair_id"), limit=100).upper()
    by_id = {str(row["pair_id"]): row for row in active_rows}
    if supplied:
        if supplied not in by_id:
            return None, "OUT_OF_SHARD_PAIR_ID"
        selected = by_id[supplied]
    else:
        try:
            a = _finding_id(parsed.get("a"))
            b = _finding_id(parsed.get("b"))
        except ChainTailAuthorityError:
            return None, "MALFORMED_FINDING_ID"
        candidates = [
            row for row in active_rows
            if set((str(row["a"]), str(row["b"]))) == set((a, b))
        ]
        if len(candidates) != 1:
            return None, "AMBIGUOUS_PAIR_WITHOUT_ID"
        selected = candidates[0]
        supplied = str(selected["pair_id"])
    try:
        parsed_endpoints = {
            _finding_id(parsed.get("a")), _finding_id(parsed.get("b"))
        }
    except ChainTailAuthorityError:
        return None, "MALFORMED_FINDING_ID"
    if parsed_endpoints != {str(selected["a"]), str(selected["b"])}:
        return None, "PAIR_ID_ENDPOINT_MISMATCH"
    return supplied, None


def _normalize_disposition(value: object) -> str:
    return re.sub(r"[^A-Z_]+", "", _clean_text(value, limit=60).upper().replace(" ", "_"))


def _split_divergent_families(ledger: dict[str, Any]) -> None:
    families: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in ledger.get("pairs", []):
        families[str(row.get("family_id"))].append(row)
    for family_id, rows in families.items():
        fingerprints = {
            (
                str(row.get("disposition")),
                _sha256_bytes(_clean_text(row.get("evidence"), limit=1000).lower().encode("utf-8"))[:12],
            )
            for row in rows
            if row.get("disposition") in _TERMINAL
        }
        divergent = len(fingerprints) > 1
        for row in rows:
            if divergent and row.get("disposition") in _TERMINAL:
                fingerprint = _sha256_bytes(
                    _canonical_bytes({
                        "disposition": row.get("disposition"),
                        "evidence": _clean_text(row.get("evidence"), limit=1000).lower(),
                    })
                )[:12].upper()
                row["resolved_family_id"] = f"{family_id}~{fingerprint}"
            else:
                row["resolved_family_id"] = family_id


def _composition_candidate_payload(
    manifest: Mapping[str, Any],
    ledger: Mapping[str, Any],
) -> dict[str, Any]:
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in ledger.get("pairs", []):
        if (
            isinstance(row, Mapping)
            and row.get("disposition") == "COMPOSED"
            and row.get("chain_id")
        ):
            grouped[str(row["chain_id"]).upper()].append(row)
    candidates: list[dict[str, Any]] = []
    for chain_id, rows in sorted(grouped.items()):
        pair_ids = list(dict.fromkeys(str(row["pair_id"]) for row in rows))
        constituents = list(dict.fromkeys(
            finding
            for row in rows
            for finding in (str(row["a"]), str(row["b"]))
        ))
        evidence = " | ".join(dict.fromkeys(
            _clean_text(row.get("evidence"), limit=1000) for row in rows
        ))
        candidates.append(
            {
                "pair_id": pair_ids[0],
                "pair_ids": pair_ids,
                "chain_id": chain_id,
                "constituent_finding_ids": constituents,
                "evidence": evidence,
                "proof_authority": "NONE",
                "route": "ORDINARY_VERIFICATION",
            }
        )
    for proposal in ledger.get("unresolved_chain_proposals") or []:
        if not isinstance(proposal, Mapping):
            continue
        candidates.append(
            {
                "pair_id": "",
                "pair_ids": [],
                "chain_id": str(proposal.get("chain_id") or ""),
                "constituent_finding_ids": list(
                    proposal.get("constituent_finding_ids") or []
                ),
                "evidence": str(proposal.get("section") or ""),
                "reason": str(
                    proposal.get("reason") or "ORPHAN_CHAIN_SECTION"
                ),
                "proof_authority": "NONE",
                "route": "HUMAN_REVIEW",
            }
        )
    payload: dict[str, Any] = {
        "schema_version": CANDIDATE_SCHEMA,
        "manifest_sha256": manifest["manifest_sha256"],
        "ledger_sha256": ledger["ledger_sha256"],
        "proof_authority": "NONE",
        "candidates": candidates,
    }
    payload["candidate_digest"] = _digest(payload, "candidate_digest")
    return payload


def _write_composition_candidates(
    scratchpad: Path, manifest: Mapping[str, Any], ledger: Mapping[str, Any]
) -> None:
    payload = _composition_candidate_payload(manifest, ledger)
    root = Path(scratchpad)
    _atomic_json(root / CONTROL_DIR / COMPOSITION_CANDIDATES_NAME, payload)
    if (
        not (root / CONTROL_DIR / CONTROL_JOURNAL_NAME).is_file()
        or _publication_is_armed(root)
    ):
        _atomic_json(root / COMPOSITION_CANDIDATES_NAME, payload)


def _chain_sections(text: str) -> list[tuple[str, str]]:
    matches = list(_CHAIN_HEADING_RE.finditer(text))
    tail = _TAIL_HEADING_RE.search(text)
    sections: list[tuple[str, str]] = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        if tail is not None and tail.start() > match.start():
            end = min(end, tail.start())
        section = text[match.start():end].strip()
        if section:
            sections.append((match.group(1).upper(), section))
    return sections


def _divergent_duplicate_chain_ids(text: str) -> set[str]:
    """Return shard-local identities naming more than one distinct section."""
    grouped: dict[str, list[str]] = defaultdict(list)
    for chain_id, section in _chain_sections(text):
        # Normalize transport-only line ending/trailing-space drift, but retain
        # every semantic byte. Distinct titles or bodies remain divergent.
        normalized = "\n".join(
            line.rstrip() for line in section.replace("\r\n", "\n").split("\n")
        ).strip()
        grouped[chain_id].append(_sha256_bytes(normalized.encode("utf-8")))
    return {
        chain_id
        for chain_id, fingerprints in grouped.items()
        if len(fingerprints) > 1 and len(set(fingerprints)) > 1
    }


def _terminal_plan_relative(disposition_receipt_name: str) -> str:
    relative = str(disposition_receipt_name or "").replace("\\", "/").strip("/")
    candidate = Path(relative)
    if (
        not relative
        or candidate.is_absolute()
        or ".." in candidate.parts
        or candidate.name != "disposition_receipt.json"
    ):
        raise ChainTailAuthorityError(
            "invalid isolated chain-tail disposition receipt path"
        )
    return str(candidate.with_name("terminal_plan.json")).replace("\\", "/")


def _validated_terminal_plan(path: Path) -> dict[str, Any]:
    plan = _read_json(path)
    if plan.get("schema_version") != "plamen.chain_tail.terminal_plan.v1":
        raise ChainTailAuthorityError("chain-tail terminal plan schema mismatch")
    if plan.get("authority") != "TRANSACTION_INTENT_ONLY":
        raise ChainTailAuthorityError("chain-tail terminal plan claimed authority")
    if plan.get("plan_sha256") != _digest(plan, "plan_sha256"):
        raise ChainTailAuthorityError("chain-tail terminal plan digest mismatch")
    post_ledger = plan.get("post_ledger")
    disposition = plan.get("disposition_receipt")
    if not isinstance(post_ledger, Mapping) or not isinstance(
        disposition, Mapping
    ):
        raise ChainTailAuthorityError("chain-tail terminal plan payload malformed")
    if post_ledger.get("ledger_sha256") != _digest(
        post_ledger, "ledger_sha256"
    ):
        raise ChainTailAuthorityError("chain-tail terminal plan post-ledger mismatch")
    if disposition.get("receipt_sha256") != _digest(
        disposition, "receipt_sha256"
    ):
        raise ChainTailAuthorityError("chain-tail terminal plan receipt mismatch")
    return plan


def _apply_terminal_plan(
    scratchpad: Path,
    *,
    plan_path: Path,
    disposition_receipt_name: str,
) -> dict[str, Any]:
    """Idempotently roll a prewritten shard terminal plan to completion."""

    root = Path(scratchpad)
    plan = _validated_terminal_plan(plan_path)
    manifest, current = _load_manifest_ledger(root)
    if plan.get("manifest_sha256") != manifest.get("manifest_sha256"):
        raise ChainTailAuthorityError("chain-tail terminal plan manifest is stale")
    before = str(plan.get("pre_ledger_sha256") or "")
    post = dict(plan["post_ledger"])
    after = str(post.get("ledger_sha256") or "")
    current_sha = str(current.get("ledger_sha256") or "")
    if current_sha == before:
        _write_ledger(root / LEDGER_NAME, post)
    elif current_sha != after:
        raise ChainTailAuthorityError(
            "chain-tail terminal plan compare-and-swap precondition failed"
        )
    manifest, committed = _load_manifest_ledger(root)
    if committed != post:
        raise ChainTailAuthorityError("chain-tail terminal post-ledger drift")

    disposition_relative, disposition_path = _safe_relative_path(
        root,
        disposition_receipt_name,
        field="isolated disposition receipt path",
        required_prefix=(
            f"{SHARD_ARCHIVE_DIR}/"
            f"shard_{int(plan.get('shard_index') or 0):04d}"
        ),
    )
    if disposition_relative != plan.get("disposition_receipt_path"):
        raise ChainTailAuthorityError("chain-tail terminal receipt path changed")
    expected_disposition = dict(plan["disposition_receipt"])
    if disposition_path.is_file():
        if _read_json(disposition_path) != expected_disposition:
            raise ChainTailAuthorityError("chain-tail terminal receipt changed")
    else:
        _atomic_json(disposition_path, expected_disposition)

    _write_composition_candidates(root, manifest, committed)
    progress = _write_receipt_and_projection(
        root,
        manifest,
        committed,
        last_mechanical_count=int(
            expected_disposition.get("mechanical_consumed_pairs") or 0
        ),
        last_worker_claim=(
            int(expected_disposition["worker_claimed_pairs"])
            if expected_disposition.get("worker_claimed_pairs") is not None
            else None
        ),
    )
    shard_index = int(plan.get("shard_index") or 0)
    shard_key = f"{shard_index:04d}"
    with _scheduler_lock(root):
        journal = _read_scheduler_journal(root)
        started = dict(journal.get("started_shards") or {})
        current_started = started.get(shard_key)
        if not isinstance(current_started, Mapping):
            raise ChainTailAuthorityError(
                "chain-tail terminal plan lacks its scheduled shard"
            )
        expected_work_sha = str(plan.get("work_unit_sha256") or "")
        if current_started.get("work_unit_sha256") != expected_work_sha:
            raise ChainTailAuthorityError(
                "chain-tail terminal plan work-unit binding changed"
            )
        terminal = str(expected_disposition.get("terminal_status") or "")
        current_started = dict(current_started)
        already_terminal = bool(current_started.get("terminal_status"))
        current_started["terminal_status"] = terminal
        current_started["transcript_sha256"] = str(
            expected_disposition.get("transcript_sha256") or ""
        )
        current_started["disposition_receipt_sha256"] = str(
            expected_disposition.get("receipt_sha256") or ""
        )
        current_started["terminal_plan_sha256"] = str(
            plan.get("plan_sha256") or ""
        )
        started[shard_key] = current_started
        if not already_terminal:
            sequence = int(journal.get("sequence") or 0) + 1
            journal["sequence"] = sequence
            journal.setdefault("events", []).append(
                {
                    "sequence": sequence,
                    "event": "SHARD_TERMINAL",
                    "shard_index": shard_index,
                    "terminal_status": terminal,
                    "receipt_sha256": expected_disposition["receipt_sha256"],
                    "terminal_plan_sha256": plan["plan_sha256"],
                }
            )
        journal["started_shards"] = started
        _write_scheduler_journal(root, journal)
    return progress


def reconcile_chain_tail_output(
    scratchpad: Path,
    *,
    output_name: str = "chain_iteration2.md",
    disposition_receipt_name: str = "",
    model_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    scratchpad = Path(scratchpad)
    manifest, ledger = _load_manifest_ledger(scratchpad)
    active = ledger.get("active_shard")
    if not isinstance(active, dict):
        if disposition_receipt_name:
            plan_relative = _terminal_plan_relative(disposition_receipt_name)
            plan_path = scratchpad / plan_relative
            if plan_path.is_file():
                return _apply_terminal_plan(
                    scratchpad,
                    plan_path=plan_path,
                    disposition_receipt_name=disposition_receipt_name,
                )
        # Reconciliation is a commit operation and therefore idempotent.  A
        # repeated validator call after the active shard was committed returns
        # the hash-bound receipt rather than attempting to consume the same
        # model output twice.
        try:
            receipt = _read_progress_receipt(scratchpad)
            if (
                receipt.get("manifest_sha256") == manifest.get("manifest_sha256")
                and receipt.get("ledger_sha256") == ledger.get("ledger_sha256")
                and receipt.get("authority_digest") == _digest(receipt, "authority_digest")
            ):
                return receipt
        except Exception:
            pass
        if int(manifest.get("denominator") or 0) == 0:
            return _write_receipt_and_projection(scratchpad, manifest, ledger)
        raise ChainTailAuthorityError("no active chain-tail shard to reconcile")
    output_path = scratchpad / output_name
    output_bytes = output_path.read_bytes() if output_path.exists() else b""
    text = (
        output_bytes.decode("utf-8", errors="replace")
        .replace("\r\n", "\n")
        .replace("\r", "\n")
    )
    output_sha = _sha256_bytes(output_bytes)
    parsed_rows, issues = _tail_table_rows(text)
    divergent_chain_ids = _divergent_duplicate_chain_ids(text)
    if divergent_chain_ids:
        issues.append("DIVERGENT_DUPLICATE_CHAIN_IDENTITY")
    by_manifest_id = {row["pair_id"]: row for row in manifest.get("pairs", [])}
    active_rows = [by_manifest_id[pair_id] for pair_id in active.get("pair_ids", [])]
    ledger_by_id = {row["pair_id"]: row for row in ledger.get("pairs", [])}
    parsed_by_id: dict[str, list[dict[str, str]]] = defaultdict(list)
    for parsed in parsed_rows:
        pair_id, issue = _manifest_pair_match(parsed, active_rows)
        if issue:
            issues.append(issue)
            continue
        assert pair_id is not None
        parsed_by_id[pair_id].append(parsed)
    chain_ids = {match.group(1).upper() for match in _CHAIN_HEADING_RE.finditer(text)}
    consumed = 0
    for pair_id in active.get("pair_ids", []):
        row = ledger_by_id[pair_id]
        row["attempts"] = int(row.get("attempts") or 0) + 1
        row["last_shard_index"] = active["shard_index"]
        row["output_sha256"] = output_sha
        candidates = parsed_by_id.get(pair_id, [])
        if len(candidates) != 1:
            row.update({
                "disposition": "UNRESOLVED_COMPOSITION",
                "reason": "DUPLICATE_WORKER_ROWS" if len(candidates) > 1 else (
                    "TABLE_SCHEMA_DRIFT" if "TABLE_SCHEMA_DRIFT" in issues else "MISSING_WORKER_ROW"
                ),
                "evidence": "",
                "chain_id": "",
            })
            if len(candidates) > 1:
                issues.append("DUPLICATE_WORKER_ROWS")
            continue
        parsed = candidates[0]
        disposition = _normalize_disposition(parsed.get("disposition"))
        evidence = _clean_text(parsed.get("evidence"), limit=1000)
        if disposition == "DEFERRED":
            row.update({
                "disposition": "UNRESOLVED_COMPOSITION",
                "reason": "WORKER_DEFERRED",
                "evidence": evidence,
                "chain_id": "",
            })
            continue
        if disposition not in _TERMINAL or not evidence or evidence in {"-", "—", "n/a", "N/A"}:
            row.update({
                "disposition": "UNRESOLVED_COMPOSITION",
                "reason": "INVALID_DISPOSITION_OR_EVIDENCE",
                "evidence": evidence,
                "chain_id": "",
            })
            issues.append("INVALID_DISPOSITION_OR_EVIDENCE")
            continue
        chain_id = ""
        if disposition == "COMPOSED":
            match = _CHAIN_ID_RE.search(evidence)
            chain_id = match.group(0).upper() if match else ""
            if chain_id in divergent_chain_ids:
                row.update({
                    "disposition": "UNRESOLVED_COMPOSITION",
                    "reason": "DIVERGENT_DUPLICATE_CHAIN_IDENTITY",
                    "evidence": evidence,
                    "chain_id": "",
                })
                continue
            if not chain_id or chain_id not in chain_ids:
                row.update({
                    "disposition": "UNRESOLVED_COMPOSITION",
                    "reason": "COMPOSED_WITHOUT_CHAIN_SECTION",
                    "evidence": evidence,
                    "chain_id": chain_id,
                })
                issues.append("COMPOSED_WITHOUT_CHAIN_SECTION")
                continue
        row.update({
            "disposition": disposition,
            "reason": "",
            "evidence": evidence,
            "chain_id": chain_id,
        })
        consumed += 1
    referenced_chain_ids = {
        str(ledger_by_id[pair_id].get("chain_id") or "").upper()
        for pair_id in active.get("pair_ids", [])
        if ledger_by_id[pair_id].get("disposition") == "COMPOSED"
        and ledger_by_id[pair_id].get("chain_id")
    }
    section_by_id: dict[str, str] = {}
    for chain_id, section in _chain_sections(text):
        section_by_id.setdefault(chain_id, section)
    orphan_chain_ids = sorted(
        chain_ids - referenced_chain_ids - divergent_chain_ids
    )
    shard_unresolved_proposals: list[dict[str, Any]] = []
    manifest_finding_ids = {
        str(row.get(field))
        for row in manifest.get("pairs") or []
        if isinstance(row, Mapping)
        for field in ("a", "b")
    }
    for chain_id in orphan_chain_ids:
        section = section_by_id.get(chain_id, "")
        proposal = {
            "chain_id": chain_id,
            "shard_index": int(active["shard_index"]),
            "reason": "ORPHAN_CHAIN_SECTION",
            "constituent_finding_ids": [
                value
                for value in _finding_ids_in_text(section)
                if value in manifest_finding_ids
            ],
            "section": section,
            "route": "HUMAN_REVIEW",
            "proof_authority": "NONE",
        }
        shard_unresolved_proposals.append(proposal)
    if shard_unresolved_proposals:
        issues.append("ORPHAN_CHAIN_SECTION")
        retained = [
            row
            for row in ledger.get("unresolved_chain_proposals") or []
            if not (
                isinstance(row, Mapping)
                and int(row.get("shard_index") or 0)
                == int(active["shard_index"])
            )
        ]
        ledger["unresolved_chain_proposals"] = [
            *retained,
            *shard_unresolved_proposals,
        ]
    worker_claim = _worker_claim(text)
    if worker_claim is not None and worker_claim != consumed:
        issues.append("WORKER_MECHANICAL_COUNT_MISMATCH")
    ledger["issues"] = list(dict.fromkeys([
        *ledger.get("issues", []), *issues,
    ]))
    if disposition_receipt_name:
        committed_output_path = output_name.replace("\\", "/")
    else:
        # Explicit legacy/direct-library adapter only.  Isolated production
        # binds and consumes the committed unique MODEL transcript directly.
        archive_dir = scratchpad / SHARD_ARCHIVE_DIR
        archive_dir.mkdir(parents=True, exist_ok=True)
        archive_name = f"shard_{int(active['shard_index']):04d}.md"
        _atomic_text(archive_dir / archive_name, text)
        committed_output_path = f"{SHARD_ARCHIVE_DIR}/{archive_name}"
    ledger.setdefault("shards", []).append({
        "shard_index": active["shard_index"],
        "pass_index": active.get("pass_index", 0),
        "cursor_start": active["cursor_start"],
        "cursor_end": active["cursor_end"],
        "pair_ids": list(active.get("pair_ids", [])),
        "input_path": active.get("input_path", ""),
        "input_sha256": active.get("input_sha256", ""),
        "output_path": committed_output_path,
        "output_sha256": output_sha,
        "worker_claimed_pairs": worker_claim,
        "mechanical_consumed_pairs": consumed,
        "issues": list(dict.fromkeys(issues)),
    })
    if active.get("retry_mode"):
        ledger["retry_cursor"] = int(active["cursor_end"])
        if ledger["retry_cursor"] >= len(ledger.get("retry_pair_ids") or []):
            # The retry roster is an exact snapshot of every unresolved ID at
            # re-arm time.  Once traversed, the whole manifest has been
            # examined even though some retry rows may still be explicit debt.
            ledger["cursor"] = int(manifest.get("denominator") or 0)
    else:
        ledger["cursor"] = int(active["cursor_end"])
    ledger["active_shard"] = None
    _split_divergent_families(ledger)
    if disposition_receipt_name:
        relative = disposition_receipt_name.replace("\\", "/").strip("/")
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ChainTailAuthorityError(
                "invalid isolated chain-tail disposition receipt path"
            )
        journal = _read_scheduler_journal(scratchpad)
        shard_key = f"{int(active['shard_index']):04d}"
        started = dict(journal.get("started_shards") or {})
        started_row = started.get(shard_key)
        if not isinstance(started_row, Mapping):
            raise ChainTailAuthorityError(
                "isolated chain-tail disposition lacks a started journal row"
            )
        if str(started_row.get("disposition_receipt_path") or "") != relative:
            raise ChainTailAuthorityError(
                "isolated chain-tail disposition path changed after launch"
            )
        pair_results = [
            {
                "pair_id": pair_id,
                "disposition": ledger_by_id[pair_id].get("disposition"),
                "reason": ledger_by_id[pair_id].get("reason"),
                "evidence": ledger_by_id[pair_id].get("evidence"),
                "chain_id": ledger_by_id[pair_id].get("chain_id"),
                "attempts": ledger_by_id[pair_id].get("attempts"),
                "last_shard_index": ledger_by_id[pair_id].get(
                    "last_shard_index"
                ),
                "output_sha256": ledger_by_id[pair_id].get("output_sha256"),
            }
            for pair_id in active.get("pair_ids", [])
        ]
        disposition_receipt: dict[str, Any] = {
            "schema_version": "plamen.chain_tail.shard_disposition_receipt.v1",
            "authority": "DRIVER_RECONCILIATION",
            "terminal_kind": "DISPOSITION",
            "shard_index": int(active["shard_index"]),
            "manifest_sha256": manifest["manifest_sha256"],
            "work_unit_path": str(started_row.get("work_unit_path") or ""),
            "work_unit_sha256": str(started_row.get("work_unit_sha256") or ""),
            "transcript_path": output_name.replace("\\", "/"),
            "transcript_sha256": output_sha,
            "pair_ids": list(active.get("pair_ids", [])),
            "pair_results": pair_results,
            "mechanical_consumed_pairs": consumed,
            "worker_claimed_pairs": worker_claim,
            "issues": list(dict.fromkeys(issues)),
            "unresolved_chain_proposals": shard_unresolved_proposals,
            "terminal_status": (
                "COMMITTED"
                if consumed == len(active.get("pair_ids", [])) and not issues
                else "DEBT"
            ),
            "model_binding": dict(model_binding or {}),
        }
        disposition_receipt["receipt_sha256"] = _digest(
            disposition_receipt, "receipt_sha256"
        )
        ledger["ledger_sha256"] = _digest(ledger, "ledger_sha256")
        plan_relative = _terminal_plan_relative(relative)
        plan: dict[str, Any] = {
            "schema_version": "plamen.chain_tail.terminal_plan.v1",
            "authority": "TRANSACTION_INTENT_ONLY",
            "shard_index": int(active["shard_index"]),
            "manifest_sha256": manifest["manifest_sha256"],
            "work_unit_path": str(started_row.get("work_unit_path") or ""),
            "work_unit_sha256": str(started_row.get("work_unit_sha256") or ""),
            "pre_ledger_sha256": str(
                _load_manifest_ledger(scratchpad)[1].get("ledger_sha256") or ""
            ),
            "post_ledger": ledger,
            "disposition_receipt_path": relative,
            "disposition_receipt": disposition_receipt,
        }
        plan["plan_sha256"] = _digest(plan, "plan_sha256")
        plan_path = scratchpad / plan_relative
        if plan_path.is_file():
            if _validated_terminal_plan(plan_path) != plan:
                raise ChainTailAuthorityError(
                    "chain-tail terminal plan changed on resume"
                )
        else:
            _atomic_json(plan_path, plan)
        return _apply_terminal_plan(
            scratchpad,
            plan_path=plan_path,
            disposition_receipt_name=relative,
        )
    _write_ledger(scratchpad / LEDGER_NAME, ledger)
    manifest, ledger = _load_manifest_ledger(scratchpad)
    _write_composition_candidates(scratchpad, manifest, ledger)
    return _write_receipt_and_projection(
        scratchpad,
        manifest,
        ledger,
        last_mechanical_count=consumed,
        last_worker_claim=worker_claim,
    )


def record_isolated_chain_tail_failure(
    scratchpad: Path,
    *,
    disposition_receipt_name: str,
    reason: str,
    transcript_path: str = "",
    model_binding: Mapping[str, Any] | None = None,
    abandoned_model_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Terminalize a started shard as explicit debt.

    A pre-MODEL failure is explicitly transcript-less.  If MODEL already
    committed, the failure transaction preserves and binds that exact
    transcript instead of discarding the strongest available evidence.
    """

    root = Path(scratchpad)
    manifest, ledger = _load_manifest_ledger(root)
    pre_ledger_sha256 = str(ledger.get("ledger_sha256") or "")
    active = ledger.get("active_shard")
    if not isinstance(active, Mapping):
        plan_relative = _terminal_plan_relative(disposition_receipt_name)
        plan_path = root / plan_relative
        if plan_path.is_file():
            return _apply_terminal_plan(
                root,
                plan_path=plan_path,
                disposition_receipt_name=disposition_receipt_name,
            )
        raise ChainTailAuthorityError("no active chain-tail shard to fail")
    shard_index = int(active.get("shard_index") or 0)
    clean_reason = re.sub(r"[^A-Z0-9_]+", "_", str(reason).upper()).strip("_")
    clean_reason = clean_reason or "CHAIN_TAIL_WORKER_FAILURE"
    preserved_transcript_path = ""
    preserved_transcript_sha256 = ""
    preserved_model_binding: dict[str, Any] = {}
    preserved_abandoned_binding: dict[str, Any] = {}
    if transcript_path:
        preserved_transcript_path, preserved_path = _safe_relative_path(
            root,
            transcript_path,
            field="failed shard committed transcript path",
            required_prefix=f"{SHARD_ARCHIVE_DIR}/shard_{shard_index:04d}",
        )
        if not preserved_path.is_file():
            raise ChainTailAuthorityError(
                "failed shard committed transcript is unavailable"
            )
        if not isinstance(model_binding, Mapping):
            raise ChainTailAuthorityError(
                "failed shard committed transcript lacks MODEL binding"
            )
        preserved_transcript_sha256 = _sha256_bytes(preserved_path.read_bytes())
        if (
            not str(model_binding.get("work_unit_key") or "")
            or model_binding.get("execution_state") != "OUTPUT_COMMITTED"
            or model_binding.get("semantic_status") != "ACTIVE"
            or model_binding.get("transcript_sha256")
            != preserved_transcript_sha256
        ):
            raise ChainTailAuthorityError(
                "failed shard committed MODEL binding is invalid"
            )
        preserved_model_binding = dict(model_binding)
    elif model_binding:
        raise ChainTailAuthorityError(
            "failed shard MODEL binding cannot omit its transcript"
        )
    if abandoned_model_binding:
        if preserved_model_binding:
            raise ChainTailAuthorityError(
                "failed shard cannot bind committed and abandoned MODEL states"
            )
        if (
            not isinstance(abandoned_model_binding, Mapping)
            or abandoned_model_binding.get("execution_state")
            != "INPUTS_BOUND_PREEXECUTION"
            or abandoned_model_binding.get("semantic_status")
            != "INPUTS_BOUND"
            or abandoned_model_binding.get("output_present") is not False
            or not str(
                abandoned_model_binding.get("work_unit_key") or ""
            )
            or not str(
                abandoned_model_binding.get("contract_digest") or ""
            )
            or not str(
                abandoned_model_binding.get("input_set_digest") or ""
            )
        ):
            raise ChainTailAuthorityError(
                "failed shard abandoned MODEL binding is invalid"
            )
        preserved_abandoned_binding = dict(abandoned_model_binding)
    failure_issues = [clean_reason]
    if not preserved_transcript_path:
        failure_issues.append("TRANSCRIPTLESS_TERMINAL_DEBT")
    ledger_by_id = {
        str(row.get("pair_id")): row for row in ledger.get("pairs") or []
    }
    pair_results: list[dict[str, Any]] = []
    for pair_id in active.get("pair_ids") or []:
        row = ledger_by_id[str(pair_id)]
        row["attempts"] = int(row.get("attempts") or 0) + 1
        row["last_shard_index"] = shard_index
        row["disposition"] = "UNRESOLVED_COMPOSITION"
        row["reason"] = clean_reason
        row["evidence"] = ""
        row["chain_id"] = ""
        row["output_sha256"] = preserved_transcript_sha256
        pair_results.append(
            {
                "pair_id": pair_id,
                "disposition": "UNRESOLVED_COMPOSITION",
                "reason": clean_reason,
                "evidence": "",
                "chain_id": "",
                "attempts": row["attempts"],
                "last_shard_index": shard_index,
                "output_sha256": preserved_transcript_sha256,
            }
        )
    ledger.setdefault("shards", []).append(
        {
            "shard_index": shard_index,
            "pass_index": int(active.get("pass_index") or 0),
            "cursor_start": int(active.get("cursor_start") or 0),
            "cursor_end": int(active.get("cursor_end") or 0),
            "pair_ids": list(active.get("pair_ids") or []),
            "input_path": str(active.get("input_path") or ""),
            "input_sha256": str(active.get("input_sha256") or ""),
            "output_path": preserved_transcript_path,
            "output_sha256": preserved_transcript_sha256,
            "worker_claimed_pairs": None,
            "mechanical_consumed_pairs": 0,
            "issues": list(failure_issues),
            "terminal_status": "DEBT",
        }
    )
    ledger["cursor"] = int(active.get("cursor_end") or ledger.get("cursor") or 0)
    ledger["active_shard"] = None
    ledger["issues"] = list(dict.fromkeys([
        *ledger.get("issues", []), *failure_issues,
    ]))
    journal = _read_scheduler_journal(root)
    shard_key = f"{shard_index:04d}"
    started = dict(journal.get("started_shards") or {})
    started_row = started.get(shard_key)
    if not isinstance(started_row, Mapping):
        raise ChainTailAuthorityError("failed shard lacks its started journal row")
    relative = disposition_receipt_name.replace("\\", "/").strip("/")
    if str(started_row.get("disposition_receipt_path") or "") != relative:
        raise ChainTailAuthorityError("failed shard disposition path changed")
    if preserved_abandoned_binding:
        expected_model_key_suffix = (
            f"/chain_iter2/tail_shard_model.{shard_index:04d}"
        )
        if (
            not str(
                preserved_abandoned_binding.get("work_unit_key") or ""
            ).endswith(expected_model_key_suffix)
            or preserved_abandoned_binding.get("expected_transcript_path")
            != str(started_row.get("transcript_path") or "")
            or (root / str(started_row.get("transcript_path") or "")).exists()
        ):
            raise ChainTailAuthorityError(
                "failed shard abandoned MODEL lineage changed"
            )
    disposition: dict[str, Any] = {
        "schema_version": "plamen.chain_tail.shard_disposition_receipt.v1",
        "authority": "DRIVER_RECONCILIATION",
        "terminal_kind": "FAILURE",
        "shard_index": shard_index,
        "manifest_sha256": manifest["manifest_sha256"],
        "work_unit_path": str(started_row.get("work_unit_path") or ""),
        "work_unit_sha256": str(started_row.get("work_unit_sha256") or ""),
        "transcript_path": preserved_transcript_path,
        "transcript_sha256": preserved_transcript_sha256,
        "pair_ids": list(active.get("pair_ids") or []),
        "pair_results": pair_results,
        "mechanical_consumed_pairs": 0,
        "worker_claimed_pairs": None,
        "issues": list(failure_issues),
        "terminal_status": "DEBT",
        "model_binding": preserved_model_binding,
        "abandoned_model_binding": preserved_abandoned_binding,
    }
    disposition["receipt_sha256"] = _digest(disposition, "receipt_sha256")
    ledger["ledger_sha256"] = _digest(ledger, "ledger_sha256")
    plan_relative = _terminal_plan_relative(relative)
    plan: dict[str, Any] = {
        "schema_version": "plamen.chain_tail.terminal_plan.v1",
        "authority": "TRANSACTION_INTENT_ONLY",
        "shard_index": shard_index,
        "manifest_sha256": manifest["manifest_sha256"],
        "work_unit_path": str(started_row.get("work_unit_path") or ""),
        "work_unit_sha256": str(started_row.get("work_unit_sha256") or ""),
        "pre_ledger_sha256": pre_ledger_sha256,
        "post_ledger": ledger,
        "disposition_receipt_path": relative,
        "disposition_receipt": disposition,
    }
    plan["plan_sha256"] = _digest(plan, "plan_sha256")
    plan_path = root / plan_relative
    if plan_path.is_file():
        if _validated_terminal_plan(plan_path) != plan:
            raise ChainTailAuthorityError(
                "failed chain-tail terminal plan changed on resume"
            )
    else:
        _atomic_json(plan_path, plan)
    return _apply_terminal_plan(
        root,
        plan_path=plan_path,
        disposition_receipt_name=relative,
    )


def chain_tail_budget_stop_generation(scratchpad: Path) -> dict[str, Any]:
    """Describe the exact quiescent control generation a budget stop may own."""

    _manifest, ledger = _load_manifest_ledger(Path(scratchpad))
    if isinstance(ledger.get("active_shard"), Mapping):
        raise ChainTailAuthorityError(
            "chain-tail budget stop cannot discard an active shard"
        )
    return {
        "pass_index": int(ledger.get("pass_index") or 0),
        "next_shard_index": len(ledger.get("shards") or []),
        "ledger_sha256": str(ledger.get("ledger_sha256") or ""),
    }


def mark_chain_tail_budget_stop(
    scratchpad: Path,
    reason: str,
    *,
    expected_pass_index: int | None = None,
    expected_next_shard_index: int | None = None,
    expected_ledger_sha256: str | None = None,
) -> dict[str, Any]:
    scratchpad = Path(scratchpad)
    manifest, ledger = _load_manifest_ledger(scratchpad)
    actual_generation = {
        "pass_index": int(ledger.get("pass_index") or 0),
        "next_shard_index": len(ledger.get("shards") or []),
        "ledger_sha256": str(ledger.get("ledger_sha256") or ""),
    }
    expected_generation = {
        "pass_index": expected_pass_index,
        "next_shard_index": expected_next_shard_index,
        "ledger_sha256": expected_ledger_sha256,
    }
    for field, expected in expected_generation.items():
        if expected is not None and actual_generation[field] != expected:
            raise ChainTailAuthorityError(
                "chain-tail budget-stop generation changed before mutation: "
                f"{field}"
            )
    if isinstance(ledger.get("active_shard"), Mapping):
        raise ChainTailAuthorityError(
            "chain-tail budget stop cannot discard an active shard"
        )
    clean_reason = re.sub(r"[^A-Z0-9_]+", "_", str(reason).upper()).strip("_")
    clean_reason = clean_reason or "CHAIN_TAIL_BUDGET_STOP"
    cursor = int(ledger.get("cursor") or 0)
    remaining_retry = set(
        (ledger.get("retry_pair_ids") or [])[int(ledger.get("retry_cursor") or 0):]
    )
    for row in ledger.get("pairs", []):
        is_unseen_tail = int(row.get("ordinal") or 0) >= cursor and not int(row.get("attempts") or 0)
        if row.get("pair_id") in remaining_retry:
            is_unseen_tail = True
        if row.get("disposition") == "UNRESOLVED_COMPOSITION" and is_unseen_tail:
            row["reason"] = "BUDGET_STOP_UNEXAMINED"
    ledger["budget_stop_reason"] = clean_reason
    ledger["active_shard"] = None
    ledger["issues"] = list(dict.fromkeys([*ledger.get("issues", []), "CHAIN_TAIL_BUDGET_STOP"]))
    _write_ledger(scratchpad / LEDGER_NAME, ledger)
    manifest, ledger = _load_manifest_ledger(scratchpad)
    _write_composition_candidates(scratchpad, manifest, ledger)
    return _write_receipt_and_projection(
        scratchpad, manifest, ledger, status_override="BUDGET_STOP"
    )


def _rearm_predecessor_manifest_ledger(
    scratchpad: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load the immutable retry predecessor, including crash recovery.

    Once a terminal snapshot exists, the canonical root ledger is the frozen
    predecessor even after a partially applied retry makes mutable control
    differ.  Pre-isolation compatibility callers have no snapshot and retain
    the ordinary authoritative-ledger selection.
    """

    root = Path(scratchpad)
    snapshot_path = root / TERMINAL_SNAPSHOT_NAME
    if not snapshot_path.is_file():
        return _load_manifest_ledger(root)

    root_manifest = root / MANIFEST_NAME
    control_manifest = root / CONTROL_MANIFEST_PATH
    manifest_path = (
        control_manifest if control_manifest.is_file() else root_manifest
    )
    manifest = _read_json(manifest_path)
    if (
        not root_manifest.is_file()
        or (
            control_manifest.is_file()
            and root_manifest.read_bytes() != control_manifest.read_bytes()
        )
        or manifest.get("schema_version") != MANIFEST_SCHEMA
        or manifest.get("manifest_sha256")
        != _digest(manifest, "manifest_sha256")
    ):
        raise ChainTailAuthorityError(
            "chain-tail rearm manifest predecessor is invalid"
        )

    snapshot = _read_json(snapshot_path)
    ledger = _read_json(root / LEDGER_NAME)
    semantic_ledger = snapshot.get("semantic_ledger")
    try:
        terminal_generation = _terminal_snapshot_generation(snapshot)
    except ChainTailAuthorityError as exc:
        raise ChainTailAuthorityError(
            "chain-tail rearm terminal predecessor is legacy or malformed"
        ) from exc
    if (
        snapshot.get("schema_version") != TERMINAL_SNAPSHOT_SCHEMA
        or snapshot.get("snapshot_sha256")
        != _digest(snapshot, "snapshot_sha256")
        or snapshot.get("manifest_sha256")
        != manifest.get("manifest_sha256")
        or not isinstance(semantic_ledger, Mapping)
        or ledger != semantic_ledger
        or ledger.get("schema_version") != LEDGER_SCHEMA
        or ledger.get("ledger_sha256")
        != _digest(ledger, "ledger_sha256")
        or ledger.get("manifest_sha256")
        != manifest.get("manifest_sha256")
        or _ledger_terminal_generation(ledger) != terminal_generation
    ):
        raise ChainTailAuthorityError(
            "chain-tail rearm terminal predecessor is invalid or stale"
        )
    return manifest, ledger


def plan_rearm_unresolved_chain_tail(
    scratchpad: Path,
) -> dict[str, Any]:
    """Purely derive the exact five-output retry-control postimage."""

    root = Path(scratchpad)
    manifest, predecessor = _rearm_predecessor_manifest_ledger(root)
    if isinstance(predecessor.get("active_shard"), Mapping):
        raise ChainTailAuthorityError(
            "cannot rearm chain tail with an active shard"
        )
    unresolved_ids = [
        str(row["pair_id"])
        for row in predecessor.get("pairs", [])
        if row.get("disposition") == "UNRESOLVED_COMPOSITION"
    ]
    if not unresolved_ids:
        raise ChainTailAuthorityError(
            "chain-tail rearm has no unresolved denominator"
        )
    ledger = copy.deepcopy(predecessor)
    ledger["retry_pair_ids"] = unresolved_ids
    ledger["retry_cursor"] = 0
    ledger["pass_index"] = int(ledger.get("pass_index") or 0) + 1
    ledger["budget_stop_reason"] = ""
    ledger["active_shard"] = None
    ledger["ledger_sha256"] = _digest(ledger, "ledger_sha256")

    receipt = _receipt_from_state(manifest, ledger)
    candidates = _composition_candidate_payload(manifest, ledger)
    projection = _render_projection(receipt, ledger).encode("utf-8")

    journal_path = root / CONTROL_DIR / CONTROL_JOURNAL_NAME
    _read_scheduler_journal(root)
    journal_stat = journal_path.lstat()
    if (
        not stat.S_ISREG(journal_stat.st_mode)
        or int(journal_stat.st_nlink) != 1
    ):
        raise ChainTailAuthorityError(
            "chain-tail rearm journal is not a single-link regular file"
        )
    journal_bytes = journal_path.read_bytes()

    postimages = {
        f"{CONTROL_DIR}/{LEDGER_NAME}": _render_json_postimage(ledger),
        f"{CONTROL_DIR}/{RECEIPT_NAME}": _render_json_postimage(receipt),
        f"{CONTROL_DIR}/{COMPOSITION_CANDIDATES_NAME}": (
            _render_json_postimage(candidates)
        ),
        f"{CONTROL_DIR}/{PROJECTION_NAME}": projection,
        f"{CONTROL_DIR}/{CONTROL_JOURNAL_NAME}": journal_bytes,
    }
    if set(postimages) != set(MUTABLE_CONTROL_PATHS):
        raise ChainTailAuthorityError(
            "chain-tail rearm postimage denominator is incomplete"
        )
    return {
        "pass_index": int(ledger["pass_index"]),
        "next_shard_index": len(ledger.get("shards") or []),
        "receipt": receipt,
        "postimages": postimages,
    }


def validate_rearm_unresolved_chain_tail_generation(
    scratchpad: Path,
    plan: Mapping[str, Any],
) -> list[str]:
    """Validate one frozen retry plan against its materialized generation."""

    root = Path(scratchpad)
    try:
        if not isinstance(plan, Mapping) or set(plan) != {
            "pass_index",
            "next_shard_index",
            "receipt",
            "postimages",
        }:
            raise ChainTailAuthorityError(
                "chain-tail rearm plan shape is invalid"
            )
        pass_index = plan.get("pass_index")
        next_shard_index = plan.get("next_shard_index")
        if type(pass_index) is not int or type(next_shard_index) is not int:
            raise ChainTailAuthorityError(
                "chain-tail rearm generation fields are malformed"
            )
        chain_tail_generation_id(pass_index, next_shard_index)

        postimages = plan.get("postimages")
        if not isinstance(postimages, Mapping):
            raise ChainTailAuthorityError(
                "chain-tail rearm postimages are absent"
            )
        if set(postimages) != set(MUTABLE_CONTROL_PATHS):
            raise ChainTailAuthorityError(
                "chain-tail rearm postimage denominator is incomplete"
            )

        live_postimages: dict[str, bytes] = {}
        for relative in MUTABLE_CONTROL_PATHS:
            raw = postimages.get(relative)
            if type(raw) is not bytes:
                raise ChainTailAuthorityError(
                    f"chain-tail rearm postimage is not immutable bytes: {relative}"
                )
            path = root / relative
            path_stat = path.lstat()
            if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISREG(
                path_stat.st_mode
            ):
                raise ChainTailAuthorityError(
                    f"chain-tail rearm live postimage is not regular: {relative}"
                )
            if (
                relative.endswith(f"/{CONTROL_JOURNAL_NAME}")
                and int(path_stat.st_nlink) != 1
            ):
                raise ChainTailAuthorityError(
                    "chain-tail rearm journal is not a single-link regular file"
                )
            live_raw = path.read_bytes()
            if live_raw != raw:
                raise ChainTailAuthorityError(
                    f"chain-tail rearm live postimage differs: {relative}"
                )
            live_postimages[relative] = live_raw

        decoded: dict[str, dict[str, Any]] = {}
        for relative in (
            f"{CONTROL_DIR}/{LEDGER_NAME}",
            f"{CONTROL_DIR}/{RECEIPT_NAME}",
            f"{CONTROL_DIR}/{COMPOSITION_CANDIDATES_NAME}",
            f"{CONTROL_DIR}/{CONTROL_JOURNAL_NAME}",
        ):
            payload = json.loads(live_postimages[relative].decode("utf-8"))
            if not isinstance(payload, dict):
                raise ChainTailAuthorityError(
                    f"chain-tail rearm JSON postimage is malformed: {relative}"
                )
            canonical_raw = _render_json_postimage(payload)
            allowed_canonical = (canonical_raw,)
            if relative.endswith(f"/{CONTROL_JOURNAL_NAME}"):
                allowed_canonical = (
                    canonical_raw,
                    canonical_raw.replace(b"\n", b"\r\n"),
                )
            if live_postimages[relative] not in allowed_canonical:
                raise ChainTailAuthorityError(
                    f"chain-tail rearm JSON postimage is not canonical: {relative}"
                )
            decoded[relative] = payload

        manifest_path = root / CONTROL_MANIFEST_PATH
        manifest = _read_json(manifest_path)
        if manifest.get("schema_version") != MANIFEST_SCHEMA:
            raise ChainTailAuthorityError("chain-tail manifest schema mismatch")
        if (
            manifest.get("manifest_sha256")
            != _digest(manifest, "manifest_sha256")
        ):
            raise ChainTailAuthorityError("chain-tail manifest digest mismatch")
        manifest_pairs = manifest.get("pairs")
        denominator = manifest.get("denominator")
        if (
            not isinstance(manifest_pairs, list)
            or type(denominator) is not int
            or denominator != len(manifest_pairs)
        ):
            raise ChainTailAuthorityError(
                "chain-tail manifest denominator semantics are invalid"
            )
        manifest_ids = [
            row.get("pair_id") if isinstance(row, Mapping) else None
            for row in manifest_pairs
        ]
        if (
            any(not isinstance(pair_id, str) or not pair_id for pair_id in manifest_ids)
            or len(set(manifest_ids)) != len(manifest_ids)
        ):
            raise ChainTailAuthorityError(
                "chain-tail manifest pair identities are invalid"
            )

        ledger = decoded[f"{CONTROL_DIR}/{LEDGER_NAME}"]
        if ledger.get("schema_version") != LEDGER_SCHEMA:
            raise ChainTailAuthorityError("chain-tail ledger schema mismatch")
        if ledger.get("ledger_sha256") != _digest(
            ledger, "ledger_sha256"
        ):
            raise ChainTailAuthorityError("chain-tail ledger digest mismatch")
        if ledger.get("manifest_sha256") != manifest.get(
            "manifest_sha256"
        ):
            raise ChainTailAuthorityError(
                "chain-tail ledger is stale for manifest"
            )
        ledger_pairs = ledger.get("pairs")
        if (
            ledger.get("denominator") != denominator
            or not isinstance(ledger_pairs, list)
            or len(ledger_pairs) != denominator
        ):
            raise ChainTailAuthorityError(
                "chain-tail ledger denominator semantics are invalid"
            )
        ledger_ids = [
            row.get("pair_id") if isinstance(row, Mapping) else None
            for row in ledger_pairs
        ]
        if ledger_ids != manifest_ids:
            raise ChainTailAuthorityError(
                "chain-tail manifest/ledger identity or order mismatch"
            )
        retry_pair_ids = ledger.get("retry_pair_ids")
        unresolved_ids = [
            str(row["pair_id"])
            for row in ledger_pairs
            if isinstance(row, Mapping)
            and row.get("disposition") == "UNRESOLVED_COMPOSITION"
        ]
        if (
            not unresolved_ids
            or not isinstance(retry_pair_ids, list)
            or retry_pair_ids != unresolved_ids
            or ledger.get("active_shard") is not None
            or type(ledger.get("retry_cursor")) is not int
            or ledger.get("retry_cursor") != 0
            or ledger.get("budget_stop_reason") != ""
        ):
            raise ChainTailAuthorityError(
                "chain-tail rearm retry semantics are invalid"
            )
        if _ledger_terminal_generation(ledger) != (
            pass_index,
            next_shard_index,
        ):
            raise ChainTailAuthorityError(
                "chain-tail rearm generation does not match ledger"
            )

        receipt = plan.get("receipt")
        decoded_receipt = decoded[f"{CONTROL_DIR}/{RECEIPT_NAME}"]
        expected_receipt = _receipt_from_state(manifest, ledger)
        if (
            not isinstance(receipt, Mapping)
            or dict(receipt) != decoded_receipt
            or decoded_receipt != expected_receipt
            or decoded_receipt.get("pass_index") != pass_index
            or decoded_receipt.get("status") != "CONTINUE"
        ):
            raise ChainTailAuthorityError(
                "chain-tail rearm receipt semantics are invalid"
            )

        candidates = decoded[
            f"{CONTROL_DIR}/{COMPOSITION_CANDIDATES_NAME}"
        ]
        if candidates != _composition_candidate_payload(manifest, ledger):
            raise ChainTailAuthorityError(
                "chain-tail rearm candidate projection is invalid"
            )
        if live_postimages[
            f"{CONTROL_DIR}/{PROJECTION_NAME}"
        ] != _render_projection(decoded_receipt, ledger).encode("utf-8"):
            raise ChainTailAuthorityError(
                "chain-tail rearm Markdown projection is invalid"
            )

        journal = decoded[f"{CONTROL_DIR}/{CONTROL_JOURNAL_NAME}"]
        if _read_scheduler_journal(root) != journal:
            raise ChainTailAuthorityError(
                "chain-tail rearm scheduler journal is invalid"
            )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
        ChainTailAuthorityError,
    ) as exc:
        return [
            "chain-tail rearm generation invalid: "
            f"{type(exc).__name__}: {exc}"
        ]
    return []


def rearm_unresolved_chain_tail(scratchpad: Path) -> dict[str, Any]:
    """Compatibility wrapper for direct callers; production uses PhaseIO."""

    root = Path(scratchpad)
    with _scheduler_lock(root):
        plan = plan_rearm_unresolved_chain_tail(root)
        postimages = plan["postimages"]
        for relative in MUTABLE_CONTROL_PATHS:
            raw = postimages[relative]
            path = root / relative
            if relative.endswith(f"/{CONTROL_JOURNAL_NAME}"):
                # The retry does not semantically mutate scheduler history.
                if path.read_bytes() != raw:
                    raise ChainTailAuthorityError(
                        "chain-tail rearm journal changed before apply"
                    )
                continue
            _atomic_bytes(path, raw)
        issues = validate_rearm_unresolved_chain_tail_generation(
            root, plan
        )
        if issues:
            raise ChainTailAuthorityError("; ".join(issues))
        return dict(plan["receipt"])


def run_chain_tail_shard_loop(
    scratchpad: Path,
    execute_next_shard: Callable[[dict[str, Any]], int],
    *,
    max_shards_per_run: int = 8,
    max_seconds: float | None = None,
) -> dict[str, Any]:
    """Reconcile the current worker output and deterministically continue.

    ``execute_next_shard`` is the only backend-specific hook.  It receives the
    exact typed shard and must return a process return code after writing
    ``chain_iteration2.md``.  Non-zero exit, time budget, or shard budget is a
    durable budget/debt outcome, never clean completion.
    """
    if max_shards_per_run < 1:
        raise ChainTailAuthorityError("max_shards_per_run must be positive")
    scratchpad = Path(scratchpad)
    begin_isolated_chain_tail_scheduler(scratchpad)
    started = time.monotonic()
    processed_this_run = 0
    manifest, ledger = _load_manifest_ledger(scratchpad)
    if not isinstance(ledger.get("active_shard"), dict):
        if int(manifest.get("denominator") or 0) == 0:
            return finalize_chain_tail_aggregate_output(scratchpad)
        receipt = _read_progress_receipt(scratchpad)
        if receipt.get("status") in {"BUDGET_STOP", "DEGRADED_UNRESOLVED"}:
            rearm_unresolved_chain_tail(scratchpad)
            prepare_next_chain_tail_shard(scratchpad)
        elif receipt.get("status") == "CONTINUE":
            prepare_next_chain_tail_shard(scratchpad)
    while True:
        receipt = reconcile_chain_tail_output(scratchpad)
        processed_this_run += 1
        if receipt.get("status") != "CONTINUE":
            break
        if processed_this_run >= max_shards_per_run:
            receipt = mark_chain_tail_budget_stop(
                scratchpad, "CHAIN_TAIL_SHARD_BUDGET"
            )
            break
        if max_seconds is not None and time.monotonic() - started >= max_seconds:
            receipt = mark_chain_tail_budget_stop(
                scratchpad, "CHAIN_TAIL_TIME_BUDGET"
            )
            break
        shard = prepare_next_chain_tail_shard(scratchpad)
        output = scratchpad / "chain_iteration2.md"
        try:
            output.unlink(missing_ok=True)
        except OSError:
            pass
        rc = int(execute_next_shard(shard))
        if rc != 0:
            receipt = mark_chain_tail_budget_stop(
                scratchpad,
                "CHAIN_TAIL_WORKER_TIMEOUT" if rc == -2 else "CHAIN_TAIL_WORKER_FAILURE",
            )
            break
    return finalize_chain_tail_aggregate_output(scratchpad)


def prepare_final_chain_tail_publication(
    scratchpad: Path,
    *,
    snapshot_sha256: str,
    producer_key: str,
    producer_contract_digest: str,
) -> None:
    """Consume a generation-scoped prearm before replacing presentation."""

    root = Path(scratchpad)
    manifest, ledger = _load_manifest_ledger(root)
    generation = _ledger_terminal_generation(ledger)
    generation_id = chain_tail_generation_id(*generation)
    if isinstance(ledger.get("active_shard"), Mapping):
        raise ChainTailAuthorityError(
            "cannot arm final chain-tail publication with an active shard"
        )
    if int(manifest.get("denominator") or 0) != len(ledger.get("pairs") or []):
        raise ChainTailAuthorityError(
            "cannot arm final chain-tail publication with denominator drift"
        )
    snapshot = _read_json(root / TERMINAL_SNAPSHOT_NAME)
    _terminal_producer_prefix(
        producer_key,
        role="tail_reconcile",
        generation_id=generation_id,
    )
    if (
        _terminal_snapshot_generation(snapshot) != generation
        or snapshot.get("snapshot_sha256") != snapshot_sha256
        or snapshot.get("snapshot_sha256")
        != _digest(snapshot, "snapshot_sha256")
    ):
        raise ChainTailAuthorityError(
            "cannot arm final chain-tail publication for a different generation"
        )
    with _scheduler_lock(root):
        marker = root / CONTROL_DIR / PUBLICATION_ARMED_NAME
        if marker.is_file():
            existing = _read_json(marker)
            if (
                existing.get("marker_sha256")
                == _digest(existing, "marker_sha256")
                and existing.get("state") == "ARMED"
                and existing.get("snapshot_sha256") == snapshot_sha256
                and existing.get("producer_key") == producer_key
                and existing.get("producer_contract_digest")
                == producer_contract_digest
            ):
                return
            raise ChainTailAuthorityError(
                "another chain-tail publication generation is already armed"
            )
        for name in (
            LEDGER_NAME,
            RECEIPT_NAME,
            COMPOSITION_CANDIDATES_NAME,
            PROJECTION_NAME,
            "chain_iteration2.md",
        ):
            try:
                (root / name).unlink(missing_ok=True)
            except OSError as exc:
                raise ChainTailAuthorityError(
                    f"cannot clear stale chain-tail compatibility output: {name}"
                ) from exc
        payload: dict[str, Any] = {
            "schema_version": "plamen.chain_tail.final_publication.v1",
            "authority": "CONTROL_ONLY",
            "state": "ARMED",
            "snapshot_sha256": snapshot_sha256,
            "producer_key": producer_key,
            "producer_contract_digest": producer_contract_digest,
        }
        payload["marker_sha256"] = _digest(payload, "marker_sha256")
        _atomic_json(marker, payload)


def align_terminal_control_generation(
    scratchpad: Path,
    *,
    terminal_snapshot_name: str = TERMINAL_SNAPSHOT_NAME,
) -> dict[str, str]:
    """Align mutable control to the exact pre-armed terminal postimage.

    The caller must already have armed a PhaseIO transaction that owns both
    the canonical root publication and every mutable control output.  This
    renderer grants no authority on its own: it copies the four corresponding
    semantic postimages byte-for-byte and proves that the scheduler journal
    stayed physically and byte-for-byte unchanged.  The enclosing transaction
    thereby has one exact control predecessor for a later typed rearm.
    """

    root = Path(scratchpad)
    if terminal_snapshot_name != TERMINAL_SNAPSHOT_NAME:
        raise ChainTailAuthorityError(
            "terminal control alignment requires the canonical snapshot"
        )
    if not _publication_is_armed(root):
        raise ChainTailAuthorityError(
            "terminal control alignment requires an armed publication"
        )

    snapshot = _read_json(root / terminal_snapshot_name)
    ledger = _read_json(root / LEDGER_NAME)
    receipt = _read_json(root / RECEIPT_NAME)
    candidates = _read_json(root / COMPOSITION_CANDIDATES_NAME)
    semantic_ledger = snapshot.get("semantic_ledger")
    try:
        terminal_generation = _terminal_snapshot_generation(snapshot)
    except ChainTailAuthorityError as exc:
        raise ChainTailAuthorityError(
            "terminal root postimage uses a legacy or malformed generation"
        ) from exc
    if (
        snapshot.get("schema_version") != TERMINAL_SNAPSHOT_SCHEMA
        or snapshot.get("snapshot_sha256")
        != _digest(snapshot, "snapshot_sha256")
        or not isinstance(semantic_ledger, Mapping)
        or ledger != semantic_ledger
        or ledger.get("ledger_sha256")
        != _digest(ledger, "ledger_sha256")
        or receipt.get("ledger_sha256") != ledger.get("ledger_sha256")
        or receipt.get("authority_digest")
        != _digest(receipt, "authority_digest")
        or candidates.get("ledger_sha256") != ledger.get("ledger_sha256")
        or candidates.get("candidate_digest")
        != _digest(candidates, "candidate_digest")
        or not (root / PROJECTION_NAME).is_file()
        or _ledger_terminal_generation(ledger) != terminal_generation
    ):
        raise ChainTailAuthorityError(
            "terminal root postimage is invalid or stale"
        )

    corresponding = (
        LEDGER_NAME,
        RECEIPT_NAME,
        COMPOSITION_CANDIDATES_NAME,
        PROJECTION_NAME,
    )
    postimages = {
        name: (root / name).read_bytes()
        for name in corresponding
    }
    journal_path = root / CONTROL_DIR / CONTROL_JOURNAL_NAME
    _read_scheduler_journal(root)
    journal_stat = journal_path.lstat()
    if (
        not stat.S_ISREG(journal_stat.st_mode)
        or int(journal_stat.st_nlink) != 1
    ):
        raise ChainTailAuthorityError(
            "terminal scheduler journal is not a single-link regular file"
        )
    journal_bytes = journal_path.read_bytes()
    journal_identity = (journal_stat.st_dev, journal_stat.st_ino)

    for name in corresponding:
        _atomic_bytes(root / CONTROL_DIR / name, postimages[name])

    if any(
        (root / CONTROL_DIR / name).read_bytes() != postimages[name]
        for name in corresponding
    ):
        raise ChainTailAuthorityError(
            "terminal root/control byte parity failed"
        )
    _read_scheduler_journal(root)
    post_journal_stat = journal_path.lstat()
    if (
        not stat.S_ISREG(post_journal_stat.st_mode)
        or int(post_journal_stat.st_nlink) != 1
        or (post_journal_stat.st_dev, post_journal_stat.st_ino)
        != journal_identity
        or journal_path.read_bytes() != journal_bytes
    ):
        raise ChainTailAuthorityError(
            "terminal scheduler journal changed during alignment"
        )
    return {
        "ledger_sha256": str(ledger.get("ledger_sha256") or ""),
        "receipt_sha256": _sha256_bytes(postimages[RECEIPT_NAME]),
        "candidates_sha256": _sha256_bytes(
            postimages[COMPOSITION_CANDIDATES_NAME]
        ),
        "projection_sha256": _sha256_bytes(postimages[PROJECTION_NAME]),
        "scheduler_journal_sha256": _sha256_bytes(journal_bytes),
    }


def commit_final_chain_tail_publication(
    scratchpad: Path,
    *,
    snapshot_sha256: str,
    producer_key: str,
    producer_contract_digest: str,
) -> None:
    """Consume the exact ARMED capability only after PhaseIO output commit."""

    root = Path(scratchpad)
    with _scheduler_lock(root):
        marker = root / CONTROL_DIR / PUBLICATION_ARMED_NAME
        if not marker.is_file():
            raise ChainTailAuthorityError(
                "chain-tail final publication capability is absent"
            )
        payload = _read_json(marker)
        if (
            payload.get("marker_sha256")
            != _digest(payload, "marker_sha256")
            or payload.get("state") != "ARMED"
            or payload.get("snapshot_sha256") != snapshot_sha256
            or payload.get("producer_key") != producer_key
            or payload.get("producer_contract_digest")
            != producer_contract_digest
        ):
            raise ChainTailAuthorityError(
                "chain-tail final publication capability changed"
            )
        _observe_durable_transition("MARKER_UNLINK", "BEFORE", marker)
        marker.unlink()
        _observe_durable_transition("MARKER_UNLINK", "AFTER", marker)


def finalize_chain_tail_aggregate_output(
    scratchpad: Path,
    *,
    terminal_snapshot_name: str = "",
) -> dict[str, Any]:
    """Build one deterministic delta from every shard output.

    Shard workers can independently reuse a ``CH-N`` label.  Cross-shard
    collisions are resolved monotonically. Within one shard, byte-identical
    duplicate sections are deduplicated, while divergent reuse is ambiguous:
    the exact archive remains durable but affected pairs become unresolved
    debt and no section is guessed into the aggregate. The final aggregate is
    what the existing digest-bound chain merge consumes.
    """
    scratchpad = Path(scratchpad)
    manifest, ledger = _load_manifest_ledger(scratchpad)
    if terminal_snapshot_name:
        snapshot = _read_json(scratchpad / terminal_snapshot_name)
        try:
            terminal_generation = _terminal_snapshot_generation(snapshot)
        except ChainTailAuthorityError as exc:
            raise ChainTailAuthorityError(
                "chain-tail terminal snapshot is legacy or malformed"
            ) from exc
        if (
            snapshot.get("schema_version") != TERMINAL_SNAPSHOT_SCHEMA
            or snapshot.get("snapshot_sha256")
            != _digest(snapshot, "snapshot_sha256")
            or snapshot.get("manifest_sha256")
            != manifest.get("manifest_sha256")
            or not isinstance(snapshot.get("semantic_ledger"), Mapping)
            or _ledger_terminal_generation(snapshot["semantic_ledger"])
            != terminal_generation
        ):
            raise ChainTailAuthorityError(
                "chain-tail terminal snapshot is invalid or stale"
            )
        ledger = dict(snapshot["semantic_ledger"])
    existing_text = ""
    existing_path = scratchpad / "chain_hypotheses.md"
    if existing_path.exists():
        existing_text = existing_path.read_text(encoding="utf-8", errors="replace")
    used = {match.group(1).upper() for match in _CHAIN_HEADING_RE.finditer(existing_text)}
    next_number = max(
        [int(value.split("-", 1)[1]) for value in used if value.split("-", 1)[1].isdigit()]
        or [0]
    ) + 1
    aggregate_sections: list[str] = []
    rename_by_shard: dict[tuple[int, str], str] = {}
    for shard in sorted(ledger.get("shards", []), key=lambda row: int(row.get("shard_index") or 0)):
        relative = str(shard.get("output_path") or "")
        if not relative:
            ledger["issues"] = list(dict.fromkeys([
                *ledger.get("issues", []), "TRANSCRIPTLESS_TERMINAL_DEBT",
            ]))
            continue
        path = scratchpad / relative
        if not path.is_file():
            ledger["issues"] = list(dict.fromkeys([
                *ledger.get("issues", []), "SHARD_OUTPUT_ARCHIVE_MISSING",
            ]))
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        shard_index = int(shard.get("shard_index") or 0)
        sections = _chain_sections(text)
        divergent_ids = _divergent_duplicate_chain_ids(text)
        if divergent_ids:
            ledger["issues"] = list(dict.fromkeys([
                *ledger.get("issues", []), "DIVERGENT_DUPLICATE_CHAIN_IDENTITY",
            ]))
            for row in ledger.get("pairs", []):
                if (
                    int(row.get("last_shard_index") or 0) == shard_index
                    and row.get("disposition") == "COMPOSED"
                    and str(row.get("chain_id") or "").upper() in divergent_ids
                ):
                    row.update({
                        "disposition": "UNRESOLVED_COMPOSITION",
                        "reason": "DIVERGENT_DUPLICATE_CHAIN_IDENTITY",
                        "chain_id": "",
                    })
        seen_shard_ids: set[str] = set()
        for old_id, section in sections:
            if old_id in divergent_ids or old_id in seen_shard_ids:
                continue
            seen_shard_ids.add(old_id)
            new_id = old_id
            if new_id in used:
                while f"CH-{next_number}" in used:
                    next_number += 1
                new_id = f"CH-{next_number}"
                next_number += 1
            used.add(new_id)
            rename_by_shard[(shard_index, old_id)] = new_id
            normalized = re.sub(rf"\b{re.escape(old_id)}\b", new_id, section, flags=re.I)
            aggregate_sections.append(normalized)
    for row in ledger.get("pairs", []):
        if row.get("disposition") != "COMPOSED" or not row.get("chain_id"):
            continue
        key = (int(row.get("last_shard_index") or 0), str(row["chain_id"]).upper())
        new_id = rename_by_shard.get(key)
        if new_id:
            old_id = str(row["chain_id"])
            row["chain_id"] = new_id
            row["evidence"] = re.sub(
                rf"\b{re.escape(old_id)}\b", new_id, str(row.get("evidence") or ""), flags=re.I
            )
    if terminal_snapshot_name:
        ledger["ledger_sha256"] = _digest(ledger, "ledger_sha256")
        _atomic_json(scratchpad / LEDGER_NAME, ledger)
        candidate_payload = _composition_candidate_payload(manifest, ledger)
        _atomic_json(
            scratchpad / COMPOSITION_CANDIDATES_NAME, candidate_payload
        )
    else:
        _write_ledger(scratchpad / LEDGER_NAME, ledger)
        manifest, ledger = _load_manifest_ledger(scratchpad)
        _write_composition_candidates(scratchpad, manifest, ledger)
    lines = [
        "# Chain Iteration 2 Aggregate Delta",
        "",
        "This driver-owned delta preserves every shard proposal and binds every",
        "pair disposition to the authoritative manifest. Composed chains remain",
        "unproven candidates for ordinary independent verification.",
        "",
    ]
    if aggregate_sections:
        lines.extend(("\n\n".join(aggregate_sections), ""))
    else:
        lines.extend(("_No additional chain hypotheses were emitted._", ""))
    lines.extend((
        "## Tail Pair Dispositions",
        "",
        "| Pair ID | Finding A | Finding B | Disposition | Evidence |",
        "|---|---|---|---|---|",
    ))
    for row in ledger.get("pairs", []):
        disposition = str(row.get("disposition") or "UNRESOLVED_COMPOSITION")
        if disposition == "UNRESOLVED_COMPOSITION":
            disposition = "DEFERRED"
            evidence = (
                f"{row.get('reason') or 'UNRESOLVED'}; exact details in {LEDGER_NAME}"
            )
        else:
            evidence = str(row.get("evidence") or "")
        lines.append(
            f"| {row['pair_id']} | {row['a']} | {row['b']} | {disposition} | "
            f"{evidence.replace('|', '/')} |"
        )
    if not ledger.get("pairs"):
        lines.append("| (none) | - | - | EXPLORED | exact empty denominator |")
    _atomic_text(scratchpad / "chain_iteration2.md", "\n".join(lines) + "\n")
    try:
        prior = _read_progress_receipt(scratchpad)
    except Exception:
        prior = {}
    status_override = (
        "BUDGET_STOP" if ledger.get("budget_stop_reason") else ""
    )
    receipt_kwargs = {
        "status_override": status_override,
        "last_mechanical_count": int(
            prior.get("mechanical_consumed_pairs") or 0
        ),
        "last_worker_claim": (
            int(prior["worker_claimed_pairs"])
            if prior.get("worker_claimed_pairs") is not None else None
        ),
    }
    if terminal_snapshot_name:
        receipt = _receipt_from_state(
            manifest,
            ledger,
            **receipt_kwargs,
        )
        _atomic_json(scratchpad / RECEIPT_NAME, receipt)
        _atomic_text(
            scratchpad / PROJECTION_NAME,
            _render_projection(receipt, ledger),
        )
        return receipt
    return _write_receipt_and_projection(
        scratchpad,
        manifest,
        ledger,
        **receipt_kwargs,
    )


def validate_chain_tail_authority(
    scratchpad: Path,
    *,
    require_complete: bool = False,
) -> list[str]:
    scratchpad = Path(scratchpad)
    issues: list[str] = []
    try:
        manifest, ledger = _load_manifest_ledger(scratchpad)
    except Exception as exc:
        return [f"chain-tail authority unavailable: {type(exc).__name__}: {exc}"]
    isolated_scheduler = (
        scratchpad / CONTROL_DIR / CONTROL_JOURNAL_NAME
    ).is_file()
    use_control = bool(
        isolated_scheduler
        and not (
            scratchpad / CONTROL_DIR / PUBLICATION_ARMED_NAME
        ).is_file()
        and not _terminal_publication_is_complete(scratchpad)
    )
    selected_base = (
        scratchpad / CONTROL_DIR if use_control else scratchpad
    )
    try:
        receipt = _read_json(selected_base / RECEIPT_NAME)
    except Exception as exc:
        return [f"chain-tail receipt unavailable: {type(exc).__name__}: {exc}"]
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        issues.append("chain-tail receipt schema mismatch")
    if receipt.get("authority_digest") != _digest(receipt, "authority_digest"):
        issues.append("chain-tail receipt authority digest mismatch")
    if receipt.get("manifest_sha256") != manifest.get("manifest_sha256"):
        issues.append("chain-tail receipt stale for manifest")
    if receipt.get("ledger_sha256") != ledger.get("ledger_sha256"):
        issues.append("chain-tail receipt stale for ledger")
    denominator = int(manifest.get("denominator") or 0)
    manifest_ids = [row.get("pair_id") for row in manifest.get("pairs", [])]
    ledger_ids = [row.get("pair_id") for row in ledger.get("pairs", [])]
    if denominator != len(manifest_ids) or denominator != len(ledger_ids):
        issues.append("chain-tail denominator/row-count mismatch")
    if len(set(manifest_ids)) != len(manifest_ids):
        issues.append("chain-tail manifest pair identities are not unique")
    if manifest_ids != ledger_ids:
        issues.append("chain-tail manifest/ledger identity or order mismatch")
    if receipt.get("denominator") != denominator:
        issues.append("chain-tail receipt denominator mismatch")
    if int(ledger.get("denominator") or 0) != denominator:
        issues.append("chain-tail ledger denominator mismatch")
    cursor = int(ledger.get("cursor") or 0)
    if not 0 <= cursor <= denominator:
        issues.append("chain-tail ledger cursor outside denominator")
    if receipt.get("cursor") != cursor:
        issues.append("chain-tail receipt cursor mismatch")
    active = ledger.get("active_shard")
    expected_active_index = (
        active.get("shard_index") if isinstance(active, Mapping) else None
    )
    if receipt.get("active_shard_index") != expected_active_index:
        issues.append("chain-tail receipt active shard mismatch")
    ledger_by_id = {
        str(row.get("pair_id")): row
        for row in ledger.get("pairs", [])
        if isinstance(row, Mapping)
    }
    if isinstance(active, Mapping):
        active_ids = list(active.get("pair_ids") or [])
        if not active_ids or any(pair_id not in set(manifest_ids) for pair_id in active_ids):
            issues.append("chain-tail active shard identity mismatch")
        try:
            cursor_start = int(active.get("cursor_start"))
            cursor_end = int(active.get("cursor_end"))
            shard_size = int(manifest.get("shard_size") or 0)
            if not 0 <= cursor_start < cursor_end:
                issues.append("chain-tail active shard cursor range invalid")
            if len(active_ids) > shard_size:
                issues.append("chain-tail active shard exceeds shard budget")
            if bool(active.get("retry_mode")):
                retry_ids = list(ledger.get("retry_pair_ids") or [])
                retry_cursor = int(ledger.get("retry_cursor") or 0)
                if not 0 <= cursor_end <= len(retry_ids):
                    issues.append("chain-tail active retry cursor outside roster")
                    expected_active_ids: list[object] = []
                else:
                    expected_active_ids = retry_ids[cursor_start:cursor_end]
                if cursor_start != retry_cursor:
                    issues.append("chain-tail active retry cursor disagrees with ledger")
            else:
                if not 0 <= cursor_end <= denominator:
                    issues.append("chain-tail active shard cursor outside denominator")
                    expected_active_ids = []
                else:
                    expected_active_ids = [
                        str(row.get("pair_id"))
                        for row in ledger.get("pairs", [])[cursor_start:cursor_end]
                        if row.get("disposition") not in _TERMINAL
                    ]
                if cursor_start != cursor:
                    issues.append("chain-tail active shard cursor disagrees with ledger")
            if active_ids != expected_active_ids:
                issues.append("chain-tail active shard cursor/identity projection mismatch")
        except (TypeError, ValueError):
            issues.append("chain-tail active shard cursor metadata malformed")
    for ordinal, row in enumerate(ledger.get("pairs", [])):
        if ordinal >= cursor:
            break
        if int(row.get("attempts") or 0) <= 0:
            issues.append("chain-tail ledger cursor advances past unattempted pair")
            break
    retry_ids = list(ledger.get("retry_pair_ids") or [])
    retry_cursor = int(ledger.get("retry_cursor") or 0)
    if len(set(retry_ids)) != len(retry_ids) or any(
        pair_id not in ledger_by_id for pair_id in retry_ids
    ):
        issues.append("chain-tail retry roster identity mismatch")
    if not 0 <= retry_cursor <= len(retry_ids):
        issues.append("chain-tail retry cursor outside roster")
    budget_reason = str(ledger.get("budget_stop_reason") or "")
    if str(receipt.get("budget_stop_reason") or "") != budget_reason:
        issues.append("chain-tail receipt budget-stop reason mismatch")
    if budget_reason:
        if isinstance(active, Mapping):
            issues.append("chain-tail budget stop retains active shard")
        if not any(
            row.get("disposition") == "UNRESOLVED_COMPOSITION"
            for row in ledger.get("pairs", [])
        ):
            issues.append("chain-tail budget stop lacks unresolved work")
    family_members: list[str] = []
    for family in (manifest.get("families") or {}).values():
        if isinstance(family, Mapping):
            family_members.extend(family.get("member_pair_ids") or [])
    if sorted(family_members) != sorted(manifest_ids):
        issues.append("chain-tail family membership parity mismatch")
    dispositions, reasons, signals = _summary_counts(ledger)
    terminal = sum(dispositions[value] for value in _TERMINAL)
    unresolved = dispositions["UNRESOLVED_COMPOSITION"]
    if receipt.get("terminal_pairs") != terminal:
        issues.append("chain-tail receipt terminal count mismatch")
    if receipt.get("unresolved_pairs") != unresolved:
        issues.append("chain-tail receipt unresolved count mismatch")
    if terminal + unresolved != denominator:
        issues.append("chain-tail pairs lack exactly one disposition")
    if receipt.get("disposition_counts") != dict(sorted(dispositions.items())):
        issues.append("chain-tail disposition summary mismatch")
    if receipt.get("unresolved_reason_counts") != dict(sorted(reasons.items())):
        issues.append("chain-tail unresolved-reason summary mismatch")
    if receipt.get("signal_family_counts") != dict(sorted(signals.items())):
        issues.append("chain-tail signal-family summary mismatch")
    attempted = sum(
        1 for row in ledger.get("pairs", []) if int(row.get("attempts") or 0) > 0
    )
    remaining_unattempted = denominator - attempted
    if receipt.get("processed_pairs") != attempted:
        issues.append("chain-tail processed-pair summary mismatch")
    if receipt.get("remaining_unattempted_pairs") != remaining_unattempted:
        issues.append("chain-tail remaining-unattempted summary mismatch")
    expected_mismatch = "WORKER_MECHANICAL_COUNT_MISMATCH" in set(
        ledger.get("issues") or []
    )
    if bool(receipt.get("worker_mechanical_mismatch")) != expected_mismatch:
        issues.append("chain-tail worker/mechanical mismatch summary mismatch")
    expected_status = _semantic_status(manifest, ledger)
    if receipt.get("status") != expected_status:
        issues.append(
            "chain-tail receipt semantic status mismatch: "
            f"expected {expected_status}, got {receipt.get('status')}"
        )
    if require_complete and receipt.get("status") != "COMPLETE":
        issues.append(f"chain-tail status is not COMPLETE: {receipt.get('status')}")
    projection_path = selected_base / PROJECTION_NAME
    if not projection_path.exists():
        issues.append("chain-tail client projection missing")
    else:
        try:
            expected = _render_projection(receipt, ledger)
            actual = projection_path.read_text(encoding="utf-8", errors="strict")
            if actual != expected:
                issues.append("chain-tail client projection renderer parity mismatch")
            if len(actual.encode("utf-8")) > DEFAULT_PROJECTION_BYTE_CEILING:
                issues.append("chain-tail client projection exceeds byte ceiling")
        except Exception as exc:
            issues.append(f"chain-tail client projection invalid: {type(exc).__name__}: {exc}")
    for shard in ledger.get("shards", []):
        if not isinstance(shard, Mapping):
            continue
        relative = str(shard.get("output_path") or "")
        if not relative:
            continue
        archive_path = scratchpad / relative
        if not archive_path.exists():
            continue
        try:
            shard_index = int(shard.get("shard_index") or 0)
            divergent_ids = _divergent_duplicate_chain_ids(
                archive_path.read_text(encoding="utf-8", errors="replace")
            )
        except (OSError, TypeError, ValueError):
            continue
        if divergent_ids and any(
            int(row.get("last_shard_index") or 0) == shard_index
            and row.get("disposition") == "COMPOSED"
            and str(row.get("chain_id") or "").upper() in divergent_ids
            for row in ledger.get("pairs", [])
        ):
            issues.append(
                "chain-tail divergent duplicate chain identity remains terminal"
            )
    candidate_path = selected_base / COMPOSITION_CANDIDATES_NAME
    if candidate_path.exists():
        try:
            candidates = _read_json(candidate_path)
            if candidates.get("schema_version") != CANDIDATE_SCHEMA:
                issues.append("chain composition candidate schema mismatch")
            if candidates.get("candidate_digest") != _digest(
                candidates, "candidate_digest"
            ):
                issues.append("chain composition candidate digest mismatch")
            if candidates.get("manifest_sha256") != manifest.get("manifest_sha256"):
                issues.append("chain composition candidates stale for manifest")
            if candidates.get("ledger_sha256") != ledger.get("ledger_sha256"):
                issues.append("chain composition candidates stale for ledger")
            candidate_rows = candidates.get("candidates") or []
            expected_rows = _composition_candidate_payload(
                manifest, ledger
            ).get("candidates") or []
            # Candidate publication is a deterministic projection.  Compare
            # the complete grouped roster so one chain may bind the union of
            # several COMPOSED pair_ids, while orphan chain sections remain
            # visible as proof-less HUMAN_REVIEW debt.
            if candidate_rows != expected_rows:
                issues.append("chain composition candidate routing parity mismatch")
            if any(
                row.get("proof_authority") != "NONE"
                or row.get("route") not in {
                    "ORDINARY_VERIFICATION", "HUMAN_REVIEW",
                }
                or (
                    row.get("route") == "ORDINARY_VERIFICATION"
                    and not list(row.get("pair_ids") or [])
                )
                or (
                    row.get("route") == "HUMAN_REVIEW"
                    and (
                        list(row.get("pair_ids") or [])
                        or str(row.get("reason") or "")
                        != "ORPHAN_CHAIN_SECTION"
                    )
                )
                for row in candidate_rows if isinstance(row, dict)
            ):
                issues.append("chain composition candidate granted invalid authority")
        except Exception as exc:
            issues.append(f"chain composition candidates invalid: {type(exc).__name__}: {exc}")
    else:
        issues.append("chain composition candidate routing sidecar missing")
    return sorted(set(issues))
