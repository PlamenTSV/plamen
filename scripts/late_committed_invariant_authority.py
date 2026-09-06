"""Typed authority for committed invariants discovered after verification.

These records are deliberately incapable of granting current-run verification.
They retain only enough identity to route an exact verifier-emitted invariant to
human review and verification during the next run.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import uuid
from typing import Any, Mapping, Sequence

from plamen_parsers import COMMITTED_INVARIANT_ID_PATTERN


LATE_CI_AUTHORITY_SCHEMA = "plamen.late_committed_invariant_authority.v1"
LATE_CI_LEDGER_SCHEMA = "plamen.late_committed_invariant_ledger.v1"
LATE_CI_AUTHORITY = "HUMAN_REVIEW_NEXT_RUN"
LATE_CI_STATUS = "NEEDS_VERIFICATION"
LATE_CI_LEDGER_NAME = "_late_committed_invariant_authority.json"

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_CI_ID_RE = re.compile(COMMITTED_INVARIANT_ID_PATTERN)


class LateCommittedInvariantError(RuntimeError):
    """A late-CI derivation, persistence, or emission stage failed closed."""

    def __init__(self, *, stage: str, code: str, detail: str) -> None:
        self.stage = stage
        self.code = code
        self.detail = detail
        super().__init__(f"{stage}:{code}: {detail}")


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LateCommittedInvariantError(
            stage="PERSISTENCE",
            code="NON_CANONICAL_AUTHORITY",
            detail="late committed-invariant authority is not canonical JSON",
        ) from exc


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _relative_artifact(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise LateCommittedInvariantError(
            stage="DERIVATION",
            code="SOURCE_IDENTITY_INVALID",
            detail="late committed-invariant source artifact is not canonical",
        )
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise LateCommittedInvariantError(
            stage="DERIVATION",
            code="SOURCE_IDENTITY_INVALID",
            detail="late committed-invariant source artifact escapes scratchpad",
        )
    canonical = path.as_posix()
    if canonical != value or canonical.startswith("./"):
        raise LateCommittedInvariantError(
            stage="DERIVATION",
            code="SOURCE_IDENTITY_INVALID",
            detail="late committed-invariant source artifact is not canonical",
        )
    return canonical


def _digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise LateCommittedInvariantError(
            stage="DERIVATION",
            code="DIGEST_INVALID",
            detail=f"{label} digest is malformed",
        )
    return value


@dataclass(frozen=True)
class LateCommittedInvariantAuthority:
    """One exact verifier-emitted CI routed exclusively to the next run."""

    source_artifact: str
    source_artifact_sha256: str
    committed_invariant_id: str
    committed_invariant_sha256: str
    candidate_key: str
    authority_sha256: str
    schema: str = LATE_CI_AUTHORITY_SCHEMA
    authority: str = LATE_CI_AUTHORITY
    status: str = LATE_CI_STATUS

    @classmethod
    def create(
        cls,
        *,
        source_artifact: str,
        source_artifact_sha256: str,
        committed_invariant_id: str,
        committed_invariant_sha256: str,
        candidate_key: str,
    ) -> "LateCommittedInvariantAuthority":
        source = _relative_artifact(source_artifact)
        source_digest = _digest(
            source_artifact_sha256,
            label="source artifact",
        )
        ci_digest = _digest(
            committed_invariant_sha256,
            label="committed invariant",
        )
        if (
            not isinstance(committed_invariant_id, str)
            or _CI_ID_RE.fullmatch(committed_invariant_id) is None
        ):
            raise LateCommittedInvariantError(
                stage="DERIVATION",
                code="CI_IDENTITY_INVALID",
                detail="committed-invariant identity is malformed",
            )
        if not isinstance(candidate_key, str) or not candidate_key:
            raise LateCommittedInvariantError(
                stage="DERIVATION",
                code="CANDIDATE_IDENTITY_INVALID",
                detail="late committed-invariant candidate key is malformed",
            )
        core = {
            "schema": LATE_CI_AUTHORITY_SCHEMA,
            "authority": LATE_CI_AUTHORITY,
            "status": LATE_CI_STATUS,
            "source_artifact": source,
            "source_artifact_sha256": source_digest,
            "committed_invariant_id": committed_invariant_id,
            "committed_invariant_sha256": ci_digest,
            "candidate_key": candidate_key,
        }
        return cls(
            source_artifact=source,
            source_artifact_sha256=source_digest,
            committed_invariant_id=committed_invariant_id,
            committed_invariant_sha256=ci_digest,
            candidate_key=candidate_key,
            authority_sha256=_sha256(core),
        )

    @classmethod
    def replay(
        cls,
        value: Mapping[str, Any],
    ) -> "LateCommittedInvariantAuthority":
        fields = {
            "schema",
            "authority",
            "status",
            "source_artifact",
            "source_artifact_sha256",
            "committed_invariant_id",
            "committed_invariant_sha256",
            "candidate_key",
            "authority_sha256",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise LateCommittedInvariantError(
                stage="PERSISTENCE",
                code="AUTHORITY_SCHEMA_INVALID",
                detail="late committed-invariant authority fields differ",
            )
        if (
            value.get("schema") != LATE_CI_AUTHORITY_SCHEMA
            or value.get("authority") != LATE_CI_AUTHORITY
            or value.get("status") != LATE_CI_STATUS
        ):
            raise LateCommittedInvariantError(
                stage="PERSISTENCE",
                code="CURRENT_RUN_AUTHORITY_FORBIDDEN",
                detail="late committed-invariant authority/status differs",
            )
        result = cls.create(
            source_artifact=value.get("source_artifact"),
            source_artifact_sha256=value.get("source_artifact_sha256"),
            committed_invariant_id=value.get("committed_invariant_id"),
            committed_invariant_sha256=value.get(
                "committed_invariant_sha256"
            ),
            candidate_key=value.get("candidate_key"),
        )
        if value.get("authority_sha256") != result.authority_sha256:
            raise LateCommittedInvariantError(
                stage="PERSISTENCE",
                code="AUTHORITY_DIGEST_INVALID",
                detail="late committed-invariant authority digest differs",
            )
        return result

    def to_dict(self) -> dict[str, str]:
        return {
            "schema": self.schema,
            "authority": self.authority,
            "status": self.status,
            "source_artifact": self.source_artifact,
            "source_artifact_sha256": self.source_artifact_sha256,
            "committed_invariant_id": self.committed_invariant_id,
            "committed_invariant_sha256": self.committed_invariant_sha256,
            "candidate_key": self.candidate_key,
            "authority_sha256": self.authority_sha256,
        }


class LateCommittedInvariantRecoveryResult(int):
    """Int-compatible success result with typed late-CI authority records."""

    def __new__(
        cls,
        emitted: int,
        *,
        authorities: Sequence[LateCommittedInvariantAuthority],
        ledger_path: Path,
    ) -> "LateCommittedInvariantRecoveryResult":
        if not isinstance(emitted, int) or isinstance(emitted, bool) or emitted < 0:
            raise ValueError("emitted must be a non-negative integer")
        result = int.__new__(cls, emitted)
        result.emitted = emitted
        result.authorities = tuple(authorities)
        result.ledger_path = Path(ledger_path)
        return result


def _ledger_payload(
    authorities: Sequence[LateCommittedInvariantAuthority],
) -> dict[str, Any]:
    rows = [authority.to_dict() for authority in authorities]
    rows.sort(
        key=lambda row: (
            row["source_artifact"],
            row["committed_invariant_id"],
            row["committed_invariant_sha256"],
        )
    )
    identities = [
        (
            row["source_artifact"],
            row["committed_invariant_id"],
            row["committed_invariant_sha256"],
        )
        for row in rows
    ]
    if len(identities) != len(set(identities)):
        raise LateCommittedInvariantError(
            stage="PERSISTENCE",
            code="DUPLICATE_AUTHORITY",
            detail="late committed-invariant authority identities collide",
        )
    core = {
        "schema": LATE_CI_LEDGER_SCHEMA,
        "authority": LATE_CI_AUTHORITY,
        "status": LATE_CI_STATUS,
        "records": rows,
    }
    return {**core, "ledger_sha256": _sha256(core)}


def persist_late_committed_invariant_authorities(
    scratchpad: Path,
    authorities: Sequence[LateCommittedInvariantAuthority],
) -> Path:
    """Atomically persist and fresh-replay the complete late-CI ledger."""

    root = Path(scratchpad).resolve(strict=True)
    if not root.is_dir():
        raise LateCommittedInvariantError(
            stage="PERSISTENCE",
            code="SCRATCHPAD_INVALID",
            detail="late committed-invariant scratchpad is not a directory",
        )
    payload = _ledger_payload(authorities)
    raw = _canonical_json(payload) + b"\n"
    target = root / LATE_CI_LEDGER_NAME
    temporary = target.with_name(
        f".{target.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    )
    try:
        with temporary.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        observed = target.read_bytes()
        if observed != raw:
            raise LateCommittedInvariantError(
                stage="PERSISTENCE",
                code="LEDGER_REPLAY_FAILED",
                detail="late committed-invariant ledger bytes differ",
            )
        replay_late_committed_invariant_ledger(
            json.loads(observed.decode("utf-8"))
        )
        return target
    except LateCommittedInvariantError:
        raise
    except Exception as exc:
        raise LateCommittedInvariantError(
            stage="PERSISTENCE",
            code="LEDGER_WRITE_FAILED",
            detail=f"late committed-invariant ledger write failed ({type(exc).__name__})",
        ) from exc
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def replay_late_committed_invariant_ledger(
    value: Mapping[str, Any],
) -> tuple[LateCommittedInvariantAuthority, ...]:
    fields = {"schema", "authority", "status", "records", "ledger_sha256"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise LateCommittedInvariantError(
            stage="PERSISTENCE",
            code="LEDGER_SCHEMA_INVALID",
            detail="late committed-invariant ledger fields differ",
        )
    core = dict(value)
    digest = core.pop("ledger_sha256")
    if (
        core.get("schema") != LATE_CI_LEDGER_SCHEMA
        or core.get("authority") != LATE_CI_AUTHORITY
        or core.get("status") != LATE_CI_STATUS
        or not isinstance(core.get("records"), list)
        or not isinstance(digest, str)
        or digest != _sha256(core)
    ):
        raise LateCommittedInvariantError(
            stage="PERSISTENCE",
            code="LEDGER_AUTHORITY_INVALID",
            detail="late committed-invariant ledger authority/digest differs",
        )
    records = tuple(
        LateCommittedInvariantAuthority.replay(row)
        for row in core["records"]
    )
    if _ledger_payload(records) != value:
        raise LateCommittedInvariantError(
            stage="PERSISTENCE",
            code="LEDGER_ORDER_INVALID",
            detail="late committed-invariant ledger ordering differs",
        )
    return records
