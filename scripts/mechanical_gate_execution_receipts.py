"""Typed, content-bound receipts for the mechanical-gate runtime.

The runtime does not infer success from prose or from output presence.  Every
terminal execution is represented by a closed receipt whose count equations,
failure direction, authority effect, and optional PhaseIO checked-commit link
are validated before publication.

The ledger is deliberately an immutable event set rather than a mutable JSON
array.  One execution ID maps to one content-bound receipt file.  Exact resume
is a read-only success; a divergent replay is rejected.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping
import uuid


_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,511}$")
_WORK_UNIT_RE = re.compile(
    r"^[a-z0-9][a-z0-9_.-]*(?:/[a-z0-9][a-z0-9_.-]*){5}$"
)
_ARTIFACT_RE = re.compile(r"^(?:scratchpad|project):[^\\:*?\"<>|]+$")
_REPARSE_ATTRIBUTE = 0x400

RECEIPT_SCHEMA = "plamen.mechanical_gate_execution_receipt.v1"
LEDGER_SCHEMA = "plamen.mechanical_gate_execution_ledger_entry.v1"
MAX_LEDGER_ENTRY_BYTES = 8 * 1024 * 1024

TERMINAL_STATES = frozenset(
    {"COMMITTED", "QUARANTINED", "DEBT", "NOT_APPLICABLE", "SHADOW"}
)
DECISIONS = frozenset({"FIRED", "CLEAR", "UNKNOWN", "NOT_APPLICABLE"})
AUTHORITY_EFFECTS = frozenset(
    {
        "AUTHORITATIVE",
        "ADD_ONLY",
        "RETAIN_UPSTREAM_AND_FLAG",
        "SHADOW_ONLY",
        "NONE",
    }
)
COMMIT_STATES = frozenset({"ACTIVE", "QUARANTINED", "SUPERSEDED"})


class GateReceiptError(ValueError):
    """A receipt, publication, or replay failed closed."""


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise GateReceiptError("receipt is not canonical JSON data") from exc


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise GateReceiptError(f"{label} must be a string")
    normalized = value.strip()
    if not normalized or normalized != value:
        raise GateReceiptError(f"{label} must be canonical non-empty text")
    return normalized


def _identifier(value: object, label: str) -> str:
    normalized = _text(value, label)
    if _ID_RE.fullmatch(normalized) is None:
        raise GateReceiptError(f"{label} is not a canonical identifier")
    return normalized


def _sha(value: object, label: str) -> str:
    normalized = _text(value, label)
    if _SHA_RE.fullmatch(normalized) is None:
        raise GateReceiptError(f"{label} must be lowercase SHA-256")
    return normalized


def _count(value: object, label: str) -> int:
    if type(value) is not int or value < 0 or value > 2**63 - 1:
        raise GateReceiptError(
            f"{label} must be a bounded non-negative integer"
        )
    return value


def _closed_strings(
    values: object,
    label: str,
    *,
    sha256: bool = False,
) -> tuple[str, ...]:
    if not isinstance(values, (tuple, list)):
        raise GateReceiptError(f"{label} must be an array")
    parsed = tuple(
        _sha(item, label) if sha256 else _identifier(item, label)
        for item in values
    )
    if len(parsed) != len(set(parsed)):
        raise GateReceiptError(f"{label} contains duplicates")
    if parsed != tuple(sorted(parsed, key=lambda item: item.encode("utf-8"))):
        raise GateReceiptError(f"{label} must be sorted")
    return parsed


@dataclass(frozen=True, slots=True)
class GateCountReceipt:
    """Exact denominator and outcome accounting for one gate execution."""

    raw_subjects: int
    unique_subjects: int
    eligible_subjects: int
    evaluated_subjects: int
    fired_subjects: int
    clear_subjects: int
    unknown_subjects: int
    overflow_subjects: int
    emitted_candidates: int
    denominator_kind: str = "EXACT"

    def __post_init__(self) -> None:
        for field_name in self.__dataclass_fields__:
            if field_name == "denominator_kind":
                continue
            _count(getattr(self, field_name), field_name)
        kind = _text(self.denominator_kind, "denominator_kind").upper()
        if kind not in {"EXACT", "LOWER_BOUND"}:
            raise GateReceiptError("denominator_kind is invalid")
        object.__setattr__(self, "denominator_kind", kind)
        if self.unique_subjects > self.raw_subjects:
            raise GateReceiptError("unique_subjects exceeds raw_subjects")
        if self.eligible_subjects > self.unique_subjects:
            raise GateReceiptError("eligible_subjects exceeds unique_subjects")
        if (
            self.evaluated_subjects + self.overflow_subjects
            != self.eligible_subjects
        ):
            raise GateReceiptError(
                "eligible_subjects must equal evaluated plus overflow"
            )
        if (
            self.fired_subjects
            + self.clear_subjects
            + self.unknown_subjects
            != self.evaluated_subjects
        ):
            raise GateReceiptError(
                "evaluated_subjects must equal fired plus clear plus unknown"
            )
        if self.emitted_candidates > self.fired_subjects:
            raise GateReceiptError(
                "emitted_candidates exceeds fired_subjects"
            )

    @classmethod
    def all_unknown(cls, denominator: int) -> "GateCountReceipt":
        count = _count(denominator, "denominator")
        return cls(
            raw_subjects=count,
            unique_subjects=count,
            eligible_subjects=count,
            evaluated_subjects=count,
            fired_subjects=0,
            clear_subjects=0,
            unknown_subjects=count,
            overflow_subjects=0,
            emitted_candidates=0,
            denominator_kind="EXACT",
        )

    @classmethod
    def empty(cls) -> "GateCountReceipt":
        return cls(
            raw_subjects=0,
            unique_subjects=0,
            eligible_subjects=0,
            evaluated_subjects=0,
            fired_subjects=0,
            clear_subjects=0,
            unknown_subjects=0,
            overflow_subjects=0,
            emitted_candidates=0,
            denominator_kind="EXACT",
        )

    def to_dict(self) -> dict[str, int | str]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "GateCountReceipt":
        if not isinstance(value, Mapping):
            raise GateReceiptError("counts must be an object")
        expected = frozenset(cls.__dataclass_fields__)
        if frozenset(value) != expected:
            raise GateReceiptError("counts have a non-closed shape")
        return cls(**{key: value[key] for key in expected})


@dataclass(frozen=True, slots=True)
class GateArtifactEvidence:
    """Exact artifact identity, schema, size, and byte digest."""

    artifact_identity: str
    schema_version: str
    sha256: str
    size: int

    def __post_init__(self) -> None:
        identity = _text(self.artifact_identity, "artifact_identity")
        if _ARTIFACT_RE.fullmatch(identity) is None:
            raise GateReceiptError("artifact_identity is not canonical")
        object.__setattr__(self, "artifact_identity", identity)
        schema = _identifier(self.schema_version, "schema_version")
        object.__setattr__(self, "schema_version", schema)
        object.__setattr__(self, "sha256", _sha(self.sha256, "sha256"))
        _count(self.size, "size")

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_identity": self.artifact_identity,
            "schema_version": self.schema_version,
            "sha256": self.sha256,
            "size": self.size,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "GateArtifactEvidence":
        if not isinstance(value, Mapping) or frozenset(value) != {
            "artifact_identity",
            "schema_version",
            "sha256",
            "size",
        }:
            raise GateReceiptError("artifact evidence has a non-closed shape")
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class GateCostReceipt:
    """Integer-only resource observation; registry maxima remain authority."""

    wall_clock_ms: int = 0
    external_processes: int = 0
    workers: int = 0
    tokens: int = 0

    def __post_init__(self) -> None:
        for field_name in self.__dataclass_fields__:
            _count(getattr(self, field_name), field_name)

    def to_dict(self) -> dict[str, int]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "GateCostReceipt":
        if not isinstance(value, Mapping) or frozenset(value) != frozenset(
            cls.__dataclass_fields__
        ):
            raise GateReceiptError("cost receipt has a non-closed shape")
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class GateDebtRow:
    """Typed failure direction; evidence never collapses into prose CLEAR."""

    code: str
    condition: str
    action: str
    evidence_digest: str | None = None

    def __post_init__(self) -> None:
        for field_name in ("code", "condition", "action"):
            object.__setattr__(
                self,
                field_name,
                _identifier(getattr(self, field_name), field_name),
            )
        if self.evidence_digest is not None:
            object.__setattr__(
                self,
                "evidence_digest",
                _sha(self.evidence_digest, "evidence_digest"),
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "condition": self.condition,
            "action": self.action,
            "evidence_digest": self.evidence_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "GateDebtRow":
        if not isinstance(value, Mapping) or frozenset(value) != {
            "code",
            "condition",
            "action",
            "evidence_digest",
        }:
            raise GateReceiptError("debt row has a non-closed shape")
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class PhaseIOCommitLink:
    """Digest-only linkage to an existing PhaseIO checked-commit receipt."""

    work_unit_key: str
    contract_digest: str
    launch_digest: str
    input_set_digest: str
    output_identities: tuple[str, ...]
    commit_state: str
    commit_receipt_digest: str
    reason_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        key = _text(self.work_unit_key, "work_unit_key")
        if _WORK_UNIT_RE.fullmatch(key) is None:
            raise GateReceiptError("work_unit_key is not canonical")
        object.__setattr__(self, "work_unit_key", key)
        for field_name in (
            "contract_digest",
            "launch_digest",
            "input_set_digest",
            "commit_receipt_digest",
        ):
            object.__setattr__(
                self,
                field_name,
                _sha(getattr(self, field_name), field_name),
            )
        if not isinstance(self.output_identities, (tuple, list)):
            raise GateReceiptError("output_identities must be an array")
        identities = tuple(
            _text(item, "output identity") for item in self.output_identities
        )
        if any(_ARTIFACT_RE.fullmatch(item) is None for item in identities):
            raise GateReceiptError("output identity is not canonical")
        if identities != tuple(
            sorted(set(identities), key=lambda item: item.encode("utf-8"))
        ):
            raise GateReceiptError("output_identities must be sorted and unique")
        object.__setattr__(self, "output_identities", identities)
        state = _text(self.commit_state, "commit_state").upper()
        if state not in COMMIT_STATES:
            raise GateReceiptError("commit_state is invalid")
        object.__setattr__(self, "commit_state", state)
        reasons = _closed_strings(self.reason_codes, "reason_codes")
        if state == "ACTIVE" and reasons:
            raise GateReceiptError(
                "ACTIVE PhaseIO commit cannot carry reason codes"
            )
        if state == "QUARANTINED" and not reasons:
            raise GateReceiptError(
                "QUARANTINED PhaseIO commit requires reason codes"
            )
        object.__setattr__(self, "reason_codes", reasons)

    @property
    def digest(self) -> str:
        return _digest(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {
            "work_unit_key": self.work_unit_key,
            "contract_digest": self.contract_digest,
            "launch_digest": self.launch_digest,
            "input_set_digest": self.input_set_digest,
            "output_identities": list(self.output_identities),
            "commit_state": self.commit_state,
            "commit_receipt_digest": self.commit_receipt_digest,
            "reason_codes": list(self.reason_codes),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PhaseIOCommitLink":
        if not isinstance(value, Mapping):
            raise GateReceiptError("phase_io must be an object")
        expected = frozenset(cls.__dataclass_fields__)
        if frozenset(value) != expected:
            raise GateReceiptError("phase_io has a non-closed shape")
        return cls(
            work_unit_key=value["work_unit_key"],
            contract_digest=value["contract_digest"],
            launch_digest=value["launch_digest"],
            input_set_digest=value["input_set_digest"],
            output_identities=tuple(value["output_identities"]),
            commit_state=value["commit_state"],
            commit_receipt_digest=value["commit_receipt_digest"],
            reason_codes=tuple(value["reason_codes"]),
        )


@dataclass(frozen=True, slots=True)
class GateExecutionReceipt:
    execution_id: str
    run_id: str
    gate_id: str
    activation_id: str
    registry_digest: str
    inventory_digest: str
    source_tree_digest: str
    pipeline: str
    mode: str
    ecosystem: str
    backend: str
    phase: str
    state: str
    decision: str
    authority_effect: str
    counts: GateCountReceipt
    input_evidence_digests: tuple[str, ...]
    output_evidence_digests: tuple[str, ...]
    debt_codes: tuple[str, ...]
    phase_io: PhaseIOCommitLink | None = None
    registry_schema_version: str = (
        "plamen.mechanical_gate_registry.v2"
    )
    registry_revision: int = 1
    input_artifacts: tuple[GateArtifactEvidence, ...] = ()
    output_artifacts: tuple[GateArtifactEvidence, ...] = ()
    cost: GateCostReceipt = field(default_factory=GateCostReceipt)
    debt_rows: tuple[GateDebtRow, ...] = ()
    expires_at: str | None = None
    schema_version: str = RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != RECEIPT_SCHEMA:
            raise GateReceiptError("receipt schema is invalid")
        for field_name in (
            "execution_id",
            "run_id",
            "gate_id",
            "activation_id",
        ):
            object.__setattr__(
                self,
                field_name,
                _identifier(getattr(self, field_name), field_name),
            )
        if not self.activation_id.startswith(self.gate_id + "."):
            raise GateReceiptError("activation is outside the gate namespace")
        for field_name in (
            "registry_digest",
            "inventory_digest",
            "source_tree_digest",
        ):
            object.__setattr__(
                self,
                field_name,
                _sha(getattr(self, field_name), field_name),
            )
        for field_name in (
            "pipeline",
            "mode",
            "ecosystem",
            "backend",
            "phase",
        ):
            value = _text(getattr(self, field_name), field_name).upper()
            object.__setattr__(self, field_name, value)
        object.__setattr__(
            self,
            "registry_schema_version",
            _identifier(
                self.registry_schema_version,
                "registry_schema_version",
            ),
        )
        if (
            type(self.registry_revision) is not int
            or self.registry_revision < 1
        ):
            raise GateReceiptError(
                "registry_revision must be a positive integer"
            )
        state = _text(self.state, "state").upper()
        decision = _text(self.decision, "decision").upper()
        effect = _text(self.authority_effect, "authority_effect").upper()
        if state not in TERMINAL_STATES:
            raise GateReceiptError("receipt state is invalid")
        if decision not in DECISIONS:
            raise GateReceiptError("receipt decision is invalid")
        if effect not in AUTHORITY_EFFECTS:
            raise GateReceiptError("authority_effect is invalid")
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "decision", decision)
        object.__setattr__(self, "authority_effect", effect)
        if not isinstance(self.counts, GateCountReceipt):
            raise GateReceiptError("counts must be GateCountReceipt")
        inputs = _closed_strings(
            self.input_evidence_digests,
            "input_evidence_digests",
            sha256=True,
        )
        outputs = _closed_strings(
            self.output_evidence_digests,
            "output_evidence_digests",
            sha256=True,
        )
        debts = _closed_strings(self.debt_codes, "debt_codes")
        object.__setattr__(self, "input_evidence_digests", inputs)
        object.__setattr__(self, "output_evidence_digests", outputs)
        object.__setattr__(self, "debt_codes", debts)
        input_artifacts = self._artifacts(
            self.input_artifacts, "input_artifacts"
        )
        output_artifacts = self._artifacts(
            self.output_artifacts, "output_artifacts"
        )
        object.__setattr__(self, "input_artifacts", input_artifacts)
        object.__setattr__(self, "output_artifacts", output_artifacts)
        if input_artifacts and {
            item.sha256 for item in input_artifacts
        } != set(inputs):
            raise GateReceiptError(
                "input artifact and digest denominators differ"
            )
        if output_artifacts and {
            item.sha256 for item in output_artifacts
        } != set(outputs):
            raise GateReceiptError(
                "output artifact and digest denominators differ"
            )
        if not isinstance(self.cost, GateCostReceipt):
            raise GateReceiptError("cost has the wrong type")
        if not isinstance(self.debt_rows, (tuple, list)):
            raise GateReceiptError("debt_rows must be an array")
        rows = tuple(self.debt_rows)
        if any(not isinstance(row, GateDebtRow) for row in rows):
            raise GateReceiptError("debt_rows contain the wrong type")
        if tuple(row.code for row in rows) != tuple(
            sorted(
                {row.code for row in rows},
                key=lambda item: item.encode("utf-8"),
            )
        ):
            raise GateReceiptError(
                "debt rows must be code-sorted and unique"
            )
        if {row.code for row in rows} != set(debts):
            raise GateReceiptError(
                "debt rows and debt codes differ"
            )
        object.__setattr__(self, "debt_rows", rows)
        if self.expires_at is not None:
            expiry = _text(self.expires_at, "expires_at")
            if not expiry.endswith("Z"):
                raise GateReceiptError(
                    "expires_at must be a canonical UTC instant"
                )
            object.__setattr__(self, "expires_at", expiry)

        if decision == "CLEAR":
            if (
                self.counts.fired_subjects
                or self.counts.unknown_subjects
                or self.counts.overflow_subjects
                or debts
                or state != "COMMITTED"
            ):
                raise GateReceiptError(
                    "CLEAR requires complete, debt-free committed evidence"
                )
            if self.counts.denominator_kind != "EXACT":
                raise GateReceiptError(
                    "lower-bound denominator can never CLEAR"
                )
        if self.counts.unknown_subjects and not debts:
            raise GateReceiptError("unknown subjects require typed debt")
        if self.counts.overflow_subjects and "BUDGET_OVERFLOW" not in debts:
            raise GateReceiptError(
                "overflow subjects require BUDGET_OVERFLOW debt"
            )
        if (
            self.counts.denominator_kind == "LOWER_BOUND"
            and "UNKNOWN_REMAINDER" not in debts
        ):
            raise GateReceiptError(
                "lower-bound denominator requires UNKNOWN_REMAINDER debt"
            )
        if state in {"DEBT", "QUARANTINED", "SHADOW"} and not debts:
            raise GateReceiptError(f"{state} requires typed debt")
        if state == "NOT_APPLICABLE":
            if decision != "NOT_APPLICABLE" or effect != "NONE":
                raise GateReceiptError(
                    "NOT_APPLICABLE state has inconsistent authority"
                )
        elif decision == "NOT_APPLICABLE":
            raise GateReceiptError(
                "NOT_APPLICABLE decision requires matching state"
            )
        if effect == "AUTHORITATIVE":
            if (
                state != "COMMITTED"
                or self.phase_io is None
                or self.phase_io.commit_state != "ACTIVE"
            ):
                raise GateReceiptError(
                    "authoritative effect requires an ACTIVE PhaseIO commit"
                )
        if (
            effect == "RETAIN_UPSTREAM_AND_FLAG"
            and decision not in {"UNKNOWN", "FIRED"}
        ):
            raise GateReceiptError(
                "recall-open effect cannot assert CLEAR"
            )
        if self.phase_io is not None:
            if not isinstance(self.phase_io, PhaseIOCommitLink):
                raise GateReceiptError("phase_io has the wrong type")
            if (
                self.phase_io.commit_state == "QUARANTINED"
                and state != "QUARANTINED"
            ):
                raise GateReceiptError(
                    "quarantined PhaseIO link requires quarantined receipt"
                )

    @staticmethod
    def _artifacts(
        values: object,
        label: str,
    ) -> tuple[GateArtifactEvidence, ...]:
        if not isinstance(values, (tuple, list)):
            raise GateReceiptError(f"{label} must be an array")
        parsed = tuple(values)
        if any(not isinstance(item, GateArtifactEvidence) for item in parsed):
            raise GateReceiptError(f"{label} contains the wrong type")
        identities = tuple(item.artifact_identity for item in parsed)
        if identities != tuple(
            sorted(set(identities), key=lambda item: item.encode("utf-8"))
        ):
            raise GateReceiptError(
                f"{label} must be identity-sorted and unique"
            )
        return parsed

    @property
    def digest(self) -> str:
        return _digest(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "execution_id": self.execution_id,
            "run_id": self.run_id,
            "gate_id": self.gate_id,
            "activation_id": self.activation_id,
            "registry_digest": self.registry_digest,
            "registry_schema_version": self.registry_schema_version,
            "registry_revision": self.registry_revision,
            "inventory_digest": self.inventory_digest,
            "source_tree_digest": self.source_tree_digest,
            "pipeline": self.pipeline,
            "mode": self.mode,
            "ecosystem": self.ecosystem,
            "backend": self.backend,
            "phase": self.phase,
            "state": self.state,
            "decision": self.decision,
            "authority_effect": self.authority_effect,
            "counts": self.counts.to_dict(),
            "input_evidence_digests": list(self.input_evidence_digests),
            "output_evidence_digests": list(self.output_evidence_digests),
            "input_artifacts": [
                item.to_dict() for item in self.input_artifacts
            ],
            "output_artifacts": [
                item.to_dict() for item in self.output_artifacts
            ],
            "cost": self.cost.to_dict(),
            "debt_codes": list(self.debt_codes),
            "debt_rows": [row.to_dict() for row in self.debt_rows],
            "expires_at": self.expires_at,
            "phase_io": self.phase_io.to_dict() if self.phase_io else None,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "GateExecutionReceipt":
        if not isinstance(value, Mapping):
            raise GateReceiptError("receipt must be an object")
        expected = frozenset(cls.__dataclass_fields__)
        if frozenset(value) != expected:
            raise GateReceiptError("receipt has a non-closed shape")
        phase_io_raw = value["phase_io"]
        return cls(
            execution_id=value["execution_id"],
            run_id=value["run_id"],
            gate_id=value["gate_id"],
            activation_id=value["activation_id"],
            registry_digest=value["registry_digest"],
            registry_schema_version=value["registry_schema_version"],
            registry_revision=value["registry_revision"],
            inventory_digest=value["inventory_digest"],
            source_tree_digest=value["source_tree_digest"],
            pipeline=value["pipeline"],
            mode=value["mode"],
            ecosystem=value["ecosystem"],
            backend=value["backend"],
            phase=value["phase"],
            state=value["state"],
            decision=value["decision"],
            authority_effect=value["authority_effect"],
            counts=GateCountReceipt.from_dict(value["counts"]),
            input_evidence_digests=tuple(value["input_evidence_digests"]),
            output_evidence_digests=tuple(value["output_evidence_digests"]),
            input_artifacts=tuple(
                GateArtifactEvidence.from_dict(item)
                for item in value["input_artifacts"]
            ),
            output_artifacts=tuple(
                GateArtifactEvidence.from_dict(item)
                for item in value["output_artifacts"]
            ),
            cost=GateCostReceipt.from_dict(value["cost"]),
            debt_codes=tuple(value["debt_codes"]),
            debt_rows=tuple(
                GateDebtRow.from_dict(item) for item in value["debt_rows"]
            ),
            expires_at=value["expires_at"],
            phase_io=(
                None
                if phase_io_raw is None
                else PhaseIOCommitLink.from_dict(phase_io_raw)
            ),
            schema_version=value["schema_version"],
        )


@dataclass(frozen=True, slots=True)
class LedgerPublication:
    state: str
    execution_id: str
    receipt_digest: str
    path: Path


class ImmutableGateExecutionLedger:
    """Create-only execution receipt store with exact replay semantics."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)

    def _ensure_root(self) -> Path:
        absolute = Path(os.path.abspath(self.root))
        cursor = Path(absolute.anchor)
        for component in absolute.parts[1:]:
            candidate = cursor / component
            try:
                component_row = candidate.lstat()
            except FileNotFoundError:
                try:
                    candidate.mkdir()
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise GateReceiptError(
                        "ledger path component cannot be created"
                    ) from exc
                try:
                    component_row = candidate.lstat()
                except OSError as exc:
                    raise GateReceiptError(
                        "created ledger component cannot be inspected"
                    ) from exc
            except OSError as exc:
                raise GateReceiptError(
                    "ledger path component cannot be inspected"
                ) from exc
            if (
                not stat.S_ISDIR(component_row.st_mode)
                or stat.S_ISLNK(component_row.st_mode)
                or bool(
                getattr(component_row, "st_file_attributes", 0)
                & _REPARSE_ATTRIBUTE
                )
            ):
                raise GateReceiptError(
                    "ledger path component is not a plain directory"
                )
            cursor = candidate
        try:
            row = absolute.lstat()
        except OSError as exc:
            raise GateReceiptError("ledger root cannot be inspected") from exc
        if (
            not stat.S_ISDIR(row.st_mode)
            or stat.S_ISLNK(row.st_mode)
            or bool(
                getattr(row, "st_file_attributes", 0)
                & _REPARSE_ATTRIBUTE
            )
        ):
            raise GateReceiptError("ledger root is not a plain directory")
        return absolute.resolve(strict=True)

    def _path(self, execution_id: str) -> Path:
        identifier = _identifier(execution_id, "execution_id")
        key = hashlib.sha256(identifier.encode("utf-8")).hexdigest()
        return self._ensure_root() / f"{key}.json"

    @staticmethod
    def _envelope(receipt: GateExecutionReceipt) -> dict[str, object]:
        if not isinstance(receipt, GateExecutionReceipt):
            raise GateReceiptError("ledger accepts GateExecutionReceipt only")
        return {
            "schema_version": LEDGER_SCHEMA,
            "execution_id": receipt.execution_id,
            "receipt_digest": receipt.digest,
            "receipt": receipt.to_dict(),
        }

    def publish(self, receipt: GateExecutionReceipt) -> LedgerPublication:
        envelope = self._envelope(receipt)
        raw = _canonical_bytes(envelope) + b"\n"
        if len(raw) > MAX_LEDGER_ENTRY_BYTES:
            raise GateReceiptError("execution receipt exceeds 8 MiB")
        path = self._path(receipt.execution_id)
        temporary = path.parent / (
            f".{receipt.digest}.{uuid.uuid4().hex}.tmp"
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        try:
            descriptor = os.open(temporary, flags, 0o600)
        except OSError as exc:
            raise GateReceiptError("execution receipt publication failed") from exc
        try:
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise GateReceiptError(
                        "execution receipt publication was incomplete"
                    )
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            try:
                os.link(temporary, path)
            except FileExistsError:
                existing = self._read_raw(path)
                if existing != raw:
                    raise GateReceiptError(
                        "divergent replay for immutable execution ID"
                    )
                self.read(receipt.execution_id)
                return LedgerPublication(
                    "EXACT_REPLAY",
                    receipt.execution_id,
                    receipt.digest,
                    path,
                )
            except OSError as exc:
                raise GateReceiptError(
                    "execution receipt atomic publication failed"
                ) from exc
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise GateReceiptError(
                    "execution receipt temporary cleanup failed"
                ) from exc
        try:
            path.chmod(0o444)
        except OSError as exc:
            raise GateReceiptError(
                "execution receipt cannot be made read-only"
            ) from exc
        return LedgerPublication(
            "CREATED", receipt.execution_id, receipt.digest, path
        )

    @staticmethod
    def _read_raw(path: Path) -> bytes:
        try:
            before = path.lstat()
        except OSError as exc:
            raise GateReceiptError("execution receipt is unavailable") from exc
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
            raise GateReceiptError("execution receipt is not a plain file")
        if before.st_size > MAX_LEDGER_ENTRY_BYTES:
            raise GateReceiptError("execution receipt exceeds 8 MiB")
        try:
            raw = path.read_bytes()
            after = path.lstat()
        except OSError as exc:
            raise GateReceiptError("execution receipt cannot be read") from exc
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise GateReceiptError("execution receipt mutated while read")
        return raw

    def read(self, execution_id: str) -> GateExecutionReceipt:
        path = self._path(execution_id)
        raw = self._read_raw(path)
        try:
            value = json.loads(
                raw.decode("utf-8", errors="strict"),
                parse_float=lambda _value: (_ for _ in ()).throw(
                    GateReceiptError("floats are forbidden")
                ),
                parse_constant=lambda _value: (_ for _ in ()).throw(
                    GateReceiptError("non-finite numbers are forbidden")
                ),
                object_pairs_hook=_reject_duplicate_pairs,
            )
        except GateReceiptError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GateReceiptError("execution receipt JSON is malformed") from exc
        if not isinstance(value, Mapping) or frozenset(value) != {
            "schema_version",
            "execution_id",
            "receipt_digest",
            "receipt",
        }:
            raise GateReceiptError("ledger envelope has a non-closed shape")
        if value["schema_version"] != LEDGER_SCHEMA:
            raise GateReceiptError("ledger envelope schema is invalid")
        receipt = GateExecutionReceipt.from_dict(value["receipt"])
        if (
            value["execution_id"] != receipt.execution_id
            or receipt.execution_id != _identifier(execution_id, "execution_id")
            or value["receipt_digest"] != receipt.digest
        ):
            raise GateReceiptError("ledger envelope binding is invalid")
        if raw != _canonical_bytes(value) + b"\n":
            raise GateReceiptError("ledger envelope is not canonical")
        return receipt

    def read_if_present(
        self,
        execution_id: str,
    ) -> GateExecutionReceipt | None:
        path = self._path(execution_id)
        if not path.exists():
            return None
        return self.read(execution_id)


def _reject_duplicate_pairs(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GateReceiptError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


__all__ = [
    "AUTHORITY_EFFECTS",
    "COMMIT_STATES",
    "DECISIONS",
    "GateArtifactEvidence",
    "GateCostReceipt",
    "GateCountReceipt",
    "GateDebtRow",
    "GateExecutionReceipt",
    "GateReceiptError",
    "ImmutableGateExecutionLedger",
    "LEDGER_SCHEMA",
    "MAX_LEDGER_ENTRY_BYTES",
    "LedgerPublication",
    "PhaseIOCommitLink",
    "RECEIPT_SCHEMA",
    "TERMINAL_STATES",
]
