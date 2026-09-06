"""Runtime authority boundary for registered mechanical gates.

This module is intentionally unusable as an ambient global switch.  A caller
must supply a digest-bound :class:`GateRuntimeAuthority`, one exact literal
gate/activation pair, a typed invocation, an exact applicability selector, and
the declared evaluator callable.  Caller module, wrapper, evaluator, decision
closure, registry, inventory, and source-tree identities are all checked before
the evaluator can run.

The currently valid registry schema is migration-only.  Consequently,
``LEGACY_ACTIVE_UNGOVERNED`` executions are observable shadow/debt receipts,
not proof that the 33 forensic candidates have completed baseline review.
Unknown activations and dynamic/reflected call sites likewise remain
non-runtime.  Invalid destructive authority is always recall-open.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import inspect
import json
import os
from pathlib import Path
import stat
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol, runtime_checkable

from mechanical_gate_execution_receipts import (
    GateArtifactEvidence,
    GateCostReceipt,
    GateCountReceipt,
    GateDebtRow,
    GateExecutionReceipt,
    GateReceiptError,
    ImmutableGateExecutionLedger,
    PhaseIOCommitLink,
)
from mechanical_gate_inventory import (
    ActivationInventoryError,
    activation_inventory_digest,
    compute_decision_code_digest,
    compute_source_tree_digest,
    validate_activation_parity,
)
from mechanical_gate_registry import (
    BACKENDS,
    ECOSYSTEMS,
    MODES,
    PHASES,
    PIPELINES,
    GateActivation,
    GateRecord,
    MechanicalGateRegistry,
    MechanicalGateRegistryError,
    mechanical_gate_registry_digest,
    load_mechanical_gate_registry,
    resolve_gate_record,
    strict_json_loads,
    validate_mechanical_gate_registry,
)


class GateRuntimeError(RuntimeError):
    """The runtime substrate or transaction adapter is invalid."""


# Frozen dataclasses prevent accidental mutation; this process-local issuance
# table additionally prevents public dataclass construction/replace from
# manufacturing runtime capability without crossing ``from_objects``.
_ISSUED_AUTHORITIES: dict[int, "GateRuntimeAuthority"] = {}


@dataclass(frozen=True, slots=True)
class RuntimeApplicability:
    pipeline: str
    mode: str
    ecosystem: str
    backend: str
    phase: str

    def __post_init__(self) -> None:
        dimensions = (
            ("pipeline", PIPELINES),
            ("mode", MODES),
            ("ecosystem", ECOSYSTEMS),
            ("backend", BACKENDS),
            ("phase", PHASES),
        )
        for field_name, allowed in dimensions:
            value = getattr(self, field_name)
            if not isinstance(value, str):
                raise GateRuntimeError(f"{field_name} must be a string")
            normalized = value.strip().upper()
            if normalized not in allowed:
                raise GateRuntimeError(
                    f"{field_name} must be one of {sorted(allowed)}"
                )
            object.__setattr__(self, field_name, normalized)


@dataclass(frozen=True, slots=True)
class GateInvocation:
    """Typed evidence denominator supplied by one registered wrapper."""

    run_id: str
    input_evidence_digests: tuple[str, ...]
    subject_denominator: int
    input_artifacts: tuple[GateArtifactEvidence, ...] = ()

    def __post_init__(self) -> None:
        run_id = str(self.run_id or "").strip()
        if (
            not run_id
            or len(run_id) > 192
            or any(character not in "abcdefghijklmnopqrstuvwxyz"
                   "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
                   for character in run_id)
        ):
            raise GateRuntimeError("run_id is not canonical")
        object.__setattr__(self, "run_id", run_id)
        if (
            type(self.subject_denominator) is not int
            or self.subject_denominator < 0
        ):
            raise GateRuntimeError(
                "subject_denominator must be a non-negative integer"
            )
        if not isinstance(self.input_evidence_digests, (tuple, list)):
            raise GateRuntimeError(
                "input_evidence_digests must be an array"
            )
        digests = tuple(self.input_evidence_digests)
        if any(
            not isinstance(item, str)
            or len(item) != 64
            or any(character not in "0123456789abcdef" for character in item)
            for item in digests
        ):
            raise GateRuntimeError(
                "input evidence must contain lowercase SHA-256 digests"
            )
        if digests != tuple(
            sorted(set(digests), key=lambda item: item.encode("utf-8"))
        ):
            raise GateRuntimeError(
                "input evidence digests must be sorted and unique"
            )
        object.__setattr__(self, "input_evidence_digests", digests)
        if not isinstance(self.input_artifacts, (tuple, list)):
            raise GateRuntimeError("input_artifacts must be an array")
        artifacts = tuple(self.input_artifacts)
        if any(
            not isinstance(item, GateArtifactEvidence)
            for item in artifacts
        ):
            raise GateRuntimeError(
                "input_artifacts contain the wrong type"
            )
        identities = tuple(item.artifact_identity for item in artifacts)
        if identities != tuple(
            sorted(set(identities), key=lambda item: item.encode("utf-8"))
        ):
            raise GateRuntimeError(
                "input_artifacts must be identity-sorted and unique"
            )
        if artifacts and {item.sha256 for item in artifacts} != set(digests):
            raise GateRuntimeError(
                "input artifact and digest denominators differ"
            )
        object.__setattr__(self, "input_artifacts", artifacts)


@dataclass(frozen=True, slots=True)
class GateEvaluation:
    """Only accepted evaluator return type; booleans and prose are rejected."""

    decision: str
    counts: GateCountReceipt
    output_evidence_digests: tuple[str, ...] = ()
    debt_codes: tuple[str, ...] = ()
    output_artifacts: tuple[GateArtifactEvidence, ...] = ()
    cost: GateCostReceipt = field(default_factory=GateCostReceipt)

    def __post_init__(self) -> None:
        decision = str(self.decision or "").strip().upper()
        if decision not in {"FIRED", "CLEAR", "UNKNOWN"}:
            raise GateRuntimeError("evaluation decision is invalid")
        object.__setattr__(self, "decision", decision)
        if not isinstance(self.counts, GateCountReceipt):
            raise GateRuntimeError("evaluation counts have the wrong type")
        for field_name, digest_mode in (
            ("output_evidence_digests", True),
            ("debt_codes", False),
        ):
            values = getattr(self, field_name)
            if not isinstance(values, (tuple, list)):
                raise GateRuntimeError(f"{field_name} must be an array")
            normalized = tuple(values)
            if digest_mode:
                if any(
                    not isinstance(item, str)
                    or len(item) != 64
                    or any(
                        character not in "0123456789abcdef"
                        for character in item
                    )
                    for item in normalized
                ):
                    raise GateRuntimeError(
                        "output evidence contains an invalid digest"
                    )
            elif any(
                not isinstance(item, str)
                or not item
                or len(item) > 192
                or any(
                    character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
                    for character in item
                )
                for item in normalized
            ):
                raise GateRuntimeError("evaluation debt code is invalid")
            if normalized != tuple(
                sorted(
                    set(normalized),
                    key=lambda item: item.encode("utf-8"),
                )
            ):
                raise GateRuntimeError(
                    f"{field_name} must be sorted and unique"
                )
            object.__setattr__(self, field_name, normalized)
        if not isinstance(self.output_artifacts, (tuple, list)):
            raise GateRuntimeError("output_artifacts must be an array")
        artifacts = tuple(self.output_artifacts)
        if any(
            not isinstance(item, GateArtifactEvidence)
            for item in artifacts
        ):
            raise GateRuntimeError(
                "output_artifacts contain the wrong type"
            )
        identities = tuple(item.artifact_identity for item in artifacts)
        if identities != tuple(
            sorted(set(identities), key=lambda item: item.encode("utf-8"))
        ):
            raise GateRuntimeError(
                "output_artifacts must be identity-sorted and unique"
            )
        if artifacts and {
            item.sha256 for item in artifacts
        } != set(self.output_evidence_digests):
            raise GateRuntimeError(
                "output artifact and digest denominators differ"
            )
        object.__setattr__(self, "output_artifacts", artifacts)
        if not isinstance(self.cost, GateCostReceipt):
            raise GateRuntimeError("evaluation cost has the wrong type")
        if self.decision == "CLEAR" and (
            self.counts.fired_subjects
            or self.counts.unknown_subjects
            or self.counts.overflow_subjects
            or self.debt_codes
        ):
            raise GateRuntimeError(
                "CLEAR evaluation has incomplete or contradictory evidence"
            )
        if self.decision == "FIRED" and self.counts.fired_subjects == 0:
            raise GateRuntimeError("FIRED evaluation has no fired subjects")
        if self.counts.unknown_subjects and not self.debt_codes:
            raise GateRuntimeError("unknown subjects require typed debt")
        if (
            self.counts.overflow_subjects
            and "BUDGET_OVERFLOW" not in self.debt_codes
        ):
            raise GateRuntimeError(
                "overflow subjects require BUDGET_OVERFLOW debt"
            )
        if (
            self.counts.denominator_kind == "LOWER_BOUND"
            and "UNKNOWN_REMAINDER" not in self.debt_codes
        ):
            raise GateRuntimeError(
                "lower-bound evaluation requires UNKNOWN_REMAINDER debt"
            )


@dataclass(frozen=True, slots=True)
class GateRuntimeAuthority:
    """Deeply validated registry/inventory/source identity capability."""

    source_root: Path
    registry: MechanicalGateRegistry
    inventory: Mapping[str, Any]
    registry_digest: str
    inventory_digest: str
    source_tree_digest: str

    @classmethod
    def from_paths(
        cls,
        *,
        installed_root: Path | str,
        registry_path: Path | str | None = None,
    ) -> "GateRuntimeAuthority":
        """Load only the canonical in-tree registry and its cited manifest."""

        try:
            root = Path(installed_root).resolve(strict=True)
        except OSError as exc:
            raise GateRuntimeError("installed root is unavailable") from exc
        expected_registry = root / "rules" / "mechanical-gate-registry.json"
        candidate = (
            expected_registry
            if registry_path is None
            else Path(registry_path)
        )
        try:
            if candidate.resolve(strict=True) != expected_registry.resolve(
                strict=True
            ):
                raise GateRuntimeError(
                    "runtime registry path is not canonical"
                )
            registry = load_mechanical_gate_registry(
                candidate,
                installed_root=root,
            )
            manifest_relative = str(
                registry.activation_inventory["manifest_path"]
            )
            manifest = _read_inventory_manifest(
                root,
                root / Path(manifest_relative),
            )
        except (
            OSError,
            ActivationInventoryError,
            MechanicalGateRegistryError,
        ) as exc:
            raise GateRuntimeError(
                "canonical runtime authority cannot be loaded"
            ) from exc
        return cls.from_objects(
            source_root=root,
            registry=registry,
            inventory=manifest,
        )

    @classmethod
    def from_objects(
        cls,
        *,
        source_root: Path | str,
        registry: MechanicalGateRegistry | Mapping[str, Any],
        inventory: Mapping[str, Any],
    ) -> "GateRuntimeAuthority":
        try:
            root = Path(source_root).resolve(strict=True)
            validated = validate_mechanical_gate_registry(registry)
            inventory_digest = activation_inventory_digest(inventory)
            result = validate_activation_parity(
                validated,
                inventory,
                source_root=root,
            )
        except (
            OSError,
            ActivationInventoryError,
            MechanicalGateRegistryError,
        ) as exc:
            raise GateRuntimeError(
                "mechanical gate runtime authority is invalid"
            ) from exc
        if (
            result["inventory_sha256"] != inventory_digest
            or result["source_tree_digest"]
            != validated.migration["source_tree_digest"]
        ):
            raise GateRuntimeError(
                "mechanical gate runtime authority digest drift"
            )
        authority = cls(
            source_root=root,
            registry=validated,
            inventory=_deep_freeze_mapping(inventory),
            registry_digest=mechanical_gate_registry_digest(validated),
            inventory_digest=inventory_digest,
            source_tree_digest=result["source_tree_digest"],
        )
        _ISSUED_AUTHORITIES[id(authority)] = authority
        return authority


def _deep_freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {
                str(key): _deep_freeze(item)
                for key, item in value.items()
            }
        )
    if isinstance(value, list):
        return tuple(_deep_freeze(item) for item in value)
    return value


def _deep_freeze_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    """Detach the authority from caller-owned mutable inventory objects."""

    try:
        raw = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        detached = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise GateRuntimeError("inventory cannot be detached") from exc
    frozen = _deep_freeze(detached)
    if not isinstance(frozen, Mapping):
        raise GateRuntimeError("inventory did not freeze as a mapping")
    return frozen


def _read_inventory_manifest(
    installed_root: Path,
    path: Path,
) -> Mapping[str, Any]:
    """Stable, no-alias read for the registry-cited activation inventory."""

    try:
        root = installed_root.resolve(strict=True)
        lexical = Path(os.path.abspath(path))
        lexical.relative_to(Path(os.path.abspath(root)))
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise GateRuntimeError(
            "activation manifest is outside the installed root"
        ) from exc
    cursor = Path(lexical.anchor)
    for component in lexical.parts[1:]:
        cursor = cursor / component
        try:
            row = cursor.lstat()
        except OSError as exc:
            raise GateRuntimeError(
                "activation manifest path cannot be inspected"
            ) from exc
        if stat.S_ISLNK(row.st_mode) or bool(
            getattr(row, "st_file_attributes", 0) & 0x400
        ):
            raise GateRuntimeError(
                "activation manifest path contains an alias"
            )
    try:
        before = resolved.stat(follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 8 * 1024 * 1024:
            raise GateRuntimeError(
                "activation manifest is not a bounded regular file"
            )
        raw = resolved.read_bytes()
        after = resolved.stat(follow_symlinks=False)
    except OSError as exc:
        raise GateRuntimeError(
            "activation manifest cannot be read"
        ) from exc
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise GateRuntimeError(
            "activation manifest mutated while read"
        )
    value = strict_json_loads(raw)
    if not isinstance(value, Mapping):
        raise GateRuntimeError(
            "activation manifest root must be an object"
        )
    return value


@runtime_checkable
class PhaseIOGateTransaction(Protocol):
    """Adapter to existing PhaseIO arm/revalidate/checked-commit APIs."""

    def arm(
        self,
        *,
        gate: GateRecord,
        activation: GateActivation,
        invocation: GateInvocation,
        applicability: RuntimeApplicability,
    ) -> None: ...

    def stage(self, evaluation: GateEvaluation) -> None: ...

    def revalidate(self) -> tuple[str, ...]: ...

    def checked_commit(self) -> PhaseIOCommitLink: ...

    def quarantine(self, reason_codes: tuple[str, ...]) -> PhaseIOCommitLink: ...


class GateTransactionStateMachine:
    """Strict ARM→EVALUATE→STAGE→REVALIDATE→COMMIT transaction order."""

    def __init__(self, transaction: PhaseIOGateTransaction) -> None:
        if not isinstance(transaction, PhaseIOGateTransaction):
            raise GateRuntimeError(
                "transaction does not implement the PhaseIO adapter"
            )
        self._transaction = transaction
        self._state = "NEW"

    @property
    def state(self) -> str:
        return self._state

    def arm(
        self,
        *,
        gate: GateRecord,
        activation: GateActivation,
        invocation: GateInvocation,
        applicability: RuntimeApplicability,
    ) -> None:
        self._require("NEW")
        self._transaction.arm(
            gate=gate,
            activation=activation,
            invocation=invocation,
            applicability=applicability,
        )
        self._state = "ARMED"

    def evaluated(self) -> None:
        self._require("ARMED")
        self._state = "EVALUATED"

    def stage(self, evaluation: GateEvaluation) -> None:
        self._require("EVALUATED")
        self._transaction.stage(evaluation)
        self._state = "STAGED"

    def revalidate(self) -> tuple[str, ...]:
        self._require("STAGED")
        issues = self._transaction.revalidate()
        if not isinstance(issues, tuple) or any(
            not isinstance(item, str)
            or not item
            or any(
                character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
                for character in item
            )
            for item in issues
        ):
            raise GateRuntimeError(
                "PhaseIO revalidation returned malformed issues"
            )
        if issues != tuple(
            sorted(set(issues), key=lambda item: item.encode("utf-8"))
        ):
            raise GateRuntimeError(
                "PhaseIO revalidation issues must be sorted and unique"
            )
        self._state = "REVALIDATED"
        return issues

    def finish(
        self,
        *,
        reason_codes: tuple[str, ...] = (),
    ) -> PhaseIOCommitLink:
        self._require("REVALIDATED")
        if reason_codes:
            link = self._transaction.quarantine(reason_codes)
        else:
            link = self._transaction.checked_commit()
        if not isinstance(link, PhaseIOCommitLink):
            raise GateRuntimeError(
                "PhaseIO adapter returned the wrong commit-link type"
            )
        if reason_codes and link.commit_state != "QUARANTINED":
            raise GateRuntimeError(
                "PhaseIO adapter failed to quarantine invalid execution"
            )
        if not reason_codes and link.commit_state != "ACTIVE":
            raise GateRuntimeError(
                "PhaseIO adapter failed to produce ACTIVE checked commit"
            )
        self._state = "RECEIPTED"
        return link

    def fail(
        self,
        reason_codes: tuple[str, ...],
    ) -> PhaseIOCommitLink:
        """Quarantine any post-arm partial state without granting success."""

        if self._state not in {"ARMED", "EVALUATED", "STAGED", "REVALIDATED"}:
            raise GateRuntimeError(
                f"cannot quarantine transaction from {self._state}"
            )
        if (
            not reason_codes
            or reason_codes
            != tuple(
                sorted(
                    set(reason_codes),
                    key=lambda item: item.encode("utf-8"),
                )
            )
        ):
            raise GateRuntimeError(
                "quarantine reason codes must be sorted and unique"
            )
        link = self._transaction.quarantine(reason_codes)
        if (
            not isinstance(link, PhaseIOCommitLink)
            or link.commit_state != "QUARANTINED"
        ):
            raise GateRuntimeError(
                "PhaseIO adapter failed to quarantine partial execution"
            )
        self._state = "RECEIPTED"
        return link

    def _require(self, state: str) -> None:
        if self._state != state:
            raise GateRuntimeError(
                f"invalid gate transaction transition: "
                f"{self._state} -> expected {state}"
            )


def _execution_id(
    authority: GateRuntimeAuthority,
    gate_id: str,
    activation_id: str,
    invocation: GateInvocation,
    applicability: RuntimeApplicability,
) -> str:
    payload = {
        "registry": authority.registry_digest,
        "inventory": authority.inventory_digest,
        "tree": authority.source_tree_digest,
        "gate": gate_id,
        "activation": activation_id,
        "run": invocation.run_id,
        "inputs": list(invocation.input_evidence_digests),
        "input_artifacts": [
            item.to_dict() for item in invocation.input_artifacts
        ],
        "denominator": invocation.subject_denominator,
        "applicability": {
            "pipeline": applicability.pipeline,
            "mode": applicability.mode,
            "ecosystem": applicability.ecosystem,
            "backend": applicability.backend,
            "phase": applicability.phase,
        },
    }
    raw = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "mechanical." + hashlib.sha256(raw).hexdigest()


def _receipt(
    *,
    authority: GateRuntimeAuthority,
    gate_id: str,
    activation_id: str,
    invocation: GateInvocation,
    applicability: RuntimeApplicability,
    state: str,
    decision: str,
    authority_effect: str,
    counts: GateCountReceipt,
    output_evidence_digests: tuple[str, ...] = (),
    output_artifacts: tuple[GateArtifactEvidence, ...] = (),
    cost: GateCostReceipt | None = None,
    debt_codes: tuple[str, ...] = (),
    debt_action: str = "UNKNOWN_DEBT_CONTINUE",
    phase_io: PhaseIOCommitLink | None = None,
    ledger: ImmutableGateExecutionLedger | None = None,
) -> GateExecutionReceipt:
    normalized_debts = tuple(
        sorted(set(debt_codes), key=lambda item: item.encode("utf-8"))
    )
    receipt = GateExecutionReceipt(
        execution_id=_execution_id(
            authority,
            gate_id,
            activation_id,
            invocation,
            applicability,
        ),
        run_id=invocation.run_id,
        gate_id=gate_id,
        activation_id=activation_id,
        registry_digest=authority.registry_digest,
        registry_schema_version=authority.registry.schema_version,
        registry_revision=authority.registry.registry_revision,
        inventory_digest=authority.inventory_digest,
        source_tree_digest=authority.source_tree_digest,
        pipeline=applicability.pipeline,
        mode=applicability.mode,
        ecosystem=applicability.ecosystem,
        backend=applicability.backend,
        phase=applicability.phase,
        state=state,
        decision=decision,
        authority_effect=authority_effect,
        counts=counts,
        input_evidence_digests=invocation.input_evidence_digests,
        output_evidence_digests=output_evidence_digests,
        input_artifacts=invocation.input_artifacts,
        output_artifacts=output_artifacts,
        cost=cost or GateCostReceipt(),
        debt_codes=normalized_debts,
        debt_rows=tuple(
            GateDebtRow(
                code=code,
                condition=_debt_condition(code),
                action=debt_action,
            )
            for code in normalized_debts
        ),
        phase_io=phase_io,
    )
    if ledger is not None:
        ledger.publish(receipt)
    return receipt


def _debt_condition(code: str) -> str:
    if "OVERFLOW" in code or "BUDGET" in code:
        return "budget_overflow"
    if "TIMEOUT" in code:
        return "timeout"
    if "INPUT" in code or "SOURCE_TREE" in code:
        return "input_mutation"
    if "MALFORMED" in code or "UNTYPED" in code:
        return "malformed"
    if "UNKNOWN" in code or "ABSENT" in code:
        return "absent"
    if "REPLAY" in code or "RESUME" in code:
        return "partial_resume"
    return "receipt_failure"


def _unknown_receipt(
    *,
    authority: GateRuntimeAuthority,
    gate_id: str,
    activation_id: str,
    invocation: GateInvocation,
    applicability: RuntimeApplicability,
    debt_codes: tuple[str, ...],
    destructive: bool,
    ledger: ImmutableGateExecutionLedger | None = None,
) -> GateExecutionReceipt:
    return _receipt(
        authority=authority,
        gate_id=gate_id,
        activation_id=activation_id,
        invocation=invocation,
        applicability=applicability,
        state="DEBT",
        decision="UNKNOWN",
        authority_effect=(
            "RETAIN_UPSTREAM_AND_FLAG" if destructive else "SHADOW_ONLY"
        ),
        counts=GateCountReceipt.all_unknown(
            invocation.subject_denominator
        ),
        debt_codes=tuple(
            sorted(set(debt_codes), key=lambda item: item.encode("utf-8"))
        ),
        debt_action=(
            "RETAIN_UPSTREAM_AND_FLAG"
            if destructive
            else "SHADOW_ONLY_WITH_DEBT"
        ),
        ledger=ledger,
    )


def _is_destructive(gate: GateRecord) -> bool:
    authority = gate.authority
    return bool(
        authority["can_remove"]
        or authority["can_lower_severity"]
        or authority["can_clear_debt"]
        or authority["can_block_execution"]
        or authority["can_veto_ship"]
    )


def _input_contract_debts(
    gate: GateRecord,
    invocation: GateInvocation,
) -> tuple[str, ...]:
    if not invocation.input_artifacts:
        return ("INPUT_ARTIFACT_IDENTITY_ABSENT",)
    expected = {
        str(row["artifact_identity"]): str(row["schema_version"])
        for row in gate.input_contracts
    }
    observed = {
        row.artifact_identity: row.schema_version
        for row in invocation.input_artifacts
    }
    if set(observed) != set(expected):
        return ("INPUT_ARTIFACT_DENOMINATOR_MISMATCH",)
    if observed != expected:
        return ("INPUT_ARTIFACT_SCHEMA_MISMATCH",)
    return ()


def _budget_debts(
    gate: GateRecord,
    invocation: GateInvocation,
    evaluation: GateEvaluation,
) -> tuple[str, ...]:
    budget = gate.runtime_budget
    observed = {
        "max_input_bytes": sum(
            row.size for row in invocation.input_artifacts
        ),
        "max_input_files": len(invocation.input_artifacts),
        "max_raw_rows": evaluation.counts.raw_subjects,
        "max_unique_subjects": evaluation.counts.unique_subjects,
        "max_eligible_subjects": evaluation.counts.eligible_subjects,
        "max_retained_or_fired": evaluation.counts.fired_subjects,
        "max_emitted_candidates": (
            evaluation.counts.emitted_candidates
        ),
        "max_wall_clock_ms": evaluation.cost.wall_clock_ms,
        "max_external_processes": evaluation.cost.external_processes,
        "max_workers": evaluation.cost.workers,
        "max_tokens": evaluation.cost.tokens,
    }
    debts = {
        "BUDGET_OVERFLOW"
        for name, actual in observed.items()
        if budget[name] is not None and actual > budget[name]
    }
    if evaluation.counts.denominator_kind == "LOWER_BOUND":
        debts.add("UNKNOWN_REMAINDER")
    if evaluation.counts.overflow_subjects:
        overflow_identities = {
            str(row["artifact_identity"])
            for row in gate.output_contracts
            if row["authority_carried"] == "OVERFLOW_BACKLOG"
        }
        observed_outputs = {
            row.artifact_identity for row in evaluation.output_artifacts
        }
        if not overflow_identities & observed_outputs:
            debts.add("OVERFLOW_BACKLOG_ABSENT")
    return tuple(
        sorted(debts, key=lambda item: item.encode("utf-8"))
    )


def _output_contract_debts(
    gate: GateRecord,
    evaluation: GateEvaluation,
) -> tuple[str, ...]:
    if (
        evaluation.output_evidence_digests
        and not evaluation.output_artifacts
    ):
        return ("OUTPUT_ARTIFACT_IDENTITY_ABSENT",)
    allowed = {
        str(row["artifact_identity"]): str(row["schema_version"])
        for row in gate.output_contracts
    }
    observed = {
        row.artifact_identity: row.schema_version
        for row in evaluation.output_artifacts
    }
    if not set(observed).issubset(allowed):
        return ("OUTPUT_ARTIFACT_DENOMINATOR_MISMATCH",)
    if any(allowed[identity] != schema for identity, schema in observed.items()):
        return ("OUTPUT_ARTIFACT_SCHEMA_MISMATCH",)
    return ()


def _validate_phase_io_link(
    gate: GateRecord,
    link: PhaseIOCommitLink,
) -> None:
    expected_work_units = {
        str(row["phase_io_work_unit_id"])
        for row in gate.output_contracts
    }
    expected_outputs = tuple(
        sorted(
            {
                str(row["artifact_identity"])
                for row in gate.output_contracts
            },
            key=lambda item: item.encode("utf-8"),
        )
    )
    if (
        len(expected_work_units) != 1
        or link.work_unit_key not in expected_work_units
        or link.output_identities != expected_outputs
    ):
        raise GateRuntimeError(
            "PhaseIO commit link differs from registry output authority"
        )


def _activation(
    gate: GateRecord,
    activation_id: str,
) -> GateActivation | None:
    matches = [
        item
        for item in gate.activations
        if item.activation_id == activation_id
    ]
    return matches[0] if len(matches) == 1 else None


def _applicable(
    activation: GateActivation,
    applicability: RuntimeApplicability,
) -> bool:
    return bool(
        applicability.phase in activation.phases
        and applicability.pipeline in activation.pipelines
        and applicability.mode in activation.modes
        and applicability.ecosystem in activation.ecosystems
        and applicability.backend in activation.backends
    )


def _caller_identity(
    source_root: Path,
    activation: GateActivation,
    evaluator: Callable[[GateInvocation], GateEvaluation],
    caller: Any,
    *,
    require_evaluator_identity: bool,
) -> tuple[bool, str]:
    try:
        if caller is None:
            return False, "CALLER_IDENTITY_MISSING"
        caller_path = Path(caller.f_code.co_filename).resolve(strict=True)
        try:
            relative = caller_path.relative_to(source_root).as_posix()
        except ValueError:
            return False, "CALLER_MODULE_MISMATCH"
        wrapper = activation.wrapper_symbol.rsplit(".", 1)[-1]
        if (
            relative != activation.module
            or caller.f_code.co_name != wrapper
        ):
            return False, "CALLER_IDENTITY_MISMATCH"
        if not require_evaluator_identity:
            return True, ""
        evaluator_name = str(getattr(evaluator, "__name__", "")).rsplit(
            ".", 1
        )[-1]
        allowed = {
            symbol.rsplit(".", 1)[-1]
            for symbol in activation.implementation_symbols
        }
        if evaluator_name not in allowed:
            return False, "EVALUATOR_IDENTITY_MISMATCH"
        evaluator_source = inspect.getsourcefile(evaluator)
        if evaluator_source is None:
            return False, "EVALUATOR_SOURCE_MISSING"
        evaluator_path = Path(evaluator_source).resolve(strict=True)
        try:
            evaluator_relative = evaluator_path.relative_to(
                source_root
            ).as_posix()
        except ValueError:
            return False, "EVALUATOR_MODULE_MISMATCH"
        if evaluator_relative != activation.module:
            return False, "EVALUATOR_MODULE_MISMATCH"
        return True, ""
    except OSError:
        return False, "CALLER_IDENTITY_UNREADABLE"


def _closure_matches(
    authority: GateRuntimeAuthority,
    activation: GateActivation,
) -> bool:
    try:
        return (
            compute_decision_code_digest(
                authority.source_root,
                activation,
                production_roots=tuple(
                    authority.registry.registry_scope["production_roots"]
                ),
                production_excludes=tuple(
                    authority.registry.registry_scope["production_excludes"]
                ),
            )
            == activation.code_digest
        )
    except ActivationInventoryError:
        return False


def _source_tree_matches(authority: GateRuntimeAuthority) -> bool:
    try:
        return (
            compute_source_tree_digest(
                authority.source_root,
                production_roots=tuple(
                    authority.registry.registry_scope["production_roots"]
                ),
                production_excludes=tuple(
                    authority.registry.registry_scope["production_excludes"]
                ),
            )
            == authority.source_tree_digest
        )
    except ActivationInventoryError:
        return False


def _shadow_evaluation_counts(
    evaluation: GateEvaluation,
) -> tuple[str, GateCountReceipt]:
    if evaluation.decision != "CLEAR":
        return evaluation.decision, evaluation.counts
    count = evaluation.counts.evaluated_subjects
    return (
        "UNKNOWN",
        GateCountReceipt(
            raw_subjects=evaluation.counts.raw_subjects,
            unique_subjects=evaluation.counts.unique_subjects,
            eligible_subjects=evaluation.counts.eligible_subjects,
            evaluated_subjects=count,
            fired_subjects=0,
            clear_subjects=0,
            unknown_subjects=count,
            overflow_subjects=evaluation.counts.overflow_subjects,
            emitted_candidates=0,
            denominator_kind=evaluation.counts.denominator_kind,
        ),
    )


def _execute_registered_gate(
    gate_id: str,
    *,
    activation_id: str,
    context: GateInvocation,
    evaluator: Callable[[GateInvocation], GateEvaluation],
    authority: GateRuntimeAuthority | None = None,
    applicability: RuntimeApplicability | None = None,
    transaction: PhaseIOGateTransaction | None = None,
    ledger: ImmutableGateExecutionLedger | None = None,
    caller_frame: Any,
    require_evaluator_identity: bool,
) -> GateExecutionReceipt:
    """Evaluate one exact registered gate without ambient authority.

    Missing runtime authority raises before evaluator execution because there
    is no trustworthy registry/tree digest with which to construct even a debt
    receipt.  Once authority is valid, all later mismatches are represented as
    typed recall-open or shadow debt.
    """

    if (
        not isinstance(authority, GateRuntimeAuthority)
        or _ISSUED_AUTHORITIES.get(id(authority)) is not authority
    ):
        raise GateRuntimeError("explicit GateRuntimeAuthority is required")
    if not isinstance(context, GateInvocation):
        raise GateRuntimeError("context must be GateInvocation")
    if not isinstance(applicability, RuntimeApplicability):
        raise GateRuntimeError(
            "explicit RuntimeApplicability is required"
        )
    if not callable(evaluator):
        raise GateRuntimeError("evaluator must be callable")
    if ledger is not None and not isinstance(
        ledger, ImmutableGateExecutionLedger
    ):
        raise GateRuntimeError(
            "ledger must be ImmutableGateExecutionLedger"
        )
    gate_id = str(gate_id or "").strip()
    activation_id = str(activation_id or "").strip()
    if (
        not gate_id
        or not activation_id.startswith(gate_id + ".")
        or any(
            character not in
            "abcdefghijklmnopqrstuvwxyz0123456789._"
            for character in gate_id + activation_id
        )
    ):
        raise GateRuntimeError("gate or activation ID is not canonical")
    execution_id = _execution_id(
        authority,
        gate_id,
        activation_id,
        context,
        applicability,
    )
    if ledger is not None:
        try:
            existing = ledger.read_if_present(execution_id)
        except GateReceiptError as exc:
            raise GateRuntimeError(
                "existing execution receipt is invalid"
            ) from exc
        if existing is not None:
            expected = (
                existing.gate_id == gate_id
                and existing.activation_id == activation_id
                and existing.run_id == context.run_id
                and existing.registry_digest == authority.registry_digest
                and existing.inventory_digest == authority.inventory_digest
                and existing.source_tree_digest
                == authority.source_tree_digest
                and existing.pipeline == applicability.pipeline
                and existing.mode == applicability.mode
                and existing.ecosystem == applicability.ecosystem
                and existing.backend == applicability.backend
                and existing.phase == applicability.phase
                and existing.input_artifacts == context.input_artifacts
            )
            if not expected:
                raise GateRuntimeError(
                    "execution replay binding is invalid"
                )
            return existing

    try:
        gate = resolve_gate_record(authority.registry, gate_id)
    except MechanicalGateRegistryError:
        return _unknown_receipt(
            authority=authority,
            gate_id=gate_id,
            activation_id=activation_id,
            invocation=context,
            applicability=applicability,
            debt_codes=("UNKNOWN_GATE",),
            destructive=False,
            ledger=ledger,
        )
    activation = _activation(gate, activation_id)
    destructive = _is_destructive(gate)
    if activation is None:
        return _unknown_receipt(
            authority=authority,
            gate_id=gate_id,
            activation_id=activation_id,
            invocation=context,
            applicability=applicability,
            debt_codes=("UNKNOWN_ACTIVATION",),
            # An undeclared activation has no runtime authority at all.  It is
            # migration shadow/debt, never an inferred extension of the
            # registered gate's destructive capability.
            destructive=False,
            ledger=ledger,
        )
    if not _applicable(activation, applicability):
        return _receipt(
            authority=authority,
            gate_id=gate_id,
            activation_id=activation_id,
            invocation=context,
            applicability=applicability,
            state="NOT_APPLICABLE",
            decision="NOT_APPLICABLE",
            authority_effect="NONE",
            counts=GateCountReceipt.empty(),
            ledger=ledger,
        )
    if activation.runtime_state != "RUNTIME":
        return _unknown_receipt(
            authority=authority,
            gate_id=gate_id,
            activation_id=activation_id,
            invocation=context,
            applicability=applicability,
            debt_codes=("ACTIVATION_NON_RUNTIME",),
            destructive=destructive,
            ledger=ledger,
        )
    if not _source_tree_matches(authority):
        return _unknown_receipt(
            authority=authority,
            gate_id=gate_id,
            activation_id=activation_id,
            invocation=context,
            applicability=applicability,
            debt_codes=("SOURCE_TREE_DRIFT",),
            destructive=destructive,
            ledger=ledger,
        )
    caller_valid, caller_debt = _caller_identity(
        authority.source_root,
        activation,
        evaluator,
        caller_frame,
        require_evaluator_identity=require_evaluator_identity,
    )
    if not caller_valid:
        return _unknown_receipt(
            authority=authority,
            gate_id=gate_id,
            activation_id=activation_id,
            invocation=context,
            applicability=applicability,
            debt_codes=(caller_debt,),
            destructive=destructive,
            ledger=ledger,
        )
    if not _closure_matches(authority, activation):
        return _unknown_receipt(
            authority=authority,
            gate_id=gate_id,
            activation_id=activation_id,
            invocation=context,
            applicability=applicability,
            debt_codes=("DECISION_CLOSURE_DRIFT",),
            destructive=destructive,
            ledger=ledger,
        )
    if not context.input_evidence_digests:
        return _unknown_receipt(
            authority=authority,
            gate_id=gate_id,
            activation_id=activation_id,
            invocation=context,
            applicability=applicability,
            debt_codes=("INPUT_EVIDENCE_ABSENT",),
            destructive=True,
            ledger=ledger,
        )
    input_contract_debts = _input_contract_debts(gate, context)
    if input_contract_debts:
        return _unknown_receipt(
            authority=authority,
            gate_id=gate_id,
            activation_id=activation_id,
            invocation=context,
            applicability=applicability,
            debt_codes=input_contract_debts,
            destructive=True,
            ledger=ledger,
        )
    if gate.lifecycle_state not in {
        "ACTIVE",
        "LEGACY_ACTIVE_UNGOVERNED",
    }:
        return _unknown_receipt(
            authority=authority,
            gate_id=gate_id,
            activation_id=activation_id,
            invocation=context,
            applicability=applicability,
            debt_codes=("LIFECYCLE_NON_RUNTIME",),
            destructive=destructive,
            ledger=ledger,
        )
    if gate.lifecycle_state == "ACTIVE" and ledger is None:
        return _unknown_receipt(
            authority=authority,
            gate_id=gate_id,
            activation_id=activation_id,
            invocation=context,
            applicability=applicability,
            debt_codes=("EXECUTION_LEDGER_ABSENT",),
            destructive=destructive,
            ledger=None,
        )

    machine: GateTransactionStateMachine | None = None
    try:
        if gate.lifecycle_state == "ACTIVE":
            if transaction is None:
                return _unknown_receipt(
                    authority=authority,
                    gate_id=gate_id,
                    activation_id=activation_id,
                    invocation=context,
                    applicability=applicability,
                    debt_codes=("PHASEIO_TRANSACTION_ABSENT",),
                    destructive=destructive,
                    ledger=ledger,
                )
            machine = GateTransactionStateMachine(transaction)
            machine.arm(
                gate=gate,
                activation=activation,
                invocation=context,
                applicability=applicability,
            )
        evaluation = evaluator(context)
        if not isinstance(evaluation, GateEvaluation):
            raise GateRuntimeError(
                "evaluator returned an untyped decision"
            )
        if (
            evaluation.counts.raw_subjects
            != context.subject_denominator
        ):
            raise GateRuntimeError(
                "evaluator denominator differs from armed invocation"
            )
        evaluation_debts = tuple(
            sorted(
                {
                    *evaluation.debt_codes,
                    *_budget_debts(gate, context, evaluation),
                    *_output_contract_debts(gate, evaluation),
                },
                key=lambda item: item.encode("utf-8"),
            )
        )
        if machine is not None:
            machine.evaluated()
            machine.stage(evaluation)
            issues = machine.revalidate()
            if issues:
                link = machine.finish(reason_codes=issues)
                _validate_phase_io_link(gate, link)
                return _receipt(
                    authority=authority,
                    gate_id=gate_id,
                    activation_id=activation_id,
                    invocation=context,
                    applicability=applicability,
                    state="QUARANTINED",
                    decision="UNKNOWN",
                    authority_effect="RETAIN_UPSTREAM_AND_FLAG",
                    counts=GateCountReceipt.all_unknown(
                        context.subject_denominator
                    ),
                    debt_codes=issues,
                    debt_action="QUARANTINE_AND_RETRY",
                    phase_io=link,
                    ledger=ledger,
                )
            if evaluation_debts and destructive:
                link = machine.finish(
                    reason_codes=evaluation_debts
                )
                _validate_phase_io_link(gate, link)
                return _receipt(
                    authority=authority,
                    gate_id=gate_id,
                    activation_id=activation_id,
                    invocation=context,
                    applicability=applicability,
                    state="QUARANTINED",
                    decision="UNKNOWN",
                    authority_effect="RETAIN_UPSTREAM_AND_FLAG",
                    counts=GateCountReceipt.all_unknown(
                        context.subject_denominator
                    ),
                    debt_codes=evaluation_debts,
                    debt_action="QUARANTINE_AND_RETRY",
                    phase_io=link,
                    ledger=ledger,
                )
            link = machine.finish()
            _validate_phase_io_link(gate, link)
            effect = (
                "ADD_ONLY"
                if gate.authority["direction"]
                in {"GENERATE_ADD_ONLY", "REOPEN_ADD_ONLY"}
                else "AUTHORITATIVE"
            )
            debts = evaluation_debts
            state = "COMMITTED" if not debts else "DEBT"
            final_decision = evaluation.decision
            final_counts = evaluation.counts
            if state == "DEBT":
                effect = "ADD_ONLY"
                if final_decision == "CLEAR":
                    final_decision = "UNKNOWN"
                    final_counts = GateCountReceipt.all_unknown(
                        context.subject_denominator
                    )
            return _receipt(
                authority=authority,
                gate_id=gate_id,
                activation_id=activation_id,
                invocation=context,
                applicability=applicability,
                state=state,
                decision=final_decision,
                authority_effect=effect,
                counts=final_counts,
                output_evidence_digests=(
                    evaluation.output_evidence_digests
                ),
                output_artifacts=evaluation.output_artifacts,
                cost=evaluation.cost,
                debt_codes=debts,
                debt_action=(
                    "GENERATE_ADD_ONLY_WITH_DEBT"
                    if debts
                    else "NOT_APPLICABLE"
                ),
                phase_io=link,
                ledger=ledger,
            )
    except Exception:
        # Evaluator/provider failure never becomes CLEAR.  Do not include
        # exception prose in deterministic receipts.
        if machine is not None and machine.state != "RECEIPTED":
            reason = ("TRANSACTION_OR_EVALUATOR_FAILURE",)
            try:
                link = machine.fail(reason)
            except Exception:
                link = None
            if link is not None:
                try:
                    _validate_phase_io_link(gate, link)
                except GateRuntimeError:
                    link = None
            if link is not None:
                return _receipt(
                    authority=authority,
                    gate_id=gate_id,
                    activation_id=activation_id,
                    invocation=context,
                    applicability=applicability,
                    state="QUARANTINED",
                    decision="UNKNOWN",
                    authority_effect="RETAIN_UPSTREAM_AND_FLAG",
                    counts=GateCountReceipt.all_unknown(
                        context.subject_denominator
                    ),
                    debt_codes=reason,
                    debt_action="QUARANTINE_AND_RETRY",
                    phase_io=link,
                    ledger=ledger,
                )
        return _unknown_receipt(
            authority=authority,
            gate_id=gate_id,
            activation_id=activation_id,
            invocation=context,
            applicability=applicability,
            debt_codes=(
                "EVALUATOR_FAILURE"
                if machine is None
                else "TRANSACTION_OR_EVALUATOR_FAILURE",
            ),
            destructive=destructive,
            ledger=ledger,
        )

    # The current strict registry admits only legacy runtime-counted gates.
    # Evaluate them for migration evidence, but do not grant reviewed authority.
    decision, counts = _shadow_evaluation_counts(evaluation)
    debts = tuple(
        sorted(
            {
                *evaluation_debts,
                "LEGACY_UNGOVERNED",
                *(
                    ("EXECUTION_LEDGER_ABSENT",)
                    if ledger is None
                    else ()
                ),
            },
            key=lambda item: item.encode("utf-8"),
        )
    )
    return _receipt(
        authority=authority,
        gate_id=gate_id,
        activation_id=activation_id,
        invocation=context,
        applicability=applicability,
        state="DEBT",
        decision=decision,
        authority_effect="SHADOW_ONLY",
        counts=counts,
        output_evidence_digests=evaluation.output_evidence_digests,
        output_artifacts=evaluation.output_artifacts,
        cost=evaluation.cost,
        debt_codes=debts,
        debt_action="SHADOW_ONLY_WITH_DEBT",
        ledger=ledger,
    )


def evaluate_registered_gate(
    gate_id: str,
    *,
    activation_id: str,
    context: GateInvocation,
    evaluator: Callable[[GateInvocation], GateEvaluation],
    authority: GateRuntimeAuthority | None = None,
    applicability: RuntimeApplicability | None = None,
    transaction: PhaseIOGateTransaction | None = None,
    ledger: ImmutableGateExecutionLedger | None = None,
) -> GateExecutionReceipt:
    """Evaluate through the literal wrapper-bound implementation callback."""

    frame = inspect.currentframe()
    caller = frame.f_back if frame is not None else None
    try:
        return _execute_registered_gate(
            gate_id,
            activation_id=activation_id,
            context=context,
            evaluator=evaluator,
            authority=authority,
            applicability=applicability,
            transaction=transaction,
            ledger=ledger,
            caller_frame=caller,
            require_evaluator_identity=True,
        )
    finally:
        del caller
        del frame


def record_registered_gate(
    gate_id: str,
    *,
    activation_id: str,
    context: GateInvocation,
    result: GateEvaluation,
    authority: GateRuntimeAuthority | None = None,
    applicability: RuntimeApplicability | None = None,
    transaction: PhaseIOGateTransaction | None = None,
    ledger: ImmutableGateExecutionLedger | None = None,
) -> GateExecutionReceipt:
    """Record a wrapper-computed typed decision without accepting prose/bools."""

    if not isinstance(result, GateEvaluation):
        raise GateRuntimeError("result must be GateEvaluation")

    def recorded_result(_context: GateInvocation) -> GateEvaluation:
        return result

    frame = inspect.currentframe()
    caller = frame.f_back if frame is not None else None
    try:
        return _execute_registered_gate(
            gate_id,
            activation_id=activation_id,
            context=context,
            evaluator=recorded_result,
            authority=authority,
            applicability=applicability,
            transaction=transaction,
            ledger=ledger,
            caller_frame=caller,
            require_evaluator_identity=False,
        )
    finally:
        del caller
        del frame


__all__ = [
    "GateEvaluation",
    "GateInvocation",
    "GateRuntimeAuthority",
    "GateRuntimeError",
    "GateTransactionStateMachine",
    "PhaseIOGateTransaction",
    "RuntimeApplicability",
    "evaluate_registered_gate",
    "record_registered_gate",
]
