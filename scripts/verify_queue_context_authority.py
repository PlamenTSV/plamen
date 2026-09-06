"""Pure authority selection for optional verify-queue context.

This module is intentionally unwired.  It turns one frozen filesystem/ledger
snapshot into an immutable, child-scoped selection.  Invalid optional context
is omitted with durable status data; it never blocks routing of the ordinary
inventory denominator and never gains proof authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping


COMMITTED_APPLIED = "COMMITTED_APPLIED"
COMMITTED_CLEAN_NOOP = "COMMITTED_CLEAN_NOOP"
COMPLETED_WITH_DEBT_SAFE_BASE = "COMPLETED_WITH_DEBT_SAFE_BASE"
PREPARED_NOT_CONSUMABLE = "PREPARED_NOT_CONSUMABLE"
QUARANTINED_FOREIGN_STATE = "QUARANTINED_FOREIGN_STATE"

CONTEXT_STATES = frozenset({
    COMMITTED_APPLIED,
    COMMITTED_CLEAN_NOOP,
    COMPLETED_WITH_DEBT_SAFE_BASE,
    PREPARED_NOT_CONSUMABLE,
    QUARANTINED_FOREIGN_STATE,
})

SUPPORTED_PIPELINES = frozenset({"sc", "l1"})
SUPPORTED_MODES = frozenset({"light", "core", "thorough"})
SUPPORTED_BACKENDS = frozenset({"claude", "codex"})
CONSUMERS = (
    "compound",
    "grouping",
    "mandatory_reverification",
)

APPLICATION_SKEPTIC = "application_skeptic_proposals.md"
CANDIDATE_NEGATIVE_SKEPTIC = "candidate_negative_skeptic_proposals.md"
HYPOTHESES = "hypotheses.md"
FINDING_MAPPING = "finding_mapping.md"
CHAIN_GROUPING_RELATIONS = "chain_grouping_relations.json"
CHAIN_ANTI_ABSORPTION_RECEIPT = (
    "chain_anti_absorption_applied_receipt.json"
)
CHAIN_EQUIVALENCE_PROPOSALS = "chain_equivalence_proposals.json"
CHAIN_COMPOSITION_CANDIDATES = (
    "chain_composition_verification_candidates.json"
)
CHAIN_HYPOTHESES = "chain_hypotheses.md"

KNOWN_ARTIFACTS = (
    APPLICATION_SKEPTIC,
    CANDIDATE_NEGATIVE_SKEPTIC,
    HYPOTHESES,
    FINDING_MAPPING,
    CHAIN_GROUPING_RELATIONS,
    CHAIN_ANTI_ABSORPTION_RECEIPT,
    CHAIN_EQUIVALENCE_PROPOSALS,
    CHAIN_COMPOSITION_CANDIDATES,
    CHAIN_HYPOTHESES,
)

_DIGEST_RE = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class ProducerRule:
    owner_suffix: str
    modes: frozenset[str]
    generation_scoped: bool = False


@dataclass(frozen=True, slots=True)
class ArtifactPolicy:
    artifact: str
    pipelines: frozenset[str]
    modes: frozenset[str]
    consumers: frozenset[str]
    producers: tuple[ProducerRule, ...]
    atomic_pair: str = ""


_ALL_MODES = frozenset(SUPPORTED_MODES)
_CORE_THOROUGH = frozenset({"core", "thorough"})

POLICIES: tuple[ArtifactPolicy, ...] = (
    ArtifactPolicy(
        artifact=APPLICATION_SKEPTIC,
        pipelines=frozenset({"sc", "l1"}),
        modes=_CORE_THOROUGH,
        consumers=frozenset({"mandatory_reverification"}),
        producers=(
            ProducerRule(
                "application_skeptic/reconcile", _CORE_THOROUGH
            ),
        ),
    ),
    ArtifactPolicy(
        artifact=CANDIDATE_NEGATIVE_SKEPTIC,
        pipelines=frozenset({"sc", "l1"}),
        modes=_CORE_THOROUGH,
        consumers=frozenset({"mandatory_reverification"}),
        producers=(
            ProducerRule(
                "application_skeptic/negative.reconcile",
                _CORE_THOROUGH,
            ),
        ),
    ),
    ArtifactPolicy(
        artifact=HYPOTHESES,
        pipelines=frozenset({"sc"}),
        modes=_ALL_MODES,
        consumers=frozenset({"grouping"}),
        producers=(ProducerRule("chain/canonicalize", _ALL_MODES),),
        atomic_pair="hypothesis_mapping",
    ),
    ArtifactPolicy(
        artifact=FINDING_MAPPING,
        pipelines=frozenset({"sc"}),
        modes=_ALL_MODES,
        consumers=frozenset({"grouping"}),
        producers=(ProducerRule("chain/canonicalize", _ALL_MODES),),
        atomic_pair="hypothesis_mapping",
    ),
    ArtifactPolicy(
        artifact=CHAIN_GROUPING_RELATIONS,
        pipelines=frozenset({"sc"}),
        modes=_ALL_MODES,
        consumers=frozenset({"grouping"}),
        producers=(
            ProducerRule("chain/grouping_relation_repair", _ALL_MODES),
        ),
        atomic_pair="grouping_relation",
    ),
    ArtifactPolicy(
        artifact=CHAIN_ANTI_ABSORPTION_RECEIPT,
        pipelines=frozenset({"sc"}),
        modes=_ALL_MODES,
        consumers=frozenset({"grouping"}),
        producers=(
            ProducerRule("chain/grouping_relation_repair", _ALL_MODES),
        ),
        atomic_pair="grouping_relation",
    ),
    ArtifactPolicy(
        artifact=CHAIN_COMPOSITION_CANDIDATES,
        pipelines=frozenset({"sc"}),
        modes=_ALL_MODES,
        consumers=frozenset({"compound"}),
        producers=(
            ProducerRule("chain/state_resolution", _ALL_MODES),
            ProducerRule(
                "chain_iter2/tail_reconcile",
                frozenset({"thorough"}),
                True,
            ),
        ),
    ),
    ArtifactPolicy(
        artifact=CHAIN_HYPOTHESES,
        pipelines=frozenset({"sc"}),
        modes=_ALL_MODES,
        consumers=frozenset({"compound", "grouping"}),
        producers=(
            ProducerRule("chain_agent2/model", _ALL_MODES),
            ProducerRule(
                "chain_iter2/driver_merge",
                frozenset({"thorough"}),
                True,
            ),
        ),
    ),
)

_POLICY_BY_ARTIFACT = {policy.artifact: policy for policy in POLICIES}
_SC_ONLY_ARTIFACTS = frozenset({
    HYPOTHESES,
    FINDING_MAPPING,
    CHAIN_GROUPING_RELATIONS,
    CHAIN_ANTI_ABSORPTION_RECEIPT,
    CHAIN_EQUIVALENCE_PROPOSALS,
    CHAIN_COMPOSITION_CANDIDATES,
    CHAIN_HYPOTHESES,
})
_PAIR_MEMBERS = {
    "grouping_relation": (
        CHAIN_GROUPING_RELATIONS,
        CHAIN_ANTI_ABSORPTION_RECEIPT,
    ),
    "hypothesis_mapping": (HYPOTHESES, FINDING_MAPPING),
}


@dataclass(frozen=True, slots=True)
class LedgerArtifactSnapshot:
    identity: str
    owner_key: str
    status: str
    run_id: str
    contract_digest: str
    sha256: str
    size: int | None


@dataclass(frozen=True, slots=True)
class LedgerOwnerSnapshot:
    work_unit_key: str
    execution_state: str
    semantic_status: str
    run_id: str
    contract_digest: str
    artifact: LedgerArtifactSnapshot | None


@dataclass(frozen=True, slots=True)
class ContextArtifactSnapshot:
    artifact: str
    present: bool
    content: bytes | None
    sha256: str
    size: int
    read_error: str
    binding: LedgerArtifactSnapshot | None
    owner: LedgerOwnerSnapshot | None


@dataclass(frozen=True, slots=True)
class VerifyQueueContextSnapshot:
    artifacts: tuple[ContextArtifactSnapshot, ...]
    chain_tail_generation_id: str
    chain_tail_generation_error: str
    snapshot_digest: str

    def artifact(self, name: str) -> ContextArtifactSnapshot:
        for artifact in self.artifacts:
            if artifact.artifact == name:
                return artifact
        raise KeyError(name)


@dataclass(frozen=True, slots=True)
class AcceptedContext:
    artifact: str
    owner_key: str
    contract_digest: str
    sha256: str
    size: int
    consumers: tuple[str, ...]
    content: bytes


@dataclass(frozen=True, slots=True)
class ContextIssue:
    artifact: str
    state: str
    codes: tuple[str, ...]
    details: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class VerifyQueueContextSelection:
    pipeline: str
    mode: str
    ecosystem: str
    backend: str
    run_id: str
    state: str
    accepted: tuple[AcceptedContext, ...]
    issues: tuple[ContextIssue, ...]
    not_applicable_paths: tuple[str, ...]
    snapshot_digest: str
    selection_digest: str
    safe_base_routing: bool = True
    proof_authority: str = "NONE"

    @property
    def accepted_paths(self) -> tuple[str, ...]:
        return tuple(item.artifact for item in self.accepted)

    def accepted_paths_for(self, consumer: str) -> tuple[str, ...]:
        consumer_n = str(consumer or "").strip()
        if consumer_n not in {*CONSUMERS, "routing"}:
            raise ValueError(f"unsupported context consumer: {consumer!r}")
        return tuple(
            item.artifact
            for item in self.accepted
            if consumer_n in item.consumers
        )

    def status_payload(self) -> dict[str, Any]:
        return build_verify_queue_context_status(self)


def _canonical_json_bytes(payload: Any) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _as_size(value: Any) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _ledger_artifact_snapshot(
    value: Any,
    *,
    default_identity: str,
) -> LedgerArtifactSnapshot | None:
    row = _as_mapping(value)
    if not row:
        return None
    return LedgerArtifactSnapshot(
        identity=str(row.get("identity") or default_identity),
        owner_key=str(row.get("owner_key") or ""),
        status=str(row.get("status") or ""),
        run_id=str(row.get("run_id") or ""),
        contract_digest=str(row.get("contract_digest") or ""),
        sha256=str(row.get("sha256") or ""),
        size=_as_size(row.get("size")),
    )


def capture_verify_queue_context_snapshot(
    root: Path,
    ledger: Mapping[str, Any] | None,
) -> VerifyQueueContextSnapshot:
    """Read every closed-policy artifact once and freeze its ledger lineage."""

    base = Path(root)
    ledger_map = _as_mapping(ledger)
    bindings = _as_mapping(ledger_map.get("artifact_bindings"))
    work_units = _as_mapping(ledger_map.get("work_units"))
    captured: list[ContextArtifactSnapshot] = []
    chain_tail_generation_id = ""
    chain_tail_generation_error = ""
    control_ledger = (
        base / "_chain_tail_control" / "chain_tail_disposition_ledger.json"
    )
    if control_ledger.exists() or any(
        (base / artifact).exists()
        for artifact in (
            CHAIN_COMPOSITION_CANDIDATES,
            CHAIN_HYPOTHESES,
        )
    ):
        try:
            from chain_tail_authority import (
                chain_tail_control_generation,
                chain_tail_generation_id as render_chain_tail_generation_id,
            )

            generation = chain_tail_control_generation(base)
            if (
                not isinstance(generation, tuple)
                or len(generation) != 2
            ):
                raise ValueError(
                    "chain-tail control generation helper is malformed"
                )
            pass_index, shard_count = generation
            if (
                not isinstance(pass_index, int)
                or isinstance(pass_index, bool)
                or not isinstance(shard_count, int)
                or isinstance(shard_count, bool)
                or not 0 <= pass_index <= 9999
                or not 0 <= shard_count <= 9999
            ):
                raise ValueError(
                    "chain-tail control generation is outside exact bounds"
                )
            chain_tail_generation_id = (
                render_chain_tail_generation_id(
                    pass_index,
                    shard_count,
                )
            )
        except (
            OSError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            chain_tail_generation_error = (
                f"{type(exc).__name__}: {exc}"
            )

    for artifact in KNOWN_ARTIFACTS:
        path = base / artifact
        present = path.exists() or path.is_symlink()
        content: bytes | None = None
        read_error = ""
        if present:
            if path.is_symlink():
                read_error = "SYMLINK_NOT_ALLOWED"
            else:
                try:
                    content = path.read_bytes()
                except OSError as exc:
                    read_error = type(exc).__name__
        digest = _sha256(content) if content is not None else ""
        size = len(content) if content is not None else 0
        identity = f"scratchpad:{artifact}"
        binding = _ledger_artifact_snapshot(
            bindings.get(identity), default_identity=identity
        )
        owner: LedgerOwnerSnapshot | None = None
        if binding is not None and binding.owner_key:
            owner_row = _as_mapping(work_units.get(binding.owner_key))
            if owner_row:
                owner_artifacts = _as_mapping(owner_row.get("artifacts"))
                owner = LedgerOwnerSnapshot(
                    work_unit_key=str(
                        owner_row.get("work_unit_key")
                        or binding.owner_key
                    ),
                    execution_state=str(
                        owner_row.get("execution_state") or ""
                    ),
                    semantic_status=str(
                        owner_row.get("semantic_status") or ""
                    ),
                    run_id=str(owner_row.get("run_id") or ""),
                    contract_digest=str(
                        owner_row.get("contract_digest") or ""
                    ),
                    artifact=_ledger_artifact_snapshot(
                        owner_artifacts.get(identity),
                        default_identity=identity,
                    ),
                )
        captured.append(ContextArtifactSnapshot(
            artifact=artifact,
            present=present,
            content=content,
            sha256=digest,
            size=size,
            read_error=read_error,
            binding=binding,
            owner=owner,
        ))

    snapshot_rows = [
        {
            "artifact": item.artifact,
            "present": item.present,
            "sha256": item.sha256,
            "size": item.size,
            "read_error": item.read_error,
            "binding": (
                {
                    "identity": item.binding.identity,
                    "owner_key": item.binding.owner_key,
                    "status": item.binding.status,
                    "run_id": item.binding.run_id,
                    "contract_digest": item.binding.contract_digest,
                    "sha256": item.binding.sha256,
                    "size": item.binding.size,
                }
                if item.binding is not None
                else None
            ),
            "owner": (
                {
                    "work_unit_key": item.owner.work_unit_key,
                    "execution_state": item.owner.execution_state,
                    "semantic_status": item.owner.semantic_status,
                    "run_id": item.owner.run_id,
                    "contract_digest": item.owner.contract_digest,
                    "artifact": (
                        {
                            "identity": item.owner.artifact.identity,
                            "owner_key": item.owner.artifact.owner_key,
                            "status": item.owner.artifact.status,
                            "run_id": item.owner.artifact.run_id,
                            "contract_digest": (
                                item.owner.artifact.contract_digest
                            ),
                            "sha256": item.owner.artifact.sha256,
                            "size": item.owner.artifact.size,
                        }
                        if item.owner.artifact is not None
                        else None
                    ),
                }
                if item.owner is not None
                else None
            ),
        }
        for item in captured
    ]
    return VerifyQueueContextSnapshot(
        artifacts=tuple(captured),
        chain_tail_generation_id=chain_tail_generation_id,
        chain_tail_generation_error=chain_tail_generation_error,
        snapshot_digest=_sha256(_canonical_json_bytes({
            "artifacts": snapshot_rows,
            "chain_tail_generation_id": chain_tail_generation_id,
            "chain_tail_generation_error": chain_tail_generation_error,
        })),
    )


def _normalize_dimension(
    value: str,
    *,
    label: str,
    allowed: frozenset[str] | None = None,
) -> str:
    normalized = str(value or "").strip().lower()
    if not normalized or "/" in normalized or "\\" in normalized:
        raise ValueError(f"invalid context {label}: {value!r}")
    if allowed is not None and normalized not in allowed:
        raise ValueError(f"unsupported context {label}: {value!r}")
    return normalized


def _expected_owner_suffixes(
    policy: ArtifactPolicy,
    mode: str,
    *,
    chain_tail_generation_id: str,
) -> tuple[str, ...]:
    return tuple(
        (
            f"{rule.owner_suffix}.{chain_tail_generation_id}"
            if rule.generation_scoped and chain_tail_generation_id
            else rule.owner_suffix
        )
        for rule in policy.producers
        if mode in rule.modes
    )


def _validate_artifact(
    snapshot: ContextArtifactSnapshot,
    policy: ArtifactPolicy,
    *,
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
    run_id: str,
    chain_tail_generation_id: str,
    chain_tail_generation_error: str,
) -> tuple[AcceptedContext | None, ContextIssue | None]:
    codes: list[str] = []
    details: list[str] = []
    binding = snapshot.binding
    owner = snapshot.owner
    identity = f"scratchpad:{snapshot.artifact}"

    def reject(code: str, detail: str) -> None:
        if code not in codes:
            codes.append(code)
        if detail not in details:
            details.append(detail)

    if snapshot.read_error:
        reject("ARTIFACT_UNREADABLE", snapshot.read_error)
    if snapshot.content is None:
        reject("ARTIFACT_UNREADABLE", "no frozen content")
    if binding is None:
        reject("BINDING_MISSING", "artifact has no ledger binding")
    else:
        if binding.identity != identity:
            reject("IDENTITY_MISMATCH", "binding identity differs")
        if binding.status != "ACTIVE":
            reject(
                "BINDING_NOT_ACTIVE",
                f"binding status={binding.status or 'UNKNOWN'}",
            )
        if binding.run_id != run_id:
            reject("RUN_MISMATCH", "binding run differs")
        if binding.sha256 != snapshot.sha256:
            reject("HASH_MISMATCH", "binding hash differs")
        if binding.size != snapshot.size:
            reject("SIZE_MISMATCH", "binding size differs")

        prefix = f"{pipeline}/{mode}/{ecosystem}/{backend}/"
        applicable_rules = tuple(
            rule for rule in policy.producers if mode in rule.modes
        )
        requires_generation = any(
            rule.generation_scoped for rule in applicable_rules
        )
        if requires_generation and (
            chain_tail_generation_error
            or not re.fullmatch(
                r"p\d{4}\.s\d{4}",
                chain_tail_generation_id,
            )
        ):
            reject(
                "GENERATION_AUTHORITY_INVALID",
                chain_tail_generation_error
                or "current chain-tail generation is unavailable",
            )
        suffixes = _expected_owner_suffixes(
            policy,
            mode,
            chain_tail_generation_id=chain_tail_generation_id,
        )
        allowed_owners = {prefix + suffix for suffix in suffixes}
        if binding.owner_key not in allowed_owners:
            reject(
                "OWNER_NOT_ALLOWED",
                "owner is outside the closed producer policy",
            )

    if owner is None:
        reject("OWNER_MISSING", "owner work unit is unavailable")
    else:
        if binding is not None and owner.work_unit_key != binding.owner_key:
            reject("OWNER_KEY_MISMATCH", "work-unit key differs")
        if owner.execution_state != "OUTPUT_COMMITTED":
            reject(
                "OWNER_NOT_COMMITTED",
                f"owner execution={owner.execution_state or 'UNKNOWN'}",
            )
        if owner.semantic_status != "ACTIVE":
            reject(
                "OWNER_NOT_ACTIVE",
                f"owner semantic={owner.semantic_status or 'UNKNOWN'}",
            )
        if owner.run_id != run_id:
            reject("RUN_MISMATCH", "owner run differs")
        if not _DIGEST_RE.fullmatch(owner.contract_digest):
            reject(
                "CONTRACT_DIGEST_INVALID",
                "owner contract digest is malformed",
            )
        if (
            binding is not None
            and binding.contract_digest != owner.contract_digest
        ):
            reject(
                "CONTRACT_DIGEST_MISMATCH",
                "binding and owner contract digests differ",
            )
        artifact_record = owner.artifact
        if artifact_record is None:
            reject(
                "OWNER_ARTIFACT_MISSING",
                "owner has no artifact record",
            )
        else:
            if artifact_record.identity != identity:
                reject("IDENTITY_MISMATCH", "owner artifact identity differs")
            if binding is not None and (
                artifact_record.owner_key != binding.owner_key
            ):
                reject("OWNER_KEY_MISMATCH", "owner artifact key differs")
            if artifact_record.status != "ACTIVE":
                reject(
                    "OWNER_ARTIFACT_NOT_ACTIVE",
                    "owner artifact is not ACTIVE",
                )
            if artifact_record.run_id != run_id:
                reject("RUN_MISMATCH", "owner artifact run differs")
            if artifact_record.sha256 != snapshot.sha256:
                reject("HASH_MISMATCH", "owner artifact hash differs")
            if artifact_record.size != snapshot.size:
                reject("SIZE_MISMATCH", "owner artifact size differs")
            if artifact_record.contract_digest != owner.contract_digest:
                reject(
                    "CONTRACT_DIGEST_MISMATCH",
                    "owner artifact contract digest differs",
                )

    if codes:
        return None, ContextIssue(
            artifact=snapshot.artifact,
            state=QUARANTINED_FOREIGN_STATE,
            codes=tuple(sorted(codes)),
            details=tuple(sorted(details)),
        )

    assert binding is not None
    assert owner is not None
    assert snapshot.content is not None
    return AcceptedContext(
        artifact=snapshot.artifact,
        owner_key=binding.owner_key,
        contract_digest=owner.contract_digest,
        sha256=snapshot.sha256,
        size=snapshot.size,
        consumers=tuple(sorted(policy.consumers)),
        content=snapshot.content,
    ), None


def _pair_issue(
    pair_id: str,
    code: str,
    members: Iterable[str],
) -> ContextIssue:
    member_tuple = tuple(sorted(set(members)))
    return ContextIssue(
        artifact=pair_id,
        state=QUARANTINED_FOREIGN_STATE,
        codes=(code,),
        details=("members=" + ",".join(member_tuple),),
    )


def select_verify_queue_context(
    snapshot: VerifyQueueContextSnapshot,
    *,
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
    run_id: str,
) -> VerifyQueueContextSelection:
    """Select a closed, immutable optional-context subset from one snapshot."""

    pipeline_n = _normalize_dimension(
        pipeline, label="pipeline", allowed=SUPPORTED_PIPELINES
    )
    mode_n = _normalize_dimension(
        mode, label="mode", allowed=SUPPORTED_MODES
    )
    ecosystem_n = _normalize_dimension(ecosystem, label="ecosystem")
    backend_n = _normalize_dimension(
        backend, label="backend", allowed=SUPPORTED_BACKENDS
    )
    run_id_n = str(run_id or "").strip()
    if not run_id_n:
        raise ValueError("context run_id is required")

    accepted_by_name: dict[str, AcceptedContext] = {}
    issues: list[ContextIssue] = []
    not_applicable: list[str] = []

    for artifact_name in KNOWN_ARTIFACTS:
        artifact = snapshot.artifact(artifact_name)
        if not artifact.present:
            continue
        if (
            pipeline_n != "sc"
            and artifact_name in _SC_ONLY_ARTIFACTS
        ):
            not_applicable.append(artifact_name)
            continue
        policy = _POLICY_BY_ARTIFACT.get(artifact_name)
        if policy is None:
            issues.append(ContextIssue(
                artifact=artifact_name,
                state=QUARANTINED_FOREIGN_STATE,
                codes=("POLICY_EXCLUDED",),
                details=("no production consumer policy exists",),
            ))
            continue
        if (
            pipeline_n not in policy.pipelines
            or mode_n not in policy.modes
        ):
            not_applicable.append(artifact_name)
            continue
        accepted, issue = _validate_artifact(
            artifact,
            policy,
            pipeline=pipeline_n,
            mode=mode_n,
            ecosystem=ecosystem_n,
            backend=backend_n,
            run_id=run_id_n,
            chain_tail_generation_id=(
                snapshot.chain_tail_generation_id
            ),
            chain_tail_generation_error=(
                snapshot.chain_tail_generation_error
            ),
        )
        if accepted is not None:
            accepted_by_name[artifact_name] = accepted
        if issue is not None:
            issues.append(issue)

    for pair_id, members in sorted(_PAIR_MEMBERS.items()):
        policies = tuple(_POLICY_BY_ARTIFACT[name] for name in members)
        applicable = all(
            pipeline_n in policy.pipelines and mode_n in policy.modes
            for policy in policies
        )
        if not applicable:
            continue
        present = tuple(
            name for name in members if snapshot.artifact(name).present
        )
        if not present:
            continue
        if len(present) != len(members):
            for name in members:
                accepted_by_name.pop(name, None)
            issues.append(_pair_issue(
                pair_id, "PAIR_INCOMPLETE", members
            ))
            continue
        accepted_members = [
            accepted_by_name.get(name) for name in members
        ]
        if any(item is None for item in accepted_members):
            for name in members:
                accepted_by_name.pop(name, None)
            issues.append(_pair_issue(
                pair_id, "PAIR_MEMBER_INVALID", members
            ))
            continue
        pair_owners = {
            (
                item.owner_key,
                item.contract_digest,
            )
            for item in accepted_members
            if item is not None
        }
        if len(pair_owners) != 1:
            for name in members:
                accepted_by_name.pop(name, None)
            issues.append(_pair_issue(
                pair_id, "PAIR_OWNER_MISMATCH", members
            ))

    accepted_tuple = tuple(
        accepted_by_name[name] for name in sorted(accepted_by_name)
    )
    issues_tuple = tuple(sorted(
        issues,
        key=lambda issue: (
            issue.artifact, issue.codes, issue.details
        ),
    ))
    not_applicable_tuple = tuple(sorted(set(not_applicable)))
    state = (
        COMPLETED_WITH_DEBT_SAFE_BASE
        if issues_tuple
        else COMMITTED_APPLIED
        if accepted_tuple
        else COMMITTED_CLEAN_NOOP
    )
    selection_core = {
        "pipeline": pipeline_n,
        "mode": mode_n,
        "ecosystem": ecosystem_n,
        "backend": backend_n,
        "run_id": run_id_n,
        "state": state,
        "snapshot_digest": snapshot.snapshot_digest,
        "accepted": [
            {
                "artifact": item.artifact,
                "owner_key": item.owner_key,
                "contract_digest": item.contract_digest,
                "sha256": item.sha256,
                "size": item.size,
                "consumers": list(item.consumers),
            }
            for item in accepted_tuple
        ],
        "issues": [
            {
                "artifact": issue.artifact,
                "state": issue.state,
                "codes": list(issue.codes),
                "details": list(issue.details),
            }
            for issue in issues_tuple
        ],
        "not_applicable": list(not_applicable_tuple),
        "safe_base_routing": True,
        "proof_authority": "NONE",
    }
    return VerifyQueueContextSelection(
        pipeline=pipeline_n,
        mode=mode_n,
        ecosystem=ecosystem_n,
        backend=backend_n,
        run_id=run_id_n,
        state=state,
        accepted=accepted_tuple,
        issues=issues_tuple,
        not_applicable_paths=not_applicable_tuple,
        snapshot_digest=snapshot.snapshot_digest,
        selection_digest=_sha256(_canonical_json_bytes(selection_core)),
    )


def build_verify_queue_context_status(
    selection: VerifyQueueContextSelection,
) -> dict[str, Any]:
    """Return one deterministic always-present status payload."""

    if selection.state not in CONTEXT_STATES:
        raise ValueError(f"unsupported context state: {selection.state!r}")
    payload: dict[str, Any] = {
        "schema_version": "plamen.verify_queue_context_input_status.v1",
        "pipeline": selection.pipeline,
        "mode": selection.mode,
        "ecosystem": selection.ecosystem,
        "backend": selection.backend,
        "run_id": selection.run_id,
        "state": selection.state,
        "safe_to_consume": True,
        "safe_base_routing": selection.safe_base_routing,
        "proof_authority": selection.proof_authority,
        "snapshot_digest": selection.snapshot_digest,
        "selection_digest": selection.selection_digest,
        "accepted_artifacts": [
            {
                "artifact": item.artifact,
                "owner_key": item.owner_key,
                "contract_digest": item.contract_digest,
                "sha256": item.sha256,
                "size": item.size,
                "consumers": list(item.consumers),
            }
            for item in selection.accepted
        ],
        "consumer_bindings": {
            consumer: list(selection.accepted_paths_for(consumer))
            for consumer in CONSUMERS
        },
        "omitted_artifacts": [
            {
                "artifact": issue.artifact,
                "state": issue.state,
                "codes": list(issue.codes),
                "details": list(issue.details),
            }
            for issue in selection.issues
        ],
        "not_applicable_artifacts": list(
            selection.not_applicable_paths
        ),
    }
    payload["receipt_digest"] = _sha256(_canonical_json_bytes(payload))
    return payload


__all__ = [
    "APPLICATION_SKEPTIC",
    "CANDIDATE_NEGATIVE_SKEPTIC",
    "CHAIN_ANTI_ABSORPTION_RECEIPT",
    "CHAIN_COMPOSITION_CANDIDATES",
    "CHAIN_EQUIVALENCE_PROPOSALS",
    "CHAIN_GROUPING_RELATIONS",
    "CHAIN_HYPOTHESES",
    "COMMITTED_APPLIED",
    "COMMITTED_CLEAN_NOOP",
    "COMPLETED_WITH_DEBT_SAFE_BASE",
    "CONTEXT_STATES",
    "ContextArtifactSnapshot",
    "ContextIssue",
    "FINDING_MAPPING",
    "HYPOTHESES",
    "KNOWN_ARTIFACTS",
    "PREPARED_NOT_CONSUMABLE",
    "QUARANTINED_FOREIGN_STATE",
    "VerifyQueueContextSelection",
    "VerifyQueueContextSnapshot",
    "build_verify_queue_context_status",
    "capture_verify_queue_context_snapshot",
    "select_verify_queue_context",
]
