"""RED contracts for moving L1 semantic dedup ahead of queue publication.

The live L1 order currently publishes the complete T0--T9 verification queue
and only then runs ``semantic_dedup``.  Its post-processor rewrites
``verification_queue.md``, the typed work-item sidecar, and verifier shards.
That makes the object called a committed T9 publication mutable.

These fixtures specify the smaller and safer boundary:

* the L1 dedup MODEL proposes against ``findings_inventory.md`` before T0;
* a DRIVER transaction applies the proposal to the inventory under the
  existing field-complete semantic-dedup authority;
* the later queue transaction is the sole writer of every public queue
  artifact;
* every input candidate is either still active or is an authenticated alias
  of one active survivor; and
* replay is byte-idempotent and never compounds preserved-member cards.

No production code is changed by this file.  The callable and PhaseIO contract
named below are deliberately absent at fixture introduction time.
"""
from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path
from typing import Any, Callable, Mapping

import pytest

import plamen_driver as DRIVER
from artifact_ledger import (
    arm_semantic_mutation,
    finalize_semantic_mutation,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    recover_armed_semantic_mutations,
    semantic_mutation_events,
)
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
    resolve_phase_io_contract,
)
from plamen_types import Checkpoint, L1_PHASES
from preverify_frozen_projection import (
    derive_preverify_finding_records_bytes,
)
import semantic_dedup_authority as AUTHORITY


RUN_ID = "3a021614-193f-4af7-bb7c-887907dc6f25"
APPLY_WORK_UNIT = "prequeue_apply"
NOOP_PROPOSAL_WORK_UNIT = "noop_proposal"
TRANSACTION_ROOT = "_sdt"
NOOP_INPUT_NAMES = (
    "findings_inventory.md",
    "dedup_blocks.md",
    "dedup_candidate_pairs.md",
    "dedup_candidate_pairs_full.md",
)
PAIR_CANDIDATE_WORK_UNIT = "dedup_pair_candidates"
PAIR_PACKET_OUTPUT_NAMES = (
    "dedup_blocks.md",
    "dedup_candidate_pairs.md",
    "dedup_candidate_pairs_full.md",
    "dedup_focus_inventory.md",
)
PUBLIC_QUEUE_NAMES = {
    "verification_queue.md",
    "verification_queue.json",
    "verification_queue.work_items.json",
    "verification_queue.work_plan.json",
    "verification_context_packets.json",
}
ROOT_OUTPUT_NAMES = (
    "findings_inventory.md",
    "finding_records.json",
    AUTHORITY.PRIMARY_RECEIPT_NAME,
    "dedup_absorbed_map.md",
    "findings_inventory_deduped.md",
)

CRASH_BOUNDARIES = (
    "AFTER_INPUTS_VALIDATED",
    "AFTER_PHASEIO_ARM",
    "AFTER_GENERATION_DURABLE",
    "AFTER_PENDING_STAGED_DURABLE",
    "AFTER_MUTATION_ARM",
    "AFTER_PENDING_ARMED_DURABLE",
    "AFTER_INVENTORY_REPLACED",
    "AFTER_RECORDS_REPLACED",
    "AFTER_APPLIED_RECEIPT_REPLACED",
    "AFTER_ABSORBED_MAP_REPLACED",
    "AFTER_DEDUPED_INVENTORY_REPLACED",
    "AFTER_PAIR_VERIFIED",
    "AFTER_PHASEIO_COMMIT",
    "AFTER_MUTATION_FINALIZE",
    "AFTER_RECEIPT_DURABLE",
    "AFTER_PENDING_CLEARED",
)


def _required_apply() -> Callable[..., Mapping[str, Any]]:
    value = getattr(
        DRIVER,
        "_run_l1_prequeue_semantic_dedup_transaction",
        None,
    )
    assert callable(value), (
        "L1 prequeue semantic-dedup apply transaction is absent; do not "
        "reorder phases until the receipt-authorized inventory transaction "
        "exists"
    )
    return value


def _required_noop_proposal() -> Callable[..., Mapping[str, Any]]:
    value = getattr(
        DRIVER,
        "_run_l1_semantic_dedup_noop_proposal",
        None,
    )
    assert callable(value), (
        "L1 semantic-dedup no-signal/budget exits still lack a typed DRIVER "
        "proposal boundary; they must not publish an unowned PASSTHROUGH or "
        "skip the five-output prequeue transaction"
    )
    return value


def test_generic_semantic_recovery_never_finalizes_one_half_of_paired_apply(
    tmp_path: Path,
) -> None:
    """The semantic-dedup transaction, not generic recovery, owns both events."""

    project = tmp_path / "project"
    scratchpad, config = _seed(project)

    def crash(label: str) -> None:
        if label == "AFTER_PENDING_ARMED_DURABLE":
            raise RuntimeError("fixture-crash")

    with pytest.raises(RuntimeError, match="fixture-crash"):
        _required_apply()(
            scratchpad=scratchpad,
            project_root=project,
            config=config,
            run_id=RUN_ID,
            fault_hook=crash,
        )

    armed_before = [
        row
        for row in semantic_mutation_events(scratchpad)
        if str(row.get("mutation_kind") or "").startswith(
            "SEMANTIC_DEDUP_TRANSACTION_"
        )
    ]
    assert len(armed_before) == 2
    assert {row["status"] for row in armed_before} == {"ARMED"}

    assert recover_armed_semantic_mutations(
        scratchpad,
        project,
        run_id=RUN_ID,
    ) == []
    armed_after = [
        row
        for row in semantic_mutation_events(scratchpad)
        if str(row.get("mutation_kind") or "").startswith(
            "SEMANTIC_DEDUP_TRANSACTION_"
        )
    ]
    assert armed_after == armed_before

    recovered = _required_apply()(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )
    assert recovered["safe_to_consume"] is True


def _finding(
    finding_id: str,
    *,
    title: str,
    location: str,
    source_ids: str,
    root_cause: str,
    impact: str,
) -> str:
    return (
        f"### Finding [{finding_id}]: {title}\n"
        "**Severity**: High\n"
        f"**Location**: {location}\n"
        f"**Source IDs**: {source_ids}\n"
        f"**Root Cause**: {root_cause}\n"
        "**Description**: The state transition admits the described invalid "
        "state and carries it into a later security decision.\n"
        "**Preconditions**: An untrusted input reaches the transition.\n"
        f"**Impact**: {impact}\n"
        "**Recommendation**: Enforce the invariant at every entry path.\n"
        "**External Premises**: No best-case external behavior is assumed.\n"
        "**Evidence Scope**: The named transition and its direct consumers.\n"
        "[CODE-TRACE]\n\n"
    )


def _inventory() -> str:
    # INV-001 is a real superset of INV-002.  INV-003 is deliberately
    # independent and must remain active.
    return (
        "# Findings Inventory\n\n"
        + _finding(
            "INV-001",
            title="Complete transition invariant omission",
            location="consensus/state.rs:10-50",
            source_ids="B-1, B-2",
            root_cause="Both boundary paths omit the same transition guard.",
            impact="The invalid state can affect consensus safety.",
        )
        + _finding(
            "INV-002",
            title="Boundary variant of transition invariant omission",
            location="consensus/state.rs:20-25",
            source_ids="B-2",
            root_cause="The boundary path omits the same transition guard.",
            impact="The boundary variant reaches the same invalid state.",
        )
        + _finding(
            "INV-003",
            title="Independent authentication-state defect",
            location="network/auth.rs:70-82",
            source_ids="N-7",
            root_cause="Authentication state is committed before validation.",
            impact="An unauthenticated peer can enter the trusted peer set.",
        )
    )


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_json(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _claim_current_run_outputs(
    *,
    scratchpad: Path,
    project: Path,
    phase: str,
    work_unit_id: str,
    outputs: Mapping[str, bytes],
    writer: str,
    model_invoked: bool,
    consumers: tuple[str, ...],
) -> str:
    """Register fixture bytes through the real current-run ledger boundary."""

    owner = canonical_work_unit_key(
        "l1",
        "thorough",
        "rust",
        "claude",
        phase,
        work_unit_id,
    )
    contract = PhaseIOContract(
        pipeline="l1",
        mode="thorough",
        ecosystem="rust",
        backend="claude",
        phase=phase,
        work_unit_id=work_unit_id,
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=name,
                owner_key=owner,
                artifact_class=(
                    "REQUIRED" if writer == "MODEL" else "DRIVER_GENERATED"
                ),
                writer=writer,
                write_mode="CREATE",
                schema_version=(
                    "plamen.finding_records.v2"
                    if name == "finding_records.json"
                    else "unstructured.v1"
                ),
                minimum_gate="FIXTURE_EXACT_CURRENT_RUN_PRODUCER",
                consumers=consumers,
            )
            for name in outputs
        ),
        immutable_inputs=(),
        bounded_lookup_inputs=(),
        model_invoked=model_invoked,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline="l1",
        mode="thorough",
        ecosystem="rust",
        backend="claude",
        model="fixture-model" if model_invoked else "driver",
        timeout_s=60,
        exec_mode="pty" if model_invoked else "python",
        tool_policy=("filesystem",) if model_invoked else (),
    )
    assert all(not (scratchpad / name).exists() for name in outputs)
    armed = record_work_unit_inputs(
        scratchpad,
        project,
        contract,
        launch,
        run_id=RUN_ID,
    )
    assert armed["semantic_status"] == "INPUTS_BOUND"
    for name, raw in outputs.items():
        target = scratchpad / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(bytes(raw))
    committed = record_work_unit_artifacts(
        scratchpad,
        project,
        contract,
        launch,
        run_id=RUN_ID,
        actor=writer,
    )
    assert committed["semantic_status"] == "ACTIVE"
    return owner


def _advance_pair_through_semantic_mutation(
    *,
    scratchpad: Path,
    project: Path,
) -> None:
    """Make the canonical pair mutation-current without self-reblessing it."""

    inventory_event = arm_semantic_mutation(
        scratchpad,
        project,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="FIXTURE_AUTHORIZED_INVENTORY_ADVANCE",
        run_id=RUN_ID,
    )
    records_event = arm_semantic_mutation(
        scratchpad,
        project,
        artifact_identity="scratchpad:finding_records.json",
        mutation_kind="FIXTURE_AUTHORIZED_RECORDS_ADVANCE",
        run_id=RUN_ID,
    )
    inventory_raw = (
        (scratchpad / "findings_inventory.md").read_bytes()
        + b"\n<!-- fixture-authorized-current-generation -->\n"
    )
    records_raw = derive_preverify_finding_records_bytes(inventory_raw)
    (scratchpad / "findings_inventory.md").write_bytes(inventory_raw)
    (scratchpad / "finding_records.json").write_bytes(records_raw)
    finalize_semantic_mutation(
        scratchpad,
        project,
        str(inventory_event["event_id"]),
        run_id=RUN_ID,
        affected_record_ids=("INV-001", "INV-002", "INV-003"),
    )
    finalize_semantic_mutation(
        scratchpad,
        project,
        str(records_event["event_id"]),
        run_id=RUN_ID,
        affected_record_ids=("INV-001", "INV-002", "INV-003"),
    )


def _seed(
    project: Path,
    *,
    merge: bool = True,
    mutation_current: bool = False,
) -> tuple[Path, dict[str, Any]]:
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    inventory_raw = _inventory().encode("utf-8")
    records_raw = derive_preverify_finding_records_bytes(inventory_raw)
    id_ledger_raw = (
        json.dumps(
            {
                "schema_version": "plamen.id_ledger.v1",
                "allocations": [],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    decision = (
        "MERGE: INV-001, INV-002\tsame mechanism and repair\n"
        "KEEP: INV-003\n"
        if merge
        else "KEEP: INV-001\nKEEP: INV-002\nKEEP: INV-003\n"
    )
    decision_raw = (
        "# Semantic Dedup Decisions\n\n" + decision
    ).encode("utf-8")
    _claim_current_run_outputs(
        scratchpad=scratchpad,
        project=project,
        phase="inventory",
        # Use the real resolver-registered handoff identity. The fixture owns
        # only the two semantic roots needed by this focused successor test.
        work_unit_id="canonical_aggregate",
        outputs={
            "findings_inventory.md": inventory_raw,
            "finding_records.json": records_raw,
            "_id_ledger.json": id_ledger_raw,
        },
        writer="DRIVER",
        model_invoked=False,
        consumers=("semantic_dedup/prequeue_apply",),
    )
    if mutation_current:
        _advance_pair_through_semantic_mutation(
            scratchpad=scratchpad,
            project=project,
        )
    _claim_current_run_outputs(
        scratchpad=scratchpad,
        project=project,
        phase="semantic_dedup",
        work_unit_id="worker.semantic_dedup",
        outputs={"dedup_decisions.md": decision_raw},
        writer="MODEL",
        model_invoked=True,
        consumers=("semantic_dedup/prequeue_apply",),
    )
    config = {
        "pipeline": "l1",
        "mode": "thorough",
        "language": "rust",
        "ecosystem": "rust",
        "backend": "claude",
        "cli_backend": "claude",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": RUN_ID,
    }
    return scratchpad, config


def _passthrough_decision(reason: str) -> bytes:
    return (
        "# Semantic Dedup Decisions\n\n"
        "**Status**: PASSTHROUGH\n\n"
        f"**Reason**: {reason}.\n\n"
        "No semantic merge decision was applied. Every upstream finding "
        "remains active.\n"
    ).encode("utf-8")


def _empty_candidate_pairs() -> bytes:
    return (
        "# Dedup Candidate Pairs\n\n"
        "| Finding A | Finding B | Title Score | Signal | Same Sev? |\n"
        "|---|---|---|---|---|\n"
    ).encode("utf-8")


def _live_candidate_pairs() -> bytes:
    return (
        "# Dedup Candidate Pairs\n\n"
        "| Finding A | Finding B | Title Score | Signal | Same Sev? |\n"
        "|---|---|---|---|---|\n"
        "| INV-001 | INV-002 | 0.91 | same root/fix candidate | yes |\n"
    ).encode("utf-8")


def _seed_bounded_dedup_denominator(
    project: Path,
    *,
    oversized_blocks: bool = False,
    live_pair: bool = False,
) -> tuple[Path, dict[str, Any], dict[str, bytes]]:
    """Register the exact current bounded packet without a proposal output."""

    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    inventory_raw = _inventory().encode("utf-8")
    records_raw = derive_preverify_finding_records_bytes(inventory_raw)
    blocks_raw = (
        (
            "# Dedup Candidate Blocks\n\n## Block 1\n\n"
            + ("bounded-fixture-token " * 12000)
        ).encode("utf-8")
        if oversized_blocks
        else b"# Dedup Candidate Blocks\n\nNo candidate blocks.\n"
    )
    pairs_raw = (
        _live_candidate_pairs() if live_pair else _empty_candidate_pairs()
    )
    focus_raw = inventory_raw
    _claim_current_run_outputs(
        scratchpad=scratchpad,
        project=project,
        phase="inventory",
        work_unit_id="canonical_aggregate",
        outputs={
            "findings_inventory.md": inventory_raw,
            "finding_records.json": records_raw,
        },
        writer="DRIVER",
        model_invoked=False,
        consumers=(
            "semantic_dedup/noop_proposal",
            "semantic_dedup/model",
            "semantic_dedup/supplemental_proposals",
            "semantic_dedup/prequeue_apply",
        ),
    )
    _claim_current_run_outputs(
        scratchpad=scratchpad,
        project=project,
        phase="semantic_dedup",
        work_unit_id="dedup_pair_candidates",
        outputs={
            "dedup_blocks.md": blocks_raw,
            "dedup_candidate_pairs.md": pairs_raw,
            "dedup_candidate_pairs_full.md": pairs_raw,
            "dedup_focus_inventory.md": focus_raw,
        },
        writer="DRIVER",
        model_invoked=False,
        consumers=(
            "semantic_dedup/noop_proposal",
            "semantic_dedup/model",
            "semantic_dedup/supplemental_proposals",
        ),
    )
    config = {
        "pipeline": "l1",
        "mode": "thorough",
        "language": "rust",
        "ecosystem": "rust",
        "backend": "claude",
        "cli_backend": "claude",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": RUN_ID,
    }
    sources = {
        "findings_inventory.md": inventory_raw,
        "dedup_blocks.md": blocks_raw,
        "dedup_candidate_pairs.md": pairs_raw,
        "dedup_candidate_pairs_full.md": pairs_raw,
        "dedup_focus_inventory.md": focus_raw,
    }
    return scratchpad, config, sources


def _seed_candidate_prep_inventory(
    project: Path,
) -> tuple[Path, dict[str, Any], Checkpoint, bytes]:
    """Seed only the current receipt-authorized canonical inventory pair."""

    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    inventory_raw = _inventory().encode("utf-8")
    records_raw = derive_preverify_finding_records_bytes(inventory_raw)
    _claim_current_run_outputs(
        scratchpad=scratchpad,
        project=project,
        phase="inventory",
        work_unit_id="canonical_aggregate",
        outputs={
            "findings_inventory.md": inventory_raw,
            "finding_records.json": records_raw,
        },
        writer="DRIVER",
        model_invoked=False,
        consumers=(
            "semantic_dedup/dedup_pair_candidates",
            "semantic_dedup/prequeue_apply",
        ),
    )
    config = {
        "pipeline": "l1",
        "mode": "thorough",
        "language": "rust",
        "ecosystem": "rust",
        "backend": "claude",
        "cli_backend": "claude",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": RUN_ID,
    }
    return scratchpad, config, Checkpoint(run_id=RUN_ID), inventory_raw


def _isolate_candidate_prep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep the live prep boundary but neutralize unrelated additive feeders."""

    monkeypatch.setattr(
        DRIVER,
        "_promote_findings_with_semantic_invalidation",
        lambda *args, **kwargs: [],
    )
    monkeypatch.setattr(
        DRIVER,
        "_promote_cross_domain_with_semantic_invalidation",
        lambda *args, **kwargs: [],
    )
    monkeypatch.setattr(
        DRIVER,
        "_run_gate_p_with_semantic_invalidation",
        lambda *args, **kwargs: {},
    )
    monkeypatch.setattr(
        DRIVER,
        "_validate_registered_finding_delivery_receipt",
        lambda *args, **kwargs: [],
    )
    monkeypatch.setattr(
        DRIVER,
        "_validate_depth_promotion_dedup",
        lambda *args, **kwargs: [],
    )


def _pair_candidate_key() -> str:
    return canonical_work_unit_key(
        "l1",
        "thorough",
        "rust",
        "claude",
        "semantic_dedup",
        PAIR_CANDIDATE_WORK_UNIT,
    )


def _pair_packet_snapshot(scratchpad: Path) -> dict[str, bytes]:
    return {
        name: (scratchpad / name).read_bytes()
        for name in PAIR_PACKET_OUTPUT_NAMES
    }


def _claim_model_dedup_decisions(
    *,
    scratchpad: Path,
    project: Path,
) -> str:
    return _claim_current_run_outputs(
        scratchpad=scratchpad,
        project=project,
        phase="semantic_dedup",
        work_unit_id="worker.semantic_dedup",
        outputs={
            "dedup_decisions.md": (
                "# Semantic Dedup Decisions\n\n"
                "MERGE: INV-001, INV-002\tsame mechanism and repair\n"
                "KEEP: INV-003\n"
            ).encode("utf-8"),
        },
        writer="MODEL",
        model_invoked=True,
        consumers=(
            "semantic_dedup/supplemental_proposals",
            "semantic_dedup/prequeue_apply",
        ),
    )


def _claim_driver_passthrough_scaffold(
    *,
    scratchpad: Path,
    project: Path,
    reason: str,
) -> str:
    """Publish the scaffold through the registered noop proposal contract."""

    contract = resolve_phase_io_contract(
        pipeline="l1",
        mode="thorough",
        ecosystem="rust",
        backend="claude",
        phase="semantic_dedup",
        work_unit_id=NOOP_PROPOSAL_WORK_UNIT,
        exact_inputs=NOOP_INPUT_NAMES,
        exact_outputs=("dedup_decisions.md",),
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=60,
        exec_mode="python",
        tool_policy=(),
    )
    bound = record_work_unit_inputs(
        scratchpad,
        project,
        contract,
        launch,
        run_id=RUN_ID,
    )
    assert bound["semantic_status"] == "INPUTS_BOUND"
    (scratchpad / "dedup_decisions.md").write_bytes(
        _passthrough_decision(reason)
    )
    committed = record_work_unit_artifacts(
        scratchpad,
        project,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )
    assert committed["semantic_status"] == "ACTIVE"
    return contract.key


def _semantic_public_snapshot(scratchpad: Path) -> dict[str, bytes]:
    return {
        name: (scratchpad / name).read_bytes()
        for name in ("dedup_decisions.md", *ROOT_OUTPUT_NAMES)
    }


def _run(
    project: Path,
    *,
    merge: bool = True,
    mutation_current: bool = False,
    fault_hook: Callable[[str], None] | None = None,
) -> tuple[Path, Mapping[str, Any]]:
    scratchpad, config = _seed(
        project,
        merge=merge,
        mutation_current=mutation_current,
    )
    result = _required_apply()(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
        fault_hook=fault_hook,
    )
    assert isinstance(result, Mapping)
    assert result.get("state") in {
        "COMMITTED",
        "OUTPUT_COMMITTED",
        "ALREADY_COMMITTED",
    }
    assert result.get("safe_to_consume") is True
    return scratchpad, result


def test_depth_promotion_advances_inventory_and_records_as_one_semantic_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A late additive inventory mutation cannot strand its JSON projection."""

    project = tmp_path / "project"
    project.mkdir()
    scratchpad, config = _seed(project, merge=False)
    checkpoint = Checkpoint(run_id=RUN_ID)

    def _append_one(root: Path, min_confidence: float = 0.70) -> list[str]:
        del min_confidence
        inventory = Path(root) / "findings_inventory.md"
        inventory.write_bytes(
            inventory.read_bytes()
            + (
                "\n### Finding [INV-004]: Late promoted candidate\n"
                "**Source IDs**: [DA-PAIR-001]\n"
                "**Severity**: Medium\n"
                "**Location**: src/late.rs:40\n"
                "**Preferred Tag**: [STATE]\n"
                "**Description**: A fixture candidate promoted after the "
                "canonical inventory projection was committed.\n"
            ).encode("utf-8")
        )
        ledger = Path(root) / "_id_ledger.json"
        payload = json.loads(ledger.read_text(encoding="utf-8"))
        payload["allocations"].append(
            {
                "id": "INV-004",
                "prefix": "INV-",
                "owner_phase": "depth_promotion",
                "owner_attempt": 1,
                "owning_artifact": "findings_inventory.md",
                "title_hash": "sha256:" + ("4" * 64),
                "title_preview": "Late promoted candidate",
                "allocated_at": "1970-01-01T00:00:00+00:00",
            }
        )
        ledger.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        return ["DA-PAIR-001"]

    monkeypatch.setattr(
        DRIVER, "_promote_depth_findings_to_inventory", _append_one
    )
    promoted = DRIVER._promote_findings_with_semantic_invalidation(
        scratchpad,
        config,
        checkpoint,
        owner_phase="semantic_dedup",
    )
    assert promoted == ["DA-PAIR-001"]

    inventory_raw = (scratchpad / "findings_inventory.md").read_bytes()
    assert (scratchpad / "finding_records.json").read_bytes() == (
        derive_preverify_finding_records_bytes(inventory_raw)
    )
    pair_events = {
        str(row.get("artifact_identity") or ""): row
        for row in semantic_mutation_events(scratchpad)
        if str(row.get("mutation_kind") or "").startswith(
            "FINDING_PROMOTION"
        )
    }
    assert set(pair_events) == {
        "scratchpad:findings_inventory.md",
        "scratchpad:finding_records.json",
        "scratchpad:_id_ledger.json",
    }
    assert all(
        row.get("status") in {
            "INVALIDATION_APPLIED",
            "NO_CHANGE",
        }
        for row in pair_events.values()
    )

    # The real consumer must now accept the pair as a registered semantic
    # successor.  This is the exact boundary that the L1 smoke run reached.
    result = _required_apply()(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )
    assert result.get("safe_to_consume") is True


def test_gate_p_advances_inventory_and_records_as_one_semantic_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The final additive harvester cannot rewrite records outside authority."""

    project = tmp_path / "project"
    project.mkdir()
    scratchpad, config = _seed(project, merge=False)
    checkpoint = Checkpoint(run_id=RUN_ID)

    def _append_gate_p(
        root: Path, *, owner_phase: str = "semantic_dedup"
    ) -> dict[str, int]:
        del owner_phase
        inventory = Path(root) / "findings_inventory.md"
        inventory_raw = (
            inventory.read_bytes()
            + (
                "\n### Finding [INV-004]: Gate P recovered candidate\n"
                "**Source IDs**: [PROMOGAP-PAIR-001]\n"
                "**Severity**: Medium\n"
                "**Location**: src/gate.rs:44\n"
                "**Preferred Tag**: [CODE-TRACE]\n"
                "**Verdict**: NEEDS_VERIFICATION\n"
                "**Description**: Fixture additive recovery.\n"
            ).encode("utf-8")
        )
        inventory.write_bytes(inventory_raw)
        (Path(root) / "finding_records.json").write_bytes(
            derive_preverify_finding_records_bytes(inventory_raw)
        )
        ledger = Path(root) / "_id_ledger.json"
        payload = json.loads(ledger.read_text(encoding="utf-8"))
        payload["allocations"].append(
            {
                "id": "INV-004",
                "prefix": "INV-",
                "owner_phase": "promotion_gate",
                "owner_attempt": 1,
                "owning_artifact": "findings_inventory.md",
                "title_hash": "sha256:" + ("5" * 64),
                "title_preview": "Gate P recovered candidate",
                "allocated_at": "1970-01-01T00:00:00+00:00",
            }
        )
        ledger.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        return {
            "harvested": 1,
            "body_candidates": 1,
            "appendix_c": 0,
            "appendix_a": 0,
            "emitted_to_inventory": 1,
        }

    monkeypatch.setattr(
        DRIVER, "_run_gate_p_before_verify_queue", _append_gate_p
    )
    result = DRIVER._run_gate_p_with_semantic_invalidation(
        scratchpad,
        config,
        checkpoint,
        owner_phase="semantic_dedup",
    )
    assert result["emitted_to_inventory"] == 1

    inventory_raw = (scratchpad / "findings_inventory.md").read_bytes()
    assert (scratchpad / "finding_records.json").read_bytes() == (
        derive_preverify_finding_records_bytes(inventory_raw)
    )
    pair_events = {
        str(row.get("artifact_identity") or ""): row
        for row in semantic_mutation_events(scratchpad)
        if str(row.get("mutation_kind") or "").startswith(
            "GATE_P_ADDITIVE_PROMOTION"
        )
    }
    assert set(pair_events) == {
        "scratchpad:findings_inventory.md",
        "scratchpad:finding_records.json",
        "scratchpad:_id_ledger.json",
    }

    applied = _required_apply()(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )
    assert applied.get("safe_to_consume") is True


def test_noop_replacement_refreshes_stale_supplemental_proposal(
    tmp_path: Path,
) -> None:
    """A fallback decision must refresh its deterministic decision consumer."""

    project = tmp_path / "project"
    scratchpad, config, _ = _seed_bounded_dedup_denominator(
        project,
        live_pair=True,
    )
    phase = next(item for item in L1_PHASES if item.name == "semantic_dedup")
    assert DRIVER._bind_typed_model_phase_inputs(
        phase, scratchpad, config
    ) == []
    model_raw = (
        "# Semantic Dedup Decisions\n\n"
        "MERGE: INV-001, INV-002\tsame mechanism and repair\n"
        "KEEP: INV-003\n"
    ).encode("utf-8")
    (scratchpad / "dedup_decisions.md").write_bytes(model_raw)
    assert DRIVER._record_typed_model_phase_artifacts(
        phase, scratchpad, config
    ) == []

    first = DRIVER._run_l1_supplemental_dedup_proposal_phase(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )
    assert first["state"] in {"ACTIVE", "DEGRADED_PRIMARY_ONLY"}
    first_raw = (
        scratchpad / "semantic_dedup_supplemental_proposals.json"
    ).read_bytes()

    decision_event = arm_semantic_mutation(
        scratchpad,
        project,
        artifact_identity="scratchpad:dedup_decisions.md",
        mutation_kind="FIXTURE_NOOP_DECISION_REPLACEMENT",
        run_id=RUN_ID,
    )
    (scratchpad / "dedup_decisions.md").write_bytes(
        _passthrough_decision("fixture validator failure")
    )
    finalize_semantic_mutation(
        scratchpad,
        project,
        str(decision_event["event_id"]),
        run_id=RUN_ID,
    )
    second = DRIVER._run_l1_supplemental_dedup_proposal_phase(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )
    assert second["state"] in {"ACTIVE", "DEGRADED_PRIMARY_ONLY"}
    second_raw = (
        scratchpad / "semantic_dedup_supplemental_proposals.json"
    ).read_bytes()
    assert second_raw != first_raw
    payload = json.loads(second_raw.decode("utf-8"))
    decisions_raw = (scratchpad / "dedup_decisions.md").read_bytes()
    assert payload["source_artifacts"]["dedup_decisions.md"] == {
        "sha256": hashlib.sha256(decisions_raw).hexdigest(),
        "size_bytes": len(decisions_raw),
    }


def test_noop_fallback_recovers_armed_apply_without_replacing_its_input(
    tmp_path: Path,
) -> None:
    """Once apply is armed, fallback must preserve its exact decision bytes."""

    project = tmp_path / "project"
    scratchpad, config, _ = _seed_bounded_dedup_denominator(
        project,
        live_pair=True,
    )
    phase = next(item for item in L1_PHASES if item.name == "semantic_dedup")
    assert DRIVER._bind_typed_model_phase_inputs(
        phase, scratchpad, config
    ) == []
    model_raw = (
        "# Semantic Dedup Decisions\n\n"
        "MERGE: INV-001, INV-002\tsame mechanism and repair\n"
        "KEEP: INV-003\n"
    ).encode("utf-8")
    (scratchpad / "dedup_decisions.md").write_bytes(model_raw)
    assert DRIVER._record_typed_model_phase_artifacts(
        phase, scratchpad, config
    ) == []

    def _stop_after_arm(point: str) -> None:
        if point == "AFTER_PHASEIO_ARM":
            raise RuntimeError("fixture stop after apply arm")

    with pytest.raises(RuntimeError, match="fixture stop after apply arm"):
        _required_apply()(
            scratchpad=scratchpad,
            project_root=project,
            config=config,
            run_id=RUN_ID,
            fault_hook=_stop_after_arm,
        )
    armed_decision = (scratchpad / "dedup_decisions.md").read_bytes()
    assert armed_decision == model_raw

    result = DRIVER._run_l1_semantic_dedup_noop_proposal(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
        reason="later validator requested a conservative fallback",
    )
    assert result.get("safe_to_consume") is True
    assert (scratchpad / "dedup_decisions.md").read_bytes() == armed_decision


def test_group_primary_receipt_uses_exact_cross_os_output_bytes() -> None:
    """Windows newline translation cannot invalidate the staged receipt."""

    inventory_raw = _inventory().encode("utf-8")
    decisions_raw = (
        "# Semantic Dedup Decisions\n\n"
        "### GROUP: INV-001 represents INV-001, INV-002\n"
        "- Pattern: related mechanism; keep both candidates\n"
    ).encode("utf-8")
    empty_pairs = _empty_candidate_pairs()
    proposal_raw = DRIVER._derive_l1_supplemental_dedup_proposals(
        inventory_raw=inventory_raw,
        decisions_raw=decisions_raw,
        candidate_pairs_raw=empty_pairs,
        candidate_pairs_full_raw=empty_pairs,
        run_id=RUN_ID,
    )
    (
        post_inventory,
        post_records,
        sidecars,
        aliases,
        _metadata,
    ) = DRIVER._derive_l1_semantic_dedup_postimages(
        inventory_raw=inventory_raw,
        decisions_raw=decisions_raw,
        supplemental_proposal_raw=proposal_raw,
        run_id=RUN_ID,
    )
    assert b"Dedup Group" in post_inventory
    assert post_records == derive_preverify_finding_records_bytes(
        post_inventory
    )
    assert aliases == {}
    assert sidecars["semantic_dedup_applied_receipt.json"]


def test_committed_apply_replay_does_not_recertify_consumed_model_output(
    tmp_path: Path,
) -> None:
    """Downstream trusts the frozen apply input, not a stale raw producer."""

    project = tmp_path / "project"
    scratchpad, config, _ = _seed_bounded_dedup_denominator(
        project,
        live_pair=True,
    )
    phase = next(item for item in L1_PHASES if item.name == "semantic_dedup")
    assert DRIVER._bind_typed_model_phase_inputs(
        phase, scratchpad, config
    ) == []
    (scratchpad / "dedup_decisions.md").write_bytes(
        (
            "# Semantic Dedup Decisions\n\n"
            "MERGE: INV-001, INV-002\tsame mechanism and repair\n"
            "KEEP: INV-003\n"
        ).encode("utf-8")
    )
    assert DRIVER._record_typed_model_phase_artifacts(
        phase, scratchpad, config
    ) == []
    applied = _required_apply()(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )
    assert applied.get("safe_to_consume") is True

    # Re-running raw MODEL attribution after its bounded packet was consumed
    # is invalid and may quarantine that historical producer.  It must not
    # revoke the already-committed transaction that froze those exact bytes.
    blocks = scratchpad / "dedup_blocks.md"
    blocks.write_bytes(blocks.read_bytes() + b"\npost-consumption drift\n")
    assert DRIVER._record_typed_model_phase_artifacts(
        phase, scratchpad, config
    )
    replay = DRIVER._ensure_l1_prequeue_successor_for_downstream(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
        downstream_phase="verify_queue",
        semantic_phase_completed=True,
    )
    assert replay.get("safe_to_consume") is True


def test_canonical_identity_projection_is_driver_owned_before_preverify(
    tmp_path: Path,
) -> None:
    """The final identity denominator cannot remain an unowned side effect."""

    project = tmp_path / "project"
    project.mkdir()
    scratchpad, config = _seed(project, merge=False)

    result = DRIVER._run_canonical_identity_projection_transaction(
        scratchpad=scratchpad,
        config=config,
        source_phase="semantic_dedup",
    )
    assert result.get("issues") == []
    assert result.get("safe_to_consume") is True
    ledger = read_artifact_ledger(scratchpad)
    for identity in (
        "scratchpad:_canonical_finding_ids.json",
        "scratchpad:_unmapped_id_tokens.json",
    ):
        binding = ledger["artifact_bindings"].get(identity)
        assert isinstance(binding, Mapping)
        assert binding.get("status") == "ACTIVE"
        assert binding.get("writer") == "DRIVER"
        assert str(binding.get("owner_key") or "").endswith(
            "/semantic_identity/projection.semantic_dedup"
        )


def test_canonical_identity_projection_refresh_has_registered_lineage(
    tmp_path: Path,
) -> None:
    """A later phase may refresh, but never anonymously replace, the map."""

    project = tmp_path / "project"
    project.mkdir()
    scratchpad, config = _seed(project, merge=False)

    first = DRIVER._run_canonical_identity_projection_transaction(
        scratchpad=scratchpad,
        config=config,
        source_phase="inventory_chunk_a",
    )
    assert first.get("safe_to_consume") is True
    assert first.get("issues") == []

    second = DRIVER._run_canonical_identity_projection_transaction(
        scratchpad=scratchpad,
        config=config,
        source_phase="semantic_dedup",
    )
    assert second.get("safe_to_consume") is True
    assert second.get("issues") == []
    ledger = read_artifact_ledger(scratchpad)
    for identity in (
        "scratchpad:_canonical_finding_ids.json",
        "scratchpad:_unmapped_id_tokens.json",
    ):
        binding = ledger["artifact_bindings"].get(identity)
        assert isinstance(binding, Mapping)
        assert binding.get("status") == "ACTIVE"
        assert str(binding.get("owner_key") or "").endswith(
            "/semantic_identity/projection.semantic_dedup"
        )


def test_canonical_identity_projection_refresh_accepts_exact_stale_handoff(
    tmp_path: Path,
) -> None:
    """A semantic invalidation may hand stale bytes to the next projection."""

    project = tmp_path / "project"
    project.mkdir()
    scratchpad, config = _seed(project, merge=False)
    first = DRIVER._run_canonical_identity_projection_transaction(
        scratchpad=scratchpad,
        config=config,
        source_phase="depth",
    )
    assert first.get("safe_to_consume") is True

    event = arm_semantic_mutation(
        scratchpad,
        project,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="FINDING_PROMOTION",
        run_id=RUN_ID,
    )
    with (scratchpad / "findings_inventory.md").open("ab") as stream:
        stream.write(
            b"\n### Finding [INV-999]: exact stale handoff\n"
            b"**Severity**: Low\n**Description**: regression\n"
        )
    finalized = finalize_semantic_mutation(
        scratchpad,
        project,
        str(event["event_id"]),
        run_id=RUN_ID,
        affected_record_ids=("INV-999",),
    )
    assert finalized["status"] == "INVALIDATION_APPLIED"
    stale = read_artifact_ledger(scratchpad)
    assert stale["artifact_bindings"][
        "scratchpad:_canonical_finding_ids.json"
    ]["status"] == "STALE_INPUT"

    second = DRIVER._run_canonical_identity_projection_transaction(
        scratchpad=scratchpad,
        config=config,
        source_phase="sc_semantic_dedup",
    )

    assert second.get("safe_to_consume") is True, second
    assert second.get("issues") == []
    ledger = read_artifact_ledger(scratchpad)
    for identity in (
        "scratchpad:_canonical_finding_ids.json",
        "scratchpad:_unmapped_id_tokens.json",
    ):
        binding = ledger["artifact_bindings"][identity]
        assert binding["status"] == "ACTIVE"
        assert str(binding["owner_key"]).endswith(
            "/semantic_identity/projection.sc_semantic_dedup"
        )


def _active_ids(scratchpad: Path) -> set[str]:
    text = (scratchpad / "findings_inventory.md").read_text(
        encoding="utf-8", errors="strict"
    )
    return set(AUTHORITY.extract_finding_records(text))


def _semantic_snapshot(scratchpad: Path) -> dict[str, bytes]:
    names = (
        "findings_inventory.md",
        "finding_records.json",
        "findings_inventory_deduped.md",
        AUTHORITY.PRIMARY_RECEIPT_NAME,
        "dedup_absorbed_map.md",
    )
    snapshot = {
        name: (scratchpad / name).read_bytes()
        for name in names
        if (scratchpad / name).is_file()
    }
    transaction_root = scratchpad / TRANSACTION_ROOT
    if transaction_root.is_dir():
        for path in sorted(transaction_root.rglob("*")):
            if path.is_file():
                snapshot[path.relative_to(scratchpad).as_posix()] = (
                    path.read_bytes()
                )
    return snapshot


def _transaction_generation(
    scratchpad: Path,
    result: Mapping[str, Any],
) -> tuple[Path, Mapping[str, Any]]:
    digest = str(result.get("generation_digest") or "")
    assert len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest)
    generation = scratchpad / TRANSACTION_ROOT / f"g_{digest}"
    assert generation.is_dir()
    manifest_raw = (generation / "i.json").read_bytes()
    manifest = json.loads(manifest_raw)
    assert manifest_raw == _canonical_json(manifest)
    return generation, manifest


def _staged_sidecars(
    generation: Path,
    manifest: Mapping[str, Any],
) -> dict[str, bytes]:
    rows = manifest.get("staged_sidecars")
    assert isinstance(rows, list)
    result: dict[str, bytes] = {}
    for row in rows:
        assert isinstance(row, Mapping)
        assert set(row) == {"path", "payload", "sha256", "size_bytes"}
        logical = str(row["path"])
        payload = generation / str(row["payload"])
        raw = payload.read_bytes()
        assert _sha(raw) == row["sha256"]
        assert len(raw) == row["size_bytes"]
        assert logical not in result
        result[logical] = raw
    return result


def _assert_exact_records_projection(scratchpad: Path) -> None:
    inventory_raw = (scratchpad / "findings_inventory.md").read_bytes()
    records_raw = (scratchpad / "finding_records.json").read_bytes()
    assert records_raw == derive_preverify_finding_records_bytes(inventory_raw)
    payload = json.loads(records_raw)
    assert payload["source"] == "findings_inventory.md"
    assert payload["source_sha256"] == _sha(inventory_raw)
    assert {
        str(row["inventory_id"]).upper() for row in payload["records"]
    } == set(AUTHORITY.extract_finding_records(
        inventory_raw.decode("utf-8", errors="strict")
    ))


def test_l1_semantic_dedup_is_prequeue_not_post_t9() -> None:
    """The proposal/apply phase must complete before T0 is armed."""

    order = [phase.name for phase in L1_PHASES]
    assert (
        order.index("semantic_dedup")
        < order.index("rag_sweep")
        < order.index("verify_queue")
    ), (
        "current L1 order publishes T9 before semantic dedup and therefore "
        "permits a post-commit queue rewrite"
    )


def test_l1_phase_and_prompt_declare_inventory_proposal_only() -> None:
    """The model may propose decisions; it may not author queue successors."""

    phase = next(row for row in L1_PHASES if row.name == "semantic_dedup")
    assert "dedup_decisions.md" in phase.expected_artifacts
    assert "findings_inventory_deduped.md" not in phase.expected_artifacts
    assert "verification_queue_deduped.md" not in phase.expected_artifacts

    prompt = (
        Path(__file__).parents[1]
        / "prompts"
        / "shared"
        / "v2"
        / "phase4e-semantic-dedup.md"
    ).read_text(encoding="utf-8", errors="strict")
    assert (
        "L1: do NOT read `{SCRATCHPAD}/verification_queue.md`" in prompt
    )
    assert "driver alone derives the post-dedup inventory" in prompt
    assert (
        "You do NOT write or edit `findings_inventory_deduped.md`."
        in prompt
    )
    assert (
        "copy `{SCRATCHPAD}/verification_queue.md`" not in prompt
    ), "the L1 model prompt still instructs a post-T9 queue copy"


def test_l1_prequeue_apply_has_one_typed_driver_contract() -> None:
    """One DRIVER work unit owns the inventory successor and exact receipt."""

    contract = resolve_phase_io_contract(
        pipeline="l1",
        mode="thorough",
        ecosystem="rust",
        backend="claude",
        phase="semantic_dedup",
        work_unit_id=APPLY_WORK_UNIT,
        exact_inputs=("dedup_decisions.md",),
    )
    outputs_by_identity = {
        item.identity: item for item in contract.outputs
    }
    outputs = set(outputs_by_identity)
    assert {
        "scratchpad:findings_inventory.md",
        "scratchpad:finding_records.json",
        "scratchpad:findings_inventory_deduped.md",
        "scratchpad:" + AUTHORITY.PRIMARY_RECEIPT_NAME,
        "scratchpad:dedup_absorbed_map.md",
    } <= outputs
    assert not any(
        identity.removeprefix("scratchpad:") in PUBLIC_QUEUE_NAMES
        or identity.removeprefix("scratchpad:").startswith("verify_")
        for identity in outputs
    )
    assert contract.model_invoked is False
    assert all(item.writer == "DRIVER" for item in contract.outputs)
    assert outputs_by_identity[
        "scratchpad:findings_inventory.md"
    ].write_mode == "REPLACE"
    assert outputs_by_identity[
        "scratchpad:finding_records.json"
    ].write_mode == "REPLACE"
    assert outputs_by_identity[
        "scratchpad:" + AUTHORITY.PRIMARY_RECEIPT_NAME
    ].write_mode == "REPLACE"
    assert set(contract.immutable_inputs) == {"scratchpad:dedup_decisions.md"}
    assert not {
        "scratchpad:findings_inventory.md",
        "scratchpad:finding_records.json",
    } & {
        item for item in (
            *contract.immutable_inputs,
            *contract.bounded_lookup_inputs,
        )
    }, "canonical RMW targets must be bound as output prestates, not inputs"


def test_l1_pair_candidate_packet_has_one_exact_driver_contract() -> None:
    """The live bounded packet is a typed producer, not unowned prework."""

    contract = resolve_phase_io_contract(
        pipeline="l1",
        mode="thorough",
        ecosystem="rust",
        backend="claude",
        phase="semantic_dedup",
        work_unit_id=PAIR_CANDIDATE_WORK_UNIT,
        exact_inputs=("findings_inventory.md",),
        exact_outputs=PAIR_PACKET_OUTPUT_NAMES,
    )
    assert contract.key == _pair_candidate_key()
    assert contract.model_invoked is False
    assert contract.immutable_inputs == (
        "scratchpad:findings_inventory.md",
    )
    outputs = {spec.path: spec for spec in contract.outputs}
    assert set(outputs) == set(PAIR_PACKET_OUTPUT_NAMES)
    assert all(spec.writer == "DRIVER" for spec in outputs.values())
    assert all(spec.write_mode == "REPLACE" for spec in outputs.values())

    expected_consumers = {
        "dedup_blocks.md": {
            "semantic_dedup/noop_proposal",
            "semantic_dedup/model",
        },
        "dedup_candidate_pairs.md": {
            "semantic_dedup/noop_proposal",
            "semantic_dedup/model",
            "semantic_dedup/supplemental_proposals",
        },
        "dedup_candidate_pairs_full.md": {
            "semantic_dedup/noop_proposal",
            "semantic_dedup/supplemental_proposals",
        },
        "dedup_focus_inventory.md": {
            "semantic_dedup/model",
        },
    }
    for name, consumers in expected_consumers.items():
        assert consumers <= set(outputs[name].consumers)


def test_live_l1_candidate_prep_arms_before_builder_and_publishes_exact_packet(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real prep helper arms exact inventory before its first packet write."""

    project = tmp_path / "project"
    scratchpad, config, checkpoint, inventory_raw = (
        _seed_candidate_prep_inventory(project)
    )
    _isolate_candidate_prep(monkeypatch)
    real_builder = DRIVER._compute_dedup_candidate_blocks
    observed_arm: dict[str, Any] = {}

    def observed_builder(root: Path) -> int:
        ledger = read_artifact_ledger(scratchpad)
        unit = ledger["work_units"].get(_pair_candidate_key())
        assert isinstance(unit, Mapping), (
            "candidate builder ran before its PhaseIO work unit existed"
        )
        assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
        assert unit["semantic_status"] == "INPUTS_BOUND"
        binding = unit["input_bindings"][
            "scratchpad:findings_inventory.md"
        ]
        assert binding["status"] == "ACTIVE"
        assert binding["sha256"] == _sha(inventory_raw)
        assert all(
            not (scratchpad / name).exists()
            for name in PAIR_PACKET_OUTPUT_NAMES
        ), "candidate packet bytes existed before the typed producer arm"
        observed_arm["unit"] = unit
        return real_builder(root)

    monkeypatch.setattr(
        DRIVER, "_compute_dedup_candidate_blocks", observed_builder
    )
    issues = DRIVER._prepare_l1_semantic_dedup_inventory(
        scratchpad=scratchpad,
        config=config,
        checkpoint=checkpoint,
    )
    assert issues == []
    assert "unit" in observed_arm
    packet = _pair_packet_snapshot(scratchpad)

    ledger = read_artifact_ledger(scratchpad)
    unit = ledger["work_units"][_pair_candidate_key()]
    assert unit["model_invoked"] is False
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert unit["semantic_status"] == "ACTIVE"
    assert set(unit["artifacts"]) == {
        "scratchpad:" + name for name in PAIR_PACKET_OUTPUT_NAMES
    }
    for name, raw in packet.items():
        identity = "scratchpad:" + name
        assert unit["artifacts"][identity]["sha256"] == _sha(raw)
        binding = ledger["artifact_bindings"][identity]
        assert binding["owner_key"] == _pair_candidate_key()
        assert binding["sha256"] == _sha(raw)

    # The ordinary model consumes the primary block/pair/focus packet through
    # this exact producer rather than rereading unregistered prework.
    phase = next(row for row in L1_PHASES if row.name == "semantic_dedup")
    assert DRIVER._bind_typed_model_phase_inputs(
        phase, scratchpad, config
    ) == []
    model_contract, _launch = DRIVER._typed_model_phase_contract_and_launch(
        phase, scratchpad, config
    )
    model_unit = read_artifact_ledger(scratchpad)["work_units"][
        model_contract.key
    ]
    for name in (
        "dedup_blocks.md",
        "dedup_candidate_pairs.md",
        "dedup_focus_inventory.md",
    ):
        assert model_unit["input_bindings"]["scratchpad:" + name][
            "producer_work_unit_key"
        ] == _pair_candidate_key()


def test_l1_candidate_prep_recovers_after_input_arm_and_replays_byte_exact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A builder fault degrades to an exact inventory-only successor."""

    project = tmp_path / "project"
    scratchpad, config, checkpoint, inventory_raw = (
        _seed_candidate_prep_inventory(project)
    )
    _isolate_candidate_prep(monkeypatch)

    def crash_after_arm(_root: Path) -> int:
        ledger = read_artifact_ledger(scratchpad)
        unit = ledger["work_units"][_pair_candidate_key()]
        assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
        assert unit["input_bindings"][
            "scratchpad:findings_inventory.md"
        ]["sha256"] == _sha(inventory_raw)
        raise RuntimeError("fixture-crash-after-pair-candidate-input-arm")

    monkeypatch.setattr(
        DRIVER, "_compute_dedup_candidate_blocks", crash_after_arm
    )
    issues = DRIVER._prepare_l1_semantic_dedup_inventory(
        scratchpad=scratchpad,
        config=config,
        checkpoint=checkpoint,
    )
    assert any(
        "FIXTURE-CRASH-AFTER-PAIR-CANDIDATE-INPUT-ARM" in issue.upper()
        for issue in issues
    )
    ledger = read_artifact_ledger(scratchpad)
    armed = ledger["work_units"][
        _pair_candidate_key()
    ]
    assert armed["semantic_status"] == "INPUTS_BOUND"
    assert armed["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert armed["artifacts"] == {}
    assert all(
        not (scratchpad / name).exists()
        for name in PAIR_PACKET_OUTPUT_NAMES
    )
    noop_key = canonical_work_unit_key(
        "l1",
        "thorough",
        "rust",
        "claude",
        "semantic_dedup",
        NOOP_PROPOSAL_WORK_UNIT,
    )
    noop = ledger["work_units"][noop_key]
    assert noop["model_invoked"] is False
    assert noop["semantic_status"] == "ACTIVE"
    assert noop["execution_state"] == "OUTPUT_COMMITTED"
    assert set(noop["input_bindings"]) == {
        "scratchpad:findings_inventory.md"
    }
    decisions = (scratchpad / "dedup_decisions.md").read_text(
        encoding="utf-8",
        errors="strict",
    ).upper()
    assert "PASSTHROUGH" in decisions
    assert "SIGNAL AUTHORITY**: UNAVAILABLE" in decisions
    assert "NO ABSENCE-OF-DUPLICATES" in decisions
    assert "MERGE:" not in decisions
    assert "DROP:" not in decisions
    assert not any(
        unit.get("model_invoked") is True
        for key, unit in ledger["work_units"].items()
        if "/semantic_dedup/" in key
    )

    apply_key = canonical_work_unit_key(
        "l1",
        "thorough",
        "rust",
        "claude",
        "semantic_dedup",
        APPLY_WORK_UNIT,
    )
    apply = ledger["work_units"][apply_key]
    assert apply["semantic_status"] == "ACTIVE"
    assert apply["execution_state"] == "OUTPUT_COMMITTED"
    for name in ROOT_OUTPUT_NAMES:
        assert (scratchpad / name).is_file()
        binding = ledger["artifact_bindings"]["scratchpad:" + name]
        assert binding["owner_key"] == apply_key
        assert binding["sha256"] == _sha((scratchpad / name).read_bytes())
    assert (scratchpad / "findings_inventory.md").read_bytes() == inventory_raw
    _assert_exact_records_projection(scratchpad)
    receipt = json.loads(
        (scratchpad / AUTHORITY.PRIMARY_RECEIPT_NAME).read_bytes()
    )
    assert set(receipt["input_artifact"]["finding_ids"]) == {
        "INV-001", "INV-002", "INV-003"
    }
    assert set(receipt["output_artifact"]["finding_ids"]) == {
        "INV-001", "INV-002", "INV-003"
    }
    assert receipt["accepted_absorbed_ids"] == []

    before = _semantic_public_snapshot(scratchpad)
    before_apply = read_artifact_ledger(scratchpad)["work_units"][
        apply_key
    ]

    def forbidden_recompute(_root: Path) -> int:
        raise AssertionError(
            "committed inventory-only successor retried the failed packet"
        )

    monkeypatch.setattr(
        DRIVER, "_compute_dedup_candidate_blocks", forbidden_recompute
    )
    assert DRIVER._prepare_l1_semantic_dedup_inventory(
        scratchpad=scratchpad,
        config=config,
        checkpoint=checkpoint,
    ) == []
    assert _semantic_public_snapshot(scratchpad) == before
    assert read_artifact_ledger(scratchpad)["work_units"][apply_key] == (
        before_apply
    )


@pytest.mark.parametrize("foreign_name", PAIR_PACKET_OUTPUT_NAMES)
def test_l1_candidate_prep_rejects_unowned_packet_prestate_without_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    foreign_name: str,
) -> None:
    """Unowned candidate bytes are visible debt, never blessed or replaced."""

    project = tmp_path / "project"
    scratchpad, config, checkpoint, _ = _seed_candidate_prep_inventory(
        project
    )
    _isolate_candidate_prep(monkeypatch)
    foreign_raw = (
        f"unowned packet prestate for {foreign_name}\n"
    ).encode("utf-8")
    (scratchpad / foreign_name).write_bytes(foreign_raw)

    def forbidden_builder(_root: Path) -> int:
        raise AssertionError(
            "candidate builder ran despite an unowned output prestate"
        )

    monkeypatch.setattr(
        DRIVER, "_compute_dedup_candidate_blocks", forbidden_builder
    )
    issues = DRIVER._prepare_l1_semantic_dedup_inventory(
        scratchpad=scratchpad,
        config=config,
        checkpoint=checkpoint,
    )
    assert issues
    assert any(
        foreign_name in issue
        and (
            "UNOWNED" in issue.upper()
            or "UNREGISTERED" in issue.upper()
            or "PRESTATE" in issue.upper()
        )
        for issue in issues
    )
    assert (scratchpad / foreign_name).read_bytes() == foreign_raw
    ledger = read_artifact_ledger(scratchpad)
    binding = ledger.get("artifact_bindings", {}).get(
        "scratchpad:" + foreign_name
    )
    assert not isinstance(binding, Mapping) or (
        binding.get("owner_key") != _pair_candidate_key()
    )


@pytest.mark.parametrize("tampered_name", PAIR_PACKET_OUTPUT_NAMES)
def test_l1_candidate_prep_rejects_tampered_committed_packet_without_rebless(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tampered_name: str,
) -> None:
    """A committed packet postimage cannot be recomputed over or self-blessed."""

    project = tmp_path / "project"
    scratchpad, config, checkpoint, _ = _seed_candidate_prep_inventory(
        project
    )
    _isolate_candidate_prep(monkeypatch)
    assert DRIVER._prepare_l1_semantic_dedup_inventory(
        scratchpad=scratchpad,
        config=config,
        checkpoint=checkpoint,
    ) == []
    before = read_artifact_ledger(scratchpad)["work_units"][
        _pair_candidate_key()
    ]
    target = scratchpad / tampered_name
    tampered_raw = target.read_bytes() + b"\nTAMPERED-PACKET-BYTE\n"
    target.write_bytes(tampered_raw)

    def forbidden_builder(_root: Path) -> int:
        raise AssertionError(
            "tampered committed packet was recomputed and re-blessed"
        )

    monkeypatch.setattr(
        DRIVER, "_compute_dedup_candidate_blocks", forbidden_builder
    )
    issues = DRIVER._prepare_l1_semantic_dedup_inventory(
        scratchpad=scratchpad,
        config=config,
        checkpoint=checkpoint,
    )
    assert issues
    assert any(
        tampered_name in issue
        and (
            "CHANGED" in issue.upper()
            or "DRIFT" in issue.upper()
            or "HASH" in issue.upper()
            or "AUTHORITY" in issue.upper()
        )
        for issue in issues
    )
    assert target.read_bytes() == tampered_raw
    after = read_artifact_ledger(scratchpad)["work_units"][
        _pair_candidate_key()
    ]
    assert after == before
    assert after["artifacts"]["scratchpad:" + tampered_name][
        "sha256"
    ] != _sha(tampered_raw)


def test_l1_legacy_round_files_never_stage_over_committed_candidate_packet(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """L1 ignores legacy rounds; only SC may stage them into canonical bytes."""

    project = tmp_path / "project"
    scratchpad, config, checkpoint, _ = _seed_candidate_prep_inventory(
        project
    )
    _isolate_candidate_prep(monkeypatch)
    assert DRIVER._prepare_l1_semantic_dedup_inventory(
        scratchpad=scratchpad,
        config=config,
        checkpoint=checkpoint,
    ) == []
    canonical_before = _pair_packet_snapshot(scratchpad)

    incidental = {
        "dedup_candidate_pairs_round1.md": (
            b"# FOREIGN ROUND 1\n\n| INV-001 | INV-003 |\n"
        ),
        "dedup_candidate_pairs_round2.md": (
            b"# FOREIGN ROUND 2\n\n| INV-002 | INV-003 |\n"
        ),
        "dedup_focus_inventory_round1.md": b"# FOREIGN FOCUS 1\n",
        "dedup_focus_inventory_round2.md": b"# FOREIGN FOCUS 2\n",
        "dedup_round_count.txt": b"999\n",
        "dedup_block_count.txt": b"999\n",
    }
    for name, raw in incidental.items():
        (scratchpad / name).write_bytes(raw)

    phase = next(row for row in L1_PHASES if row.name == "semantic_dedup")
    assert DRIVER._bind_typed_model_phase_inputs(
        phase, scratchpad, config
    ) == []
    model_contract, _launch = DRIVER._typed_model_phase_contract_and_launch(
        phase, scratchpad, config
    )
    assert set(model_contract.immutable_inputs) == {
        "scratchpad:dedup_blocks.md",
        "scratchpad:dedup_candidate_pairs.md",
        "scratchpad:dedup_focus_inventory.md",
    }
    model_unit = read_artifact_ledger(scratchpad)["work_units"][
        model_contract.key
    ]
    for identity, row in model_unit["input_bindings"].items():
        assert row["producer_work_unit_key"] == _pair_candidate_key()
        assert "round" not in identity
        assert "count" not in identity
    assert _pair_packet_snapshot(scratchpad) == canonical_before
    for name, raw in incidental.items():
        assert (scratchpad / name).read_bytes() == raw

    # The live main loop must preserve the same guarantee. Merely making the
    # model resolver ignore round files is insufficient if prelaunch staging
    # first overwrites the already-committed canonical packet.
    source = inspect.getsource(DRIVER.main)
    branch_start = source.index(
        'if phase.name in ("semantic_dedup", "sc_semantic_dedup"):'
    )
    stage_call = source.index(
        "_stage_dedup_round_packet(",
        branch_start,
    )
    stage_prefix = source[branch_start:stage_call]
    assert (
        'phase.name == "sc_semantic_dedup"' in stage_prefix
        or 'config.get("pipeline") == "sc"' in stage_prefix
    ), (
        "the L1 main path can still stage an unowned legacy round over the "
        "committed dedup_candidate_pairs.md/focus packet before model bind"
    )


@pytest.mark.parametrize(
    "apply_state",
    ("INPUTS_BOUND_PREEXECUTION", "OUTPUT_COMMITTED"),
    ids=("apply-armed", "apply-committed"),
)
def test_l1_candidate_prepare_replay_is_inert_after_apply_authority_exists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    apply_state: str,
) -> None:
    """Resume preserves the denominator and rolls an armed apply forward."""

    project = tmp_path / "project"
    scratchpad, config, checkpoint, _ = _seed_candidate_prep_inventory(
        project
    )
    _isolate_candidate_prep(monkeypatch)
    assert DRIVER._prepare_l1_semantic_dedup_inventory(
        scratchpad=scratchpad,
        config=config,
        checkpoint=checkpoint,
    ) == []
    _claim_model_dedup_decisions(
        scratchpad=scratchpad,
        project=project,
    )
    if apply_state == "INPUTS_BOUND_PREEXECUTION":
        def crash(label: str) -> None:
            if label == "AFTER_PHASEIO_ARM":
                raise RuntimeError("fixture-crash-after-apply-arm")

        with pytest.raises(
            RuntimeError,
            match="fixture-crash-after-apply-arm",
        ):
            _required_apply()(
                scratchpad=scratchpad,
                project_root=project,
                config=config,
                run_id=RUN_ID,
                fault_hook=crash,
            )
    else:
        result = _required_apply()(
            scratchpad=scratchpad,
            project_root=project,
            config=config,
            run_id=RUN_ID,
        )
        assert result.get("safe_to_consume") is True

    apply_key = canonical_work_unit_key(
        "l1",
        "thorough",
        "rust",
        "claude",
        "semantic_dedup",
        APPLY_WORK_UNIT,
    )
    ledger_before = read_artifact_ledger(scratchpad)
    assert ledger_before["work_units"][apply_key][
        "execution_state"
    ] == apply_state
    packet_before = _pair_packet_snapshot(scratchpad)
    candidate_before = ledger_before["work_units"][_pair_candidate_key()]
    inventory_before = (scratchpad / "findings_inventory.md").read_bytes()
    public_before = (
        _semantic_public_snapshot(scratchpad)
        if apply_state == "OUTPUT_COMMITTED"
        else None
    )

    def forbidden_builder(_root: Path) -> int:
        raise AssertionError(
            "candidate denominator was recomputed after prequeue_apply "
            "authority existed"
        )

    monkeypatch.setattr(
        DRIVER, "_compute_dedup_candidate_blocks", forbidden_builder
    )
    assert DRIVER._prepare_l1_semantic_dedup_inventory(
        scratchpad=scratchpad,
        config=config,
        checkpoint=checkpoint,
    ) == []
    assert _pair_packet_snapshot(scratchpad) == packet_before
    ledger_after = read_artifact_ledger(scratchpad)
    candidate_after = ledger_after["work_units"][_pair_candidate_key()]
    if apply_state == "INPUTS_BOUND_PREEXECUTION":
        # The exact packet is not regenerated or re-blessed after its
        # inventory denominator is replaced.  Roll-forward correctly marks
        # that historical producer stale while retaining its byte evidence.
        assert candidate_after["semantic_status"] == "STALE_INPUT"
        assert candidate_after["run_id"] == candidate_before["run_id"]
        assert (
            candidate_after["contract_digest"]
            == candidate_before["contract_digest"]
        )
        assert (
            candidate_after["input_set_digest"]
            == candidate_before["input_set_digest"]
        )
        for name, raw in packet_before.items():
            artifact = candidate_after["artifacts"]["scratchpad:" + name]
            assert artifact["sha256"] == _sha(raw)
    else:
        assert candidate_after == candidate_before
    assert ledger_after["work_units"][apply_key][
        "execution_state"
    ] == "OUTPUT_COMMITTED"
    assert ledger_after["work_units"][apply_key][
        "semantic_status"
    ] == "ACTIVE"
    for name in ROOT_OUTPUT_NAMES:
        binding = ledger_after["artifact_bindings"]["scratchpad:" + name]
        assert binding["owner_key"] == apply_key
        assert binding["sha256"] == _sha((scratchpad / name).read_bytes())
    _assert_exact_records_projection(scratchpad)
    receipt = json.loads(
        (scratchpad / AUTHORITY.PRIMARY_RECEIPT_NAME).read_bytes()
    )
    if apply_state == "INPUTS_BOUND_PREEXECUTION":
        assert receipt["input_artifact"]["sha256"] == _sha(inventory_before)
    else:
        assert receipt["output_artifact"]["sha256"] == _sha(inventory_before)
    assert receipt["output_artifact"]["sha256"] == _sha(
        (scratchpad / "findings_inventory.md").read_bytes()
    )
    if public_before is not None:
        assert _semantic_public_snapshot(scratchpad) == public_before


def test_l1_noop_proposal_has_a_distinct_typed_driver_contract() -> None:
    """A no-model exit is an authenticated proposal, never MODEL work."""

    contract = resolve_phase_io_contract(
        pipeline="l1",
        mode="thorough",
        ecosystem="rust",
        backend="claude",
        phase="semantic_dedup",
        work_unit_id=NOOP_PROPOSAL_WORK_UNIT,
        exact_inputs=NOOP_INPUT_NAMES,
        exact_outputs=("dedup_decisions.md",),
    )
    assert contract.key.endswith(
        f"/semantic_dedup/{NOOP_PROPOSAL_WORK_UNIT}"
    )
    assert contract.model_invoked is False
    assert set(contract.immutable_inputs) == {
        "scratchpad:" + name for name in NOOP_INPUT_NAMES
    }
    assert len(contract.outputs) == 1
    proposal = contract.outputs[0]
    assert proposal.identity == "scratchpad:dedup_decisions.md"
    assert proposal.writer == "DRIVER"
    assert proposal.write_mode == "REPLACE"
    assert proposal.schema_version == "plamen.semantic_dedup_proposals.v1"
    assert "semantic_dedup/prequeue_apply" in proposal.consumers


def test_l1_no_signal_and_budget_exits_use_typed_proposal_apply_then_commit() -> None:
    """Both early exits must traverse the same successor and phase commit."""

    source = inspect.getsource(DRIVER.main)
    no_signal_start = source.index(
        "if not has_blocks and not has_likely_dup:"
    )
    budget_start = source.index("if _blocks_over_budget:", no_signal_start)
    budget_end = source.index("continue", budget_start) + len("continue")
    no_signal = source[no_signal_start:budget_start]
    budget = source[budget_start:budget_end]
    for label, branch in (
        ("no-signal", no_signal),
        ("oversized-budget", budget),
    ):
        assert "_run_l1_semantic_dedup_noop_proposal(" in branch, (
            f"{label} branch does not publish an authenticated DRIVER "
            "proposal and run the prequeue transaction"
        )
        assert "_run_l1_prequeue_semantic_dedup_transaction(" not in branch, (
            f"{label} branch bypasses the single noop-proposal coordinator"
        )
        assert "_write_semantic_dedup_skip_outputs(" not in branch, (
            f"{label} branch still writes an unowned Markdown scaffold"
        )
        assert "_commit_accepted_phase_from_disk(" in branch, (
            f"{label} branch does not commit the phase after the five-output "
            "successor"
        )
        assert (
            branch.index("_run_l1_semantic_dedup_noop_proposal(")
            < branch.index("_commit_accepted_phase_from_disk(")
            < branch.rindex("continue")
        ), f"{label} branch commits or exits before its successor transaction"

    # The ordinary model path may retain crash safety only through a typed
    # predecessor. A raw write before model input arm can otherwise be
    # retroactively mislabeled as MODEL output.
    normal_end = source.index(
        "# Fix 4 + Fix 1 (item C):",
        budget_end,
    )
    normal = source[budget_end:normal_end]
    assert "_write_semantic_dedup_skip_outputs(" not in normal, (
        "normal semantic-dedup still prewrites an unowned PASSTHROUGH before "
        "the MODEL PhaseIO arm"
    )


@pytest.mark.parametrize(
    ("oversized_blocks", "reason_fragment"),
    (
        (False, "no candidate blocks and no LIKELY-DUP tags"),
        (True, "semantic dedup budget guard: oversized block file"),
    ),
    ids=("no-signal", "oversized-budget"),
)
def test_l1_noop_paths_are_driver_owned_transactional_and_byte_idempotent(
    tmp_path: Path,
    oversized_blocks: bool,
    reason_fragment: str,
) -> None:
    """No-model exits still publish all five outputs under exact authority."""

    project = tmp_path / "project"
    scratchpad, config, sources = _seed_bounded_dedup_denominator(
        project,
        oversized_blocks=oversized_blocks,
    )
    if oversized_blocks:
        assert len(sources["dedup_blocks.md"]) > 200 * 1024

    result = _required_noop_proposal()(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
        reason=reason_fragment,
    )
    assert result.get("safe_to_consume") is True
    assert result.get("state") in {
        "COMMITTED",
        "OUTPUT_COMMITTED",
        "ALREADY_COMMITTED",
    }
    assert not any((scratchpad / name).exists() for name in PUBLIC_QUEUE_NAMES)

    ledger = read_artifact_ledger(scratchpad)
    noop_key = canonical_work_unit_key(
        "l1",
        "thorough",
        "rust",
        "claude",
        "semantic_dedup",
        NOOP_PROPOSAL_WORK_UNIT,
    )
    binding = ledger["artifact_bindings"][
        "scratchpad:dedup_decisions.md"
    ]
    assert binding["owner_key"] == noop_key
    noop = ledger["work_units"][noop_key]
    assert noop["model_invoked"] is False
    assert noop["execution_state"] == "OUTPUT_COMMITTED"
    assert noop["semantic_status"] == "ACTIVE"
    # These fixture packet bytes were produced by a compatibility contract,
    # not the live typed packet producer.  The no-op must therefore bind only
    # the canonical inventory and must not turn plausible packet bytes into
    # negative signal authority.
    assert set(noop["input_bindings"]) == {
        "scratchpad:findings_inventory.md"
    }
    inventory_row = noop["input_bindings"][
        "scratchpad:findings_inventory.md"
    ]
    assert inventory_row["status"] == "ACTIVE"
    assert inventory_row["sha256"] == _sha(sources["findings_inventory.md"])
    decision_raw = (scratchpad / "dedup_decisions.md").read_bytes()
    assert b"PASSTHROUGH" in decision_raw
    assert reason_fragment.encode("utf-8") in decision_raw
    assert b"Signal Authority**: UNAVAILABLE" in decision_raw
    assert b"No absence-of-duplicates" in decision_raw
    assert b"MERGE:" not in decision_raw
    assert b"DROP:" not in decision_raw

    model_units = [
        unit
        for key, unit in ledger["work_units"].items()
        if "/semantic_dedup/" in key
        and unit.get("model_invoked") is True
    ]
    assert model_units == [], "a no-model exit fabricated MODEL invocation"

    apply_key = canonical_work_unit_key(
        "l1",
        "thorough",
        "rust",
        "claude",
        "semantic_dedup",
        APPLY_WORK_UNIT,
    )
    apply = ledger["work_units"][apply_key]
    assert apply["execution_state"] == "OUTPUT_COMMITTED"
    assert (
        apply["input_bindings"]["scratchpad:dedup_decisions.md"][
            "producer_work_unit_key"
        ]
        == noop_key
    )
    for name in ROOT_OUTPUT_NAMES:
        output_binding = ledger["artifact_bindings"]["scratchpad:" + name]
        assert output_binding["owner_key"] == apply_key
        assert output_binding["sha256"] == _sha(
            (scratchpad / name).read_bytes()
        )
    _assert_exact_records_projection(scratchpad)

    before = _semantic_public_snapshot(scratchpad)
    generation_dirs = sorted(
        path.name for path in (scratchpad / TRANSACTION_ROOT).glob("g_*")
    )
    replay = _required_noop_proposal()(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
        reason=reason_fragment,
    )
    assert replay.get("safe_to_consume") is True
    assert _semantic_public_snapshot(scratchpad) == before
    assert sorted(
        path.name for path in (scratchpad / TRANSACTION_ROOT).glob("g_*")
    ) == generation_dirs


def test_model_scaffold_is_not_retroactively_blessed_but_real_output_flows(
    tmp_path: Path,
) -> None:
    """Unchanged DRIVER scaffold is not MODEL output; a real overwrite is."""

    phase = next(row for row in L1_PHASES if row.name == "semantic_dedup")

    rejected_project = tmp_path / "rejected"
    rejected_root, rejected_config, _ = _seed_bounded_dedup_denominator(
        rejected_project,
        live_pair=True,
    )
    scaffold_owner = _claim_driver_passthrough_scaffold(
        scratchpad=rejected_root,
        project=rejected_project,
        reason="pre-run crash-safety scaffold",
    )
    bind_issues = DRIVER._bind_typed_model_phase_inputs(
        phase, rejected_root, rejected_config
    )
    assert bind_issues == []
    rejected = DRIVER._record_typed_model_phase_artifacts(
        phase, rejected_root, rejected_config
    )
    assert rejected, (
        "unchanged prewritten PASSTHROUGH was retroactively blessed as MODEL "
        "output"
    )
    rejected_ledger = read_artifact_ledger(rejected_root)
    assert rejected_ledger["artifact_bindings"][
        "scratchpad:dedup_decisions.md"
    ]["owner_key"] == scaffold_owner
    assert not any(
        unit.get("model_invoked") is True
        and unit.get("semantic_status") == "ACTIVE"
        for key, unit in rejected_ledger["work_units"].items()
        if "/semantic_dedup/" in key
    )

    accepted_project = tmp_path / "accepted"
    accepted_root, accepted_config, _ = _seed_bounded_dedup_denominator(
        accepted_project,
        live_pair=True,
    )
    accepted_scaffold_owner = _claim_driver_passthrough_scaffold(
        scratchpad=accepted_root,
        project=accepted_project,
        reason="pre-run crash-safety scaffold",
    )
    assert DRIVER._bind_typed_model_phase_inputs(
        phase, accepted_root, accepted_config
    ) == []
    genuine_raw = (
        "# Semantic Dedup Decisions\n\n"
        "MERGE: INV-001, INV-002\tsame mechanism and repair\n"
        "KEEP: INV-003\n"
    ).encode("utf-8")
    assert genuine_raw != (
        accepted_root / "dedup_decisions.md"
    ).read_bytes()
    (accepted_root / "dedup_decisions.md").write_bytes(genuine_raw)
    assert DRIVER._record_typed_model_phase_artifacts(
        phase, accepted_root, accepted_config
    ) == []

    model_ledger = read_artifact_ledger(accepted_root)
    model_binding = model_ledger["artifact_bindings"][
        "scratchpad:dedup_decisions.md"
    ]
    model_key = model_binding["owner_key"]
    assert model_key != accepted_scaffold_owner
    assert model_key.endswith("/semantic_dedup/model")
    assert model_binding["sha256"] == _sha(genuine_raw)
    model = model_ledger["work_units"][model_key]
    assert model["model_invoked"] is True
    assert model["execution_state"] == "OUTPUT_COMMITTED"
    assert model["semantic_status"] == "ACTIVE"
    assert model["output_prestates"][
        "scratchpad:dedup_decisions.md"
    ]["predecessor_owner_key"] == accepted_scaffold_owner

    result = _required_apply()(
        scratchpad=accepted_root,
        project_root=accepted_project,
        config=accepted_config,
        run_id=RUN_ID,
    )
    assert result.get("safe_to_consume") is True
    final_ledger = read_artifact_ledger(accepted_root)
    apply_key = canonical_work_unit_key(
        "l1",
        "thorough",
        "rust",
        "claude",
        "semantic_dedup",
        APPLY_WORK_UNIT,
    )
    assert (
        final_ledger["work_units"][apply_key]["input_bindings"][
            "scratchpad:dedup_decisions.md"
        ]["producer_work_unit_key"]
        == model_key
    )
    assert final_ledger["artifact_bindings"][
        "scratchpad:dedup_decisions.md"
    ]["owner_key"] == model_key
    for name in ROOT_OUTPUT_NAMES:
        assert final_ledger["artifact_bindings"][
            "scratchpad:" + name
        ]["owner_key"] == apply_key


def test_l1_post_model_coverage_never_launders_driver_repair_as_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Raw MODEL proposal bytes are immutable across post-model validation.

    Missing-disposition handling may emit a distinct DRIVER proposal or durable
    debt, but it must not append mechanical rows to ``dedup_decisions.md`` and
    then attribute that mixed-author file to the MODEL work unit.
    """

    project = tmp_path / "project"
    scratchpad, config, _ = _seed_bounded_dedup_denominator(
        project,
        live_pair=True,
    )
    phase = next(row for row in L1_PHASES if row.name == "semantic_dedup")
    assert DRIVER._bind_typed_model_phase_inputs(
        phase,
        scratchpad,
        config,
    ) == []
    file_state_before = DRIVER._snapshot_file_state(scratchpad, str(project))
    raw_model_proposal = (
        "# Step 4e: Semantic Dedup\n\n"
        "## Semantic Dedup Decisions\n\n"
        "The bounded candidate-pair denominator was reviewed, but the model "
        "did not emit a disposition row for the live pair.\n\n"
        "| Candidate Pair | Disposition | Reason |\n"
        "|---|---|---|\n"
    ).encode("utf-8")
    (scratchpad / "dedup_decisions.md").write_bytes(raw_model_proposal)
    assert DRIVER._check_dedup_decision_coverage(scratchpad), (
        "fixture must expose an undisposed live pair before validation"
    )

    repair_calls: list[tuple[bytes, bytes]] = []
    real_repair = DRIVER._repair_dedup_missing_dispositions

    def observe_repair(*args: Any, **kwargs: Any) -> int:
        before = (scratchpad / "dedup_decisions.md").read_bytes()
        result = real_repair(*args, **kwargs)
        after = (scratchpad / "dedup_decisions.md").read_bytes()
        repair_calls.append((before, after))
        return result

    monkeypatch.setattr(
        DRIVER,
        "_repair_dedup_missing_dispositions",
        observe_repair,
    )
    # Exercise the fresh-audit L1 coverage branch without enabling unrelated
    # marker enforcement inside gate_passes().
    monkeypatch.setattr(
        DRIVER,
        "scratchpad_is_fresh_audit",
        lambda _scratchpad: True,
    )

    passed, missing = DRIVER._run_phase_validators(
        phase,
        config,
        scratchpad,
        L1_PHASES,
        0,
        file_state_before,
    )
    assert passed is True, missing
    assert missing == [], (
        "an incomplete L1 model disposition is recall-safe warning/debt, not "
        "a phase-halting condition"
    )

    ledger = read_artifact_ledger(scratchpad)
    model_key = canonical_work_unit_key(
        "l1",
        "thorough",
        "rust",
        "claude",
        "semantic_dedup",
        "model",
    )
    model = ledger["work_units"][model_key]
    model_artifact = model["artifacts"][
        "scratchpad:dedup_decisions.md"
    ]
    active_binding = ledger["artifact_bindings"][
        "scratchpad:dedup_decisions.md"
    ]

    assert model_artifact["sha256"] == _sha(raw_model_proposal), (
        "the semantic_dedup/model receipt attributed post-validation DRIVER "
        "bytes instead of the exact raw MODEL proposal"
    )
    assert active_binding["owner_key"] == model_key
    assert active_binding["sha256"] == _sha(raw_model_proposal)
    assert (scratchpad / "dedup_decisions.md").read_bytes() == raw_model_proposal
    assert repair_calls == [], (
        "L1 post-model validation called the legacy in-place repair and mixed "
        "DRIVER-authored PASSTHROUGH rows into the MODEL proposal"
    )


def test_real_prepare_model_supplemental_apply_sequence_has_one_authority_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise the production L1 sequence without fixture-owned pair bytes.

    The inventory fixture is the last upstream authority.  From that point on,
    every dedup artifact must be produced by the same production coordinators
    used by ``main``: prepare owns the bounded packet, the typed MODEL work unit
    owns only its raw proposal, the supplemental DRIVER work unit owns its
    separate proposal, and the five-output transaction owns the canonical
    post-dedup generation.  In particular, no queue artifact may exist yet.
    """

    project = tmp_path / "project"
    scratchpad, config, checkpoint, _ = _seed_candidate_prep_inventory(
        project
    )
    _isolate_candidate_prep(monkeypatch)
    assert not any(
        (scratchpad / name).exists() for name in PAIR_PACKET_OUTPUT_NAMES
    )

    assert DRIVER._prepare_l1_semantic_dedup_inventory(
        scratchpad=scratchpad,
        config=config,
        checkpoint=checkpoint,
    ) == []

    ledger = read_artifact_ledger(scratchpad)
    pair_key = _pair_candidate_key()
    pair_unit = ledger["work_units"][pair_key]
    assert pair_unit["model_invoked"] is False
    assert pair_unit["execution_state"] == "OUTPUT_COMMITTED"
    assert pair_unit["semantic_status"] == "ACTIVE"
    for name in PAIR_PACKET_OUTPUT_NAMES:
        binding = ledger["artifact_bindings"]["scratchpad:" + name]
        assert binding["owner_key"] == pair_key
        assert binding["sha256"] == _sha((scratchpad / name).read_bytes())

    phase = next(
        row for row in L1_PHASES if row.name == "semantic_dedup"
    )
    assert DRIVER._bind_typed_model_phase_inputs(
        phase,
        scratchpad,
        config,
    ) == []
    file_state_before = DRIVER._snapshot_file_state(
        scratchpad,
        str(project),
    )
    raw_model_proposal = (
        "# Step 4e: Semantic Dedup\n\n"
        "## Semantic Dedup Decisions\n\n"
        "MERGE: INV-001, INV-002\tsame mechanism and repair; INV-001 "
        "preserves every material field.\n"
        "KEEP: INV-003\tindependent authentication-state mechanism and "
        "remediation.\n\n"
        "| Candidate Pair | Disposition | Survivor | Reason |\n"
        "|---|---|---|---|\n"
        "| INV-001 / INV-002 | MERGE | INV-001 | Same mechanism, transition, "
        "impact, and remediation; field-complete survivor. |\n\n"
        "## Coverage\n\n"
        "The complete bounded candidate-pair denominator was reviewed. Every "
        "live pair has an explicit disposition. No finding outside the "
        "accepted merge is removed, demoted, or omitted.\n"
    ).encode("utf-8")
    (scratchpad / "dedup_decisions.md").write_bytes(raw_model_proposal)

    passed, missing = DRIVER._run_phase_validators(
        phase,
        config,
        scratchpad,
        L1_PHASES,
        0,
        file_state_before,
    )
    assert passed is True, missing
    assert missing == []
    assert not any(
        (scratchpad / name).exists() for name in PUBLIC_QUEUE_NAMES
    )

    ledger = read_artifact_ledger(scratchpad)
    model_key = canonical_work_unit_key(
        "l1",
        "thorough",
        "rust",
        "claude",
        "semantic_dedup",
        "model",
    )
    supplemental_key = canonical_work_unit_key(
        "l1",
        "thorough",
        "rust",
        "claude",
        "semantic_dedup",
        "supplemental_proposals",
    )
    apply_key = canonical_work_unit_key(
        "l1",
        "thorough",
        "rust",
        "claude",
        "semantic_dedup",
        APPLY_WORK_UNIT,
    )
    model = ledger["work_units"][model_key]
    supplemental = ledger["work_units"][supplemental_key]
    apply = ledger["work_units"][apply_key]
    assert model["model_invoked"] is True
    assert model["execution_state"] == "OUTPUT_COMMITTED"
    assert model["artifacts"]["scratchpad:dedup_decisions.md"][
        "sha256"
    ] == _sha(raw_model_proposal)
    assert supplemental["model_invoked"] is False
    assert supplemental["execution_state"] == "OUTPUT_COMMITTED"
    assert supplemental["input_bindings"][
        "scratchpad:dedup_decisions.md"
    ]["producer_work_unit_key"] == model_key
    assert apply["model_invoked"] is False
    assert apply["execution_state"] == "OUTPUT_COMMITTED"
    assert apply["input_bindings"][
        "scratchpad:dedup_decisions.md"
    ]["producer_work_unit_key"] == model_key
    assert apply["input_bindings"][
        "scratchpad:semantic_dedup_supplemental_proposals.json"
    ]["producer_work_unit_key"] == supplemental_key
    for name in ROOT_OUTPUT_NAMES:
        binding = ledger["artifact_bindings"]["scratchpad:" + name]
        assert binding["owner_key"] == apply_key
        assert binding["sha256"] == _sha((scratchpad / name).read_bytes())

    assert _active_ids(scratchpad) == {"INV-001", "INV-003"}
    assert AUTHORITY.load_applied_aliases(scratchpad) == {
        "INV-002": {
            "survivor": "INV-001",
            "coupled": "field-complete-preserved",
        }
    }
    _assert_exact_records_projection(scratchpad)


def test_driver_has_no_l1_semantic_dedup_queue_mutator() -> None:
    """After cutover, the old validator branch cannot silently return."""

    source = inspect.getsource(DRIVER._run_phase_validators)
    start = source.find("# --- semantic_dedup (L1)")
    end = source.find("# --- sc_semantic_dedup (SC)")
    legacy = source[start:end] if start >= 0 and end > start else ""
    assert "verification_queue.md" not in legacy
    assert "_write_queue_json_sidecar" not in legacy
    assert "_write_typed_queue_work_items" not in legacy
    assert "ensure_verify_shard_manifests" not in legacy


def test_prequeue_apply_conserves_exact_candidate_partition(
    tmp_path: Path,
) -> None:
    """Every input identity is active or aliases to exactly one active ID."""

    project = tmp_path / "project"
    scratchpad, result = _run(project)

    active = _active_ids(scratchpad)
    aliases = AUTHORITY.load_applied_aliases(scratchpad)
    assert active == {"INV-001", "INV-003"}
    assert aliases == {
        "INV-002": {
            "survivor": "INV-001",
            "coupled": "field-complete-preserved",
        }
    }
    assert set(_inventory_ids := {"INV-001", "INV-002", "INV-003"}) == (
        active | set(aliases)
    )
    assert active.isdisjoint(aliases)
    assert {
        row["survivor"] for row in aliases.values()
    } <= active

    # The absorbed member is not independently queued, but its exact content
    # remains authenticated inside its survivor.
    canonical = (scratchpad / "findings_inventory.md").read_text(
        encoding="utf-8", errors="strict"
    )
    assert "PLAMEN_DEDUP_PRESERVED_MEMBER_BEGIN id=INV-002" in canonical
    assert canonical.count(
        "PLAMEN_DEDUP_PRESERVED_MEMBER_BEGIN id=INV-002"
    ) == 1
    assert not any((scratchpad / name).exists() for name in PUBLIC_QUEUE_NAMES)
    assert result.get("input_candidate_ids") == sorted(_inventory_ids)
    assert result.get("active_candidate_ids") == sorted(active)
    assert result.get("absorbed_candidate_ids") == sorted(aliases)
    _assert_exact_records_projection(scratchpad)

    receipt_raw = (
        scratchpad / AUTHORITY.PRIMARY_RECEIPT_NAME
    ).read_bytes()
    receipt = json.loads(receipt_raw)
    assert set(receipt["input_artifact"]["finding_ids"]) == _inventory_ids
    assert set(receipt["output_artifact"]["finding_ids"]) == active
    assert set(receipt["accepted_absorbed_ids"]) == set(aliases)
    assert (
        set(receipt["input_artifact"]["finding_ids"])
        == set(receipt["output_artifact"]["finding_ids"])
        | set(receipt["accepted_absorbed_ids"])
    )
    assert not (
        set(receipt["output_artifact"]["finding_ids"])
        & set(receipt["accepted_absorbed_ids"])
    )

    generation, manifest = _transaction_generation(scratchpad, result)
    pre_inventory = (generation / "b0.bin").read_bytes()
    pre_records = (generation / "b1.bin").read_bytes()
    post_inventory = (generation / "a0.bin").read_bytes()
    post_records = (generation / "a1.bin").read_bytes()
    assert pre_inventory == _inventory().encode("utf-8")
    assert pre_records == derive_preverify_finding_records_bytes(pre_inventory)
    assert post_inventory == (
        scratchpad / "findings_inventory.md"
    ).read_bytes()
    assert post_records == (scratchpad / "finding_records.json").read_bytes()
    sidecars = _staged_sidecars(generation, manifest)
    assert sidecars[AUTHORITY.PRIMARY_RECEIPT_NAME] == receipt_raw
    absorbed_map_raw = (scratchpad / "dedup_absorbed_map.md").read_bytes()
    deduped_raw = (
        scratchpad / "findings_inventory_deduped.md"
    ).read_bytes()
    assert sidecars["dedup_absorbed_map.md"] == absorbed_map_raw
    assert deduped_raw == post_inventory
    assert sidecars["findings_inventory_deduped.md"] == deduped_raw
    manifest_text = json.dumps(manifest, sort_keys=True)
    for raw in (
        pre_inventory,
        pre_records,
        post_inventory,
        post_records,
        receipt_raw,
        absorbed_map_raw,
        deduped_raw,
    ):
        assert _sha(raw) in manifest_text
    assert RUN_ID in manifest_text
    assert "semantic_dedup" in manifest_text
    assert str(result["generation_digest"]) in manifest_text
    for logical in (
        AUTHORITY.PRIMARY_RECEIPT_NAME,
        "dedup_absorbed_map.md",
        "findings_inventory_deduped.md",
    ):
        assert logical in manifest_text
    committed = (
        scratchpad
        / TRANSACTION_ROOT
        / f"c_{result['generation_digest']}.json"
    )
    assert committed.is_file()
    assert not (scratchpad / TRANSACTION_ROOT / "p.json").exists()

    ledger = read_artifact_ledger(scratchpad)
    binding = ledger.get("artifact_bindings", {}).get(
        "scratchpad:findings_inventory.md"
    )
    assert isinstance(binding, Mapping)
    assert str(binding.get("owner_key") or "").endswith(
        f"/semantic_dedup/{APPLY_WORK_UNIT}"
    )
    work_unit = ledger["work_units"][str(binding["owner_key"])]
    prestates = work_unit["output_prestates"]
    assert prestates["scratchpad:findings_inventory.md"]["status"] == (
        "ACTIVE_REGISTERED_PREDECESSOR"
    )
    assert prestates["scratchpad:finding_records.json"]["status"] == (
        "ACTIVE_REGISTERED_PREDECESSOR"
    )
    assert prestates["scratchpad:findings_inventory.md"]["sha256"] == _sha(
        pre_inventory
    )
    assert prestates["scratchpad:finding_records.json"]["sha256"] == _sha(
        pre_records
    )
    for name in ROOT_OUTPUT_NAMES[2:]:
        assert prestates["scratchpad:" + name]["status"] == "ABSENT"


def test_prequeue_apply_is_byte_idempotent_and_does_not_compound_cards(
    tmp_path: Path,
) -> None:
    """Resume/retry returns the accepted generation without a second rewrite."""

    project = tmp_path / "project"
    scratchpad, _first = _run(project)
    before = _semantic_snapshot(scratchpad)
    config = {
        "pipeline": "l1",
        "mode": "thorough",
        "language": "rust",
        "ecosystem": "rust",
        "backend": "claude",
        "cli_backend": "claude",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": RUN_ID,
    }

    second = _required_apply()(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )

    assert second.get("state") in {"COMMITTED", "ALREADY_COMMITTED"}
    assert second.get("safe_to_consume") is True
    assert second.get("recovered") is True or (
        second.get("state") == "ALREADY_COMMITTED"
    )
    assert _semantic_snapshot(scratchpad) == before
    canonical = (scratchpad / "findings_inventory.md").read_text(
        encoding="utf-8", errors="strict"
    )
    assert canonical.count(
        "PLAMEN_DEDUP_PRESERVED_MEMBER_BEGIN id=INV-002"
    ) == 1


def test_prequeue_keep_only_is_exact_passthrough_without_queue_bytes(
    tmp_path: Path,
) -> None:
    """A precision veto keeps all candidates and never needs a queue rewrite."""

    project = tmp_path / "project"
    scratchpad, config = _seed(project, merge=False)
    before = (scratchpad / "findings_inventory.md").read_bytes()

    result = _required_apply()(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )

    assert result.get("safe_to_consume") is True
    assert (scratchpad / "findings_inventory.md").read_bytes() == before
    assert _active_ids(scratchpad) == {"INV-001", "INV-002", "INV-003"}
    _assert_exact_records_projection(scratchpad)
    assert AUTHORITY.load_applied_aliases(scratchpad) == {}
    assert not any((scratchpad / name).exists() for name in PUBLIC_QUEUE_NAMES)
    generation, manifest = _transaction_generation(scratchpad, result)
    assert (generation / "b0.bin").read_bytes() == before
    assert (generation / "a0.bin").read_bytes() == before
    assert _staged_sidecars(generation, manifest)[
        AUTHORITY.PRIMARY_RECEIPT_NAME
    ] == (scratchpad / AUTHORITY.PRIMARY_RECEIPT_NAME).read_bytes()


def test_mutation_current_pair_is_bound_as_one_exact_prestate_generation(
    tmp_path: Path,
) -> None:
    """A valid same-run semantic chain is current authority, not raw drift."""

    project = tmp_path / "project"
    scratchpad, result = _run(project, mutation_current=True)
    generation, manifest = _transaction_generation(scratchpad, result)
    pre_inventory = (generation / "b0.bin").read_bytes()
    pre_records = (generation / "b1.bin").read_bytes()
    assert pre_inventory.endswith(
        b"<!-- fixture-authorized-current-generation -->\n"
    )
    assert pre_records == derive_preverify_finding_records_bytes(pre_inventory)

    ledger = read_artifact_ledger(scratchpad)
    owner = ledger["artifact_bindings"][
        "scratchpad:findings_inventory.md"
    ]["owner_key"]
    unit = ledger["work_units"][owner]
    prestates = unit["output_prestates"]
    manifest_text = json.dumps(manifest, sort_keys=True)
    for identity, expected in {
        "scratchpad:findings_inventory.md": pre_inventory,
        "scratchpad:finding_records.json": pre_records,
    }.items():
        row = prestates[identity]
        assert row["status"] == "ACTIVE_REGISTERED_SEMANTIC_PREDECESSOR"
        assert row["sha256"] == _sha(expected)
        authority = row["semantic_predecessor_authority"]
        assert authority["authority_digest"]
        assert authority["mutation_event_ids"]
        assert authority["mutation_authority_digests"]
        assert authority["live_sha256"] == _sha(expected)
        assert authority["authority_digest"] in manifest_text
        for event_id in authority["mutation_event_ids"]:
            assert event_id in manifest_text
    _assert_exact_records_projection(scratchpad)


def test_unarmed_canonical_pair_drift_cannot_become_a_new_preimage(
    tmp_path: Path,
) -> None:
    """Raw bytes never replace a registered or semantic-current producer."""

    project = tmp_path / "project"
    scratchpad, config = _seed(project)
    records = scratchpad / "finding_records.json"
    records.write_bytes(records.read_bytes() + b"\nUNARMED-DRIFT\n")
    before = {
        name: (scratchpad / name).read_bytes()
        for name in ("findings_inventory.md", "finding_records.json")
    }

    with pytest.raises(
        Exception,
        match="(?i)prestate|preimage|authority|producer|input",
    ):
        _required_apply()(
            scratchpad=scratchpad,
            project_root=project,
            config=config,
            run_id=RUN_ID,
        )
    for name, raw in before.items():
        assert (scratchpad / name).read_bytes() == raw
    transaction = scratchpad / TRANSACTION_ROOT
    assert not transaction.exists() or not any(transaction.glob("g_*"))


@pytest.mark.parametrize("boundary", CRASH_BOUNDARIES)
def test_crash_at_every_transaction_boundary_recovers_exact_pair(
    tmp_path: Path,
    boundary: str,
) -> None:
    """Recovery accepts only the signed before/after pair lattice."""

    project = tmp_path / "project"
    scratchpad, config = _seed(project)
    before = {
        name: (
            (scratchpad / name).read_bytes()
            if (scratchpad / name).is_file()
            else None
        )
        for name in ROOT_OUTPUT_NAMES
    }

    def crash(label: str) -> None:
        if label == boundary:
            raise RuntimeError(f"fixture-crash:{label}")

    with pytest.raises(RuntimeError, match="fixture-crash"):
        _required_apply()(
            scratchpad=scratchpad,
            project_root=project,
            config=config,
            run_id=RUN_ID,
            fault_hook=crash,
        )

    generations = sorted(
        (scratchpad / TRANSACTION_ROOT).glob("g_*")
    ) if (scratchpad / TRANSACTION_ROOT).is_dir() else []
    postimages: dict[str, bytes] = {}
    if generations:
        assert len(generations) == 1
        manifest = json.loads((generations[0] / "i.json").read_bytes())
        postimages = {
            "findings_inventory.md": (
                generations[0] / "a0.bin"
            ).read_bytes(),
            "finding_records.json": (
                generations[0] / "a1.bin"
            ).read_bytes(),
            **_staged_sidecars(generations[0], manifest),
        }
        assert set(ROOT_OUTPUT_NAMES) <= set(postimages)
    for name in ROOT_OUTPUT_NAMES:
        current = (
            (scratchpad / name).read_bytes()
            if (scratchpad / name).is_file()
            else None
        )
        allowed = {before[name]}
        if name in postimages:
            allowed.add(postimages[name])
        assert current in allowed

    ledger = read_artifact_ledger(scratchpad)
    apply_key = canonical_work_unit_key(
        "l1",
        "thorough",
        "rust",
        "claude",
        "semantic_dedup",
        APPLY_WORK_UNIT,
    )
    before_terminal_commit = (
        CRASH_BOUNDARIES.index(boundary)
        < CRASH_BOUNDARIES.index("AFTER_PHASEIO_COMMIT")
    )
    if before_terminal_commit:
        for identity in (
            "scratchpad:findings_inventory.md",
            "scratchpad:finding_records.json",
        ):
            assert ledger["artifact_bindings"][identity][
                "owner_key"
            ].endswith("/inventory/canonical_aggregate")
        if apply_key in ledger["work_units"]:
            assert ledger["work_units"][apply_key].get(
                "execution_state"
            ) != "OUTPUT_COMMITTED"
        for name in ROOT_OUTPUT_NAMES[2:]:
            identity = "scratchpad:" + name
            if before[name] is None:
                assert identity not in ledger["artifact_bindings"]
    else:
        assert generations, "terminal commit cannot precede durable postimages"
        for name in ROOT_OUTPUT_NAMES:
            identity = "scratchpad:" + name
            binding = ledger["artifact_bindings"][identity]
            assert binding["owner_key"] == apply_key
            assert binding["sha256"] == _sha(postimages[name])
        assert ledger["work_units"][apply_key][
            "execution_state"
        ] == "OUTPUT_COMMITTED"

    resumed = _required_apply()(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )
    assert resumed.get("safe_to_consume") is True
    assert resumed.get("state") in {
        "COMMITTED",
        "OUTPUT_COMMITTED",
        "ALREADY_COMMITTED",
    }
    assert isinstance(resumed.get("recovered"), bool)
    _assert_exact_records_projection(scratchpad)
    assert not (scratchpad / TRANSACTION_ROOT / "p.json").exists()
    generation, manifest = _transaction_generation(scratchpad, resumed)
    final_postimages = {
        "findings_inventory.md": (generation / "a0.bin").read_bytes(),
        "finding_records.json": (generation / "a1.bin").read_bytes(),
        **_staged_sidecars(generation, manifest),
    }
    final_ledger = read_artifact_ledger(scratchpad)
    for name in ROOT_OUTPUT_NAMES:
        assert (scratchpad / name).read_bytes() == final_postimages[name]
        assert final_ledger["artifact_bindings"][
            "scratchpad:" + name
        ]["owner_key"] == apply_key
    stable = _semantic_snapshot(scratchpad)
    replay = _required_apply()(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )
    assert replay.get("safe_to_consume") is True
    assert _semantic_snapshot(scratchpad) == stable


def test_open_transaction_rejects_proposal_drift_without_pair_mutation(
    tmp_path: Path,
) -> None:
    """A proposal changed after staging cannot authorize the old postimage."""

    project = tmp_path / "project"
    scratchpad, config = _seed(project)
    before = {
        name: (scratchpad / name).read_bytes()
        for name in ("findings_inventory.md", "finding_records.json")
    }

    def crash(label: str) -> None:
        if label == "AFTER_PENDING_STAGED_DURABLE":
            raise RuntimeError("fixture-crash")

    with pytest.raises(RuntimeError):
        _required_apply()(
            scratchpad=scratchpad,
            project_root=project,
            config=config,
            run_id=RUN_ID,
            fault_hook=crash,
        )
    (scratchpad / "dedup_decisions.md").write_text(
        "# Semantic Dedup Decisions\n\n"
        "KEEP: INV-001\nKEEP: INV-002\nKEEP: INV-003\n",
        encoding="utf-8",
    )

    with pytest.raises(
        Exception,
        match="(?i)input|proposal|drift|changed",
    ):
        _required_apply()(
            scratchpad=scratchpad,
            project_root=project,
            config=config,
            run_id=RUN_ID,
        )
    for name, raw in before.items():
        assert (scratchpad / name).read_bytes() == raw


def test_canonical_prestate_drift_after_arm_cannot_reach_terminal_commit(
    tmp_path: Path,
) -> None:
    """Arm-time authority is revalidated before any staged postimage lands."""

    project = tmp_path / "project"
    scratchpad, config = _seed(project)

    def crash(label: str) -> None:
        if label == "AFTER_PHASEIO_ARM":
            raise RuntimeError("fixture-crash")

    with pytest.raises(RuntimeError):
        _required_apply()(
            scratchpad=scratchpad,
            project_root=project,
            config=config,
            run_id=RUN_ID,
            fault_hook=crash,
        )
    inventory = scratchpad / "findings_inventory.md"
    inventory.write_bytes(inventory.read_bytes() + b"\nUNARMED-TOCTOU\n")
    before_recovery = {
        name: (scratchpad / name).read_bytes()
        for name in ("findings_inventory.md", "finding_records.json")
    }

    with pytest.raises(
        Exception,
        match="(?i)prestate|preimage|authority|input|third|changed",
    ):
        _required_apply()(
            scratchpad=scratchpad,
            project_root=project,
            config=config,
            run_id=RUN_ID,
        )
    for name, raw in before_recovery.items():
        assert (scratchpad / name).read_bytes() == raw
    ledger = read_artifact_ledger(scratchpad)
    apply_key = canonical_work_unit_key(
        "l1",
        "thorough",
        "rust",
        "claude",
        "semantic_dedup",
        APPLY_WORK_UNIT,
    )
    assert ledger["work_units"][apply_key][
        "execution_state"
    ] != "OUTPUT_COMMITTED"
    assert ledger["artifact_bindings"][
        "scratchpad:findings_inventory.md"
    ]["owner_key"].endswith("/inventory/canonical_aggregate")


@pytest.mark.parametrize(
    ("boundary", "relative"),
    (
        ("AFTER_GENERATION_DURABLE", "i.json"),
        ("AFTER_GENERATION_DURABLE", "a1.bin"),
        ("AFTER_PENDING_STAGED_DURABLE", "../p.json"),
    ),
)
def test_open_transaction_rejects_manifest_postimage_or_pending_tamper(
    tmp_path: Path,
    boundary: str,
    relative: str,
) -> None:
    project = tmp_path / "project"
    scratchpad, config = _seed(project)

    def crash(label: str) -> None:
        if label == boundary:
            raise RuntimeError("fixture-crash")

    with pytest.raises(RuntimeError):
        _required_apply()(
            scratchpad=scratchpad,
            project_root=project,
            config=config,
            run_id=RUN_ID,
            fault_hook=crash,
        )
    generations = sorted((scratchpad / TRANSACTION_ROOT).glob("g_*"))
    assert len(generations) == 1
    target = (
        scratchpad / TRANSACTION_ROOT / "p.json"
        if relative == "../p.json"
        else generations[0] / relative
    )
    target.write_bytes(target.read_bytes() + b"\nTAMPER\n")
    before_recovery = {
        name: (scratchpad / name).read_bytes()
        for name in ("findings_inventory.md", "finding_records.json")
    }

    with pytest.raises(
        Exception,
        match="(?i)tamper|digest|manifest|pending|stale|conflict|generation",
    ):
        _required_apply()(
            scratchpad=scratchpad,
            project_root=project,
            config=config,
            run_id=RUN_ID,
        )
    for name, raw in before_recovery.items():
        assert (scratchpad / name).read_bytes() == raw


def test_mixed_pair_third_state_is_recovery_debt_and_never_self_heals(
    tmp_path: Path,
) -> None:
    """Recovery cannot choose a winner after an out-of-lattice records write."""

    project = tmp_path / "project"
    scratchpad, config = _seed(project)

    def crash(label: str) -> None:
        if label == "AFTER_INVENTORY_REPLACED":
            raise RuntimeError("fixture-crash")

    with pytest.raises(RuntimeError):
        _required_apply()(
            scratchpad=scratchpad,
            project_root=project,
            config=config,
            run_id=RUN_ID,
            fault_hook=crash,
        )
    arbitrary = (
        (scratchpad / "finding_records.json").read_bytes()
        + b"\nARBITRARY-THIRD-STATE\n"
    )
    (scratchpad / "finding_records.json").write_bytes(arbitrary)
    before_recovery = {
        name: (scratchpad / name).read_bytes()
        for name in ("findings_inventory.md", "finding_records.json")
    }

    with pytest.raises(Exception, match="(?i)outside|third|state|pair"):
        _required_apply()(
            scratchpad=scratchpad,
            project_root=project,
            config=config,
            run_id=RUN_ID,
        )
    for name, raw in before_recovery.items():
        assert (scratchpad / name).read_bytes() == raw
    assert (scratchpad / TRANSACTION_ROOT / "p.json").is_file()


@pytest.mark.parametrize(
    ("boundary", "logical"),
    (
        (
            "AFTER_APPLIED_RECEIPT_REPLACED",
            AUTHORITY.PRIMARY_RECEIPT_NAME,
        ),
        ("AFTER_ABSORBED_MAP_REPLACED", "dedup_absorbed_map.md"),
        (
            "AFTER_DEDUPED_INVENTORY_REPLACED",
            "findings_inventory_deduped.md",
        ),
    ),
)
def test_sidecar_third_state_is_recovery_debt_and_byte_preserved(
    tmp_path: Path,
    boundary: str,
    logical: str,
) -> None:
    """Every public sidecar obeys the same before/after recovery lattice."""

    project = tmp_path / "project"
    scratchpad, config = _seed(project)

    def crash(label: str) -> None:
        if label == boundary:
            raise RuntimeError("fixture-crash")

    with pytest.raises(RuntimeError):
        _required_apply()(
            scratchpad=scratchpad,
            project_root=project,
            config=config,
            run_id=RUN_ID,
            fault_hook=crash,
        )
    target = scratchpad / logical
    assert target.is_file()
    target.write_bytes(target.read_bytes() + b"\nARBITRARY-THIRD-STATE\n")
    before_recovery = {
        name: (
            (scratchpad / name).read_bytes()
            if (scratchpad / name).is_file()
            else None
        )
        for name in ROOT_OUTPUT_NAMES
    }

    with pytest.raises(
        Exception,
        match="(?i)outside|third|state|sidecar|lattice",
    ):
        _required_apply()(
            scratchpad=scratchpad,
            project_root=project,
            config=config,
            run_id=RUN_ID,
        )
    for name, raw in before_recovery.items():
        path = scratchpad / name
        assert path.is_file() is (raw is not None)
        if raw is not None:
            assert path.read_bytes() == raw
    assert (scratchpad / TRANSACTION_ROOT / "p.json").is_file()
