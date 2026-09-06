"""Red acceptance fixtures for the live verify-queue producer closure.

These fixtures exercise production authority rules over states a real driver
run creates immediately before the live T0--T9 cutover.  They must not weaken
strict producer validation: the intended fix is a current-run PhaseIO
successor/canonicalization work unit which owns the exact post-mutation bytes.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from artifact_ledger import (
    arm_semantic_mutation,
    finalize_semantic_mutation,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    semantic_input_prebind_producer_authority_issues,
)
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
import live_verify_queue_semantics as SEMANTICS
import plamen_mechanical as MECHANICAL
import plamen_driver as DRIVER
import test_live_verify_queue_sc_prearm_dynamic_inputs as PREARM
import test_live_verify_queue_driver_adapter_cutover as ADAPTER
import test_live_verify_queue_main_boundary_a0 as MAIN_BOUNDARY
import verify_queue_transaction as TRANSACTION


SUCCESSOR_NAMES = (
    "preverify_inventory_successor.json",
    "finding_delivery_successor.json",
)
SUCCESSOR_IDENTITIES = tuple(
    "scratchpad:" + name for name in SUCCESSOR_NAMES
)
SUCCESSOR_OWNER = (
    "sc/thorough/evm/claude/sc_verify_queue/preverify_successors"
)


def _semantic_mutate(
    root: Path,
    project: Path,
    *,
    relative: str,
    run_id: str,
    raw: bytes,
    kind: str,
    affected_record_ids: tuple[str, ...],
) -> bytes:
    event = arm_semantic_mutation(
        root,
        project,
        artifact_identity="scratchpad:" + relative,
        mutation_kind=kind,
        run_id=run_id,
    )
    (root / relative).write_text(
        raw.decode("utf-8", errors="strict"),
        encoding="utf-8",
    )
    persisted = (root / relative).read_bytes()
    finalize_semantic_mutation(
        root,
        project,
        str(event["event_id"]),
        run_id=run_id,
        affected_record_ids=affected_record_ids,
    )
    return persisted


def _t0_bundle(root: Path) -> dict:
    return json.loads(
        (
            root
            / "_live_verify_queue_transaction"
            / "t0"
            / "input_bundle.json"
        ).read_text(encoding="utf-8", errors="strict")
    )


def _bundle_bytes(bundle: dict, relative: str) -> bytes:
    return SEMANTICS._decode_bytes_row(
        bundle["files"].get(relative),
        "fixture T0 logical input " + relative,
    )


def _claim_exact_optional(
    root: Path,
    project: Path,
    *,
    relative: str,
    raw: bytes,
    run_id: str,
    phase: str,
    work_unit_id: str,
    write_mode: str = "REPLACE",
) -> None:
    """Publish one fixture optional under the intended exact producer owner."""

    pipeline = "sc"
    mode = "thorough"
    ecosystem = "evm"
    backend = "claude"
    owner = canonical_work_unit_key(
        pipeline,
        mode,
        ecosystem,
        backend,
        phase,
        work_unit_id,
    )
    contract = PhaseIOContract(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase=phase,
        work_unit_id=work_unit_id,
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path=relative,
                owner_key=owner,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode=write_mode,
                schema_version="fixture.producer-closure.v1",
                minimum_gate="FIXTURE_EXACT_BYTES",
                consumers=(
                    "sc_verify_queue/prearm_presence_authority",
                    "sc_verify_queue/t0.live_upstream_authority",
                ),
            ),
        ),
        immutable_inputs=(),
        bounded_lookup_inputs=(),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        model="fixture-driver",
        timeout_s=60,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
    )
    (root / relative).write_bytes(raw)
    record_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    )


def _reset_fixture_upstream_owners(
    root: Path,
    project: Path,
    config: dict,
    run_id: str,
    *,
    exclude: tuple[str, ...],
) -> None:
    """Rebuild the adapter fixture ledger without selected optional owners."""

    (root / "_artifact_state.json").unlink(missing_ok=True)
    present = tuple(
        relative
        for relative in sorted({
            *ADAPTER.LIVE._upstream_inputs("sc"),
            "findings_inventory.md",
            "hypotheses.md",
            "finding_mapping.md",
        })
        if relative not in set(exclude) and (root / relative).is_file()
    )
    ADAPTER._claim_group(
        root=root,
        project=project,
        config=config,
        run_id=run_id,
        paths=present,
        work_unit_id="current_run_upstream_without_selected_optionals",
    )


def _claim_chain_canonical_pair(
    root: Path,
    project: Path,
    *,
    hypotheses: bytes,
    mapping: bytes,
    run_id: str,
) -> None:
    """Publish the hypothesis/mapping postimage as one atomic work unit."""

    owner = canonical_work_unit_key(
        "sc",
        "thorough",
        "evm",
        "claude",
        "chain",
        "model",
    )
    outputs = {
        "hypotheses.md": hypotheses,
        "finding_mapping.md": mapping,
        "enabler_results.md": (root / "enabler_results.md").read_bytes(),
    }
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="chain",
        work_unit_id="model",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=relative,
                owner_key=owner,
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="CREATE",
                schema_version="fixture.chain-canonical-pair.v1",
                minimum_gate="ATOMIC_HYPOTHESIS_MAPPING_PAIR",
                consumers=(
                    "sc_verify_queue/prearm_presence_authority",
                    "sc_verify_queue/t0.live_upstream_authority",
                ),
            )
            for relative in outputs
        ),
        immutable_inputs=(),
        bounded_lookup_inputs=(),
        model_invoked=True,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        model="fixture-model",
        timeout_s=60,
        exec_mode="pty",
        tool_policy=("filesystem",),
    )
    for relative in outputs:
        (root / relative).unlink(missing_ok=True)
    record_work_unit_inputs(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
    )
    for relative, raw in outputs.items():
        (root / relative).write_bytes(raw)
    record_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        actor="MODEL",
    )


def _finalize_authentic_preverify_successors(
    root: Path,
    project: Path,
    config: dict,
    run_id: str,
) -> dict:
    """Run the real production prequeue projection/finalization chronology."""

    assert not any((root / name).exists() for name in SUCCESSOR_NAMES)
    chain_projection = DRIVER.prepare_preverify_chain_pair_projection(
        scratchpad=root,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase_name="sc_verify_queue",
        run_id=run_id,
    )
    assert chain_projection["state"] == "OUTPUT_COMMITTED"
    assert chain_projection["debt"] == []
    frozen_projection = DRIVER.prepare_preverify_frozen_projection(
        scratchpad=root,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase_name="sc_verify_queue",
        run_id=run_id,
        chain_pair_projection=chain_projection,
    )
    assert frozen_projection["state"] == "OUTPUT_COMMITTED"
    assert DRIVER._finalize_preverify_inventory_successors(
        root,
        config,
        phase_name="sc_verify_queue",
        frozen_projection=frozen_projection,
    ) == []
    return frozen_projection


def _assert_authentic_preverify_successor_authority(
    root: Path,
    project: Path,
    run_id: str,
) -> dict:
    """Require one exact current-run atomic successor owner and prebind."""

    ledger = read_artifact_ledger(root)
    unit = ledger["work_units"][SUCCESSOR_OWNER]
    assert unit["run_id"] == run_id
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["model_invoked"] is False
    assert unit["commit_authority"]["attempt_ordinal"] == 1
    assert unit["commit_authority"]["receipt_digest"]
    assert set(unit["artifacts"]) == set(SUCCESSOR_IDENTITIES)
    assert all(
        unit["artifacts"][identity]["status"] == "ACTIVE"
        and unit["artifacts"][identity]["writer"] == "DRIVER"
        and unit["artifacts"][identity]["owner_key"] == SUCCESSOR_OWNER
        and unit["artifacts"][identity]["run_id"] == run_id
        for identity in SUCCESSOR_IDENTITIES
    )
    assert semantic_input_prebind_producer_authority_issues(
        root,
        project,
        SUCCESSOR_IDENTITIES,
        run_id=run_id,
    ) == []
    return ledger


def test_queue_time_inventory_mutation_has_current_run_phaseio_successor(
    tmp_path,
) -> None:
    """Recall-additive queue prework must remain consumable by strict T0.

    ``_promote_findings_with_semantic_invalidation`` deliberately records a
    semantic-mutation transition.  That transition authenticates the byte
    change but does not provide T0's required owner/writer/run/contract/launch
    producer tuple.  Before the adapter captures its presence roster, a
    current-run PhaseIO successor must therefore canonicalize/rebind the exact
    final inventory bytes.
    """

    project = tmp_path / "project"
    project.mkdir()
    root, config, run_id = MAIN_BOUNDARY._seed(
        project,
        pipeline="sc",
        backend="claude",
        preseed_adapter_successors=False,
    )
    assert not any((root / name).exists() for name in SUCCESSOR_NAMES)

    inventory = root / "findings_inventory.md"
    event = arm_semantic_mutation(
        root,
        project,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="FINDING_PROMOTION",
        run_id=run_id,
    )
    inventory.write_text(
        "# Finding Inventory\n\n"
        "### Finding [INV-001]: Fixture recall candidate\n"
        "**Severity**: Medium\n"
        "**Location**: contracts/Fixture.sol:L1\n"
        "**Preferred Tag**: [CODE-TRACE]\n"
        "**Source IDs**: DCI-1\n"
        "**Primary Artifact**: depth_consensus_invariant_findings.md\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
        "**Root Cause**: exact fixture mechanism\n"
        "**Description**: exact fixture mechanism remains candidate-bearing\n"
        "**Impact**: material effect if confirmed\n",
        encoding="utf-8",
    )
    finalize_semantic_mutation(
        root,
        project,
        str(event["event_id"]),
        run_id=run_id,
        affected_record_ids=("INV-001",),
    )

    records_event = arm_semantic_mutation(
        root,
        project,
        artifact_identity="scratchpad:finding_records.json",
        mutation_kind="FINDING_RECORDS_RECONCILIATION",
        run_id=run_id,
    )
    assert DRIVER._write_finding_records_from_inventory(root) == 1
    finalize_semantic_mutation(
        root,
        project,
        str(records_event["event_id"]),
        run_id=run_id,
        affected_record_ids=("INV-001",),
    )

    # The lower-level adapter begins after successor finalization.  A separate
    # otherwise-authentic pre-finalizer root proves that entering it directly
    # with the pair absent remains a hard prearm rejection and cannot publish
    # any T0--T9 public artifact.  Keep that failed arm off the positive root:
    # its exact missing-input denominator is intentionally not replayable after
    # the pair exists.
    absent_project = tmp_path / "absent-successor-project"
    absent_project.mkdir()
    absent_root, absent_config, absent_run_id = MAIN_BOUNDARY._seed(
        absent_project,
        pipeline="sc",
        backend="claude",
        preseed_adapter_successors=False,
    )
    with pytest.raises(
        ADAPTER._error_type(),
        match="preverify_inventory_successor|finding_delivery_successor",
    ):
        ADAPTER._invoke(
            absent_root,
            absent_project,
            absent_config,
            absent_run_id,
        )
    assert ADAPTER._public_bytes(absent_root, "sc") == {}

    frozen_projection = _finalize_authentic_preverify_successors(
        root,
        project,
        config,
        run_id,
    )

    ledger = _assert_authentic_preverify_successor_authority(
        root, project, run_id
    )
    unit = ledger["work_units"][SUCCESSOR_OWNER]
    assert unit["work_unit_key"] == SUCCESSOR_OWNER
    assert unit["run_id"] == run_id
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["model_invoked"] is False
    assert unit["commit_authority"]["attempt_ordinal"] == 1
    assert unit["commit_authority"]["run_id"] == run_id
    assert unit["commit_authority"]["work_unit_key"] == SUCCESSOR_OWNER
    assert unit["commit_authority"]["receipt_digest"]
    assert unit["contract_digest"] == unit["commit_authority"][
        "contract_digest"
    ]
    assert unit["launch_digest"] == unit["commit_authority"][
        "launch_digest"
    ]
    assert {
        row["identity"] for row in unit["contract_manifest"]["outputs"]
    } == set(SUCCESSOR_IDENTITIES)
    assert unit["commit_authority"]["recorded_output_identities"] == list(
        sorted(SUCCESSOR_IDENTITIES)
    )
    assert len(unit["input_bindings"]) == 1
    capture = next(iter(unit["input_bindings"].values()))
    assert capture["status"] == "ACTIVE"
    assert capture["producer_run_id"] == run_id
    assert capture["producer_work_unit_key"].startswith(
        "sc/thorough/evm/claude/sc_verify_queue/preverify_capture."
    )
    for identity in SUCCESSOR_IDENTITIES:
        record = unit["artifacts"][identity]
        binding = ledger["artifact_bindings"][identity]
        legacy = ledger["artifacts"][identity.split(":", 1)[1]]
        assert record["owner_key"] == SUCCESSOR_OWNER
        assert record["run_id"] == run_id
        assert record["writer"] == "DRIVER"
        assert record["status"] == "ACTIVE"
        assert record["authority_level"] == "ACTIVE_AUTHORITY"
        for field in (
            "owner_key",
            "run_id",
            "contract_digest",
            "launch_digest",
            "status",
            "size",
            "sha256",
            "authority_level",
        ):
            assert binding[field] == record[field]
            assert legacy[field] == record[field]
    assert semantic_input_prebind_producer_authority_issues(
        root,
        project,
        SUCCESSOR_IDENTITIES,
        run_id=run_id,
    ) == []
    assert all(
        not set(SUCCESSOR_IDENTITIES).intersection(
            row.get("artifacts", {})
        )
        for key, row in ledger["work_units"].items()
        if key != SUCCESSOR_OWNER
    )

    frozen_inventory = (
        root
        / frozen_projection["logical_to_physical"][
            "findings_inventory.md"
        ]
    ).read_bytes()
    successor = json.loads(
        (root / SUCCESSOR_NAMES[0]).read_text(
            encoding="utf-8", errors="strict"
        )
    )
    delivery = json.loads(
        (root / SUCCESSOR_NAMES[1]).read_text(
            encoding="utf-8", errors="strict"
        )
    )
    assert successor["run_id"] == run_id
    assert successor["inventory_sha256"] == SEMANTICS._sha(
        frozen_inventory
    )
    assert delivery["run_id"] == run_id
    assert delivery["inventory_sha256"] == successor["inventory_sha256"]
    assert delivery["final_inventory_receipt_digest"] == successor[
        "receipt_digest"
    ]

    pair_bytes = {
        name: (root / name).read_bytes() for name in SUCCESSOR_NAMES
    }
    unit_before_replay = unit
    assert DRIVER._finalize_preverify_inventory_successors(
        root,
        config,
        phase_name="sc_verify_queue",
        frozen_projection=frozen_projection,
    ) == []
    assert {
        name: (root / name).read_bytes() for name in SUCCESSOR_NAMES
    } == pair_bytes
    assert read_artifact_ledger(root)["work_units"][SUCCESSOR_OWNER] == (
        unit_before_replay
    )

    # Exact bytes alone never repair partial, tampered, or foreign-run input
    # authority.  Restore the authentic pair only after observing rejection.
    tampered = root / SUCCESSOR_NAMES[0]
    tampered.write_bytes(pair_bytes[SUCCESSOR_NAMES[0]] + b"\n")
    assert semantic_input_prebind_producer_authority_issues(
        root,
        project,
        SUCCESSOR_IDENTITIES,
        run_id=run_id,
    )
    tampered.write_bytes(pair_bytes[SUCCESSOR_NAMES[0]])
    assert semantic_input_prebind_producer_authority_issues(
        root,
        project,
        SUCCESSOR_IDENTITIES,
        run_id="foreign-run",
    )
    assert semantic_input_prebind_producer_authority_issues(
        root,
        project,
        SUCCESSOR_IDENTITIES,
        run_id=run_id,
    ) == []

    result = ADAPTER._invoke(root, project, config, run_id)

    ADAPTER._assert_success(
        result,
        root=root,
        project=project,
        pipeline="sc",
        backend="claude",
        run_id=run_id,
    )
    assert _bundle_bytes(
        _t0_bundle(root), "findings_inventory.md"
    ) == frozen_inventory

    public_before_partial = ADAPTER._public_bytes(root, "sc")
    missing = root / SUCCESSOR_NAMES[1]
    missing.unlink()
    assert semantic_input_prebind_producer_authority_issues(
        root,
        project,
        SUCCESSOR_IDENTITIES,
        run_id=run_id,
    )
    assert ADAPTER._public_bytes(root, "sc") == public_before_partial


def test_frozen_preverify_pair_and_evidence_are_staged_under_logical_names(
    tmp_path,
) -> None:
    """RED: final paired bytes must be frozen after all semantic mutation."""

    project = tmp_path / "project"
    project.mkdir()
    root, config, run_id = MAIN_BOUNDARY._seed(
        project,
        pipeline="sc",
        backend="claude",
        preseed_adapter_successors=False,
    )
    assert not any((root / name).exists() for name in SUCCESSOR_NAMES)
    inventory_raw = (
        b"# Finding Inventory\n\n"
        b"### Finding [INV-001]: Fixture recall candidate\n"
        b"**Severity**: Medium\n"
        b"**Location**: contracts/Fixture.sol:L1\n"
        b"**Preferred Tag**: [CODE-TRACE]\n"
        b"**Source IDs**: DCI-1\n"
        b"**Primary Artifact**: depth_consensus_invariant_findings.md\n"
        b"**Verdict**: NEEDS_VERIFICATION\n"
        b"**Root Cause**: exact fixture mechanism\n"
        b"**Description**: exact fixture mechanism remains candidate-bearing\n"
        b"**Impact**: material effect if confirmed\n"
    )
    inventory_raw = _semantic_mutate(
        root,
        project,
        relative="findings_inventory.md",
        run_id=run_id,
        raw=inventory_raw,
        kind="FINDING_PROMOTION",
        affected_record_ids=("INV-001",),
    )

    records_event = arm_semantic_mutation(
        root,
        project,
        artifact_identity="scratchpad:finding_records.json",
        mutation_kind="FINDING_RECORDS_RECONCILIATION",
        run_id=run_id,
    )
    assert MECHANICAL._write_finding_records_from_inventory(root) == 1
    finalize_semantic_mutation(
        root,
        project,
        str(records_event["event_id"]),
        run_id=run_id,
        affected_record_ids=("INV-001",),
    )
    records_raw = (root / "finding_records.json").read_bytes()
    records = json.loads(records_raw)
    assert records["source_sha256"] == SEMANTICS._sha(inventory_raw)

    # Preserve the evidence sibling's original current-run producer.  The
    # seed publishes inventory and evidence atomically; independently mutating
    # both would invalidate that complete producer rather than model the real
    # chronology exercised by the inventory transition.
    evidence_raw = (
        root / "inventory_evidence_validation.md"
    ).read_bytes()
    assert evidence_raw == b"# Inventory Evidence Validation\n\n"

    frozen_projection = _finalize_authentic_preverify_successors(
        root,
        project,
        config,
        run_id,
    )
    _assert_authentic_preverify_successor_authority(
        root,
        project,
        run_id,
    )
    mandatory_logical_bytes = {
        "findings_inventory.md": inventory_raw,
        "finding_records.json": records_raw,
    }
    assert {
        logical: (
            root / frozen_projection["logical_to_physical"][logical]
        ).read_bytes()
        for logical in mandatory_logical_bytes
    } == mandatory_logical_bytes
    assert "inventory_evidence_validation.md" not in (
        frozen_projection["logical_to_physical"]
    )
    assert all(
        "inventory_evidence_validation.md" not in str(relative)
        for relative in frozen_projection["required_paths"]
    )
    assert frozen_projection["debt"] == [{
        "artifact": "inventory_evidence_validation.md",
        "reason_code": "EVIDENCE_PROJECTION_UNAUTHORIZED",
        "authority": "ADVISORY_REPAIR_ONLY",
        "candidate_disposition": "PRESERVE_ALL_FOR_VERIFICATION",
    }]
    assert (
        root / "inventory_evidence_validation.md"
    ).read_bytes() == evidence_raw

    result = ADAPTER._invoke(root, project, config, run_id)
    ADAPTER._assert_success(
        result,
        root=root,
        project=project,
        pipeline="sc",
        backend="claude",
        run_id=run_id,
    )
    bundle = _t0_bundle(root)
    assert _bundle_bytes(bundle, "findings_inventory.md") == inventory_raw
    assert _bundle_bytes(bundle, "finding_records.json") == records_raw
    assert "inventory_evidence_validation.md" not in bundle["files"]
    assert {
        logical: (
            root / frozen_projection["logical_to_physical"][logical]
        ).read_bytes()
        for logical in mandatory_logical_bytes
    } == mandatory_logical_bytes
    assert (
        root / "inventory_evidence_validation.md"
    ).read_bytes() == evidence_raw


@pytest.mark.parametrize(
    "pipeline,dead",
    (
        ("sc", "dedup_decisions.md"),
        ("sc", "chain_equivalence_proposals.json"),
        ("l1", "dedup_decisions.md"),
        ("l1", "l1_composition_fact_worklist.json"),
        ("l1", "l1_composition_fact_records.json"),
    ),
)
def test_context_only_artifacts_are_omitted_from_t0_authorization_roster(
    pipeline: str,
    dead: str,
) -> None:
    """RED: provenance already projected downstream is not T0 authority."""

    assert dead not in set(
        TRANSACTION.live_verify_queue_base_upstream_roster(pipeline)
    )


def test_optional_authority_quarantines_unowned_and_consumes_exact_owner(
    tmp_path,
) -> None:
    """RED: optional presence is tri-state, not absent-or-hard-fail."""

    # Unowned/stale bytes are preserved on disk but excluded from semantics.
    optional = "application_skeptic_proposals.md"
    unowned_project = tmp_path / "unowned"
    unowned_project.mkdir()
    root, config, run_id = ADAPTER._seed(
        unowned_project,
        pipeline="sc",
        backend="claude",
        absent=(optional,),
    )
    assert not (root / optional).exists()
    (root / optional).write_text(
        "# Application Skeptic Proposals\n\nunowned fixture bytes\n",
        encoding="utf-8",
    )
    mandatory = (
        "scratchpad:findings_inventory.md",
        *SUCCESSOR_IDENTITIES,
    )
    assert semantic_input_prebind_producer_authority_issues(
        root,
        unowned_project,
        mandatory,
        run_id=run_id,
    ) == []
    unowned_result = ADAPTER._invoke(
        root,
        unowned_project,
        config,
        run_id,
    )
    unowned_rows = {
        str(row["identity"]): row
        for row in unowned_result["prearm_presence"]["authority"]["entries"]
    }
    assert unowned_rows["scratchpad:" + optional]["state"] == (
        "PRESENT_UNAUTHORIZED_QUARANTINED"
    )
    assert optional not in _t0_bundle(root)["files"]
    assert "QUARANTINED" in json.dumps(
        unowned_result,
        sort_keys=True,
    )

    # Overwriting an optional input already owned by the shared seed producer
    # poisons that producer's complete output authority.  It must fail closed,
    # rather than mask the mandatory siblings as a benign quarantine.
    masked_project = tmp_path / "masked-shared-owner"
    masked_project.mkdir()
    masked_root, masked_config, masked_run_id = ADAPTER._seed(
        masked_project,
        pipeline="sc",
        backend="claude",
    )
    (masked_root / optional).write_text(
        "# Application Skeptic Proposals\n\nmasked shared-owner bytes\n",
        encoding="utf-8",
    )
    assert semantic_input_prebind_producer_authority_issues(
        masked_root,
        masked_project,
        mandatory,
        run_id=masked_run_id,
    )
    with pytest.raises(ADAPTER._error_type(), match="semantic input"):
        ADAPTER._invoke(
            masked_root,
            masked_project,
            masked_config,
            masked_run_id,
        )
    assert ADAPTER._public_bytes(masked_root, "sc") == {}

    # The exact policy owner remains a live semantic input.
    owned_project = tmp_path / "owned"
    owned_project.mkdir()
    root, config, run_id = ADAPTER._seed(
        owned_project,
        pipeline="sc",
        backend="claude",
        absent=(optional,),
    )
    owned_raw = (
        b"# Application Skeptic Proposals\n\n"
        b"fixture policy-owned optional input\n"
    )
    _claim_exact_optional(
        root,
        owned_project,
        relative=optional,
        raw=owned_raw,
        run_id=run_id,
        phase="application_skeptic",
        work_unit_id="reconcile",
        write_mode="CREATE",
    )
    owned_result = ADAPTER._invoke(root, owned_project, config, run_id)
    owned_rows = {
        str(row["identity"]): row
        for row in owned_result["prearm_presence"]["authority"]["entries"]
    }
    assert owned_rows["scratchpad:" + optional]["state"] == (
        "PRESENT_AUTHORIZED"
    )
    assert _bundle_bytes(_t0_bundle(root), optional) == owned_raw


def test_sc_identity_denominator_enters_t0_only_through_prearm_manifest(
    tmp_path,
) -> None:
    """RED: the identity map is dynamic control binding, not static T0 data."""

    assert PREARM.IDENTITY_FILE not in set(
        TRANSACTION.live_verify_queue_base_upstream_roster("sc")
    )

    root = tmp_path / ".scratchpad"
    root.mkdir()
    payloads = PREARM._seed(root, tmp_path)
    outcome = PREARM._prepare(root, tmp_path)
    manifest = PREARM._json_file(root, PREARM.MANIFEST_FILE)
    plan = PREARM._resolved_plan(outcome)
    t0 = PREARM.LIVE._child_map(plan)[PREARM.LIVE.CHILD_IDS[0]]

    assert manifest["identity_denominator"] == {
        "identity": "scratchpad:" + PREARM.IDENTITY_FILE,
        "sha256": PREARM._sha(payloads[PREARM.IDENTITY_FILE]),
        "size": len(payloads[PREARM.IDENTITY_FILE]),
    }
    assert PREARM.IDENTITY_FILE in set(map(str, t0["exact_inputs"]))
    assert PREARM.IDENTITY_FILE in set(map(str, t0["required_inputs"]))


def test_chain_hypothesis_mapping_pair_requires_atomic_canonical_owner(
    tmp_path,
) -> None:
    """RED: both grouping inputs are consumed only as one canonical pair."""

    project = tmp_path / "project"
    project.mkdir()
    root, config, run_id = ADAPTER._seed(
        project,
        pipeline="sc",
        backend="claude",
        absent=("hypotheses.md", "finding_mapping.md"),
    )
    hypotheses = (
        b"# Hypotheses\n\n"
        b"| Hypothesis | Constituents | Severity |\n"
        b"| --- | --- | --- |\n"
        b"| H-1 | INV-1 | Medium |\n"
    )
    mapping = (
        b"# Finding Mapping\n\n"
        b"| Hypothesis | Source Findings |\n"
        b"| --- | --- |\n"
        b"| H-1 | INV-1 |\n"
    )
    _claim_chain_canonical_pair(
        root,
        project,
        hypotheses=hypotheses,
        mapping=mapping,
        run_id=run_id,
    )

    result = ADAPTER._invoke(root, project, config, run_id)
    rows = {
        str(row["identity"]): row
        for row in result["prearm_presence"]["authority"]["entries"]
    }
    projection = result["preverify_chain_pair_projection"]
    aliases = projection["logical_to_physical"]
    assert set(aliases) == {"hypotheses.md", "finding_mapping.md"}
    assert "scratchpad:hypotheses.md" not in rows
    assert "scratchpad:finding_mapping.md" not in rows
    for relative, raw in (
        ("hypotheses.md", hypotheses),
        ("finding_mapping.md", mapping),
    ):
        physical = str(aliases[relative])
        assert rows["scratchpad:" + physical]["state"] == "PRESENT_AUTHORIZED"
        assert _bundle_bytes(_t0_bundle(root), relative) == raw
        assert rows["scratchpad:" + physical]["owner_key"].endswith(
            "/preverify_chain_pair_projection."
            + str(projection["generation_digest"])
        )
    receipt = json.loads(
        (root / str(projection["receipt_path"])).read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    source_owners = {
        str(row["producer_work_unit_key"])
        for row in receipt["source_authorities"].values()
    }
    assert len(source_owners) == 1
    assert next(iter(source_owners)).endswith("/chain/model")


def test_chain_relation_debt_is_visible_without_dropping_projected_roots(
    tmp_path,
) -> None:
    """Ambiguous relation syntax is repair debt, never a queue-time drop."""

    project = tmp_path / "project"
    project.mkdir()
    root, config, run_id = ADAPTER._seed(
        project,
        pipeline="sc",
        backend="claude",
        absent=("hypotheses.md", "finding_mapping.md"),
    )
    hypotheses = (
        b"# Hypotheses\n\n"
        b"## Hypothesis H-1\n\n"
        b"Constituents might include INV-1; retain for verification.\n"
    )
    mapping = (
        b"# Finding Mapping\n\n"
        b"| Hypothesis | Source Findings |\n"
        b"| --- | --- |\n"
        b"| H-1 | INV-1 |\n"
    )
    _claim_chain_canonical_pair(
        root,
        project,
        hypotheses=hypotheses,
        mapping=mapping,
        run_id=run_id,
    )

    result = ADAPTER._invoke(root, project, config, run_id)

    projection = result["preverify_chain_pair_projection"]
    assert projection["state"] == "OUTPUT_COMMITTED"
    assert projection["safe_to_consume"] is True
    assert projection["debt"][0]["reason_code"] == (
        "CHAIN_PAIR_RELATION_AMBIGUOUS"
    )
    assert projection["debt"][0]["candidate_disposition"] == (
        "PRESERVE_BOTH_ROOTS_FOR_VERIFICATION"
    )
    bundle = _t0_bundle(root)
    assert _bundle_bytes(bundle, "hypotheses.md") == hypotheses
    assert _bundle_bytes(bundle, "finding_mapping.md") == mapping
    assert "CHAIN_PAIR_RELATION_AMBIGUOUS" in json.dumps(
        result["plan"],
        sort_keys=True,
    )
