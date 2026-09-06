"""Acceptance tests for the immutable pre-verification input projection."""
from __future__ import annotations

import json

import pytest

from artifact_ledger import arm_semantic_mutation, finalize_semantic_mutation
from preverify_frozen_projection import (
    EVIDENCE_LOGICAL,
    INVENTORY_LOGICAL,
    PreverifyFrozenProjectionError,
    RECORDS_LOGICAL,
    prepare_preverify_frozen_projection,
)
from preverify_inventory_successor import (
    build_preverify_capture_plan,
    build_preverify_successor_payloads,
    build_successor_generation_payload,
    validate_preverify_capture_plan,
    validate_preverify_successor_payloads,
    validate_successor_generation_payload,
)
from phase_io_contracts import resolve_phase_io_contract
import test_live_verify_queue_driver_adapter_cutover as ADAPTER
import test_preverify_inventory_successor_p0_al as SUCCESSOR


def _prepare(root, project, config, run_id):
    return prepare_preverify_frozen_projection(
        scratchpad=root,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase_name="sc_verify_queue",
        run_id=run_id,
    )


def _split_source_owners(root, project, config, run_id):
    """Give mutable fixture sources independent realistic producer owners."""

    evidence = root / EVIDENCE_LOGICAL
    if not evidence.exists():
        evidence.write_text(
            "# Inventory Evidence Validation\n\n"
            "**Status**: FIXTURE_AUTHORIZED\n",
            encoding="utf-8",
        )
    (root / "_artifact_state.json").unlink(missing_ok=True)
    ADAPTER._claim_group(
        root=root,
        project=project,
        config=config,
        run_id=run_id,
        paths=(INVENTORY_LOGICAL,),
        work_unit_id="inventory_source",
    )
    ADAPTER._claim_group(
        root=root,
        project=project,
        config=config,
        run_id=run_id,
        paths=(EVIDENCE_LOGICAL,),
        work_unit_id="evidence_source",
    )


def _mutate(root, project, run_id, relative, raw, kind):
    event = arm_semantic_mutation(
        root,
        project,
        artifact_identity="scratchpad:" + relative,
        mutation_kind=kind,
        run_id=run_id,
    )
    (root / relative).write_bytes(raw)
    finalize_semantic_mutation(
        root,
        project,
        str(event["event_id"]),
        run_id=run_id,
        affected_record_ids=("INV-1",),
    )


def test_exact_sources_commit_content_addressed_pair_and_replay(tmp_path):
    root, config, run_id = ADAPTER._seed(
        tmp_path,
        pipeline="sc",
        backend="claude",
    )
    _split_source_owners(root, tmp_path, config, run_id)
    result = _prepare(root, tmp_path, config, run_id)
    second = _prepare(root, tmp_path, config, run_id)

    assert result == second
    assert result["state"] == "OUTPUT_COMMITTED"
    assert set(result["logical_to_physical"]) == {
        INVENTORY_LOGICAL,
        RECORDS_LOGICAL,
        EVIDENCE_LOGICAL,
    }
    assert result["debt"] == []
    assert result["receipt_path"] in result["required_paths"]
    for relative in result["required_paths"]:
        assert (root / relative).is_file()
    records = json.loads(
        (root / result["logical_to_physical"][RECORDS_LOGICAL])
        .read_text(encoding="utf-8", errors="strict")
    )
    inventory_raw = (
        root / result["logical_to_physical"][INVENTORY_LOGICAL]
    ).read_bytes()
    assert records == {
        "schema_version": "plamen.finding_records.v2",
        "source": INVENTORY_LOGICAL,
        "source_sha256": ADAPTER._sha(inventory_raw),
        "records": [],
    }


def test_same_run_contiguous_mutations_are_imported_without_reblessing_roots(
    tmp_path,
):
    root, config, run_id = ADAPTER._seed(
        tmp_path,
        pipeline="sc",
        backend="claude",
    )
    _split_source_owners(root, tmp_path, config, run_id)
    inventory_raw = (
        b"# Findings Inventory\n\n"
        b"### Finding [INV-1]: Generic fixture candidate\n"
        b"**Source IDs**: [DF-1]\n"
        b"**Severity**: Medium\n"
        b"**Location**: contracts/Fixture.sol:1\n"
        b"**Description**: Generic fixture mechanism.\n"
        b"**Impact**: Requires independent verification.\n"
    )
    evidence_raw = (
        b"# Inventory Evidence Validation\n\n"
        b"| Finding | Status | Evidence |\n"
        b"| --- | --- | --- |\n"
        b"| INV-1 | VALID | contracts/Fixture.sol:1 |\n"
    )
    _mutate(
        root,
        tmp_path,
        run_id,
        INVENTORY_LOGICAL,
        inventory_raw,
        "FINDING_PROMOTION",
    )
    _mutate(
        root,
        tmp_path,
        run_id,
        EVIDENCE_LOGICAL,
        evidence_raw,
        "INVENTORY_EVIDENCE_RECONCILIATION",
    )

    result = _prepare(root, tmp_path, config, run_id)

    assert (
        root / result["logical_to_physical"][INVENTORY_LOGICAL]
    ).read_bytes() == inventory_raw
    assert (
        root / result["logical_to_physical"][EVIDENCE_LOGICAL]
    ).read_bytes() == evidence_raw
    records = json.loads(
        (root / result["logical_to_physical"][RECORDS_LOGICAL])
        .read_text(encoding="utf-8", errors="strict")
    )
    assert records["source_sha256"] == ADAPTER._sha(inventory_raw)
    assert [row["inventory_id"] for row in records["records"]] == ["INV-1"]
    receipt = json.loads(
        (root / result["receipt_path"]).read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    assert receipt["source_authorities"]["inventory"][
        "authority_kind"
    ] == "CONTIGUOUS_SEMANTIC_MUTATION_CHAIN"
    assert receipt["source_authorities"]["evidence"][
        "authority_kind"
    ] == "CONTIGUOUS_SEMANTIC_MUTATION_CHAIN"
    assert (root / INVENTORY_LOGICAL).read_bytes() == inventory_raw
    assert (root / EVIDENCE_LOGICAL).read_bytes() == evidence_raw


def test_untrusted_evidence_becomes_visible_repair_debt_not_semantic_input(
    tmp_path,
):
    root, config, run_id = ADAPTER._seed(
        tmp_path,
        pipeline="sc",
        backend="claude",
    )
    (root / EVIDENCE_LOGICAL).write_text(
        "# Unowned advisory evidence\n",
        encoding="utf-8",
    )

    result = _prepare(root, tmp_path, config, run_id)

    assert EVIDENCE_LOGICAL not in result["logical_to_physical"]
    assert result["debt"] == [{
        "artifact": EVIDENCE_LOGICAL,
        "reason_code": "EVIDENCE_PROJECTION_UNAUTHORIZED",
        "authority": "ADVISORY_REPAIR_ONLY",
        "candidate_disposition": "PRESERVE_ALL_FOR_VERIFICATION",
    }]
    advisory = (root / result["advisory_evidence_path"]).read_text(
        encoding="utf-8",
        errors="strict",
    )
    assert "PRESERVE_ALL_FOR_VERIFICATION" in advisory
    assert "Proof Authority**: NONE" in advisory


def test_armed_or_nonterminal_inventory_mutation_cannot_cross_import_boundary(
    tmp_path,
):
    root, config, run_id = ADAPTER._seed(
        tmp_path,
        pipeline="sc",
        backend="claude",
    )
    event = arm_semantic_mutation(
        root,
        tmp_path,
        artifact_identity="scratchpad:" + INVENTORY_LOGICAL,
        mutation_kind="FINDING_PROMOTION",
        run_id=run_id,
    )
    assert event["status"] == "ARMED"
    (root / INVENTORY_LOGICAL).write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-1]: Interrupted mutation\n",
        encoding="utf-8",
    )

    with pytest.raises(
        PreverifyFrozenProjectionError,
        match="contiguous|producer|mutation",
    ):
        _prepare(root, tmp_path, config, run_id)


def test_successor_builders_accept_explicit_frozen_pair_and_evidence_paths(
    tmp_path,
):
    root = tmp_path / ".scratchpad"
    root.mkdir()
    _scan, delivery = SUCCESSOR._seed(root)
    frozen = root / "_preverify_frozen" / ("generation_" + "a" * 64)
    frozen.mkdir(parents=True)
    inventory_source = (
        "_preverify_frozen/generation_"
        + "a" * 64
        + "/findings_inventory.md"
    )
    records_source = (
        "_preverify_frozen/generation_"
        + "a" * 64
        + "/finding_records.json"
    )
    evidence_source = (
        "_preverify_frozen/generation_"
        + "a" * 64
        + "/inventory_evidence_validation.md"
    )
    (root / inventory_source).write_bytes(
        (root / INVENTORY_LOGICAL).read_bytes()
    )
    (root / records_source).write_bytes(
        (root / RECORDS_LOGICAL).read_bytes()
    )
    (root / evidence_source).write_text(
        "# Advisory evidence\n",
        encoding="utf-8",
    )

    plan = build_preverify_capture_plan(
        root,
        run_id="frozen-successor-run",
        producer_artifacts=("depth_consensus_invariant_findings.md",),
        mutation_authority_candidates=(),
        control_artifact_candidates=(),
        registry_digest="b" * 64,
        trusted_code_digest="c" * 64,
        inventory_source_artifact=inventory_source,
        records_source_artifact=records_source,
        evidence_source_artifact=evidence_source,
    )
    validate_preverify_capture_plan(root, plan)
    final, registered = build_preverify_successor_payloads(
        root,
        run_id="frozen-successor-run",
        delivery_payload=delivery,
        producer_artifacts=("depth_consensus_invariant_findings.md",),
        inventory_source_artifact=inventory_source,
    )
    validate_preverify_successor_payloads(
        root,
        final_payload=final,
        delivery_payload=registered,
        run_id="frozen-successor-run",
        inventory_source_artifact=inventory_source,
    )
    generation_name, generation = build_successor_generation_payload(
        run_id="frozen-successor-run",
        final_payload=final,
        delivery_payload=registered,
        capture_plan=plan,
    )
    validate_successor_generation_payload(
        root,
        payload=generation,
        artifact_name=generation_name,
        expected_capture_plan=plan,
    )

    assert plan.payload["source_projection"] == {
        "inventory": inventory_source,
        "records": records_source,
        "evidence": evidence_source,
    }
    assert {
        inventory_source,
        records_source,
        evidence_source,
    } <= set(plan.exact_inputs)
    # Queue/report compatibility remains canonical even though validation
    # reads the immutable physical source.
    assert final["inventory_artifact"] == INVENTORY_LOGICAL
    assert registered["inventory_artifact"] == INVENTORY_LOGICAL


def test_delivery_payload_hashes_explicit_frozen_inventory_not_canonical_root(
    tmp_path,
):
    root = tmp_path / ".scratchpad"
    root.mkdir()
    scan, _canonical_delivery = SUCCESSOR._seed(root)
    canonical_raw = (root / INVENTORY_LOGICAL).read_bytes()
    generation = "_preverify_frozen/generation_" + "d" * 64
    inventory_source = generation + "/" + INVENTORY_LOGICAL
    records_source = generation + "/" + RECORDS_LOGICAL
    (root / generation).mkdir(parents=True)
    frozen_raw = canonical_raw + (
        b"\n### Finding [EN-10]: Frozen-only chain candidate\n"
        b"**Severity**: Medium\n"
        b"**Location**: src/Generic.sol:10\n"
        b"**Source IDs**: EN-10\n"
        b"**Description**: Requires an independent disposition.\n"
        b"**Impact**: Candidate-bearing composition effect.\n"
    )
    (root / inventory_source).write_bytes(frozen_raw)
    (root / records_source).write_text(
        json.dumps(
            {
                "schema_version": "plamen.finding_records.v2",
                "source": INVENTORY_LOGICAL,
                "source_sha256": ADAPTER._sha(frozen_raw),
                "records": [],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    delivery = SUCCESSOR.V._build_registered_finding_delivery_receipt_payload(
        root,
        scan,
        frozen_raw.decode("utf-8"),
        inventory_source_artifact=inventory_source,
    )
    final, registered = build_preverify_successor_payloads(
        root,
        run_id="frozen-denominator-run",
        delivery_payload=delivery,
        producer_artifacts=("depth_consensus_invariant_findings.md",),
        inventory_source_artifact=inventory_source,
    )

    assert canonical_raw != frozen_raw
    assert delivery["inventory_artifact"] == INVENTORY_LOGICAL
    assert delivery["inventory_sha256"] == "sha256:" + ADAPTER._sha(
        frozen_raw
    )
    assert delivery["inventory_sha256"] != "sha256:" + ADAPTER._sha(
        canonical_raw
    )
    assert final["inventory_sha256"] == ADAPTER._sha(frozen_raw)
    assert registered["delivery_payload"] == delivery


def test_delivery_payload_crlf_source_uses_exact_bytes_across_hosts(tmp_path):
    root = tmp_path / ".scratchpad"
    root.mkdir()
    scan, _canonical_delivery = SUCCESSOR._seed(root)
    source = "_preverify_frozen/generation_" + "c" * 64
    inventory_source = source + "/" + INVENTORY_LOGICAL
    (root / source).mkdir(parents=True)
    raw = (
        b"# Finding Inventory\r\n\r\n"
        b"### Finding [INV-001]: candidate\r\n"
        b"**Source IDs**: DCI-1\r\n"
        b"**Severity**: Medium\r\n"
        b"**Location**: src/A.sol:10\r\n"
        b"**Description**: Exact source bytes are authoritative.\r\n"
        b"**Impact**: Requires verification.\r\n"
    )
    (root / inventory_source).write_bytes(raw)

    payload = SUCCESSOR.V._build_registered_finding_delivery_receipt_payload(
        root,
        scan,
        raw.decode("utf-8").replace("\r\n", "\n"),
        inventory_source_artifact=inventory_source,
    )

    assert payload["inventory_sha256"] == "sha256:" + ADAPTER._sha(raw)
    assert payload["actions"][0]["disposition"] == "PROMOTED_FINDING"


def test_preverify_capture_contract_accepts_only_one_corooted_physical_pair():
    generation = "_preverify_frozen/generation_" + "e" * 64
    inventory = generation + "/" + INVENTORY_LOGICAL
    records = generation + "/" + RECORDS_LOGICAL
    receipt = generation + "/receipt.json"
    output = "_preverify_successors/generation_" + "f" * 64 + ".json"

    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="sc_verify_queue",
        work_unit_id="preverify_capture." + "f" * 64,
        exact_inputs=(inventory, records, receipt),
        exact_outputs=(output,),
    )

    assert contract.immutable_inputs == tuple(sorted((
        "scratchpad:" + inventory,
        "scratchpad:" + records,
        "scratchpad:" + receipt,
    )))
    with pytest.raises(ValueError, match="paired"):
        resolve_phase_io_contract(
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
            phase="sc_verify_queue",
            work_unit_id="preverify_capture." + "f" * 64,
            exact_inputs=(
                inventory,
                "_preverify_frozen/generation_" + "a" * 64 + "/"
                + RECORDS_LOGICAL,
            ),
            exact_outputs=(output,),
        )
    with pytest.raises(ValueError, match="paired"):
        resolve_phase_io_contract(
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
            phase="sc_verify_queue",
            work_unit_id="preverify_capture." + "f" * 64,
            exact_inputs=(
                "project::" + INVENTORY_LOGICAL,
                "project::" + RECORDS_LOGICAL,
            ),
            exact_outputs=(output,),
        )
    with pytest.raises(ValueError, match="paired"):
        resolve_phase_io_contract(
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
            phase="sc_verify_queue",
            work_unit_id="preverify_capture." + "f" * 64,
            exact_inputs=(inventory, records),
            exact_outputs=(output,),
        )
    with pytest.raises(ValueError, match="content-addressed"):
        resolve_phase_io_contract(
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
            phase="sc_verify_queue",
            work_unit_id="preverify_capture." + "a" * 64,
            exact_inputs=(inventory, records, receipt),
            exact_outputs=(output,),
        )
    with pytest.raises(ValueError, match="paired"):
        resolve_phase_io_contract(
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
            phase="sc_verify_queue",
            work_unit_id="preverify_capture." + "f" * 64,
            exact_inputs=(
                inventory,
                records,
                "shadow/" + INVENTORY_LOGICAL,
                "shadow/" + RECORDS_LOGICAL,
            ),
            exact_outputs=(output,),
        )
