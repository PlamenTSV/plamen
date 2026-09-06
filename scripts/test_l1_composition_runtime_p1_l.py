from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

import l1_composition_runtime as R


RUN_ID = "run-l1-runtime-001"
SNAPSHOT = "a" * 64


def _block(candidate_id: str, title: str = "Candidate") -> str:
    return (
        f"## Finding [{candidate_id}]: {title}\n\n"
        "**Severity**: Medium\n\n"
        "Generic prose must never be parsed into composition atoms.\n"
    )


def _write_sources(root: Path, *blocks: str) -> None:
    (root / R.INVENTORY_NAME).write_text(
        "# L1 Findings Inventory\n\n" + "\n".join(blocks),
        encoding="utf-8",
    )


def _source_blocks(root: Path) -> dict[str, dict]:
    payload = R.derive_l1_composition_runtime(
        root,
        pipeline="l1",
        mode="core",
        language="go",
        run_id=RUN_ID,
        snapshot_digest=SNAPSHOT,
    )
    return {row["candidate_id"]: row for row in payload["facts"]}


def _record(
    source_row: dict,
    *,
    layer: str,
    subsystem: str,
    requires: list[dict] | None = None,
    produces: list[dict] | None = None,
    touches: list[dict] | None = None,
    candidate_state: str = "CONFIRMED",
) -> dict:
    return {
        "candidate_id": source_row["candidate_id"],
        "source_artifact": source_row["source_artifact"],
        "source_block_sha256": source_row["source_block_sha256"],
        "language": "GO",
        "layer": layer,
        "subsystem": subsystem,
        "root_cause_id": f"ROOT-{source_row['candidate_id']}",
        "candidate_state": candidate_state,
        "requires": requires or [],
        "produces": produces or [],
        "touches": touches or [],
    }


def _write_records(root: Path, records: list[dict], **updates: object) -> None:
    payload: dict[str, object] = {
        "schema_version": R.TYPED_RECORDS_SCHEMA,
        "run_id": RUN_ID,
        "snapshot_digest": SNAPSHOT,
        "producer_identity": "l1-composition-model-worker",
        "producer_invocation_id": "invocation-001",
        "records": records,
    }
    payload.update(updates)
    (root / R.TYPED_RECORDS_NAME).write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )


def _derive(root: Path, **updates: object) -> dict:
    kwargs: dict[str, object] = {
        "pipeline": "l1",
        "mode": "core",
        "language": "go",
        "run_id": RUN_ID,
        "snapshot_digest": SNAPSHOT,
    }
    kwargs.update(updates)
    return R.derive_l1_composition_runtime(root, **kwargs)


def _typed_pair(root: Path) -> dict:
    _write_sources(root, _block("L1-A1"), _block("L1-B1"))
    sources = _source_blocks(root)
    atom = {"kind": "STATE", "atom_id": "ledger.commit"}
    _write_records(
        root,
        [
            _record(
                sources["L1-A1"],
                layer="execution",
                subsystem="execution",
                produces=[atom],
            ),
            _record(
                sources["L1-B1"],
                layer="consensus",
                subsystem="consensus",
                requires=[atom],
            ),
        ],
    )
    return _derive(root)


def _proposal(runtime: dict, disposition: str = "COMPOUND_CANDIDATE") -> dict:
    return {
        "schema_version": R.MODEL_DISPOSITIONS_SCHEMA,
        "run_id": RUN_ID,
        "snapshot_digest": SNAPSHOT,
        "producer_identity": "l1-composition-disposition-worker",
        "producer_invocation_id": "disposition-invocation-001",
        "runtime_digest": runtime["runtime_digest"],
        "graph_digest": runtime["graph"]["graph_digest"],
        "work_packets_digest": runtime["work_packets_digest"],
        "dispositions": [
            {
                "obligation_id": runtime["work_packets"][0]["obligation_id"],
                "disposition": disposition,
                "rationale": "Independent reasoning proposes verification of the composition.",
            }
        ],
    }


def test_sc_and_light_are_deterministic_not_triggered_without_reading_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _write_sources(tmp_path, _block("L1-A1"))

    def forbidden_read(_: Path) -> bytes:
        raise AssertionError("inactive provider must not read audit artifacts")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read)
    sc = _derive(tmp_path, pipeline="sc", mode="thorough")
    light = _derive(tmp_path, pipeline="l1", mode="light")

    assert sc["status"] == light["status"] == "NOT_TRIGGERED"
    assert sc["facts"] == light["facts"] == []
    assert sc["input_artifacts"] == light["input_artifacts"] == []
    assert sc["activation"]["triggered"] is False
    assert light["activation"]["reason"] == "LIGHT_MODE_EXCLUDED"


def test_missing_typed_fields_preserves_complete_opaque_denominator_with_debt(
    tmp_path: Path,
):
    _write_sources(
        tmp_path,
        _block("L1-A1", "STATE EVENT RESOURCE VALIDATION"),
        _block("L1-B1", "Same semantic-looking title"),
    )

    runtime = _derive(tmp_path)

    assert runtime["denominator_count"] == 2
    assert runtime["measurable_count"] == 0
    assert runtime["status"] == "DEGRADED"
    assert runtime["graph"]["edges"] == []
    assert all(row["composition_fact"] is None for row in runtime["facts"])
    assert len({row["opaque_identity"] for row in runtime["facts"]}) == 2
    assert all(row["extraction_status"] == "UNMEASURABLE" for row in runtime["facts"])
    assert any(row["code"] == "TYPED_RECORD_ARTIFACT_ABSENT" for row in runtime["debts"])


def test_explicit_exact_block_bound_records_produce_exact_graph_work_packet(
    tmp_path: Path,
):
    runtime = _typed_pair(tmp_path)

    assert runtime["status"] == "READY"
    assert runtime["denominator_count"] == runtime["measurable_count"] == 2
    assert len(runtime["graph"]["edges"]) == 1
    assert len(runtime["work_packets"]) == 1
    packet = runtime["work_packets"][0]
    assert packet["candidate_ids"] == ["L1-A1", "L1-B1"]
    assert packet["relation"] == "STATE_DEPENDENCY"
    assert packet["capabilities"] == R.PROPOSAL_ONLY_CAPABILITIES
    assert packet["constituent_source_bindings"] == sorted(
        packet["constituent_source_bindings"], key=lambda row: row["candidate_id"]
    )
    assert R.validate_l1_composition_runtime(
        runtime,
        tmp_path,
        pipeline="l1",
        mode="core",
        language="go",
        run_id=RUN_ID,
        snapshot_digest=SNAPSHOT,
    ) == []


def test_semantic_prose_and_chain_summary_tables_never_create_atoms(tmp_path: Path):
    (tmp_path / R.INVENTORY_NAME).write_text(
        "# Inventory\n\n"
        + _block("L1-A1", "produces STATE ledger.commit")
        + "\n| Finding ID | Postconditions Created | Preconditions Required |\n"
        + "|---|---|---|\n| L1-A1 | STATE:ledger.commit | EVENT:accepted |\n",
        encoding="utf-8",
    )

    runtime = _derive(tmp_path)

    assert runtime["measurable_count"] == 0
    assert runtime["graph"]["edges"] == []


def test_real_l1_inventory_heading_without_finding_prefix_or_colon_is_preserved(
    tmp_path: Path,
):
    (tmp_path / R.INVENTORY_NAME).write_text(
        "# L1 Findings Inventory\n\n## [F-1] Real inventory title\n\nBody.\n",
        encoding="utf-8",
    )

    runtime = _derive(tmp_path)

    assert runtime["denominator_count"] == 1
    assert runtime["facts"][0]["candidate_id"] == "F-1"


def test_stale_or_mismatched_record_binding_never_attaches_semantics(tmp_path: Path):
    _write_sources(tmp_path, _block("L1-A1"))
    source = _source_blocks(tmp_path)["L1-A1"]
    record = _record(source, layer="state", subsystem="state")
    record["source_block_sha256"] = "b" * 64
    _write_records(tmp_path, [record])

    runtime = _derive(tmp_path)

    assert runtime["facts"][0]["extraction_status"] == "UNMEASURABLE"
    assert runtime["facts"][0]["composition_fact"] is None
    assert any(row["code"] == "TYPED_RECORD_SOURCE_UNKNOWN" for row in runtime["debts"])


def test_duplicate_source_identity_or_typed_binding_cannot_select_by_order(tmp_path: Path):
    _write_sources(tmp_path, _block("L1-A1", "first"), _block("L1-A1", "second"))
    sources = _source_blocks(tmp_path)
    assert sources["L1-A1"]["extraction_status"] == "UNMEASURABLE"

    # A unique source with duplicate typed records is also unmeasurable.
    _write_sources(tmp_path, _block("L1-B1"))
    source = _source_blocks(tmp_path)["L1-B1"]
    record = _record(source, layer="state", subsystem="state")
    _write_records(tmp_path, [record, copy.deepcopy(record)])
    runtime = _derive(tmp_path)

    assert runtime["facts"][0]["extraction_status"] == "UNMEASURABLE"
    assert any(row["code"] == "DUPLICATE_TYPED_SOURCE_BINDING" for row in runtime["debts"])


def test_typed_record_run_snapshot_and_schema_are_fail_closed_visible_debt(tmp_path: Path):
    _write_sources(tmp_path, _block("L1-A1"))
    source = _source_blocks(tmp_path)["L1-A1"]
    _write_records(
        tmp_path,
        [_record(source, layer="state", subsystem="state")],
        snapshot_digest="c" * 64,
    )

    runtime = _derive(tmp_path)

    assert runtime["measurable_count"] == 0
    assert any(row["code"] == "TYPED_RECORD_CONTEXT_MISMATCH" for row in runtime["debts"])


def test_each_authoritative_source_is_read_once_and_exact_bytes_bind_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _write_sources(tmp_path, _block("L1-A1"))
    (tmp_path / "depth_state_trace_findings.md").write_text(
        _block("L1-B1"), encoding="utf-8"
    )
    original = Path.read_bytes
    calls: dict[Path, int] = {}

    def counted(path: Path) -> bytes:
        calls[path] = calls.get(path, 0) + 1
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", counted)
    runtime = _derive(tmp_path)

    for name in (R.INVENTORY_NAME, "depth_state_trace_findings.md"):
        path = tmp_path / name
        assert calls[path] == 1
        descriptor = next(row for row in runtime["input_artifacts"] if row["artifact"] == name)
        assert descriptor["sha256"] == hashlib.sha256(original(path)).hexdigest()


@pytest.mark.parametrize(
    "name",
    [
        "depth_findings.md",
        "blind_spot_a_findings.md",
        "niche_restart_safety_findings.md",
        "scanner_validation_findings.md",
        "validation_sweep_findings.md",
        "design_stress_findings.md",
        "perturbation_findings.md",
    ],
)
def test_supplementary_depth_finding_producers_are_in_the_denominator(
    tmp_path: Path, name: str
):
    _write_sources(tmp_path, _block("L1-A1"))
    (tmp_path / name).write_text(_block("L1-B1"), encoding="utf-8")

    runtime = _derive(tmp_path)

    assert {row["candidate_id"] for row in runtime["facts"]} == {"L1-A1", "L1-B1"}
    assert any(row["artifact"] == name for row in runtime["input_artifacts"])


def test_source_drift_tamper_and_resume_are_detected_and_writer_is_idempotent(
    tmp_path: Path,
):
    runtime = _typed_pair(tmp_path)
    first = R.write_l1_composition_runtime(
        tmp_path,
        pipeline="l1",
        mode="core",
        language="go",
        run_id=RUN_ID,
        snapshot_digest=SNAPSHOT,
    )
    original_bytes = (tmp_path / R.RUNTIME_NAME).read_bytes()
    second = R.write_l1_composition_runtime(
        tmp_path,
        pipeline="l1",
        mode="core",
        language="go",
        run_id=RUN_ID,
        snapshot_digest=SNAPSHOT,
    )
    assert first == second == runtime
    assert (tmp_path / R.RUNTIME_NAME).read_bytes() == original_bytes

    tampered = copy.deepcopy(runtime)
    tampered["facts"][0]["extraction_status"] = "MEASURABLE" if tampered["facts"][0]["extraction_status"] != "MEASURABLE" else "UNMEASURABLE"
    assert R.validate_l1_composition_runtime(
        tampered,
        tmp_path,
        pipeline="l1",
        mode="core",
        language="go",
        run_id=RUN_ID,
        snapshot_digest=SNAPSHOT,
    )

    inventory = tmp_path / R.INVENTORY_NAME
    inventory.write_text(inventory.read_text(encoding="utf-8") + "\nchanged\n", encoding="utf-8")
    issues = R.validate_l1_composition_runtime(
        runtime,
        tmp_path,
        pipeline="l1",
        mode="core",
        language="go",
        run_id=RUN_ID,
        snapshot_digest=SNAPSHOT,
    )
    assert any("stale" in issue or "mismatch" in issue for issue in issues)


def test_malformed_duplicate_key_and_oversized_inputs_degrade_without_halt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _write_sources(tmp_path, _block("L1-A1"))
    (tmp_path / R.TYPED_RECORDS_NAME).write_text(
        '{"schema_version":"x","records":[],"records":[]}', encoding="utf-8"
    )
    malformed = _derive(tmp_path)
    assert malformed["status"] == "DEGRADED"
    assert any(row["code"] == "TYPED_RECORD_ARTIFACT_MALFORMED" for row in malformed["debts"])

    monkeypatch.setattr(R, "MAX_SOURCE_ARTIFACT_BYTES", 8)
    oversized = _derive(tmp_path)
    assert oversized["status"] == "DEGRADED"
    assert oversized["facts"] == []
    assert any(row["code"] == "SOURCE_ARTIFACT_OVERSIZED" for row in oversized["debts"])


def test_cardinality_and_packet_output_are_bounded_with_visible_debt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _write_sources(tmp_path, *[_block(f"L1-A{i}") for i in range(1, 5)])
    monkeypatch.setattr(R, "MAX_SOURCE_FINDINGS", 2)
    bounded = _derive(tmp_path)
    assert len(bounded["facts"]) == 2
    assert bounded["status"] == "DEGRADED"
    assert any(row["code"] == "SOURCE_FINDING_BUDGET_EXHAUSTED" for row in bounded["debts"])

    runtime = _typed_pair(tmp_path)
    monkeypatch.setattr(R, "MAX_WORK_PACKETS", 0)
    packet_bounded = _derive(tmp_path)
    assert packet_bounded["work_packets"] == []
    assert packet_bounded["status"] == "DEGRADED"
    assert any(row["code"] == "WORK_PACKET_BUDGET_EXHAUSTED" for row in packet_bounded["debts"])


def test_exact_disposition_coverage_creates_proposal_only_compound_handoff(tmp_path: Path):
    runtime = _typed_pair(tmp_path)
    proposal = _proposal(runtime)

    receipt = R.reconcile_l1_composition_runtime(runtime, proposal)

    assert receipt["status"] == "P0_AF_ADAPTER_REQUIRED"
    assert receipt["exact_coverage"] is True
    assert len(receipt["compound_handoffs"]) == 1
    handoff = receipt["compound_handoffs"][0]
    assert handoff["candidate_ids"] == ["L1-A1", "L1-B1"]
    assert handoff["authority"] == "PROPOSAL_ONLY"
    assert handoff["required_adapter"] == "L1_COMPOSITION_QUEUE_TRANSACTION"
    assert handoff["capabilities"] == R.PROPOSAL_ONLY_CAPABILITIES
    assert "finding_id" not in handoff
    assert "severity" not in handoff
    assert "proof" not in handoff
    assert any(
        row["code"] == "L1_COMPOSITION_QUEUE_TRANSACTION_REQUIRED"
        for row in receipt["debts"]
    )


def test_non_candidate_disposition_has_no_queue_handoff_or_decision_authority(tmp_path: Path):
    runtime = _typed_pair(tmp_path)
    receipt = R.reconcile_l1_composition_runtime(
        runtime, _proposal(runtime, disposition="NEEDS_EVIDENCE")
    )

    assert receipt["status"] == "COMPLETE_NO_COMPOUND_CANDIDATES"
    assert receipt["compound_handoffs"] == []
    assert receipt["capabilities"] == R.PROPOSAL_ONLY_CAPABILITIES


def test_unmeasurable_denominator_can_never_reconcile_as_clean_empty_coverage(
    tmp_path: Path,
):
    _write_sources(tmp_path, _block("L1-A1"))
    runtime = _derive(tmp_path)
    proposal = {
        "schema_version": R.MODEL_DISPOSITIONS_SCHEMA,
        "run_id": RUN_ID,
        "snapshot_digest": SNAPSHOT,
        "producer_identity": "l1-composition-disposition-worker",
        "producer_invocation_id": "disposition-invocation-001",
        "runtime_digest": runtime["runtime_digest"],
        "graph_digest": runtime["graph"]["graph_digest"],
        "work_packets_digest": runtime["work_packets_digest"],
        "dispositions": [],
    }

    receipt = R.reconcile_l1_composition_runtime(runtime, proposal)

    assert receipt["status"] == "DEGRADED"
    assert receipt["exact_coverage"] is False
    assert receipt["compound_handoffs"] == []
    assert any(row["code"] == "RUNTIME_COVERAGE_DEGRADED" for row in receipt["debts"])


def test_missing_duplicate_unexpected_or_stale_dispositions_cannot_emit_handoffs(
    tmp_path: Path,
):
    runtime = _typed_pair(tmp_path)
    missing = _proposal(runtime)
    missing["dispositions"] = []
    missing_receipt = R.reconcile_l1_composition_runtime(runtime, missing)
    assert missing_receipt["exact_coverage"] is False
    assert missing_receipt["compound_handoffs"] == []

    duplicate = _proposal(runtime)
    duplicate["dispositions"].append(copy.deepcopy(duplicate["dispositions"][0]))
    duplicate_receipt = R.reconcile_l1_composition_runtime(runtime, duplicate)
    assert duplicate_receipt["exact_coverage"] is False
    assert duplicate_receipt["compound_handoffs"] == []

    stale = _proposal(runtime)
    stale["runtime_digest"] = "b" * 64
    stale_receipt = R.reconcile_l1_composition_runtime(runtime, stale)
    assert stale_receipt["status"] == "DEGRADED"
    assert stale_receipt["compound_handoffs"] == []
    assert any(row["code"] == "MODEL_DISPOSITION_CONTEXT_MISMATCH" for row in stale_receipt["debts"])

    oversized = _proposal(runtime)
    oversized["dispositions"] = oversized["dispositions"] * (R.MAX_WORK_PACKETS + 1)
    oversized_receipt = R.reconcile_l1_composition_runtime(runtime, oversized)
    assert oversized_receipt["status"] == "DEGRADED"
    assert oversized_receipt["compound_handoffs"] == []
    assert any(row["code"] == "MODEL_DISPOSITION_ARTIFACT_MALFORMED" for row in oversized_receipt["debts"])


def test_typed_fact_writer_cannot_self_certify_its_own_composition(tmp_path: Path):
    runtime = _typed_pair(tmp_path)
    proposal = _proposal(runtime)
    proposal["producer_identity"] = "l1-composition-model-worker"
    proposal["producer_invocation_id"] = "invocation-001"

    receipt = R.reconcile_l1_composition_runtime(runtime, proposal)

    assert receipt["status"] == "DEGRADED"
    assert receipt["compound_handoffs"] == []
    assert any(row["code"] == "MODEL_DISPOSITION_SELF_CERTIFICATION" for row in receipt["debts"])


def test_receipt_tamper_validation_and_idempotent_write(tmp_path: Path):
    runtime = _typed_pair(tmp_path)
    proposal = _proposal(runtime)
    first = R.write_l1_composition_receipt(tmp_path, runtime, proposal)
    original = (tmp_path / R.RECEIPT_NAME).read_bytes()
    second = R.write_l1_composition_receipt(tmp_path, runtime, proposal)
    assert first == second
    assert original == (tmp_path / R.RECEIPT_NAME).read_bytes()
    assert R.validate_l1_composition_receipt(first, runtime, proposal) == []

    tampered = copy.deepcopy(first)
    tampered["compound_handoffs"][0]["authority"] = "PROOF"
    assert R.validate_l1_composition_receipt(tampered, runtime, proposal)


def test_recomputed_runtime_hash_cannot_hide_internal_row_or_schema_tampering(
    tmp_path: Path,
):
    runtime = _typed_pair(tmp_path)
    proposal = _proposal(runtime)

    tampered = copy.deepcopy(runtime)
    tampered["facts"][0]["source_block_sha256"] = "c" * 64
    unsigned_row = dict(tampered["facts"][0])
    unsigned_row["row_digest"] = ""
    tampered["facts"][0]["row_digest"] = R._digest(unsigned_row)
    unsigned_runtime = dict(tampered)
    unsigned_runtime["runtime_digest"] = ""
    tampered["runtime_digest"] = R._digest(unsigned_runtime)
    receipt = R.reconcile_l1_composition_runtime(tampered, proposal)
    assert receipt["status"] == "DEGRADED"
    assert receipt["compound_handoffs"] == []
    assert any(row["code"] == "RUNTIME_AUTHORITY_INVALID" for row in receipt["debts"])

    extra = copy.deepcopy(runtime)
    extra["unexpected_authority"] = True
    unsigned_extra = dict(extra)
    unsigned_extra["runtime_digest"] = ""
    extra["runtime_digest"] = R._digest(unsigned_extra)
    assert any("schema" in issue for issue in R._validate_runtime_self(extra))


def test_provider_never_reads_model_dispositions_or_report_outputs(tmp_path: Path):
    left = tmp_path / "left"
    right = tmp_path / "right"
    left.mkdir()
    right.mkdir()
    for root in (left, right):
        _write_sources(root, _block("L1-A1"))
    (right / "l1_composition_model_dispositions.json").write_text(
        json.dumps({"inject": "STATE:ledger.commit"}), encoding="utf-8"
    )
    (right / "security_report.md").write_text("COMPOUND_CANDIDATE", encoding="utf-8")
    assert _derive(left) == _derive(right)


def test_driver_integration_contract_is_live_and_proposal_only():
    contract = R.driver_integration_contract()
    assert contract["integrated"] is True
    assert contract["pipeline"] == "l1"
    assert contract["modes"] == ["core", "thorough"]
    assert contract["must_run_before"] == "verify_queue"
    assert contract["compound_delivery"] == "L1_COMPOSITION_QUEUE_TRANSACTION"
    assert contract["independent_fact_and_disposition_workers"] is True
    assert contract["capabilities"] == R.PROPOSAL_ONLY_CAPABILITIES
