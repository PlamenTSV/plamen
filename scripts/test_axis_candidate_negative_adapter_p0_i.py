"""P0-I typed candidate-negative adapter for axis CLEAR dispositions."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import axis_disposition as AXIS
import axis_canonical_prior as AXIS_PRIOR
import candidate_negative_authority as NEG
import test_axis_disposition_v2_core_red as FIX


RUN_ID = "run-axis-negative-adapter"


def _semantic_context(
    scratchpad: Path,
    worklist: dict,
) -> tuple[dict, object]:
    evidence = FIX._zero_evidence(RUN_ID)
    AXIS.write_axis_disposition_v2_artifacts(
        scratchpad,
        worklist=worklist,
        execution_evidence_authority=evidence,
    )
    prior = AXIS_PRIOR.capture_axis_canonical_prior_authority(
        scratchpad,
        run_id=RUN_ID,
        worklist_hash=str(worklist["worklist_hash"]),
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
    )
    return evidence, prior


def _authorities(
    tmp_path: Path,
    *,
    dispositions: list[dict] | None = None,
    exact_zero: bool = False,
    debt: bool = False,
) -> tuple[Path, Path, dict, dict]:
    project, scratchpad = FIX._seed(tmp_path)
    if exact_zero or debt:
        matrix = FIX._matrix([])
    else:
        matrix = FIX._matrix(
            [
                FIX._gap(
                    "A.settle(uint256)",
                    "contracts/A.sol",
                    "boundary",
                )
            ]
        )
    worklist = FIX._worklist(
        project,
        matrix,
        run_id=RUN_ID,
        status="UNKNOWN" if debt else "EXACT",
        debt=("provider unavailable",) if debt else (),
    )
    rows = list(dispositions or [])
    if not exact_zero and not debt and dispositions is None:
        item = worklist["items"][0]
        rows = [
            {
                "work_item_id": item["work_item_id"],
                "disposition": "CLEAR",
                "action_id": "",
                "evidence": [FIX._source_clear(item)],
                "rationale": "the cited in-scope source guard closes this axis",
            }
        ]
    sidecar = FIX._sidecar(worklist, rows, run_id=RUN_ID)
    evidence, prior = _semantic_context(scratchpad, worklist)
    initial, plan = AXIS.reconcile_axis_dispositions_initial(
        worklist,
        base_dispositions_raw=sidecar,
        base_findings_raw=b"",
        execution_evidence_authority=evidence,
        canonical_prior_ids=prior.aliases,
        canonical_prior_authority_digest=prior.authority_digest,
        repair_cap=16,
    )
    execution = AXIS.build_axis_repair_execution_receipt(
        plan,
        state="NOT_REQUIRED",
    )
    final = AXIS.reconcile_axis_dispositions_final(
        worklist,
        initial_receipt=initial,
        repair_plan=plan,
        repair_execution_receipt=execution,
        base_findings_raw=b"",
        execution_evidence_authority=evidence,
        canonical_prior_ids=prior.aliases,
        canonical_prior_authority_digest=prior.authority_digest,
    )
    AXIS.write_axis_disposition_v2_artifacts(
        scratchpad,
        worklist=worklist,
        application_receipt=final,
    )
    return (
        scratchpad / AXIS.WORKLIST_NAME,
        scratchpad / AXIS.AXIS_APPLICATION_RECEIPT_NAME,
        worklist,
        final,
    )


def test_typed_clear_emits_one_exact_axw_event_without_markdown(
    tmp_path: Path,
) -> None:
    worklist_path, receipt_path, worklist, final = _authorities(tmp_path)

    ledger = NEG.build_axis_clear_candidate_negative_ledger(
        worklist_path=worklist_path,
        application_receipt_path=receipt_path,
        expected_run_id=RUN_ID,
    )
    NEG.validate_axis_clear_candidate_negative_ledger(
        ledger,
        worklist_path=worklist_path,
        application_receipt_path=receipt_path,
        expected_run_id=RUN_ID,
    )

    assert ledger["phase"] == "axis_coverage"
    assert ledger["status"] == "CLEAN"
    assert ledger["event_count"] == 1
    event = ledger["events"][0]
    item = worklist["items"][0]
    assert event["source_item_id"] == item["work_item_id"]
    assert event["identity_state"] == "EXACT"
    assert event["legacy_disposition"] == "CLEAR"
    assert event["proposed_disposition"] == "REFUTATION_PROPOSAL"
    assert event["producer_invocation_id"] == RUN_ID
    assert event["methodology_obligation_id"] == (
        f"AXISGAP:{item['work_item_id']}"
    )
    assert event["guard_locus"] == (
        f"{item['source_relpath']}:{item['source_locus']}"
    )
    assert event["harvest_kind"] == "TYPED_AXIS_CLEAR_V2"
    assert json.loads(event["source_excerpt"]) == final["dispositions"][0]
    axis_commitment = final["dispositions"][0]["invariant_commitment"]
    commitment = event["invariant_commitment"]
    assert commitment["status"] == "COMPLETE"
    assert commitment["ci_id"] == axis_commitment["ci_id"]
    assert commitment["ci_block_sha256"] == axis_commitment["ci_block_sha256"]
    assert commitment["source_item_id"] == item["work_item_id"]
    assert commitment["source_artifact_sha256"] == event[
        "source_artifact_sha256"
    ]
    assert commitment["source_excerpt_sha256"] == event[
        "source_excerpt_sha256"
    ]
    assert commitment["axis_commitment_binding_digest"] == axis_commitment[
        "binding_digest"
    ]
    assert ledger["axis_authority_binding"][
        "application_receipt_digest"
    ] == final["application_receipt_digest"]


def test_exact_zero_emits_valid_empty_axis_ledger(tmp_path: Path) -> None:
    worklist_path, receipt_path, _worklist, _final = _authorities(
        tmp_path,
        exact_zero=True,
    )
    ledger = NEG.build_axis_clear_candidate_negative_ledger(
        worklist_path=worklist_path,
        application_receipt_path=receipt_path,
        expected_run_id=RUN_ID,
    )

    NEG.validate_candidate_negative_ledger(ledger)
    assert ledger["status"] == "CLEAN"
    assert ledger["event_count"] == 0
    assert ledger["events"] == []
    assert ledger["families"] == []


def test_emits_exactly_one_event_for_each_typed_clear_row(
    tmp_path: Path,
) -> None:
    project, scratchpad = FIX._seed(tmp_path)
    worklist = FIX._worklist(
        project,
        FIX._matrix(
            [
                FIX._gap(
                    "A.settle(uint256)",
                    "contracts/A.sol",
                    "boundary",
                ),
                FIX._gap(
                    "B.settle(uint256)",
                    "contracts/B.sol",
                    "identity",
                ),
            ]
        ),
        run_id=RUN_ID,
    )
    rows = [
        {
            "work_item_id": item["work_item_id"],
            "disposition": "CLEAR",
            "action_id": "",
            "evidence": [FIX._source_clear(item)],
            "rationale": f"exact source guard for {item['function_identity']}",
        }
        for item in worklist["items"]
    ]
    sidecar = FIX._sidecar(worklist, rows, run_id=RUN_ID)
    evidence, prior = _semantic_context(scratchpad, worklist)
    initial, plan = AXIS.reconcile_axis_dispositions_initial(
        worklist,
        base_dispositions_raw=sidecar,
        base_findings_raw=b"",
        execution_evidence_authority=evidence,
        canonical_prior_ids=prior.aliases,
        canonical_prior_authority_digest=prior.authority_digest,
        repair_cap=16,
    )
    final = AXIS.reconcile_axis_dispositions_final(
        worklist,
        initial_receipt=initial,
        repair_plan=plan,
        repair_execution_receipt=AXIS.build_axis_repair_execution_receipt(
            plan,
            state="NOT_REQUIRED",
        ),
        base_findings_raw=b"",
        execution_evidence_authority=evidence,
        canonical_prior_ids=prior.aliases,
        canonical_prior_authority_digest=prior.authority_digest,
    )
    AXIS.write_axis_disposition_v2_artifacts(
        scratchpad,
        worklist=worklist,
        application_receipt=final,
    )
    ledger = NEG.build_axis_clear_candidate_negative_ledger(
        worklist_path=scratchpad / AXIS.WORKLIST_NAME,
        application_receipt_path=(
            scratchpad / AXIS.AXIS_APPLICATION_RECEIPT_NAME
        ),
        expected_run_id=RUN_ID,
    )

    assert ledger["event_count"] == 2
    assert {
        event["source_item_id"] for event in ledger["events"]
    } == {
        item["work_item_id"] for item in worklist["items"]
    }
    assert len({event["event_id"] for event in ledger["events"]}) == 2
    assert len({event["family_id"] for event in ledger["events"]}) == 2


def test_writer_emits_canonical_axis_ledger_filename(tmp_path: Path) -> None:
    worklist_path, receipt_path, _worklist, _final = _authorities(tmp_path)
    output = NEG.write_axis_clear_candidate_negative_ledger(
        receipt_path.parent,
        worklist_path=worklist_path,
        application_receipt_path=receipt_path,
        expected_run_id=RUN_ID,
    )
    assert output == (
        receipt_path.parent
        / "candidate_negative_proposals_axis_coverage.json"
    )
    persisted = json.loads(output.read_text(encoding="utf-8"))
    NEG.validate_axis_clear_candidate_negative_ledger(
        persisted,
        worklist_path=worklist_path,
        application_receipt_path=receipt_path,
        expected_run_id=RUN_ID,
    )
    plan = NEG.build_candidate_negative_application_plan(
        receipt_path.parent,
        phases=["axis_coverage"],
    )
    assert plan["status"] == "READY"
    assert plan["input_row_count"] == 1
    assert plan["work_item_count"] == 1
    item = plan["work_items"][0]
    assert item["candidate_identity_state"] == "EXACT"
    assert item["producer_invocation_ids"] == [RUN_ID]
    original = json.loads(item["original_evidence"])
    assert original["source_item_ids"] == [
        persisted["events"][0]["source_item_id"]
    ]
    before = output.read_bytes()
    NEG.write_axis_clear_candidate_negative_ledger(
        receipt_path.parent,
        worklist_path=worklist_path,
        application_receipt_path=receipt_path,
        expected_run_id=RUN_ID,
    )
    assert output.read_bytes() == before


def test_stale_run_and_tampered_authority_never_emit_clear(
    tmp_path: Path,
) -> None:
    worklist_path, receipt_path, _worklist, _final = _authorities(tmp_path)
    with pytest.raises(NEG.CandidateNegativeAuthorityError, match="run"):
        NEG.build_axis_clear_candidate_negative_ledger(
            worklist_path=worklist_path,
            application_receipt_path=receipt_path,
            expected_run_id="stale-run",
        )

    tampered = json.loads(receipt_path.read_text(encoding="utf-8"))
    tampered["dispositions"][0]["rationale"] = "tampered"
    receipt_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(
        NEG.CandidateNegativeAuthorityError,
        match="application receipt",
    ):
        NEG.build_axis_clear_candidate_negative_ledger(
            worklist_path=worklist_path,
            application_receipt_path=receipt_path,
            expected_run_id=RUN_ID,
        )


def test_duplicate_json_authority_key_is_rejected(tmp_path: Path) -> None:
    worklist_path, receipt_path, _worklist, _final = _authorities(tmp_path)
    raw = worklist_path.read_text(encoding="utf-8")
    worklist_path.write_text(
        raw.replace(
            '"schema_version":',
            '"schema_version":"forged","schema_version":',
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(
        NEG.CandidateNegativeAuthorityError,
        match="worklist/application receipt is invalid",
    ):
        NEG.build_axis_clear_candidate_negative_ledger(
            worklist_path=worklist_path,
            application_receipt_path=receipt_path,
            expected_run_id=RUN_ID,
        )


def test_debt_authority_is_fail_visible_without_invented_clear(
    tmp_path: Path,
) -> None:
    worklist_path, receipt_path, _worklist, _final = _authorities(
        tmp_path,
        debt=True,
    )
    ledger = NEG.build_axis_clear_candidate_negative_ledger(
        worklist_path=worklist_path,
        application_receipt_path=receipt_path,
        expected_run_id=RUN_ID,
    )

    assert ledger["status"] == "INPUT_DEBT"
    assert ledger["events"] == []
    assert {
        issue["code"] for issue in ledger["issues"]
    } >= {
        "AXIS_DENOMINATOR_NOT_EXACT",
        "AXIS_APPLICATION_AUTHORITY_DEBT",
    }


def test_tampered_emitted_event_cannot_replay_against_axis_authority(
    tmp_path: Path,
) -> None:
    worklist_path, receipt_path, _worklist, _final = _authorities(tmp_path)
    ledger = NEG.build_axis_clear_candidate_negative_ledger(
        worklist_path=worklist_path,
        application_receipt_path=receipt_path,
        expected_run_id=RUN_ID,
    )
    tampered = json.loads(json.dumps(ledger))
    tampered["events"][0]["source_item_id"] = "AXW-" + "F" * 24
    unsigned = {
        key: value for key, value in tampered.items()
        if key != "ledger_digest"
    }
    tampered["ledger_digest"] = NEG._digest(unsigned)

    with pytest.raises(NEG.CandidateNegativeAuthorityError):
        NEG.validate_axis_clear_candidate_negative_ledger(
            tampered,
            worklist_path=worklist_path,
            application_receipt_path=receipt_path,
            expected_run_id=RUN_ID,
        )


def test_resigned_axis_commitment_tamper_fails_generic_downstream_validation(
    tmp_path: Path,
) -> None:
    worklist_path, receipt_path, _worklist, _final = _authorities(tmp_path)
    ledger = NEG.build_axis_clear_candidate_negative_ledger(
        worklist_path=worklist_path,
        application_receipt_path=receipt_path,
        expected_run_id=RUN_ID,
    )
    tampered = json.loads(json.dumps(ledger))
    commitment = tampered["events"][0]["invariant_commitment"]
    commitment["axis_source_hash"] = "0" * 64
    commitment["binding_digest"] = NEG._digest(
        {key: value for key, value in commitment.items() if key != "binding_digest"}
    )
    event = tampered["events"][0]
    event["event_digest"] = NEG._digest(
        {key: value for key, value in event.items() if key != "event_digest"}
    )
    tampered["ledger_digest"] = NEG._digest(
        {key: value for key, value in tampered.items() if key != "ledger_digest"}
    )

    with pytest.raises(
        NEG.CandidateNegativeAuthorityError,
        match="committed-invariant projection mismatch",
    ):
        NEG.validate_candidate_negative_ledger(tampered)


def test_axis_ledger_cannot_be_forged_through_markdown_parser(
    tmp_path: Path,
) -> None:
    method = tmp_path / "method.md"
    method.write_text("# not typed axis authority\n", encoding="utf-8")
    with pytest.raises(
        NEG.CandidateNegativeAuthorityError,
        match="typed v2 adapter",
    ):
        NEG.build_candidate_negative_ledger(
            phase="axis_coverage",
            artifacts=[
                NEG.ArtifactInput(
                    relative_path="axis_coverage_findings.md",
                    content=(
                        b"## Finding [AXW-FAKE]: fake\n"
                        b"**Verdict**: CLEAR\n"
                    ),
                    producer_identity="MODEL",
                    producer_invocation_id=RUN_ID,
                )
            ],
            methodology_path=method,
        )
