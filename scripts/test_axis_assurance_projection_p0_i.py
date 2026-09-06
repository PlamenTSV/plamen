"""P0-I schema-v2 axis debt must reach the unified assurance authority."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from assurance_limitations import (
    DISCOVERY_RECALL,
    assurance_projection_input_paths,
    build_current_assurance_manifest,
)
from axis_disposition import (
    AXIS_PROMOTION_RECEIPT_NAME,
    build_axis_execution_evidence_authority,
    build_axis_promotion_authority,
    build_axis_repair_execution_receipt,
    compile_axis_worklist_v2,
    reconcile_axis_dispositions_final,
    reconcile_axis_dispositions_initial,
    write_axis_disposition_v2_artifacts,
)
from axis_canonical_prior import (
    AUTHORITY_NAME as AXIS_PRIOR_AUTHORITY_NAME,
    SNAPSHOT_NAME as AXIS_PRIOR_SNAPSHOT_NAME,
    capture_axis_canonical_prior_authority,
)
from exploration_clear_lifecycle import derive_canonical_prior_authority
from plamen_types import Checkpoint


RUN_ID = "axis-assurance-fixture"
CANONICAL_AXIS_INPUTS = {
    "_hot_function_axes.json",
    AXIS_PRIOR_SNAPSHOT_NAME,
    AXIS_PRIOR_AUTHORITY_NAME,
    "axis_disposition_worklist.json",
    "axis_execution_evidence_authority.json",
    "axis_coverage_findings.md",
    "axis_coverage_dispositions.json",
    "axis_disposition_initial_receipt.json",
    "axis_repair_plan.json",
    "axis_coverage_repair_findings.md",
    "axis_coverage_repair_dispositions.json",
    "axis_repair_execution_receipt.json",
    "axis_disposition_receipt.json",
    "axis_repair_work.json",
    "axis_assurance_debt.json",
    "axis_assurance_limitations.md",
    "findings_inventory.md",
    "axis_coverage_promotion_receipt.json",
}


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value) + b"\n")


def _seed_project(tmp_path: Path) -> tuple[Path, Path]:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    source = project / "contracts" / "Unit.sol"
    scratchpad.mkdir(parents=True)
    source.parent.mkdir(parents=True)
    source.write_text(
        "contract Unit {\n"
        "  function settle(address recipient) external {\n"
        "    require(recipient != address(0));\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    prior = derive_canonical_prior_authority(
        scratchpad / "_canonical_finding_ids.json"
    )
    _write_json(scratchpad / "exploration_clear_prior_aliases.json", prior.payload)
    return project, scratchpad


def _population(
    project: Path,
    *,
    gap_axes: tuple[str, ...] = (),
    status: str = "EXACT",
    debt: tuple[str, ...] = (),
) -> dict:
    source = project / "contracts" / "Unit.sol"
    source_hash = _sha(
        source.read_text(encoding="utf-8", errors="strict").encode("utf-8")
    )
    gaps = [
        {
            "function_identity": "Unit.settle(address)",
            "function": "settle",
            "loc": "contracts/Unit.sol:L2",
            "axis": axis,
            "lang": "solidity",
            "source_relpath": "contracts/Unit.sol",
            "source_locus": "contracts/Unit.sol:L2",
            "source_sha256": source_hash,
        }
        for axis in gap_axes
    ]
    hot = (
        [
            {
                "function_identity": "Unit.settle(address)",
                "function": "settle",
                "loc": "contracts/Unit.sol:L2",
                "lang": "solidity",
            }
        ]
        if gap_axes
        else []
    )
    cells = {
        axis: ("GAP" if axis in gap_axes else "EXAMINED")
        for axis in (
            "theft",
            "liveness",
            "accounting",
            "provenance",
            "boundary",
            "identity",
        )
    }
    matrix = (
        [
            {
                "function_identity": "Unit.settle(address)",
                "function": "settle",
                "loc": "contracts/Unit.sol:L2",
                "lang": "solidity",
                "score": 1,
                "source_relpath": "contracts/Unit.sol",
                "source_locus": "contracts/Unit.sol:L2",
                "source_sha256": source_hash,
                "cells": cells,
                "cell_authority": {
                    axis: (
                        "RECALL_SAFE_DEFAULT"
                        if axis in gap_axes
                        else "TYPED_APPLICATION_AUTHORITY"
                    )
                    for axis in cells
                },
            }
        ]
        if gap_axes
        else []
    )
    unsigned = {
        "schema_version": "plamen.axis_population.v2",
        "provider_version": "enumeration.axis_population/2",
        "run_id": RUN_ID,
        "denominator_status": status,
        "observed_hot_function_count": len(hot),
        "gap_count": len(gaps),
        "exact_zero_proven": (
            status == "EXACT" and not hot and not gaps and not debt
        ),
        "requires_execution": bool(gaps or debt or status != "EXACT"),
        "source_bindings": {
            "_mechanical_graph.json": "1" * 64,
            "_hot_function_cap_receipt.json": "2" * 64,
        },
        "cap_receipt_sha256": "2" * 64,
        "examined_authority": {
            "status": "ABSENT",
            "schema_version": "plamen.axis_examined_authority.v1",
            "row_count": 0,
            "authority_digest": "",
            "hint_artifacts_consumed": [],
        },
        "hot": hot,
        "matrix": matrix,
        "gaps": gaps,
        "debt": list(debt),
        "raw_fallback_authority": "CANDIDATE_ONLY",
        "methodology_application_proven_by_raw_prose": False,
    }
    return {**unsigned, "population_digest": _sha(_canonical(unsigned))}


def _sidecar(
    worklist: dict,
    rows: list[dict],
    *,
    repair_plan_digest: str = "",
) -> bytes:
    unsigned = {
        "schema_version": (
            "plamen.axis_repair_model_dispositions.v1"
            if repair_plan_digest
            else "plamen.axis_model_dispositions.v1"
        ),
        "run_id": RUN_ID,
        "worklist_hash": worklist["worklist_hash"],
        "producer": "MODEL",
        "items": rows,
    }
    if repair_plan_digest:
        unsigned["repair_plan_digest"] = repair_plan_digest
    return _canonical(
        {**unsigned, "sidecar_digest": _sha(_canonical(unsigned))}
    )


def _action(item: dict) -> bytes:
    return (
        f"### Finding [{item['required_action_id']}]: retained axis candidate\n"
        f"**Work Item ID**: {item['work_item_id']}\n"
        "**Severity**: Low\n"
        f"**Location**: {item['source_relpath']}:{item['source_locus']}\n"
        "**Description**: exact typed candidate\n"
        "**Impact**: verifier determines material harm\n\n"
    ).encode("utf-8")


def _source_clear(item: dict) -> dict:
    return {
        "kind": "SOURCE_LOCUS",
        "source_relpath": item["source_relpath"],
        "source_locus": item["source_locus"],
        "source_hash": item["source_hash"],
    }


def _persist_v2_authority(
    project: Path,
    scratchpad: Path,
    *,
    gap_axes: tuple[str, ...] = (),
    status: str = "EXACT",
    input_debt: tuple[str, ...] = (),
    disposition: str = "MISSING",
    repair_state: str | None = None,
    repair_cap: int = 16,
    promotion: bool = True,
) -> dict:
    population = _population(
        project,
        gap_axes=gap_axes,
        status=status,
        debt=input_debt,
    )
    population_raw = _canonical(population)
    (scratchpad / "_hot_function_axes.json").write_bytes(population_raw)
    worklist = compile_axis_worklist_v2(
        population,
        matrix_raw=population_raw,
        production_root=project,
        population_authority=population,
        run_id=RUN_ID,
    )
    evidence = build_axis_execution_evidence_authority(
        run_id=RUN_ID,
        receipt_bindings=(),
    )
    rows: list[dict] = []
    findings_raw = b""
    if worklist["items"] and disposition != "MISSING":
        for item in worklist["items"]:
            if disposition == "CLEAR":
                rows.append(
                    {
                        "work_item_id": item["work_item_id"],
                        "disposition": "CLEAR",
                        "action_id": "",
                        "evidence": [_source_clear(item)],
                        "rationale": "exact source guard at the bound locus",
                    }
                )
            elif disposition == "FINDING":
                rows.append(
                    {
                        "work_item_id": item["work_item_id"],
                        "disposition": "FINDING",
                        "action_id": item["required_action_id"],
                        "evidence": [],
                        "rationale": "candidate requires independent verification",
                    }
                )
                findings_raw += _action(item)
            else:
                raise AssertionError(f"unknown test disposition {disposition}")
    base_sidecar = _sidecar(worklist, rows)
    prior = (
        capture_axis_canonical_prior_authority(
            scratchpad,
            run_id=RUN_ID,
            worklist_hash=str(worklist["worklist_hash"]),
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
        )
        if worklist.get("requires_execution") is True
        else derive_canonical_prior_authority(
            scratchpad / "_canonical_finding_ids.json"
        )
    )
    initial, plan = reconcile_axis_dispositions_initial(
        worklist,
        base_dispositions_raw=base_sidecar,
        base_findings_raw=findings_raw,
        execution_evidence_authority=evidence,
        canonical_prior_ids=prior.aliases,
        canonical_prior_authority_digest=prior.authority_digest,
        repair_cap=repair_cap,
    )
    state = repair_state or (
        "NOT_REQUIRED" if not plan["observed_count"] else "FAILED"
    )
    repair_kwargs = (
        {"issues": ("bounded repair worker failed",)}
        if state == "FAILED"
        else {}
    )
    repair = build_axis_repair_execution_receipt(
        plan,
        state=state,
        **repair_kwargs,
    )
    final = reconcile_axis_dispositions_final(
        worklist,
        initial_receipt=initial,
        repair_plan=plan,
        repair_execution_receipt=repair,
        base_findings_raw=findings_raw,
        execution_evidence_authority=evidence,
        canonical_prior_ids=prior.aliases,
        canonical_prior_authority_digest=prior.authority_digest,
    )
    (scratchpad / "axis_coverage_dispositions.json").write_bytes(base_sidecar)
    (scratchpad / "axis_coverage_findings.md").write_bytes(findings_raw)
    write_axis_disposition_v2_artifacts(
        scratchpad,
        worklist=worklist,
        execution_evidence_authority=evidence,
        initial_receipt=initial,
        repair_plan=plan,
        repair_execution_receipt=repair,
        application_receipt=final,
    )
    if promotion:
        inventory = ""
        for index, item in enumerate(worklist["items"], start=1):
            if disposition != "FINDING":
                continue
            inventory += (
                f"### Finding [INV-{index:03d}]: delivered axis action\n"
                "**Severity**: Low\n"
                f"**Location**: {item['source_relpath']}:{item['source_locus']}\n"
                f"**Source IDs**: AXISGAP:{item['required_action_id']}\n"
                "**Description**: exact typed candidate\n"
                "**Impact**: verifier determines material harm\n\n"
            )
        (scratchpad / "findings_inventory.md").write_text(
            inventory, encoding="utf-8"
        )
        promotion_receipt = build_axis_promotion_authority(
            final,
            run_id=RUN_ID,
            base_findings_raw=findings_raw,
            repair_findings_raw=b"",
            inventory_text=inventory,
        )
        _write_json(
            scratchpad / AXIS_PROMOTION_RECEIPT_NAME,
            promotion_receipt,
        )
    return {
        "worklist": worklist,
        "initial": initial,
        "plan": plan,
        "repair": repair,
        "final": final,
    }


def _manifest(project: Path, scratchpad: Path) -> dict:
    return build_current_assurance_manifest(
        Checkpoint(run_id=RUN_ID),
        scratchpad,
        project,
    )


def _axis_rows(manifest: dict) -> list[dict]:
    return [row for row in manifest["rows"] if row["phase"] == "axis_coverage"]


def test_exact_v2_zero_with_not_required_receipt_has_no_limitation(
    tmp_path: Path,
) -> None:
    project, scratchpad = _seed_project(tmp_path)
    authority = _persist_v2_authority(project, scratchpad)
    assert authority["repair"]["state"] == "NOT_REQUIRED"
    assert authority["final"]["application_record_complete"] is True
    for name in (
        "axis_coverage_findings.md",
        "axis_coverage_dispositions.json",
        "axis_disposition_initial_receipt.json",
        "axis_repair_plan.json",
        "axis_repair_execution_receipt.json",
        "axis_disposition_receipt.json",
        "axis_repair_work.json",
        "axis_assurance_debt.json",
        "axis_assurance_limitations.md",
        "axis_coverage_promotion_receipt.json",
    ):
        (scratchpad / name).unlink(missing_ok=True)
    assert _axis_rows(_manifest(project, scratchpad)) == []


@pytest.mark.parametrize("mutation", ["missing", "tampered"])
def test_unconditional_not_required_repair_receipt_is_replayed(
    tmp_path: Path,
    mutation: str,
) -> None:
    project, scratchpad = _seed_project(tmp_path)
    _persist_v2_authority(project, scratchpad)
    path = scratchpad / "axis_repair_execution_receipt.json"
    if mutation == "missing":
        path.unlink()
    else:
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["state"] = "FAILED"
        _write_json(path, payload)
    rows = _axis_rows(_manifest(project, scratchpad))
    assert {row["gate_id"] for row in rows} == {
        "axis_disposition_authority_invalid"
    }


@pytest.mark.parametrize("status", ["UNKNOWN", "DEGRADED"])
def test_nonexact_zero_population_projects_application_debt(
    tmp_path: Path,
    status: str,
) -> None:
    project, scratchpad = _seed_project(tmp_path)
    authority = _persist_v2_authority(
        project,
        scratchpad,
        status=status,
        input_debt=("provider could not prove exact population",),
    )
    assert authority["final"]["application_record_complete"] is False
    rows = _axis_rows(_manifest(project, scratchpad))
    assert "axis_denominator_not_exact" in {row["gate_id"] for row in rows}
    assert all(row["assurance_impact"] == DISCOVERY_RECALL for row in rows)


def test_failed_repair_and_residual_are_report_visible(tmp_path: Path) -> None:
    project, scratchpad = _seed_project(tmp_path)
    authority = _persist_v2_authority(
        project,
        scratchpad,
        gap_axes=("boundary",),
        repair_state="FAILED",
    )
    assert authority["final"]["residual_work_item_ids"]
    gate_ids = {row["gate_id"] for row in _axis_rows(_manifest(project, scratchpad))}
    assert {"axis_disposition_unresolved", "axis_repair_execution_failed"} <= gate_ids


def test_overflow_and_residual_are_report_visible(tmp_path: Path) -> None:
    project, scratchpad = _seed_project(tmp_path)
    authority = _persist_v2_authority(
        project,
        scratchpad,
        gap_axes=("boundary",),
        repair_state="OVERFLOW",
        repair_cap=0,
    )
    assert authority["plan"]["overflow"] is True
    gate_ids = {row["gate_id"] for row in _axis_rows(_manifest(project, scratchpad))}
    assert {"axis_disposition_unresolved", "axis_repair_overflow"} <= gate_ids


def test_application_and_delivery_debt_are_separate(tmp_path: Path) -> None:
    project, scratchpad = _seed_project(tmp_path)
    authority = _persist_v2_authority(
        project,
        scratchpad,
        gap_axes=("theft",),
        disposition="FINDING",
        promotion=False,
    )
    assert authority["final"]["application_record_complete"] is True
    gate_ids = {row["gate_id"] for row in _axis_rows(_manifest(project, scratchpad))}
    assert gate_ids == {"axis_promotion_delivery_invalid"}


def test_legacy_self_signed_promotion_remains_delivery_only_debt(
    tmp_path: Path,
) -> None:
    project, scratchpad = _seed_project(tmp_path)
    _persist_v2_authority(
        project,
        scratchpad,
        gap_axes=("theft",),
        disposition="FINDING",
    )
    assert {
        row["gate_id"] for row in _axis_rows(_manifest(project, scratchpad))
    } == {"axis_promotion_delivery_invalid"}
    path = scratchpad / AXIS_PROMOTION_RECEIPT_NAME
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["status"] = "COMPLETED_WITH_DEBT"
    _write_json(path, payload)
    gate_ids = {row["gate_id"] for row in _axis_rows(_manifest(project, scratchpad))}
    assert gate_ids == {"axis_promotion_delivery_invalid"}


def test_application_receipt_tamper_is_application_debt(tmp_path: Path) -> None:
    project, scratchpad = _seed_project(tmp_path)
    _persist_v2_authority(
        project,
        scratchpad,
        gap_axes=("boundary",),
        disposition="CLEAR",
    )
    path = scratchpad / "axis_disposition_receipt.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["status"] = "COMPLETED_WITH_DEBT"
    _write_json(path, payload)
    gate_ids = {row["gate_id"] for row in _axis_rows(_manifest(project, scratchpad))}
    assert gate_ids == {"axis_disposition_authority_invalid"}


def test_generic_shortfall_alone_does_not_activate_axis(tmp_path: Path) -> None:
    project, scratchpad = _seed_project(tmp_path)
    (scratchpad / "_coverage_shortfalls.json").write_text(
        '{"schema_version":1,"shortfalls":[{"producer":"optional","omitted":3}]}',
        encoding="utf-8",
    )
    assert _axis_rows(_manifest(project, scratchpad)) == []


def test_projection_inputs_bind_every_v2_axis_authority_file(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    for name in CANONICAL_AXIS_INPUTS:
        (scratchpad / name).write_text("{}\n", encoding="utf-8")
    assert CANONICAL_AXIS_INPUTS <= set(assurance_projection_input_paths(scratchpad))
