"""P0-I schema-v2 deterministic axis-disposition core.

These fixtures intentionally avoid driver/orchestrator behavior.  They define
the exact authority contract that the later PhaseIO integration may consume.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from axis_disposition import (
    APPLICATION_RECEIPT_V2_SCHEMA,
    AXIS_EXECUTION_EVIDENCE_AUTHORITY_NAME,
    AXIS_MODEL_DISPOSITIONS_NAME,
    AXIS_PROMOTION_RECEIPT_NAME,
    AXIS_REPAIR_EXECUTION_RECEIPT_NAME,
    AXIS_REPAIR_MODEL_DISPOSITIONS_NAME,
    AXIS_REPAIR_PLAN_NAME,
    LIMITATIONS_NAME,
    WORKLIST_V2_SCHEMA,
    AxisDispositionError,
    build_axis_execution_evidence_authority,
    build_axis_promotion_authority,
    build_axis_repair_execution_receipt,
    compile_axis_worklist_v2,
    parse_axis_model_dispositions,
    reconcile_axis_dispositions_final,
    reconcile_axis_dispositions_initial,
    referenced_axis_action_blocks,
    validate_axis_disposition_authority_v2,
    validate_axis_execution_evidence_authority,
    validate_axis_assurance_projection_v2,
    validate_axis_promotion_authority,
    write_axis_disposition_v2_artifacts,
)


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


def _seed(tmp_path: Path) -> tuple[Path, Path]:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    (project / "contracts").mkdir(parents=True)
    scratchpad.mkdir()
    (project / "contracts" / "A.sol").write_text(
        "contract A {\n"
        " function settle(uint256 amount) external { require(amount > 0); }\n"
        "}\n",
        encoding="utf-8",
    )
    (project / "contracts" / "B.sol").write_text(
        "contract B {\n"
        " function settle(uint256 amount) external { require(amount < 10); }\n"
        "}\n",
        encoding="utf-8",
    )
    return project, scratchpad


def _matrix(gaps: list[dict]) -> dict:
    grouped: dict[tuple[str, str, str], dict[str, str]] = {}
    hot: list[dict] = []
    for gap in gaps:
        key = (
            gap["function_identity"],
            gap["function"],
            gap["loc"],
        )
        if key not in grouped:
            grouped[key] = {
                "theft": "EXAMINED",
                "liveness": "EXAMINED",
                "accounting": "EXAMINED",
                "provenance": "EXAMINED",
                "boundary": "EXAMINED",
                "identity": "EXAMINED",
            }
            hot.append(
                {
                    "function_identity": gap["function_identity"],
                    "function": gap["function"],
                    "loc": gap["loc"],
                    "lang": gap["lang"],
                }
            )
        grouped[key][gap["axis"]] = "GAP"
    matrix = [
        {
            "function_identity": identity,
            "function": function,
            "loc": loc,
            "cells": cells,
        }
        for (identity, function, loc), cells in grouped.items()
    ]
    return {"hot": hot, "matrix": matrix, "gaps": gaps}


def _gap(
    identity: str,
    path: str,
    axis: str,
    *,
    function: str = "settle",
) -> dict:
    return {
        "function_identity": identity,
        "function": function,
        "loc": f"{path}:L2",
        "axis": axis,
        "lang": "solidity",
    }


def _worklist(
    project: Path,
    matrix: dict,
    *,
    run_id: str = "run-axis-v2",
    status: str = "EXACT",
    debt: tuple[str, ...] = (),
) -> dict:
    for row in matrix["gaps"]:
        relpath, locus = row["loc"].rsplit(":", 1)
        row.update(
            {
                "source_relpath": relpath,
                "source_locus": f"{relpath}:{locus}",
                "source_sha256": _sha(
                    (project / relpath)
                    .read_text(encoding="utf-8", errors="strict")
                    .encode("utf-8")
                ),
            }
        )
    gaps_by_identity = {
        (row["function_identity"], row["axis"]): row
        for row in matrix["gaps"]
    }
    for row in matrix["matrix"]:
        matching = next(
            gap
            for gap in matrix["gaps"]
            if gap["function_identity"] == row["function_identity"]
        )
        row.update(
            {
                "lang": matching["lang"],
                "score": 1,
                "source_relpath": matching["source_relpath"],
                "source_locus": matching["source_locus"],
                "source_sha256": matching["source_sha256"],
                "cell_authority": {
                    axis: (
                        "RECALL_SAFE_DEFAULT"
                        if (row["function_identity"], axis)
                        in gaps_by_identity
                        else "TYPED_APPLICATION_AUTHORITY"
                    )
                    for axis in row["cells"]
                },
            }
        )
    unsigned = {
        "schema_version": "plamen.axis_population.v2",
        "provider_version": "enumeration.axis_population/2",
        "run_id": run_id,
        "denominator_status": status,
        "observed_hot_function_count": len(matrix["hot"]),
        "gap_count": len(matrix["gaps"]),
        "exact_zero_proven": (
            status == "EXACT"
            and not matrix["hot"]
            and not matrix["gaps"]
            and not debt
        ),
        "requires_execution": bool(
            matrix["gaps"] or debt or status != "EXACT"
        ),
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
        "hot": matrix["hot"],
        "matrix": matrix["matrix"],
        "gaps": matrix["gaps"],
        "debt": list(debt),
        "raw_fallback_authority": "CANDIDATE_ONLY",
        "methodology_application_proven_by_raw_prose": False,
    }
    authority = {
        **unsigned,
        "population_digest": _sha(_canonical(unsigned)),
    }
    matrix.clear()
    matrix.update(authority)
    matrix_raw = _canonical(authority)
    return compile_axis_worklist_v2(
        authority,
        matrix_raw=matrix_raw,
        production_root=project,
        population_authority=authority,
        run_id=run_id,
    )


def _sidecar(
    worklist: dict,
    rows: list[dict],
    *,
    run_id: str = "run-axis-v2",
    repair_plan_digest: str = "",
    add_clear_invariants: bool = True,
) -> bytes:
    schema = (
        "plamen.axis_repair_model_dispositions.v1"
        if repair_plan_digest
        else "plamen.axis_model_dispositions.v1"
    )
    normalized_rows: list[dict] = []
    work_by_id = {
        str(item["work_item_id"]): item for item in worklist["items"]
    }
    for original in rows:
        row = dict(original)
        if "invariant_commitment" not in row:
            if row.get("disposition") == "CLEAR" and add_clear_invariants:
                item = work_by_id.get(str(row.get("work_item_id") or ""))
                row["invariant_commitment"] = (
                    _axis_ci(item, row.get("evidence"))
                    if item is not None
                    else None
                )
            elif row.get("disposition") in {"FINDING", "UNRESOLVED"}:
                row["invariant_commitment"] = None
        normalized_rows.append(row)
    unsigned = {
        "schema_version": schema,
        "run_id": run_id,
        "worklist_hash": worklist["worklist_hash"],
        "producer": "MODEL",
        "items": normalized_rows,
    }
    if repair_plan_digest:
        unsigned["repair_plan_digest"] = repair_plan_digest
    return _canonical(
        {
            **unsigned,
            "sidecar_digest": _sha(_canonical(unsigned)),
        }
    )


def _action(item: dict, *, title: str = "axis candidate") -> str:
    return (
        f"### Finding [{item['required_action_id']}]: {title}\n"
        f"**Work Item ID**: {item['work_item_id']}\n"
        "**Severity**: Low\n"
        f"**Location**: {item['source_relpath']}:{item['source_locus']}\n"
        "**Description**: exact typed candidate\n"
        "**Impact**: verifier determines material harm\n\n"
    )


def _source_clear(item: dict) -> dict:
    return {
        "kind": "SOURCE_LOCUS",
        "source_relpath": item["source_relpath"],
        "source_locus": item["source_locus"],
        "source_hash": item["source_hash"],
    }


def _axis_ci(
    item: dict,
    evidence: object,
    *,
    ci_id: str | None = None,
    shape: str = "NO_REVERT_AT_BOUNDARY",
    assertion: str | None = None,
    falsify_class: str = "boundary",
) -> dict:
    unsigned = {
        "ci_id": ci_id or f"AXIS-CI-{item['work_item_id'][4:]}",
        "locus": f"{item['source_relpath']}:{item['source_locus']}",
        "shape": shape,
        "assertion": assertion or (
            f"The {item['axis']} safety property holds at the exact AXW locus."
        ),
        "falsify_class": falsify_class,
        "provenance": f"AXW:{item['work_item_id']}",
        "source_hash": item["source_hash"],
        "evidence_sha256": _sha(_canonical(evidence)),
    }
    return {
        **unsigned,
        "ci_block_sha256": _sha(_canonical(unsigned)),
    }


def _zero_evidence(run_id: str = "run-axis-v2") -> dict:
    return build_axis_execution_evidence_authority(
        run_id=run_id,
        receipt_bindings=(),
    )


def _initial(
    worklist: dict,
    sidecar: bytes,
    markdown: str,
    *,
    canonical_ids: dict[str, str] | None = None,
    canonical_digest: str = "c" * 64,
) -> tuple[dict, dict]:
    return reconcile_axis_dispositions_initial(
        worklist,
        base_dispositions_raw=sidecar,
        base_findings_raw=markdown.encode("utf-8"),
        execution_evidence_authority=_zero_evidence(worklist["run_id"]),
        canonical_prior_ids=canonical_ids or {},
        canonical_prior_authority_digest=canonical_digest,
        repair_cap=16,
    )


def test_worklist_v2_binds_exact_function_source_cell_and_action(
    tmp_path: Path,
) -> None:
    project, _scratchpad = _seed(tmp_path)
    matrix = _matrix(
        [_gap("A.settle(uint256)", "contracts/A.sol", "boundary")]
    )
    worklist = _worklist(project, matrix)

    assert worklist["schema_version"] == WORKLIST_V2_SCHEMA
    assert worklist["denominator_status"] == "EXACT"
    assert worklist["clean_empty"] is False
    item = worklist["items"][0]
    assert set(item) == {
        "work_item_id",
        "function_identity",
        "function",
        "axis",
        "language",
        "source_relpath",
        "source_locus",
        "source_hash",
        "matrix_cell_hash",
        "required_action_id",
    }
    assert item["function_identity"] == "A.settle(uint256)"
    assert item["source_hash"] == _sha(
        (project / "contracts" / "A.sol")
        .read_text(encoding="utf-8", errors="strict")
        .encode("utf-8")
    )
    assert item["matrix_cell_hash"] == _sha(
        _canonical(matrix["gaps"][0])
    )
    assert item["work_item_id"].startswith("AXW-")
    assert item["required_action_id"].startswith("AXIS-V2-")


def test_unknown_zero_denominator_is_never_clean_and_projects_debt(
    tmp_path: Path,
) -> None:
    project, _scratchpad = _seed(tmp_path)
    matrix = _matrix([])
    worklist = _worklist(
        project,
        matrix,
        status="UNKNOWN",
        debt=("provider exception",),
    )
    assert worklist["count"] == 0
    assert worklist["clean_empty"] is False
    assert worklist["requires_execution"] is True

    sidecar = _sidecar(worklist, [])
    initial, plan = _initial(worklist, sidecar, "")
    repair = build_axis_repair_execution_receipt(
        plan,
        state="NOT_REQUIRED",
    )
    final = reconcile_axis_dispositions_final(
        worklist,
        initial_receipt=initial,
        repair_plan=plan,
        repair_execution_receipt=repair,
        base_findings_raw=b"",
        execution_evidence_authority=_zero_evidence(),
        canonical_prior_ids={},
        canonical_prior_authority_digest="c" * 64,
    )
    assert final["application_record_complete"] is False
    assert final["status"] == "COMPLETED_WITH_DEBT"
    assert final["assurance_debt"]["count"] >= 2
    assert {
        row["debt_kind"] for row in final["assurance_debt"]["items"]
    } >= {"POPULATION_STATUS", "POPULATION_INPUT"}


def test_same_named_functions_are_reconciled_only_by_work_item_id(
    tmp_path: Path,
) -> None:
    project, _scratchpad = _seed(tmp_path)
    worklist = _worklist(
        project,
        _matrix(
            [
                _gap("A.settle(uint256)", "contracts/A.sol", "boundary"),
                _gap("B.settle(uint256)", "contracts/B.sol", "boundary"),
            ]
        ),
    )
    first, second = worklist["items"]
    sidecar = _sidecar(
        worklist,
        [
            {
                "work_item_id": first["work_item_id"],
                "disposition": "CLEAR",
                "action_id": "",
                "evidence": [_source_clear(first)],
                "rationale": "exact source guard",
            },
            {
                "work_item_id": second["work_item_id"],
                "disposition": "UNRESOLVED",
                "action_id": second["required_action_id"],
                "evidence": [],
                "rationale": "requires verification",
            },
        ],
    )
    initial, plan = _initial(worklist, sidecar, _action(second))
    assert initial["status"] == "COMPLETE"
    assert plan["observed_count"] == 0
    assert [
        row["work_item_id"] for row in initial["dispositions"]
    ] == [first["work_item_id"], second["work_item_id"]]


def test_untyped_or_source_drifted_clear_enters_repair(
    tmp_path: Path,
) -> None:
    project, _scratchpad = _seed(tmp_path)
    worklist = _worklist(
        project,
        _matrix([_gap("A.settle(uint256)", "contracts/A.sol", "boundary")]),
    )
    item = worklist["items"][0]
    vague = _sidecar(
        worklist,
        [
            {
                "work_item_id": item["work_item_id"],
                "disposition": "CLEAR",
                "action_id": "",
                "evidence": ["contracts/A.sol:L2 looks safe"],
                "rationale": "looks safe",
            }
        ],
    )
    initial, plan = _initial(worklist, vague, "")
    assert initial["status"] == "REPAIR_REQUIRED"
    assert plan["retained_work_item_ids"] == [item["work_item_id"]]

    altered = _source_clear(item)
    altered["source_hash"] = "0" * 64
    drifted = _sidecar(
        worklist,
        [
            {
                "work_item_id": item["work_item_id"],
                "disposition": "CLEAR",
                "action_id": "",
                "evidence": [altered],
                "rationale": "exact source guard at the bound locus",
            }
        ],
    )
    initial, _plan = _initial(worklist, drifted, "")
    assert initial["status"] == "REPAIR_REQUIRED"


def test_source_locus_clear_rejects_generic_safe_attestation(
    tmp_path: Path,
) -> None:
    project, _scratchpad = _seed(tmp_path)
    worklist = _worklist(
        project,
        _matrix([_gap("A.settle(uint256)", "contracts/A.sol", "boundary")]),
    )
    item = worklist["items"][0]
    sidecar = _sidecar(
        worklist,
        [
            {
                "work_item_id": item["work_item_id"],
                "disposition": "CLEAR",
                "action_id": "",
                "evidence": [_source_clear(item)],
                "rationale": "looks safe",
            }
        ],
    )
    initial, plan = _initial(worklist, sidecar, "")

    assert initial["application_record_complete"] is False
    assert plan["retained_work_item_ids"] == [item["work_item_id"]]
    assert "generic safe prose" in initial["dispositions"][0]["reason"]


def test_clear_without_committed_invariant_enters_exact_repair(
    tmp_path: Path,
) -> None:
    project, _scratchpad = _seed(tmp_path)
    worklist = _worklist(
        project,
        _matrix([_gap("A.settle(uint256)", "contracts/A.sol", "boundary")]),
    )
    item = worklist["items"][0]
    sidecar = _sidecar(
        worklist,
        [
            {
                "work_item_id": item["work_item_id"],
                "disposition": "CLEAR",
                "action_id": "",
                "evidence": [_source_clear(item)],
                "invariant_commitment": None,
                "rationale": "the exact current source guard closes this axis",
            }
        ],
    )

    initial, plan = _initial(worklist, sidecar, "")

    assert initial["status"] == "REPAIR_REQUIRED"
    assert initial["application_record_complete"] is False
    assert initial["dispositions"][0]["invariant_commitment"] is None
    assert "commitment shape mismatch" in initial["dispositions"][0]["reason"]
    assert plan["retained_work_item_ids"] == [item["work_item_id"]]


def test_malformed_clear_committed_invariant_enters_exact_repair(
    tmp_path: Path,
) -> None:
    project, _scratchpad = _seed(tmp_path)
    worklist = _worklist(
        project,
        _matrix([_gap("A.settle(uint256)", "contracts/A.sol", "identity")]),
    )
    item = worklist["items"][0]
    evidence = [_source_clear(item)]
    commitment = _axis_ci(item, evidence)
    commitment["provenance"] = "AXW:AXW-FFFFFFFFFFFFFFFFFFFFFFFF"
    unsigned = {
        key: value
        for key, value in commitment.items()
        if key != "ci_block_sha256"
    }
    commitment["ci_block_sha256"] = _sha(_canonical(unsigned))
    sidecar = _sidecar(
        worklist,
        [
            {
                "work_item_id": item["work_item_id"],
                "disposition": "CLEAR",
                "action_id": "",
                "evidence": evidence,
                "invariant_commitment": commitment,
                "rationale": "the exact current source guard closes this axis",
            }
        ],
    )

    initial, plan = _initial(worklist, sidecar, "")

    assert initial["status"] == "REPAIR_REQUIRED"
    assert "AXW provenance" in initial["dispositions"][0]["reason"]
    assert plan["retained_work_item_ids"] == [item["work_item_id"]]


def test_cross_row_reused_ci_identity_never_completes_either_clear(
    tmp_path: Path,
) -> None:
    project, _scratchpad = _seed(tmp_path)
    worklist = _worklist(
        project,
        _matrix(
            [
                _gap("A.settle(uint256)", "contracts/A.sol", "boundary"),
                _gap("A.settle(uint256)", "contracts/A.sol", "identity"),
            ]
        ),
    )
    rows = []
    for item in worklist["items"]:
        evidence = [_source_clear(item)]
        rows.append(
            {
                "work_item_id": item["work_item_id"],
                "disposition": "CLEAR",
                "action_id": "",
                "evidence": evidence,
                "invariant_commitment": _axis_ci(
                    item,
                    evidence,
                    ci_id="AXIS-CI-REUSED",
                ),
                "rationale": "the exact current source guard closes this axis",
            }
        )

    initial, plan = _initial(worklist, _sidecar(worklist, rows), "")

    assert initial["status"] == "REPAIR_REQUIRED"
    assert initial["application_record_complete"] is False
    assert all(
        row["application_record_complete"] is False
        and "reused across rows" in row["reason"]
        for row in initial["dispositions"]
    )
    assert set(plan["retained_work_item_ids"]) == {
        item["work_item_id"] for item in worklist["items"]
    }


def test_execution_authority_proves_current_run_and_exact_zero() -> None:
    authority = _zero_evidence()
    assert authority["schema_version"] == (
        "plamen.axis_execution_evidence_authority.v1"
    )
    assert authority["state"] == "EXACT"
    assert authority["receipt_count"] == 0
    assert authority["exact_zero"] is True
    assert validate_axis_execution_evidence_authority(
        authority, expected_run_id="run-axis-v2"
    ) == authority
    with pytest.raises(AxisDispositionError, match="run"):
        validate_axis_execution_evidence_authority(
            authority, expected_run_id="foreign-run"
        )


def test_missing_duplicate_unknown_rows_produce_exact_bounded_repair_plan(
    tmp_path: Path,
) -> None:
    project, _scratchpad = _seed(tmp_path)
    worklist = _worklist(
        project,
        _matrix(
            [
                _gap("A.settle(uint256)", "contracts/A.sol", "boundary"),
                _gap("A.settle(uint256)", "contracts/A.sol", "identity"),
            ]
        ),
    )
    first = worklist["items"][0]
    row = {
        "work_item_id": first["work_item_id"],
        "disposition": "CLEAR",
        "action_id": "",
        "evidence": [_source_clear(first)],
        "rationale": "exact source guard at the bound locus",
    }
    sidecar = _sidecar(
        worklist,
        [
            row,
            row,
            {
                **row,
                "work_item_id": "AXW-" + "F" * 24,
            },
        ],
    )
    initial, plan = _initial(worklist, sidecar, "")
    assert initial["status"] == "REPAIR_REQUIRED"
    assert plan["observed_count"] == 2
    assert set(plan["retained_work_item_ids"]) == {
        item["work_item_id"] for item in worklist["items"]
    }
    assert any("duplicate" in issue.lower() for issue in initial["issues"])
    assert any("unknown" in issue.lower() for issue in initial["issues"])


def test_repair_fills_only_planned_rows_and_cannot_override_valid_base(
    tmp_path: Path,
) -> None:
    project, _scratchpad = _seed(tmp_path)
    worklist = _worklist(
        project,
        _matrix(
            [
                _gap("A.settle(uint256)", "contracts/A.sol", "boundary"),
                _gap("A.settle(uint256)", "contracts/A.sol", "identity"),
            ]
        ),
    )
    first, second = worklist["items"]
    base = _sidecar(
        worklist,
        [
            {
                "work_item_id": first["work_item_id"],
                "disposition": "CLEAR",
                "action_id": "",
                "evidence": [_source_clear(first)],
                "rationale": "exact source guard at the bound locus",
            }
        ],
    )
    initial, plan = _initial(worklist, base, "")
    repair_rows = [
        {
            "work_item_id": first["work_item_id"],
            "disposition": "UNRESOLVED",
            "action_id": first["required_action_id"],
            "evidence": [],
            "rationale": "attempted override",
        },
        {
            "work_item_id": second["work_item_id"],
            "disposition": "UNRESOLVED",
            "action_id": second["required_action_id"],
            "evidence": [],
            "rationale": "requires verifier",
        },
    ]
    repair_sidecar = _sidecar(
        worklist,
        repair_rows,
        repair_plan_digest=plan["plan_digest"],
    )
    repair_markdown = (_action(first) + _action(second)).encode("utf-8")
    repair_execution = build_axis_repair_execution_receipt(
        plan,
        state="EXECUTED",
        repair_dispositions_raw=repair_sidecar,
        repair_findings_raw=repair_markdown,
    )
    final = reconcile_axis_dispositions_final(
        worklist,
        initial_receipt=initial,
        repair_plan=plan,
        repair_execution_receipt=repair_execution,
        base_findings_raw=b"",
        repair_dispositions_raw=repair_sidecar,
        repair_findings_raw=repair_markdown,
        execution_evidence_authority=_zero_evidence(),
        canonical_prior_ids={},
        canonical_prior_authority_digest="c" * 64,
    )
    by_id = {row["work_item_id"]: row for row in final["dispositions"]}
    assert by_id[first["work_item_id"]]["disposition"] == "CLEAR"
    assert by_id[first["work_item_id"]]["source"] == "BASE"
    assert by_id[second["work_item_id"]]["source"] == "REPAIR"
    assert any("outside" in issue.lower() for issue in final["issues"])


def test_repair_clear_cannot_reuse_base_clear_ci_identity(
    tmp_path: Path,
) -> None:
    project, _scratchpad = _seed(tmp_path)
    worklist = _worklist(
        project,
        _matrix(
            [
                _gap("A.settle(uint256)", "contracts/A.sol", "boundary"),
                _gap("A.settle(uint256)", "contracts/A.sol", "identity"),
            ]
        ),
    )
    first, second = worklist["items"]
    base = _sidecar(
        worklist,
        [
            {
                "work_item_id": first["work_item_id"],
                "disposition": "CLEAR",
                "action_id": "",
                "evidence": [_source_clear(first)],
                "rationale": "the exact source guard closes this axis",
            }
        ],
    )
    initial, plan = _initial(worklist, base, "")
    reused_id = initial["dispositions"][0]["invariant_commitment"]["ci_id"]
    evidence = [_source_clear(second)]
    repair_sidecar = _sidecar(
        worklist,
        [
            {
                "work_item_id": second["work_item_id"],
                "disposition": "CLEAR",
                "action_id": "",
                "evidence": evidence,
                "invariant_commitment": _axis_ci(
                    second,
                    evidence,
                    ci_id=reused_id,
                ),
                "rationale": "the exact source guard closes this axis",
            }
        ],
        repair_plan_digest=plan["plan_digest"],
    )
    repair_findings = b"<!-- PLAMEN_STATUS: COMPLETE -->\n"
    final = reconcile_axis_dispositions_final(
        worklist,
        initial_receipt=initial,
        repair_plan=plan,
        repair_execution_receipt=build_axis_repair_execution_receipt(
            plan,
            state="EXECUTED",
            repair_dispositions_raw=repair_sidecar,
            repair_findings_raw=repair_findings,
        ),
        base_findings_raw=b"",
        repair_dispositions_raw=repair_sidecar,
        repair_findings_raw=repair_findings,
        execution_evidence_authority=_zero_evidence(),
        canonical_prior_ids={},
        canonical_prior_authority_digest="c" * 64,
    )

    assert final["status"] == "COMPLETED_WITH_DEBT"
    assert set(final["residual_work_item_ids"]) == {
        first["work_item_id"], second["work_item_id"]
    }
    assert all(
        row["application_record_complete"] is False
        and "reused across base/repair rows" in row["reason"]
        for row in final["dispositions"]
    )


def test_exact_repair_closes_initial_row_debt_without_erasing_audit_trail(
    tmp_path: Path,
) -> None:
    project, _scratchpad = _seed(tmp_path)
    worklist = _worklist(
        project,
        _matrix([_gap("A.settle(uint256)", "contracts/A.sol", "boundary")]),
    )
    item = worklist["items"][0]
    initial, plan = _initial(worklist, _sidecar(worklist, []), "")
    repair_sidecar = _sidecar(
        worklist,
        [
            {
                "work_item_id": item["work_item_id"],
                "disposition": "UNRESOLVED",
                "action_id": item["required_action_id"],
                "evidence": [],
                "rationale": "candidate requires independent verification",
            }
        ],
        repair_plan_digest=plan["plan_digest"],
    )
    repair_findings = _action(item).encode("utf-8")
    final = reconcile_axis_dispositions_final(
        worklist,
        initial_receipt=initial,
        repair_plan=plan,
        repair_execution_receipt=build_axis_repair_execution_receipt(
            plan,
            state="EXECUTED",
            repair_dispositions_raw=repair_sidecar,
            repair_findings_raw=repair_findings,
        ),
        base_findings_raw=b"",
        repair_dispositions_raw=repair_sidecar,
        repair_findings_raw=repair_findings,
        execution_evidence_authority=_zero_evidence(),
        canonical_prior_ids={},
        canonical_prior_authority_digest="c" * 64,
    )

    assert final["status"] == "COMPLETE"
    assert final["residual_work_item_ids"] == []
    assert final["assurance_debt"]["count"] == 0


@pytest.mark.parametrize(
    ("state", "has_work"),
    [
        ("NOT_REQUIRED", False),
        ("EXECUTED", True),
        ("FAILED", True),
        ("OVERFLOW", True),
    ],
)
def test_repair_execution_receipt_has_unconditional_terminal_state(
    tmp_path: Path,
    state: str,
    has_work: bool,
) -> None:
    project, _scratchpad = _seed(tmp_path)
    gaps = (
        [_gap("A.settle(uint256)", "contracts/A.sol", "boundary")]
        if has_work
        else []
    )
    worklist = _worklist(project, _matrix(gaps))
    sidecar = _sidecar(worklist, [])
    initial, plan = reconcile_axis_dispositions_initial(
        worklist,
        base_dispositions_raw=sidecar,
        base_findings_raw=b"",
        execution_evidence_authority=_zero_evidence(),
        canonical_prior_ids={},
        canonical_prior_authority_digest="c" * 64,
        repair_cap=(0 if state == "OVERFLOW" else 16),
    )
    kwargs = {}
    if state == "EXECUTED":
        item = worklist["items"][0]
        repair_sidecar = _sidecar(
            worklist,
            [
                {
                    "work_item_id": item["work_item_id"],
                    "disposition": "UNRESOLVED",
                    "action_id": item["required_action_id"],
                    "evidence": [],
                    "rationale": "verify",
                }
            ],
            repair_plan_digest=plan["plan_digest"],
        )
        kwargs = {
            "repair_dispositions_raw": repair_sidecar,
            "repair_findings_raw": _action(item).encode("utf-8"),
        }
    if state == "FAILED":
        kwargs["issues"] = ("worker timeout",)
    receipt = build_axis_repair_execution_receipt(
        plan,
        state=state,
        **kwargs,
    )
    assert receipt["schema_version"] == (
        "plamen.axis_repair_execution_receipt.v1"
    )
    assert receipt["state"] == state
    assert receipt["execution_digest"]


def test_final_application_receipt_has_no_inventory_or_promotion_binding(
    tmp_path: Path,
) -> None:
    project, _scratchpad = _seed(tmp_path)
    worklist = _worklist(project, _matrix([]))
    initial, plan = _initial(worklist, _sidecar(worklist, []), "")
    repair = build_axis_repair_execution_receipt(
        plan, state="NOT_REQUIRED"
    )
    final = reconcile_axis_dispositions_final(
        worklist,
        initial_receipt=initial,
        repair_plan=plan,
        repair_execution_receipt=repair,
        base_findings_raw=b"",
        execution_evidence_authority=_zero_evidence(),
        canonical_prior_ids={},
        canonical_prior_authority_digest="c" * 64,
    )
    assert final["schema_version"] == APPLICATION_RECEIPT_V2_SCHEMA
    forbidden = {
        key
        for key in final
        if "inventory" in key.lower() or "promotion" in key.lower()
    }
    assert forbidden == set()


def test_v2_writer_emits_deterministic_projection_only(
    tmp_path: Path,
) -> None:
    project, scratchpad = _seed(tmp_path)
    worklist = _worklist(project, _matrix([]))
    initial, plan = _initial(worklist, _sidecar(worklist, []), "")
    final = reconcile_axis_dispositions_final(
        worklist,
        initial_receipt=initial,
        repair_plan=plan,
        repair_execution_receipt=build_axis_repair_execution_receipt(
            plan, state="NOT_REQUIRED"
        ),
        base_findings_raw=b"",
        execution_evidence_authority=_zero_evidence(),
        canonical_prior_ids={},
        canonical_prior_authority_digest="c" * 64,
    )
    paths = write_axis_disposition_v2_artifacts(
        scratchpad,
        worklist=worklist,
        application_receipt=final,
    )
    projection_path = scratchpad / LIMITATIONS_NAME
    projection = projection_path.read_text(encoding="utf-8")

    assert projection_path in paths
    assert "plamen.axis_assurance_limitations.v2" in projection
    assert final["assurance_debt"]["assurance_digest"] in projection
    assert validate_axis_assurance_projection_v2(
        projection, final
    ) == projection
    with pytest.raises(AxisDispositionError, match="projection drift"):
        validate_axis_assurance_projection_v2(
            projection + "model-authored claim\n", final
        )


def test_promotion_authority_delivers_only_referenced_actions_and_survives_append(
    tmp_path: Path,
) -> None:
    project, _scratchpad = _seed(tmp_path)
    worklist = _worklist(
        project,
        _matrix([_gap("A.settle(uint256)", "contracts/A.sol", "boundary")]),
    )
    item = worklist["items"][0]
    markdown = _action(item).encode("utf-8")
    sidecar = _sidecar(
        worklist,
        [
            {
                "work_item_id": item["work_item_id"],
                "disposition": "FINDING",
                "action_id": item["required_action_id"],
                "evidence": [],
                "rationale": "candidate",
            }
        ],
    )
    initial, plan = _initial(worklist, sidecar, markdown.decode())
    repair = build_axis_repair_execution_receipt(
        plan, state="NOT_REQUIRED"
    )
    final = reconcile_axis_dispositions_final(
        worklist,
        initial_receipt=initial,
        repair_plan=plan,
        repair_execution_receipt=repair,
        base_findings_raw=markdown,
        execution_evidence_authority=_zero_evidence(),
        canonical_prior_ids={},
        canonical_prior_authority_digest="c" * 64,
    )
    inventory = (
        "### Finding [INV-001]: delivered axis action\n"
        "**Severity**: Low\n"
        "**Location**: contracts/A.sol:L2\n"
        f"**Source IDs**: AXISGAP:{item['required_action_id']}\n"
        "**Description**: exact typed candidate\n"
        "**Impact**: verifier determines material harm\n"
    )
    promotion = build_axis_promotion_authority(
        final,
        run_id=worklist["run_id"],
        base_findings_raw=markdown,
        repair_findings_raw=b"",
        inventory_text=inventory,
    )
    assert promotion["schema_version"] == (
        "plamen.axis_coverage_promotion_receipt.v2"
    )
    assert promotion["status"] == "COMPLETE"
    assert promotion["delivery_count"] == 1
    assert validate_axis_promotion_authority(
        promotion,
        final,
        base_findings_raw=markdown,
        repair_findings_raw=b"",
        inventory_text=inventory + "\n### Finding [INV-999]: unrelated\n",
    ) == promotion


def test_referenced_action_blocks_filter_orphans_and_reject_drift(
    tmp_path: Path,
) -> None:
    project, _scratchpad = _seed(tmp_path)
    worklist = _worklist(
        project,
        _matrix([_gap("A.settle(uint256)", "contracts/A.sol", "boundary")]),
    )
    item = worklist["items"][0]
    markdown = _action(item).encode("utf-8")
    sidecar = _sidecar(
        worklist,
        [
            {
                "work_item_id": item["work_item_id"],
                "disposition": "FINDING",
                "action_id": item["required_action_id"],
                "evidence": [],
                "rationale": "candidate requires verification",
            }
        ],
    )
    initial, plan = _initial(worklist, sidecar, markdown.decode())
    application = reconcile_axis_dispositions_final(
        worklist,
        initial_receipt=initial,
        repair_plan=plan,
        repair_execution_receipt=build_axis_repair_execution_receipt(
            plan, state="NOT_REQUIRED"
        ),
        base_findings_raw=markdown,
        execution_evidence_authority=_zero_evidence(),
        canonical_prior_ids={},
        canonical_prior_authority_digest="c" * 64,
    )
    orphan = (
        "### Finding [AXIS-V2-999]: unrelated orphan\n"
        "**Work Item ID**: AXW-FFFFFFFFFFFFFFFFFFFFFFFF\n"
        "**Severity**: Low\n"
        "**Location**: contracts/B.sol:L2\n"
        "**Description**: unrelated\n"
        "**Impact**: unrelated\n"
    ).encode("utf-8")

    blocks = referenced_axis_action_blocks(
        application,
        base_findings_raw=markdown + orphan,
        repair_findings_raw=b"",
    )
    assert len(blocks) == 1
    assert blocks[0]["action_id"] == item["required_action_id"]
    assert "unrelated orphan" not in blocks[0]["block_utf8"]

    with pytest.raises(AxisDispositionError, match="differs"):
        referenced_axis_action_blocks(
            application,
            base_findings_raw=markdown.replace(b"candidate", b"changed"),
            repair_findings_raw=b"",
        )


def test_v2_authority_replay_detects_source_drift(tmp_path: Path) -> None:
    project, _scratchpad = _seed(tmp_path)
    worklist = _worklist(
        project,
        _matrix([_gap("A.settle(uint256)", "contracts/A.sol", "boundary")]),
    )
    item = worklist["items"][0]
    sidecar = _sidecar(
        worklist,
        [
            {
                "work_item_id": item["work_item_id"],
                "disposition": "CLEAR",
                "action_id": "",
                "evidence": [_source_clear(item)],
                "rationale": "exact source guard at the bound locus",
            }
        ],
    )
    initial, plan = _initial(worklist, sidecar, "")
    repair = build_axis_repair_execution_receipt(
        plan, state="NOT_REQUIRED"
    )
    final = reconcile_axis_dispositions_final(
        worklist,
        initial_receipt=initial,
        repair_plan=plan,
        repair_execution_receipt=repair,
        base_findings_raw=b"",
        execution_evidence_authority=_zero_evidence(),
        canonical_prior_ids={},
        canonical_prior_authority_digest="c" * 64,
    )
    assert validate_axis_disposition_authority_v2(
        final,
        worklist,
        production_root=project,
        execution_evidence_authority=_zero_evidence(),
        canonical_prior_ids={},
        canonical_prior_authority_digest="c" * 64,
    ) == final
    (project / "contracts" / "A.sol").write_text(
        "contract A { function settle(uint256) external {} }\n",
        encoding="utf-8",
    )
    with pytest.raises(AxisDispositionError, match="source"):
        validate_axis_disposition_authority_v2(
            final,
            worklist,
            production_root=project,
            execution_evidence_authority=_zero_evidence(),
            canonical_prior_ids={},
            canonical_prior_authority_digest="c" * 64,
        )


def test_canonical_v2_filenames_are_stable() -> None:
    assert AXIS_EXECUTION_EVIDENCE_AUTHORITY_NAME == (
        "axis_execution_evidence_authority.json"
    )
    assert AXIS_MODEL_DISPOSITIONS_NAME == "axis_coverage_dispositions.json"
    assert AXIS_REPAIR_PLAN_NAME == "axis_repair_plan.json"
    assert AXIS_REPAIR_MODEL_DISPOSITIONS_NAME == (
        "axis_coverage_repair_dispositions.json"
    )
    assert AXIS_REPAIR_EXECUTION_RECEIPT_NAME == (
        "axis_repair_execution_receipt.json"
    )
    assert AXIS_PROMOTION_RECEIPT_NAME == (
        "axis_coverage_promotion_receipt.json"
    )


def test_legacy_markdown_table_is_not_v2_authority(
    tmp_path: Path,
) -> None:
    project, _scratchpad = _seed(tmp_path)
    worklist = _worklist(
        project,
        _matrix([_gap("A.settle(uint256)", "contracts/A.sol", "boundary")]),
    )
    legacy = (
        "| Function | Axis | Disposition | Evidence |\n"
        "|---|---|---|---|\n"
        "| settle | boundary | CLEAR | contracts/A.sol:L2 |\n"
    ).encode("utf-8")
    with pytest.raises(AxisDispositionError):
        parse_axis_model_dispositions(
            legacy,
            worklist=worklist,
            expected_run_id=worklist["run_id"],
        )
