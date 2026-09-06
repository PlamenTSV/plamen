"""P0-I exact hot-function-axis input-to-disposition authority."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import enumeration_gate as EG
from axis_disposition import (
    ASSURANCE_DEBT_NAME,
    LIMITATIONS_NAME,
    RECEIPT_NAME,
    REPAIR_NAME,
    WORKLIST_NAME,
    AxisDispositionError,
    compile_axis_worklist,
    reconcile_axis_output,
    validate_axis_disposition_authority,
    write_axis_disposition_artifacts,
    write_axis_worklist,
)


AXES = ("theft", "liveness", "accounting", "provenance", "boundary", "identity")


def _seed_project(tmp_path: Path, *, non_evm: bool = False) -> tuple[Path, Path]:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    if non_evm:
        source = project / "sources" / "ledger.move"
        source.parent.mkdir(parents=True)
        source.write_text(
            "module 0x1::ledger {\n"
            "  public entry fun settle<T>(account: &signer) {\n"
            "    let marker = 1;\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )
    else:
        source = project / "contracts" / "Unit.sol"
        source.parent.mkdir(parents=True)
        source.write_text(
            "contract Unit {\n"
            "  function settle(address recipient, uint256 amount) external {\n"
            "    require(recipient != address(0));\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )
    return project, scratchpad


def _gap(
    function: str,
    loc: str,
    axis: str,
    *,
    lang: str,
) -> dict:
    return {"function": function, "loc": loc, "axis": axis, "lang": lang}


def _write_matrix(scratchpad: Path, gaps: list[dict]) -> None:
    grouped: dict[tuple[str, str, str], dict[str, str]] = {}
    for gap in gaps:
        key = (gap["function"], gap["loc"], gap["lang"])
        grouped.setdefault(key, {axis: "EXAMINED" for axis in AXES})[
            gap["axis"]
        ] = "GAP"
    hot = [
        {
            "function": function,
            "loc": loc,
            "callers": 2,
            "writes": True,
            "elevate": False,
            "value_effect": True,
            "lang": lang,
            "score": 5.0,
        }
        for function, loc, lang in grouped
    ]
    matrix = [
        {"function": function, "loc": loc, "score": 5.0, "cells": cells}
        for (function, loc, _lang), cells in grouped.items()
    ]
    (scratchpad / "_hot_function_axes.json").write_text(
        json.dumps({"hot": hot, "matrix": matrix, "gaps": gaps}, indent=2),
        encoding="utf-8",
    )


def _action(action_id: str, *, loc: str = "contracts/Unit.sol:L2") -> str:
    return (
        f"### Finding [{action_id}]: independently retained axis candidate\n"
        "**Severity**: Low\n"
        f"**Location**: {loc}\n"
        "**Description**: [TRACE:entry->terminal state] exact candidate work\n"
        "**Impact**: verifier must determine whether protected state is harmed\n\n"
    )


def _coverage(rows: list[tuple[str, str, str, str]], *, actions: str = "") -> str:
    body = [
        "# Axis Coverage",
        "",
        actions.rstrip(),
        "",
        "## Coverage Record",
        "",
        "| Function | Axis | Disposition | Evidence |",
        "|---|---|---|---|",
    ]
    body.extend(f"| {fn} | {axis} | {disp} | {evidence} |" for fn, axis, disp, evidence in rows)
    return "\n".join(body) + "\n"


def _compile(scratchpad: Path) -> dict:
    worklist = compile_axis_worklist(scratchpad)
    write_axis_worklist(scratchpad, worklist)
    return worklist


def _reconcile(
    scratchpad: Path,
    project: Path,
    worklist: dict,
    output: str,
    *,
    prior: dict[str, str] | None = None,
    repair_cap: int = 20,
) -> dict:
    (scratchpad / "axis_coverage_findings.md").write_text(output, encoding="utf-8")
    receipt = reconcile_axis_output(
        worklist,
        output,
        production_root=project,
        canonical_prior_ids=prior or {},
        executed_evidence_receipts={},
        repair_cap=repair_cap,
        scratchpad=scratchpad,
    )
    write_axis_disposition_artifacts(scratchpad, receipt)
    return receipt


def test_all_evm_inputs_receive_one_exact_current_disposition(tmp_path: Path) -> None:
    project, scratchpad = _seed_project(tmp_path)
    gaps = [
        _gap("settle", "contracts/Unit.sol:L2", "theft", lang="solidity"),
        _gap("settle", "contracts/Unit.sol:L2", "boundary", lang="solidity"),
        _gap("settle", "contracts/Unit.sol:L2", "identity", lang="solidity"),
    ]
    _write_matrix(scratchpad, gaps)
    worklist = _compile(scratchpad)
    by_axis = {row["axis"]: row for row in worklist["items"]}
    output = _coverage(
        [
            ("settle", "theft", "FINDING", "AXIS-1"),
            ("settle", "boundary", "CLEAR", "contracts/Unit.sol:L3 guard"),
            ("settle", "identity", "CLEAR", "INV-007"),
        ],
        actions=_action("AXIS-1"),
    )
    receipt = _reconcile(
        scratchpad,
        project,
        worklist,
        output,
        prior={"INV-007": "INV-007"},
    )

    assert receipt["status"] == "CLEAN"
    assert receipt["denominator_count"] == 3
    assert receipt["denominator_tail"] == worklist["tail"]
    assert receipt["unresolved_work_item_ids"] == []
    assert receipt["repair_work"]["count"] == 0
    assert receipt["assurance_debt"]["count"] == 0
    kinds = {row["axis"]: row["resolution_kind"] for row in receipt["dispositions"]}
    assert kinds == {
        "theft": "EMITTED_ACTION",
        "boundary": "IN_SCOPE_SOURCE_LOCUS",
        "identity": "EXISTING_FINDING_IDENTITY",
    }
    assert by_axis["theft"]["work_item_id"] in {
        row["work_item_id"] for row in receipt["dispositions"]
    }


def test_non_evm_generic_type_shape_identity_is_stable_and_closes(tmp_path: Path) -> None:
    project, scratchpad = _seed_project(tmp_path, non_evm=True)
    gap = _gap(
        "0x1::ledger::settle<T>",
        "sources/ledger.move:L2",
        "identity",
        lang="move",
    )
    _write_matrix(scratchpad, [gap])
    worklist = _compile(scratchpad)
    assert worklist["items"][0]["function"] == "0x1::ledger::settle<T>"
    assert worklist["items"][0]["language"] == "move"

    receipt = _reconcile(
        scratchpad,
        project,
        worklist,
        _coverage(
            [
                (
                    "0x1::ledger::settle<T>",
                    "identity",
                    "CLEAR",
                    "sources/ledger.move:L3 exact signer-bound statement",
                )
            ]
        ),
    )
    assert receipt["status"] == "CLEAN"
    assert receipt["dispositions"][0]["resolution_kind"] == "IN_SCOPE_SOURCE_LOCUS"


def test_one_of_n_missing_becomes_targeted_content_bearing_debt(tmp_path: Path) -> None:
    project, scratchpad = _seed_project(tmp_path)
    gaps = [
        _gap("settle", "contracts/Unit.sol:L2", "boundary", lang="solidity"),
        _gap("settle", "contracts/Unit.sol:L2", "identity", lang="solidity"),
    ]
    _write_matrix(scratchpad, gaps)
    worklist = _compile(scratchpad)
    receipt = _reconcile(
        scratchpad,
        project,
        worklist,
        _coverage(
            [("settle", "boundary", "CLEAR", "contracts/Unit.sol:L3 guard")]
        ),
    )

    assert receipt["status"] == "COMPLETED_WITH_DEBT"
    assert len(receipt["unresolved_work_item_ids"]) == 1
    debt = receipt["assurance_debt"]["items"][0]
    assert debt["axis"] == "identity"
    assert debt["raw_fallback_authority"] == "CANDIDATE_ONLY"
    assert debt["methodology_application_proven"] is False
    assert "require(recipient" in debt["source_excerpt_utf8"]
    assert debt["source_excerpt_sha256"] == hashlib.sha256(
        debt["source_excerpt_utf8"].encode("utf-8")
    ).hexdigest()
    assert receipt["repair_work"]["items"][0]["work_item_id"] == debt["work_item_id"]
    assert debt["work_item_id"] in (scratchpad / LIMITATIONS_NAME).read_text(encoding="utf-8")


def test_duplicate_or_conflicting_dispositions_are_invalid(tmp_path: Path) -> None:
    project, scratchpad = _seed_project(tmp_path)
    _write_matrix(
        scratchpad,
        [_gap("settle", "contracts/Unit.sol:L2", "boundary", lang="solidity")],
    )
    worklist = _compile(scratchpad)
    receipt = _reconcile(
        scratchpad,
        project,
        worklist,
        _coverage(
            [
                ("settle", "boundary", "CLEAR", "contracts/Unit.sol:L3 guard"),
                ("settle", "boundary", "FINDING", "AXIS-2"),
            ],
            actions=_action("AXIS-2"),
        ),
    )
    assert receipt["dispositions"][0]["resolution_kind"] == "DUPLICATE_CONFLICT"
    assert receipt["repair_work"]["count"] == 1


@pytest.mark.parametrize(
    "evidence",
    [
        "looks safe after review",
        "contracts/Unit.sol:L3 [EXTERNAL-ASSUMPTION: dependency behaves favorably]",
        "contracts/Unit.sol:L3 assuming the external provider remains correct",
    ],
)
def test_vague_or_favorable_external_clear_cannot_self_close(
    tmp_path: Path,
    evidence: str,
) -> None:
    project, scratchpad = _seed_project(tmp_path)
    _write_matrix(
        scratchpad,
        [_gap("settle", "contracts/Unit.sol:L2", "provenance", lang="solidity")],
    )
    worklist = _compile(scratchpad)
    receipt = _reconcile(
        scratchpad,
        project,
        worklist,
        _coverage([("settle", "provenance", "CLEAR", evidence)]),
    )
    assert receipt["status"] == "COMPLETED_WITH_DEBT"
    assert receipt["dispositions"][0]["resolution_kind"] in {
        "INVALID_CLEAR",
        "UNSUPPORTED_EXTERNAL_CLEAR",
    }


def test_finding_linkage_records_exact_emitted_and_promoted_identity(tmp_path: Path) -> None:
    project, scratchpad = _seed_project(tmp_path)
    _write_matrix(
        scratchpad,
        [_gap("settle", "contracts/Unit.sol:L2", "theft", lang="solidity")],
    )
    worklist = _compile(scratchpad)
    (scratchpad / "findings_inventory.md").write_text(
        "### Finding [INV-009]: promoted axis action\n"
        "**Severity**: Low\n"
        "**Location**: contracts/Unit.sol:L2\n"
        "**Source IDs**: AXISGAP:AXIS-A-1\n",
        encoding="utf-8",
    )
    (scratchpad / "axis_coverage_promotion_receipt.md").write_text(
        "# Receipt\n\nAXIS-A-1 -> INV-009\n", encoding="utf-8"
    )
    receipt = _reconcile(
        scratchpad,
        project,
        worklist,
        _coverage(
            [("settle", "theft", "FINDING", "AXIS-A-1")],
            actions=_action("AXIS-A-1"),
        ),
    )
    row = receipt["dispositions"][0]
    assert row["resolution_kind"] == "PROMOTED_ACTION"
    assert row["emitted_action_id"] == "AXIS-A-1"
    assert row["promoted_finding_id"] == "INV-009"
    assert row["emitted_action_sha256"]


def test_repair_cap_and_tail_preserve_exact_omitted_identities(tmp_path: Path) -> None:
    project, scratchpad = _seed_project(tmp_path)
    gaps = [
        _gap("settle", "contracts/Unit.sol:L2", axis, lang="solidity")
        for axis in ("theft", "liveness", "accounting", "boundary")
    ]
    _write_matrix(scratchpad, gaps)
    worklist = _compile(scratchpad)
    receipt = _reconcile(
        scratchpad,
        project,
        worklist,
        _coverage([]),
        repair_cap=2,
    )
    repair = receipt["repair_work"]
    unresolved = receipt["unresolved_work_item_ids"]
    assert repair["observed_count"] == 4
    assert repair["count"] == 2
    assert repair["omitted_count"] == 2
    assert repair["retained_work_item_ids"] == unresolved[:2]
    assert repair["omitted_work_item_ids"] == unresolved[2:]
    assert repair["denominator_tail"] == unresolved[-1]
    assert repair["retained_tail"] == unresolved[1]
    assert receipt["assurance_debt"]["count"] == 4


def test_hotset_cap_full_denominator_becomes_axis_work_not_sampled_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project, scratchpad = _seed_project(tmp_path)
    graph = {
        "functions": {
            f"C.f{index}": {
                "bare": f"f{index}",
                "loc": f"contracts/Unit.sol:L{index + 1}",
                "callers": ["a", "b"],
            }
            for index in range(4)
        },
        "var_refs": {},
    }
    monkeypatch.setattr(EG, "_load_graph", lambda _scratchpad: graph)
    monkeypatch.setattr(EG, "_locate_project_root", lambda _scratchpad: None)
    monkeypatch.setattr(EG, "_MAX_HOT_FUNCTIONS", 2)
    (scratchpad / "findings_inventory.md").write_text("# Inventory\n", encoding="utf-8")

    assert len(EG.compute_axis_coverage_gaps(scratchpad)) == 8
    worklist = compile_axis_worklist(scratchpad)

    # Two retained and two cap-omitted pure functions each carry the four
    # applicable axes. Theft/identity remain the same mechanically-proven N/A
    # used by the matrix producer.
    assert worklist["count"] == 16
    cap_items = [item for item in worklist["items"] if item["cap_omission_present"]]
    assert len(cap_items) == 8
    assert {item["function"] for item in cap_items} == {"f2", "f3"}
    assert {item["axis"] for item in cap_items} == {
        "liveness",
        "accounting",
        "provenance",
        "boundary",
    }
    assert worklist["input_debt"] == []
    assert all(item["raw_fallback_authority"] == "CANDIDATE_ONLY" for item in cap_items)


def test_source_drift_and_receipt_tamper_invalidate_replay(tmp_path: Path) -> None:
    project, scratchpad = _seed_project(tmp_path)
    _write_matrix(
        scratchpad,
        [_gap("settle", "contracts/Unit.sol:L2", "boundary", lang="solidity")],
    )
    worklist = _compile(scratchpad)
    output = _coverage(
        [("settle", "boundary", "CLEAR", "contracts/Unit.sol:L3 guard")]
    )
    _reconcile(scratchpad, project, worklist, output)
    assert validate_axis_disposition_authority(
        scratchpad,
        production_root=project,
        canonical_prior_ids={},
        executed_evidence_receipts={},
        repair_cap=20,
    )["status"] == "CLEAN"

    matrix_path = scratchpad / "_hot_function_axes.json"
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    matrix["gaps"][0]["lang"] = "changed"
    matrix_path.write_text(json.dumps(matrix), encoding="utf-8")
    with pytest.raises(AxisDispositionError, match="worklist"):
        validate_axis_disposition_authority(
            scratchpad,
            production_root=project,
            canonical_prior_ids={},
            executed_evidence_receipts={},
            repair_cap=20,
        )

    _write_matrix(
        scratchpad,
        [_gap("settle", "contracts/Unit.sol:L2", "boundary", lang="solidity")],
    )
    receipt_path = scratchpad / RECEIPT_NAME
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["status"] = "EMPTY"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    with pytest.raises(AxisDispositionError, match="digest"):
        validate_axis_disposition_authority(
            scratchpad,
            production_root=project,
            canonical_prior_ids={},
            executed_evidence_receipts={},
            repair_cap=20,
        )


def test_identical_resume_is_byte_idempotent(tmp_path: Path) -> None:
    project, scratchpad = _seed_project(tmp_path)
    _write_matrix(
        scratchpad,
        [_gap("settle", "contracts/Unit.sol:L2", "boundary", lang="solidity")],
    )
    worklist = _compile(scratchpad)
    output = _coverage(
        [("settle", "boundary", "CLEAR", "contracts/Unit.sol:L3 guard")]
    )
    receipt = _reconcile(scratchpad, project, worklist, output)
    names = (WORKLIST_NAME, RECEIPT_NAME, REPAIR_NAME, ASSURANCE_DEBT_NAME, LIMITATIONS_NAME)
    before = {name: (scratchpad / name).read_bytes() for name in names}

    assert write_axis_worklist(scratchpad, compile_axis_worklist(scratchpad)).read_bytes() == before[WORKLIST_NAME]
    write_axis_disposition_artifacts(scratchpad, receipt)
    assert before == {name: (scratchpad / name).read_bytes() for name in names}
