from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from enumgap_disposition import (
    EnumgapDispositionError,
    compile_enumgap_worklist,
    load_enumgap_disposition_receipt,
    load_enumgap_worklist,
    reconcile_enumgap_output,
    residual_enumgap_queue,
    write_enumgap_disposition_artifacts,
    write_enumgap_worklist,
)
from exploration_clear_lifecycle import (
    compile_initial_receipt,
    write_lifecycle_artifacts,
)


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _seed_inputs(root: Path, project: Path) -> tuple[str, str]:
    (project / "src").mkdir(parents=True)
    (project / "src" / "Unit.sol").write_text(
        "line one\nline two\nline three\n", encoding="utf-8"
    )
    (root / "_enumeration_obligations.json").write_text(
        json.dumps(
            {
                "source": "mechanical-graph",
                "obligations": [
                    {
                        "finding_id": "INV-1",
                        "function": "entry",
                        "symbol": "state",
                        "required_corefs": ["paired"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    exploration = root / "exploration_skeptic_findings.md"
    exploration.write_text(
        "# Exploration\n\n## Coverage Record\n\n"
        "| Finding | Axis | Instance | Disposition | Evidence |\n"
        "|---|---|---|---|---|\n"
        "| INV-2 | sibling | alternate | NO-GAP | vague wording |\n",
        encoding="utf-8",
    )
    receipt = compile_initial_receipt(
        exploration, production_root=project, canonical_prior_ids={}
    )
    write_lifecycle_artifacts(root, receipt)
    assert len(receipt.obligations) == 1
    return "INV-1", receipt.obligations[0].obligation_id


def _output(enum_id: str, clear_id: str, *, clear_evidence: str) -> str:
    return (
        "# Enumeration Exploration\n\n"
        "## Finding [NEXP-1]: traced candidate\n\n"
        "**Severity**: Low\n\n**Location**: src/Unit.sol:L1\n\n"
        "## Coverage Record\n\n"
        "| Obligation | Relationship | Disposition | Evidence |\n"
        "|---|---|---|---|\n"
        f"| {enum_id} | co-reference | FINDING | NEXP-1 |\n"
        f"| {clear_id} | prior invalid clear | CLEAR | {clear_evidence} |\n"
    )


def test_union_worklist_and_exact_dispositions_close(tmp_path: Path) -> None:
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    _, clear_id = _seed_inputs(root, project)
    worklist = compile_enumgap_worklist(root)
    worklist_path = write_enumgap_worklist(root, worklist)
    assert load_enumgap_worklist(worklist_path) == worklist
    assert worklist["count"] == 2
    assert worklist["tail"] == worklist["items"][-1]["work_item_id"]
    assert {item["kind"] for item in worklist["items"]} == {
        "ENUMERATION_COREFERENCE",
        "EXPLORATION_CLEAR",
    }
    enum_id = next(
        item["work_item_id"]
        for item in worklist["items"]
        if item["kind"] == "ENUMERATION_COREFERENCE"
    )
    receipt = reconcile_enumgap_output(
        worklist,
        _output(enum_id, clear_id, clear_evidence="src/Unit.sol:L2"),
        production_root=project,
        canonical_prior_ids={},
    )
    assert receipt["status"] == "CLEAN"
    assert receipt["denominator_count"] == 2
    assert receipt["unresolved_work_item_ids"] == []
    assert {
        row["kind"]: row["resolution_kind"]
        for row in receipt["dispositions"]
    } == {
        "ENUMERATION_COREFERENCE": "EMITTED_ACTION",
        "EXPLORATION_CLEAR": "PRODUCTION_LOCUS",
    }
    assert residual_enumgap_queue(receipt)["count"] == 0


def test_missing_duplicate_vague_clear_and_absent_heading_stay_exact_debt(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    _, clear_id = _seed_inputs(root, project)
    worklist = compile_enumgap_worklist(root)
    enum_id = next(
        item["work_item_id"]
        for item in worklist["items"]
        if item["kind"] == "ENUMERATION_COREFERENCE"
    )
    output = (
        "# Exploration\n\n## Coverage Record\n\n"
        "| Obligation | Relationship | Disposition | Evidence |\n"
        "|---|---|---|---|\n"
        f"| {enum_id} | co-reference | FINDING | NEXP-404 |\n"
        f"| {enum_id} | co-reference | CLEAR | src/Unit.sol:L1 |\n"
        f"| {clear_id} | invalid clear | CLEAR | reviewed and safe |\n"
    )
    receipt = reconcile_enumgap_output(
        worklist,
        output,
        production_root=project,
        canonical_prior_ids={},
    )
    assert receipt["status"] == "COMPLETED_WITH_DEBT"
    assert set(receipt["unresolved_work_item_ids"]) == {enum_id, clear_id}
    assert any("duplicate" in item.lower() for item in receipt["debt"])
    assert any("exact resolvable evidence" in item.lower() for item in receipt["debt"])
    residual = residual_enumgap_queue(receipt)
    assert residual["count"] == 2
    assert residual["tail"] == residual["items"][-1]["work_item_id"]


def test_input_tamper_is_debt_and_receipt_roundtrip_fails_closed(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    _seed_inputs(root, project)
    queue_path = root / "exploration_clear_obligations.json"
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    queue["count"] = 99
    queue_path.write_text(json.dumps(queue), encoding="utf-8")
    worklist = compile_enumgap_worklist(root)
    assert worklist["input_debt"]
    assert worklist["requires_execution"] is True

    receipt = reconcile_enumgap_output(
        worklist,
        "# Empty\n",
        production_root=project,
        canonical_prior_ids={},
    )
    paths = write_enumgap_disposition_artifacts(root, receipt)
    assert len(paths) == 2
    loaded = load_enumgap_disposition_receipt(paths[0])
    assert loaded == receipt
    payload = json.loads(paths[0].read_text(encoding="utf-8"))
    payload["status"] = "CLEAN"
    unsigned = {key: value for key, value in payload.items() if key != "receipt_hash"}
    payload["receipt_hash"] = hashlib.sha256(
        _canonical(unsigned).encode("utf-8")
    ).hexdigest()
    paths[0].write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(EnumgapDispositionError):
        load_enumgap_disposition_receipt(paths[0])


def test_empty_valid_worklists_are_clean_noop(tmp_path: Path) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    (root / "_enumeration_obligations.json").write_text(
        json.dumps({"source": "graph", "obligations": []}), encoding="utf-8"
    )
    worklist = compile_enumgap_worklist(root)
    assert worklist["count"] == 0
    assert worklist["requires_execution"] is False
    receipt = reconcile_enumgap_output(
        worklist,
        "# No work\n",
        production_root=tmp_path,
        canonical_prior_ids={},
    )
    assert receipt["status"] == "EMPTY"
    assert receipt["denominator_count"] == 0
