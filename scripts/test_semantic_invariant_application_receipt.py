from __future__ import annotations

import json
from pathlib import Path

import plamen_driver as D
import plamen_validators as V


REQUIRED_SECTIONS = (
    "Main Table",
    "Mirror Variable Pairs",
    "Time-Weighted Accumulators",
    "Semantic Clusters",
    "Write Completeness vs Semantic Correctness",
    "Read-Site Expectations",
    "Write/Read Meaning Drift",
    "Branch-Conditioned Formula Inputs",
    "Lifecycle Semantics",
    "Refutation Hazards",
)


def _state_variables(sp: Path) -> None:
    (sp / "state_variables.md").write_text(
        "# State Variables\n\n"
        "| File | Variable | Type |\n"
        "|---|---|---|\n"
        "| src/Example.sol | totalAssets | uint256 |\n"
        "| src/Example.sol | checkpointRate | uint256 |\n"
        "| src/Other.sol | pendingByUser[user] | mapping |\n",
        encoding="utf-8",
    )


def _all_sections() -> str:
    return "\n".join(f"### {heading}\n\n| x |\n|---|\n" for heading in REQUIRED_SECTIONS)


def test_invariant_receipt_enumerates_missing_variables_and_sections(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    _state_variables(sp)
    (sp / "semantic_invariants.md").write_text(
        "# Semantic Invariants\n\n"
        "### Main Table\n\n"
        "| Variable | Status |\n|---|---|\n"
        "| totalAssets | WRITE_SITES_COMPLETE |\n"
        "| checkpointRate | NOT_PRECOMPUTED_DEPTH_MUST_INSPECT |\n",
        encoding="utf-8",
    )

    receipt = V._reconcile_semantic_invariant_application(sp)

    assert receipt["status"] == "GAPS"
    assert receipt["expected_variables"] == 3
    assert receipt["represented_variables"] == 2
    assert receipt["missing_variables"] == ["pendingByUser"]
    assert "Mirror Variable Pairs" in receipt["missing_sections"]
    disk = json.loads((sp / "semantic_invariant_application_receipt.json").read_text())
    assert disk["input_sha256"] and disk["output_sha256"]
    gaps = (sp / "semantic_invariant_coverage_gaps.md").read_text()
    assert "pendingByUser" in gaps
    assert "DEPTH_MUST_INSPECT" in gaps


def test_invariant_receipt_accepts_explicitly_deferred_variables(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    _state_variables(sp)
    (sp / "semantic_invariants.md").write_text(
        "# Semantic Invariants\n\n"
        + _all_sections()
        + "\n`totalAssets`: inspected.\n"
        + "`checkpointRate`: NOT_PRECOMPUTED_DEPTH_MUST_INSPECT.\n"
        + "`pendingByUser`: NOT_PRECOMPUTED_DEPTH_MUST_INSPECT.\n",
        encoding="utf-8",
    )

    receipt = V._reconcile_semantic_invariant_application(sp)

    assert receipt["status"] == "COVERED"
    assert receipt["missing_variables"] == []
    assert receipt["missing_sections"] == []
    gaps = (sp / "semantic_invariant_coverage_gaps.md").read_text()
    assert "No deterministic coverage gaps" in gaps


def test_depth_prompt_consumes_invariant_coverage_gap_ledger(
    tmp_path: Path, monkeypatch,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "semantic_invariant_coverage_gaps.md").write_text(
        "# Gaps\n\n| pendingByUser | DEPTH_MUST_INSPECT |\n",
        encoding="utf-8",
    )
    home = Path(D.__file__).resolve().parents[1]
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    job = {
        "agent_id": "depth-state-trace",
        "role": "state_trace",
        "category": "standard",
        "output": "depth_state_trace_findings.md",
        "focus": "state transitions",
    }

    prompt = D._build_depth_worker_prompt(
        job=job,
        scratchpad=sp,
        project_root=str(tmp_path),
        config={"language": "evm", "pipeline": "sc", "mode": "core"},
        attempt=1,
        methodology_descriptors=[],
    )

    assert "semantic_invariant_coverage_gaps.md" in prompt
    assert "DEPTH_MUST_INSPECT" in prompt


def test_unparseable_nonempty_state_inventory_is_not_treated_as_empty_coverage(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "state_variables.md").write_text(
        "# State Variables\n\n- totalAssets in src/Example.sol\n",
        encoding="utf-8",
    )
    (sp / "semantic_invariants.md").write_text(
        "# Semantic Invariants\n\n" + _all_sections(), encoding="utf-8"
    )

    receipt = V._reconcile_semantic_invariant_application(sp)

    assert receipt["status"] == "UNMEASURABLE"
    assert receipt["input_parser_status"] == "UNPARSEABLE_NONEMPTY"
    gaps = (sp / "semantic_invariant_coverage_gaps.md").read_text()
    assert "DEPTH_MUST_INSPECT" in gaps
    assert "state_variables.md" in gaps
