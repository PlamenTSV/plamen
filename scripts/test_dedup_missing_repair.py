from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_driver as D  # noqa: E402
from plamen_validators import (  # noqa: E402
    _check_dedup_decision_coverage,
    _dedup_decision_coverage_detail,
    _generate_dedup_decision_retry_hint,
    _repair_dedup_missing_dispositions,
)


def _write_pairs(sp: Path) -> None:
    (sp / "dedup_candidate_pairs.md").write_text(
        "| Pair | Finding A | Finding B |\n"
        "|---|---|---|\n"
        "| 1 | H-1 | H-2 |\n"
        "| 2 | H-3 | H-4 |\n"
        "| 3 | H-5 | H-6 |\n",
        encoding="utf-8",
    )


def test_dedup_detail_lists_only_unaccounted_candidate_rows(tmp_path: Path):
    _write_pairs(tmp_path)
    (tmp_path / "dedup_decisions.md").write_text(
        "| Pair | Decision |\n"
        "|---|---|\n"
        "| 1 | KEEP SEPARATE |\n",
        encoding="utf-8",
    )

    detail = _dedup_decision_coverage_detail(tmp_path)

    assert detail["pair_count"] == 3
    assert detail["accounted"] == 1
    assert detail["missing_count"] == 2
    assert "H-3" in detail["missing_rows"][0]
    assert "H-5" in detail["missing_rows"][1]
    assert _check_dedup_decision_coverage(tmp_path)


def test_dedup_retry_hint_preserves_existing_rows(tmp_path: Path):
    _write_pairs(tmp_path)
    (tmp_path / "dedup_decisions.md").write_text(
        "| Pair | Decision |\n"
        "|---|---|\n"
        "| 1 | MERGE |\n",
        encoding="utf-8",
    )

    hint = _generate_dedup_decision_retry_hint(tmp_path, "sc_semantic_dedup")

    assert "Repair only the missing dispositions" in hint
    assert "H-3" in hint
    assert "H-5" in hint
    assert "MERGE/GROUP/KEEP SEPARATE" in hint


def test_dedup_mechanical_repair_adds_passthrough_rows(tmp_path: Path):
    _write_pairs(tmp_path)
    (tmp_path / "dedup_decisions.md").write_text(
        "| Pair | Decision |\n|---|---|\n| 1 | KEEP SEPARATE |\n",
        encoding="utf-8",
    )

    model_bytes = (tmp_path / "dedup_decisions.md").read_bytes()
    repaired = _repair_dedup_missing_dispositions(tmp_path, "sc_semantic_dedup")

    assert repaired == 2
    assert _check_dedup_decision_coverage(tmp_path) == []
    assert (tmp_path / "dedup_decisions.md").read_bytes() == model_bytes
    repair = __import__("json").loads(
        (tmp_path / "dedup_coverage_repair.json").read_text(encoding="utf-8")
    )
    assert len(repair["items"]) == 2
    assert {item["disposition"] for item in repair["items"]} == {"PASSTHROUGH"}


def test_fresh_dedup_coverage_gap_is_repaired_without_blocking(
    tmp_path: Path, monkeypatch,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "_audit_started_with_markers.json").write_text("{}", encoding="utf-8")
    _write_pairs(sp)
    (sp / "dedup_decisions.md").write_text(
        "| Pair | Decision |\n|---|---|\n| 1 | KEEP SEPARATE |\n",
        encoding="utf-8",
    )
    model_bytes = (sp / "dedup_decisions.md").read_bytes()
    (sp / "findings_inventory_deduped.md").write_text("x" * 200, encoding="utf-8")
    phase = D.Phase(
        name="sc_semantic_dedup",
        section_markers=[],
        expected_artifacts=["dedup_decisions.md", "findings_inventory_deduped.md"],
        base_timeout_s=1,
        min_artifact_bytes=10,
    )
    # This fixture targets the coverage projection only; PhaseIO transaction
    # mechanics have dedicated integration suites with fully bound ledgers.
    monkeypatch.setattr(D, "_record_typed_model_phase_artifacts", lambda *_a, **_k: [])
    monkeypatch.setattr(
        D,
        "_run_l1_prequeue_semantic_dedup_transaction",
        lambda **_k: {"safe_to_consume": True},
    )

    passed, missing = D._run_phase_validators(
        phase,
        {
            "mode": "core", "pipeline": "sc", "language": "evm",
            "cli_backend": "codex", "project_root": str(tmp_path),
            "scratchpad": str(sp), "_run_id": "dedup-repair-test",
        },
        sp,
        [],
        0,
        {},
    )

    assert passed is True, missing
    assert missing == []
    assert (sp / "dedup_decisions.md").read_bytes() == model_bytes
    decisions = (sp / "dedup_decisions.md").read_text(encoding="utf-8")
    assert "Mechanical Missing Disposition Repair" not in decisions
    repair = __import__("json").loads(
        (sp / "dedup_coverage_repair.json").read_text(encoding="utf-8")
    )
    assert {item["disposition"] for item in repair["items"]} == {"PASSTHROUGH"}
    contract, _launch = D._sc_dedup_coverage_repair_contract_and_launch({
        "mode": "core", "pipeline": "sc", "language": "evm",
        "cli_backend": "codex",
    })
    unit = D.read_artifact_ledger(sp)["work_units"][contract.key]
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert set(unit["input_bindings"]) == {
        "scratchpad:dedup_candidate_pairs.md",
        "scratchpad:dedup_decisions.md",
    }
    artifact = unit["artifacts"][
        "scratchpad:dedup_coverage_repair.json"
    ]
    assert artifact["writer"] == "DRIVER"
