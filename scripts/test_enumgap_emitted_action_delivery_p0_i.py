from __future__ import annotations

import json
from pathlib import Path

import enumeration_gate as EG
import plamen_driver as D
import plamen_validators as V
from exploration_clear_lifecycle import compile_initial_receipt, write_lifecycle_artifacts
from plamen_types import Phase


def _phase() -> Phase:
    return Phase(
        "enumgap_exploration",
        ["Phase 4b.7"],
        ["enumgap_exploration_findings.md"],
        base_timeout_s=120,
        modes={"core", "thorough"},
        critical=False,
        model="sonnet",
    )


def _inventory_phase() -> Phase:
    return Phase(
        "inventory",
        ["Phase 4a"],
        ["findings_inventory.md"],
        base_timeout_s=120,
        modes={"core", "thorough"},
        critical=True,
        model="sonnet",
    )


def _config(project: Path) -> dict[str, object]:
    return {
        "project_root": str(project),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "_run_id": "42345678-1234-4567-8abc-1234567890ab",
    }


def _seed_emitted_action(project: Path) -> tuple[Path, str]:
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    (project / "src").mkdir()
    (project / "src" / "Unit.sol").write_text("one\ntwo\n", encoding="utf-8")
    source = scratch / "exploration_skeptic_findings.md"
    source.write_text(
        "# Exploration\n\n## Coverage Record\n\n"
        "| Finding | Axis | Instance | Disposition | Evidence |\n"
        "|---|---|---|---|---|\n"
        "| BASE-1 | sibling | inverse | NO-GAP | vague wording |\n",
        encoding="utf-8",
    )
    initial = compile_initial_receipt(
        source, production_root=project, canonical_prior_ids={}
    )
    write_lifecycle_artifacts(scratch, initial)
    obligation_id = initial.obligations[0].obligation_id
    assert D._bind_typed_model_phase_inputs(
        _inventory_phase(), scratch, _config(project)
    ) == []
    (scratch / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Seed\n"
        "**Source IDs**: [BASE-0]\n"
        "**Severity**: Low\n"
        "**Location**: src/Unit.sol:L1\n"
        "**Description**: retained seed.\n",
        encoding="utf-8",
    )
    assert D._record_typed_model_phase_artifacts(
        _inventory_phase(), scratch, _config(project)
    ) == []
    worklist, issues = D._prepare_enumgap_disposition_worklist(
        _phase(), _config(project), scratch
    )
    assert issues == [] and worklist["count"] == 1
    assert D._bind_typed_model_phase_inputs(
        _phase(), scratch, _config(project)
    ) == []
    (scratch / "enumgap_exploration_findings.md").write_text(
        "# Enumgap\n\n"
        "## Finding [NEXP-1]: traced candidate\n\n"
        "**Severity**: Low\n\n"
        "**Location**: src/Unit.sol:L1\n\n"
        "**Description**: A concrete traced candidate remains for verification.\n\n"
        "## Coverage Record\n\n"
        "| Obligation | Relationship | Disposition | Evidence |\n"
        "|---|---|---|---|\n"
        f"| {obligation_id} | sibling / inverse | FINDING | NEXP-1 |\n",
        encoding="utf-8",
    )
    assert D._record_typed_model_phase_artifacts(
        _phase(), scratch, _config(project)
    ) == []
    receipt, reconcile_issues = D._reconcile_enumgap_dispositions(
        _phase(), _config(project), scratch
    )
    assert reconcile_issues == [] and receipt["status"] == "CLEAN"
    return scratch, obligation_id


def _delivery_row(scratch: Path, obligation_id: str) -> dict[str, object]:
    V._promote_depth_findings_to_inventory(scratch)
    payload = json.loads(
        (scratch / "finding_delivery_receipt.json").read_text(encoding="utf-8")
    )
    return next(
        row for row in payload["actions"] if row["action_id"] == obligation_id
    )


def test_parsed_action_cannot_dispose_eclr_before_exact_promotion_delivery(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, obligation_id = _seed_emitted_action(project)

    before = _delivery_row(scratch, obligation_id)
    assert before["disposition"] == "INDEPENDENT_ENUMERATION_REQUIRED"

    assert EG.promote_enumgap_exploration_to_inventory(scratch) == {
        "parsed": 1,
        "emitted": 1,
    }
    after = _delivery_row(scratch, obligation_id)
    assert after["disposition"] == "INDEPENDENT_ENUMERATION_DISPOSED"
    assert after["resolved_reference"] == "NEXP-1"
    assert after["promotion_delivery_id"] == "INV-002"
    assert after["proof_scope"] == "NONE"
    assert after["content_bearing"] is False


def test_inventory_delivery_drift_revokes_emitted_action_disposal(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, obligation_id = _seed_emitted_action(project)
    assert EG.promote_enumgap_exploration_to_inventory(scratch)["emitted"] == 1
    inventory = scratch / "findings_inventory.md"
    inventory.write_text(
        inventory.read_text(encoding="utf-8").replace(
            "**Source IDs**: NEXP-1", "**Source IDs**: NEXP-9"
        ),
        encoding="utf-8",
    )

    row = _delivery_row(scratch, obligation_id)
    assert row["disposition"] == "INDEPENDENT_ENUMERATION_REQUIRED"
    assert "promotion_delivery_id" not in row


def test_inventory_provenance_without_bound_promotion_receipt_remains_debt(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch, obligation_id = _seed_emitted_action(project)
    assert EG.promote_enumgap_exploration_to_inventory(scratch)["emitted"] == 1
    (scratch / "enumgap_exploration_promotion_receipt.json").unlink()

    row = _delivery_row(scratch, obligation_id)
    assert row["disposition"] == "INDEPENDENT_ENUMERATION_REQUIRED"
    assert "promotion_delivery_id" not in row


def test_shared_exact_parser_is_the_live_promoter_parser(tmp_path: Path) -> None:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    malformed = (
        "## Finding [NEXP-1]\n\n"
        "**Severity**: Low\n"
        "**Location**: src/Unit.sol:L1\n"
        "**Description**: Parsed prose is not a promotable finding heading.\n"
    )
    (scratch / "enumgap_exploration_findings.md").write_text(
        malformed, encoding="utf-8"
    )
    (scratch / "findings_inventory.md").write_text("# Inventory\n", encoding="utf-8")

    assert EG.parse_enumgap_exploration_findings(malformed) == ()
    assert EG.promote_enumgap_exploration_to_inventory(scratch) == {
        "parsed": 0,
        "emitted": 0,
    }
    assert not (scratch / "enumgap_exploration_promotion_receipt.json").exists()
