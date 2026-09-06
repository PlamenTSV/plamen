"""NC-2: Gate P is a recovery net, never lexical negative authority."""
from __future__ import annotations

import inspect
from pathlib import Path

import plamen_driver as driver
from plamen_types import L1_PHASES, SC_PHASES
from plamen_mechanical import (
    _write_finding_records_from_inventory,
    compute_promotion_orphans,
    route_promotion_orphans,
)
from plamen_driver import (
    _run_gate_p_before_verify_queue,
    _write_promotion_coverage_seed,
)
from plamen_validators import (
    _auto_map_unmapped_depth_findings,
    _validate_chain_baseline_not_regrouped,
)
from plamen_parsers import (
    _write_mechanical_verification_queue_from_inventory,
    parse_verification_queue_rows,
)


_SEED = (
    "# Report Index Coverage Seed\n\n"
    "| Finding/Hyp ID | Expected Severity | Verdict | Mapped Hypothesis | Dedup Relation |\n"
    "|---|---|---|---|---|\n"
    "| (none) | | | | |\n"
)


def _setup(tmp_path: Path) -> Path:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (scratchpad / "findings_inventory.md").write_text(
        "# Inventory\n\n### Finding [INV-001]: seed\n"
        "**Severity**: Low\n**Location**: `src/Seed.sol:L1`\n",
        encoding="utf-8",
    )
    (scratchpad / "report_index_coverage_seed.md").write_text(
        _SEED, encoding="utf-8"
    )
    return scratchpad


def test_gate_p_safe_prose_is_harvested_as_negative_proposal(tmp_path: Path):
    scratchpad = _setup(tmp_path)
    (scratchpad / "analysis_sweep.md").write_text(
        "# Sweep\n\n"
        "## No finding after boundary review\n"
        "**Location**: `src/Router.sol:L41`\n"
        "The transfer path is safe because it does not miss a validation guard "
        "and therefore permits no unauthorized value movement.\n",
        encoding="utf-8",
    )
    rows = compute_promotion_orphans(scratchpad)
    assert len(rows) == 1
    assert rows[0]["disposition"] == "BODY"
    assert rows[0]["negative_proposal"] is True
    assert rows[0]["negative_proposal_kind"] == "REFUTATION_PROPOSAL"


def test_gate_p_refuted_prose_reopens_without_provider(tmp_path: Path):
    scratchpad = _setup(tmp_path)
    (scratchpad / "depth_state_findings.md").write_text(
        "# State findings\n\n"
        "## Finding [DS-7]: unchecked transition can corrupt accounting\n"
        "**Verdict**: REFUTED\n"
        "**Severity**: High\n"
        "**Location**: `src/State.sol:L88`\n"
        "**Description**: The transition does not validate its boundary and can "
        "corrupt accounting, but the reviewer concluded it was unreachable.\n"
        "**Impact**: State may become inconsistent.\n",
        encoding="utf-8",
    )
    rows = compute_promotion_orphans(scratchpad)
    assert len(rows) == 1
    assert rows[0]["disposition"] == "BODY"
    assert rows[0]["negative_proposal"] is True
    result = route_promotion_orphans(scratchpad, rows)
    assert result["emitted_to_inventory"] == 1
    inventory = (scratchpad / "findings_inventory.md").read_text(encoding="utf-8")
    assert "**Verdict**: NEEDS_VERIFICATION" in inventory
    assert "Negative Proposal" in inventory


def test_gate_p_zero_harm_classifier_is_veto_only(tmp_path: Path):
    scratchpad = _setup(tmp_path)
    (scratchpad / "validation_sweep_findings.md").write_text(
        "# Sweep\n\n"
        "| Location | Note |\n|---|---|\n"
        "| src/Admin.sol:L52 | setter does not emit an event when configuration "
        "changes, leaving monitoring state stale |\n",
        encoding="utf-8",
    )
    rows = compute_promotion_orphans(scratchpad)
    assert len(rows) == 1
    assert rows[0]["disposition"] == "BODY"
    assert rows[0]["zero_harm_proposal"] is True
    assert "authority" in rows[0]["reason"].lower()


def test_preverify_promotion_seed_is_structured_and_additive(tmp_path: Path):
    scratchpad = _setup(tmp_path)
    (scratchpad / "findings_inventory.md").write_text(
        "# Inventory\n\n"
        "### Finding [INV-021]: retained candidate\n"
        "**Severity**: Medium\n"
        "**Location**: `src/Keep.sol:L20`\n"
        "**Source IDs**: DS-4, TF-9\n"
        "Narrative mentions FAKE-999 but is not an identity field.\n",
        encoding="utf-8",
    )
    count = _write_promotion_coverage_seed(scratchpad)
    seed = (scratchpad / "promotion_coverage_seed.md").read_text(encoding="utf-8")
    assert count == 3
    assert "| INV-021 |" in seed
    assert "| DS-4 |" in seed
    assert "| TF-9 |" in seed
    assert "FAKE-999" not in seed


def test_gate_p_recovery_precedes_queue_freeze_and_enters_queue(tmp_path: Path):
    scratchpad = _setup(tmp_path)
    (scratchpad / "depth_state_findings.md").write_text(
        "# State findings\n\n"
        "## Finding [DS-77]: missing boundary validation corrupts accounting\n"
        "**Verdict**: REFUTED\n"
        "**Severity**: High\n"
        "**Location**: `src/State.sol:L188`\n"
        "**Description**: The transition fails to validate its boundary and can "
        "corrupt accounting, but a producer called the path unreachable.\n"
        "**Impact**: State may become inconsistent.\n",
        encoding="utf-8",
    )
    result = _run_gate_p_before_verify_queue(scratchpad)
    assert result["emitted_to_inventory"] == 1
    _write_finding_records_from_inventory(scratchpad)
    _write_mechanical_verification_queue_from_inventory(scratchpad)
    rows = parse_verification_queue_rows(scratchpad)
    recovered = [row for row in rows if "missing boundary validation" in row["title"]]
    assert len(recovered) == 1
    assert recovered[0]["finding id"].startswith("INV-")


def test_driver_wires_gate_p_before_dedup_or_l1_queue_and_not_report_mutation():
    source = Path(__file__).with_name("plamen_driver.py").read_text(encoding="utf-8")
    l1_prepare = inspect.getsource(
        driver._prepare_l1_semantic_dedup_inventory
    )
    assert l1_prepare.index(
        "_run_gate_p_with_semantic_invalidation("
    ) < l1_prepare.index("_run_l1_dedup_pair_candidate_phase(")
    l1_names = [phase.name for phase in L1_PHASES]
    assert l1_names.index("application_skeptic") < l1_names.index(
        "semantic_dedup"
    ) < l1_names.index("verify_queue")
    sc_names = [phase.name for phase in SC_PHASES]
    assert sc_names.index("application_skeptic") < sc_names.index(
        "sc_semantic_dedup"
    ) < sc_names.index("sc_verify_queue")
    sc_dedup_start = source.index(
        'if phase.name == "sc_semantic_dedup" and config.get("pipeline") == "sc":'
    )
    sc_dedup_end = source.index(
        'if phase.name == "attention_repair" and config.get("pipeline") == "sc":',
        sc_dedup_start,
    )
    sc_dedup_block = source[sc_dedup_start:sc_dedup_end]
    assert sc_dedup_block.index("_run_gate_p_with_semantic_invalidation(") < sc_dedup_block.index(
        "_compute_dedup_candidate_blocks(scratchpad)"
    )
    queue_source = inspect.getsource(
        driver._run_live_verify_queue_phase_boundary
    )
    assert "_run_gate_p_with_semantic_invalidation(" not in queue_source
    # The compatibility helper may remain defined, but report execution must
    # never invoke it as a late inventory mutation.
    assert source.count("_run_gate_p_for_report_index(") == 1


def test_gate_p_textual_duplicate_is_alias_proposal_not_authority(tmp_path: Path):
    scratchpad = _setup(tmp_path)
    (scratchpad / "analysis_percontract_1.md").write_text(
        "# Per-contract\n\n"
        "EXCLUDED [PC-4] duplicate of [INV-001] at src/Other.sol:L44; "
        "the update misses a boundary check and can corrupt a distinct state slot\n",
        encoding="utf-8",
    )
    rows = compute_promotion_orphans(scratchpad)
    assert len(rows) == 1
    assert rows[0]["alias_proposal"] is True
    assert rows[0]["alias_target"] == "INV-001"
    assert rows[0]["disposition"] == "BODY"


def test_gate_p_location_proximity_never_applies_semantic_dedup(tmp_path: Path):
    scratchpad = _setup(tmp_path)
    # Inventory covers this exact location under a different mechanism.
    (scratchpad / "findings_inventory.md").write_text(
        "# Inventory\n\n### Finding [INV-001]: event omission\n"
        "**Severity**: Low\n**Location**: `src/Hot.sol:L100`\n"
        "**Description**: A setter does not emit an event.\n",
        encoding="utf-8",
    )
    (scratchpad / "depth_state_findings.md").write_text(
        "# State\n\n## Finding [DS-90]: missing boundary check corrupts balance\n"
        "**Location**: `src/Hot.sol:L100`\n"
        "**Severity**: High\n"
        "**Description**: The update misses a boundary check and can corrupt "
        "the stored balance.\n**Impact**: Accounting becomes inconsistent.\n",
        encoding="utf-8",
    )
    rows = compute_promotion_orphans(scratchpad)
    assert any(row.get("orig_id") == "DS-90" for row in rows)


def test_gate_p_meta_word_collision_does_not_hide_finding(tmp_path: Path):
    scratchpad = _setup(tmp_path)
    (scratchpad / "depth_design_findings.md").write_text(
        "# Design\n\n"
        "## Finding [DD-5]: methodology registry misses authorization boundary\n"
        "**Location**: `src/Registry.sol:L73`\n"
        "**Severity**: Medium\n"
        "**Description**: The registry fails to validate the caller and permits "
        "an unauthorized state change.\n**Impact**: Protected state can change.\n",
        encoding="utf-8",
    )
    rows = compute_promotion_orphans(scratchpad)
    assert any(row.get("orig_id") == "DD-5" for row in rows)


def test_gate_p_candidate_shape_failure_becomes_visible_debt(tmp_path: Path):
    scratchpad = _setup(tmp_path)
    (scratchpad / "depth_composition_findings.md").write_text(
        "# Composition\n\n"
        "## Finding [DC-3]: cross-component invariant may diverge\n"
        "**Severity**: Medium\n"
        "**Description**: Two independently valid transitions compose into a "
        "state for which the repository-level invariant no longer holds.\n"
        "**Impact**: The system-wide accounting relation can diverge.\n",
        encoding="utf-8",
    )
    rows = compute_promotion_orphans(scratchpad)
    debt = next(row for row in rows if row.get("orig_id") == "DC-3")
    assert debt["shape_debt"] is True
    assert debt["disposition"] == "BODY"
    assert debt["location"] == "UNKNOWN"


def test_unbacked_negative_depth_rows_remain_in_composition_denominator(
    tmp_path: Path,
) -> None:
    scratchpad = _setup(tmp_path)
    (scratchpad / "hypotheses.md").write_text(
        "# Hypotheses\n\n**Status**: MECHANICAL_BASELINE\n",
        encoding="utf-8",
    )
    (scratchpad / "finding_mapping.md").write_text(
        "# Mapping\n\n**Status**: MECHANICAL_BASELINE\n",
        encoding="utf-8",
    )
    (scratchpad / "depth_state_findings.md").write_text(
        "# State\n\n"
        "### Finding [DS-701]: boundary variant remains composition-relevant\n"
        "**Verdict**: REFUTED\n**Severity**: High\n"
        "**Location**: `src/State.sol:L701`\n"
        "**Description**: A content-bearing mechanism was called unreachable.\n\n"
        "### Finding [DS-702]: second variant was called duplicate\n"
        "**Verdict**: DUPLICATE\n**Severity**: Medium\n"
        "**Location**: `src/State.sol:L702`\n"
        "**Description**: A distinct state transition still needs equivalence proof.\n",
        encoding="utf-8",
    )

    issues = _validate_chain_baseline_not_regrouped(scratchpad, "thorough")
    assert any("DS-701" in issue for issue in issues)
    assert any("DS-702" in issue for issue in issues)
    assert _auto_map_unmapped_depth_findings(scratchpad) == ["DS-701", "DS-702"]
    mapping = (scratchpad / "finding_mapping.md").read_text(encoding="utf-8")
    assert "| DS-701 |" in mapping
    assert "| DS-702 |" in mapping
