"""R0-2c: committed-invariant schema drift must recover, not merely warn."""

from __future__ import annotations

from pathlib import Path

import enumeration_gate as E
import plamen_parsers as P
import plamen_validators as V


def _scratchpad(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    scratchpad = root / ".scratchpad"
    scratchpad.mkdir(parents=True)
    (scratchpad / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n", encoding="utf-8"
    )
    return scratchpad


def _namespaced_ci() -> str:
    return (
        "committed-invariant [C1-CI-1]\n"
        "Locus: src/Accounting.sol:L42\n"
        "Shape: CONSERVATION\n"
        "Assertion: total credited value equals total settled value\n"
        "Falsify Class: conservation\n"
        "Provenance: exploration skeptic clear C1\n"
    )


def test_namespaced_ci_is_harvested_with_exact_identity(tmp_path):
    sp = _scratchpad(tmp_path)
    (sp / "exploration_skeptic_findings.md").write_text(
        "# Exploration Skeptic\n\nNO-GAP at a value boundary\n\n" + _namespaced_ci(),
        encoding="utf-8",
    )
    candidates = E.compute_invariant_assertion_candidates(sp)
    assert len(candidates) == 1
    assert candidates[0]["source_tag"] == "INVARIANT:C1-CI-1"
    assert "C1-CI-1" in candidates[0]["key"]


def test_validator_recovers_namespaced_ci_into_inventory_not_warning_only(tmp_path):
    sp = _scratchpad(tmp_path)
    (sp / "exploration_skeptic_findings.md").write_text(
        "# Exploration Skeptic\n\nNO-GAP at a value boundary\n\n" + _namespaced_ci(),
        encoding="utf-8",
    )
    issues = V._validate_invariant_commitment(sp, "thorough")
    inventory = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert issues == []
    assert "INVARIANT:C1-CI-1" in inventory
    assert "NEEDS_VERIFICATION" in inventory
    assert not (sp / "invariant_commitment.ci_format_gap").exists()


def test_ci_recovery_is_idempotent_and_self_clears_stale_drift_marker(tmp_path):
    sp = _scratchpad(tmp_path)
    (sp / "exploration_skeptic_findings.md").write_text(
        "# Exploration Skeptic\n\nDOWNGRADE at a value boundary\n\n" + _namespaced_ci(),
        encoding="utf-8",
    )
    stale = sp / "invariant_commitment.ci_format_gap"
    stale.write_text("stale")
    V._validate_invariant_commitment(sp, "thorough")
    once = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    V._validate_invariant_commitment(sp, "thorough")
    twice = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert once == twice
    assert once.count("INVARIANT:C1-CI-1") == 1
    assert not stale.exists()


def test_namespaced_ci_is_recognized_as_one_internal_id_not_suffix_alias():
    matches = P._INTERNAL_FINDING_ID_RE.findall(
        "committed-invariant [C1-CI-1]"
    )
    assert matches == ["C1-CI-1"]
    assert P._CLIENT_BODY_INTERNAL_ID_RE.search("see C1-CI-1")


def test_bare_and_shard_ci_forms_remain_supported(tmp_path):
    sp = _scratchpad(tmp_path)
    artifact = sp / "depth_token_flow_findings.md"
    artifact.write_text(
        _namespaced_ci().replace("C1-CI-1", "CI-1")
        + "\n"
        + _namespaced_ci().replace("C1-CI-1", "CI-A1"),
        encoding="utf-8",
    )
    tags = {
        candidate["source_tag"]
        for candidate in E.compute_invariant_assertion_candidates(sp)
    }
    assert tags == {"INVARIANT:CI-1", "INVARIANT:CI-A1"}
