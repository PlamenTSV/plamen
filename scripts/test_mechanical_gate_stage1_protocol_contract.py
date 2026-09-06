from __future__ import annotations

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "rules" / "post-audit-improvement-protocol.md"


def _flat(value: str) -> str:
    return " ".join(value.split())


def test_protocol_has_closed_class_specific_admission_taxonomy() -> None:
    text = PROTOCOL.read_text(encoding="utf-8")
    section = text.split(
        "#### Mechanical-Gate Decision Classes", 1
    )[1].split("#### Mandatory Mechanical-Gate Lifecycle", 1)[0]
    for decision_class in (
        "RC_AGENT_MECHANIZABLE",
        "RECALL_GENERATOR",
        "PIPELINE_INTEGRITY",
        "PRECISION_DISCRIMINATOR",
        "TELEMETRY_ONLY",
    ):
        assert f"`{decision_class}`" in section
    flattened = _flat(section)
    assert "class-specific admission evidence" in flattened
    assert "all classes independently pass part 0" in flattened.lower()
    assert (
        "moving a gate to a class with broader authority is a new proposal"
        in flattened.lower()
    )
    assert (
        "M4 remains mandatory for `RC_AGENT_MECHANIZABLE`"
        in flattened
    )
    assert (
        "M4 is structurally inapplicable to `RECALL_GENERATOR`"
        in flattened
    )


def test_protocol_uses_the_noncontradictory_set_equations() -> None:
    text = PROTOCOL.read_text(encoding="utf-8")
    lifecycle = text.split(
        "#### Mandatory Mechanical-Gate Lifecycle", 1
    )[1].split("## Mechanical-Gate Registry Record", 1)[0]
    flattened = _flat(lifecycle)
    assert "addition_gate_ids ∩ baseline_gate_ids = empty" in flattened
    assert "addition_gate_ids ∩ release_gate_ids = empty" in flattened
    assert "release_gate_ids ⊆ baseline_gate_ids" in flattened
    assert (
        "post_change_gate_ids = (baseline_gate_ids - release_gate_ids) "
        "∪ addition_gate_ids"
    ) in flattened
    assert "the sets are pairwise disjoint" not in flattened


def test_protocol_freezes_legacy_migration_without_certifying_it() -> None:
    text = PROTOCOL.read_text(encoding="utf-8")
    flattened = _flat(text)
    assert "`LEGACY_ACTIVE_UNGOVERNED`" in text
    assert "`LEGACY_UNASSESSED`" in text
    assert "`LEGACY_NOT_MIGRATED`" in text
    assert "new runtime transitions remain blocked" in flattened
    assert "does not grant runtime authority" in flattened
    assert not re.search(
        r"every record defines M1(?:\s|[-–—])*M4 evidence",
        flattened,
        re.IGNORECASE,
    )


def test_protocol_matches_v2_exception_and_expiry_contract() -> None:
    text = PROTOCOL.read_text(encoding="utf-8")
    assert "`exception_rationale_code`" in text
    assert "`exception_rationale`" not in text
    assert "`EXPIRED_BLOCKED`" in text
    assert "`EXPIRED_BLOCKED → PROPOSED`" in text
