"""R0-8e: mechanical-gate growth has an enforceable policy record."""
from pathlib import Path
import json
import re


ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "rules" / "post-audit-improvement-protocol.md"
REGISTRY = ROOT / "rules" / "mechanical-gate-registry.json"
SEAMS = {
    "STARTUP_RESUME", "PRE_DISCOVERY", "POST_DISCOVERY", "PRE_VERIFY",
    "POST_VERIFY", "REPORT_ASSEMBLY",
}


def _section(text: str, start: str, end: str) -> str:
    assert start in text and end in text
    return text.split(start, 1)[1].split(end, 1)[0]


def _flat(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def test_authoritative_record_has_closed_seam_and_balanced_numeric_budget():
    text = PROTOCOL.read_text(encoding="utf-8")
    lifecycle = _section(
        text,
        "#### Mandatory Mechanical-Gate Lifecycle Registry and Review Contract",
        "### Change Type Risk Tiers",
    )
    template = _section(
        text, "## Mechanical-Gate Registry Record", "## Anti-Bloat Gates"
    )

    lifecycle_seams = set(re.findall(r"`([A-Z_]+)`", lifecycle))
    assert lifecycle_seams & SEAMS == SEAMS
    assert not {name for name in lifecycle_seams if "_" in name} - SEAMS
    template_seams = set(re.findall(r"\b[A-Z]+(?:_[A-Z]+)+\b", template)) & SEAMS
    assert template_seams == SEAMS
    for field in (
        "active_gate_count", "activated_or_shadow_additions",
        "approved_slot_releases", "gate_budget_ceiling",
        "post_change_gate_count", "baseline_gate_ids", "addition_gate_ids",
        "release_gate_ids",
    ):
        assert f"**{field}**" in template
    assert (
        "post_change_gate_count = active_gate_count + activated_or_shadow_additions\n"
        "    - approved_slot_releases"
    ) in lifecycle
    assert "authoritative record" in template
    assert "Gate-inventory baseline artifact / SHA-256 / committed revision" in template


def test_registry_is_persistent_closed_and_blocks_uninventoried_activation():
    payload = json.loads(REGISTRY.read_text(encoding="utf-8"))
    assert set(payload) == {
        "schema_version", "migration_status", "seam_taxonomy",
        "seam_budgets", "gate_records",
    }
    assert payload["schema_version"] == "plamen.mechanical_gate_registry.v1"
    assert payload["migration_status"] == "BLOCK_NEW_ACTIVATIONS_PENDING_BASELINE"
    assert set(payload["seam_taxonomy"]) == SEAMS
    assert payload["seam_budgets"] == [] and payload["gate_records"] == []
    text = PROTOCOL.read_text(encoding="utf-8")
    assert "rules/mechanical-gate-registry.json" in text
    assert "allowed persistent methodology artifact" in _flat(text)
    assert "an empty migration registry is not evidence of zero active gates" in _flat(text)


def test_ceiling_and_seam_are_frozen_outside_the_gate_proposal():
    text = PROTOCOL.read_text(encoding="utf-8")
    lifecycle = _section(
        text,
        "#### Mandatory Mechanical-Gate Lifecycle Registry and Review Contract",
        "### Change Type Risk Tiers",
    )
    flat = _flat(lifecycle)
    assert "prior committed revision, before the proposal under review" in flat
    assert "cannot create or rename a seam, raise its ceiling" in flat
    assert "Count every runtime-executed predicate" in lifecycle
    assert "independently fireable decisions count separately" in lifecycle


def test_slot_release_preserves_recall_or_records_explicit_tradeoff():
    text = PROTOCOL.read_text(encoding="utf-8")
    lifecycle = _section(
        text,
        "#### Mandatory Mechanical-Gate Lifecycle Registry and Review Contract",
        "### Change Type Risk Tiers",
    )
    flat = _flat(lifecycle)
    for requirement in (
        "independent held-out evidence of recall parity",
        "replacement subsumes the retired predicate",
        "no unique true-positive contribution",
        "explicit recall tradeoff",
    ):
        assert requirement in flat


def test_exception_has_distinct_hard_expiry_and_runtime_disable():
    text = PROTOCOL.read_text(encoding="utf-8")
    lifecycle = _section(
        text,
        "#### Mandatory Mechanical-Gate Lifecycle Registry and Review Contract",
        "### Change Type Risk Tiers",
    )
    template = _section(
        text, "## Mechanical-Gate Registry Record", "## Anti-Bloat Gates"
    )
    for field in (
        "exception_approver", "temporary_ceiling_delta", "exception_rationale",
        "review_by", "expires_on",
    ):
        assert f"`{field}`" in lifecycle
    assert "automatically returns to a non-runtime state" in _flat(lifecycle)
    assert (
        "post_change_gate_count <= gate_budget_ceiling + temporary_ceiling_delta"
        in _flat(lifecycle)
    )
    assert "review_by / expires_on" in template
    assert "Expiry action" in template


def test_identity_sets_reconcile_counts_and_mechanizable_rc_is_encodable():
    text = PROTOCOL.read_text(encoding="utf-8")
    lifecycle = _flat(_section(
        text,
        "#### Mandatory Mechanical-Gate Lifecycle Registry and Review Contract",
        "### Change Type Risk Tiers",
    ))
    template = _section(
        text, "## Mechanical-Gate Registry Record", "## Anti-Bloat Gates"
    )
    assert "Counts MUST equal the cardinality of those sets" in lifecycle
    assert "all counts are non-negative integers" in lifecycle
    assert "the sets are pairwise disjoint" in lifecycle
    assert "release_gate_ids` MUST be a subset" in lifecycle
    assert "approved_slot_releases <= active_gate_count" in lifecycle
    for field in ("baseline_gate_ids", "addition_gate_ids", "release_gate_ids"):
        assert f"**{field}**" in template
    source = _section(text, "## Source", "## Proposed Change")
    assert "RC-AGENT-MECHANIZABLE (M1-M4 PASS)" in source


def test_file_size_appendix_defers_to_gate_count_budget():
    text = PROTOCOL.read_text(encoding="utf-8")
    appendix = text.split("## Appendix A: File Size Budget Caps", 1)[1]
    assert "do **not** budget mechanical-gate count" in appendix
    assert "A smaller implementation" in appendix
