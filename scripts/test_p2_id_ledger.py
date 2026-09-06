"""Tests for v2.0.6 P2 — canonical ID ledger + collision gate.

Covers:
  P2.1  _id_ledger.json schema + helpers (load/save/register/next/lookup)
  P2.2  Inventory + niche promotion register at mint time
  P2.3  Chain prompt receives driver-injected ID ledger directive
  P2.4  Post-phase collision gate (BLOCKING for chain / chain_agent2)
  P2.5  Consumer backstop gate (WARNING-only at first ship)

The observed root cause was chain attempt 1 minting GRP-01 for
title-A (Critical public-withdraw), then chain attempt 2 re-minting
GRP-01 for title-B (Medium reinitializer). All P2 fixtures here are
synthetic — never past-audit scratchpad copies — to prevent overfitting.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from plamen_parsers import (  # noqa: E402
    _ID_LEDGER_NAME,
    _ID_LEDGER_SCHEMA_VERSION,
    _id_ledger_load,
    _id_prefix_of,
    _title_hash,
    id_ledger_all_for_prefix,
    id_ledger_all_records,
    id_ledger_lookup,
    id_ledger_next_available,
    id_ledger_register,
)
from plamen_validators import (  # noqa: E402
    _generate_id_ledger_collision_retry_hint,
    _parse_hypothesis_id_title_pairs,
    _promote_depth_findings_to_inventory,
    _repair_chain_anti_absorption_splits,
    _validate_consumer_ids_in_ledger,
    _validate_id_ledger_collisions,
)
from plamen_prompt import _render_id_ledger_directive  # noqa: E402


# ---------------------------------------------------------------------------
# P2.1 — schema + helpers
# ---------------------------------------------------------------------------


def test_p21_round_trip(tmp_path):
    """Allocate, persist, reload — basic ledger round-trip."""
    r1 = id_ledger_register(
        tmp_path, finding_id="GRP-01", owner_phase="chain_agent1",
        owner_attempt=1, owning_artifact="hypotheses.md",
        title="Some root cause",
    )
    assert r1["status"] == "REGISTERED"
    assert (tmp_path / _ID_LEDGER_NAME).exists()
    payload = json.loads((tmp_path / _ID_LEDGER_NAME).read_text(encoding="utf-8"))
    assert payload["schema_version"] == _ID_LEDGER_SCHEMA_VERSION
    assert len(payload["allocations"]) == 1
    rec = payload["allocations"][0]
    assert rec["id"] == "GRP-01"
    assert rec["owner_phase"] == "chain_agent1"
    assert rec["prefix"] == "GRP-"
    assert "title_hash" in rec and rec["title_hash"].startswith("sha256:")


def test_p21_title_hash_stable_across_minor_variations():
    """Same logical title hashes identically across case/whitespace/ID-prefix."""
    base = "NativeVault.withdraw() Is Public — Permissionless Drain"
    h_base = _title_hash(base)
    assert _title_hash(base.lower()) == h_base
    assert _title_hash(f"  {base}  ") == h_base
    assert _title_hash(f"[GRP-01]: {base}") == h_base
    assert _title_hash(f"Finding [GRP-01]: {base}") == h_base


def test_fix2_title_hash_dash_family_collapses():
    """Em/en/figure-dash and minus all normalize to ASCII hyphen (FIX 2)."""
    base_hyphen = "GCC trusts inbound externalId verbatim - no provenance"
    for dash in "‒–—―−":
        variant = base_hyphen.replace("-", dash)
        assert _title_hash(variant) == _title_hash(base_hyphen)


def test_fix2_title_hash_backtick_and_emphasis_ignored():
    """Code-framing/emphasis punctuation does not change identity (FIX 2)."""
    a = "CrossChainRouter.withdraw() is public"
    b = "CrossChainRouter.`withdraw()` is **public**"
    assert _title_hash(a) == _title_hash(b)


def test_fix2_titles_collide_false_on_dash_reword():
    """The exact observed cascade: em-dash reword is NOT a collision (FIX 2)."""
    from plamen_parsers import _titles_collide
    a = "GCC trusts inbound externalId verbatim — no provenance check"
    b = "GCC trusts inbound externalId verbatim - no provenance check"
    assert _titles_collide(a, b) is False


def test_fix2_titles_collide_false_on_abbrev_expansion():
    """Abbreviation expanded with otherwise-identical wording is same finding."""
    from plamen_parsers import _titles_collide
    a = "GCC trusts inbound externalId verbatim — no provenance"
    b = "CrossChainRouter trusts inbound externalId verbatim - no provenance"
    assert _titles_collide(a, b) is False


def test_fix2_titles_collide_false_on_added_trailing_detail():
    """Added trailing detail (prefix containment) is same finding, not collision."""
    from plamen_parsers import _titles_collide
    a = "CrossChainRouter trusts inbound externalId verbatim"
    b = "CrossChainRouter trusts inbound externalId verbatim, enabling spoof"
    assert _titles_collide(a, b) is False


def test_fix2_titles_collide_true_on_genuinely_different_finding():
    """Different findings reusing an ID MUST still be a collision (recall-safe)."""
    from plamen_parsers import _titles_collide
    a = "NativeVault.withdraw() Is Public — Permissionless Drain"
    b = "Missing reinitializer() function blocks upgrade"
    assert _titles_collide(a, b) is True


def test_fix2_register_reuses_on_cosmetic_reword(tmp_path):
    """Ledger register: cosmetic chain reword -> REUSED, not COLLISION (FIX 2)."""
    id_ledger_register(
        tmp_path, finding_id="GRP-01", owner_phase="chain",
        owner_attempt=1, owning_artifact="hypotheses.md",
        title="GCC trusts inbound externalId verbatim — no provenance check",
    )
    r = id_ledger_register(
        tmp_path, finding_id="GRP-01", owner_phase="chain",
        owner_attempt=2, owning_artifact="hypotheses.md",
        title="CrossChainRouter trusts inbound externalId verbatim - no provenance check",
    )
    assert r["status"] == "REUSED"


def test_fix2_register_still_collides_on_different_finding(tmp_path):
    """Ledger register: genuinely different finding for same ID -> COLLISION."""
    id_ledger_register(
        tmp_path, finding_id="GRP-01", owner_phase="chain",
        owner_attempt=1, owning_artifact="hypotheses.md",
        title="NativeVault.withdraw() Is Public — Permissionless Drain",
    )
    r = id_ledger_register(
        tmp_path, finding_id="GRP-01", owner_phase="chain",
        owner_attempt=2, owning_artifact="hypotheses.md",
        title="Missing reinitializer() function blocks contract upgrade",
    )
    assert r["status"] == "COLLISION"


def test_fix2_collision_gate_no_false_alarm_on_chain_reword(tmp_path):
    """End-to-end: chain retry that reworded its OWN titles does NOT collide."""
    (tmp_path / "hypotheses.md").write_text(
        "### GRP-01 — GCC trusts inbound externalId verbatim — no check\n",
        encoding="utf-8",
    )
    assert _validate_id_ledger_collisions(tmp_path, "chain", attempt=1) == []
    # Retry reworded the SAME finding (abbrev expanded, em-dash -> hyphen).
    (tmp_path / "hypotheses.md").write_text(
        "### GRP-01 - CrossChainRouter trusts inbound externalId verbatim - no check\n",
        encoding="utf-8",
    )
    assert _validate_id_ledger_collisions(tmp_path, "chain", attempt=2) == []


def test_p21_id_prefix_of():
    """Prefix extractor handles common forms; returns '' for non-IDs."""
    assert _id_prefix_of("GRP-01") == "GRP-"
    assert _id_prefix_of("HM-99") == "HM-"
    assert _id_prefix_of("INV-001") == "INV-"
    assert _id_prefix_of("CH-12") == "CH-"
    assert _id_prefix_of("not-an-id") == ""
    assert _id_prefix_of("") == ""


def test_p21_register_reuse_when_title_unchanged(tmp_path):
    """Re-registering the same ID with the SAME title is REUSED, not a write."""
    r1 = id_ledger_register(
        tmp_path, finding_id="GRP-01", owner_phase="chain_agent1",
        owner_attempt=1, owning_artifact="hypotheses.md",
        title="Same root cause",
    )
    assert r1["status"] == "REGISTERED"
    r2 = id_ledger_register(
        tmp_path, finding_id="GRP-01", owner_phase="chain_agent1",
        owner_attempt=2, owning_artifact="hypotheses.md",
        title="Same root cause",
    )
    assert r2["status"] == "REUSED"
    # Ledger should still have exactly ONE allocation.
    assert len(id_ledger_all_records(tmp_path)) == 1


def test_p21_register_collision_when_title_differs(tmp_path):
    """The observed root cause: same ID, different title → COLLISION."""
    id_ledger_register(
        tmp_path, finding_id="GRP-01", owner_phase="chain_agent1",
        owner_attempt=1, owning_artifact="hypotheses.md",
        title="NativeVault.withdraw() Is Public",
    )
    r = id_ledger_register(
        tmp_path, finding_id="GRP-01", owner_phase="chain_agent1",
        owner_attempt=2, owning_artifact="hypotheses.md",
        title="No reinitializer() Function",
    )
    assert r["status"] == "COLLISION"
    assert r["existing"]["title_preview"].startswith("NativeVault")
    assert r["current"]["title_preview"].startswith("No reinitializer")


def test_p21_next_available_advances_per_prefix(tmp_path):
    """next_available picks max+1 per prefix; prefixes are independent."""
    for i in range(1, 4):
        id_ledger_register(
            tmp_path, finding_id=f"GRP-{i:02d}", owner_phase="chain_agent1",
            owner_attempt=1, owning_artifact="hypotheses.md",
            title=f"title {i}",
        )
    id_ledger_register(
        tmp_path, finding_id="HH-01", owner_phase="chain_agent1",
        owner_attempt=1, owning_artifact="hypotheses.md", title="hh title",
    )
    assert id_ledger_next_available(tmp_path, "GRP-") == "GRP-04"
    assert id_ledger_next_available(tmp_path, "HH-") == "HH-02"
    assert id_ledger_next_available(tmp_path, "HM-") == "HM-01"


def test_p21_lookup_and_filter(tmp_path):
    """lookup + all_for_prefix return expected records."""
    id_ledger_register(
        tmp_path, finding_id="GRP-01", owner_phase="chain_agent1",
        owner_attempt=1, owning_artifact="hypotheses.md", title="t1",
    )
    id_ledger_register(
        tmp_path, finding_id="HH-01", owner_phase="chain_agent1",
        owner_attempt=1, owning_artifact="hypotheses.md", title="t2",
    )
    assert id_ledger_lookup(tmp_path, "GRP-01")["title_preview"] == "t1"
    assert id_ledger_lookup(tmp_path, "missing") is None
    grp_recs = id_ledger_all_for_prefix(tmp_path, "GRP-")
    assert len(grp_recs) == 1


# ---------------------------------------------------------------------------
# P2.3 — prompt directive
# ---------------------------------------------------------------------------


def test_p23_chain_directive_lists_allocations_and_nextavail(tmp_path):
    """build_phase_prompt for chain emits the directive with the live ledger state."""
    id_ledger_register(
        tmp_path, finding_id="GRP-01", owner_phase="chain_agent1",
        owner_attempt=1, owning_artifact="hypotheses.md",
        title="A real title",
    )
    id_ledger_register(
        tmp_path, finding_id="INV-001", owner_phase="inventory",
        owner_attempt=1, owning_artifact="findings_inventory.md",
        title="An inventory finding",
    )
    d = _render_id_ledger_directive("chain", tmp_path)
    assert "## ID LEDGER" in d
    assert "GRP-01" in d
    # INV-* is NOT in chain's namespace — must not appear.
    assert "INV-001" not in d
    # Next-available numbers present.
    assert "GRP-02" in d
    assert "HM-01" in d


def test_p23_chain_directive_handles_empty_ledger(tmp_path):
    """Empty ledger → directive still emits with 'no prior allocations' note."""
    d = _render_id_ledger_directive("chain", tmp_path)
    assert "No prior allocations" in d
    assert "GRP-01" in d  # next-available


def test_p23_directive_empty_for_non_chain_phases(tmp_path):
    """Phases other than chain/chain_agent2 get no directive (empty string)."""
    assert _render_id_ledger_directive("inventory_chunk_a", tmp_path) == ""
    assert _render_id_ledger_directive("breadth", tmp_path) == ""
    assert _render_id_ledger_directive("depth", tmp_path) == ""


def test_p23_chain_agent2_directive_scoped_to_CH(tmp_path):
    """chain_agent2 sees CH-* only — not GRP/HM/etc."""
    id_ledger_register(
        tmp_path, finding_id="GRP-01", owner_phase="chain_agent1",
        owner_attempt=1, owning_artifact="hypotheses.md", title="t1",
    )
    d = _render_id_ledger_directive("chain_agent2", tmp_path)
    assert "CH-01" in d  # next-available CH
    assert "GRP-01" not in d  # different namespace from chain_agent2


# ---------------------------------------------------------------------------
# P2.4 — collision gate
# ---------------------------------------------------------------------------


def test_p24_parse_hypothesis_id_title_pairs():
    """Heading parser extracts (ID, title) pairs from hypotheses-like MD."""
    text = (
        "# Hypotheses\n\n"
        "### GRP-01 — NativeVault.withdraw() Is Public\n\n"
        "Some body text.\n\n"
        "### HH-02 — Initial fee setter has no upper bound\n\n"
        "Body.\n\n"
        "## Chain Hypothesis CH-01: chain title\n\n"
    )
    pairs = _parse_hypothesis_id_title_pairs(text)
    pair_dict = dict(pairs)
    assert "GRP-01" in pair_dict
    assert "NativeVault" in pair_dict["GRP-01"]
    assert pair_dict.get("HH-02", "").startswith("Initial fee")
    assert pair_dict.get("CH-01", "").startswith("chain title")


def test_p24_collision_gate_registers_table_hypotheses(tmp_path):
    """Chain hypotheses emitted as markdown rows still enter the ledger."""
    (tmp_path / "hypotheses.md").write_text(
        "| Hypothesis ID | Severity | Title | Source |\n"
        "|---------------|----------|-------|--------|\n"
        "| HM-01 | Medium | No emergency pause mechanism | BLIND-B-3 |\n"
        "| HH-01 | High | Public withdraw drain | INV-001 |\n",
        encoding="utf-8",
    )

    issues = _validate_id_ledger_collisions(tmp_path, "chain", attempt=1)

    assert issues == []
    assert id_ledger_lookup(tmp_path, "HM-01") is not None
    assert id_ledger_lookup(tmp_path, "HH-01") is not None


def test_chain_anti_absorption_repair_registers_split_ids(tmp_path):
    (tmp_path / "_audit_started_with_markers.json").write_text("{}", encoding="utf-8")
    (tmp_path / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Public withdraw drain\n"
        "**Severity**: High\n"
        "**Location**: A.sol:withdraw\n"
        "**Root Cause**: public withdraw drains funds\n\n"
        "### Finding [INV-002]: Unsafe transfer delivery failure\n"
        "**Severity**: Low\n"
        "**Location**: B.sol:onCall\n"
        "**Root Cause**: transfer uses 2300 gas\n\n",
        encoding="utf-8",
    )
    (tmp_path / "hypotheses.md").write_text(
        "| Hypothesis ID | Severity | Title | Source Findings |\n"
        "|---------------|----------|-------|-----------------|\n"
        "| H-01 | High | Over-merged group | INV-001, INV-002 |\n",
        encoding="utf-8",
    )
    (tmp_path / "finding_mapping.md").write_text(
        "| Finding ID | Hypothesis ID | Mapping Status |\n"
        "|------------|---------------|----------------|\n"
        "| INV-001 | H-01 | GROUPED |\n"
        "| INV-002 | H-01 | GROUPED |\n",
        encoding="utf-8",
    )

    repaired = _repair_chain_anti_absorption_splits(tmp_path)

    assert repaired == 2
    assert id_ledger_lookup(tmp_path, "HH-01") is None
    assert id_ledger_lookup(tmp_path, "HL-01") is None
    relation = json.loads(
        (tmp_path / "chain_grouping_relations.json").read_text(encoding="utf-8")
    )
    assert relation["groups"][0]["member_to_work"] == {
        "INV-001": "INV-001", "INV-002": "INV-002"
    }


def test_p24_collision_gate_passes_on_first_attempt(tmp_path):
    """Attempt 1: no prior allocations → no collisions."""
    (tmp_path / "hypotheses.md").write_text(
        "### GRP-01 — public withdraw drain\n"
        "**Severity**: Critical\n", encoding="utf-8",
    )
    issues = _validate_id_ledger_collisions(tmp_path, "chain", attempt=1)
    assert issues == []
    # AND the ID is now registered.
    assert id_ledger_lookup(tmp_path, "GRP-01") is not None


def test_p24_collision_gate_detects_remint_with_different_content(tmp_path):
    """Attempt 2 re-mints GRP-01 with DIFFERENT title → collision."""
    # Attempt 1
    (tmp_path / "hypotheses.md").write_text(
        "### GRP-01 — public withdraw drain\n", encoding="utf-8",
    )
    _validate_id_ledger_collisions(tmp_path, "chain", attempt=1)
    # Attempt 2 overwrites with different content
    (tmp_path / "hypotheses.md").write_text(
        "### GRP-01 — no reinitializer in any contract\n", encoding="utf-8",
    )
    issues = _validate_id_ledger_collisions(tmp_path, "chain", attempt=2)
    assert len(issues) == 1
    assert "GRP-01" in issues[0]
    assert "public withdraw" in issues[0]
    assert "no reinitializer" in issues[0]


def test_p24_collision_gate_no_false_positive_on_same_content(tmp_path):
    """Attempt 2 reuses GRP-01 with SAME title → no collision."""
    (tmp_path / "hypotheses.md").write_text(
        "### GRP-01 — public withdraw drain\n", encoding="utf-8",
    )
    _validate_id_ledger_collisions(tmp_path, "chain", attempt=1)
    # Same content (LLM retry that preserved its grouping)
    _validate_id_ledger_collisions(tmp_path, "chain", attempt=2)
    issues = _validate_id_ledger_collisions(tmp_path, "chain", attempt=2)
    assert issues == []


def test_p24_chain_agent2_ignores_referenced_upstream_ids(tmp_path):
    """chain_agent2 mints CH-* only; referenced H-* IDs are consumers."""
    id_ledger_register(
        tmp_path,
        finding_id="H-01",
        owner_phase="chain",
        owner_attempt=1,
        owning_artifact="hypotheses.md",
        title="claimPayout authorization bypass",
    )
    (tmp_path / "chain_hypotheses.md").write_text(
        "# Chain Hypotheses\n\n"
        "| Chain ID | Finding A | Missing Precondition | Finding B | Chain Severity |\n"
        "|---|---|---|---|---|\n"
        "| CH-01 | H-09: fee mismatch | refund entry exists | H-01: auth bypass | Critical |\n\n"
        "## Chain Hypothesis CH-01\n"
        "### Blocked Finding (A)\n"
        "- **ID**: H-09, **Title**: fee mismatch\n"
        "### Enabler Finding (B)\n"
        "- **ID**: H-01, **Title**: claimPayout authorization bypass\n",
        encoding="utf-8",
    )

    issues = _validate_id_ledger_collisions(tmp_path, "chain_agent2", attempt=1)

    assert issues == []
    assert id_ledger_lookup(tmp_path, "CH-01") is not None
    assert id_ledger_lookup(tmp_path, "H-01") is not None


def test_p24_chain_agent2_retry_prunes_failed_same_phase_allocations(tmp_path):
    """Expanded wording for the same CH source pair must not collide on retry."""
    (tmp_path / "chain_hypotheses.md").write_text(
        "| Chain ID | Finding A | Missing Precondition | Finding B | Chain Severity |\n"
        "|---|---|---|---|---|\n"
        "| CH-01 | H-09 (GTN no-fee bypass missing) | refund entry | H-01 (auth bypass) | Critical |\n",
        encoding="utf-8",
    )
    assert _validate_id_ledger_collisions(tmp_path, "chain_agent2", attempt=1) == []

    (tmp_path / "chain_hypotheses.md").write_text(
        "| Chain ID | Finding A | Missing Precondition | Finding B | Chain Severity |\n"
        "|---|---|---|---|---|\n"
        "| CH-01 | H-09: NativeVault.onCall() Missing amount -= platformFeesForTx | refund entry | H-01: claimPayout() Authorization Bypass for Non-EVM Wallets | Critical |\n",
        encoding="utf-8",
    )

    assert _validate_id_ledger_collisions(tmp_path, "chain_agent2", attempt=2) == []


def test_p24_retry_hint_format(tmp_path):
    """Retry hint mentions the conflict and gives actionable repair steps."""
    fake_collisions = [
        "ID `GRP-01` was previously allocated by chain/attempt 1 "
        "to title 'public withdraw'; this attempt tried "
        "to re-allocate it to 'reinitializer missing'"
    ]
    hint = _generate_id_ledger_collision_retry_hint(fake_collisions, "chain")
    assert "ID ledger collision" in hint
    assert "GRP-01" in hint
    assert "REUSE" in hint
    assert "next-available" in hint


def test_p24_gate_silent_on_non_chain_phases(tmp_path):
    """Gate only triggers on chain / chain_agent2; other phases get [] silently."""
    (tmp_path / "hypotheses.md").write_text(
        "### GRP-01 — t\n", encoding="utf-8",
    )
    assert _validate_id_ledger_collisions(tmp_path, "breadth") == []
    assert _validate_id_ledger_collisions(tmp_path, "inventory_chunk_a") == []
    assert _validate_id_ledger_collisions(tmp_path, "depth") == []


# ---------------------------------------------------------------------------
# P2.5 — consumer backstop
# ---------------------------------------------------------------------------


def test_p25_backstop_empty_when_all_refs_in_ledger(tmp_path):
    """Consumer references only ledger-registered IDs → no warnings."""
    id_ledger_register(
        tmp_path, finding_id="GRP-01", owner_phase="chain_agent1",
        owner_attempt=1, owning_artifact="hypotheses.md", title="t",
    )
    id_ledger_register(
        tmp_path, finding_id="HH-02", owner_phase="chain_agent1",
        owner_attempt=1, owning_artifact="hypotheses.md", title="t2",
    )
    (tmp_path / "report_index.md").write_text(
        "| C-01 | Title | Critical | ... | GRP-01 |\n"
        "| H-01 | Title | High | ... | HH-02 |\n", encoding="utf-8",
    )
    issues = _validate_consumer_ids_in_ledger(tmp_path, "report_index")
    assert issues == []


def test_p25_backstop_flags_unregistered_refs(tmp_path):
    """Consumer references an ID not in the ledger → warning issue."""
    id_ledger_register(
        tmp_path, finding_id="GRP-01", owner_phase="chain_agent1",
        owner_attempt=1, owning_artifact="hypotheses.md", title="t",
    )
    (tmp_path / "report_index.md").write_text(
        "| C-01 | Title | Critical | ... | GRP-99 |\n", encoding="utf-8",
    )
    issues = _validate_consumer_ids_in_ledger(tmp_path, "report_index")
    assert len(issues) == 1
    assert "GRP-99" in issues[0]
    assert "consumer-backstop" in issues[0]


def test_p25_skeptic_backstop_ignores_prose_local_ids(tmp_path):
    """Skeptic prose may mention local concern IDs; structural keys matter."""
    id_ledger_register(
        tmp_path, finding_id="HH-09", owner_phase="chain",
        owner_attempt=1, owning_artifact="hypotheses.md", title="real high",
    )
    (tmp_path / "skeptic_findings.md").write_text(
        "# Skeptic Findings\n\n"
        "## HH-09 - real high\n\n"
        "The verifier also cited CC-09, EX-1, INV-4, and OR-2 as local "
        "context labels, but those are not the reviewed finding IDs.\n",
        encoding="utf-8",
    )
    (tmp_path / "skeptic_judge_decisions.md").write_text(
        "| Finding ID | Original Severity | Final Severity | Decision | Rationale |\n"
        "|---|---|---|---|---|\n"
        "| HH-09 | High | High | KEEP | Prose references are contextual only. |\n",
        encoding="utf-8",
    )

    assert _validate_consumer_ids_in_ledger(tmp_path, "skeptic") == []


def test_p25_skeptic_backstop_flags_unregistered_structural_id(tmp_path):
    id_ledger_register(
        tmp_path, finding_id="HH-09", owner_phase="chain",
        owner_attempt=1, owning_artifact="hypotheses.md", title="real high",
    )
    (tmp_path / "skeptic_findings.md").write_text(
        "# Skeptic Findings\n\n## CC-09 - hallucinated structural key\n",
        encoding="utf-8",
    )
    (tmp_path / "skeptic_judge_decisions.md").write_text(
        "| Finding ID | Original Severity | Final Severity | Decision | Rationale |\n"
        "|---|---|---|---|---|\n"
        "| CC-09 | High | High | KEEP | Bad key. |\n",
        encoding="utf-8",
    )

    issues = _validate_consumer_ids_in_ledger(tmp_path, "skeptic")

    assert len(issues) == 1
    assert "CC-09" in issues[0]


def test_p25_backstop_silent_when_ledger_empty(tmp_path):
    """No ledger (legacy audit) → backstop skips silently (no false halt)."""
    (tmp_path / "report_index.md").write_text(
        "| C-01 | Title | Critical | ... | GRP-01 |\n", encoding="utf-8",
    )
    issues = _validate_consumer_ids_in_ledger(tmp_path, "report_index")
    assert issues == []


def test_p25_backstop_ignores_report_tier_ids(tmp_path):
    """M-NN/L-NN/etc. report-tier IDs are not part of the ledger namespace."""
    id_ledger_register(
        tmp_path, finding_id="GRP-01", owner_phase="chain_agent1",
        owner_attempt=1, owning_artifact="hypotheses.md", title="t",
    )
    (tmp_path / "report_index.md").write_text(
        "| M-01 | Title | Medium | ... | GRP-01 |\n"
        "| L-05 | Title | Low | ... | GRP-01 |\n", encoding="utf-8",
    )
    # M-01 and L-05 are report-tier IDs; they're not validated here.
    # GRP-01 is in ledger → no issues.
    issues = _validate_consumer_ids_in_ledger(tmp_path, "report_index")
    assert issues == []


def test_p25_backstop_ignores_inv_for_now(tmp_path):
    """INV-* allowed without ledger entry (legacy compatibility)."""
    # No ledger entries; but consumer references INV-099.
    id_ledger_register(
        tmp_path, finding_id="GRP-01", owner_phase="chain_agent1",
        owner_attempt=1, owning_artifact="hypotheses.md", title="t",
    )
    (tmp_path / "verification_queue.md").write_text(
        "| 1 | INV-099 | verify_INV-099.md | High | Title |\n",
        encoding="utf-8",
    )
    # INV-099 is NOT in ledger but is allowed (P2.2 exception).
    issues = _validate_consumer_ids_in_ledger(tmp_path, "sc_verify_queue")
    assert issues == []


def test_p25_backstop_backfills_real_inventory_inv_rows_on_fresh_audit(tmp_path):
    """Fresh audits should not warn when a real inventory row missed registration."""
    (tmp_path / "_audit_started_with_markers.json").write_text("{}", encoding="utf-8")
    id_ledger_register(
        tmp_path, finding_id="GRP-01", owner_phase="chain",
        owner_attempt=1, owning_artifact="hypotheses.md", title="registered",
    )
    (tmp_path / "findings_inventory.md").write_text(
        "### Finding [INV-60]: Depth promoted issue\n\n"
        "**Severity**: High\n"
        "**Location**: src/A.sol:L10\n"
        "**Source IDs**: DCI-1\n",
        encoding="utf-8",
    )
    (tmp_path / "verify_core.md").write_text(
        "| INV-60 | CONFIRMED | [CODE-TRACE] | src/A.sol:L10 |\n",
        encoding="utf-8",
    )

    issues = _validate_consumer_ids_in_ledger(tmp_path, "sc_verify_aggregate")

    assert issues == []
    assert id_ledger_lookup(tmp_path, "INV-60") is not None


def test_p25_depth_promotion_allocates_registered_three_digit_inv_ids(tmp_path):
    """Depth promotion appends first-class inventory IDs and registers them."""
    id_ledger_register(
        tmp_path, finding_id="INV-059", owner_phase="inventory",
        owner_attempt=1, owning_artifact="findings_inventory.md",
        title="Existing inventory finding",
    )
    (tmp_path / "findings_inventory.md").write_text(
        "### Finding [INV-059]: Existing inventory finding\n\n"
        "**Severity**: High\n"
        "**Location**: src/A.sol:L1\n"
        "**Source IDs**: AC-1\n",
        encoding="utf-8",
    )
    (tmp_path / "depth_external_findings.md").write_text(
        "### Finding [DX-1]: Depth-only issue\n\n"
        "**Severity**: High\n"
        "**Location**: src/B.sol:L20\n"
        "**Preferred Tag**: [CODE-TRACE]\n"
        "**Description**: Real depth issue.\n",
        encoding="utf-8",
    )

    promoted = _promote_depth_findings_to_inventory(tmp_path)
    inv_text = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")

    assert promoted == ["DX-1"]
    assert "### Finding [INV-060]: Depth-only issue" in inv_text
    assert id_ledger_lookup(tmp_path, "INV-060") is not None


def test_p25_backstop_accepts_traceable_depth_local_ids(tmp_path):
    """Synthetic depth IDs are accepted only when traceable to depth artifacts."""
    id_ledger_register(
        tmp_path, finding_id="GRP-01", owner_phase="chain_agent1",
        owner_attempt=1, owning_artifact="hypotheses.md", title="t",
    )
    (tmp_path / "depth_state_trace_findings.md").write_text(
        "### Finding [DCI-3]: state trace issue\n", encoding="utf-8",
    )
    (tmp_path / "report_index.md").write_text(
        "| H-01 | Title | High | ... | DCI-3 |\n", encoding="utf-8",
    )

    issues = _validate_consumer_ids_in_ledger(tmp_path, "report_index")

    assert issues == []
    synthetic_map = json.loads(
        (tmp_path / "_id_ledger_synthetic_map.json").read_text(encoding="utf-8")
    )
    assert synthetic_map["traces"][0]["id"] == "DCI-3"
    assert synthetic_map["traces"][0]["source_artifact"] == "depth_state_trace_findings.md"


def test_p25_backstop_accepts_traceable_report_local_ids(tmp_path):
    """Report index may reference local EN/ST/VS methodology IDs with trace."""
    id_ledger_register(
        tmp_path, finding_id="INV-001", owner_phase="inventory",
        owner_attempt=1, owning_artifact="findings_inventory.md", title="seed",
    )
    (tmp_path / "enabler_results.md").write_text(
        "### EN-01\nEnabler evidence.\n", encoding="utf-8"
    )
    (tmp_path / "design_stress_findings.md").write_text(
        "### ST-2\nStress finding.\n", encoding="utf-8"
    )
    (tmp_path / "validation_sweep_findings.md").write_text(
        "### VS-1\nValidation sweep finding.\n", encoding="utf-8"
    )
    (tmp_path / "report_index.md").write_text(
        "| H-01 | Title | High | ... | EN-01, ST-2, VS-1 |\n",
        encoding="utf-8",
    )

    issues = _validate_consumer_ids_in_ledger(tmp_path, "report_index")

    assert issues == []
    synthetic_map = json.loads(
        (tmp_path / "_id_ledger_synthetic_map.json").read_text(encoding="utf-8")
    )
    trace_ids = {t["id"] for t in synthetic_map["traces"]}
    assert {"EN-01", "ST-2", "VS-1"} <= trace_ids


def test_p25_backstop_still_flags_untraceable_synthetic_ids(tmp_path):
    id_ledger_register(
        tmp_path, finding_id="GRP-01", owner_phase="chain_agent1",
        owner_attempt=1, owning_artifact="hypotheses.md", title="t",
    )
    (tmp_path / "report_index.md").write_text(
        "| H-01 | Title | High | ... | DCI-404 |\n", encoding="utf-8",
    )

    issues = _validate_consumer_ids_in_ledger(tmp_path, "report_index")

    assert len(issues) == 1
    assert "DCI-404" in issues[0]


def test_p25_backstop_does_not_synthetic_accept_ledger_owned_chain_ids(tmp_path):
    id_ledger_register(
        tmp_path, finding_id="GRP-01", owner_phase="chain",
        owner_attempt=1, owning_artifact="hypotheses.md", title="registered",
    )
    (tmp_path / "hypotheses.md").write_text(
        "### HM-99 - stale unregistered hypothesis\n", encoding="utf-8",
    )
    (tmp_path / "report_index.md").write_text(
        "| H-01 | Title | High | ... | HM-99 |\n", encoding="utf-8",
    )

    issues = _validate_consumer_ids_in_ledger(tmp_path, "report_index")

    assert len(issues) == 1
    assert "HM-99" in issues[0]
