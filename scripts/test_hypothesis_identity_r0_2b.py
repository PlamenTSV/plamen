"""R0-2b: one hypothesis-ID grammar and lossless split identity flow."""
from __future__ import annotations

from pathlib import Path

import plamen_driver as D
import plamen_parsers as P
import plamen_validators as V


MAPPING_HEADER = (
    "| Finding | Hypothesis ID | Mapping Status |\n"
    "|---------|---------------|----------------|\n"
)


def _split_mapping() -> str:
    return MAPPING_HEADER + (
        "| INV-041 | GRP-022A | ABSORBED_DEDUP (SPLIT from H-22) |\n"
        "| INV-042 | GRP-022A | PRIMARY (SPLIT from H-22, anti-absorption) |\n"
        "| INV-116 | GRP-022B | PRIMARY (SPLIT from H-22; prior H-65) |\n"
        "| INV-239 | GRP-022A | ABSORBED_DEDUP (SPLIT from H-22; mentions H-999) |\n"
    )


def _spectra_mapping_excerpt() -> str:
    """The two typed table shapes emitted in the real Spectra artifact."""
    return _split_mapping() + (
        "\n| Source ID | Hypothesis ID(s) |\n"
        "|-----------|------------------|\n"
        "| DS-1 | GRP-022A, GRP-052A, H-190 |\n"
        "| DS-4 | GRP-022B |\n"
        "| SGI-2 | GRP-052A |\n"
    )


def _write_queue(path: Path, ids: list[str]) -> None:
    lines = [
        "| Queue # | Finding ID | Severity | Title | PoC Class |",
        "|---------|------------|----------|-------|-----------|",
    ]
    lines.extend(
        f"| {i} | {fid} | Low | title {i} | structural |"
        for i, fid in enumerate(ids, 1)
    )
    (path / "verification_queue.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def test_canonical_grammar_accepts_current_forms_and_suffix_splits():
    accepted = (
        "H-22", "H-C01", "HC-01", "HH-02", "HM-03", "HL-04", "HI-05",
        "CH-6", "L1-H-12", "GRP-022", "GRP-022A", "grp-022b",
        # Backward-compatible legacy hypothesis/report forms already accepted
        # by the pipeline before R0-2b.
        "CC-7", "F-8", "C-01", "M-02", "L-03", "I-04",
    )
    assert all(P.is_hypothesis_id(fid) for fid in accepted)
    assert P.extract_hypothesis_ids(
        "join GRP-022a / H-22, then L1-H-12"
    ) == ["GRP-022A", "H-22", "L1-H-12"]


def test_canonical_grammar_rejects_prefix_and_non_ascii_token_boundaries():
    rejected = (
        "XGRP-022A", "GRP-022AB", "GRP-022A_more", "GRP-022A-more",
        "H-22extra", "H-22_more", "L1-H-12-tail",
    )
    assert all(not P.is_hypothesis_id(fid) for fid in rejected)
    assert P.extract_hypothesis_ids(" ".join(rejected)) == []


def test_split_aliases_own_constituents_parent_is_union_only(tmp_path):
    (tmp_path / "finding_mapping.md").write_text(
        _split_mapping(), encoding="utf-8"
    )
    mapping = P._parse_hypothesis_constituents(tmp_path)

    assert mapping["GRP-022A"] == ["INV-041", "INV-042", "INV-239"]
    assert mapping["GRP-022B"] == ["INV-116"]
    assert "H-22" not in mapping
    assert "H-999" not in mapping

    lookup_mapping = P._parse_hypothesis_constituents(
        tmp_path, include_split_parent_aliases=True
    )
    assert lookup_mapping["H-22"] == [
        "INV-041", "INV-042", "INV-239", "INV-116",
    ]


def test_actual_spectra_tables_parse_plural_header_and_all_targets():
    rows = P.parse_finding_mapping_rows(_spectra_mapping_excerpt())
    ds1 = next(row for row in rows if row["source_ids"] == ("DS-1",))
    assert ds1["hypothesis_ids"] == ("GRP-022A", "GRP-052A", "H-190")
    assert any(row["source_ids"] == ("DS-4",) for row in rows)
    assert any(row["source_ids"] == ("SGI-2",) for row in rows)


def test_headerless_mapping_degrades_loud_without_inventing_edges(tmp_path):
    mapping_path = tmp_path / "finding_mapping.md"
    mapping_path.write_text(
        "# Finding Mapping\n\n| INV-001 | H-5 | PRIMARY |\n",
        encoding="utf-8",
    )
    assert P._parse_hypothesis_constituents(tmp_path) == {}
    sentinel = tmp_path / "finding_mapping_parse.degraded"
    assert sentinel.exists()
    assert "DEGRADED_UNTYPED_MAPPING" in sentinel.read_text(encoding="utf-8")

    mapping_path.write_text(
        "| Finding ID | Hypothesis ID | Mapping Status |\n"
        "|------------|---------------|----------------|\n"
        "| INV-001 | H-5 | PRIMARY |\n",
        encoding="utf-8",
    )
    assert P._parse_hypothesis_constituents(tmp_path) == {"H-5": ["INV-001"]}
    assert not sentinel.exists()


def test_typed_mapping_rejects_prose_target_loudly_without_inventing_edge(tmp_path):
    (tmp_path / "finding_mapping.md").write_text(
        "| Finding ID | Hypothesis ID | Mapping Status |\n"
        "|------------|---------------|----------------|\n"
        "| INV-001 | H-5 (primary) | PRIMARY |\n",
        encoding="utf-8",
    )

    assert P._parse_hypothesis_constituents(tmp_path) == {}
    sentinel = tmp_path / "finding_mapping_parse.degraded"
    assert sentinel.exists()
    assert "rejected data rows: 1" in sentinel.read_text(encoding="utf-8")


def test_typed_mapping_rejects_prose_source_loudly_without_inventing_edge(tmp_path):
    (tmp_path / "finding_mapping.md").write_text(
        "| Finding ID | Hypothesis ID | Mapping Status |\n"
        "|------------|---------------|----------------|\n"
        "| finding INV-001 | H-5 | PRIMARY |\n",
        encoding="utf-8",
    )

    assert P._parse_hypothesis_constituents(tmp_path) == {}
    sentinel = tmp_path / "finding_mapping_parse.degraded"
    assert sentinel.exists()
    assert "rejected data rows: 1" in sentinel.read_text(encoding="utf-8")


def test_partial_typed_mapping_reports_each_rejected_row_and_keeps_valid_edge(tmp_path):
    (tmp_path / "finding_mapping.md").write_text(
        "| Finding ID | Hypothesis ID | Mapping Status |\n"
        "|------------|---------------|----------------|\n"
        "| INV-001 | H-5 | PRIMARY |\n"
        "| INV-002 | H-6 (split) | SPLIT |\n",
        encoding="utf-8",
    )

    assert P._parse_hypothesis_constituents(tmp_path) == {"H-5": ["INV-001"]}
    sentinel = tmp_path / "finding_mapping_parse.degraded"
    assert sentinel.exists()
    assert "rejected data rows: 1" in sentinel.read_text(encoding="utf-8")


def test_split_parent_parser_uses_only_explicit_relation_clause():
    assert P.parse_split_parent_hypothesis_id(
        "PRIMARY (SPLIT from H-22; prior H-65)"
    ) == "H-22"
    assert P.parse_split_parent_hypothesis_id(
        "PRIMARY (related to H-22; prior H-65)"
    ) == ""
    assert P.parse_split_parent_hypothesis_id(
        "SPLIT from H-22; SPLIT from H-23"
    ) == ""


def test_split_parent_union_does_not_steal_queue_identity(tmp_path):
    _write_queue(tmp_path, ["INV-041", "INV-042", "INV-116", "INV-239"])
    (tmp_path / "finding_mapping.md").write_text(
        _split_mapping(), encoding="utf-8"
    )
    (tmp_path / "hypotheses.md").write_text("# Hypotheses\n", encoding="utf-8")

    assert P._dedup_queue_by_hypothesis(tmp_path) == 2
    rows = P.parse_verification_queue_rows(tmp_path)
    assert {row["finding id"] for row in rows} == {"GRP-022A", "GRP-022B"}


def test_one_source_schedules_every_active_hypothesis_target(tmp_path):
    _write_queue(tmp_path, ["DS-1"])
    (tmp_path / "finding_mapping.md").write_text(
        "| Source ID | Hypothesis ID(s) |\n"
        "|-----------|------------------|\n"
        "| DS-1 | GRP-022A, GRP-052A, H-190 |\n",
        encoding="utf-8",
    )

    P._dedup_queue_by_hypothesis(tmp_path)
    rows = P.parse_verification_queue_rows(tmp_path)
    assert {row["finding id"] for row in rows} == {
        "GRP-022A", "GRP-052A", "H-190",
    }


def test_stale_split_parent_in_hypotheses_cannot_reenter_active_mapping(tmp_path):
    (tmp_path / "finding_mapping.md").write_text(
        _split_mapping(), encoding="utf-8"
    )
    (tmp_path / "hypotheses.md").write_text(
        "### H-22: stale pre-split parent\n\n"
        "Constituents: INV-041, INV-042, INV-116, INV-239\n",
        encoding="utf-8",
    )

    active = P._parse_hypothesis_constituents(tmp_path)
    lookup = P._parse_hypothesis_constituents(
        tmp_path, include_split_parent_aliases=True
    )
    assert "H-22" not in active
    assert lookup["H-22"] == ["INV-041", "INV-042", "INV-239", "INV-116"]


def test_parent_lookup_union_is_derived_from_complete_split_children(tmp_path):
    (tmp_path / "finding_mapping.md").write_text(
        _split_mapping()
        + "\n| Source ID | Hypothesis ID(s) |\n"
        "|-----------|------------------|\n"
        "| DS-1 | GRP-022A |\n"
        "| SGI-2 | GRP-022B |\n",
        encoding="utf-8",
    )

    lookup = P._parse_hypothesis_constituents(
        tmp_path, include_split_parent_aliases=True
    )
    assert lookup["H-22"] == [
        "INV-041", "INV-042", "INV-239", "DS-1", "INV-116", "SGI-2",
    ]


def test_suffix_split_ids_are_exact_chain_owned_ledger_mints(tmp_path):
    """Policy: suffix IDs are exact chain-owned IDs, never rewritten to parent.

    They remain outside the numeric base allocator, so registering 022A/B does
    not consume or reinterpret a future ordinary GRP-NN allocation.
    """
    (tmp_path / "hypotheses.md").write_text(
        "### GRP-022A: first split\n\n### GRP-022B: second split\n",
        encoding="utf-8",
    )
    assert V._validate_id_ledger_collisions(tmp_path, "chain", attempt=1) == []
    for fid in ("GRP-022A", "GRP-022B"):
        record = P.id_ledger_lookup(tmp_path, fid)
        assert record is not None
        assert record["id"] == fid
        assert record["owner_phase"] == "chain"
    assert P.id_ledger_next_available(tmp_path, "GRP-") == "GRP-01"

    # Registered split references are valid consumers. A sibling not minted by
    # chain remains a reference hole even if it appears in report_index itself.
    (tmp_path / "report_index.md").write_text(
        "| Report ID | Internal Hypothesis |\n"
        "|-----------|---------------------|\n"
        "| H-01 | GRP-022A |\n"
        "| H-02 | GRP-023A |\n",
        encoding="utf-8",
    )
    issues = V._validate_consumer_ids_in_ledger(tmp_path, "report_index")
    assert len(issues) == 1 and "GRP-023A" in issues[0]
    assert "GRP-022A" not in issues[0]


def test_chain_ledger_ignores_chain_agent2_rows_appended_to_hypotheses(tmp_path):
    P.id_ledger_register(
        tmp_path,
        finding_id="CH-01",
        owner_phase="chain_agent2",
        owner_attempt=1,
        owning_artifact="chain_hypotheses.md",
        title="GRP-022A + HC-01",
    )
    (tmp_path / "hypotheses.md").write_text(
        "### GRP-022A: split family\n\n"
        "| Hypothesis ID | Severity | Source Findings |\n"
        "|---------------|----------|-----------------|\n"
        "| CH-01 | High | GRP-022A, HC-01 |\n",
        encoding="utf-8",
    )

    assert V._validate_id_ledger_collisions(tmp_path, "chain", attempt=1) == []
    record = P.id_ledger_lookup(tmp_path, "CH-01")
    assert record is not None and record["owner_phase"] == "chain_agent2"


def test_chain_agent2_content_key_uses_full_upstream_identity_grammar():
    pairs = V._parse_chain_agent2_id_title_pairs(
        "| Chain ID | Severity | Sources |\n"
        "|----------|----------|---------|\n"
        "| CH-01 | High | GRP-022A + HC-01 + H-C02 + L1-H-12 |\n"
    )
    assert pairs == [("CH-01", "GRP-022A + HC-01 + H-C02 + L1-H-12")]


def test_validator_title_parser_and_report_rewriter_use_canonical_grammar():
    pairs = V._parse_hypothesis_id_title_pairs(
        "### Finding [GRP-022A]: first split\n"
        "| GRP-022B | Low | second split | INV-116 |\n"
    )
    assert pairs == [
        ("GRP-022A", "first split"),
        ("GRP-022B", "second split"),
    ]

    rewritten, count = V._rewrite_public_report_references(
        "See GRP-022A for the same mechanism.",
        {"GRP-022A": "H-01"},
        {"H-01"},
    )
    assert count == 1 and "See H-01" in rewritten


def test_driver_seed_preserves_exact_split_provenance_without_parent_alias(tmp_path):
    (tmp_path / "finding_mapping.md").write_text(
        _spectra_mapping_excerpt(), encoding="utf-8"
    )
    D._write_report_index_coverage_seed(tmp_path)
    seed = (tmp_path / "report_index_coverage_seed.md").read_text(encoding="utf-8")

    for fid in (
        "INV-041", "INV-042", "INV-116", "INV-239", "DS-1",
        "GRP-022A", "GRP-022B", "GRP-052A", "H-190",
    ):
        assert fid in seed
    assert "| H-22 |" not in seed
    assert "| INV-041 |" in seed and "| GRP-022A |" in seed
    assert (
        "| DS-1 |  |  | GRP-022A, GRP-052A, H-190 |" in seed
    )


def test_driver_dedup_propagation_keeps_exact_split_chain_identity(tmp_path):
    (tmp_path / "finding_mapping.md").write_text(
        _split_mapping(), encoding="utf-8"
    )
    (tmp_path / "dedup_decisions.md").write_text(
        "| Absorbed ID | Decision | Coupled Mechanism |\n"
        "|-------------|----------|-------------------|\n"
        "| INV-040 | MERGED into INV-041 | same root cause |\n",
        encoding="utf-8",
    )

    assert D._propagate_dedup_absorbed_to_finding_mapping(tmp_path) == 1
    assert D._propagate_dedup_absorbed_to_finding_mapping(tmp_path) == 0
    mapping_text = (tmp_path / "finding_mapping.md").read_text(encoding="utf-8")
    assert "| INV-040 | GRP-022A | DEDUP_ABSORBED |" in mapping_text
    assert "| INV-040 | H-22 |" not in mapping_text
    parsed = P._parse_hypothesis_constituents(tmp_path)
    assert parsed["GRP-022A"].count("INV-040") == 1


def test_dedup_propagation_preserves_all_survivor_targets(tmp_path):
    (tmp_path / "finding_mapping.md").write_text(
        "| Source ID | Hypothesis ID(s) |\n"
        "|-----------|------------------|\n"
        "| INV-041 | GRP-022A, GRP-052A, H-190 |\n",
        encoding="utf-8",
    )
    (tmp_path / "dedup_decisions.md").write_text(
        "| Absorbed ID | Decision | Coupled Mechanism |\n"
        "|-------------|----------|-------------------|\n"
        "| INV-040 | MERGED into INV-041 | same root cause |\n",
        encoding="utf-8",
    )

    assert D._propagate_dedup_absorbed_to_finding_mapping(tmp_path) == 1
    rows = P.parse_finding_mapping_rows(
        (tmp_path / "finding_mapping.md").read_text(encoding="utf-8")
    )
    propagated = next(row for row in rows if row["source_ids"] == ("INV-040",))
    assert propagated["hypothesis_ids"] == (
        "GRP-022A", "GRP-052A", "H-190",
    )


def test_unmapped_dedup_survivor_uses_idempotent_diagnostic_relation(tmp_path):
    (tmp_path / "finding_mapping.md").write_text(
        "| Finding ID | Hypothesis ID | Mapping Status |\n"
        "|------------|---------------|----------------|\n"
        "| INV-001 | H-5 | PRIMARY |\n",
        encoding="utf-8",
    )
    (tmp_path / "dedup_decisions.md").write_text(
        "| INV-098 | MERGED into INV-099 | coupled | n |\n",
        encoding="utf-8",
    )

    assert D._propagate_dedup_absorbed_to_finding_mapping(tmp_path) == 1
    assert D._propagate_dedup_absorbed_to_finding_mapping(tmp_path) == 0
    text = (tmp_path / "finding_mapping.md").read_text(encoding="utf-8")
    assert text.count("| INV-098 | INV-099 | DEDUP_UNMAPPED_SURVIVOR |") == 1


def test_unmapped_dedup_diagnostic_upgrades_when_survivor_later_maps(tmp_path):
    mapping_path = tmp_path / "finding_mapping.md"
    mapping_path.write_text(
        "| Finding ID | Hypothesis ID | Mapping Status |\n"
        "|------------|---------------|----------------|\n"
        "| INV-001 | H-5 | PRIMARY |\n",
        encoding="utf-8",
    )
    (tmp_path / "dedup_decisions.md").write_text(
        "| INV-098 | MERGED into INV-099 | coupled | n |\n",
        encoding="utf-8",
    )
    assert D._propagate_dedup_absorbed_to_finding_mapping(tmp_path) == 1

    mapping_path.write_text(
        mapping_path.read_text(encoding="utf-8")
        + "\n| Source ID | Hypothesis ID(s) |\n"
        "|-----------|------------------|\n"
        "| INV-099 | GRP-099A, H-190 |\n",
        encoding="utf-8",
    )
    assert D._propagate_dedup_absorbed_to_finding_mapping(tmp_path) == 1
    assert D._propagate_dedup_absorbed_to_finding_mapping(tmp_path) == 0

    text = mapping_path.read_text(encoding="utf-8")
    rows = P.parse_finding_mapping_rows(text)
    upgraded = next(row for row in rows if row["source_ids"] == ("INV-098",))
    assert upgraded["hypothesis_ids"] == ("GRP-099A", "H-190")
    assert "| INV-098 | INV-099 | DEDUP_DIAGNOSTIC_RESOLVED |" in text
    assert text.count("| INV-098 | GRP-099A, H-190 | DEDUP_ABSORBED |") == 1


def test_retry_hint_and_report_privacy_use_canonical_policy():
    hint_ids = {
        match.group(0).upper()
        for match in D._VERIFY_HINT_ID_RE.finditer(
            "retry GRP-022A, HC-01, H-C02, L1-H-12"
        )
    }
    assert hint_ids == {"GRP-022A", "HC-01", "H-C02", "L1-H-12"}

    assert P.is_public_report_id("H-22")
    assert P.is_public_report_id("M-1")
    assert not P.is_public_report_id("H-1")
    assert not P.is_public_report_id("H-123")
    assert V._report_internal_hypothesis_ids(
        "H-1 H-22 H-123 GRP-022A M-1"
    ) == ["H-1", "H-123", "GRP-022A"]


def test_report_privacy_uses_internal_and_public_membership_for_ambiguous_h_ids():
    assert V._report_internal_hypothesis_ids(
        "H-22 H-23 H-123",
        internal_hypothesis_ids={"H-22", "H-123"},
        public_report_ids={"H-23"},
    ) == ["H-22", "H-123"]


def test_consumer_ledger_enforces_unregistered_internal_h_forms(tmp_path):
    P.id_ledger_register(
        tmp_path,
        finding_id="GRP-01",
        owner_phase="chain",
        owner_attempt=1,
        owning_artifact="hypotheses.md",
        title="registered baseline",
    )
    (tmp_path / "verification_queue.md").write_text(
        "| Queue # | Finding ID | Severity | Title |\n"
        "|---------|------------|----------|-------|\n"
        "| 1 | H-1 | High | internal one digit |\n"
        "| 2 | H-22 | High | ambiguous internal |\n"
        "| 3 | H-123 | High | internal three digit |\n",
        encoding="utf-8",
    )
    issues = V._validate_consumer_ids_in_ledger(tmp_path, "sc_verify_queue")
    assert len(issues) == 1
    for fid in ("H-1", "H-22", "H-123"):
        assert fid in issues[0]


def test_fresh_audit_empty_ledger_does_not_skip_internal_h_enforcement(tmp_path):
    (tmp_path / "_audit_started_with_markers.json").write_text(
        "{}", encoding="utf-8"
    )
    _write_queue(tmp_path, ["H-1", "H-22", "H-123"])
    issues = V._validate_consumer_ids_in_ledger(tmp_path, "sc_verify_queue")
    assert len(issues) == 1
    for fid in ("H-1", "H-22", "H-123"):
        assert fid in issues[0]


def test_consumer_ledger_accepts_registered_internal_h_and_report_column_h(tmp_path):
    for fid in ("GRP-01", "H-22"):
        P.id_ledger_register(
            tmp_path,
            finding_id=fid,
            owner_phase="chain",
            owner_attempt=1,
            owning_artifact="hypotheses.md",
            title=f"registered {fid}",
        )
    (tmp_path / "report_index.md").write_text(
        "## Master Finding Index\n"
        "| Report ID | Title | Severity | Internal Hypothesis |\n"
        "|-----------|-------|----------|---------------------|\n"
        "| H-01 | public report id | High | H-22 |\n",
        encoding="utf-8",
    )
    assert V._validate_consumer_ids_in_ledger(tmp_path, "report_index") == []


def test_quality_gate_flags_undefined_two_digit_h_as_internal_leak(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir()
    (project / "AUDIT_REPORT.md").write_text(
        "# Audit Report\n\n"
        "## Summary\n| Severity | Count |\n|---|---:|\n| High | 1 |\n\n"
        "## High Findings\n"
        "### [H-01] Defined client finding\n"
        "**Severity**: High\n"
        "**Location**: src/F.sol:1\n"
        "**Description**: See H-22 for related internal analysis. This section "
        "contains enough substantive client-facing explanation to avoid the "
        "thin-section guard while reproducing the ambiguous identifier leak.\n"
        "**Impact**: Funds can be affected under the described condition.\n"
        "**PoC Result**: Code trace reviewed.\n"
        "**Recommendation**: Apply validation before state mutation.\n",
        encoding="utf-8",
    )
    (scratchpad / "report_index.md").write_text(
        "## Master Finding Index\n"
        "| Report ID | Title | Severity | Internal Hypothesis |\n"
        "|-----------|-------|----------|---------------------|\n"
        "| H-01 | Defined client finding | High | INV-001 |\n",
        encoding="utf-8",
    )

    issues = V._run_report_quality_gate(scratchpad, str(project))
    assert any("internal IDs leaked" in issue and "H-22" in issue for issue in issues)


def test_legacy_group_envelope_is_deprecated_structured_input_only(tmp_path):
    text = (
        "| Source ID | Hypothesis ID(s) |\n"
        "|-----------|------------------|\n"
        "| INV-001 | GRP-M-001 |\n"
    )
    rows = P.parse_finding_mapping_rows(text)
    assert rows[0]["hypothesis_ids"] == ("M-001",)
    (tmp_path / "finding_mapping.md").write_text(text, encoding="utf-8")
    assert P._parse_hypothesis_constituents(tmp_path) == {"M-001": ["INV-001"]}
    assert not P.is_hypothesis_id("GRP-M-001")


def test_r10_parent_join_fire_set_is_unchanged(tmp_path):
    """R0-2b changes identity parsing, not the pre-R10.1 gate verdict set."""
    from test_r10_demotion_gate import (
        _inventory, _queue, _research_stub, _scratch, _verify,
    )

    sp = _scratch(tmp_path)
    _queue(sp, [("H-22", "Low", "structural")])
    blocks: list[str] = []
    for fid, verdict in (
        ("INV-041", "CONFIRMED"),
        ("INV-042", "REFUTED"),
        ("INV-116", "REFUTED"),
        ("INV-239", "REFUTED"),
    ):
        _inventory(sp, fid, verdict=verdict, severity="Low", ext_tag=True)
        blocks.append((sp / "findings_inventory.md").read_text(encoding="utf-8"))
    (sp / "findings_inventory.md").write_text("".join(blocks), encoding="utf-8")
    _verify(sp, "H-22", verdict="CONTESTED", severity="Low")
    (sp / "finding_mapping.md").write_text(_split_mapping(), encoding="utf-8")
    (sp / "hypotheses.md").write_text("# Hypotheses\n", encoding="utf-8")
    _research_stub(sp)

    fired = V._apply_external_assumption_undemotions(sp, "thorough")
    assert {row["finding_id"] for row in fired} == {"H-22"}
