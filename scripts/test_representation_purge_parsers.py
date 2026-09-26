"""Representation-purge regression suite for the parser/authority layer.

Every test here is one of exactly two kinds:

* METAMORPHIC — a presentation-only mutation of REAL worker bytes must not
  change the verdict. Each mutation kind listed here was MEASURED to flip its
  gate before the migration (DODO run48 / run47 / run46 worker artifacts).
* ADVERSARIAL CONTROL — a mutation that really does change MEANING must still
  be rejected. A fix that accepts everything is worse than the bug it replaces.

The bytes in `_RUN48_DEPTH_BLOCK` are copied verbatim from
`.worker_transactions/depth/worker.depth-token-flow/.../
depth_token_flow_findings.md` (run48). They are pasted, never read at runtime.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import artifact_surface  # noqa: E402
import plamen_parsers as P  # noqa: E402


# --------------------------------------------------------------------------
# Real run48 worker bytes (pasted; never read from disk at runtime)
# --------------------------------------------------------------------------

_RUN48_HEADER = (
    "<!-- PLAMEN_DISPATCH_PHASE: depth -->\n"
    "<!-- PLAMEN_DISPATCH_WORKER: depth-token-flow -->\n"
    "<!-- PLAMEN_ARTIFACT: depth_token_flow_findings.md -->\n"
    "<!-- PLAMEN_OWNER: depth-token-flow -->\n"
    "<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
    "<!-- PLAMEN_PHASE: depth -->\n"
    "<!-- PLAMEN_VERSION: 1 -->\n"
)

_RUN48_DEPTH_BLOCK = (
    "### Finding [DT-3]: `GatewayTransferNative.onCall` pays the platform fee "
    "out of reserves\n"
    "\n"
    "**Source**: INV-030, INV-031, INV-032\n"
    "**Verdict**: CONFIRMED\n"
    "**Step Execution**: ✓1,2,3,4,5,6\n"
    "**Rules Applied**: [R4:✓, R5:✗(single fee parameter), R10:✓]\n"
    "**Preferred Tag**: CODE-TRACE\n"
    "**Severity**: High\n"
    "**Location**: `contracts/GatewayTransferNative.sol:L370` (fee taken)\n"
    "\n"
    "**Description**\n"
    "Three call sites invoke `_handleFeeTransfer`. Two decrement `amount`; "
    "one does not.\n"
    "\n"
    "**Impact**: the contract pays out amount + fee for an inflow of amount.\n"
    "**Material Harm**: depositors lose 0.5% of every cross-token message.\n"
    "**Evidence**: `contracts/GatewayTransferNative.sol:L370-L403`\n"
)

_RUN48_ARTIFACT = (
    _RUN48_HEADER
    + "\n# DEPTH ANALYSIS: Token Flow\n\n"
    + _RUN48_DEPTH_BLOCK
    + "\n<!-- PLAMEN_STATUS: COMPLETE -->\n"
)


def _write(text: str, name: str = "depth_token_flow_findings.md") -> Path:
    path = Path(tempfile.mkdtemp()) / name
    path.write_text(text, encoding="utf-8")
    return path


# ==========================================================================
# GATE: is_artifact_complete / _extract_artifact_status / marker reading
# Property: completion.status_marker -> DEBT
# ==========================================================================

_COMPLETE_MARKER = "<!-- PLAMEN_STATUS: COMPLETE -->"


@pytest.mark.parametrize(
    "spelling",
    (
        "<!-- PLAMEN_STATUS: COMPLETE -->",              # baseline
        "<!--PLAMEN_STATUS:COMPLETE-->",                 # no padding
        "**PLAMEN_STATUS: COMPLETE**",                   # bolded
        "PLAMEN_STATUS: COMPLETE",                       # bare
        "<!-- PLAMEN_STATUS: Complete -->",              # casing
        "<!-- PLAMEN_STATUS: COMPLETED -->",             # tense
        "<!-- PLAMEN_STATUS: COMPLETE. -->",             # trailing period
        "<!-- PLAMEN_STATUS: DONE -->",                  # synonym
        "- <!-- PLAMEN_STATUS: COMPLETE -->",            # list item
        "    <!-- PLAMEN_STATUS: COMPLETE -->",          # indented
    ),
)
def test_metamorphic_completion_marker_spellings(spelling: str) -> None:
    """METAMORPHIC: every one of these flipped the gate to IN_PROGRESS, and the
    driver then waited on a worker that had already exited."""
    path = _write(_RUN48_ARTIFACT.replace(_COMPLETE_MARKER, spelling))
    assert P.is_artifact_complete(path, 1) is True, spelling


def test_adversarial_fenced_only_status_does_not_assert_completion() -> None:
    """A quoted example cannot establish the worker's lifecycle state.

    Adding a balanced fence changes assertion into quotation, so this is a
    semantic control, not a presentation-only metamorphic mutation.
    """
    body = _RUN48_ARTIFACT.replace(
        "<!-- PLAMEN_STATUS: IN_PROGRESS -->\n", ""
    ).replace(_COMPLETE_MARKER, "```\n" + _COMPLETE_MARKER + "\n```")
    assert P.is_artifact_complete(_write(body), 1) is False


@pytest.mark.parametrize(
    "status",
    ("IN_PROGRESS", "INCOMPLETE", "NOT_COMPLETE", "FAILED", "PENDING"),
)
def test_adversarial_non_complete_statuses_still_block(status: str) -> None:
    """ADVERSARIAL CONTROL: tolerating SPELLINGS must not tolerate MEANINGS."""
    path = _write(
        _RUN48_ARTIFACT.replace(_COMPLETE_MARKER, f"<!-- PLAMEN_STATUS: {status} -->")
    )
    assert P.is_artifact_complete(path, 1) is False, status


def test_adversarial_prose_mention_of_the_marker_is_not_authority() -> None:
    """ADVERSARIAL CONTROL: the run48 'structured evidence ignored' family in
    reverse — a sentence that NAMES the marker is a MENTION, never a claim."""
    path = _write(
        _RUN48_HEADER
        + "\nI will end with `<!-- PLAMEN_STATUS: COMPLETE -->` when done, "
        "but I am NOT done.\n"
    )
    assert P.is_artifact_complete(path, 1) is False


def test_adversarial_fenced_example_cannot_mask_a_real_in_progress() -> None:
    """ADVERSARIAL CONTROL: an asserted marker OUTSIDE a fence wins per key."""
    path = _write(
        "# Doc\n\nContract example:\n```\n"
        + _COMPLETE_MARKER
        + "\n```\n\n<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
    )
    assert P.is_artifact_complete(path, 1) is False


def test_marker_values_are_preserved_verbatim_for_ownership_checks() -> None:
    """Ownership validation compares PLAMEN_ARTIFACT/OWNER verbatim."""
    markers = P._extract_artifact_status(_write(_RUN48_ARTIFACT))
    assert markers["ARTIFACT"] == "depth_token_flow_findings.md"
    assert markers["OWNER"] == "depth-token-flow"
    assert markers["STATUS"] == "COMPLETE"


# ==========================================================================
# GATE: _artifact_has_findings / _findings_section_has_body
# Property: completion.artifact_carries_analysis -> DEBT
# ==========================================================================


@pytest.mark.parametrize(
    "heading",
    (
        "### Finding [DT-3]: title",
        "## Finding [DT-3]: title",
        "#### Finding [DT-3]: title",
        "### Issue [DT-3]: title",
        "### Candidate [DT-3]: title",
        "### Finding DT-3: title",
        "### [DT-3] title",
        "### **Finding [DT-3]**: title",
        "### Finding `DT-3`: title",
    ),
)
def test_metamorphic_finding_block_heading_spellings(heading: str) -> None:
    """METAMORPHIC: identical analysis, different heading spelling."""
    text = f"# Doc\n\n{heading}\n\nDetails of the bug here, at length.\n"
    assert P._artifact_has_findings(text) is True, heading


def test_metamorphic_results_section_with_a_real_body_counts() -> None:
    text = "## Results\n\nNo exploitable issues; reviewed every setter and the math.\n"
    assert P._artifact_has_findings(text) is True


def test_adversarial_bare_section_shell_is_still_empty() -> None:
    """ADVERSARIAL CONTROL: a heading with nothing under it is not analysis."""
    assert P._artifact_has_findings("# Title\n\n## Findings\n") is False
    assert P._artifact_has_findings("## Findings") is False


def test_adversarial_crash_safety_stub_is_still_empty() -> None:
    stub = "# Core State\n\n## Findings\n\n(findings appended below as they are discovered)\n"
    assert P._findings_section_has_body(stub) is False


def test_metamorphic_analysis_quoting_a_placeholder_word_is_not_a_stub() -> None:
    """METAMORPHIC: the placeholder regex's `[^)\\n]*` tail used to eat the
    rest of the line, so real analysis DISCUSSING a placeholder bug measured as
    an empty stub."""
    body = (
        "## Findings\n\nThis placeholder discussion is about a real placeholder "
        "bug in the code: the initializer leaves a placeholder address that any "
        "caller can claim, so the first caller seizes the admin role.\n"
    )
    assert P._findings_section_has_body(body) is True


# ==========================================================================
# GATE: _structural_completeness_ok / structural_completeness_result
# THE CALL SITE THAT DECIDES DISCARD.
# ==========================================================================


def test_run48_depth_artifact_is_not_discarded() -> None:
    result = P.structural_completeness_result(
        _write(_RUN48_ARTIFACT), required_headings=()
    )
    assert result.should_discard is False, result.render()


@pytest.mark.parametrize(
    "mutate",
    (
        lambda t: t.replace("### Finding [DT-3]", "#### Finding [DT-3]"),
        lambda t: t.replace("### Finding [DT-3]", "### Issue [DT-3]"),
        lambda t: t.replace("**Verdict**: CONFIRMED", "- **Verdict**: CONFIRMED"),
        lambda t: t.replace("**Severity**: High", "**Severity:** High"),
        lambda t: t.replace("**Severity**: High", "**Severity**: high"),
        lambda t: t.replace("\n", "\r\n"),
        lambda t: t.replace("**Material Harm**:", "**Material Harm** (MANDATORY):"),
    ),
)
def test_metamorphic_presentation_mutations_never_discard(mutate) -> None:
    """METAMORPHIC: the verdict must be UNCHANGED under every mutation kind
    that was measured to flip this gate."""
    result = P.structural_completeness_result(
        _write(mutate(_RUN48_ARTIFACT)), required_headings=()
    )
    assert result.should_discard is False, result.render()


def test_required_heading_level_drift_is_debt_not_a_discard() -> None:
    text = _RUN48_ARTIFACT.replace(
        "# DEPTH ANALYSIS: Token Flow", "### Findings\n\nreal analysis body text"
    )
    result = P.structural_completeness_result(
        _write(text), required_headings=("Findings",)
    )
    assert result.should_discard is False, result.render()


def test_adversarial_genuinely_empty_artifact_still_blocks() -> None:
    """ADVERSARIAL CONTROL: an empty shell has no analysis to preserve."""
    result = P.structural_completeness_result(
        _write(_RUN48_HEADER + "\n# Doc\n\n## Methodology\n\nI read the code.\n"),
        required_headings=(),
    )
    assert result.should_discard is True
    assert any(
        d.property_violated == "completion.no_analysis_present"
        for d in result.blocking_defects
    )


def test_adversarial_missing_file_still_blocks() -> None:
    result = P.structural_completeness_result(Path(tempfile.mkdtemp()) / "nope.md")
    assert result.should_discard is True


def test_every_defect_carries_a_physical_line_and_a_repair_hint() -> None:
    """Principle 3: repair, don't reject."""
    text = _RUN48_ARTIFACT.replace(
        "### Finding [DT-3]", "## Candidate [RS1-1]"
    ).replace("**Material Harm**: depositors lose 0.5% of every cross-token message.\n", "")
    result = P.structural_completeness_result(
        _write(text, "analysis_rescan_1.md"), required_headings=()
    )
    assert result.defects
    for defect in result.defects:
        assert defect.repair_hint
        assert defect.property_violated
        assert defect.closure == artifact_surface.closure_for_property(
            defect.property_violated
        )


def test_only_the_four_closed_families_can_discard() -> None:
    """The invariant this whole migration rests on."""
    for prop in (
        "completion.status_marker",
        "completion.candidate_field_envelope",
        "completion.required_heading",
        "receipt.line_grammar",
        "graph.consumption_acknowledgement",
    ):
        assert artifact_surface.closure_for_property(prop) == artifact_surface.DEBT
    for prop in (
        "identity.candidate_producer_scope",
        "dedup.merge_decision",
        "severity.chain_upgrade_justification",
        "disposition.report_placement_proposal",
    ):
        assert artifact_surface.closure_for_property(prop) == artifact_surface.FAIL_CLOSED


# ==========================================================================
# GATE: _chain_severity_upgrade_justified
# Property: severity.chain_upgrade_justification -> FAIL_CLOSED
# ==========================================================================

_CHAIN_IMPACT = "claimants receive 15% less than their pro-rata share"
_CHAIN_BASE = (
    f"Constituents: DT-1,DT-2 | Severity-Upgrade-Justified: YES | "
    f"Combined-Impact: {_CHAIN_IMPACT}"
)


@pytest.mark.parametrize(
    "section",
    (
        _CHAIN_BASE,
        _CHAIN_BASE.replace(
            "Severity-Upgrade-Justified", "**Severity-Upgrade-Justified**"
        ),
        f"Combined-Impact: {_CHAIN_IMPACT} | Severity-Upgrade-Justified: YES "
        "| Constituents: DT-1,DT-2",
        "| Constituents | Severity-Upgrade-Justified | Combined-Impact |\n"
        "|---|---|---|\n"
        f"| DT-1,DT-2 | YES | {_CHAIN_IMPACT} |",
        f"Constituents: DT-1,DT-2 | Severity-Upgrade-Justified: `YES` | "
        f"Combined-Impact: {_CHAIN_IMPACT}",
        "- Constituents: DT-1, DT-2\n- Severity-Upgrade-Justified: YES\n"
        f"- Combined-Impact: {_CHAIN_IMPACT}",
        f"> Constituents: DT-1,DT-2 | Severity-Upgrade-Justified: YES | "
        f"Combined-Impact: {_CHAIN_IMPACT}",
    ),
)
def test_metamorphic_chain_upgrade_justification_survives_presentation(
    section: str,
) -> None:
    """METAMORPHIC: each of these returned False and force-collapsed a genuine
    compound finding into a constituent at the LOWER tier — a
    presentation-driven severity downgrade."""
    assert P._chain_severity_upgrade_justified(section) is True, section
    assert P._chain_machine_constituent_ids(section) == ["DT-1", "DT-2"]


@pytest.mark.parametrize(
    "section",
    (
        _CHAIN_BASE.replace("YES", "NO"),
        _CHAIN_BASE.replace(_CHAIN_IMPACT, "NONE"),
        _CHAIN_BASE.replace(_CHAIN_IMPACT, "N/A"),
        _CHAIN_BASE.replace(_CHAIN_IMPACT, "–"),
        _CHAIN_BASE.replace(_CHAIN_IMPACT, ""),
        "Constituents: DT-1,DT-2",
        "",
    ),
)
def test_adversarial_unjustified_chain_is_still_unjustified(section: str) -> None:
    """ADVERSARIAL CONTROL: the anti-inflation direction is unchanged."""
    assert P._chain_severity_upgrade_justified(section) is False, section


# ==========================================================================
# GATE: parse_disposition_md
# Property: disposition.report_placement_proposal -> FAIL_CLOSED
# ==========================================================================


def _disposition(rows: str) -> dict:
    root = Path(tempfile.mkdtemp())
    (root / "disposition.md").write_text(rows, encoding="utf-8")
    return P.parse_disposition_md(root)


_DISP_HEADER = "| Report ID | Disposition | Reason |\n|---|---|---|\n"


@pytest.mark.parametrize(
    "table",
    (
        _DISP_HEADER + "| L-07 | APPENDIX | hardening |\n",
        _DISP_HEADER + "| `L-07` | APPENDIX | hardening |\n",
        _DISP_HEADER + "| **L-07** | **APPENDIX** | hardening |\n",
        _DISP_HEADER + "| L-07 | Appendix-only | hardening |\n",
        "| # | Report ID | Disposition | Reason |\n|---|---|---|---|\n"
        "| 1 | L-07 | APPENDIX | hardening |\n",
        "| Report ID | Disposition | Reason | Owner |\n|---|---|---|---|\n"
        "| L-07 | APPENDIX | hardening | me |\n",
    ),
)
def test_metamorphic_disposition_rows(table: str) -> None:
    assert _disposition(table)["L-07"][0] == "APPENDIX", table


@pytest.mark.parametrize(
    "value", ("MAYBE", "BODY", "REPORTABLE", "", "appendix-ish")
)
def test_adversarial_unrecognised_disposition_defaults_to_body(value: str) -> None:
    """ADVERSARIAL CONTROL: fail-closed on disposition means the DECISION is
    conservative — an unreadable value keeps the finding in the BODY."""
    parsed = _disposition(_DISP_HEADER + f"| L-07 | {value} | hardening |\n")
    assert parsed.get("L-07", ("BODY", ""))[0] == "BODY", value


def test_adversarial_non_report_identity_is_not_a_disposition_row() -> None:
    assert _disposition(_DISP_HEADER + "| DT-7 | APPENDIX | hardening |\n") == {}


# ==========================================================================
# GATE: parse_finding_mapping_rows
# Property: identity.constituent_hypothesis_edge -> FAIL_CLOSED
# ==========================================================================


@pytest.mark.parametrize(
    "table",
    (
        "| Source Finding ID | Hypothesis ID | Status |\n|---|---|---|\n"
        "| DT-1 | H-1 | ok |\n",
        "| Agent Finding | Grouped Into |\n|---|---|\n| DT-1 | H-1 |\n",
        "| Source Finding ID | Hypothesis ID |\n| DT-1 | H-1 |\n",  # no separator
        "| **Source Finding ID** | **Hypothesis ID** |\n|---|---|\n"
        "| `DT-1` | H-1 |\n",
        "Source Finding ID | Hypothesis ID\n---|---\nDT-1 | H-1\n",  # no outer pipes
        "| # | Source Finding ID | Hypothesis ID |\n|---|---|---|\n"
        "| 1 | DT-1 | H-1 |\n",
    ),
)
def test_metamorphic_finding_mapping_edges(table: str) -> None:
    rows = P.parse_finding_mapping_rows(table)
    assert [(r["source_ids"], r["hypothesis_ids"]) for r in rows] == [
        (("DT-1",), ("H-1",))
    ], table


def test_adversarial_prose_cannot_manufacture_a_mapping_edge() -> None:
    """ADVERSARIAL CONTROL: status/Notes prose citing IDs creates no edge."""
    rows = P.parse_finding_mapping_rows(
        "| Source Finding ID | Hypothesis ID | Notes |\n|---|---|---|\n"
        "| DT-1 | H-1 | supersedes DT-9 and H-4 |\n"
    )
    assert [(r["source_ids"], r["hypothesis_ids"]) for r in rows] == [
        (("DT-1",), ("H-1",))
    ]


def test_adversarial_unknown_columns_create_no_edges() -> None:
    assert P.parse_finding_mapping_rows(
        "| Owner | Comment |\n|---|---|\n| DT-1 | H-1 |\n"
    ) == []


# ==========================================================================
# GATE: parse_inventory_shard_manifest / parse_breadth_manifest_count
# ==========================================================================


def _shard(text: str) -> list[str]:
    root = Path(tempfile.mkdtemp())
    (root / "inv.manifest.md").write_text(text, encoding="utf-8")
    return P.parse_inventory_shard_manifest(root, "inv")


@pytest.mark.parametrize(
    "table",
    (
        "| File | Role | Model |\n|---|---|---|\n"
        "| analysis_a.md | x | y |\n| analysis_b.md | x | y |\n",
        "| File | Role | Model |\n|---|---|---|\n"
        "| `analysis_a.md` | x | y |\n| analysis_b.md | x | y |\n",
        "| File | Role | Model |\n|---|---|---|\n"
        "| **analysis_a.md** | x | y |\n| analysis_b.md | x | y |\n",
        "| # | File | Role |\n|---|---|---|\n"
        "| 1 | analysis_a.md | x |\n| 2 | analysis_b.md | x |\n",
    ),
)
def test_metamorphic_shard_manifest_enumeration(table: str) -> None:
    """METAMORPHIC: bolding ONE path silently dropped that artifact from the
    shard denominator while the shard still looked populated."""
    assert _shard(table) == ["analysis_a.md", "analysis_b.md"], table


def test_adversarial_shard_manifest_without_artifacts_is_empty() -> None:
    assert _shard("| Note |\n|---|\n| nothing assigned |\n") == []


def _breadth(text: str):
    root = Path(tempfile.mkdtemp())
    (root / "spawn_manifest.md").write_text(text, encoding="utf-8")
    return P.parse_breadth_manifest_count(root)


_ROSTER = (
    "## Breadth Agents\n\n"
    "| Template | Required? | Agent ID | Focus | Status |\n"
    "|---|---|---|---|---|\n"
    "| access-control | Yes | B1 | acl | pending |\n"
    "| token-flow | Yes | B2 | tokens | pending |\n"
    "| state | Required | B3 | state | pending |\n"
)


@pytest.mark.parametrize(
    "roster",
    (
        _ROSTER,
        _ROSTER.replace("Required?", "Mandatory"),
        _ROSTER.replace("| Template |", "| Skill |"),
        _ROSTER.replace("| Template | Required? |", "| **Template** | **Required?** |"),
    ),
)
def test_metamorphic_breadth_quorum_survives_header_renames(roster: str) -> None:
    """METAMORPHIC: None made the caller fall back to the hardcoded floor —
    reopening exactly the hole this quorum exists to close."""
    assert _breadth(roster) == 3, roster


def test_adversarial_no_roster_table_returns_none() -> None:
    assert _breadth("## Breadth Agents\n\nprose only, no table\n") is None


# ==========================================================================
# GATE: classify_poc_testability / extract_unambiguous_internal_ids
# ==========================================================================


@pytest.mark.parametrize(
    "title",
    (
        "Reentrancy in withdraw",
        "Re-entrancy in withdraw",
        "Callback re-enters withdraw",
        "**Reentrancy** in withdraw",
        "`reentrancy` in withdraw",
    ),
)
def test_metamorphic_reentrancy_routes_to_property(title: str) -> None:
    """METAMORPHIC: a `unit` route mandates a single-call harness a reentrancy
    finding cannot satisfy, producing an unjustified [POC-FAIL] on a real bug."""
    assert P.classify_poc_testability("", "", title, "High") == "property", title


def test_adversarial_negated_reentrancy_does_not_route_to_property() -> None:
    assert P.classify_poc_testability(
        "", "", "no reentrancy possible here", "High"
    ) == "structural"


def test_adversarial_structural_titles_are_unchanged() -> None:
    for title in ("missing event on setter", "setter does not emit"):
        assert P.classify_poc_testability("", "", title, "Low") == "structural"


@pytest.mark.parametrize(
    "text",
    (
        "See DT-1 for details.",
        "See `DT-1` for details.",
        "See **DT-1** for details.",
        "See [DT-1] for details.",
        "See DT‑1 for details.",  # U+2011 NON-BREAKING HYPHEN
    ),
)
def test_metamorphic_internal_id_is_visible_in_every_spelling(text: str) -> None:
    assert P.extract_unambiguous_internal_ids(text) == ["DT-1"], text


def test_adversarial_ordinary_prose_is_not_an_internal_id() -> None:
    assert P.extract_unambiguous_internal_ids(
        "price-of-1 and ERC-20 and EIP-1559 and CVE-2021"
    ) == []


# ==========================================================================
# Idempotence: a gate that re-reads its own output must be stable.
# ==========================================================================


def test_normalized_view_of_the_run48_artifact_is_idempotent() -> None:
    once = artifact_surface.normalized_text(_RUN48_ARTIFACT)
    twice = artifact_surface.normalized_text(once)
    assert once == twice
