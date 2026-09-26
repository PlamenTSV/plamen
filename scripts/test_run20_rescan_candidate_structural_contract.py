"""Run20 regression: rescan Candidate proposals satisfy the structural gate."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from plamen_parsers import _structural_completeness_ok  # noqa: E402


def _proposal(*, heading: str = "## Candidate [PC2-1]: callback mismatch") -> str:
    return "\n".join(
        (
            "<!-- PLAMEN_STATUS: COMPLETE -->",
            "# GatewaySend localized rescan",
            "",
            heading,
            "",
            "**Verdict**: UNRESOLVED",
            "**Step Execution**: ✓1,2,3,4,5",
            "**Rules Applied**: [R4:✓, R5:✓]",
            "**Preferred Tag**: CODE-TRACE",
            "**Severity**: High",
            "**Location**: contracts/GatewaySend.sol:L341",
            "**Description**: Callback fields are not bound to delivery context.",
            "**Impact**: A mismatched callback may transfer retained tokens.",
            "**Material Harm**: Users may lose retained tokens.",
            "**Evidence**: contracts/GatewaySend.sol:L341-L372",
            "",
            "### Precondition Analysis",
            "The external gateway must deliver the mismatched payload.",
            "",
        )
    )


def _check(tmp_path: Path, text: str) -> tuple[bool, list[str]]:
    path = tmp_path / "analysis_percontract_GatewaySend.md"
    path.write_text(text, encoding="utf-8")
    return _structural_completeness_ok(path, required_headings=())


@pytest.mark.parametrize("marks", ("##", "###"))
def test_pc2_unresolved_candidate_proposal_passes(
    tmp_path: Path, marks: str
) -> None:
    ok, reasons = _check(
        tmp_path,
        _proposal(heading=f"{marks} Candidate [PC2-1]: callback mismatch"),
    )
    assert ok is True, reasons


# ── Representation purge (run48 bug class) ────────────────────────────────
# These cases previously DISCARDED the whole artifact. Every one of them is a
# presentation difference over the SAME proposal, so the artifact is now
# PUBLISHED and the difference is reported as repairable debt. The adversarial
# controls that must STILL block are the two tests below: a foreign producer
# identity (FAIL_CLOSED `identity.candidate_producer_scope`) and an artifact
# whose only proposal lives inside a fence (genuinely no analysis).
@pytest.mark.parametrize(
    "heading",
    (
        "## Candidate review for [PC2-1]",
        "## Candidate [PC2-1] discussed in prose",
        "#### Candidate [PC2-1]: wrong heading depth",
        "### **Candidate [PC2-1]**: bolded heading",
        "## Candidate `PC2-1`: backticked identity",
        "## Candidate PC2-1: bracket-free identity",
    ),
)
def test_heading_spelling_no_longer_discards_the_proposal(
    tmp_path: Path, heading: str
) -> None:
    ok, reasons = _check(tmp_path, _proposal(heading=heading))
    assert ok is True, reasons


def test_unreadable_candidate_identity_is_visible_debt_not_a_discard(
    tmp_path: Path,
) -> None:
    ok, reasons = _check(
        tmp_path, _proposal(heading="## Candidate [PC2/path]: malformed identity")
    )
    assert ok is True, reasons
    assert any("not an exact H2/H3" in reason for reason in reasons)


def test_candidate_role_compound_is_not_a_foreign_candidate_identity(
    tmp_path: Path,
) -> None:
    """Run57: lexical prose must not become FAIL_CLOSED producer identity."""

    path = tmp_path / "depth_state_trace_findings.md"
    path.write_text(
        "\n".join((
            "<!-- PLAMEN_STATUS: COMPLETE -->",
            "# State Trace Analysis",
            "",
            "## Candidate-negative review of state-write alerts",
            "",
            "The reviewed alerts did not add another candidate.",
            "",
            "## Finding [DST-1]: committed state can be observed stale",
            "",
            "**Verdict**: CONFIRMED",
            "**Severity**: Medium",
            "**Location**: contracts/Core.sol:L10",
            "**Description**: A callback observes stale committed state.",
            "**Impact**: The stale read can authorize a duplicate action.",
            "**Material Harm**: Users can lose the duplicated amount.",
        )),
        encoding="utf-8",
    )

    ok, reasons = _structural_completeness_ok(path, required_headings=())
    assert ok is True, reasons
    assert not any("producer grammar" in reason for reason in reasons)


def test_candidate_id_must_match_registered_rescan_producer(
    tmp_path: Path,
) -> None:
    """ADVERSARIAL CONTROL: a genuinely different identity still BLOCKS."""
    ok, reasons = _check(
        tmp_path,
        _proposal(heading="## Candidate [B1-1]: foreign producer identity"),
    )
    assert ok is False
    assert any("artifact-scoped producer grammar" in reason for reason in reasons)


def test_candidate_missing_required_field_is_debt(tmp_path: Path) -> None:
    ok, reasons = _check(
        tmp_path,
        _proposal().replace(
            "**Material Harm**: Users may lose retained tokens.\n", ""
        ),
    )
    assert ok is True
    assert any("exactly one **Material Harm**" in reason for reason in reasons)


@pytest.mark.parametrize(
    "spelling",
    (
        "**Material Harm** (MANDATORY): Users may lose retained tokens.",
        "**Material Harm (MANDATORY)**: Users may lose retained tokens.",
        "- **Material Harm**: Users may lose retained tokens.",
        "**Material Harm:** Users may lose retained tokens.",
        "`Material Harm`: Users may lose retained tokens.",
        "**Material Harm**:\n  Users may lose retained tokens.",
    ),
)
def test_material_harm_spellings_are_one_field(
    tmp_path: Path, spelling: str
) -> None:
    """METAMORPHIC: the spelling printed in the pipeline's OWN bound contract
    (rules/finding-output-format.md) must not read as a missing field."""
    ok, reasons = _check(
        tmp_path,
        _proposal().replace(
            "**Material Harm**: Users may lose retained tokens.", spelling
        ),
    )
    assert ok is True, reasons
    assert not any("Material Harm" in reason for reason in reasons), reasons


def test_candidate_nonproposal_verdict_is_debt(tmp_path: Path) -> None:
    ok, reasons = _check(
        tmp_path,
        _proposal().replace("**Verdict**: UNRESOLVED", "**Verdict**: CONFIRMED"),
    )
    assert ok is True
    assert any("Verdict must be" in reason for reason in reasons)


@pytest.mark.parametrize(
    "verdict",
    (
        "NOT_APPLICABLE_PROPOSAL.",
        "NOT_APPLICABLE_PROPOSAL: no emission",
        "REFUTATION_PROPOSAL (blocked by access control)",
        "**UNRESOLVED**",
        "unresolved",
    ),
)
def test_verdict_punctuation_does_not_change_the_enum(
    tmp_path: Path, verdict: str
) -> None:
    """METAMORPHIC: one trailing period used to collapse the nonterminal
    proposal enum onto the legacy terminal one and discard the artifact."""
    ok, reasons = _check(
        tmp_path, _proposal().replace("**Verdict**: UNRESOLVED", f"**Verdict**: {verdict}")
    )
    assert ok is True, reasons
    assert not any("Verdict must be" in reason for reason in reasons), reasons


def test_terminal_verdict_is_still_reported(tmp_path: Path) -> None:
    """ADVERSARIAL CONTROL: a genuinely terminal closure verdict is still
    flagged — tolerating punctuation must not tolerate a different MEANING."""
    ok, reasons = _check(
        tmp_path, _proposal().replace("**Verdict**: UNRESOLVED", "**Verdict**: REFUTED")
    )
    assert ok is True
    assert any("Verdict must be" in reason for reason in reasons)


@pytest.mark.parametrize("severity", ("high", "**High**", "High (Medium x High)"))
def test_severity_spelling_does_not_leave_the_enum(
    tmp_path: Path, severity: str
) -> None:
    ok, reasons = _check(
        tmp_path, _proposal().replace("**Severity**: High", f"**Severity**: {severity}")
    )
    assert ok is True, reasons
    assert not any("severity enum" in reason for reason in reasons), reasons


def test_severity_outside_the_enum_is_still_reported(tmp_path: Path) -> None:
    """ADVERSARIAL CONTROL."""
    ok, reasons = _check(
        tmp_path, _proposal().replace("**Severity**: High", "**Severity**: Catastrophic")
    )
    assert ok is True
    assert any("severity enum" in reason for reason in reasons)


def test_candidate_duplicate_verdict_is_debt(tmp_path: Path) -> None:
    ok, reasons = _check(
        tmp_path,
        _proposal().replace(
            "**Verdict**: UNRESOLVED",
            "**Verdict**: UNRESOLVED\n**Verdict**: REFUTATION_PROPOSAL",
        ),
    )
    assert ok is True
    assert any("exactly one **Verdict**" in reason for reason in reasons)


def test_valid_candidate_cannot_hide_an_invalid_sibling(tmp_path: Path) -> None:
    """The complete candidate denominator is still preserved — as debt."""
    invalid_sibling = "\n".join(
        (
            "## Candidate [PC2-2]: incomplete sibling",
            "",
            "**Verdict**: UNRESOLVED",
            "**Severity**: Medium",
        )
    )
    ok, reasons = _check(tmp_path, _proposal() + invalid_sibling)
    assert ok is True
    assert any("[PC2-2]" in reason and "exactly one" in reason for reason in reasons)


def test_fenced_candidate_example_does_not_pass(tmp_path: Path) -> None:
    """ADVERSARIAL CONTROL: an artifact whose only proposal is a fenced example
    genuinely carries no analysis and is still rejected."""
    ok, reasons = _check(tmp_path, "# Notes\n\n```markdown\n" + _proposal() + "```\n")
    assert ok is False
    assert any("empty/incomplete" in reason for reason in reasons)
