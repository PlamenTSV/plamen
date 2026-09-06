"""Red fixtures for the EIP public-standard/private-producer namespace collision.

These tests deliberately exercise the client sanitizer and the final report
privacy gate as one contract.  Lexical preservation is not sufficient when the
same spelling is still rejected by the delivery gate, and lexical redaction is
not sufficient when Markdown targets or Unicode aliases can retain the private
identity.
"""

from pathlib import Path

import pytest

import plamen_driver as D
from plamen_parsers import (
    _sanitize_client_body,
    _sanitize_client_title,
    extract_unambiguous_internal_ids,
)
from plamen_validators import _inventory_structural_source_action_referents


def _write_single_high_report(project: Path, scratch: Path, description: str) -> None:
    (project / "AUDIT_REPORT.md").write_text(
        "# Audit Report\n\n"
        "## Summary\n"
        "| Severity | Count |\n|---|---:|\n| High | 1 |\n\n"
        "## High Findings\n"
        "### [H-01] Report-safe title\n"
        "**Severity**: High\n"
        "**Location**: src/F.sol:1\n"
        f"**Description**: {description} This section contains sufficient "
        "client-facing explanation to keep the fixture independent from "
        "thin-section and structural report checks.\n"
        "**Impact**: Funds can be affected under the described condition.\n"
        "**PoC Result**: Code trace reviewed.\n"
        "**Recommendation**: Apply validation before state mutation.\n",
        encoding="utf-8",
    )
    (scratch / "report_index.md").write_text(
        "## Master Finding Index\n"
        "| Report ID | Title | Severity | Internal Hypothesis |\n"
        "|-----------|-------|----------|---------------------|\n"
        "| H-01 | Report-safe title | High | INV-001 |\n",
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    "text",
    [
        "Signature verification follows the EIP-712 standard.",
        "Behavior is defined by Ethereum Improvement Proposal EIP-1559.",
        "See https://eips.ethereum.org/EIPS/eip-20 for the specification.",
        "`EIP-712` typed-data signatures are domain-separated.",
        "**EIP-712** typed-data signatures are domain-separated.",
        "(EIP-712) typed-data semantics apply.",
        "EIP-712, the typed-data standard, applies.",
        "EIP-712 signatures are domain-separated.",
        "EIP-1559 fees use a dynamic base fee.",
        "EIP-1967 proxy slots are used.",
        "EIP-712-compatible signatures are accepted.",
        "Signature verification follows the eIp-712 standard.",
    ],
)
def test_legitimate_eip_standard_prose_survives_without_final_privacy_debt(
    text: str,
) -> None:
    sanitized = _sanitize_client_body(text)

    assert sanitized == text
    assert extract_unambiguous_internal_ids(sanitized) == []


@pytest.mark.parametrize(
    "text",
    [
        "For reference EIP-712 standard semantics apply.",
        "The standards reference EIP-1559 specification defines the fee rule.",
    ],
)
def test_generic_reference_vocabulary_does_not_override_explicit_standard_context(
    text: str,
) -> None:
    assert _sanitize_client_body(text) == text


@pytest.mark.parametrize(
    "text,private_spellings",
    [
        ("finding_id: EIP-20 standard candidate.", ("EIP-20",)),
        ("Finding-ID: EIP-20 standard candidate.", ("EIP-20",)),
        (
            "Internal IDs: INV-001, EIP-20 standard candidate.",
            ("INV-001", "EIP-20"),
        ),
        (
            "Internal IDs: INV-001/EIP-20 standard candidate.",
            ("INV-001", "EIP-20"),
        ),
    ],
)
def test_explicit_internal_namespace_wins_over_nearby_standard_vocabulary(
    text: str,
    private_spellings: tuple[str, ...],
) -> None:
    sanitized = _sanitize_client_body(text)

    for private in private_spellings:
        assert private.casefold() not in sanitized.casefold()
    assert extract_unambiguous_internal_ids(sanitized) == []


def test_legitimate_markdown_standard_link_is_preserved_and_delivery_safe() -> None:
    text = (
        "[EIP-712](https://eips.ethereum.org/EIPS/eip-712) "
        "defines the typed-data standard."
    )

    sanitized = _sanitize_client_body(text)

    assert sanitized == text
    assert extract_unambiguous_internal_ids(sanitized) == []


def test_internal_markdown_link_text_and_anchor_are_both_redacted() -> None:
    text = "[EIP-20](#finding-EIP-20) is an internal candidate."

    sanitized = _sanitize_client_body(text)

    assert "eip-20" not in sanitized.casefold()
    assert extract_unambiguous_internal_ids(sanitized) == []


def test_hyphen_adjacent_internal_eip_does_not_escape_token_boundaries() -> None:
    text = "Internal producer EIP-20-candidate was verified."

    sanitized = _sanitize_client_body(text)

    assert "eip-20" not in sanitized.casefold()
    assert extract_unambiguous_internal_ids(sanitized) == []


@pytest.mark.parametrize(
    "text,private_spelling",
    [
        ("Internal ID EIP\N{NON-BREAKING HYPHEN}20 was confirmed.", "EIP\N{NON-BREAKING HYPHEN}20"),
        ("Internal ID E\N{LATIN CAPITAL LETTER I WITH DOT ABOVE}P-20 was confirmed.", "E\N{LATIN CAPITAL LETTER I WITH DOT ABOVE}P-20"),
        ("Internal ID EIP-\N{FULLWIDTH DIGIT TWO}\N{FULLWIDTH DIGIT ZERO} was confirmed.", "EIP-\N{FULLWIDTH DIGIT TWO}\N{FULLWIDTH DIGIT ZERO}"),
    ],
)
def test_unicode_and_confusable_internal_eip_aliases_do_not_leak(
    text: str,
    private_spelling: str,
) -> None:
    sanitized = _sanitize_client_body(text)

    assert private_spelling not in sanitized
    assert "upstream finding" in sanitized


def test_unicode_dash_standard_reference_remains_public() -> None:
    text = "Signature verification follows the EIP\N{NON-BREAKING HYPHEN}712 standard."

    assert _sanitize_client_body(text) == text


@pytest.mark.parametrize(
    "title",
    [
        "EIP-712 signature replay protection is incomplete",
        "ERC-20 / EIP-20 compatibility issue",
    ],
)
def test_public_eip_standards_are_not_removed_from_client_titles(title: str) -> None:
    assert _sanitize_client_title(title) == title


@pytest.mark.parametrize(
    "description",
    [
        "Signature verification follows the EIP-712 standard.",
        "See https://eips.ethereum.org/EIPS/eip-20 for the specification.",
    ],
)
def test_final_report_privacy_gate_accepts_legitimate_eip_standards(
    tmp_path: Path,
    description: str,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    scratch = project / ".scratchpad"
    scratch.mkdir()
    _write_single_high_report(project, scratch, description)

    issues = D._run_report_quality_gate(scratch, str(project))

    assert not any("internal IDs leaked" in issue for issue in issues)
    quality = (scratch / "report_quality.md").read_text(encoding="utf-8")
    assert "| internal_id_leak | PASS |" in quality


@pytest.mark.parametrize(
    "description",
    [
        "The internal trace points to [details](#finding-EIP-20).",
        "Internal producer EIP-20-candidate was verified.",
        "Internal ID EIP\N{NON-BREAKING HYPHEN}20 was confirmed.",
    ],
)
def test_final_report_privacy_gate_catches_contextual_eip_leaks(
    tmp_path: Path,
    description: str,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    scratch = project / ".scratchpad"
    scratch.mkdir()
    _write_single_high_report(project, scratch, description)

    issues = D._run_report_quality_gate(scratch, str(project))

    assert any("internal IDs leaked" in issue for issue in issues)


def test_owned_legacy_artifact_membership_reaches_final_privacy_gate(
    tmp_path: Path,
) -> None:
    """Producer ownership, not caller luck, must supply legacy membership."""

    project = tmp_path / "project"
    project.mkdir()
    scratch = project / ".scratchpad"
    scratch.mkdir()
    (scratch / "niche_legacy_findings.md").write_text(
        "### Finding [EIP-20]: Legacy private candidate\n"
        "**Severity**: Medium\n"
        "**Location**: src/F.sol:1\n"
        "**Description**: A substantive historical candidate remains readable "
        "only through its producer-owned legacy namespace.\n",
        encoding="utf-8",
    )
    _write_single_high_report(
        project,
        scratch,
        "The trace cites EIP-20 from an upstream audit worker.",
    )

    issues = D._run_report_quality_gate(scratch, str(project))

    assert any("internal IDs leaked" in issue and "EIP-20" in issue for issue in issues)


def test_known_private_membership_does_not_reclassify_public_standard_occurrence() -> None:
    """One spelling can occur once as lineage and once as a public standard."""

    text = (
        "Source ID: EIP-20. "
        "The token implementation follows the EIP-20 standard."
    )

    sanitized = _sanitize_client_body(text, known_internal_ids={"EIP-20"})

    assert sanitized == (
        "Source ID: upstream finding. "
        "The token implementation follows the EIP-20 standard."
    )
    assert extract_unambiguous_internal_ids(
        "The token implementation follows the EIP-20 standard.",
        known_internal_ids={"EIP-20"},
    ) == []


def test_artifact_qualified_delivery_keeps_colliding_legacy_actions_distinct() -> None:
    """Two historical producer files may reuse the same producer-local ID."""

    inventory = (
        "### Finding [INV-001]: First promoted issue\n"
        "**Source IDs**: EIP-20\n"
        "**Primary Artifact**: niche_alpha_findings.md\n\n"
        "### Finding [INV-002]: Second promoted issue\n"
        "**Source IDs**: EIP-20\n"
        "**Primary Artifact**: niche_beta_findings.md\n"
    )

    referents = _inventory_structural_source_action_referents(inventory)

    assert referents == {
        ("niche_alpha_findings.md", "EIP-20"): {"INV-001"},
        ("niche_beta_findings.md", "EIP-20"): {"INV-002"},
    }


@pytest.mark.parametrize(
    "text",
    [
        (
            "The private trace cites EIP-20. "
            "EIP-712 standard semantics apply."
        ),
        (
            "The private trace cites EIP-20; compare "
            "https://eips.ethereum.org/EIPS/eip-712."
        ),
        (
            "The private trace cites EIP-20 while "
            "EIP-712 standard semantics apply."
        ),
        (
            "EIP-712 standard semantics apply while "
            "the private trace cites EIP-20."
        ),
    ],
)
def test_public_standard_cue_only_exempts_its_own_occurrence(text: str) -> None:
    """A public cue elsewhere on one line cannot launder a private identity."""

    sanitized = _sanitize_client_body(text, known_internal_ids={"EIP-20"})

    assert "private trace cites upstream finding" in sanitized
    assert "EIP-712" in sanitized or "eip-712" in sanitized
    assert extract_unambiguous_internal_ids(
        text, known_internal_ids={"EIP-20"}
    ) == ["EIP-20"]
