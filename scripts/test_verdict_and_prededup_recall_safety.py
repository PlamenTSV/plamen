"""Adversarial fixtures for pre-verification recall safety.

These cases are intentionally mechanical: no parser or identity heuristic may
dispose of a candidate before an independent verifier sees it merely because
legacy prose is ambiguous, a generic status says ``CLEAR``, or two mechanisms
have a cosmetic title collision.
"""

from __future__ import annotations

from itertools import permutations

from plamen_parsers import (
    _merge_inventory_entries,
    _queue_rows_from_inventory_with_exclusions,
    _verifier_status_from_text,
)
import plamen_validators as _validators
from plamen_validators import (
    _promote_depth_findings_to_inventory,
    _validate_depth_promotion_receipt,
)


def _entry(
    source_ids: list[str],
    *,
    location: str,
    verdict: str = "CONFIRMED",
    root_cause: str = "",
) -> dict[str, object]:
    return {
        "title": "Repeated accounting title",
        "severity": "Medium",
        "location": location,
        "source_ids": source_ids,
        "verdict": verdict,
        "root_cause": root_cause,
        "description": root_cause,
        "impact": root_cause,
    }


def _seed_inventory(tmp_path) -> None:
    (tmp_path / "findings_inventory.md").write_text(
        "# Finding Inventory\n\n"
        "### Finding [INV-001]: Repeated accounting title\n"
        "**Source IDs**: BREADTH-1\n"
        "**Severity**: High\n"
        "**Location**: contracts/A.sol:10\n"
        "**Description**: First mechanism.\n",
        encoding="utf-8",
    )


def test_exact_machine_verdict_wins_over_unstructured_prose() -> None:
    assert _verifier_status_from_text(
        "**Verdict**: CONFIRMED\n\nHistorical prose calls the hypothesis refuted."
    ) == "CONFIRMED"
    assert _verifier_status_from_text(
        "**Final Verdict**: REFUTED\n\nA quoted note says CONFIRMED."
    ) == "REFUTED"


def test_conflicting_exact_verdict_fields_are_unresolved_in_any_order() -> None:
    for first, second in (
        ("CONFIRMED", "REFUTED"),
        ("REFUTED", "CONFIRMED"),
    ):
        assert _verifier_status_from_text(
            f"**Verdict**: {first}\n\n**Final Verdict**: {second}\n"
        ) == "UNRESOLVED"


def test_identical_duplicate_exact_verdict_fields_remain_machine_decidable() -> None:
    assert _verifier_status_from_text(
        "**Verdict**: CONFIRMED\n\n**Final Verdict**: CONFIRMED\n"
    ) == "CONFIRMED"


def test_table_and_inline_exact_verdict_conflict_is_unresolved() -> None:
    assert _verifier_status_from_text(
        "| Verdict | CONFIRMED |\n|---|---|\n\n**Final Verdict**: REFUTED\n"
    ) == "UNRESOLVED"


def test_legacy_negation_or_conflict_never_becomes_negative_disposition() -> None:
    probes = (
        "**Verdict**: not refuted; CONFIRMED",
        "**Verdict**: not a false positive; CONFIRMED",
        "**Verdict**: not duplicate; CONFIRMED",
        "This finding is not refuted; the mechanism remains CONFIRMED.",
        "The result is REFUTED in one paragraph but CONFIRMED in another.",
    )
    assert {
        _verifier_status_from_text(probe) for probe in probes
    } == {"UNRESOLVED"}


def test_refuted_poc_blocker_uses_canonical_exact_field_discriminator() -> None:
    exact_refutation = (
        "**Verdict**: REFUTED\n\n"
        "The traced path cannot cause loss of funds.\n"
    )
    conflicting = (
        "**Verdict**: REFUTED\n\n"
        "**Final Verdict**: CONFIRMED\n\n"
        "The path can cause loss of funds.\n"
    )
    negated = (
        "**Verdict**: not REFUTED; CONFIRMED after execution\n\n"
        "The path can cause loss of funds.\n"
    )

    assert _validators._has_refuted_verdict(exact_refutation)
    assert _validators._has_valid_skip_blocker(exact_refutation)
    for probe in (conflicting, negated):
        assert _verifier_status_from_text(probe) == "UNRESOLVED"
        assert not _validators._has_refuted_verdict(probe)
        assert not _validators._has_valid_skip_blocker(probe)


def test_generic_status_clear_is_not_a_finding_disposition() -> None:
    assert _verifier_status_from_text("**Status**: CLEAR") == "UNRESOLVED"
    assert _verifier_status_from_text(
        "# CLEAR (not a finding)\n\n**Severity**: High"
    ) == "UNRESOLVED"
    # A verdict-labelled negative disposition remains supported for legacy
    # artifacts that explicitly use CLEAR (no finding).
    assert _verifier_status_from_text(
        "**Verdict**: CLEAR (no finding)"
    ) == "REFUTED"


def test_inventory_status_clear_stays_on_verification_queue(tmp_path) -> None:
    (tmp_path / "findings_inventory.md").write_text(
        "### Finding [INV-001]: Candidate under review\n"
        "**Source IDs**: BREADTH-1\n"
        "**Severity**: High\n"
        "**Location**: contracts/A.sol:10\n"
        "**Status**: CLEAR\n",
        encoding="utf-8",
    )
    active, excluded = _queue_rows_from_inventory_with_exclusions(tmp_path)
    assert [row["finding id"] for row in active] == ["INV-001"]
    assert excluded == []


def test_depth_status_clear_and_clear_heading_do_not_silently_dispose(
    tmp_path,
) -> None:
    _seed_inventory(tmp_path)
    (tmp_path / "depth_external_findings.md").write_text(
        "### Finding [DX-10]: Generic workflow status\n"
        "**Status**: CLEAR\n"
        "**Severity**: High\n"
        "**Location**: contracts/B.sol:20\n"
        "**Description**: Candidate still needs finding verification.\n\n"
        "### Finding [DX-11]: CLEAR (not a finding)\n"
        "**Severity**: High\n"
        "**Location**: contracts/C.sol:30\n"
        "**Description**: Heading prose is not a verdict field.\n",
        encoding="utf-8",
    )
    assert _promote_depth_findings_to_inventory(tmp_path) == ["DX-10", "DX-11"]


def test_depth_title_only_collision_is_tagged_but_promoted(tmp_path) -> None:
    _seed_inventory(tmp_path)
    (tmp_path / "depth_external_findings.md").write_text(
        "### Finding [DX-1]: Repeated accounting title\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: High\n"
        "**Location**: contracts/A.sol:900\n"
        "**Description**: A distinct far-away mechanism.\n",
        encoding="utf-8",
    )

    assert _promote_depth_findings_to_inventory(tmp_path) == ["DX-1"]
    inventory = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
    assert "**Source IDs**: [DX-1]" in inventory
    assert "[LIKELY-DUP" in inventory


def test_depth_same_site_similarity_is_also_tag_only_before_verification(
    tmp_path,
) -> None:
    _seed_inventory(tmp_path)
    (tmp_path / "depth_external_findings.md").write_text(
        "### Finding [DX-2]: Repeated accounting title\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: High\n"
        "**Location**: contracts/A.sol:11\n"
        "**Description**: A sibling mechanism at the same site.\n",
        encoding="utf-8",
    )

    assert _promote_depth_findings_to_inventory(tmp_path) == ["DX-2"]


def test_depth_id_mentioned_only_in_description_cannot_suppress_promotion(
    tmp_path,
) -> None:
    _seed_inventory(tmp_path)
    inventory = (tmp_path / "findings_inventory.md")
    inventory.write_text(
        inventory.read_text(encoding="utf-8")
        + "\nThe analyst compared this candidate with DX-77 in prose only.\n",
        encoding="utf-8",
    )
    (tmp_path / "depth_external_findings.md").write_text(
        "### Finding [DX-77]: Distinct structural referent\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: High\n"
        "**Location**: contracts/Z.sol:77\n"
        "**Description**: This finding must receive its own Source IDs row.\n",
        encoding="utf-8",
    )

    assert _promote_depth_findings_to_inventory(tmp_path) == ["DX-77"]
    promoted = inventory.read_text(encoding="utf-8")
    assert "**Source IDs**: [DX-77]" in promoted


def test_likely_duplicate_hint_never_satisfies_promotion_completeness(
    tmp_path,
) -> None:
    _seed_inventory(tmp_path)
    original_inventory = (tmp_path / "findings_inventory.md").read_text(
        encoding="utf-8"
    )
    (tmp_path / "depth_external_findings.md").write_text(
        "### Finding [DX-3]: Repeated accounting title\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: High\n"
        "**Location**: contracts/A.sol:11\n"
        "**Description**: Similarity-tagged candidate.\n",
        encoding="utf-8",
    )
    assert _promote_depth_findings_to_inventory(tmp_path) == ["DX-3"]
    # Simulate a downstream loss after promotion while leaving the receipt and
    # its Likely Duplicates hint intact.
    (tmp_path / "findings_inventory.md").write_text(
        original_inventory, encoding="utf-8"
    )
    issues = _validate_depth_promotion_receipt(tmp_path)
    assert any("DX-3" in issue for issue in issues)


def test_exact_title_location_disjoint_provenance_stays_distinct() -> None:
    merged = _merge_inventory_entries(
        [
            _entry(["A-1"], location="contracts/A.sol:10", root_cause="mechanism-a"),
            _entry(["B-1"], location="contracts/A.sol:10", root_cause="mechanism-b"),
        ]
    )
    assert len(merged) == 2
    assert {tuple(item["source_ids"]) for item in merged} == {("A-1",), ("B-1",)}


def test_exact_title_location_root_mech_signature_is_tag_only() -> None:
    merged = _merge_inventory_entries(
        [
            _entry(["A-1"], location="contracts/A.sol:10", root_cause="same mechanism"),
            _entry(["B-1"], location="contracts/A.sol:10", root_cause="same mechanism"),
        ]
    )
    assert len(merged) == 2


def test_provenance_bridge_cannot_transitively_collapse_without_one_anchor() -> None:
    records = [
        _entry(["ANCHOR-A"], location="contracts/A.sol:10", root_cause="evidence-a"),
        _entry(
            ["ANCHOR-A", "ANCHOR-B"],
            location="contracts/A.sol:10 (branch)",
            root_cause="evidence-bridge",
        ),
        _entry(["ANCHOR-B"], location="contracts/A.sol:12", root_cause="evidence-b"),
    ]
    signatures = set()
    for ordering in permutations(records):
        merged = _merge_inventory_entries([dict(item) for item in ordering])
        signatures.add(
            tuple(
                sorted(tuple(sorted(item["source_ids"])) for item in merged)
            )
        )
        assert len(merged) == 2
    assert len(signatures) == 1, "merge partition must not depend on input order"


def test_conflicting_duplicate_verdict_is_recall_safe_and_order_independent() -> None:
    reportable = _entry(
        ["COMMON-1", "A-1"],
        location="contracts/A.sol:10",
        verdict="CONFIRMED",
        root_cause="reportable evidence",
    )
    negative = _entry(
        ["COMMON-1", "B-1"],
        location="contracts/A.sol:10 (branch)",
        verdict="REFUTED",
        root_cause="negative evidence",
    )
    outputs = []
    for ordering in ((reportable, negative), (negative, reportable)):
        merged = _merge_inventory_entries([dict(item) for item in ordering])
        assert len(merged) == 1
        survivor = merged[0]
        assert survivor["verdict"] == "UNRESOLVED"
        assert set(survivor["source_ids"]) == {
            "COMMON-1", "A-1", "B-1"
        }
        assert "reportable evidence" in str(survivor["root_cause"])
        assert "negative evidence" in str(survivor["root_cause"])
        outputs.append(survivor["verdict"])
    assert outputs == ["UNRESOLVED", "UNRESOLVED"]
