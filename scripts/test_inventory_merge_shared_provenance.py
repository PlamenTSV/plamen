"""Regression coverage for inventory duplicate amplification.

Inventory findings are the seed set for the mechanical enumeration gates.  A
single logical finding emitted twice with cosmetically different Location text
must not become two independent generator seeds when both copies carry the same
upstream finding ID.
"""

from plamen_parsers import _merge_inventory_entries
from plamen_validators import _promote_depth_findings_to_inventory


def _entry(
    *,
    location: str,
    source_ids: list[str],
    severity: str = "Medium",
    root_cause: str = "",
    description: str = "",
    impact: str = "",
) -> dict[str, object]:
    return {
        "title": "Accounting update omits a required multiplicand",
        "severity": severity,
        "location": location,
        "source_ids": source_ids,
        "root_cause": root_cause,
        "description": description,
        "impact": impact,
    }


def test_exact_title_shared_provenance_merges_location_format_variants() -> None:
    merged = _merge_inventory_entries(
        [
            _entry(
                location="contracts/Math.sol:55-67",
                source_ids=["TF-1", "SAF-1"],
                severity="Medium",
                root_cause="The calculation omits one factor.",
                description="The first pass traces the arithmetic expression.",
                impact="The receiver obtains an incorrect amount.",
            ),
            _entry(
                location=(
                    "contracts/Math.sol:55-67 "
                    "(function settle, dual-recipient branch)"
                ),
                source_ids=["TF-1", "CC-03"],
                severity="High",
                root_cause="The settlement branch omits the earned amount factor.",
                description="The inventory shard also traces the downstream transfer.",
                impact="Every affected settlement can misallocate the full balance.",
            ),
        ]
    )

    assert len(merged) == 1
    survivor = merged[0]
    assert survivor["severity"] == "High"
    assert set(survivor["source_ids"]) == {"TF-1", "SAF-1", "CC-03"}
    assert "contracts/Math.sol:55-67" in str(survivor["location"])
    assert "dual-recipient branch" in str(survivor["location"])
    assert "omits one factor" in str(survivor["root_cause"])
    assert "earned amount factor" in str(survivor["root_cause"])
    assert "arithmetic expression" in str(survivor["description"])
    assert "downstream transfer" in str(survivor["description"])
    assert "incorrect amount" in str(survivor["impact"])
    assert "full balance" in str(survivor["impact"])


def test_exact_title_disjoint_provenance_remains_separate() -> None:
    merged = _merge_inventory_entries(
        [
            _entry(
                location="contracts/A.sol:10",
                source_ids=["TF-1"],
            ),
            _entry(
                location="contracts/B.sol:20",
                source_ids=["TF-2"],
            ),
        ]
    )

    assert len(merged) == 2


def test_shared_provenance_bridge_requires_one_common_cluster_anchor() -> None:
    merged = _merge_inventory_entries(
        [
            _entry(
                location="contracts/A.sol:10",
                source_ids=["TF-1"],
                root_cause="evidence-a",
            ),
            _entry(
                location="contracts/A.sol:10 (settle)",
                source_ids=["TF-1", "CC-01"],
                root_cause="evidence-b",
            ),
            _entry(
                location="contracts/A.sol:10-12",
                source_ids=["CC-01", "SAF-2"],
                root_cause="evidence-c",
            ),
        ]
    )

    assert len(merged) == 2
    # A<->B and B<->C must not imply A<->C. One anchored pair is coupled and
    # the other mechanism survives independently; no evidence disappears.
    assert set().union(*(set(item["source_ids"]) for item in merged)) == {
        "TF-1", "CC-01", "SAF-2"
    }
    joined = " | ".join(str(item["root_cause"]) for item in merged)
    for token in ("evidence-a", "evidence-b", "evidence-c"):
        assert token in joined


def test_depth_promotion_receipt_does_not_forget_prior_promotions_on_rerun(
    tmp_path,
) -> None:
    """A later duplicate-only pass must not overwrite cumulative provenance."""
    (tmp_path / "findings_inventory.md").write_text(
        "# Finding Inventory\n\n"
        "### Finding [INV-001]: Existing arithmetic defect\n"
        "**Source IDs**: TF-1\n"
        "**Severity**: High\n"
        "**Location**: contracts/Math.sol:10\n"
        "**Description**: Existing issue.\n",
        encoding="utf-8",
    )
    (tmp_path / "depth_external_findings.md").write_text(
        "### Finding [DX-1]: Novel external-state inconsistency\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: Medium\n"
        "**Location**: contracts/External.sol:44\n"
        "**Description**: Novel finding retained for verification.\n\n"
        "### Finding [DX-2]: Existing arithmetic defect\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: High\n"
        "**Location**: contracts/Math.sol:10\n"
        "**Description**: Duplicate of the existing inventory row.\n",
        encoding="utf-8",
    )

    assert _promote_depth_findings_to_inventory(tmp_path) == ["DX-1", "DX-2"]
    first_receipt = (tmp_path / "depth_promotion_receipt.md").read_text(
        encoding="utf-8"
    )
    assert "Promoted 2 depth finding" in first_receipt
    assert "`DX-1`" in first_receipt
    assert "`DX-2`" in first_receipt

    # The normal driver invokes promotion again at later queue boundaries and
    # both IDs are now present. Recreate the legacy failure shape: a later
    # boundary overwrote the cumulative receipt even though the supplement
    # remained authoritative.
    (tmp_path / "depth_promotion_receipt.md").write_text(
        "# Depth Promotion Receipt\n\n"
        "Promoted 0 depth finding(s) into findings_inventory.md.\n\n"
        "## Likely Duplicates\n\n"
        "- `DX-2` — duplicate\n",
        encoding="utf-8",
    )
    assert _promote_depth_findings_to_inventory(tmp_path) == []
    second_receipt = (tmp_path / "depth_promotion_receipt.md").read_text(
        encoding="utf-8"
    )
    assert "Promoted 2 depth finding" in second_receipt
    assert "## Promoted" in second_receipt and "`DX-1`" in second_receipt
    assert "`DX-2`" in second_receipt


def test_depth_clear_not_a_finding_is_not_promoted(tmp_path) -> None:
    (tmp_path / "findings_inventory.md").write_text(
        "# Finding Inventory\n\n"
        "### Finding [INV-001]: seed\n"
        "**Source IDs**: SEED-1\n"
        "**Severity**: Low\n"
        "**Location**: contracts/Seed.sol:1\n",
        encoding="utf-8",
    )
    (tmp_path / "depth_external_findings.md").write_text(
        "### Finding [DX-1]: investigated hypothesis — CLEAR (not a finding)\n"
        "**Verdict**: CLEAR (no finding)\n"
        "**Severity**: N/A\n"
        "**Location**: contracts/Safe.sol:20\n"
        "**Description**: The hypothesized state transition is atomic.\n",
        encoding="utf-8",
    )

    assert _promote_depth_findings_to_inventory(tmp_path) == []
    inventory = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
    assert "DX-1" not in inventory
