"""P0-K/M: registry-derived lineage and explicit finding headings.

These fixtures keep producer-local and lineage identities from disappearing at
the Markdown/JSON boundary while preventing ordinary methodology headings from
manufacturing finding blocks.
"""
from __future__ import annotations

from plamen_mechanical import _records_from_inventory_text
from plamen_parsers import (
    _extract_finding_ids_from_text,
    _extract_finding_signals,
    _parse_depth_finding_blocks,
)


def test_registry_current_and_lineage_identities_survive_freeform_extraction():
    text = (
        "Source IDs: ASKP-7, SKEP-LEGACY-A1B2C3D4E5F6, "
        "ECLR-A1B2C3D4E5F60718293A4B5C, "
        "ASCP-00112233445566778899AABB, "
        "ASW-AABBCCDDEEFF001122334455, DXRE-ROLE_A_17, PCRE-9. "
        "Standards EIP-1559, ERC-20, OZ-4626 are not finding identities."
    )

    assert _extract_finding_ids_from_text(text) == {
        "ASKP-7",
        "SKEP-LEGACY-A1B2C3D4E5F6",
        "ECLR-A1B2C3D4E5F60718293A4B5C",
        "ASCP-00112233445566778899AABB",
        "ASW-AABBCCDDEEFF001122334455",
        "DXRE-ROLE_A_17",
        "PCRE-9",
    }


def test_manifest_selected_prefix_needs_owning_artifact_and_explicit_heading(
    tmp_path,
):
    assert _extract_finding_ids_from_text(
        "Standards OZ-4626 and WETH-9 are referenced."
    ) == set()

    artifact = tmp_path / "analysis_dynamic_role.md"
    artifact.write_text(
        "### OZ-4626 compatibility notes\n"
        "This is standards prose, not a candidate.\n\n"
        "### Finding [DYNAMICROLE-1]: Exact artifact-owned candidate\n"
        "**Severity**: Medium\n"
        "**Location**: src/module.rs:L42\n"
        "**Description**: The explicit finding heading carries a substantive mechanism.\n",
        encoding="utf-8",
    )

    parsed = _parse_depth_finding_blocks(artifact)
    assert [row["id"] for row in parsed] == ["DYNAMICROLE-1"]


def test_inventory_record_projection_preserves_registered_source_lineage():
    inventory = (
        "# Finding Inventory\n\n"
        "### Finding [INV-001]: Registry lineage survives\n"
        "**Severity**: Medium\n"
        "**Location**: src/module.rs:L42\n"
        "**Source IDs**: ASKP-7, ECLR-A1B2C3D4E5F60718293A4B5C, "
        "ASCP-00112233445566778899AABB, DXRE-ROLE_A_17\n"
        "**Description**: A bounded candidate remains independently reviewable.\n"
        "**Impact**: A protected transition can become inconsistent.\n"
    )

    records = _records_from_inventory_text(inventory)

    assert len(records) == 1
    assert records[0]["inventory_id"] == "INV-001"
    assert records[0]["source_ids"] == [
        "ASCP-00112233445566778899AABB",
        "ASKP-7",
        "DXRE-ROLE_A_17",
        "ECLR-A1B2C3D4E5F60718293A4B5C",
    ]


def test_bare_methodology_heading_is_not_a_finding_block():
    ids, loose = _extract_finding_signals(
        "## H-2 Methodology application rule\n\n"
        "This section describes a workflow and contains no finding.\n"
    )

    assert ids == set()
    assert loose == 0


def test_explicit_finding_or_bracketed_heading_remains_a_finding_block():
    ids, loose = _extract_finding_signals(
        "### Finding [ASKP-7]: Independent candidate\n"
        "**Location**: src/module.rs:L42\n\n"
        "### [INV-002] Bracketed canonical finding\n"
        "**Location**: src/module.rs:L57\n"
    )

    assert ids == {"ASKP-7", "INV-002"}
    assert loose == 1
