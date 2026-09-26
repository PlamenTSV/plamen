from __future__ import annotations

import plamen_mechanical as mechanical


def test_operational_inventory_field_restores_authenticated_inline_code() -> None:
    text = """# Finding Inventory

### Finding [INV-001]: retained candidate

**Primary Artifact**: `niche_example_findings.md`
**Source IDs**: `NX-1`
**Source Action Identity**: `NACT-0123456789ABCDEF01234567`
"""
    [(identity, raw, operational)] = (
        mechanical._operational_inventory_finding_blocks(text)
    )

    assert identity == "INV-001"
    assert mechanical._operational_inventory_field(
        operational, ("Primary Artifact",), raw_block=raw
    ) == "niche_example_findings.md"
    assert mechanical._operational_inventory_field(
        operational, ("Source IDs",), raw_block=raw
    ) == "NX-1"


def test_operational_inventory_field_rejects_inline_code_label() -> None:
    text = """# Finding Inventory

### Finding [INV-001]: retained candidate

`**Source IDs**: NX-1`
"""
    [(_identity, raw, operational)] = (
        mechanical._operational_inventory_finding_blocks(text)
    )

    assert mechanical._operational_inventory_field(
        operational, ("Source IDs",), raw_block=raw
    ) == ""
