from __future__ import annotations

import json

from preverify_frozen_projection import derive_preverify_finding_records_bytes


def test_preverify_uses_operational_structure_and_exact_raw_field_values() -> None:
    inventory = b"""# Findings Inventory

<!--
### Finding [INV-999]: Commented decoy
**Location**: `contracts/Decoy.sol:L1`
-->

### Finding [INV-001]: Canonical candidate
**Severity**: `High`
**Location**: `contracts/Target.sol:L42`
**Source IDs**: `B1-7`, `DA2-3`
**Preferred Tag**: `[POC-PASS]`
**Description**: Exact authored values survive structural masking.
"""

    payload = json.loads(
        derive_preverify_finding_records_bytes(inventory).decode("utf-8")
    )

    assert [row["inventory_id"] for row in payload["records"]] == ["INV-001"]
    record = payload["records"][0]
    assert record["location"] == "contracts/Target.sol:L42"
    assert record["source_ids"] == ["B1-7", "DA2-3"]
    assert record["preferred_tag"] == "[POC-PASS]"
