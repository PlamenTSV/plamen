from __future__ import annotations

import axis_disposition as axis


def test_axis_action_location_accepts_inline_code_value() -> None:
    text = """# Axis Coverage Findings

### Finding [AXIS-V2-123]: unresolved boundary candidate

**Severity**: Pending verification
**Location**: `contracts/Target.sol:L17`
**Work Item ID**: AXW-0123456789ABCDEF01234567
**Description**: [TRACE:contracts/Target.sol:L17] Exact source-grounded candidate.
"""

    actions, duplicates = axis._action_records(text)

    assert duplicates == set()
    assert actions["AXIS-V2-123"]["fields"]["Location"] == (
        "`contracts/Target.sol:L17`"
    )


def test_axis_action_inline_code_cannot_fabricate_a_field_label() -> None:
    block = """### Finding [AXIS-V2-123]: candidate

**Severity**: Pending verification
`**Location**: contracts/Decoy.sol:L1`
**Work Item ID**: AXW-0123456789ABCDEF01234567
**Description**: Concrete candidate.
"""

    assert axis._field(block, "Location") == ""
