from __future__ import annotations

import os
from pathlib import Path

import plamen_mechanical as mechanical


def _inventory(title: str) -> str:
    return f"""# Finding Inventory

### [H-1] {title}

**Severity**: High
**Location**: `contracts/Target.sol:1`
**Description**: A state transition violates its accounting invariant.
**Impact**: Funds can be lost.
**Root Cause**: The transition omits a required balance update.
"""


def test_finding_records_exact_republication_is_filesystem_noop(
    tmp_path: Path,
) -> None:
    inventory = tmp_path / "findings_inventory.md"
    inventory.write_text(_inventory("Stable finding"), encoding="utf-8")

    assert mechanical._write_finding_records_from_inventory(tmp_path) == 1
    projection = tmp_path / "finding_records.json"
    before = projection.stat()
    before_bytes = projection.read_bytes()

    assert mechanical._write_finding_records_from_inventory(tmp_path) == 1
    after = projection.stat()

    assert projection.read_bytes() == before_bytes
    assert (after.st_dev, after.st_ino, after.st_mtime_ns) == (
        before.st_dev,
        before.st_ino,
        before.st_mtime_ns,
    )


def test_finding_records_refresh_uses_source_digest_not_mtime(
    tmp_path: Path,
) -> None:
    inventory = tmp_path / "findings_inventory.md"
    inventory.write_text(_inventory("Original finding"), encoding="utf-8")
    assert mechanical._write_finding_records_from_inventory(tmp_path) == 1
    projection = tmp_path / "finding_records.json"
    projection_mtime = projection.stat().st_mtime_ns

    inventory.write_text(_inventory("Changed finding"), encoding="utf-8")
    # Reproduce coarse or restored filesystem timestamps: the source bytes
    # changed while the timestamp appears older than the derived projection.
    os.utime(inventory, ns=(projection_mtime - 1, projection_mtime - 1))

    by_id, _ = mechanical._load_finding_record_maps(tmp_path)

    assert by_id["H-1"]["title"] == "Changed finding"
    assert b"Changed finding" in projection.read_bytes()
