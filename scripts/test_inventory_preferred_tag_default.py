"""Inventory chunk validation observes defects without mutating MODEL bytes.

Canonical aggregate materialization may derive a ``[CODE-TRACE]`` default, but
the validator cannot write it into a MODEL-owned chunk before PhaseIO commits.
"""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path


def _val():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    return importlib.import_module("plamen_validators")


_FIELDS_NO_TAG = (
    "**Source IDs**: B1-{n}\n"
    "**Severity**: Medium\n"
    "**Location**: Contract.sol:L{n}0\n"
    "**Verdict**: CONFIRMED\n"
    "**Root Cause**: root cause text {n}\n"
    "**Description**: description text {n}\n"
    "**Impact**: impact text {n}\n"
)


def _chunk(
    n_blocks: int,
    *,
    with_tag: bool = False,
    drop_location: bool = False,
) -> str:
    out = ["# Inventory Chunk\n\n## Per-Finding Detail\n"]
    for i in range(1, n_blocks + 1):
        fields = _FIELDS_NO_TAG.format(n=i)
        if drop_location:
            fields = "\n".join(
                line
                for line in fields.splitlines()
                if not line.startswith("**Location**")
            ) + "\n"
        if with_tag:
            fields += "**Preferred Tag**: [POC-PASS]\n"
        out.append(f"\n### [CC-{i}]: Finding {i}\n{fields}")
    return "".join(out)


def _write(
    tmp_path: Path,
    text: str,
    phase: str = "inventory_chunk_b",
) -> Path:
    path = tmp_path / f"findings_{phase}.md"
    path.write_text(text, encoding="utf-8")
    return path


def test_missing_preferred_tag_is_observed_without_mutation(tmp_path):
    validator = _val()
    chunk = _write(tmp_path, _chunk(6))
    before = chunk.read_bytes()

    issues = validator._validate_inventory_chunk_structure(
        tmp_path, "inventory_chunk_b"
    )

    assert any("Preferred Tag (" in issue for issue in issues), issues
    assert chunk.read_bytes() == before


def test_non_defaultable_field_still_retries(tmp_path):
    validator = _val()
    _write(tmp_path, _chunk(6, drop_location=True))

    issues = validator._validate_inventory_chunk_structure(
        tmp_path, "inventory_chunk_b"
    )

    assert any("Location (" in issue for issue in issues), issues


def test_repeated_validation_is_pure_and_idempotent(tmp_path):
    validator = _val()
    chunk = _write(tmp_path, _chunk(6))
    before = chunk.read_bytes()

    issues1 = validator._validate_inventory_chunk_structure(
        tmp_path, "inventory_chunk_b"
    )
    issues2 = validator._validate_inventory_chunk_structure(
        tmp_path, "inventory_chunk_b"
    )

    assert any("Preferred Tag (" in issue for issue in issues1), issues1
    assert issues2 == issues1
    assert chunk.read_bytes() == before


def test_existing_tag_untouched(tmp_path):
    validator = _val()
    chunk = _write(tmp_path, _chunk(6, with_tag=True))
    before = chunk.read_bytes()

    issues = validator._validate_inventory_chunk_structure(
        tmp_path, "inventory_chunk_b"
    )

    assert not any("Preferred Tag (" in issue for issue in issues), issues
    assert chunk.read_bytes() == before


def test_mixed_missing_tag_and_location_are_both_observed(tmp_path):
    validator = _val()
    chunk = _write(tmp_path, _chunk(6, drop_location=True))
    before = chunk.read_bytes()

    issues = validator._validate_inventory_chunk_structure(
        tmp_path, "inventory_chunk_b"
    )

    assert any("Preferred Tag (" in issue for issue in issues), issues
    assert any("Location (" in issue for issue in issues), issues
    assert chunk.read_bytes() == before


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-q"]))
