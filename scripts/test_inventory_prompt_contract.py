"""Regression tests for inventory shard prompt schema contracts."""
from __future__ import annotations

from pathlib import Path


def test_inventory_chunk_prompt_makes_impact_unskippable() -> None:
    prompt_source = (Path(__file__).with_name("plamen_prompt.py")).read_text(
        encoding="utf-8"
    )

    assert "Use this exact detail-block skeleton for every finding" in prompt_source
    assert "**Impact**: <security/economic/operational effect" in prompt_source
    assert "`**Impact**:` is mandatory even when the verdict is PARTIAL" in prompt_source
    assert "Precondition analysis may appear only after the mandatory" in prompt_source
    assert "If any block lacks it, fix the block before returning" in prompt_source


def test_inventory_chunk_retry_hint_names_impact_as_hard_field() -> None:
    driver_source = (Path(__file__).with_name("plamen_driver.py")).read_text(
        encoding="utf-8"
    )

    assert "`**Impact**:` is mandatory for CONFIRMED, PARTIAL" in driver_source
    assert "does not replace Impact" in driver_source
    assert "block contains a literal " in driver_source


def test_inventory_chunk_contract_is_lossless_one_to_one_before_dedup() -> None:
    prompt_source = (Path(__file__).with_name("plamen_prompt.py")).read_text(
        encoding="utf-8"
    )
    driver_source = (Path(__file__).with_name("plamen_driver.py")).read_text(
        encoding="utf-8"
    )

    assert "lossless normalization boundary, not a semantic-dedup authority" in prompt_source
    assert "exactly ONE `### Finding [<SHARD-ID>]" in prompt_source
    assert "Never combine two upstream identities" in prompt_source
    assert "copy the source Root Cause/Description" in driver_source
    assert "Later phases own semantic deduplication" in driver_source
