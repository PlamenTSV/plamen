"""Regression tests for inventory shard prompt schema contracts."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import plamen_prompt as P


def _finding(finding_id: str, title: str) -> str:
    return (
        f"### Finding [{finding_id}]: {title}\n\n"
        "**Severity**: High\n"
        "**Location**: src/Gateway.sol:L10\n"
        f"**Root Cause**: shared mechanism for {title}\n"
        f"**Description**: shared mechanism for {title}\n"
        f"**Impact**: material loss from {title}\n"
        "**Verdict**: CONFIRMED\n\n"
    )


def _manifest(root: Path, *sources: str) -> None:
    (root / "inventory_chunk_a.manifest.md").write_text(
        "# inventory_chunk_a manifest\n\n"
        "| File | Estimated signals |\n"
        "|------|-------------------|\n"
        + "".join(f"| {source} | 1 |\n" for source in sources),
        encoding="utf-8",
    )


def _checklist_payload(rendered: str) -> dict:
    return json.loads(rendered.split("```json\n", 1)[1].split("\n```", 1)[0])


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


def test_inventory_chunk_prompt_projects_duplicate_mechanisms_as_distinct_identities(
    tmp_path: Path,
) -> None:
    access = "analysis_access_control.md"
    refunds = "analysis_refunds_and_encoding.md"
    (tmp_path / access).write_text(
        _finding("B2-1", "authorized bot receives non-EVM refund"),
        encoding="utf-8",
    )
    (tmp_path / refunds).write_text(
        _finding("B5-2", "authorized bot receives non-EVM refund"),
        encoding="utf-8",
    )
    _manifest(tmp_path, access, refunds)

    rendered = P._render_inventory_chunk_identity_checklist(
        tmp_path, "inventory_chunk_a"
    )
    payload = _checklist_payload(rendered)

    assert payload["denominator_count"] == 2
    assert len(payload["rows"]) == 2
    assert len({row["candidate_key"] for row in payload["rows"]}) == 2
    assert {
        row["required_source_id_token"] for row in payload["rows"]
    } == {
        "analysis_access_control.md:B2-1",
        "analysis_refunds_and_encoding.md:B5-2",
    }
    assert "Emit exactly 2 Master Table rows" in rendered
    assert "one independent detail block for every checklist row" in rendered

    phase = P.Phase(
        "inventory_chunk_a",
        ["Inventory"],
        ["findings_inventory_chunk_a.md"],
        300,
    )
    prompt = P.build_phase_prompt(
        tmp_path / "unused-v1-prompt.md",
        phase,
        {
            "scratchpad": str(tmp_path),
            "project_root": str(tmp_path),
            "language": "evm",
            "mode": "thorough",
            "pipeline": "sc",
            "cli_backend": "codex",
            "proven_only": False,
        },
    )
    assert prompt.count("## EXACT ASSIGNED RAW-IDENTITY CHECKLIST (HARD)") == 1
    assert "analysis_access_control.md:B2-1" in prompt
    assert "analysis_refunds_and_encoding.md:B5-2" in prompt
    assert "Do local dedup only within this shard" not in prompt


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {
            "candidates": {},
            "denominator_count": 0,
            "denominator_digest": "0" * 64,
        },
        {
            "candidates": [],
            "denominator_count": 1,
            "denominator_digest": "0" * 64,
        },
    ],
)
def test_inventory_chunk_prompt_rejects_malformed_denominator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: object,
) -> None:
    monkeypatch.setattr(
        P, "_reconcile_inventory_for_prompt", lambda *_a, **_k: payload
    )

    with pytest.raises(P.PhasePromptError, match="denominator is malformed"):
        P._render_inventory_chunk_identity_checklist(tmp_path, "inventory_chunk_a")


def test_inventory_chunk_prompt_rejects_duplicate_denominator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = {
        "candidate_key": "INVC-" + "A" * 24,
        "source_artifact": "analysis_access_control.md",
        "source_sha256": "1" * 64,
        "source_finding_id": "B2-1",
        "source_ordinal": 1,
        "source_block_sha256": "2" * 64,
    }
    monkeypatch.setattr(
        P,
        "_reconcile_inventory_for_prompt",
        lambda *_a, **_k: {
            "candidates": [row, {**row, "source_ordinal": 2}],
            "denominator_count": 2,
            "denominator_digest": "0" * 64,
        },
    )

    with pytest.raises(P.PhasePromptError, match="duplicate candidate"):
        P._render_inventory_chunk_identity_checklist(tmp_path, "inventory_chunk_a")


def test_inventory_chunk_prompt_contains_no_shard_local_dedup_escape() -> None:
    prompt_source = (Path(__file__).with_name("plamen_prompt.py")).read_text(
        encoding="utf-8"
    )

    assert "Do local dedup only within this shard" not in prompt_source
    assert "Do not deduplicate within this shard" in prompt_source
    assert "A Source Summary mention is not a disposition" in prompt_source
