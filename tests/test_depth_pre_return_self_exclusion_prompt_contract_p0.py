"""Prompt contract for depth pre-return self-exclusion review."""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEPTH_PROMPT = REPO_ROOT / "prompts" / "shared" / "v2" / "phase4b-depth.md"


def _contract_block() -> str:
    body = DEPTH_PROMPT.read_text(encoding="utf-8")
    start = body.index("### Pre-Return Self-Exclusion Check")
    end = body.index(
        "### Negative-Proposal Boundary and Committed-Invariant Emission",
        start,
    )
    return body[start:end]


def test_self_exclusion_check_reaches_every_candidate_emitting_depth_worker() -> None:
    block = _contract_block()
    assert "COPY INTO EVERY DEPTH WORKER PROMPT" in block
    assert "every standard depth-agent prompt" in block
    assert "iteration-2/3 depth-worker prompt" in block
    assert "Immediately before returning" in block
    assert "EVERY candidate" in block


def test_self_exclusion_check_binds_decisions_to_provided_upstream_source() -> None:
    block = _contract_block()
    for source in (
        "findings_inventory.md",
        "analysis_*.md",
        "analysis_rescan_*.md",
        "file:Lnnn",
    ):
        assert source in block
    assert "actually appears in that provided exclusion source" in block
    assert "belief that another worker probably covered" in block


def test_uncited_or_external_assumption_drop_is_restored_to_live_findings() -> None:
    block = _contract_block()
    assert "unverified external" in block
    assert "not a valid refutation or exclusion referent" in block
    assert "restore the candidate as a normal live finding" in block
    assert "never silently drop it" in block


def test_valid_exclusion_preserves_candidate_content_and_referent() -> None:
    block = _contract_block()
    assert "keep it out of the live finding blocks" in block
    assert "Non-Reportable / Absorbed Candidates" in block
    for required in ("own location", "mechanism", "one-line harm", "referent inline"):
        assert required in block


def test_driver_recovery_is_explicitly_defense_in_depth_not_primary_control() -> None:
    block = _contract_block()
    normalized = " ".join(block.split())
    assert "post-return self-exclusion recovery remains defense in depth" in normalized
    assert "Do not rely on that recovery" in normalized
    assert "do not use this check to" in normalized
    assert "SAFE`/`REFUTED" in normalized
