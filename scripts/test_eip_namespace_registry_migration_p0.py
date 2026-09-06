"""Focused contracts for the EIP producer-namespace migration."""
from pathlib import Path

from finding_producer_registry import (
    PRODUCERS_BY_KEY,
    producer_accepts_local_id,
    producer_id_pattern,
)
from plamen_parsers import (
    _parse_depth_finding_blocks,
    _sanitize_client_body,
    extract_unambiguous_internal_ids,
)


def test_global_registry_projection_uses_collision_free_niche_prefix() -> None:
    pattern = producer_id_pattern(include_lineage=True)

    assert "EIPF" in pattern
    assert "|EIP|" not in pattern
    assert "EIP-\\d+" not in pattern


def test_legacy_eip_is_readable_only_by_its_owned_producer() -> None:
    niche = PRODUCERS_BY_KEY["niche"]
    depth = PRODUCERS_BY_KEY["depth_core"]

    assert producer_accepts_local_id(niche, "EIPF-20")
    assert producer_accepts_local_id(niche, "EIP-20")
    assert not producer_accepts_local_id(depth, "EIP-20")


def test_legacy_niche_heading_survives_producer_scoped_resume(tmp_path: Path) -> None:
    artifact = tmp_path / "niche_legacy_findings.md"
    artifact.write_text(
        "### Finding [EIP-20]: Legacy producer candidate\n"
        "**Severity**: Medium\n"
        "**Location**: src/F.sol:1\n"
        "**Description**: A substantive historical candidate remains readable "
        "when resuming its producer-owned artifact.\n",
        encoding="utf-8",
    )

    parsed = _parse_depth_finding_blocks(artifact)

    assert [row["id"] for row in parsed] == ["EIP-20"]
    assert parsed[0]["_local_id_valid"] == "true"
    assert parsed[0]["_content_bearing"] == "true"


def test_public_eip_heading_in_niche_artifact_is_not_legacy_identity(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "niche_standard_notes_findings.md"
    artifact.write_text(
        "### EIP-20 compatibility notes\n"
        "This heading documents the public token standard.\n\n"
        "### Finding [SIG-1]: Actual producer candidate\n"
        "**Severity**: Medium\n"
        "**Location**: src/F.sol:1\n"
        "**Description**: A substantive candidate is deliberately separate "
        "from the public standards heading.\n",
        encoding="utf-8",
    )

    parsed = _parse_depth_finding_blocks(artifact)

    assert [row["id"] for row in parsed] == ["SIG-1"]


def test_known_legacy_membership_is_explicit_authority_not_global_shape() -> None:
    text = "The trace cites EIP-20."

    assert extract_unambiguous_internal_ids(text) == []
    assert extract_unambiguous_internal_ids(
        text, known_internal_ids={"EIP-20"}
    ) == ["EIP-20"]
    assert _sanitize_client_body(text) == text
    assert "EIP-20" not in _sanitize_client_body(
        text, known_internal_ids={"EIP-20"}
    )
