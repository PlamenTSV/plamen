from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import plamen_driver as D
import plamen_mechanical as M
import plamen_parsers as P


def _finding(finding_id: str, title: str) -> str:
    return (
        f"## Finding [{finding_id}]: {title}\n"
        "**Severity**: Medium\n"
        "**Location**: src/Module.sol:L1\n"
        f"**Description**: {title} remains a candidate for verification.\n"
        "**Impact**: Silent loss would reduce recall.\n"
    )


def _inventory(root: Path) -> None:
    (root / "findings_inventory.md").write_text(
        "# Findings Inventory\n", encoding="utf-8"
    )


def _publish_rehashed_payload(path: Path, payload: dict) -> None:
    payload.pop("artifact_sha256", None)
    payload["artifact_sha256"] = M._niche_identity_debt_digest(payload)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_live_validation_rejects_rehashed_action_denominator_omission(
    tmp_path: Path,
) -> None:
    _inventory(tmp_path)
    source = tmp_path / "niche_runtime_findings.md"
    source.write_text(
        _finding("SC-61", "first action")
        + "\n"
        + _finding("SC-62", "second action"),
        encoding="utf-8",
    )
    assert M.promote_niche_to_inventory(tmp_path) == (2, 2)
    sidecar = tmp_path / "niche_identity_debt.json"
    payload = json.loads(sidecar.read_text(encoding="utf-8"))
    payload["actions"] = payload["actions"][:1]
    payload["action_count"] = 1
    payload["action_set_sha256"] = M._niche_action_set_digest(
        payload["actions"]
    )
    _publish_rehashed_payload(sidecar, payload)

    with pytest.raises(RuntimeError, match="live action denominator"):
        M.read_niche_identity_debt_sidecar(tmp_path)


def test_driver_cannot_accept_rehashed_omission_with_matching_result_fields(
    tmp_path: Path,
) -> None:
    _inventory(tmp_path)
    source = tmp_path / "niche_runtime_findings.md"
    source.write_text(
        _finding("SC-61", "first action")
        + "\n"
        + _finding("SC-62", "second action"),
        encoding="utf-8",
    )
    M.promote_niche_to_inventory(tmp_path)
    sidecar = tmp_path / "niche_identity_debt.json"
    payload = json.loads(sidecar.read_text(encoding="utf-8"))
    payload["actions"] = payload["actions"][:1]
    payload["action_count"] = 1
    payload["action_set_sha256"] = M._niche_action_set_digest(
        payload["actions"]
    )
    _publish_rehashed_payload(sidecar, payload)
    result = {
        "parsed": 1,
        "appended": 0,
        "identity_debt_artifact": sidecar.name,
        "identity_debt_sha256": payload["artifact_sha256"],
        "identity_debt_count": payload["blocking_debt_count"],
        "identity_debt_candidate_count": payload["candidate_count"],
        "identity_debt_source_error_count": payload["source_error_count"],
        "identity_debt_denominator_complete": payload["denominator_complete"],
        "identity_debt_action_count": payload["action_count"],
        "identity_debt_action_set_sha256": payload["action_set_sha256"],
        "identity_debt_source_snapshots": payload["source_snapshots"],
        "identity_debt_validation_status": "LIVE_VALIDATED",
    }
    valid, reason = D._depth_processor_outcome_valid(
        tmp_path,
        "niche_promotion",
        {
            "status": "COMPLETE",
            "result": result,
            "outcome": {"inventory_referents": []},
        },
    )
    assert valid is False
    assert "live action denominator" in reason


def test_removed_undelivered_action_persists_as_blocking_tombstone(
    tmp_path: Path,
) -> None:
    source = tmp_path / "niche_runtime_findings.md"
    source.write_text(
        _finding("SC-61", "undelivered action"), encoding="utf-8"
    )
    assert M.promote_niche_to_inventory(tmp_path) == (1, 0)
    prior = M.read_niche_identity_debt_sidecar(tmp_path)
    assert prior is not None
    old_identity = prior["actions"][0]["source_action_identity"]

    source.write_text("# Niche review\n\nNo findings.\n", encoding="utf-8")
    assert M.promote_niche_to_inventory(tmp_path) == (0, 0)
    current = M.read_niche_identity_debt_sidecar(tmp_path)
    assert current is not None
    assert current["blocking_debt_count"] >= 1
    removed = [
        row
        for row in current["source_errors"]
        if row.get("status") == "SOURCE_ACTION_REMOVED"
    ]
    assert len(removed) == 1
    assert removed[0]["source_action_identity"] == old_identity
    assert removed[0]["drop_authority"] is False
    assert removed[0]["clean_authority"] is False
    first_tombstone_bytes = (
        tmp_path / "niche_identity_debt.json"
    ).read_bytes()
    assert M.promote_niche_to_inventory(tmp_path) == (0, 0)
    assert (tmp_path / "niche_identity_debt.json").read_bytes() == (
        first_tombstone_bytes
    )


def test_removed_delivered_action_retains_nonblocking_lifecycle_record(
    tmp_path: Path,
) -> None:
    _inventory(tmp_path)
    source = tmp_path / "niche_runtime_findings.md"
    source.write_text(_finding("SC-61", "delivered action"), encoding="utf-8")
    assert M.promote_niche_to_inventory(tmp_path) == (1, 1)
    prior = M.read_niche_identity_debt_sidecar(tmp_path)
    assert prior is not None
    old_identity = prior["actions"][0]["source_action_identity"]

    source.write_text("# Niche review\n\nNo findings.\n", encoding="utf-8")
    M.promote_niche_to_inventory(tmp_path)
    current = M.read_niche_identity_debt_sidecar(tmp_path)
    assert current is not None
    rows = current["lifecycle_records"]
    assert any(
        row.get("source_action_identity") == old_identity
        and row.get("status") == "DELIVERED_ACTION_REMOVED"
        and row.get("blocking") is False
        for row in rows
    )
    first_lifecycle_bytes = (
        tmp_path / "niche_identity_debt.json"
    ).read_bytes()
    M.promote_niche_to_inventory(tmp_path)
    assert (tmp_path / "niche_identity_debt.json").read_bytes() == (
        first_lifecycle_bytes
    )


def test_zero_action_source_is_in_live_source_snapshot_denominator(
    tmp_path: Path,
) -> None:
    _inventory(tmp_path)
    source = tmp_path / "niche_empty_findings.md"
    source.write_text("# Niche review\n\nNo findings.\n", encoding="utf-8")
    assert M.promote_niche_to_inventory(tmp_path) == (0, 0)
    payload = M.read_niche_identity_debt_sidecar(tmp_path)
    assert payload is not None
    assert payload["source_namespace"] == [source.name]
    assert [row["source_file"] for row in payload["source_snapshots"]] == [
        source.name
    ]


@pytest.mark.parametrize(
    "header,row",
    (
        (
            "| # | Finding ID | Location | Mechanism | Severity |",
            "| 1 | SC-61 | src/X.sol:L1 | registered issue | Medium |",
        ),
        (
            "| Severity | Candidate ID | Location | Description |",
            "| Medium | SC-61 | src/X.sol:L1 | registered issue |",
        ),
        (
            "| Finding ID | Title | Impact |",
            "| SC-61 | registered issue | material protocol harm |",
        ),
        (
            "| Ordinal | Finding ID | Issue Title | Impact Summary |",
            "| 1 | SC-61 | registered issue | material protocol harm |",
        ),
    ),
)
def test_row_only_catalog_resolves_explicit_id_column_by_header(
    tmp_path: Path,
    header: str,
    row: str,
) -> None:
    source = tmp_path / "niche_runtime_findings.md"
    separators = "|" + "|".join(
        "---" for _ in header.strip("|").split("|")
    ) + "|"
    source.write_text(
        "\n".join((header, separators, row, "")), encoding="utf-8"
    )
    assert [
        value["id"] for value in P._parse_depth_finding_blocks(source)
    ] == ["SC-61"]
    assert [
        value["source_id"] for value in M._parse_niche_findings(tmp_path)
    ] == ["SC-61"]


@pytest.mark.parametrize("prefix", ("&NewLine;", "&amp;NewLine;"))
def test_named_structural_newline_entity_is_lexical_not_physical(
    tmp_path: Path,
    prefix: str,
) -> None:
    source = tmp_path / "niche_runtime_findings.md"
    raw = (
        "multibyte café preamble\r\n"
        + prefix
        + _finding("SC-61", "named entity action")
    ).encode("utf-8")
    source.write_bytes(raw)
    rows = P._parse_depth_finding_blocks(source)
    assert [row["id"] for row in rows] == ["SC-61"]
    start = rows[0]["_source_byte_start"]
    end = rows[0]["_source_byte_end"]
    assert 0 <= start < end <= len(raw)
    assert raw[start:end].startswith(prefix.encode("ascii") + b"## Finding")


def test_niche_source_hardlink_alias_is_rejected(tmp_path: Path) -> None:
    _inventory(tmp_path)
    outside = tmp_path.parent / f"{tmp_path.name}-outside.md"
    outside.write_text(_finding("SC-61", "outside alias"), encoding="utf-8")
    source = tmp_path / "niche_runtime_findings.md"
    try:
        os.link(outside, source)
    except OSError as exc:
        pytest.skip(f"hardlink creation unavailable: {exc}")
    try:
        with pytest.raises((RuntimeError, ValueError), match="link|alias|nlink"):
            M.promote_niche_to_inventory(tmp_path)
    finally:
        outside.unlink(missing_ok=True)


def test_niche_source_symlink_alias_is_rejected(tmp_path: Path) -> None:
    _inventory(tmp_path)
    outside = tmp_path.parent / f"{tmp_path.name}-symlink-outside.md"
    outside.write_text(_finding("SC-61", "outside alias"), encoding="utf-8")
    source = tmp_path / "niche_runtime_findings.md"
    try:
        source.symlink_to(outside)
    except OSError as exc:
        outside.unlink(missing_ok=True)
        pytest.skip(f"symlink creation unavailable: {exc}")
    try:
        with pytest.raises((RuntimeError, ValueError), match="link|reparse"):
            M.promote_niche_to_inventory(tmp_path)
    finally:
        source.unlink(missing_ok=True)
        outside.unlink(missing_ok=True)


def test_niche_namespace_uses_casefold_stable_order(tmp_path: Path) -> None:
    _inventory(tmp_path)
    upper = tmp_path / "niche_Zeta_findings.md"
    lower = tmp_path / "niche_alpha_findings.md"
    upper.write_text("# Empty\n", encoding="utf-8")
    lower.write_text("# Empty\n", encoding="utf-8")
    assert M.promote_niche_to_inventory(tmp_path) == (0, 0)
    payload = M.read_niche_identity_debt_sidecar(tmp_path)
    assert payload is not None
    assert payload["source_namespace"] == [lower.name, upper.name]


def test_rehashed_delivered_lifecycle_requires_live_inventory_referent(
    tmp_path: Path,
) -> None:
    source = tmp_path / "niche_runtime_findings.md"
    source.write_text(_finding("SC-61", "undelivered action"), encoding="utf-8")
    M.promote_niche_to_inventory(tmp_path)
    source.write_text("# Empty\n", encoding="utf-8")
    M.promote_niche_to_inventory(tmp_path)
    sidecar = tmp_path / "niche_identity_debt.json"
    payload = json.loads(sidecar.read_text(encoding="utf-8"))
    removed = next(
        row
        for row in payload["source_errors"]
        if row["status"] == "SOURCE_ACTION_REMOVED"
    )
    lifecycle = {
        key: value
        for key, value in removed.items()
        if key
        not in {
            "debt_id", "record_sha256", "identity_debt", "required_action",
            "resolution_status", "identity_authority", "quarantine",
        }
    }
    lifecycle.update({
        "status": "DELIVERED_ACTION_REMOVED",
        "blocking": False,
        "inventory_referents": ["INV-999"],
    })
    record_hash = M._niche_identity_debt_digest(lifecycle)
    lifecycle["record_sha256"] = record_hash
    lifecycle["lifecycle_id"] = f"NIDLIFE-{record_hash[:24].upper()}"
    payload["source_errors"] = []
    payload["source_error_count"] = 0
    payload["blocking_debt_count"] = 0
    payload["lifecycle_records"] = [lifecycle]
    payload["lifecycle_count"] = 1
    payload["lifecycle_set_sha256"] = M._niche_lifecycle_set_digest(
        payload["lifecycle_records"]
    )
    payload["removed_action_count"] = 1
    payload["removed_action_set_sha256"] = M._niche_removed_action_set_digest(
        payload["source_errors"], payload["lifecycle_records"]
    )
    _publish_rehashed_payload(sidecar, payload)
    with pytest.raises(RuntimeError, match="live lifecycle delivery"):
        M.read_niche_identity_debt_sidecar(tmp_path)


def test_driver_attestation_binds_removed_action_tombstone_digest(
    tmp_path: Path,
) -> None:
    source = tmp_path / "niche_runtime_findings.md"
    source.write_text(_finding("SC-61", "undelivered action"), encoding="utf-8")
    M.promote_niche_to_inventory(tmp_path)
    source.write_text("# Empty\n", encoding="utf-8")
    M.promote_niche_to_inventory(tmp_path)
    sidecar = tmp_path / "niche_identity_debt.json"
    payload = M.read_niche_identity_debt_sidecar(tmp_path)
    assert payload is not None
    result = {
        "parsed": 0,
        "appended": 0,
        "identity_debt_artifact": sidecar.name,
        "identity_debt_sha256": payload["artifact_sha256"],
        "identity_debt_count": payload["blocking_debt_count"],
        "identity_debt_candidate_count": payload["candidate_count"],
        "identity_debt_source_error_count": payload["source_error_count"],
        "identity_debt_denominator_complete": payload["denominator_complete"],
        "identity_debt_action_count": payload["action_count"],
        "identity_debt_action_set_sha256": payload["action_set_sha256"],
        "identity_debt_live_action_denominator_sha256": payload[
            "live_action_denominator_sha256"
        ],
        "identity_debt_source_namespace": payload["source_namespace"],
        "identity_debt_source_namespace_sha256": payload[
            "source_namespace_sha256"
        ],
        "identity_debt_source_snapshots": payload["source_snapshots"],
        "identity_debt_lifecycle_count": payload["lifecycle_count"],
        "identity_debt_lifecycle_set_sha256": payload[
            "lifecycle_set_sha256"
        ],
        "identity_debt_removed_action_count": payload[
            "removed_action_count"
        ],
        "identity_debt_removed_action_set_sha256": payload[
            "removed_action_set_sha256"
        ],
        "identity_debt_validation_status": "LIVE_VALIDATED",
    }
    forged = json.loads(sidecar.read_text(encoding="utf-8"))
    forged["source_errors"] = []
    forged["source_error_count"] = 0
    forged["blocking_debt_count"] = 0
    forged["removed_action_count"] = 0
    forged["removed_action_set_sha256"] = M._niche_removed_action_set_digest(
        [], forged["lifecycle_records"]
    )
    _publish_rehashed_payload(sidecar, forged)
    valid, reason = D._depth_processor_outcome_valid(
        tmp_path,
        "niche_promotion",
        {
            "status": "COMPLETE",
            "result": result,
            "outcome": {"inventory_referents": []},
        },
    )
    assert valid is False
    assert "identity-debt binding changed" in reason


def test_delivered_removed_action_reblocks_if_inventory_referent_vanishes(
    tmp_path: Path,
) -> None:
    _inventory(tmp_path)
    source = tmp_path / "niche_runtime_findings.md"
    source.write_text(_finding("SC-61", "delivered action"), encoding="utf-8")
    assert M.promote_niche_to_inventory(tmp_path) == (1, 1)
    source.write_text("# Empty\n", encoding="utf-8")
    M.promote_niche_to_inventory(tmp_path)
    delivered = M.read_niche_identity_debt_sidecar(tmp_path)
    assert delivered is not None
    old_identity = delivered["lifecycle_records"][0][
        "source_action_identity"
    ]

    _inventory(tmp_path)
    M.promote_niche_to_inventory(tmp_path)
    reblocked = M.read_niche_identity_debt_sidecar(tmp_path)
    assert reblocked is not None
    assert any(
        row.get("status") == "SOURCE_ACTION_REMOVED"
        and row.get("source_action_identity") == old_identity
        for row in reblocked["source_errors"]
    )
    assert reblocked["lifecycle_records"] == []
