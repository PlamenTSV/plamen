from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from axis_canonical_prior import (
    AUTHORITY_NAME,
    SNAPSHOT_NAME,
    AxisCanonicalPriorError,
    capture_axis_canonical_prior_authority,
    load_axis_canonical_prior_authority,
)


RUN_ID = "8bc3bca7-f4e0-4bcc-92af-d83168071b8f"
WORKLIST_HASH = "a" * 64


def _finding(identity: str, title: str, location: str) -> str:
    return (
        f"### Finding [{identity}]: {title}\n"
        "**Severity**: Low\n"
        f"**Location**: {location}\n"
        "**Description**: deterministic fixture candidate\n"
        "**Impact**: bounded fixture impact\n"
    )


def _capture(root: Path):
    return capture_axis_canonical_prior_authority(
        root,
        run_id=RUN_ID,
        worklist_hash=WORKLIST_HASH,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
    )


def _load(root: Path):
    return load_axis_canonical_prior_authority(
        root,
        expected_run_id=RUN_ID,
        expected_worklist_hash=WORKLIST_HASH,
        expected_pipeline="sc",
        expected_mode="thorough",
        expected_ecosystem="evm",
    )


def test_exact_capture_is_idempotent_and_ignores_later_global_drift(
    tmp_path: Path,
) -> None:
    inventory = tmp_path / "findings_inventory.md"
    inventory.write_text(
        _finding("INV-001", "pre-axis candidate", "contracts/A.sol:L7"),
        encoding="utf-8",
        newline="\n",
    )

    first = _capture(tmp_path)
    before = {
        SNAPSHOT_NAME: (tmp_path / SNAPSHOT_NAME).read_bytes(),
        AUTHORITY_NAME: (tmp_path / AUTHORITY_NAME).read_bytes(),
    }
    assert first.status == "EXACT"
    assert "INV-001" in first.aliases
    manifest = first.snapshot["source_artifacts"]
    assert manifest == [
        {
            "capture_state": "CAPTURED",
            "issue": "",
            "relative_path": "findings_inventory.md",
            "sha256": __import__("hashlib").sha256(
                inventory.read_bytes()
            ).hexdigest(),
            "size_bytes": len(inventory.read_bytes()),
        }
    ]

    inventory.write_text(
        inventory.read_text(encoding="utf-8")
        + "\n"
        + _finding("INV-002", "post-axis candidate", "contracts/B.sol:L9"),
        encoding="utf-8",
        newline="\n",
    )
    # These mutable general projections are deliberately unrelated to replay.
    (tmp_path / "_canonical_finding_ids.json").write_text(
        '{"schema_version":"drift"}\n', encoding="utf-8"
    )
    (tmp_path / "exploration_clear_prior_aliases.json").write_text(
        '{"schema_version":"drift"}\n', encoding="utf-8"
    )

    loaded = _load(tmp_path)
    second = _capture(tmp_path)
    assert loaded == second == first
    assert "INV-001" in loaded.aliases
    assert "INV-002" not in loaded.aliases
    assert {
        SNAPSHOT_NAME: (tmp_path / SNAPSHOT_NAME).read_bytes(),
        AUTHORITY_NAME: (tmp_path / AUTHORITY_NAME).read_bytes(),
    } == before


def test_ambiguous_short_aliases_are_not_clear_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "analysis_a.md").write_text(
        _finding("H-01", "first mechanism", "contracts/A.sol:L2"),
        encoding="utf-8",
    )
    (tmp_path / "analysis_b.md").write_text(
        _finding("H-01", "different mechanism", "contracts/B.sol:L3"),
        encoding="utf-8",
    )

    authority = _capture(tmp_path)

    assert authority.status == "EXACT"
    assert "H-01" not in authority.aliases
    assert len(authority.ambiguous_aliases["H-01"]) == 2
    assert authority.aliases["analysis_a.md:H-01"].startswith("CID-")
    assert authority.aliases["analysis_b.md:H-01"].startswith("CID-")


def test_strict_source_failure_degrades_and_grants_no_aliases(
    tmp_path: Path,
) -> None:
    (tmp_path / "analysis_bad.md").write_bytes(b"\xff\xfe\x00bad")

    authority = _capture(tmp_path)

    assert authority.status == "DEGRADED"
    assert authority.aliases == {}
    assert authority.ambiguous_aliases == {}
    assert authority.debt
    assert authority.snapshot["source_artifacts"][0]["capture_state"] == (
        "UNAVAILABLE"
    )
    assert _load(tmp_path) == authority


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("run_id", "different-run"),
        ("worklist_hash", "b" * 64),
        ("pipeline", "l1"),
        ("mode", "core"),
        ("ecosystem", "soroban"),
    ),
)
def test_authority_binding_mismatch_is_rejected(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    (tmp_path / "findings_inventory.md").write_text(
        _finding("INV-001", "candidate", "contracts/A.sol:L1"),
        encoding="utf-8",
    )
    _capture(tmp_path)
    kwargs = {
        "expected_run_id": RUN_ID,
        "expected_worklist_hash": WORKLIST_HASH,
        "expected_pipeline": "sc",
        "expected_mode": "thorough",
        "expected_ecosystem": "evm",
    }
    kwargs[
        {
            "run_id": "expected_run_id",
            "worklist_hash": "expected_worklist_hash",
            "pipeline": "expected_pipeline",
            "mode": "expected_mode",
            "ecosystem": "expected_ecosystem",
        }[field]
    ] = value

    with pytest.raises(AxisCanonicalPriorError, match="binding"):
        load_axis_canonical_prior_authority(tmp_path, **kwargs)


@pytest.mark.parametrize("artifact_name", (SNAPSHOT_NAME, AUTHORITY_NAME))
def test_tamper_is_rejected(tmp_path: Path, artifact_name: str) -> None:
    (tmp_path / "findings_inventory.md").write_text(
        _finding("INV-001", "candidate", "contracts/A.sol:L1"),
        encoding="utf-8",
    )
    _capture(tmp_path)
    path = tmp_path / artifact_name
    payload = json.loads(path.read_text(encoding="utf-8"))
    if artifact_name == SNAPSHOT_NAME:
        payload["record_count"] += 1
    else:
        payload["status"] = "DEGRADED"
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(AxisCanonicalPriorError):
        _load(tmp_path)


def test_snapshot_only_crash_recovers_without_re_reading_sources(
    tmp_path: Path,
) -> None:
    inventory = tmp_path / "findings_inventory.md"
    inventory.write_text(
        _finding("INV-001", "candidate", "contracts/A.sol:L1"),
        encoding="utf-8",
    )
    expected = _capture(tmp_path)
    expected_snapshot = (tmp_path / SNAPSHOT_NAME).read_bytes()
    expected_authority = (tmp_path / AUTHORITY_NAME).read_bytes()
    (tmp_path / AUTHORITY_NAME).unlink()
    inventory.write_text(
        _finding("INV-999", "later drift", "contracts/Z.sol:L99"),
        encoding="utf-8",
    )

    recovered = _capture(tmp_path)

    assert recovered == expected
    assert (tmp_path / SNAPSHOT_NAME).read_bytes() == expected_snapshot
    assert (tmp_path / AUTHORITY_NAME).read_bytes() == expected_authority


def test_fresh_capture_refuses_after_model_output_exists(
    tmp_path: Path,
) -> None:
    (tmp_path / "findings_inventory.md").write_text(
        _finding("INV-001", "candidate", "contracts/A.sol:L1"),
        encoding="utf-8",
    )
    (tmp_path / "axis_coverage_findings.md").write_text(
        _finding("AXIS-001", "model candidate", "contracts/A.sol:L1"),
        encoding="utf-8",
    )

    with pytest.raises(AxisCanonicalPriorError, match="after axis execution"):
        _capture(tmp_path)
    assert not (tmp_path / SNAPSHOT_NAME).exists()
    assert not (tmp_path / AUTHORITY_NAME).exists()


def test_complete_valid_capture_remains_loadable_after_model_output(
    tmp_path: Path,
) -> None:
    (tmp_path / "findings_inventory.md").write_text(
        _finding("INV-001", "candidate", "contracts/A.sol:L1"),
        encoding="utf-8",
    )
    expected = _capture(tmp_path)
    (tmp_path / "axis_coverage_dispositions.json").write_text(
        "{}\n", encoding="utf-8"
    )
    assert _capture(tmp_path) == expected


def test_snapshot_only_is_not_adopted_after_model_output(
    tmp_path: Path,
) -> None:
    (tmp_path / "findings_inventory.md").write_text(
        _finding("INV-001", "candidate", "contracts/A.sol:L1"),
        encoding="utf-8",
    )
    _capture(tmp_path)
    (tmp_path / AUTHORITY_NAME).unlink()
    (tmp_path / "axis_coverage_findings.md").write_text("", encoding="utf-8")

    with pytest.raises(AxisCanonicalPriorError, match="partial"):
        _capture(tmp_path)


def test_symlinked_authority_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "findings_inventory.md").write_text(
        _finding("INV-001", "candidate", "contracts/A.sol:L1"),
        encoding="utf-8",
    )
    _capture(tmp_path)
    authority = tmp_path / AUTHORITY_NAME
    target = tmp_path / "authority-target.json"
    authority.replace(target)
    try:
        os.symlink(target, authority)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this host")

    with pytest.raises(AxisCanonicalPriorError, match="link|reparse"):
        _load(tmp_path)
