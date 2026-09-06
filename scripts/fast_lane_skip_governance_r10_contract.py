"""Executable contract for the R10 fast-lane quarantine manifest.

The filename intentionally does not match pytest's recursive ``test_*.py``
pattern.  It is a directly invocable governance gate and therefore does not
change the frozen 15,889-node production denominator.
"""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import tomllib

import pytest

import conftest as governance


def _manifest() -> dict:
    return governance._load_fast_governance_manifest()


def test_manifest_exact_counts_rosters_and_policy() -> None:
    manifest = _manifest()
    assert manifest["schema"] == "plamen.fast-lane-skip-governance.v1"
    assert manifest["counts"] == {
        "expanded_pytest_skip_sites": 132,
        "expanded_skipif_sites": 106,
        "guaranteed_current_nodes": 17,
        "quarantine_nodes": 168,
        "source_files": len(manifest["sources"]),
        "unresolved_runtime_nodes": 151,
    }
    assert manifest["hashes"]["guaranteed_nodes_sha256"] == (
        "1d15ca6442a2c751d36275be053a7673facf3b51ea63f36fbaf4b96b4c50126b"
    )
    assert manifest["hashes"]["unresolved_nodes_sha256"] == (
        "3176c06f7446119f92bdd97eb4f2482f620ffff7474558665ded06cf95e7a874"
    )
    assert manifest["hashes"]["quarantine_nodes_sha256"] == (
        "29bdd0de57165822ae1472f57de64d272a30617a14c5fb654ac5ffae2158e98b"
    )
    assert manifest["hashes"]["governed_production_nodes_sha256"] == (
        "76364b33eaea680c8a282f93d87a8406b046a039fb682bcd673dc9947c748ef5"
    )
    assert manifest["platform_policy"] == {
        "logical_integration_selector": "integration",
        "posix_integration_selector": "integration",
        "production_selector": "not integration and not fast_quarantine",
        "supported_os_names": ["nt", "posix"],
        "unknown_os_name": "abort_collection",
        "windows_integration_selector": "integration and not posix_only",
    }


def test_manifest_file_and_canonical_submanifest_hashes_are_exact() -> None:
    manifest_path = Path(governance.__file__).with_name(
        "fast_lane_skip_governance_r10.json"
    )
    assert hashlib.sha256(manifest_path.read_bytes()).hexdigest() == (
        governance._FAST_GOVERNANCE_MANIFEST_SHA256
    )
    manifest = _manifest()
    assert hashlib.sha256(
        governance._canonical_source_roster(manifest["sources"])
    ).hexdigest() == manifest["hashes"]["source_roster_sha256"]
    assert hashlib.sha256(
        governance._canonical_entry_roster(manifest["entries"])
    ).hexdigest() == manifest["hashes"]["entry_roster_sha256"]


def test_all_narrow_governance_markers_are_registered() -> None:
    pyproject = Path(governance.__file__).parent.parent / "pyproject.toml"
    configured = tomllib.loads(pyproject.read_text(encoding="utf-8"))[
        "tool"
    ]["pytest"]["ini_options"]["markers"]
    names = {row.split(":", 1)[0] for row in configured}
    assert names >= governance._FAST_GOVERNANCE_MARKERS | {"fast_quarantine"}


def test_manifest_rejects_unknown_platform_and_malformed_policy() -> None:
    assert governance._require_supported_os_name("nt") == "nt"
    assert governance._require_supported_os_name("posix") == "posix"
    with pytest.raises(pytest.UsageError, match="unsupported os.name"):
        governance._require_supported_os_name("unsupported-fixture")

    manifest = _manifest()
    malformed = copy.deepcopy(manifest)
    malformed["platform_policy"]["supported_os_names"] = ["nt", "mystery"]
    with pytest.raises(pytest.UsageError, match="platform_policy"):
        governance._validate_fast_governance_payload(
            malformed, verify_sources=False
        )


def test_manifest_rejects_duplicate_case_collision_and_source_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest()

    duplicate = copy.deepcopy(manifest)
    duplicate["entries"].append(copy.deepcopy(duplicate["entries"][0]))
    with pytest.raises(pytest.UsageError, match="duplicate"):
        governance._validate_fast_governance_payload(
            duplicate, verify_sources=False
        )

    collision = copy.deepcopy(manifest)
    collision["entries"][1]["nodeid"] = collision["entries"][0][
        "nodeid"
    ].swapcase()
    with pytest.raises(pytest.UsageError, match="case-collision"):
        governance._validate_fast_governance_payload(
            collision, verify_sources=False
        )

    expected = manifest["sources"][0]["sha256"]
    monkeypatch.setattr(
        governance,
        "_sha256_file",
        lambda _path: "0" * 64 if expected != "0" * 64 else "1" * 64,
    )
    with pytest.raises(pytest.UsageError, match="source hash drift"):
        governance._validate_fast_governance_payload(
            manifest, verify_sources=True
        )


def test_private_source_roster_is_all_present_or_all_absent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    expected = {row["path"]: row["sha256"] for row in manifest["sources"]}

    monkeypatch.setattr(governance, "_REPO_ROOT", tmp_path)
    monkeypatch.setattr(
        governance,
        "_sha256_file",
        lambda path: expected[path.relative_to(tmp_path).as_posix()],
    )
    governance._validate_fast_governance_payload(manifest, verify_sources=True)

    one_private_path = sorted(
        governance._FAST_GOVERNANCE_PRIVATE_SOURCE_PATHS
    )[0]
    materialized = tmp_path / one_private_path
    materialized.parent.mkdir(parents=True, exist_ok=True)
    materialized.write_bytes(b"private-source-fixture")
    with pytest.raises(pytest.UsageError, match="materialization is partial"):
        governance._validate_fast_governance_payload(
            manifest, verify_sources=True
        )


class _Config:
    def __init__(self, args: list[str]):
        self.args = args


class _Item:
    def __init__(self, nodeid: str):
        self.nodeid = nodeid
        self.fspath = nodeid.split("::", 1)[0]
        self.markers: list[str] = []

    def add_marker(self, marker) -> None:
        self.markers.append(marker.name)


def test_marker_application_is_exact_and_partial_direct_collection_survives() -> None:
    manifest = _manifest()
    quarantined = manifest["entries"][0]
    ordinary = "scripts/test_test_infrastructure_contracts.py::test_unit_and_integration_sets_are_disjoint"
    items = [_Item(quarantined["nodeid"]), _Item(ordinary)]
    governance._apply_fast_governance(
        _Config([quarantined["nodeid"]]), items, manifest
    )
    assert items[0].markers == ["fast_quarantine", *quarantined["markers"]]
    assert items[1].markers == []


def test_complete_collection_rejects_missing_manifest_identity() -> None:
    manifest = _manifest()
    with pytest.raises(pytest.UsageError, match="missing quarantine identities"):
        governance._apply_fast_governance(
            _Config(["scripts", "tests"]),
            [_Item(manifest["entries"][0]["nodeid"])],
            manifest,
        )


def test_json_duplicate_keys_are_rejected() -> None:
    with pytest.raises(pytest.UsageError, match="duplicate JSON key"):
        governance._decode_fast_governance_json(
            b'{"schema":"one","schema":"two"}'
        )
