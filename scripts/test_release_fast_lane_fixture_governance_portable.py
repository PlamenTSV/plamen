from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest

import release_fast_lane_fixture_collector as collector
import release_fast_lane_fixture_governance_gate as gate


def _write(root: Path, relative: str, body: bytes = b"def test_ok():\n    pass\n") -> str:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    return hashlib.sha256(body).hexdigest()


def _payload(root: Path) -> dict:
    first = "Temp/a/test_alpha.py"
    second = "review_fixtures/b/test_beta.py"
    rows = [
        {"path": first, "sha256": _write(root, first)},
        {"path": second, "sha256": _write(root, second)},
    ]
    nodes = [f"{first}::test_alpha", f"{second}::test_beta"]
    return {
        "files": rows,
        "authority": {
            "fixture_node_roster": {
                "node_count": len(nodes),
                "sha256": hashlib.sha256(collector.canonical_roster(nodes)).hexdigest(),
                "nodes": nodes,
            }
        },
    }


@pytest.mark.parametrize(
    "bad",
    [
        "/Temp/test_bad.py",
        "C:/Temp/test_bad.py",
        "Temp/../test_bad.py",
        "Temp/./test_bad.py",
        "Temp\\test_bad.py",
    ],
)
def test_absolute_traversal_and_noncanonical_paths_are_rejected(
    tmp_path: Path, bad: str
) -> None:
    payload = _payload(tmp_path)
    payload["files"][0]["path"] = bad
    with pytest.raises(collector.CollectionAuthorityError):
        collector.validate_sources(payload, tmp_path)


def test_source_tamper_and_hardlink_substitution_are_rejected(tmp_path: Path) -> None:
    payload = _payload(tmp_path)
    source = tmp_path / payload["files"][0]["path"]
    source.write_bytes(source.read_bytes() + b"# drift\n")
    with pytest.raises(collector.CollectionAuthorityError, match="hash drift"):
        collector.validate_sources(payload, tmp_path)

    payload = _payload(tmp_path)
    source = tmp_path / payload["files"][0]["path"]
    os.link(source, tmp_path / "second-hardlink.py")
    with pytest.raises(collector.CollectionAuthorityError, match="single-link"):
        collector.validate_sources(payload, tmp_path)


def test_symlink_substitution_is_rejected_when_supported(tmp_path: Path) -> None:
    payload = _payload(tmp_path)
    relative = payload["files"][0]["path"]
    source = tmp_path / relative
    target = tmp_path / "target.py"
    target.write_bytes(source.read_bytes())
    source.unlink()
    try:
        source.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("host does not permit an unprivileged file symlink")
    with pytest.raises(collector.CollectionAuthorityError, match="aliased"):
        collector.validate_sources(payload, tmp_path)


def test_ancestor_replacement_race_cannot_redirect_opened_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repository"
    payload = _payload(root)
    original = root / "Temp" / "a"
    held = root / "Temp" / "a-held"
    external = tmp_path / "external-a"
    external.mkdir()
    shutil.copy2(original / "test_alpha.py", external / "test_alpha.py")

    probe = root / "Temp" / "symlink-probe"
    try:
        probe.symlink_to(external, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("host does not permit an unprivileged directory symlink")
    probe.unlink()

    def replace_ancestor(_root: Path, relative: str) -> None:
        if relative != "Temp/a/test_alpha.py":
            return
        original.rename(held)
        original.symlink_to(external, target_is_directory=True)

    monkeypatch.setattr(collector, "_OPEN_RACE_HOOK", replace_ancestor)
    try:
        with pytest.raises(
            collector.CollectionAuthorityError,
            match="escaped|changed|handle-relative|aliased|not a directory",
        ):
            collector.validate_sources(payload, root)
    finally:
        if original.is_symlink():
            original.unlink()
        if held.exists():
            held.rename(original)


def test_hardlink_relocation_ancestor_race_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repository"
    payload = _payload(root)
    temp = root / "Temp"
    original = temp / "a"
    held = temp / "held-a"
    leaf_name = "test_alpha.py"
    temp_times = temp.stat()

    def relocate_with_single_link(_root: Path, relative: str) -> None:
        if relative != f"Temp/a/{leaf_name}":
            return
        original.rename(held)
        original.mkdir()
        os.link(held / leaf_name, original / leaf_name)
        (held / leaf_name).unlink()
        os.utime(
            temp,
            ns=(temp_times.st_atime_ns, temp_times.st_mtime_ns),
        )
        assert (original / leaf_name).stat().st_nlink == 1

    monkeypatch.setattr(collector, "_OPEN_RACE_HOOK", relocate_with_single_link)
    try:
        with pytest.raises(
            (collector.CollectionAuthorityError, PermissionError, OSError),
            match="ancestor|changed|denied|sharing|identity",
        ):
            collector.validate_sources(payload, root)
    finally:
        new_leaf = original / leaf_name
        if new_leaf.exists() and held.exists():
            new_leaf.rename(held / leaf_name)
        if original.exists():
            original.rmdir()
        if held.exists():
            held.rename(original)


def test_crlf_manifest_is_rejected_before_json_admission(tmp_path: Path) -> None:
    manifest = tmp_path / "scripts" / "manifest.json"
    manifest.parent.mkdir()
    manifest.write_bytes(
        b'{\r\n  "schema_version": '
        b'"plamen.release_fast_lane_fixture_governance.v2"\r\n}\r\n'
    )
    with pytest.raises(collector.CollectionAuthorityError, match="exact LF"):
        collector.load_manifest(tmp_path, manifest)


def test_duplicate_reorder_foreign_and_missing_roster_attacks_fail_closed(
    tmp_path: Path,
) -> None:
    payload = _payload(tmp_path)
    paths = collector.validate_sources(payload, tmp_path)
    collector.validate_committed_roster(payload, paths)

    duplicate = copy.deepcopy(payload)
    duplicate["authority"]["fixture_node_roster"]["nodes"][1] = duplicate[
        "authority"
    ]["fixture_node_roster"]["nodes"][0]
    with pytest.raises(collector.CollectionAuthorityError, match="duplicate"):
        collector.validate_committed_roster(duplicate, paths)

    reordered = copy.deepcopy(payload)
    reordered["authority"]["fixture_node_roster"]["nodes"].reverse()
    with pytest.raises(collector.CollectionAuthorityError, match="count/hash mismatch"):
        collector.validate_committed_roster(reordered, paths)

    foreign = copy.deepcopy(payload)
    foreign_nodes = foreign["authority"]["fixture_node_roster"]["nodes"]
    foreign_nodes[0] = "scripts/test_foreign.py::test_foreign"
    foreign["authority"]["fixture_node_roster"]["sha256"] = hashlib.sha256(
        collector.canonical_roster(foreign_nodes)
    ).hexdigest()
    with pytest.raises(collector.CollectionAuthorityError, match="foreign"):
        collector.validate_committed_roster(foreign, paths)

    missing = copy.deepcopy(payload)
    missing_nodes = missing["authority"]["fixture_node_roster"]["nodes"][:1]
    missing["authority"]["fixture_node_roster"].update(
        node_count=1,
        nodes=missing_nodes,
        sha256=hashlib.sha256(collector.canonical_roster(missing_nodes)).hexdigest(),
    )
    with pytest.raises(collector.CollectionAuthorityError, match="omits"):
        collector.validate_committed_roster(missing, paths)


def test_committed_manifest_is_lf_utf8_source_exact_and_runtime_packaged() -> None:
    raw = gate.MANIFEST.read_bytes()
    assert raw.endswith(b"\n") and b"\r" not in raw
    raw.decode("utf-8")
    payload = collector.load_manifest(gate.REPO, gate.MANIFEST)
    paths = collector.validate_sources(payload, gate.REPO)
    nodes, digest = collector.validate_committed_roster(payload, paths)
    assert (len(paths), len(nodes), digest) == (
        72,
        1036,
        "9b746138049fdea6fe73a1a6b3101b407a0302b522997bfdd403c0919effc4ac",
    )
    assert gate.PLAMEN_RUNTIME_ASSETS == (
        {
            "kind": "control",
            "mode": "file",
            "path": "scripts/release_fast_lane_fixture_governance_manifest.json",
        },
    )


def test_authority_metadata_contains_no_external_dereference_path() -> None:
    payload = collector.load_manifest(gate.REPO, gate.MANIFEST)
    authority = copy.deepcopy(payload["authority"])
    # Pytest parameter values inside canonical node IDs are opaque identities,
    # not authority paths.  Exclude only that list from path-metadata checks.
    authority["fixture_node_roster"].pop("nodes")
    serialized = json.dumps(authority, sort_keys=True, separators=(",", ":"))
    assert ".scratchpad" not in serialized
    assert "AppData" not in serialized
    assert not re.search(r"(?i)[a-z]:[\\/]", serialized)
    assert not re.search(r"(?i)(?:^|[\\/])temp[\\/]", serialized)

    pending = [authority]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            assert "path" not in value
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)

    for name in (
        "classification_audit",
        "classification_audit_r2",
        "partition_plan",
        "post_collection_repair",
    ):
        assert authority[name]["evidence_policy"] == (
            "HISTORICAL_HASH_ONLY_NON_DEREFERENCED"
        )


def test_gate_passes_from_clean_shipped_copy_without_scratch_evidence(
    tmp_path: Path,
) -> None:
    payload = collector.load_manifest(gate.REPO, gate.MANIFEST)
    clean = tmp_path / "clean-package"
    for relative in (
        "pyproject.toml",
        "scripts/release_fast_lane_fixture_collector.py",
        "scripts/release_fast_lane_fixture_governance_gate.py",
        "scripts/release_fast_lane_fixture_governance_manifest.json",
        *(row["path"] for row in payload["files"]),
    ):
        source = gate.REPO / relative
        destination = clean / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    assert not (clean / ".scratchpad").exists()
    environment = collector._fixed_subprocess_environment()
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            (
                "import runpy,sys;"
                f"sys.path.insert(0,{str(clean)!r});"
                "runpy.run_module('pytest',run_name='__main__')"
            ),
            "--noconftest",
            "-q",
            "-o",
            "addopts=",
            "-p",
            "no:cacheprovider",
            "scripts/release_fast_lane_fixture_governance_gate.py",
        ],
        cwd=clean,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, (
        completed.stdout + b"\n" + completed.stderr
    ).decode("utf-8", errors="replace")
