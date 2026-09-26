"""Archive-free source closure must remain exact without blessing partial runtimes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil

import pytest

import toolchain_control_authority as authority


ROOT = Path(__file__).resolve().parents[1]
POLICY = Path("verification_policy/js_toolchain_acquisition.v1.json")


def _archive_free_root(tmp_path: Path) -> Path:
    root = tmp_path.resolve() / "source"
    target = root / POLICY
    target.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / POLICY, target)
    return root


def test_archive_free_source_uses_only_pinned_acquisition_rows(tmp_path: Path) -> None:
    root = _archive_free_root(tmp_path)
    identities = authority._acquired_runtime_assets(root)
    files = tuple(sorted((POLICY.as_posix(), *identities)))
    rows = authority._runtime_asset_rows_for_files(root, files)
    by_path = {row["path"]: row for row in rows}
    assert len(identities) == 7
    assert set(by_path) == set(files)
    for relative, identity in identities.items():
        assert by_path[relative] == {
            "digest_mode": "raw-v1",
            "kind": "runtime-data",
            "path": relative,
            "sha256": identity["sha256"],
        }
    assert by_path[POLICY.as_posix()]["sha256"] == hashlib.sha256(
        (root / POLICY).read_bytes()
    ).hexdigest()


def test_partial_acquisition_is_rejected(tmp_path: Path) -> None:
    root = _archive_free_root(tmp_path)
    first = next(iter(authority._acquired_runtime_assets(root)))
    archive = root / first
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"not an archive")
    with pytest.raises(authority.ToolchainControlError, match="partial"):
        authority._acquired_runtime_assets(root)


def test_acquisition_policy_tamper_is_rejected(tmp_path: Path) -> None:
    root = _archive_free_root(tmp_path)
    policy = root / POLICY
    payload = json.loads(policy.read_text(encoding="utf-8"))
    payload["artifacts"][0]["sha256"] = "0" * 64
    policy.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(authority.ToolchainControlError, match="policy differs"):
        authority._acquired_runtime_assets(root)


def test_absent_archive_rejects_case_aliased_ancestor(tmp_path: Path) -> None:
    root = _archive_free_root(tmp_path)
    (root / "Runtime").mkdir()
    relative = next(iter(authority._acquired_runtime_assets(root)))
    index = authority._RuntimePathIndex(root)
    with pytest.raises(authority.ToolchainControlError, match="case alias"):
        authority._require_absent_runtime_spelling(
            root, relative, "archive", path_index=index
        )


def test_installed_runtime_still_requires_archive_bytes(tmp_path: Path) -> None:
    root = _archive_free_root(tmp_path)
    archives = authority._acquired_runtime_assets(root)
    assert set(archives).issubset(authority.runtime_required_missing(root))
