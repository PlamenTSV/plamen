"""R27B live protobuf installed-closure totality contracts."""
from __future__ import annotations

from importlib import metadata, util
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

import audit_snapshot as SNAP


_ROOT = Path(__file__).resolve().parents[1]
_SOURCE = Path(r"C:\p27a\installed2")
_EVIDENCE = _ROOT / "verification_policy" / "protobuf_reviewed_content.v1.json"
_LOCK = _ROOT / "verification_policy" / "toolchain_version_lock.v1.json"


def _copy_install(tmp_path: Path) -> Path:
    assert _SOURCE.is_dir()
    installed = tmp_path / "installed"
    shutil.copytree(_SOURCE, installed)
    return installed


def _select_install(installed: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    selected = [
        item
        for item in metadata.distributions(path=[str(installed)])
        if str(item.metadata.get("Name") or "").casefold() == "protobuf"
    ]
    monkeypatch.setattr(metadata, "distributions", lambda: list(selected))
    monkeypatch.setattr(
        util,
        "find_spec",
        lambda name: SimpleNamespace(
            origin=str(installed / "google" / "protobuf" / "__init__.py")
        ) if name == "google.protobuf" else None,
    )


def _closure(installed: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    _select_install(installed, monkeypatch)
    return SNAP._python_distribution_closure("protobuf", "google.protobuf")


def _locked_row() -> dict:
    payload = json.loads(_LOCK.read_text(encoding="utf-8"))
    return next(
        row for row in payload["identities"]
        if row["identity_id"] == "protobuf"
    )


def _reviewed_observation(closure: dict) -> dict:
    evidence = json.loads(_EVIDENCE.read_text(encoding="utf-8"))
    observed = {
        "wheel_filename": evidence["wheel"]["filename"],
        "wheel_python_tag": evidence["wheel"]["python_tag"],
        "wheel_abi_tag": evidence["wheel"]["abi_tag"],
        "wheel_platform_tag": evidence["wheel"]["platform_tag"],
        "wheel_sha256": evidence["wheel"]["sha256"],
        "generated_module_sha256": evidence["generated_module"]["sha256"],
    }
    observed.update(closure)
    return observed


def test_exact_installed_protobuf_live_closure_remains_match(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closure = _closure(_copy_install(tmp_path), monkeypatch)
    assert closure["distribution_file_count"] == 61
    assert SNAP._reviewed_python_distribution_content_status(
        _locked_row(), _reviewed_observation(closure)
    ) == ("MATCH", True, ())


@pytest.mark.parametrize(
    "relative",
    (
        "google/protobuf/r27b_unrecorded.py",
        "google/_upb/r27b_unrecorded.pyd",
        "protobuf-7.35.1.dist-info/R27B-EXTRA",
    ),
)
def test_unrecorded_member_under_each_governed_root_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
) -> None:
    installed = _copy_install(tmp_path)
    path = installed / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"unrecorded protobuf member\n")
    with pytest.raises(SNAP.SnapshotInputError, match="unrecorded|denominator"):
        _closure(installed, monkeypatch)


def test_recorded_member_case_alias_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed = _copy_install(tmp_path)
    source = installed / "google" / "protobuf" / "any.py"
    hop = source.with_name("r27b-case-hop")
    alias = source.with_name("ANY.py")
    source.rename(hop)
    hop.rename(alias)
    with pytest.raises(SNAP.SnapshotInputError, match="alias|denominator"):
        _closure(installed, monkeypatch)


def test_unrecorded_symlink_or_reparse_member_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed = _copy_install(tmp_path)
    target = installed / "outside.py"
    target.write_bytes(b"outside\n")
    link = installed / "google" / "protobuf" / "r27b_link.py"
    os.symlink(target, link)
    with pytest.raises(SNAP.SnapshotInputError, match="reparse|symlink|denominator"):
        _closure(installed, monkeypatch)


def test_stale_extra_protobuf_dist_info_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed = _copy_install(tmp_path)
    shutil.copytree(
        installed / "protobuf-7.35.1.dist-info",
        installed / "protobuf-6.33.6.dist-info",
    )
    with pytest.raises(SNAP.SnapshotInputError, match="ambiguous|unreadable"):
        _closure(installed, monkeypatch)


@pytest.mark.parametrize("operation", ("missing", "changed"))
def test_record_member_missing_or_changed_remains_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    installed = _copy_install(tmp_path)
    member = installed / "google" / "protobuf" / "any.py"
    if operation == "missing":
        member.unlink()
    else:
        member.write_bytes(member.read_bytes() + b"\nchanged\n")
    with pytest.raises(
        SNAP.SnapshotInputError,
        match="missing|drifted|unreadable|denominator",
    ):
        _closure(installed, monkeypatch)
