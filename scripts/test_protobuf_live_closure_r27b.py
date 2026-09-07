"""R27B live protobuf installed-closure totality contracts."""
from __future__ import annotations

import base64
from importlib import metadata, util
import hashlib
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

import audit_snapshot as SNAP


_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = _ROOT / "verification_policy" / "protobuf_reviewed_content.v1.json"
_LOCK = _ROOT / "verification_policy" / "toolchain_version_lock.v1.json"
_EXPECTED_FIXTURE_CLOSURE = {
    "distribution_bytes": 8728,
    "distribution_file_count": 61,
    "distribution_files_sha256": (
        "501a33c19a5dbe66c2a9aeb2de6a735ef6ba2306ba038d9dfb152590be6fb722"
    ),
    "distribution_path_set_sha256": (
        "8105d7a9f5c967367169a8c3710fcf50cf8bcb16ecc279d2d641b63336247e1b"
    ),
    "module_sha256": (
        "c88a4079eb0414669a03b14bac494e49e78b565e8fdaf77d7fb0260ac192d159"
    ),
    "record_normalized_rows_sha256": (
        "6b8df5ed5153d0929d27c3b0c4a361dc4d1d23a5f738f15e4b6590ed423e01f5"
    ),
    "record_row_count": 61,
    "record_sha256": (
        "1a081b85ed83a87db4b705f2e0b50edb7f6874b7e5ad3679af30697590ba9a8a"
    ),
}


def _copy_install(tmp_path: Path) -> Path:
    """Build a deterministic RECORD-complete distribution under pytest's root."""

    installed = tmp_path / "installed"
    evidence = json.loads(_EVIDENCE.read_text(encoding="utf-8"))
    members = [
        str(row["path"])
        for row in evidence["installed_closure"]["members"]
    ]
    assert len(members) == 61
    record_relative = "protobuf-7.35.1.dist-info/RECORD"
    assert record_relative in members
    for relative in members:
        if relative == record_relative:
            continue
        path = installed / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative == "protobuf-7.35.1.dist-info/METADATA":
            raw = (
                b"Metadata-Version: 2.1\n"
                b"Name: protobuf\n"
                b"Version: 7.35.1\n"
            )
        elif relative == "google/protobuf/__init__.py":
            raw = (
                b'"""Hermetic protobuf closure fixture."""\n'
                b'__version__ = "7.35.1"\n'
            )
        else:
            raw = f"plamen-r27b-fixture:{relative}\n".encode("utf-8")
        path.write_bytes(raw)

    record_lines = []
    for relative in sorted(members):
        if relative == record_relative:
            record_lines.append(f"{relative},,")
            continue
        raw = (installed / relative).read_bytes()
        digest = base64.urlsafe_b64encode(
            hashlib.sha256(raw).digest()
        ).decode("ascii").rstrip("=")
        record_lines.append(f"{relative},sha256={digest},{len(raw)}")
    record = installed / record_relative
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text("\n".join(record_lines) + "\n", encoding="utf-8")
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
    audit_target = installed.parent / "audit-target"
    audit_target.mkdir(exist_ok=True)
    return SNAP._python_distribution_closure(
        "protobuf",
        "google.protobuf",
        project_root=audit_target,
    )


def _locked_row() -> dict:
    payload = json.loads(_LOCK.read_text(encoding="utf-8"))
    row = next(
        row for row in payload["identities"]
        if row["identity_id"] == "protobuf"
    )
    fields = {
        "record": "record_sha256",
        "normalized_record_rows": "record_normalized_rows_sha256",
        "distribution_path_set": "distribution_path_set_sha256",
        "distribution_files": "distribution_files_sha256",
        "module": "module_sha256",
    }
    for reviewed in row["content_authority"]["reviewed_content_sha256"]:
        field = fields.get(reviewed["content_kind"])
        if field is not None:
            reviewed["sha256"] = _EXPECTED_FIXTURE_CLOSURE[field]
    return row


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
    assert {
        key: closure[key] for key in _EXPECTED_FIXTURE_CLOSURE
    } == _EXPECTED_FIXTURE_CLOSURE
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
