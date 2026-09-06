from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile

import pytest

import audit_snapshot as SNAP
import toolchain_control_authority as CONTROL


_ROOT = Path(__file__).resolve().parents[1]
_LOCK = _ROOT / "verification_policy" / "toolchain_version_lock.v1.json"
_GOVERNANCE = _ROOT / "verification_policy" / "toolchain_governance.v1.json"
_EVIDENCE = _ROOT / "verification_policy" / "protobuf_reviewed_content.v1.json"
_WHEEL_FILENAME = "protobuf-7.35.1-cp310-abi3-win_amd64.whl"
_WHEEL_SHA256 = "230a75ddfc2de4806e56696ce9640c1cdfdb6543b7cfce98d42a4c0a0e7bdb87"
_NON_PROTOBUF_LOCK_ROWS_SHA256 = (
    "5e24956deb4de88c8f7b404dec2b3d188458e36b430752cf26a5e6bcbf858209"
)
_NON_PROTOBUF_GOVERNANCE_ROWS_SHA256 = (
    "53d465d09916204e091fdc58373f88934c617cb7aee3dc01b15445a47e71d4b5"
)


def _row(payload: dict, key: str, value: str) -> dict:
    return next(row for row in payload[key] if row[value] == "protobuf")


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _reject_physical_alias(path: Path) -> None:
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode)
    assert not path.is_symlink()
    assert int(getattr(info, "st_nlink", 1)) == 1
    assert not (
        int(getattr(info, "st_file_attributes", 0))
        & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    )


def build_reviewed_content_evidence(wheel: Path, installed: Path) -> dict:
    wheel = wheel.resolve(strict=True)
    installed = installed.resolve(strict=True)
    assert wheel.name == _WHEEL_FILENAME
    assert wheel.stat().st_size == 439996
    assert _sha(wheel) == _WHEEL_SHA256
    _reject_physical_alias(wheel)

    dist_info = installed / "protobuf-7.35.1.dist-info"
    assert dist_info.is_dir()
    assert [path.name for path in installed.glob("protobuf-*.dist-info")] == [
        "protobuf-7.35.1.dist-info"
    ]
    record_path = dist_info / "RECORD"
    _reject_physical_alias(record_path)
    record_raw = record_path.read_bytes()
    record_csv = list(
        csv.reader(record_raw.decode("utf-8", "strict").splitlines())
    )
    assert record_csv and all(len(row) == 3 for row in record_csv)
    normalized_rows: list[dict[str, object]] = []
    record_paths: list[str] = []
    for relative, digest, size_text in record_csv:
        relative = relative.replace("\\", "/")
        assert relative and not relative.startswith("/")
        assert ".." not in Path(relative).parts
        member = (installed / relative).resolve(strict=True)
        member.relative_to(installed)
        _reject_physical_alias(member)
        raw = member.read_bytes()
        if digest:
            assert digest.startswith("sha256=") and size_text.isdigit()
            expected = base64.urlsafe_b64encode(
                hashlib.sha256(raw).digest()
            ).decode("ascii").rstrip("=")
            assert digest == f"sha256={expected}"
            assert int(size_text) == len(raw)
            size: int | None = int(size_text)
        else:
            assert (
                relative == "protobuf-7.35.1.dist-info/RECORD"
                or "__pycache__" in Path(relative).parts
                or relative.endswith((".pyc", ".pyo"))
            )
            size = None
        normalized_rows.append(
            {"path": relative, "hash": digest, "bytes": size}
        )
        record_paths.append(relative)
    assert len(record_paths) == len(set(record_paths))
    disk_paths = sorted(
        path.relative_to(installed).as_posix()
        for path in installed.rglob("*")
        if path.is_file()
    )
    assert sorted(record_paths) == disk_paths
    normalized_rows.sort(key=lambda row: str(row["path"]))

    members: list[dict[str, object]] = []
    for row in normalized_rows:
        relative = str(row["path"])
        if (
            "__pycache__" in Path(relative).parts
            or relative.endswith((".pyc", ".pyo"))
        ):
            continue
        member = installed / relative
        raw = member.read_bytes()
        members.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "bytes": len(raw),
            }
        )
    members.sort(key=lambda row: str(row["path"]))
    path_set = hashlib.sha256()
    contents = hashlib.sha256()
    logical_bytes = 0
    for member in members:
        encoded = str(member["path"]).encode("utf-8")
        size = int(member["bytes"])
        path_set.update(len(encoded).to_bytes(8, "big"))
        path_set.update(encoded)
        contents.update(len(encoded).to_bytes(8, "big"))
        contents.update(encoded)
        contents.update(bytes.fromhex(str(member["sha256"])))
        contents.update(size.to_bytes(8, "big"))
        logical_bytes += size

    module_path = installed / "google" / "protobuf" / "__init__.py"
    module_raw = module_path.read_bytes()
    generated_path = _ROOT / "plamen_l1" / "scip_pb2.py"
    generated_raw = generated_path.read_bytes()
    matches = re.findall(
        rb"(?m)^# Protobuf Python Version: "
        rb"([0-9]+\.[0-9]+\.[0-9]+)\s*$",
        generated_raw,
    )
    assert matches == [b"7.34.1"]
    return {
        "schema_version": "plamen.protobuf_reviewed_content.v1",
        "package_name": "protobuf",
        "version": "7.35.1",
        "wheel": {
            "filename": _WHEEL_FILENAME,
            "bytes": 439996,
            "sha256": _WHEEL_SHA256,
            "python_tag": "cp310",
            "abi_tag": "abi3",
            "platform_tag": "win_amd64",
        },
        "record": {
            "path": "protobuf-7.35.1.dist-info/RECORD",
            "bytes": len(record_raw),
            "sha256": hashlib.sha256(record_raw).hexdigest(),
            "row_count": len(normalized_rows),
            "normalized_rows_sha256": hashlib.sha256(
                _canonical(normalized_rows)
            ).hexdigest(),
            "rows": normalized_rows,
        },
        "installed_closure": {
            "file_count": len(members),
            "logical_bytes": logical_bytes,
            "path_set_sha256": path_set.hexdigest(),
            "files_sha256": contents.hexdigest(),
            "members": members,
        },
        "module": {
            "name": "google.protobuf",
            "path": "google/protobuf/__init__.py",
            "bytes": len(module_raw),
            "sha256": hashlib.sha256(module_raw).hexdigest(),
        },
        "generated_module": {
            "path": "plamen_l1/scip_pb2.py",
            "version": "7.34.1",
            "bytes": len(generated_raw),
            "sha256": hashlib.sha256(generated_raw).hexdigest(),
        },
    }


def _write_transactionally(path: Path, payload: dict) -> None:
    raw = json.dumps(
        payload,
        indent=2,
        sort_keys=True,
        ensure_ascii=True,
    ).encode("utf-8") + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _observed_from_evidence(evidence: dict) -> dict:
    return {
        "wheel_filename": evidence["wheel"]["filename"],
        "wheel_python_tag": evidence["wheel"]["python_tag"],
        "wheel_abi_tag": evidence["wheel"]["abi_tag"],
        "wheel_platform_tag": evidence["wheel"]["platform_tag"],
        "wheel_sha256": evidence["wheel"]["sha256"],
        "record_sha256": evidence["record"]["sha256"],
        "record_normalized_rows_sha256": evidence["record"][
            "normalized_rows_sha256"
        ],
        "distribution_path_set_sha256": evidence["installed_closure"][
            "path_set_sha256"
        ],
        "distribution_files_sha256": evidence["installed_closure"][
            "files_sha256"
        ],
        "module_sha256": evidence["module"]["sha256"],
        "generated_module_sha256": evidence["generated_module"]["sha256"],
    }


def test_protobuf_requires_exact_reviewed_content_match_for_authority() -> None:
    lock = json.loads(_LOCK.read_text(encoding="utf-8"))
    governance = json.loads(_GOVERNANCE.read_text(encoding="utf-8"))
    locked = _row(lock, "identities", "identity_id")
    governed = _row(governance, "tools", "tool_id")

    assert locked["content_authority"]["mode"] == "REVIEWED_CONTENT_MATCH"
    assert governed["update_policy"]["state"] == "REVIEWED_CONTENT_MATCH"
    assert governed["runtime_authority"] == {
        "identity_status": "MATCH",
        "deterministic_provider_authority": True,
        "mismatch_effect": "REVOKE_ON_REVIEWED_CONTENT_MISMATCH",
    }


def test_reviewed_evidence_and_control_pair_are_exact() -> None:
    evidence_raw = _EVIDENCE.read_bytes()
    evidence = json.loads(evidence_raw)
    lock = json.loads(_LOCK.read_text(encoding="utf-8"))
    locked = _row(lock, "identities", "identity_id")
    content = locked["content_authority"]
    assert content["evidence_path"] == (
        "verification_policy/protobuf_reviewed_content.v1.json"
    )
    assert content["evidence_sha256"] == hashlib.sha256(evidence_raw).hexdigest()
    assert content["reviewed_content_sha256"] == (
        CONTROL._validate_protobuf_reviewed_evidence(evidence)
    )
    controls = CONTROL.load_toolchain_controls(_GOVERNANCE, _LOCK)
    assert controls.locked["protobuf"] == locked
    assert controls.governed["protobuf"]["runtime_authority"][
        "deterministic_provider_authority"
    ] is True


def test_exact_reviewed_content_is_the_only_authoritative_observation() -> None:
    lock = json.loads(_LOCK.read_text(encoding="utf-8"))
    locked = _row(lock, "identities", "identity_id")
    observed = _observed_from_evidence(json.loads(_EVIDENCE.read_text()))
    assert SNAP._reviewed_python_distribution_content_status(
        locked, observed
    ) == ("MATCH", True, ())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("wheel_sha256", "0" * 64),
        ("wheel_filename", "protobuf-7.35.1-py3-none-any.whl"),
        ("wheel_python_tag", "py3"),
        ("wheel_abi_tag", "none"),
        ("wheel_platform_tag", "manylinux2014_x86_64"),
        ("record_sha256", "1" * 64),
        ("record_normalized_rows_sha256", "2" * 64),
        ("distribution_path_set_sha256", "3" * 64),
        ("distribution_files_sha256", "4" * 64),
        ("module_sha256", "5" * 64),
        ("generated_module_sha256", "6" * 64),
    ],
)
def test_any_content_or_platform_drift_revokes_authority(
    field: str,
    value: str,
) -> None:
    lock = json.loads(_LOCK.read_text(encoding="utf-8"))
    locked = _row(lock, "identities", "identity_id")
    observed = _observed_from_evidence(json.loads(_EVIDENCE.read_text()))
    observed[field] = value
    status, authority, issues = SNAP._reviewed_python_distribution_content_status(
        locked, observed
    )
    assert status == "REVOKED"
    assert authority is False
    assert issues


def test_missing_empty_malformed_and_duplicate_authority_fail_closed() -> None:
    lock = json.loads(_LOCK.read_text(encoding="utf-8"))
    locked = _row(lock, "identities", "identity_id")
    observed = _observed_from_evidence(json.loads(_EVIDENCE.read_text()))
    absent = {**locked, "content_authority": {"mode": "OBSERVED_NONAUTHORITATIVE"}}
    assert SNAP._reviewed_python_distribution_content_status(
        absent, observed
    )[0:2] == ("OBSERVED_NONAUTHORITATIVE", False)
    empty = json.loads(json.dumps(locked))
    empty["content_authority"]["reviewed_content_sha256"] = []
    assert SNAP._reviewed_python_distribution_content_status(
        empty, observed
    )[0:2] == ("OBSERVED_NONAUTHORITATIVE", False)
    malformed = json.loads(json.dumps(locked))
    malformed["content_authority"]["reviewed_content_sha256"][0][
        "sha256"
    ] = "not-a-digest"
    assert SNAP._reviewed_python_distribution_content_status(
        malformed, observed
    )[0:2] == ("REVOKED", False)
    duplicate = json.loads(json.dumps(locked))
    duplicate["content_authority"]["reviewed_content_sha256"].append(
        dict(duplicate["content_authority"]["reviewed_content_sha256"][0])
    )
    assert SNAP._reviewed_python_distribution_content_status(
        duplicate, observed
    )[0:2] == ("REVOKED", False)
    missing = dict(observed)
    missing.pop("record_sha256")
    assert SNAP._reviewed_python_distribution_content_status(
        locked, missing
    )[0:2] == ("OBSERVED_NONAUTHORITATIVE", False)


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong-version",
        "wrong-wheel",
        "record-count",
        "record-duplicate",
        "record-escape",
        "record-normalized-digest",
        "closure-count",
        "closure-member",
        "closure-extra",
        "module-origin",
        "generated-version",
    ],
)
def test_evidence_schema_rejects_tamper_missing_and_foreign_content(
    mutation: str,
) -> None:
    evidence = json.loads(_EVIDENCE.read_text(encoding="utf-8"))
    if mutation == "wrong-version":
        evidence["version"] = "6.33.6"
    elif mutation == "wrong-wheel":
        evidence["wheel"]["sha256"] = "0" * 64
    elif mutation == "record-count":
        evidence["record"]["row_count"] += 1
    elif mutation == "record-duplicate":
        evidence["record"]["rows"].append(
            dict(evidence["record"]["rows"][0])
        )
        evidence["record"]["row_count"] += 1
    elif mutation == "record-escape":
        evidence["record"]["rows"][0]["path"] = "../foreign"
    elif mutation == "record-normalized-digest":
        evidence["record"]["normalized_rows_sha256"] = "1" * 64
    elif mutation == "closure-count":
        evidence["installed_closure"]["file_count"] += 1
    elif mutation == "closure-member":
        evidence["installed_closure"]["members"][0]["sha256"] = "2" * 64
    elif mutation == "closure-extra":
        evidence["installed_closure"]["members"].append(
            {"path": "foreign.py", "sha256": "3" * 64, "bytes": 1}
        )
        evidence["installed_closure"]["file_count"] += 1
    elif mutation == "module-origin":
        evidence["module"]["path"] = "foreign/protobuf.py"
    elif mutation == "generated-version":
        evidence["generated_module"]["version"] = "8.0.0"
    with pytest.raises(CONTROL.ToolchainControlError):
        CONTROL._validate_protobuf_reviewed_evidence(evidence)


def test_packaged_evidence_hash_missing_and_governance_drift_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = tmp_path / "verification_policy"
    policy.mkdir()
    lock = policy / _LOCK.name
    governance = policy / _GOVERNANCE.name
    evidence = policy / _EVIDENCE.name
    shutil.copyfile(_LOCK, lock)
    shutil.copyfile(_GOVERNANCE, governance)
    shutil.copyfile(_EVIDENCE, evidence)
    monkeypatch.setattr(CONTROL, "_MODULE_ROOT", tmp_path)
    assert CONTROL.load_toolchain_controls(governance, lock).locked["protobuf"]

    evidence.write_bytes(evidence.read_bytes() + b" ")
    with pytest.raises(CONTROL.ToolchainControlError, match="digest"):
        CONTROL.load_toolchain_controls(governance, lock)
    evidence.unlink()
    with pytest.raises(CONTROL.ToolchainControlError, match="unreadable|reparse"):
        CONTROL.load_toolchain_controls(governance, lock)

    shutil.copyfile(_EVIDENCE, evidence)
    payload = json.loads(governance.read_text(encoding="utf-8"))
    protobuf = _row(payload, "tools", "tool_id")
    protobuf["runtime_authority"]["deterministic_provider_authority"] = False
    governance.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CONTROL.ToolchainControlError, match="semantics"):
        CONTROL.load_toolchain_controls(governance, lock)


def test_version_mismatch_and_physical_alias_remain_non_authoritative(
    tmp_path: Path,
) -> None:
    controls = SNAP._load_toolchain_identity_controls()
    _expected, status, authority, *_digests = SNAP._runtime_identity_policy(
        "protobuf",
        resolved_identity="protobuf",
        version="6.33.6",
        identity_kind="python_distribution",
        controls=controls,
    )
    assert (status, authority) == ("MISMATCH", False)

    wheel = tmp_path / _WHEEL_FILENAME
    wheel.write_bytes(b"fixture")
    alias = tmp_path / "alias.whl"
    os.link(wheel, alias)
    with pytest.raises(AssertionError):
        _reject_physical_alias(wheel)


def test_non_protobuf_lock_and_governance_rows_are_preserved() -> None:
    lock = json.loads(_LOCK.read_text(encoding="utf-8"))
    governance = json.loads(_GOVERNANCE.read_text(encoding="utf-8"))
    other_lock = [
        row for row in lock["identities"] if row["identity_id"] != "protobuf"
    ]
    other_governance = [
        row for row in governance["tools"] if row["tool_id"] != "protobuf"
    ]
    assert hashlib.sha256(_canonical(other_lock)).hexdigest() == (
        _NON_PROTOBUF_LOCK_ROWS_SHA256
    )
    assert hashlib.sha256(_canonical(other_governance)).hexdigest() == (
        _NON_PROTOBUF_GOVERNANCE_ROWS_SHA256
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--installed", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = build_reviewed_content_evidence(args.wheel, args.installed)
    _write_transactionally(args.output, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
