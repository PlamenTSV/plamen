from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

import native_runtime_bindings as bindings


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _validated_fixture() -> dict:
    members = {}
    scripts = {
        "js_offline_materializer", "managed_provisioner", "specialized_worker"
    }
    for name, path in bindings.IMAGE_MEMBER_PATHS.items():
        members[name] = {
            "mode": "0444" if name in scripts else "0555",
            "path": path,
            "sha256": _sha("member:" + name),
            "size": 100 + len(name),
        }
    return {
        "schema": bindings.SCHEMA,
        "references": {
            "oci_image_reference": "registry.invalid/plamen@sha256:" + _sha("index"),
            "oci_init_reference": bindings.INIT_REFERENCE,
        },
        "digests": {name: _sha("digest:" + name) for name in bindings.DIGEST_FIELDS},
        "image_members": members,
        "evidence": {
            "artifact_rows": {},
            "image_member_roster_sha256": _sha("claims"),
            "policy_sha256": _sha("policy"),
            "policy_bytes_sha256": _sha("policy-bytes"),
        },
    }


def test_checked_in_policy_is_truthful_blocked_candidate() -> None:
    root = Path(__file__).resolve().parents[1]
    raw = (root / bindings.POLICY_PATH).read_bytes()
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        value = bindings.validate_native_runtime_bindings_v2(
            raw, root_fd, require_frozen=False
        )
        assert value["state"] == "CANDIDATE_BLOCKED"
        assert value["digests"] == {}
        assert value["image_members"] == {}
        with pytest.raises(bindings.NativeRuntimeBindingsError, match="not frozen"):
            bindings.load_native_runtime_bindings_v2(root_fd)
    finally:
        os.close(root_fd)


def test_blocked_candidate_cannot_be_frozen_or_hide_missing_authority(tmp_path: Path) -> None:
    raw = bindings.blocked_candidate(["NATIVE_BUILD_GUEST_RECEIPT"])
    root_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(bindings.NativeRuntimeBindingsError, match="ready"):
            bindings.freeze_candidate(raw, root_fd)
        value = json.loads(raw)
        value["missing_authorities"] = []
        tampered = bindings._canonical(value)
        with pytest.raises(bindings.NativeRuntimeBindingsError, match="self-digest"):
            bindings.validate_native_runtime_bindings_v2(
                tampered, root_fd, require_frozen=False
            )
    finally:
        os.close(root_fd)


def test_image_member_receipt_binary_abi_binds_every_parent_authority() -> None:
    value = _validated_fixture()
    runtime_manifest = _sha("runtime-package-manifest")
    raw = bindings.encode_image_member_receipt_v2(
        value, runtime_package_manifest_sha256=runtime_manifest
    )
    rows = bindings.encode_image_member_rows_v2(value)
    assert len(rows) == len(
        bindings.IMAGE_MEMBER_PATHS
    ) * bindings.IMAGE_MEMBER_RECEIPT_ROW_SIZE
    assert raw[bindings.IMAGE_MEMBER_RECEIPT_HEADER_SIZE:] == rows
    assert hashlib.sha256(rows).digest() == raw[176:208]
    assert len(raw) == (
        bindings.IMAGE_MEMBER_RECEIPT_HEADER_SIZE
        + len(bindings.IMAGE_MEMBER_PATHS) * bindings.IMAGE_MEMBER_RECEIPT_ROW_SIZE
    )
    assert raw[:8] == bindings.IMAGE_MEMBER_RECEIPT_MAGIC
    assert int.from_bytes(raw[8:10], "big") == 2
    assert int.from_bytes(raw[10:12], "big") == 256
    assert int.from_bytes(raw[12:14], "big") == 320
    assert int.from_bytes(raw[14:16], "big") == len(bindings.IMAGE_MEMBER_PATHS)
    assert raw[16:48].hex() == value["digests"]["image_manifest_digest"]
    assert raw[48:80].hex() == runtime_manifest
    assert raw[80:112].hex() == value["digests"]["image_closure_sha256"]
    assert raw[112:144].hex() == value["digests"]["closure_census_sha256"]
    assert raw[144:176].hex() == value["digests"]["materialization_receipt_sha256"]
    rows = raw[256:]
    assert raw[176:208] == hashlib.sha256(rows).digest()
    assert raw[208:240].hex() == value["evidence"]["policy_sha256"]
    assert raw[240:256] == bytes(16)

    first = rows[:320]
    assert first[48:53] == b"forge"
    assert first[80:80 + len(bindings.IMAGE_MEMBER_PATHS["forge"])] == (
        bindings.IMAGE_MEMBER_PATHS["forge"].encode()
    )


def test_image_member_receipt_rejects_zero_digest_and_wrong_path() -> None:
    value = _validated_fixture()
    value["digests"]["image_closure_sha256"] = "0" * 64
    with pytest.raises(bindings.NativeRuntimeBindingsError, match="nonzero"):
        bindings.encode_image_member_receipt_v2(
            value, runtime_package_manifest_sha256=_sha("runtime")
        )
    value = _validated_fixture()
    value["image_members"]["forge"]["path"] = "/usr/bin/forge"
    with pytest.raises(bindings.NativeRuntimeBindingsError, match="path"):
        bindings.encode_image_member_receipt_v2(
            value, runtime_package_manifest_sha256=_sha("runtime")
        )


def _admission_v4(validated: dict, archive: bytes, layout: bytes) -> dict:
    return {
        "schema": "plamen.apple-container.image-admission.v4", "state": "TERMINAL",
        "image_reference": validated["references"]["oci_image_reference"],
        "index_digest": "sha256:" + validated["digests"]["oci_index_digest"],
        "manifest_digest": "sha256:" + validated["digests"]["image_manifest_digest"],
        "configuration_sha256": validated["digests"]["apple_container_configuration_sha256"],
        "platform_os": "linux", "platform_architecture": "arm64",
        "archive_identity_sha256": _sha("physical"),
        "archive_content_sha256": hashlib.sha256(archive).hexdigest(),
        "archive_size": len(archive),
        "layout_receipt_sha256": hashlib.sha256(layout).hexdigest(),
        "image_closure_sha256": validated["digests"]["image_closure_sha256"],
        "admission_nonce": "2" * 32,
        "provider_provenance_sha256": _sha("provider"),
        "postcondition_sha256": _sha("postcondition"),
    }


def test_v3_join_binds_archive_layout_config_and_closure() -> None:
    validated, archive, layout = _validated_fixture(), b"archive", b"layout\n"
    expected = _admission_v4(validated, archive, layout)
    assert bindings._validate_apple_image_admission_v4(
        bindings._canonical(expected), archive, layout, validated) == expected
    for field, replacement in (
        ("archive_content_sha256", "5" * 64), ("archive_size", 999),
        ("layout_receipt_sha256", "6" * 64),
        ("image_closure_sha256", "7" * 64),
        ("configuration_sha256", "8" * 64),
    ):
        damaged = dict(expected); damaged[field] = replacement
        with pytest.raises(bindings.NativeRuntimeBindingsError,
                           match="retained OCI evidence graph"):
            bindings._validate_apple_image_admission_v4(
                bindings._canonical(damaged), archive, layout, validated)


def test_v3_join_rejects_v3_provider_record_and_noncanonical_bytes() -> None:
    validated, archive, layout = _validated_fixture(), b"archive", b"layout\n"
    expected = _admission_v4(validated, archive, layout)
    old = dict(expected); old["schema"] = "plamen.apple-container.image-admission.v3"
    with pytest.raises(bindings.NativeRuntimeBindingsError,
                       match="retained OCI evidence graph"):
        bindings._validate_apple_image_admission_v4(
            bindings._canonical(old), archive, layout, validated)
    with pytest.raises(bindings.NativeRuntimeBindingsError, match="canonical"):
        bindings._validate_apple_image_admission_v4(
            json.dumps(expected).encode(), archive, layout, validated)


def test_descriptor_reader_rejects_symlink_and_hardlink(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.write_bytes(b"receipt\n")
    real.chmod(0o400)
    linked = tmp_path / "linked"
    os.link(real, linked)
    row = {
        "mode": "0400",
        "path": "real",
        "sha256": hashlib.sha256(b"receipt\n").hexdigest(),
        "size": len(b"receipt\n"),
    }
    root_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(bindings.NativeRuntimeBindingsError, match="unsafe"):
            bindings._read_evidence(root_fd, row, "receipt")
        real.chmod(0o600)
        linked.unlink()
        symlink = tmp_path / "symlink"
        symlink.symlink_to("real")
        row["path"] = "symlink"
        with pytest.raises(bindings.NativeRuntimeBindingsError, match="unavailable"):
            bindings._read_evidence(root_fd, row, "receipt")
    finally:
        os.close(root_fd)
