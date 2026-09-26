"""Adversarial acceptance tests for the deterministic OCI image lock."""

from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import ctypes
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import threading
import unicodedata
import fcntl

import pytest

import oci_image_lock as O
import runtime_image_materializer as runtime_materializer
import test_runtime_image_materializer as materializer_tests


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _fixture(tmp_path: Path) -> tuple[Path, dict]:
    root = tmp_path / "context"
    payloads: dict[str, bytes] = {
        "artifacts/python.tar": b"cpython-3.12.12\n",
        "backends/claude": b"claude-cli-2.1.252\n",
        "backends/codex": b"codex-cli-0.153.4\n",
        "runtime/closure.json": b'{"runtime":"closed"}\n',
        "toolchains/foundry.tar": b"foundry-1.4.0\n",
    }
    rootfs_source_sha256 = _digest(payloads["runtime/closure.json"])
    rootfs_derivation = {
        "schema_version": O.ROOTFS_DERIVATION_BINDING_SCHEMA_VERSION,
        "derivation_schema_version": (
            "plamen.cache_free_rootfs_derivation.test.v1"
        ),
        "recipe_version": O.TEST_ONLY_ROOTFS_DERIVATION_RECIPE,
        "authentication_scope": "TEST_ONLY_NO_RELEASE_AUTHORITY",
        "production_authority": False,
        "source_asset_id": "runtime-closure",
        "source_reference": "TEST_ONLY_SYNTHETIC_CACHE_FREE_ROOT",
        "source_sha256": rootfs_source_sha256,
        "source_size": len(payloads["runtime/closure.json"]),
        "source_diff_id": "sha256:" + rootfs_source_sha256,
        "derived_sha256": rootfs_source_sha256,
        "derived_size": len(payloads["runtime/closure.json"]),
        "derived_diff_id": "sha256:" + rootfs_source_sha256,
        "derived_tar_size": len(payloads["runtime/closure.json"]),
        "derived_census_sha256": _digest(b"TEST_ONLY_CENSUS\n"),
        "derived_entry_count": 1,
        "manifest_sha256": "0" * 64,
        "removed_cache_path": "/etc/ld.so.cache",
        "removed_cache_sha256": "0" * 64,
        "removed_cache_size": 0,
        "forbidden_environment": {
            "exact_names": ["GLIBC_TUNABLES"],
            "prefixes": ["LD_"],
        },
    }
    rootfs_derivation["manifest_sha256"] = _digest(
        O._TEST_ONLY_rootfs_derivation_manifest_bytes(rootfs_derivation)
    )
    runtime_bindings = [
        {
            "artifact_id": "cpython",
            "path": "artifacts/python.tar",
            "role": "cpython",
            "sha256": _digest(payloads["artifacts/python.tar"]),
            "version": "3.12.12",
        },
        {
            "artifact_id": "claude",
            "path": "backends/claude",
            "role": "backend_cli",
            "sha256": _digest(payloads["backends/claude"]),
            "version": "2.1.252",
        },
        {
            "artifact_id": "codex",
            "path": "backends/codex",
            "role": "backend_cli",
            "sha256": _digest(payloads["backends/codex"]),
            "version": "0.153.4",
        },
        {
            "artifact_id": "foundry",
            "path": "toolchains/foundry.tar",
            "role": "toolchain",
            "sha256": _digest(payloads["toolchains/foundry.tar"]),
            "version": "1.4.0",
        },
        {
            "artifact_id": "runtime-closure",
            "path": "runtime/closure.json",
            "role": "asset",
            "sha256": _digest(payloads["runtime/closure.json"]),
            "version": None,
        },
        {
            "artifact_id": "cache-free-rootfs-derivation",
            "path": "usr/local/lib/plamen/attestations/cache-free-rootfs-derivation.json",
            "role": "generated_attestation",
            "sha256": rootfs_derivation["manifest_sha256"],
            "version": rootfs_derivation["recipe_version"],
        },
    ]
    runtime_bindings.sort(
        key=lambda row: (str(row["role"]), str(row["artifact_id"]))
    )
    payloads["attestations/sbom.spdx.json"] = O._canonical_bytes(
        {
            "packages": [
                {
                    "checksums": [
                        {
                            "algorithm": "SHA256",
                            "checksumValue": row["sha256"],
                        }
                    ],
                    "name": f"{row['role']}:{row['artifact_id']}",
                    "versionInfo": row["version"] or "content-addressed",
                }
                for row in runtime_bindings
            ],
            "spdxVersion": "SPDX-2.3",
        }
    )
    payloads["attestations/census.json"] = O._canonical_bytes(
        {
            "artifacts": runtime_bindings,
            "schema_version": O.RUNTIME_CENSUS_SCHEMA_VERSION,
        }
    )
    materialized, materialized_watcher, _retained, composition_manifest = (
        materializer_tests._compose(tmp_path / "materializer-work")
    )
    try:
        materialized_size = os.fstat(materialized.archive_descriptor).st_size
        materialized_archive = os.pread(
            materialized.archive_descriptor, materialized_size, 0
        )
        materialized_receipt = json.loads(materialized.receipt_bytes)
        payloads.update(
            {
                "materialization/composition-manifest.json": composition_manifest,
                "materialization/runtime.tar": materialized_archive,
                "materialization/receipt.json": materialized.receipt_bytes,
                "materialization/census.json": materialized.census_bytes,
                "materialization/sbom.spdx.json": materialized.sbom_bytes,
                "materialization/provenance.json": materialized.provenance_bytes,
            }
        )
    finally:
        os.close(materialized.archive_descriptor)
        os.close(materialized_watcher)
    for relative, raw in payloads.items():
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        destination.chmod(0o644)
    inputs = [
        {
            "path": relative,
            "sha256": _digest(raw),
            "size": len(raw),
            "mode": "0644",
        }
        for relative, raw in sorted(
            payloads.items(), key=lambda row: (row[0].casefold(), row[0])
        )
    ]
    by_path = {row["path"]: row for row in inputs}
    manifest = "sha256:" + "a" * 64
    index = "sha256:" + "c" * 64
    config = "sha256:" + "d" * 64
    apple_configuration = "e" * 64
    base_manifest = "sha256:" + "b" * 64
    unsigned = {
        "schema_version": O.SCHEMA_VERSION,
        "platform": {
            "host": O.APPLE_HOST_PLATFORM,
            "target": O.TARGET_PLATFORM,
        },
        "image": {
            "reference": f"ghcr.io/plamen/audit-runtime@{index}",
            "index_digest": index,
            "manifest_digest": manifest,
            "config_digest": config,
            "apple_container_configuration_sha256": apple_configuration,
            "base_reference": f"docker.io/library/debian@{base_manifest}",
            "base_manifest_digest": base_manifest,
        },
        "runtime": {
            "cpython": {
                "version": "3.12.12",
                "path": "artifacts/python.tar",
                "sha256": by_path["artifacts/python.tar"]["sha256"],
            },
            "backend_clis": [
                {
                    "backend": "claude",
                    "version": "2.1.252",
                    "path": "backends/claude",
                    "sha256": by_path["backends/claude"]["sha256"],
                },
                {
                    "backend": "codex",
                    "version": "0.153.4",
                    "path": "backends/codex",
                    "sha256": by_path["backends/codex"]["sha256"],
                },
            ],
            "toolchains": [
                {
                    "toolchain_id": "foundry",
                    "version": "1.4.0",
                    "path": "toolchains/foundry.tar",
                    "sha256": by_path["toolchains/foundry.tar"]["sha256"],
                }
            ],
            "assets": [
                {
                    "asset_id": "runtime-closure",
                    "path": "runtime/closure.json",
                    "sha256": by_path["runtime/closure.json"]["sha256"],
                }
            ],
        },
        "rootfs_derivation": rootfs_derivation,
        "attestations": {
            "sbom": {
                "format": "spdx-json",
                "path": "attestations/sbom.spdx.json",
                "sha256": by_path["attestations/sbom.spdx.json"]["sha256"],
            },
            "census": {
                "schema_version": O.RUNTIME_CENSUS_SCHEMA_VERSION,
                "path": "attestations/census.json",
                "sha256": by_path["attestations/census.json"]["sha256"],
            },
        },
        "runtime_materialization": {
            "schema_version": O.RUNTIME_MATERIALIZATION_SCHEMA_VERSION,
            "required_roles": list(O.RUNTIME_MATERIALIZATION_REQUIRED_ROLES),
            "source_roster_sha256": materialized_receipt[
                "source_roster_sha256"
            ],
            "composition_manifest": {
                "schema_version": runtime_materializer.SCHEMA_VERSION,
                "path": "materialization/composition-manifest.json",
                "sha256": _digest(composition_manifest),
                "size": len(composition_manifest),
            },
            "archive": {
                "media_type": materialized_receipt["archive"]["media_type"],
                "path": "materialization/runtime.tar",
                "sha256": materialized_receipt["archive"]["sha256"],
                "size": materialized_receipt["archive"]["size"],
                "diff_id": materialized_receipt["archive"]["diff_id"],
            },
            "receipt": {
                "path": "materialization/receipt.json",
                "sha256": _digest(materialized.receipt_bytes),
                "size": len(materialized.receipt_bytes),
            },
            "census": {
                "schema_version": runtime_materializer.CENSUS_SCHEMA_VERSION,
                "path": "materialization/census.json",
                "sha256": _digest(materialized.census_bytes),
                "size": len(materialized.census_bytes),
                "entry_count": materialized_receipt["installed"]["entry_count"],
                "expanded_bytes": materialized_receipt["installed"]["expanded_bytes"],
            },
            "sbom": {
                "format": "spdx-json-2.3",
                "path": "materialization/sbom.spdx.json",
                "sha256": _digest(materialized.sbom_bytes),
                "size": len(materialized.sbom_bytes),
            },
            "provenance": {
                "schema_version": runtime_materializer.PROVENANCE_SCHEMA_VERSION,
                "path": "materialization/provenance.json",
                "sha256": _digest(materialized.provenance_bytes),
                "size": len(materialized.provenance_bytes),
            },
        },
        "policies": {
            "network": "DENY",
            "runtime_package_resolution": "DENY",
            "build_input_admission": "EXACT_ROSTER",
            "symlinks": "DENY",
            "hardlinks": "DENY",
            "extended_attributes": "DENY",
        },
        "build_inputs": inputs,
    }
    return root, O.seal_image_lock(unsigned)


def _resign(lock: dict) -> dict:
    candidate = copy.deepcopy(lock)
    candidate["lock_sha256"] = O.canonical_lock_sha256(candidate)
    return candidate


def _replay_consumer(
    replay_store: set[tuple[int, str, str]] | None = None,
):
    consumed = replay_store if replay_store is not None else set()

    def consume_once(
        observed_generation: int,
        observed_nonce: str,
        observed_digest: str,
    ) -> bool:
        identity = (observed_generation, observed_nonce, observed_digest)
        if identity in consumed:
            return False
        consumed.add(identity)
        return True

    return consume_once


def _render(
    lock: dict,
    root: Path,
    *,
    trusted_digest: str | None = None,
    generation: int = 1,
    nonce: str | None = None,
    replay_store: set[tuple[int, str, str]] | None = None,
) -> O.OCIValidatedBuildPlan:
    return O._render_build_plan_for_testing(
        lock,
        root.resolve(),
        expected_lock_sha256=trusted_digest or lock["lock_sha256"],
        release_generation=generation,
        release_nonce=nonce or _digest(os.urandom(32)),
        durable_replay_consumer=_replay_consumer(replay_store),
    )


def _consume_all(plan: O.OCIValidatedBuildPlan) -> dict[str, bytes]:
    def consume(readers):
        result = {}
        for reader in readers:
            chunks = []
            while chunk := reader.read(7):
                chunks.append(chunk)
            result[reader.path] = b"".join(chunks)
        return result

    return plan.consume_build_context_for_testing(consume)


def test_exact_lock_renders_stable_nonexecuting_plan(tmp_path: Path) -> None:
    root, lock = _fixture(tmp_path)
    first = _render(lock, root, nonce="c" * 32)
    second = _render(copy.deepcopy(lock), root, nonce="d" * 32)
    first_release_neutral = dict(first)
    second_release_neutral = dict(second)
    for body in (first_release_neutral, second_release_neutral):
        body.pop("plan_sha256")
        body.pop("release_nonce")
    assert first_release_neutral == second_release_neutral
    assert first["schema_version"] == O.BUILD_PLAN_SCHEMA_VERSION
    assert first["authentication_scope"] == "TEST_ONLY_NO_RELEASE_AUTHORITY"
    assert type(first) is not O.OCIValidatedBuildPlan
    assert first["network"] == "DENY"
    assert first["runtime_package_resolution"] == "DENY"
    assert first["host_platform"] == "darwin/arm64"
    assert first["target_platform"] == "linux/arm64"
    assert first["expected_index_digest"] == lock["image"]["index_digest"]
    assert first["expected_manifest_digest"] == lock["image"]["manifest_digest"]
    assert first["expected_config_digest"] == lock["image"]["config_digest"]
    assert first["expected_apple_container_configuration_sha256"] == lock[
        "image"
    ]["apple_container_configuration_sha256"]
    assert first["expected_image_reference"].endswith(
        "@" + lock["image"]["index_digest"]
    )
    assert str(root.resolve()) not in json.dumps(first, sort_keys=True)
    unsigned_plan = dict(first)
    observed_digest = unsigned_plan.pop("plan_sha256")
    assert observed_digest == hashlib.sha256(
        O._canonical_bytes(unsigned_plan)
    ).hexdigest()
    assert _consume_all(first)["backends/codex"] == b"codex-cli-0.153.4\n"
    second.close()


def test_duplicate_key_json_is_rejected_before_schema_validation() -> None:
    raw = b'{"schema_version":"a","schema_version":"b"}'
    with pytest.raises(O.OCIImageLockError, match="duplicate JSON key"):
        O.parse_image_lock(raw)


def test_large_duplicate_lock_key_is_redacted_and_error_is_bounded() -> None:
    marker = "SENSITIVE_ATTACKER_FIELD_"
    key = marker + "x" * 500_000
    encoded_key = json.dumps(key).encode("utf-8")
    raw = b"{" + encoded_key + b":0," + encoded_key + b":1}\n"
    assert len(raw) < O._MAX_JSON_BYTES

    with pytest.raises(O.OCIImageLockError) as raised:
        O.parse_image_lock(raw)
    assert str(raised.value) == "duplicate JSON key is forbidden"
    assert marker not in str(raised.value)
    assert len(str(raised.value).encode("utf-8")) < 128
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_canonical_lock_digest_detects_any_lock_drift(tmp_path: Path) -> None:
    _root, lock = _fixture(tmp_path)
    lock["runtime"]["cpython"]["version"] = "3.12.13"
    with pytest.raises(O.OCIImageLockError, match="canonical digest mismatch"):
        O.validate_image_lock(lock)


@pytest.mark.parametrize(
    "reference",
    (
        "ghcr.io/plamen/audit-runtime:latest",
        "ghcr.io/plamen/audit-runtime:stable@sha256:" + "a" * 64,
        "ghcr.io/plamen/audit-runtime@sha512:" + "a" * 64,
    ),
)
def test_mutable_or_non_sha256_image_references_are_rejected(
    tmp_path: Path,
    reference: str,
) -> None:
    _root, lock = _fixture(tmp_path)
    lock["image"]["reference"] = reference
    with pytest.raises(O.OCIImageLockError, match="image reference"):
        O.validate_image_lock(_resign(lock))


def test_index_and_reference_digests_must_agree(tmp_path: Path) -> None:
    _root, lock = _fixture(tmp_path)
    lock["image"]["index_digest"] = "sha256:" + "d" * 64
    with pytest.raises(O.OCIImageLockError, match="disagrees"):
        O.validate_image_lock(_resign(lock))


def test_index_and_selected_manifest_identities_must_be_distinct(
    tmp_path: Path,
) -> None:
    _root, lock = _fixture(tmp_path)
    lock["image"]["manifest_digest"] = lock["image"]["index_digest"]
    with pytest.raises(O.OCIImageLockError, match="must be distinct"):
        O.validate_image_lock(_resign(lock))


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("config_digest", "d" * 64, "config digest"),
        (
            "apple_container_configuration_sha256",
            "sha256:" + "e" * 64,
            "Apple Container configuration",
        ),
    ),
)
def test_config_identities_use_distinct_exact_digest_encodings(
    tmp_path: Path,
    field: str,
    value: str,
    message: str,
) -> None:
    _root, lock = _fixture(tmp_path)
    lock["image"][field] = value
    with pytest.raises(O.OCIImageLockError, match=message):
        O.validate_image_lock(_resign(lock))


@pytest.mark.parametrize("host", ("darwin/amd64", "linux/arm64"))
def test_renderer_rejects_platform_mismatch(
    tmp_path: Path,
    host: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, lock = _fixture(tmp_path)
    monkeypatch.setattr(O, "_host_platform", lambda: host)
    with pytest.raises(O.OCIImageLockError, match="platform mismatch"):
        _render(lock, root)


def test_lock_schema_rejects_non_apple_platform(tmp_path: Path) -> None:
    _root, lock = _fixture(tmp_path)
    lock["platform"]["host"] = "linux/arm64"
    with pytest.raises(O.OCIImageLockError, match="darwin/arm64"):
        O.validate_image_lock(_resign(lock))


def test_unlisted_build_input_is_rejected(tmp_path: Path) -> None:
    root, lock = _fixture(tmp_path)
    (root / "unlisted.txt").write_text("foreign", encoding="utf-8")
    with pytest.raises(O.OCIImageLockError, match="unlisted"):
        _render(lock, root)


def test_missing_build_input_is_rejected(tmp_path: Path) -> None:
    root, lock = _fixture(tmp_path)
    (root / "backends" / "codex").unlink()
    with pytest.raises(O.OCIImageLockError, match="missing"):
        _render(lock, root)


@pytest.mark.parametrize("mutation", ["bytes", "mode"])
def test_build_input_content_or_mode_drift_is_rejected(
    tmp_path: Path,
    mutation: str,
) -> None:
    root, lock = _fixture(tmp_path)
    target = root / "runtime" / "closure.json"
    if mutation == "bytes":
        target.write_bytes(b'{"runtime":"drifted"}\n')
    else:
        target.chmod(0o600)
    with pytest.raises(O.OCIImageLockError, match="drifted from its lock"):
        _render(lock, root)


def test_symlink_build_input_is_rejected(tmp_path: Path) -> None:
    root, lock = _fixture(tmp_path)
    target = root / "runtime" / "closure.json"
    target.unlink()
    target.symlink_to(root / "backends" / "codex")
    with pytest.raises(O.OCIImageLockError, match="symlink"):
        _render(lock, root)


def test_hardlink_alias_outside_context_is_rejected(tmp_path: Path) -> None:
    root, lock = _fixture(tmp_path)
    os.link(root / "runtime" / "closure.json", tmp_path / "external-alias")
    with pytest.raises(O.OCIImageLockError, match="hardlink alias"):
        _render(lock, root)


def test_extended_metadata_is_rejected_by_descriptor_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, lock = _fixture(tmp_path)
    target = root / "runtime" / "closure.json"
    target_inode = target.stat().st_ino

    def inspect(descriptor: int):
        return ("user.injected",) if os.fstat(descriptor).st_ino == target_inode else ()

    monkeypatch.setattr(O, "_default_metadata_inspector", lambda: inspect)
    with pytest.raises(O.OCIImageLockError, match="extended metadata is forbidden"):
        _render(lock, root)


def test_absent_metadata_provider_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, lock = _fixture(tmp_path)
    monkeypatch.setattr(O, "_default_metadata_inspector", lambda: None)
    with pytest.raises(O.OCIImageLockError, match="inspection is unavailable"):
        _render(lock, root)


@pytest.mark.parametrize(
    "path",
    (
        "../escape",
        "/absolute",
        "nested\\windows",
        "nested/../../escape",
        unicodedata.normalize("NFD", "runtime/café"),
    ),
)
def test_traversal_and_noncanonical_paths_are_rejected(
    tmp_path: Path,
    path: str,
) -> None:
    _root, lock = _fixture(tmp_path)
    lock["build_inputs"][0]["path"] = path
    with pytest.raises(O.OCIImageLockError, match="path"):
        O.validate_image_lock(_resign(lock))


def test_case_colliding_build_input_paths_are_rejected(tmp_path: Path) -> None:
    _root, lock = _fixture(tmp_path)
    first = copy.deepcopy(lock["build_inputs"][0])
    first["path"] = "A"
    second = copy.deepcopy(first)
    second["path"] = "a"
    lock["build_inputs"] = [first, second]
    with pytest.raises(O.OCIImageLockError, match="case/NFC collision"):
        O.validate_image_lock(_resign(lock))


def test_case_colliding_path_components_are_rejected(tmp_path: Path) -> None:
    _root, lock = _fixture(tmp_path)
    lock["build_inputs"][0]["path"] = "A/file"
    lock["build_inputs"][1]["path"] = "a/other"
    lock["build_inputs"].sort(
        key=lambda row: (row["path"].casefold(), row["path"])
    )
    with pytest.raises(O.OCIImageLockError, match="components case/NFC collide"):
        O.validate_image_lock(_resign(lock))


def test_runtime_artifact_hash_must_match_build_roster(tmp_path: Path) -> None:
    _root, lock = _fixture(tmp_path)
    lock["runtime"]["assets"][0]["sha256"] = "f" * 64
    with pytest.raises(O.OCIImageLockError, match="absent or disagrees"):
        O.validate_image_lock(_resign(lock))


def test_derivation_schema_source_and_environment_are_exactly_bound(
    tmp_path: Path,
) -> None:
    _root, lock = _fixture(tmp_path)
    for key, value in (
        ("schema_version", "plamen.oci_rootfs_derivation_binding.v0"),
        ("source_sha256", "e" * 64),
        ("derived_diff_id", "sha256:" + "e" * 64),
        ("manifest_sha256", "e" * 64),
    ):
        bad = copy.deepcopy(lock)
        bad["rootfs_derivation"][key] = value
        with pytest.raises(O.OCIImageLockError, match="rootfs derivation|manifest"):
            O.validate_image_lock(_resign(bad))
    bad = copy.deepcopy(lock)
    bad["rootfs_derivation"]["forbidden_environment"] = {
        "exact_names": [],
        "prefixes": ["LD_"],
    }
    with pytest.raises(O.OCIImageLockError, match="environment denials"):
        O.validate_image_lock(_resign(bad))
    legacy = copy.deepcopy(lock)
    legacy["schema_version"] = "plamen.oci_image_lock.v1"
    with pytest.raises(O.OCIImageLockError, match="schema version"):
        O.validate_image_lock(_resign(legacy))


def test_retained_rootfs_borrow_is_readonly_same_snapshot_and_unforgeable(
    tmp_path: Path,
) -> None:
    root, lock = _fixture(tmp_path)
    plan = _render(lock, root)
    original = (root / "runtime/closure.json").read_bytes()
    (root / "runtime/closure.json").write_bytes(b"rebound\n")

    def consume(readers):
        target = next(reader for reader in readers if reader.path == "runtime/closure.json")
        borrowed = O._TEST_ONLY_borrow_reader_descriptor(target)
        try:
            assert fcntl.fcntl(borrowed, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
            assert os.pread(borrowed, len(original), 0) == original
        finally:
            os.close(borrowed)
        for reader in readers:
            while reader.read(17):
                pass

    plan.consume_build_context_for_testing(consume)
    with pytest.raises((TypeError, O.OCIImageLockError)):
        O._TEST_ONLY_borrow_reader_descriptor(object())


@pytest.mark.parametrize(
    "version",
    ["latest", "3.12", "3.13.0", "3.12.*", "3.12.12.1", "3.12.12-rc1"],
)
def test_cpython_must_be_an_exact_3_12_patch(
    tmp_path: Path,
    version: str,
) -> None:
    _root, lock = _fixture(tmp_path)
    lock["runtime"]["cpython"]["version"] = version
    with pytest.raises(O.OCIImageLockError, match="CPython"):
        O.validate_image_lock(_resign(lock))


def test_unknown_policy_or_runtime_resolution_field_is_rejected(
    tmp_path: Path,
) -> None:
    _root, lock = _fixture(tmp_path)
    lock["runtime"]["package_install_command"] = "pip install latest"
    with pytest.raises(O.OCIImageLockError, match="runtime must contain exactly"):
        O.validate_image_lock(_resign(lock))


def test_non_regular_fifo_input_is_rejected_when_supported(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("host has no FIFO primitive")
    root, lock = _fixture(tmp_path)
    target = root / "runtime" / "closure.json"
    target.unlink()
    os.mkfifo(target, mode=0o644)
    assert stat.S_ISFIFO(target.lstat().st_mode)
    with pytest.raises(O.OCIImageLockError, match="not an ordinary file"):
        _render(lock, root)


def test_parser_requires_exact_canonical_wire_bytes(tmp_path: Path) -> None:
    _root, lock = _fixture(tmp_path)
    assert O.parse_image_lock(O._canonical_bytes(lock)) == lock
    pretty = json.dumps(lock, indent=2, ensure_ascii=False).encode("utf-8")
    with pytest.raises(O.OCIImageLockError, match="canonical wire form"):
        O.parse_image_lock(pretty)


@pytest.mark.parametrize(
    "raw",
    (
        "\ud800",
        (b'{"integer":' + b"1" * 5_000 + b"}"),
    ),
)
def test_parser_sanitizes_unicode_and_integer_decoder_errors(
    raw: bytes | str,
) -> None:
    with pytest.raises(O.OCIImageLockError):
        O.parse_image_lock(raw)


def test_all_public_mapping_entrypoints_enforce_string_bounds(
    tmp_path: Path,
) -> None:
    _root, lock = _fixture(tmp_path)
    unsigned = copy.deepcopy(lock)
    unsigned.pop("lock_sha256")
    unsigned["attestations"]["census"]["schema_version"] = "x" * (
        O._MAX_STRING_BYTES + 1
    )
    with pytest.raises(O.OCIImageLockError, match="oversized string"):
        O.seal_image_lock(unsigned)


def test_trusted_digest_rejects_semantically_valid_self_resigned_lock(
    tmp_path: Path,
) -> None:
    root, lock = _fixture(tmp_path)
    trusted = lock["lock_sha256"]
    replacement = "sha256:" + "f" * 64
    lock["image"]["manifest_digest"] = replacement
    attacker_lock = _resign(lock)
    with pytest.raises(O.OCIImageLockError, match="authenticated release lock"):
        _render(attacker_lock, root, trusted_digest=trusted)


def test_python_caller_cannot_issue_authority_for_self_resigned_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, lock = _fixture(tmp_path)
    replacement = "sha256:" + "f" * 64
    lock["image"]["manifest_digest"] = replacement
    attacker_lock = _resign(lock)
    assert not hasattr(O, "_issue_authenticated_lock_authority")
    reached_test_renderer: list[bool] = []

    def forged_test_renderer(*_args, **_kwargs):
        reached_test_renderer.append(True)
        raise AssertionError("production renderer reached a Python test seam")

    monkeypatch.setattr(O, "_render_test_build_plan", forged_test_renderer)
    with pytest.raises(
        O.OCIImageLockError,
        match=O._RELEASE_VERIFIER_REQUIRED,
    ):
        O.render_build_plan(
            attacker_lock,
            root.resolve(),
            authenticated_release_receipt={
                "digest": attacker_lock["lock_sha256"],
                "generation": 1,
                "nonce": "e" * 32,
            },
        )
    assert reached_test_renderer == []


def test_release_authority_is_one_shot_and_durably_replay_protected(
    tmp_path: Path,
) -> None:
    root, lock = _fixture(tmp_path)
    replay_store: set[tuple[int, str, str]] = set()
    nonce = "d" * 32
    first = _render(
        lock,
        root,
        generation=7,
        nonce=nonce,
        replay_store=replay_store,
    )
    assert first["release_generation"] == 7
    assert first["release_nonce"] == nonce
    first.close()
    with pytest.raises(O.OCIImageLockError, match="already consumed"):
        _render(
            lock,
            root,
            generation=7,
            nonce=nonce,
            replay_store=replay_store,
        )
    assert replay_store == {(7, nonce, lock["lock_sha256"])}


def test_test_seam_preserves_atomic_replay_callback_contract(
    tmp_path: Path,
) -> None:
    root, lock = _fixture(tmp_path)
    nonce = "f" * 32
    identities: set[tuple[int, str, str]] = set()
    replay_lock = threading.Lock()

    def atomic_consume(generation: int, observed_nonce: str, digest: str) -> bool:
        identity = (generation, observed_nonce, digest)
        with replay_lock:
            if identity in identities:
                return False
            identities.add(identity)
            return True

    def attempt(_index: int):
        try:
            return O._render_build_plan_for_testing(
                lock,
                root.resolve(),
                expected_lock_sha256=lock["lock_sha256"],
                release_generation=9,
                release_nonce=nonce,
                durable_replay_consumer=atomic_consume,
            )
        except O.OCIImageLockError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(attempt, range(16)))
    plans = [row for row in results if isinstance(row, dict)]
    errors = [row for row in results if isinstance(row, O.OCIImageLockError)]
    assert len(plans) == 1
    assert len(errors) == 15
    assert all("already consumed" in str(error) for error in errors)
    plans[0].close()
    assert identities == {(9, nonce, lock["lock_sha256"])}


def test_release_authority_rejects_noncanonical_freshness_fields(
    tmp_path: Path,
) -> None:
    root, lock = _fixture(tmp_path)
    with pytest.raises(O.OCIImageLockError, match="generation"):
        _render(lock, root, generation=0)
    with pytest.raises(O.OCIImageLockError, match="nonce"):
        _render(lock, root, nonce="attacker-selected")


def test_unreferenced_secret_cannot_enter_closed_build_roster(
    tmp_path: Path,
) -> None:
    _root, lock = _fixture(tmp_path)
    lock["build_inputs"].append(
        {
            "path": "secrets/api-token.txt",
            "sha256": "f" * 64,
            "size": 12,
            "mode": "0600",
        }
    )
    lock["build_inputs"].sort(
        key=lambda row: (row["path"].casefold(), row["path"])
    )
    with pytest.raises(O.OCIImageLockError, match="exact closed roster"):
        O.validate_image_lock(_resign(lock))


def test_runtime_roles_cannot_alias_one_artifact(tmp_path: Path) -> None:
    _root, lock = _fixture(tmp_path)
    claude, codex = lock["runtime"]["backend_clis"]
    codex["path"] = claude["path"]
    codex["sha256"] = claude["sha256"]
    with pytest.raises(O.OCIImageLockError, match="paths must be exclusive"):
        O.validate_image_lock(_resign(lock))


def test_census_schema_is_exact_not_attacker_selected(tmp_path: Path) -> None:
    _root, lock = _fixture(tmp_path)
    lock["attestations"]["census"]["schema_version"] = (
        "attacker.not-a-census.v999"
    )
    with pytest.raises(O.OCIImageLockError, match="census schema"):
        O.validate_image_lock(_resign(lock))


def _replace_attestation(
    root: Path,
    lock: dict,
    relative: str,
    raw: bytes,
) -> dict:
    target = root / relative
    target.write_bytes(raw)
    target.chmod(0o644)
    digest = _digest(raw)
    for row in lock["build_inputs"]:
        if row["path"] == relative:
            row["sha256"] = digest
            row["size"] = len(raw)
            break
    section = "sbom" if "sbom" in relative else "census"
    lock["attestations"][section]["sha256"] = digest
    return _resign(lock)


@pytest.mark.parametrize(
    "relative",
    (
        "attestations/sbom.spdx.json",
        "attestations/census.json",
    ),
)
def test_large_duplicate_retained_attestation_key_is_redacted_and_bounded(
    tmp_path: Path,
    relative: str,
) -> None:
    root, lock = _fixture(tmp_path)
    marker = "SENSITIVE_ATTACKER_FIELD_"
    key = marker + "x" * 500_000
    encoded_key = json.dumps(key).encode("utf-8")
    raw = b"{" + encoded_key + b":0," + encoded_key + b":1}\n"
    assert len(raw) < O._MAX_ATTESTATION_BYTES
    candidate = _replace_attestation(root, lock, relative, raw)

    with pytest.raises(O.OCIImageLockError) as raised:
        _render(candidate, root)
    assert str(raised.value) == "duplicate JSON key is forbidden"
    assert marker not in str(raised.value)
    assert len(str(raised.value).encode("utf-8")) < 128
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.parametrize(
    "raw",
    (
        b"not-json\n",
        O._canonical_bytes({"packages": [], "spdxVersion": "SPDX-2.3"}),
    ),
)
def test_sbom_must_be_valid_and_cover_every_runtime_digest(
    tmp_path: Path,
    raw: bytes,
) -> None:
    root, lock = _fixture(tmp_path)
    candidate = _replace_attestation(
        root,
        lock,
        "attestations/sbom.spdx.json",
        raw,
    )
    with pytest.raises(O.OCIImageLockError, match="SBOM"):
        _render(candidate, root)


def test_sbom_digest_cannot_be_bound_to_the_wrong_component(
    tmp_path: Path,
) -> None:
    root, lock = _fixture(tmp_path)
    sbom_path = root / "attestations" / "sbom.spdx.json"
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    sbom["packages"][0]["name"] = "backend_cli:attacker"
    candidate = _replace_attestation(
        root,
        lock,
        "attestations/sbom.spdx.json",
        O._canonical_bytes(sbom),
    )
    with pytest.raises(O.OCIImageLockError, match="exactly equal"):
        _render(candidate, root)


def test_resigned_sbom_cannot_append_an_unknown_package(
    tmp_path: Path,
) -> None:
    root, lock = _fixture(tmp_path)
    sbom_path = root / "attestations" / "sbom.spdx.json"
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    sbom["packages"].append(
        {
            "checksums": [
                {"algorithm": "SHA256", "checksumValue": "f" * 64}
            ],
            "name": "backend_cli:attacker",
            "versionInfo": "9.9.9",
        }
    )
    candidate = _replace_attestation(
        root,
        lock,
        "attestations/sbom.spdx.json",
        O._canonical_bytes(sbom),
    )
    with pytest.raises(O.OCIImageLockError, match="exactly equal"):
        _render(candidate, root)


def test_sbom_requires_the_exact_supported_schema_version(tmp_path: Path) -> None:
    root, lock = _fixture(tmp_path)
    sbom_path = root / "attestations" / "sbom.spdx.json"
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    sbom["spdxVersion"] = "SPDX-2.2"
    candidate = _replace_attestation(
        root,
        lock,
        "attestations/sbom.spdx.json",
        O._canonical_bytes(sbom),
    )
    with pytest.raises(O.OCIImageLockError, match="SPDX JSON schema"):
        _render(candidate, root)


def test_runtime_census_document_must_exactly_match_runtime_lock(
    tmp_path: Path,
) -> None:
    root, lock = _fixture(tmp_path)
    census_path = root / "attestations" / "census.json"
    census = json.loads(census_path.read_text(encoding="utf-8"))
    census["artifacts"][0]["path"] = "runtime/attacker"
    candidate = _replace_attestation(
        root,
        lock,
        "attestations/census.json",
        O._canonical_bytes(census),
    )
    with pytest.raises(O.OCIImageLockError, match="exactly bind"):
        _render(candidate, root)


def test_cyclonedx_sbom_binds_every_runtime_component(tmp_path: Path) -> None:
    root, lock = _fixture(tmp_path)
    census = json.loads(
        (root / "attestations" / "census.json").read_text(encoding="utf-8")
    )
    sbom = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "hashes": [{"alg": "SHA-256", "content": row["sha256"]}],
                "name": f"{row['role']}:{row['artifact_id']}",
                "version": row["version"] or "content-addressed",
            }
            for row in census["artifacts"]
        ],
        "specVersion": "1.6",
    }
    lock["attestations"]["sbom"]["format"] = "cyclonedx-json"
    candidate = _replace_attestation(
        root,
        lock,
        "attestations/sbom.spdx.json",
        O._canonical_bytes(sbom),
    )
    plan = _render(candidate, root)
    plan.close()


@pytest.mark.parametrize("mutation", ("old-version", "extra-component"))
def test_cyclonedx_sbom_requires_exact_version_and_component_closure(
    tmp_path: Path,
    mutation: str,
) -> None:
    root, lock = _fixture(tmp_path)
    census = json.loads(
        (root / "attestations" / "census.json").read_text(encoding="utf-8")
    )
    sbom = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "hashes": [{"alg": "SHA-256", "content": row["sha256"]}],
                "name": f"{row['role']}:{row['artifact_id']}",
                "version": row["version"] or "content-addressed",
            }
            for row in census["artifacts"]
        ],
        "specVersion": "1.6",
    }
    if mutation == "old-version":
        sbom["specVersion"] = "1.5"
    else:
        sbom["components"].append(
            {
                "hashes": [{"alg": "SHA-256", "content": "f" * 64}],
                "name": "backend_cli:attacker",
                "version": "9.9.9",
            }
        )
    lock["attestations"]["sbom"]["format"] = "cyclonedx-json"
    candidate = _replace_attestation(
        root,
        lock,
        "attestations/sbom.spdx.json",
        O._canonical_bytes(sbom),
    )
    with pytest.raises(O.OCIImageLockError, match="CycloneDX|exactly equal"):
        _render(candidate, root)


def test_actual_size_mismatch_is_rejected_before_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, lock = _fixture(tmp_path)
    target = root / "artifacts" / "python.tar"
    with target.open("r+b") as handle:
        handle.truncate(64 * 1024 * 1024 * 1024)
    calls: list[int] = []

    def forbidden_hash(_descriptor: int, size: int) -> str:
        calls.append(size)
        raise AssertionError("size-mismatched input reached the hasher")

    monkeypatch.setattr(O, "_file_sha256", forbidden_hash)
    monkeypatch.setattr(O, "_snapshot_file", forbidden_hash)
    with pytest.raises(O.OCIImageLockError, match="drifted from its lock"):
        _render(lock, root)
    assert calls == []


def test_symlinked_build_root_ancestor_is_rejected(tmp_path: Path) -> None:
    real_parent = tmp_path / "real"
    root, lock = _fixture(real_parent)
    alias = tmp_path / "alias"
    alias.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(O.OCIImageLockError, match="aliased"):
        O._render_build_plan_for_testing(
            lock,
            alias / "context",
            expected_lock_sha256=lock["lock_sha256"],
            release_generation=1,
            release_nonce="e" * 32,
            durable_replay_consumer=_replay_consumer(),
        )


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin xattr backend")
def test_default_darwin_inspector_rejects_real_xattr(tmp_path: Path) -> None:
    tool = Path("/usr/bin/xattr")
    if not tool.is_file():
        pytest.skip("Darwin xattr utility is unavailable")
    root, lock = _fixture(tmp_path)
    target = root / "runtime" / "closure.json"
    result = subprocess.run(
        [str(tool), "-w", "com.plamen.test", "hidden", str(target)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"host cannot create test xattr: {result.stderr}")
    with pytest.raises(O.OCIImageLockError, match="extended metadata"):
        _render(lock, root)


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin HFS compression")
def test_default_darwin_inspector_detects_hidden_compression_xattr(
    tmp_path: Path,
) -> None:
    ditto = Path("/usr/bin/ditto")
    if not ditto.is_file():
        pytest.skip("Darwin ditto utility is unavailable")
    source = tmp_path / "source"
    compressed = tmp_path / "compressed"
    source.write_bytes(b"A" * (1024 * 1024))
    result = subprocess.run(
        [str(ditto), "--hfsCompression", str(source), str(compressed)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or not compressed.is_file():
        pytest.skip(f"host cannot create compressed file: {result.stderr}")
    descriptor = os.open(compressed, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        inspector = O._default_metadata_inspector()
        assert inspector is not None
        with pytest.raises(O.OCIImageLockError, match="forbidden"):
            O._assert_no_extended_metadata(
                descriptor,
                inspector=inspector,
                label="compressed input",
            )
    finally:
        os.close(descriptor)


def test_darwin_descriptor_xattr_query_includes_compression_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, int]] = []
    public_calls: list[int] = []

    def incomplete_public_wrapper(descriptor: int):
        public_calls.append(descriptor)
        return ()

    class FakeFListXAttr:
        argtypes = None
        restype = None

        def __call__(
            self,
            descriptor: int,
            _buffer: object,
            _size: int,
            options: int,
        ) -> int:
            calls.append((descriptor, options))
            return 41

    class FakeLibC:
        flistxattr = FakeFListXAttr()

    monkeypatch.setattr(
        O.os,
        "listxattr",
        incomplete_public_wrapper,
        raising=False,
    )
    monkeypatch.setattr(O.os, "supports_fd", {incomplete_public_wrapper})
    monkeypatch.setattr(O.sys, "platform", "darwin")
    monkeypatch.setattr(ctypes, "CDLL", lambda *_args, **_kwargs: FakeLibC())
    inspector = O._default_metadata_inspector()
    assert inspector is not None
    assert inspector(73) == (b"<extended-metadata-present>",)
    assert calls == [(73, O._XATTR_SHOWCOMPRESSION)]
    assert public_calls == []
    assert O._XATTR_SHOWCOMPRESSION == 0x20


def test_retained_authority_isolated_from_post_render_path_mutation(
    tmp_path: Path,
) -> None:
    root, lock = _fixture(tmp_path)
    plan = _render(lock, root)
    target = root / "runtime" / "closure.json"
    target.write_bytes(b'{"runtime":"altered"}\n')
    consumed = _consume_all(plan)
    assert consumed["runtime/closure.json"] == b'{"runtime":"closed"}\n'


def test_retained_authority_is_one_shot_and_requires_exact_consumption(
    tmp_path: Path,
) -> None:
    root, lock = _fixture(tmp_path)
    plan = _render(lock, root)
    with pytest.raises(O.OCIImageLockError, match="did not consume"):
        plan.consume_build_context_for_testing(lambda readers: readers[0].read(1))
    with pytest.raises(O.OCIImageLockError, match="unavailable or consumed"):
        plan.consume_build_context_for_testing(lambda _readers: None)


def test_production_consumer_refuses_python_completion_forgery_and_zero_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, lock = _fixture(tmp_path)
    plan = _render(lock, root)
    callback_calls: list[tuple] = []
    monkeypatch.setattr(O, "_require_reader_complete", lambda _reader: None)

    def zero_byte_forgery(readers) -> None:
        callback_calls.append(readers)

    with pytest.raises(
        O.OCIImageLockError,
        match=O._CONTEXT_CONSUMER_REQUIRED,
    ):
        plan.consume_build_context(zero_byte_forgery)
    assert callback_calls == []
    with pytest.raises(O.OCIImageLockError, match="unavailable or consumed"):
        plan.consume_build_context_for_testing(zero_byte_forgery)


def test_reader_completion_cannot_be_forged_through_object_attributes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, lock = _fixture(tmp_path)
    plan = _render(lock, root)
    captured = []

    def forge_completion(readers) -> None:
        reader = readers[0]
        captured.append(reader)
        for field, value in (("_complete", True), ("_observed", 0)):
            with pytest.raises(AttributeError):
                setattr(reader, field, value)
        monkeypatch.setattr(O, "_require_reader_complete", lambda _reader: None)
        monkeypatch.setattr(O, "_revoke_reader", lambda _reader: None)

    with pytest.raises(O.OCIImageLockError, match="did not consume"):
        plan.consume_build_context_for_testing(forge_completion)
    assert not hasattr(captured[0], "__dict__")
    with pytest.raises(O.OCIImageLockError, match="revoked"):
        captured[0].read()


def test_public_error_drops_sensitive_low_level_cause_and_context(
    tmp_path: Path,
) -> None:
    _root, lock = _fixture(tmp_path)
    secret_component = "credential-do-not-disclose"
    with pytest.raises(O.OCIImageLockError) as raised:
        O._render_build_plan_for_testing(
            lock,
            tmp_path / secret_component / "context",
            expected_lock_sha256=lock["lock_sha256"],
            release_generation=1,
            release_nonce="e" * 32,
            durable_replay_consumer=_replay_consumer(),
        )
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert secret_component not in str(raised.value)


def test_consumer_exception_is_sanitized_without_retaining_context(
    tmp_path: Path,
) -> None:
    root, lock = _fixture(tmp_path)
    plan = _render(lock, root)

    def fail(_readers) -> None:
        raise FileNotFoundError(2, "missing", "credential-do-not-disclose")

    with pytest.raises(O.OCIImageLockError, match="failed closed") as raised:
        plan.consume_build_context_for_testing(fail)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert "credential-do-not-disclose" not in str(raised.value)


def test_reader_error_is_sanitized_before_control_returns_to_consumer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, lock = _fixture(tmp_path)
    plan = _render(lock, root)
    observed: list[BaseException] = []

    def fail_read(readers) -> None:
        def missing(_descriptor: int, _size: int) -> bytes:
            raise FileNotFoundError(
                2,
                "missing",
                "credential-do-not-disclose",
            )

        monkeypatch.setattr(O.os, "read", missing)
        try:
            readers[0].read()
        except O.OCIImageLockError as exc:
            observed.append(exc)

    with pytest.raises(O.OCIImageLockError, match="did not consume"):
        plan.consume_build_context_for_testing(fail_read)
    assert len(observed) == 1
    assert observed[0].__cause__ is None
    assert observed[0].__context__ is None
    assert "credential-do-not-disclose" not in str(observed[0])


def test_retained_authority_close_releases_every_snapshot_descriptor(
    tmp_path: Path,
) -> None:
    descriptor_root = Path("/dev/fd")
    if not descriptor_root.is_dir():
        pytest.skip("host does not expose a descriptor census")
    root, lock = _fixture(tmp_path)
    before = len(tuple(descriptor_root.iterdir()))
    for _index in range(20):
        plan = _render(lock, root)
        plan.close()
    assert len(tuple(descriptor_root.iterdir())) == before


def test_plan_tampering_revokes_retained_context_authority(tmp_path: Path) -> None:
    root, lock = _fixture(tmp_path)
    plan = _render(lock, root)
    with pytest.raises(TypeError, match="immutable"):
        plan["network"] = "ALLOW"
    plan["build_inputs"][0]["size"] += 1
    with pytest.raises(O.OCIImageLockError, match="plan changed"):
        plan.consume_build_context_for_testing(lambda _readers: None)


def test_deep_paths_are_bounded_before_prefix_expansion(tmp_path: Path) -> None:
    _root, lock = _fixture(tmp_path)
    lock["build_inputs"][0]["path"] = (
        "nested/" * (O._MAX_PATH_COMPONENTS + 1) + "leaf"
    )
    with pytest.raises(O.OCIImageLockError, match="path"):
        O.validate_image_lock(_resign(lock))


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("required_roles", ["base_rootfs"], "role roster"),
        ("source_roster_sha256", "f" * 64, None),
    ],
)
def test_runtime_materialization_identity_is_structurally_closed(
    tmp_path: Path, field: str, replacement: object, message: str | None,
) -> None:
    _root, lock = _fixture(tmp_path)
    lock["runtime_materialization"][field] = replacement
    candidate = _resign(lock)
    if message is not None:
        with pytest.raises(O.OCIImageLockError, match=message):
            O.validate_image_lock(candidate)
    else:
        # A structurally valid changed identity is rejected when the retained
        # receipt/census/provenance closure is authenticated.
        with pytest.raises(O.OCIImageLockError, match="materialization"):
            _render(candidate, _root)
