"""Apple Container v2 runtime-image source-plan boundary tests."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

import runtime_image_materializer as R
from test_runtime_image_materializer import _fixture_values


ROOT = Path(__file__).resolve().parent.parent


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _candidate() -> tuple[dict, bytes]:
    manifest, _payloads, _source_manifests = _fixture_values()
    manifest = copy.deepcopy(manifest)
    manifest["schema_version"] = R.APPLE_CONTAINER_COMPOSITION_SCHEMA_VERSION
    manifest["authentication_scope"] = R.NATIVE_RETAINED_AUTHENTICATION_SCOPE
    source_manifest = _canonical(
        {
            "artifact_id": "opengrep-1.30.0-manylinux-aarch64",
            "authentication_scope": R.NATIVE_RETAINED_AUTHENTICATION_SCOPE,
            "media_type": "application/vnd.plamen.executable",
            "payload_sha256": "a5d5a4a58ba5d46ff51e921663da1c2bba38f4b03987f4aeec87f16c6ad3ecae",
            "payload_size": 47_982_360,
            "platform": "linux/arm64",
            "required_paths": [
                "/usr/local/lib/plamen/toolchains/opengrep/bin/opengrep"
            ],
            "role": "opengrep",
            "schema_version": R.NATIVE_RETAINED_SOURCE_MANIFEST_SCHEMA_VERSION,
            "source_reference": (
                "https://github.com/opengrep/opengrep/releases/download/"
                "v1.30.0/opengrep_manylinux_aarch64"
            ),
            "version": "1.30.0",
        }
    )
    manifest["sources"].append(
        {
            "artifact_id": "opengrep-1.30.0-manylinux-aarch64",
            "destination": "/usr/local/lib/plamen/toolchains/opengrep/bin/opengrep",
            "media_type": "application/vnd.plamen.executable",
            "payload_sha256": "a5d5a4a58ba5d46ff51e921663da1c2bba38f4b03987f4aeec87f16c6ad3ecae",
            "payload_size": 47_982_360,
            "required_paths": [
                "/usr/local/lib/plamen/toolchains/opengrep/bin/opengrep"
            ],
            "role": "opengrep",
            "source_manifest_sha256": hashlib.sha256(source_manifest).hexdigest(),
            "source_manifest_size": len(source_manifest),
        }
    )
    return manifest, source_manifest


def test_v2_candidate_binds_distinct_pinned_opengrep_role() -> None:
    manifest, source_manifest = _candidate()
    raw = _canonical(manifest)
    value, rows = R.validate_apple_container_composition_candidate(
        raw, expected_sha256=hashlib.sha256(raw).hexdigest()
    )
    assert value["schema_version"] == R.APPLE_CONTAINER_COMPOSITION_SCHEMA_VERSION
    assert tuple(row["role"] for row in rows) == R.APPLE_CONTAINER_REQUIRED_ROLES
    opengrep = rows[-1]
    assert opengrep["payload_sha256"] == (
        "a5d5a4a58ba5d46ff51e921663da1c2bba38f4b03987f4aeec87f16c6ad3ecae"
    )
    validated = R._validate_source_manifest(
        source_manifest,
        opengrep,
        expected_schema_version=R.NATIVE_RETAINED_SOURCE_MANIFEST_SCHEMA_VERSION,
        expected_authentication_scope=R.NATIVE_RETAINED_AUTHENTICATION_SCOPE,
    )
    assert validated["platform"] == "linux/arm64"


def test_installer_image_policy_binds_reviewed_static_inputs_but_no_authority() -> None:
    raw = (ROOT / R.APPLE_CONTAINER_IMAGE_GENERATION_POLICY_PATH).read_bytes()
    policy = R.load_apple_container_image_generation_policy(raw)
    assert hashlib.sha256(raw).hexdigest() == R.APPLE_CONTAINER_IMAGE_GENERATION_POLICY_SHA256
    assert len(raw) == R.APPLE_CONTAINER_IMAGE_GENERATION_POLICY_SIZE
    assert policy["cache"] == {
        "ambient_cache": "DENY",
        "content_identity": "SHA256_PLUS_SIZE",
        "network_scope": "INSTALLER_SETUP_ONLY",
        "retained_inputs": "EXACT_O_RDONLY_DESCRIPTOR_ROSTER",
        "runtime_network": "DENY",
        "transaction": "PRIVATE_STAGE_VALIDATE_ATOMIC_COMMIT_OR_ROLLBACK",
    }
    members = policy["composition"]["static_members"]
    assert [row["role"] for row in members] == ["foundry", "medusa", "opengrep"]
    for member in members:
        for binding in ("acquisition_policy", "source_manifest"):
            expected = member[binding]
            bound = (ROOT / expected["path"]).read_bytes()
            assert len(bound) == expected["size"]
            assert hashlib.sha256(bound).hexdigest() == expected["sha256"]
    assert members[-1]["producer_receipt"] is None
    assert policy["generation"]["production_authority"] is False
    assert policy["generation"]["state"] == "CANDIDATE_BLOCKED"
    assert "NATIVE_OPENGREP_SIGSTORE_ACQUISITION_RECEIPT" in policy["generation"][
        "missing_authorities"
    ]


def test_installer_image_policy_rejects_mutation_and_noncanonical_bytes() -> None:
    raw = (ROOT / R.APPLE_CONTAINER_IMAGE_GENERATION_POLICY_PATH).read_bytes()
    value = json.loads(raw)
    value["cache"]["runtime_network"] = "OPEN"
    with pytest.raises(R.RuntimeMaterializationError, match="digest differs"):
        R.load_apple_container_image_generation_policy(_canonical(value))
    with pytest.raises(R.RuntimeMaterializationError, match="size differs"):
        R.load_apple_container_image_generation_policy(raw + b"\n")


def test_v1_native_wire_cannot_silently_absorb_opengrep_ordinal() -> None:
    manifest, _ = _candidate()
    manifest["schema_version"] = R.NATIVE_RETAINED_COMPOSITION_SCHEMA_VERSION
    raw = _canonical(manifest)
    with pytest.raises(R.RuntimeMaterializationError, match="roster is not exact"):
        R._validate_composition_manifest(
            raw,
            hashlib.sha256(raw).hexdigest(),
            expected_schema_version=R.NATIVE_RETAINED_COMPOSITION_SCHEMA_VERSION,
            expected_authentication_scope=R.NATIVE_RETAINED_AUTHENTICATION_SCOPE,
        )


@pytest.mark.parametrize("mutation", ("missing", "cross-platform", "wrong-path"))
def test_v2_opengrep_absence_or_cross_binding_fails_closed(mutation: str) -> None:
    manifest, source_manifest = _candidate()
    if mutation == "missing":
        manifest["sources"].pop()
        raw = _canonical(manifest)
        with pytest.raises(R.RuntimeMaterializationError, match="roster is not exact"):
            R.validate_apple_container_composition_candidate(
                raw, expected_sha256=hashlib.sha256(raw).hexdigest()
            )
        return
    source = manifest["sources"][-1]
    value = json.loads(source_manifest)
    if mutation == "cross-platform":
        value["platform"] = "darwin/arm64"
    else:
        value["required_paths"] = ["/usr/local/bin/opengrep"]
    mutated = _canonical(value)
    source["source_manifest_sha256"] = hashlib.sha256(mutated).hexdigest()
    source["source_manifest_size"] = len(mutated)
    with pytest.raises(R.RuntimeMaterializationError):
        R._validate_source_manifest(
            mutated,
            source,
            expected_schema_version=R.NATIVE_RETAINED_SOURCE_MANIFEST_SCHEMA_VERSION,
            expected_authentication_scope=R.NATIVE_RETAINED_AUTHENTICATION_SCOPE,
        )


def test_production_stays_unavailable_until_v2_native_signer_exists(monkeypatch) -> None:
    touched = False

    def explode(*_args, **_kwargs):
        nonlocal touched
        touched = True
        raise AssertionError("input inspected")

    monkeypatch.setattr(R.os, "fstat", explode)
    with pytest.raises(
        R.RuntimeMaterializationUnsupported,
        match="APPLE_CONTAINER_V2_STATIC_TOOL_ROSTER_UNSIGNED",
    ):
        R.materialize_runtime_image(object(), payload=object())
    assert touched is False
