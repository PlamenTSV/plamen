from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

import opengrep_release_policy as O


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / O.POLICY_PATH
SOURCE_MANIFEST = ROOT / O.SOURCE_MANIFEST_PATH


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _changed_document(path: tuple[str, ...], replacement: object) -> bytes:
    changed = copy.deepcopy(json.loads(POLICY.read_bytes()))
    cursor = changed
    for component in path[:-1]:
        cursor = cursor[component]
    cursor[path[-1]] = replacement
    return _canonical(changed)


def test_reviewed_v1300_policy_binds_exact_three_retained_release_inputs() -> None:
    raw = POLICY.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == O.POLICY_SHA256
    policy = O.load_opengrep_acquisition_policy(raw)
    inputs = policy["artifact"]["retained_inputs"]
    assert tuple(inputs) == ("certificate", "payload", "signature")
    assert inputs == {
        "certificate": {
            "asset_id": 548_657_430,
            "filename": "opengrep_manylinux_aarch64.cert",
            "sha256": O.CERTIFICATE_SHA256,
            "size": 3_368,
            "url": "https://github.com/opengrep/opengrep/releases/download/v1.30.0/opengrep_manylinux_aarch64.cert",
        },
        "payload": {
            "asset_id": 548_657_431,
            "filename": "opengrep_manylinux_aarch64",
            "sha256": O.PAYLOAD_SHA256,
            "size": 47_982_360,
            "url": "https://github.com/opengrep/opengrep/releases/download/v1.30.0/opengrep_manylinux_aarch64",
        },
        "signature": {
            "asset_id": 548_657_439,
            "filename": "opengrep_manylinux_aarch64.sig",
            "sha256": O.SIGNATURE_SHA256,
            "size": 96,
            "url": "https://github.com/opengrep/opengrep/releases/download/v1.30.0/opengrep_manylinux_aarch64.sig",
        },
    }


def test_policy_is_setup_only_offline_and_explicitly_non_authoritative() -> None:
    policy = O.load_opengrep_acquisition_policy(POLICY.read_bytes())
    assert policy["materialization"] == {
        "acquisition_scope": "SETUP_ONLY",
        "audit_network": "DENY",
        "identity_mode": "STATIC_PAYLOAD",
        "next_required_authorities": list(O.NEXT_REQUIRED_AUTHORITIES),
        "production_authority": False,
        "retained_input_count": 3,
    }
    requirement = O.native_producer_receipt_requirement()
    assert requirement["production_authority"] is False
    assert requirement["next_required_authorities"] == (
        "PLAMEN_NATIVE_SOURCE_BOOTSTRAP_COORDINATOR_RECEIPT_V1",
        "NATIVE_RETAINED_FD_RUNTIME_MATERIALIZATION_RECEIPT",
        "APPLE_CONTAINER_RUNTIME_IMAGE_ADMISSION_RECEIPT",
    )
    assert requirement["retained_inputs"] == (
        ("certificate", 548_657_430, O.CERTIFICATE_SHA256, 3_368),
        ("payload", 548_657_431, O.PAYLOAD_SHA256, 47_982_360),
        ("signature", 548_657_439, O.SIGNATURE_SHA256, 96),
    )


def test_release_identity_sigstore_provenance_and_direct_elf_are_exact() -> None:
    artifact = O.load_opengrep_acquisition_policy(POLICY.read_bytes())["artifact"]
    assert artifact["upstream"] == {
        "api_url": "https://api.github.com/repos/opengrep/opengrep/releases/tags/v1.30.0",
        "published_at": "2026-09-07T11:20:14Z",
        "release_id": 384_027_581,
        "release_url": "https://github.com/opengrep/opengrep/releases/tag/v1.30.0",
        "tag": "v1.30.0",
    }
    assert artifact["sigstore"] == {
        "certificate_identity": O.CERTIFICATE_IDENTITY,
        "certificate_oidc_issuer": O.CERTIFICATE_OIDC_ISSUER,
        "signed_input": "payload",
        "source_commit": O.SOURCE_COMMIT,
        "verification": "SIGSTORE_KEYLESS_BLOB_CERTIFICATE_SIGNATURE",
    }
    assert artifact["executable"] == {
        "elf_class": 64,
        "endianness": "little",
        "machine": "aarch64",
        "sha256": O.PAYLOAD_SHA256,
        "size": 47_982_360,
    }
    assert artifact["install"] == {
        "media_type": "application/vnd.plamen.executable",
        "mode": "0555",
        "path": O.INSTALL_PATH,
        "role": "opengrep",
    }


def test_runtime_source_manifest_is_canonical_and_bound_to_payload() -> None:
    raw = SOURCE_MANIFEST.read_bytes()
    assert len(raw) == O.SOURCE_MANIFEST_SIZE
    assert hashlib.sha256(raw).hexdigest() == O.SOURCE_MANIFEST_SHA256
    source = O.load_opengrep_runtime_source_manifest(raw)
    assert source == {
        "artifact_id": O.ARTIFACT_ID,
        "authentication_scope": "NATIVE_RETAINED_SOURCE_INPUT",
        "media_type": "application/vnd.plamen.executable",
        "payload_sha256": O.PAYLOAD_SHA256,
        "payload_size": 47_982_360,
        "platform": "linux/arm64",
        "required_paths": [O.INSTALL_PATH],
        "role": "opengrep",
        "schema_version": "plamen.runtime_source_manifest.native-retained.v1",
        "source_reference": "https://github.com/opengrep/opengrep/releases/download/v1.30.0/opengrep_manylinux_aarch64",
        "version": "1.30.0",
    }


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("artifact", "retained_inputs", "payload", "sha256"), "0" * 64),
        (("artifact", "retained_inputs", "certificate", "asset_id"), 548_657_431),
        (("artifact", "retained_inputs", "signature", "size"), 95),
        (("artifact", "sigstore", "source_commit"), "0" * 40),
        (("artifact", "sigstore", "certificate_identity"), "https://example.invalid"),
        (("artifact", "executable", "machine"), "x86_64"),
        (("artifact", "install", "mode"), "0755"),
        (("materialization", "audit_network"), "ALLOW"),
        (("materialization", "production_authority"), 0),
        (("materialization", "retained_input_count"), 2),
        (("materialization", "next_required_authorities"), []),
    ],
)
def test_semantic_mutation_is_rejected_even_with_recomputed_outer_digest(
    path: tuple[str, ...], replacement: object
) -> None:
    raw = _changed_document(path, replacement)
    with pytest.raises(O.OpenGrepReleasePolicyError):
        O.load_opengrep_acquisition_policy(
            raw, expected_sha256=hashlib.sha256(raw).hexdigest()
        )


def test_policy_digest_and_canonical_bytes_are_not_advisory() -> None:
    raw = POLICY.read_bytes()
    changed = bytearray(raw)
    changed[20] ^= 1
    with pytest.raises(O.OpenGrepReleasePolicyError, match="policy digest differs"):
        O.load_opengrep_acquisition_policy(bytes(changed))

    noncanonical = raw[:-1] + b" \n"
    with pytest.raises(O.OpenGrepReleasePolicyError, match="canonical JSON"):
        O.load_opengrep_acquisition_policy(
            noncanonical,
            expected_sha256=hashlib.sha256(noncanonical).hexdigest(),
        )


def test_source_manifest_semantic_mutation_fails_with_recomputed_digest() -> None:
    changed = json.loads(SOURCE_MANIFEST.read_bytes())
    changed["payload_size"] += 1
    raw = _canonical(changed)
    with pytest.raises(O.OpenGrepReleasePolicyError, match="semantics differ"):
        O.load_opengrep_runtime_source_manifest(
            raw, expected_sha256=hashlib.sha256(raw).hexdigest()
        )


def test_duplicate_keys_are_rejected_before_any_policy_projection() -> None:
    raw = b'{"artifact":{},"artifact":{},"materialization":{},"schema":"x"}\n'
    with pytest.raises(O.OpenGrepReleasePolicyError, match="duplicate"):
        O.load_opengrep_acquisition_policy(
            raw, expected_sha256=hashlib.sha256(raw).hexdigest()
        )
