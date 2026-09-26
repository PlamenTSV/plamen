from __future__ import annotations

import json
from pathlib import Path

import pytest

import native_static_acquisition_policies as P
import runtime_image_materializer as R


ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> bytes:
    return (ROOT / path).read_bytes()


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


@pytest.mark.parametrize("contract", (P.FOUNDRY, P.AMD64_COMPAT))
def test_reviewed_static_role_inputs_are_exact_and_cross_bound(
    contract: P.StaticAcquisitionContract,
) -> None:
    policy = P.load_static_acquisition_policy(
        contract.role, _read(contract.policy_path)
    )
    receipt = P.load_static_semantic_receipt(
        contract.role, _read(contract.receipt_path)
    )
    manifest = P.load_static_source_manifest(
        contract.role, _read(contract.source_manifest_path)
    )
    projection = P.native_operation4_static_policy_input(contract.role)
    assert policy["materialization"]["output"]["payload"] == receipt["payload"]
    assert receipt["payload"] == {
        "sha256": manifest["payload_sha256"],
        "size": manifest["payload_size"],
    }
    assert receipt["source_manifest"] == {
        "sha256": contract.source_manifest_sha256,
        "size": contract.source_manifest_size,
    }
    assert projection == {
        "identity_mode": 1,
        "payload_sha256": contract.payload_sha256,
        "payload_size": contract.payload_size,
        "policy_sha256": contract.policy_sha256,
        "producer_fd_size": contract.receipt_size + 512,
        "receipt_schema": contract.receipt_schema,
        "receipt_validator": contract.receipt_validator,
        "role": contract.role,
        "role_ordinal": contract.role_ordinal,
        "semantic_receipt_sha256": contract.receipt_sha256,
        "semantic_receipt_size": contract.receipt_size,
        "source_manifest_sha256": contract.source_manifest_sha256,
        "source_manifest_size": contract.source_manifest_size,
        "version": contract.version,
    }
    destination, media_types = R._ROLE_CONTRACT[contract.role]
    R._validate_source_manifest(
        _read(contract.source_manifest_path),
        {
            "artifact_id": contract.artifact_id,
            "destination": destination,
            "media_type": next(iter(media_types)),
            "payload_sha256": contract.payload_sha256,
            "payload_size": contract.payload_size,
            "required_paths": list(R._REQUIRED_OUTPUTS[contract.role]),
            "role": contract.role,
            "source_manifest_sha256": contract.source_manifest_sha256,
            "source_manifest_size": contract.source_manifest_size,
        },
        expected_schema_version=R.NATIVE_RETAINED_SOURCE_MANIFEST_SCHEMA_VERSION,
        expected_authentication_scope=R.NATIVE_RETAINED_AUTHENTICATION_SCOPE,
    )


@pytest.mark.parametrize("contract", (P.FOUNDRY, P.AMD64_COMPAT))
def test_operation4_semantic_receipt_wire_is_canonical_json_without_lf(
    contract: P.StaticAcquisitionContract,
) -> None:
    raw = _read(contract.receipt_path)
    value = json.loads(raw)
    expected = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    assert raw == expected
    assert raw.endswith(b"}")
    assert b"\n" not in raw and b"\r" not in raw


def test_foundry_policy_uses_official_stable_release_and_sigstore_identity() -> None:
    policy = P.load_static_acquisition_policy(
        "foundry", _read(P.FOUNDRY.policy_path)
    )
    artifact = policy["artifact"]
    assert artifact["upstream"] == {
        "api_url": "https://api.github.com/repos/foundry-rs/foundry/releases/tags/v1.8.1",
        "published_at": "2026-08-28T19:03:04Z",
        "release_id": 378652150,
        "release_url": "https://github.com/foundry-rs/foundry/releases/tag/v1.8.1",
        "security_policy_url": "https://github.com/foundry-rs/foundry/security",
        "tag": "v1.8.1",
    }
    assert artifact["sigstore"]["certificate_identity"].endswith(
        "/release.yml@refs/tags/v1.8.1"
    )
    assert artifact["sigstore"]["certificate_oidc_issuer"] == (
        "https://token.actions.githubusercontent.com"
    )
    assert policy["materialization"]["ambient_foundryup"] == "DENY"


def test_amd64_policy_reuses_exact_official_debian_index_and_direct_closure() -> None:
    policy = P.load_static_acquisition_policy(
        "amd64_compat", _read(P.AMD64_COMPAT.policy_path)
    )
    artifact = policy["artifact"]
    assert artifact["index"]["sha256"] == (
        "88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171"
    )
    assert artifact["official_images"]["url"].startswith(
        "https://raw.githubusercontent.com/docker-library/official-images/"
    )
    assert artifact["source"]["repository_url"] == "https://hub.docker.com/_/debian"
    assert policy["materialization"]["ambient_apt"] == "DENY"
    receipt = P.load_static_semantic_receipt(
        "amd64_compat", _read(P.AMD64_COMPAT.receipt_path)
    )
    members = receipt["materialization"]["members"]
    assert [row["path"] for row in members] == policy["materialization"][
        "selected_members"
    ]
    assert members[-1] == {
        "kind": "symlink",
        "linkname": "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        "path": "usr/lib64/ld-linux-x86-64.so.2",
    }


@pytest.mark.parametrize(
    ("contract", "kind", "path", "replacement"),
    [
        (P.FOUNDRY, "policy", ("artifact", "version"), "1.8.2"),
        (
            P.FOUNDRY,
            "policy",
            ("artifact", "sigstore", "source_commit"),
            "0" * 40,
        ),
        (
            P.FOUNDRY,
            "receipt",
            ("materialization", "archive_members", 3, "sha256"),
            "0" * 64,
        ),
        (
            P.AMD64_COMPAT,
            "policy",
            ("artifact", "layer", "sha256"),
            "0" * 64,
        ),
        (
            P.AMD64_COMPAT,
            "receipt",
            ("materialization", "members", 8, "linkname"),
            "/tmp/attacker",
        ),
        (
            P.AMD64_COMPAT,
            "manifest",
            ("required_paths", 0),
            "/usr/local/bin/ld-linux-x86-64.so.2",
        ),
    ],
)
def test_mutated_reviewed_input_is_rejected(
    contract: P.StaticAcquisitionContract,
    kind: str,
    path: tuple[str | int, ...],
    replacement: object,
) -> None:
    file_path = {
        "policy": contract.policy_path,
        "receipt": contract.receipt_path,
        "manifest": contract.source_manifest_path,
    }[kind]
    changed = json.loads(_read(file_path))
    cursor = changed
    for component in path[:-1]:
        cursor = cursor[component]
    cursor[path[-1]] = replacement
    raw = _canonical(changed)
    loader = {
        "policy": P.load_static_acquisition_policy,
        "receipt": P.load_static_semantic_receipt,
        "manifest": P.load_static_source_manifest,
    }[kind]
    with pytest.raises(P.StaticAcquisitionPolicyError, match="exact bytes differ"):
        loader(contract.role, raw)


def test_duplicate_noncanonical_and_cross_role_inputs_fail_closed() -> None:
    foundry = _read(P.FOUNDRY.policy_path)
    duplicate = foundry.replace(
        b'{"artifact":', b'{"schema":"attacker","artifact":', 1
    )
    with pytest.raises(P.StaticAcquisitionPolicyError):
        P.load_static_acquisition_policy("foundry", duplicate)
    with pytest.raises(P.StaticAcquisitionPolicyError):
        P.load_static_acquisition_policy("amd64_compat", foundry)
    with pytest.raises(P.StaticAcquisitionPolicyError, match="unsupported"):
        P.native_operation4_static_policy_input("attacker")
