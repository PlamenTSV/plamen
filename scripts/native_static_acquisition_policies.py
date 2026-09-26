"""Reviewed static operation-4 acquisition inputs for native runtime roles.

This module validates frozen policy, semantic-receipt, and source-manifest
bytes.  It never downloads, extracts, signs, appends the native producer
footer, or opens an installation path.  Those effects belong to the signed
native source-bootstrap coordinator.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, NoReturn


NEXT_REQUIRED_AUTHORITY = "PLAMEN_NATIVE_SOURCE_BOOTSTRAP_COORDINATOR_RECEIPT_V1"
PRODUCER_FOOTER_SIZE = 512
STATIC_PAYLOAD_IDENTITY_MODE = 1

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class StaticAcquisitionPolicyError(RuntimeError):
    """Frozen acquisition input bytes or semantics differ."""


@dataclass(frozen=True, slots=True)
class StaticAcquisitionContract:
    role: str
    role_ordinal: int
    receipt_validator: int
    version: str
    policy_path: str
    policy_sha256: str
    policy_size: int
    receipt_path: str
    receipt_schema: str
    receipt_sha256: str
    receipt_size: int
    source_manifest_path: str
    source_manifest_sha256: str
    source_manifest_size: int
    payload_sha256: str
    payload_size: int
    platform: str
    artifact_id: str


FOUNDRY = StaticAcquisitionContract(
    role="foundry",
    role_ordinal=7,
    receipt_validator=5,
    version="1.8.1",
    policy_path="verification_policy/foundry_acquisition.v1.json",
    policy_sha256="b52bbbcd7eb6900bc6d6fdafbd45465cad4a47ab211ac5a1438f180f9e2eff6a",
    policy_size=2307,
    receipt_path="verification_policy/foundry_acquisition_receipt.v1.json",
    receipt_schema="plamen.foundry-acquisition-receipt.v1",
    receipt_sha256="1bd453b262415bc1153d4ecdecc99e134b96df45f3d511b7a2f144ed87ede436",
    receipt_size=1616,
    source_manifest_path="verification_policy/foundry_runtime_source_manifest.v1.json",
    source_manifest_sha256="6f380e0dd982ebc76a77e5c463b765c04ed440ebf2ed873bf691d4d927bed9f9",
    source_manifest_size=745,
    payload_sha256="b19dfe910e75b23aabd21f58181f561bca73d51a24be39fa3b900ecd5f0d288b",
    payload_size=269_271_040,
    platform="linux/arm64",
    artifact_id="foundry-1.8.1-linux-arm64",
)

AMD64_COMPAT = StaticAcquisitionContract(
    role="amd64_compat",
    role_ordinal=10,
    receipt_validator=8,
    version="bookworm-20260824-slim",
    policy_path="verification_policy/amd64_compat_acquisition.v1.json",
    policy_sha256="d7951743a7c7f4573ded15905320a56debbee12578d561144086456a110b8d7e",
    policy_size=2562,
    receipt_path="verification_policy/amd64_compat_acquisition_receipt.v1.json",
    receipt_schema="plamen.amd64-compat-acquisition-receipt.v1",
    receipt_sha256="808eeea571533676faf9cd9d41b7a146f62f4a3baee29ee3d4d89965eca26fa0",
    receipt_size=2504,
    source_manifest_path="verification_policy/amd64_compat_runtime_source_manifest.v1.json",
    source_manifest_sha256="5d05126bd00f1765d09a5a27dba8b144a81fcc96e6c50f9ff5410b740dda74a0",
    source_manifest_size=652,
    payload_sha256="4e9c886e6558a93cfbdab5cec905852209fc3c61a867c9672a0162522e36e490",
    payload_size=3_112_960,
    platform="linux/amd64",
    artifact_id="debian-bookworm-20260824-amd64-compat",
)

CONTRACTS = {contract.role: contract for contract in (FOUNDRY, AMD64_COMPAT)}


def _fail(message: str) -> NoReturn:
    raise StaticAcquisitionPolicyError(message) from None


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if type(key) is not str or key in value:
            _fail("static acquisition JSON contains a duplicate/non-string key")
        value[key] = item
    return value


def _canonical(value: Any) -> bytes:
    try:
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
    except (TypeError, ValueError, UnicodeError):
        _fail("static acquisition JSON is not canonicalizable")


def _decode(raw: bytes, *, digest: str, size: int, label: str,
            trailing_lf: bool = True) -> dict[str, Any]:
    if (
        type(raw) is not bytes
        or len(raw) != size
        or _HEX64.fullmatch(digest) is None
        or hashlib.sha256(raw).hexdigest() != digest
    ):
        _fail(f"{label} exact bytes differ")
    try:
        value = json.loads(
            raw.decode("ascii", "strict"),
            object_pairs_hook=_pairs,
            parse_constant=lambda token: _fail(f"{label} contains {token}"),
        )
    except (UnicodeError, json.JSONDecodeError):
        _fail(f"{label} is not strict JSON")
    canonical = _canonical(value)
    if not trailing_lf:
        canonical = canonical[:-1]
    if type(value) is not dict or canonical != raw:
        _fail(f"{label} is not canonical JSON")
    return value


def _contract(role: str) -> StaticAcquisitionContract:
    if type(role) is not str or role not in CONTRACTS:
        _fail("static acquisition role is unsupported")
    return CONTRACTS[role]


def load_static_acquisition_policy(role: str, raw: bytes) -> dict[str, Any]:
    """Validate one exact reviewed policy without conferring acquisition authority."""

    contract = _contract(role)
    value = _decode(
        raw,
        digest=contract.policy_sha256,
        size=contract.policy_size,
        label=f"{role} policy",
    )
    if frozenset(value) != frozenset({"artifact", "materialization", "receipt", "schema"}):
        _fail(f"{role} policy field set differs")
    expected_schema = f"plamen.{role.replace('_', '-')}-acquisition-policy.v1"
    artifact = value["artifact"]
    materialization = value["materialization"]
    receipt = value["receipt"]
    if (
        value["schema"] != expected_schema
        or type(artifact) is not dict
        or artifact.get("artifact_id") != contract.artifact_id
        or artifact.get("platform") != contract.platform
        or artifact.get("version") != contract.version
        or type(materialization) is not dict
        or materialization.get("acquisition_scope") != "SETUP_ONLY"
        or materialization.get("audit_network") != "DENY"
        or materialization.get("identity_mode") != "STATIC_PAYLOAD"
        or materialization.get("next_required_authority") != NEXT_REQUIRED_AUTHORITY
        or materialization.get("output")
        != {
            "payload": {
                "sha256": contract.payload_sha256,
                "size": contract.payload_size,
            },
            "source_manifest": {
                "path": contract.source_manifest_path,
                "sha256": contract.source_manifest_sha256,
                "size": contract.source_manifest_size,
            },
        }
        or receipt
        != {
            "path": contract.receipt_path,
            "schema": contract.receipt_schema,
            "sha256": contract.receipt_sha256,
            "size": contract.receipt_size,
        }
    ):
        _fail(f"{role} policy semantics differ")
    if role == "foundry":
        _validate_foundry_policy(artifact, materialization)
    else:
        _validate_amd64_policy(artifact, materialization)
    return value


def _validate_foundry_policy(artifact: dict[str, Any], materialization: dict[str, Any]) -> None:
    archive = artifact.get("archive")
    checksum = artifact.get("checksum")
    sigstore = artifact.get("sigstore")
    upstream = artifact.get("upstream")
    if (
        archive
        != {
            "asset_id": 534164782,
            "filename": "foundry_v1.8.1_linux_arm64.tar.gz",
            "sha256": "27a32bd282d73018ab4d043de15ab0320b561c71b4bf3a549b130a0806e79f5c",
            "size": 114_076_891,
            "url": "https://github.com/foundry-rs/foundry/releases/download/v1.8.1/foundry_v1.8.1_linux_arm64.tar.gz",
        }
        or checksum
        != {
            "asset_id": 534164787,
            "sha256": "972a8ab932508e1501a8807c39f4ef63379a6ddced782516e678d5268ad467fb",
            "size": 100,
            "url": "https://github.com/foundry-rs/foundry/releases/download/v1.8.1/foundry_v1.8.1_linux_arm64.sha256",
        }
        or type(sigstore) is not dict
        or sigstore.get("certificate_identity")
        != "https://github.com/foundry-rs/foundry/.github/workflows/release.yml@refs/tags/v1.8.1"
        or sigstore.get("certificate_oidc_issuer")
        != "https://token.actions.githubusercontent.com"
        or sigstore.get("source_commit")
        != "982849d3140c01fd3b72905759581a132df7aa98"
        or sigstore.get("bundle")
        != {
            "asset_id": 534164786,
            "sha256": "53296fab2c6653fc7ee010f5868065077d8c6a684ef11c82cbbb610615d872e6",
            "size": 10_157,
            "url": "https://github.com/foundry-rs/foundry/releases/download/v1.8.1/foundry_v1.8.1_linux_arm64.sigstore.json",
        }
        or upstream
        != {
            "api_url": "https://api.github.com/repos/foundry-rs/foundry/releases/tags/v1.8.1",
            "published_at": "2026-08-28T19:03:04Z",
            "release_id": 378652150,
            "release_url": "https://github.com/foundry-rs/foundry/releases/tag/v1.8.1",
            "security_policy_url": "https://github.com/foundry-rs/foundry/security",
            "tag": "v1.8.1",
        }
        or materialization.get("ambient_foundryup") != "DENY"
        or materialization.get("archive_members")
        != ["anvil", "cast", "chisel", "forge", "solar"]
        or materialization.get("canonical_projection")
        != "PLAMEN_CANONICAL_USTAR_ROOT_FILES_TO_BIN_V1"
    ):
        _fail("foundry policy release authority differs")


def _validate_amd64_policy(artifact: dict[str, Any], materialization: dict[str, Any]) -> None:
    if (
        artifact.get("index")
        != {
            "sha256": "88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171",
            "size": 5_651,
        }
        or artifact.get("manifest")
        != {
            "sha256": "5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867",
            "size": 1_021,
        }
        or artifact.get("config")
        != {
            "sha256": "160466e67bb85a4099d9d9c2356b4a6a64747b281a22c142efbd4539db1b8525",
            "size": 453,
        }
        or artifact.get("layer")
        != {
            "diff_id": "1d69a5fd31932841d7825ef4780c06f008eea65aaa9f3110fe09d5832ed5c7d8",
            "sha256": "a8ac7f6c67abc236e4c745052c404112b8fab6fe8ac3a329d1ef3b867ad67c71",
            "size": 28_232_655,
        }
        or artifact.get("image_revision")
        != "bae6d64d90b4068b09ff9d8b564c2773ef5d8d83"
        or artifact.get("official_images")
        != {
            "commit": "b9c995a1c91bf8b195b035893ebdf8e877e7f7fa",
            "sha256": "6d254035660febfa46162fc76a1a148f217387677ff740a5bf1ed3c35aabb443",
            "size": 6_779,
            "url": "https://raw.githubusercontent.com/docker-library/official-images/b9c995a1c91bf8b195b035893ebdf8e877e7f7fa/library/debian",
        }
        or artifact.get("source")
        != {
            "index_url": "https://registry-1.docker.io/v2/library/debian/manifests/bookworm-20260824-slim",
            "manifest_url": "https://registry-1.docker.io/v2/library/debian/manifests/sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867",
            "reference": "docker.io/library/debian:bookworm-20260824-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171",
            "repository_url": "https://hub.docker.com/_/debian",
        }
        or materialization.get("ambient_apt") != "DENY"
        or materialization.get("canonical_projection")
        != "PLAMEN_CANONICAL_USTAR_DEBIAN_AMD64_DIRECT_CLOSURE_V1"
        or materialization.get("selected_members")
        != [
            "lib",
            "lib64",
            "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
            "usr/lib/x86_64-linux-gnu/libc.so.6",
            "usr/lib/x86_64-linux-gnu/libdl.so.2",
            "usr/lib/x86_64-linux-gnu/libm.so.6",
            "usr/lib/x86_64-linux-gnu/libpthread.so.0",
            "usr/lib/x86_64-linux-gnu/librt.so.1",
            "usr/lib64/ld-linux-x86-64.so.2",
        ]
    ):
        _fail("amd64 compatibility policy source authority differs")


def load_static_semantic_receipt(role: str, raw: bytes) -> dict[str, Any]:
    """Validate the exact semantic prefix placed before the native footer."""

    contract = _contract(role)
    value = _decode(
        raw,
        digest=contract.receipt_sha256,
        size=contract.receipt_size,
        label=f"{role} semantic receipt",
        trailing_lf=False,
    )
    if (
        value.get("schema") != contract.receipt_schema
        or value.get("role") != role
        or value.get("artifact_id") != contract.artifact_id
        or value.get("version") != contract.version
        or value.get("platform") != contract.platform
        or value.get("payload")
        != {"sha256": contract.payload_sha256, "size": contract.payload_size}
        or value.get("source_manifest")
        != {
            "sha256": contract.source_manifest_sha256,
            "size": contract.source_manifest_size,
        }
    ):
        _fail(f"{role} semantic receipt fields differ")
    return value


def load_static_source_manifest(role: str, raw: bytes) -> dict[str, Any]:
    """Validate the exact source-manifest bytes retained beside the payload."""

    contract = _contract(role)
    value = _decode(
        raw,
        digest=contract.source_manifest_sha256,
        size=contract.source_manifest_size,
        label=f"{role} source manifest",
    )
    if (
        value.get("schema_version")
        != "plamen.runtime_source_manifest.native-retained.v1"
        or value.get("authentication_scope") != "NATIVE_RETAINED_SOURCE_INPUT"
        or value.get("role") != role
        or value.get("artifact_id") != contract.artifact_id
        or value.get("version") != contract.version
        or value.get("platform") != contract.platform
        or value.get("payload_sha256") != contract.payload_sha256
        or value.get("payload_size") != contract.payload_size
    ):
        _fail(f"{role} source manifest fields differ")
    return value


def native_operation4_static_policy_input(role: str) -> dict[str, Any]:
    """Project compile-time row facts; never a signer or live authority."""

    contract = _contract(role)
    return {
        "identity_mode": STATIC_PAYLOAD_IDENTITY_MODE,
        "payload_sha256": contract.payload_sha256,
        "payload_size": contract.payload_size,
        "policy_sha256": contract.policy_sha256,
        "producer_fd_size": contract.receipt_size + PRODUCER_FOOTER_SIZE,
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
