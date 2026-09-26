from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

import native_evm_static_acquisition_assets as A
import runtime_image_materializer as R


ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> bytes:
    return (ROOT / path).read_bytes()


def _parent(contract: A.RoleContract) -> bytes | None:
    return (
        _read(A.MANAGED_EVM_POLICY_PATH)
        if contract.role == "solc_amd64" else None
    )


@pytest.mark.parametrize("contract", (A.MEDUSA, A.SOLC_AMD64))
def test_reviewed_policy_single_renderer_and_frozen_outputs_are_exact(
    contract: A.RoleContract,
) -> None:
    policy = A.load_reviewed_policy(
        contract.role, _read(contract.policy_path),
        managed_evm_policy_raw=_parent(contract),
    )
    receipt, manifest = A.render_assets(
        contract.role, _read(contract.policy_path),
        managed_evm_policy_raw=_parent(contract),
    )
    assert policy
    assert receipt == _read(contract.receipt_path)
    assert manifest == _read(contract.source_manifest_path)
    assert (len(receipt), hashlib.sha256(receipt).hexdigest()) == (
        contract.receipt_size, contract.receipt_sha256,
    )
    assert (len(manifest), hashlib.sha256(manifest).hexdigest()) == (
        contract.source_manifest_size, contract.source_manifest_sha256,
    )
    assert json.loads(receipt)["generation"] == {
        "renderer": A.RENDERER_PATH,
        "schema": A.RENDERER_SCHEMA,
    }


@pytest.mark.parametrize("contract", (A.MEDUSA, A.SOLC_AMD64))
def test_wire_contract_is_no_lf_receipt_and_exactly_one_lf_manifest(
    contract: A.RoleContract,
) -> None:
    receipt = _read(contract.receipt_path)
    manifest = _read(contract.source_manifest_path)
    assert receipt.endswith(b"}") and b"\n" not in receipt and b"\r" not in receipt
    assert manifest.endswith(b"}\n") and not manifest.endswith(b"\n\n")
    assert receipt == json.dumps(
        json.loads(receipt), sort_keys=True, separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    assert manifest == (
        json.dumps(
            json.loads(manifest), sort_keys=True, separators=(",", ":"),
            ensure_ascii=True,
        ) + "\n"
    ).encode("ascii")


@pytest.mark.parametrize("contract", (A.MEDUSA, A.SOLC_AMD64))
def test_operation4_row_and_native_coordinator_seam_are_exact(
    contract: A.RoleContract,
) -> None:
    row = A.native_operation4_evm_policy_input(contract.role)
    assert row == {
        "identity_mode": 1,
        "payload_sha256": contract.payload_sha256,
        "payload_size": contract.payload_size,
        "policy_sha256": contract.policy_sha256,
        "producer_fd_size": contract.receipt_size + 512,
        "receipt_schema": contract.receipt_schema,
        "receipt_validator": contract.receipt_validator,
        "role": contract.role,
        "role_ordinal": contract.ordinal,
        "semantic_receipt_sha256": contract.receipt_sha256,
        "semantic_receipt_size": contract.receipt_size,
        "source_manifest_sha256": contract.source_manifest_sha256,
        "source_manifest_size": contract.source_manifest_size,
        "version": contract.version,
    }
    native = A.native_coordinator_evm_acquisition_input(contract.role)
    assert native["policy_row"] == row
    assert native["production_authority"] is False
    assert native["next_required_authority"] == A.NEXT_REQUIRED_AUTHORITY
    assert native["producer_output"]["wire"] == (
        "CANONICAL_SEMANTIC_PREFIX_NO_LF_THEN_NATIVE_FOOTER_V1"
    )
    assert tuple(item["kind"] for item in native["ordered_retained_inputs"]) == (
        ("medusa_release_archive", "medusa_sigstore_bundle")
        if contract.role == "medusa" else
        ("solc_provider_index", "solc_selected_binary")
    )


@pytest.mark.parametrize("contract", (A.MEDUSA, A.SOLC_AMD64))
def test_generated_manifest_is_accepted_by_the_runtime_compositor(
    contract: A.RoleContract,
) -> None:
    raw = _read(contract.source_manifest_path)
    destination, media_types = R._ROLE_CONTRACT[contract.role]
    value = R._validate_source_manifest(
        raw,
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
    assert value["role"] == contract.role


def test_medusa_native_seam_binds_archive_bundle_and_sigstore_replay() -> None:
    seam = A.native_coordinator_evm_acquisition_input("medusa")
    assert seam["ordered_retained_inputs"] == (
        {
            "kind": "medusa_release_archive",
            "sha256": "ddfe1517ae9028ef9fc331b00f5a6a9d5406f3fcd11a715d60c6b6fb3e4546d3",
            "size": 11_948_454,
        },
        {
            "kind": "medusa_sigstore_bundle",
            "sha256": "e7a277b17588fe02425a0cf4656f36d98f39eea9d4a7b0548e6617184238efb6",
            "size": 10_584,
        },
    )
    assert seam["required_native_replay"] == "SIGSTORE_BUNDLE_AND_SOLE_ARCHIVE_MEMBER_V1"


def test_solc_native_seam_binds_provider_index_binary_and_parent_policy() -> None:
    policy = A.load_reviewed_policy(
        "solc_amd64", _read(A.SOLC_AMD64.policy_path),
        managed_evm_policy_raw=_read(A.MANAGED_EVM_POLICY_PATH),
    )
    seam = A.native_coordinator_evm_acquisition_input("solc_amd64")
    assert seam["ordered_retained_inputs"] == (
        {
            "kind": "solc_provider_index",
            "sha256": "ee1a2b4811bd1225c220cd2342e2b49a58cbe18f5687f230f456c443b29497d6",
            "size": 47_730,
        },
        {
            "kind": "solc_selected_binary",
            "sha256": "d5f23436f443edb85d8e76906d12f0a86ce0490e7663a9e608efeb7a93f149ef",
            "size": 15_434_456,
        },
    )
    assert policy["reviewed_source"]["sha256"] == A.MANAGED_EVM_POLICY_SHA256
    assert seam["required_native_replay"] == "SOLC_PROVIDER_INDEX_SELECTION_AND_BINARY_V1"


@pytest.mark.parametrize("contract", (A.MEDUSA, A.SOLC_AMD64))
def test_substitution_newline_cross_role_and_freeze_drift_fail_closed(
    monkeypatch: pytest.MonkeyPatch, contract: A.RoleContract,
) -> None:
    policy = bytearray(_read(contract.policy_path))
    policy[len(policy) // 2] ^= 1
    with pytest.raises(A.NativeEVMStaticAcquisitionError):
        A.load_reviewed_policy(
            contract.role, bytes(policy), managed_evm_policy_raw=_parent(contract),
        )
    receipt = _read(contract.receipt_path)
    manifest = _read(contract.source_manifest_path)
    with pytest.raises(A.NativeEVMStaticAcquisitionError):
        A.validate_semantic_receipt(contract.role, receipt + b"\n")
    with pytest.raises(A.NativeEVMStaticAcquisitionError):
        A.validate_source_manifest(contract.role, manifest[:-1])
    other = A.SOLC_AMD64 if contract is A.MEDUSA else A.MEDUSA
    with pytest.raises(A.NativeEVMStaticAcquisitionError):
        A.validate_semantic_receipt(contract.role, _read(other.receipt_path))
    monkeypatch.setitem(
        A.CONTRACTS, contract.role,
        replace(contract, receipt_sha256="0" * 64),
    )
    with pytest.raises(A.NativeEVMStaticAcquisitionError, match="renderer output differs"):
        A.render_assets(
            contract.role, _read(contract.policy_path),
            managed_evm_policy_raw=_parent(contract),
        )


def test_solc_parent_policy_substitution_and_missing_parent_fail_closed() -> None:
    policy = _read(A.SOLC_AMD64.policy_path)
    with pytest.raises(A.NativeEVMStaticAcquisitionError, match="required"):
        A.load_reviewed_policy("solc_amd64", policy)
    parent = bytearray(_read(A.MANAGED_EVM_POLICY_PATH))
    parent[len(parent) // 2] ^= 1
    with pytest.raises(A.NativeEVMStaticAcquisitionError, match="exact bytes differ"):
        A.load_reviewed_policy(
            "solc_amd64", policy, managed_evm_policy_raw=bytes(parent),
        )


@pytest.mark.parametrize("contract", (A.MEDUSA, A.SOLC_AMD64))
@pytest.mark.parametrize("kind", ("receipt", "source-manifest"))
def test_cli_is_the_same_single_renderer(contract: A.RoleContract, kind: str) -> None:
    completed = subprocess.run(
        [
            sys.executable, str(ROOT / A.RENDERER_PATH), kind, contract.role,
            "--root", str(ROOT),
        ],
        check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env={"LANG": "C", "LC_ALL": "C"},
    )
    expected = _read(
        contract.receipt_path if kind == "receipt" else contract.source_manifest_path
    )
    assert completed.stdout == expected and completed.stderr == b""


def test_renderer_has_no_acquisition_signing_or_production_authority_surface() -> None:
    source = _read(A.RENDERER_PATH).decode("utf-8")
    for forbidden in ("import requests", "import socket", "import urllib", "import subprocess"):
        assert forbidden not in source
    assert "production_authority\": False" in source
    assert not any(name.startswith(("sign_", "acquire_", "download_")) for name in A.__all__)
