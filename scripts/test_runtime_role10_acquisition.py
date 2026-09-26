from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import runtime_role10_acquisition as R
import runtime_image_materializer as M


ROOT = Path(__file__).resolve().parents[1]
STATIC_ROLES = ("base_rootfs", "debian_package_state", "cpython")
FROZEN_ROLES = ("plamen_guest", "plamen_package")
STATIC_RECEIPTS = {
    "base_rootfs": (1064, "41cffd26c10b7842e976c809f00273caf26f0a72cdba0fda38887ce277a47309"),
    "debian_package_state": (1176, "ea38e4b6ee41511f00b2d583f4dc5875318b71abfd0b436160fdc043375e6a98"),
    "cpython": (1322, "15ae3230f2c05b4d14fade1628dfb8287185344bff343997e1de196167908dd0"),
}


def _policy(role: str) -> bytes:
    return (ROOT / R.REVIEWED_POLICIES[role].path).read_bytes()


def _manifest(role: str) -> bytes:
    return (
        ROOT
        / f"verification_policy/runtime_role10_{role}_source_manifest.v1.json"
    ).read_bytes()


def _canonical(value: object, *, lf: bool) -> bytes:
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return raw + (b"\n" if lf else b"")


def _frozen(role: str) -> tuple[bytes, bytes, bytes]:
    policy = _policy(role)
    commit = "1" * 40
    payload_sha256 = "2" * 64
    manifest = R.render_source_manifest_candidate(
        policy,
        payload_sha256=payload_sha256,
        payload_size=123456,
        source_reference=(
            "git+https://github.com/PlamenTSV/plamen.git@" + commit
        ),
        version=commit,
    )
    schema = (
        "plamen.native-production-source-freeze.v2"
        if role == "plamen_guest"
        else "plamen.runtime-source-projection.v1"
    )
    receipt = R.render_frozen_plamen_semantic_receipt(
        policy,
        payload_sha256=payload_sha256,
        payload_size=123456,
        source_manifest_raw=manifest,
        projection_authority_schema=schema,
        projection_authority_sha256="3" * 64,
        projection_authority_size=789,
        projection_roster_sha256="4" * 64,
        source_commit=commit,
    )
    return policy, manifest, receipt


def test_five_exact_reviewed_policies_form_one_cross_bound_roster() -> None:
    raw = {role: _policy(role) for role in R.REVIEWED_POLICIES}
    bindings = R.validate_reviewed_policy_roster(raw)
    assert [row.role for row in bindings] == [
        "base_rootfs",
        "debian_package_state",
        "plamen_guest",
        "cpython",
        "plamen_package",
    ]
    for binding in bindings:
        reviewed = R.REVIEWED_POLICIES[binding.role]
        assert len(raw[binding.role]) == reviewed.size
        assert hashlib.sha256(raw[binding.role]).hexdigest() == reviewed.sha256
        assert not binding.document["source_reference"].startswith(("fixture:", "test:"))
    assert bindings[1].document["acquisition"]["upstream_payload"] == (
        bindings[0].document["acquisition"]["upstream_payload"]
    )


@pytest.mark.parametrize("role", STATIC_ROLES)
def test_static_source_manifests_and_receipts_have_exact_replay(role: str) -> None:
    policy = _policy(role)
    manifest = _manifest(role)
    assert manifest == R.render_source_manifest_candidate(policy)
    receipt = R.render_static_semantic_receipt(
        policy, source_manifest_raw=manifest
    )
    expected_size, expected_sha256 = STATIC_RECEIPTS[role]
    assert len(receipt) == expected_size
    assert hashlib.sha256(receipt).hexdigest() == expected_sha256
    assert receipt.startswith(b"{") and receipt.endswith(b"}")
    assert b"\n" not in receipt and b"\r" not in receipt
    binding = R.REVIEWED_POLICIES[role]
    validated = R.validate_semantic_receipt(
        receipt,
        policy_raw=policy,
        expected_policy_sha256=binding.sha256,
        observed_payload_sha256=json.loads(policy)["payload"]["sha256"],
        observed_payload_size=json.loads(policy)["payload"]["size"],
        source_manifest_raw=manifest,
    )
    row = R.native_operation4_policy_input(
        policy, source_manifest_raw=manifest
    )
    assert validated["role"] == row["role"] == role
    assert row["identity_mode"] == 1
    assert row["receipt_validator"] in {1, 3}
    assert row["source_manifest_sha256"] == hashlib.sha256(manifest).hexdigest()
    document = json.loads(policy)
    M._validate_source_manifest(
        manifest,
        {
            "artifact_id": document["artifact_id"],
            "destination": document["destination"],
            "media_type": document["media_type"],
            "payload_sha256": document["payload"]["sha256"],
            "payload_size": document["payload"]["size"],
            "required_paths": document["required_paths"],
            "role": role,
            "source_manifest_sha256": row["source_manifest_sha256"],
            "source_manifest_size": row["source_manifest_size"],
        },
        expected_schema_version=M.NATIVE_RETAINED_SOURCE_MANIFEST_SCHEMA_VERSION,
        expected_authentication_scope=M.NATIVE_RETAINED_AUTHENTICATION_SCOPE,
    )


def test_cpython_policy_binds_upstream_release_and_canonical_transform() -> None:
    policy = R.load_exact_reviewed_policy("cpython", _policy("cpython")).document
    acquisition = policy["acquisition"]
    assert acquisition["release"] == {
        "asset_id": 302742295,
        "commit": "31349d7b98bb156bf778492f546a6c5dc405cfcc",
        "release_tag": "20251010",
    }
    assert acquisition["upstream_archive"] == {
        "sha256": "21bcf71dccb56ef611f50543b04e63e6585ac063463f2d248cb4ec28118d264d",
        "size": 80116339,
    }
    assert policy["payload"] == {
        "sha256": "0bf0e5d7680c37a46edc59ed9ce274cd311d229387decc16ef8c7318df09c711",
        "size": 222525440,
    }
    assert hashlib.sha256(R.canonical_json(acquisition["transform"])).hexdigest() == (
        "065155912c71c29be9afbda4f014d26375d267cf5f6e2db4406500ddf0ee0fd5"
    )


@pytest.mark.parametrize("role", FROZEN_ROLES)
def test_frozen_plamen_receipt_requires_exact_commit_and_compiled_identities(
    role: str,
) -> None:
    policy, manifest, receipt = _frozen(role)
    value = R.validate_semantic_receipt(
        receipt,
        policy_raw=policy,
        expected_policy_sha256=R.REVIEWED_POLICIES[role].sha256,
        observed_payload_sha256="2" * 64,
        observed_payload_size=123456,
        source_manifest_raw=manifest,
    )
    row = R.native_operation4_policy_input(
        policy,
        payload_sha256="2" * 64,
        payload_size=123456,
        source_manifest_raw=manifest,
    )
    assert value["source_commit"] == "1" * 40
    assert value["projection_authority_sha256"] == "3" * 64
    assert value["projection_roster_sha256"] == "4" * 64
    assert row["identity_mode"] == 3
    assert row["receipt_validator"] == 2
    assert b"\n" not in receipt


def test_debian_package_state_payload_is_strictly_sorted_and_installed() -> None:
    good = _canonical(
        {
            "packages": [
                {
                    "architecture": "arm64",
                    "name": "base-files",
                    "status": "install ok installed",
                    "version": "12.4+deb12u12",
                },
                {
                    "architecture": "arm64",
                    "name": "zlib1g",
                    "status": "install ok installed",
                    "version": "1:1.2.13.dfsg-1",
                },
            ],
            "schema_version": "plamen.debian_package_state.v1",
        },
        lf=False,
    )
    assert len(R.validate_debian_package_state_payload(good)["packages"]) == 2
    for mutate in (
        lambda value: value["packages"].reverse(),
        lambda value: value["packages"][0].update(status="deinstall ok config-files"),
        lambda value: value["packages"][0].update(attacker="extra"),
    ):
        changed = json.loads(good)
        mutate(changed)
        with pytest.raises(R.RuntimeRole10AcquisitionError):
            R.validate_debian_package_state_payload(_canonical(changed, lf=False))


@pytest.mark.parametrize("role", R.REVIEWED_POLICIES)
def test_policy_mutation_noncanonical_and_cross_role_fail_closed(role: str) -> None:
    raw = _policy(role)
    changed = json.loads(raw)
    changed["version"] += "-attacker"
    with pytest.raises(R.RuntimeRole10AcquisitionError):
        R.load_exact_reviewed_policy(role, _canonical(changed, lf=True))
    duplicate = raw.replace(b'{"acquisition":', b'{"schema":"attacker","acquisition":', 1)
    with pytest.raises(R.RuntimeRole10AcquisitionError):
        R.load_reviewed_policy(duplicate)
    with pytest.raises(R.RuntimeRole10AcquisitionError):
        R.load_reviewed_policy(raw[:-1])
    other = "cpython" if role != "cpython" else "base_rootfs"
    with pytest.raises(R.RuntimeRole10AcquisitionError):
        R.load_exact_reviewed_policy(other, raw)


def test_static_receipt_and_manifest_mutations_fail_closed() -> None:
    role = "base_rootfs"
    policy = _policy(role)
    manifest = _manifest(role)
    receipt = R.render_static_semantic_receipt(policy, source_manifest_raw=manifest)
    value = json.loads(receipt)
    attacks = (
        {**value, "payload_size": value["payload_size"] + 1},
        {**value, "schema": "plamen.debian-runtime-acquisition-receipt.v2"},
        {**value, "attacker": True},
        {key: item for key, item in value.items() if key != "upstream_sha256"},
    )
    for attack in attacks:
        with pytest.raises(R.RuntimeRole10AcquisitionError):
            R.validate_semantic_receipt(
                _canonical(attack, lf=False),
                policy_raw=policy,
                expected_policy_sha256=R.REVIEWED_POLICIES[role].sha256,
                observed_payload_sha256=value["payload_sha256"],
                observed_payload_size=value["payload_size"],
                source_manifest_raw=manifest,
            )
    with pytest.raises(R.RuntimeRole10AcquisitionError):
        R.validate_semantic_receipt(
            receipt + b"\n",
            policy_raw=policy,
            expected_policy_sha256=R.REVIEWED_POLICIES[role].sha256,
            observed_payload_sha256=value["payload_sha256"],
            observed_payload_size=value["payload_size"],
            source_manifest_raw=manifest,
        )
    changed_manifest = json.loads(manifest)
    changed_manifest["required_paths"].append("/attacker")
    with pytest.raises(R.RuntimeRole10AcquisitionError):
        R.render_static_semantic_receipt(
            policy, source_manifest_raw=_canonical(changed_manifest, lf=True)
        )


@pytest.mark.parametrize("role", FROZEN_ROLES)
def test_frozen_receipt_cannot_cross_commit_authority_or_policy(role: str) -> None:
    policy, manifest, receipt = _frozen(role)
    value = json.loads(receipt)
    attacks = []
    for key, replacement in (
        ("source_commit", "5" * 40),
        ("projection_authority_sha256", "0" * 64),
        ("projection_roster_sha256", "0" * 64),
        ("projection_authority_schema", "attacker.v1"),
    ):
        changed = dict(value)
        changed[key] = replacement
        attacks.append(changed)
    for attack in attacks:
        with pytest.raises(R.RuntimeRole10AcquisitionError):
            R.validate_semantic_receipt(
                _canonical(attack, lf=False),
                policy_raw=policy,
                expected_policy_sha256=R.REVIEWED_POLICIES[role].sha256,
                observed_payload_sha256="2" * 64,
                observed_payload_size=123456,
                source_manifest_raw=manifest,
            )
    with pytest.raises(R.RuntimeRole10AcquisitionError):
        R.native_operation4_policy_input(
            policy,
            payload_sha256="2" * 64,
            payload_size=123457,
            source_manifest_raw=manifest,
        )
