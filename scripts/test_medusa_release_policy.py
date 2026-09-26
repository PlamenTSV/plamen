from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

import medusa_release_policy as M


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / M.POLICY_PATH
GOVERNANCE = ROOT / "verification_policy/toolchain_governance.v1.json"


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def test_reviewed_medusa_v151_policy_and_native_receipt_seam_are_exact() -> None:
    raw = POLICY.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == M.POLICY_SHA256
    policy = M.load_medusa_acquisition_policy(raw)
    requirement = M.native_producer_receipt_requirement()
    assert policy["artifact"]["executable"]["go_module_version"] == "v1.5.1"
    assert requirement == {
        "archive_sha256": M.ARCHIVE_SHA256,
        "archive_size": 11_948_454,
        "executable_sha256": M.EXECUTABLE_SHA256,
        "executable_size": 23_748_448,
        "install_path": "/usr/local/lib/plamen/toolchains/medusa/bin/medusa",
        "next_required_authority": M.NEXT_REQUIRED_AUTHORITY,
        "platform": "linux/amd64",
        "policy_sha256": M.POLICY_SHA256,
        "production_authority": False,
        "role": "medusa",
        "sigstore_bundle_sha256": M.SIGSTORE_BUNDLE_SHA256,
        "sigstore_bundle_size": 10_584,
        "version": "1.5.1",
    }


def test_governance_uses_signed_native_member_not_ambient_go_debt() -> None:
    governance = json.loads(GOVERNANCE.read_text(encoding="utf-8"))
    medusa = next(
        row for row in governance["tools"] if row["tool_id"] == "medusa"
    )
    assert medusa["update_policy"] == {
        "state": "REVIEWED_NATIVE_SIGNED_CONTENT",
        "acquisition_scope": "SETUP_ONLY",
        "policy_path": M.POLICY_PATH,
        "policy_sha256": M.POLICY_SHA256,
        "signed_receipt_contract": "PLAMEN_NATIVE_IMAGE_MEMBER_RECEIPT_V2",
        "next_required_authority": M.NEXT_REQUIRED_AUTHORITY,
    }
    assert medusa["runtime_authority"] == {
        "identity_status": "MATCH",
        "deterministic_provider_authority": True,
        "mismatch_effect": "REVOKE_ON_SIGNED_IMAGE_MEMBER_MISMATCH",
    }
    assert "go" not in medusa["version_policy"].lower()
    assert "go" not in medusa["update_policy"].get("reason", "").lower()


@pytest.mark.parametrize(
    ("path", "replacement", "pattern"),
    [
        (("artifact", "version"), "1.5.2", "artifact identity"),
        (("artifact", "install", "path"), "/usr/local/bin/medusa", "install contract"),
        (("artifact", "executable", "sha256"), "0" * 64, "executable authority"),
        (("artifact", "sigstore", "source_commit"), "0" * 40, "Sigstore provenance"),
        (("materialization", "ambient_go"), "ALLOW", "materialization contract"),
    ],
)
def test_semantic_mutation_is_rejected_even_with_recomputed_outer_digest(
    path: tuple[str, ...], replacement: object, pattern: str
) -> None:
    value = json.loads(POLICY.read_bytes())
    changed = copy.deepcopy(value)
    cursor = changed
    for component in path[:-1]:
        cursor = cursor[component]
    cursor[path[-1]] = replacement
    raw = _canonical(changed)
    with pytest.raises(M.MedusaReleasePolicyError, match=pattern):
        M.load_medusa_acquisition_policy(
            raw, expected_sha256=hashlib.sha256(raw).hexdigest()
        )


def test_policy_digest_and_primary_source_urls_are_not_advisory() -> None:
    raw = POLICY.read_bytes()
    changed = bytearray(raw)
    changed[20] ^= 1
    with pytest.raises(M.MedusaReleasePolicyError, match="digest differs"):
        M.load_medusa_acquisition_policy(bytes(changed))
    policy = M.load_medusa_acquisition_policy(raw)
    upstream = policy["artifact"]["upstream"]
    assert upstream["api_url"].startswith("https://api.github.com/repos/crytic/medusa/")
    assert upstream["release_url"] == "https://github.com/crytic/medusa/releases/tag/v1.5.1"
