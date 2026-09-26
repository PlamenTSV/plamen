"""Exact setup-only OpenGrep release policy for the native runtime image.

This module validates reviewed policy and source-manifest bytes and exposes the
three retained-input contract to the native source-bootstrap coordinator.  It
does not download, verify Sigstore provenance, install, materialize an image,
or issue a receipt.  Production authority begins only after the native
coordinator authenticates the retained payload/certificate/signature FDs and
the later native image authorities accept the resulting member.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, NoReturn


SCHEMA = "plamen.opengrep-acquisition.v1"
POLICY_PATH = "verification_policy/opengrep_acquisition.v1.json"
POLICY_SHA256 = "2d545763d0d298797f1d16899fe60cf3a4cd644b01f3bb285aecd0f581886dd2"
POLICY_SIZE = 2_238
SOURCE_MANIFEST_PATH = "verification_policy/opengrep_runtime_source_manifest.v1.json"
SOURCE_MANIFEST_SHA256 = "891b0834c56160163ea91b93c6e1ae1d4366426d1c9bd3f7d500c7ce352ff2f6"
SOURCE_MANIFEST_SIZE = 581
SOURCE_MANIFEST_SCHEMA = "plamen.runtime_source_manifest.native-retained.v1"

VERSION = "1.30.0"
TAG = "v1.30.0"
ARTIFACT_ID = "opengrep-1.30.0-manylinux-aarch64"
PLATFORM = "linux/arm64"
ROLE = "opengrep"
INSTALL_PATH = "/usr/local/lib/plamen/toolchains/opengrep/bin/opengrep"
PAYLOAD_NAME = "opengrep_manylinux_aarch64"
PAYLOAD_SHA256 = "a5d5a4a58ba5d46ff51e921663da1c2bba38f4b03987f4aeec87f16c6ad3ecae"
PAYLOAD_SIZE = 47_982_360
CERTIFICATE_SHA256 = "d89ff9a719325a32d626823377ccd22fbbac90aee9984251db3989d321bd012e"
CERTIFICATE_SIZE = 3_368
SIGNATURE_SHA256 = "2c36b808ac1d6f7d4419c6e3a041b6dc90bc594003ff354b2462e1cb69f4ad8d"
SIGNATURE_SIZE = 96
SOURCE_COMMIT = "acf67b45c97c4b63626536605c77064ef536806d"
CERTIFICATE_IDENTITY = (
    "https://github.com/opengrep/opengrep/.github/workflows/"
    "rolling-release.yml@refs/heads/main"
)
CERTIFICATE_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
NEXT_REQUIRED_AUTHORITIES = (
    "PLAMEN_NATIVE_SOURCE_BOOTSTRAP_COORDINATOR_RECEIPT_V1",
    "NATIVE_RETAINED_FD_RUNTIME_MATERIALIZATION_RECEIPT",
    "APPLE_CONTAINER_RUNTIME_IMAGE_ADMISSION_RECEIPT",
)

# Literal runtime-data declarations are consumed by
# toolchain_control_authority's AST closure derivation.  They do not confer
# authority; they ensure the exact reviewed bytes cannot be omitted when the
# runtime source projection is next frozen.
PLAMEN_RUNTIME_ASSETS = (
    {
        "kind": "control",
        "mode": "named-files",
        "root": "verification_policy",
        "names": (
            "opengrep_acquisition.v1.json",
            "opengrep_runtime_source_manifest.v1.json",
        ),
    },
)

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class OpenGrepReleasePolicyError(RuntimeError):
    """Reviewed OpenGrep acquisition bytes are absent or different."""


def _fail(message: str) -> NoReturn:
    raise OpenGrepReleasePolicyError(message) from None


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            _fail("OpenGrep document contains a duplicate/non-string key")
        result[key] = value
    return result


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
        _fail("OpenGrep document is not canonicalizable")


def _load_exact_json(raw: bytes, expected_sha256: str, label: str) -> dict[str, Any]:
    if (
        type(raw) is not bytes
        or not raw
        or len(raw) > 64 * 1024
        or type(expected_sha256) is not str
        or _HEX64.fullmatch(expected_sha256) is None
        or hashlib.sha256(raw).hexdigest() != expected_sha256
    ):
        _fail(f"OpenGrep {label} digest differs")
    try:
        value = json.loads(
            raw.decode("ascii", "strict"),
            object_pairs_hook=_pairs,
            parse_constant=lambda item: _fail(
                f"OpenGrep {label} contains non-JSON constant {item}"
            ),
        )
    except (UnicodeError, json.JSONDecodeError):
        _fail(f"OpenGrep {label} is not strict JSON")
    if type(value) is not dict or _canonical(value) != raw:
        _fail(f"OpenGrep {label} bytes are not canonical JSON")
    return value


def _same(actual: Any, expected: Any) -> bool:
    """Compare JSON values without bool/int equality or permissive containers."""

    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return actual.keys() == expected.keys() and all(
            _same(actual[key], value) for key, value in expected.items()
        )
    if type(expected) is list:
        return len(actual) == len(expected) and all(
            _same(left, right) for left, right in zip(actual, expected, strict=True)
        )
    return bool(actual == expected)


def _input(name: str, asset_id: int, size: int, sha256: str) -> dict[str, Any]:
    filename = PAYLOAD_NAME + name
    return {
        "asset_id": asset_id,
        "filename": filename,
        "sha256": sha256,
        "size": size,
        "url": f"https://github.com/opengrep/opengrep/releases/download/{TAG}/{filename}",
    }


_EXPECTED_INPUTS = {
    "certificate": _input(".cert", 548_657_430, CERTIFICATE_SIZE, CERTIFICATE_SHA256),
    "payload": _input("", 548_657_431, PAYLOAD_SIZE, PAYLOAD_SHA256),
    "signature": _input(".sig", 548_657_439, SIGNATURE_SIZE, SIGNATURE_SHA256),
}

_EXPECTED_ARTIFACT = {
    "artifact_id": ARTIFACT_ID,
    "executable": {
        "elf_class": 64,
        "endianness": "little",
        "machine": "aarch64",
        "sha256": PAYLOAD_SHA256,
        "size": PAYLOAD_SIZE,
    },
    "install": {
        "media_type": "application/vnd.plamen.executable",
        "mode": "0555",
        "path": INSTALL_PATH,
        "role": ROLE,
    },
    "platform": PLATFORM,
    "retained_inputs": _EXPECTED_INPUTS,
    "sigstore": {
        "certificate_identity": CERTIFICATE_IDENTITY,
        "certificate_oidc_issuer": CERTIFICATE_OIDC_ISSUER,
        "signed_input": "payload",
        "source_commit": SOURCE_COMMIT,
        "verification": "SIGSTORE_KEYLESS_BLOB_CERTIFICATE_SIGNATURE",
    },
    "upstream": {
        "api_url": f"https://api.github.com/repos/opengrep/opengrep/releases/tags/{TAG}",
        "published_at": "2026-09-07T11:20:14Z",
        "release_id": 384_027_581,
        "release_url": f"https://github.com/opengrep/opengrep/releases/tag/{TAG}",
        "tag": TAG,
    },
    "version": VERSION,
}

_EXPECTED_MATERIALIZATION = {
    "acquisition_scope": "SETUP_ONLY",
    "audit_network": "DENY",
    "identity_mode": "STATIC_PAYLOAD",
    "next_required_authorities": list(NEXT_REQUIRED_AUTHORITIES),
    "production_authority": False,
    "retained_input_count": 3,
}

_EXPECTED_SOURCE_MANIFEST = {
    "artifact_id": ARTIFACT_ID,
    "authentication_scope": "NATIVE_RETAINED_SOURCE_INPUT",
    "media_type": "application/vnd.plamen.executable",
    "payload_sha256": PAYLOAD_SHA256,
    "payload_size": PAYLOAD_SIZE,
    "platform": PLATFORM,
    "required_paths": [INSTALL_PATH],
    "role": ROLE,
    "schema_version": SOURCE_MANIFEST_SCHEMA,
    "source_reference": _EXPECTED_INPUTS["payload"]["url"],
    "version": VERSION,
}


def load_opengrep_acquisition_policy(
    raw: bytes, *, expected_sha256: str = POLICY_SHA256
) -> dict[str, Any]:
    """Validate exact reviewed bytes; return policy data, never authority."""

    value = _load_exact_json(raw, expected_sha256, "policy")
    if expected_sha256 == POLICY_SHA256 and len(raw) != POLICY_SIZE:
        _fail("OpenGrep policy size differs")
    if value.keys() != {"artifact", "materialization", "schema"}:
        _fail("OpenGrep policy field set differs")
    if value["schema"] != SCHEMA:
        _fail("OpenGrep policy schema differs")
    if not _same(value["artifact"], _EXPECTED_ARTIFACT):
        _fail("OpenGrep artifact or retained-input authority differs")
    if not _same(value["materialization"], _EXPECTED_MATERIALIZATION):
        _fail("OpenGrep materialization contract differs")
    return value


def load_opengrep_runtime_source_manifest(
    raw: bytes, *, expected_sha256: str = SOURCE_MANIFEST_SHA256
) -> dict[str, Any]:
    """Validate the exact non-authoritative source-manifest candidate bytes."""

    value = _load_exact_json(raw, expected_sha256, "source manifest")
    if len(raw) != SOURCE_MANIFEST_SIZE:
        _fail("OpenGrep source manifest size differs")
    if not _same(value, _EXPECTED_SOURCE_MANIFEST):
        _fail("OpenGrep source manifest semantics differ")
    return value


def native_producer_receipt_requirement() -> dict[str, Any]:
    """Return the unsigned seam the native signed coordinators must satisfy."""

    return {
        "artifact_id": ARTIFACT_ID,
        "install_path": INSTALL_PATH,
        "next_required_authorities": NEXT_REQUIRED_AUTHORITIES,
        "platform": PLATFORM,
        "policy_sha256": POLICY_SHA256,
        "production_authority": False,
        "retained_inputs": tuple(
            (
                kind,
                row["asset_id"],
                row["sha256"],
                row["size"],
            )
            for kind, row in _EXPECTED_INPUTS.items()
        ),
        "role": ROLE,
        "source_manifest_sha256": SOURCE_MANIFEST_SHA256,
        "source_manifest_size": SOURCE_MANIFEST_SIZE,
        "version": VERSION,
    }


__all__ = [
    "NEXT_REQUIRED_AUTHORITIES",
    "OpenGrepReleasePolicyError",
    "POLICY_PATH",
    "POLICY_SHA256",
    "POLICY_SIZE",
    "SOURCE_MANIFEST_PATH",
    "SOURCE_MANIFEST_SHA256",
    "load_opengrep_acquisition_policy",
    "load_opengrep_runtime_source_manifest",
    "native_producer_receipt_requirement",
]
