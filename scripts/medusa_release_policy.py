"""Exact setup-only Medusa release policy for the native runtime image.

This module validates reviewed policy bytes and exposes the retained-input
contract to the native source-bootstrap coordinator.  It deliberately does
not download, extract, sign, or install anything: Python is not the authority
boundary for the native image.  The coordinator must authenticate the pinned
archive and Sigstore bundle FDs, extract the sole member, and issue the signed
producer receipt consumed by ``runtime_source_manifest_renderer``.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, NoReturn


SCHEMA = "plamen.medusa-acquisition.v1"
POLICY_PATH = "verification_policy/medusa_acquisition.v1.json"
POLICY_SHA256 = "4112703567b4c398207eaf09c75503840704be44b663a43e82fae42aa32a0208"
VERSION = "1.5.1"
TAG = "v1.5.1"
PLATFORM = "linux/amd64"
ROLE = "medusa"
INSTALL_PATH = "/usr/local/lib/plamen/toolchains/medusa/bin/medusa"
ARCHIVE_SHA256 = "ddfe1517ae9028ef9fc331b00f5a6a9d5406f3fcd11a715d60c6b6fb3e4546d3"
ARCHIVE_SIZE = 11_948_454
SIGSTORE_BUNDLE_SHA256 = "e7a277b17588fe02425a0cf4656f36d98f39eea9d4a7b0548e6617184238efb6"
SIGSTORE_BUNDLE_SIZE = 10_584
EXECUTABLE_SHA256 = "86e54c586e49e6bf9676f448218e10475afacb0a8bd5ca1aea234f66db7169d6"
EXECUTABLE_SIZE = 23_748_448
SOURCE_COMMIT = "540a483b7a2a35b0a6d210aeb6ae6015aa7a0f62"
CERTIFICATE_IDENTITY = (
    "https://github.com/crytic/medusa/.github/workflows/ci.yml@refs/tags/v1.5.1"
)
CERTIFICATE_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
NEXT_REQUIRED_AUTHORITY = "PLAMEN_NATIVE_SOURCE_BOOTSTRAP_COORDINATOR_RECEIPT_V1"

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class MedusaReleasePolicyError(RuntimeError):
    """Reviewed Medusa acquisition policy bytes are absent or different."""


def _fail(message: str) -> NoReturn:
    raise MedusaReleasePolicyError(message) from None


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
        _fail("Medusa policy is not canonicalizable")


def _exact(value: Any, keys: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != keys:
        _fail(f"{label} field set differs")
    return value


def load_medusa_acquisition_policy(
    raw: bytes, *, expected_sha256: str = POLICY_SHA256
) -> dict[str, Any]:
    """Validate exact policy bytes; return data, never acquisition authority."""

    if (
        type(raw) is not bytes
        or not raw
        or len(raw) > 64 * 1024
        or type(expected_sha256) is not str
        or _HEX64.fullmatch(expected_sha256) is None
        or hashlib.sha256(raw).hexdigest() != expected_sha256
    ):
        _fail("Medusa policy digest differs")
    try:
        value = json.loads(
            raw.decode("ascii", "strict"),
            object_pairs_hook=lambda pairs: _pairs(pairs),
            parse_constant=lambda item: _fail(f"Medusa policy contains {item}"),
        )
    except (UnicodeError, json.JSONDecodeError):
        _fail("Medusa policy is not strict JSON")
    if _canonical(value) != raw:
        _fail("Medusa policy bytes are not canonical JSON")
    top = _exact(value, frozenset({"artifact", "materialization", "schema"}), "policy")
    if top["schema"] != SCHEMA:
        _fail("Medusa policy schema differs")
    artifact = _exact(
        top["artifact"],
        frozenset(
            {
                "archive",
                "artifact_id",
                "executable",
                "install",
                "platform",
                "sigstore",
                "upstream",
                "version",
            }
        ),
        "artifact",
    )
    archive = _exact(
        artifact["archive"],
        frozenset({"asset_id", "format", "member", "members", "sha256", "size", "url"}),
        "archive",
    )
    executable = _exact(
        artifact["executable"],
        frozenset(
            {"elf_class", "endianness", "go_module", "go_module_version", "machine", "sha256", "size"}
        ),
        "executable",
    )
    install = _exact(
        artifact["install"],
        frozenset({"media_type", "mode", "path", "role"}),
        "install",
    )
    sigstore = _exact(
        artifact["sigstore"],
        frozenset({"bundle", "certificate_identity", "certificate_oidc_issuer", "source_commit"}),
        "Sigstore",
    )
    bundle = _exact(
        sigstore["bundle"],
        frozenset({"asset_id", "sha256", "size", "url"}),
        "Sigstore bundle",
    )
    upstream = _exact(
        artifact["upstream"],
        frozenset({"api_url", "published_at", "release_id", "release_url", "tag"}),
        "upstream",
    )
    materialization = _exact(
        top["materialization"],
        frozenset(
            {"acquisition_scope", "ambient_go", "audit_network", "next_required_authority", "rosetta_required"}
        ),
        "materialization",
    )
    expected = {
        "artifact_id": "medusa-1.5.1-linux-x64",
        "platform": PLATFORM,
        "version": VERSION,
    }
    if any(artifact[name] != wanted for name, wanted in expected.items()):
        _fail("Medusa artifact identity differs")
    if archive != {
        "asset_id": 371539722,
        "format": "tar.gz",
        "member": "medusa",
        "members": ["medusa"],
        "sha256": ARCHIVE_SHA256,
        "size": ARCHIVE_SIZE,
        "url": "https://github.com/crytic/medusa/releases/download/v1.5.1/medusa-linux-x64.tar.gz",
    }:
        _fail("Medusa archive authority differs")
    if executable != {
        "elf_class": 64,
        "endianness": "little",
        "go_module": "github.com/crytic/medusa",
        "go_module_version": TAG,
        "machine": "x86_64",
        "sha256": EXECUTABLE_SHA256,
        "size": EXECUTABLE_SIZE,
    }:
        _fail("Medusa executable authority differs")
    if install != {
        "media_type": "application/vnd.plamen.executable",
        "mode": "0555",
        "path": INSTALL_PATH,
        "role": ROLE,
    }:
        _fail("Medusa install contract differs")
    if bundle != {
        "asset_id": 371539721,
        "sha256": SIGSTORE_BUNDLE_SHA256,
        "size": SIGSTORE_BUNDLE_SIZE,
        "url": "https://github.com/crytic/medusa/releases/download/v1.5.1/medusa-linux-x64.tar.gz.sigstore.json",
    } or any(
        (
            sigstore["certificate_identity"] != CERTIFICATE_IDENTITY,
            sigstore["certificate_oidc_issuer"] != CERTIFICATE_OIDC_ISSUER,
            sigstore["source_commit"] != SOURCE_COMMIT,
        )
    ):
        _fail("Medusa Sigstore provenance differs")
    if upstream != {
        "api_url": "https://api.github.com/repos/crytic/medusa/releases/tags/v1.5.1",
        "published_at": "2026-03-11T13:21:11Z",
        "release_id": 295655662,
        "release_url": "https://github.com/crytic/medusa/releases/tag/v1.5.1",
        "tag": TAG,
    }:
        _fail("Medusa primary-source release provenance differs")
    if materialization != {
        "acquisition_scope": "SETUP_ONLY",
        "ambient_go": "DENY",
        "audit_network": "DENY",
        "next_required_authority": NEXT_REQUIRED_AUTHORITY,
        "rosetta_required": True,
    }:
        _fail("Medusa materialization contract differs")
    return top


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            _fail("Medusa policy contains a duplicate/non-string key")
        result[key] = value
    return result


def native_producer_receipt_requirement() -> dict[str, Any]:
    """Return the exact unsigned seam the native coordinator must satisfy."""

    return {
        "archive_sha256": ARCHIVE_SHA256,
        "archive_size": ARCHIVE_SIZE,
        "executable_sha256": EXECUTABLE_SHA256,
        "executable_size": EXECUTABLE_SIZE,
        "install_path": INSTALL_PATH,
        "next_required_authority": NEXT_REQUIRED_AUTHORITY,
        "platform": PLATFORM,
        "policy_sha256": POLICY_SHA256,
        "production_authority": False,
        "role": ROLE,
        "sigstore_bundle_sha256": SIGSTORE_BUNDLE_SHA256,
        "sigstore_bundle_size": SIGSTORE_BUNDLE_SIZE,
        "version": VERSION,
    }


__all__ = [
    "MedusaReleasePolicyError",
    "NEXT_REQUIRED_AUTHORITY",
    "POLICY_PATH",
    "POLICY_SHA256",
    "load_medusa_acquisition_policy",
    "native_producer_receipt_requirement",
]
