#!/usr/bin/env python3
"""Install-time authority for dynamically selected Claude/Codex releases.

The word ``latest`` is accepted only at this boundary.  A successful call
returns an exact, signed-registry resolution which callers must materialize
and bind into an immutable generation receipt.  Runtime/audit launch code
must consume that receipt and must never call this module's resolver.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import stat
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import quote, urlparse


POLICY_SCHEMA = "plamen.native-backend-acquisition.v2"
RECEIPT_SCHEMA = "plamen.native-backend-latest-acquisition-receipt.v1"
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
SRI_RE = re.compile(r"^sha512-([A-Za-z0-9+/]{86}==)$")
KEY_ID_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}=?$")


class BackendAcquisitionError(RuntimeError):
    """A latest release failed closed before generation publication."""


@dataclass(frozen=True)
class ValidatedBackendGeneration:
    selector: str
    resolved_version: str
    resolved_release: str
    executable_sha256: str
    executable_size: int
    closure_sha256: str
    closure_count: int
    closure_bytes: int
    receipt_sha256: str
    signer_key_id: str
    generation_id: str
    relative_path: str
    transaction_id: str
    install_receipt_sha256: str
    source_manifest_sha256: str
    source_manifest_size: int


@dataclass(frozen=True)
class RetainedBackendGenerationAuthority:
    generation: ValidatedBackendGeneration
    payload_fd: int
    semantic_receipt_fd: int
    source_manifest_fd: int
    verifier_public_key_fd: int


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def authenticate_archive_payload(
    payload: bytes, *, source_url: str, expected_integrity: str,
    selected_member_pattern: str,
) -> dict[str, Any]:
    """Authenticate one npm tarball and census names before any extraction."""
    match = SRI_RE.fullmatch(expected_integrity)
    if match is None or not isinstance(payload, bytes) or not payload:
        raise BackendAcquisitionError("backend archive payload authority differs")
    observed_sri = "sha512-" + base64.b64encode(
        hashlib.sha512(payload).digest()
    ).decode("ascii")
    if observed_sri != expected_integrity:
        raise BackendAcquisitionError("backend archive sha512 integrity differs")
    try:
        archive = tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz")
        members = archive.getmembers()
    except (tarfile.TarError, OSError) as exc:
        raise BackendAcquisitionError("backend archive is not a valid tar.gz") from exc
    names = []
    selected = []
    pattern = re.compile(selected_member_pattern)
    for member in members:
        name = member.name
        parts = name.split("/")
        if (
            not name or name.startswith("/") or "\\" in name
            or any(part in {"", ".", ".."} for part in parts)
            or member.issym() or member.islnk() or member.isdev()
        ):
            raise BackendAcquisitionError("backend archive has unsafe member")
        names.append(name)
        if member.isfile() and pattern.fullmatch(name):
            selected.append(name)
    if len(selected) != 1:
        raise BackendAcquisitionError("backend archive executable member differs")
    roster = sorted(names, key=lambda value: value.encode("utf-8"))
    return {
        "source_url": source_url,
        "size": len(payload),
        "sha256": sha256_bytes(payload),
        "sha512_sri": observed_sri,
        "archive_format": "tar.gz",
        "member_count": len(roster),
        "member_roster_sha256": sha256_bytes(canonical_json(roster)),
        "selected_member": selected[0],
        "path_traversal_rejected": True,
    }


def load_policy_bytes(raw: bytes) -> tuple[dict[str, Any], str]:
    """Validate exact frozen policy bytes without reopening a pathname."""
    if type(raw) is not bytes:
        raise BackendAcquisitionError("backend acquisition policy bytes differ")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackendAcquisitionError("backend acquisition policy is not JSON") from exc
    if not isinstance(value, dict) or value.get("schema") != POLICY_SCHEMA:
        raise BackendAcquisitionError("backend acquisition policy schema differs")
    if raw != canonical_json(value) + b"\n":
        raise BackendAcquisitionError("backend acquisition policy is not canonical")
    if set(value) != {
        "schema", "backends", "materialization", "npm_registry", "receipt",
    }:
        raise BackendAcquisitionError("backend acquisition policy fields differ")
    if set(value.get("backends") or {}) != {"claude", "codex"}:
        raise BackendAcquisitionError("backend acquisition policy roster differs")
    materialization = value.get("materialization") or {}
    if materialization != {
        "audit_time_resolution": "FORBIDDEN",
        "credentials": "FORBIDDEN",
        "install_time_resolution": "EXACTLY_ONCE_PER_BACKEND_PER_INSTALL_OR_UPDATE",
        "lifecycle_scripts": "DISABLED_EXCEPT_REVIEWED_CLAUDE_NATIVE_FINALIZER",
        "proxy_environment": "IGNORED",
        "redirects": {"allowed_hosts": [], "maximum": 0},
        "tls_minimum": "1.2",
    }:
        raise BackendAcquisitionError("backend materialization policy differs")
    registry = value.get("npm_registry") or {}
    if (
        set(registry) != {
            "latest_url_template", "metadata_url_template", "registry_host",
            "signature_keys",
        }
        or registry.get("registry_host") != "registry.npmjs.org"
        or registry.get("latest_url_template")
        != "https://registry.npmjs.org/{encoded_package}/latest"
        or registry.get("metadata_url_template")
        != "https://registry.npmjs.org/{encoded_package}/{version}"
    ):
        raise BackendAcquisitionError("backend registry authority differs")
    keys = registry.get("signature_keys")
    expected_keys = [{
        "expires": None,
        "key": (
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY6Ya7W++7aUPzvMTrezH6Ycx3c+"
            "HOKYCcNGybJZSCJq/fd7Qa8uuAKtdIkUQtQiEKERhAmE5lMMJhP8OkDOa2g=="
        ),
        "keyid": "SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U",
        "keytype": "ecdsa-sha2-nistp256",
        "scheme": "ecdsa-sha2-nistp256",
    }]
    if keys != expected_keys:
        raise BackendAcquisitionError("backend registry trust anchors are absent")
    for key in keys:
        if (
            not isinstance(key, dict)
            or set(key) != {
                "expires", "key", "keyid", "keytype", "scheme",
            }
            or not KEY_ID_RE.fullmatch(str(key.get("keyid") or ""))
            or key.get("keytype") != "ecdsa-sha2-nistp256"
            or key.get("scheme") != "ecdsa-sha2-nistp256"
            or key.get("expires") is not None
        ):
            raise BackendAcquisitionError("backend registry trust anchor differs")
        try:
            base64.b64decode(key["key"], validate=True)
        except Exception as exc:
            raise BackendAcquisitionError("backend registry public key differs") from exc
    receipt = value.get("receipt") or {}
    if (
        set(receipt) != {"canonical_encoding", "schema", "signature"}
        or receipt.get("schema") != RECEIPT_SCHEMA
        or receipt.get("canonical_encoding")
        != "UTF8_RFC8785_SUBSET_SORTED_KEYS_NO_WHITESPACE"
        or receipt.get("signature") != "PLAMEN_INSTALL_ED25519"
    ):
        raise BackendAcquisitionError("backend acquisition receipt schema differs")
    for selector, expected_package in (
        ("claude", "@anthropic-ai/claude-code"),
        ("codex", "@openai/codex"),
    ):
        row = value["backends"][selector]
        expected_fields = {"cli_contract", "npm_package", "publisher"}
        if selector == "claude":
            expected_fields.add("release")
        else:
            expected_fields.add("provenance")
        if set(row) != expected_fields or row.get("npm_package") != expected_package:
            raise BackendAcquisitionError("backend policy row differs: " + selector)
        publisher = row.get("publisher") or {}
        expected_publisher = (
            {
                "apple_identifier": "com.anthropic.claude-code",
                "apple_team_identifier": "Q6L2SF6YDW",
                "npm_maintainer_email_suffix": "@anthropic.com",
            }
            if selector == "claude" else
            {
                "apple_identifier": "codex",
                "apple_team_identifier": "2DC432GLL2",
                "npm_maintainer_email_suffix": "@openai.com",
                "npm_trusted_publisher": "github",
            }
        )
        if publisher != expected_publisher:
            raise BackendAcquisitionError("backend publisher policy differs: " + selector)
        contract = row.get("cli_contract") or {}
        expected_contract = (
            {
                "help_required_flags": [
                    "--allowedTools", "--disallowedTools", "--json-schema",
                    "--mcp-config", "--model", "--output-format",
                    "--permission-mode", "--strict-mcp-config",
                ],
                "version_pattern": (
                    r"^[0-9]+\.[0-9]+\.[0-9]+ \(Claude Code\)$"
                ),
            }
            if selector == "claude" else
            {
                "exec_help_required_flags": [
                    "--ephemeral", "--json", "--model",
                    "--output-last-message", "--sandbox",
                    "--skip-git-repo-check",
                ],
                "version_pattern": r"^codex-cli [0-9]+\.[0-9]+\.[0-9]+$",
            }
        )
        if contract != expected_contract:
            raise BackendAcquisitionError("backend CLI policy differs: " + selector)
        if selector == "claude":
            if row.get("release") != {
                "latest_url": "https://downloads.claude.ai/claude-code-releases/latest",
                "manifest_url_template": (
                    "https://downloads.claude.ai/claude-code-releases/"
                    "{version}/manifest.json"
                ),
            }:
                raise BackendAcquisitionError("Claude release policy differs")
        elif row.get("provenance") != {
            "predicate_type": "https://slsa.dev/provenance/v1",
            "required": True,
        }:
            raise BackendAcquisitionError("Codex provenance policy differs")
    # The operation-4 policy row binds the retained file, including its one
    # required trailing newline.  Do not silently substitute a digest of the
    # parsed JSON projection here.
    return value, sha256_bytes(raw)


def load_policy(path: Path | str) -> tuple[dict[str, Any], str]:
    return load_policy_bytes(Path(path).read_bytes())


def latest_metadata_url(policy: Mapping[str, Any], selector: str) -> str:
    row = _backend_row(policy, selector)
    encoded = row["npm_package"].replace("/", "%2f")
    return policy["npm_registry"]["latest_url_template"].format(
        encoded_package=encoded,
    )


def exact_metadata_url(
    policy: Mapping[str, Any], package: str, version: str,
) -> str:
    encoded = package.replace("/", "%2f")
    encoded_version = quote(version, safe="")
    return policy["npm_registry"]["metadata_url_template"].format(
        encoded_package=encoded, version=encoded_version,
    )


def _backend_row(policy: Mapping[str, Any], selector: str) -> Mapping[str, Any]:
    if selector not in {"claude", "codex"}:
        raise BackendAcquisitionError("backend selector differs")
    row = (policy.get("backends") or {}).get(selector)
    if not isinstance(row, Mapping):
        raise BackendAcquisitionError("backend policy row is absent")
    return row


def _verify_registry_signature(
    package: str, version: str, integrity: str,
    signatures: Any, policy: Mapping[str, Any],
) -> dict[str, str]:
    if not isinstance(signatures, list) or not signatures:
        raise BackendAcquisitionError("npm registry signature is absent")
    keys = {
        row["keyid"]: row
        for row in policy["npm_registry"]["signature_keys"]
    }
    message = f"{package}@{version}:{integrity}".encode("utf-8")
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError as exc:
        raise BackendAcquisitionError(
            "cryptography is required to authenticate npm releases"
        ) from exc
    for signature in signatures:
        if not isinstance(signature, Mapping):
            continue
        key = keys.get(signature.get("keyid"))
        if key is None:
            continue
        signature_value = signature.get("sig", signature.get("signature"))
        if (
            "message_sha256" in signature
            and signature.get("message_sha256") != sha256_bytes(message)
        ):
            continue
        try:
            public = serialization.load_der_public_key(
                base64.b64decode(key["key"], validate=True)
            )
            if not isinstance(public, ec.EllipticCurvePublicKey):
                continue
            public.verify(
                base64.b64decode(signature_value, validate=True),
                message,
                ec.ECDSA(hashes.SHA256()),
            )
        except Exception:
            continue
        return {
            "keyid": key["keyid"],
            "message_sha256": sha256_bytes(message),
            "signature": signature_value,
        }
    raise BackendAcquisitionError("npm registry signature is not authenticated")


def validate_npm_release_metadata(
    selector: str,
    metadata: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate one latest metadata response and return an exact resolution."""
    row = _backend_row(policy, selector)
    package = row["npm_package"]
    if not isinstance(metadata, Mapping) or metadata.get("name") != package:
        raise BackendAcquisitionError("npm package identity differs")
    version = metadata.get("version")
    if not isinstance(version, str) or not SEMVER_RE.fullmatch(version):
        raise BackendAcquisitionError("npm resolved version differs")
    dist = metadata.get("dist")
    if not isinstance(dist, Mapping):
        raise BackendAcquisitionError("npm distribution authority is absent")
    integrity = dist.get("integrity")
    if not isinstance(integrity, str) or SRI_RE.fullmatch(integrity) is None:
        raise BackendAcquisitionError("npm sha512 integrity differs")
    tarball = dist.get("tarball")
    expected_tail = "/" + package.rsplit("/", 1)[-1] + "-" + version + ".tgz"
    parsed = urlparse(str(tarball or ""))
    if (
        parsed.scheme != "https"
        or parsed.hostname != policy["npm_registry"]["registry_host"]
        or parsed.query or parsed.fragment or not parsed.path.endswith(expected_tail)
    ):
        raise BackendAcquisitionError("npm tarball authority differs")
    shasum = dist.get("shasum")
    if not isinstance(shasum, str) or re.fullmatch(r"[0-9a-f]{40}", shasum) is None:
        raise BackendAcquisitionError("npm sha1 compatibility digest differs")
    signature = _verify_registry_signature(
        package, version, integrity, dist.get("signatures"), policy,
    )
    maintainers = metadata.get("maintainers")
    suffix = row["publisher"]["npm_maintainer_email_suffix"]
    if (
        not isinstance(maintainers, list)
        or not any(
            isinstance(item, Mapping)
            and isinstance(item.get("email"), str)
            and item["email"].lower().endswith(suffix)
            for item in maintainers
        )
    ):
        raise BackendAcquisitionError("npm publisher identity differs")
    trusted_publisher = None
    provenance = None
    if selector == "codex":
        npm_user = metadata.get("_npmUser")
        trusted = npm_user.get("trustedPublisher") if isinstance(npm_user, Mapping) else None
        expected = row["publisher"]["npm_trusted_publisher"]
        if not isinstance(trusted, Mapping) or trusted.get("id") != expected:
            raise BackendAcquisitionError("npm trusted publisher differs")
        trusted_publisher = {
            "id": trusted["id"],
            "oidc_config_id": str(trusted.get("oidcConfigId") or ""),
        }
        attestations = dist.get("attestations")
        provenance_row = (
            attestations.get("provenance")
            if isinstance(attestations, Mapping) else None
        )
        provenance_url = attestations.get("url") if isinstance(attestations, Mapping) else None
        expected_predicate = row["provenance"]["predicate_type"]
        expected_prefix = (
            "https://registry.npmjs.org/-/npm/v1/attestations/"
            + package.replace("/", "%2f") + "@" + version
        )
        if (
            not isinstance(provenance_row, Mapping)
            or provenance_row.get("predicateType") != expected_predicate
            or not isinstance(provenance_url, str)
            or provenance_url != expected_prefix
        ):
            raise BackendAcquisitionError("npm SLSA provenance authority differs")
        provenance = {
            "predicate_type": expected_predicate,
            "url": provenance_url,
        }
    return {
        "selector": selector,
        "package": package,
        "version": version,
        "metadata_sha256": sha256_bytes(canonical_json(metadata)),
        "metadata_url": latest_metadata_url(policy, selector),
        "tarball_url": tarball,
        "integrity": integrity,
        "shasum": shasum,
        "registry_signature": signature,
        "trusted_publisher": trusted_publisher,
        "provenance": provenance,
    }


def validate_claude_upstream_release(
    resolution: Mapping[str, Any],
    latest_bytes: bytes,
    manifest: Mapping[str, Any],
    platform: str,
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    """Join npm latest to Anthropic's exact official release manifest."""
    if resolution.get("selector") != "claude":
        raise BackendAcquisitionError("Claude release selector differs")
    try:
        latest = latest_bytes.decode("ascii", "strict").strip()
    except UnicodeDecodeError as exc:
        raise BackendAcquisitionError("Claude latest selector is not ASCII") from exc
    version = resolution.get("version")
    if latest != version or not SEMVER_RE.fullmatch(latest):
        raise BackendAcquisitionError("Claude npm and upstream latest differ")
    platforms = manifest.get("platforms") if isinstance(manifest, Mapping) else None
    member = platforms.get(platform) if isinstance(platforms, Mapping) else None
    if (
        manifest.get("version") != version
        or not re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("commit") or ""))
        or not isinstance(member, Mapping)
        or not HEX64_RE.fullmatch(str(member.get("checksum") or ""))
        or type(member.get("size")) is not int or member["size"] <= 0
        or member.get("binary") not in {"claude", "claude.exe"}
    ):
        raise BackendAcquisitionError("Claude upstream manifest differs")
    row = _backend_row(policy, "claude")
    manifest_url = row["release"]["manifest_url_template"].format(version=version)
    manifest_raw = canonical_json(manifest)
    return {
        "latest_url": row["release"]["latest_url"],
        "latest_sha256": sha256_bytes(latest_bytes),
        "manifest_url": manifest_url,
        "manifest_sha256": sha256_bytes(manifest_raw),
        "manifest_size": len(manifest_raw),
        "commit": manifest["commit"],
        "platform": platform,
        "executable_sha256": member["checksum"],
        "executable_size": member["size"],
    }


def resolve_latest_backends(
    policy: Mapping[str, Any],
    *,
    fetch_json: Callable[[str], Mapping[str, Any]],
    fetch_bytes: Callable[[str], bytes],
    platform: str,
) -> dict[str, dict[str, Any]]:
    """Resolve each upstream exactly once; callers retain the returned bytes."""
    resolutions: dict[str, dict[str, Any]] = {}
    for selector in ("claude", "codex"):
        url = latest_metadata_url(policy, selector)
        metadata = fetch_json(url)
        resolution = validate_npm_release_metadata(
            selector, metadata, policy,
        )
        package_platform = (
            platform[:-5]
            if selector == "codex" and platform.endswith("-musl")
            else platform
        )
        platform_name = {
            "darwin-arm64": f"@{('anthropic-ai' if selector == 'claude' else 'openai')}/"
            + ("claude-code" if selector == "claude" else "codex")
            + "-darwin-arm64",
            "darwin-x64": f"@{('anthropic-ai' if selector == 'claude' else 'openai')}/"
            + ("claude-code" if selector == "claude" else "codex")
            + "-darwin-x64",
            "linux-arm64": f"@{('anthropic-ai' if selector == 'claude' else 'openai')}/"
            + ("claude-code" if selector == "claude" else "codex")
            + "-linux-arm64",
            "linux-x64": f"@{('anthropic-ai' if selector == 'claude' else 'openai')}/"
            + ("claude-code" if selector == "claude" else "codex")
            + "-linux-x64",
            "linux-arm64-musl": "@anthropic-ai/claude-code-linux-arm64-musl"
            if selector == "claude" else None,
            "linux-x64-musl": "@anthropic-ai/claude-code-linux-x64-musl"
            if selector == "claude" else None,
            "win32-arm64": f"@{('anthropic-ai' if selector == 'claude' else 'openai')}/"
            + ("claude-code" if selector == "claude" else "codex")
            + "-win32-arm64",
            "win32-x64": f"@{('anthropic-ai' if selector == 'claude' else 'openai')}/"
            + ("claude-code" if selector == "claude" else "codex")
            + "-win32-x64",
        }.get(package_platform)
        if platform_name is None:
            raise BackendAcquisitionError("backend acquisition platform differs")
        optional = metadata.get("optionalDependencies")
        spec = optional.get(platform_name) if isinstance(optional, Mapping) else None
        if not isinstance(spec, str):
            raise BackendAcquisitionError("backend platform package is absent")
        if selector == "codex":
            expected_spec = f"npm:@openai/codex@{resolution['version']}-{package_platform}"
            platform_package = "@openai/codex"
            platform_version = resolution["version"] + "-" + package_platform
        else:
            expected_spec = resolution["version"]
            platform_package = platform_name
            platform_version = resolution["version"]
        if spec != expected_spec:
            raise BackendAcquisitionError("backend platform package release differs")
        platform_url = exact_metadata_url(
            policy, platform_package, platform_version,
        )
        platform_metadata = fetch_json(platform_url)
        platform_dist = platform_metadata.get("dist") if isinstance(platform_metadata, Mapping) else None
        if (
            platform_metadata.get("name") != platform_package
            or platform_metadata.get("version") != platform_version
            or not isinstance(platform_dist, Mapping)
            or not SRI_RE.fullmatch(str(platform_dist.get("integrity") or ""))
        ):
            raise BackendAcquisitionError("backend platform metadata differs")
        platform_signature = _verify_registry_signature(
            platform_package, platform_version, platform_dist["integrity"],
            platform_dist.get("signatures"), policy,
        )
        platform_tarball = str(platform_dist.get("tarball") or "")
        parsed = urlparse(platform_tarball)
        if parsed.scheme != "https" or parsed.hostname != "registry.npmjs.org":
            raise BackendAcquisitionError("backend platform tarball authority differs")
        platform_provenance = None
        if selector == "codex":
            attestations = platform_dist.get("attestations")
            provenance = attestations.get("provenance") if isinstance(attestations, Mapping) else None
            if (
                not isinstance(provenance, Mapping)
                or provenance.get("predicateType")
                != policy["backends"]["codex"]["provenance"]["predicate_type"]
            ):
                raise BackendAcquisitionError("backend platform provenance differs")
            platform_provenance = {
                "predicate_type": provenance["predicateType"],
                "url": str(attestations.get("url") or ""),
            }
        resolution["platform_package"] = {
            "install_name": platform_name,
            "package": platform_package,
            "version": platform_version,
            "metadata_url": platform_url,
            "metadata_sha256": sha256_bytes(canonical_json(platform_metadata)),
            "tarball_url": platform_tarball,
            "integrity": platform_dist["integrity"],
            "shasum": str(platform_dist.get("shasum") or ""),
            "registry_signature": platform_signature,
            "provenance": platform_provenance,
        }
        resolutions[selector] = resolution
    claude_row = _backend_row(policy, "claude")
    latest_url = claude_row["release"]["latest_url"]
    latest_raw = fetch_bytes(latest_url)
    version = resolutions["claude"]["version"]
    manifest_url = claude_row["release"]["manifest_url_template"].format(
        version=version,
    )
    manifest = fetch_json(manifest_url)
    resolutions["claude"]["upstream_release"] = validate_claude_upstream_release(
        resolutions["claude"], latest_raw, manifest, platform, policy,
    )
    return resolutions


RECEIPT_FIELDS = frozenset({
    "schema", "selector", "policy_schema", "policy_sha256",
    "resolved_version", "resolved_release", "registry", "upstream",
    "transport", "payload", "installed", "probes", "install",
    "authentication", "receipt_sha256",
})
REGISTRY_FIELDS = frozenset({
    "selector", "package", "version", "metadata_sha256", "metadata_url",
    "tarball_url", "integrity", "shasum", "registry_signature",
    "trusted_publisher", "provenance", "platform_package",
})
PLATFORM_PACKAGE_FIELDS = frozenset({
    "install_name", "package", "version", "metadata_url", "metadata_sha256",
    "tarball_url", "integrity", "shasum", "registry_signature", "provenance",
})
TRANSPORT_FIELDS = frozenset({
    "tls_minimum", "redirect_count", "credentials", "proxy_environment",
    "endpoints_sha256",
})
PAYLOAD_FIELDS = frozenset({
    "source_url", "size", "sha256", "sha512_sri", "archive_format",
    "member_count", "member_roster_sha256", "selected_member",
    "path_traversal_rejected",
})
INSTALLED_FIELDS = frozenset({
    "platform", "relative_path", "executable_size", "executable_sha256", "closure_count",
    "closure_bytes", "closure_sha256", "code_signature",
})
CODE_SIGNATURE_FIELDS = frozenset({
    "mode", "identifier", "team_identifier", "cdhash_sha256",
})
PROBE_FIELDS = frozenset({
    "argv", "returncode", "stdout_sha256", "stderr_sha256",
    "normalized_output", "observed_contract",
})
INSTALL_FIELDS = frozenset({
    "transaction_id", "generation_id", "install_receipt_sha256",
    "source_manifest_sha256", "source_manifest_size",
})


def receipt_unsigned_bytes(receipt: Mapping[str, Any]) -> bytes:
    unsigned = dict(receipt)
    unsigned.pop("authentication", None)
    unsigned.pop("receipt_sha256", None)
    return canonical_json(unsigned)


def build_generation_receipt(
    *, selector: str, policy_sha256: str, resolution: Mapping[str, Any],
    resolved_release: str, upstream: Mapping[str, Any] | None,
    transport: Mapping[str, Any], payload: Mapping[str, Any],
    installed: Mapping[str, Any], probes: Mapping[str, Any],
    install: Mapping[str, Any], signer: Callable[[bytes], Mapping[str, str]],
) -> dict[str, Any]:
    """Bind resolved bytes/closure/probes into one immutable signed receipt."""
    if selector not in {"claude", "codex"} or resolution.get("selector") != selector:
        raise BackendAcquisitionError("backend receipt selector differs")
    if not HEX64_RE.fullmatch(policy_sha256):
        raise BackendAcquisitionError("backend receipt policy digest differs")
    receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "selector": selector,
        "policy_schema": POLICY_SCHEMA,
        "policy_sha256": policy_sha256,
        "resolved_version": resolution["version"],
        "resolved_release": resolved_release,
        "registry": dict(resolution),
        "upstream": None if upstream is None else dict(upstream),
        "transport": dict(transport),
        "payload": dict(payload),
        "installed": dict(installed),
        "probes": dict(probes),
        "install": dict(install),
    }
    raw = receipt_unsigned_bytes(receipt)
    authentication = signer(raw)
    if (
        not isinstance(authentication, Mapping)
        or set(authentication) != {"scheme", "key_id", "signature"}
        or authentication.get("scheme") != "ed25519"
        or not HEX64_RE.fullmatch(str(authentication.get("key_id") or ""))
        or not re.fullmatch(r"[0-9a-f]{128}", str(authentication.get("signature") or ""))
    ):
        raise BackendAcquisitionError("backend receipt authentication differs")
    receipt["authentication"] = dict(authentication)
    receipt["receipt_sha256"] = sha256_bytes(canonical_json(receipt))
    return receipt


def validate_generation_receipt(
    receipt: Mapping[str, Any], *, policy: Mapping[str, Any], policy_sha256: str,
    verifier: Callable[[bytes, Mapping[str, str]], bool],
    payload_bytes: bytes | None = None,
) -> ValidatedBackendGeneration:
    if not isinstance(receipt, Mapping) or set(receipt) != RECEIPT_FIELDS:
        raise BackendAcquisitionError("backend generation receipt fields differ")
    if (
        receipt.get("schema") != RECEIPT_SCHEMA
        or receipt.get("policy_schema") != POLICY_SCHEMA
        or receipt.get("policy_sha256") != policy_sha256
        or receipt.get("selector") not in {"claude", "codex"}
        or not SEMVER_RE.fullmatch(str(receipt.get("resolved_version") or ""))
    ):
        raise BackendAcquisitionError("backend generation receipt authority differs")
    authentication = receipt.get("authentication")
    if (
        not isinstance(authentication, Mapping)
        or set(authentication) != {"scheme", "key_id", "signature"}
        or authentication.get("scheme") != "ed25519"
        or not HEX64_RE.fullmatch(str(authentication.get("key_id") or ""))
        or not re.fullmatch(
            r"[0-9a-f]{128}", str(authentication.get("signature") or ""),
        )
    ):
        raise BackendAcquisitionError("backend generation receipt signer differs")
    unsigned = receipt_unsigned_bytes(receipt)
    if verifier(unsigned, authentication) is not True:
        raise BackendAcquisitionError("backend generation receipt signature differs")
    candidate = dict(receipt)
    candidate.pop("receipt_sha256")
    if receipt["receipt_sha256"] != sha256_bytes(canonical_json(candidate)):
        raise BackendAcquisitionError("backend generation receipt digest differs")
    selector = receipt["selector"]
    version = receipt["resolved_version"]
    row = _backend_row(policy, selector)
    if sha256_bytes(canonical_json(policy) + b"\n") != policy_sha256:
        raise BackendAcquisitionError("backend policy bytes differ from digest")
    registry = receipt.get("registry")
    if not isinstance(registry, Mapping) or set(registry) != REGISTRY_FIELDS:
        raise BackendAcquisitionError("backend receipt registry fields differ")
    if (
        registry.get("selector") != selector
        or registry.get("package") != row["npm_package"]
        or registry.get("version") != version
        or not HEX64_RE.fullmatch(str(registry.get("metadata_sha256") or ""))
        or registry.get("metadata_url") != latest_metadata_url(policy, selector)
        or not SRI_RE.fullmatch(str(registry.get("integrity") or ""))
        or not re.fullmatch(r"[0-9a-f]{40}", str(registry.get("shasum") or ""))
    ):
        raise BackendAcquisitionError("backend receipt registry authority differs")
    root_tarball = urlparse(str(registry.get("tarball_url") or ""))
    expected_root_tail = (
        "/" + registry["package"].rsplit("/", 1)[-1]
        + "-" + version + ".tgz"
    )
    if (
        root_tarball.scheme != "https"
        or root_tarball.hostname != policy["npm_registry"]["registry_host"]
        or root_tarball.query or root_tarball.fragment
        or not root_tarball.path.endswith(expected_root_tail)
    ):
        raise BackendAcquisitionError("backend receipt registry URL differs")
    _verify_registry_signature(
        registry["package"], version, registry["integrity"],
        [registry["registry_signature"]], policy,
    )
    platform_package = registry.get("platform_package")
    if (
        not isinstance(platform_package, Mapping)
        or set(platform_package) != PLATFORM_PACKAGE_FIELDS
        or not SEMVER_RE.fullmatch(str(platform_package.get("version") or ""))
        or not HEX64_RE.fullmatch(str(platform_package.get("metadata_sha256") or ""))
        or not SRI_RE.fullmatch(str(platform_package.get("integrity") or ""))
        or not re.fullmatch(r"[0-9a-f]{40}", str(platform_package.get("shasum") or ""))
        or platform_package.get("metadata_url") != exact_metadata_url(
            policy, str(platform_package.get("package") or ""),
            str(platform_package.get("version") or ""),
        )
    ):
        raise BackendAcquisitionError("backend receipt platform package differs")
    parsed = urlparse(str(platform_package.get("tarball_url") or ""))
    expected_platform_tail = (
        "/" + str(platform_package.get("package") or "").rsplit("/", 1)[-1]
        + "-" + str(platform_package.get("version") or "") + ".tgz"
    )
    if (
        parsed.scheme != "https"
        or parsed.hostname != policy["npm_registry"]["registry_host"]
        or parsed.query or parsed.fragment
        or not parsed.path.endswith(expected_platform_tail)
    ):
        raise BackendAcquisitionError("backend receipt platform URL differs")
    _verify_registry_signature(
        platform_package["package"], platform_package["version"],
        platform_package["integrity"],
        [platform_package["registry_signature"]], policy,
    )
    if selector == "codex":
        trusted = registry.get("trusted_publisher")
        provenance = registry.get("provenance")
        platform_provenance = platform_package.get("provenance")
        expected_predicate = row["provenance"]["predicate_type"]
        if (
            not isinstance(trusted, Mapping)
            or set(trusted) != {"id", "oidc_config_id"}
            or trusted.get("id") != row["publisher"]["npm_trusted_publisher"]
            or not trusted.get("oidc_config_id")
            or not isinstance(provenance, Mapping)
            or set(provenance) != {"predicate_type", "url"}
            or provenance.get("predicate_type") != expected_predicate
            or provenance.get("url") != (
                "https://registry.npmjs.org/-/npm/v1/attestations/"
                + registry["package"].replace("/", "%2f") + "@" + version
            )
            or not isinstance(platform_provenance, Mapping)
            or set(platform_provenance) != {"predicate_type", "url"}
            or platform_provenance.get("predicate_type") != expected_predicate
            or platform_provenance.get("url") != (
                "https://registry.npmjs.org/-/npm/v1/attestations/"
                + str(platform_package["package"]).replace("/", "%2f")
                + "@" + str(platform_package["version"])
            )
        ):
            raise BackendAcquisitionError("backend receipt provenance differs")
    elif (
        registry.get("trusted_publisher") is not None
        or registry.get("provenance") is not None
        or platform_package.get("provenance") is not None
    ):
        raise BackendAcquisitionError("Claude receipt claims foreign provenance")

    upstream = receipt.get("upstream")
    if selector == "claude":
        if (
            not isinstance(upstream, Mapping)
            or set(upstream) != {
                "latest_url", "latest_sha256", "manifest_url",
                "manifest_sha256", "manifest_size", "commit", "platform",
                "executable_sha256", "executable_size",
            }
            or upstream.get("latest_url") != row["release"]["latest_url"]
            or upstream.get("manifest_url")
            != row["release"]["manifest_url_template"].format(version=version)
            or not HEX64_RE.fullmatch(str(upstream.get("latest_sha256") or ""))
            or not HEX64_RE.fullmatch(str(upstream.get("manifest_sha256") or ""))
            or type(upstream.get("manifest_size")) is not int
            or upstream["manifest_size"] <= 0
            or not re.fullmatch(r"[0-9a-f]{40}", str(upstream.get("commit") or ""))
            or not HEX64_RE.fullmatch(str(upstream.get("executable_sha256") or ""))
            or type(upstream.get("executable_size")) is not int
            or upstream["executable_size"] <= 0
        ):
            raise BackendAcquisitionError("Claude receipt upstream authority differs")
    elif upstream is not None:
        raise BackendAcquisitionError("Codex receipt has foreign upstream authority")

    transport = receipt.get("transport")
    if (
        not isinstance(transport, Mapping)
        or set(transport) != TRANSPORT_FIELDS
        or transport.get("tls_minimum") != "1.2"
        or transport.get("redirect_count") != 0
        or transport.get("credentials") != "FORBIDDEN"
        or transport.get("proxy_environment") != "IGNORED"
        or not HEX64_RE.fullmatch(str(transport.get("endpoints_sha256") or ""))
    ):
        raise BackendAcquisitionError("backend receipt transport differs")

    installed = receipt.get("installed")
    payload = receipt.get("payload")
    probes = receipt.get("probes")
    if (
        not isinstance(installed, Mapping)
        or set(installed) != INSTALLED_FIELDS
        or not HEX64_RE.fullmatch(str(installed.get("executable_sha256") or ""))
        or type(installed.get("executable_size")) is not int
        or installed["executable_size"] <= 0
        or not HEX64_RE.fullmatch(str(installed.get("closure_sha256") or ""))
        or type(installed.get("closure_count")) is not int
        or installed["closure_count"] <= 0
        or type(installed.get("closure_bytes")) is not int
        or installed["closure_bytes"] <= 0
        or not isinstance(payload, Mapping)
        or set(payload) != PAYLOAD_FIELDS
        or not HEX64_RE.fullmatch(str(payload.get("sha256") or ""))
        or type(payload.get("size")) is not int or payload["size"] <= 0
        or payload.get("source_url") != platform_package["tarball_url"]
        or payload.get("sha512_sri") != platform_package["integrity"]
        or payload.get("archive_format") != "tar.gz"
        or type(payload.get("member_count")) is not int
        or payload["member_count"] <= 0
        or not HEX64_RE.fullmatch(str(payload.get("member_roster_sha256") or ""))
        or not isinstance(payload.get("selected_member"), str)
        or not payload["selected_member"]
        or payload.get("path_traversal_rejected") is not True
        or not isinstance(probes, Mapping)
        or set(probes) != {"version", "help"}
    ):
        raise BackendAcquisitionError("backend receipt byte authority differs")
    if payload_bytes is not None:
        authenticated_payload = authenticate_archive_payload(
            payload_bytes, source_url=payload["source_url"],
            expected_integrity=payload["sha512_sri"],
            selected_member_pattern=re.escape(payload["selected_member"]),
        )
        if authenticated_payload != payload:
            raise BackendAcquisitionError("backend retained payload differs")
    signature = installed.get("code_signature")
    if not isinstance(signature, Mapping) or set(signature) != CODE_SIGNATURE_FIELDS:
        raise BackendAcquisitionError("backend receipt code signature differs")
    if installed.get("platform") not in {
        "darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64",
        "linux-arm64-musl", "linux-x64-musl", "win32-arm64", "win32-x64",
    }:
        raise BackendAcquisitionError("backend installed platform differs")
    expected_member = (
        r"package/claude(?:\.exe)?" if selector == "claude"
        else r"package/vendor/[^/]+/bin/codex(?:\.exe)?"
    )
    expected_relative = (
        installed.get("relative_path")
        == "node_modules/@anthropic-ai/claude-code/bin/claude.exe"
        if selector == "claude" else
        isinstance(installed.get("relative_path"), str)
        and re.fullmatch(
            r"node_modules/@openai/codex-[^/]+/vendor/[^/]+/bin/"
            r"codex(?:\.exe)?",
            installed["relative_path"],
        ) is not None
    )
    if (
        re.fullmatch(expected_member, payload["selected_member"]) is None
        or not expected_relative
        or (selector == "claude" and upstream.get("platform") != installed["platform"])
    ):
        raise BackendAcquisitionError("backend executable platform binding differs")
    package_platform = (
        installed["platform"][:-5]
        if selector == "codex" and installed["platform"].endswith("-musl")
        else installed["platform"]
    )
    expected_install_name = row["npm_package"] + "-" + package_platform
    if (
        platform_package.get("install_name") != expected_install_name
        or (
            selector == "claude"
            and (
                platform_package.get("package") != expected_install_name
                or platform_package.get("version") != version
            )
        )
        or (
            selector == "codex"
            and (
                platform_package.get("package") != row["npm_package"]
                or platform_package.get("version")
                != version + "-" + package_platform
            )
        )
    ):
        raise BackendAcquisitionError("backend platform release join differs")
    if installed["platform"].startswith("darwin"):
        if (
            signature.get("mode") != "APPLE_DEVELOPER_ID"
            or signature.get("identifier") != row["publisher"]["apple_identifier"]
            or signature.get("team_identifier")
            != row["publisher"]["apple_team_identifier"]
            or not HEX64_RE.fullmatch(str(signature.get("cdhash_sha256") or ""))
        ):
            raise BackendAcquisitionError("backend Apple publisher differs")
    elif signature != {
        "mode": "REGISTRY_SIGNATURE_ONLY", "identifier": None,
        "team_identifier": None, "cdhash_sha256": None,
    }:
        raise BackendAcquisitionError("backend platform publisher mode differs")
    if selector == "claude" and (
        installed["executable_sha256"] != upstream["executable_sha256"]
        or installed["executable_size"] != upstream["executable_size"]
    ):
        raise BackendAcquisitionError("Claude installed executable differs from manifest")
    if receipt.get("resolved_release") != platform_package["version"]:
        raise BackendAcquisitionError("backend resolved release differs")
    for probe_name, expected_argv in (
        ("version", ["--version"]),
        ("help", ["--help"] if selector == "claude" else ["exec", "--help"]),
    ):
        probe = probes.get(probe_name)
        if (
            not isinstance(probe, Mapping) or set(probe) != PROBE_FIELDS
            or probe.get("argv") != expected_argv
            or probe.get("returncode") != 0
            or not HEX64_RE.fullmatch(str(probe.get("stdout_sha256") or ""))
            or not HEX64_RE.fullmatch(str(probe.get("stderr_sha256") or ""))
            or not isinstance(probe.get("normalized_output"), str)
            or not isinstance(probe.get("observed_contract"), list)
            or not all(isinstance(item, str) for item in probe["observed_contract"])
        ):
            raise BackendAcquisitionError("backend probe authority differs")
    expected_version_output = (
        f"{version} (Claude Code)" if selector == "claude"
        else f"codex-cli {version}"
    )
    if probes["version"]["normalized_output"] != expected_version_output:
        raise BackendAcquisitionError("backend version probe differs")
    required = row["cli_contract"].get(
        "help_required_flags" if selector == "claude"
        else "exec_help_required_flags"
    )
    if sorted(probes["help"]["observed_contract"]) != sorted(required):
        raise BackendAcquisitionError("backend CLI contract differs")
    install = receipt.get("install")
    if (
        not isinstance(install, Mapping) or set(install) != INSTALL_FIELDS
        or not re.fullmatch(r"[A-Za-z0-9._-]{1,200}", str(install.get("transaction_id") or ""))
        or not re.fullmatch(r"npm-[0-9a-f]{64}", str(install.get("generation_id") or ""))
        or not HEX64_RE.fullmatch(str(install.get("install_receipt_sha256") or ""))
        or not HEX64_RE.fullmatch(str(install.get("source_manifest_sha256") or ""))
        or type(install.get("source_manifest_size")) is not int
        or install["source_manifest_size"] <= 0
    ):
        raise BackendAcquisitionError("backend install binding differs")
    return ValidatedBackendGeneration(
        selector=selector,
        resolved_version=version,
        resolved_release=receipt["resolved_release"],
        executable_sha256=installed["executable_sha256"],
        executable_size=installed["executable_size"],
        closure_sha256=installed["closure_sha256"],
        closure_count=installed["closure_count"],
        closure_bytes=installed["closure_bytes"],
        receipt_sha256=receipt["receipt_sha256"],
        signer_key_id=receipt["authentication"]["key_id"],
        generation_id=install["generation_id"],
        relative_path=installed["relative_path"],
        transaction_id=install["transaction_id"],
        install_receipt_sha256=install["install_receipt_sha256"],
        source_manifest_sha256=install["source_manifest_sha256"],
        source_manifest_size=install["source_manifest_size"],
    )


def _read_retained_regular_fd(fd: int, label: str, maximum: int) -> bytes:
    if type(fd) is not int or fd < 0:
        raise BackendAcquisitionError(label + " descriptor differs")
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
        or info.st_size <= 0 or info.st_size > maximum
    ):
        raise BackendAcquisitionError(label + " descriptor identity differs")
    if hasattr(os, "pread"):
        chunks = []
        offset = 0
        while offset < info.st_size:
            block = os.pread(fd, min(1024 * 1024, info.st_size - offset), offset)
            if not block:
                raise BackendAcquisitionError(label + " descriptor truncated")
            chunks.append(block)
            offset += len(block)
        raw = b"".join(chunks)
    else:
        original = os.lseek(fd, 0, os.SEEK_CUR)
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            raw = b""
            while len(raw) < info.st_size:
                block = os.read(fd, min(1024 * 1024, info.st_size - len(raw)))
                if not block:
                    raise BackendAcquisitionError(label + " descriptor truncated")
                raw += block
        finally:
            os.lseek(fd, original, os.SEEK_SET)
    after = os.fstat(fd)
    if (after.st_dev, after.st_ino, after.st_size) != (
        info.st_dev, info.st_ino, info.st_size,
    ):
        raise BackendAcquisitionError(label + " descriptor changed")
    return raw


def bind_retained_generation_authority(
    *, receipt: Mapping[str, Any], policy: Mapping[str, Any],
    policy_sha256: str,
    verifier: Callable[[bytes, Mapping[str, str]], bool],
    payload_fd: int, semantic_receipt_fd: int, source_manifest_fd: int,
    verifier_public_key_fd: int,
) -> RetainedBackendGenerationAuthority:
    """Validate and bind the four descriptor-only native handoff objects."""
    public_key = _read_retained_regular_fd(
        verifier_public_key_fd, "backend verifier public key", 32,
    )
    if len(public_key) != 32:
        raise BackendAcquisitionError("backend verifier public key size differs")
    authentication = receipt.get("authentication") if isinstance(receipt, Mapping) else None
    if (
        not isinstance(authentication, Mapping)
        or authentication.get("key_id") != sha256_bytes(public_key)
    ):
        raise BackendAcquisitionError("backend verifier public key identity differs")
    payload = _read_retained_regular_fd(
        payload_fd, "backend payload", 1024 * 1024 * 1024,
    )
    generation = validate_generation_receipt(
        receipt, policy=policy, policy_sha256=policy_sha256,
        verifier=verifier, payload_bytes=payload,
    )
    source_manifest = _read_retained_regular_fd(
        source_manifest_fd, "backend source manifest", 64 * 1024 * 1024,
    )
    if (
        len(source_manifest) != generation.source_manifest_size
        or sha256_bytes(source_manifest) != generation.source_manifest_sha256
    ):
        raise BackendAcquisitionError("backend source manifest descriptor differs")
    semantic = _read_retained_regular_fd(
        semantic_receipt_fd, "backend semantic receipt", 64 * 1024 * 1024,
    )
    # Native role10's fixed semantic wire is canonical JSON immediately
    # followed by its 512-byte footer; there is deliberately no line ending.
    prefix = canonical_json(receipt)
    if len(semantic) != len(prefix) + 512 or not semantic.startswith(prefix):
        raise BackendAcquisitionError("backend semantic receipt descriptor differs")
    return RetainedBackendGenerationAuthority(
        generation=generation, payload_fd=payload_fd,
        semantic_receipt_fd=semantic_receipt_fd,
        source_manifest_fd=source_manifest_fd,
        verifier_public_key_fd=verifier_public_key_fd,
    )


__all__ = [
    "BackendAcquisitionError", "ValidatedBackendGeneration",
    "RetainedBackendGenerationAuthority", "POLICY_SCHEMA", "RECEIPT_SCHEMA",
    "RECEIPT_FIELDS", "authenticate_archive_payload",
    "bind_retained_generation_authority", "build_generation_receipt", "canonical_json",
    "exact_metadata_url", "latest_metadata_url", "load_policy",
    "load_policy_bytes",
    "resolve_latest_backends", "validate_claude_upstream_release",
    "validate_generation_receipt", "validate_npm_release_metadata",
]
