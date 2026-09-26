"""Reviewed operation-4 acquisition policy and semantic receipt contracts.

This module is release tooling, not an authority issuer.  Production trusts a
policy only after its exact raw-file SHA-256 has been compiled into the signed
native operation-4 helper.  The native helper independently authenticates the
retained payload, source manifest, semantic receipt prefix, and fixed footer.

Semantic receipts use canonical ASCII JSON with no trailing newline so the
native parser has one byte representation.  Reviewed policy files use the
same representation plus exactly one final newline for ordinary source-tree
hygiene; their digest covers that newline.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import re
from typing import Any, Mapping, NoReturn


POLICY_SCHEMA = "plamen.runtime-role10-acquisition-policy.v1"
DEBIAN_RECEIPT_SCHEMA = "plamen.debian-runtime-acquisition-receipt.v1"
PLAMEN_RECEIPT_SCHEMA = (
    "plamen.plamen-source-projection-acquisition-receipt.v1"
)
CPYTHON_RECEIPT_SCHEMA = "plamen.cpython-runtime-acquisition-receipt.v1"
SOURCE_MANIFEST_SCHEMA = "plamen.runtime_source_manifest.native-retained.v1"
AUTHENTICATION_SCOPE = "NATIVE_RETAINED_SOURCE_INPUT"

STATIC = "STATIC_PAYLOAD_V1"
FROZEN = "FROZEN_SOURCE_PROJECTION_V1"
RELEASE_FREEZE_REQUIRED = "RELEASE_FREEZE_REQUIRED"

MAX_POLICY_BYTES = 128 * 1024
MAX_RECEIPT_BYTES = 1024 * 1024
MAX_PROJECTION_AUTHORITY_BYTES = 16 * 1024 * 1024
MAX_SOURCE_MANIFEST_BYTES = 64 * 1024

_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._+-]{0,127}\Z")

_POLICY_KEYS = frozenset(
    {
        "acquisition",
        "artifact_id",
        "destination",
        "identity_mode",
        "media_type",
        "ordinal",
        "payload",
        "platform",
        "receipt_schema",
        "receipt_validator",
        "required_paths",
        "role",
        "schema",
        "source_manifest",
        "source_reference",
        "version",
    }
)
_SOURCE_MANIFEST_KEYS = frozenset(
    {
        "artifact_id",
        "authentication_scope",
        "media_type",
        "payload_sha256",
        "payload_size",
        "platform",
        "required_paths",
        "role",
        "schema_version",
        "source_reference",
        "version",
    }
)
_COMMON_RECEIPT_KEYS = frozenset(
    {
        "artifact_id",
        "derivation",
        "destination",
        "identity_mode",
        "media_type",
        "payload_sha256",
        "payload_size",
        "platform",
        "policy_schema",
        "policy_sha256",
        "required_paths_sha256",
        "role",
        "schema",
        "source_manifest_sha256",
        "source_manifest_size",
        "source_reference",
        "version",
    }
)
_DEBIAN_RECEIPT_KEYS = _COMMON_RECEIPT_KEYS | {
    "upstream_sha256",
    "upstream_size",
}
_CPYTHON_RECEIPT_KEYS = _COMMON_RECEIPT_KEYS | {
    "transform_sha256",
    "upstream_asset_id",
    "upstream_commit",
    "upstream_release_tag",
    "upstream_sha256",
    "upstream_size",
}
_PLAMEN_RECEIPT_KEYS = _COMMON_RECEIPT_KEYS | {
    "projection_authority_schema",
    "projection_authority_sha256",
    "projection_authority_size",
    "projection_roster_sha256",
    "source_commit",
}

_ROLE_CONTRACT: Mapping[str, Mapping[str, Any]] = {
    "base_rootfs": {
        "ordinal": 0,
        "mode": STATIC,
        "validator": "DEBIAN_RECEIPT_V1",
        "receipt_schema": DEBIAN_RECEIPT_SCHEMA,
        "destination": "/",
        "media_type": "application/vnd.plamen.canonical-rootfs.tar",
        "platform": "linux/arm64",
        "required_paths": (
            "/bin/sh",
            "/etc/passwd",
            "/lib/aarch64-linux-gnu/libc.so.6",
            "/lib/aarch64-linux-gnu/libdl.so.2",
            "/lib/aarch64-linux-gnu/libm.so.6",
            "/lib/aarch64-linux-gnu/libpthread.so.0",
            "/lib/aarch64-linux-gnu/librt.so.1",
            "/lib/ld-linux-aarch64.so.1",
            "/usr/bin/env",
            "/var/lib/dpkg/status",
        ),
    },
    "debian_package_state": {
        "ordinal": 1,
        "mode": STATIC,
        "validator": "DEBIAN_RECEIPT_V1",
        "receipt_schema": DEBIAN_RECEIPT_SCHEMA,
        "destination": "/usr/local/lib/plamen/attestations/debian-packages.json",
        "media_type": "application/vnd.plamen.debian-package-state+json",
        "platform": "linux/arm64",
        "required_paths": (
            "/usr/local/lib/plamen/attestations/debian-packages.json",
        ),
    },
    "plamen_guest": {
        "ordinal": 2,
        "mode": FROZEN,
        "validator": "PLAMEN_SOURCE_RECEIPT_V1",
        "receipt_schema": PLAMEN_RECEIPT_SCHEMA,
        "destination": "/usr/local",
        "media_type": "application/vnd.plamen.preinstalled-tree.tar",
        "platform": "linux/arm64",
        "required_paths": (
            "/usr/local/lib/plamen/native/cpython-312/_plamen_native_supervisor.so",
            "/usr/local/libexec/plamen-guest",
        ),
    },
    "cpython": {
        "ordinal": 3,
        "mode": STATIC,
        "validator": "CPYTHON_RECEIPT_V1",
        "receipt_schema": CPYTHON_RECEIPT_SCHEMA,
        "destination": "/usr",
        "media_type": "application/vnd.plamen.preinstalled-tree.tar",
        "platform": "linux/arm64",
        "required_paths": ("/usr/bin/python3",),
    },
    "plamen_package": {
        "ordinal": 4,
        "mode": FROZEN,
        "validator": "PLAMEN_SOURCE_RECEIPT_V1",
        "receipt_schema": PLAMEN_RECEIPT_SCHEMA,
        "destination": "/opt/plamen",
        "media_type": "application/vnd.plamen.preinstalled-tree.tar",
        "platform": "linux/noarch",
        "required_paths": ("/opt/plamen/scripts/plamen_driver.py",),
    },
}


class RuntimeRole10AcquisitionError(RuntimeError):
    """A reviewed policy, semantic receipt, or source binding is inexact."""


@dataclass(frozen=True, slots=True)
class PolicyBinding:
    role: str
    ordinal: int
    identity_mode: str
    receipt_schema: str
    receipt_validator: str
    policy_sha256: str
    document: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ReviewedPolicy:
    role: str
    path: str
    sha256: str
    size: int


REVIEWED_POLICIES: Mapping[str, ReviewedPolicy] = {
    row.role: row
    for row in (
        ReviewedPolicy(
            "base_rootfs",
            "verification_policy/runtime_role10_base_rootfs_acquisition.v1.json",
            "0b99540e2f193533ec15808820b914ae6638860fed9cab64b11897b1e58abd45",
            3224,
        ),
        ReviewedPolicy(
            "debian_package_state",
            "verification_policy/runtime_role10_debian_package_state_acquisition.v1.json",
            "a2ab7976b0d65e3144ed24672796e4f6c249f234dd758b2e3db8eb6ab570ed6c",
            1247,
        ),
        ReviewedPolicy(
            "plamen_guest",
            "verification_policy/runtime_role10_plamen_guest_acquisition.v1.json",
            "02927beca9af860b8001fc5add064484c28f8e68a8076d99629965e55c605401",
            1106,
        ),
        ReviewedPolicy(
            "cpython",
            "verification_policy/runtime_role10_cpython_acquisition.v1.json",
            "9484a90eae84561a57c85971b34469a1eca7f12a849e670761be1b7ab8826e38",
            1762,
        ),
        ReviewedPolicy(
            "plamen_package",
            "verification_policy/runtime_role10_plamen_package_acquisition.v1.json",
            "430ba913907e7c71594b2fbeae33309d32e3ce6e135a5cb593a1aad190ac891b",
            1172,
        ),
    )
}

_VALIDATOR_IDS = {
    "DEBIAN_RECEIPT_V1": 1,
    "PLAMEN_SOURCE_RECEIPT_V1": 2,
    "CPYTHON_RECEIPT_V1": 3,
}
_MODE_IDS = {STATIC: 1, FROZEN: 3}


def _fail(message: str) -> NoReturn:
    raise RuntimeRole10AcquisitionError(message) from None


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise RuntimeRole10AcquisitionError("document is not canonicalizable") from exc


def _pairs(pairs: list[tuple[str, Any]], label: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            _fail(f"{label} contains a duplicate or non-string key")
        result[key] = value
    return result


def _decode(raw: bytes, *, label: str, maximum: int, final_lf: bool) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        _fail(f"{label} is outside its byte bound")
    candidate = raw[:-1] if final_lf and raw.endswith(b"\n") else raw
    if final_lf and (not raw.endswith(b"\n") or candidate.endswith((b"\n", b"\r"))):
        _fail(f"{label} must have exactly one final LF")
    if not final_lf and (b"\n" in raw or b"\r" in raw):
        _fail(f"{label} contains non-canonical line breaks")
    try:
        text = candidate.decode("ascii", "strict")
        value = json.loads(
            text,
            object_pairs_hook=lambda pairs: _pairs(pairs, label),
            parse_constant=lambda constant: _fail(
                f"{label} contains non-finite {constant}"
            ),
        )
    except RuntimeRole10AcquisitionError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeRole10AcquisitionError(f"{label} is not strict JSON") from exc
    if type(value) is not dict or canonical_json(value) != candidate:
        _fail(f"{label} is not canonical JSON")
    return value


def _sha256(value: Any, label: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None or value == "0" * 64:
        _fail(f"{label} is not an exact nonzero SHA-256")
    return value


def _size(value: Any, label: str, *, maximum: int = 8 * 1024**3) -> int:
    if type(value) is not int or value <= 0 or value > maximum:
        _fail(f"{label} is outside its byte bound")
    return value


def _ascii(value: Any, label: str, *, maximum: int = 4096) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > maximum:
        _fail(f"{label} is invalid")
    try:
        raw = value.encode("ascii", "strict")
    except UnicodeError as exc:
        raise RuntimeRole10AcquisitionError(f"{label} is not ASCII") from exc
    if any(byte < 0x21 or byte > 0x7E for byte in raw):
        _fail(f"{label} is not canonical printable ASCII")
    return value


def _artifact(value: Any, label: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        _fail(f"{label} is not a canonical identifier")
    return value


def _binding_placeholder(value: Any, label: str, *, manifest: bool = False) -> None:
    expected = {"binding": RELEASE_FREEZE_REQUIRED}
    if manifest:
        expected["schema"] = SOURCE_MANIFEST_SCHEMA
    if value != expected:
        _fail(f"{label} release binding differs")


def _exact_keys(value: Any, keys: set[str] | frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != frozenset(keys):
        _fail(f"{label} field set differs")
    return value


def _transport(value: Any, *, github: bool) -> None:
    value = _exact_keys(
        value,
        {
            "credentials",
            "initial_hosts",
            "maximum_redirects",
            "minimum_tls",
            "proxy_environment",
            "scheme",
        },
        "acquisition transport",
    )
    expected_hosts = (
        ["github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"]
        if github
        else ["registry-1.docker.io"]
    )
    if value != {
        "credentials": "FORBIDDEN",
        "initial_hosts": expected_hosts,
        "maximum_redirects": 5 if github else 0,
        "minimum_tls": "1.2",
        "proxy_environment": "IGNORED",
        "scheme": "https",
    }:
        _fail("acquisition transport differs")


def _validate_acquisition(role: str, value: Any) -> None:
    """Validate semantics that are intentionally not delegated to a downloader."""
    if role == "base_rootfs":
        value = _exact_keys(
            value,
            {
                "authentication",
                "derivation",
                "oci_closure",
                "transform",
                "transport",
                "upstream_payload",
            },
            "base-rootfs acquisition",
        )
        if value["authentication"] != {
            "audience": "registry.docker.io",
            "credential_source": "NONE",
            "scope": "repository:library/debian:pull",
            "token_endpoint": "https://auth.docker.io/token",
        }:
            _fail("base-rootfs anonymous registry authentication differs")
        upstream = _exact_keys(
            value["upstream_payload"], {"sha256", "size"}, "base-rootfs upstream payload"
        )
        _sha256(upstream.get("sha256"), "base-rootfs upstream sha256")
        _size(upstream.get("size"), "base-rootfs upstream size")
        closure = _exact_keys(
            value["oci_closure"],
            {
                "config_digest",
                "config_size",
                "index_digest",
                "index_size",
                "layer_diff_id",
                "manifest_digest",
                "manifest_size",
                "official_images_commit",
                "official_images_sha256",
                "official_images_size",
                "official_images_url",
                "platform",
            },
            "base-rootfs OCI closure",
        )
        for key in ("config_digest", "index_digest", "layer_diff_id", "manifest_digest"):
            digest = closure.get(key)
            if type(digest) is not str or not digest.startswith("sha256:"):
                _fail(f"base-rootfs {key} differs")
            _sha256(digest[7:], f"base-rootfs {key}")
        for key in ("config_size", "index_size", "manifest_size"):
            _size(closure.get(key), f"base-rootfs {key}")
        commit = closure.get("official_images_commit")
        if type(commit) is not str or _HEX40.fullmatch(commit) is None:
            _fail("base-rootfs official-images commit is not exact")
        _sha256(closure.get("official_images_sha256"), "base-rootfs official-images sha256")
        _size(closure.get("official_images_size"), "base-rootfs official-images size")
        if (
            closure.get("official_images_url")
            != "https://raw.githubusercontent.com/docker-library/official-images/"
            "b9c995a1c91bf8b195b035893ebdf8e877e7f7fa/library/debian"
            or closure.get("platform") != "linux/arm64/v8"
            or value.get("derivation")
            != "DEBIAN_ARM64_CACHE_FREE_ROOTFS_V1"
        ):
            _fail("base-rootfs derivation differs")
        transform = _exact_keys(
            value["transform"],
            {
                "derived_diff_id", "manifest_sha256", "output_sha256",
                "output_size", "recipe_version", "removed_path",
                "source_diff_id", "source_sha256", "source_size",
            },
            "base-rootfs cache-free transform",
        )
        if transform != {
            "derived_diff_id":
                "sha256:819f5c7a0170514b424e5a272bafe78bb28d5c5a66cb04c624545bd7797553a9",
            "manifest_sha256":
                "0960d7dd99bbd7acc6027579118eb1f8402400f888c35df095cebd949811edf3",
            "output_sha256":
                "70b69e00fbe608f857f0cc44b0b4b504423fe9008df287d260760ed2a84da7f0",
            "output_size": 100_236_788,
            "recipe_version": "plamen.debian_arm64_cache_free.v1",
            "removed_path": "/etc/ld.so.cache",
            "source_diff_id":
                "sha256:13a56b6535801be2adde694dabaf1c2df1d862a390661907dac821c42cd565cc",
            "source_sha256":
                "75782e20ea1f4a9d9259bc20a5ecbbea8d5943bf5370bf0f5727900728f1cc9a",
            "source_size": 28_117_289,
        }:
            _fail("base-rootfs cache-free transform differs")
        expected_transport = {
            "credentials": "FORBIDDEN",
            "initial_hosts": ["auth.docker.io", "registry-1.docker.io"],
            "maximum_redirects": 1,
            "minimum_tls": "1.2",
            "proxy_environment": "IGNORED",
            "redirect_targets": [{
                "host": "production.cloudfront.docker.com",
                "path":
                    "/registry-v2/docker/registry/v2/blobs/sha256/75/"
                    "75782e20ea1f4a9d9259bc20a5ecbbea8d5943bf5370bf0f5727900728f1cc9a/data",
            }],
            "scheme": "https",
        }
        if value["transport"] != expected_transport:
            _fail("base-rootfs acquisition transport differs")
        return
    if role == "debian_package_state":
        value = _exact_keys(
            value,
            {"derivation", "member", "package_count", "upstream_payload"},
            "Debian package-state acquisition",
        )
        upstream = _exact_keys(
            value["upstream_payload"], {"sha256", "size"}, "Debian package-state upstream payload"
        )
        _sha256(upstream.get("sha256"), "Debian package-state upstream sha256")
        _size(upstream.get("size"), "Debian package-state upstream size")
        if (
            value.get("derivation") != "DEBIAN_DPKG_STATUS_CANONICAL_JSON_V1"
            or value.get("member") != "var/lib/dpkg/status"
            or type(value.get("package_count")) is not int
            or value["package_count"] <= 0
        ):
            _fail("Debian package-state derivation differs")
        return
    if role == "cpython":
        value = _exact_keys(
            value,
            {"derivation", "release", "transform", "transport", "upstream_archive"},
            "CPython acquisition",
        )
        upstream = _exact_keys(
            value["upstream_archive"], {"sha256", "size"}, "CPython upstream archive"
        )
        _sha256(upstream.get("sha256"), "CPython upstream sha256")
        _size(upstream.get("size"), "CPython upstream size")
        release = _exact_keys(
            value["release"], {"asset_id", "commit", "release_tag"}, "CPython release"
        )
        _size(release.get("asset_id"), "CPython asset id", maximum=2**63 - 1)
        if type(release.get("commit")) is not str or _HEX40.fullmatch(release["commit"]) is None:
            _fail("CPython release commit is not exact")
        _ascii(release.get("release_tag"), "CPython release tag", maximum=64)
        transform = _exact_keys(
            value["transform"],
            {
                "archive_format",
                "file_mode",
                "member_types",
                "metadata",
                "omit_prefixes",
                "order",
                "source_prefix",
                "symlink_mode",
            },
            "CPython canonical transform",
        )
        if transform != {
            "archive_format": "USTAR_UNCOMPRESSED",
            "file_mode": "0555_IF_SOURCE_EXECUTABLE_ELSE_0444",
            "member_types": ["REGULAR", "SYMLINK"],
            "metadata": {"gid": 0, "gname": "", "mtime": 0, "uid": 0, "uname": ""},
            "omit_prefixes": ["python/share/terminfo/"],
            "order": "UTF8_PATH_BYTES_ASCENDING",
            "source_prefix": "python/",
            "symlink_mode": "0555",
        } or value.get("derivation") != "CPYTHON_INSTALL_ONLY_PREFIX_STRIP_USTAR_V1":
            _fail("CPython canonical transform differs")
        _transport(value["transport"], github=True)
        return
    if role in {"plamen_guest", "plamen_package"}:
        expected = (
            {
                "derivation", "external_authorities",
                "projection_authority_schema_prefix", "release_binding",
                "repository",
            }
            if role == "plamen_guest"
            else {
                "derivation",
                "projection_authority_schema_prefix",
                "projection_manifest_schema",
                "projection_policy_schema",
                "projection_state",
                "release_binding",
                "repository",
            }
        )
        value = _exact_keys(value, expected, f"{role} acquisition")
        if (
            value.get("release_binding")
            != "EXACT_COMPILED_PAYLOAD_AND_SOURCE_MANIFEST_REQUIRED"
            or value.get("repository") != "https://github.com/PlamenTSV/plamen.git"
        ):
            _fail(f"{role} release binding differs")
        if role == "plamen_guest":
            if (
                value.get("derivation") != "SIGNED_NATIVE_GUEST_PROJECTION_V1"
                or value.get("external_authorities")
                != ["HOST_NATIVE_INSTALL_RECEIPT_V2"]
                or value.get("projection_authority_schema_prefix") != "plamen.native-"
            ):
                _fail("Plamen guest projection contract differs")
        elif (
            value.get("derivation") != "FROZEN_PLAMEN_PACKAGE_PROJECTION_V1"
            or value.get("projection_authority_schema_prefix")
            != "plamen.runtime-source-projection."
            or value.get("projection_manifest_schema")
            != "plamen.runtime-source-projection.v1"
            or value.get("projection_policy_schema")
            != "plamen.runtime-source-projection-policy.v1"
            or value.get("projection_state") != "FROZEN"
        ):
            _fail("Plamen package projection contract differs")
        return
    _fail("acquisition role is unsupported")


def load_reviewed_policy(
    raw: bytes, *, expected_policy_sha256: str | None = None
) -> PolicyBinding:
    value = _decode(raw, label="role10 acquisition policy", maximum=MAX_POLICY_BYTES, final_lf=True)
    if frozenset(value) != _POLICY_KEYS or value.get("schema") != POLICY_SCHEMA:
        _fail("role10 acquisition policy field set or schema differs")
    role = value.get("role")
    contract = _ROLE_CONTRACT.get(role) if type(role) is str else None
    if contract is None:
        _fail("role10 acquisition policy role is unsupported")
    if (
        value.get("ordinal") != contract["ordinal"]
        or value.get("identity_mode") != contract["mode"]
        or value.get("receipt_validator") != contract["validator"]
        or value.get("receipt_schema") != contract["receipt_schema"]
        or value.get("destination") != contract["destination"]
        or value.get("media_type") != contract["media_type"]
        or value.get("platform") != contract["platform"]
        or value.get("required_paths") != list(contract["required_paths"])
    ):
        _fail("role10 acquisition policy role contract differs")
    _artifact(value.get("artifact_id"), "policy artifact_id")
    _ascii(value.get("version"), "policy version", maximum=256)
    reference = _ascii(value.get("source_reference"), "policy source_reference")
    if reference.startswith(("fixture:", "test:")):
        _fail("policy source_reference is non-production")
    _validate_acquisition(role, value.get("acquisition"))
    if contract["mode"] == STATIC:
        payload = value.get("payload")
        manifest = value.get("source_manifest")
        if type(payload) is not dict or frozenset(payload) != {"sha256", "size"}:
            _fail("static policy payload binding is malformed")
        if type(manifest) is not dict or frozenset(manifest) != {"schema", "sha256", "size"}:
            _fail("static policy source-manifest binding is malformed")
        _sha256(payload.get("sha256"), "policy payload sha256")
        _size(payload.get("size"), "policy payload size")
        if manifest.get("schema") != SOURCE_MANIFEST_SCHEMA:
            _fail("static policy source-manifest schema differs")
        _sha256(manifest.get("sha256"), "policy source-manifest sha256")
        _size(manifest.get("size"), "policy source-manifest size", maximum=MAX_SOURCE_MANIFEST_BYTES)
    else:
        _binding_placeholder(value.get("payload"), "frozen payload")
        _binding_placeholder(value.get("source_manifest"), "frozen source manifest", manifest=True)
    digest = hashlib.sha256(raw).hexdigest()
    if expected_policy_sha256 is not None and not hmac.compare_digest(
        digest, _sha256(expected_policy_sha256, "expected policy sha256")
    ):
        _fail("reviewed policy digest differs")
    return PolicyBinding(
        role=role,
        ordinal=contract["ordinal"],
        identity_mode=contract["mode"],
        receipt_schema=contract["receipt_schema"],
        receipt_validator=contract["validator"],
        policy_sha256=digest,
        document=value,
    )


def load_exact_reviewed_policy(role: str, raw: bytes) -> PolicyBinding:
    """Admit only the immutable policy bytes named in the production roster."""
    reviewed = REVIEWED_POLICIES.get(role) if type(role) is str else None
    if reviewed is None or len(raw) != reviewed.size:
        _fail("reviewed role10 policy source differs")
    binding = load_reviewed_policy(raw, expected_policy_sha256=reviewed.sha256)
    if binding.role != role:
        _fail("reviewed role10 policy crossed roles")
    return binding


def validate_reviewed_policy_roster(raw_by_role: Mapping[str, bytes]) -> tuple[PolicyBinding, ...]:
    if type(raw_by_role) is not dict or frozenset(raw_by_role) != frozenset(REVIEWED_POLICIES):
        _fail("reviewed role10 policy roster differs")
    bindings = tuple(
        load_exact_reviewed_policy(role, raw_by_role[role])
        for role in sorted(REVIEWED_POLICIES, key=lambda item: _ROLE_CONTRACT[item]["ordinal"])
    )
    base = bindings[0].document
    packages = bindings[1].document
    if (
        packages["acquisition"]["upstream_payload"]
        != base["acquisition"]["upstream_payload"]
    ):
        _fail("Debian package-state predecessor payload differs")
    return bindings


def _required_paths_sha256(policy: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(policy["required_paths"])).hexdigest()


def render_source_manifest_candidate(
    policy_raw: bytes,
    *,
    payload_sha256: str | None = None,
    payload_size: int | None = None,
    source_reference: str | None = None,
    version: str | None = None,
) -> bytes:
    """Render the exact op4 source manifest; this does not issue authority."""
    parsed = load_reviewed_policy(policy_raw)
    binding = load_exact_reviewed_policy(parsed.role, policy_raw)
    policy = binding.document
    if binding.identity_mode == STATIC:
        expected_payload = policy["payload"]
        digest = expected_payload["sha256"]
        size = expected_payload["size"]
        reference = policy["source_reference"]
        selected_version = policy["version"]
        if payload_sha256 is not None and payload_sha256 != digest:
            _fail("static source-manifest payload digest differs")
        if payload_size is not None and payload_size != size:
            _fail("static source-manifest payload size differs")
        if source_reference is not None and source_reference != reference:
            _fail("static source-manifest source reference differs")
        if version is not None and version != selected_version:
            _fail("static source-manifest version differs")
    else:
        digest = _sha256(payload_sha256, "frozen payload sha256")
        size = _size(payload_size, "frozen payload size")
        reference = _ascii(source_reference, "frozen source reference")
        selected_version = _ascii(version, "frozen version", maximum=256)
        if reference.startswith(("fixture:", "test:")):
            _fail("frozen source reference is non-production")
    return canonical_json(
        {
            "artifact_id": policy["artifact_id"],
            "authentication_scope": AUTHENTICATION_SCOPE,
            "media_type": policy["media_type"],
            "payload_sha256": digest,
            "payload_size": size,
            "platform": policy["platform"],
            "required_paths": policy["required_paths"],
            "role": binding.role,
            "schema_version": SOURCE_MANIFEST_SCHEMA,
            "source_reference": reference,
            "version": selected_version,
        }
    ) + b"\n"


def _validate_source_manifest(
    raw: bytes,
    *,
    binding: PolicyBinding,
    payload_sha256: str,
    payload_size: int,
) -> dict[str, Any]:
    manifest = _decode(
        raw,
        label="operation4 source manifest",
        maximum=MAX_SOURCE_MANIFEST_BYTES,
        final_lf=True,
    )
    if frozenset(manifest) != _SOURCE_MANIFEST_KEYS:
        _fail("operation4 source-manifest field set differs")
    policy = binding.document
    if (
        manifest.get("schema_version") != SOURCE_MANIFEST_SCHEMA
        or manifest.get("authentication_scope") != AUTHENTICATION_SCOPE
        or manifest.get("artifact_id") != policy["artifact_id"]
        or manifest.get("role") != binding.role
        or manifest.get("media_type") != policy["media_type"]
        or manifest.get("platform") != policy["platform"]
        or manifest.get("required_paths") != policy["required_paths"]
        or manifest.get("payload_sha256") != payload_sha256
        or manifest.get("payload_size") != payload_size
    ):
        _fail("operation4 source manifest does not bind the exact policy/payload")
    _ascii(manifest.get("source_reference"), "source-manifest source reference")
    _ascii(manifest.get("version"), "source-manifest version", maximum=256)
    return manifest


def _common_receipt(
    binding: PolicyBinding,
    *,
    payload_sha256: str,
    payload_size: int,
    source_manifest_raw: bytes,
    derivation: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    payload_sha256 = _sha256(payload_sha256, "observed payload sha256")
    payload_size = _size(payload_size, "observed payload size")
    manifest = _validate_source_manifest(
        source_manifest_raw,
        binding=binding,
        payload_sha256=payload_sha256,
        payload_size=payload_size,
    )
    if binding.identity_mode == STATIC:
        if binding.document["payload"] != {
            "sha256": payload_sha256,
            "size": payload_size,
        }:
            _fail("static receipt payload differs from reviewed policy")
        manifest_binding = binding.document["source_manifest"]
        if manifest_binding != {
            "schema": SOURCE_MANIFEST_SCHEMA,
            "sha256": hashlib.sha256(source_manifest_raw).hexdigest(),
            "size": len(source_manifest_raw),
        }:
            _fail("static receipt source manifest differs from reviewed policy")
    common = {
        "artifact_id": binding.document["artifact_id"],
        "derivation": _ascii(derivation, "receipt derivation", maximum=256),
        "destination": binding.document["destination"],
        "identity_mode": binding.identity_mode,
        "media_type": binding.document["media_type"],
        "payload_sha256": payload_sha256,
        "payload_size": payload_size,
        "platform": binding.document["platform"],
        "policy_schema": POLICY_SCHEMA,
        "policy_sha256": binding.policy_sha256,
        "required_paths_sha256": _required_paths_sha256(binding.document),
        "role": binding.role,
        "schema": binding.receipt_schema,
        "source_manifest_sha256": hashlib.sha256(source_manifest_raw).hexdigest(),
        "source_manifest_size": len(source_manifest_raw),
        "source_reference": manifest["source_reference"],
        "version": manifest["version"],
    }
    return common, manifest


def render_static_semantic_receipt(
    policy_raw: bytes, *, source_manifest_raw: bytes
) -> bytes:
    parsed = load_reviewed_policy(policy_raw)
    binding = load_exact_reviewed_policy(parsed.role, policy_raw)
    if binding.identity_mode != STATIC:
        _fail("static receipt renderer received a frozen-source policy")
    policy = binding.document
    acquisition = policy["acquisition"]
    common, _ = _common_receipt(
        binding,
        payload_sha256=policy["payload"]["sha256"],
        payload_size=policy["payload"]["size"],
        source_manifest_raw=source_manifest_raw,
        derivation=acquisition.get("derivation"),
    )
    if binding.receipt_schema == DEBIAN_RECEIPT_SCHEMA:
        upstream = acquisition.get("upstream_payload")
        if type(upstream) is not dict or frozenset(upstream) != {"sha256", "size"}:
            _fail("Debian upstream payload binding is malformed")
        value = {
            **common,
            "upstream_sha256": _sha256(upstream.get("sha256"), "Debian upstream sha256"),
            "upstream_size": _size(upstream.get("size"), "Debian upstream size"),
        }
    elif binding.receipt_schema == CPYTHON_RECEIPT_SCHEMA:
        upstream = acquisition.get("upstream_archive")
        transform = acquisition.get("transform")
        release = acquisition.get("release")
        if (
            type(upstream) is not dict
            or frozenset(upstream) != {"sha256", "size"}
            or type(transform) is not dict
            or type(release) is not dict
            or frozenset(release)
            != {"asset_id", "commit", "release_tag"}
        ):
            _fail("CPython acquisition binding is malformed")
        value = {
            **common,
            "transform_sha256": hashlib.sha256(canonical_json(transform)).hexdigest(),
            "upstream_asset_id": _size(
                release.get("asset_id"), "CPython upstream asset id", maximum=2**63 - 1
            ),
            "upstream_commit": release.get("commit"),
            "upstream_release_tag": _ascii(
                release.get("release_tag"), "CPython release tag", maximum=64
            ),
            "upstream_sha256": _sha256(upstream.get("sha256"), "CPython upstream sha256"),
            "upstream_size": _size(upstream.get("size"), "CPython upstream size"),
        }
        if type(value["upstream_commit"]) is not str or _HEX40.fullmatch(value["upstream_commit"]) is None:
            _fail("CPython upstream commit is not exact")
    else:
        _fail("static receipt schema is unsupported")
    return canonical_json(value)


def render_frozen_plamen_semantic_receipt(
    policy_raw: bytes,
    *,
    payload_sha256: str,
    payload_size: int,
    source_manifest_raw: bytes,
    projection_authority_schema: str,
    projection_authority_sha256: str,
    projection_authority_size: int,
    projection_roster_sha256: str,
    source_commit: str,
) -> bytes:
    parsed = load_reviewed_policy(policy_raw)
    binding = load_exact_reviewed_policy(parsed.role, policy_raw)
    if binding.identity_mode != FROZEN or binding.receipt_schema != PLAMEN_RECEIPT_SCHEMA:
        _fail("Plamen receipt renderer received a non-projection policy")
    common, manifest = _common_receipt(
        binding,
        payload_sha256=payload_sha256,
        payload_size=payload_size,
        source_manifest_raw=source_manifest_raw,
        derivation=binding.document["acquisition"].get("derivation"),
    )
    if type(source_commit) is not str or _HEX40.fullmatch(source_commit) is None:
        _fail("Plamen source commit is not exact")
    if (
        manifest["source_reference"]
        != f"git+https://github.com/PlamenTSV/plamen.git@{source_commit}"
        or manifest["version"] != source_commit
    ):
        _fail("Plamen source manifest is not bound to the exact source commit")
    value = {
        **common,
        "projection_authority_schema": _ascii(
            projection_authority_schema, "projection authority schema", maximum=128
        ),
        "projection_authority_sha256": _sha256(
            projection_authority_sha256, "projection authority sha256"
        ),
        "projection_authority_size": _size(
            projection_authority_size,
            "projection authority size",
            maximum=MAX_PROJECTION_AUTHORITY_BYTES,
        ),
        "projection_roster_sha256": _sha256(
            projection_roster_sha256, "projection roster sha256"
        ),
        "source_commit": source_commit,
    }
    return canonical_json(value)


def native_operation4_policy_input(
    policy_raw: bytes,
    *,
    payload_sha256: str | None = None,
    payload_size: int | None = None,
    source_manifest_raw: bytes | None = None,
) -> dict[str, Any]:
    """Project one exact compile-time role row without issuing authority."""
    role = load_reviewed_policy(policy_raw).role
    binding = load_exact_reviewed_policy(role, policy_raw)
    if binding.identity_mode == STATIC:
        expected = binding.document["payload"]
        digest = expected["sha256"]
        size = expected["size"]
        rendered = render_source_manifest_candidate(policy_raw)
        if source_manifest_raw is not None and source_manifest_raw != rendered:
            _fail("static compiled source manifest differs")
        source_manifest_raw = rendered
        if payload_sha256 is not None and payload_sha256 != digest:
            _fail("static compiled payload digest differs")
        if payload_size is not None and payload_size != size:
            _fail("static compiled payload size differs")
    else:
        digest = _sha256(payload_sha256, "frozen compiled payload sha256")
        size = _size(payload_size, "frozen compiled payload size")
        if source_manifest_raw is None:
            _fail("frozen compiled source manifest is absent")
        _validate_source_manifest(
            source_manifest_raw,
            binding=binding,
            payload_sha256=digest,
            payload_size=size,
        )
    return {
        "identity_mode": _MODE_IDS[binding.identity_mode],
        "payload_sha256": digest,
        "payload_size": size,
        "policy_sha256": binding.policy_sha256,
        "receipt_schema": binding.receipt_schema,
        "receipt_validator": _VALIDATOR_IDS[binding.receipt_validator],
        "role": binding.role,
        "role_ordinal": binding.ordinal,
        "source_manifest_sha256": hashlib.sha256(source_manifest_raw).hexdigest(),
        "source_manifest_size": len(source_manifest_raw),
    }


def validate_semantic_receipt(
    raw: bytes,
    *,
    policy_raw: bytes,
    expected_policy_sha256: str,
    observed_payload_sha256: str,
    observed_payload_size: int,
    source_manifest_raw: bytes,
) -> dict[str, Any]:
    """Strict reference validation for the native validator implementation."""
    binding = load_reviewed_policy(
        policy_raw, expected_policy_sha256=expected_policy_sha256
    )
    value = _decode(
        raw,
        label="operation4 semantic receipt",
        maximum=MAX_RECEIPT_BYTES,
        final_lf=False,
    )
    expected_keys = {
        DEBIAN_RECEIPT_SCHEMA: _DEBIAN_RECEIPT_KEYS,
        CPYTHON_RECEIPT_SCHEMA: _CPYTHON_RECEIPT_KEYS,
        PLAMEN_RECEIPT_SCHEMA: _PLAMEN_RECEIPT_KEYS,
    }[binding.receipt_schema]
    if frozenset(value) != expected_keys or value.get("schema") != binding.receipt_schema:
        _fail("operation4 semantic receipt field set or schema differs")
    common, _ = _common_receipt(
        binding,
        payload_sha256=observed_payload_sha256,
        payload_size=observed_payload_size,
        source_manifest_raw=source_manifest_raw,
        derivation=binding.document["acquisition"].get("derivation"),
    )
    for key, expected in common.items():
        if value.get(key) != expected:
            _fail(f"operation4 semantic receipt {key} differs")
    if binding.identity_mode == STATIC:
        expected = _decode(
            render_static_semantic_receipt(
                policy_raw, source_manifest_raw=source_manifest_raw
            ),
            label="expected static receipt",
            maximum=MAX_RECEIPT_BYTES,
            final_lf=False,
        )
        if value != expected:
            _fail("static semantic receipt differs from reviewed acquisition")
    else:
        if value.get("derivation") != binding.document["acquisition"].get("derivation"):
            _fail("Plamen projection derivation differs")
        _ascii(value.get("projection_authority_schema"), "projection authority schema", maximum=128)
        _sha256(value.get("projection_authority_sha256"), "projection authority sha256")
        _size(
            value.get("projection_authority_size"),
            "projection authority size",
            maximum=MAX_PROJECTION_AUTHORITY_BYTES,
        )
        _sha256(value.get("projection_roster_sha256"), "projection roster sha256")
        if type(value.get("source_commit")) is not str or _HEX40.fullmatch(value["source_commit"]) is None:
            _fail("Plamen projection source commit is not exact")
        prefix = binding.document["acquisition"].get("projection_authority_schema_prefix")
        if type(prefix) is not str or not value["projection_authority_schema"].startswith(prefix):
            _fail("Plamen projection authority schema is unsupported")
        if (
            value["source_reference"]
            != f"git+https://github.com/PlamenTSV/plamen.git@{value['source_commit']}"
            or value["version"] != value["source_commit"]
        ):
            _fail("Plamen projection receipt is not bound to its source commit")
    return value


def validate_debian_package_state_payload(raw: bytes) -> dict[str, Any]:
    value = _decode(
        raw,
        label="Debian package-state payload",
        maximum=16 * 1024 * 1024,
        final_lf=False,
    )
    if frozenset(value) != {"packages", "schema_version"} or value.get("schema_version") != "plamen.debian_package_state.v1":
        _fail("Debian package-state schema differs")
    packages = value.get("packages")
    if type(packages) is not list or not packages:
        _fail("Debian package-state roster is empty")
    prior: tuple[str, str, str] | None = None
    for row in packages:
        if type(row) is not dict or frozenset(row) != {"architecture", "name", "status", "version"}:
            _fail("Debian package-state row field set differs")
        for key in ("architecture", "name", "version"):
            _ascii(row.get(key), f"Debian package-state {key}", maximum=256)
        current = (row["name"], row["architecture"], row["version"])
        if prior is not None and current <= prior:
            _fail("Debian package-state rows are not strictly ordered")
        if type(row.get("status")) is not str or row["status"] != "install ok installed":
            _fail("Debian package-state contains a non-installed package")
        prior = current
    return value


__all__ = (
    "AUTHENTICATION_SCOPE",
    "CPYTHON_RECEIPT_SCHEMA",
    "DEBIAN_RECEIPT_SCHEMA",
    "FROZEN",
    "PLAMEN_RECEIPT_SCHEMA",
    "POLICY_SCHEMA",
    "PolicyBinding",
    "REVIEWED_POLICIES",
    "RELEASE_FREEZE_REQUIRED",
    "ReviewedPolicy",
    "RuntimeRole10AcquisitionError",
    "SOURCE_MANIFEST_SCHEMA",
    "STATIC",
    "canonical_json",
    "load_reviewed_policy",
    "load_exact_reviewed_policy",
    "native_operation4_policy_input",
    "render_frozen_plamen_semantic_receipt",
    "render_source_manifest_candidate",
    "render_static_semantic_receipt",
    "validate_debian_package_state_payload",
    "validate_reviewed_policy_roster",
    "validate_semantic_receipt",
)
