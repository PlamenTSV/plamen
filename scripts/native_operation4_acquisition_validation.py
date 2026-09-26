"""Frozen operation-4 acquisition receipt validator.

This module is loaded from a retained, native-authenticated descriptor.  It
accepts descriptors only, performs no network or pathname access, and returns
no authority.  The native parent binds the same receipt bytes, payloads,
manifests, policy rows, verifier key, and this module's digest into its MACed
terminal.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import struct
from typing import Any


_FOOTER_SIZE = 512
_MAX_RECEIPT = 16 * 1024 * 1024
_SCHEMAS = (
    "plamen.debian-runtime-acquisition-receipt.v1",
    "plamen.debian-runtime-acquisition-receipt.v1",
    "plamen.plamen-source-projection-acquisition-receipt.v1",
    "plamen.cpython-runtime-acquisition-receipt.v1",
    "plamen.plamen-source-projection-acquisition-receipt.v1",
    "plamen.native-backend-latest-acquisition-receipt.v1",
    "plamen.native-backend-latest-acquisition-receipt.v1",
    "plamen.foundry-acquisition-receipt.v1",
    "plamen.medusa-acquisition-receipt.v1",
    "plamen.solc-amd64-acquisition-receipt.v1",
    "plamen.amd64-compat-acquisition-receipt.v1",
)
_ROLES = (
    "base_rootfs", "debian_package_state", "plamen_guest", "cpython",
    "plamen_package", "codex", "claude", "foundry", "medusa",
    "solc_amd64", "amd64_compat",
)
_GROUP_PATHS = ("control/runtime-composition-manifest.json",) + tuple(
    item
    for index, role in enumerate(_ROLES)
    for item in (
        f"runtime-inputs/{index:02d}-{role}.payload",
        f"runtime-inputs/{index:02d}-{role}.source-manifest.json",
    )
)
_VALIDATORS = (1, 1, 2, 3, 2, 4, 4, 5, 6, 7, 8)
_MODES = (1, 1, 3, 1, 3, 2, 2, 1, 1, 1, 1)
_SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX128 = re.compile(r"^[0-9a-f]{128}$")
_SRI = re.compile(r"^sha512-([A-Za-z0-9+/]{86}==)$")
_PLATFORMS = {
    "darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64",
    "win32-arm64", "win32-x64",
}
_NPM_KEY_ID = "SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U"
_NPM_P256_DER = (
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY6Ya7W++7aUPzvMTrezH6Ycx3c+"
    "HOKYCcNGybJZSCJq/fd7Qa8uuAKtdIkUQtQiEKERhAmE5lMMJhP8OkDOa2g=="
)

_ED_Q = 2**255 - 19
_ED_L = 2**252 + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_Q - 2, _ED_Q)) % _ED_Q
_ED_I = pow(2, (_ED_Q - 1) // 4, _ED_Q)
_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = _P256_P - 3
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


class NativeOperation4ValidationError(RuntimeError):
    pass


def _ed_add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    factor = _ED_D * x1 * x2 * y1 * y2 % _ED_Q
    return (
        (x1 * y2 + x2 * y1) * pow(1 + factor, _ED_Q - 2, _ED_Q) % _ED_Q,
        (y1 * y2 + x1 * x2) * pow(1 - factor, _ED_Q - 2, _ED_Q) % _ED_Q,
    )


def _ed_scalar(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = (0, 1)
    while scalar:
        if scalar & 1:
            result = _ed_add(result, point)
        point = _ed_add(point, point)
        scalar >>= 1
    return result


def _ed_decode(raw: bytes) -> tuple[int, int]:
    if len(raw) != 32:
        raise NativeOperation4ValidationError("Ed25519 point length differs")
    value = int.from_bytes(raw, "little")
    y, sign = value & ((1 << 255) - 1), value >> 255
    if y >= _ED_Q:
        raise NativeOperation4ValidationError("Ed25519 point is non-canonical")
    xx = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_Q - 2, _ED_Q) % _ED_Q
    x = pow(xx, (_ED_Q + 3) // 8, _ED_Q)
    if (x * x - xx) % _ED_Q:
        x = x * _ED_I % _ED_Q
    if (x * x - xx) % _ED_Q:
        raise NativeOperation4ValidationError("Ed25519 point is not on curve")
    if x == 0 and sign:
        raise NativeOperation4ValidationError("Ed25519 negative zero is non-canonical")
    if (x & 1) != sign:
        x = _ED_Q - x
    return x, y


def _verify_ed25519(public: bytes, message: bytes, signature: bytes) -> None:
    if len(public) != 32 or len(signature) != 64:
        raise NativeOperation4ValidationError("Ed25519 signature bounds differ")
    base_y = 4 * pow(5, _ED_Q - 2, _ED_Q) % _ED_Q
    base = _ed_decode(base_y.to_bytes(32, "little"))
    point_a, point_r = _ed_decode(public), _ed_decode(signature[:32])
    if (
        _ed_scalar(point_a, 8) == (0, 1)
        or _ed_scalar(point_r, 8) == (0, 1)
        or _ed_scalar(point_a, _ED_L) != (0, 1)
        or _ed_scalar(point_r, _ED_L) != (0, 1)
    ):
        raise NativeOperation4ValidationError("Ed25519 non-prime-subgroup point is forbidden")
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= _ED_L:
        raise NativeOperation4ValidationError("Ed25519 scalar is non-canonical")
    challenge = int.from_bytes(
        hashlib.sha512(signature[:32] + public + message).digest(), "little",
    ) % _ED_L
    if _ed_scalar(base, scalar) != _ed_add(point_r, _ed_scalar(point_a, challenge)):
        raise NativeOperation4ValidationError("Ed25519 signature differs")


def _ec_add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % _P256_P == 0:
        return None
    slope = (
        (3 * x1 * x1 + _P256_A) * pow(2 * y1, _P256_P - 2, _P256_P)
        if left == right else
        (y2 - y1) * pow((x2 - x1) % _P256_P, _P256_P - 2, _P256_P)
    ) % _P256_P
    x3 = (slope * slope - x1 - x2) % _P256_P
    return x3, (slope * (x1 - x3) - y1) % _P256_P


def _ec_scalar(point, scalar: int):
    result = None
    while scalar:
        if scalar & 1:
            result = _ec_add(result, point)
        point = _ec_add(point, point)
        scalar >>= 1
    return result


def _der_signature(raw: bytes) -> tuple[int, int]:
    if len(raw) < 8 or raw[0] != 0x30 or raw[1] != len(raw) - 2 or raw[2] != 0x02:
        raise NativeOperation4ValidationError("ECDSA DER signature differs")
    r_size = raw[3]
    r_end = 4 + r_size
    if r_end + 2 > len(raw) or raw[r_end] != 0x02:
        raise NativeOperation4ValidationError("ECDSA DER scalar differs")
    s_size = raw[r_end + 1]
    if r_end + 2 + s_size != len(raw):
        raise NativeOperation4ValidationError("ECDSA DER size differs")
    r_raw = raw[4:r_end]
    s_raw = raw[r_end + 2:]
    if (
        not r_raw or not s_raw
        or (r_raw[0] & 0x80) or (s_raw[0] & 0x80)
        or (len(r_raw) > 1 and r_raw[0] == 0 and not (r_raw[1] & 0x80))
        or (len(s_raw) > 1 and s_raw[0] == 0 and not (s_raw[1] & 0x80))
    ):
        raise NativeOperation4ValidationError("ECDSA DER integer is non-canonical")
    r = int.from_bytes(r_raw, "big")
    s = int.from_bytes(s_raw, "big")
    if not (1 <= r < _P256_N and 1 <= s < _P256_N):
        raise NativeOperation4ValidationError("ECDSA scalar bounds differ")
    return r, s


def _verify_p256_public(public: tuple[int, int], message: bytes, signature: bytes) -> None:
    if (public[1] * public[1] - (public[0] ** 3 + _P256_A * public[0] + _P256_B)) % _P256_P:
        raise NativeOperation4ValidationError("npm P-256 key is not on curve")
    r, s = _der_signature(signature)
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    inverse = pow(s, _P256_N - 2, _P256_N)
    point = _ec_add(_ec_scalar(_P256_G, z * inverse % _P256_N), _ec_scalar(public, r * inverse % _P256_N))
    if point is None or point[0] % _P256_N != r:
        raise NativeOperation4ValidationError("npm P-256 signature differs")


def _verify_p256(message: bytes, signature: bytes) -> None:
    encoded = base64.b64decode(_NPM_P256_DER, validate=True)
    point_raw = encoded[-65:]
    if point_raw[:1] != b"\x04":
        raise NativeOperation4ValidationError("npm P-256 key differs")
    public = (int.from_bytes(point_raw[1:33], "big"), int.from_bytes(point_raw[33:], "big"))
    _verify_p256_public(public, message, signature)


def _read(fd: int, size: int, offset: int = 0) -> bytes:
    result = bytearray()
    while len(result) < size:
        part = os.pread(fd, min(1 << 20, size - len(result)), offset + len(result))
        if not part:
            raise NativeOperation4ValidationError("retained receipt is truncated")
        result.extend(part)
    return bytes(result)


def _stream_hashes(fd: int, offset: int, size: int) -> tuple[str, str]:
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    consumed = 0
    while consumed < size:
        part = os.pread(fd, min(1 << 20, size - consumed), offset + consumed)
        if not part:
            raise NativeOperation4ValidationError("grouped payload is truncated")
        sha256.update(part)
        sha512.update(part)
        consumed += len(part)
    return sha256.hexdigest(), "sha512-" + base64.b64encode(sha512.digest()).decode("ascii")


def _payload_identity(payload: bytes | tuple[int, int, int]) -> tuple[int, str, str]:
    if isinstance(payload, bytes):
        return (
            len(payload), hashlib.sha256(payload).hexdigest(),
            "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode("ascii"),
        )
    if (
        not isinstance(payload, tuple) or len(payload) != 3
        or not all(type(item) is int for item in payload)
    ):
        raise NativeOperation4ValidationError("retained payload reference differs")
    descriptor, offset, size = payload
    sha256, sri = _stream_hashes(descriptor, offset, size)
    return size, sha256, sri


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _safe_relative_path(value: Any) -> bool:
    return (
        type(value) is str
        and bool(value)
        and not value.startswith("/")
        and "\\" not in value
        and all(0x21 <= ord(character) <= 0x7E for character in value)
        and all(part not in {"", ".", ".."} for part in value.split("/"))
    )


def _cstr(raw: bytes) -> str:
    head, marker, tail = raw.partition(b"\0")
    if not marker or any(tail) or not head or any(byte < 0x21 or byte > 0x7E for byte in head):
        raise NativeOperation4ValidationError("footer string differs")
    return head.decode("ascii")


def _footer(raw: bytes, role: int) -> dict[str, Any]:
    if (
        len(raw) != _FOOTER_SIZE or raw[:8] != b"PLMOP4R1"
        or struct.unpack_from(">HH", raw, 8) != (1, _FOOTER_SIZE)
        or struct.unpack_from(">H", raw, 12)[0] != role
        or struct.unpack_from(">H", raw, 14)[0] != _MODES[role]
        or struct.unpack_from(">H", raw, 16)[0] != _VALIDATORS[role]
        or struct.unpack_from(">H", raw, 18)[0] != 0
        or any(raw[396:480])
        or hashlib.sha256(raw[:480]).digest() != raw[480:]
    ):
        raise NativeOperation4ValidationError("native producer footer differs")
    payload_size, manifest_size, semantic_size = struct.unpack_from(">QQQ", raw, 20)
    schema = _cstr(raw[172:268])
    version_raw = raw[268:396]
    version = _cstr(version_raw) if version_raw[0] else ""
    if schema != _SCHEMAS[role] or not payload_size or not manifest_size or not semantic_size:
        raise NativeOperation4ValidationError("footer authority differs")
    return {
        "payload_size": payload_size,
        "manifest_size": manifest_size,
        "semantic_size": semantic_size,
        "policy_sha256": raw[44:76].hex(),
        "payload_sha256": raw[76:108].hex(),
        "manifest_sha256": raw[108:140].hex(),
        "semantic_sha256": raw[140:172],
        "schema": schema,
        "version": version,
    }


def _verify_registry_signature(row: Any, package: str, version: str) -> None:
    if not isinstance(row, dict):
        raise NativeOperation4ValidationError("registry row differs")
    integrity = row.get("integrity")
    signature = row.get("registry_signature")
    if (
        row.get("package") != package or row.get("version") != version
        or not isinstance(integrity, str) or _SRI.fullmatch(integrity) is None
        or not isinstance(signature, dict)
        or set(signature) != {"keyid", "message_sha256", "signature"}
        or signature.get("keyid") != _NPM_KEY_ID
    ):
        raise NativeOperation4ValidationError("registry identity differs")
    message = f"{package}@{version}:{integrity}".encode("ascii")
    if signature.get("message_sha256") != hashlib.sha256(message).hexdigest():
        raise NativeOperation4ValidationError("registry signed message differs")
    try:
        encoded_signature = base64.b64decode(signature["signature"], validate=True)
    except Exception as exc:
        raise NativeOperation4ValidationError("npm P-256 signature encoding differs") from exc
    _verify_p256(message, encoded_signature)


def _cross_bind_runtime(value: dict[str, Any], footer: dict[str, Any]) -> None:
    install = value.get("install")
    if not isinstance(install, dict):
        raise NativeOperation4ValidationError("backend install binding is absent")
    if (
        set(install) != {
            "transaction_id", "generation_id", "install_receipt_sha256",
            "source_manifest_sha256", "source_manifest_size",
        }
        or re.fullmatch(r"[A-Za-z0-9._-]{1,200}", str(install.get("transaction_id") or "")) is None
        or re.fullmatch(r"npm-[0-9a-f]{64}", str(install.get("generation_id") or "")) is None
        or _HEX64.fullmatch(str(install.get("install_receipt_sha256") or "")) is None
        or install.get("source_manifest_sha256") != footer["manifest_sha256"]
        or install.get("source_manifest_size") != footer["manifest_size"]
    ):
        raise NativeOperation4ValidationError("backend runtime projection differs")


def _validate_backend(value: Any, footer: dict[str, Any], role: int, key: bytes,
                      payload_bytes: bytes | tuple[int, int, int], *,
                      authenticate_registry: bool = True) -> None:
    fields = {
        "schema", "selector", "policy_schema", "policy_sha256",
        "resolved_version", "resolved_release", "registry", "upstream",
        "transport", "payload", "installed", "probes", "install",
        "authentication", "receipt_sha256",
    }
    selector = _ROLES[role]
    if (
        not isinstance(value, dict) or set(value) != fields
        or value.get("schema") != _SCHEMAS[role]
        or value.get("selector") != selector
        or value.get("policy_schema") != "plamen.native-backend-acquisition.v2"
        or value.get("policy_sha256") != footer["policy_sha256"]
        or value.get("resolved_version") != footer["version"]
        or not _SEMVER.fullmatch(str(value.get("resolved_version") or ""))
    ):
        raise NativeOperation4ValidationError("backend receipt authority differs")
    authentication = value.get("authentication")
    key_id = hashlib.sha256(key).hexdigest()
    if (
        not isinstance(authentication, dict)
        or set(authentication) != {"scheme", "key_id", "signature"}
        or authentication.get("scheme") != "ed25519"
        or authentication.get("key_id") != key_id
        or _HEX128.fullmatch(str(authentication.get("signature") or "")) is None
    ):
        raise NativeOperation4ValidationError("backend receipt signer differs")
    unsigned = dict(value)
    unsigned.pop("authentication")
    unsigned.pop("receipt_sha256")
    _verify_ed25519(
        key, _canonical(unsigned), bytes.fromhex(authentication["signature"]),
    )
    candidate = dict(value)
    candidate.pop("receipt_sha256")
    if value.get("receipt_sha256") != hashlib.sha256(_canonical(candidate)).hexdigest():
        raise NativeOperation4ValidationError("backend receipt digest differs")
    registry = value.get("registry")
    package = "@openai/codex" if selector == "codex" else "@anthropic-ai/claude-code"
    registry_fields = {
        "selector", "package", "version", "metadata_sha256", "metadata_url",
        "tarball_url", "integrity", "shasum", "registry_signature",
        "trusted_publisher", "provenance", "platform_package",
    }
    if (
        not isinstance(registry, dict) or set(registry) != registry_fields
        or registry.get("selector") != selector
        or registry.get("package") != package
        or registry.get("version") != value["resolved_version"]
        or _HEX64.fullmatch(str(registry.get("metadata_sha256") or "")) is None
        or registry.get("metadata_url") != (
            "https://registry.npmjs.org/" + package.replace("/", "%2f") + "/latest"
        )
        or re.fullmatch(r"[0-9a-f]{40}", str(registry.get("shasum") or "")) is None
        or not str(registry.get("tarball_url") or "").startswith("https://registry.npmjs.org/")
    ):
        raise NativeOperation4ValidationError("backend registry fields differ")
    if authenticate_registry:
        _verify_registry_signature(registry, package, value["resolved_version"])
    platform_package = registry.get("platform_package")
    platform_fields = {
        "install_name", "package", "version", "metadata_url", "metadata_sha256",
        "tarball_url", "integrity", "shasum", "registry_signature", "provenance",
    }
    if (
        not isinstance(platform_package, dict) or set(platform_package) != platform_fields
        or not isinstance(platform_package.get("install_name"), str)
        or not platform_package["install_name"]
        or _SEMVER.fullmatch(str(platform_package.get("version") or "")) is None
        or _HEX64.fullmatch(str(platform_package.get("metadata_sha256") or "")) is None
        or re.fullmatch(r"[0-9a-f]{40}", str(platform_package.get("shasum") or "")) is None
        or not str(platform_package.get("metadata_url") or "").startswith("https://registry.npmjs.org/")
        or not str(platform_package.get("tarball_url") or "").startswith("https://registry.npmjs.org/")
        or value.get("resolved_release") != platform_package.get("version")
    ):
        raise NativeOperation4ValidationError("backend platform package is absent")
    if authenticate_registry:
        _verify_registry_signature(
            platform_package, str(platform_package.get("package") or ""),
            str(platform_package.get("version") or ""),
        )
    platform_integrity = platform_package.get("integrity")
    payload_size, payload_sha256, expected_sri = _payload_identity(payload_bytes)
    if (
        platform_integrity != expected_sri
        or payload_size != footer["payload_size"]
        or payload_sha256 != footer["payload_sha256"]
    ):
        raise NativeOperation4ValidationError("backend payload SRI projection differs")
    payload = value.get("payload")
    if (
        not isinstance(payload, dict)
        or set(payload) != {
            "source_url", "size", "sha256", "sha512_sri", "archive_format",
            "member_count", "member_roster_sha256", "selected_member",
            "path_traversal_rejected",
        }
        or payload.get("source_url") != platform_package.get("tarball_url")
        or payload.get("size") != footer["payload_size"]
        or payload.get("sha256") != footer["payload_sha256"]
        or payload.get("sha512_sri") != expected_sri
        or payload.get("archive_format") != "tar.gz"
        or type(payload.get("member_count")) is not int or payload["member_count"] <= 0
        or _HEX64.fullmatch(str(payload.get("member_roster_sha256") or "")) is None
        or not isinstance(payload.get("selected_member"), str) or not payload["selected_member"]
        or payload.get("path_traversal_rejected") is not True
    ):
        raise NativeOperation4ValidationError("backend retained payload differs")
    if selector == "codex":
        trusted = registry.get("trusted_publisher")
        if not isinstance(trusted, dict) or set(trusted) != {"id", "oidc_config_id"} or trusted.get("id") != "github" or not trusted.get("oidc_config_id"):
            raise NativeOperation4ValidationError("Codex trusted publisher differs")
        for provenance in (registry.get("provenance"), platform_package.get("provenance")):
            if not isinstance(provenance, dict) or set(provenance) != {"predicate_type", "url"} or provenance.get("predicate_type") != "https://slsa.dev/provenance/v1" or not str(provenance.get("url") or "").startswith("https://"):
                raise NativeOperation4ValidationError("Codex SLSA provenance differs")
    else:
        upstream = value.get("upstream")
        installed = value.get("installed")
        if (
            registry.get("trusted_publisher") is not None
            or registry.get("provenance") is not None
            or platform_package.get("provenance") is not None
            or not isinstance(upstream, dict)
            or set(upstream) != {
                "latest_url", "latest_sha256", "manifest_url", "manifest_sha256",
                "manifest_size", "commit", "platform", "executable_sha256",
                "executable_size",
            }
            or upstream.get("latest_url") != "https://downloads.claude.ai/claude-code-releases/latest"
            or upstream.get("manifest_url") != f"https://downloads.claude.ai/claude-code-releases/{value['resolved_version']}/manifest.json"
            or _HEX64.fullmatch(str(upstream.get("latest_sha256") or "")) is None
            or _HEX64.fullmatch(str(upstream.get("manifest_sha256") or "")) is None
            or type(upstream.get("manifest_size")) is not int or upstream["manifest_size"] <= 0
            or upstream.get("platform") not in _PLATFORMS
            or not isinstance(installed, dict)
            or upstream.get("executable_sha256") != installed.get("executable_sha256")
            or upstream.get("executable_size") != installed.get("executable_size")
            or not re.fullmatch(r"[0-9a-f]{40}", str(upstream.get("commit") or ""))
        ):
            raise NativeOperation4ValidationError("Claude manifest join differs")
    if selector == "codex" and value.get("upstream") is not None:
        raise NativeOperation4ValidationError("Codex receipt has foreign upstream")
    installed = value.get("installed")
    probes = value.get("probes")
    expected_publisher = (
        ("codex", "2DC432GLL2") if selector == "codex"
        else ("com.anthropic.claude-code", "Q6L2SF6YDW")
    )
    code_signature = installed.get("code_signature") if isinstance(installed, dict) else None
    if (
        not isinstance(installed, dict)
        or set(installed) != {
            "platform", "relative_path", "executable_size", "executable_sha256",
            "closure_count", "closure_bytes", "closure_sha256", "code_signature",
        }
        or installed.get("platform") not in _PLATFORMS
        or not isinstance(installed.get("relative_path"), str) or not installed["relative_path"]
        or not _HEX64.fullmatch(str(installed.get("executable_sha256") or ""))
        or type(installed.get("executable_size")) is not int or installed["executable_size"] <= 0
        or not _HEX64.fullmatch(str(installed.get("closure_sha256") or ""))
        or type(installed.get("closure_count")) is not int or installed["closure_count"] <= 0
        or type(installed.get("closure_bytes")) is not int or installed["closure_bytes"] <= 0
        or not isinstance(code_signature, dict)
        or set(code_signature) != {"mode", "identifier", "team_identifier", "cdhash_sha256"}
        or not isinstance(probes, dict) or set(probes) != {"version", "help"}
    ):
        raise NativeOperation4ValidationError("backend installed closure differs")
    package_platform = installed["platform"]
    expected_install_name = package + "-" + package_platform
    expected_platform_package = (
        package if selector == "codex" else expected_install_name
    )
    expected_platform_version = (
        value["resolved_version"] + "-" + package_platform
        if selector == "codex" else value["resolved_version"]
    )
    expected_member = (
        r"package/vendor/[^/]+/bin/codex(?:\.exe)?"
        if selector == "codex" else r"package/claude(?:\.exe)?"
    )
    expected_relative = (
        re.fullmatch(
            re.escape("node_modules/" + expected_install_name)
            + r"/vendor/[^/]+/bin/"
            r"codex(?:\.exe)?",
            installed["relative_path"],
        ) is not None
        if selector == "codex" else
        installed["relative_path"]
        == "node_modules/@anthropic-ai/claude-code/bin/claude.exe"
    )
    if (
        platform_package.get("install_name") != expected_install_name
        or platform_package.get("package") != expected_platform_package
        or platform_package.get("version") != expected_platform_version
        or value.get("resolved_release") != expected_platform_version
        or not _safe_relative_path(payload["selected_member"])
        or re.fullmatch(expected_member, payload["selected_member"]) is None
        or not _safe_relative_path(installed["relative_path"])
        or not expected_relative
    ):
        raise NativeOperation4ValidationError("backend executable platform binding differs")
    expected_mode = "APPLE_DEVELOPER_ID" if installed["platform"].startswith("darwin") else "REGISTRY_SIGNATURE_ONLY"
    if code_signature.get("mode") != expected_mode:
        raise NativeOperation4ValidationError("backend publisher mode differs")
    if installed["platform"].startswith("darwin") and (
        code_signature.get("identifier") != expected_publisher[0]
        or code_signature.get("team_identifier") != expected_publisher[1]
        or _HEX64.fullmatch(str(code_signature.get("cdhash_sha256") or "")) is None
    ):
        raise NativeOperation4ValidationError("backend Apple publisher differs")
    if not installed["platform"].startswith("darwin") and any(
        item is not None
        for item in (
            code_signature.get("identifier"),
            code_signature.get("team_identifier"),
            code_signature.get("cdhash_sha256"),
        )
    ):
        raise NativeOperation4ValidationError("backend publisher fields differ")
    transport = value.get("transport")
    if (
        not isinstance(transport, dict)
        or set(transport) != {"tls_minimum", "redirect_count", "credentials", "proxy_environment", "endpoints_sha256"}
        or transport.get("tls_minimum") != "1.2" or transport.get("redirect_count") != 0
        or transport.get("credentials") != "FORBIDDEN" or transport.get("proxy_environment") != "IGNORED"
        or _HEX64.fullmatch(str(transport.get("endpoints_sha256") or "")) is None
    ):
        raise NativeOperation4ValidationError("backend transport differs")
    for name, argv in (("version", ["--version"]), ("help", ["--help"] if selector == "claude" else ["exec", "--help"])):
        probe = probes.get(name)
        if (
            not isinstance(probe, dict)
            or set(probe) != {"argv", "returncode", "stdout_sha256", "stderr_sha256", "normalized_output", "observed_contract"}
            or probe.get("argv") != argv or probe.get("returncode") != 0
            or _HEX64.fullmatch(str(probe.get("stdout_sha256") or "")) is None
            or _HEX64.fullmatch(str(probe.get("stderr_sha256") or "")) is None
            or not isinstance(probe.get("normalized_output"), str)
            or not isinstance(probe.get("observed_contract"), list)
            or not all(isinstance(item, str) for item in probe["observed_contract"])
        ):
            raise NativeOperation4ValidationError("backend probe differs")
    expected_version_output = f"{value['resolved_version']} (Claude Code)" if selector == "claude" else f"codex-cli {value['resolved_version']}"
    if probes["version"]["normalized_output"] != expected_version_output:
        raise NativeOperation4ValidationError("backend version probe differs")
    expected_contract = (
        ["--allowedTools", "--disallowedTools", "--json-schema", "--mcp-config", "--model", "--output-format", "--permission-mode", "--strict-mcp-config"]
        if selector == "claude" else
        ["--ephemeral", "--json", "--model", "--output-last-message", "--sandbox", "--skip-git-repo-check"]
    )
    if sorted(probes["help"]["observed_contract"]) != sorted(expected_contract):
        raise NativeOperation4ValidationError("backend CLI contract differs")
    _cross_bind_runtime(value, footer)


def _group_payloads(group_fd: int) -> tuple[tuple[int, int, int], ...]:
    info = os.fstat(group_fd)
    if not 256 + 23 * 256 <= info.st_size <= 8 * 1024**3:
        raise NativeOperation4ValidationError("grouped input bounds differ")
    header = _read(group_fd, 256)
    version, header_size, operation, count, row_size, data_start, total = struct.unpack_from(
        ">HHIIIQQ", header, 8,
    )
    if (
        header[:8] != b"PLMRHG1\0" or (version, header_size, operation, count, row_size)
        != (1, 256, 4, 23, 256) or data_start != 256 + count * 256
        or data_start + total != info.st_size or any(header[104:])
    ):
        raise NativeOperation4ValidationError("grouped input header differs")
    roster = _read(group_fd, count * 256, 256)
    if hashlib.sha256(roster).digest() != header[72:104]:
        raise NativeOperation4ValidationError("grouped input roster differs")
    payloads: list[tuple[int, int, int]] = []
    expected_offset = data_start
    for index, expected_path in enumerate(_GROUP_PATHS):
        row = roster[index * 256:(index + 1) * 256]
        name_size = struct.unpack_from(">H", row, 0)[0]
        size, offset = struct.unpack_from(">QQ", row, 8)
        name = expected_path.encode("ascii")
        if (
            name_size != len(name) or row[56:56 + name_size] != name
            or any(row[2:8]) or any(row[56 + name_size:])
            or offset != expected_offset
        ):
            raise NativeOperation4ValidationError("grouped input row differs")
        sha256, _sri = _stream_hashes(group_fd, offset, size)
        if bytes.fromhex(sha256) != row[24:56]:
            raise NativeOperation4ValidationError("grouped payload commitment differs")
        if index > 0 and index % 2 == 1:
            payloads.append((group_fd, offset, size))
        expected_offset += size
    if expected_offset != info.st_size or len(payloads) != 11:
        raise NativeOperation4ValidationError("grouped input extent differs")
    return tuple(payloads)


def validate_all(verifier_key_fd: int, producer_receipt_fds: tuple[int, ...],
                 group_fd: int, *, _testing_skip_registry_signature: bool = False) -> None:
    """Validate every retained semantic prefix before operation 4 can run."""
    if type(verifier_key_fd) is not int or type(group_fd) is not int or type(producer_receipt_fds) is not tuple or len(producer_receipt_fds) != 11:
        raise NativeOperation4ValidationError("operation-4 validator ABI differs")
    key_info = os.fstat(verifier_key_fd)
    key = _read(verifier_key_fd, 32)
    if key_info.st_size != 32 or len(key) != 32:
        raise NativeOperation4ValidationError("install verifier key differs")
    payloads = _group_payloads(group_fd)
    for role, descriptor in enumerate(producer_receipt_fds):
        info = os.fstat(descriptor)
        if not _FOOTER_SIZE < info.st_size <= _MAX_RECEIPT:
            raise NativeOperation4ValidationError("producer receipt bounds differ")
        footer_raw = _read(descriptor, _FOOTER_SIZE, info.st_size - _FOOTER_SIZE)
        footer = _footer(footer_raw, role)
        semantic = _read(descriptor, info.st_size - _FOOTER_SIZE)
        if (
            len(semantic) != footer["semantic_size"]
            or hashlib.sha256(semantic).digest() != footer["semantic_sha256"]
        ):
            raise NativeOperation4ValidationError("semantic receipt commitment differs")
        try:
            value = json.loads(semantic)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise NativeOperation4ValidationError("semantic receipt is not JSON") from exc
        if _canonical(value) != semantic or not isinstance(value, dict) or value.get("schema") != _SCHEMAS[role]:
            raise NativeOperation4ValidationError("semantic receipt encoding differs")
        if role in (5, 6):
            _validate_backend(
                value, footer, role, key, payloads[role],
                authenticate_registry=not _testing_skip_registry_signature,
            )
        elif value.get("role") != _ROLES[role]:
            raise NativeOperation4ValidationError("static receipt role differs")


__all__ = ["NativeOperation4ValidationError", "validate_all"]
