"""Exact, replayable Claude Code executable and version observation.

The configured Claude executable is a launch authority, not a PATH hint.  This
module resolves one absolute, unaliased path, content-binds the implementation
that can be mechanically enumerated, and probes that exact path with
``--version`` through the owned process runner.  It performs no provider query.

Wrapper formats are executable programs in their own right.  A wrapper is
proof-grade only when a reviewed parser can enumerate its runtime and
entrypoint closure.  Unknown wrappers remain useful diagnostic observations,
but carry ``TRANSITIVE_IMPLEMENTATION_UNBOUND`` and cannot replay as launch
authority.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import threading
from typing import Any, Mapping, Sequence

from claude_headless_profile import (
    ClaudeHeadlessProfileError,
    parse_claude_code_version,
)
from owned_process_runner import (
    OwnedProcessRunnerError,
    run_owned_process,
)


OBSERVATION_SCHEMA = "plamen.claude_executable_observation.v1"
GENERATION_OBSERVATION_SCHEMA = (
    "plamen.claude_generation_backend_observation.v1"
)
OBSERVATION_REFERENCE_SCHEMA = (
    "plamen.claude_executable_observation_reference.v1"
)
NATIVE_PLATFORM_AUTHORITY_SCHEMA = (
    "plamen.claude_native_platform_authority.v1"
)
DIRECT_IMPLEMENTATION_BOUND = "DIRECT_IMPLEMENTATION_BOUND"
TRANSITIVE_IMPLEMENTATION_BOUND = "TRANSITIVE_IMPLEMENTATION_BOUND"
TRANSITIVE_IMPLEMENTATION_UNBOUND = "TRANSITIVE_IMPLEMENTATION_UNBOUND"
NATIVE_IMPLEMENTATION_UNBOUND = "NATIVE_IMPLEMENTATION_UNBOUND"
NPM_RESOLUTION_DENOMINATOR_UNBOUND = (
    "NPM_RESOLUTION_DENOMINATOR_UNBOUND"
)
PROOF_GRADE = "PROOF_GRADE"
NO_PROOF_GRADE_LAUNCH = "NO_PROOF_GRADE_LAUNCH"

DEFAULT_VERSION_PROBE_TIMEOUT_SECONDS = 3.0
# The authenticated front replays the signed install and generation closures
# before it reaches Claude.  That bounded local admission is materially slower
# than probing an already-resolved executable, especially on Windows and while
# sibling workers are reading the same immutable generation.  Keep this equal
# to the public current-selection admission ceiling: the probe remains bounded
# and fail-closed, but ordinary authenticated closure replay is not mistaken
# for an unavailable executable under benign disk/AV contention.
GENERATION_VERSION_PROBE_TIMEOUT_SECONDS = 120.0
VERSION_PROBE_OUTPUT_LIMIT_BYTES = 512
MAX_IMPLEMENTATION_FILE_BYTES = 512 * 1024 * 1024
MAX_WRAPPER_BYTES = 256 * 1024
MAX_NPM_CLOSURE_FILES = 8192
MAX_NPM_CLOSURE_BYTES = 512 * 1024 * 1024

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_SELECTED_BACKEND_KEYS = {
    "execution_kind", "relative_path", "version", "size", "sha256",
    "member_authority",
}
_MEMBER_AUTHORITY_KEYS = {
    "schema", "generation_id", "receipt_sha256", "census_sha256",
    "request_sha256", "generation_policy_sha256", "execution_kind",
    "receipt_file_sha256", "relative_path", "size", "sha256", "mode",
    "link_count", "closure_root", "closure_count", "closure_sha256",
    "closure", "ancestors",
}
_MEMBER_CLOSURE_ROW_KEYS = {
    "path", "kind", "size", "sha256", "mode", "link_count", "reparse",
}
_MEMBER_ANCESTOR_KEYS = {"path", "mode", "link_count", "reparse"}
_MEMBER_AUTHENTICATION_KEYS = {"scheme", "key_id", "signature"}
_CAPABILITY_RE = re.compile(r"-{0,2}[A-Za-z0-9][A-Za-z0-9_.:=/-]{0,126}")
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_NATIVE_MAGICS = (
    b"MZ",
    b"\x7fELF",
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
)
_WINDOWS_PUBLISHER_POLICY = {
    "policy_id": "anthropic-claude-code-windows-v1",
    "publisher_names": frozenset(
        {
            "anthropic pbc",
            "anthropic, pbc",
        }
    ),
    "product_name": "Claude Code",
}

# One driver process prepares many Claude attempts against the same immutable,
# signed generation.  The public backend front independently revalidates that
# generation immediately before every real provider execution.  Retain only a
# process-local successful version observation so concurrent preparations do
# not each perform the same expensive authenticated closure replay.  Reuse is
# exact-authority only: the key binds the current front file identity/bytes,
# launch selection, selected backend, environment, capabilities, and timeout.
_GENERATION_OBSERVATION_CACHE_LOCK = threading.Lock()
_GENERATION_OBSERVATION_CACHE: tuple[tuple[str, ...], bytes] | None = None

# A version is admitted only after its complete flag/init contract has a
# fixture.  Deliberately use exact rows: an unknown patch release is an unknown
# future version, not an implicit promise of CLI compatibility.
_REVIEWED_COMPATIBILITY_ROWS: dict[str, dict[str, Any]] = {
    "2.1.220": {
        "compatibility_id": "claude-code-2.1.220",
        "supported_capabilities": (
            "-p",
            "--dangerously-skip-permissions",
            "--disable-slash-commands",
            "--mcp-config",
            "--no-chrome",
            "--no-session-persistence",
            "--output-format=stream-json",
            "--permission-mode=dontAsk",
            "--prompt-suggestions=false",
            "--safe-mode",
            "--session-id",
            "--setting-sources=",
            "--strict-mcp-config",
            "--tools",
            "--verbose",
            "init-security-v2",
        ),
    },
    "2.1.250": {
        "compatibility_id": "claude-code-2.1.250",
        "supported_capabilities": (
            "-p",
            "--dangerously-skip-permissions",
            "--disable-slash-commands",
            "--mcp-config",
            "--no-chrome",
            "--no-session-persistence",
            "--output-format=stream-json",
            "--permission-mode=dontAsk",
            "--prompt-suggestions=false",
            "--safe-mode",
            "--session-id",
            "--setting-sources=",
            "--strict-mcp-config",
            "--tools",
            "--verbose",
            "init-security-v2",
        ),
    },
    "2.1.252": {
        "compatibility_id": "claude-code-2.1.252",
        "supported_capabilities": (
            "-p",
            "--dangerously-skip-permissions",
            "--disable-slash-commands",
            "--mcp-config",
            "--no-chrome",
            "--no-session-persistence",
            "--output-format=stream-json",
            "--permission-mode=default",
            "--permission-mode=dontAsk",
            "--prompt-suggestions=false",
            "--safe-mode",
            "--session-id",
            "--setting-sources=",
            "--strict-mcp-config",
            "--tools",
            "--verbose",
            "init-security-v2",
        ),
    },
}

# Path-bearing flags are attached only after WER materializes attempt-private
# files, so they were absent from the legacy executable compatibility
# denominator.  Typed profile references still gate them by the exact observed
# version through this reviewed companion row.
_REVIEWED_TYPED_PROFILE_CAPABILITIES_BY_VERSION = {
    "2.1.220": frozenset({"--settings"}),
    "2.1.250": frozenset({"--settings"}),
    "2.1.252": frozenset({
        "--allowedTools",
        "--restricted",
        "--settings",
    }),
}

_REVIEWED_NPM_CMD_WRAPPER = (
    "@echo off\n"
    '"%~dp0node.exe" '
    '"%~dp0node_modules\\@anthropic-ai\\claude-code\\cli.js" %*'
)


class ClaudeExecutableObservationError(RuntimeError):
    """Executable identity, probe output, compatibility, or replay is unsafe."""


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ClaudeExecutableObservationError(
            "Claude executable observation is not canonical JSON"
        ) from exc


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _is_reparse_stat(info: os.stat_result) -> bool:
    return bool(
        int(getattr(info, "st_file_attributes", 0))
        & _FILE_ATTRIBUTE_REPARSE_POINT
    )


def _same_path_spelling(left: str, right: str) -> bool:
    if os.name == "nt":
        return os.path.normcase(left) == os.path.normcase(right)
    return left == right


def _canonical_unaliased_path(value: str, *, label: str) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\x00" in value
    ):
        raise ClaudeExecutableObservationError(f"{label} is malformed")
    path = Path(value)
    if not path.is_absolute():
        raise ClaudeExecutableObservationError(
            f"{label} must be an absolute exact path"
        )
    normalized = os.path.normpath(value)
    if not _same_path_spelling(value, normalized):
        raise ClaudeExecutableObservationError(
            f"{label} is not a canonical path spelling"
        )

    # Inspect the submitted spelling before resolve() can erase an alias.
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor = cursor / part
        try:
            info = os.lstat(cursor)
        except OSError as exc:
            raise ClaudeExecutableObservationError(
                f"{label} cannot be inspected: {cursor}"
            ) from exc
        if stat.S_ISLNK(info.st_mode) or _is_reparse_stat(info):
            raise ClaudeExecutableObservationError(
                f"{label} traverses a symlink/reparse alias"
            )

    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ClaudeExecutableObservationError(f"{label} does not exist") from exc
    if not _same_path_spelling(str(path), str(resolved)):
        raise ClaudeExecutableObservationError(
            f"{label} resolves through an alias"
        )
    return resolved


def _stable_file_bytes(path: Path, *, label: str) -> tuple[dict[str, Any], bytes]:
    canonical = _canonical_unaliased_path(str(path), label=label)
    try:
        before = os.lstat(canonical)
    except OSError as exc:
        raise ClaudeExecutableObservationError(f"{label} cannot be inspected") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or _is_reparse_stat(before)
    ):
        raise ClaudeExecutableObservationError(
            f"{label} must be a regular non-symlink/non-reparse file"
        )
    if int(getattr(before, "st_nlink", 1)) != 1:
        raise ClaudeExecutableObservationError(
            f"{label} is a hardlink alias"
        )
    if int(before.st_size) > MAX_IMPLEMENTATION_FILE_BYTES:
        raise ClaudeExecutableObservationError(
            f"{label} exceeds the implementation binding ceiling"
        )

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(canonical, flags)
    except OSError as exc:
        raise ClaudeExecutableObservationError(f"{label} cannot be opened") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (int(opened.st_dev), int(opened.st_ino))
            != (int(before.st_dev), int(before.st_ino))
            or int(getattr(opened, "st_nlink", 1)) != 1
        ):
            raise ClaudeExecutableObservationError(
                f"{label} changed or resolved through an alias while opening"
            )
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_IMPLEMENTATION_FILE_BYTES:
                raise ClaudeExecutableObservationError(
                    f"{label} exceeds the implementation binding ceiling"
                )
            digest.update(chunk)
            chunks.append(chunk)
        after_fd = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        after_path = os.lstat(canonical)
    except OSError as exc:
        raise ClaudeExecutableObservationError(
            f"{label} disappeared during observation"
        ) from exc
    # Windows' CRT may synthesize execute bits differently for ``fstat`` and
    # path ``lstat``.  Bind path mode before/after, while the descriptor
    # identity comparison uses the stable kernel-backed fields.
    descriptor_stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_nlink")
    if any(
        int(getattr(before, name, 0))
        != int(getattr(after_fd, name, 0))
        or int(getattr(before, name, 0))
        != int(getattr(after_path, name, 0))
        for name in descriptor_stable
    ) or int(before.st_mode) != int(after_path.st_mode):
        raise ClaudeExecutableObservationError(
            f"{label} changed or drifted during observation"
        )
    raw = b"".join(chunks)
    if len(raw) != int(before.st_size):
        raise ClaudeExecutableObservationError(
            f"{label} byte count drifted during observation"
        )
    row = {
        "path": str(canonical),
        "sha256": digest.hexdigest(),
        "size": len(raw),
        "device": int(before.st_dev),
        "inode": int(before.st_ino),
        "mode": int(before.st_mode),
        "link_count": int(getattr(before, "st_nlink", 1)),
    }
    return row, raw


def _with_role(row: Mapping[str, Any], role: str) -> dict[str, Any]:
    return {"role": role, **dict(row)}


def _is_native_image(raw: bytes) -> bool:
    return any(raw.startswith(magic) for magic in _NATIVE_MAGICS)


def _normalized_publisher_name(value: str) -> str:
    return " ".join(value.strip().casefold().split())


def _query_windows_native_metadata(
    executable: Path,
    *,
    environment: Mapping[str, str],
) -> dict[str, str] | None:
    """Query WinVerifyTrust, signed PE certificates, and version resources.

    The implementation is in-process and cache-only: it cannot leak the
    ambient environment or silently make a revocation-network request.
    """

    del environment
    if os.name != "nt":
        return None
    try:
        version_strings = _windows_version_strings(executable)
        validated_signer = _win_verify_trust_validated_signer(executable)
    except (OSError, ValueError, ImportError):
        return None
    if version_strings is None or validated_signer is None:
        return None
    if (
        _normalized_publisher_name(validated_signer["publisher_name"])
        not in _WINDOWS_PUBLISHER_POLICY["publisher_names"]
    ):
        return None
    return {
        "signature_status": "Valid",
        "signer_subject": validated_signer["signer_subject"],
        "publisher_name": validated_signer["publisher_name"],
        "product_name": version_strings["product_name"],
        "file_version": version_strings["file_version"],
    }


def _win_verify_trust_validated_signer(
    executable: Path,
) -> dict[str, str] | None:
    """Return only the leaf certificate selected by WinVerifyTrust.

    Enumerating every certificate embedded in a CMS bag is unsafe: an
    unrelated valid signer can carry an Anthropic certificate as an unused
    decoy.  WinTrust's provider state identifies the SignerInfo chain it
    actually validated; only that chain's leaf is publisher authority.
    """

    import ctypes
    from ctypes import wintypes
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pcwszFilePath", wintypes.LPCWSTR),
            ("hFile", wintypes.HANDLE),
            ("pgKnownSubject", ctypes.c_void_p),
        ]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", wintypes.DWORD),
            ("fdwRevocationChecks", wintypes.DWORD),
            ("dwUnionChoice", wintypes.DWORD),
            ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
            ("dwStateAction", wintypes.DWORD),
            ("hWVTStateData", wintypes.HANDLE),
            ("pwszURLReference", wintypes.LPCWSTR),
            ("dwProvFlags", wintypes.DWORD),
            ("dwUIContext", wintypes.DWORD),
            ("pSignatureSettings", ctypes.c_void_p),
        ]

    class CERT_CONTEXT(ctypes.Structure):
        _fields_ = [
            ("dwCertEncodingType", wintypes.DWORD),
            ("pbCertEncoded", ctypes.POINTER(ctypes.c_ubyte)),
            ("cbCertEncoded", wintypes.DWORD),
            ("pCertInfo", ctypes.c_void_p),
            ("hCertStore", wintypes.HANDLE),
        ]

    class CRYPT_PROVIDER_CERT(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pCert", ctypes.POINTER(CERT_CONTEXT)),
        ]

    action = GUID(
        0x00AAC56B,
        0xCD44,
        0x11D0,
        (ctypes.c_ubyte * 8)(
            0x8C,
            0xC2,
            0x00,
            0xC0,
            0x4F,
            0xC2,
            0x95,
            0xEE,
        ),
    )
    file_info = WINTRUST_FILE_INFO(
        ctypes.sizeof(WINTRUST_FILE_INFO),
        str(executable),
        None,
        None,
    )
    data = WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    data.dwUIChoice = 2  # WTD_UI_NONE
    data.fdwRevocationChecks = 0  # WTD_REVOKE_NONE
    data.dwUnionChoice = 1  # WTD_CHOICE_FILE
    data.pFile = ctypes.pointer(file_info)
    data.dwStateAction = 1  # WTD_STATEACTION_VERIFY
    data.dwProvFlags = 0x1000  # WTD_CACHE_ONLY_URL_RETRIEVAL
    win_verify_trust = ctypes.windll.wintrust.WinVerifyTrust
    win_verify_trust.argtypes = [
        wintypes.HWND,
        ctypes.POINTER(GUID),
        ctypes.POINTER(WINTRUST_DATA),
    ]
    win_verify_trust.restype = ctypes.c_long
    status = int(
        win_verify_trust(None, ctypes.byref(action), ctypes.byref(data))
    )
    try:
        if status != 0 or not data.hWVTStateData:
            return None
        helper_data = ctypes.windll.wintrust.WTHelperProvDataFromStateData
        helper_data.argtypes = [wintypes.HANDLE]
        helper_data.restype = ctypes.c_void_p
        helper_signer = ctypes.windll.wintrust.WTHelperGetProvSignerFromChain
        helper_signer.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        helper_signer.restype = ctypes.c_void_p
        helper_cert = ctypes.windll.wintrust.WTHelperGetProvCertFromChain
        helper_cert.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        helper_cert.restype = ctypes.POINTER(CRYPT_PROVIDER_CERT)

        provider_data = helper_data(data.hWVTStateData)
        if not provider_data:
            return None
        signer = helper_signer(provider_data, 0, False, 0)
        if not signer:
            return None
        provider_cert = helper_cert(signer, 0)
        if (
            not provider_cert
            or not provider_cert.contents.pCert
            or not provider_cert.contents.pCert.contents.pbCertEncoded
        ):
            return None
        context = provider_cert.contents.pCert.contents
        encoded_size = int(context.cbCertEncoded)
        if encoded_size <= 0 or encoded_size > 1024 * 1024:
            return None
        encoded = ctypes.string_at(
            context.pbCertEncoded,
            encoded_size,
        )
        certificate = x509.load_der_x509_certificate(encoded)
        organizations = certificate.subject.get_attributes_for_oid(
            NameOID.ORGANIZATION_NAME
        )
        if not organizations:
            return None
        return {
            "publisher_name": organizations[0].value,
            "signer_subject": certificate.subject.rfc4514_string(),
        }
    finally:
        data.dwStateAction = 2  # WTD_STATEACTION_CLOSE
        win_verify_trust(None, ctypes.byref(action), ctypes.byref(data))


def _win_verify_trust(executable: Path) -> bool:
    """Compatibility predicate backed by validated signer-chain extraction."""

    return _win_verify_trust_validated_signer(executable) is not None


def _windows_version_strings(executable: Path) -> dict[str, str] | None:
    import ctypes
    from ctypes import wintypes

    version = ctypes.windll.version
    handle = wintypes.DWORD(0)
    size = int(
        version.GetFileVersionInfoSizeW(
            str(executable),
            ctypes.byref(handle),
        )
    )
    if size <= 0:
        return None
    buffer = ctypes.create_string_buffer(size)
    if not version.GetFileVersionInfoW(
        str(executable),
        0,
        size,
        buffer,
    ):
        return None
    translation_pointer = ctypes.c_void_p()
    translation_length = wintypes.UINT(0)
    if not version.VerQueryValueW(
        buffer,
        "\\VarFileInfo\\Translation",
        ctypes.byref(translation_pointer),
        ctypes.byref(translation_length),
    ):
        return None
    raw = ctypes.string_at(
        translation_pointer,
        int(translation_length.value),
    )
    if len(raw) < 4:
        return None
    language = int.from_bytes(raw[0:2], "little")
    codepage = int.from_bytes(raw[2:4], "little")

    def query(name: str) -> str | None:
        pointer = ctypes.c_void_p()
        length = wintypes.UINT(0)
        key = (
            f"\\StringFileInfo\\{language:04x}{codepage:04x}\\{name}"
        )
        if not version.VerQueryValueW(
            buffer,
            key,
            ctypes.byref(pointer),
            ctypes.byref(length),
        ):
            return None
        value = ctypes.wstring_at(pointer, max(0, int(length.value) - 1))
        return value if value else None

    product = query("ProductName")
    file_version = query("FileVersion")
    if product is None or file_version is None:
        return None
    return {
        "product_name": product,
        "file_version": file_version,
    }


def _pe_authenticode_signers(
    executable: Path,
) -> list[dict[str, str]]:
    import warnings

    from cryptography.hazmat.primitives.serialization import pkcs7
    from cryptography.x509.oid import NameOID

    raw = executable.read_bytes()
    if len(raw) < 0x100 or raw[:2] != b"MZ":
        return []
    pe_offset = int.from_bytes(raw[0x3C:0x40], "little")
    if (
        pe_offset <= 0
        or pe_offset + 24 > len(raw)
        or raw[pe_offset : pe_offset + 4] != b"PE\0\0"
    ):
        return []
    optional = pe_offset + 24
    magic = int.from_bytes(raw[optional : optional + 2], "little")
    if magic == 0x10B:
        directory = optional + 96
    elif magic == 0x20B:
        directory = optional + 112
    else:
        return []
    security = directory + (4 * 8)
    if security + 8 > len(raw):
        return []
    offset = int.from_bytes(raw[security : security + 4], "little")
    size = int.from_bytes(raw[security + 4 : security + 8], "little")
    if offset <= 0 or size < 8 or offset + size > len(raw):
        return []
    cursor = offset
    end = offset + size
    rows: list[dict[str, str]] = []
    while cursor + 8 <= end:
        length = int.from_bytes(raw[cursor : cursor + 4], "little")
        revision = int.from_bytes(raw[cursor + 4 : cursor + 6], "little")
        certificate_type = int.from_bytes(
            raw[cursor + 6 : cursor + 8],
            "little",
        )
        if length < 8 or cursor + length > end:
            return []
        if revision in {0x0100, 0x0200} and certificate_type == 0x0002:
            blob = raw[cursor + 8 : cursor + length]
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                certificates = pkcs7.load_der_pkcs7_certificates(blob)
            for certificate in certificates:
                organizations = certificate.subject.get_attributes_for_oid(
                    NameOID.ORGANIZATION_NAME
                )
                for organization in organizations:
                    rows.append(
                        {
                            "publisher_name": organization.value,
                            "signer_subject": (
                                certificate.subject.rfc4514_string()
                            ),
                        }
                    )
        cursor += (length + 7) & ~7
    return rows


def _compile_native_platform_authority(
    *,
    executable_row: Mapping[str, Any],
    metadata: Mapping[str, str] | None,
    claude_code_version: str,
) -> dict[str, Any] | None:
    if metadata is None:
        return None
    expected_fields = {
        "signature_status",
        "signer_subject",
        "publisher_name",
        "product_name",
        "file_version",
    }
    if set(metadata) != expected_fields:
        return None
    publisher = metadata.get("publisher_name")
    subject = metadata.get("signer_subject")
    product = metadata.get("product_name")
    file_version = metadata.get("file_version")
    accepted_versions = {
        claude_code_version,
        f"{claude_code_version}.0",
    }
    if (
        metadata.get("signature_status") != "Valid"
        or not isinstance(publisher, str)
        or _normalized_publisher_name(publisher)
        not in _WINDOWS_PUBLISHER_POLICY["publisher_names"]
        or not isinstance(subject, str)
        or not subject
        or len(subject) > 1024
        or "\x00" in subject
        or not isinstance(product, str)
        or product != _WINDOWS_PUBLISHER_POLICY["product_name"]
        or not isinstance(file_version, str)
        or file_version not in accepted_versions
    ):
        return None
    core = {
        "schema": NATIVE_PLATFORM_AUTHORITY_SCHEMA,
        "platform": "WINDOWS_AUTHENTICODE",
        "publisher_policy_id": _WINDOWS_PUBLISHER_POLICY["policy_id"],
        "publisher_name": publisher,
        "signer_subject": subject,
        "product_name": product,
        "file_version": file_version,
        "claude_code_version": claude_code_version,
        "executable_path": executable_row["path"],
        "executable_sha256": executable_row["sha256"],
        "executable_size": executable_row["size"],
        "signature_status": "Valid",
        "implementation_closure": (
            "SIGNED_NATIVE_PRODUCT_IMAGE_WITH_EXTERNAL_OS_AUTHORITY"
        ),
    }
    return {**core, "authority_sha256": _digest(core)}


def replay_claude_native_platform_authority(
    value: Mapping[str, Any],
    *,
    executable_row: Mapping[str, Any],
    claude_code_version: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ClaudeExecutableObservationError(
            "native platform authority must be an object"
        )
    clone = dict(value)
    expected_fields = {
        "schema",
        "platform",
        "publisher_policy_id",
        "publisher_name",
        "signer_subject",
        "product_name",
        "file_version",
        "claude_code_version",
        "executable_path",
        "executable_sha256",
        "executable_size",
        "signature_status",
        "implementation_closure",
        "authority_sha256",
    }
    if set(clone) != expected_fields:
        raise ClaudeExecutableObservationError(
            "native platform authority fields drifted"
        )
    digest = clone.pop("authority_sha256")
    rebuilt = _compile_native_platform_authority(
        executable_row=executable_row,
        metadata={
            "signature_status": clone.get("signature_status"),
            "signer_subject": clone.get("signer_subject"),
            "publisher_name": clone.get("publisher_name"),
            "product_name": clone.get("product_name"),
            "file_version": clone.get("file_version"),
        },
        claude_code_version=claude_code_version,
    )
    if (
        rebuilt is None
        or clone.get("schema") != NATIVE_PLATFORM_AUTHORITY_SCHEMA
        or clone.get("platform") != "WINDOWS_AUTHENTICODE"
        or clone.get("publisher_policy_id")
        != _WINDOWS_PUBLISHER_POLICY["policy_id"]
        or clone.get("claude_code_version") != claude_code_version
        or clone.get("executable_path") != executable_row.get("path")
        or clone.get("executable_sha256") != executable_row.get("sha256")
        or clone.get("executable_size") != executable_row.get("size")
        or clone.get("implementation_closure")
        != "SIGNED_NATIVE_PRODUCT_IMAGE_WITH_EXTERNAL_OS_AUTHORITY"
        or not isinstance(digest, str)
        or _SHA256_RE.fullmatch(digest) is None
        or rebuilt != {**clone, "authority_sha256": digest}
    ):
        raise ClaudeExecutableObservationError(
            "native platform signature/product/version authority does not replay"
        )
    return rebuilt


def _normalize_environment(
    environment: Mapping[str, str] | None,
) -> dict[str, str]:
    source = os.environ if environment is None else environment
    if not isinstance(source, Mapping):
        raise ClaudeExecutableObservationError(
            "version probe environment must be an object"
        )
    result: dict[str, str] = {}
    for key, value in source.items():
        if (
            not isinstance(key, str)
            or not key
            or "=" in key
            or "\x00" in key
            or not isinstance(value, str)
            or "\x00" in value
        ):
            raise ClaudeExecutableObservationError(
                "version probe environment is malformed"
            )
        result[key] = value
    return result


def _strict_json_object(raw: bytes, *, label: str) -> dict[str, Any] | None:
    def object_pairs(pairs):
        result: dict[str, Any] = {}
        for name, value in pairs:
            if not isinstance(name, str) or name in result:
                raise ValueError(f"{label} has duplicated/malformed keys")
            result[name] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=object_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError(f"{label} contains non-finite JSON")
            ),
        )
    except (UnicodeError, ValueError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _dependency_path(node_modules_root: Path, name: str) -> Path | None:
    if (
        not isinstance(name, str)
        or not name
        or "\x00" in name
        or "\\" in name
        or name.startswith(".")
        or (
            name.startswith("@")
            and (
                name.count("/") != 1
                or any(not part for part in name.split("/"))
            )
        )
        or (not name.startswith("@") and "/" in name)
    ):
        return None
    candidate = node_modules_root.joinpath(*name.split("/"))
    return candidate if candidate.is_dir() else None


def _npm_declared_package_roots(
    *,
    primary_root: Path,
    node_modules_root: Path,
) -> list[str] | None:
    """Close over every declared runtime/optional/peer npm package.

    The entire contents of every resolved package root are bound. Missing
    declared packages are an unbound result because their later appearance
    could change Node resolution after arm.
    """

    try:
        primary = _canonical_unaliased_path(
            str(primary_root.resolve(strict=True)),
            label="Claude npm package root",
        )
        top_node_modules = _canonical_unaliased_path(
            str(node_modules_root.resolve(strict=True)),
            label="Claude npm node_modules root",
        )
    except ClaudeExecutableObservationError:
        return None
    pending = [primary]
    seen: set[str] = set()
    roots: list[Path] = []
    while pending:
        current = pending.pop()
        current_text = str(current)
        if current_text in seen:
            continue
        seen.add(current_text)
        manifest = current / "package.json"
        try:
            _manifest_row, raw = _stable_file_bytes(
                manifest,
                label="Claude npm package manifest",
            )
        except ClaudeExecutableObservationError:
            return None
        parsed = _strict_json_object(
            raw,
            label="Claude npm package manifest",
        )
        if parsed is None:
            return None
        names: set[str] = set()
        for field in (
            "dependencies",
            "optionalDependencies",
            "peerDependencies",
        ):
            dependencies = parsed.get(field, {})
            if dependencies is None:
                dependencies = {}
            if (
                not isinstance(dependencies, dict)
                or any(
                    not isinstance(name, str)
                    or not isinstance(requirement, str)
                    or not requirement
                    for name, requirement in dependencies.items()
                )
            ):
                return None
            names.update(dependencies)
        roots.append(current)
        local_node_modules = current / "node_modules"
        for name in sorted(names):
            dependency = _dependency_path(local_node_modules, name)
            if dependency is None:
                dependency = _dependency_path(top_node_modules, name)
            if dependency is None:
                return None
            try:
                dependency = _canonical_unaliased_path(
                    str(dependency.resolve(strict=True)),
                    label=f"Claude npm dependency {name}",
                )
            except ClaudeExecutableObservationError:
                return None
            pending.append(dependency)

    # Nested package roots are already covered by their ancestor's exact tree.
    minimal: list[Path] = []
    for root in sorted(roots, key=lambda value: (len(value.parts), str(value))):
        if any(root.is_relative_to(parent) for parent in minimal):
            continue
        minimal.append(root)
    return sorted(str(root) for root in minimal)


def _npm_package_closure_rows(
    roots: Sequence[str],
) -> list[dict[str, Any]] | None:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    total = 0
    for root_text in roots:
        try:
            root = _canonical_unaliased_path(
                root_text,
                label="Claude npm closure root",
            )
        except ClaudeExecutableObservationError:
            return None
        for current_text, directory_names, file_names in os.walk(
            root,
            topdown=True,
            followlinks=False,
        ):
            current = Path(current_text)
            safe_directories: list[str] = []
            for name in sorted(directory_names):
                candidate = current / name
                try:
                    info = os.lstat(candidate)
                except OSError:
                    return None
                if (
                    stat.S_ISLNK(info.st_mode)
                    or _is_reparse_stat(info)
                    or not stat.S_ISDIR(info.st_mode)
                ):
                    return None
                safe_directories.append(name)
            directory_names[:] = safe_directories
            for name in sorted(file_names):
                path = current / name
                try:
                    row, _raw = _stable_file_bytes(
                        path,
                        label="Claude npm implementation closure file",
                    )
                except ClaudeExecutableObservationError:
                    return None
                if row["path"] in seen:
                    continue
                seen.add(row["path"])
                rows.append(row)
                total += row["size"]
                if (
                    len(rows) > MAX_NPM_CLOSURE_FILES
                    or total > MAX_NPM_CLOSURE_BYTES
                ):
                    return None
    return sorted(rows, key=lambda row: row["path"])


def _npm_cmd_transitive_files(
    *,
    wrapper: Path,
    wrapper_raw: bytes,
    environment: Mapping[str, str],
) -> tuple[list[dict[str, Any]], str, list[str]] | None:
    if wrapper.name.casefold() != "claude.cmd" or len(wrapper_raw) > MAX_WRAPPER_BYTES:
        return None
    try:
        text = wrapper_raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    # Batch is a programming language.  Do not infer authority from tokens or
    # comments: only the complete reviewed two-line shim is admitted.  Normal
    # CRLF/LF transport differences are semantically immaterial to cmd.exe.
    normalized = "\n".join(text.splitlines()).casefold()
    if normalized != _REVIEWED_NPM_CMD_WRAPPER.casefold():
        return None

    entrypoint = (
        wrapper.parent
        / "node_modules"
        / "@anthropic-ai"
        / "claude-code"
        / "cli.js"
    )
    sibling_runtime = wrapper.parent / "node.exe"
    runtime: Path | None = None
    if sibling_runtime.is_file():
        runtime = sibling_runtime
    else:
        found = shutil.which(
            "node.exe" if os.name == "nt" else "node",
            path=environment.get("PATH"),
        )
        if found:
            runtime = Path(found)
    if not entrypoint.is_file() or runtime is None:
        return None

    runtime_row, runtime_raw = _stable_file_bytes(
        runtime, label="Claude npm Node runtime"
    )
    if not _is_native_image(runtime_raw):
        return None
    package_root = entrypoint.parent
    roots = _npm_declared_package_roots(
        primary_root=package_root,
        node_modules_root=wrapper.parent / "node_modules",
    )
    if roots is None:
        return None
    package_rows = _npm_package_closure_rows(roots)
    if package_rows is None:
        return None
    entrypoint_row = next(
        (
            row
            for row in package_rows
            if row["path"] == str(entrypoint.resolve(strict=True))
        ),
        None,
    )
    if entrypoint_row is None:
        return None
    closure_rows: list[dict[str, Any]] = [
        _with_role(entrypoint_row, "JS_ENTRYPOINT"),
    ]
    for row in package_rows:
        if row["path"] == entrypoint_row["path"]:
            continue
        role_suffix = hashlib.sha256(
            row["path"].encode("utf-8")
        ).hexdigest()
        closure_rows.append(
            _with_role(row, f"NPM_PACKAGE_FILE:{role_suffix}")
        )
    return (
        [
            _with_role(runtime_row, "NODE_RUNTIME"),
            *closure_rows,
        ],
        "NPM_CMD_WRAPPER",
        roots,
    )


def _compatibility_row(version: str) -> dict[str, Any]:
    raw = _REVIEWED_COMPATIBILITY_ROWS.get(version)
    if raw is None:
        raise ClaudeExecutableObservationError(
            f"Claude Code version {version} has no reviewed compatibility row; "
            "old and unknown-future versions are unsupported"
        )
    core = {
        "compatibility_id": raw["compatibility_id"],
        "claude_code_version": version,
        "supported_capabilities": sorted(raw["supported_capabilities"]),
    }
    return {**core, "compatibility_sha256": _digest(core)}


def _required_capabilities(
    value: Sequence[str],
) -> list[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ClaudeExecutableObservationError(
            "required capabilities must be a string sequence"
        )
    result = list(value)
    if (
        any(
            not isinstance(item, str)
            or _CAPABILITY_RE.fullmatch(item) is None
            for item in result
        )
        or len(result) != len(set(result))
    ):
        raise ClaudeExecutableObservationError(
            "required capabilities are duplicated or malformed"
        )
    return sorted(result)


def _manifest_after_recheck(
    rows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for value in rows:
        role = value.get("role")
        path = value.get("path")
        if not isinstance(role, str) or not isinstance(path, str):
            raise ClaudeExecutableObservationError(
                "implementation manifest is malformed"
            )
        current, _ = _stable_file_bytes(
            Path(path), label=f"Claude implementation file {role}"
        )
        result.append(_with_role(current, role))
    return sorted(result, key=lambda item: (item["role"], item["path"]))


def _npm_manifest_after_recheck(
    rows: Sequence[Mapping[str, Any]],
    roots: Sequence[str],
) -> list[dict[str, Any]]:
    by_role = {str(row.get("role")): row for row in rows}
    wrapper = by_role.get("CONFIGURED_WRAPPER")
    runtime = by_role.get("NODE_RUNTIME")
    entrypoint = by_role.get("JS_ENTRYPOINT")
    if wrapper is None or runtime is None or entrypoint is None:
        raise ClaudeExecutableObservationError(
            "Claude npm implementation manifest lacks its fixed roles"
        )
    fixed: list[dict[str, Any]] = []
    for row, role in (
        (wrapper, "CONFIGURED_WRAPPER"),
        (runtime, "NODE_RUNTIME"),
    ):
        current, _raw = _stable_file_bytes(
            Path(str(row["path"])),
            label=f"Claude implementation file {role}",
        )
        fixed.append(_with_role(current, role))
    closure = _npm_package_closure_rows(roots)
    if closure is None:
        raise ClaudeExecutableObservationError(
            "Claude npm implementation closure became unbound"
        )
    found_entrypoint = False
    for row in closure:
        if row["path"] == entrypoint.get("path"):
            fixed.append(_with_role(row, "JS_ENTRYPOINT"))
            found_entrypoint = True
            continue
        suffix = hashlib.sha256(row["path"].encode("utf-8")).hexdigest()
        fixed.append(_with_role(row, f"NPM_PACKAGE_FILE:{suffix}"))
    if not found_entrypoint:
        raise ClaudeExecutableObservationError(
            "Claude npm entrypoint disappeared from its package closure"
        )
    return sorted(fixed, key=lambda item: (item["role"], item["path"]))


def observe_claude_executable(
    *,
    configured_claude_bin: str,
    environment: Mapping[str, str] | None = None,
    required_capabilities: Sequence[str] = (),
    timeout_seconds: float = DEFAULT_VERSION_PROBE_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Observe exact executable bytes and a reviewed canonical version.

    The function may return a diagnostic observation with
    ``TRANSITIVE_IMPLEMENTATION_UNBOUND``.  Such an observation is
    intentionally rejected by the default replay and prelaunch APIs.
    """

    try:
        timeout_n = float(timeout_seconds)
    except (TypeError, ValueError) as exc:
        raise ClaudeExecutableObservationError(
            "version probe timeout must be positive"
        ) from exc
    if not math.isfinite(timeout_n) or timeout_n <= 0 or timeout_n > 30:
        raise ClaudeExecutableObservationError(
            "version probe timeout must be positive and at most 30 seconds"
        )
    env = _normalize_environment(environment)
    executable = _canonical_unaliased_path(
        configured_claude_bin, label="configured CLAUDE_BIN"
    )
    executable_row, executable_raw = _stable_file_bytes(
        executable, label="configured CLAUDE_BIN"
    )

    native_image = _is_native_image(executable_raw)
    native_metadata: dict[str, str] | None = None
    native_platform_authority: dict[str, Any] | None = None
    implementation_closure_roots: list[str] = []
    if native_image:
        implementation_kind = "NATIVE_EXECUTABLE_IMAGE"
        implementation_status = TRANSITIVE_IMPLEMENTATION_UNBOUND
        implementation_debt: str | None = NATIVE_IMPLEMENTATION_UNBOUND
        files = [_with_role(executable_row, "CONFIGURED_EXECUTABLE")]
        native_metadata = _query_windows_native_metadata(
            executable,
            environment=env,
        )
    else:
        transitive = _npm_cmd_transitive_files(
            wrapper=executable,
            wrapper_raw=executable_raw,
            environment=env,
        )
        if transitive is None:
            implementation_kind = "UNREVIEWED_WRAPPER"
            implementation_status = TRANSITIVE_IMPLEMENTATION_UNBOUND
            implementation_debt = TRANSITIVE_IMPLEMENTATION_UNBOUND
            files = [_with_role(executable_row, "CONFIGURED_WRAPPER")]
        else:
            # A package.json dependency walk is not Node's executable module
            # resolution denominator.  Bare/dynamic imports may resolve an
            # undeclared sibling, an ancestor node_modules directory, or a
            # global lookup root.  Binding only declared packages therefore
            # creates false proof-grade authority.  Retain the exact wrapper
            # as diagnostic evidence, but fail closed until the launcher
            # supplies a reviewed loader policy that closes every lookup root.
            del transitive
            implementation_kind = "NPM_CMD_WRAPPER"
            implementation_status = TRANSITIVE_IMPLEMENTATION_UNBOUND
            implementation_debt = NPM_RESOLUTION_DENOMINATOR_UNBOUND
            implementation_closure_roots = []
            files = [_with_role(executable_row, "CONFIGURED_WRAPPER")]
    files = sorted(files, key=lambda item: (item["role"], item["path"]))

    try:
        result = run_owned_process(
            [str(executable), "--version"],
            env=env,
            timeout=timeout_n,
            encoding="utf-8",
            errors="strict",
            output_limit_bytes=VERSION_PROBE_OUTPUT_LIMIT_BYTES,
        )
    except (
        FileNotFoundError,
        OSError,
        OwnedProcessRunnerError,
        subprocess.TimeoutExpired,
        UnicodeError,
    ) as exc:
        raise ClaudeExecutableObservationError(
            f"owned Claude version probe failed: {type(exc).__name__}"
        ) from exc
    if getattr(result, "process_tree_terminated", None) is not True:
        raise ClaudeExecutableObservationError(
            "owned Claude version probe did not prove its process scope terminated"
        )
    if int(getattr(result, "returncode", -1)) != 0:
        raise ClaudeExecutableObservationError(
            "Claude version probe returned nonzero"
        )
    stdout = getattr(result, "stdout", None)
    stderr = getattr(result, "stderr", None)
    if not isinstance(stdout, str) or not isinstance(stderr, str):
        raise ClaudeExecutableObservationError(
            "Claude version probe output is malformed"
        )
    if stderr != "":
        raise ClaudeExecutableObservationError(
            "Claude version probe emitted stderr"
        )
    if len(stdout.encode("utf-8")) > VERSION_PROBE_OUTPUT_LIMIT_BYTES:
        raise ClaudeExecutableObservationError(
            "Claude version probe output exceeded its bound"
        )
    try:
        version = parse_claude_code_version(stdout)
    except ClaudeHeadlessProfileError as exc:
        raise ClaudeExecutableObservationError(
            "Claude Code version output is not canonical"
        ) from exc
    compatibility = _compatibility_row(version)
    required = _required_capabilities(required_capabilities)
    unsupported = sorted(
        set(required) - set(compatibility["supported_capabilities"])
    )
    if unsupported:
        raise ClaudeExecutableObservationError(
            "reviewed Claude compatibility row lacks required capability: "
            + ", ".join(unsupported)
        )

    if native_image:
        native_platform_authority = _compile_native_platform_authority(
            executable_row=executable_row,
            metadata=native_metadata,
            claude_code_version=version,
        )
        if native_platform_authority is not None:
            implementation_status = DIRECT_IMPLEMENTATION_BOUND
            implementation_debt = None

    # A wrapper, runtime, or entrypoint that changes while --version executes
    # did not produce a byte-bound version observation.
    after_files = (
        _npm_manifest_after_recheck(
            files,
            implementation_closure_roots,
        )
        if implementation_closure_roots
        else _manifest_after_recheck(files)
    )
    if after_files != files:
        raise ClaudeExecutableObservationError(
            "Claude executable implementation changed or drifted during version probe"
        )

    proof_grade = implementation_status in {
        DIRECT_IMPLEMENTATION_BOUND,
        TRANSITIVE_IMPLEMENTATION_BOUND,
    }
    probe_stdout = stdout.encode("utf-8")
    probe_stderr = stderr.encode("utf-8")
    core = {
        "schema": OBSERVATION_SCHEMA,
        "configured_claude_bin": str(executable),
        "resolved_executable": str(executable),
        "claude_code_version": version,
        "compatibility": compatibility,
        "implementation_kind": implementation_kind,
        "implementation_status": implementation_status,
        "implementation_debt": implementation_debt,
        "implementation_files": files,
        "implementation_closure_roots": implementation_closure_roots,
        "native_platform_authority": native_platform_authority,
        "version_probe": {
            "argv": [str(executable), "--version"],
            "returncode": 0,
            "stdout_utf8": stdout,
            "stdout_bytes": len(probe_stdout),
            "stdout_sha256": hashlib.sha256(probe_stdout).hexdigest(),
            "stderr_bytes": len(probe_stderr),
            "stderr_sha256": hashlib.sha256(probe_stderr).hexdigest(),
            "owned_process_scope_closed": True,
        },
        "launch_authority": PROOF_GRADE if proof_grade else NO_PROOF_GRADE_LAUNCH,
    }
    return {**core, "observation_sha256": _digest(core)}


def _backend_launch_prefix(value: Sequence[str], *, installed_front: str) -> list[str]:
    """Replay the non-ambient installed-front Claude launch prefix.

    The generation-relative native member is deliberately absent: the
    authenticated installed front resolves and locks it after revalidating the
    signed selection.  This parser is intentionally exact so an observation
    cannot bless a direct generation-member execution route.
    """

    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ClaudeExecutableObservationError(
            "Claude backend-launch prefix is malformed"
        )
    argv = list(value)
    option_names = (
        "--generation",
        "--receipt-sha256",
        "--census-sha256",
        "--request-sha256",
        "--policy-sha256",
    )
    if (
        len(argv) != 15
        or argv[:4]
        != [installed_front, "backend-launch", "--backend", "claude"]
        or argv[-1] != "--"
        or any(argv[4 + index * 2] != name for index, name in enumerate(option_names))
        or any(
            not isinstance(item, str)
            or not item
            or "\x00" in item
            for item in argv
        )
    ):
        raise ClaudeExecutableObservationError(
            "Claude backend-launch prefix is malformed"
        )
    generation = argv[5]
    if (
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", generation) is None
        or any(_SHA256_RE.fullmatch(argv[index]) is None for index in (7, 9, 11, 13))
    ):
        raise ClaudeExecutableObservationError(
            "Claude backend-launch authority is malformed"
        )
    return argv


def _replay_selected_claude_backend(
    value: Mapping[str, Any], *, expected_version: str,
) -> dict[str, Any]:
    """Preserve the signed native-member seal carried by a Claude row."""

    backend = dict(value) if isinstance(value, Mapping) else {}
    member = backend.get("member_authority")
    authority = member.get("authority") if isinstance(member, dict) else None
    authentication = (
        member.get("authentication") if isinstance(member, dict) else None
    )
    if (
        set(backend) != _SELECTED_BACKEND_KEYS
        or backend.get("execution_kind") != "native"
        or backend.get("relative_path")
        != "node_modules/@anthropic-ai/claude-code/bin/claude.exe"
        or backend.get("version") != expected_version
        or isinstance(backend.get("size"), bool)
        or not isinstance(backend.get("size"), int)
        or backend["size"] < 0
        or not isinstance(backend.get("sha256"), str)
        or _SHA256_RE.fullmatch(backend["sha256"]) is None
        or not isinstance(member, dict)
        or set(member) != {"authority", "authentication"}
        or not isinstance(authority, dict)
        or set(authority) != _MEMBER_AUTHORITY_KEYS
        or not isinstance(authentication, dict)
        or set(authentication) != _MEMBER_AUTHENTICATION_KEYS
        or authority.get("schema") != "plamen.mcp_native_resource_closure.v2"
        or authority.get("execution_kind") != backend["execution_kind"]
        or authority.get("relative_path") != backend["relative_path"]
        or authority.get("size") != backend["size"]
        or authority.get("sha256") != backend["sha256"]
        or type(authority.get("mode")) is not int
        or not 0 <= authority["mode"] <= 0o7777
        or type(authority.get("link_count")) is not int
        or authority["link_count"] != 1
        or authentication.get("scheme") != "ed25519"
        or not isinstance(authentication.get("key_id"), str)
        or _SHA256_RE.fullmatch(authentication["key_id"]) is None
        or not isinstance(authentication.get("signature"), str)
        or re.fullmatch(r"[0-9a-f]{128}", authentication["signature"]) is None
    ):
        raise ClaudeExecutableObservationError(
            "selected Claude backend authority is malformed"
        )
    if any(
        not isinstance(authority.get(field), str)
        or _SHA256_RE.fullmatch(authority[field]) is None
        for field in (
            "receipt_sha256", "census_sha256", "request_sha256",
            "generation_policy_sha256", "receipt_file_sha256", "sha256",
            "closure_sha256",
        )
    ):
        raise ClaudeExecutableObservationError(
            "selected Claude member digest authority is malformed"
        )
    closure = authority.get("closure")
    expected_root = "node_modules/@anthropic-ai/claude-code/bin"
    if (
        authority.get("closure_root") != expected_root
        or not isinstance(closure, list)
        or len(closure) != 2
        or type(authority.get("closure_count")) is not int
        or authority["closure_count"] != len(closure)
        or authority["closure_sha256"]
        != hashlib.sha256(_canonical_json(closure)).hexdigest()
    ):
        raise ClaudeExecutableObservationError(
            "selected Claude member closure authority is malformed"
        )
    expected_paths = {expected_root, backend["relative_path"]}
    paths: list[str] = []
    primary = None
    for row in closure:
        if (
            not isinstance(row, dict)
            or set(row) != _MEMBER_CLOSURE_ROW_KEYS
            or row.get("kind") not in {"file", "directory"}
            or row.get("reparse") is not False
            or not isinstance(row.get("path"), str)
            or type(row.get("size")) is not int
            or row["size"] < 0
            or type(row.get("mode")) is not int
            or not 0 <= row["mode"] <= 0o7777
            or type(row.get("link_count")) is not int
            or row["link_count"] < 1
            or (row["kind"] == "file" and row["link_count"] != 1)
            or not isinstance(row.get("sha256"), str)
            or _SHA256_RE.fullmatch(row["sha256"]) is None
        ):
            raise ClaudeExecutableObservationError(
                "selected Claude member closure row is malformed"
            )
        paths.append(row["path"])
        if row["path"] == backend["relative_path"]:
            primary = row
    if (
        closure != sorted(closure, key=lambda row: (row["path"].casefold(), row["path"]))
        or set(paths) != expected_paths
        or len(paths) != len(set(paths))
        or primary is None
        or primary.get("kind") != "file"
        or any(
            primary[field] != authority[field]
            for field in ("size", "sha256", "mode", "link_count")
        )
    ):
        raise ClaudeExecutableObservationError(
            "selected Claude member closure topology is malformed"
        )
    ancestors = authority.get("ancestors")
    expected_ancestors = [
        ".", "node_modules", "node_modules/@anthropic-ai",
        "node_modules/@anthropic-ai/claude-code",
    ]
    if not isinstance(ancestors, list) or len(ancestors) != len(
        expected_ancestors
    ):
        raise ClaudeExecutableObservationError(
            "selected Claude member ancestor authority is malformed"
        )
    for row, path in zip(ancestors, expected_ancestors):
        if (
            not isinstance(row, dict)
            or set(row) != _MEMBER_ANCESTOR_KEYS
            or row.get("path") != path
            or type(row.get("mode")) is not int
            or not 0 <= row["mode"] <= 0o7777
            or type(row.get("link_count")) is not int
            or row["link_count"] < 1
            or row.get("reparse") is not False
        ):
            raise ClaudeExecutableObservationError(
                "selected Claude member ancestor authority is malformed"
            )
    return backend


def _generation_observation_cache_key(
    *,
    front_row: Mapping[str, Any],
    prefix: Sequence[str],
    selection_sha256: str,
    backend: Mapping[str, Any],
    environment: Mapping[str, str],
    required_capabilities: Sequence[str],
    timeout_seconds: float,
) -> tuple[str, ...]:
    """Bind every input that can affect one cached generation observation."""

    return (
        _digest(dict(front_row)),
        _digest({"argv_prefix": list(prefix)}),
        selection_sha256,
        _digest(dict(backend)),
        _digest({"environment": dict(environment)}),
        _digest({"required_capabilities": list(required_capabilities)}),
        float(timeout_seconds).hex(),
    )


def _observe_claude_generation_backend_uncached(
    *,
    env: Mapping[str, str],
    front: Path,
    front_row: Mapping[str, Any],
    prefix: Sequence[str],
    selection_sha256: str,
    backend: Mapping[str, Any],
    required: Sequence[str],
    timeout_n: float,
) -> dict[str, Any]:
    """Execute and bind one fresh authenticated generation version probe."""

    try:
        result = run_owned_process(
            [*prefix, "--version"],
            env=dict(env),
            timeout=timeout_n,
            encoding="utf-8",
            errors="strict",
            output_limit_bytes=VERSION_PROBE_OUTPUT_LIMIT_BYTES,
        )
    except (
        FileNotFoundError,
        OSError,
        OwnedProcessRunnerError,
        subprocess.TimeoutExpired,
        UnicodeError,
    ) as exc:
        raise ClaudeExecutableObservationError(
            f"owned Claude generation version probe failed: {type(exc).__name__}"
        ) from exc
    if (
        getattr(result, "process_tree_terminated", None) is not True
        or int(getattr(result, "returncode", -1)) != 0
        or not isinstance(getattr(result, "stdout", None), str)
        or getattr(result, "stderr", None) != ""
    ):
        raise ClaudeExecutableObservationError(
            "Claude generation version probe failed closed"
        )
    stdout = result.stdout
    if len(stdout.encode("utf-8")) > VERSION_PROBE_OUTPUT_LIMIT_BYTES:
        raise ClaudeExecutableObservationError(
            "Claude version probe output exceeded its bound"
        )
    try:
        version = parse_claude_code_version(stdout)
    except ClaudeHeadlessProfileError as exc:
        raise ClaudeExecutableObservationError(
            "Claude Code version output is not canonical"
        ) from exc
    if version != backend["version"]:
        raise ClaudeExecutableObservationError(
            "selected Claude backend version differs from authenticated probe"
        )
    compatibility = _compatibility_row(version)
    unsupported = sorted(
        set(required) - set(compatibility["supported_capabilities"])
    )
    if unsupported:
        raise ClaudeExecutableObservationError(
            "reviewed Claude compatibility row lacks required capability: "
            + ", ".join(unsupported)
        )
    after, _after_raw = _stable_file_bytes(
        front, label="installed Plamen front"
    )
    if after != front_row:
        raise ClaudeExecutableObservationError(
            "installed Plamen front changed during version probe"
        )
    files = [_with_role(dict(front_row), "INSTALLED_AUTHENTICATED_FRONT")]
    probe_stdout = stdout.encode("utf-8")
    core = {
        "schema": GENERATION_OBSERVATION_SCHEMA,
        "configured_claude_bin": str(front),
        "resolved_executable": str(front),
        "claude_code_version": version,
        "compatibility": compatibility,
        "implementation_kind": "AUTHENTICATED_GENERATION_BACKEND",
        "implementation_status": DIRECT_IMPLEMENTATION_BOUND,
        "implementation_debt": None,
        "implementation_files": files,
        "implementation_closure_roots": [],
        "native_platform_authority": None,
        "backend_launch_authority": {
            "argv_prefix": list(prefix),
            "selection_sha256": selection_sha256,
            "selected_backend": dict(backend),
        },
        "version_probe": {
            "argv": [*prefix, "--version"],
            "returncode": 0,
            "stdout_utf8": stdout,
            "stdout_bytes": len(probe_stdout),
            "stdout_sha256": hashlib.sha256(probe_stdout).hexdigest(),
            "stderr_bytes": 0,
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "owned_process_scope_closed": True,
        },
        "launch_authority": PROOF_GRADE,
    }
    return {**core, "observation_sha256": _digest(core)}


def observe_claude_generation_backend(
    *,
    installed_front: str,
    backend_argv_prefix: Sequence[str],
    selection_sha256: str,
    selected_backend: Mapping[str, Any],
    environment: Mapping[str, str] | None = None,
    required_capabilities: Sequence[str] = (),
    timeout_seconds: float = GENERATION_VERSION_PROBE_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Observe Claude only through authenticated ``plamen backend-launch``.

    The signed selection binds the immutable generation member's bytes, size,
    version, and relative path.  Consumers bind the installed front and probe
    the selected member through that front; they never resolve or execute the
    generation-relative member themselves.
    """

    try:
        timeout_n = float(timeout_seconds)
    except (TypeError, ValueError) as exc:
        raise ClaudeExecutableObservationError(
            "version probe timeout must be positive"
        ) from exc
    if (
        not math.isfinite(timeout_n)
        or timeout_n <= 0
        or timeout_n > GENERATION_VERSION_PROBE_TIMEOUT_SECONDS
    ):
        raise ClaudeExecutableObservationError(
            "generation version probe timeout must be positive and at most "
            f"{GENERATION_VERSION_PROBE_TIMEOUT_SECONDS:g} seconds"
        )
    env = _normalize_environment(environment)
    front = _canonical_unaliased_path(
        installed_front, label="installed Plamen front"
    )
    front_row, _front_raw = _stable_file_bytes(
        front, label="installed Plamen front"
    )
    prefix = _backend_launch_prefix(
        backend_argv_prefix, installed_front=str(front)
    )
    if not isinstance(selection_sha256, str) or _SHA256_RE.fullmatch(selection_sha256) is None:
        raise ClaudeExecutableObservationError(
            "Claude runtime selection digest is malformed"
        )
    backend = _replay_selected_claude_backend(
        selected_backend, expected_version="2.1.252",
    )
    required = _required_capabilities(required_capabilities)
    cache_key = _generation_observation_cache_key(
        front_row=front_row,
        prefix=prefix,
        selection_sha256=selection_sha256,
        backend=backend,
        environment=env,
        required_capabilities=required,
        timeout_seconds=timeout_n,
    )
    global _GENERATION_OBSERVATION_CACHE
    with _GENERATION_OBSERVATION_CACHE_LOCK:
        # Recheck after potentially waiting for another preparation's probe.
        # A changed/replaced front cannot borrow the earlier authority.
        current_front_row, _current_front_raw = _stable_file_bytes(
            front, label="installed Plamen front"
        )
        if current_front_row != front_row:
            raise ClaudeExecutableObservationError(
                "installed Plamen front changed during observation admission"
            )
        cached = _GENERATION_OBSERVATION_CACHE
        if cached is not None and cached[0] == cache_key:
            try:
                cached_value = json.loads(cached[1].decode("utf-8"))
                replayed = replay_claude_executable_observation(cached_value)
            except (
                ClaudeExecutableObservationError,
                json.JSONDecodeError,
                UnicodeError,
            ):
                _GENERATION_OBSERVATION_CACHE = None
            else:
                expected_files = [
                    _with_role(
                        current_front_row,
                        "INSTALLED_AUTHENTICATED_FRONT",
                    )
                ]
                if replayed["implementation_files"] == expected_files:
                    return replayed
                _GENERATION_OBSERVATION_CACHE = None

        observed = _observe_claude_generation_backend_uncached(
            env=env,
            front=front,
            front_row=current_front_row,
            prefix=prefix,
            selection_sha256=selection_sha256,
            backend=backend,
            required=required,
            timeout_n=timeout_n,
        )
        # Store immutable canonical bytes; callers receive an independent dict
        # and therefore cannot mutate the retained authority.
        _GENERATION_OBSERVATION_CACHE = (
            cache_key,
            _canonical_json(observed),
        )
        return observed


def _validate_file_rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ClaudeExecutableObservationError(
            "implementation file manifest is malformed"
        )
    rows: list[dict[str, Any]] = []
    expected_fields = {
        "role",
        "path",
        "sha256",
        "size",
        "device",
        "inode",
        "mode",
        "link_count",
    }
    for raw in value:
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise ClaudeExecutableObservationError(
                "implementation file row denominator drifted"
            )
        if (
            not isinstance(raw["role"], str)
            or not raw["role"]
            or not isinstance(raw["path"], str)
            or not Path(raw["path"]).is_absolute()
            or not isinstance(raw["sha256"], str)
            or _SHA256_RE.fullmatch(raw["sha256"]) is None
            or isinstance(raw["size"], bool)
            or not isinstance(raw["size"], int)
            or raw["size"] < 0
            or raw["size"] > MAX_IMPLEMENTATION_FILE_BYTES
            or any(
                isinstance(raw[name], bool) or not isinstance(raw[name], int)
                for name in ("device", "inode", "mode", "link_count")
            )
            or raw["link_count"] != 1
        ):
            raise ClaudeExecutableObservationError(
                "implementation file row is malformed"
            )
        rows.append(dict(raw))
    ordered = sorted(rows, key=lambda item: (item["role"], item["path"]))
    if ordered != rows or len({row["path"] for row in rows}) != len(rows):
        raise ClaudeExecutableObservationError(
            "implementation file manifest is duplicated or noncanonical"
        )
    return rows


def _replay_generation_backend_observation(
    clone: dict[str, Any],
    *,
    require_proof_grade: bool,
) -> dict[str, Any]:
    expected_fields = {
        "schema",
        "configured_claude_bin",
        "resolved_executable",
        "claude_code_version",
        "compatibility",
        "implementation_kind",
        "implementation_status",
        "implementation_debt",
        "implementation_files",
        "implementation_closure_roots",
        "native_platform_authority",
        "backend_launch_authority",
        "version_probe",
        "launch_authority",
        "observation_sha256",
    }
    if set(clone) != expected_fields:
        raise ClaudeExecutableObservationError(
            "generation backend observation field denominator drifted"
        )
    digest = clone.pop("observation_sha256")
    if (
        clone.get("schema") != GENERATION_OBSERVATION_SCHEMA
        or not isinstance(digest, str)
        or _SHA256_RE.fullmatch(digest) is None
        or digest != _digest(clone)
    ):
        raise ClaudeExecutableObservationError(
            "generation backend observation schema or digest drifted"
        )
    configured = clone.get("configured_claude_bin")
    resolved = clone.get("resolved_executable")
    if (
        not isinstance(configured, str)
        or configured != resolved
        or not Path(configured).is_absolute()
    ):
        raise ClaudeExecutableObservationError(
            "installed generation front authority drifted"
        )
    version = clone.get("claude_code_version")
    compatibility = _compatibility_row(version)
    if clone.get("compatibility") != compatibility:
        raise ClaudeExecutableObservationError(
            "reviewed generation compatibility authority drifted"
        )
    rows = _validate_file_rows(clone.get("implementation_files"))
    if (
        len(rows) != 1
        or rows[0]["role"] != "INSTALLED_AUTHENTICATED_FRONT"
        or rows[0]["path"] != resolved
        or clone.get("implementation_kind")
        != "AUTHENTICATED_GENERATION_BACKEND"
        or clone.get("implementation_status") != DIRECT_IMPLEMENTATION_BOUND
        or clone.get("implementation_debt") is not None
        or clone.get("implementation_closure_roots") != []
        or clone.get("native_platform_authority") is not None
        or clone.get("launch_authority") != PROOF_GRADE
    ):
        raise ClaudeExecutableObservationError(
            "generation backend implementation authority drifted"
        )
    authority = clone.get("backend_launch_authority")
    if not isinstance(authority, dict) or set(authority) != {
        "argv_prefix",
        "selection_sha256",
        "selected_backend",
    }:
        raise ClaudeExecutableObservationError(
            "generation backend launch authority drifted"
        )
    prefix = _backend_launch_prefix(
        authority.get("argv_prefix"), installed_front=resolved
    )
    selection_digest = authority.get("selection_sha256")
    if (
        not isinstance(selection_digest, str)
        or _SHA256_RE.fullmatch(selection_digest) is None
    ):
        raise ClaudeExecutableObservationError(
            "selected generation backend authority drifted"
        )
    try:
        backend = _replay_selected_claude_backend(
            authority.get("selected_backend"), expected_version=version,
        )
    except ClaudeExecutableObservationError as exc:
        raise ClaudeExecutableObservationError(
            "selected generation backend authority drifted"
        ) from exc
    probe = clone.get("version_probe")
    if (
        not isinstance(probe, dict)
        or set(probe)
        != {
            "argv",
            "returncode",
            "stdout_utf8",
            "stdout_bytes",
            "stdout_sha256",
            "stderr_bytes",
            "stderr_sha256",
            "owned_process_scope_closed",
        }
        or probe.get("argv") != [*prefix, "--version"]
        or probe.get("returncode") != 0
        or not isinstance(probe.get("stdout_utf8"), str)
        or isinstance(probe.get("stdout_bytes"), bool)
        or not isinstance(probe.get("stdout_bytes"), int)
        or not 0 < probe["stdout_bytes"] <= VERSION_PROBE_OUTPUT_LIMIT_BYTES
        or probe.get("stderr_bytes") != 0
        or probe.get("stderr_sha256") != hashlib.sha256(b"").hexdigest()
        or probe.get("owned_process_scope_closed") is not True
    ):
        raise ClaudeExecutableObservationError(
            "generation backend version probe receipt drifted"
        )
    stdout_raw = probe["stdout_utf8"].encode("utf-8")
    try:
        probe_version = parse_claude_code_version(probe["stdout_utf8"])
    except ClaudeHeadlessProfileError as exc:
        raise ClaudeExecutableObservationError(
            "generation backend version probe stdout is malformed"
        ) from exc
    if (
        probe_version != version
        or probe["stdout_bytes"] != len(stdout_raw)
        or probe.get("stdout_sha256") != hashlib.sha256(stdout_raw).hexdigest()
    ):
        raise ClaudeExecutableObservationError(
            "generation backend version probe does not bind selected version"
        )
    if require_proof_grade and clone["launch_authority"] != PROOF_GRADE:
        raise ClaudeExecutableObservationError(
            "generation backend observation is not proof-grade"
        )
    clone["backend_launch_authority"] = {
        "argv_prefix": prefix,
        "selection_sha256": selection_digest,
        "selected_backend": dict(backend),
    }
    return {**clone, "observation_sha256": digest}


def replay_claude_executable_observation(
    value: Mapping[str, Any],
    *,
    require_proof_grade: bool = True,
) -> dict[str, Any]:
    """Replay structure, digest, compatibility row, and launch authority."""

    if not isinstance(value, Mapping):
        raise ClaudeExecutableObservationError("observation must be an object")
    try:
        clone = json.loads(_canonical_json(dict(value)).decode("utf-8"))
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ClaudeExecutableObservationError("observation JSON is invalid") from exc
    if clone.get("schema") == GENERATION_OBSERVATION_SCHEMA:
        return _replay_generation_backend_observation(
            clone, require_proof_grade=require_proof_grade
        )
    expected_fields = {
        "schema",
        "configured_claude_bin",
        "resolved_executable",
        "claude_code_version",
        "compatibility",
        "implementation_kind",
        "implementation_status",
        "implementation_debt",
        "implementation_files",
        "implementation_closure_roots",
        "native_platform_authority",
        "version_probe",
        "launch_authority",
        "observation_sha256",
    }
    if not isinstance(clone, dict) or set(clone) != expected_fields:
        raise ClaudeExecutableObservationError(
            "observation field denominator drifted"
        )
    digest = clone.pop("observation_sha256")
    if (
        clone.get("schema") != OBSERVATION_SCHEMA
        or not isinstance(digest, str)
        or _SHA256_RE.fullmatch(digest) is None
        or digest != _digest(clone)
    ):
        raise ClaudeExecutableObservationError(
            "observation schema or digest drifted"
        )
    configured = clone.get("configured_claude_bin")
    resolved = clone.get("resolved_executable")
    if (
        not isinstance(configured, str)
        or not isinstance(resolved, str)
        or configured != resolved
        or not Path(configured).is_absolute()
    ):
        raise ClaudeExecutableObservationError(
            "configured and resolved executable authority drifted"
        )
    version = clone.get("claude_code_version")
    if not isinstance(version, str):
        raise ClaudeExecutableObservationError(
            "observed Claude Code version is malformed"
        )
    compatibility = _compatibility_row(version)
    if clone.get("compatibility") != compatibility:
        raise ClaudeExecutableObservationError(
            "reviewed compatibility authority drifted"
        )
    rows = _validate_file_rows(clone.get("implementation_files"))
    closure_roots = clone.get("implementation_closure_roots")
    if (
        not isinstance(closure_roots, list)
        or any(
            not isinstance(root, str) or not Path(root).is_absolute()
            for root in closure_roots
        )
        or closure_roots != sorted(set(closure_roots))
    ):
        raise ClaudeExecutableObservationError(
            "implementation closure root denominator drifted"
        )
    status = clone.get("implementation_status")
    kind = clone.get("implementation_kind")
    debt = clone.get("implementation_debt")
    authority = clone.get("launch_authority")
    roles = {row["role"] for row in rows}
    for row in rows:
        role = row["role"]
        if role.startswith("NPM_PACKAGE_FILE:"):
            expected_role = "NPM_PACKAGE_FILE:" + hashlib.sha256(
                row["path"].encode("utf-8")
            ).hexdigest()
            if role != expected_role:
                raise ClaudeExecutableObservationError(
                    "npm package closure role/path binding drifted"
                )
    native_authority: dict[str, Any] | None = None
    if status == DIRECT_IMPLEMENTATION_BOUND:
        try:
            native_authority = replay_claude_native_platform_authority(
                clone.get("native_platform_authority"),
                executable_row=rows[0],
                claude_code_version=version,
            )
        except ClaudeExecutableObservationError:
            native_authority = None
        valid = (
            kind == "NATIVE_EXECUTABLE_IMAGE"
            and debt is None
            and authority == PROOF_GRADE
            and roles == {"CONFIGURED_EXECUTABLE"}
            and len(rows) == 1
            and native_authority is not None
            and not closure_roots
        )
    elif status == TRANSITIVE_IMPLEMENTATION_BOUND:
        package_roles = {
            role for role in roles if role.startswith("NPM_PACKAGE_FILE:")
        }
        valid = (
            kind == "NPM_CMD_WRAPPER"
            and debt is None
            and authority == PROOF_GRADE
            and clone.get("native_platform_authority") is None
            and {
                "CONFIGURED_WRAPPER",
                "JS_ENTRYPOINT",
                "NODE_RUNTIME",
            }.issubset(roles)
            and roles
            == {
                "CONFIGURED_WRAPPER",
                "JS_ENTRYPOINT",
                "NODE_RUNTIME",
                *package_roles,
            }
            and bool(package_roles)
            and bool(closure_roots)
        )
    elif status == TRANSITIVE_IMPLEMENTATION_UNBOUND:
        valid = (
            kind in {"UNREVIEWED_WRAPPER", "NPM_CMD_WRAPPER"}
            and debt
            in {
                TRANSITIVE_IMPLEMENTATION_UNBOUND,
                NPM_RESOLUTION_DENOMINATOR_UNBOUND,
            }
            and authority == NO_PROOF_GRADE_LAUNCH
            and clone.get("native_platform_authority") is None
            and roles == {"CONFIGURED_WRAPPER"}
            and len(rows) == 1
            and not closure_roots
        )
        if (
            kind == "NATIVE_EXECUTABLE_IMAGE"
            and debt == NATIVE_IMPLEMENTATION_UNBOUND
            and authority == NO_PROOF_GRADE_LAUNCH
            and clone.get("native_platform_authority") is None
            and roles == {"CONFIGURED_EXECUTABLE"}
            and len(rows) == 1
            and not closure_roots
        ):
            valid = True
    else:
        valid = False
    if not valid:
        raise ClaudeExecutableObservationError(
            "implementation binding or launch authority drifted"
        )
    if rows[0 if len(rows) == 1 else next(
        index
        for index, row in enumerate(rows)
        if row["role"] in {"CONFIGURED_EXECUTABLE", "CONFIGURED_WRAPPER"}
    )]["path"] != resolved:
        raise ClaudeExecutableObservationError(
            "configured executable is absent from implementation manifest"
        )
    probe = clone.get("version_probe")
    if (
        not isinstance(probe, dict)
        or set(probe)
        != {
            "argv",
            "returncode",
            "stdout_utf8",
            "stdout_bytes",
            "stdout_sha256",
            "stderr_bytes",
            "stderr_sha256",
            "owned_process_scope_closed",
        }
        or probe.get("argv") != [resolved, "--version"]
        or probe.get("returncode") != 0
        or not isinstance(probe.get("stdout_utf8"), str)
        or probe.get("stderr_bytes") != 0
        or probe.get("stderr_sha256") != hashlib.sha256(b"").hexdigest()
        or probe.get("owned_process_scope_closed") is not True
        or isinstance(probe.get("stdout_bytes"), bool)
        or not isinstance(probe.get("stdout_bytes"), int)
        or not 0 < probe["stdout_bytes"] <= VERSION_PROBE_OUTPUT_LIMIT_BYTES
        or not isinstance(probe.get("stdout_sha256"), str)
        or _SHA256_RE.fullmatch(probe["stdout_sha256"]) is None
    ):
        raise ClaudeExecutableObservationError(
            "version probe receipt drifted"
        )
    probe_stdout = probe["stdout_utf8"].encode("utf-8")
    try:
        probe_version = parse_claude_code_version(probe["stdout_utf8"])
    except ClaudeHeadlessProfileError as exc:
        raise ClaudeExecutableObservationError(
            "version probe receipt contains noncanonical stdout"
        ) from exc
    if (
        probe_version != version
        or probe["stdout_bytes"] != len(probe_stdout)
        or probe["stdout_sha256"] != hashlib.sha256(probe_stdout).hexdigest()
    ):
        raise ClaudeExecutableObservationError(
            "version probe stdout does not bind the observed version"
        )
    if require_proof_grade and authority != PROOF_GRADE:
        raise ClaudeExecutableObservationError(
            f"{TRANSITIVE_IMPLEMENTATION_UNBOUND}: observation cannot authorize "
            "a proof-grade launch"
        )
    clone["native_platform_authority"] = native_authority
    return {**clone, "observation_sha256": digest}


def compile_claude_executable_observation_reference(
    value: Mapping[str, Any],
    *,
    required_capabilities: Sequence[str],
) -> dict[str, Any]:
    """Compile a portable reference to one proof-grade observation.

    The full observation remains the prelaunch request authority.  Durable
    semantic policies may carry this smaller reference and later exact-match
    its digest against that request without duplicating host file metadata.
    """

    observation = replay_claude_executable_observation(value)
    required = _required_capabilities(required_capabilities)
    supported = set(
        observation["compatibility"]["supported_capabilities"]
    ) | set(
        _REVIEWED_TYPED_PROFILE_CAPABILITIES_BY_VERSION.get(
            observation["claude_code_version"],
            (),
        )
    )
    missing = sorted(set(required) - supported)
    if missing:
        raise ClaudeExecutableObservationError(
            "reviewed Claude compatibility row lacks required capability: "
            + ", ".join(missing)
        )
    core = {
        "schema": OBSERVATION_REFERENCE_SCHEMA,
        "observation_sha256": observation["observation_sha256"],
        "claude_code_version": observation["claude_code_version"],
        "compatibility_sha256": observation["compatibility"][
            "compatibility_sha256"
        ],
        "required_capabilities": required,
        "launch_authority": PROOF_GRADE,
    }
    return {**core, "reference_sha256": _digest(core)}


def replay_claude_executable_observation_reference(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay a typed executable/version/capability observation reference."""

    if not isinstance(value, Mapping):
        raise ClaudeExecutableObservationError(
            "Claude executable observation reference must be an object"
        )
    clone = dict(value)
    if set(clone) != {
        "schema",
        "observation_sha256",
        "claude_code_version",
        "compatibility_sha256",
        "required_capabilities",
        "launch_authority",
        "reference_sha256",
    }:
        raise ClaudeExecutableObservationError(
            "Claude executable observation reference fields drifted"
        )
    digest = clone.pop("reference_sha256")
    version = clone.get("claude_code_version")
    try:
        compatibility = _compatibility_row(version)
        required = _required_capabilities(
            clone.get("required_capabilities")
        )
    except (ClaudeExecutableObservationError, TypeError) as exc:
        raise ClaudeExecutableObservationError(
            f"Claude executable observation reference does not replay: {exc}"
        ) from exc
    supported = set(compatibility["supported_capabilities"]) | set(
        _REVIEWED_TYPED_PROFILE_CAPABILITIES_BY_VERSION.get(
            version,
            (),
        )
    )
    if (
        clone.get("schema") != OBSERVATION_REFERENCE_SCHEMA
        or not isinstance(clone.get("observation_sha256"), str)
        or _SHA256_RE.fullmatch(clone["observation_sha256"]) is None
        or clone.get("compatibility_sha256")
        != compatibility["compatibility_sha256"]
        or clone.get("required_capabilities") != required
        or any(
            capability not in supported
            for capability in required
        )
        or clone.get("launch_authority") != PROOF_GRADE
        or not isinstance(digest, str)
        or _SHA256_RE.fullmatch(digest) is None
        or digest != _digest(clone)
    ):
        raise ClaudeExecutableObservationError(
            "Claude executable observation reference capability or digest "
            "authority drifted"
        )
    return {**clone, "reference_sha256": digest}


def recheck_claude_executable_before_launch(
    value: Mapping[str, Any],
    *,
    launch_executable: str,
) -> dict[str, Any]:
    """Replay launch authority and recheck every implementation byte."""

    observation = replay_claude_executable_observation(value)
    executable = _canonical_unaliased_path(
        launch_executable, label="launch executable"
    )
    if str(executable) != observation["resolved_executable"]:
        raise ClaudeExecutableObservationError(
            "launch executable differs from the observed configured CLAUDE_BIN"
        )
    current = (
        _npm_manifest_after_recheck(
            observation["implementation_files"],
            observation["implementation_closure_roots"],
        )
        if observation["implementation_closure_roots"]
        else _manifest_after_recheck(observation["implementation_files"])
    )
    if current != observation["implementation_files"]:
        raise ClaudeExecutableObservationError(
            "Claude executable implementation changed or drifted before launch"
        )
    return observation


__all__ = [
    "ClaudeExecutableObservationError",
    "DEFAULT_VERSION_PROBE_TIMEOUT_SECONDS",
    "GENERATION_VERSION_PROBE_TIMEOUT_SECONDS",
    "DIRECT_IMPLEMENTATION_BOUND",
    "GENERATION_OBSERVATION_SCHEMA",
    "NATIVE_IMPLEMENTATION_UNBOUND",
    "NATIVE_PLATFORM_AUTHORITY_SCHEMA",
    "NPM_RESOLUTION_DENOMINATOR_UNBOUND",
    "NO_PROOF_GRADE_LAUNCH",
    "OBSERVATION_SCHEMA",
    "OBSERVATION_REFERENCE_SCHEMA",
    "PROOF_GRADE",
    "TRANSITIVE_IMPLEMENTATION_BOUND",
    "TRANSITIVE_IMPLEMENTATION_UNBOUND",
    "VERSION_PROBE_OUTPUT_LIMIT_BYTES",
    "compile_claude_executable_observation_reference",
    "observe_claude_executable",
    "observe_claude_generation_backend",
    "recheck_claude_executable_before_launch",
    "replay_claude_native_platform_authority",
    "replay_claude_executable_observation",
    "replay_claude_executable_observation_reference",
]
