"""Pinned, ambient-independent Node and Yarn Classic identity authority.

This module is deliberately an identity and launch-policy layer, not a
downloader, extractor, installer, or process runner.  Production callers must
load the checked-in manifest, verify packaged archive bytes, materialize those
archives through a separately authenticated mechanism, and enforce the
returned network requirement outside the target process.

No API consults PATH, Corepack, a project ``yarnPath``, user configuration, or
the caller's environment.  The checked-in policy is authenticated by a
compiled content digest.  The independently generated runtime closure binds
this module, that policy, and every archive; its observed digest is returned
to callers for receipts.  Neither this module nor the policy embeds that
closure digest, so regenerating the closure has no self-reference.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
import platform
import re
import stat
from types import MappingProxyType
from typing import Any, Mapping, Sequence


SCHEMA = "plamen.js-toolchain-authority.v1"
BOOTSTRAP_SCHEMA = "plamen.js-toolchain-bootstrap.v1"
BOOTSTRAP_PROVENANCE_SCHEMA = (
    "plamen.js-bootstrap-install-provenance.v1"
)
BOOTSTRAP_TRUST_BOUNDARY = (
    "AUTHENTICATED_INSTALLER_LAUNCHER_BOUNDARY_V1"
)
BOOTSTRAP_TRUST_ASSUMPTION = (
    "EXTERNAL_AUTHENTICATED_DISTRIBUTION_AND_INSTALL_PROVENANCE_V1"
)
BOOTSTRAP_RELATIVE_PATH = Path(
    "verification_policy/js_toolchain_bootstrap.v1.json"
)
MANIFEST_RELATIVE_PATH = Path(
    "verification_policy/js_toolchain_authority.v1.json"
)
RUNTIME_CLOSURE_RELATIVE_PATH = Path(
    "verification_policy/toolchain_runtime_closure.v1.json"
)
RUNTIME_CLOSURE_SCHEMA = "plamen.toolchain-runtime-closure.v1"
# Keep this in lockstep with toolchain_control_authority's bounded source
# member limit. The V3 orchestrator is slightly larger than 4 MiB, while every
# member remains individually hashed and the closure keeps a fixed file cap.
MAX_RUNTIME_SOURCE_BYTES = 8 * 1024 * 1024
MANIFEST_AUTHENTICATION_SCHEME = (
    "COMPILED_CONTENT_SHA256_PLUS_OBSERVED_RUNTIME_CLOSURE_V1"
)
EXTRACTION_POLICY_SCHEMA = "plamen.js-toolchain-extraction-policy.v1"
EXTRACTION_RECEIPT_SCHEMA = "plamen.js-toolchain-extraction-receipt.v1"
EXTRACTION_RECEIPT_PARSER_ID = (
    "PLAMEN_JS_TOOLCHAIN_EXTRACTION_RECEIPT_PARSER_V1"
)
EXTRACTION_RECEIPT_PARSER_PATH = "scripts/js_toolchain_authority.py"

PLAMEN_RUNTIME_ASSETS = (
    {
        "kind": "control",
        "mode": "file",
        "path": "verification_policy/js_toolchain_bootstrap.v1.json",
    },
    {
        "kind": "control",
        "mode": "file",
        "path": "verification_policy/js_toolchain_authority.v1.json",
    },
    {
        "kind": "control",
        "mode": "file",
        "path": "verification_policy/js_toolchain_acquisition.v1.json",
    },
    {
        "kind": "runtime-data",
        "mode": "acquired-file",
        "path": (
            "runtime/toolchains/js/node/"
            "node-v24.20.0-win-x64.zip"
        ),
    },
    {
        "kind": "runtime-data",
        "mode": "acquired-file",
        "path": (
            "runtime/toolchains/js/node/"
            "node-v24.20.0-win-arm64.zip"
        ),
    },
    {
        "kind": "runtime-data",
        "mode": "acquired-file",
        "path": (
            "runtime/toolchains/js/node/"
            "node-v24.20.0-linux-x64.tar.xz"
        ),
    },
    {
        "kind": "runtime-data",
        "mode": "acquired-file",
        "path": (
            "runtime/toolchains/js/node/"
            "node-v24.20.0-linux-arm64.tar.xz"
        ),
    },
    {
        "kind": "runtime-data",
        "mode": "acquired-file",
        "path": (
            "runtime/toolchains/js/node/"
            "node-v24.20.0-darwin-x64.tar.gz"
        ),
    },
    {
        "kind": "runtime-data",
        "mode": "acquired-file",
        "path": (
            "runtime/toolchains/js/node/"
            "node-v24.20.0-darwin-arm64.tar.gz"
        ),
    },
    {
        "kind": "runtime-data",
        "mode": "acquired-file",
        "path": "runtime/toolchains/js/yarn/yarn-v1.22.22.tar.gz",
    },
)

NODE_VERSION = "24.20.0"
YARN_VERSION = "1.22.22"
YARN_ARCHIVE_SHA256 = (
    "88268464199d1611fcf73ce9c0a6c4d44c7d5363682720d8506f6508addf36a0"
)
YARN_ARCHIVE_SIZE = 1_247_457
MAX_LOCK_EGRESS_ORIGINS = 128
EXPECTED_MANIFEST_CONTENT_SHA256 = (
    "c530d09dc7cd295ae3339f9db585bf051ebe847ee7677e4ea191b2599df9506b"
)

FIXED_YARN_INSTALL_FLAGS = (
    "--no-default-rc",
    "--ignore-path",
    "--frozen-lockfile",
    "--ignore-scripts",
    "--production=false",
    "--no-bin-links",
    "--non-interactive",
)

_MAX_MANIFEST_BYTES = 256 * 1024
_READ_CHUNK = 1024 * 1024
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
_ARTIFACT_KEYS = frozenset(
    {
        "archive_format",
        "archive_root",
        "artifact_id",
        "executable",
        "extraction_policy",
        "filename",
        "identity_state",
        "kind",
        "os",
        "arch",
        "packaged_path",
        "sha256",
        "size",
        "source_url",
        "upstream_authentication",
        "version",
    }
)
_BOOTSTRAP_MEMBER_KEYS = frozenset(
    {"digest_mode", "kind", "path", "sha256", "size"}
)
_BOOTSTRAP_MODULE_PATHS = (
    "scripts/js_dependency_materializer_authority.py",
    "scripts/js_dependency_materializer_runtime.py",
    "scripts/js_lock_authority.py",
    "scripts/js_toolchain_authority.py",
)
_EXTRACTION_POLICY_KEYS = frozenset(
    {
        "allowed_member_types",
        "directory_count",
        "max_expanded_regular_file_bytes",
        "max_members",
        "max_path_utf8_bytes",
        "max_single_regular_file_bytes",
        "parser_id",
        "parser_path",
        "path_policy",
        "regular_file_count",
        "reviewed_skipped_symlinks_sha256",
        "schema",
        "skipped_symlink_count",
        "symlink_policy",
        "type_policy",
    }
)
_EXPECTED_UPSTREAM_VERIFICATION = {
    "node": {
        "plaintext_manifest": {
            "sha256": "ccf01a92bf3036a46551f02037b1d2347c5c52435642a951a3c9bec4f93c8272",
            "size": 3172,
            "source_url": "https://nodejs.org/dist/v24.20.0/SHASUMS256.txt",
        },
        "public_key": {
            "sha256": "5115095e2f8010c75da052ecb1cfb3af630e084f0f8daa93a863557b01b0f90a",
            "size": 924,
            "source_commit": "7b6eb2d6ab524bb30487f31612cdbeb35ae37533",
            "source_url": (
                "https://raw.githubusercontent.com/nodejs/release-keys/"
                "7b6eb2d6ab524bb30487f31612cdbeb35ae37533/keys/"
                "5BE8A3F6C8A5C01D106C0AD820B1A390B168D356.asc"
            ),
        },
        "signed_manifest": {
            "sha256": "8cc4c2dc94d07c7bfd4898ff1ca641d09e65e465becb50baecb4578ed93d95dc",
            "size": 3449,
            "source_url": "https://nodejs.org/dist/v24.20.0/SHASUMS256.txt.asc",
        },
        "signer_fingerprint": "5BE8A3F6C8A5C01D106C0AD820B1A390B168D356",
        "verification_kind": "OPENPGP_CLEARSIGNED_SHA256_MANIFEST",
        "verification_result": "SIGNATURE_VALID_AND_ALL_SIX_DIGESTS_MATCH",
    },
    "yarn": {
        "archive": {
            "sha256": YARN_ARCHIVE_SHA256,
            "size": YARN_ARCHIVE_SIZE,
            "source_url": (
                "https://github.com/yarnpkg/yarn/releases/download/"
                "v1.22.22/yarn-v1.22.22.tar.gz"
            ),
        },
        "detached_signature": {
            "sha256": "ce5a2cc19283cee2a4f931cc50769dcf695afb0dd40657d374f50f573bcb6cac",
            "size": 847,
            "source_url": (
                "https://github.com/yarnpkg/yarn/releases/download/"
                "v1.22.22/yarn-v1.22.22.tar.gz.asc"
            ),
        },
        "public_key": {
            "sha256": "63edc60568db873b70db03a3c4dd062a16c6b3d6e3015eb748edc234e6a4facd",
            "size": 23138,
            "source_commit": "8e1ecd1ab460f82245316a4cdd888aaad6e041a5",
            "source_url": (
                "https://raw.githubusercontent.com/yarnpkg/releases/"
                "8e1ecd1ab460f82245316a4cdd888aaad6e041a5/debian/pubkey.gpg"
            ),
        },
        "signer_fingerprint": "72ECF46A56B4AD39C907BBB71646B01B86E50310",
        "verification_kind": "OPENPGP_DETACHED_SIGNATURE",
        "verification_result": "SIGNATURE_VALID_AND_ARCHIVE_DIGEST_MATCHES",
    },
}

_EXPECTED_NODE_ARTIFACTS: Mapping[str, Mapping[str, str | int]] = {
    "node-windows-x86_64": {
        "os": "windows",
        "arch": "x86_64",
        "filename": "node-v24.20.0-win-x64.zip",
        "archive_format": "zip",
        "archive_root": "node-v24.20.0-win-x64",
        "executable": "node.exe",
        "sha256": "6cac9ffbca8f6a47091e4b5c772e0606049c3871cb67d900c0cedde630e545ba",
        "size": 37_539_751,
    },
    "node-windows-arm64": {
        "os": "windows",
        "arch": "arm64",
        "filename": "node-v24.20.0-win-arm64.zip",
        "archive_format": "zip",
        "archive_root": "node-v24.20.0-win-arm64",
        "executable": "node.exe",
        "sha256": "31c6799744de8a54601643098040c68c3697e56c94e407d61d0e5fa5f34191d7",
        "size": 33_621_271,
    },
    "node-linux-x86_64": {
        "os": "linux",
        "arch": "x86_64",
        "filename": "node-v24.20.0-linux-x64.tar.xz",
        "archive_format": "tar.xz",
        "archive_root": "node-v24.20.0-linux-x64",
        "executable": "bin/node",
        "sha256": "2f2c0da162318f0de47665410c7c8c2ed3d36c8f3105de4bbc61176c70a7cbf2",
        "size": 31_838_904,
    },
    "node-linux-arm64": {
        "os": "linux",
        "arch": "arm64",
        "filename": "node-v24.20.0-linux-arm64.tar.xz",
        "archive_format": "tar.xz",
        "archive_root": "node-v24.20.0-linux-arm64",
        "executable": "bin/node",
        "sha256": "5f4ddab610c1ab2016b3c227cebdbf6d9495161487e4739c7b90090595f465f7",
        "size": 30_778_928,
    },
    "node-darwin-x86_64": {
        "os": "darwin",
        "arch": "x86_64",
        "filename": "node-v24.20.0-darwin-x64.tar.gz",
        "archive_format": "tar.gz",
        "archive_root": "node-v24.20.0-darwin-x64",
        "executable": "bin/node",
        "sha256": "9e5b2644cf107befb6aefca676b96d3296bc10138096f022ed378d6233ed81f4",
        "size": 54_021_618,
    },
    "node-darwin-arm64": {
        "os": "darwin",
        "arch": "arm64",
        "filename": "node-v24.20.0-darwin-arm64.tar.gz",
        "archive_format": "tar.gz",
        "archive_root": "node-v24.20.0-darwin-arm64",
        "executable": "bin/node",
        "sha256": "40e5607e5ecb3db9192723776da2d75d966260fc74a7a9e731c1bd67dda96bc8",
        "size": 52_813_331,
    },
}

_EMPTY_REVIEWED_SYMLINKS_SHA256 = (
    "37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570"
)
_EXPECTED_EXTRACTION_CENSUS: Mapping[str, Mapping[str, int | str]] = {
    "node-windows-x86_64": {
        "max_members": 2_459,
        "regular_file_count": 1_994,
        "directory_count": 465,
        "skipped_symlink_count": 0,
        "max_expanded_regular_file_bytes": 106_774_079,
        "max_single_regular_file_bytes": 93_381_448,
        "max_path_utf8_bytes": 125,
        "reviewed_skipped_symlinks_sha256": _EMPTY_REVIEWED_SYMLINKS_SHA256,
    },
    "node-windows-arm64": {
        "max_members": 2_459,
        "regular_file_count": 1_994,
        "directory_count": 465,
        "skipped_symlink_count": 0,
        "max_expanded_regular_file_bytes": 95_119_935,
        "max_single_regular_file_bytes": 81_727_304,
        "max_path_utf8_bytes": 127,
        "reviewed_skipped_symlinks_sha256": _EMPTY_REVIEWED_SYMLINKS_SHA256,
    },
    "node-linux-x86_64": {
        "max_members": 5_888,
        "regular_file_count": 4_797,
        "directory_count": 1_088,
        "skipped_symlink_count": 3,
        "max_expanded_regular_file_bytes": 201_155_641,
        "max_single_regular_file_bytes": 126_458_664,
        "max_path_utf8_bytes": 131,
        "reviewed_skipped_symlinks_sha256": (
            "471c5ae9a51bf91e77fd827b2aa730c68b303d38c2c98aa11018b1bda60c0312"
        ),
    },
    "node-linux-arm64": {
        "max_members": 5_888,
        "regular_file_count": 4_797,
        "directory_count": 1_088,
        "skipped_symlink_count": 3,
        "max_expanded_regular_file_bytes": 197_375_869,
        "max_single_regular_file_bytes": 122_678_944,
        "max_path_utf8_bytes": 133,
        "reviewed_skipped_symlinks_sha256": (
            "a1b77d84312fbd7c48841960bb928fc2e4ade0c7865023a9d02669b5a7895cae"
        ),
    },
    "node-darwin-x86_64": {
        "max_members": 5_888,
        "regular_file_count": 4_797,
        "directory_count": 1_088,
        "skipped_symlink_count": 3,
        "max_expanded_regular_file_bytes": 198_982_730,
        "max_single_regular_file_bytes": 124_285_824,
        "max_path_utf8_bytes": 132,
        "reviewed_skipped_symlinks_sha256": (
            "41d6c293f2e6852a43fa8db115fd6abd6bc9b42e6976169dc1e085c3ce24de90"
        ),
    },
    "node-darwin-arm64": {
        "max_members": 5_888,
        "regular_file_count": 4_797,
        "directory_count": 1_088,
        "skipped_symlink_count": 3,
        "max_expanded_regular_file_bytes": 196_608_637,
        "max_single_regular_file_bytes": 121_911_744,
        "max_path_utf8_bytes": 134,
        "reviewed_skipped_symlinks_sha256": (
            "f87f376290035dec3e2bb4ceeb9516b77b20d8233119ee12908ee2dcb73092ff"
        ),
    },
    "yarn-classic-noarch": {
        "max_members": 13,
        "regular_file_count": 11,
        "directory_count": 2,
        "skipped_symlink_count": 0,
        "max_expanded_regular_file_bytes": 5_340_487,
        "max_single_regular_file_bytes": 5_320_747,
        "max_path_utf8_bytes": 37,
        "reviewed_skipped_symlinks_sha256": _EMPTY_REVIEWED_SYMLINKS_SHA256,
    },
}

_PLATFORM_ALIASES = {
    "win32": "windows",
    "windows": "windows",
    "linux": "linux",
    "darwin": "darwin",
    "macos": "darwin",
}
_ARCH_ALIASES = {
    "amd64": "x86_64",
    "x64": "x86_64",
    "x86_64": "x86_64",
    "aarch64": "arm64",
    "arm64": "arm64",
}


class JSToolchainAuthorityError(RuntimeError):
    """The JavaScript toolchain cannot be authorized safely."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class JSToolchainPackagingError(JSToolchainAuthorityError):
    """Required distributable bytes or identity evidence are unavailable."""

    def __init__(self, debt: Sequence["PackagingDebt"]) -> None:
        self.debt = tuple(debt)
        super().__init__("JS_TOOLCHAIN_PACKAGING_DEBT")


@dataclass(frozen=True)
class ArchiveExtractionPolicy:
    schema: str
    artifact_id: str
    archive_format: str
    archive_root: str
    allowed_member_types: tuple[str, ...]
    type_policy: str
    symlink_policy: str
    path_policy: str
    parser_id: str
    parser_path: str
    parser_sha256: str
    max_members: int
    regular_file_count: int
    directory_count: int
    skipped_symlink_count: int
    max_expanded_regular_file_bytes: int
    max_single_regular_file_bytes: int
    max_path_utf8_bytes: int
    reviewed_skipped_symlinks_sha256: str
    policy_sha256: str


@dataclass(frozen=True)
class ArtifactIdentity:
    artifact_id: str
    kind: str
    os: str
    arch: str
    version: str
    filename: str
    packaged_path: str
    archive_format: str
    archive_root: str
    executable: str
    extraction_policy: ArchiveExtractionPolicy
    source_url: str
    sha256: str | None
    size: int
    identity_state: str
    upstream_authentication: str


@dataclass(frozen=True)
class EgressTarget:
    authority: str
    target_id: str
    scheme: str
    host: str
    port: int
    credentials: str
    authority_sha256: str

    @property
    def registry_url(self) -> str:
        default_port = 443 if self.scheme == "https" else 80
        suffix = "" if self.port == default_port else f":{self.port}"
        return f"{self.scheme}://{self.host}{suffix}"


@dataclass(frozen=True)
class AuthorityManifest:
    bootstrap_anchor_sha256: str
    bootstrap_signed_set_sha256: str
    bootstrap_members: tuple["BootstrapMemberIdentity", ...]
    content_sha256: str
    runtime_closure_sha256: str
    artifacts: tuple[ArtifactIdentity, ...]
    online_target: EgressTarget
    upstream_verification_sha256: str


@dataclass(frozen=True, order=True)
class PackagingDebt:
    artifact_id: str
    code: str
    packaged_path: str


@dataclass(frozen=True)
class TrustedJSBootstrapAuthority:
    """Authority injected by the already-authenticated install boundary.

    This value is not a certificate and cannot be created from mutable runtime
    files.  The installer/launcher first verifies its immutable provenance,
    then passes these already-retained values into this module.
    """

    anchor_relative_path: str
    anchor_sha256: str
    source_census_sha256: str
    install_provenance_sha256: str
    trust_boundary: str


@dataclass(frozen=True, order=True)
class BootstrapMemberIdentity:
    path: str
    kind: str
    digest_mode: str
    sha256: str
    size: int


@dataclass(frozen=True)
class ToolchainExtractionReceipt:
    artifact_id: str
    archive_sha256: str
    bootstrap_anchor_sha256: str
    bootstrap_signed_set_sha256: str
    policy_sha256: str
    parser_sha256: str
    destination_root: str
    destination_identity_sha256: str
    member_count: int
    regular_file_count: int
    directory_count: int
    skipped_symlink_count: int
    expanded_regular_file_bytes: int
    max_single_regular_file_bytes: int
    max_path_utf8_bytes: int
    reviewed_skipped_symlinks_sha256: str
    tree_sha256: str
    executable_relative_path: str
    receipt_sha256: str


@dataclass(frozen=True)
class WritableRoots:
    private_root: str
    home_root: str
    modules_root: str
    cache_root: str
    temp_root: str


@dataclass(frozen=True)
class NetworkRequirement:
    mode: str
    target: EgressTarget | None


def _fail(code: str) -> None:
    raise JSToolchainAuthorityError(code)


def _canonical_bytes(value: Any) -> bytes:
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
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("MANIFEST_NON_CANONICAL_VALUE")
    raise AssertionError("unreachable")


def bootstrap_install_provenance_sha256(
    *,
    anchor_relative_path: str,
    anchor_sha256: str,
    source_census_sha256: str,
    trust_boundary: str,
) -> str:
    """Bind retained install provenance; this does not authenticate its input."""

    if (
        anchor_relative_path != BOOTSTRAP_RELATIVE_PATH.as_posix()
        or type(anchor_sha256) is not str
        or _HEX64.fullmatch(anchor_sha256) is None
        or type(source_census_sha256) is not str
        or _HEX64.fullmatch(source_census_sha256) is None
        or trust_boundary != BOOTSTRAP_TRUST_BOUNDARY
    ):
        _fail("BOOTSTRAP_INSTALL_PROVENANCE_INPUT_INVALID")
    payload = {
        "anchor_path": anchor_relative_path,
        "anchor_sha256": anchor_sha256,
        "schema": BOOTSTRAP_PROVENANCE_SCHEMA,
        "source_census_sha256": source_census_sha256,
        "trust_boundary": trust_boundary,
    }
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _validate_trusted_bootstrap_authority(
    value: TrustedJSBootstrapAuthority,
) -> None:
    if type(value) is not TrustedJSBootstrapAuthority:
        _fail("TRUSTED_BOOTSTRAP_AUTHORITY_REQUIRED")
    expected = bootstrap_install_provenance_sha256(
        anchor_relative_path=value.anchor_relative_path,
        anchor_sha256=value.anchor_sha256,
        source_census_sha256=value.source_census_sha256,
        trust_boundary=value.trust_boundary,
    )
    if value.install_provenance_sha256 != expected:
        _fail("BOOTSTRAP_INSTALL_PROVENANCE_BINDING_INVALID")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("MANIFEST_DUPLICATE_KEY")
        result[key] = value
    return result


def _reject_number(_value: str) -> None:
    _fail("MANIFEST_NON_INTEGER_NUMBER")


def _bounded_manifest(path: Path) -> tuple[bytes, dict[str, Any]]:
    try:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size <= 0
            or info.st_size > _MAX_MANIFEST_BYTES
            or info.st_nlink != 1
        ):
            _fail("MANIFEST_FILE_UNSAFE")
        raw = path.read_bytes()
    except JSToolchainAuthorityError:
        raise
    except OSError:
        _fail("MANIFEST_UNREADABLE")
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_strict_object,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except JSToolchainAuthorityError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError):
        _fail("MANIFEST_INVALID_JSON")
    if type(value) is not dict:
        _fail("MANIFEST_ROOT_NOT_OBJECT")
    return raw, value


def _exact(value: Any, keys: frozenset[str], code: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        _fail(code)
    return value


def _text(value: Any, code: str, pattern: re.Pattern[str] | None = None) -> str:
    if type(value) is not str or not value or value != value.strip() or "\x00" in value:
        _fail(code)
    if pattern is not None and pattern.fullmatch(value) is None:
        _fail(code)
    return value


def _relative_path(value: Any, code: str) -> str:
    rendered = _text(value, code)
    parsed = PurePosixPath(rendered)
    if (
        parsed.is_absolute()
        or parsed.as_posix() != rendered
        or any(part in {"", ".", ".."} for part in parsed.parts)
        or "\\" in rendered
    ):
        _fail(code)
    return rendered


def _https_url(value: Any, expected: str, code: str) -> str:
    rendered = _text(value, code)
    if rendered != expected:
        _fail(code)
    return rendered


def _extraction_policy(
    value: Any,
    *,
    artifact_id: str,
    archive_format: str,
    archive_root: str,
    parser_sha256: str,
) -> ArchiveExtractionPolicy:
    row = _exact(
        value,
        _EXTRACTION_POLICY_KEYS,
        "EXTRACTION_POLICY_SCHEMA_INVALID",
    )
    census = _EXPECTED_EXTRACTION_CENSUS.get(artifact_id)
    if census is None:
        _fail("EXTRACTION_POLICY_ARTIFACT_UNKNOWN")
    expected = {
        "allowed_member_types": [
            "directory",
            "regular-file",
            "reviewed-skipped-symlink",
        ],
        "directory_count": census["directory_count"],
        "max_expanded_regular_file_bytes": census[
            "max_expanded_regular_file_bytes"
        ],
        "max_members": census["max_members"],
        "max_path_utf8_bytes": census["max_path_utf8_bytes"],
        "max_single_regular_file_bytes": census[
            "max_single_regular_file_bytes"
        ],
        "parser_id": EXTRACTION_RECEIPT_PARSER_ID,
        "parser_path": EXTRACTION_RECEIPT_PARSER_PATH,
        "path_policy": (
            "CANONICAL_RELATIVE_UTF8_SINGLE_ROOT_NO_ALIAS_NO_COLLISION_V1"
        ),
        "regular_file_count": census["regular_file_count"],
        "reviewed_skipped_symlinks_sha256": census[
            "reviewed_skipped_symlinks_sha256"
        ],
        "schema": EXTRACTION_POLICY_SCHEMA,
        "skipped_symlink_count": census["skipped_symlink_count"],
        "symlink_policy": (
            "SKIP_EXACT_DIGEST_BOUND_ROSTER_NEVER_CREATE_LINKS_V1"
        ),
        "type_policy": (
            "REJECT_HARDLINK_DEVICE_FIFO_SOCKET_SPARSE_AND_UNKNOWN_V1"
        ),
    }
    if row != expected:
        _fail("EXTRACTION_POLICY_DRIFT")
    binding = {
        "archive_format": archive_format,
        "archive_root": archive_root,
        "artifact_id": artifact_id,
        "parser_sha256": parser_sha256,
        "policy": row,
    }
    return ArchiveExtractionPolicy(
        schema=EXTRACTION_POLICY_SCHEMA,
        artifact_id=artifact_id,
        archive_format=archive_format,
        archive_root=archive_root,
        allowed_member_types=tuple(row["allowed_member_types"]),
        type_policy=row["type_policy"],
        symlink_policy=row["symlink_policy"],
        path_policy=row["path_policy"],
        parser_id=row["parser_id"],
        parser_path=row["parser_path"],
        parser_sha256=parser_sha256,
        max_members=int(row["max_members"]),
        regular_file_count=int(row["regular_file_count"]),
        directory_count=int(row["directory_count"]),
        skipped_symlink_count=int(row["skipped_symlink_count"]),
        max_expanded_regular_file_bytes=int(
            row["max_expanded_regular_file_bytes"]
        ),
        max_single_regular_file_bytes=int(
            row["max_single_regular_file_bytes"]
        ),
        max_path_utf8_bytes=int(row["max_path_utf8_bytes"]),
        reviewed_skipped_symlinks_sha256=row[
            "reviewed_skipped_symlinks_sha256"
        ],
        policy_sha256=hashlib.sha256(_canonical_bytes(binding)).hexdigest(),
    )


def _artifact(value: Any, *, parser_sha256: str) -> ArtifactIdentity:
    if type(value) is not dict:
        _fail("ARTIFACT_SCHEMA_INVALID")
    row = _exact(value, _ARTIFACT_KEYS, "ARTIFACT_SCHEMA_INVALID")
    artifact_id = _text(row["artifact_id"], "ARTIFACT_ID_INVALID", _ID)
    kind = _text(row["kind"], "ARTIFACT_KIND_INVALID", _ID)
    os_name = _text(row["os"], "ARTIFACT_OS_INVALID", _ID)
    arch = _text(row["arch"], "ARTIFACT_ARCH_INVALID", _ID)
    version = _text(row["version"], "ARTIFACT_VERSION_INVALID", _VERSION)
    filename = _relative_path(row["filename"], "ARTIFACT_FILENAME_INVALID")
    if "/" in filename:
        _fail("ARTIFACT_FILENAME_INVALID")
    packaged_path = _relative_path(
        row["packaged_path"], "ARTIFACT_PACKAGED_PATH_INVALID"
    )
    archive_format = _text(
        row["archive_format"], "ARTIFACT_FORMAT_INVALID"
    )
    archive_root = _relative_path(
        row["archive_root"], "ARTIFACT_ARCHIVE_ROOT_INVALID"
    )
    executable = _relative_path(
        row["executable"], "ARTIFACT_EXECUTABLE_INVALID"
    )
    extraction = _extraction_policy(
        row["extraction_policy"],
        artifact_id=artifact_id,
        archive_format=archive_format,
        archive_root=archive_root,
        parser_sha256=parser_sha256,
    )
    identity_state = _text(
        row["identity_state"], "ARTIFACT_IDENTITY_STATE_INVALID"
    )
    upstream = _text(
        row["upstream_authentication"],
        "ARTIFACT_UPSTREAM_AUTH_INVALID",
    )
    digest_value = row["sha256"]
    if digest_value is not None:
        digest_value = _text(
            digest_value, "ARTIFACT_DIGEST_INVALID", _HEX64
        )
    artifact_size = row["size"]
    if type(artifact_size) is not int or artifact_size <= 0:
        _fail("ARTIFACT_SIZE_INVALID")

    if artifact_id == "yarn-classic-noarch":
        if artifact_size != YARN_ARCHIVE_SIZE:
            _fail("YARN_IDENTITY_DRIFT")
        if {
            "kind": kind,
            "os": os_name,
            "arch": arch,
            "version": version,
            "filename": filename,
            "archive_format": archive_format,
            "archive_root": archive_root,
            "executable": executable,
            "packaged_path": packaged_path,
            "identity_state": identity_state,
            "upstream_authentication": upstream,
        } != {
            "kind": "yarn-classic-distribution",
            "os": "any",
            "arch": "noarch",
            "version": YARN_VERSION,
            "filename": "yarn-v1.22.22.tar.gz",
            "archive_format": "tar.gz",
            "archive_root": "yarn-v1.22.22",
            "executable": "bin/yarn.js",
            "packaged_path": (
                "runtime/toolchains/js/yarn/yarn-v1.22.22.tar.gz"
            ),
            "identity_state": "CONTENT_DIGEST_AND_SIGNATURE_PINNED",
            "upstream_authentication": (
                "VERIFIED_YARN_DETACHED_OPENPGP_SIGNATURE"
            ),
        } or digest_value != YARN_ARCHIVE_SHA256:
            _fail("YARN_IDENTITY_DRIFT")
        source_url = _https_url(
            row["source_url"],
            "https://github.com/yarnpkg/yarn/releases/download/"
            "v1.22.22/yarn-v1.22.22.tar.gz",
            "YARN_SOURCE_DRIFT",
        )
    else:
        expected = _EXPECTED_NODE_ARTIFACTS.get(artifact_id)
        if expected is None:
            _fail("NODE_ARTIFACT_UNKNOWN")
        observed = {
            "os": os_name,
            "arch": arch,
            "filename": filename,
            "archive_format": archive_format,
            "archive_root": archive_root,
            "executable": executable,
            "sha256": digest_value,
            "size": artifact_size,
        }
        if observed != expected:
            _fail("NODE_IDENTITY_DRIFT")
        if (
            kind != "node-distribution"
            or version != NODE_VERSION
            or packaged_path != f"runtime/toolchains/js/node/{filename}"
            or identity_state != "CONTENT_DIGEST_PINNED"
            or upstream != "VERIFIED_NODEJS_CLEARSIGNED_SHA256_MANIFEST"
        ):
            _fail("NODE_IDENTITY_DRIFT")
        source_url = _https_url(
            row["source_url"],
            f"https://nodejs.org/dist/v{NODE_VERSION}/{filename}",
            "NODE_SOURCE_DRIFT",
        )

    return ArtifactIdentity(
        artifact_id=artifact_id,
        kind=kind,
        os=os_name,
        arch=arch,
        version=version,
        filename=filename,
        packaged_path=packaged_path,
        archive_format=archive_format,
        archive_root=archive_root,
        executable=executable,
        extraction_policy=extraction,
        source_url=source_url,
        sha256=digest_value,
        size=artifact_size,
        identity_state=identity_state,
        upstream_authentication=upstream,
    )


def _validate_declared_debt(value: Any) -> None:
    if value != []:
        _fail("DECLARED_PACKAGING_DEBT_DRIFT")


def _validate_install_policy(value: Any) -> None:
    expected = {
        "fixed_flags": list(FIXED_YARN_INSTALL_FLAGS),
        "modules_flag": "--modules-folder",
        "cache_flag": "--cache-folder",
        "offline_flag": "--offline",
        "registry_flag": "--registry",
        "subcommand": "install",
    }
    if value != expected:
        _fail("INSTALL_POLICY_DRIFT")


def _egress_target(value: Any) -> EgressTarget:
    row = _exact(
        value,
        frozenset(
            {"authority", "target_id", "scheme", "host", "port", "credentials"}
        ),
        "EGRESS_TARGET_SCHEMA_INVALID",
    )
    expected = {
        "authority": "plamen.verified_backend_egress.v1",
        "target_id": "yarn-classic-registry",
        "scheme": "https",
        "host": "registry.yarnpkg.com",
        "port": 443,
        "credentials": "FORBIDDEN",
    }
    if row != expected or type(row["port"]) is not int:
        _fail("EGRESS_TARGET_DRIFT")
    return EgressTarget(
        **expected,
        authority_sha256=hashlib.sha256(_canonical_bytes(expected)).hexdigest(),
    )


def _validate_manifest_document(
    value: dict[str, Any],
    *,
    bootstrap_anchor_sha256: str,
    bootstrap_signed_set_sha256: str,
    bootstrap_members: tuple[BootstrapMemberIdentity, ...],
    runtime_closure_sha256: str,
) -> AuthorityManifest:
    _exact(
        value,
        frozenset(
            {
                "schema",
                "manifest_authentication",
                "toolchain",
                "artifacts",
                "install_policy",
                "network_policy",
                "declared_packaging_debt",
                "upstream_verification",
            }
        ),
        "MANIFEST_SCHEMA_INVALID",
    )
    if value["schema"] != SCHEMA:
        _fail("MANIFEST_SCHEMA_VERSION_INVALID")
    authentication = _exact(
        value["manifest_authentication"],
        frozenset(
            {
                "scheme",
                "content_sha256",
                "runtime_closure_path",
                "runtime_closure_schema",
            }
        ),
        "MANIFEST_AUTHENTICATION_SCHEMA_INVALID",
    )
    unsigned = dict(value)
    unsigned.pop("manifest_authentication")
    computed = hashlib.sha256(_canonical_bytes(unsigned)).hexdigest()
    if (
        authentication["scheme"] != MANIFEST_AUTHENTICATION_SCHEME
        or authentication["content_sha256"] != computed
        or computed != EXPECTED_MANIFEST_CONTENT_SHA256
        or authentication["runtime_closure_path"]
        != RUNTIME_CLOSURE_RELATIVE_PATH.as_posix()
        or authentication["runtime_closure_schema"] != RUNTIME_CLOSURE_SCHEMA
    ):
        _fail("MANIFEST_AUTHENTICATION_FAILED")
    if value["toolchain"] != {
        "node_version": NODE_VERSION,
        "yarn_flavor": "classic",
        "yarn_version": YARN_VERSION,
    }:
        _fail("TOOLCHAIN_VERSION_DRIFT")

    rows = value["artifacts"]
    if type(rows) is not list or len(rows) != 7:
        _fail("ARTIFACT_ROSTER_INVALID")
    parser_member = next(
        (
            row
            for row in bootstrap_members
            if row.path == EXTRACTION_RECEIPT_PARSER_PATH
        ),
        None,
    )
    if parser_member is None:
        _fail("EXTRACTION_RECEIPT_PARSER_NOT_BOOTSTRAPPED")
    artifacts = tuple(
        _artifact(row, parser_sha256=parser_member.sha256) for row in rows
    )
    expected_order = (*_EXPECTED_NODE_ARTIFACTS, "yarn-classic-noarch")
    if tuple(row.artifact_id for row in artifacts) != expected_order:
        _fail("ARTIFACT_ROSTER_INVALID")

    _validate_declared_debt(value["declared_packaging_debt"])
    _validate_install_policy(value["install_policy"])
    upstream_verification = value["upstream_verification"]
    if upstream_verification != _EXPECTED_UPSTREAM_VERIFICATION:
        _fail("UPSTREAM_VERIFICATION_PROVENANCE_DRIFT")
    upstream_verification_sha256 = hashlib.sha256(
        _canonical_bytes(upstream_verification)
    ).hexdigest()
    network = _exact(
        value["network_policy"],
        frozenset(
            {
                "lock_resolved_origin_policy",
                "offline_mode",
                "online_mode",
                "online_target",
            }
        ),
        "NETWORK_POLICY_SCHEMA_INVALID",
    )
    if (
        network["offline_mode"] != "NO_NETWORK"
        or network["online_mode"]
        != "VERIFIED_EXACT_LOCK_ORIGIN_ALLOWLIST"
        or network["lock_resolved_origin_policy"]
        != {
            "credentials": "FORBIDDEN",
            "dns_mode": "NATIVE_BROKER_ALLOWLIST_ONLY",
            "maximum_origins": MAX_LOCK_EGRESS_ORIGINS,
            "origin_source": (
                "AUTHENTICATED_REACHABLE_YARN_LOCK_PLUS_BASE_REGISTRY"
            ),
            "port": 443,
            "scheme": "https",
        }
    ):
        _fail("NETWORK_POLICY_DRIFT")
    target = _egress_target(network["online_target"])
    return AuthorityManifest(
        bootstrap_anchor_sha256=bootstrap_anchor_sha256,
        bootstrap_signed_set_sha256=bootstrap_signed_set_sha256,
        bootstrap_members=bootstrap_members,
        content_sha256=computed,
        runtime_closure_sha256=runtime_closure_sha256,
        artifacts=artifacts,
        online_target=target,
        upstream_verification_sha256=upstream_verification_sha256,
    )


def _closure_file_digest(
    path: Path,
    *,
    digest_mode: str,
    maximum_bytes: int,
) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size <= 0
                or before.st_size > maximum_bytes
            ):
                _fail("RUNTIME_CLOSURE_MEMBER_UNSAFE")
            digest = hashlib.sha256()
            if digest_mode == "raw-v1":
                while True:
                    block = os.read(descriptor, _READ_CHUNK)
                    if not block:
                        break
                    digest.update(block)
            elif digest_mode == "utf8-lf-v1":
                raw = bytearray()
                while True:
                    block = os.read(descriptor, _READ_CHUNK)
                    if not block:
                        break
                    raw.extend(block)
                try:
                    canonical = bytes(raw).decode("utf-8", "strict").replace(
                        "\r\n", "\n"
                    ).encode("utf-8")
                except UnicodeError:
                    _fail("RUNTIME_CLOSURE_MEMBER_ENCODING_INVALID")
                digest.update(canonical)
            else:
                _fail("RUNTIME_CLOSURE_DIGEST_MODE_INVALID")
            after = os.fstat(descriptor)
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ):
                _fail("RUNTIME_CLOSURE_MEMBER_CHANGED_DURING_HASH")
            return digest.hexdigest()
        finally:
            os.close(descriptor)
    except JSToolchainAuthorityError:
        raise
    except OSError:
        _fail("RUNTIME_CLOSURE_MEMBER_UNREADABLE")
    raise AssertionError("unreachable")


def _load_bootstrap_anchor(
    repository_root: Path,
    authority: TrustedJSBootstrapAuthority,
) -> tuple[str, tuple[BootstrapMemberIdentity, ...]]:
    """Verify the externally pinned anchor and every member it authenticates."""

    _validate_trusted_bootstrap_authority(authority)
    anchor_path = _safe_artifact_path(
        repository_root,
        authority.anchor_relative_path,
    )
    raw, value = _bounded_manifest(anchor_path)
    observed_anchor_sha256 = hashlib.sha256(raw).hexdigest()
    if observed_anchor_sha256 != authority.anchor_sha256:
        _fail("BOOTSTRAP_ANCHOR_DIGEST_MISMATCH")
    if set(value) != {
        "schema",
        "signed_set",
        "signed_set_sha256",
        "trust_assumption",
    }:
        _fail("BOOTSTRAP_ANCHOR_SCHEMA_INVALID")
    rows = value.get("signed_set")
    if (
        value.get("schema") != BOOTSTRAP_SCHEMA
        or value.get("trust_assumption") != BOOTSTRAP_TRUST_ASSUMPTION
        or type(rows) is not list
    ):
        _fail("BOOTSTRAP_ANCHOR_SCHEMA_INVALID")

    members: list[BootstrapMemberIdentity] = []
    for raw_row in rows:
        row = _exact(
            raw_row,
            _BOOTSTRAP_MEMBER_KEYS,
            "BOOTSTRAP_MEMBER_SCHEMA_INVALID",
        )
        relative = _relative_path(row["path"], "BOOTSTRAP_MEMBER_PATH_INVALID")
        kind = _text(row["kind"], "BOOTSTRAP_MEMBER_KIND_INVALID")
        digest_mode = _text(
            row["digest_mode"],
            "BOOTSTRAP_MEMBER_DIGEST_MODE_INVALID",
        )
        digest = _text(row["sha256"], "BOOTSTRAP_MEMBER_DIGEST_INVALID", _HEX64)
        size = row["size"]
        if (
            kind not in {"python-source", "control", "runtime-data"}
            or digest_mode not in {"utf8-lf-v1", "raw-v1"}
            or type(size) is not int
            or size <= 0
            or size > 64 * 1024 * 1024
        ):
            _fail("BOOTSTRAP_MEMBER_SCHEMA_INVALID")
        members.append(
            BootstrapMemberIdentity(
                path=relative,
                kind=kind,
                digest_mode=digest_mode,
                sha256=digest,
                size=size,
            )
        )
    members_tuple = tuple(members)
    if (
        len({row.path for row in members_tuple}) != len(members_tuple)
        or members_tuple
        != tuple(sorted(members_tuple, key=lambda row: row.path))
    ):
        _fail("BOOTSTRAP_MEMBER_ROSTER_INVALID")

    expected_archive_identities: dict[str, tuple[str, int]] = {
        f"runtime/toolchains/js/node/{row['filename']}": (
            str(row["sha256"]),
            int(row["size"]),
        )
        for row in _EXPECTED_NODE_ARTIFACTS.values()
    }
    expected_archive_identities[
        "runtime/toolchains/js/yarn/yarn-v1.22.22.tar.gz"
    ] = (YARN_ARCHIVE_SHA256, YARN_ARCHIVE_SIZE)
    expected_shapes = {
        **{
            relative: ("python-source", "utf8-lf-v1")
            for relative in _BOOTSTRAP_MODULE_PATHS
        },
        MANIFEST_RELATIVE_PATH.as_posix(): ("control", "utf8-lf-v1"),
        **{
            relative: ("runtime-data", "raw-v1")
            for relative in expected_archive_identities
        },
    }
    by_path = {row.path: row for row in members_tuple}
    if (
        set(by_path) != set(expected_shapes)
        or BOOTSTRAP_RELATIVE_PATH.as_posix() in by_path
    ):
        _fail("BOOTSTRAP_MEMBER_ROSTER_INVALID")

    for relative, expected_shape in expected_shapes.items():
        member = by_path[relative]
        if (member.kind, member.digest_mode) != expected_shape:
            _fail("BOOTSTRAP_MEMBER_IDENTITY_INVALID")
        archive_identity = expected_archive_identities.get(relative)
        if archive_identity is not None and (
            member.sha256,
            member.size,
        ) != archive_identity:
            _fail("BOOTSTRAP_ARCHIVE_IDENTITY_INVALID")
        member_path = _safe_artifact_path(repository_root, relative)
        try:
            observed_size = member_path.lstat().st_size
        except OSError:
            _fail("BOOTSTRAP_MEMBER_UNREADABLE")
        if observed_size != member.size:
            _fail("BOOTSTRAP_MEMBER_SIZE_MISMATCH")
        observed_digest = _closure_file_digest(
            member_path,
            digest_mode=member.digest_mode,
            maximum_bytes=64 * 1024 * 1024,
        )
        if observed_digest != member.sha256:
            _fail("BOOTSTRAP_MEMBER_DIGEST_MISMATCH")

    signed_set_sha256 = hashlib.sha256(
        _canonical_bytes(
            [
                {
                    "digest_mode": row.digest_mode,
                    "kind": row.kind,
                    "path": row.path,
                    "sha256": row.sha256,
                    "size": row.size,
                }
                for row in members_tuple
            ]
        )
    ).hexdigest()
    if value.get("signed_set_sha256") != signed_set_sha256:
        _fail("BOOTSTRAP_SIGNED_SET_DIGEST_MISMATCH")
    return signed_set_sha256, members_tuple


def _verify_runtime_closure(repository_root: Path, path: Path) -> str:
    raw, value = _bounded_manifest(path)
    expected_document_keys = {
        "assets",
        "derivation",
        "entrypoints",
        "files",
        "manifest_control",
        "schema",
    }
    entrypoints = value.get("entrypoints")
    files = value.get("files")
    assets = value.get("assets")
    if (
        set(value) != expected_document_keys
        or value.get("schema") != RUNTIME_CLOSURE_SCHEMA
        or value.get("derivation") != "python-ast-typed-runtime-closure-v2"
        or value.get("manifest_control")
        != {
            "kind": "control",
            "path": RUNTIME_CLOSURE_RELATIVE_PATH.as_posix(),
        }
        or type(entrypoints) is not list
        or not all(
            type(item) is str
            and _relative_path(item, "RUNTIME_CLOSURE_ENTRYPOINT_INVALID")
            == item
            for item in entrypoints
        )
        or len(entrypoints) != len(set(entrypoints))
        or type(files) is not list
        or any(
            type(item) is not str
            or _relative_path(item, "RUNTIME_CLOSURE_PATH_INVALID") != item
            for item in files
        )
        or files != sorted(set(files))
        or type(assets) is not list
        or len(assets) != len(files) - 1
    ):
        _fail("RUNTIME_CLOSURE_IDENTITY_INVALID")

    asset_by_path: dict[str, dict[str, Any]] = {}
    for row in assets:
        if (
            type(row) is not dict
            or set(row) != {"digest_mode", "kind", "path", "sha256"}
            or row.get("digest_mode") not in {"raw-v1", "utf8-lf-v1"}
            or row.get("kind")
            not in {"python-source", "runtime-data", "control"}
            or type(row.get("path")) is not str
            or row["path"] not in files
            or row["path"] == RUNTIME_CLOSURE_RELATIVE_PATH.as_posix()
            or type(row.get("sha256")) is not str
            or _HEX64.fullmatch(row["sha256"]) is None
            or row["path"] in asset_by_path
        ):
            _fail("RUNTIME_CLOSURE_ASSET_ROW_INVALID")
        asset_by_path[row["path"]] = row
    if [row["path"] for row in assets] != sorted(asset_by_path):
        _fail("RUNTIME_CLOSURE_ASSET_ORDER_INVALID")
    if (
        RUNTIME_CLOSURE_RELATIVE_PATH.as_posix() not in files
        or not set(entrypoints).issubset(files)
        or set(asset_by_path)
        != set(files) - {RUNTIME_CLOSURE_RELATIVE_PATH.as_posix()}
    ):
        _fail("RUNTIME_CLOSURE_MEMBERSHIP_INVALID")

    expected_artifact_hashes = {
        f"runtime/toolchains/js/node/{row['filename']}": str(row["sha256"])
        for row in _EXPECTED_NODE_ARTIFACTS.values()
    }
    expected_artifact_hashes[
        "runtime/toolchains/js/yarn/yarn-v1.22.22.tar.gz"
    ] = YARN_ARCHIVE_SHA256
    required = {
        "scripts/js_toolchain_authority.py": ("python-source", "utf8-lf-v1"),
        "scripts/js_lock_authority.py": ("python-source", "utf8-lf-v1"),
        "scripts/js_dependency_materializer_authority.py": (
            "python-source",
            "utf8-lf-v1",
        ),
        "scripts/js_dependency_materializer_runtime.py": (
            "python-source",
            "utf8-lf-v1",
        ),
        MANIFEST_RELATIVE_PATH.as_posix(): ("control", "utf8-lf-v1"),
        **{
            relative: ("runtime-data", "raw-v1")
            for relative in expected_artifact_hashes
        },
    }
    if not set(required).issubset(files):
        _fail("RUNTIME_CLOSURE_REQUIRED_MEMBERS_MISSING")
    for relative, (kind, digest_mode) in required.items():
        row = asset_by_path.get(relative)
        if row is None or (row["kind"], row["digest_mode"]) != (
            kind,
            digest_mode,
        ):
            _fail("RUNTIME_CLOSURE_REQUIRED_MEMBER_INVALID")
        expected_archive_digest = expected_artifact_hashes.get(relative)
        if (
            expected_archive_digest is not None
            and row["sha256"] != expected_archive_digest
        ):
            _fail("RUNTIME_CLOSURE_ARCHIVE_AUTHORITY_MISMATCH")

    root = Path(repository_root)
    for relative, row in asset_by_path.items():
        member = _safe_artifact_path(root, relative)
        maximum = (
            64 * 1024 * 1024
            if row["kind"] == "runtime-data"
            else MAX_RUNTIME_SOURCE_BYTES
        )
        observed = _closure_file_digest(
            member,
            digest_mode=row["digest_mode"],
            maximum_bytes=maximum,
        )
        if observed != row["sha256"]:
            _fail("RUNTIME_CLOSURE_MEMBER_DIGEST_MISMATCH")
    return hashlib.sha256(raw).hexdigest()


def load_authority_manifest(
    repository_root: os.PathLike[str] | str | None = None,
    *,
    bootstrap_authority: TrustedJSBootstrapAuthority,
    manifest_path: os.PathLike[str] | str | None = None,
    runtime_closure_path: os.PathLike[str] | str | None = None,
) -> AuthorityManifest:
    """Load the reviewed policy and admit one observed runtime closure."""

    root = (
        Path(repository_root)
        if repository_root is not None
        else Path(__file__).resolve().parents[1]
    )
    manifest = (
        Path(manifest_path)
        if manifest_path is not None
        else root / MANIFEST_RELATIVE_PATH
    )
    closure = (
        Path(runtime_closure_path)
        if runtime_closure_path is not None
        else root / RUNTIME_CLOSURE_RELATIVE_PATH
    )
    bootstrap_signed_set_sha256, bootstrap_members = _load_bootstrap_anchor(
        root,
        bootstrap_authority,
    )
    runtime_closure_sha256 = _verify_runtime_closure(root, closure)
    _raw, value = _bounded_manifest(manifest)
    return _validate_manifest_document(
        value,
        bootstrap_anchor_sha256=bootstrap_authority.anchor_sha256,
        bootstrap_signed_set_sha256=bootstrap_signed_set_sha256,
        bootstrap_members=bootstrap_members,
        runtime_closure_sha256=runtime_closure_sha256,
    )


def parse_toolchain_extraction_receipt(
    authority: AuthorityManifest,
    artifact: ArtifactIdentity,
    receipt_bytes: bytes,
    *,
    expected_destination_root: os.PathLike[str] | str,
    target_os: str,
) -> ToolchainExtractionReceipt:
    """Parse one canonical, bounded receipt from the authenticated extractor.

    The parser validates claims; it does not extract archives or inspect the
    destination tree.  The native lifecycle must verify those effects before
    emitting this receipt.
    """

    if type(authority) is not AuthorityManifest or artifact not in authority.artifacts:
        _fail("EXTRACTION_RECEIPT_AUTHORITY_INVALID")
    if type(receipt_bytes) is not bytes or not (0 < len(receipt_bytes) <= 64 * 1024):
        _fail("EXTRACTION_RECEIPT_SIZE_INVALID")
    try:
        value = json.loads(
            receipt_bytes.decode("utf-8", "strict"),
            object_pairs_hook=_strict_object,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except JSToolchainAuthorityError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError):
        _fail("EXTRACTION_RECEIPT_JSON_INVALID")
    if type(value) is not dict or _canonical_bytes(value) != receipt_bytes:
        _fail("EXTRACTION_RECEIPT_NOT_CANONICAL")
    _exact(
        value,
        frozenset(
            {
                "archive",
                "bootstrap",
                "census",
                "destination",
                "parser",
                "policy_sha256",
                "schema",
                "terminal",
                "tree",
            }
        ),
        "EXTRACTION_RECEIPT_SCHEMA_INVALID",
    )
    policy = artifact.extraction_policy
    if value["schema"] != EXTRACTION_RECEIPT_SCHEMA:
        _fail("EXTRACTION_RECEIPT_SCHEMA_INVALID")
    archive = _exact(
        value["archive"],
        frozenset(
            {"archive_format", "archive_root", "artifact_id", "path", "sha256", "size"}
        ),
        "EXTRACTION_RECEIPT_ARCHIVE_SCHEMA_INVALID",
    )
    expected_archive = {
        "archive_format": artifact.archive_format,
        "archive_root": artifact.archive_root,
        "artifact_id": artifact.artifact_id,
        "path": artifact.packaged_path,
        "sha256": artifact.sha256,
        "size": artifact.size,
    }
    if archive != expected_archive or type(archive["size"]) is not int:
        _fail("EXTRACTION_RECEIPT_ARCHIVE_IDENTITY_INVALID")
    bootstrap = _exact(
        value["bootstrap"],
        frozenset({"anchor_sha256", "signed_set_sha256"}),
        "EXTRACTION_RECEIPT_BOOTSTRAP_SCHEMA_INVALID",
    )
    if bootstrap != {
        "anchor_sha256": authority.bootstrap_anchor_sha256,
        "signed_set_sha256": authority.bootstrap_signed_set_sha256,
    }:
        _fail("EXTRACTION_RECEIPT_BOOTSTRAP_IDENTITY_INVALID")
    parser = _exact(
        value["parser"],
        frozenset({"id", "path", "sha256"}),
        "EXTRACTION_RECEIPT_PARSER_SCHEMA_INVALID",
    )
    if parser != {
        "id": policy.parser_id,
        "path": policy.parser_path,
        "sha256": policy.parser_sha256,
    }:
        _fail("EXTRACTION_RECEIPT_PARSER_IDENTITY_INVALID")
    if value["policy_sha256"] != policy.policy_sha256:
        _fail("EXTRACTION_RECEIPT_POLICY_IDENTITY_INVALID")

    census = _exact(
        value["census"],
        frozenset(
            {
                "directory_count",
                "expanded_regular_file_bytes",
                "max_path_utf8_bytes",
                "max_single_regular_file_bytes",
                "member_count",
                "regular_file_count",
                "rejected_member_count",
                "reviewed_skipped_symlinks_sha256",
                "skipped_symlink_count",
            }
        ),
        "EXTRACTION_RECEIPT_CENSUS_SCHEMA_INVALID",
    )
    integer_census_keys = {
        "directory_count",
        "expanded_regular_file_bytes",
        "max_path_utf8_bytes",
        "max_single_regular_file_bytes",
        "member_count",
        "regular_file_count",
        "rejected_member_count",
        "skipped_symlink_count",
    }
    if any(type(census[key]) is not int for key in integer_census_keys):
        _fail("EXTRACTION_RECEIPT_CENSUS_TYPE_INVALID")
    expected_census = {
        "directory_count": policy.directory_count,
        "expanded_regular_file_bytes": policy.max_expanded_regular_file_bytes,
        "max_path_utf8_bytes": policy.max_path_utf8_bytes,
        "max_single_regular_file_bytes": policy.max_single_regular_file_bytes,
        "member_count": policy.max_members,
        "regular_file_count": policy.regular_file_count,
        "rejected_member_count": 0,
        "reviewed_skipped_symlinks_sha256": (
            policy.reviewed_skipped_symlinks_sha256
        ),
        "skipped_symlink_count": policy.skipped_symlink_count,
    }
    if census != expected_census:
        _fail("EXTRACTION_RECEIPT_CENSUS_MISMATCH")

    normalized_os, _ = normalized_platform(target_os, "x86_64")
    expected_root = str(
        _pure_path(
            expected_destination_root,
            normalized_os,
            "EXTRACTION_DESTINATION_ROOT_INVALID",
        )
    )
    destination = _exact(
        value["destination"],
        frozenset({"identity_sha256", "root", "sealed_state"}),
        "EXTRACTION_RECEIPT_DESTINATION_SCHEMA_INVALID",
    )
    if (
        destination.get("root") != expected_root
        or destination.get("sealed_state") != "IMMUTABLE_READ_ONLY_VERIFIED"
        or type(destination.get("identity_sha256")) is not str
        or _HEX64.fullmatch(destination["identity_sha256"]) is None
    ):
        _fail("EXTRACTION_RECEIPT_DESTINATION_INVALID")

    executable_relative = (
        PurePosixPath(artifact.archive_root) / artifact.executable
    ).as_posix()
    tree = _exact(
        value["tree"],
        frozenset(
            {
                "algorithm",
                "executable_relative_path",
                "file_count",
                "logical_bytes",
                "sha256",
            }
        ),
        "EXTRACTION_RECEIPT_TREE_SCHEMA_INVALID",
    )
    if (
        tree.get("algorithm") != "PLAMEN_CANONICAL_TREE_SHA256_V1"
        or tree.get("executable_relative_path") != executable_relative
        or type(tree.get("file_count")) is not int
        or tree.get("file_count") != policy.regular_file_count
        or type(tree.get("logical_bytes")) is not int
        or tree.get("logical_bytes") != policy.max_expanded_regular_file_bytes
        or type(tree.get("sha256")) is not str
        or _HEX64.fullmatch(tree["sha256"]) is None
    ):
        _fail("EXTRACTION_RECEIPT_TREE_INVALID")
    terminal = _exact(
        value["terminal"],
        frozenset(
            {
                "destination_alias_free",
                "exit_code",
                "network_mode",
                "source_archive_unchanged",
            }
        ),
        "EXTRACTION_RECEIPT_TERMINAL_SCHEMA_INVALID",
    )
    if (
        type(terminal.get("exit_code")) is not int
        or type(terminal.get("destination_alias_free")) is not bool
        or type(terminal.get("source_archive_unchanged")) is not bool
        or terminal
        != {
            "destination_alias_free": True,
            "exit_code": 0,
            "network_mode": "NO_NETWORK",
            "source_archive_unchanged": True,
        }
    ):
        _fail("EXTRACTION_RECEIPT_TERMINAL_INVALID")
    return ToolchainExtractionReceipt(
        artifact_id=artifact.artifact_id,
        archive_sha256=str(artifact.sha256),
        bootstrap_anchor_sha256=authority.bootstrap_anchor_sha256,
        bootstrap_signed_set_sha256=authority.bootstrap_signed_set_sha256,
        policy_sha256=policy.policy_sha256,
        parser_sha256=policy.parser_sha256,
        destination_root=expected_root,
        destination_identity_sha256=destination["identity_sha256"],
        member_count=policy.max_members,
        regular_file_count=policy.regular_file_count,
        directory_count=policy.directory_count,
        skipped_symlink_count=policy.skipped_symlink_count,
        expanded_regular_file_bytes=policy.max_expanded_regular_file_bytes,
        max_single_regular_file_bytes=policy.max_single_regular_file_bytes,
        max_path_utf8_bytes=policy.max_path_utf8_bytes,
        reviewed_skipped_symlinks_sha256=(
            policy.reviewed_skipped_symlinks_sha256
        ),
        tree_sha256=tree["sha256"],
        executable_relative_path=executable_relative,
        receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
    )


def normalized_platform(
    os_name: str | None = None,
    arch: str | None = None,
) -> tuple[str, str]:
    """Return one of the six reviewed Node distribution targets."""

    observed_os = (os_name or ("windows" if os.name == "nt" else platform.system())).lower()
    observed_arch = (arch or platform.machine()).lower()
    normalized_os = _PLATFORM_ALIASES.get(observed_os)
    normalized_arch = _ARCH_ALIASES.get(observed_arch)
    if normalized_os is None or normalized_arch is None:
        _fail("PLATFORM_UNSUPPORTED")
    return normalized_os, normalized_arch


def select_artifacts(
    authority: AuthorityManifest,
    *,
    os_name: str | None = None,
    arch: str | None = None,
) -> tuple[ArtifactIdentity, ArtifactIdentity]:
    """Select the exact platform Node archive and platform-neutral Yarn."""

    target_os, target_arch = normalized_platform(os_name, arch)
    node = next(
        (
            row
            for row in authority.artifacts
            if row.kind == "node-distribution"
            and row.os == target_os
            and row.arch == target_arch
        ),
        None,
    )
    yarn = next(
        (
            row
            for row in authority.artifacts
            if row.artifact_id == "yarn-classic-noarch"
        ),
        None,
    )
    if node is None or yarn is None:
        _fail("PLATFORM_ARTIFACT_MISSING")
    return node, yarn


def _safe_artifact_path(root: Path, relative: str) -> Path:
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    try:
        root_absolute = root.absolute()
        candidate_absolute = candidate.absolute()
        candidate_absolute.relative_to(root_absolute)
    except (OSError, ValueError):
        _fail("ARTIFACT_PATH_ESCAPE")
    cursor = root_absolute
    for part in PurePosixPath(relative).parts[:-1]:
        cursor /= part
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            break
        except OSError:
            _fail("ARTIFACT_ANCESTOR_UNREADABLE")
        if not stat.S_ISDIR(info.st_mode):
            _fail("ARTIFACT_ANCESTOR_UNSAFE")
    return candidate_absolute


def _file_sha256(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                _fail("ARTIFACT_FILE_UNSAFE")
            digest = hashlib.sha256()
            while True:
                block = os.read(descriptor, _READ_CHUNK)
                if not block:
                    break
                digest.update(block)
            after = os.fstat(descriptor)
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ):
                _fail("ARTIFACT_CHANGED_DURING_HASH")
            return digest.hexdigest()
        finally:
            os.close(descriptor)
    except JSToolchainAuthorityError:
        raise
    except OSError:
        _fail("ARTIFACT_UNREADABLE")
    raise AssertionError("unreachable")


def classify_packaging_debt(
    authority: AuthorityManifest,
    repository_root: os.PathLike[str] | str,
    *,
    artifacts: Sequence[ArtifactIdentity] | None = None,
) -> tuple[PackagingDebt, ...]:
    """Classify every absent, unpinned, unsafe, or mismatched archive."""

    root = Path(repository_root)
    selected = tuple(artifacts) if artifacts is not None else authority.artifacts
    debt: list[PackagingDebt] = []
    for artifact in selected:
        if artifact.sha256 is None:
            debt.append(
                PackagingDebt(
                    artifact.artifact_id,
                    "CONTENT_DIGEST_AUTHORITY_MISSING",
                    artifact.packaged_path,
                )
            )
        path = _safe_artifact_path(root, artifact.packaged_path)
        try:
            info = path.lstat()
        except FileNotFoundError:
            debt.append(
                PackagingDebt(
                    artifact.artifact_id,
                    "PACKAGED_ARTIFACT_MISSING",
                    artifact.packaged_path,
                )
            )
            continue
        except OSError:
            debt.append(
                PackagingDebt(
                    artifact.artifact_id,
                    "PACKAGED_ARTIFACT_UNREADABLE",
                    artifact.packaged_path,
                )
            )
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            debt.append(
                PackagingDebt(
                    artifact.artifact_id,
                    "PACKAGED_ARTIFACT_UNSAFE",
                    artifact.packaged_path,
                )
            )
            continue
        if artifact.size is not None and info.st_size != artifact.size:
            debt.append(
                PackagingDebt(
                    artifact.artifact_id,
                    "PACKAGED_ARTIFACT_SIZE_MISMATCH",
                    artifact.packaged_path,
                )
            )
            continue
        if artifact.sha256 is not None:
            try:
                observed = _file_sha256(path)
            except JSToolchainAuthorityError:
                debt.append(
                    PackagingDebt(
                        artifact.artifact_id,
                        "PACKAGED_ARTIFACT_UNREADABLE",
                        artifact.packaged_path,
                    )
                )
                continue
            if observed != artifact.sha256:
                debt.append(
                    PackagingDebt(
                        artifact.artifact_id,
                        "PACKAGED_ARTIFACT_DIGEST_MISMATCH",
                        artifact.packaged_path,
                    )
                )
    return tuple(sorted(debt))


def require_packaged_artifacts(
    authority: AuthorityManifest,
    repository_root: os.PathLike[str] | str,
    *,
    os_name: str | None = None,
    arch: str | None = None,
) -> Mapping[str, Path]:
    """Return selected archive paths only when both identities verify."""

    selected = select_artifacts(authority, os_name=os_name, arch=arch)
    debt = classify_packaging_debt(
        authority, repository_root, artifacts=selected
    )
    if debt:
        raise JSToolchainPackagingError(debt)
    root = Path(repository_root)
    return MappingProxyType(
        {
            row.artifact_id: _safe_artifact_path(root, row.packaged_path)
            for row in selected
        }
    )


def _pure_path(value: os.PathLike[str] | str, target_os: str, code: str) -> PurePath:
    rendered = os.fspath(value)
    if type(rendered) is not str or not rendered or "\x00" in rendered:
        _fail(code)
    parsed: PurePath = (
        PureWindowsPath(rendered)
        if target_os == "windows"
        else PurePosixPath(rendered)
    )
    if not parsed.is_absolute() or any(part == ".." for part in parsed.parts):
        _fail(code)
    return parsed


def writable_roots(
    private_root: os.PathLike[str] | str,
    *,
    target_os: str | None = None,
) -> WritableRoots:
    """Derive disjoint writable roots without creating or probing them."""

    normalized_os, _arch = normalized_platform(target_os, "x86_64")
    root = _pure_path(private_root, normalized_os, "PRIVATE_ROOT_INVALID")
    return WritableRoots(
        private_root=str(root),
        home_root=str(root / "home"),
        modules_root=str(root / "modules"),
        cache_root=str(root / "cache"),
        temp_root=str(root / "temp"),
    )


def network_requirement(
    authority: AuthorityManifest,
    phase: str,
) -> NetworkRequirement:
    """Declare the supervisor-enforced network authority for a phase."""

    if phase == "offline":
        return NetworkRequirement(mode="NO_NETWORK", target=None)
    if phase == "online":
        return NetworkRequirement(
            mode="VERIFIED_EXACT_LOCK_ORIGIN_ALLOWLIST",
            target=authority.online_target,
        )
    _fail("PHASE_INVALID")
    raise AssertionError("unreachable")


def closed_environment(
    authority: AuthorityManifest,
    *,
    node_binary: os.PathLike[str] | str,
    roots: WritableRoots,
    phase: str,
    target_os: str | None = None,
    windows_system_root: os.PathLike[str] | str | None = None,
) -> Mapping[str, str]:
    """Construct a new environment; no ambient mapping is accepted or read."""

    normalized_os, _arch = normalized_platform(target_os, "x86_64")
    node = _pure_path(node_binary, normalized_os, "NODE_BINARY_PATH_INVALID")
    private = _pure_path(
        roots.private_root, normalized_os, "PRIVATE_ROOT_INVALID"
    )
    root_values = {
        "HOME": roots.home_root,
        "PLAMEN_JS_MODULES_ROOT": roots.modules_root,
        "YARN_CACHE_FOLDER": roots.cache_root,
        "TMPDIR": roots.temp_root,
    }
    parsed_roots: dict[str, PurePath] = {}
    for name, value in root_values.items():
        parsed = _pure_path(value, normalized_os, "WRITABLE_ROOT_INVALID")
        try:
            parsed.relative_to(private)
        except ValueError:
            _fail("WRITABLE_ROOT_ESCAPE")
        if parsed == private:
            _fail("WRITABLE_ROOT_NOT_ALTERNATE")
        parsed_roots[name] = parsed
    if len(set(parsed_roots.values())) != len(parsed_roots):
        _fail("WRITABLE_ROOT_ALIAS")

    requirement = network_requirement(authority, phase)
    environment = {
        "HOME": str(parsed_roots["HOME"]),
        "USERPROFILE": str(parsed_roots["HOME"]),
        "XDG_CONFIG_HOME": str(parsed_roots["HOME"] / ".config"),
        "XDG_CACHE_HOME": str(parsed_roots["YARN_CACHE_FOLDER"]),
        "PATH": str(node.parent),
        "NODE_ENV": "development",
        "YARN_CACHE_FOLDER": str(parsed_roots["YARN_CACHE_FOLDER"]),
        "YARN_GLOBAL_FOLDER": str(parsed_roots["YARN_CACHE_FOLDER"] / "global"),
        "YARN_IGNORE_PATH": "1",
        "TMPDIR": str(parsed_roots["TMPDIR"]),
        "TMP": str(parsed_roots["TMPDIR"]),
        "TEMP": str(parsed_roots["TMPDIR"]),
        "PLAMEN_JS_NETWORK_MODE": requirement.mode,
    }
    if requirement.target is not None:
        environment.update(
            {
                "PLAMEN_JS_EGRESS_TARGET_ID": requirement.target.target_id,
                "PLAMEN_JS_EGRESS_TARGET_AUTHORITY_SHA256": (
                    requirement.target.authority_sha256
                ),
            }
        )
    if normalized_os == "windows":
        if windows_system_root is None:
            _fail("WINDOWS_SYSTEM_ROOT_REQUIRED")
        system_root = _pure_path(
            windows_system_root,
            normalized_os,
            "WINDOWS_SYSTEM_ROOT_INVALID",
        )
        environment["SYSTEMROOT"] = str(system_root)
        environment["WINDIR"] = str(system_root)
    return MappingProxyType(environment)


def yarn_install_argv(
    authority: AuthorityManifest,
    *,
    node_binary: os.PathLike[str] | str,
    yarn_cli: os.PathLike[str] | str,
    roots: WritableRoots,
    phase: str,
    target_os: str | None = None,
) -> tuple[str, ...]:
    """Build the exact Yarn Classic install argv without PATH/Corepack use."""

    normalized_os, _arch = normalized_platform(target_os, "x86_64")
    node = _pure_path(node_binary, normalized_os, "NODE_BINARY_PATH_INVALID")
    yarn = _pure_path(yarn_cli, normalized_os, "YARN_CLI_PATH_INVALID")
    modules = _pure_path(
        roots.modules_root, normalized_os, "MODULES_ROOT_INVALID"
    )
    cache = _pure_path(roots.cache_root, normalized_os, "CACHE_ROOT_INVALID")
    temp = _pure_path(roots.temp_root, normalized_os, "TEMP_ROOT_INVALID")
    private = _pure_path(
        roots.private_root, normalized_os, "PRIVATE_ROOT_INVALID"
    )
    for writable in (modules, cache, temp):
        try:
            writable.relative_to(private)
        except ValueError:
            _fail("WRITABLE_ROOT_ESCAPE")

    command = [
        str(node),
        str(yarn),
        "install",
        *FIXED_YARN_INSTALL_FLAGS,
        "--modules-folder",
        str(modules),
        "--cache-folder",
        str(cache),
        "--mutex",
        f"file:{temp / 'yarn-install.mutex'}",
    ]
    requirement = network_requirement(authority, phase)
    if requirement.target is None:
        command.append("--offline")
    else:
        command.extend(("--registry", requirement.target.registry_url))
    return tuple(command)


__all__ = [
    "ArchiveExtractionPolicy",
    "ArtifactIdentity",
    "AuthorityManifest",
    "BOOTSTRAP_PROVENANCE_SCHEMA",
    "BOOTSTRAP_RELATIVE_PATH",
    "BOOTSTRAP_SCHEMA",
    "BOOTSTRAP_TRUST_BOUNDARY",
    "BootstrapMemberIdentity",
    "EgressTarget",
    "EXPECTED_MANIFEST_CONTENT_SHA256",
    "MAX_LOCK_EGRESS_ORIGINS",
    "FIXED_YARN_INSTALL_FLAGS",
    "JSToolchainAuthorityError",
    "JSToolchainPackagingError",
    "MANIFEST_RELATIVE_PATH",
    "NODE_VERSION",
    "NetworkRequirement",
    "PackagingDebt",
    "ToolchainExtractionReceipt",
    "TrustedJSBootstrapAuthority",
    "WritableRoots",
    "YARN_VERSION",
    "YARN_ARCHIVE_SHA256",
    "YARN_ARCHIVE_SIZE",
    "bootstrap_install_provenance_sha256",
    "classify_packaging_debt",
    "closed_environment",
    "load_authority_manifest",
    "network_requirement",
    "normalized_platform",
    "parse_toolchain_extraction_receipt",
    "require_packaged_artifacts",
    "select_artifacts",
    "writable_roots",
    "yarn_install_argv",
]
