"""Platform-qualified Linux source-install and launch authority.

This module owns Linux *policy*, not installation effects.  It gives the
shared POSIX source dispatcher one exact answer for the current Linux ABI and
one exact source/build/launch denominator.  All observations made here remain
diagnostic until a native installer authenticates the signed provenance,
retained ELF closure, fixed receipt and service readiness.

Keeping this policy separate prevents Darwin's Mach-O/code-signing roster from
being accidentally treated as meaningful Linux authority.  It also makes an
unsupported Linux architecture fail before a source pathname is inspected or
an installation directory is created.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Any, NoReturn


AUTHORITY_SCHEMA = "plamen.linux-native-platform-authority.v2"
SOURCE_FREEZE_SCHEMA = "plamen.native-production-source-freeze.v2"
SOURCE_ROSTER_DOMAIN = b"PLAMEN-NATIVE-SOURCE-ROSTER-DEFINITION-V2\0"
SOURCE_CONTENT_DOMAIN = b"PLAMEN-NATIVE-SOURCE-ROSTER-CONTENT-V2\0"
MAX_AUTHORITY_BYTES = 64 * 1024
MAX_FREEZE_BYTES = 256 * 1024
MAX_SOURCE_MEMBER_BYTES = 16 * 1024 * 1024
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class LinuxNativeInstallAuthorityError(RuntimeError):
    """Stable, fail-closed Linux source-install authority failure."""


def _fail(code: str, diagnostic: str) -> NoReturn:
    raise LinuxNativeInstallAuthorityError(f"{code}: {diagnostic}") from None


@dataclass(frozen=True, slots=True)
class LinuxPlatformAuthority:
    platform_key: str
    canonical_machine: str
    aliases: tuple[str, ...]
    target_arch: int
    elf_class: int
    elf_data: int
    elf_machine: int
    extension_suffix: str
    source_freeze_relative: str


_PLATFORMS = MappingProxyType({
    "linux-x86_64": LinuxPlatformAuthority(
        platform_key="linux-x86_64",
        canonical_machine="x86_64",
        aliases=("amd64", "x86_64"),
        target_arch=1,
        elf_class=2,
        elf_data=1,
        elf_machine=62,
        extension_suffix=".cpython-312-x86_64-linux-gnu.so",
        source_freeze_relative=(
            "native/linux/native-production-source-freeze-v2.x86_64.json"
        ),
    ),
    "linux-arm64": LinuxPlatformAuthority(
        platform_key="linux-arm64",
        canonical_machine="aarch64",
        aliases=("aarch64", "arm64"),
        target_arch=2,
        elf_class=2,
        elf_data=1,
        elf_machine=183,
        extension_suffix=".cpython-312-aarch64-linux-gnu.so",
        source_freeze_relative=(
            "native/linux/native-production-source-freeze-v2.arm64.json"
        ),
    ),
})


# This is an exact denominator, not recursive discovery.  Both architectures
# intentionally use identical portable source bytes while producing distinct
# ELF/receipt identities and distinct source-freeze manifests.
LINUX_SOURCE_ROSTER = (
    ("source_build_dispatch", "scripts/build_posix_native_supervisor.py"),
    ("linux_install_authority", "scripts/linux_native_install_authority.py"),
    ("linux_platform_authority", "native/linux/native-platform-authority-v2.json"),
    ("cpython_extension", "native/cpython/_plamen_native_supervisor.c"),
    ("shared_broker_abi", "native/include/plamen_broker_v2.h"),
    ("broker_protocol_header", "native/posix/plamen_broker_v2_protocol.h"),
    ("broker_protocol", "native/posix/plamen_broker_v2_protocol.c"),
    ("linux_install_receipt_header", "native/linux/plamen_linux_install_receipt_v2.h"),
    ("linux_install_receipt", "native/linux/plamen_linux_install_receipt_v2.c"),
    ("linux_process_header", "native/linux/plamen_broker_v2_linux.h"),
    ("linux_process", "native/linux/plamen_broker_v2_linux_process.c"),
    ("linux_podman_admission_header", "native/linux/plamen_broker_v2_podman_admission.h"),
    ("linux_podman_admission", "native/linux/plamen_broker_v2_podman_admission.c"),
    ("linux_podman_lifecycle_header", "native/linux/plamen_broker_v2_podman_lifecycle.h"),
    ("linux_podman_lifecycle", "native/linux/plamen_broker_v2_podman_lifecycle.c"),
    ("native_broker", "native/posix/plamen_native_broker.c"),
    ("native_builder_header", "native/posix/plamen_native_builder_v2.h"),
    ("native_builder", "native/posix/plamen_native_builder_v2.c"),
    ("native_installer_header", "native/posix/plamen_native_installer_v2.h"),
    ("native_installer", "native/posix/plamen_native_installer_v2.c"),
    ("source_install_dispatch", "scripts/posix_native_install_dispatch.py"),
    ("cold_install_transaction", "scripts/posix_native_install_transaction.py"),
    ("cold_install_publication", "scripts/posix_native_install_publication.py"),
    ("cold_install_effects", "scripts/posix_native_install_effects.py"),
    ("package_front", "plamen.py"),
    ("outer_entrypoint", "scripts/posix_audit_entrypoint.py"),
    ("outer_authority_adapter", "scripts/posix_native_authority_adapter.py"),
    ("specialized_guest_worker", "scripts/posix_specialized_tool_worker.py"),
    ("report_output_routing", "scripts/report_output_routing.py"),
    ("runtime_source_projection", "scripts/runtime_source_projection.py"),
    ("native_runtime_bindings", "scripts/native_runtime_bindings.py"),
    ("native_runtime_bindings_policy", "verification_policy/native_runtime_bindings.v2.json"),
    ("native_runtime_policy_artifacts", "scripts/runtime_policy_artifacts.py"),
    ("native_elf_loader_closure", "scripts/elf_loader_closure.py"),
    ("native_runtime_image_materializer", "scripts/runtime_image_materializer.py"),
    ("native_backend_acquisition", "scripts/backend_acquisition.py"),
    ("native_backend_latest_acquisition_policy", "verification_policy/native_backend_acquisition.v2.json"),
)


LINUX_BUILD_ROSTER = (
    {
        "artifact": "lib/plamen/_plamen_native_supervisor{EXT_SUFFIX}",
        "kind": "cpython-extension",
        "mode": 0o400,
        "compile_flags": (
            "-std=c11", "-fPIC", "-fvisibility=hidden", "-Wall",
            "-Wextra", "-Werror",
        ),
        "link_flags": ("-shared", "-Wl,-z,relro,-z,now,-z,noexecstack", "-lcrypto", "-ldl"),
        "source_roles": (
            "cpython_extension", "broker_protocol", "linux_install_receipt",
        ),
    },
    {
        "artifact": "libexec/plamen-audit-broker-v2",
        "kind": "peer-credential-service",
        "mode": 0o500,
        "compile_flags": ("-std=c11", "-Wall", "-Wextra", "-Werror"),
        "link_flags": ("-Wl,-z,relro,-z,now,-z,noexecstack", "-lcrypto"),
        "source_roles": (
            "native_broker", "broker_protocol", "linux_process",
            "linux_podman_admission", "linux_podman_lifecycle",
        ),
    },
)


LINUX_LAUNCH_CONTRACT = MappingProxyType({
    "environment": MappingProxyType({}),
    "receipt_fd": 198,
    "install_root_fd": 199,
    "interpreter_argv": (
        "{generation}/bin/python3.12", "-I", "-B",
        "{generation}/lib/plamen/runtime/scripts/posix_audit_entrypoint.py",
    ),
    "stable_launcher": "{home}/.local/share/plamen/bin/plamen-native-launcher",
    "outer_socket": "/run/user/{uid}/plamen/broker-v2.sock",
    "guest_socket": "/run/plamen/broker-v2.sock",
    "publication": "ATOMIC_HARDLINK_AFTER_AUTHENTICATED_SERVICE_READINESS",
})


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False).encode("ascii")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeError):
        _fail("LINUX_AUTHORITY_JSON_INVALID", "value is not canonical JSON")


def _strict_object(raw: bytes, maximum: int, label: str) -> dict[str, Any]:
    if type(raw) is not bytes or not 1 <= len(raw) <= maximum:
        _fail("LINUX_AUTHORITY_SIZE_INVALID", f"{label} size is invalid")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if type(key) is not str or key in result:
                raise ValueError("duplicate or non-string key")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("ascii", "strict"), object_pairs_hook=pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite number")
            ),
        )
    except (UnicodeError, ValueError, json.JSONDecodeError):
        _fail("LINUX_AUTHORITY_JSON_INVALID", f"{label} is not strict JSON")
    if type(value) is not dict or canonical_json_bytes(value) != raw:
        _fail("LINUX_AUTHORITY_JSON_NONCANONICAL", f"{label} bytes differ")
    return value


def platform_authority(
    *, platform_name: str | None = None, machine: str | None = None,
) -> LinuxPlatformAuthority:
    """Resolve only native CPython Linux release ABIs.

    No fuzzy prefix or userspace bitness inference is accepted.  A caller may
    supply observations for tests/candidate rendering, but production passes
    ``sys.platform`` and ``os.uname().machine`` directly.
    """

    observed_platform = platform_name if platform_name is not None else __import__("sys").platform
    observed_machine = machine if machine is not None else os.uname().machine
    if type(observed_platform) is not str or observed_platform != "linux":
        _fail("LINUX_PLATFORM_UNSUPPORTED", "native host is not exact Linux")
    if type(observed_machine) is not str or not observed_machine:
        _fail("LINUX_MACHINE_UNSUPPORTED", "machine identity is unavailable")
    matches = [
        authority for authority in _PLATFORMS.values()
        if observed_machine in authority.aliases
    ]
    if len(matches) != 1:
        _fail(
            "LINUX_MACHINE_UNSUPPORTED",
            "supported machines are x86_64/amd64 and aarch64/arm64",
        )
    return matches[0]


def source_roster_definition_sha256() -> str:
    rows = [{"role": role, "path": path} for role, path in LINUX_SOURCE_ROSTER]
    if len({row["role"] for row in rows}) != len(rows) or len(
        {row["path"] for row in rows}
    ) != len(rows):
        _fail("LINUX_SOURCE_ROSTER_DUPLICATE", "role or path is duplicated")
    return hashlib.sha256(SOURCE_ROSTER_DOMAIN + canonical_json_bytes(rows)).hexdigest()


def source_content_sha256(rows: list[dict[str, Any]]) -> str:
    return hashlib.sha256(SOURCE_CONTENT_DOMAIN + canonical_json_bytes(rows)).hexdigest()


def decode_platform_contract(raw: bytes) -> dict[str, Any]:
    value = _strict_object(raw, MAX_AUTHORITY_BYTES, "Linux platform authority")
    if set(value) != {"launch", "platforms", "receipt", "schema", "signature_policy", "version"}:
        _fail("LINUX_PLATFORM_AUTHORITY_FIELDS", "top-level fields differ")
    if value.get("schema") != AUTHORITY_SCHEMA or value.get("version") != 2:
        _fail("LINUX_PLATFORM_AUTHORITY_HEADER", "schema/version differs")
    if set(value.get("platforms", {})) != set(_PLATFORMS):
        _fail("LINUX_PLATFORM_AUTHORITY_ROSTER", "platform roster differs")
    for key, expected in _PLATFORMS.items():
        row = value["platforms"].get(key)
        if type(row) is not dict or row != {
            "aliases": list(expected.aliases),
            "canonical_machine": expected.canonical_machine,
            "elf": {
                "class": expected.elf_class, "data": expected.elf_data,
                "machine": expected.elf_machine,
            },
            "extension_suffix": expected.extension_suffix,
            "platform_key": expected.platform_key,
            "target_arch": expected.target_arch,
        }:
            _fail("LINUX_PLATFORM_AUTHORITY_ABI", f"{key} ABI differs")
    expected_receipt = {
        "byte_count": 8192, "hashed_byte_count": 8160,
        "install_root_fd": 199, "magic": "PLNLIR2\\0",
        "member_roles": ["broker", "extension", "interpreter", "service_bootstrap"],
        "receipt_fd": 198, "schema": "plamen.linux-install-receipt.v2",
        "version": 2,
    }
    if value["receipt"] != expected_receipt:
        _fail("LINUX_PLATFORM_AUTHORITY_RECEIPT", "receipt ABI differs")
    expected_launch = {
        "environment": {},
        "inherited_fds": {"install_receipt": 198, "install_root": 199},
        "interpreter_argv": list(LINUX_LAUNCH_CONTRACT["interpreter_argv"]),
        "public_launcher": LINUX_LAUNCH_CONTRACT["stable_launcher"],
        "service_socket": {
            "guest_root": LINUX_LAUNCH_CONTRACT["guest_socket"],
            "outer_user": LINUX_LAUNCH_CONTRACT["outer_socket"],
        },
    }
    if value["launch"] != expected_launch:
        _fail("LINUX_PLATFORM_AUTHORITY_LAUNCH", "launch contract differs")
    expected_signatures = {
        "ambient_path_executable": "DENY",
        "artifact_identity": "SHA256_SIZE_MODE_ELF_INTERP_AND_ORDERED_DT_NEEDED_CLOSURE",
        "install_provenance": "RETAINED_VERIFIED_SIGNED_RELEASE_PROVENANCE",
        "receipt_trust_boundary": "RETAINED_IMMUTABLE_SIGNED_GENERATION",
        "unsigned_local_build": "NEVER_PRODUCTION_AUTHORITY",
    }
    if value["signature_policy"] != expected_signatures:
        _fail("LINUX_PLATFORM_AUTHORITY_SIGNATURE", "signature policy differs")
    return value


def decode_source_freeze(
    raw: bytes, *, authority: LinuxPlatformAuthority,
) -> dict[str, Any]:
    value = _strict_object(raw, MAX_FREEZE_BYTES, "Linux source freeze")
    if set(value) != {
        "platform", "roster_definition_sha256", "schema", "source_count",
        "source_roster_sha256", "sources", "version",
    }:
        _fail("LINUX_SOURCE_FREEZE_FIELDS", "manifest fields differ")
    if (
        value.get("schema") != SOURCE_FREEZE_SCHEMA
        or value.get("version") != 2
        or value.get("platform") != authority.platform_key
        or value.get("roster_definition_sha256") != source_roster_definition_sha256()
    ):
        _fail("LINUX_SOURCE_FREEZE_HEADER", "platform/schema/roster differs")
    sources = value.get("sources")
    if type(sources) is not list or value.get("source_count") != len(LINUX_SOURCE_ROSTER) or len(sources) != len(LINUX_SOURCE_ROSTER):
        _fail("LINUX_SOURCE_FREEZE_COUNT", "source count differs")
    for expected, row in zip(LINUX_SOURCE_ROSTER, sources, strict=True):
        if type(row) is not dict or set(row) != {"path", "role", "sha256", "size"}:
            _fail("LINUX_SOURCE_FREEZE_MEMBER_FIELDS", "member fields differ")
        role, path = expected
        if (
            row.get("role") != role or row.get("path") != path
            or type(row.get("sha256")) is not str
            or _HEX64.fullmatch(row["sha256"]) is None
            or not isinstance(row.get("size"), int)
            or isinstance(row.get("size"), bool)
            or not 1 <= row["size"] <= MAX_SOURCE_MEMBER_BYTES
        ):
            _fail("LINUX_SOURCE_FREEZE_MEMBER_IDENTITY", f"member {role} differs")
    if value.get("source_roster_sha256") != source_content_sha256(sources):
        _fail("LINUX_SOURCE_FREEZE_DIGEST", "source content digest differs")
    return value


def production_contract(
    repository_root: Path, *, platform_name: str | None = None,
    machine: str | None = None,
) -> dict[str, Any]:
    """Return immutable Linux build/launch policy after exact contract replay."""

    authority = platform_authority(platform_name=platform_name, machine=machine)
    root = Path(repository_root)
    if not root.is_absolute() or root != root.resolve(strict=True):
        _fail("LINUX_REPOSITORY_ROOT_INVALID", "repository root is not absolute")
    contract_path = root / "native/linux/native-platform-authority-v2.json"
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
    )
    file_flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    root_fd = native_fd = linux_fd = descriptor = -1
    try:
        root_fd = os.open(root, directory_flags)
        for observed, label in ((os.fstat(root_fd), "repository"),):
            if (
                not stat.S_ISDIR(observed.st_mode)
                or observed.st_uid not in {0, os.geteuid()}
                or stat.S_IMODE(observed.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                _fail(
                    "LINUX_REPOSITORY_ROOT_INVALID",
                    f"{label} directory authority differs",
                )
        native_fd = os.open("native", directory_flags, dir_fd=root_fd)
        linux_fd = os.open("linux", directory_flags, dir_fd=native_fd)
        for observed, label in (
            (os.fstat(native_fd), "native"),
            (os.fstat(linux_fd), "native/linux"),
        ):
            if (
                not stat.S_ISDIR(observed.st_mode)
                or observed.st_uid not in {0, os.geteuid()}
                or stat.S_IMODE(observed.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                _fail(
                    "LINUX_PLATFORM_AUTHORITY_DIRECTORY",
                    f"{label} directory authority differs",
                )
        descriptor = os.open(
            "native-platform-authority-v2.json", file_flags, dir_fd=linux_fd,
        )
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1 or observed.st_size > MAX_AUTHORITY_BYTES:
            _fail("LINUX_PLATFORM_AUTHORITY_FILE", "contract file is linked or invalid")
        raw = b""
        while len(raw) < observed.st_size:
            chunk = os.pread(descriptor, observed.st_size - len(raw), len(raw))
            if not chunk:
                _fail("LINUX_PLATFORM_AUTHORITY_READ", "contract read was incomplete")
            raw += chunk
        current = os.fstat(descriptor)
        stable_identity = lambda value: (
            value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns,
        )
        if (
            os.pread(descriptor, 1, observed.st_size)
            or stable_identity(current) != stable_identity(observed)
            or stable_identity(os.stat(
                "native-platform-authority-v2.json", dir_fd=linux_fd,
                follow_symlinks=False,
            )) != stable_identity(observed)
        ):
            _fail("LINUX_PLATFORM_AUTHORITY_DRIFT", "contract changed during replay")
        contract = decode_platform_contract(raw)
    except LinuxNativeInstallAuthorityError:
        raise
    except OSError:
        _fail("LINUX_PLATFORM_AUTHORITY_UNAVAILABLE", "contract cannot be opened")
    finally:
        for retained in (descriptor, linux_fd, native_fd, root_fd):
            if retained >= 0:
                os.close(retained)
    artifacts = []
    for row in LINUX_BUILD_ROSTER:
        materialized = dict(row)
        materialized["artifact"] = materialized["artifact"].replace(
            "{EXT_SUFFIX}", authority.extension_suffix
        )
        materialized["compile_flags"] = list(materialized["compile_flags"])
        materialized["link_flags"] = list(materialized["link_flags"])
        materialized["source_roles"] = list(materialized["source_roles"])
        artifacts.append(materialized)
    return {
        "schema": "plamen.linux-native-production-contract.v2",
        "platform": authority.platform_key,
        "machine": authority.canonical_machine,
        "source_freeze_path": str(root / authority.source_freeze_relative),
        "source_roster": [
            {"role": role, "path": path} for role, path in LINUX_SOURCE_ROSTER
        ],
        "source_roster_definition_sha256": source_roster_definition_sha256(),
        "artifact_roster": artifacts,
        "launch": {
            **{key: value for key, value in LINUX_LAUNCH_CONTRACT.items()
               if key != "environment"},
            "environment": {},
        },
        "receipt": dict(contract["receipt"]),
        "signature_policy": dict(contract["signature_policy"]),
        # These stable blockers prevent this policy object from being mistaken
        # for native install authority while the Linux service/installer
        # effect implementations are not frozen into the release closure.
        "transaction_admission_blockers": [
            "LINUX_NATIVE_INSTALL_EFFECTS_UNAVAILABLE",
            "LINUX_NATIVE_LAUNCHER_SOURCE_UNAVAILABLE",
            "LINUX_NATIVE_SERVICE_ENTRYPOINT_UNAVAILABLE",
            "LINUX_RELEASE_PINS_UNAVAILABLE",
            "LINUX_SIGNED_RELEASE_PROVENANCE_UNOBSERVED",
        ],
    }


__all__ = [
    "AUTHORITY_SCHEMA", "LINUX_BUILD_ROSTER", "LINUX_LAUNCH_CONTRACT",
    "LINUX_SOURCE_ROSTER", "LinuxNativeInstallAuthorityError",
    "LinuxPlatformAuthority", "canonical_json_bytes", "decode_platform_contract",
    "decode_source_freeze", "platform_authority", "production_contract",
    "source_content_sha256", "source_roster_definition_sha256",
]
