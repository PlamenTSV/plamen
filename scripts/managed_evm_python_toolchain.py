#!/usr/bin/env python3
"""Deterministic CPython 3.12 toolchain materializer for EVM analysis.

This module deliberately has no third-party imports.  The committed policy is the
complete dependency graph.  Provisioning therefore never asks an index or a live
resolver for an answer: it downloads only named, hashed artifacts into an inert
cache and performs an offline, hash-required, wheel-only, no-dependency install.

The generation directory is immutable after publication.  It is suitable as an
input to the native custody layer, but this module never updates a ``current``
pointer and never writes in the audited project.
"""

from __future__ import annotations

import argparse
import ast
import base64
import csv
import email.parser
import hashlib
import importlib.machinery
import json
import os
import platform
import re
import secrets
import shutil
import stat
import struct
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping, Sequence
import types
import weakref


POLICY_SCHEMA = "plamen.managed-evm-python-toolchain-policy.v1"
RECEIPT_SCHEMA = "plamen.managed-evm-python-toolchain-receipt.v1"
NATIVE_PLAN_SCHEMA = "plamen.managed-evm-python-native-plan.v1"
NATIVE_RESULT_SCHEMA = "plamen.managed-evm-python-native-result.v1"
APPLE_GUEST_CUSTODY_SCHEMA = "plamen.apple-container-tool-custody.v1"
NATIVE_BRIDGE_MODULE = "_plamen_native_supervisor"
NATIVE_BRIDGE_ABI = "plamen.native-broker.v2"
RECEIPT_NAME = ".plamen-managed-evm-toolchain-receipt.v1.json"
EXPECTED_POLICY_SHA256 = "c4091eeadb398b17bd36dbfd88358d06a6bb2b7976ad20f75a37183a9e2e93b5"
EXPECTED_ROOTS = ("slither-analyzer==0.11.5", "solc-select==1.2.0")
PROVIDED_TOOL_IDS = ("slither", "solc")
PLAMEN_RUNTIME_ASSETS = (
    {
        "kind": "control",
        "mode": "file",
        "path": "verification_policy/managed_evm_python_toolchain.v1.json",
    },
)
SUPPORTED_TARGETS: Mapping[str, tuple[str, str]] = {
    "macos-arm64": ("darwin", "arm64"),
    "linux-x86_64": ("linux", "x86_64"),
    "windows-amd64": ("win32", "AMD64"),
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.!+_-]*$")
_REQUIREMENT_HEAD_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\s*\[\s*(?P<extras>[A-Za-z0-9._-]+(?:\s*,\s*[A-Za-z0-9._-]+)*)\s*\])?"
)
_MARKER_TOKEN_RE = re.compile(
    r"\s*(?:"
    r"(?P<string>'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")|"
    r"(?P<op>===|~=|==|!=|<=|>=|<|>|not\s+in\b|in\b)|"
    r"(?P<lparen>\()|(?P<rparen>\))|"
    r"(?P<bool>and\b|or\b)|"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r")"
)
_MARKER_VARIABLES = frozenset(
    {
        "implementation_name",
        "implementation_version",
        "os_name",
        "platform_machine",
        "platform_python_implementation",
        "platform_release",
        "platform_system",
        "platform_version",
        "python_full_version",
        "python_version",
        "sys_platform",
        "extra",
    }
)
_FORBIDDEN_AUTOLOAD_BASENAMES = frozenset({"sitecustomize.py", "usercustomize.py"})


class ToolchainError(RuntimeError):
    """Fail-closed policy, cache, materialization, or replay error."""


class NativeToolchainUnavailable(ToolchainError):
    """The installed runtime has no authenticated native provision capability."""


class _FrozenManagedGenerationAuthorityType(type):
    def __setattr__(cls, _name: str, _value: object) -> None:
        raise TypeError("managed EVM generation authority types are frozen")

    def __delattr__(cls, _name: str) -> None:
        raise TypeError("managed EVM generation authority types are frozen")


class ManagedEVMGenerationAuthority(
    metaclass=_FrozenManagedGenerationAuthorityType
):
    """Opaque process-local handoff for one replayed immutable generation.

    The authority is intentionally issued from the complete reviewed policy +
    receipt + tree replay rather than from a caller-supplied pathname or a
    distribution-only digest.  It carries no mutation or process-launch API;
    the snapshot-bound native executor consumes it as a read-only source-root
    admission.
    """

    __slots__ = ("_policy_path", "_generation_root", "_binding", "__weakref__")

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> "ManagedEVMGenerationAuthority":
        raise TypeError("managed EVM generation authorities are issuer-created")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("managed EVM generation authorities cannot be subclassed")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("managed EVM generation authorities are immutable")

    def __delattr__(self, _name: str) -> None:
        raise TypeError("managed EVM generation authorities are immutable")

    @property
    def public_reference(self) -> Mapping[str, Any]:
        binding = _require_managed_generation_shell(self)
        return types.MappingProxyType({
            key: binding[key]
            for key in (
                "schema", "policy_sha256", "target_id", "receipt_sha256",
                "generation_payload_file_count",
                "generation_payload_manifest_sha256", "binding_sha256",
            )
        })

    def __reduce__(self) -> object:
        raise TypeError("managed EVM generation authorities are not serializable")


_LIVE_MANAGED_GENERATIONS: weakref.WeakKeyDictionary[
    ManagedEVMGenerationAuthority, tuple[object, ...]
] = weakref.WeakKeyDictionary()


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _pretty_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode(
        "ascii"
    )


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _open_native_regular_input(
    path: os.PathLike[str] | str, label: str
) -> tuple[int, Path, os.stat_result]:
    requested = Path(path).expanduser()
    if requested.is_symlink():
        raise ToolchainError(f"{label} cannot be a symlink alias")
    resolved = requested.resolve(strict=True)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError as exc:
        raise ToolchainError(f"{label} could not be opened without following links") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size < 1
            or info.st_size > 4 * 1024 * 1024
        ):
            raise ToolchainError(f"{label} is not a bounded unique ordinary file")
        current = resolved.lstat()
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_dev != info.st_dev
            or current.st_ino != info.st_ino
            or current.st_size != info.st_size
            or current.st_mtime_ns != info.st_mtime_ns
        ):
            raise ToolchainError(f"{label} changed while its descriptor was acquired")
        return descriptor, resolved, info
    except BaseException:
        os.close(descriptor)
        raise


def _open_native_directory(
    path: os.PathLike[str] | str, label: str
) -> tuple[int, Path, os.stat_result]:
    requested = Path(path).expanduser()
    if requested.is_symlink():
        raise ToolchainError(f"{label} cannot be a symlink alias")
    resolved = requested.resolve(strict=True)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        descriptor = os.open(resolved, flags)
    except OSError as exc:
        raise ToolchainError(f"{label} could not be opened without following links") from exc
    try:
        info = os.fstat(descriptor)
        current = resolved.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or not stat.S_ISDIR(current.st_mode)
            or current.st_dev != info.st_dev
            or current.st_ino != info.st_ino
        ):
            raise ToolchainError(f"{label} changed while its descriptor was acquired")
        return descriptor, resolved, info
    except BaseException:
        os.close(descriptor)
        raise


def _revalidate_native_descriptor(
    descriptor: int, path: Path, expected: os.stat_result, label: str
) -> None:
    current_fd = os.fstat(descriptor)
    current_path = path.lstat()
    if (
        current_fd.st_dev != expected.st_dev
        or current_fd.st_ino != expected.st_ino
        or current_fd.st_size != expected.st_size
        or current_fd.st_mtime_ns != expected.st_mtime_ns
        or current_path.st_dev != expected.st_dev
        or current_path.st_ino != expected.st_ino
    ):
        raise ToolchainError(f"{label} changed across native lease preparation")


def _sha256_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    offset = os.lseek(descriptor, 0, os.SEEK_CUR)
    os.lseek(descriptor, 0, os.SEEK_SET)
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.lseek(descriptor, offset, os.SEEK_SET)
    return digest.hexdigest()


def _exact_keys(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    expected_set = set(expected)
    actual = set(value)
    if actual != expected_set:
        raise ToolchainError(
            f"{label} keys differ: missing={sorted(expected_set - actual)!r} "
            f"extra={sorted(actual - expected_set)!r}"
        )


def _plain_dict(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise ToolchainError(f"{label} must be an object with string keys")
    return value


def _plain_list(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ToolchainError(f"{label} must be an array")
    return value


def _safe_basename(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value in {".", ".."}:
        raise ToolchainError(f"{label} is invalid")
    if Path(value).name != value or "/" in value or "\\" in value or "\x00" in value:
        raise ToolchainError(f"{label} is not a basename")
    return value


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ToolchainError(f"{label} must be a lowercase SHA-256")
    return value


def _positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ToolchainError(f"{label} must be a positive integer")
    return value


def _https_artifact_url(value: object, origin: str, filename: str, label: str) -> str:
    if not isinstance(value, str):
        raise ToolchainError(f"{label} must be a URL")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ToolchainError(f"{label} must be a clean HTTPS URL")
    if not value.startswith(origin):
        raise ToolchainError(f"{label} is outside its reviewed origin")
    if urllib.parse.unquote(parsed.path.rsplit("/", 1)[-1]) != filename:
        raise ToolchainError(f"{label} filename differs from the locked artifact")
    return value


def _root_name(requirement: str) -> str:
    return requirement.split("==", 1)[0]


def validate_policy(policy: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and return a policy without consulting the host or network."""

    policy = _plain_dict(dict(policy), "policy")
    _exact_keys(
        policy,
        {
            "schema",
            "policy_id",
            "roots",
            "python",
            "source_authority",
            "targets",
            "unsupported_target_policy",
        },
        "policy",
    )
    if policy["schema"] != POLICY_SCHEMA:
        raise ToolchainError("managed EVM Python policy schema is unsupported")
    if policy["policy_id"] != "plamen-evm-python-tools-cpython312-v1":
        raise ToolchainError("managed EVM Python policy id is unsupported")
    roots = _plain_list(policy["roots"], "roots")
    if roots != list(EXPECTED_ROOTS):
        raise ToolchainError("root requirements are not the exact reviewed roots")

    py = _plain_dict(policy["python"], "python")
    _exact_keys(
        py,
        {
            "implementation",
            "major_minor",
            "minimum_patch",
            "forbidden_major_minor",
            "venv_mode",
            "pip_global_flags",
            "install_flags",
        },
        "python",
    )
    if (
        py["implementation"] != "CPython"
        or py["major_minor"] != [3, 12]
        or py["minimum_patch"] != 1
        or py["forbidden_major_minor"] != [[3, 14]]
        or py["venv_mode"] != "private-copies"
        or py["pip_global_flags"] != ["--isolated"]
        or py["install_flags"]
        != [
            "--no-index",
            "--find-links=<PRIVATE_CACHE>",
            "--require-hashes",
            "--only-binary=:all:",
            "--no-deps",
            "--no-compile",
        ]
    ):
        raise ToolchainError("CPython or offline pip invariants differ from v1")

    source = _plain_dict(policy["source_authority"], "source_authority")
    _exact_keys(
        source,
        {
            "wheel_origin",
            "wheel_release_api_template",
            "compiler_origin",
            "transport",
            "resolver",
            "resolver_python",
        },
        "source_authority",
    )
    if source != {
        "wheel_origin": "https://files.pythonhosted.org/packages/",
        "wheel_release_api_template": "https://pypi.org/pypi/{project}/{version}/json",
        "compiler_origin": "https://binaries.soliditylang.org/",
        "transport": "HTTPS",
        "resolver": "pip==26.0",
        "resolver_python": "CPython 3.12.12",
    }:
        raise ToolchainError("artifact source authority differs from v1")

    unsupported = _plain_dict(policy["unsupported_target_policy"], "unsupported target policy")
    _exact_keys(unsupported, {"status", "behavior", "debt"}, "unsupported target policy")
    if (
        unsupported["status"] != "UNSUPPORTED_DEBT"
        or unsupported["behavior"]
        != "FAIL_CLOSED_BEFORE_NETWORK_OR_FILESYSTEM_MUTATION"
        or not isinstance(unsupported["debt"], str)
        or not unsupported["debt"]
    ):
        raise ToolchainError("unsupported-target policy is not fail closed")

    targets = _plain_list(policy["targets"], "targets")
    target_ids: list[str] = []
    for target_ordinal, raw_target in enumerate(targets):
        label = f"target[{target_ordinal}]"
        target = _plain_dict(raw_target, label)
        _exact_keys(
            target,
            {
                "id",
                "status",
                "sys_platform",
                "machine",
                "platform_tag",
                "distributions",
                "compiler",
            },
            label,
        )
        target_id = target.get("id")
        if not isinstance(target_id, str) or target_id not in SUPPORTED_TARGETS:
            raise ToolchainError(f"{label} id is unsupported")
        if target_id in target_ids:
            raise ToolchainError(f"duplicate target id: {target_id}")
        target_ids.append(target_id)
        expected_platform, expected_machine = SUPPORTED_TARGETS[target_id]
        if (
            target["status"] != "SUPPORTED"
            or target["sys_platform"] != expected_platform
            or target["machine"] != expected_machine
            or not isinstance(target["platform_tag"], str)
            or not target["platform_tag"]
        ):
            raise ToolchainError(f"{label} platform authority differs")

        rows = _plain_list(target["distributions"], f"{label}.distributions")
        if not rows:
            raise ToolchainError(f"{label} distribution closure is empty")
        names: list[str] = []
        graph: dict[str, list[str]] = {}
        for ordinal, raw_row in enumerate(rows):
            row_label = f"{label}.distributions[{ordinal}]"
            row = _plain_dict(raw_row, row_label)
            _exact_keys(
                row,
                {
                    "name",
                    "version",
                    "requirement",
                    "filename",
                    "sha256",
                    "size",
                    "source_url",
                    "metadata_sha256",
                    "dependencies",
                },
                row_label,
            )
            name = row.get("name")
            version = row.get("version")
            if not isinstance(name, str) or not NAME_RE.fullmatch(name):
                raise ToolchainError(f"{row_label}.name is not canonical")
            if name in names:
                raise ToolchainError(f"duplicate distribution: {target_id}:{name}")
            names.append(name)
            if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
                raise ToolchainError(f"{row_label}.version is invalid")
            if row.get("requirement") != f"{name}=={version}":
                raise ToolchainError(f"{row_label} is floated or not exactly pinned")
            filename = _safe_basename(row.get("filename"), f"{row_label}.filename")
            if not filename.casefold().endswith(".whl"):
                raise ToolchainError(f"{row_label} is not a wheel")
            wheel_parts = filename[:-4].split("-")
            if len(wheel_parts) < 5:
                raise ToolchainError(f"{row_label} wheel filename is malformed")
            wheel_name = re.sub(r"[-_.]+", "-", wheel_parts[0]).casefold()
            wheel_version = wheel_parts[1].replace("_", "-")
            if wheel_name != name or wheel_version != version:
                raise ToolchainError(f"{row_label} wheel filename identity differs")
            universal = filename.endswith("-py3-none-any.whl")
            platform_compatible = {
                "macos-arm64": (
                    "macosx_" in filename
                    and ("_arm64.whl" in filename or "_universal2.whl" in filename)
                ),
                "linux-x86_64": "manylinux" in filename and "x86_64.whl" in filename,
                "windows-amd64": filename.endswith("-win_amd64.whl"),
            }[target_id]
            if not (universal or platform_compatible):
                raise ToolchainError(f"{row_label} wheel platform tag is incompatible")
            _sha(row.get("sha256"), f"{row_label}.sha256")
            _sha(row.get("metadata_sha256"), f"{row_label}.metadata_sha256")
            _positive_int(row.get("size"), f"{row_label}.size")
            _https_artifact_url(
                row.get("source_url"), source["wheel_origin"], filename, f"{row_label}.source_url"
            )
            dependencies = _plain_list(row.get("dependencies"), f"{row_label}.dependencies")
            if dependencies != sorted(set(dependencies)) or not all(
                isinstance(dep, str) and NAME_RE.fullmatch(dep) for dep in dependencies
            ):
                raise ToolchainError(f"{row_label}.dependencies are not sorted canonical names")
            graph[name] = list(dependencies)
        if names != sorted(names):
            raise ToolchainError(f"{label} distributions are not sorted")
        unknown = sorted({dep for deps in graph.values() for dep in deps} - set(names))
        if unknown:
            raise ToolchainError(f"{label} dependency closure is incomplete: {unknown!r}")
        reachable = {_root_name(root) for root in roots}
        frontier = list(reachable)
        while frontier:
            current = frontier.pop()
            if current not in graph:
                raise ToolchainError(f"{label} is missing root distribution {current}")
            for dependency in graph[current]:
                if dependency not in reachable:
                    reachable.add(dependency)
                    frontier.append(dependency)
        if reachable != set(names):
            raise ToolchainError(
                f"{label} has unreachable/unproven transitive rows: {sorted(set(names) - reachable)!r}"
            )

        compiler = _plain_dict(target["compiler"], f"{label}.compiler")
        _exact_keys(
            compiler,
            {
                "name",
                "version",
                "long_version",
                "build",
                "filename",
                "sha256",
                "size",
                "source_url",
                "provider_index_url",
                "provider_index_sha256",
                "binary_format",
                "architectures",
                "minimum_os",
                "install_relative_path",
            },
            f"{label}.compiler",
        )
        if (
            compiler["name"] != "solc"
            or compiler["version"] != "0.8.26"
            or compiler["long_version"] != "0.8.26+commit.8a97fa7a"
            or compiler["build"] != "commit.8a97fa7a"
        ):
            raise ToolchainError(f"{label} compiler version differs from DODO authority")
        compiler_filename = _safe_basename(
            compiler.get("filename"), f"{label}.compiler.filename"
        )
        _sha(compiler.get("sha256"), f"{label}.compiler.sha256")
        _sha(compiler.get("provider_index_sha256"), f"{label}.compiler.provider_index_sha256")
        _positive_int(compiler.get("size"), f"{label}.compiler.size")
        _https_artifact_url(
            compiler.get("source_url"),
            source["compiler_origin"],
            compiler_filename,
            f"{label}.compiler.source_url",
        )
        index_url = compiler.get("provider_index_url")
        if (
            not isinstance(index_url, str)
            or not index_url.startswith(source["compiler_origin"])
            or not index_url.endswith("/list.json")
        ):
            raise ToolchainError(f"{label} compiler index URL is invalid")
        if not isinstance(compiler.get("architectures"), list) or not compiler["architectures"]:
            raise ToolchainError(f"{label} compiler architecture denominator is empty")
        expected_architecture = {
            "macos-arm64": "arm64",
            "linux-x86_64": "x86_64",
            "windows-amd64": "AMD64",
        }[target_id]
        if expected_architecture not in compiler["architectures"]:
            raise ToolchainError(f"{label} compiler does not contain the host architecture")
        for field in ("binary_format", "minimum_os", "install_relative_path"):
            if not isinstance(compiler.get(field), str) or not compiler[field]:
                raise ToolchainError(f"{label}.compiler.{field} is invalid")
        install_parts = Path(compiler["install_relative_path"]).parts
        if ".." in install_parts or Path(compiler["install_relative_path"]).is_absolute():
            raise ToolchainError(f"{label} compiler installation path escapes the generation")

    if target_ids != list(SUPPORTED_TARGETS):
        raise ToolchainError("supported target denominator is incomplete or not sorted")
    if _sha256_bytes(_pretty_bytes(policy)) != EXPECTED_POLICY_SHA256:
        raise ToolchainError(
            "managed EVM Python policy differs from the code-reviewed digest anchor"
        )
    return policy


def load_policy(path: os.PathLike[str] | str) -> tuple[dict[str, Any], str]:
    policy_path = Path(path)
    raw = policy_path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ToolchainError("managed EVM Python policy is not valid JSON") from exc
    policy = validate_policy(_plain_dict(value, "policy"))
    if raw != _pretty_bytes(policy):
        raise ToolchainError("managed EVM Python policy is not canonical pretty JSON")
    policy_sha256 = _sha256_bytes(raw)
    if policy_sha256 != EXPECTED_POLICY_SHA256:
        raise ToolchainError("managed EVM Python policy digest anchor differs")
    return policy, policy_sha256


def detect_target(*, sys_platform: str | None = None, machine: str | None = None) -> str:
    observed_platform = sys_platform if sys_platform is not None else sys.platform
    observed_machine = machine if machine is not None else platform.machine()
    aliases = {"aarch64": "arm64", "AMD64": "AMD64", "amd64": "AMD64", "x86_64": "x86_64"}
    observed_machine = aliases.get(observed_machine, observed_machine)
    for target_id, pair in SUPPORTED_TARGETS.items():
        if pair == (observed_platform, observed_machine):
            return target_id
    raise ToolchainError(
        "UNSUPPORTED_DEBT: no reviewed managed EVM Python closure for "
        f"{observed_platform}/{observed_machine}"
    )


_PROBE = r"""
import json, platform, sys, sysconfig
print(json.dumps({
  "implementation": platform.python_implementation(),
  "version": platform.python_version(),
  "version_info": list(sys.version_info[:3]),
  "executable": sys.executable,
  "prefix": sys.prefix,
  "base_prefix": sys.base_prefix,
  "sys_platform": sys.platform,
  "machine": platform.machine(),
  "purelib": sysconfig.get_path("purelib"),
  "platlib": sysconfig.get_path("platlib"),
}, sort_keys=True, separators=(",", ":")))
""".strip()


def _clean_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("PIP_")}
    env.update(
        {
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
        }
    )
    if extra:
        env.update(extra)
    return env


def validate_interpreter_probe(probe: Mapping[str, Any]) -> dict[str, Any]:
    probe = _plain_dict(dict(probe), "interpreter probe")
    _exact_keys(
        probe,
        {
            "implementation",
            "version",
            "version_info",
            "executable",
            "prefix",
            "base_prefix",
            "sys_platform",
            "machine",
            "purelib",
            "platlib",
        },
        "interpreter probe",
    )
    version = probe.get("version_info")
    if probe.get("implementation") != "CPython" or not isinstance(version, list):
        raise ToolchainError("the toolchain interpreter must be CPython")
    if len(version) != 3 or not all(isinstance(v, int) for v in version):
        raise ToolchainError("interpreter version probe is malformed")
    if version[:2] == [3, 14]:
        raise ToolchainError("Python 3.14 is forbidden for the managed EVM toolchain")
    if version[:2] != [3, 12] or version[2] < 1:
        raise ToolchainError("the managed EVM toolchain requires CPython >=3.12.1,<3.13")
    if probe.get("version") != ".".join(str(v) for v in version):
        raise ToolchainError("interpreter version strings disagree")
    for field in ("executable", "prefix", "base_prefix", "purelib", "platlib"):
        if not isinstance(probe.get(field), str) or not Path(probe[field]).is_absolute():
            raise ToolchainError(f"interpreter probe {field} must be absolute")
    if not isinstance(probe.get("sys_platform"), str) or not isinstance(probe.get("machine"), str):
        raise ToolchainError("interpreter platform probe is malformed")
    return probe


def probe_interpreter(python: os.PathLike[str] | str) -> dict[str, Any]:
    executable = Path(python).resolve(strict=True)
    if not executable.is_file():
        raise ToolchainError("interpreter is not an ordinary file")
    completed = subprocess.run(
        [str(executable), "-I", "-B", "-c", _PROBE],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
        env=_clean_env(),
        cwd=str(executable.parent),
        timeout=30,
    )
    if completed.returncode != 0:
        raise ToolchainError(f"interpreter probe failed: {completed.stderr.strip()[:400]}")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ToolchainError("interpreter probe did not return JSON") from exc
    probe = validate_interpreter_probe(_plain_dict(value, "interpreter probe"))
    if Path(probe["executable"]).resolve(strict=True) != executable:
        raise ToolchainError("interpreter probe executed a different binary")
    return probe


def select_target(policy: Mapping[str, Any], target_id: str) -> dict[str, Any]:
    validate_policy(policy)
    for target in policy["targets"]:
        if target["id"] == target_id:
            return target
    raise ToolchainError(f"target is not present in the policy: {target_id}")


def _artifact_rows(target: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [*target["distributions"], target["compiler"]]


def _cache_path(cache_root: Path, target_id: str, filename: str) -> Path:
    return cache_root / target_id / filename


def _require_cache_target_directory(root: Path, target_id: str, *, create: bool) -> Path:
    directory = root / target_id
    if create and not directory.exists() and not directory.is_symlink():
        directory.mkdir(mode=0o700)
    try:
        info = directory.lstat()
    except FileNotFoundError as exc:
        raise ToolchainError(f"partial cache; target directory is missing: {directory}") from exc
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ToolchainError(f"cache target path is not an owned directory: {directory}")
    return directory


def validate_cache(
    policy: Mapping[str, Any], target_id: str, cache_root: os.PathLike[str] | str
) -> dict[str, Any]:
    target = select_target(policy, target_id)
    root = Path(cache_root).resolve(strict=True)
    _require_cache_target_directory(root, target_id, create=False)
    entries: list[dict[str, Any]] = []
    missing: list[str] = []
    for row in _artifact_rows(target):
        path = _cache_path(root, target_id, row["filename"])
        try:
            info = path.lstat()
        except FileNotFoundError:
            missing.append(row["filename"])
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ToolchainError(f"cache artifact is not a unique ordinary file: {path}")
        if info.st_size != row["size"] or _sha256_file(path) != row["sha256"]:
            raise ToolchainError(f"cache artifact hash/size mismatch: {path}")
        entries.append(
            {"filename": row["filename"], "sha256": row["sha256"], "size": row["size"]}
        )
    if missing:
        raise ToolchainError(f"partial cache for {target_id}; missing={missing!r}")
    entries.sort(key=lambda row: row["filename"])
    return {
        "target_id": target_id,
        "artifact_count": len(entries),
        "entries": entries,
        "closure_sha256": _sha256_bytes(_canonical_bytes(entries)),
    }


def _download_one(
    url: str,
    destination: Path,
    expected_sha256: str,
    expected_size: int,
    *,
    opener: Callable[..., Any] | None = None,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    download = opener or urllib.request.urlopen
    temp = destination.with_name(f".{destination.name}.{os.getpid()}.partial")
    try:
        descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        digest = hashlib.sha256()
        byte_count = 0
        try:
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "Plamen/3 managed-evm-toolchain"},
                method="GET",
            )
            with os.fdopen(descriptor, "wb", closefd=True) as output, download(request, timeout=60) as response:
                final_url = response.geturl()
                if final_url != url:
                    raise ToolchainError(f"artifact redirect is not admitted: {url} -> {final_url}")
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    output.write(chunk)
                    digest.update(chunk)
                    byte_count += len(chunk)
                output.flush()
                os.fsync(output.fileno())
        except BaseException:
            # fdopen owns the descriptor after construction.
            raise
        if byte_count != expected_size or digest.hexdigest() != expected_sha256:
            raise ToolchainError(f"downloaded artifact hash/size mismatch: {destination.name}")
        os.replace(temp, destination)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def acquire_cache(
    policy: Mapping[str, Any],
    target_id: str,
    cache_root: os.PathLike[str] | str,
    *,
    offline: bool = False,
    opener: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Populate only explicitly locked URLs, then replay every artifact hash."""

    target = select_target(policy, target_id)
    root = Path(cache_root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    _require_cache_target_directory(root, target_id, create=True)
    for row in _artifact_rows(target):
        path = _cache_path(root, target_id, row["filename"])
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_size != row["size"]
                or _sha256_file(path) != row["sha256"]
            ):
                raise ToolchainError(f"existing cache artifact is not the locked object: {path}")
            continue
        if offline:
            continue
        _download_one(
            row["source_url"], path, row["sha256"], row["size"], opener=opener
        )
    return validate_cache(policy, target_id, root)


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _assert_outside_project(path: Path, project_root: Path | None, label: str) -> None:
    if project_root is None:
        return
    if _path_is_within(path, project_root) or _path_is_within(project_root, path):
        raise ToolchainError(f"{label} must be outside and disjoint from the target project")


def _run(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    timeout: int = 300,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        list(argv),
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
        env=dict(env),
        cwd=str(cwd) if cwd is not None else None,
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise ToolchainError(
            f"command failed ({completed.returncode}): {argv[0]}: {completed.stderr.strip()[:1000]}"
        )
    return completed


def _venv_python(generation: Path, target_id: str) -> Path:
    if target_id == "windows-amd64":
        return generation / "venv" / "Scripts" / "python.exe"
    return generation / "venv" / "bin" / "python3.12"


def _distribution_probe(python: Path, names: Sequence[str]) -> list[dict[str, str]]:
    code = (
        "import importlib.metadata as m,json;"
        f"names={list(names)!r};"
        "print(json.dumps([{'name':n,'version':m.version(n),'path':str(m.distribution(n)._path)} "
        "for n in names],sort_keys=True,separators=(',',':')))"
    )
    result = _run(
        [str(python), "-I", "-B", "-c", code],
        env=_clean_env(),
        cwd=python.parent,
    )
    try:
        rows = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ToolchainError("installed distribution probe did not return JSON") from exc
    if not isinstance(rows, list):
        raise ToolchainError("installed distribution probe is malformed")
    return rows


def _decode_record_hash(value: str, label: str) -> str:
    if not value.startswith("sha256="):
        raise ToolchainError(f"{label} is not a sha256 RECORD hash")
    encoded = value.split("=", 1)[1]
    try:
        digest = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except Exception as exc:
        raise ToolchainError(f"{label} has invalid base64") from exc
    if len(digest) != 32:
        raise ToolchainError(f"{label} digest length is invalid")
    return digest.hex()


def _canonical_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).casefold()


def _target_marker_environment(target_id: str) -> dict[str, str]:
    """Return the exact PEP 508 environment used by the locked CPython 3.12 lane."""

    if target_id not in SUPPORTED_TARGETS:
        raise ToolchainError(f"marker environment target is unsupported: {target_id}")
    sys_platform, machine = SUPPORTED_TARGETS[target_id]
    platform_system = {
        "macos-arm64": "Darwin",
        "linux-x86_64": "Linux",
        "windows-amd64": "Windows",
    }[target_id]
    os_name = "nt" if target_id == "windows-amd64" else "posix"
    return {
        "implementation_name": "cpython",
        "implementation_version": "3.12.12",
        "os_name": os_name,
        "platform_machine": machine,
        "platform_python_implementation": "CPython",
        # These host-release values are intentionally unavailable to the locked
        # closure.  A package depending on them would make the policy non-portable
        # across otherwise supported machines and is rejected by the evaluator.
        "platform_release": "",
        "platform_system": platform_system,
        "platform_version": "",
        "python_full_version": "3.12.12",
        "python_version": "3.12",
        "sys_platform": sys_platform,
        "extra": "",
    }


def _marker_tokens(marker: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    offset = 0
    while offset < len(marker):
        match = _MARKER_TOKEN_RE.match(marker, offset)
        if match is None:
            raise ToolchainError(f"Requires-Dist marker is unsupported near {marker[offset:]!r}")
        kind = match.lastgroup
        if kind is None:
            raise ToolchainError("Requires-Dist marker token is malformed")
        value = match.group(kind)
        if kind == "op":
            value = " ".join(value.split())
        tokens.append((kind, value))
        offset = match.end()
    return tokens


def _version_key(value: str) -> tuple[int, ...]:
    """Parse the numeric versions used by Python/platform PEP 508 markers.

    We deliberately reject non-numeric marker ordering rather than silently
    approximating PEP 440.  The reviewed closure uses only numeric Python
    version ordering; equality and membership remain valid for arbitrary text.
    """

    if re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", value) is None:
        raise ToolchainError(f"ordered Requires-Dist marker version is unsupported: {value!r}")
    return tuple(int(item) for item in value.split("."))


def _marker_compare(left: str, operator: str, right: str, *, version: bool) -> bool:
    if operator in {"in", "not in"}:
        result = left in right
        return not result if operator == "not in" else result
    if operator in {"==", "!="}:
        result = left == right
        return not result if operator == "!=" else result
    if operator in {"===", "~="}:
        raise ToolchainError(f"Requires-Dist marker operator is unsupported: {operator}")
    lhs: object = _version_key(left) if version else left
    rhs: object = _version_key(right) if version else right
    return {
        "<": lhs < rhs,
        "<=": lhs <= rhs,
        ">": lhs > rhs,
        ">=": lhs >= rhs,
    }[operator]


class _MarkerParser:
    __slots__ = ("_tokens", "_offset", "_environment")

    def __init__(self, marker: str, environment: Mapping[str, str]) -> None:
        self._tokens = _marker_tokens(marker)
        self._offset = 0
        self._environment = environment

    def _peek(self, kind: str, value: str | None = None) -> bool:
        if self._offset >= len(self._tokens):
            return False
        token_kind, token_value = self._tokens[self._offset]
        return token_kind == kind and (value is None or token_value == value)

    def _take(self, kind: str, value: str | None = None) -> str:
        if not self._peek(kind, value):
            raise ToolchainError("Requires-Dist marker grammar is malformed")
        token = self._tokens[self._offset][1]
        self._offset += 1
        return token

    def _operand(self) -> tuple[str, str | None]:
        if self._peek("string"):
            raw = self._take("string")
            try:
                decoded = ast.literal_eval(raw)
            except (SyntaxError, ValueError) as exc:
                raise ToolchainError("Requires-Dist marker string is malformed") from exc
            if not isinstance(decoded, str):
                raise ToolchainError("Requires-Dist marker string is not text")
            return decoded, None
        name = self._take("name")
        if name not in _MARKER_VARIABLES:
            raise ToolchainError(f"Requires-Dist marker variable is unsupported: {name}")
        if name in {"platform_release", "platform_version"}:
            raise ToolchainError(
                f"Requires-Dist marker depends on unpinned host metadata: {name}"
            )
        return self._environment[name], name

    def _atom(self) -> bool:
        if self._peek("lparen"):
            self._take("lparen")
            value = self._or_expression()
            self._take("rparen")
            return value
        left, left_name = self._operand()
        operator = self._take("op")
        right, right_name = self._operand()
        version_variables = {
            "implementation_version",
            "python_full_version",
            "python_version",
        }
        return _marker_compare(
            left,
            operator,
            right,
            version=left_name in version_variables or right_name in version_variables,
        )

    def _and_expression(self) -> bool:
        value = self._atom()
        while self._peek("bool", "and"):
            self._take("bool", "and")
            # Parse even after a false result so malformed trailing input cannot
            # hide behind Python's boolean short-circuit semantics.
            right = self._atom()
            value = value and right
        return value

    def _or_expression(self) -> bool:
        value = self._and_expression()
        while self._peek("bool", "or"):
            self._take("bool", "or")
            right = self._and_expression()
            value = value or right
        return value

    def evaluate(self) -> bool:
        value = self._or_expression()
        if self._offset != len(self._tokens):
            raise ToolchainError("Requires-Dist marker has trailing input")
        return value


def _parse_requires_dist(value: str) -> tuple[str, frozenset[str], str | None]:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ToolchainError("installed Requires-Dist value is malformed")
    requirement, separator, marker = value.partition(";")
    match = _REQUIREMENT_HEAD_RE.match(requirement)
    if match is None:
        raise ToolchainError(f"installed Requires-Dist head is unsupported: {value!r}")
    name = _canonical_distribution_name(match.group("name"))
    extras_value = match.group("extras")
    extras = frozenset(
        _canonical_distribution_name(item.strip())
        for item in extras_value.split(",")
    ) if extras_value else frozenset()
    return name, extras, marker.strip() if separator else None


def _derive_metadata_dependency_graph(
    target_id: str,
    metadata_by_name: Mapping[str, bytes],
) -> dict[str, list[str]]:
    """Resolve active dependency edges from the exact locked METADATA bytes."""

    expected_names = set(metadata_by_name)
    roots = {_root_name(root) for root in EXPECTED_ROOTS}
    if not roots <= expected_names:
        raise ToolchainError("installed METADATA graph is missing a root")
    parsed: dict[str, list[tuple[str, frozenset[str], str | None]]] = {}
    for name, raw in metadata_by_name.items():
        message = email.parser.BytesParser().parsebytes(raw)
        parsed[name] = [
            _parse_requires_dist(item)
            for item in (message.get_all("Requires-Dist", []) or [])
        ]

    environment = _target_marker_environment(target_id)
    selected_extras: dict[str, set[str]] = {name: set() for name in expected_names}
    reachable = set(roots)
    graph: dict[str, set[str]] = {name: set() for name in expected_names}
    frontier = list(sorted(roots))
    while frontier:
        owner = frontier.pop()
        active_extra_values = ["", *sorted(selected_extras[owner])]
        for dependency, propagated_extras, marker in parsed[owner]:
            active = marker is None
            if marker is not None:
                active = any(
                    _MarkerParser(marker, {**environment, "extra": extra}).evaluate()
                    for extra in active_extra_values
                )
            if not active:
                continue
            if dependency not in expected_names:
                raise ToolchainError(
                    f"installed METADATA dependency closure is incomplete: {owner}->{dependency}"
                )
            graph[owner].add(dependency)
            changed = dependency not in reachable
            reachable.add(dependency)
            before = len(selected_extras[dependency])
            selected_extras[dependency].update(propagated_extras)
            if changed or len(selected_extras[dependency]) != before:
                frontier.append(dependency)
    if reachable != expected_names:
        raise ToolchainError(
            "installed METADATA graph has unreachable rows: "
            f"{sorted(expected_names - reachable)!r}"
        )
    return {name: sorted(graph[name]) for name in sorted(graph)}


def _static_distribution_probe(
    generation: Path, expected_names: Sequence[str]
) -> list[dict[str, str]]:
    expected = set(expected_names)
    found: dict[str, dict[str, str]] = {}
    for metadata in sorted(generation.rglob("*.dist-info/METADATA")):
        message = email.parser.BytesParser().parsebytes(metadata.read_bytes())
        raw_name = message.get("Name")
        version = message.get("Version")
        if not isinstance(raw_name, str) or not isinstance(version, str):
            raise ToolchainError(f"installed METADATA identity is incomplete: {metadata}")
        name = _canonical_distribution_name(raw_name)
        if name not in expected:
            continue
        if name in found:
            raise ToolchainError(f"duplicate installed distribution metadata: {name}")
        found[name] = {"name": name, "version": version, "path": str(metadata.parent)}
    if set(found) != expected:
        raise ToolchainError(
            f"static installed distribution denominator differs: missing={sorted(expected-set(found))!r}"
        )
    return [found[name] for name in sorted(found)]


def _record_closure(
    generation: Path, target: Mapping[str, Any], python: Path | None
) -> tuple[list[dict[str, Any]], str]:
    expected = {row["name"]: row for row in target["distributions"]}
    probes = (
        _distribution_probe(python, sorted(expected))
        if python is not None
        else _static_distribution_probe(generation, sorted(expected))
    )
    observed_names = [row.get("name") for row in probes if isinstance(row, dict)]
    if observed_names != sorted(expected):
        raise ToolchainError("installed distribution denominator differs from the policy")
    output: list[dict[str, Any]] = []
    generation_resolved = generation.resolve(strict=True)
    parsed_distributions: list[dict[str, Any]] = []
    owners: dict[str, list[dict[str, Any]]] = {}
    metadata_by_name: dict[str, bytes] = {}
    requires_dist_by_name: dict[str, list[str]] = {}
    site_roots: set[Path] = set()
    for probe in probes:
        name = probe["name"]
        row = expected[name]
        if probe.get("version") != row["version"]:
            raise ToolchainError(f"installed distribution version differs: {name}")
        dist_info = Path(probe.get("path", "")).resolve(strict=True)
        if not _path_is_within(dist_info, generation_resolved) or not dist_info.name.endswith(".dist-info"):
            raise ToolchainError(f"distribution metadata escapes the generation: {name}")
        metadata = dist_info / "METADATA"
        record = dist_info / "RECORD"
        metadata_bytes = metadata.read_bytes()
        if _sha256_bytes(metadata_bytes) != row["metadata_sha256"]:
            raise ToolchainError(f"installed METADATA differs from the locked wheel: {name}")
        metadata_by_name[name] = metadata_bytes
        metadata_message = email.parser.BytesParser().parsebytes(metadata_bytes)
        requires_dist_by_name[name] = sorted(
            metadata_message.get_all("Requires-Dist", []) or []
        )
        record_entries: list[dict[str, Any]] = []
        with record.open("r", encoding="utf-8", newline="") as stream:
            parsed_rows = list(csv.reader(stream))
        if not parsed_rows:
            raise ToolchainError(f"installed RECORD is empty: {name}")
        site_root = dist_info.parent
        site_roots.add(site_root)
        seen_paths: set[str] = set()
        for ordinal, parsed in enumerate(parsed_rows):
            if len(parsed) != 3 or not parsed[0] or parsed[0] in seen_paths:
                raise ToolchainError(f"invalid/duplicate RECORD row: {name}:{ordinal}")
            seen_paths.add(parsed[0])
            candidate = (site_root / parsed[0]).resolve(strict=True)
            if not _path_is_within(candidate, generation_resolved):
                raise ToolchainError(f"RECORD path escapes generation: {name}:{parsed[0]}")
            info = candidate.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ToolchainError(f"RECORD path is not a unique ordinary file: {candidate}")
            actual_hash = _sha256_file(candidate)
            expected_hash = ""
            if parsed[1]:
                expected_hash = _decode_record_hash(parsed[1], f"{name}:{parsed[0]}")
            expected_size: int | None = None
            if parsed[2]:
                try:
                    expected_size = int(parsed[2])
                except ValueError as exc:
                    raise ToolchainError(f"RECORD size is invalid: {name}:{parsed[0]}") from exc
            relative = candidate.relative_to(generation_resolved).as_posix()
            entry = {
                "path": relative,
                "expected_sha256": expected_hash,
                "expected_size": expected_size,
                "observed_sha256": actual_hash,
                "observed_size": info.st_size,
            }
            record_entries.append(entry)
            owners.setdefault(relative, []).append(entry)
        record_entries.sort(key=lambda item: item["path"])
        parsed_distributions.append(
            {
                "name": name,
                "version": row["version"],
                "metadata_sha256": row["metadata_sha256"],
                "record_sha256": _sha256_file(record),
                "entries": record_entries,
            }
        )

    # Wheels occasionally install colliding non-module data paths (notably docs/).
    # A final path is admitted only when its bytes are one of the exact hashes claimed
    # by its locked RECORD owners.  The collision cardinality is committed into every
    # owning distribution's fold, so replay cannot silently change the winning wheel.
    for relative, path_owners in owners.items():
        allowed_hashes = {
            entry["expected_sha256"] for entry in path_owners if entry["expected_sha256"]
        }
        observed_hashes = {entry["observed_sha256"] for entry in path_owners}
        if len(observed_hashes) != 1:
            raise ToolchainError(f"RECORD owners observe different bytes: {relative}")
        observed_hash = next(iter(observed_hashes))
        if allowed_hashes and observed_hash not in allowed_hashes:
            raise ToolchainError(f"RECORD content hash is not owned by a locked wheel: {relative}")
        allowed_sizes = {
            entry["expected_size"] for entry in path_owners if entry["expected_size"] is not None
        }
        observed_sizes = {entry["observed_size"] for entry in path_owners}
        if len(observed_sizes) != 1:
            raise ToolchainError(f"RECORD owners observe different sizes: {relative}")
        if allowed_sizes and next(iter(observed_sizes)) not in allowed_sizes:
            raise ToolchainError(f"RECORD content size is not owned by a locked wheel: {relative}")
        for entry in path_owners:
            entry["collision_owner_count"] = len(path_owners)

    # A tree self-digest is an integrity checksum, not provenance.  Close the
    # importable Python denominator independently: every ordinary file below an
    # admitted site-packages root must be named by at least one locked wheel
    # RECORD.  Automatic startup hooks are forbidden even if a future wheel were
    # to claim one, because ``-I`` does not suppress sitecustomize processing.
    owned_paths = set(owners)
    for site_root in sorted(site_roots):
        for candidate in sorted(site_root.rglob("*")):
            info = candidate.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            relative = candidate.relative_to(generation_resolved).as_posix()
            if candidate.name.casefold() in _FORBIDDEN_AUTOLOAD_BASENAMES or (
                candidate.suffix.casefold() == ".pth"
            ):
                raise ToolchainError(
                    f"automatic Python startup path is forbidden: {relative}"
                )
            if relative not in owned_paths:
                raise ToolchainError(
                    f"importable generation path is not owned by a locked wheel RECORD: {relative}"
                )

    target_id = target.get("id")
    if not isinstance(target_id, str):
        raise ToolchainError("target id is missing during METADATA replay")
    derived_graph = _derive_metadata_dependency_graph(target_id, metadata_by_name)
    policy_graph = {
        row["name"]: list(row["dependencies"])
        for row in target["distributions"]
    }
    if derived_graph != policy_graph:
        differing = sorted(
            name for name in policy_graph if policy_graph[name] != derived_graph.get(name)
        )
        raise ToolchainError(
            "policy dependency graph differs from locked METADATA: "
            f"{differing!r}"
        )

    for parsed in parsed_distributions:
        entries = parsed.pop("entries")
        parsed["record_file_count"] = len(entries)
        parsed["record_closure_sha256"] = _sha256_bytes(_canonical_bytes(entries))
        parsed["requires_dist_sha256"] = _sha256_bytes(
            _canonical_bytes(requires_dist_by_name[parsed["name"]])
        )
        parsed["active_dependency_names"] = derived_graph[parsed["name"]]
        output.append(parsed)
    output.sort(key=lambda item: item["name"])
    return output, _sha256_bytes(_canonical_bytes(output))


def _codesign_identity(path: Path) -> dict[str, Any]:
    if sys.platform != "darwin" or not Path("/usr/bin/codesign").exists():
        return {"status": "NOT_APPLICABLE", "identifier": "", "cdhash": "", "cdhash_full": ""}
    completed = subprocess.run(
        ["/usr/bin/codesign", "-d", "--verbose=4", str(path)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=30,
    )
    if completed.returncode != 0:
        raise ToolchainError("managed interpreter has no replayable Darwin CodeDirectory")
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    cdhash = values.get("CDHash", "")
    full = values.get("CandidateCDHashFull sha256", "")
    identifier = values.get("Identifier", "")
    if not re.fullmatch(r"[0-9a-f]{40}", cdhash) or not SHA256_RE.fullmatch(full) or not identifier:
        raise ToolchainError("managed interpreter Darwin CodeDirectory fields are incomplete")
    return {"status": "PRESENT", "identifier": identifier, "cdhash": cdhash, "cdhash_full": full}


def _windows_pe_identity(path: Path) -> dict[str, Any]:
    """Read non-authoritative PE structure; native NT custody is still required."""

    size = path.stat().st_size
    with path.open("rb") as stream:
        dos = stream.read(64)
        if len(dos) != 64 or dos[:2] != b"MZ":
            raise ToolchainError("Windows managed executable lacks a DOS/PE header")
        pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
        if pe_offset < 64 or pe_offset > size - 26:
            raise ToolchainError("Windows managed executable PE offset is invalid")
        stream.seek(pe_offset)
        header = stream.read(26)
    if len(header) != 26 or header[:4] != b"PE\0\0":
        raise ToolchainError("Windows managed executable PE signature is invalid")
    machine, sections, _timestamp, _symbols, _symbol_count, optional_size, characteristics = (
        struct.unpack_from("<HHIIIHH", header, 4)
    )
    optional_magic = struct.unpack_from("<H", header, 24)[0]
    if machine != 0x8664 or sections < 1 or optional_size < 2 or optional_magic != 0x20B:
        raise ToolchainError("Windows managed executable is not PE32+ AMD64")
    return {
        "status": "STRUCTURAL_ONLY_PENDING_NATIVE_NT_CUSTODY",
        "pe_machine": "AMD64",
        "pe_machine_code": machine,
        "pe_optional_header_magic": optional_magic,
        "pe_section_count": sections,
        "pe_characteristics": characteristics,
        "native_reparse_tag": "REQUIRED_AT_PRODUCTION_ADMISSION",
        "native_alternate_streams": "REQUIRED_AT_PRODUCTION_ADMISSION",
        "native_extended_attributes": "REQUIRED_AT_PRODUCTION_ADMISSION",
        "native_security_descriptor": "REQUIRED_AT_PRODUCTION_ADMISSION",
    }


def _platform_binary_identity(path: Path, target_id: str) -> dict[str, Any]:
    if target_id == "windows-amd64":
        return _windows_pe_identity(path)
    return {
        "status": "NOT_WINDOWS",
        "pe_machine": "",
        "pe_machine_code": 0,
        "pe_optional_header_magic": 0,
        "pe_section_count": 0,
        "pe_characteristics": 0,
        "native_reparse_tag": "NOT_APPLICABLE",
        "native_alternate_streams": "NOT_APPLICABLE",
        "native_extended_attributes": "NOT_APPLICABLE",
        "native_security_descriptor": "NOT_APPLICABLE",
    }


def _interpreter_identity(
    staging_python: Path, final_python: Path, target_id: str
) -> dict[str, Any]:
    info = staging_python.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ToolchainError("materialized interpreter is not a unique ordinary file")
    probe = probe_interpreter(staging_python)
    core = {
        "absolute_path": str(final_python),
        "sha256": _sha256_file(staging_python),
        "byte_count": info.st_size,
        "version": probe["version"],
        "implementation": probe["implementation"],
        "no_link": True,
        "owner_uid": info.st_uid,
        "mode_octal": "0555",
        "base_prefix": probe["base_prefix"],
        "code_directory": _codesign_identity(staging_python),
        "platform_binary_identity": _platform_binary_identity(staging_python, target_id),
    }
    core["closure_sha256"] = _sha256_bytes(_canonical_bytes(core))
    return core


def _ordinary_tree_manifest(root: Path, *, exclude_receipt: bool = True) -> tuple[int, str]:
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if exclude_receipt and relative == RECEIPT_NAME:
            continue
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ToolchainError(f"generation contains a symlink: {relative}")
        if stat.S_ISDIR(info.st_mode):
            if info.st_mode & 0o022:
                raise ToolchainError(f"generation directory remains group/world writable: {relative}")
            try:
                directory_xattrs = os.listxattr(path, follow_symlinks=False)
            except (AttributeError, NotImplementedError):
                directory_xattrs = []
            if directory_xattrs:
                raise ToolchainError(
                    f"generation directory has extended attributes: {relative}:{directory_xattrs!r}"
                )
            rows.append(
                {
                    "kind": "DIRECTORY",
                    "path": relative,
                    "mode_octal": format(stat.S_IMODE(info.st_mode), "04o"),
                }
            )
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ToolchainError(f"generation contains non-ordinary/hardlinked content: {relative}")
        if info.st_mode & 0o022:
            raise ToolchainError(f"generation file remains group/world writable: {relative}")
        try:
            xattrs = os.listxattr(path, follow_symlinks=False)
        except (AttributeError, NotImplementedError):
            xattrs = []
        if xattrs:
            raise ToolchainError(f"generation file has extended attributes: {relative}:{xattrs!r}")
        rows.append(
            {
                "kind": "FILE",
                "path": relative,
                "sha256": _sha256_file(path),
                "size": info.st_size,
                "mode_octal": format(stat.S_IMODE(info.st_mode), "04o"),
            }
        )
    return len(rows), _sha256_bytes(_canonical_bytes(rows))


def _freeze_tree(root: Path) -> None:
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ToolchainError(f"refusing to freeze symlink: {path}")
        if stat.S_ISDIR(info.st_mode):
            path.chmod(0o555)
        elif stat.S_ISREG(info.st_mode):
            path.chmod(0o555 if info.st_mode & 0o111 else 0o444)
        else:
            raise ToolchainError(f"refusing to freeze non-ordinary path: {path}")


def _write_requirements(path: Path, target: Mapping[str, Any]) -> None:
    lines = [
        f"{row['requirement']} --hash=sha256:{row['sha256']}"
        for row in target["distributions"]
    ]
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def _record_hash_field(path: Path) -> str:
    digest = bytes.fromhex(_sha256_file(path))
    return "sha256=" + base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _remove_bytecode(root: Path) -> None:
    for path in sorted(root.rglob("*.pyc")):
        path.unlink()
    for directory in sorted(root.rglob("__pycache__"), key=lambda item: len(item.parts), reverse=True):
        try:
            directory.rmdir()
        except OSError as exc:
            raise ToolchainError(f"bytecode cache directory is not empty: {directory}") from exc


def _relocate_generation_text(staging: Path, destination: Path) -> None:
    """Rewrite venv-authored absolute staging paths and reconcile RECORD hashes.

    Python/pip console scripts and activation files embed the absolute venv path.
    Atomic publication necessarily changes that path, so this deterministic pass
    happens before publication and then rewrites every owning RECORD row.
    """

    old = str(staging).encode("utf-8")
    new = str(destination).encode("utf-8")
    if len(old) != len(new):
        raise ToolchainError("staging and destination paths must have equal byte length")
    changed: set[Path] = set()
    records: list[Path] = []
    for path in sorted(staging.rglob("*")):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            continue
        if path.name == "RECORD" and path.parent.name.endswith(".dist-info"):
            records.append(path)
            continue
        data = path.read_bytes()
        if old not in data:
            continue
        # Equal-length replacement also supports pip's Windows .exe launchers,
        # whose embedded shebang is carried in an otherwise binary file.
        path.write_bytes(data.replace(old, new))
        changed.add(path.resolve(strict=True))
    for record in records:
        site_root = record.parent.parent
        with record.open("r", encoding="utf-8", newline="") as stream:
            rows = list(csv.reader(stream))
        touched = False
        for row in rows:
            if len(row) != 3:
                raise ToolchainError(f"malformed RECORD during relocation: {record}")
            try:
                candidate = (site_root / row[0]).resolve(strict=True)
            except FileNotFoundError:
                # Bytecode generated while bootstrapping pip is intentionally removed;
                # it is outside the locked EVM distribution denominator.
                continue
            except RuntimeError as exc:
                raise ToolchainError(f"RECORD path loop during relocation: {record}:{row[0]}") from exc
            if candidate in changed:
                row[1] = _record_hash_field(candidate)
                row[2] = str(candidate.stat().st_size)
                touched = True
        if touched:
            with record.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.writer(stream, lineterminator="\n")
                writer.writerows(rows)
    # Staging paths are never valid runtime authority after publication.
    for path in sorted(staging.rglob("*")):
        if path.is_file() and old in path.read_bytes():
            raise ToolchainError(f"staging path remained after relocation: {path}")


def _receipt_payload(receipt: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(receipt)
    payload.pop("receipt_sha256", None)
    return payload


def _create_staging_directory(destination: Path) -> Path:
    """Create a non-authoritative sibling with the exact final path byte length."""

    basename_bytes = len(destination.name.encode("utf-8"))
    if basename_bytes < 2 or len(destination.name) != basename_bytes:
        raise ToolchainError("generation basename must be non-empty ASCII")
    for _ in range(64):
        candidate_name = "." + secrets.token_hex(basename_bytes)[: basename_bytes - 1]
        candidate = destination.with_name(candidate_name)
        try:
            candidate.mkdir(mode=0o700)
        except FileExistsError:
            continue
        if len(str(candidate).encode("utf-8")) != len(str(destination).encode("utf-8")):
            candidate.rmdir()
            raise ToolchainError("staging path length invariant failed")
        return candidate
    raise ToolchainError("could not allocate a unique staging generation")


def _seal_receipt(payload: Mapping[str, Any]) -> dict[str, Any]:
    receipt = dict(payload)
    receipt["receipt_sha256"] = _sha256_bytes(_canonical_bytes(receipt))
    return receipt


def _load_receipt(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        receipt = _plain_dict(json.loads(raw), "managed EVM Python receipt")
    except (FileNotFoundError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ToolchainError("managed EVM Python receipt is missing or malformed") from exc
    if raw != _pretty_bytes(receipt):
        raise ToolchainError("managed EVM Python receipt is not canonical pretty JSON")
    observed = receipt.get("receipt_sha256")
    if not isinstance(observed, str) or observed != _sha256_bytes(_canonical_bytes(_receipt_payload(receipt))):
        raise ToolchainError("managed EVM Python receipt self-digest mismatch")
    return receipt


def validate_generation(
    policy: Mapping[str, Any],
    policy_sha256: str,
    target_id: str,
    generation: os.PathLike[str] | str,
    *,
    runtime_probe: bool = True,
) -> dict[str, Any]:
    target = select_target(policy, target_id)
    requested_root = Path(generation).expanduser()
    if requested_root.is_symlink():
        raise ToolchainError("managed generation launch authority cannot be a symlink")
    root = requested_root.resolve(strict=True)
    root_info = root.lstat()
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_IMODE(root_info.st_mode) != 0o555:
        raise ToolchainError("managed generation root is not an immutable directory")
    try:
        root_xattrs = os.listxattr(root, follow_symlinks=False)
    except (AttributeError, NotImplementedError):
        root_xattrs = []
    if root_xattrs:
        raise ToolchainError("managed generation root has extended attributes")
    receipt = _load_receipt(root / RECEIPT_NAME)
    required_top = {
        "schema",
        "receipt_sha256",
        "policy_sha256",
        "target_id",
        "interpreter",
        "wheel_cache_entries",
        "wheel_cache_closure_sha256",
        "installed_distributions",
        "installed_distribution_closure_sha256",
        "solc",
        "solc_select_state",
        "provided_tool_ids",
        "pip_install_invariants",
        "execution_boundary",
        "generation_payload_file_count",
        "generation_payload_manifest_sha256",
    }
    _exact_keys(receipt, required_top, "managed EVM Python receipt")
    if (
        receipt["schema"] != RECEIPT_SCHEMA
        or receipt["policy_sha256"] != policy_sha256
        or receipt["target_id"] != target_id
        or receipt["provided_tool_ids"] != list(PROVIDED_TOOL_IDS)
    ):
        raise ToolchainError("managed EVM Python receipt authority differs")
    expected_pip = {
        "ambient_configuration": "NEUTRALIZED",
        "dependency_graph": "COMMITTED_COMPLETE_CLOSURE",
        "metadata_graph": "LOCKED_REQUIRES_DIST_MARKERS_EXTRAS_AND_CONSTRAINTS_REPLAYED",
        "index_access": "DISABLED_NO_INDEX_PRIVATE_FIND_LINKS",
        "hash_mode": "ALL_REQUIREMENTS_EXACT_AND_HASHED",
        "artifact_mode": "WHEELS_ONLY_NO_SDIST",
        "dependency_resolution": "DISABLED_NO_DEPS",
    }
    if receipt["pip_install_invariants"] != expected_pip:
        raise ToolchainError("offline pip receipt invariants differ")
    if receipt["execution_boundary"] != {
        "mode": "BOOTSTRAP_EVIDENCE_NOT_PRODUCTION_AUTHORITY",
        "production_authority_schema": NATIVE_RESULT_SCHEMA,
    }:
        raise ToolchainError("provider receipt execution boundary differs")
    interpreter = _plain_dict(receipt["interpreter"], "receipt interpreter")
    _exact_keys(
        interpreter,
        {
            "absolute_path",
            "sha256",
            "byte_count",
            "version",
            "implementation",
            "no_link",
            "owner_uid",
            "mode_octal",
            "base_prefix",
            "code_directory",
            "platform_binary_identity",
            "closure_sha256",
        },
        "receipt interpreter",
    )
    code_directory = _plain_dict(interpreter["code_directory"], "interpreter CodeDirectory")
    _exact_keys(
        code_directory,
        {"status", "identifier", "cdhash", "cdhash_full"},
        "interpreter CodeDirectory",
    )
    if target_id == "macos-arm64":
        if (
            code_directory["status"] != "PRESENT"
            or not isinstance(code_directory["identifier"], str)
            or not code_directory["identifier"]
            or re.fullmatch(r"[0-9a-f]{40}", code_directory["cdhash"]) is None
            or SHA256_RE.fullmatch(code_directory["cdhash_full"]) is None
        ):
            raise ToolchainError("Darwin interpreter CodeDirectory authority is incomplete")
    elif code_directory != {
        "status": "NOT_APPLICABLE",
        "identifier": "",
        "cdhash": "",
        "cdhash_full": "",
    }:
        raise ToolchainError("non-Darwin interpreter carries an invalid CodeDirectory claim")
    try:
        expected_python = root / Path(interpreter.get("absolute_path", "")).relative_to(root)
    except ValueError as exc:
        raise ToolchainError("receipt interpreter path escapes this generation") from exc
    if Path(interpreter.get("absolute_path", "")) != expected_python:
        raise ToolchainError("receipt interpreter path is not this exact generation")
    platform_binary_identity = _plain_dict(
        interpreter["platform_binary_identity"], "interpreter platform binary identity"
    )
    if platform_binary_identity != _platform_binary_identity(expected_python, target_id):
        raise ToolchainError("managed interpreter platform binary identity differs")
    info = expected_python.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o555
        or info.st_size != interpreter.get("byte_count")
        or _sha256_file(expected_python) != interpreter.get("sha256")
    ):
        raise ToolchainError("managed interpreter identity no longer replays")
    try:
        interpreter_version = [int(item) for item in interpreter.get("version", "").split(".")]
    except (AttributeError, ValueError) as exc:
        raise ToolchainError("managed interpreter version receipt is malformed") from exc
    if (
        interpreter.get("implementation") != "CPython"
        or interpreter_version[:2] != [3, 12]
        or len(interpreter_version) != 3
        or interpreter_version[2] < 1
        or interpreter.get("no_link") is not True
        or interpreter.get("mode_octal") != "0555"
    ):
        raise ToolchainError("managed interpreter receipt is not CPython >=3.12.1,<3.13")
    core = dict(interpreter)
    closure = core.pop("closure_sha256", None)
    if closure != _sha256_bytes(_canonical_bytes(core)):
        raise ToolchainError("managed interpreter closure digest mismatch")
    if runtime_probe:
        probe = probe_interpreter(expected_python)
        if probe["version"] != interpreter.get("version") or probe["implementation"] != "CPython":
            raise ToolchainError("managed interpreter runtime probe differs")
    installed, installed_fold = _record_closure(
        root, target, expected_python if runtime_probe else None
    )
    if (
        installed != receipt["installed_distributions"]
        or installed_fold != receipt["installed_distribution_closure_sha256"]
    ):
        raise ToolchainError("installed distribution/RECORD closure differs")
    wheel_entries = receipt["wheel_cache_entries"]
    if not isinstance(wheel_entries, list):
        raise ToolchainError("wheel cache entries are malformed")
    expected_wheels = [
        {"filename": row["filename"], "sha256": row["sha256"], "size": row["size"]}
        for row in target["distributions"]
    ]
    expected_wheels.sort(key=lambda row: row["filename"])
    if (
        wheel_entries != expected_wheels
        or receipt["wheel_cache_closure_sha256"]
        != _sha256_bytes(_canonical_bytes(expected_wheels))
    ):
        raise ToolchainError("wheel cache receipt closure differs from policy")
    solc = _plain_dict(receipt["solc"], "receipt solc")
    _exact_keys(
        solc,
        {
            "version",
            "long_version",
            "absolute_path",
            "sha256",
            "byte_count",
            "binary_format",
            "architectures",
            "minimum_os",
            "provider_index_sha256",
        },
        "receipt solc",
    )
    compiler = target["compiler"]
    expected_solc_receipt = {
        "version": compiler["version"],
        "long_version": compiler["long_version"],
        "absolute_path": str(root / compiler["install_relative_path"]),
        "sha256": compiler["sha256"],
        "byte_count": compiler["size"],
        "binary_format": compiler["binary_format"],
        "architectures": compiler["architectures"],
        "minimum_os": compiler["minimum_os"],
        "provider_index_sha256": compiler["provider_index_sha256"],
    }
    if solc != expected_solc_receipt:
        raise ToolchainError("managed solc receipt differs from policy")
    solc_path = Path(solc.get("absolute_path", ""))
    expected_solc = root / target["compiler"]["install_relative_path"]
    if solc_path != expected_solc:
        raise ToolchainError("receipt solc path is not this exact generation")
    solc_info = expected_solc.lstat()
    if (
        not stat.S_ISREG(solc_info.st_mode)
        or solc_info.st_nlink != 1
        or stat.S_IMODE(solc_info.st_mode) != 0o555
        or solc_info.st_size != target["compiler"]["size"]
        or _sha256_file(expected_solc) != target["compiler"]["sha256"]
    ):
        raise ToolchainError("managed solc identity no longer replays")
    solc_select_state = _plain_dict(receipt["solc_select_state"], "solc-select state")
    _exact_keys(
        solc_select_state,
        {"mode", "version", "compiler_absolute_path", "network_resolution"},
        "solc-select state",
    )
    if solc_select_state != {
        "mode": "DIRECT_LOCKED_COMPILER_NO_MUTABLE_GLOBAL_STATE",
        "version": "0.8.26",
        "compiler_absolute_path": str(expected_solc),
        "network_resolution": "FORBIDDEN",
    }:
        raise ToolchainError("solc-select direct compiler state differs")
    receipt_info = (root / RECEIPT_NAME).lstat()
    if (
        not stat.S_ISREG(receipt_info.st_mode)
        or receipt_info.st_nlink != 1
        or stat.S_IMODE(receipt_info.st_mode) != 0o444
    ):
        raise ToolchainError("managed receipt file mode/type differs")
    try:
        receipt_xattrs = os.listxattr(root / RECEIPT_NAME, follow_symlinks=False)
    except (AttributeError, NotImplementedError):
        receipt_xattrs = []
    if receipt_xattrs:
        raise ToolchainError("managed receipt file has extended attributes")
    count, fold = _ordinary_tree_manifest(root)
    if (
        count != receipt["generation_payload_file_count"]
        or fold != receipt["generation_payload_manifest_sha256"]
    ):
        raise ToolchainError("managed generation tree manifest differs")
    return receipt


def _managed_generation_binding(
    policy_path: os.PathLike[str] | str,
    generation: os.PathLike[str] | str,
) -> dict[str, Any]:
    """Replay and bind the entire immutable generation for native handoff."""

    policy_file = Path(policy_path).expanduser().resolve(strict=True)
    policy, policy_sha256 = load_policy(policy_file)
    requested = Path(generation).expanduser()
    if requested.is_symlink():
        raise ToolchainError("managed generation handoff cannot use a symlink alias")
    root = requested.resolve(strict=True)
    receipt_hint = _load_receipt(root / RECEIPT_NAME)
    target_id = receipt_hint.get("target_id")
    if not isinstance(target_id, str) or target_id not in SUPPORTED_TARGETS:
        raise ToolchainError("managed generation handoff target is unsupported")
    receipt = validate_generation(
        policy, policy_sha256, target_id, root, runtime_probe=False
    )
    root_info = root.lstat()
    receipt_path = root / RECEIPT_NAME
    receipt_raw = receipt_path.read_bytes()
    interpreter_path = Path(str(receipt["interpreter"]["absolute_path"]))
    if not _path_is_within(interpreter_path, root):
        raise ToolchainError("managed interpreter escapes the generation handoff")
    slither_modules = sorted(
        candidate.resolve(strict=True)
        for candidate in root.rglob("slither/__init__.py")
        if candidate.is_file()
    )
    if len(slither_modules) != 1 or not _path_is_within(slither_modules[0], root):
        raise ToolchainError(
            "managed generation has no unique Slither module origin"
        )
    script_name = "slither.exe" if target_id == "windows-amd64" else "slither"
    slither_scripts = sorted(
        candidate.resolve(strict=True)
        for candidate in root.rglob(script_name)
        if candidate.is_file()
        and candidate.parent.name in {"bin", "Scripts"}
    )
    if len(slither_scripts) != 1 or not _path_is_within(slither_scripts[0], root):
        raise ToolchainError(
            "managed generation has no unique Slither console entrypoint"
        )
    slither_distribution = [
        row for row in receipt["installed_distributions"]
        if row.get("name") == "slither-analyzer"
    ]
    if len(slither_distribution) != 1:
        raise ToolchainError(
            "managed generation Slither distribution receipt is ambiguous"
        )
    unsigned = {
        "schema": "plamen.managed-evm-generation-execution-authority.v1",
        "policy_absolute_path": str(policy_file),
        "policy_sha256": policy_sha256,
        "target_id": target_id,
        "generation_absolute_path": str(root),
        "generation_device": int(root_info.st_dev),
        "generation_inode": int(root_info.st_ino),
        "generation_mode_octal": format(stat.S_IMODE(root_info.st_mode), "04o"),
        "receipt_sha256": str(receipt["receipt_sha256"]),
        "receipt_file_sha256": _sha256_bytes(receipt_raw),
        "receipt_byte_count": len(receipt_raw),
        "generation_payload_file_count": int(
            receipt["generation_payload_file_count"]
        ),
        "generation_payload_manifest_sha256": str(
            receipt["generation_payload_manifest_sha256"]
        ),
        "installed_distribution_closure_sha256": str(
            receipt["installed_distribution_closure_sha256"]
        ),
        "slither_version": str(slither_distribution[0]["version"]),
        "slither_record_closure_sha256": str(
            slither_distribution[0]["record_closure_sha256"]
        ),
        "slither_module_origin": str(slither_modules[0]),
        "slither_module_sha256": _sha256_file(slither_modules[0]),
        "slither_entrypoint": str(slither_scripts[0]),
        "slither_entrypoint_sha256": _sha256_file(slither_scripts[0]),
        "interpreter_absolute_path": str(interpreter_path),
        "interpreter_sha256": str(receipt["interpreter"]["sha256"]),
    }
    return {
        **unsigned,
        "binding_sha256": _sha256_bytes(_canonical_bytes(unsigned)),
    }


def _managed_slither_record_projection(
    generation: Path,
    *,
    module_origin: Path,
    entrypoint: Path,
) -> dict[str, Any]:
    """Rebuild the exact Slither RECORD/content denominator without import.

    The managed generation is a Linux guest closure on Darwin, so importing it
    through the host interpreter would be both incorrect and unsafe.  This
    descriptor-free projection is valid only after ``validate_generation`` has
    replayed the immutable, single-link tree; every member is then rehashed
    below and checked against the installed wheel RECORD.
    """

    metadata_candidates: list[tuple[Path, bytes]] = []
    for metadata in sorted(generation.rglob("*.dist-info/METADATA")):
        try:
            raw = metadata.read_bytes()
            message = email.parser.BytesParser().parsebytes(raw)
            name = _canonical_distribution_name(str(message.get("Name") or ""))
        except (OSError, ValueError) as exc:
            raise ToolchainError(
                "managed Slither METADATA denominator is unreadable"
            ) from exc
        if name == "slither-analyzer":
            metadata_candidates.append((metadata, raw))
    if len(metadata_candidates) != 1:
        raise ToolchainError("managed Slither METADATA is absent or ambiguous")

    metadata_path, _metadata_raw = metadata_candidates[0]
    site_root = metadata_path.parent.parent
    record_path = metadata_path.parent / "RECORD"
    try:
        record_raw = record_path.read_bytes()
        record_rows = list(
            csv.reader(record_raw.decode("utf-8", "strict").splitlines())
        )
    except (OSError, UnicodeError, csv.Error) as exc:
        raise ToolchainError("managed Slither RECORD is unreadable") from exc
    if not record_rows or any(len(row) != 3 for row in record_rows):
        raise ToolchainError("managed Slither RECORD is malformed")

    record_relative = record_path.relative_to(site_root).as_posix()
    normalized_rows: list[dict[str, Any]] = []
    record_entries: list[tuple[str, str, int]] = []
    content_entries: list[tuple[str, str, int]] = []
    observed_paths: set[str] = set()
    observed_casefolded: set[str] = set()
    observed_identities: set[tuple[int, int]] = set()
    module_digest = ""
    entrypoint_digest = ""
    entrypoint_bytes = 0

    for name, record_digest, record_size in record_rows:
        if (
            not name
            or "\\" in name
            or name.startswith("/")
            or name.endswith("/")
            or "//" in name
            or "\x00" in name
            or re.search(r"%2e|%2f|%5c", name, re.IGNORECASE)
        ):
            raise ToolchainError("managed Slither RECORD path is invalid")
        parts = tuple(name.split("/"))
        parent_count = 0
        while parent_count < len(parts) and parts[parent_count] == "..":
            parent_count += 1
        if (
            any(part in {"", "."} or ":" in part for part in parts)
            or any(part == ".." for part in parts[parent_count:])
            or name in observed_paths
            or name.casefold() in observed_casefolded
        ):
            raise ToolchainError(
                "managed Slither RECORD contains an unsafe or aliased path"
            )
        observed_paths.add(name)
        observed_casefolded.add(name.casefold())

        candidate = (site_root / name).resolve(strict=True)
        if not _path_is_within(candidate, generation):
            raise ToolchainError("managed Slither RECORD path escapes generation")
        info = candidate.lstat()
        identity = (int(info.st_dev), int(info.st_ino))
        if (
            not stat.S_ISREG(info.st_mode)
            or candidate.is_symlink()
            or info.st_nlink != 1
            or identity in observed_identities
        ):
            raise ToolchainError(
                "managed Slither RECORD member is not a unique ordinary file"
            )
        observed_identities.add(identity)
        digest = _sha256_file(candidate)
        size = int(info.st_size)
        if record_digest:
            if not record_digest.startswith("sha256=") or not record_size.isdigit():
                raise ToolchainError("managed Slither RECORD digest is malformed")
            expected = base64.urlsafe_b64encode(
                bytes.fromhex(digest)
            ).decode("ascii").rstrip("=")
            if record_digest != f"sha256={expected}" or int(record_size) != size:
                raise ToolchainError("managed Slither RECORD member differs")
            normalized_size: int | None = int(record_size)
        elif (
            name != record_relative
            and "__pycache__" not in PurePosixPath(name).parts
            and not name.endswith((".pyc", ".pyo"))
        ):
            raise ToolchainError(
                "managed Slither RECORD member lacks wheel authentication"
            )
        else:
            normalized_size = None
        normalized_rows.append(
            {"path": name, "hash": record_digest, "bytes": normalized_size}
        )
        record_entries.append((name, digest, size))
        scripts_member = parent_count > 0
        if (
            not scripts_member
            and "__pycache__" not in PurePosixPath(name).parts
            and not name.endswith((".pyc", ".pyo"))
        ):
            content_entries.append((name, digest, size))
        if candidate == module_origin:
            module_digest = digest
        if candidate == entrypoint:
            entrypoint_digest = digest
            entrypoint_bytes = size

    if (
        record_relative not in observed_paths
        or not content_entries
        or not module_digest
        or not entrypoint_digest
        or len(observed_identities) != len(record_entries)
    ):
        raise ToolchainError("managed Slither RECORD denominator is incomplete")
    normalized_rows.sort(key=lambda row: str(row["path"]))
    record_entries.sort(key=lambda row: row[0])
    content_entries.sort(key=lambda row: row[0])

    def fold(entries: Sequence[tuple[str, str, int]]) -> tuple[str, str, int]:
        content = hashlib.sha256()
        paths = hashlib.sha256()
        total = 0
        for relative, digest, size in entries:
            encoded = relative.encode("utf-8")
            paths.update(len(encoded).to_bytes(8, "big"))
            paths.update(encoded)
            content.update(len(encoded).to_bytes(8, "big"))
            content.update(encoded)
            content.update(bytes.fromhex(digest))
            content.update(size.to_bytes(8, "big"))
            total += size
        return content.hexdigest(), paths.hexdigest(), total

    content_digest, content_paths, content_bytes = fold(content_entries)
    record_digest, record_paths, record_bytes = fold(record_entries)
    return {
        "distribution_files_sha256": content_digest,
        "distribution_path_set_sha256": content_paths,
        "distribution_file_count": len(content_entries),
        "distribution_bytes": content_bytes,
        "record_member_files_sha256": record_digest,
        "record_member_path_set_sha256": record_paths,
        "record_member_file_count": len(record_entries),
        "record_member_native_identity_count": len(observed_identities),
        "record_member_bytes": record_bytes,
        "record_path": record_relative,
        "record_sha256": _sha256_bytes(record_raw),
        "record_bytes": len(record_raw),
        "record_row_count": len(normalized_rows),
        "record_normalized_rows_sha256": _sha256_bytes(
            _canonical_bytes(normalized_rows)
        ),
        "module_origin": str(module_origin),
        "module_sha256": module_digest,
        "entrypoint_path": str(entrypoint),
        "entrypoint_sha256": entrypoint_digest,
        "entrypoint_bytes": entrypoint_bytes,
    }


def managed_evm_slither_snapshot_observation(
    authority: object,
) -> Mapping[str, Any]:
    """Return replayed evidence for an audit-snapshot Slither projection.

    This mapping grants no launch authority.  Its opaque input is revalidated
    against the complete immutable generation on every call, so audit snapshot
    capture can compare caller-retained bytes without importing guest code.
    """

    binding = dict(require_managed_evm_generation_authority(authority))
    generation = Path(binding["generation_absolute_path"])
    module_origin = Path(binding["slither_module_origin"])
    entrypoint = Path(binding["slither_entrypoint"])
    closure = _managed_slither_record_projection(
        generation,
        module_origin=module_origin,
        entrypoint=entrypoint,
    )
    interpreter = Path(binding["interpreter_absolute_path"])
    interpreter_info = interpreter.lstat()
    if (
        closure["module_sha256"] != binding["slither_module_sha256"]
        or closure["entrypoint_sha256"]
        != binding["slither_entrypoint_sha256"]
        or _sha256_file(interpreter) != binding["interpreter_sha256"]
        or not stat.S_ISREG(interpreter_info.st_mode)
        or interpreter_info.st_nlink != 1
    ):
        raise ToolchainError("managed Slither snapshot observation drifted")
    observation = {
        "managed_generation_binding_sha256": binding["binding_sha256"],
        "interpreter_implementation": "CPython",
        "interpreter_version": str(
            _load_receipt(generation / RECEIPT_NAME)["interpreter"]["version"]
        ),
        "interpreter_path": str(interpreter),
        "interpreter_sha256": binding["interpreter_sha256"],
        "interpreter_bytes": int(interpreter_info.st_size),
        "version": binding["slither_version"],
        **closure,
    }
    return types.MappingProxyType(observation)


def _require_managed_generation_shell(
    authority: object,
) -> dict[str, Any]:
    if (
        type(authority) is not ManagedEVMGenerationAuthority
        or authority not in _LIVE_MANAGED_GENERATIONS
    ):
        raise ToolchainError(
            "managed EVM generation authority is absent, forged, or expired"
        )
    try:
        registered = _LIVE_MANAGED_GENERATIONS[authority]
        binding = dict(authority._binding)
        current = (
            authority._policy_path,
            authority._generation_root,
            _sha256_bytes(_canonical_bytes(binding)),
        )
    except (AttributeError, KeyError, TypeError) as exc:
        raise ToolchainError("managed EVM generation authority is malformed") from exc
    if registered != current:
        raise ToolchainError("managed EVM generation authority changed after issuance")
    return binding


def issue_managed_evm_generation_authority(
    policy_path: os.PathLike[str] | str,
    generation: os.PathLike[str] | str,
) -> ManagedEVMGenerationAuthority:
    """Issue an opaque handoff only after complete immutable-tree replay."""

    binding = _managed_generation_binding(policy_path, generation)
    authority = object.__new__(ManagedEVMGenerationAuthority)
    object.__setattr__(authority, "_policy_path", binding["policy_absolute_path"])
    object.__setattr__(
        authority, "_generation_root", binding["generation_absolute_path"]
    )
    object.__setattr__(
        authority, "_binding", types.MappingProxyType(dict(binding))
    )
    _LIVE_MANAGED_GENERATIONS[authority] = (
        authority._policy_path,
        authority._generation_root,
        _sha256_bytes(_canonical_bytes(binding)),
    )
    require_managed_evm_generation_authority(authority)
    return authority


def require_managed_evm_generation_authority(
    authority: object,
) -> Mapping[str, Any]:
    """Replay an opaque generation handoff and return an immutable binding."""

    binding = _require_managed_generation_shell(authority)
    replayed = _managed_generation_binding(
        binding["policy_absolute_path"], binding["generation_absolute_path"]
    )
    if replayed != binding:
        raise ToolchainError("managed EVM generation changed after authority issuance")
    return types.MappingProxyType(dict(binding))


def bootstrap_provision_test_only(
    policy_path: os.PathLike[str] | str,
    python: os.PathLike[str] | str,
    generation: os.PathLike[str] | str,
    cache_root: os.PathLike[str] | str,
    *,
    project_root: os.PathLike[str] | str | None = None,
    offline: bool = False,
    dry_run: bool = False,
    confirm_test_only: bool = False,
) -> dict[str, Any]:
    """Bootstrap a generation without native custody; never production authority."""

    if not confirm_test_only and not dry_run:
        raise ToolchainError(
            "direct Python materialization is TEST_ONLY; production requires native custody"
        )
    if not dry_run and project_root is None:
        raise ToolchainError(
            "project_root is required before TEST_ONLY filesystem materialization"
        )

    policy, policy_sha256 = load_policy(policy_path)
    project = Path(project_root).expanduser().resolve(strict=True) if project_root else None
    base_python = Path(python).expanduser().resolve(strict=True)
    _assert_outside_project(base_python, project, "managed base interpreter")
    base_probe = probe_interpreter(base_python)
    target_id = detect_target(
        sys_platform=base_probe["sys_platform"], machine=base_probe["machine"]
    )
    target = select_target(policy, target_id)
    requested_destination = Path(generation).expanduser()
    requested_cache = Path(cache_root).expanduser()
    if requested_destination.is_symlink() or requested_cache.is_symlink():
        raise ToolchainError("generation and cache roots cannot be symlink aliases")
    destination = requested_destination.resolve()
    cache = requested_cache.resolve()
    _assert_outside_project(destination, project, "managed generation")
    _assert_outside_project(cache, project, "managed artifact cache")
    if _path_is_within(cache, destination) or _path_is_within(destination, cache):
        raise ToolchainError("cache and immutable generation must be disjoint")
    expected_suffix = ("generations", policy_sha256)
    if tuple(destination.parts[-2:]) != expected_suffix:
        raise ToolchainError(
            "generation path must end in generations/<exact-policy-sha256>"
        )
    if dry_run:
        return {
            "status": "DRY_RUN_READY",
            "policy_sha256": policy_sha256,
            "target_id": target_id,
            "generation": str(destination),
            "cache": str(cache),
            "distribution_count": len(target["distributions"]),
            "compiler": target["compiler"]["long_version"],
        }
    if destination.exists() or destination.is_symlink():
        return validate_generation(policy, policy_sha256, target_id, destination)

    cache_receipt = acquire_cache(policy, target_id, cache, offline=offline)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = _create_staging_directory(destination)
    try:
        _run(
            [str(base_python), "-I", "-B", "-m", "venv", "--copies", str(staging / "venv")],
            env=_clean_env(),
            cwd=destination.parent,
        )
        venv_python = _venv_python(staging, target_id)
        venv_probe = probe_interpreter(venv_python)
        if venv_probe["prefix"] != str(staging / "venv"):
            raise ToolchainError("venv interpreter prefix differs from the staged generation")
        requirements = staging / ".locked-requirements.txt"
        _write_requirements(requirements, target)
        cache_target = cache / target_id
        command = [
            str(venv_python),
            "-I",
            "-B",
            "-m",
            "pip",
            "--isolated",
            "install",
            "--no-index",
            f"--find-links={cache_target}",
            "--require-hashes",
            "--only-binary=:all:",
            "--no-deps",
            "--no-compile",
            "--requirement",
            str(requirements),
        ]
        _run(command, env=_clean_env(), timeout=600, cwd=staging)
        requirements.unlink()

        # pip's vendored standards implementation validates every active PEP 508
        # marker, requested extra, PEP 440 constraint, and installed version.  The
        # independent stdlib replay below then derives the active name graph from
        # the exact METADATA bytes; neither check can be replaced by policy edges.
        _run(
            [str(venv_python), "-I", "-B", "-m", "pip", "--isolated", "check"],
            env=_clean_env(),
            timeout=120,
            cwd=staging,
        )

        # ``venv`` bootstraps pip as a convenience, but pip is not part of the
        # reviewed EVM runtime closure.  Remove it before RECORD ownership is
        # closed so an ambient installer package cannot become executable input.
        _run(
            [
                str(venv_python),
                "-I",
                "-B",
                "-m",
                "pip",
                "--isolated",
                "uninstall",
                "--yes",
                "pip",
            ],
            env=_clean_env(),
            timeout=120,
            cwd=staging,
        )

        compiler = target["compiler"]
        solc_staging = staging / compiler["install_relative_path"]
        solc_staging.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copyfile(
            _cache_path(cache, target_id, compiler["filename"]), solc_staging
        )
        solc_staging.chmod(0o755)
        solc_probe = _run(
            [str(solc_staging), "--version"], env=_clean_env(), timeout=60, cwd=staging
        ).stdout
        if "Version: 0.8.26+commit.8a97fa7a" not in solc_probe:
            raise ToolchainError("managed solc runtime version probe differs")

        _remove_bytecode(staging)
        _relocate_generation_text(staging, destination)
        installed, installed_fold = _record_closure(staging, target, venv_python)
        wheel_entries = [
            {"filename": row["filename"], "sha256": row["sha256"], "size": row["size"]}
            for row in target["distributions"]
        ]
        wheel_entries.sort(key=lambda row: row["filename"])
        wheel_fold = _sha256_bytes(_canonical_bytes(wheel_entries))
        if wheel_fold == cache_receipt["closure_sha256"]:
            raise ToolchainError("wheel-only and wheel-plus-compiler closures must be distinct")

        final_python = _venv_python(destination, target_id)
        interpreter = _interpreter_identity(venv_python, final_python, target_id)
        final_solc = destination / compiler["install_relative_path"]
        solc_identity = {
            "version": compiler["version"],
            "long_version": compiler["long_version"],
            "absolute_path": str(final_solc),
            "sha256": compiler["sha256"],
            "byte_count": compiler["size"],
            "binary_format": compiler["binary_format"],
            "architectures": compiler["architectures"],
            "minimum_os": compiler["minimum_os"],
            "provider_index_sha256": compiler["provider_index_sha256"],
        }
        _freeze_tree(staging)
        # Receipt creation requires only the generation root to remain temporarily writable.
        staging.chmod(0o700)
        file_count, tree_fold = _ordinary_tree_manifest(staging)
        payload = {
            "schema": RECEIPT_SCHEMA,
            "policy_sha256": policy_sha256,
            "target_id": target_id,
            "interpreter": interpreter,
            "wheel_cache_entries": wheel_entries,
            "wheel_cache_closure_sha256": wheel_fold,
            "installed_distributions": installed,
            "installed_distribution_closure_sha256": installed_fold,
            "solc": solc_identity,
            "solc_select_state": {
                "mode": "DIRECT_LOCKED_COMPILER_NO_MUTABLE_GLOBAL_STATE",
                "version": "0.8.26",
                "compiler_absolute_path": str(final_solc),
                "network_resolution": "FORBIDDEN",
            },
            "provided_tool_ids": list(PROVIDED_TOOL_IDS),
            "pip_install_invariants": {
                "ambient_configuration": "NEUTRALIZED",
                "dependency_graph": "COMMITTED_COMPLETE_CLOSURE",
                "metadata_graph": "LOCKED_REQUIRES_DIST_MARKERS_EXTRAS_AND_CONSTRAINTS_REPLAYED",
                "index_access": "DISABLED_NO_INDEX_PRIVATE_FIND_LINKS",
                "hash_mode": "ALL_REQUIREMENTS_EXACT_AND_HASHED",
                "artifact_mode": "WHEELS_ONLY_NO_SDIST",
                "dependency_resolution": "DISABLED_NO_DEPS",
            },
            "execution_boundary": {
                "mode": "BOOTSTRAP_EVIDENCE_NOT_PRODUCTION_AUTHORITY",
                "production_authority_schema": NATIVE_RESULT_SCHEMA,
            },
            "generation_payload_file_count": file_count,
            "generation_payload_manifest_sha256": tree_fold,
        }
        receipt = _seal_receipt(payload)
        receipt_path = staging / RECEIPT_NAME
        receipt_path.write_bytes(_pretty_bytes(receipt))
        receipt_path.chmod(0o444)
        staging.chmod(0o555)
        os.replace(staging, destination)
        return validate_generation(policy, policy_sha256, target_id, destination)
    except BaseException:
        if staging.exists():
            for path in [staging, *staging.rglob("*")]:
                try:
                    path.chmod(0o700 if path.is_dir() else 0o600)
                except OSError:
                    pass
            shutil.rmtree(staging, ignore_errors=True)
        raise


def _validate_apple_guest_execution_authority(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    guest = _plain_dict(dict(value), "guest execution authority")
    _exact_keys(
        guest,
        {
            "schema",
            "platform",
            "architecture",
            "runtime_image_reference",
            "image_closure_sha256",
            "provider_admission_sha256",
            "rosetta_required",
            "rosetta_authority_sha256",
            "rootfs_readonly",
            "network_policy",
            "network_isolation_authority_sha256",
            "custody_receipt_sha256",
            "immutable_launch_authority",
            "population_zero_authority",
        },
        "guest execution authority",
    )
    if (
        guest["schema"] != APPLE_GUEST_CUSTODY_SCHEMA
        or guest["platform"] != "linux"
        or guest["architecture"] != "amd64"
        or guest["rosetta_required"] is not True
        or guest["rootfs_readonly"] is not True
        or guest["network_policy"] != "DENY_ALL"
        or guest["immutable_launch_authority"]
        != "PRIVATE_IMMUTABLE_PROJECTED_CLOSURE"
        or guest["population_zero_authority"] is not True
    ):
        raise ToolchainError("guest execution authority is not the exact Linux/Rosetta lane")
    image = guest.get("runtime_image_reference")
    if (
        not isinstance(image, str)
        or re.search(r"@sha256:[0-9a-f]{64}$", image) is None
        or any(char.isspace() for char in image)
    ):
        raise ToolchainError("guest runtime image is not digest pinned")
    for field in (
        "image_closure_sha256",
        "provider_admission_sha256",
        "rosetta_authority_sha256",
        "network_isolation_authority_sha256",
        "custody_receipt_sha256",
    ):
        _sha(guest.get(field), f"guest execution authority {field}")
    return guest


_NATIVE_TOOLCHAIN_TYPE_NAMES = (
    "ManagedEVMToolchainInitialAuthority",
    "ManagedEVMToolchainProvisionLease",
    "ManagedEVMToolchainProvisionTerminal",
)
_NATIVE_TOOLCHAIN_FUNCTION_NAMES = (
    "managed_evm_toolchain_runtime_identity",
    "prepare_managed_evm_toolchain_provision",
    "execute_managed_evm_toolchain_provision",
    "project_managed_evm_toolchain_terminal",
)


def _native_toolchain_bridge(
    native_initial_authority: object,
) -> tuple[types.ModuleType, type[Any], type[Any], Any, Any, Any, Any]:
    """Authenticate the installed extension surface without importing a substitute.

    Ordinary Python callbacks, mappings, module lookalikes, and TEST_ONLY extension
    builds are intentionally outside this boundary.  The initial authority is a
    non-constructible, one-shot native object published only after broker-v2
    installation/session authentication.
    """

    try:
        module_table = types.ModuleType.__getattribute__(sys, "__dict__").get("modules")
        if type(module_table) is not dict:
            raise TypeError
        module = module_table.get(NATIVE_BRIDGE_MODULE)
        if type(module) is not types.ModuleType:
            raise TypeError
        namespace = types.ModuleType.__getattribute__(module, "__dict__")
        spec = namespace.get("__spec__")
        if type(namespace) is not dict or type(spec) is not importlib.machinery.ModuleSpec:
            raise TypeError
        spec_namespace = object.__getattribute__(spec, "__dict__")
        loader = spec_namespace.get("loader")
        if type(loader) is not importlib.machinery.ExtensionFileLoader:
            raise TypeError
        loader_namespace = object.__getattribute__(loader, "__dict__")
        origin = spec_namespace.get("origin")
        metadata = (
            namespace.get("__name__"),
            namespace.get("__file__"),
            namespace.get("BROKER_V2_ABI_SCHEMA"),
            namespace.get("BROKER_V2_PRODUCTION_ACQUISITION"),
            spec_namespace.get("name"),
            origin,
            loader_namespace.get("name"),
            loader_namespace.get("path"),
        )
        if any(type(item) is not str or not item or "\x00" in item for item in metadata):
            raise TypeError
        (
            module_name,
            module_file,
            abi_schema,
            acquisition,
            spec_name,
            _origin,
            loader_name,
            loader_path,
        ) = metadata
        if (
            module_name != NATIVE_BRIDGE_MODULE
            or module_file != origin
            or spec_name != NATIVE_BRIDGE_MODULE
            or loader_name != NATIVE_BRIDGE_MODULE
            or loader_path != origin
            or abi_schema != NATIVE_BRIDGE_ABI
            or acquisition != "AVAILABLE_AUTHENTICATED_NATIVE_SESSION"
            or namespace.get("TEST_ONLY_BUILD") is not False
            or namespace.get("BROKER_V2_INITIAL_AUTHORITY_AVAILABLE") is not True
            or not any(str(origin).endswith(suffix) for suffix in importlib.machinery.EXTENSION_SUFFIXES)
        ):
            raise TypeError
        native_types = tuple(namespace.get(name) for name in _NATIVE_TOOLCHAIN_TYPE_NAMES)
        native_functions = tuple(
            namespace.get(name) for name in _NATIVE_TOOLCHAIN_FUNCTION_NAMES
        )
        if any(type(item) is not type for item in native_types) or any(
            type(item) is not types.BuiltinFunctionType
            or getattr(item, "__module__", None) != NATIVE_BRIDGE_MODULE
            or getattr(item, "__name__", None) != expected_name
            for expected_name, item in zip(
                _NATIVE_TOOLCHAIN_FUNCTION_NAMES, native_functions, strict=True
            )
        ):
            raise TypeError
        initial_type, lease_type, terminal_type = native_types
        for native_type in native_types:
            if (
                type.__getattribute__(native_type, "__module__") != NATIVE_BRIDGE_MODULE
                or type.__getattribute__(native_type, "__flags__") & (1 << 9)
            ):
                # ``Py_TPFLAGS_HEAPTYPE`` identifies Python-created/lookalike
                # types; the authority types must be static native types.
                raise TypeError
        initial = namespace.get("MANAGED_EVM_TOOLCHAIN_INITIAL_AUTHORITY")
        if type(initial) is not initial_type or native_initial_authority is not initial:
            raise TypeError
        runtime_identity, prepare, execute, project = native_functions
        return (
            module,
            lease_type,
            terminal_type,
            runtime_identity,
            prepare,
            execute,
            project,
        )
    except BaseException as exc:
        raise NativeToolchainUnavailable(
            "authenticated native managed-EVM toolchain bridge is unavailable"
        ) from exc


def _native_toolchain_runtime_binding(
    module: types.ModuleType,
    runtime_identity: Any,
    native_initial_authority: object,
) -> dict[str, Any]:
    origin = Path(str(module.__spec__.origin))
    if origin.is_symlink() or not origin.is_absolute():
        raise NativeToolchainUnavailable("native toolchain extension path is aliased")
    resolved = origin.resolve(strict=True)
    if resolved != origin:
        raise NativeToolchainUnavailable("native toolchain extension path drifted")
    info = resolved.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size < 1
        or info.st_size > 512 * 1024 * 1024
        or info.st_mode & 0o022
    ):
        raise NativeToolchainUnavailable("native toolchain extension file identity is unsafe")
    raw = runtime_identity(native_initial_authority)
    if type(raw) is not bytes or not raw or len(raw) > 64 * 1024:
        raise NativeToolchainUnavailable("native toolchain runtime identity is malformed")
    try:
        identity = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise NativeToolchainUnavailable(
            "native toolchain runtime identity is not JSON"
        ) from exc
    if type(identity) is not dict or raw != _canonical_bytes(identity):
        raise NativeToolchainUnavailable(
            "native toolchain runtime identity is not exact canonical JSON"
        )
    expected_keys = {
        "schema",
        "platform",
        "extension_path",
        "extension_sha256",
        "extension_byte_count",
        "native_deployment_receipt_sha256",
        "runtime_closure_sha256",
        "broker_peer_identity_sha256",
        "managed_toolchain_custody_sha256",
    }
    if set(identity) != expected_keys or identity.get("schema") != (
        "plamen.managed-evm-toolchain-runtime-identity.v1"
    ):
        raise NativeToolchainUnavailable("native toolchain runtime identity schema differs")
    platform_id = (
        "MACOS" if sys.platform == "darwin"
        else "WINDOWS" if sys.platform == "win32"
        else "LINUX" if sys.platform.startswith("linux")
        else "UNSUPPORTED"
    )
    for field in (
        "extension_sha256",
        "native_deployment_receipt_sha256",
        "runtime_closure_sha256",
        "broker_peer_identity_sha256",
        "managed_toolchain_custody_sha256",
    ):
        _sha(identity.get(field), f"native toolchain runtime {field}")
    if (
        identity.get("platform") != platform_id
        or identity.get("extension_path") != str(resolved)
        or identity.get("extension_sha256") != _sha256_file(resolved)
        or identity.get("extension_byte_count") != info.st_size
    ):
        raise NativeToolchainUnavailable(
            "native toolchain runtime identity differs from the loaded extension"
        )
    return identity


_NATIVE_GUEST_MANAGED_FUNCTION_NAMES = (
    "native_guest_managed_evm_runtime_identity",
    "native_guest_managed_evm_bootstrap_inputs",
    "prepare_native_guest_managed_evm_provision",
    "execute_native_guest_managed_evm_provision",
    "project_native_guest_managed_evm_terminal",
)


def _native_guest_managed_bridge(
    native_runtime_authority: object,
) -> tuple[types.ModuleType, tuple[Any, ...], dict[str, Any]]:
    """Admit the narrow role-2 managed-provision surface and its identity.

    The POSIX runtime owns the opaque bundle registry and exact static native
    types.  This consumer never receives or rediscovers INITIAL_AUTHORITY.
    """

    try:
        import posix_backend_execution as runtime

        functions = tuple(
            types.ModuleType.__getattribute__(runtime, "__dict__").get(name)
            for name in _NATIVE_GUEST_MANAGED_FUNCTION_NAMES
        )
        if any(not callable(function) for function in functions):
            raise TypeError
        raw = functions[0](native_runtime_authority)
        if type(raw) is not bytes or not raw or len(raw) > 64 * 1024:
            raise TypeError
        identity = json.loads(raw)
        if type(identity) is not dict or raw != _canonical_bytes(identity):
            raise TypeError
        base = {
            "schema", "platform", "extension_path", "extension_sha256",
            "extension_byte_count", "native_deployment_receipt_sha256",
            "runtime_closure_sha256", "broker_peer_identity_sha256",
            "managed_toolchain_custody_sha256",
        }
        expected = base | (
            {
                "guest_execution_authority", "managed_python_sha256",
                "managed_python_size", "native_interpreter_probe",
            }
            if identity.get("platform") == "MACOS" else set()
        )
        if (
            set(identity) != expected
            or identity.get("schema")
            != "plamen.managed-evm-toolchain-runtime-identity.v1"
        ):
            raise TypeError
        platform_id = (
            "MACOS" if sys.platform == "darwin"
            else "WINDOWS" if sys.platform == "win32"
            else "LINUX" if sys.platform.startswith("linux")
            else "UNSUPPORTED"
        )
        extension = Path(str(identity.get("extension_path") or ""))
        if (
            identity.get("platform") != platform_id
            or not extension.is_absolute()
            or extension.is_symlink()
            or extension.resolve(strict=True) != extension
        ):
            raise TypeError
        info = extension.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or not 1 <= info.st_size <= 512 * 1024 * 1024
            or info.st_mode & 0o022
            or identity.get("extension_byte_count") != info.st_size
            or identity.get("extension_sha256") != _sha256_file(extension)
        ):
            raise TypeError
        for field in (
            "extension_sha256", "native_deployment_receipt_sha256",
            "runtime_closure_sha256", "broker_peer_identity_sha256",
            "managed_toolchain_custody_sha256",
        ):
            _sha(identity.get(field), f"native managed runtime {field}")
        if identity.get("platform") == "MACOS":
            _sha(
                identity.get("managed_python_sha256"),
                "native managed runtime managed_python_sha256",
            )
            managed_python_size = identity.get("managed_python_size")
            if (
                isinstance(managed_python_size, bool)
                or not isinstance(managed_python_size, int)
                or not 1 <= managed_python_size <= 512 * 1024 * 1024
            ):
                raise TypeError
        bootstrap_raw = functions[1](native_runtime_authority)
        if (
            type(bootstrap_raw) is not bytes
            or not bootstrap_raw
            or len(bootstrap_raw) > 64 * 1024
        ):
            raise TypeError
        bootstrap = json.loads(bootstrap_raw)
        if (
            type(bootstrap) is not dict
            or bootstrap_raw != _canonical_bytes(bootstrap)
            or set(bootstrap) != {
                "schema", "guest_execution_authority",
                "managed_python_sha256", "managed_python_size",
                "managed_runtime_identity_sha256", "native_interpreter_probe",
            }
            or bootstrap.get("schema")
            != "plamen.native-guest-managed-evm-bootstrap-inputs.v1"
            or bootstrap.get("managed_runtime_identity_sha256")
            != _sha256_bytes(raw)
            or bootstrap.get("managed_python_sha256")
            != identity.get("managed_python_sha256")
            or bootstrap.get("managed_python_size")
            != identity.get("managed_python_size")
            or bootstrap.get("native_interpreter_probe")
            != identity.get("native_interpreter_probe")
            or bootstrap.get("guest_execution_authority")
            != identity.get("guest_execution_authority")
        ):
            raise TypeError
        validate_interpreter_probe(
            _plain_dict(
                bootstrap["native_interpreter_probe"],
                "native managed interpreter probe",
            )
        )
        _validate_apple_guest_execution_authority(
            _plain_dict(
                bootstrap["guest_execution_authority"],
                "native managed guest execution authority",
            )
        )
    except BaseException as exc:
        raise NativeToolchainUnavailable(
            "opaque native guest managed-EVM provision authority is unavailable"
        ) from exc
    return runtime, functions, {"identity": identity, "bootstrap": bootstrap}


def build_native_provision_plan(
    policy_path: os.PathLike[str] | str,
    interpreter_probe: Mapping[str, Any],
    generation: os.PathLike[str] | str,
    cache_root: os.PathLike[str] | str,
    *,
    acquisition_receipt_path: os.PathLike[str] | str,
    project_root: os.PathLike[str] | str | None = None,
    guest_execution_authority: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the immutable request passed to a native custody executor.

    This function is read-only.  The interpreter probe is opaque evidence produced
    by the native capability; Python validates its shape/version but does not launch
    the interpreter in the production path.
    """

    policy, policy_sha256 = load_policy(policy_path)
    probe = validate_interpreter_probe(interpreter_probe)
    target_id = detect_target(sys_platform=probe["sys_platform"], machine=probe["machine"])
    guest = _validate_apple_guest_execution_authority(guest_execution_authority)
    if target_id != "linux-x86_64":
        raise ToolchainError(
            "Apple Container production custody requires the linux-x86_64 policy target"
        )
    target = select_target(policy, target_id)
    requested_destination = Path(generation).expanduser()
    requested_cache = Path(cache_root).expanduser()
    if requested_destination.is_symlink() or requested_cache.is_symlink():
        raise ToolchainError("generation and cache roots cannot be symlink aliases")
    destination = requested_destination.resolve()
    cache = requested_cache.resolve()
    if project_root is None:
        raise ToolchainError("project_root is required for production path exclusion")
    project = Path(project_root).expanduser().resolve(strict=True)
    acquisition_fd, acquisition_receipt, acquisition_info = _open_native_regular_input(
        acquisition_receipt_path, "signed acquisition receipt"
    )
    try:
        acquisition_receipt_sha256 = _sha256_descriptor(acquisition_fd)
        _revalidate_native_descriptor(
            acquisition_fd,
            acquisition_receipt,
            acquisition_info,
            "signed acquisition receipt",
        )
    finally:
        os.close(acquisition_fd)
    _assert_outside_project(destination, project, "managed generation")
    _assert_outside_project(cache, project, "managed artifact cache")
    if _path_is_within(cache, destination) or _path_is_within(destination, cache):
        raise ToolchainError("cache and immutable generation must be disjoint")
    if tuple(destination.parts[-2:]) != ("generations", policy_sha256):
        raise ToolchainError("generation path must end in generations/<exact-policy-sha256>")
    artifacts = []
    for row in target["distributions"]:
        artifacts.append(
            {
                "kind": "PYPI_WHEEL",
                "filename": row["filename"],
                "sha256": row["sha256"],
                "size": row["size"],
                "source_url": row["source_url"],
            }
        )
    compiler = target["compiler"]
    artifacts.append(
        {
            "kind": "SOLIDITY_COMPILER",
            "filename": compiler["filename"],
            "sha256": compiler["sha256"],
            "size": compiler["size"],
            "source_url": compiler["source_url"],
        }
    )
    artifacts.sort(key=lambda row: (row["kind"], row["filename"]))
    payload = {
        "schema": NATIVE_PLAN_SCHEMA,
        "policy_absolute_path": str(Path(policy_path).expanduser().resolve(strict=True)),
        "policy_sha256": policy_sha256,
        "target_id": target_id,
        "interpreter_probe": probe,
        "guest_execution_authority": guest,
        "guest_execution_authority_sha256": _sha256_bytes(_canonical_bytes(guest)),
        "generation_absolute_path": str(destination),
        "cache_absolute_path": str(cache),
        "project_root_absolute_path": str(project),
        "acquisition_receipt_absolute_path": str(acquisition_receipt),
        "acquisition_receipt_sha256": acquisition_receipt_sha256,
        "acquisition_receipt_byte_count": acquisition_info.st_size,
        "artifacts": artifacts,
        "artifact_set_sha256": _sha256_bytes(_canonical_bytes(artifacts)),
        "pip_invocation": {
            "global_flags": ["--isolated"],
            "install_flags": [
                "--no-index",
                "--find-links=<PRIVATE_CACHE>",
                "--require-hashes",
                "--only-binary=:all:",
                "--no-deps",
                "--no-compile",
            ],
            "ambient_configuration": "NEUTRALIZED",
        },
        "immutable_target": {
            "files": "0444_OR_0555_EXECUTABLE",
            "directories": "0555",
            "links": "FORBIDDEN",
            "xattrs": "FORBIDDEN",
            "publication": "ATOMIC_CONTENT_ADDRESSED_GENERATION",
        },
        "required_terminal_receipts": [
            "NATIVE_CAPABILITY",
            "NETWORK_AUTHORITY",
            "ACQUISITION",
            "MATERIALIZATION",
            "SOLC_PROBE",
            "PYPI_METADATA_GRAPH",
            "SNAPSHOT_BOUND_MATERIALIZATION",
        ],
    }
    plan = dict(payload)
    plan["plan_sha256"] = _sha256_bytes(_canonical_bytes(payload))
    return plan


def validate_native_provision_result(
    plan: Mapping[str, Any], result: Mapping[str, Any]
) -> dict[str, Any]:
    """TEST_ONLY structural replay of projected terminal data.

    A plain mapping can never carry native authority.  Production calls this
    validator only on bytes projected from the opaque native terminal, and keeps
    that terminal as the returned authority object.
    """

    plan = _plain_dict(dict(plan), "native provision plan")
    result = _plain_dict(dict(result), "native provision result")
    expected_plan_keys = {
        "schema",
        "plan_sha256",
        "policy_absolute_path",
        "policy_sha256",
        "target_id",
        "interpreter_probe",
        "guest_execution_authority",
        "guest_execution_authority_sha256",
        "generation_absolute_path",
        "cache_absolute_path",
        "project_root_absolute_path",
        "acquisition_receipt_absolute_path",
        "acquisition_receipt_sha256",
        "acquisition_receipt_byte_count",
        "artifacts",
        "artifact_set_sha256",
        "pip_invocation",
        "immutable_target",
        "required_terminal_receipts",
    }
    _exact_keys(plan, expected_plan_keys, "native provision plan")
    plan_payload = dict(plan)
    observed_plan_sha256 = plan_payload.pop("plan_sha256")
    if (
        plan["schema"] != NATIVE_PLAN_SCHEMA
        or observed_plan_sha256 != _sha256_bytes(_canonical_bytes(plan_payload))
    ):
        raise ToolchainError("native provision plan self-digest differs")
    if plan.get("target_id") == "windows-amd64":
        raise ToolchainError(
            "WINDOWS_NATIVE_METADATA_UNAVAILABLE: reparse tags, alternate streams, "
            "extended attributes, and security descriptors require a native collector"
        )
    _exact_keys(
        result,
        {
            "schema",
            "result_sha256",
            "plan_sha256",
            "guest_execution_authority_sha256",
            "native_capability_receipt_sha256",
            "network_authority_receipt_sha256",
            "acquisition_terminal_receipt_sha256",
            "materialization_terminal_receipt_sha256",
            "solc_probe_terminal_receipt_sha256",
            "pypi_metadata_graph_terminal_receipt_sha256",
            "snapshot_bound_materialization_receipt_sha256",
            "source_provenance_sha256",
            "pre_replay_sha256",
            "post_replay_sha256",
            "provider_receipt_sha256",
            "provider_receipt_file_sha256",
            "generation_payload_manifest_sha256",
            "complete",
        },
        "native provision result",
    )
    if result["schema"] != NATIVE_RESULT_SCHEMA or result["complete"] is not True:
        raise ToolchainError("native provision did not return a complete terminal result")
    result_payload = dict(result)
    observed_result_sha256 = result_payload.pop("result_sha256")
    if observed_result_sha256 != _sha256_bytes(_canonical_bytes(result_payload)):
        raise ToolchainError("native provision result self-digest differs")
    if result["plan_sha256"] != plan.get("plan_sha256"):
        raise ToolchainError("native provision result is bound to a different plan")
    if result["guest_execution_authority_sha256"] != plan.get(
        "guest_execution_authority_sha256"
    ):
        raise ToolchainError("native provision result is bound to a different guest custody")
    for field in (
        "native_capability_receipt_sha256",
        "result_sha256",
        "guest_execution_authority_sha256",
        "network_authority_receipt_sha256",
        "acquisition_terminal_receipt_sha256",
        "materialization_terminal_receipt_sha256",
        "solc_probe_terminal_receipt_sha256",
        "pypi_metadata_graph_terminal_receipt_sha256",
        "snapshot_bound_materialization_receipt_sha256",
        "source_provenance_sha256",
        "pre_replay_sha256",
        "post_replay_sha256",
        "provider_receipt_sha256",
        "provider_receipt_file_sha256",
        "generation_payload_manifest_sha256",
    ):
        _sha(result.get(field), f"native provision result {field}")
    if (
        result["acquisition_terminal_receipt_sha256"]
        != plan["acquisition_receipt_sha256"]
    ):
        raise ToolchainError(
            "native acquisition terminal differs from the retained signed receipt"
        )
    if (
        result["pre_replay_sha256"] != plan.get("artifact_set_sha256")
        or result["post_replay_sha256"] != plan.get("artifact_set_sha256")
    ):
        raise ToolchainError("native pre/post artifact replay differs from the exact plan")
    policy, policy_sha256 = load_policy(plan["policy_absolute_path"])
    if policy_sha256 != plan["policy_sha256"]:
        raise ToolchainError("native plan policy changed before terminal validation")
    receipt = validate_generation(
        policy,
        policy_sha256,
        plan["target_id"],
        plan["generation_absolute_path"],
        runtime_probe=False,
    )
    receipt_path = Path(plan["generation_absolute_path"]) / RECEIPT_NAME
    if (
        result["provider_receipt_sha256"] != receipt["receipt_sha256"]
        or result["provider_receipt_file_sha256"] != _sha256_file(receipt_path)
        or result["generation_payload_manifest_sha256"]
        != receipt["generation_payload_manifest_sha256"]
    ):
        raise ToolchainError("native result does not bind the replayed provider receipt")
    return {
        "schema": "plamen.managed-evm-python-native-result-shape-replay.v1",
        "authority": "TEST_ONLY_DATA_VALIDATION_NOT_PRODUCTION_ADMISSION",
        "plan_sha256": plan["plan_sha256"],
        "native_result": result,
        "provider_receipt": receipt,
    }


def provision(
    policy_path: os.PathLike[str] | str,
    python: os.PathLike[str] | str,
    generation: os.PathLike[str] | str,
    cache_root: os.PathLike[str] | str,
    *,
    acquisition_receipt_path: os.PathLike[str] | str,
    project_root: os.PathLike[str] | str | None = None,
    dry_run: bool = False,
    native_interpreter_probe: Mapping[str, Any] | None = None,
    guest_execution_authority: Mapping[str, Any] | None = None,
    native_executor: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
    native_runtime_authority: object | None = None,
) -> object:
    """Production provision through a native custody capability.

    No production filesystem or network mutation occurs in Python.  Production
    accepts only the installed extension's non-constructible, one-shot authority.
    The extension receives canonical immutable request bytes and returns an opaque
    terminal whose projection is replayed here.  The terminal itself, not a plain
    mapping or digest, is the return value and downstream authority.
    """

    if dry_run:
        return bootstrap_provision_test_only(
            policy_path,
            python,
            generation,
            cache_root,
            project_root=project_root,
            dry_run=True,
        )
    if project_root is None:
        raise ToolchainError("project_root is required before production mutation")
    if native_executor is not None:
        raise ToolchainError(
            "caller-supplied native executors are TEST_ONLY data and cannot grant production authority"
        )
    if native_runtime_authority is None:
        raise ToolchainError(
            "opaque native runtime provision capability is required before mutation"
        )
    runtime, functions, runtime_binding = _native_guest_managed_bridge(
        native_runtime_authority
    )
    bootstrap = runtime_binding["bootstrap"]
    authenticated_probe = _plain_dict(
        bootstrap["native_interpreter_probe"],
        "native managed interpreter probe",
    )
    authenticated_guest = _plain_dict(
        bootstrap["guest_execution_authority"],
        "native managed guest execution authority",
    )
    if (
        native_interpreter_probe is not None
        and dict(native_interpreter_probe) != authenticated_probe
    ):
        raise ToolchainError(
            "caller interpreter probe differs from native runtime custody"
        )
    if (
        guest_execution_authority is not None
        and dict(guest_execution_authority) != authenticated_guest
    ):
        raise ToolchainError(
            "caller guest execution authority differs from native runtime custody"
        )
    plan = build_native_provision_plan(
        policy_path,
        authenticated_probe,
        generation,
        cache_root,
        acquisition_receipt_path=acquisition_receipt_path,
        project_root=project_root,
        guest_execution_authority=authenticated_guest,
    )
    runtime_identity, bootstrap_inputs, prepare, execute, project = functions
    request_bytes = _canonical_bytes(plan)
    opened: list[tuple[int, Path, os.stat_result, str]] = []
    try:
        policy_fd, policy_resolved, policy_info = _open_native_regular_input(
            plan["policy_absolute_path"], "managed EVM policy"
        )
        opened.append((policy_fd, policy_resolved, policy_info, "managed EVM policy"))
        project_fd, project_resolved, project_info = _open_native_directory(
            plan["project_root_absolute_path"], "audited project root"
        )
        opened.append((project_fd, project_resolved, project_info, "audited project root"))
        cache_fd, cache_resolved, cache_info = _open_native_directory(
            plan["cache_absolute_path"], "managed artifact cache"
        )
        opened.append((cache_fd, cache_resolved, cache_info, "managed artifact cache"))
        generations_fd, generations_resolved, generations_info = _open_native_directory(
            Path(plan["generation_absolute_path"]).parent,
            "managed generations root",
        )
        opened.append(
            (generations_fd, generations_resolved, generations_info, "managed generations root")
        )
        acquisition_fd, acquisition_resolved, acquisition_info = (
            _open_native_regular_input(
                plan["acquisition_receipt_absolute_path"],
                "signed acquisition receipt",
            )
        )
        opened.append(
            (
                acquisition_fd,
                acquisition_resolved,
                acquisition_info,
                "signed acquisition receipt",
            )
        )
        identities = {(info.st_dev, info.st_ino) for _, _, info, _ in opened}
        if len(identities) != len(opened):
            raise ToolchainError("native managed-EVM descriptors are aliased")
        if (
            _sha256_descriptor(acquisition_fd) != plan["acquisition_receipt_sha256"]
            or acquisition_info.st_size != plan["acquisition_receipt_byte_count"]
        ):
            raise ToolchainError("signed acquisition receipt changed after plan construction")
        for descriptor, path, info, label in opened:
            _revalidate_native_descriptor(descriptor, path, info, label)
        lease = prepare(
            native_runtime_authority,
            request_bytes,
            policy_fd,
            project_fd,
            cache_fd,
            generations_fd,
            acquisition_fd,
        )
        for descriptor, path, info, label in opened:
            _revalidate_native_descriptor(descriptor, path, info, label)
    finally:
        for descriptor, _path, _info, _label in reversed(opened):
            os.close(descriptor)
    if _native_guest_managed_bridge(native_runtime_authority)[:2] != (
        runtime, functions
    ):
        raise NativeToolchainUnavailable("native managed provision bridge changed")
    terminal = execute(native_runtime_authority, lease)
    projected = project(native_runtime_authority, terminal)
    if type(projected) is not bytes or not projected or len(projected) > 1024 * 1024:
        raise NativeToolchainUnavailable("native toolchain terminal projection is malformed")
    try:
        result = json.loads(projected)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise NativeToolchainUnavailable(
            "native toolchain terminal projection is not JSON"
        ) from exc
    if projected != _canonical_bytes(result):
        raise NativeToolchainUnavailable(
            "native toolchain terminal projection is not exact canonical JSON"
        )
    validate_native_provision_result(plan, _plain_dict(result, "native terminal projection"))
    if (
        _native_guest_managed_bridge(native_runtime_authority)[:2]
        != (runtime, functions)
        or _native_guest_managed_bridge(native_runtime_authority)[2]
        != runtime_binding
    ):
        raise NativeToolchainUnavailable(
            "native toolchain bridge/runtime identity changed during provision"
        )
    return terminal


def provision_managed_evm_generation_authority(
    policy_path: os.PathLike[str] | str,
    python: os.PathLike[str] | str,
    managed_root: os.PathLike[str] | str,
    *,
    acquisition_receipt_path: os.PathLike[str] | str,
    project_root: os.PathLike[str] | str,
    native_interpreter_probe: Mapping[str, Any] | None = None,
    guest_execution_authority: Mapping[str, Any] | None = None,
    native_runtime_authority: object,
) -> ManagedEVMGenerationAuthority:
    """Provision and issue one exact content-addressed generation capability.

    ``managed_root`` is an explicit driver/setup authority, never a home/PATH
    discovery result.  Its pre-existing private ``cache`` and ``generations``
    directories are retained by the native provider; the generation leaf is
    derived only from the reviewed policy digest.
    """

    root_input = Path(managed_root).expanduser()
    if root_input.is_symlink():
        raise ToolchainError("managed EVM root cannot be a symlink alias")
    root = root_input.resolve(strict=True)
    if not root.is_dir():
        raise ToolchainError("managed EVM root is not a directory")
    policy, policy_sha256 = load_policy(policy_path)
    del policy
    cache = root / "cache"
    generations = root / "generations"
    if (
        not cache.is_dir()
        or cache.is_symlink()
        or not generations.is_dir()
        or generations.is_symlink()
    ):
        raise ToolchainError(
            "managed EVM cache/generations custody roots are unavailable"
        )
    if os.name == "posix":
        for candidate, label in (
            (root, "managed EVM root"),
            (cache, "managed EVM cache"),
            (generations, "managed EVM generations"),
        ):
            info = candidate.lstat()
            if int(info.st_uid) != int(os.geteuid()) or stat.S_IMODE(
                info.st_mode
            ) & 0o077:
                raise ToolchainError(f"{label} is not private and owner-bound")
    generation = generations / policy_sha256
    provision(
        policy_path,
        python,
        generation,
        cache,
        acquisition_receipt_path=acquisition_receipt_path,
        project_root=project_root,
        native_interpreter_probe=native_interpreter_probe,
        guest_execution_authority=guest_execution_authority,
        native_runtime_authority=native_runtime_authority,
    )
    return issue_managed_evm_generation_authority(
        policy_path, generation
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--python", required=True)
    parser.add_argument("--generation", required=True)
    parser.add_argument("--cache", required=True)
    parser.add_argument("--project-root")
    parser.add_argument("--acquisition-receipt")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--test-only-bootstrap", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.test_only_bootstrap:
            result = bootstrap_provision_test_only(
                arguments.policy,
                arguments.python,
                arguments.generation,
                arguments.cache,
                project_root=arguments.project_root,
                offline=arguments.offline,
                dry_run=arguments.dry_run,
                confirm_test_only=True,
            )
        else:
            result = provision(
                arguments.policy,
                arguments.python,
                arguments.generation,
                arguments.cache,
                acquisition_receipt_path=arguments.acquisition_receipt,
                project_root=arguments.project_root,
                dry_run=arguments.dry_run,
            )
    except ToolchainError as exc:
        print(f"managed-evm-python-toolchain: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
