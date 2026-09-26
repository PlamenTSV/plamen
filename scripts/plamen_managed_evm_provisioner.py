#!/usr/bin/env python3
"""Offline, descriptor-rooted managed EVM wheel provisioner.

This file is baked into the Linux/arm64 guest as
``/usr/local/libexec/plamen-managed-evm-provisioner.py``.  It deliberately has
no acquisition or resolver feature: every wheel and every dependency edge is
already present in the authenticated policy and acquisition receipt.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import PurePosixPath
import re
import stat
import sys
import zipfile
from typing import Any, NoReturn


POLICY_SCHEMA = "plamen.managed-evm-offline-provision-policy.v1"
ACQUISITION_SCHEMA = "plamen.linux-arm64-managed-evm-acquisition-receipt.v1"
TERMINAL_SCHEMA = "plamen.managed-evm-offline-provision-terminal.v1"
TARGET = "linux-arm64"
PYTHON_PATH = "/usr/local/lib/plamen/python/bin/python3.12"
SLITHER_PATH = "/usr/local/lib/plamen/toolchains/managed-evm/bin/slither"
MAX_POLICY_BYTES = 2 * 1024 * 1024
MAX_RECEIPT_BYTES = 2 * 1024 * 1024
MAX_WHEELS = 128
MAX_WHEEL_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 768 * 1024 * 1024
MAX_ENTRIES = 100_000
_HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_WHEEL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,239}\.whl\Z", re.ASCII)


class ProvisionError(RuntimeError):
    pass


def _fail(code: str) -> NoReturn:
    raise ProvisionError(code)


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ProvisionError("NON_CANONICAL_JSON_MODEL") from exc


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _load_fd(fd: int, maximum: int, code: str) -> tuple[dict[str, Any], bytes]:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_size < 2 or info.st_size > maximum:
        _fail(code)
    raw = os.pread(fd, info.st_size, 0)
    if len(raw) != info.st_size or raw.endswith(b"\n"):
        _fail(code)
    try:
        value = json.loads(raw, object_pairs_hook=_duplicates)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProvisionError(code) from exc
    if type(value) is not dict or raw != _canonical(value):
        _fail(code)
    return value, raw


def _exact(value: Any, keys: set[str], code: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        _fail(code)
    return value


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hex(value: Any, code: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        _fail(code)
    return value


def _fd_token(value: str, code: str) -> int:
    match = re.fullmatch(r"/proc/self/fd/([0-9]{1,4})", value)
    if match is None:
        _fail(code)
    fd = int(match.group(1), 10)
    if fd <= 2:
        _fail(code)
    return fd


def _require_fd(fd: int, *, directory: bool, writable: bool, code: str) -> os.stat_result:
    info = os.fstat(fd)
    if directory != stat.S_ISDIR(info.st_mode):
        _fail(code)
    if not directory and not stat.S_ISREG(info.st_mode):
        _fail(code)
    flags = __import__("fcntl").fcntl(fd, __import__("fcntl").F_GETFL)
    access = flags & os.O_ACCMODE
    if writable and access == os.O_RDONLY:
        _fail(code)
    if not writable and access != os.O_RDONLY:
        _fail(code)
    return info


def _empty_directory(fd: int, code: str) -> None:
    if os.listdir(fd):
        _fail(code)


def _safe_member(name: str) -> tuple[str, ...]:
    if not name or "\\" in name or "\x00" in name:
        _fail("WHEEL_MEMBER_PATH_INVALID")
    path = PurePosixPath(name)
    if path.is_absolute() or str(path) != name.rstrip("/"):
        _fail("WHEEL_MEMBER_PATH_INVALID")
    parts = path.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        _fail("WHEEL_MEMBER_PATH_INVALID")
    return parts


def _mkdirs(root_fd: int, parts: tuple[str, ...]) -> int:
    current = os.dup(root_fd)
    try:
        for part in parts:
            try:
                os.mkdir(part, 0o755, dir_fd=current)
            except FileExistsError:
                pass
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=current,
            )
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _write_member(root_fd: int, parts: tuple[str, ...], payload: bytes, mode: int) -> None:
    parent = _mkdirs(root_fd, parts[:-1])
    try:
        descriptor = os.open(
            parts[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            mode,
            dir_fd=parent,
        )
        try:
            offset = 0
            while offset < len(payload):
                offset += os.write(descriptor, payload[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)


def _wheel_install_path(name: str) -> tuple[str, ...]:
    parts = _safe_member(name)
    marker = next((i for i, part in enumerate(parts) if part.endswith(".data")), None)
    if marker is None:
        return ("site-packages", *parts)
    if marker + 1 >= len(parts):
        _fail("WHEEL_DATA_PATH_INVALID")
    scheme = parts[marker + 1]
    remainder = parts[marker + 2 :]
    if not remainder:
        _fail("WHEEL_DATA_PATH_INVALID")
    if scheme in {"purelib", "platlib"}:
        return ("site-packages", *remainder)
    if scheme == "scripts":
        return ("wheel-scripts", *remainder)
    if scheme == "data":
        return ("data", *remainder)
    _fail("WHEEL_DATA_SCHEME_DENIED")


def _verify_record(archive: zipfile.ZipFile) -> None:
    names = [item.filename for item in archive.infolist()]
    records = [name for name in names if name.endswith(".dist-info/RECORD")]
    if len(records) != 1:
        _fail("WHEEL_RECORD_INVALID")
    try:
        rows = list(csv.reader(io.TextIOWrapper(archive.open(records[0]), encoding="utf-8", newline="")))
    except (UnicodeError, csv.Error, KeyError) as exc:
        raise ProvisionError("WHEEL_RECORD_INVALID") from exc
    by_name = {row[0]: row for row in rows if len(row) == 3}
    if len(by_name) != len(rows) or set(by_name) != set(names):
        _fail("WHEEL_RECORD_INCOMPLETE")
    for name in names:
        row = by_name[name]
        if name == records[0]:
            if row[1:] != ["", ""]:
                _fail("WHEEL_RECORD_INVALID")
            continue
        if not row[1].startswith("sha256=") or not row[2].isdigit():
            _fail("WHEEL_RECORD_INVALID")
        payload = archive.read(name)
        expected = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode("ascii")
        if row[1][7:] != expected or int(row[2], 10) != len(payload):
            _fail("WHEEL_RECORD_MISMATCH")


def _install_wheel(cache_fd: int, generation_fd: int, row: dict[str, Any], counters: list[int]) -> None:
    filename = row["filename"]
    fd = os.open(
        filename,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=cache_fd,
    )
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_size != row["size"] or info.st_size > MAX_WHEEL_BYTES):
            _fail("WHEEL_IDENTITY_MISMATCH")
        payload = os.pread(fd, info.st_size, 0)
        if len(payload) != info.st_size or _sha(payload) != row["sha256"]:
            _fail("WHEEL_IDENTITY_MISMATCH")
    finally:
        os.close(fd)
    try:
        archive = zipfile.ZipFile(io.BytesIO(payload), "r")
        _verify_record(archive)
        for item in archive.infolist():
            if item.is_dir():
                continue
            mode = (item.external_attr >> 16) & 0o170000
            if mode not in {0, stat.S_IFREG}:
                _fail("WHEEL_SPECIAL_MEMBER_DENIED")
            if item.file_size < 0 or item.file_size > MAX_EXPANDED_BYTES:
                _fail("WHEEL_MEMBER_SIZE_INVALID")
            counters[0] += 1
            counters[1] += item.file_size
            if counters[0] > MAX_ENTRIES or counters[1] > MAX_EXPANDED_BYTES:
                _fail("WHEEL_EXPANSION_LIMIT_EXCEEDED")
            data = archive.read(item)
            if len(data) != item.file_size:
                _fail("WHEEL_MEMBER_SHORT_READ")
            _write_member(generation_fd, _wheel_install_path(item.filename), data, 0o444)
    except (zipfile.BadZipFile, RuntimeError) as exc:
        raise ProvisionError("WHEEL_ARCHIVE_INVALID") from exc


def _validate_policy(policy: dict[str, Any]) -> None:
    _exact(policy, {"acquisition_receipt_sha256", "roots", "schema", "target", "wheel_set_sha256", "wheels"}, "POLICY_KEYS_INVALID")
    if policy["schema"] != POLICY_SCHEMA or policy["target"] != TARGET:
        _fail("POLICY_IDENTITY_INVALID")
    _hex(policy["acquisition_receipt_sha256"], "ACQUISITION_DIGEST_INVALID")
    _hex(policy["wheel_set_sha256"], "WHEEL_SET_DIGEST_INVALID")
    if policy["roots"] != ["slither-analyzer==0.11.5", "solc-select==1.2.0"]:
        _fail("ROOT_SET_INVALID")
    wheels = policy["wheels"]
    if type(wheels) is not list or not wheels or len(wheels) > MAX_WHEELS:
        _fail("WHEEL_ROSTER_INVALID")
    names: list[str] = []
    for row in wheels:
        _exact(row, {"filename", "sha256", "size"}, "WHEEL_ROW_INVALID")
        if type(row["filename"]) is not str or _WHEEL_NAME.fullmatch(row["filename"]) is None:
            _fail("WHEEL_FILENAME_INVALID")
        _hex(row["sha256"], "WHEEL_DIGEST_INVALID")
        if type(row["size"]) is not int or row["size"] < 1 or row["size"] > MAX_WHEEL_BYTES:
            _fail("WHEEL_SIZE_INVALID")
        names.append(row["filename"])
    if names != sorted(names) or len(names) != len(set(names)):
        _fail("WHEEL_ORDER_INVALID")
    if _sha(_canonical(wheels)) != policy["wheel_set_sha256"]:
        _fail("WHEEL_SET_DIGEST_INVALID")


def _validate_acquisition(receipt: dict[str, Any], raw: bytes, policy: dict[str, Any], policy_sha: str) -> None:
    _exact(receipt, {"network", "policy_sha256", "schema", "target", "wheel_count", "wheel_set_sha256"}, "ACQUISITION_KEYS_INVALID")
    if (_sha(raw) != policy["acquisition_receipt_sha256"]
            or receipt["schema"] != ACQUISITION_SCHEMA
            or receipt["target"] != TARGET
            or receipt["network"] != "DENY_ALL"
            or receipt["policy_sha256"] != policy_sha
            or receipt["wheel_set_sha256"] != policy["wheel_set_sha256"]
            or receipt["wheel_count"] != len(policy["wheels"])):
        _fail("ACQUISITION_BINDING_INVALID")


def _launcher() -> bytes:
    return (
        f"#!{PYTHON_PATH}\n"
        "import os,sys\n"
        "root=os.path.dirname(os.path.dirname(os.path.realpath(__file__)))\n"
        "sys.path[:0]=[os.path.join(root,'site-packages')]\n"
        "from slither.__main__ import main\n"
        "raise SystemExit(main())\n"
    ).encode("ascii")


def provision(argv: list[str]) -> dict[str, Any]:
    if os.environ:
        _fail("AMBIENT_ENVIRONMENT_DENIED")
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--generation", required=True)
    parser.add_argument("--cache", required=True)
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--acquisition-receipt", required=True)
    parser.add_argument("--offline", action="store_true")
    args, extras = parser.parse_known_args(argv)
    if extras or not args.offline:
        _fail("CLI_CONTRACT_INVALID")
    values = [args.policy, args.generation, args.cache, args.project_root, args.acquisition_receipt]
    fds = [_fd_token(value, "CLI_DESCRIPTOR_INVALID") for value in values]
    if len(fds) != len(set(fds)):
        _fail("DESCRIPTOR_ALIAS_DENIED")
    policy_fd, generation_fd, cache_fd, project_fd, acquisition_fd = fds
    _require_fd(policy_fd, directory=False, writable=False, code="POLICY_DESCRIPTOR_INVALID")
    _require_fd(generation_fd, directory=True, writable=True, code="GENERATION_DESCRIPTOR_INVALID")
    _require_fd(cache_fd, directory=True, writable=True, code="CACHE_DESCRIPTOR_INVALID")
    _require_fd(project_fd, directory=True, writable=False, code="PROJECT_DESCRIPTOR_INVALID")
    _require_fd(acquisition_fd, directory=False, writable=False, code="ACQUISITION_DESCRIPTOR_INVALID")
    _empty_directory(generation_fd, "GENERATION_NOT_EMPTY")
    policy, policy_raw = _load_fd(policy_fd, MAX_POLICY_BYTES, "POLICY_INVALID")
    _validate_policy(policy)
    policy_sha = _sha(policy_raw)
    acquisition, acquisition_raw = _load_fd(acquisition_fd, MAX_RECEIPT_BYTES, "ACQUISITION_INVALID")
    _validate_acquisition(acquisition, acquisition_raw, policy, policy_sha)
    counters = [0, 0]
    for row in policy["wheels"]:
        _install_wheel(cache_fd, generation_fd, row, counters)
    launcher = _launcher()
    _write_member(generation_fd, ("bin", "slither"), launcher, 0o555)
    os.fsync(generation_fd)
    terminal = {
        "entry_count": counters[0] + 1,
        "expanded_bytes": counters[1] + len(launcher),
        "network": "DENY_ALL",
        "policy_sha256": policy_sha,
        "schema": TERMINAL_SCHEMA,
        "slither_path": SLITHER_PATH,
        "target": TARGET,
        "wheel_count": len(policy["wheels"]),
        "wheel_set_sha256": policy["wheel_set_sha256"],
    }
    return terminal


def main() -> int:
    try:
        result = provision(sys.argv[1:])
        os.write(1, _canonical(result))
        return 0
    except BaseException as exc:
        code = exc.args[0] if isinstance(exc, ProvisionError) and exc.args else "PROVISION_FAILED"
        os.write(2, str(code).encode("ascii", "replace")[:256])
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
