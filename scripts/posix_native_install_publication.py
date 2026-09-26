"""Recoverable publication of the ordinary POSIX ``plamen`` front shim.

The native launcher is authoritative for audit execution, but users enter
through ``~/.local/bin/plamen``.  This module publishes that ordinary shim only
after its installed Python and ``~/.plamen/plamen.py`` targets have been
revalidated.  Existing bytes are replaced only when the caller supplies their
exact previously-authenticated authority.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shlex
import stat
from typing import Any


_HEX64 = re.compile(r"[0-9a-f]{64}")
_TXID = re.compile(r"[0-9a-f]{32}")
_MAX_LAUNCHER_BYTES = 8192


class PosixNativeInstallPublicationError(RuntimeError):
    """A fail-closed public-shim publication error."""


def _fail(message: str) -> None:
    raise PosixNativeInstallPublicationError(message) from None


def _absolute(value: object, label: str) -> Path:
    if type(value) is not str or not value or "\x00" in value:
        _fail(f"{label} is malformed")
    path = Path(value)
    if not path.is_absolute() or os.path.normpath(value) != value:
        _fail(f"{label} is not canonical absolute")
    return path


def _inside(home: Path, path: Path, label: str) -> None:
    try:
        relative = path.relative_to(home)
    except ValueError:
        _fail(f"{label} escapes the account home")
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        _fail(f"{label} is malformed")


def _identity(
    path: Path, *, expected_mode: int | None = None,
    maximum: int | None = _MAX_LAUNCHER_BYTES,
    allowed_links: tuple[int, ...] = (1,),
) -> dict[str, Any]:
    fd = -1
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        observed = os.fstat(fd)
    except OSError:
        _fail("launcher authority could not be inspected")
    mode = stat.S_IMODE(observed.st_mode)
    if (
        not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != os.getuid()
        or observed.st_nlink not in allowed_links
        or observed.st_size <= 0
        or (maximum is not None and observed.st_size > maximum)
        or mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
        or (expected_mode is not None and mode != expected_mode)
    ):
        _fail("launcher authority differs")
    try:
        raw = b""
        while len(raw) < observed.st_size:
            part = os.read(fd, observed.st_size - len(raw))
            if not part:
                break
            raw += part
        after = os.fstat(fd)
        if (
            len(raw) != observed.st_size
            or (observed.st_dev, observed.st_ino, observed.st_mode,
                observed.st_uid, observed.st_gid, observed.st_nlink,
                observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_mode,
                after.st_uid, after.st_gid, after.st_nlink,
                after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        ):
            _fail("launcher authority changed during inspection")
    except OSError:
        _fail("launcher authority could not be read")
    finally:
        if fd >= 0:
            os.close(fd)
    return {
        "schema": "plamen.posix-native-install.file-authority.v1",
        "path": str(path),
        "device": observed.st_dev,
        "inode": observed.st_ino,
        "mode": mode,
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _validate_authority(value: object, *, path: Path | None = None) -> dict[str, Any]:
    fields = {"schema", "path", "device", "inode", "mode", "size", "sha256"}
    if (
        type(value) is not dict
        or set(value) != fields
        or value.get("schema") != "plamen.posix-native-install.file-authority.v1"
        or type(value.get("path")) is not str
        or type(value.get("device")) is not int
        or type(value.get("inode")) is not int
        or type(value.get("mode")) is not int
        or type(value.get("size")) is not int
        or value.get("size", 0) <= 0
        or _HEX64.fullmatch(value.get("sha256", "")) is None
        or (path is not None and value.get("path") != str(path))
    ):
        _fail("launcher file authority is malformed")
    return dict(value)


def _same_content(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return all(left[key] == right[key] for key in ("path", "mode", "size", "sha256"))


def _same_identity(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return all(
        left[key] == right[key]
        for key in ("path", "device", "inode", "mode", "size", "sha256")
    )


def _ensure_directory(parent_fd: int, name: str) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        return os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
            return os.open(name, flags, dir_fd=parent_fd)
        except OSError:
            _fail("launcher directory creation failed")
    except OSError:
        _fail("launcher directory authority differs")


def _open_public_directory(home: Path) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        current = os.open(home, flags)
    except OSError:
        _fail("account home authority differs")
    try:
        for component in (".local", "bin"):
            opened = _ensure_directory(current, component)
            os.close(current)
            current = opened
            observed = os.fstat(current)
            if (
                observed.st_uid != os.getuid()
                or stat.S_IMODE(observed.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                _fail("launcher directory authority differs")
        return current
    except BaseException:
        os.close(current)
        raise


def launcher_bytes(interpreter: str, front_script: str) -> bytes:
    """Render the fixed ordinary front shim; neither target is an authority."""

    python = _absolute(interpreter, "managed Python")
    front = _absolute(front_script, "installed front script")
    return (
        "#!/bin/sh\n"
        "# Plamen managed native front launcher v3.\n"
        f"exec {shlex.quote(str(python))} -I -B {shlex.quote(str(front))} \"$@\"\n"
    ).encode("utf-8")


def observe_file_authority(
    path: str, *, expected_mode: int | None = None,
    maximum: int | None = None,
) -> dict[str, Any]:
    """Return descriptor-bound authority for a direct installed file."""

    return _identity(
        _absolute(path, "installed file"), expected_mode=expected_mode,
        maximum=maximum,
    )


def _revalidate_target(authority: object, label: str) -> None:
    expected = _validate_authority(authority)
    observed = _identity(Path(expected["path"]), maximum=None)
    if not _same_content(observed, expected):
        _fail(f"{label} changed after package commit")


def prepare_publication(
    *, home: str, transaction_id: str, interpreter: str, front_script: str,
    interpreter_authority: object, front_authority: object,
    prior_authority: object | None,
) -> dict[str, Any]:
    """Stage the exact shim and bind its admitted predecessor.

    Targets may not exist yet on a cold install.  Their authenticated staged
    authorities are retained here and are revalidated immediately before the
    shim becomes public.
    """

    account = _absolute(home, "account home")
    python = _absolute(interpreter, "managed Python")
    front = _absolute(front_script, "installed front script")
    _inside(account, python, "managed Python")
    _inside(account, front, "installed front script")
    if _TXID.fullmatch(transaction_id) is None:
        _fail("install transaction id is malformed")
    expected_python = _validate_authority(interpreter_authority, path=python)
    expected_front = _validate_authority(front_authority, path=front)
    public = account / ".local" / "bin" / "plamen"
    prior = None if prior_authority is None else _validate_authority(
        prior_authority, path=public,
    )
    if os.path.lexists(public):
        observed = _identity(public, expected_mode=0o700)
        if prior is None or not _same_identity(observed, prior):
            _fail("existing public launcher is not authenticated")
    elif prior is not None:
        _fail("authenticated public launcher predecessor disappeared")

    desired = launcher_bytes(str(python), str(front))
    desired_sha256 = hashlib.sha256(desired).hexdigest()
    stage_name = f".plamen.native-{transaction_id}.next"
    backup_name = f".plamen.native-{transaction_id}.rollback"
    bin_fd = _open_public_directory(account)
    stage_fd = -1
    try:
        for reserved in (stage_name, backup_name):
            try:
                observed = os.stat(reserved, dir_fd=bin_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.getuid():
                _fail("launcher transaction residue is unauthenticated")
        try:
            stage_fd = os.open(
                stage_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=bin_fd,
            )
            view = memoryview(desired)
            while view:
                count = os.write(stage_fd, view)
                if count <= 0:
                    _fail("launcher staging write failed")
                view = view[count:]
            os.fchmod(stage_fd, 0o700)
            os.fsync(stage_fd)
            os.fsync(bin_fd)
        except FileExistsError:
            existing = _identity(public.parent / stage_name, expected_mode=0o700)
            if existing["sha256"] != desired_sha256 or existing["size"] != len(desired):
                _fail("launcher transaction stage differs")
    finally:
        if stage_fd >= 0:
            os.close(stage_fd)
        os.close(bin_fd)
    return {
        "schema": "plamen.posix-native-install.publication.v1",
        "transaction_id": transaction_id,
        "home": str(account),
        "public_path": str(public),
        "stage_name": stage_name,
        "backup_name": backup_name,
        "desired_sha256": desired_sha256,
        "desired_size": len(desired),
        "interpreter_authority": expected_python,
        "front_authority": expected_front,
        "prior_authority": prior,
    }


def _validate_plan(value: object) -> dict[str, Any]:
    fields = {
        "schema", "transaction_id", "home", "public_path", "stage_name",
        "backup_name", "desired_sha256", "desired_size",
        "interpreter_authority", "front_authority", "prior_authority",
    }
    if (
        type(value) is not dict
        or set(value) != fields
        or value.get("schema") != "plamen.posix-native-install.publication.v1"
        or _TXID.fullmatch(value.get("transaction_id", "")) is None
        or _HEX64.fullmatch(value.get("desired_sha256", "")) is None
        or type(value.get("desired_size")) is not int
        or value.get("desired_size", 0) <= 0
    ):
        _fail("launcher publication plan is malformed")
    account = _absolute(value["home"], "account home")
    public = _absolute(value["public_path"], "public launcher")
    if public != account / ".local" / "bin" / "plamen":
        _fail("launcher publication path differs")
    expected_stage = f".plamen.native-{value['transaction_id']}.next"
    expected_backup = f".plamen.native-{value['transaction_id']}.rollback"
    if value["stage_name"] != expected_stage or value["backup_name"] != expected_backup:
        _fail("launcher publication residue names differ")
    _validate_authority(value["interpreter_authority"])
    _validate_authority(value["front_authority"])
    if value["prior_authority"] is not None:
        _validate_authority(value["prior_authority"], path=public)
    return dict(value)


def validate_published(plan: object) -> dict[str, Any]:
    admitted = _validate_plan(plan)
    observed = _identity(Path(admitted["public_path"]), expected_mode=0o700)
    if (
        observed["sha256"] != admitted["desired_sha256"]
        or observed["size"] != admitted["desired_size"]
    ):
        _fail("published launcher differs")
    _revalidate_target(admitted["interpreter_authority"], "managed Python")
    _revalidate_target(admitted["front_authority"], "installed front script")
    return observed


def publish(plan: object) -> dict[str, Any]:
    """Publish or replay the desired shim without accepting foreign bytes."""

    admitted = _validate_plan(plan)
    public = Path(admitted["public_path"])
    backup_path = public.parent / admitted["backup_name"]
    backup_present = os.path.lexists(backup_path)
    if os.path.lexists(public):
        observed = _identity(
            public, expected_mode=0o700,
            allowed_links=(1, 2) if backup_present else (1,),
        )
        if (
            observed["sha256"] == admitted["desired_sha256"]
            and observed["size"] == admitted["desired_size"]
        ):
            return validate_published(admitted)
    _revalidate_target(admitted["interpreter_authority"], "managed Python")
    _revalidate_target(admitted["front_authority"], "installed front script")
    prior = admitted["prior_authority"]
    if os.path.lexists(public):
        observed = _identity(
            public, expected_mode=0o700,
            allowed_links=(1, 2) if backup_present else (1,),
        )
        if prior is None or not _same_identity(observed, prior):
            _fail("public launcher predecessor changed before commit")
    elif prior is not None:
        _fail("public launcher predecessor disappeared before commit")

    bin_fd = _open_public_directory(Path(admitted["home"]))
    try:
        stage = public.parent / admitted["stage_name"]
        staged = _identity(stage, expected_mode=0o700)
        if (
            staged["sha256"] != admitted["desired_sha256"]
            or staged["size"] != admitted["desired_size"]
        ):
            _fail("public launcher stage changed before commit")
        if prior is not None:
            try:
                os.link(
                    "plamen", admitted["backup_name"],
                    src_dir_fd=bin_fd, dst_dir_fd=bin_fd,
                    follow_symlinks=False,
                )
                os.fsync(bin_fd)
            except FileExistsError:
                backup = _identity(
                    backup_path, expected_mode=0o700,
                    allowed_links=(1, 2),
                )
                if not _same_identity(backup, prior):
                    _fail("public launcher rollback authority differs")
        os.replace(admitted["stage_name"], "plamen", src_dir_fd=bin_fd, dst_dir_fd=bin_fd)
        os.fsync(bin_fd)
    except OSError:
        _fail("public launcher commit failed")
    finally:
        os.close(bin_fd)
    return validate_published(admitted)


def rollback(plan: object) -> None:
    """Restore only the exact authenticated predecessor."""

    admitted = _validate_plan(plan)
    public = Path(admitted["public_path"])
    prior = admitted["prior_authority"]
    bin_fd = _open_public_directory(Path(admitted["home"]))
    try:
        backup_path = public.parent / admitted["backup_name"]
        backup_present = os.path.lexists(backup_path)
        if os.path.lexists(public):
            observed = _identity(
                public, expected_mode=0o700,
                allowed_links=(1, 2) if backup_present else (1,),
            )
            if (
                observed["sha256"] != admitted["desired_sha256"]
                or observed["size"] != admitted["desired_size"]
            ):
                if prior is not None and _same_identity(observed, prior):
                    return
                _fail("public launcher changed before rollback")
            if prior is None:
                os.unlink("plamen", dir_fd=bin_fd)
            else:
                backup = _identity(
                    backup_path, expected_mode=0o700,
                    allowed_links=(1, 2),
                )
                if not _same_identity(backup, prior):
                    _fail("public launcher rollback authority differs")
                os.replace(admitted["backup_name"], "plamen", src_dir_fd=bin_fd, dst_dir_fd=bin_fd)
            os.fsync(bin_fd)
        elif prior is not None:
            backup = _identity(backup_path, expected_mode=0o700)
            if not _same_identity(backup, prior):
                _fail("public launcher rollback authority differs")
            os.replace(admitted["backup_name"], "plamen", src_dir_fd=bin_fd, dst_dir_fd=bin_fd)
            os.fsync(bin_fd)
        for leaf in (admitted["stage_name"], admitted["backup_name"]):
            try:
                os.unlink(leaf, dir_fd=bin_fd)
            except FileNotFoundError:
                pass
        os.fsync(bin_fd)
    except OSError:
        _fail("public launcher rollback failed")
    finally:
        os.close(bin_fd)


def cleanup(plan: object) -> None:
    admitted = _validate_plan(plan)
    public = Path(admitted["public_path"])
    bin_fd = _open_public_directory(Path(admitted["home"]))
    try:
        for leaf in (admitted["stage_name"], admitted["backup_name"]):
            path = public.parent / leaf
            if not os.path.lexists(path):
                continue
            observed = _identity(path, expected_mode=0o700)
            admitted_hashes = {admitted["desired_sha256"]}
            if admitted["prior_authority"] is not None:
                admitted_hashes.add(admitted["prior_authority"]["sha256"])
            if observed["sha256"] not in admitted_hashes:
                _fail("launcher cleanup residue differs")
            os.unlink(leaf, dir_fd=bin_fd)
        os.fsync(bin_fd)
    except OSError:
        _fail("launcher cleanup failed")
    finally:
        os.close(bin_fd)


__all__ = [
    "PosixNativeInstallPublicationError", "cleanup", "launcher_bytes",
    "observe_file_authority", "prepare_publication", "publish", "rollback",
    "validate_published",
]
