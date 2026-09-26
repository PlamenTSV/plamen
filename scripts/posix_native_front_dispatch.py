"""Minimal POSIX front-to-native audit launcher handoff.

This module deliberately has no request-projection, credential, environment,
or descriptor transport.  It validates one stable installed native launcher
and one existing config pathname, closes its inspection descriptors, and then
executes the launcher with an empty environment.  The launcher independently
authenticates its generation receipt and config before it may contact the
native service or spawn managed Python.
"""

from __future__ import annotations

import os
import pwd
import stat
import sys
import unicodedata
from typing import NoReturn


INSTALL_ROOT_SUFFIX = (".local", "share", "plamen")
STABLE_LAUNCHER_SUFFIX = (*INSTALL_ROOT_SUFFIX, "bin", "plamen-native-launcher")
LAUNCHER_MODE = 0o500
MAX_PATH_BYTES = 4096
MAX_CONFIG_BYTES = 256 * 1024
COMMANDS = frozenset({"start-config", "resume"})


class PosixNativeFrontDispatchError(RuntimeError):
    """A bounded front handoff failure with no caller-controlled diagnostic."""


def _fail(message: str) -> NoReturn:
    raise PosixNativeFrontDispatchError(message) from None


def _canonical_absolute_path(value: object, label: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        _fail(f"{label} is malformed")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        _fail(f"{label} is malformed")
    if (
        len(encoded) > MAX_PATH_BYTES
        or value != unicodedata.normalize("NFC", value)
        or any(ord(character) < 32 for character in value)
        or not value.startswith("/")
        or value.startswith("//")
        or not os.path.isabs(value)
        or os.path.normpath(value) != value
    ):
        _fail(f"{label} is not canonical absolute")
    components = value.split("/")[1:]
    if not components or any(component in {"", ".", ".."} for component in components):
        _fail(f"{label} is not canonical absolute")
    return value


def _account_home() -> tuple[int, str]:
    if os.name != "posix" or sys.platform not in {"darwin", "linux"}:
        _fail("native audit launcher requires Darwin or Linux")
    uid = os.getuid()
    if type(uid) is not int or isinstance(uid, bool) or uid < 0:
        _fail("native audit account identity is malformed")
    try:
        record = pwd.getpwuid(uid)
        record_uid = record.pw_uid
        home = record.pw_dir
    except (KeyError, OSError, AttributeError):
        _fail("native audit account record is unavailable")
    if type(record_uid) is not int or record_uid != uid:
        _fail("native audit account identity differs")
    return uid, _canonical_absolute_path(home, "native audit account home")


def _directory_is_safe(observed: os.stat_result, uid: int) -> bool:
    mode = observed.st_mode
    if not stat.S_ISDIR(mode) or observed.st_uid not in {0, uid}:
        return False
    writable_by_others = mode & (stat.S_IWGRP | stat.S_IWOTH)
    # Root-owned sticky traversal roots such as /tmp are safe against rename
    # by unrelated users when every later component is opened without links.
    sticky_root = observed.st_uid == 0 and bool(mode & stat.S_ISVTX)
    return not writable_by_others or sticky_root


def _open_absolute_no_links(path: str, uid: int) -> tuple[int, os.stat_result]:
    """Open an absolute path one component at a time without following links."""
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    final_flags = os.O_RDONLY | os.O_CLOEXEC
    if not hasattr(os, "O_NOFOLLOW"):
        _fail("native audit no-link descriptor support is unavailable")
    directory_flags |= os.O_NOFOLLOW
    final_flags |= os.O_NOFOLLOW
    current = -1
    try:
        current = os.open("/", directory_flags)
        root_stat = os.fstat(current)
        if not _directory_is_safe(root_stat, uid):
            _fail("native audit traversal root is unsafe")
        components = path.split("/")[1:]
        for index, component in enumerate(components):
            final = index == len(components) - 1
            opened = os.open(
                component,
                final_flags if final else directory_flags,
                dir_fd=current,
            )
            observed = os.fstat(opened)
            if not final and not _directory_is_safe(observed, uid):
                os.close(opened)
                _fail("native audit path traversal is unsafe")
            os.close(current)
            current = opened
        os.set_inheritable(current, False)
        return current, os.fstat(current)
    except PosixNativeFrontDispatchError:
        if current >= 0:
            os.close(current)
        raise
    except (OSError, ValueError, OverflowError):
        if current >= 0:
            os.close(current)
        _fail("native audit path admission failed")


def _identity(observed: os.stat_result) -> tuple[int, ...]:
    return (
        int(observed.st_dev),
        int(observed.st_ino),
        int(observed.st_mode),
        int(observed.st_uid),
        int(observed.st_gid),
        int(observed.st_nlink),
        int(observed.st_size),
    )


def _revalidate_path(path: str, expected: os.stat_result) -> None:
    try:
        observed = os.stat(path, follow_symlinks=False)
    except OSError:
        _fail("native audit path revalidation failed")
    if _identity(observed) != _identity(expected):
        _fail("native audit path identity drifted")


def _validate_launcher(observed: os.stat_result, uid: int) -> None:
    mode = stat.S_IMODE(observed.st_mode)
    if (
        not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != uid
        or mode != LAUNCHER_MODE
        or observed.st_nlink < 2
        or observed.st_size <= 0
    ):
        _fail("installed native audit launcher authority differs")


def _validate_config(observed: os.stat_result, uid: int) -> None:
    mode = stat.S_IMODE(observed.st_mode)
    if (
        not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != uid
        or observed.st_size <= 0
        or observed.st_size > MAX_CONFIG_BYTES
        or not mode & stat.S_IRUSR
        or mode & (stat.S_IWGRP | stat.S_IWOTH)
        or mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
    ):
        _fail("native audit config authority differs")


def exec_native_audit(command: str, config_path: str) -> NoReturn:
    """Exec the stable native launcher with exact argv and an empty env."""
    if type(command) is not str or command not in COMMANDS:
        _fail("native audit command is unsupported")
    config = _canonical_absolute_path(config_path, "native audit config path")
    if not config.endswith("/.scratchpad/config.json"):
        _fail("native audit config path shape differs")
    uid, home = _account_home()
    launcher = os.path.join(home, *STABLE_LAUNCHER_SUFFIX)
    launcher = _canonical_absolute_path(launcher, "native audit launcher path")

    launcher_fd = -1
    config_fd = -1
    try:
        launcher_fd, launcher_stat = _open_absolute_no_links(launcher, uid)
        _validate_launcher(launcher_stat, uid)
        config_fd, config_stat = _open_absolute_no_links(config, uid)
        _validate_config(config_stat, uid)
        _revalidate_path(launcher, launcher_stat)
        _revalidate_path(config, config_stat)
    finally:
        if config_fd >= 0:
            os.close(config_fd)
        if launcher_fd >= 0:
            os.close(launcher_fd)

    argv = [launcher, command, config]
    os.execve(launcher, argv, {})
    _fail("native audit launcher exec returned")


__all__ = [
    "COMMANDS",
    "INSTALL_ROOT_SUFFIX",
    "LAUNCHER_MODE",
    "PosixNativeFrontDispatchError",
    "STABLE_LAUNCHER_SUFFIX",
    "exec_native_audit",
]
