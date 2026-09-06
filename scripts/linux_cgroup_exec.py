"""Trusted Linux cgroup-v2 pre-exec assignment helper.

This helper is intentionally tiny.  It moves only itself into the exact
provider-created cgroup, waits for a one-byte parent acknowledgement, closes
the inherited gate descriptor, and then replaces itself with the requested
program.  No requested program byte executes before cgroup membership has
been observed by the parent.
"""

from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path
import sys


_LANDLOCK_CREATE_RULESET_VERSION = 1
_LANDLOCK_RULE_PATH_BENEATH = 1
_PR_SET_NO_NEW_PRIVS = 38

_ACCESS_EXECUTE = 1 << 0
_ACCESS_WRITE_FILE = 1 << 1
_ACCESS_READ_FILE = 1 << 2
_ACCESS_READ_DIR = 1 << 3
_ACCESS_REMOVE_DIR = 1 << 4
_ACCESS_REMOVE_FILE = 1 << 5
_ACCESS_MAKE_CHAR = 1 << 6
_ACCESS_MAKE_DIR = 1 << 7
_ACCESS_MAKE_REG = 1 << 8
_ACCESS_MAKE_SOCK = 1 << 9
_ACCESS_MAKE_FIFO = 1 << 10
_ACCESS_MAKE_BLOCK = 1 << 11
_ACCESS_MAKE_SYM = 1 << 12
_ACCESS_REFER = 1 << 13
_ACCESS_TRUNCATE = 1 << 14
_ACCESS_IOCTL_DEV = 1 << 15

_BASE_WRITE_ACCESS = (
    _ACCESS_WRITE_FILE
    | _ACCESS_REMOVE_DIR
    | _ACCESS_REMOVE_FILE
    | _ACCESS_MAKE_CHAR
    | _ACCESS_MAKE_DIR
    | _ACCESS_MAKE_REG
    | _ACCESS_MAKE_SOCK
    | _ACCESS_MAKE_FIFO
    | _ACCESS_MAKE_BLOCK
    | _ACCESS_MAKE_SYM
)
_READ_EXECUTE_ACCESS = _ACCESS_EXECUTE | _ACCESS_READ_FILE | _ACCESS_READ_DIR


def _syscall_numbers() -> tuple[int, int, int]:
    try:
        machine = os.uname().machine.casefold()
    except AttributeError:
        return (0, 0, 0)
    # Landlock uses the generic 444-446 syscall allocation on the supported
    # 64-bit Linux architectures below.
    if machine in {
        "x86_64",
        "amd64",
        "aarch64",
        "arm64",
        "riscv64",
        "ppc64",
        "ppc64le",
        "s390x",
    }:
        return (444, 445, 446)
    return (0, 0, 0)


def _landlock_abi(libc: ctypes.CDLL, create_number: int) -> int:
    result = int(
        libc.syscall(
            create_number,
            ctypes.c_void_p(),
            ctypes.c_size_t(0),
            ctypes.c_uint(_LANDLOCK_CREATE_RULESET_VERSION),
        )
    )
    return result if result >= 1 else 0


def _apply_landlock(write_roots: list[Path]) -> int:
    class _RulesetAttr(ctypes.Structure):
        _fields_ = [("handled_access_fs", ctypes.c_uint64)]

    class _PathBeneathAttr(ctypes.Structure):
        _fields_ = [
            ("allowed_access", ctypes.c_uint64),
            ("parent_fd", ctypes.c_int32),
            ("reserved", ctypes.c_uint32),
        ]

    create_number, add_number, restrict_number = _syscall_numbers()
    if not all((create_number, add_number, restrict_number)):
        raise OSError(errno.ENOSYS, "Landlock syscall ABI is unknown")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    abi = _landlock_abi(libc, create_number)
    if abi < 1:
        raise OSError(errno.ENOSYS, "Landlock is unavailable")
    write_access = _BASE_WRITE_ACCESS
    if abi >= 2:
        write_access |= _ACCESS_REFER
    if abi >= 3:
        write_access |= _ACCESS_TRUNCATE
    if abi >= 5:
        write_access |= _ACCESS_IOCTL_DEV
    handled = _READ_EXECUTE_ACCESS | write_access
    ruleset_attr = _RulesetAttr(handled)
    ruleset_fd = int(
        libc.syscall(
            create_number,
            ctypes.byref(ruleset_attr),
            ctypes.sizeof(ruleset_attr),
            ctypes.c_uint(0),
        )
    )
    if ruleset_fd < 0:
        error = ctypes.get_errno()
        raise OSError(error, "landlock_create_ruleset failed")

    opened: list[int] = []
    try:
        def add_path(path: Path, access: int) -> None:
            descriptor = os.open(
                path,
                getattr(os, "O_PATH", os.O_RDONLY) | os.O_CLOEXEC,
            )
            opened.append(descriptor)
            rule = _PathBeneathAttr(access, descriptor, 0)
            result = int(
                libc.syscall(
                    add_number,
                    ruleset_fd,
                    _LANDLOCK_RULE_PATH_BENEATH,
                    ctypes.byref(rule),
                    ctypes.c_uint(0),
                )
            )
            if result != 0:
                error = ctypes.get_errno()
                raise OSError(error, f"landlock_add_rule failed for {path}")

        # The worker may read/execute the host view, but receives write-like
        # rights only beneath attempt-owned roots.
        add_path(Path("/"), _READ_EXECUTE_ACCESS)
        for root in write_roots:
            add_path(root, handled)
        if int(libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) != 0:
            error = ctypes.get_errno()
            raise OSError(error, "PR_SET_NO_NEW_PRIVS failed")
        if int(
            libc.syscall(
                restrict_number,
                ruleset_fd,
                ctypes.c_uint(0),
            )
        ) != 0:
            error = ctypes.get_errno()
            raise OSError(error, "landlock_restrict_self failed")
        return abi
    finally:
        for descriptor in opened:
            os.close(descriptor)
        os.close(ruleset_fd)


def main(argv: list[str]) -> int:
    if len(argv) < 7:
        return 64
    procs_path = Path(argv[1])
    try:
        gate_fd = int(argv[2], 10)
        status_fd = int(argv[3], 10)
    except ValueError:
        return 64
    if gate_fd < 3 or status_fd < 3 or not procs_path.is_absolute():
        return 64
    try:
        separator = argv.index("--", 4)
    except ValueError:
        return 64
    write_roots = [Path(item) for item in argv[4:separator]]
    command = argv[separator + 1 :]
    if not command or not Path(command[0]).is_absolute():
        return 64
    if not write_roots or any(
        not root.is_absolute()
        or not root.is_dir()
        or root.is_symlink()
        for root in write_roots
    ):
        return 64
    try:
        # A single PID and newline is the cgroup-v2 migration ABI.
        with procs_path.open("w", encoding="ascii", newline="\n") as stream:
            stream.write(f"{os.getpid()}\n")
            stream.flush()
        landlock_abi = _apply_landlock(
            [root.resolve(strict=True) for root in write_roots]
        )
        status = f"LANDLOCK_READY:{landlock_abi}\n".encode("ascii")
        if os.write(status_fd, status) != len(status):
            return 70
        os.close(status_fd)
        acknowledgement = os.read(gate_fd, 1)
        os.close(gate_fd)
        if acknowledgement != b"1":
            return 72
        os.execve(command[0], command, os.environ)
    except (OSError, ValueError):
        return 71
    return 71


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
