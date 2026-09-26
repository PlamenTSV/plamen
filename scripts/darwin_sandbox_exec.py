"""Trusted macOS Seatbelt pre-exec write-confinement helper.

The provider passes already-authenticated directory descriptors, not ambient
path strings.  This helper is itself launched beneath Apple's compiled
``sandbox-exec`` utility. It resolves each descriptor through ``F_GETPATH``,
replays its filesystem identity, and only then acknowledges readiness.
Requested program bytes cannot execute until the provider releases the
one-byte gate.

Seatbelt confines writes but does not itself provide descendant lifecycle
ownership.  The provider must independently establish kernel process tracking
before it releases this helper; this module deliberately makes no lifecycle or
recovery claim.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat
import sys

if sys.platform == "darwin":
    import fcntl
else:  # Keep the packaged helper importable for cross-OS closure checks.
    fcntl = None


_F_GETPATH = 50
_PATH_MAX = 1024


def _descriptor_path(descriptor: int) -> Path:
    # ``bytes`` is accepted by every supported CPython fcntl implementation;
    # mutable buffers were only added to some newer releases.
    if fcntl is None:
        raise OSError("F_GETPATH is unavailable outside macOS")
    raw = fcntl.fcntl(descriptor, _F_GETPATH, bytes(_PATH_MAX))
    encoded = bytes(raw).split(b"\0", 1)[0]
    if not encoded:
        raise OSError("F_GETPATH returned an empty path")
    return Path(os.fsdecode(encoded))


def _authenticated_roots(descriptors: list[int]) -> list[Path]:
    roots: list[Path] = []
    identities: list[tuple[int, int]] = []
    for descriptor in descriptors:
        opened = os.fstat(descriptor)
        if not stat.S_ISDIR(opened.st_mode):
            raise OSError("writable-root descriptor is not a directory")
        path = _descriptor_path(descriptor)
        named = os.stat(path, follow_symlinks=False)
        identity = (int(opened.st_dev), int(opened.st_ino))
        if (
            not stat.S_ISDIR(named.st_mode)
            or identity != (int(named.st_dev), int(named.st_ino))
        ):
            raise OSError("writable-root descriptor identity changed")
        roots.append(path)
        identities.append(identity)
    if len({os.fspath(root) for root in roots}) != len(roots):
        raise OSError("duplicate writable-root descriptor")

    # Replay after every pathname has been resolved. A name race inside the
    # already-active policy boundary is a hard failure.
    for descriptor, path, identity in zip(descriptors, roots, identities):
        opened = os.fstat(descriptor)
        named = os.stat(path, follow_symlinks=False)
        if (
            identity != (int(opened.st_dev), int(opened.st_ino))
            or identity != (int(named.st_dev), int(named.st_ino))
        ):
            raise OSError("writable-root identity changed during admission")
    return roots


def main(argv: list[str]) -> int:
    if sys.platform != "darwin" or len(argv) < 6:
        return 64
    try:
        gate_fd = int(argv[1], 10)
        status_fd = int(argv[2], 10)
        root_count = int(argv[3], 10)
    except ValueError:
        return 64
    if gate_fd < 3 or status_fd < 3 or root_count < 0 or root_count > 64:
        return 64
    descriptor_end = 4 + (root_count * 2)
    if len(argv) <= descriptor_end or argv[descriptor_end] != "--":
        return 64
    try:
        root_descriptors = [
            int(argv[index], 10)
            for index in range(4, descriptor_end, 2)
        ]
    except ValueError:
        return 64
    expected_roots = [
        Path(argv[index]) for index in range(5, descriptor_end, 2)
    ]
    command = argv[descriptor_end + 1 :]
    if (
        any(descriptor < 3 for descriptor in root_descriptors)
        or len(set(root_descriptors)) != len(root_descriptors)
        or any(not root.is_absolute() for root in expected_roots)
        or gate_fd in root_descriptors
        or status_fd in root_descriptors
        or gate_fd == status_fd
        or not command
        or not Path(command[0]).is_absolute()
    ):
        return 64
    try:
        observed_roots = _authenticated_roots(root_descriptors)
        if observed_roots != expected_roots:
            raise OSError("writable-root descriptor path changed")
        # Re-observe retained descriptors inside the already-active Seatbelt
        # boundary. A failure never releases requested program bytes.
        if _authenticated_roots(root_descriptors) != expected_roots:
            raise OSError("writable-root descriptor path changed")
        for descriptor in root_descriptors:
            os.close(descriptor)
        status = b"SEATBELT_READY:1\n"
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
