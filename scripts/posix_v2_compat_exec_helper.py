"""Trusted stdlib exec-start observer for the POSIX-V2 compatibility lane.

The parent passes a private control descriptor.  This helper makes that
descriptor non-inheritable before starting the selected executable, so the
target cannot forge either acknowledgement.  ``Popen`` returning establishes
only that the selected executable crossed exec; it does not establish that a
selected test body ran.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

SCHEMA = "plamen.posix_v2_compat_exec_start.v1"

_FAILURE_PREFIX = "PLAMEN_EXEC_HELPER_FAILURE"

def _failure(stage: str, error: BaseException | None = None) -> int:
    """Emit only a bounded stage, exception class, and numeric errno."""
    exception_name = type(error).__name__ if error is not None else "NONE"
    errno = getattr(error, "errno", None) if error is not None else None
    errno_text = str(errno) if isinstance(errno, int) else "NONE"
    raw = f"{_FAILURE_PREFIX} stage={stage} exception={exception_name} errno={errno_text}\n"
    try:
        os.write(2, raw.encode("ascii", "strict"))
    except BaseException:
        pass
    return 125

def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      sort_keys=True, separators=(",", ":")).encode("ascii")

def _hash_file(path: Path) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1:
            raise OSError("selected executable is not a single-link regular file")
        digest = hashlib.sha256()
        remaining = int(observed.st_size)
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise OSError("selected executable shortened")
            digest.update(chunk); remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise OSError("selected executable grew")
        after = os.fstat(descriptor)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode,
                                  value.st_uid, value.st_gid, value.st_size,
                                  value.st_mtime_ns, value.st_ctime_ns)
        if identity(observed) != identity(after):
            raise OSError("selected executable changed while hashing")
        return digest.hexdigest()
    finally:
        os.close(descriptor)

def _write(fd: int, value: dict[str, object]) -> None:
    raw = _canonical(value) + b"\n"
    while raw:
        written = os.write(fd, raw)
        if written <= 0:
            raise OSError("control acknowledgement write stopped")
        raw = raw[written:]

def main(argv: list[str]) -> int:
    if sys.version_info[:2] != (3, 12):
        return _failure("PYTHON_VERSION")
    if len(argv) < 7 or argv[5] != "--":
        return _failure("ARGUMENT_SHAPE")
    stage = "CONTROL_ARGUMENT"
    try:
        control_fd = int(argv[1]); nonce = argv[2]; request_sha = argv[3]
        executable_sha = argv[4]; target = argv[6:]
        if control_fd < 3 or len(nonce) != 64 or len(request_sha) != 64 or len(executable_sha) != 64:
            return _failure("CONTROL_ARGUMENT")
        stage = "EXECUTABLE_RESOLVE"
        executable = Path(target[0]).resolve(strict=True)
        stage = "EXECUTABLE_HASH"
        if _hash_file(executable) != executable_sha:
            return _failure("EXECUTABLE_DIGEST")
        stage = "CONTROL_CLOEXEC"
        os.set_inheritable(control_fd, False)
        stage = "TARGET_EXEC"
        # The controller already bound the helper's fd 0 to /dev/null before
        # entering Seatbelt.  Reopening /dev/null here requests a file-write
        # operation denied by the write-bounded profile, so inherit that
        # already-open descriptor into the selected executable.
        child = subprocess.Popen(target, stdin=None, shell=False,
                                 close_fds=True)
        stage = "START_ACK_WRITE"
        _write(control_fd, {"schema": SCHEMA, "kind": "EXEC_STARTED",
                            "nonce": nonce, "request_sha256": request_sha,
                            "executable_sha256": executable_sha,
                            "pid": int(child.pid)})
        stage = "TARGET_WAIT"
        returncode = child.wait()
        stage = "COMPLETION_ACK_WRITE"
        _write(control_fd, {"schema": SCHEMA, "kind": "EXEC_COMPLETED",
                            "nonce": nonce, "request_sha256": request_sha,
                            "executable_sha256": executable_sha,
                            "returncode": int(returncode)})
        return int(returncode) if 0 <= returncode <= 124 else 124
    except BaseException as error:
        return _failure(stage, error)
    finally:
        try: os.close(int(argv[1]))
        except BaseException: pass

if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
