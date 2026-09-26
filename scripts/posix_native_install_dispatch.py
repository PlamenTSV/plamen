"""One-way POSIX handoff from the source CLI to the native installer.

This module is deliberately only an admission and ``execve`` boundary.  It
does not build, copy, publish, repair, or remove anything.  The production
builder owns the installation transaction and must independently authenticate
all of its inputs.
"""

from __future__ import annotations

import hashlib
import os
import pwd
import stat
import sys
import unicodedata
from typing import NoReturn


INSTALL_ARGV = ("install", "--codex")
BUILDER_RELATIVE = ("scripts", "build_posix_native_supervisor.py")
COMPAT_INSTALLER_RELATIVE = ("scripts", "posix_v2_compat_install.py")
DISPATCH_RELATIVE = ("scripts", "posix_native_install_dispatch.py")
PYTHON_CANDIDATES = (
    "/opt/homebrew/bin/python3.12",
    "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12",
    "/usr/local/bin/python3.12",
    "/usr/bin/python3.12",
    "/opt/local/bin/python3.12",
)
CLOSED_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "PYTHONHASHSEED": "0",
}
MAX_PATH_BYTES = 4096
MAX_BUILDER_BYTES = 4 * 1024 * 1024
_dispatch_started = False

# The designated interpreter is the explicit source-install bootstrap trust
# boundary.  It consumes the already-retained builder descriptor; the child
# never opens the mutable repository pathname as Python source.
_RETAINED_BUILDER_LOADER = """\
import hashlib,os,stat,sys,types
fd=int(sys.argv[1]); size=int(sys.argv[2]); expected=sys.argv[3]
display=sys.argv[4]; expected_uid=int(sys.argv[5]); expected_mode=int(sys.argv[6])
os.set_inheritable(fd,False)
before=os.fstat(fd)
identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,
                   s.st_size,s.st_mtime_ns,s.st_ctime_ns)
before_identity=identity(before)
if (not stat.S_ISREG(before.st_mode) or before.st_uid!=expected_uid or
    before.st_nlink!=1 or stat.S_IMODE(before.st_mode)!=expected_mode or
    before.st_size!=size or size<1 or size>4194304):
    raise SystemExit(126)
chunks=[]; offset=0
while offset<size:
    chunk=os.pread(fd,min(262144,size-offset),offset)
    if not chunk: raise SystemExit(126)
    chunks.append(chunk); offset+=len(chunk)
if os.pread(fd,1,size) or identity(os.fstat(fd))!=before_identity:
    raise SystemExit(126)
raw=b''.join(chunks)
if len(raw)!=size or hashlib.sha256(raw).hexdigest()!=expected:
    raise SystemExit(126)
os.close(fd)
sys.argv=[display,'--install-codex']
main=types.ModuleType('__main__')
main.__file__=display
main.__package__=None
main.__cached__=None
sys.modules['__main__']=main
exec(compile(raw,display,'exec',dont_inherit=True),main.__dict__,main.__dict__)
"""

_RETAINED_COMPAT_INSTALLER_LOADER = """\
import hashlib,os,stat,sys,types
fd=int(sys.argv[1]); size=int(sys.argv[2]); expected=sys.argv[3]
display=sys.argv[4]; expected_uid=int(sys.argv[5]); expected_mode=int(sys.argv[6])
source=sys.argv[7]; home=sys.argv[8]; python=sys.argv[9]
os.set_inheritable(fd,False)
before=os.fstat(fd)
identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,
                   s.st_size,s.st_mtime_ns,s.st_ctime_ns)
before_identity=identity(before)
if (not stat.S_ISREG(before.st_mode) or before.st_uid!=expected_uid or
    before.st_nlink!=1 or stat.S_IMODE(before.st_mode)!=expected_mode or
    before.st_size!=size or size<1 or size>4194304):
    raise SystemExit(126)
chunks=[]; offset=0
while offset<size:
    chunk=os.pread(fd,min(262144,size-offset),offset)
    if not chunk: raise SystemExit(126)
    chunks.append(chunk); offset+=len(chunk)
if os.pread(fd,1,size) or identity(os.fstat(fd))!=before_identity:
    raise SystemExit(126)
raw=b''.join(chunks)
if len(raw)!=size or hashlib.sha256(raw).hexdigest()!=expected:
    raise SystemExit(126)
os.close(fd)
sys.argv=[display,'--posix-compat-v2','--source',source,'--install',
          '--home',home,'--python',python]
main=types.ModuleType('__main__')
main.__file__=display
main.__package__=None
main.__cached__=None
sys.modules['__main__']=main
exec(compile(raw,display,'exec',dont_inherit=True),main.__dict__,main.__dict__)
"""


class PosixNativeInstallDispatchError(RuntimeError):
    """A bounded failure before the native install authority is entered."""


def _fail(message: str) -> NoReturn:
    raise PosixNativeInstallDispatchError(message) from None


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
    if not components or any(item in {"", ".", ".."} for item in components):
        _fail(f"{label} is not canonical absolute")
    return value


def _account() -> tuple[int, str]:
    if os.name != "posix" or sys.platform not in {"darwin", "linux"}:
        _fail("native installation requires Darwin or Linux")
    try:
        uid = os.getuid()
    except (AttributeError, OSError):
        _fail("native install account identity is unavailable")
    if type(uid) is not int or isinstance(uid, bool) or uid < 0:
        _fail("native install account identity is malformed")
    try:
        record = pwd.getpwuid(uid)
        record_uid = record.pw_uid
        home = record.pw_dir
    except (KeyError, OSError, AttributeError):
        _fail("native install account record is unavailable")
    if type(record_uid) is not int or isinstance(record_uid, bool) or record_uid != uid:
        _fail("native install account identity differs")
    return uid, _canonical_absolute_path(home, "native install account home")


def _directory_is_safe(
    observed: os.stat_result,
    uid: int,
    *,
    allow_owned_group_write: bool = False,
) -> bool:
    mode = observed.st_mode
    if not stat.S_ISDIR(mode) or observed.st_uid not in {0, uid}:
        return False
    writable_by_others = mode & (stat.S_IWGRP | stat.S_IWOTH)
    sticky_root = observed.st_uid == 0 and bool(mode & stat.S_ISVTX)
    owned_group_write = (
        allow_owned_group_write
        and observed.st_uid == uid
        and not mode & stat.S_IWOTH
    )
    return not writable_by_others or sticky_root or owned_group_write


def _identity(observed: os.stat_result) -> tuple[int, ...]:
    return (
        int(observed.st_dev),
        int(observed.st_ino),
        int(observed.st_mode),
        int(observed.st_uid),
        int(observed.st_gid),
        int(observed.st_nlink),
        int(observed.st_size),
        int(observed.st_mtime_ns),
        int(observed.st_ctime_ns),
    )


def _directory_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        _fail("native install no-link descriptor support is unavailable")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW


def _open_directory_no_links(
    path: str,
    uid: int,
    *,
    missing_ok: bool = False,
    allow_owned_group_write: bool = False,
) -> tuple[int, os.stat_result]:
    """Open every directory component without resolving a symbolic link."""
    canonical = _canonical_absolute_path(path, "native install directory")
    flags = _directory_flags()
    current = -1
    try:
        current = os.open("/", flags)
        root_stat = os.fstat(current)
        if not _directory_is_safe(
            root_stat, uid, allow_owned_group_write=allow_owned_group_write
        ):
            _fail("native install traversal root is unsafe")
        for component in canonical.split("/")[1:]:
            opened = os.open(component, flags, dir_fd=current)
            observed = os.fstat(opened)
            if not _directory_is_safe(
                observed, uid,
                allow_owned_group_write=allow_owned_group_write,
            ):
                os.close(opened)
                _fail("native install directory authority differs")
            os.close(current)
            current = opened
        os.set_inheritable(current, False)
        return current, os.fstat(current)
    except PosixNativeInstallDispatchError:
        if current >= 0:
            os.close(current)
        raise
    except FileNotFoundError:
        if current >= 0:
            os.close(current)
        if missing_ok:
            raise
        _fail("native install directory admission failed")
    except (OSError, ValueError, OverflowError):
        if current >= 0:
            os.close(current)
        _fail("native install directory admission failed")


def _validate_regular_source(observed: os.stat_result, uid: int, label: str) -> None:
    mode = stat.S_IMODE(observed.st_mode)
    if (
        not stat.S_ISREG(observed.st_mode)
        or observed.st_uid not in {0, uid}
        or observed.st_nlink != 1
        or observed.st_size <= 0
        or not mode & stat.S_IRUSR
        or mode & (stat.S_IWGRP | stat.S_IWOTH)
        or mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
    ):
        _fail(f"{label} authority differs")


def _open_repository_builder(
    uid: int,
) -> tuple[str, int, int, int, os.stat_result, os.stat_result]:
    source = _canonical_absolute_path(__file__, "native install dispatcher path")
    expected_suffix = "/" + "/".join(DISPATCH_RELATIVE)
    if not source.endswith(expected_suffix):
        _fail("native install dispatcher repository shape differs")
    repository = source[:-len(expected_suffix)]
    if not repository:
        repository = "/"
    repository = _canonical_absolute_path(repository, "native install repository")
    repository_fd = scripts_fd = builder_fd = -1
    try:
        repository_fd, repository_stat = _open_directory_no_links(repository, uid)
        scripts_fd = os.open("scripts", _directory_flags(), dir_fd=repository_fd)
        scripts_stat = os.fstat(scripts_fd)
        if not _directory_is_safe(scripts_stat, uid):
            _fail("native install scripts directory authority differs")
        source_fd = os.open(
            DISPATCH_RELATIVE[1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=scripts_fd,
        )
        try:
            source_stat = os.fstat(source_fd)
            _validate_regular_source(source_stat, uid, "native install dispatcher")
            if _identity(source_stat) != _identity(os.stat(source, follow_symlinks=False)):
                _fail("native install dispatcher identity differs")
        finally:
            os.close(source_fd)
        builder_fd = os.open(
            BUILDER_RELATIVE[1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=scripts_fd,
        )
        builder_stat = os.fstat(builder_fd)
        _validate_regular_source(builder_stat, uid, "native install builder")
        builder = repository + "/" + "/".join(BUILDER_RELATIVE)
        builder = _canonical_absolute_path(builder, "native install builder path")
        return (
            builder,
            repository_fd,
            scripts_fd,
            builder_fd,
            repository_stat,
            builder_stat,
        )
    except PosixNativeInstallDispatchError:
        if builder_fd >= 0:
            os.close(builder_fd)
        if scripts_fd >= 0:
            os.close(scripts_fd)
        if repository_fd >= 0:
            os.close(repository_fd)
        raise
    except (OSError, ValueError, OverflowError):
        if builder_fd >= 0:
            os.close(builder_fd)
        if scripts_fd >= 0:
            os.close(scripts_fd)
        if repository_fd >= 0:
            os.close(repository_fd)
        _fail("native install builder admission failed")


def _validate_python_target(observed: os.stat_result, uid: int) -> None:
    mode = stat.S_IMODE(observed.st_mode)
    if (
        not stat.S_ISREG(observed.st_mode)
        or observed.st_uid not in {0, uid}
        or observed.st_nlink < 1
        or observed.st_size <= 0
        or not mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        or mode & (stat.S_IWGRP | stat.S_IWOTH)
        or mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
    ):
        _fail("CPython 3.12 executable authority differs")


def _open_python_candidate(path: str, uid: int) -> tuple[int, os.stat_result, os.stat_result]:
    canonical = _canonical_absolute_path(path, "CPython 3.12 candidate")
    if canonical.rsplit("/", 1)[-1] not in {"python", "python3.12"}:
        _fail("CPython 3.12 candidate name differs")
    parent, _name = canonical.rsplit("/", 1)
    parent_fd = target_fd = -1
    candidate_seen = False
    try:
        parent_fd, _parent_stat = _open_directory_no_links(
            parent,
            uid,
            missing_ok=True,
            allow_owned_group_write=True,
        )
        link_stat = os.stat(canonical, follow_symlinks=False)
        candidate_seen = True
        if stat.S_ISLNK(link_stat.st_mode):
            if link_stat.st_uid not in {0, uid}:
                _fail("CPython 3.12 link authority differs")
        elif not stat.S_ISREG(link_stat.st_mode):
            _fail("CPython 3.12 candidate type differs")
        target_fd = os.open(_name, os.O_RDONLY | os.O_CLOEXEC, dir_fd=parent_fd)
        target_stat = os.fstat(target_fd)
        _validate_python_target(target_stat, uid)
        os.set_inheritable(target_fd, False)
        os.close(parent_fd)
        return target_fd, link_stat, target_stat
    except PosixNativeInstallDispatchError:
        if target_fd >= 0:
            os.close(target_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
        raise
    except FileNotFoundError:
        if target_fd >= 0:
            os.close(target_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
        if candidate_seen:
            _fail("CPython 3.12 candidate target is unavailable")
        raise
    except (OSError, ValueError, OverflowError):
        if target_fd >= 0:
            os.close(target_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
        _fail("CPython 3.12 candidate admission failed")


def _select_python(uid: int) -> tuple[str, int, os.stat_result, os.stat_result]:
    for candidate in PYTHON_CANDIDATES:
        try:
            descriptor, link_stat, target_stat = _open_python_candidate(candidate, uid)
        except FileNotFoundError:
            continue
        return candidate, descriptor, link_stat, target_stat
    _fail("an admitted CPython 3.12 executable is unavailable")


def _revalidate_python(
    path: str,
    descriptor: int,
    expected_link: os.stat_result,
    expected_target: os.stat_result,
) -> None:
    try:
        if (
            _identity(os.fstat(descriptor)) != _identity(expected_target)
            or _identity(os.stat(path, follow_symlinks=False)) != _identity(expected_link)
            or _identity(os.stat(path, follow_symlinks=True)) != _identity(expected_target)
        ):
            _fail("CPython 3.12 executable identity drifted")
    except PosixNativeInstallDispatchError:
        raise
    except (OSError, ValueError, OverflowError):
        _fail("CPython 3.12 executable revalidation failed")


def _revalidate_builder(
    path: str,
    repository_fd: int,
    expected_repository: os.stat_result,
    scripts_fd: int,
    builder_fd: int,
    expected_builder: os.stat_result,
) -> None:
    try:
        observed_repository = os.fstat(repository_fd)
        observed_scripts = os.stat("scripts", dir_fd=repository_fd, follow_symlinks=False)
        observed_builder = os.stat(
            BUILDER_RELATIVE[1], dir_fd=scripts_fd, follow_symlinks=False
        )
        absolute_builder = os.stat(path, follow_symlinks=False)
        if (
            _identity(observed_repository) != _identity(expected_repository)
            or not stat.S_ISDIR(observed_scripts.st_mode)
            or _identity(os.fstat(builder_fd)) != _identity(expected_builder)
            or _identity(observed_builder) != _identity(expected_builder)
            or _identity(absolute_builder) != _identity(expected_builder)
        ):
            _fail("native install builder identity drifted")
    except PosixNativeInstallDispatchError:
        raise
    except (OSError, ValueError, OverflowError):
        _fail("native install builder revalidation failed")


def exec_native_install(argv: object) -> NoReturn:
    """Admit exactly ``install --codex`` and replace this process once."""
    global _dispatch_started
    if type(argv) is not list or argv != list(INSTALL_ARGV):
        _fail("native install argv is unsupported")
    if _dispatch_started:
        _fail("native install dispatch was already attempted")
    _dispatch_started = True

    uid, _home = _account()
    python_path = builder_path = ""
    python_fd = repository_fd = scripts_fd = builder_fd = -1
    try:
        python_path, python_fd, python_link, python_target = _select_python(uid)
        (
            builder_path,
            repository_fd,
            scripts_fd,
            builder_fd,
            repository_stat,
            builder_stat,
        ) = _open_repository_builder(uid)
        _revalidate_python(python_path, python_fd, python_link, python_target)
        _revalidate_builder(
            builder_path,
            repository_fd,
            repository_stat,
            scripts_fd,
            builder_fd,
            builder_stat,
        )
        if not 1 <= builder_stat.st_size <= MAX_BUILDER_BYTES:
            _fail("native install builder size differs")
        builder_raw = bytearray()
        offset = 0
        while offset < builder_stat.st_size:
            chunk = os.pread(
                builder_fd,
                min(256 * 1024, builder_stat.st_size - offset),
                offset,
            )
            if not chunk:
                _fail("native install builder read was incomplete")
            builder_raw.extend(chunk)
            offset += len(chunk)
        if os.pread(builder_fd, 1, builder_stat.st_size):
            _fail("native install builder size differs")
        builder_sha256 = hashlib.sha256(builder_raw).hexdigest()
        del builder_raw
        os.set_inheritable(builder_fd, True)
        exec_argv = [
            python_path,
            "-I",
            "-B",
            "-c",
            _RETAINED_BUILDER_LOADER,
            str(builder_fd),
            str(builder_stat.st_size),
            builder_sha256,
            builder_path,
            str(builder_stat.st_uid),
            str(stat.S_IMODE(builder_stat.st_mode)),
        ]
        os.execve(python_path, exec_argv, dict(CLOSED_ENVIRONMENT))
        _fail("native install exec returned")
    finally:
        if builder_fd >= 0:
            os.close(builder_fd)
        if scripts_fd >= 0:
            os.close(scripts_fd)
        if repository_fd >= 0:
            os.close(repository_fd)
        if python_fd >= 0:
            os.close(python_fd)


def exec_posix_install(argv: object) -> NoReturn:
    """Select the qualified POSIX install transaction without fallback."""

    if sys.platform != "darwin":
        exec_native_install(argv)
    global _dispatch_started
    if type(argv) is not list or argv != list(INSTALL_ARGV):
        _fail("compatibility install argv is unsupported")
    if _dispatch_started:
        _fail("POSIX install dispatch was already attempted")
    _dispatch_started = True

    uid, home = _account()
    python_path = os.path.join(
        home, ".local", "share", "plamen", "runtime", "py312", "bin", "python"
    )
    python_fd = repository_fd = scripts_fd = builder_fd = installer_fd = -1
    try:
        python_fd, python_link, python_target = _open_python_candidate(
            python_path, uid,
        )
        (
            builder_path, repository_fd, scripts_fd, builder_fd,
            repository_stat, builder_stat,
        ) = _open_repository_builder(uid)
        source = builder_path.rsplit("/scripts/", 1)[0]
        installer_path = source + "/" + "/".join(COMPAT_INSTALLER_RELATIVE)
        installer_fd = os.open(
            COMPAT_INSTALLER_RELATIVE[1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=scripts_fd,
        )
        installer_stat = os.fstat(installer_fd)
        _validate_regular_source(
            installer_stat, uid, "POSIX compatibility installer",
        )
        _revalidate_python(python_path, python_fd, python_link, python_target)
        _revalidate_builder(
            builder_path, repository_fd, repository_stat,
            scripts_fd, builder_fd, builder_stat,
        )
        if _identity(os.stat(
            COMPAT_INSTALLER_RELATIVE[1], dir_fd=scripts_fd,
            follow_symlinks=False,
        )) != _identity(installer_stat) or _identity(os.stat(
            installer_path, follow_symlinks=False,
        )) != _identity(installer_stat):
            _fail("POSIX compatibility installer identity drifted")
        if not 1 <= installer_stat.st_size <= MAX_BUILDER_BYTES:
            _fail("POSIX compatibility installer size differs")
        raw = bytearray()
        offset = 0
        while offset < installer_stat.st_size:
            chunk = os.pread(
                installer_fd,
                min(256 * 1024, installer_stat.st_size - offset), offset,
            )
            if not chunk:
                _fail("POSIX compatibility installer read was incomplete")
            raw.extend(chunk)
            offset += len(chunk)
        if os.pread(installer_fd, 1, installer_stat.st_size):
            _fail("POSIX compatibility installer size differs")
        digest = hashlib.sha256(raw).hexdigest()
        del raw
        os.set_inheritable(installer_fd, True)
        exec_argv = [
            python_path, "-I", "-B", "-c",
            _RETAINED_COMPAT_INSTALLER_LOADER,
            str(installer_fd), str(installer_stat.st_size), digest,
            installer_path, str(installer_stat.st_uid),
            str(stat.S_IMODE(installer_stat.st_mode)), source, home,
            python_path,
        ]
        os.execve(python_path, exec_argv, dict(CLOSED_ENVIRONMENT))
        _fail("compatibility install exec returned")
    finally:
        for descriptor in (
            installer_fd, builder_fd, scripts_fd, repository_fd, python_fd,
        ):
            if descriptor >= 0:
                os.close(descriptor)


def main(argv: list[str] | None = None) -> NoReturn:
    exec_posix_install(sys.argv[1:] if argv is None else argv)


__all__ = [
    "BUILDER_RELATIVE",
    "COMPAT_INSTALLER_RELATIVE",
    "CLOSED_ENVIRONMENT",
    "INSTALL_ARGV",
    "PYTHON_CANDIDATES",
    "PosixNativeInstallDispatchError",
    "exec_native_install",
    "exec_posix_install",
    "main",
]


if __name__ == "__main__":
    main()
