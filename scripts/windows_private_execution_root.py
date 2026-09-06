"""Descriptor-bound private execution roots for Windows provider processes.

The public object in this module is intentionally opaque and process-local.  A
root is created as a fresh leaf with an explicit protected, inheritable DACL,
then held through a no-share-delete handle for its complete lifetime.  Integrity
labels are applied and restored through retained handles, never by reopening a
mutable pathname.
"""

from __future__ import annotations

import ctypes
from pathlib import Path
import os
import re
import stat
from typing import Any


class WindowsPrivateExecutionRootError(RuntimeError):
    """A private execution-root authority could not be established/replayed."""


_FILE_READ_ATTRIBUTES = 0x00000080
_READ_CONTROL = 0x00020000
_WRITE_OWNER = 0x00080000
_FILE_SHARE_READ = 0x1
_FILE_SHARE_WRITE = 0x2
_OPEN_EXISTING = 3
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_SE_FILE_OBJECT = 1
_OWNER_SECURITY_INFORMATION = 0x1
_DACL_SECURITY_INFORMATION = 0x4
_LABEL_SECURITY_INFORMATION = 0x10
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_SE_DACL_PROTECTED = 0x1000
_ACCESS_ALLOWED_ACE_TYPE = 0
_OBJECT_INHERIT_ACE = 0x1
_CONTAINER_INHERIT_ACE = 0x2
_FILE_ALL_ACCESS = 0x001F01FF


def _require_windows() -> None:
    if os.name != "nt":
        raise WindowsPrivateExecutionRootError(
            "Windows private execution roots are unavailable on this host"
        )


def _apis() -> tuple[Any, Any]:
    _require_windows()
    return (
        ctypes.WinDLL("kernel32", use_last_error=True),
        ctypes.WinDLL("advapi32", use_last_error=True),
    )


def _native_path(path: Path) -> str:
    value = str(path.absolute())
    if value.startswith("\\\\?\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _path_lstat(path: Path) -> os.stat_result:
    """No-follow metadata through the extended-length Windows namespace."""

    return os.stat(_native_path(path), follow_symlinks=False)


def _path_lexists(path: Path) -> bool:
    try:
        _path_lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    return True


def _current_user_sid() -> str:
    from ctypes import wintypes

    kernel32, advapi32 = _apis()

    class _SidAndAttributes(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    class _TokenUser(ctypes.Structure):
        _fields_ = [("User", _SidAndAttributes)]

    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)
    ):
        raise WindowsPrivateExecutionRootError("cannot open current process token")
    try:
        needed = wintypes.DWORD()
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if not needed.value:
            raise WindowsPrivateExecutionRootError("cannot size token-user record")
        raw = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(
            token, 1, raw, needed, ctypes.byref(needed)
        ):
            raise WindowsPrivateExecutionRootError("cannot read token-user record")
        sid = ctypes.cast(raw, ctypes.POINTER(_TokenUser)).contents.User.Sid
        text = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise WindowsPrivateExecutionRootError("cannot stringify token-user SID")
        try:
            if not text.value:
                raise WindowsPrivateExecutionRootError("token-user SID is empty")
            return str(text.value)
        finally:
            kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
    finally:
        kernel32.CloseHandle(token)


def _security_descriptor(sddl: str) -> tuple[Any, ctypes.c_void_p]:
    from ctypes import wintypes

    kernel32, advapi32 = _apis()
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    descriptor = ctypes.c_void_p()
    size = wintypes.DWORD()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), ctypes.byref(size)
    ):
        raise WindowsPrivateExecutionRootError(
            f"cannot compile Windows security descriptor: {ctypes.get_last_error()}"
        )
    return kernel32, descriptor


def _close_native(handle: int | None) -> None:
    if handle in (None, 0, _INVALID_HANDLE_VALUE):
        return
    from ctypes import wintypes

    kernel32, _ = _apis()
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle(wintypes.HANDLE(handle))


def _open_retained(path: Path, *, directory: bool) -> int:
    from ctypes import wintypes

    kernel32, _ = _apis()
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    flags = _FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= _FILE_FLAG_BACKUP_SEMANTICS
    handle = kernel32.CreateFileW(
        _native_path(path),
        _READ_CONTROL | _WRITE_OWNER | _FILE_READ_ATTRIBUTES,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
        None,
        _OPEN_EXISTING,
        flags,
        None,
    )
    raw = ctypes.cast(handle, ctypes.c_void_p).value
    if raw == _INVALID_HANDLE_VALUE:
        raise WindowsPrivateExecutionRootError(
            f"cannot retain private execution-root object: {ctypes.get_last_error()}"
        )
    return int(raw)


def _handle_identity(handle: int, *, require_directory: bool) -> tuple[int, ...]:
    from ctypes import wintypes

    class _FileTime(ctypes.Structure):
        _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD),
            ("created", _FileTime),
            ("accessed", _FileTime),
            ("written", _FileTime),
            ("volume", wintypes.DWORD),
            ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD),
            ("links", wintypes.DWORD),
            ("index_high", wintypes.DWORD),
            ("index_low", wintypes.DWORD),
        ]

    kernel32, _ = _apis()
    kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_ByHandleFileInformation),
    ]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    row = _ByHandleFileInformation()
    if not kernel32.GetFileInformationByHandle(
        wintypes.HANDLE(handle), ctypes.byref(row)
    ):
        raise WindowsPrivateExecutionRootError("cannot identify retained root handle")
    attributes = int(row.attributes)
    if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise WindowsPrivateExecutionRootError("execution root is a reparse point")
    if bool(attributes & _FILE_ATTRIBUTE_DIRECTORY) is not require_directory:
        raise WindowsPrivateExecutionRootError("execution-root object type drifted")
    if int(row.links) != 1:
        raise WindowsPrivateExecutionRootError("execution-root object is hardlinked")
    return (
        int(row.volume),
        int(row.index_high),
        int(row.index_low),
        int(row.links),
        attributes,
    )


def _handle_final_path(handle: int) -> Path:
    from ctypes import wintypes

    kernel32, _ = _apis()
    kernel32.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    size = int(kernel32.GetFinalPathNameByHandleW(wintypes.HANDLE(handle), None, 0, 0))
    if not size or size > 32768:
        raise WindowsPrivateExecutionRootError("cannot size retained root path")
    buf = ctypes.create_unicode_buffer(size + 1)
    used = int(
        kernel32.GetFinalPathNameByHandleW(
            wintypes.HANDLE(handle), buf, len(buf), 0
        )
    )
    if not used or used >= len(buf):
        raise WindowsPrivateExecutionRootError("cannot read retained root path")
    value = buf.value
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return Path(value)


def _ancestor_identities(path: Path) -> tuple[tuple[str, int, int, int], ...]:
    """Reject aliases and bind every existing ancestor through the volume root."""

    rows: list[tuple[str, int, int, int]] = []
    current = path.absolute()
    while True:
        try:
            row = _path_lstat(current)
        except OSError as exc:
            raise WindowsPrivateExecutionRootError(
                "execution-root ancestor is unavailable"
            ) from exc
        attributes = int(getattr(row, "st_file_attributes", 0))
        if (
            stat.S_ISLNK(row.st_mode)
            or attributes & _FILE_ATTRIBUTE_REPARSE_POINT
            or not stat.S_ISDIR(row.st_mode)
        ):
            raise WindowsPrivateExecutionRootError(
                "execution-root ancestor is aliased or not a directory"
            )
        rows.append(
            (
                os.path.normcase(str(current)),
                int(row.st_dev),
                int(row.st_ino),
                attributes,
            )
        )
        parent = current.parent
        if parent == current:
            break
        current = parent
    return tuple(reversed(rows))


def _handle_integrity_sddl(handle: int) -> str:
    from ctypes import wintypes

    kernel32, advapi32 = _apis()
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
    descriptor = ctypes.c_void_p()
    result = int(
        advapi32.GetSecurityInfo(
            wintypes.HANDLE(handle),
            _SE_FILE_OBJECT,
            _LABEL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            ctypes.byref(descriptor),
        )
    )
    if result or not descriptor.value:
        if descriptor.value:
            kernel32.LocalFree(descriptor)
        raise WindowsPrivateExecutionRootError(
            f"cannot inspect retained integrity label: {result}"
        )
    text = wintypes.LPWSTR()
    length = wintypes.DWORD()
    try:
        if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            1,
            _LABEL_SECURITY_INFORMATION,
            ctypes.byref(text),
            ctypes.byref(length),
        ):
            raise WindowsPrivateExecutionRootError(
                "cannot canonicalize retained integrity label"
            )
        return str(text.value or "")
    finally:
        if text:
            kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
        kernel32.LocalFree(descriptor)


def _verify_private_security(handle: int, sid_text: str) -> dict[str, Any]:
    from ctypes import wintypes

    class _Acl(ctypes.Structure):
        _fields_ = [
            ("revision", ctypes.c_ubyte),
            ("reserved", ctypes.c_ubyte),
            ("size", wintypes.WORD),
            ("count", wintypes.WORD),
            ("reserved2", wintypes.WORD),
        ]

    class _AceHeader(ctypes.Structure):
        _fields_ = [
            ("ace_type", ctypes.c_ubyte),
            ("flags", ctypes.c_ubyte),
            ("size", wintypes.WORD),
        ]

    class _AllowAce(ctypes.Structure):
        _fields_ = [
            ("header", _AceHeader),
            ("mask", wintypes.DWORD),
            ("sid_start", wintypes.DWORD),
        ]

    kernel32, advapi32 = _apis()
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi32.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    advapi32.EqualSid.restype = wintypes.BOOL
    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = int(
        advapi32.GetSecurityInfo(
            wintypes.HANDLE(handle),
            _SE_FILE_OBJECT,
            _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
            ctypes.byref(owner),
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(descriptor),
        )
    )
    if result or not owner.value or not dacl.value or not descriptor.value:
        if descriptor.value:
            kernel32.LocalFree(descriptor)
        raise WindowsPrivateExecutionRootError(
            f"cannot inspect private execution-root security: {result}"
        )
    expected = ctypes.c_void_p()
    try:
        if not advapi32.ConvertStringSidToSidW(sid_text, ctypes.byref(expected)):
            raise WindowsPrivateExecutionRootError("cannot compile expected owner SID")
        if not advapi32.EqualSid(owner, expected):
            raise WindowsPrivateExecutionRootError("execution-root owner drifted")
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi32.GetSecurityDescriptorControl(
            descriptor, ctypes.byref(control), ctypes.byref(revision)
        ) or not int(control.value) & _SE_DACL_PROTECTED:
            raise WindowsPrivateExecutionRootError("execution-root DACL is not protected")
        acl = ctypes.cast(dacl, ctypes.POINTER(_Acl)).contents
        if int(acl.count) != 1:
            raise WindowsPrivateExecutionRootError("execution-root DACL is not single-principal")
        ptr = ctypes.c_void_p()
        if not advapi32.GetAce(dacl, 0, ctypes.byref(ptr)):
            raise WindowsPrivateExecutionRootError("cannot inspect execution-root ACE")
        ace = ctypes.cast(ptr, ctypes.POINTER(_AllowAce)).contents
        if (
            int(ace.header.ace_type) != _ACCESS_ALLOWED_ACE_TYPE
            or int(ace.header.flags) != (_OBJECT_INHERIT_ACE | _CONTAINER_INHERIT_ACE)
            or int(ace.mask) != _FILE_ALL_ACCESS
        ):
            raise WindowsPrivateExecutionRootError("execution-root ACE authority drifted")
        ace_sid = ctypes.c_void_p(int(ptr.value) + int(_AllowAce.sid_start.offset))
        if not advapi32.EqualSid(ace_sid, expected):
            raise WindowsPrivateExecutionRootError("execution-root ACE principal drifted")
        return {
            "owner_sid": sid_text,
            "dacl_protected": True,
            "ace_count": 1,
            "access_mask": _FILE_ALL_ACCESS,
            "inheritance_flags": _OBJECT_INHERIT_ACE | _CONTAINER_INHERIT_ACE,
        }
    finally:
        if expected.value:
            kernel32.LocalFree(expected)
        kernel32.LocalFree(descriptor)


def _set_handle_integrity(handle: int, *, sid_alias: str, inheritable: bool) -> None:
    from ctypes import wintypes

    kernel32, advapi32 = _apis()
    flags = "OICI" if inheritable else ""
    _, descriptor = _security_descriptor(f"S:(ML;{flags};NW;;;{sid_alias})")
    advapi32.GetSecurityDescriptorSacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorSacl.restype = wintypes.BOOL
    advapi32.SetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    advapi32.SetSecurityInfo.restype = wintypes.DWORD
    try:
        present = wintypes.BOOL()
        defaulted = wintypes.BOOL()
        sacl = ctypes.c_void_p()
        if not advapi32.GetSecurityDescriptorSacl(
            descriptor,
            ctypes.byref(present),
            ctypes.byref(sacl),
            ctypes.byref(defaulted),
        ) or not present.value or not sacl.value:
            raise WindowsPrivateExecutionRootError("compiled integrity label is absent")
        result = int(
            advapi32.SetSecurityInfo(
                wintypes.HANDLE(handle),
                _SE_FILE_OBJECT,
                _LABEL_SECURITY_INFORMATION,
                None,
                None,
                None,
                sacl,
            )
        )
        if result:
            raise WindowsPrivateExecutionRootError(
                f"SetSecurityInfo(integrity label) failed: {result}"
            )
    finally:
        kernel32.LocalFree(descriptor)


class WindowsPrivateExecutionRootAuthority:
    """Opaque retained authority for one fresh private execution root."""

    __slots__ = ("_path", "_handle", "_identity", "_sid", "_security", "_low")

    def __init__(
        self,
        *,
        path: Path,
        handle: int,
        identity: tuple[int, ...],
        sid: str,
        security: dict[str, Any],
    ) -> None:
        self._path = path
        self._handle = handle
        self._identity = identity
        self._sid = sid
        self._security = security
        self._low = False

    @property
    def path(self) -> Path:
        return self._path

    @property
    def binding(self) -> dict[str, Any]:
        self.replay()
        return {
            "protocol": "WINDOWS_RETAINED_PRIVATE_EXECUTION_ROOT_V1",
            "path": str(self._path),
            "identity": list(self._identity),
            "owner": "CURRENT_PROCESS_TOKEN_USER",
            "dacl": dict(self._security),
            "retained_no_share_delete": True,
            "integrity_state": "LOW" if self._low else "MEDIUM",
        }

    def replay(self) -> None:
        if self._handle is None:
            raise WindowsPrivateExecutionRootError("execution-root authority is closed")
        if _handle_identity(self._handle, require_directory=True) != self._identity:
            raise WindowsPrivateExecutionRootError("execution-root identity drifted")
        final = _handle_final_path(self._handle)
        if os.path.normcase(str(final)) != os.path.normcase(str(self._path)):
            raise WindowsPrivateExecutionRootError("execution-root path drifted")
        security = _verify_private_security(self._handle, self._sid)
        if security != self._security:
            raise WindowsPrivateExecutionRootError("execution-root security drifted")

    def lower_to_low_integrity(self) -> None:
        self.replay()
        _set_handle_integrity(self._handle, sid_alias="LW", inheritable=True)
        if not re.search(r";;;(?:LW|S-1-16-4096)\)", _handle_integrity_sddl(self._handle)):
            raise WindowsPrivateExecutionRootError(
                "retained execution root did not replay Low integrity"
            )
        self.replay()
        self._low = True

    def restore_medium_integrity_tree(self) -> None:
        self.replay()
        members: list[tuple[Path, bool]] = []
        pending = [self._path]
        while pending:
            current = pending.pop()
            try:
                # Codex can create nested cache/plugin paths beyond the legacy
                # Win32 MAX_PATH boundary inside its private runtime home.
                # The authority already owns and identity-binds this root, so
                # enumerate through the extended-length spelling just as the
                # retained-handle helpers do.
                with os.scandir(_native_path(current)) as entries:
                    for entry in entries:
                        member = Path(entry.path)
                        if entry.is_symlink():
                            raise WindowsPrivateExecutionRootError(
                                "private execution root contains a symlink/reparse point"
                            )
                        row = member.lstat()
                        if int(getattr(row, "st_file_attributes", 0)) & _FILE_ATTRIBUTE_REPARSE_POINT:
                            raise WindowsPrivateExecutionRootError(
                                "private execution root contains a reparse point"
                            )
                        if stat.S_ISDIR(row.st_mode):
                            members.append((member, True))
                            pending.append(member)
                        elif stat.S_ISREG(row.st_mode):
                            members.append((member, False))
                        else:
                            raise WindowsPrivateExecutionRootError(
                                "private execution root contains a special object"
                            )
            except OSError as exc:
                raise WindowsPrivateExecutionRootError(
                    "cannot enumerate private execution root"
                ) from exc
        for member, directory in reversed(members):
            handle = _open_retained(member, directory=directory)
            try:
                _handle_identity(handle, require_directory=directory)
                final = _handle_final_path(handle)
                try:
                    final.relative_to(self._path)
                except ValueError as exc:
                    raise WindowsPrivateExecutionRootError(
                        "private execution-root member escaped root"
                    ) from exc
                _set_handle_integrity(handle, sid_alias="ME", inheritable=directory)
            finally:
                _close_native(handle)
        _set_handle_integrity(self._handle, sid_alias="ME", inheritable=True)
        if not re.search(r";;;(?:ME|S-1-16-8192)\)", _handle_integrity_sddl(self._handle)):
            raise WindowsPrivateExecutionRootError(
                "retained execution root did not replay Medium integrity"
            )
        self.replay()
        self._low = False

    def close_after_medium_restore(self) -> None:
        if self._low:
            raise WindowsPrivateExecutionRootError(
                "cannot close a private execution root while it is Low integrity"
            )
        self.replay()
        handle = self._handle
        self._handle = None
        _close_native(handle)

    def __reduce__(self) -> None:
        raise TypeError("WindowsPrivateExecutionRootAuthority cannot be serialized")

    def __repr__(self) -> str:
        return "<WindowsPrivateExecutionRootAuthority opaque>"


def create_windows_private_execution_root(
    path: str | Path,
) -> WindowsPrivateExecutionRootAuthority:
    """Create and retain one exact fresh leaf without changing its parent ACL."""

    from ctypes import wintypes

    _require_windows()
    candidate = Path(path).absolute()
    parent = candidate.parent
    try:
        parent_row = _path_lstat(parent)
    except OSError as exc:
        raise WindowsPrivateExecutionRootError(
            "execution-root parent is unavailable"
        ) from exc
    if (
        not candidate.name
        or not stat.S_ISDIR(parent_row.st_mode)
        or stat.S_ISLNK(parent_row.st_mode)
        or int(getattr(parent_row, "st_file_attributes", 0))
        & _FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise WindowsPrivateExecutionRootError("execution-root parent is unavailable")
    if _path_lexists(candidate):
        raise WindowsPrivateExecutionRootError("execution root must be a fresh leaf")
    ancestors = _ancestor_identities(parent)
    sid = _current_user_sid()
    kernel32, descriptor = _security_descriptor(
        f"O:{sid}G:{sid}D:P(A;OICI;FA;;;{sid})"
    )

    class _SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.DWORD),
            ("descriptor", ctypes.c_void_p),
            ("inherit", wintypes.BOOL),
        ]

    attrs = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
    kernel32.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(_SecurityAttributes)]
    kernel32.CreateDirectoryW.restype = wintypes.BOOL
    created = False
    handle: int | None = None
    try:
        if not kernel32.CreateDirectoryW(
            _native_path(candidate),
            ctypes.byref(attrs),
        ):
            raise WindowsPrivateExecutionRootError(
                f"cannot create private execution root: {ctypes.get_last_error()}"
            )
        created = True
    finally:
        kernel32.LocalFree(descriptor)
    try:
        handle = _open_retained(candidate, directory=True)
        identity = _handle_identity(handle, require_directory=True)
        final = _handle_final_path(handle)
        # The retained handle supplies the canonical object/path replay. Avoid
        # pathlib's legacy Win32 spelling here: retry output roots can exceed
        # MAX_PATH even though the already-validated parent is ordinary.
        expected = candidate
        if os.path.normcase(str(final)) != os.path.normcase(str(expected)):
            raise WindowsPrivateExecutionRootError("created execution root was redirected")
        security = _verify_private_security(handle, sid)
        if _ancestor_identities(parent) != ancestors:
            raise WindowsPrivateExecutionRootError(
                "execution-root ancestor identity drifted during creation"
            )
        authority = WindowsPrivateExecutionRootAuthority(
            path=expected,
            handle=handle,
            identity=identity,
            sid=sid,
            security=security,
        )
        handle = None
        authority.replay()
        return authority
    except BaseException:
        _close_native(handle)
        if created:
            try:
                os.rmdir(_native_path(candidate))
            except OSError:
                pass
        raise


def is_windows_private_execution_root_authority(value: object) -> bool:
    return type(value) is WindowsPrivateExecutionRootAuthority


__all__ = [
    "WindowsPrivateExecutionRootAuthority",
    "WindowsPrivateExecutionRootError",
    "create_windows_private_execution_root",
    "is_windows_private_execution_root_authority",
]
