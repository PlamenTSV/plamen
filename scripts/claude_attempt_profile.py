"""Ephemeral, attempt-owned Claude subscription profile materialization.

Only the credential document is copied from the user's Claude config.  Global
settings/state are never imported wholesale or written back.  The attempt
receives minimal synthesized onboarding/trust/isolation state and is revoked
only after the provider proves its complete process scope empty and closed.

The integration boundary is deliberate: materialization binds the profile to
the same persistent process-scope identity used by OwnedProcessScope (and by
an auxiliary writable-root lease, when present).  After normal scope closure,
the trusted coordinator mints ``ClaudeProfileScopeClosureToken`` from that
exact scope object and revokes this profile before revoking its enclosing
auxiliary root.  Raw booleans are never revocation authority.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import threading
from types import MappingProxyType
from typing import Any, Mapping, Sequence

import claude_stored_subscription_source as _stored_subscription
import claude_child_environment as _child_environment
import owned_directory_guard as _owned_directory


_validate_stored_subscription_file_shape = (
    _stored_subscription._validate_file_store_shape
)
_verify_windows_private_credential_security = (
    _stored_subscription._verify_windows_source_security
)
_verify_posix_private_credential_security = (
    _stored_subscription._validate_posix_source_security
)


ATTEMPT_PROFILE_SCHEMA = "plamen.claude_attempt_profile.v3"
REVOCATION_SCHEMA = "plamen.claude_attempt_profile_revocation.v3"
_ATTEMPT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_RUN_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
_EPOCH_RE = re.compile(r"[0-9a-f]{32}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_REPARSE_ATTRIBUTE = 0x400
_PROFILE_TOKEN_CAPABILITY = object()
_POSTPROCESS_AUTHORITY_CAPABILITY = object()
_NORMAL_FAILURE_TOKEN_CAPABILITY = object()
_BOUND_PRELAUNCH_TOKEN_CAPABILITY = object()
_ATTACH_FAILURE_TOKEN_CAPABILITY = object()
_PROFILE_GUARD_SUBJECT_SCHEMA = (
    "plamen.claude_attempt_profile.directory_guard_subject.v1"
)
_PROFILE_LIFECYCLE_DIRECTORY = "profile-lifecycle-v1"
_STARTUP_BINDING_SCHEMA = (
    "plamen.auxiliary_writable_root_startup_permit_binding.v2"
)
_STARTUP_BINDING_FIELDS = {
    "schema",
    "run_id",
    "startup_epoch",
    "current_pointer_sha256",
    "receipt_relative_path",
    "receipt_sha256",
    "allocation_disposition",
}
_STARTUP_ALLOW_DISPOSITIONS = {
    "ALLOW_NEW_LEASES",
    "ALLOW_NEW_LEASES_WITH_RUNTIME_DEBT",
}
_HOME_VARIABLE_POLICIES = {
    "PRIVATE_HOME",
    "PRESERVE_TOOLCHAIN_HOME",
}
_PERMISSION_MODES = {"bypassPermissions", "default", "dontAsk"}
_CREDENTIAL_MODE_ROUTES = {
    "ENVIRONMENT_OAUTH_TOKEN": "OAUTH_TOKEN",
    "COPIED_STORED_SUBSCRIPTION": "STORED_SUBSCRIPTION_OAUTH",
}
_PRIVATE_COPY_MUTATION_DISCARD_ONLY = (
    "UNTRUSTED_PRIVATE_COPY_CHANGED_OR_REPLACED_DISCARD_ONLY"
)
_CURRENT_ATTEMPT_COMPLETION_CREDENTIAL_STATUSES = {
    "NOT_APPLICABLE_ENVIRONMENT_TOKEN",
    "ORIGINAL_PRIVATE_COPY_UNCHANGED",
    _PRIVATE_COPY_MUTATION_DISCARD_ONLY,
}
_CLAUDE_STATE_VERSION = "2.1.252"
_CLAUDE_STATE_MIGRATION_VERSION = 13
_CLAUDE_STATE_INITIAL_STARTUPS = 1
_MAX_STATE_BYTES = 4 * 1024 * 1024
_MAX_STATE_DEPTH = 12
_MAX_STATE_COLLECTION = 4096
_MAX_STATE_STRING = 64 * 1024
_SAFE_STATE_KEY_RE = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
_STATE_SECRET_KEYS = {
    "accesstoken",
    "apikey",
    "apikeyhelper",
    "clientsecret",
    "credential",
    "oauthaccount",
    "oauthtoken",
    "organizationuuid",
    "password",
    "primaryapikey",
    "refreshtoken",
    "secret",
    "token",
    "trusteddevicetoken",
}
_STATE_FORBIDDEN_ROOT_KEYS = {
    "apiKeyHelper",
    "chromeExtension",
    "claudeInChromeDefaultEnabled",
    "enabledPlugins",
    "env",
    "hooks",
    "mcpServers",
    "organizationUuid",
    "permissions",
    "primaryApiKey",
    "remoteControlAtStartup",
    "replBridgeEnabled",
    "trustedDeviceToken",
}
_OAUTH_ACCOUNT_REQUIRED_STRING_LIMITS = {
    "accountUuid": 256,
    "emailAddress": 320,
    "organizationUuid": 256,
    "billingType": 128,
    "displayName": 512,
    "fullName": 512,
}
_OAUTH_ACCOUNT_TIMESTAMP_FIELDS = {
    "accountCreatedAt",
    "subscriptionCreatedAt",
    "claudeCodeTrialEndsAt",
}
_OAUTH_ACCOUNT_FIELDS = (
    set(_OAUTH_ACCOUNT_REQUIRED_STRING_LIMITS)
    | _OAUTH_ACCOUNT_TIMESTAMP_FIELDS
    | {
        "hasExtraUsageEnabled",
        "ccOnboardingFlags",
        "claudeCodeTrialDurationDays",
        "profileFetchedAt",
        "seatTier",
    }
)
_STATE_OPAQUE_CACHE_FIELDS = {
    "additionalModelCostsCache",
    "additionalModelOptionsCache",
    "autoCompactWindowsCache",
    "cachedExperimentData",
    "cachedExperimentFeatures",
    "cachedGrowthBookFeatures",
    "cachedUsageUtilization",
    "clientDataCacheSlots",
    "modelAccessCache",
    "orgModelDefaultCache",
}
_STATE_OPAQUE_USAGE_FIELDS = {
    "pluginUsage",
    "pluginUsageLspGraceAppliedIds",
    "seenNotifications",
    "tipLifetimeShownCounts",
    "tipsHistory",
}
_STATE_COUNTER_FIELDS = {
    "btwUseCount",
    "cachedGrowthBookFeaturesAt",
    "changelogLastFetched",
    "memoryUsageCount",
    "promptQueueUseCount",
    "queuedCommandUpHintCount",
}
_STATE_BOOLEAN_FIELDS = {
    "hasResetAutoModeOptInForDefaultOffer",
    "hasSeenTasksHint",
    "hasUsedBackgroundTask",
    "hasUsedStash",
    "penguinModeOrgEnabled",
    "opusProMigrationComplete",
    "sonnet1m45MigrationComplete",
}
_PROJECT_COUNTER_FIELDS = {
    "lastAPIDuration",
    "lastAPIDurationWithoutRetries",
    "lastDuration",
    "lastLinesAdded",
    "lastLinesRemoved",
    "lastStartTime",
    "lastToolDuration",
    "lastTotalCacheCreationInputTokens",
    "lastTotalCacheReadInputTokens",
    "lastTotalInputTokens",
    "lastTotalOutputTokens",
    "lastTotalWebSearchRequests",
}
_PROJECT_NUMERIC_FIELDS = {
    "lastCost",
    "lastFpsAverage",
    "lastFpsLow1Pct",
}
_PROJECT_STRING_FIELDS = {
    "lastSessionId",
    "lastVersionBase",
}
_LAST_MODEL_USAGE_FIELDS = {
    "cacheCreationInputTokens",
    "cacheReadInputTokens",
    "costUSD",
    "inputTokens",
    "outputTokens",
    "webSearchRequests",
}

_WINDOWS_TOKEN_QUERY = 0x0008
_WINDOWS_TOKEN_USER = 1
_WINDOWS_ERROR_INSUFFICIENT_BUFFER = 122
_WINDOWS_SE_FILE_OBJECT = 1
_WINDOWS_DACL_SECURITY_INFORMATION = 0x00000004
_WINDOWS_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_WINDOWS_SE_DACL_PROTECTED = 0x1000
_WINDOWS_ACCESS_ALLOWED_ACE_TYPE = 0
_WINDOWS_OBJECT_INHERIT_ACE = 0x01
_WINDOWS_CONTAINER_INHERIT_ACE = 0x02
_WINDOWS_FILE_ALL_ACCESS = 0x001F01FF
_WINDOWS_SDDL_REVISION_1 = 1
_WINDOWS_LABEL_SECURITY_INFORMATION = 0x00000010
_WINDOWS_SYSTEM_MANDATORY_LABEL_ACE_TYPE = 0x11
_WINDOWS_SYSTEM_MANDATORY_LABEL_NO_WRITE_UP = 0x00000001
_WINDOWS_LOW_INTEGRITY_SID = "S-1-16-4096"
_PROVIDER_MUTABLE_STATE_SCHEMA = (
    "plamen.claude_provider_mutable_state_security.v1"
)


class ClaudeAttemptProfileError(RuntimeError):
    """An attempt profile could not be safely created or revoked."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _is_reparse(path: Path) -> bool:
    try:
        return bool(getattr(path.lstat(), "st_file_attributes", 0) & _REPARSE_ATTRIBUTE)
    except OSError:
        return True


def _real_directory(path: str | Path, label: str) -> Path:
    candidate = Path(path)
    if candidate.is_symlink() or _is_reparse(candidate):
        raise ClaudeAttemptProfileError(f"{label} cannot be a symlink/reparse point")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ClaudeAttemptProfileError(f"{label} is unavailable") from exc
    if not resolved.is_dir():
        raise ClaudeAttemptProfileError(f"{label} must be a directory")
    return resolved


def _real_file(path: str | Path, label: str) -> Path:
    candidate = Path(path)
    if candidate.is_symlink() or _is_reparse(candidate):
        raise ClaudeAttemptProfileError(f"{label} cannot be a symlink/reparse point")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ClaudeAttemptProfileError(f"{label} is unavailable") from exc
    if not resolved.is_file():
        raise ClaudeAttemptProfileError(f"{label} must be a regular file")
    return resolved


def _current_windows_user_sid_string() -> str:
    """Read the exact current process token-user SID."""

    if os.name != "nt":
        raise ClaudeAttemptProfileError(
            "Windows token-user SID requested on a non-Windows host"
        )
    from ctypes import wintypes

    class _SidAndAttributes(ctypes.Structure):
        _fields_ = [
            ("Sid", ctypes.c_void_p),
            ("Attributes", wintypes.DWORD),
        ]

    class _TokenUser(ctypes.Structure):
        _fields_ = [("User", _SidAndAttributes)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
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

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        _WINDOWS_TOKEN_QUERY,
        ctypes.byref(token),
    ):
        raise ClaudeAttemptProfileError(
            "cannot open the current Windows process token"
        )
    try:
        needed = wintypes.DWORD()
        if advapi32.GetTokenInformation(
            token,
            _WINDOWS_TOKEN_USER,
            None,
            0,
            ctypes.byref(needed),
        ):
            raise ClaudeAttemptProfileError(
                "Windows token-user sizing unexpectedly succeeded"
            )
        if (
            ctypes.get_last_error() != _WINDOWS_ERROR_INSUFFICIENT_BUFFER
            or needed.value <= 0
        ):
            raise ClaudeAttemptProfileError(
                "cannot size the current Windows token-user record"
            )
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(
            token,
            _WINDOWS_TOKEN_USER,
            buffer,
            needed,
            ctypes.byref(needed),
        ):
            raise ClaudeAttemptProfileError(
                "cannot read the current Windows token-user record"
            )
        token_user = ctypes.cast(
            buffer,
            ctypes.POINTER(_TokenUser),
        ).contents
        sid_text = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(
            token_user.User.Sid,
            ctypes.byref(sid_text),
        ):
            raise ClaudeAttemptProfileError(
                "cannot canonicalize the current Windows token-user SID"
            )
        try:
            result = sid_text.value
            if not result:
                raise ClaudeAttemptProfileError(
                    "current Windows token-user SID is empty"
                )
            return result
        finally:
            kernel32.LocalFree(
                ctypes.c_void_p(
                    ctypes.cast(sid_text, ctypes.c_void_p).value
                )
            )
    finally:
        kernel32.CloseHandle(token)


def _install_windows_private_directory_dacl(path: Path) -> None:
    """Install a protected, current-token-user-only inheritable DACL."""

    from ctypes import wintypes

    sid = _current_windows_user_sid_string()
    # The only ACE grants the current process token user full control. OI+CI
    # makes files and directories created later inherit the same private
    # boundary. D:P disables inheritance from the caller-owned runtime parent.
    sddl = f"D:P(A;OICI;FA;;;{sid})"
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
        wintypes.BOOL
    )
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    descriptor = ctypes.c_void_p()
    descriptor_size = wintypes.DWORD()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        _WINDOWS_SDDL_REVISION_1,
        ctypes.byref(descriptor),
        ctypes.byref(descriptor_size),
    ):
        raise ClaudeAttemptProfileError(
            "cannot construct the private Windows directory DACL"
        )
    try:
        present = wintypes.BOOL()
        defaulted = wintypes.BOOL()
        dacl = ctypes.c_void_p()
        if not advapi32.GetSecurityDescriptorDacl(
            descriptor,
            ctypes.byref(present),
            ctypes.byref(dacl),
            ctypes.byref(defaulted),
        ):
            raise ClaudeAttemptProfileError(
                "cannot extract the private Windows directory DACL"
            )
        if not present.value or not dacl.value:
            raise ClaudeAttemptProfileError(
                "private Windows directory DACL is absent"
            )
        result = int(
            advapi32.SetNamedSecurityInfoW(
                str(path),
                _WINDOWS_SE_FILE_OBJECT,
                (
                    _WINDOWS_DACL_SECURITY_INFORMATION
                    | _WINDOWS_PROTECTED_DACL_SECURITY_INFORMATION
                ),
                None,
                None,
                dacl,
                None,
            )
        )
        if result != 0:
            raise ClaudeAttemptProfileError(
                "private Windows directory DACL installation failed "
                f"with error {result}"
            )
    finally:
        kernel32.LocalFree(descriptor)


def _verify_windows_private_directory_dacl(
    path: Path,
) -> dict[str, Any]:
    """Mechanically replay the exact protected one-principal directory DACL."""

    if os.name != "nt":
        raise ClaudeAttemptProfileError(
            "Windows directory DACL replay requested on a non-Windows host"
        )
    if path.is_symlink() or _is_reparse(path):
        raise ClaudeAttemptProfileError(
            "private Windows directory became a symlink/reparse point"
        )
    try:
        row = path.lstat()
    except OSError as exc:
        raise ClaudeAttemptProfileError(
            "private Windows directory is unavailable"
        ) from exc
    if not stat.S_ISDIR(row.st_mode):
        raise ClaudeAttemptProfileError(
            "private Windows directory is not a directory"
        )

    from ctypes import wintypes

    class _Acl(ctypes.Structure):
        _fields_ = [
            ("AclRevision", ctypes.c_ubyte),
            ("Sbz1", ctypes.c_ubyte),
            ("AclSize", wintypes.WORD),
            ("AceCount", wintypes.WORD),
            ("Sbz2", wintypes.WORD),
        ]

    class _AceHeader(ctypes.Structure):
        _fields_ = [
            ("AceType", ctypes.c_ubyte),
            ("AceFlags", ctypes.c_ubyte),
            ("AceSize", wintypes.WORD),
        ]

    class _AccessAllowedAce(ctypes.Structure):
        _fields_ = [
            ("Header", _AceHeader),
            ("Mask", wintypes.DWORD),
            ("SidStart", wintypes.DWORD),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.ConvertStringSidToSidW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi32.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    advapi32.EqualSid.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = int(
        advapi32.GetNamedSecurityInfoW(
            str(path),
            _WINDOWS_SE_FILE_OBJECT,
            _WINDOWS_DACL_SECURITY_INFORMATION,
            None,
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(descriptor),
        )
    )
    if result != 0 or not descriptor.value or not dacl.value:
        if descriptor.value:
            kernel32.LocalFree(descriptor)
        raise ClaudeAttemptProfileError(
            "private Windows directory DACL replay failed "
            f"with error {result}"
        )
    expected_sid = ctypes.c_void_p()
    try:
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi32.GetSecurityDescriptorControl(
            descriptor,
            ctypes.byref(control),
            ctypes.byref(revision),
        ):
            raise ClaudeAttemptProfileError(
                "cannot read private Windows security-descriptor controls"
            )
        if not control.value & _WINDOWS_SE_DACL_PROTECTED:
            raise ClaudeAttemptProfileError(
                "private Windows directory DACL is not protected"
            )
        acl = ctypes.cast(dacl, ctypes.POINTER(_Acl)).contents
        if int(acl.AceCount) != 1:
            raise ClaudeAttemptProfileError(
                "private Windows directory DACL has unexpected principals"
            )
        ace_pointer = ctypes.c_void_p()
        if not advapi32.GetAce(dacl, 0, ctypes.byref(ace_pointer)):
            raise ClaudeAttemptProfileError(
                "cannot read private Windows directory DACL ACE"
            )
        ace = ctypes.cast(
            ace_pointer,
            ctypes.POINTER(_AccessAllowedAce),
        ).contents
        if int(ace.Header.AceType) != _WINDOWS_ACCESS_ALLOWED_ACE_TYPE:
            raise ClaudeAttemptProfileError(
                "private Windows directory DACL ACE is not allow-only"
            )
        required_flags = (
            _WINDOWS_OBJECT_INHERIT_ACE
            | _WINDOWS_CONTAINER_INHERIT_ACE
        )
        if int(ace.Header.AceFlags) != required_flags:
            raise ClaudeAttemptProfileError(
                "private Windows directory DACL inheritance flags are unsafe"
            )
        if int(ace.Mask) != _WINDOWS_FILE_ALL_ACCESS:
            raise ClaudeAttemptProfileError(
                "private Windows directory DACL access mask is not exact"
            )
        sid_text = _current_windows_user_sid_string()
        if not advapi32.ConvertStringSidToSidW(
            sid_text,
            ctypes.byref(expected_sid),
        ):
            raise ClaudeAttemptProfileError(
                "cannot construct expected Windows token-user SID"
            )
        sid_pointer = ctypes.c_void_p(
            int(ace_pointer.value)
            + int(_AccessAllowedAce.SidStart.offset)
        )
        if not advapi32.EqualSid(sid_pointer, expected_sid):
            raise ClaudeAttemptProfileError(
                "private Windows directory DACL principal is not "
                "the current process token user"
            )
        return {
            "protocol": (
                "WINDOWS_PROTECTED_DACL_CURRENT_TOKEN_USER_ONLY_OI_CI"
            ),
            "dacl_protected": True,
            "ace_count": 1,
            "principal": "CURRENT_PROCESS_TOKEN_USER",
            "principal_sid_sha256": _sha(sid_text.encode("ascii")),
            "access_mask": _WINDOWS_FILE_ALL_ACCESS,
            "inheritance": "OBJECT_AND_CONTAINER_NO_INHERITED_ACE",
        }
    finally:
        if expected_sid.value:
            kernel32.LocalFree(expected_sid)
        kernel32.LocalFree(descriptor)


def _verify_posix_private_directory(path: Path) -> dict[str, Any]:
    if path.is_symlink() or _is_reparse(path):
        raise ClaudeAttemptProfileError(
            "private directory became a symlink/reparse point"
        )
    try:
        row = path.lstat()
    except OSError as exc:
        raise ClaudeAttemptProfileError(
            "private directory is unavailable"
        ) from exc
    if not stat.S_ISDIR(row.st_mode):
        raise ClaudeAttemptProfileError("private path is not a directory")
    mode = stat.S_IMODE(row.st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ClaudeAttemptProfileError(
            "private directory grants group/world access"
        )
    return {
        "protocol": "POSIX_OWNER_MODE_NO_GROUP_OR_WORLD",
        "mode": mode,
        "group_world_access": False,
    }


def _install_and_verify_private_directory_security(
    path: Path,
) -> dict[str, Any]:
    """Install and replay directory security before any secret write."""

    if path.is_symlink() or _is_reparse(path):
        raise ClaudeAttemptProfileError(
            "private directory cannot be a symlink/reparse point"
        )
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    except OSError as exc:
        raise ClaudeAttemptProfileError(
            "private directory mode installation failed"
        ) from exc
    if os.name == "nt":
        _install_windows_private_directory_dacl(path)
        return _verify_windows_private_directory_dacl(path)
    return _verify_posix_private_directory(path)


def _verify_private_directory_security(path: Path) -> dict[str, Any]:
    if os.name == "nt":
        return _verify_windows_private_directory_dacl(path)
    return _verify_posix_private_directory(path)


def _create_private_directory(path: Path) -> dict[str, Any]:
    try:
        path.mkdir(mode=0o700, exist_ok=False)
    except FileExistsError as exc:
        raise ClaudeAttemptProfileError(
            "attempt private directory already exists"
        ) from exc
    except OSError as exc:
        raise ClaudeAttemptProfileError(
            "attempt private directory creation failed"
        ) from exc
    try:
        return _install_and_verify_private_directory_security(path)
    except BaseException:
        try:
            path.rmdir()
        except OSError:
            # The outer materialization rollback handles non-empty parents.
            # An installation failure occurs before this directory receives
            # application bytes, so a residue is debt but not secret exposure.
            pass
        raise


def _prepare_profile_lifecycle_directory(namespace: Path) -> Path:
    path = namespace / _PROFILE_LIFECYCLE_DIRECTORY
    if path.parent != namespace:
        raise ClaudeAttemptProfileError(
            "profile lifecycle directory escaped its namespace"
        )
    try:
        path.mkdir(mode=0o700, exist_ok=False)
    except FileExistsError:
        pass
    except OSError as exc:
        raise ClaudeAttemptProfileError(
            "profile lifecycle directory creation failed"
        ) from exc
    _install_and_verify_private_directory_security(path)
    try:
        resolved_namespace = namespace.resolve(strict=True)
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ClaudeAttemptProfileError(
            "profile lifecycle directory cannot be resolved"
        ) from exc
    if (
        resolved.parent != resolved_namespace
        or resolved.name != _PROFILE_LIFECYCLE_DIRECTORY
    ):
        raise ClaudeAttemptProfileError(
            "profile lifecycle directory identity drifted"
        )
    return resolved


def _write_private(path: Path, raw: bytes) -> None:
    _verify_private_directory_security(path.parent)
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            stat.S_IRUSR | stat.S_IWUSR,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        with path.open("rb") as handle:
            if handle.read() != raw:
                raise ClaudeAttemptProfileError("attempt profile write replay failed")
    except OSError as exc:
        raise ClaudeAttemptProfileError("attempt profile file write failed") from exc


def _open_empty_private_regular_file(path: Path) -> int:
    """Create one private, unaliased target and return its live descriptor."""

    _verify_private_directory_security(path.parent)
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            flags,
            stat.S_IRUSR | stat.S_IWUSR,
        )
        row = os.fstat(descriptor)
        if (
            not stat.S_ISREG(row.st_mode)
            or int(getattr(row, "st_nlink", 1)) != 1
            or int(row.st_size) != 0
        ):
            raise ClaudeAttemptProfileError(
                "attempt credential target is not an empty single-link file"
            )
        try:
            os.fchmod(
                descriptor,
                stat.S_IRUSR | stat.S_IWUSR,
            )
        except AttributeError:
            pass
        row = os.fstat(descriptor)
        if (
            not stat.S_ISREG(row.st_mode)
            or int(getattr(row, "st_nlink", 1)) != 1
            or int(row.st_size) != 0
            or (
                os.name != "nt"
                and stat.S_IMODE(row.st_mode)
                != stat.S_IRUSR | stat.S_IWUSR
            )
        ):
            raise ClaudeAttemptProfileError(
                "attempt credential target is not private"
            )
        return descriptor
    except BaseException:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
        raise


def _credential_integrity_tag(
    descriptor: int,
    key: bytes | bytearray,
) -> bytes:
    """Compute a private keyed live-copy check without retaining raw bytes."""

    digest = hmac.new(key, digestmod="sha256")
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        os.lseek(descriptor, 0, os.SEEK_END)
    except OSError as exc:
        raise ClaudeAttemptProfileError(
            "attempt credential integrity replay failed"
        ) from exc
    return digest.digest()


def _validate_private_credential_descriptor(
    path: Path,
    descriptor: int,
    *,
    validate_supported_schema: bool,
) -> os.stat_result:
    """Replay the exact path/descriptor and private-file security boundary."""

    if path.is_symlink() or _is_reparse(path):
        raise ClaudeAttemptProfileError(
            "attempt credential became a symlink/reparse point"
        )
    try:
        path_row = path.lstat()
        descriptor_row = os.fstat(descriptor)
    except OSError as exc:
        raise ClaudeAttemptProfileError(
            "attempt credential copy is unavailable"
        ) from exc
    _regular_file_identity(path_row)
    _regular_file_identity(descriptor_row)
    if (
        int(path_row.st_dev),
        int(path_row.st_ino),
    ) != (
        int(descriptor_row.st_dev),
        int(descriptor_row.st_ino),
    ):
        raise ClaudeAttemptProfileError(
            "attempt credential path/descriptor identity drifted"
        )
    try:
        if os.name == "nt":
            _verify_windows_private_credential_security(path)
        else:
            _verify_posix_private_credential_security(
                path,
                path_row,
            )
    except _stored_subscription.ClaudeStoredSubscriptionSourceError:
        raise ClaudeAttemptProfileError(
            "attempt credential private-file security drifted"
        ) from None
    if not validate_supported_schema:
        return path_row
    size = int(descriptor_row.st_size)
    if (
        size <= 0
        or size
        > _stored_subscription.MAX_CREDENTIAL_FILE_BYTES
    ):
        raise ClaudeAttemptProfileError(
            "attempt credential schema is unsupported"
        )
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        raw = bytearray()
        while len(raw) <= size:
            chunk = os.read(
                descriptor,
                min(64 * 1024, size + 1 - len(raw)),
            )
            if not chunk:
                break
            raw.extend(chunk)
        os.lseek(descriptor, 0, os.SEEK_END)
    except OSError as exc:
        raise ClaudeAttemptProfileError(
            "attempt credential schema cannot be read"
        ) from exc
    if len(raw) != size:
        for index in range(len(raw)):
            raw[index] = 0
        raise ClaudeAttemptProfileError(
            "attempt credential size drifted during replay"
        )
    immutable = bytes(raw)
    try:
        _validate_stored_subscription_file_shape(immutable)
    except _stored_subscription.ClaudeStoredSubscriptionSourceError:
        raise ClaudeAttemptProfileError(
            "attempt credential schema is unsupported"
        ) from None
    finally:
        for index in range(len(raw)):
            raw[index] = 0
    return path_row


def _read_private_regular_bytes(
    path: Path,
    *,
    label: str,
    maximum_bytes: int,
) -> bytes:
    """Read one private, single-link regular file through its exact descriptor."""

    if path.is_symlink() or _is_reparse(path):
        raise ClaudeAttemptProfileError(
            f"{label} became a symlink/reparse point"
        )
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        path_row = path.lstat()
        descriptor_row = os.fstat(descriptor)
        _regular_file_identity(path_row)
        _regular_file_identity(descriptor_row)
        if (
            int(path_row.st_dev),
            int(path_row.st_ino),
        ) != (
            int(descriptor_row.st_dev),
            int(descriptor_row.st_ino),
        ):
            raise ClaudeAttemptProfileError(
                f"{label} path/descriptor identity drifted"
            )
        try:
            if os.name == "nt":
                _verify_windows_private_credential_security(path)
            else:
                _verify_posix_private_credential_security(
                    path,
                    path_row,
                )
        except _stored_subscription.ClaudeStoredSubscriptionSourceError:
            raise ClaudeAttemptProfileError(
                f"{label} private-file security drifted"
            ) from None
        size = int(descriptor_row.st_size)
        if size <= 0 or size > maximum_bytes:
            raise ClaudeAttemptProfileError(
                f"{label} size is unsupported"
            )
        raw = bytearray()
        os.lseek(descriptor, 0, os.SEEK_SET)
        while len(raw) <= size:
            chunk = os.read(
                descriptor,
                min(64 * 1024, size + 1 - len(raw)),
            )
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) != size:
            raise ClaudeAttemptProfileError(
                f"{label} size drifted during replay"
            )
        return bytes(raw)
    except ClaudeAttemptProfileError:
        raise
    except OSError as exc:
        raise ClaudeAttemptProfileError(
            f"{label} is unavailable"
        ) from exc
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _strict_json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite JSON number")

    def unique_object(
        pairs: list[tuple[str, Any]],
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            parse_constant=reject_constant,
            object_pairs_hook=unique_object,
        )
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise ClaudeAttemptProfileError(
            f"{label} is not strict JSON"
        ) from exc
    if not isinstance(value, dict):
        raise ClaudeAttemptProfileError(
            f"{label} must be a JSON object"
        )
    return value


def _state_key_is_secret_like(key: str) -> bool:
    normalized = key.casefold().replace("_", "").replace("-", "")
    return normalized in _STATE_SECRET_KEYS or normalized.endswith(
        ("apikey", "password", "secret", "token")
    )


def _bounded_state_value(
    value: Any,
    *,
    depth: int = 0,
    reject_authority_keys: bool = True,
) -> None:
    if depth > _MAX_STATE_DEPTH:
        raise ClaudeAttemptProfileError(
            "attempt state exceeds the supported JSON depth"
        )
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > (2**63 - 1):
            raise ClaudeAttemptProfileError(
                "attempt state integer is out of bounds"
            )
        return
    if isinstance(value, float):
        if not math.isfinite(value) or abs(value) > 1e18:
            raise ClaudeAttemptProfileError(
                "attempt state numeric value is out of bounds"
            )
        return
    if isinstance(value, str):
        if len(value) > _MAX_STATE_STRING:
            raise ClaudeAttemptProfileError(
                "attempt state string is out of bounds"
            )
        return
    if isinstance(value, list):
        if len(value) > _MAX_STATE_COLLECTION:
            raise ClaudeAttemptProfileError(
                "attempt state array is out of bounds"
            )
        for item in value:
            _bounded_state_value(
                item,
                depth=depth + 1,
                reject_authority_keys=reject_authority_keys,
            )
        return
    if isinstance(value, dict):
        if len(value) > _MAX_STATE_COLLECTION:
            raise ClaudeAttemptProfileError(
                "attempt state object is out of bounds"
            )
        for key, item in value.items():
            if (
                not isinstance(key, str)
                or len(key) > 256
                or (
                    reject_authority_keys
                    and _state_key_is_secret_like(key)
                )
            ):
                raise ClaudeAttemptProfileError(
                    "attempt state contains an authority-bearing key"
                )
            _bounded_state_value(
                item,
                depth=depth + 1,
                reject_authority_keys=reject_authority_keys,
            )
        return
    raise ClaudeAttemptProfileError(
        "attempt state contains an unsupported JSON value"
    )


def _state_counter(value: Any, *, label: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > (2**63 - 1)
    ):
        raise ClaudeAttemptProfileError(
            f"attempt state {label} is not a bounded counter"
        )


def _state_finite_number(value: Any, *, label: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0
        or float(value) > 1e18
    ):
        raise ClaudeAttemptProfileError(
            f"attempt state {label} is not a bounded numeric value"
        )


def _rfc3339_in_attempt_window(
    value: Any,
    *,
    created_at_utc: str,
) -> None:
    if not isinstance(value, str) or len(value) > 64:
        raise ClaudeAttemptProfileError(
            "attempt state firstStartTime is invalid"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        created = datetime.fromisoformat(
            created_at_utc.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ClaudeAttemptProfileError(
            "attempt state firstStartTime is invalid"
        ) from exc
    if parsed.tzinfo is None or created.tzinfo is None:
        raise ClaudeAttemptProfileError(
            "attempt state firstStartTime is not timezone-qualified"
        )
    now = datetime.now(timezone.utc)
    if (
        parsed.astimezone(timezone.utc)
        < created.astimezone(timezone.utc) - timedelta(minutes=1)
        or parsed.astimezone(timezone.utc) > now + timedelta(minutes=5)
    ):
        raise ClaudeAttemptProfileError(
            "attempt state firstStartTime is outside the attempt window"
        )


def _validate_project_state(
    project: Any,
    *,
    project_key: str,
) -> None:
    if not isinstance(project, dict):
        raise ClaudeAttemptProfileError(
            "attempt state project entry is invalid"
        )
    security = {
        "allowedTools": [],
        "mcpContextUris": [],
        "mcpServers": {},
        "enabledMcpjsonServers": [],
        "disabledMcpjsonServers": [],
        "hasTrustDialogAccepted": True,
        "hasClaudeMdExternalIncludesApproved": True,
        "hasClaudeMdExternalIncludesWarningShown": True,
    }
    for key, expected in security.items():
        if project.get(key) != expected:
            raise ClaudeAttemptProfileError(
                "attempt state project security projection drifted"
            )
    onboarding_state = {
        "hasCompletedProjectOnboarding": True,
        "projectOnboardingSeenCount": 0,
    }
    onboarding_keys = set(onboarding_state)
    present_onboarding_keys = onboarding_keys & set(project)
    if present_onboarding_keys and (
        present_onboarding_keys != onboarding_keys
        or any(project[key] != expected for key, expected in onboarding_state.items())
    ):
        raise ClaudeAttemptProfileError(
            "attempt state project onboarding canonicalization is invalid"
        )
    allowed = (
        set(security)
        | onboarding_keys
        | _PROJECT_COUNTER_FIELDS
        | _PROJECT_NUMERIC_FIELDS
        | _PROJECT_STRING_FIELDS
        | {
            "lastGracefulShutdown",
            "lastModelUsage",
            "lastSessionMetrics",
        }
    )
    if not set(project).issubset(allowed):
        raise ClaudeAttemptProfileError(
            "attempt state project gained an unsupported field"
        )
    for key in _PROJECT_COUNTER_FIELDS & set(project):
        _state_counter(project[key], label=f"{project_key}.{key}")
    for key in _PROJECT_NUMERIC_FIELDS & set(project):
        _state_finite_number(project[key], label=f"{project_key}.{key}")
    for key in _PROJECT_STRING_FIELDS & set(project):
        value = project[key]
        if not isinstance(value, str) or len(value) > 4096:
            raise ClaudeAttemptProfileError(
                "attempt state project string metric is invalid"
            )
    if (
        "lastGracefulShutdown" in project
        and not isinstance(project["lastGracefulShutdown"], bool)
    ):
        raise ClaudeAttemptProfileError(
            "attempt state project graceful-shutdown metric is invalid"
        )
    if "lastModelUsage" in project:
        usage = project["lastModelUsage"]
        if not isinstance(usage, dict) or len(usage) > 64:
            raise ClaudeAttemptProfileError(
                "attempt state project model-usage metric is invalid"
            )
        for model_name, model_usage in usage.items():
            if (
                not isinstance(model_name, str)
                or not _SAFE_STATE_KEY_RE.fullmatch(model_name)
                or not isinstance(model_usage, dict)
                or not set(model_usage).issubset(
                    _LAST_MODEL_USAGE_FIELDS
                )
            ):
                raise ClaudeAttemptProfileError(
                    "attempt state project model-usage metric is invalid"
                )
            for key, value in model_usage.items():
                _state_finite_number(
                    value,
                    label=(
                        f"{project_key}.lastModelUsage."
                        f"{model_name}.{key}"
                    ),
                )
    if "lastSessionMetrics" in project:
        metrics = project["lastSessionMetrics"]
        if not isinstance(metrics, dict) or len(metrics) > 512:
            raise ClaudeAttemptProfileError(
                "attempt state project session metrics are invalid"
            )
        for key, value in metrics.items():
            if (
                not isinstance(key, str)
                or not _SAFE_STATE_KEY_RE.fullmatch(key)
            ):
                raise ClaudeAttemptProfileError(
                    "attempt state project session metric name is invalid"
                )
            _state_finite_number(
                value,
                label=f"{project_key}.lastSessionMetrics.{key}",
            )


def _validate_oauth_account_state(
    value: Any,
    *,
    binding: Mapping[str, Any],
) -> None:
    """Validate Claude 2.1.252's exact, ephemeral account-metadata shape."""

    if (
        binding.get("credential_mode") != "COPIED_STORED_SUBSCRIPTION"
        or binding.get("auth_route") != "STORED_SUBSCRIPTION_OAUTH"
    ):
        raise ClaudeAttemptProfileError(
            "attempt state OAuth account metadata is invalid for the auth route"
        )
    if not isinstance(value, dict) or set(value) != _OAUTH_ACCOUNT_FIELDS:
        raise ClaudeAttemptProfileError(
            "attempt state OAuth account metadata schema is invalid"
        )
    for key, maximum in _OAUTH_ACCOUNT_REQUIRED_STRING_LIMITS.items():
        field = value[key]
        if (
            not isinstance(field, str)
            or len(field) > maximum
            or any(ord(character) < 0x20 for character in field)
        ):
            raise ClaudeAttemptProfileError(
                "attempt state OAuth account metadata string is invalid"
            )
    if not isinstance(value["hasExtraUsageEnabled"], bool):
        raise ClaudeAttemptProfileError(
            "attempt state OAuth account metadata boolean is invalid"
        )
    flags = value["ccOnboardingFlags"]
    if not isinstance(flags, dict) or len(flags) > 128:
        raise ClaudeAttemptProfileError(
            "attempt state OAuth account onboarding flags are invalid"
        )
    for key, flag in flags.items():
        if (
            not isinstance(key, str)
            or not _SAFE_STATE_KEY_RE.fullmatch(key)
            or _state_key_is_secret_like(key)
            or not (
                flag is None
                or isinstance(flag, bool)
                or (
                    isinstance(flag, (int, float))
                    and not isinstance(flag, bool)
                    and math.isfinite(float(flag))
                    and 0 <= float(flag) <= 1e18
                )
                or (
                    isinstance(flag, str)
                    and len(flag) <= 4096
                    and not any(ord(character) < 0x20 for character in flag)
                )
            )
        ):
            raise ClaudeAttemptProfileError(
                "attempt state OAuth account onboarding flags are invalid"
            )
    for key in _OAUTH_ACCOUNT_TIMESTAMP_FIELDS:
        timestamp = value[key]
        if timestamp is None:
            continue
        if (
            not isinstance(timestamp, str)
            or len(timestamp) > 64
            or any(ord(character) < 0x20 for character in timestamp)
        ):
            raise ClaudeAttemptProfileError(
                "attempt state OAuth account timestamp is invalid"
            )
        try:
            parsed_timestamp = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ClaudeAttemptProfileError(
                "attempt state OAuth account timestamp is invalid"
            ) from exc
        if parsed_timestamp.tzinfo is None:
            raise ClaudeAttemptProfileError(
                "attempt state OAuth account timestamp is not timezone-qualified"
            )
    trial_duration = value["claudeCodeTrialDurationDays"]
    if trial_duration is not None:
        _state_finite_number(
            trial_duration,
            label="oauthAccount.claudeCodeTrialDurationDays",
        )
    seat_tier = value["seatTier"]
    if seat_tier is not None and (
        not isinstance(seat_tier, str)
        or len(seat_tier) > 128
        or any(ord(character) < 0x20 for character in seat_tier)
    ):
        raise ClaudeAttemptProfileError(
            "attempt state OAuth account seat tier is invalid"
        )
    _state_finite_number(
        value["profileFetchedAt"],
        label="oauthAccount.profileFetchedAt",
    )


def _validate_postprocess_state_projection(
    state: Mapping[str, Any],
    binding: Mapping[str, Any],
) -> None:
    """Validate only Claude 2.1.252's bounded, non-authoritative deltas."""

    if binding.get("state_provider_version") != _CLAUDE_STATE_VERSION:
        raise ClaudeAttemptProfileError(
            "attempt state provider-version authority drifted"
        )
    if _STATE_FORBIDDEN_ROOT_KEYS & set(state):
        raise ClaudeAttemptProfileError(
            "attempt state gained authority-bearing root state"
        )
    if "oauthAccount" in state:
        _validate_oauth_account_state(state["oauthAccount"], binding=binding)
    exact_root = {
        "installMethod": "native",
        "autoUpdates": False,
        "hasCompletedOnboarding": True,
        "migrationVersion": _CLAUDE_STATE_MIGRATION_VERSION,
        "lastOnboardingVersion": _CLAUDE_STATE_VERSION,
        "lastReleaseNotesSeen": _CLAUDE_STATE_VERSION,
    }
    for key, expected in exact_root.items():
        if state.get(key) != expected:
            raise ClaudeAttemptProfileError(
                "attempt state immutable security projection drifted"
            )
    startup_count = state.get("numStartups")
    if (
        isinstance(startup_count, bool)
        or not isinstance(startup_count, int)
        or startup_count
        not in {
            _CLAUDE_STATE_INITIAL_STARTUPS,
            _CLAUDE_STATE_INITIAL_STARTUPS + 1,
        }
    ):
        raise ClaudeAttemptProfileError(
            "attempt state startup counter is not the bound initial value "
            "or one exact advance"
        )
    if (
        "bypassPermissionsModeAccepted" in state
        and state["bypassPermissionsModeAccepted"] is not True
    ):
        raise ClaudeAttemptProfileError(
            "attempt state bypass acceptance drifted"
        )
    project_keys = binding.get("state_project_keys")
    projects = state.get("projects")
    if (
        not isinstance(project_keys, list)
        or not all(isinstance(item, str) for item in project_keys)
        or binding.get("state_project_key_denominator_sha256")
        != _binding_digest({"state_project_keys": project_keys})
        or not isinstance(projects, dict)
        or list(projects) != project_keys
    ):
        raise ClaudeAttemptProfileError(
            "attempt state project-key denominator drifted"
        )
    for project_key in project_keys:
        _validate_project_state(
            projects[project_key],
            project_key=project_key,
        )
    allowed_root = (
        set(exact_root)
        | {
            "projects",
            "numStartups",
            "bypassPermissionsModeAccepted",
            "userID",
            "machineID",
            "firstStartTime",
            "firstStartVersion",
            "claudeCodeFirstTokenDate",
            "cachedExtraUsageDisabledReason",
            "lastSeenOrgDefaultUpdatedAt",
            "oauthAccount",
        }
        | _STATE_OPAQUE_CACHE_FIELDS
        | _STATE_OPAQUE_USAGE_FIELDS
        | _STATE_COUNTER_FIELDS
        | _STATE_BOOLEAN_FIELDS
    )
    if not set(state).issubset(allowed_root):
        raise ClaudeAttemptProfileError(
            "attempt state gained an unsupported version field"
        )
    for key in ("userID", "machineID"):
        if key in state and (
            not isinstance(state[key], str)
            or not _SHA256_RE.fullmatch(state[key])
        ):
            raise ClaudeAttemptProfileError(
                f"attempt state {key} is invalid"
            )
    if "firstStartTime" in state:
        _rfc3339_in_attempt_window(
            state["firstStartTime"],
            created_at_utc=str(binding["attempt_profile_created_at_utc"]),
        )
    if (
        "firstStartVersion" in state
        and state["firstStartVersion"] != _CLAUDE_STATE_VERSION
    ):
        raise ClaudeAttemptProfileError(
            "attempt state first-start version drifted"
        )
    if "claudeCodeFirstTokenDate" in state:
        value = state["claudeCodeFirstTokenDate"]
        if value is None:
            pass
        elif not isinstance(value, str) or len(value) > 64:
            raise ClaudeAttemptProfileError(
                "attempt state first-token date is invalid"
            )
        else:
            try:
                first_token_date = datetime.fromisoformat(
                    value.replace("Z", "+00:00")
                )
            except ValueError as exc:
                raise ClaudeAttemptProfileError(
                    "attempt state first-token date is invalid"
                ) from exc
            if first_token_date.tzinfo is None:
                raise ClaudeAttemptProfileError(
                    "attempt state first-token date is not timezone-qualified"
                )
    if "cachedExtraUsageDisabledReason" in state:
        value = state["cachedExtraUsageDisabledReason"]
        if (
            value is not None
            and (not isinstance(value, str) or len(value) > 4096)
        ):
            raise ClaudeAttemptProfileError(
                "attempt state extra-usage reason is invalid"
            )
    if "lastSeenOrgDefaultUpdatedAt" in state:
        value = state["lastSeenOrgDefaultUpdatedAt"]
        if not isinstance(value, (int, str)) or isinstance(value, bool):
            raise ClaudeAttemptProfileError(
                "attempt state org-default timestamp is invalid"
            )
        _bounded_state_value(value)
    for key in _STATE_COUNTER_FIELDS & set(state):
        _state_counter(state[key], label=key)
    for key in _STATE_BOOLEAN_FIELDS & set(state):
        if not isinstance(state[key], bool):
            raise ClaudeAttemptProfileError(
                f"attempt state {key} is not boolean"
            )
    for key in (
        _STATE_OPAQUE_CACHE_FIELDS
        | _STATE_OPAQUE_USAGE_FIELDS
    ) & set(state):
        _bounded_state_value(state[key])


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ClaudeAttemptProfileError("attempt profile JSON is invalid") from exc


def _clone_json_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        cloned = json.loads(
            _canonical_json(dict(value)).decode("utf-8")
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ClaudeAttemptProfileError(
            "attempt profile binding is malformed"
        ) from exc
    if not isinstance(cloned, dict):
        raise ClaudeAttemptProfileError(
            "attempt profile binding must be an object"
        )
    return cloned


def _required_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ClaudeAttemptProfileError(f"{label} is invalid")
    return value


def _normalize_startup_permit_binding(
    value: Mapping[str, Any],
    *,
    expected_run_id: str,
) -> dict[str, Any]:
    candidate = _clone_json_mapping(value)
    if set(candidate) != _STARTUP_BINDING_FIELDS:
        raise ClaudeAttemptProfileError(
            "startup permit binding fields are invalid"
        )
    if (
        candidate.get("schema") != _STARTUP_BINDING_SCHEMA
        or candidate.get("run_id") != expected_run_id
        or candidate.get("allocation_disposition")
        not in _STARTUP_ALLOW_DISPOSITIONS
    ):
        raise ClaudeAttemptProfileError(
            "startup permit binding authority is invalid"
        )
    epoch = candidate.get("startup_epoch")
    pointer_sha256 = candidate.get("current_pointer_sha256")
    receipt_sha256 = candidate.get("receipt_sha256")
    if not isinstance(epoch, str) or not _EPOCH_RE.fullmatch(epoch):
        raise ClaudeAttemptProfileError(
            "startup permit binding epoch is invalid"
        )
    _required_sha256(
        pointer_sha256,
        "startup permit current-pointer digest",
    )
    _required_sha256(
        receipt_sha256,
        "startup permit receipt digest",
    )
    expected_suffix = f"startup-{epoch}-{receipt_sha256}.json"
    relative = candidate.get("receipt_relative_path")
    if (
        not isinstance(relative, str)
        or Path(relative).is_absolute()
        or ".." in Path(relative).parts
        or Path(relative).name != expected_suffix
    ):
        raise ClaudeAttemptProfileError(
            "startup permit receipt path is invalid"
        )
    return candidate


def _auxiliary_writable_root_lease_type() -> type[Any]:
    from auxiliary_writable_root_lease import AuxiliaryWritableRootLease

    return AuxiliaryWritableRootLease


def _replay_auxiliary_lease_binding(
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    from auxiliary_writable_root_lease import (
        replay_auxiliary_writable_root_binding,
    )

    return replay_auxiliary_writable_root_binding(binding)


def _live_auxiliary_lease(
    lease: object,
    *,
    require_unbound: bool,
) -> tuple[Any, dict[str, Any], Path]:
    expected_type = _auxiliary_writable_root_lease_type()
    if type(lease) is not expected_type:
        raise ClaudeAttemptProfileError(
            "leased_parent is not the trusted auxiliary-root lease"
        )
    try:
        binding = _clone_json_mapping(lease.binding)
        replay = _replay_auxiliary_lease_binding(binding)
    except Exception as exc:
        raise ClaudeAttemptProfileError(
            "auxiliary lease binding replay failed"
        ) from exc
    if (
        replay.get("valid") is not True
        or replay.get("binding_sha256")
        != binding.get("binding_sha256")
    ):
        raise ClaudeAttemptProfileError(
            "auxiliary lease binding is not live"
        )
    root = _real_directory(lease.root, "auxiliary lease root")
    if root != Path(str(binding.get("root"))).resolve(strict=True):
        raise ClaudeAttemptProfileError(
            "auxiliary lease root mismatched its binding"
        )
    scope_bound = getattr(lease, "process_scope_bound", None)
    if scope_bound not in {False, True}:
        raise ClaudeAttemptProfileError(
            "auxiliary lease process-scope state is malformed"
        )
    if require_unbound and scope_bound is not False:
        raise ClaudeAttemptProfileError(
            "auxiliary lease already entered a process scope"
        )
    return lease, binding, root


def _directory_identity(path: Path) -> dict[str, int]:
    try:
        row = path.lstat()
    except OSError as exc:
        raise ClaudeAttemptProfileError(
            "private root identity is unavailable"
        ) from exc
    if (
        not stat.S_ISDIR(row.st_mode)
        or bool(
            getattr(row, "st_file_attributes", 0)
            & _REPARSE_ATTRIBUTE
        )
    ):
        raise ClaudeAttemptProfileError(
            "private root identity is not a real directory"
        )
    return {
        "st_dev": int(row.st_dev),
        "st_ino": int(row.st_ino),
        "st_mode_type": int(stat.S_IFMT(row.st_mode)),
        "st_file_attributes": int(
            getattr(row, "st_file_attributes", 0)
        ),
    }


def _regular_file_identity(info: os.stat_result) -> dict[str, int]:
    if (
        not stat.S_ISREG(info.st_mode)
        or int(getattr(info, "st_nlink", 1)) != 1
    ):
        raise ClaudeAttemptProfileError(
            "private credential is not a regular single-link file"
        )
    return {
        "st_dev": int(info.st_dev),
        "st_ino": int(info.st_ino),
        "st_mode": int(info.st_mode),
        "st_nlink": int(getattr(info, "st_nlink", 1)),
        "st_file_attributes": int(
            getattr(info, "st_file_attributes", 0)
        ),
    }


def _exact_regular_file_identity(
    path: Path,
    descriptor: int,
    *,
    label: str,
) -> dict[str, int]:
    """Bind one non-aliased path to one retained live descriptor."""

    if path.is_symlink() or _is_reparse(path):
        raise ClaudeAttemptProfileError(
            f"{label} became a symlink/reparse point"
        )
    try:
        path_row = path.lstat()
        descriptor_row = os.fstat(descriptor)
    except OSError as exc:
        raise ClaudeAttemptProfileError(
            f"{label} identity is unavailable"
        ) from exc
    path_identity = _regular_file_identity(path_row)
    descriptor_identity = _regular_file_identity(descriptor_row)
    if path_identity != descriptor_identity:
        raise ClaudeAttemptProfileError(
            f"{label} path/descriptor identity drifted"
        )
    return path_identity


def _verify_windows_low_integrity_state_label(
    path: Path,
) -> dict[str, Any]:
    """Replay the one exact, non-inheriting Low-IL mandatory-label ACE."""

    if os.name != "nt":
        raise ClaudeAttemptProfileError(
            "Windows state-label replay requested on a non-Windows host"
        )
    if path.is_symlink() or _is_reparse(path):
        raise ClaudeAttemptProfileError(
            "provider mutable state became a symlink/reparse point"
        )
    try:
        row = path.lstat()
    except OSError as exc:
        raise ClaudeAttemptProfileError(
            "provider mutable state is unavailable"
        ) from exc
    _regular_file_identity(row)

    from ctypes import wintypes

    class _Acl(ctypes.Structure):
        _fields_ = [
            ("AclRevision", ctypes.c_ubyte),
            ("Sbz1", ctypes.c_ubyte),
            ("AclSize", wintypes.WORD),
            ("AceCount", wintypes.WORD),
            ("Sbz2", wintypes.WORD),
        ]

    class _AceHeader(ctypes.Structure):
        _fields_ = [
            ("AceType", ctypes.c_ubyte),
            ("AceFlags", ctypes.c_ubyte),
            ("AceSize", wintypes.WORD),
        ]

    class _MandatoryLabelAce(ctypes.Structure):
        _fields_ = [
            ("Header", _AceHeader),
            ("Mask", wintypes.DWORD),
            ("SidStart", wintypes.DWORD),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetAce.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.ConvertStringSidToSidW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi32.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    advapi32.EqualSid.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    sacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = int(
        advapi32.GetNamedSecurityInfoW(
            str(path),
            _WINDOWS_SE_FILE_OBJECT,
            _WINDOWS_LABEL_SECURITY_INFORMATION,
            None,
            None,
            None,
            ctypes.byref(sacl),
            ctypes.byref(descriptor),
        )
    )
    if result != 0 or not descriptor.value or not sacl.value:
        if descriptor.value:
            kernel32.LocalFree(descriptor)
        raise ClaudeAttemptProfileError(
            "provider mutable state label replay failed "
            f"with error {result}"
        )
    expected_sid = ctypes.c_void_p()
    try:
        acl = ctypes.cast(sacl, ctypes.POINTER(_Acl)).contents
        if int(acl.AceCount) != 1:
            raise ClaudeAttemptProfileError(
                "provider mutable state label ACE count drifted"
            )
        ace_pointer = ctypes.c_void_p()
        if not advapi32.GetAce(sacl, 0, ctypes.byref(ace_pointer)):
            raise ClaudeAttemptProfileError(
                "provider mutable state label ACE is unavailable"
            )
        ace = ctypes.cast(
            ace_pointer,
            ctypes.POINTER(_MandatoryLabelAce),
        ).contents
        if (
            int(ace.Header.AceType)
            != _WINDOWS_SYSTEM_MANDATORY_LABEL_ACE_TYPE
            or int(ace.Header.AceFlags) != 0
            or int(ace.Mask)
            != _WINDOWS_SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
        ):
            raise ClaudeAttemptProfileError(
                "provider mutable state label policy drifted"
            )
        if not advapi32.ConvertStringSidToSidW(
            _WINDOWS_LOW_INTEGRITY_SID,
            ctypes.byref(expected_sid),
        ):
            raise ClaudeAttemptProfileError(
                "cannot construct the expected Low-IL SID"
            )
        sid_pointer = ctypes.c_void_p(
            int(ace_pointer.value)
            + int(_MandatoryLabelAce.SidStart.offset)
        )
        if not advapi32.EqualSid(sid_pointer, expected_sid):
            raise ClaudeAttemptProfileError(
                "provider mutable state integrity SID drifted"
            )
        return {
            "ace_count": 1,
            "ace_flags": 0,
            "ace_type": "SYSTEM_MANDATORY_LABEL",
            "inheritance": "NONE",
            "integrity_sid": _WINDOWS_LOW_INTEGRITY_SID,
            "policy": "NO_WRITE_UP",
            "policy_mask": (
                _WINDOWS_SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
            ),
        }
    finally:
        if expected_sid.value:
            kernel32.LocalFree(expected_sid)
        kernel32.LocalFree(descriptor)


def _install_windows_low_integrity_state_label(
    path: Path,
) -> dict[str, Any]:
    """Lower only the pre-existing state file, never its parent directory."""

    try:
        from windows_low_integrity_lease import (
            _set_windows_integrity_label,
        )

        _set_windows_integrity_label(
            path,
            sid_alias="LW",
            inheritable=False,
        )
    except Exception as exc:
        raise ClaudeAttemptProfileError(
            "provider mutable state Low-IL label installation failed"
        ) from exc
    return _verify_windows_low_integrity_state_label(path)


class _ClaudeProviderMutableStateAuthority:
    """Retain exact state identity and deny delete/rename during execution."""

    __slots__ = (
        "_binding",
        "_descriptor",
        "_released",
        "_state_path",
    )

    def __init__(
        self,
        *,
        state_path: Path,
        descriptor: int,
        binding: Mapping[str, Any],
    ) -> None:
        self._state_path = state_path
        self._descriptor = descriptor
        self._binding = MappingProxyType(
            json.loads(_canonical_json(binding).decode("utf-8"))
        )
        self._released = False

    @classmethod
    def acquire(
        cls,
        state_path: Path,
        *,
        windows_job_only_restricted: bool = False,
    ) -> "_ClaudeProviderMutableStateAuthority":
        path = _real_file(state_path, "provider mutable state")
        mandatory_label: Mapping[str, Any] | None
        platform: str
        retained_no_delete_handle: bool
        if os.name == "nt":
            if windows_job_only_restricted:
                mandatory_label = None
                platform = "WINDOWS_RESTRICTED_PROVIDER_STATE_EXACT_FILE"
            else:
                mandatory_label = (
                    _install_windows_low_integrity_state_label(path)
                )
                platform = "WINDOWS_LOW_INTEGRITY_EXACT_FILE"
            retained_no_delete_handle = True
        elif windows_job_only_restricted:
            raise ClaudeAttemptProfileError(
                "Windows Job-only provider state authority is unavailable"
            )
        else:
            try:
                path.chmod(stat.S_IRUSR | stat.S_IWUSR)
            except OSError as exc:
                raise ClaudeAttemptProfileError(
                    "provider mutable state mode installation failed"
                ) from exc
            mandatory_label = None
            platform = "POSIX_PRIVATE_OWNER_EXACT_FILE"
            retained_no_delete_handle = False
        descriptor = -1
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            os.set_inheritable(descriptor, False)
            if os.get_inheritable(descriptor):
                raise ClaudeAttemptProfileError(
                    "provider mutable state descriptor is inheritable"
                )
            identity = _exact_regular_file_identity(
                path,
                descriptor,
                label="provider mutable state",
            )
            binding = {
                "schema": _PROVIDER_MUTABLE_STATE_SCHEMA,
                "platform": platform,
                "mutable_relative_paths": [".claude.json"],
                "state_file_identity": identity,
                "mandatory_label": mandatory_label,
                "read_policy": "READ_IS_PROVIDER_INPUT_AUTHORITY",
                "existing_file_truncate_write": True,
                "create_entries": False,
                "delete_entries": False,
                "rename_entries": False,
                "directory_mutation": False,
                "credential_write": False,
                "settings_write": False,
                "lifecycle_ledger_write": False,
                "retained_no_delete_handle": (
                    retained_no_delete_handle
                ),
                "handle_noninheritable": True,
                "completion_authority": False,
            }
            return cls(
                state_path=path,
                descriptor=descriptor,
                binding=binding,
            )
        except BaseException:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise

    @property
    def binding(self) -> dict[str, Any]:
        return _clone_json_mapping(self._binding)

    def replay(self) -> dict[str, Any]:
        if self._released or self._descriptor < 0:
            raise ClaudeAttemptProfileError(
                "provider mutable state authority was released"
            )
        try:
            if os.get_inheritable(self._descriptor):
                raise ClaudeAttemptProfileError(
                    "provider mutable state descriptor became inheritable"
                )
        except OSError as exc:
            raise ClaudeAttemptProfileError(
                "provider mutable state descriptor is unavailable"
            ) from exc
        identity = _exact_regular_file_identity(
            self._state_path,
            self._descriptor,
            label="provider mutable state",
        )
        if identity != self._binding["state_file_identity"]:
            raise ClaudeAttemptProfileError(
                "provider mutable state identity drifted"
            )
        mandatory_label: Mapping[str, Any] | None
        if self._binding["platform"] == "WINDOWS_LOW_INTEGRITY_EXACT_FILE":
            mandatory_label = (
                _verify_windows_low_integrity_state_label(
                    self._state_path
                )
            )
        elif self._binding["platform"] == "WINDOWS_RESTRICTED_PROVIDER_STATE_EXACT_FILE":
            if os.name != "nt":
                raise ClaudeAttemptProfileError(
                    "Windows restricted provider state replay changed platforms"
                )
            mandatory_label = None
        else:
            mandatory_label = None
            try:
                mode = stat.S_IMODE(self._state_path.lstat().st_mode)
            except OSError as exc:
                raise ClaudeAttemptProfileError(
                    "provider mutable state mode is unavailable"
                ) from exc
            if mode != stat.S_IRUSR | stat.S_IWUSR:
                raise ClaudeAttemptProfileError(
                    "provider mutable state private mode drifted"
                )
        if mandatory_label != self._binding["mandatory_label"]:
            raise ClaudeAttemptProfileError(
                "provider mutable state platform security drifted"
            )
        return {
            "valid": True,
            "binding": self.binding,
            "handle_noninheritable": True,
            "completion_authority": False,
        }

    def release_for_cleanup(self) -> dict[str, Any]:
        if self._released:
            return {
                "released": True,
                "idempotent": True,
                "completion_authority": False,
            }
        try:
            os.close(self._descriptor)
        except OSError as exc:
            raise ClaudeAttemptProfileError(
                "provider mutable state descriptor release failed"
            ) from exc
        self._descriptor = -1
        self._released = True
        return {
            "released": True,
            "idempotent": False,
            "completion_authority": False,
        }


def _binding_digest(value: Mapping[str, Any]) -> str:
    return _sha(_canonical_json(value))


def _claude_project_state_key(path: Path) -> str:
    normalized = os.path.normpath(str(path))
    return (
        normalized.replace("\\", "/")
        if os.name == "nt"
        else normalized
    )


def _private_target_authority(
    *,
    run_id: str,
    startup_permit_sha256: str,
    outer_attempt_arm_sha256: str,
    work_plan_sha256: str,
    attempt_id: str,
    process_scope_identity: str,
    auxiliary_lease_binding_sha256: str,
    launch_security_policy_sha256: str,
    executable_observation_sha256: str,
    auth_environment_receipt_sha256: str,
    settings_authority_sha256: str,
    mcp_authority_sha256: str,
    credential_parent_identity: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind the secret target role without recording its pathname or bytes."""

    return {
            "schema": (
                _stored_subscription
                .PRIVATE_CREDENTIAL_TARGET_AUTHORITY_SCHEMA
            ),
            "run_id": run_id,
            "startup_permit_sha256": startup_permit_sha256,
            "outer_attempt_arm_sha256": outer_attempt_arm_sha256,
            # WorkPlan identity is the immutable execution-generation
            # denominator at this provider boundary.
            "execution_generation_sha256": work_plan_sha256,
            "work_plan_sha256": work_plan_sha256,
            "attempt_id": attempt_id,
            "process_scope_identity": process_scope_identity,
            "auxiliary_lease_binding_sha256": (
                auxiliary_lease_binding_sha256
            ),
            "launch_security_policy_sha256": (
                launch_security_policy_sha256
            ),
            "executable_observation_sha256": (
                executable_observation_sha256
            ),
            "auth_environment_receipt_sha256": (
                auth_environment_receipt_sha256
            ),
            "settings_authority_sha256": settings_authority_sha256,
            "mcp_authority_sha256": mcp_authority_sha256,
            "target_role": "CLAUDE_STORED_SUBSCRIPTION_CREDENTIAL",
            "credential_parent_identity": dict(
                credential_parent_identity
            ),
        }


def _private_target_authority_sha256(**kwargs: Any) -> str:
    return _binding_digest(_private_target_authority(**kwargs))


def _terminal_receipt(core: Mapping[str, Any]) -> dict[str, Any]:
    normalized = _clone_json_mapping(core)
    return {
        **normalized,
        "receipt_sha256": _binding_digest(normalized),
    }


def _remove_alias(path: Path, mode: int) -> None:
    operations = (
        (os.rmdir, os.unlink)
        if stat.S_ISDIR(mode)
        else (os.unlink, os.rmdir)
    )
    first_error: OSError | None = None
    for operation in operations:
        try:
            operation(path)
            return
        except FileNotFoundError:
            return
        except OSError as exc:
            if first_error is None:
                first_error = exc
    raise ClaudeAttemptProfileError(
        "attempt runtime alias revocation failed"
    ) from first_error


def _same_directory_identity(
    path: Path,
    expected_identity: Mapping[str, int],
) -> bool:
    try:
        return _directory_identity(path) == dict(expected_identity)
    except ClaudeAttemptProfileError:
        return False


def _remove_owned_directory(
    path: Path,
    *,
    expected_identity: Mapping[str, int],
) -> None:
    """Delete one quarantined directory without following substituted paths."""

    try:
        if not _same_directory_identity(path, expected_identity):
            raise ClaudeAttemptProfileError(
                "attempt runtime directory identity drifted before traversal"
            )
        entries_context = os.scandir(path)
        # os.scandir(path) itself can be a race boundary.  Do not consume the
        # iterator until the path still names the exact directory opened.
        if not _same_directory_identity(path, expected_identity):
            entries_context.close()
            raise ClaudeAttemptProfileError(
                "attempt runtime directory identity drifted during traversal"
            )
        with entries_context as entries:
            for entry in entries:
                if not _same_directory_identity(path, expected_identity):
                    raise ClaudeAttemptProfileError(
                        "attempt runtime directory identity drifted during cleanup"
                    )
                child = Path(entry.path)
                try:
                    row = entry.stat(follow_symlinks=False)
                    aliased = entry.is_symlink() or bool(
                        getattr(row, "st_file_attributes", 0)
                        & _REPARSE_ATTRIBUTE
                    )
                except FileNotFoundError:
                    continue
                if aliased:
                    _remove_alias(child, row.st_mode)
                elif stat.S_ISDIR(row.st_mode):
                    # Windows DirEntry.stat() reports zero st_dev/st_ino.
                    # Bind the child with its exact no-follow path identity,
                    # then require that same identity at recursive entry.
                    child_identity = _directory_identity(child)
                    _remove_owned_directory(
                        child,
                        expected_identity=child_identity,
                    )
                else:
                    if not _same_directory_identity(
                        path,
                        expected_identity,
                    ):
                        raise ClaudeAttemptProfileError(
                            "attempt runtime directory identity drifted before file cleanup"
                        )
                    try:
                        os.unlink(child)
                    except FileNotFoundError:
                        continue
                    except PermissionError:
                        try:
                            os.chmod(child, stat.S_IRUSR | stat.S_IWUSR)
                            os.unlink(child)
                        except OSError as exc:
                            raise ClaudeAttemptProfileError(
                                "attempt runtime file revocation failed"
                            ) from exc
                    except OSError as exc:
                        raise ClaudeAttemptProfileError(
                            "attempt runtime file revocation failed"
                        ) from exc
                if not _same_directory_identity(path, expected_identity):
                    raise ClaudeAttemptProfileError(
                        "attempt runtime directory identity drifted after child cleanup"
                    )
        if not _same_directory_identity(path, expected_identity):
            raise ClaudeAttemptProfileError(
                "attempt runtime directory identity drifted before removal"
            )
        os.rmdir(path)
    except ClaudeAttemptProfileError:
        raise
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ClaudeAttemptProfileError(
            "attempt runtime directory revocation failed"
        ) from exc


def _safe_remove_tree(
    root: Path,
    *,
    expected_identity: Mapping[str, int] | None = None,
) -> None:
    """Quarantine and delete only the exact directory bound by the caller.

    The unpredictable same-parent rename removes the public root name before
    traversal.  Every later traversal boundary revalidates the quarantined
    directory identity.  Any substitution is retained as cleanup debt rather
    than followed.
    """

    if not os.path.lexists(root):
        return
    observed_identity = _directory_identity(root)
    if (
        expected_identity is not None
        and observed_identity != dict(expected_identity)
    ):
        raise ClaudeAttemptProfileError(
            "attempt runtime root identity drifted before quarantine"
        )
    parent_identity = _directory_identity(root.parent)
    # Keep the quarantine component short enough for legacy Windows path
    # ceilings while retaining 96 bits of unpredictable same-parent naming.
    quarantine = root.parent / (
        f".q-{secrets.token_urlsafe(12)}"
    )
    if os.path.lexists(quarantine):
        raise ClaudeAttemptProfileError(
            "attempt runtime quarantine path unexpectedly exists"
        )
    try:
        os.rename(root, quarantine)
    except OSError as exc:
        raise ClaudeAttemptProfileError(
            "attempt runtime root quarantine failed"
        ) from exc
    if not _same_directory_identity(root.parent, parent_identity):
        raise ClaudeAttemptProfileError(
            "attempt runtime parent identity drifted during quarantine"
        )
    if not _same_directory_identity(quarantine, observed_identity):
        raise ClaudeAttemptProfileError(
            "attempt runtime quarantine identity drifted"
        )
    _remove_owned_directory(
        quarantine,
        expected_identity=observed_identity,
    )
    if os.path.lexists(quarantine):
        raise ClaudeAttemptProfileError(
            "attempt runtime quarantine remained after cleanup"
        )
    if os.path.lexists(root):
        raise ClaudeAttemptProfileError(
            "attempt runtime root name was recreated during cleanup"
        )


class ClaudeFreshPostprocessAuthority:
    """Opaque one-shot authority bound to one exact postprocess observation."""

    __slots__ = (
        "_capability",
        "_profile_sha256",
        "_scope_identity",
        "_generation",
        "_nonce",
        "_observation_tag",
        "_current_attempt_completion_eligible",
    )

    def __new__(
        cls,
        *,
        _capability: object,
        profile_sha256: str,
        scope_identity: str,
        generation: int,
        nonce: object,
        observation_tag: bytes,
        current_attempt_completion_eligible: bool,
    ) -> ClaudeFreshPostprocessAuthority:
        if _capability is not _POSTPROCESS_AUTHORITY_CAPABILITY:
            raise TypeError("ClaudeFreshPostprocessAuthority is opaque")
        instance = super().__new__(cls)
        object.__setattr__(instance, "_capability", _capability)
        object.__setattr__(instance, "_profile_sha256", profile_sha256)
        object.__setattr__(instance, "_scope_identity", scope_identity)
        object.__setattr__(instance, "_generation", generation)
        object.__setattr__(instance, "_nonce", nonce)
        object.__setattr__(
            instance,
            "_observation_tag",
            bytes(observation_tag),
        )
        object.__setattr__(
            instance,
            "_current_attempt_completion_eligible",
            current_attempt_completion_eligible,
        )
        return instance

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError(
            "ClaudeFreshPostprocessAuthority is immutable"
        )

    def __reduce__(self) -> object:
        raise TypeError(
            "ClaudeFreshPostprocessAuthority cannot be serialized"
        )

    def __repr__(self) -> str:
        return "<ClaudeFreshPostprocessAuthority opaque>"


class ClaudeProfileScopeClosureToken:
    """Opaque, profile-bound evidence of an exact owned scope closure."""

    __slots__ = (
        "_capability",
        "_profile_sha256",
        "_scope_identity",
        "_evidence_sha256",
        "_cleanup_mode",
        "_postprocess_generation",
        "_postprocess_nonce",
        "_postprocess_observation_tag",
    )

    def __new__(
        cls,
        *,
        _capability: object,
        profile_sha256: str,
        scope_identity: str,
        evidence_sha256: str,
        cleanup_mode: str,
        postprocess_generation: int | None,
        postprocess_nonce: object | None,
        postprocess_observation_tag: bytes | None,
    ) -> ClaudeProfileScopeClosureToken:
        if _capability is not _PROFILE_TOKEN_CAPABILITY:
            raise TypeError("ClaudeProfileScopeClosureToken is opaque")
        instance = super().__new__(cls)
        object.__setattr__(instance, "_capability", _capability)
        object.__setattr__(instance, "_profile_sha256", profile_sha256)
        object.__setattr__(instance, "_scope_identity", scope_identity)
        object.__setattr__(instance, "_evidence_sha256", evidence_sha256)
        object.__setattr__(instance, "_cleanup_mode", cleanup_mode)
        object.__setattr__(
            instance,
            "_postprocess_generation",
            postprocess_generation,
        )
        object.__setattr__(
            instance,
            "_postprocess_nonce",
            postprocess_nonce,
        )
        object.__setattr__(
            instance,
            "_postprocess_observation_tag",
            (
                bytes(postprocess_observation_tag)
                if postprocess_observation_tag is not None
                else None
            ),
        )
        return instance

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("ClaudeProfileScopeClosureToken is immutable")

    def __reduce__(self) -> object:
        raise TypeError(
            "ClaudeProfileScopeClosureToken cannot be serialized"
        )

    def __repr__(self) -> str:
        return "<ClaudeProfileScopeClosureToken opaque>"


class ClaudeNormalScopeFailureClosureToken:
    """Opaque one-shot authority for ordinary failed-provider cleanup."""

    __slots__ = (
        "_capability",
        "_profile_sha256",
        "_scope_identity",
        "_evidence_sha256",
        "_primary_failure_evidence_sha256",
        "_generation",
        "_nonce",
    )

    def __new__(
        cls,
        *,
        _capability: object,
        profile_sha256: str,
        scope_identity: str,
        evidence_sha256: str,
        primary_failure_evidence_sha256: str,
        generation: int,
        nonce: object,
    ) -> ClaudeNormalScopeFailureClosureToken:
        if _capability is not _NORMAL_FAILURE_TOKEN_CAPABILITY:
            raise TypeError(
                "ClaudeNormalScopeFailureClosureToken is opaque"
            )
        instance = super().__new__(cls)
        object.__setattr__(instance, "_capability", _capability)
        object.__setattr__(
            instance,
            "_profile_sha256",
            profile_sha256,
        )
        object.__setattr__(
            instance,
            "_scope_identity",
            scope_identity,
        )
        object.__setattr__(
            instance,
            "_evidence_sha256",
            evidence_sha256,
        )
        object.__setattr__(
            instance,
            "_primary_failure_evidence_sha256",
            primary_failure_evidence_sha256,
        )
        object.__setattr__(instance, "_generation", generation)
        object.__setattr__(instance, "_nonce", nonce)
        return instance

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError(
            "ClaudeNormalScopeFailureClosureToken is immutable"
        )

    def __reduce__(self) -> object:
        raise TypeError(
            "ClaudeNormalScopeFailureClosureToken cannot be serialized"
        )

    def __repr__(self) -> str:
        return "<ClaudeNormalScopeFailureClosureToken opaque>"


class ClaudeBoundPrelaunchScopeClosureToken:
    """Opaque proof that a bound scope closed before any process attach."""

    __slots__ = (
        "_capability",
        "_profile_sha256",
        "_scope_identity",
        "_evidence_sha256",
        "_process_creation_state",
    )

    def __new__(
        cls,
        *,
        _capability: object,
        profile_sha256: str,
        scope_identity: str,
        evidence_sha256: str,
        process_creation_state: str,
    ) -> ClaudeBoundPrelaunchScopeClosureToken:
        if _capability is not _BOUND_PRELAUNCH_TOKEN_CAPABILITY:
            raise TypeError(
                "ClaudeBoundPrelaunchScopeClosureToken is opaque"
            )
        instance = super().__new__(cls)
        object.__setattr__(instance, "_capability", _capability)
        object.__setattr__(
            instance,
            "_profile_sha256",
            profile_sha256,
        )
        object.__setattr__(
            instance,
            "_scope_identity",
            scope_identity,
        )
        object.__setattr__(
            instance,
            "_evidence_sha256",
            evidence_sha256,
        )
        object.__setattr__(
            instance,
            "_process_creation_state",
            process_creation_state,
        )
        return instance

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError(
            "ClaudeBoundPrelaunchScopeClosureToken is immutable"
        )

    def __reduce__(self) -> object:
        raise TypeError(
            "ClaudeBoundPrelaunchScopeClosureToken cannot be serialized"
        )

    def __repr__(self) -> str:
        return "<ClaudeBoundPrelaunchScopeClosureToken opaque>"


class ClaudeProcessAttachFailureScopeClosureToken:
    """Opaque proof that an exact created process died after attach failed."""

    __slots__ = (
        "_capability",
        "_profile_sha256",
        "_scope_identity",
        "_evidence_sha256",
    )

    def __new__(
        cls,
        *,
        _capability: object,
        profile_sha256: str,
        scope_identity: str,
        evidence_sha256: str,
    ) -> ClaudeProcessAttachFailureScopeClosureToken:
        if _capability is not _ATTACH_FAILURE_TOKEN_CAPABILITY:
            raise TypeError(
                "ClaudeProcessAttachFailureScopeClosureToken is opaque"
            )
        instance = super().__new__(cls)
        object.__setattr__(instance, "_capability", _capability)
        object.__setattr__(
            instance,
            "_profile_sha256",
            profile_sha256,
        )
        object.__setattr__(
            instance,
            "_scope_identity",
            scope_identity,
        )
        object.__setattr__(
            instance,
            "_evidence_sha256",
            evidence_sha256,
        )
        return instance

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError(
            "ClaudeProcessAttachFailureScopeClosureToken is immutable"
        )

    def __reduce__(self) -> object:
        raise TypeError(
            "ClaudeProcessAttachFailureScopeClosureToken cannot be serialized"
        )

    def __repr__(self) -> str:
        return "<ClaudeProcessAttachFailureScopeClosureToken opaque>"


def _owned_process_scope_type() -> type[Any]:
    from owned_process_scope import OwnedProcessScope

    return OwnedProcessScope


@dataclass
class ClaudeAttemptProfile:
    root: Path
    config_dir: Path
    home_dir: Path
    state_path: Path
    temp_dir: Path
    environment: Mapping[str, str]
    _binding: Mapping[str, Any] = field(repr=False)
    _leased_parent: Any = field(repr=False)
    _directory_guard: _owned_directory.OwnedDirectoryGuard = field(
        repr=False
    )
    _provider_mutable_state_authority: (
        _ClaudeProviderMutableStateAuthority
    ) = field(repr=False)
    _private_credential_file_identity: Mapping[str, int] = field(
        repr=False
    )
    _private_credential_integrity_key: bytearray = field(repr=False)
    _private_credential_integrity_tag: bytearray = field(repr=False)
    _private_home_overlay_authority: (
        _child_environment.ClaudePrivateHomeOverlayAuthority | None
    ) = field(default=None, repr=False)
    _private_postprocess_authority_key: bytearray = field(
        default_factory=lambda: bytearray(secrets.token_bytes(32)),
        repr=False,
    )
    _postprocess_authority_generation: int = field(
        default=0,
        repr=False,
    )
    _pending_postprocess_nonce: object | None = field(
        default=None,
        repr=False,
    )
    _pending_postprocess_observation_tag: bytes | None = field(
        default=None,
        repr=False,
    )
    _pending_postprocess_completion_eligible: bool | None = field(
        default=None,
        repr=False,
    )
    _normal_failure_authority_generation: int = field(
        default=0,
        repr=False,
    )
    _pending_normal_failure_nonce: object | None = field(
        default=None,
        repr=False,
    )
    _pending_normal_failure_evidence_sha256: str | None = field(
        default=None,
        repr=False,
    )
    _lifecycle_lock: Any = field(
        default_factory=threading.RLock,
        repr=False,
    )
    _revocation_receipt: Mapping[str, Any] | None = field(
        default=None,
        repr=False,
    )
    _revoked: bool = field(default=False, repr=False)

    @property
    def binding(self) -> dict[str, Any]:
        return _clone_json_mapping(self._binding)

    def consume_private_home_overlay_authority(
        self,
    ) -> _child_environment.ClaudePrivateHomeOverlayAuthority | None:
        """Transfer the attempt-bound home authority to one child compiler."""

        with self._lifecycle_lock:
            authority = self._private_home_overlay_authority
            self._private_home_overlay_authority = None
            return authority

    def _store_terminal_receipt(
        self,
        core: Mapping[str, Any],
    ) -> dict[str, Any]:
        receipt = _terminal_receipt(core)
        self._revocation_receipt = MappingProxyType(receipt)
        self._revoked = True
        return _clone_json_mapping(receipt)

    def _destroy_private_integrity_material(self) -> None:
        for private in (
            self._private_credential_integrity_key,
            self._private_credential_integrity_tag,
            self._private_postprocess_authority_key,
        ):
            for index in range(len(private)):
                private[index] = 0
        self._private_credential_integrity_key = bytearray()
        self._private_credential_integrity_tag = bytearray()
        self._private_postprocess_authority_key = bytearray()
        self._pending_postprocess_nonce = None
        self._pending_postprocess_observation_tag = None
        self._pending_postprocess_completion_eligible = None
        self._pending_normal_failure_nonce = None
        self._pending_normal_failure_evidence_sha256 = None

    def _revoke_owned_profile_root(
        self,
        *,
        zero_population_evidence_sha256: str,
        cleanup_mode: str,
    ) -> dict[str, Any]:
        state_release = (
            self._provider_mutable_state_authority
            .release_for_cleanup()
        )
        if (
            state_release.get("released") is not True
            or state_release.get("completion_authority") is not False
        ):
            raise ClaudeAttemptProfileError(
                "provider mutable state authority did not release"
            )
        try:
            receipt = self._directory_guard.revoke_after_zero(
                zero_population_evidence_sha256=(
                    zero_population_evidence_sha256
                ),
                cleanup_mode=cleanup_mode,
            )
        except _owned_directory.OwnedDirectoryGuardError as exc:
            raise ClaudeAttemptProfileError(
                "attempt profile retained-handle cleanup failed"
            ) from exc
        if (
            receipt.get("schema")
            != _owned_directory.GUARD_REVOCATION_SCHEMA
            or receipt.get("subject_binding_sha256")
            != self._binding[
                "directory_guard_subject_binding_sha256"
            ]
            or receipt.get("zero_population_evidence_sha256")
            != zero_population_evidence_sha256
            or receipt.get("cleanup_mode") != cleanup_mode
            or receipt.get("terminal_stage") != "VERIFIED_ABSENT"
            or receipt.get("bound_root_link_absent") is not True
            or receipt.get("completion_authority") is not False
            or os.path.lexists(self.root)
        ):
            raise ClaudeAttemptProfileError(
                "attempt profile retained-handle cleanup did not replay"
            )
        return receipt

    def revoke(
        self,
        closure: ClaudeProfileScopeClosureToken,
    ) -> dict[str, Any]:
        with self._lifecycle_lock:
            return self._revoke_locked(closure)

    def _revoke_locked(
        self,
        closure: ClaudeProfileScopeClosureToken,
    ) -> dict[str, Any]:
        if (
            type(closure) is not ClaudeProfileScopeClosureToken
            or closure._capability is not _PROFILE_TOKEN_CAPABILITY
            or closure._profile_sha256 != self._binding["profile_sha256"]
            or closure._scope_identity
            != self._binding["process_scope_identity"]
        ):
            raise ClaudeAttemptProfileError(
                "attempt profile closure token is invalid"
            )
        if self._revoked:
            if self._revocation_receipt is None:
                raise ClaudeAttemptProfileError(
                    "attempt profile terminal receipt is unavailable"
                )
            existing = _clone_json_mapping(self._revocation_receipt)
            if (
                existing.get("scope_closure_evidence_sha256")
                != closure._evidence_sha256
                or existing.get("cleanup_mode") != closure._cleanup_mode
            ):
                raise ClaudeAttemptProfileError(
                    "attempt profile was closed by different authority"
                )
            return existing
        if closure._cleanup_mode in {
            "NORMAL_COMPLETION",
            "NORMAL_SCOPE_CLEANUP_NO_REFRESH_CONTINUITY",
        }:
            authority_current = (
                isinstance(closure._postprocess_generation, int)
                and not isinstance(
                    closure._postprocess_generation,
                    bool,
                )
                and closure._postprocess_generation
                == self._postprocess_authority_generation
                and closure._postprocess_nonce is not None
                and closure._postprocess_nonce
                is self._pending_postprocess_nonce
                and isinstance(
                    closure._postprocess_observation_tag,
                    bytes,
                )
                and self._pending_postprocess_observation_tag
                is not None
                and hmac.compare_digest(
                    closure._postprocess_observation_tag,
                    self._pending_postprocess_observation_tag,
                )
                and self._pending_postprocess_completion_eligible
                is (
                    closure._cleanup_mode == "NORMAL_COMPLETION"
                )
            )
            if not authority_current:
                raise ClaudeAttemptProfileError(
                    "normal completion requires fresh one-shot postprocess authority"
                )
            # Consume before cleanup: a failed cleanup must be retried only
            # after a new current-state replay and a new opaque authority.
            self._pending_postprocess_nonce = None
            self._pending_postprocess_observation_tag = None
            self._pending_postprocess_completion_eligible = None
            try:
                replay = replay_claude_attempt_profile_postprocess_binding(
                    self,
                    self.binding,
                )
                current_observation = (
                    _postprocess_authority_observation_tag(self)
                )
            except ClaudeAttemptProfileError:
                raise
            if not hmac.compare_digest(
                current_observation,
                closure._postprocess_observation_tag,
            ):
                raise ClaudeAttemptProfileError(
                    "postprocess state changed after authority mint"
                )
            replay_eligible = replay[
                "current_attempt_credential_copy_status"
            ] in _CURRENT_ATTEMPT_COMPLETION_CREDENTIAL_STATUSES
            if replay_eligible is not (
                closure._cleanup_mode == "NORMAL_COMPLETION"
            ):
                raise ClaudeAttemptProfileError(
                    "postprocess credential status changed after authority mint"
                )
        elif (
            closure._postprocess_generation is not None
            or closure._postprocess_nonce is not None
            or closure._postprocess_observation_tag is not None
        ):
            raise ClaudeAttemptProfileError(
                "cleanup-only closure carried completion authority"
            )
        # Secret revocation is the security boundary. Global-source drift is
        # diagnostic evidence and must never become a precondition for cleanup.
        guard_receipt = self._revoke_owned_profile_root(
            zero_population_evidence_sha256=closure._evidence_sha256,
            cleanup_mode=closure._cleanup_mode,
        )
        self._destroy_private_integrity_material()
        return self._store_terminal_receipt({
            "schema": REVOCATION_SCHEMA,
            "attempt_profile_sha256": str(self._binding["profile_sha256"]),
            "auxiliary_lease_binding_sha256": str(
                self._binding["auxiliary_lease_binding_sha256"]
            ),
            "scope_closure_evidence_sha256": closure._evidence_sha256,
            "process_scope_identity": closure._scope_identity,
            "cleanup_mode": closure._cleanup_mode,
            "completion_authority": (
                closure._cleanup_mode == "NORMAL_COMPLETION"
            ),
            "directory_guard_revocation_receipt_sha256": (
                guard_receipt["receipt_sha256"]
            ),
            "directory_guard_terminal_ledger_head_sha256": (
                guard_receipt["terminal_ledger_head_sha256"]
            ),
            "revoked": True,
            "profile_root_absent_after": True,
            "global_source_stable": None,
            "global_source_drift": [],
        })

    def revoke_bound_prelaunch_scope(
        self,
        closure: ClaudeBoundPrelaunchScopeClosureToken,
    ) -> dict[str, Any]:
        """Delete only the profile after a bound never-attached scope closes."""

        if (
            type(closure)
            is not ClaudeBoundPrelaunchScopeClosureToken
            or closure._capability
            is not _BOUND_PRELAUNCH_TOKEN_CAPABILITY
            or closure._profile_sha256
            != self._binding["profile_sha256"]
            or closure._scope_identity
            != self._binding["process_scope_identity"]
        ):
            raise ClaudeAttemptProfileError(
                "bound-prelaunch profile closure token is invalid"
            )
        if self._revoked:
            if self._revocation_receipt is None:
                raise ClaudeAttemptProfileError(
                    "attempt profile terminal receipt is unavailable"
                )
            existing = _clone_json_mapping(
                self._revocation_receipt
            )
            if (
                existing.get("cleanup_mode")
                != "BOUND_PRELAUNCH_ABORT"
                or existing.get("scope_closure_evidence_sha256")
                != closure._evidence_sha256
                or existing.get("process_creation_state")
                != closure._process_creation_state
            ):
                raise ClaudeAttemptProfileError(
                    "attempt profile was closed by different authority"
                )
            return existing
        if (
            getattr(
                self._leased_parent,
                "process_scope_bound",
                None,
            )
            is not True
        ):
            raise ClaudeAttemptProfileError(
                "bound-prelaunch cleanup requires a bound auxiliary lease"
            )
        guard_receipt = self._revoke_owned_profile_root(
            zero_population_evidence_sha256=closure._evidence_sha256,
            cleanup_mode="BOUND_PRELAUNCH_ABORT",
        )
        self._destroy_private_integrity_material()
        return self._store_terminal_receipt({
            "schema": REVOCATION_SCHEMA,
            "attempt_profile_sha256": str(
                self._binding["profile_sha256"]
            ),
            "auxiliary_lease_binding_sha256": str(
                self._binding["auxiliary_lease_binding_sha256"]
            ),
            "scope_closure_evidence_sha256": (
                closure._evidence_sha256
            ),
            "process_scope_identity": closure._scope_identity,
            "process_scope_created": True,
            "process_attached": False,
            "process_creation_state": closure._process_creation_state,
            "cleanup_mode": "BOUND_PRELAUNCH_ABORT",
            "completion_authority": False,
            "directory_guard_revocation_receipt_sha256": (
                guard_receipt["receipt_sha256"]
            ),
            "directory_guard_terminal_ledger_head_sha256": (
                guard_receipt["terminal_ledger_head_sha256"]
            ),
            "revoked": True,
            "profile_root_absent_after": True,
            "global_source_stable": None,
            "global_source_drift": [],
        })

    def revoke_normal_scope_failure(
        self,
        closure: ClaudeNormalScopeFailureClosureToken,
    ) -> dict[str, Any]:
        """Delete this profile under fresh ordinary-failure authority."""

        with self._lifecycle_lock:
            if (
                type(closure)
                is not ClaudeNormalScopeFailureClosureToken
                or closure._capability
                is not _NORMAL_FAILURE_TOKEN_CAPABILITY
                or closure._profile_sha256
                != self._binding["profile_sha256"]
                or closure._scope_identity
                != self._binding["process_scope_identity"]
            ):
                raise ClaudeAttemptProfileError(
                    "normal-scope failure profile closure token is invalid"
                )
            if self._revoked:
                raise ClaudeAttemptProfileError(
                    "normal-scope failure authority was already consumed"
                )
            authority_current = (
                isinstance(closure._generation, int)
                and not isinstance(closure._generation, bool)
                and closure._generation
                == self._normal_failure_authority_generation
                and closure._nonce is not None
                and closure._nonce
                is self._pending_normal_failure_nonce
                and isinstance(
                    self._pending_normal_failure_evidence_sha256,
                    str,
                )
                and hmac.compare_digest(
                    closure._primary_failure_evidence_sha256,
                    self._pending_normal_failure_evidence_sha256,
                )
            )
            if not authority_current:
                raise ClaudeAttemptProfileError(
                    "normal-scope failure authority is stale or invalid"
                )
            # Consume before mutation. A cleanup fault requires a fresh proof
            # from the still-closed exact scope; a stale token cannot be
            # replayed after a partial cleanup.
            self._pending_normal_failure_nonce = None
            self._pending_normal_failure_evidence_sha256 = None
            if (
                getattr(
                    self._leased_parent,
                    "process_scope_bound",
                    None,
                )
                is not True
            ):
                raise ClaudeAttemptProfileError(
                    "normal-scope failure cleanup requires a bound scope"
                )
            guard_receipt = self._revoke_owned_profile_root(
                zero_population_evidence_sha256=(
                    closure._evidence_sha256
                ),
                cleanup_mode="NORMAL_SCOPE_FAILURE_CLEANUP",
            )
            self._destroy_private_integrity_material()
            return self._store_terminal_receipt({
                "schema": REVOCATION_SCHEMA,
                "attempt_profile_sha256": str(
                    self._binding["profile_sha256"]
                ),
                "auxiliary_lease_binding_sha256": str(
                    self._binding["auxiliary_lease_binding_sha256"]
                ),
                "scope_closure_evidence_sha256": (
                    closure._evidence_sha256
                ),
                "primary_failure_evidence_sha256": (
                    closure._primary_failure_evidence_sha256
                ),
                "process_scope_identity": closure._scope_identity,
                "process_scope_created": True,
                "process_created": True,
                "process_attached": True,
                "process_creation_state": "ATTACHED",
                "closed": True,
                "population_zero_proven": True,
                "cleanup_mode": "NORMAL_SCOPE_FAILURE_CLEANUP",
                "completion_authority": False,
                "completion_capable": False,
                "emergency_zero_population": False,
                "directory_guard_revocation_receipt_sha256": (
                    guard_receipt["receipt_sha256"]
                ),
                "directory_guard_terminal_ledger_head_sha256": (
                    guard_receipt[
                        "terminal_ledger_head_sha256"
                    ]
                ),
                "revoked": True,
                "profile_root_absent_after": True,
                "global_source_stable": None,
                "global_source_drift": [],
            })

    def revoke_process_attach_failure_scope(
        self,
        closure: ClaudeProcessAttachFailureScopeClosureToken,
    ) -> dict[str, Any]:
        """Delete only this profile after exact attach-failure cleanup."""

        if (
            type(closure)
            is not ClaudeProcessAttachFailureScopeClosureToken
            or closure._capability is not _ATTACH_FAILURE_TOKEN_CAPABILITY
            or closure._profile_sha256
            != self._binding["profile_sha256"]
            or closure._scope_identity
            != self._binding["process_scope_identity"]
        ):
            raise ClaudeAttemptProfileError(
                "process-attach-failure profile closure token is invalid"
            )
        if self._revoked:
            if self._revocation_receipt is None:
                raise ClaudeAttemptProfileError(
                    "attempt profile terminal receipt is unavailable"
                )
            existing = _clone_json_mapping(
                self._revocation_receipt
            )
            if (
                existing.get("cleanup_mode")
                != "PROCESS_ATTACH_FAILURE_CLEANUP"
                or existing.get("scope_closure_evidence_sha256")
                != closure._evidence_sha256
            ):
                raise ClaudeAttemptProfileError(
                    "attempt profile was closed by different authority"
                )
            return existing
        if (
            getattr(
                self._leased_parent,
                "process_scope_bound",
                None,
            )
            is not True
        ):
            raise ClaudeAttemptProfileError(
                "attach-failure cleanup requires a bound auxiliary lease"
            )
        guard_receipt = self._revoke_owned_profile_root(
            zero_population_evidence_sha256=closure._evidence_sha256,
            cleanup_mode="PROCESS_ATTACH_FAILURE_CLEANUP",
        )
        self._destroy_private_integrity_material()
        return self._store_terminal_receipt({
            "schema": REVOCATION_SCHEMA,
            "attempt_profile_sha256": str(
                self._binding["profile_sha256"]
            ),
            "auxiliary_lease_binding_sha256": str(
                self._binding["auxiliary_lease_binding_sha256"]
            ),
            "scope_closure_evidence_sha256": (
                closure._evidence_sha256
            ),
            "process_scope_identity": closure._scope_identity,
            "process_scope_created": True,
            "process_created": True,
            "process_attached": False,
            "process_creation_state": "PROCESS_CREATED",
            "created_process_termination_proven": True,
            "cleanup_mode": "PROCESS_ATTACH_FAILURE_CLEANUP",
            "completion_authority": False,
            "directory_guard_revocation_receipt_sha256": (
                guard_receipt["receipt_sha256"]
            ),
            "directory_guard_terminal_ledger_head_sha256": (
                guard_receipt["terminal_ledger_head_sha256"]
            ),
            "revoked": True,
            "profile_root_absent_after": True,
            "global_source_stable": None,
            "global_source_drift": [],
        })

    def abort_before_process_scope(
        self,
        *,
        attempt_arm_sha256: str,
        process_scope_identity: str,
        reason_code: str,
    ) -> dict[str, Any]:
        """Delete the complete leased root before any process scope exists."""

        with self._lifecycle_lock:
            return self._abort_before_process_scope_locked(
                attempt_arm_sha256=attempt_arm_sha256,
                process_scope_identity=process_scope_identity,
                reason_code=reason_code,
            )

    def _abort_before_process_scope_locked(
        self,
        *,
        attempt_arm_sha256: str,
        process_scope_identity: str,
        reason_code: str,
    ) -> dict[str, Any]:
        if self._revoked:
            if self._revocation_receipt is None:
                raise ClaudeAttemptProfileError(
                    "attempt profile terminal receipt is unavailable"
                )
            existing = _clone_json_mapping(self._revocation_receipt)
            if (
                existing.get("cleanup_mode") != "PRELAUNCH_ABORT"
                or existing.get("outer_attempt_arm_sha256")
                != attempt_arm_sha256
                or existing.get("process_scope_identity")
                != process_scope_identity
                or existing.get("reason_code") != reason_code
            ):
                raise ClaudeAttemptProfileError(
                    "attempt profile was closed by different authority"
                )
            return existing
        if (
            attempt_arm_sha256
            != self._binding["outer_attempt_arm_sha256"]
            or process_scope_identity
            != self._binding["process_scope_identity"]
            or not isinstance(reason_code, str)
            or not _ATTEMPT_RE.fullmatch(reason_code)
        ):
            raise ClaudeAttemptProfileError(
                "prelaunch abort authority does not match the profile"
            )
        try:
            claim = self._leased_parent.claim_prelaunch_abort(
                attempt_arm_sha256=attempt_arm_sha256,
                process_scope_identity=process_scope_identity,
                reason_code=reason_code,
            )
            claim_binding = claim.binding
        except Exception as exc:
            raise ClaudeAttemptProfileError(
                "prelaunch abort claim failed"
            ) from exc
        cleanup_evidence_sha256 = _binding_digest({
            "attempt_profile_sha256": str(
                self._binding["profile_sha256"]
            ),
            "prelaunch_abort_claim_sha256": claim_binding[
                "claim_sha256"
            ],
            "outer_attempt_arm_sha256": attempt_arm_sha256,
            "process_scope_identity": process_scope_identity,
            "process_scope_created": False,
            "reason_code": reason_code,
            "cleanup_mode": "PRELAUNCH_ABORT",
        })
        guard_receipt = self._revoke_owned_profile_root(
            zero_population_evidence_sha256=cleanup_evidence_sha256,
            cleanup_mode="PRELAUNCH_ABORT",
        )
        self._destroy_private_integrity_material()
        try:
            auxiliary_receipt = (
                self._leased_parent.abort_before_process_scope(
                    attempt_arm_sha256=attempt_arm_sha256,
                    process_scope_identity=process_scope_identity,
                    reason_code=reason_code,
                    claim=claim,
                )
            )
        except Exception as exc:
            raise ClaudeAttemptProfileError(
                "auxiliary lease prelaunch abort failed"
            ) from exc
        if (
            auxiliary_receipt.get("revoked") is not True
            or auxiliary_receipt.get("revocation_mode")
            != "PRELAUNCH_ABORT"
            or auxiliary_receipt.get(
                "prelaunch_abort_claim_sha256"
            )
            != claim_binding["claim_sha256"]
            or auxiliary_receipt.get("reason_code") != reason_code
            or os.path.lexists(self.root)
            or os.path.lexists(self._leased_parent.root)
        ):
            raise ClaudeAttemptProfileError(
                "prelaunch abort did not revoke the profile lease"
            )
        return self._store_terminal_receipt({
            "schema": REVOCATION_SCHEMA,
            "attempt_profile_sha256": str(self._binding["profile_sha256"]),
            "auxiliary_lease_binding_sha256": str(
                self._binding["auxiliary_lease_binding_sha256"]
            ),
            "auxiliary_lease_revocation_sha256": str(
                auxiliary_receipt["receipt_sha256"]
            ),
            "prelaunch_abort_claim_sha256": claim_binding[
                "claim_sha256"
            ],
            "outer_attempt_arm_sha256": attempt_arm_sha256,
            "process_scope_identity": process_scope_identity,
            "process_scope_created": False,
            "reason_code": reason_code,
            "cleanup_mode": "PRELAUNCH_ABORT",
            "completion_authority": False,
            "scope_closure_evidence_sha256": cleanup_evidence_sha256,
            "directory_guard_revocation_receipt_sha256": (
                guard_receipt["receipt_sha256"]
            ),
            "directory_guard_terminal_ledger_head_sha256": (
                guard_receipt["terminal_ledger_head_sha256"]
            ),
            "revoked": True,
            "profile_root_absent_after": True,
            "auxiliary_root_absent_after": True,
            "global_source_stable": None,
            "global_source_drift": [],
        })


def _replay_stored_attempt_credential(
    profile: ClaudeAttemptProfile,
    candidate: Mapping[str, Any],
    *,
    allow_credential_refresh: bool,
) -> str:
    try:
        materialization = (
            _stored_subscription
            .replay_stored_subscription_materialization_receipt(
                candidate.get("credential_copy")
            )
        )
    except _stored_subscription.ClaudeStoredSubscriptionSourceError:
        raise ClaudeAttemptProfileError(
            "attempt credential materialization receipt is invalid"
        ) from None
    expected_target_authority = _private_target_authority_sha256(
        run_id=str(candidate["run_id"]),
        startup_permit_sha256=str(
            candidate["startup_permit_sha256"]
        ),
        outer_attempt_arm_sha256=str(
            candidate["outer_attempt_arm_sha256"]
        ),
        work_plan_sha256=str(candidate["work_plan_sha256"]),
        attempt_id=str(candidate["attempt_id"]),
        process_scope_identity=str(
            candidate["process_scope_identity"]
        ),
        auxiliary_lease_binding_sha256=str(
            candidate["auxiliary_lease_binding_sha256"]
        ),
        launch_security_policy_sha256=str(
            candidate["launch_security_policy_sha256"]
        ),
        executable_observation_sha256=str(
            candidate["executable_observation_sha256"]
        ),
        auth_environment_receipt_sha256=str(
            candidate["auth_environment_receipt_sha256"]
        ),
        settings_authority_sha256=str(
            candidate["settings_authority_sha256"]
        ),
        mcp_authority_sha256=str(
            candidate["mcp_authority_sha256"]
        ),
        credential_parent_identity=_directory_identity(
            profile.config_dir
        ),
    )
    if (
        materialization != candidate.get("credential_copy")
        or materialization["private_target_authority_sha256"]
        != expected_target_authority
        or candidate.get(
            "credential_target_path_authority_sha256"
        )
        != expected_target_authority
    ):
        raise ClaudeAttemptProfileError(
            "attempt credential target authority drifted"
        )
    credential_path = profile.config_dir / ".credentials.json"
    credential = _real_file(
        credential_path,
        "attempt credential copy",
    )
    descriptor = -1
    try:
        descriptor = os.open(
            credential,
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        row = _validate_private_credential_descriptor(
            credential_path,
            descriptor,
            validate_supported_schema=allow_credential_refresh,
        )
        identity_unchanged = (
            _regular_file_identity(row)
            == dict(profile._private_credential_file_identity)
        )
        if (
            not allow_credential_refresh
            and not identity_unchanged
        ):
            raise ClaudeAttemptProfileError(
                "attempt credential file identity drifted"
            )
        size_unchanged = (
            int(row.st_size) == materialization["source_size"]
        )
        integrity_unchanged = hmac.compare_digest(
            _credential_integrity_tag(
                descriptor,
                profile._private_credential_integrity_key,
            ),
            profile._private_credential_integrity_tag,
        )
        copy_unchanged = (
            identity_unchanged
            and size_unchanged
            and integrity_unchanged
        )
        if not allow_credential_refresh and not copy_unchanged:
            raise ClaudeAttemptProfileError(
                "attempt credential copy drifted"
            )
        # Claude may refresh OAuth material in this attempt-owned copy during
        # a long request, including by atomic replacement. Its resulting
        # bytes are never authentication or writeback authority: postprocess
        # merely proves that the path is still a private regular file with a
        # supported bounded schema so the whole profile can be discarded.
        return (
            "ORIGINAL_PRIVATE_COPY_UNCHANGED"
            if copy_unchanged
            else _PRIVATE_COPY_MUTATION_DISCARD_ONLY
        )
    except OSError as exc:
        raise ClaudeAttemptProfileError(
            "attempt credential copy is unavailable"
        ) from exc
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _replay_claude_attempt_profile_binding(
    profile: ClaudeAttemptProfile,
    binding: Mapping[str, Any],
    *,
    allow_credential_refresh: bool,
) -> dict[str, Any]:
    """Replay immutable authority under one explicit credential policy."""

    if type(profile) is not ClaudeAttemptProfile:
        raise ClaudeAttemptProfileError("attempt profile is invalid")
    if profile._revoked:
        raise ClaudeAttemptProfileError(
            "attempt profile binding cannot replay after revocation"
        )
    candidate = _clone_json_mapping(binding)
    expected = _clone_json_mapping(profile._binding)
    if candidate != expected:
        raise ClaudeAttemptProfileError(
            "attempt profile binding was substituted"
        )
    core = dict(candidate)
    digest = core.pop("profile_sha256", None)
    if digest != _binding_digest(core):
        raise ClaudeAttemptProfileError(
            "attempt profile binding digest is invalid"
        )
    startup = _normalize_startup_permit_binding(
        candidate["startup_permit_binding"],
        expected_run_id=str(candidate["run_id"]),
    )
    if (
        candidate.get("startup_permit_sha256")
        != _binding_digest(startup)
        or candidate.get("startup_epoch") != startup["startup_epoch"]
    ):
        raise ClaudeAttemptProfileError(
            "attempt profile startup binding digest is invalid"
        )
    lease, lease_binding, lease_root = _live_auxiliary_lease(
        profile._leased_parent,
        require_unbound=False,
    )
    if (
        lease_binding.get("binding_sha256")
        != candidate.get("auxiliary_lease_binding_sha256")
        or lease_binding.get("attempt_arm_sha256")
        != candidate.get("outer_attempt_arm_sha256")
        or lease_binding.get("attempt_id") != candidate.get("attempt_id")
        or lease_binding.get("process_scope_identity")
        != candidate.get("process_scope_identity")
    ):
        raise ClaudeAttemptProfileError(
            "attempt profile auxiliary lease binding mismatched"
        )
    private_root = candidate.get("private_root")
    if not isinstance(private_root, dict) or set(private_root) != {
        "lease_root",
        "lease_root_identity",
        "profile_root",
        "profile_root_identity",
    }:
        raise ClaudeAttemptProfileError(
            "attempt profile private-root binding is invalid"
        )
    if (
        lease_root != Path(str(private_root["lease_root"])).resolve(strict=True)
        or profile.root
        != Path(str(private_root["profile_root"])).resolve(strict=True)
        or private_root["lease_root_identity"]
        != lease_binding["root_identity"]
        or private_root["profile_root_identity"]
        != _directory_identity(profile.root)
        or candidate.get("private_root_identity_sha256")
        != _binding_digest(private_root)
    ):
        raise ClaudeAttemptProfileError(
            "attempt profile private-root identity drifted"
        )
    guard_binding = candidate.get("directory_guard")
    if (
        not isinstance(guard_binding, dict)
        or guard_binding != profile._directory_guard.binding
        or candidate.get(
            "directory_guard_subject_binding_sha256"
        )
        != guard_binding.get("subject_binding_sha256")
        or guard_binding.get("schema")
        != _owned_directory.GUARD_BINDING_SCHEMA
        or guard_binding.get("completion_authority") is not False
        or guard_binding.get("retained_parent_authority") is not True
        or guard_binding.get("retained_root_authority") is not True
        or guard_binding.get("handles_noninheritable") is not True
    ):
        raise ClaudeAttemptProfileError(
            "attempt profile directory-guard binding drifted"
        )
    expected_config_dir = profile.root / "claude-config"
    expected_home_dir = profile.root / "home"
    expected_temp_dir = profile.root / "temp"
    expected_appdata_dir = profile.root / "appdata"
    expected_localappdata_dir = profile.root / "localappdata"
    expected_state_path = expected_config_dir / ".claude.json"
    if (
        profile.config_dir != expected_config_dir
        or profile.home_dir != expected_home_dir
        or profile.temp_dir != expected_temp_dir
        or profile.state_path != expected_state_path
    ):
        raise ClaudeAttemptProfileError(
            "attempt profile derived path authority drifted"
        )
    provider_mutable_state_security = candidate.get(
        "provider_mutable_state_security"
    )
    if not isinstance(provider_mutable_state_security, dict):
        raise ClaudeAttemptProfileError(
            "provider mutable state security binding is absent"
        )
    state_security_replay = (
        profile._provider_mutable_state_authority.replay()
    )
    if (
        state_security_replay.get("valid") is not True
        or state_security_replay.get("completion_authority")
        is not False
        or state_security_replay.get("handle_noninheritable")
        is not True
        or state_security_replay.get("binding")
        != provider_mutable_state_security
    ):
        raise ClaudeAttemptProfileError(
            "provider mutable state security binding drifted"
        )
    expected_environment = {
        "CLAUDE_CONFIG_DIR": str(expected_config_dir),
        "TEMP": str(expected_temp_dir),
        "TMP": str(expected_temp_dir),
        "TMPDIR": str(expected_temp_dir),
        "CLAUDE_CODE_TMPDIR": str(expected_temp_dir),
    }
    if candidate.get("home_variable_policy") == "PRIVATE_HOME":
        expected_environment.update(
            {
                "HOME": str(expected_home_dir),
                "USERPROFILE": str(expected_home_dir),
                "APPDATA": str(expected_appdata_dir),
                "LOCALAPPDATA": str(expected_localappdata_dir),
            }
        )
    elif (
        candidate.get("home_variable_policy")
        != "PRESERVE_TOOLCHAIN_HOME"
    ):
        raise ClaudeAttemptProfileError(
            "attempt profile home-variable policy is invalid"
        )
    if (
        dict(profile.environment) != expected_environment
        or candidate.get("environment_keys")
        != sorted(expected_environment)
    ):
        raise ClaudeAttemptProfileError(
            "attempt profile environment authority drifted"
        )
    directory_security = candidate.get("directory_security")
    if (
        not isinstance(directory_security, dict)
        or candidate.get("directory_security_sha256")
        != _binding_digest(directory_security)
    ):
        raise ClaudeAttemptProfileError(
            "attempt profile directory-security binding is invalid"
        )
    recorded_directories = directory_security.get("directories")
    expected_directory_names = {
        ".",
        "claude-config",
        "home",
        "temp",
        "appdata",
        "localappdata",
    }
    if (
        not isinstance(recorded_directories, dict)
        or set(recorded_directories) != expected_directory_names
    ):
        raise ClaudeAttemptProfileError(
            "attempt profile directory-security rows are invalid"
        )
    for label in sorted(expected_directory_names):
        path = profile.root if label == "." else profile.root / label
        evidence = _verify_private_directory_security(path)
        if recorded_directories[label] != evidence:
            raise ClaudeAttemptProfileError(
                "attempt profile directory security drifted"
            )
    if (
        directory_security.get("credential_parent_replay")
        != recorded_directories["claude-config"]
        or directory_security.get("protocol")
        != recorded_directories["."]["protocol"]
        or directory_security.get("verified_before_secret_write") is not True
    ):
        raise ClaudeAttemptProfileError(
            "attempt profile directory-security authority drifted"
        )
    credential_mode = candidate.get("credential_mode")
    auth_route = candidate.get("auth_route")
    expected_auth_route = _CREDENTIAL_MODE_ROUTES.get(credential_mode)
    if expected_auth_route is None or auth_route != expected_auth_route:
        raise ClaudeAttemptProfileError(
            "attempt credential mode/auth route is contradictory"
        )
    credential_path = profile.config_dir / ".credentials.json"
    if (
        "CLAUDE_SECURESTORAGE_CONFIG_DIR" in profile.environment
        or "CLAUDE_SECURESTORAGE_CONFIG_DIR"
        in candidate.get("environment_keys", [])
    ):
        raise ClaudeAttemptProfileError(
            "attempt environment contains secure-storage source authority"
        )
    if credential_mode == "ENVIRONMENT_OAUTH_TOKEN":
        if (
            candidate.get("credential_copy") != "ABSENT"
            or "credential_target_path_authority_sha256" in candidate
            or os.path.lexists(credential_path)
            or profile._private_credential_file_identity
            or profile._private_credential_integrity_key
            or profile._private_credential_integrity_tag
        ):
            raise ClaudeAttemptProfileError(
                "environment OAuth-token credential absence drifted"
            )
        credential_copy_status = (
            "NOT_APPLICABLE_ENVIRONMENT_TOKEN"
        )
    else:
        credential_copy_status = _replay_stored_attempt_credential(
            profile,
            candidate,
            allow_credential_refresh=allow_credential_refresh,
        )
    settings_raw = _read_private_regular_bytes(
        profile.config_dir / "settings.json",
        label="attempt settings",
        maximum_bytes=1024 * 1024,
    )
    if _sha(settings_raw) != candidate.get("settings_sha256"):
        raise ClaudeAttemptProfileError(
            "attempt settings bytes drifted"
        )
    state_raw = _read_private_regular_bytes(
        profile.state_path,
        label="attempt state",
        maximum_bytes=_MAX_STATE_BYTES,
    )
    if allow_credential_refresh:
        state_value = _strict_json_object(
            state_raw,
            label="attempt state",
        )
        # oauthAccount is validated below by an exact version-pinned schema.
        # Keep the generic recursive authority-key rejection over every other
        # provider-controlled field so token/secret-like additions still fail.
        _bounded_state_value(
            {
                key: value
                for key, value in state_value.items()
                if key != "oauthAccount"
            }
        )
        _validate_postprocess_state_projection(
            state_value,
            candidate,
        )
    elif _sha(state_raw) != candidate.get("state_sha256"):
        raise ClaudeAttemptProfileError(
            "attempt state bytes drifted before process launch"
        )
    cwd_rows = [
        str(_real_directory(path, "trusted cwd"))
        for path in candidate.get("trusted_cwds", [])
    ]
    if (
        candidate.get("trusted_cwd_denominator_sha256")
        != _binding_digest({"trusted_cwds": cwd_rows})
    ):
        raise ClaudeAttemptProfileError(
            "attempt trusted-cwd denominator drifted"
        )
    # Keep the exact trusted type alive for the duration of this replay. This
    # local is intentional: a substituted object must not be accepted merely
    # because its public mapping resembles a lease.
    del lease
    return {
        "valid": True,
        "reason": (
            "POSTPROCESS_PROFILE_STRUCTURE_AND_AUTHORITY_REPLAYED"
            if allow_credential_refresh
            else "LIVE_PROFILE_BYTES_AND_AUTHORITY_REPLAYED"
        ),
        "binding": expected,
        "profile_sha256": str(expected["profile_sha256"]),
        "current_attempt_credential_copy_status": (
            credential_copy_status
        ),
    }


def replay_claude_attempt_profile_binding(
    profile: ClaudeAttemptProfile,
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    """Strict prelaunch replay, including exact credential bytes."""

    return _replay_claude_attempt_profile_binding(
        profile,
        binding,
        allow_credential_refresh=False,
    )


def replay_claude_attempt_profile_postprocess_binding(
    profile: ClaudeAttemptProfile,
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    """Post-process structural replay allowing only in-place credential refresh."""

    return _replay_claude_attempt_profile_binding(
        profile,
        binding,
        allow_credential_refresh=True,
    )


def _postprocess_authority_observation_tag(
    profile: ClaudeAttemptProfile,
) -> bytes:
    """Bind an opaque authority to exact, non-public attempt bytes."""

    if len(profile._private_postprocess_authority_key) != 32:
        raise ClaudeAttemptProfileError(
            "postprocess authority key is unavailable"
        )
    observation = hmac.new(
        bytes(profile._private_postprocess_authority_key),
        digestmod=hashlib.sha256,
    )
    for label, path, maximum_bytes in (
        (
            "settings",
            profile.config_dir / "settings.json",
            1024 * 1024,
        ),
        ("state", profile.state_path, _MAX_STATE_BYTES),
    ):
        raw = _read_private_regular_bytes(
            path,
            label=f"postprocess {label}",
            maximum_bytes=maximum_bytes,
        )
        label_raw = label.encode("ascii")
        observation.update(len(label_raw).to_bytes(2, "big"))
        observation.update(label_raw)
        observation.update(len(raw).to_bytes(8, "big"))
        observation.update(raw)
    credential_path = profile.config_dir / ".credentials.json"
    if os.path.lexists(credential_path):
        credential_raw = _read_private_regular_bytes(
            credential_path,
            label="postprocess credential",
            maximum_bytes=4 * 1024 * 1024,
        )
        observation.update(b"\x01credential-present")
        observation.update(
            len(credential_raw).to_bytes(8, "big")
        )
        observation.update(credential_raw)
    else:
        observation.update(b"\x00credential-absent")
    observation.update(
        _canonical_json(
            {
                "root": _directory_identity(profile.root),
                "config": _directory_identity(profile.config_dir),
                "home": _directory_identity(profile.home_dir),
                "temp": _directory_identity(profile.temp_dir),
            }
        )
    )
    return observation.digest()


def mint_claude_fresh_postprocess_authority(
    profile: ClaudeAttemptProfile,
    scope: object,
) -> ClaudeFreshPostprocessAuthority:
    """Replay current state and mint one exact ordinary-close authority."""

    if type(profile) is not ClaudeAttemptProfile:
        raise ClaudeAttemptProfileError("attempt profile is invalid")
    expected_type = _owned_process_scope_type()
    scope_identity = str(profile._binding["process_scope_identity"])
    expected_creation_evidence = {
        "state": "ATTACHED",
        "creation_attempted": True,
        "process_object_returned": True,
        "attached": True,
        "created_process_termination_proven": False,
    }
    if (
        type(scope) is not expected_type
        or getattr(scope, "persistent_identity", None)
        != scope_identity
        or getattr(scope, "closed", None) is not True
        or getattr(scope, "population_zero_proven", None) is not True
        or getattr(scope, "attached", None) is not True
        or getattr(scope, "emergency_closed", None) is not False
        or getattr(scope, "process_creation_state", None) != "ATTACHED"
        or getattr(scope, "process_creation_evidence", None)
        != expected_creation_evidence
        or getattr(
            profile._leased_parent,
            "process_scope_bound",
            None,
        )
        is not True
    ):
        raise ClaudeAttemptProfileError(
            "fresh postprocess authority requires the exact closed normal scope"
        )
    with profile._lifecycle_lock:
        if profile._revoked:
            raise ClaudeAttemptProfileError(
                "attempt profile is already revoked"
            )
        # A failed new mint invalidates any older authority.
        profile._pending_postprocess_nonce = None
        profile._pending_postprocess_observation_tag = None
        profile._pending_postprocess_completion_eligible = None
        replay = replay_claude_attempt_profile_postprocess_binding(
            profile,
            profile.binding,
        )
        if (
            replay.get("valid") is not True
            or replay.get("profile_sha256")
            != profile._binding["profile_sha256"]
        ):
            raise ClaudeAttemptProfileError(
                "fresh postprocess replay did not bind the profile"
            )
        observation_tag = _postprocess_authority_observation_tag(
            profile
        )
        # Current output completion is independent from future credential
        # continuity. A schema-valid private-copy mutation is untrusted and
        # discarded, but it cannot veto output produced before the exact
        # process scope reached population zero. The observation tag below
        # still seals the exact bytes until profile-first revocation.
        current_attempt_completion_eligible = replay[
            "current_attempt_credential_copy_status"
        ] in _CURRENT_ATTEMPT_COMPLETION_CREDENTIAL_STATUSES
        profile._postprocess_authority_generation += 1
        generation = profile._postprocess_authority_generation
        nonce = object()
        profile._pending_postprocess_nonce = nonce
        profile._pending_postprocess_observation_tag = observation_tag
        profile._pending_postprocess_completion_eligible = (
            current_attempt_completion_eligible
        )
        return ClaudeFreshPostprocessAuthority(
            _capability=_POSTPROCESS_AUTHORITY_CAPABILITY,
            profile_sha256=str(
                profile._binding["profile_sha256"]
            ),
            scope_identity=scope_identity,
            generation=generation,
            nonce=nonce,
            observation_tag=observation_tag,
            current_attempt_completion_eligible=(
                current_attempt_completion_eligible
            ),
        )


def replay_claude_attempt_profile_revocation(
    profile: ClaudeAttemptProfile,
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay the one terminal profile receipt and root absence."""

    if type(profile) is not ClaudeAttemptProfile:
        raise ClaudeAttemptProfileError("attempt profile is invalid")
    if not profile._revoked or profile._revocation_receipt is None:
        raise ClaudeAttemptProfileError(
            "attempt profile has no terminal revocation receipt"
        )
    candidate = _clone_json_mapping(receipt)
    expected = _clone_json_mapping(profile._revocation_receipt)
    if candidate != expected:
        raise ClaudeAttemptProfileError(
            "attempt profile revocation receipt was substituted"
        )
    core = dict(candidate)
    digest = core.pop("receipt_sha256", None)
    if digest != _binding_digest(core):
        raise ClaudeAttemptProfileError(
            "attempt profile revocation receipt digest is invalid"
        )
    if (
        candidate.get("attempt_profile_sha256")
        != profile._binding["profile_sha256"]
        or candidate.get("revoked") is not True
        or candidate.get("profile_root_absent_after") is not True
        or os.path.lexists(profile.root)
    ):
        raise ClaudeAttemptProfileError(
            "attempt profile revocation did not replay"
        )
    try:
        guard_replay = (
            _owned_directory.replay_owned_directory_cleanup_ledger(
                profile._directory_guard.ledger_path,
                expected_subject_binding_sha256=str(
                    profile._binding[
                        "directory_guard_subject_binding_sha256"
                    ]
                ),
            )
        )
    except _owned_directory.OwnedDirectoryGuardError as exc:
        raise ClaudeAttemptProfileError(
            "attempt profile directory-guard ledger did not replay"
        ) from exc
    guard_first = guard_replay["records"][0]
    guard_core = {
        "schema": _owned_directory.GUARD_REVOCATION_SCHEMA,
        "guard_binding_sha256": profile._directory_guard.binding[
            "binding_sha256"
        ],
        "subject_binding_sha256": profile._binding[
            "directory_guard_subject_binding_sha256"
        ],
        "zero_population_evidence_sha256": guard_first[
            "zero_population_evidence_sha256"
        ],
        "cleanup_mode": guard_first["cleanup_mode"],
        "terminal_stage": "VERIFIED_ABSENT",
        "terminal_ledger_head_sha256": guard_replay[
            "head_sha256"
        ],
        "bound_root_link_absent": True,
        "completion_authority": False,
        "recovered": False,
    }
    if (
        guard_replay["terminal"] is not True
        or candidate.get("cleanup_mode")
        != guard_first["cleanup_mode"]
        or candidate.get("scope_closure_evidence_sha256")
        != guard_first["zero_population_evidence_sha256"]
        or candidate.get(
            "directory_guard_terminal_ledger_head_sha256"
        )
        != guard_replay["head_sha256"]
        or candidate.get(
            "directory_guard_revocation_receipt_sha256"
        )
        != _binding_digest(guard_core)
    ):
        raise ClaudeAttemptProfileError(
            "attempt profile directory-guard revocation drifted"
        )
    if (
        candidate.get("cleanup_mode") == "PRELAUNCH_ABORT"
        and (
            os.path.lexists(profile._leased_parent.root)
            or not isinstance(
                candidate.get("prelaunch_abort_claim_sha256"),
                str,
            )
            or _SHA256_RE.fullmatch(
                candidate["prelaunch_abort_claim_sha256"]
            )
            is None
            or not isinstance(
                candidate.get("auxiliary_lease_revocation_sha256"),
                str,
            )
            or _SHA256_RE.fullmatch(
                candidate["auxiliary_lease_revocation_sha256"]
            )
            is None
        )
    ):
        raise ClaudeAttemptProfileError(
            "prelaunch-aborted auxiliary-root semantics drifted"
        )
    if candidate.get("cleanup_mode") == "BOUND_PRELAUNCH_ABORT":
        if (
            candidate.get("completion_authority") is not False
            or candidate.get("process_scope_created") is not True
            or candidate.get("process_attached") is not False
            or candidate.get("process_creation_state")
            not in {
                "NOT_ATTEMPTED",
                "CREATION_FAILED_WITHOUT_PROCESS_OBJECT",
            }
            or "auxiliary_lease_revocation_sha256" in candidate
        ):
            raise ClaudeAttemptProfileError(
                "bound-prelaunch profile revocation semantics drifted"
            )
    if candidate.get("cleanup_mode") == (
        "PROCESS_ATTACH_FAILURE_CLEANUP"
    ):
        if (
            candidate.get("completion_authority") is not False
            or candidate.get("process_scope_created") is not True
            or candidate.get("process_created") is not True
            or candidate.get("process_attached") is not False
            or candidate.get("process_creation_state")
            != "PROCESS_CREATED"
            or candidate.get("created_process_termination_proven")
            is not True
            or "auxiliary_lease_revocation_sha256" in candidate
        ):
            raise ClaudeAttemptProfileError(
                "attach-failure profile revocation semantics drifted"
            )
    if candidate.get("cleanup_mode") == (
        "NORMAL_SCOPE_FAILURE_CLEANUP"
    ):
        if (
            candidate.get("completion_authority") is not False
            or candidate.get("completion_capable") is not False
            or candidate.get("emergency_zero_population") is not False
            or candidate.get("process_scope_created") is not True
            or candidate.get("process_created") is not True
            or candidate.get("process_attached") is not True
            or candidate.get("process_creation_state") != "ATTACHED"
            or candidate.get("closed") is not True
            or candidate.get("population_zero_proven") is not True
            or not isinstance(
                candidate.get("primary_failure_evidence_sha256"),
                str,
            )
            or _SHA256_RE.fullmatch(
                candidate["primary_failure_evidence_sha256"]
            )
            is None
            or "auxiliary_lease_revocation_sha256" in candidate
        ):
            raise ClaudeAttemptProfileError(
                "normal-scope failure revocation semantics drifted"
            )
    return {
        "valid": True,
        "reason": "TERMINAL_PROFILE_REVOCATION_REPLAYED",
        "receipt_sha256": str(candidate["receipt_sha256"]),
        "completion_authority": bool(
            candidate["completion_authority"]
        ),
    }


def prove_claude_profile_scope_closed(
    profile: ClaudeAttemptProfile,
    scope: object,
    *,
    postprocess_authority: (
        ClaudeFreshPostprocessAuthority | None
    ) = None,
) -> ClaudeProfileScopeClosureToken:
    """Mint profile-bound closure evidence from the exact trusted scope type."""

    if type(profile) is not ClaudeAttemptProfile:
        raise ClaudeAttemptProfileError("attempt profile is invalid")
    if profile._revoked:
        raise ClaudeAttemptProfileError(
            "attempt profile is already revoked"
        )
    expected_type = _owned_process_scope_type()
    if type(scope) is not expected_type:
        raise ClaudeAttemptProfileError(
            "process scope type is not the trusted OwnedProcessScope"
        )
    scope_identity = str(profile._binding["process_scope_identity"])
    if getattr(scope, "persistent_identity", None) != scope_identity:
        raise ClaudeAttemptProfileError(
            "process scope identity does not match the attempt profile"
        )
    if getattr(profile._leased_parent, "process_scope_bound", None) is not True:
        raise ClaudeAttemptProfileError(
            "auxiliary lease was not bound to the process scope"
        )
    if getattr(scope, "closed", None) is not True:
        raise ClaudeAttemptProfileError(
            "process scope closure is not proven"
        )
    if getattr(scope, "population_zero_proven", None) is not True:
        raise ClaudeAttemptProfileError(
            "process scope population-zero proof is absent"
        )
    if getattr(scope, "attached", None) is not True:
        raise ClaudeAttemptProfileError(
            "normal profile closure requires an attached process; use "
            "the bound-prelaunch closure authority"
        )
    if getattr(scope, "process_creation_state", None) != "ATTACHED":
        raise ClaudeAttemptProfileError(
            "normal profile closure requires ATTACHED process-creation state"
        )
    expected_creation_evidence = {
        "state": "ATTACHED",
        "creation_attempted": True,
        "process_object_returned": True,
        "attached": True,
        "created_process_termination_proven": False,
    }
    if (
        getattr(scope, "process_creation_evidence", None)
        != expected_creation_evidence
    ):
        raise ClaudeAttemptProfileError(
            "normal profile process-creation evidence is malformed"
        )
    emergency_closed = getattr(scope, "emergency_closed", None)
    if emergency_closed not in {False, True}:
        raise ClaudeAttemptProfileError(
            "process scope emergency-closure state is malformed"
        )
    if not emergency_closed:
        with profile._lifecycle_lock:
            if (
                type(postprocess_authority)
                is not ClaudeFreshPostprocessAuthority
                or postprocess_authority._capability
                is not _POSTPROCESS_AUTHORITY_CAPABILITY
                or postprocess_authority._profile_sha256
                != profile._binding["profile_sha256"]
                or postprocess_authority._scope_identity
                != scope_identity
                or postprocess_authority._generation
                != profile._postprocess_authority_generation
                or postprocess_authority._nonce
                is not profile._pending_postprocess_nonce
                or profile._pending_postprocess_observation_tag
                is None
                or not isinstance(
                    postprocess_authority._current_attempt_completion_eligible,
                    bool,
                )
                or postprocess_authority._current_attempt_completion_eligible
                is not profile._pending_postprocess_completion_eligible
                or not hmac.compare_digest(
                    postprocess_authority._observation_tag,
                    profile._pending_postprocess_observation_tag,
                )
            ):
                raise ClaudeAttemptProfileError(
                    "normal completion requires fresh postprocess authority"
                )
        cleanup_mode = (
            "NORMAL_COMPLETION"
            if postprocess_authority._current_attempt_completion_eligible
            else "NORMAL_SCOPE_CLEANUP_NO_REFRESH_CONTINUITY"
        )
    elif postprocess_authority is not None:
        raise ClaudeAttemptProfileError(
            "emergency cleanup cannot carry completion authority"
        )
    else:
        cleanup_mode = "EMERGENCY_ZERO_POPULATION_CLEANUP"
    evidence = {
        "attempt_profile_sha256": str(profile._binding["profile_sha256"]),
        "attempt_id": str(profile._binding["attempt_id"]),
        "process_scope_identity": scope_identity,
        "process_creation_evidence": expected_creation_evidence,
        "closed": True,
        "population_zero_proven": True,
        "emergency_closed": emergency_closed,
        "cleanup_mode": cleanup_mode,
        "fresh_postprocess_authority": (
            not emergency_closed
        ),
    }
    return ClaudeProfileScopeClosureToken(
        _capability=_PROFILE_TOKEN_CAPABILITY,
        profile_sha256=str(profile._binding["profile_sha256"]),
        scope_identity=scope_identity,
        evidence_sha256=_sha(_canonical_json(evidence)),
        cleanup_mode=cleanup_mode,
        postprocess_generation=(
            postprocess_authority._generation
            if postprocess_authority is not None
            else None
        ),
        postprocess_nonce=(
            postprocess_authority._nonce
            if postprocess_authority is not None
            else None
        ),
        postprocess_observation_tag=(
            postprocess_authority._observation_tag
            if postprocess_authority is not None
            else None
        ),
    )


def prove_claude_normal_scope_failure_closed(
    profile: ClaudeAttemptProfile,
    scope: object,
    *,
    primary_failure_evidence_sha256: str,
) -> ClaudeNormalScopeFailureClosureToken:
    """Mint one cleanup-only authority for an ordinary failed-provider close.

    The trusted runtime owns classification of the provider result. This
    profile boundary requires its exact closed primary-failure evidence digest
    and binds it into a non-completion capability. Success and ambiguous
    result branches have no reason to call this constructor and receive no
    completion authority from it.
    """

    if type(profile) is not ClaudeAttemptProfile:
        raise ClaudeAttemptProfileError("attempt profile is invalid")
    if (
        not isinstance(primary_failure_evidence_sha256, str)
        or _SHA256_RE.fullmatch(primary_failure_evidence_sha256) is None
    ):
        raise ClaudeAttemptProfileError(
            "primary failure evidence digest is invalid"
        )
    expected_type = _owned_process_scope_type()
    scope_identity = str(profile._binding["process_scope_identity"])
    expected_creation_evidence = {
        "state": "ATTACHED",
        "creation_attempted": True,
        "process_object_returned": True,
        "attached": True,
        "created_process_termination_proven": False,
    }
    if (
        type(scope) is not expected_type
        or getattr(scope, "persistent_identity", None)
        != scope_identity
        or getattr(scope, "closed", None) is not True
        or getattr(scope, "population_zero_proven", None) is not True
        or getattr(scope, "emergency_closed", None) is not False
        or getattr(scope, "attached", None) is not True
        or getattr(scope, "process_creation_state", None) != "ATTACHED"
        or getattr(scope, "process_creation_evidence", None)
        != expected_creation_evidence
        or getattr(
            profile._leased_parent,
            "process_scope_bound",
            None,
        )
        is not True
    ):
        raise ClaudeAttemptProfileError(
            "normal-scope failure cleanup requires the exact attached "
            "ordinary zero-population scope"
        )
    evidence = {
        "attempt_profile_sha256": str(
            profile._binding["profile_sha256"]
        ),
        "auxiliary_lease_binding_sha256": str(
            profile._binding["auxiliary_lease_binding_sha256"]
        ),
        "attempt_id": str(profile._binding["attempt_id"]),
        "process_scope_identity": scope_identity,
        "process_creation_evidence": expected_creation_evidence,
        "closed": True,
        "population_zero_proven": True,
        "emergency_closed": False,
        "primary_failure_evidence_sha256": (
            primary_failure_evidence_sha256
        ),
        "cleanup_mode": "NORMAL_SCOPE_FAILURE_CLEANUP",
        "completion_capable": False,
    }
    evidence_sha256 = _sha(_canonical_json(evidence))
    with profile._lifecycle_lock:
        if profile._revoked:
            raise ClaudeAttemptProfileError(
                "attempt profile is already revoked"
            )
        # Minting a newer failure-cleanup capability invalidates any older
        # one, including one bound to a different primary failure.
        profile._pending_normal_failure_nonce = None
        profile._pending_normal_failure_evidence_sha256 = None
        profile._normal_failure_authority_generation += 1
        generation = profile._normal_failure_authority_generation
        nonce = object()
        profile._pending_normal_failure_nonce = nonce
        profile._pending_normal_failure_evidence_sha256 = (
            primary_failure_evidence_sha256
        )
        return ClaudeNormalScopeFailureClosureToken(
            _capability=_NORMAL_FAILURE_TOKEN_CAPABILITY,
            profile_sha256=str(profile._binding["profile_sha256"]),
            scope_identity=scope_identity,
            evidence_sha256=evidence_sha256,
            primary_failure_evidence_sha256=(
                primary_failure_evidence_sha256
            ),
            generation=generation,
            nonce=nonce,
        )


def prove_claude_bound_prelaunch_scope_closed(
    profile: ClaudeAttemptProfile,
    scope: object,
) -> ClaudeBoundPrelaunchScopeClosureToken:
    """Prove a bound exact scope closed without ever attaching a process."""

    if type(profile) is not ClaudeAttemptProfile:
        raise ClaudeAttemptProfileError("attempt profile is invalid")
    if profile._revoked:
        raise ClaudeAttemptProfileError(
            "attempt profile is already revoked"
        )
    expected_type = _owned_process_scope_type()
    if type(scope) is not expected_type:
        raise ClaudeAttemptProfileError(
            "process scope type is not the trusted OwnedProcessScope"
        )
    lease, lease_binding, _lease_root = _live_auxiliary_lease(
        profile._leased_parent,
        require_unbound=False,
    )
    scope_identity = str(profile._binding["process_scope_identity"])
    if (
        lease_binding.get("binding_sha256")
        != profile._binding["auxiliary_lease_binding_sha256"]
        or lease_binding.get("process_scope_identity")
        != scope_identity
        or getattr(scope, "persistent_identity", None)
        != scope_identity
    ):
        raise ClaudeAttemptProfileError(
            "process scope identity/lease does not match the attempt profile"
        )
    if getattr(lease, "process_scope_bound", None) is not True:
        raise ClaudeAttemptProfileError(
            "auxiliary lease was not bound to the process scope"
        )
    if getattr(scope, "attached", None) is not False:
        raise ClaudeAttemptProfileError(
            "bound-prelaunch cleanup is forbidden after process attachment"
        )
    process_creation_state = getattr(
        scope,
        "process_creation_state",
        None,
    )
    if process_creation_state not in {
        "NOT_ATTEMPTED",
        "CREATION_FAILED_WITHOUT_PROCESS_OBJECT",
    }:
        raise ClaudeAttemptProfileError(
            "bound-prelaunch cleanup requires a no-process creation state"
        )
    process_creation_evidence = getattr(
        scope,
        "process_creation_evidence",
        None,
    )
    expected_creation_evidence = {
        "state": process_creation_state,
        "creation_attempted": (
            process_creation_state
            == "CREATION_FAILED_WITHOUT_PROCESS_OBJECT"
        ),
        "process_object_returned": False,
        "attached": False,
        "created_process_termination_proven": False,
    }
    if process_creation_evidence != expected_creation_evidence:
        raise ClaudeAttemptProfileError(
            "bound-prelaunch process-creation evidence is malformed"
        )
    if getattr(scope, "terminated", None) is not False:
        raise ClaudeAttemptProfileError(
            "never-attached process scope termination state is malformed"
        )
    if getattr(scope, "pre_release_process_identity", None) is not None:
        raise ClaudeAttemptProfileError(
            "never-attached process scope has a process identity"
        )
    if getattr(scope, "closed", None) is not True:
        raise ClaudeAttemptProfileError(
            "process scope closure is not proven"
        )
    if getattr(scope, "population_zero_proven", None) is not True:
        raise ClaudeAttemptProfileError(
            "process scope population-zero proof is absent"
        )
    if getattr(scope, "emergency_closed", None) is not False:
        raise ClaudeAttemptProfileError(
            "bound-prelaunch cleanup requires ordinary scope closure"
        )
    replay_claude_attempt_profile_binding(
        profile,
        profile.binding,
    )
    evidence = {
        "attempt_profile_sha256": str(
            profile._binding["profile_sha256"]
        ),
        "auxiliary_lease_binding_sha256": str(
            profile._binding["auxiliary_lease_binding_sha256"]
        ),
        "attempt_id": str(profile._binding["attempt_id"]),
        "process_scope_identity": scope_identity,
        "process_scope_bound": True,
        "process_attached": False,
        "process_creation_state": process_creation_state,
        "process_creation_evidence": expected_creation_evidence,
        "process_terminated": False,
        "pre_release_process_identity_absent": True,
        "closed": True,
        "population_zero_proven": True,
        "emergency_closed": False,
        "cleanup_mode": "BOUND_PRELAUNCH_ABORT",
    }
    del lease
    return ClaudeBoundPrelaunchScopeClosureToken(
        _capability=_BOUND_PRELAUNCH_TOKEN_CAPABILITY,
        profile_sha256=str(profile._binding["profile_sha256"]),
        scope_identity=scope_identity,
        evidence_sha256=_sha(_canonical_json(evidence)),
        process_creation_state=process_creation_state,
    )


def prove_claude_process_attach_failure_scope_closed(
    profile: ClaudeAttemptProfile,
    scope: object,
) -> ClaudeProcessAttachFailureScopeClosureToken:
    """Prove exact-process termination after creation succeeded but attach failed."""

    if type(profile) is not ClaudeAttemptProfile:
        raise ClaudeAttemptProfileError("attempt profile is invalid")
    if profile._revoked:
        raise ClaudeAttemptProfileError(
            "attempt profile is already revoked"
        )
    expected_type = _owned_process_scope_type()
    if type(scope) is not expected_type:
        raise ClaudeAttemptProfileError(
            "process scope type is not the trusted OwnedProcessScope"
        )
    lease, lease_binding, _lease_root = _live_auxiliary_lease(
        profile._leased_parent,
        require_unbound=False,
    )
    scope_identity = str(profile._binding["process_scope_identity"])
    if (
        lease_binding.get("binding_sha256")
        != profile._binding["auxiliary_lease_binding_sha256"]
        or lease_binding.get("process_scope_identity")
        != scope_identity
        or getattr(scope, "persistent_identity", None)
        != scope_identity
    ):
        raise ClaudeAttemptProfileError(
            "process scope identity/lease does not match the attempt profile"
        )
    if getattr(lease, "process_scope_bound", None) is not True:
        raise ClaudeAttemptProfileError(
            "auxiliary lease was not bound to the process scope"
        )
    if getattr(scope, "process_creation_state", None) != "PROCESS_CREATED":
        raise ClaudeAttemptProfileError(
            "attach-failure cleanup requires PROCESS_CREATED state"
        )
    if getattr(scope, "attached", None) is not False:
        raise ClaudeAttemptProfileError(
            "attach-failure cleanup is forbidden after process attachment"
        )
    if (
        getattr(
            scope,
            "created_process_termination_proven",
            None,
        )
        is not True
    ):
        raise ClaudeAttemptProfileError(
            "exact created-process termination proof is absent"
        )
    expected_creation_evidence = {
        "state": "PROCESS_CREATED",
        "creation_attempted": True,
        "process_object_returned": True,
        "attached": False,
        "created_process_termination_proven": True,
    }
    if (
        getattr(scope, "process_creation_evidence", None)
        != expected_creation_evidence
    ):
        raise ClaudeAttemptProfileError(
            "attach-failure process-creation evidence is malformed"
        )
    if getattr(scope, "pre_release_process_identity", None) is not None:
        raise ClaudeAttemptProfileError(
            "never-attached process scope has a released process identity"
        )
    if getattr(scope, "closed", None) is not True:
        raise ClaudeAttemptProfileError(
            "process scope closure is not proven"
        )
    if getattr(scope, "population_zero_proven", None) is not True:
        raise ClaudeAttemptProfileError(
            "process scope population-zero proof is absent"
        )
    if getattr(scope, "emergency_closed", None) is not False:
        raise ClaudeAttemptProfileError(
            "attach-failure cleanup requires ordinary scope closure"
        )
    # Attach failed before the provider could execute. Credential and state
    # therefore remain under the strict prelaunch replay, not postprocess
    # mutation policy.
    replay_claude_attempt_profile_binding(
        profile,
        profile.binding,
    )
    evidence = {
        "attempt_profile_sha256": str(
            profile._binding["profile_sha256"]
        ),
        "auxiliary_lease_binding_sha256": str(
            profile._binding["auxiliary_lease_binding_sha256"]
        ),
        "attempt_id": str(profile._binding["attempt_id"]),
        "process_scope_identity": scope_identity,
        "process_scope_bound": True,
        "process_creation_state": "PROCESS_CREATED",
        "process_creation_evidence": expected_creation_evidence,
        "created_process_termination_proven": True,
        "process_attached": False,
        "pre_release_process_identity_absent": True,
        "closed": True,
        "population_zero_proven": True,
        "emergency_closed": False,
        "cleanup_mode": "PROCESS_ATTACH_FAILURE_CLEANUP",
    }
    del lease
    return ClaudeProcessAttachFailureScopeClosureToken(
        _capability=_ATTACH_FAILURE_TOKEN_CAPABILITY,
        profile_sha256=str(profile._binding["profile_sha256"]),
        scope_identity=scope_identity,
        evidence_sha256=_sha(_canonical_json(evidence)),
    )


def materialize_claude_attempt_profile(
    *,
    leased_parent: object,
    project_root: str | Path,
    trusted_cwds: Sequence[str | Path],
    stored_subscription_capability: (
        _stored_subscription.StoredSubscriptionMaterializationCapability
        | None
    ),
    expected_stored_subscription_source_evidence: (
        Mapping[str, Any] | None
    ),
    credential_mode: str,
    auth_route: str,
    run_id: str,
    startup_permit_binding: Mapping[str, Any],
    outer_attempt_arm_sha256: str,
    work_plan_sha256: str,
    attempt_id: str,
    process_scope_identity: str,
    launch_security_policy_sha256: str,
    executable_observation_sha256: str,
    auth_environment_receipt_sha256: str,
    settings_authority_sha256: str,
    mcp_authority_sha256: str,
    home_variable_policy: str,
    permission_mode: str,
    windows_job_only_restricted: bool = False,
) -> ClaudeAttemptProfile:
    """Materialize a private profile inside one already armed opaque lease."""

    lease, lease_binding, runtime = _live_auxiliary_lease(
        leased_parent,
        require_unbound=True,
    )
    actual_arm_sha256 = str(lease_binding.get("attempt_arm_sha256") or "")
    actual_scope_identity = str(
        lease_binding.get("process_scope_identity") or ""
    )
    capability = (
        stored_subscription_capability
        if type(stored_subscription_capability)
        is _stored_subscription.StoredSubscriptionMaterializationCapability
        else None
    )
    capability_terminal = False
    credential_integrity_key: bytearray | None = None
    credential_integrity_tag: bytearray | None = None
    private_credential_file_identity: Mapping[str, int] = {}
    directory_guard: _owned_directory.OwnedDirectoryGuard | None = None
    provider_mutable_state_authority: (
        _ClaudeProviderMutableStateAuthority | None
    ) = None
    try:
        expected_route = _CREDENTIAL_MODE_ROUTES.get(
            credential_mode
        )
        if expected_route is None or auth_route != expected_route:
            raise ClaudeAttemptProfileError(
                "credential mode/auth route is contradictory"
            )
        stored_credential_lane = (
            credential_mode == "COPIED_STORED_SUBSCRIPTION"
        )
        if stored_credential_lane:
            if capability is None:
                raise ClaudeAttemptProfileError(
                    "stored-subscription materialization capability "
                    "is invalid"
                )
            if not isinstance(
                expected_stored_subscription_source_evidence,
                Mapping,
            ):
                raise ClaudeAttemptProfileError(
                    "stored-subscription expected source evidence "
                    "is invalid"
                )
        elif (
            stored_subscription_capability is not None
            or expected_stored_subscription_source_evidence is not None
        ):
            raise ClaudeAttemptProfileError(
                "environment OAuth-token profile forbids stored "
                "credential authority"
            )
        if (
            not isinstance(run_id, str)
            or not _RUN_ID_RE.fullmatch(run_id)
        ):
            raise ClaudeAttemptProfileError("run_id is invalid")
        startup_binding = _normalize_startup_permit_binding(
            startup_permit_binding,
            expected_run_id=run_id,
        )
        if (
            not isinstance(attempt_id, str)
            or not _ATTEMPT_RE.fullmatch(attempt_id)
        ):
            raise ClaudeAttemptProfileError("attempt_id is invalid")
        if (
            not isinstance(process_scope_identity, str)
            or not _ATTEMPT_RE.fullmatch(process_scope_identity)
        ):
            raise ClaudeAttemptProfileError(
                "process_scope_identity is invalid"
            )
        if (
            lease_binding.get("attempt_id") != attempt_id
            or lease_binding.get("process_scope_identity")
            != process_scope_identity
            or lease_binding.get("attempt_arm_sha256")
            != outer_attempt_arm_sha256
        ):
            raise ClaudeAttemptProfileError(
                "attempt identity/arm mismatched the auxiliary lease binding"
            )
        _required_sha256(
            outer_attempt_arm_sha256,
            "outer AttemptArm digest",
        )
        work_plan_sha256 = _required_sha256(
            work_plan_sha256,
            "WorkPlan digest",
        )
        launch_security_policy_sha256 = _required_sha256(
            launch_security_policy_sha256,
            "Claude launch-security policy digest",
        )
        executable_observation_sha256 = _required_sha256(
            executable_observation_sha256,
            "Claude executable observation digest",
        )
        auth_environment_receipt_sha256 = _required_sha256(
            auth_environment_receipt_sha256,
            "Claude auth-environment receipt digest",
        )
        settings_authority_sha256 = _required_sha256(
            settings_authority_sha256,
            "settings authority digest",
        )
        mcp_authority_sha256 = _required_sha256(
            mcp_authority_sha256,
            "MCP authority digest",
        )
        if home_variable_policy not in _HOME_VARIABLE_POLICIES:
            raise ClaudeAttemptProfileError(
                "home_variable_policy must be explicit"
            )
        if permission_mode not in _PERMISSION_MODES:
            raise ClaudeAttemptProfileError(
                "permission_mode is unsupported"
            )
        if type(windows_job_only_restricted) is not bool:
            raise ClaudeAttemptProfileError(
                "Windows Job-only restricted marker must be boolean"
            )
        if windows_job_only_restricted and (
            os.name != "nt" or permission_mode != "default"
        ):
            raise ClaudeAttemptProfileError(
                "Windows Job-only restricted authority is inconsistent"
            )
        project = _real_directory(project_root, "project root")
        if (
            runtime == project
            or project in runtime.parents
            or runtime in project.parents
        ):
            raise ClaudeAttemptProfileError(
                "attempt lease must be disjoint from the project root"
            )
        cwd_rows = tuple(
            sorted(
                {
                    _real_directory(item, "trusted cwd")
                    for item in trusted_cwds
                },
                key=lambda item: str(item).casefold(),
            )
        )
        if not cwd_rows:
            raise ClaudeAttemptProfileError(
                "at least one trusted cwd is required"
            )
        if any(
            (
                path == runtime
                or runtime in path.parents
                or path in runtime.parents
            )
            for path in cwd_rows
        ):
            raise ClaudeAttemptProfileError(
                "trusted cwd overlaps the auxiliary lease"
            )
        try:
            with os.scandir(runtime) as entries:
                if next(entries, None) is not None:
                    raise ClaudeAttemptProfileError(
                        "auxiliary lease root is not empty"
                    )
        except OSError as exc:
            raise ClaudeAttemptProfileError(
                "auxiliary lease root cannot be inspected"
            ) from exc

        directory_guard_subject_binding_sha256 = _binding_digest({
            "schema": _PROFILE_GUARD_SUBJECT_SCHEMA,
            "run_id": run_id,
            "startup_permit_sha256": _binding_digest(
                startup_binding
            ),
            "outer_attempt_arm_sha256": outer_attempt_arm_sha256,
            "work_plan_sha256": work_plan_sha256,
            "attempt_id": attempt_id,
            "process_scope_identity": process_scope_identity,
            "auxiliary_lease_binding_sha256": str(
                lease_binding["binding_sha256"]
            ),
            "launch_security_policy_sha256": (
                launch_security_policy_sha256
            ),
            "executable_observation_sha256": (
                executable_observation_sha256
            ),
            "auth_environment_receipt_sha256": (
                auth_environment_receipt_sha256
            ),
            "settings_authority_sha256": settings_authority_sha256,
            "mcp_authority_sha256": mcp_authority_sha256,
        })
        lifecycle_directory = _prepare_profile_lifecycle_directory(
            runtime.parent
        )
        root = runtime / "claude-profile"
        root_security = _create_private_directory(root)
        try:
            directory_guard = _owned_directory.bind_owned_directory(
                root,
                subject_binding_sha256=(
                    directory_guard_subject_binding_sha256
                ),
                ledger_directory=lifecycle_directory,
            )
        except _owned_directory.OwnedDirectoryGuardError as exc:
            raise ClaudeAttemptProfileError(
                "attempt profile directory guard acquisition failed"
            ) from exc
        config_dir = root / "claude-config"
        home_dir = root / "home"
        temp_dir = root / "temp"
        appdata_dir = root / "appdata"
        localappdata_dir = root / "localappdata"
        directory_security: dict[str, Mapping[str, Any]] = {
            ".": root_security,
        }
        for path in (
            config_dir,
            home_dir,
            temp_dir,
            appdata_dir,
            localappdata_dir,
        ):
            directory_security[path.name] = _create_private_directory(path)
        # Re-verify immediately before credential materialization. This is a
        # mechanical precondition, not a post-write chmod assertion.
        credential_parent_security = _verify_private_directory_security(
            config_dir
        )
        credential_target = config_dir / ".credentials.json"
        private_target_authority_sha256: str | None = None
        credential_materialization: Mapping[str, Any] | str
        if stored_credential_lane:
            private_target_authority = (
                _private_target_authority(
                    run_id=run_id,
                    startup_permit_sha256=_binding_digest(
                        startup_binding
                    ),
                    outer_attempt_arm_sha256=outer_attempt_arm_sha256,
                    work_plan_sha256=work_plan_sha256,
                    attempt_id=attempt_id,
                    process_scope_identity=process_scope_identity,
                    auxiliary_lease_binding_sha256=str(
                        lease_binding["binding_sha256"]
                    ),
                    launch_security_policy_sha256=(
                        launch_security_policy_sha256
                    ),
                    executable_observation_sha256=(
                        executable_observation_sha256
                    ),
                    auth_environment_receipt_sha256=(
                        auth_environment_receipt_sha256
                    ),
                    settings_authority_sha256=(
                        settings_authority_sha256
                    ),
                    mcp_authority_sha256=mcp_authority_sha256,
                    credential_parent_identity=_directory_identity(
                        config_dir
                    ),
                )
            )
            private_target_authority_sha256 = _binding_digest(
                private_target_authority
            )
            credential_descriptor = _open_empty_private_regular_file(
                credential_target
            )
            credential_integrity_key = bytearray(os.urandom(32))
            try:
                # The capability becomes terminal on every consume attempt:
                # success consumes it; any failure poisons and zeroizes it.
                capability_terminal = True
                try:
                    private_target_capability = (
                        _stored_subscription
                        .authorize_private_credential_target(
                            credential_descriptor,
                            destination_path=credential_target,
                            target_authority=private_target_authority,
                        )
                    )
                    credential_materialization = (
                        capability.consume_into_private_descriptor(
                            private_target_capability,
                            expected_source_evidence=(
                                expected_stored_subscription_source_evidence
                            ),
                        )
                    )
                except (
                    _stored_subscription
                    .ClaudeStoredSubscriptionSourceError
                ) as exc:
                    raise ClaudeAttemptProfileError(
                        "stored-subscription credential materialization "
                        "failed"
                    ) from exc
                credential_materialization = (
                    _stored_subscription
                    .replay_stored_subscription_materialization_receipt(
                        credential_materialization
                    )
                )
                if (
                    credential_materialization[
                        "private_target_authority_sha256"
                    ]
                    != private_target_authority_sha256
                ):
                    raise ClaudeAttemptProfileError(
                        "attempt credential target authority mismatched"
                    )
                credential_integrity_tag = bytearray(
                    _credential_integrity_tag(
                        credential_descriptor,
                        credential_integrity_key,
                    )
                )
                descriptor_row = os.fstat(credential_descriptor)
                path_row = credential_target.lstat()
                if (
                    credential_target.is_symlink()
                    or _is_reparse(credential_target)
                    or not stat.S_ISREG(path_row.st_mode)
                    or int(getattr(path_row, "st_nlink", 1)) != 1
                    or (
                        int(descriptor_row.st_dev),
                        int(descriptor_row.st_ino),
                    )
                    != (int(path_row.st_dev), int(path_row.st_ino))
                    or int(path_row.st_size)
                    != credential_materialization["source_size"]
                ):
                    raise ClaudeAttemptProfileError(
                        "attempt credential target identity drifted"
                    )
                private_credential_file_identity = (
                    _regular_file_identity(
                        _validate_private_credential_descriptor(
                            credential_target,
                            credential_descriptor,
                            validate_supported_schema=False,
                        )
                    )
                )
            finally:
                os.close(credential_descriptor)
        else:
            if os.path.lexists(credential_target):
                raise ClaudeAttemptProfileError(
                    "environment OAuth-token profile credential target "
                    "must be absent"
                )
            credential_materialization = "ABSENT"

        settings_payload = {
            "enabledPlugins": {},
            "hooks": {},
            "mcpServers": {},
            "extraKnownMarketplaces": {},
            "permissions": {
                "allow": [],
                "deny": [],
                "defaultMode": permission_mode,
            },
            "skipDangerousModePermissionPrompt": True,
            "skipWorkflowUsageWarning": True,
            "skipAutoPermissionPrompt": True,
            "autoUpdatesChannel": "stable",
        }
        settings_raw = _canonical_json(settings_payload)
        _write_private(config_dir / "settings.json", settings_raw)
        state_project_keys = [
            _claude_project_state_key(path)
            for path in cwd_rows
        ]
        projects = {
            project_key: {
                "allowedTools": [],
                "disabledMcpjsonServers": [],
                "enabledMcpjsonServers": [],
                "hasClaudeMdExternalIncludesApproved": True,
                "hasClaudeMdExternalIncludesWarningShown": True,
                "hasCompletedProjectOnboarding": True,
                "hasTrustDialogAccepted": True,
                "mcpContextUris": [],
                "mcpServers": {},
                "projectOnboardingSeenCount": 0,
            }
            for project_key in state_project_keys
        }
        state_payload = {
            "numStartups": _CLAUDE_STATE_INITIAL_STARTUPS,
            "installMethod": "native",
            "autoUpdates": False,
            "hasCompletedOnboarding": True,
            "migrationVersion": _CLAUDE_STATE_MIGRATION_VERSION,
            "lastOnboardingVersion": _CLAUDE_STATE_VERSION,
            "lastReleaseNotesSeen": _CLAUDE_STATE_VERSION,
            "bypassPermissionsModeAccepted": True,
            "projects": projects,
        }
        attempt_profile_created_at_utc = (
            datetime.now(timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
        state_raw = _canonical_json(state_payload)
        state_path = config_dir / ".claude.json"
        _write_private(state_path, state_raw)
        provider_mutable_state_authority = (
            _ClaudeProviderMutableStateAuthority.acquire(
                state_path,
                windows_job_only_restricted=windows_job_only_restricted,
            )
        )
        provider_mutable_state_replay = (
            provider_mutable_state_authority.replay()
        )
        if (
            provider_mutable_state_replay.get("valid") is not True
            or provider_mutable_state_replay.get(
                "completion_authority"
            )
            is not False
        ):
            raise ClaudeAttemptProfileError(
                "provider mutable state authority did not replay"
            )
        expected_config_entries = {
            ".claude.json",
            "settings.json",
        }
        if stored_credential_lane:
            expected_config_entries.add(".credentials.json")
        try:
            with os.scandir(config_dir) as entries:
                actual_config_entries = {entry.name for entry in entries}
        except OSError as exc:
            raise ClaudeAttemptProfileError(
                "attempt config directory cannot be inspected"
            ) from exc
        if actual_config_entries != expected_config_entries:
            raise ClaudeAttemptProfileError(
                "attempt config directory contains unexpected entries"
            )
        environment = {
            "CLAUDE_CONFIG_DIR": str(config_dir),
            "TEMP": str(temp_dir),
            "TMP": str(temp_dir),
            "TMPDIR": str(temp_dir),
            "CLAUDE_CODE_TMPDIR": str(temp_dir),
        }
        if home_variable_policy == "PRIVATE_HOME":
            environment.update(
                {
                    "HOME": str(home_dir),
                    "USERPROFILE": str(home_dir),
                    "APPDATA": str(appdata_dir),
                    "LOCALAPPDATA": str(localappdata_dir),
                }
            )
        trusted_cwd_strings = [str(item) for item in cwd_rows]
        trusted_cwd_denominator_sha256 = _binding_digest(
            {"trusted_cwds": trusted_cwd_strings}
        )
        private_root = {
            "lease_root": str(runtime),
            "lease_root_identity": lease_binding["root_identity"],
            "profile_root": str(root.resolve(strict=True)),
            "profile_root_identity": _directory_identity(root),
        }
        directory_security_binding = {
            "protocol": str(root_security["protocol"]),
            "verified_before_secret_write": True,
            "credential_parent_replay": credential_parent_security,
            "directories": directory_security,
        }
        binding_core: dict[str, Any] = {
            "schema": ATTEMPT_PROFILE_SCHEMA,
            "run_id": run_id,
            "startup_permit_binding": startup_binding,
            "startup_permit_sha256": _binding_digest(startup_binding),
            "startup_epoch": startup_binding["startup_epoch"],
            "outer_attempt_arm_sha256": outer_attempt_arm_sha256,
            "work_plan_sha256": work_plan_sha256,
            "attempt_id": attempt_id,
            "process_scope_identity": process_scope_identity,
            "auxiliary_lease_binding_sha256": lease_binding[
                "binding_sha256"
            ],
            "launch_security_policy_sha256": (
                launch_security_policy_sha256
            ),
            "executable_observation_sha256": (
                executable_observation_sha256
            ),
            "auth_environment_receipt_sha256": (
                auth_environment_receipt_sha256
            ),
            "settings_authority_sha256": settings_authority_sha256,
            "mcp_authority_sha256": mcp_authority_sha256,
            "credential_mode": credential_mode,
            "auth_route": auth_route,
            "credential_copy": credential_materialization,
            "settings_sha256": _sha(settings_raw),
            "state_sha256": _sha(state_raw),
            "state_provider_version": _CLAUDE_STATE_VERSION,
            "attempt_profile_created_at_utc": (
                attempt_profile_created_at_utc
            ),
            "state_project_keys": state_project_keys,
            "state_project_key_denominator_sha256": _binding_digest(
                {"state_project_keys": state_project_keys}
            ),
            "project_root": str(project),
            "trusted_cwds": trusted_cwd_strings,
            "trusted_cwd_denominator_sha256": (
                trusted_cwd_denominator_sha256
            ),
            "private_root": private_root,
            "private_root_identity_sha256": _binding_digest(private_root),
            "home_variable_policy": home_variable_policy,
            "permission_mode": permission_mode,
            "environment_keys": sorted(environment),
            "directory_security": directory_security_binding,
            "directory_security_sha256": _binding_digest(
                directory_security_binding
            ),
            "directory_guard_subject_binding_sha256": (
                directory_guard_subject_binding_sha256
            ),
            "directory_guard": directory_guard.binding,
            "provider_mutable_state_security": (
                provider_mutable_state_authority.binding
            ),
        }
        if stored_credential_lane:
            binding_core[
                "credential_target_path_authority_sha256"
            ] = private_target_authority_sha256
        if "CLAUDE_SECURESTORAGE_CONFIG_DIR" in environment:
            raise ClaudeAttemptProfileError(
                "attempt environment leaked secure-storage source authority"
            )
        binding = {
            **binding_core,
            "profile_sha256": _binding_digest(binding_core),
        }
        private_home_overlay_authority = (
            _child_environment
            ._mint_claude_private_home_overlay_authority(
                attempt_profile_environment=environment,
                attempt_profile_binding=binding,
            )
            if home_variable_policy == "PRIVATE_HOME"
            else None
        )
        return ClaudeAttemptProfile(
            root=root,
            config_dir=config_dir,
            home_dir=home_dir,
            state_path=state_path,
            temp_dir=temp_dir,
            environment=MappingProxyType(dict(environment)),
            _binding=MappingProxyType(
                json.loads(_canonical_json(binding).decode("utf-8"))
            ),
            _leased_parent=lease,
            _directory_guard=directory_guard,
            _provider_mutable_state_authority=(
                provider_mutable_state_authority
            ),
            _private_credential_file_identity=MappingProxyType(
                dict(private_credential_file_identity)
            ),
            _private_credential_integrity_key=(
                credential_integrity_key
                if credential_integrity_key is not None
                else bytearray()
            ),
            _private_credential_integrity_tag=(
                credential_integrity_tag
                if credential_integrity_tag is not None
                else bytearray()
            ),
            _private_home_overlay_authority=(
                private_home_overlay_authority
            ),
        )
    except BaseException:
        for private in (
            credential_integrity_key,
            credential_integrity_tag,
        ):
            if private is not None:
                for index in range(len(private)):
                    private[index] = 0
        discard_error: Exception | None = None
        if capability is not None and not capability_terminal:
            try:
                capability.discard()
                capability_terminal = True
            except Exception as exc:
                discard_error = exc
        # Claim the lease lifecycle before deleting any partially
        # materialized profile bytes. If a process scope won the race, retain
        # the root for zero-population recovery instead of deleting beneath
        # that scope.
        try:
            prelaunch_abort_claim = lease.claim_prelaunch_abort(
                attempt_arm_sha256=actual_arm_sha256,
                process_scope_identity=actual_scope_identity,
                reason_code="PROFILE_MATERIALIZATION_FAILED",
            )
        except Exception as claim_exc:
            raise ClaudeAttemptProfileError(
                "attempt profile materialization failed and prelaunch "
                "abort claim was unavailable; partial root retained"
            ) from claim_exc
        if directory_guard is not None:
            try:
                if provider_mutable_state_authority is not None:
                    provider_mutable_state_authority.release_for_cleanup()
                rollback_evidence_sha256 = _binding_digest({
                    "directory_guard_subject_binding_sha256": (
                        directory_guard.binding[
                            "subject_binding_sha256"
                        ]
                    ),
                    "attempt_id": attempt_id,
                    "process_scope_identity": process_scope_identity,
                    "failure": "PROFILE_MATERIALIZATION_FAILED",
                    "process_scope_created": False,
                    "cleanup_mode": (
                        "MATERIALIZATION_FAILURE_CLEANUP"
                    ),
                })
                guard_receipt = directory_guard.revoke_after_zero(
                    zero_population_evidence_sha256=(
                        rollback_evidence_sha256
                    ),
                    cleanup_mode="MATERIALIZATION_FAILURE_CLEANUP",
                )
                if (
                    guard_receipt.get("terminal_stage")
                    != "VERIFIED_ABSENT"
                    or guard_receipt.get("completion_authority")
                    is not False
                ):
                    raise ClaudeAttemptProfileError(
                        "materialization guard rollback did not replay"
                    )
            except (
                _owned_directory.OwnedDirectoryGuardError,
                ClaudeAttemptProfileError,
            ) as cleanup_exc:
                raise ClaudeAttemptProfileError(
                    "attempt profile materialization failed and retained-"
                    "handle rollback was incomplete"
                ) from cleanup_exc
        try:
            lease.abort_before_process_scope(
                attempt_arm_sha256=actual_arm_sha256,
                process_scope_identity=actual_scope_identity,
                reason_code="PROFILE_MATERIALIZATION_FAILED",
                claim=prelaunch_abort_claim,
            )
        except Exception as cleanup_exc:
            raise ClaudeAttemptProfileError(
                "attempt profile materialization failed and rollback was incomplete"
            ) from cleanup_exc
        if discard_error is not None:
            raise ClaudeAttemptProfileError(
                "attempt profile capability discard failed"
            ) from discard_error
        raise


__all__ = [
    "ATTEMPT_PROFILE_SCHEMA",
    "ClaudeAttemptProfile",
    "ClaudeAttemptProfileError",
    "ClaudeBoundPrelaunchScopeClosureToken",
    "ClaudeFreshPostprocessAuthority",
    "ClaudeNormalScopeFailureClosureToken",
    "ClaudeProcessAttachFailureScopeClosureToken",
    "ClaudeProfileScopeClosureToken",
    "REVOCATION_SCHEMA",
    "materialize_claude_attempt_profile",
    "mint_claude_fresh_postprocess_authority",
    "prove_claude_bound_prelaunch_scope_closed",
    "prove_claude_normal_scope_failure_closed",
    "prove_claude_process_attach_failure_scope_closed",
    "prove_claude_profile_scope_closed",
    "replay_claude_attempt_profile_binding",
    "replay_claude_attempt_profile_postprocess_binding",
    "replay_claude_attempt_profile_revocation",
]
