"""Audit-start admission of one installed managed-EVM generation.

The cold installer owns acquisition and publication.  This module owns only
audit-time readmission: it asks the opaque native runtime bundle for the exact
installed-generation effects surface, replays the durable setup transaction,
and retains both that owner and the admitted generation for the audit process.

There is deliberately no path discovery, ambient lookup, process-launch
fallback, or mapping-shaped authority.  Windows and unknown hosts fail before
opening the audited project because their native installed-generation collector
has not been implemented.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import sys
from typing import Any, NoReturn
import weakref

from native_managed_evm_setup_effects import NativeManagedEVMSetupEffects
from posix_managed_evm_setup_transaction import (
    execute_managed_evm_setup_transaction,
)


_HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class NativeManagedEVMDriverPreflightError(RuntimeError):
    """The installed generation could not be re-admitted for this audit."""


def _fail(message: str) -> NoReturn:
    raise NativeManagedEVMDriverPreflightError(message) from None


class NativeManagedEVMAuditPreflight:
    """Opaque, process-local owner of a re-admitted managed generation."""

    __slots__ = ("__token", "__weakref__")

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("native managed-EVM audit preflight is native-issued")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("native managed-EVM audit preflight is immutable")

    def __copy__(self) -> NoReturn:
        raise TypeError("native managed-EVM audit preflight cannot be copied")

    def __deepcopy__(self, _memo: Any) -> NoReturn:
        raise TypeError("native managed-EVM audit preflight cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("native managed-EVM audit preflight cannot be serialized")

    def __repr__(self) -> str:
        return "<NativeManagedEVMAuditPreflight opaque>"


class _Record:
    __slots__ = (
        "effects", "generation", "native_runtime", "project_identity_sha256",
        "projection", "creator_pid", "finalizer",
    )

    def __init__(
        self, *, effects: NativeManagedEVMSetupEffects, generation: object,
        native_runtime: object, project_identity_sha256: str,
        projection: bytes,
        finalizer: weakref.finalize,
    ) -> None:
        self.effects = effects
        self.generation = generation
        self.native_runtime = native_runtime
        self.project_identity_sha256 = project_identity_sha256
        self.projection = projection
        self.creator_pid = os.getpid()
        self.finalizer = finalizer


_LIVE: weakref.WeakKeyDictionary[
    NativeManagedEVMAuditPreflight, _Record
] = weakref.WeakKeyDictionary()


def _record(
    authority: object,
    *,
    native_runtime: object | None = None,
    project_identity_sha256: str | None = None,
) -> _Record:
    if type(authority) is not NativeManagedEVMAuditPreflight:
        _fail("managed-EVM audit preflight authority is absent or forged")
    value = _LIVE.get(authority)
    if (
        value is None
        or value.creator_pid != os.getpid()
        or (native_runtime is not None and value.native_runtime is not native_runtime)
        or (
            project_identity_sha256 is not None
            and value.project_identity_sha256 != project_identity_sha256
        )
    ):
        _fail("managed-EVM audit preflight authority is foreign or expired")
    return value


def prepare_native_managed_evm_for_audit(
    *,
    account_root: Path,
    native_runtime: object,
    project_root: Path,
    project_identity_sha256: str,
) -> NativeManagedEVMAuditPreflight:
    """Re-admit the installer-owned generation before snapshot side effects.

    ``project_identity_sha256`` is the authenticated target identity from the
    native audit request.  The project pathname is used only to acquire one
    read-only no-follow descriptor; downstream authority is the retained
    descriptor plus the exact native runtime capability.
    """

    if os.name == "nt" or sys.platform == "win32":
        _fail(
            "WINDOWS_NATIVE_MANAGED_EVM_UNAVAILABLE: native reparse-tag, "
            "stream, ACL, and process custody is not implemented"
        )
    if sys.platform != "darwin" and not sys.platform.startswith("linux"):
        _fail("UNSUPPORTED_NATIVE_MANAGED_EVM_PLATFORM")
    if (
        native_runtime is None
        or type(project_identity_sha256) is not str
        or _HEX64.fullmatch(project_identity_sha256) is None
    ):
        _fail("native runtime or audited target identity is malformed")
    account = Path(account_root).absolute()
    project = Path(project_root).absolute()
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(
        os, "O_CLOEXEC", 0
    ) | getattr(os, "O_NOFOLLOW", 0)
    try:
        project_fd = os.open(project, flags)
    except OSError as exc:
        raise NativeManagedEVMDriverPreflightError(
            "audited project descriptor cannot be retained"
        ) from exc
    effects: NativeManagedEVMSetupEffects | None = None
    try:
        import posix_backend_execution as runtime

        factory = getattr(runtime, "native_guest_managed_evm_setup_effects", None)
        if not callable(factory):
            _fail("native installed-generation setup ABI is unavailable")
        effects = factory(
            native_runtime,
            home=account,
            project_fd=project_fd,
            project_identity_sha256=project_identity_sha256,
        )
        if type(effects) is not NativeManagedEVMSetupEffects:
            _fail("native installed-generation effects have the wrong exact type")
    finally:
        os.close(project_fd)
    try:
        terminal = execute_managed_evm_setup_transaction(
            home=account, effects=effects,
        )
        if (
            type(terminal) is not dict
            or terminal.get("schema")
            != "plamen.posix-managed-evm-setup.receipt.v1"
            or terminal.get("state") != "COMMITTED"
        ):
            _fail("native managed-EVM setup terminal differs")
        generation = effects.managed_evm_generation_authority()
        import audit_snapshot

        projection = audit_snapshot.managed_evm_slither_snapshot_projection(
            generation, project_root=project,
        )
        if type(projection) is not bytes or not projection or projection.endswith(b"\n"):
            _fail("managed Slither projection is malformed")
        issued = object.__new__(NativeManagedEVMAuditPreflight)
        object.__setattr__(
            issued, "_NativeManagedEVMAuditPreflight__token", object(),
        )
        finalizer = weakref.finalize(issued, effects.close)
        _LIVE[issued] = _Record(
            effects=effects,
            generation=generation,
            native_runtime=native_runtime,
            project_identity_sha256=project_identity_sha256,
            projection=bytes(projection),
            finalizer=finalizer,
        )
        effects = None
        return issued
    except BaseException:
        if effects is not None:
            effects.close()
        raise


def managed_evm_generation_authority_for_runtime(
    authority: object,
    *,
    native_runtime: object,
    project_identity_sha256: str,
) -> object:
    """Return the retained opaque generation after native replay."""

    value = _record(
        authority,
        native_runtime=native_runtime,
        project_identity_sha256=project_identity_sha256,
    )
    required = value.effects.managed_evm_generation_authority()
    if required is not value.generation:
        _fail("managed-EVM generation identity changed during replay")
    return required


def managed_evm_slither_projection_for_runtime(
    authority: object,
    *,
    native_runtime: object,
    project_identity_sha256: str,
) -> bytes:
    """Return snapshot bytes only after replaying the same live authority."""

    value = _record(
        authority,
        native_runtime=native_runtime,
        project_identity_sha256=project_identity_sha256,
    )
    required = value.effects.managed_evm_generation_authority()
    if required is not value.generation:
        _fail("managed-EVM generation identity changed during projection replay")
    return bytes(value.projection)


def close_native_managed_evm_audit_preflight(authority: object) -> None:
    """Release descriptor custody; a closed authority cannot be reused."""

    value = _record(authority)
    del _LIVE[authority]
    value.finalizer()


__all__ = (
    "NativeManagedEVMAuditPreflight", "NativeManagedEVMDriverPreflightError",
    "close_native_managed_evm_audit_preflight",
    "managed_evm_generation_authority_for_runtime",
    "managed_evm_slither_projection_for_runtime",
    "prepare_native_managed_evm_for_audit",
)
