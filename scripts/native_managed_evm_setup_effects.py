"""Descriptor-custodied effects for the pre-audit managed-EVM setup.

This module deliberately does not reuse ``DarwinColdInstallEffects``.  A
running audit has no cold-install package snapshot and must not reconstruct
one.  Instead, a native runtime callback admits the installed terminal
receipt/runtime census and retains the source-bootstrap acquisition authority;
all setup mutations remain behind that opaque native authority.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Callable, Mapping


class NativeManagedEVMSetupEffectsError(RuntimeError):
    """Installed authority, descriptor custody, or setup effect differs."""


def _fail(message: str) -> None:
    raise NativeManagedEVMSetupEffectsError(message) from None


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")


def _hex64(value: object) -> bool:
    return (
        type(value) is str and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _artifact(value: object, kind: str) -> dict[str, Any]:
    fields = {"schema", "kind", "path", "size", "sha256"}
    if kind == "package-receipt":
        fields.add("transaction_id")
    if (
        type(value) is not dict
        or set(value) != fields
        or value.get("schema") != "plamen.posix-native-install.artifact.v1"
        or value.get("kind") != kind
        or type(value.get("path")) is not str
        or not value["path"].startswith("/")
        or type(value.get("size")) is not int
        or value["size"] <= 0
        or not _hex64(value.get("sha256"))
        or (kind == "package-receipt"
            and (type(value["transaction_id"]) is not str
                 or len(value["transaction_id"]) != 32
                 or not all(character in "0123456789abcdef"
                            for character in value["transaction_id"])))
    ):
        _fail(f"{kind} authority differs")
    return dict(value)


def _dup_project_fd(fd: int) -> tuple[int, dict[str, Any]]:
    duplicate = -1
    try:
        if type(fd) is not int or fd < 0:
            _fail("audited project descriptor is absent")
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        if flags & os.O_ACCMODE != os.O_RDONLY:
            _fail("audited project descriptor is not read-only")
        duplicate = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 3)
        information = os.fstat(duplicate)
        if (
            not stat.S_ISDIR(information.st_mode)
            or information.st_uid != os.getuid()
        ):
            _fail("audited project descriptor identity differs")
        binding = {
            "schema": "plamen.native-managed-evm.project-fd.v1",
            "device": int(information.st_dev),
            "inode": int(information.st_ino),
            "mode": stat.S_IMODE(information.st_mode),
            "uid": int(information.st_uid),
        }
        return duplicate, binding
    except OSError:
        if duplicate >= 0:
            os.close(duplicate)
        _fail("audited project descriptor cannot be retained")


class NativeManagedEVMSetupEffects:
    """Setup transaction effects admitted from one native runtime authority.

    Every callable is mandatory and receives the opaque installed authority.
    Python never receives an acquisition-receipt path, managed-root path, or a
    serializable replacement for the native authority.  Resume creates a fresh
    instance, re-admits the installed terminal, and replays the exact durable
    transaction through the same callbacks.
    """

    def __init__(
        self, *, home: Path, native_runtime: object, project_fd: int,
        project_identity_sha256: str,
        admit_installed: Callable[..., object],
        observe_installed: Callable[..., object],
        stage_setup: Callable[..., object],
        validate_stage: Callable[..., object],
        commit_setup: Callable[..., object],
        validate_receipt: Callable[..., object],
        rollback_setup: Callable[..., object],
        cleanup_setup: Callable[..., object],
        require_generation: Callable[..., object],
    ):
        account = Path(home).absolute()
        try:
            account_information = os.lstat(account)
        except OSError:
            _fail("setup account root is unavailable")
        if (
            not stat.S_ISDIR(account_information.st_mode)
            or stat.S_ISLNK(account_information.st_mode)
            or account_information.st_uid != os.getuid()
            or stat.S_IMODE(account_information.st_mode) & 0o022
            or native_runtime is None
            or not _hex64(project_identity_sha256)
        ):
            _fail("setup account/runtime/project authority differs")
        operations = {
            "admit_installed": admit_installed,
            "observe_installed": observe_installed,
            "stage_setup": stage_setup,
            "validate_stage": validate_stage,
            "commit_setup": commit_setup,
            "validate_receipt": validate_receipt,
            "rollback_setup": rollback_setup,
            "cleanup_setup": cleanup_setup,
            "require_generation": require_generation,
        }
        if any(not callable(value) for value in operations.values()):
            _fail("native managed-EVM setup effect roster is incomplete")
        retained_fd, project_binding = _dup_project_fd(project_fd)
        try:
            installed = admit_installed(native_runtime)
        except BaseException:
            os.close(retained_fd)
            raise
        if installed is None:
            os.close(retained_fd)
            _fail("authenticated installed runtime admission is absent")
        self.home = account
        self._native_runtime = native_runtime
        self._installed = installed
        self._project_fd = retained_fd
        self._project_binding = project_binding
        self._project_identity_sha256 = project_identity_sha256
        self._operations = operations
        self._generation: object | None = None

    def close(self) -> None:
        descriptor = getattr(self, "_project_fd", -1)
        if descriptor >= 0:
            os.close(descriptor)
            self._project_fd = -1
        self._generation = None

    def __enter__(self) -> "NativeManagedEVMSetupEffects":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _replay_project(self) -> dict[str, Any]:
        if self._project_fd < 0:
            _fail("audited project descriptor custody is closed")
        information = os.fstat(self._project_fd)
        current = {
            "schema": "plamen.native-managed-evm.project-fd.v1",
            "device": int(information.st_dev),
            "inode": int(information.st_ino),
            "mode": stat.S_IMODE(information.st_mode),
            "uid": int(information.st_uid),
        }
        if current != self._project_binding:
            _fail("audited project descriptor identity changed")
        return current

    def _installed_prestate(self) -> dict[str, Any]:
        observed = self._operations["observe_installed"](
            self._installed, self._project_fd,
            self._project_identity_sha256,
        )
        fields = {
            "package_receipt", "native_install_receipt",
            "deployment_receipt", "prior_managed_evm_generation_receipt",
            "installed_runtime_binding_sha256",
        }
        if (
            type(observed) is not dict or set(observed) != fields
            or not _hex64(observed.get("installed_runtime_binding_sha256"))
        ):
            _fail("installed setup predecessor projection differs")
        package = _artifact(observed["package_receipt"], "package-receipt")
        native = _artifact(
            observed["native_install_receipt"], "native-install-receipt",
        )
        deployment = _artifact(
            observed["deployment_receipt"], "deployment-receipt",
        )
        prior = observed["prior_managed_evm_generation_receipt"]
        if prior is not None:
            prior = _artifact(prior, "managed-evm-generation-receipt")
        binding = {
            "schema": "plamen.native-managed-evm.setup-input-binding.v1",
            "installed_runtime_binding_sha256":
                observed["installed_runtime_binding_sha256"],
            "project_fd": self._replay_project(),
            "project_identity_sha256": self._project_identity_sha256,
        }
        return {
            "schema": "plamen.posix-managed-evm-setup.prestate.v1",
            "home": str(self.home),
            "package_receipt": package,
            "native_install_receipt": native,
            "deployment_receipt": deployment,
            "prior_managed_evm_generation_receipt": prior,
            "input_binding_sha256": hashlib.sha256(
                _canonical(binding),
            ).hexdigest(),
        }

    def observe_managed_evm_setup_prestate(self, home: Path) -> dict[str, Any]:
        if Path(home).absolute() != self.home:
            _fail("managed-EVM setup account root differs")
        return self._installed_prestate()

    def stage_managed_evm_setup(
        self, home: Path, transaction_root: Path, prestate: Mapping[str, Any],
    ) -> dict[str, Any]:
        if Path(home).absolute() != self.home or dict(prestate) != self._installed_prestate():
            _fail("managed-EVM setup predecessor changed before stage")
        root_fd = os.open(
            transaction_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            stage = self._operations["stage_setup"](
                self._installed, self._project_fd,
                self._project_identity_sha256, root_fd,
                transaction_root.name, dict(prestate),
            )
        finally:
            os.close(root_fd)
        return self._validate_stage_shape(stage, transaction_root.name)

    @staticmethod
    def _validate_stage_shape(value: object, transaction_id: str) -> dict[str, Any]:
        fields = {"schema", "kind", "transaction_id", "manifest_sha256", "artifact_count"}
        if (
            type(value) is not dict or set(value) != fields
            or value.get("schema") != "plamen.posix-native-install.stage.v1"
            or value.get("kind") != "managed-evm"
            or value.get("transaction_id") != transaction_id
            or not _hex64(value.get("manifest_sha256"))
            or type(value.get("artifact_count")) is not int
            or value["artifact_count"] <= 0
        ):
            _fail("native managed-EVM stage authority differs")
        return dict(value)

    def validate_managed_evm_setup_stage(
        self, stage: Mapping[str, Any], prestate: Mapping[str, Any],
    ) -> None:
        validated = self._validate_stage_shape(stage, stage.get("transaction_id", ""))
        if dict(prestate) != self._installed_prestate() or self._operations[
            "validate_stage"
        ](
            self._installed, self._project_fd,
            self._project_identity_sha256, validated, dict(prestate),
        ) is not True:
            _fail("native managed-EVM stage replay differs")

    def commit_managed_evm_setup(
        self, stage: Mapping[str, Any], prestate: Mapping[str, Any],
    ) -> dict[str, Any]:
        self.validate_managed_evm_setup_stage(stage, prestate)
        receipt = self._operations["commit_setup"](
            self._installed, self._project_fd,
            self._project_identity_sha256, dict(stage), dict(prestate),
        )
        artifact = _artifact(receipt, "managed-evm-generation-receipt")
        self.validate_managed_evm_setup_receipt(artifact, stage, prestate)
        return artifact

    def validate_managed_evm_setup_receipt(
        self, receipt: Mapping[str, Any], stage: Mapping[str, Any] | None,
        prestate: Mapping[str, Any],
    ) -> None:
        if dict(prestate) != self._installed_prestate():
            _fail("managed-EVM installed predecessor changed")
        artifact = _artifact(dict(receipt), "managed-evm-generation-receipt")
        admitted = self._operations["validate_receipt"](
            self._installed, self._project_fd,
            self._project_identity_sha256, artifact,
            None if stage is None else dict(stage), dict(prestate),
        )
        self._operations["require_generation"](admitted)
        self._generation = admitted

    def rollback_managed_evm_setup(
        self, receipt: Mapping[str, Any] | None, stage: Mapping[str, Any],
        prestate: Mapping[str, Any],
    ) -> None:
        self.validate_managed_evm_setup_stage(stage, prestate)
        artifact = None if receipt is None else _artifact(
            dict(receipt), "managed-evm-generation-receipt",
        )
        if self._operations["rollback_setup"](
            self._installed, self._project_fd,
            self._project_identity_sha256, artifact, dict(stage),
            dict(prestate),
        ) is not True:
            _fail("native managed-EVM rollback is incomplete")
        self._generation = None

    def cleanup_managed_evm_setup(self, stage: Mapping[str, Any]) -> None:
        validated = self._validate_stage_shape(stage, stage.get("transaction_id", ""))
        if self._operations["cleanup_setup"](
            self._installed, validated,
        ) is not True:
            _fail("native managed-EVM setup cleanup is incomplete")

    def managed_evm_generation_authority(self) -> object:
        if self._generation is None:
            _fail("managed-EVM generation has not been admitted")
        self._operations["require_generation"](self._generation)
        return self._generation


__all__ = [
    "NativeManagedEVMSetupEffects", "NativeManagedEVMSetupEffectsError",
]
