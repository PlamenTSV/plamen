from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from native_managed_evm_setup_effects import (
    NativeManagedEVMSetupEffects,
    NativeManagedEVMSetupEffectsError,
)
from posix_managed_evm_setup_transaction import (
    execute_managed_evm_setup_transaction,
)


def _artifact(path: Path, kind: str, *, transaction: bool = False) -> dict:
    raw = path.read_bytes()
    value = {
        "schema": "plamen.posix-native-install.artifact.v1",
        "kind": kind, "path": str(path), "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    if transaction:
        value["transaction_id"] = "a" * 32
    return value


def _fixture(tmp_path: Path):
    home = tmp_path / "home"
    project = tmp_path / "project"
    home.mkdir(mode=0o700)
    project.mkdir(mode=0o700)
    receipts = home / "installed"
    receipts.mkdir(mode=0o700)
    package = receipts / "package.json"
    native = receipts / "native.bin"
    deployment = receipts / "deployment.bin"
    for path, raw in (
        (package, b"package\n"), (native, b"native\n"),
        (deployment, b"deployment\n"),
    ):
        path.write_bytes(raw)
        path.chmod(0o400)
    managed = receipts / "managed.bin"
    runtime = object()
    installed = object()
    generation = object()
    calls: list[str] = []

    def admit(candidate):
        calls.append("admit")
        assert candidate is runtime
        return installed

    def observe(candidate, project_fd, project_sha):
        calls.append("observe")
        assert candidate is installed
        assert os.path.isdir(f"/dev/fd/{project_fd}")
        assert project_sha == "1" * 64
        return {
            "package_receipt": _artifact(package, "package-receipt", transaction=True),
            "native_install_receipt": _artifact(native, "native-install-receipt"),
            "deployment_receipt": _artifact(deployment, "deployment-receipt"),
            "prior_managed_evm_generation_receipt": None,
            "installed_runtime_binding_sha256": "2" * 64,
        }

    def stage(candidate, project_fd, project_sha, root_fd, txid, prestate):
        calls.append("stage")
        assert candidate is installed and os.fstat(project_fd).st_ino
        assert os.fstat(root_fd).st_ino
        assert project_sha == "1" * 64
        assert prestate["input_binding_sha256"]
        return {
            "schema": "plamen.posix-native-install.stage.v1",
            "kind": "managed-evm", "transaction_id": txid,
            "manifest_sha256": "3" * 64, "artifact_count": 4,
        }

    def validate_stage(candidate, project_fd, project_sha, stage_value, prestate):
        calls.append("validate-stage")
        assert candidate is installed and os.fstat(project_fd).st_ino
        assert project_sha == "1" * 64
        assert stage_value["kind"] == "managed-evm"
        assert prestate["native_install_receipt"]["path"] == str(native)
        return True

    def commit(candidate, project_fd, project_sha, stage_value, prestate):
        calls.append("commit")
        assert candidate is installed and os.fstat(project_fd).st_ino
        assert project_sha == "1" * 64 and stage_value["transaction_id"]
        assert prestate["deployment_receipt"]["path"] == str(deployment)
        managed.write_bytes(b"signed installed generation\n")
        managed.chmod(0o400)
        return _artifact(managed, "managed-evm-generation-receipt")

    def validate_receipt(candidate, project_fd, project_sha, receipt, stage_value, prestate):
        calls.append("validate-receipt")
        assert candidate is installed and os.fstat(project_fd).st_ino
        assert project_sha == "1" * 64
        assert receipt == _artifact(managed, "managed-evm-generation-receipt")
        assert stage_value is not None and prestate["input_binding_sha256"]
        return generation

    def rollback(*_args):
        calls.append("rollback")
        managed.unlink(missing_ok=True)
        return True

    def cleanup(*_args):
        calls.append("cleanup")
        return True

    def require(candidate):
        calls.append("require")
        assert candidate is generation
        return {"schema": "plamen.managed-evm-generation-execution-authority.v1"}

    project_fd = os.open(project, os.O_RDONLY | os.O_CLOEXEC)
    try:
        effects = NativeManagedEVMSetupEffects(
            home=home, native_runtime=runtime, project_fd=project_fd,
            project_identity_sha256="1" * 64,
            admit_installed=admit, observe_installed=observe,
            stage_setup=stage, validate_stage=validate_stage,
            commit_setup=commit, validate_receipt=validate_receipt,
            rollback_setup=rollback, cleanup_setup=cleanup,
            require_generation=require,
        )
    finally:
        os.close(project_fd)
    return home, effects, generation, calls


def test_snapshotless_installed_runtime_setup_executes_recoverable_transaction(
    tmp_path: Path,
) -> None:
    home, effects, generation, calls = _fixture(tmp_path)
    try:
        receipt = execute_managed_evm_setup_transaction(home=home, effects=effects)
        assert receipt["state"] == "COMMITTED"
        assert effects.managed_evm_generation_authority() is generation
        replay = execute_managed_evm_setup_transaction(home=home, effects=effects)
        assert replay == receipt
        assert calls.count("commit") == 1
        assert "admit" in calls and "validate-receipt" in calls
    finally:
        effects.close()


def test_setup_effects_have_no_cold_snapshot_or_acquisition_path_surface() -> None:
    source = Path(__file__).with_name("native_managed_evm_setup_effects.py").read_text()
    assert "package_snapshot" not in source
    assert "acquisition_receipt_path" not in source
    assert "managed_root" not in source


def test_setup_rejects_non_readonly_project_descriptor(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    descriptor = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC)
    try:
        with pytest.raises(
            NativeManagedEVMSetupEffectsError,
            match="project descriptor is not read-only",
        ):
            NativeManagedEVMSetupEffects(
                home=home, native_runtime=object(), project_fd=descriptor,
                project_identity_sha256="1" * 64,
                **{name: (lambda *_args: object()) for name in (
                    "admit_installed", "observe_installed", "stage_setup",
                    "validate_stage", "commit_setup", "validate_receipt",
                    "rollback_setup", "cleanup_setup", "require_generation",
                )},
            )
    finally:
        os.close(descriptor)
