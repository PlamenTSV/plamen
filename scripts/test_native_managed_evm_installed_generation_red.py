"""Release-blocking contracts for the absent installer-side producer.

These stay RED until cold install publishes a signed managed generation and
the native extension re-admits it.  They intentionally prevent driver wiring
from turning the provisioner image-member receipt into generation authority.
"""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXTENSION = ROOT / "native/cpython/_plamen_native_supervisor.c"


def test_native_extension_has_complete_installed_generation_readmission_abi() -> None:
    source = EXTENSION.read_text(encoding="utf-8")
    for symbol in (
        "ManagedEVMInstalledGenerationAuthority",
        "acquire_managed_evm_installed_generation",
        "observe_managed_evm_installed_generation",
        "stage_managed_evm_audit_setup",
        "validate_managed_evm_audit_setup_stage",
        "commit_managed_evm_audit_setup",
        "validate_managed_evm_installed_generation_receipt",
        "rollback_managed_evm_audit_setup",
        "cleanup_managed_evm_audit_setup",
        "require_managed_evm_installed_generation",
    ):
        assert symbol in source


def test_cold_install_has_real_offline_managed_generation_inputs() -> None:
    projection = (
        ROOT / "scripts/runtime_source_projection.py"
    ).read_text(encoding="utf-8")
    builder = (
        ROOT / "scripts/build_posix_native_supervisor.py"
    ).read_text(encoding="utf-8")
    for required in (
        "managed_evm_offline_provision_policy",
        "managed_evm_offline_acquisition_receipt",
        "managed_evm_offline_wheel_cache",
        "managed_evm_installed_generation_receipt",
    ):
        assert required in projection
        assert required in builder
