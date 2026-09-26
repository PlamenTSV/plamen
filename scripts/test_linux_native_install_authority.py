"""Linux-native release-slice and source-freeze authority gates."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import ModuleType

import pytest

import linux_native_install_authority as L


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "build_posix_native_supervisor.py"


def _load_builder() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "_plamen_linux_platform_builder_test", BUILDER,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("machine", "key", "canonical", "elf_machine", "suffix"),
    (
        (
            "x86_64", "linux-x86_64", "x86_64", 62,
            ".cpython-312-x86_64-linux-gnu.so",
        ),
        (
            "amd64", "linux-x86_64", "x86_64", 62,
            ".cpython-312-x86_64-linux-gnu.so",
        ),
        (
            "aarch64", "linux-arm64", "aarch64", 183,
            ".cpython-312-aarch64-linux-gnu.so",
        ),
        (
            "arm64", "linux-arm64", "aarch64", 183,
            ".cpython-312-aarch64-linux-gnu.so",
        ),
    ),
)
def test_supported_linux_slices_are_exact(
    machine: str, key: str, canonical: str, elf_machine: int, suffix: str,
) -> None:
    authority = L.platform_authority(platform_name="linux", machine=machine)
    assert authority.platform_key == key
    assert authority.canonical_machine == canonical
    assert authority.elf_class == 2
    assert authority.elf_data == 1
    assert authority.elf_machine == elf_machine
    assert authority.extension_suffix == suffix


@pytest.mark.parametrize(
    ("platform_name", "machine", "code"),
    (
        ("darwin", "arm64", "LINUX_PLATFORM_UNSUPPORTED"),
        ("linux2", "x86_64", "LINUX_PLATFORM_UNSUPPORTED"),
        ("linux", "i686", "LINUX_MACHINE_UNSUPPORTED"),
        ("linux", "riscv64", "LINUX_MACHINE_UNSUPPORTED"),
    ),
)
def test_unsupported_host_fails_with_stable_code_before_contract_open(
    platform_name: str, machine: str, code: str,
) -> None:
    with pytest.raises(L.LinuxNativeInstallAuthorityError, match=code):
        L.platform_authority(platform_name=platform_name, machine=machine)


def test_committed_platform_contract_is_canonical_and_exact() -> None:
    raw = (ROOT / "native/linux/native-platform-authority-v2.json").read_bytes()
    contract = L.decode_platform_contract(raw)
    assert L.canonical_json_bytes(contract) == raw
    assert contract["receipt"]["receipt_fd"] == 198
    assert contract["receipt"]["install_root_fd"] == 199
    assert contract["launch"]["environment"] == {}
    assert contract["signature_policy"] == {
        "ambient_path_executable": "DENY",
        "artifact_identity": (
            "SHA256_SIZE_MODE_ELF_INTERP_AND_ORDERED_DT_NEEDED_CLOSURE"
        ),
        "install_provenance": "RETAINED_VERIFIED_SIGNED_RELEASE_PROVENANCE",
        "receipt_trust_boundary": "RETAINED_IMMUTABLE_SIGNED_GENERATION",
        "unsigned_local_build": "NEVER_PRODUCTION_AUTHORITY",
    }


@pytest.mark.parametrize(
    ("section", "field", "replacement", "code"),
    (
        ("receipt", "receipt_fd", 197, "LINUX_PLATFORM_AUTHORITY_RECEIPT"),
        ("launch", "environment", {"PATH": "/tmp"}, "LINUX_PLATFORM_AUTHORITY_LAUNCH"),
        (
            "signature_policy", "unsigned_local_build", "ALLOW",
            "LINUX_PLATFORM_AUTHORITY_SIGNATURE",
        ),
    ),
)
def test_platform_contract_substitution_is_rejected(
    section: str, field: str, replacement: object, code: str,
) -> None:
    path = ROOT / "native/linux/native-platform-authority-v2.json"
    value = json.loads(path.read_text(encoding="ascii"))
    value[section][field] = replacement
    with pytest.raises(L.LinuxNativeInstallAuthorityError, match=code):
        L.decode_platform_contract(L.canonical_json_bytes(value))


def _freeze(authority: L.LinuxPlatformAuthority) -> dict[str, object]:
    rows = []
    for index, (role, path) in enumerate(L.LINUX_SOURCE_ROSTER, start=1):
        rows.append({
            "path": path, "role": role,
            "sha256": format(index, "064x"), "size": index,
        })
    return {
        "platform": authority.platform_key,
        "roster_definition_sha256": L.source_roster_definition_sha256(),
        "schema": L.SOURCE_FREEZE_SCHEMA,
        "source_count": len(rows),
        "source_roster_sha256": L.source_content_sha256(rows),
        "sources": rows,
        "version": 2,
    }


def test_architecture_qualified_freezes_cannot_cross_slices() -> None:
    amd64 = L.platform_authority(platform_name="linux", machine="x86_64")
    arm64 = L.platform_authority(platform_name="linux", machine="aarch64")
    raw = L.canonical_json_bytes(_freeze(amd64))
    assert L.decode_source_freeze(raw, authority=amd64)["platform"] == (
        "linux-x86_64"
    )
    with pytest.raises(
        L.LinuxNativeInstallAuthorityError, match="LINUX_SOURCE_FREEZE_HEADER",
    ):
        L.decode_source_freeze(raw, authority=arm64)


def test_freeze_rejects_order_path_digest_and_extra_field() -> None:
    authority = L.platform_authority(platform_name="linux", machine="x86_64")
    mutations = []
    reordered = _freeze(authority)
    reordered["sources"][0], reordered["sources"][1] = (
        reordered["sources"][1], reordered["sources"][0]
    )
    reordered["source_roster_sha256"] = L.source_content_sha256(
        reordered["sources"]
    )
    mutations.append(reordered)
    escaped = _freeze(authority)
    escaped["sources"][0]["path"] = "../builder.py"
    escaped["source_roster_sha256"] = L.source_content_sha256(escaped["sources"])
    mutations.append(escaped)
    bad_digest = _freeze(authority)
    bad_digest["source_roster_sha256"] = "0" * 64
    mutations.append(bad_digest)
    extra = _freeze(authority)
    extra["sources"][0]["extra"] = True
    mutations.append(extra)
    for value in mutations:
        with pytest.raises(L.LinuxNativeInstallAuthorityError):
            L.decode_source_freeze(
                L.canonical_json_bytes(value), authority=authority,
            )


@pytest.mark.parametrize(
    ("machine", "platform_key", "suffix"),
    (
        ("x86_64", "linux-x86_64", ".cpython-312-x86_64-linux-gnu.so"),
        ("aarch64", "linux-arm64", ".cpython-312-aarch64-linux-gnu.so"),
    ),
)
@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor authority")
def test_production_contract_materializes_exact_build_and_launch_authority(
    machine: str, platform_key: str, suffix: str,
) -> None:
    contract = L.production_contract(
        ROOT, platform_name="linux", machine=machine,
    )
    assert contract["platform"] == platform_key
    assert contract["artifact_roster"][0]["artifact"].endswith(suffix)
    assert contract["launch"]["environment"] == {}
    assert contract["launch"]["receipt_fd"] == 198
    assert contract["launch"]["install_root_fd"] == 199
    assert contract["transaction_admission_blockers"] == [
        "LINUX_NATIVE_INSTALL_EFFECTS_UNAVAILABLE",
        "LINUX_NATIVE_LAUNCHER_SOURCE_UNAVAILABLE",
        "LINUX_NATIVE_SERVICE_ENTRYPOINT_UNAVAILABLE",
        "LINUX_RELEASE_PINS_UNAVAILABLE",
        "LINUX_SIGNED_RELEASE_PROVENANCE_UNOBSERVED",
    ]
    assert all(
        "-Wl,-z,relro,-z,now,-z,noexecstack" in row["link_flags"]
        for row in contract["artifact_roster"]
    )


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor authority")
def test_builder_can_render_both_linux_freezes_without_host_spoofing() -> None:
    builder = _load_builder()
    for platform_key in ("linux-x86_64", "linux-arm64"):
        raw = builder.render_linux_source_freeze_candidate(platform_key)
        value = json.loads(raw)
        assert value["platform"] == platform_key
        assert value["source_count"] == len(L.LINUX_SOURCE_ROSTER)
        assert value["source_roster_sha256"] == L.source_content_sha256(
            value["sources"]
        )
        assert hashlib.sha256(raw).hexdigest()


def test_builder_target_platform_is_candidate_only(capsys: pytest.CaptureFixture[str]) -> None:
    builder = _load_builder()
    assert builder.main(["--production-readiness", "--target-platform", "linux-arm64"]) == 2
    assert "valid only with --source-freeze-candidate" in capsys.readouterr().err


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor authority")
def test_builder_linux_readiness_uses_linux_contract_not_darwin_roster(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    monkeypatch.setattr(builder.sys, "platform", "linux")
    monkeypatch.setattr(
        builder.os, "uname",
        lambda: type("Uname", (), {"machine": "x86_64"})(),
    )
    report = builder.production_readiness()
    assert report["closure"]["linux_contract"]["platform"] == "linux-x86_64"
    assert "FIRST_PRODUCTION_PLATFORM_NOT_DARWIN" not in report["blockers"]
    assert "LINUX_NATIVE_INSTALL_EFFECTS_UNAVAILABLE" in report["blockers"]
    assert "LINUX_SOURCE_FREEZE_MANIFEST_UNAVAILABLE" in report["blockers"]
    assert report["production_build_allowed"] is False


def test_loaded_policy_never_promotes_python_diagnostics_to_install_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    readiness = {
        "schema": "plamen.native-supervisor.production-readiness.v2",
        "authority": "DIAGNOSTIC_ONLY_LOADED_PYTHON_NO_BUILD_AUTHORITY",
        "production_build_allowed": True,
        "blockers": [],
        "transaction_admission_blockers": [],
        "platform": "linux",
    }
    unsigned = dict(readiness)
    readiness["observation_sha256"] = hashlib.sha256(
        builder._canonical_json_bytes(unsigned)
    ).hexdigest()
    with pytest.raises(builder.BuildError, match="LINUX_NATIVE_INSTALL_EFFECTS_UNAVAILABLE"):
        builder._execute_native_source_install_transaction(readiness)
