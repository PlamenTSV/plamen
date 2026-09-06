"""Adversarial fixtures for deterministic toolchain/provider authority.

These tests never install, download, or launch a real audit provider.  They
exercise only local control parsing and monkeypatched provider boundaries.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
from types import ModuleType

import pytest

import audit_snapshot as SNAP
import plamen as INSTALLER
import recon_prepass as RECON
import tool_coverage_ledger as TOOL_LEDGER


_ROOT = Path(__file__).resolve().parents[1]
_LOCK = _ROOT / "verification_policy" / "toolchain_version_lock.v1.json"
_GOVERNANCE = (
    _ROOT / "verification_policy" / "toolchain_governance.v1.json"
)


def _control_copies(tmp_path: Path) -> tuple[Path, Path]:
    lock = tmp_path / "toolchain_version_lock.v1.json"
    governance = tmp_path / "toolchain_governance.v1.json"
    lock.write_bytes(_LOCK.read_bytes())
    governance.write_bytes(_GOVERNANCE.read_bytes())
    return lock, governance


def test_lock_and_governance_must_reconcile_exactly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock, governance = _control_copies(tmp_path)
    monkeypatch.setattr(SNAP, "_TOOLCHAIN_VERSION_LOCK_PATH", lock)
    monkeypatch.setattr(SNAP, "_TOOLCHAIN_GOVERNANCE_PATH", governance)

    payload = json.loads(governance.read_text(encoding="utf-8"))
    payload["reviewed_version_lock"]["path"] = "elsewhere/unreviewed.json"
    governance.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SNAP.SnapshotInputError, match="version-lock"):
        SNAP._load_toolchain_identity_controls()

    governance.write_bytes(_GOVERNANCE.read_bytes())
    payload = json.loads(governance.read_text(encoding="utf-8"))
    scip = next(row for row in payload["tools"] if row["tool_id"] == "scip-go")
    scip["update_policy"]["version_lock_identity"] = "slither"
    governance.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SNAP.SnapshotInputError, match="exactly one"):
        SNAP._load_toolchain_identity_controls()

    governance.write_bytes(_GOVERNANCE.read_bytes())
    payload = json.loads(lock.read_text(encoding="utf-8"))
    scip = next(
        row for row in payload["identities"]
        if row["identity_id"] == "scip-go"
    )
    scip["expected_version"] = "0.2.6"
    lock.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SNAP.SnapshotInputError, match="digest"):
        SNAP._load_toolchain_identity_controls()
    with pytest.raises(
        TOOL_LEDGER.ToolCoverageLedgerError,
        match="digest",
    ):
        TOOL_LEDGER.load_toolchain_governance(governance)


def test_governance_state_and_revocation_semantics_are_machine_checked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock, governance = _control_copies(tmp_path)
    monkeypatch.setattr(SNAP, "_TOOLCHAIN_VERSION_LOCK_PATH", lock)
    monkeypatch.setattr(SNAP, "_TOOLCHAIN_GOVERNANCE_PATH", governance)

    payload = json.loads(governance.read_text(encoding="utf-8"))
    forge = next(
        row for row in payload["tools"] if row["tool_id"] == "forge"
    )
    forge["runtime_authority"] = {
        "identity_status": "MATCH",
        "deterministic_provider_authority": True,
        "mismatch_effect": "FAIL_PROVIDER_SELECTION",
    }
    governance.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SNAP.SnapshotInputError, match="governance semantics"):
        SNAP._load_toolchain_identity_controls()
    with pytest.raises(
        TOOL_LEDGER.ToolCoverageLedgerError,
        match="governance semantics",
    ):
        TOOL_LEDGER.load_toolchain_governance(governance)

    governance.write_bytes(_GOVERNANCE.read_bytes())
    payload = json.loads(governance.read_text(encoding="utf-8"))
    forge = next(
        row for row in payload["tools"] if row["tool_id"] == "forge"
    )
    forge["revocation_policy"]["blocked_executable_sha256"] = ["not-a-digest"]
    governance.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SNAP.SnapshotInputError, match="revocation"):
        SNAP._load_toolchain_identity_controls()

    governance.write_bytes(_GOVERNANCE.read_bytes())
    payload = json.loads(governance.read_text(encoding="utf-8"))
    forge = next(
        row for row in payload["tools"] if row["tool_id"] == "forge"
    )
    forge["revocation_policy"]["blocked_version_substrings"] = [""]
    governance.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SNAP.SnapshotInputError, match="revocation"):
        SNAP._load_toolchain_identity_controls()


def test_version_lock_install_spec_must_match_the_expected_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock, governance = _control_copies(tmp_path)
    lock_payload = json.loads(lock.read_text(encoding="utf-8"))
    scip = next(
        row for row in lock_payload["identities"]
        if row["identity_id"] == "scip-go"
    )
    scip["install_spec"] = (
        "github.com/scip-code/scip-go/cmd/scip-go@v0.2.6"
    )
    lock.write_text(json.dumps(lock_payload), encoding="utf-8")
    governance_payload = json.loads(
        governance.read_text(encoding="utf-8")
    )
    governance_payload["reviewed_version_lock"]["sha256"] = hashlib.sha256(
        lock.read_bytes()
    ).hexdigest()
    governance.write_text(
        json.dumps(governance_payload),
        encoding="utf-8",
    )
    monkeypatch.setattr(SNAP, "_TOOLCHAIN_VERSION_LOCK_PATH", lock)
    monkeypatch.setattr(SNAP, "_TOOLCHAIN_GOVERNANCE_PATH", governance)
    monkeypatch.setattr(INSTALLER, "_TOOLCHAIN_VERSION_LOCK_PATH", str(lock))
    monkeypatch.setattr(
        INSTALLER,
        "_TOOLCHAIN_GOVERNANCE_PATH",
        str(governance),
    )

    with pytest.raises(SNAP.SnapshotInputError, match="version-lock identity"):
        SNAP._load_toolchain_identity_controls()
    with pytest.raises(
        TOOL_LEDGER.ToolCoverageLedgerError,
        match="version-lock identity",
    ):
        TOOL_LEDGER.load_toolchain_governance(governance)
    with pytest.raises(RuntimeError, match=r"version[- ]lock identity"):
        INSTALLER._load_toolchain_version_lock()


@pytest.mark.parametrize(
    ("observed", "expected"),
    [
        ("rc=0\n0.2.7", True),
        ("rc=0\nscip-go 0.2.7", True),
        ("rc=0\nscip-go version v0.2.7", True),
        ("rc=0\n0.2.7 compatible", False),
        ("rc=0\ncompatibility 0.2.7\nscip-go 0.2.6", False),
        ("rc=0\nscip-go 0.2.6 (compatible with 0.2.7)", False),
        ("rc=0\nscip-go 0.2.7\nscip-go 0.2.7", False),
        ("rc=1\nscip-go 0.2.7", False),
    ],
)
def test_locked_version_parser_is_tool_anchored_and_unambiguous(
    observed: str,
    expected: bool,
) -> None:
    controls = SNAP._load_toolchain_identity_controls()
    assert (
        SNAP._locked_version_output_matches("scip-go", observed, controls)
        is expected
    )


def test_installer_accepts_official_bare_scip_go_version_output() -> None:
    assert (
        INSTALLER._version_identity_status("0.2.7", "0.2.7", "scip-go")
        == "MATCH"
    )
    assert (
        INSTALLER._version_identity_status(
            "0.2.7", "0.2.7 compatible", "scip-go"
        )
        == "MISMATCH"
    )


def test_runtime_executable_fingerprint_never_reuses_cross_snapshot_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "scip-go"
    first_bytes = b"A" * 128
    second_bytes = b"B" * 128
    binary.write_bytes(first_bytes)
    original_times = (binary.stat().st_atime_ns, binary.stat().st_mtime_ns)
    monkeypatch.setattr(
        SNAP.shutil,
        "which",
        lambda name: str(binary) if name in {"scip-go", "go"} else None,
    )
    monkeypatch.setattr(
        SNAP,
        "_command_version",
        lambda command: (
            b"rc=0\nscip-go 0.2.7"
            if Path(command[0]).name.startswith("scip-go")
            else (
                "rc=0\n"
                f"{binary}: go1.25.0\n"
                "\tpath\tgithub.com/scip-code/scip-go/cmd/scip-go\n"
                "\tmod\tgithub.com/scip-code/scip-go\tv0.2.7\n"
            ).encode()
        ),
    )
    first = json.loads(
        SNAP._runtime_tool_fingerprint(("scip-go", "--version"))
    )

    binary.write_bytes(second_bytes)
    os.utime(binary, ns=original_times)
    second = json.loads(
        SNAP._runtime_tool_fingerprint(("scip-go", "--version"))
    )

    assert first["executable_sha256"] == hashlib.sha256(first_bytes).hexdigest()
    assert second["executable_sha256"] == hashlib.sha256(second_bytes).hexdigest()
    assert first["executable_sha256"] != second["executable_sha256"]


def test_runtime_executable_fingerprint_bypasses_a_forged_file_hash_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "scip-go"
    actual_bytes = b"B" * 128
    stale_bytes = b"A" * 128
    binary.write_bytes(actual_bytes)
    identity = SNAP._file_identity(binary, binary.stat(), None)
    SNAP._FILE_HASH_CACHE[str(identity[0])] = (
        identity,
        (hashlib.sha256(stale_bytes).digest(), len(stale_bytes)),
    )
    monkeypatch.setattr(
        SNAP.shutil,
        "which",
        lambda name: str(binary) if name in {"scip-go", "go"} else None,
    )
    monkeypatch.setattr(
        SNAP,
        "_command_version",
        lambda command: (
            b"rc=0\nscip-go 0.2.7"
            if Path(command[0]).name.startswith("scip-go")
            else (
                "rc=0\n"
                f"{binary}: go1.25.0\n"
                "\tpath\tgithub.com/scip-code/scip-go/cmd/scip-go\n"
                "\tmod\tgithub.com/scip-code/scip-go\tv0.2.7\n"
            ).encode()
        ),
    )

    observed = json.loads(
        SNAP._runtime_tool_fingerprint(("scip-go", "--version"))
    )

    assert observed["executable_sha256"] == hashlib.sha256(
        actual_bytes
    ).hexdigest()


def test_snapshot_does_not_execute_non_authoritative_runtime_tools(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "opengrep"
    binary.write_bytes(b"content-bound debt tool")
    monkeypatch.setattr(
        SNAP,
        "RUNTIME_TOOL_COMMANDS",
        {"opengrep": ("opengrep", "--version")},
    )
    monkeypatch.setattr(
        SNAP.shutil,
        "which",
        lambda name: str(binary) if name == "opengrep" else None,
    )
    monkeypatch.setattr(
        SNAP,
        "_command_version",
        lambda _command: pytest.fail(
            "DEBT/EXTERNAL tools must not execute merely to build a snapshot"
        ),
    )
    monkeypatch.setattr(
        SNAP,
        "_runtime_python_distribution_fingerprint",
        lambda identity_id, **_kwargs: json.dumps({
            "tool_id": identity_id,
        }).encode(),
    )
    monkeypatch.setattr(
        SNAP,
        "_installed_python_packages",
        lambda: b"[]\n",
    )

    entries = dict(SNAP._fixed_runtime_tool_entries())
    identity = json.loads(entries["@runtime/tool/opengrep"])
    assert identity["identity_status"] == "DEBT"
    assert identity["deterministic_provider_authority"] is False
    assert identity["version"] == "NOT_PROBED_NONAUTHORITATIVE"
    assert identity["executable_sha256"] == hashlib.sha256(
        binary.read_bytes()
    ).hexdigest()


def test_scip_go_mismatch_never_invokes_provider_and_falls_back_visibly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    project.mkdir()
    scratch.mkdir()
    (project / "go.mod").write_text("module fixture\n", encoding="utf-8")
    (project / "main.go").write_text(
        "package main\nfunc main() {}\n", encoding="utf-8"
    )
    monkeypatch.setattr(RECON.shutil, "which", lambda _name: "present")
    monkeypatch.setattr(
        RECON,
        "_capture_command_provider_authority",
        lambda *_args, **_kwargs: {
            "authority_status": "MISMATCH",
            "deterministic_provider_authority": False,
            "reason": "reviewed version mismatch",
        },
    )
    monkeypatch.setattr(
        RECON,
        "_run_hardened",
        lambda *_args, **_kwargs: pytest.fail(
            "mismatched provider must never execute"
        ),
    )

    status = RECON._bake_go_graph(scratch, project)
    assert status.startswith("WRITTEN:go-source")
    assert "TOOLCHAIN_AUTHORITY_DEBT" in status
    assert (scratch / "_mechanical_graph.json").is_file()


def test_slither_unbound_module_never_imports_provider_and_falls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    project.mkdir()
    scratch.mkdir()
    (project / "A.sol").write_text(
        "contract A {\nfunction f() external {}\n}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        RECON,
        "_capture_python_provider_authority",
        lambda *_args, **_kwargs: {
            "authority_status": "MISMATCH",
            "deterministic_provider_authority": False,
            "reason": "distribution closure mismatch",
        },
    )

    status = RECON._bake_evm_graph(scratch, project)
    assert status.startswith("WRITTEN:evm-source")
    assert "TOOLCHAIN_AUTHORITY_DEBT" in status


def test_target_checkout_can_never_supply_runtime_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    binary = project / "scip-go"
    binary.write_bytes(b"target-controlled")
    monkeypatch.setattr(
        SNAP.shutil,
        "which",
        lambda name: str(binary) if name == "scip-go" else None,
    )

    authority = SNAP.capture_command_provider_authority(
        "scip-go",
        ("scip-go", "--version"),
        project_root=project,
    )
    assert authority["authority_status"] == "TARGET_RESOLUTION_REJECTED"
    assert authority["deterministic_provider_authority"] is False


def test_scip_go_executes_the_exact_path_whose_bytes_were_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    project.mkdir()
    scratch.mkdir()
    (project / "go.mod").write_text("module fixture\n", encoding="utf-8")
    provider = tmp_path / "trusted tools" / "scip-go.exe"
    provider.parent.mkdir()
    provider.write_bytes(b"reviewed executable")
    monkeypatch.setattr(RECON.shutil, "which", lambda _name: "present")
    monkeypatch.setattr(
        RECON,
        "_capture_command_provider_authority",
        lambda *_args, **_kwargs: {
            "authority_status": "MATCH",
            "deterministic_provider_authority": True,
            "resolved_executable": str(provider),
            "executable_sha256": hashlib.sha256(
                provider.read_bytes()
            ).hexdigest(),
        },
    )
    observed: list[list[str]] = []

    def fake_run(command, *_args, **_kwargs):
        observed.append(list(command))
        return 127, ""

    monkeypatch.setattr(RECON, "_run_hardened", fake_run)
    RECON._bake_go_scip(scratch, project)
    assert observed
    assert observed[0][0] == str(provider.resolve())


def test_protobuf_generated_marker_is_observed_not_self_attested(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = tmp_path / "scip_pb2.py"
    generated.write_text(
        "# Protobuf Python Version: 8.0.0\n", encoding="utf-8"
    )
    monkeypatch.setattr(SNAP, "_SCIP_PROTOBUF_GENERATED_PATH", generated)
    monkeypatch.setattr(
        SNAP,
        "_python_distribution_version",
        lambda _name: "7.35.1",
    )
    monkeypatch.setattr(
        SNAP,
        "_python_distribution_closure",
        lambda *_args, **_kwargs: {
            "distribution_files_sha256": "1" * 64,
            "distribution_path_set_sha256": "2" * 64,
            "distribution_file_count": 1,
            "distribution_bytes": 1,
            "module_origin": "fixture",
            "module_sha256": "3" * 64,
        },
    )
    identity = json.loads(
        SNAP._runtime_python_distribution_fingerprint("protobuf")
    )
    assert identity["generated_code_observed_version"] == "8.0.0"
    assert identity["identity_status"] == "MISMATCH"
    assert identity["deterministic_provider_authority"] is False


def test_protobuf_lock_must_name_the_generated_module_that_is_observed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock, governance = _control_copies(tmp_path)
    lock_payload = json.loads(lock.read_text(encoding="utf-8"))
    protobuf = next(
        row for row in lock_payload["identities"]
        if row["identity_id"] == "protobuf"
    )
    protobuf["generated_module_path"] = "elsewhere/unobserved_pb2.py"
    lock.write_text(json.dumps(lock_payload), encoding="utf-8")
    governance_payload = json.loads(
        governance.read_text(encoding="utf-8")
    )
    governance_payload["reviewed_version_lock"]["sha256"] = hashlib.sha256(
        lock.read_bytes()
    ).hexdigest()
    governance.write_text(
        json.dumps(governance_payload),
        encoding="utf-8",
    )
    monkeypatch.setattr(SNAP, "_TOOLCHAIN_VERSION_LOCK_PATH", lock)
    monkeypatch.setattr(SNAP, "_TOOLCHAIN_GOVERNANCE_PATH", governance)
    monkeypatch.setattr(INSTALLER, "_TOOLCHAIN_VERSION_LOCK_PATH", str(lock))
    monkeypatch.setattr(
        INSTALLER,
        "_TOOLCHAIN_GOVERNANCE_PATH",
        str(governance),
    )

    with pytest.raises(SNAP.SnapshotInputError, match="generated/runtime"):
        SNAP._load_toolchain_identity_controls()
    with pytest.raises(
        TOOL_LEDGER.ToolCoverageLedgerError,
        match="identity",
    ):
        TOOL_LEDGER.load_toolchain_governance(governance)
    with pytest.raises(RuntimeError, match="generated/runtime identity"):
        INSTALLER._load_toolchain_version_lock()


def test_every_runtime_probe_has_explicit_governance_and_unknown_is_debt() -> None:
    governance = json.loads(_GOVERNANCE.read_text(encoding="utf-8"))
    governed = {str(row["tool_id"]) for row in governance["tools"]}
    runtime_denominator = (
        set(SNAP.RUNTIME_TOOL_COMMANDS)
        | {"protobuf", "slither"}
    )
    assert governed == runtime_denominator | {
        "osv-scanner",
        "sec3-xray",
    }
    assert all(
        isinstance(row.get("runtime_authority"), dict)
        and row["runtime_authority"].get(
            "deterministic_provider_authority"
        )
        in {True, False}
        for row in governance["tools"]
    )

    expected, status, authority, *_ = SNAP._runtime_identity_policy(
        "not-registered",
        resolved_identity="C:/trusted/not-registered.exe",
        version="rc=0\nnot-registered 1.0.0",
    )
    assert expected["policy"] == "UNREGISTERED_DEBT"
    assert status == "UNREGISTERED"
    assert authority is False


def test_setup_treats_wrong_locked_versions_as_repair_candidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        INSTALLER,
        "_locked_identity_is_current",
        lambda identity_id, **_kwargs: identity_id == "protobuf",
    )
    assert INSTALLER._slither_is_current() is False
    assert INSTALLER._scip_go_is_current() is False
    assert INSTALLER._protobuf_runtime_is_current() is True


def test_slither_setup_identity_is_the_imported_distribution_not_cli_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[str] = []

    def locked(identity_id: str, **_kwargs) -> bool:
        observed.append(identity_id)
        return True

    monkeypatch.setattr(INSTALLER, "_locked_identity_is_current", locked)
    monkeypatch.setattr(
        INSTALLER,
        "_find_bin",
        lambda *_args, **_kwargs: pytest.fail(
            "the Python Slither provider must not be authorized by a CLI path"
        ),
    )

    assert INSTALLER._slither_is_current() is True
    assert observed == ["slither"]
    assert (
        INSTALLER._locked_toolchain_identity("slither")["identity_kind"]
        == "python_distribution"
    )


def test_slither_recon_consumes_python_module_authority_not_cli_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    project.mkdir()
    scratch.mkdir()
    module_path = tmp_path / "trusted" / "slither" / "__init__.py"
    module_path.parent.mkdir(parents=True)
    module_path.write_text("# fixture\n", encoding="utf-8")
    module = ModuleType("slither")
    module.__file__ = str(module_path)
    module.Slither = object
    monkeypatch.setitem(sys.modules, "slither", module)
    observed: list[str] = []

    def python_authority(identity_id: str, **_kwargs):
        observed.append(identity_id)
        return {
            "authority_status": "MATCH",
            "deterministic_provider_authority": True,
            "module_origin": str(module_path),
        }

    monkeypatch.setattr(
        RECON,
        "_capture_python_provider_authority",
        python_authority,
    )
    monkeypatch.setattr(
        RECON,
        "_capture_command_provider_authority",
        lambda *_args, **_kwargs: pytest.fail(
            "Slither's imported module must not consume CLI authority"
        ),
    )

    assert RECON._bake_evm_slither_graph(
        scratch, project
    ) == "SKIPPED:no .sol sources"
    assert observed == ["slither"]


def test_same_version_setup_repairs_protobuf_from_exact_requirements(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for module_name in (
        "rich",
        "InquirerPy",
        "sentence_transformers",
        "chromadb",
    ):
        monkeypatch.setitem(sys.modules, module_name, ModuleType(module_name))
    (tmp_path / "requirements-runtime-full.lock").write_text(
        "protobuf==7.35.1\n",
        encoding="utf-8",
    )
    for relative in (
        "custom-mcp/solana-fender/solana_fender_mcp",
        "custom-mcp/slither-mcp/slither_mcp",
        "custom-mcp/unified-vuln-db/unified_vuln",
        "custom-mcp/farofino-mcp/farofino_mcp",
    ):
        (tmp_path / relative).mkdir(parents=True)
    monkeypatch.setattr(INSTALLER, "PLAMEN_HOME", str(tmp_path))
    monkeypatch.setattr(INSTALLER, "_installed_version", lambda: INSTALLER.VERSION)
    monkeypatch.setattr(
        INSTALLER,
        "_python_dependency_stamp_status",
        lambda _digest, **_kwargs: "VALID",
    )
    monkeypatch.setattr(
        INSTALLER,
        "_python_dependency_exact_probe",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(INSTALLER, "_installed_runtime_bundle_sha256", lambda: "same")
    monkeypatch.setattr(INSTALLER, "_toolchain_runtime_bundle_sha256", lambda _root: "same")
    compatibility = iter((False, True))
    monkeypatch.setattr(
        INSTALLER,
        "_protobuf_runtime_is_current",
        lambda: next(compatibility),
    )
    monkeypatch.setattr(
        INSTALLER,
        "_python_bin",
        lambda: "python-fixture",
    )
    monkeypatch.setattr(
        INSTALLER,
        "_pip_install_args",
        lambda: ["python-fixture", "-m", "pip", "install"],
    )
    monkeypatch.setattr(
        INSTALLER,
        "_write_python_dependency_stamp",
        lambda _digest, **_kwargs: None,
    )
    commands: list[str] = []
    monkeypatch.setattr(
        INSTALLER,
        "_run_install_cmd",
        lambda command, **_kwargs: commands.append(command) is None or True,
    )
    monkeypatch.setattr(
        INSTALLER.subprocess,
        "run",
        lambda *_args, **_kwargs: INSTALLER.subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        ),
    )

    assert INSTALLER._setup_python_deps(lambda _text: None) is True
    assert len(commands) == 1
    assert "requirements-runtime-full.lock" in commands[0]
    assert "protobuf==7.35.1" in (
        tmp_path / "requirements-runtime-full.lock"
    ).read_text(encoding="utf-8")


def test_windows_slither_setup_never_bypasses_the_hash_locked_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(INSTALLER.sys, "platform", "win32")
    monkeypatch.setattr(
        INSTALLER,
        "_pip_install_args",
        lambda: [
            r"C:\Program Files\Python\python.exe",
            "-m",
            "pip",
            "install",
        ],
    )
    assert INSTALLER._slither_cmds() == []
