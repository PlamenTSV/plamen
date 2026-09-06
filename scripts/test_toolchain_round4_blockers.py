"""Round-4 contracts for toolchain readiness and graph-provider debt.

All fixtures are local and synthetic.  They do not install providers, contact
registries, or launch an audit.
"""

from __future__ import annotations

import inspect
import json
import os
from pathlib import Path
import tarfile

import pytest

import plamen as INSTALLER
import recon_prepass as RECON
import tool_coverage_ledger as LEDGER
import toolchain_control_authority as CONTROL


_ROOT = Path(__file__).resolve().parents[1]
_LOCK = _ROOT / "verification_policy" / "toolchain_version_lock.v1.json"
_GOVERNANCE = (
    _ROOT / "verification_policy" / "toolchain_governance.v1.json"
)

_GRAPH_CAPABILITIES = {
    "slither.evm-reference-graph": "slither",
    "scip-go.reference-graph": "scip-go",
    "scip-rust.reference-graph": "rust-analyzer",
    "protobuf.scip-graph-parser": "protobuf",
}

_RUNTIME_REQUIRED_FILES = {
    "plamen.py",
    "plamen_l1/__init__.py",
    "plamen_l1/scip_pb2.py",
    "plamen_l1/scip_reader.py",
    "scripts/audit_snapshot.py",
    "scripts/enumeration_type_ir.py",
    "scripts/linux_cgroup_exec.py",
    "scripts/owned_process_runner.py",
    "scripts/owned_process_scope.py",
    "scripts/plamen_types.py",
    "scripts/program_facts_bake.py",
    "scripts/program_facts_evm_helper.py",
    "scripts/program_facts_evm_provider.py",
    "scripts/program_facts_evm_tool_authority.py",
    "scripts/program_facts_evm_wtx.py",
    "scripts/program_facts_loader.py",
    "scripts/program_facts_methodology_authority.py",
    "scripts/program_facts_provider_api.py",
    "scripts/program_facts_provider_registry.py",
    "scripts/program_facts_source_manifest.py",
    "scripts/program_facts_types.py",
    "scripts/production_source_scope.py",
    "scripts/recon_prepass.py",
    "scripts/state_symbol_authority.py",
    "scripts/supply_chain_gate.py",
    "scripts/tool_coverage_ledger.py",
    "scripts/toolchain_control_authority.py",
    "scripts/windows_low_integrity_lease.py",
    "rules/program-facts-evm-tool-manifest.v1.json",
    "rules/program-facts-provider-registry.v1.json",
    "rules/schemas/mechanical_program_facts.v1.schema.json",
    "rules/schemas/mechanical_program_facts_debt.v1.schema.json",
    "rules/schemas/mechanical_program_facts_receipt.v1.schema.json",
    "rules/schemas/program_facts_disagreement.v1.schema.json",
    "rules/schemas/program_facts_evm_slither_raw.v1.schema.json",
    "rules/schemas/program_facts_evm_tool_manifest.v1.schema.json",
    "rules/schemas/program_facts_provider_registry.v1.schema.json",
    "rules/schemas/program_facts_slice.v1.schema.json",
    "verification_policy/toolchain_governance.v1.json",
    "verification_policy/toolchain_version_lock.v1.json",
}

_PROGRAM_FACTS_STAGE2_RUNTIME_FILES = {
    "scripts/program_facts_provider_api.py",
    "scripts/program_facts_provider_registry.py",
    "scripts/program_facts_types.py",
    "scripts/program_facts_source_manifest.py",
    "scripts/program_facts_methodology_authority.py",
    "scripts/program_facts_evm_tool_authority.py",
    "scripts/program_facts_evm_helper.py",
    "scripts/program_facts_evm_wtx.py",
    "scripts/program_facts_evm_provider.py",
    "scripts/program_facts_bake.py",
    "scripts/program_facts_loader.py",
    "rules/program-facts-provider-registry.v1.json",
    "rules/program-facts-evm-tool-manifest.v1.json",
    "rules/schemas/program_facts_provider_registry.v1.schema.json",
    "rules/schemas/program_facts_evm_tool_manifest.v1.schema.json",
    "rules/schemas/program_facts_evm_slither_raw.v1.schema.json",
    "rules/schemas/mechanical_program_facts.v1.schema.json",
    "rules/schemas/mechanical_program_facts_receipt.v1.schema.json",
    "rules/schemas/mechanical_program_facts_debt.v1.schema.json",
    "rules/schemas/program_facts_disagreement.v1.schema.json",
    "rules/schemas/program_facts_slice.v1.schema.json",
}


def test_version_match_is_not_reported_as_provider_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only the identity with reviewed content may report provider authority."""
    monkeypatch.setattr(
        INSTALLER,
        "_observed_locked_command_version",
        lambda row: f"{row['identity_id']} version {row['expected_version']}",
    )
    monkeypatch.setattr(
        INSTALLER,
        "_observed_python_distribution_version",
        lambda package: {
            "slither-analyzer": "0.11.5",
            "protobuf": "7.35.1",
        }[package],
    )

    rows = INSTALLER._locked_toolchain_identity_report()
    assert rows
    for row in rows:
        assert row["identity_status"] == "MATCH"
        if row["identity_id"] == "protobuf":
            assert row["provider_authority_status"] == "MATCH"
            assert row["deterministic_provider_authority"] is True
            assert row["provider_ready"] is True
        else:
            assert row["identity_id"] in {"slither", "scip-go"}
            assert row["provider_authority_status"] == (
                "OBSERVED_NONAUTHORITATIVE"
            )
            assert row["deterministic_provider_authority"] is False
            assert row["provider_ready"] is False

    doctor_source = inspect.getsource(INSTALLER.run_doctor)
    setup_source = inspect.getsource(INSTALLER.run_setup)
    assert "provider_ready" in doctor_source
    assert "provider_ready" in setup_source


def test_graph_provider_capabilities_are_in_governed_denominator() -> None:
    governance = LEDGER.load_toolchain_governance(_GOVERNANCE)
    capabilities = {
        row["capability_id"]: row
        for row in governance["capabilities"]
    }
    assert _GRAPH_CAPABILITIES.keys() <= capabilities.keys()
    for capability_id, tool in _GRAPH_CAPABILITIES.items():
        invocations = capabilities[capability_id]["invocations"]
        assert any(tool in row["tool_ids"] for row in invocations)


def test_graph_provider_debt_is_durable_and_haltless(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / ".scratchpad"
    authority = {
        "authority_status": "OBSERVED_NONAUTHORITATIVE",
        "deterministic_provider_authority": False,
        "reason": "reviewed content digest is unavailable",
        "tool_id": "scip-go",
        "lock_sha256": "1" * 64,
        "governance_sha256": "2" * 64,
    }
    RECON._record_precise_graph_outcome(
        scratch,
        capability_id="scip-go.reference-graph",
        tool="scip-go",
        status="SKIPPED:TOOLCHAIN_AUTHORITY_DEBT:OBSERVED_NONAUTHORITATIVE",
        authority=authority,
    )

    outcomes = LEDGER.load_tool_coverage_ledger(scratch)
    outcome = outcomes["scip-go.reference-graph"]
    assert outcome.state is LEDGER.ToolOutcomeState.UNAVAILABLE
    assert "OBSERVED_NONAUTHORITATIVE" in outcome.reason
    assert json.loads(outcome.provider_ref)["authority_status"] == (
        "OBSERVED_NONAUTHORITATIVE"
    )
    assert (scratch / LEDGER.LEDGER_MARKDOWN_FILENAME).is_file()


def test_graph_success_status_cannot_override_missing_provider_authority(
    tmp_path: Path,
) -> None:
    RECON._record_precise_graph_outcome(
        tmp_path,
        capability_id="slither.evm-reference-graph",
        tool="slither",
        status="WRITTEN",
        authority={
            "authority_status": "OBSERVED_NONAUTHORITATIVE",
            "deterministic_provider_authority": False,
        },
    )
    outcome = LEDGER.load_tool_coverage_ledger(tmp_path)[
        "slither.evm-reference-graph"
    ]
    assert outcome.state is LEDGER.ToolOutcomeState.FAILED
    assert "completed without replayed deterministic authority" in outcome.reason


def test_graph_fallback_wrappers_persist_each_precise_provider_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = {
        "authority_status": "OBSERVED_NONAUTHORITATIVE",
        "deterministic_provider_authority": False,
        "reason": "reviewed content digest is unavailable",
    }
    debt = "SKIPPED:TOOLCHAIN_AUTHORITY_DEBT:OBSERVED_NONAUTHORITATIVE"
    monkeypatch.setattr(RECON, "_maybe_warn_via_ir_build", lambda _proj: None)
    monkeypatch.setattr(RECON, "_bake_evm_slither_graph", lambda *_args: debt)
    monkeypatch.setattr(RECON, "_bake_evm_source_graph", lambda *_args: "WRITTEN")
    monkeypatch.setattr(RECON, "_bake_go_scip", lambda *_args: debt)
    monkeypatch.setattr(RECON, "_bake_go_source_graph", lambda *_args: "WRITTEN")
    monkeypatch.setattr(RECON, "_bake_rust_scip", lambda *_args: debt)
    monkeypatch.setattr(RECON, "_bake_rust_source_graph", lambda *_args: "WRITTEN")
    monkeypatch.setattr(
        RECON,
        "_scip_to_graph_artifacts_impl",
        lambda *_args, **_kwargs: "FAILED:parser unavailable",
    )
    monkeypatch.setattr(
        RECON,
        "_capture_command_provider_authority",
        lambda *_args, **_kwargs: dict(authority),
    )
    monkeypatch.setattr(
        RECON,
        "_capture_python_provider_authority",
        lambda *_args, **_kwargs: dict(authority),
    )

    project = tmp_path / "project"
    project.mkdir()
    cases = (
        (
            "evm",
            "slither.evm-reference-graph",
            lambda scratch: RECON._bake_evm_graph(scratch, project),
        ),
        (
            "go",
            "scip-go.reference-graph",
            lambda scratch: RECON._bake_go_graph(scratch, project),
        ),
        (
            "rust",
            "scip-rust.reference-graph",
            lambda scratch: RECON._bake_rust_graph(scratch, project),
        ),
        (
            "protobuf",
            "protobuf.scip-graph-parser",
            lambda scratch: RECON._scip_to_graph_artifacts(
                scratch,
                project / "fixture.scip",
                project,
                ecosystem="go",
            ),
        ),
    )
    for name, capability_id, invoke in cases:
        scratch = tmp_path / name
        invoke(scratch)
        outcome = LEDGER.load_tool_coverage_ledger(scratch)[capability_id]
        assert outcome.state in {
            LEDGER.ToolOutcomeState.UNAVAILABLE,
            LEDGER.ToolOutcomeState.FAILED,
        }


@pytest.mark.parametrize(
    "function_name",
    [
        "_bake_evm_graph",
        "_bake_go_graph",
        "_bake_rust_graph",
        "_scip_to_graph_artifacts",
    ],
)
def test_each_precise_graph_path_records_a_capability_outcome(
    function_name: str,
) -> None:
    source = inspect.getsource(getattr(RECON, function_name))
    assert "_record_precise_graph_outcome" in source


def test_runtime_required_file_denominator_is_explicit_and_complete() -> None:
    required = set(CONTROL.TOOLCHAIN_RUNTIME_REQUIRED_FILES)
    assert _RUNTIME_REQUIRED_FILES <= required
    assert required == set(CONTROL.derive_runtime_dependency_closure(_ROOT))
    assert all((_ROOT / relative).is_file() for relative in required)


def test_program_facts_stage2_runtime_closure_is_required() -> None:
    required = set(CONTROL.TOOLCHAIN_RUNTIME_REQUIRED_FILES)
    assert _PROGRAM_FACTS_STAGE2_RUNTIME_FILES <= required
    assert all(
        (_ROOT / relative).is_file()
        for relative in _PROGRAM_FACTS_STAGE2_RUNTIME_FILES
    )


@pytest.mark.parametrize(
    "missing",
    sorted(_PROGRAM_FACTS_STAGE2_RUNTIME_FILES),
)
def test_doctor_detects_each_program_facts_stage2_runtime_omission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    missing: str,
) -> None:
    """Every PF runtime dependency is part of doctor's clean-package check."""
    package = tmp_path / "incomplete-package"
    missing_path = os.path.normcase(
        os.path.normpath(package / Path(missing))
    )
    real_isfile = os.path.isfile

    def fixture_isfile(path: str | os.PathLike[str]) -> bool:
        candidate = os.path.normcase(os.path.normpath(os.fspath(path)))
        try:
            in_fixture = os.path.commonpath(
                (candidate, os.path.normcase(os.path.normpath(package)))
            ) == os.path.normcase(os.path.normpath(package))
        except ValueError:
            in_fixture = False
        if in_fixture:
            return candidate != missing_path
        return real_isfile(path)

    monkeypatch.setattr(INSTALLER.os.path, "isfile", fixture_isfile)
    assert INSTALLER._toolchain_runtime_required_missing(package) == [missing]
    doctor_source = inspect.getsource(INSTALLER.run_doctor)
    assert "_doctor_runtime_integrity_issues(installed_runtime)" in doctor_source
    assert "_toolchain_runtime_required_missing(PLAMEN_HOME)" not in doctor_source


def test_doctor_uses_committed_generation_not_mutable_checkout_for_integrity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    committed = tmp_path / "committed-generation"
    checkout = tmp_path / "mutable-checkout"
    committed.mkdir()
    checkout.mkdir()
    monkeypatch.setattr(INSTALLER, "PLAMEN_HOME", os.fspath(checkout))
    receipt = {"address": committed}
    assert INSTALLER._doctor_runtime_integrity_root(receipt) == os.fspath(committed)
    assert INSTALLER._doctor_runtime_integrity_root(None) == os.fspath(checkout)
    observed = []
    monkeypatch.setattr(
        INSTALLER, "_toolchain_runtime_required_integrity_issues",
        lambda root, *, closure_root: (
            observed.append((os.fspath(root), os.fspath(closure_root)))
            or {"missing": [], "mismatched": []}
        ),
    )
    assert INSTALLER._doctor_runtime_integrity_issues(receipt) == {
        "missing": [], "mismatched": [],
    }
    assert observed == [(os.fspath(committed), os.fspath(committed))]
    helper_source = inspect.getsource(INSTALLER._doctor_runtime_integrity_root)
    assert 'installed_runtime["address"]' in helper_source


def test_public_archive_contains_runtime_required_denominator(
    tmp_path: Path,
) -> None:
    import test_public_packaging_freeze as packaging

    archive = packaging._temporary_public_archive(tmp_path)
    members = packaging._archive_members(archive)
    assert set(CONTROL.TOOLCHAIN_RUNTIME_REQUIRED_FILES) <= members


def test_extracted_archive_doctor_names_every_runtime_omission(
    tmp_path: Path,
) -> None:
    """Every generated runtime path is an exact doctor failure boundary."""

    import test_public_packaging_freeze as packaging

    archive = packaging._temporary_public_archive(tmp_path)
    extracted = tmp_path / "runtime-omission-matrix"
    extracted.mkdir()
    with tarfile.open(archive, "r") as package:
        package.extractall(extracted, filter="data")
    assert INSTALLER._toolchain_runtime_required_missing(extracted) == []

    for relative in CONTROL.TOOLCHAIN_RUNTIME_REQUIRED_FILES:
        path = extracted / relative
        content = path.read_bytes()
        path.unlink()
        assert INSTALLER._toolchain_runtime_required_missing(extracted) == [
            relative
        ]
        path.write_bytes(content)


def test_install_rejects_a_package_missing_one_runtime_required_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "incomplete-package"
    missing = "scripts/toolchain_control_authority.py"
    for relative in CONTROL.TOOLCHAIN_RUNTIME_REQUIRED_FILES:
        if relative == missing:
            continue
        path = source / Path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# fixture\n", encoding="utf-8")
    monkeypatch.setattr(INSTALLER, "PLAMEN_HOME", str(source))
    monkeypatch.setattr(
        INSTALLER,
        "CLAUDE_HOME",
        str(tmp_path / ".claude"),
    )
    with pytest.raises(RuntimeError, match="toolchain_control_authority"):
        INSTALLER._run_symlink_install(lambda *_args: None)


@pytest.mark.parametrize(
    "consumer",
    [
        INSTALLER._run_symlink_install,
        INSTALLER.run_doctor,
        INSTALLER.run_setup,
    ],
)
def test_install_lifecycle_consumes_runtime_required_denominator(
    consumer,
) -> None:
    source = inspect.getsource(consumer)
    assert (
        "TOOLCHAIN_RUNTIME_REQUIRED_FILES" in source
        or "_toolchain_runtime_required" in source
    )


def test_uninstall_consumes_receipt_owned_runtime_denominator() -> None:
    source = inspect.getsource(INSTALLER.run_uninstall)
    assert 'manifest.get("runtime_assets", [])' in source
    assert "receipt-owned runtime assets survived uninstall" in source
    assert "_toolchain_runtime_required" not in source


def _copy_controls(root: Path) -> tuple[Path, Path]:
    root.mkdir(parents=True)
    lock = root / _LOCK.name
    governance = root / _GOVERNANCE.name
    lock.write_bytes(_LOCK.read_bytes())
    governance.write_bytes(_GOVERNANCE.read_bytes())
    return lock, governance


def test_control_pair_rejects_symlinked_ancestor(tmp_path: Path) -> None:
    real = tmp_path / "real-controls"
    lock, governance = _copy_controls(real)
    alias = tmp_path / "aliased-controls"
    try:
        os.symlink(real, alias, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")

    with pytest.raises(
        CONTROL.ToolchainControlError,
        match="ancestor|symlink|junction|reparse",
    ):
        CONTROL.load_toolchain_controls(
            lock_path=alias / lock.name,
            governance_path=alias / governance.name,
        )


def test_control_pair_rejects_synthetic_reparse_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controls = tmp_path / "reparse-controls"
    lock, governance = _copy_controls(controls)
    original = CONTROL._is_reparse_point

    def synthetic_reparse(path: Path) -> bool:
        if Path(path) == controls:
            return True
        return original(Path(path))

    monkeypatch.setattr(CONTROL, "_is_reparse_point", synthetic_reparse)
    with pytest.raises(
        CONTROL.ToolchainControlError,
        match="ancestor|symlink|junction|reparse",
    ):
        CONTROL.load_toolchain_controls(
            lock_path=lock,
            governance_path=governance,
        )
