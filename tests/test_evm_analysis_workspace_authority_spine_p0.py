"""Focused real-PhaseIO tests for the shared EVM workspace authority."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from artifact_ledger import read_artifact_ledger  # noqa: E402
from evm_analysis_workspace_authority import (  # noqa: E402
    capture_evm_build_root_resolver_authority,
    EVMAnalysisWorkspaceAuthorityError,
    WORKSPACE_RECEIPT_PATH,
    ensure_evm_analysis_workspace_authority,
    load_evm_analysis_workspace_authority,
    require_admitted_workspace_tool,
    workspace_public_reference,
)
from phase_io_contracts import resolve_phase_io_contract  # noqa: E402


RUN_ID = "12345678-1234-5678-9234-567812345678"


def _case(tmp_path: Path) -> tuple[dict, Path, Path, dict]:
    project = tmp_path / "project"
    scratch = tmp_path / "scratch"
    (project / "src").mkdir(parents=True)
    dependency = project / "lib" / "dep"
    dependency.mkdir(parents=True)
    scratch.mkdir()
    (project / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\n', encoding="utf-8"
    )
    (project / "src" / "A.sol").write_text(
        "contract A {\n"
        "uint value;\n"
        "function set(uint x) external { value=x; }\n"
        "}\n",
        encoding="utf-8",
    )
    (dependency / "Dependency.sol").write_text(
        "contract Dependency {}\n", encoding="utf-8"
    )
    snapshot = {
        "snapshot_digest": "2" * 64,
        "components": {
            "source_scope": {
                "digest": "1" * 64,
                "path_set_digest": "3" * 64,
                "file_count": 1,
                "byte_count": 72,
            },
            "toolchain": {"digest": "4" * 64, "runtime_entries": {}},
        },
    }
    config = {
        "pipeline": "sc",
        "mode": "core",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(project),
        "scratchpad": str(scratch),
        "_resolved_build_root": str(project),
        "_resolved_build_root_authority": (
            capture_evm_build_root_resolver_authority(project, project)
        ),
        "_resolved_compiled_dependency_roots": [str(dependency)],
    }
    return config, project, scratch, snapshot


def _publish(tmp_path: Path):
    config, project, scratch, snapshot = _case(tmp_path)
    outcome = ensure_evm_analysis_workspace_authority(
        config=config,
        scratchpad=scratch,
        project_root=project,
        run_id=RUN_ID,
        audit_snapshot=snapshot,
        implementation_root=ROOT,
    )
    assert outcome is not None
    return config, project, scratch, snapshot, outcome


def test_real_phaseio_publish_replay_and_path_free_reference(tmp_path: Path) -> None:
    config, project, scratch, snapshot, first = _publish(tmp_path)
    second = ensure_evm_analysis_workspace_authority(
        config=config,
        scratchpad=scratch,
        project_root=project,
        run_id=RUN_ID,
        audit_snapshot=snapshot,
        implementation_root=ROOT,
    )
    assert second is not None and second.reused is True
    assert second.receipt_sha256 == first.receipt_sha256
    receipt = load_evm_analysis_workspace_authority(
        scratch,
        expected_run_id=RUN_ID,
        expected_snapshot_sha256=snapshot["snapshot_digest"],
    )
    assert receipt["project_root"]["absolute_path"] == str(project)
    reference = workspace_public_reference(receipt)
    rendered = json.dumps(reference, sort_keys=True)
    assert str(project) not in rendered
    assert reference["build_root"]["rooted_alias"] == "project:."
    assert [row["tool_id"] for row in reference["tool_rows"]] == [
        "forge", "opengrep", "semgrep", "slither", "solc"
    ]
    owner = read_artifact_ledger(scratch)["work_units"][
        first.owner_work_unit_key
    ]
    assert (owner["semantic_status"], owner["execution_state"]) == (
        "ACTIVE", "OUTPUT_COMMITTED"
    )


def test_publication_crash_resumes_same_owner(tmp_path: Path) -> None:
    config, project, scratch, snapshot = _case(tmp_path)

    def crash(point: str) -> None:
        if point == "after_publish_before_commit":
            raise RuntimeError("crash")

    with pytest.raises(RuntimeError, match="crash"):
        ensure_evm_analysis_workspace_authority(
            config=config,
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            audit_snapshot=snapshot,
            implementation_root=ROOT,
            fault_injector=crash,
        )
    assert (scratch / WORKSPACE_RECEIPT_PATH).is_file()
    resumed = ensure_evm_analysis_workspace_authority(
        config=config,
        scratchpad=scratch,
        project_root=project,
        run_id=RUN_ID,
        audit_snapshot=snapshot,
        implementation_root=ROOT,
    )
    assert resumed is not None and resumed.reused is False


def test_unadmitted_rows_block_success(tmp_path: Path) -> None:
    _config, _project, scratch, _snapshot, _outcome = _publish(tmp_path)
    receipt = load_evm_analysis_workspace_authority(scratch)
    with pytest.raises(EVMAnalysisWorkspaceAuthorityError):
        require_admitted_workspace_tool(receipt, "slither")


def test_committed_load_replays_exact_manifest_bytes(tmp_path: Path) -> None:
    _config, project, scratch, _snapshot, _outcome = _publish(tmp_path)
    (project / "foundry.toml").write_text(
        '[profile.default]\nsrc = "contracts"\n', encoding="utf-8"
    )
    with pytest.raises(
        EVMAnalysisWorkspaceAuthorityError,
        match="capture changed during replay: .*manifest",
    ):
        load_evm_analysis_workspace_authority(scratch)


def test_committed_load_replays_dependency_content_bytes(tmp_path: Path) -> None:
    _config, project, scratch, _snapshot, _outcome = _publish(tmp_path)
    (project / "lib" / "dep" / "Dependency.sol").write_text(
        "contract Substituted {}\n", encoding="utf-8"
    )
    with pytest.raises(
        EVMAnalysisWorkspaceAuthorityError, match="dependency content changed"
    ):
        load_evm_analysis_workspace_authority(scratch)


def test_committed_load_rejects_identical_dependency_inode_swap(
    tmp_path: Path,
) -> None:
    _config, project, scratch, _snapshot, _outcome = _publish(tmp_path)
    dependency = project / "lib" / "dep"
    displaced = project / "lib" / "displaced"
    dependency.rename(displaced)
    dependency.mkdir()
    (dependency / "Dependency.sol").write_text(
        "contract Dependency {}\n", encoding="utf-8"
    )
    with pytest.raises(
        EVMAnalysisWorkspaceAuthorityError, match="physical identity changed"
    ):
        load_evm_analysis_workspace_authority(scratch)


def test_workspace_phaseio_is_exact_pf_predecessor(tmp_path: Path) -> None:
    _config, _project, _scratch, _snapshot = _case(tmp_path)
    workspace = resolve_phase_io_contract(
        pipeline="sc", mode="core", ecosystem="evm", backend="claude",
        phase="recon", work_unit_id="evm_analysis_workspace_capture",
        exact_inputs=(), exact_outputs=(WORKSPACE_RECEIPT_PATH,),
        exact_writer="DRIVER",
    )
    assert workspace.required_commit_actor == "DRIVER"
    assert workspace.outputs[0].write_mode == "CREATE"
    pf_inputs = (
        "_program_facts_inputs/checkpoint_capture.v1.json",
        "_program_facts_methodology/program-facts-methodology-package.v1.json",
        "_program_facts_methodology/program-facts-provider-registry.v1.json",
        "_program_facts_methodology/schemas/mechanical_program_facts.v1.schema.json",
        "_program_facts_methodology/schemas/mechanical_program_facts_receipt.v1.schema.json",
        "_program_facts_methodology/schemas/mechanical_program_facts_debt.v1.schema.json",
        "_program_facts_methodology/schemas/program_facts_provider_registry.v1.schema.json",
        "_program_facts_methodology/schemas/program_facts_disagreement.v1.schema.json",
        "_program_facts_methodology/schemas/program_facts_slice.v1.schema.json",
        WORKSPACE_RECEIPT_PATH,
    )
    pf = resolve_phase_io_contract(
        pipeline="sc", mode="core", ecosystem="evm", backend="claude",
        phase="recon", work_unit_id="program_facts_bake",
        exact_inputs=pf_inputs,
        exact_outputs=(
            "mechanical_program_facts.v1.json",
            "mechanical_program_facts_receipt.v1.json",
            "mechanical_program_facts_debt.v1.json",
        ),
        exact_writer="DRIVER",
    )
    requirement = next(
        row for row in pf.input_authority_requirements
        if row.identity.endswith(WORKSPACE_RECEIPT_PATH)
    )
    assert requirement.expected_producer_work_unit_key == workspace.key
    assert requirement.expected_contract_digest == workspace.digest


def test_build_root_symlink_is_rejected(tmp_path: Path) -> None:
    config, project, scratch, snapshot = _case(tmp_path)
    real = project / "real-build"
    real.mkdir()
    linked = project / "linked-build"
    linked.symlink_to(real, target_is_directory=True)
    config["_resolved_build_root"] = str(linked)
    with pytest.raises(
        EVMAnalysisWorkspaceAuthorityError, match="link/reparse"
    ):
        ensure_evm_analysis_workspace_authority(
            config=config,
            scratchpad=scratch,
            project_root=project,
            run_id=RUN_ID,
            audit_snapshot=snapshot,
            implementation_root=ROOT,
        )


def test_tampered_stale_and_unowned_receipts_are_rejected(tmp_path: Path) -> None:
    _config, _project, scratch, snapshot, outcome = _publish(tmp_path)
    with pytest.raises(
        EVMAnalysisWorkspaceAuthorityError, match="run_id differs"
    ):
        load_evm_analysis_workspace_authority(
            scratch, expected_run_id="87654321-4321-6789-9234-567812345678"
        )
    with pytest.raises(
        EVMAnalysisWorkspaceAuthorityError, match="owner differs"
    ):
        load_evm_analysis_workspace_authority(
            scratch,
            expected_owner_work_unit_key=(
                outcome.owner_work_unit_key.rsplit("/", 1)[0] + "/other"
            ),
        )
    path = scratch / WORKSPACE_RECEIPT_PATH
    value = json.loads(path.read_text(encoding="utf-8"))
    value["snapshot"]["snapshot_sha256"] = "9" * 64
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(
        EVMAnalysisWorkspaceAuthorityError, match="integrity failure"
    ):
        load_evm_analysis_workspace_authority(
            scratch,
            expected_snapshot_sha256=snapshot["snapshot_digest"],
        )


def test_real_recon_consumers_share_reference_and_emit_only_debt(
    tmp_path: Path,
) -> None:
    """Exercise production recon consumers in an isolated Python 3.12 child.

    The checkout-wide runtime closure is intentionally frozen and currently
    differs because this change is not allowed to regenerate it.  The child
    replaces only that import-time closure guard; workspace, PhaseIO, recon,
    graph, Forge and scanner code paths are the real production modules.
    """

    _config, project, scratch, _snapshot, outcome = _publish(tmp_path)
    probe = r'''
import json, sys, types
from pathlib import Path

guard = types.ModuleType("toolchain_control_authority")
class ToolchainControlError(RuntimeError):
    pass
guard.ToolchainControlError = ToolchainControlError
guard.load_toolchain_controls = lambda *a, **k: (_ for _ in ()).throw(
    ToolchainControlError("frozen closure intentionally unavailable")
)
sys.modules["toolchain_control_authority"] = guard

from evm_analysis_workspace_authority import load_evm_analysis_workspace_authority
from recon_prepass import _bake_evm_graph, _run_opengrep_scan, _write_build_status

scratch = Path(sys.argv[1])
project = Path(sys.argv[2])
workspace = load_evm_analysis_workspace_authority(scratch)
graph_status = _bake_evm_graph(
    scratch, project, workspace_authority=workspace
)
build_status = _write_build_status(
    scratch, project, "evm", graph_status,
    workspace_authority=workspace,
)
scan_status = _run_opengrep_scan(
    scratch, project, "evm", workspace_authority=workspace
)
graph = json.loads((scratch / "_mechanical_graph.json").read_text())
forge = json.loads((scratch / "forge_build_receipt.v1.json").read_text())
ledger = json.loads((scratch / "tool_coverage_ledger.json").read_text())
print(json.dumps({
    "graph_status": graph_status,
    "build_status": build_status,
    "scan_status": scan_status,
    "graph_reference": graph["evm_analysis_workspace"],
    "forge_reference": forge["workspace_reference"],
    "states": sorted(
        row["state"] for row in ledger["capabilities"].values()
    ),
}))
'''
    completed = subprocess.run(
        [sys.executable, "-B", "-c", probe, str(scratch), str(project)],
        cwd=ROOT,
        env={"PYTHONPATH": str(SCRIPTS)},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["graph_status"].startswith("WRITTEN:evm-source")
    assert result["build_status"] == "WRITTEN"
    assert result["scan_status"].startswith("SKIPPED:")
    assert "SUCCEEDED" not in result["states"]
    assert result["graph_reference"] == outcome.public_reference
    assert result["forge_reference"] == outcome.public_reference
    build_markdown = (scratch / "build_status.md").read_text()
    assert "DEGRADED_AUTHORITY_DEBT" in build_markdown
    assert "report_semantic_evm_workspace_toolchain.md" in {
        path.name for path in scratch.iterdir()
    }


def test_recon_selects_only_manifest_consistent_lock_without_filename_priority(
    tmp_path: Path,
) -> None:
    root = tmp_path / "dodo-shaped"
    (root / "src").mkdir(parents=True)
    (root / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\nlibs = ["node_modules", "lib"]\n',
        encoding="utf-8",
    )
    (root / "src" / "A.sol").write_text(
        "pragma solidity 0.8.26; contract A {}\n", encoding="utf-8"
    )
    (root / "package.json").write_text(
        json.dumps({
            "name": "fixture",
            "version": "1.0.0",
            "dependencies": {"a": "^1"},
            "devDependencies": {"b": "2.0.0"},
        }, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    (root / "package-lock.json").write_text(
        json.dumps({
            "name": "fixture",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": True,
            "packages": {"": {
                "name": "fixture",
                "version": "1.0.0",
                "dependencies": {"a": "^9"},
            }},
        }, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    def integrity(seed: str) -> str:
        return "sha512-" + base64.b64encode(
            hashlib.sha512(seed.encode()).digest()
        ).decode("ascii")

    (root / "yarn.lock").write_text(
        "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n"
        "# yarn lockfile v1\n\n"
        '"a@^1":\n'
        '  version "1.0.0"\n'
        '  resolved "https://registry.example.invalid/a.tgz"\n'
        f"  integrity {integrity('a')}\n\n"
        '"b@2.0.0":\n'
        '  version "2.0.0"\n'
        '  resolved "https://registry.example.invalid/b.tgz"\n'
        f"  integrity {integrity('b')}\n",
        encoding="utf-8",
    )
    probe = r'''
import json, sys, types
from pathlib import Path
guard = types.ModuleType("toolchain_control_authority")
class ToolchainControlError(RuntimeError): pass
guard.ToolchainControlError = ToolchainControlError
guard.load_toolchain_controls = lambda *a, **k: (_ for _ in ()).throw(ToolchainControlError("test"))
sys.modules["toolchain_control_authority"] = guard
from recon_prepass import _select_js_lock_authority, resolve_snapshot_build_root
root = Path(sys.argv[1])
config = {"pipeline":"sc", "language":"evm", "project_root":str(root)}
resolved = resolve_snapshot_build_root(config)
print(json.dumps({
    "decision": _select_js_lock_authority(root),
    "family": config["_resolved_js_lock_authority"]["family"],
    "resolved": str(resolved),
    "selection_sha256": config["_resolved_js_lock_authority"]["selection_sha256"],
}))
'''
    completed = subprocess.run(
        [sys.executable, "-B", "-c", probe, str(root)],
        cwd=ROOT,
        env={"PYTHONPATH": str(SCRIPTS)},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["decision"] == ["yarn", None]
    assert result["family"] == "yarn"
    assert result["resolved"] == str(root)
    assert len(result["selection_sha256"]) == 64
