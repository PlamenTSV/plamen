"""Real-ledger adversarial tests for the Program Facts v2 authority spine."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from artifact_ledger import read_artifact_ledger, record_work_unit_artifacts, record_work_unit_inputs  # noqa: E402
import evm_analysis_workspace_authority as evm_workspace  # noqa: E402
from evm_analysis_workspace_authority import ensure_evm_analysis_workspace_authority, load_committed_evm_analysis_projection, load_evm_analysis_workspace_authority, require_admitted_workspace_tool, workspace_public_reference  # noqa: E402
from js_lock_authority import select_js_lock_authority  # noqa: E402
from phase_io_contracts import ArtifactSpec, LaunchSpec, PhaseIOContract, replay_phase_io_authority_pair, resolve_phase_io_contract, resolve_program_facts_registered_launch  # noqa: E402
from program_facts_types import ProgramFactsTypeError, canonical_file_bytes, canonical_json_bytes, strict_json_loads  # noqa: E402
from program_facts_workspace_v2 import PROGRAM_FACTS_V2_ACTIVATION_AUTHORITY_PATH, PROGRAM_FACTS_V2_WORKER_OUTPUT_PATH, V2_ARTIFACT_IDENTITIES, compose_workspace_bound_program_facts_v2, validate_workspace_bound_program_facts_v2, workspace_program_facts_v2_decision  # noqa: E402
from program_facts_v2_driver_integration import PROGRAM_FACTS_V2_AUTHORITY_CAPTURE_PATH, ProgramFactsV2DriverIntegrationError, ensure_program_facts_v2_workspace_bound  # noqa: E402
from test_support.program_facts_r2_1_b0_red_support import body_digest, linux_environment_document, linux_permit_document  # noqa: E402

RUN_ID = "12345678-1234-5678-9234-567812345678"
GENERATION = 7
WORK_PLAN_DIGEST = "1" * 64


def _sha(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _signed(unsigned: dict, digest_field: str) -> dict:
    return {**unsigned, digest_field: _sha(unsigned)}


def _commit_test_projection(
    *,
    project: Path,
    projection: Path,
    scratch: Path,
    snapshot: dict,
    config: dict,
) -> object:
    """Issue the fixture capability through real PhaseIO/ledger replay.

    The native custodian is intentionally represented by deterministic fixture
    receipt bytes, but the opaque authority consumed by production is never
    constructed or registered by the test.  Only the production committed
    loader may issue it after validating the snapshot and ArtifactLedger.
    """

    build_record = evm_workspace._directory_record(
        projection, rooted_alias="projection:."
    )
    workspace = evm_workspace._dependency_content_closure(
        projection, rooted_alias="projection:.", expected_root=build_record
    )
    source = evm_workspace._dependency_content_closure(
        projection,
        rooted_alias="projection-source:.",
        expected_root=build_record,
        excluded_top_level=frozenset({"node_modules"}),
    )
    modules_root = projection / "node_modules"
    modules_record = evm_workspace._directory_record(
        modules_root, rooted_alias="projection:node_modules"
    )
    modules = evm_workspace._dependency_content_closure(
        modules_root,
        rooted_alias="projection:node_modules",
        expected_root=modules_record,
    )
    selection = select_js_lock_authority(
        (projection / "package.json").read_bytes(),
        {"yarn.lock": (projection / "yarn.lock").read_bytes()},
    )
    unsigned = {
        "analysis_workspace_bytes": workspace["byte_count"],
        "analysis_workspace_closure_sha256": workspace["closure_sha256"],
        "analysis_workspace_directory_count": workspace["directory_count"],
        "analysis_workspace_file_count": workspace["file_count"],
        "component_kind": evm_workspace.ANALYSIS_PROJECTION_COMPONENT_KIND,
        "dependency_materialization_receipt_sha256": "6" * 64,
        "guest_mount_identity_sha256": "7" * 64,
        "guest_mount_path": "/workspace/project",
        "host_descriptor_identity_sha256": build_record["descriptor_sha256"],
        "invocation_sha256": "8" * 64,
        "js_lock_selection_sha256": selection.selection_sha256,
        "materialized_node_modules_bytes": modules["byte_count"],
        "materialized_node_modules_closure_sha256": modules["closure_sha256"],
        "materialized_node_modules_directory_count": modules["directory_count"],
        "materialized_node_modules_file_count": modules["file_count"],
        "native_projection_custody_sha256": "9" * 64,
        "original_source_scope_sha256": snapshot["components"]["source_scope"]["digest"],
        "project_read_only": True,
        "receipt_byte_count": 0,
        "schema": evm_workspace.ANALYSIS_PROJECTION_SCHEMA,
        "source_copy_bytes": source["byte_count"],
        "source_copy_closure_sha256": source["closure_sha256"],
        "source_copy_directory_count": source["directory_count"],
        "source_copy_file_count": source["file_count"],
        "writable_mounts": ["/workspace/scratch", "/workspace/state"],
    }
    while True:
        receipt = {**unsigned, "receipt_sha256": _sha(unsigned)}
        size = len(canonical_json_bytes(receipt))
        if unsigned["receipt_byte_count"] == size:
            break
        unsigned["receipt_byte_count"] = size
    component_unsigned = {
        "kind": evm_workspace.ANALYSIS_PROJECTION_COMPONENT_KIND,
        "receipt_sha256": receipt["receipt_sha256"],
        "receipt_byte_count": receipt["receipt_byte_count"],
        "original_source_scope_sha256": receipt["original_source_scope_sha256"],
        "source_copy_closure_sha256": receipt["source_copy_closure_sha256"],
        "js_lock_selection_sha256": receipt["js_lock_selection_sha256"],
        "dependency_materialization_receipt_sha256": receipt["dependency_materialization_receipt_sha256"],
        "materialized_node_modules_closure_sha256": receipt["materialized_node_modules_closure_sha256"],
        "analysis_workspace_closure_sha256": receipt["analysis_workspace_closure_sha256"],
        "native_projection_custody_sha256": receipt["native_projection_custody_sha256"],
    }
    snapshot["components"]["evm_analysis_projection"] = {
        **component_unsigned,
        "digest": _sha(component_unsigned),
    }

    contract, launch = evm_workspace._projection_contract_and_launch(config)
    record_work_unit_inputs(scratch, project, contract, launch, run_id=RUN_ID)
    raw = canonical_json_bytes(receipt)
    path = scratch / evm_workspace.ANALYSIS_PROJECTION_RECEIPT_PATH
    path.write_bytes(raw)
    record_work_unit_artifacts(
        scratch,
        project,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
        expected_output_records={
            contract.outputs[0].identity: {
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
            }
        },
    )
    return load_committed_evm_analysis_projection(
        scratch,
        project_root=project,
        run_id=RUN_ID,
        audit_snapshot=snapshot,
        config=config,
    )


def _published_workspace(tmp_path: Path, *, admit_pf_tools: bool = True) -> tuple[dict, dict]:
    project, scratch = tmp_path / "project", tmp_path / "scratch"
    (project / "src").mkdir(parents=True)
    scratch.mkdir()
    (project / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n', encoding="utf-8")
    (project / "src" / "A.sol").write_text("contract A { function f() external {} }\n", encoding="utf-8")
    implementation_root, admitted, runtime_entries = ROOT, {}, {}
    if admit_pf_tools:
        implementation_root = tmp_path / "implementation"
        policy = implementation_root / "verification_policy"
        policy.mkdir(parents=True)
        governance = json.loads((ROOT / "verification_policy" / "toolchain_governance.v1.json").read_text())
        for row in governance["tools"]:
            if row["tool_id"] in {"slither", "solc"}:
                row["runtime_authority"] = {"identity_status": "REVIEWED_EXACT_CONTENT", "deterministic_provider_authority": True, "mismatch_effect": "UNADMITTED"}
        governance_raw = json.dumps(governance, sort_keys=True, separators=(",", ":")) + "\n"
        (policy / "toolchain_governance.v1.json").write_text(governance_raw)
        shutil.copyfile(ROOT / "verification_policy" / "toolchain_version_lock.v1.json", policy / "toolchain_version_lock.v1.json")
        governance_sha = hashlib.sha256(governance_raw.encode()).hexdigest()
        lock_sha = hashlib.sha256((policy / "toolchain_version_lock.v1.json").read_bytes()).hexdigest()
        for tool_id in ("slither", "solc"):
            executable = Path(sys.executable).resolve()
            executable_raw = executable.read_bytes()
            unsigned = {"tool_id": tool_id, "deterministic_provider_authority": True, "identity_kind": "command", "resolved_executable": str(executable), "executable_sha256": hashlib.sha256(executable_raw).hexdigest(), "executable_bytes": len(executable_raw), "toolchain_governance_sha256": governance_sha, "toolchain_version_lock_sha256": lock_sha}
            admitted[tool_id] = {**unsigned, "authority_digest": _sha(unsigned)}
            frozen = canonical_json_bytes(unsigned)
            runtime_entries[f"@runtime/tool/{tool_id}"] = {"sha256": hashlib.sha256(frozen).hexdigest(), "byte_count": len(frozen)}
    snapshot = {"snapshot_digest": "2" * 64, "components": {"source_scope": {"digest": "1" * 64, "path_set_digest": "3" * 64, "file_count": 1, "byte_count": 42}, "toolchain": {"digest": "4" * 64, "runtime_entries": runtime_entries}}}
    projection = tmp_path / "private-projection"
    (projection / "src").mkdir(parents=True)
    shutil.copyfile(project / "foundry.toml", projection / "foundry.toml")
    shutil.copyfile(project / "src" / "A.sol", projection / "src" / "A.sol")
    package = canonical_file_bytes({"name": "program-facts-fixture", "version": "1.0.0", "dependencies": {"a": "^1"}})
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(b"a").digest()).decode()
    yarn = (
        "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n"
        "# yarn lockfile v1\n\n"
        '"a@^1":\n'
        '  version "1.0.0"\n'
        '  resolved "https://registry.example.invalid/a.tgz"\n'
        f"  integrity {integrity}\n"
    ).encode()
    (projection / "package.json").write_bytes(package)
    (projection / "yarn.lock").write_bytes(yarn)
    module = projection / "node_modules" / "a"
    module.mkdir(parents=True)
    (module / "package.json").write_bytes(
        canonical_file_bytes({"name": "a", "version": "1.0.0"})
    )
    preparation = {
        "schema_version": "plamen.evm_input_preparation.v1",
        "status": "PREPARED",
        "reason": "test projection committed through PhaseIO replay",
    }
    config = {"pipeline": "sc", "mode": "core", "language": "evm", "cli_backend": "claude", "project_root": str(project), "scratchpad": str(scratch), "_resolved_build_root": str(projection), "_snapshot_input_preparation": {**preparation, "preparation_sha256": _sha(preparation)}}
    config["_committed_evm_analysis_projection"] = _commit_test_projection(
        project=project,
        projection=projection,
        scratch=scratch,
        snapshot=snapshot,
        config=config,
    )
    outcome = ensure_evm_analysis_workspace_authority(config=config, scratchpad=scratch, project_root=project, run_id=RUN_ID, audit_snapshot=snapshot, implementation_root=implementation_root, admitted_tool_authorities=admitted)
    assert outcome is not None
    workspace = load_evm_analysis_workspace_authority(scratch, expected_run_id=RUN_ID, expected_snapshot_sha256=snapshot["snapshot_digest"], expected_owner_work_unit_key=outcome.owner_work_unit_key)
    return workspace, {"snapshot_sha256": snapshot["snapshot_digest"], "owner_work_unit_key": outcome.owner_work_unit_key, "scratchpad": scratch, "project_root": project, "config": config}


def _contract(context: dict, unit: str, path: str, actor: str) -> tuple[PhaseIOContract, LaunchSpec]:
    prefix = context["owner_work_unit_key"].split("/")[:4]
    contract = resolve_phase_io_contract(
        pipeline=prefix[0], mode=prefix[1], ecosystem=prefix[2],
        backend=prefix[3], phase="recon", work_unit_id=unit,
        exact_inputs=("evm_analysis_workspace_receipt.v1.json",),
        exact_outputs=(path,), exact_writer=actor,
    )
    launch = resolve_program_facts_registered_launch(contract)
    return contract, launch


def _activation_bundle(*, denied: bool = False) -> dict:
    environment = linux_environment_document()
    package = _signed({"schema_version": "plamen.program_facts_provider_package_authority.v1", "run_id": RUN_ID, "provider_id": "evm.slither.typed"}, "provider_package_digest")
    native = _signed({"schema_version": "plamen.program_facts_native_host_authority.v1", "run_id": RUN_ID}, "native_host_receipt_digest")
    composition = _signed({"schema_version": "plamen.program_facts_composition_authority.v1", "run_id": RUN_ID, "execution_authority_digest": WORK_PLAN_DIGEST}, "composition_authority_digest")
    methodology = _signed({"schema_version": "plamen.program_facts_methodology_package.v2", "run_id": RUN_ID, "execution_authority_digest": WORK_PLAN_DIGEST, "composition_authority_digest": composition["composition_authority_digest"]}, "methodology_package_digest")
    issuer = _signed({"schema_version": "plamen.program_facts_issuer_policy.v1", "issuer_id": "fixture-release-authority", "release_id": "fixture-release"}, "issuer_policy_digest")
    decision = _signed({"schema_version": "plamen.program_facts_activation_decision.v1", "run_id": RUN_ID, "decision": "DENIED" if denied else "PERMITTED"}, "activation_decision_digest")
    targets = {"B": WORK_PLAN_DIGEST, "C": composition["composition_authority_digest"], "NATIVE_HOST": native["native_host_receipt_digest"], "PACKAGE": package["provider_package_digest"]}
    reviews = [_signed({"schema_version": "plamen.program_facts_independent_review.v1", "role": role, "candidate_digest": target}, "review_sha256") for role, target in targets.items()]
    if denied:
        permit = {"state": "ABSENT_DENIED", "reason": "ACTIVATION_POLICY_DENIED"}
    else:
        permit = linux_permit_document(run_id=RUN_ID, run_generation=GENERATION)
        permit.update({"execution_authority_digest": WORK_PLAN_DIGEST, "composition_authority_digest": composition["composition_authority_digest"], "methodology_package_digest": methodology["methodology_package_digest"], "provider_environment_digest": environment["environment_digest"], "provider_package_digest": package["provider_package_digest"], "native_host_receipt_digest": native["native_host_receipt_digest"], "independent_review_receipts": [{"role": row["role"], "sha256": row["review_sha256"]} for row in reviews], "issuer_policy_digest": issuer["issuer_policy_digest"], "issuer_id": issuer["issuer_id"], "release_id": issuer["release_id"], "activation_decision_digest": decision["activation_decision_digest"]})
        permit["permit_digest"] = body_digest(permit, "permit_digest")
    unsigned = {"schema_version": "plamen.program_facts_v2_activation_authority.v1", "run_id": RUN_ID, "run_generation": GENERATION, "provider_environment": environment, "provider_package_authority": package, "native_host_authority": native, "composition_authority": composition, "methodology_authority": methodology, "issuer_policy_authority": issuer, "activation_decision_authority": decision, "independent_reviews": reviews, "activation_permit": permit}
    return {**unsigned, "activation_authority_sha256": _sha(unsigned)}


def _public_authority(workspace: dict, output: dict, activation: dict) -> dict:
    ref, permit = workspace_public_reference(workspace), activation["activation_permit"]
    cells = sorted([[row["capability_id"], row["build_variant_id"]] for row in output["internal_cells"]])
    return {"execution_authority_digest": WORK_PLAN_DIGEST, "composition_authority_digest": activation["composition_authority"]["composition_authority_digest"], "methodology_package_digest": activation["methodology_authority"]["methodology_package_digest"], "activation_decision_digest": activation["activation_decision_authority"]["activation_decision_digest"], "activation_permit_digest": _sha(permit) if permit.get("state") == "ABSENT_DENIED" else permit["permit_digest"], "build_input_snapshot_digest": ref["snapshot_sha256"], "candidate_universe_digest": _sha({"workspace_receipt_sha256": ref["receipt_sha256"], "provider_id": "evm.slither.typed"}), "selected_scope_digest": _sha(output["analysis_scope"]), "capability_selection_digest": _sha(cells), "build_plan_digest": _sha({"build_variant_sha256": ref["build_variant_sha256"], "dependency_closure_sha256": ref["dependency_closure_sha256"]}), "execution_set_digest": _sha(output["provider_executions"])}


def _worker_output(workspace: dict, activation: dict, *, edge_override: dict | None = None) -> dict:
    ref = workspace_public_reference(workspace)
    slither, solc = require_admitted_workspace_tool(workspace, "slither"), require_admitted_workspace_tool(workspace, "solc")
    capability, variant = "evm-callgraph-v1", "variant-a"
    execution = {"provider_id": "evm.slither.typed", "build_variant_id": variant, "capability_id": capability, "request_digest": "3" * 64, "request_size": 1, "environment_digest": "4" * 64, "raw_cas": {"namespace": "program-facts-raw-v2", "digest": "5" * 64, "size": 1}, "execution_set_row_digest": "6" * 64, "workspace_receipt_sha256": ref["receipt_sha256"], "slither_tool_row_sha256": slither["tool_row_sha256"], "solc_tool_row_sha256": solc["tool_row_sha256"], "build_variant_sha256": ref["build_variant_sha256"], "dependency_closure_sha256": ref["dependency_closure_sha256"]}
    execution.update(edge_override or {})
    fact = {"fact_id": "PFV2F-a", "capability_id": capability, "relation_kind": "CALLS", "subject_id": "function:A.f", "object_id": "function:B.g", "precision": "MAY"}
    denied = activation["activation_permit"].get("state") == "ABSENT_DENIED"
    output = {"schema_version": "plamen.program_facts_v2_worker_output.v1", "run_id": RUN_ID, "run_generation": GENERATION, "workspace_reference": ref, "authority_bindings": {}, "analysis_scope": {"claim": "EXACT_SELECTED_SCOPE_NOT_PROJECT_COMPLETE", "selected_candidate_ids": [variant]}, "coverage": [{"capability_id": capability, "build_variant_id": variant, "status": "UNAVAILABLE" if denied else "WRITTEN", "unresolved_debt_ids": []}], "provider_executions": [execution], "internal_cells": [{"capability_id": capability, "build_variant_id": variant, "internal_state": "DENIED" if denied else "COMPLETE", "public_status": "UNAVAILABLE" if denied else "WRITTEN"}], "public_projection_policy_digest": "7" * 64, "facts": [] if denied else [{**fact, "fact_sha256": _sha(fact)}], "debt": []}
    output["authority_bindings"] = _public_authority(workspace, output, activation)
    output["worker_output_sha256"] = _sha(output)
    return output


def _write_json(path: Path, value: dict) -> bytes:
    raw = canonical_file_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return raw


def _commit_activation(context: dict, activation: dict) -> None:
    contract, launch = _contract(context, "program_facts_v2_activation_authority", PROGRAM_FACTS_V2_ACTIVATION_AUTHORITY_PATH, "DRIVER")
    record_work_unit_inputs(context["scratchpad"], context["project_root"], contract, launch, run_id=RUN_ID)
    raw = _write_json(context["scratchpad"] / PROGRAM_FACTS_V2_ACTIVATION_AUTHORITY_PATH, activation)
    record_work_unit_artifacts(context["scratchpad"], context["project_root"], contract, launch, run_id=RUN_ID, actor="DRIVER", expected_output_records={contract.outputs[0].identity: {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}})


def _commit_worker(context: dict, output: dict) -> dict:
    contract, launch = _contract(context, "program_facts_provider", PROGRAM_FACTS_V2_WORKER_OUTPUT_PATH, "MODEL")
    record_work_unit_inputs(context["scratchpad"], context["project_root"], contract, launch, run_id=RUN_ID)
    raw = _write_json(context["scratchpad"] / PROGRAM_FACTS_V2_WORKER_OUTPUT_PATH, output)
    wtx = context["scratchpad"] / "_wtx_pf"
    provider_unsigned = {"output_source_mode": "STDOUT_ASSIGNED_OUTPUT"}
    provider = {
        **provider_unsigned,
        "completion_sha256": hashlib.sha256(
            canonical_json_bytes(provider_unsigned) + b"\n"
        ).hexdigest(),
    }
    _write_json(wtx / "provider.json", provider)
    common = {"run_id": RUN_ID, "phase": "recon", "work_unit_id": "program_facts_provider", "generation": GENERATION, "work_plan_digest": WORK_PLAN_DIGEST, "attempt_id": "attempt-a"}
    attempt_unsigned = {**common, "provider_completion_relative_path": "_wtx_pf/provider.json", "provider_completion_digest": provider["completion_sha256"], "canonical_projection_state": "PENDING_PHASE_IO"}
    attempt = _signed(attempt_unsigned, "completion_digest")
    _write_json(wtx / "attempt.json", attempt)
    incorporation_unsigned = {"schema": "plamen.worker_phaseio_incorporation.v1", **common, "provider_completion_digest": attempt["provider_completion_digest"], "contract_digest": contract.digest, "launch_digest": launch.digest, "projection_state": "COMPLETE", "projected_members": [{"canonical_identity": contract.outputs[0].identity, "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}]}
    incorporation = _signed(incorporation_unsigned, "incorporation_digest")
    _write_json(wtx / "incorporation.json", incorporation)
    authority_unsigned = {"schema": "plamen.worker_execution_authority.v1", **common, "attempt_completion_relative_path": "_wtx_pf/attempt.json", "attempt_completion_digest": attempt["completion_digest"], "provider_completion_relative_path": "_wtx_pf/provider.json", "provider_completion_digest": attempt["provider_completion_digest"], "incorporation_relative_path": "_wtx_pf/incorporation.json", "incorporation_digest": incorporation["incorporation_digest"], "contract_digest": contract.digest, "launch_digest": launch.digest}
    authority = _signed(authority_unsigned, "authority_digest")
    unit = record_work_unit_artifacts(context["scratchpad"], context["project_root"], contract, launch, run_id=RUN_ID, actor="MODEL", execution_authority=authority)
    assert unit["semantic_status"] == "ACTIVE"
    return authority


def _committed_fixture(tmp_path: Path, *, denied: bool = False, edge_override: dict | None = None):
    workspace, context = _published_workspace(tmp_path)
    activation = _activation_bundle(denied=denied)
    _commit_activation(context, activation)
    output = _worker_output(workspace, activation, edge_override=edge_override)
    authority = _commit_worker(context, output)
    return workspace, context, activation, output, authority


def _compose(context: dict) -> dict:
    return compose_workspace_bound_program_facts_v2(workspace_scratchpad=context["scratchpad"], project_root=context["project_root"], expected_run_id=RUN_ID, expected_snapshot_sha256=context["snapshot_sha256"], expected_owner_work_unit_key=context["owner_work_unit_key"])


def _ensure(context: dict):
    return ensure_program_facts_v2_workspace_bound(config=context["config"], scratchpad=context["scratchpad"], project_root=context["project_root"], run_id=RUN_ID, audit_snapshot_digest=context["snapshot_sha256"])


def test_unadmitted_workspace_yields_typed_nonterminal_debt(tmp_path: Path) -> None:
    _, context = _published_workspace(tmp_path, admit_pf_tools=False)
    decision = workspace_program_facts_v2_decision(context["scratchpad"], expected_run_id=RUN_ID, expected_snapshot_sha256=context["snapshot_sha256"], expected_owner_work_unit_key=context["owner_work_unit_key"])
    assert decision["state"] == "TYPED_DEBT"
    assert {row["tool_id"] for row in decision["debt"]} == {"slither", "solc"}
    assert all(row["terminal_negative_authority"] is False for row in decision["debt"])


def test_projection_capability_is_opaque_and_same_run_bound(tmp_path: Path) -> None:
    _, context = _published_workspace(tmp_path)
    authority = context["config"]["_committed_evm_analysis_projection"]
    assert isinstance(authority, evm_workspace.CommittedEVMAnalysisProjection)
    projection_unit = read_artifact_ledger(context["scratchpad"])["work_units"][
        authority.owner_work_unit_key
    ]
    assert projection_unit["semantic_status"] == "ACTIVE"
    with pytest.raises(TypeError, match="issued only by committed"):
        evm_workspace.CommittedEVMAnalysisProjection()
    with pytest.raises(
        evm_workspace.EVMAnalysisWorkspaceAuthorityError,
        match="committed PhaseIO lineage",
    ):
        load_committed_evm_analysis_projection(
            context["scratchpad"],
            project_root=context["project_root"],
            run_id="87654321-4321-6789-a234-876543210987",
            audit_snapshot={
                "snapshot_digest": context["snapshot_sha256"],
                "components": {
                    "source_scope": {
                        "digest": "1" * 64,
                    },
                    "evm_analysis_projection": dict(authority.component),
                },
            },
            config=context["config"],
        )


def test_missing_committed_wtx_is_typed_debt_not_success(tmp_path: Path) -> None:
    _, context = _published_workspace(tmp_path)
    outcome = _ensure(context)
    assert (outcome.state, outcome.valid) == ("TYPED_DEBT", False)
    assert "COMMITTED_AUTHORITY_MISSING" in outcome.reason_code


def test_caller_invented_hashes_are_not_an_api(tmp_path: Path) -> None:
    _, context = _published_workspace(tmp_path)
    with pytest.raises(TypeError):
        compose_workspace_bound_program_facts_v2(workspace_scratchpad=context["scratchpad"], project_root=context["project_root"], expected_run_id=RUN_ID, expected_snapshot_sha256=context["snapshot_sha256"], expected_owner_work_unit_key=context["owner_work_unit_key"], worker_transaction_receipt_sha256="a" * 64, activation_permit_sha256="b" * 64)


def test_committed_authorities_mint_documented_trio(tmp_path: Path) -> None:
    workspace, context, _, _, authority = _committed_fixture(tmp_path)
    candidate = _compose(context)
    assert candidate["execution_authority"]["worker_execution_authority_sha256"] == authority["authority_digest"]
    assert candidate["execution_authority"]["execution_authority_digest"] == WORK_PLAN_DIGEST
    assert tuple(identity for identity, _ in candidate["artifacts"]) == V2_ARTIFACT_IDENTITIES
    docs = [strict_json_loads(raw, require_final_lf=True) for _, raw in candidate["artifacts"]]
    assert len(docs[1]) == 9 and len(docs[1]["authority_bindings"]) == 11
    assert docs[0]["authority_bindings"] == docs[1]["authority_bindings"] == docs[2]["authority_bindings"]
    assert candidate["workspace_reference"] == workspace_public_reference(workspace)
    assert validate_workspace_bound_program_facts_v2(candidate, workspace_scratchpad=context["scratchpad"], project_root=context["project_root"], expected_run_id=RUN_ID, expected_snapshot_sha256=context["snapshot_sha256"], expected_owner_work_unit_key=context["owner_work_unit_key"]) == candidate


def test_resigned_wrong_review_parent_cannot_mint(tmp_path: Path) -> None:
    workspace, context = _published_workspace(tmp_path)
    activation = _activation_bundle()
    review = activation["independent_reviews"][0]
    review["candidate_digest"] = "f" * 64
    review["review_sha256"] = _sha({k: v for k, v in review.items() if k != "review_sha256"})
    activation["activation_authority_sha256"] = _sha({k: v for k, v in activation.items() if k != "activation_authority_sha256"})
    _commit_activation(context, activation)
    _commit_worker(context, _worker_output(workspace, activation))
    with pytest.raises(ProgramFactsTypeError, match="review parent"):
        _compose(context)


def test_wrong_workspace_tool_edge_rejected(tmp_path: Path) -> None:
    _, context, _, _, _ = _committed_fixture(tmp_path, edge_override={"slither_tool_row_sha256": "f" * 64})
    with pytest.raises(ProgramFactsTypeError, match="workspace/tool execution edge"):
        _compose(context)


def test_absent_denied_is_stable_typed_debt(tmp_path: Path) -> None:
    _, context, _, _, _ = _committed_fixture(tmp_path, denied=True)
    candidate = _compose(context)
    docs = [strict_json_loads(raw, require_final_lf=True) for _, raw in candidate["artifacts"]]
    assert docs[0]["status"] == docs[1]["status"] == docs[2]["status"] == "UNAVAILABLE"
    assert docs[0]["facts"] == []
    assert docs[2]["rows"][0]["reason_code"] == "ACTIVATION_POLICY_DENIED"
    assert docs[2]["rows"][0]["terminal_negative_authority"] is False
    outcome = _ensure(context)
    assert (outcome.state, outcome.valid) == ("UNAVAILABLE", True)


def test_active_capture_recovers_without_wtx_sidecars(tmp_path: Path) -> None:
    _, context, _, _, _ = _committed_fixture(tmp_path)
    first = _ensure(context)
    assert first.valid is True and first.reused is False
    for relative in (PROGRAM_FACTS_V2_WORKER_OUTPUT_PATH, PROGRAM_FACTS_V2_ACTIVATION_AUTHORITY_PATH, "_wtx_pf/provider.json", "_wtx_pf/attempt.json", "_wtx_pf/incorporation.json"):
        (context["scratchpad"] / relative).unlink()
    second = _ensure(context)
    assert second.valid is True and second.reused is True


def test_tampered_active_capture_rejected(tmp_path: Path) -> None:
    _, context, _, _, _ = _committed_fixture(tmp_path)
    _ensure(context)
    path = context["scratchpad"] / PROGRAM_FACTS_V2_AUTHORITY_CAPTURE_PATH
    capture = strict_json_loads(path.read_bytes(), require_final_lf=True)
    capture["candidate"]["schema_version"] = "plamen.program_facts_workspace_candidate.v1"
    capture["capture_sha256"] = _sha({k: v for k, v in capture.items() if k != "capture_sha256"})
    path.write_bytes(canonical_file_bytes(capture))
    with pytest.raises(ProgramFactsV2DriverIntegrationError, match="committed capture replay"):
        _ensure(context)


def test_v1_downgrade_candidate_rejected(tmp_path: Path) -> None:
    _, context, _, _, _ = _committed_fixture(tmp_path)
    candidate = deepcopy(_compose(context))
    candidate["schema_version"] = "plamen.program_facts_workspace_candidate.v1"
    with pytest.raises(ProgramFactsTypeError, match="V1_DOWNGRADE_REJECTED"):
        validate_workspace_bound_program_facts_v2(candidate, workspace_scratchpad=context["scratchpad"], project_root=context["project_root"], expected_run_id=RUN_ID, expected_snapshot_sha256=context["snapshot_sha256"], expected_owner_work_unit_key=context["owner_work_unit_key"])


def test_worker_bytes_tamper_breaks_ledger_replay(tmp_path: Path) -> None:
    _, context, _, output, _ = _committed_fixture(tmp_path)
    output["analysis_scope"]["claim"] = "TAMPERED"
    output["worker_output_sha256"] = _sha({k: v for k, v in output.items() if k != "worker_output_sha256"})
    (context["scratchpad"] / PROGRAM_FACTS_V2_WORKER_OUTPUT_PATH).write_bytes(canonical_file_bytes(output))
    with pytest.raises(ProgramFactsTypeError, match="COMMITTED_PHASEIO_INVALID"):
        _compose(context)


def test_shaped_sidecars_without_ledger_owner_cannot_mint(tmp_path: Path) -> None:
    workspace, context = _published_workspace(tmp_path)
    activation = _activation_bundle()
    _write_json(context["scratchpad"] / PROGRAM_FACTS_V2_ACTIVATION_AUTHORITY_PATH, activation)
    _write_json(context["scratchpad"] / PROGRAM_FACTS_V2_WORKER_OUTPUT_PATH, _worker_output(workspace, activation))
    with pytest.raises(ProgramFactsTypeError, match="COMMITTED_AUTHORITY_MISSING"):
        _compose(context)


def test_capture_embeds_complete_recovery_authority(tmp_path: Path) -> None:
    _, context, activation, output, authority = _committed_fixture(tmp_path)
    _ensure(context)
    capture = strict_json_loads((context["scratchpad"] / PROGRAM_FACTS_V2_AUTHORITY_CAPTURE_PATH).read_bytes(), require_final_lf=True)
    assert capture["worker_execution_authority"] == authority
    assert capture["worker_output"] == output
    assert capture["activation_authority"] == activation
    assert len(capture["public_artifacts"]) == 3
    key = "/".join((*context["owner_work_unit_key"].split("/")[:4], "recon", "program_facts_v2_authority_capture"))
    assert read_artifact_ledger(context["scratchpad"])["work_units"][key]["semantic_status"] == "ACTIVE"


def test_provider_and_activation_phaseio_registry_is_exact(tmp_path: Path) -> None:
    _, context = _published_workspace(tmp_path)
    provider, provider_launch = _contract(context, "program_facts_provider", PROGRAM_FACTS_V2_WORKER_OUTPUT_PATH, "MODEL")
    activation, activation_launch = _contract(context, "program_facts_v2_activation_authority", PROGRAM_FACTS_V2_ACTIVATION_AUTHORITY_PATH, "DRIVER")
    assert provider.model_invoked is True
    assert provider.outputs[0].writer == "MODEL"
    assert provider_launch.model == "program-facts-provider"
    assert provider_launch.exec_mode == "worker-transaction"
    assert provider_launch.tool_policy == ("slither", "solc")
    assert activation.model_invoked is False
    assert activation.outputs[0].writer == "DRIVER"
    assert activation_launch.model == "driver"
    assert provider.immutable_inputs == activation.immutable_inputs == ("scratchpad:evm_analysis_workspace_receipt.v1.json",)


def test_caller_constructed_provider_shape_is_not_registry_authority(tmp_path: Path) -> None:
    _, context = _published_workspace(tmp_path)
    prefix = context["owner_work_unit_key"].split("/")[:4]
    key = "/".join((*prefix, "recon", "program_facts_provider"))
    registered, _registered_launch = _contract(
        context,
        "program_facts_provider",
        PROGRAM_FACTS_V2_WORKER_OUTPUT_PATH,
        "MODEL",
    )
    forged = PhaseIOContract(
        pipeline=prefix[0], mode=prefix[1], ecosystem=prefix[2], backend=prefix[3],
        phase="recon", work_unit_id="program_facts_provider",
        outputs=(ArtifactSpec(
            root="scratchpad", path=PROGRAM_FACTS_V2_WORKER_OUTPUT_PATH,
            owner_key=key, artifact_class="REQUIRED", writer="MODEL",
                write_mode="CREATE",
        ),),
        immutable_inputs=registered.immutable_inputs,
        input_authority_requirements=registered.input_authority_requirements,
        model_invoked=True,
        required_commit_actor="MODEL",
    )
    forged_launch = LaunchSpec(
        work_unit_key=key, pipeline=prefix[0], mode=prefix[1],
        ecosystem=prefix[2], backend=prefix[3], model="provider",
        timeout_s=30, exec_mode="python", tool_policy=(),
    )
    with pytest.raises(ValueError, match="registered canonical manifest"):
        replay_phase_io_authority_pair(forged, forged_launch)
