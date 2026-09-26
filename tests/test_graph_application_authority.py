from __future__ import annotations

from dataclasses import replace
import copy
import hashlib
import inspect
import json
import os
from pathlib import Path
import sys

import pytest


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import artifact_ledger  # noqa: E402
import depth_handoff  # noqa: E402
import evm_analysis_workspace_authority as workspace_authority  # noqa: E402
import graph_application_authority as authority  # noqa: E402
from phase_io_contracts import (  # noqa: E402
    ArtifactSpec,
    InputAuthorityRequirement,
    LaunchSpec,
    PhaseIOContract,
    resolve_phase_io_contract,
)


RUN_ID = "run-graph-application-1"
SNAPSHOT = "1" * 64
EVIDENCE_ID = "scratchpad:depth_token_flow_findings.md"


def _compact(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _signed_tool(tool_id: str, executable: Path) -> dict:
    unsigned = {
        "schema": "plamen.runtime_tool_identity.v1",
        "tool_id": tool_id,
        "identity_kind": "command" if tool_id != "slither" else "python_distribution",
        "resolved_executable": str(executable),
        **({
            "executable_sha256": _sha(executable.read_bytes()),
            "executable_bytes": len(executable.read_bytes()),
        } if tool_id != "slither" else {}),
        **({
            "module_origin": str(executable),
            "module_sha256": _sha(executable.read_bytes()),
        } if tool_id == "slither" else {}),
        "version": "1.2.3",
        "deterministic_provider_authority": True,
        "toolchain_governance_sha256": "a" * 64,
        "toolchain_version_lock_sha256": "b" * 64,
        "authority_status": "MATCH",
        "reason": "",
    }
    return {**unsigned, "authority_digest": _sha(_compact(unsigned))}


def _workspace(root: Path, monkeypatch, *, degraded: bool = False) -> bytes:
    # This slice verifies how graph authority consumes an already validated
    # workspace receipt.  Keep the producer fixture independent of changes to
    # the native workspace-capture implementation while retaining strict,
    # deterministic replay at this boundary.
    del root
    unsigned = {
        "schema_version": workspace_authority.WORKSPACE_SCHEMA,
        "run_id": RUN_ID,
        "snapshot_sha256": SNAPSHOT,
        "state": "BOUND_WITH_DEBT" if degraded else "BOUND",
        "owner": {
            "work_unit_key": (
                "sc/thorough/evm/codex/recon/evm_analysis_workspace_capture"
            ),
        },
        "tools": [{
            "tool_id": "slither",
            "admission_state": "UNADMITTED" if degraded else "ADMITTED",
            "tool_row_sha256": "7" * 64,
        }],
    }
    receipt = {**unsigned, "receipt_sha256": _sha(_compact(unsigned))}

    def validate(value, *, expected_run_id=None, expected_snapshot_sha256=None):
        if (
            value != receipt
            or expected_run_id not in {None, RUN_ID}
            or expected_snapshot_sha256 not in {None, SNAPSHOT}
        ):
            raise workspace_authority.EVMAnalysisWorkspaceAuthorityError(
                "focused workspace fixture lineage differs"
            )
        return dict(receipt)

    def public_reference(value):
        validate(value)
        reference = {
            "artifact_identity": (
                "scratchpad:evm_analysis_workspace_receipt.v1.json"
            ),
            "receipt_sha256": receipt["receipt_sha256"],
            "snapshot_sha256": SNAPSHOT,
            "state": receipt["state"],
        }
        return {**reference, "reference_sha256": _sha(_compact(reference))}

    monkeypatch.setattr(authority, "validate_evm_analysis_workspace_receipt", validate)
    monkeypatch.setattr(authority, "workspace_public_reference", public_reference)
    return authority.canonical_file_bytes(receipt)


def _graph(function_count: int = 2, *, dense: bool = False) -> bytes:
    functions = {}
    for index in range(function_count):
        identity = f"Vault.f{index}"
        if dense:
            callees = [f"Vault.f{other}" for other in range(function_count) if other != index]
        else:
            callees = [f"Vault.f{index + 1}"] if index + 1 < function_count else []
        functions[identity] = {
            "bare": f"f{index}",
            "loc": f"contracts/Vault.sol:L{10 + index}",
            "callers": [],
            "callees": callees,
        }
    value = {
        "schema_version": "plamen.mechanical_graph.v2",
        "source": "slither",
        "functions": functions,
        "state_symbols": [{
            "symbol_id": "STATE-1",
            "qualified_name": "Vault.balance",
            "declaration_locus": "contracts/Vault.sol:L5",
            "read_sites": [f"Vault.f{function_count - 1}"],
            "write_sites": ["Vault.f0"],
            "graph_confidence": "AST_EXACT",
        }],
    }
    return (json.dumps(value, indent=1, sort_keys=True) + "\n").encode()


def _handoff(graph_raw: bytes) -> tuple[bytes, bytes, dict[str, bytes]]:
    inventory = b"""# Finding Inventory

### Finding [INV-001]: Token balance mismatch
**Severity**: High
**Location**: contracts/Vault.sol:L10
**Verdict**: UNRESOLVED
**Root Cause**: Token balance transfer is inconsistent.

### Finding [INV-002]: Admin overwrite
**Severity**: Medium
**Location**: contracts/Vault.sol:L11
**Verdict**: UNRESOLVED
**Root Cause**: Admin state role can be overwritten.

### Finding [INV-003]: Zero boundary
**Severity**: Low
**Location**: contracts/Vault.sol:L12
**Verdict**: UNRESOLVED
**Root Cause**: Zero precision boundary.

### Finding [INV-004]: Gateway callback
**Severity**: High
**Location**: contracts/Vault.sol:L13
**Verdict**: UNRESOLVED
**Root Cause**: Cross-chain callback is external.
"""
    outputs = depth_handoff.render_depth_handoff(
        mechanical_graph_raw=graph_raw,
        findings_inventory_raw=inventory,
        contract_inventory_raw=(
            b"# Contract Inventory\n| File | Path | Lines | Bytes |\n"
            b"|---|---|---:|---:|\n| Vault.sol | `contracts/Vault.sol` | 100 | 1000 |\n"
        ),
        spawn_manifest_raw=b"# Spawn Manifest\n| Template | Output |\n|---|---|\n| breadth | analysis_a.md |\n",
        breadth_raw_by_name={"analysis_a.md": b"contracts/Vault.sol\n"},
    )
    return outputs["depth_handoff_receipt.json"], outputs["depth_candidates.md"], outputs


def _generation(graph_raw: bytes, outputs: dict[str, bytes]) -> bytes:
    denominator = [
        "caller_map.md", "callee_map.md", "state_write_map.md",
        "function_summary.md", "_mechanical_graph.json",
    ]
    artifacts = []
    for name in denominator:
        raw = graph_raw if name == "_mechanical_graph.json" else outputs[name]
        artifacts.append({"path": name, "sha256": _sha(raw), "bytes": len(raw)})
    unsigned = {
        "schema_version": "plamen.mechanical_graph_generation.v1",
        "state": "COMMITTED",
        "artifact_denominator": denominator,
        "artifacts": artifacts,
    }
    return (json.dumps({
        **unsigned,
        "generation_sha256": _sha(authority.canonical_file_bytes(unsigned)),
    }, indent=2, sort_keys=True) + "\n").encode()


def _consumer(*, consumer_id: str = "depth/worker.token_flow", empty: bool = False) -> dict:
    return {
        "consumer_id": consumer_id,
        "phase": "depth",
        "agent_id": consumer_id.rsplit(".", 1)[-1],
        "graph_element_kinds": [] if empty else ["NODE", "EDGE"],
        "graph_shard_index": 0,
        "graph_shard_count": 1,
        "lead_routes": [] if empty else ["Edge Case", "External", "State Trace", "Token Flow"],
        "minimum_disposition": "REFERENCED",
        "evidence_artifacts": [EVIDENCE_ID],
    }


def _contract(
    *, phase: str, work_unit: str,
    outputs: tuple[tuple[str, str], ...],
    producers: dict[str, tuple[PhaseIOContract, LaunchSpec]] | None = None,
) -> tuple[PhaseIOContract, LaunchSpec]:
    key = f"sc/thorough/evm/codex/{phase}/{work_unit}"
    specs = tuple(ArtifactSpec(
        root="scratchpad", path=path, owner_key=key,
        artifact_class="DRIVER_GENERATED", writer="DRIVER",
        write_mode="REPLACE", schema_version=schema,
    ) for path, schema in outputs)
    inputs = tuple(sorted((producers or {}).keys()))
    requirements = tuple(
        InputAuthorityRequirement(
            identity=identity,
            allow_raw=False,
            expected_producer_work_unit_key=producer.key,
            expected_writer="DRIVER",
            require_same_run=True,
            expected_contract_digest=producer.digest,
            expected_launch_digest=launch.digest,
            require_exact_contract=True,
            require_exact_launch=True,
        )
        for identity, (producer, launch) in sorted((producers or {}).items())
    )
    contract = PhaseIOContract(
        pipeline="sc", mode="thorough", ecosystem="evm", backend="codex",
        phase=phase, work_unit_id=work_unit, outputs=specs,
        immutable_inputs=inputs, input_authority_requirements=requirements,
        model_invoked=False, launch_profile="DRIVER_PYTHON_NO_TOOLS",
        required_commit_actor="DRIVER",
    )
    launch = LaunchSpec(
        work_unit_key=contract.key, pipeline="sc", mode="thorough",
        ecosystem="evm", backend="codex", model="driver", timeout_s=30,
        exec_mode="python",
    )
    return contract, launch


def _commit(
    scratch: Path, project: Path,
    contract: PhaseIOContract, launch: LaunchSpec,
    raws: dict[str, bytes],
) -> None:
    artifact_ledger.record_work_unit_inputs(
        scratch, project, contract, launch, run_id=RUN_ID
    )
    for output in contract.outputs:
        raw = raws[output.identity]
        target = (scratch if output.root == "scratchpad" else project) / output.path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    artifact_ledger.record_work_unit_artifacts(
        scratch, project, contract, launch, run_id=RUN_ID, actor="DRIVER"
    )


def _all_outcomes(plan: dict, *, disposition: str = "REFERENCED") -> list[dict]:
    return [{
        "element_id": element_id,
        "disposition": disposition,
        "evidence": [{
            "artifact_identity": EVIDENCE_ID,
            "artifact_sha256": "e" * 64,
            "loci": ["L1"],
        }],
        "conclusion": "The assigned graph element was examined in the bound evidence.",
        "debt": None,
    } for element_id in plan["consumers"][0]["assigned_element_ids"]]


def _world(tmp_path: Path, monkeypatch, *, consumers: list[dict] | None = None,
           degraded_workspace: bool = False) -> dict:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    source_root = tmp_path / "bundle"
    consumers = [_consumer()] if consumers is None else consumers
    workspace_raw = _workspace(source_root, monkeypatch, degraded=degraded_workspace)
    graph_raw = _graph()
    handoff_raw, candidates_raw, handoff_outputs = _handoff(graph_raw)
    generation_raw = _generation(graph_raw, handoff_outputs)

    schedule_contract, schedule_launch = _contract(
        phase="recon", work_unit="graph_application.scheduler",
        outputs=((authority.SCHEDULE_ARTIFACT, authority.SCHEDULE_SCHEMA),),
    )
    schedule = authority.build_graph_schedule_payload(
        run_id=RUN_ID, snapshot_sha256=SNAPSHOT,
        required_consumers=consumers,
        contract=schedule_contract, launch=schedule_launch,
    )
    schedule_raw = authority.canonical_file_bytes(schedule)
    _commit(scratch, tmp_path, schedule_contract, schedule_launch, {
        f"scratchpad:{authority.SCHEDULE_ARTIFACT}": schedule_raw,
    })

    workspace_contract = resolve_phase_io_contract(
        pipeline="sc", mode="thorough", ecosystem="evm", backend="codex",
        phase="recon", work_unit_id="evm_analysis_workspace_capture",
        exact_inputs=(),
        exact_outputs=("evm_analysis_workspace_receipt.v1.json",),
        exact_writer="DRIVER",
    )
    workspace_launch = LaunchSpec(
        work_unit_key=workspace_contract.key, pipeline="sc", mode="thorough",
        ecosystem="evm", backend="codex", model="driver", timeout_s=30,
        exec_mode="python",
    )
    graph_contract, graph_launch = _contract(
        phase="recon", work_unit="mechanical_graph",
        outputs=(("_mechanical_graph.json", "plamen.mechanical_graph.v2"),),
    )
    handoff_contract, handoff_launch = _contract(
        phase="inventory", work_unit="depth_handoff",
        outputs=(("depth_handoff_receipt.json", "plamen.depth_handoff_receipt.v1"),
                 ("depth_candidates.md", "plamen.depth_candidates_projection.v1")),
    )
    generation_contract, generation_launch = _contract(
        phase="inventory", work_unit="graph_generation",
        outputs=(("_mechanical_graph_generation.json", "plamen.mechanical_graph_generation.v1"),),
    )
    producers = {
        "scratchpad:evm_analysis_workspace_receipt.v1.json": (workspace_contract, workspace_launch),
        "scratchpad:_mechanical_graph.json": (graph_contract, graph_launch),
        "scratchpad:depth_handoff_receipt.json": (handoff_contract, handoff_launch),
        "scratchpad:depth_candidates.md": (handoff_contract, handoff_launch),
        "scratchpad:_mechanical_graph_generation.json": (generation_contract, generation_launch),
    }
    for contract, launch, raws in (
        (workspace_contract, workspace_launch, {"scratchpad:evm_analysis_workspace_receipt.v1.json": workspace_raw}),
        (graph_contract, graph_launch, {"scratchpad:_mechanical_graph.json": graph_raw}),
        (handoff_contract, handoff_launch, {
            "scratchpad:depth_handoff_receipt.json": handoff_raw,
            "scratchpad:depth_candidates.md": candidates_raw,
        }),
        (generation_contract, generation_launch, {"scratchpad:_mechanical_graph_generation.json": generation_raw}),
    ):
        _commit(scratch, tmp_path, contract, launch, raws)

    roster_contract, roster_launch = _contract(
        phase="inventory", work_unit="graph_application.consumer_roster",
        outputs=((authority.CONSUMER_ROSTER_ARTIFACT, authority.CONSUMER_ROSTER_SCHEMA),),
        producers={f"scratchpad:{authority.SCHEDULE_ARTIFACT}": (schedule_contract, schedule_launch)},
    )
    roster_payload = authority.build_graph_consumer_roster_payload(
        run_id=RUN_ID, snapshot_sha256=SNAPSHOT,
        committed_schedule_raw=schedule_raw,
        contract=roster_contract, launch=roster_launch,
    )
    _commit(scratch, tmp_path, roster_contract, roster_launch, {
        f"scratchpad:{authority.CONSUMER_ROSTER_ARTIFACT}": authority.canonical_file_bytes(roster_payload),
    })
    roster = authority.load_committed_graph_consumer_roster(
        scratchpad=scratch, project_root=tmp_path,
        contract=roster_contract, launch=roster_launch,
        run_id=RUN_ID, expected_snapshot_sha256=SNAPSHOT,
    )
    producers[f"scratchpad:{authority.CONSUMER_ROSTER_ARTIFACT}"] = (roster_contract, roster_launch)
    authority_contract, authority_launch = _contract(
        phase="inventory", work_unit="graph_application.authority",
        outputs=((authority.AUTHORITY_ARTIFACT, authority.AUTHORITY_SCHEMA),),
        producers=producers,
    )
    plan = authority.build_graph_application_authority(
        run_id=RUN_ID, snapshot_sha256=SNAPSHOT,
        workspace_receipt_raw=workspace_raw,
        mechanical_graph_raw=graph_raw,
        depth_handoff_receipt_raw=handoff_raw,
        depth_candidates_raw=candidates_raw,
        graph_generation_manifest_raw=generation_raw,
        committed_consumer_roster=roster,
    )
    _commit(scratch, tmp_path, authority_contract, authority_launch, {
        f"scratchpad:{authority.AUTHORITY_ARTIFACT}": authority.canonical_file_bytes(plan),
    })
    committed_plan = authority.load_committed_graph_application_authority(
        scratchpad=scratch, project_root=tmp_path,
        contract=authority_contract, launch=authority_launch,
        committed_consumer_roster=roster, run_id=RUN_ID,
        expected_snapshot_sha256=SNAPSHOT,
    )
    return locals()


def _finish(
    world: dict,
    *,
    complete: bool = True,
) -> tuple[object, object, dict]:
    scratch, project, plan = world["scratch"], world["tmp_path"], world["plan"]
    evidence_raw = b"# exact evidence\n"
    evidence_contract, evidence_launch = _contract(
        phase="depth", work_unit="worker.token_flow",
        outputs=(("depth_token_flow_findings.md", "text/markdown"),),
    )
    _commit(scratch, project, evidence_contract, evidence_launch, {EVIDENCE_ID: evidence_raw})
    evidence_sha = _sha(evidence_raw)
    outcomes = _all_outcomes(plan) if complete else []
    for row in outcomes:
        row["evidence"][0]["artifact_sha256"] = evidence_sha
    evidence_bindings = {EVIDENCE_ID: evidence_sha} if complete else {}
    observations = authority.build_graph_application_observations(
        committed_authority=world["committed_plan"],
        evidence_artifact_sha256=evidence_bindings,
        consumer_observations=(
            [{
                "consumer_id": plan["consumers"][0]["consumer_id"],
                "full_availability_acknowledgement": plan["full_availability"],
                "outcomes": outcomes,
            }]
            if complete
            else []
        ),
    )
    obs_contract, obs_launch = _contract(
        phase="chain", work_unit="graph_application.observations",
        outputs=((authority.OBSERVATIONS_ARTIFACT, authority.OBSERVATIONS_SCHEMA),),
        producers={
            f"scratchpad:{authority.AUTHORITY_ARTIFACT}": (
                world["authority_contract"], world["authority_launch"]
            ),
            **(
                {EVIDENCE_ID: (evidence_contract, evidence_launch)}
                if complete
                else {}
            ),
        },
    )
    _commit(scratch, project, obs_contract, obs_launch, {
        f"scratchpad:{authority.OBSERVATIONS_ARTIFACT}": authority.canonical_file_bytes(observations),
    })
    committed_obs = authority.load_committed_graph_application_observations(
        scratchpad=scratch, project_root=project,
        contract=obs_contract, launch=obs_launch,
        committed_authority=world["committed_plan"], run_id=RUN_ID,
        expected_evidence_artifact_sha256=evidence_bindings,
    )
    reconciliation = authority.reconcile_graph_application(
        committed_authority=world["committed_plan"],
        committed_observations=committed_obs,
    )
    rec_contract, rec_launch = _contract(
        phase="chain", work_unit="graph_application.reconciliation",
        outputs=((authority.RECONCILIATION_ARTIFACT, authority.RECONCILIATION_SCHEMA),),
        producers={
            f"scratchpad:{authority.AUTHORITY_ARTIFACT}": (world["authority_contract"], world["authority_launch"]),
            f"scratchpad:{authority.OBSERVATIONS_ARTIFACT}": (obs_contract, obs_launch),
        },
    )
    _commit(scratch, project, rec_contract, rec_launch, {
        f"scratchpad:{authority.RECONCILIATION_ARTIFACT}": authority.canonical_file_bytes(reconciliation),
    })
    committed_rec = authority.load_committed_graph_application_reconciliation(
        scratchpad=scratch, project_root=project,
        contract=rec_contract, launch=rec_launch,
        committed_authority=world["committed_plan"],
        committed_observations=committed_obs, run_id=RUN_ID,
    )
    return committed_obs, committed_rec, reconciliation


def test_committed_full_lineage_reaches_complete(tmp_path, monkeypatch):
    world = _world(tmp_path, monkeypatch)
    observations, reconciliation, payload = _finish(world)
    assert world["plan"]["state"] == "READY"
    assert payload["state"] == "COMPLETE"
    assert not payload["debts"]
    assert authority.load_graph_application_reconciliation_bytes(
        reconciliation,
        authority=world["committed_plan"],
        observations=observations,
    ) == payload


def test_no_module_mint_credential_and_constructor_forgery_rejects():
    assert not hasattr(authority, "_COMMITTED_TOKEN_SEAL")
    assert not hasattr(authority, "_issue_committed_token")
    assert not hasattr(authority, "_require_committed_token")
    assert not hasattr(authority, "_load_committed_graph_consumer_roster_impl")
    for loader in (
        authority.load_committed_graph_consumer_roster,
        authority.load_committed_graph_application_authority,
        authority.load_committed_graph_application_observations,
        authority.load_committed_graph_application_reconciliation,
    ):
        assert "__issuer" not in inspect.signature(loader).parameters
        assert loader.__defaults__ is None
        assert loader.__kwdefaults__ is None
    with pytest.raises(authority.GraphApplicationAuthorityError, match="loader-issued"):
        authority.CommittedGraphConsumerRoster(payload={})
    forged = object.__new__(authority.CommittedGraphConsumerRoster)
    for name, value in {
        "payload": {}, "canonical_bytes": b"{}\n", "artifact_sha256": _sha(b"{}\n"),
        "contract_digest": "a" * 64, "launch_digest": "b" * 64,
    }.items():
        object.__setattr__(forged, name, value)
    with pytest.raises(authority.GraphApplicationAuthorityError, match="loader replay"):
        authority.build_graph_application_authority(
            run_id=RUN_ID, snapshot_sha256=SNAPSHOT,
            workspace_receipt_raw=b"{}\n", mechanical_graph_raw=b"{}\n",
            depth_handoff_receipt_raw=b"{}\n", depth_candidates_raw=b"x",
            committed_consumer_roster=forged,
        )


def test_recovered_python_issuer_cannot_authorize_uncommitted_complete(
    tmp_path, monkeypatch,
):
    world = _world(tmp_path, monkeypatch)
    plan = world["plan"]
    outcomes = _all_outcomes(plan)
    observation_payload = authority._build_graph_application_observations_payload(
        authority=plan,
        expected_consumer_denominator_sha256=plan[
            "consumer_denominator_sha256"
        ],
        expected_scheduler_artifact_sha256=plan["consumer_roster"][
            "scheduler_artifact_sha256"
        ],
        evidence_artifact_sha256={EVIDENCE_ID: "e" * 64},
        consumer_observations=[{
            "consumer_id": plan["consumers"][0]["consumer_id"],
            "full_availability_acknowledgement": plan["full_availability"],
            "outcomes": outcomes,
        }],
    )
    issuer = next(
        cell.cell_contents
        for cell in authority.load_committed_graph_consumer_roster.__closure__ or ()
        if callable(cell.cell_contents)
        and {"cls", "kind"}.issubset(
            inspect.signature(cell.cell_contents).parameters
        )
    )
    forged = issuer(
        authority.CommittedGraphApplicationObservations,
        kind="committed graph application observations",
        payload=observation_payload,
        canonical_bytes=authority.canonical_file_bytes(observation_payload),
        artifact_sha256=_sha(authority.canonical_file_bytes(observation_payload)),
        contract_digest="a" * 64,
        launch_digest="b" * 64,
    )
    with pytest.raises(
        authority.GraphApplicationAuthorityError,
        match="PhaseIO replay context",
    ):
        authority.reconcile_graph_application(
            committed_authority=world["committed_plan"],
            committed_observations=forged,
        )


def test_schedule_is_the_denominator_not_caller_subset(tmp_path, monkeypatch):
    world = _world(tmp_path, monkeypatch, consumers=[
        _consumer(), _consumer(consumer_id="depth/worker.state_trace"),
    ])
    assert world["plan"]["consumer_count"] == 2
    subset = copy.deepcopy(world["roster_payload"])
    subset["required_consumers"] = subset["required_consumers"][:1]
    subset["consumer_count"] = 1
    subset["consumer_denominator_sha256"] = authority.consumer_denominator_sha256_test_only(
        subset["required_consumers"]
    )
    unsigned = dict(subset); unsigned.pop("roster_sha256")
    subset["roster_sha256"] = authority._digest(unsigned)
    with pytest.raises(authority.GraphApplicationAuthorityError, match="denominator"):
        authority.decode_graph_consumer_roster_test_only(
            authority.canonical_file_bytes(subset),
            expected_run_id=RUN_ID, expected_snapshot_sha256=SNAPSHOT,
            committed_schedule=world["schedule"],
            schedule_artifact_sha256=_sha(world["schedule_raw"]),
        )


def test_unbound_or_wrong_fixed_producer_contract_rejects(tmp_path, monkeypatch):
    world = _world(tmp_path, monkeypatch)
    bad_contract, bad_launch = _contract(
        phase="inventory", work_unit="graph_application.authority",
        outputs=((authority.AUTHORITY_ARTIFACT, authority.AUTHORITY_SCHEMA),),
        producers={
            **world["producers"],
            "scratchpad:_mechanical_graph.json": world["producers"]["scratchpad:depth_handoff_receipt.json"],
        },
    )
    with pytest.raises(authority.GraphApplicationAuthorityError, match="producer token"):
        authority.load_committed_graph_application_authority(
            scratchpad=world["scratch"], project_root=tmp_path,
            contract=bad_contract, launch=bad_launch,
            committed_consumer_roster=world["roster"], run_id=RUN_ID,
            expected_snapshot_sha256=SNAPSHOT,
        )


def test_fixed_producer_manifest_cannot_launder_extra_outputs(
    tmp_path, monkeypatch,
):
    world = _world(tmp_path, monkeypatch)
    ledger = copy.deepcopy(artifact_ledger.read_artifact_ledger(world["scratch"]))
    graph_key = world["graph_contract"].key
    manifest = ledger["work_units"][graph_key]["contract_manifest"]
    extra = copy.deepcopy(manifest["outputs"][0])
    extra["path"] = "unrelated.json"
    extra["identity"] = "scratchpad:unrelated.json"
    manifest["outputs"].append(extra)

    with pytest.raises(
        authority.GraphApplicationAuthorityError,
        match="committed fixed producer differs",
    ):
        authority._validate_fixed_input_producers_in_ledger(
            ledger,
            world["authority_contract"],
            run_id=RUN_ID,
            expected={
                "scratchpad:_mechanical_graph.json": (
                    "recon",
                    "mechanical_graph",
                    "DRIVER",
                    "plamen.mechanical_graph.v2",
                ),
            },
        )


def test_observation_evidence_must_come_from_scheduled_consumer(
    tmp_path, monkeypatch,
):
    world = _world(tmp_path, monkeypatch)
    unrelated_contract, unrelated_launch = _contract(
        phase="depth",
        work_unit="worker.unrelated",
        outputs=(("depth_token_flow_findings.md", "text/markdown"),),
    )
    observation_contract, _observation_launch = _contract(
        phase="chain",
        work_unit="graph_application.observations",
        outputs=((authority.OBSERVATIONS_ARTIFACT, authority.OBSERVATIONS_SCHEMA),),
        producers={
            f"scratchpad:{authority.AUTHORITY_ARTIFACT}": (
                world["authority_contract"], world["authority_launch"]
            ),
            EVIDENCE_ID: (unrelated_contract, unrelated_launch),
        },
    )
    with pytest.raises(
        authority.GraphApplicationAuthorityError,
        match="producer differs from scheduled consumer",
    ):
        authority._require_evidence_producer_topology(
            observation_contract,
            world["plan"],
            [{"artifact_identity": EVIDENCE_ID, "artifact_sha256": "e" * 64}],
        )


def test_unused_evidence_binding_cannot_enter_observation_denominator(
    tmp_path, monkeypatch,
):
    world = _world(tmp_path, monkeypatch)
    with pytest.raises(
        authority.GraphApplicationAuthorityError,
        match="differs from referenced evidence",
    ):
        authority.build_graph_application_observations(
            committed_authority=world["committed_plan"],
            evidence_artifact_sha256={EVIDENCE_ID: "e" * 64},
            consumer_observations=[],
        )


def test_caller_constructed_raw_phaseio_input_rejects(tmp_path, monkeypatch):
    world = _world(tmp_path, monkeypatch)
    key = "sc/thorough/evm/codex/inventory/graph_application.authority"
    inputs = tuple(sorted(world["producers"]))
    raw_contract = PhaseIOContract(
        pipeline="sc", mode="thorough", ecosystem="evm", backend="codex",
        phase="inventory", work_unit_id="graph_application.authority",
        outputs=(ArtifactSpec(
            root="scratchpad", path=authority.AUTHORITY_ARTIFACT,
            owner_key=key, artifact_class="DRIVER_GENERATED", writer="DRIVER",
            write_mode="REPLACE", schema_version=authority.AUTHORITY_SCHEMA,
        ),),
        immutable_inputs=inputs,
        input_authority_requirements=tuple(
            InputAuthorityRequirement(identity=item, allow_raw=True) for item in inputs
        ),
        model_invoked=False, launch_profile="DRIVER_PYTHON_NO_TOOLS",
        required_commit_actor="DRIVER",
    )
    launch = replace(world["authority_launch"], work_unit_key=raw_contract.key)
    with pytest.raises(authority.GraphApplicationAuthorityError, match="producer token"):
        authority.load_committed_graph_application_authority(
            scratchpad=world["scratch"], project_root=tmp_path,
            contract=raw_contract, launch=launch,
            committed_consumer_roster=world["roster"], run_id=RUN_ID,
            expected_snapshot_sha256=SNAPSHOT,
        )


def test_workspace_debt_and_unadmitted_provider_never_ready(tmp_path, monkeypatch):
    world = _world(tmp_path, monkeypatch, degraded_workspace=True)
    codes = {row["code"] for row in world["plan"]["debts"]}
    assert world["plan"]["state"] == "DEGRADED"
    assert "WORKSPACE_AUTHORITY_DEGRADED" in codes
    assert "GRAPH_PROVIDER_UNADMITTED" in codes


def test_empty_assignment_debt_is_exact_and_cannot_be_removed(tmp_path, monkeypatch):
    world = _world(tmp_path, monkeypatch, consumers=[_consumer(empty=True)])
    plan = world["plan"]
    assert "CONSUMER_ASSIGNMENT_EMPTY" in {row["code"] for row in plan["debts"]}
    tampered = copy.deepcopy(plan)
    tampered["debts"] = [
        row for row in tampered["debts"] if row["code"] != "CONSUMER_ASSIGNMENT_EMPTY"
    ]
    unsigned = dict(tampered); unsigned.pop("authority_sha256")
    tampered["authority_sha256"] = authority._digest(unsigned)
    with pytest.raises(authority.GraphApplicationAuthorityError, match="debt denominator"):
        authority.validate_graph_application_authority(tampered)


def test_missing_consumer_observation_expands_exact_pair_debt(tmp_path, monkeypatch):
    world = _world(tmp_path, monkeypatch)
    empty = authority._build_graph_application_observations_payload(
        authority=world["plan"],
        expected_consumer_denominator_sha256=world["plan"]["consumer_denominator_sha256"],
        expected_scheduler_artifact_sha256=world["plan"]["consumer_roster"]["scheduler_artifact_sha256"],
        evidence_artifact_sha256={}, consumer_observations=[],
    )
    rec = authority._reconcile_graph_application_payload(
        authority=world["plan"], observations=empty,
        expected_consumer_denominator_sha256=world["plan"]["consumer_denominator_sha256"],
        expected_scheduler_artifact_sha256=world["plan"]["consumer_roster"]["scheduler_artifact_sha256"],
    )
    missing = [row for row in rec["debts"] if row["code"] == "ELEMENT_OUTCOME_OMITTED"]
    absent = [row for row in rec["debts"] if row["code"] == "CONSUMER_OBSERVATION_ABSENT"]
    assert rec["state"] == "DEGRADED"
    assert len(missing) == world["plan"]["assignment_pair_count"]
    assert len(absent) == world["plan"]["consumer_count"]


def test_full_availability_ack_is_exact(tmp_path, monkeypatch):
    world = _world(tmp_path, monkeypatch)
    plan = world["plan"]
    with pytest.raises(authority.GraphApplicationAuthorityError, match="acknowledgement"):
        authority._build_graph_application_observations_payload(
            authority=plan,
            expected_consumer_denominator_sha256=plan["consumer_denominator_sha256"],
            expected_scheduler_artifact_sha256=plan["consumer_roster"]["scheduler_artifact_sha256"],
            evidence_artifact_sha256={EVIDENCE_ID: "e" * 64},
            consumer_observations=[{
                "consumer_id": plan["consumers"][0]["consumer_id"],
                "full_availability_acknowledgement": {**plan["full_availability"], "snapshot_sha256": "f" * 64},
                "outcomes": _all_outcomes(plan),
            }],
        )


def test_graph_edges_fail_incrementally_before_denominator_amplification(monkeypatch):
    monkeypatch.setattr(authority, "_MAX_ELEMENTS", 100)
    with pytest.raises(authority.GraphApplicationAuthorityError, match="element denominator"):
        authority._parse_graph(_graph(function_count=30, dense=True))


def test_real_element_ceiling_fails_before_one_excess_node_is_retained():
    # Exercise the production ceiling (not a monkeypatched toy bound).  The
    # state-symbol row would be element MAX+1 after the exact function limit.
    with pytest.raises(authority.GraphApplicationAuthorityError, match="node denominator"):
        authority._parse_graph(_graph(function_count=authority._MAX_ELEMENTS))


def test_pair_cap_fails_before_assignment_product_extension(tmp_path, monkeypatch):
    world = _world(tmp_path, monkeypatch)
    roster = world["roster"]
    monkeypatch.setattr(authority, "_MAX_ASSIGNMENT_PAIRS", 2)
    with pytest.raises(authority.GraphApplicationAuthorityError, match="pair limit"):
        authority.build_graph_application_authority(
            run_id=RUN_ID, snapshot_sha256=SNAPSHOT,
            workspace_receipt_raw=world["workspace_raw"],
            mechanical_graph_raw=world["graph_raw"],
            depth_handoff_receipt_raw=world["handoff_raw"],
            depth_candidates_raw=world["candidates_raw"],
            graph_generation_manifest_raw=world["generation_raw"],
            committed_consumer_roster=roster,
        )


def test_validator_enforces_pair_cap_before_selector_materialization(
    tmp_path, monkeypatch,
):
    world = _world(tmp_path, monkeypatch)
    assigned_count = len(world["plan"]["consumers"][0]["assigned_element_ids"])
    assert assigned_count > 1
    monkeypatch.setattr(authority, "_MAX_ASSIGNMENT_PAIRS", assigned_count - 1)
    with pytest.raises(
        authority.GraphApplicationAuthorityError,
        match="nested denominator exceeds bound|pair limit",
    ):
        authority.validate_graph_application_authority(world["plan"])


def test_evidence_denominators_fail_before_unbounded_copy(monkeypatch):
    monkeypatch.setattr(authority, "_MAX_EVIDENCE_BINDINGS", 1)
    with pytest.raises(authority.GraphApplicationAuthorityError, match="exceeds bound"):
        authority._evidence_bindings({
            "scratchpad:a.md": "a" * 64,
            "scratchpad:b.md": "b" * 64,
        })


def test_committed_token_cannot_replay_under_another_run(tmp_path, monkeypatch):
    world = _world(tmp_path, monkeypatch)
    with pytest.raises(authority.GraphApplicationAuthorityError, match="PhaseIO replay"):
        authority.load_committed_graph_application_authority(
            scratchpad=world["scratch"],
            project_root=tmp_path,
            contract=world["authority_contract"],
            launch=world["authority_launch"],
            committed_consumer_roster=world["roster"],
            run_id="run-graph-application-other",
            expected_snapshot_sha256=SNAPSHOT,
        )


def test_source_tamper_after_commit_rejects_loader(tmp_path, monkeypatch):
    world = _world(tmp_path, monkeypatch)
    (world["scratch"] / "_mechanical_graph.json").write_bytes(b"{}\n")
    with pytest.raises(authority.GraphApplicationAuthorityError, match="PhaseIO replay"):
        authority.load_committed_graph_application_authority(
            scratchpad=world["scratch"], project_root=tmp_path,
            contract=world["authority_contract"], launch=world["authority_launch"],
            committed_consumer_roster=world["roster"], run_id=RUN_ID,
            expected_snapshot_sha256=SNAPSHOT,
        )


def test_raw_projection_loaders_replay_but_never_grant_authority(
    tmp_path, monkeypatch,
):
    world = _world(tmp_path, monkeypatch)
    _committed_obs, _committed_rec, reconciliation = _finish(world)
    authority_raw = (
        world["scratch"] / authority.AUTHORITY_ARTIFACT
    ).read_bytes()
    observations_raw = (
        world["scratch"] / authority.OBSERVATIONS_ARTIFACT
    ).read_bytes()
    reconciliation_raw = (
        world["scratch"] / authority.RECONCILIATION_ARTIFACT
    ).read_bytes()

    projected_authority = authority.load_graph_application_authority_bytes(
        authority_raw, expected_run_id=RUN_ID
    )
    projected_observations = authority.load_graph_application_observations_bytes(
        observations_raw,
        authority=projected_authority,
    )
    projected_reconciliation = (
        authority.load_graph_application_reconciliation_bytes(
            reconciliation_raw,
            authority=projected_authority,
            observations=projected_observations,
        )
    )
    assert projected_reconciliation == reconciliation
    assert type(projected_authority) is dict
    with pytest.raises(authority.GraphApplicationAuthorityError, match="committed"):
        authority.build_graph_application_observations(
            committed_authority=projected_authority,
            evidence_artifact_sha256={},
            consumer_observations=[],
        )


def test_schedule_and_generation_are_required_integration_inputs():
    contract = authority.integration_contract()
    assert contract["consumer_activation"] is False
    assert contract["optional_parent_artifacts"] == []
    assert f"scratchpad:{authority.SCHEDULE_ARTIFACT}" in contract["required_parent_artifacts"]
    assert "scratchpad:_mechanical_graph_generation.json" in contract["required_parent_artifacts"]
    assert contract["schemas"][authority.SCHEDULE_ARTIFACT] == authority.SCHEDULE_SCHEMA


def test_canonical_schedule_rejects_duplicate_json_key(tmp_path):
    raw = b'{"schema_version":"x","schema_version":"y"}\n'
    with pytest.raises(authority.GraphApplicationAuthorityError, match="duplicate key"):
        authority.decode_graph_schedule_test_only(
            raw,
            expected_run_id=RUN_ID, expected_snapshot_sha256=SNAPSHOT,
            expected_owner_work_unit_key="x", expected_contract_digest="a" * 64,
            expected_launch_digest="b" * 64,
        )
