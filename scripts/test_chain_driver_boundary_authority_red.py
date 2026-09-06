"""Red executable specification for the real SC chain ownership boundary.

These fixtures deliberately use the registered resolver and live driver helpers.
They do not manufacture permissive PhaseIO output contracts.  The boundary is
complete only when:

* summary compaction and the scaffold have exact DRIVER ownership;
* state resolution replaces the scaffold enabler and owns every chain-prep root;
* chain/model binds the exact live denominator and replaces its predecessors; and
* the final immutable pair provider admits only a common chain/model pair or the
  journaled final_pair_auto_map_apply.<digest> successor.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence

from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from chain_pair_auto_map_transaction import run_chain_pair_auto_map_transaction
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
    registered_projection_handoff,
)
from plamen_types import SC_PHASES
from preverify_chain_pair_projection import prepare_preverify_chain_pair_projection
import plamen_driver as DRIVER


RUN_ID = "d8d4cc76-4498-48d6-a927-9510f16df5c9"
PAIR = ("hypotheses.md", "finding_mapping.md")
CHAIN_OUTPUTS = (*PAIR, "enabler_results.md")
AUTH_INPUTS = (
    "authentication_role_authority.json",
    "arm_before_trust_composition_obligations.json",
    "authentication_external_research_obligations.json",
    "authentication_role_obligations.md",
)


def _chain_phase():
    return next(phase for phase in SC_PHASES if phase.name == "chain")


def _config(project: Path, *, backend: str = "claude") -> dict[str, Any]:
    return {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": backend,
        "project_root": str(project),
        "scratchpad": str(project / ".scratchpad"),
        "_run_id": RUN_ID,
    }


def _root(tmp_path: Path) -> tuple[Path, Path]:
    project = tmp_path / "project"
    project.mkdir()
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir()
    return project, scratchpad


def _write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def _claim_depth_sources(
    project: Path,
    scratchpad: Path,
    paths: Sequence[str],
) -> None:
    owner = canonical_work_unit_key(
        "sc", "thorough", "evm", "claude", "depth", "fixture_sources"
    )
    postimages = {
        relative: (scratchpad / relative).read_bytes()
        for relative in paths
    }
    for relative in paths:
        (scratchpad / relative).unlink()
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="depth",
        work_unit_id="fixture_sources",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=relative,
                owner_key=owner,
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="CREATE",
                schema_version="unstructured.v1",
                minimum_gate="FIXTURE_EXACT_DEPTH_SOURCE",
                consumers=("chain/model", "chain/final_pair_auto_map_stage"),
            )
            for relative in paths
        ),
        immutable_inputs=(),
        bounded_lookup_inputs=(),
        model_invoked=True,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="fixture-depth",
        timeout_s=60,
        exec_mode="pty",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        scratchpad, project, contract, launch, run_id=RUN_ID
    )
    for relative, raw in postimages.items():
        (scratchpad / relative).write_bytes(raw)
    record_work_unit_artifacts(
        scratchpad,
        project,
        contract,
        launch,
        run_id=RUN_ID,
        actor="MODEL",
    )


def _seed_chain_inputs(
    project: Path,
    scratchpad: Path,
    *,
    include_dynamic: bool = True,
) -> dict[str, Any]:
    _write(scratchpad / "_v2_checkpoint.json", "{}\n")
    _write(
        scratchpad / "findings_inventory.md",
        "# Findings Inventory\n\n"
        "### Finding [INV-1]: Fixture candidate\n"
        "**Severity**: Medium\n"
        "**Location**: src/Fixture.sol:1\n"
        "**Description**: Candidate retained for independent verification.\n",
    )
    _write(scratchpad / "attack_surface.md", "# Attack Surface\n\nFixture.\n")
    _write(
        scratchpad / "depth_alpha_findings.md",
        "# Depth\n\n"
        "## Chain Summary\n\n"
        "- INV-1 changes a security-relevant state transition.\n",
    )
    if include_dynamic:
        _write(
            scratchpad / "depth_beta_findings.md",
            "# Depth Beta\n\n"
            "## Chain Summary\n\n"
            "- Independent dynamic input.\n",
        )
        _write(
            scratchpad / "confidence_scores.md",
            "# Confidence\n\n| Finding | Confidence |\n|---|---|\n| INV-1 | 70 |\n",
        )
    _claim_depth_sources(
        project,
        scratchpad,
        tuple(
            path.name
            for path in sorted(scratchpad.glob("depth_*_findings.md"))
        ),
    )
    config = _config(project)
    assert DRIVER._run_chain_summary_compaction_transaction(
        scratchpad, config
    ) == []
    written, issues = DRIVER._run_chain_scaffold_transaction(
        scratchpad, config
    )
    assert issues == []
    assert set(written) == set(CHAIN_OUTPUTS)
    return config


def _bindings(scratchpad: Path) -> Mapping[str, Mapping[str, Any]]:
    return read_artifact_ledger(scratchpad)["artifact_bindings"]


def _commit_state_resolution(
    project: Path,
    scratchpad: Path,
    config: dict[str, Any],
) -> None:
    phase = _chain_phase()
    config["_chain_state_resolution_initializes_tail"] = True
    execute, prebind_issues = DRIVER._arm_chain_state_resolution_phase_io(
        scratchpad=scratchpad,
        config=config,
        phase=phase,
    )
    assert execute is True
    assert prebind_issues == []
    prefill_execute, prefill_issues = (
        DRIVER._arm_chain_enabler_prefill_phase_io(
            scratchpad=scratchpad,
            config=config,
            phase=phase,
        )
    )
    assert prefill_execute is True
    assert prefill_issues == []

    outputs = (
        "chain_state_resolution.json",
        *DRIVER._CHAIN_TAIL_INITIALIZATION_OUTPUTS,
        *DRIVER._CHAIN_ENABLER_PREFILL_OUTPUTS,
    )
    for relative in outputs:
        body = (
            '{"schema_version":"fixture.state-resolution.v1"}\n'
            if relative.endswith(".json")
            else f"# DRIVER state-resolution output: {relative}\n"
        )
        _write(scratchpad / relative, body)

    assert DRIVER._commit_chain_enabler_prefill_phase_io(
        scratchpad=scratchpad,
        config=config,
        phase=phase,
    ) == []
    commit_issues = DRIVER._record_chain_state_resolution_phase_io(
        scratchpad=scratchpad,
        config=config,
        phase=phase,
    )
    assert commit_issues == []


def _commit_chain_model(
    project: Path,
    scratchpad: Path,
    config: dict[str, Any],
) -> None:
    phase = _chain_phase()
    bind_issues = DRIVER._bind_typed_model_phase_inputs(
        phase, scratchpad, config
    )
    assert bind_issues == []
    _write(
        scratchpad / "hypotheses.md",
        "# Hypotheses\n\n"
        "| Hypothesis ID | Severity | Title | Constituent Findings |\n"
        "|---|---|---|---|\n"
        "| H-1 | Medium | Model candidate | INV-1 |\n",
    )
    _write(
        scratchpad / "finding_mapping.md",
        "# Finding Mapping\n\n"
        "| Finding ID | Hypothesis ID | Mapping Status |\n"
        "|---|---|---|\n"
        "| INV-1 | H-1 | GROUPED |\n",
    )
    _write(
        scratchpad / "enabler_results.md",
        "# Enabler Results\n\n"
        "**Status**: MODEL_ANALYZED\n\n"
        "No proof authority; candidate retained for verification.\n",
    )
    commit_issues = DRIVER._record_typed_model_phase_artifacts(
        phase, scratchpad, config
    )
    assert commit_issues == [], commit_issues


def _prepare_projection(
    project: Path,
    scratchpad: Path,
    *,
    backend: str = "claude",
) -> dict[str, Any]:
    return prepare_preverify_chain_pair_projection(
        scratchpad=scratchpad,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend=backend,
        phase_name="sc_verify_queue",
        run_id=RUN_ID,
    )


def _commit_registered_dynamic_chain_owner(
    project: Path,
    scratchpad: Path,
    *,
    backend: str,
    outputs: Sequence[str],
) -> str:
    for relative in AUTH_INPUTS:
        if not (scratchpad / relative).exists():
            _write(scratchpad / relative, "{}\n")
    config = _config(project, backend=backend)
    contract, launch = DRIVER._p1dm_contract_and_launch(
        scratchpad,
        config,
        phase_name="chain",
        work_unit_id="worker.arm_before_trust",
        phase=_chain_phase(),
        exact_inputs=AUTH_INPUTS,
        exact_outputs=outputs,
        actor="MODEL",
    )
    record_work_unit_inputs(
        scratchpad,
        project,
        contract,
        launch,
        run_id=RUN_ID,
    )
    assert validate_work_unit_inputs(
        scratchpad,
        project,
        contract,
        launch,
        run_id=RUN_ID,
    ) == []
    for relative in outputs:
        if relative == "hypotheses.md":
            _write(
                scratchpad / relative,
                "# Hypotheses\n\n| Hypothesis | Constituents |\n"
                "|---|---|\n| H-1 | INV-1 |\n",
            )
        elif relative == "finding_mapping.md":
            _write(
                scratchpad / relative,
                "# Finding Mapping\n\n| Hypothesis | Source Findings |\n"
                "|---|---|\n| H-1 | INV-1 |\n",
            )
        else:
            _write(scratchpad / relative, f"# {relative}\n")
    record_work_unit_artifacts(
        scratchpad,
        project,
        contract,
        launch,
        run_id=RUN_ID,
        actor="MODEL",
    )
    assert validate_work_unit_artifacts(
        scratchpad,
        project,
        contract,
        launch,
        run_id=RUN_ID,
        actor="MODEL",
    ) == []
    return contract.key


def test_summary_compaction_is_driver_owned_with_exact_live_source_roster(
    tmp_path: Path,
) -> None:
    project, scratchpad = _root(tmp_path)
    _write(scratchpad / "_v2_checkpoint.json", "{}\n")
    _write(
        scratchpad / "depth_alpha_findings.md",
        "# Depth\n\n## Chain Summary\n\n- alpha\n",
    )
    _write(
        scratchpad / "niche_beta_findings.md",
        "# Niche\n\n## Chain Summary\n\n- beta\n",
    )
    _write(
        scratchpad / "unregistered_notes.md",
        "# Notes\n\n## Chain Summary\n\n- must not enter denominator\n",
    )
    config = _config(project)

    assert DRIVER._run_chain_summary_compaction_transaction(
        scratchpad, config
    ) == []

    key = "sc/thorough/evm/claude/chain/summary_compaction"
    unit = read_artifact_ledger(scratchpad)["work_units"][key]
    manifest = unit["contract_manifest"]
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert manifest["model_invoked"] is False
    assert manifest["immutable_inputs"] == [
        "scratchpad:_v2_checkpoint.json",
        "scratchpad:depth_alpha_findings.md",
        "scratchpad:niche_beta_findings.md",
    ]
    assert manifest["outputs"] == [{
        "artifact_class": "DRIVER_GENERATED",
        "condition_id": "",
        "consumers": ["chain/model"],
        "identity": "scratchpad:chain_summaries_compact.md",
        "minimum_gate": "EXACT_CHAIN_SUMMARY_SOURCE_DENOMINATOR",
        "owner_key": key,
        "schema_version": "unstructured.v1",
        "write_mode": "REPLACE",
        "writer": "DRIVER",
    }]


def test_scaffold_roots_share_one_exact_driver_owner(tmp_path: Path) -> None:
    project, scratchpad = _root(tmp_path)
    _write(
        scratchpad / "findings_inventory.md",
        "# Findings\n\n### Finding [INV-1]: Fixture\n**Severity**: Medium\n",
    )
    config = _config(project)

    written, issues = DRIVER._run_chain_scaffold_transaction(
        scratchpad, config
    )

    assert issues == []
    assert set(written) == set(CHAIN_OUTPUTS)
    bindings = _bindings(scratchpad)
    owners = {
        bindings["scratchpad:" + relative]["owner_key"]
        for relative in CHAIN_OUTPUTS
    }
    assert owners == {"sc/thorough/evm/claude/chain/scaffold"}
    assert {
        bindings["scratchpad:" + relative]["writer"]
        for relative in CHAIN_OUTPUTS
    } == {"DRIVER"}


def test_enabler_prefill_is_split_from_durable_state_resolution_roots(
    tmp_path: Path,
) -> None:
    project, scratchpad = _root(tmp_path)
    config = _seed_chain_inputs(project, scratchpad)
    scaffold_enabler = _bindings(scratchpad)[
        "scratchpad:enabler_results.md"
    ]["owner_key"]
    assert scaffold_enabler.endswith("/chain/scaffold")

    _commit_state_resolution(project, scratchpad, config)

    required_static = {
        "chain_candidate_pairs.md",
        "chain_candidate_pairs_full.md",
        "variable_finding_map.md",
        "chain_enabler_baseline.md",
    }
    assert required_static <= set(DRIVER._CHAIN_TAIL_INITIALIZATION_OUTPUTS)
    assert "enabler_results.md" not in DRIVER._CHAIN_TAIL_INITIALIZATION_OUTPUTS
    bindings = _bindings(scratchpad)
    for relative in required_static:
        binding = bindings["scratchpad:" + relative]
        assert binding["owner_key"].endswith("/chain/state_resolution")
        assert binding["writer"] == "DRIVER"
        assert binding["write_mode"] == "REPLACE"
    prefill = bindings["scratchpad:enabler_results.md"]
    assert prefill["owner_key"].endswith(
        "/chain/state_resolution_enabler_prefill"
    )
    assert prefill["history"][-1]["owner_key"] == scaffold_enabler


def test_enabler_prefill_output_before_commit_resumes_exact_generation(
    tmp_path: Path,
) -> None:
    project, scratchpad = _root(tmp_path)
    config = _seed_chain_inputs(project, scratchpad)
    phase = _chain_phase()
    execute, issues = DRIVER._arm_chain_enabler_prefill_phase_io(
        scratchpad=scratchpad,
        config=config,
        phase=phase,
    )
    assert execute is True
    assert issues == []
    body = (
        "# Enabler Results\n\n"
        "**Status**: DRIVER_PREFILL\n\n"
        "Exact deterministic STEP-0a denominator.\n"
    )
    _write(scratchpad / "enabler_results.md", body)

    replay_execute, replay_issues = (
        DRIVER._arm_chain_enabler_prefill_phase_io(
            scratchpad=scratchpad,
            config=config,
            phase=phase,
        )
    )

    assert replay_execute is True
    assert replay_issues == []
    assert DRIVER._commit_chain_enabler_prefill_phase_io(
        scratchpad=scratchpad,
        config=config,
        phase=phase,
    ) == []
    assert (scratchpad / "enabler_results.md").read_text(
        encoding="utf-8"
    ) == body
    binding = _bindings(scratchpad)["scratchpad:enabler_results.md"]
    assert binding["owner_key"].endswith(
        "/chain/state_resolution_enabler_prefill"
    )
    assert binding["history"][-1]["owner_key"].endswith("/chain/scaffold")


def test_chain_model_contract_separates_inputs_from_replaced_output_roots(
    tmp_path: Path,
) -> None:
    project, scratchpad = _root(tmp_path)
    config = _seed_chain_inputs(project, scratchpad)
    _commit_state_resolution(project, scratchpad, config)
    phase = _chain_phase()

    contract, _launch = DRIVER._typed_model_phase_contract_and_launch(
        phase, scratchpad, config
    )

    expected_inputs = {
        "scratchpad:_v2_checkpoint.json",
        "scratchpad:findings_inventory.md",
        "scratchpad:chain_summaries_compact.md",
        "scratchpad:attack_surface.md",
        "scratchpad:chain_enabler_baseline.md",
        "scratchpad:confidence_scores.md",
        "scratchpad:depth_alpha_findings.md",
        "scratchpad:depth_beta_findings.md",
    }
    assert set(contract.immutable_inputs) == expected_inputs
    assert {
        (spec.path, spec.writer, spec.write_mode, spec.owner_key)
        for spec in contract.outputs
    } == {
        (relative, "MODEL", "REPLACE", contract.key)
        for relative in CHAIN_OUTPUTS
    }
    assert registered_projection_handoff(
        "sc/thorough/evm/claude/chain/scaffold",
        contract.key,
        "scratchpad:hypotheses.md",
    )
    assert registered_projection_handoff(
        "sc/thorough/evm/claude/chain/scaffold",
        contract.key,
        "scratchpad:finding_mapping.md",
    )
    assert registered_projection_handoff(
        "sc/thorough/evm/claude/chain/state_resolution_enabler_prefill",
        contract.key,
        "scratchpad:enabler_results.md",
    )
    assert not registered_projection_handoff(
        "sc/thorough/evm/claude/chain/state_resolution",
        contract.key,
        "scratchpad:enabler_results.md",
    )


def test_chain_model_replaces_scaffold_and_prep_roots_under_one_model_owner(
    tmp_path: Path,
) -> None:
    project, scratchpad = _root(tmp_path)
    config = _seed_chain_inputs(project, scratchpad)
    _commit_state_resolution(project, scratchpad, config)
    phase = _chain_phase()
    contract, _launch = DRIVER._typed_model_phase_contract_and_launch(
        phase, scratchpad, config
    )
    state_contract, state_launch = (
        DRIVER._chain_state_resolution_contract_and_launch(
            scratchpad=scratchpad,
            config=config,
            phase=phase,
        )
    )
    baseline_before = dict(
        _bindings(scratchpad)["scratchpad:chain_enabler_baseline.md"]
    )

    _commit_chain_model(project, scratchpad, config)
    bindings = _bindings(scratchpad)
    assert {
        bindings["scratchpad:" + relative]["owner_key"]
        for relative in CHAIN_OUTPUTS
    } == {contract.key}
    assert validate_work_unit_inputs(
        scratchpad,
        project,
        state_contract,
        state_launch,
        run_id=RUN_ID,
    ) == []
    assert validate_work_unit_artifacts(
        scratchpad,
        project,
        state_contract,
        state_launch,
        run_id=RUN_ID,
        actor="DRIVER",
    ) == []
    baseline_after = bindings["scratchpad:chain_enabler_baseline.md"]
    assert baseline_after["owner_key"] == baseline_before["owner_key"]
    assert baseline_after["sha256"] == baseline_before["sha256"]
    assert {
        bindings["scratchpad:" + relative]["writer"]
        for relative in CHAIN_OUTPUTS
    } == {"MODEL"}


def test_provider_rejects_common_arbitrary_same_run_chain_owner(
    tmp_path: Path,
) -> None:
    project, scratchpad = _root(tmp_path)
    owner = _commit_registered_dynamic_chain_owner(
        project,
        scratchpad,
        backend="claude",
        outputs=PAIR,
    )
    assert owner.endswith("/chain/worker.arm_before_trust")

    result = _prepare_projection(project, scratchpad)

    assert result["state"] == "DEGRADED_INPUT_AUTHORITY"
    assert result["safe_to_consume"] is False
    assert result["logical_to_physical"] == {}
    assert result["debt"][0]["reason_code"] == (
        "FINAL_CHAIN_PAIR_AUTHORITY_UNAVAILABLE"
    )


def test_provider_rejects_split_same_run_registered_chain_owners(
    tmp_path: Path,
) -> None:
    project, scratchpad = _root(tmp_path)
    hypotheses_owner = _commit_registered_dynamic_chain_owner(
        project,
        scratchpad,
        backend="claude",
        outputs=("hypotheses.md",),
    )
    mapping_owner = _commit_registered_dynamic_chain_owner(
        project,
        scratchpad,
        backend="codex",
        outputs=("finding_mapping.md",),
    )
    assert hypotheses_owner != mapping_owner
    assert hypotheses_owner.endswith("/chain/worker.arm_before_trust")
    assert mapping_owner.endswith("/chain/worker.arm_before_trust")

    result = _prepare_projection(project, scratchpad)

    assert result["state"] == "DEGRADED_INPUT_AUTHORITY"
    assert result["safe_to_consume"] is False
    assert result["logical_to_physical"] == {}
    assert result["debt"][0]["reason_code"] == (
        "FINAL_CHAIN_PAIR_AUTHORITY_UNAVAILABLE"
    )


def test_provider_accepts_only_real_chain_model_then_journaled_pair_successor(
    tmp_path: Path,
) -> None:
    project, scratchpad = _root(tmp_path)
    config = _seed_chain_inputs(project, scratchpad)
    _commit_state_resolution(project, scratchpad, config)
    _commit_chain_model(project, scratchpad, config)

    model_projection = _prepare_projection(project, scratchpad)
    assert model_projection["state"] == "OUTPUT_COMMITTED"
    model_owners = {
        _bindings(scratchpad)["scratchpad:" + relative]["owner_key"]
        for relative in PAIR
    }
    assert model_owners == {"sc/thorough/evm/claude/chain/model"}

    before = {
        relative: (scratchpad / relative).read_bytes()
        for relative in PAIR
    }

    def derive(_root: Path):
        return ["DA-2"], {
            "hypotheses.md": (
                before["hypotheses.md"]
                + b"| H-2 | Medium | Recovered candidate | DA-2 |\n"
            ),
            "finding_mapping.md": (
                before["finding_mapping.md"]
                + b"| DA-2 | H-2 | AUTO_MAPPED_DEPTH |\n"
            ),
        }

    successor = run_chain_pair_auto_map_transaction(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
        derive=derive,
    )
    assert successor["state"] == "OUTPUT_COMMITTED"
    assert successor["safe_to_project"] is True
    successor_owners = {
        _bindings(scratchpad)["scratchpad:" + relative]["owner_key"]
        for relative in PAIR
    }
    assert len(successor_owners) == 1
    successor_owner = next(iter(successor_owners))
    assert successor_owner.startswith(
        "sc/thorough/evm/claude/chain/final_pair_auto_map_apply."
    )

    successor_projection = _prepare_projection(project, scratchpad)
    assert successor_projection["state"] == "OUTPUT_COMMITTED"
    assert successor_projection["safe_to_consume"] is True
