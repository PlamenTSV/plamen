"""P0-AE report-index transaction-boundary acceptance fixtures.

These tests exercise the live prework/model/routing seams without changing
runtime behavior.  The final source-order fixture prevents a parent phase from
being committed before its deterministic routing children are recorded.
"""
from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from artifact_ledger import read_artifact_ledger
from phase_contract_compiler import extract_compiled_phase_io
from phase_io_contracts import resolve_phase_io_contract
import plamen_driver as D
from plamen_prompt import build_phase_prompt, plamen_home
from plamen_types import SC_PHASES


def _config(tmp_path: Path, *, backend: str = "claude") -> dict:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir(parents=True, exist_ok=True)
    return {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": backend,
        "scratchpad": str(scratchpad),
        "project_root": str(tmp_path),
        "proven_only": False,
        "_run_id": "report-index-p0-ae-test",
    }


def _seed_authenticated_empty_t9(config: dict) -> None:
    """Commit the empty queue through the production T0--T9 transaction."""

    from plamen_parsers import render_verification_queue_work_item_markdown
    from queue_work_items import build_queue_work_plan, queue_records_to_json
    import test_live_verify_queue_transaction_semantic_closure as LIVE
    import verify_queue_transaction as TRANSACTION

    backend = config["cli_backend"]
    run_id = f"live-sc-{backend}"
    config["_run_id"] = run_id
    scratchpad = Path(config["scratchpad"])
    project_root = Path(config["project_root"])
    plan = LIVE._plan("sc", backend)
    LIVE._seed_inputs(scratchpad, project_root, "sc", backend)

    class _EmptyQueueExecutor(LIVE._LiveSemanticExecutor):
        def _public_bytes(self) -> dict[str, bytes]:
            rows = super()._public_bytes()
            items = ()
            work_plan = build_queue_work_plan(
                items,
                {"fixture-0": ()},
                planner_version="report-index-empty-t9-fixture-v1",
            )
            rows["verification_queue.work_items.json"] = (
                queue_records_to_json(items) + "\n"
            ).encode("utf-8")
            rows["verification_queue.work_plan.json"] = (
                work_plan.to_json() + "\n"
            ).encode("utf-8")
            rows["verification_queue.md"] = (
                render_verification_queue_work_item_markdown(items)
                .encode("utf-8")
            )
            return rows

    result = TRANSACTION.execute_live_verify_queue_transaction(
        scratchpad=scratchpad,
        project_root=project_root,
        plan=plan,
        run_id=run_id,
        semantic_executor=_EmptyQueueExecutor(plan),
    )
    assert result["state"] == "OUTPUT_COMMITTED"
    decision = TRANSACTION.validate_live_verify_queue_publication(
        scratchpad=scratchpad,
        project_root=project_root,
        plan=plan,
        run_id=run_id,
    )
    assert decision["safe_to_consume"] is True, decision["issues"]
    assert (
        scratchpad
        / "_live_verify_queue_transaction"
        / "t0"
        / "resolved_plan.json"
    ).is_file()


def _contract(config: dict, work_unit_id: str, **kwargs):
    return resolve_phase_io_contract(
        pipeline=config["pipeline"],
        mode=config["mode"],
        ecosystem=config["language"],
        backend=config["cli_backend"],
        phase="report_index",
        work_unit_id=work_unit_id,
        **kwargs,
    )


def _seed_nonconditional_prework_outputs(config: dict, monkeypatch) -> None:
    # This file isolates generic report-prework output/conditional ordering.
    # R10 production input authority is exercised by test_r10_demotion_gate.
    monkeypatch.setattr(
        D, "_r10_report_prework_input_paths", lambda *_args, **_kwargs: ()
    )
    monkeypatch.setattr(
        D, "_r10_report_prework_authority_issues", lambda *_args, **_kwargs: []
    )
    scratchpad = Path(config["scratchpad"])
    contract = _contract(config, "prework")
    for name in (
        "verification_queue.md", "finding_mapping.md", "dedup_decisions.md",
    ):
        (scratchpad / name).write_text(f"# {name}\n", encoding="utf-8")
    execute, issues = D._arm_report_index_prework_artifacts(
        scratchpad, config
    )
    assert execute and issues == []
    for spec in contract.outputs:
        if spec.artifact_class == "CONDITIONAL":
            continue
        path = scratchpad / spec.path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n" if path.suffix == ".json" else "# typed prework\n", encoding="utf-8")


def _work_unit_record(config: dict, work_unit_id: str) -> dict:
    ledger = read_artifact_ledger(Path(config["scratchpad"]))
    return ledger["work_units"][_contract(config, work_unit_id).key]


def _seed_routable_empty_report_index(config: dict, monkeypatch) -> Path:
    """Produce the genuine empty canonical head consumed by routing."""

    # This fixture isolates routing ownership. Exact R10 prework authority is
    # covered by test_r10_demotion_gate and is intentionally neutralized here.
    monkeypatch.setattr(
        D, "_r10_report_consumer_ready_issues", lambda *_args, **_kwargs: []
    )
    import plamen_mechanical as mechanical
    monkeypatch.setattr(
        mechanical, "successor_projection_present", lambda *_args: False
    )
    scratchpad = Path(config["scratchpad"])
    _seed_authenticated_empty_t9(config)
    phase = next(item for item in SC_PHASES if item.name == "report_index")
    for name, payload in {
        "report_index_coverage_seed.md": "# Coverage Seed\n",
        "candidate_semantic_facets.md": "# Candidate Facets\n",
        "candidate_semantic_facets.json": "{}\n",
    }.items():
        (scratchpad / name).write_text(payload, encoding="utf-8")
    assert D._bind_typed_model_phase_inputs(phase, scratchpad, config) == []
    (scratchpad / "report_index.md").write_text(
        "# Report Index\n\nNo reportable findings.\n",
        encoding="utf-8",
    )
    (scratchpad / "report_coverage.md").write_text(
        "# Report Coverage\n\nNo reportable findings.\n",
        encoding="utf-8",
    )
    _model, model_issues = D._record_report_index_model_preimage(
        phase, scratchpad, config
    )
    assert model_issues == []
    assert D._run_report_index_canonicalization_transaction(
        phase, scratchpad, config
    ) == []
    return scratchpad


def test_prework_records_not_triggered_for_every_zero_denominator(
    tmp_path: Path, monkeypatch
):
    config = _config(tmp_path)
    _seed_nonconditional_prework_outputs(config, monkeypatch)

    issues = D._record_report_index_prework_artifacts(
        Path(config["scratchpad"]),
        config,
        severity_denominator=0,
        status_denominator=0,
        external_gap_denominator=0,
    )

    assert issues == []
    records = _work_unit_record(config, "prework")["artifacts"]
    conditional = {
        identity: record["conditional_receipt"]
        for identity, record in records.items()
        if record["artifact_class"] == "CONDITIONAL"
    }
    assert set(conditional) == {
        "scratchpad:severity_binding.md",
        "scratchpad:status_binding.md",
        "scratchpad:external_research_gaps.md",
    }
    assert {receipt["state"] for receipt in conditional.values()} == {
        "NOT_TRIGGERED"
    }
    assert {receipt["expected_denominator"] for receipt in conditional.values()} == {0}
    assert all(not receipt["produced_identities"] for receipt in conditional.values())


def test_prework_missing_triggered_output_is_failed_and_visible_as_debt(
    tmp_path: Path, monkeypatch
):
    config = _config(tmp_path)
    _seed_nonconditional_prework_outputs(config, monkeypatch)

    issues = D._record_report_index_prework_artifacts(
        Path(config["scratchpad"]),
        config,
        severity_denominator=3,
        status_denominator=0,
        external_gap_denominator=0,
    )

    assert any(
        "scratchpad:severity_binding.md" in issue
        and "valid absent-state receipt" in issue
        for issue in issues
    )
    record = _work_unit_record(config, "prework")["artifacts"][
        "scratchpad:severity_binding.md"
    ]
    receipt = record["conditional_receipt"]
    assert record["status"] == "MISSING"
    assert receipt["state"] == "FAILED"
    assert receipt["expected_denominator"] == 3
    assert receipt["failure_ids"] == ["expected_output_missing"]


def test_report_index_model_contract_has_only_exact_model_owned_outputs(tmp_path: Path):
    config = _config(tmp_path)
    contract = _contract(config, "model")

    assert {spec.identity for spec in contract.outputs} == {
        "scratchpad:report_index.md",
        "scratchpad:report_coverage.md",
    }
    assert {spec.writer for spec in contract.outputs} == {"MODEL"}
    assert {spec.artifact_class for spec in contract.outputs} == {"REQUIRED"}
    assert contract.model_invoked is True
    assert not any("*" in spec.path for spec in contract.outputs)


def test_report_index_routing_records_exact_driver_owned_nested_outputs(
    tmp_path: Path, monkeypatch
):
    config = _config(tmp_path, backend="codex")
    scratchpad = _seed_routable_empty_report_index(config, monkeypatch)
    real_canonical = D._report_index_canonical_contract_and_launch
    canonical_calls = 0

    def counted_canonical(*args, **kwargs):
        nonlocal canonical_calls
        canonical_calls += 1
        return real_canonical(*args, **kwargs)

    monkeypatch.setattr(
        D, "_report_index_canonical_contract_and_launch", counted_canonical
    )
    manifests, issues = D._run_report_index_routing_transaction(
        scratchpad, config
    )
    assert issues == []
    assert canonical_calls == 1
    outputs = (
        "report_records.json",
        *(f"body_manifests/{name}.json" for name in sorted(manifests)),
    )
    (scratchpad / "body_manifests" / "README.md").write_text(
        "not a routing record\n", encoding="utf-8"
    )

    contract = _contract(config, "routing", exact_outputs=outputs)
    ledger = read_artifact_ledger(scratchpad)
    unit = ledger["work_units"][contract.key]
    records = unit["artifacts"]
    assert set(records) == {f"scratchpad:{path}" for path in outputs}
    assert {record["writer"] for record in records.values()} == {"DRIVER"}
    assert {record["artifact_class"] for record in records.values()} == {
        "DRIVER_GENERATED"
    }
    assert {record["owner_key"] for record in records.values()} == {contract.key}
    assert "scratchpad:body_manifests/README.md" not in records


@pytest.mark.parametrize("extra_name", ["report_medium", "report_low_info"])
def test_report_index_routing_rejects_plan_change_during_materialization(
    tmp_path: Path, monkeypatch, extra_name: str
):
    config = _config(tmp_path, backend="codex")
    scratchpad = _seed_routable_empty_report_index(config, monkeypatch)
    real_builder = D._build_sc_body_writer_manifests
    calls: list[tuple[bool, bool]] = []

    def changed_after_arm(*args, **kwargs):
        built = real_builder(*args, **kwargs)
        persist = bool(kwargs.get("persist", True))
        materialize = bool(kwargs.get("materialize_evidence", True))
        calls.append((persist, materialize))
        if persist:
            # Simulate a changed deterministic denominator at the exact
            # materialization barrier while retaining the real delegate's
            # reads, validation, and writes.
            built = dict(built)
            built[extra_name] = {
                "schema_version": "plamen.report_body_manifest.v1",
                "findings": [],
                "shard": extra_name,
            }
        return built

    monkeypatch.setattr(
        D, "_build_sc_body_writer_manifests", changed_after_arm
    )
    _manifests, issues = D._run_report_index_routing_transaction(
        scratchpad, config
    )

    assert issues == [
        "report-index routing plan changed during materialization"
    ]
    assert calls == [(False, False), (True, False)]
    routing_contract = _contract(
        config, "routing", exact_outputs=(
            "report_records.json", "body_manifests/report_empty.json",
        ),
    )
    routing = read_artifact_ledger(scratchpad)["work_units"][routing_contract.key]
    assert routing["execution_state"] == "INPUTS_BOUND_PREEXECUTION"


def test_empty_report_routing_emits_explicit_records_envelope(
    tmp_path: Path, monkeypatch
):
    # This fixture isolates the empty routing envelope, not R10 ancestry.
    monkeypatch.setattr(
        D, "_r10_report_consumer_ready_issues", lambda *_args, **_kwargs: []
    )
    import plamen_mechanical as mechanical
    monkeypatch.setattr(
        mechanical, "successor_projection_present", lambda *_args: False
    )
    config = _config(tmp_path, backend="codex")
    scratchpad = Path(config["scratchpad"])
    _seed_authenticated_empty_t9(config)
    phase = next(item for item in SC_PHASES if item.name == "report_index")
    for name, payload in {
        "report_index_coverage_seed.md": "# Coverage Seed\n",
        "candidate_semantic_facets.md": "# Candidate Facets\n",
        "candidate_semantic_facets.json": "{}\n",
    }.items():
        (scratchpad / name).write_text(payload, encoding="utf-8")
    assert D._bind_typed_model_phase_inputs(
        phase, scratchpad, config
    ) == []
    (scratchpad / "report_index.md").write_text(
        "# Report Index\n\nNo reportable findings.\n", encoding="utf-8"
    )
    (scratchpad / "report_coverage.md").write_text(
        "# Report Coverage\n\nNo reportable findings.\n", encoding="utf-8"
    )
    _model, model_issues = D._record_report_index_model_preimage(
        phase, scratchpad, config
    )
    assert model_issues == []
    assert D._run_report_index_canonicalization_transaction(
        phase, scratchpad, config
    ) == []

    manifests, issues = D._run_report_index_routing_transaction(
        scratchpad, config
    )
    assert issues == []
    assert manifests == {
        "report_empty": {
            "schema_version": "plamen.empty_report_denominator.v1",
            "denominator_state": "EMPTY",
            "findings": [],
            "shard": "report_empty",
        }
    }
    payload = json.loads(
        (scratchpad / "report_records.json").read_text(encoding="utf-8")
    )
    assert payload["active"] == []
    assert payload["excluded"] == []


def test_live_report_index_prompt_compiles_exact_output_and_immutable_input_contract(
    tmp_path: Path,
):
    config = _config(tmp_path)
    phase = next(item for item in SC_PHASES if item.name == "report_index")

    prompt = build_phase_prompt(
        plamen_home() / "commands" / "plamen.md",
        phase,
        config,
    )
    payload = extract_compiled_phase_io(prompt)
    contract = _contract(config, "model")

    assert payload["contract_digest"] == contract.digest
    assert payload["work_unit_key"] == "sc/thorough/evm/claude/report_index/model"
    assert payload["actor"] == "MODEL"
    assert payload["allowed_outputs"] == [
        "scratchpad:report_coverage.md",
        "scratchpad:report_index.md",
    ]
    assert payload["immutable_inputs"] == list(contract.immutable_inputs)
    assert set(payload["immutable_inputs"]) >= {
        "scratchpad:verification_queue.md",
        "scratchpad:report_index_coverage_seed.md",
        "scratchpad:candidate_semantic_facets.json",
        "scratchpad:severity_binding.md",
        "scratchpad:status_binding.md",
        "scratchpad:external_research_gaps.md",
    }


def test_report_routing_and_typed_records_precede_parent_artifact_state_and_commit():
    """The parent transaction cannot commit before its routing children exist."""

    source = inspect.getsource(D.main)
    commit_boundary_at = source.rfind("_commit_phase_from_disk_debt(")
    assert commit_boundary_at >= 0, "main no longer invokes the typed commit boundary"

    typed_model_at = source.rfind(
        "_record_typed_model_phase_artifacts(", 0, commit_boundary_at
    )
    routing_transaction_at = source.rfind(
        "_run_report_index_routing_transaction(", 0, commit_boundary_at
    )

    assert typed_model_at >= 0, (
        "accepted report_index model outputs must be typed before parent recording"
    )
    assert routing_transaction_at >= 0, (
        "report routing outputs must be planned, built, and typed before "
        "parent recording"
    )
    assert (
        typed_model_at
        < routing_transaction_at
        < commit_boundary_at
    )
    helper_source = inspect.getsource(D._commit_phase_from_disk_debt)
    artifact_state_at = helper_source.index("_record_phase_artifact_state(")
    commit_at = helper_source.index("PhaseCommitController(", artifact_state_at)
    assert artifact_state_at < commit_at, (
        "PhaseCommitController commit must follow parent artifact-state recording"
    )
