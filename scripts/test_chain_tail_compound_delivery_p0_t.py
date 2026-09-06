"""P0-T downstream closure: typed compositions reach ordinary verification."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import chain_tail_authority as CTA
import plamen_driver as D
import plamen_parsers as P
import plamen_validators as PV
import verification_method_compiler as V
from plamen_types import Phase
from verifier_work_roster import (
    build_verifier_runtime_policy,
    build_verifier_work_roster,
)


def _pair() -> dict[str, object]:
    return {
        "a": "H-1", "b": "M-1", "a_sev": "High", "b_sev": "Medium",
        "signal": "state-graph: shared transition", "score": 9.0,
        "graph_backed": True,
    }


def _queue_rows() -> list[dict[str, str]]:
    return [
        {
            "queue #": str(index), "finding id": work_id,
            "expected output file": f"verify_{work_id}.md", "severity": severity,
            "title": f"Constituent {work_id}", "bug class": "state-transition",
            "preferred tag": "CODE-TRACE", "location": f"src/state.rs:{index}",
            "primary artifact": "findings_inventory.md", "poc class": "structural",
        }
        for index, (work_id, severity) in enumerate(
            (("H-1", "High"), ("M-1", "Medium")), start=1
        )
    ]


def _composition_output(
    row: dict,
    heading: str,
    evidence: str = "CH-77 links the exact postcondition to the dependent precondition.",
) -> str:
    return (
        f"{heading}\n\n"
        "## Tail Pair Dispositions\n\n"
        "| Pair ID | Finding A | Finding B | Disposition | Evidence |\n"
        "|---|---|---|---|---|\n"
        f"| {row['pair_id']} | {row['a']} | {row['b']} | COMPOSED | "
        f"{evidence} |\n"
    )


def _phase() -> Phase:
    return Phase(
        "chain_iter2",
        ["Phase 4c Iteration 2: Chain Composition Re-evaluation"],
        ["chain_iteration2.md"],
        base_timeout_s=30,
        modes={"thorough"},
        critical=False,
        model="sonnet",
    )


def _materialize_state_resolution_denominator(scratch: Path) -> None:
    """Supply non-tail state artifacts now owned by state resolution."""

    for relative in D._CHAIN_TAIL_INITIALIZATION_OUTPUTS:
        path = scratch / relative
        if path.is_file():
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        body = (
            '{"schema_version":"fixture.chain-state-resolution.v1"}\n'
            if path.suffix == ".json"
            else f"# Fixture state-resolution output: {relative}\n"
        )
        path.write_text(body, encoding="utf-8")


def _publish_composition_candidate(
    tmp_path: Path,
    scratch: Path,
    *,
    heading: str,
    evidence: str,
    inventory_text: str = "# Findings Inventory\n",
) -> None:
    (scratch / "findings_inventory.md").write_text(
        inventory_text, encoding="utf-8"
    )
    (scratch / "composition_coverage.md").write_text(
        "# Composition Coverage\n", encoding="utf-8"
    )
    (scratch / "chain_hypotheses.md").write_text(
        "# Chain Hypotheses\n", encoding="utf-8"
    )
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        # This fixture exercises publication/consumer authority, not Claude's
        # separate exact-write hook receipt (covered by the hook suite).
        "cli_backend": "codex",
        "project_root": str(tmp_path),
        "scratchpad": str(scratch),
        "_run_id": "chain-compound-publication",
        "_chain_state_resolution_initializes_tail": True,
    }
    (scratch / "config.json").write_text(
        json.dumps(config, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    phase = _phase()
    init_contract, init_launch = D._chain_state_resolution_contract_and_launch(
        scratchpad=scratch,
        config=config,
        phase=phase,
    )
    execute, issues = D._arm_deterministic_driver_work_unit(
        scratchpad=scratch,
        project_root=tmp_path,
        contract=init_contract,
        launch=init_launch,
        run_id=config["_run_id"],
    )
    assert execute is True
    assert issues == []
    tail_execute, tail_issues = D._arm_chain_tail_initial_phase_io(
        scratchpad=scratch,
        config=config,
        phase=phase,
    )
    assert tail_execute is True
    assert tail_issues == []
    (scratch / "chain_state_resolution.json").write_text(
        '{"schema_version":"plamen.chain_state_resolution.v1"}\n',
        encoding="utf-8",
    )
    CTA.initialize_chain_tail(
        scratch, [_pair()], shard_size=1, activate_first_shard=False
    )
    _materialize_state_resolution_denominator(scratch)
    assert D._commit_chain_tail_initial_phase_io(
        scratchpad=scratch,
        config=config,
        phase=phase,
    ) == []
    assert D._commit_deterministic_driver_work_unit(
        scratchpad=scratch,
        project_root=tmp_path,
        contract=init_contract,
        launch=init_launch,
        run_id=config["_run_id"],
    ) == []
    assert D._bind_typed_model_phase_inputs(phase, scratch, config) == []
    isolated = config["_chain_tail_active_isolated"]

    def fake_run(_phase, inner_config, _attempt):
        _write_path = Path(inner_config["scratchpad"]) / "chain_iteration2.md"
        _write_path.write_text(
            _composition_output(isolated["rows"][0], heading, evidence),
            encoding="utf-8",
        )
        return 0

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(D, "run_phase", fake_run)
        assert D._run_isolated_chain_tail_model_attempt(phase, config, 1) == 0
    receipt, final_issues = D._run_chain_tail_final_reconcile_transaction(
        scratch, config, phase
    )
    assert final_issues == []
    assert receipt["status"] == "COMPLETE"


def _publish_custom_chain_output(
    tmp_path: Path,
    scratch: Path,
    *,
    pairs: list[dict[str, object]],
    output_builder,
) -> None:
    (scratch / "findings_inventory.md").write_text(
        "# Findings Inventory\n", encoding="utf-8"
    )
    (scratch / "composition_coverage.md").write_text(
        "# Composition Coverage\n", encoding="utf-8"
    )
    (scratch / "chain_hypotheses.md").write_text(
        "# Chain Hypotheses\n", encoding="utf-8"
    )
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
        "project_root": str(tmp_path),
        "scratchpad": str(scratch),
        "_run_id": "chain-compound-custom-publication",
        "_chain_state_resolution_initializes_tail": True,
    }
    (scratch / "config.json").write_text(
        json.dumps(config, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    phase = _phase()
    init_contract, init_launch = D._chain_state_resolution_contract_and_launch(
        scratchpad=scratch,
        config=config,
        phase=phase,
    )
    execute, issues = D._arm_deterministic_driver_work_unit(
        scratchpad=scratch,
        project_root=tmp_path,
        contract=init_contract,
        launch=init_launch,
        run_id=config["_run_id"],
    )
    assert execute is True
    assert issues == []
    tail_execute, tail_issues = D._arm_chain_tail_initial_phase_io(
        scratchpad=scratch,
        config=config,
        phase=phase,
    )
    assert tail_execute is True
    assert tail_issues == []
    (scratch / "chain_state_resolution.json").write_text(
        '{"schema_version":"plamen.chain_state_resolution.v1"}\n',
        encoding="utf-8",
    )
    CTA.initialize_chain_tail(
        scratch,
        pairs,
        shard_size=max(1, len(pairs)),
        activate_first_shard=False,
    )
    _materialize_state_resolution_denominator(scratch)
    assert D._commit_chain_tail_initial_phase_io(
        scratchpad=scratch,
        config=config,
        phase=phase,
    ) == []
    assert D._commit_deterministic_driver_work_unit(
        scratchpad=scratch,
        project_root=tmp_path,
        contract=init_contract,
        launch=init_launch,
        run_id=config["_run_id"],
    ) == []
    assert D._bind_typed_model_phase_inputs(phase, scratch, config) == []
    isolated = config["_chain_tail_active_isolated"]

    def fake_run(_phase, inner_config, _attempt):
        path = Path(inner_config["scratchpad"]) / "chain_iteration2.md"
        path.write_text(output_builder(isolated["rows"]), encoding="utf-8")
        return 0

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(D, "run_phase", fake_run)
        assert D._run_isolated_chain_tail_model_attempt(
            phase, config, 1
        ) == 0
    receipt, final_issues = D._run_chain_tail_final_reconcile_transaction(
        scratch, config, phase
    )
    assert final_issues == []
    assert receipt["status"] == "COMPLETE"


@pytest.mark.parametrize(
    "heading",
    [
        "## Chain Hypothesis CH-77 - composed transition",
        "## CH-77 composed transition",
    ],
)
def test_typed_composed_candidate_reaches_plan_queue_and_roster_for_any_heading(
    tmp_path: Path, heading: str
) -> None:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    P._write_queue_subset_manifest(scratch / "verification_queue.md", _queue_rows())
    _publish_composition_candidate(
        tmp_path,
        scratch,
        heading=heading,
        evidence=(
            "CH-77 links the exact postcondition to the dependent precondition."
        ),
    )

    shards = P.ensure_sc_verify_shard_manifests(scratch)
    candidate_sidecar = json.loads(
        (scratch / CTA.COMPOSITION_CANDIDATES_NAME).read_text(encoding="utf-8")
    )
    assert candidate_sidecar["candidates"][0]["chain_id"] == "CH-77"
    assert candidate_sidecar["candidates"][0]["proof_authority"] == "NONE"
    typed = P._read_typed_queue_work_items(scratch / "verification_queue.md")
    assert [item.work_item_id for item in typed] == ["H-1", "M-1", "CH-77"]
    composed_item = typed[-1]
    assert composed_item.constituents == ("H-1", "M-1")
    assert any(
        "claim_sha256=" in location.artifact
        for location in composed_item.location_records
    )
    assert any(
        row.get("finding id") == "CH-77"
        for rows in shards.values() for row in rows
    )
    plan = P.read_queue_work_plan(scratch)
    assert "CH-77" in plan.ordered_work_item_ids
    compound = json.loads(
        (scratch / "compound_verification_work_plan.json").read_text(encoding="utf-8")
    )
    work = compound["compound_work_plan"]["work_items"][0]
    assert work["subject_id"] == "CH-77"
    assert work["readiness"] == "READY"
    delivery = json.loads(
        (scratch / "compound_verification_delivery_receipt.json").read_text(encoding="utf-8")
    )
    assert delivery["delivered_work_item_ids"] == ["CH-77"]
    assert delivery["proof_authority"] == "NONE"

    roster = build_verifier_work_roster(
        plan,
        pipeline="sc", ecosystem="evm", mode="thorough",
        runtime_policy=build_verifier_runtime_policy(
            backend="claude", model="opus", timeout_seconds=120,
            max_concurrency=2, source_root=str(tmp_path.resolve()), transport="pty",
        ),
        method_registry_digest="a" * 64,
        context_packet_digest="b" * 64,
    )
    assert "CH-77" in roster.ordered_work_item_ids


def test_composition_evidence_changes_every_downstream_semantic_authority(
    tmp_path: Path,
) -> None:
    snapshots = []
    for suffix, evidence in (
        ("a", "CH-77 binds the first exact state relation."),
        ("b", "CH-77 binds a different exact state relation."),
    ):
        scratch = tmp_path / suffix / ".scratchpad"
        scratch.mkdir(parents=True)
        P._write_queue_subset_manifest(scratch / "verification_queue.md", _queue_rows())
        _publish_composition_candidate(
            tmp_path / suffix,
            scratch,
            heading="## CH-77 composed transition",
            evidence=evidence,
        )
        P.ensure_sc_verify_shard_manifests(scratch)
        item = P._read_typed_queue_work_items(
            scratch / "verification_queue.md"
        )[-1]
        plan = P.read_queue_work_plan(scratch)
        shards = P.compute_sc_verify_shards(scratch)
        ch_row = next(
            value for rows in shards.values() for value in rows
            if value.get("finding id") == "CH-77"
        )
        packet_unsigned = {
            "packet_id": "VCTX-CH-77",
            "work_item_id": "CH-77",
            "state": "CONTEXT_UNRESOLVED",
            "seed_locations": [],
            "graph_matches": [],
            "expansion_candidates": [],
            "hub_truncated": False,
            "fanout_limit": 8,
            "primary_artifact_bindings": [
                {
                    "artifact": artifact,
                    "scope": None,
                    "status": "MISSING",
                    "sha256": None,
                    "size_bytes": None,
                }
                for artifact in item.primary_artifacts
            ],
            "primary_artifact_binding_complete": False,
            "graph_binding_complete": True,
        }
        packet = {
            **packet_unsigned,
            "packet_digest": V.stable_digest(packet_unsigned),
        }
        dispatch = V.compile_verification_method_dispatch(
            pipeline="sc", ecosystem="evm", backend="claude",
            rows=[item.to_dict()], context_packets={"CH-77": packet},
            manifest_path="verify_runtime.md", scratchpad_path="/scratch",
            root=Path(__file__).resolve().parent.parent,
        )
        snapshots.append((item.digest, plan.digest, ch_row, dispatch))

    assert snapshots[0][0] != snapshots[1][0]
    assert snapshots[0][1] != snapshots[1][1]
    assert snapshots[0][2]["constituents"] == "H-1,M-1"
    assert "claim_sha256=" in snapshots[0][2]["location"]
    assert snapshots[0][2]["location"] != snapshots[1][2]["location"]
    assert snapshots[0][3]["dispatch_id"] != snapshots[1][3]["dispatch_id"]
    assert snapshots[0][3]["prompt_sha256"] != snapshots[1][3]["prompt_sha256"]
    assert "claim_sha256=" in snapshots[0][3]["prompt_markdown"]
    assert '"constituents":["H-1","M-1"]' in snapshots[0][3]["prompt_markdown"]


def test_human_review_orphan_is_visible_without_blocking_ordinary_candidate(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    P._write_queue_subset_manifest(
        scratch / "verification_queue.md", _queue_rows()
    )
    _publish_composition_candidate(
        tmp_path,
        scratch,
        heading=(
            "## CH-77 composed transition\n\n"
            "Verified only as an unproven composition candidate.\n\n"
            "## CH-88 orphan hypothesis\n\n"
            "Unlinked model proposal retained for human review."
        ),
        evidence=(
            "CH-77 links the exact postcondition to the dependent precondition."
        ),
    )

    candidates = json.loads(
        (scratch / CTA.COMPOSITION_CANDIDATES_NAME).read_text(encoding="utf-8")
    )["candidates"]
    assert {
        (row["chain_id"], row["route"]) for row in candidates
    } == {
        ("CH-77", "ORDINARY_VERIFICATION"),
        ("CH-88", "HUMAN_REVIEW"),
    }
    assert CTA.validate_chain_tail_authority(scratch) == []
    P.ensure_sc_verify_shard_manifests(scratch)
    typed = P._read_typed_queue_work_items(
        scratch / "verification_queue.md"
    )
    assert [item.work_item_id for item in typed] == ["H-1", "M-1", "CH-77"]
    delivery = json.loads(
        (
            scratch / "compound_verification_delivery_receipt.json"
        ).read_text(encoding="utf-8")
    )
    assert delivery["delivered_work_item_ids"] == ["CH-77"]


def test_grouped_candidate_validates_and_delivers_union_of_all_composed_pairs(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    queue_rows = [
        {
            "queue #": str(index),
            "finding id": finding_id,
            "expected output file": f"verify_{finding_id}.md",
            "severity": severity,
            "title": f"Constituent {finding_id}",
            "bug class": "state-transition",
            "preferred tag": "CODE-TRACE",
            "location": f"src/state.rs:{index}",
            "primary artifact": "findings_inventory.md",
            "poc class": "structural",
        }
        for index, (finding_id, severity) in enumerate(
            (
                ("H-1", "High"),
                ("M-1", "Medium"),
                ("H-2", "High"),
                ("M-2", "Medium"),
            ),
            start=1,
        )
    ]
    P._write_queue_subset_manifest(
        scratch / "verification_queue.md", queue_rows
    )
    pairs = [
        _pair(),
        {
            "a": "H-2",
            "b": "M-2",
            "a_sev": "High",
            "b_sev": "Medium",
            "signal": "state-graph: second shared transition",
            "score": 8.5,
            "graph_backed": True,
        },
    ]

    def grouped_output(rows):
        lines = [
            "## CH-7 grouped composed transition",
            "",
            "**Constituent Findings**: H-1, M-1, H-2, M-2",
            "",
            "## Tail Pair Dispositions",
            "",
            "| Pair ID | Finding A | Finding B | Disposition | Evidence |",
            "|---|---|---|---|---|",
        ]
        lines.extend(
            f"| {row['pair_id']} | {row['a']} | {row['b']} | COMPOSED | "
            "CH-7 joins the exact dependent transitions. |"
            for row in rows
        )
        return "\n".join(lines) + "\n"

    _publish_custom_chain_output(
        tmp_path,
        scratch,
        pairs=pairs,
        output_builder=grouped_output,
    )

    candidate = json.loads(
        (scratch / CTA.COMPOSITION_CANDIDATES_NAME).read_text(encoding="utf-8")
    )["candidates"][0]
    assert len(candidate["pair_ids"]) == 2
    assert candidate["constituent_finding_ids"] == [
        "H-1",
        "M-1",
        "H-2",
        "M-2",
    ]
    assert CTA.validate_chain_tail_authority(scratch) == []
    P.ensure_sc_verify_shard_manifests(scratch)
    typed = P._read_typed_queue_work_items(
        scratch / "verification_queue.md"
    )
    grouped = next(item for item in typed if item.work_item_id == "CH-7")
    assert grouped.constituents == ("H-1", "M-1", "H-2", "M-2")


def test_pre_final_typed_candidate_cannot_enter_verification_queue(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    (scratch / "config.json").write_text(
        json.dumps(
            {
                "pipeline": "sc",
                "mode": "thorough",
                "language": "evm",
                "cli_backend": "codex",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    P._write_queue_subset_manifest(scratch / "verification_queue.md", _queue_rows())
    CTA.initialize_chain_tail(scratch, [_pair()])
    row = CTA.current_chain_tail_shard(scratch)["rows"][0]
    (scratch / "chain_iteration2.md").write_text(
        _composition_output(row, "## CH-77 composed transition"),
        encoding="utf-8",
    )
    CTA.reconcile_chain_tail_output(scratch)

    P.ensure_sc_verify_shard_manifests(scratch)

    typed = P._read_typed_queue_work_items(scratch / "verification_queue.md")
    assert [item.work_item_id for item in typed] == ["H-1", "M-1"]
    debt = json.loads(
        (scratch / "compound_verification_delivery_debt.json").read_text(
            encoding="utf-8"
        )
    )
    assert "committed final producer ancestry" in debt["error"]


def test_chain_composition_verification_then_r10_1_ordering(
    tmp_path: Path,
) -> None:
    prefinal = tmp_path / "prefinal" / ".scratchpad"
    prefinal.mkdir(parents=True)
    (prefinal / "config.json").write_text(
        json.dumps(
            {
                "pipeline": "sc",
                "mode": "thorough",
                "language": "evm",
                "cli_backend": "codex",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    P._write_queue_subset_manifest(
        prefinal / "verification_queue.md", _queue_rows()
    )
    CTA.initialize_chain_tail(prefinal, [_pair()])
    prefinal_row = CTA.current_chain_tail_shard(prefinal)["rows"][0]
    (prefinal / "chain_iteration2.md").write_text(
        _composition_output(
            prefinal_row,
            "## CH-77 composed transition",
        ),
        encoding="utf-8",
    )
    CTA.reconcile_chain_tail_output(prefinal)
    P.ensure_sc_verify_shard_manifests(prefinal)
    assert [
        item.work_item_id
        for item in P._read_typed_queue_work_items(
            prefinal / "verification_queue.md"
        )
    ] == ["H-1", "M-1"]
    assert PV._apply_external_assumption_undemotions(
        prefinal, "thorough"
    ) == []

    root = tmp_path / "final"
    scratch = root / ".scratchpad"
    scratch.mkdir(parents=True)
    P._write_queue_subset_manifest(
        scratch / "verification_queue.md", _queue_rows()
    )
    inventory = (
        "# Findings Inventory\n\n"
        "### Finding [H-1] Confirmed constituent\n\n"
        "**Severity**: High\n\n"
        "**Verdict**: CONFIRMED\n\n"
        "**Location**: `src/state.rs:1`\n\n"
        "**Description**: The state transition consumes a non-vendored "
        "dependency result. [EXTERNAL-ASSUMPTION: returned value may change] "
        "NEEDS_DEPENDENCY_RESEARCH: stability across calls.\n\n"
        "### Finding [M-1] Confirmed constituent\n\n"
        "**Severity**: Medium\n\n"
        "**Verdict**: CONFIRMED\n\n"
        "**Location**: `src/state.rs:2`\n\n"
        "**Description**: The dependent transition uses the same external "
        "result. [EXTERNAL-ASSUMPTION: returned value may change] "
        "NEEDS_DEPENDENCY_RESEARCH: stability across calls.\n"
    )
    _publish_composition_candidate(
        root,
        scratch,
        heading="## CH-77 composed transition",
        evidence=(
            "CH-77 links the exact postcondition to the dependent precondition."
        ),
        inventory_text=inventory,
    )
    P.ensure_sc_verify_shard_manifests(scratch)
    (scratch / "finding_mapping.md").write_text(
        "# Finding Mapping\n\n"
        "## INV Finding -> Hypothesis\n\n"
        "| Finding ID | Hypothesis ID | Mapping Status |\n"
        "|---|---|---|\n"
        "| H-1 | CH-77 | PRIMARY |\n"
        "| M-1 | CH-77 | CONSTITUENT |\n",
        encoding="utf-8",
    )
    (scratch / "hypotheses.md").write_text(
        "# Hypotheses\n", encoding="utf-8"
    )
    typed = P._read_typed_queue_work_items(
        scratch / "verification_queue.md"
    )
    composed = next(
        item for item in typed if item.work_item_id == "CH-77"
    )
    candidate = json.loads(
        (scratch / CTA.COMPOSITION_CANDIDATES_NAME).read_text(
            encoding="utf-8"
        )
    )["candidates"][0]
    assert candidate["proof_authority"] == "NONE"
    assert composed.constituents == ("H-1", "M-1")
    composed_severity = composed.severity_proposal.level
    queue_before = (scratch / "verification_queue.md").read_bytes()
    assert PV._apply_external_assumption_undemotions(
        scratch, "thorough"
    ) == []
    assert not (scratch / "external_assumption_undemotions.md").exists()

    (scratch / "external_dependency_research.md").write_text(
        "# External Dependency Research\n\n"
        "| Dependency | Integration Surface |\n"
        "|---|---|\n",
        encoding="utf-8",
    )
    verify_path = scratch / "verify_CH-77.md"
    verify_path.write_text(
        f"**Severity**: {composed_severity}\n\n"
        "**Verdict**: REFUTED\n\n"
        "**Location**: `src/state.rs:1`\n\n"
        "**Evidence Tag**: [CODE-TRACE]\n\n"
        "An external dependency exists, but the composition is REFUTED "
        "because an in-scope bound rejects every unsafe value.\n\n"
        "### PoC Attempt\n"
        "- PoC Required: YES\n"
        "- Attempted: NO\n"
        "- PoC Not Attempted Because: EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS\n\n"
        "### Execution Result\n"
        "- Result: NOT_EXECUTED\n",
        encoding="utf-8",
    )
    assert PV._apply_external_assumption_undemotions(
        scratch, "thorough"
    ) == []
    assert (scratch / "verification_queue.md").read_bytes() == queue_before
    assert not (scratch / "external_assumption_undemotions.md").exists()
    assert not (root / "AUDIT_REPORT.md").exists()
    assert not (scratch / "report_index.md").exists()

    verify_path.write_text(
        f"**Severity**: {composed_severity}\n\n"
        "**Verdict**: REFUTED\n\n"
        "**Location**: `src/state.rs:1`\n\n"
        "**Evidence Tag**: [CODE-TRACE]\n\n"
        "The local composition mechanism exists, but the finding is REFUTED "
        "because the external dependency's returned value is stable within "
        "a block; as long as that favorable condition holds, no harm can "
        "materialize. [EXTERNAL-ASSUMPTION: external returned value is "
        "stable within a block]\n\n"
        "### PoC Attempt\n"
        "- PoC Required: YES\n"
        "- Attempted: NO\n"
        "- PoC Not Attempted Because: EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS\n\n"
        "### Execution Result\n"
        "- Result: NOT_EXECUTED\n",
        encoding="utf-8",
    )
    verify_before_gate = verify_path.read_bytes()
    fired = PV._apply_external_assumption_undemotions(
        scratch, "thorough"
    )
    assert [row["finding_id"] for row in fired] == ["CH-77"]
    assert fired[0]["depth_verdict"] == "CONFIRMED"
    assert fired[0]["restored_floor"] == composed_severity
    assert (scratch / "verification_queue.md").read_bytes() == queue_before
    assert verify_path.read_bytes() == verify_before_gate
    receipt = json.loads(
        (scratch / "external_assumption_undemotions.json").read_text(
            encoding="utf-8"
        )
    )
    assert receipt["sequencing_state"] == "PRE_MECHANICAL_UNRECONCILED"
    assert receipt["rows"][0]["finding_id"] == "CH-77"
    assert receipt["rows"][0]["source_verify"]["byte_length"] == len(
        verify_before_gate
    )
    assert (scratch / "external_assumption_undemotions.md").is_file()
    assert not (root / "AUDIT_REPORT.md").exists()
    assert not (scratch / "report_index.md").exists()


def test_typed_delivery_failure_is_exact_visible_debt_without_markdown_fallback(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    P._write_queue_subset_manifest(scratch / "verification_queue.md", _queue_rows())
    CTA.initialize_chain_tail(scratch, [_pair()])
    sidecar = scratch / CTA.COMPOSITION_CANDIDATES_NAME
    payload = json.loads(sidecar.read_text(encoding="utf-8"))
    payload["candidate_digest"] = "0" * 64
    sidecar.write_text(json.dumps(payload), encoding="utf-8")
    (scratch / "chain_hypotheses.md").write_text(
        "## Chain Hypothesis CH-99\n\nThis must not become fallback authority.\n",
        encoding="utf-8",
    )
    before = (scratch / "verification_queue.md").read_bytes()

    result = P._deliver_compound_candidates_to_queue(scratch, "sc")

    assert result["status"] == "COMPLETED_WITH_DEBT"
    assert result["ordinary_verification_delivery_complete"] is False
    assert result["source_artifact"] == CTA.COMPOSITION_CANDIDATES_NAME
    assert len(result["receipt_digest"]) == 64
    assert (scratch / "verification_queue.md").read_bytes() == before
    assert not (scratch / "compound_verification_delivery_receipt.json").exists()


@pytest.mark.parametrize(
    "ensure",
    [P.ensure_sc_verify_shard_manifests, P.ensure_verify_shard_manifests],
)
def test_malformed_composed_authority_repairs_then_degrades_at_real_entrypoint(
    tmp_path: Path, ensure
) -> None:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    P._write_queue_subset_manifest(scratch / "verification_queue.md", _queue_rows())
    CTA.initialize_chain_tail(scratch, [_pair()])
    sidecar = scratch / CTA.COMPOSITION_CANDIDATES_NAME
    payload = json.loads(sidecar.read_text(encoding="utf-8"))
    payload["candidate_digest"] = "0" * 64
    sidecar.write_text(json.dumps(payload), encoding="utf-8")

    shards = ensure(scratch)

    assert sum(len(rows) for rows in shards.values()) == 2
    debt = json.loads(
        (scratch / "compound_verification_delivery_debt.json")
        .read_text(encoding="utf-8")
    )
    assert debt["status"] == "COMPLETED_WITH_DEBT"
    assert debt["ordinary_verification_delivery_complete"] is False
    assert debt["proof_authority"] == "NONE"
    assert (scratch / "verification_queue.work_plan.json").is_file()
