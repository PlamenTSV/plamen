"""Live-cutover contracts for the bounded verifier roster (P0-AK).

No fixture launches a provider.  The tests exercise the exact-subset prompt,
receipt identity, coordinator projection, tamper-resume, and aggregate-debt
boundaries which the main driver consumes.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import uuid

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

import plamen_driver as D  # noqa: E402
import plamen_mechanical as M  # noqa: E402
import plamen_prompt as PR  # noqa: E402
import plamen_validators as V  # noqa: E402
import report_evidence_authority as REA  # noqa: E402
import report_index_machinery as RIM  # noqa: E402
from artifact_ledger import (  # noqa: E402
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from phase_io_contracts import (  # noqa: E402
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
    resolve_phase_io_contract,
)
from queue_work_items import VerifierOutputIdentity  # noqa: E402
from test_support_startup_permit import (  # noqa: E402
    durable_startup_permit,
)
from test_verifier_output_receipt_runtime_p0_aj import (  # noqa: E402
    LAUNCH_DIGEST,
    _ignore_poc_gate,
    _policy,
    _proposal_bytes,
    _setup_plan,
    _verify_bytes,
)
from verifier_work_roster import (  # noqa: E402
    VerifierRosterError,
    VerifierUnitReceipt,
    build_verifier_runtime_policy,
    build_verifier_work_roster,
    build_verifier_launch_spec,
)
from verification_policy import Backend  # noqa: E402


def _write_operator_application(
    scratchpad: Path,
    work_unit_id: str,
    work_item_id: str,
) -> None:
    """Emit the model-owned typed application against the live unit dispatch."""

    dispatch = json.loads(
        (
            scratchpad
            / "_verifier_runtime_units"
            / work_unit_id
            / "method_dispatch.json"
        ).read_text(encoding="utf-8")
    )
    row = next(
        item
        for item in dispatch["rows"]
        if item["work_item_id"] == work_item_id
    )
    operators = []
    for operator_id in row["operator_ids"]:
        if (
            operator_id == "context-closure"
            and row["context_state"] == "CONTEXT_UNRESOLVED"
        ):
            operators.append({
                "operator_id": operator_id,
                "status": "BLOCKED",
                "evidence": [],
                "predicate": None,
                "debt_code": "CONTEXT_UNRESOLVED",
                "blocker_evidence": [
                    "Fixture repository has no matching caller/state graph edge."
                ],
            })
        else:
            operators.append({
                "operator_id": operator_id,
                "status": "APPLIED",
                "evidence": [{
                    "source": "src/generic.ext:1",
                    "detail": "Fixture exercised the dispatched verification operator.",
                }],
                "predicate": None,
                "debt_code": None,
                "blocker_evidence": [],
            })
    payload = {
        "schema_version": "plamen.verification_operator_application.v1",
        "work_item_id": work_item_id,
        "method_dispatch_id": dispatch["dispatch_id"],
        "selected_module_hashes": row["module_hashes"],
        "context_packet_digest": row["context_packet_digest"],
        "context_status": row["context_state"],
        "context_expansion": [],
        "operators": operators,
        "new_observations": [],
    }
    (scratchpad / f"verify_{work_item_id}.operator_application.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _bind_sc_shared_context_producer(
    scratchpad: Path,
    project_root: Path,
    items,
    *,
    run_id: str,
) -> dict:
    """Model the queue-level producer used before dynamic SC children."""

    (scratchpad / "findings_inventory.md").write_text(
        "# Findings Inventory\n\nFixture-only producer input.\n",
        encoding="utf-8",
    )
    context_payload = D.build_verification_context_packets(
        rows=[item.to_dict() for item in items],
        scratchpad=scratchpad,
        project_root=project_root.resolve(),
    )
    # This fixture isolates the shared-input ownership rule from the queue
    # transaction's much larger output denominator.  It deliberately uses the
    # real queue-routing owner identity without going through the registered
    # resolver, whose mandatory successor inputs are tested separately.
    owner_key = "sc/thorough/evm/claude/sc_verify_queue/routing"
    producer_contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="sc_verify_queue",
        work_unit_id="routing",
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path="verification_context_packets.json",
                owner_key=owner_key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version="fixture.verification_context_packets.v1",
                minimum_gate="FIXTURE_EXACT_CONTEXT_PACKET_BINDING",
            ),
        ),
        immutable_inputs=("scratchpad:findings_inventory.md",),
        model_invoked=False,
    )
    producer_launch = LaunchSpec(
        work_unit_key=producer_contract.key,
        pipeline=producer_contract.pipeline,
        mode=producer_contract.mode,
        ecosystem=producer_contract.ecosystem,
        backend=producer_contract.backend,
        model="driver",
        timeout_s=60,
        exec_mode="python",
    )
    record_work_unit_inputs(
        scratchpad,
        project_root,
        producer_contract,
        producer_launch,
        run_id=run_id,
    )
    D.write_or_validate_context_packets(
        scratchpad / "verification_context_packets.json",
        context_payload,
    )
    record_work_unit_artifacts(
        scratchpad,
        project_root,
        producer_contract,
        producer_launch,
        run_id=run_id,
        actor="DRIVER",
    )
    identity = "scratchpad:verification_context_packets.json"
    return read_artifact_ledger(scratchpad)["artifact_bindings"][identity]


def _bind_existing_sc_queue_routing(
    scratchpad: Path,
    config: dict,
) -> None:
    """Replay fixture bytes through the real arm-before-write queue seam."""

    if not (scratchpad / "finding_records.json").is_file():
        D._write_finding_records_from_inventory(scratchpad)
    if not (scratchpad / "finding_records.json").is_file():
        inventory_raw = (scratchpad / "findings_inventory.md").read_bytes()
        (scratchpad / "finding_records.json").write_text(
            json.dumps(
                {
                    "schema_version": "plamen.finding_records.v2",
                    "source": "findings_inventory.md",
                    "source_sha256": hashlib.sha256(
                        inventory_raw
                    ).hexdigest(),
                    "records": [],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    paired_paths = ("findings_inventory.md", "finding_records.json")
    postimage = {
        relative: (scratchpad / relative).read_bytes()
        for relative in paired_paths
    }
    for relative in paired_paths:
        (scratchpad / relative).unlink()
    owner = canonical_work_unit_key(
        "sc",
        str(config.get("mode") or "thorough"),
        str(config.get("language") or "evm"),
        str(config.get("cli_backend") or "claude"),
        "inventory",
        "dynamic_verifier_fixture_pair",
    )
    source_contract = PhaseIOContract(
        pipeline="sc",
        mode=str(config.get("mode") or "thorough"),
        ecosystem=str(config.get("language") or "evm"),
        backend=str(config.get("cli_backend") or "claude"),
        phase="inventory",
        work_unit_id="dynamic_verifier_fixture_pair",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=relative,
                owner_key=owner,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version="plamen.fixture_upstream.v1",
                minimum_gate="FIXTURE_EXACT_BYTES",
            )
            for relative in paired_paths
        ),
        model_invoked=False,
    )
    source_launch = LaunchSpec(
        work_unit_key=source_contract.key,
        pipeline=source_contract.pipeline,
        mode=source_contract.mode,
        ecosystem=source_contract.ecosystem,
        backend=source_contract.backend,
        model="fixture-driver",
        timeout_s=30,
        exec_mode="python",
    )
    record_work_unit_inputs(
        scratchpad,
        Path(config["project_root"]),
        source_contract,
        source_launch,
        run_id=str(config["_run_id"]),
    )
    for relative, raw in postimage.items():
        (scratchpad / relative).write_bytes(raw)
    record_work_unit_artifacts(
        scratchpad,
        Path(config["project_root"]),
        source_contract,
        source_launch,
        run_id=str(config["_run_id"]),
        actor="DRIVER",
    )
    frozen_projection = D.prepare_preverify_frozen_projection(
        scratchpad=scratchpad,
        project_root=Path(config["project_root"]),
        pipeline="sc",
        mode=str(config.get("mode") or "thorough"),
        ecosystem=str(config.get("language") or "evm"),
        backend=str(config.get("cli_backend") or "claude"),
        phase_name="sc_verify_queue",
        run_id=str(config["_run_id"]),
    )
    assert D._finalize_preverify_inventory_successors(
        scratchpad,
        config,
        phase_name="sc_verify_queue",
        frozen_projection=frozen_projection,
    ) == []
    contract, _launch = (
        D._typed_verify_queue_routing_contract_and_launch(
            "sc_verify_queue", scratchpad, config
        )
    )
    generated_by_commit = {
        "verification_context_packets.json",
        "verification_methodology_reachability.json",
    }
    for spec in contract.outputs:
        path = scratchpad / spec.path
        if not path.is_file() and spec.path not in generated_by_commit:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                "# Fixture projection\n"
                if path.suffix == ".md"
                else "{}\n",
                encoding="utf-8",
            )
    output_bytes = {
        spec.path: (scratchpad / spec.path).read_bytes()
        for spec in contract.outputs
        if (scratchpad / spec.path).is_file()
    }
    for relative in output_bytes:
        (scratchpad / relative).unlink()
    execute, issues = D._arm_typed_verify_queue_routing_artifacts(
        "sc_verify_queue", scratchpad, config
    )
    assert issues == []
    assert execute is True
    for relative, raw in output_bytes.items():
        path = scratchpad / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    assert D._record_typed_verify_queue_routing_artifacts(
        "sc_verify_queue", scratchpad, config
    ) == []


@pytest.mark.parametrize("pipeline", ["sc", "l1"])
def test_prompt_checklist_consumes_exact_dynamic_child_not_parent_shard(
    tmp_path: Path, pipeline: str
) -> None:
    ids = tuple(f"H-{index:02d}" for index in range(1, 6))
    scratchpad, phase_name, _items, _plan = _setup_plan(
        tmp_path, pipeline, finding_ids=ids
    )
    config = {
        "scratchpad": str(scratchpad),
        "_dynamic_verifier_work_item_ids": ids[:4],
    }
    checklist = PR._render_verify_shard_checklist(config, phase_name)
    assert all(work_id in checklist for work_id in ids[:4])
    assert ids[4] not in checklist
    assert checklist.count("severity_proposal.json") == 4


@pytest.mark.parametrize("pipeline", ["sc", "l1"])
def test_exact_child_receipts_preserve_original_queue_shard_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline: str,
) -> None:
    ids = tuple(f"H-{index:02d}" for index in range(1, 6))
    scratchpad, phase_name, items, plan = _setup_plan(
        tmp_path, pipeline, finding_ids=ids
    )
    _ignore_poc_gate(monkeypatch)
    by_id = {item.work_item_id: item for item in items}
    for work_id in ids[:4]:
        (scratchpad / f"verify_{work_id}.md").write_bytes(_verify_bytes(work_id))
        (scratchpad / f"verify_{work_id}.severity_proposal.json").write_bytes(
            _proposal_bytes(by_id[work_id])
        )
    policy = _policy(pipeline, Backend.CLAUDE)
    before = V._validate_verifier_outputs_before_receipt(
        scratchpad,
        phase_name,
        min_bytes=1,
        mode="core",
        execution_policy=policy,
        require_severity_proposals=True,
        assigned_work_item_ids=ids[:4],
    )
    assert before == []
    V._persist_verifier_output_receipts(
        scratchpad,
        phase_name,
        execution_policy=policy,
        launch_digest=LAUNCH_DIGEST,
        assigned_work_item_ids=ids[:4],
    )
    exact = V._validate_verify_completion(
        scratchpad,
        phase_name,
        min_bytes=1,
        mode="core",
        execution_policy=policy,
        launch_digest=LAUNCH_DIGEST,
        assigned_work_item_ids=ids[:4],
    )
    assert exact == []
    identity = VerifierOutputIdentity.from_dict(
        json.loads(
            (scratchpad / "verify_H-01.identity.json").read_text(encoding="utf-8")
        )
    )
    assert identity.shard_id == phase_name
    assert identity.work_plan_digest == plan.digest
    legacy_full_parent = V._validate_verify_completion(
        scratchpad,
        phase_name,
        min_bytes=1,
        mode="core",
        execution_policy=policy,
        launch_digest=LAUNCH_DIGEST,
    )
    assert legacy_full_parent
    assert "verify_H-05.md" in " ".join(legacy_full_parent)


def test_unit_receipt_roundtrip_is_strict_and_tamper_evident() -> None:
    # Build locally to avoid importing fixture internals into driver state.
    from test_verifier_work_roster_p0_ak import _fixed_slot_plan

    _items, plan = _fixed_slot_plan(1, "sc")
    policy = build_verifier_runtime_policy(
        backend="claude",
        model="sonnet",
        transport="pty",
        timeout_seconds=60,
        source_root="/audit/source",
    )
    roster = build_verifier_work_roster(
        plan,
        pipeline="sc",
        ecosystem="evm",
        mode="thorough",
        runtime_policy=policy,
        method_registry_digest="1" * 64,
        context_packet_digest="2" * 64,
    )
    unit = roster.work_units[0]
    receipt = VerifierUnitReceipt.completed_for(
        unit,
        launch_spec_digest="3" * 64,
        output_receipt_digests=("4" * 64,),
        gate_receipt_digests=("5" * 64,),
    )
    assert VerifierUnitReceipt.from_json(receipt.to_json()) == receipt
    payload = receipt.to_dict()
    payload["status"] = "DEBT"
    with pytest.raises(VerifierRosterError):
        VerifierUnitReceipt.from_json(json.dumps(payload))


@pytest.mark.parametrize(
    ("pipeline", "expected"),
    [
        (
            "sc",
            {
                "critical_high": "sc_verify_crithigh",
                "medium": "sc_verify_medium_a",
                "low_info": "sc_verify_low_a",
            },
        ),
        (
            "l1",
            {
                "critical_high": "verify_crithigh",
                "medium": "verify_medium_a",
                "low_info": "verify_low_a",
            },
        ),
    ],
)
def test_only_three_legacy_phases_are_runtime_coordinators(
    pipeline: str, expected: dict[str, str]
) -> None:
    assert D._dynamic_verifier_coordinator_map({"pipeline": pipeline}) == expected
    all_fixed = (
        D.SC_VERIFY_PHASE_NAMES if pipeline == "sc" else D.L1_VERIFY_PHASE_NAMES
    )
    assert len(set(expected.values())) == 3
    assert set(expected.values()).issubset(set(all_fixed))
    assert all(
        D._dynamic_verifier_tier_for_phase(name, {"pipeline": pipeline}) is None
        for name in set(all_fixed) - set(expected.values())
    )


def test_pending_aggregate_is_explicit_unverified_debt_not_per_finding_stub(
    tmp_path: Path,
) -> None:
    scratchpad, _phase_name, _items, _plan = _setup_plan(
        tmp_path, "sc", finding_ids=("H-01", "M-01")
    )
    issues = ["verify-low-info-0001 retained TIMEOUT_DEBT"]
    D._retain_dynamic_verification_debt(
        scratchpad,
        {"pipeline": "sc"},
        issues,
        ("H-01", "M-01"),
    )
    payload = json.loads(
        (scratchpad / D._DYNAMIC_VERIFIER_DEBT_NAME).read_text(encoding="utf-8")
    )
    assert payload["schema_version"] == "plamen.verification_runtime_debt.v2"
    assert len(payload["receipt_digest"]) == 64
    assert payload["proof_authority"] == "NONE"
    assert payload["verifier_status"] == "UNRESOLVED"
    assert payload["report_verification_projection"] == "CONTESTED"
    assert payload["pending_work_item_ids"] == ["H-01", "M-01"]
    assert "Verdict: UNRESOLVED" in (
        scratchpad / "verification_runtime_debt.md"
    ).read_text(encoding="utf-8")
    assert "Proof Authority**: NONE" in (
        scratchpad / "verify_core.md"
    ).read_text(encoding="utf-8")
    assert not (scratchpad / "verify_H-01.md").exists()
    assert not (scratchpad / "verify_M-01.md").exists()
    assert V._validate_report_verification_denominator(scratchpad) == []
    assert RIM._verification_status(
        {
            "verifier_status": "UNRESOLVED",
            "mechanical_authority_state": "ABSENT",
            "integrity_state": "",
            "effective_tag": "",
        }
    ) == "CONTESTED"


def test_runtime_debt_projection_replaces_prior_pending_denominator(
    tmp_path: Path,
) -> None:
    scratchpad, _phase_name, _items, _plan = _setup_plan(
        tmp_path, "sc", finding_ids=("H-01", "M-01")
    )
    (scratchpad / "verify_core.md").write_text(
        "# Verification Aggregate\n\nStable aggregate prefix.\n",
        encoding="utf-8",
    )

    D._retain_dynamic_verification_debt(
        scratchpad,
        {"pipeline": "sc"},
        ("two children unresolved",),
        ("H-01", "M-01"),
    )
    D._retain_dynamic_verification_debt(
        scratchpad,
        {"pipeline": "sc"},
        ("one child unresolved",),
        ("M-01",),
    )

    core = (scratchpad / "verify_core.md").read_text(encoding="utf-8")
    projection = (scratchpad / "verification_runtime_debt.md").read_text(
        encoding="utf-8"
    )
    payload = json.loads(
        (scratchpad / D._DYNAMIC_VERIFIER_DEBT_NAME).read_text(
            encoding="utf-8"
        )
    )
    assert core.count("<!-- PLAMEN_DYNAMIC_VERIFICATION_DEBT -->") == 1
    assert "Stable aggregate prefix." in core
    assert "H-01" not in projection
    assert "H-01" not in core
    assert "M-01" in projection
    assert payload["pending_work_item_ids"] == ["M-01"]
    assert payload["issues"] == ["one child unresolved"]


def test_successful_runtime_replay_retires_visible_debt_without_erasing_core(
    tmp_path: Path,
) -> None:
    scratchpad, _phase_name, _items, _plan = _setup_plan(
        tmp_path, "sc", finding_ids=("H-01",)
    )
    (scratchpad / "verify_core.md").write_text(
        "# Verification Aggregate\n\nStable aggregate prefix.\n",
        encoding="utf-8",
    )
    D._retain_dynamic_verification_debt(
        scratchpad,
        {"pipeline": "sc"},
        ("child unresolved",),
        ("H-01",),
    )

    D._retire_dynamic_verification_debt(
        scratchpad,
        {"pipeline": "sc"},
    )

    assert not (scratchpad / D._DYNAMIC_VERIFIER_DEBT_NAME).exists()
    assert not (scratchpad / "verification_runtime_debt.md").exists()
    core = (scratchpad / "verify_core.md").read_text(encoding="utf-8")
    assert core == "# Verification Aggregate\n\nStable aggregate prefix.\n"
    assert "PLAMEN_DYNAMIC_VERIFICATION_DEBT" not in core


def test_runtime_debt_retirement_supersedes_live_phaseio_binding(
    tmp_path: Path,
) -> None:
    scratchpad, _phase_name, _items, _plan = _setup_plan(
        tmp_path, "sc", finding_ids=("H-01",)
    )
    (scratchpad / "findings_inventory.md").write_text(
        "# Findings Inventory\n\nFixture queue authority.\n",
        encoding="utf-8",
    )
    for relative in (
        "compound_candidates.json",
        "compound_verification_work_plan.json",
    ):
        (scratchpad / relative).write_text("{}\n", encoding="utf-8")
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(scratchpad.parent),
        "_run_id": "RUN-DEBT-RETIRE",
    }
    _bind_existing_sc_queue_routing(scratchpad, config)
    D._retain_dynamic_verification_debt(
        scratchpad,
        config,
        ("child unresolved",),
        ("H-01",),
    )
    identity = "scratchpad:verification_runtime_debt.json"
    assert read_artifact_ledger(scratchpad)["artifact_bindings"][identity][
        "status"
    ] == "ACTIVE"

    issues = D._retire_dynamic_verification_debt(scratchpad, config)

    assert issues == []
    ledger = read_artifact_ledger(scratchpad)
    assert ledger["artifact_bindings"][identity]["status"] == "SUPERSEDED"
    assert (
        ledger["artifact_bindings"][
            "scratchpad:verification_runtime_debt.md"
        ]["status"]
        == "SUPERSEDED"
    )
    assert not (scratchpad / D._DYNAMIC_VERIFIER_DEBT_NAME).exists()
    assert not (scratchpad / "verification_runtime_debt.md").exists()


def test_runtime_debt_retirement_failure_retains_forensic_sidecars(
    tmp_path: Path,
) -> None:
    scratchpad, _phase_name, _items, _plan = _setup_plan(
        tmp_path, "sc", finding_ids=("H-01",)
    )
    (scratchpad / "findings_inventory.md").write_text(
        "# Findings Inventory\n\nFixture queue authority.\n",
        encoding="utf-8",
    )
    for relative in (
        "compound_candidates.json",
        "compound_verification_work_plan.json",
    ):
        (scratchpad / relative).write_text("{}\n", encoding="utf-8")
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(scratchpad.parent),
        "_run_id": "RUN-DEBT-RETIRE-FAIL",
    }
    _bind_existing_sc_queue_routing(scratchpad, config)
    D._retain_dynamic_verification_debt(
        scratchpad, config, ("child unresolved",), ("H-01",)
    )
    ledger_path = scratchpad / "_artifact_state.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    owner = "sc/thorough/evm/claude/verify/runtime_debt"
    ledger["work_units"][owner]["launch_digest"] = "0" * 64
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")

    issues = D._retire_dynamic_verification_debt(scratchpad, config)

    assert any("retirement contract or launch drifted" in row for row in issues)
    assert (scratchpad / D._DYNAMIC_VERIFIER_DEBT_NAME).is_file()
    assert (scratchpad / "verification_runtime_debt.md").is_file()
    assert "PLAMEN_DYNAMIC_VERIFICATION_DEBT" not in (
        scratchpad / "verify_core.md"
    ).read_text(encoding="utf-8")


def test_malformed_roster_and_work_plan_retains_full_queue_denominator(
    tmp_path: Path,
) -> None:
    scratchpad, _phase_name, _items, _plan = _setup_plan(
        tmp_path, "sc", finding_ids=("H-01", "M-01")
    )
    (scratchpad / D._DYNAMIC_VERIFIER_ROSTER_NAME).write_text(
        "{not-json", encoding="utf-8"
    )
    (scratchpad / "verification_queue.work_plan.json").write_text(
        "{also-not-json", encoding="utf-8"
    )

    issues, pending = D._dynamic_verifier_aggregate_issues(
        scratchpad, {"pipeline": "sc"}
    )

    assert issues
    assert pending == ("H-01", "M-01")


def test_runtime_debt_tamper_cannot_cover_missing_verifier_output(
    tmp_path: Path,
) -> None:
    scratchpad, _phase_name, _items, _plan = _setup_plan(
        tmp_path, "sc", finding_ids=("H-01",)
    )
    D._retain_dynamic_verification_debt(
        scratchpad,
        {"pipeline": "sc", "_run_id": "RUN-TAMPER"},
        ("provider completion unavailable",),
        ("H-01",),
    )
    path = scratchpad / D._DYNAMIC_VERIFIER_DEBT_NAME
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["pending_work_item_ids"] = []
    path.write_text(json.dumps(payload), encoding="utf-8")

    issues = V._validate_report_verification_denominator(scratchpad)

    assert issues
    assert "neither verifier output nor exact CONTESTED retention" in issues[0]


@pytest.mark.parametrize("padding", [0, 240])
def test_unreceipted_verifier_bytes_never_override_runtime_debt(
    tmp_path: Path,
    padding: int,
) -> None:
    scratchpad, _phase_name, _items, _plan = _setup_plan(
        tmp_path, "sc", finding_ids=("H-01",)
    )
    (scratchpad / "verify_H-01.md").write_text(
        "# H-01\n\n**Verdict**: CONFIRMED\n\n"
        "**Preferred Tag**: [CODE-TRACE]\n\n"
        "**Severity**: High\n\n"
        "Substantive-looking but transactionally uncommitted bytes.\n"
        + ("x" * padding),
        encoding="utf-8",
    )
    D._retain_dynamic_verification_debt(
        scratchpad,
        {"pipeline": "sc", "_run_id": "RUN-UNRECEIPTED"},
        ("provider did not commit exact completion authority",),
        ("H-01",),
    )

    assert not V._verifier_output_has_completion_authority(
        scratchpad, "H-01"
    )
    binding = M._verification_runtime_debt_binding(scratchpad, ["H-01"])
    assert binding is not None
    assert binding["covered_candidate_ids"] == ["H-01"]
    assert V._validate_report_verification_denominator(scratchpad) == []


def test_resume_retries_dynamic_debt_despite_plausible_verifier_prose(
    tmp_path: Path,
) -> None:
    scratchpad, phase_name, _items, plan = _setup_plan(
        tmp_path, "sc", finding_ids=("H-01",)
    )
    roster = build_verifier_work_roster(
        plan,
        pipeline="sc",
        ecosystem="evm",
        mode="thorough",
        runtime_policy=build_verifier_runtime_policy(
            backend="claude",
            model="sonnet",
            transport="pty",
            timeout_seconds=60,
            source_root=str(tmp_path.resolve()),
        ),
        method_registry_digest="1" * 64,
        context_packet_digest="2" * 64,
    )
    (scratchpad / D._DYNAMIC_VERIFIER_ROSTER_NAME).write_text(
        roster.to_json(), encoding="utf-8"
    )
    (scratchpad / "verify_H-01.md").write_text(
        "# H-01\n\n**Verdict**: CONFIRMED\n\n"
        "**Preferred Tag**: [CODE-TRACE]\n\n"
        "Substantive but uncommitted verifier prose.\n" + ("x" * 240),
        encoding="utf-8",
    )
    D._retain_dynamic_verification_debt(
        scratchpad,
        {"pipeline": "sc", "_run_id": "RUN-RESUME-DEBT"},
        ("dynamic unit retained provider debt",),
        ("H-01",),
    )
    child = next(item for item in D.SC_PHASES if item.name == phase_name)
    aggregate = next(
        item for item in D.SC_PHASES if item.name == "sc_verify_aggregate"
    )

    child_issues = D._resume_phase_contract_issues(
        scratchpad,
        str(tmp_path),
        child,
        mode="thorough",
        language="evm",
        pipeline="sc",
        backend="claude",
    )
    aggregate_issues = D._resume_phase_contract_issues(
        scratchpad,
        str(tmp_path),
        aggregate,
        mode="thorough",
        language="evm",
        pipeline="sc",
        backend="claude",
    )

    assert any("dynamic verifier resume requires exact retry" in issue
               for issue in child_issues)
    assert any("cannot classify retained runtime debt" in issue
               for issue in aggregate_issues)


def test_runtime_debt_prevents_uncommitted_safe_or_low_report_projection(
    tmp_path: Path,
) -> None:
    scratchpad, _phase_name, _items, _plan = _setup_plan(
        tmp_path, "sc", finding_ids=("H-01",)
    )
    (scratchpad / "verify_H-01.md").write_text(
        "# H-01\n\n**Verdict**: REFUTED\n\n**Severity**: Low\n\n"
        "**Preferred Tag**: [CODE-TRACE]\n\n"
        "Plausible but uncommitted best-case prose.\n" + ("x" * 240),
        encoding="utf-8",
    )
    D._retain_dynamic_verification_debt(
        scratchpad,
        {"pipeline": "sc", "_run_id": "RUN-PROJECTION-DEBT"},
        ("verifier conclusion lacks completion authority",),
        ("H-01",),
    )

    assert V._expected_report_index_severities(scratchpad)["H-01"] == "High"
    assert V._expected_report_index_statuses(scratchpad)["H-01"] == "CONTESTED"


def test_mixed_completed_and_debt_manifest_binds_only_incomplete_identity(
    tmp_path: Path,
) -> None:
    scratchpad, phase_name, items, _plan = _setup_plan(
        tmp_path, "sc", finding_ids=("H-01", "H-02")
    )
    by_id = {item.work_item_id: item for item in items}
    (scratchpad / "verify_H-01.md").write_bytes(_verify_bytes("H-01"))
    (scratchpad / "verify_H-01.severity_proposal.json").write_bytes(
        _proposal_bytes(by_id["H-01"])
    )
    V._persist_verifier_output_receipts(
        scratchpad,
        phase_name,
        execution_policy=_policy("sc", Backend.CLAUDE),
        launch_digest=LAUNCH_DIGEST,
        assigned_work_item_ids=("H-01",),
    )
    # Plausible bytes for H-02 are deliberately not receipted.
    (scratchpad / "verify_H-02.md").write_text(
        "# H-02\n\n**Verdict**: CONFIRMED\n\n"
        "**Preferred Tag**: [CODE-TRACE]\n\n"
        "**Severity**: High\n\n" + ("uncommitted " * 30),
        encoding="utf-8",
    )
    D._retain_dynamic_verification_debt(
        scratchpad,
        {"pipeline": "sc", "_run_id": "RUN-MIXED"},
        ("second work item did not commit",),
        ("H-02",),
    )

    completion_issues = V._verifier_completion_authority_issues(
        scratchpad, "H-01"
    )
    assert completion_issues == []
    assert not V._verifier_output_has_completion_authority(
        scratchpad, "H-02"
    )
    binding = M._verification_runtime_debt_binding(
        scratchpad, ["H-01", "H-02"]
    )
    assert binding is not None
    assert binding["covered_candidate_ids"] == ["H-02"]

    receipt_path = scratchpad / "verify_H-01.receipt.json"
    receipt_payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt_payload["output_sha256"] = "0" * 64
    receipt_path.write_text(json.dumps(receipt_payload), encoding="utf-8")
    assert not V._verifier_output_has_completion_authority(
        scratchpad, "H-01"
    )


def test_runtime_debt_is_report_provenance_not_proof_or_confidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, _phase_name, _items, _plan = _setup_plan(
        tmp_path, "sc", finding_ids=("H-01",)
    )
    (scratchpad / "findings_inventory.md").write_text(
        "# Findings Inventory\n\nFixture queue authority.\n",
        encoding="utf-8",
    )
    for relative in (
        "compound_candidates.json",
        "compound_verification_work_plan.json",
    ):
        (scratchpad / relative).write_text("{}\n", encoding="utf-8")
    queue_config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(scratchpad.parent),
        "_run_id": "RUN-REPORT-DEBT",
    }
    _bind_existing_sc_queue_routing(scratchpad, queue_config)
    D._retain_dynamic_verification_debt(
        scratchpad,
        queue_config,
        ("provider completion unavailable",),
        ("H-01",),
    )
    binding = M._verification_runtime_debt_binding(scratchpad, ["H-01"])
    assert binding is not None
    (scratchpad / "body_manifests").mkdir()
    manifest_row = {
        "report_id": "H-1",
        "finding_id": "H-01",
        "severity": "High",
        "title": "Retained candidate",
        "location": "src/Generic.sol:10",
        "evidence_tag": "UNVERIFIED",
        "verify_file": "verify_H-01.md",
        "verify_files": ["verify_H-01.md"],
        "verify_statuses": [{
            "file": "verify_H-01.md",
            "exists": False,
            "evidence_missing": True,
        }],
        "description": "A proposed mechanism remains pending independent verification.",
        "poc_result": "",
        "recommendation": "",
        "report_blocked": True,
        "verification_runtime_debt": binding,
    }
    (scratchpad / "body_manifests" / "report_critical_high.json").write_text(
        json.dumps({"shard": "report_critical_high", "findings": [manifest_row]}),
        encoding="utf-8",
    )
    (scratchpad / "report_records.json").write_text(
        json.dumps({
            "schema_version": "plamen.report_records.v1",
            "source": "report_index.md",
            "active": [{
                "report_id": "H-1",
                "finding_id": "H-01",
                "severity": "High",
                "title": "Retained candidate",
                "location": "src/Generic.sol:10",
                "evidence": "UNVERIFIED",
                "verdict": "UNRESOLVED",
                "unresolved": True,
                "severity_adjustments": [],
                "absorbed_finding_ids": [],
                "report_blocked": True,
            }],
            "excluded": [],
            "consolidation_map": [],
        }),
        encoding="utf-8",
    )

    runtime = REA.materialize_report_evidence_runtime(scratchpad)
    record = runtime["bundle"]["records"][0]

    assert record["verdict"] == "UNRESOLVED"
    assert record["evidence_authenticity"] == "NOT_EXECUTED"
    assert record["evidence_result"] == "NOT_EXECUTED"
    assert record["proof_scope"] == "NONE"
    assert "VERIFICATION_RUNTIME_DEBT_UNRESOLVED" in record["limitations"]
    assert any(
        row["artifact"] == "verification_runtime_debt.json"
        for row in record["evidence_sources"]
    )
    # The pure renderer assertions above deliberately ran outside the driver.
    # Remove those proposal bytes so the live boundary can prove its real
    # arm-before-write ownership rather than adopting fixture-created output.
    for relative in D._report_evidence_runtime_outputs(scratchpad):
        (scratchpad / relative).unlink(missing_ok=True)

    project = scratchpad.parent
    phase = next(
        item for item in D.SC_PHASES
        if item.name == "report_body_writer_critical_high"
    )
    config = {
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "language": "evm",
        "mode": "thorough",
        "pipeline": "sc",
        "cli_backend": "claude",
        "_run_id": "RUN-REPORT-DEBT",
    }
    rebound, pre_issues = D._materialize_report_evidence_pre_body(
        phase,
        config,
        scratchpad,
        enforce_upstream_ownership=False,
    )
    assert rebound is not None, pre_issues
    assert pre_issues == []
    real_record_artifacts = D.record_work_unit_artifacts

    def _crash_after_output_write(*args, **kwargs):
        raise OSError("fixture crash after output write before ledger commit")

    monkeypatch.setattr(D, "record_work_unit_artifacts", _crash_after_output_write)
    written, fallback_issues = D._materialize_runtime_debt_report_body(
        phase, config, scratchpad
    )
    assert written is False
    assert any("transaction failed" in issue for issue in fallback_issues)
    assert (scratchpad / "report_critical_high.md").is_file()
    assert list(
        (scratchpad / "_report_body_transactions").glob(
            "*.runtime_debt.json"
        )
    )

    monkeypatch.setattr(D, "record_work_unit_artifacts", real_record_artifacts)
    written, fallback_issues = D._materialize_runtime_debt_report_body(
        phase, config, scratchpad
    )
    assert written is True, fallback_issues
    assert fallback_issues == []
    fallback = (scratchpad / "report_critical_high.md").read_text(
        encoding="utf-8"
    )
    assert "[STUB-RECOVERED]" not in fallback
    assert "**Verdict**: UNRESOLVED" in fallback
    assert "**Confidence**: UNVERIFIED" in fallback
    fallback_key = (
        "sc/thorough/evm/claude/report_body/"
        "report_critical_high.runtime_debt_fallback"
    )
    fallback_inputs = read_artifact_ledger(scratchpad)["work_units"][
        fallback_key
    ]["input_bindings"]
    assert set(fallback_inputs) == {
        "scratchpad:report_evidence_records.json",
        "scratchpad:report_evidence_manifests/report_critical_high.json",
    }
    assert not list(
        (scratchpad / "_report_body_transactions").glob(
            "*.runtime_debt.json"
        )
    )

    section = M._synth_report_section_from_verify(
        scratchpad,
        "H-1",
        "H-01",
        {"finding id": "H-01", "severity": "High", "title": "Retained candidate"},
        True,
    )
    assert "[STUB-RECOVERED]" in section
    assert "[UNRESOLVED - needs human review]" in section
    assert "**Confidence**: UNVERIFIED" in section
    assert "**Verdict**: UNRESOLVED" in section


def test_runtime_debt_manifest_binding_tamper_cannot_become_report_evidence(
    tmp_path: Path,
) -> None:
    scratchpad, _phase_name, _items, _plan = _setup_plan(
        tmp_path, "sc", finding_ids=("H-01",)
    )
    D._retain_dynamic_verification_debt(
        scratchpad,
        {"pipeline": "sc", "_run_id": "RUN-REPORT-TAMPER"},
        ("provider completion unavailable",),
        ("H-01",),
    )
    binding = M._verification_runtime_debt_binding(scratchpad, ["H-01"])
    assert binding is not None
    binding["sha256"] = "0" * 64
    row = {
        "report_id": "H-1", "finding_id": "H-01", "severity": "High",
        "title": "Retained candidate", "location": "src/Generic.sol:10",
        "verify_file": "verify_H-01.md", "verify_files": ["verify_H-01.md"],
        "report_blocked": True, "verification_runtime_debt": binding,
    }
    (scratchpad / "body_manifests").mkdir()
    (scratchpad / "body_manifests" / "report_critical_high.json").write_text(
        json.dumps({"shard": "report_critical_high", "findings": [row]}),
        encoding="utf-8",
    )
    (scratchpad / "report_records.json").write_text(
        json.dumps({"active": [{
            "report_id": "H-1", "finding_id": "H-01", "severity": "High",
            "title": "Retained candidate", "location": "src/Generic.sol:10",
            "verdict": "UNRESOLVED", "report_blocked": True,
        }]}),
        encoding="utf-8",
    )

    with pytest.raises(REA.ReportEvidenceError, match="source hash is stale"):
        REA.materialize_report_evidence_runtime(scratchpad)


def test_five_row_parent_runs_two_exact_children_and_resumes_without_relaunch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = tuple(f"H-{index:02d}" for index in range(1, 6))
    scratchpad, phase_name, items, plan = _setup_plan(
        tmp_path, "sc", finding_ids=ids
    )
    phase = next(item for item in D.SC_PHASES if item.name == phase_name)
    runtime_policy = build_verifier_runtime_policy(
        backend="claude",
        model="sonnet",
        transport="headless",
        timeout_seconds=60,
        source_root=str(tmp_path.resolve()),
    )
    roster = build_verifier_work_roster(
        plan,
        pipeline="sc",
        ecosystem="evm",
        mode="thorough",
        runtime_policy=runtime_policy,
        method_registry_digest="1" * 64,
        context_packet_digest="2" * 64,
    )
    assert [len(unit.ordered_work_item_ids) for unit in roster.work_units] == [4, 1]
    by_id = {item.work_item_id: item for item in items}
    launched: list[str] = []
    selected_front = str(
        (tmp_path / "authenticated-claude-runtime-front").resolve()
    )
    selected_prefix = (
        selected_front,
        "backend-launch",
        "--backend",
        "claude",
        "--generation",
        "fixture-generation",
        "--",
    )

    def fake_execute(spec, **_kwargs):
        assert spec.transport == "headless"
        assert spec.argv[: len(selected_prefix)] == selected_prefix
        assert "--dangerously-skip-permissions" not in spec.argv
        launched.append(spec.work_unit_id)
        unit = roster.work_unit(spec.work_unit_id)
        for work_id in unit.ordered_work_item_ids:
            (scratchpad / f"verify_{work_id}.md").write_bytes(
                _verify_bytes(work_id)
            )
            (scratchpad / f"verify_{work_id}.severity_proposal.json").write_bytes(
                _proposal_bytes(by_id[work_id])
            )
            _write_operator_application(
                scratchpad, spec.work_unit_id, work_id
            )
        return 0

    monkeypatch.setattr(D, "_execute_dynamic_verifier_launch", fake_execute)
    monkeypatch.setattr(
        D,
        "_selected_claude_backend_argv_prefix",
        lambda: selected_prefix,
    )
    _ignore_poc_gate(monkeypatch)
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "claude_exec_mode": "headless",
        "project_root": str(tmp_path.resolve()),
        "scratchpad": str(scratchpad),
        "_run_id": str(uuid.uuid4()),
    }
    context_identity = "scratchpad:verification_context_packets.json"
    producer_binding = _bind_sc_shared_context_producer(
        scratchpad, tmp_path, items, run_id=config["_run_id"]
    )
    producer_contract_key = producer_binding["owner_key"]
    context_path = scratchpad / "verification_context_packets.json"
    context_bytes = context_path.read_bytes()
    for unit in roster.work_units:
        assert D._run_dynamic_verifier_unit(
            phase, scratchpad, config, roster, unit
        ) == []
        ledger = read_artifact_ledger(scratchpad)
        context_units = [
            row
            for key, row in ledger["work_units"].items()
            if key.endswith(f"/method_context.{unit.work_unit_id}")
        ]
        model_units = [
            row
            for key, row in ledger["work_units"].items()
            if key.endswith(f"/method_model.{unit.work_unit_id}")
        ]
        assert len(context_units) == 1
        assert len(model_units) == 1
        # This packet is a queue-level shared immutable input. A child may
        # consume its exact bytes, but must never steal producer ownership
        # from the queue transaction.
        assert context_identity not in context_units[0]["artifacts"]
        assert context_identity in model_units[0]["input_bindings"]
        assert (
            model_units[0]["input_bindings"][context_identity][
                "producer_work_unit_key"
            ]
            == producer_contract_key
        )
        assert ledger["artifact_bindings"][context_identity] == producer_binding
    assert launched == [unit.work_unit_id for unit in roster.work_units]
    for unit in roster.work_units:
        assert D._run_dynamic_verifier_unit(
            phase, scratchpad, config, roster, unit
        ) == []
    assert launched == [unit.work_unit_id for unit in roster.work_units]
    context_path.write_bytes(context_bytes + b"\n")
    tamper_issues = D._run_dynamic_verifier_unit(
        phase, scratchpad, config, roster, roster.work_units[0]
    )
    assert tamper_issues
    assert "verification_context_packets.json" in " ".join(tamper_issues)
    assert launched == [unit.work_unit_id for unit in roster.work_units]
    context_path.write_bytes(context_bytes)
    assert D._run_dynamic_verifier_unit(
        phase, scratchpad, config, roster, roster.work_units[0]
    ) == []
    assert all(
        D.VerifierUnitReceipt.from_json(
            D._dynamic_verifier_unit_paths(scratchpad, unit.work_unit_id)[
                "receipt"
            ].read_text(encoding="utf-8")
        ).status
        == "COMPLETED"
        for unit in roster.work_units
    )


def test_dynamic_child_refuses_unowned_shared_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, phase_name, _items, plan = _setup_plan(
        tmp_path, "sc", finding_ids=("H-01",)
    )
    phase = next(item for item in D.SC_PHASES if item.name == phase_name)
    runtime_policy = build_verifier_runtime_policy(
        backend="claude",
        model="sonnet",
        transport="pty",
        timeout_seconds=60,
        source_root=str(tmp_path.resolve()),
    )
    roster = build_verifier_work_roster(
        plan,
        pipeline="sc",
        ecosystem="evm",
        mode="thorough",
        runtime_policy=runtime_policy,
        method_registry_digest="1" * 64,
        context_packet_digest="2" * 64,
    )
    launched: list[str] = []

    def forbidden_launch(spec, **_kwargs):
        launched.append(spec.work_unit_id)
        return 0

    monkeypatch.setattr(D, "_execute_dynamic_verifier_launch", forbidden_launch)
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "claude_exec_mode": "pty",
        "project_root": str(tmp_path.resolve()),
        "scratchpad": str(scratchpad),
        "_run_id": str(uuid.uuid4()),
    }
    issues = D._run_dynamic_verifier_unit(
        phase, scratchpad, config, roster, roster.work_units[0]
    )
    assert launched == []
    assert any(
        "shared immutable input has no active upstream producer authority"
        in issue
        for issue in issues
    )
    paths = D._dynamic_verifier_unit_paths(
        scratchpad, roster.work_units[0].work_unit_id
    )
    assert not paths["receipt"].exists()
    assert not paths["debt"].exists()


def _one_unit_launch_spec(tmp_path: Path, *, backend: str, transport: str):
    from test_verifier_work_roster_p0_ak import _fixed_slot_plan

    _items, plan = _fixed_slot_plan(1, "sc")
    policy = build_verifier_runtime_policy(
        backend=backend,
        model="sonnet" if backend == "claude" else "gpt-5.4",
        transport=transport,
        timeout_seconds=60,
        source_root=str(tmp_path.resolve()),
    )
    roster = build_verifier_work_roster(
        plan,
        pipeline="sc",
        ecosystem="evm",
        mode="thorough",
        runtime_policy=policy,
        method_registry_digest="1" * 64,
        context_packet_digest="2" * 64,
    )
    return build_verifier_launch_spec(
        roster,
        roster.work_units[0].work_unit_id,
        prompt_bytes=b"bounded verifier prompt",
        claude_executable="claude",
        codex_executable="codex",
    )


def test_claude_pty_leaf_is_rejected_before_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = _one_unit_launch_spec(tmp_path, backend="claude", transport="pty")
    prompt = tmp_path / "prompt.md"
    prompt.write_text("bounded verifier prompt", encoding="utf-8")
    def forbidden(*_args, **_kwargs):
        raise AssertionError("untrusted PTY completion transport spawned")

    monkeypatch.setattr(D, "ClaudePtySession", forbidden)
    log_path = tmp_path / "pty.log"
    rc = D._execute_dynamic_verifier_launch(
        spec,
        prompt_path=prompt,
        log_path=log_path,
        scratchpad=tmp_path,
        phase=next(item for item in D.SC_PHASES if item.name == "sc_verify_crithigh"),
        config={"claude_pty_quiescence_s": 0.01},
    )
    assert rc == D._UNTRUSTED_COMPLETION_TRANSPORT_RC
    assert (
        json.loads(log_path.read_text(encoding="utf-8"))["reason_code"]
        == "UNTRUSTED_COMPLETION_TRANSPORT"
    )


def test_rate_limit_retains_exact_debt_then_retries_only_that_unit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, phase_name, items, plan = _setup_plan(
        tmp_path, "sc", finding_ids=("H-01",)
    )
    phase = next(item for item in D.SC_PHASES if item.name == phase_name)
    roster = build_verifier_work_roster(
        plan,
        pipeline="sc",
        ecosystem="evm",
        mode="thorough",
        runtime_policy=build_verifier_runtime_policy(
            backend="claude",
            model="sonnet",
            transport="pty",
            timeout_seconds=60,
            source_root=str(tmp_path.resolve()),
        ),
        method_registry_digest="1" * 64,
        context_packet_digest="2" * 64,
    )
    unit = roster.work_units[0]
    attempts = 0

    def rate_then_complete(_spec, **_kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return 1
        item = items[0]
        (scratchpad / item.expected_output_file).write_bytes(
            _verify_bytes(item.work_item_id)
        )
        (scratchpad / f"verify_{item.work_item_id}.severity_proposal.json").write_bytes(
            _proposal_bytes(item)
        )
        _write_operator_application(
            scratchpad, unit.work_unit_id, item.work_item_id
        )
        return 0

    monkeypatch.setattr(D, "_execute_dynamic_verifier_launch", rate_then_complete)
    _ignore_poc_gate(monkeypatch)
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "claude_exec_mode": "pty",
        "project_root": str(tmp_path.resolve()),
        "scratchpad": str(scratchpad),
        "_run_id": str(uuid.uuid4()),
    }
    _bind_sc_shared_context_producer(
        scratchpad, tmp_path, items, run_id=config["_run_id"]
    )
    first = D._run_dynamic_verifier_unit(
        phase, scratchpad, config, roster, unit
    )
    receipt_path = D._dynamic_verifier_unit_paths(
        scratchpad, unit.work_unit_id
    )["receipt"]
    assert first and "RATE_LIMIT_DEBT" in " ".join(first)
    assert VerifierUnitReceipt.from_json(
        receipt_path.read_text(encoding="utf-8")
    ).reason_class == "RATE_LIMIT_DEBT"
    assert D._run_dynamic_verifier_unit(
        phase, scratchpad, config, roster, unit
    ) == []
    assert attempts == 2
    assert VerifierUnitReceipt.from_json(
        receipt_path.read_text(encoding="utf-8")
    ).status == "COMPLETED"


@pytest.mark.parametrize(
    ("backend", "transport"),
    [("claude", "headless"), ("codex", "exec")],
)
def test_nonpty_leaf_without_transaction_authority_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
    transport: str,
) -> None:
    spec = _one_unit_launch_spec(tmp_path, backend=backend, transport=transport)
    prompt = tmp_path / "prompt.md"
    prompt.write_text("bounded verifier prompt", encoding="utf-8")
    def forbidden_popen(*_args, **_kwargs):
        raise AssertionError("non-PTY verifier bypassed MODEL transaction")

    monkeypatch.setattr(D.subprocess, "Popen", forbidden_popen)
    log_path = tmp_path / f"{backend}.log"
    rc = D._execute_dynamic_verifier_launch(
        spec,
        prompt_path=prompt,
        log_path=log_path,
        scratchpad=tmp_path,
        phase=next(item for item in D.SC_PHASES if item.name == "sc_verify_crithigh"),
        config={},
    )
    assert rc == D.EXIT_ERROR
    assert (
        log_path.read_text(encoding="utf-8")
        == "dynamic verifier non-PTY launch lacks exact transaction authority\n"
    )


def test_codex_dynamic_child_routes_through_bound_headless_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, phase_name, items, plan = _setup_plan(
        tmp_path, "sc", finding_ids=("H-01",)
    )
    phase = next(item for item in D.SC_PHASES if item.name == phase_name)
    roster = build_verifier_work_roster(
        plan,
        pipeline="sc",
        ecosystem="evm",
        mode="thorough",
        runtime_policy=build_verifier_runtime_policy(
            backend="codex",
            model="gpt-5.4",
            transport="exec",
            timeout_seconds=60,
            source_root=str(tmp_path.resolve()),
        ),
        method_registry_digest="1" * 64,
        context_packet_digest="2" * 64,
    )
    unit = roster.work_units[0]
    run_id = str(uuid.uuid4())
    _bind_sc_shared_context_producer(
        scratchpad, tmp_path, items, run_id=run_id
    )
    observed: dict[str, object] = {}

    def fake_execute_headless_worker(**kwargs):
        observed.update(kwargs)
        output_directory = (
            scratchpad / ".worker_transactions" / "fixture-output"
        )
        argv = tuple(kwargs["command_builder"](output_directory))
        observed["argv"] = argv
        assert argv[-3:] == (
            "--add-dir",
            output_directory.as_posix(),
            "-",
        )
        item = items[0]
        (scratchpad / item.expected_output_file).write_bytes(
            _verify_bytes(item.work_item_id)
        )
        (
            scratchpad
            / f"verify_{item.work_item_id}.severity_proposal.json"
        ).write_bytes(_proposal_bytes(item))
        _write_operator_application(
            scratchpad, unit.work_unit_id, item.work_item_id
        )
        return SimpleNamespace(stdout=b"codex-event\n", stderr=b"")

    monkeypatch.setattr(
        D, "execute_headless_worker", fake_execute_headless_worker
    )
    _ignore_poc_gate(monkeypatch)
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
        "project_root": str(tmp_path.resolve()),
        "scratchpad": str(scratchpad),
        "_run_id": run_id,
        "_audit_snapshot": {"snapshot_digest": "a" * 64},
        "_auxiliary_writable_root_startup_binding": (
            durable_startup_permit(scratchpad, run_id=run_id)
        ),
    }
    assert D._run_dynamic_verifier_unit(
        phase, scratchpad, config, roster, unit
    ) == []
    model_contract = observed["phase_io_contract"]
    model_launch = observed["phase_io_launch"]
    assert model_contract.key.endswith(f"/method_model.{unit.work_unit_id}")
    assert model_launch.work_unit_key == model_contract.key
    assert model_launch.backend == "codex"
    assert model_launch.exec_mode == "exec"
    assert observed["source_snapshot_digest"] == "a" * 64
    assert (
        D._dynamic_verifier_unit_paths(
            scratchpad, unit.work_unit_id
        )["stdio"].read_bytes()
        == b"codex-event\n"
    )
