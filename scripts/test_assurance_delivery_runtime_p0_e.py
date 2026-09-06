"""P0-E live report-delivery and no-ship acceptance fixtures.

The pure renderer has its own unit suite.  These fixtures pin the driver seams:
typed ownership, post-assembly/final validation, legacy migration, and the
distinction between a qualified deliverable and report-integrity no-ship debt.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from assurance_limitations import START_MARKER
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract
import plamen_driver as D
from plamen_types import Checkpoint, GateFailure, PhaseCommit, SC_PHASES


def _config(tmp_path: Path) -> dict:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir(parents=True, exist_ok=True)
    run_id = str(uuid.uuid4())
    return {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "scratchpad": str(scratchpad),
        "project_root": str(tmp_path),
        "_run_id": run_id,
    }


def _phase(name: str):
    return next(item for item in SC_PHASES if item.name == name)


def _debt_checkpoint(config: dict, phase_name: str = "axis_coverage") -> Checkpoint:
    failure = GateFailure(
        gate_id=f"{phase_name}.p0e.fixture",
        gate_class="METHODOLOGY_APPLICATION",
        message="bounded recall repair exhausted",
        affected_identities=("OBL-1",),
    )
    commit = PhaseCommit(
        phase_name=phase_name,
        state="COMPLETED_WITH_DEBT",
        run_id=config["_run_id"],
        unresolved_failures=(failure,),
    )
    checkpoint = Checkpoint(
        completed=[phase_name],
        degraded=[phase_name],
        run_id=config["_run_id"],
        phase_commits={phase_name: commit},
    )
    checkpoint.save(Path(config["scratchpad"]))
    return checkpoint


def _report(tmp_path: Path, suffix: str = "") -> Path:
    scratchpad = tmp_path / ".scratchpad"
    source = scratchpad / "report_assembly_fixture_source.md"
    source.write_text("# exact assembly fixture source\n", encoding="utf-8")
    checkpoint = json.loads(
        (scratchpad / "_v2_checkpoint.json").read_text(encoding="utf-8")
    )
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="report_assemble",
        work_unit_id="assembly",
        exact_inputs=(source.name,),
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=120,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        scratchpad, tmp_path, contract, launch, run_id=checkpoint["run_id"]
    )
    path = tmp_path / "AUDIT_REPORT.md"
    path.write_text(
        "# Audit Report\n\n## Summary\n\nQualified audit result.\n" + suffix,
        encoding="utf-8",
    )
    record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=checkpoint["run_id"],
        actor="DRIVER",
    )
    return path


def test_assurance_projection_contract_is_exact_and_driver_only():
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="report_floor",
        work_unit_id="assurance_projection",
    )

    assert contract.model_invoked is False
    assert {item.identity for item in contract.outputs} == {
        "scratchpad:assurance_limitations.json",
        "scratchpad:assurance_limitations.md",
        "scratchpad:assurance_limitations_projection.json",
        "scratchpad:assurance_projection_merge_intent.json",
        "project:AUDIT_REPORT.md",
    }
    assert {item.writer for item in contract.outputs} == {"DRIVER"}
    assert contract.output("project:AUDIT_REPORT.md").write_mode == "MERGE"
    assert "scratchpad:_v2_checkpoint.json" in contract.immutable_inputs


def test_post_assembly_projection_is_exact_qualified_and_ledger_bound(tmp_path: Path):
    config = _config(tmp_path)
    checkpoint = _debt_checkpoint(config)
    report = _report(tmp_path)

    issues = D._refresh_assurance_projection(
        checkpoint, Path(config["scratchpad"]), config,
    )

    assert issues == []
    delivered = report.read_text(encoding="utf-8")
    assert delivered.count(START_MARKER) == 1
    assert "DISCOVERY_RECALL" in delivered
    manifest = json.loads(
        (Path(config["scratchpad"]) / "assurance_limitations.json").read_text(
            encoding="utf-8"
        )
    )
    assert manifest["clean_full_audit_claim_allowed"] is False
    assert D._assert_assurance_status(checkpoint, Path(config["scratchpad"])) == []

    ledger = read_artifact_ledger(Path(config["scratchpad"]))
    key = "sc/thorough/evm/claude/report_floor/assurance_projection"
    records = ledger["work_units"][key]["artifacts"]
    assert set(records) == {
        "scratchpad:assurance_limitations.json",
        "scratchpad:assurance_limitations.md",
        "scratchpad:assurance_limitations_projection.json",
        "scratchpad:assurance_projection_merge_intent.json",
        "project:AUDIT_REPORT.md",
    }
    assert all(record["status"] == "ACTIVE" for record in records.values())
    ledger_before_resume = (
        Path(config["scratchpad"]) / "_artifact_state.json"
    ).read_bytes()
    assert D._refresh_assurance_projection(
        Checkpoint.load(Path(config["scratchpad"])),
        Path(config["scratchpad"]),
        config,
    ) == []
    assert (
        Path(config["scratchpad"]) / "_artifact_state.json"
    ).read_bytes() == ledger_before_resume


def test_assurance_projection_precommit_crash_resumes_exact_merge_preimage(
    tmp_path: Path,
    monkeypatch,
):
    config = _config(tmp_path)
    checkpoint = _debt_checkpoint(config)
    report = _report(tmp_path)
    scratchpad = Path(config["scratchpad"])
    preimage = report.read_bytes()
    real_commit = D._commit_deterministic_driver_work_unit
    monkeypatch.setattr(
        D,
        "_commit_deterministic_driver_work_unit",
        lambda **_kwargs: ["simulated crash before assurance commit"],
    )

    assert D._refresh_assurance_projection(
        checkpoint, scratchpad, config
    ) == ["simulated crash before assurance commit"]
    assert report.read_bytes() != preimage
    key = "sc/thorough/evm/claude/report_floor/assurance_projection"
    unit = read_artifact_ledger(scratchpad)["work_units"][key]
    assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert unit["artifacts"] == {}

    monkeypatch.setattr(D, "_commit_deterministic_driver_work_unit", real_commit)
    assert D._refresh_assurance_projection(
        checkpoint, scratchpad, config
    ) == []
    unit = read_artifact_ledger(scratchpad)["work_units"][key]
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert unit["commit_authority"]["read_modify_write_transitions"][
        "project:AUDIT_REPORT.md"
    ]["write_mode"] == "MERGE"


def test_report_assembly_arms_before_create_and_commits_producer(
    tmp_path: Path,
):
    config = _config(tmp_path)
    scratchpad = Path(config["scratchpad"])
    (scratchpad / "report_index.md").write_text(
        "# Report Index\n\n## Summary\n\nMedium: 1\n",
        encoding="utf-8",
    )
    (scratchpad / "report_medium.md").write_text(
        "### [M-01] Exact finding\n\n"
        "**Severity**: Medium\n\n"
        "**Location**: `src/module.sol:1`\n\n"
        "**Description**: Exact report assembly fixture.\n\n"
        "**Impact**: State integrity can be lost.\n\n"
        "**Recommendation**: Enforce the required relation.\n",
        encoding="utf-8",
    )

    contract, launch, execute, issues = D._arm_report_assembly_phase_io(
        scratchpad=scratchpad,
        config=config,
    )
    assert issues == [] and execute is True
    assert contract is not None and launch is not None
    assert not (tmp_path / "AUDIT_REPORT.md").exists()
    assert D._assemble_report_python(scratchpad, str(tmp_path)) is True
    assert D._commit_report_assembly_phase_io(
        scratchpad=scratchpad,
        config=config,
        contract=contract,
        launch=launch,
    ) == []
    unit = read_artifact_ledger(scratchpad)["work_units"][
        "sc/thorough/evm/claude/report_assemble/assembly"
    ]
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert set(unit["artifacts"]) == {"project:AUDIT_REPORT.md"}


def test_report_assembly_phaseio_binds_exact_scope_coverage_authority(
    tmp_path: Path,
):
    config = _config(tmp_path)
    scratchpad = Path(config["scratchpad"])
    (scratchpad / "report_index.md").write_text(
        "# Report Index\n\n## Summary\n\nMedium: 1\n",
        encoding="utf-8",
    )
    (scratchpad / "report_medium.md").write_text(
        "### [M-01] Exact finding\n\n"
        "**Severity**: Medium\n\n"
        "**Location**: `src/module.sol:1`\n\n"
        "**Description**: Exact report assembly fixture.\n\n"
        "**Impact**: State integrity can be lost.\n\n"
        "**Recommendation**: Enforce the required relation.\n",
        encoding="utf-8",
    )
    authority = scratchpad / "exact_scope_coverage_authority.json"
    authority.write_text('{"authority":"before"}\n', encoding="utf-8")

    contract, launch, execute, issues = D._arm_report_assembly_phase_io(
        scratchpad=scratchpad,
        config=config,
    )
    assert issues == [] and execute is True
    assert contract is not None and launch is not None
    assert (
        "scratchpad:exact_scope_coverage_authority.json"
        in contract.immutable_inputs
    )
    assert D._assemble_report_python(scratchpad, str(tmp_path)) is True
    authority.write_text('{"authority":"after"}\n', encoding="utf-8")

    commit_issues = D._commit_report_assembly_phase_io(
        scratchpad=scratchpad,
        config=config,
        contract=contract,
        launch=launch,
    )
    assert any("input" in issue.lower() for issue in commit_issues)


def test_checkpoint_parity_includes_semantic_mutation_ack_authority(tmp_path: Path):
    """A durable mutation acknowledgement is checkpoint state, not drift.

    Inventory promotion can create this authority before report assembly.  The
    assurance boundary must compare the same complete payload that
    ``Checkpoint.save`` wrote instead of treating a valid acknowledgement as an
    in-memory/disk split.
    """
    config = _config(tmp_path)
    checkpoint = _debt_checkpoint(config)
    checkpoint.semantic_mutation_acks["SMUT-" + "A" * 24] = "1" * 64
    checkpoint.save(Path(config["scratchpad"]))
    _report(tmp_path)

    assert D._checkpoint_memory_disk_parity_issues(
        checkpoint, Path(config["scratchpad"])
    ) == []
    assert D._refresh_assurance_projection(
        checkpoint, Path(config["scratchpad"]), config
    ) == []


def test_legacy_appendix_e_migrates_to_one_managed_projection_on_resume(tmp_path: Path):
    config = _config(tmp_path)
    checkpoint = _debt_checkpoint(config)
    legacy = (
        "\n\n## Appendix E: Unresolved Phase-Completion Debt\n\n"
        "| Phase | State | Gate class | Affected identities | Limitation |\n"
        "|---|---|---|---|---|\n"
        "| axis_coverage | COMPLETED_WITH_DEBT | old | OBL-1 | old row |\n"
    )
    report = _report(tmp_path, legacy)

    assert D._refresh_assurance_projection(
        checkpoint,
        Path(config["scratchpad"]),
        config,
        allow_legacy_migration=True,
    ) == []
    once = report.read_bytes()
    assert b"Appendix E: Unresolved Phase-Completion Debt" not in once
    assert once.count(START_MARKER.encode()) == 1

    assert D._refresh_assurance_projection(
        Checkpoint.load(Path(config["scratchpad"])),
        Path(config["scratchpad"]),
        config,
        allow_legacy_migration=True,
    ) == []
    assert report.read_bytes() == once


def test_final_projection_tamper_is_report_integrity_no_ship(tmp_path: Path):
    config = _config(tmp_path)
    checkpoint = _debt_checkpoint(config)
    report = _report(tmp_path)
    scratchpad = Path(config["scratchpad"])
    assert D._refresh_assurance_projection(checkpoint, scratchpad, config) == []

    report.write_text(
        report.read_text(encoding="utf-8").replace(
            "DISCOVERY_RECALL", "ENRICHMENT_ONLY", 1
        ),
        encoding="utf-8",
    )
    issues = D._validate_final_assurance_delivery(checkpoint, scratchpad, config)
    assert any("driver-owned projection" in item for item in issues)

    D._commit_report_integrity_no_ship(
        _phase("report_floor"), checkpoint, scratchpad, config, issues
    )
    quarantined = D._quarantine_report_integrity_no_ship(
        scratchpad, config["project_root"], checkpoint
    )
    assert quarantined is not None and quarantined.exists()
    assert not report.exists()
    quarantine_receipt = json.loads(
        (
            scratchpad
            / "_overflow"
            / "report_integrity_no_ship"
            / "receipt.json"
        ).read_text(encoding="utf-8")
    )
    assert quarantine_receipt["no_timestamp_snapshot"] is True
    assert quarantine_receipt["sha256"]
    failure = checkpoint.phase_commits["report_floor"].unresolved_failures[0]
    assert failure.gate_class == "REPORT_INTEGRITY"
    assert failure.fallback_policy == "NO_SHIP_QUARANTINE"
    assert D._checkpoint_has_report_integrity_no_ship(checkpoint) is True


def test_earlier_recall_debt_is_qualified_delivery_not_no_ship(
    tmp_path: Path, monkeypatch,
):
    config = _config(tmp_path)
    checkpoint = _debt_checkpoint(config)
    report = _report(tmp_path)
    scratchpad = Path(config["scratchpad"])

    assert D._refresh_assurance_projection(checkpoint, scratchpad, config) == []
    assert D._validate_final_assurance_delivery(checkpoint, scratchpad, config) == []
    assert D._checkpoint_has_report_integrity_no_ship(checkpoint) is False
    assert report.exists()
    assert checkpoint.degraded == ["axis_coverage"]
    snapshot = tmp_path / "AUDIT_REPORT-qualified-snapshot.md"
    snapshot.write_text("qualified snapshot\n", encoding="utf-8")
    calls = []

    def snapshot_writer(project_root):
        calls.append(project_root)
        return str(snapshot)

    monkeypatch.setattr(D, "_snapshot_report_timestamped", snapshot_writer)
    assert D._snapshot_deliverable_report(checkpoint, str(tmp_path)) == (
        str(report),
        str(snapshot),
    )
    assert calls == [str(tmp_path)]


def test_assurance_status_assertion_rejects_false_clean_manifest(tmp_path: Path):
    config = _config(tmp_path)
    checkpoint = _debt_checkpoint(config)
    report = _report(tmp_path)
    scratchpad = Path(config["scratchpad"])
    assert D._refresh_assurance_projection(checkpoint, scratchpad, config) == []
    manifest_path = scratchpad / "assurance_limitations.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["clean_full_audit_claim_allowed"] = True
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    issues = D._assert_assurance_status(checkpoint, scratchpad)
    assert issues and "false clean/full-audit authorization" in issues[0]
    assert report.exists()


def test_main_wires_projection_after_assembly_and_final_gate_before_snapshot():
    source = __import__("inspect").getsource(D.main)
    assembly = source.index("_assemble_report_python(")
    first_projection = source.index("_refresh_assurance_projection(", assembly)
    report_floor = source.index('if phase.name == "report_floor"')
    floor_projection = source.index("_refresh_assurance_projection(", report_floor)
    final_validation = source.rindex("_validate_final_assurance_delivery(")
    terminal_delivery = source.rindex("_publish_terminal_deliverable_report(")

    assert assembly < first_projection < report_floor
    assert report_floor < floor_projection < final_validation < terminal_delivery


def test_no_ship_snapshot_guard_never_calls_snapshot_writer(
    tmp_path: Path, monkeypatch,
):
    config = _config(tmp_path)
    checkpoint = _debt_checkpoint(config)
    _report(tmp_path)
    scratchpad = Path(config["scratchpad"])
    D._commit_report_integrity_no_ship(
        _phase("report_floor"),
        checkpoint,
        scratchpad,
        config,
        ["synthetic delivery fault"],
    )

    def forbidden(_project_root):
        raise AssertionError("snapshot writer must not run for no-ship debt")

    monkeypatch.setattr(D, "_snapshot_report_timestamped", forbidden)
    assert D._snapshot_deliverable_report(checkpoint, str(tmp_path)) == (
        None,
        None,
    )


def test_terminal_report_removed_before_delivery_is_no_ship_and_nonzero(
    tmp_path: Path, monkeypatch,
):
    config = _config(tmp_path)
    checkpoint = Checkpoint(run_id=config["_run_id"])
    checkpoint.save(Path(config["scratchpad"]))
    report = _report(tmp_path)
    accepted_report_sha256 = hashlib.sha256(report.read_bytes()).hexdigest()

    def remove_before_snapshot(project_root):
        (Path(project_root) / "AUDIT_REPORT.md").unlink()
        return None

    monkeypatch.setattr(D, "_snapshot_report_timestamped", remove_before_snapshot)
    report_str, snapshot_str, no_ship, quarantined = (
        D._publish_terminal_deliverable_report(
            checkpoint,
            Path(config["scratchpad"]),
            config,
            list(SC_PHASES),
            expected_report_sha256=accepted_report_sha256,
        )
    )

    assert report_str is None and snapshot_str is None
    assert no_ship is True and quarantined is None
    assert not report.exists()
    assert D._checkpoint_has_report_integrity_no_ship(checkpoint)
    assert D._pipeline_terminal_exit_code(checkpoint) != 0
    failure = checkpoint.phase_commits["report_floor"].unresolved_failures[0]
    assert failure.gate_class == "REPORT_INTEGRITY"
    assert "disappeared" in failure.message


def test_terminal_report_byte_replacement_before_delivery_is_rejected(
    tmp_path: Path, monkeypatch,
):
    config = _config(tmp_path)
    checkpoint = Checkpoint(run_id=config["_run_id"])
    checkpoint.save(Path(config["scratchpad"]))
    report = _report(tmp_path)
    accepted_report_sha256 = hashlib.sha256(report.read_bytes()).hexdigest()
    replacement = b"# Replaced report\n\n## Summary\n\nUnbound replacement bytes.\n"

    def replace_during_snapshot(project_root):
        canonical = Path(project_root) / "AUDIT_REPORT.md"
        canonical.write_bytes(replacement)
        snapshot = Path(project_root) / "AUDIT_REPORT-replaced.md"
        snapshot.write_bytes(replacement)
        return str(snapshot)

    monkeypatch.setattr(D, "_snapshot_report_timestamped", replace_during_snapshot)
    report_str, snapshot_str, no_ship, quarantined = (
        D._publish_terminal_deliverable_report(
            checkpoint,
            Path(config["scratchpad"]),
            config,
            list(SC_PHASES),
            expected_report_sha256=accepted_report_sha256,
        )
    )

    assert report_str is None and snapshot_str is None
    assert no_ship is True
    assert quarantined is not None and quarantined.read_bytes() == replacement
    assert not report.exists()
    assert D._checkpoint_has_report_integrity_no_ship(checkpoint)
    assert D._pipeline_terminal_exit_code(checkpoint) != 0
    failure = checkpoint.phase_commits["report_floor"].unresolved_failures[0]
    assert failure.gate_class == "REPORT_INTEGRITY"
    assert "changed after final validation" in failure.message


def test_terminal_publisher_rejects_missing_digest_authority(
    tmp_path: Path, monkeypatch,
):
    config = _config(tmp_path)
    checkpoint = Checkpoint(run_id=config["_run_id"])
    checkpoint.save(Path(config["scratchpad"]))
    report = _report(tmp_path)

    def forbidden_snapshot(_project_root):
        raise AssertionError("publisher must not mint authority from current bytes")

    monkeypatch.setattr(D, "_snapshot_report_timestamped", forbidden_snapshot)
    report_str, snapshot_str, no_ship, quarantined = (
        D._publish_terminal_deliverable_report(
            checkpoint,
            Path(config["scratchpad"]),
            config,
            list(SC_PHASES),
            expected_report_sha256=None,
        )
    )

    assert report_str is None and snapshot_str is None
    assert no_ship is True
    assert quarantined is not None and quarantined.is_file()
    assert not report.exists()
    assert D._pipeline_terminal_exit_code(checkpoint) != 0


def test_terminal_snapshot_byte_mutation_is_not_blessed(
    tmp_path: Path, monkeypatch,
):
    config = _config(tmp_path)
    checkpoint = Checkpoint(run_id=config["_run_id"])
    checkpoint.save(Path(config["scratchpad"]))
    report = _report(tmp_path)
    accepted_report_sha256 = hashlib.sha256(report.read_bytes()).hexdigest()

    def mutate_snapshot_only(project_root):
        snapshot = Path(project_root) / "AUDIT_REPORT-mutated-snapshot.md"
        snapshot.write_bytes(b"unbound snapshot bytes\n")
        return str(snapshot)

    monkeypatch.setattr(D, "_snapshot_report_timestamped", mutate_snapshot_only)
    report_str, snapshot_str, no_ship, quarantined = (
        D._publish_terminal_deliverable_report(
            checkpoint,
            Path(config["scratchpad"]),
            config,
            list(SC_PHASES),
            expected_report_sha256=accepted_report_sha256,
        )
    )

    assert report_str is None and snapshot_str is None
    assert no_ship is True
    assert quarantined is not None
    assert D._pipeline_terminal_exit_code(checkpoint) != 0


def test_projection_fault_becomes_typed_no_ship_without_reblessing_report(
    tmp_path: Path, monkeypatch,
):
    config = _config(tmp_path)
    checkpoint = _debt_checkpoint(config)
    report = _report(tmp_path)
    original = report.read_bytes()
    scratchpad = Path(config["scratchpad"])

    def fail_projection(*_args, **_kwargs):
        raise OSError("synthetic projection replace failure")

    monkeypatch.setattr(D, "project_assurance_limitations", fail_projection)
    issues = D._refresh_assurance_projection(checkpoint, scratchpad, config)
    assert issues and "synthetic projection replace failure" in issues[0]
    assert report.read_bytes() == original

    D._commit_report_integrity_no_ship(
        _phase("report_floor"), checkpoint, scratchpad, config, issues
    )
    assert D._checkpoint_has_report_integrity_no_ship(checkpoint)


def test_final_gate_detects_phaseio_ledger_tamper(tmp_path: Path):
    config = _config(tmp_path)
    checkpoint = _debt_checkpoint(config)
    _report(tmp_path)
    scratchpad = Path(config["scratchpad"])
    assert D._refresh_assurance_projection(checkpoint, scratchpad, config) == []
    ledger_path = scratchpad / "_artifact_state.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    key = "sc/thorough/evm/claude/report_floor/assurance_projection"
    ledger["work_units"][key]["artifacts"][
        "project:AUDIT_REPORT.md"
    ]["owner_key"] = "sc/thorough/evm/claude/report_floor/forged"
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")

    issues = D._validate_final_assurance_delivery(checkpoint, scratchpad, config)
    assert any("owner work-unit mismatch" in issue for issue in issues)


def test_exact_resume_can_clear_prior_no_ship_only_with_validated_evidence(
    tmp_path: Path,
):
    config = _config(tmp_path)
    checkpoint = _debt_checkpoint(config)
    scratchpad = Path(config["scratchpad"])
    _report(tmp_path)
    phase = _phase("report_floor")
    D._commit_report_integrity_no_ship(
        phase, checkpoint, scratchpad, config, ["synthetic prior projection fault"]
    )
    checkpoint.save(scratchpad)
    resumed = Checkpoint.load(scratchpad)
    assert D._checkpoint_has_report_integrity_no_ship(resumed)

    # A repaired report is projected and validated before the explicit
    # same-gate clearance; ordinary mark_completed cannot erase this debt.
    assert D._refresh_assurance_projection(resumed, scratchpad, config) == []
    D._commit_report_phase_success(
        phase, resumed, scratchpad, config, list(SC_PHASES)
    )
    assert D._checkpoint_has_report_integrity_no_ship(resumed) is False
    assert resumed.phase_commits["report_floor"].state == "CLEAN"
    assert resumed.phase_commits["report_floor"].clearance_events

    # Refresh once more because clearing the report-integrity debt changes the
    # authoritative assurance manifest.  Resume then validates byte-for-byte.
    assert D._refresh_assurance_projection(resumed, scratchpad, config) == []
    ledger_after_reexecution = (scratchpad / "_artifact_state.json").read_bytes()
    assert D._refresh_assurance_projection(
        Checkpoint.load(scratchpad), scratchpad, config
    ) == []
    assert (scratchpad / "_artifact_state.json").read_bytes() == (
        ledger_after_reexecution
    )
    roundtrip = Checkpoint.load(scratchpad)
    assert D._validate_final_assurance_delivery(
        roundtrip, scratchpad, config
    ) == []
