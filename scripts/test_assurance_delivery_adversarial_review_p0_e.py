"""Independent adversarial review fixtures for the live P0-E boundary.

These tests express delivery invariants that are not established by the
acceptance fixtures.  They intentionally exercise the source/ownership and
clearance boundaries rather than retesting the pure Markdown renderer.
"""

from __future__ import annotations

from dataclasses import replace
import uuid
from pathlib import Path

from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
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


def _checkpoint(config: dict) -> Checkpoint:
    failure = GateFailure(
        gate_id="axis_coverage.p0e.adversarial",
        gate_class="METHODOLOGY_APPLICATION",
        message="bounded recall repair exhausted",
        affected_identities=("OBL-1",),
        input_digest="a" * 64,
        output_digest="b" * 64,
        contract_digest="c" * 64,
        repair_owner="axis_coverage",
        fallback_policy="CONSUME_WITH_DEBT",
        allowed_fallback="retain unresolved coverage obligation",
    )
    commit = PhaseCommit(
        phase_name="axis_coverage",
        state="COMPLETED_WITH_DEBT",
        run_id=config["_run_id"],
        unresolved_failures=(failure,),
    )
    checkpoint = Checkpoint(
        completed=["axis_coverage"],
        degraded=["axis_coverage"],
        run_id=config["_run_id"],
        phase_commits={"axis_coverage": commit},
    )
    checkpoint.save(Path(config["scratchpad"]))
    return checkpoint


def _report(tmp_path: Path, body: str = "Qualified audit result.") -> Path:
    scratchpad = tmp_path / ".scratchpad"
    source = scratchpad / "report_assembly_fixture_source.md"
    source.write_text("# exact assembly fixture source\n", encoding="utf-8")
    checkpoint = __import__("json").loads(
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
    report = tmp_path / "AUDIT_REPORT.md"
    report.write_text(
        f"# Audit Report\n\n## Summary\n\n{body}\n",
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
    return report


def test_phaseio_receipt_binds_the_declared_checkpoint_input(tmp_path: Path):
    """The immutable checkpoint in the contract must be an actual receipt input."""
    config = _config(tmp_path)
    checkpoint = _checkpoint(config)
    _report(tmp_path)

    assert D._refresh_assurance_projection(
        checkpoint, Path(config["scratchpad"]), config
    ) == []
    ledger = read_artifact_ledger(Path(config["scratchpad"]))
    key = "sc/thorough/evm/claude/report_floor/assurance_projection"
    unit = ledger["work_units"][key]

    assert "scratchpad:_v2_checkpoint.json" in unit["input_bindings"]
    assert unit["input_set_digest"]


def test_final_gate_rejects_semantically_changed_unbound_checkpoint_source(
    tmp_path: Path,
):
    """Changing delivery policy in the source checkpoint cannot reuse a receipt."""
    config = _config(tmp_path)
    checkpoint = _checkpoint(config)
    _report(tmp_path)
    scratchpad = Path(config["scratchpad"])
    assert D._refresh_assurance_projection(checkpoint, scratchpad, config) == []

    original_commit = checkpoint.phase_commits["axis_coverage"]
    original_failure = original_commit.unresolved_failures[0]
    changed_failure = replace(
        original_failure,
        fallback_policy="NO_SHIP_QUARANTINE",
        allowed_fallback="report must not ship",
    )
    checkpoint.phase_commits["axis_coverage"] = replace(
        original_commit,
        unresolved_failures=(changed_failure,),
    )
    checkpoint.save(scratchpad)

    issues = D._validate_final_assurance_delivery(
        checkpoint, scratchpad, config
    )
    assert issues, "a receipt for the prior checkpoint source was accepted"


def test_report_success_cannot_clear_no_ship_without_current_validation(
    tmp_path: Path,
):
    """The clearance authority must prove current bytes, not trust its caller."""
    config = _config(tmp_path)
    checkpoint = _checkpoint(config)
    report = _report(tmp_path)
    scratchpad = Path(config["scratchpad"])
    phase = _phase("report_floor")

    D._commit_report_integrity_no_ship(
        phase,
        checkpoint,
        scratchpad,
        config,
        ["synthetic prior projection failure"],
    )
    assert D._checkpoint_has_report_integrity_no_ship(checkpoint)
    report.write_text("# Audit Report\n\nUnvalidated replacement.\n", encoding="utf-8")

    D._commit_report_phase_success(
        phase, checkpoint, scratchpad, config, list(SC_PHASES)
    )
    assert D._checkpoint_has_report_integrity_no_ship(checkpoint), (
        "unvalidated report bytes cleared typed no-ship debt"
    )


def test_human_authored_appendix_e_is_not_deleted_as_legacy_projection(
    tmp_path: Path,
):
    """A heading collision alone is not provenance for destructive migration."""
    config = _config(tmp_path)
    checkpoint = _checkpoint(config)
    report = _report(
        tmp_path,
        "Qualified audit result.\n\n"
        "## Appendix E: Unresolved Phase-Completion Debt\n\n"
        "Human-authored analysis that does not use the legacy generated table.",
    )

    assert D._refresh_assurance_projection(
        checkpoint,
        Path(config["scratchpad"]),
        config,
        allow_legacy_migration=True,
    ) == []
    assert "Human-authored analysis" in report.read_text(encoding="utf-8")


def test_quarantine_failure_cannot_leave_no_ship_report_at_delivery_path(
    tmp_path: Path, monkeypatch,
):
    """Hard no-ship must fail closed even when the first rename is unavailable."""
    config = _config(tmp_path)
    checkpoint = _checkpoint(config)
    report = _report(tmp_path)
    scratchpad = Path(config["scratchpad"])
    phase = _phase("report_floor")
    D._commit_report_integrity_no_ship(
        phase, checkpoint, scratchpad, config, ["synthetic integrity failure"]
    )

    real_rename = Path.rename

    def deny_delivery_rename(path: Path, target):
        if path == report:
            raise OSError("synthetic Windows sharing violation")
        return real_rename(path, target)

    monkeypatch.setattr(Path, "rename", deny_delivery_rename)
    D._quarantine_report_integrity_no_ship(
        scratchpad, config["project_root"], checkpoint
    )

    assert not report.exists(), (
        "typed no-ship debt suppressed snapshots but left AUDIT_REPORT.md at "
        "the canonical delivery path"
    )
