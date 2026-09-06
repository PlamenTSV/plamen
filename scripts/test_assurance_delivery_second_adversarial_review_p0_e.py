"""Second independent adversarial review of the live P0-E delivery boundary.

These fixtures target source/output coupling and failure paths that the first
acceptance and review suites do not exercise.  Production code and the prior
reviewer-owned fixtures remain immutable during this review.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import uuid

from artifact_ledger import record_work_unit_artifacts, record_work_unit_inputs
import plamen_driver as D
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract
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
        gate_id="axis_coverage.p0e.second-review",
        gate_class="METHODOLOGY_APPLICATION",
        message="bounded recall repair exhausted",
        affected_identities=("OBL-1",),
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


def test_projection_rejects_in_memory_checkpoint_that_differs_from_bound_file(
    tmp_path: Path,
):
    """The rendered manifest and PhaseIO input must share one checkpoint source."""

    config = _config(tmp_path)
    checkpoint = _checkpoint(config)
    _report(tmp_path)
    scratchpad = Path(config["scratchpad"])

    # Change the authoritative semantics used by the renderer without changing
    # the checkpoint bytes that PhaseIO will bind as its immutable input.
    original = checkpoint.phase_commits["axis_coverage"]
    changed = replace(
        original.unresolved_failures[0],
        message="different in-memory delivery limitation",
    )
    checkpoint.phase_commits["axis_coverage"] = replace(
        original, unresolved_failures=(changed,)
    )

    issues = D._refresh_assurance_projection(checkpoint, scratchpad, config)
    assert issues, (
        "projection accepted a manifest derived from one checkpoint while its "
        "PhaseIO receipt bound different on-disk checkpoint bytes"
    )


def test_same_gate_clearance_rechecks_bytes_after_validation(
    tmp_path: Path, monkeypatch,
):
    """A validate/read race must not clear no-ship debt for changed report bytes."""

    config = _config(tmp_path)
    checkpoint = _checkpoint(config)
    report = _report(tmp_path)
    scratchpad = Path(config["scratchpad"])
    phase = _phase("report_floor")

    D._commit_report_integrity_no_ship(
        phase, checkpoint, scratchpad, config, ["synthetic prior delivery fault"]
    )
    assert D._refresh_assurance_projection(checkpoint, scratchpad, config) == []
    real_validate = D._validate_final_assurance_delivery

    def validate_then_change(*args, **kwargs):
        issues = real_validate(*args, **kwargs)
        assert issues == []
        report.write_text("# Audit Report\n\nchanged after validation\n", encoding="utf-8")
        return issues

    monkeypatch.setattr(D, "_validate_final_assurance_delivery", validate_then_change)
    D._commit_report_phase_success(
        phase, checkpoint, scratchpad, config, list(SC_PHASES)
    )
    assert D._checkpoint_has_report_integrity_no_ship(checkpoint), (
        "same-gate clearance trusted a validation result after the report bytes "
        "used to form its evidence digest had changed"
    )


def test_legacy_shape_with_impossible_driver_row_is_preserved_as_ambiguous_human_text(
    tmp_path: Path,
):
    """A table header alone is not a fingerprint of a driver-generated block."""

    config = _config(tmp_path)
    checkpoint = _checkpoint(config)
    human_block = (
        "Qualified audit result.\n\n"
        "## Appendix E: Unresolved Phase-Completion Debt\n\n"
        "| Phase | State | Gate class | Affected identities | Limitation |\n"
        "|---|---|---|---|---|\n"
        "| human_phase | HUMAN_NOTE | prose | none | author-authored content |"
    )
    report = _report(tmp_path, human_block)

    issues = D._refresh_assurance_projection(
        checkpoint,
        Path(config["scratchpad"]),
        config,
        allow_legacy_migration=True,
    )
    assert issues, "ambiguous legacy-shaped human text was treated as generated"
    assert "author-authored content" in report.read_text(encoding="utf-8")


def test_legacy_shape_must_bind_rows_to_checkpoint_debt_before_deletion(
    tmp_path: Path,
):
    """Valid-looking rows for unrelated debt are not a migration fingerprint."""

    config = _config(tmp_path)
    checkpoint = _checkpoint(config)
    # Every cell is individually valid for the historic table schema, but this
    # row describes breadth debt while the durable checkpoint describes only
    # axis_coverage debt.  A human-authored collision must not be deleted merely
    # because it uses real phase/state/gate/identity vocabulary.
    human_block = (
        "Qualified audit result.\n\n"
        "## Appendix E: Unresolved Phase-Completion Debt\n\n"
        "| Phase | State | Gate class | Affected identities | Limitation |\n"
        "|---|---|---|---|---|\n"
        "| breadth | COMPLETED_WITH_DEBT | METHODOLOGY_APPLICATION | "
        "OBL-999 | author-authored breadth discussion |"
    )
    report = _report(tmp_path, human_block)

    issues = D._refresh_assurance_projection(
        checkpoint,
        Path(config["scratchpad"]),
        config,
        allow_legacy_migration=True,
    )
    assert issues, (
        "legacy migration deleted a schema-valid row that was not derivable "
        "from the exact checkpoint debt"
    )
    assert "author-authored breadth discussion" in report.read_text(encoding="utf-8")


def test_legacy_checkpoint_match_does_not_accept_arbitrary_unknown_gate_text(
    tmp_path: Path,
):
    """Only the literal historic ``old`` escape hatch may relax row parity."""

    config = _config(tmp_path)
    checkpoint = _checkpoint(config)
    human_block = (
        "Qualified audit result.\n\n"
        "## Appendix E: Unresolved Phase-Completion Debt\n\n"
        "| Phase | State | Gate class | Affected identities | Limitation |\n"
        "|---|---|---|---|---|\n"
        "| axis_coverage | COMPLETED_WITH_DEBT | HUMAN_ANALYSIS | "
        "OBL-1 | author-authored interpretation of the same debt |"
    )
    report = _report(tmp_path, human_block)

    issues = D._refresh_assurance_projection(
        checkpoint,
        Path(config["scratchpad"]),
        config,
        allow_legacy_migration=True,
    )
    assert issues, (
        "checkpoint matching treated every unknown gate label as the literal "
        "historic `old` compatibility fingerprint"
    )
    assert "author-authored interpretation" in report.read_text(encoding="utf-8")


def test_existing_quarantine_copy_with_windows_unlink_denial_writes_loud_marker(
    tmp_path: Path, monkeypatch,
):
    """The common resume branch must use the same fail-closed Windows fallback."""

    config = _config(tmp_path)
    checkpoint = _checkpoint(config)
    report = _report(tmp_path)
    scratchpad = Path(config["scratchpad"])
    D._commit_report_integrity_no_ship(
        _phase("report_floor"),
        checkpoint,
        scratchpad,
        config,
        ["synthetic report-integrity failure"],
    )
    digest = hashlib.sha256(report.read_bytes()).hexdigest()
    quarantine = scratchpad / "_overflow" / "report_integrity_no_ship"
    quarantine.mkdir(parents=True, exist_ok=True)
    (quarantine / f"AUDIT_REPORT.{digest}.md").write_bytes(report.read_bytes())

    real_unlink = Path.unlink

    def deny_canonical_unlink(path: Path, *args, **kwargs):
        if path == report:
            raise OSError("synthetic Windows sharing violation")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", deny_canonical_unlink)
    assert D._quarantine_report_integrity_no_ship(
        scratchpad, config["project_root"], checkpoint
    ) is None
    assert report.exists()
    assert (tmp_path / "AUDIT_REPORT.NO_SHIP.json").is_file(), (
        "canonical no-ship report remained after the existing-copy unlink "
        "branch failed, without the loud adjacent fallback marker"
    )
    assert D._snapshot_deliverable_report(checkpoint, str(tmp_path)) == (None, None)


def test_projection_unexpected_data_error_degrades_instead_of_halting(
    tmp_path: Path, monkeypatch,
):
    """Repair-then-degrade applies to renderer data faults as well as I/O faults."""

    config = _config(tmp_path)
    checkpoint = _checkpoint(config)
    report = _report(tmp_path)
    before = report.read_bytes()

    def fail_with_data_shape(*_args, **_kwargs):
        raise TypeError("synthetic renderer data-shape failure")

    monkeypatch.setattr(D, "project_assurance_limitations", fail_with_data_shape)
    issues = D._refresh_assurance_projection(
        checkpoint, Path(config["scratchpad"]), config
    )
    assert issues and "TypeError" in issues[0]
    assert report.read_bytes() == before
