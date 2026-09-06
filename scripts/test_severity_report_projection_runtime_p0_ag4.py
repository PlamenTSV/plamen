"""Red P0-AG4 contracts for live severity report projection.

This file is deliberately test-only.  It fixes the two runtime observation
points without authorizing the later severity cutover:

* ``PRE_ASSEMBLE`` runs at the start of ``report_assemble``, after the index
  and tier writers exist but before Python concatenates them;
* ``POST_REPORT_FLOOR`` runs after every final-report mutation and before the
  final assurance projection;
* both projections replay provider-owned adjudication receipts, are
  driver-owned, and never rewrite a report artifact; and
* drift, ambiguity, unresolved authority, or tamper is durable phase debt,
  not a model-authored success/failure label.

Expected driver seam::

    _refresh_severity_report_shadow_projection(
        checkpoint, scratchpad, config, *, stage
    ) -> list[str]

The helper owns the PhaseIO record and commits child work units
``report_projection`` and ``final_report_projection`` under
``severity_adjudication_shadow``.  It is haltless, but any non-clean receipt
must remain ``COMPLETED_WITH_DEBT``.

Expected runtime extension::

    write_shadow_report_severity_receipt(
        scratchpad, *, run_id, projection_stage="PRE_ASSEMBLE",
        project_root=None,
    ) -> dict

``POST_REPORT_FLOOR`` writes ``severity_final_report_shadow_receipt.json``;
it must not overwrite the pre-assemble receipt.  Neither API may consume a
configuration boolean as benchmark/cutover authority.
"""
from __future__ import annotations

import inspect
import json
from pathlib import Path
import uuid

import pytest

from phase_io_contracts import resolve_phase_io_contract
import plamen_driver as D
from plamen_types import Checkpoint, L1_PHASES, SC_PHASES
import severity_runtime as runtime
import test_severity_adjudication_report_shadow_p0_ag2 as ag2


PRE_STAGE = "PRE_ASSEMBLE"
FINAL_STAGE = "POST_REPORT_FLOOR"
PRE_RECEIPT = "severity_report_shadow_receipt.json"
FINAL_RECEIPT = "severity_final_report_shadow_receipt.json"


def _config(tmp_path: Path, *, pipeline: str = "sc") -> dict:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir(parents=True, exist_ok=True)
    return {
        "pipeline": pipeline,
        "mode": "thorough",
        "language": "evm" if pipeline == "sc" else "rust",
        "cli_backend": "claude",
        "scratchpad": str(scratchpad),
        "project_root": str(tmp_path),
        "_run_id": str(uuid.uuid4()),
    }


def _body(
    scratchpad: Path,
    *,
    report_id: str,
    severity: str,
    duplicate: bool = False,
) -> None:
    block = (
        f"## [{report_id}] Generic retained claim\n\n"
        f"**Severity**: {severity}\n\n"
        "Evidence-bound generic report body.\n"
    )
    if duplicate:
        block += "\n" + block
    (scratchpad / "report_critical_high.md").write_text(
        block, encoding="utf-8"
    )
    (scratchpad / "report_medium.md").write_text("", encoding="utf-8")
    (scratchpad / "report_low_info.md").write_text("", encoding="utf-8")


def _index(
    scratchpad: Path,
    *,
    candidate_id: str,
    report_id: str,
    severity: str,
    duplicate: bool = False,
) -> None:
    row = f"| {report_id} | Generic retained claim | {severity} | None | {candidate_id} |\n"
    (scratchpad / "report_index.md").write_text(
        "## Master Finding Index\n\n"
        "| Report ID | Title | Severity | Trust Adjustment | Source Findings |\n"
        "|---|---|---|---|---|\n"
        + row
        + (row if duplicate else ""),
        encoding="utf-8",
    )


def _unresolved_state(
    scratchpad: Path,
    *,
    run_id: str,
    candidate_id: str = "H-101",
) -> dict:
    decision = ag2._authoritative_decision(
        candidate_id=candidate_id,
        upstream="High",
        proposed="Medium",
        run_id=run_id,
    )
    assert decision["status"] == "CHALLENGE_REQUIRED"
    assert decision["retention_severity"] == "High"
    ag2._write_shadow_state(scratchpad, [decision], run_id=run_id)
    return decision


def _resolved_state(
    scratchpad: Path,
    *,
    run_id: str,
    candidate_id: str = "H-101",
) -> dict:
    decision = ag2._authoritative_decision(
        candidate_id=candidate_id,
        upstream="High",
        proposed="Medium",
        run_id=run_id,
    )
    ag2._write_shadow_state(scratchpad, [decision], run_id=run_id)
    ag2._execute_observed_adjudicator(
        scratchpad,
        candidate_id,
        ag2._adjudication_proposal(decision, resolved="Medium"),
        run_id=run_id,
    )
    _written, issues = ag2._bind(scratchpad, candidate_id)
    assert not issues
    return ag2._load_candidate_decision(scratchpad, candidate_id)


def _driver_projection_api():
    value = getattr(D, "_refresh_severity_report_shadow_projection", None)
    assert callable(value), (
        "P0-AG4 driver seam is absent: add "
        "_refresh_severity_report_shadow_projection(checkpoint, scratchpad, "
        "config, *, stage)"
    )
    return value


def test_phaseio_has_separate_driver_owned_pre_and_final_projection_contracts():
    common = dict(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="severity_adjudication_shadow",
    )
    pre = resolve_phase_io_contract(
        **common,
        work_unit_id="report_projection",
    )
    final = resolve_phase_io_contract(
        **common,
        work_unit_id="final_report_projection",
    )

    assert pre.model_invoked is final.model_invoked is False
    assert {item.identity for item in pre.outputs} == {
        f"scratchpad:{PRE_RECEIPT}"
    }
    assert {item.identity for item in final.outputs} == {
        f"scratchpad:{FINAL_RECEIPT}"
    }
    assert {item.writer for item in (*pre.outputs, *final.outputs)} == {"DRIVER"}
    assert {
        "scratchpad:report_index.md",
        "scratchpad:report_critical_high.md",
        "scratchpad:report_medium.md",
        "scratchpad:report_low_info.md",
    }.issubset(set(pre.immutable_inputs))
    assert {
        "scratchpad:severity_decision_ledger.shadow.json",
        f"scratchpad:{PRE_RECEIPT}",
        "project:AUDIT_REPORT.md",
    }.issubset(set(final.immutable_inputs))
    assert "project:AUDIT_REPORT.md" not in {
        item.identity for item in (*pre.outputs, *final.outputs)
    }


def test_preassemble_projection_uses_retention_for_unresolved_and_never_mutates_report(
    tmp_path: Path,
):
    config = _config(tmp_path)
    scratchpad = Path(config["scratchpad"])
    _unresolved_state(scratchpad, run_id=config["_run_id"])
    _index(
        scratchpad,
        candidate_id="H-101",
        report_id="H-01",
        severity="High",
    )
    _body(scratchpad, report_id="H-01", severity="High")
    tracked = {
        path: path.read_bytes()
        for path in (
            scratchpad / "report_index.md",
            scratchpad / "report_critical_high.md",
            scratchpad / "report_medium.md",
            scratchpad / "report_low_info.md",
        )
    }

    receipt = runtime.write_shadow_report_severity_receipt(
        scratchpad,
        run_id=config["_run_id"],
        projection_stage=PRE_STAGE,
    )

    row = next(item for item in receipt["rows"] if item["candidate_id"] == "H-101")
    assert receipt["projection_stage"] == PRE_STAGE
    assert receipt["authority_status"] == "SHADOW_ONLY"
    assert receipt["unresolved_candidate_ids"] == ["H-101"]
    assert row["severity_status"] == "UNRESOLVED_SEVERITY"
    assert row["authorized_severity"] == "High"
    assert all(path.read_bytes() == before for path, before in tracked.items())


def test_preassemble_projection_replays_provider_receipt_and_rejects_tamper(
    tmp_path: Path,
):
    config = _config(tmp_path)
    scratchpad = Path(config["scratchpad"])
    _resolved_state(scratchpad, run_id=config["_run_id"])
    _index(
        scratchpad,
        candidate_id="H-101",
        report_id="M-01",
        severity="Medium",
    )
    _body(scratchpad, report_id="M-01", severity="Medium")

    clean = runtime.write_shadow_report_severity_receipt(
        scratchpad,
        run_id=config["_run_id"],
        projection_stage=PRE_STAGE,
    )
    assert clean["drift_event_count"] == 0

    worker_runs = list(scratchpad.glob("severity_adjudication_worker_run.*.json"))
    assert len(worker_runs) == 1
    worker = json.loads(worker_runs[0].read_text(encoding="utf-8"))
    worker["backend"] = "forged-backend"
    worker_runs[0].write_text(json.dumps(worker), encoding="utf-8")
    with pytest.raises(Exception, match="receipt|digest|backend|authority"):
        runtime.write_shadow_report_severity_receipt(
            scratchpad,
            run_id=config["_run_id"],
            projection_stage=PRE_STAGE,
        )


def test_drift_and_ambiguous_mapping_are_visible_typed_projection_debt(
    tmp_path: Path,
):
    config = _config(tmp_path)
    scratchpad = Path(config["scratchpad"])
    checkpoint = Checkpoint(run_id=config["_run_id"])
    _resolved_state(scratchpad, run_id=config["_run_id"])
    _index(
        scratchpad,
        candidate_id="H-101",
        report_id="L-01",
        severity="Low",
        duplicate=True,
    )
    _body(scratchpad, report_id="L-01", severity="Low", duplicate=True)
    before = {
        path: path.read_bytes()
        for path in scratchpad.glob("report_*.md")
    }

    issues = _driver_projection_api()(
        checkpoint, scratchpad, config, stage=PRE_STAGE
    )

    assert issues
    receipt = json.loads((scratchpad / PRE_RECEIPT).read_text(encoding="utf-8"))
    kinds = {event["drift_kind"] for event in receipt["drift_events"]}
    assert "AMBIGUOUS_LEGACY_MAPPING" in kinds
    assert "UNAUTHORIZED_TIER_MUTATION" in kinds
    commit = checkpoint.phase_commits[
        "severity_adjudication_shadow::report_projection"
    ]
    assert commit.state == "COMPLETED_WITH_DEBT"
    assert commit.unresolved_failures
    assert all(path.read_bytes() == raw for path, raw in before.items())


def test_provider_tamper_becomes_visible_debt_without_relaunch_or_report_mutation(
    tmp_path: Path,
):
    config = _config(tmp_path)
    scratchpad = Path(config["scratchpad"])
    checkpoint = Checkpoint(run_id=config["_run_id"])
    _resolved_state(scratchpad, run_id=config["_run_id"])
    _index(
        scratchpad,
        candidate_id="H-101",
        report_id="M-01",
        severity="Medium",
    )
    _body(scratchpad, report_id="M-01", severity="Medium")
    report_before = {
        path: path.read_bytes() for path in scratchpad.glob("report_*.md")
    }
    worker_run = next(
        scratchpad.glob("severity_adjudication_worker_run.*.json")
    )
    payload = json.loads(worker_run.read_text(encoding="utf-8"))
    payload["receipt_digest"] = "0" * 64
    worker_run.write_text(json.dumps(payload), encoding="utf-8")
    provider_dirs_before = sorted(
        path.relative_to(scratchpad).as_posix()
        for path in (scratchpad / ".worker_execution_receipts").rglob("*")
    )

    issues = _driver_projection_api()(
        checkpoint, scratchpad, config, stage=PRE_STAGE
    )

    assert issues and any("receipt" in issue.casefold() for issue in issues)
    commit = checkpoint.phase_commits[
        "severity_adjudication_shadow::report_projection"
    ]
    assert commit.state == "COMPLETED_WITH_DEBT"
    assert sorted(
        path.relative_to(scratchpad).as_posix()
        for path in (scratchpad / ".worker_execution_receipts").rglob("*")
    ) == provider_dirs_before
    assert all(path.read_bytes() == raw for path, raw in report_before.items())


def test_post_floor_projection_binds_final_report_without_mutating_it(
    tmp_path: Path,
):
    config = _config(tmp_path)
    scratchpad = Path(config["scratchpad"])
    _unresolved_state(scratchpad, run_id=config["_run_id"])
    _index(
        scratchpad,
        candidate_id="H-101",
        report_id="H-01",
        severity="High",
    )
    _body(scratchpad, report_id="H-01", severity="High")
    runtime.write_shadow_report_severity_receipt(
        scratchpad,
        run_id=config["_run_id"],
        projection_stage=PRE_STAGE,
    )
    report = tmp_path / "AUDIT_REPORT.md"
    report.write_text(
        "# Audit Report\n\n"
        "## [H-01] Generic retained claim\n\n"
        "**Severity**: High\n\n"
        "Final post-floor body.\n",
        encoding="utf-8",
    )
    before = report.read_bytes()
    pre_receipt_before = (scratchpad / PRE_RECEIPT).read_bytes()

    final = runtime.write_shadow_report_severity_receipt(
        scratchpad,
        run_id=config["_run_id"],
        projection_stage=FINAL_STAGE,
        project_root=tmp_path,
    )

    assert final["projection_stage"] == FINAL_STAGE
    assert final["authority_status"] == "SHADOW_ONLY"
    assert final["unresolved_candidate_ids"] == ["H-101"]
    assert final["final_report_sha256"]
    assert (scratchpad / FINAL_RECEIPT).is_file()
    assert (scratchpad / PRE_RECEIPT).read_bytes() == pre_receipt_before
    assert report.read_bytes() == before


def test_driver_hooks_are_at_immediate_preassemble_and_true_post_floor_boundaries():
    source = inspect.getsource(D.main)

    assemble = source.index('if phase.name == "report_assemble"')
    pre_hook = source.index(
        "_refresh_severity_report_shadow_projection(", assemble
    )
    pre_stage = source.index(f'"{PRE_STAGE}"', pre_hook)
    assembly_work = source.index("_write_final_subsystem_coverage_summary(", assemble)
    assert assemble < pre_hook < pre_stage < assembly_work

    floor = source.index('if phase.name == "report_floor"')
    last_floor_mutation = source.index(
        "_append_external_research_appendix_note(", floor
    )
    final_hook = source.index(
        "_refresh_severity_report_shadow_projection(", last_floor_mutation
    )
    final_stage = source.index(f'"{FINAL_STAGE}"', final_hook)
    assurance = source.index("_refresh_assurance_projection(", last_floor_mutation)
    assert last_floor_mutation < final_hook < final_stage < assurance

    for phases in (SC_PHASES, L1_PHASES):
        names = [phase.name for phase in phases]
        assert names.index("report_index") < names.index("report_critical_high")
        assert names.index("report_medium") < names.index("report_assemble")
        assert names.index("report_low_info") < names.index("report_assemble")
        assert names.index("report_assemble") < names.index("report_floor")


def test_sc_and_l1_adjudication_methodology_bindings_are_disjoint_and_exact():
    resolver = getattr(D, "_severity_adjudication_methodology_files", None)
    assert callable(resolver), (
        "live severity preparation needs one pipeline-aware methodology resolver"
    )
    sc = {key: Path(value).resolve() for key, value in resolver("sc").items()}
    l1 = {key: Path(value).resolve() for key, value in resolver("l1").items()}

    assert sc and l1
    # Generic finding/evidence rules stay shared per the anti-bloat contract;
    # only the ecosystem severity matrices must be disjoint.
    shared = set(sc.values()) & set(l1.values())
    assert {
        next(
            suffix for suffix in (
                "rules/finding-output-format.md",
                "rules/phase5-poc-execution.md",
            )
            if path.as_posix().endswith(suffix)
        )
        for path in shared
    } == {
        "rules/finding-output-format.md",
        "rules/phase5-poc-execution.md",
    }
    assert any(
        path.as_posix().endswith("rules/report-template.md")
        for path in sc.values()
    )
    assert any(
        path.as_posix().endswith("docs/l1-mode/severity-matrix.md")
        for path in l1.values()
    )
    assert not any("docs/l1-mode" in path.as_posix() for path in sc.values())
    assert not any("rules/report-template.md" in path.as_posix() for path in l1.values())
    with pytest.raises(ValueError):
        resolver("unknown-pipeline")


def test_shadow_projection_cannot_cut_over_severity_without_benchmark_authority(
    tmp_path: Path,
):
    config = _config(tmp_path)
    scratchpad = Path(config["scratchpad"])
    _unresolved_state(scratchpad, run_id=config["_run_id"])
    _index(
        scratchpad,
        candidate_id="H-101",
        report_id="L-01",
        severity="Low",
    )
    _body(scratchpad, report_id="L-01", severity="Low")
    report = tmp_path / "AUDIT_REPORT.md"
    report.write_text(
        "# Audit Report\n\n## [L-01] Generic retained claim\n\n"
        "**Severity**: Low\n",
        encoding="utf-8",
    )
    tracked = {
        path: path.read_bytes()
        for path in (
            scratchpad / "report_index.md",
            scratchpad / "report_critical_high.md",
            scratchpad / "report_medium.md",
            scratchpad / "report_low_info.md",
            report,
        )
    }

    pre = runtime.write_shadow_report_severity_receipt(
        scratchpad,
        run_id=config["_run_id"],
        projection_stage=PRE_STAGE,
    )
    final = runtime.write_shadow_report_severity_receipt(
        scratchpad,
        run_id=config["_run_id"],
        projection_stage=FINAL_STAGE,
        project_root=tmp_path,
    )

    assert pre["authority_status"] == final["authority_status"] == "SHADOW_ONLY"
    assert pre["drift_event_count"] and final["drift_event_count"]
    assert all(path.read_bytes() == raw for path, raw in tracked.items())
    assert not (scratchpad / "severity_benchmark_cutover_authorization.json").exists()
    # Shadow observation may expose debt, but it cannot rewrite the existing
    # legacy severity binding or create a second binding authority.
    assert not (scratchpad / "severity_binding.shadow_cutover.md").exists()
