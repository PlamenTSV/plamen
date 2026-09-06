"""Fixture-first contract for the live severity-adjudication shadow phase.

The lower-level planner, provider receipt, binder, and reconciliation modules
are already independently tested.  These fixtures deliberately stay red until
the driver makes that transaction a real, haltless phase.  In particular, a
generic model phase is not sufficient: the driver must own planning, launch
authority, binding, reconciliation, and the typed clean/debt checkpoint.
"""
from __future__ import annotations

import inspect
import json
from pathlib import Path
import sys
from typing import Any, Mapping

import pytest

import plamen_driver as D
import severity_adjudication_work as W
import worker_execution_receipts as X
from plamen_types import Checkpoint, GateFailure, L1_PHASES, SC_PHASES
from test_severity_adjudication_work_p0_ag3 import (
    AUDIT_DIGEST,
    CONFIG_DIGEST,
    RUN_ID,
    _adjudication_proposal,
    _decision,
    _write_state,
)


CANDIDATE_ID = "H-LIVE-PHASE"
PHASE_NAME = "severity_adjudication_shadow"
HANDLER_ARTIFACTS = {
    W.MANIFEST_NAME,
    W.WORK_PLAN_NAME,
    W.RECONCILIATION_NAME,
}
EXPECTED_PHASE_ARTIFACTS = HANDLER_ARTIFACTS | {
    "trust_evidence_authority.json",
    "trust_evidence_provider_receipt.json",
}
ALL_MODES = {"light", "core", "thorough"}


def _phase(pipeline: str):
    phases = L1_PHASES if pipeline == "l1" else SC_PHASES
    matches = [phase for phase in phases if phase.name == PHASE_NAME]
    assert len(matches) == 1, (
        f"{pipeline} must declare exactly one {PHASE_NAME} phase"
    )
    return matches[0]


def _handler():
    handler = getattr(D, "_run_severity_adjudication_shadow_phase", None)
    assert callable(handler), (
        "the driver needs one custom deterministic severity-adjudication "
        "handler; routing this phase through generic run_phase would make "
        "model prose/artifact presence the completion authority"
    )
    return handler


def _methodology_home(root: Path) -> Path:
    home = root / "plamen-home"
    files = {
        "rules/report-template.md": "# Smart-contract severity matrix\n",
        "rules/finding-output-format.md": "# Finding format\n",
        "rules/phase5-poc-execution.md": "# Verification evidence\n",
        "docs/l1-mode/severity-matrix.md": "# L1 severity matrix\n",
    }
    for relative, body in files.items():
        path = home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return home


def _config(
    tmp_path: Path,
    *,
    pipeline: str,
    mode: str = "core",
) -> dict[str, Any]:
    project = tmp_path / f"project-{pipeline}-{mode}"
    project.mkdir(parents=True, exist_ok=True)
    return {
        "project_root": str(project),
        "pipeline": pipeline,
        "mode": mode,
        "language": "rust" if pipeline == "l1" else "evm",
        # The fixture backend is intentionally accepted only by the existing
        # provider's test-only backend validator.  It still launches a real
        # child process and produces real provider arm/completion/publish
        # receipts; no caller-authored execution receipt is introduced.
        "cli_backend": "fixture-subprocess",
        "_run_id": RUN_ID,
        "_audit_snapshot": {
            "snapshot_digest": AUDIT_DIGEST,
            "components": {"audit_config": {"digest": CONFIG_DIGEST}},
        },
        "severity_adjudication_environment": {},
        "severity_adjudication_environment_allowlist": (),
        "severity_adjudication_timeout_s": 10.0,
        "_active_phase_names": [
            "crossbatch",
            PHASE_NAME,
            "report_index",
        ],
    }


def _proposal_script(
    shard: Mapping[str, Any],
    *,
    behavior: str = "success",
) -> str:
    payloads = {
        candidate_id: _adjudication_proposal(candidate_id)
        for candidate_id in shard["candidate_ids"]
    }
    encoded = json.dumps(payloads, ensure_ascii=False, sort_keys=True)
    output_names = json.dumps(shard["staged_outputs"], sort_keys=True)
    scope = json.dumps(shard["staging_output_scope"])
    prefix = (
        "import json, time; from pathlib import Path; "
        f"payloads=json.loads({encoded!r}); names=json.loads({output_names!r}); "
        f"scope=Path(json.loads({scope!r})); scope.mkdir(parents=True, exist_ok=True); "
    )
    if behavior == "success":
        return prefix + (
            "[(scope/names[c]).write_text(json.dumps(payloads[c], "
            "sort_keys=True)+'\\n', encoding='utf-8') for c in "
            "sorted(payloads)]"
        )
    if behavior == "nonzero":
        return prefix + "raise SystemExit(9)"
    if behavior == "timeout":
        return prefix + "time.sleep(2)"
    if behavior == "malformed":
        return prefix + (
            "[(scope/names[c]).write_text('{}\\n', encoding='utf-8') "
            "for c in sorted(payloads)]"
        )
    if behavior == "extra":
        return _proposal_script(shard, behavior="success") + (
            "; (scope/'unassigned.json').write_text('{}\\n', "
            "encoding='utf-8')"
        )
    raise AssertionError(f"unknown fake-worker behavior {behavior!r}")


def _install_fake_process_launch(
    monkeypatch: pytest.MonkeyPatch,
    *,
    behavior: str = "success",
) -> list[str]:
    """Install the production launch-spec seam, not an execution fake."""

    calls: list[str] = []

    def launch_spec(*_args: object, **kwargs: object) -> dict[str, Any]:
        shard = kwargs.get("shard")
        assert isinstance(shard, Mapping), (
            "launch-spec builder must receive the immutable planned shard"
        )
        calls.append(str(shard["shard_id"]))
        timeout = 0.05 if behavior == "timeout" else 10.0
        return {
            "argv": [sys.executable, "-c", _proposal_script(shard, behavior=behavior)],
            "environment": {},
            "environment_allowlist": (),
            "timeout_seconds": timeout,
        }

    monkeypatch.setattr(
        D,
        "_build_severity_adjudication_worker_launch_spec",
        launch_spec,
        raising=False,
    )
    return calls


def _run_live(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    pipeline: str,
    mode: str = "core",
    behavior: str = "success",
    decisions: list[dict[str, Any]] | None = None,
) -> tuple[Path, dict[str, Any], dict[str, Any], list[str], list[str]]:
    scratchpad = tmp_path / f"scratch-{pipeline}-{mode}"
    scratchpad.mkdir(parents=True)
    _write_state(
        scratchpad,
        [_decision(CANDIDATE_ID)] if decisions is None else decisions,
    )
    home = _methodology_home(tmp_path)
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    calls = _install_fake_process_launch(monkeypatch, behavior=behavior)
    config = _config(tmp_path, pipeline=pipeline, mode=mode)
    reconciliation, issues = _handler()(
        _phase(pipeline), config, scratchpad
    )
    assert isinstance(reconciliation, dict)
    assert isinstance(issues, list)
    return scratchpad, config, reconciliation, issues, calls


@pytest.mark.parametrize(
    ("pipeline", "phases"),
    (("sc", SC_PHASES), ("l1", L1_PHASES)),
)
def test_phase_graph_orders_live_adjudication_between_crossbatch_and_report_index(
    pipeline: str, phases,
) -> None:
    names = [phase.name for phase in phases]
    assert names.count(PHASE_NAME) == 1
    assert names.index("crossbatch") < names.index(PHASE_NAME) < names.index(
        "report_index"
    )
    phase = _phase(pipeline)
    assert phase.modes == ALL_MODES
    assert set(phase.expected_artifacts) == EXPECTED_PHASE_ARTIFACTS
    assert phase.critical is False, "adjudication debt must degrade, never halt"
    assert phase.model == "opus", "direction-neutral tiering is a reasoning role"

    # The declaration must survive mode filtering in every audit mode.  In
    # Light, crossbatch itself is skipped; declaration order is still fixed.
    for mode in sorted(ALL_MODES):
        active = [item.name for item in phases if mode in item.modes]
        assert PHASE_NAME in active
        assert active.index(PHASE_NAME) < active.index("report_index")


def test_driver_dispatches_one_custom_handler_and_never_generic_run_phase() -> None:
    _handler()
    source = inspect.getsource(D.main)
    anchor = 'if phase.name == "severity_adjudication_shadow"'
    assert source.count(anchor) == 1, (
        "main must have one unambiguous custom severity phase branch"
    )
    start = source.index(anchor)
    end = source.index("continue", start)
    branch = source[start:end]
    assert "_run_severity_adjudication_shadow_phase(" in branch
    assert "PhaseCommitController(" in branch
    assert '"COMPLETED_WITH_DEBT"' in branch
    assert '"CLEAN"' in branch
    assert "run_phase(" not in branch


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
@pytest.mark.parametrize("mode", tuple(sorted(ALL_MODES)))
def test_zero_candidate_phase_is_clean_and_never_launches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline: str,
    mode: str,
) -> None:
    scratchpad = tmp_path / f"scratch-zero-{pipeline}-{mode}"
    scratchpad.mkdir(parents=True)
    _write_state(scratchpad, [])
    home = _methodology_home(tmp_path)
    monkeypatch.setattr(D, "plamen_home", lambda: home)

    def forbidden_launch(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("zero-row severity phase attempted a worker launch")

    monkeypatch.setattr(
        D,
        "_build_severity_adjudication_worker_launch_spec",
        forbidden_launch,
        raising=False,
    )
    monkeypatch.setattr(W, "run_observed_worker", forbidden_launch)
    config = _config(tmp_path, pipeline=pipeline, mode=mode)

    reconciliation, issues = _handler()(
        _phase(pipeline), config, scratchpad
    )

    assert issues == []
    assert reconciliation["denominator_count"] == 0
    assert reconciliation["states"] == {}
    assert reconciliation["debt_ids"] == []
    assert reconciliation["all_terminal"] is True
    assert reconciliation["all_resolved"] is True
    plan = json.loads((scratchpad / W.WORK_PLAN_NAME).read_text(encoding="utf-8"))
    assert plan["launch_count"] == 0
    assert plan["zero_row_no_launch"] is True
    assert not (scratchpad / ".worker_execution_receipts").exists()


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_canonical_empty_verification_queue_bootstraps_empty_shadow_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline: str,
) -> None:
    """A legitimate zero denominator must not become runtime debt.

    The verifier empty-queue short circuit predates the typed severity ledger,
    so it has no per-candidate producer invocation from which to create that
    ledger.  This is the only missing-ledger state the live observer may
    synthesize, and it must remain a zero-row/no-worker transaction.
    """

    scratchpad = tmp_path / f"scratch-empty-queue-{pipeline}"
    scratchpad.mkdir(parents=True)
    (scratchpad / "verification_queue.md").write_text(
        "# Verification Queue\n\n"
        "| Finding ID | Severity | Status |\n"
        "|---|---|---|\n\n"
        "Total: 0 findings\n\n"
        "Reason: fixture-confirmed zero denominator.\n",
        encoding="utf-8",
    )
    home = _methodology_home(tmp_path)
    monkeypatch.setattr(D, "plamen_home", lambda: home)

    def forbidden_launch(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("canonical empty queue attempted a worker launch")

    monkeypatch.setattr(
        D,
        "_build_severity_adjudication_worker_launch_spec",
        forbidden_launch,
        raising=False,
    )
    config = _config(tmp_path, pipeline=pipeline)
    reconciliation, issues = _handler()(
        _phase(pipeline), config, scratchpad
    )

    assert issues == []
    assert reconciliation["denominator_count"] == 0
    assert reconciliation["all_resolved"] is True
    ledger = json.loads(
        (scratchpad / W.SOURCE_LEDGER_NAME).read_text(encoding="utf-8")
    )
    assert ledger["run_id"] == RUN_ID
    assert ledger["decision_count"] == 0
    assert ledger["decisions"] == []
    plan = json.loads((scratchpad / W.WORK_PLAN_NAME).read_text(encoding="utf-8"))
    assert plan["zero_row_no_launch"] is True


def test_missing_shadow_ledger_with_nonempty_queue_is_visible_debt_not_forged_empty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad = tmp_path / "scratch-missing-ledger-nonempty"
    scratchpad.mkdir(parents=True)
    (scratchpad / "verification_queue.md").write_text(
        "# Verification Queue\n\n"
        "| Finding ID | Severity | Status |\n"
        "|---|---|---|\n"
        "| H-NONEMPTY | High | ACTIVE |\n\n"
        "Total: 1 findings\n",
        encoding="utf-8",
    )
    home = _methodology_home(tmp_path)
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    config = _config(tmp_path, pipeline="sc")

    with pytest.raises(
        Exception,
        match="severity ledger|unreadable|No such file|missing adjudication artifact",
    ):
        _handler()(_phase("sc"), config, scratchpad)

    assert not (scratchpad / W.SOURCE_LEDGER_NAME).exists(), (
        "a nonempty verification denominator must never be converted into an "
        "authoritative empty severity ledger"
    )


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_live_phase_runs_real_provider_publish_bind_reconcile_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline: str,
) -> None:
    scratchpad, _config_value, reconciliation, issues, calls = _run_live(
        tmp_path, monkeypatch, pipeline=pipeline
    )

    assert issues == []
    assert reconciliation["states"] == {CANDIDATE_ID: "COMPLETED"}
    assert reconciliation["completed_ids"] == [CANDIDATE_ID]
    assert reconciliation["debt_ids"] == []
    assert reconciliation["all_terminal"] is True
    assert reconciliation["all_resolved"] is True
    assert len(calls) == 1
    assert HANDLER_ARTIFACTS <= {
        path.name for path in scratchpad.iterdir() if path.is_file()
    }
    assert (
        scratchpad
        / f"verify_{CANDIDATE_ID}.severity_adjudication_proposal.json"
    ).is_file()
    assert (
        scratchpad / f"verify_{CANDIDATE_ID}.severity_adjudication_receipt.json"
    ).is_file()
    decision = json.loads(
        (
            scratchpad / f"verify_{CANDIDATE_ID}.severity_decision.json"
        ).read_text(encoding="utf-8")
    )
    assert decision["status"] == "RESOLVED"

    evidence_root = scratchpad / ".worker_execution_receipts" / calls[0]
    assert len(list(evidence_root.glob("arm_*.json"))) == 1
    assert len(list(evidence_root.glob("completion_*.json"))) == 1
    assert len(
        [
            path
            for path in evidence_root.glob("publish_*.json")
            if not path.name.startswith("publish_arm_")
        ]
    ) == 1

    manifest = json.loads(
        (scratchpad / W.MANIFEST_NAME).read_text(encoding="utf-8")
    )
    methodology_names = {
        str(row["logical_name"]) for row in manifest["methodology_entries"]
    }
    if pipeline == "sc":
        assert "report-template" in methodology_names
        assert "l1-severity-matrix" not in methodology_names
    else:
        assert "l1-severity-matrix" in methodology_names
        assert "report-template" not in methodology_names


@pytest.mark.parametrize("behavior", ("nonzero", "timeout", "malformed", "extra"))
def test_worker_failure_modes_finish_with_visible_debt_not_false_clean_or_halt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    behavior: str,
) -> None:
    _scratchpad, _config_value, reconciliation, issues, calls = _run_live(
        tmp_path,
        monkeypatch,
        pipeline="sc",
        behavior=behavior,
    )

    assert len(calls) == 1
    assert issues, f"{behavior} worker failure was silently treated as clean"
    assert reconciliation["states"][CANDIDATE_ID] != "COMPLETED"
    assert reconciliation["all_resolved"] is False
    assert any(
        token in " ".join(map(str, issues)).lower()
        for token in (
            "worker",
            "provider",
            "timeout",
            "output",
            "pending",
            "unresolved",
        )
    )


def test_exact_resume_replays_provider_authority_without_child_relaunch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, config, first, first_issues, first_calls = _run_live(
        tmp_path, monkeypatch, pipeline="sc"
    )
    assert first_issues == [] and len(first_calls) == 1
    before = {
        path.relative_to(scratchpad).as_posix(): path.read_bytes()
        for path in scratchpad.rglob("*")
        if path.is_file()
    }

    def forbidden_relaunch(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("exact severity phase resume relaunched a child")

    monkeypatch.setattr(W, "run_observed_worker", forbidden_relaunch)
    monkeypatch.setattr(X, "run_observed_worker", forbidden_relaunch)
    resumed, resumed_issues = _handler()(
        _phase("sc"), config, scratchpad
    )
    after = {
        path.relative_to(scratchpad).as_posix(): path.read_bytes()
        for path in scratchpad.rglob("*")
        if path.is_file()
    }

    assert resumed_issues == []
    assert resumed == first
    assert after == before


def _checkpoint_from_live_result(
    *,
    scratchpad: Path,
    config: dict[str, Any],
    issues: list[str],
) -> Checkpoint:
    phase = _phase(str(config["pipeline"]))
    checkpoint = Checkpoint(run_id=RUN_ID)
    controller = D.PhaseCommitController(
        checkpoint, scratchpad, config["project_root"], config
    )
    if issues:
        failures = tuple(
            GateFailure(
                gate_id=f"{PHASE_NAME}.runtime.{ordinal}",
                gate_class="EVIDENCE_INTEGRITY",
                message=message,
                affected_identities=(CANDIDATE_ID,),
                fallback_policy="UNPROVEN_ONLY",
                allowed_fallback=(
                    "Keep the upstream severity and expose adjudication debt."
                ),
            )
            for ordinal, message in enumerate(issues, start=1)
        )
        controller.commit(phase, "COMPLETED_WITH_DEBT", failures)
    else:
        controller.commit(phase, "CLEAN")
    return Checkpoint.load(scratchpad)


def test_phase_checkpoint_is_clean_only_after_full_provider_bound_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, config, reconciliation, issues, _calls = _run_live(
        tmp_path, monkeypatch, pipeline="sc"
    )
    assert reconciliation["all_resolved"] is True and issues == []

    loaded = _checkpoint_from_live_result(
        scratchpad=scratchpad, config=config, issues=issues
    )
    commit = loaded.phase_commits[PHASE_NAME]
    assert commit.state == "CLEAN"
    assert PHASE_NAME in loaded.completed
    assert PHASE_NAME not in loaded.degraded
    assert not (scratchpad / f"{PHASE_NAME}.degraded").exists()


def test_phase_checkpoint_persists_completed_with_debt_and_resume_visibility(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, config, reconciliation, issues, _calls = _run_live(
        tmp_path,
        monkeypatch,
        pipeline="l1",
        behavior="malformed",
    )
    assert reconciliation["all_resolved"] is False and issues

    loaded = _checkpoint_from_live_result(
        scratchpad=scratchpad, config=config, issues=issues
    )
    commit = loaded.phase_commits[PHASE_NAME]
    assert commit.state == "COMPLETED_WITH_DEBT"
    assert commit.unresolved_failures
    assert PHASE_NAME in loaded.completed
    assert PHASE_NAME in loaded.degraded
    assert (scratchpad / f"{PHASE_NAME}.degraded").is_file()
    debt_projection = (scratchpad / "phase_completion_debt.md").read_text(
        encoding="utf-8"
    )
    assert PHASE_NAME in debt_projection
    assert CANDIDATE_ID in debt_projection
