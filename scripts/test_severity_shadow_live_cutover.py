"""Live severity cutover transaction integration.

The nonempty fixture uses the genuine same-run T0--T9 verifier/source chain and
a deterministic POSIX compatibility child.  It proves driver reachability,
ownership, recovery, and debt classification only; the child is not semantic
MODEL/provider evidence.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping

import pytest

import audit_snapshot as snapshot_api
from artifact_ledger import ArtifactLedgerError, read_artifact_ledger
import plamen_driver as driver
import severity_adjudication_work as severity_work
import severity_compat_runtime
from severity_bind_transaction import validate_severity_bind_resume_state
import severity_shadow_transaction as live_transaction
import test_posix_v2_compat_severity_execution as compat_fixture
import test_severity_bind_transaction as bind_fixture
import test_severity_initial_source_integration as same_run_fixture
import test_severity_planning_inputs as planning_fixture
from test_nonempty_report_handoff_extension import assert_nonempty_report_handoff
from test_verification_report_tail_same_run_integration import (
    _patch_compat_codex_lookup,
)


class _InjectedCutoverCrash(RuntimeError):
    pass


def _unit_by_suffix(
    root: Path, suffix: str,
) -> tuple[str, Mapping[str, Any]]:
    matches = [
        (key, row)
        for key, row in read_artifact_ledger(root)["work_units"].items()
        if key.endswith(suffix)
    ]
    assert len(matches) == 1, (suffix, matches)
    return matches[0]


def _phase(pipeline: str):
    phases = driver.SC_PHASES if pipeline == "sc" else driver.L1_PHASES
    return next(item for item in phases if item.name == "severity_adjudication_shadow")


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_live_handler_zero_uses_typed_source_planning_and_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline: str,
) -> None:
    """The zero component seed is typed but does not claim full T0--T9 ancestry."""

    monkeypatch.setattr(
        snapshot_api,
        "_runtime_tool_entries",
        lambda **_kwargs: [("@runtime/test-host", b"stable-toolchain")],
    )
    project, root, implementation, config, _snapshot = planning_fixture._fixture(
        tmp_path, pipeline=pipeline,
    )
    monkeypatch.setattr(driver, "plamen_home", lambda: implementation)
    reconciliation, issues = driver._run_severity_adjudication_shadow_phase(
        _phase(pipeline), config, root,
    )
    assert issues == []
    assert reconciliation["denominator_ids"] == []
    assert reconciliation["states"] == {}
    assert reconciliation["all_terminal"] is True
    assert reconciliation["all_resolved"] is True

    source_key, source_row = _unit_by_suffix(
        root, "/severity_adjudication_shadow/source_empty",
    )
    planning_key, planning_row = _unit_by_suffix(
        root, "/severity_adjudication_shadow/planning",
    )
    final_key, final_row = _unit_by_suffix(
        root, "/severity_adjudication_shadow/reconcile_empty",
    )
    assert all(
        row["execution_state"] == "OUTPUT_COMMITTED"
        and row["model_invoked"] is False
        for row in (source_row, planning_row, final_row)
    )
    assert source_key != planning_key != final_key
    binding = read_artifact_ledger(root)["artifact_bindings"][
        "scratchpad:severity_adjudication_work_reconciliation.json"
    ]
    assert binding["owner_key"] == final_key

    output = root / "severity_adjudication_work_reconciliation.json"
    ledger = root / "_artifact_state.json"
    frozen = (
        output.read_bytes(), output.stat().st_ino, output.stat().st_mtime_ns,
        ledger.read_bytes(), ledger.stat().st_ino, ledger.stat().st_mtime_ns,
    )
    replay, replay_issues = driver._run_severity_adjudication_shadow_phase(
        _phase(pipeline), config, root,
    )
    assert replay == reconciliation
    assert replay_issues == []
    assert (
        output.read_bytes(), output.stat().st_ino, output.stat().st_mtime_ns,
        ledger.read_bytes(), ledger.stat().st_ino, ledger.stat().st_mtime_ns,
    ) == frozen


@pytest.mark.posix_only
def test_live_handler_pending_then_armed_output3_resume_and_unresolved_final(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One genuine source chain covers pending, launch, bind resume, and final."""

    if os.name != "posix":
        pytest.skip("real compatibility child requires POSIX")
    tmp_path = tmp_path / "é-audit"
    tmp_path.mkdir()
    exercised = False

    def run_live_cutover(
        root: Path,
        project: Path,
        config: dict[str, Any],
        candidate_ids: tuple[str, ...],
        fixture_monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        nonlocal exercised
        # The inherited verifier helper dispatches only the three dynamic
        # tier coordinators.  Mirror the production sc_verify_aggregate R10
        # boundary here, before the live severity handler or any mechanical
        # successor can change the verifier denominator.  This intentionally
        # leaves the upstream initial-source fixture's missing-R10 scope
        # unchanged.
        r10_phase = next(
            item for item in driver.SC_PHASES
            if item.name == "sc_verify_aggregate"
        )
        r10_source_names = (
            "verification_runtime_roster.json",
            "verification_queue.md",
            "verification_queue.work_items.json",
            "verification_queue.work_plan.json",
            *(
                name
                for candidate in candidate_ids
                for name in (
                    f"verify_{candidate}.md",
                    f"verify_{candidate}.identity.json",
                    f"verify_{candidate}.receipt.json",
                    f"verify_{candidate}.severity_proposal.json",
                )
            ),
        )
        assert not any(
            (root / f"verify_{candidate}.mechanical_successor.receipt.json")
            .exists()
            for candidate in candidate_ids
        )
        r10_sources_before = {
            name: (root / name).read_bytes() for name in r10_source_names
        }
        r10_compute, r10_issues = driver._write_and_record_r10_phase_io(
            scratchpad=root,
            config=config,
            phase=r10_phase,
        )
        assert r10_issues == [], {
            "r10_issues": r10_issues,
            "r10_compute": r10_compute,
            "external_dependency_binding": read_artifact_ledger(root)[
                "artifact_bindings"
            ].get("scratchpad:external_dependency_research.md"),
            "external_dependency_research": (
                (root / "external_dependency_research.md").read_text(
                    encoding="utf-8", errors="strict",
                )
                if (root / "external_dependency_research.md").is_file()
                else None
            ),
        }
        assert r10_compute.get("outcome") in {"FIRED", "CLEAN_ZERO"}, (
            r10_compute
        )
        assert {
            name: (root / name).read_bytes() for name in r10_source_names
        } == r10_sources_before
        assert not any(
            (root / f"verify_{candidate}.mechanical_successor.receipt.json")
            .exists()
            for candidate in candidate_ids
        )
        phase = _phase("sc")
        counter = root.parent.parent / "severity-live-cutover-launches"
        proposals = {
            f"verify_{candidate}.severity_adjudication_proposal.json": (
                bind_fixture._unresolved_proposal()
            )
            for candidate in candidate_ids
        }
        binary = compat_fixture._fake_codex(
            root.parent.parent / "severity-live-cutover-codex",
            proposals=proposals,
            counter=counter,
        )
        real_worker = severity_compat_runtime.run_posix_compat_severity_worker
        real_bind = live_transaction.run_next_severity_bind_transaction

        with fixture_monkeypatch.context() as live_patch:
            _patch_compat_codex_lookup(live_patch, binary)

            def unavailable_worker(*_args: Any, **_kwargs: Any) -> Any:
                raise RuntimeError("deterministic pending worker debt")

            live_patch.setattr(
                severity_compat_runtime,
                "run_posix_compat_severity_worker",
                unavailable_worker,
            )
            pending, pending_issues = driver._run_severity_adjudication_shadow_phase(
                phase, config, root,
            )
            assert set(pending["states"].values()) == {"PENDING"}
            assert any("compatibility worker debt" in item for item in pending_issues)
            assert not (root / "severity_adjudication_work_reconciliation.json").exists()
            assert not counter.exists()
            pending_checkpoint = driver.Checkpoint.load(root)
            projection_issues = driver._refresh_severity_report_shadow_projection(
                pending_checkpoint, root, config, stage="PRE_ASSEMBLE",
            )
            assert any(
                "terminal severity reconciliation is invalid" in item
                for item in projection_issues
            )
            assert not any(
                key.endswith("/severity_adjudication_shadow/report_projection")
                for key in read_artifact_ledger(root)["work_units"]
            )

            live_patch.setattr(
                severity_compat_runtime,
                "run_posix_compat_severity_worker",
                real_worker,
            )
            fault_fired = False

            def bind_with_one_output3_crash(**kwargs: Any) -> str | None:
                nonlocal fault_fired
                if fault_fired:
                    return real_bind(**kwargs)

                def crash(point: str) -> None:
                    nonlocal fault_fired
                    if point == "after_output_3":
                        fault_fired = True
                        raise _InjectedCutoverCrash(point)

                return real_bind(**kwargs, fault_hook=crash)

            live_patch.setattr(
                live_transaction,
                "run_next_severity_bind_transaction",
                bind_with_one_output3_crash,
            )
            with pytest.raises(_InjectedCutoverCrash, match="after_output_3"):
                driver._run_severity_adjudication_shadow_phase(
                    phase, config, root,
                )
            assert fault_fired is True
            plan = json.loads(
                (root / severity_work.WORK_PLAN_NAME).read_text(encoding="utf-8")
            )
            assert set(plan["denominator_ids"]) == set(candidate_ids)
            launch_count = counter.read_text(encoding="ascii")
            assert int(launch_count) == len(plan["shards"])
            first = plan["denominator_ids"][0]
            _bind_key, bind_row = _unit_by_suffix(
                root,
                "/severity_adjudication_shadow/"
                f"bind.0001.{first.casefold()}",
            )
            assert bind_row["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
            assert bind_row["artifacts"] == {}
            # The selector's shared resume view is read-only at the exact
            # third-output projection-lag window of bind ordinal 1, and a
            # same-filesystem request carrying another run cannot adopt it.
            resume_before = (
                (root / "_artifact_state.json").read_bytes(),
                (root / "_artifact_state.json").stat().st_ino,
                (root / "_artifact_state.json").stat().st_mtime_ns,
                counter.read_text(encoding="ascii"),
            )
            resume = validate_severity_bind_resume_state(
                root, project, config,
            )
            assert resume["completed_candidate_ids"] == []
            assert resume["armed_candidate_id"] == first
            assert resume["candidate_ids"] == plan["denominator_ids"]
            wrong_run = {
                **config,
                "_run_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            }
            with pytest.raises(ArtifactLedgerError, match="run|planning"):
                validate_severity_bind_resume_state(
                    root, project, wrong_run,
                )
            assert (
                (root / "_artifact_state.json").read_bytes(),
                (root / "_artifact_state.json").stat().st_ino,
                (root / "_artifact_state.json").stat().st_mtime_ns,
                counter.read_text(encoding="ascii"),
            ) == resume_before
            # All postimages are visible, so semantic state looks terminal;
            # the PhaseIO bind itself is deliberately still uncommitted.
            partial = severity_work.build_adjudication_work_reconciliation(root)
            assert partial["states"][first] == "COMPLETED_UNRESOLVED"
            assert not (root / "severity_adjudication_work_reconciliation.json").exists()

            completed, completed_issues = (
                driver._run_severity_adjudication_shadow_phase(
                    phase, config, root,
                )
            )
            assert counter.read_text(encoding="ascii") == launch_count
            assert completed["all_terminal"] is True
            assert completed["all_resolved"] is False
            assert set(completed["states"].values()) == {
                "COMPLETED_UNRESOLVED"
            }
            assert completed_issues
            assert all(
                "unresolved severity adjudication state" in item
                for item in completed_issues
            )
            final_key, final_row = _unit_by_suffix(
                root, "/severity_adjudication_shadow/reconcile_final",
            )
            assert final_row["execution_state"] == "OUTPUT_COMMITTED"
            assert final_row["model_invoked"] is False
            assert read_artifact_ledger(root)["artifact_bindings"][
                "scratchpad:severity_adjudication_work_reconciliation.json"
            ]["owner_key"] == final_key

            output = root / "severity_adjudication_work_reconciliation.json"
            ledger = root / "_artifact_state.json"
            frozen = (
                output.read_bytes(), output.stat().st_ino,
                output.stat().st_mtime_ns, ledger.read_bytes(),
            )
            replay, replay_issues = driver._run_severity_adjudication_shadow_phase(
                phase, config, root,
            )
            assert replay == completed
            assert replay_issues == completed_issues
            assert counter.read_text(encoding="ascii") == launch_count
            assert (
                output.read_bytes(), output.stat().st_ino,
                output.stat().st_mtime_ns, ledger.read_bytes(),
            ) == frozen
            assert_nonempty_report_handoff(
                root=root,
                project=project,
                config=config,
                severity_issues=completed_issues,
                monkeypatch=live_patch,
            )
        exercised = True

    monkeypatch.setattr(
        same_run_fixture,
        "_assert_nonempty_planning_recovery",
        run_live_cutover,
    )
    same_run_fixture.test_same_run_low_verifier_source_publication_recovers_without_relaunch(
        tmp_path, monkeypatch,
    )
    assert exercised is True


def test_driver_cutover_source_contains_no_legacy_raw_publication() -> None:
    """Keep the bounded handler wiring structural while runtime tests prove it."""

    source = Path(driver.__file__).read_text(encoding="utf-8")
    start = source.index("def _run_severity_adjudication_shadow_phase(")
    end = source.index("\ndef _refresh_severity_report_shadow_projection(", start)
    handler = source[start:end]
    assert "prepare_live_severity_transaction(" in handler
    assert "finalize_live_severity_transaction(" in handler
    assert "build_adjudication_work_reconciliation(root)" in handler
    for forbidden in (
        "prepare_adjudication_work(",
        "reconcile_adjudication_work(",
        "recover_receipt_pending_decision_commit(",
        "bind_shadow_adjudication_for_candidate(",
    ):
        assert forbidden not in handler
