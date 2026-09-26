"""Genuine straight-line severity-to-report integration entrypoint.

This test deliberately reuses the existing same-run T0--T9 verifier/source
fixture and its live POSIX compatibility session.  Inside that session it
publishes the real R10 aggregate boundary, invokes the production severity
handler once, and continues through the existing nonempty report handoff and
report-floor authority checks.

The deterministic children exercise the real process transport and registered
MODEL/DRIVER transactions, but they are controlled fixtures rather than proof
of provider judgment or native-backend parity.  The inherited setup still
exercises source/planning recovery; the straight-line claim begins at the live
severity handler.  The resulting unresolved severity state is intentional and
must remain visible as EXIT_DEGRADED.  This is a scoped same-process report-tail
integration, not a fresh-OS restart, global publication, or full 75-phase E2E
claim.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from artifact_ledger import read_artifact_ledger
import plamen_driver as driver
import severity_adjudication_work as severity_work
import test_posix_v2_compat_severity_execution as compat_fixture
import test_severity_bind_transaction as bind_fixture
import test_severity_initial_source_integration as same_run_fixture
from test_nonempty_report_handoff_extension import assert_nonempty_report_handoff
from test_verification_report_tail_same_run_integration import (
    _patch_compat_codex_lookup,
)


def _publish_genuine_r10_boundary(
    *,
    root: Path,
    config: dict[str, Any],
    candidate_ids: tuple[str, ...],
) -> None:
    """Publish R10 before mechanical successors can change its denominator."""

    phase = next(
        item for item in driver.SC_PHASES
        if item.name == "sc_verify_aggregate"
    )
    source_names = (
        "verification_runtime_roster.json",
        "verification_queue.md",
        "verification_queue.work_items.json",
        "verification_queue.work_plan.json",
        *(
            name
            for candidate_id in candidate_ids
            for name in (
                f"verify_{candidate_id}.md",
                f"verify_{candidate_id}.identity.json",
                f"verify_{candidate_id}.receipt.json",
                f"verify_{candidate_id}.severity_proposal.json",
            )
        ),
    )
    successor_receipts = tuple(
        root / f"verify_{candidate_id}.mechanical_successor.receipt.json"
        for candidate_id in candidate_ids
    )
    assert all(not path.exists() and not path.is_symlink()
               for path in successor_receipts)
    source_bytes = {
        name: (root / name).read_bytes() for name in source_names
    }

    compute, issues = driver._write_and_record_r10_phase_io(
        scratchpad=root,
        config=config,
        phase=phase,
    )
    assert issues == [], {"issues": issues, "compute": compute}
    assert compute.get("outcome") in {"FIRED", "CLEAN_ZERO"}, compute
    assert {
        name: (root / name).read_bytes() for name in source_names
    } == source_bytes
    assert all(not path.exists() and not path.is_symlink()
               for path in successor_receipts)


def _severity_phase():
    return next(
        item for item in driver.SC_PHASES
        if item.name == "severity_adjudication_shadow"
    )


@pytest.mark.posix_only
def test_genuine_straight_line_nonempty_report_tail_feedback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reach the genuine report tail after one production severity call."""

    if os.name != "posix":
        pytest.skip("real compatibility children require POSIX")
    tmp_path = tmp_path / "é-straight-report"
    tmp_path.mkdir()
    exercised = False

    def run_straight_line(
        root: Path,
        project: Path,
        config: dict[str, Any],
        candidate_ids: tuple[str, ...],
        fixture_monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        nonlocal exercised
        _publish_genuine_r10_boundary(
            root=root,
            config=config,
            candidate_ids=candidate_ids,
        )

        counter = root.parent.parent / "severity-straight-line-launches"
        binary = compat_fixture._fake_codex(
            root.parent.parent / "severity-straight-line-codex",
            proposals={
                f"verify_{candidate_id}.severity_adjudication_proposal.json": (
                    bind_fixture._unresolved_proposal()
                )
                for candidate_id in candidate_ids
            },
            counter=counter,
        )

        with fixture_monkeypatch.context() as live_patch:
            _patch_compat_codex_lookup(live_patch, binary)
            reconciliation, issues = (
                driver._run_severity_adjudication_shadow_phase(
                    _severity_phase(), config, root,
                )
            )
            assert reconciliation["denominator_ids"] == list(candidate_ids)
            assert reconciliation["all_terminal"] is True
            assert reconciliation["all_resolved"] is False
            assert set(reconciliation["states"].values()) == {
                "COMPLETED_UNRESOLVED"
            }
            assert issues
            assert all(
                "unresolved severity adjudication state" in issue
                for issue in issues
            )

            plan = json.loads(
                (root / severity_work.WORK_PLAN_NAME).read_text(
                    encoding="utf-8", errors="strict",
                )
            )
            assert set(plan["denominator_ids"]) == set(candidate_ids)
            assert int(counter.read_text(encoding="ascii")) == len(
                plan["shards"]
            )
            launch_count = counter.read_text(encoding="ascii")

            ledger = read_artifact_ledger(root)
            final_units = [
                (key, row)
                for key, row in ledger["work_units"].items()
                if key.endswith(
                    "/severity_adjudication_shadow/reconcile_final"
                )
            ]
            assert len(final_units) == 1
            final_key, final_row = final_units[0]
            assert final_row["execution_state"] == "OUTPUT_COMMITTED"
            assert final_row["model_invoked"] is False
            assert ledger["artifact_bindings"][
                "scratchpad:severity_adjudication_work_reconciliation.json"
            ]["owner_key"] == final_key

            assert_nonempty_report_handoff(
                root=root,
                project=project,
                config=config,
                severity_issues=issues,
                monkeypatch=live_patch,
            )

            # Report phases use their own genuine deterministic children; the
            # severity worker must not be relaunched while report authority is
            # captured, projected, assembled, and floored.
            assert counter.read_text(encoding="ascii") == launch_count
            checkpoint = driver.Checkpoint.load(root)
            assert _severity_phase().name in checkpoint.degraded
            assert {
                "report_dedup_agent",
                "report_dedup",
                "report_disposition",
                "report_floor",
            } <= set(checkpoint.completed)
            assert driver._pipeline_terminal_exit_code(checkpoint) == (
                driver.EXIT_DEGRADED
            )
            report = project / "AUDIT_REPORT.md"
            assert report.is_file() and not report.is_symlink()
            report_binding = read_artifact_ledger(root)["artifact_bindings"][
                "project:AUDIT_REPORT.md"
            ]
            assert report_binding["owner_key"].endswith(
                "/report_floor/assurance_projection"
            )
            assert report_binding["status"] == "ACTIVE"
        exercised = True

    # The inherited setup owns genuine queue/verifier/source/planning
    # provenance and calls this hook while its issued compatibility session is
    # still live.  Replacing only the test hook does not patch a production
    # authority, worker, validator, or receipt.
    monkeypatch.setattr(
        same_run_fixture,
        "_assert_nonempty_planning_recovery",
        run_straight_line,
    )
    same_run_fixture.test_same_run_low_verifier_source_publication_recovers_without_relaunch(
        tmp_path, monkeypatch,
    )
    assert exercised is True
