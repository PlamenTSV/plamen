"""P0-N: a resume-detected inventory dropout remains verification work.

The old resume repair wrote late inventory identities to the evidence-excluded
ledger and therefore allowed queue cardinality to pass without any verifier
ever seeing them.  These fixtures require active routing, a bounded recovery
assignment, aggregate/descendant invalidation, and an idempotent second resume.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import plamen_driver as D
import plamen_mechanical as M
import plamen_parsers as P
import plamen_types as T
from test_verify_queue_no_resume_revert import (
    _COVERED,
    _UNROUTED,
    _write_inventory,
    _write_partial_canonical_queue,
    _write_verify_files,
)


def _setup_completed_l1_run(sp: Path) -> tuple[list[T.Phase], T.Checkpoint]:
    _write_inventory(sp)
    _write_partial_canonical_queue(sp)
    _write_verify_files(sp)
    phases = [phase for phase in T.L1_PHASES if "thorough" in phase.modes]
    verify_queue_idx = next(
        idx for idx, phase in enumerate(phases) if phase.name == "verify_queue"
    )
    completed = [phase.name for phase in phases[verify_queue_idx:]]
    return phases, T.Checkpoint(completed=completed, degraded=[])


def _config(sp: Path) -> dict[str, str]:
    return {
        "scratchpad": str(sp),
        "project_root": str(sp),
        "pipeline": "l1",
        "language": "rust",
        "mode": "thorough",
        "cli_backend": "claude",
    }


def _write_recovered_verify_files(sp: Path, missing: list[tuple[str, dict]]) -> None:
    for fid, row in missing:
        (sp / f"verify_{fid}.md").write_text(
            f"# Verification: {fid}\n\n"
            f"**Finding ID**: {fid}\n"
            f"**Verdict**: CONFIRMED\n"
            f"**Severity**: {row.get('severity', 'Medium')}\n"
            "**Evidence Tag**: [CODE-TRACE]\n\n"
            "Recovery verifier examined the late active candidate and wrote "
            "this substantive, bounded verification artifact.\n",
            encoding="utf-8",
        )


def test_backfill_forbids_excluded_or_producer_disposition(tmp_path: Path):
    _write_inventory(tmp_path)
    _write_partial_canonical_queue(tmp_path)
    with pytest.raises(ValueError, match="active verification work"):
        M.backfill_unrouted_inventory_into_queue(tmp_path, route="excluded")


def test_exact_legacy_resume_deferred_rows_migrate_back_to_active(tmp_path: Path):
    _write_inventory(tmp_path)
    _write_partial_canonical_queue(tmp_path)
    with (tmp_path / "findings_inventory.md").open("a", encoding="utf-8") as fh:
        fh.write(
            "## Finding [INV-017]: Legitimately mode-excluded low item\n"
            "**Severity**: Low\n"
            "**Verdict**: CONFIRMED\n"
            "**Bug Class**: Example Class\n"
            "**Location**: src/contract.sol:L99\n"
            "**Preferred Tag**: [CODE-TRACE]\n"
            "**Description**: A real low-severity candidate.\n\n"
        )
    inventory_rows = {
        row["finding id"]: row
        for row in M._queue_rows_from_inventory_with_exclusions(tmp_path)[0]
    }
    legacy_rows = []
    for fid in _UNROUTED:
        row = dict(inventory_rows[fid])
        row["exclusion reason"] = (
            "Deferred on resume: queue-generation dropout acknowledged here "
            "to preserve verify_queue<->inventory parity without re-running "
            "the already-completed verify stage"
        )
        legacy_rows.append(row)
    legitimate = dict(inventory_rows["INV-017"])
    legitimate["exclusion reason"] = "Excluded by Core mode: Low/Info policy"
    legacy_rows.append(legitimate)
    P._write_queue_excluded_manifest(
        tmp_path / "verification_queue_evidence_excluded.md", legacy_rows
    )

    # The old parity contract considers them acknowledged, but P0-N must not.
    assert M.backfill_unrouted_inventory_into_queue(tmp_path) == _UNROUTED
    active = {row["finding id"] for row in P.parse_verification_queue_rows(tmp_path)}
    assert active == set(_COVERED + _UNROUTED)
    retained = P._read_queue_json_sidecar(
        tmp_path / "verification_queue_evidence_excluded.md"
    )
    assert [row["finding id"] for row in retained] == ["INV-017"]
    assert "Core mode" in retained[0]["exclusion reason"]
    assert M.backfill_unrouted_inventory_into_queue(tmp_path) == []


def test_legacy_migration_crash_window_still_returns_active_recovery_work(
    tmp_path: Path,
):
    _write_inventory(tmp_path)
    _write_partial_canonical_queue(tmp_path)
    active_rows, _excluded = M._queue_rows_from_inventory_with_exclusions(tmp_path)
    by_id = {row["finding id"]: row for row in active_rows}
    # Simulate a crash after active queue publication but before stale legacy
    # exclusion cleanup: the same late IDs exist in both projections.
    P._write_queue_subset_manifest(
        tmp_path / "verification_queue.md",
        [by_id[fid] for fid in _COVERED + _UNROUTED],
    )
    old_excluded = []
    for fid in _UNROUTED:
        row = dict(by_id[fid])
        row["exclusion reason"] = (
            "Deferred on resume: queue-generation dropout acknowledged here"
        )
        old_excluded.append(row)
    P._write_queue_excluded_manifest(
        tmp_path / "verification_queue_evidence_excluded.md", old_excluded
    )

    assert M.backfill_unrouted_inventory_into_queue(tmp_path) == _UNROUTED
    assert P._read_queue_json_sidecar(
        tmp_path / "verification_queue_evidence_excluded.md"
    ) == []
    assert M.backfill_unrouted_inventory_into_queue(tmp_path) == []


def test_late_row_gets_recovery_assignment_and_only_descendants_rewind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    phases, checkpoint = _setup_completed_l1_run(tmp_path)
    recovery_calls: list[list[str]] = []

    def recover(_config: dict, missing: list[tuple[str, dict]]) -> list[str]:
        recovery_calls.append([fid for fid, _row in missing])
        _write_recovered_verify_files(tmp_path, missing)
        return []

    monkeypatch.setattr(D, "_run_verify_recovery_shard", recover)
    result = D._repair_late_verification_backfill(
        tmp_path, _config(tmp_path), checkpoint, phases, "thorough"
    )

    assert result["backfilled"] == _UNROUTED
    assert recovery_calls == [_UNROUTED]
    active = {row["finding id"] for row in P.parse_verification_queue_rows(tmp_path)}
    assert active == set(_COVERED + _UNROUTED)

    recovery_rows = P._read_queue_json_sidecar(
        tmp_path / "verification_queue_recovery.md"
    )
    assert [row["finding id"] for row in recovery_rows] == _UNROUTED
    assert all(
        row["expected output file"] == f"verify_{row['finding id']}.md"
        for row in recovery_rows
    )
    assert all((tmp_path / f"verify_{fid}.md").is_file() for fid in _UNROUTED)

    verify_shards = {
        phase.name
        for phase in phases
        if phase.name in T.L1_VERIFY_PHASE_NAMES
    }
    assert verify_shards <= set(checkpoint.completed)
    assert "verify_queue" in checkpoint.completed
    assert "verify_aggregate" not in checkpoint.completed
    assert "report_index" not in checkpoint.completed
    assert "verify_aggregate" in checkpoint.degraded
    assert "report_index" in checkpoint.degraded
    assert set(result["rewound"]) >= {"verify_aggregate", "report_index"}


def test_targeted_rewind_preserves_unrelated_shard_phase_commit_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    phases, checkpoint = _setup_completed_l1_run(tmp_path)
    run_id = "123e4567-e89b-42d3-a456-426614174000"
    checkpoint.run_id = run_id
    shard_name = next(
        phase.name for phase in phases if phase.name in T.L1_VERIFY_PHASE_NAMES
    )
    shard_commit = T.PhaseCommit(
        phase_name=shard_name, state="CLEAN", run_id=run_id
    )
    aggregate_commit = T.PhaseCommit(
        phase_name="verify_aggregate", state="CLEAN", run_id=run_id
    )
    report_commit = T.PhaseCommit(
        phase_name="report_index", state="CLEAN", run_id=run_id
    )
    checkpoint.phase_commits = {
        shard_name: shard_commit,
        "verify_aggregate": aggregate_commit,
        "report_index": report_commit,
    }

    def recover(_config: dict, missing: list[tuple[str, dict]]) -> list[str]:
        _write_recovered_verify_files(tmp_path, missing)
        return []

    monkeypatch.setattr(D, "_run_verify_recovery_shard", recover)
    D._repair_late_verification_backfill(
        tmp_path, _config(tmp_path), checkpoint, phases, "thorough"
    )

    assert checkpoint.phase_commits[shard_name] is shard_commit
    assert "verify_aggregate" not in checkpoint.phase_commits
    assert "report_index" not in checkpoint.phase_commits
    assert shard_name in checkpoint.completed


def test_exact_resume_does_not_repeat_recovery_or_rewind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    phases, checkpoint = _setup_completed_l1_run(tmp_path)
    calls = 0

    def recover(_config: dict, missing: list[tuple[str, dict]]) -> list[str]:
        nonlocal calls
        calls += 1
        _write_recovered_verify_files(tmp_path, missing)
        return []

    monkeypatch.setattr(D, "_run_verify_recovery_shard", recover)
    first = D._repair_late_verification_backfill(
        tmp_path, _config(tmp_path), checkpoint, phases, "thorough"
    )
    state_after_first = (
        list(checkpoint.completed),
        list(checkpoint.degraded),
        (tmp_path / "verification_queue.md").read_bytes(),
    )
    second = D._repair_late_verification_backfill(
        tmp_path, _config(tmp_path), checkpoint, phases, "thorough"
    )

    assert first["backfilled"] == _UNROUTED
    assert second == {
        "backfilled": [], "recovered": [], "unresolved": [], "rewound": []
    }
    assert calls == 1
    assert state_after_first == (
        list(checkpoint.completed),
        list(checkpoint.degraded),
        (tmp_path / "verification_queue.md").read_bytes(),
    )


def test_recovery_unavailable_keeps_upstream_severity_as_unverified_debt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    phases, checkpoint = _setup_completed_l1_run(tmp_path)
    monkeypatch.setattr(
        D,
        "_run_verify_recovery_shard",
        # Worker self-report claims success but writes nothing. Disk artifacts,
        # not return prose/status, must keep every identity unresolved.
        lambda _config, _missing: [],
    )

    result = D._repair_late_verification_backfill(
        tmp_path, _config(tmp_path), checkpoint, phases, "thorough"
    )

    assert result["unresolved"] == _UNROUTED
    queue = {
        row["finding id"]: row for row in P.parse_verification_queue_rows(tmp_path)
    }
    for fid in _UNROUTED:
        text = (tmp_path / f"verify_{fid}.md").read_text(encoding="utf-8")
        assert "**Verdict**: UNVERIFIED" in text
        assert f"**Severity**: {queue[fid]['severity']}" in text
        assert "Human reviewer" in text
        tier = {
            "Critical": "C", "High": "H", "Medium": "M", "Low": "L"
        }[queue[fid]["severity"]]
        delivered = M._synth_report_section_from_verify(
            tmp_path, f"{tier}-99", fid, queue[fid], True
        )
        assert f"**Severity**: {queue[fid]['severity']}" in delivered
        assert "**Verdict**: UNVERIFIED" in delivered
        assert "UNRESOLVED - needs human review" in delivered
    assert (tmp_path / "verify_aggregate.degraded").is_file()
    assert not (tmp_path / "verify_recovery.degraded").exists()
    assert "verify_aggregate" not in checkpoint.completed
    assert "verify_aggregate" in checkpoint.degraded


def test_recovery_manifest_failure_degrades_to_unverified_without_worker_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    phases, checkpoint = _setup_completed_l1_run(tmp_path)
    monkeypatch.setattr(
        D,
        "_write_queue_subset_manifest",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk fault")),
    )
    monkeypatch.setattr(
        D,
        "_run_verify_recovery_shard",
        lambda *_args, **_kwargs: pytest.fail(
            "worker must not launch without a durable assignment manifest"
        ),
    )

    result = D._repair_late_verification_backfill(
        tmp_path, _config(tmp_path), checkpoint, phases, "thorough"
    )

    assert result["unresolved"] == _UNROUTED
    assert all(
        "**Verdict**: UNVERIFIED" in (
            tmp_path / f"verify_{fid}.md"
        ).read_text(encoding="utf-8")
        for fid in _UNROUTED
    )
    debt = (tmp_path / "verify_aggregate.degraded").read_text(encoding="utf-8")
    assert "LATE_VERIFICATION_MANIFEST_DEBT" in debt


def test_preexisting_unverified_stub_is_retried_not_counted_as_recovered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    phases, checkpoint = _setup_completed_l1_run(tmp_path)
    assert M.backfill_unrouted_inventory_into_queue(tmp_path) == _UNROUTED
    queue = {
        row["finding id"]: row for row in P.parse_verification_queue_rows(tmp_path)
    }
    old_excluded = []
    for fid in _UNROUTED:
        row = dict(queue[fid])
        row["exclusion reason"] = (
            "Deferred on resume: queue-generation dropout acknowledged here"
        )
        old_excluded.append(row)
        (tmp_path / f"verify_{fid}.md").write_text(
            f"# Verification: {fid}\n\n**Finding ID**: {fid}\n"
            f"**Severity**: {row['severity']}\n**Verdict**: UNVERIFIED\n"
            "**Evidence Tag**: [CODE-TRACE]\n\n"
            "## VERIFICATION NOT EXECUTED - HUMAN REVIEW REQUIRED\n\n"
            "This old fallback is substantive in size but is not a verifier "
            "decision and therefore must be retried.\n",
            encoding="utf-8",
        )
    P._write_queue_excluded_manifest(
        tmp_path / "verification_queue_evidence_excluded.md", old_excluded
    )
    calls: list[list[str]] = []

    def recover(_config: dict, missing: list[tuple[str, dict]]) -> list[str]:
        calls.append([fid for fid, _row in missing])
        _write_recovered_verify_files(tmp_path, missing)
        return []

    monkeypatch.setattr(D, "_run_verify_recovery_shard", recover)
    result = D._repair_late_verification_backfill(
        tmp_path, _config(tmp_path), checkpoint, phases, "thorough"
    )

    assert calls == [_UNROUTED]
    assert result["recovered"] == _UNROUTED
    assert result["unresolved"] == []


def test_before_any_shard_late_rows_join_normal_active_queue_without_rewind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _write_inventory(tmp_path)
    _write_partial_canonical_queue(tmp_path)
    phases = [phase for phase in T.L1_PHASES if "thorough" in phase.modes]
    checkpoint = T.Checkpoint(completed=["verify_queue"], degraded=[])
    monkeypatch.setattr(
        D,
        "_run_verify_recovery_shard",
        lambda *_args, **_kwargs: pytest.fail("recovery must wait for normal shards"),
    )

    result = D._repair_late_verification_backfill(
        tmp_path, _config(tmp_path), checkpoint, phases, "thorough"
    )

    assert result == {
        "backfilled": _UNROUTED,
        "recovered": [],
        "unresolved": [],
        "rewound": [],
    }
    assert "verify_queue" in checkpoint.completed
    assert checkpoint.degraded == []
    rows = P.parse_verification_queue_rows(tmp_path)
    assert {row["finding id"] for row in rows} == set(_COVERED + _UNROUTED)


@pytest.mark.parametrize(
    "verdict", ["CONFIRMED", "REFUTED", "CONTESTED", "UNRESOLVED"]
)
def test_recovery_dispositions_continue_through_ordinary_verify_gates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, verdict: str
):
    phases, checkpoint = _setup_completed_l1_run(tmp_path)

    def recover(_config: dict, missing: list[tuple[str, dict]]) -> list[str]:
        for fid, row in missing:
            (tmp_path / f"verify_{fid}.md").write_text(
                f"# Verification: {fid}\n\n**Finding ID**: {fid}\n"
                f"**Verdict**: {verdict}\n"
                f"**Severity**: {row['severity']}\n"
                "**Evidence Tag**: [CODE-TRACE]\n\n"
                "Independent recovery analysis produced a substantive ordinary "
                "verifier decision without any mechanical verdict override.\n",
                encoding="utf-8",
            )
        return []

    monkeypatch.setattr(D, "_run_verify_recovery_shard", recover)
    result = D._repair_late_verification_backfill(
        tmp_path, _config(tmp_path), checkpoint, phases, "thorough"
    )

    assert result["recovered"] == _UNROUTED
    assert result["unresolved"] == []
    assert D._validate_verify_files_for_queue(tmp_path) == []
    assert D._validate_verify_evidence_tags(tmp_path) == []
    for fid in _UNROUTED:
        assert f"**Verdict**: {verdict}" in (
            tmp_path / f"verify_{fid}.md"
        ).read_text(encoding="utf-8")


def test_sc_resume_targets_sc_aggregate_and_preserves_sc_shards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _write_inventory(tmp_path)
    _write_partial_canonical_queue(tmp_path)
    _write_verify_files(tmp_path)
    phases = [phase for phase in T.SC_PHASES if "thorough" in phase.modes]
    start = next(i for i, phase in enumerate(phases) if phase.name == "sc_verify_queue")
    checkpoint = T.Checkpoint(
        completed=[phase.name for phase in phases[start:]], degraded=[]
    )

    def recover(_config: dict, missing: list[tuple[str, dict]]) -> list[str]:
        _write_recovered_verify_files(tmp_path, missing)
        return []

    monkeypatch.setattr(D, "_run_verify_recovery_shard", recover)
    result = D._repair_late_verification_backfill(
        tmp_path,
        {
            **_config(tmp_path),
            "pipeline": "sc",
            "language": "evm",
        },
        checkpoint,
        phases,
        "thorough",
    )

    completed_shards = {
        phase.name for phase in phases if phase.name in T.SC_VERIFY_PHASE_NAMES
    }
    assert result["recovered"] == _UNROUTED
    assert completed_shards <= set(checkpoint.completed)
    assert "sc_verify_aggregate" not in checkpoint.completed
    assert "sc_verify_aggregate" in checkpoint.degraded
    assert "report_index" in checkpoint.degraded
