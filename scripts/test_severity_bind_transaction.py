"""Ordered severity-bind transaction integration.

This deliberately reuses the genuine same-run verifier/source/planning fixture
and the real POSIX compatibility worker transaction.  The compatibility child
returns a deterministic ``UNRESOLVED`` proposal, so this test proves transport,
ownership, durability, and successor history only.  It is not MODEL quality,
provider, Core acceptance, or final-report evidence.
"""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import shutil
from typing import Any, Mapping

import pytest

from artifact_ledger import ArtifactLedgerError, read_artifact_ledger
import plamen_driver as driver
import posix_v2_compat_runtime as compat
import severity_compat_runtime
from severity_bind_transaction import (
    FAULT_POINTS,
    run_next_severity_bind_transaction,
    validate_completed_severity_bind_prefix,
)
from severity_final_reconciliation import (
    FAULT_POINTS as FINAL_RECONCILIATION_FAULT_POINTS,
    run_final_severity_reconciliation,
)
from severity_decision_ledger import ADJUDICATION_PROPOSAL_SCHEMA
import test_posix_v2_compat_severity_execution as compat_fixture
import test_severity_initial_source_integration as same_run_fixture
from test_verification_report_tail_same_run_integration import (
    _patch_compat_codex_lookup,
    _same_run_verifier_binary,
)


class _InjectedBindCrash(RuntimeError):
    pass


def _unresolved_proposal() -> bytes:
    value = {
        "schema_version": ADJUDICATION_PROPOSAL_SCHEMA,
        "decision": "UNRESOLVED",
        "resolved_severity": None,
        "resolved_premise_ids": [],
        "evidence_ids": [],
        "proof_scope": None,
        "rationale": (
            "Deterministic compatibility transport fixture; no semantic "
            "severity conclusion is asserted."
        ),
        "resolved_axes": None,
        "constituent_resolutions": {},
    }
    return (
        json.dumps(
            value, ensure_ascii=True, allow_nan=False,
            sort_keys=True, separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


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


def _run_workers(
    *, root: Path, config: dict[str, Any], session: object,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[tuple[str, ...], dict[str, bytes]]:
    plan = json.loads(
        (root / "severity_adjudication_work_plan.json").read_text(
            encoding="utf-8"
        )
    )
    shards = plan["shards"]
    candidate_ids = tuple(plan["denominator_ids"])
    assert candidate_ids
    proposals = {
        output_name: _unresolved_proposal()
        for shard in shards
        for output_name in shard["expected_outputs"].values()
    }
    counter = root.parent.parent / "severity-bind-worker-launches"
    binary = compat_fixture._fake_codex(
        root.parent.parent / "severity-bind-codex",
        proposals=proposals,
        counter=counter,
    )
    with monkeypatch.context() as worker_patch:
        _patch_compat_codex_lookup(worker_patch, binary)
        for shard in shards:
            receipt = severity_compat_runtime.run_posix_compat_severity_worker(
                root,
                config=config,
                shard_id=str(shard["shard_id"]),
                session_authority=session,
            )
            assert receipt["completion_status"] == "COMPLETED"
    assert int(counter.read_text(encoding="ascii")) == len(shards)
    receipts = {
        path.name: path.read_bytes()
        for path in root.glob("severity_adjudication_worker_run.*.json")
    }
    assert len(receipts) == len(shards)
    return candidate_ids, receipts


@pytest.mark.posix_only
def test_provider_lookup_is_local_and_preserves_binary_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_which = shutil.which
    real_tools = compat.shutil
    binary = compat_fixture._fake_codex(
        tmp_path / "codex-outer", proposals={}, counter=tmp_path / "unused-counter",
    )
    nested = compat_fixture._fake_codex(
        tmp_path / "codex-inner", proposals={}, counter=tmp_path / "unused-inner",
    )
    with monkeypatch.context() as outer:
        _patch_compat_codex_lookup(outer, binary)
        assert shutil.which is real_which
        assert compat.shutil.copytree is real_tools.copytree
        for name in ("git", "forge", "solc", "definitely-missing-plamen-tool"):
            assert compat.shutil.which(name) == real_which(name)
            assert compat.shutil.which(name, path=str(tmp_path)) == real_which(
                name, path=str(tmp_path)
            )
        assert compat._resolve_codex_binary() == (
            binary.resolve(), "codex-cli severity-compat-fixture",
            hashlib.sha256(binary.read_bytes()).hexdigest(),
        )
        with monkeypatch.context() as inner:
            _patch_compat_codex_lookup(inner, nested)
            assert compat._resolve_codex_binary()[0] == nested.resolve()
            assert compat.shutil.which("git") == real_which("git")
            assert shutil.which is real_which
        assert compat._resolve_codex_binary()[0] == binary.resolve()
        binary.chmod(0o644)
        with pytest.raises(compat.PosixV2CompatRuntimeError, match="trusted executable"):
            compat._resolve_codex_binary()
    assert compat.shutil is real_tools
    assert shutil.which is real_which


@pytest.mark.posix_only
def test_verifier_fixture_executable_preserves_audit_source_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from audit_snapshot import _source_component

    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    (project / "Unit.sol").write_text(
        "pragma solidity ^0.8.20; contract Unit {}\n", encoding="utf-8",
    )
    config = {
        "project_root": str(project), "scratchpad": str(root),
        "pipeline": "sc", "language": "evm", "cli_backend": "codex",
    }
    before = _source_component(config)
    binary = compat_fixture._fake_codex(
        _same_run_verifier_binary(root), proposals={}, counter=tmp_path / "unused",
    )
    assert not binary.is_relative_to(project)
    _patch_compat_codex_lookup(monkeypatch, binary)
    assert compat._resolve_codex_binary()[0] == binary.resolve()
    assert _source_component(config) == before
    # A real new target input must still invalidate this exact source snapshot.
    (project / "new-input.md").write_text("new audit context\n", encoding="utf-8")
    assert _source_component(config) != before


@pytest.mark.posix_only
def test_ordered_bind_recovers_every_barrier_without_worker_relaunch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise exact staged bytes, three transitions, and grouped history."""

    if os.name != "posix":
        pytest.skip("real compatibility child requires POSIX")
    original_planning = same_run_fixture._assert_nonempty_planning_recovery
    exercised = False

    def planning_then_bind(
        root: Path,
        project: Path,
        config: dict[str, Any],
        candidate_ids: tuple[str, ...],
        fixture_monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        nonlocal exercised
        original_planning(
            root, project, config, candidate_ids, fixture_monkeypatch,
        )
        session = driver._POSIX_COMPAT_V2_SESSION_AUTHORITY
        assert session is not None
        planned, worker_receipts = _run_workers(
            root=root, config=config, session=session,
            monkeypatch=fixture_monkeypatch,
        )
        assert planned == candidate_ids
        launch_counter = root.parent.parent / "severity-bind-worker-launches"
        launch_count = launch_counter.read_text(encoding="ascii")
        worker_receipt_state = {
            name: (raw, (root / name).stat().st_mtime_ns)
            for name, raw in worker_receipts.items()
        }

        first = candidate_ids[0]
        decision = root / f"verify_{first}.severity_decision.json"
        aggregate = root / "severity_decision_ledger.shadow.json"
        receipt = root / f"verify_{first}.severity_adjudication_receipt.json"
        before_decision = decision.read_bytes()
        before_aggregate = aggregate.read_bytes()
        assert not receipt.exists()

        # The same armed candidate is resumed repeatedly. Each later injected
        # barrier observes the exact stored plan/CAS rather than rederiving
        # postimages over its already changed predecessor files.
        for point in FAULT_POINTS:
            def crash(observed: str, *, selected: str = point) -> None:
                if observed == selected:
                    raise _InjectedBindCrash(selected)

            with pytest.raises(_InjectedBindCrash, match=point):
                run_next_severity_bind_transaction(
                    scratchpad=root,
                    project_root=project,
                    config=config,
                    fault_hook=crash,
                )
            ledger = read_artifact_ledger(root)
            if point == "after_stage":
                assert not any(
                    key.endswith(
                        "/severity_adjudication_shadow/"
                        f"bind.0001.{first.casefold()}"
                    )
                    for key in ledger["work_units"]
                )
                assert not receipt.exists()
                assert decision.read_bytes() == before_decision
                assert aggregate.read_bytes() == before_aggregate
                row = None
            else:
                key, row = _unit_by_suffix(
                    root,
                    "/severity_adjudication_shadow/"
                    f"bind.0001.{first.casefold()}",
                )
                assert ledger["work_units"][key] == row
            if point == "after_stage":
                pass
            elif point == "after_arm":
                assert row["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
                assert row["artifacts"] == {}
                assert not receipt.exists()
            elif point == "after_output_1":
                assert row["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
                assert receipt.is_file()
                assert decision.read_bytes() == before_decision
                assert aggregate.read_bytes() == before_aggregate
            elif point == "after_output_2":
                assert decision.read_bytes() != before_decision
                assert aggregate.read_bytes() == before_aggregate
            elif point in {"after_output_3", "before_commit"}:
                assert decision.read_bytes() != before_decision
                assert aggregate.read_bytes() != before_aggregate
                assert row["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
                assert row["artifacts"] == {}
            else:
                assert point == "after_commit"
                assert row["execution_state"] == "OUTPUT_COMMITTED"
                assert set(row["artifacts"]) == {
                    f"scratchpad:{receipt.name}",
                    f"scratchpad:{decision.name}",
                    "scratchpad:severity_decision_ledger.shadow.json",
                }
            assert launch_counter.read_text(encoding="ascii") == launch_count
            assert {
                name: ((root / name).read_bytes(), (root / name).stat().st_mtime_ns)
                for name in worker_receipts
            } == worker_receipt_state

        # Candidate 2 forces historical replay of candidate 1; candidate 3
        # forces the two-hop canonical-ledger chain. No caller candidate can be
        # supplied, skipped, or reordered.
        assert run_next_severity_bind_transaction(
            scratchpad=root, project_root=project, config=config,
        ) == candidate_ids[1]
        assert run_next_severity_bind_transaction(
            scratchpad=root, project_root=project, config=config,
        ) == candidate_ids[2]
        frozen_ledger = (root / "_artifact_state.json").read_bytes()
        frozen_outputs = {
            path.name: (path.read_bytes(), path.stat().st_mtime_ns)
            for path in (
                aggregate,
                *(root / f"verify_{candidate}.severity_decision.json"
                  for candidate in candidate_ids),
                *(root / f"verify_{candidate}.severity_adjudication_receipt.json"
                  for candidate in candidate_ids),
            )
        }
        assert run_next_severity_bind_transaction(
            scratchpad=root, project_root=project, config=config,
        ) is None
        assert (root / "_artifact_state.json").read_bytes() == frozen_ledger
        assert {
            name: ((root / name).read_bytes(), (root / name).stat().st_mtime_ns)
            for name in frozen_outputs
        } == frozen_outputs
        assert launch_counter.read_text(encoding="ascii") == launch_count
        prefix = validate_completed_severity_bind_prefix(
            root, project, config,
        )
        assert prefix.candidate_ids == candidate_ids
        assert prefix.bind_authority_digests == tuple(
            _unit_by_suffix(
                root,
                "/severity_adjudication_shadow/"
                f"bind.{ordinal:04d}.{candidate.casefold()}",
            )[1]["preexecution_authority"]["authority_sha256"]
            for ordinal, candidate in enumerate(candidate_ids, 1)
        )
        assert {
            "severity_adjudication_work_manifest.json",
            "severity_adjudication_work_plan.json",
            "severity_decision_ledger.shadow.json",
            *(f"verify_{candidate}.severity_decision.json"
              for candidate in candidate_ids),
            *(f"verify_{candidate}.severity_adjudication_receipt.json"
              for candidate in candidate_ids),
        }.issubset(prefix.input_names)
        assert "_severity_adjudication_inputs/source_ledger.initial.json" in prefix.input_names
        assert dict(prefix.absence_records) == {"skeptic_challenges.json": "MISSING"}
        assert dict(prefix.read_set) == {
            name: (root / name).read_bytes() for name in prefix.input_names
        }
        with pytest.raises(TypeError):
            prefix.read_set["foreign"] = b"foreign"  # type: ignore[index]
        assert validate_completed_severity_bind_prefix(
            root, project, config,
        ) == prefix

        # A nonraising hook may expose a concurrent appearance after the input
        # arm. Reject before recording the expected absence as PRESENT, then
        # resume the same genuine input-bound transaction after it disappears.
        skeptic_path = root / "skeptic_challenges.json"

        def appear_after_input_arm(observed: str) -> None:
            if observed == "after_input_arm":
                skeptic_path.write_bytes(b"{}\n")

        try:
            with pytest.raises(ArtifactLedgerError, match="skeptic absence changed"):
                run_final_severity_reconciliation(
                    scratchpad=root, project_root=project, config=config,
                    fault_hook=appear_after_input_arm,
                )
            _key, armed_final = _unit_by_suffix(
                root, "/severity_adjudication_shadow/reconcile_final",
            )
            assert armed_final["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
            assert armed_final.get("explicit_absence_authority") is None
        finally:
            if skeptic_path.exists():
                skeptic_path.unlink()

        # Final reconciliation is a separate DRIVER transaction. Every crash
        # boundary resumes exact bytes and never relaunches a worker.
        for point in FINAL_RECONCILIATION_FAULT_POINTS:
            def final_crash(observed: str, *, selected: str = point) -> None:
                if observed == selected:
                    raise _InjectedBindCrash("final-" + selected)

            if point == "after_commit":
                # The commit is durable, but a nonraising hook must not turn a
                # now-invalid absence into stale success. Removing only this
                # unowned transient lets the following read-only replay prove
                # recovery without rewriting any owned output or authority.
                def appear_after_commit(observed: str) -> None:
                    if observed == "after_commit":
                        skeptic_path.write_bytes(b"{}\n")

                try:
                    with pytest.raises(ArtifactLedgerError, match="absence|skeptic"):
                        run_final_severity_reconciliation(
                            scratchpad=root, project_root=project, config=config,
                            fault_hook=appear_after_commit,
                        )
                finally:
                    if skeptic_path.exists():
                        skeptic_path.unlink()
            else:
                with pytest.raises(_InjectedBindCrash, match="final-" + point):
                    run_final_severity_reconciliation(
                        scratchpad=root, project_root=project, config=config,
                        fault_hook=final_crash,
                    )
            assert launch_counter.read_text(encoding="ascii") == launch_count
            assert validate_completed_severity_bind_prefix(root, project, config) == prefix
        reconciliation = root / "severity_adjudication_work_reconciliation.json"
        ledger_path = root / "_artifact_state.json"
        before_replay = (
            reconciliation.read_bytes(), reconciliation.stat().st_ino,
            reconciliation.stat().st_mtime_ns,
        )
        ledger_before_replay = (
            ledger_path.read_bytes(), ledger_path.stat().st_ino,
            ledger_path.stat().st_mtime_ns,
        )
        assert run_final_severity_reconciliation(
            scratchpad=root, project_root=project, config=config,
        ) is True
        assert (
            reconciliation.read_bytes(), reconciliation.stat().st_ino,
            reconciliation.stat().st_mtime_ns,
        ) == before_replay
        assert (
            ledger_path.read_bytes(), ledger_path.stat().st_ino,
            ledger_path.stat().st_mtime_ns,
        ) == ledger_before_replay
        payload = json.loads(reconciliation.read_text(encoding="utf-8"))
        assert payload["all_terminal"] is True
        assert payload["all_resolved"] is False
        assert set(payload["states"].values()) == {"COMPLETED_UNRESOLVED"}
        assert launch_counter.read_text(encoding="ascii") == launch_count

        # A previously absent semantic input cannot appear on committed replay.
        skeptic_path = root / "skeptic_challenges.json"
        assert not skeptic_path.exists()
        skeptic_path.write_bytes(b"{}\n")
        try:
            with pytest.raises(ArtifactLedgerError, match="skeptic"):
                run_final_severity_reconciliation(
                    scratchpad=root, project_root=project, config=config,
                )
            assert (
                ledger_path.read_bytes(), ledger_path.stat().st_ino,
                ledger_path.stat().st_mtime_ns,
            ) == ledger_before_replay
            assert (
                reconciliation.read_bytes(), reconciliation.stat().st_ino,
                reconciliation.stat().st_mtime_ns,
            ) == before_replay
        finally:
            skeptic_path.unlink()

        # A committed CREATE receipt has no successor. Changing its live bytes
        # must invalidate the historical prefix instead of being "repaired"
        # from the private recovery CAS.
        first_receipt = root / (
            f"verify_{candidate_ids[0]}.severity_adjudication_receipt.json"
        )
        first_receipt.chmod(0o600)
        first_receipt.write_bytes(b"{}\n")
        with pytest.raises(
            ArtifactLedgerError, match="historical replay failed",
        ):
            run_next_severity_bind_transaction(
                scratchpad=root, project_root=project, config=config,
            )
        with pytest.raises(
            ArtifactLedgerError, match="historical replay failed",
        ):
            validate_completed_severity_bind_prefix(root, project, config)
        assert launch_counter.read_text(encoding="ascii") == launch_count
        exercised = True

    monkeypatch.setattr(
        same_run_fixture,
        "_assert_nonempty_planning_recovery",
        planning_then_bind,
    )
    same_run_fixture.test_same_run_low_verifier_source_publication_recovers_without_relaunch(
        tmp_path, monkeypatch,
    )
    assert exercised is True


@pytest.mark.parametrize("completed_prefix", [False, True])
def test_public_runner_rejects_invalid_roots_before_planning(
    tmp_path: Path, completed_prefix: bool,
) -> None:
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    config = {
        "_run_id": "11111111-2222-4333-8444-555555555555",
        "pipeline": "sc", "mode": "core", "language": "evm",
        "cli_backend": "codex", "project_root": str(project),
        "scratchpad": str(tmp_path / "other"),
    }
    with pytest.raises(ArtifactLedgerError, match="root authority is invalid"):
        if completed_prefix:
            validate_completed_severity_bind_prefix(root, project, config)
        else:
            run_next_severity_bind_transaction(
                scratchpad=root, project_root=project, config=config,
            )
