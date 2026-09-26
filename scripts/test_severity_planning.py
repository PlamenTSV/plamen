"""Draft component tests for immutable severity planning publication.

These tests reuse the genuine snapshot/methodology/source-empty component
fixture.  Its typed queue producer is intentionally not described as full
T0--T9 ancestry, and these tests make no MODEL execution claim.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

import audit_snapshot as snapshot_api
from artifact_ledger import ArtifactLedgerError, LEDGER_NAME, read_artifact_ledger
import severity_adjudication_work as work
import severity_planning as planning
from severity_planning import run_severity_planning
import test_severity_planning_inputs as capture_test
from worker_execution_receipts import environment_allowlist_sha256


@pytest.fixture(autouse=True)
def _deterministic_host_tool_observation(monkeypatch: pytest.MonkeyPatch) -> None:
    # Same bounded host-observation seam as the capture component fixture; the
    # live snapshot builder and exact snapshot equality remain in production.
    monkeypatch.setattr(
        snapshot_api,
        "_runtime_tool_entries",
        lambda **_kwargs: [("@runtime/test-host", b"stable-toolchain")],
    )


def _planning_args(project: Path) -> dict[str, object]:
    return {
        "backend": "codex",
        "transport": "posix-v2-compat",
        "effective_model": "gpt-5.6-sol",
        "working_directory": str(project),
        "source_root": str(project),
        "tool_policy": [
            "read-bound-inputs-and-source",
            "write-assigned-staging-only",
        ],
        "environment_allowlist_digest": environment_allowlist_sha256(()),
        "adjudicator_identity": "independent-severity-adjudicator",
        "invocation_prefix": "severity-planning-component",
        "timeout_seconds_per_worker": 30,
        "max_items_per_worker": 4,
        "max_weight_per_worker": 8,
        "max_context_bytes_per_worker": 65_536,
    }


def _fixture(tmp_path: Path, *, pipeline: str = "sc"):
    project, root, implementation, config, _snapshot = capture_test._fixture(
        tmp_path, pipeline=pipeline,
    )
    return project, root, implementation, config, _planning_args(project)


def _run(
    fixture, *, planning_args=None, fault_hook=None,
    expected_source_ledger_digest=None,
):
    project, root, implementation, config, default_args = fixture
    return run_severity_planning(
        scratchpad=root,
        project_root=project,
        implementation_root=implementation,
        config=config,
        planning_args=default_args if planning_args is None else planning_args,
        fault_hook=fault_hook,
        expected_source_ledger_digest=expected_source_ledger_digest,
    )


def _unit(root: Path):
    matches = [
        row
        for key, row in read_artifact_ledger(root)["work_units"].items()
        if key.endswith("/severity_adjudication_shadow/planning")
    ]
    assert len(matches) == 1
    return matches[0]


@pytest.mark.parametrize("committed", (False, True))
def test_selected_source_mismatch_rejects_before_planning_change(
    tmp_path: Path, committed: bool,
) -> None:
    fixture = _fixture(tmp_path)
    root = fixture[1]
    if committed:
        _run(fixture)
    before = {
        name: (root / name).read_bytes()
        for name in (work.MANIFEST_NAME, work.WORK_PLAN_NAME)
        if (root / name).exists()
    }
    with pytest.raises(ArtifactLedgerError, match="differs from selected source"):
        _run(fixture, expected_source_ledger_digest="0" * 64)
    assert {
        name: (root / name).read_bytes()
        for name in (work.MANIFEST_NAME, work.WORK_PLAN_NAME)
        if (root / name).exists()
    } == before
    if not committed:
        assert not any(
            key.endswith("/severity_adjudication_shadow/planning")
            for key in read_artifact_ledger(root)["work_units"]
        )


@pytest.mark.parametrize(
    "invalid_digest",
    ("", " " * 64, "A" * 64, "0" * 63, "g" * 64, 1, True),
)
def test_expected_source_digest_format_rejects_before_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invalid_digest,
) -> None:
    fixture = _fixture(tmp_path)
    root = fixture[1]

    def forbidden_capture(**_kwargs):
        raise AssertionError("invalid expectation reached source capture")

    monkeypatch.setattr(
        planning, "capture_severity_planning_inputs", forbidden_capture,
    )
    with pytest.raises(ArtifactLedgerError, match="lowercase SHA-256"):
        _run(
            fixture,
            expected_source_ledger_digest=invalid_digest,
        )
    assert not any(
        key.endswith("/severity_adjudication_shadow/planning_inputs")
        or key.endswith("/severity_adjudication_shadow/planning")
        for key in read_artifact_ledger(root)["work_units"]
    )


@pytest.mark.parametrize(
    "invalid_digest",
    (None, "", " " * 64, "A" * 64, "0" * 63, "g" * 64, 1, True),
)
def test_live_prepare_refuses_malformed_selector_before_planning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invalid_digest,
) -> None:
    import severity_shadow_transaction as live

    project, root, implementation, config, args = _fixture(tmp_path)
    planner_calls = []
    monkeypatch.setattr(
        live,
        "select_severity_initial_source",
        lambda **_kwargs: {"source_ledger_sha256": invalid_digest},
    )

    def forbidden_planner(**kwargs):
        planner_calls.append(kwargs)
        raise AssertionError("malformed selector reached planning")

    monkeypatch.setattr(live, "run_severity_planning", forbidden_planner)
    with pytest.raises(ArtifactLedgerError, match="lowercase SHA-256"):
        live.prepare_live_severity_transaction(
            scratchpad=root,
            project_root=project,
            implementation_root=implementation,
            config=config,
            planning_args=args,
        )
    assert planner_calls == []
    assert not any(
        key.endswith("/severity_adjudication_shadow/planning_inputs")
        or key.endswith("/severity_adjudication_shadow/planning")
        for key in read_artifact_ledger(root)["work_units"]
    )


def test_live_prepare_uses_one_authenticated_capture_per_invocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import severity_shadow_transaction as live

    project, root, implementation, config, args = _fixture(tmp_path)
    real_capture = planning.capture_severity_planning_inputs
    captures = []

    def observed_capture(**kwargs):
        result = real_capture(**kwargs)
        captures.append(result)
        return result

    monkeypatch.setattr(planning, "capture_severity_planning_inputs", observed_capture)
    # Guard the old outer call as well, without replacing any live validation.
    monkeypatch.setattr(live, "capture_severity_planning_inputs", observed_capture,
                        raising=False)
    first = live.prepare_live_severity_transaction(
        scratchpad=root, project_root=project, implementation_root=implementation,
        config=config, planning_args=args,
    )
    assert len(captures) == 1
    assert captures[0]["source_ledger_digest"] == first[2]["source_ledger_sha256"]
    assert first[0]["denominator_count"] == 0
    second = live.prepare_live_severity_transaction(
        scratchpad=root, project_root=project, implementation_root=implementation,
        config=config, planning_args=args,
    )
    assert len(captures) == 2
    assert second == first


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_zero_planning_commits_and_replays_without_rederive_or_rewrite(
    tmp_path: Path, pipeline: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path, pipeline=pipeline)
    _project, root, _implementation, _config, _args = fixture
    plan = _run(fixture)
    assert plan["denominator_count"] == 0
    assert plan["launch_count"] == 0
    assert work.validate_prepared_work(root) == []

    unit = _unit(root)
    assert unit["model_invoked"] is False
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert unit["semantic_status"] == "ACTIVE"
    assert set(unit["artifacts"]) == {
        f"scratchpad:{work.MANIFEST_NAME}",
        f"scratchpad:{work.WORK_PLAN_NAME}",
    }
    frozen = {
        name: ((root / name).read_bytes(), (root / name).stat().st_mtime_ns)
        for name in (work.MANIFEST_NAME, work.WORK_PLAN_NAME)
    }
    ledger = (root / LEDGER_NAME).read_bytes()

    def forbidden(*_args, **_kwargs):
        raise AssertionError("committed planning replay must not derive")

    monkeypatch.setattr("severity_planning.derive_adjudication_work", forbidden)
    assert _run(fixture) == plan
    assert {
        name: ((root / name).read_bytes(), (root / name).stat().st_mtime_ns)
        for name in (work.MANIFEST_NAME, work.WORK_PLAN_NAME)
    } == frozen
    assert (root / LEDGER_NAME).read_bytes() == ledger


@pytest.mark.parametrize(
    "fault_point",
    (
        "after_arm", "after_output_1", "after_output_2",
        "before_commit", "after_commit",
    ),
)
def test_fault_prefix_recovers_only_exact_sealed_outputs(
    tmp_path: Path, fault_point: str,
) -> None:
    fixture = _fixture(tmp_path)
    _project, root, _implementation, _config, _args = fixture
    fired = False

    def crash(point: str) -> None:
        nonlocal fired
        if point == fault_point and not fired:
            fired = True
            raise RuntimeError(f"fault:{point}")

    with pytest.raises(RuntimeError, match=f"fault:{fault_point}"):
        _run(fixture, fault_hook=crash)
    assert fired is True
    first = root / work.MANIFEST_NAME
    prior = (
        (first.read_bytes(), first.stat().st_mtime_ns)
        if first.exists() else None
    )
    plan = _run(fixture)
    assert plan["denominator_count"] == 0
    assert _unit(root)["execution_state"] == "OUTPUT_COMMITTED"
    if prior is not None:
        assert (first.read_bytes(), first.stat().st_mtime_ns) == prior


def test_committed_replay_rejects_changed_planning_arguments(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    _run(fixture)
    changed = dict(fixture[-1])
    changed["effective_model"] = "different-model"
    ledger = (fixture[1] / LEDGER_NAME).read_bytes()
    with pytest.raises(ArtifactLedgerError, match="identity changed"):
        _run(fixture, planning_args=changed)
    assert (fixture[1] / LEDGER_NAME).read_bytes() == ledger


@pytest.mark.parametrize("field", ("backend", "source_root", "working_directory"))
def test_planning_arguments_cannot_escape_contract_or_admitted_roots(
    tmp_path: Path, field: str,
) -> None:
    fixture = _fixture(tmp_path)
    changed = dict(fixture[-1])
    changed[field] = "claude" if field == "backend" else str(tmp_path)
    with pytest.raises(ArtifactLedgerError, match="backend|source root|working"):
        _run(fixture, planning_args=changed)
    assert not any(
        key.endswith("/severity_adjudication_shadow/planning")
        for key in read_artifact_ledger(fixture[1])["work_units"]
    )


@pytest.mark.parametrize(
    "mutation", ("skeptic", "implementation_mode", "captured_input"),
)
def test_barrier_rejects_ambient_input_or_root_identity_mutation(
    tmp_path: Path, mutation: str,
) -> None:
    fixture = _fixture(tmp_path)
    _project, root, implementation, _config, _args = fixture
    original_mode = implementation.stat().st_mode & 0o777

    def mutate(point: str) -> None:
        if point != "after_output_1":
            return
        if mutation == "skeptic":
            (root / "skeptic_challenges.json").write_bytes(b"{}\n")
        elif mutation == "implementation_mode":
            os.chmod(implementation, 0o711)
        else:
            target = root / capture_test.COMMON_NAMES[0]
            os.chmod(target, 0o600)
            target.write_bytes(b"{}")

    try:
        with pytest.raises(ArtifactLedgerError, match="skeptic|identity|inputs"):
            _run(fixture, fault_hook=mutate)
    finally:
        if mutation == "implementation_mode":
            os.chmod(implementation, original_mode)
    assert _unit(root)["execution_state"] == "INPUTS_BOUND_PREEXECUTION"


def test_after_commit_mutation_cannot_return_stale_success(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    _project, root, _implementation, _config, _args = fixture

    def mutate(point: str) -> None:
        if point == "after_commit":
            (root / "skeptic_challenges.json").write_bytes(b"{}\n")

    with pytest.raises(ArtifactLedgerError, match="skeptic"):
        _run(fixture, fault_hook=mutate)
    assert _unit(root)["execution_state"] == "OUTPUT_COMMITTED"


@pytest.mark.parametrize("kind", ("file", "symlink"))
def test_fresh_foreign_output_collision_is_rejected(
    tmp_path: Path, kind: str,
) -> None:
    fixture = _fixture(tmp_path)
    root = fixture[1]
    target = root / work.MANIFEST_NAME
    if kind == "file":
        target.write_bytes(b"foreign\n")
    else:
        target.symlink_to("missing-target")
    with pytest.raises(ArtifactLedgerError, match="foreign outputs"):
        _run(fixture)


@pytest.mark.parametrize("damage", ("missing", "tampered"))
def test_committed_damage_is_rejected_without_repair(
    tmp_path: Path, damage: str,
) -> None:
    fixture = _fixture(tmp_path)
    _run(fixture)
    root = fixture[1]
    target = root / work.WORK_PLAN_NAME
    if damage == "missing":
        target.unlink()
    else:
        os.chmod(target, 0o600)
        target.write_bytes(b"{}\n")
    with pytest.raises(ArtifactLedgerError):
        _run(fixture)
    if damage == "missing":
        assert not target.exists()
    else:
        assert target.read_bytes() == b"{}\n"


def test_armed_partial_different_bytes_are_never_repaired(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    root = fixture[1]

    def crash(point: str) -> None:
        if point == "after_output_1":
            raise RuntimeError("partial")

    with pytest.raises(RuntimeError, match="partial"):
        _run(fixture, fault_hook=crash)
    target = root / work.MANIFEST_NAME
    os.chmod(target, 0o600)
    target.write_bytes(b"{}\n")
    with pytest.raises(ArtifactLedgerError, match="partial output differs"):
        _run(fixture)
    assert target.read_bytes() == b"{}\n"


def test_input_mutated_after_pure_derivation_fails_before_arm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    _project, root, _implementation, _config, _args = fixture
    target = root / capture_test.COMMON_NAMES[0]
    actual_derive = planning.derive_adjudication_work

    def derive_then_mutate(*args, **kwargs):
        result = actual_derive(*args, **kwargs)
        os.chmod(target, 0o600)
        target.write_bytes(b"{}")
        return result

    monkeypatch.setattr(planning, "derive_adjudication_work", derive_then_mutate)
    with pytest.raises(ArtifactLedgerError, match="inputs|producer"):
        _run(fixture)
    assert not any(
        key.endswith("/severity_adjudication_shadow/planning")
        for key in read_artifact_ledger(root)["work_units"]
    )


@pytest.mark.parametrize(
    "name",
    (
        "severity_adjudication_context.stale.json",
        "Severity_Adjudication_Prompt.STALE.MD",
        "severity_adjudication_launch_intent.stale.json",
        "SEVERITY_ADJUDICATION_TOOL_POLICY.STALE.JSON",
    ),
)
def test_stale_planning_namespace_refuses_fresh_arm(
    tmp_path: Path, name: str,
) -> None:
    fixture = _fixture(tmp_path)
    root = fixture[1]
    stale = root / name
    stale.write_bytes(b"foreign\n")
    with pytest.raises(ArtifactLedgerError, match="stale namespace"):
        _run(fixture)
    assert stale.read_bytes() == b"foreign\n"
    assert not any(
        key.endswith("/severity_adjudication_shadow/planning")
        for key in read_artifact_ledger(root)["work_units"]
    )


def test_stale_namespace_appearing_after_first_output_prevents_commit(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    root = fixture[1]
    stale = root / "Severity_Adjudication_Context.RACE.JSON"

    def inject(point: str) -> None:
        if point == "after_output_1":
            stale.write_bytes(b"foreign\n")

    with pytest.raises(ArtifactLedgerError, match="stale namespace"):
        _run(fixture, fault_hook=inject)
    assert stale.read_bytes() == b"foreign\n"
    assert (root / work.MANIFEST_NAME).is_file()
    assert _unit(root)["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
