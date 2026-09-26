"""Regression coverage for authority-safe phase progression."""
from __future__ import annotations

import uuid
import ast
import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest

import plamen_driver as D
from plamen_types import Checkpoint, Phase


def _phase(name: str = "rag_sweep", *, critical: bool = False) -> Phase:
    return Phase(
        name,
        [name],
        [f"{name}.md"],
        60,
        critical=critical,
    )


def _config(project: Path) -> dict[str, object]:
    return {
        "project_root": str(project),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
        "_run_id": str(uuid.uuid4()),
    }


def test_producer_authority_failures_are_not_schema_debt() -> None:
    examples = (
        "scratchpad:findings_inventory.md: semantic input binding is "
        "PRODUCER_AUTHORITY_MISMATCH",
        "chain/scaffold: output execution state is OUTPUT_QUARANTINED",
        "scratchpad:hypotheses.md: status=QUARANTINED",
        "chain/scaffold: active producer authority does not replay",
        "chain/scaffold: output commit authority receipt invalid",
    )

    for issue in examples:
        suffix, gate_class = D._registered_gate_identity(issue)
        assert suffix == "semantic_identity.producer_authority"
        assert gate_class == "SEMANTIC_IDENTITY"
        assert D._fallback_policy_for_gate_class(gate_class) == (
            "BLOCK_AS_AUTHORITY"
        )
        assert D._blocking_phase_authority_issues([issue]) == (issue,)


def test_typed_haltless_debt_does_not_become_terminal_policy() -> None:
    safe = (
        "selected-skill application parity failed for SKILL-7",
        "depth tail checklist artifact is missing",
        "independent adjudication remains unresolved",
    )

    assert D._blocking_phase_authority_issues(safe) == ()


@pytest.mark.parametrize("detail", (
    "source_decisions.unit: stored commit authority is invalid",
    "source_decisions.unit: stored output denominator differs",
    "source_decisions.unit: stored artifact byte counts are invalid",
    "source_decisions.unit: stored commit output denominator differs",
    "verify_H-A.severity_decision.json: registered source successor proof failed",
))
def test_historical_initial_source_failures_cannot_be_consumed_as_schema_debt(
    detail: str,
) -> None:
    from severity_initial_source import _source_authority_failures

    issues = _source_authority_failures((detail, detail))
    assert len(issues) == 1
    assert detail in issues[0]
    assert D._blocking_phase_authority_issues(issues) == issues
    assert D._registered_gate_identity(issues[0]) == (
        "semantic_identity.producer_authority", "SEMANTIC_IDENTITY",
    )
    assert _source_authority_failures(()) == ()


def test_initial_source_validator_exception_has_blocking_authority_class(
    tmp_path: Path,
) -> None:
    from severity_initial_source import validate_source_decisions

    issues = validate_source_decisions(
        scratchpad=tmp_path / "absent-source-root", project_root=tmp_path,
        config={}, phase_name="sc_verify_low_a", unit=None,
        model_contract=None, model_launch=None,
        control_contract=None, control_launch=None,
        allow_registered_successors=True,
    )
    assert issues
    assert D._blocking_phase_authority_issues(issues) == issues


def test_blocking_debt_arms_exact_phase_retry_without_touching_peer(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    blocked = _phase("rag_sweep", critical=True)
    peer = _phase("chain", critical=True)
    checkpoint = Checkpoint(run_id=str(uuid.uuid4()))
    config = _config(tmp_path)
    issue = (
        "scratchpad:findings_inventory.md: semantic input binding is "
        "PRODUCER_AUTHORITY_MISMATCH"
    )

    blocking = D._block_phase_progression_on_authority_debt(
        blocked,
        checkpoint,
        scratchpad,
        config,
        [issue],
    )

    assert blocking == (issue,)
    assert blocked.name not in checkpoint.completed
    assert peer.name not in checkpoint.phase_commits
    assert checkpoint.phase_commits[blocked.name].state == (
        "INCOMPLETE_WITH_DEBT"
    )
    failure = checkpoint.phase_commits[blocked.name].unresolved_failures[0]
    assert failure.gate_class == "SEMANTIC_IDENTITY"
    assert failure.fallback_policy == "BLOCK_AS_AUTHORITY"
    assert D._incomplete_retry_arm_path(scratchpad, blocked.name).is_file()


def test_registered_driver_transaction_never_mutates_after_input_rejection(
    monkeypatch,
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    config = _config(tmp_path)
    observed = {"actions": 0, "outputs": 0}
    issue = (
        "scratchpad:findings_inventory.md: semantic input binding is "
        "PRODUCER_AUTHORITY_MISMATCH"
    )
    monkeypatch.setattr(
        D,
        "_p1dm_contract_and_launch",
        lambda *args, **kwargs: (
            SimpleNamespace(key="registered/phase/work"),
            SimpleNamespace(),
        ),
    )
    monkeypatch.setattr(D, "record_work_unit_inputs", lambda *a, **k: None)
    monkeypatch.setattr(
        D, "validate_work_unit_inputs", lambda *a, **k: [issue]
    )
    monkeypatch.setattr(
        D,
        "record_work_unit_artifacts",
        lambda *a, **k: observed.__setitem__("outputs", 1),
    )

    issues = D._record_p1dm_driver_transaction(
        scratchpad,
        config,
        phase_name="chain",
        work_unit_id="scaffold",
        exact_inputs=("findings_inventory.md",),
        exact_outputs=("hypotheses.md",),
        action=lambda: observed.__setitem__("actions", 1),
        validate=lambda: (),
    )

    assert issues == [issue]
    assert observed == {"actions": 0, "outputs": 0}


def test_registered_driver_transaction_retains_typed_missing_input_fallback(
    monkeypatch,
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    config = _config(tmp_path)
    observed = {"actions": 0, "outputs": 0}
    issue = "optional precedent context is missing"
    monkeypatch.setattr(
        D,
        "_p1dm_contract_and_launch",
        lambda *args, **kwargs: (
            SimpleNamespace(key="registered/phase/work"),
            SimpleNamespace(),
        ),
    )
    monkeypatch.setattr(D, "record_work_unit_inputs", lambda *a, **k: None)
    monkeypatch.setattr(
        D, "validate_work_unit_inputs", lambda *a, **k: [issue]
    )
    monkeypatch.setattr(
        D,
        "record_work_unit_artifacts",
        lambda *a, **k: observed.__setitem__("outputs", 1),
    )
    monkeypatch.setattr(
        D, "validate_work_unit_artifacts", lambda *a, **k: []
    )

    issues = D._record_p1dm_driver_transaction(
        scratchpad,
        config,
        phase_name="rag_sweep",
        work_unit_id="precedent_facts",
        exact_inputs=("findings_inventory.md",),
        exact_outputs=("precedent_finding_facts.json",),
        action=lambda: observed.__setitem__("actions", 1),
        validate=lambda: (),
    )

    assert issues == [issue]
    assert observed == {"actions": 1, "outputs": 1}


def test_committed_driver_derivation_replays_without_minting_new_receipt(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Shared RAG facts are immutable products, not per-consumer actions."""

    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    config = _config(tmp_path)
    contract = SimpleNamespace(key="rag/precedent_facts", digest="c" * 64)
    launch = SimpleNamespace(digest="l" * 64)
    observed = {"action": 0, "bind": 0, "commit": 0, "domain": 0}
    monkeypatch.setattr(
        D,
        "_p1dm_contract_and_launch",
        lambda *args, **kwargs: (contract, launch),
    )
    monkeypatch.setattr(
        D,
        "read_artifact_ledger",
        lambda _root: {
            "work_units": {
                contract.key: {
                    "run_id": config["_run_id"],
                    "contract_digest": contract.digest,
                    "launch_digest": launch.digest,
                    "semantic_status": "ACTIVE",
                    "execution_state": "OUTPUT_COMMITTED",
                    "commit_receipt_sha256": "r" * 64,
                }
            }
        },
    )
    monkeypatch.setattr(
        D,
        "record_work_unit_inputs",
        lambda *a, **k: observed.__setitem__("bind", 1),
    )
    monkeypatch.setattr(D, "validate_work_unit_inputs", lambda *a, **k: [])
    monkeypatch.setattr(
        D,
        "record_work_unit_artifacts",
        lambda *a, **k: observed.__setitem__("commit", 1),
    )
    monkeypatch.setattr(D, "validate_work_unit_artifacts", lambda *a, **k: [])

    issues = D._record_p1dm_driver_transaction(
        scratchpad,
        config,
        phase_name="rag_sweep",
        work_unit_id="precedent_facts",
        exact_inputs=("findings_inventory.md",),
        exact_outputs=("precedent_finding_facts.json",),
        action=lambda: observed.__setitem__("action", 1),
        validate=lambda: (
            observed.__setitem__("domain", observed["domain"] + 1) or ()
        ),
    )

    assert issues == []
    assert observed == {"action": 0, "bind": 0, "commit": 0, "domain": 1}


def test_missing_soft_output_cannot_be_silently_completed(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    phase = _phase("exploration_skeptic")
    checkpoint = Checkpoint(run_id=str(uuid.uuid4()))
    config = _config(tmp_path)
    original = D._commit_incomplete_phase_attempt(
        phase,
        checkpoint,
        scratchpad,
        config,
        ["exploration_skeptic.md is missing"],
    )

    result = D._commit_phase_from_disk_debt(
        phase,
        checkpoint,
        scratchpad,
        config,
        [phase],
        clean_transients=True,
    )

    assert result == original
    assert checkpoint.phase_commits[phase.name].state == "INCOMPLETE_WITH_DEBT"
    assert phase.name not in checkpoint.completed


def _execute_severity_dispatch(phase, config, scratchpad, checkpoint):
    """Execute the actual main branch with real checkpoint machinery.

    Worker/content seams are fixture-controlled by callers. This proves the
    dispatch failure/retry policy, not the underlying artifact authority.
    """
    main = ast.parse(inspect.getsource(D.main))
    branches = [
        node for node in ast.walk(main)
        if isinstance(node, ast.If)
        and ast.unparse(node.test) == "phase.name == 'severity_adjudication_shadow'"
    ]
    assert len(branches) == 1
    module = ast.parse(
        "def dispatch(phase, config, scratchpad, checkpoint):\n"
        "    total_active = 1\n"
        "    for phase_idx in range(total_active):\n"
        "        pass\n"
        "    return 0\n"
    )
    module.body[0].body[1].body = [branches[0]]
    ast.fix_missing_locations(module)
    namespace = dict(vars(D))
    namespace["display"] = SimpleNamespace(print_phase_skipped=lambda *a: None)
    exec(compile(module, "<actual severity main dispatch>", "exec"), namespace)
    return namespace["dispatch"](phase, config, scratchpad, checkpoint)


@pytest.mark.parametrize("failure", ("runtime", "content", "authority"))
def test_severity_dispatch_failure_preserves_output_paths_and_exact_retry(
    tmp_path: Path, monkeypatch, failure: str,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    config = _config(tmp_path)
    checkpoint = Checkpoint(run_id=config["_run_id"])
    phase = _phase("severity_adjudication_shadow")
    names = (
        D.SEVERITY_ADJUDICATION_MANIFEST_NAME,
        D.SEVERITY_ADJUDICATION_WORK_PLAN_NAME,
        D.SEVERITY_ADJUDICATION_RECONCILIATION_NAME,
    )
    partial = root / names[1]
    partial.write_bytes(b'{"partial_transaction_fixture":true}\n')
    before = (partial.read_bytes(), partial.stat().st_mtime_ns)

    def failed(*args):
        if failure == "runtime":
            raise RuntimeError("injected severity interruption")
        return {"all_resolved": True}, (
            ["scratchpad:source.json: semantic input binding is "
             "PRODUCER_AUTHORITY_MISMATCH"] if failure == "authority" else []
        )

    monkeypatch.setattr(D, "_run_severity_adjudication_shadow_phase", failed)
    monkeypatch.setattr(D, "_reconcile_trust_evidence_provider_state", lambda *a: [])
    monkeypatch.setattr(D, "_run_bb_policy_terminal_boundary", lambda *a: ({}, []))
    monkeypatch.setattr(
        D, "gate_passes", lambda *a: (
            (False, ["severity required output missing"])
            if failure == "content" else (True, [])
        ),
    )
    assert _execute_severity_dispatch(phase, config, root, checkpoint) == D.EXIT_DEGRADED
    checkpoint = Checkpoint.load(root)
    previous = checkpoint.phase_commits[phase.name]
    assert previous.state == "INCOMPLETE_WITH_DEBT"
    assert phase.name not in checkpoint.completed
    assert previous.unresolved_failures
    assert D._incomplete_retry_arm_path(root, phase.name).is_file()
    assert (partial.read_bytes(), partial.stat().st_mtime_ns) == before
    assert not (root / names[0]).exists()
    assert not (root / names[2]).exists()

    # Only a fully successful revalidation can clear the exact prior failures.
    monkeypatch.setattr(
        D, "_run_severity_adjudication_shadow_phase",
        lambda *a: ({"all_resolved": True, "denominator_count": 0}, []),
    )
    monkeypatch.setattr(D, "gate_passes", lambda *a: (True, []))
    assert _execute_severity_dispatch(phase, config, root, checkpoint) == 0
    completed = Checkpoint.load(root).phase_commits[phase.name]
    assert completed.state == "CLEAN"
    assert completed.unresolved_failures == ()
    assert {event.gate_id for event in completed.clearance_events} == {
        event.gate_id for event in previous.unresolved_failures
    }
    assert not D._incomplete_retry_arm_path(root, phase.name).exists()
    assert (partial.read_bytes(), partial.stat().st_mtime_ns) == before


def test_severity_dispatch_completed_semantic_debt_remains_haltless(
    tmp_path: Path, monkeypatch,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    config = _config(tmp_path)
    checkpoint = Checkpoint(run_id=config["_run_id"])
    phase = _phase("severity_adjudication_shadow")
    monkeypatch.setattr(
        D, "_run_severity_adjudication_shadow_phase",
        lambda *a: ({"all_resolved": False}, ["independent adjudication remains unresolved"]),
    )
    monkeypatch.setattr(D, "_reconcile_trust_evidence_provider_state", lambda *a: [])
    monkeypatch.setattr(D, "_run_bb_policy_terminal_boundary", lambda *a: ({}, []))
    monkeypatch.setattr(D, "gate_passes", lambda *a: (True, []))
    assert _execute_severity_dispatch(phase, config, root, checkpoint) == 0
    assert checkpoint.phase_commits[phase.name].state == "COMPLETED_WITH_DEBT"
    assert not D._incomplete_retry_arm_path(root, phase.name).exists()
