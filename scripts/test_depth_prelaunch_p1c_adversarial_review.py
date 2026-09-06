"""Adversarial runtime fixtures for depth prelaunch and P1-C authority.

These tests intentionally exercise orchestration seams instead of duplicating
the feature-fact derivation suite: first-bind ordering, retry immutability,
runtime launch parity, and the inability of output-only/missing-PRE evidence to
acquire terminal security-obligation authority.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_artifacts,
)
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract
import plamen_driver as D
import security_obligation_authority as A
import test_typed_feature_facts_p1_c as F


RUN_ID = F.RUN_ID
OUTPUT = "depth_state_trace_findings.md"
JOB = {
    "agent_id": "depth-state-trace",
    "role": "state_trace",
    "output": OUTPUT,
    "category": "standard",
    "focus": "state transitions",
}
PRE_SIDECARS = (
    A.FEATURE_FACT_FILE,
    A.AUTHORITY_FILE,
    A.PROJECTION_FILE,
)


def _phase() -> D.Phase:
    return next(item for item in D.SC_PHASES if item.name == "depth")


def _config(root: Path, *, backend: str = "claude") -> dict[str, object]:
    return {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": backend,
        "scratchpad": str(root),
        "project_root": str(root.parent),
        "_run_id": RUN_ID,
    }


def _write_worker_inputs(root: Path, *, backend: str = "claude") -> None:
    F._checkpoint(root)
    F._graph(root)
    (root / "findings_inventory.md").write_text(
        "# findings_inventory.md\n", encoding="utf-8"
    )
    F._materialize_valid_semantic_final_byte_authority(root, backend=backend)
    for name in PRE_SIDECARS:
        (root / name).write_text(f"pre:{name}\n", encoding="utf-8")
    config = _config(root, backend=backend)
    exact = D._typed_worker_registered_input_paths(
        phase_name="depth",
        scratchpad=root,
        config=config,
        agent_id=JOB["agent_id"],
        agent_role=JOB["role"],
        output=OUTPUT,
        work_category=JOB["category"],
        focus_area=JOB["focus"],
    )
    for name in exact:
        path = root / name
        if path.exists():
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "{}\n" if path.suffix == ".json" else f"fixture:{name}\n",
            encoding="utf-8",
        )


def _receipt_output(root: Path, *, finding_id: str = "INV-001") -> None:
    (root / OUTPUT).write_text(
        "<!-- PLAMEN_ARTIFACT: depth_state_trace_findings.md -->\n"
        "<!-- PLAMEN_OWNER: depth-state-trace -->\n"
        "<!-- PLAMEN_PHASE: depth -->\n"
        "# Depth\n\n"
        "[OBLIG:security_obligations.md:SO-001] STATUS:R "
        f"KEY:bound-transfer -> {finding_id}\n\n"
        f"### Finding [{finding_id}]\n\nBound referent.\n"
        "<!-- PLAMEN_STATUS: COMPLETE -->\n",
        encoding="utf-8",
    )


def _depth_contract_file(root: Path) -> None:
    (root / "_depth_worker_pool_contract.json").write_text(
        json.dumps(
            {
                "version": 2,
                "phase": "depth",
                "canonical_outputs": [OUTPUT],
                "outputs": [OUTPUT],
                "jobs": [{"agent_id": JOB["agent_id"], "output": OUTPUT}],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _patch_serial_fanout(
    monkeypatch: pytest.MonkeyPatch,
    *,
    complete,
    timeout: int = 211,
) -> None:
    monkeypatch.setattr(D, "_depth_worker_jobs", lambda *_a, **_k: [dict(JOB)])
    monkeypatch.setattr(D, "_depth_worker_output_complete", complete)
    monkeypatch.setattr(
        D,
        "_depth_dispatch_plan",
        lambda **_kwargs: [{"job": dict(JOB), "prompt": "bounded prompt"}],
    )
    monkeypatch.setattr(D, "_write_depth_dispatch_contract", lambda *_a, **_k: None)
    monkeypatch.setattr(D, "phase_model", lambda *_a, **_k: "runtime-model")
    monkeypatch.setattr(D, "scale_timeout", lambda *_a, **_k: timeout)
    monkeypatch.setattr(
        D, "_record_typed_model_worker_artifact", lambda **_kwargs: []
    )
    monkeypatch.setattr(
        D, "_synthesize_depth_lifecycle_artifacts", lambda *_a, **_k: None
    )
    monkeypatch.setattr(D, "_depth_da_job_if_required", lambda *_a, **_k: [])


def test_all_pty_prelaunch_receipts_precede_first_pool_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    jobs = [dict(JOB), {**JOB, "agent_id": "depth-edge", "output": "depth_edge_case_findings.md"}]
    events: list[tuple[str, str, float]] = []

    def bind(**kwargs):
        events.append(("bind", str(kwargs["output"]), float(kwargs["timeout_s"])))
        return []

    def execute(**kwargs):
        events.append(("exec", str(kwargs["job"]["output"]), float(kwargs["timeout"])))
        return {
            "output": kwargs["job"]["output"],
            "rc": 0,
            "status": "complete",
            "reasons": [],
        }

    monkeypatch.setattr(D, "_bind_typed_model_worker_inputs", bind)
    monkeypatch.setattr(D, "_run_single_depth_worker_pty", execute)
    monkeypatch.setattr(D, "_depth_worker_output_complete", lambda *_a, **_k: False)
    monkeypatch.setattr(D.display, "print_phase_heartbeat", lambda *_a, **_k: None)
    monkeypatch.setattr(D.display, "spin", lambda *_a, **_k: None)

    rc, results = D._run_depth_worker_batch(
        scratchpad=root,
        project_root=str(tmp_path),
        config=_config(root),
        phase=_phase(),
        base_cmd=[],
        env={},
        timeout=120,
        quiescence_s=1,
        jobs=jobs,
        attempt=1,
        pool_started=time.time(),
        retry_reasons_by_output={},
    )

    assert rc == 0 and len(results) == 2
    assert [event[0] for event in events[:2]] == ["bind", "bind"]
    assert {event[1] for event in events[:2]} == {job["output"] for job in jobs}
    assert all(event[2] == 120 for event in events)


@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_serialized_backend_binds_before_launch_with_exact_timeout_and_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: str,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    config = _config(root, backend=backend)
    events: list[tuple[str, float, str]] = []
    state = {"complete": False}
    _patch_serial_fanout(
        monkeypatch,
        complete=lambda *_a, **_k: state["complete"],
    )

    def bind(**kwargs):
        events.append(
            ("bind", float(kwargs["timeout_s"]), str(kwargs["config"]["cli_backend"]))
        )
        return []

    def execute(*_args, **kwargs):
        events.append(("exec", float(kwargs["timeout"]), str(kwargs["effective_model"])))
        state["complete"] = True
        return 0

    monkeypatch.setattr(D, "_bind_typed_model_worker_inputs", bind)
    if backend == "codex":
        monkeypatch.setattr(D, "_run_one_codex_exec", execute)
        monkeypatch.setattr(
            D,
            "_run_one_claude_headless_breadth_worker",
            lambda **_kwargs: pytest.fail("Claude launcher used for Codex backend"),
        )
    else:
        monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", execute)
        monkeypatch.setattr(
            D,
            "_run_one_codex_exec",
            lambda **_kwargs: pytest.fail("Codex launcher used for Claude backend"),
        )

    assert D._run_depth_codex_fanout(
        phase=_phase(), config=config, scratchpad=root, attempt=1
    ) == 0
    assert events == [
        ("bind", 211.0, backend),
        ("exec", 211.0, "runtime-model"),
    ]


def test_unchanged_model_prelaunch_retry_is_byte_stable_and_commit_parity_exact(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    _write_worker_inputs(root)
    config = _config(root, backend="claude")
    phase = _phase()
    kwargs = {
        "phase": phase,
        "config": config,
        "scratchpad": root,
        "project_root": str(tmp_path),
        "agent_id": JOB["agent_id"],
        "output": OUTPUT,
        "timeout_s": 173.9,
    }

    contract, launch = D._typed_model_worker_contract_and_launch(**kwargs)
    runtime = D._live_phase_runtime_launch_policy(phase, root, config)
    assert launch.backend == runtime["backend"] == "claude"
    assert launch.model == runtime["model"]
    assert launch.exec_mode == runtime["exec_mode"]
    assert launch.timeout_s == 173
    assert D._bind_typed_model_worker_inputs(**kwargs) == []
    ledger_path = root / "_artifact_state.json"
    first = ledger_path.read_bytes()
    assert D._bind_typed_model_worker_inputs(**kwargs) == []
    assert ledger_path.read_bytes() == first

    _receipt_output(root)
    assert D._record_typed_model_worker_artifact(**kwargs) == []
    unit = read_artifact_ledger(root)["work_units"][contract.key]
    assert unit["contract_digest"] == contract.digest
    assert unit["launch_digest"] == launch.digest
    assert unit["semantic_status"] == "ACTIVE"


@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_model_input_drift_is_not_reblessed_or_relaunched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: str,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    _write_worker_inputs(root, backend=backend)
    config = _config(root, backend=backend)
    phase = _phase()
    _patch_serial_fanout(
        monkeypatch,
        complete=lambda *_a, **_k: False,
    )
    bind_kwargs = {
        "phase": phase,
        "config": config,
        "scratchpad": root,
        "project_root": str(tmp_path),
        "agent_id": JOB["agent_id"],
        "output": OUTPUT,
        "timeout_s": 211,
    }
    assert D._bind_typed_model_worker_inputs(**bind_kwargs) == []
    contract, _launch = D._typed_model_worker_contract_and_launch(**bind_kwargs)
    first = read_artifact_ledger(root)["work_units"][contract.key]
    (root / A.AUTHORITY_FILE).write_text("model-side drift\n", encoding="utf-8")

    launches: list[str] = []
    monkeypatch.setattr(
        D,
        "_run_one_codex_exec",
        lambda **_kwargs: launches.append("codex") or 0,
    )
    monkeypatch.setattr(
        D,
        "_run_one_claude_headless_breadth_worker",
        lambda **_kwargs: launches.append("claude") or 0,
    )

    assert D._run_depth_codex_fanout(
        phase=phase, config=config, scratchpad=root, attempt=1
    ) == 0
    assert launches == []
    assert read_artifact_ledger(root)["work_units"][contract.key] == first
    retry_contract, _retry_launch = D._typed_model_worker_contract_and_launch(
        **bind_kwargs,
        attempt=2,
    )
    assert retry_contract.key not in read_artifact_ledger(root)["work_units"]
    debt = (root / "depth.degraded").read_text(encoding="utf-8")
    assert "DEPTH_WORKER_PRELAUNCH_INPUT_DEBT" in debt
    assert "model prelaunch input drift" in debt


@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_serial_incomplete_output_retry_requires_actual_backend_invocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: str,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    config = _config(root, backend=backend)
    state = {"complete": False}
    _patch_serial_fanout(
        monkeypatch,
        complete=lambda *_a, **_k: state["complete"],
    )
    binds: list[int] = []
    launches: list[int] = []
    retry_reasons: list[dict[str, list[str]]] = []

    def prepare(**kwargs):
        binds.append(int(kwargs["attempt"]))
        return []

    def dispatch(**kwargs):
        retry_reasons.append(dict(kwargs["retry_reasons_by_output"]))
        return [{"job": dict(JOB), "prompt": "bounded prompt"}]

    def launch(**kwargs):
        launch_attempt = int(kwargs["attempt"])
        launches.append(launch_attempt)
        if launch_attempt == 2:
            state["complete"] = True
        return 0

    monkeypatch.setattr(D, "_prepare_typed_model_worker_launch", prepare)
    monkeypatch.setattr(D, "_depth_dispatch_plan", dispatch)
    monkeypatch.setattr(D, "_run_one_codex_exec", launch)
    monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", launch)

    assert D._run_depth_codex_fanout(
        phase=_phase(), config=config, scratchpad=root, attempt=1
    ) == 0
    assert binds == [1, 2]
    assert launches == [1, 2]
    assert retry_reasons == [
        {OUTPUT: []},
        {OUTPUT: ["status=incomplete", f"output={OUTPUT}"]},
    ]


@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_da_prelaunch_block_is_terminal_for_that_leaf_without_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: str,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    config = _config(root, backend=backend)
    da_job = {
        "agent_id": "depth-da-iter2",
        "role": "da_iter2",
        "output": "depth_da_iter2_findings.md",
        "category": "standard",
        "focus": "adversarial second pass",
    }
    _patch_serial_fanout(
        monkeypatch,
        complete=lambda _root, _phase, job: job["output"] == OUTPUT,
    )
    monkeypatch.setattr(D, "_depth_da_job_if_required", lambda *_a, **_k: [da_job])
    monkeypatch.setattr(
        D,
        "_depth_dispatch_plan",
        lambda **kwargs: [
            {"job": dict(job), "prompt": "bounded prompt"}
            for job in kwargs["jobs"]
        ],
    )
    binds: list[int] = []
    launches: list[int] = []

    def blocked(**kwargs):
        binds.append(int(kwargs["attempt"]))
        D._append_phase_io_debt(
            root,
            "depth",
            "DEPTH_WORKER_PRELAUNCH_INPUT_DEBT",
            "depth_da_iter2_findings.md: fatal binding sentinel",
        )
        return ["fatal binding sentinel"]

    monkeypatch.setattr(D, "_prepare_typed_model_worker_launch", blocked)
    monkeypatch.setattr(
        D,
        "_run_one_codex_exec",
        lambda **kwargs: launches.append(int(kwargs["attempt"])) or 0,
    )
    monkeypatch.setattr(
        D,
        "_run_one_claude_headless_breadth_worker",
        lambda **kwargs: launches.append(int(kwargs["attempt"])) or 0,
    )

    assert D._run_depth_codex_fanout(
        phase=_phase(), config=config, scratchpad=root, attempt=1
    ) == 0
    assert binds == [1]
    assert launches == []
    debt = (root / "depth.degraded").read_text(encoding="utf-8")
    assert "fatal binding sentinel" in debt


@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_da_incomplete_output_retry_requires_actual_backend_invocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: str,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    config = _config(root, backend=backend)
    da_job = {
        "agent_id": "depth-da-iter2",
        "role": "da_iter2",
        "output": "depth_da_iter2_findings.md",
        "category": "standard",
        "focus": "adversarial second pass",
    }
    state = {"complete": False}
    _patch_serial_fanout(
        monkeypatch,
        complete=lambda _root, _phase, job: (
            job["output"] == OUTPUT or state["complete"]
        ),
    )
    monkeypatch.setattr(D, "_depth_da_job_if_required", lambda *_a, **_k: [da_job])
    monkeypatch.setattr(
        D,
        "_depth_dispatch_plan",
        lambda **kwargs: [
            {"job": dict(job), "prompt": "bounded prompt"}
            for job in kwargs["jobs"]
        ],
    )
    binds: list[int] = []
    launches: list[int] = []

    monkeypatch.setattr(
        D,
        "_prepare_typed_model_worker_launch",
        lambda **kwargs: binds.append(int(kwargs["attempt"])) or [],
    )

    def launch(**kwargs):
        launch_attempt = int(kwargs["attempt"])
        launches.append(launch_attempt)
        if launch_attempt == 2:
            state["complete"] = True
        return 0

    monkeypatch.setattr(D, "_run_one_codex_exec", launch)
    monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", launch)

    assert D._run_depth_codex_fanout(
        phase=_phase(), config=config, scratchpad=root, attempt=1
    ) == 0
    assert binds == [1, 2]
    assert launches == [1, 2]


def test_missing_pre_sidecar_is_visible_input_debt_and_never_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    F._checkpoint(root)
    F._graph(
        root,
        functions={
            "vault::transfer_asset_amount_to_recipient": {
                "bare": "transfer_asset_amount_to_recipient",
                "loc": "src/vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    F._build(root, stage="pre_depth")
    F._record_pre_authority(root)
    for name in ("findings_inventory.md", "semantic_invariants.md"):
        (root / name).write_text(f"# {name}\n", encoding="utf-8")
    (root / A.AUTHORITY_FILE).unlink()

    def execute(**kwargs):
        _receipt_output(root)
        issues = D._record_typed_model_worker_artifact(
            phase=kwargs["phase"],
            config=kwargs["config"],
            scratchpad=root,
            project_root=str(tmp_path),
            agent_id=JOB["agent_id"],
            output=OUTPUT,
            timeout_s=kwargs["timeout"],
        )
        return {
            "output": OUTPUT,
            "rc": 0 if not issues else -2,
            "status": "complete" if not issues else "incomplete",
            "reasons": issues,
        }

    monkeypatch.setattr(D, "_run_single_depth_worker_pty", execute)
    monkeypatch.setattr(D.display, "print_phase_heartbeat", lambda *_a, **_k: None)
    monkeypatch.setattr(D.display, "spin", lambda *_a, **_k: None)
    rc, _results = D._run_depth_worker_batch(
        scratchpad=root,
        project_root=str(tmp_path),
        config=_config(root),
        phase=_phase(),
        base_cmd=[],
        env={},
        timeout=120,
        quiescence_s=1,
        jobs=[dict(JOB)],
        attempt=1,
        pool_started=time.time(),
        retry_reasons_by_output={},
    )
    assert rc == 0
    assert "semantic input missing at binding" in (
        root / "depth.degraded"
    ).read_text(encoding="utf-8")

    contract, _launch = D._typed_model_worker_contract_and_launch(
        phase=_phase(),
        config=_config(root),
        scratchpad=root,
        project_root=str(tmp_path),
        agent_id=JOB["agent_id"],
        output=OUTPUT,
        timeout_s=120,
    )
    unit = read_artifact_ledger(root)["work_units"][contract.key]
    assert unit["semantic_status"] == "INPUT_DEBT"
    assert f"scratchpad:{OUTPUT}" not in unit["artifacts"]
    assert not (root / OUTPUT).exists()
    assert unit["input_bindings"][
        f"scratchpad:{A.AUTHORITY_FILE}"
    ]["status"] == "MISSING"

    _depth_contract_file(root)
    payload = F._build(root, stage="post_depth")
    obligation = F._by_rule(payload, "security.asset_binding.v1")
    assert obligation is not None and obligation["state"] == "UNACCOUNTED"
    assert not any(
        receipt.get("terminal_authority") is True
        for receipt in obligation.get("receipts", [])
    )


def test_output_only_historical_worker_row_cannot_certify_p1c(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    F._checkpoint(root)
    F._graph(
        root,
        functions={
            "vault::transfer_asset_amount_to_recipient": {
                "bare": "transfer_asset_amount_to_recipient",
                "loc": "src/vault.sol:L10",
                "callers": [],
                "callees": [],
            }
        },
    )
    F._build(root, stage="pre_depth")
    F._record_pre_authority(root)
    for name in ("findings_inventory.md", "semantic_invariants.md"):
        (root / name).write_text(f"# {name}\n", encoding="utf-8")
    _receipt_output(root)
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="depth",
        work_unit_id="worker.depth-state-trace",
        exact_outputs=(OUTPUT,),
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="opus",
        timeout_s=120,
        exec_mode="pty",
        tool_policy=("filesystem",),
    )
    record_work_unit_artifacts(
        root,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
        actor="MODEL",
    )
    assert read_artifact_ledger(root)["work_units"][contract.key][
        "input_bindings"
    ] == {}

    _depth_contract_file(root)
    payload = F._build(root, stage="post_depth")
    obligation = F._by_rule(payload, "security.asset_binding.v1")
    assert obligation is not None and obligation["state"] == "UNACCOUNTED"
    assert any(
        "unbound depth receipt artifact ignored" in issue
        and "artifact ledger status is not ACTIVE" in issue
        for issue in payload.get("issues", [])
    )


def test_completed_depth_resume_cannot_ignore_all_missing_p1c_sidecars(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".scratchpad"
    root.mkdir()
    F._checkpoint(root)
    F._graph(root)
    config = _config(root)
    D._record_security_obligation_phase_io(
        root, config, stage="post_depth"
    )
    for name in PRE_SIDECARS:
        (root / name).unlink()

    phase = D.Phase(
        "depth",
        [],
        [],
        base_timeout_s=120,
        min_artifact_bytes=1,
    )
    issues = D._resume_phase_contract_issues(
        root,
        str(tmp_path),
        phase,
        "thorough",
        "evm",
        "sc",
        "claude",
    )

    assert issues
    assert any(
        "security-obligation" in issue
        or "security_obligation" in issue
        for issue in issues
    )
