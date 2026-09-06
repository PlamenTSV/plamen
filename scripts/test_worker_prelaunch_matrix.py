"""Backend-neutral prelaunch input-authority regression matrix."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import pytest

from artifact_ledger import (
    arm_semantic_mutation,
    finalize_semantic_mutation,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
import plamen_driver as D
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
from recon_prepass import _prepass_output_names


def _phase(name: str) -> D.Phase:
    return D.Phase(name, [name], [f"{name}_out.md"], base_timeout_s=120)


def _config(tmp_path: Path, backend: str) -> dict[str, object]:
    return {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": backend,
        "project_root": str(tmp_path),
        "_run_id": "prelaunch-matrix",
    }


def _write_recon_retry_plan(
    scratchpad: Path,
    phase: D.Phase,
    *,
    config: dict[str, object] | None = None,
    run_id: str = "prelaunch-matrix",
    attempt: int = 2,
    failure_count: int = 1,
) -> tuple[bytes, D.GateFailure]:
    active_config = config or _config(scratchpad, "claude")
    input_digest = D._resolved_phase_input_digest(phase, active_config)
    contract_digest = D._resolved_phase_contract_digest(phase, active_config)
    failures = [
        D.GateFailure(
            gate_id=f"recon.full_validator.{index:04d}",
            gate_class="SCHEMA",
            message=f"repair failed full recon predicate {index}",
            affected_identities=(f"recon_out_{index}.md",),
            input_digest=input_digest,
            output_digest="2" * 64,
            contract_digest=contract_digest,
            evidence_paths=(f"recon_out_{index}.md",),
            repair_owner="recon",
            denominator_count=failure_count,
            denominator_digest="4" * 64,
        )
        for index in range(1, failure_count + 1)
    ]
    payload = {
        "schema": "plamen.retry-plan/v1",
        "run_id": run_id,
        "phase_name": "recon",
        "work_unit_id": "phase",
        "attempt": attempt,
        "input_digest": input_digest,
        "output_digest_before": "6" * 64,
        "contract_digest": contract_digest,
        "launch_digest": D._resolved_phase_launch_digest(
            phase, active_config
        ),
        "required_output_schema": [
            {
                "pattern": pattern,
                "minimum_bytes": phase.min_artifact_bytes,
                "minimum_count": phase.min_artifacts_count,
            }
            for pattern in phase.expected_artifacts
        ],
        "failed_predicates": [failure.to_dict() for failure in failures],
        "semantic_retry": True,
    }
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    (scratchpad / "recon_retry_plan.json").write_bytes(raw)
    return raw, failures[0]


def _write_authenticated_prepass_fixture(
    scratchpad: Path,
    *,
    pipeline: str = "sc",
) -> dict[str, bytes]:
    selected = tuple(_prepass_output_names(pipeline)[:-1])
    payloads = {
        name: (f"prepass baseline {name}\n" + "p" * 600).encode()
        for name in selected
    }
    for name, raw in payloads.items():
        (scratchpad / name).write_bytes(raw)
    receipt = {
        "schema": "plamen.recon_prepass_publication.v2",
        "authority_capture": {},
        "selected_outputs": list(selected),
        "selected_output_sha256": {
            name: hashlib.sha256(raw).hexdigest()
            for name, raw in payloads.items()
        },
        "auxiliary_outputs": [],
        "auxiliary_output_sha256": {},
        "results": {},
    }
    receipt["artifact_sha256"] = hashlib.sha256(
        json.dumps(
            receipt,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
    ).hexdigest().upper()
    (scratchpad / "recon_prepass_publication_receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return payloads


@pytest.mark.parametrize("backend", ("claude", "codex"))
@pytest.mark.parametrize("phase_name", ("recon", "breadth", "rescan", "depth"))
def test_unchanged_retry_is_byte_stable_and_new_input_drift_is_fatal(
    tmp_path: Path, backend: str, phase_name: str,
) -> None:
    phase = _phase(phase_name)
    config = _config(tmp_path, backend)
    kwargs = {
        "phase": phase,
        "config": config,
        "scratchpad": tmp_path,
        "project_root": str(tmp_path),
        "agent_id": f"{phase_name}-matrix",
        "output": f"{phase_name}_out.md",
        "timeout_s": 120,
    }

    # A sparse fixture deliberately exercises repair-then-degrade: missing
    # semantic inputs are recorded as INPUT_DEBT but do not suppress recall.
    assert D._prepare_typed_model_worker_launch(**kwargs) == []
    first = (tmp_path / "_artifact_state.json").read_bytes()
    assert D._prepare_typed_model_worker_launch(**kwargs) == []
    assert (tmp_path / "_artifact_state.json").read_bytes() == first

    contract, _launch = D._typed_model_worker_contract_and_launch(**kwargs)
    unit = read_artifact_ledger(tmp_path)["work_units"][contract.key]
    assert unit["semantic_status"] == "INPUT_DEBT"
    missing = next(
        key.removeprefix("scratchpad:")
        for key, row in unit["input_bindings"].items()
        if key.startswith("scratchpad:") and row["status"] == "MISSING"
    )
    path = tmp_path / missing
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("late input\n", encoding="utf-8")

    fatal = D._prepare_typed_model_worker_launch(**kwargs)
    assert fatal and any("model prelaunch input drift" in issue for issue in fatal)
    assert (tmp_path / "_artifact_state.json").read_bytes() == first


def test_recon_retry_uses_new_bound_unit_but_rejects_drift_after_binding(
    tmp_path: Path,
) -> None:
    phase = _phase("recon")
    config = _config(tmp_path, "claude")
    base = {
        "phase": phase,
        "config": config,
        "scratchpad": tmp_path,
        "project_root": str(tmp_path),
        "agent_id": "R1",
        "output": "recon_out.md",
        "timeout_s": 120,
    }

    assert D._prepare_typed_model_worker_launch(**base, attempt=1) == []
    first_contract, _ = D._typed_model_worker_contract_and_launch(
        **base, attempt=1
    )
    first_unit = read_artifact_ledger(tmp_path)["work_units"][first_contract.key]
    missing_identity = next(
        identity
        for identity, row in first_unit["input_bindings"].items()
        if identity.startswith("scratchpad:") and row["status"] == "MISSING"
    )
    changed_input = tmp_path / missing_identity.removeprefix("scratchpad:")
    changed_input.parent.mkdir(parents=True, exist_ok=True)
    changed_input.write_text("authorized retry denominator\n", encoding="utf-8")
    plan_raw, failure = _write_recon_retry_plan(
        tmp_path, phase, config=config
    )
    (tmp_path / "recon_retry_hint.md").write_text(
        "Repair only the full recon validator.\n", encoding="utf-8"
    )

    # Outer recon attempt 2 begins at worker ordinal 3. It receives a new
    # immutable work unit and may therefore bind the post-quarantine/retry-plan
    # denominator instead of attempting to bless it under attempt 1.
    retry_attempt = D._recon_worker_attempt_ordinal(2, 1)
    assert retry_attempt == 3
    assert D._prepare_typed_model_worker_launch(
        **base, attempt=retry_attempt
    ) == []
    retry_contract, _ = D._typed_model_worker_contract_and_launch(
        **base, attempt=retry_attempt
    )
    assert retry_contract.key != first_contract.key
    retry_unit = read_artifact_ledger(tmp_path)["work_units"][retry_contract.key]
    bound_digest = retry_unit["input_set_digest"]
    plan_binding = retry_unit["input_bindings"][
        "scratchpad:recon_retry_plan.json"
    ]
    # The ledger persists a present typed input as ACTIVE authority; the
    # observation layer's equivalent state is PRESENT.
    assert plan_binding["status"] == "ACTIVE"
    assert plan_binding["sha256"] == hashlib.sha256(plan_raw).hexdigest()
    assert (
        read_artifact_ledger(tmp_path)["work_units"][first_contract.key]
        == first_unit
    )
    prompt = D._build_recon_worker_prompt(
        job={
            "agent_id": "R1",
            "role": "build_static",
            "output": "recon_out.md",
            "focus": "build",
        },
        scratchpad=tmp_path,
        project_root=str(tmp_path),
        config=config,
        attempt=retry_attempt,
    )
    assert "## HARD Retry Authority" in prompt
    assert hashlib.sha256(plan_raw).hexdigest() in prompt
    assert failure.gate_id not in prompt
    assert "No authenticated predicate is assigned to this output" in prompt
    assert "Repair only the full recon validator" not in prompt
    assert "recon_retry_hint.md" not in prompt
    assert "sole output" in prompt

    changed_input.write_text(
        "foreign drift after retry binding\n", encoding="utf-8"
    )
    fatal = D._prepare_typed_model_worker_launch(
        **base, attempt=retry_attempt
    )
    assert fatal and any(
        "model prelaunch input drift" in issue for issue in fatal
    )
    assert (
        read_artifact_ledger(tmp_path)["work_units"][retry_contract.key][
            "input_set_digest"
        ]
        == bound_digest
    )
    postcommit = D._record_typed_model_worker_artifact(
        **base, attempt=retry_attempt
    )
    assert postcommit, "postcommit must not bless output after input drift"


def test_attempt2_plan_authorizes_only_immediate_attempt3_transport_successor(
    tmp_path: Path,
) -> None:
    phase = _phase("recon")
    config = _config(tmp_path, "claude")
    plan_raw, failure = _write_recon_retry_plan(
        tmp_path, phase, config=config, attempt=2
    )
    base = {
        "phase": phase,
        "config": config,
        "scratchpad": tmp_path,
        "project_root": str(tmp_path),
        "agent_id": "R1",
        "output": "recon_out.md",
        "timeout_s": 120,
    }
    semantic_worker = D._recon_worker_attempt_ordinal(2, 1)
    successor_workers = (
        D._recon_worker_attempt_ordinal(3, 1),
        D._recon_worker_attempt_ordinal(3, 2),
    )
    assert D._prepare_typed_model_worker_launch(
        **base, attempt=semantic_worker
    ) == []
    semantic_contract, _ = D._typed_model_worker_contract_and_launch(
        **base, attempt=semantic_worker
    )
    semantic_row = read_artifact_ledger(tmp_path)["work_units"][
        semantic_contract.key
    ]
    for worker_attempt in successor_workers:
        authority = D._validated_recon_retry_plan(
            tmp_path,
            config,
            worker_attempt=worker_attempt,
            phase=phase,
        )
        assert authority["transport_successor"] is True
        assert authority["plan_attempt"] == 2
        assert D._prepare_typed_model_worker_launch(
            **base, attempt=worker_attempt
        ) == []
    assert (
        read_artifact_ledger(tmp_path)["work_units"][semantic_contract.key]
        == semantic_row
    )
    prompt = D._build_recon_worker_prompt(
        job={
            "agent_id": "R1", "role": "build_static",
            "output": "recon_out.md", "focus": "build",
        },
        scratchpad=tmp_path,
        project_root=str(tmp_path),
        config=config,
        attempt=successor_workers[0],
    )
    assert "Transport-successor state: `ACTIVE`" in prompt
    assert hashlib.sha256(plan_raw).hexdigest() in prompt
    assert failure.gate_id not in prompt
    assert "No authenticated predicate is assigned to this output" in prompt
    with pytest.raises(ValueError, match="stale"):
        D._validated_recon_retry_plan(
            tmp_path,
            config,
            worker_attempt=D._recon_worker_attempt_ordinal(4, 1),
            phase=phase,
        )


@pytest.mark.parametrize("plan_attempt", (3, 4))
def test_outer4_rejects_present_plan_without_durable_authority(
    tmp_path: Path,
    plan_attempt: int,
) -> None:
    phase = _phase("recon")
    config = _config(tmp_path, "claude")
    _write_recon_retry_plan(
        tmp_path, phase, config=config, attempt=plan_attempt
    )
    with pytest.raises(ValueError, match="stale"):
        D._validated_recon_retry_plan(
            tmp_path,
            config,
            worker_attempt=D._recon_worker_attempt_ordinal(4, 1),
            phase=phase,
        )


def test_retry_prompt_binds_full_plan_but_projects_only_assigned_predicates(
    tmp_path: Path,
) -> None:
    phase = _phase("recon")
    config = _config(tmp_path, "claude")
    _write_recon_retry_plan(
        tmp_path, phase, config=config, failure_count=20
    )
    prompt = D._build_recon_worker_prompt(
        job={
            "agent_id": "R1", "role": "build_static",
            "output": "recon_out.md", "focus": "build",
        },
        scratchpad=tmp_path,
        project_root=str(tmp_path),
        config=config,
        attempt=D._recon_worker_attempt_ordinal(2, 1),
    )
    assert "Authenticated predicate count: `20`" in prompt
    assert "Read the exact registered PhaseIO input" in prompt
    assert "at-most-16 applicable rows" in prompt
    assert "No authenticated predicate is assigned to this output" in prompt
    assert "recon.full_validator.0016" not in prompt
    assert "recon.full_validator.0017" not in prompt
    assert "recon.full_validator.0020" in (
        tmp_path / "recon_retry_plan.json"
    ).read_text(encoding="utf-8")


@pytest.mark.parametrize("violation", ("namespace", "contract_digest"))
def test_retry_plan_rejects_foreign_gate_namespace_or_contract(
    tmp_path: Path,
    violation: str,
) -> None:
    phase = _phase("recon")
    config = _config(tmp_path, "claude")
    _write_recon_retry_plan(tmp_path, phase, config=config)
    path = tmp_path / "recon_retry_plan.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    row = dict(payload["failed_predicates"][0])
    row["gate_id"] = (
        "breadth.full_validator.0001"
        if violation == "namespace"
        else row["gate_id"]
    )
    row["contract_digest"] = (
        "f" * 64 if violation == "contract_digest" else row["contract_digest"]
    )
    row["predicate_digest"] = ""
    row["failure_instance_id"] = ""
    canonical = D.GateFailure.from_dict(row).to_dict()
    payload["failed_predicates"] = [canonical]
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    match = "namespace" if violation == "namespace" else "contract digest"
    with pytest.raises(ValueError, match=match):
        D._validated_recon_retry_plan(
            tmp_path,
            config,
            worker_attempt=D._recon_worker_attempt_ordinal(2, 1),
            phase=phase,
        )


@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_recon_rate_limit_replays_same_outer_attempt_despite_shallow_gate(
    tmp_path: Path,
    backend: str,
) -> None:
    phase = _phase("recon")
    decision = D._rate_limit_retry_dispatch(
        phase,
        _config(tmp_path, backend),
        tmp_path,
        current_attempt=1,
        shallow_gate_passed=True,
    )
    assert decision == {
        "skip_spawn": False,
        "attempt": 1,
        "recon_transport_replay": True,
    }
    # The replay retains both internal hinted rounds without consuming the
    # separately authorized semantic retry namespace (workers 3/4).
    assert D._recon_worker_attempt_ordinal(decision["attempt"], 1) == 1
    assert D._recon_worker_attempt_ordinal(decision["attempt"], 2) == 2
    extended = D._rate_limit_retry_dispatch(
        phase,
        _config(tmp_path, backend),
        tmp_path,
        current_attempt=3,
        shallow_gate_passed=True,
    )
    assert extended == {
        "skip_spawn": False,
        "attempt": 3,
        "recon_transport_replay": True,
    }


def test_extended_rate_limit_dispatch_never_reuses_attempt_two(
    tmp_path: Path,
) -> None:
    ordinary = _phase("breadth")
    decision = D._rate_limit_retry_dispatch(
        ordinary,
        _config(tmp_path, "claude"),
        tmp_path,
        current_attempt=3,
        shallow_gate_passed=False,
    )
    assert decision["attempt"] == 3
    config = _config(tmp_path, "claude")
    config["_recon_force_direct_retry"] = True
    direct = D._rate_limit_retry_dispatch(
        _phase("recon"),
        config,
        tmp_path,
        current_attempt=3,
        shallow_gate_passed=True,
    )
    assert direct == {
        "skip_spawn": False,
        "attempt": 3,
        "recon_transport_replay": True,
    }


def test_recon_semantic_quarantine_hides_invalid_shards_not_prepass_bundle(
    tmp_path: Path,
) -> None:
    phase = next(item for item in D.SC_PHASES if item.name == "recon")
    canonical = {
        name: (f"canonical authority {name}\n" + "c" * 600).encode()
        for name in phase.expected_artifacts
    }
    for name, raw in canonical.items():
        (tmp_path / name).write_bytes(raw)
    invalid = tmp_path / "recon_build_static.md"
    invalid.write_text("invalid attempt-one shard\n" + "x" * 600, encoding="utf-8")

    moved = D._quarantine_stale_on_retry(
        tmp_path, phase, ["recon global semantic validator failed"]
    )
    assert moved == ["recon_build_static.md"]
    assert not invalid.exists()
    assert (
        tmp_path / "_retry_quarantine" / "recon" / invalid.name
    ).is_file()
    for name, raw in canonical.items():
        assert (tmp_path / name).read_bytes() == raw

    D._restore_quarantined_on_retry_failure(tmp_path, phase)
    assert invalid.is_file()
    assert "invalid attempt-one shard" in invalid.read_text(encoding="utf-8")


def test_recon_retry_accepts_only_byte_identical_authenticated_prepass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, "claude")
    payloads = _write_authenticated_prepass_fixture(tmp_path)
    authority_calls: list[tuple[str, ...]] = []

    def authority(_sp, _project, identities, **_kwargs):
        authority_calls.append(tuple(identities))
        return []

    monkeypatch.setattr(
        D, "semantic_input_prebind_producer_authority_issues", authority
    )
    assert D._ensure_recon_prepass_retry_baseline(tmp_path, config) == []
    assert D._restore_recon_prepass_retry_baseline(tmp_path, config) == []
    assert (tmp_path / "contract_inventory.md").read_bytes() == payloads[
        "contract_inventory.md"
    ]
    assert len(authority_calls) == 2  # capture and exact retry replay


def test_unauthenticated_canonical_mutation_cannot_enter_recon_attempt2(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, "claude")
    _write_authenticated_prepass_fixture(tmp_path)
    calls = 0

    def authority(_sp, _project, _identities, **_kwargs):
        nonlocal calls
        calls += 1
        return [] if calls == 1 else ["contract_inventory producer mismatch"]

    monkeypatch.setattr(
        D, "semantic_input_prebind_producer_authority_issues", authority
    )
    assert D._ensure_recon_prepass_retry_baseline(tmp_path, config) == []
    mutated = tmp_path / "contract_inventory.md"
    foreign = b"foreign attempt-one canonical bytes\n" + b"f" * 600
    mutated.write_bytes(foreign)
    issues = D._restore_recon_prepass_retry_baseline(tmp_path, config)
    assert issues and "no authenticated producer" in issues[0]
    assert mutated.read_bytes() == foreign


def test_real_semantic_mutation_cannot_be_reblessed_as_prepass_retry_input(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, "claude")
    selected = tuple(_prepass_output_names("sc")[:-1])
    payloads = {
        name: (f"prepass authority {name}\n" + "p" * 600).encode()
        for name in selected
    }
    receipt = {
        "schema": "plamen.recon_prepass_publication.v2",
        "authority_capture": {},
        "selected_outputs": list(selected),
        "selected_output_sha256": {
            name: hashlib.sha256(raw).hexdigest()
            for name, raw in payloads.items()
        },
        "auxiliary_outputs": [],
        "auxiliary_output_sha256": {},
        "results": {},
    }
    receipt["artifact_sha256"] = hashlib.sha256(
        json.dumps(
            receipt,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
    ).hexdigest().upper()
    all_payloads = {
        **payloads,
        "recon_prepass_publication_receipt.json": (
            json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        ).encode(),
    }
    key = canonical_work_unit_key(
        "sc", "thorough", "evm", "claude", "recon", "prepass"
    )
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="recon",
        work_unit_id="prepass",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=name,
                owner_key=key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                minimum_gate="FIXTURE_EXACT_BYTES",
            )
            for name in all_payloads
        ),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        model="driver",
        timeout_s=30,
        exec_mode="python",
        tool_policy=(),
    )
    record_work_unit_inputs(
        tmp_path, tmp_path, contract, launch, run_id="prelaunch-matrix"
    )
    for name, raw in all_payloads.items():
        (tmp_path / name).write_bytes(raw)
    record_work_unit_artifacts(
        tmp_path,
        tmp_path,
        contract,
        launch,
        run_id="prelaunch-matrix",
        actor="DRIVER",
    )
    assert D._ensure_recon_prepass_retry_baseline(tmp_path, config) == []

    identity = "scratchpad:contract_inventory.md"
    event = arm_semantic_mutation(
        tmp_path,
        tmp_path,
        artifact_identity=identity,
        mutation_kind="FIXTURE_CANONICAL_MUTATION",
        run_id="prelaunch-matrix",
    )
    foreign = b"authenticated but non-prepass successor\n" + b"f" * 600
    (tmp_path / "contract_inventory.md").write_bytes(foreign)
    finalize_semantic_mutation(
        tmp_path,
        tmp_path,
        str(event["event_id"]),
        run_id="prelaunch-matrix",
    )

    issues = D._restore_recon_prepass_retry_baseline(tmp_path, config)
    assert issues
    assert "semantic-mutation authority lacks" in issues[0]
    assert (tmp_path / "contract_inventory.md").read_bytes() == foreign


def test_recon_pool_maps_outer_retry_to_fresh_worker_attempts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase = _phase("recon")
    config = _config(tmp_path, "claude")
    jobs = [
        {"agent_id": "R1", "role": "general", "output": "recon_out.md"}
    ]
    complete: set[str] = set()
    bound_attempts: list[int] = []
    launched_attempts: list[int] = []

    def prepare(**kwargs):
        bound_attempts.append(int(kwargs["attempt"]))
        return []

    def execute(**kwargs):
        launched_attempts.append(int(kwargs["attempt"]))
        complete.add(str(kwargs["job"]["output"]))
        return {
            "output": kwargs["job"]["output"],
            "rc": 0,
            "status": "complete",
            "reasons": [],
        }

    monkeypatch.setattr(D, "_recon_worker_jobs", lambda *_a, **_k: jobs)
    monkeypatch.setattr(
        D,
        "_recon_worker_complete",
        lambda _sp, output, _job, _config: (output in complete, []),
    )
    monkeypatch.setattr(D, "_prepare_typed_model_worker_launch", prepare)
    monkeypatch.setattr(D, "_run_single_recon_worker_pty", execute)
    monkeypatch.setattr(D, "_merge_recon_worker_shards", lambda *_a, **_k: None)
    monkeypatch.setattr(
        D,
        "_run_recon_dependency_research_wave",
        lambda **_k: {"status": "not_applicable"},
    )
    monkeypatch.setattr(D, "gate_passes", lambda *_a, **_k: (True, []))
    monkeypatch.setattr(D.display, "print_phase_heartbeat", lambda *_a, **_k: None)
    monkeypatch.setattr(D.display, "spin", lambda *_a, **_k: None)

    rc = D._run_recon_worker_pool_pty(
        scratchpad=tmp_path,
        project_root=str(tmp_path),
        config=config,
        phase=phase,
        base_cmd=[],
        env={},
        timeout=120,
        quiescence_s=0.1,
        attempt=2,
    )

    assert rc == 0
    assert bound_attempts == [3]
    assert launched_attempts == [3]


@pytest.mark.parametrize(
    ("outer_attempt", "expected"),
    ((1, [1, 2]), (2, [3, 4])),
)
def test_recon_pool_executes_both_rounds_in_outer_attempt_namespace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    outer_attempt: int,
    expected: list[int],
) -> None:
    phase = _phase("recon")
    config = _config(tmp_path, "claude")
    jobs = [{"agent_id": "R1", "role": "general", "output": "recon_out.md"}]
    bound: list[int] = []
    launched: list[int] = []

    def prepare(**kwargs):
        bound.append(int(kwargs["attempt"]))
        return []

    def execute(**kwargs):
        launched.append(int(kwargs["attempt"]))
        return {
            "output": kwargs["job"]["output"],
            "rc": -2,
            "status": "incomplete",
            "reasons": ["exercise next round"],
        }

    monkeypatch.setattr(D, "_recon_worker_jobs", lambda *_a, **_k: jobs)
    monkeypatch.setattr(D, "_recon_worker_complete", lambda *_a, **_k: (False, []))
    monkeypatch.setattr(D, "_prepare_typed_model_worker_launch", prepare)
    monkeypatch.setattr(D, "_run_single_recon_worker_pty", execute)
    monkeypatch.setattr(D, "_merge_recon_worker_shards", lambda *_a, **_k: None)
    monkeypatch.setattr(
        D, "_run_recon_dependency_research_wave",
        lambda **_k: {"status": "not_applicable"},
    )
    monkeypatch.setattr(D, "gate_passes", lambda *_a, **_k: (False, ["missing"]))
    monkeypatch.setattr(
        D, "_try_recon_prepass_marker_degrade",
        lambda *_a, **_k: (False, ["missing"]),
    )
    monkeypatch.setattr(D.display, "print_phase_heartbeat", lambda *_a, **_k: None)
    monkeypatch.setattr(D.display, "spin", lambda *_a, **_k: None)

    assert D._run_recon_worker_pool_pty(
        scratchpad=tmp_path,
        project_root=str(tmp_path),
        config=config,
        phase=phase,
        base_cmd=[],
        env={},
        timeout=120,
        quiescence_s=0.1,
        attempt=outer_attempt,
    ) == -2
    assert bound == expected
    assert launched == expected


def test_recon_phase_log_excludes_stale_worker_rate_limit_output_when_no_leaf_launches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stale = tmp_path / "_stdio_recon_worker_R1.attempt1.log"
    stale.write_text(
        "api_error_status=429 type=rate_limit_error\n", encoding="utf-8"
    )
    phase = _phase("recon")
    config = _config(tmp_path, "claude")
    jobs = [{"agent_id": "R1", "role": "general", "output": "recon_out.md"}]
    bound_attempts: list[int] = []
    monkeypatch.setattr(D, "_recon_worker_jobs", lambda *_a, **_k: jobs)
    monkeypatch.setattr(
        D, "_recon_worker_complete", lambda *_a, **_k: (False, ["missing"])
    )
    def deny(**kwargs):
        bound_attempts.append(int(kwargs["attempt"]))
        return ["separately authorized retry work unit required"]

    monkeypatch.setattr(D, "_prepare_typed_model_worker_launch", deny)
    monkeypatch.setattr(
        D, "_run_single_recon_worker_pty",
        lambda **_k: pytest.fail("leaf launched after prelaunch denial"),
    )
    monkeypatch.setattr(D, "_merge_recon_worker_shards", lambda *_a, **_k: None)
    monkeypatch.setattr(
        D, "_run_recon_dependency_research_wave",
        lambda **_k: {"status": "not_applicable"},
    )
    monkeypatch.setattr(D, "gate_passes", lambda *_a, **_k: (False, ["missing"]))
    monkeypatch.setattr(
        D, "_try_recon_prepass_marker_degrade",
        lambda *_a, **_k: (False, ["missing"]),
    )
    monkeypatch.setattr(D.display, "print_phase_heartbeat", lambda *_a, **_k: None)
    monkeypatch.setattr(D.display, "spin", lambda *_a, **_k: None)
    attempt_log = tmp_path / "_stdio_recon.attempt2.log"
    canonical = tmp_path / "_stdio_recon.log"
    rc = D._run_and_publish_recon_worker_pool_attempt(
        scratchpad=tmp_path,
        project_root=str(tmp_path),
        config=config,
        phase=phase,
        base_cmd=[],
        env={},
        timeout=120,
        quiescence_s=0.1,
        attempt=2,
        log_path=attempt_log,
        canonical=canonical,
        started_at=time.time(),
    )
    assert rc == -2
    assert bound_attempts == [3, 4]
    for path in (attempt_log, canonical):
        text = path.read_text(encoding="utf-8")
        assert "429" not in text
        assert "rate_limit_error" not in text
        assert "PLAMEN_RATE_LIMIT_DETECTED" not in text
        assert D.detect_rate_limit(path) is False


@pytest.mark.parametrize("malformed", (False, True))
def test_recon_retry_plan_drift_or_malformed_plan_blocks_leaf_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    malformed: bool,
) -> None:
    phase = _phase("recon")
    config = _config(tmp_path, "claude")
    job = {
        "agent_id": "R1", "role": "build_static",
        "output": "recon_out.md", "focus": "build",
    }
    raw, _failure = _write_recon_retry_plan(tmp_path, phase, config=config)
    attempt = D._recon_worker_attempt_ordinal(2, 1)
    kwargs = {
        "phase": phase,
        "config": config,
        "scratchpad": tmp_path,
        "project_root": str(tmp_path),
        "agent_id": "R1",
        "output": "recon_out.md",
        "timeout_s": 120,
        "attempt": attempt,
    }
    monkeypatch.setattr(
        D, "ClaudePtySession",
        lambda *_a, **_k: pytest.fail("leaf session launched"),
    )
    if not malformed:
        assert D._prepare_typed_model_worker_launch(**kwargs) == []
        (tmp_path / "recon_retry_plan.json").write_bytes(
            raw.replace(b"repair failed", b"repair forged")
        )
        result = D._run_single_recon_worker_pty(
            job=job,
            scratchpad=tmp_path,
            project_root=str(tmp_path),
            config=config,
            phase=phase,
            base_cmd=[],
            env={},
            timeout=120,
            quiescence_s=0.1,
            attempt=attempt,
            inputs_prebound=True,
        )
        assert result["status"] == "input_authority_debt"
    else:
        (tmp_path / "recon_retry_plan.json").write_text(
            '{"schema":"plamen.retry-plan/v1","schema":"duplicate"}',
            encoding="utf-8",
        )
        assert D._prepare_typed_model_worker_launch(**kwargs)


@pytest.mark.parametrize("backend", ("codex", "claude-headless"))
def test_headless_recon_revalidates_plan_immediately_before_backend_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
) -> None:
    phase = _phase("recon")
    config = _config(tmp_path, "codex" if backend == "codex" else "claude")
    _write_recon_retry_plan(tmp_path, phase, config=config)
    job = {
        "agent_id": "R1", "role": "build_static",
        "output": "recon_out.md", "focus": "build",
    }
    original_builder = D._build_recon_worker_prompt

    def build_then_mutate(**kwargs):
        prompt = original_builder(**kwargs)
        plan = tmp_path / "recon_retry_plan.json"
        plan.write_bytes(plan.read_bytes() + b"\n")
        return prompt

    monkeypatch.setattr(D, "_recon_worker_jobs", lambda *_a, **_k: [job])
    monkeypatch.setattr(
        D, "_recon_worker_complete", lambda *_a, **_k: (False, ["missing"])
    )
    monkeypatch.setattr(D, "_build_recon_worker_prompt", build_then_mutate)
    monkeypatch.setattr(
        D,
        "_run_one_codex_exec",
        lambda **_k: pytest.fail("Codex spawned after retry-plan drift"),
    )
    monkeypatch.setattr(
        D,
        "_run_one_claude_headless_breadth_worker",
        lambda **_k: pytest.fail("Claude spawned after retry-plan drift"),
    )
    assert D._run_recon_backend_fanout(
        backend=backend,
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=2,
        timeout=120,
        effective_model="test-model",
    ) == -2


@pytest.mark.parametrize("pool_name", ("recon", "breadth", "rescan"))
def test_pty_pool_binds_every_row_before_first_leaf_invocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pool_name: str,
) -> None:
    phase = _phase(pool_name)
    config = _config(tmp_path, "claude")
    jobs = [
        {"agent_id": "A", "role": "general", "output": "a.md"},
        {"agent_id": "B", "role": "general", "output": "b.md"},
    ]
    events: list[tuple[str, str]] = []
    completed: set[str] = set()

    def prepare(**kwargs):
        events.append(("bind", str(kwargs["output"])))
        return []

    def execute(**kwargs):
        output = str(kwargs["job"]["output"])
        assert kwargs["inputs_prebound"] is True
        events.append(("exec", output))
        completed.add(output)
        return {"output": output, "rc": 0, "status": "complete", "reasons": []}

    monkeypatch.setattr(D, "_prepare_typed_model_worker_launch", prepare)
    monkeypatch.setattr(D, "gate_passes", lambda *_a, **_k: (True, []))
    monkeypatch.setattr(D.display, "print_phase_heartbeat", lambda *_a, **_k: None)
    monkeypatch.setattr(D.display, "spin", lambda *_a, **_k: None)

    common = dict(
        scratchpad=tmp_path,
        project_root=str(tmp_path),
        config=config,
        phase=phase,
        base_cmd=[],
        env={},
        timeout=120,
        quiescence_s=0.1,
        attempt=1,
    )
    if pool_name == "breadth":
        plan = [{"job": dict(job), "prompt": "prompt"} for job in jobs]
        monkeypatch.setattr(D, "_breadth_dispatch_plan", lambda **_k: plan)
        monkeypatch.setattr(D, "_breadth_open_jobs", lambda *_a, **_k: jobs)
        monkeypatch.setattr(D, "_write_breadth_dispatch_contract", lambda *_a, **_k: None)
        monkeypatch.setattr(D, "_run_single_breadth_worker_pty", execute)
        rc = D._run_breadth_worker_pool_pty_core(**common)
    elif pool_name == "rescan":
        plan = [{"job": dict(job), "prompt": "prompt"} for job in jobs]
        monkeypatch.setattr(D, "_rescan_worker_jobs", lambda *_a, **_k: jobs)
        monkeypatch.setattr(D, "_rescan_open_jobs", lambda *_a, **_k: jobs)
        monkeypatch.setattr(D, "_rescan_dispatch_plan", lambda **_k: plan)
        monkeypatch.setattr(D, "_write_rescan_dispatch_contract", lambda *_a, **_k: None)
        monkeypatch.setattr(D, "_rescan_worker_pool_progress_status", lambda *_a, **_k: "ok")
        monkeypatch.setattr(D, "_run_single_rescan_worker_pty", execute)
        rc = D._run_rescan_worker_pool_pty(**common)
    else:
        monkeypatch.setattr(D, "_recon_worker_jobs", lambda *_a, **_k: jobs)
        monkeypatch.setattr(
            D, "_recon_worker_complete",
            lambda _sp, output, _job, _config: (output in completed, []),
        )
        monkeypatch.setattr(D, "_run_single_recon_worker_pty", execute)
        monkeypatch.setattr(D, "_merge_recon_worker_shards", lambda *_a, **_k: None)
        monkeypatch.setattr(
            D, "_run_recon_dependency_research_wave",
            lambda **_k: {"status": "not_applicable"},
        )
        rc = D._run_recon_worker_pool_pty(**common)

    assert rc == 0
    assert events[:2] == [("bind", "a.md"), ("bind", "b.md")]
    assert {event for event in events[2:]} == {("exec", "a.md"), ("exec", "b.md")}


@pytest.mark.parametrize("pool_name", ("breadth", "rescan"))
def test_pty_retry_round_uses_same_attempt_for_prebind_and_leaf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pool_name: str,
) -> None:
    phase = _phase(pool_name)
    config = {**_config(tmp_path, "claude"), "pty_continuation_budget": 1}
    job = {
        "agent_id": "A",
        "role": "rescan" if pool_name == "rescan" else "general",
        "output": "a.md",
    }
    bound: list[int] = []
    launched: list[int] = []
    gate_calls = 0

    def prepare(**kwargs):
        bound.append(int(kwargs["attempt"]))
        return []

    def execute(**kwargs):
        attempt = int(kwargs["attempt"])
        launched.append(attempt)
        return {
            "output": "a.md",
            "rc": 0 if attempt == 2 else -2,
            "status": "complete" if attempt == 2 else "incomplete",
            "reasons": [],
        }

    def gate(*_args, **_kwargs):
        nonlocal gate_calls
        gate_calls += 1
        return (gate_calls >= 2, [] if gate_calls >= 2 else ["retry"])

    plan = [{"job": dict(job), "prompt": "prompt"}]
    monkeypatch.setattr(D, "_prepare_typed_model_worker_launch", prepare)
    monkeypatch.setattr(D, "gate_passes", gate)
    monkeypatch.setattr(D.display, "print_phase_heartbeat", lambda *_a, **_k: None)
    monkeypatch.setattr(D.display, "spin", lambda *_a, **_k: None)
    common = dict(
        scratchpad=tmp_path,
        project_root=str(tmp_path),
        config=config,
        phase=phase,
        base_cmd=[],
        env={},
        timeout=120,
        quiescence_s=0.1,
        attempt=1,
    )
    if pool_name == "breadth":
        monkeypatch.setattr(D, "_breadth_dispatch_plan", lambda **_k: plan)
        monkeypatch.setattr(D, "_breadth_open_jobs", lambda *_a, **_k: [job])
        monkeypatch.setattr(D, "_write_breadth_dispatch_contract", lambda *_a, **_k: None)
        monkeypatch.setattr(D, "_run_single_breadth_worker_pty", execute)
        rc = D._run_breadth_worker_pool_pty_core(**common)
    else:
        monkeypatch.setattr(D, "_rescan_worker_jobs", lambda *_a, **_k: [job])
        monkeypatch.setattr(D, "_rescan_open_jobs", lambda *_a, **_k: [job])
        monkeypatch.setattr(D, "_rescan_dispatch_plan", lambda **_k: plan)
        monkeypatch.setattr(D, "_write_rescan_dispatch_contract", lambda *_a, **_k: None)
        monkeypatch.setattr(D, "_rescan_worker_pool_progress_status", lambda *_a, **_k: "ok")
        monkeypatch.setattr(D, "_run_single_rescan_worker_pty", execute)
        rc = D._run_rescan_worker_pool_pty(**common)

    assert rc == 0
    assert bound == [1, 2]
    assert launched == [1, 2]


def test_headless_breadth_retry_prebind_and_postcommit_use_round_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase = _phase("breadth")
    config = _config(tmp_path, "claude")
    job = {"agent_id": "B1", "role": "general", "output": "a.md"}
    plan = [{"job": dict(job), "prompt": "prompt"}]
    bound: list[int] = []
    launched: list[int] = []
    committed: list[int] = []

    def prepare(**kwargs):
        bound.append(int(kwargs["attempt"]))
        return []

    def execute(**kwargs):
        launched.append(int(kwargs["attempt"]))
        return 0

    def record(**kwargs):
        committed.append(int(kwargs["attempt"]))
        return []

    monkeypatch.setattr(D, "_breadth_dispatch_plan", lambda **_k: plan)
    monkeypatch.setattr(D, "_breadth_open_jobs", lambda *_a, **_k: [job])
    monkeypatch.setattr(D, "_write_breadth_dispatch_contract", lambda *_a, **_k: None)
    monkeypatch.setattr(D, "_prepare_typed_model_worker_launch", prepare)
    monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", execute)
    monkeypatch.setattr(D, "_record_typed_model_worker_artifact", record)
    monkeypatch.setattr(
        D,
        "compute_breadth_row_statuses",
        lambda *_a, **_k: [{
            "name": "a.md",
            "status": "complete" if launched and launched[-1] == 2 else "missing",
        }],
    )
    monkeypatch.setattr(
        D, "gate_passes", lambda *_a, **_k: (launched[-1] == 2, ["retry"])
    )
    assert D._run_breadth_backend_fanout(
        backend="claude-headless",
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=1,
        timeout=120,
        effective_model="model",
    ) == 0
    assert bound == [1, 2]
    assert launched == [1, 2]
    assert committed == [2]


def test_headless_breadth_outer_retry_uses_disjoint_worker_attempts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Outer attempt 2 must not reuse outer attempt 1's snapshot attempt 2."""

    phase = _phase("breadth")
    config = _config(tmp_path, "claude")
    job = {"agent_id": "B1", "role": "general", "output": "a.md"}
    launched: list[int] = []
    invocation_start = 0

    def dispatch_plan(**kwargs):
        worker_attempt = int(kwargs["attempt"])
        retry_reasons = kwargs["retry_reasons_by_output"]
        return [{
            "job": dict(job),
            "prompt": (
                f"prompt attempt={worker_attempt} "
                f"retry={bool(retry_reasons)}"
            ),
        }]

    monkeypatch.setattr(D, "_breadth_dispatch_plan", dispatch_plan)
    monkeypatch.setattr(D, "_breadth_open_jobs", lambda *_a, **_k: [job])
    monkeypatch.setattr(D, "_write_breadth_dispatch_contract", lambda *_a, **_k: None)
    monkeypatch.setattr(D, "_prepare_typed_model_worker_launch", lambda **_k: [])

    def execute(**kwargs):
        worker_attempt = int(kwargs["attempt"])
        prompt_bytes = str(kwargs["prompt"]).encode("utf-8")
        snapshot = tmp_path / (
            f"_prompt_breadth_worker_B1.attempt{worker_attempt}.md"
        )
        if snapshot.exists():
            assert snapshot.read_bytes() == prompt_bytes, (
                "test fixture observed the production snapshot collision"
            )
        else:
            snapshot.write_bytes(prompt_bytes)
        launched.append(worker_attempt)
        return 0

    monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", execute)
    monkeypatch.setattr(D, "_record_typed_model_worker_artifact", lambda **_k: [])

    def row_status(*_args, **_kwargs):
        rounds_this_invocation = launched[invocation_start:]
        return [{
            "name": "a.md",
            "status": "complete" if len(rounds_this_invocation) == 2 else "missing",
        }]

    monkeypatch.setattr(D, "compute_breadth_row_statuses", row_status)
    monkeypatch.setattr(
        D,
        "gate_passes",
        lambda *_a, **_k: (
            len(launched[invocation_start:]) == 2,
            ["retry"],
        ),
    )

    assert D._run_breadth_backend_fanout(
        backend="claude-headless",
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=1,
        timeout=120,
        effective_model="model",
    ) == 0
    assert launched == [1, 2]
    attempt_two_snapshot = tmp_path / "_prompt_breadth_worker_B1.attempt2.md"
    attempt_two_bytes = attempt_two_snapshot.read_bytes()
    assert b"attempt=2" in attempt_two_bytes
    assert b"retry=True" in attempt_two_bytes

    invocation_start = len(launched)
    assert D._run_breadth_backend_fanout(
        backend="claude-headless",
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=2,
        timeout=120,
        effective_model="model",
    ) == 0
    assert launched == [1, 2, 3, 4]
    assert set(launched[:2]).isdisjoint(launched[2:])
    assert attempt_two_snapshot.read_bytes() == attempt_two_bytes
    assert attempt_two_snapshot.stat().st_size > 0


@pytest.mark.parametrize("backend", ("codex", "claude-headless"))
def test_serial_breadth_drift_blocks_before_backend_invocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: str,
) -> None:
    phase = _phase("breadth")
    job = {"agent_id": "B1", "output": "breadth_out.md"}
    monkeypatch.setattr(
        D, "_breadth_dispatch_plan",
        lambda **_k: [{"job": job, "prompt": "prompt"}],
    )
    monkeypatch.setattr(D, "_breadth_open_jobs", lambda *_a, **_k: [job])
    monkeypatch.setattr(D, "_write_breadth_dispatch_contract", lambda *_a, **_k: None)
    monkeypatch.setattr(
        D, "_prepare_typed_model_worker_launch",
        lambda **_k: ["model prelaunch input drift"],
    )
    monkeypatch.setattr(
        D, "_run_one_codex_exec",
        lambda **_k: pytest.fail("Codex launched after input drift"),
    )
    monkeypatch.setattr(
        D, "_run_one_claude_headless_breadth_worker",
        lambda **_k: pytest.fail("Claude launched after input drift"),
    )
    assert D._run_breadth_backend_fanout(
        backend=backend,
        phase=phase,
        config=_config(tmp_path, backend),
        scratchpad=tmp_path,
        attempt=1,
        timeout=120,
        effective_model="model",
    ) == -2


@pytest.mark.parametrize("backend", ("codex", "claude"))
@pytest.mark.parametrize("drift", (False, True))
def test_methodology_repair_binds_before_launch_and_drift_suppresses_producer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
    drift: bool,
) -> None:
    phase = _phase("breadth")
    events: list[str] = []
    result = {"status": "GAPS", "dispatch_sha256": "d" * 64, "rows": []}
    plan = {
        "job": {"agent_id": "methodology_repair", "output": "breadth_repair.md"},
        "prompt": "repair",
        "entry": {
            "source_phase": "breadth",
            "prompt_sha256": "p" * 64,
        },
    }
    monkeypatch.setattr(D, "_methodology_application_mode", lambda _c: "repair")
    monkeypatch.setattr(D, "validate_phase_application", lambda *_a, **_k: result)
    monkeypatch.setattr(D, "_build_methodology_repair_plan", lambda **_k: plan)
    monkeypatch.setattr(D, "write_phase_dispatch", lambda *_a, **_k: {})
    monkeypatch.setattr(D, "write_human_review_projection", lambda *_a, **_k: None)

    def prepare(**_kwargs):
        events.append("bind")
        return ["model prelaunch input drift"] if drift else []

    def produce(**_kwargs):
        events.append("exec")
        return 0

    monkeypatch.setattr(D, "_prepare_typed_model_worker_launch", prepare)
    monkeypatch.setattr(D, "_run_methodology_repair_producer", produce)
    monkeypatch.setattr(D, "_record_typed_model_worker_artifact", lambda **_k: [])
    D._run_methodology_application_boundary(
        phase,
        {**_config(tmp_path, backend), "methodology_application_mode": "repair"},
        tmp_path,
        source_phase="breadth",
    )
    assert events == (["bind"] if drift else ["bind", "exec"])


def test_legacy_depth_without_typed_post_state_remains_legacy_resumable(
    tmp_path: Path,
) -> None:
    phase = D.Phase("depth", [], [], base_timeout_s=120)
    assert D._resume_phase_contract_issues(
        tmp_path, str(tmp_path), phase,
        "thorough", "evm", "sc", "claude",
    ) == []
