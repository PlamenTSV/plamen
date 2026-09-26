"""POSIX compatibility execution contracts for severity adjudication.

The child in this module is a deterministic transport double, not a model and
not semantic audit evidence.  The tests exercise the real reduced-isolation
compatibility session, private output routing, semantic admission, and durable
MODEL incorporation.  Native WER coverage remains in the AG3/AG4 suites.

The severity plan is prepared directly because the current batch has not yet
migrated that deterministic planning ancestry into PhaseIO.  No test in this
module treats the raw preparation step as typed producer ancestry.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from artifact_ledger import ArtifactLedgerError, read_artifact_ledger
import plamen_driver as driver
import posix_v2_compat_runtime as compat
from rooted_path_io import DurableWriteOnceDebtError
import severity_adjudication_work as work
import severity_compat_authority as authority
import severity_compat_runtime as runtime
from test_severity_adjudication_work_p0_ag3 import (
    _adjudication_proposal,
    _decision,
    _write_state,
)
import test_live_verify_queue_main_boundary_a0 as QUEUE
import test_verification_report_tail_same_run_integration as TAIL
from test_support_startup_permit import durable_startup_permit
from verify_queue_transaction import validate_live_verify_queue_publication
from worker_execution_receipts import environment_allowlist_sha256


# The authentic source-decision fixture binds this run identity internally.
RUN_ID = "33333333-4444-4555-8666-777777777777"
OTHER_RUN_ID = "9e414f09-a441-4140-bfc9-983ae3528432"
CANDIDATE_ID = "H-COMPAT-SEVERITY"
AUDIT_DIGEST = "a" * 64
CONFIG_DIGEST = "b" * 64
MODEL = "gpt-5.6-sol"


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


def _fake_codex(
    path: Path,
    *,
    proposals: dict[str, bytes],
    counter: Path,
) -> Path:
    encoded = {
        name: base64.b64encode(raw).decode("ascii")
        for name, raw in proposals.items()
    }
    path.write_text(
        f"#!{sys.executable} -B\n"
        "import base64,json,re,sys\n"
        "from pathlib import Path\n"
        "if sys.argv[1:] == ['--version']:\n"
        " print('codex-cli severity-compat-fixture'); raise SystemExit(0)\n"
        f"counter=Path({os.fspath(counter)!r})\n"
        "prior=int(counter.read_text(encoding='ascii')) if counter.exists() else 0\n"
        "counter.write_text(str(prior+1),encoding='ascii')\n"
        "prompt=sys.stdin.buffer.read().decode('utf-8',errors='strict')\n"
        f"sys.stderr.write('OpenAI Codex v0.test\\n--------\\nworkdir: /fixture\\nmodel: {MODEL}\\nprovider: openai\\n--------\\nuser\\n')\n"
        "blocks=[json.loads(raw) for raw in re.findall(r'```json\\s*(.*?)\\s*```',prompt,re.S)]\n"
        "routing=next(row for row in blocks if row.get('schema')=='plamen.posix_v2_codex_local_phaseio.v1')\n"
        f"payloads={encoded!r}\n"
        "for route in routing['output_routes']:\n"
        " name=Path(route['canonical_path']).name\n"
        " if name not in payloads: raise SystemExit(8)\n"
        " target=Path(route['path']); target.parent.mkdir(parents=True,exist_ok=True)\n"
        " target.write_bytes(base64.b64decode(payloads[name]))\n"
        "Path(sys.argv[sys.argv.index('-o')+1]).write_text('complete\\n',encoding='utf-8')\n"
        "print(json.dumps({'type':'turn.completed'},sort_keys=True))\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def _prepared_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
    *,
    malformed: bool = False,
) -> tuple[Path, Path, dict[str, Any], dict[str, Any], object, Path]:
    if os.name != "posix":
        pytest.skip("real-child fixture requires POSIX compatibility")
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    (project / "Unit.sol").write_text(
        "pragma solidity ^0.8.20; contract Unit {}\n",
        encoding="utf-8",
    )
    _write_state(scratchpad, [_decision(CANDIDATE_ID)])
    methodology = tmp_path / "severity-methodology.md"
    methodology.write_text(
        "# Direction-neutral severity adjudication\n", encoding="utf-8"
    )
    plan = work.prepare_adjudication_work(
        scratchpad,
        run_id=RUN_ID,
        audit_snapshot_digest=AUDIT_DIGEST,
        audit_config_digest=CONFIG_DIGEST,
        methodology_files={"severity-methodology": methodology},
        backend="codex",
        transport=authority.COMPAT_TRANSPORT,
        effective_model=MODEL,
        working_directory=scratchpad,
        source_root=project,
        tool_policy=(
            "read-bound-inputs-and-source",
            "write-assigned-staging-only",
            "no-shell-network-or-subagents",
        ),
        environment_allowlist_digest=environment_allowlist_sha256(()),
        adjudicator_identity="independent-severity-adjudicator",
        invocation_prefix="severity-compat-test",
        timeout_seconds_per_worker=30,
    )
    assert len(plan["shards"]) == 1
    shard = plan["shards"][0]
    proposal = {} if malformed else _adjudication_proposal(CANDIDATE_ID)
    output_name = shard["expected_outputs"][CANDIDATE_ID]
    counter = tmp_path / "codex-invocations"
    binary = _fake_codex(
        tmp_path / "codex",
        proposals={output_name: _canonical_json(proposal)},
        counter=counter,
    )
    session = compat.issue_posix_v2_compat_session_for_installed_front(
        run_id=RUN_ID,
        project_root=project,
        scratchpad=scratchpad,
    )
    def close_session() -> None:
        try:
            session.close()
        except Exception:
            # A cold-replay case deliberately closes it before finalization.
            pass

    request.addfinalizer(close_session)
    # Replace only the compatibility runtime's lookup namespace.  Patching
    # ``shutil.which`` on the shared stdlib module would also alter the live
    # audit-snapshot toolchain census and correctly trigger input drift.
    TAIL._patch_compat_codex_lookup(monkeypatch, binary)
    monkeypatch.setattr(
        compat,
        "_load_ambient_codex_auth",
        lambda: (
            "PRIVATE_AUTH_JSON_COPY",
            b'{"tokens":{}}\n',
            "c" * 64,
        ),
    )
    config = {
        "pipeline": "sc",
        "mode": "core",
        "language": "evm",
        "cli_backend": "codex",
        "project_root": str(project.resolve()),
        "scratchpad": str(scratchpad.resolve()),
        "_run_id": RUN_ID,
        "_audit_snapshot": {
            "snapshot_digest": AUDIT_DIGEST,
            "components": {"audit_config": {"digest": CONFIG_DIGEST}},
        },
        "_auxiliary_writable_root_startup_binding": durable_startup_permit(
            scratchpad, run_id=RUN_ID
        ),
        "severity_adjudication_environment": {},
        "severity_adjudication_environment_allowlist": (),
        "severity_adjudication_timeout_s": 30.0,
    }
    return project, scratchpad, config, shard, session, counter


def _driver_methodology_home(tmp_path: Path) -> Path:
    home = tmp_path / "plamen-home"
    for relative in (
        "rules/finding-output-format.md",
        "rules/phase5-poc-execution.md",
        "rules/report-template.md",
    ):
        path = home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {path.stem}\n", encoding="utf-8")
    return home


def _attempted_fixture_verifier_bytes(work_id: str) -> bytes:
    """Describe the bounded source-read attempt executed by this fixture.

    This is transaction-shape evidence only.  It does not claim a security
    finding, exploit, or production PoC authority.
    """

    return (
        f"# Verification: {work_id}\n\n"
        f"**Finding ID**: {work_id}\n\n"
        "**Severity**: Low\n\n"
        "**Verdict**: CONTESTED\n\n"
        "**Location**: `src/Unit.sol:L1`\n\n"
        "**Evidence Tag**: [CODE-TRACE]\n\n"
        "The bounded fixture source-read attempt completed, but it does not "
        "establish executable harm. The external premise remains unproven. "
        "[EXTERNAL-ASSUMPTION: fixture condition]\n\n"
        "**PoC Class**: structural\n\n"
        "### PoC Attempt\n"
        "- PoC Required: YES\n"
        "- Attempted: YES\n"
        "- Test File: `src/Unit.sol`\n"
        "- Command: `fixture-python-read src/Unit.sol`\n\n"
        "### Execution Result\n"
        "- Compiled: YES\n"
        "- Result: PASS\n"
    ).encode("utf-8")


def test_fixture_startup_permit_keeps_provider_runtime_outside_audit_target(
    tmp_path: Path,
) -> None:
    project = tmp_path / "audit-target"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)

    durable_startup_permit(scratchpad)

    assert not list(project.glob(".fixture-aux-runtime-*"))
    assert list(tmp_path.glob(".fixture-aux-runtime-audit-target-.scratchpad"))


def _unresolved_adjudication_proposal() -> dict[str, Any]:
    """Retain source uncertainty without inventing resolution evidence."""

    return {
        "schema_version": "plamen.severity_adjudication_proposal.v1",
        "decision": "UNRESOLVED",
        "resolved_severity": None,
        "resolved_premise_ids": [],
        "evidence_ids": [],
        "proof_scope": None,
        "rationale": (
            "The compatibility transaction fixture supplies no independent "
            "evidence capable of resolving the retained external premise."
        ),
        "resolved_axes": None,
        "constituent_resolutions": {},
    }


def _run(
    scratchpad: Path,
    config: dict[str, Any],
    shard: dict[str, Any],
    session: object,
) -> dict[str, Any]:
    return runtime.run_posix_compat_severity_worker(
        scratchpad,
        config=config,
        shard_id=str(shard["shard_id"]),
        session_authority=session,
    )


def test_real_compat_child_is_semantically_admitted_and_replays_without_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    project, root, config, shard, session, counter = _prepared_case(
        tmp_path, monkeypatch, request
    )
    worker_run = _run(root, config, shard, session)
    assert worker_run["schema_version"] == authority.COMPAT_WORKER_RUN_SCHEMA
    assert worker_run["authority_kind"] == "POSIX_V2_COMPAT_MODEL_PHASE_IO"
    assert counter.read_text(encoding="ascii") == "1"
    compat_receipt_path = root / worker_run[
        "compatibility_receipt_relative_path"
    ]
    compat_receipt = json.loads(
        compat_receipt_path.read_text(encoding="ascii")
    )
    assert compat_receipt["mode"] == "V2_COMPATIBILITY_REDUCED_ISOLATION"
    assert compat_receipt["status"] == "COMPLETED"
    assert compat_receipt["staged_output_validator_binding"][
        "input_identities"
    ] == sorted(
        [
            "scratchpad:severity_adjudication_work_plan.json",
            "scratchpad:severity_adjudication_work_manifest.json",
            f"scratchpad:{shard['launch_intent_file']}",
            f"scratchpad:{shard['context_file']}",
            f"scratchpad:{shard['prompt_file']}",
            f"scratchpad:{shard['tool_policy_file']}",
        ]
    )
    assert all(
        route["path"] != route["canonical_path"]
        for route in compat_receipt["phase_io_output_routes"]
    )
    output = root / shard["expected_outputs"][CANDIDATE_ID]
    assert work.severity_adjudication_output_digest(
        output, output.read_bytes()
    )
    before_output = output.read_bytes()
    before_ledger = (root / "_artifact_state.json").read_bytes()
    assert _run(root, config, shard, session) == worker_run
    assert counter.read_text(encoding="ascii") == "1"
    assert output.read_bytes() == before_output
    assert (root / "_artifact_state.json").read_bytes() == before_ledger
    contract, _launch = authority.severity_compat_contract_launch(
        root,
        shard_id=str(shard["shard_id"]),
        pipeline="sc",
        mode="core",
        ecosystem="evm",
    )
    model_unit = read_artifact_ledger(root)["work_units"][contract.key]
    assert model_unit["semantic_status"] == "ACTIVE"
    assert model_unit["execution_state"] == "OUTPUT_COMMITTED"
    execution = model_unit["execution_authority"]
    assert execution["schema"] == "plamen.worker_execution_authority.v1"
    assert execution["attempt_completion_relative_path"].startswith(
        ".worker_transactions/posix_v2_compat_severity/"
    )
    assert ".worker_transactions/" in execution[
        "attempt_completion_relative_path"
    ]
    assert not (root / ".worker_execution_receipts").exists()
    assert Path(config["project_root"]) == project.resolve()


def test_driver_reaches_compat_worker_bind_and_completed_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    if os.name != "posix":
        pytest.skip("real-child fixture requires POSIX compatibility")
    project = tmp_path / "driver-project"
    (project / "src").mkdir(parents=True)
    (project / "src" / "Unit.sol").write_text(
        "pragma solidity ^0.8.20; contract Unit {}\n", encoding="utf-8"
    )
    TAIL._install_supported_queue_seed(
        monkeypatch, severity="Low", mode="thorough",
    )
    root, config, run_id = QUEUE._seed(
        project,
        pipeline="sc",
        backend="codex",
        preseed_adapter_successors=False,
    )
    dependency = driver._ensure_recon_dependency_parity(
        root, str(project), config,
    )
    assert dependency["expected_ids"] == []
    assert driver._run_sc_semantic_dedup_noop(
        root, config, "compat severity fixture conservative preserve-all",
    ) == ["dedup_decisions.md", "findings_inventory_deduped.md"]
    queue_phase, phases = QUEUE._phase_and_graph("sc")
    checkpoint = QUEUE._checkpoint(root, config, run_id)
    queue_outcome = QUEUE._invoke(
        boundary=QUEUE._boundary(),
        phase=queue_phase,
        checkpoint=checkpoint,
        root=root,
        config=config,
        phases=phases,
    )
    assert queue_outcome["state"] == "COMMITTED", queue_outcome
    assert validate_live_verify_queue_publication(
        scratchpad=root,
        project_root=project,
        plan=queue_outcome["cutover_result"]["plan"],
        run_id=run_id,
    )["safe_to_consume"] is True
    attempt = subprocess.run(
        (
            sys.executable,
            "-B",
            "-c",
            (
                "from pathlib import Path; "
                "raw=Path('src/Unit.sol').read_bytes(); "
                "raise SystemExit(0 if b'contract Unit' in raw else 3)"
            ),
        ),
        cwd=project,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    assert attempt.returncode == 0
    assert attempt.stdout == attempt.stderr == b""
    monkeypatch.setattr(
        TAIL, "_low_verifier_bytes", _attempted_fixture_verifier_bytes,
    )
    TAIL._run_same_run_harmless_verifier(
        root=root,
        config=config,
        checkpoint=checkpoint,
        phases=phases,
        monkeypatch=monkeypatch,
    )
    candidate_ids = tuple(
        item.work_item_id
        for item in driver._read_typed_queue_work_items(
            root / "verification_queue.md"
        )
    )
    assert candidate_ids
    assert json.loads(
        (root / "verify_INV-1.severity_decision.json").read_text(
            encoding="utf-8"
        )
    )["candidate_id"] == "INV-1"
    counter = tmp_path / "driver-codex-invocations"
    binary = _fake_codex(
        tmp_path / "driver-codex",
        proposals={
            f"verify_{candidate_id}.severity_adjudication_proposal.json":
            _canonical_json(_unresolved_adjudication_proposal())
            for candidate_id in candidate_ids
        },
        counter=counter,
    )
    session = compat.issue_posix_v2_compat_session_for_installed_front(
        run_id=run_id, project_root=project, scratchpad=root
    )

    def close_session() -> None:
        try:
            session.close()
        except Exception:
            pass

    request.addfinalizer(close_session)
    # Replace only the compatibility runtime's lookup namespace.  Patching
    # ``shutil.which`` on the shared stdlib module would also alter the live
    # audit-snapshot toolchain census and correctly trigger input drift.
    TAIL._patch_compat_codex_lookup(monkeypatch, binary)
    monkeypatch.setattr(
        compat,
        "_load_ambient_codex_auth",
        lambda: (
            "PRIVATE_AUTH_JSON_COPY",
            b'{"tokens":{}}\n',
            "c" * 64,
        ),
    )
    monkeypatch.setattr(
        driver,
        "_POSIX_COMPAT_V2_PROCESS_MARKER",
        driver._POSIX_COMPAT_V2_MARKER_TOKEN,
    )
    monkeypatch.setattr(driver, "_POSIX_COMPAT_V2_SESSION_AUTHORITY", session)
    config["_auxiliary_writable_root_startup_binding"] = (
        durable_startup_permit(root, run_id=run_id)
    )
    phase = next(
        item
        for item in driver.SC_PHASES
        if item.name == "severity_adjudication_shadow"
    )
    reconciliation, issues = driver._run_severity_adjudication_shadow_phase(
        phase, config, root
    )
    expected_unresolved_issues = [
        f"{candidate_id} unresolved severity adjudication state "
        "COMPLETED_UNRESOLVED: independent adjudication retained "
        "unresolved severity"
        for candidate_id in candidate_ids
    ]
    assert issues == expected_unresolved_issues
    assert reconciliation["states"] == {
        candidate_id: "COMPLETED_UNRESOLVED"
        for candidate_id in candidate_ids
    }
    assert counter.read_text(encoding="ascii") == "1"
    plan = json.loads(
        (root / work.WORK_PLAN_NAME).read_text(encoding="utf-8")
    )
    assert plan["transport"] == authority.COMPAT_TRANSPORT
    worker_run_path = next(
        root.glob("severity_adjudication_worker_run.*.json")
    )
    worker_run = json.loads(worker_run_path.read_text(encoding="utf-8"))
    assert worker_run["schema_version"] == authority.COMPAT_WORKER_RUN_SCHEMA
    assert not (root / ".worker_execution_receipts").exists()
    replayed, replay_issues = driver._run_severity_adjudication_shadow_phase(
        phase, config, root
    )
    assert replay_issues == expected_unresolved_issues
    assert replayed == reconciliation
    assert counter.read_text(encoding="ascii") == "1"


def test_malformed_staged_proposal_never_publishes_or_commits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    _project, root, config, shard, session, counter = _prepared_case(
        tmp_path, monkeypatch, request, malformed=True
    )
    contract, _launch = authority.severity_compat_contract_launch(
        root,
        shard_id=str(shard["shard_id"]),
        pipeline="sc",
        mode="core",
        ecosystem="evm",
    )
    output = root / shard["expected_outputs"][CANDIDATE_ID]
    with pytest.raises(ArtifactLedgerError, match="worker failed"):
        _run(root, config, shard, session)
    assert counter.read_text(encoding="ascii") == "1"
    assert not output.exists()
    model_unit = read_artifact_ledger(root)["work_units"][contract.key]
    assert model_unit["semantic_status"] == "INPUTS_BOUND"
    assert model_unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert model_unit["artifacts"] == {}
    receipt = next((root / ".posix_v2_compat_receipts").glob("*.json"))
    payload = json.loads(receipt.read_text(encoding="ascii"))
    assert payload["status"] == "STAGED_SEMANTIC_REJECTED"
    assert payload["completed_output_evidence"] == []


def test_foreign_session_run_is_rejected_before_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    project, root, config, shard, session, counter = _prepared_case(
        tmp_path, monkeypatch, request
    )
    foreign = compat.issue_posix_v2_compat_session_for_installed_front(
        run_id=OTHER_RUN_ID,
        project_root=project,
        scratchpad=root,
    )
    request.addfinalizer(foreign.close)
    with pytest.raises(
        authority.SeverityCompatAuthorityError,
        match="registration is foreign",
    ):
        _run(root, config, shard, foreign)
    assert not counter.exists()
    assert not (root / shard["expected_outputs"][CANDIDATE_ID]).exists()
    assert session is not foreign


def test_false_terminal_model_state_never_authorizes_child_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    _project, root, config, shard, session, counter = _prepared_case(
        tmp_path, monkeypatch, request
    )

    class StopAfterArm(RuntimeError):
        pass

    def stop(point: str) -> None:
        if point == "after_arm":
            raise StopAfterArm(point)

    with pytest.raises(StopAfterArm, match="after_arm"):
        runtime.run_posix_compat_severity_worker(
            root,
            config=config,
            shard_id=str(shard["shard_id"]),
            session_authority=session,
            fault_hook=stop,
        )
    contract, _launch = authority.severity_compat_contract_launch(
        root,
        shard_id=str(shard["shard_id"]),
        pipeline="sc",
        mode="core",
        ecosystem="evm",
    )
    state_path = root / "_artifact_state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    unit = state["work_units"][contract.key]
    unit["semantic_status"] = "ACTIVE"
    unit["execution_state"] = "OUTPUT_COMMITTED"
    state_path.write_text(
        json.dumps(state, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="ascii",
    )
    with pytest.raises(authority.SeverityCompatAuthorityError):
        _run(root, config, shard, session)
    assert not counter.exists()
    assert not (root / shard["expected_outputs"][CANDIDATE_ID]).exists()


def test_compat_receipt_tamper_prevents_replay_without_relaunch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    _project, root, config, shard, session, counter = _prepared_case(
        tmp_path, monkeypatch, request
    )
    assert _run(root, config, shard, session)["completion_status"] == "COMPLETED"
    assert counter.read_text(encoding="ascii") == "1"
    receipt = next((root / ".posix_v2_compat_receipts").glob("*.json"))
    receipt.chmod(0o600)
    receipt.write_bytes(b"{}\n")
    with pytest.raises(authority.SeverityCompatAuthorityError):
        _run(root, config, shard, session)
    assert counter.read_text(encoding="ascii") == "1"


@pytest.mark.parametrize("fault_point", ("after_execution", "after_commit"))
def test_execution_or_commit_crash_replays_without_relaunch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
    fault_point: str,
) -> None:
    _project, root, config, shard, session, counter = _prepared_case(
        tmp_path, monkeypatch, request
    )

    class InjectedCrash(RuntimeError):
        pass

    fired: list[str] = []

    def crash(point: str) -> None:
        if point == fault_point:
            fired.append(point)
            raise InjectedCrash(point)

    with pytest.raises(InjectedCrash, match=fault_point):
        runtime.run_posix_compat_severity_worker(
            root,
            config=config,
            shard_id=str(shard["shard_id"]),
            session_authority=session,
            fault_hook=crash,
        )
    assert fired == [fault_point]
    assert counter.read_text(encoding="ascii") == "1"
    recovered = _run(root, config, shard, session)
    assert recovered["schema_version"] == authority.COMPAT_WORKER_RUN_SCHEMA
    assert counter.read_text(encoding="ascii") == "1"


@pytest.mark.skipif(
    sys.platform != "darwin",
    reason="Darwin retained write-once quarantine semantics",
)
def test_deleted_write_once_worker_run_is_rejected_without_relaunch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    _project, root, config, shard, session, counter = _prepared_case(
        tmp_path, monkeypatch, request
    )
    _run(root, config, shard, session)
    worker_paths = list(root.glob("severity_adjudication_worker_run.*.json"))
    assert len(worker_paths) == 1
    worker_path = worker_paths[0]
    worker_path.unlink()
    with pytest.raises(
        DurableWriteOnceDebtError,
        match="DARWIN_ORPHANED_QUARANTINE_PRESERVED",
    ):
        _run(root, config, shard, session)
    assert counter.read_text(encoding="ascii") == "1"


def test_model_commit_before_worker_run_publication_recovers_without_relaunch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    _project, root, config, shard, session, counter = _prepared_case(
        tmp_path, monkeypatch, request
    )
    original_publish = authority._publish_exact
    fired: list[str] = []

    class StopBeforeWorkerRun(RuntimeError):
        pass

    def stop_worker_run(path: Path, raw: bytes, atomic_write) -> None:
        if path.name.startswith("severity_adjudication_worker_run."):
            fired.append(path.name)
            raise StopBeforeWorkerRun(path.name)
        original_publish(path, raw, atomic_write)

    monkeypatch.setattr(authority, "_publish_exact", stop_worker_run)
    with pytest.raises(StopBeforeWorkerRun):
        _run(root, config, shard, session)
    assert len(fired) == 1
    assert counter.read_text(encoding="ascii") == "1"
    assert not list(root.glob("severity_adjudication_worker_run.*.json"))
    monkeypatch.setattr(authority, "_publish_exact", original_publish)
    recovered = _run(root, config, shard, session)
    assert recovered["schema_version"] == authority.COMPAT_WORKER_RUN_SCHEMA
    assert len(list(root.glob("severity_adjudication_worker_run.*.json"))) == 1
    assert counter.read_text(encoding="ascii") == "1"


def test_fresh_same_run_session_cannot_replace_historical_session_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    project, root, config, shard, session, counter = _prepared_case(
        tmp_path, monkeypatch, request
    )
    worker_run = _run(root, config, shard, session)
    ledger_before = (root / "_artifact_state.json").read_bytes()
    worker_path = next(
        root.glob("severity_adjudication_worker_run.*.json")
    )
    worker_before = worker_path.read_bytes()
    fresh = compat.issue_posix_v2_compat_session_for_installed_front(
        run_id=RUN_ID,
        project_root=project,
        scratchpad=root,
    )
    request.addfinalizer(fresh.close)
    with pytest.raises(
        authority.SeverityCompatAuthorityError,
        match="registration collision",
    ):
        _run(root, config, shard, fresh)
    assert worker_run["session_binding_sha256"]
    assert worker_path.read_bytes() == worker_before
    assert (root / "_artifact_state.json").read_bytes() == ledger_before
    assert counter.read_text(encoding="ascii") == "1"


def test_cold_same_run_session_replays_historical_commit_without_relaunch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    project, root, config, shard, session, counter = _prepared_case(
        tmp_path, monkeypatch, request
    )
    worker_run = _run(root, config, shard, session)
    worker_path = next(root.glob("severity_adjudication_worker_run.*.json"))
    ledger_before = (root / "_artifact_state.json").read_bytes()
    worker_before = worker_path.read_bytes()
    session.close()
    child = """
import json
from pathlib import Path
import sys
sys.path.insert(0, sys.argv[1])
import posix_v2_compat_runtime as compat
import severity_compat_runtime as runtime
root = Path(sys.argv[2])
project = Path(sys.argv[3])
run_id = sys.argv[4]
shard_id = sys.argv[5]
session = compat.issue_posix_v2_compat_session_for_installed_front(
    run_id=run_id, project_root=project, scratchpad=root,
)
try:
    result = runtime.run_posix_compat_severity_worker(
        root,
        config={
            "pipeline": "sc", "mode": "core", "language": "evm",
            "cli_backend": "codex", "project_root": str(project.resolve()),
            "scratchpad": str(root.resolve()), "_run_id": run_id,
        },
        shard_id=shard_id,
        session_authority=session,
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
finally:
    session.close()
"""
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            child,
            str(Path(__file__).resolve().parent),
            str(root),
            str(project),
            RUN_ID,
            str(shard["shard_id"]),
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == worker_run
    assert worker_path.read_bytes() == worker_before
    assert (root / "_artifact_state.json").read_bytes() == ledger_before
    assert counter.read_text(encoding="ascii") == "1"


def test_post_execution_foreign_mutation_blocks_model_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    project, root, config, shard, session, counter = _prepared_case(
        tmp_path, monkeypatch, request
    )

    def mutate(point: str) -> None:
        if point == "after_execution":
            (project / "foreign-child-mutation.txt").write_text(
                "not an assigned severity output\n", encoding="utf-8"
            )

    with pytest.raises(ArtifactLedgerError, match="containment violation"):
        runtime.run_posix_compat_severity_worker(
            root,
            config=config,
            shard_id=str(shard["shard_id"]),
            session_authority=session,
            fault_hook=mutate,
        )
    assert counter.read_text(encoding="ascii") == "1"
    contract, _launch = authority.severity_compat_contract_launch(
        root,
        shard_id=str(shard["shard_id"]),
        pipeline="sc",
        mode="core",
        ecosystem="evm",
    )
    unit = read_artifact_ledger(root)["work_units"][contract.key]
    assert unit["semantic_status"] == "INPUTS_BOUND"
    assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert not list(root.glob("severity_adjudication_worker_run.*.json"))
