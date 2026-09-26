"""Dynamic verifier backends require process authority before MODEL commit.

The positive fixture deliberately traverses the installed-front POSIX V2
compatibility adapter and launches a harmless fake ``codex`` executable.  It
does not manufacture a compatibility receipt or a worker execution authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest

from artifact_ledger import read_artifact_ledger, record_work_unit_inputs
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
import plamen_driver as D
from verifier_work_roster import VerifierLaunchSpec


_RUN_ID = "run-dynamic-verifier-authority"
_PHASE = "sc_verify_crithigh"
_MODEL = "gpt-5.4"
_REFUSAL = (
    "ERROR: This content was flagged for possible cybersecurity risk. "
    "If this seems wrong, try rephrasing your request. To get authorized "
    "for security work, join the Trusted Access for Cyber program: "
    "https://chatgpt.com/cyber\n"
)


@dataclass(frozen=True)
class _Case:
    project: Path
    scratchpad: Path
    prompt_path: Path
    log_path: Path
    config: dict[str, Any]
    execution_config: D._DriverConfig
    phase: Any
    spec: VerifierLaunchSpec
    contract: PhaseIOContract
    launch: LaunchSpec


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _build_case(tmp_path: Path) -> _Case:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    (scratchpad / "verification-input.md").write_text(
        "bounded verifier input\n", encoding="utf-8"
    )
    prompt = b"Review the bounded fixture and write the assigned output.\n"
    prompt_path = scratchpad / "verifier-prompt.md"
    prompt_path.write_bytes(prompt)

    work_unit_id = "method_model.verify-fixture"
    key = canonical_work_unit_key(
        "sc", "thorough", "evm", "codex", _PHASE, work_unit_id
    )
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        phase=_PHASE,
        work_unit_id=work_unit_id,
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path="verify-FIXTURE.md",
                owner_key=key,
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="CREATE",
            ),
        ),
        immutable_inputs=("scratchpad:verification-input.md",),
        required_commit_actor="MODEL",
    )
    launch = LaunchSpec(
        work_unit_key=key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        model=_MODEL,
        timeout_s=15,
        exec_mode="exec",
        tool_policy=("filesystem", "shell", "foreground-only"),
    )
    config: dict[str, Any] = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
        "project_root": str(project.resolve()),
        "_run_id": _RUN_ID,
    }
    record_work_unit_inputs(
        scratchpad, project, contract, launch, run_id=_RUN_ID
    )
    spec = VerifierLaunchSpec(
        work_unit_id="verify-fixture",
        work_unit_resume_digest="a" * 64,
        backend="codex",
        model=_MODEL,
        transport="exec",
        argv=("codex", "exec", "--model", _MODEL, "-"),
        cwd=str(scratchpad.resolve()),
        timeout_seconds=15,
        prompt_sha256=_sha(prompt),
        prompt_size_bytes=len(prompt),
        expected_output_files=("verify-FIXTURE.md",),
        tool_policy_digest="b" * 64,
        foreground_only=True,
        background_children_allowed=False,
        child_join_policy="REQUIRE_JOIN_BEFORE_RECEIPT",
        process_group_policy="ISOLATED_PROCESS_GROUP",
        orphan_policy="TERMINATE_TREE_AND_RETAIN_DEBT",
    )
    native_authority = object()
    return _Case(
        project=project,
        scratchpad=scratchpad,
        prompt_path=prompt_path,
        log_path=scratchpad / "dynamic-verifier.log",
        config=config,
        execution_config=D._DriverConfig(
            config,
            native_guest_runtime_authorities=native_authority,
        ),
        phase=SimpleNamespace(name=_PHASE, needs_mcp=False),
        spec=spec,
        contract=contract,
        launch=launch,
    )


def _fake_codex(
    path: Path,
    counter_path: Path,
    *,
    returncode: int = 0,
    refusal: bool = False,
) -> Path:
    """Create a harmless executable; non-version invocations are counted."""

    refusal_write = (
        f"sys.stderr.write({_REFUSAL!r})"
        if refusal
        else "pass"
    )
    success = "" if returncode else """
blocks = re.findall(r"```json\\n(.*?)\\n```", prompt.decode("utf-8"), re.S)
route = json.loads(blocks[-1])["output_routes"][0]
destination = Path(route["path"])
destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_text("# MODEL verifier fixture\\n", encoding="utf-8")
Path(sys.argv[sys.argv.index("-o") + 1]).write_bytes(b"fixture complete\\n")
print(json.dumps({"type": "turn.completed"}, sort_keys=True))
"""
    path.write_text(
        "#!" + __import__("sys").executable + "\n"
        + f"""import json
from pathlib import Path
import re
import sys

if sys.argv[1:] == ["--version"]:
    print("codex-cli 0.test")
    raise SystemExit(0)
counter = Path({str(counter_path)!r})
count = int(counter.read_text(encoding="ascii")) if counter.exists() else 0
counter.write_text(str(count + 1), encoding="ascii")
sys.stderr.write("OpenAI Codex v0.test\\n--------\\nworkdir: /fixture\\nmodel: {_MODEL}\\nprovider: openai\\n--------\\nuser\\n")
prompt = sys.stdin.buffer.read()
{refusal_write}
{success}
raise SystemExit({returncode})
""",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def _compat_runtime():
    if os.name != "posix":
        pytest.skip("real-child fixture requires the POSIX compatibility runtime")
    import posix_v2_compat_runtime as compat

    return compat


def _activate_compat(
    monkeypatch: pytest.MonkeyPatch,
    *,
    session: object,
    binary: Path,
) -> None:
    compat = _compat_runtime()
    monkeypatch.setattr(
        D, "_POSIX_COMPAT_V2_PROCESS_MARKER", D._POSIX_COMPAT_V2_MARKER_TOKEN
    )
    monkeypatch.setattr(D, "_POSIX_COMPAT_V2_SESSION_AUTHORITY", session)
    monkeypatch.setattr(compat.shutil, "which", lambda _name: str(binary))
    monkeypatch.setattr(
        compat,
        "_load_ambient_codex_auth",
        lambda: ("PRIVATE_AUTH_JSON_COPY", b'{"tokens":{}}\n', "c" * 64),
    )
    monkeypatch.setattr(
        D, "_dynamic_verifier_method_digest", lambda _config: "d" * 64
    )
    monkeypatch.setattr(
        D,
        "_security_obligation_source_snapshot_digest",
        lambda _config: "e" * 64,
    )


def _execute_case(
    case: _Case,
) -> tuple[int, tuple[dict[str, Any], dict[str, Any]] | None]:
    """Invoke the production execute/replay entry with its two config views."""

    return D._execute_or_replay_dynamic_verifier_model(
        case.spec,
        prompt_path=case.prompt_path,
        log_path=case.log_path,
        scratchpad=case.scratchpad,
        phase=case.phase,
        config=case.config,
        execution_config=case.execution_config,
        model_io_contract=case.contract,
        model_io_launch=case.launch,
    )


def _issue_session(case: _Case, *, run_id: str = _RUN_ID):
    compat = _compat_runtime()
    return compat.issue_posix_v2_compat_session_for_installed_front(
        run_id=run_id,
        project_root=case.project,
        scratchpad=case.scratchpad,
    )


def test_genuine_compat_child_commits_model_authority_and_new_handle_replays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _build_case(tmp_path)
    counter = tmp_path / "provider-count"
    binary = _fake_codex(tmp_path / "codex", counter)
    first_session = _issue_session(case)
    try:
        _activate_compat(
            monkeypatch, session=first_session, binary=binary
        )
        rc, committed = _execute_case(case)
        assert rc == 0
        assert committed is not None
        execution_authority, commit_authority = committed
        assert counter.read_text(encoding="ascii") == "1"

        unit = read_artifact_ledger(case.scratchpad)["work_units"][
            case.contract.key
        ]
        assert unit["semantic_status"] == "ACTIVE"
        assert unit["execution_state"] == "OUTPUT_COMMITTED"
        assert unit["execution_authority"] == execution_authority
        assert unit["commit_authority"]["actor"] == "MODEL"
        assert execution_authority["schema"] == (
            "plamen.worker_execution_authority.v1"
        )
        assert commit_authority["schema"] == (
            "plamen.posix_v2_compat_dynamic_verifier_plan.v1"
        )
        # This authority proves one MODEL process/output transaction only.  It
        # is deliberately not a PoC result or a VERIFIED finding verdict.
        forbidden_verification_claims = {
            "poc_receipt",
            "proof_grade",
            "verdict",
            "verification_status",
            "verified",
        }
        assert forbidden_verification_claims.isdisjoint(execution_authority)
        assert forbidden_verification_claims.isdisjoint(commit_authority)
    finally:
        first_session.close()

    fresh_session = _issue_session(case)
    try:
        monkeypatch.setattr(D, "_POSIX_COMPAT_V2_SESSION_AUTHORITY", fresh_session)
        monkeypatch.setattr(
            _compat_runtime().shutil,
            "which",
            lambda _name: (_ for _ in ()).throw(
                AssertionError("committed MODEL authority relaunched Codex")
            ),
        )
        replay_rc, replayed = _execute_case(case)
        assert replay_rc == 0
        assert replayed == committed
        assert counter.read_text(encoding="ascii") == "1"
    finally:
        fresh_session.close()


def test_fresh_interpreter_replays_historical_session_without_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _build_case(tmp_path)
    counter = tmp_path / "provider-count"
    binary = _fake_codex(tmp_path / "codex", counter)
    first_session = _issue_session(case)
    try:
        _activate_compat(
            monkeypatch, session=first_session, binary=binary
        )
        rc, committed = _execute_case(case)
        assert rc == 0 and committed is not None
        historical_binding = str(
            first_session.binding["session_binding_sha256"]
        )
    finally:
        first_session.close()

    execution_authority, commit_authority = committed
    child = tmp_path / "replay-in-fresh-interpreter.py"
    child.write_text(
        f"""from __future__ import annotations
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from phase_io_contracts import ArtifactSpec, LaunchSpec, PhaseIOContract, canonical_work_unit_key
import plamen_driver as D
import posix_v2_compat_runtime as compat
from verifier_work_roster import VerifierLaunchSpec

project = Path({str(case.project)!r})
scratchpad = Path({str(case.scratchpad)!r})
prompt_path = Path({str(case.prompt_path)!r})
prompt = prompt_path.read_bytes()
work_unit_id = "method_model.verify-fixture"
key = canonical_work_unit_key("sc", "thorough", "evm", "codex", {_PHASE!r}, work_unit_id)
contract = PhaseIOContract(
    pipeline="sc", mode="thorough", ecosystem="evm", backend="codex",
    phase={_PHASE!r}, work_unit_id=work_unit_id,
    outputs=(ArtifactSpec(
        root="scratchpad", path="verify-FIXTURE.md", owner_key=key,
        artifact_class="REQUIRED", writer="MODEL", write_mode="CREATE",
    ),),
    immutable_inputs=("scratchpad:verification-input.md",),
    required_commit_actor="MODEL",
)
launch = LaunchSpec(
    work_unit_key=key, pipeline="sc", mode="thorough", ecosystem="evm",
    backend="codex", model={_MODEL!r}, timeout_s=15, exec_mode="exec",
    tool_policy=("filesystem", "shell", "foreground-only"),
)
spec = VerifierLaunchSpec(
    work_unit_id="verify-fixture", work_unit_resume_digest="a" * 64,
    backend="codex", model={_MODEL!r}, transport="exec",
    argv=("codex", "exec", "--model", {_MODEL!r}, "-"),
    cwd=str(scratchpad.resolve()), timeout_seconds=15,
    prompt_sha256=hashlib.sha256(prompt).hexdigest(),
    prompt_size_bytes=len(prompt),
    expected_output_files=("verify-FIXTURE.md",),
    tool_policy_digest="b" * 64, foreground_only=True,
    background_children_allowed=False,
    child_join_policy="REQUIRE_JOIN_BEFORE_RECEIPT",
    process_group_policy="ISOLATED_PROCESS_GROUP",
    orphan_policy="TERMINATE_TREE_AND_RETAIN_DEBT",
)
config = {{
    "pipeline": "sc", "mode": "thorough", "language": "evm",
    "cli_backend": "codex", "project_root": str(project.resolve()),
    "_run_id": {_RUN_ID!r},
}}
session = compat.issue_posix_v2_compat_session_for_installed_front(
    run_id={_RUN_ID!r}, project_root=project, scratchpad=scratchpad,
)
try:
    current_binding = str(session.binding["session_binding_sha256"])
    if current_binding == {historical_binding!r}:
        raise AssertionError("fresh interpreter reused historical session binding")
    D._POSIX_COMPAT_V2_PROCESS_MARKER = D._POSIX_COMPAT_V2_MARKER_TOKEN
    D._POSIX_COMPAT_V2_SESSION_AUTHORITY = session
    D._dynamic_verifier_method_digest = lambda _config: "d" * 64
    D._security_obligation_source_snapshot_digest = lambda _config: "e" * 64
    compat.shutil.which = lambda _name: (_ for _ in ()).throw(
        AssertionError("historical MODEL replay tried to resolve Codex")
    )
    rc, replayed = D._execute_or_replay_dynamic_verifier_model(
        spec,
        prompt_path=prompt_path,
        log_path=scratchpad / "fresh-interpreter-replay.log",
        scratchpad=scratchpad,
        phase=SimpleNamespace(name={_PHASE!r}, needs_mcp=False),
        config=config,
        execution_config=D._DriverConfig(
            config, native_guest_runtime_authorities=object()
        ),
        model_io_contract=contract,
        model_io_launch=launch,
    )
    if rc != 0 or replayed is None:
        raise AssertionError(f"historical MODEL replay failed: rc={{rc}}")
    authority, plan = replayed
    print(json.dumps({{
        "session_binding_sha256": current_binding,
        "authority_digest": authority["authority_digest"],
        "work_plan_digest": plan["work_plan_digest"],
    }}, sort_keys=True))
finally:
    session.close()
""",
        encoding="utf-8",
    )
    environment = dict(os.environ)
    script_root = str(Path(D.__file__).resolve().parent)
    prior_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        script_root
        if not prior_pythonpath
        else script_root + os.pathsep + prior_pythonpath
    )
    result = subprocess.run(
        [sys.executable, "-B", str(child)],
        cwd=case.project,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    observed = json.loads(result.stdout.strip().splitlines()[-1])
    assert observed["session_binding_sha256"] != historical_binding
    assert observed["authority_digest"] == execution_authority[
        "authority_digest"
    ]
    assert observed["work_plan_digest"] == commit_authority[
        "work_plan_digest"
    ]
    assert counter.read_text(encoding="ascii") == "1"


def test_rc_zero_without_committed_worker_authority_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _build_case(tmp_path)
    session = _issue_session(case)
    try:
        _activate_compat(
            monkeypatch,
            session=session,
            binary=_fake_codex(tmp_path / "unused-codex", tmp_path / "unused-count"),
        )
        monkeypatch.setattr(D, "_run_one_codex_exec", lambda **_kwargs: 0)
        # Even an erroneous status-only commit return cannot pass the final
        # replay ratchet without a durable MODEL execution authority.
        monkeypatch.setattr(
            D,
            "_commit_posix_v2_compat_dynamic_verifier",
            lambda **_kwargs: [],
        )
        rc, committed = _execute_case(case)
        assert rc == D.EXIT_ERROR
        assert committed is None
        assert b"success without committed worker execution authority" in (
            case.log_path.read_bytes()
        )
        unit = read_artifact_ledger(case.scratchpad)["work_units"][
            case.contract.key
        ]
        assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
        assert "execution_authority" not in unit
    finally:
        session.close()


@pytest.mark.parametrize("session_kind", ("absent", "foreign"))
def test_absent_or_foreign_compat_session_cannot_reach_model_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    session_kind: str,
) -> None:
    case = _build_case(tmp_path)
    counter = tmp_path / "provider-count"
    binary = _fake_codex(tmp_path / "codex", counter)
    session = (
        None
        if session_kind == "absent"
        else _issue_session(case, run_id="foreign-run")
    )
    try:
        _activate_compat(monkeypatch, session=session, binary=binary)
        rc, committed = _execute_case(case)
        assert rc == D.EXIT_ERROR
        assert committed is None
        assert not counter.exists()
        unit = read_artifact_ledger(case.scratchpad)["work_units"][
            case.contract.key
        ]
        assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
        assert "execution_authority" not in unit
    finally:
        if session is not None:
            session.close()


def test_native_dynamic_verifier_receives_original_driver_config_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _build_case(tmp_path)
    observed: dict[str, object] = {}
    monkeypatch.setattr(D, "_POSIX_COMPAT_V2_PROCESS_MARKER", None)
    monkeypatch.setattr(D, "_replay_committed_model_worker", lambda **_kwargs: None)
    monkeypatch.setattr(
        D, "_dynamic_verifier_method_digest", lambda _config: "d" * 64
    )
    monkeypatch.setattr(
        D,
        "_security_obligation_source_snapshot_digest",
        lambda _config: "e" * 64,
    )

    def effect_boundary(_spec: object, **kwargs: object) -> int:
        observed["execution_config"] = kwargs["execution_config"]
        return 23

    monkeypatch.setattr(D, "_execute_dynamic_verifier_launch", effect_boundary)
    rc, committed = _execute_case(case)
    assert rc == 23
    assert committed is None
    assert observed["execution_config"] is case.execution_config
    assert type(observed["execution_config"]) is D._DriverConfig


def test_exact_compat_provider_policy_refusal_is_terminal_without_model_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _build_case(tmp_path)
    counter = tmp_path / "provider-count"
    binary = _fake_codex(
        tmp_path / "codex", counter, returncode=7, refusal=True
    )
    session = _issue_session(case)
    try:
        _activate_compat(monkeypatch, session=session, binary=binary)
        rc, committed = _execute_case(case)
        assert rc == D._CODEX_WORKER_POLICY_REFUSAL_RC
        assert committed is None
        assert counter.read_text(encoding="ascii") == "1"
        assert _REFUSAL.encode("utf-8") in case.log_path.read_bytes()
        unit = read_artifact_ledger(case.scratchpad)["work_units"][
            case.contract.key
        ]
        assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
        assert "execution_authority" not in unit
    finally:
        session.close()


def test_verifier_coordinator_partial_refusal_retains_debt_and_continues(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One refused unit must not discard the rest of the tier's verification.

    Opus has refused content in this corpus repeatedly, and the refusal
    arrives late in the pipeline.  The refused rows stay UNVERIFIED runtime
    debt (already honoured by the report gates) and the roster commits with
    debt instead of demanding an operator resume.
    """

    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    run_id = "12345678-1234-4234-8234-123456789abc"
    config: dict[str, Any] = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
        "project_root": str(project.resolve()),
        "_run_id": run_id,
    }
    phase = D.Phase(_PHASE, [], [], 30, model=_MODEL, critical=True)
    checkpoint = D.Checkpoint(run_id=run_id)
    refused = SimpleNamespace(
        work_unit_id="verify-refused", tier_pool="critical_high"
    )
    completed = SimpleNamespace(
        work_unit_id="verify-completed", tier_pool="critical_high"
    )
    roster = SimpleNamespace(work_units=(refused, completed))
    outcome = SimpleNamespace(roster=roster, debts=())
    monkeypatch.setattr(
        D, "_prepare_dynamic_verifier_roster", lambda *_args: outcome
    )
    monkeypatch.setattr(
        D,
        "_dynamic_verifier_tier_for_phase",
        lambda _phase_name, _config: "critical_high",
    )
    invoked: list[str] = []

    def run_unit(_phase, _scratchpad, _config, _roster, unit):
        invoked.append(unit.work_unit_id)
        if unit is refused:
            return [
                "verify-refused exited rc="
                f"{D._CODEX_WORKER_POLICY_REFUSAL_RC} "
                "(PROVIDER_POLICY_REFUSAL_DEBT)"
            ]
        return []

    monkeypatch.setattr(D, "_run_dynamic_verifier_unit", run_unit)
    monkeypatch.setattr(
        D, "_write_dynamic_verifier_status", lambda *_a, **_k: (None, [])
    )
    committed: list[object] = []

    def _commit(*args, **kwargs):
        committed.append(args)
        return SimpleNamespace(
            state="COMPLETED_WITH_DEBT",
            unresolved_failures=(),
            to_dict=lambda: {"state": "COMPLETED_WITH_DEBT"},
        )

    monkeypatch.setattr(D, "_commit_verification_transaction", _commit)
    monkeypatch.setattr(
        D.display, "print_failure_diagnosis", lambda *_a, **_k: None
    )
    for name in (
        "_resolved_phase_artifact_digest",
        "_resolved_phase_contract_digest",
        "_resolved_phase_input_digest",
        "_resolved_phase_launch_digest",
    ):
        monkeypatch.setattr(D, name, lambda *_args, **_kwargs: "f" * 64)

    D._handle_dynamic_verifier_phase(
        phase, checkpoint, scratchpad, config, [phase],
        phase_idx=0, total_active=1,
    )

    # every unit ran, and the phase did not stop the run
    assert invoked == [refused.work_unit_id, completed.work_unit_id]
    assert committed, "the roster must still commit"
    sentinel = scratchpad / f"{phase.name}.degraded"
    assert sentinel.is_file()
    assert "PROVIDER_POLICY_REFUSAL_DEBT" in sentinel.read_text(encoding="utf-8")


def test_verifier_coordinator_refusal_of_every_unit_commits_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tier with NO verification evidence at all stays an operator decision.

    A refusal of only SOME units is different and must not end the run: those
    rows are retained as UNVERIFIED runtime debt that the report gates already
    honour, and stopping the tier threw away every other unit's verification.
    That case is covered by
    `test_verifier_coordinator_partial_refusal_retains_debt_and_continues`.
    """
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    run_id = "12345678-1234-4234-8234-123456789abc"
    config: dict[str, Any] = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
        "project_root": str(project.resolve()),
        "_run_id": run_id,
    }
    phase = D.Phase(
        _PHASE,
        [],
        [],
        30,
        model=_MODEL,
        critical=True,
    )
    checkpoint = D.Checkpoint(run_id=run_id)
    refused = SimpleNamespace(
        work_unit_id="verify-refused",
        tier_pool="critical_high",
    )
    next_unit = SimpleNamespace(
        work_unit_id="verify-must-not-run",
        tier_pool="critical_high",
    )
    roster = SimpleNamespace(work_units=(refused, next_unit))
    outcome = SimpleNamespace(roster=roster, debts=())
    monkeypatch.setattr(
        D, "_prepare_dynamic_verifier_roster", lambda *_args: outcome
    )
    monkeypatch.setattr(
        D,
        "_dynamic_verifier_tier_for_phase",
        lambda _phase_name, _config: "critical_high",
    )

    evidence_path = D._dynamic_verifier_unit_paths(
        scratchpad, refused.work_unit_id
    )["receipt"]
    evidence_path.parent.mkdir(parents=True)
    evidence_raw = (
        json.dumps(
            {
                "schema": "plamen.test.exact_provider_refusal.v1",
                "work_unit_id": refused.work_unit_id,
                "reason_class": "PROVIDER_POLICY_REFUSAL_DEBT",
                "returncode": D._CODEX_WORKER_POLICY_REFUSAL_RC,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )
    evidence_path.write_bytes(evidence_raw)
    exact_issue = (
        "verify-refused exited rc="
        f"{D._CODEX_WORKER_POLICY_REFUSAL_RC} "
        "(PROVIDER_POLICY_REFUSAL_DEBT)"
    )
    invoked: list[str] = []

    def run_unit(_phase, _scratchpad, _config, _roster, unit):
        invoked.append(unit.work_unit_id)
        if unit is refused:
            assert evidence_path.read_bytes() == evidence_raw
            return [exact_issue]
        # every unit in this tier is refused
        return [
            f"{unit.work_unit_id} exited rc="
            f"{D._CODEX_WORKER_POLICY_REFUSAL_RC} "
            "(PROVIDER_POLICY_REFUSAL_DEBT)"
        ]

    status_calls: list[object] = []
    monkeypatch.setattr(D, "_run_dynamic_verifier_unit", run_unit)
    monkeypatch.setattr(
        D,
        "_write_dynamic_verifier_status",
        lambda root, observed: status_calls.append((root, observed)) or (None, []),
    )
    monkeypatch.setattr(
        D,
        "_commit_verification_transaction",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("refusal reached ordinary verifier phase commit")
        ),
    )
    monkeypatch.setattr(
        D.display, "print_failure_diagnosis", lambda *_args, **_kwargs: None
    )
    # Keep this coordinator regression focused on transition semantics while
    # exercising the real PhaseCommitController and checkpoint persistence.
    for name in (
        "_resolved_phase_artifact_digest",
        "_resolved_phase_contract_digest",
        "_resolved_phase_input_digest",
        "_resolved_phase_launch_digest",
    ):
        monkeypatch.setattr(D, name, lambda *_args, **_kwargs: "f" * 64)

    with pytest.raises(SystemExit) as stopped:
        D._handle_dynamic_verifier_phase(
            phase,
            checkpoint,
            scratchpad,
            config,
            [phase],
            phase_idx=0,
            total_active=1,
        )
    assert stopped.value.code == D.EXIT_DEGRADED
    assert invoked == [refused.work_unit_id, next_unit.work_unit_id]
    assert len(status_calls) == 1
    assert status_calls[0] == (scratchpad, roster)
    assert evidence_path.read_bytes() == evidence_raw

    commit = checkpoint.phase_commits[phase.name]
    assert commit.state == "INCOMPLETE_WITH_DEBT"
    assert phase.name not in checkpoint.completed
    assert phase.name in checkpoint.degraded
    assert any(
        exact_issue in failure.message
        for failure in commit.unresolved_failures
    )
    persisted = D.Checkpoint.load(scratchpad)
    assert persisted.phase_commits[phase.name].to_dict() == commit.to_dict()
    assert phase.name not in persisted.completed
    sentinel = scratchpad / f"{phase.name}.degraded"
    assert sentinel.read_text(encoding="utf-8").startswith(
        f"Phase {phase.name} committed as INCOMPLETE_WITH_DEBT.\n"
    )
    assert exact_issue in sentinel.read_text(encoding="utf-8")
