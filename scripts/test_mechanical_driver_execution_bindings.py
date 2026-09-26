"""Normal/recovery mechanical calls retain driver and live-session identity.

These are caller/validation contracts, not compiler or candidate PoC evidence.
Only the POSIX-specific fixtures load the compatibility runtime.
"""
from __future__ import annotations

import ast
import hashlib
import importlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import mechanical_verify as M
import plamen_driver as D


RUN_ID = "mechanical-binding-fixture"
DRIVER_ID = "sha256:" + "a" * 64


@pytest.fixture(autouse=True)
def _current_mechanical_module(monkeypatch: pytest.MonkeyPatch):
    # Legacy mechanical tests reload this module. Patch the same current
    # instance that the driver's lazy import will actually call.
    monkeypatch.setitem(globals(), "M", importlib.import_module("mechanical_verify"))


def _session(tmp_path: Path):
    if os.name != "posix":
        pytest.skip("requires a live POSIX compatibility session")
    import posix_v2_compat_runtime as R

    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    session = R.issue_posix_v2_compat_session_for_installed_front(
        run_id=RUN_ID, project_root=project, scratchpad=scratch
    )
    return project, scratch, session


@pytest.mark.parametrize("compat_mode", [False, True])
def test_driver_helper_passes_explicit_current_identity_and_exact_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, compat_mode: bool,
) -> None:
    if compat_mode:
        project, scratch, session = _session(tmp_path)
    else:
        project, scratch, session = tmp_path, tmp_path / ".scratchpad", None
    calls = []
    snapshot_checks = []
    expected = {"status": "fixture-result"}
    snapshot = {"snapshot_digest": "snapshot-routing-fixture"}
    config = {
        "_run_id": RUN_ID, "project_root": str(project), "language": "evm",
        "_audit_snapshot": snapshot,
    }

    def capture(*args, **kwargs):
        calls.append((args, kwargs))
        return expected

    monkeypatch.setattr(M, "run_phase5b_mechanical_verify", capture)
    monkeypatch.setattr(D, "_posix_v2_compat_process_active", lambda: compat_mode)
    monkeypatch.setattr(D, "_POSIX_COMPAT_V2_SESSION_AUTHORITY", session)
    monkeypatch.setattr(
        D, "_assert_audit_snapshot_still_bound",
        lambda *args: snapshot_checks.append(args),
    )
    try:
        result = D._run_mechanical_verification(scratch, config)
        assert result is expected
        extra = {}
        if compat_mode:
            callback = calls[0][1]["assert_snapshot_current"]
            assert callable(callback)
            assert calls[0][1]["audit_snapshot"] is snapshot
            callback()
            assert snapshot_checks == [(config, scratch, "verification_mechanical:prewarm")]
            extra = {"audit_snapshot": snapshot, "assert_snapshot_current": callback}
        assert calls == [((scratch, project, "evm"), {
            "run_identity": RUN_ID,
            "driver_identity": "sha256:" + hashlib.sha256(Path(D.__file__).read_bytes()).hexdigest(),
            "posix_compat_session": session,
            **extra,
        })]
    finally:
        if session is not None:
            session.close()


@pytest.mark.parametrize("run_id", [None, "", " ", " padded ", "test-unbound", 123])
def test_driver_helper_rejects_missing_or_placeholder_run_before_executor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, run_id,
) -> None:
    def forbidden(*args, **kwargs):
        pytest.fail("invalid run identity reached the mechanical executor")

    monkeypatch.setattr(M, "run_phase5b_mechanical_verify", forbidden)
    with pytest.raises(ValueError, match="active driver run id"):
        D._run_mechanical_verification(tmp_path, {
            "_run_id": run_id, "project_root": str(tmp_path),
        })


@pytest.mark.parametrize("when", ["before", "during"])
def test_driver_prewarm_guard_cannot_accept_a_rebound_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, when: str,
) -> None:
    project, scratch, session = _session(tmp_path)
    config = {
        "_run_id": RUN_ID, "project_root": str(project), "language": "evm",
        "_audit_snapshot": {"snapshot_digest": "original-fixture"},
    }
    callbacks = []
    monkeypatch.setattr(D, "_posix_v2_compat_process_active", lambda: True)
    monkeypatch.setattr(D, "_POSIX_COMPAT_V2_SESSION_AUTHORITY", session)

    def capture(*args, **kwargs):
        callbacks.append(kwargs["assert_snapshot_current"])
        return {}

    def rebind(*args):
        config["_audit_snapshot"] = {"snapshot_digest": "different-fixture"}

    monkeypatch.setattr(M, "run_phase5b_mechanical_verify", capture)
    monkeypatch.setattr(D, "_assert_audit_snapshot_still_bound", rebind)
    try:
        D._run_mechanical_verification(scratch, config)
        if when == "before":
            rebind()
        with pytest.raises(ValueError, match="accepted driver binding changed"):
            callbacks[0]()
    finally:
        session.close()


def test_active_compat_driver_cannot_fall_back_when_session_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(D, "_posix_v2_compat_process_active", lambda: True)
    monkeypatch.setattr(D, "_POSIX_COMPAT_V2_SESSION_AUTHORITY", None)
    with pytest.raises(RuntimeError, match="session is absent"):
        D._run_mechanical_verification(tmp_path, {
            "_run_id": RUN_ID, "project_root": str(tmp_path),
        })


@pytest.mark.parametrize("mismatch", [
    "forged_session", "closed_session", "run", "project", "scratchpad", "driver",
])
def test_mechanical_rejects_session_mismatch_before_tool_lookup_or_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mismatch: str,
) -> None:
    project, scratch, session = _session(tmp_path)
    args = {
        "scratchpad": scratch, "project_root": project, "language": "evm",
        "run_identity": RUN_ID, "driver_identity": DRIVER_ID,
        "posix_compat_session": session,
    }
    if mismatch == "forged_session":
        args["posix_compat_session"] = object()
    elif mismatch == "closed_session":
        session.close()
    elif mismatch == "run":
        args["run_identity"] = "another-run"
    elif mismatch == "project":
        args["project_root"] = tmp_path
    elif mismatch == "scratchpad":
        args["scratchpad"] = project
    else:
        args["driver_identity"] = "test-unbound"

    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid compatibility identity reached an execution effect")

    monkeypatch.setattr(M.shutil, "which", forbidden)
    monkeypatch.setattr(M, "_write_manifest", forbidden)
    monkeypatch.setattr(M, "gate_supply_chain", forbidden)
    before = list(scratch.iterdir())
    try:
        with pytest.raises(M.SupplyChainAbortError, match="execution binding is invalid"):
            M.run_phase5b_mechanical_verify(**args)
        assert list(scratch.iterdir()) == before
    finally:
        if mismatch != "closed_session":
            session.close()


def test_mechanical_forwards_exact_session_to_supply_chain_before_prewarm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratch, session = _session(tmp_path)
    (project / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (scratch / "verify_FIXTURE.md").write_text(
        "# Verification: FIXTURE\n\n"
        "**Test File**: `test/Fixture.t.sol`\n"
        "**Test Function**: `test_fixture`\n\n"
        "### Mechanical PoC Source\n\n"
        "```solidity\n"
        "contract FixtureTest { function test_fixture() public {} }\n"
        "```\n",
        encoding="utf-8",
    )
    calls = []

    class StopAtGate(Exception):
        pass

    def gate(root, **kwargs):
        calls.append((root, kwargs))
        raise StopAtGate

    def forbidden(*_args, **_kwargs):
        pytest.fail("prewarm ran before the gate admitted its inputs")

    monkeypatch.setattr(M.shutil, "which", lambda _name: "/fixture/forge")
    monkeypatch.setattr(M, "gate_supply_chain", gate)
    monkeypatch.setattr(M, "_prewarm_build", forbidden)
    try:
        with pytest.raises(StopAtGate):
            M.run_phase5b_mechanical_verify(
                scratch, project, "evm", run_identity=RUN_ID,
                driver_identity=DRIVER_ID, posix_compat_session=session,
                registry={"languages": {}},
            )
        assert calls == [(project, {"posix_compat_session": session})]
    finally:
        session.close()


def test_normal_and_recovery_routes_share_the_execution_binding_helper() -> None:
    tree = ast.parse(Path(D.__file__).read_bytes())
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    helper_calls = [
        node for node in calls
        if isinstance(node.func, ast.Name) and node.func.id == "_run_mechanical_verification"
    ]
    direct_calls = [
        node for node in calls
        if ((isinstance(node.func, ast.Name) and node.func.id == "run_phase5b_mechanical_verify")
            or (isinstance(node.func, ast.Attribute) and node.func.attr == "run_phase5b_mechanical_verify"))
    ]
    assert len(helper_calls) == 2
    assert len(direct_calls) == 1


@pytest.mark.parametrize("prewarm_fails", [False, True])
def test_compat_mechanical_retains_live_admission_and_workspace_for_consumer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, prewarm_fails: bool,
) -> None:
    """Caller contract only; the candidate consumer is stopped before execution."""
    project, scratch, session = _session(tmp_path)
    import mechanical_prewarm as P

    (project / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (scratch / "verify_FIXTURE.md").write_text(
        "# Verification: FIXTURE\n\n"
        "**Test File**: `test/Fixture.t.sol`\n"
        "**Test Function**: `test_fixture`\n\n"
        "### Mechanical PoC Source\n\n"
        "```solidity\n"
        "contract FixtureTest { function test_fixture() public {} }\n"
        "```\n",
        encoding="utf-8",
    )
    workspace = scratch / "published-workspace"
    admission = object()  # Handoff identity only, not a forged executable authority.
    snapshot = {"snapshot_digest": "snapshot-routing-fixture"}
    events = []

    class StopAtConsumer(Exception):
        pass

    class StopAtPrewarm(Exception):
        pass

    def snapshot_check():
        events.append("snapshot")

    def gate(root, **kwargs):
        assert root == project
        assert kwargs == {"posix_compat_session": session}
        events.append("gate")
        return admission

    def prewarm(**kwargs):
        assert kwargs["session_authority"] is session
        assert kwargs["supply_chain_admission"] is admission
        assert kwargs["source_build_root"] == project
        assert kwargs["audit_snapshot"] is snapshot
        assert kwargs["assert_snapshot_current"] is snapshot_check
        assert kwargs["driver_identity"] == DRIVER_ID
        events.append("prewarm")
        if prewarm_fails:
            raise StopAtPrewarm
        workspace.mkdir()
        (workspace / "cache-marker").write_text("fixture cache", encoding="utf-8")
        return SimpleNamespace(
            workspace_root=workspace, ok=True, note="fixture build",
            cargo_ok=None, cargo_note=None, terminals=(),
        )

    def consumer(vf, build_root, *args, **kwargs):
        assert build_root == workspace
        assert (build_root / "cache-marker").read_text() == "fixture cache"
        assert (build_root / "test/Fixture.t.sol").is_file()
        assert kwargs["project_root"] is None
        assert callable(kwargs["process_runner"])
        events.append("consumer")
        raise StopAtConsumer

    monkeypatch.setattr(M.shutil, "which", lambda _name: "/fixture/forge")
    monkeypatch.setattr(M, "gate_supply_chain", gate)
    monkeypatch.setattr(P, "run_compat_prewarm", prewarm)
    monkeypatch.setattr(
        M, "_prewarm_build",
        lambda *args, **kwargs: pytest.fail("ambient legacy prewarm was used"),
    )
    monkeypatch.setattr(M, "_run_test_for_finding", consumer)
    try:
        with pytest.raises(StopAtPrewarm if prewarm_fails else StopAtConsumer):
            M.run_phase5b_mechanical_verify(
                scratch, project, "evm", run_identity=RUN_ID,
                driver_identity=DRIVER_ID, posix_compat_session=session,
                audit_snapshot=snapshot, assert_snapshot_current=snapshot_check,
                registry={"languages": {}},
            )
        assert events == (["gate", "prewarm"] if prewarm_fails else ["gate", "prewarm", "consumer"])
        assert not (project / "cache-marker").exists()
    finally:
        session.close()
