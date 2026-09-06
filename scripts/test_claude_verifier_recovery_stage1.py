"""Stage-1 fixtures for Claude verifier/recovery semantic transport.

These tests are provider-free.  They pin the only completion transport whose
stdout can eventually be admitted as Claude semantic evidence and require the
legacy PTY route to remain visible debt without starting a process.
"""
from __future__ import annotations

import json
from pathlib import Path
import uuid

import pytest

import plamen_driver as D
from test_verification_recovery_contract_p0_ai import _semantic_row
from test_verifier_work_roster_p0_ak import _fixed_slot_plan
from verification_recovery_contract import build_verification_recovery_contract
from verifier_work_roster import (
    build_verifier_launch_spec,
    build_verifier_runtime_policy,
    build_verifier_work_roster,
)


def _claude_spec(tmp_path: Path, transport: str):
    _items, plan = _fixed_slot_plan(1, "sc")
    roster = build_verifier_work_roster(
        plan,
        pipeline="sc",
        ecosystem="evm",
        mode="thorough",
        runtime_policy=build_verifier_runtime_policy(
            backend="claude",
            model="sonnet",
            transport=transport,
            timeout_seconds=60,
            source_root=str(tmp_path.resolve()),
        ),
        method_registry_digest="1" * 64,
        context_packet_digest="2" * 64,
    )
    return build_verifier_launch_spec(
        roster,
        roster.work_units[0].work_unit_id,
        prompt_bytes=b"bounded verifier prompt",
        claude_executable="claude",
    )


def _assert_canonical_claude_stream_argv(argv: tuple[str, ...]) -> None:
    assert Path(argv[0]).name.lower() in {
        "claude", "claude.exe", "claude.cmd"
    }
    assert argv[1] == "-p"
    assert argv[argv.index("--output-format") + 1] == "stream-json"
    assert "--verbose" in argv
    assert "--no-session-persistence" in argv
    session_id = argv[argv.index("--session-id") + 1]
    assert str(uuid.UUID(session_id)) == session_id
    assert argv.count("--session-id") == 1


def test_dynamic_verifier_headless_spec_is_canonical_and_deterministic(
    tmp_path: Path,
) -> None:
    first = _claude_spec(tmp_path, "headless")
    second = _claude_spec(tmp_path, "headless")

    _assert_canonical_claude_stream_argv(first.argv)
    assert first == second
    assert first.digest == second.digest


def test_recovery_defaults_to_canonical_headless_stream_transport(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    contract = build_verification_recovery_contract(
        run_id="run-1",
        recovery_kind="GENERIC_RECOVERY",
        rows=[_semantic_row()],
        scratchpad=scratchpad,
        project_root=project,
        pipeline="sc",
        ecosystem="evm",
        backend="claude",
        repo_root=Path(__file__).resolve().parent.parent,
    )
    config = {
        "scratchpad": str(scratchpad),
        "project_root": str(project),
        "pipeline": "sc",
        "language": "evm",
        "cli_backend": "claude",
        "mode": "core",
    }

    first = D._verify_recovery_launch_spec(contract, config=config)
    second = D._verify_recovery_launch_spec(contract, config=config)

    assert first.transport == "headless"
    _assert_canonical_claude_stream_argv(first.argv)
    assert first == second


def test_claude_pty_verifier_is_typed_debt_and_never_spawned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _claude_spec(tmp_path, "pty")
    prompt = tmp_path / "prompt.md"
    prompt.write_text("bounded verifier prompt", encoding="utf-8")
    log_path = tmp_path / "pty.log"

    def forbidden(*_args, **_kwargs):
        raise AssertionError("untrusted PTY completion transport was launched")

    monkeypatch.setattr(D, "ClaudePtySession", forbidden)
    monkeypatch.setattr(D, "execute_headless_worker", forbidden)
    rc = D._execute_dynamic_verifier_launch(
        spec,
        prompt_path=prompt,
        log_path=log_path,
        scratchpad=tmp_path,
        phase=next(
            item
            for item in D.SC_PHASES
            if item.name == "sc_verify_crithigh"
        ),
        config={},
    )

    assert rc == D._UNTRUSTED_COMPLETION_TRANSPORT_RC
    debt = json.loads(log_path.read_text(encoding="utf-8"))
    assert debt["status"] == "COMPLETED_WITH_DEBT"
    assert debt["reason_code"] == "UNTRUSTED_COMPLETION_TRANSPORT"
    assert debt["backend"] == "claude"
    assert debt["transport"] == "pty"
    assert debt["work_unit_id"] == spec.work_unit_id
