"""Report transport execution and negative preimage admission tests.

The minimal resolved contract isolates transport and the artifact recorder.
The child is a deterministic local double, not a remote model; full report
methodology and queue-to-report acceptance remain separate integration work.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys

import pytest

import artifact_ledger as ledger
from phase_io_contracts import ArtifactSpec, LaunchSpec, PhaseIOContract
import plamen_driver as driver


def _case(tmp_path: Path):
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    phase = next(item for item in driver.SC_PHASES if item.name == "report_index")
    owner = "sc/core/evm/codex/report_index/model"
    contract = PhaseIOContract(
        pipeline="sc", mode="core", ecosystem="evm", backend="codex",
        phase="report_index", work_unit_id="model",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad", path=name, owner_key=owner,
                artifact_class="REQUIRED", writer="MODEL", write_mode="CREATE",
            )
            for name in ("report_index.md", "report_coverage.md")
        ),
    )
    launch = LaunchSpec(
        work_unit_key=contract.key, pipeline="sc", mode="core", ecosystem="evm",
        backend="codex", model="gpt-5.6-sol", timeout_s=30, exec_mode="headless",
    )
    run_id = "23456789-1234-4abc-8def-1234567890ab"
    config = {
        "_run_id": run_id, "project_root": str(project), "cli_backend": "codex",
        "mode": "core", "pipeline": "sc", "language": "evm",
    }
    return project, root, phase, contract, launch, config


@pytest.mark.parametrize("legacy_committed", [False, True])
def test_posix_report_preimage_cannot_adopt_bytes_without_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, legacy_committed: bool,
) -> None:
    project, root, phase, contract, launch, config = _case(tmp_path)
    run_id = config["_run_id"]
    ledger.record_work_unit_inputs(root, project, contract, launch, run_id=run_id)
    proposed = {
        name: ("# Unexecuted report proposal\n" + name + "\n").encode()
        for name in ("report_index.md", "report_coverage.md")
    }
    for name, raw in proposed.items():
        (root / name).write_bytes(raw)
    if legacy_committed:
        # Deliberately reproduce the old descriptor-only state; it must not be
        # mistaken for actual worker execution during report recovery.
        ledger.record_work_unit_artifacts(
            root, project, contract, launch, run_id=run_id, actor="MODEL",
        )
    before = (root / "_artifact_state.json").read_bytes()
    monkeypatch.setattr(driver, "_posix_v2_compat_process_active", lambda: True)
    issues = driver._record_typed_model_phase_artifacts(
        phase, root, config, allow_report_index_preimage=True,
        _resolved_contract=contract, _resolved_launch=launch,
    )
    assert issues, "unexecuted bytes must not gain POSIX report MODEL authority"
    assert any("execution" in issue.lower() for issue in issues), issues
    assert (root / "_artifact_state.json").read_bytes() == before
    assert {name: (root / name).read_bytes() for name in proposed} == proposed


@pytest.mark.parametrize("damage", [
    "none", "authority_missing",
    "attempt_completion_relative_path:missing",
    "attempt_completion_relative_path:tampered",
    "provider_completion_relative_path:missing",
    "provider_completion_relative_path:tampered",
    "incorporation_relative_path:missing",
    "incorporation_relative_path:tampered",
])
def test_real_report_child_retains_execution_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, damage: str,
) -> None:
    """Exercise report execution transport, not full report semantic acceptance."""
    if os.name != "posix":
        pytest.skip("real-child fixture requires POSIX compatibility runtime")
    import posix_v2_compat_runtime as compat
    from audit_snapshot import build_audit_snapshot
    from test_support_startup_permit import durable_startup_permit

    project, root, phase, contract, launch, config = _case(tmp_path)
    (project / "Unit.sol").write_text(
        "pragma solidity ^0.8.20; contract Unit {}\n", encoding="utf-8",
    )
    run_id = config["_run_id"]
    config["_auxiliary_writable_root_startup_binding"] = durable_startup_permit(
        root, run_id=run_id,
    )
    config["_audit_snapshot"] = build_audit_snapshot(
        config, Path(__file__).resolve().parent.parent,
    )
    ledger.record_work_unit_inputs(root, project, contract, launch, run_id=run_id)
    binary = tmp_path / "codex-report-fixture"
    binary.write_text(
        f"#!{sys.executable} -B\n"
        "import json,re,sys\nfrom pathlib import Path\n"
        "if sys.argv[1:] == ['--version']:\n"
        " print('codex-cli report-fixture'); raise SystemExit(0)\n"
        "prompt=sys.stdin.read()\n"
        "sys.stderr.write('OpenAI Codex v0.test\\n--------\\nworkdir: /fixture\\n"
        "model: gpt-5.6-sol\\nprovider: openai\\n--------\\nuser\\n')\n"
        "blocks=[json.loads(b) for b in re.findall(r'```json\\s*(.*?)\\s*```',prompt,re.S)]\n"
        "routing=next(b for b in blocks if b.get('schema')=='plamen.posix_v2_codex_local_phaseio.v1')\n"
        "for route in routing['output_routes']:\n"
        " Path(route['path']).write_text('# Deterministic report transport fixture\\n')\n"
        "Path(sys.argv[sys.argv.index('-o')+1]).write_text('complete\\n')\n"
        "print(json.dumps({'type':'turn.completed'}))\n",
        encoding="utf-8",
    )
    binary.chmod(0o755)
    session = compat.issue_posix_v2_compat_session_for_installed_front(
        run_id=run_id, project_root=project, scratchpad=root,
    )
    monkeypatch.setattr(driver, "_POSIX_COMPAT_V2_PROCESS_MARKER", driver._POSIX_COMPAT_V2_MARKER_TOKEN)
    monkeypatch.setattr(driver, "_POSIX_COMPAT_V2_SESSION_AUTHORITY", session)
    monkeypatch.setattr(compat.shutil, "which", lambda _name: str(binary))
    monkeypatch.setattr(compat, "_load_ambient_codex_auth", lambda: (
        "PRIVATE_AUTH_JSON_COPY", b'{"tokens":{}}\n', "c" * 64,
    ))
    monkeypatch.setattr(driver, "_codex_prompt_fits", lambda *_args: True)
    try:
        assert driver._run_one_codex_exec(
            prompt="Write the two assigned harmless report transport fixtures.\n",
            phase=phase, config=config, scratchpad=root, attempt=1,
            label="report_index", expected_outputs=[spec.path for spec in contract.outputs],
            timeout=float(launch.timeout_s), effective_model=launch.model,
            phase_io_contract=contract, phase_io_launch=launch,
        ) == 0
        state = ledger.read_artifact_ledger(root)
        unit = state["work_units"][contract.key]
        authority = unit["execution_authority"]
        assert authority["schema"] == "plamen.worker_execution_authority.v1"
        assert unit["semantic_status"] == "ACTIVE"
        assert unit["execution_state"] == "OUTPUT_COMMITTED"

        def replay():
            return driver._record_typed_model_phase_artifacts(
                phase, root, config, allow_report_index_preimage=True,
                _resolved_contract=contract, _resolved_launch=launch,
            )

        assert replay() == []
        if damage == "authority_missing":
            # Damage the retained ledger, not a replacement success receipt.
            path = root / "_artifact_state.json"
            raw_state = json.loads(path.read_text())
            del raw_state["work_units"][contract.key]["execution_authority"]
            path.write_text(json.dumps(raw_state), encoding="utf-8")
        elif damage != "none":
            field, operation = damage.split(":")
            target = root / authority[field]
            if operation == "missing":
                target.unlink()
            else:
                target.write_bytes(b"{}\n")
        before = (root / "_artifact_state.json").read_bytes()
        outputs = {spec.path: (root / spec.path).read_bytes() for spec in contract.outputs}
        issues = replay()
        assert bool(issues) is (damage != "none"), issues
        assert (root / "_artifact_state.json").read_bytes() == before
        assert {name: (root / name).read_bytes() for name in outputs} == outputs
    finally:
        session.close()
