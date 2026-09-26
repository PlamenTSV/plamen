from __future__ import annotations

import json
import os
from pathlib import Path
import sys

import posix_v2_compat_runtime as compat
import static_analysis_compat_execution as static_exec


def _workspace(project: Path, source: Path) -> dict[str, object]:
    return {
        "run_id": "run-static-test",
        "receipt_sha256": "1" * 64,
        "project_root": {"absolute_path": os.fspath(project)},
        "build_root": {"absolute_path": os.fspath(source)},
        "snapshot": {"snapshot_sha256": "2" * 64},
        "source_closure": {"snapshot_source_scope_sha256": "3" * 64},
        "dependency_closure": {"closure_sha256": "4" * 64},
    }


def test_static_analysis_uses_real_compat_child_and_binds_output(
    tmp_path: Path, monkeypatch,
) -> None:
    project = tmp_path / "project"
    source = project / "source"
    scratch = project / ".scratchpad"
    stage = scratch / "static-stage"
    source.mkdir(parents=True)
    scratch.mkdir()
    stage.mkdir()
    (source / "Contract.sol").write_text("contract Contract {}\n", encoding="ascii")
    session = compat.issue_posix_v2_compat_session_for_installed_front(
        run_id="run-static-test",
        project_root=project,
        scratchpad=scratch,
    )
    workspace = _workspace(project, source)
    replays: list[str] = []
    monkeypatch.setattr(
        static_exec.evm_workspace,
        "replay_evm_analysis_workspace_execution_closure",
        lambda _receipt: replays.append("replay") or workspace,
    )
    monkeypatch.setattr(
        static_exec,
        "gate_supply_chain",
        lambda _root, **_kwargs: object(),
    )
    monkeypatch.setattr(
        static_exec,
        "project_supply_chain_admission",
        lambda _authority, **_kwargs: {"admission_sha256": "5" * 64},
    )
    executable = Path(sys.executable).resolve(strict=True)
    output = stage / "result.json"
    try:
        evidence = static_exec.execute_compat_static_analysis(
            session_authority=session,
            workspace_authority=workspace,
            stage=stage,
            tool_id="fixture-scanner",
            executable=executable,
            argv=(
                os.fspath(executable),
                "-I",
                "-S",
                "-B",
                "-c",
                (
                    "import pathlib,sys;"
                    "pathlib.Path(sys.argv[1]).write_text('[]',encoding='ascii')"
                ),
                os.fspath(output),
            ),
            environment={"PATH": os.fspath(executable.parent)},
            expected_outputs=("result.json",),
            timeout_seconds=10.0,
            policy_inputs={"rules_sha256": "6" * 64},
            auxiliary_executables={"python_runtime": executable},
        )
        assert output.read_text(encoding="ascii") == "[]"
        assert replays == ["replay", "replay"]
        assert evidence["schema"] == "plamen.compat-static-analysis-execution.v1"
        assert evidence["authority_tier"] == "OBSERVATIONAL_REDUCED_ISOLATION"
        assert evidence["can_certify_clean"] is False
        terminal = evidence["terminal"]
        assert terminal["purpose"] == "STATIC_ANALYSIS"
        assert terminal["subject_kind"] == "STATIC_ANALYSIS_MANIFEST"
        assert terminal["status"] == "COMPLETED"
        assert terminal["actual_tool_started"] is True
        assert terminal["actual_tool_completion_observed"] is True
        assert terminal["nonattempt_reason"] == "STATIC_ANALYSIS_NOT_POC"
        assert terminal["poc_attempted"] is False
        assert terminal["expected_outputs"] == [{
            "path": "result.json",
            "sha256": __import__("hashlib").sha256(b"[]").hexdigest(),
            "size": 2,
        }]
        manifest = json.loads(
            (stage / "static-analysis-manifest.json").read_text(encoding="ascii")
        )
        assert manifest["can_certify_clean"] is False
        assert manifest["workspace_receipt_sha256"] == "1" * 64
        assert manifest["auxiliary_executables"]["python_runtime"]["path"] == (
            os.fspath(executable)
        )
        assert evidence["auxiliary_executables"] == (
            manifest["auxiliary_executables"]
        )
    finally:
        session.close()


def test_static_analysis_rejects_stage_outside_session_scratch(
    tmp_path: Path, monkeypatch,
) -> None:
    project = tmp_path / "project"
    source = project / "source"
    scratch = project / ".scratchpad"
    outside = project / "outside"
    source.mkdir(parents=True)
    scratch.mkdir()
    outside.mkdir()
    session = compat.issue_posix_v2_compat_session_for_installed_front(
        run_id="run-static-test",
        project_root=project,
        scratchpad=scratch,
    )
    workspace = _workspace(project, source)
    monkeypatch.setattr(
        static_exec.evm_workspace,
        "replay_evm_analysis_workspace_execution_closure",
        lambda _receipt: workspace,
    )
    try:
        try:
            static_exec.execute_compat_static_analysis(
                session_authority=session,
                workspace_authority=workspace,
                stage=outside,
                tool_id="fixture-scanner",
                executable=Path(sys.executable).resolve(strict=True),
                argv=(sys.executable, "-c", "pass"),
                environment={"PATH": os.fspath(Path(sys.executable).parent)},
                expected_outputs=(),
                timeout_seconds=1.0,
            )
        except static_exec.StaticAnalysisCompatExecutionError as exc:
            assert "outside the audit scratchpad" in str(exc)
        else:
            raise AssertionError("outside stage was admitted")
    finally:
        session.close()
