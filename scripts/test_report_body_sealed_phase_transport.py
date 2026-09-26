"""Real compatibility-runtime coverage for report-body parent aliases."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import textwrap

import pytest

from artifact_ledger import record_work_unit_inputs
from phase_io_contracts import (
    LaunchSpec,
    resolve_phase_io_contract,
)
import plamen_driver as D
import posix_compat_model_incorporation as incorporation
import posix_v2_compat_runtime as compat
import report_model_preimages


pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX-only route")


def _fake_codex(path: Path, *, model: str) -> Path:
    path.write_text(
        "#!" + sys.executable + " -B\n" + textwrap.dedent(
            f"""
            import json
            from pathlib import Path
            import re
            import sys

            if sys.argv[1:] == ["--version"]:
                print("codex-cli 0.test")
                raise SystemExit(0)
            sys.stderr.write("OpenAI Codex v0.test\\n--------\\nworkdir: /test\\nmodel: {model}\\nprovider: openai\\n--------\\nuser\\n")
            prompt = sys.stdin.buffer.read().decode("utf-8")
            blocks = re.findall(r"```json\\n(.*?)\\n```", prompt, re.S)
            route = json.loads(blocks[-1])["output_routes"][0]
            Path(route["path"]).write_bytes(b"exact report model output\\n")
            Path(sys.argv[sys.argv.index("-o") + 1]).write_bytes(b"done\\n")
            print(json.dumps({{"type": "turn.completed"}}))
            """
        ),
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


@pytest.mark.parametrize(
    ("work_unit_id", "label", "output", "exact_inputs", "expects_preimage"),
    (
        (
            "evidence_repair.model",
            "report_evidence_repair",
            "report_evidence_repair_response.json",
            (
                "report_evidence_records.json",
                "report_evidence_repair_request.json",
                "report_evidence_repair_attempt.json",
                "_prompt_report_evidence_repair.md",
            ),
            False,
        ),
        (
            "model.report_low_info",
            "report_body_writer_low_info",
            "report_low_info.md",
            (
                "body_manifests/report_low_info.json",
                "report_evidence_manifests/report_low_info.json",
            ),
            True,
        ),
    ),
)
def test_report_body_parent_alias_executes_under_sealed_runtime_phase(
    tmp_path, monkeypatch, work_unit_id, label, output, exact_inputs,
    expects_preimage,
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    for name in exact_inputs:
        path = scratchpad / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"{}\n")
    run_id = "12345678-1234-4123-8123-123456789abc"
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        phase="report_body",
        work_unit_id=work_unit_id,
        exact_inputs=exact_inputs,
        exact_outputs=(output,),
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        model="gpt-5.4",
        timeout_s=17,
        exec_mode="headless",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        scratchpad, project, contract, launch, run_id=run_id,
    )
    session = compat.issue_posix_v2_compat_session_for_installed_front(
        run_id=run_id, project_root=project, scratchpad=scratchpad,
    )
    binary = _fake_codex(tmp_path / "codex", model=launch.model)
    monkeypatch.setattr(compat.shutil, "which", lambda _name: str(binary))
    monkeypatch.setattr(
        compat,
        "_load_ambient_codex_auth",
        lambda: ("PRIVATE_AUTH_JSON_COPY", b'{"tokens":{}}\n', "a" * 64),
    )
    monkeypatch.setattr(
        D, "_POSIX_COMPAT_V2_PROCESS_MARKER", D._POSIX_COMPAT_V2_MARKER_TOKEN,
    )
    monkeypatch.setattr(D, "_POSIX_COMPAT_V2_SESSION_AUTHORITY", session)
    incorporated = []
    monkeypatch.setattr(
        incorporation,
        "commit_validated_posix_compat_model_execution",
        lambda **kwargs: incorporated.append(kwargs) or [],
    )
    captured = []
    monkeypatch.setattr(
        report_model_preimages,
        "capture_report_model_preimages",
        lambda *args, **kwargs: captured.append((args, kwargs)),
    )
    monkeypatch.setattr(
        D, "_security_obligation_source_snapshot_digest", lambda _config: "d" * 64,
    )
    config = {
        "_run_id": run_id,
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "mode": "thorough",
        "pipeline": "sc",
        "language": "evm",
        "cli_backend": "codex",
    }
    try:
        rc = D._run_one_codex_exec(
            prompt="render exact report output",
            phase=type("Phase", (), {
                "name": "report_body_writer_low_info", "needs_mcp": False,
            })(),
            config=config,
            scratchpad=scratchpad,
            attempt=1,
            label=label,
            expected_outputs=[output],
            # Parent hints intentionally differ. The runtime must execute the
            # already-admitted sealed launch and its report_body phase.
            timeout=99,
            effective_model="parent-policy-model",
            phase_io_contract=contract,
            phase_io_launch=launch,
        )
        assert rc == 0
        assert len(incorporated) == 1
        receipts = list(
            (scratchpad / ".posix_v2_compat_receipts").glob(
                f"report_body.{label}.attempt1.*.json"
            )
        )
        assert len(receipts) == 1
        receipt = json.loads(receipts[0].read_text(encoding="ascii"))
        assert receipt["phase"] == contract.phase == "report_body"
        assert receipt["requested_model"] == launch.model
        assert receipt["phase_io_launch_digest"] == launch.digest
        assert receipt["phase_io_contract_digest"] == contract.digest
        assert bool(captured) is expects_preimage
        assert hashlib.sha256((scratchpad / output).read_bytes()).hexdigest() == (
            incorporated[0]["outputs"][0]["sha256"]
        )
    finally:
        session.close()
