"""Real local transactions preserve a healthy sibling at a refusal boundary.

The workers are deterministic harmless protocol doubles, not model providers.
This tests runtime lineage and recovery, not audit findings or semantic proof.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

import artifact_ledger
from audit_snapshot import build_audit_snapshot
import plamen_driver as driver
from test_support_startup_permit import durable_startup_permit


RUN_ID = "12345678-1234-4abc-8def-1234567890ab"
REFUSAL = (
    "ERROR: This content was flagged for possible cybersecurity risk. "
    "If this seems wrong, try rephrasing your request. To get authorized "
    "for security work, join the Trusted Access for Cyber program: "
    "https://chatgpt.com/cyber\n"
)


def _manifest(root: Path) -> list[dict[str, str]]:
    root.joinpath("spawn_manifest.md").write_text(
        "# Spawn Manifest\n\n"
        "| Template | Required? | Agent ID | Focus Area | Expected Output | Status | Type |\n"
        "|---|---|---|---|---|---|---|\n"
        "| GENERAL | YES | B1 | state | analysis_refused.md | PENDING | agent |\n"
        "| GENERAL | YES | B2 | access | analysis_healthy.md | PENDING | agent |\n",
        encoding="utf-8",
    )
    return [
        {
            "agent_id": "B1", "role": "general", "focus_area": "state",
            "output": "analysis_refused.md",
        },
        {
            "agent_id": "B2", "role": "general", "focus_area": "access",
            "output": "analysis_healthy.md",
        },
    ]


def _breadth_inputs(root: Path) -> None:
    for name in (
        "recon_summary.md",
        "attack_surface.md",
        "contract_inventory.md",
        "function_list.md",
        "state_variables.md",
        "template_recommendations.md",
        "opengrep_obligations_B1_state.md",
        "opengrep_obligations_B2_access.md",
    ):
        root.joinpath(name).write_text(
            f"## {name}\n\nfixture authority\n", encoding="utf-8"
        )


def _fake_codex(path: Path) -> Path:
    path.write_text(
        "#!" + sys.executable + "\n"
        + f'''import json
from pathlib import Path
import re
import sys

if sys.argv[1:] == ["--version"]:
    print("codex-cli 0.test")
    raise SystemExit(0)
prompt = sys.stdin.buffer.read().decode("utf-8", errors="strict")
match = re.search(r"TARGET=([^\\r\\n]+)", prompt)
if match is None:
    raise SystemExit(8)
target = Path(match.group(1))
counter = target.parent / ("_calls_" + target.stem)
prior = int(counter.read_text(encoding="ascii")) if counter.exists() else 0
counter.write_text(str(prior + 1), encoding="ascii")
sys.stderr.write("OpenAI Codex v0.test\\n--------\\nworkdir: /fixture\\nmodel: gpt-5.6-sol\\nprovider: openai\\n--------\\nuser\\n")
if target.name == "analysis_refused.md":
    sys.stderr.write({REFUSAL!r})
    raise SystemExit(7)
routes = [json.loads(block) for block in re.findall(r"```json\\s*(.*?)\\s*```", prompt, re.S)]
routing = next(row for row in routes if row.get("schema") == "plamen.posix_v2_codex_local_phaseio.v1")
target = Path(next(row["path"] for row in routing["output_routes"]
                   if row["identity"] == "scratchpad:analysis_healthy.md"))
target.write_text(
    "<!-- PLAMEN_ARTIFACT: analysis_healthy.md -->\\n"
    "<!-- PLAMEN_OWNER: B2 -->\\n"
    "<!-- PLAMEN_STATUS: IN_PROGRESS -->\\n"
    "<!-- PLAMEN_PHASE: breadth -->\\n"
    "<!-- PLAMEN_VERSION: 1 -->\\n"
    "<!-- AGENT_ROW: B2 -->\\n"
    "<!-- EXPECTED_OUTPUT: analysis_healthy.md -->\\n\\n"
    "# Healthy breadth sibling\\n\\n## No Findings\\n\\n"
    + ("No exploitable issue was found for this assigned scope. " * 12)
    + "\\n\\n<!-- PLAMEN_FINDINGS_COUNT: 0 -->\\n"
    "<!-- PLAMEN_STATUS: COMPLETE -->\\n",
    encoding="utf-8",
)
if "-o" in sys.argv:
    Path(sys.argv[sys.argv.index("-o") + 1]).write_bytes(b"fixture complete\\n")
print(json.dumps({{"type": "turn.completed"}}, sort_keys=True))
''',
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


@pytest.mark.parametrize("damage", [
    "none", "authority_missing",
    "attempt_completion_relative_path:missing",
    "attempt_completion_relative_path:tampered",
    "provider_completion_relative_path:missing",
    "provider_completion_relative_path:tampered",
    "incorporation_relative_path:missing",
    "incorporation_relative_path:tampered",
])
def test_refusal_checkpoint_retains_active_breadth_sibling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    damage: str,
) -> None:
    if os.name != "posix":
        pytest.skip("real-child fixture requires POSIX compatibility runtime")
    import posix_v2_compat_runtime as compat
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    (project / "Unit.sol").write_text(
        "pragma solidity ^0.8.20; contract Unit {}\n", encoding="utf-8"
    )
    jobs = _manifest(scratchpad)
    _breadth_inputs(scratchpad)
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
        "project_root": str(project.resolve()),
        "_run_id": RUN_ID,
        "_auxiliary_writable_root_startup_binding": durable_startup_permit(
            scratchpad, run_id=RUN_ID
        ),
    }
    config["_audit_snapshot"] = build_audit_snapshot(config, Path(__file__).resolve().parent.parent)
    phase = driver.Phase(
        "breadth", ["breadth"], ["analysis_*.md"],
        base_timeout_s=30, model="gpt-5.6-sol", min_artifact_bytes=1,
    )
    binary = _fake_codex(tmp_path / "codex")
    session = compat.issue_posix_v2_compat_session_for_installed_front(
        run_id=RUN_ID,
        project_root=project,
        scratchpad=scratchpad,
    )
    monkeypatch.setattr(
        driver, "_POSIX_COMPAT_V2_PROCESS_MARKER",
        driver._POSIX_COMPAT_V2_MARKER_TOKEN,
    )
    monkeypatch.setattr(driver, "_POSIX_COMPAT_V2_SESSION_AUTHORITY", session)
    monkeypatch.setattr(compat.shutil, "which", lambda _name: str(binary))
    monkeypatch.setattr(
        compat,
        "_load_ambient_codex_auth",
        lambda: ("PRIVATE_AUTH_JSON_COPY", b'{"tokens":{}}\n', "c" * 64),
    )
    monkeypatch.setattr(driver, "_codex_prompt_fits", lambda *_args: True)

    def dispatch_plan(**_kwargs):
        return [
            {
                "job": dict(job),
                "prompt": f"TARGET={scratchpad / job['output']}\n",
                "prompt_sha256": hashlib.sha256(
                    f"TARGET={scratchpad / job['output']}\n".encode("utf-8")
                ).hexdigest(),
                "skill_dispatch": [],
                "dispatch_contract_sha256": "d" * 64,
            }
            for job in jobs
        ]

    monkeypatch.setattr(driver, "_breadth_dispatch_plan", dispatch_plan)
    try:
        rc = driver._run_breadth_backend_fanout(
            backend="codex",
            phase=phase,
            config=config,
            scratchpad=scratchpad,
            attempt=1,
            timeout=30,
            effective_model="gpt-5.6-sol",
        )
        assert rc == driver._CODEX_WORKER_POLICY_REFUSAL_RC

        ledger_before = artifact_ledger.read_artifact_ledger(scratchpad)
        healthy_key, healthy_before = next(
            (key, unit)
            for key, unit in ledger_before["work_units"].items()
            if "scratchpad:analysis_healthy.md" in unit.get("artifacts", {})
        )
        assert healthy_before["semantic_status"] == "ACTIVE"
        assert healthy_before["execution_state"] == "OUTPUT_COMMITTED"
        assert healthy_before["execution_authority"]["schema"] == (
            "plamen.worker_execution_authority.v1"
        )
        healthy_bytes = json.dumps(
            healthy_before, sort_keys=True, separators=(",", ":")
        )

        evidence = driver._codex_provider_policy_refusal_evidence(
            scratchpad=scratchpad,
            phase_name="breadth",
            attempt=1,
            returncode=rc,
            worker_attempts=(1,),
        )
        assert len(evidence) == 1
        checkpoint = driver.Checkpoint(run_id=RUN_ID)
        receipt = driver._record_codex_provider_policy_refusal(
            phase=phase,
            checkpoint=checkpoint,
            scratchpad=scratchpad,
            config=config,
            attempt=1,
            returncode=rc,
            evidence=evidence,
        )
        receipt_bytes = receipt.read_bytes()

        resumed = driver.Checkpoint.load(scratchpad)
        assert resumed.phase_commits["breadth"].state == "INCOMPLETE_WITH_DEBT"
        assert "breadth" not in resumed.completed
        assert "breadth" in resumed.degraded
        healthy_after = artifact_ledger.read_artifact_ledger(scratchpad)[
            "work_units"
        ][healthy_key]
        assert json.dumps(
            healthy_after, sort_keys=True, separators=(",", ":")
        ) == healthy_bytes
        assert driver._breadth_open_jobs(scratchpad, phase, jobs) == [jobs[0]]
        assert scratchpad.joinpath("_calls_analysis_healthy").read_text(
            encoding="ascii"
        ) == "1"
        assert scratchpad.joinpath("_calls_analysis_refused").read_text(
            encoding="ascii"
        ) == "1"
        assert receipt.read_bytes() == receipt_bytes
        # Retained MODEL authority must replay, not merely retain file bytes.
        def replay_healthy():
            return driver._record_typed_model_worker_artifact(
                phase=phase, config=config, scratchpad=scratchpad,
                project_root=str(project), agent_id="B2", agent_role="general",
                output="analysis_healthy.md", timeout_s=30, focus_area="access",
                attempt=1,
            )

        assert replay_healthy() == []
        artifact_bytes = (scratchpad / "analysis_healthy.md").read_bytes()
        if damage == "authority_missing":
            altered = artifact_ledger.read_artifact_ledger(scratchpad)
            del altered["work_units"][healthy_key]["execution_authority"]
            (scratchpad / "_artifact_state.json").write_text(
                json.dumps(altered), encoding="utf-8"
            )
        elif damage != "none":
            field, mutation = damage.split(":")
            damaged_path = scratchpad / healthy_before["execution_authority"][field]
            if mutation == "missing":
                damaged_path.rename(damaged_path.with_name(damaged_path.name + ".retained"))
            else:
                damaged_path.write_bytes(b"{}\n")
        if damage != "none":
            assert replay_healthy(), "damaged execution lineage must remain debt"
            assert driver._breadth_open_jobs(scratchpad, phase, jobs) == jobs
            assert (scratchpad / "analysis_healthy.md").read_bytes() == artifact_bytes
            assert receipt.read_bytes() == receipt_bytes
            assert scratchpad.joinpath("_calls_analysis_healthy").read_text(encoding="ascii") == "1"
    finally:
        session.close()
