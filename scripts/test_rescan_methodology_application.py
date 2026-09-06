from __future__ import annotations

import hashlib
import json
from pathlib import Path

import methodology_application as A
import plamen_driver as D


def _manifest(scratchpad: Path, *, rows: int = 3) -> None:
    outputs = [f"analysis_rescan_{index}.md" for index in range(1, rows + 1)]
    outputs.append("analysis_percontract_ExampleVault.md")
    (scratchpad / "rescan_manifest.md").write_text(
        "# Rescan Manifest\n\n" + "".join(f"- {name}\n" for name in outputs),
        encoding="utf-8",
    )


def _config(tmp_path: Path) -> dict:
    return {
        "project_root": str(tmp_path),
        "language": "evm",
        "pipeline": "sc",
        "mode": "thorough",
        "cli_backend": "claude",
    }


def test_rescan_jobs_partition_the_methodology_instead_of_cloning_generic_scope(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    _manifest(sp)

    jobs = D._rescan_worker_jobs(sp)
    broad = [job for job in jobs if job["output"].startswith("analysis_rescan_")]
    per_contract = [
        job for job in jobs if job["output"].startswith("analysis_percontract_")
    ]

    assert len({job["focus_area"] for job in broad}) == 3
    assert {"RS-0", "RS-1", "RS-2", "RS-3", "RS-4", "RS-5", "RS-X"} <= {
        step for job in broad for step in job["methodology_steps"]
    }
    assert per_contract[0]["methodology_steps"] == ["RS-X", "RS-PC"]
    assert "ExampleVault" in per_contract[0]["focus_area"]


def test_two_rescan_rows_still_cover_every_broad_step(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    _manifest(sp, rows=2)

    broad = [
        job for job in D._rescan_worker_jobs(sp)
        if job["output"].startswith("analysis_rescan_")
    ]

    assert {"RS-0", "RS-1", "RS-2", "RS-3", "RS-4", "RS-5", "RS-X"} <= {
        step for job in broad for step in job["methodology_steps"]
    }


def test_rescan_dispatch_is_content_and_prompt_bound(tmp_path: Path, monkeypatch):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    _manifest(sp)
    home = tmp_path / "plamen-home"
    method = home / "prompts" / "shared" / "v2" / "phase3b-rescan.md"
    method.parent.mkdir(parents=True)
    method.write_text(
        "# Rescan\n\n## Work Plan\n\n### RS-0\nSelect gap.\n### RS-1\nTrace state.\n",
        encoding="utf-8",
    )
    rule = home / "rules" / "finding-output-format.md"
    rule.parent.mkdir(parents=True)
    rule.write_text("# Finding format\n", encoding="utf-8")
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    # Production pins are deliberately fixed. This isolated authenticated-root
    # fixture supplies its own exact source denominator rather than weakening
    # the runtime guard to accept arbitrary selected bytes.
    monkeypatch.setitem(
        D._BOUND_RESCAN_METHODOLOGY_SOURCE_SHA256,
        "execution",
        hashlib.sha256(method.read_bytes()).hexdigest(),
    )
    monkeypatch.setitem(
        D._BOUND_RESCAN_METHODOLOGY_SOURCE_SHA256,
        "finding_format",
        hashlib.sha256(rule.read_bytes()).hexdigest(),
    )

    plan = D._rescan_dispatch_plan(
        scratchpad=sp,
        project_root=str(tmp_path),
        config=_config(tmp_path),
        attempt=1,
    )

    item = plan[0]
    descriptor = item["methodology_dispatch"][0]
    assert descriptor["sha256"] == hashlib.sha256(method.read_bytes()).hexdigest()
    assert descriptor["top_level_checklist_step_ids"] == plan[0]["job"][
        "methodology_steps"
    ]
    assert item["prompt_sha256"] == hashlib.sha256(
        plan[0]["prompt"].encode("utf-8")
    ).hexdigest()
    contract_entry = {
        "worker_id": item["job"]["agent_id"],
        "output": item["job"]["output"],
        "methodologies": item["methodology_dispatch"],
    }
    assert item["dispatch_contract_sha256"] == A.worker_dispatch_contract_sha256(
        "rescan", contract_entry
    )
    prompt = plan[0]["prompt"]
    assert A.TRACE_JSON_BEGIN in prompt and A.TRACE_JSON_END in prompt
    assert "PLAMEN_DISPATCH_CONTRACT_SHA256" in prompt
    assert "# Finding format" in prompt
    assert str(home).replace("\\", "/") not in prompt.replace("\\", "/")


def test_rescan_dispatch_preserves_completed_rows_on_mixed_retry(
    tmp_path: Path, monkeypatch,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    _manifest(sp, rows=2)
    home = Path(D.__file__).resolve().parents[1]
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    config = _config(tmp_path)
    first = D._rescan_dispatch_plan(
        scratchpad=sp,
        project_root=str(tmp_path),
        config=config,
        attempt=1,
    )
    D._write_rescan_dispatch_contract(
        sp, config, "claude-pty", first,
        dispatched_outputs={item["job"]["output"] for item in first},
    )
    original = {
        item["output"]: item["prompt_sha256"]
        for item in json.loads((sp / A.DISPATCH_FILE).read_text())["phases"]["rescan"]["entries"]
    }
    retried_output = "analysis_rescan_2.md"
    second = D._rescan_dispatch_plan(
        scratchpad=sp,
        project_root=str(tmp_path),
        config=config,
        attempt=2,
        retry_reasons_by_output={retried_output: ["missing trace"]},
    )
    D._write_rescan_dispatch_contract(
        sp, config, "claude-pty", second,
        dispatched_outputs={retried_output},
    )
    current = {
        item["output"]: item["prompt_sha256"]
        for item in json.loads((sp / A.DISPATCH_FILE).read_text())["phases"]["rescan"]["entries"]
    }

    assert current[retried_output] != original[retried_output]
    for output, prompt_sha in original.items():
        if output != retried_output:
            assert current[output] == prompt_sha


def test_rescan_application_reconciles_every_partitioned_step(
    tmp_path: Path, monkeypatch,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    source = tmp_path / "src" / "ExampleVault.sol"
    source.parent.mkdir()
    source.write_text("\n".join(f"line {i}" for i in range(1, 20)), encoding="utf-8")
    _manifest(sp, rows=2)
    home = Path(D.__file__).resolve().parents[1]
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    config = _config(tmp_path)
    plan = D._rescan_dispatch_plan(
        scratchpad=sp,
        project_root=str(tmp_path),
        config=config,
        attempt=1,
    )
    D._write_rescan_dispatch_contract(
        sp, config, "claude-pty", plan,
        dispatched_outputs={item["job"]["output"] for item in plan},
    )
    for item in plan:
        job = item["job"]
        (sp / f"_prompt_rescan_worker_{Path(job['output']).stem}.attempt1.md").write_text(
            item["prompt"], encoding="utf-8", newline="\n"
        )
        markers = A.worker_dispatch_markers(
            "rescan", job["agent_id"], job["output"],
            item["dispatch_contract_sha256"],
        )
        rows = [
            {
                "skill": "RESCAN_METHOD",
                "step": step,
                "executed": "yes",
                "evidence": "src/ExampleVault.sol:L1",
                "result": f"{step} traced a concrete assigned source transition",
            }
            for step in job["methodology_steps"]
        ]
        (sp / job["output"]).write_text(
            markers
            + "\n\n## No Findings\n\nNo candidate survived.\n\n"
            + A.TRACE_HEADING
            + "\n\n"
            + A.TRACE_JSON_BEGIN
            + "\n"
            + json.dumps({"schema_version": 1, "rows": rows})
            + "\n"
            + A.TRACE_JSON_END
            + "\n\n<!-- PLAMEN_STATUS: COMPLETE -->\n",
            encoding="utf-8",
        )

    result = A.validate_phase_application(
        sp, tmp_path, phase="rescan", trusted_methodology_roots=[home]
    )

    assert result["status"] == "ATTESTED", result
    assert result["expected_steps"] == sum(
        len(item["job"]["methodology_steps"]) for item in plan
    )
    assert result["gap_steps"] == 0
