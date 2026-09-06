"""R61: restricted rescan rows consume methodology from the bound prompt."""
from __future__ import annotations

from pathlib import Path

import claude_worker_prompt_consistency as C
import headless_worker_runtime as H
import plamen_driver as D
from phase_contract_compiler import extract_compiled_phase_io


R61_OUTPUTS = (
    "analysis_rescan_1.md",
    "analysis_rescan_2.md",
    "analysis_rescan_3.md",
    "analysis_percontract_GatewayCrossChain.md",
    "analysis_percontract_GatewaySend.md",
    "analysis_percontract_GatewayTransferNative.md",
    "analysis_percontract_IDODORouteProxy.md",
    "analysis_percontract_IUniswapV2Factory.md",
    "analysis_percontract_IUniswapV2Router01.md",
)


def _r61_plan(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (tmp_path / "src").mkdir()
    (scratchpad / "rescan_manifest.md").write_text(
        "# Rescan Manifest\n\n"
        + "\n".join(f"| {name} |" for name in R61_OUTPUTS)
        + "\n",
        encoding="utf-8",
    )
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(tmp_path),
        "scratchpad": str(scratchpad),
        "_run_id": "r61-projection-regression",
    }
    plan = D._rescan_dispatch_plan(
        scratchpad=scratchpad,
        project_root=str(tmp_path),
        config=config,
        attempt=1,
    )
    return scratchpad, config, plan


def test_exact_r61_rescan_and_percontract_prompts_embed_bound_methodology(
    tmp_path: Path,
) -> None:
    scratchpad, config, plan = _r61_plan(tmp_path)
    assert tuple(row["job"]["output"] for row in plan) == R61_OUTPUTS
    assert tuple(row["job"]["agent_id"] for row in plan) == (
        "R1", "R2", "R3", "PC1", "PC2", "PC3", "PC4", "PC5", "PC6",
    )

    installed_home = str(D.plamen_home().resolve()).replace("\\", "/").casefold()
    for row in plan:
        prompt = row["prompt"]
        normalized_prompt = prompt.replace("\\", "/").casefold()
        assert installed_home not in normalized_prompt
        assert "~/.plamen" not in normalized_prompt
        assert "~/.claude" not in normalized_prompt
        assert "read `prompts/shared/v2/phase3b-rescan.md`" not in normalized_prompt
        assert "read `rules/finding-output-format.md`" not in normalized_prompt
        assert "Logical source: `prompts/shared/v2/phase3b-rescan.md`" in prompt
        assert "Logical source: `rules/finding-output-format.md`" in prompt
        assert D._SC_RESCAN_WORKER_EXECUTION_PROJECTION.rstrip("\n") in prompt
        assert (
            D.plamen_home() / "rules" / "finding-output-format.md"
        ).read_text(encoding="utf-8").rstrip("\n") in prompt
        assert prompt.count("<!-- PLAMEN_BOUND_METHODOLOGY_BEGIN:") == 2
        assert prompt.count("<!-- PLAMEN_BOUND_METHODOLOGY_END:") == 2
        assert prompt.count("Source SHA-256: `") == 2
        assert prompt.count("Effective projection SHA-256: `") == 2
        assert D._trusted_methodology_paths_named_by_prompt(
            prompt, {"methodology_read_roots": [str(D.plamen_home())]}
        ) == ()

        contract = extract_compiled_phase_io(prompt)
        exact_inputs = D._typed_worker_registered_input_paths(
            phase_name="rescan",
            scratchpad=scratchpad,
            config=config,
            agent_id=str(row["job"]["agent_id"]),
            agent_role="rescan",
            output=str(row["job"]["output"]),
            work_category=(
                "per_contract"
                if str(row["job"]["output"]).startswith("analysis_percontract_")
                else "rescan"
            ),
            focus_area=str(row["job"]["focus_area"]),
            attempt=1,
        )
        assert set(contract["immutable_inputs"]) == {
            f"scratchpad:{name}" for name in exact_inputs
        }
        assert contract["allowed_outputs"] == [
            f"scratchpad:{row['job']['output']}"
        ]
        issues = C.validate_claude_worker_prompt_consistency(
            prompt,
            phase_io_inputs=[scratchpad / name for name in exact_inputs],
            phase_io_outputs=[scratchpad / str(row["job"]["output"])],
            policy_tools=["Read", "Write", "Glob", "Grep"],
            safe_search_roots=[tmp_path / "src"],
            project_root=tmp_path,
            scratchpad_root=scratchpad,
        )
        assert issues == ()


def test_rescan_provider_prompt_routes_only_to_attempt_stage(tmp_path: Path) -> None:
    scratchpad, _config, plan = _r61_plan(tmp_path)
    row = next(item for item in plan if item["job"]["agent_id"] == "PC4")
    output = str(row["job"]["output"])
    private_output = (
        Path(".scratchpad")
        / ".worker_transactions"
        / "rescan"
        / "worker.pc4"
        / "attempts"
        / "attempt-private"
        / "output"
    )
    provider_prompt = H._route_prompt(
        row["prompt"],
        output_directory=private_output,
        output_paths=(output,),
    ).decode("utf-8")

    canonical_output = (scratchpad / output).as_posix()
    staged_output = (private_output / output).as_posix()
    assert canonical_output not in provider_prompt
    assert f"`{output}` -> `{staged_output}`" in provider_prompt
    assert "Do not write the canonical scratchpad\npath" in provider_prompt
    assert "path` equal to one exact file" in provider_prompt
    assert "Never Grep the scratchpad directory" in provider_prompt


def test_exact_r61_rows_prebind_transactionally_without_methodology_authority(
    tmp_path: Path,
) -> None:
    scratchpad, config, plan = _r61_plan(tmp_path)
    phase = next(item for item in D.SC_PHASES if item.name == "rescan")

    for row in plan:
        job = row["job"]
        category = (
            "per_contract"
            if str(job["output"]).startswith("analysis_percontract_")
            else "rescan"
        )
        exact_inputs = D._typed_worker_registered_input_paths(
            phase_name="rescan",
            scratchpad=scratchpad,
            config=config,
            agent_id=str(job["agent_id"]),
            agent_role="rescan",
            output=str(job["output"]),
            work_category=category,
            focus_area=str(job["focus_area"]),
            attempt=1,
        )
        assert D._prepare_typed_model_worker_launch(
            phase=phase,
            config=config,
            scratchpad=scratchpad,
            project_root=str(tmp_path),
            agent_id=str(job["agent_id"]),
            agent_role="rescan",
            output=str(job["output"]),
            timeout_s=120,
            work_category=category,
            focus_area=str(job["focus_area"]),
            exact_inputs=exact_inputs,
            attempt=1,
        ) == []

    ledger = D.read_artifact_ledger(scratchpad)
    rescan_units = {
        key: unit
        for key, unit in ledger["work_units"].items()
        if "/rescan/" in key
    }
    assert len(rescan_units) == 9
    assert all(
        not any("phase3b-rescan.md" in identity or "finding-output-format.md" in identity
                for identity in unit["input_bindings"])
        for unit in rescan_units.values()
    )


def test_rescan_projection_source_digest_drift_is_fail_closed(
    tmp_path: Path, monkeypatch,
) -> None:
    source = D.plamen_home() / "prompts" / "shared" / "v2" / "phase3b-rescan.md"
    real_hash = D._BOUND_RESCAN_METHODOLOGY_SOURCE_SHA256["execution"]
    monkeypatch.setitem(
        D._BOUND_RESCAN_METHODOLOGY_SOURCE_SHA256,
        "execution",
        "0" * 64,
    )
    try:
        scratchpad = tmp_path / ".scratchpad"
        scratchpad.mkdir()
        (scratchpad / "rescan_manifest.md").write_text(
            "# Rescan Manifest\n- analysis_rescan_1.md\n",
            encoding="utf-8",
        )
        config = {
            "pipeline": "sc", "mode": "thorough", "language": "evm",
            "cli_backend": "claude", "project_root": str(tmp_path),
            "scratchpad": str(scratchpad),
        }
        job = D._rescan_worker_jobs(scratchpad)[0]
        try:
            D._build_rescan_worker_prompt(
                job=job,
                scratchpad=scratchpad,
                project_root=str(tmp_path),
                config=config,
                attempt=1,
            )
        except ValueError as exc:
            assert "digest drifted" in str(exc)
        else:
            raise AssertionError("rescan source drift was accepted")
    finally:
        D._BOUND_RESCAN_METHODOLOGY_SOURCE_SHA256["execution"] = real_hash
    assert source.is_file()
