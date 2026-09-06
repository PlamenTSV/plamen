"""L1 recon must use the backend-neutral transactional role fanout."""
from __future__ import annotations

from pathlib import Path

import pytest

import plamen_driver as D
from artifact_ledger import read_artifact_ledger
from phase_io_contracts import resolve_phase_io_contract


def _config(root: Path, *, mode: str = "thorough") -> dict:
    return {
        "pipeline": "l1",
        "mode": mode,
        "language": "rust",
        "cli_backend": "codex",
        "project_root": str(root),
        "scratchpad": str(root),
        "_run_id": "run-l1-recon",
    }


def _shard(job: dict[str, str]) -> str:
    return (
        f"<!-- PLAMEN_ARTIFACT: {job['output']} -->\n"
        f"<!-- PLAMEN_OWNER: {job['agent_id']} -->\n"
        "<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
        "<!-- PLAMEN_PHASE: recon -->\n"
        "<!-- PLAMEN_VERSION: 1 -->\n"
        f"<!-- RECON_ROLE: {job['role']} -->\n"
        f"<!-- EXPECTED_OUTPUT: {job['output']} -->\n\n"
        f"# L1 Recon {job['role']}\n\n"
        "## Evidence\n\n"
        "- `src/lib.rs:L10` was inspected for externally reachable behavior.\n"
        "- `src/state.rs:L20` was inspected for state and trust transitions.\n"
        "- The role enumerated its full assigned denominator and recorded "
        "unresolved questions without asserting safety.\n\n"
        "## Canonical Merge Hints\n\n"
        f"- Merge the {job['role']} evidence into its L1 canonical artifacts.\n\n"
        "<!-- PLAMEN_STATUS: COMPLETE -->\n"
    )


def test_l1_recon_pool_is_enabled_and_has_nonoverlapping_role_roster(
    tmp_path: Path,
) -> None:
    cfg = _config(tmp_path)
    jobs = D._recon_worker_jobs(cfg)
    assert D._should_use_recon_worker_pool(cfg, tmp_path)
    assert [row["role"] for row in jobs] == [
        "l1_threat_fork",
        "l1_subsystem_scope",
        "l1_attack_trust",
        "l1_build_static",
        "l1_templates_patterns",
    ]
    assert len({row["output"] for row in jobs}) == len(jobs) == 5
    assert len(D._recon_worker_jobs(_config(tmp_path, mode="light"))) == 3


def test_l1_recon_worker_prompt_is_l1_specific_and_single_output(
    tmp_path: Path,
) -> None:
    cfg = _config(tmp_path)
    job = D._recon_worker_jobs(cfg)[0]
    prompt = D._build_recon_worker_prompt(
        job=job,
        scratchpad=tmp_path,
        project_root=str(tmp_path),
        config=cfg,
        attempt=1,
    )
    assert "prompts/l1/v2/phase1-recon-prompt.md" in prompt
    assert "There is no recon coordinator" in prompt
    assert "Write exactly this file and no other scratchpad artifact" in prompt
    assert job["output"] in prompt
    for other in D._recon_worker_jobs(cfg)[1:]:
        assert f"`{tmp_path.as_posix()}/{other['output']}`" not in prompt
    assert "forge build" not in prompt
    assert "Do not run tests, fuzzers, PoCs, or verification commands" in prompt


def test_l1_recon_worker_phaseio_binds_bake_status_not_sc_inputs() -> None:
    contract = resolve_phase_io_contract(
        pipeline="l1",
        mode="thorough",
        ecosystem="rust",
        backend="claude",
        phase="recon",
        work_unit_id="worker.r1",
        exact_outputs=("recon_l1_threat_fork.md",),
    )
    assert contract.immutable_inputs == (
        "scratchpad:primitive_status.md",
    )
    assert contract.bounded_lookup_inputs == ()


def test_l1_recon_merge_projects_all_canonical_outputs_without_loss(
    tmp_path: Path,
) -> None:
    cfg = _config(tmp_path)
    (tmp_path / "primitive_status.md").write_text(
        "BAKE_EXECUTION=DRIVER_CAPABILITY_PROBE_ONLY\n",
        encoding="utf-8",
    )
    jobs = D._recon_worker_jobs(cfg)
    for job in jobs:
        (tmp_path / job["output"]).write_text(
            _shard(job), encoding="utf-8", newline="\n"
        )

    written = D._merge_recon_worker_shards(tmp_path, cfg)

    expected = {
        "recon_summary.md",
        "threat_model.md",
        "subsystem_map.md",
        "attack_surface.md",
        "trust_boundaries.md",
        "template_recommendations.md",
        "scope_leftover.md",
    }
    assert expected.issubset(set(written))
    for name in expected:
        raw = (tmp_path / name).read_text(encoding="utf-8")
        assert "PLAMEN_STATUS" not in raw
        assert len(raw.encode("utf-8")) >= 120
    summary = (tmp_path / "recon_summary.md").read_text(encoding="utf-8")
    for job in jobs:
        assert job["role"] in summary


@pytest.mark.parametrize("backend", ["claude", "codex"])
def test_l1_recon_leaf_authority_is_backend_specific_but_logically_equal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
) -> None:
    cfg = _config(tmp_path)
    cfg["cli_backend"] = backend
    (tmp_path / "primitive_status.md").write_text(
        "BAKE_EXECUTION=DRIVER_CAPABILITY_PROBE_ONLY\n",
        encoding="utf-8",
    )
    phase = next(row for row in D.L1_PHASES if row.name == "recon")
    job = D._recon_worker_jobs(cfg)[0]
    monkeypatch.setattr(
        D,
        "_live_phase_runtime_launch_policy",
        lambda *_args: {
            "backend": backend,
            "model": "fixture",
            "timeout_s": 30,
            "exec_mode": "headless",
        },
    )
    assert D._prepare_typed_model_worker_launch(
        phase=phase,
        config=cfg,
        scratchpad=tmp_path,
        project_root=str(tmp_path),
        agent_id=job["agent_id"],
        output=job["output"],
        timeout_s=30,
    ) == []
    ledger = read_artifact_ledger(tmp_path)
    unit = next(iter(ledger["work_units"].values()))
    assert unit["input_bindings"]["scratchpad:primitive_status.md"][
        "status"
    ] == "ACTIVE"
