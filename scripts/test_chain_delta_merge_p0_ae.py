"""P0-AE: chain iteration 2 emits an immutable model delta.

The deterministic driver is the only writer allowed to merge that delta into
the two downstream aggregate artifacts.  These are lifecycle fixtures: a
collision must preserve both inputs, a repeated merge must be byte-idempotent,
and a successful merge must carry digest-bound recall-monotonic evidence.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import chain_tail_authority as CTA
import plamen_driver as D
import plamen_validators as V


CONFIG = {
    "pipeline": "sc",
    "mode": "thorough",
    "language": "evm",
    "cli_backend": "claude",
}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _seed(scratchpad: Path, *, delta_id: str = "CH-02") -> None:
    scratchpad.mkdir()
    CTA.initialize_chain_tail(
        scratchpad,
        [],
        shard_size=1,
        activate_first_shard=False,
    )
    (scratchpad / "chain_hypotheses.md").write_text(
        "# Chain Hypotheses\n\n"
        "## Chain Hypothesis CH-01\n\n"
        "### Chain Match\n- Match Strength: STRONG\n",
        encoding="utf-8",
    )
    (scratchpad / "composition_coverage.md").write_text(
        "# Composition Coverage\n\n"
        "| Finding A | Finding B | Explored? | Result | Notes |\n"
        "|---|---|---|---|---|\n"
        "| H-01 | M-01 | YES | COMPOSED CH-01 | baseline |\n",
        encoding="utf-8",
    )
    (scratchpad / "chain_iteration2.md").write_text(
        "# Chain Iteration 2\n\n"
        f"## Chain Hypothesis {delta_id}\n\n"
        "### Blocked Finding (A)\n- ID: H-02\n\n"
        "### Enabler Finding (B)\n- ID: M-02\n\n"
        "### Chain Match\n- Match Strength: MODERATE\n\n"
        "### Combined Attack Sequence\n1. State transition\n2. Follow-on effect\n\n"
        "## Tail Pair Dispositions\n\n"
        "| Finding A | Finding B | Disposition | Evidence |\n"
        "|---|---|---|---|\n"
        f"| H-02 | M-02 | COMPOSED | {delta_id} supported by source comparison |\n\n"
        "DONE: 1 new chains from 1 unexplored pairs\n",
        encoding="utf-8",
    )
    (scratchpad / "chain_candidate_pairs_iter2.md").write_text(
        "# Iteration 2 Pair Packet\n", encoding="utf-8",
    )
    (scratchpad / "findings_inventory.md").write_text(
        "# Findings Inventory\n", encoding="utf-8",
    )


def test_prompts_and_owned_outputs_make_model_delta_only():
    root = Path(__file__).resolve().parents[1]
    iter2 = (root / "prompts/shared/v2/phase4c-chain-iter2.md").read_text(
        encoding="utf-8"
    )
    agent2 = (root / "prompts/shared/v2/phase4c-chain-agent2.md").read_text(
        encoding="utf-8"
    )
    assert "Write only `{SCRATCHPAD}/chain_iteration2.md`" in iter2
    assert "MUST NOT modify `chain_hypotheses.md`" in iter2
    assert "Do **not** update `{SCRATCHPAD}/hypotheses.md`" in agent2
    owned = V._owned_artifact_patterns("sc")
    assert owned["chain_iter2"] == ["chain_iteration2.md"]


def test_driver_merge_adds_chain_and_coverage_with_typed_events(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    _seed(sp)

    result = D._apply_chain_iter2_driver_merge(sp, CONFIG)

    assert result["status"] == "APPLIED"
    assert result["issues"] == []
    assert result["added_chain_ids"] == ["CH-02"]
    chain = (sp / "chain_hypotheses.md").read_text(encoding="utf-8")
    coverage = (sp / "composition_coverage.md").read_text(encoding="utf-8")
    assert chain.count("## Chain Hypothesis CH-02") == 1
    assert "| H-02 | M-02 | COMPOSED |" in coverage
    assert len(result["events"]) == 2
    assert all(event["source_identities"] == ["scratchpad:chain_iteration2.md"]
               for event in result["events"])
    assert result["events"][0]["identities_before"]
    assert set(result["events"][0]["identities_before"]) <= set(
        result["events"][0]["identities_after"]
    )
    receipt = json.loads(
        (
            sp / "_chain_iter2_merge_receipt.p0000.s0000.json"
        ).read_text(encoding="utf-8")
    )
    assert receipt == result


def test_driver_merge_is_byte_idempotent_on_identical_resume(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    _seed(sp)
    first = D._apply_chain_iter2_driver_merge(sp, CONFIG)
    paths = (
        sp / "chain_hypotheses.md",
        sp / "composition_coverage.md",
        sp / "_chain_iter2_merge_receipt.p0000.s0000.json",
    )
    before = {path.name: (_sha(path), path.stat().st_mtime_ns) for path in paths}

    second = D._apply_chain_iter2_driver_merge(sp, CONFIG)

    after = {path.name: (_sha(path), path.stat().st_mtime_ns) for path in paths}
    assert second == first
    assert after == before
    assert second["status"] == "APPLIED"


def test_collision_preserves_source_and_aggregates_and_records_debt(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    _seed(sp, delta_id="CH-01")
    tracked = (
        sp / "chain_iteration2.md",
        sp / "chain_hypotheses.md",
        sp / "composition_coverage.md",
    )
    before = {path.name: _sha(path) for path in tracked}

    result = D._apply_chain_iter2_driver_merge(sp, CONFIG)

    assert result["status"] == "FAILED"
    assert result["collision_ids"] == ["CH-01"]
    assert any("collision" in issue.lower() for issue in result["issues"])
    assert {path.name: _sha(path) for path in tracked} == before
    assert (sp / "chain_iter2.degraded").exists()


def test_duplicate_id_inside_delta_is_rejected_without_mutation(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    _seed(sp)
    delta = sp / "chain_iteration2.md"
    delta.write_text(
        delta.read_text(encoding="utf-8")
        + "\n## Chain Hypothesis CH-02\n\nsecond definition\n",
        encoding="utf-8",
    )
    before = {
        name: _sha(sp / name)
        for name in ("chain_hypotheses.md", "composition_coverage.md")
    }

    result = D._apply_chain_iter2_driver_merge(sp, CONFIG)

    assert result["status"] == "FAILED"
    assert any("duplicate" in issue.lower() for issue in result["issues"])
    assert {
        name: _sha(sp / name)
        for name in ("chain_hypotheses.md", "composition_coverage.md")
    } == before


def test_changed_delta_cannot_reuse_a_completed_receipt(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    _seed(sp)
    D._apply_chain_iter2_driver_merge(sp, CONFIG)
    delta = sp / "chain_iteration2.md"
    delta.write_text(
        delta.read_text(encoding="utf-8").replace("source comparison", "changed"),
        encoding="utf-8",
    )

    result = D._apply_chain_iter2_driver_merge(sp, CONFIG)

    assert result["status"] == "FAILED"
    assert any("source digest" in issue.lower() for issue in result["issues"])


def test_generic_model_cannot_replace_exact_tail_reconcile_merge_parent(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    _seed(sp)
    config = {
        **CONFIG,
        "project_root": str(tmp_path),
        "_run_id": "run-chain-fixture",
    }

    # Establish the real causal producer chain.  Pre-existing Markdown is not
    # allowed to manufacture either MODEL or DRIVER authority after the fact.
    chain_text = (sp / "chain_hypotheses.md").read_text(encoding="utf-8")
    coverage_text = (sp / "composition_coverage.md").read_text(encoding="utf-8")
    delta_text = (sp / "chain_iteration2.md").read_text(encoding="utf-8")
    for name in (
        "chain_hypotheses.md",
        "composition_coverage.md",
        "chain_iteration2.md",
    ):
        (sp / name).unlink()
    for name in (
        "hypotheses.md",
        "finding_mapping.md",
        "enabler_results.md",
        "variable_finding_map.md",
        "chain_candidate_pairs.md",
    ):
        (sp / name).write_text(f"# {name}\n", encoding="utf-8")

    chain_inputs = (
        "hypotheses.md",
        "finding_mapping.md",
        "enabler_results.md",
        "variable_finding_map.md",
        "chain_candidate_pairs.md",
        "findings_inventory.md",
    )
    chain_contract = D.resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="chain_agent2",
        work_unit_id="model",
        exact_inputs=chain_inputs,
    )
    chain_launch = D.LaunchSpec(
        work_unit_key=chain_contract.key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        model="claude",
        timeout_s=120,
        exec_mode="pty",
    )
    D.record_work_unit_inputs(
        sp, tmp_path, chain_contract, chain_launch,
        run_id=config["_run_id"],
    )
    (sp / "chain_hypotheses.md").write_text(chain_text, encoding="utf-8")
    (sp / "composition_coverage.md").write_text(coverage_text, encoding="utf-8")
    (sp / "synthesis_full.md").write_text("# Synthesis\n", encoding="utf-8")
    D.record_work_unit_artifacts(
        sp, tmp_path, chain_contract, chain_launch,
        run_id=config["_run_id"], actor="MODEL",
    )

    iter_contract = D.resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="chain_iter2",
        work_unit_id="model",
        exact_inputs=(
            "chain_candidate_pairs_iter2.md",
            "composition_coverage.md",
            "chain_hypotheses.md",
            "findings_inventory.md",
        ),
    )
    iter_launch = D.LaunchSpec(
        work_unit_key=iter_contract.key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        model="claude",
        timeout_s=120,
        exec_mode="pty",
    )
    D.record_work_unit_inputs(
        sp, tmp_path, iter_contract, iter_launch,
        run_id=config["_run_id"],
    )
    (sp / "chain_iteration2.md").write_text(delta_text, encoding="utf-8")
    D.record_work_unit_artifacts(
        sp, tmp_path, iter_contract, iter_launch,
        run_id=config["_run_id"], actor="MODEL",
    )

    receipt, issues = D._run_and_record_chain_iter2_driver_merge(sp, config)
    assert receipt["status"] == "FAILED"
    assert issues == [
        "chain iteration 2 driver merge requires the exact committed "
        "tail_reconcile parent"
    ]
    ledger = json.loads((sp / "_artifact_state.json").read_text(encoding="utf-8"))
    model_key = "sc/thorough/evm/claude/chain_iter2/model"
    merge_key = (
        "sc/thorough/evm/claude/chain_iter2/"
        "driver_merge.p0000.s0000"
    )
    assert set(ledger["work_units"][model_key]["artifacts"]) == {
        "scratchpad:chain_iteration2.md"
    }
    assert merge_key not in ledger["work_units"]


def test_live_chain_iter2_prompt_carries_typed_exact_contract(tmp_path: Path):
    from phase_contract_compiler import extract_compiled_phase_io
    from plamen_prompt import build_phase_prompt, plamen_home
    from plamen_types import SC_PHASES

    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    phase = next(item for item in SC_PHASES if item.name == "chain_iter2")
    prompt = build_phase_prompt(
        plamen_home() / "commands" / "plamen.md",
        phase,
        {
            "pipeline": "sc",
            "mode": "thorough",
            "language": "evm",
            "cli_backend": "claude",
            "scratchpad": str(sp),
            "project_root": str(tmp_path),
            "proven_only": False,
        },
    )
    payload = extract_compiled_phase_io(prompt)
    assert payload["work_unit_key"] == (
        "sc/thorough/evm/claude/chain_iter2/model"
    )
    assert payload["allowed_outputs"] == ["scratchpad:chain_iteration2.md"]
    assert "scratchpad:chain_hypotheses.md" in payload["immutable_inputs"]
