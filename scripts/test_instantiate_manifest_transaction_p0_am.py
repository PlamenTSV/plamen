"""Typed instantiate proposal/canonical successor regression fixtures."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import plamen_driver as D
import plamen_validators as V
import skill_selection_authority as S
from artifact_ledger import read_artifact_ledger


def _phase() -> D.Phase:
    return D.Phase(
        name="instantiate",
        section_markers=["## Instantiate"],
        expected_artifacts=["spawn_manifest.md"],
        base_timeout_s=30,
        model="sonnet",
        min_artifact_bytes=1,
    )


def _config(root: Path, backend: str = "claude") -> dict:
    return {
        "pipeline": "sc",
        "mode": "core",
        "language": "evm",
        "cli_backend": backend,
        "claude_exec_mode": "headless",
        "project_root": str(root),
        "scratchpad": str(root),
        "_run_id": "run-instantiate",
        "_active_model_attempts": {"instantiate": 1},
    }


def _seed_inputs(root: Path) -> dict[str, bytes]:
    values = {
        "skill_selection_catalog.json": b"{}\n",
        "template_recommendations.md": (
            b"# Template Recommendations\n\n"
            b"## Binding Manifest\n\nNo required skill rows.\n"
        ),
        "detected_patterns.md": (
            b"# Detected Patterns\n\nMISSING_EVENT = YES\n"
        ),
        "design_context.md": b"# Design Context\n\nSimple fixture.\n",
        "attack_surface.md": b"# Attack Surface\n\nOne entry point.\n",
        "contract_inventory.md": (
            b"# Contract Inventory\n\n| File | Lines |\n|---|---:|\n"
            b"| src/A.sol | 10 |\n"
        ),
        "function_list.md": b"# Functions\n\n- A.f\n",
        "state_variables.md": b"# State\n\n- A.value\n",
    }
    for name, raw in values.items():
        (root / name).write_bytes(raw)
    return values


def _proposal(*, extra_niche: str = "") -> str:
    niche_row = ""
    if extra_niche:
        slug = extra_niche.lower().replace("_", "-")
        niche_row = (
            f"| {extra_niche} | model-positive | YES | niche-{slug} | "
            f"niche_{extra_niche.lower()}_findings.md |\n"
        )
    return (
        "# Spawn Manifest\n\n"
        "## Breadth Agents\n\n"
        "| Row Type | Template | Required? | Agent ID | Focus Area | "
        "Expected Output | Status |\n"
        "|---|---|---|---|---|---|---|\n"
        "| AGENT | GENERAL | YES | B1 | state | analysis_state.md | QUEUED |\n"
        "| AGENT | GENERAL | YES | B2 | access | analysis_access.md | QUEUED |\n"
        "| AGENT | GENERAL | YES | B3 | external | analysis_external.md | QUEUED |\n"
        "\n## Niche Agents\n\n"
        "| Niche Agent | Trigger | Required? | Agent ID | Expected Output |\n"
        "|---|---|---|---|---|\n"
        f"{niche_row}"
        "\n## Skill Bindings\n\n"
        "| Skill | Type | Inject Into | Delivery Mode |\n"
        "|---|---|---|---|\n"
        "\n**Gate Check**: All REQUIRED templates have agents? YES\n"
    )


def _seed_r51_depth_only_catalog(root: Path) -> None:
    catalog = {
        "schema": S.SELECTION_SCHEMA,
        "authority": {
            "ecosystem": "evm",
            "pipeline": "sc",
            "mode": "core",
            "backend": "claude",
        },
        "skills": [
            {
                "skill_id": "CROSS_CHAIN_TIMING",
                "state": "REQUIRED",
                "consumer_metadata_status": "CURRENT",
                "index_consumers": ["depth:external"],
            },
            {
                "skill_id": "STORAGE_LAYOUT_SAFETY",
                "state": "REQUIRED",
                "consumer_metadata_status": "CURRENT",
                "index_consumers": ["depth:edge_case", "depth:state_trace"],
            },
            {
                "skill_id": "INTEGRATION_HAZARD_RESEARCH",
                "state": "REQUIRED",
                "consumer_metadata_status": "CURRENT",
                "index_consumers": ["depth:external"],
            },
        ],
        "debts": [],
        "status": "CURRENT",
    }
    catalog["artifact_sha256"] = S.authority_artifact_digest(catalog)
    S.write_authority_artifact(root / "skill_selection_catalog.json", catalog)
    (root / "template_recommendations.md").write_text(
        "# Template Recommendations\n\n"
        "## BINDING MANIFEST\n\n"
        "| Skill | Trigger | Required | Rationale |\n"
        "|---|---|---|---|\n"
        "| CROSS_CHAIN_TIMING | cross-chain timing | YES | r52 |\n"
        "| STORAGE_LAYOUT_SAFETY | upgrade storage | YES | r52 |\n"
        "| INTEGRATION_HAZARD_RESEARCH | integration | YES | r52 |\n",
        encoding="utf-8",
        newline="\n",
    )


def _r51_proposal(*, compatible: bool) -> str:
    b4_template = "GENERAL" if compatible else "CROSS_CHAIN_TIMING"
    b5_template = "GENERAL" if compatible else "STORAGE_LAYOUT_SAFETY"
    if compatible:
        bindings = (
            "| CROSS_CHAIN_TIMING | Standard | depth-external | Full SKILL.md |\n"
            "| INTEGRATION_HAZARD_RESEARCH | Injectable | depth-external | Full SKILL.md |\n"
            "| STORAGE_LAYOUT_SAFETY | Standard | depth-edge-case | Full SKILL.md |\n"
            "| STORAGE_LAYOUT_SAFETY | Standard | depth-state-trace | Full SKILL.md |\n"
        )
    else:
        bindings = (
            "| INTEGRATION_HAZARD_RESEARCH | Injectable | B5 | Header extract |\n"
        )
    return (
        "# Spawn Manifest\n\n"
        "## Breadth Agents\n\n"
        "| Row Type | Template | Required? | Agent ID | Focus Area | Expected Output | Status |\n"
        "|---|---|---|---|---|---|---|\n"
        "| AGENT | GENERAL | YES | B1 | core_state | analysis_core.md | QUEUED |\n"
        f"| AGENT | {b4_template} | YES | B4 | token_flow_timing | analysis_timing.md | QUEUED |\n"
        f"| AGENT | {b5_template} | YES | B5 | storage_layout_upgrade | analysis_storage.md | QUEUED |\n"
        "\n## Skill Bindings\n\n"
        "| Skill | Type | Inject Into | Delivery Mode |\n"
        "|---|---|---|---|\n"
        f"{bindings}"
        "\n**Gate Check**: All REQUIRED templates have agents? YES\n"
    )


def _r60_proposal(*, invalid_retry: bool) -> str:
    templates = {
        3: "STORAGE_LAYOUT_SAFETY" if invalid_retry else "GENERAL",
        5: "CROSS_CHAIN_TIMING" if invalid_retry else "GENERAL",
    }
    count = 9 if invalid_retry else 6
    rows = "".join(
        f"| AGENT | {templates.get(i, 'GENERAL')} | YES | B{i} | "
        f"focus_{i} | analysis_focus_{i}.md | QUEUED |\n"
        for i in range(1, count + 1)
    )
    bindings = (
        "| INTEGRATION_HAZARD_RESEARCH | Injectable | B7 | summary |\n"
        if invalid_retry
        else (
            "| CROSS_CHAIN_TIMING | Standard | depth-external | full |\n"
            "| INTEGRATION_HAZARD_RESEARCH | Injectable | depth-external | full |\n"
            "| STORAGE_LAYOUT_SAFETY | Standard | depth-edge-case | full |\n"
            "| STORAGE_LAYOUT_SAFETY | Standard | depth-state-trace | full |\n"
        )
    )
    return (
        "# Spawn Manifest Proposal\n\n## Breadth Agents\n\n"
        "| Row Type | Template | Required? | Agent ID | Focus Area | Expected Output | Status |\n"
        "|---|---|---|---|---|---|---|\n"
        + rows
        + "\n## Skill Bindings\n\n"
        "| Skill | Type | Inject Into | Delivery Mode |\n"
        "|---|---|---|---|\n"
        + bindings
        + "\n**Gate Check**: All REQUIRED templates have agents? YES\n"
    )


def _bind_and_commit_proposal(
    root: Path,
    config: dict,
    proposal: str,
) -> None:
    phase = _phase()
    assert D._bind_typed_model_phase_inputs(phase, root, config) == []
    (root / "spawn_manifest_proposal.md").write_text(
        proposal, encoding="utf-8", newline="\n"
    )
    assert D._record_typed_model_phase_artifacts(phase, root, config) == []


def test_r51_ineligible_breadth_bindings_fail_before_canonical_commit(
    tmp_path: Path,
) -> None:
    _seed_inputs(tmp_path)
    _seed_r51_depth_only_catalog(tmp_path)
    config = _config(tmp_path)
    _bind_and_commit_proposal(tmp_path, config, _r51_proposal(compatible=False))

    issues = D._run_instantiate_manifest_reconcile_transaction(
        _phase(), tmp_path, config
    )

    assert {
        ("CROSS_CHAIN_TIMING", "breadth:B4"),
        ("STORAGE_LAYOUT_SAFETY", "breadth:B5"),
        ("INTEGRATION_HAZARD_RESEARCH", "breadth:B5"),
    } <= {
        (skill, consumer)
        for issue in issues
        for skill in (
            "CROSS_CHAIN_TIMING",
            "STORAGE_LAYOUT_SAFETY",
            "INTEGRATION_HAZARD_RESEARCH",
        )
        for consumer in ("breadth:B4", "breadth:B5")
        if skill in issue and consumer in issue
    }
    assert not (tmp_path / "spawn_manifest.md").exists()
    assert not (tmp_path / D._INSTANTIATE_RECONCILE_RECEIPT).exists()


def test_r51_compatible_depth_bindings_commit(tmp_path: Path) -> None:
    _seed_inputs(tmp_path)
    _seed_r51_depth_only_catalog(tmp_path)
    config = _config(tmp_path)
    _bind_and_commit_proposal(tmp_path, config, _r51_proposal(compatible=True))

    assert D._run_instantiate_manifest_reconcile_transaction(
        _phase(), tmp_path, config
    ) == []
    assert (tmp_path / "spawn_manifest.md").is_file()
    assert (tmp_path / D._INSTANTIATE_RECONCILE_RECEIPT).is_file()


def test_r60_retry_prompt_binds_floor_and_consumer_predicates_together(
    tmp_path: Path,
) -> None:
    _seed_inputs(tmp_path)
    _seed_r51_depth_only_catalog(tmp_path)
    config = _config(tmp_path)
    config["mode"] = "thorough"
    config["_active_model_attempts"]["instantiate"] = 2

    compiled = D._compile_instantiate_model_prompt(
        "# RETRY ATTEMPT\n\nbreadth tier floor: only 6 rows; require >=7",
        scratchpad=tmp_path,
        config=config,
    )

    assert "Driver-bound conjunctive retry contract" in compiled
    assert "add `GENERAL` breadth" in compiled
    assert "| CROSS_CHAIN_TIMING | depth-external |" in compiled
    assert "| INTEGRATION_HAZARD_RESEARCH | depth-external |" in compiled
    assert (
        "| STORAGE_LAYOUT_SAFETY | depth-edge-case, depth-state-trace |"
        in compiled
    )
    assert "the breadth floor and this exact catalog-derived" in compiled.replace(
        "\n", " "
    ).replace("  ", " ")


def test_optional_depth_only_skill_explicit_breadth_binding_is_rejected(
    tmp_path: Path,
) -> None:
    _seed_inputs(tmp_path)
    _seed_r51_depth_only_catalog(tmp_path)
    catalog_path = tmp_path / "skill_selection_catalog.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    for skill in catalog["skills"]:
        skill["state"] = "NOT_REQUIRED"
    catalog["artifact_sha256"] = S.authority_artifact_digest(catalog)
    S.write_authority_artifact(catalog_path, catalog)

    issues = D._instantiate_consumer_compatibility_issues(
        tmp_path,
        _r51_proposal(compatible=False).encode("utf-8"),
        mode="core",
    )

    assert any(
        "CROSS_CHAIN_TIMING" in issue and "breadth:B4" in issue
        for issue in issues
    ), issues


def test_unknown_explicit_skill_is_rejected_for_noncomplex_manifest(
    tmp_path: Path,
) -> None:
    _seed_inputs(tmp_path)
    _seed_r51_depth_only_catalog(tmp_path)
    proposal = _r51_proposal(compatible=True).replace(
        "| AGENT | GENERAL | YES | B1 |",
        "| AGENT | INVENTED_UNCATALOGED_SKILL | YES | B1 |",
    )

    issues = D._instantiate_consumer_compatibility_issues(
        tmp_path, proposal.encode("utf-8"), mode="core"
    )

    assert any(
        "unknown skill INVENTED_UNCATALOGED_SKILL" in issue
        and "breadth:B1" in issue
        for issue in issues
    ), issues


def test_r60_attempt1_floor_retry_then_attempt2_ineligible_never_commits(
    tmp_path: Path,
) -> None:
    _seed_inputs(tmp_path)
    _seed_r51_depth_only_catalog(tmp_path)
    (tmp_path / "contract_inventory.md").write_text(
        "# Contract Inventory\n\n| Contract | Path | Lines |\n|---|---|---:|\n"
        + "".join(
            f"| C{i} | contracts/C{i}.sol | 100 |\n" for i in range(12)
        ),
        encoding="utf-8",
        newline="\n",
    )
    phase = _phase()
    config = _config(tmp_path)
    config["mode"] = "thorough"
    _bind_and_commit_proposal(tmp_path, config, _r60_proposal(invalid_retry=False))

    first_issues = D._run_instantiate_manifest_reconcile_transaction(
        phase, tmp_path, config
    )
    assert any("breadth tier floor" in issue for issue in first_issues)
    assert not (tmp_path / "spawn_manifest.md").exists()

    archived, archive_issues = D._archive_instantiate_retry_proposal(
        tmp_path, prior_attempt=1
    )
    assert archive_issues == [] and archived
    config["_active_model_attempts"]["instantiate"] = 2
    retry_prompt = D._compile_instantiate_model_prompt(
        "# RETRY ATTEMPT\n\nbreadth tier floor: only 6 rows; require >=7",
        scratchpad=tmp_path,
        config=config,
    )
    assert "add `GENERAL` breadth" in retry_prompt
    assert "| CROSS_CHAIN_TIMING | depth-external |" in retry_prompt

    assert D._bind_typed_model_phase_inputs(phase, tmp_path, config) == []
    (tmp_path / "spawn_manifest_proposal.md").write_text(
        _r60_proposal(invalid_retry=True), encoding="utf-8", newline="\n"
    )
    assert D._record_typed_model_phase_artifacts(phase, tmp_path, config) == []
    second_issues = D._run_instantiate_manifest_reconcile_transaction(
        phase, tmp_path, config
    )
    joined = "\n".join(second_issues)
    assert "STORAGE_LAYOUT_SAFETY" in joined and "breadth:B3" in joined
    assert "CROSS_CHAIN_TIMING" in joined and "breadth:B5" in joined
    assert "INTEGRATION_HAZARD_RESEARCH" in joined and "breadth:B7" in joined
    assert not (tmp_path / "spawn_manifest.md").exists()
    assert not (tmp_path / D._INSTANTIATE_RECONCILE_RECEIPT).exists()


def test_r52_hybrid_role_underscores_normalize_within_closed_denominator(
    tmp_path: Path,
) -> None:
    _seed_inputs(tmp_path)
    _seed_r51_depth_only_catalog(tmp_path)
    config = _config(tmp_path)
    proposal = _r51_proposal(compatible=True).replace(
        "depth-edge-case", "depth-edge_case"
    ).replace("depth-state-trace", "depth-state_trace")
    _bind_and_commit_proposal(tmp_path, config, proposal)

    assert D._run_instantiate_manifest_reconcile_transaction(
        _phase(), tmp_path, config
    ) == []
    assert (tmp_path / "spawn_manifest.md").is_file()


def test_r52_depth_underscore_prefix_is_rejected_with_exact_denominator(
    tmp_path: Path,
) -> None:
    _seed_inputs(tmp_path)
    _seed_r51_depth_only_catalog(tmp_path)
    config = _config(tmp_path)
    proposal = _r51_proposal(compatible=True).replace(
        "depth-edge-case", "depth_edge_case"
    ).replace("depth-state-trace", "depth_state_trace")
    _bind_and_commit_proposal(tmp_path, config, proposal)

    issues = D._run_instantiate_manifest_reconcile_transaction(
        _phase(), tmp_path, config
    )

    joined = "\n".join(issues)
    assert "required skill binding missing" in joined
    assert "STORAGE_LAYOUT_SAFETY" in joined
    assert "depth_edge_case" in joined
    assert "depth_state_trace" in joined
    assert (
        "depth-token-flow, depth-state-trace, depth-edge-case, or depth-external"
        in joined
    )
    assert not (tmp_path / "spawn_manifest.md").exists()


@pytest.mark.parametrize("backend", ["claude", "codex"])
def test_reconcile_adds_upstream_positive_and_retains_valid_model_positive(
    tmp_path: Path,
    backend: str,
) -> None:
    before = _seed_inputs(tmp_path)
    config = _config(tmp_path, backend)
    _bind_and_commit_proposal(
        tmp_path,
        config,
        _proposal(extra_niche="SEMANTIC_CONSISTENCY_AUDIT"),
    )

    assert D._run_instantiate_manifest_reconcile_transaction(
        _phase(), tmp_path, config
    ) == []

    canonical = (tmp_path / "spawn_manifest.md").read_text(encoding="utf-8")
    assert V._niche_tokens_from_required_table(canonical) == {
        "EVENT_COMPLETENESS",
        "SEMANTIC_CONSISTENCY_AUDIT",
    }
    receipt = json.loads(
        (tmp_path / D._INSTANTIATE_RECONCILE_RECEIPT).read_text(
            encoding="utf-8"
        )
    )
    assert receipt["added_upstream_niches"] == ["EVENT_COMPLETENESS"]
    assert receipt["retained_model_only_niches"] == [
        "SEMANTIC_CONSISTENCY_AUDIT"
    ]
    assert receipt["reconciliation"] == "RECALL_SAFE_POSITIVE_UNION"
    assert receipt["canonical"]["sha256"] == hashlib.sha256(
        (tmp_path / "spawn_manifest.md").read_bytes()
    ).hexdigest()
    for name, raw in before.items():
        assert (tmp_path / name).read_bytes() == raw

    ledger = read_artifact_ledger(tmp_path)
    model = next(
        row for key, row in ledger["work_units"].items()
        if key.endswith("/instantiate/model")
    )
    driver = next(
        row for key, row in ledger["work_units"].items()
        if key.endswith("/instantiate/manifest_reconcile")
    )
    assert model["artifacts"]["scratchpad:spawn_manifest_proposal.md"][
        "writer"
    ] == "MODEL"
    assert driver["artifacts"]["scratchpad:spawn_manifest.md"]["writer"] == (
        "DRIVER"
    )


@pytest.mark.parametrize("failpoint", ["after_manifest", "after_receipt"])
def test_reconcile_recovers_idempotently_after_each_output_boundary(
    tmp_path: Path,
    failpoint: str,
) -> None:
    _seed_inputs(tmp_path)
    config = _config(tmp_path)
    _bind_and_commit_proposal(tmp_path, config, _proposal())
    config["_instantiate_reconcile_failpoint"] = failpoint

    first = D._run_instantiate_manifest_reconcile_transaction(
        _phase(), tmp_path, config
    )
    assert any(failpoint in issue for issue in first)
    assert (tmp_path / "spawn_manifest.md").is_file()
    assert (
        (tmp_path / D._INSTANTIATE_RECONCILE_RECEIPT).exists()
        is (failpoint == "after_receipt")
    )

    config.pop("_instantiate_reconcile_failpoint")
    assert D._run_instantiate_manifest_reconcile_transaction(
        _phase(), tmp_path, config
    ) == []
    first_bytes = (tmp_path / "spawn_manifest.md").read_bytes()
    first_receipt = (
        tmp_path / D._INSTANTIATE_RECONCILE_RECEIPT
    ).read_bytes()
    assert D._run_instantiate_manifest_reconcile_transaction(
        _phase(), tmp_path, config
    ) == []
    assert (tmp_path / "spawn_manifest.md").read_bytes() == first_bytes
    assert (
        tmp_path / D._INSTANTIATE_RECONCILE_RECEIPT
    ).read_bytes() == first_receipt


def test_second_model_attempt_rebinds_without_reusing_first_attempt_authority(
    tmp_path: Path,
) -> None:
    _seed_inputs(tmp_path)
    config = _config(tmp_path)
    phase = _phase()
    _bind_and_commit_proposal(tmp_path, config, _proposal())
    assert D._run_instantiate_manifest_reconcile_transaction(
        phase, tmp_path, config
    ) == []

    first_canonical = (tmp_path / "spawn_manifest.md").read_bytes()
    first_proposal = (tmp_path / "spawn_manifest_proposal.md").read_bytes()
    renamed = D._quarantine_stale_on_retry(
        tmp_path,
        phase,
        ["spawn_manifest.md failed deterministic successor validation"],
    )
    assert renamed == ["spawn_manifest.md"]
    archived, archive_issues = D._archive_instantiate_retry_proposal(
        tmp_path, prior_attempt=1
    )
    assert archive_issues == []
    assert archived == [
        "_attempt_history/instantiate/model-attempt-0001/"
        "spawn_manifest_proposal.md"
    ]
    assert not (tmp_path / "spawn_manifest_proposal.md").exists()
    assert (
        tmp_path
        / "_attempt_history"
        / "instantiate"
        / "model-attempt-0001"
        / "spawn_manifest_proposal.md"
    ).read_bytes() == first_proposal
    config["_active_model_attempts"]["instantiate"] = 2
    # A retry is a new MODEL proposal and a new DRIVER successor.  The test
    # exercises the production quarantine boundary; the committed first-attempt
    # authority remains in the ledger as history while shared live output paths
    # are empty before attempt-2 input binding.
    assert D._bind_typed_model_phase_inputs(phase, tmp_path, config) == []
    (tmp_path / "spawn_manifest_proposal.md").write_text(
        _proposal(extra_niche="SEMANTIC_CONSISTENCY_AUDIT"),
        encoding="utf-8",
        newline="\n",
    )
    assert D._record_typed_model_phase_artifacts(phase, tmp_path, config) == []
    assert D._run_instantiate_manifest_reconcile_transaction(
        phase, tmp_path, config
    ) == []

    second_canonical = (tmp_path / "spawn_manifest.md").read_bytes()
    assert second_canonical != first_canonical
    ledger = read_artifact_ledger(tmp_path)
    assert any(
        key.endswith("/instantiate/model.attempt-0002")
        for key in ledger["work_units"]
    )
    assert any(
        key.endswith("/instantiate/manifest_reconcile.attempt-0002")
        for key in ledger["work_units"]
    )


def test_invalid_model_only_niche_never_reaches_canonical(
    tmp_path: Path,
) -> None:
    _seed_inputs(tmp_path)
    config = _config(tmp_path)
    _bind_and_commit_proposal(
        tmp_path, config, _proposal(extra_niche="INVENTED_PROTOCOL_CHECK")
    )

    issues = D._run_instantiate_manifest_reconcile_transaction(
        _phase(), tmp_path, config
    )

    assert any("no resolvable niche methodology" in issue for issue in issues)
    assert not (tmp_path / "spawn_manifest.md").exists()
    assert not (tmp_path / D._INSTANTIATE_RECONCILE_RECEIPT).exists()


def test_attempt_scoped_model_and_driver_work_unit_ids_are_distinct(
    tmp_path: Path,
) -> None:
    _seed_inputs(tmp_path)
    config = _config(tmp_path)
    phase = _phase()
    first_model, _ = D._typed_model_phase_contract_and_launch(
        phase, tmp_path, config
    )
    first_driver, _, _ = D._instantiate_reconcile_contract_and_launch(
        tmp_path, config
    )
    config["_active_model_attempts"]["instantiate"] = 2
    second_model, _ = D._typed_model_phase_contract_and_launch(
        phase, tmp_path, config
    )
    second_driver, _, _ = D._instantiate_reconcile_contract_and_launch(
        tmp_path, config
    )

    assert first_model.work_unit_id == "model"
    assert second_model.work_unit_id == "model.attempt-0002"
    assert first_driver.work_unit_id == "manifest_reconcile"
    assert second_driver.work_unit_id == "manifest_reconcile.attempt-0002"


def test_live_validation_only_mode_never_mutates_recon_or_manifest(
    tmp_path: Path,
) -> None:
    before = _seed_inputs(tmp_path)
    proposal = _proposal()
    (tmp_path / "spawn_manifest.md").write_text(
        proposal, encoding="utf-8", newline="\n"
    )
    manifest_before = (tmp_path / "spawn_manifest.md").read_bytes()

    issues = V._validate_niche_manifest_consistency(
        tmp_path, "core", repair=False
    )

    assert any("EVENT_COMPLETENESS" in issue for issue in issues)
    assert (tmp_path / "spawn_manifest.md").read_bytes() == manifest_before
    for name, raw in before.items():
        assert (tmp_path / name).read_bytes() == raw


def test_prompt_routes_all_canonical_writes_to_proposal() -> None:
    compiled = D._compile_instantiate_model_prompt(
        "Write spawn_manifest.md. Re-read `spawn_manifest.md`."
    )
    assert "spawn_manifest_proposal.md" in compiled
    assert "Write spawn_manifest.md" not in compiled
    assert "Do not create or modify `spawn_manifest.md`" in compiled


def test_instantiate_supervisor_contract_is_model_owned_proposal_only(
    tmp_path: Path,
) -> None:
    phase = _phase()
    supervised = D._model_owned_supervision_phase(phase)

    assert supervised is not phase
    assert phase.expected_artifacts == ["spawn_manifest.md"]
    assert supervised.name == "instantiate"
    assert supervised.expected_artifacts == ["spawn_manifest_proposal.md"]
    assert supervised.any_of == []

    # A stale/foreign canonical artifact cannot satisfy the live MODEL turn.
    (tmp_path / "spawn_manifest.md").write_text(
        _proposal(), encoding="utf-8", newline="\n"
    )
    passed, missing = D.gate_passes(tmp_path, str(tmp_path), supervised)
    assert passed is False
    assert missing == ["spawn_manifest_proposal.md"]

    # The proposal is the terminal model-owned artifact. Canonical publication
    # occurs later in _run_phase_validators via the DRIVER transaction.
    (tmp_path / "spawn_manifest_proposal.md").write_text(
        _proposal(), encoding="utf-8", newline="\n"
    )
    passed, missing = D.gate_passes(tmp_path, str(tmp_path), supervised)
    assert passed is True
    assert missing == []


def test_supervised_pty_loop_applies_instantiate_model_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase = _phase()
    (tmp_path / "spawn_manifest_proposal.md").write_text(
        _proposal(), encoding="utf-8", newline="\n"
    )
    observed: list[list[str]] = []
    real_gate = D.gate_passes

    def _gate(scratchpad: Path, project_root: str, candidate: D.Phase):
        observed.append(list(candidate.expected_artifacts))
        return real_gate(scratchpad, project_root, candidate)

    monkeypatch.setattr(D, "gate_passes", _gate)
    session = SimpleNamespace(
        wait_for_turn_complete=lambda *args, **kwargs: SimpleNamespace(
            rate_limited=False,
            context_thrash=False,
        ),
    )

    rc, final = D._run_supervised_pty_loop(
        session=session,
        scratchpad=tmp_path,
        project_root=str(tmp_path),
        phase=phase,
        config={"pty_continuation_budget": 3},
        preflight={},
        timeout=5.0,
        quiescence_s=0.0,
        on_poll=None,
        base_cmd=["claude"],
        cwd=str(tmp_path),
        env={},
        log_file=None,
        prompt_path=tmp_path / "prompt.md",
    )

    assert rc == 0
    assert final is session
    assert observed == [["spawn_manifest_proposal.md"]]


def test_instantiate_retry_cannot_launder_prior_proposal_as_fresh_output(
    tmp_path: Path,
) -> None:
    _seed_inputs(tmp_path)
    config = _config(tmp_path)
    phase = _phase()
    _bind_and_commit_proposal(tmp_path, config, _proposal())
    assert D._run_instantiate_manifest_reconcile_transaction(
        phase, tmp_path, config
    ) == []

    archived, archive_issues = D._archive_instantiate_retry_proposal(
        tmp_path, prior_attempt=1
    )
    assert archive_issues == []
    assert archived
    config["_active_model_attempts"]["instantiate"] = 2
    assert D._bind_typed_model_phase_inputs(phase, tmp_path, config) == []

    supervised = D._model_owned_supervision_phase(phase)
    passed, missing = D.gate_passes(tmp_path, str(tmp_path), supervised)
    assert passed is False
    assert missing == ["spawn_manifest_proposal.md"]

    # A genuinely new attempt-2 write is required before the supervisor and
    # typed artifact recorder can accept the output.
    new_proposal = _proposal(extra_niche="SEMANTIC_CONSISTENCY_AUDIT")
    (tmp_path / "spawn_manifest_proposal.md").write_text(
        new_proposal, encoding="utf-8", newline="\n"
    )
    passed, missing = D.gate_passes(tmp_path, str(tmp_path), supervised)
    assert passed is True
    assert missing == []
    assert D._record_typed_model_phase_artifacts(
        phase, tmp_path, config
    ) == []

    ledger = read_artifact_ledger(tmp_path)
    second = next(
        row
        for key, row in ledger["work_units"].items()
        if key.endswith("/instantiate/model.attempt-0002")
    )
    assert second["artifacts"]["scratchpad:spawn_manifest_proposal.md"][
        "sha256"
    ] == hashlib.sha256(new_proposal.encode("utf-8")).hexdigest()


def test_instantiate_retry_archives_truncated_proposal_without_size_heuristic(
    tmp_path: Path,
) -> None:
    truncated = b"x" * 499
    live = tmp_path / "spawn_manifest_proposal.md"
    live.write_bytes(truncated)

    archived, issues = D._archive_instantiate_retry_proposal(
        tmp_path, prior_attempt=1
    )

    assert issues == []
    assert archived == [
        "_attempt_history/instantiate/model-attempt-0001/"
        "spawn_manifest_proposal.md"
    ]
    assert not live.exists()
    history = (
        tmp_path
        / "_attempt_history"
        / "instantiate"
        / "model-attempt-0001"
        / "spawn_manifest_proposal.md"
    )
    assert history.read_bytes() == truncated

    # Replaying the same stale bytes is idempotently cleared. Different bytes
    # for an already archived attempt fail closed and remain available for
    # operator inspection instead of overwriting committed history.
    live.write_bytes(truncated)
    archived, issues = D._archive_instantiate_retry_proposal(
        tmp_path, prior_attempt=1
    )
    assert issues == []
    assert archived
    assert not live.exists()
    live.write_bytes(b"different-generation")
    archived, issues = D._archive_instantiate_retry_proposal(
        tmp_path, prior_attempt=1
    )
    assert archived == []
    assert issues
    assert live.read_bytes() == b"different-generation"
    assert history.read_bytes() == truncated


def test_instantiate_attempt_receipt_binds_monotonic_history_bytes(
    tmp_path: Path,
) -> None:
    run_id = "run-instantiate-receipt"
    assert D._publish_instantiate_attempt_receipt(
        tmp_path,
        run_id=run_id,
        state="ACTIVE",
        active_attempt=1,
        from_attempt=1,
        to_attempt=1,
        history=[],
        predecessor_receipt_digest="",
    ) == []
    first, issues = D._load_instantiate_attempt_receipt(
        tmp_path, run_id=run_id
    )
    assert issues == []
    assert first is not None
    assert first["active_attempt"] == 1

    assert D._publish_instantiate_attempt_receipt(
        tmp_path,
        run_id=run_id,
        state="PREPARING",
        active_attempt=1,
        from_attempt=1,
        to_attempt=2,
        history=[],
        predecessor_receipt_digest=first["receipt_digest"],
    ) == []
    preparing, issues = D._load_instantiate_attempt_receipt(
        tmp_path, run_id=run_id
    )
    assert issues == []
    assert preparing is not None
    assert preparing["state"] == "PREPARING"

    proposal = b"partial-current-attempt" * 9
    (tmp_path / "spawn_manifest_proposal.md").write_bytes(proposal)
    archived, issues = D._archive_instantiate_retry_proposal(
        tmp_path, prior_attempt=1
    )
    assert issues == []
    assert archived
    history = [D._instantiate_history_record(tmp_path, attempt=1)]
    assert D._publish_instantiate_attempt_receipt(
        tmp_path,
        run_id=run_id,
        state="ACTIVE",
        active_attempt=2,
        from_attempt=2,
        to_attempt=2,
        history=history,
        predecessor_receipt_digest=preparing["receipt_digest"],
    ) == []
    second, issues = D._load_instantiate_attempt_receipt(
        tmp_path, run_id=run_id
    )
    assert issues == []
    assert second is not None
    assert second["active_attempt"] == 2
    assert second["history"] == history

    archive_path = tmp_path / history[0]["path"]
    archive_path.write_bytes(b"tampered-history")
    observed, issues = D._load_instantiate_attempt_receipt(
        tmp_path, run_id=run_id
    )
    assert observed is None
    assert any("history digest mismatch" in issue for issue in issues)
