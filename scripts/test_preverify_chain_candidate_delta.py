"""Acceptance tests for the typed chain-only preverify candidate delta.

The delta is a proposal-preserving PhaseIO authority.  It cannot prove a
finding or mutate the canonical inventory; it binds the accepted final chain
pair and the exact model enabler output, then gives the frozen inventory
projection an additive input.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from preverify_chain_pair_projection import (
    prepare_preverify_chain_pair_projection,
)
from chain_candidate_inventory_union import (
    ChainCandidateDeltaError,
    prepare_preverify_chain_candidate_delta,
)
from preverify_frozen_projection import (
    PreverifyFrozenProjectionError,
    prepare_preverify_frozen_projection,
)
import plamen_driver as DRIVER
import live_verify_queue_driver_adapter as LIVE_ADAPTER
import test_chain_driver_boundary_authority_red as CHAIN_FIXTURE
import test_chain_post_model_driver_order_integration as ORDER


def _accepted_delta_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    model_outputs: dict[str, str] | None = None,
    base_inventory_extra: str = "",
):
    if model_outputs is not None:
        monkeypatch.setattr(
            ORDER,
            "_model_outputs",
            lambda *, include_enabler: dict(model_outputs),
        )
    project, scratchpad, config, _checkpoint = ORDER._accepted_chain_model(
        tmp_path,
        include_enabler=True,
        base_inventory_extra=base_inventory_extra,
    )
    before = (scratchpad / "findings_inventory.md").read_bytes()
    monkeypatch.setattr(
        DRIVER,
        "_derive_auto_map_unmapped_depth_findings",
        ORDER._additive_pair_deriver(),
    )
    mapped, issues = (
        DRIVER._auto_map_unmapped_depth_findings_with_semantic_authority(
            scratchpad,
            config,
            owner_phase="chain",
            gate_issues=("unmapped DA-2",),
        )
    )
    assert mapped == ["DA-2"]
    assert issues == []
    pair = prepare_preverify_chain_pair_projection(
        scratchpad=scratchpad,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase_name="sc_verify_queue",
        run_id=CHAIN_FIXTURE.RUN_ID,
    )
    assert pair["state"] == "OUTPUT_COMMITTED"
    return project, scratchpad, pair, before


def _model_outputs_for(*identities: str, malformed_mapping: bool = False):
    hypotheses = (
        "# Hypotheses\n\n"
        "| Hypothesis ID | Severity | Title | Constituent Findings | Location |\n"
        "|---|---|---|---|---|\n"
        "| H-1 | Medium | Existing candidate | INV-1 | src/Fixture.sol:1 |\n"
    )
    mapping = (
        "# Finding Mapping\n\n"
        "| Finding ID | Hypothesis ID | Mapping Status |\n"
        "|---|---|---|\n"
        "| INV-1 | H-1 | GROUPED |\n"
    )
    enablers = "# Enabler Results\n\n**Status**: MODEL_ANALYZED\n"
    for index, identity in enumerate(identities, start=2):
        hypotheses += (
            f"| H-{index} | High | Candidate {identity} | {identity} | "
            f"src/Generic{index}.sol:{index}0 |\n"
        )
        if not malformed_mapping:
            mapping += f"| {identity} | H-{index} | CHAIN_GENERATED |\n"
        enablers += (
            f"\n### Finding [{identity}]: Candidate {identity}\n"
            "**Severity**: High\n"
            f"**Location**: src/Generic{index}.sol:{index}0\n"
            f"**Description**: Distinct mechanism for {identity}.\n"
            f"**Impact**: Distinct harm for {identity}.\n"
        )
    if malformed_mapping:
        mapping = (
            "# Finding Mapping\n\n"
            "| malformed relation without machine identities |\n"
        )
    return {
        "hypotheses.md": hypotheses,
        "finding_mapping.md": mapping,
        "enabler_results.md": enablers,
    }


def test_exact_pair_and_model_enabler_publish_typed_nonmutating_delta(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratchpad, pair, before = _accepted_delta_sources(
        tmp_path,
        monkeypatch,
    )

    result = prepare_preverify_chain_candidate_delta(
        scratchpad=scratchpad,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase_name="sc_verify_queue",
        run_id=CHAIN_FIXTURE.RUN_ID,
        chain_pair_projection=pair,
    )

    assert result["state"] == "OUTPUT_COMMITTED"
    assert result["safe_to_consume"] is True
    assert result["candidate_ids"] == ["EN-1"]
    assert result["proof_authority"] == "NONE"
    assert (scratchpad / "findings_inventory.md").read_bytes() == before
    payload = result["candidates"]
    assert payload["base_inventory_mutated"] is False
    assert payload["candidate_ids"] == ["EN-1"]
    row = payload["candidates"][0]
    assert row["candidate_identity"] == "EN-1"
    assert row["relation_kind"] == "ENABLER_CONSTITUENT"
    assert row["required_disposition"] == "VERIFY_INDEPENDENTLY"
    assert row["source_artifact"] == "enabler_results.md"
    assert row["title"] == "Chain-only candidate"
    assert row["description"] == (
        "A generic chain-discovered precondition path."
    )
    assert row["impact"] == (
        "Requires independent verification before disposition."
    )


def test_delta_replay_is_exact_and_content_addressed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratchpad, pair, _before = _accepted_delta_sources(
        tmp_path,
        monkeypatch,
    )
    kwargs = {
        "scratchpad": scratchpad,
        "project_root": project,
        "pipeline": "sc",
        "mode": "thorough",
        "ecosystem": "evm",
        "backend": "claude",
        "phase_name": "sc_verify_queue",
        "run_id": CHAIN_FIXTURE.RUN_ID,
        "chain_pair_projection": pair,
    }

    first = prepare_preverify_chain_candidate_delta(**kwargs)
    second = prepare_preverify_chain_candidate_delta(**kwargs)

    assert second == first
    assert first["candidate_path"] in first["required_paths"]
    assert first["receipt_path"] in first["required_paths"]
    for relative in first["required_paths"]:
        assert (scratchpad / relative).is_file()


def test_multi_digit_candidate_order_and_frozen_union_fixed_point_are_exact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratchpad, pair, before = _accepted_delta_sources(
        tmp_path,
        monkeypatch,
        model_outputs=_model_outputs_for("EN-2", "EN-10"),
    )

    frozen = prepare_preverify_frozen_projection(
        scratchpad=scratchpad,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase_name="sc_verify_queue",
        run_id=CHAIN_FIXTURE.RUN_ID,
        chain_pair_projection=pair,
    )

    inventory = (
        scratchpad
        / frozen["logical_to_physical"]["findings_inventory.md"]
    ).read_text(encoding="utf-8", errors="strict")
    records = json.loads((
        scratchpad
        / frozen["logical_to_physical"]["finding_records.json"]
    ).read_text(encoding="utf-8", errors="strict"))
    receipt = json.loads(
        (scratchpad / frozen["receipt_path"]).read_text(
            encoding="utf-8", errors="strict"
        )
    )
    fixed = receipt["candidate_delivery_fixed_point"]

    assert fixed["delta_ids"] == ["EN-2", "EN-10"]
    assert set(fixed["base_ids"]) | set(fixed["delta_ids"]) == set(
        fixed["frozen_ids"]
    )
    assert {row["inventory_id"] for row in records["records"]} == set(
        fixed["frozen_ids"]
    )
    assert inventory.index("Finding [EN-2]") < inventory.index(
        "Finding [EN-10]"
    )
    assert (scratchpad / "findings_inventory.md").read_bytes() == before


def test_unparseable_mapping_retains_every_enabler_with_visible_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratchpad, pair, _before = _accepted_delta_sources(
        tmp_path,
        monkeypatch,
        model_outputs=_model_outputs_for(
            "EN-1",
            malformed_mapping=True,
        ),
    )

    delta = prepare_preverify_chain_candidate_delta(
        scratchpad=scratchpad,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase_name="sc_verify_queue",
        run_id=CHAIN_FIXTURE.RUN_ID,
        chain_pair_projection=pair,
    )

    assert delta["candidate_ids"] == ["EN-1"]
    assert delta["debt"]
    assert all(
        row["candidate_disposition"] == "PRESERVE_ALL_FOR_VERIFICATION"
        for row in delta["debt"]
    )


def test_same_identity_different_claim_is_visible_debt_not_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    existing = (
        "\n### Finding [EN-1]: Existing unrelated claim\n"
        "**Severity**: Low\n"
        "**Location**: src/Existing.sol:99\n"
        "**Description**: Existing distinct content.\n"
        "**Impact**: Existing distinct impact.\n"
    )
    project, scratchpad, pair, before = _accepted_delta_sources(
        tmp_path,
        monkeypatch,
        base_inventory_extra=existing,
    )

    frozen = prepare_preverify_frozen_projection(
        scratchpad=scratchpad,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase_name="sc_verify_queue",
        run_id=CHAIN_FIXTURE.RUN_ID,
        chain_pair_projection=pair,
    )
    receipt = json.loads(
        (scratchpad / frozen["receipt_path"]).read_text(
            encoding="utf-8", errors="strict"
        )
    )

    assert receipt["candidate_delivery_fixed_point"][
        "identity_collision_ids"
    ] == ["EN-1"]
    collision = next(
        row for row in frozen["debt"]
        if row.get("reason_code") == "CHAIN_CANDIDATE_IDENTITY_COLLISION"
    )
    assert collision["candidate_disposition"] == (
        "VISIBLE_HUMAN_REVIEW_DEBT"
    )
    assert collision["candidate"]["candidate_identity"] == "EN-1"
    assert (scratchpad / "findings_inventory.md").read_bytes() == before


def test_delta_rejects_cross_run_pair_and_frozen_rejects_tampered_delta(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratchpad, pair, _before = _accepted_delta_sources(
        tmp_path,
        monkeypatch,
    )
    with pytest.raises(
        ChainCandidateDeltaError,
        match="identity|run|tuple|dimension",
    ):
        prepare_preverify_chain_candidate_delta(
            scratchpad=scratchpad,
            project_root=project,
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
            phase_name="sc_verify_queue",
            run_id="foreign-run",
            chain_pair_projection=pair,
        )

    delta = prepare_preverify_chain_candidate_delta(
        scratchpad=scratchpad,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase_name="sc_verify_queue",
        run_id=CHAIN_FIXTURE.RUN_ID,
        chain_pair_projection=pair,
    )
    (scratchpad / delta["candidate_path"]).write_text(
        "{}\n", encoding="utf-8"
    )
    with pytest.raises(
        PreverifyFrozenProjectionError,
        match="PhaseIO|delta|artifact|digest",
    ):
        prepare_preverify_frozen_projection(
            scratchpad=scratchpad,
            project_root=project,
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
            phase_name="sc_verify_queue",
            run_id=CHAIN_FIXTURE.RUN_ID,
            chain_pair_projection=pair,
        )


def test_context_capture_uses_frozen_union_and_chain_candidate_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratchpad, pair, before = _accepted_delta_sources(
        tmp_path,
        monkeypatch,
    )
    source = project / "src" / "Generic.sol"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(
        "contract Generic { function transition() external {} }\n",
        encoding="utf-8",
    )
    for name in (
        "methodology_registry.json",
        "methodology_reachability_manifest.json",
    ):
        (scratchpad / name).write_text("{}\n", encoding="utf-8")
    frozen = prepare_preverify_frozen_projection(
        scratchpad=scratchpad,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase_name="sc_verify_queue",
        run_id=CHAIN_FIXTURE.RUN_ID,
        chain_pair_projection=pair,
    )

    context = LIVE_ADAPTER._context_capture(
        scratchpad=scratchpad,
        project_root=project,
        frozen_projection=frozen,
    )

    assert "enabler_results.md" in context["exact_inputs"]
    assert "project::src/Generic.sol" in context["primary_artifacts"]
    assert set(frozen["required_paths"]) <= set(context["exact_inputs"])
    assert (scratchpad / "findings_inventory.md").read_bytes() == before
