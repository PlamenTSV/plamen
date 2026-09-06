"""End-to-end RED contracts for chain-delta runtime replay.

The chain-candidate provider and the frozen provider already authenticate a
versioned delta plus its source preimages.  Runtime consumption must accept
that complete v2 bundle, preserve the exact base-plus-delta union, and
independently replay the public delta algorithm.  Envelope self-digests alone
are not semantic authority.

These fixtures cross the real driver boundary:

    accepted chain/model -> paired auto-map -> chain pair projection
    -> frozen base-plus-delta projection -> stable successors
    -> armed SC routing -> runtime resolution

No audit, model, network request, subprocess, or production artifact is
launched.  Production modules and pre-existing tests are not modified.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Callable

import pytest

import chain_candidate_inventory_union as DELTA
from preverify_chain_pair_projection import (
    prepare_preverify_chain_pair_projection,
)
from preverify_frozen_projection import prepare_preverify_frozen_projection
import preverify_projection_authority as AUTHORITY
from preverify_projection_authority import (
    PreverifyProjectionAuthorityError,
    resolve_current_preverify_projection,
)
import plamen_driver as DRIVER
import test_chain_post_model_driver_order_integration as CHAIN


_ROUTING_KEY = "sc/thorough/evm/claude/sc_verify_queue/routing"
_EXACT_DELTA_SOURCE_LEAVES = {
    # These physical leaves are deliberately compact so the nested
    # content-addressed projection remains usable under Windows path limits.
    # Semantic roles stay explicit in the receipt.
    "chain_candidate_delta": "d.json",
    "chain_candidate_delta_receipt": "r.json",
    "chain_candidate_source_auto_map_receipt": "d_a.json",
    "chain_candidate_source_enabler_results": "d_e.bin",
    "chain_candidate_source_finding_mapping": "d_m.bin",
    "chain_candidate_source_hypotheses": "d_h.bin",
    "chain_candidate_source_pair_receipt": "d_p.json",
    "inventory": "i.bin",
}


def _build_frozen_delta(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, dict[str, Any], dict[str, Any], dict[str, Any]]:
    project, scratchpad, config, _checkpoint = CHAIN._accepted_chain_model(
        tmp_path,
        include_enabler=True,
    )
    monkeypatch.setattr(
        DRIVER,
        "_derive_auto_map_unmapped_depth_findings",
        CHAIN._additive_pair_deriver(),
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
        run_id=CHAIN.CHAIN_FIXTURE.RUN_ID,
    )
    assert pair["state"] == "OUTPUT_COMMITTED"
    assert pair["safe_to_consume"] is True

    frozen = prepare_preverify_frozen_projection(
        scratchpad=scratchpad,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase_name="sc_verify_queue",
        run_id=CHAIN.CHAIN_FIXTURE.RUN_ID,
        chain_pair_projection=pair,
    )
    assert frozen["state"] == "OUTPUT_COMMITTED"
    receipt = json.loads(
        (scratchpad / str(frozen["receipt_path"])).read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    return project, scratchpad, config, frozen, receipt


def _assert_exact_delta_union_and_sources(
    scratchpad: Path,
    frozen: dict[str, Any],
    receipt: dict[str, Any],
) -> None:
    assert receipt["schema_version"] == (
        "plamen.preverify_frozen_projection_receipt.v2"
    )
    assert receipt["chain_candidate_delta"]["candidate_ids"] == ["EN-1"]
    fixed = receipt["candidate_delivery_fixed_point"]
    assert fixed == {
        "base_ids": ["INV-1"],
        "delta_ids": ["EN-1"],
        "frozen_ids": ["EN-1", "INV-1"],
        "base_union_delta_equals_frozen": True,
        "candidate_records_removed": 0,
        "identity_collision_ids": [],
    }

    source_authorities = receipt["source_authorities"]
    source_preimages = receipt["source_preimage_bindings"]
    assert set(source_authorities) == set(_EXACT_DELTA_SOURCE_LEAVES)
    assert set(source_preimages) == set(_EXACT_DELTA_SOURCE_LEAVES)
    assert {
        role: row["leaf"]
        for role, row in source_preimages.items()
    } == _EXACT_DELTA_SOURCE_LEAVES

    frozen_root = Path(str(frozen["receipt_path"])).parent
    for role, leaf in _EXACT_DELTA_SOURCE_LEAVES.items():
        raw = (scratchpad / frozen_root / "_sources" / leaf).read_bytes()
        binding = source_preimages[role]
        assert binding["size"] == len(raw)

    inventory = (
        scratchpad
        / str(frozen["logical_to_physical"]["findings_inventory.md"])
    ).read_text(encoding="utf-8", errors="strict")
    records = json.loads(
        (
            scratchpad
            / str(frozen["logical_to_physical"]["finding_records.json"])
        ).read_text(encoding="utf-8", errors="strict")
    )
    assert "Finding [INV-1]" in inventory
    assert "Finding [EN-1]" in inventory
    assert {row["inventory_id"] for row in records["records"]} == {
        "INV-1",
        "EN-1",
    }


def _arm_runtime(
    scratchpad: Path,
    config: dict[str, Any],
    frozen: dict[str, Any],
) -> None:
    assert DRIVER._finalize_preverify_inventory_successors(
        scratchpad,
        config,
        phase_name="sc_verify_queue",
        frozen_projection=frozen,
    ) == []
    execute, issues = DRIVER._arm_typed_verify_queue_routing_artifacts(
        "sc_verify_queue",
        scratchpad,
        config,
    )
    assert execute is True
    assert issues == []


def _resolve(scratchpad: Path) -> dict[str, Any]:
    return resolve_current_preverify_projection(
        scratchpad,
        expected_run_id=CHAIN.CHAIN_FIXTURE.RUN_ID,
        expected_consumer_work_unit_key=_ROUTING_KEY,
    )


def test_delta_v2_frozen_union_is_runtime_resolvable_from_exact_source_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ordinary authenticated v2 delta path must reach runtime."""

    _project, scratchpad, config, frozen, receipt = _build_frozen_delta(
        tmp_path,
        monkeypatch,
    )
    _assert_exact_delta_union_and_sources(scratchpad, frozen, receipt)
    _arm_runtime(scratchpad, config, frozen)

    resolved = _resolve(scratchpad)

    assert resolved["runtime_authority"] is True
    assert resolved["authority_scope"] == "RUNTIME_BOUND"
    assert resolved["inventory_source_artifact"] == (
        frozen["logical_to_physical"]["findings_inventory.md"]
    )
    assert "Finding [INV-1]" in resolved["inventory_text"]
    assert "Finding [EN-1]" in resolved["inventory_text"]
    assert {
        row["inventory_id"]
        for row in resolved["records_payload"]["records"]
    } == {"INV-1", "EN-1"}


def test_runtime_independently_rederives_delta_v2_from_source_preimages(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A self-consistent stored delta is insufficient without source replay."""

    _project, scratchpad, config, frozen, receipt = _build_frozen_delta(
        tmp_path,
        monkeypatch,
    )
    _assert_exact_delta_union_and_sources(scratchpad, frozen, receipt)
    _arm_runtime(scratchpad, config, frozen)
    assert "Finding [EN-1]" in _resolve(scratchpad)["inventory_text"]

    original: Callable[..., tuple[dict[str, Any], list[dict[str, Any]]]] = (
        DELTA.derive_preverify_chain_candidate_payload
    )

    def coherently_forged_derivation(
        *args: Any,
        **kwargs: Any,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        payload, debt = original(*args, **kwargs)
        changed = deepcopy(payload)
        row = changed["candidates"][0]
        row["description"] = (
            "Fixture-only semantics absent from the committed delta."
        )
        row["inventory_block"] = str(row["inventory_block"]).replace(
            "A generic chain-discovered precondition path.",
            "Fixture-only semantics absent from the committed delta.",
        )
        changed.pop("candidate_digest", None)
        changed["candidate_digest"] = DELTA._digest(changed)
        return changed, deepcopy(debt)

    monkeypatch.setattr(
        DELTA,
        "derive_preverify_chain_candidate_payload",
        coherently_forged_derivation,
    )
    # Accommodate either a module-level import or a local import in the
    # runtime authority implementation without prescribing that structure.
    monkeypatch.setattr(
        AUTHORITY,
        "derive_preverify_chain_candidate_payload",
        coherently_forged_derivation,
        raising=False,
    )

    with pytest.raises(
        PreverifyProjectionAuthorityError,
        match="algorithm|conformance|derive|replay|source|delta",
    ):
        _resolve(scratchpad)


@pytest.mark.parametrize(
    "role",
    (
        "chain_candidate_source_hypotheses",
        "chain_candidate_source_finding_mapping",
        "chain_candidate_source_pair_receipt",
        "chain_candidate_source_enabler_results",
        "chain_candidate_source_auto_map_receipt",
    ),
)
def test_runtime_authenticates_every_nested_delta_source_preimage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    role: str,
) -> None:
    """No nested input may fall outside runtime's exact source denominator."""

    _project, scratchpad, config, frozen, receipt = _build_frozen_delta(
        tmp_path,
        monkeypatch,
    )
    _assert_exact_delta_union_and_sources(scratchpad, frozen, receipt)
    _arm_runtime(scratchpad, config, frozen)
    assert "Finding [EN-1]" in _resolve(scratchpad)["inventory_text"]

    leaf = _EXACT_DELTA_SOURCE_LEAVES[role]
    target = (
        scratchpad
        / Path(str(frozen["receipt_path"])).parent
        / "_sources"
        / leaf
    )
    original = target.read_bytes()
    target.write_bytes(original + b"\nfixture-tamper")
    try:
        with pytest.raises(
            PreverifyProjectionAuthorityError,
            match="source|preimage|binding|artifact|replay|delta",
        ):
            _resolve(scratchpad)
    finally:
        target.write_bytes(original)

    assert "Finding [EN-1]" in _resolve(scratchpad)["inventory_text"]
