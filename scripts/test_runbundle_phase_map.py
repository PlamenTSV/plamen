"""Focused contracts for the frozen RunBundle v2 native phase maps."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import json

import pytest

import plamen_types as T
import runbundle_contracts as C
import runbundle_phase_map as M


EXPECTED = {
    "SC": {
        "map_id": "plamen-sc-macro",
        "map_version": "2",
        "map_sha256": (
            "28779f0e8bfb0358f0b496661b61918f7b837530c05ff1295f63e83d5d5ac9ae"
        ),
        "native_count": 75,
    },
    "L1": {
        "map_id": "plamen-l1-macro",
        "map_version": "2",
        "map_sha256": (
            "1eb129d128fc47427b1de2d0502aa82f3162546246f57d6d738090d441c526a6"
        ),
        "native_count": 59,
    },
}


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


@pytest.mark.parametrize("pipeline_kind", ["SC", "L1"])
def test_versioned_phase_map_preimages_and_hashes_are_canonical(
    pipeline_kind: str,
):
    expected = EXPECTED[pipeline_kind]
    phase_map = M.pinned_phase_map(pipeline_kind)
    preimage = M.phase_map_preimage(pipeline_kind)
    digest = hashlib.sha256(_canonical_bytes(preimage)).hexdigest()

    assert phase_map.pipeline_kind == pipeline_kind
    assert phase_map.map_id == expected["map_id"]
    assert phase_map.map_version == expected["map_version"]
    assert phase_map.map_sha256 == expected["map_sha256"]
    assert digest == expected["map_sha256"]
    assert M.phase_map_sha256(phase_map) == digest
    assert len(phase_map.ordered_native_phases) == expected["native_count"]


@pytest.mark.parametrize(
    ("pipeline_kind", "runtime_phases"),
    [("SC", T.SC_PHASES), ("L1", T.L1_PHASES)],
)
def test_frozen_native_rosters_match_current_base_driver_rosters(
    pipeline_kind: str,
    runtime_phases,
):
    frozen = M.pinned_phase_map(pipeline_kind)
    frozen_names = tuple(
        binding.native_phase
        for binding in frozen.ordered_native_phases
    )
    runtime_names = tuple(phase.name for phase in runtime_phases)

    # Any base driver add/remove/reorder must fail here until the evaluator
    # deliberately versions and re-hashes the public phase-map protocol.
    assert frozen_names == runtime_names
    assert len(frozen_names) == len(set(frozen_names))


def test_phase_maps_are_detached_immutable_and_driver_independent(monkeypatch):
    phase_map = M.pinned_phase_map("SC")
    original_names = tuple(phase_map.native_order())
    preimage = phase_map.preimage()

    with pytest.raises(FrozenInstanceError):
        phase_map.map_version = "attacker-version"
    with pytest.raises(TypeError):
        phase_map.native_macros()["future_phase"] = "report"

    preimage["ordered_native_phases"].append(
        {"native_phase": "future_phase", "macro_phase": "report"}
    )
    monkeypatch.setattr(T, "SC_PHASES", [])
    assert tuple(M.pinned_phase_map("SC").native_order()) == original_names
    assert "future_phase" not in M.pinned_phase_map("SC").native_macros()
    assert len(M.phase_map_preimage("SC")["ordered_native_phases"]) == 75
    assert "plamen_types" not in M.__dict__


@pytest.mark.parametrize("pipeline_kind", ["", "sc", "L1 ", "UNKNOWN"])
def test_unknown_pipeline_kinds_fail_closed(pipeline_kind: str):
    with pytest.raises(M.RunBundlePhaseMapError, match="unknown"):
        M.pinned_phase_map(pipeline_kind)


@pytest.mark.parametrize(
    ("pipeline_kind", "native_phase"),
    [
        ("SC", "verify"),
        ("SC", "report"),
        ("SC", "future_phase"),
        ("L1", "verify"),
        ("L1", "report"),
        ("L1", "future_phase"),
    ],
)
def test_macro_aliases_and_unknown_native_phases_are_not_native_identity(
    pipeline_kind: str,
    native_phase: str,
):
    with pytest.raises(M.RunBundlePhaseMapError, match="unknown.*native phase"):
        M.native_phase_binding(pipeline_kind, native_phase)


def test_native_mapping_and_order_are_exact_not_macro_heuristics():
    assert M.native_phase_binding(
        "SC", "sc_verify_aggregate"
    ).macro_phase == "verify"
    assert M.native_phase_binding(
        "L1", "verify_aggregate"
    ).macro_phase == "verify"
    assert M.native_phase_binding(
        "SC", "inventory_prepare"
    ).macro_phase == "CONTROL"
    assert M.native_phase_rank("L1", "bake") < M.native_phase_rank(
        "L1", "recon"
    )


@pytest.mark.parametrize(
    ("pipeline_kind", "native_phase"),
    [
        ("SC", "instantiate"),
        ("SC", "rescan_prepare"),
        ("SC", "inventory_prepare"),
        ("SC", "sc_verify_queue"),
        ("L1", "inventory_prepare"),
        ("L1", "verify_queue"),
    ],
)
def test_control_native_phases_cannot_emit_semantic_output(
    pipeline_kind: str,
    native_phase: str,
):
    assert not M.native_phase_allows_semantic_output(
        pipeline_kind,
        native_phase,
    )
    assert M.native_phase_binding(
        pipeline_kind,
        native_phase,
    ).macro_phase == "CONTROL"


@pytest.mark.parametrize(
    ("pipeline_kind", "native_phase"),
    [("SC", "breadth"), ("SC", "report_assemble"), ("L1", "depth")],
)
def test_noncontrol_native_phases_may_emit_semantic_output(
    pipeline_kind: str,
    native_phase: str,
):
    assert M.native_phase_allows_semantic_output(
        pipeline_kind,
        native_phase,
    )


def test_runbundle_contracts_consumes_dedicated_phase_map_protocol():
    assert not hasattr(C, "_PINNED_PHASE_MAPS")
    for pipeline_kind in M.PIPELINE_KINDS:
        phase_map = M.pinned_phase_map(pipeline_kind)
        descriptor = {
            "pipeline_kind": pipeline_kind,
            "map_id": phase_map.map_id,
            "map_version": phase_map.map_version,
            "map_sha256": phase_map.map_sha256,
        }
        assert C._pinned_phase_map_preimage(
            pipeline_kind
        ) == phase_map.preimage()
        assert C._pinned_phase_order(descriptor) == dict(
            phase_map.macro_order()
        )
        assert C._pinned_native_phase_order(descriptor) == dict(
            phase_map.native_order()
        )
        assert C._pinned_native_phase_macros(descriptor) == dict(
            phase_map.native_macros()
        )
