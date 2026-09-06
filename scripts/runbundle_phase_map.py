"""Frozen evaluator-owned native phase maps for the RunBundle v2 protocol.

This module is deliberately independent of ``plamen_types`` and all driver
state.  Runtime phase-roster mutation must not change the public protocol.
Parity tests compare these frozen maps with the current base driver rosters so
intentional driver changes require an explicit map version/hash update.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from types import MappingProxyType
from typing import Any, Mapping


class RunBundlePhaseMapError(ValueError):
    """A caller requested data outside the closed phase-map protocol."""


@dataclass(frozen=True, slots=True)
class NativePhaseBinding:
    native_phase: str
    macro_phase: str


@dataclass(frozen=True, slots=True)
class PinnedPhaseMap:
    pipeline_kind: str
    map_id: str
    map_version: str
    map_sha256: str
    ordered_macro_phases: tuple[str, ...]
    ordered_native_phases: tuple[NativePhaseBinding, ...]

    def preimage(self) -> dict[str, Any]:
        """Return a detached canonical-hash preimage."""

        return {
            "map_id": self.map_id,
            "map_version": self.map_version,
            "pipeline_kind": self.pipeline_kind,
            "ordered_macro_phases": list(self.ordered_macro_phases),
            "ordered_native_phases": [
                {
                    "native_phase": binding.native_phase,
                    "macro_phase": binding.macro_phase,
                }
                for binding in self.ordered_native_phases
            ],
        }

    def native_order(self) -> Mapping[str, int]:
        return MappingProxyType(
            {
                binding.native_phase: index
                for index, binding in enumerate(self.ordered_native_phases)
            }
        )

    def native_macros(self) -> Mapping[str, str]:
        return MappingProxyType(
            {
                binding.native_phase: binding.macro_phase
                for binding in self.ordered_native_phases
            }
        )

    def macro_order(self) -> Mapping[str, int]:
        return MappingProxyType(
            {
                macro_phase: index
                for index, macro_phase in enumerate(
                    self.ordered_macro_phases
                )
            }
        )


def _bindings(
    rows: tuple[tuple[str, str], ...],
) -> tuple[NativePhaseBinding, ...]:
    bindings = tuple(
        NativePhaseBinding(native_phase, macro_phase)
        for native_phase, macro_phase in rows
    )
    native_names = tuple(binding.native_phase for binding in bindings)
    if len(native_names) != len(set(native_names)):
        raise RuntimeError("pinned native phase roster contains duplicates")
    return bindings


_SC_NATIVE_PHASES = _bindings(
    (
        ("recon", "recon"),
        ("instantiate", "CONTROL"),
        ("breadth", "breadth"),
        ("rescan_prepare", "CONTROL"),
        ("rescan", "breadth"),
        ("inventory_prepare", "CONTROL"),
        ("inventory_chunk_a", "inventory"),
        ("inventory_chunk_b", "inventory"),
        ("inventory_chunk_c", "inventory"),
        ("inventory", "inventory"),
        ("invariants", "depth"),
        ("invariants_p2", "depth"),
        ("depth", "depth"),
        ("attention_repair", "depth"),
        ("exploration_skeptic", "depth"),
        ("enumgap_exploration", "depth"),
        ("axis_coverage", "depth"),
        ("application_skeptic", "depth"),
        ("sc_semantic_dedup", "inventory"),
        ("rag_sweep", "depth"),
        ("chain", "chain"),
        ("chain_agent2", "chain"),
        ("chain_iter2", "chain"),
        ("sc_verify_queue", "CONTROL"),
        ("sc_verify_crithigh", "verify"),
        ("sc_verify_high_b", "verify"),
        ("sc_verify_high_c", "verify"),
        ("sc_verify_high_d", "verify"),
        ("sc_verify_high_e", "verify"),
        ("sc_verify_high_f", "verify"),
        ("sc_verify_high_g", "verify"),
        ("sc_verify_high_h", "verify"),
        ("sc_verify_high_i", "verify"),
        ("sc_verify_high_j", "verify"),
        ("sc_verify_medium_a", "verify"),
        ("sc_verify_medium_b", "verify"),
        ("sc_verify_medium_c", "verify"),
        ("sc_verify_medium_d", "verify"),
        ("sc_verify_medium_e", "verify"),
        ("sc_verify_medium_f", "verify"),
        ("sc_verify_medium_g", "verify"),
        ("sc_verify_medium_h", "verify"),
        ("sc_verify_medium_i", "verify"),
        ("sc_verify_medium_j", "verify"),
        ("sc_verify_low_a", "verify"),
        ("sc_verify_low_b", "verify"),
        ("sc_verify_low_c", "verify"),
        ("sc_verify_low_d", "verify"),
        ("sc_verify_low_e", "verify"),
        ("sc_verify_low_f", "verify"),
        ("sc_verify_low_g", "verify"),
        ("sc_verify_low_h", "verify"),
        ("sc_verify_low_i", "verify"),
        ("sc_verify_low_j", "verify"),
        ("sc_verify_aggregate", "verify"),
        ("sc_mechanical_verify", "verify"),
        ("post_verify_extract", "verify"),
        ("skeptic", "verify"),
        ("crossbatch", "verify"),
        ("severity_adjudication_shadow", "verify"),
        ("report_index", "report"),
        ("report_body_writer_critical_high", "report"),
        ("report_body_writer_medium", "report"),
        ("report_body_writer_low_info", "report"),
        ("report_critical_high", "report"),
        ("report_critical_high_merge", "report"),
        ("report_medium", "report"),
        ("report_medium_merge", "report"),
        ("report_low_info", "report"),
        ("report_low_info_merge", "report"),
        ("report_assemble", "report"),
        ("report_dedup_agent", "report"),
        ("report_dedup", "report"),
        ("report_disposition", "report"),
        ("report_floor", "report"),
    )
)

_L1_NATIVE_PHASES = _bindings(
    (
        ("bake", "bake"),
        ("recon", "recon"),
        ("breadth", "breadth"),
        ("graph_sweeps", "graph"),
        ("inventory_prepare", "CONTROL"),
        ("inventory_chunk_a", "inventory"),
        ("inventory_chunk_b", "inventory"),
        ("inventory_chunk_c", "inventory"),
        ("inventory", "inventory"),
        ("location_recovery", "inventory"),
        ("invariants", "depth"),
        ("invariants_p2", "depth"),
        ("depth", "depth"),
        ("attention_repair", "depth"),
        ("enumgap_exploration", "depth"),
        ("application_skeptic", "depth"),
        ("semantic_dedup", "inventory"),
        ("rag_sweep", "depth"),
        ("verify_queue", "CONTROL"),
        ("verify_crithigh", "verify"),
        ("verify_high_b", "verify"),
        ("verify_high_c", "verify"),
        ("verify_high_d", "verify"),
        ("verify_high_e", "verify"),
        ("verify_high_f", "verify"),
        ("verify_high_g", "verify"),
        ("verify_high_h", "verify"),
        ("verify_high_i", "verify"),
        ("verify_high_j", "verify"),
        ("verify_medium_a", "verify"),
        ("verify_medium_b", "verify"),
        ("verify_medium_c", "verify"),
        ("verify_medium_d", "verify"),
        ("verify_medium_e", "verify"),
        ("verify_medium_f", "verify"),
        ("verify_low_a", "verify"),
        ("verify_low_b", "verify"),
        ("verify_low_c", "verify"),
        ("verify_low_d", "verify"),
        ("verify_aggregate", "verify"),
        ("mechanical_verify", "verify"),
        ("post_verify_extract", "verify"),
        ("skeptic", "verify"),
        ("crossbatch", "verify"),
        ("severity_adjudication_shadow", "verify"),
        ("report_index", "report"),
        ("report_body_writer_critical_high", "report"),
        ("report_body_writer_medium", "report"),
        ("report_body_writer_low_info", "report"),
        ("report_critical_high", "report"),
        ("report_critical_high_merge", "report"),
        ("report_medium", "report"),
        ("report_medium_merge", "report"),
        ("report_low_info", "report"),
        ("report_low_info_merge", "report"),
        ("report_assemble", "report"),
        ("report_dedup", "report"),
        ("report_disposition", "report"),
        ("report_floor", "report"),
    )
)

SC_PHASE_MAP_SHA256 = (
    "28779f0e8bfb0358f0b496661b61918f7b837530c05ff1295f63e83d5d5ac9ae"
)
L1_PHASE_MAP_SHA256 = (
    "1eb129d128fc47427b1de2d0502aa82f3162546246f57d6d738090d441c526a6"
)

_PHASE_MAPS = MappingProxyType(
    {
        "SC": PinnedPhaseMap(
            pipeline_kind="SC",
            map_id="plamen-sc-macro",
            map_version="2",
            map_sha256=SC_PHASE_MAP_SHA256,
            ordered_macro_phases=(
                "recon",
                "breadth",
                "inventory",
                "depth",
                "chain",
                "verify",
                "report",
            ),
            ordered_native_phases=_SC_NATIVE_PHASES,
        ),
        "L1": PinnedPhaseMap(
            pipeline_kind="L1",
            map_id="plamen-l1-macro",
            map_version="2",
            map_sha256=L1_PHASE_MAP_SHA256,
            ordered_macro_phases=(
                "bake",
                "recon",
                "breadth",
                "graph",
                "inventory",
                "depth",
                "chain",
                "composition",
                "verify",
                "report",
            ),
            ordered_native_phases=_L1_NATIVE_PHASES,
        ),
    }
)
PIPELINE_KINDS = frozenset(_PHASE_MAPS)


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def phase_map_sha256(phase_map: PinnedPhaseMap) -> str:
    if not isinstance(phase_map, PinnedPhaseMap):
        raise RunBundlePhaseMapError("phase map must be a pinned map")
    return hashlib.sha256(_canonical_json_bytes(phase_map.preimage())).hexdigest()


def pinned_phase_map(pipeline_kind: str) -> PinnedPhaseMap:
    if not isinstance(pipeline_kind, str):
        raise RunBundlePhaseMapError("pipeline kind must be an exact string")
    try:
        return _PHASE_MAPS[pipeline_kind]
    except KeyError as exc:
        raise RunBundlePhaseMapError(
            f"unknown pinned pipeline kind {pipeline_kind!r}"
        ) from exc


def phase_map_preimage(pipeline_kind: str) -> dict[str, Any]:
    return pinned_phase_map(pipeline_kind).preimage()


def native_phase_binding(
    pipeline_kind: str,
    native_phase: str,
) -> NativePhaseBinding:
    if not isinstance(native_phase, str):
        raise RunBundlePhaseMapError("native phase must be an exact string")
    phase_map = pinned_phase_map(pipeline_kind)
    for binding in phase_map.ordered_native_phases:
        if binding.native_phase == native_phase:
            return binding
    raise RunBundlePhaseMapError(
        f"unknown {pipeline_kind} native phase {native_phase!r}"
    )


def native_phase_rank(pipeline_kind: str, native_phase: str) -> int:
    native_phase_binding(pipeline_kind, native_phase)
    return pinned_phase_map(pipeline_kind).native_order()[native_phase]


def native_phase_allows_semantic_output(
    pipeline_kind: str,
    native_phase: str,
) -> bool:
    """Return whether a pinned native phase may emit semantic audit output."""

    return (
        native_phase_binding(pipeline_kind, native_phase).macro_phase
        != "CONTROL"
    )


for _phase_map in _PHASE_MAPS.values():
    if phase_map_sha256(_phase_map) != _phase_map.map_sha256:
        raise RuntimeError(
            f"{_phase_map.pipeline_kind} pinned phase-map hash drift"
        )
    if any(
        binding.macro_phase
        not in set(_phase_map.ordered_macro_phases) | {"CONTROL"}
        for binding in _phase_map.ordered_native_phases
    ):
        raise RuntimeError(
            f"{_phase_map.pipeline_kind} native phase has an unknown macro"
        )


__all__ = [
    "L1_PHASE_MAP_SHA256",
    "NativePhaseBinding",
    "PIPELINE_KINDS",
    "PinnedPhaseMap",
    "RunBundlePhaseMapError",
    "SC_PHASE_MAP_SHA256",
    "native_phase_allows_semantic_output",
    "native_phase_binding",
    "native_phase_rank",
    "phase_map_preimage",
    "phase_map_sha256",
    "pinned_phase_map",
]
