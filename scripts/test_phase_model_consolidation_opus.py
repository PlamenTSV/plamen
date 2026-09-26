"""Bloat fix #3: promote the weak-model consolidation/authoring phases
(inventory merge + chunks, report body-writers) to Opus in SC Thorough — they
decide what reaches the client and were running on sonnet. Light/Core, L1, and
Codex paths unchanged.
"""
from __future__ import annotations

import plamen_types as T


def _pm(name: str, *, mode: str = "thorough", pipeline: str = "sc",
        model: str = "sonnet") -> str:
    ph = T.Phase(name, [], [], 60, model=model)
    return T.phase_model(ph, mode, {"pipeline": pipeline})


def test_inventory_and_tier_writers_opus_in_sc_thorough():
    for name in (
        "inventory",
        "report_body_writer_medium", "report_body_writer_low_info",
        "report_body_writer_medium_a",            # expanded shard (prefix match)
        "report_body_writer_low_info_b",
    ):
        assert "opus" in _pm(name).lower(), name


def test_inventory_chunks_stay_sonnet_in_sc_thorough():
    """Chunks are lossless P0-L normalization shards (the reconciler enforces
    preservation), and Opus 5 refuses the transcription task as
    `reasoning_extraction` (DODO run41/43/45). Only the MERGE is promoted."""
    for name in ("inventory_chunk_a", "inventory_chunk_b", "inventory_chunk_c"):
        assert "opus" not in _pm(name).lower(), name
        assert "sonnet" in _pm(name).lower(), name


def test_chain_already_opus_unchanged():
    # regression guard: chain was already promoted (is_sc_chain) — must stay opus
    assert "opus" in _pm("chain").lower()


def test_not_promoted_in_core_or_light():
    for mode in ("core", "light"):
        assert "opus" not in _pm("inventory", mode=mode).lower(), mode
        assert "opus" not in _pm("report_body_writer_medium", mode=mode).lower(), mode


def test_not_promoted_for_l1_pipeline():
    # these promotions are SC-scoped
    assert "opus" not in _pm("inventory", pipeline="l1").lower()
    assert "opus" not in _pm("report_body_writer_medium", pipeline="l1").lower()
