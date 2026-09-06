"""2026-06-02: (1) L1 Thorough reasoning-role bump to Opus 4.8; (2) Bug-1 fix —
the 529 overload-retry must ITERATE attempts 1..N (was pinned to a hardcoded
attempt=2 / attempt2.log so it never advanced past attempt 1).
"""
from __future__ import annotations
import re
from pathlib import Path

import plamen_types as T


def _phase(name, model="sonnet"):
    p = T.Phase(name, ["S"], [name + ".md"], base_timeout_s=60, min_artifact_bytes=10)
    p.model = model
    return p


# ---------- Edit 1: L1 Thorough Opus-4.8 bump (verify caps preserved) ----------

def test_l1_thorough_depth_is_opus_5():
    assert T.phase_model(_phase("depth", "opus"), "thorough", {"pipeline": "l1"}) == "claude-opus-5"

def test_l1_thorough_breadth_promoted_to_opus_5():
    assert T.phase_model(_phase("breadth", "sonnet"), "thorough", {"pipeline": "l1"}) == "claude-opus-5"

def test_l1_thorough_skeptic_promoted_to_opus_5():
    assert T.phase_model(_phase("skeptic", "sonnet"), "thorough", {"pipeline": "l1"}) == "claude-opus-5"

def test_l1_thorough_verify_shard_now_opus5():
    # L1 verify shards (`verify_*`, not `_queue`/`_aggregate`) now promote to
    # Opus 5 in Thorough for parity with SC sc_verify_* shards (Sonnet was
    # dropping the mandatory PoC ledger under load).
    assert T.phase_model(_phase("verify_high_b", "sonnet"), "thorough", {"pipeline": "l1"}) == "claude-opus-5"

def test_l1_thorough_verify_queue_stays_unpromoted():
    assert T.phase_model(_phase("verify_queue", "haiku"), "thorough", {"pipeline": "l1"}) == T._resolve_model_alias("haiku")

def test_l1_thorough_verify_aggregate_stays_unpromoted():
    # verify_aggregate is a summary phase, not a reasoning shard -> NOT promoted.
    assert T.phase_model(_phase("verify_aggregate", "haiku"), "thorough", {"pipeline": "l1"}) == T._resolve_model_alias("haiku")

def test_sc_thorough_generic_phase_unaffected():
    # Regression: a generic SC Thorough phase (rescan) is NOT promoted.
    assert T.phase_model(_phase("rescan", "sonnet"), "thorough", {"pipeline": "sc"}) == "claude-sonnet-5"

def test_l1_core_verify_shard_not_promoted():
    # Promotion is Thorough-only: Core L1 verify shards keep their phase model.
    assert T.phase_model(_phase("verify_high_b", "sonnet"), "core", {"pipeline": "l1"}) == T._resolve_model_alias("sonnet")

def test_l1_light_verify_shard_sonnet():
    # Light forces sonnet for all phases regardless of promotion.
    assert T.phase_model(_phase("verify_high_b", "sonnet"), "light", {"pipeline": "l1"}) == "claude-sonnet-5"

def test_l1_core_depth_opus_is_5():
    # Opus 5 is the pinned default on every non-Light mode.
    assert T.phase_model(_phase("depth", "opus"), "core", {"pipeline": "l1"}) == "claude-opus-5"

def test_l1_light_depth_sonnet():
    assert T.phase_model(_phase("depth", "opus"), "light", {"pipeline": "l1"}) == "claude-sonnet-5"

def test_sc_thorough_depth_still_opus_5():
    # Regression: SC Thorough behavior unchanged.
    assert T.phase_model(_phase("depth", "opus"), "thorough", {"pipeline": "sc"}) == "claude-opus-5"

def test_sc_thorough_sc_verify_shard_still_promoted():
    assert T.phase_model(_phase("sc_verify_high_b", "sonnet"), "thorough", {"pipeline": "sc"}) == "claude-opus-5"


def test_codex_thorough_reasoning_promotions_match_claude_tiers():
    promoted = (
        ("breadth", "sc"),
        ("skeptic", "sc"),
        ("sc_verify_high_b", "sc"),
        ("chain_agent2", "sc"),
        ("inventory_chunk_a", "sc"),
        ("report_body_writer_high", "sc"),
        ("verify_high_b", "l1"),
    )
    for name, pipeline in promoted:
        config = {"pipeline": pipeline, "cli_backend": "codex"}
        assert T.phase_model(_phase(name), "thorough", config) == "gpt-5.6-sol"


def test_codex_thorough_non_reasoning_tiers_remain_unpromoted():
    config = {"pipeline": "sc", "cli_backend": "codex"}
    assert T.phase_model(_phase("rescan", "sonnet"), "thorough", config) == "gpt-5.6-terra"
    assert T.phase_model(_phase("verify_queue", "haiku"), "thorough", config) == "gpt-5.6-luna"


# ---------- Edit 2: Bug-1 overload-retry iterates 1..N ----------

def test_overload_loop_uses_incrementing_attempt_not_hardcoded_2():
    """Source-level guard: the overload retry block must NOT re-introduce the
    hardcoded attempt=2 / attempt2.log that pinned every iteration to attempt 1."""
    src = Path(__file__).resolve().parent.joinpath("plamen_driver.py").read_text(encoding="utf-8")
    # isolate the overload loop region, then drop comment lines so the checks
    # match CODE only (the fix comment legitimately mentions the old strings).
    start = src.index("529 transient-overload pre-check")
    end = src.index("rate limit detected -- auto-waiting", start)
    region = src[start:end]
    code = "\n".join(l for l in region.splitlines() if not l.strip().startswith("#"))
    assert "_ovl_run_attempt" in code, "overload loop must track an incrementing attempt number"
    assert "run_phase(phase, config, attempt=_ovl_run_attempt)" in code, \
        "overload re-run must use the incrementing attempt, not a constant"
    assert "run_phase(phase, config, attempt=2)" not in code, \
        "hardcoded attempt=2 must be gone from the overload loop"
    assert ".attempt2.log" not in code, "hardcoded attempt2.log path must be gone"
    assert "attempt{_ovl_run_attempt}.log" in code, \
        "retry log must be parameterized by the incrementing attempt"

def test_overload_backoff_plan_iterates_at_least_4():
    # The schedule the loop consumes must allow >=4 retries (helper lives in driver).
    import plamen_driver as D
    attempts = []
    i = 0
    while True:
        go, wait = D.overload_backoff_plan(i)
        if not go:
            break
        attempts.append(wait)
        i += 1
        if i > 20:
            break
    assert len(attempts) >= 4, f"overload backoff should allow >=4 retries, got {attempts}"
