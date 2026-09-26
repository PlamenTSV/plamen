"""Recon transport fencing identity must be disjoint from the retry budget.

This is the recon sibling of ``test_depth_transport_generation_fencing.py``.
The capped DODO run (run25) died in depth, but recon carries the identical
defect:

  1. ``_rate_limit_retry_dispatch`` sets ``recon_transport_replay`` and
     deliberately returns ``current_attempt`` (not ``current_attempt + 1``)
     so a provider rate limit does not spend the semantic retry budget.
  2. The driver therefore re-runs recon's SAME outer attempt.
  3. ``_recon_worker_attempt_ordinal`` used to derive every leaf ordinal from
     that semantic attempt, so the second dispatch asked for leaf identities
     the first dispatch had already consumed.
  4. The POSIX compatibility launcher refuses a non-fresh invocation with
     ``INVOCATION_REPLAY``, so every recon worker is rejected and the phase
     cannot recover.

The repair separates the *fencing* identity (a durable, strictly increasing
per-phase transport generation) from the *semantic* retry ordinal.

Recon additionally needs the inverse: several call sites must recover the
semantic attempt from a worker ordinal.  A free-running generation is NOT
invertible by arithmetic, so the reservation transaction records the
``generation -> outer attempt`` mapping and the inverse consults that ledger.
When no ledger exists (an old scratchpad, or a resume of a run whose ordinals
were minted arithmetically) the inverse falls back to the legacy arithmetic
band, which is exactly the pre-repair answer.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import plamen_driver as D  # noqa: E402


_ROUNDS = D._RECON_WORKER_ROUNDS_PER_PHASE_ATTEMPT
_CONFIG = {"_run_id": "run-recon-fencing-test"}


def _reserve(tmp_path: Path, outer_attempt: int, config=None) -> int:
    return D._reserve_transport_generation(
        scratchpad=tmp_path,
        config=config or _CONFIG,
        phase_name="recon",
        outer_attempt=outer_attempt,
    )


def _leaves(band: int) -> set[int]:
    return {
        D._recon_worker_attempt_ordinal(band, worker_round)
        for worker_round in range(1, _ROUNDS + 1)
    }


# ---------------------------------------------------------------------------
# 1. The collision itself
# ---------------------------------------------------------------------------


def test_same_outer_attempt_twice_yields_disjoint_recon_leaves(tmp_path):
    """The exact run25 sequence must not reuse a single recon leaf ordinal."""
    # Dispatch 1: initial run of semantic attempt 1.
    gen_a = _reserve(tmp_path, 1)
    # Dispatch 2: rate-limit transport recovery, which deliberately re-runs
    # the SAME semantic attempt rather than spending the retry budget.
    gen_b = _reserve(tmp_path, 1)
    # Dispatch 3: the normal gate retry, semantic attempt 2.
    gen_c = _reserve(tmp_path, 2)

    assert gen_a < gen_b < gen_c, "generations must strictly increase"

    a, b, c = (_leaves(g) for g in (gen_a, gen_b, gen_c))
    assert not (a & b), "rate-limit recovery replayed attempt-1 leaf ordinals"
    assert not (a & c) and not (b & c), "gate retry replayed earlier leaves"


def test_recon_generation_survives_process_restart(tmp_path):
    """Resume must continue the sequence, not restart it and collide."""
    first = _reserve(tmp_path, 1)
    resumed = _reserve(tmp_path, 1)
    assert resumed > first
    ledger = json.loads(
        (tmp_path / D._TRANSPORT_GENERATION_NAME).read_text("utf-8")
    )
    entry = ledger["phases"]["recon"]
    assert entry["by_attempt"]["1"] == [first, resumed]


def test_recon_reservation_records_reverse_mapping(tmp_path):
    """The inverse is only possible if reservation records generation->attempt."""
    gen_a = _reserve(tmp_path, 1)
    gen_b = _reserve(tmp_path, 1)
    gen_c = _reserve(tmp_path, 2)
    entry = json.loads(
        (tmp_path / D._TRANSPORT_GENERATION_NAME).read_text("utf-8")
    )["phases"]["recon"]
    assert entry["by_generation"] == {
        str(gen_a): 1, str(gen_b): 1, str(gen_c): 2
    }


# ---------------------------------------------------------------------------
# 2. The inversion contract
# ---------------------------------------------------------------------------


def test_inverse_recovers_semantic_attempt_not_the_band(tmp_path):
    """A generation-derived ordinal must invert to its SEMANTIC attempt."""
    gen_a = _reserve(tmp_path, 1)
    gen_b = _reserve(tmp_path, 1)   # rate-limit replay of attempt 1
    gen_c = _reserve(tmp_path, 2)

    for band, expected in ((gen_a, 1), (gen_b, 1), (gen_c, 2)):
        for worker_round in range(1, _ROUNDS + 1):
            ordinal = D._recon_worker_attempt_ordinal(band, worker_round)
            assert D._recon_outer_attempt_from_worker(
                ordinal, scratchpad=tmp_path
            ) == expected, (
                f"band {band} round {worker_round} inverted to the transport "
                f"band instead of semantic attempt {expected}"
            )


def test_inverse_falls_back_to_legacy_arithmetic_without_ledger(tmp_path):
    """Old scratchpads / resume: no ledger means the arithmetic band is truth."""
    for outer in (1, 2, 3):
        for worker_round in range(1, _ROUNDS + 1):
            ordinal = D._recon_worker_attempt_ordinal(outer, worker_round)
            # Legacy signature (no scratchpad) must keep working unchanged.
            assert D._recon_outer_attempt_from_worker(ordinal) == outer
            # And an explicitly supplied but ledger-free scratchpad must give
            # the identical pre-repair answer, never a spurious retry demand.
            assert D._recon_outer_attempt_from_worker(
                ordinal, scratchpad=tmp_path
            ) == outer


def test_inverse_ignores_a_foreign_phase_ledger(tmp_path):
    """Depth's generations must not be read as recon's semantic attempts."""
    D._reserve_transport_generation(
        scratchpad=tmp_path, config=_CONFIG, phase_name="depth", outer_attempt=1
    )
    D._reserve_transport_generation(
        scratchpad=tmp_path, config=_CONFIG, phase_name="depth", outer_attempt=1
    )
    ordinal = D._recon_worker_attempt_ordinal(2, 1)
    assert D._recon_outer_attempt_from_worker(ordinal, scratchpad=tmp_path) == 2


def test_inverse_fails_closed_on_a_corrupt_reverse_mapping(tmp_path):
    """A malformed authority is explicit debt, never a silent legacy answer.

    Silently returning the arithmetic band here would be an authority bypass:
    a band that really belongs to semantic attempt 2 would invert to 1 and the
    recon retry-plan requirement would be skipped without a trace.
    """
    _reserve(tmp_path, 1)
    path = tmp_path / D._TRANSPORT_GENERATION_NAME
    state = json.loads(path.read_text("utf-8"))
    state["phases"]["recon"]["by_generation"]["1"] = "not-an-attempt"
    path.write_text(json.dumps(state), encoding="utf-8")
    ordinal = D._recon_worker_attempt_ordinal(1, 1)
    with pytest.raises(ValueError):
        D._recon_outer_attempt_from_worker(ordinal, scratchpad=tmp_path)


def test_inverse_rejects_invalid_ordinals(tmp_path):
    for bad in (0, -1, True, "2", 2.0):
        with pytest.raises(ValueError):
            D._recon_outer_attempt_from_worker(bad, scratchpad=tmp_path)


# ---------------------------------------------------------------------------
# 3. Per-call-site pins
# ---------------------------------------------------------------------------


def test_retry_plan_input_is_not_demanded_for_a_replayed_first_attempt(tmp_path):
    """Call site: ``_typed_worker_registered_input_paths`` (retry-plan input).

    A rate-limit replay of outer attempt 1 runs on generation 2.  Under the
    pre-repair arithmetic inverse that ordinal reads as "attempt 2", so the
    registered input denominator would demand ``recon_retry_plan.json`` for a
    dispatch that has no retry plan and never should have one.
    """
    _reserve(tmp_path, 1)
    replay = _reserve(tmp_path, 1)
    config = {
        "pipeline": "sc",
        "project_root": str(tmp_path),
        "scratchpad": str(tmp_path),
        **_CONFIG,
    }
    ordinal = D._recon_worker_attempt_ordinal(replay, 1)
    values = D._typed_worker_registered_input_paths(
        phase_name="recon",
        scratchpad=tmp_path,
        config=config,
        agent_id="R-1",
        output="contract_inventory.md",
        attempt=ordinal,
    )
    assert "recon_retry_plan.json" not in values

    # ... while a genuine semantic retry still registers it.
    genuine = _reserve(tmp_path, 2)
    values2 = D._typed_worker_registered_input_paths(
        phase_name="recon",
        scratchpad=tmp_path,
        config=config,
        agent_id="R-1",
        output="contract_inventory.md",
        attempt=D._recon_worker_attempt_ordinal(genuine, 1),
    )
    assert "recon_retry_plan.json" in values2


def test_retry_plan_validation_accepts_an_explicit_outer_attempt(tmp_path):
    """Call site: the attempt-3 transport successor and the R-EXT wave.

    Both mint a *synthetic* ordinal purely to round-trip a semantic attempt
    through the worker-ordinal parameter.  A synthetic band would be looked up
    in the generation ledger and resolve to whatever attempt really owns that
    band, so those sites must pass the semantic attempt directly instead.
    """
    # Generations 1..3 all belong to semantic attempt 1 (two rate limits).
    _reserve(tmp_path, 1)
    _reserve(tmp_path, 1)
    _reserve(tmp_path, 1)
    state = D._validated_recon_retry_plan(
        tmp_path, dict(_CONFIG), outer_attempt=3
    )
    # No plan file on disk: attempt 3 is past the NOT_APPLICABLE cutoff, so the
    # typed absence must be MISSING and must report outer attempt 3 -- not the
    # attempt that happens to own transport band 3.
    assert state == {"state": "MISSING", "outer_attempt": 3}

    assert D._validated_recon_retry_plan(
        tmp_path, dict(_CONFIG), outer_attempt=1
    ) == {"state": "NOT_APPLICABLE", "outer_attempt": 1}

    with pytest.raises(ValueError):
        D._validated_recon_retry_plan(
            tmp_path, dict(_CONFIG), worker_attempt=1, outer_attempt=1
        )
    with pytest.raises(ValueError):
        D._validated_recon_retry_plan(tmp_path, dict(_CONFIG))


def test_refusal_evidence_enumerates_every_recon_generation(tmp_path):
    """Call site: ``_codex_phase_refusal_worker_attempts``.

    One semantic attempt can own several generations, so provider-refusal
    evidence must enumerate every band's worker logs or it silently misses the
    recovery dispatch that actually failed.
    """
    g1 = _reserve(tmp_path, 1)
    g2 = _reserve(tmp_path, 1)
    attempts = D._codex_phase_refusal_worker_attempts(
        "recon", 1, dict(_CONFIG), scratchpad=tmp_path
    )
    expected = {
        D._recon_worker_attempt_ordinal(band, worker_round)
        for band in (g1, g2)
        for worker_round in range(1, _ROUNDS + 1)
    }
    assert set(attempts) == expected
    assert len(attempts) == len(expected) == 2 * _ROUNDS


def test_refusal_evidence_without_ledger_keeps_legacy_bands(tmp_path):
    """No ledger (old scratchpad) must keep the pre-repair enumeration."""
    attempts = D._codex_phase_refusal_worker_attempts(
        "recon", 2, dict(_CONFIG), scratchpad=tmp_path
    )
    assert set(attempts) == {
        D._recon_worker_attempt_ordinal(2, worker_round)
        for worker_round in range(1, _ROUNDS + 1)
    }


def test_recon_producers_reserve_a_transport_generation():
    """Both recon dispatch paths must fence on a reserved generation.

    ``_run_recon_worker_pool_pty`` (Claude PTY) and ``_run_recon_backend_fanout``
    (Codex / headless Claude) are the only two producers of recon leaf
    ordinals.  Neither may key a leaf on the semantic attempt.
    """
    import inspect

    for func in (D._run_recon_worker_pool_pty, D._run_recon_backend_fanout):
        src = inspect.getsource(func)
        assert "_reserve_transport_generation(" in src, (
            f"{func.__name__} still derives recon leaf ordinals from the "
            f"semantic attempt; a rate-limit replay will collide"
        )
        assert "_recon_worker_attempt_ordinal(attempt," not in src, (
            f"{func.__name__} still passes the semantic attempt as the "
            f"transport band"
        )
