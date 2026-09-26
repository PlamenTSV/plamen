"""Depth transport fencing identity must be disjoint from the retry budget.

Reproduces the first causal transition of the capped DODO run (run25):

  1. Codex returned a usage cap whose reset was ~5 days out.
  2. ``estimate_rate_limit_wait_seconds`` could not read the plain-text form,
     returned ``None``, and the caller spin-waited 300s instead of pausing for
     resume.
  3. The rate-limit recovery re-dispatched semantic attempt 2, consuming that
     attempt's depth leaf ordinals.
  4. ``rate_limit_consumed_retry`` was then reset to preserve the retry budget,
     so the normal gate retry re-dispatched semantic attempt 2 a second time.
  5. Every leaf invocation key was already used, so the POSIX compatibility
     launcher refused all nine workers with ``INVOCATION_REPLAY`` and depth
     could not recover for the rest of the run.

The repair separates the *fencing* identity (a durable, strictly increasing
transport generation) from the *semantic* retry ordinal, per
``docs/continuation/RELIABILITY_E2E_PLAN.md`` open architecture debt item 3.
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
import plamen_mechanical as M  # noqa: E402


_BUDGET = 3
_CONFIG = {"_run_id": "run-fencing-test", "pty_continuation_budget": _BUDGET}


def _leaves(generation: int, locals_used: tuple[int, ...]) -> set[int]:
    return {
        D._depth_transport_attempt_ordinal(
            outer_attempt=generation,
            local_attempt=local,
            continuation_budget=_BUDGET,
        )
        for local in locals_used
    }


def test_same_semantic_attempt_twice_yields_disjoint_leaves(tmp_path):
    """The exact run25 sequence must not reuse a single leaf ordinal."""
    # Dispatch 1: initial run of semantic attempt 1.
    gen_a = D._reserve_transport_generation(
        scratchpad=tmp_path, config=_CONFIG, phase_name="depth", outer_attempt=1
    )
    # Dispatch 2: rate-limit transport recovery, which deliberately re-runs
    # the SAME semantic attempt rather than spending the retry budget.
    gen_b = D._reserve_transport_generation(
        scratchpad=tmp_path, config=_CONFIG, phase_name="depth", outer_attempt=1
    )
    # Dispatch 3: the normal gate retry, semantic attempt 2.
    gen_c = D._reserve_transport_generation(
        scratchpad=tmp_path, config=_CONFIG, phase_name="depth", outer_attempt=2
    )

    assert gen_a < gen_b < gen_c, "generations must strictly increase"

    # The PTY pool consumes budget+1 worker rounds plus a finalization slot.
    locals_used = tuple(range(1, _BUDGET + 3))
    a, b, c = (_leaves(g, locals_used) for g in (gen_a, gen_b, gen_c))
    assert not (a & b), "rate-limit recovery replayed attempt-1 leaf ordinals"
    assert not (a & c) and not (b & c), "gate retry replayed earlier leaves"


def test_generation_survives_process_restart(tmp_path):
    """Resume must continue the sequence, not restart it and collide."""
    first = D._reserve_transport_generation(
        scratchpad=tmp_path, config=_CONFIG, phase_name="depth", outer_attempt=1
    )
    # A fresh driver process reads the persisted ledger from disk.
    resumed = D._reserve_transport_generation(
        scratchpad=tmp_path, config=_CONFIG, phase_name="depth", outer_attempt=1
    )
    assert resumed > first
    ledger = json.loads(
        (tmp_path / D._TRANSPORT_GENERATION_NAME).read_text("utf-8")
    )
    assert ledger["schema"] == D._TRANSPORT_GENERATION_SCHEMA
    assert ledger["phases"]["depth"]["by_attempt"]["1"] == [first, resumed]


def test_foreign_run_ledger_is_not_reused(tmp_path):
    """Another run's ledger cannot hand this run a band it already consumed."""
    D._reserve_transport_generation(
        scratchpad=tmp_path, config=_CONFIG, phase_name="depth", outer_attempt=1
    )
    other = dict(_CONFIG, _run_id="a-different-run")
    generation = D._reserve_transport_generation(
        scratchpad=tmp_path, config=other, phase_name="depth", outer_attempt=1
    )
    assert generation == 1, "foreign ledger must not seed this run's sequence"


def test_breadth_refusal_evidence_follows_generations(tmp_path):
    """Breadth refusal evidence must follow the generation, not the attempt."""
    g1 = D._reserve_transport_generation(
        scratchpad=tmp_path, config=_CONFIG, phase_name="breadth", outer_attempt=1
    )
    g2 = D._reserve_transport_generation(
        scratchpad=tmp_path, config=_CONFIG, phase_name="breadth", outer_attempt=1
    )
    rounds = D._codex_phase_refusal_worker_attempts(
        "breadth", 1, _CONFIG, scratchpad=tmp_path
    )
    expected = {((g - 1) * 2) + n for g in (g1, g2) for n in (1, 2)}
    assert set(rounds) == expected and len(rounds) == 4


def test_refusal_evidence_enumerates_every_generation(tmp_path):
    """Refusal evidence must not miss the recovery generation's workers."""
    D._reserve_transport_generation(
        scratchpad=tmp_path, config=_CONFIG, phase_name="depth", outer_attempt=2
    )
    D._reserve_transport_generation(
        scratchpad=tmp_path, config=_CONFIG, phase_name="depth", outer_attempt=2
    )
    attempts = D._codex_phase_refusal_worker_attempts(
        "depth", 2, _CONFIG, scratchpad=tmp_path
    )
    # Two generations x two leaf rounds, all distinct.
    assert len(attempts) == 4 and len(set(attempts)) == 4


@pytest.mark.parametrize(
    "line",
    [
        "ERROR: You've hit your usage limit. Visit "
        "https://chatgpt.com/codex/settings/usage to purchase more credits "
        "or try again at Sep 21st, 2026 12:15 AM.",
    ],
)
def test_plaintext_usage_cap_yields_absolute_reset(tmp_path, line):
    """The real Codex CLI cap line must produce a far-future reset window.

    Before the repair this returned ``None`` and the caller defaulted to a
    300-second spin-wait, so the far-future-reset resume guard never fired.
    """
    log = tmp_path / "_stdio_depth.log"
    log.write_text(line + "\n", encoding="utf-8")
    estimate = M.estimate_rate_limit_wait_seconds(log)
    assert estimate is not None, "plain-text usage cap was not recognized"
    assert estimate > D._RATE_LIMIT_RESUME_THRESHOLD_S, (
        "a multi-day cap must exceed the resume threshold so the driver "
        "pauses for resume instead of spin-waiting into the same cap"
    )


def test_unanchored_prose_is_not_a_reset_window(tmp_path):
    """Model prose mentioning a limit must not mint a control-plane window."""
    log = tmp_path / "_stdio_depth.log"
    log.write_text(
        "The contract reached its usage limit; try again at Sep 21st, 2026 "
        "12:15 AM per the spec.\n",
        encoding="utf-8",
    )
    assert M.estimate_rate_limit_wait_seconds(log) is None


def test_generation_ledger_uses_durable_publication(tmp_path, monkeypatch):
    """The fence ledger must publish via the durable path, not a raw replace.

    fsync(2): "Calling fsync() does not necessarily ensure that the entry in
    the directory containing the file has also reached disk. For that an
    explicit fsync() on a file descriptor for the directory is also needed."
    A hand-rolled write_text + file-fsync + os.replace can therefore lose the
    rename on crash, the counter goes BACKWARDS, and the next dispatch replays
    an already-consumed leaf key -- re-entering the production failure this
    ledger exists to prevent, via the durability layer.
    """
    seen = {}
    real = D._atomic_driver_bytes

    def _spy(path, data):
        seen["path"] = Path(path)
        return real(path, data)

    monkeypatch.setattr(D, "_atomic_driver_bytes", _spy)
    D._reserve_transport_generation(
        scratchpad=tmp_path, config=_CONFIG, phase_name="depth", outer_attempt=1
    )
    assert seen.get("path") == tmp_path / D._TRANSPORT_GENERATION_NAME, (
        "generation ledger bypassed the durable publication path"
    )


def test_unpersistable_generation_refuses_to_dispatch(tmp_path, monkeypatch):
    """A generation we cannot prove durable must never be handed out."""
    def _boom(path, data):
        raise OSError("simulated ENOSPC during fence publication")

    monkeypatch.setattr(D, "_atomic_driver_bytes", _boom)
    with pytest.raises(Exception) as caught:
        D._reserve_transport_generation(
            scratchpad=tmp_path, config=_CONFIG, phase_name="depth",
            outer_attempt=1,
        )
    assert "transport generation" in str(caught.value)


def test_resume_across_driver_upgrade_does_not_replay(tmp_path):
    """A run that started under the OLD driver must not restart at 1.

    The old driver minted leaf ordinals from the semantic attempt and kept no
    generation ledger.  Resuming under the new driver with an absent ledger and
    starting at generation 1 would hand out an ordinal the earlier process
    already consumed -- INVOCATION_REPLAY, the original bug, re-entering across
    a mid-run driver upgrade.
    """
    # Evidence left behind by the pre-upgrade process.
    for n in (1, 2, 3):
        (tmp_path / f"_stdio_depth.attempt{n}.log").write_text("x", encoding="utf-8")
    generation = D._reserve_transport_generation(
        scratchpad=tmp_path, config=_CONFIG, phase_name="depth", outer_attempt=2,
    )
    assert generation > 3, (
        f"generation {generation} replays an ordinal the pre-upgrade process "
        "already consumed"
    )


def test_foreign_ledger_still_seeds_above_prior_evidence(tmp_path):
    """Refusing a foreign ledger must not reset the counter to 1 either."""
    (tmp_path / "_stdio_depth.attempt7.log").write_text("x", encoding="utf-8")
    D._reserve_transport_generation(
        scratchpad=tmp_path, config=dict(_CONFIG, _run_id="other-run"),
        phase_name="depth", outer_attempt=1,
    )
    generation = D._reserve_transport_generation(
        scratchpad=tmp_path, config=_CONFIG, phase_name="depth", outer_attempt=1,
    )
    assert generation > 7


def test_fresh_scratchpad_still_starts_at_one(tmp_path):
    """Seeding must not inflate a genuinely fresh run."""
    assert D._reserve_transport_generation(
        scratchpad=tmp_path, config=_CONFIG, phase_name="depth", outer_attempt=1,
    ) == 1
