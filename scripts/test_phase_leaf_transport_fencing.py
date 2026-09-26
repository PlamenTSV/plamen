"""Monolithic phase-LLM leaves must be fenced per dispatch, not per attempt.

F1 from the fencing sweep, and the last unfixed instance of the defect class
that destroyed DODO run25.

``_run_phase_once`` gives every monolithic phase the compat leaf identity
``label=phase.name``, ``attempt=<semantic phase attempt>`` -- on both the Codex
path and the Claude-headless path -- so its fence key is
``{phase}:{phase}:{attempt}``.  Meanwhile:

* ``_rate_limit_retry_dispatch`` returns attempt 2 for transport recovery;
* the call site advances ``current_attempt`` ONLY for
  ``_INVENTORY_RETRY_MODEL_PHASES``;
* the ordinary gate-failure retry then hardcodes ``_semantic_retry_attempt = 2``
  for every other phase.

So a phase that is rate-limited on attempt 1 and then fails its gate dispatches
attempt 2 twice, the launcher refuses the second with ``INVOCATION_REPLAY``, and
the phase dies having made no provider call.  Blast radius is every post-depth
phase: chain, verify, skeptic, crossbatch, report_index, the tier writers, and
report assembly.

The repair must keep the stdio log path resolvable: ~8 consumers read
``_stdio_{phase}.attempt{N}.log`` to detect rate limits and policy refusals, so
moving the leaf onto a generation without moving them would make that detection
read a nonexistent file -- a silent failure strictly worse than the refusal.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import plamen_driver as D  # noqa: E402


_CONFIG = {"_run_id": "phase-leaf-fencing", "pty_continuation_budget": 3}


def _dispatch_attempts_for(phase_name: str, tmp_path: Path) -> list[int]:
    """Replay the driver's own bookkeeping for one rate-limited phase.

    Mirrors the real sequence: initial dispatch, rate-limit transport recovery
    (which deliberately re-runs the SAME semantic attempt), then the ordinary
    gate-failure retry.
    """
    attempts: list[int] = []
    current_attempt = 1
    attempts.append(D._phase_leaf_transport_attempt(
        scratchpad=tmp_path, config=_CONFIG, phase_name=phase_name,
        semantic_attempt=current_attempt,
    ))

    # Rate-limit transport recovery.
    rl_attempt = 2 if current_attempt < 3 else current_attempt
    attempts.append(D._phase_leaf_transport_attempt(
        scratchpad=tmp_path, config=_CONFIG, phase_name=phase_name,
        semantic_attempt=rl_attempt,
    ))

    # Ordinary gate-failure retry (hardcoded to 2 for non-inventory phases).
    semantic_retry = 2
    attempts.append(D._phase_leaf_transport_attempt(
        scratchpad=tmp_path, config=_CONFIG, phase_name=phase_name,
        semantic_attempt=semantic_retry,
    ))
    return attempts


@pytest.mark.parametrize(
    "phase_name",
    ["chain", "report_index", "skeptic", "crossbatch", "invariants"],
)
def test_rate_limited_then_gate_failed_phase_never_replays_a_leaf(
    phase_name: str, tmp_path: Path,
) -> None:
    """The exact run25 sequence, one layer up from depth."""
    attempts = _dispatch_attempts_for(phase_name, tmp_path)
    assert len(attempts) == len(set(attempts)), (
        f"{phase_name} replayed a consumed leaf ordinal {attempts}; the "
        "compatibility launcher refuses this as INVOCATION_REPLAY and the "
        "phase dies without making a provider call"
    )


def test_leaf_attempts_are_strictly_increasing(tmp_path: Path) -> None:
    attempts = _dispatch_attempts_for("chain", tmp_path)
    assert attempts == sorted(attempts)


def test_phases_do_not_share_a_leaf_namespace(tmp_path: Path) -> None:
    """One phase's dispatches must not consume another phase's ordinals."""
    chain = _dispatch_attempts_for("chain", tmp_path)
    report = _dispatch_attempts_for("report_index", tmp_path)
    # Per-phase sequences are independent; each must be internally fresh.
    assert len(chain) == len(set(chain))
    assert len(report) == len(set(report))


def test_stdio_log_path_resolves_to_the_dispatched_leaf(tmp_path: Path) -> None:
    """Rate-limit detection must read the log the leaf actually wrote.

    This is the coupling that makes F1 non-trivial: if the leaf moves onto a
    transport generation but the log-path consumers keep using the semantic
    attempt, `detect_rate_limit` silently reads a nonexistent file and a real
    throttle becomes invisible.
    """
    leaf = D._phase_leaf_transport_attempt(
        scratchpad=tmp_path, config=_CONFIG, phase_name="chain",
        semantic_attempt=1,
    )
    # The worker writes its log under the leaf ordinal it was dispatched with.
    (tmp_path / f"_stdio_chain.attempt{leaf}.log").write_text(
        "rate limit\n", encoding="utf-8",
    )
    resolved = D._phase_leaf_stdio_log(
        scratchpad=tmp_path, phase_name="chain", semantic_attempt=1,
    )
    assert resolved.exists(), (
        f"log resolver returned {resolved.name}, which does not exist; "
        "rate-limit and policy-refusal detection would read nothing"
    )
    assert resolved.name == f"_stdio_chain.attempt{leaf}.log"


def test_log_resolver_falls_back_for_pre_generation_scratchpads(
    tmp_path: Path,
) -> None:
    """Resume against an old scratchpad has no ledger; must not break."""
    (tmp_path / "_stdio_chain.attempt2.log").write_text("x\n", encoding="utf-8")
    resolved = D._phase_leaf_stdio_log(
        scratchpad=tmp_path, phase_name="chain", semantic_attempt=2,
    )
    assert resolved.name == "_stdio_chain.attempt2.log"


@pytest.mark.parametrize(
    "phase_name", ["inventory_chunk_a", "inventory_chunk_b", "inventory_chunk_c"],
)
def test_inventory_phases_name_leaves_by_semantic_attempt(
    phase_name: str, tmp_path: Path,
) -> None:
    """Inventory retry-model phases must NOT be remapped onto a generation.

    They genuinely advance `current_attempt` (1 -> 2 -> 3) on every semantic
    retry, so the semantic attempt is already a fresh leaf identity. Mapping
    them onto a transport generation puts generation N into attempt N's
    filename slot: DODO run33 reserved generation 2 for semantic attempt 1, the
    leaf wrote `_prompt_inventory_chunk_a.attempt2.md`, and the real semantic
    attempt 2 then collided with its own predecessor's bytes --
    "durable write-once destination contains foreign bytes ... cannot spawn
    subprocess (snapshot is the stdin source)" -- killing the phase after six
    committed phases of real work.
    """
    for semantic in (1, 2, 3):
        leaf = D._phase_leaf_transport_attempt(
            scratchpad=tmp_path, config=_CONFIG, phase_name=phase_name,
            semantic_attempt=semantic,
        )
        assert leaf == semantic, (
            f"{phase_name} attempt {semantic} was remapped to leaf {leaf}; "
            "this collides with the write-once prompt snapshot"
        )
    # No ledger entry should have been minted for these phases at all.
    ledger = tmp_path / D._TRANSPORT_GENERATION_NAME
    if ledger.exists():
        import json
        phases = json.loads(ledger.read_text("utf-8")).get("phases", {})
        assert phase_name not in phases, (
            f"{phase_name} minted a transport generation it must not use"
        )


def test_inventory_log_resolver_matches_dispatch(tmp_path: Path) -> None:
    """The log resolver must look where the inventory leaf actually wrote."""
    (tmp_path / "_stdio_inventory_chunk_a.attempt2.log").write_text(
        "x", encoding="utf-8",
    )
    resolved = D._phase_leaf_stdio_log(
        scratchpad=tmp_path, phase_name="inventory_chunk_a", semantic_attempt=2,
    )
    assert resolved.name == "_stdio_inventory_chunk_a.attempt2.log"
    assert resolved.exists()
