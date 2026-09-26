"""A failed GATE must not hide a successful MODEL execution.

DODO run34 died terminal at `inventory_chunk_a`:

    [ERROR] retry attempt 3 stopped before provider launch;
            durable transition remains 2 -> 2
    [INVENTORY_RETRY_PLAN_DEBT] attempt 3 launch vetoed: ArtifactLedgerError:
      attempt 2 terminal receipt recovery failed:
      successful inventory terminal authority lacks committed MODEL output

Attempt 2 had SUCCEEDED and made large progress: the exact-reconciliation gate
went from "20/20 assigned raw identity(s) remain NEEDS_INVENTORY_REVIEW" to
"3/20", it published `findings_inventory_chunk_a.md` at 80,498 bytes / 40
parsed entries, and its retry receipt was coherent (status=PROGRESSED,
terminal_rc=0, distinct output digests).

Root cause: in `_run_phase_validators`, the inventory-chunk branch called
`_record_typed_model_phase_artifacts(...)` ONLY in the `else` (gate-passed)
branch. Attempt 2 had chunk issues, took the `if` branch, wrote a retry hint,
and never committed its MODEL output -- leaving the work unit at
`semantic_status=INPUTS_BOUND` / `execution_state=INPUTS_BOUND_PREEXECUTION`.
The successor's pre-launch check requires a `terminal_rc == 0` inventory
authority to show `ACTIVE` / `OUTPUT_COMMITTED`, found the pre-execution state,
and refused to launch.

A gate failure and a MODEL-execution commit are DIFFERENT FACTS. The provider
turn ran and published bytes; only the CONTENT failed its structural gate.

The assertion that vetoed attempt 3 is CORRECT and must stay: an rc=0 with a
genuinely uncommitted output is an inconsistent state. The negative control
below pins that -- a unit whose provider turn never executed must still be
refused.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))


_DRIVER = (_SCRIPTS / "plamen_driver.py").read_text(encoding="utf-8")


def _inventory_chunk_validator_region() -> str:
    """The `_run_phase_validators` inventory-chunk branch, source-exact."""
    start = _DRIVER.find("chunk_issues = _validate_inventory_chunk_structure")
    assert start != -1, "inventory chunk validation branch not found"
    end = _DRIVER.find("_record_inventory_reconciliation_phase_io", start)
    assert end != -1, "inventory reconciliation phase-io call not found"
    return _DRIVER[start:end]


def test_model_commit_happens_on_the_gate_failure_path() -> None:
    """The regression: both branches must record the MODEL execution."""
    region = _inventory_chunk_validator_region()
    commits = region.count("_record_typed_model_phase_artifacts")
    assert commits >= 2, (
        "the inventory chunk branch records its MODEL execution in only "
        f"{commits} place(s). A gate-failing attempt then leaves its work unit "
        "at INPUTS_BOUND_PREEXECUTION and vetoes its own successor "
        "(DODO run34: 'successful inventory terminal authority lacks "
        "committed MODEL output')."
    )


def test_gate_failure_commit_precedes_the_retry_hint() -> None:
    """Commit before handing the worker a retry hint, so the successor can replay."""
    region = _inventory_chunk_validator_region()
    commit_at = region.find("_record_typed_model_phase_artifacts")
    hint_at = region.find("_write_retry_hint")
    assert commit_at != -1 and hint_at != -1
    assert commit_at < hint_at, (
        "the MODEL commit must be recorded before the retry hint is written"
    )


def test_commit_failure_becomes_visible_debt_not_silence() -> None:
    """A failed commit must be recorded, never swallowed."""
    region = _inventory_chunk_validator_region()
    assert "INVENTORY_CHUNK_MODEL_COMMIT_ON_GATE_FAILURE" in region, (
        "a failure to record the MODEL commit must surface as typed debt"
    )
    assert "_append_phase_io_debt" in region


def test_rc_zero_committed_output_assertion_is_intact() -> None:
    """NEGATIVE CONTROL: the guard that caught this must NOT be weakened.

    An rc=0 terminal authority whose unit never reached ACTIVE/OUTPUT_COMMITTED
    is genuinely inconsistent and must still be refused. A fix that deleted this
    assertion would make every veto vanish and disarm a real guard.
    """
    assert (
        "successful inventory terminal authority lacks committed MODEL output"
        in _DRIVER
    ), "the rc=0 committed-output assertion was removed; that disarms the guard"
    pattern = re.compile(
        r'semantic_status\s*!=\s*"ACTIVE"\s*\n\s*or\s+execution_state\s*'
        r'!=\s*"OUTPUT_COMMITTED"'
    )
    assert pattern.search(_DRIVER), (
        "the ACTIVE/OUTPUT_COMMITTED requirement for a successful inventory "
        "terminal authority is no longer enforced"
    )


def test_commit_is_exception_isolated() -> None:
    """Bookkeeping must never mask the gate result it accompanies."""
    region = _inventory_chunk_validator_region()
    assert "except Exception" in region, (
        "the gate-failure MODEL commit must be exception-isolated so a "
        "bookkeeping error cannot replace the real gate diagnosis"
    )
