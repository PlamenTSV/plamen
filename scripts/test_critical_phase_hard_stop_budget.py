"""RETRACTED HYPOTHESIS — kept as a record of what `critical` actually means.

DO NOT re-apply the demotion this file originally asserted. It was WRONG, and
the way it was wrong is worth keeping.

The original hypothesis and its disproof are recorded in THE_MISTAKE below.
The two tests in this file now GUARD AGAINST re-applying it.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from plamen_types import L1_PHASES, SC_PHASES  # noqa: E402


THE_MISTAKE = """
The hypothesis: 59 of 75 SC phases were `critical=True`; 30 of those were verify
shards declaring no required artifact; `wait_critical_halt_choice()` returns
"exit" on a non-TTY; therefore those 30 were unjustified hard stops and
demoting them would raise completion probability from 4.9% to 22.6% at a 5%
per-phase failure rate.

The arithmetic was right and the conclusion was WRONG, because the premise that
`critical=True` means "hard stop" is false for these phases.

`test_driver_smoke.py::test_scenario_h_verify_completeness_gate` is the
disproof, and it is explicit: a degraded `verify_medium_a` must end up

    - in checkpoint["degraded"], AND
    - in checkpoint["completed"]  ("completed-with-debt shard must remain
      resumably completed"), AND
    - with phase_commits["verify_medium_a"]["state"] == "COMPLETED_WITH_DEBT",
    - with a `verify_medium_a.degraded` marker, and a
      `verification_runtime_debt.json` row.

So on a verify shard, `critical=True` is what routes a failure into the TYPED
DEBT lane — degraded-but-resumably-completed, with proof authority NONE
recorded for every unresolved queue row. Demoting the shard does not "let the
haltless design work"; it converts a recorded, resumable, report-visible debt
obligation into a silent skip. That is precisely the provenance-laundering
failure mode this driver exists to prevent — the same class as the
`never_cut_checkpoint` and inventory-manifest defects found earlier in this
same session.

Three tests caught it: scenario H (verify completeness gate), scenario I
(phase containment detector), scenario K (inventory sharding). They passed with
the demotion reverted and failed with it applied, which is the decisive
attribution.

WHAT REMAINS TRUE AND UNRESOLVED:
  * `wait_critical_halt_choice()` really does return "exit" on a non-TTY, and
    every Claude bring-up run (27 recon, 30 instantiate, 31 breadth) really did
    exit on a critical degrade rather than continue.
  * So SOME critical phases hard-stop and some route to typed debt. The
    difference is not visible from the `critical` flag alone.
  * The real question is therefore NOT "how many phases are critical" but
    "which critical phases lack a debt lane, and why". Answer that from the
    driver's degrade paths before touching the phase table again.
"""


def test_the_demotion_hypothesis_is_retracted() -> None:
    """Guard: the 50 verify shards must stay critical.

    Demoting them loses the COMPLETED_WITH_DEBT authority that
    test_scenario_h_verify_completeness_gate requires. If a future change wants
    to reduce hard stops, it must first give these shards an explicit debt lane
    that does not depend on the `critical` flag.
    """
    shards = [
        phase for phase in (*SC_PHASES, *L1_PHASES)
        if phase.name.startswith(("sc_verify_", "verify_"))
        and phase.name not in {
            "sc_verify_queue", "sc_verify_aggregate",
            "verify_queue", "verify_aggregate",
        }
        and not phase.expected_artifacts
    ]
    assert shards, "verify shard family disappeared; update this test"
    demoted = [p.name for p in shards if not getattr(p, "critical", False)]
    assert demoted == [], (
        "these verify shards were demoted from critical; that removes their "
        "COMPLETED_WITH_DEBT lane and silently drops verification debt. See "
        f"THE_MISTAKE in this file: {demoted}"
    )


def test_spine_phases_remain_critical() -> None:
    by_name = {phase.name: phase for phase in SC_PHASES}
    for name in ("recon", "instantiate", "breadth", "depth", "report_assemble"):
        assert by_name[name].critical, f"{name} must remain a hard stop"
    assert "AUDIT_REPORT.md" in by_name["report_assemble"].expected_artifacts
