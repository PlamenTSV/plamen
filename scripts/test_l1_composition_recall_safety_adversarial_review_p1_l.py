"""Adversarial recall review for the conditional P1-L provider."""

from pathlib import Path

import l1_composition_runtime as R
import test_l1_composition_runtime_p1_l as F


def test_unrelated_opaque_finding_does_not_suppress_exact_known_compound_work(
    tmp_path: Path,
) -> None:
    """Global extraction debt is not negative authority over valid graph edges.

    The provider is proposal-only and every survivor still enters independent
    verification.  Therefore an unrelated untyped occurrence must stay as
    visible coverage debt, but it must not erase a fully bound, fully
    dispositioned positive edge between two other occurrences.
    """

    F._write_sources(
        tmp_path,
        F._block("L1-A1"),
        F._block("L1-B1"),
        F._block("L1-OPAQUE"),
    )
    sources = F._source_blocks(tmp_path)
    atom = {"kind": "STATE", "atom_id": "state.commit"}
    F._write_records(
        tmp_path,
        [
            F._record(
                sources["L1-A1"],
                layer="execution",
                subsystem="execution",
                produces=[atom],
            ),
            F._record(
                sources["L1-B1"],
                layer="consensus",
                subsystem="consensus",
                requires=[atom],
            ),
        ],
    )
    runtime = F._derive(tmp_path)
    assert runtime["status"] == "DEGRADED"
    assert runtime["measurable_count"] == 2
    assert runtime["unmeasurable_count"] == 1
    assert len(runtime["work_packets"]) == 1

    receipt = R.reconcile_l1_composition_runtime(runtime, F._proposal(runtime))

    assert receipt["exact_coverage"] is False
    assert receipt["deliverable_obligation_coverage_exact"] is True
    assert len(receipt["compound_handoffs"]) == 1
    assert receipt["compound_handoffs"][0]["authority"] == "PROPOSAL_ONLY"
    assert any(
        debt["code"] == "RUNTIME_COVERAGE_DEGRADED"
        for debt in receipt["debts"]
    )
