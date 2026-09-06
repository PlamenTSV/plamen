"""Realistic resume-revert regression for the verify-queue completeness fix.

This is the test the prior (committed) backfill LACKED. The prior fix raw-
appended 6-column rows AFTER the manifest footer line and left the JSON sidecar
stale, so `parse_verification_queue_rows` (sidecar-authoritative) never saw the
backfilled rows, `_compute_unrouted_inventory_ids` stayed non-empty, the
verify_queue parity gate kept failing, and the resume reconciliation rewound
~15 downstream verify phases on EVERY attempt -> infinite rewind loop.

This test reproduces the FULL reality:
  * findings_inventory.md in the exact `_inventory_blocks` format
  * a queue persisted via the CANONICAL writer (`_write_queue_subset_manifest`),
    so verification_queue.json exists and is authoritative
  * the parity gap seen THROUGH the JSON sidecar (not a toy markdown fixture)
  * a real L1 Checkpoint with verify_queue + the downstream verify phases
    marked completed
  * the real `_reconcile_completed_checkpoint_artifacts` resume path

The load-bearing assertion (Part E): after the canonical backfill closes the
gap, reconciliation returns [] and NONE of the verify phases are rewound.
"""

from pathlib import Path
import json

import plamen_driver as D
import plamen_mechanical as M
import plamen_parsers as P
import plamen_types as T
import plamen_validators as V


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_INV_IDS = [f"INV-{n:03d}" for n in range(1, 17)]  # INV-001 .. INV-016
_COVERED = _INV_IDS[:13]                            # INV-001 .. INV-013
_UNROUTED = _INV_IDS[13:]                           # INV-014 .. INV-016


def _severity_for(i: int) -> str:
    # Spread severities so findings land across crithigh/medium/low shards.
    return ["Critical", "High", "Medium", "Low"][i % 4]


def _write_inventory(sp: Path) -> None:
    """16 findings in the EXACT format `_inventory_blocks` parses."""
    lines = ["# Findings Inventory\n\n", "Total Findings: 16\n\n"]
    for i, fid in enumerate(_INV_IDS):
        sev = _severity_for(i)
        lines.append(f"## Finding [{fid}]: Example bug {fid}\n")
        lines.append(f"**Severity**: {sev}\n")
        lines.append("**Verdict**: CONFIRMED\n")
        lines.append("**Bug Class**: Example Class\n")
        lines.append(f"**Location**: src/contract.sol:L{10 + i}\n")
        lines.append("**Preferred Tag**: [CODE-TRACE]\n")
        lines.append("**Description**: Something is wrong here.\n\n")
    (sp / "findings_inventory.md").write_text("".join(lines), encoding="utf-8")


def _write_partial_canonical_queue(sp: Path) -> None:
    """Persist a queue that covers only INV-001..013 via the CANONICAL writer.

    This is the crucial difference from the prior toy test: the queue is written
    through `_write_queue_subset_manifest`, so verification_queue.json exists and
    is the authoritative source for `parse_verification_queue_rows`. The 3
    unrouted IDs are therefore a real sidecar-visible dropout.
    """
    rows = []
    for i, fid in enumerate(_COVERED):
        rows.append({
            "queue #": str(i + 1),
            "finding id": fid,
            "severity": _severity_for(i),
            "title": f"Example bug {fid}",
            "bug class": "Example Class",
            "preferred tag": "CODE-TRACE",
            "location": f"src/contract.sol:L{10 + i}",
            "primary artifact": "findings_inventory.md",
            "poc class": "structural",
        })
    P._write_queue_subset_manifest(sp / "verification_queue.md", rows)


def _verify_phases_l1_thorough() -> list:
    """Real L1 Phase objects for the verify segment in thorough mode.

    Filtered to verify_queue + every verify_* shard phase (+ verify_aggregate),
    using the actual `L1_PHASES` definitions. semantic_dedup is intentionally
    excluded so this test stays focused on the verify segment; the reconcile
    operates on whatever active list it is given, and prefix-closure is checked
    within that list.
    """
    out = []
    for ph in T.L1_PHASES:
        if "thorough" not in ph.modes:
            continue
        if ph.name == "verify_queue" or ph.name.startswith("verify_"):
            out.append(ph)
    return out


def _write_verify_files(sp: Path) -> None:
    """Write a substantive, tag-bearing verify_<id>.md for every queue ID.

    Needed so the downstream verify shard gates AND the verify_aggregate
    parity/evidence-tag validators pass — i.e. the entire completed prefix is
    genuinely valid and the ONLY thing that could trigger a rewind is the
    verify_queue parity gap. If the backfill works, nothing rewinds.
    """
    rows = P.parse_verification_queue_rows(sp)
    for r in rows:
        fid = r.get("finding id", "")
        if not fid:
            continue
        body = (
            f"# Verification: {fid}\n\n"
            f"**Finding ID**: {fid}\n"
            f"**Verdict**: CONFIRMED\n"
            f"**Severity**: {r.get('severity', 'Medium')}\n"
            f"**Evidence Tag**: [CODE-TRACE]\n\n"
            "### Execution Result\n"
            "- Compiled: N/A\n"
            "- Result: NOT_EXECUTED\n"
            "- Evidence Tag: [CODE-TRACE]\n\n"
            "Manual trace confirms the issue with concrete values.\n"
            "This file is padded well past the 100-byte minimum so the verify "
            "shard and aggregate gates treat it as a real verifier artifact.\n"
        )
        (sp / f"verify_{fid}.md").write_text(body, encoding="utf-8")
    # verify_aggregate expected artifact.
    (sp / "verify_core.md").write_text(
        "# Verification Core\n\n"
        "All queued findings verified. Aggregate of per-finding verify files.\n"
        "This aggregate is padded well past the minimum byte gate so the "
        "verify_aggregate phase contract passes on resume.\n",
        encoding="utf-8",
    )


def _setup(sp: Path) -> None:
    _write_inventory(sp)
    _write_partial_canonical_queue(sp)


# ---------------------------------------------------------------------------
# A-D: dropout reproduced via JSON sidecar, then closed by canonical backfill
# ---------------------------------------------------------------------------

def test_dropout_visible_through_json_sidecar_before_fix(tmp_path: Path):
    sp = tmp_path
    _setup(sp)
    # Sanity: the sidecar exists and is authoritative.
    assert (sp / "verification_queue.json").exists()
    rows = P.parse_verification_queue_rows(sp)
    assert {r["finding id"] for r in rows} == set(_COVERED)
    # C: parity sees the gap THROUGH the sidecar (3 unrouted).
    assert V._compute_unrouted_inventory_ids(sp) == _UNROUTED


def test_canonical_backfill_closes_gap(tmp_path: Path):
    sp = tmp_path
    _setup(sp)
    # D: backfill routes the 3 unrouted IDs.
    appended = M.backfill_unrouted_inventory_into_queue(sp)
    assert appended == _UNROUTED
    # parse_verification_queue_rows now returns all 16 (proves the JSON sidecar
    # was updated, not just markdown after a footer the parser stops at).
    rows = P.parse_verification_queue_rows(sp)
    assert {r["finding id"] for r in rows} == set(_INV_IDS)
    # JSON sidecar is authoritative + consistent.
    import json
    payload = json.loads((sp / "verification_queue.json").read_text(encoding="utf-8"))
    assert payload["row_count"] == 16
    assert {r["finding id"] for r in payload["rows"]} == set(_INV_IDS)
    # _compute_unrouted_inventory_ids is now empty -> no dropout.
    assert V._compute_unrouted_inventory_ids(sp) == []
    # Parity validator reports no dropout/coverage issue.
    issues = V._validate_verification_queue_inventory_parity(sp)
    joined = " ".join(issues).lower()
    assert "dropout" not in joined, issues
    assert "coverage" not in joined, issues


def test_backfilled_rows_are_canonical_10_column(tmp_path: Path):
    sp = tmp_path
    _setup(sp)
    M.backfill_unrouted_inventory_into_queue(sp)
    text = (sp / "verification_queue.md").read_text(encoding="utf-8")
    assert "| Queue # | Finding ID | Expected Output File |" in text
    for fid in _UNROUTED:
        line = next(
            ln for ln in text.splitlines()
            if fid in ln and ln.strip().startswith("|")
        )
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        assert len(cells) == 10, (fid, cells)


# ---------------------------------------------------------------------------
# E: the load-bearing resume-revert assertion
# ---------------------------------------------------------------------------

def test_resume_does_not_rewind_after_backfill(tmp_path: Path):
    sp = tmp_path
    _setup(sp)

    phases = _verify_phases_l1_thorough()
    phase_names = [p.name for p in phases]
    # The active verify segment must contain verify_queue + many downstream
    # verify phases (the ~15 the prior bug rewound).
    assert phase_names[0] == "verify_queue"
    assert "verify_crithigh" in phase_names
    assert "verify_aggregate" in phase_names
    downstream = [n for n in phase_names if n != "verify_queue"]
    assert len(downstream) >= 15, downstream

    # Build a checkpoint where verify_queue + ALL downstream verify phases are
    # completed (prefix-closed within this active segment).
    checkpoint = T.Checkpoint(completed=list(phase_names), degraded=[])

    # C2 backfill (the resume-startup path) closes the queue gap...
    appended = M.backfill_unrouted_inventory_into_queue(sp)
    assert appended == _UNROUTED

    # ...and now the entire completed prefix is genuinely valid: write the
    # per-finding verify files + aggregate so the downstream phase contracts
    # pass. (If they were missing the rewind would be for a DIFFERENT, real
    # reason; we want to isolate the verify_queue-parity cause.)
    _write_verify_files(sp)

    removed = D._reconcile_completed_checkpoint_artifacts(
        sp, str(sp), checkpoint, phases, "thorough"
    )

    # The whole point: NO rewind.
    assert removed == [], removed
    # verify_queue and every downstream verify phase REMAIN completed.
    assert "verify_queue" in checkpoint.completed
    for name in downstream:
        assert name in checkpoint.completed, name
    assert set(checkpoint.completed) == set(phase_names)


def test_resume_requires_severity_receipt_once_typed_work_was_armed(tmp_path: Path):
    """Legacy absence is tolerated; an armed current-run projection is not."""
    sp = tmp_path
    _setup(sp)
    M.backfill_unrouted_inventory_into_queue(sp)
    _write_verify_files(sp)
    (sp / "_artifact_state.json").write_text(
        json.dumps(
            {
                "version": 2,
                "artifacts": {},
                "artifact_bindings": {},
                "work_units": {
                    "l1/thorough/rust/claude/verify_aggregate/independent_severity_reconcile": {}
                },
            }
        ),
        encoding="utf-8",
    )
    aggregate = next(
        phase for phase in _verify_phases_l1_thorough()
        if phase.name == "verify_aggregate"
    )

    issues = D._resume_phase_contract_issues(
        sp,
        str(sp),
        aggregate,
        "thorough",
        "rust",
        "l1",
        "claude",
    )

    assert any(
        "independent severity" in issue.casefold()
        or "independent_severity" in issue.casefold()
        for issue in issues
    ), issues


def test_resume_WOULD_rewind_without_backfill(tmp_path: Path):
    """Control: prove the rewind is real when the gap is NOT closed.

    Without the backfill, verify_queue's parity gate fails -> reconcile rewinds
    verify_queue + the entire downstream verify segment. This is the failure the
    fix prevents; the contrast makes the no-rewind assertion meaningful.
    """
    sp = tmp_path
    _setup(sp)
    phases = _verify_phases_l1_thorough()
    phase_names = [p.name for p in phases]
    checkpoint = T.Checkpoint(completed=list(phase_names), degraded=[])

    # Write verify files for the COVERED ids only (verify_queue still has the
    # 3-ID parity gap because we deliberately skip the backfill here).
    _write_verify_files(sp)

    removed = D._reconcile_completed_checkpoint_artifacts(
        sp, str(sp), checkpoint, phases, "thorough"
    )

    # verify_queue is the first invalid phase -> it and everything after rewind.
    assert "verify_queue" in removed
    assert "verify_aggregate" in removed
    assert "verify_queue" not in checkpoint.completed


# ---------------------------------------------------------------------------
# F: idempotency
# ---------------------------------------------------------------------------

def test_backfill_idempotent_stable_rowcount(tmp_path: Path):
    sp = tmp_path
    _setup(sp)
    first = M.backfill_unrouted_inventory_into_queue(sp)
    assert first == _UNROUTED
    count_after_first = len(P.parse_verification_queue_rows(sp))
    assert count_after_first == 16

    second = M.backfill_unrouted_inventory_into_queue(sp)
    assert second == []  # nothing left to route
    count_after_second = len(P.parse_verification_queue_rows(sp))
    assert count_after_second == 16  # stable, no duplicates
