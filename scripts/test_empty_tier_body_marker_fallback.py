"""Regression tests for the empty-tier validator self-heal from body marker.

Background: `_maybe_skip_empty_body_writer` is the driver's deterministic
path for tier shards with zero findings. It writes BOTH:
  1. The tier body file (e.g. `report_medium_c.md`) containing an
     authentic empty-tier note with `PLAMEN-DRIVER-AUTHENTIC-EMPTY-TIER`
     as a provenance marker in the body text.
  2. A JSON sidecar (`body_manifests/<shard>.empty.json`) with the same
     auth marker.

If the sidecar write fails silently (FS error, permission, parallel
sweep race), the body file is still on disk and is still authentic.
Pre-fix, the legacy tier confirmation handler `report_<tier>_<shard>`
would FAIL the validator because the sidecar was missing, even though
the body file's marker was right there. This halted the entire audit.

A prior audit hit this exact failure mode at phase 42
(`report_medium_c`) — the medium tier had no findings in shard c, the
body-writer skip wrote `report_medium_c.md` with the marker but the
sidecar `body_manifests/report_medium_c.empty.json` was missing on disk.
Pipeline halted with "body validator: manifest report_medium_c.json
missing for report_medium_c.md."

Post-fix: `_empty_tier_sidecar_valid` accepts EITHER the sidecar OR the
body file's authoritative marker. Both routes still cross-check that
`expected_tier_assignment_count == 0` so impostors are rejected.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))


def _write(p: Path, body: str) -> None:
    p.write_text(body, encoding="utf-8")


def _seed_empty_tier_inputs(scratchpad: Path) -> None:
    """Minimal inputs so `_expected_tier_assignment_count` returns 0
    for the medium_c tier shard."""
    # No findings at all → all tiers have 0 → medium_c has 0 by default.
    _write(
        scratchpad / "verification_queue.md",
        "| Queue # | Finding ID | Severity | Title |\n"
        "|---------|------------|----------|-------|\n",
    )
    _write(
        scratchpad / "findings_inventory.md",
        "# Findings Inventory\n\n_No findings produced._\n",
    )


def _AUTHENTIC_NOTE_BODY(shard: str) -> str:
    pretty = shard.replace("report_", "").replace("_", " ").title()
    return (
        f"# {pretty} Findings\n\n"
        "_No findings of this severity tier were produced by the "
        "verification stage in this run. This is an authentic empty "
        "tier; it is not a placeholder for a missing finding. The "
        "driver deterministically skipped the body writer phase "
        f"because the per-shard manifest at `body_manifests/{shard}.json` "
        "was absent (zero reportable findings after Phase 5 / E1-E8 gates)."
        "\n\n## Provenance\n\n"
        f"Phase: report_body_writer_{shard.replace('report_','')} (skipped via empty-shard handler)\n"
        f"Manifest: absent\n"
        "Validator: soft-pass (no findings to validate)\n"
        "Empty-Tier-Auth: PLAMEN-DRIVER-AUTHENTIC-EMPTY-TIER\n"
    )


def test_sidecar_present_accepts(tmp_path: Path):
    """Baseline: when the JSON sidecar exists with the proper auth
    markers, validator accepts."""
    import plamen_validators as V

    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "body_manifests").mkdir()
    _seed_empty_tier_inputs(sp)
    _write(sp / "report_medium_c.md", _AUTHENTIC_NOTE_BODY("report_medium_c"))
    _write(
        sp / "body_manifests" / "report_medium_c.empty.json",
        json.dumps(
            {
                "auth": "PLAMEN-DRIVER-AUTHENTIC-EMPTY-TIER",
                "phase": "report_body_writer_medium_c",
                "shard": "report_medium_c",
                "assigned_count": 0,
                "output": "report_medium_c.md",
            },
            indent=2,
        ),
    )
    assert V._empty_tier_sidecar_valid(sp, "report_medium_c", "report_medium_c.md")


def test_body_marker_accepted_without_sidecar(tmp_path: Path):
    """A prior failure mode: body file has the auth marker,
    sidecar is missing on disk. Pre-fix: validator returned False and
    audit halted. Post-fix: validator accepts via body marker."""
    import plamen_validators as V

    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "body_manifests").mkdir()
    _seed_empty_tier_inputs(sp)
    _write(sp / "report_medium_c.md", _AUTHENTIC_NOTE_BODY("report_medium_c"))
    # NOTE: deliberately NO sidecar written.
    assert V._empty_tier_sidecar_valid(sp, "report_medium_c", "report_medium_c.md"), (
        "Body file with auth marker should pass even when sidecar is "
        "absent — this is the halt fix"
    )


def test_no_marker_no_sidecar_rejects(tmp_path: Path):
    """Impostor case: body file exists but neither sidecar nor marker
    present. Must reject — this is what protects against an LLM
    fabricating an empty tier body."""
    import plamen_validators as V

    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "body_manifests").mkdir()
    _seed_empty_tier_inputs(sp)
    _write(
        sp / "report_medium_c.md",
        "# Medium C Findings\n\nNo findings in this tier.\n",
    )
    assert not V._empty_tier_sidecar_valid(
        sp, "report_medium_c", "report_medium_c.md"
    ), "Body lacking authentic-empty-tier marker must NOT be accepted"


def test_nonzero_expected_count_rejects(tmp_path: Path):
    """When the queue says the tier has findings, an empty-tier note is
    impossible and must be rejected even if marker is present."""
    import plamen_validators as V

    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "body_manifests").mkdir()
    # Forty-one Medium findings deterministically split into three shards at
    # the production cap of 20, so report_medium_c is necessarily non-empty.
    queue_lines = [
        "| Queue # | Finding ID | Severity | Title |",
        "|---------|------------|----------|-------|",
    ]
    queue_lines.extend(
        f"| {i} | INV-{i:03d} | Medium | synthetic {i} |"
        for i in range(1, 42)
    )
    _write(
        sp / "verification_queue.md",
        "\n".join(queue_lines) + "\n",
    )
    for i in range(1, 42):
        _write(
            sp / f"verify_INV-{i:03d}.md",
            "**Severity**: Medium\n**Verdict**: CONFIRMED\n",
        )
    # Body file with marker — but the queue contradicts the empty-tier claim.
    _write(sp / "report_medium_c.md", _AUTHENTIC_NOTE_BODY("report_medium_c"))
    # The cross-check uses `_expected_tier_assignment_count`. The exact
    # routing of INV-X to medium_c depends on driver internals — the
    # important assertion is "if assignment count is non-zero, reject."
    # We test that path explicitly through the helper.
    count = V._expected_tier_assignment_count(sp, "report_medium_c")
    assert count is not None and count > 0, (
        "fixture must deterministically populate report_medium_c; "
        f"got {count}"
    )
    assert not V._empty_tier_sidecar_valid(
        sp, "report_medium_c", "report_medium_c.md"
    ), "Non-zero expected count must reject empty-tier acceptance"


def test_body_with_real_findings_rejects(tmp_path: Path):
    """Edge case: body file claims to be an empty tier (has marker)
    but ALSO contains report ID sections. The full validator path
    (`_validate_tier_body_against_manifest`) calls
    `_extract_report_ids_from_body` BEFORE us — that catches this case
    at the caller. The marker check inside this helper is necessarily
    permissive about content because the caller filters."""
    import plamen_validators as V

    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "body_manifests").mkdir()
    _seed_empty_tier_inputs(sp)
    _write(
        sp / "report_medium_c.md",
        _AUTHENTIC_NOTE_BODY("report_medium_c")
        + "\n\n### [M-99] Real Finding\n\nThis has real content.\n",
    )
    # This helper itself returns True (marker is present). The caller
    # is responsible for the report-ID-presence cross-check. Lock in
    # that semantic so future refactors don't accidentally move the
    # report-ID check into this helper.
    assert V._empty_tier_sidecar_valid(sp, "report_medium_c", "report_medium_c.md")
