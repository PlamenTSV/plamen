"""P2-B fixtures for bounded assurance-debt client/model projections."""

from __future__ import annotations

import json
from pathlib import Path

from assurance_limitations import (
    ASSURANCE_PROJECTION_MAX_GROUPS,
    build_assurance_manifest,
    build_assurance_projection_manifest,
    project_assurance_limitations,
    validate_assurance_projection,
)
from plamen_types import Checkpoint


def _rows(count: int, *, groups: int = 1) -> tuple[dict, ...]:
    return tuple(
        {
            "phase": f"chain_{index % groups:03d}",
            "work_unit_id": f"packet-{index:06d}",
            "state": "COMPLETED_WITH_DEBT",
            "assurance_impact": "DISCOVERY_RECALL",
            "gate_id": f"chain.coverage.{index:06d}",
            "gate_class": "CHAIN_COVERAGE",
            "affected_identities": [f"CH-{index + 1}"],
            "message": "Unresolved composition coverage obligation " + ("x" * 500),
            "failure_instance_id": f"failure-{index:06d}",
        }
        for index in range(count)
    )


def test_thousands_of_rows_remain_authoritative_but_projection_is_bounded() -> None:
    manifest = build_assurance_manifest(
        Checkpoint(run_id="run-bounded"), supplemental_rows=_rows(7_546)
    )

    projection = build_assurance_projection_manifest(manifest)

    assert manifest["row_count"] == len(manifest["rows"]) == 7_546
    assert projection["source_manifest_sha256"] == manifest["manifest_sha256"]
    assert projection["source_row_count"] == 7_546
    assert projection["represented_row_count"] == 7_546
    assert projection["omitted_row_count"] == 0
    assert projection["projected_group_count"] == 1
    assert projection["groups"][0]["row_count"] == 7_546
    assert projection["groups"][0]["affected_identity_count"] == 7_546
    assert len(projection["groups"][0]["affected_identity_samples"]) <= 8
    assert len(json.dumps(projection, sort_keys=True).encode("utf-8")) < 32_000


def test_group_overflow_is_digest_bound_and_never_claimed_as_complete_projection() -> None:
    manifest = build_assurance_manifest(
        Checkpoint(run_id="run-overflow"),
        supplemental_rows=_rows(250, groups=250),
    )

    projection = build_assurance_projection_manifest(manifest)

    assert projection["projected_group_count"] == ASSURANCE_PROJECTION_MAX_GROUPS
    assert projection["omitted_group_count"] == 250 - ASSURANCE_PROJECTION_MAX_GROUPS
    assert projection["represented_row_count"] + projection["omitted_row_count"] == 250
    assert projection["omitted_row_count"] > 0
    assert len(projection["omitted_groups_digest"]) == 64
    assert projection["projection_complete"] is False
    # The source manifest, not the bounded projection, retains every identity.
    assert sum(len(row["affected_identities"]) for row in manifest["rows"]) == 250


def test_projection_sidecar_and_report_bind_exact_full_manifest(tmp_path: Path) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    report = tmp_path / "AUDIT_REPORT.md"
    report.write_text("# Audit Report\n", encoding="utf-8")
    checkpoint = Checkpoint(run_id="run-projection")

    # Use a typed-like supplemental authority by monkeypatching only the pure
    # builder entrypoint consumed by project/validate; no report bytes are
    # hand-authored by the fixture.
    import assurance_limitations as A

    manifest = build_assurance_manifest(
        checkpoint, supplemental_rows=_rows(7_546)
    )
    original = A.build_current_assurance_manifest
    A.build_current_assurance_manifest = lambda *args, **kwargs: manifest
    try:
        project_assurance_limitations(checkpoint, scratchpad, report)
        assert validate_assurance_projection(checkpoint, scratchpad, report) == []
    finally:
        A.build_current_assurance_manifest = original

    projection = json.loads(
        (scratchpad / "assurance_limitations_projection.json").read_text(
            encoding="utf-8"
        )
    )
    rendered = report.read_text(encoding="utf-8")
    assert projection["source_row_count"] == 7_546
    assert manifest["manifest_sha256"] in rendered
    assert "assurance_limitations.json" in rendered
    assert len(rendered.encode("utf-8")) < 32_000
