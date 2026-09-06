"""P0-AC report-dedup denominator and exact-pair coverage contracts.

The live failure shape had a mechanically known denominator larger than the
bounded Markdown projection.  Coverage then treated two IDs appearing anywhere
in the decision prose as disposition of their candidate pair.  These fixtures
stay protocol-neutral while preserving that shape: 88 total pairs, 50 prompt
rows, 38 tail rows, and two projected pairs whose endpoints appear elsewhere
but which never receive an exact disposition.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import plamen_parsers as P
import plamen_validators as V


def _write_88_pair_report_index(scratchpad: Path) -> None:
    lines = [
        "# Report Index",
        "",
        "## Master Finding Index",
        "",
        "| Report ID | Title | Severity | Location |",
        "|---|---|---|---|",
    ]
    # A unique file per two-row group yields exactly one candidate pair per
    # group.  Cross-tier generation is location-based, so this makes exactly
    # 88 deterministic pairs without relying on title heuristics.
    for idx in range(1, 89):
        lines.append(
            f"| H-{idx:03d} | Primary observation {idx} | High | "
            f"src/Module{idx:03d}.sol:L10-L20 |"
        )
        lines.append(
            f"| M-{idx:03d} | Secondary observation {idx} | Medium | "
            f"src/Module{idx:03d}.sol:L10-L20 |"
        )
    (scratchpad / "report_index.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def _load_ledger(scratchpad: Path) -> dict:
    return json.loads(
        (scratchpad / "report_dedup_candidate_pairs.json").read_text(
            encoding="utf-8"
        )
    )


def _pair_ids(pair: dict) -> tuple[str, str]:
    ids = pair["report_ids"]
    return str(ids[0]), str(ids[1])


def test_all_pairs_json_preserves_88_denominator_and_50_row_projection(
    tmp_path: Path,
) -> None:
    _write_88_pair_report_index(tmp_path)

    projected = P._compute_report_dedup_candidate_pairs(tmp_path)

    assert projected == 50
    ledger = _load_ledger(tmp_path)
    assert ledger["schema_version"] == "plamen.report_dedup_candidate_pairs.v1"
    assert ledger["status"] == "COMPLETE"
    assert ledger["total_pairs"] == 88
    assert ledger["projected_pairs"] == 50
    assert ledger["tail_pairs"] == 38
    assert ledger["projection_cap"] == 50
    assert len(ledger["pairs"]) == 88

    keys = [pair["pair_key"] for pair in ledger["pairs"]]
    assert len(keys) == len(set(keys)) == 88
    assert all(_pair_ids(pair) == tuple(sorted(_pair_ids(pair))) for pair in ledger["pairs"])
    expected_digest = hashlib.sha256(
        ("\n".join(sorted(keys)) + "\n").encode("utf-8")
    ).hexdigest()
    assert ledger["denominator_digest"] == expected_digest
    assert [p["projection_rank"] for p in ledger["pairs"][:50]] == list(
        range(1, 51)
    )
    assert all(p["projection_rank"] is None for p in ledger["pairs"][50:])

    projection = (tmp_path / "report_dedup_candidate_pairs.md").read_text(
        encoding="utf-8"
    )
    assert "50 candidate pair(s)" in projection
    assert "88 candidate pair(s) found" in projection
    data_rows = [
        line
        for line in projection.splitlines()
        if line.startswith("| H-") or line.startswith("| M-")
    ]
    assert len(data_rows) == 50


def test_exact_pair_reconciliation_keeps_38_tail_and_two_emitted_gaps(
    tmp_path: Path,
) -> None:
    _write_88_pair_report_index(tmp_path)
    assert P._compute_report_dedup_candidate_pairs(tmp_path) == 50
    ledger = _load_ledger(tmp_path)
    projected = ledger["pairs"][:50]

    # Dispose exactly 48 projected pairs.  The two omitted pairs' endpoint IDs
    # appear in the QO table, reproducing the old global-ID false-clear without
    # actually disposing either unordered pair.
    lines = [
        "# Report Consolidation Decisions",
        "",
        "## MERGE Decisions",
        "| Survivor | Absorbed | Same Root Cause | Reason |",
        "|---|---|---|---|",
        "",
        "## Quality Observation Reclassifications",
        "| Report ID | Class | Reason |",
        "|---|---|---|",
    ]
    for pair in projected[48:]:
        for report_id in pair["report_ids"]:
            lines.append(f"| {report_id} | cosmetic | endpoint mentioned elsewhere |")
    lines.extend(
        [
            "",
            "## Reviewed - Kept Separate",
            "| Report ID(s) | Reason kept separate |",
            "|---|---|",
        ]
    )
    for pair in projected[:48]:
        a, b = pair["report_ids"]
        lines.append(f"| {a}, {b} | distinct mechanism and remediation |")
    (tmp_path / "report_dedup_agent_decisions.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )

    detail = V._report_dedup_exact_pair_coverage_detail(tmp_path)

    assert detail["denominator_count"] == 88
    assert detail["accounted_count"] == 48
    assert detail["missing_count"] == 40
    assert detail["projected_count"] == 50
    assert detail["projected_accounted_count"] == 48
    assert detail["projected_missing_count"] == 2
    assert detail["tail_count"] == 38
    assert detail["tail_accounted_count"] == 0
    assert detail["tail_missing_count"] == 38
    expected_projected_gaps = {
        pair["pair_key"] for pair in projected[48:]
    }
    assert set(detail["projected_missing_pair_keys"]) == expected_projected_gaps
    assert not detail["ledger_issues"]
    assert not detail["decision_schema_issues"]


def test_exact_pair_reconciliation_ignores_ids_only_in_reason_text(
    tmp_path: Path,
) -> None:
    _write_88_pair_report_index(tmp_path)
    P._compute_report_dedup_candidate_pairs(tmp_path)
    ledger = _load_ledger(tmp_path)
    first = ledger["pairs"][0]
    a, b = first["report_ids"]
    (tmp_path / "report_dedup_agent_decisions.md").write_text(
        "# Report Consolidation Decisions\n\n"
        "## Reviewed - Kept Separate\n"
        "| Report ID(s) | Reason kept separate |\n"
        "|---|---|\n"
        f"| H-999, M-999 | unrelated comparison mentions {a} and {b} |\n",
        encoding="utf-8",
    )

    detail = V._report_dedup_exact_pair_coverage_detail(tmp_path)
    assert first["pair_key"] in detail["missing_pair_keys"]


def test_invalid_typed_denominator_is_loud_not_vacuously_complete(
    tmp_path: Path,
) -> None:
    (tmp_path / "report_dedup_candidate_pairs.json").write_text(
        '{"schema_version":"plamen.report_dedup_candidate_pairs.v1",'
        '"status":"COMPLETE","total_pairs":1,"pairs":[]}',
        encoding="utf-8",
    )
    (tmp_path / "report_dedup_agent_decisions.md").write_text(
        "# Report Consolidation Decisions\n", encoding="utf-8"
    )

    detail = V._report_dedup_exact_pair_coverage_detail(tmp_path)
    assert detail["ledger_issues"]
    issues = V._validate_report_dedup_exact_pair_coverage(tmp_path)
    assert any("typed candidate ledger" in issue for issue in issues)
