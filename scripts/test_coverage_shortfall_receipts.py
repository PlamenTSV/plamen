"""R0-5: bounded recall mechanisms must never truncate silently.

These fixtures cover the shared, deterministic receipt contract first.  Gate-
specific fixtures below prove the co-reference and Gate-P paths use it without
turning high-fan-in state into a combinatorial candidate explosion.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import coverage_shortfalls as CS
import enumeration_gate as EG
import plamen_mechanical as M


def _shortfalls(sp: Path) -> list[dict]:
    return json.loads((sp / "_coverage_shortfalls.json").read_text(encoding="utf-8"))[
        "shortfalls"
    ]


def test_receipt_replace_is_deterministic_idempotent_and_deliverable(tmp_path: Path):
    rows = [
        CS.shortfall(
            producer="enumeration.axis1",
            scope="finding:INV-1:variables",
            cap="MAX_VARS_PER_FINDING",
            limit=5,
            observed=8,
            retained=5,
            exact=True,
            samples=["z", "a", "a"],
            detail="state-symbol enumeration exceeded its bounded budget",
        )
    ]
    CS.replace_producer_shortfalls(tmp_path, "enumeration.axis1", rows)
    first_json = (tmp_path / "_coverage_shortfalls.json").read_bytes()
    first_md = (tmp_path / "report_semantic_coverage_shortfalls.md").read_bytes()

    CS.replace_producer_shortfalls(tmp_path, "enumeration.axis1", list(reversed(rows)))
    assert (tmp_path / "_coverage_shortfalls.json").read_bytes() == first_json
    assert (tmp_path / "report_semantic_coverage_shortfalls.md").read_bytes() == first_md

    parsed = _shortfalls(tmp_path)
    assert parsed[0]["omitted"] == 3
    assert parsed[0]["count_semantics"] == "EXACT"
    assert parsed[0]["samples"] == ["a", "z"]
    report = first_md.decode("utf-8")
    assert "COVERAGE-SHORTFALL" in report
    assert "enumeration.axis1" in report

    # Replacing a producer with a clean result removes stale warnings while
    # preserving other producers' rows.
    other = CS.shortfall(
        producer="promotion_gate",
        scope="files",
        cap="PROMO_MAX_FILES",
        limit=1,
        observed=2,
        retained=1,
        exact=True,
    )
    CS.replace_producer_shortfalls(tmp_path, "promotion_gate", [other])
    CS.replace_producer_shortfalls(tmp_path, "enumeration.axis1", [])
    assert {r["producer"] for r in _shortfalls(tmp_path)} == {"promotion_gate"}


def test_receipt_contract_rejects_impossible_forged_or_malformed_truth(tmp_path: Path):
    with pytest.raises(CS.CoverageShortfallError):
        CS.shortfall(
            producer="fixture", scope="scope", cap="CAP", limit=5,
            observed=1, retained=5, exact=True,
        )
    with pytest.raises(CS.CoverageShortfallError):
        CS.shortfall(
            producer="fixture", scope="scope", cap="CAP", limit=1,
            observed=5, retained=2, exact=True,
        )

    valid = CS.shortfall(
        producer="original", scope="scope", cap="CAP", limit=1,
        observed=2, retained=1, exact=True,
    )
    CS.replace_producer_shortfalls(tmp_path, "original", [valid])
    before = (tmp_path / "_coverage_shortfalls.json").read_bytes()
    with pytest.raises(CS.CoverageShortfallError):
        CS.replace_producer_shortfalls(tmp_path, "replacement", [valid])
    with pytest.raises(CS.CoverageShortfallError):
        CS.replace_producer_shortfalls(tmp_path, "original", [None])
    forged = dict(valid)
    forged["receipt_id"] = "CS-" + "0" * 16
    with pytest.raises(CS.CoverageShortfallError):
        CS.replace_producer_shortfalls(tmp_path, "original", [forged])
    assert (tmp_path / "_coverage_shortfalls.json").read_bytes() == before


def test_concurrent_producer_replacement_preserves_every_producer(tmp_path: Path):
    workers = 8
    barrier = threading.Barrier(workers)

    def write(index: int) -> None:
        producer = f"fixture.concurrent.{index}"
        row = CS.shortfall(
            producer=producer,
            scope=f"scope-{index}",
            cap="FIXTURE_CAP",
            limit=1,
            observed=2,
            retained=1,
            exact=True,
        )
        barrier.wait()
        CS.replace_producer_shortfalls(tmp_path, producer, [row])

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(write, range(workers)))

    assert {row["producer"] for row in _shortfalls(tmp_path)} == {
        f"fixture.concurrent.{i}" for i in range(workers)
    }
    assert not list(tmp_path.glob("*.tmp"))
    assert not list(tmp_path.glob(".*.tmp"))


def test_projection_is_bounded_but_json_retains_all_source_rows(tmp_path: Path):
    rows = [
        CS.shortfall(
            producer="fixture.cardinality",
            scope=f"finding-scope-{i}",
            cap="FIXTURE_CAP",
            limit=1,
            observed=2,
            retained=1,
            exact=True,
        )
        for i in range(1000)
    ]
    CS.replace_producer_shortfalls(tmp_path, "fixture.cardinality", rows)
    assert len(_shortfalls(tmp_path)) == 1000
    projection = CS.coverage_shortfalls_projection(tmp_path)
    assert "affected_scopes:1000" in projection
    assert projection.count("\n| CS-") <= CS._PROJECTION_ROW_LIMIT
    assert len(projection.encode("utf-8")) < 50_000


def _write_graph_and_inventory(sp: Path) -> None:
    refs = [f"f{i} (src/C.sol:{10 + i})" for i in range(30)]
    graph = {
        "source": "fixture",
        "functions": {
            "C.target": {"bare": "target", "loc": "src/C.sol:1"},
            **{
                f"C.f{i}": {"bare": f"f{i}", "loc": f"src/C.sol:{10 + i}"}
                for i in range(30)
            },
        },
        "var_refs": {
            "C.zzglobalAccounting": {"bare": "globalAccounting", "refs": refs + ["target (src/C.sol:1)"]},
            "C.01small": {"bare": "small", "refs": refs[:9] + ["target (src/C.sol:1)"]},
            **{
                f"C.extra{i}": {"bare": f"extra{i}", "refs": ["target (src/C.sol:1)", refs[i]]}
                for i in range(6)
            },
        },
    }
    (sp / "_mechanical_graph.json").write_text(json.dumps(graph), encoding="utf-8")
    (sp / "findings_inventory.md").write_text(
        "### Finding [INV-1]: fixture\n"
        "**Severity**: Low\n"
        "**Location**: `src/C.sol:L2`\n"
        "**Description**: generic state interaction\n",
        encoding="utf-8",
    )


def test_axis1_caps_are_loud_and_high_fanin_does_not_expand(tmp_path: Path):
    _write_graph_and_inventory(tmp_path)
    EG.compute_enumeration_obligations(tmp_path)
    payload = json.loads((tmp_path / "_enumeration_obligations.json").read_text())

    # The >25-reference symbol is flagged, never expanded into an arbitrary
    # six-of-N obligation set.
    assert all(o["symbol"] != "globalAccounting" for o in payload["obligations"])
    rows = _shortfalls(tmp_path)
    assert any(r["kind"] == "HIGH_FAN_IN_UNENUMERATED" for r in rows)
    assert any(r["cap"] == "MAX_VARS_PER_FINDING" for r in rows)
    assert any(r["cap"] == "MAX_COREFS_PER_VAR" for r in rows)


def test_high_fanin_projection_groups_duplicate_finding_rows(tmp_path: Path):
    rows = [
        CS.shortfall(
            producer="enumeration.axis1",
            scope=f"finding:INV-{i}:symbol:globalState",
            cap="SKIP_VAR_REF_THRESHOLD",
            limit=25,
            observed=30,
            retained=0,
            exact=True,
            kind="HIGH_FAN_IN_UNENUMERATED",
        )
        for i in (1, 2, 3)
    ]
    CS.replace_producer_shortfalls(tmp_path, "enumeration.axis1", rows)
    projection = CS.coverage_shortfalls_projection(tmp_path)
    assert projection.count("HIGH_FAN_IN_UNENUMERATED") == 1
    assert "affected_findings:3" in projection


def test_emit_candidates_exactly_at_cap_is_clean_but_overflow_is_loud(tmp_path: Path):
    (tmp_path / "findings_inventory.md").write_text("# Inventory\n", encoding="utf-8")

    def cand(i: int) -> dict:
        return {
            "key": f"K{i}",
            "title": f"candidate {i}",
            "location": "`src/C.sol:L1`",
            "source_note": "fixture candidate",
            "root_cause": "generic mechanism",
            "description": "generic description",
            "impact": "generic impact",
        }

    assert EG._emit_candidates(
        tmp_path, [cand(i) for i in range(3)], 3, producer="fixture.deriver"
    ) == 3
    assert not (tmp_path / "_coverage_shortfalls.json").exists()

    assert EG._emit_candidates(
        tmp_path, [cand(i) for i in range(3, 8)], 3, producer="fixture.deriver"
    ) == 3
    row = next(r for r in _shortfalls(tmp_path) if r["producer"] == "fixture.deriver")
    assert row["observed"] == 5 and row["retained"] == 3 and row["omitted"] == 2
    assert row["count_semantics"] == "EXACT"


def _enum_candidate(i: int, prefix: str = "PERSIST") -> dict:
    return {
        "key": f"{prefix}{i}",
        "title": f"candidate {i}",
        "location": "`src/C.sol:L1`",
        "source_note": "fixture candidate",
        "root_cause": "generic mechanism",
        "description": "generic description",
        "impact": "generic impact",
    }


def test_concurrent_candidate_emitters_preserve_inventory_and_receipt_union(
    tmp_path: Path, monkeypatch,
):
    (tmp_path / "findings_inventory.md").write_text("# Inventory\n", encoding="utf-8")
    workers = 8
    barrier = threading.Barrier(workers)
    real_write = EG._write_candidate_artifact

    def widen_pre_fix_race(path: Path, text: str) -> None:
        if path.name == "findings_inventory.md":
            time.sleep(0.03)
        real_write(path, text)

    monkeypatch.setattr(EG, "_write_candidate_artifact", widen_pre_fix_race)

    def emit(i: int) -> int:
        barrier.wait()
        return EG._emit_candidates(
            tmp_path, [_enum_candidate(i, prefix="TX")], 1,
            producer=f"fixture.concurrent.{i}",
        )

    with ThreadPoolExecutor(max_workers=workers) as pool:
        assert list(pool.map(emit, range(workers))) == [1] * workers
    expected = {f"TX{i}" for i in range(workers)}
    assert EG._inventory_candidate_keys(tmp_path) == expected
    assert EG._receipt_candidate_keys(tmp_path) == expected
    assert EG._emitted_candidate_keys(tmp_path) == expected


def test_axis1_inventory_persistence_failure_is_unknown_not_false_retention(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setattr(EG, "_MAX_ENUMGAP_PER_RUN", 2)
    (tmp_path / "findings_inventory.md").write_text(
        "### Finding [INV-1]: base\n"
        "**Severity**: Low\n"
        "**Location**: `src/C.sol:L1`\n"
        "**Description**: no sibling names are discussed\n",
        encoding="utf-8",
    )
    (tmp_path / "_enumeration_obligations.json").write_text(
        json.dumps({
            "obligations": [{
                "finding_id": "INV-1",
                "function": "target",
                "symbol": "state",
                "required_corefs": ["siblingA", "siblingB", "siblingC"],
            }]
        }),
        encoding="utf-8",
    )
    real_write = EG._write_candidate_artifact

    def fail_inventory(path: Path, content: str) -> None:
        if path.name == "findings_inventory.md":
            raise OSError("fixture inventory persistence failure")
        real_write(path, content)

    monkeypatch.setattr(EG, "_write_candidate_artifact", fail_inventory)
    assert EG.validate_enumeration_coverage(tmp_path) == {"gaps": 1, "emitted": 0}
    rows = [
        row for row in _shortfalls(tmp_path)
        if row["producer"] == "enumeration.axis1.emission"
    ]
    assert len(rows) == 1
    assert rows[0]["kind"] == "PERSISTENCE_FAILED"
    assert rows[0]["count_semantics"] == "UNKNOWN"
    assert rows[0]["retained"] == 0
    assert "MAX_ENUMGAP_PER_RUN" not in {row["cap"] for row in rows}
    assert "ENUMGAP-KEY" not in (tmp_path / "findings_inventory.md").read_text()


def test_shared_emitter_receipt_failure_recovers_without_false_retention_or_duplicate(
    tmp_path: Path, monkeypatch
):
    (tmp_path / "findings_inventory.md").write_text("# Inventory\n", encoding="utf-8")
    candidates = [_enum_candidate(i) for i in range(4)]
    real_write = EG._write_candidate_artifact

    def fail_receipt(path: Path, content: str) -> None:
        if path.name == "enumeration_gap_receipt.md":
            raise OSError("fixture receipt persistence failure")
        real_write(path, content)

    monkeypatch.setattr(EG, "_write_candidate_artifact", fail_receipt)
    assert EG._emit_candidates(
        tmp_path, candidates, 2, producer="fixture.persistence"
    ) == 0
    rows = [row for row in _shortfalls(tmp_path) if row["producer"] == "fixture.persistence"]
    assert len(rows) == 1
    assert rows[0]["kind"] == "PERSISTENCE_FAILED"
    assert rows[0]["count_semantics"] == "UNKNOWN"
    assert rows[0]["retained"] == 0
    assert (tmp_path / "findings_inventory.md").read_text().count(
        "<!-- ENUMGAP-KEY:"
    ) == 2

    # Inventory markers recover the first two durable candidates. A healthy
    # resume emits only the tail and repairs the shared key receipt.
    monkeypatch.setattr(EG, "_write_candidate_artifact", real_write)
    assert EG._emit_candidates(
        tmp_path, candidates, 2, producer="fixture.persistence"
    ) == 2
    inventory = (tmp_path / "findings_inventory.md").read_text(encoding="utf-8")
    assert inventory.count("<!-- ENUMGAP-KEY:") == 4
    receipt = (tmp_path / "enumeration_gap_receipt.md").read_text(encoding="utf-8")
    assert all(f"PERSIST{i}" in receipt for i in range(4))
    assert not (tmp_path / "_coverage_shortfalls.json").exists()


def test_source_scan_overflow_is_explicit_lower_bound(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(EG, "_MAX_PER_DERIVER", 3)
    candidates = [{"key": f"K{i}"} for i in range(4)]
    assert len(EG._bounded_deriver_result(tmp_path, "fixture.scan", candidates)) == 3
    row = next(r for r in _shortfalls(tmp_path) if r["producer"] == "fixture.scan")
    assert row["observed"] == 4 and row["omitted"] == 1
    assert row["count_semantics"] == "LOWER_BOUND"
    assert "selected for return" in row["detail"]


def test_source_scan_tail_drains_on_resume(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(EG, "_MAX_PER_DERIVER", 3)
    (tmp_path / "findings_inventory.md").write_text("# Inventory\n", encoding="utf-8")

    def cand(i: int) -> dict:
        return {
            "key": f"TAIL{i}",
            "title": f"candidate {i}",
            "location": "`src/C.sol:L1`",
            "source_note": "fixture",
            "root_cause": "generic mechanism",
            "description": "generic description",
            "impact": "generic impact",
        }

    all_candidates = [cand(i) for i in range(4)]
    first = EG._bounded_deriver_result(tmp_path, "fixture.scan", all_candidates)
    assert [row["key"] for row in first] == ["TAIL0", "TAIL1", "TAIL2"]
    assert EG._emit_candidates(tmp_path, first, 3, producer="fixture.emission") == 3

    second = EG._bounded_deriver_result(tmp_path, "fixture.scan", all_candidates)
    assert [row["key"] for row in second] == ["TAIL3"]
    assert EG._emit_candidates(tmp_path, second, 3, producer="fixture.emission") == 1
    receipt = (tmp_path / "enumeration_gap_receipt.md").read_text(encoding="utf-8")
    assert all(f"TAIL{i}" in receipt for i in range(4))
    assert not (tmp_path / "_coverage_shortfalls.json").exists()


def test_unavailable_provider_replaces_stale_cap_state(tmp_path: Path, monkeypatch):
    stale = CS.shortfall(
        producer="enumeration.deriver.array_uniqueness.scan",
        scope="source-candidate-scan",
        cap="MAX_PER_DERIVER",
        limit=3,
        observed=4,
        retained=3,
        exact=False,
    )
    CS.replace_producer_shortfalls(
        tmp_path, "enumeration.deriver.array_uniqueness.scan", [stale]
    )
    monkeypatch.setattr(EG, "_locate_project_root", lambda _sp: None)
    assert EG.compute_array_uniqueness_candidates(tmp_path) == []
    rows = _shortfalls(tmp_path)
    assert len(rows) == 1
    assert rows[0]["kind"] == "PROVIDER_UNAVAILABLE"
    assert rows[0]["count_semantics"] == "UNKNOWN"


def test_variant_outer_provider_failure_is_unknown_not_clean_zero(
    tmp_path: Path, monkeypatch,
):
    monkeypatch.setattr(EG, "compute_enumeration_obligations", lambda _sp: 0)
    monkeypatch.setattr(
        EG, "validate_enumeration_coverage", lambda _sp: {"gaps": 0, "emitted": 0}
    )
    monkeypatch.setattr(
        EG, "compute_boundary_input_candidates",
        lambda _sp: (_ for _ in ()).throw(RuntimeError("provider regression")),
    )
    monkeypatch.setattr(EG, "compute_symmetric_operation_candidates", lambda _sp: [])
    result = EG.compute_variant_gaps(tmp_path)
    assert result["axis2_emitted"] == 0
    rows = _shortfalls(tmp_path)
    assert any(
        row["producer"] == "enumeration.variant.boundary.orchestration"
        and row["kind"] == "PIPELINE_FAILED"
        and row["count_semantics"] == "UNKNOWN"
        for row in rows
    )


def test_variant_handled_provider_unknown_survives_orchestration_success(tmp_path: Path):
    result = EG.compute_variant_gaps(tmp_path)
    assert result["axis2_emitted"] == 0 and result["axis3_emitted"] == 0
    producers = {row["producer"] for row in _shortfalls(tmp_path)}
    assert "enumeration.variant.boundary.scan" in producers
    assert "enumeration.variant.symmetric.scan" in producers


def test_json_is_authoritative_when_markdown_projection_write_fails(
    tmp_path: Path, monkeypatch
):
    real_write = CS._write_atomic

    def fail_markdown(path: Path, content: str) -> None:
        if path.name == "report_semantic_coverage_shortfalls.md":
            raise OSError("fixture markdown failure")
        real_write(path, content)

    monkeypatch.setattr(CS, "_write_atomic", fail_markdown)
    row = CS.shortfall(
        producer="fixture.producer",
        scope="fixture",
        cap="FIXTURE_CAP",
        limit=1,
        observed=2,
        retained=1,
        exact=True,
    )
    CS.replace_producer_shortfalls(tmp_path, "fixture.producer", [row])
    assert (tmp_path / "_coverage_shortfalls.json").exists()
    assert not (tmp_path / "report_semantic_coverage_shortfalls.md").exists()
    appendix = M._build_human_review_appendix(tmp_path)
    assert "Coverage Shortfalls" in appendix and "FIXTURE_CAP" in appendix


def test_corrupt_json_fails_loud_in_delivered_projection(tmp_path: Path):
    (tmp_path / "_coverage_shortfalls.json").write_text("{broken", encoding="utf-8")
    appendix = M._build_human_review_appendix(tmp_path)
    assert "CONTROL_PLANE_CORRUPTION" in appendix
    assert "coverage as UNKNOWN" in appendix


def test_assembled_appendix_resolves_public_identity_and_keeps_opaque_fallback(
    tmp_path: Path,
):
    scratchpad = tmp_path / "sp"
    scratchpad.mkdir()
    (scratchpad / "report_index.md").write_text(
        "## Summary\n\n"
        "| Severity | Count |\n|----------|-------|\n"
        "| High | 1 |\n| Medium | 0 |\n\n"
        "## Master Finding Index\n\n"
        "| Report ID | Title | Severity | Internal ID |\n"
        "|-----------|-------|----------|-------------|\n"
        "| H-01 | mapped accounting issue | High | INV-041 |\n",
        encoding="utf-8",
    )
    (scratchpad / "report_critical_high.md").write_text(
        "## High Findings\n\n"
        "### [H-01] mapped accounting issue\n\n"
        "**Severity**: High\n\n"
        "Body describing the issue in adequate detail for the quality gate.\n\n"
        "**Impact**:\nAccounting can diverge.\n\n"
        "**PoC Result**:\nCode trace confirms the state transition.\n",
        encoding="utf-8",
    )
    (scratchpad / "report_medium.md").write_text("", encoding="utf-8")
    CS.replace_producer_shortfalls(
        scratchpad,
        "enumeration.axis1",
        [CS.shortfall(
            producer="enumeration.axis1",
            scope="finding:INV-041:variables",
            cap="MAX_VARS_PER_FINDING",
            limit=5,
            observed=7,
            retained=5,
            exact=True,
            samples=["INV-042"],
        )],
    )
    project = tmp_path / "project"
    project.mkdir()
    assert M._assemble_report_python(scratchpad, str(project)) is True
    report = (project / "AUDIT_REPORT.md").read_text(encoding="utf-8")
    assert "## Appendix B: Flagged for Human Review" in report
    assert "H-01 (mapped accounting issue)" in report
    assert "source-ref-" in report
    assert "INV-041" not in report and "INV-042" not in report
    assert "finding:upstream finding:variables" not in report


def test_appendix_reference_mapping_uses_only_typed_internal_column(tmp_path: Path):
    (tmp_path / "report_index.md").write_text(
        "## Master Finding Index\n\n"
        "| Severity | Report ID | Trust Adj. | Internal Finding IDs | Title |\n"
        "|----------|-----------|------------|----------------------|-------|\n"
        "| High | H-01 | related narrative cites INV-999 | INV-041, DS-1 | typed title |\n"
        "\n## Excluded Findings\n\n"
        "| Report ID | Title | Internal Finding IDs |\n"
        "|-----------|-------|----------------------|\n"
        "| H-02 | excluded | INV-777 |\n",
        encoding="utf-8",
    )
    mapping = M._coverage_report_reference_map(tmp_path)
    assert mapping == {
        "INV-041": "H-01 (typed title)",
        "DS-1": "H-01 (typed title)",
    }


def test_appendix_mapping_never_infers_lineage_from_title_or_trust_prose(tmp_path: Path):
    (tmp_path / "report_index.md").write_text(
        "## Master Finding Index\n\n"
        "| Report ID | Title | Severity | Trust Adjustment |\n"
        "|-----------|-------|----------|------------------|\n"
        "| H-01 | concern from INV-999 | High | rejected H-22 |\n",
        encoding="utf-8",
    )
    assert M._coverage_report_reference_map(tmp_path) == {}


def test_appendix_no_lineage_table_cannot_reclassify_later_rows_as_headers(tmp_path: Path):
    (tmp_path / "report_index.md").write_text(
        "## Master Finding Index\n\n"
        "| Report ID | Title | Severity | Trust Adjustment |\n"
        "|-----------|-------|----------|------------------|\n"
        "| H-01 | Internal ID | High | rejected H-22 |\n"
        "\n| Internal ID | Note |\n"
        "|-------------|------|\n"
        "| INV-041 | diagnostic only |\n",
        encoding="utf-8",
    )
    assert M._coverage_report_reference_map(tmp_path) == {}


def test_appendix_mapping_accepts_common_internal_id_alias(tmp_path: Path):
    (tmp_path / "report_index.md").write_text(
        "## Master Finding Index\n\n"
        "| Report ID | Title | Severity | Internal ID |\n"
        "|-----------|-------|----------|-------------|\n"
        "| H-01 | issue | High | INV-041 |\n",
        encoding="utf-8",
    )
    assert M._coverage_report_reference_map(tmp_path) == {
        "INV-041": "H-01 (issue)"
    }


def test_global_enumgap_cap_is_exact_and_idempotent(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(EG, "_MAX_ENUMGAP_PER_RUN", 2)
    (tmp_path / "findings_inventory.md").write_text(
        "### Finding [INV-1]: base\n"
        "**Severity**: Low\n"
        "**Location**: `src/C.sol:L1`\n"
        "**Description**: no sibling names are discussed\n",
        encoding="utf-8",
    )
    (tmp_path / "_enumeration_obligations.json").write_text(
        json.dumps({
            "obligations": [{
                "finding_id": "INV-1",
                "function": "target",
                "symbol": "state",
                "required_corefs": ["siblingA", "siblingB", "siblingC", "siblingD"],
            }]
        }),
        encoding="utf-8",
    )
    result = EG.validate_enumeration_coverage(tmp_path)
    assert result == {"gaps": 1, "emitted": 2}
    row = next(r for r in _shortfalls(tmp_path) if r["cap"] == "MAX_ENUMGAP_PER_RUN")
    assert row["observed"] == 4 and row["retained"] == 2 and row["omitted"] == 2
    assert row["count_semantics"] == "EXACT"

    # The two remaining obligations drain on resume and clear the stale cap row.
    result2 = EG.validate_enumeration_coverage(tmp_path)
    assert result2 == {"gaps": 1, "emitted": 2}
    assert not (tmp_path / "_coverage_shortfalls.json").exists() or not any(
        r["producer"] == "enumeration.axis1.emission" for r in _shortfalls(tmp_path)
    )


def test_hot_function_cap_is_exact(tmp_path: Path, monkeypatch):
    graph = {
        "functions": {
            f"C.f{i}": {
                "bare": f"f{i}",
                "loc": f"src/C.sol:{i + 1}",
                "callers": ["a", "b"],
            }
            for i in range(4)
        },
        "var_refs": {},
    }
    monkeypatch.setattr(EG, "_load_graph", lambda _sp: graph)
    monkeypatch.setattr(EG, "_locate_project_root", lambda _sp: None)
    monkeypatch.setattr(EG, "_MAX_HOT_FUNCTIONS", 2)
    hot = EG.compute_hot_function_set(tmp_path)
    assert len(hot) == 2
    row = next(r for r in _shortfalls(tmp_path) if r["cap"] == "MAX_HOT_FUNCTIONS")
    assert row["observed"] == 4 and row["retained"] == 2 and row["omitted"] == 2
    assert row["count_semantics"] == "EXACT"


def test_gate_p_file_cap_emits_exact_receipt(tmp_path: Path, monkeypatch):
    (tmp_path / "report_index_coverage_seed.md").write_text(
        "| Finding/Hyp ID | Title | Verdict |\n|---|---|---|\n", encoding="utf-8"
    )
    for i in range(3):
        (tmp_path / f"depth_{i}.md").write_text("# no candidates\n", encoding="utf-8")
    monkeypatch.setattr(M, "_PROMO_MAX_FILES", 2)
    M.compute_promotion_orphans(tmp_path)
    row = next(r for r in _shortfalls(tmp_path) if r["cap"] == "PROMO_MAX_FILES")
    assert row["observed"] == 3 and row["retained"] == 2 and row["omitted"] == 1
    assert row["count_semantics"] == "EXACT"


def _gate_p_candidate(path: Path, i: int) -> dict:
    return {
        "source_file": path.name,
        "shape": "finding_block",
        "orig_id": f"D-{i}",
        "title": f"candidate {i}",
        "location": f"src/C.sol:L{10 + i}",
        "text": "missing guard with material impact",
    }


def _patch_gate_p_harvest(monkeypatch, count: int) -> None:
    monkeypatch.setattr(M, "_PROMO_FEEDER_GLOBS", ("depth_*.md",))
    monkeypatch.setattr(
        M,
        "_promo_harvest_finding_blocks",
        lambda path, _text: [_gate_p_candidate(path, i) for i in range(count)],
    )
    monkeypatch.setattr(M, "_promo_harvest_table_rows", lambda *_a: [])
    monkeypatch.setattr(M, "_promo_harvest_excluded_stubs", lambda *_a: [])
    monkeypatch.setattr(M, "_promo_location_is_covered", lambda *_a: False)
    monkeypatch.setattr(M, "_promo_disposition", lambda _c: ("BODY", "fixture"))


def test_gate_p_per_file_cap_is_loud_lower_bound(tmp_path: Path, monkeypatch):
    (tmp_path / "report_index_coverage_seed.md").write_text("| Finding | X | Y |\n")
    (tmp_path / "depth_one.md").write_text("fixture\n")
    _patch_gate_p_harvest(monkeypatch, 3)
    monkeypatch.setattr(M, "_PROMO_MAX_PER_FILE", 2)
    monkeypatch.setattr(M, "_PROMO_MAX_PER_RUN", 10)
    assert len(M.compute_promotion_orphans(tmp_path)) == 2
    row = next(r for r in _shortfalls(tmp_path) if r["cap"] == "PROMO_MAX_PER_FILE")
    assert row["observed"] == 3 and row["retained"] == 2
    assert row["count_semantics"] == "LOWER_BOUND"


def test_gate_p_global_cap_is_loud_lower_bound(tmp_path: Path, monkeypatch):
    (tmp_path / "report_index_coverage_seed.md").write_text("| Finding | X | Y |\n")
    (tmp_path / "depth_one.md").write_text("fixture\n")
    _patch_gate_p_harvest(monkeypatch, 3)
    monkeypatch.setattr(M, "_PROMO_MAX_PER_FILE", 10)
    monkeypatch.setattr(M, "_PROMO_MAX_PER_RUN", 2)
    assert len(M.compute_promotion_orphans(tmp_path)) == 2
    row = next(r for r in _shortfalls(tmp_path) if r["cap"] == "PROMO_MAX_PER_RUN")
    assert row["observed"] == 3 and row["retained"] == 2
    assert row["count_semantics"] == "LOWER_BOUND"


def test_gate_p_tracked_row_after_exact_capacity_does_not_fake_overflow(
    tmp_path: Path, monkeypatch
):
    (tmp_path / "report_index_coverage_seed.md").write_text(
        "| Finding/Hyp ID | Title | Verdict |\n"
        "|----------------|-------|---------|\n"
        "| H-99 | tracked | CONFIRMED |\n",
        encoding="utf-8",
    )
    source = tmp_path / "depth_one.md"
    source.write_text("fixture\n", encoding="utf-8")
    monkeypatch.setattr(M, "_PROMO_FEEDER_GLOBS", ("depth_*.md",))
    candidates = [_gate_p_candidate(source, 1), _gate_p_candidate(source, 2)]
    candidates.append({**_gate_p_candidate(source, 3), "orig_id": "H-99"})
    monkeypatch.setattr(M, "_promo_harvest_finding_blocks", lambda *_a: candidates)
    monkeypatch.setattr(M, "_promo_harvest_table_rows", lambda *_a: [])
    monkeypatch.setattr(M, "_promo_harvest_excluded_stubs", lambda *_a: [])
    monkeypatch.setattr(M, "_promo_location_is_covered", lambda *_a: False)
    monkeypatch.setattr(M, "_promo_disposition", lambda _c: ("BODY", "fixture"))
    monkeypatch.setattr(M, "_PROMO_MAX_PER_FILE", 2)
    monkeypatch.setattr(M, "_PROMO_MAX_PER_RUN", 2)
    assert len(M.compute_promotion_orphans(tmp_path)) == 2
    assert not (tmp_path / "_coverage_shortfalls.json").exists()


def test_gate_p_covered_row_after_exact_capacity_does_not_fake_overflow(
    tmp_path: Path, monkeypatch
):
    (tmp_path / "report_index_coverage_seed.md").write_text(
        "| Finding/Hyp ID | Title | Verdict |\n|---|---|---|\n",
        encoding="utf-8",
    )
    source = tmp_path / "depth_one.md"
    source.write_text("fixture\n", encoding="utf-8")
    candidates = [_gate_p_candidate(source, i) for i in (1, 2, 3)]
    monkeypatch.setattr(M, "_PROMO_FEEDER_GLOBS", ("depth_*.md",))
    monkeypatch.setattr(M, "_promo_harvest_finding_blocks", lambda *_a: candidates)
    monkeypatch.setattr(M, "_promo_harvest_table_rows", lambda *_a: [])
    monkeypatch.setattr(M, "_promo_harvest_excluded_stubs", lambda *_a: [])
    monkeypatch.setattr(
        M, "_promo_location_is_covered", lambda cand, _locs: cand["orig_id"] == "D-3"
    )
    monkeypatch.setattr(M, "_promo_disposition", lambda _c: ("BODY", "fixture"))
    monkeypatch.setattr(M, "_PROMO_MAX_PER_FILE", 2)
    monkeypatch.setattr(M, "_PROMO_MAX_PER_RUN", 2)
    assert len(M.compute_promotion_orphans(tmp_path)) == 2
    assert not (tmp_path / "_coverage_shortfalls.json").exists()


def test_gate_p_duplicate_row_after_exact_capacity_does_not_fake_overflow(
    tmp_path: Path, monkeypatch
):
    (tmp_path / "report_index_coverage_seed.md").write_text(
        "| Finding/Hyp ID | Title | Verdict |\n|---|---|---|\n",
        encoding="utf-8",
    )
    source = tmp_path / "depth_one.md"
    source.write_text("fixture\n", encoding="utf-8")
    first = _gate_p_candidate(source, 1)
    candidates = [first, _gate_p_candidate(source, 2), {**first, "orig_id": "D-3"}]
    monkeypatch.setattr(M, "_PROMO_FEEDER_GLOBS", ("depth_*.md",))
    monkeypatch.setattr(M, "_promo_harvest_finding_blocks", lambda *_a: candidates)
    monkeypatch.setattr(M, "_promo_harvest_table_rows", lambda *_a: [])
    monkeypatch.setattr(M, "_promo_harvest_excluded_stubs", lambda *_a: [])
    monkeypatch.setattr(M, "_promo_location_is_covered", lambda *_a: False)
    monkeypatch.setattr(M, "_promo_disposition", lambda _c: ("BODY", "fixture"))
    monkeypatch.setattr(M, "_PROMO_MAX_PER_FILE", 2)
    monkeypatch.setattr(M, "_PROMO_MAX_PER_RUN", 2)
    assert len(M.compute_promotion_orphans(tmp_path)) == 2
    assert not (tmp_path / "_coverage_shortfalls.json").exists()


def test_gate_p_unreadable_seed_is_unknown_not_orphan_noise(tmp_path: Path, monkeypatch):
    (tmp_path / "report_index_coverage_seed.md").write_text("fixture\n", encoding="utf-8")
    monkeypatch.setattr(M, "_promo_seed_ids", lambda _sp: (_ for _ in ()).throw(OSError("denied")))
    assert M.compute_promotion_orphans(tmp_path) == []
    rows = _shortfalls(tmp_path)
    assert len(rows) == 1
    assert rows[0]["scope"] == "promotion-seed"
    assert rows[0]["kind"] == "PROVIDER_FAILED"
    assert rows[0]["count_semantics"] == "UNKNOWN"


def test_gate_p_unreadable_feeder_is_unknown_not_clean(tmp_path: Path, monkeypatch):
    (tmp_path / "report_index_coverage_seed.md").write_text(
        "| Finding/Hyp ID | Title | Verdict |\n|---|---|---|\n",
        encoding="utf-8",
    )
    feeder = tmp_path / "depth_unreadable.md"
    feeder.write_text("fixture\n", encoding="utf-8")
    monkeypatch.setattr(M, "_PROMO_FEEDER_GLOBS", ("depth_*.md",))
    real_read = Path.read_text

    def fail_feeder(path: Path, *args, **kwargs):
        if path == feeder:
            raise OSError("fixture feeder read failure")
        return real_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", fail_feeder)
    assert M.compute_promotion_orphans(tmp_path) == []
    rows = _shortfalls(tmp_path)
    assert len(rows) == 1
    assert rows[0]["scope"] == "feeder:depth_unreadable.md"
    assert rows[0]["kind"] == "PROVIDER_FAILED"
    assert rows[0]["count_semantics"] == "UNKNOWN"


def test_gate_p_unreadable_inventory_location_map_is_unknown_but_haltless(
    tmp_path: Path, monkeypatch,
):
    (tmp_path / "report_index_coverage_seed.md").write_text(
        "| Finding/Hyp ID | Title | Verdict |\n|---|---|---|\n",
        encoding="utf-8",
    )
    feeder = tmp_path / "depth_one.md"
    feeder.write_text("fixture\n", encoding="utf-8")
    candidate = _gate_p_candidate(feeder, 1)
    monkeypatch.setattr(M, "_PROMO_FEEDER_GLOBS", ("depth_*.md",))
    monkeypatch.setattr(
        M, "_promo_covered_locations",
        lambda _sp: (_ for _ in ()).throw(OSError("inventory denied")),
    )
    monkeypatch.setattr(M, "_promo_harvest_finding_blocks", lambda *_a: [candidate])
    monkeypatch.setattr(M, "_promo_harvest_table_rows", lambda *_a: [])
    monkeypatch.setattr(M, "_promo_harvest_excluded_stubs", lambda *_a: [])
    monkeypatch.setattr(M, "_promo_disposition", lambda _c: ("BODY", "fixture"))
    assert len(M.compute_promotion_orphans(tmp_path)) == 1
    assert any(
        row["scope"] == "inventory-location-reconciliation"
        and row["kind"] == "PROVIDER_FAILED"
        and row["count_semantics"] == "UNKNOWN"
        for row in _shortfalls(tmp_path)
    )


def test_attention_repair_all_named_caps_are_loud(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(M, "_write_security_obligations", lambda *_a: None)
    monkeypatch.setattr(
        M,
        "_parse_security_obligation_items",
        lambda _sp: [
            {"id": f"SO-{i}", "class": "generic", "question": "q", "signals": "s"}
            for i in range(11)
        ],
    )
    monkeypatch.setattr(
        M,
        "_extract_skill_execution_repair_items",
        lambda _sp: [
            {"kind": "skill", "target": f"skill-{i}", "reason": "r", "source": "s"}
            for i in range(9)
        ],
    )
    monkeypatch.setattr(
        M, "_check_perturbation_block_per_finding", lambda _sp: [f"perturb-{i}" for i in range(20)]
    )
    monkeypatch.setattr(
        M,
        "_compute_scip_coverage_sets",
        lambda _sp: {"uncited": [f"src/file{i}.sol" for i in range(17)], "spec_support_indexed": set()},
    )
    monkeypatch.setattr(M, "_write_spec_expectations", lambda *_a: None)
    monkeypatch.setattr(M, "_path_security_weight", lambda _p: 1)
    monkeypatch.setattr(
        M,
        "_extract_graph_attention_rows",
        lambda _sp: [
            {"kind": "graph-row", "target": f"row-{i}", "reason": "r", "source": "g", "evidence": "e"}
            for i in range(13)
        ],
    )
    items = M._build_attention_repair_items(tmp_path, "thorough")
    assert len(items) == M._ATTENTION_REPAIR_MAX_ITEMS
    caps = {row["cap"] for row in _shortfalls(tmp_path)}
    assert {
        "ATTENTION_SECURITY_OBLIGATIONS",
        "ATTENTION_SKILL_REPAIRS",
        "ATTENTION_UNCITED_FILES",
        "ATTENTION_GRAPH_ROWS",
        "ATTENTION_REPAIR_MAX_ITEMS",
    } <= caps
