"""R0-6: SC enumeration graph resolution must fail loud, never closed.

The co-reference gate can only derive obligations for inventory findings whose
production source location resolves into the mechanical graph.  These fixtures
lock the health denominator and require missing, degenerate, or materially
under-resolved graph state to reach the shared coverage-shortfall control plane
without suppressing obligations for rows that did resolve.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import enumeration_gate as EG
import plamen_mechanical as PM
import recon_prepass as RP


_PROVIDERS = (
    ("slither", ".sol"),
    ("evm-source", ".sol"),
    ("scip", ".rs"),
    ("rust-source", ".rs"),
    ("move", ".move"),
    ("daml", ".daml"),
)


def _finding(fid: str, location: str, body: str = "No sibling path is addressed.") -> str:
    return (
        f"### Finding [{fid}]: graph-health fixture\n"
        "**Severity**: Medium\n"
        f"**Location**: `{location}`\n"
        f"**Description**: {body}\n"
    )


def _inventory(sp: Path, *blocks: str) -> None:
    (sp / "findings_inventory.md").write_text(
        "# Finding Inventory\n\n" + "\n\n".join(blocks) + "\n",
        encoding="utf-8",
    )


def _graph(sp: Path, source: str, suffix: str, *, include_unresolved: bool = False) -> None:
    functions = {
        "Module.target": {
            "bare": "target", "loc": f"src/Target{suffix}:L10", "callers": [],
        },
        "Module.sibling": {
            "bare": "sibling", "loc": f"src/Target{suffix}:L40", "callers": [],
        },
    }
    if include_unresolved:
        functions["Module.other"] = {
            "bare": "other", "loc": f"src/Other{suffix}:L10", "callers": [],
        }
    payload = {
        "source": source,
        "var_refs": {
            "Module.state": {
                "bare": "state",
                "refs": [
                    f"target (src/Target{suffix}:L10)",
                    f"sibling (src/Target{suffix}:L40)",
                ],
            },
        },
        "functions": functions,
    }
    (sp / "_mechanical_graph.json").write_text(json.dumps(payload), encoding="utf-8")


def _rows(sp: Path, producer: str = "enumeration.axis1.graph_health") -> list[dict]:
    path = sp / "_coverage_shortfalls.json"
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    return [row for row in payload["shortfalls"] if row["producer"] == producer]


def test_missing_graph_emits_unknown_never_halts_or_claims_clean_zero(tmp_path: Path):
    _inventory(tmp_path, _finding("INV-001", "src/Target.sol:L12"))

    assert EG.compute_enumeration_obligations(tmp_path) == 0

    rows = _rows(tmp_path)
    assert len(rows) == 1
    assert rows[0]["scope"] == "location-function-resolution"
    assert rows[0]["kind"] == "PROVIDER_UNAVAILABLE"
    assert rows[0]["count_semantics"] == "UNKNOWN"


def test_malformed_and_degenerate_graphs_emit_unknown_without_raising(tmp_path: Path):
    _inventory(tmp_path, _finding("INV-001", "src/Target.sol:L12"))
    graph_path = tmp_path / "_mechanical_graph.json"

    unrecoverable_payload = {"source": "slither", "functions": [], "var_refs": {}}
    graph_path.write_text(json.dumps(unrecoverable_payload), encoding="utf-8")
    assert EG.compute_enumeration_obligations(tmp_path) == 0
    assert _rows(tmp_path)[0]["kind"] == "PROVIDER_FAILED"

    partially_recoverable_payloads = (
        {
            "source": "slither",
            "functions": {"Module.target": {"bare": 7, "loc": "src/Target.sol:L10"}},
            "var_refs": {},
        },
        {
            "source": "slither",
            "functions": {"Module.target": {"bare": "target", "loc": "src/Target.sol:L10"}},
            "var_refs": {"Module.state": {"bare": "state", "refs": 7}},
        },
    )
    for payload in partially_recoverable_payloads:
        graph_path.write_text(json.dumps(payload), encoding="utf-8")
        assert EG.compute_enumeration_obligations(tmp_path) == 0
        rows = _rows(tmp_path)
        assert any(row["kind"] == "PARTIAL_GRAPH_SCHEMA" for row in rows)
        assert all(row["count_semantics"] == "UNKNOWN" for row in rows)

    graph_path.write_text(
        json.dumps({"source": "slither", "functions": {}, "var_refs": {}}),
        encoding="utf-8",
    )
    assert EG.compute_enumeration_obligations(tmp_path) == 0
    rows = _rows(tmp_path)
    assert len(rows) == 1 and rows[0]["kind"] == "DEGENERATE_GRAPH"
    assert rows[0]["count_semantics"] == "UNKNOWN"


@pytest.mark.parametrize(("source", "suffix"), _PROVIDERS)
def test_under_resolution_is_provider_agnostic_and_keeps_partial_obligations(
    tmp_path: Path, source: str, suffix: str,
):
    _graph(tmp_path, source, suffix)
    _inventory(
        tmp_path,
        _finding("INV-001", f"src/Target{suffix}:L12"),
        _finding("INV-002", f"src/Other{suffix}:L12"),
    )

    # One of two production locations resolves.  Its co-reference obligation
    # must survive even while graph health is loudly below threshold.
    assert EG.compute_enumeration_obligations(tmp_path) == 1
    obligations = json.loads(
        (tmp_path / "_enumeration_obligations.json").read_text(encoding="utf-8")
    )["obligations"]
    assert [row["finding_id"] for row in obligations] == ["INV-001"]

    rows = _rows(tmp_path)
    assert len(rows) == 1
    row = rows[0]
    assert row["kind"] == "GRAPH_RESOLUTION_SHORTFALL"
    assert (row["observed"], row["retained"], row["omitted"]) == (2, 1, 1)
    assert row["count_semantics"] == "EXACT"


def test_threshold_is_explicit_configurable_and_invalid_values_fail_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    _graph(tmp_path, "slither", ".sol")
    _inventory(
        tmp_path,
        _finding("INV-001", "src/Target.sol:L12"),
        _finding("INV-002", "src/Other.sol:L12"),
    )

    monkeypatch.setenv("PLAMEN_GRAPH_LOCATION_RESOLUTION_MIN_RATIO", "0.50")
    assert EG.compute_enumeration_obligations(tmp_path) == 1
    assert _rows(tmp_path) == []  # equality satisfies the configured floor

    for invalid in ("not-a-ratio", "nan", "0", "-0.1", "1.1"):
        monkeypatch.setenv("PLAMEN_GRAPH_LOCATION_RESOLUTION_MIN_RATIO", invalid)
        assert EG.compute_enumeration_obligations(tmp_path) == 1
        assert _rows(tmp_path)[0]["kind"] == "GRAPH_RESOLUTION_SHORTFALL"


def test_no_parseable_nonempty_inventory_is_unknown_not_clean_health(tmp_path: Path):
    _graph(tmp_path, "slither", ".sol")
    _inventory(
        tmp_path,
        _finding("INV-001", "tests/Target.t.sol:L12"),
        _finding("INV-002", "See verification artifacts"),
    )

    assert EG.compute_enumeration_obligations(tmp_path) == 0
    rows = _rows(tmp_path)
    assert len(rows) == 1
    assert rows[0]["kind"] == "LOCATION_UNMEASURABLE"
    assert rows[0]["count_semantics"] == "UNKNOWN"


def test_healthy_graph_with_no_findings_does_not_fire(tmp_path: Path):
    _graph(tmp_path, "slither", ".sol")
    _inventory(tmp_path)

    assert EG.compute_enumeration_obligations(tmp_path) == 0
    assert _rows(tmp_path) == []


def test_graph_health_receipt_is_idempotent_and_self_clears_after_repair(tmp_path: Path):
    _graph(tmp_path, "slither", ".sol")
    _inventory(
        tmp_path,
        _finding("INV-001", "src/Target.sol:L12"),
        _finding("INV-002", "src/Other.sol:L12"),
    )

    assert EG.compute_enumeration_obligations(tmp_path) == 1
    first = (tmp_path / "_coverage_shortfalls.json").read_bytes()
    assert EG.compute_enumeration_obligations(tmp_path) == 1
    assert (tmp_path / "_coverage_shortfalls.json").read_bytes() == first

    _graph(tmp_path, "slither", ".sol", include_unresolved=True)
    assert EG.compute_enumeration_obligations(tmp_path) == 1
    assert _rows(tmp_path) == []


def test_missing_provider_identity_is_unknown_but_resolved_work_continues(tmp_path: Path):
    _graph(tmp_path, "", ".sol")
    _inventory(tmp_path, _finding("INV-001", "src/Target.sol:L12"))

    assert EG.compute_enumeration_obligations(tmp_path) == 1
    rows = _rows(tmp_path)
    assert len(rows) == 1
    assert rows[0]["kind"] == "PROVIDER_UNAVAILABLE"
    assert rows[0]["count_semantics"] == "UNKNOWN"


def test_graph_health_receipt_failure_writes_driver_visible_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    _graph(tmp_path, "slither", ".sol")
    _inventory(tmp_path, _finding("INV-001", "src/Target.sol:L12"))
    original = EG.replace_producer_shortfalls

    def fail_receipt(*_args, **_kwargs):
        raise OSError("injected coverage-ledger failure")

    monkeypatch.setattr(EG, "replace_producer_shortfalls", fail_receipt)
    # Health accounting failure is haltless and must not suppress the valid
    # co-reference obligation.
    assert EG.compute_enumeration_obligations(tmp_path) == 1
    fallback = tmp_path / "report_semantic_enumeration_graph_health.md"
    assert fallback.exists()
    text = fallback.read_text(encoding="utf-8")
    assert "UNKNOWN" in text
    assert "enumeration.axis1.graph_health" in text
    assert "injected coverage-ledger failure" in text
    appendix = PM._build_human_review_appendix(tmp_path)
    assert "Enumeration Graph Health" in appendix
    assert "Coverage State**: **UNKNOWN" in appendix

    # A later successful accounting pass clears the stale fallback.
    monkeypatch.setattr(EG, "replace_producer_shortfalls", original)
    assert EG.compute_enumeration_obligations(tmp_path) == 1
    assert not fallback.exists()


def test_multi_location_finding_uses_one_canonical_resolved_location_everywhere(
    tmp_path: Path,
):
    _graph(tmp_path, "slither", ".sol")
    _inventory(
        tmp_path,
        _finding(
            "INV-001",
            "src/Absent.sol:L12; src/Target.sol:L12",
        ),
    )

    assert EG.compute_enumeration_obligations(tmp_path) == 1
    obligations = json.loads(
        (tmp_path / "_enumeration_obligations.json").read_text(encoding="utf-8")
    )["obligations"]
    assert obligations[0]["finding_id"] == "INV-001"
    assert obligations[0]["function"] == "target"
    assert _rows(tmp_path) == []


def test_exact_relative_path_wins_and_duplicate_basename_fallback_is_ambiguous(
    tmp_path: Path,
):
    payload = {
        "source": "slither",
        "var_refs": {
            "A.left_state": {
                "bare": "left_state",
                "refs": [
                    "left (pkg/a/Target.sol:L10)",
                    "left_sibling (pkg/a/Target.sol:L40)",
                ],
            },
            "B.right_state": {
                "bare": "right_state",
                "refs": [
                    "right (pkg/b/Target.sol:L10)",
                    "right_sibling (pkg/b/Target.sol:L40)",
                ],
            },
        },
        "functions": {
            "A.left": {"bare": "left", "loc": "pkg/a/Target.sol:L10"},
            "A.left_sibling": {
                "bare": "left_sibling", "loc": "pkg/a/Target.sol:L40",
            },
            "B.right": {"bare": "right", "loc": "pkg/b/Target.sol:L10"},
            "B.right_sibling": {
                "bare": "right_sibling", "loc": "pkg/b/Target.sol:L40",
            },
        },
    }
    (tmp_path / "_mechanical_graph.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )
    _inventory(tmp_path, _finding("INV-001", "Target.sol:L12"))

    assert EG.compute_enumeration_obligations(tmp_path) == 0
    rows = _rows(tmp_path)
    assert len(rows) == 1
    assert rows[0]["kind"] == "GRAPH_RESOLUTION_SHORTFALL"
    assert rows[0]["retained"] == 0

    _inventory(tmp_path, _finding("INV-001", "pkg/b/Target.sol:L12"))
    assert EG.compute_enumeration_obligations(tmp_path) == 1
    obligations = json.loads(
        (tmp_path / "_enumeration_obligations.json").read_text(encoding="utf-8")
    )["obligations"]
    assert obligations[0]["function"] == "right"
    assert obligations[0]["symbol"] == "right_state"


def test_scip_path_location_descriptors_resolve_to_function_names(tmp_path: Path):
    payload = {
        "source": "scip",
        "var_refs": {
            "state": {
                "bare": "state",
                # SCIP emits reference locations without function names.
                "refs": ["src/Target.rs:L12", "src/Target.rs:L42"],
            },
        },
        "functions": {
            "Module.target": {"bare": "target", "loc": "src/Target.rs:L10"},
            "Module.sibling": {"bare": "sibling", "loc": "src/Target.rs:L40"},
        },
    }
    (tmp_path / "_mechanical_graph.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )
    _inventory(tmp_path, _finding("INV-001", "src/Target.rs:L12"))

    assert EG.compute_enumeration_obligations(tmp_path) == 1
    obligations = json.loads(
        (tmp_path / "_enumeration_obligations.json").read_text(encoding="utf-8")
    )["obligations"]
    assert obligations[0]["required_corefs"] == ["sibling"]
    assert _rows(tmp_path) == []


def test_path_only_inventory_location_is_unknown_not_clean_zero(tmp_path: Path):
    _graph(tmp_path, "slither", ".sol")
    _inventory(tmp_path, _finding("INV-001", "src/Target.sol"))

    assert EG.compute_enumeration_obligations(tmp_path) == 0
    rows = _rows(tmp_path)
    assert len(rows) == 1
    assert rows[0]["kind"] == "LOCATION_UNMEASURABLE"
    assert rows[0]["count_semantics"] == "UNKNOWN"


def test_vyper_locations_participate_in_health_and_obligations(tmp_path: Path):
    _graph(tmp_path, "vyper-source", ".vy")
    _inventory(tmp_path, _finding("INV-001", "src/Target.vy:L12"))

    assert EG.compute_enumeration_obligations(tmp_path) == 1
    assert _rows(tmp_path) == []


def test_mixed_valid_and_poison_graph_entries_salvage_valid_obligations(
    tmp_path: Path,
):
    _graph(tmp_path, "slither", ".sol")
    graph_path = tmp_path / "_mechanical_graph.json"
    payload = json.loads(graph_path.read_text(encoding="utf-8"))
    payload["functions"]["poison"] = "not-an-object"
    payload["var_refs"]["bad"] = {"bare": "bad", "refs": 7}
    graph_path.write_text(json.dumps(payload), encoding="utf-8")
    _inventory(tmp_path, _finding("INV-001", "src/Target.sol:L12"))

    assert EG.compute_enumeration_obligations(tmp_path) == 1
    rows = _rows(tmp_path)
    assert any(row["kind"] == "PARTIAL_GRAPH_SCHEMA" for row in rows)
    assert all(row["count_semantics"] == "UNKNOWN" for row in rows)


def test_health_production_predicate_matches_graph_producer(tmp_path: Path):
    rels = (
        "src/Target.sol",
        "examples/Example.sol",
        "tests/TestTarget.sol",
        "lib/Dependency.sol",
        ".hidden/Hidden.sol",
        "src/Target.t.sol",
    )
    for rel in rels:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("contract Fixture {}", encoding="utf-8")

    producer = {
        path.relative_to(tmp_path).as_posix()
        for path in RP._production_source_files(tmp_path, (".sol",))
    }
    health = {
        rel
        for rel in rels
        if EG._production_source_locations(f"{rel}:L1")
    }
    assert health == producer


def test_nonproduction_descriptor_cannot_reenter_through_bare_name_fallback(
    tmp_path: Path,
):
    payload = {
        "source": "slither",
        "var_refs": {
            "state": {
                "bare": "state",
                "refs": [
                    "target (src/Target.sol:L10)",
                    "sibling (src/Target.sol:L40)",
                    "poc_helper (tests/Target.t.sol:L10)",
                ],
            },
        },
        "functions": {
            "Module.target": {"bare": "target", "loc": "src/Target.sol:L10"},
            "Module.sibling": {"bare": "sibling", "loc": "src/Target.sol:L40"},
            "Tests.poc_helper": {
                "bare": "poc_helper", "loc": "tests/Target.t.sol:L10",
            },
        },
    }
    (tmp_path / "_mechanical_graph.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )
    _inventory(tmp_path, _finding("INV-001", "src/Target.sol:L12"))

    assert EG.compute_enumeration_obligations(tmp_path) == 1
    obligations = json.loads(
        (tmp_path / "_enumeration_obligations.json").read_text(encoding="utf-8")
    )["obligations"]
    assert obligations[0]["required_corefs"] == ["sibling"]


def test_empty_varrefs_is_unknown_capability_for_nonempty_inventory(tmp_path: Path):
    _graph(tmp_path, "slither", ".sol")
    graph_path = tmp_path / "_mechanical_graph.json"
    payload = json.loads(graph_path.read_text(encoding="utf-8"))
    payload["var_refs"] = {}
    graph_path.write_text(json.dumps(payload), encoding="utf-8")
    _inventory(tmp_path, _finding("INV-001", "src/Target.sol:L12"))

    assert EG.compute_enumeration_obligations(tmp_path) == 0
    rows = _rows(tmp_path)
    assert len(rows) == 1
    assert rows[0]["kind"] == "COREFERENCE_CAPABILITY_EMPTY"
    assert rows[0]["count_semantics"] == "UNKNOWN"
