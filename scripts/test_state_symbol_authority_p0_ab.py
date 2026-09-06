"""P0-AB typed state-symbol authority and chain-application fixtures."""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest


HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))


def _authority():
    sys.modules.pop("state_symbol_authority", None)
    return importlib.import_module("state_symbol_authority")


def _finding(fid: str, *, location: str, prose: str = "") -> dict:
    return {
        "local_id": fid,
        "title": prose,
        "root_cause": prose,
        "description": prose,
        "location": location,
    }


def _graph(sp: Path, source: str, var_refs: dict) -> None:
    import recon_prepass

    recon_prepass._write_mechanical_graph_json(sp, source, var_refs, {})


def _legacy_global(sp: Path, rows: list[tuple[str, str]]) -> None:
    lines = [
        "# State Write Map",
        "",
        "| State Variable | Writers (function @ file:line) |",
        "|---|---|",
    ]
    lines.extend(f"| `{name}` | {writers} |" for name, writers in rows)
    (sp / "state_write_map.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _legacy_scoped(sp: Path) -> None:
    (sp / "state_write_map.md").write_text(
        "# State Write Map\n\n"
        "## Ledger.sol\n\n"
        "| State Variable | Writer Function | Write Site | Access Guard |\n"
        "|---|---|---|---|\n"
        "| `pending` | settle | src/Ledger.sol:L41 | guarded |\n",
        encoding="utf-8",
    )


def test_real_projection_writer_emits_typed_symbols_and_keeps_var_refs(tmp_path):
    _graph(
        tmp_path,
        "slither",
        {
            "Ledger.pending": {
                "bare": "pending",
                "aliases": ["pending"],
                "declaration_locus": "src/Ledger.sol:L8",
                "read_sites": ["load (src/Ledger.sol:L30)"],
                "write_sites": ["settle (src/Ledger.sol:L41)"],
                "refs": ["load (src/Ledger.sol:L30)", "settle (src/Ledger.sol:L41)"],
                "confidence": "AST_PRECISE",
            }
        },
    )
    payload = json.loads((tmp_path / "_mechanical_graph.json").read_text())
    assert payload["schema_version"] == "plamen.mechanical_graph.v2"
    assert "Ledger.pending" in payload["var_refs"]
    row = payload["state_symbols"][0]
    assert row["symbol_id"].startswith("STATE-")
    assert row["qualified_name"] == "Ledger.pending"
    assert row["bare_aliases"] == ["pending"]
    assert row["declaration_locus"] == "src/Ledger.sol:L8"
    assert row["read_sites"] and row["write_sites"]


def test_scip_projection_shape_is_normalized_without_inventing_write_proof(tmp_path):
    _graph(
        tmp_path,
        "scip",
        {"pkg/mod/Counter#value.": {"bare": "value", "refs": ["src/counter.rs:L22"]}},
    )
    row = json.loads((tmp_path / "_mechanical_graph.json").read_text())["state_symbols"][0]
    assert row["qualified_name"] == "pkg/mod/Counter#value."
    assert row["reference_sites"] == ["src/counter.rs:L22"]
    assert row["write_sites"] == []
    assert row["graph_confidence"] == "REFERENCE_ONLY"


def test_legacy_global_two_column_and_scoped_multicolumn_are_both_parsed(tmp_path):
    s = _authority()
    _legacy_global(tmp_path, [("Ledger.pending", "settle (src/Ledger.sol:L41)")])
    rows, counts = s.parse_legacy_state_symbols(tmp_path)
    assert [r["qualified_name"] for r in rows] == ["Ledger.pending"]
    assert counts["legacy_global_two_column"] == 1

    _legacy_scoped(tmp_path)
    rows, counts = s.parse_legacy_state_symbols(tmp_path)
    assert [r["qualified_name"] for r in rows] == ["Ledger.pending"]
    assert counts["legacy_contract_scoped_multi_column"] == 1
    assert rows[0]["write_sites"] == ["src/Ledger.sol:L41"]


def test_graph_is_authoritative_and_narrative_cannot_overwrite_it(tmp_path):
    s = _authority()
    _graph(tmp_path, "slither", {"A.balance": {"bare": "balance", "refs": ["src/A.sol:L9"]}})
    _legacy_global(tmp_path, [("A.balance", "wrong (src/Fake.sol:L999)"), ("B.extra", "b (src/B.sol:L7)")])
    symbols, counts, _ = s.load_state_symbols(tmp_path)
    by_name = {row["qualified_name"]: row for row in symbols}
    assert by_name["A.balance"]["reference_sites"] == ["src/A.sol:L9"]
    assert by_name["A.balance"]["authority"] == "MECHANICAL_GRAPH"
    assert by_name["B.extra"]["authority"] == "LEGACY_COMPATIBILITY"
    assert counts["legacy_shadowed_by_graph"] == 1


def test_exact_cited_location_precedes_prose_and_read_only_is_resolved(tmp_path):
    s = _authority()
    _graph(
        tmp_path,
        "slither",
        {
            "Ledger.pending": {
                "bare": "pending",
                "declaration_locus": "src/Ledger.sol:L8",
                "read_sites": ["read (src/Ledger.sol:L30)"],
                "write_sites": [],
                "refs": ["read (src/Ledger.sol:L30)"],
            }
        },
    )
    receipt = s.resolve_chain_state(tmp_path, [_finding("INV-1", location="src/Ledger.sol:L30", prose="no alias here")])
    assert receipt["graph_edge_count"] == 1
    assert receipt["prose_edge_count"] == 0
    assert receipt["resolution_edges"][0]["basis"] == "GRAPH_CITED_LOCATION"


def test_word_bounded_prose_fallback_and_same_bare_never_conflate(tmp_path):
    s = _authority()
    _graph(
        tmp_path,
        "slither",
        {
            "A.balance": {"bare": "balance", "refs": ["src/A.sol:L8"]},
            "B.balance": {"bare": "balance", "refs": ["src/B.sol:L8"]},
            "A.rate": {"bare": "rate", "refs": ["src/A.sol:L9"]},
        },
    )
    receipt = s.resolve_chain_state(
        tmp_path,
        [
            _finding("INV-1", location="Other.sol:L1", prose="balance can drift"),
            _finding("INV-2", location="Other.sol:L2", prose="A.balance can drift"),
            _finding("INV-3", location="Other.sol:L3", prose="rate can drift but prorate cannot"),
        ],
    )
    edges = {(e["finding_id"], e["qualified_name"], e["basis"]) for e in receipt["resolution_edges"]}
    assert not any(fid == "INV-1" for fid, _, _ in edges)
    assert ("INV-2", "A.balance", "PROSE_QUALIFIED_ALIAS") in edges
    assert ("INV-3", "A.rate", "PROSE_UNAMBIGUOUS_BARE_ALIAS") in edges


def test_constructor_only_immutable_declaration_can_bind_by_exact_citation(tmp_path):
    s = _authority()
    _graph(
        tmp_path,
        "slither",
        {"Config.domain": {"bare": "domain", "declaration_locus": "src/Config.sol:L5", "refs": []}},
    )
    r = s.resolve_chain_state(tmp_path, [_finding("INV-1", location="src/Config.sol:L5")])
    assert r["graph_edge_count"] == 1


def test_basename_only_citation_cannot_conflate_two_graph_paths(tmp_path):
    s = _authority()
    _graph(
        tmp_path,
        "slither",
        {
            "A.left": {"bare": "left", "refs": ["src/a/State.sol:L9"]},
            "B.right": {"bare": "right", "refs": ["src/b/State.sol:L9"]},
        },
    )
    ambiguous = s.resolve_chain_state(
        tmp_path, [_finding("INV-1", location="State.sol:L9", prose="no alias")]
    )
    assert ambiguous["graph_edge_count"] == 0
    exact = s.resolve_chain_state(
        tmp_path, [_finding("INV-1", location="src/a/State.sol:L9", prose="no alias")]
    )
    assert [edge["qualified_name"] for edge in exact["resolution_edges"]] == ["A.left"]


@pytest.mark.parametrize(
    ("source", "qualified", "bare", "site"),
    [
        ("slither", "Vault.pending", "pending", "src/Vault.sol:L11"),
        ("rust-source", "crate::accounts::Vault::pending", "pending", "src/accounts.rs:L11"),
        ("move-source", "0x1::vault::Vault.pending", "pending", "sources/vault.move:L11"),
        ("go-source", "ledger.State.Pending", "Pending", "pkg/ledger/state.go:L11"),
    ],
)
def test_ecosystem_neutral_symbol_forms(source, qualified, bare, site, tmp_path):
    s = _authority()
    _graph(tmp_path, source, {qualified: {"bare": bare, "refs": [site]}})
    r = s.resolve_chain_state(tmp_path, [_finding("INV-1", location=site)])
    assert r["input_symbol_count"] == 1
    assert r["graph_edge_count"] == 1


def test_populated_graph_zero_edges_is_loud_and_exactly_unresolved(tmp_path):
    s = _authority()
    _graph(tmp_path, "slither", {"A.state": {"bare": "state", "refs": ["src/A.sol:L9"]}})
    r = s.resolve_chain_state(tmp_path, [_finding("INV-1", location="src/B.sol:L1", prose="unrelated")])
    assert r["status"] == "DEGRADED_GRAPH_APPLICATION"
    assert r["unresolved_symbol_ids"] == [r["symbols"][0]["symbol_id"]]
    assert r["unresolved_finding_ids"] == ["INV-1"]
    assert (tmp_path / "chain_state_resolution.degraded").is_file()


def test_explicit_typed_deterministic_negative_is_clean_not_inferred(tmp_path):
    s = _authority()
    _graph(tmp_path, "slither", {"A.state": {"bare": "state", "refs": ["src/A.sol:L9"]}})
    finding = _finding("INV-1", location="src/B.sol:L1", prose="unrelated")
    finding["state_touch_disposition"] = "DETERMINISTIC_NO_STATE_TOUCH"
    finding["state_touch_evidence"] = "typed-source-classification"
    r = s.resolve_chain_state(tmp_path, [finding])
    assert r["status"] == "DETERMINISTIC_NEGATIVE"
    assert not (tmp_path / "chain_state_resolution.degraded").exists()


def test_receipt_input_digest_changes_on_schema_version_or_graph_change(tmp_path):
    s = _authority()
    _graph(tmp_path, "slither", {"A.state": {"bare": "state", "refs": ["src/A.sol:L9"]}})
    a = s.resolve_chain_state(tmp_path, [_finding("INV-1", location="src/A.sol:L9")])
    payload = json.loads((tmp_path / "_mechanical_graph.json").read_text())
    payload["schema_version"] = "plamen.mechanical_graph.v3-test"
    (tmp_path / "_mechanical_graph.json").write_text(json.dumps(payload), encoding="utf-8")
    b = s.resolve_chain_state(tmp_path, [_finding("INV-1", location="src/A.sol:L9")])
    assert a["input_digest"] != b["input_digest"]
    assert b["schema_counts"]["mechanical_graph_schema_version"] == "plamen.mechanical_graph.v3-test"


def test_resolution_receipt_and_debt_are_byte_idempotent(tmp_path):
    s = _authority()
    _graph(tmp_path, "slither", {"A.state": {"bare": "state", "refs": ["src/A.sol:L9"]}})
    findings = [_finding("INV-1", location="src/B.sol:L1", prose="unrelated")]
    s.resolve_chain_state(tmp_path, findings)
    before = (
        (tmp_path / "chain_state_resolution.json").read_bytes(),
        (tmp_path / "chain_state_resolution.degraded").read_bytes(),
    )
    s.resolve_chain_state(tmp_path, findings)
    after = (
        (tmp_path / "chain_state_resolution.json").read_bytes(),
        (tmp_path / "chain_state_resolution.degraded").read_bytes(),
    )
    assert before == after


def test_source_digest_drift_invalidates_receipt_before_phase_commit(tmp_path):
    s = _authority()
    _graph(tmp_path, "slither", {"A.state": {"bare": "state", "refs": ["src/A.sol:L9"]}})
    s.resolve_chain_state(tmp_path, [_finding("INV-1", location="src/A.sol:L9")])
    graph = json.loads((tmp_path / "_mechanical_graph.json").read_text())
    graph["source"] = "mutated-after-resolution"
    (tmp_path / "_mechanical_graph.json").write_text(json.dumps(graph), encoding="utf-8")
    assert any(
        "source digest drift: _mechanical_graph.json" in issue
        for issue in s.validate_chain_state_resolution(tmp_path)
    )


def test_absent_graph_is_not_recorded_as_a_drifting_input(tmp_path):
    s = _authority()
    r = s.resolve_chain_state(
        tmp_path, [_finding("INV-1", location="src/A.sol:L9", prose="none")]
    )
    assert r["status"] == "NO_STATE_SYMBOLS"
    assert "_mechanical_graph.json" not in r["source_artifact_digests"]
    assert s.validate_chain_state_resolution(tmp_path) == []


def test_malformed_graph_cannot_be_cleaned_by_legacy_fallback(tmp_path):
    s = _authority()
    (tmp_path / "_mechanical_graph.json").write_text("{broken", encoding="utf-8")
    _legacy_global(tmp_path, [("A.state", "write (src/A.sol:L9)")])
    r = s.resolve_chain_state(
        tmp_path, [_finding("INV-1", location="src/A.sol:L9", prose="state")]
    )
    assert r["total_edge_count"] == 1
    assert r["status"] == "DEGRADED_GRAPH_SCHEMA"
    assert (tmp_path / "chain_state_resolution.degraded").is_file()


def test_chain_prep_keeps_state_quota_and_separate_tail_family_under_type_volume(tmp_path):
    import chain_prep

    _graph(tmp_path, "slither", {"A.shared_state": {"bare": "shared_state", "refs": ["src/A.sol:L10"]}})
    findings = [
        _finding("INV-1", location="src/A.sol:L10", prose="one"),
        _finding("INV-2", location="src/A.sol:L10", prose="two"),
    ]
    for i in range(3, 146):
        findings.append(_finding(f"INV-{i}", location=f"src/T{i}.sol:L1", prose="sharedIdentifierSignal"))
    # Avoid Markdown parser variability: this fixture exercises the pair engine.
    original = chain_prep._load_inventory
    chain_prep._load_inventory = lambda _: findings
    try:
        out = chain_prep.compute_chain_candidate_pairs(tmp_path)
    finally:
        chain_prep._load_inventory = original
    assert out["state_pairs"] >= 1
    bounded = (tmp_path / "chain_candidate_pairs.md").read_text(encoding="utf-8")
    assert "state-graph: A.shared_state" in bounded
    ledger = json.loads((tmp_path / "chain_tail_disposition_ledger.json").read_text())
    state_rows = [row for row in ledger["pairs"] if row.get("signal_family") == "state"]
    assert state_rows
    receipt = json.loads((tmp_path / "chain_state_resolution.json").read_text())
    assert receipt["signal_family_pair_counts"]["STATE"] == out["state_pairs"]
    assert receipt["signal_family_pair_counts"]["TYPE"] == out["type_pairs"]


def test_driver_hook_persists_graph_application_and_phaseio_debt(tmp_path, monkeypatch):
    import plamen_driver as d

    s = _authority()
    _graph(tmp_path, "slither", {"A.state": {"bare": "state", "refs": ["src/A.sol:L9"]}})
    receipt = s.resolve_chain_state(
        tmp_path,
        [_finding("INV-1", location="src/B.sol:L1", prose="unrelated")],
    )
    assert receipt["status"] == "DEGRADED_GRAPH_APPLICATION"
    monkeypatch.setattr(d, "_record_chain_state_resolution_phase_io", lambda **_: ["fixture PhaseIO failure"])
    issues = d._commit_chain_state_resolution_authority(
        scratchpad=tmp_path,
        config={"pipeline": "sc", "mode": "thorough", "language": "evm"},
        phase=type("P", (), {"name": "chain", "base_timeout_s": 10})(),
    )
    assert any("DEGRADED_GRAPH_APPLICATION" in issue for issue in issues)
    assert any("PhaseIO" in issue for issue in issues)
    debt = (tmp_path / "chain.degraded").read_text(encoding="utf-8")
    assert "DEGRADED_GRAPH_APPLICATION" in debt and "PhaseIO" in debt


def test_phaseio_receipt_is_exact_and_unchanged_replay_is_idempotent(tmp_path):
    import plamen_driver as d

    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "findings_inventory.md").write_text("# inventory\n", encoding="utf-8")
    _graph(sp, "slither", {"A.state": {"bare": "state", "refs": ["src/A.sol:L9"]}})
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(tmp_path),
        "_run_id": "p0-ab-fixture",
    }
    (sp / "_v2_checkpoint.json").write_text(
        json.dumps({"run_id": "p0-ab-fixture"}), encoding="utf-8"
    )
    phase = type("P", (), {"name": "chain", "base_timeout_s": 10})()
    execute, issues = d._arm_chain_state_resolution_phase_io(
        scratchpad=sp, config=config, phase=phase
    )
    assert execute and issues == []
    _authority().resolve_chain_state(
        sp, [_finding("INV-1", location="src/A.sol:L9")]
    )
    assert d._record_chain_state_resolution_phase_io(
        scratchpad=sp, config=config, phase=phase
    ) == []
    # PhaseIO paths are registry-owned; capture all generated contract bytes,
    # then prove an identical call does not mutate them.
    before = json.loads((sp / "_artifact_state.json").read_text())
    assert d._record_chain_state_resolution_phase_io(
        scratchpad=sp, config=config, phase=phase
    ) == []
    after = json.loads((sp / "_artifact_state.json").read_text())
    key = "sc/thorough/evm/claude/chain/state_resolution"
    for field in ("contract_digest", "input_set_digest", "launch_digest"):
        assert before["work_units"][key][field] == after["work_units"][key][field]
    assert (
        before["artifacts"]["chain_state_resolution.json"]["sha256"]
        == after["artifacts"]["chain_state_resolution.json"]["sha256"]
    )
    assert d._validate_chain_state_resolution_phase_io(
        scratchpad=sp,
        project_root=tmp_path,
        mode="thorough",
        language="evm",
        pipeline="sc",
        backend="claude",
        timeout_s=10,
    ) == []


def test_clean_rebuild_clears_only_prior_state_resolution_debt(tmp_path):
    import plamen_driver as d

    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "findings_inventory.md").write_text("# inventory\n", encoding="utf-8")
    _graph(sp, "slither", {"A.state": {"bare": "state", "refs": ["src/A.sol:L9"]}})
    s = _authority()
    s.resolve_chain_state(sp, [_finding("INV-1", location="src/B.sol:L1")])
    (sp / "chain.degraded").write_text(
        "[STATE_GRAPH_APPLICATION] stale\n[OTHER_GATE] preserve\n",
        encoding="utf-8",
    )
    config = {
        "pipeline": "sc", "mode": "thorough", "language": "evm",
        "cli_backend": "claude", "project_root": str(tmp_path),
        "_run_id": "p0-ab-clear-fixture",
    }
    phase = type("P", (), {"name": "chain", "base_timeout_s": 10})()
    # The earlier degraded receipt is uncommitted fixture setup, so retire it
    # before exercising the real arm -> derive -> commit rebuild boundary.
    (sp / "chain_state_resolution.json").unlink()
    execute, issues = d._arm_chain_state_resolution_phase_io(
        scratchpad=sp, config=config, phase=phase
    )
    assert execute and issues == []
    s.resolve_chain_state(sp, [_finding("INV-1", location="src/A.sol:L9")])
    assert d._commit_chain_state_resolution_authority(
        scratchpad=sp, config=config, phase=phase
    ) == []
    debt = (sp / "chain.degraded").read_text(encoding="utf-8")
    assert "STATE_GRAPH_APPLICATION" not in debt
    assert "[OTHER_GATE] preserve" in debt
