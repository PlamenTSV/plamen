"""P1-D fixtures for typed semantic-invariant application authority.

The fixtures define the isolated authority boundary only.  Driver wiring,
PhaseIO ownership, and model prompt compilation are deliberately tested in a
later integration slice.
"""
from __future__ import annotations

import json
from pathlib import Path

import semantic_invariant_authority as A


RUN_ID = "123e4567-e89b-42d3-a456-426614174000"
SNAPSHOT = "a" * 64
SOURCE_SCOPE = "b" * 64


def _checkpoint(root: Path, *, ecosystem: str = "evm") -> None:
    payload = {
        "run_id": RUN_ID,
        "config": {
            "language": ecosystem,
            "mode": "thorough",
            "pipeline": "sc",
        },
        "audit_snapshot": {
            "snapshot_digest": SNAPSHOT,
            "components": {"source_scope": {"digest": SOURCE_SCOPE}},
        },
    }
    (root / "_v2_checkpoint.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _graph(root: Path, rows: list[dict], *, source: str = "fixture") -> None:
    payload = {
        "schema_version": "plamen.mechanical_graph.v2",
        "source": source,
        "state_symbols": rows,
        "var_refs": {},
    }
    (root / "_mechanical_graph.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _read(root: Path, name: str) -> dict:
    return json.loads((root / name).read_text(encoding="utf-8"))


def _application(worklist: dict, rows: list[dict]) -> dict:
    payload = {
        "schema_version": A.APPLICATION_TRACE_SCHEMA,
        "run_binding_digest": worklist["run_binding"]["binding_digest"],
        "authority_digest": worklist["authority_digest"],
        "worklist_digest": worklist["worklist_digest"],
        "producer_operator_digest": "e" * 64,
        "rows": rows,
    }
    payload["payload_digest"] = A.payload_digest(payload)
    return payload


def _delivered(state_id: str, locus: str) -> dict:
    return {
        "state_id": state_id,
        "disposition": "DELIVERED",
        "evidence_loci": [locus],
        "write_site_status": "COMPLETE",
        "semantic_status": "SEMANTICS_OK",
        "result": "All enumerated transitions were checked against the stated meaning.",
    }


def _independent(
    worklist: dict,
    producer_payload: dict,
    rows: list[dict],
    *,
    consumer_kind: str = "APPLICATION_SKEPTIC",
) -> dict:
    payload = {
        "schema_version": A.INDEPENDENT_TRACE_SCHEMA,
        "run_binding_digest": worklist["run_binding"]["binding_digest"],
        "authority_digest": worklist["authority_digest"],
        "worklist_digest": worklist["worklist_digest"],
        "producer_payload_digest": producer_payload["payload_digest"],
        "consumer_kind": consumer_kind,
        "consumer_operator_digest": "d" * 64,
        "rows": rows,
    }
    payload["payload_digest"] = A.payload_digest(payload)
    return payload


def _independently_applied(state_id: str, locus: str, producer_row: dict) -> dict:
    return {
        "state_id": state_id,
        "disposition": "APPLIED",
        "producer_row_digest": A.producer_row_digest(producer_row),
        "evidence_loci": [locus],
        "result": "Independent consumer challenged the producer row against source.",
    }


def test_evm_graph_is_authoritative_without_markdown_and_duplicate_bare_names_stay_distinct(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        [
            {
                "qualified_name": "VaultA.total",
                "bare": "total",
                "declaration_locus": "src/VaultA.sol:L8",
                "write_sites": ["src/VaultA.sol:L22"],
                "state_class": "mutable",
                "type_domain": "uint256",
            },
            {
                "qualified_name": "VaultB.total",
                "bare": "total",
                "declaration_locus": "src/VaultB.sol:L9",
                "write_sites": [],
                "state_class": "immutable",
                "type_domain": "uint256",
            },
        ],
        source="slither",
    )

    authority, worklist, projection = A.derive_semantic_invariant_authority(
        tmp_path
    )

    assert authority["status"] == "READY"
    assert authority["state_count"] == 2
    assert len({row["state_id"] for row in authority["states"]}) == 2
    assert {tuple(row["bare_aliases"]) for row in authority["states"]} == {
        ("total",)
    }
    assert {row["state_class"] for row in authority["states"]} == {
        "MUTABLE",
        "IMMUTABLE",
    }
    assert all(row["authority"] == "MECHANICAL_GRAPH" for row in authority["states"])
    assert worklist["state_count"] == 2
    assert all(row["state_id"] in projection for row in worklist["states"])
    assert "state_variables.md" not in authority["input_bindings"]


def test_phaseio_pre_materializes_missing_compatibility_inputs_without_fabricating_state(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        [
            {
                "qualified_name": "Store.value",
                "bare": "value",
                "declaration_locus": "src/Store.sol:L7",
                "write_sites": ["src/Store.sol:L19"],
                "state_class": "mutable",
                "type_domain": "uint256",
            }
        ],
    )

    created = A.materialize_semantic_invariant_compatibility_inputs(tmp_path)

    assert created == ["state_variables.md", "state_write_map.md"]
    for name in created:
        text = (tmp_path / name).read_text(encoding="utf-8")
        assert "UNAVAILABLE_COMPATIBILITY_INPUT" in text
        assert "authoritative" not in text.casefold()
    authority, worklist, _projection = A.derive_semantic_invariant_authority(tmp_path)
    assert authority["status"] == "READY"
    assert authority["state_count"] == 1
    assert worklist["state_count"] == 1
    assert {row["artifact"] for row in authority["input_bindings"]} == {
        "_mechanical_graph.json",
        "_v2_checkpoint.json",
        "state_variables.md",
        "state_write_map.md",
    }

    before = {
        name: ((tmp_path / name).read_bytes(), (tmp_path / name).stat().st_mtime_ns)
        for name in created
    }
    assert A.materialize_semantic_invariant_compatibility_inputs(tmp_path) == []
    assert before == {
        name: ((tmp_path / name).read_bytes(), (tmp_path / name).stat().st_mtime_ns)
        for name in created
    }


def test_state_write_map_is_additive_but_disagreement_cannot_overwrite_graph(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        [
            {
                "qualified_name": "Ledger.pending",
                "bare": "pending",
                "declaration_locus": "src/Ledger.sol:L7",
                "write_sites": ["src/Ledger.sol:L20"],
                "state_class": "mutable",
            }
        ],
    )
    (tmp_path / "state_write_map.md").write_text(
        "# State Write Map\n\n"
        "## Ledger\n\n"
        "| State Variable | Type | Writers |\n"
        "|---|---|---|\n"
        "| pending | uint256 | src/Ledger.sol:L30 |\n"
        "| compatibilityOnly | uint256 | src/Ledger.sol:L40 |\n",
        encoding="utf-8",
    )

    authority, worklist, _projection = A.derive_semantic_invariant_authority(
        tmp_path
    )

    pending = next(row for row in authority["states"] if row["qualified_name"] == "Ledger.pending")
    assert pending["authority"] == "MECHANICAL_GRAPH"
    assert pending["provider_source"] == "fixture"
    assert pending["write_sites"] == ["src/Ledger.sol:L20", "src/Ledger.sol:L30"]
    assert any(
        row["state_id"] == pending["state_id"]
        and row["kind"] == "WRITE_SITE_SOURCE_DISAGREEMENT"
        for row in authority["conflicts"]
    )
    compatibility = next(
        row for row in authority["states"]
        if row["qualified_name"] == "Ledger.compatibilityOnly"
    )
    assert compatibility["authority"] == "LEGACY_COMPATIBILITY"
    assert authority["status"] == "CONFLICT"
    pending_work = next(row for row in worklist["states"] if row["state_id"] == pending["state_id"])
    assert pending_work["conflict_ids"]


def test_aptos_resource_qualified_state_is_ecosystem_neutral(tmp_path: Path) -> None:
    _checkpoint(tmp_path, ecosystem="aptos")
    _graph(
        tmp_path,
        [
            {
                "qualified_name": "0x1::vault::Vault.pending",
                "bare": "pending",
                "declaration_locus": "sources/vault.move:L11",
                "read_sites": ["sources/vault.move:L31"],
                "write_sites": ["sources/vault.move:L42"],
                "state_class": "mutable",
                "type_domain": "table::Table<address, u64>",
            },
            {
                "qualified_name": "0x1::queue::Queue.pending",
                "bare": "pending",
                "declaration_locus": "sources/queue.move:L9",
                "write_sites": ["sources/queue.move:L28"],
                "state_class": "mutable",
                "type_domain": "u64",
            },
        ],
        source="move-source-graph",
    )

    authority, worklist, _projection = A.derive_semantic_invariant_authority(
        tmp_path
    )

    assert authority["run_binding"]["ecosystem"] == "aptos"
    assert {row["qualified_name"] for row in authority["states"]} == {
        "0x1::vault::Vault.pending",
        "0x1::queue::Queue.pending",
    }
    assert len({row["state_id"] for row in authority["states"]}) == 2
    assert {row["type_domain"] for row in authority["states"]} == {
        "table::Table<address, u64>",
        "u64",
    }
    assert worklist["status"] == "READY"


def test_exact_typed_producer_trace_is_delivered_but_cannot_self_certify_application(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        [
            {
                "qualified_name": "Ledger.total",
                "declaration_locus": "src/Ledger.sol:L7",
                "write_sites": ["src/Ledger.sol:L20"],
            },
            {
                "qualified_name": "Ledger.rate",
                "declaration_locus": "src/Ledger.sol:L8",
                "write_sites": ["src/Ledger.sol:L21"],
            },
        ],
    )
    A.write_semantic_invariant_authority(tmp_path)
    worklist = _read(tmp_path, A.WORKLIST_FILE)
    rows = [
        _delivered(row["state_id"], row["declaration_locus"])
        for row in worklist["states"]
    ]
    trace = _application(worklist, rows)
    semantic_text = (
        "# Semantic Invariants\n\n"
        + A.TRACE_BEGIN
        + "\n"
        + json.dumps(trace, sort_keys=True)
        + "\n"
        + A.TRACE_END
        + "\n"
    )
    (tmp_path / "semantic_invariants.md").write_text(semantic_text, encoding="utf-8")

    receipt = A.reconcile_semantic_invariant_application(tmp_path)

    assert receipt["status"] == "DELIVERED"
    assert receipt["delivered_count"] == 2
    assert receipt["applied_count"] == 0
    assert receipt["open_count"] == 2
    assert all(row["status"] == "DELIVERED" for row in receipt["states"])
    assert "No open semantic-invariant application debt" not in (
        tmp_path / A.GAPS_PROJECTION_FILE
    ).read_text(encoding="utf-8")


def test_independent_bound_consumer_receipt_can_close_delivered_rows_as_applied(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        [
            {
                "qualified_name": "Ledger.total",
                "declaration_locus": "src/Ledger.sol:L7",
                "write_sites": ["src/Ledger.sol:L20"],
            }
        ],
    )
    A.write_semantic_invariant_authority(tmp_path)
    worklist = _read(tmp_path, A.WORKLIST_FILE)
    state = worklist["states"][0]
    producer_row = _delivered(state["state_id"], state["declaration_locus"])
    producer = _application(worklist, [producer_row])
    independent = _independent(
        worklist,
        producer,
        [
            _independently_applied(
                state["state_id"], state["declaration_locus"], producer_row
            )
        ],
    )

    receipt = A.reconcile_semantic_invariant_application(
        tmp_path,
        application_payload=producer,
        independent_payload=independent,
    )

    assert receipt["status"] == "APPLIED"
    assert receipt["applied_count"] == 1
    assert receipt["delivered_count"] == 0
    assert receipt["open_count"] == 0
    assert receipt["states"][0]["independent_consumer"] == "APPLICATION_SKEPTIC"
    assert "No open semantic-invariant application debt" in (
        tmp_path / A.GAPS_PROJECTION_FILE
    ).read_text(encoding="utf-8")


def test_producer_operator_cannot_self_certify_as_independent_consumer(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        [
            {
                "qualified_name": "Ledger.total",
                "declaration_locus": "src/Ledger.sol:L7",
                "write_sites": ["src/Ledger.sol:L20"],
            }
        ],
    )
    A.write_semantic_invariant_authority(tmp_path)
    worklist = _read(tmp_path, A.WORKLIST_FILE)
    state = worklist["states"][0]
    producer_row = _delivered(state["state_id"], state["declaration_locus"])
    producer = _application(worklist, [producer_row])
    independent = _independent(
        worklist,
        producer,
        [
            _independently_applied(
                state["state_id"], state["declaration_locus"], producer_row
            )
        ],
    )
    independent["consumer_operator_digest"] = producer["producer_operator_digest"]
    independent["payload_digest"] = A.payload_digest(independent)

    receipt = A.reconcile_semantic_invariant_application(
        tmp_path,
        application_payload=producer,
        independent_payload=independent,
    )

    assert receipt["status"] == "UNMEASURABLE"
    assert receipt["states"][0]["status"] == "DELIVERED"
    assert receipt["applied_count"] == 0
    assert any("distinct" in issue for issue in receipt["issues"])


def test_deferred_row_stays_open_and_never_becomes_covered(tmp_path: Path) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        [
            {
                "qualified_name": "Ledger.total",
                "declaration_locus": "src/Ledger.sol:L7",
                "write_sites": ["src/Ledger.sol:L20"],
            },
            {
                "qualified_name": "Ledger.pending",
                "declaration_locus": "src/Ledger.sol:L8",
                "write_sites": ["src/Ledger.sol:L21"],
            },
        ],
    )
    A.write_semantic_invariant_authority(tmp_path)
    worklist = _read(tmp_path, A.WORKLIST_FILE)
    first, second = worklist["states"]
    trace = _application(
        worklist,
        [
            _delivered(first["state_id"], first["declaration_locus"]),
            {
                "state_id": second["state_id"],
                "disposition": "DEFERRED",
                "evidence_loci": [],
                "write_site_status": "BOUNDED",
                "semantic_status": "SEMANTICS_UNKNOWN",
                "result": "Bounded pass exhausted; depth must inspect this exact state.",
            },
        ],
    )

    receipt = A.reconcile_semantic_invariant_application(
        tmp_path, application_payload=trace
    )

    assert receipt["status"] == "DEFERRED"
    assert receipt["deferred_count"] == 1
    assert receipt["delivered_count"] == 1
    assert receipt["open_count"] == 2
    deferred = next(row for row in receipt["states"] if row["status"] == "DEFERRED")
    assert deferred["state_id"] == second["state_id"]
    gaps = (tmp_path / A.GAPS_PROJECTION_FILE).read_text(encoding="utf-8")
    assert second["state_id"] in gaps
    assert "No open semantic-invariant application debt" not in gaps


def test_source_conflict_remains_open_even_when_model_claims_application(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        [
            {
                "qualified_name": "Ledger.pending",
                "declaration_locus": "src/Ledger.sol:L7",
                "write_sites": ["src/Ledger.sol:L20"],
            }
        ],
    )
    (tmp_path / "state_write_map.md").write_text(
        "## Ledger\n\n| State Variable | Writers |\n|---|---|\n"
        "| pending | src/Ledger.sol:L30 |\n",
        encoding="utf-8",
    )
    A.write_semantic_invariant_authority(tmp_path)
    worklist = _read(tmp_path, A.WORKLIST_FILE)
    row = worklist["states"][0]
    trace = _application(
        worklist, [_delivered(row["state_id"], row["declaration_locus"])]
    )

    receipt = A.reconcile_semantic_invariant_application(
        tmp_path, application_payload=trace
    )

    assert receipt["status"] == "CONFLICT"
    assert receipt["conflict_count"] == 1
    assert receipt["open_count"] == 1
    assert receipt["states"][0]["status"] == "CONFLICT"
    assert receipt["states"][0]["conflict_ids"]


def test_missing_or_digest_mismatched_trace_is_unmeasurable(tmp_path: Path) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        [{"qualified_name": "Ledger.total", "write_sites": ["src/Ledger.sol:L20"]}],
    )
    A.write_semantic_invariant_authority(tmp_path)

    missing = A.reconcile_semantic_invariant_application(tmp_path)
    assert missing["status"] == "UNMEASURABLE"
    assert missing["unmeasurable_count"] == 1

    worklist = _read(tmp_path, A.WORKLIST_FILE)
    trace = _application(
        worklist,
        [_delivered(worklist["states"][0]["state_id"], "src/Ledger.sol:L20")],
    )
    trace["authority_digest"] = "0" * 64
    trace["payload_digest"] = A.payload_digest(trace)
    mismatched = A.reconcile_semantic_invariant_application(
        tmp_path, application_payload=trace
    )
    assert mismatched["status"] == "UNMEASURABLE"
    assert any("authority digest mismatch" in issue for issue in mismatched["issues"])


def test_pre_and_post_writes_are_byte_and_mtime_idempotent(tmp_path: Path) -> None:
    _checkpoint(tmp_path, ecosystem="aptos")
    _graph(
        tmp_path,
        [
            {
                "qualified_name": "0x1::vault::Vault.total",
                "declaration_locus": "sources/vault.move:L10",
                "write_sites": ["sources/vault.move:L30"],
            }
        ],
    )
    A.write_semantic_invariant_authority(tmp_path)
    pre_paths = [
        tmp_path / A.AUTHORITY_FILE,
        tmp_path / A.WORKLIST_FILE,
        tmp_path / A.WORKLIST_PROJECTION_FILE,
    ]
    pre_state = [(path.read_bytes(), path.stat().st_mtime_ns) for path in pre_paths]
    A.write_semantic_invariant_authority(tmp_path)
    assert pre_state == [(path.read_bytes(), path.stat().st_mtime_ns) for path in pre_paths]

    worklist = _read(tmp_path, A.WORKLIST_FILE)
    trace = _application(
        worklist,
        [_delivered(worklist["states"][0]["state_id"], "sources/vault.move:L30")],
    )
    A.reconcile_semantic_invariant_application(tmp_path, application_payload=trace)
    post_paths = [tmp_path / A.APPLICATION_RECEIPT_FILE, tmp_path / A.GAPS_PROJECTION_FILE]
    post_state = [(path.read_bytes(), path.stat().st_mtime_ns) for path in post_paths]
    A.reconcile_semantic_invariant_application(tmp_path, application_payload=trace)
    assert post_state == [(path.read_bytes(), path.stat().st_mtime_ns) for path in post_paths]


def test_input_drift_makes_a_previously_bound_worklist_unmeasurable(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    rows = [
        {
            "qualified_name": "Ledger.total",
            "declaration_locus": "src/Ledger.sol:L7",
            "write_sites": ["src/Ledger.sol:L20"],
        }
    ]
    _graph(tmp_path, rows)
    A.write_semantic_invariant_authority(tmp_path)
    worklist = _read(tmp_path, A.WORKLIST_FILE)
    trace = _application(
        worklist,
        [_delivered(worklist["states"][0]["state_id"], "src/Ledger.sol:L20")],
    )
    rows[0]["write_sites"] = ["src/Ledger.sol:L21"]
    _graph(tmp_path, rows)

    receipt = A.reconcile_semantic_invariant_application(
        tmp_path, application_payload=trace
    )

    assert receipt["status"] == "UNMEASURABLE"
    assert any("current inputs" in issue for issue in receipt["issues"])


def test_unsupported_graph_cannot_be_cleaned_by_legacy_fallback_and_projection_is_exact(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    (tmp_path / "_mechanical_graph.json").write_text(
        json.dumps(
            {
                "schema_version": "plamen.mechanical_graph.v0",
                "source": "unsupported-fixture",
                "state_symbols": [],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "state_variables.md").write_text(
        "# State Variables\n\n"
        "| File | State Variable | Line |\n"
        "|---|---|---|\n"
        "| src/Ledger.sol | total | 7 |\n",
        encoding="utf-8",
    )

    authority = A.write_semantic_invariant_authority(tmp_path)

    assert authority["status"] == "UNMEASURABLE"
    assert authority["graph_substrate_healthy"] is False
    assert authority["state_count"] == 1
    assert A.validate_semantic_invariant_authority(tmp_path) == []
    projection = tmp_path / A.WORKLIST_PROJECTION_FILE
    projection.write_text(
        projection.read_text(encoding="utf-8") + "tampered\n", encoding="utf-8"
    )
    assert any(
        A.WORKLIST_PROJECTION_FILE in issue
        for issue in A.validate_semantic_invariant_authority(tmp_path)
    )


def test_legacy_only_symbol_in_healthy_graph_is_explicit_open_conflict(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        [
            {
                "qualified_name": "Ledger.total",
                "declaration_locus": "src/Ledger.sol:L7",
                "write_sites": ["src/Ledger.sol:L20"],
            }
        ],
    )
    (tmp_path / "state_write_map.md").write_text(
        "## LegacyOnly\n\n"
        "| State Variable | Writers |\n"
        "|---|---|\n"
        "| pending | src/LegacyOnly.sol:L30 |\n",
        encoding="utf-8",
    )

    authority, worklist, _projection = A.derive_semantic_invariant_authority(
        tmp_path
    )

    legacy = next(
        row for row in authority["states"]
        if row["qualified_name"] == "LegacyOnly.pending"
    )
    assert authority["status"] == "CONFLICT"
    assert any(
        row["kind"] == "LEGACY_ONLY_SYMBOL" and row["state_id"] == legacy["state_id"]
        for row in authority["conflicts"]
    )
    work = next(row for row in worklist["states"] if row["state_id"] == legacy["state_id"])
    assert work["conflict_ids"]


def test_arbitrary_nonempty_producer_evidence_is_not_bound_and_cannot_be_delivered(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(
        tmp_path,
        [
            {
                "qualified_name": "Ledger.total",
                "declaration_locus": "src/Ledger.sol:L7",
                "write_sites": ["src/Ledger.sol:L20"],
            }
        ],
    )
    A.write_semantic_invariant_authority(tmp_path)
    worklist = _read(tmp_path, A.WORKLIST_FILE)
    state = worklist["states"][0]
    producer_row = _delivered(state["state_id"], "analysis complete")
    producer = _application(worklist, [producer_row])

    receipt = A.reconcile_semantic_invariant_application(
        tmp_path, application_payload=producer
    )

    assert receipt["status"] == "UNMEASURABLE"
    assert receipt["delivered_count"] == 0
    assert receipt["states"][0]["status"] == "UNMEASURABLE"
    assert any(
        "bound state/source denominator" in issue
        for issue in receipt["states"][0]["issues"]
    )
