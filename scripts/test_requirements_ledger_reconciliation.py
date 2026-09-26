"""Fail-closed tests for the continuation requirements reconciliation."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import requirements_ledger_reconciliation as R


REPO = Path(__file__).resolve().parents[1]


def _write_json(path: Path, value: object) -> None:
    path.write_text(R._canonical(value) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, values: list[dict[str, object]]) -> None:
    path.write_text(R.render_jsonl(values), encoding="utf-8")


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path, list[dict[str, object]]]:
    continuation = tmp_path / "docs" / "continuation"
    continuation.mkdir(parents=True)
    ledger = continuation / "REQUIREMENTS.jsonl"
    evidence = continuation / "EVIDENCE_INDEX.json"
    reconciliation = continuation / "REQUIREMENTS_RECONCILIATION.jsonl"
    ledger.write_bytes((REPO / R.DEFAULT_LEDGER).read_bytes())
    evidence.write_bytes((REPO / R.DEFAULT_EVIDENCE_INDEX).read_bytes())
    documents = R.build_seed_documents(tmp_path, ledger, evidence)
    _write_jsonl(reconciliation, documents)
    return tmp_path, ledger, reconciliation, evidence, documents


def _validate(paths: tuple[Path, Path, Path, Path, object]) -> dict[str, object]:
    root, ledger, reconciliation, evidence, _documents = paths
    return R.validate_reconciliation(root, ledger, reconciliation, evidence)


def _ledger_record(documents: list[dict[str, object]], suffix: str) -> dict[str, object]:
    return next(
        item
        for item in documents
        if item.get("record_type") == "ledger_reconciliation"
        and str(item["ledger_key"]).endswith(suffix)
    )


def _child(documents: list[dict[str, object]], child_id: str = "S-1") -> dict[str, object]:
    return next(
        item
        for item in documents
        if item.get("record_type") == "child_proof" and item["child_id"] == child_id
    )


def _add_evidence(evidence: Path, classification: str | None = "PASS") -> str:
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    identifier = "EV-RECONCILIATION-FOCUSED"
    record: dict[str, object] = {
        "id": identifier,
        "kind": "test_observation",
        "result": "fixture result text is not classification authority",
    }
    if classification is not None:
        record["proof_classification"] = classification
    payload["records"].append(record)
    _write_json(evidence, payload)
    return identifier


def _make_mapped(
    root: Path,
    ledger: Path,
    evidence: Path,
    record: dict[str, object],
    *,
    classification: str = "PASS",
    derived_status: str = "PROVEN",
    receipt_id: str = "RECEIPT-FOCUSED-1",
) -> dict[str, object]:
    scripts = root / "scripts"
    scripts.mkdir(exist_ok=True)
    source = scripts / "fixture_impl.py"
    test_source = scripts / "test_fixture_impl.py"
    source.write_text("def implemented_symbol():\n    return True\n", encoding="utf-8")
    test_source.write_text(
        "def test_implemented_symbol():\n    assert True\n", encoding="utf-8"
    )
    package = root / "fixture-package.whl"
    package.write_bytes(b"synthetic-package-witness\n")
    source_hash = R._sha_bytes(source.read_bytes())
    test_hash = R._sha_bytes(test_source.read_bytes())
    package_hash = R._sha_bytes(package.read_bytes())
    implementation = {
        "path": "scripts/fixture_impl.py",
        "sha256": source_hash,
        "symbol": "implemented_symbol",
    }
    test = {
        "nodeid": "scripts/test_fixture_impl.py::test_implemented_symbol",
        "sha256": test_hash,
    }
    files = [
        {"path": "scripts/fixture_impl.py", "sha256": source_hash},
        {"path": "scripts/test_fixture_impl.py", "sha256": test_hash},
        {"path": "fixture-package.whl", "sha256": package_hash},
    ]
    evidence_id = _add_evidence(evidence, classification)
    subject_key = str(record.get("ledger_key") or record.get("proof_key"))
    receipt = {
        "id": receipt_id,
        "subject_key": subject_key,
        "evidence_ref": f"docs/continuation/EVIDENCE_INDEX.json#{evidence_id}",
        "classification": classification,
        "proven_facets": list(R.FACETS),
        "source_witnesses": [implementation],
        "worktree_witness": {
            "files": files,
            "manifest_sha256": R._digest(files),
        },
        "argv": ["python3.12", "-m", "pytest", "-q", test["nodeid"]],
        "runtime": {"python_version": "3.12.11", "platform": "fixture-posix"},
        "backend": {"name": "fixture-backend", "model": "fixture-model"},
        "exit_code": 0,
        "collected_nodeids": [test["nodeid"]],
        "artifact_hashes": [],
        "package_hashes": [
            {"path": "fixture-package.whl", "sha256": package_hash}
        ],
        "scope": "One exact implementation symbol and focused node.",
        "limits": ["Synthetic focused fixture; no full-suite or E2E inference."],
        "snapshot_binding": {
            "ledger_sha256": R._sha_bytes(ledger.read_bytes()),
            "worktree_manifest_sha256": R._digest(files),
        },
    }
    record["mapping_state"] = "MAPPED"
    record["disposition"] = "CLOSED"
    record["derived_status"] = derived_status
    record["implementation_witnesses"] = [implementation]
    record["test_witnesses"] = [test]
    record["receipts"] = [receipt]
    record["facets"] = {
        name: {"applicability": "REQUIRED", "receipt_ids": [receipt_id]}
        for name in R.FACETS
    }
    return receipt


def test_seed_is_exact_open_bijection_with_current_row_hashes(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)

    summary = _validate(paths)

    assert summary == {
        "schema": R.SCHEMA,
        "ledger_sha256": "9100882ed513e45f18665f9d3c271f569b0b880c77b815cc356e91fceae725ea",
        "active_required_count": 131,
        "child_proof_count": 64,
        "aggregate_count": 6,
        "open_count": 195,
        "proven_count": 0,
        "completion_claim": False,
    }
    records = [item for item in paths[4] if item["record_type"] != "reconciliation_metadata"]
    assert all(item["mapping_state"] == "UNMAPPED" for item in records)
    assert all(item["derived_status"] == "OPEN" for item in records)
    assert len({_child(paths[4], f"S-{number}")["proof_key"] for number in range(1, 13)}) == 12


def test_row_line_hash_is_not_replaceable_by_a_file_level_claim(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    record = _ledger_record(paths[4], ":P0-0")
    record["ledger_line_sha256"] = "0" * 64
    _write_jsonl(paths[2], paths[4])

    with pytest.raises(R.ReconciliationError, match="row-line hash mismatch"):
        _validate(paths)


@pytest.mark.parametrize("case", ["duplicate", "unknown", "missing"])
def test_active_row_bijection_rejects_duplicate_unknown_or_missing(
    tmp_path: Path, case: str
) -> None:
    paths = _fixture(tmp_path)
    record = _ledger_record(paths[4], ":P0-0")
    if case == "duplicate":
        paths[4].append(copy.deepcopy(record))
    elif case == "unknown":
        record["ledger_key"] = "requirement:HISTORICAL_ACCEPTANCE:UNKNOWN"
    else:
        paths[4].remove(record)
    _write_jsonl(paths[2], paths[4])

    with pytest.raises(R.ReconciliationError, match="duplicate ledger key|unknown ledger key|bijection failed"):
        _validate(paths)


@pytest.mark.parametrize(
    "aggregate_suffix",
    ["namespace:HISTORICAL_ACCEPTANCE", ":AUG-AUDIT-001"],
)
def test_namespace_or_requirement_set_receipt_cannot_prove_child_facets(
    tmp_path: Path, aggregate_suffix: str
) -> None:
    paths = _fixture(tmp_path)
    aggregate = _ledger_record(paths[4], aggregate_suffix)
    _make_mapped(
        paths[0], paths[1], paths[3], aggregate,
        derived_status="OPEN", receipt_id="AGGREGATE-ONLY",
    )
    child = _child(paths[4])
    child["mapping_state"] = "MAPPED"
    child["disposition"] = "CLOSED"
    child["implementation_witnesses"] = copy.deepcopy(aggregate["implementation_witnesses"])
    child["test_witnesses"] = copy.deepcopy(aggregate["test_witnesses"])
    child["facets"] = {
        name: {"applicability": "REQUIRED", "receipt_ids": ["AGGREGATE-ONLY"]}
        for name in R.FACETS
    }
    # The receipt exists globally but not under the exact child subject.
    child["receipts"] = []
    _write_jsonl(paths[2], paths[4])

    with pytest.raises(R.ReconciliationError, match="facet/receipt bijection failed"):
        _validate(paths)


def test_receipt_subject_binding_rejects_aggregate_receipt_copied_to_child(
    tmp_path: Path,
) -> None:
    paths = _fixture(tmp_path)
    aggregate = _ledger_record(paths[4], ":AUG-AUDIT-001")
    receipt = _make_mapped(paths[0], paths[1], paths[3], aggregate, derived_status="OPEN")
    child = _child(paths[4])
    child.update(
        mapping_state="MAPPED",
        disposition="CLOSED",
        implementation_witnesses=copy.deepcopy(aggregate["implementation_witnesses"]),
        test_witnesses=copy.deepcopy(aggregate["test_witnesses"]),
        receipts=[copy.deepcopy(receipt)],
        facets=copy.deepcopy(aggregate["facets"]),
    )
    _write_jsonl(paths[2], paths[4])

    with pytest.raises(R.ReconciliationError, match="cannot prove"):
        _validate(paths)


def test_ordering_edges_are_graph_constraints_only(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    ordering = _ledger_record(paths[4], "ordering_edges:AUGUST_RESEARCH_REVIEW")
    assert all(
        item["applicability"] == "NOT_APPLICABLE_WITH_POLICY"
        for item in ordering["facets"].values()
    )
    ordering["graph_constraints"] = []
    _write_jsonl(paths[2], paths[4])

    with pytest.raises(R.ReconciliationError, match="graph constraints mismatch"):
        _validate(paths)


def test_unresolved_evidence_fragment_is_rejected(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    record = _ledger_record(paths[4], ":P0-0")
    receipt = _make_mapped(paths[0], paths[1], paths[3], record)
    receipt["evidence_ref"] = "docs/continuation/EVIDENCE_INDEX.json#DOES-NOT-EXIST"
    _write_jsonl(paths[2], paths[4])

    with pytest.raises(R.ReconciliationError, match="unresolved evidence fragment"):
        _validate(paths)


@pytest.mark.parametrize("classification", ["PENDING", "FAILURE", "DEFICIT"])
def test_nonpass_evidence_cannot_promote_a_requirement(
    tmp_path: Path, classification: str
) -> None:
    paths = _fixture(tmp_path)
    record = _ledger_record(paths[4], ":P0-0")
    _make_mapped(paths[0], paths[1], paths[3], record, classification=classification)
    _write_jsonl(paths[2], paths[4])

    with pytest.raises(R.ReconciliationError, match="derived_status must be OPEN"):
        _validate(paths)


@pytest.mark.parametrize(
    ("target", "replacement", "message"),
    [
        ("implementation", "missing_symbol", "source symbol does not resolve"),
        ("test", "scripts/test_fixture_impl.py::test_missing", "test node does not resolve"),
    ],
)
def test_implementation_symbol_and_test_node_must_resolve(
    tmp_path: Path, target: str, replacement: str, message: str
) -> None:
    paths = _fixture(tmp_path)
    record = _ledger_record(paths[4], ":P0-0")
    _make_mapped(paths[0], paths[1], paths[3], record)
    if target == "implementation":
        record["implementation_witnesses"][0]["symbol"] = replacement
    else:
        record["test_witnesses"][0]["nodeid"] = replacement
    _write_jsonl(paths[2], paths[4])

    with pytest.raises(R.ReconciliationError, match=message):
        _validate(paths)


def test_witness_blob_hash_drift_is_rejected(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    record = _ledger_record(paths[4], ":P0-0")
    _make_mapped(paths[0], paths[1], paths[3], record)
    _write_jsonl(paths[2], paths[4])
    (paths[0] / "scripts" / "fixture_impl.py").write_text(
        "def implemented_symbol():\n    return False\n", encoding="utf-8"
    )

    with pytest.raises(R.ReconciliationError, match="witness blob hash drift"):
        _validate(paths)


def test_receipt_must_bind_the_current_ledger_snapshot(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    record = _ledger_record(paths[4], ":P0-0")
    receipt = _make_mapped(paths[0], paths[1], paths[3], record)
    receipt["snapshot_binding"]["ledger_sha256"] = "0" * 64
    _write_jsonl(paths[2], paths[4])

    with pytest.raises(R.ReconciliationError, match="current ledger snapshot mismatch"):
        _validate(paths)


@pytest.mark.parametrize("case", ["omitted", "implicit"])
def test_every_facet_requires_explicit_applicability(tmp_path: Path, case: str) -> None:
    paths = _fixture(tmp_path)
    record = _ledger_record(paths[4], ":P0-0")
    if case == "omitted":
        del record["facets"]["platform"]
    else:
        record["facets"]["platform"] = {"receipt_ids": []}
    _write_jsonl(paths[2], paths[4])

    with pytest.raises(R.ReconciliationError, match="every facet must be explicit|invalid applicability"):
        _validate(paths)


def test_suite_total_filename_and_result_prose_are_not_classification(
    tmp_path: Path,
) -> None:
    paths = _fixture(tmp_path)
    record = _ledger_record(paths[4], ":P0-0")
    receipt = _make_mapped(paths[0], paths[1], paths[3], record)
    index = json.loads(paths[3].read_text(encoding="utf-8"))
    indexed = next(item for item in index["records"] if item["id"] == "EV-RECONCILIATION-FOCUSED")
    indexed.pop("proof_classification")
    indexed["id"] = "EV-999-PASSED-SUITE"
    indexed["result"] = "999 passed, exit 0"
    receipt["evidence_ref"] = (
        "docs/continuation/EVIDENCE_INDEX.json#EV-999-PASSED-SUITE"
    )
    _write_json(paths[3], index)
    _write_jsonl(paths[2], paths[4])

    with pytest.raises(R.ReconciliationError, match="explicit evidence-index classification UNCLASSIFIED"):
        _validate(paths)


def test_structured_pass_receipt_can_only_promote_its_exact_leaf(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    record = _ledger_record(paths[4], ":P0-0")
    _make_mapped(paths[0], paths[1], paths[3], record)
    _write_jsonl(paths[2], paths[4])

    summary = _validate(paths)

    assert summary["proven_count"] == 1
    assert summary["open_count"] == 194
    assert summary["completion_claim"] is False
