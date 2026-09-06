"""Regression fixtures for JSON ``bool``-as-``int`` authority confusion.

Python intentionally makes ``bool`` a subclass of ``int`` and also considers
``True == 1``.  Persisted control-plane artifacts must use the JSON scalar type
declared by their schema, even when an attacker coherently recomputes every
content digest after changing an integer to a boolean.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

import axis_disposition as A
import coverage_shortfalls as C
import enumeration_gate as E
import mandatory_reverification as M
import report_evidence_authority as R
import security_obligation_lifecycle as L
from test_security_obligation_lifecycle_p1_c import (
    _setup as setup_security_lifecycle,
    _write_mandatory_chain,
)
from test_report_evidence_runtime_p1_k import _write_inputs as write_report_inputs
from test_axis_disposition_p0_i import (
    _compile as compile_axis_v1,
    _coverage as axis_v1_coverage,
    _gap as axis_v1_gap,
    _reconcile as reconcile_axis_v1,
    _seed_project as seed_axis_v1,
    _write_matrix as write_axis_v1_matrix,
)
from test_axis_assurance_projection_p0_i import (
    RUN_ID as AXIS_V2_RUN_ID,
    _persist_v2_authority,
    _seed_project as seed_axis_v2,
)
from test_markdown_heading_section_boundaries_r8 import (
    _prepare_direct_enumgap_promotion,
)


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _redigest_assignment(assignment: dict[str, object]) -> None:
    for binding in assignment["assignments"]:  # type: ignore[index]
        unsigned = {
            key: value
            for key, value in binding.items()  # type: ignore[union-attr]
            if key != "assignment_binding_digest"
        }
        binding["assignment_binding_digest"] = M._digest(unsigned)  # type: ignore[index]
    unsigned_receipt = {
        key: value
        for key, value in assignment.items()
        if key != "assignment_receipt_digest"
    }
    assignment["assignment_receipt_digest"] = M._digest(unsigned_receipt)


def _redigest(value: dict[str, object], digest_key: str, digest) -> None:
    value[digest_key] = digest(
        {key: item for key, item in value.items() if key != digest_key}
    )


def _mandatory_artifacts(
    tmp_path: Path,
) -> tuple[Path, dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
    root, aliases = setup_security_lifecycle(tmp_path, count=1)
    _write_mandatory_chain(root, aliases, verdict="CONFIRMED")
    denominator = json.loads(
        (root / M.DENOMINATOR_FILE).read_text(encoding="utf-8")
    )
    routing = json.loads(
        (root / M.ROUTING_FILE).read_text(encoding="utf-8")
    )
    completion = json.loads(
        (root / M.COMPLETION_FILE).read_text(encoding="utf-8")
    )
    candidate_id = denominator["candidates"][0]["candidate_id"]
    delivery = M.reconcile_mandatory_reverification_delivery(
        denominator=denominator,
        completion=completion,
        report_routes={
            candidate_id: {
                "report_delivery_state": "DELIVERED_BODY",
                "public_report_ids": ["H-01"],
            }
        },
    )
    return root, denominator, routing, completion, delivery


def _report_repair_receipt(*, attempt: object) -> dict[str, object]:
    receipt: dict[str, object] = {
        "schema_version": R.REPORT_EVIDENCE_REPAIR_RECEIPT_SCHEMA,
        "request_digest": "1" * 64,
        "response_digest": "2" * 64,
        "baseline_bundle_digest": "3" * 64,
        "repaired_bundle_digest": "4" * 64,
        "repair_attempts": {"H-01": attempt},
        "receipt_digest": "",
    }
    receipt["receipt_digest"] = R._digest({**receipt, "receipt_digest": ""})
    return receipt


def _hot_cap_payload(items: list[dict[str, object]]) -> dict[str, object]:
    identities = [f"{item['function']}@{item['loc']}" for item in items]
    unsigned: dict[str, object] = {
        "schema_version": A.HOT_CAP_SCHEMA,
        "producer": "enumeration.hot_function_set",
        "source_scope": "production-source",
        "limit": len(items),
        "observed_count": len(items),
        "retained_count": len(items),
        "omitted_count": 0,
        "population_tail": identities[-1] if identities else "",
        "retained_tail": identities[-1] if identities else "",
        "omitted_tail": "",
        "retained_identities": identities,
        "omitted_identities": [],
        "observed_items": items,
        "retained_items": items,
        "omitted_items": [],
        "omitted_identities_sha256": A._ascii_digest([]),
        "population_sha256": A._ascii_digest(identities),
        "raw_fallback_authority": "CANDIDATE_ONLY",
        "methodology_application_proven": False,
    }
    return {**unsigned, "receipt_sha256": A._ascii_digest(unsigned)}


def _axis_v1_authorities(
    tmp_path: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    project, scratchpad = seed_axis_v1(tmp_path)
    write_axis_v1_matrix(
        scratchpad,
        [
            axis_v1_gap(
                "settle",
                "contracts/Unit.sol:L2",
                "boundary",
                lang="solidity",
            )
        ],
    )
    worklist = compile_axis_v1(scratchpad)
    receipt = reconcile_axis_v1(
        scratchpad,
        project,
        worklist,
        axis_v1_coverage([]),
    )
    assert len(worklist["items"]) == 1
    assert len(receipt["repair_work"]["items"]) == 1
    assert len(receipt["assurance_debt"]["items"]) == 1
    return worklist, receipt


def test_redigested_boolean_mandatory_counts_cannot_advance_lifecycle(
    tmp_path: Path,
) -> None:
    root, aliases = setup_security_lifecycle(tmp_path, count=1)
    _write_mandatory_chain(
        root,
        aliases,
        verdict="CONFIRMED",
        include_completion=False,
    )
    denominator = json.loads(
        (root / M.DENOMINATOR_FILE).read_text(encoding="utf-8")
    )
    assignment_path = root / M.ASSIGNMENT_FILE
    assignment = json.loads(assignment_path.read_text(encoding="utf-8"))

    # Both cardinalities still compare equal to integer 1 under Python's normal
    # equality rules.  Recompute both digests so only exact JSON typing can
    # distinguish this artifact from an authentic singleton assignment.
    assignment["assignment_count"] = True
    assignment["assignments"][0]["assignment_count"] = True
    _redigest_assignment(assignment)
    _write_json(assignment_path, assignment)

    with pytest.raises(
        M.MandatoryReverificationError,
        match="assignment count|assigned once",
    ):
        M._validate_assignment(assignment, denominator)

    lifecycle = L.build_security_obligation_lifecycle(root)
    assert lifecycle["rows"][0]["state"] != L.VERIFY_PENDING
    assert "MANDATORY_ASSIGNMENT_INVALID" in lifecycle["rows"][0]["debt_reasons"]


def test_redigested_boolean_report_repair_attempt_is_rejected() -> None:
    request = {
        "schema_version": R.REPORT_EVIDENCE_REPAIR_REQUEST_SCHEMA,
        "bundle_digest": "a" * 64,
        "items": [
            {
                "report_id": "H-01",
                "record_digest": "b" * 64,
                "missing_fields": ["impact"],
                "attempt": True,
            }
        ],
        "request_digest": "",
    }
    request["request_digest"] = R._digest({**request, "request_digest": ""})

    with pytest.raises(
        R.ReportEvidenceError,
        match="repair request item is invalid",
    ):
        R.validate_report_evidence_repair_request(request)


@pytest.mark.parametrize(
    ("field", "boolean"),
    [
        ("route_count", True),
        ("debt_count", False),
        ("source_input_debt_count", False),
    ],
)
def test_redigested_boolean_mandatory_routing_counts_are_rejected(
    tmp_path: Path,
    field: str,
    boolean: bool,
) -> None:
    root, denominator, routing, _completion, _delivery = _mandatory_artifacts(
        tmp_path
    )
    routing[field] = boolean
    _redigest(routing, "routing_digest", M._digest)

    with pytest.raises(
        M.MandatoryReverificationError,
        match="mandatory routing counts are invalid",
    ):
        M._validate_routing(routing, denominator)

    _write_json(root / M.ROUTING_FILE, routing)
    lifecycle = L.build_security_obligation_lifecycle(root)
    assert lifecycle["rows"][0]["state"] != L.VERIFY_PENDING
    assert "MANDATORY_ROUTING_INVALID" in lifecycle["rows"][0]["debt_reasons"]


@pytest.mark.parametrize(
    ("field", "boolean"),
    [
        ("obligation_count", True),
        ("completed_obligation_count", True),
        ("source_input_debt_count", False),
    ],
)
def test_redigested_boolean_mandatory_completion_counts_are_rejected(
    tmp_path: Path,
    field: str,
    boolean: bool,
) -> None:
    root, denominator, _routing, completion, _delivery = _mandatory_artifacts(
        tmp_path
    )
    completion[field] = boolean
    _redigest(completion, "completion_receipt_digest", M._digest)

    with pytest.raises(
        M.MandatoryReverificationError,
        match="mandatory completion counts are invalid",
    ):
        M._validate_completion(completion, denominator)

    _write_json(root / M.COMPLETION_FILE, completion)
    lifecycle = L.build_security_obligation_lifecycle(root)
    assert lifecycle["rows"][0]["state"] not in {
        L.VERIFIED_CONFIRMED,
        L.VERIFIED_CONTESTED,
    }
    assert "MANDATORY_COMPLETION_INVALID" in lifecycle["rows"][0]["debt_reasons"]


@pytest.mark.parametrize(
    ("field", "boolean"),
    [
        ("row_count", True),
        ("source_input_debt_count", False),
    ],
)
def test_redigested_boolean_mandatory_delivery_counts_are_rejected(
    tmp_path: Path,
    field: str,
    boolean: bool,
) -> None:
    _root, denominator, _routing, _completion, delivery = _mandatory_artifacts(
        tmp_path
    )
    delivery[field] = boolean
    _redigest(delivery, "delivery_receipt_digest", M._digest)

    with pytest.raises(
        M.MandatoryReverificationError,
        match="mandatory delivery counts are invalid",
    ):
        M._validate_delivery(delivery, denominator)


def test_redigested_boolean_report_repair_receipt_attempt_is_rejected() -> None:
    receipt = _report_repair_receipt(attempt=True)

    with pytest.raises(
        R.ReportEvidenceError,
        match="report evidence repair attempts are invalid",
    ):
        R._validate_repair_receipt(receipt)


def test_final_quality_runtime_does_not_coerce_boolean_repair_attempt(
    tmp_path: Path,
) -> None:
    write_report_inputs(tmp_path, impact="", recommendation="")
    runtime = R.materialize_report_evidence_runtime(tmp_path)
    body = R.project_report_evidence_markdown(
        """### [H-01] Paired accounting state can diverge

**Severity**: High
**Verdict**: CONFIRMED
**Location**: src/Module.sol:L10-L30

**Description**:
One transition updates one accounting leg without its pair.
""",
        runtime["bundle"],
    )
    report_path = tmp_path / "AUDIT_REPORT.md"
    report_path.write_text(body, encoding="utf-8")
    _write_json(
        tmp_path / "report_evidence_repair_receipt.json",
        _report_repair_receipt(attempt=True),
    )

    receipt = R.finalize_report_evidence_delivery(
        tmp_path,
        report_path=report_path,
    )

    assert receipt["repair_attempts"] == {}


@pytest.mark.parametrize(
    ("items", "boolean"),
    [
        ([], False),
        ([{"function": "settle", "loc": "Unit.sol:L1"}], True),
    ],
)
def test_redigested_boolean_hot_cap_counts_are_rejected_by_both_consumers(
    tmp_path: Path,
    items: list[dict[str, object]],
    boolean: bool,
) -> None:
    payload = _hot_cap_payload(items)
    payload["observed_count"] = boolean
    payload["retained_count"] = boolean
    payload["omitted_count"] = False
    _redigest(payload, "receipt_sha256", A._ascii_digest)

    with pytest.raises(
        A.AxisDispositionError,
        match="hot-function cap receipt denominator mismatch",
    ):
        A._validate_cap_receipt(payload)

    _write_json(tmp_path / "_hot_function_cap_receipt.json", payload)
    accepted, issues = E._axis_cap_authority(
        tmp_path,
        items,
        current_run_stamp={
            "run_id": "run-bool-cap",
            "write_count": 1,
            "receipt_sha256": payload["receipt_sha256"],
        },
        run_id="run-bool-cap",
    )
    assert accepted is None
    assert issues == [
        "hot-function cap receipt does not bind the returned/full population"
    ]


@pytest.mark.parametrize(
    ("authority_name", "field", "boolean", "validator", "digest_key"),
    [
        ("worklist", "count", True, A._validate_worklist, "worklist_hash"),
        ("repair", "count", True, A._validate_repair, "queue_hash"),
        ("repair", "observed_count", True, A._validate_repair, "queue_hash"),
        ("repair", "omitted_count", False, A._validate_repair, "queue_hash"),
        ("assurance", "count", True, A._validate_assurance, "debt_hash"),
    ],
)
def test_redigested_boolean_axis_v1_nested_counts_are_rejected(
    tmp_path: Path,
    authority_name: str,
    field: str,
    boolean: bool,
    validator,
    digest_key: str,
) -> None:
    worklist, receipt = _axis_v1_authorities(tmp_path)
    sources = {
        "worklist": worklist,
        "repair": receipt["repair_work"],
        "assurance": receipt["assurance_debt"],
    }
    authority = copy.deepcopy(sources[authority_name])
    authority[field] = boolean
    _redigest(authority, digest_key, A._digest)

    with pytest.raises(A.AxisDispositionError, match="count|denominator"):
        validator(authority)


def test_redigested_boolean_axis_v1_receipt_denominator_is_rejected(
    tmp_path: Path,
) -> None:
    _worklist, receipt = _axis_v1_authorities(tmp_path)
    receipt = copy.deepcopy(receipt)
    receipt["denominator_count"] = True
    _redigest(receipt, "receipt_hash", A._digest)

    with pytest.raises(
        A.AxisDispositionError,
        match="axis receipt denominator count mismatch",
    ):
        A._validate_receipt(receipt)


@pytest.mark.parametrize("field", ["count", "gap_count"])
def test_redigested_boolean_axis_v2_worklist_counts_are_rejected(
    tmp_path: Path,
    field: str,
) -> None:
    project, scratchpad = seed_axis_v2(tmp_path)
    authority = _persist_v2_authority(
        project,
        scratchpad,
        gap_axes=("boundary",),
        repair_state="FAILED",
        promotion=False,
    )
    worklist = copy.deepcopy(authority["worklist"])
    worklist[field] = True
    _redigest(worklist, "worklist_hash", A._digest)

    with pytest.raises(
        A.AxisDispositionError,
        match="axis worklist v2 denominator mismatch",
    ):
        A._validate_axis_worklist_v2(worklist)


@pytest.mark.parametrize(
    ("field", "boolean"),
    [
        ("observed_count", True),
        ("retained_count", True),
        ("omitted_count", False),
    ],
)
def test_redigested_boolean_axis_v2_repair_plan_counts_are_rejected(
    tmp_path: Path,
    field: str,
    boolean: bool,
) -> None:
    project, scratchpad = seed_axis_v2(tmp_path)
    authority = _persist_v2_authority(
        project,
        scratchpad,
        gap_axes=("boundary",),
        repair_state="FAILED",
        promotion=False,
    )
    plan = copy.deepcopy(authority["plan"])
    plan[field] = boolean
    _redigest(plan, "plan_digest", A._digest)

    with pytest.raises(
        A.AxisDispositionError,
        match="axis repair plan denominator mismatch",
    ):
        A._validate_v2_repair_plan(
            plan,
            authority["worklist"],
            authority["initial"],
        )


def test_redigested_boolean_axis_execution_receipt_count_is_rejected() -> None:
    authority = A.build_axis_execution_evidence_authority(
        run_id=AXIS_V2_RUN_ID,
        receipt_bindings=(),
    )
    authority["receipt_count"] = False
    _redigest(authority, "authority_digest", A._digest)

    with pytest.raises(
        A.AxisDispositionError,
        match="axis execution-evidence authority run or denominator mismatch",
    ):
        A.validate_axis_execution_evidence_authority(
            authority,
            expected_run_id=AXIS_V2_RUN_ID,
        )


@pytest.mark.parametrize(
    ("population", "nested", "boolean"),
    [
        ("singleton", "assurance_debt", True),
        ("singleton", "repair_work", True),
        ("zero", "assurance_debt", False),
        ("zero", "repair_work", False),
    ],
)
def test_redigested_boolean_axis_application_nested_counts_are_rejected(
    tmp_path: Path,
    population: str,
    nested: str,
    boolean: bool,
) -> None:
    project, scratchpad = seed_axis_v2(tmp_path)
    kwargs = (
        {
            "gap_axes": ("boundary",),
            "repair_state": "FAILED",
            "promotion": False,
        }
        if population == "singleton"
        else {"promotion": False}
    )
    authority = _persist_v2_authority(project, scratchpad, **kwargs)
    receipt = copy.deepcopy(authority["final"])
    nested_authority = receipt[nested]
    nested_authority["count"] = boolean
    nested_digest = (
        "assurance_digest"
        if nested == "assurance_debt"
        else "repair_work_digest"
    )
    _redigest(nested_authority, nested_digest, A._digest)
    _redigest(receipt, "application_receipt_digest", A._digest)

    with pytest.raises(
        A.AxisDispositionError,
        match="axis application receipt debt inventory mismatch",
    ):
        A._validate_v2_application_receipt(receipt, authority["worklist"])


def test_boolean_axis_examined_row_count_is_explicit_debt(tmp_path: Path) -> None:
    authority: dict[str, object] = {
        "schema_version": E.AXIS_EXAMINED_AUTHORITY_SCHEMA,
        "run_id": "run-axis-examined",
        "row_count": False,
        "rows": [],
        "hint_artifacts_consumed": [],
        "authority_digest": "",
    }
    _redigest(authority, "authority_digest", E._axis_population_digest)

    identities, projection, issues = E._validated_axis_examined_authority(
        authority,
        scratchpad=tmp_path,
        run_id="run-axis-examined",
    )

    assert identities == set()
    assert projection["status"] == "ABSENT"
    assert issues == [
        "typed axis-examined authority run, denominator, or digest mismatch"
    ]


def test_boolean_phaseio_binding_size_is_visible_promotion_debt(
    tmp_path: Path,
) -> None:
    requirements = {
        "scratchpad:enumgap_exploration_findings.md": (
            "unit/enumgap_exploration/model",
            "enumgap_exploration_findings.md",
        ),
        "scratchpad:enumgap_disposition_receipt.json": (
            "unit/enumgap_disposition/reconcile",
            "enumgap_disposition_receipt.json",
        ),
    }
    bindings: dict[str, object] = {}
    units: dict[str, object] = {}
    for identity, (owner, relative) in requirements.items():
        raw = b""
        (tmp_path / relative).write_bytes(raw)
        bindings[identity] = {
            "owner_key": owner,
            "status": "ACTIVE",
            "run_id": "run-size",
            "contract_digest": "a" * 64,
            "size": False,
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        units[owner] = {
            "semantic_status": "ACTIVE",
            "execution_state": "OUTPUT_COMMITTED",
            "run_id": "run-size",
            "contract_digest": "a" * 64,
        }
    _write_json(
        tmp_path / "_artifact_state.json",
        {"artifact_bindings": bindings, "work_units": units},
    )

    issues = E._promotion_phaseio_issues(tmp_path)

    assert len(issues) == 2
    assert all("producer bytes drifted" in issue for issue in issues)


def _empty_enumgap_promotion(tmp_path: Path) -> None:
    source = tmp_path / "enumgap_exploration_findings.md"
    inventory = tmp_path / "findings_inventory.md"
    receipt_path = tmp_path / "enumgap_exploration_promotion_receipt.json"
    source.write_text("# Enumgap\n", encoding="utf-8")
    inventory.write_text("# Findings Inventory\n", encoding="utf-8")
    receipt: dict[str, object] = {
        "schema_version": E._ENUMGAP_PROMOTION_RECEIPT_SCHEMA,
        "source_artifact": "enumgap_exploration_findings.md",
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "delivery_count": False,
        "deliveries": [],
        "receipt_sha256": "",
    }
    receipt["receipt_sha256"] = E._promotion_receipt_digest(receipt)
    _write_json(receipt_path, receipt)
    _write_json(
        tmp_path / "enumgap_inventory_append_commit.json",
        {
            "schema_version": "plamen.enumgap_inventory_append_commit.v1",
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "inventory_sha256": hashlib.sha256(inventory.read_bytes()).hexdigest(),
            "promotion_receipt_sha256": hashlib.sha256(
                receipt_path.read_bytes()
            ).hexdigest(),
            "plan_sha256": "",
        },
    )


def test_redigested_boolean_enumgap_zero_delivery_count_is_rejected(
    tmp_path: Path,
) -> None:
    _empty_enumgap_promotion(tmp_path)

    with pytest.raises(
        ValueError,
        match="enumgap promotion delivery denominator mismatch",
    ):
        E.validated_enumgap_promotion_deliveries(tmp_path)


def test_redigested_boolean_enumgap_singleton_delivery_count_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare_direct_enumgap_promotion(
        tmp_path,
        monkeypatch,
        inventory="# Findings Inventory\n",
    )
    assert E.promote_enumgap_exploration_to_inventory(tmp_path) == {
        "parsed": 1,
        "emitted": 1,
    }
    receipt_path = tmp_path / "enumgap_exploration_promotion_receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["delivery_count"] = True
    receipt["receipt_sha256"] = E._promotion_receipt_digest(receipt)
    _write_json(receipt_path, receipt)
    commit_path = tmp_path / "enumgap_inventory_append_commit.json"
    commit = json.loads(commit_path.read_text(encoding="utf-8"))
    commit["promotion_receipt_sha256"] = hashlib.sha256(
        receipt_path.read_bytes()
    ).hexdigest()
    _write_json(commit_path, commit)

    with pytest.raises(
        ValueError,
        match="enumgap promotion delivery denominator mismatch",
    ):
        E.validated_enumgap_promotion_deliveries(tmp_path)


@pytest.mark.parametrize(
    ("field", "boolean"),
    [
        ("state_counts", True),
        ("terminal_negative_count", False),
    ],
)
def test_redigested_boolean_security_lifecycle_counts_are_rejected(
    tmp_path: Path,
    field: str,
    boolean: bool,
) -> None:
    root, aliases = setup_security_lifecycle(tmp_path, count=1)
    _write_mandatory_chain(
        root,
        aliases,
        verdict="CONFIRMED",
        include_completion=False,
    )
    authority = L.build_security_obligation_lifecycle(root)
    if field == "state_counts":
        authority["state_counts"][authority["rows"][0]["state"]] = boolean
    else:
        authority[field] = boolean
    _redigest(authority, "authority_digest", L._authority_digest)

    with pytest.raises(
        L.SecurityObligationLifecycleError,
        match="lifecycle (state counts|terminal-negative count) mismatch",
    ):
        L._validate_payload(authority)


@pytest.mark.parametrize(
    ("consumer", "expected_debt"),
    [
        (
            "axis_disposition",
            "coverage-shortfall ledger schema is invalid",
        ),
        (
            "enumeration_gate",
            "coverage-shortfall authority has an invalid schema",
        ),
    ],
)
def test_boolean_coverage_shortfall_schema_version_is_haltless_debt(
    tmp_path: Path,
    consumer: str,
    expected_debt: str,
) -> None:
    _write_json(
        tmp_path / "_coverage_shortfalls.json",
        {"schema_version": True, "shortfalls": []},
    )

    if consumer == "axis_disposition":
        debts = A._source_cap_records(tmp_path)[-1]
    else:
        debts = E._axis_coverage_shortfall_debt(tmp_path)

    assert expected_debt in debts


def _exact_coverage_shortfall_row() -> dict[str, object]:
    return C.shortfall(
        producer="enumeration.hot_function_set",
        scope="production-source",
        cap="hot-functions",
        limit=1,
        observed=1,
        retained=1,
        exact=True,
    )


@pytest.mark.parametrize("consumer", ["axis_disposition", "enumeration_gate"])
@pytest.mark.parametrize("field", ["limit", "observed", "retained"])
@pytest.mark.parametrize("boolean", [False, True])
def test_boolean_coverage_shortfall_row_integer_is_haltless_debt(
    tmp_path: Path,
    consumer: str,
    field: str,
    boolean: bool,
) -> None:
    row = _exact_coverage_shortfall_row()
    row[field] = boolean
    _write_json(
        tmp_path / "_coverage_shortfalls.json",
        {"schema_version": 1, "shortfalls": [row]},
    )

    if consumer == "axis_disposition":
        selected, *_rest, debts = A._source_cap_records(tmp_path)
        assert selected == []
        assert "coverage-shortfall ledger row is invalid" in debts
    else:
        debts = E._axis_coverage_shortfall_debt(tmp_path)
        assert (
            "enumeration.hot_function_set: coverage-shortfall row is invalid"
            in debts
        )


@pytest.mark.parametrize("consumer", ["axis_disposition", "enumeration_gate"])
@pytest.mark.parametrize(
    "invalid_semantics",
    [
        pytest.param([], id="empty-array"),
        pytest.param({}, id="empty-object"),
        pytest.param(["EXACT"], id="nonempty-array"),
        pytest.param({"value": "EXACT"}, id="nonempty-object"),
    ],
)
def test_coverage_shortfall_count_semantics_container_is_haltless_debt(
    tmp_path: Path,
    consumer: str,
    invalid_semantics: object,
) -> None:
    row = _exact_coverage_shortfall_row()
    row["count_semantics"] = invalid_semantics
    _write_json(
        tmp_path / "_coverage_shortfalls.json",
        {"schema_version": 1, "shortfalls": [row]},
    )

    if consumer == "axis_disposition":
        selected, *_rest, debts = A._source_cap_records(tmp_path)
        assert selected == []
        assert "coverage-shortfall ledger row is invalid" in debts
    else:
        debts = E._axis_coverage_shortfall_debt(tmp_path)
        assert (
            "enumeration.hot_function_set: coverage-shortfall row is invalid"
            in debts
        )


@pytest.mark.parametrize("consumer", ["axis_disposition", "enumeration_gate"])
def test_integer_coverage_shortfall_row_control_remains_valid(
    tmp_path: Path,
    consumer: str,
) -> None:
    row = _exact_coverage_shortfall_row()
    _write_json(
        tmp_path / "_coverage_shortfalls.json",
        {"schema_version": 1, "shortfalls": [row]},
    )

    if consumer == "axis_disposition":
        selected, *_rest, debts = A._source_cap_records(tmp_path)
        assert debts == []
        assert selected == [
            {
                "receipt_id": row["receipt_id"],
                "count_semantics": "EXACT",
                "observed": 1,
                "retained": 1,
                "omitted": 0,
                "human_projection_samples": [],
                "human_projection_is_authoritative": False,
            }
        ]
    else:
        assert E._axis_coverage_shortfall_debt(tmp_path) == []


@pytest.mark.parametrize("consumer", ["axis_disposition", "enumeration_gate"])
@pytest.mark.parametrize("semantics", ["EXACT", "LOWER_BOUND", "UNKNOWN"])
def test_coverage_shortfall_valid_semantics_controls_remain_typed(
    tmp_path: Path,
    consumer: str,
    semantics: str,
) -> None:
    if semantics == "UNKNOWN":
        row = C.unknown_shortfall(
            producer="enumeration.hot_function_set",
            scope="production-source",
            kind="POPULATION_UNAVAILABLE",
            detail="population coverage is unavailable",
        )
    else:
        row = C.shortfall(
            producer="enumeration.hot_function_set",
            scope="production-source",
            cap="hot-functions",
            limit=1,
            observed=1,
            retained=1,
            exact=semantics == "EXACT",
        )
    _write_json(
        tmp_path / "_coverage_shortfalls.json",
        {"schema_version": 1, "shortfalls": [row]},
    )

    if consumer == "axis_disposition":
        selected, *_rest, debts = A._source_cap_records(tmp_path)
        assert len(selected) == 1
        assert selected[0]["count_semantics"] == semantics
        assert "coverage-shortfall ledger row is invalid" not in debts
    else:
        debts = E._axis_coverage_shortfall_debt(tmp_path)
        assert not any("row is invalid" in debt for debt in debts)
        if semantics == "EXACT":
            assert debts == []
        else:
            assert debts


def test_integer_control_values_remain_valid(tmp_path: Path) -> None:
    request = {
        "schema_version": R.REPORT_EVIDENCE_REPAIR_REQUEST_SCHEMA,
        "bundle_digest": "a" * 64,
        "items": [
            {
                "report_id": "H-01",
                "record_digest": "b" * 64,
                "missing_fields": ["impact"],
                "attempt": 1,
            }
        ],
        "request_digest": "",
    }
    request["request_digest"] = R._digest({**request, "request_digest": ""})
    assert R.validate_report_evidence_repair_request(request) == request

    _write_json(
        tmp_path / "_coverage_shortfalls.json",
        {"schema_version": 1, "shortfalls": []},
    )
    assert A._source_cap_records(tmp_path)[-1] == []
    assert E._axis_coverage_shortfall_debt(tmp_path) == []
