from __future__ import annotations

import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
import pytest

from mechanical_gate_registry import (
    MechanicalGateRegistryError,
    load_mechanical_gate_registry,
    strict_json_loads,
    validate_mechanical_gate_registry,
)
from test_mechanical_gate_registry_schema import valid_registry_payload


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "rules" / "mechanical-gate-registry.json"
SCHEMA_PATH = ROOT / "rules" / "mechanical-gate-registry.schema.v2.json"

LIVE_BY_SEAM = {
    "STARTUP_RESUME": (
        "snapshot.interphase_drift",
        "snapshot.startup_binding",
        "supply_chain.pre_input_execution",
    ),
    "PRE_DISCOVERY": (),
    "POST_DISCOVERY": (
        "axis.finding_delivery",
        "axis.hot_function_gap_matrix",
        "enumeration.array_uniqueness",
        "enumeration.committed_invariant",
        "enumeration.coreference_gap",
        "enumeration.coreference_obligation",
        "enumeration.critical_asset_mover",
        "enumeration.graph_health",
        "enumeration.unbounded_stored_input",
        "enumeration.variant_boundary",
        "enumeration.variant_symmetric",
        "enumgap.exploration_delivery",
        "promotion.orphan_reopen",
    ),
    "PRE_VERIFY": (
        "inventory.identifier_exists",
        "inventory.location_exists",
        "inventory.production_scope",
        "poc.force_by_default",
    ),
    "POST_VERIFY": (
        "external_assumption.assert_cap",
        "external_assumption.demotion_veto",
        "mechanical_poc.execute",
        "postverify.late_candidate_reopen",
        "severity.independent_challenge",
        "supply_chain.pre_poc_execution",
        "verdict.evidence_integrity",
    ),
    "REPORT_ASSEMBLY": (
        "external_research.citation_gap",
        "report.dedup_lossless_consolidation",
        "report.index_retention_reconcile",
        "report.integrity_no_ship",
        "report.mandatory_reverification",
        "report.typed_disposition",
    ),
}

LIVE_CLASSES = {
    "supply_chain.pre_input_execution": "PIPELINE_INTEGRITY",
    "supply_chain.pre_poc_execution": "PIPELINE_INTEGRITY",
    "snapshot.startup_binding": "PIPELINE_INTEGRITY",
    "snapshot.interphase_drift": "PIPELINE_INTEGRITY",
    "enumeration.graph_health": "TELEMETRY_ONLY",
    "enumeration.coreference_obligation": "RECALL_GENERATOR",
    "enumeration.coreference_gap": "RECALL_GENERATOR",
    "enumeration.critical_asset_mover": "RECALL_GENERATOR",
    "enumeration.array_uniqueness": "RECALL_GENERATOR",
    "enumeration.unbounded_stored_input": "RECALL_GENERATOR",
    "enumeration.variant_boundary": "RECALL_GENERATOR",
    "enumeration.variant_symmetric": "RECALL_GENERATOR",
    "enumeration.committed_invariant": "RECALL_GENERATOR",
    "axis.hot_function_gap_matrix": "RECALL_GENERATOR",
    "enumgap.exploration_delivery": "PIPELINE_INTEGRITY",
    "axis.finding_delivery": "PIPELINE_INTEGRITY",
    "promotion.orphan_reopen": "RECALL_GENERATOR",
    "inventory.location_exists": "PRECISION_DISCRIMINATOR",
    "inventory.production_scope": "PRECISION_DISCRIMINATOR",
    "inventory.identifier_exists": "PRECISION_DISCRIMINATOR",
    "poc.force_by_default": "PIPELINE_INTEGRITY",
    "mechanical_poc.execute": "PIPELINE_INTEGRITY",
    "verdict.evidence_integrity": "PRECISION_DISCRIMINATOR",
    "external_assumption.assert_cap": "PRECISION_DISCRIMINATOR",
    "external_assumption.demotion_veto": "PRECISION_DISCRIMINATOR",
    "severity.independent_challenge": "PRECISION_DISCRIMINATOR",
    "external_research.citation_gap": "TELEMETRY_ONLY",
    "postverify.late_candidate_reopen": "RECALL_GENERATOR",
    "report.index_retention_reconcile": "PIPELINE_INTEGRITY",
    "report.dedup_lossless_consolidation": "PIPELINE_INTEGRITY",
    "report.typed_disposition": "PRECISION_DISCRIMINATOR",
    "report.mandatory_reverification": "PIPELINE_INTEGRITY",
    "report.integrity_no_ship": "PIPELINE_INTEGRITY",
}

TOMBSTONES = {
    "verdict.integrity_markdown_flip": "SUNSET",
    "report.material_harm_floor_legacy": "CONSOLIDATED",
    "promotion.orphan_appendix_route_legacy": "SUNSET",
}


def _load_raw(path: Path) -> dict[str, object]:
    return strict_json_loads(path.read_bytes())


def _set_path(
    payload: object,
    path: tuple[object, ...],
    value: object,
) -> None:
    cursor = payload
    for component in path[:-1]:
        cursor = cursor[component]  # type: ignore[index]
    cursor[path[-1]] = value  # type: ignore[index]


def _assert_schema_and_semantics_reject(payload: dict[str, object]) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(payload)
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)


def test_canonical_schema_is_draft_202012_and_closed_recursively() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"

    def visit(value: object) -> None:
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
            for nested in value.values():
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(schema)


def test_every_schema_integer_has_an_explicit_finite_maximum() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    integer_schemas: list[dict[str, object]] = []

    def visit(value: object) -> None:
        if isinstance(value, dict):
            if value.get("type") == "integer":
                integer_schemas.append(value)
            for nested in value.values():
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(schema)
    assert integer_schemas
    assert all(
        type(row.get("maximum")) is int
        and int(row["maximum"]) <= 9_007_199_254_740_991
        for row in integer_schemas
    )


def test_canonical_filename_cannot_bypass_the_adjacent_schema(
    tmp_path: Path,
) -> None:
    registry_path = tmp_path / "mechanical-gate-registry.json"
    registry_path.write_text(
        json.dumps(valid_registry_payload()),
        encoding="utf-8",
    )
    with pytest.raises(MechanicalGateRegistryError):
        load_mechanical_gate_registry(
            registry_path,
            installed_root=tmp_path,
        )


def test_canonical_registry_matches_schema_and_exact_stage1_denominator() -> None:
    raw = _load_raw(REGISTRY_PATH)
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(raw)
    registry = load_mechanical_gate_registry(
        REGISTRY_PATH,
        installed_root=ROOT,
    )
    records = {record.gate_id: record for record in registry.gate_records}
    expected_live = {
        gate_id
        for gate_ids in LIVE_BY_SEAM.values()
        for gate_id in gate_ids
    }
    assert len(expected_live) == 33
    assert set(records) == expected_live | set(TOMBSTONES)
    assert {
        gate_id: records[gate_id].decision_class
        for gate_id in expected_live
    } == LIVE_CLASSES
    assert {
        gate_id: records[gate_id].lifecycle_state
        for gate_id in TOMBSTONES
    } == TOMBSTONES


def test_stage1_seam_counts_and_set_equations_are_exact() -> None:
    registry = load_mechanical_gate_registry(
        REGISTRY_PATH,
        installed_root=ROOT,
    )
    budgets = {
        budget.owning_seam: budget for budget in registry.seam_budgets
    }
    assert tuple(len(LIVE_BY_SEAM[seam]) for seam in budgets) == (
        3,
        0,
        13,
        4,
        7,
        6,
    )
    for seam, expected in LIVE_BY_SEAM.items():
        budget = budgets[seam]
        expected_sorted = tuple(
            sorted(expected, key=lambda item: item.encode("utf-8"))
        )
        assert budget.baseline_gate_ids == expected_sorted
        assert budget.addition_gate_ids == ()
        assert budget.release_gate_ids == ()
        assert budget.active_gate_count == len(expected)
        assert budget.activated_or_shadow_additions == 0
        assert budget.approved_slot_releases == 0
        assert budget.post_change_gate_count == len(expected)
        assert budget.approval_status == "UNAPPROVED_BASELINE"
        assert budget.gate_budget_ceiling is None
        assert budget.approval_revision is None
        assert budget.approver is None
        assert budget.exception is None


def test_stage1_live_records_never_fabricate_governance_authority() -> None:
    registry = load_mechanical_gate_registry(
        REGISTRY_PATH,
        installed_root=ROOT,
    )
    assert registry.migration["new_runtime_transitions_blocked"] is True
    assert registry.migration["baseline_review_status"] == "UNREVIEWED"
    assert registry.migration["baseline_reviewer"] is None
    assert registry.migration["baseline_reviewed_at"] is None
    assert registry.migration["baseline_review_receipt_sha256"] is None
    live = [
        record
        for record in registry.gate_records
        if record.lifecycle_state == "LEGACY_ACTIVE_UNGOVERNED"
    ]
    assert len(live) == 33
    for record in live:
        assert record.admission["status"] == "LEGACY_UNASSESSED"
        assert record.admission["evidence_receipt_sha256"] is None
        assert set(record.ownership.values()) == {
            None,
            "UNASSIGNED_MIGRATION_DEBT",
        }
        assert record.review_and_sunset["transition_review_status"] == (
            "LEGACY_UNREVIEWED"
        )
        assert record.review_and_sunset["review_receipt_sha256"] is None
        assert record.input_contracts == ()
        assert record.output_contracts == ()
        assert record.activations
        assert all(
            activation.runtime_state == "LEGACY_NOT_MIGRATED"
            for activation in record.activations
        )
        assert all(
            value is None
            for key, value in record.false_fire_budget.items()
            if key != "status"
        )
        assert record.false_fire_budget["status"] == "UNESTABLISHED"


def test_legacy_migration_allowance_is_narrow_and_cannot_promote() -> None:
    payload = valid_registry_payload()
    payload["gate_records"][0]["activations"][0]["runtime_state"] = (
        "LEGACY_NOT_MIGRATED"
    )
    payload["gate_records"][0]["input_contracts"] = []
    payload["gate_records"][0]["output_contracts"] = []
    validate_mechanical_gate_registry(payload)

    for state in ("SHADOW", "REPLAY", "ACTIVE"):
        candidate = copy.deepcopy(payload)
        candidate["gate_records"][0]["lifecycle_state"] = state
        candidate["gate_records"][0]["admission"]["status"] = (
            "EVIDENCE_COMPLETE"
        )
        candidate["gate_records"][0]["admission"][
            "evidence_receipt_sha256"
        ] = "b" * 64
        with pytest.raises(MechanicalGateRegistryError):
            validate_mechanical_gate_registry(candidate)

    candidate = copy.deepcopy(payload)
    candidate["migration"]["new_runtime_transitions_blocked"] = False
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(candidate)


def test_stage1_canonical_rejects_runtime_activation_and_full_contracts() -> None:
    raw = _load_raw(REGISTRY_PATH)
    live_index = next(
        index
        for index, row in enumerate(raw["gate_records"])  # type: ignore[union-attr]
        if row["lifecycle_state"] == "LEGACY_ACTIVE_UNGOVERNED"
    )

    runtime = copy.deepcopy(raw)
    runtime["gate_records"][live_index]["activations"][0][  # type: ignore[index]
        "runtime_state"
    ] = "RUNTIME"
    _assert_schema_and_semantics_reject(runtime)

    full_contracts = copy.deepcopy(raw)
    dirty = valid_registry_payload()["gate_records"][0]  # type: ignore[index]
    full_contracts["gate_records"][live_index]["input_contracts"] = (  # type: ignore[index]
        copy.deepcopy(dirty["input_contracts"])
    )
    full_contracts["gate_records"][live_index]["output_contracts"] = (  # type: ignore[index]
        copy.deepcopy(dirty["output_contracts"])
    )
    _assert_schema_and_semantics_reject(full_contracts)


@pytest.mark.parametrize(
    ("path", "value"),
    (
        (("registry_scope", "scope_review_receipt_sha256"), "b" * 64),
        (("migration", "baseline_review_status"), "REVIEWED"),
        (("migration", "baseline_reviewer"), "independent-reviewer"),
        (
            ("migration", "baseline_reviewed_at"),
            "2030-01-01T00:00:00Z",
        ),
        (("migration", "baseline_review_receipt_sha256"), "b" * 64),
        (
            ("activation_inventory", "independent_review_receipt_sha256"),
            "b" * 64,
        ),
        (
            ("gate_records", 0, "admission", "evidence_receipt_sha256"),
            "b" * 64,
        ),
        (
            ("gate_records", 0, "runtime_budget", "max_input_bytes"),
            1,
        ),
        (
            (
                "gate_records",
                0,
                "release_evidence",
                "recall_parity_receipt_sha256",
            ),
            "b" * 64,
        ),
        (
            (
                "gate_records",
                0,
                "release_evidence",
                "system_owner_approval_sha256",
            ),
            "b" * 64,
        ),
        (
            (
                "gate_records",
                0,
                "false_fire_budget",
                "current_evidence_receipt_sha256",
            ),
            "b" * 64,
        ),
        (
            (
                "gate_records",
                0,
                "overlap_and_consolidation",
                "recall_parity_receipt_sha256",
            ),
            "b" * 64,
        ),
        (
            ("gate_records", 0, "ownership", "component_owner"),
            "component-owner",
        ),
        (
            (
                "gate_records",
                0,
                "review_and_sunset",
                "review_receipt_sha256",
            ),
            "b" * 64,
        ),
        (
            ("gate_records", 0, "part0", "review_receipt_sha256"),
            "b" * 64,
        ),
    ),
)
def test_stage1_canonical_rejects_fabricated_authority_everywhere(
    path: tuple[object, ...],
    value: object,
) -> None:
    raw = _load_raw(REGISTRY_PATH)
    _set_path(raw, path, value)
    _assert_schema_and_semantics_reject(raw)


@pytest.mark.parametrize(
    ("path", "value"),
    (
        (("admission", "evidence_receipt_sha256"), "b" * 64),
        (
            ("release_evidence", "system_owner_approval_sha256"),
            "b" * 64,
        ),
        (
            ("false_fire_budget", "current_evidence_receipt_sha256"),
            "b" * 64,
        ),
        (("ownership", "system_owner"), "system-owner"),
        (("part0", "review_receipt_sha256"), "b" * 64),
    ),
)
def test_stage1_tombstones_cannot_fabricate_authority(
    path: tuple[object, ...],
    value: object,
) -> None:
    raw = _load_raw(REGISTRY_PATH)
    tombstone = next(
        row
        for row in raw["gate_records"]  # type: ignore[union-attr]
        if row["lifecycle_state"] in {"CONSOLIDATED", "SUNSET"}
    )
    _set_path(tombstone, path, value)
    _assert_schema_and_semantics_reject(raw)


def test_stage1_canonical_rejects_approved_seam_ceiling_cutover() -> None:
    raw = _load_raw(REGISTRY_PATH)
    raw["registry_revision"] = 2
    for row in raw["seam_budgets"]:  # type: ignore[union-attr]
        row.update(
            {
                "approval_status": "APPROVED",
                "gate_budget_ceiling": row["active_gate_count"],
                "approval_revision": 1,
                "approver": "independent-reviewer",
            }
        )
    _assert_schema_and_semantics_reject(raw)


def test_stage1_canonical_rejects_seam_exception_authority() -> None:
    raw = _load_raw(REGISTRY_PATH)
    raw["seam_budgets"][0]["exception"] = {  # type: ignore[index]
        "exception_approver": "independent-reviewer",
        "temporary_ceiling_delta": 1,
        "exception_rationale_code": "HELD_OUT_JUSTIFICATION",
        "held_out_evidence_receipt_sha256": "b" * 64,
        "review_by": "2099-01-01T00:00:00Z",
        "expires_on": "2099-02-01T00:00:00Z",
    }
    _assert_schema_and_semantics_reject(raw)


@pytest.mark.parametrize(
    ("field", "value", "schema_rejects"),
    (
        ("display_name", "   ", True),
        ("purpose", "\t", True),
        ("part0.generic_subject", "\n", True),
        ("display_name", " untrimmed ", True),
        ("purpose", "x" * 4097, True),
        ("part0.generic_subject", "Cafe\u0301", False),
    ),
)
def test_stage1_human_metadata_is_trimmed_normalized_and_bounded(
    field: str,
    value: str,
    schema_rejects: bool,
) -> None:
    raw = _load_raw(REGISTRY_PATH)
    gate = raw["gate_records"][0]  # type: ignore[index]
    if field == "part0.generic_subject":
        gate["part0"]["generic_subject"] = value
    else:
        gate[field] = value
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    if schema_rejects:
        with pytest.raises(ValidationError):
            Draft202012Validator(schema).validate(raw)
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(raw)


def test_dirty_fixture_admitted_timestamp_is_still_syntactically_validated() -> None:
    payload = valid_registry_payload()
    payload["migration"]["baseline_reviewed_at"] = "not-an-instant"  # type: ignore[index]
    with pytest.raises(MechanicalGateRegistryError, match="instant|UTC"):
        validate_mechanical_gate_registry(payload)


def test_tombstones_are_nonruntime_unreviewed_migration_debt() -> None:
    registry = load_mechanical_gate_registry(
        REGISTRY_PATH,
        installed_root=ROOT,
    )
    tombstones = [
        record
        for record in registry.gate_records
        if record.gate_id in TOMBSTONES
    ]
    assert len(tombstones) == 3
    for record in tombstones:
        assert record.activations == ()
        assert record.input_contracts == ()
        assert record.output_contracts == ()
        assert record.ownership["assignment_status"] == (
            "UNASSIGNED_MIGRATION_DEBT"
        )
        assert all(
            record.ownership[key] is None
            for key in (
                "component_owner",
                "system_owner",
                "implementer",
                "independent_reviewer",
            )
        )
        assert record.review_and_sunset["transition_review_status"] == (
            "MIGRATION_TOMBSTONE_UNASSESSED"
        )
        assert record.review_and_sunset["review_receipt_sha256"] is None
        assert record.review_and_sunset["sunset_reason"]


def test_activation_selectors_use_truthful_pipeline_product_cells() -> None:
    registry = load_mechanical_gate_registry(
        REGISTRY_PATH,
        installed_root=ROOT,
    )
    live = [
        record
        for record in registry.gate_records
        if record.lifecycle_state == "LEGACY_ACTIVE_UNGOVERNED"
    ]
    activations = [
        activation
        for record in live
        for activation in record.activations
    ]
    assert len(live) == 33
    assert len(activations) > len(live)
    sc = {"APTOS", "DAML", "EVM", "SOLANA", "SOROBAN", "SUI"}
    l1 = {"L1_GO", "L1_RUST"}
    for activation in activations:
        assert len(activation.pipelines) == 1
        if activation.pipelines == ("SC",):
            assert set(activation.ecosystems) <= sc
        else:
            assert activation.pipelines == ("L1",)
            assert set(activation.ecosystems) <= l1
    by_gate = {record.gate_id: record for record in live}
    pre_input = by_gate["supply_chain.pre_input_execution"].activations
    assert len(pre_input) == 1
    assert pre_input[0].pipelines == ("SC",)
    assert pre_input[0].ecosystems == ("EVM",)
    for gate_id, record in by_gate.items():
        if gate_id.startswith("enumeration."):
            assert all(
                set(activation.modes)
                == {"LIGHT", "CORE", "THOROUGH"}
                for activation in record.activations
            )


def test_encoded_cross_pipeline_selector_product_is_rejected() -> None:
    payload = valid_registry_payload()
    activation = payload["gate_records"][0]["activations"][0]
    activation["pipelines"] = ["L1", "SC"]
    activation["ecosystems"] = ["EVM", "L1_GO"]
    with pytest.raises(
        MechanicalGateRegistryError,
        match="selector|pipeline|product",
    ):
        validate_mechanical_gate_registry(payload)
