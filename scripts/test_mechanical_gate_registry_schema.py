from __future__ import annotations

import copy
from dataclasses import replace
import json
import os
from pathlib import Path

import pytest

from mechanical_gate_registry import (
    DECISION_CLASSES,
    DIRECTIONS,
    SEAMS,
    GateRecord,
    MechanicalGateRegistry,
    MechanicalGateRegistryError,
    SeamBudget,
    load_mechanical_gate_registry,
    mechanical_gate_registry_digest,
    strict_json_loads,
    validate_mechanical_gate_registry,
    validate_part0_metadata,
    validate_seam_budget_equations,
    _validate_authority,
)


SHA = "a" * 64
MAX_SEMANTIC_INTEGER = 9_007_199_254_740_991
GATE_ID = "fixture.integrity_guard"
ACTIVATION_ID = "fixture.integrity_guard.recon"


def _activation(*, code_digest: str = SHA) -> dict[str, object]:
    return {
        "activation_id": ACTIVATION_ID,
        "module": "scripts/gate_fixture.py",
        "wrapper_symbol": "run_fixture_guard",
        "implementation_symbols": ["_fixture_guard_impl"],
        "hook_id": "fixture.recon.guard",
        "phases": ["RECON"],
        "pipelines": ["SC"],
        "modes": ["THOROUGH"],
        "ecosystems": ["EVM"],
        "backends": ["CLAUDE"],
        "runtime_state": "RUNTIME",
        "code_digest_algorithm": (
            "sha256:plamen-python-decision-closure-ast-v1"
        ),
        "code_digest": code_digest,
    }


def _gate_record(
    *,
    gate_id: str = GATE_ID,
    activation: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "gate_id": gate_id,
        "display_name": "Generic fixture integrity guard",
        "lifecycle_state": "LEGACY_ACTIVE_UNGOVERNED",
        "decision_class": "PIPELINE_INTEGRITY",
        "admission": {
            "status": "LEGACY_UNASSESSED",
            "evidence_requirements": sorted([
                "DETERMINISTIC_CORRECTNESS_SAFETY",
                "TYPED_INPUT_OUTPUT",
                "FAULT_RESUME_EVIDENCE",
                "RECALL_SAFE_FAILURE",
                "PART0_PASS",
            ]),
            "evidence_receipt_sha256": None,
        },
        "owning_seam": "STARTUP_RESUME",
        "execution_order": 10,
        "activations": [activation or _activation()],
        "purpose": "Preserve generic transaction integrity before execution.",
        "authority": {
            "can_add": False,
            "can_remove": False,
            "can_lower_severity": False,
            "can_raise_severity": False,
            "can_block_execution": True,
            "can_execute_target": False,
            "can_clear_debt": False,
            "can_veto_ship": False,
            "direction": "BLOCK_EXECUTION",
            "subject_identity_schema": "fixture.subject.v1",
            "join_rule": "EXACT_SUBJECT_ID",
            "monotonicity_claim": "Failure preserves the upstream state.",
            "invalid_authority_fallback": "BLOCK_TARGET_EXECUTION",
        },
        "input_contracts": [
            {
                "artifact_identity": (
                    "scratchpad:_mechanical_gates/inputs/fixture.json"
                ),
                "artifact_root": "scratchpad",
                "schema_version": "fixture.input.v1",
                "authoritative_producer": "fixture.producer",
                "role": "EXACT",
                "subject_identity_schema": "fixture.subject.v1",
                "join_rule": "EXACT_SUBJECT_ID",
                "freshness_rule": "CURRENT_RUN_EXACT_BYTES",
                "absent_behavior": "HARD_STOP_BEFORE_SIDE_EFFECT",
                "malformed_behavior": "HARD_STOP_BEFORE_SIDE_EFFECT",
            }
        ],
        "output_contracts": [
            {
                "artifact_identity": (
                    "scratchpad:_mechanical_gates/receipts/"
                    "fixture.integrity_guard.json"
                ),
                "artifact_root": "scratchpad",
                "schema_version": "fixture.receipt.v1",
                "phase_io_work_unit_id": (
                    "sc/thorough/evm/claude/recon/fixture.guard"
                ),
                "artifact_class": "REQUIRED",
                "writer": "DRIVER",
                "write_mode": "CREATE",
                "minimum_gate": "SCHEMA",
                "consumers": ["fixture.consumer"],
                "condition_id": "",
                "external_preimage_validator": "",
                "authority_carried": "COMMON_RECEIPT",
            },
            {
                "artifact_identity": (
                    "scratchpad:_mechanical_gates/governance_debt/"
                    "fixture.integrity_guard.json"
                ),
                "artifact_root": "scratchpad",
                "schema_version": "fixture.governance_debt.v1",
                "phase_io_work_unit_id": (
                    "sc/thorough/evm/claude/recon/fixture.guard"
                ),
                "artifact_class": "CONDITIONAL",
                "writer": "DRIVER",
                "write_mode": "CREATE",
                "minimum_gate": "SCHEMA",
                "consumers": ["fixture.consumer"],
                "condition_id": "GOVERNANCE_DEBT_PRESENT",
                "external_preimage_validator": "",
                "authority_carried": "GOVERNANCE_DEBT",
            },
            {
                "artifact_identity": (
                    "scratchpad:_mechanical_gates/overflow/"
                    "fixture.integrity_guard.json"
                ),
                "artifact_root": "scratchpad",
                "schema_version": "fixture.overflow.v1",
                "phase_io_work_unit_id": (
                    "sc/thorough/evm/claude/recon/fixture.guard"
                ),
                "artifact_class": "CONDITIONAL",
                "writer": "DRIVER",
                "write_mode": "CREATE",
                "minimum_gate": "SCHEMA",
                "consumers": ["fixture.consumer"],
                "condition_id": "OVERFLOW_PRESENT",
                "external_preimage_validator": "",
                "authority_carried": "OVERFLOW_BACKLOG",
            },
        ],
        "failure_contract": {
            "absent": "HARD_STOP_BEFORE_SIDE_EFFECT",
            "malformed": "HARD_STOP_BEFORE_SIDE_EFFECT",
            "stale": "HARD_STOP_BEFORE_SIDE_EFFECT",
            "split": "HARD_STOP_BEFORE_SIDE_EFFECT",
            "duplicate": "HARD_STOP_BEFORE_SIDE_EFFECT",
            "contradictory": "HARD_STOP_BEFORE_SIDE_EFFECT",
            "provider_failure": "HARD_STOP_BEFORE_SIDE_EFFECT",
            "timeout": "HARD_STOP_BEFORE_SIDE_EFFECT",
            "budget_overflow": "HARD_STOP_BEFORE_SIDE_EFFECT",
            "receipt_failure": "HARD_STOP_BEFORE_SIDE_EFFECT",
            "input_mutation": "HARD_STOP_BEFORE_SIDE_EFFECT",
            "partial_resume": "QUARANTINE_AND_RETRY",
        },
        "runtime_budget": {
            "denominator_must_be_exact": True,
            "stable_shard_ordering": "UTF8_BYTE_ORDER",
            "overflow_action": "HARD_STOP_BEFORE_SIDE_EFFECT",
            "max_input_bytes": None,
            "max_input_files": None,
            "max_raw_rows": None,
            "max_unique_subjects": None,
            "max_eligible_subjects": None,
            "max_retained_or_fired": None,
            "max_emitted_candidates": None,
            "max_wall_clock_ms": None,
            "max_external_processes": None,
            "max_workers": None,
            "max_tokens": None,
        },
        "release_evidence": {
            "status": "UNESTABLISHED",
            "replacement_gate_ids": [],
            "recall_parity_receipt_sha256": None,
            "system_owner_approval_sha256": None,
        },
        "false_fire_budget": {
            "status": "UNESTABLISHED",
            "held_out_corpus_id": None,
            "held_out_corpus_sha256": None,
            "evaluator_principal": None,
            "gate_implementer_principal": None,
            "evaluator_build_sha256": None,
            "comparator_sha256": None,
            "observation_window_id": None,
            "minimum_adjudicated_denominator": None,
            "adjudicated_fire_count": None,
            "true_fire_count": None,
            "false_fire_count": None,
            "maximum_false_fire_count": None,
            "maximum_false_fire_rate_ppm": None,
            "current_evidence_receipt_sha256": None,
        },
        "overlap_and_consolidation": {
            "overlapping_gate_ids": [],
            "shared_contract_ids": [],
            "unique_authority": "Blocks execution on invalid fixture authority.",
            "consolidation_status": "NOT_ASSESSED",
            "retirement_criteria": "Independent recall parity is required.",
            "recall_parity_receipt_sha256": None,
        },
        "ownership": {
            "component_owner": None,
            "system_owner": None,
            "implementer": None,
            "independent_reviewer": None,
            "assignment_status": "UNASSIGNED_MIGRATION_DEBT",
        },
        "review_and_sunset": {
            "previous_lifecycle_state": None,
            "transition_review_status": "LEGACY_UNREVIEWED",
            "reviewed_at": None,
            "review_receipt_sha256": None,
            "expires_at": None,
            "sunset_reason": None,
            "superseded_by_gate_ids": [],
        },
        "part0": {
            "status": "PASS",
            "generic_subject": "generic transaction authority",
            "target_names": [],
            "finding_ids": [],
            "target_locations": [],
            "motivating_answers": [],
            "review_receipt_sha256": None,
        },
    }


def _budget(seam: str, baseline: list[str]) -> dict[str, object]:
    return {
        "owning_seam": seam,
        "approval_status": "UNAPPROVED_BASELINE",
        "gate_budget_ceiling": None,
        "approval_revision": None,
        "approver": None,
        "baseline_gate_ids": baseline,
        "addition_gate_ids": [],
        "release_gate_ids": [],
        "active_gate_count": len(baseline),
        "activated_or_shadow_additions": 0,
        "approved_slot_releases": 0,
        "post_change_gate_count": len(baseline),
        "exception": None,
    }


def valid_registry_payload() -> dict[str, object]:
    return {
        "schema_version": "plamen.mechanical_gate_registry.v2",
        "registry_revision": 1,
        "registry_scope": {
            "scope_version": "plamen.mechanical_gate_scope.v1",
            "included_authorities": [
                "CANDIDATE_MEMBERSHIP",
                "OBLIGATION_LIFECYCLE",
                "DISPOSITION_OR_REPORT_TIER",
                "SEVERITY",
                "EVIDENCE_OR_SUCCESSOR_AUTHORITY",
                "TARGET_EXECUTION",
                "VERIFICATION_ROUTING",
                "SHIP_AUTHORITY",
            ],
            "excluded_control_families": [
                "STRUCTURAL_SELF_VALIDATION",
                "TRANSACTION_MECHANICS",
                "PURE_DATA_UTILITIES",
                "UNCONSUMED_TOOL_OUTPUT",
                "MODEL_JUDGMENT",
                "NON_PRODUCTION_CODE",
                "POST_AUDIT_HUMAN_CLASSIFICATION",
            ],
            "production_roots": ["scripts"],
            "production_excludes": [
                "scripts/conftest.py",
                "scripts/test_*.py",
            ],
            "scope_review_receipt_sha256": None,
        },
        "migration_status": "BASELINING_EXISTING_ACTIVATIONS",
        "migration": {
            "source_tree_digest": SHA,
            "source_tree_digest_algorithm": "sha256:plamen-source-tree-v1",
            "baseline_gate_ids": [GATE_ID],
            "baseline_live_gate_count": 1,
            "baseline_review_status": "UNREVIEWED_DIRTY_FIXTURE",
            "baseline_reviewer": None,
            "baseline_reviewed_at": None,
            "baseline_review_receipt_sha256": None,
            "new_runtime_transitions_blocked": True,
        },
        "activation_inventory": {
            "schema_version": (
                "plamen.mechanical_gate_activation_inventory.v1"
            ),
            "manifest_path": (
                "rules/mechanical-gate-activation-baseline.v1.json"
            ),
            "manifest_sha256": None,
            "source_tree_digest_algorithm": (
                "sha256:plamen-source-tree-v1"
            ),
            "source_tree_digest": SHA,
            "generator_version": (
                "plamen.mechanical_gate_inventory.fixture-v1"
            ),
            "generator_digest": None,
            "independent_review_receipt_sha256": None,
        },
        "seam_taxonomy": list(SEAMS),
        "decision_class_taxonomy": list(DECISION_CLASSES),
        "direction_taxonomy": list(DIRECTIONS),
        "seam_budgets": [
            _budget(seam, [GATE_ID] if seam == "STARTUP_RESUME" else [])
            for seam in SEAMS
        ],
        "gate_records": [_gate_record()],
    }


def _two_gate_payload() -> dict[str, object]:
    payload = valid_registry_payload()
    second = copy.deepcopy(payload["gate_records"][0])  # type: ignore[index]
    second_id = "fixture.second_guard"
    second["gate_id"] = second_id
    second["execution_order"] = 11
    second["activations"][0]["activation_id"] = f"{second_id}.recon"
    for output in second["output_contracts"]:
        output["artifact_identity"] = str(
            output["artifact_identity"]
        ).replace(GATE_ID, second_id)
    payload["gate_records"].append(second)  # type: ignore[union-attr]
    payload["migration"]["baseline_gate_ids"] = [  # type: ignore[index]
        GATE_ID,
        second_id,
    ]
    payload["migration"]["baseline_live_gate_count"] = 2  # type: ignore[index]
    first_budget = payload["seam_budgets"][0]  # type: ignore[index]
    first_budget["baseline_gate_ids"] = [GATE_ID, second_id]
    first_budget["active_gate_count"] = 2
    first_budget["post_change_gate_count"] = 2
    return payload


def test_fixture_is_a_frozen_noncanonical_registry() -> None:
    registry = validate_mechanical_gate_registry(valid_registry_payload())
    assert isinstance(registry, MechanicalGateRegistry)
    assert isinstance(registry.gate_records[0], GateRecord)
    assert isinstance(registry.seam_budgets[0], SeamBudget)
    with pytest.raises((AttributeError, TypeError)):
        registry.registry_revision = 2  # type: ignore[misc]
    with pytest.raises(TypeError):
        registry.registry_scope["scope_version"] = "changed"  # type: ignore[index]
    assert len(mechanical_gate_registry_digest(registry)) == 64


@pytest.mark.parametrize(
    ("field", "invalid"),
    (
        ("schema_version", "plamen.mechanical_gate_registry.v999"),
        ("registry_revision", 0),
        ("registry_scope", {}),
        ("migration_status", "ACTIVE"),
        ("migration", {}),
        ("activation_inventory", {}),
        ("seam_taxonomy", ("STARTUP_RESUME",)),
        ("decision_class_taxonomy", ("PIPELINE_INTEGRITY",)),
        ("direction_taxonomy", ("BLOCK_EXECUTION",)),
        ("seam_budgets", ()),
        ("gate_records", ()),
    ),
)
def test_replaced_typed_registry_cannot_bypass_revalidation(
    field: str,
    invalid: object,
) -> None:
    registry = validate_mechanical_gate_registry(valid_registry_payload())
    forged = replace(registry, **{field: invalid})
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(forged)
    with pytest.raises(MechanicalGateRegistryError):
        mechanical_gate_registry_digest(forged)


@pytest.mark.parametrize(
    ("field", "invalid"),
    (
        ("gate_id", "BAD"),
        ("display_name", ""),
        ("lifecycle_state", "LIVE"),
        ("decision_class", "UNKNOWN"),
        ("admission", {}),
        ("owning_seam", "UNKNOWN"),
        ("execution_order", -1),
        ("activations", ()),
        ("purpose", ""),
        ("authority", {}),
        ("input_contracts", ()),
        ("output_contracts", ()),
        ("failure_contract", {}),
        ("runtime_budget", {}),
        ("release_evidence", {}),
        ("false_fire_budget", {}),
        ("overlap_and_consolidation", {}),
        ("ownership", {}),
        ("review_and_sunset", {}),
        ("part0", {}),
    ),
)
def test_replaced_typed_gate_record_cannot_bypass_revalidation(
    field: str,
    invalid: object,
) -> None:
    registry = validate_mechanical_gate_registry(valid_registry_payload())
    forged_gate = replace(
        registry.gate_records[0], **{field: invalid}
    )
    forged = replace(registry, gate_records=(forged_gate,))
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(forged)
    with pytest.raises(MechanicalGateRegistryError):
        mechanical_gate_registry_digest(forged)


@pytest.mark.parametrize(
    ("field", "invalid"),
    (
        ("activation_id", "BAD"),
        ("module", r"C:\escaped.py"),
        ("wrapper_symbol", "not a symbol"),
        ("implementation_symbols", ()),
        ("hook_id", "BAD"),
        ("phases", ()),
        ("pipelines", ()),
        ("modes", ()),
        ("ecosystems", ()),
        ("backends", ()),
        ("runtime_state", "ACTIVE"),
        ("code_digest_algorithm", "sha256:unknown"),
        ("code_digest", "bad"),
    ),
)
def test_replaced_typed_activation_cannot_bypass_revalidation(
    field: str,
    invalid: object,
) -> None:
    registry = validate_mechanical_gate_registry(valid_registry_payload())
    gate = registry.gate_records[0]
    forged_activation = replace(
        gate.activations[0], **{field: invalid}
    )
    forged_gate = replace(gate, activations=(forged_activation,))
    forged = replace(registry, gate_records=(forged_gate,))
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(forged)
    with pytest.raises(MechanicalGateRegistryError):
        mechanical_gate_registry_digest(forged)


@pytest.mark.parametrize(
    ("field", "invalid"),
    (
        ("owning_seam", "UNKNOWN"),
        ("approval_status", "ACTIVE"),
        ("gate_budget_ceiling", -1),
        ("approval_revision", 0),
        ("approver", ""),
        ("baseline_gate_ids", ("BAD",)),
        ("addition_gate_ids", ("BAD",)),
        ("release_gate_ids", ("BAD",)),
        ("active_gate_count", -1),
        ("activated_or_shadow_additions", -1),
        ("approved_slot_releases", -1),
        ("post_change_gate_count", -1),
        ("exception", {}),
    ),
)
def test_replaced_typed_seam_budget_cannot_bypass_revalidation(
    field: str,
    invalid: object,
) -> None:
    registry = validate_mechanical_gate_registry(valid_registry_payload())
    forged_budget = replace(
        registry.seam_budgets[0], **{field: invalid}
    )
    forged = replace(
        registry,
        seam_budgets=(forged_budget, *registry.seam_budgets[1:]),
    )
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(forged)
    with pytest.raises(MechanicalGateRegistryError):
        mechanical_gate_registry_digest(forged)


@pytest.mark.parametrize(
    "raw",
    (
        b'{"x":1,"x":2}',
        b"\xef\xbb\xbf{}",
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":-Infinity}',
        b'{"x":1.5}',
        b"\xff",
    ),
)
def test_strict_json_rejects_ambiguous_or_noninteger_json(raw: bytes) -> None:
    with pytest.raises(MechanicalGateRegistryError):
        strict_json_loads(raw)


def test_strict_json_rejects_more_than_eight_mib() -> None:
    with pytest.raises(MechanicalGateRegistryError):
        strict_json_loads(b" " * (8 * 1024 * 1024 + 1))


def test_strict_json_normalizes_oversized_integer_parser_failure() -> None:
    raw = b'{"oversized":' + (b"9" * 5000) + b"}"
    with pytest.raises(MechanicalGateRegistryError, match="JSON|integer"):
        strict_json_loads(raw)


def test_strict_json_normalizes_excessive_nesting_failure() -> None:
    raw = (b"[" * 10_000) + b"0" + (b"]" * 10_000)
    with pytest.raises(MechanicalGateRegistryError, match="JSON|depth|nested"):
        strict_json_loads(raw)


def test_strict_json_rejects_excessive_post_parse_node_count() -> None:
    raw = b"[" + (b"0," * 250_000) + b"0]"
    with pytest.raises(MechanicalGateRegistryError, match="node"):
        strict_json_loads(raw)


@pytest.mark.parametrize(
    "raw",
    (
        b'"\\ud800"',
        b'{"nested":["\\udfff"]}',
        b'{"\\ud800":1}',
    ),
)
def test_strict_json_rejects_escaped_lone_surrogates_recursively(
    raw: bytes,
) -> None:
    with pytest.raises(MechanicalGateRegistryError, match="Unicode|surrogate"):
        strict_json_loads(raw)


def test_digest_normalizes_surrogate_canonicalization_failure() -> None:
    payload = valid_registry_payload()
    payload["gate_records"][0]["part0"]["generic_subject"] = "\ud800"  # type: ignore[index]
    with pytest.raises(MechanicalGateRegistryError):
        mechanical_gate_registry_digest(payload)


@pytest.mark.parametrize(
    ("path", "value"),
    (
        (("registry_revision",), MAX_SEMANTIC_INTEGER + 1),
        (
            ("migration", "baseline_live_gate_count"),
            MAX_SEMANTIC_INTEGER + 1,
        ),
        (
            ("gate_records", 0, "execution_order"),
            MAX_SEMANTIC_INTEGER + 1,
        ),
        (
            ("gate_records", 0, "runtime_budget", "max_input_bytes"),
            MAX_SEMANTIC_INTEGER + 1,
        ),
        (
            ("seam_budgets", 0, "active_gate_count"),
            MAX_SEMANTIC_INTEGER + 1,
        ),
    ),
)
def test_semantic_integer_fields_have_one_finite_interoperable_maximum(
    path: tuple[object, ...],
    value: int,
) -> None:
    payload: object = copy.deepcopy(valid_registry_payload())
    cursor = payload
    for component in path[:-1]:
        cursor = cursor[component]  # type: ignore[index]
    cursor[path[-1]] = value  # type: ignore[index]
    with pytest.raises(MechanicalGateRegistryError, match="maximum|integer"):
        validate_mechanical_gate_registry(payload)  # type: ignore[arg-type]


def test_loader_rejects_outside_root_symlink_and_nonregular(
    tmp_path: Path,
) -> None:
    installed = tmp_path / "installed"
    installed.mkdir()
    registry_path = installed / "fixture.json"
    registry_path.write_text(
        json.dumps(valid_registry_payload()), encoding="utf-8"
    )
    loaded = load_mechanical_gate_registry(
        registry_path, installed_root=installed
    )
    assert loaded.registry_revision == 1

    outside = tmp_path / "outside.json"
    outside.write_text(
        json.dumps(valid_registry_payload()), encoding="utf-8"
    )
    with pytest.raises(MechanicalGateRegistryError):
        load_mechanical_gate_registry(outside, installed_root=installed)

    link = installed / "link.json"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pass
    else:
        with pytest.raises(MechanicalGateRegistryError):
            load_mechanical_gate_registry(link, installed_root=installed)

    real_directory = installed / "real"
    real_directory.mkdir()
    nested = real_directory / "nested.json"
    nested.write_text(
        json.dumps(valid_registry_payload()), encoding="utf-8"
    )
    alias_directory = installed / "alias"
    try:
        alias_directory.symlink_to(real_directory, target_is_directory=True)
    except (OSError, NotImplementedError):
        pass
    else:
        with pytest.raises(MechanicalGateRegistryError):
            load_mechanical_gate_registry(
                alias_directory / "nested.json",
                installed_root=installed,
            )

    with pytest.raises(MechanicalGateRegistryError):
        load_mechanical_gate_registry(installed, installed_root=installed)


def test_dirty_fixture_marker_is_explicit_and_not_stage1_authority() -> None:
    dirty = valid_registry_payload()
    assert (
        dirty["migration"]["baseline_review_status"]  # type: ignore[index]
        == "UNREVIEWED_DIRTY_FIXTURE"
    )
    validate_mechanical_gate_registry(dirty)

    relabelled = copy.deepcopy(dirty)
    relabelled["migration"]["baseline_review_status"] = "UNREVIEWED"  # type: ignore[index]
    with pytest.raises(MechanicalGateRegistryError, match="Stage-1|legacy"):
        validate_mechanical_gate_registry(relabelled)


@pytest.mark.skipif(os.name != "nt", reason="Windows ADS fixture")
def test_loader_and_manifest_reject_windows_alternate_data_streams(
    tmp_path: Path,
) -> None:
    installed = tmp_path / "installed"
    installed.mkdir()
    base = installed / "fixture.json"
    base.write_text("base", encoding="utf-8")
    stream = Path(f"{base}:alternate")
    try:
        stream.write_text(
            json.dumps(valid_registry_payload()), encoding="utf-8"
        )
    except OSError:
        pytest.skip("host filesystem does not support named streams")
    with pytest.raises(MechanicalGateRegistryError, match="stream|canonical"):
        load_mechanical_gate_registry(stream, installed_root=installed)

    payload = valid_registry_payload()
    payload["activation_inventory"]["manifest_path"] = (  # type: ignore[index]
        "rules/mechanical-gate-activation-baseline.v1.json:alternate"
    )
    with pytest.raises(MechanicalGateRegistryError, match="manifest"):
        validate_mechanical_gate_registry(payload)


@pytest.mark.parametrize(
    ("path", "value"),
    (
        (("unexpected",), True),
        (("registry_scope", "unexpected"), True),
        (("migration", "unexpected"), True),
        (("activation_inventory", "unexpected"), True),
        (("seam_budgets", 0, "unexpected"), True),
        (("gate_records", 0, "unexpected"), True),
        (("gate_records", 0, "authority", "unexpected"), True),
        (("gate_records", 0, "activations", 0, "unexpected"), True),
        (("gate_records", 0, "part0", "unexpected"), True),
    ),
)
def test_unknown_key_is_rejected_at_every_material_level(
    path: tuple[object, ...],
    value: object,
) -> None:
    payload: object = copy.deepcopy(valid_registry_payload())
    cursor = payload
    for component in path[:-1]:
        cursor = cursor[component]  # type: ignore[index]
    cursor[path[-1]] = value  # type: ignore[index]
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "bad"),
    (
        ("seam_taxonomy", ["STARTUP_RESUME"]),
        ("decision_class_taxonomy", ["PIPELINE_INTEGRITY"]),
        ("direction_taxonomy", ["BLOCK_EXECUTION"]),
    ),
)
def test_taxonomies_are_exact_not_extensible(
    field: str, bad: list[str]
) -> None:
    payload = valid_registry_payload()
    payload[field] = bad
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)


def test_casefold_colliding_gate_and_activation_ids_are_rejected() -> None:
    payload = valid_registry_payload()
    second = copy.deepcopy(payload["gate_records"][0])  # type: ignore[index]
    second["gate_id"] = GATE_ID.upper()
    second["activations"][0]["activation_id"] = ACTIVATION_ID.upper()
    payload["gate_records"].append(second)  # type: ignore[union-attr]
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)


def test_lifecycle_transition_and_class_authority_must_be_compatible() -> None:
    payload = valid_registry_payload()
    gate = payload["gate_records"][0]  # type: ignore[index]
    gate["review_and_sunset"]["previous_lifecycle_state"] = "PROPOSED"
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)

    payload = valid_registry_payload()
    gate = payload["gate_records"][0]  # type: ignore[index]
    gate["decision_class"] = "TELEMETRY_ONLY"
    gate["admission"]["evidence_requirements"] = sorted([
        "M2_DETERMINISTIC",
        "M3_GENERIC_PART0",
        "EXACT_OR_VISIBLE_LOWER_BOUND",
        "TYPED_DELIVERY",
        "PART0_PASS",
    ])
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)


def test_seam_budget_uses_corrected_release_subset_equation() -> None:
    registry = validate_mechanical_gate_registry(valid_registry_payload())
    validate_seam_budget_equations(registry)

    for mutation in ("release_not_subset", "baseline_addition_overlap"):
        payload = valid_registry_payload()
        budget = payload["seam_budgets"][0]  # type: ignore[index]
        if mutation == "release_not_subset":
            budget["release_gate_ids"] = ["fixture.not_in_baseline"]
            budget["approved_slot_releases"] = 1
        else:
            budget["addition_gate_ids"] = [GATE_ID]
            budget["activated_or_shadow_additions"] = 1
        with pytest.raises(MechanicalGateRegistryError):
            validate_mechanical_gate_registry(payload)


def test_expired_runtime_exception_is_rejected() -> None:
    payload = valid_registry_payload()
    budget = payload["seam_budgets"][0]  # type: ignore[index]
    budget.update(
        {
            "approval_status": "APPROVED",
            "gate_budget_ceiling": 1,
            "approval_revision": 1,
            "approver": "system-owner",
            "exception": {
                "exception_approver": "independent-owner",
                "temporary_ceiling_delta": 1,
                "exception_rationale_code": "TEMPORARY_REVIEWED_CAPACITY",
                "held_out_evidence_receipt_sha256": SHA,
                "review_by": "2020-01-01T00:00:00Z",
                "expires_on": "2020-02-01T00:00:00Z",
            },
        }
    )
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)


def test_new_runtime_state_requires_independent_owner_and_review() -> None:
    payload = valid_registry_payload()
    gate = payload["gate_records"][0]  # type: ignore[index]
    gate["lifecycle_state"] = "ACTIVE"
    gate["admission"]["status"] = "EVIDENCE_COMPLETE"
    gate["admission"]["evidence_receipt_sha256"] = SHA
    gate["review_and_sunset"]["previous_lifecycle_state"] = (
        "LEGACY_ACTIVE_UNGOVERNED"
    )
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)


def test_non_array_taxonomy_is_a_domain_error_not_a_python_error() -> None:
    payload = valid_registry_payload()
    payload["seam_taxonomy"] = 7
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("artifact_identity", "scratchpad:report.json:secret"),
        ("artifact_identity", r"scratchpad:dir\report.json"),
        ("artifact_identity", "scratchpad:../report.json"),
            ("artifact_root", "SCRATCHPAD"),
            ("artifact_root", "install"),
            ("write_mode", "IMMUTABLE_CREATE"),
            ("artifact_class", "UNKNOWN"),
        ("phase_io_work_unit_id", "fixture.guard"),
    ),
)
def test_phaseio_output_contract_rejects_noncanonical_authority(
    field: str, value: object
) -> None:
    payload = valid_registry_payload()
    payload["gate_records"][0]["output_contracts"][0][field] = value  # type: ignore[index]
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)


@pytest.mark.parametrize(
    "authority",
    ("COMMON_RECEIPT", "GOVERNANCE_DEBT", "OVERFLOW_BACKLOG"),
)
def test_every_runtime_gate_requires_all_common_outputs(
    authority: str,
) -> None:
    payload = valid_registry_payload()
    outputs = payload["gate_records"][0]["output_contracts"]  # type: ignore[index]
    payload["gate_records"][0]["output_contracts"] = [  # type: ignore[index]
        row for row in outputs if row["authority_carried"] != authority
    ]
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)


def test_cross_gate_output_writer_collision_is_rejected() -> None:
    payload = _two_gate_payload()
    first_output = payload["gate_records"][0]["output_contracts"][0]  # type: ignore[index]
    second_output = payload["gate_records"][1]["output_contracts"][0]  # type: ignore[index]
    second_output["artifact_identity"] = first_output["artifact_identity"]
    second_output["writer"] = "MODEL"
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)


def test_cross_gate_output_writer_casefold_collision_is_rejected() -> None:
    payload = _two_gate_payload()
    first_output = payload["gate_records"][0]["output_contracts"][0]  # type: ignore[index]
    second_output = payload["gate_records"][1]["output_contracts"][0]  # type: ignore[index]
    root, path = str(first_output["artifact_identity"]).split(":", 1)
    second_output["artifact_identity"] = f"{root}:{path.upper()}"
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)


def test_block_execution_direction_cannot_remove_or_demote() -> None:
    for forbidden in ("can_remove", "can_lower_severity", "can_add"):
        payload = valid_registry_payload()
        payload["gate_records"][0]["authority"][forbidden] = True  # type: ignore[index]
        with pytest.raises(MechanicalGateRegistryError):
            validate_mechanical_gate_registry(payload)


def test_every_direction_rejects_every_undeclared_boolean_authority() -> None:
    boolean_names = (
        "can_add",
        "can_remove",
        "can_lower_severity",
        "can_raise_severity",
        "can_block_execution",
        "can_execute_target",
        "can_clear_debt",
        "can_veto_ship",
    )
    allowed = {
        "GENERATE_ADD_ONLY": {frozenset({"can_add"})},
        "REOPEN_ADD_ONLY": {frozenset({"can_add"})},
        "RECONCILE_LOSSLESS": {frozenset(), frozenset({"can_add"})},
        "CAP_DESTRUCTIVE": {
            frozenset({"can_remove"}),
            frozenset({"can_lower_severity"}),
            frozenset({"can_remove", "can_lower_severity"}),
        },
        "FLOOR_RECALL_OPEN": {frozenset({"can_raise_severity"})},
        "FLAG_TELEMETRY": {frozenset()},
        "ROUTE_RECALL_OPEN": {frozenset()},
        "CONSOLIDATE_LOSSLESS": {frozenset({"can_remove"})},
        "BLOCK_EXECUTION": {frozenset({"can_block_execution"})},
        "EXECUTE_TARGET": {frozenset({"can_execute_target"})},
        "VETO_SHIP": {frozenset({"can_veto_ship"})},
    }
    decision_class = {
        "GENERATE_ADD_ONLY": "RECALL_GENERATOR",
        "REOPEN_ADD_ONLY": "RECALL_GENERATOR",
        "RECONCILE_LOSSLESS": "PIPELINE_INTEGRITY",
        "CAP_DESTRUCTIVE": "PRECISION_DISCRIMINATOR",
        "FLOOR_RECALL_OPEN": "PRECISION_DISCRIMINATOR",
        "FLAG_TELEMETRY": "TELEMETRY_ONLY",
        "ROUTE_RECALL_OPEN": "PRECISION_DISCRIMINATOR",
        "CONSOLIDATE_LOSSLESS": "PRECISION_DISCRIMINATOR",
        "BLOCK_EXECUTION": "PIPELINE_INTEGRITY",
        "EXECUTE_TARGET": "PIPELINE_INTEGRITY",
        "VETO_SHIP": "PIPELINE_INTEGRITY",
    }
    for direction in DIRECTIONS:
        for mask in range(1 << len(boolean_names)):
            row = copy.deepcopy(
                valid_registry_payload()["gate_records"][0]["authority"]  # type: ignore[index]
            )
            row["direction"] = direction
            row["invalid_authority_fallback"] = (
                "RETAIN_UPSTREAM_AND_FLAG"
                if decision_class[direction] == "PRECISION_DISCRIMINATOR"
                else "BLOCK_TARGET_EXECUTION"
            )
            enabled = frozenset(
                name
                for index, name in enumerate(boolean_names)
                if mask & (1 << index)
            )
            for name in boolean_names:
                row[name] = name in enabled
            if enabled in allowed[direction]:
                _validate_authority(
                    row, "matrix.authority", decision_class[direction]
                )
            else:
                with pytest.raises(MechanicalGateRegistryError):
                    _validate_authority(
                        row, "matrix.authority", decision_class[direction]
                    )


@pytest.mark.parametrize(
    "lifecycle",
    (
        "PROPOSED",
        "FIXTURED",
        "SHADOW",
        "REPLAY",
        "ACTIVE",
        "EXPIRED_BLOCKED",
        "CONSOLIDATED",
        "SUNSET",
    ),
)
def test_legacy_fixture_cannot_be_relabelled_into_any_lifecycle(
    lifecycle: str,
) -> None:
    payload = valid_registry_payload()
    payload["gate_records"][0]["lifecycle_state"] = lifecycle  # type: ignore[index]
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)


def test_legacy_record_cannot_fabricate_review_or_ownership() -> None:
    for mutation in ("review", "ownership"):
        payload = valid_registry_payload()
        gate = payload["gate_records"][0]  # type: ignore[index]
        if mutation == "review":
            gate["review_and_sunset"].update(
                {
                    "transition_review_status": "REVIEWED",
                    "reviewed_at": "2030-01-01T00:00:00Z",
                    "review_receipt_sha256": SHA,
                }
            )
        else:
            gate["ownership"].update(
                {
                    "component_owner": "component",
                    "system_owner": "system",
                    "implementer": "implementer",
                    "independent_reviewer": "reviewer",
                    "assignment_status": "ASSIGNED",
                }
            )
        with pytest.raises(MechanicalGateRegistryError):
            validate_mechanical_gate_registry(payload)


def test_direct_legacy_to_active_and_active_unassessed_are_rejected() -> None:
    payload = valid_registry_payload()
    gate = payload["gate_records"][0]  # type: ignore[index]
    gate["lifecycle_state"] = "ACTIVE"
    gate["review_and_sunset"].update(
        {
            "previous_lifecycle_state": "LEGACY_ACTIVE_UNGOVERNED",
            "transition_review_status": "REVIEWED",
            "reviewed_at": "2030-01-01T00:00:00Z",
            "review_receipt_sha256": SHA,
        }
    )
    gate["ownership"].update(
        {
            "component_owner": "component",
            "system_owner": "system",
            "implementer": "implementer",
            "independent_reviewer": "reviewer",
            "assignment_status": "ASSIGNED",
        }
    )
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)


def test_seam_approval_must_come_from_a_prior_revision() -> None:
    payload = valid_registry_payload()
    budget = payload["seam_budgets"][0]  # type: ignore[index]
    budget.update(
        {
            "approval_status": "APPROVED",
            "gate_budget_ceiling": 1,
            "approval_revision": 1,
            "approver": "system-owner",
        }
    )
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)


def test_seam_approval_from_exact_prior_revision_is_accepted() -> None:
    payload = valid_registry_payload()
    payload["registry_revision"] = 2
    budget = payload["seam_budgets"][0]  # type: ignore[index]
    budget.update(
        {
            "approval_status": "APPROVED",
            "gate_budget_ceiling": 1,
            "approval_revision": 1,
            "approver": "system-owner",
        }
    )
    validate_mechanical_gate_registry(payload)


def test_release_requires_retired_lifecycle_and_independent_recall_authority() -> None:
    payload = valid_registry_payload()
    budget = payload["seam_budgets"][0]  # type: ignore[index]
    budget["release_gate_ids"] = [GATE_ID]
    budget["approved_slot_releases"] = 1
    budget["post_change_gate_count"] = 0
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)


def test_retirement_cannot_bypass_independent_transition_review() -> None:
    payload = valid_registry_payload()
    payload["registry_revision"] = 2
    gate = payload["gate_records"][0]  # type: ignore[index]
    gate["lifecycle_state"] = "SUNSET"
    gate["activations"][0]["runtime_state"] = "NON_RUNTIME"
    gate["review_and_sunset"]["sunset_reason"] = "Retired after parity."
    gate["release_evidence"].update(
        {
            "status": "RECALL_PARITY_ESTABLISHED",
            "recall_parity_receipt_sha256": SHA,
            "system_owner_approval_sha256": SHA,
        }
    )
    budget = payload["seam_budgets"][0]  # type: ignore[index]
    budget.update(
        {
            "approval_status": "APPROVED",
            "gate_budget_ceiling": 1,
            "approval_revision": 1,
            "approver": "system-owner",
            "release_gate_ids": [GATE_ID],
            "approved_slot_releases": 1,
            "post_change_gate_count": 0,
        }
    )
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)


def test_retired_gate_release_requires_and_accepts_independent_authority() -> None:
    payload = valid_registry_payload()
    payload["registry_revision"] = 2
    gate = payload["gate_records"][0]  # type: ignore[index]
    gate["lifecycle_state"] = "SUNSET"
    gate["activations"][0]["runtime_state"] = "NON_RUNTIME"
    gate["review_and_sunset"]["sunset_reason"] = (
        "Independent retirement review completed."
    )
    gate["review_and_sunset"].update(
        {
            "previous_lifecycle_state": "LEGACY_ACTIVE_UNGOVERNED",
            "transition_review_status": "REVIEWED",
            "reviewed_at": "2030-01-01T00:00:00Z",
            "review_receipt_sha256": SHA,
        }
    )
    gate["release_evidence"].update(
        {
            "status": "RECALL_PARITY_ESTABLISHED",
            "recall_parity_receipt_sha256": SHA,
            "system_owner_approval_sha256": SHA,
        }
    )
    budget = payload["seam_budgets"][0]  # type: ignore[index]
    budget.update(
        {
            "approval_status": "APPROVED",
            "gate_budget_ceiling": 1,
            "approval_revision": 1,
            "approver": "system-owner",
            "release_gate_ids": [GATE_ID],
            "approved_slot_releases": 1,
            "post_change_gate_count": 0,
        }
    )
    validate_mechanical_gate_registry(payload)


def test_false_fire_pass_requires_nonzero_neutral_evaluator_authority() -> None:
    payload = valid_registry_payload()
    false_fire = payload["gate_records"][0]["false_fire_budget"]  # type: ignore[index]
    false_fire.update(
        {
            "status": "PASS",
            "held_out_corpus_id": "held-out-corpus",
            "held_out_corpus_sha256": SHA,
            "evaluator_principal": "same-principal",
            "gate_implementer_principal": "same-principal",
            "evaluator_build_sha256": SHA,
            "comparator_sha256": SHA,
            "observation_window_id": "window",
            "minimum_adjudicated_denominator": 0,
            "adjudicated_fire_count": 0,
            "true_fire_count": 0,
            "false_fire_count": 0,
            "maximum_false_fire_count": 0,
            "maximum_false_fire_rate_ppm": 0,
            "current_evidence_receipt_sha256": SHA,
        }
    )
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)


def test_false_fire_pass_uses_exact_neutral_counts_and_rate() -> None:
    payload = valid_registry_payload()
    false_fire = payload["gate_records"][0]["false_fire_budget"]  # type: ignore[index]
    false_fire.update(
        {
            "status": "PASS",
            "held_out_corpus_id": "held-out-corpus",
            "held_out_corpus_sha256": SHA,
            "evaluator_principal": "neutral-evaluator",
            "gate_implementer_principal": "gate-implementer",
            "evaluator_build_sha256": SHA,
            "comparator_sha256": SHA,
            "observation_window_id": "window",
            "minimum_adjudicated_denominator": 10,
            "adjudicated_fire_count": 10,
            "true_fire_count": 9,
            "false_fire_count": 1,
            "maximum_false_fire_count": 1,
            "maximum_false_fire_rate_ppm": 100_000,
            "current_evidence_receipt_sha256": SHA,
        }
    )
    validate_mechanical_gate_registry(payload)
    false_fire["maximum_false_fire_rate_ppm"] = 99_999
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)


@pytest.mark.parametrize(
    ("evaluator", "implementer"),
    (
        ("same-principal", "same-principal "),
        ("same-principal", "Same-Principal"),
        ("same-principal", "same-principal\u0301"),
    ),
)
def test_principal_aliases_cannot_fake_independent_review(
    evaluator: str,
    implementer: str,
) -> None:
    payload = valid_registry_payload()
    false_fire = payload["gate_records"][0]["false_fire_budget"]  # type: ignore[index]
    false_fire.update(
        {
            "status": "PASS",
            "held_out_corpus_id": "held-out-corpus",
            "held_out_corpus_sha256": SHA,
            "evaluator_principal": evaluator,
            "gate_implementer_principal": implementer,
            "evaluator_build_sha256": SHA,
            "comparator_sha256": SHA,
            "observation_window_id": "window",
            "minimum_adjudicated_denominator": 1,
            "adjudicated_fire_count": 1,
            "true_fire_count": 1,
            "false_fire_count": 0,
            "maximum_false_fire_count": 0,
            "maximum_false_fire_rate_ppm": 0,
            "current_evidence_receipt_sha256": SHA,
        }
    )
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)


@pytest.mark.parametrize(
    ("authority", "field", "value"),
    (
        ("COMMON_RECEIPT", "writer", "MODEL"),
        ("COMMON_RECEIPT", "artifact_class", "OPTIONAL"),
        ("COMMON_RECEIPT", "write_mode", "REPLACE"),
        ("GOVERNANCE_DEBT", "writer", "MODEL"),
        ("OVERFLOW_BACKLOG", "write_mode", "APPEND"),
    ),
)
def test_common_phaseio_outputs_have_exact_authority_semantics(
    authority: str,
    field: str,
    value: str,
) -> None:
    payload = valid_registry_payload()
    outputs = payload["gate_records"][0]["output_contracts"]  # type: ignore[index]
    row = next(
        item for item in outputs
        if item["authority_carried"] == authority
    )
    row[field] = value
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)


def test_phaseio_work_units_bind_selectors_and_have_one_gate_owner() -> None:
    payload = valid_registry_payload()
    outputs = payload["gate_records"][0]["output_contracts"]  # type: ignore[index]
    for row in outputs:
        row["phase_io_work_unit_id"] = (
            "l1/light/daml/codex/report/unrelated.unit"
        )
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)

    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(_two_gate_payload())


def test_fixture_migration_block_forbids_self_asserted_shadow_baseline() -> None:
    payload = valid_registry_payload()
    gate = payload["gate_records"][0]  # type: ignore[index]
    gate["lifecycle_state"] = "SHADOW"
    gate["admission"].update(
        {
            "status": "EVIDENCE_COMPLETE",
            "evidence_receipt_sha256": SHA,
        }
    )
    gate["ownership"].update(
        {
            "component_owner": "component",
            "system_owner": "system",
            "implementer": "implementer",
            "independent_reviewer": "reviewer",
            "assignment_status": "ASSIGNED",
        }
    )
    gate["review_and_sunset"].update(
        {
            "previous_lifecycle_state": "FIXTURED",
            "transition_review_status": "REVIEWED",
            "reviewed_at": "2030-01-01T00:00:00Z",
            "review_receipt_sha256": SHA,
        }
    )
    with pytest.raises(MechanicalGateRegistryError, match="transitions"):
        validate_mechanical_gate_registry(payload)


@pytest.mark.parametrize(
    ("container", "field"),
    (
        (None, "display_name"),
        (None, "purpose"),
        ("authority", "monotonicity_claim"),
        ("authority", "join_rule"),
        ("input_contracts", "freshness_rule"),
        ("overlap_and_consolidation", "unique_authority"),
        ("overlap_and_consolidation", "retirement_criteria"),
        ("part0", "generic_subject"),
    ),
)
def test_part0_scans_every_free_text_metadata_channel(
    container: str | None,
    field: str,
) -> None:
    payload = valid_registry_payload()
    gate = payload["gate_records"][0]  # type: ignore[index]
    value = "Recover ExampleProtocol H-01 at contracts/Vault.sol:42"
    if container is None:
        gate[field] = value
    elif container == "input_contracts":
        gate[container][0][field] = value
    else:
        gate[container][field] = value
    with pytest.raises(MechanicalGateRegistryError):
        validate_mechanical_gate_registry(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("target_names", ["ExampleProtocol"]),
        ("finding_ids", ["H-01"]),
        ("target_locations", ["contracts/Vault.sol:42"]),
        ("motivating_answers", ["the expected vulnerable answer"]),
    ),
)
def test_part0_explicit_protocol_answer_channels_must_be_empty(
    field: str, value: list[str]
) -> None:
    payload = valid_registry_payload()
    payload["gate_records"][0]["part0"][field] = value  # type: ignore[index]
    with pytest.raises(MechanicalGateRegistryError):
        validate_part0_metadata(payload)


def test_part0_rejects_finding_ids_and_absolute_paths_in_prose() -> None:
    payload = valid_registry_payload()
    payload["gate_records"][0]["purpose"] = (  # type: ignore[index]
        "Recover H-01 from C:\\private\\target\\Vault.sol."
    )
    with pytest.raises(MechanicalGateRegistryError):
        validate_part0_metadata(payload)


def test_part0_rejects_source_style_snake_case_names_in_free_prose() -> None:
    payload = valid_registry_payload()
    payload["gate_records"][0]["purpose"] = (  # type: ignore[index]
        "Inspect vulnerable_token_vault behavior."
    )
    with pytest.raises(
        MechanicalGateRegistryError,
        match="source-style target-specific name",
    ):
        validate_part0_metadata(payload)

    # Machine-owned symbol fields remain usable; the prohibition is scoped
    # to human-authored methodology prose rather than all underscores.
    validate_part0_metadata(valid_registry_payload())
