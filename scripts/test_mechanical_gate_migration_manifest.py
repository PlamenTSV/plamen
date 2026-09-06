from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from mechanical_gate_migration_manifest import (
    EDIT_MANIFEST_PATH,
    EXPECTED_FORENSIC_IDS,
    EXPECTED_GATE_IDS,
    INVENTORY_PATH,
    MechanicalGateMigrationError,
    REGISTRY_PATH,
    SCHEMA_PATHS,
    validate_provisional_program,
)


ROOT = Path(__file__).resolve().parent.parent


def _copy_program(tmp_path: Path) -> Path:
    for relative in (
        REGISTRY_PATH,
        INVENTORY_PATH,
        EDIT_MANIFEST_PATH,
        *SCHEMA_PATHS,
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())
    return tmp_path


def _load(root: Path, relative: Path) -> dict:
    return json.loads((root / relative).read_text(encoding="utf-8"))


def _write(root: Path, relative: Path, value: dict) -> None:
    (root / relative).write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def test_archived_provisional_program_remains_internally_byte_bound() -> None:
    # The provisional manifest is forensic migration evidence, not current
    # source authority after the canonical Stage-1 registry is generated.
    receipt = validate_provisional_program(ROOT, validate_source=False)
    assert receipt["valid"] is True
    assert receipt["gate_count"] == 33
    assert receipt["activation_count"] == 33
    assert len(receipt["artifact_sha256"]) == 6


def test_exact_forensic_identity_order_and_cross_artifact_linkage() -> None:
    registry = _load(ROOT, REGISTRY_PATH)
    inventory = _load(ROOT, INVENTORY_PATH)
    edits = _load(ROOT, EDIT_MANIFEST_PATH)
    assert tuple(row["forensic_id"] for row in registry["gate_records"]) == (
        EXPECTED_FORENSIC_IDS
    )
    assert tuple(row["gate_id"] for row in registry["gate_records"]) == (
        EXPECTED_GATE_IDS
    )
    assert tuple(row["gate_id"] for row in inventory["activations"]) == (
        EXPECTED_GATE_IDS
    )
    assert tuple(row["gate_id"] for row in edits["edit_entries"]) == (
        EXPECTED_GATE_IDS
    )


def test_provisional_program_never_grants_or_invents_authority() -> None:
    registry = _load(ROOT, REGISTRY_PATH)
    assert registry["runtime_authority_granted"] is False
    assert registry["independent_review_receipt_sha256"] is None
    for row in registry["gate_records"]:
        assert row["candidate_lifecycle_state"] == "LEGACY_ACTIVE_UNGOVERNED"
        assert row["component_owner"] is None
        assert row["system_owner"] is None
        assert row["independent_reviewer"] is None
        assert row["admission_evidence_receipt_sha256"] is None


def test_all_legacy_activations_remain_literal_registration_debt() -> None:
    inventory = _load(ROOT, INVENTORY_PATH)
    edits = _load(ROOT, EDIT_MANIFEST_PATH)
    assert all(
        row["literal_runtime_registration_present"] is False
        for row in inventory["activations"]
    )
    assert all(
        "LITERAL_RUNTIME_REGISTRATION_ABSENT"
        in row["migration_debt_codes"]
        for row in edits["edit_entries"]
    )


@pytest.mark.parametrize(
    ("relative", "mutator"),
    (
        (
            REGISTRY_PATH,
            lambda value: value.__setitem__(
                "runtime_authority_granted", True
            ),
        ),
        (
            REGISTRY_PATH,
            lambda value: value["gate_records"][0].__setitem__(
                "component_owner", "self-asserted"
            ),
        ),
        (
            INVENTORY_PATH,
            lambda value: value["activations"][0].__setitem__(
                "literal_runtime_registration_present", True
            ),
        ),
        (
            EDIT_MANIFEST_PATH,
            lambda value: value["edit_entries"][0].__setitem__(
                "existing_code_edit_authorized", True
            ),
        ),
        (
            EDIT_MANIFEST_PATH,
            lambda value: value["edit_entries"][0][
                "migration_debt_codes"
            ].remove("LITERAL_RUNTIME_REGISTRATION_ABSENT"),
        ),
    ),
)
def test_authority_self_promotion_and_debt_erasure_fail_closed(
    tmp_path: Path,
    relative: Path,
    mutator,
) -> None:
    root = _copy_program(tmp_path)
    value = _load(root, relative)
    mutator(value)
    _write(root, relative, value)
    with pytest.raises(MechanicalGateMigrationError):
        validate_provisional_program(root, validate_source=False)


def test_cross_artifact_activation_drift_fails_closed(tmp_path: Path) -> None:
    root = _copy_program(tmp_path)
    inventory = _load(root, INVENTORY_PATH)
    inventory["activations"][0]["activation_id"] += ".drift"
    _write(root, INVENTORY_PATH, inventory)
    with pytest.raises(MechanicalGateMigrationError):
        validate_provisional_program(root, validate_source=False)


def test_absent_phaseio_cannot_invent_owner_or_artifact(
    tmp_path: Path,
) -> None:
    root = _copy_program(tmp_path)
    edits = _load(root, EDIT_MANIFEST_PATH)
    binding = edits["edit_entries"][0]["phase_io_binding"]
    binding["owner_key_binding"] = (
        "phase_io_contracts.canonical_work_unit_key(runtime_context)"
    )
    binding["output_artifact_identities"] = [
        "scratchpad:invented.json"
    ]
    _write(root, EDIT_MANIFEST_PATH, edits)
    with pytest.raises(MechanicalGateMigrationError):
        validate_provisional_program(root, validate_source=False)


def test_duplicate_gate_identity_fails_closed(tmp_path: Path) -> None:
    root = _copy_program(tmp_path)
    registry = _load(root, REGISTRY_PATH)
    duplicate = copy.deepcopy(registry["gate_records"][0])
    registry["gate_records"][1] = duplicate
    _write(root, REGISTRY_PATH, registry)
    with pytest.raises(MechanicalGateMigrationError):
        validate_provisional_program(root, validate_source=False)


def test_schema_files_are_closed_and_non_authoritative() -> None:
    for relative in SCHEMA_PATHS:
        schema = json.loads((ROOT / relative).read_text(encoding="utf-8"))
        assert schema["$schema"].endswith("2020-12/schema")
        assert schema["additionalProperties"] is False
        assert schema["properties"]["runtime_authority_granted"] == {
            "const": False
        }
