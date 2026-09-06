from __future__ import annotations

import json
from pathlib import Path
import sys
import uuid

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

from artifact_ledger import (  # noqa: E402
    read_artifact_ledger,
    record_work_unit_inputs,
)
from external_preimage_authority import (  # noqa: E402
    AXIS_INVENTORY_POLICY_DIGEST,
    AXIS_INVENTORY_VALIDATOR_ID,
    ExternalPreimageValidationError,
    POLICY_DIGEST,
    derive_external_preimage_receipt,
    validate_external_preimage_receipt_integrity,
)
import inventory_id_ledger_merge as M  # noqa: E402
from phase_io_contracts import (  # noqa: E402
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
    resolve_phase_io_contract,
)
from plamen_parsers import _title_hash  # noqa: E402


def _allocation(fid: str = "INV-001", title: str = "candidate") -> dict:
    return {
        "id": fid,
        "prefix": fid.rsplit("-", 1)[0] + "-",
        "owner_phase": "inventory",
        "owner_attempt": 1,
        "owning_artifact": "findings_inventory.md",
        "title_hash": _title_hash(title),
        "title_preview": title,
        "allocated_at": "1970-01-01T00:00:00+00:00",
    }


def _ledger_bytes(rows: list[dict]) -> bytes:
    return (
        json.dumps(
            {
                "schema_version": "plamen.id_ledger.v1",
                "allocations": rows,
            },
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


def _external_receipt(raw: bytes) -> dict:
    return derive_external_preimage_receipt(
        validator_id="plamen.strict_id_ledger.v1",
        work_unit_key=(
            "sc/thorough/evm/claude/inventory/id_ledger_merge"
        ),
        contract_digest="a" * 64,
        artifact_identity="scratchpad:_id_ledger.json",
        raw=raw,
        existed=True,
    )


def _axis_inventory_receipt(raw: bytes) -> dict:
    return derive_external_preimage_receipt(
        validator_id=AXIS_INVENTORY_VALIDATOR_ID,
        work_unit_key=(
            "sc/thorough/evm/claude/axis_disposition/promotion"
        ),
        contract_digest="b" * 64,
        artifact_identity="scratchpad:findings_inventory.md",
        raw=raw,
        existed=True,
    )


def test_default_external_validator_omission_preserves_manifest_shape() -> None:
    owner = canonical_work_unit_key(
        "sc", "core", "evm", "claude", "inventory", "fixture"
    )
    spec = ArtifactSpec(
        root="scratchpad",
        path="fixture.json",
        owner_key=owner,
        artifact_class="DRIVER_GENERATED",
        writer="DRIVER",
        write_mode="MERGE",
    )

    assert spec.external_preimage_validator == ""
    assert "external_preimage_validator" not in spec.to_dict()


@pytest.mark.parametrize(
    "writer,write_mode",
    [("MODEL", "REPLACE"), ("DRIVER", "REPLACE"), ("MODEL", "MERGE")],
)
def test_external_validator_declaration_requires_driver_merge(
    writer: str,
    write_mode: str,
) -> None:
    owner = canonical_work_unit_key(
        "sc", "core", "evm", "claude", "inventory", "fixture"
    )
    with pytest.raises(ValueError):
        ArtifactSpec(
            root="scratchpad",
            path="fixture.json",
            owner_key=owner,
            artifact_class=(
                "REQUIRED" if writer == "MODEL" else "DRIVER_GENERATED"
            ),
            writer=writer,
            write_mode=write_mode,
            external_preimage_validator="plamen.strict_id_ledger.v1",
        )


def test_other_unowned_merge_output_remains_input_debt(tmp_path: Path) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    (scratch / "unowned.json").write_text('{"rows":[]}\n', encoding="utf-8")
    owner = canonical_work_unit_key(
        "sc", "core", "evm", "claude", "inventory", "fixture"
    )
    contract = PhaseIOContract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="claude",
        phase="inventory",
        work_unit_id="fixture",
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path="unowned.json",
                owner_key=owner,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="MERGE",
            ),
        ),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="claude",
        model="driver",
        timeout_s=10,
        exec_mode="python",
        tool_policy=("filesystem",),
    )

    unit = record_work_unit_inputs(
        scratch, project, contract, launch, run_id=str(uuid.uuid4())
    )

    assert unit["semantic_status"] == "INPUT_DEBT"
    assert unit["output_prestates"]["scratchpad:unowned.json"][
        "status"
    ] == "UNOWNED_EXISTING_OUTPUT"
    assert "scratchpad:unowned.json" not in read_artifact_ledger(scratch)[
        "artifact_bindings"
    ]


def test_valid_external_preimage_is_prestate_only_not_global_owner(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    for name in (
        "inventory_aggregate_derivation.json",
        "inventory_id_allocation_delta.json",
        "findings_inventory.md",
        "finding_records.json",
    ):
        (scratch / name).write_text(f"{name}\n", encoding="utf-8")
    ledger_path = scratch / "_id_ledger.json"
    ledger_path.write_bytes(_ledger_bytes([_allocation()]))
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="inventory",
        work_unit_id="id_ledger_merge",
        exact_inputs=(
            "inventory_aggregate_derivation.json",
            "inventory_id_allocation_delta.json",
            "findings_inventory.md",
            "finding_records.json",
        ),
        exact_outputs=(
            "_id_ledger.json",
            "inventory_id_ledger_merge_receipt.json",
        ),
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        model="driver",
        timeout_s=10,
        exec_mode="python",
        tool_policy=("filesystem",),
    )

    unit = record_work_unit_inputs(
        scratch, project, contract, launch, run_id=str(uuid.uuid4())
    )

    prestate = unit["output_prestates"]["scratchpad:_id_ledger.json"]
    assert unit["semantic_status"] == "INPUTS_BOUND"
    assert prestate["status"] == "VALIDATED_EXTERNAL_PREIMAGE"
    receipt = prestate["external_preimage_receipt"]
    assert receipt["validator_policy_digest"] == POLICY_DIGEST
    assert receipt["parsed_identities"] == ["INV-001"]
    assert receipt["authority_scope"] == "SCHEMA_IDENTITY_PRESERVE_ONLY"
    assert "scratchpad:_id_ledger.json" not in read_artifact_ledger(scratch)[
        "artifact_bindings"
    ]


@pytest.mark.parametrize(
    "mutator",
    [
        lambda row: row.update(prefix="I-"),
        lambda row: row.update(id="inv-001"),
        lambda row: row.pop("owner_phase"),
        lambda row: row.update(extra="forged"),
    ],
)
def test_strict_external_validator_rejects_noncanonical_allocation(
    mutator,
) -> None:
    row = _allocation()
    mutator(row)
    with pytest.raises(ExternalPreimageValidationError):
        _external_receipt(_ledger_bytes([row]))


def test_strict_external_validator_rejects_duplicate_ids_and_keys() -> None:
    row = _allocation()
    with pytest.raises(ExternalPreimageValidationError):
        _external_receipt(_ledger_bytes([row, dict(row)]))
    duplicate_key = (
        b'{"schema_version":"plamen.id_ledger.v1",'
        b'"schema_version":"plamen.id_ledger.v1","allocations":[]}\n'
    )
    with pytest.raises(ExternalPreimageValidationError):
        _external_receipt(duplicate_key)


@pytest.mark.parametrize(
    "field,value",
    [
        ("owner_phase", 1),
        ("owning_artifact", ["findings_inventory.md"]),
        ("title_preview", 7),
        ("allocated_at", {"timestamp": "now"}),
    ],
)
def test_allocation_schema_rejects_string_coercion(
    field: str,
    value,
) -> None:
    row = _allocation()
    row[field] = value
    with pytest.raises(ExternalPreimageValidationError):
        _external_receipt(_ledger_bytes([row]))
    with pytest.raises(M.InventoryIDLedgerMergeError):
        M.build_inventory_allocation_delta(
            run_id="run",
            inventory_sha256="1" * 64,
            records_sha256="2" * 64,
            allocations=[row],
        )


def test_strict_external_validator_accepts_full_title_hash_with_truncated_preview(
) -> None:
    title = "long canonical title " + ("x" * 180)
    row = _allocation(title=title)
    row["title_preview"] = title[:120]

    receipt = _external_receipt(_ledger_bytes([row]))

    assert receipt["parsed_identities"] == ["INV-001"]
    assert receipt["row_fingerprints"][0]["id"] == "INV-001"


def test_external_receipt_tamper_and_validator_id_drift_are_rejected() -> None:
    receipt = _external_receipt(_ledger_bytes([_allocation()]))
    forged = dict(receipt)
    forged["parsed_identities"] = []
    with pytest.raises(ExternalPreimageValidationError):
        validate_external_preimage_receipt_integrity(forged)
    with pytest.raises(ExternalPreimageValidationError):
        derive_external_preimage_receipt(
            validator_id="plamen.strict_id_ledger.v2",
            work_unit_key=receipt["work_unit_key"],
            contract_digest=receipt["contract_digest"],
            artifact_identity=receipt["artifact_identity"],
            raw=_ledger_bytes([_allocation()]),
            existed=True,
        )


def test_axis_inventory_preimage_accepts_only_operational_canonical_ids() -> None:
    raw = (
        "# Findings Inventory\n\n"
        "```markdown\n"
        "### Finding [INV-999]: fenced example\n"
        "```\n\n"
        "### Finding [INV-001]: First candidate\n"
        "**Verdict**: NEEDS_VERIFICATION\n\n"
        "### Finding [INV-002]: Second candidate\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
    ).encode("utf-8")

    receipt = _axis_inventory_receipt(raw)

    assert receipt["validator_policy_digest"] == AXIS_INVENTORY_POLICY_DIGEST
    assert receipt["parsed_identities"] == ["INV-001", "INV-002"]
    assert [row["id"] for row in receipt["row_fingerprints"]] == [
        "INV-001",
        "INV-002",
    ]
    validate_external_preimage_receipt_integrity(receipt)


@pytest.mark.parametrize(
    "body",
    [
        (
            "### Finding [INV-001]: one\n"
            "### Finding [INV-001]: duplicate\n"
        ),
        "### Finding [inv-001]: lowercase\n",
        "### Finding [H-01]: wrong namespace\n",
        "### Finding INV-001: missing brackets\n",
        "### Finding [INV-001]:   \n",
    ],
)
def test_axis_inventory_preimage_rejects_ambiguous_finding_identity(
    body: str,
) -> None:
    with pytest.raises(ExternalPreimageValidationError):
        _axis_inventory_receipt(body.encode("utf-8"))


def test_axis_inventory_validator_is_path_bound_and_tamper_evident() -> None:
    raw = b"# Findings Inventory\n\nNo candidates yet.\n"
    receipt = _axis_inventory_receipt(raw)
    forged = dict(receipt)
    forged["validator_policy_digest"] = POLICY_DIGEST
    with pytest.raises(ExternalPreimageValidationError):
        validate_external_preimage_receipt_integrity(forged)
    with pytest.raises(ExternalPreimageValidationError):
        derive_external_preimage_receipt(
            validator_id=AXIS_INVENTORY_VALIDATOR_ID,
            work_unit_key=receipt["work_unit_key"],
            contract_digest=receipt["contract_digest"],
            artifact_identity="scratchpad:other.md",
            raw=raw,
            existed=True,
        )


def _delta() -> dict:
    return M.build_inventory_allocation_delta(
        run_id="run",
        inventory_sha256="1" * 64,
        records_sha256="2" * 64,
        allocations=[_allocation()],
    )


@pytest.mark.parametrize(
    "mutator",
    [
        lambda row: row["after_ids"].clear(),
        lambda row: row["added_ids"].clear(),
        lambda row: row.update(status="UNKNOWN"),
        lambda row: row.update(preexisting_authority="FORGED"),
        lambda row: row.update(
            status="IDENTITY_COLLISION_DEBT",
            issues=["collision"],
        ),
    ],
)
def test_merge_receipt_rejects_forged_status_or_identity_algebra(mutator) -> None:
    delta = _delta()
    receipt = M.build_inventory_id_ledger_merge_receipt(
        delta=delta,
        before_raw=None,
        preexisting_typed=False,
    )
    mutator(receipt)
    receipt["receipt_digest"] = M._digest(receipt, "receipt_digest")
    with pytest.raises(M.InventoryIDLedgerMergeError):
        M.validate_inventory_id_ledger_merge_receipt(
            receipt, delta=delta
        )


@pytest.mark.parametrize("target", ["prior", "new"])
def test_merge_receipt_rederivation_rejects_mutated_successor_rows(
    target: str,
) -> None:
    delta = _delta()
    before = _ledger_bytes([_allocation("GRP-009", "legacy")])
    receipt = M.build_inventory_id_ledger_merge_receipt(
        delta=delta,
        before_raw=before,
        preexisting_typed=False,
    )
    successor = json.loads(receipt["successor_payload"])
    row = next(
        item
        for item in successor["allocations"]
        if item["id"] == ("GRP-009" if target == "prior" else "INV-001")
    )
    row["owner_phase"] = "tampered"
    raw = (
        json.dumps(successor, ensure_ascii=False, sort_keys=True, indent=2)
        + "\n"
    ).encode("utf-8")
    receipt["successor_payload"] = raw.decode("utf-8")
    receipt["after_sha256"] = __import__("hashlib").sha256(raw).hexdigest()
    receipt["receipt_digest"] = M._digest(receipt, "receipt_digest")

    with pytest.raises(M.InventoryIDLedgerMergeError, match="re-derivation"):
        M.validate_inventory_id_ledger_merge_receipt(
            receipt, delta=delta
        )


def test_merge_receipt_requires_exact_compatible_intersection() -> None:
    delta = _delta()
    before = _ledger_bytes([_allocation()])
    receipt = M.build_inventory_id_ledger_merge_receipt(
        delta=delta,
        before_raw=before,
        preexisting_typed=False,
    )
    assert receipt["compatible_reuse_ids"] == ["INV-001"]
    receipt["compatible_reuse_ids"] = []
    receipt["receipt_digest"] = M._digest(receipt, "receipt_digest")

    with pytest.raises(M.InventoryIDLedgerMergeError, match="re-derivation"):
        M.validate_inventory_id_ledger_merge_receipt(
            receipt, delta=delta
        )
