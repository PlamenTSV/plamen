"""Exact co-root predicate for the preverify frozen capture pair."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import PurePosixPath
from typing import Any, Mapping

import pytest

from artifact_ledger import read_artifact_ledger
from phase_io_contracts import resolve_phase_io_contract
from preverify_projection_authority import (
    PreverifyProjectionAuthorityError,
    resolve_current_preverify_projection,
    resolve_exact_frozen_capture_authority,
    validate_frozen_projection_receipt,
)
import plamen_driver as D
import test_preverify_frozen_projection as FROZEN_FIXTURE
import test_preverify_inventory_successor_p0_al as SUCCESSOR_FIXTURE


GENERATION = "a" * 64
FROZEN = f"_preverify_frozen/generation_{GENERATION}"
OUTPUT = f"_preverify_successors/generation_{GENERATION}.json"


def _resolve(inputs: tuple[str, ...]):
    return resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="sc_verify_queue",
        work_unit_id=f"preverify_capture.{GENERATION}",
        exact_inputs=inputs,
        exact_outputs=(OUTPUT,),
    )


def test_one_physical_frozen_triple_is_accepted() -> None:
    contract = _resolve((
        f"{FROZEN}/findings_inventory.md",
        f"{FROZEN}/finding_records.json",
        f"{FROZEN}/receipt.json",
        "project::src/Vault.sol",
        "_semantic_mutations.json",
    ))
    inputs = set(contract.immutable_inputs)
    assert f"scratchpad:{FROZEN}/findings_inventory.md" in inputs
    assert f"scratchpad:{FROZEN}/finding_records.json" in inputs
    assert f"scratchpad:{FROZEN}/receipt.json" in inputs


@pytest.mark.parametrize(
    "inputs",
    (
        (
            "findings_inventory.md",
            "finding_records.json",
        ),
        (
            "project::findings_inventory.md",
            "project::finding_records.json",
        ),
        (
            f"{FROZEN}/findings_inventory.md",
            f"_preverify_frozen/generation_{'b' * 64}/finding_records.json",
            f"{FROZEN}/receipt.json",
        ),
        (
            f"{FROZEN}/findings_inventory.md",
            f"{FROZEN}/finding_records.json",
            f"{FROZEN}/receipt.json",
            f"_preverify_frozen/generation_{'b' * 64}/findings_inventory.md",
            f"_preverify_frozen/generation_{'b' * 64}/finding_records.json",
            f"_preverify_frozen/generation_{'b' * 64}/receipt.json",
        ),
    ),
    ids=(
        "canonical-scratchpad-is-not-frozen-authority",
        "project-files-are-not-frozen-authority",
        "mixed-generations",
        "duplicate-generations",
    ),
)
def test_non_exact_or_non_coroot_pair_is_rejected(
    inputs: tuple[str, ...],
) -> None:
    with pytest.raises(ValueError):
        _resolve(inputs)


def _live_authority_fixture(tmp_path):
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    config = SUCCESSOR_FIXTURE._config(project, root)
    run_id = config["_run_id"]
    SUCCESSOR_FIXTURE._seed(root)
    SUCCESSOR_FIXTURE._claim_seed_authority(root, config)
    frozen = FROZEN_FIXTURE._prepare(
        root, project, config, run_id
    )
    assert D._finalize_preverify_inventory_successors(
        root,
        config,
        phase_name="sc_verify_queue",
        frozen_projection=frozen,
    ) == []
    execute, routing_issues = (
        D._arm_typed_verify_queue_routing_artifacts(
            "sc_verify_queue",
            root,
            config,
        )
    )
    assert execute is True
    assert routing_issues == []
    ledger = read_artifact_ledger(root)
    captures = [
        unit
        for key, unit in ledger["work_units"].items()
        if "/sc_verify_queue/preverify_capture." in key
    ]
    assert len(captures) == 1
    return (
        root,
        config,
        run_id,
        frozen,
        ledger,
        captures[0]["input_bindings"],
    )


def test_live_bare_id_capture_commits_but_routing_remains_fail_closed(
    tmp_path,
) -> None:
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    config = SUCCESSOR_FIXTURE._config(project, root)
    run_id = config["_run_id"]
    _scan, delivery = SUCCESSOR_FIXTURE._seed(
        root,
        inventory_text=SUCCESSOR_FIXTURE._bare_id_inventory(),
    )
    assert delivery["status"] == "DEGRADED"
    assert delivery["residual_debt_count"] == 1
    assert [row["disposition"] for row in delivery["actions"]] == [
        "RESIDUAL_DEBT"
    ]
    SUCCESSOR_FIXTURE._claim_seed_authority(root, config)
    frozen = FROZEN_FIXTURE._prepare(
        root, project, config, run_id
    )
    assert D._finalize_preverify_inventory_successors(
        root,
        config,
        phase_name="sc_verify_queue",
        frozen_projection=frozen,
    ) == []

    ledger = read_artifact_ledger(root)
    capture_keys = [
        key
        for key in ledger["work_units"]
        if "/sc_verify_queue/preverify_capture." in key
    ]
    assert len(capture_keys) == 1
    capture = ledger["work_units"][capture_keys[0]]
    assert capture["execution_state"] == "OUTPUT_COMMITTED"
    assert capture["semantic_status"] == "ACTIVE"
    assert capture["commit_authority"]["state"] == "ACTIVE"
    assert capture["launch_manifest"]["timeout_s"] == 120

    execute, routing_issues = (
        D._arm_typed_verify_queue_routing_artifacts(
            "sc_verify_queue",
            root,
            config,
        )
    )
    detail = (
        "depth_consensus_invariant_findings.md:DCI-1: content-bearing "
        "registered action has no inventory referent or review disposition"
    )
    assert execute is False
    assert routing_issues == [
        "queue refused non-current registered-delivery authority: "
        "registered finding delivery has residual parser/delivery debt: "
        + detail
    ]
    post = read_artifact_ledger(root)
    assert post["work_units"][capture_keys[0]] == capture
    assert not [
        key
        for key in post["work_units"]
        if key.endswith("/sc_verify_queue/routing")
    ]


def _canonical_digest(value) -> str:
    return hashlib.sha256(
        (
            json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    ).hexdigest()


def _frozen_projection_producer(
    bindings: Mapping[str, Any],
) -> tuple[str, Mapping[str, Any]]:
    matches = [
        (identity, row)
        for identity, row in bindings.items()
        if (
            str(identity).startswith(
                "scratchpad:_preverify_frozen/generation_"
            )
            and str(identity).endswith("/findings_inventory.md")
            and isinstance(row, Mapping)
        )
    ]
    assert len(matches) == 1
    return matches[0]


def test_shared_authority_rejects_canonical_or_decoy_source_projection(
    tmp_path,
) -> None:
    _root, _config, run_id, frozen, ledger, bindings = (
        _live_authority_fixture(tmp_path)
    )
    frozen_root = PurePosixPath(
        str(frozen["receipt_path"])
    ).parent.as_posix()
    canonical = {
        **bindings,
        "scratchpad:findings_inventory.md": {
            "identity": "scratchpad:findings_inventory.md",
            "status": "ACTIVE",
        },
    }
    with pytest.raises(
        PreverifyProjectionAuthorityError,
        match="canonical logical",
    ):
        resolve_exact_frozen_capture_authority(
            input_bindings=canonical,
            ledger=ledger,
            run_id=run_id,
        )
    with pytest.raises(
        PreverifyProjectionAuthorityError,
        match="inventory source",
    ):
        resolve_exact_frozen_capture_authority(
            input_bindings=bindings,
            ledger=ledger,
            run_id=run_id,
            inventory_source="findings_inventory.md",
            records_source=f"{frozen_root}/finding_records.json",
        )


def test_shared_authority_rejects_duplicate_root_and_contract_drift(
    tmp_path,
) -> None:
    _root, _config, run_id, _frozen, ledger, bindings = (
        _live_authority_fixture(tmp_path)
    )
    other_identity = (
        "scratchpad:_preverify_frozen/generation_"
        + "b" * 64
        + "/findings_inventory.md"
    )
    _frozen_identity, frozen_row = _frozen_projection_producer(bindings)
    other_row = deepcopy(frozen_row)
    other_row["identity"] = other_identity
    with pytest.raises(
        PreverifyProjectionAuthorityError,
        match="exactly one",
    ):
        resolve_exact_frozen_capture_authority(
            input_bindings={**bindings, other_identity: other_row},
            ledger=ledger,
            run_id=run_id,
        )
    drifted = deepcopy(ledger)
    _identity, binding = _frozen_projection_producer(bindings)
    producer = str(binding["producer_work_unit_key"])
    drifted["work_units"][producer]["contract_digest"] = "e" * 64
    with pytest.raises(
        PreverifyProjectionAuthorityError,
        match="producer",
    ):
        resolve_exact_frozen_capture_authority(
            input_bindings=bindings,
            ledger=drifted,
            run_id=run_id,
        )


@pytest.mark.parametrize(
    "mutation",
    ("empty-artifacts", "duplicate-manifest-output"),
)
def test_shared_authority_replays_producer_commit_denominator(
    tmp_path,
    mutation: str,
) -> None:
    _root, _config, run_id, _frozen, ledger, bindings = (
        _live_authority_fixture(tmp_path)
    )
    forged = deepcopy(ledger)
    _identity, binding = _frozen_projection_producer(bindings)
    producer = str(binding["producer_work_unit_key"])
    unit = forged["work_units"][producer]
    if mutation == "empty-artifacts":
        unit["artifacts"] = {
            identity: {}
            for identity in unit["artifacts"]
        }
    else:
        unit["contract_manifest"]["outputs"].append(
            deepcopy(unit["contract_manifest"]["outputs"][0])
        )
    with pytest.raises(
        PreverifyProjectionAuthorityError,
        match="producer",
    ):
        resolve_exact_frozen_capture_authority(
            input_bindings=bindings,
            ledger=forged,
            run_id=run_id,
        )


@pytest.mark.parametrize(
    "case",
    (
        "canonical-only",
        "full-root-plus-extra-before",
        "full-root-plus-extra-after",
        "two-roots",
    ),
)
def test_driver_capture_boundary_rejects_legacy_or_duplicate_denominator(
    tmp_path,
    case: str,
) -> None:
    root, config, run_id, _frozen, ledger, bindings = (
        _live_authority_fixture(tmp_path)
    )
    capture_key, capture_unit = next(
        (key, unit)
        for key, unit in ledger["work_units"].items()
        if "/sc_verify_queue/preverify_capture." in key
    )
    generation = capture_key.rsplit(".", 1)[-1]
    generation_identity = next(iter(capture_unit["artifacts"]))
    generation_name = generation_identity.removeprefix("scratchpad:")
    raw_inputs = tuple(
        (
            "project::" + identity.removeprefix("project:")
            if identity.startswith("project:")
            else identity.removeprefix("scratchpad:")
        )
        for identity in bindings
    )
    base_contract, _launch = D._preverify_capture_contract_and_launch(
        "sc_verify_queue",
        config,
        generation_name=generation_name,
        generation_digest=generation,
        exact_inputs=raw_inputs,
    )
    other_root = f"_preverify_frozen/generation_{'b' * 64}"
    extra = f"scratchpad:{other_root}/findings_inventory.md"
    if case == "canonical-only":
        exact_inputs = (
            "scratchpad:findings_inventory.md",
            "scratchpad:finding_records.json",
        )
    elif case == "full-root-plus-extra-before":
        exact_inputs = (extra, *base_contract.immutable_inputs)
    elif case == "full-root-plus-extra-after":
        exact_inputs = (*base_contract.immutable_inputs, extra)
    else:
        exact_inputs = (
            *base_contract.immutable_inputs,
            f"scratchpad:{other_root}/finding_records.json",
            f"scratchpad:{other_root}/receipt.json",
            extra,
        )
    contract = replace(
        base_contract,
        immutable_inputs=tuple(exact_inputs),
    )

    issues = D._preverify_capture_input_authority_issues(
        root,
        contract,
        run_id=run_id,
    )

    assert issues
    assert any(
        token in " ".join(issues).lower()
        for token in ("canonical", "exactly one", "binding is absent")
    )


def test_receipt_validator_rejects_rehashed_false_nested_byte_claims(
    tmp_path,
) -> None:
    root, _config, run_id, frozen, ledger, bindings = (
        _live_authority_fixture(tmp_path)
    )
    physical = frozen["logical_to_physical"]
    inventory_path = str(physical["findings_inventory.md"])
    records_path = str(physical["finding_records.json"])
    evidence_path = str(
        physical.get("inventory_evidence_validation.md") or ""
    )
    authority = resolve_exact_frozen_capture_authority(
        input_bindings=bindings,
        ledger=ledger,
        run_id=run_id,
        inventory_source=inventory_path,
        records_source=records_path,
        evidence_source=evidence_path,
    )
    receipt = json.loads(
        (root / str(authority["receipt_path"])).read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    forged = deepcopy(receipt)
    forged["inventory"] = {"sha256": "0" * 64, "size": -1}
    generation_core = {
        key: value
        for key, value in forged.items()
        if key
        not in {
            "generation_digest",
            "logical_to_physical",
            "advisory_evidence_path",
            "required_paths",
            "debt",
            "proof_authority",
            "receipt_digest",
        }
    }
    generation_core["schema_version"] = (
        "plamen.preverify_frozen_projection.v1"
    )
    forged_generation = _canonical_digest(generation_core)
    forged["generation_digest"] = forged_generation
    unsigned = {
        key: value
        for key, value in forged.items()
        if key != "receipt_digest"
    }
    forged["receipt_digest"] = _canonical_digest(unsigned)
    forged_authority = {
        **authority,
        "frozen_generation": forged_generation,
        "producer_key": (
            str(authority["producer_key"]).rsplit(".", 1)[0]
            + "."
            + forged_generation
        ),
    }
    advisory_raw = (
        root / str(authority["evidence_path"])
    ).read_bytes()

    with pytest.raises(
        PreverifyProjectionAuthorityError,
        match="exact physical",
    ):
        validate_frozen_projection_receipt(
            forged,
            authority=forged_authority,
            run_id=run_id,
            evidence_source=evidence_path,
            inventory_raw=(root / inventory_path).read_bytes(),
            records_raw=(root / records_path).read_bytes(),
            advisory_evidence_raw=advisory_raw,
            scratchpad=root,
            project_root=root.parent,
        )


def test_live_current_run_frozen_capture_and_resolver_share_one_authority(
    tmp_path,
) -> None:
    root, _config, run_id, frozen, _ledger, _bindings = (
        _live_authority_fixture(tmp_path)
    )
    resolved = resolve_current_preverify_projection(
        root,
        expected_run_id=run_id,
        expected_consumer_work_unit_key=(
            "sc/thorough/evm/claude/sc_verify_queue/routing"
        ),
    )

    assert resolved["state"] == "AUTHENTICATED_FROZEN"
    assert (
        resolved["frozen_generation_digest"]
        == frozen["generation_digest"]
    )
    assert (
        resolved["inventory_source_artifact"]
        == frozen["logical_to_physical"]["findings_inventory.md"]
    )
