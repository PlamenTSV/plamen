"""RED fixtures for the remaining preverify projection authority gaps.

These tests intentionally describe the fail-closed boundary expected from the
resolver.  They do not patch production state outside pytest's temporary
scratchpad.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

import pytest

import artifact_ledger as AL
from artifact_ledger import write_artifact_ledger
from preverify_projection_authority import (
    PreverifyProjectionAuthorityError,
    resolve_current_preverify_projection,
    resolve_exact_frozen_capture_authority,
    validate_frozen_projection_receipt,
)
import test_preverify_capture_pair_contract as BASE


RUNTIME_CONSUMER = "sc/thorough/evm/claude/sc_verify_queue/routing"


def _resolve_current(root: Path, run_id: str, *, runtime_bound: bool) -> dict:
    if runtime_bound:
        return resolve_current_preverify_projection(
            root,
            expected_run_id=run_id,
            expected_consumer_work_unit_key=RUNTIME_CONSUMER,
        )
    return resolve_current_preverify_projection(root)


def _successor_and_capture(
    ledger: dict[str, Any],
) -> tuple[tuple[str, dict[str, Any]], tuple[str, dict[str, Any]]]:
    successor = next(
        (key, unit)
        for key, unit in ledger["work_units"].items()
        if key.endswith("/preverify_successors")
    )
    capture = next(
        (key, unit)
        for key, unit in ledger["work_units"].items()
        if "/preverify_capture." in key
    )
    return successor, capture


def _frozen_producer(
    ledger: dict[str, Any],
    capture_bindings: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    key = str(
        next(iter(capture_bindings.values()))["producer_work_unit_key"]
    )
    return key, ledger["work_units"][key]


def _reauthor_frozen_manifest(
    ledger: dict[str, Any],
    capture_bindings: dict[str, Any],
    producer_key: str,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    """Keep the current weak receipts self-consistent after manifest drift."""

    unit = ledger["work_units"][producer_key]
    manifest = unit["contract_manifest"]
    mutate(manifest)
    digest = AL._contract_manifest_digest(manifest)
    unit["contract_digest"] = digest
    unit["commit_authority"]["contract_digest"] = digest
    unit["commit_authority"]["receipt_digest"] = AL._commit_receipt_digest(
        unit["commit_authority"]
    )
    for identity, artifact in unit["artifacts"].items():
        artifact["contract_digest"] = digest
        ledger["artifact_bindings"][identity]["contract_digest"] = digest
    for binding in capture_bindings.values():
        if binding.get("producer_work_unit_key") == producer_key:
            binding["producer_contract_digest"] = digest


def _receipt_context(tmp_path: Path) -> dict[str, Any]:
    root, _config, run_id, frozen, ledger, bindings = (
        BASE._live_authority_fixture(tmp_path)
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
    return {
        "root": root,
        "run_id": run_id,
        "authority": authority,
        "receipt": receipt,
        "inventory_raw": (root / inventory_path).read_bytes(),
        "records_raw": (root / records_path).read_bytes(),
        "evidence_source": evidence_path,
        "evidence_raw": (
            root / str(authority["evidence_path"])
        ).read_bytes(),
    }


_GENERATION_ENVELOPE_FIELDS = {
    "generation_digest",
    "logical_to_physical",
    "advisory_evidence_path",
    "required_paths",
    "debt",
    "proof_authority",
    "receipt_digest",
}


def _readdress_receipt(
    receipt: dict[str, Any],
    authority: dict[str, Any],
) -> dict[str, Any]:
    """Recompute semantic and path digests after a generation-core mutation."""

    generation_core = {
        key: value
        for key, value in receipt.items()
        if key not in _GENERATION_ENVELOPE_FIELDS
    }
    generation_core["schema_version"] = (
        "plamen.preverify_frozen_projection.v1"
    )
    generation = BASE._canonical_digest(generation_core)
    old_root = str(authority["frozen_root"])
    new_root = f"_preverify_frozen/generation_{generation}"

    receipt["generation_digest"] = generation
    receipt["logical_to_physical"] = {
        logical: str(physical).replace(old_root, new_root, 1)
        for logical, physical in receipt["logical_to_physical"].items()
    }
    receipt["advisory_evidence_path"] = str(
        receipt["advisory_evidence_path"]
    ).replace(old_root, new_root, 1)
    receipt["required_paths"] = sorted(
        str(path).replace(old_root, new_root, 1)
        for path in receipt["required_paths"]
    )
    receipt["receipt_digest"] = BASE._canonical_digest({
        key: value
        for key, value in receipt.items()
        if key != "receipt_digest"
    })

    producer_prefix = str(authority["producer_key"]).rsplit(".", 1)[0]
    return {
        **authority,
        "frozen_root": new_root,
        "frozen_generation": generation,
        "producer_key": f"{producer_prefix}.{generation}",
        "inventory_path": (
            f"{new_root}/findings_inventory.md"
        ),
        "records_path": f"{new_root}/finding_records.json",
        "receipt_path": f"{new_root}/receipt.json",
        "evidence_path": (
            f"{new_root}/inventory_evidence_validation.md"
        ),
    }


def _validate_receipt(
    context: dict[str, Any],
    receipt: dict[str, Any],
    authority: dict[str, Any],
    *,
    records_raw: bytes | None = None,
) -> None:
    validate_frozen_projection_receipt(
        receipt,
        authority=authority,
        run_id=context["run_id"],
        evidence_source=context["evidence_source"],
        inventory_raw=context["inventory_raw"],
        records_raw=(
            context["records_raw"]
            if records_raw is None
            else records_raw
        ),
        advisory_evidence_raw=context["evidence_raw"],
        scratchpad=Path(context["root"]),
        project_root=Path(context["root"]).parent,
    )


@pytest.mark.parametrize("runtime_bound", (False, True), ids=("introspection", "runtime"))
@pytest.mark.parametrize("owner_kind", ("successor", "capture"))
def test_every_successor_hop_requires_an_active_commit_receipt(
    tmp_path: Path,
    runtime_bound: bool,
    owner_kind: str,
) -> None:
    root, _config, run_id, _frozen, ledger, _bindings = (
        BASE._live_authority_fixture(tmp_path)
    )
    successor, capture = _successor_and_capture(ledger)
    target = successor if owner_kind == "successor" else capture
    target[1].pop("commit_authority", None)
    write_artifact_ledger(root, ledger)

    with pytest.raises(PreverifyProjectionAuthorityError):
        _resolve_current(root, run_id, runtime_bound=runtime_bound)


@pytest.mark.parametrize("runtime_bound", (False, True), ids=("introspection", "runtime"))
def test_successor_hop_rejects_unit_artifact_tuple_drift(
    tmp_path: Path,
    runtime_bound: bool,
) -> None:
    root, _config, run_id, _frozen, ledger, _bindings = (
        BASE._live_authority_fixture(tmp_path)
    )
    successor, _capture = _successor_and_capture(ledger)
    artifact = next(iter(successor[1]["artifacts"].values()))
    artifact["writer"] = "MODEL"
    artifact["owner_key"] = "foreign/owner"
    write_artifact_ledger(root, ledger)

    with pytest.raises(PreverifyProjectionAuthorityError):
        _resolve_current(root, run_id, runtime_bound=runtime_bound)


@pytest.mark.parametrize("runtime_bound", (False, True), ids=("introspection", "runtime"))
def test_capture_hop_rejects_unit_artifact_tuple_drift(
    tmp_path: Path,
    runtime_bound: bool,
) -> None:
    root, _config, run_id, _frozen, ledger, _bindings = (
        BASE._live_authority_fixture(tmp_path)
    )
    _successor, capture = _successor_and_capture(ledger)
    artifact = next(iter(capture[1]["artifacts"].values()))
    artifact["sha256"] = "0" * 64
    artifact["writer"] = "MODEL"
    write_artifact_ledger(root, ledger)

    with pytest.raises(PreverifyProjectionAuthorityError):
        _resolve_current(root, run_id, runtime_bound=runtime_bound)


@pytest.mark.parametrize("runtime_bound", (False, True), ids=("introspection", "runtime"))
def test_successor_hop_rejects_duplicate_manifest_output(
    tmp_path: Path,
    runtime_bound: bool,
) -> None:
    root, _config, run_id, _frozen, ledger, _bindings = (
        BASE._live_authority_fixture(tmp_path)
    )
    successor, _capture = _successor_and_capture(ledger)
    outputs = successor[1]["contract_manifest"]["outputs"]
    outputs.append(deepcopy(outputs[0]))
    write_artifact_ledger(root, ledger)

    with pytest.raises(PreverifyProjectionAuthorityError):
        _resolve_current(root, run_id, runtime_bound=runtime_bound)


@pytest.mark.parametrize("mutation", ("missing", "extra"))
def test_frozen_producer_requires_exact_input_binding_denominator(
    tmp_path: Path,
    mutation: str,
) -> None:
    _root, _config, run_id, _frozen, ledger, bindings = (
        BASE._live_authority_fixture(tmp_path)
    )
    forged = deepcopy(ledger)
    capture_bindings = deepcopy(bindings)
    producer_key, producer = _frozen_producer(forged, capture_bindings)
    if mutation == "missing":
        producer["input_bindings"] = {}
    else:
        row = deepcopy(next(iter(producer["input_bindings"].values())))
        row["identity"] = "scratchpad:decoy.json"
        producer["input_bindings"]["scratchpad:decoy.json"] = row

    with pytest.raises(PreverifyProjectionAuthorityError):
        resolve_exact_frozen_capture_authority(
            input_bindings=capture_bindings,
            ledger=forged,
            run_id=run_id,
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "duplicate-immutable-input",
        "bounded-input",
        "model-invoked",
        "wrong-output-consumer",
    ),
)
def test_frozen_producer_requires_the_exact_provider_contract(
    tmp_path: Path,
    mutation: str,
) -> None:
    _root, _config, run_id, _frozen, ledger, bindings = (
        BASE._live_authority_fixture(tmp_path)
    )
    forged = deepcopy(ledger)
    capture_bindings = deepcopy(bindings)
    producer_key, _producer = _frozen_producer(forged, capture_bindings)

    def mutate(manifest: dict[str, Any]) -> None:
        if mutation == "duplicate-immutable-input":
            manifest["immutable_inputs"].append(
                manifest["immutable_inputs"][0]
            )
        elif mutation == "bounded-input":
            manifest["bounded_lookup_inputs"] = [
                "scratchpad:decoy.json"
            ]
        elif mutation == "model-invoked":
            manifest["model_invoked"] = True
        else:
            for row in manifest["outputs"]:
                row["consumers"] = []

    _reauthor_frozen_manifest(
        forged,
        capture_bindings,
        producer_key,
        mutate,
    )

    with pytest.raises(PreverifyProjectionAuthorityError):
        resolve_exact_frozen_capture_authority(
            input_bindings=capture_bindings,
            ledger=forged,
            run_id=run_id,
        )


@pytest.mark.parametrize(
    "mutation",
    ("missing-inventory-authority", "wrong-authority-identity"),
)
def test_receipt_source_authority_must_reconcile_to_its_source(
    tmp_path: Path,
    mutation: str,
) -> None:
    context = _receipt_context(tmp_path)
    receipt = deepcopy(context["receipt"])
    if mutation == "missing-inventory-authority":
        receipt["source_authorities"].pop("inventory", None)
    else:
        receipt["source_authorities"]["inventory"]["identity"] = (
            "scratchpad:decoy_inventory.md"
        )
    authority = _readdress_receipt(
        receipt,
        context["authority"],
    )

    with pytest.raises(PreverifyProjectionAuthorityError):
        _validate_receipt(context, receipt, authority)


@pytest.mark.parametrize(
    "mutation",
    ("empty-records", "wrong-source-sha", "duplicate-record"),
)
def test_receipt_rejects_records_that_are_not_the_inventory_derivation(
    tmp_path: Path,
    mutation: str,
) -> None:
    context = _receipt_context(tmp_path)
    records = json.loads(
        context["records_raw"].decode("utf-8", errors="strict")
    )
    if mutation == "empty-records":
        records["records"] = []
    elif mutation == "wrong-source-sha":
        records["source_sha256"] = "0" * 64
    else:
        records["records"].append(deepcopy(records["records"][0]))
    bad_records_raw = (
        json.dumps(
            records,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")

    receipt = deepcopy(context["receipt"])
    receipt["records"] = {
        "sha256": hashlib.sha256(bad_records_raw).hexdigest(),
        "size": len(bad_records_raw),
    }
    authority = _readdress_receipt(
        receipt,
        context["authority"],
    )

    with pytest.raises(PreverifyProjectionAuthorityError):
        _validate_receipt(
            context,
            receipt,
            authority,
            records_raw=bad_records_raw,
        )


def test_receipt_cannot_hide_required_advisory_repair_debt(
    tmp_path: Path,
) -> None:
    context = _receipt_context(tmp_path)
    receipt = deepcopy(context["receipt"])
    assert receipt["evidence_semantic_use"] is False
    assert receipt["debt"]
    receipt["debt"] = []
    receipt["receipt_digest"] = BASE._canonical_digest({
        key: value
        for key, value in receipt.items()
        if key != "receipt_digest"
    })

    with pytest.raises(PreverifyProjectionAuthorityError):
        _validate_receipt(context, receipt, context["authority"])


def test_receipt_v1_rejects_unknown_generation_fields(
    tmp_path: Path,
) -> None:
    context = _receipt_context(tmp_path)
    receipt = deepcopy(context["receipt"])
    receipt["unsupported_future_field"] = {"authority": "NONE"}
    authority = _readdress_receipt(
        receipt,
        context["authority"],
    )

    with pytest.raises(PreverifyProjectionAuthorityError):
        _validate_receipt(context, receipt, authority)


def test_unbound_resolution_is_not_runtime_authority(
    tmp_path: Path,
) -> None:
    root, _config, _run_id, _frozen, _ledger, _bindings = (
        BASE._live_authority_fixture(tmp_path)
    )

    with pytest.raises(
        PreverifyProjectionAuthorityError,
        match="runtime|scope|binding|introspection",
    ):
        resolve_current_preverify_projection(root)
