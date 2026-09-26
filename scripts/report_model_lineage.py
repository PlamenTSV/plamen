"""Historical report MODEL -> optional committed Summary lineage.

This is not live-output validation or canonical-publication authority. Callers
must additionally join the returned head to their exact successor prestates
and validate that successor's live bytes using its normal transaction checks.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from artifact_ledger import (
    read_artifact_ledger, stored_committed_work_unit_authority_issues,
)
from plamen_validators import derive_report_index_summary_master_parity
from report_index_summary_authority import (
    _build_summary_parity_receipt, _summary_parity_receipt_bytes,
)
from report_model_preimages import read_report_model_preimages
import rooted_path_io as rooted


@dataclass(frozen=True)
class ReportModelLineage:
    head_owner_key: str
    head_contract_digest: str
    head_launch_digest: str
    head_preimages: Mapping[str, bytes]
    read_set: tuple[str, ...]


def _exact_unit(ledger, contract, launch, run_id):
    issues = stored_committed_work_unit_authority_issues(
        ledger, work_unit_key=contract.key, run_id=run_id,
        expected_artifact_identities=tuple(spec.identity for spec in contract.outputs),
    )
    unit = ledger.get("work_units", {}).get(contract.key)
    if issues or not isinstance(unit, Mapping):
        raise ValueError("report lineage stored authority: " + "; ".join(issues))
    if (
        unit.get("contract_manifest") != contract.to_dict()
        or unit.get("launch_manifest") != launch.to_dict()
        or unit.get("contract_digest") != contract.digest
        or unit.get("launch_digest") != launch.digest
    ):
        raise ValueError("report lineage expected contract/launch differs")
    return unit


def _matches(raw: bytes, record: Mapping[str, Any]) -> bool:
    return (record.get("size") == len(raw)
            and record.get("sha256") == hashlib.sha256(raw).hexdigest())


def require_report_lineage_head_prestates(
    lineage: ReportModelLineage, prestates: Mapping[str, Any],
) -> None:
    """Join an independently validated successor arm to every report member."""
    for identity, raw in lineage.head_preimages.items():
        row = prestates.get(identity)
        if (
            not isinstance(row, Mapping)
            or row.get("status") != "ACTIVE_REGISTERED_PREDECESSOR"
            or row.get("predecessor_owner_key") != lineage.head_owner_key
            or row.get("predecessor_contract_digest") != lineage.head_contract_digest
            or row.get("predecessor_launch_digest") != lineage.head_launch_digest
            or not _matches(raw, row)
        ):
            raise ValueError(f"{identity}: report lineage predecessor differs")


def read_report_model_lineage(
    root: Path, *, model_contract, model_launch, summary_contract,
    summary_launch, run_id: str,
) -> ReportModelLineage:
    """Reopen originals and reproduce an exact committed Summary, if present.

    Expected contracts come from the current run/attempt resolver, never from
    an arbitrary artifact owner. Missing, armed, or damaged Summary authority
    cannot be treated as a committed Summary head.
    """
    originals = read_report_model_preimages(
        root, contract=model_contract, launch=model_launch, run_id=run_id,
    )
    ledger = read_artifact_ledger(root)
    _exact_unit(ledger, model_contract, model_launch, run_id)
    model_head = ReportModelLineage(
        model_contract.key, model_contract.digest, model_launch.digest,
        originals.preimages, originals.read_set,
    )
    expected_summary_id = "summary_parity" + model_contract.work_unit_id[len("model"):]
    if (
        summary_contract.work_unit_id != expected_summary_id
        or summary_contract.phase != "report_index"
        or summary_launch.work_unit_key != summary_contract.key
        or any(getattr(summary_contract, field) != getattr(model_contract, field)
               for field in ("pipeline", "mode", "ecosystem", "backend"))
    ):
        raise ValueError("report lineage Summary attempt differs from MODEL")
    if summary_contract.key not in ledger.get("work_units", {}):
        return model_head
    summary = _exact_unit(ledger, summary_contract, summary_launch, run_id)
    require_report_lineage_head_prestates(model_head, summary["output_prestates"])
    report_identity = "scratchpad:report_index.md"
    derivation = derive_report_index_summary_master_parity(
        originals.preimages[report_identity]
    )
    if derivation.issues or not derivation.repair_required:
        raise ValueError("report lineage original does not authorize Summary repair")
    head = dict(originals.preimages)
    head[report_identity] = derivation.output_bytes
    receipt_specs = [spec for spec in summary_contract.outputs if spec.identity not in head]
    suffix = model_contract.work_unit_id[len("model"):]
    receipt_name = f"report_index_summary_parity_receipt{suffix}.json"
    if (len(receipt_specs) != 1 or receipt_specs[0].root != "scratchpad"
            or receipt_specs[0].path != receipt_name
            or {spec.identity for spec in summary_contract.outputs}
            != set(head) | {f"scratchpad:{receipt_name}"}):
        raise ValueError("report lineage Summary output denominator differs")
    receipt_spec = receipt_specs[0]
    try:
        receipt_path = rooted.safe_descendant(
            root, receipt_name, allow_missing=False, label="report Summary receipt",
        )
        raw = rooted.read_bytes(
            receipt_path, label="report Summary receipt", require_single_link=True,
            max_bytes=1024 * 1024,
        )
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, rooted.RootedPathIOError) as exc:
        raise ValueError(f"report lineage Summary receipt unreadable: {exc}") from exc
    expected = _build_summary_parity_receipt(
        derivation, contract=summary_contract, run_id=run_id,
        model_work_unit_key=model_contract.key,
    )
    if payload != expected or raw != _summary_parity_receipt_bytes(expected):
        raise ValueError("report lineage Summary receipt differs from original derivation")
    for identity, member_raw in {**head, receipt_spec.identity: raw}.items():
        if not _matches(member_raw, summary["artifacts"][identity]):
            raise ValueError(f"{identity}: report lineage Summary output differs")
    # Canonical never takes ownership of the attempt-specific Summary receipt.
    binding = ledger.get("artifact_bindings", {}).get(receipt_spec.identity)
    if (not isinstance(binding, Mapping)
            or binding.get("status") != "ACTIVE"
            or binding.get("authority_level") != "ACTIVE_AUTHORITY"
            or binding.get("owner_key") != summary_contract.key
            or binding.get("run_id") != run_id
            or binding.get("contract_digest") != summary_contract.digest
            or binding.get("launch_digest") != summary_launch.digest
            or not _matches(raw, binding)):
        raise ValueError("report lineage Summary receipt binding differs")
    return ReportModelLineage(
        summary_contract.key, summary_contract.digest, summary_launch.digest,
        MappingProxyType(head), tuple(sorted((*originals.read_set, receipt_name))),
    )
