"""Select and join the expected report MODEL lineage for canonical consumers.

Mechanical reports remain subject to the caller's normal producer validation.
An existing canonical unit still needs its normal arm/commit/live-output replay;
this module authenticates its historical report predecessor only.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Callable, Mapping, Any

from artifact_ledger import read_artifact_ledger
from phase_io_contracts import canonical_work_unit_key
from report_model_lineage import (
    ReportModelLineage, read_report_model_lineage,
    require_report_lineage_head_prestates,
)
import rooted_path_io as rooted


def read_canonical_report_model_lineage(
    root: Path, *, summary_contract, summary_launch,
    canonical_work_unit_id: str, run_id: str,
    resolve_model: Callable[[], tuple[Any, Any]],
) -> ReportModelLineage | None:
    """Select only this run/attempt's known MODEL, Summary, or mechanical head."""
    pipeline = summary_contract.pipeline
    if pipeline not in {"sc", "l1"}:
        raise ValueError("canonical report lineage pipeline is unsupported")
    dimensions = (pipeline, summary_contract.mode, summary_contract.ecosystem,
                  summary_contract.backend, "report_index")
    summary_id = summary_contract.work_unit_id
    model_id = "model" + summary_id.removeprefix("summary_parity")
    model_key = canonical_work_unit_key(*dimensions, model_id)
    canonical_key = canonical_work_unit_key(*dimensions, canonical_work_unit_id)
    mechanical_key = canonical_work_unit_key(*dimensions, "mechanical")
    heads = ("scratchpad:report_index.md", "scratchpad:report_coverage.md",
             *(("scratchpad:report_records.json",) if pipeline == "l1" else ()))
    ledger = read_artifact_ledger(root)
    units, bindings = ledger.get("work_units"), ledger.get("artifact_bindings")
    if not isinstance(units, Mapping) or not isinstance(bindings, Mapping):
        raise ValueError("canonical report lineage ledger tables are malformed")
    canonical = units.get(canonical_key)
    if canonical_key in units:
        if not isinstance(canonical, Mapping) or canonical.get("run_id") != run_id:
            raise ValueError("canonical report lineage unit/run differs")
        rows = canonical.get("output_prestates")
        owner_field = "predecessor_owner_key"
    else:
        rows = bindings
        owner_field = "owner_key"
    if not isinstance(rows, Mapping):
        raise ValueError("canonical report lineage predecessor rows are absent")
    owners = {
        str(rows[identity].get(owner_field) or "")
        if isinstance(rows.get(identity), Mapping) else ""
        for identity in heads
    }
    if owners == {""} and canonical is None and not (
        model_key in units or summary_contract.key in units
    ):
        # Contract planning before any report producer exists. Normal canonical
        # admission still rejects absent/unowned heads before execution.
        return None
    if len(owners) != 1 or not next(iter(owners)):
        raise ValueError("canonical report lineage has missing or mixed head owners")
    selected = next(iter(owners))
    if selected == mechanical_key:
        return None
    if selected not in {model_key, summary_contract.key}:
        raise ValueError("canonical report lineage selects an unexpected report attempt/owner")
    model_contract, model_launch = resolve_model()
    if model_contract is None or model_launch is None or model_contract.key != model_key:
        raise ValueError("canonical report lineage expected MODEL contract is unavailable")
    lineage = read_report_model_lineage(
        root, model_contract=model_contract, model_launch=model_launch,
        summary_contract=summary_contract, summary_launch=summary_launch,
        run_id=run_id,
    )
    if lineage.head_owner_key != selected:
        raise ValueError("canonical report lineage selected head differs from replay")
    if canonical is not None:
        require_report_lineage_head_prestates(lineage, rows)
    else:
        for identity, raw in lineage.head_preimages.items():
            binding = rows[identity]
            if (binding.get("status") != "ACTIVE"
                    or binding.get("authority_level") != "ACTIVE_AUTHORITY"
                    or binding.get("run_id") != run_id
                    or binding.get("contract_digest") != lineage.head_contract_digest
                    or binding.get("launch_digest") != lineage.head_launch_digest
                    or binding.get("sha256") != hashlib.sha256(raw).hexdigest()
                    or binding.get("size") != len(raw)):
                raise ValueError(f"{identity}: canonical report lineage live binding differs")
            try:
                current = rooted.read_bytes(
                    rooted.safe_descendant(
                        root, identity.removeprefix("scratchpad:"), allow_missing=False,
                        label="canonical report predecessor",
                    ),
                    label="canonical report predecessor", require_single_link=True,
                    max_bytes=16 * 1024 * 1024,
                )
            except (OSError, ValueError, rooted.RootedPathIOError) as exc:
                raise ValueError(f"{identity}: canonical report predecessor unreadable: {exc}") from exc
            if current != raw:
                raise ValueError(f"{identity}: canonical report predecessor live bytes differ")
    return lineage
