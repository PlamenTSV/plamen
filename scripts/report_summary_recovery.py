"""Authenticate an armed report Summary transaction from retained MODEL bytes.

This reader is deliberately limited to the ordinary deterministic Summary
arm.  Summary does not use the generic DRIVER successor-plan/progress
protocol, and this module must not manufacture such a protocol on recovery.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Literal, Mapping

from artifact_ledger import (
    _input_set_digest,
    _output_prestate_digest,
    read_artifact_ledger,
)
from plamen_validators import (
    ReportIndexSummaryParityDerivation,
    derive_report_index_summary_master_parity,
)
from report_index_summary_authority import (
    _build_summary_parity_receipt,
    _summary_parity_receipt_bytes,
)
from report_model_preimages import (
    ReportModelPreimageError,
    read_report_model_preimages,
)
import rooted_path_io as rooted


class ReportSummaryRecoveryError(ValueError):
    """The armed Summary transaction cannot be replayed exactly."""


@dataclass(frozen=True)
class ReportSummaryRecovery:
    derivation: ReportIndexSummaryParityDerivation
    read_set: tuple[str, ...]
    current_state: Literal["MODEL_PREIMAGE", "SUMMARY_POSTIMAGE"]


def _matches(raw: bytes, row: Mapping[str, Any]) -> bool:
    return (
        row.get("size") == len(raw)
        and row.get("sha256") == hashlib.sha256(raw).hexdigest()
    )


def _stable_member(root: Path, relative: str) -> bytes:
    try:
        path = rooted.safe_descendant(
            root, relative, allow_missing=False,
            label="report Summary recovery member",
        )
        return rooted.read_bytes(
            path, label="report Summary recovery member",
            require_single_link=True, max_bytes=16 * 1024 * 1024,
        )
    except (OSError, ValueError, rooted.RootedPathIOError) as exc:
        raise ReportSummaryRecoveryError(
            f"{relative}: Summary recovery member unreadable: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def authenticate_report_summary_armed_recovery(
    root: Path,
    *,
    model_contract: Any,
    model_launch: Any,
    summary_contract: Any,
    summary_launch: Any,
    run_id: str,
) -> ReportSummaryRecovery:
    """Replay one exact armed MODEL-to-Summary transition.

    The live report may be either the retained MODEL preimage or its one pure
    Summary postimage.  A postimage is accepted only with the exact canonical
    receipt.  MODEL passthrough members must remain byte-identical in either
    state.
    """

    run = str(run_id or "").strip()
    if not run:
        raise ReportSummaryRecoveryError("Summary recovery run_id is absent")
    try:
        base = rooted.checked_directory(root, label="report Summary recovery root")
        originals = read_report_model_preimages(
            base, contract=model_contract, launch=model_launch, run_id=run,
        )
    except ReportSummaryRecoveryError:
        raise
    except (OSError, ValueError, ReportModelPreimageError,
            rooted.RootedPathIOError) as exc:
        raise ReportSummaryRecoveryError(
            "Summary recovery MODEL preimage authority failed: "
            f"{type(exc).__name__}: {exc}"
        ) from exc

    expected_model_identities = (
        ("scratchpad:report_index.md", "scratchpad:report_coverage.md")
        if getattr(model_contract, "pipeline", None) == "sc"
        else (
            "scratchpad:report_index.md", "scratchpad:report_coverage.md",
            "scratchpad:report_records.json",
        )
        if getattr(model_contract, "pipeline", None) == "l1"
        else ()
    )
    suffix = str(getattr(model_contract, "work_unit_id", ""))[len("model"):]
    expected_summary_id = "summary_parity" + suffix
    receipt_name = f"report_index_summary_parity_receipt{suffix}.json"
    receipt_identity = f"scratchpad:{receipt_name}"
    summary_outputs = tuple(getattr(summary_contract, "outputs", ()))
    if (
        not expected_model_identities
        or set(originals.preimages) != set(expected_model_identities)
        or getattr(summary_contract, "phase", None) != "report_index"
        or getattr(summary_contract, "work_unit_id", None) != expected_summary_id
        or getattr(summary_launch, "work_unit_key", None)
        != getattr(summary_contract, "key", None)
        or any(
            getattr(summary_contract, field, None)
            != getattr(model_contract, field, None)
            for field in ("pipeline", "mode", "ecosystem", "backend")
        )
        or {item.identity for item in summary_outputs}
        != {*expected_model_identities, receipt_identity}
        or any(
            item.root != "scratchpad"
            or item.writer != "DRIVER"
            or item.write_mode != "REPLACE"
            or item.owner_key != summary_contract.key
            for item in summary_outputs
        )
    ):
        raise ReportSummaryRecoveryError(
            "Summary recovery contract/launch denominator is unsupported"
        )

    try:
        ledger = read_artifact_ledger(base)
        unit = ledger.get("work_units", {}).get(summary_contract.key)
        if not isinstance(unit, Mapping):
            raise ReportSummaryRecoveryError("armed Summary work unit is absent")
        prestates = unit.get("output_prestates")
        if (
            unit.get("run_id") != run
            or unit.get("contract_digest") != summary_contract.digest
            or unit.get("contract_manifest") != summary_contract.to_dict()
            or unit.get("launch_digest") != summary_launch.digest
            or unit.get("launch_manifest") != summary_launch.to_dict()
            or unit.get("model_invoked") is not False
            or unit.get("semantic_status") != "INPUTS_BOUND"
            or unit.get("execution_state") != "INPUTS_BOUND_PREEXECUTION"
            or unit.get("artifacts") != {}
            or unit.get("input_bindings") != {}
            or unit.get("input_receipt_kind") != "EXPLICIT_ZERO_INPUT"
            or unit.get("input_set_digest") != _input_set_digest({})
            or not isinstance(prestates, Mapping)
            or set(prestates) != {*expected_model_identities, receipt_identity}
            or unit.get("output_prestate_digest")
            != _output_prestate_digest(prestates)
        ):
            raise ReportSummaryRecoveryError(
                "armed Summary work-unit receipt is invalid"
            )
    except ReportSummaryRecoveryError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise ReportSummaryRecoveryError(
            f"armed Summary ledger replay failed: {type(exc).__name__}: {exc}"
        ) from exc

    for identity in expected_model_identities:
        row = prestates.get(identity)
        raw = originals.preimages[identity]
        if (
            not isinstance(row, Mapping)
            or row.get("status") != "ACTIVE_REGISTERED_PREDECESSOR"
            or row.get("predecessor_owner_key") != model_contract.key
            or row.get("predecessor_contract_digest") != model_contract.digest
            or row.get("predecessor_launch_digest") != model_launch.digest
            or not _matches(raw, row)
        ):
            raise ReportSummaryRecoveryError(
                f"{identity}: armed Summary MODEL prestate differs"
            )
    receipt_prestate = prestates.get(receipt_identity)
    if (
        not isinstance(receipt_prestate, Mapping)
        or receipt_prestate.get("status") != "ABSENT"
        or receipt_prestate.get("existed") is not False
        or receipt_prestate.get("size") != 0
        or receipt_prestate.get("sha256") != ""
    ):
        raise ReportSummaryRecoveryError(
            "armed Summary receipt prestate is not exact absence"
        )

    report_original = originals.preimages["scratchpad:report_index.md"]
    derivation = derive_report_index_summary_master_parity(report_original)
    if derivation.issues or not derivation.repair_required:
        raise ReportSummaryRecoveryError(
            "retained MODEL report does not authorize Summary repair"
        )
    current_report = _stable_member(base, "report_index.md")
    if current_report == report_original:
        current_state: Literal["MODEL_PREIMAGE", "SUMMARY_POSTIMAGE"] = (
            "MODEL_PREIMAGE"
        )
    elif current_report == derivation.output_bytes:
        current_state = "SUMMARY_POSTIMAGE"
    else:
        raise ReportSummaryRecoveryError(
            "current report is neither the MODEL preimage nor Summary postimage"
        )
    for identity in expected_model_identities[1:]:
        relative = identity.removeprefix("scratchpad:")
        if _stable_member(base, relative) != originals.preimages[identity]:
            raise ReportSummaryRecoveryError(
                f"{identity}: Summary passthrough bytes changed"
            )

    receipt_path = base / receipt_name
    receipt_present = rooted.lexists(receipt_path)
    read_set = list(originals.read_set)
    if receipt_present:
        receipt_raw = _stable_member(base, receipt_name)
        expected_receipt = _build_summary_parity_receipt(
            derivation, contract=summary_contract, run_id=run,
            model_work_unit_key=model_contract.key,
        )
        if receipt_raw != _summary_parity_receipt_bytes(expected_receipt):
            raise ReportSummaryRecoveryError(
                "Summary recovery receipt differs from original derivation"
            )
        read_set.append(receipt_name)
    elif current_state == "SUMMARY_POSTIMAGE":
        raise ReportSummaryRecoveryError(
            "Summary postimage has no exact recovery receipt"
        )

    return ReportSummaryRecovery(
        derivation=derivation,
        read_set=tuple(sorted(set(read_set))),
        current_state=current_state,
    )


__all__ = [
    "ReportSummaryRecovery",
    "ReportSummaryRecoveryError",
    "authenticate_report_summary_armed_recovery",
]
