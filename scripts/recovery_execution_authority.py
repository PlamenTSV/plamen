"""Independent validation for compiler-bound verification recovery evidence.

The driver produces recovery contracts, launches, model outputs, operator
receipts, and execution receipts.  Consumers must replay that chain from the
source bytes rather than trusting a driver-authored summary or a recomputed
outer digest.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import time
from typing import Any, Mapping

from verification_method_compiler import (
    load_bound_operator_receipt,
    stable_digest,
)
from verification_recovery_contract import (
    validate_verification_recovery_contract,
)
from verifier_work_roster import VerifierLaunchSpec


EXECUTION_SCHEMA = "plamen.verification_recovery_execution.v1"
EXECUTION_FIELDS = frozenset({
    "schema_version",
    "status",
    "recovery_id",
    "recovery_kind",
    "contract_digest",
    "launch_spec_digest",
    "ordered_work_item_ids",
    "unresolved_work_item_ids",
    "issues",
    "output_sha256",
    "operator_receipt_sha256",
    "terminal_negative_authority",
    "receipt_digest",
})


class RecoveryExecutionAuthorityError(ValueError):
    """Raised when a recovery evidence chain is incomplete or inconsistent."""


LATE_AUTHORITY_SCHEMA = "plamen.post_verify_late_verification_authority.v1"
LATE_AUTHORITY_ARTIFACT = "post_verify_late_verification_authority.json"


def _strict_json(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = Path(path).read_bytes()
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        raise RecoveryExecutionAuthorityError(
            f"{Path(path).name} is not strict JSON"
        ) from exc
    if not isinstance(value, dict):
        raise RecoveryExecutionAuthorityError(
            f"{Path(path).name} must contain an object"
        )
    return value, raw


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def execution_receipt_digest(payload: Mapping[str, Any]) -> str:
    """Return the canonical digest of an execution receipt without its digest."""

    return stable_digest({
        key: value for key, value in payload.items()
        if key != "receipt_digest"
    })


def validate_recovery_execution_receipt(
    execution: Mapping[str, Any],
    *,
    contract: Mapping[str, Any],
    launch_spec: VerifierLaunchSpec,
    scratchpad: Path,
) -> dict[str, Any]:
    """Replay a recovery execution receipt against every bound source byte."""

    payload = dict(execution)
    if set(payload) != set(EXECUTION_FIELDS):
        raise RecoveryExecutionAuthorityError(
            "recovery execution receipt fields are not exact"
        )
    if payload.get("schema_version") != EXECUTION_SCHEMA:
        raise RecoveryExecutionAuthorityError(
            "recovery execution receipt schema mismatch"
        )
    if payload.get("recovery_id") != contract["recovery_id"]:
        raise RecoveryExecutionAuthorityError(
            "recovery execution receipt identity mismatch"
        )
    if payload.get("contract_digest") != contract["contract_digest"]:
        raise RecoveryExecutionAuthorityError(
            "recovery execution receipt contract changed"
        )
    if payload.get("launch_spec_digest") != launch_spec.digest:
        raise RecoveryExecutionAuthorityError(
            "recovery execution receipt launch changed"
        )
    if payload.get("recovery_kind") != contract["recovery_kind"]:
        raise RecoveryExecutionAuthorityError(
            "recovery execution receipt kind mismatch"
        )
    ordered = [str(row["work_item_id"]) for row in contract["rows"]]
    if payload.get("ordered_work_item_ids") != ordered:
        raise RecoveryExecutionAuthorityError(
            "recovery execution receipt denominator mismatch"
        )
    unresolved = payload.get("unresolved_work_item_ids")
    issues = payload.get("issues")
    if (
        not isinstance(unresolved, list)
        or len(unresolved) != len(set(unresolved))
        or unresolved
        != [work_id for work_id in ordered if work_id in set(unresolved)]
        or not isinstance(issues, list)
        or any(
            not isinstance(issue, str) or not issue.strip()
            for issue in issues
        )
    ):
        raise RecoveryExecutionAuthorityError(
            "recovery execution receipt unresolved set is invalid"
        )
    if any(work_id not in ordered for work_id in unresolved):
        raise RecoveryExecutionAuthorityError(
            "recovery execution receipt carries an unknown work item"
        )
    issue_ids = {
        work_id
        for work_id in ordered
        if any(issue.startswith(f"{work_id}:") for issue in issues)
    }
    if issue_ids != set(unresolved):
        raise RecoveryExecutionAuthorityError(
            "recovery execution issues do not match unresolved rows"
        )
    expected_status = "COMPLETED" if not unresolved else "COMPLETED_WITH_DEBT"
    if payload.get("status") != expected_status:
        raise RecoveryExecutionAuthorityError(
            "recovery execution receipt status mismatch"
        )
    if payload.get("terminal_negative_authority") is not False:
        raise RecoveryExecutionAuthorityError(
            "recovery execution receipt acquired negative authority"
        )
    if payload.get("receipt_digest") != execution_receipt_digest(payload):
        raise RecoveryExecutionAuthorityError(
            "recovery execution receipt digest mismatch"
        )

    output_hashes = payload.get("output_sha256")
    operator_hashes = payload.get("operator_receipt_sha256")
    if not isinstance(output_hashes, dict) or not isinstance(
        operator_hashes, dict
    ):
        raise RecoveryExecutionAuthorityError(
            "recovery execution receipt output maps are invalid"
        )
    root = Path(scratchpad)
    expected_output_hashes = {
        name: _sha((root / name).read_bytes())
        for name in contract["expected_model_outputs"]
        if (root / name).is_file()
    }
    expected_operator_hashes = {
        name: _sha((root / name).read_bytes())
        for name in contract["expected_operator_receipts"]
        if (root / name).is_file()
    }
    if output_hashes != expected_output_hashes:
        raise RecoveryExecutionAuthorityError(
            "recovery execution model-output exact set changed"
        )
    if operator_hashes != expected_operator_hashes:
        raise RecoveryExecutionAuthorityError(
            "recovery execution operator-receipt exact set changed"
        )
    dispatch = contract["method_dispatch"]
    for work_id in ordered:
        if work_id in unresolved:
            continue
        model_names = {
            f"verify_{work_id}.md",
            f"verify_{work_id}.severity_proposal.json",
            f"verify_{work_id}.operator_application.json",
        }
        receipt_name = f"verify_{work_id}.operator_receipt.json"
        if (
            not model_names.issubset(output_hashes)
            or receipt_name not in operator_hashes
        ):
            raise RecoveryExecutionAuthorityError(
                "recovery resolved row lacks exact execution authority: "
                f"{work_id}"
            )
        try:
            load_bound_operator_receipt(
                receipt_path=root / receipt_name,
                proposal_path=root / f"verify_{work_id}.operator_application.json",
                verify_path=root / f"verify_{work_id}.md",
                dispatch=dispatch,
                launch_digest=launch_spec.digest,
            )
        except Exception as exc:
            raise RecoveryExecutionAuthorityError(
                f"recovery operator receipt is invalid for {work_id}: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
    return payload


def load_recovery_execution_evidence(
    directory: Path,
    *,
    scratchpad: Path,
    repo_root: Path,
) -> dict[str, Any]:
    """Load and independently validate one complete recovery evidence chain."""

    unit = Path(directory)
    contract_value, contract_raw = _strict_json(unit / "contract.json")
    try:
        contract = validate_verification_recovery_contract(
            contract_value,
            repo_root=Path(repo_root),
        )
        launch_raw = (unit / "launch_spec.json").read_bytes()
        launch = VerifierLaunchSpec.from_json(
            launch_raw.decode("utf-8", errors="strict")
        )
        execution_value, execution_raw = _strict_json(
            unit / "execution_receipt.json"
        )
        execution = validate_recovery_execution_receipt(
            execution_value,
            contract=contract,
            launch_spec=launch,
            scratchpad=Path(scratchpad),
        )
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        if isinstance(exc, RecoveryExecutionAuthorityError):
            raise
        raise RecoveryExecutionAuthorityError(
            f"recovery evidence chain is invalid: {type(exc).__name__}: {exc}"
        ) from exc
    return {
        "contract": contract,
        "contract_sha256": _sha(contract_raw),
        "launch_spec": launch,
        "launch_spec_sha256": _sha(launch_raw),
        "execution": execution,
        "execution_sha256": _sha(execution_raw),
    }


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    content = (
        json.dumps(
            dict(payload),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    target = Path(path)
    temporary = target.with_name(
        f".{target.name}.{os.getpid()}.{time.time_ns()}.tmp"
    )
    try:
        temporary.write_text(content, encoding="utf-8")
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def _late_debt(
    *,
    candidate_id: str,
    code: str,
    detail: str,
    source_identity: str,
) -> dict[str, Any]:
    semantic = {
        "candidate_id": candidate_id,
        "debt_code": code,
        "detail": detail,
        "source_identity": source_identity,
    }
    return {**semantic, "debt_digest": stable_digest(semantic)}


def _candidate_contract_directories(
    scratchpad: Path,
    candidate_ids: set[str],
) -> tuple[dict[str, list[Path]], list[dict[str, Any]]]:
    """Find candidate-bearing recovery units without trusting their validity."""

    matches: dict[str, list[Path]] = {
        candidate_id: [] for candidate_id in candidate_ids
    }
    debts: list[dict[str, Any]] = []
    recovery_root = Path(scratchpad) / "_verification_recovery"
    if not recovery_root.is_dir():
        return matches, debts
    for contract_path in sorted(
        recovery_root.glob("VREC-*/contract.json"),
        key=lambda value: value.as_posix(),
    ):
        try:
            value, _raw = _strict_json(contract_path)
            rows = value.get("rows")
            if not isinstance(rows, list):
                continue
            raw_ids = {
                str(row.get("work_item_id") or "")
                for row in rows
                if isinstance(row, dict)
            } & candidate_ids
            if not raw_ids:
                continue
            if value.get("recovery_kind") != "POST_VERIFY_SIDE_OBSERVATION":
                for candidate_id in sorted(raw_ids):
                    debts.append(_late_debt(
                        candidate_id=candidate_id,
                        code="LATE_RECOVERY_KIND_MISMATCH",
                        detail=(
                            "candidate-bearing recovery unit has a non-late "
                            "recovery kind"
                        ),
                        source_identity=contract_path.parent.name,
                    ))
                continue
            for candidate_id in sorted(raw_ids):
                matches[candidate_id].append(contract_path.parent)
        except RecoveryExecutionAuthorityError as exc:
            # An unreadable contract cannot reveal a trustworthy candidate
            # identity.  It therefore cannot be charged to the delta exact set
            # (the affected candidate independently remains UNVERIFIED because
            # no valid candidate-bearing unit can be joined).  This prevents a
            # stale unrelated recovery directory from adding report noise.
            _ = exc
    return matches, debts


def _late_verification_payload(
    scratchpad: Path,
    *,
    run_id: str,
    repo_root: Path,
) -> dict[str, Any]:
    from plamen_parsers import _verifier_status_from_text
    from post_verify_candidate_delta import load_candidate_universe_authority

    root = Path(scratchpad)
    universe = load_candidate_universe_authority(root, run_id=run_id)
    delta_candidates = {
        row.item.work_item_id: row
        for row in universe.candidates
        if row.source_kind != "BASE_VERIFICATION_QUEUE"
    }
    matches, debts = _candidate_contract_directories(
        root, set(delta_candidates)
    )
    rows: list[dict[str, Any]] = []
    for candidate_id in sorted(delta_candidates):
        candidate = delta_candidates[candidate_id]
        directories = matches[candidate_id]
        evidence: dict[str, Any] | None = None
        if len(directories) > 1:
            debts.append(_late_debt(
                candidate_id=candidate_id,
                code="AMBIGUOUS_LATE_RECOVERY_AUTHORITY",
                detail="multiple recovery units claim the same late candidate",
                source_identity=",".join(
                    directory.name for directory in directories
                ),
            ))
        elif len(directories) == 1:
            try:
                evidence = load_recovery_execution_evidence(
                    directories[0],
                    scratchpad=root,
                    repo_root=Path(repo_root),
                )
                ids = [
                    str(row["work_item_id"])
                    for row in evidence["contract"]["rows"]
                ]
                if candidate_id not in ids:
                    raise RecoveryExecutionAuthorityError(
                        "validated recovery denominator lost the candidate"
                    )
            except RecoveryExecutionAuthorityError as exc:
                debts.append(_late_debt(
                    candidate_id=candidate_id,
                    code="LATE_RECOVERY_EVIDENCE_INVALID",
                    detail=str(exc),
                    source_identity=directories[0].name,
                ))
                evidence = None
        else:
            debts.append(_late_debt(
                candidate_id=candidate_id,
                code="LATE_RECOVERY_EVIDENCE_MISSING",
                detail="no compiler-bound recovery unit covers this candidate",
                source_identity=LATE_AUTHORITY_ARTIFACT,
            ))

        row: dict[str, Any] = {
            "candidate_id": candidate_id,
            "source_record_digest": candidate.source_record_digest,
            "delivery_state": "UNVERIFIED_HUMAN_REVIEW",
            "verifier_status": "UNVERIFIED",
            "evidence_authority": "NONE",
            "recovery_id": None,
            "contract_artifact": None,
            "contract_sha256": None,
            "contract_digest": None,
            "contract_row_digest": None,
            "launch_spec_artifact": None,
            "launch_spec_sha256": None,
            "launch_spec_digest": None,
            "execution_artifact": None,
            "execution_sha256": None,
            "execution_receipt_digest": None,
            "verify_artifact": None,
            "verify_sha256": None,
            "severity_proposal_artifact": None,
            "severity_proposal_sha256": None,
            "operator_application_artifact": None,
            "operator_application_sha256": None,
            "operator_receipt_artifact": None,
            "operator_receipt_sha256": None,
            "operator_receipt_digest": None,
            "terminal_negative_authority": False,
        }
        if evidence is not None:
            contract = evidence["contract"]
            execution = evidence["execution"]
            directory = directories[0]
            unresolved = set(execution["unresolved_work_item_ids"])
            contract_row = next(
                value
                for value in contract["rows"]
                if str(value["work_item_id"]) == candidate_id
            )
            row.update({
                "recovery_id": contract["recovery_id"],
                "contract_artifact": (
                    directory / "contract.json"
                ).relative_to(root).as_posix(),
                "contract_sha256": evidence["contract_sha256"],
                "contract_digest": contract["contract_digest"],
                "contract_row_digest": stable_digest(contract_row),
                "launch_spec_artifact": (
                    directory / "launch_spec.json"
                ).relative_to(root).as_posix(),
                "launch_spec_sha256": evidence["launch_spec_sha256"],
                "launch_spec_digest": evidence["launch_spec"].digest,
                "execution_artifact": (
                    directory / "execution_receipt.json"
                ).relative_to(root).as_posix(),
                "execution_sha256": evidence["execution_sha256"],
                "execution_receipt_digest": execution["receipt_digest"],
            })
            if candidate_id not in unresolved:
                names = {
                    "verify_artifact": f"verify_{candidate_id}.md",
                    "severity_proposal_artifact": (
                        f"verify_{candidate_id}.severity_proposal.json"
                    ),
                    "operator_application_artifact": (
                        f"verify_{candidate_id}.operator_application.json"
                    ),
                    "operator_receipt_artifact": (
                        f"verify_{candidate_id}.operator_receipt.json"
                    ),
                }
                for artifact_field, name in names.items():
                    row[artifact_field] = name
                    row[artifact_field.replace("_artifact", "_sha256")] = _sha(
                        (root / name).read_bytes()
                    )
                operator_receipt, _raw = _strict_json(
                    root / names["operator_receipt_artifact"]
                )
                row.update({
                    "delivery_state": "INDEPENDENT_VERIFICATION_RECORDED",
                    "verifier_status": _verifier_status_from_text(
                        (root / names["verify_artifact"]).read_text(
                            encoding="utf-8", errors="strict"
                        )
                    ),
                    "evidence_authority": (
                        "COMPILER_BOUND_INDEPENDENT_VERIFICATION"
                    ),
                    "operator_receipt_digest": operator_receipt[
                        "receipt_digest"
                    ],
                })
            else:
                debts.append(_late_debt(
                    candidate_id=candidate_id,
                    code="LATE_RECOVERY_RETAINS_DEBT",
                    detail="execution receipt retains this candidate unresolved",
                    source_identity=contract["recovery_id"],
                ))
        row["row_digest"] = stable_digest(row)
        rows.append(row)

    debts.sort(
        key=lambda value: (
            value["candidate_id"],
            value["debt_code"],
            value["source_identity"],
            value["debt_digest"],
        )
    )
    delta_raw = (
        root / "post_verify_candidate_delta.json"
    ).read_bytes()
    unsigned = {
        "schema_version": LATE_AUTHORITY_SCHEMA,
        "run_id": run_id,
        "authority": "ADDITIVE_EXECUTION_EVIDENCE_ONLY",
        "terminal_negative_authority": False,
        "candidate_universe_record_set_digest": (
            universe.union_record_set_digest
        ),
        "delta_artifact": "post_verify_candidate_delta.json",
        "delta_sha256": _sha(delta_raw),
        "row_count": len(rows),
        "rows": rows,
        "debt_count": len(debts),
        "debts": debts,
        "status": "COMPLETED_WITH_DEBT" if debts else "CLEAN",
    }
    return {**unsigned, "authority_digest": stable_digest(unsigned)}


def write_or_validate_late_verification_authority(
    scratchpad: Path,
    *,
    run_id: str,
    repo_root: Path,
) -> dict[str, Any]:
    """Seal the exact delta-to-recovery evidence join without negative power."""

    root = Path(scratchpad)
    desired = _late_verification_payload(
        root, run_id=run_id, repo_root=Path(repo_root)
    )
    path = root / LATE_AUTHORITY_ARTIFACT
    if path.is_file():
        current, _raw = _strict_json(path)
        if current != desired:
            raise RecoveryExecutionAuthorityError(
                "existing late-verification authority is stale or differs"
            )
        return current
    _atomic_json(path, desired)
    return desired


def load_late_verification_authority(
    scratchpad: Path,
    *,
    run_id: str,
    repo_root: Path,
) -> dict[str, Any]:
    """Replay the authority from source artifacts and reject recomputed forgery."""

    root = Path(scratchpad)
    current, _raw = _strict_json(root / LATE_AUTHORITY_ARTIFACT)
    desired = _late_verification_payload(
        root, run_id=run_id, repo_root=Path(repo_root)
    )
    if current != desired:
        raise RecoveryExecutionAuthorityError(
            "late-verification authority does not replay from source evidence"
        )
    return current


__all__ = [
    "EXECUTION_FIELDS",
    "EXECUTION_SCHEMA",
    "LATE_AUTHORITY_ARTIFACT",
    "LATE_AUTHORITY_SCHEMA",
    "RecoveryExecutionAuthorityError",
    "execution_receipt_digest",
    "load_late_verification_authority",
    "load_recovery_execution_evidence",
    "validate_recovery_execution_receipt",
    "write_or_validate_late_verification_authority",
]
