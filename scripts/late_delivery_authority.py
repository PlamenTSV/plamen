"""Independent recovery-execution authority for post-verify delivery state.

``post_verify_late_delivery.json`` is a driver projection, not proof that a
recovery verifier ran.  This module re-derives the only positive delivery state
from immutable recovery inputs, the foreground launch contract, the exact
execution denominator, and the bound operator receipt.  Failure is monotonic:
it can retain human-review debt but can never create a verified disposition.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from verification_method_compiler import (
    bind_operator_application_receipt,
    load_bound_operator_receipt,
    stable_digest,
)
from verification_recovery_contract import validate_verification_recovery_contract
from verifier_work_roster import VerifierLaunchSpec


RECOVERY_EXECUTION_SCHEMA = "plamen.verification_recovery_execution.v1"
INDEPENDENT_VERIFICATION_RECORDED = "INDEPENDENT_VERIFICATION_RECORDED"
UNVERIFIED_HUMAN_REVIEW = "UNVERIFIED_HUMAN_REVIEW"
_LATE_RECOVERY_KINDS = frozenset(
    {"POST_VERIFY_SIDE_OBSERVATION", "LATE_OPERATOR_CANDIDATE"}
)
_EXECUTION_FIELDS = frozenset(
    {
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
    }
)
_SEMANTIC_BINDING_FIELDS = (
    "work_item_id",
    "source_candidate_digest",
    "source_work_item_id",
    "source_identity",
    "source_operator_receipt",
    "source_operator_receipt_sha256",
    "source_operator_receipt_digest",
    "finding_lifecycle_obligation_id",
    "title",
    "mechanism",
    "evidence",
    "bug_class",
    "severity",
    "producer_identity",
    "required_discriminator_identity",
    "independent_discriminator_required",
)


class LateDeliveryAuthorityError(ValueError):
    """Recovery artifacts cannot support a positive delivery state."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _verdict(path: Path) -> str:
    text = Path(path).read_text(encoding="utf-8", errors="strict")
    match = re.search(
        r"(?im)^\s*(?:[-*]\s*)?\*{0,2}Verdict\*{0,2}\s*:\s*"
        r"([A-Z][A-Z0-9_-]*)",
        text,
    )
    return match.group(1).upper() if match else "CONTESTED"


def _strict_json(path: Path) -> dict[str, Any]:
    def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise LateDeliveryAuthorityError(
                    f"duplicate JSON field in {path.name}: {key}"
                )
            value[key] = item
        return value

    try:
        value = json.loads(
            Path(path).read_text(encoding="utf-8", errors="strict"),
            object_pairs_hook=strict_object,
            parse_constant=lambda item: (_ for _ in ()).throw(
                LateDeliveryAuthorityError(f"invalid JSON constant: {item}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LateDeliveryAuthorityError(
            f"{path.name} is unreadable: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise LateDeliveryAuthorityError(f"{path.name} must contain an object")
    return value


def _validate_materialized_inputs(
    directory: Path, contract: Mapping[str, Any]
) -> None:
    expected = {
        "manifest.md": str(contract["manifest_markdown"]).encode("utf-8"),
        "verification_context_packets.json": (
            json.dumps(
                contract["context_packets"],
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
            + "\n"
        ).encode("utf-8"),
        "method_dispatch.json": (
            json.dumps(
                contract["method_dispatch"],
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
            + "\n"
        ).encode("utf-8"),
        "prompt.md": str(contract["prompt_markdown"]).encode("utf-8"),
    }
    path_fields = {
        "manifest.md": "manifest_path",
        "verification_context_packets.json": "context_path",
        "method_dispatch.json": "method_dispatch_path",
        "prompt.md": "prompt_path",
    }
    for name, content in expected.items():
        path = directory.parent.parent / str(contract[path_fields[name]])
        try:
            actual = path.read_bytes()
        except OSError as exc:
            raise LateDeliveryAuthorityError(
                f"materialized recovery input is missing: {name}"
            ) from exc
        if actual != content:
            raise LateDeliveryAuthorityError(
                f"materialized recovery input changed: {name}"
            )


def _validate_launch(
    directory: Path, contract: Mapping[str, Any]
) -> VerifierLaunchSpec:
    try:
        launch = VerifierLaunchSpec.from_json(
            (directory / "launch_spec.json").read_text(
                encoding="utf-8", errors="strict"
            )
        )
    except Exception as exc:
        raise LateDeliveryAuthorityError(
            f"recovery launch spec is invalid: {type(exc).__name__}: {exc}"
        ) from exc
    prompt_bytes = str(contract["prompt_markdown"]).encode("utf-8")
    expected = {
        "work_unit_id": str(contract["recovery_id"]).lower(),
        "work_unit_resume_digest": contract["contract_digest"],
        "backend": contract["backend"],
        "prompt_sha256": hashlib.sha256(prompt_bytes).hexdigest(),
        "prompt_size_bytes": len(prompt_bytes),
        "expected_output_files": tuple(contract["expected_model_outputs"]),
    }
    actual = {
        "work_unit_id": launch.work_unit_id,
        "work_unit_resume_digest": launch.work_unit_resume_digest,
        "backend": launch.backend,
        "prompt_sha256": launch.prompt_sha256,
        "prompt_size_bytes": launch.prompt_size_bytes,
        "expected_output_files": launch.expected_output_files,
    }
    if actual != expected:
        raise LateDeliveryAuthorityError(
            "recovery launch spec is not bound to the exact recovery contract"
        )
    return launch


def validate_recovery_execution_authority(
    path: Path,
    *,
    contract: Mapping[str, Any],
    launch_spec: VerifierLaunchSpec,
    scratchpad: Path,
) -> dict[str, Any]:
    """Validate the exact recovery denominator independently of delivery state."""

    payload = _strict_json(Path(path))
    if set(payload) != _EXECUTION_FIELDS:
        raise LateDeliveryAuthorityError("recovery execution fields are not exact")
    if payload["schema_version"] != RECOVERY_EXECUTION_SCHEMA:
        raise LateDeliveryAuthorityError("recovery execution schema mismatch")
    exact = {
        "recovery_id": contract["recovery_id"],
        "recovery_kind": contract["recovery_kind"],
        "contract_digest": contract["contract_digest"],
        "launch_spec_digest": launch_spec.digest,
        "ordered_work_item_ids": [
            str(row["work_item_id"]) for row in contract["rows"]
        ],
        "terminal_negative_authority": False,
    }
    if any(payload.get(field) != expected for field, expected in exact.items()):
        raise LateDeliveryAuthorityError(
            "recovery execution identity or denominator changed"
        )
    ordered = exact["ordered_work_item_ids"]
    unresolved = payload["unresolved_work_item_ids"]
    issues = payload["issues"]
    if (
        not isinstance(unresolved, list)
        or len(unresolved) != len(set(unresolved))
        or unresolved
        != [work_id for work_id in ordered if work_id in set(unresolved)]
        or any(work_id not in ordered for work_id in unresolved)
        or not isinstance(issues, list)
        or any(not isinstance(issue, str) or not issue.strip() for issue in issues)
    ):
        raise LateDeliveryAuthorityError(
            "recovery execution unresolved denominator is invalid"
        )
    issue_ids = {
        work_id
        for work_id in ordered
        if any(issue.startswith(f"{work_id}:") for issue in issues)
    }
    if issue_ids != set(unresolved):
        raise LateDeliveryAuthorityError(
            "recovery execution issues do not explain the unresolved set"
        )
    expected_status = "COMPLETED" if not unresolved else "COMPLETED_WITH_DEBT"
    if payload["status"] != expected_status:
        raise LateDeliveryAuthorityError("recovery execution status mismatch")
    unsigned = {key: value for key, value in payload.items() if key != "receipt_digest"}
    if payload["receipt_digest"] != stable_digest(unsigned):
        raise LateDeliveryAuthorityError("recovery execution digest mismatch")
    output_hashes = payload["output_sha256"]
    operator_hashes = payload["operator_receipt_sha256"]
    if not isinstance(output_hashes, dict) or not isinstance(operator_hashes, dict):
        raise LateDeliveryAuthorityError(
            "recovery execution output maps are invalid"
        )
    root = Path(scratchpad)
    expected_outputs = {
        name: _sha256(root / name)
        for name in contract["expected_model_outputs"]
        if (root / name).is_file()
    }
    expected_receipts = {
        name: _sha256(root / name)
        for name in contract["expected_operator_receipts"]
        if (root / name).is_file()
    }
    if output_hashes != expected_outputs:
        raise LateDeliveryAuthorityError(
            "recovery execution model-output exact set changed"
        )
    if operator_hashes != expected_receipts:
        raise LateDeliveryAuthorityError(
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
        if not model_names.issubset(output_hashes) or receipt_name not in operator_hashes:
            raise LateDeliveryAuthorityError(
                f"resolved recovery row lacks exact outputs: {work_id}"
            )
        try:
            receipt = load_bound_operator_receipt(
                receipt_path=root / receipt_name,
                proposal_path=root / f"verify_{work_id}.operator_application.json",
                verify_path=root / f"verify_{work_id}.md",
                dispatch=dispatch,
                launch_digest=launch_spec.digest,
            )
            rebound = bind_operator_application_receipt(
                proposal_path=root / f"verify_{work_id}.operator_application.json",
                verify_path=root / f"verify_{work_id}.md",
                receipt_path=root / receipt_name,
                dispatch=dispatch,
                launch_digest=launch_spec.digest,
                verdict=_verdict(root / f"verify_{work_id}.md"),
            )
            if receipt != rebound:
                raise LateDeliveryAuthorityError(
                    "operator receipt differs from independently re-derived receipt"
                )
        except Exception as exc:
            raise LateDeliveryAuthorityError(
                f"resolved recovery operator receipt is unbound: {work_id}: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
    return payload


def _matches_expected_work(
    row: Mapping[str, Any], expected_work: Mapping[str, Any]
) -> bool:
    for field in _SEMANTIC_BINDING_FIELDS:
        if field not in expected_work:
            continue
        expected = expected_work[field]
        if field == "work_item_id" or expected is not None:
            if row.get(field) != expected:
                return False
    return True


def derive_late_delivery_recovery_authority(
    scratchpad: Path,
    *,
    run_id: str,
    expected_work: Mapping[str, Any],
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """Derive a positive delivery state from one exact, current recovery.

    Multiple semantically matching recoveries have no implicit supersession
    order.  They therefore remain human-review work until a separate current-
    attempt authority exists; accepting any one would make stale replay a
    positive-verification oracle.
    """

    root = Path(scratchpad)
    work_id = str(expected_work.get("work_item_id") or "").strip()
    if not work_id:
        raise LateDeliveryAuthorityError("expected late work identity is empty")
    recovery_root = root / "_verification_recovery"
    matches: list[dict[str, Any]] = []
    global_issues: list[str] = []
    if recovery_root.is_dir():
        paths = sorted(
            recovery_root.glob("VREC-*/contract.json"),
            key=lambda value: value.as_posix(),
        )
    else:
        paths = []
    for path in paths:
        directory = path.parent
        try:
            raw = _strict_json(path)
        except LateDeliveryAuthorityError as exc:
            global_issues.append(f"{directory.name}: {exc}")
            continue
        raw_rows = raw.get("rows")
        raw_match = bool(
            isinstance(raw_rows, list)
            and any(
                isinstance(row, Mapping)
                and row.get("work_item_id") == work_id
                for row in raw_rows
            )
        )
        try:
            contract = validate_verification_recovery_contract(
                raw, repo_root=repo_root
            )
            if directory.name != contract["recovery_id"]:
                raise LateDeliveryAuthorityError(
                    "recovery directory identity differs from its contract"
                )
            if contract["run_id"] != run_id:
                continue
            if contract["recovery_kind"] not in _LATE_RECOVERY_KINDS:
                continue
            exact_row = next(
                (
                    row
                    for row in contract["rows"]
                    if row["work_item_id"] == work_id
                    and _matches_expected_work(row, expected_work)
                ),
                None,
            )
            if exact_row is None:
                continue
            _validate_materialized_inputs(directory, contract)
            launch = _validate_launch(directory, contract)
            execution = validate_recovery_execution_authority(
                directory / "execution_receipt.json",
                contract=contract,
                launch_spec=launch,
                scratchpad=root,
            )
            matches.append(
                {
                    "recovery_id": contract["recovery_id"],
                    "contract_digest": contract["contract_digest"],
                    "launch_spec_digest": launch.digest,
                    "execution_receipt_digest": execution["receipt_digest"],
                    "state": (
                        UNVERIFIED_HUMAN_REVIEW
                        if work_id in execution["unresolved_work_item_ids"]
                        else INDEPENDENT_VERIFICATION_RECORDED
                    ),
                    "issue": None,
                }
            )
        except Exception as exc:
            if raw_match:
                matches.append(
                    {
                        "recovery_id": str(raw.get("recovery_id") or directory.name),
                        "contract_digest": raw.get("contract_digest"),
                        "launch_spec_digest": None,
                        "execution_receipt_digest": None,
                        "state": UNVERIFIED_HUMAN_REVIEW,
                        "issue": f"{type(exc).__name__}: {exc}",
                    }
                )
    matches.sort(key=lambda row: str(row["recovery_id"]))
    issues = [str(row["issue"]) for row in matches if row["issue"]]
    issues.extend(global_issues)
    clean_verified = (
        len(matches) == 1
        and not issues
        and matches[0]["state"] == INDEPENDENT_VERIFICATION_RECORDED
    )
    if not matches:
        issues.append("no exact recovery execution authority exists")
    elif len(matches) != 1:
        issues.append("multiple matching recovery executions lack supersession authority")
    elif matches[0]["state"] != INDEPENDENT_VERIFICATION_RECORDED:
        issues.append("the exact recovery execution retains this work item unresolved")
    return {
        "work_item_id": work_id,
        "derived_state": (
            INDEPENDENT_VERIFICATION_RECORDED
            if clean_verified
            else UNVERIFIED_HUMAN_REVIEW
        ),
        "match_count": len(matches),
        "matches": matches,
        "issues": list(dict.fromkeys(issues)),
        "positive_authority": clean_verified,
    }


__all__ = [
    "INDEPENDENT_VERIFICATION_RECORDED",
    "LateDeliveryAuthorityError",
    "RECOVERY_EXECUTION_SCHEMA",
    "UNVERIFIED_HUMAN_REVIEW",
    "derive_late_delivery_recovery_authority",
    "validate_recovery_execution_authority",
]
