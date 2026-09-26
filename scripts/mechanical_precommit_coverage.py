"""Typed queue denominator reconciliation for mechanical precommit."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from verification_policy import ExecutionPolicy


_MAX_MANIFEST_BYTES = 32 * 1024 * 1024


def _strict_result_ids(path: Path) -> tuple[str, ...]:
    with path.open("rb") as stream:
        raw = stream.read(_MAX_MANIFEST_BYTES + 1)
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise ValueError("mechanical result manifest exceeds byte budget")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, member in pairs:
            if key in value:
                raise ValueError(
                    f"mechanical result manifest duplicates key {key!r}"
                )
            value[key] = member
        return value

    manifest = json.loads(
        raw.decode("utf-8", errors="strict"),
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=lambda token: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON number {token}")
        ),
    )
    if not isinstance(manifest, dict) or set(manifest) != {
        "generated_at", "counts", "results",
    }:
        raise ValueError("mechanical result manifest schema mismatch")
    results = manifest.get("results")
    if not isinstance(results, list):
        raise ValueError("mechanical result rows must be a list")
    observed: list[str] = []
    folded: set[str] = set()
    for index, row in enumerate(results):
        if not isinstance(row, dict):
            raise ValueError(f"mechanical result row {index} is not an object")
        finding_id = row.get("finding_id")
        if (
            not isinstance(finding_id, str)
            or not finding_id
            or finding_id != finding_id.strip()
        ):
            raise ValueError(
                f"mechanical result row {index} has invalid finding_id"
            )
        key = finding_id.casefold()
        if key in folded:
            raise ValueError(
                "mechanical result manifest contains duplicate/case-colliding "
                f"identity {finding_id}"
            )
        folded.add(key)
        observed.append(finding_id)
    return tuple(observed)


def mechanical_precommit_queue_coverage_issues(
    scratchpad: Path,
    policy: ExecutionPolicy,
) -> list[str]:
    """Compare result identities with the current policy-mandatory queue."""
    from plamen_parsers import _read_typed_queue_work_items, read_queue_work_plan
    from plamen_validators import _poc_contract_required

    root = Path(scratchpad)
    plan = read_queue_work_plan(root)
    items = _read_typed_queue_work_items(root / "verification_queue.md")
    by_id = {item.work_item_id: item for item in items}
    if set(by_id) != set(plan.ordered_work_item_ids):
        raise ValueError("typed queue identities differ from QueueWorkPlan")
    mandatory = {
        work_id
        for work_id in plan.ordered_work_item_ids
        if _poc_contract_required(
            {
                "finding id": work_id,
                "severity": by_id[work_id].severity_proposal.level,
                "poc class": by_id[work_id].poc_class,
            },
            policy.mode.value,
            execution_policy=policy,
        )
    }
    try:
        observed = _strict_result_ids(root / "mechanical_verify_manifest.json")
    except Exception as exc:
        return [
            "mechanical verification result denominator invalid: "
            f"{type(exc).__name__}: {exc}"
        ]

    observed_set = set(observed)
    queue_set = set(plan.ordered_work_item_ids)
    issues: list[str] = []
    omitted = sorted(mandatory - observed_set)
    foreign = sorted(observed_set - queue_set)
    if omitted:
        issues.append(
            "mechanical verification omitted mandatory queue identities: "
            + ", ".join(omitted)
        )
    if foreign:
        issues.append(
            "mechanical verification contains foreign queue identities: "
            + ", ".join(foreign)
        )
    return issues


__all__ = ["mechanical_precommit_queue_coverage_issues"]
