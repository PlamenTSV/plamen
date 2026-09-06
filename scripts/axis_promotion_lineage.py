"""PhaseIO-backed lineage for inventory tails after axis promotion.

The immutable promotion plan authorizes only its exact predecessor/successor
CAS.  Later phases may append candidates, but prefix equality alone is not
authority.  This provider replays the artifact-binding history and every
stored DRIVER APPEND/MERGE transition from the exact axis successor to the
current live inventory owner.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from artifact_ledger import (
    active_committed_work_unit_authority_issues,
    read_artifact_ledger,
    semantic_import_authority,
    semantic_mutation_authority_digest,
    semantic_mutation_events,
    stored_committed_work_unit_authority_issues,
)


INVENTORY_IDENTITY = "scratchpad:findings_inventory.md"
PROMOTION_RECEIPT_NAME = "axis_coverage_promotion_receipt.json"
PROMOTION_RECEIPT_IDENTITY = f"scratchpad:{PROMOTION_RECEIPT_NAME}"


class AxisPromotionLineageError(ValueError):
    """The current inventory tail lacks contiguous commit authority."""


def _unit_output_identities(unit: Mapping[str, Any]) -> tuple[str, ...]:
    manifest = unit.get("contract_manifest")
    outputs = manifest.get("outputs") if isinstance(manifest, Mapping) else None
    if not isinstance(outputs, list):
        return ()
    identities = tuple(
        str(row.get("identity") or "")
        for row in outputs
        if isinstance(row, Mapping)
    )
    if (
        any(not identity for identity in identities)
        or len(identities) != len(set(identities))
    ):
        return ()
    return identities


def _transition_for(
    unit: Mapping[str, Any],
    identity: str,
) -> Mapping[str, Any] | None:
    commit = unit.get("commit_authority")
    transitions = (
        commit.get("read_modify_write_transitions")
        if isinstance(commit, Mapping)
        else None
    )
    value = transitions.get(identity) if isinstance(transitions, Mapping) else None
    return value if isinstance(value, Mapping) else None


def _semantic_events_for_import(
    *,
    scratchpad: Path,
    run_id: str,
    identity: str,
    authority: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Resolve transition proofs without widening import-authority schemas.

    ``semantic_import_authority`` is embedded in frozen preverify receipts and
    therefore has a deliberately stable field denominator.  Axis promotion
    needs the newer byte-transition proof, so bind the exact current ledger
    rows back to that authority's ordered event IDs and immutable authority
    digests instead of smuggling an axis-only field into the shared record.
    """

    event_ids = authority.get("mutation_event_ids")
    authority_digests = authority.get("mutation_authority_digests")
    if (
        not isinstance(event_ids, list)
        or not isinstance(authority_digests, list)
        or len(event_ids) != len(authority_digests)
        or not event_ids
        or len(event_ids) != len(set(event_ids))
    ):
        raise AxisPromotionLineageError(
            "inventory semantic import event denominator is malformed"
        )
    rows = [
        row
        for row in semantic_mutation_events(Path(scratchpad))
        if (
            row.get("artifact_identity") == str(identity)
            and row.get("run_id") == str(run_id)
        )
    ]
    by_id: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_id.setdefault(str(row.get("event_id") or ""), []).append(row)
    accepted: list[dict[str, Any]] = []
    for event_id, expected_digest in zip(event_ids, authority_digests):
        matches = by_id.get(str(event_id), [])
        if (
            len(matches) != 1
            or semantic_mutation_authority_digest(matches[0])
            != str(expected_digest)
        ):
            raise AxisPromotionLineageError(
                "inventory semantic transition lacks an exact immutable "
                "event-authority match"
            )
        accepted.append(dict(matches[0]))
    return accepted


def _row_core(row: Mapping[str, Any], *, run_id: str) -> tuple[str, str, int]:
    owner = str(row.get("owner_key") or "")
    digest = str(row.get("sha256") or "")
    size = row.get("size")
    if (
        not owner
        or row.get("run_id") != str(run_id)
        or row.get("status") != "ACTIVE"
        or row.get("writer") != "DRIVER"
        or row.get("write_mode") not in {"APPEND", "MERGE"}
        or len(digest) != 64
        or any(char not in "0123456789abcdef" for char in digest)
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size < 0
    ):
        raise AxisPromotionLineageError(
            "inventory binding history row is malformed"
        )
    return owner, digest, size


def authorize_downstream_inventory_tail(
    *,
    scratchpad: Path,
    project_root: Path,
    run_id: str,
    promotion_plan: Mapping[str, Any],
    current_inventory_raw: bytes,
) -> dict[str, Any] | None:
    """Raise unless the later tail has a contiguous committed MERGE lineage."""

    root = Path(scratchpad)
    _project = Path(project_root)
    run = str(run_id or "").strip()
    plan = dict(promotion_plan)
    successor = plan.get("inventory_successor")
    predecessor = plan.get("inventory_before")
    if (
        not run
        or plan.get("run_id") != run
        or not isinstance(successor, Mapping)
        or not isinstance(predecessor, Mapping)
    ):
        raise AxisPromotionLineageError(
            "axis promotion tail plan/run authority is malformed"
        )
    successor_hash = str(successor.get("sha256") or "")
    successor_size = successor.get("size")
    before_hash = str(predecessor.get("sha256") or "")
    phaseio = plan.get("phaseio_authority")
    promotion_binding = (
        phaseio.get("promotion") if isinstance(phaseio, Mapping) else None
    )
    promotion_owner = (
        str(promotion_binding.get("work_unit_key") or "")
        if isinstance(promotion_binding, Mapping)
        else ""
    )
    if not promotion_owner:
        raise AxisPromotionLineageError(
            "axis promotion tail lacks signed promotion owner authority"
        )
    namespace = tuple(promotion_owner.split("/")[:4])
    live = bytes(current_inventory_raw)
    live_hash = hashlib.sha256(live).hexdigest()
    if (
        not isinstance(successor_size, int)
        or isinstance(successor_size, bool)
        or successor_size < 0
    ):
        raise AxisPromotionLineageError(
            "axis promotion successor state is malformed"
        )

    ledger = read_artifact_ledger(root)
    bindings = ledger.get("artifact_bindings")
    current = (
        bindings.get(INVENTORY_IDENTITY)
        if isinstance(bindings, Mapping)
        else None
    )
    if not isinstance(current, Mapping):
        raise AxisPromotionLineageError(
            "current inventory binding is absent"
        )
    prefix_successor = (
        len(live) > successor_size
        and hashlib.sha256(live[:successor_size]).hexdigest()
        == successor_hash
    )
    current_owns_live = bool(
        current.get("run_id") == run
        and current.get("status") == "ACTIVE"
        and current.get("writer") == "DRIVER"
        and current.get("sha256") == live_hash
        and current.get("size") == len(live)
    )
    semantic_successor: dict[str, Any] | None = None
    semantic_has_dedup = False
    semantic_dedup_transition: dict[str, Any] | None = None
    expected_terminal_owner = str(current.get("owner_key") or "")
    expected_terminal_hash = live_hash
    expected_terminal_size = len(live)
    # A byte prefix proves append-only shape, but not who authorized it.  Use
    # the PhaseIO path only while the global binding owns those exact live
    # bytes.  A historical binding plus newer bytes must replay the semantic
    # transaction chain even when the planned successor remains a prefix.
    if not prefix_successor or not current_owns_live:
        try:
            semantic_successor = semantic_import_authority(
                root,
                _project,
                INVENTORY_IDENTITY,
                run_id=run,
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise AxisPromotionLineageError(
                "current inventory preserves neither an append tail nor an "
                f"authorized semantic successor: {exc}"
            ) from exc
        semantic_events = _semantic_events_for_import(
            scratchpad=root,
            run_id=run,
            identity=INVENTORY_IDENTITY,
            authority=semantic_successor,
        )
        kinds = [
            str(event.get("mutation_kind") or "")
            for event in semantic_events
        ]
        transitions = [
            dict(event.get("transition_authority") or {})
            for event in semantic_events
        ]
        additive_kinds = {
            "FINDING_PROMOTION",
            "GATE_P_ADDITIVE_PROMOTION",
        }
        dedup_seen = False
        additive_seen = False
        exact_chain = bool(
            semantic_successor.get("authority_kind")
            == "CONTIGUOUS_SEMANTIC_MUTATION_CHAIN"
            and isinstance(transitions, list)
            and len(transitions) == len(kinds)
        )
        if exact_chain:
            for kind, transition in zip(kinds, transitions):
                is_dedup = (
                    kind == "RECEIPT_AUTHORIZED_SEMANTIC_DEDUP"
                    or kind.startswith("SEMANTIC_DEDUP_TRANSACTION_")
                )
                if is_dedup:
                    if (
                        not isinstance(transition, Mapping)
                        or transition.get("transition_kind")
                        not in {"NO_CHANGE", "REPLACEMENT"}
                    ):
                        exact_chain = False
                        break
                    dedup_seen = True
                    semantic_dedup_transition = dict(transition)
                    continue
                if (
                    kind not in additive_kinds
                    or not isinstance(transition, Mapping)
                    or transition.get("transition_kind") != "STRICT_APPEND"
                ):
                    exact_chain = False
                    break
                additive_seen = True
        if not exact_chain or not (additive_seen or dedup_seen):
            raise AxisPromotionLineageError(
                "inventory semantic successor is not an exact additive and/or "
                "dedup transaction lineage"
            )
        semantic_has_dedup = dedup_seen
        expected_terminal_owner = str(current.get("owner_key") or "")
        expected_terminal_hash = str(current.get("sha256") or "")
        expected_terminal_size = int(current.get("size") or 0)
    if (
        current.get("run_id") != run
        or current.get("status") != "ACTIVE"
        or current.get("writer") != "DRIVER"
        or current.get("owner_key") != expected_terminal_owner
        or current.get("sha256") != expected_terminal_hash
        or current.get("size") != expected_terminal_size
    ):
        raise AxisPromotionLineageError(
            "current inventory binding does not own the authorized lineage "
            "preimage"
        )
    history = current.get("history")
    if not isinstance(history, list) or any(
        not isinstance(row, Mapping) for row in history
    ):
        raise AxisPromotionLineageError(
            "inventory binding history is absent or malformed"
        )
    rows = [dict(row) for row in history] + [dict(current)]
    starts = [
        index
        for index, row in enumerate(rows)
        if (
            str(row.get("owner_key") or "") == promotion_owner
            and row.get("run_id") == run
            and row.get("sha256") == successor_hash
            and row.get("size") == successor_size
        )
    ]
    if len(starts) != 1:
        raise AxisPromotionLineageError(
            "inventory history has no unique exact axis-promotion successor"
        )
    chain = rows[starts[0]:]
    if len(chain) < (1 if semantic_successor is not None else 2):
        raise AxisPromotionLineageError(
            "downstream tail has no successor producer"
        )
    work_units = ledger.get("work_units")
    if not isinstance(work_units, Mapping):
        raise AxisPromotionLineageError("work-unit ledger is absent")

    previous_owner = ""
    previous_hash = before_hash
    previous_size = int(predecessor.get("size") or 0)
    for index, row in enumerate(chain):
        owner, digest, size = _row_core(row, run_id=run)
        if tuple(owner.split("/")[:4]) != namespace:
            raise AxisPromotionLineageError(
                f"inventory lineage crosses a backend namespace: {owner}"
            )
        unit = work_units.get(owner)
        if not isinstance(unit, Mapping):
            raise AxisPromotionLineageError(
                f"inventory lineage work unit is absent: {owner}"
            )
        output_ids = _unit_output_identities(unit)
        if INVENTORY_IDENTITY not in output_ids:
            raise AxisPromotionLineageError(
                f"inventory lineage unit omits inventory output: {owner}"
            )
        stored_issues = stored_committed_work_unit_authority_issues(
            ledger,
            work_unit_key=owner,
            run_id=run,
            expected_artifact_identities=output_ids,
        )
        if stored_issues:
            raise AxisPromotionLineageError("; ".join(stored_issues))
        artifacts = unit.get("artifacts")
        artifact = (
            artifacts.get(INVENTORY_IDENTITY)
            if isinstance(artifacts, Mapping)
            else None
        )
        prestate_map = unit.get("output_prestates")
        prestate = (
            prestate_map.get(INVENTORY_IDENTITY)
            if isinstance(prestate_map, Mapping)
            else None
        )
        transition = _transition_for(unit, INVENTORY_IDENTITY)
        if (
            not isinstance(artifact, Mapping)
            or artifact.get("run_id") != run
            or artifact.get("status") != "ACTIVE"
            or artifact.get("writer") != "DRIVER"
            or artifact.get("write_mode") not in {"APPEND", "MERGE"}
            or artifact.get("sha256") != digest
            or artifact.get("size") != size
            or not isinstance(prestate, Mapping)
            or not isinstance(transition, Mapping)
            or transition.get("write_mode") not in {"APPEND", "MERGE"}
            or transition.get("preimage_sha256") != previous_hash
            or transition.get("successor_sha256") != digest
            or prestate.get("sha256") != previous_hash
            or prestate.get("size") != previous_size
        ):
            raise AxisPromotionLineageError(
                f"inventory lineage transition is not contiguous: {owner}"
            )
        if index:
            if (
                prestate.get("predecessor_owner_key")
                != previous_owner
            ):
                raise AxisPromotionLineageError(
                    f"inventory lineage predecessor owner differs: {owner}"
                )
        elif owner != promotion_owner:
            raise AxisPromotionLineageError(
                "inventory lineage does not start at axis promotion"
            )
        previous_owner = owner
        previous_hash = digest
        previous_size = size

    latest_owner = str(current.get("owner_key") or "")
    if previous_owner != latest_owner:
        raise AxisPromotionLineageError(
            "inventory lineage does not end at the current owner"
        )
    latest = work_units.get(latest_owner)
    latest_outputs = (
        _unit_output_identities(latest)
        if isinstance(latest, Mapping)
        else ()
    )
    active_issues = active_committed_work_unit_authority_issues(
        ledger,
        work_unit_key=latest_owner,
        run_id=run,
        expected_artifact_identities=latest_outputs,
    )
    if active_issues:
        raise AxisPromotionLineageError("; ".join(active_issues))
    if semantic_successor is not None:
        try:
            import axis_disposition as axis_authority
            live_text = live.decode("utf-8", errors="strict")
            aliases: Mapping[str, Any] = {}
            if semantic_has_dedup:
                from semantic_dedup_authority import load_applied_aliases

                if not isinstance(semantic_dedup_transition, Mapping):
                    raise AxisPromotionLineageError(
                        "semantic dedup transition authority is absent"
                    )
                dedup_size = semantic_dedup_transition.get("successor_size")
                dedup_hash = str(
                    semantic_dedup_transition.get("successor_sha256") or ""
                )
                if (
                    not isinstance(dedup_size, int)
                    or isinstance(dedup_size, bool)
                    or dedup_size < 0
                    or len(live) < dedup_size
                    or hashlib.sha256(live[:dedup_size]).hexdigest()
                    != dedup_hash
                ):
                    raise AxisPromotionLineageError(
                        "later additive bytes do not preserve the exact "
                        "semantic-dedup postimage prefix"
                    )
                dedup_text = live[:dedup_size].decode(
                    "utf-8", errors="strict"
                )
                aliases = load_applied_aliases(
                    root,
                    canonical_text=dedup_text,
                )
            live_blocks = axis_authority._v2_inventory_blocks(live_text)
        except (OSError, RuntimeError, TypeError, UnicodeError, ValueError) as exc:
            raise AxisPromotionLineageError(
                f"semantic dedup successor receipt is invalid: {exc}"
            ) from exc
        planned = {
            str(row.get("action_id") or ""): str(
                row.get("inventory_id") or ""
            )
            for row in plan.get("planned_deliveries", ())
            if isinstance(row, Mapping)
        }
        preexisting = {
            str(value)
            for value in plan.get("preexisting_action_ids", ())
            if str(value)
        }
        preserved: list[str] = []
        for action_id in sorted(set(planned) | preexisting):
            original_id = planned.get(action_id, "")
            survivor_id = (
                str(aliases.get(original_id, {}).get("survivor") or original_id)
                if original_id
                else ""
            )
            claims = [
                row
                for row in live_blocks
                if (
                    axis_authority._v2_exact_source_claim(
                        str(row.get("source_ids") or ""),
                        action_id,
                    )
                    and (
                        not survivor_id
                        or str(row.get("inventory_id") or "") == survivor_id
                    )
                )
            ]
            if len(claims) != 1:
                raise AxisPromotionLineageError(
                    "semantic dedup successor does not preserve exactly one "
                    f"live claim for axis action {action_id}"
                )
            preserved.append(action_id)
        return {
            "authority_kind": "RECEIPT_AUTHORIZED_SEMANTIC_SUCCESSOR",
            "preserved_action_ids": preserved,
            "semantic_import": semantic_successor,
        }
    return None


def committed_promotion_output_issues(
    *,
    scratchpad: Path,
    project_root: Path,
    run_id: str,
    promotion_plan: Mapping[str, Any] | None = None,
) -> list[str]:
    """Validate the promotion pair, including a later committed inventory tail."""

    root = Path(scratchpad)
    run = str(run_id)
    ledger = read_artifact_ledger(root)
    phaseio = (
        promotion_plan.get("phaseio_authority")
        if isinstance(promotion_plan, Mapping)
        else None
    )
    signed_binding = (
        phaseio.get("promotion") if isinstance(phaseio, Mapping) else None
    )
    key = (
        str(signed_binding.get("work_unit_key") or "")
        if isinstance(signed_binding, Mapping)
        else ""
    )
    if not key and promotion_plan is None:
        legacy_matches = [
            str(candidate)
            for candidate, raw_unit in dict(
                ledger.get("work_units") or {}
            ).items()
            if (
                isinstance(raw_unit, Mapping)
                and raw_unit.get("run_id") == run
                and raw_unit.get("semantic_status") == "ACTIVE"
                and str(candidate).endswith(
                    "/axis_disposition/promotion"
                )
            )
        ]
        if len(legacy_matches) == 1:
            key = legacy_matches[0]
    if not key:
        return [
            "axis promotion has no signed current-run PhaseIO MERGE owner"
        ]
    identities = (INVENTORY_IDENTITY, PROMOTION_RECEIPT_IDENTITY)
    unit = dict(ledger.get("work_units") or {}).get(key)
    records = (
        dict(unit.get("artifacts") or {})
        if isinstance(unit, Mapping)
        else {}
    )
    inventory_record = records.get(INVENTORY_IDENTITY)
    receipt_record = records.get(PROMOTION_RECEIPT_IDENTITY)
    issues: list[str] = []
    if isinstance(unit, Mapping) and isinstance(signed_binding, Mapping):
        observed_binding = {
            "work_unit_key": key,
            "contract_digest": str(unit.get("contract_digest") or ""),
            "launch_digest": str(unit.get("launch_digest") or ""),
        }
        if dict(signed_binding) != observed_binding:
            issues.append(
                "axis promotion PhaseIO owner differs from immutable plan"
            )
    try:
        inventory_raw = (root / "findings_inventory.md").read_bytes()
    except OSError as exc:
        inventory_raw = b""
        issues.append(
            f"{INVENTORY_IDENTITY}: committed live artifact is unreadable: "
            f"{type(exc).__name__}: {exc}"
        )
    try:
        receipt_raw = (root / PROMOTION_RECEIPT_NAME).read_bytes()
    except OSError as exc:
        receipt_raw = b""
        issues.append(
            f"{PROMOTION_RECEIPT_IDENTITY}: committed live artifact is "
            f"unreadable: {type(exc).__name__}: {exc}"
        )
    if not isinstance(inventory_record, Mapping):
        issues.append(
            f"{INVENTORY_IDENTITY}: committed artifact record is absent"
        )
    if not isinstance(receipt_record, Mapping):
        issues.append(
            f"{PROMOTION_RECEIPT_IDENTITY}: committed artifact record is absent"
        )
    if isinstance(receipt_record, Mapping) and (
        hashlib.sha256(receipt_raw).hexdigest() != receipt_record.get("sha256")
        or len(receipt_raw) != receipt_record.get("size")
    ):
        issues.append(
            f"{PROMOTION_RECEIPT_IDENTITY}: live bytes differ from committed "
            "promotion artifact"
        )
    if issues:
        return list(dict.fromkeys(str(value) for value in issues if str(value)))

    exact_inventory = (
        isinstance(inventory_record, Mapping)
        and hashlib.sha256(inventory_raw).hexdigest()
        == inventory_record.get("sha256")
        and len(inventory_raw) == inventory_record.get("size")
    )
    if exact_inventory:
        issues.extend(
            active_committed_work_unit_authority_issues(
                ledger,
                work_unit_key=key,
                run_id=run,
                expected_artifact_identities=identities,
            )
        )
        return list(dict.fromkeys(str(value) for value in issues if str(value)))

    if not isinstance(promotion_plan, Mapping):
        return [
            f"{INVENTORY_IDENTITY}: live bytes differ from committed promotion "
            "artifact without immutable plan authority"
        ]
    successor = promotion_plan.get("inventory_successor")
    if (
        not isinstance(successor, Mapping)
        or not isinstance(inventory_record, Mapping)
        or inventory_record.get("sha256") != successor.get("sha256")
        or inventory_record.get("size") != successor.get("size")
    ):
        issues.append(
            f"{INVENTORY_IDENTITY}: stored promotion output differs from "
            "immutable planned successor"
        )
    issues.extend(
        stored_committed_work_unit_authority_issues(
            ledger,
            work_unit_key=key,
            run_id=run,
            expected_artifact_identities=identities,
        )
    )
    receipt_binding = dict(ledger.get("artifact_bindings") or {}).get(
        PROMOTION_RECEIPT_IDENTITY
    )
    if (
        not isinstance(receipt_binding, Mapping)
        or receipt_binding.get("status") != "ACTIVE"
        or receipt_binding.get("owner_key") != key
        or receipt_binding.get("run_id") != run
        or receipt_binding.get("sha256") != receipt_record.get("sha256")
        or receipt_binding.get("size") != receipt_record.get("size")
    ):
        issues.append(
            f"{PROMOTION_RECEIPT_IDENTITY}: current binding no longer owns the "
            "exact promotion receipt"
        )
    if not issues:
        try:
            authorize_downstream_inventory_tail(
                scratchpad=root,
                project_root=Path(project_root),
                run_id=run,
                promotion_plan=promotion_plan,
                current_inventory_raw=inventory_raw,
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            issues.append(
                "axis promotion downstream inventory lineage is invalid: "
                f"{type(exc).__name__}: {exc}"
            )
    return list(dict.fromkeys(str(value) for value in issues if str(value)))


__all__ = [
    "AxisPromotionLineageError",
    "INVENTORY_IDENTITY",
    "PROMOTION_RECEIPT_IDENTITY",
    "PROMOTION_RECEIPT_NAME",
    "authorize_downstream_inventory_tail",
    "committed_promotion_output_issues",
]
