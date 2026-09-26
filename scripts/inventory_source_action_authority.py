"""Canonical authentication for manifest-selected inventory source actions."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Sequence

from finding_producer_registry import (
    producer_accepts_local_id,
    producer_for_artifact,
)
from plamen_parsers import (
    _parse_depth_finding_blocks,
    _parse_inventory_chunk,
)


_AMBIGUOUS_IDENTITY_DEBT: dict[tuple[str, str], list[str]] = {}


class InventorySourceActionError(ValueError):
    """The selected source denominator cannot authenticate exactly."""


def bind_exact_source_actions(
    root: Path,
    source_names: Sequence[str],
    entries: Sequence[dict[str, object]],
) -> list[str]:
    """Bind chunk claims to exact canonical producer actions in place.

    ``source_names`` is the publisher/manifest-selected denominator. Producer
    resolution deliberately uses ``canonical_identity``: selection capability
    and identity authentication are separate authorities.
    """

    base = Path(root)
    denominator = set(source_names)
    available: dict[tuple[str, str], str] = {}
    ambiguous_identities: list[str] = []
    for name in sorted(denominator):
        producer = producer_for_artifact(
            name, consumer="canonical_identity"
        )
        if producer is None:
            continue
        path = base / name
        if not path.is_file():
            continue
        source_hash = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        seen_action_ids: set[str] = set()
        ambiguous_action_ids: set[str] = set()
        for block in _parse_depth_finding_blocks(
            path, consumer="canonical_identity"
        ):
            action_id = str(block.get("id") or "").strip().upper()
            if action_id and action_id in seen_action_ids:
                # A repeated producer-local ID genuinely cannot authenticate a
                # unique source action -- so it must not bind. But RAISING here
                # failed the whole critical phase over an UPSTREAM artifact's
                # naming, which the inventory shard has no power to correct:
                # the unwinnable-contract failure mode.
                #
                # Observed in DODO run38: a per-contract worker wrote its
                # duplicate-suppression bookkeeping as `### RS-1 (...)` section
                # headings (RS-1..RS-5 are RESCAN METHODOLOGY STEP numbers, not
                # identities), so one artifact yielded four blocks all claiming
                # `RS-1` and killed `inventory_chunk_b`.
                #
                # Tightening the heading parser instead is NOT safe: measured
                # across that run's artifacts, requiring a bracketed ID would
                # have dropped 11 blocks from four artifacts that legitimately
                # use unbracketed per-contract/rescan headings.
                #
                # So withhold authentication for the ambiguous ID, keep every
                # unambiguous identity in the artifact usable, and let the
                # caller surface typed debt. Nothing is silently merged: an
                # ambiguous key binds to NOTHING rather than to an arbitrary
                # one of its claimants.
                ambiguous_action_ids.add(action_id)
                available.pop((name, action_id), None)
                continue
            if action_id:
                seen_action_ids.add(action_id)
            if (
                action_id
                and action_id not in ambiguous_action_ids
                and producer_accepts_local_id(producer, action_id)
            ):
                available[(name, action_id)] = source_hash
        for action_id in sorted(ambiguous_action_ids):
            ambiguous_identities.append(f"{name}:{action_id}")

    for entry in entries:
        bound: list[tuple[str, str, str]] = []
        for raw in entry.get("source_actions", []) or []:
            if not isinstance(raw, (tuple, list)) or len(raw) != 2:
                continue
            artifact = str(raw[0] or "").strip()
            action_id = str(raw[1] or "").strip().upper()
            source_hash = available.get((artifact, action_id))
            if source_hash is None or artifact not in denominator:
                continue
            row = (artifact, action_id, source_hash)
            if row not in bound:
                bound.append(row)
        entry["source_actions"] = bound
    return ambiguous_identities

def ambiguous_identity_debt(root: Path, chunk_name: str) -> list[str]:
    """Upstream identities that could not authenticate, for the caller to log."""

    return list(_AMBIGUOUS_IDENTITY_DEBT.get((str(root), str(chunk_name))) or ())


def _record_ambiguous_identities(
    root: Path, chunk_name: str, ambiguous: Sequence[str]
) -> None:
    key = (str(root), str(chunk_name))
    if ambiguous:
        _AMBIGUOUS_IDENTITY_DEBT[key] = list(ambiguous)
    else:
        _AMBIGUOUS_IDENTITY_DEBT.pop(key, None)


def validate_inventory_chunk_source_actions(
    root: Path,
    *,
    chunk_name: str,
    source_names: Sequence[str],
) -> list[str]:
    """Require one unique authenticated source action for every chunk row."""

    base = Path(root)
    chunk_path = base / chunk_name
    if not chunk_path.is_file():
        return [f"{chunk_name} missing"]
    entries = _parse_inventory_chunk(chunk_path)
    try:
        ambiguous = bind_exact_source_actions(base, source_names, entries)
    except (InventorySourceActionError, OSError, ValueError) as exc:
        return [f"source-action authentication failed: {exc}"]

    issues: list[str] = []
    # NOTE: `ambiguous` is deliberately NOT appended to `issues`. Gating on it
    # would re-create the unwinnable contract in a politer form -- the shard
    # cannot repair an upstream artifact's duplicate headings, so failing it
    # buys a rewrite that cannot help. It binds to nothing either way, so any
    # chunk row that really depends on it still fails its own authentication
    # check below. The caller logs it; `INVENTORY_UPSTREAM_DUPLICATE_IDENTITY`
    # is the debt category.
    _record_ambiguous_identities(base, chunk_name, ambiguous)


    observed: list[tuple[str, str, str]] = []
    for index, entry in enumerate(entries, start=1):
        actions = list(entry.get("source_actions", []) or [])
        if len(actions) != 1 or len(actions[0]) != 3:
            issues.append(
                f"source row {index} lacks exactly one authenticated source action"
            )
            continue
        observed.append(tuple(map(str, actions[0])))
    if len(observed) != len(set(observed)):
        issues.append("source-action denominator contains duplicates")
    return issues
