"""Adversarial RED contracts for exact preverify source-bundle replay.

The frozen projection is only authoritative when its inventory, candidate
union, collision debt, and semantic-mutation lineage are exact replays of the
authenticated source bundle.  Content-addressing rewritten output bytes is
not sufficient.

This suite is test-only.  It uses temporary scratchpads and never launches a
model, audit, network request, or production write.
"""
from __future__ import annotations

from copy import deepcopy
import re
from pathlib import Path
from typing import Any

import pytest

from artifact_ledger import (
    acknowledge_semantic_mutations,
    arm_semantic_mutation,
    semantic_mutation_authority_digest,
    semantic_mutation_events,
)
from preverify_frozen_projection import (
    EVIDENCE_LOGICAL,
    INVENTORY_LOGICAL,
    prepare_preverify_frozen_projection,
)
from preverify_projection_authority import (
    PreverifyProjectionAuthorityError,
    resolve_current_preverify_projection,
)
import plamen_driver as DRIVER
import test_chain_driver_boundary_authority_red as CHAIN_AUTHORITY
import test_live_verify_queue_driver_adapter_cutover as ADAPTER
import test_preverify_chain_candidate_delta as DELTA_FIXTURE
import test_preverify_frozen_projection as FROZEN_FIXTURE
import test_preverify_inventory_successor_p0_al as SUCCESSOR_FIXTURE
import test_preverify_projection_authority_red as AUTHORITY_FIXTURE
import test_preverify_runtime_source_replay_red as REPLAY_FIXTURE


_FINDING_ID = re.compile(
    rb"(?im)^#{2,4}\s+Finding\s+\[([A-Za-z0-9_.-]+)\]\s*:"
)


def _ids(raw: bytes) -> list[str]:
    return sorted(
        match.group(1).decode("ascii").upper()
        for match in _FINDING_ID.finditer(raw)
    )


def _reorder_finding_blocks(raw: bytes) -> bytes:
    starts = [match.start() for match in _FINDING_ID.finditer(raw)]
    assert len(starts) >= 2
    blocks = [
        raw[start : starts[index + 1] if index + 1 < len(starts) else len(raw)]
        for index, start in enumerate(starts)
    ]
    return raw[: starts[0]] + b"".join(reversed(blocks))


def _assert_forged_inventory_rejected(
    context: dict[str, Any],
    forged: bytes,
) -> None:
    assert forged != context["inventory_raw"]
    assert _ids(forged) == _ids(context["inventory_raw"])
    receipt, authority, records = REPLAY_FIXTURE._forge_output_bytes(
        context,
        forged,
    )
    with pytest.raises(
        PreverifyProjectionAuthorityError,
        match="source|replay|inventory|union|bytes",
    ):
        REPLAY_FIXTURE._validate_context(
            context,
            receipt=receipt,
            authority=authority,
            inventory_raw=forged,
            records_raw=records,
        )


@pytest.mark.parametrize(
    "mutation",
    ("reword", "field-order", "newline-normalization"),
)
def test_no_delta_rejects_exact_base_byte_drift_with_identical_ids(
    tmp_path: Path,
    mutation: str,
) -> None:
    """A readdressed output cannot replace its authenticated base preimage."""

    context = AUTHORITY_FIXTURE._receipt_context(tmp_path)
    original = context["inventory_raw"]
    if mutation == "reword":
        forged = original.replace(
            b"exact mechanism remains candidate-bearing",
            b"semantically reauthored mechanism remains candidate-bearing",
        )
    elif mutation == "field-order":
        newline = b"\r\n" if b"\r\n" in original else b"\n"
        first = b"**Root Cause**: exact mechanism" + newline
        second = (
            b"**Description**: exact mechanism remains candidate-bearing"
            + newline
        )
        assert first + second in original
        forged = original.replace(first + second, second + first)
    else:
        forged = (
            original.replace(b"\r\n", b"\n")
            if b"\r\n" in original
            else original.replace(b"\n", b"\r\n")
        )
    _assert_forged_inventory_rejected(context, forged)


def _delta_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Any]:
    return REPLAY_FIXTURE._chain_delta_context(tmp_path, monkeypatch)


@pytest.mark.parametrize("mutation", ("omit-field", "reorder", "reword"))
def test_delta_rejects_nonexact_union_with_identical_candidate_ids(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    """Identity-set equality cannot bless a different base-plus-delta union."""

    context = _delta_context(tmp_path, monkeypatch)
    original = context["inventory_raw"]
    if mutation == "omit-field":
        needle = b"**Proof Authority**: NONE\n"
        assert needle in original
        forged = original.replace(needle, b"", 1)
    elif mutation == "reorder":
        forged = _reorder_finding_blocks(original)
    else:
        forged = original.replace(
            b"A generic chain-discovered precondition path.",
            b"A materially reworded chain-discovered precondition path.",
        )
    _assert_forged_inventory_rejected(context, forged)


def _collision_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Any]:
    existing = (
        "\n### Finding [EN-1]: Existing unrelated claim\n"
        "**Severity**: Low\n"
        "**Location**: src/Existing.sol:99\n"
        "**Description**: Existing distinct content.\n"
        "**Impact**: Existing distinct impact.\n"
    )
    project, root, pair, _before = (
        DELTA_FIXTURE._accepted_delta_sources(
            tmp_path,
            monkeypatch,
            base_inventory_extra=existing,
        )
    )
    frozen = prepare_preverify_frozen_projection(
        scratchpad=root,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase_name="sc_verify_queue",
        run_id=CHAIN_AUTHORITY.RUN_ID,
        chain_pair_projection=pair,
    )
    context = REPLAY_FIXTURE._context_from_frozen(root, frozen)
    assert context["receipt"]["candidate_delivery_fixed_point"][
        "identity_collision_ids"
    ] == ["EN-1"]
    return context


def _collision_row(receipt: dict[str, Any]) -> dict[str, Any]:
    return next(
        row
        for row in receipt["debt"]
        if row.get("reason_code") == "CHAIN_CANDIDATE_IDENTITY_COLLISION"
    )


def test_collision_must_retain_exact_base_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A colliding proposal cannot replace or reauthor the existing base."""

    context = _collision_context(tmp_path, monkeypatch)
    forged = context["inventory_raw"].replace(
        b"Existing distinct content.",
        b"Reauthored collision-base content.",
    )
    _assert_forged_inventory_rejected(context, forged)


@pytest.mark.parametrize(
    "mutation",
    ("base-hash", "delta-hash", "candidate-content"),
)
def test_collision_debt_is_exact_source_replay_not_self_attestation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    context = _collision_context(tmp_path, monkeypatch)
    receipt = deepcopy(context["receipt"])
    collision = _collision_row(receipt)
    if mutation == "base-hash":
        collision["base_block_sha256"] = "0" * 64
    elif mutation == "delta-hash":
        collision["delta_block_sha256"] = "f" * 64
    else:
        collision["candidate"]["description"] = (
            "A reauthored collision candidate."
        )
    authority = AUTHORITY_FIXTURE._readdress_receipt(
        receipt,
        context["authority"],
    )
    with pytest.raises(
        PreverifyProjectionAuthorityError,
        match="collision|debt|source|replay",
    ):
        REPLAY_FIXTURE._validate_context(
            context,
            receipt=receipt,
            authority=authority,
        )


def _multi_mutation_context(tmp_path: Path) -> dict[str, Any]:
    root, config, run_id = ADAPTER._seed(
        tmp_path,
        pipeline="sc",
        backend="claude",
    )
    FROZEN_FIXTURE._split_source_owners(
        root,
        tmp_path,
        config,
        run_id,
    )
    inventory = (root / INVENTORY_LOGICAL).read_bytes()
    FROZEN_FIXTURE._mutate(
        root,
        tmp_path,
        run_id,
        INVENTORY_LOGICAL,
        inventory + b"\n# first semantic inventory mutation\n",
        "FIRST_INVENTORY_MUTATION",
    )
    inventory = (root / INVENTORY_LOGICAL).read_bytes()
    FROZEN_FIXTURE._mutate(
        root,
        tmp_path,
        run_id,
        INVENTORY_LOGICAL,
        inventory + b"# second semantic inventory mutation\n",
        "SECOND_INVENTORY_MUTATION",
    )
    evidence = (root / EVIDENCE_LOGICAL).read_bytes()
    FROZEN_FIXTURE._mutate(
        root,
        tmp_path,
        run_id,
        EVIDENCE_LOGICAL,
        evidence + b"\n# independent evidence mutation\n",
        "EVIDENCE_MUTATION",
    )
    frozen = FROZEN_FIXTURE._prepare(
        root,
        tmp_path,
        config,
        run_id,
    )
    context = REPLAY_FIXTURE._context_from_frozen(root, frozen)
    context["config"] = config
    inventory_authority = context["receipt"]["source_authorities"][
        "inventory"
    ]
    assert len(inventory_authority["mutation_event_ids"]) == 2
    assert len(
        context["receipt"]["source_authorities"]["evidence"][
            "mutation_event_ids"
        ]
    ) == 1
    return context


@pytest.mark.parametrize(
    "mutation",
    ("reorder", "truncate", "extra", "wrong-artifact", "wrong-run", "armed"),
)
def test_semantic_mutation_claims_replay_exact_event_chain(
    tmp_path: Path,
    mutation: str,
) -> None:
    context = _multi_mutation_context(tmp_path)
    receipt = deepcopy(context["receipt"])
    inventory = receipt["source_authorities"]["inventory"]
    if mutation == "reorder":
        inventory["mutation_event_ids"].reverse()
        inventory["mutation_authority_digests"].reverse()
    elif mutation == "truncate":
        inventory["mutation_event_ids"] = inventory[
            "mutation_event_ids"
        ][:-1]
        inventory["mutation_authority_digests"] = inventory[
            "mutation_authority_digests"
        ][:-1]
    elif mutation == "extra":
        inventory["mutation_event_ids"].append("SMUT-EXTRA-EVENT")
        inventory["mutation_authority_digests"].append("0" * 64)
    elif mutation == "wrong-artifact":
        evidence = receipt["source_authorities"]["evidence"]
        inventory["mutation_event_ids"] = list(
            evidence["mutation_event_ids"]
        )
        inventory["mutation_authority_digests"] = list(
            evidence["mutation_authority_digests"]
        )
    else:
        event = arm_semantic_mutation(
            context["root"],
            Path(context["root"]).parent,
            artifact_identity="scratchpad:" + INVENTORY_LOGICAL,
            mutation_kind=(
                "WRONG_RUN_EVENT"
                if mutation == "wrong-run"
                else "UNFINISHED_EVENT"
            ),
            run_id=(
                "different-run"
                if mutation == "wrong-run"
                else str(context["run_id"])
            ),
        )
        inventory["mutation_event_ids"].append(str(event["event_id"]))
        inventory["mutation_authority_digests"].append(
            semantic_mutation_authority_digest(event)
        )

    authority = AUTHORITY_FIXTURE._readdress_receipt(
        receipt,
        context["authority"],
    )
    with pytest.raises(
        PreverifyProjectionAuthorityError,
        match="semantic|mutation|source|authority|ledger|replay",
    ):
        REPLAY_FIXTURE._validate_context(
            context,
            receipt=receipt,
            authority=authority,
        )


def test_acknowledgement_only_control_change_preserves_receipt_semantics(
    tmp_path: Path,
) -> None:
    """Self-ack fields are not part of semantic mutation authority."""

    context = _multi_mutation_context(tmp_path)
    path = Path(context["root"]) / "_semantic_mutations.json"
    before = path.read_bytes()
    event_ids = [
        str(row["event_id"])
        for row in semantic_mutation_events(context["root"])
    ]
    acknowledge_semantic_mutations(
        context["root"],
        event_ids,
        reconciled_by_run_id=str(context["run_id"]),
    )
    assert path.read_bytes() != before
    # The public replay validator must accept the historical receipt because
    # semantic_mutation_authority_digest deliberately excludes acknowledgement
    # fields.
    REPLAY_FIXTURE._validate_context(context)


def _runtime_mutation_successor(tmp_path: Path) -> dict[str, Any]:
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    config = SUCCESSOR_FIXTURE._config(project, root)
    run_id = str(config["_run_id"])
    SUCCESSOR_FIXTURE._seed(root)
    SUCCESSOR_FIXTURE._claim_seed_authority(root, config)
    inventory = (root / INVENTORY_LOGICAL).read_bytes()
    FROZEN_FIXTURE._mutate(
        root,
        project,
        run_id,
        INVENTORY_LOGICAL,
        inventory + b"\n# first runtime semantic mutation\n",
        "FIRST_RUNTIME_MUTATION",
    )
    inventory = (root / INVENTORY_LOGICAL).read_bytes()
    FROZEN_FIXTURE._mutate(
        root,
        project,
        run_id,
        INVENTORY_LOGICAL,
        inventory + b"# second runtime semantic mutation\n",
        "SECOND_RUNTIME_MUTATION",
    )
    frozen = FROZEN_FIXTURE._prepare(
        root,
        project,
        config,
        run_id,
    )
    assert DRIVER._finalize_preverify_inventory_successors(
        root,
        config,
        phase_name="sc_verify_queue",
        frozen_projection=frozen,
    ) == []
    execute, routing_issues = (
        DRIVER._arm_typed_verify_queue_routing_artifacts(
            "sc_verify_queue",
            root,
            config,
        )
    )
    assert execute is True
    assert routing_issues == []
    return {
        "root": root,
        "run_id": run_id,
        "frozen": frozen,
    }


def test_runtime_resume_survives_acknowledgement_only_control_change(
    tmp_path: Path,
) -> None:
    """A checkpoint acknowledgement must not stale immutable semantics."""

    context = _runtime_mutation_successor(tmp_path)
    before = resolve_current_preverify_projection(
        context["root"],
        expected_run_id=context["run_id"],
        expected_consumer_work_unit_key=AUTHORITY_FIXTURE.RUNTIME_CONSUMER,
    )
    events = semantic_mutation_events(context["root"])
    acknowledge_semantic_mutations(
        context["root"],
        [str(row["event_id"]) for row in events],
        reconciled_by_run_id=context["run_id"],
    )
    after = resolve_current_preverify_projection(
        context["root"],
        expected_run_id=context["run_id"],
        expected_consumer_work_unit_key=AUTHORITY_FIXTURE.RUNTIME_CONSUMER,
    )
    assert after["frozen_generation_digest"] == before[
        "frozen_generation_digest"
    ]
