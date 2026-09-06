"""Closed, resumable child transaction for deterministic verify-queue routing.

The transaction deliberately separates private intermediate projections from
the public queue/shard namespace.  Only ``t9.final_assembler`` publishes the
public postimage.  Every child has an exact, disjoint output denominator and an
always-present status record; the parent is a read-only join.

The production driver supplies the child executor.  This module owns the
transaction topology, crash/resume rules, third-state quarantine, and
backend-neutral publication contract.
"""
from __future__ import annotations

import hashlib
import fnmatch
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
from typing import Any, Callable, Mapping, Sequence

import l1_composition_queue_runtime as _live_l1_composition
import live_verify_queue_prearm_inputs as _live_prearm
import mandatory_reverification as _live_mandatory
import p0af_v2_queue_adapter as _live_sc_adapter
import p0af_v2_queue_runtime as _live_sc_composition
import rooted_path_io as _rooted_io
from phase_io_contracts import canonical_work_unit_key


VERIFY_QUEUE_TERMINAL_STATES = frozenset({
    "COMMITTED_APPLIED",
    "COMMITTED_CLEAN_NOOP",
    "COMPLETED_WITH_DEBT_SAFE_BASE",
    "PREPARED_NOT_CONSUMABLE",
    "QUARANTINED_FOREIGN_STATE",
})

_STATE_PRECEDENCE = {
    "COMMITTED_CLEAN_NOOP": 0,
    "COMMITTED_APPLIED": 1,
    "COMPLETED_WITH_DEBT_SAFE_BASE": 2,
    "PREPARED_NOT_CONSUMABLE": 3,
    "QUARANTINED_FOREIGN_STATE": 4,
}
_STATUS_SCHEMA = "plamen.verify_queue_child_status.v1"
_PLAN_SCHEMA = "plamen.verify_queue_transaction_plan.v1"
_RECEIPT_SCHEMA = "plamen.verify_queue_transaction_receipt.v1"
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)

_CHILD_IDS = (
    "t0.input_authority",
    "t1.base_queue",
    "t2.policy_disposition",
    "t3.mandatory_reverification",
    "t4.composition_delivery",
    "t5.compound_projection",
    "t6.final_work_item_plan",
    "t7.context_and_shard_plan",
    "t8.transaction_validation",
    "t9.final_assembler",
)
_PARENT_ID = "routing.parent_commit"
_STATUS_PATHS = tuple(
    f"_verify_queue_transaction/t{index}/status.json"
    for index in range(10)
)

_T0_OUTPUTS = (
    "_verify_queue_transaction/t0/input_snapshot.json",
    _STATUS_PATHS[0],
    "verify_queue_context_input_status.json",
)
_T1_OUTPUTS = (
    "_verify_queue_transaction/t1/base_queue.json",
    "_verify_queue_transaction/t1/base_queue.md",
    "_verify_queue_transaction/t1/base_queue.work_items.json",
    _STATUS_PATHS[1],
)
_T2_OUTPUTS = (
    "_verify_queue_transaction/t2/active_queue.work_items.json",
    "_verify_queue_transaction/t2/evidence_debt.json",
    "_verify_queue_transaction/t2/evidence_excluded.work_items.json",
    _STATUS_PATHS[2],
)
_T3_OUTPUTS = (
    "_verify_queue_transaction/t3/queue_delta.json",
    _STATUS_PATHS[3],
    "mandatory_reverification_denominator.json",
    "mandatory_reverification_queue_transaction.receipt.json",
    "mandatory_reverification_routing.json",
)
_T4_OUTPUTS = (
    _STATUS_PATHS[4],
    "compound_verification_delivery_debt.json",
    "compound_verification_delivery_disposition.json",
    "compound_verification_delivery_receipt.json",
)
_T4_CONDITIONAL = {
    "compound_verification_delivery_debt.json": "compound_delivery_debt",
    "compound_verification_delivery_receipt.json": "compound_delivery_receipt",
}
_T5_OUTPUTS = (
    _STATUS_PATHS[5],
    "compound_candidates.json",
    "compound_verification_work_plan.json",
)
_T6_OUTPUTS = (
    "_verify_queue_transaction/t6/final_work_items.json",
    "_verify_queue_transaction/t6/final_publication_plan.json",
    _STATUS_PATHS[6],
)
_T7_OUTPUTS = (
    "_verify_queue_transaction/t7/context_input_capture.json",
    "_verify_queue_transaction/t7/context_input_roster.json",
    "_verify_queue_transaction/t7/verification_context_packets.json",
    "_verify_queue_transaction/t7/verification_methodology_reachability.json",
    "_verify_queue_transaction/t7/shard_plan.json",
    _STATUS_PATHS[7],
)
_T8_OUTPUTS = (
    "_verify_queue_transaction/t8/outer_denominator.json",
    "_verify_queue_transaction/t8/validated_publication.json",
    _STATUS_PATHS[8],
)
_COMMON_PUBLIC_OUTPUTS = {
    _STATUS_PATHS[9],
    "verification_context_packets.json",
    "verification_methodology_reachability.json",
    "verification_queue.json",
    "verification_queue.md",
    "verification_queue.work_items.json",
    "verification_queue.work_plan.json",
    "verification_queue_evidence_debt.json",
    "verification_queue_evidence_debt.md",
    "verification_queue_evidence_excluded.json",
    "verification_queue_evidence_excluded.md",
    "verify_queue_transaction.receipt.json",
}

# Production cutover topology.  Keep this contract distinct from the original
# ``_CHILD_IDS`` scaffold above: the scaffold remains a compatibility and
# migration test surface while these identifiers name the live SC/L1
# transaction whose only public writer is T9.
_LIVE_PLAN_SCHEMA = "plamen.live_verify_queue_plan.v1"
_LIVE_PRIVATE_ROOT = "_live_verify_queue_transaction"
_LIVE_CHILD_IDS = (
    "t0.live_upstream_authority",
    "t1.live_base_queue",
    "t2.live_policy_disposition",
    "t3.live_mandatory_delta",
    "t4.live_pipeline_composition_delta",
    "t5.live_generic_compound_delta",
    "t6.live_final_typed_merge",
    "t7.live_frozen_context_and_shard_plan",
    "t8.live_immutable_publication_bundle",
    "t9.live_receipt_last_cas",
)
_LIVE_PARENT_ID = "routing.live_parent_commit"
_LIVE_STATUS_PATHS = tuple(
    f"{_LIVE_PRIVATE_ROOT}/t{index}/status.json"
    for index in range(10)
)
_LIVE_FINAL_RECEIPT = "verify_queue_transaction.receipt.json"

_LIVE_REQUIRED_UPSTREAM = frozenset({
    "finding_delivery_successor.json",
    "live_verify_queue_methodology_projection.receipt.json",
    "preverify_inventory_successor.json",
})
_LIVE_COMMON_PRESENCE_ROSTER = frozenset({
    "application_skeptic_proposals.md",
    "candidate_negative_skeptic_proposals.md",
    "security_obligation_authority.json",
})
_LIVE_SC_PRESENCE_ROSTER = frozenset({
    "arm_before_trust_compound_candidates.json",
    "arm_before_trust_compound_work_plan.json",
    "arm_before_trust_p0af_route_debt.json",
    "chain_anti_absorption_applied_receipt.json",
    "chain_composition_verification_candidates.json",
    "chain_grouping_relations.json",
    "chain_hypotheses.md",
    "chain_tail_terminal_snapshot.json",
})
_LIVE_SC_IDENTITY_DENOMINATOR = "_canonical_finding_ids.json"
_LIVE_PREARM_INPUT_MANIFEST = "prearm_content_addressed_inputs.json"
_LIVE_L1_PRESENCE_ROSTER = frozenset({
    "l1_composition_model_dispositions.json",
    "l1_composition_receipt.json",
    "l1_composition_runtime.json",
})

def live_verify_queue_base_upstream_roster(
    pipeline: str,
) -> tuple[str, ...]:
    """Return the exact static pre-dynamic T0 upstream denominator."""

    pipeline_n = str(pipeline or "").strip().lower()
    if pipeline_n not in {"sc", "l1"}:
        raise VerifyQueueTransactionError("pipeline must be sc or l1")
    branch_presence = (
        _LIVE_SC_PRESENCE_ROSTER
        if pipeline_n == "sc"
        else _LIVE_L1_PRESENCE_ROSTER
    )
    return tuple(sorted({
        *_LIVE_REQUIRED_UPSTREAM,
        *_LIVE_COMMON_PRESENCE_ROSTER,
        *branch_presence,
    }))


def live_verify_queue_required_upstream_roster(
    pipeline: str,
) -> tuple[str, ...]:
    """Return the static T0 inputs whose absence/authority is blocking."""

    pipeline_n = str(pipeline or "").strip().lower()
    if pipeline_n not in {"sc", "l1"}:
        raise VerifyQueueTransactionError("pipeline must be sc or l1")
    return tuple(sorted(_LIVE_REQUIRED_UPSTREAM))


_LIVE_T0_OUTPUTS = (
    f"{_LIVE_PRIVATE_ROOT}/t0/input_bundle.json",
    f"{_LIVE_PRIVATE_ROOT}/t0/input_presence_roster.json",
    f"{_LIVE_PRIVATE_ROOT}/t0/context_selection.json",
    f"{_LIVE_PRIVATE_ROOT}/t0/resolved_plan.json",
    _LIVE_STATUS_PATHS[0],
)
_LIVE_T1_OUTPUTS = (
    f"{_LIVE_PRIVATE_ROOT}/t1/base_queue.md",
    f"{_LIVE_PRIVATE_ROOT}/t1/base_queue.json",
    f"{_LIVE_PRIVATE_ROOT}/t1/base_queue.work_items.json",
    _LIVE_STATUS_PATHS[1],
)
_LIVE_T2_OUTPUTS = (
    f"{_LIVE_PRIVATE_ROOT}/t2/active_queue.work_items.json",
    f"{_LIVE_PRIVATE_ROOT}/t2/evidence_excluded.work_items.json",
    f"{_LIVE_PRIVATE_ROOT}/t2/evidence_debt.json",
    f"{_LIVE_PRIVATE_ROOT}/t2/identity_accounting.json",
    f"{_LIVE_PRIVATE_ROOT}/t2/policy_disposition.json",
    _LIVE_STATUS_PATHS[2],
)
_LIVE_T3_OUTPUTS = (
    f"{_LIVE_PRIVATE_ROOT}/t3/queue_delta.work_items.json",
    f"{_LIVE_PRIVATE_ROOT}/t3/mandatory_reverification_denominator.json",
    f"{_LIVE_PRIVATE_ROOT}/t3/mandatory_reverification_routing.json",
    f"{_LIVE_PRIVATE_ROOT}/t3/mandatory_reverification_disposition.json",
    _LIVE_STATUS_PATHS[3],
)
_LIVE_T5_OUTPUTS = (
    f"{_LIVE_PRIVATE_ROOT}/t5/compound_candidates.json",
    f"{_LIVE_PRIVATE_ROOT}/t5/compound_verification_work_plan.json",
    f"{_LIVE_PRIVATE_ROOT}/t5/queue_delta.work_items.json",
    f"{_LIVE_PRIVATE_ROOT}/t5/compound_delivery_disposition.json",
    f"{_LIVE_PRIVATE_ROOT}/t5/compound_delivery_receipt.json",
    f"{_LIVE_PRIVATE_ROOT}/t5/compound_delivery_debt.json",
    _LIVE_STATUS_PATHS[5],
)
_LIVE_T6_OUTPUTS = (
    f"{_LIVE_PRIVATE_ROOT}/t6/final_work_items.json",
    f"{_LIVE_PRIVATE_ROOT}/t6/final_excluded_work_items.json",
    f"{_LIVE_PRIVATE_ROOT}/t6/final_evidence_debt.json",
    f"{_LIVE_PRIVATE_ROOT}/t6/source_obligation_accounting.json",
    f"{_LIVE_PRIVATE_ROOT}/t6/final_publication_plan.json",
    _LIVE_STATUS_PATHS[6],
)
_LIVE_T7_OUTPUTS = (
    f"{_LIVE_PRIVATE_ROOT}/t7/context_input_capture.json",
    f"{_LIVE_PRIVATE_ROOT}/t7/context_input_roster.json",
    f"{_LIVE_PRIVATE_ROOT}/t7/verification_context_packets.json",
    f"{_LIVE_PRIVATE_ROOT}/t7/verification_methodology_reachability.json",
    f"{_LIVE_PRIVATE_ROOT}/t7/shard_plan.json",
    _LIVE_STATUS_PATHS[7],
)
_LIVE_T8_OUTPUTS = (
    f"{_LIVE_PRIVATE_ROOT}/t8/outer_denominator.json",
    f"{_LIVE_PRIVATE_ROOT}/t8/validated_publication.bundle.json",
    f"{_LIVE_PRIVATE_ROOT}/t8/validation_receipt.json",
    _LIVE_STATUS_PATHS[8],
)

_LIVE_COMMON_PUBLIC_OUTPUTS = frozenset({
    "compound_candidates.json",
    "compound_verification_delivery_debt.json",
    "compound_verification_delivery_disposition.json",
    "compound_verification_delivery_receipt.json",
    "compound_verification_work_plan.json",
    _live_mandatory.DENOMINATOR_FILE,
    _live_mandatory.QUEUE_TRANSACTION_RECEIPT_FILE,
    _live_mandatory.ROUTING_FILE,
    _LIVE_FINAL_RECEIPT,
    "verification_context_packets.json",
    "verification_methodology_reachability.json",
    "verification_queue.json",
    "verification_queue.md",
    "verification_queue.work_items.json",
    "verification_queue.work_plan.json",
    "verification_queue_evidence_debt.json",
    "verification_queue_evidence_debt.md",
    "verification_queue_evidence_excluded.json",
    "verification_queue_evidence_excluded.md",
    "verify_queue_context_input_status.json",
})
_LIVE_SC_COMPATIBILITY_OUTPUTS = frozenset({
    _live_sc_composition.INPUT_SNAPSHOT_FILE,
    _live_sc_composition.RECEIPT_FILE,
    _live_sc_composition.DEBT_FILE,
    _live_sc_composition.STATUS_FILE,
})
_LIVE_L1_COMPATIBILITY_OUTPUTS = frozenset({
    _live_l1_composition.QUEUE_INPUT_NAME,
    _live_l1_composition.DELIVERY_RECEIPT_NAME,
    _live_l1_composition.DELIVERY_DEBT_NAME,
    _live_l1_composition.DELIVERY_STATUS_NAME,
})


class VerifyQueueTransactionError(ValueError):
    """The verify-queue transaction contract cannot be satisfied safely."""

    def __init__(
        self,
        message: str,
        *,
        durability_debt: Mapping[str, Any] | None = None,
    ) -> None:
        self.durability_debt = (
            dict(durability_debt) if durability_debt is not None else None
        )
        super().__init__(message)


class VerifyQueueInjectedFailure(RuntimeError):
    """Test/diagnostic failpoint; never converted into semantic completion."""


def _canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _digest_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _stable_digest(value: Any) -> str:
    return _digest_bytes(_canonical_json_bytes(value))


def _validated_prearm_input_manifest(
    value: Mapping[str, Any],
    *,
    pipeline: str,
    run_id: str,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Validate the exact SC dynamic-input denominator before T0 arm."""

    if pipeline != "sc":
        raise VerifyQueueTransactionError(
            "prearm input manifests are supported only by the SC P0-AF path"
        )
    if not isinstance(value, Mapping):
        raise VerifyQueueTransactionError(
            "SC prearm input manifest must be an object"
        )
    manifest = dict(value)
    expected_keys = {
        "schema_version",
        "pipeline",
        "run_id",
        "manifest_identity",
        "selection_authority",
        "identity_denominator",
        "referenced_source_identities",
        "referenced_source_identity_digest",
        "entries",
        "entry_count",
        "entry_identity_digest",
        "content_addressed",
        "live_glob_allowed",
        "live_read_after_arm_allowed",
        "manifest_digest",
    }
    if set(manifest) != expected_keys:
        raise VerifyQueueTransactionError(
            "SC prearm input manifest field denominator is malformed"
        )
    if (
        manifest.get("schema_version")
        != "plamen.prearm_content_addressed_input_manifest.v1"
        or str(manifest.get("pipeline") or "").strip().lower() != pipeline
        or str(manifest.get("run_id") or "").strip() != run_id
        or manifest.get("content_addressed") is not True
        or manifest.get("live_glob_allowed") is not False
        or manifest.get("live_read_after_arm_allowed") is not False
    ):
        raise VerifyQueueTransactionError(
            "SC prearm input manifest identity/policy is invalid"
        )
    digest = str(manifest.get("manifest_digest") or "")
    unsigned = {
        key: item for key, item in manifest.items()
        if key != "manifest_digest"
    }
    if not _DIGEST_RE.fullmatch(digest) or digest != _stable_digest(unsigned):
        raise VerifyQueueTransactionError(
            "SC prearm input manifest digest is malformed or stale"
        )

    manifest_identity = str(manifest.get("manifest_identity") or "")
    if manifest_identity != "scratchpad:" + _LIVE_PREARM_INPUT_MANIFEST:
        raise VerifyQueueTransactionError(
            "SC prearm manifest identity is not canonical"
        )

    def _authority_row(
        raw: Any,
        *,
        expected_identity: str,
        label: str,
    ) -> dict[str, Any]:
        if not isinstance(raw, Mapping) or set(raw) != {
            "identity", "sha256", "size"
        }:
            raise VerifyQueueTransactionError(
                f"SC prearm {label} authority row is malformed"
            )
        row = dict(raw)
        if (
            row.get("identity") != expected_identity
            or not _DIGEST_RE.fullmatch(str(row.get("sha256") or ""))
            or not isinstance(row.get("size"), int)
            or isinstance(row.get("size"), bool)
            or int(row["size"]) < 0
        ):
            raise VerifyQueueTransactionError(
                f"SC prearm {label} authority binding is invalid"
            )
        return row

    _authority_row(
        manifest.get("selection_authority"),
        expected_identity=(
            "scratchpad:" + _live_sc_adapter.CANDIDATE_FILE
        ),
        label="selection",
    )
    _authority_row(
        manifest.get("identity_denominator"),
        expected_identity=(
            "scratchpad:" + _LIVE_SC_IDENTITY_DENOMINATOR
        ),
        label="identity denominator",
    )
    references = manifest.get("referenced_source_identities")
    entries = manifest.get("entries")
    if (
        not isinstance(references, list)
        or not isinstance(entries, list)
        or any(not isinstance(item, str) for item in references)
        or references != sorted(set(references))
        or manifest.get("referenced_source_identity_digest")
        != _stable_digest(references)
    ):
        raise VerifyQueueTransactionError(
            "SC prearm referenced source denominator is malformed"
        )
    normalized_entries: list[dict[str, Any]] = []
    for raw in entries:
        if not isinstance(raw, Mapping):
            raise VerifyQueueTransactionError(
                "SC prearm source manifest entry is malformed"
            )
        identity = str(raw.get("identity") or "")
        if not identity.startswith("scratchpad:"):
            raise VerifyQueueTransactionError(
                "SC prearm source identity must be scratchpad-relative"
            )
        relative = _safe_relative(identity[len("scratchpad:"):])
        normalized_entries.append(
            _authority_row(
                raw,
                expected_identity="scratchpad:" + relative,
                label="source",
            )
        )
    entry_identities = [
        str(row["identity"]) for row in normalized_entries
    ]
    if (
        entry_identities != sorted(set(entry_identities))
        or entry_identities != references
        or manifest.get("entry_count") != len(normalized_entries)
        or manifest.get("entry_identity_digest")
        != _stable_digest(entry_identities)
    ):
        raise VerifyQueueTransactionError(
            "SC prearm referenced source/entry denominator does not close"
        )
    return manifest, tuple(
        identity[len("scratchpad:"):] for identity in entry_identities
    )


def _validated_prearm_resolution(
    value: Mapping[str, Any],
    *,
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
    phase_name: str,
    run_id: str,
) -> tuple[dict[str, Any], dict[str, Any] | None, tuple[str, ...]]:
    """Validate one committed pre-arm outcome before adding it to T0."""

    if pipeline != "sc" or not isinstance(value, Mapping):
        raise VerifyQueueTransactionError(
            "prearm dynamic input resolution is valid only for SC"
        )
    resolution = dict(value)
    expected_keys = {
        "schema_version",
        "state",
        "receipt_path",
        "active_conditional_path",
        "t0_additional_inputs",
        "dynamic_source_paths",
        "manifest",
        "phase_io_owner_key",
        "status_json_is_authority",
        "live_glob_allowed",
        "live_read_after_arm_allowed",
    }
    if set(resolution) != expected_keys:
        raise VerifyQueueTransactionError(
            "prearm resolution field denominator is malformed"
        )
    state = str(resolution.get("state") or "")
    if (
        resolution.get("schema_version")
        != "plamen.prearm_dynamic_input_resolution.v1"
        or state not in {
            "NOT_TRIGGERED",
            "RESOLVED",
            "COMPLETED_WITH_DEBT",
        }
        or resolution.get("receipt_path") != _live_prearm.RECEIPT_FILE
        or resolution.get("status_json_is_authority") is not False
        or resolution.get("live_glob_allowed") is not False
        or resolution.get("live_read_after_arm_allowed") is not False
    ):
        raise VerifyQueueTransactionError(
            "prearm resolution identity/policy is invalid"
        )
    expected_owner = canonical_work_unit_key(
        pipeline,
        mode,
        ecosystem,
        backend,
        phase_name,
        _live_prearm.WORK_UNIT_ID,
    )
    if resolution.get("phase_io_owner_key") != expected_owner:
        raise VerifyQueueTransactionError(
            "prearm resolution PhaseIO owner is foreign"
        )
    raw_additional = resolution.get("t0_additional_inputs")
    raw_sources = resolution.get("dynamic_source_paths")
    if (
        not isinstance(raw_additional, list)
        or not isinstance(raw_sources, list)
        or any(not isinstance(item, str) for item in raw_additional)
        or any(not isinstance(item, str) for item in raw_sources)
    ):
        raise VerifyQueueTransactionError(
            "prearm resolution input/source denominator is malformed"
        )
    additional = tuple(sorted({_safe_relative(item) for item in raw_additional}))
    sources = tuple(sorted({_safe_relative(item) for item in raw_sources}))
    if list(additional) != raw_additional or list(sources) != raw_sources:
        raise VerifyQueueTransactionError(
            "prearm resolution input/source denominator is noncanonical"
        )
    selected = str(resolution.get("active_conditional_path") or "")
    manifest_value = resolution.get("manifest")
    manifest: dict[str, Any] | None = None
    if state == "NOT_TRIGGERED":
        expected_additional = {_live_prearm.RECEIPT_FILE}
        expected_selected = "NONE"
        if sources or manifest_value is not None:
            raise VerifyQueueTransactionError(
                "NOT_TRIGGERED prearm resolution contains dynamic authority"
            )
    elif state == "COMPLETED_WITH_DEBT":
        expected_additional = {
            _live_prearm.RECEIPT_FILE,
            _live_prearm.DEBT_FILE,
        }
        expected_selected = _live_prearm.DEBT_FILE
        if sources or manifest_value is not None:
            raise VerifyQueueTransactionError(
                "debt prearm resolution contains positive dynamic authority"
            )
    else:
        if not isinstance(manifest_value, Mapping):
            raise VerifyQueueTransactionError(
                "RESOLVED prearm resolution has no manifest"
            )
        manifest, manifest_sources = _validated_prearm_input_manifest(
            manifest_value,
            pipeline=pipeline,
            run_id=run_id,
        )
        if sources != manifest_sources:
            raise VerifyQueueTransactionError(
                "prearm resolution source denominator differs from manifest"
            )
        expected_additional = {
            _live_prearm.RECEIPT_FILE,
            _live_prearm.MANIFEST_FILE,
            _LIVE_SC_IDENTITY_DENOMINATOR,
            *sources,
        }
        expected_selected = _live_prearm.MANIFEST_FILE
    if set(additional) != expected_additional or selected != expected_selected:
        raise VerifyQueueTransactionError(
            "prearm resolution active branch/input denominator is invalid"
        )
    normalized = {
        **resolution,
        "t0_additional_inputs": list(additional),
        "dynamic_source_paths": list(sources),
        "manifest": manifest,
    }
    return normalized, manifest, additional


def _validated_prearm_presence(
    value: Mapping[str, Any],
    *,
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
    phase_name: str,
    run_id: str,
    expected_roster: set[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate the committed exact PRESENT/ABSENT roster before T0."""

    if not isinstance(value, Mapping):
        raise VerifyQueueTransactionError(
            "prearm presence preparation is not an object"
        )
    preparation = dict(value)
    expected_preparation_keys = {
        "schema_version",
        "authority_path",
        "authority",
        "effective_input_paths",
        "phase_io_owner_key",
        "status_json_is_authority",
    }
    if set(preparation) != expected_preparation_keys:
        raise VerifyQueueTransactionError(
            "prearm presence preparation field denominator is malformed"
        )
    expected_owner = canonical_work_unit_key(
        pipeline,
        mode,
        ecosystem,
        backend,
        phase_name,
        _live_prearm.PRESENCE_WORK_UNIT_ID,
    )
    if (
        preparation.get("schema_version")
        != "plamen.prearm_presence_preparation.v1"
        or preparation.get("authority_path")
        != _live_prearm.PRESENCE_AUTHORITY_FILE
        or preparation.get("phase_io_owner_key") != expected_owner
        or preparation.get("status_json_is_authority") is not False
    ):
        raise VerifyQueueTransactionError(
            "prearm presence preparation identity/owner is invalid"
        )
    authority_raw = preparation.get("authority")
    if not isinstance(authority_raw, Mapping):
        raise VerifyQueueTransactionError(
            "prearm presence authority payload is absent"
        )
    authority = dict(authority_raw)
    expected_authority_keys = {
        "schema_version",
        "pipeline",
        "mode",
        "ecosystem",
        "backend",
        "phase_name",
        "run_id",
        "authority_identity",
        "content_addressed",
        "caller_supplied_exact_roster",
        "live_glob_allowed",
        "live_directory_enumeration_allowed",
        "roster_count",
        "roster_identities",
        "roster_identity_digest",
        "directory_roster",
        "directory_roster_digest",
        "entries",
        "authority_digest",
    }
    if set(authority) != expected_authority_keys:
        raise VerifyQueueTransactionError(
            "prearm presence authority field denominator is malformed"
        )
    unsigned = {
        key: item for key, item in authority.items()
        if key != "authority_digest"
    }
    dimensions = {
        "pipeline": pipeline,
        "mode": mode,
        "ecosystem": ecosystem,
        "backend": backend,
        "phase_name": phase_name,
        "run_id": run_id,
    }
    roster = authority.get("roster_identities")
    entries = authority.get("entries")
    directories = authority.get("directory_roster")
    expected_identities = sorted(
        "scratchpad:" + _safe_relative(path)
        for path in expected_roster
    )
    if (
        authority.get("schema_version")
        != "plamen.prearm_presence_authority.v1"
        or any(authority.get(key) != item for key, item in dimensions.items())
        or authority.get("authority_identity")
        != "scratchpad:" + _live_prearm.PRESENCE_AUTHORITY_FILE
        or authority.get("content_addressed") is not True
        or authority.get("caller_supplied_exact_roster") is not True
        or authority.get("live_glob_allowed") is not False
        or authority.get("live_directory_enumeration_allowed") is not False
        or authority.get("authority_digest") != _stable_digest(unsigned)
        or roster != expected_identities
        or authority.get("roster_count") != len(expected_identities)
        or authority.get("roster_identity_digest")
        != _stable_digest(expected_identities)
        or not isinstance(entries, list)
        or len(entries) != len(expected_identities)
        or not isinstance(directories, list)
        or directories
        != _live_prearm.presence_directory_roster(expected_identities)
        or authority.get("directory_roster_digest")
        != _stable_digest(directories)
    ):
        raise VerifyQueueTransactionError(
            "prearm presence authority digest/roster denominator is invalid"
        )
    rows: dict[str, Mapping[str, Any]] = {}
    present_paths: list[str] = []
    for row in entries:
        if not isinstance(row, Mapping):
            raise VerifyQueueTransactionError(
                "prearm presence authority entry is malformed"
            )
        identity = str(row.get("identity") or "")
        if identity in rows or identity not in expected_identities:
            raise VerifyQueueTransactionError(
                "prearm presence authority entry identity is invalid"
            )
        rows[identity] = row
        state = str(row.get("state") or "")
        if state == "ABSENT":
            if set(row) != {"identity", "state"}:
                raise VerifyQueueTransactionError(
                    "prearm ABSENT authority row is malformed"
                )
        elif state in {"PRESENT", "PRESENT_AUTHORIZED"}:
            expected_fields = {
                "identity", "state", "sha256", "size", "producer"
            }
            if state == "PRESENT_AUTHORIZED":
                expected_fields.add("owner_key")
            if (
                set(row) != expected_fields
                or not _DIGEST_RE.fullmatch(str(row.get("sha256") or ""))
                or not isinstance(row.get("size"), int)
                or isinstance(row.get("size"), bool)
                or int(row["size"]) < 0
                or not isinstance(row.get("producer"), Mapping)
            ):
                raise VerifyQueueTransactionError(
                    "prearm PRESENT authority row is malformed"
                )
            present_paths.append(identity[len("scratchpad:"):])
        elif state == "PRESENT_UNAUTHORIZED_QUARANTINED":
            if (
                set(row) != {"identity", "state", "issues"}
                or not isinstance(row.get("issues"), list)
                or not row.get("issues")
            ):
                raise VerifyQueueTransactionError(
                    "prearm quarantined authority row is malformed"
                )
        else:
            raise VerifyQueueTransactionError(
                "prearm presence authority has unsupported state"
            )
    if set(rows) != set(expected_identities):
        raise VerifyQueueTransactionError(
            "prearm presence entry denominator is incomplete"
        )
    expected_effective = [
        *present_paths,
        _live_prearm.PRESENCE_AUTHORITY_FILE,
    ]
    if preparation.get("effective_input_paths") != expected_effective:
        raise VerifyQueueTransactionError(
            "prearm presence effective input denominator is invalid"
        )
    return preparation, authority


def _validated_preverify_frozen_projection(
    value: Mapping[str, Any],
    *,
    run_id: str,
) -> tuple[dict[str, Any], dict[str, str], set[str]]:
    """Validate the content-addressed logical-to-physical T0 projection."""

    if not isinstance(value, Mapping):
        raise VerifyQueueTransactionError(
            "preverify frozen projection is absent"
        )
    projection = dict(value)
    expected_fields = {
        "schema_version",
        "state",
        "run_id",
        "generation_digest",
        "work_unit_key",
        "receipt_path",
        "logical_to_physical",
        "required_paths",
        "advisory_evidence_path",
        "debt",
        "proof_authority",
    }
    if set(projection) != expected_fields:
        raise VerifyQueueTransactionError(
            "preverify frozen projection field denominator is malformed"
        )
    generation = str(projection.get("generation_digest") or "")
    receipt = _safe_relative(projection.get("receipt_path"))
    advisory = _safe_relative(
        projection.get("advisory_evidence_path")
    )
    if (
        projection.get("schema_version")
        != "plamen.preverify_frozen_projection.v1"
        or projection.get("state") != "OUTPUT_COMMITTED"
        or projection.get("run_id") != run_id
        or not _DIGEST_RE.fullmatch(generation)
        or projection.get("proof_authority") != "NONE"
        or not str(projection.get("work_unit_key") or "").endswith(
            "/preverify_frozen_projection." + generation
        )
        or not advisory.startswith(
            f"_preverify_frozen/generation_{generation}/"
        )
    ):
        raise VerifyQueueTransactionError(
            "preverify frozen projection identity/run/generation is invalid"
        )
    aliases_raw = projection.get("logical_to_physical")
    if not isinstance(aliases_raw, Mapping):
        raise VerifyQueueTransactionError(
            "preverify frozen logical alias map is malformed"
        )
    allowed_logical = {
        "findings_inventory.md",
        "finding_records.json",
        "inventory_evidence_validation.md",
    }
    aliases = {
        _safe_relative(logical): _safe_relative(physical)
        for logical, physical in aliases_raw.items()
    }
    if (
        set(aliases) - allowed_logical
        or not {
            "findings_inventory.md",
            "finding_records.json",
        } <= set(aliases)
        or len(set(aliases.values())) != len(aliases)
        or any(
            not physical.startswith(
                f"_preverify_frozen/generation_{generation}/"
            )
            for physical in aliases.values()
        )
    ):
        raise VerifyQueueTransactionError(
            "preverify frozen logical/physical alias denominator is invalid"
        )
    raw_required = projection.get("required_paths")
    if (
        not isinstance(raw_required, list)
        or any(not isinstance(path, str) for path in raw_required)
    ):
        raise VerifyQueueTransactionError(
            "preverify frozen required path denominator is malformed"
        )
    required = {_safe_relative(path) for path in raw_required}
    if (
        raw_required != sorted(required)
        or len(raw_required) != len(required)
        or not {*aliases.values(), receipt} <= required
        or any(
            not path.startswith(
                f"_preverify_frozen/generation_{generation}/"
            )
            for path in required
        )
        or not isinstance(projection.get("debt"), list)
    ):
        raise VerifyQueueTransactionError(
            "preverify frozen required/debt denominator is invalid"
        )
    return projection, aliases, required


def _validated_preverify_chain_pair_projection(
    value: Mapping[str, Any] | None,
    *,
    pipeline: str,
    run_id: str,
) -> tuple[dict[str, Any] | None, dict[str, str], set[str]]:
    """Validate the atomic SC hypothesis/mapping projection.

    A degraded provider result is bound into the plan as visible debt but does
    not authorize either mutable root or its diagnostic receipt as a semantic
    T0 input.  L1 has no SC chain pair and must not supply this projection.
    """

    if pipeline == "l1":
        if value is not None:
            raise VerifyQueueTransactionError(
                "L1 must not supply an SC chain-pair projection"
            )
        return None, {}, set()
    if not isinstance(value, Mapping):
        raise VerifyQueueTransactionError(
            "SC preverify chain-pair projection is absent"
        )
    projection = dict(value)
    expected_fields = {
        "schema_version",
        "state",
        "safe_to_consume",
        "run_id",
        "generation_digest",
        "work_unit_key",
        "receipt_path",
        "logical_to_physical",
        "required_paths",
        "debt",
        "proof_authority",
    }
    if set(projection) != expected_fields:
        raise VerifyQueueTransactionError(
            "SC chain-pair projection field denominator is malformed"
        )
    if (
        projection.get("schema_version")
        != "plamen.preverify_chain_pair_projection.v1"
        or projection.get("run_id") != run_id
        or projection.get("proof_authority") != "NONE"
        or not isinstance(projection.get("debt"), list)
    ):
        raise VerifyQueueTransactionError(
            "SC chain-pair projection identity/run/policy is invalid"
        )
    state = str(projection.get("state") or "")
    receipt = _safe_relative(projection.get("receipt_path"))
    aliases_raw = projection.get("logical_to_physical")
    required_raw = projection.get("required_paths")
    if (
        not isinstance(aliases_raw, Mapping)
        or not isinstance(required_raw, list)
        or any(not isinstance(path, str) for path in required_raw)
    ):
        raise VerifyQueueTransactionError(
            "SC chain-pair projection path denominator is malformed"
        )
    aliases = {
        _safe_relative(logical): _safe_relative(physical)
        for logical, physical in aliases_raw.items()
    }
    required = {_safe_relative(path) for path in required_raw}
    if required_raw != sorted(required) or len(required_raw) != len(required):
        raise VerifyQueueTransactionError(
            "SC chain-pair required paths are noncanonical"
        )

    if state == "DEGRADED_INPUT_AUTHORITY":
        debt_name = receipt.removeprefix("_preverify_chain_pair/debt_")
        if (
            projection.get("safe_to_consume") is not False
            or projection.get("generation_digest") is not None
            or projection.get("work_unit_key") is not None
            or aliases
            or required != {receipt}
            or not receipt.startswith("_preverify_chain_pair/debt_")
            or not debt_name.endswith(".json")
            or not _DIGEST_RE.fullmatch(debt_name[:-5])
            or not projection["debt"]
        ):
            raise VerifyQueueTransactionError(
                "degraded SC chain-pair projection is malformed"
            )
        # Diagnostic-only debt never becomes semantic input authority.
        return projection, {}, set()

    generation = str(projection.get("generation_digest") or "")
    prefix = f"_preverify_chain_pair/generation_{generation}/"
    expected_logical = {"hypotheses.md", "finding_mapping.md"}
    relation_debt = projection.get("debt")
    relation_debt_valid = (
        relation_debt == []
        or (
            isinstance(relation_debt, list)
            and len(relation_debt) == 1
            and isinstance(relation_debt[0], Mapping)
            and set(relation_debt[0]) == {
                "reason_code",
                "issues",
                "candidate_disposition",
                "proof_authority",
            }
            and relation_debt[0].get("reason_code") in {
                "CHAIN_PAIR_RELATION_AMBIGUOUS",
                "CHAIN_PAIR_RELATION_CONTRADICTION",
            }
            and isinstance(relation_debt[0].get("issues"), list)
            and bool(relation_debt[0]["issues"])
            and all(
                isinstance(issue, str) and bool(issue.strip())
                for issue in relation_debt[0]["issues"]
            )
            and relation_debt[0].get("candidate_disposition")
            == "PRESERVE_BOTH_ROOTS_FOR_VERIFICATION"
            and relation_debt[0].get("proof_authority") == "NONE"
        )
    )
    if (
        state != "OUTPUT_COMMITTED"
        or projection.get("safe_to_consume") is not True
        or not _DIGEST_RE.fullmatch(generation)
        or not relation_debt_valid
        or not str(projection.get("work_unit_key") or "").endswith(
            "/preverify_chain_pair_projection." + generation
        )
        or set(aliases) != expected_logical
        or len(set(aliases.values())) != len(aliases)
        or any(not path.startswith(prefix) for path in aliases.values())
        or receipt != prefix + "receipt.json"
        or required != {*aliases.values(), receipt}
    ):
        raise VerifyQueueTransactionError(
            "committed SC chain-pair projection is malformed"
        )
    return projection, aliases, required


def _safe_relative(value: Any) -> str:
    text = str(value or "").strip().replace("\\", "/")
    path = PurePosixPath(text)
    if (
        not text
        or path.is_absolute()
        or re.match(r"^[A-Za-z]:", text)
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(token in text for token in "*?[")
    ):
        raise VerifyQueueTransactionError(
            f"unsafe verify-queue artifact path: {value!r}"
        )
    return path.as_posix()


def _safe_glob(value: Any) -> str:
    text = str(value or "").strip().replace("\\", "/")
    path = PurePosixPath(text)
    if (
        not text
        or path.is_absolute()
        or re.match(r"^[A-Za-z]:", text)
        or any(part in {"", ".", ".."} for part in path.parts)
        or "?" in text
        or "[" in text
        or "]" in text
        or any("*" in part for part in path.parts[:-1])
    ):
        raise VerifyQueueTransactionError(
            f"unsafe verification-context glob: {value!r}"
        )
    return path.as_posix()


def _output_row(
    path: str,
    *,
    conditional: bool = False,
    condition_id: str = "",
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "path": _safe_relative(path),
        "artifact_class": (
            "CONDITIONAL" if conditional else "DRIVER_GENERATED"
        ),
        "writer": "DRIVER",
        "write_mode": "CREATE",
    }
    if conditional:
        row.update({
            "condition_id": condition_id,
            "exclusive_group": "compound_delivery_disposition",
        })
    return row


def _unit(
    work_unit_id: str,
    exact_inputs: Sequence[str],
    outputs: Sequence[str],
    *,
    conditional: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    conditional = dict(conditional or {})
    return {
        "work_unit_id": work_unit_id,
        "exact_inputs": [_safe_relative(value) for value in exact_inputs],
        "outputs": [
            _output_row(
                path,
                conditional=path in conditional,
                condition_id=conditional.get(path, ""),
            )
            for path in outputs
        ],
        "model_invoked": False,
        "read_only": False,
    }


def _live_output_row(
    path: str,
    *,
    conditional: bool = False,
    condition_id: str = "",
    exclusive_group: str = "",
) -> dict[str, Any]:
    """Build one live output-authority row without sharing legacy semantics."""

    row: dict[str, Any] = {
        "path": _safe_relative(path),
        "root": "scratchpad",
        "artifact_class": (
            "CONDITIONAL" if conditional else "DRIVER_GENERATED"
        ),
        "writer": "DRIVER",
        "write_mode": "CREATE",
        "required": not conditional,
    }
    if conditional:
        if not condition_id or not exclusive_group:
            raise VerifyQueueTransactionError(
                f"conditional live output lacks closure identity: {path}"
            )
        row.update({
            "condition_id": str(condition_id),
            "exclusive_group": str(exclusive_group),
        })
    return row


def _live_unit(
    work_unit_id: str,
    exact_inputs: Sequence[str],
    outputs: Sequence[str],
    *,
    conditional_outputs: Mapping[str, tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Build a live child with exact PhaseIO/CAS authority."""

    conditional = dict(conditional_outputs or {})
    inputs = [
        str(value).strip().replace("\\", "/")
        if str(value).strip().replace("\\", "/").startswith("project::")
        else _safe_relative(value)
        for value in exact_inputs
    ]
    if len(inputs) != len(set(inputs)):
        raise VerifyQueueTransactionError(
            f"{work_unit_id}: duplicate exact input authority"
        )
    output_rows = []
    for path in outputs:
        path_n = _safe_relative(path)
        condition = conditional.get(path_n)
        output_rows.append(_live_output_row(
            path_n,
            conditional=condition is not None,
            condition_id=condition[0] if condition else "",
            exclusive_group=condition[1] if condition else "",
        ))
    if len(output_rows) != len({row["path"] for row in output_rows}):
        raise VerifyQueueTransactionError(
            f"{work_unit_id}: duplicate output authority"
        )
    return {
        "work_unit_id": work_unit_id,
        "exact_inputs": inputs,
        "declared_input_denominator": list(inputs),
        "outputs": output_rows,
        "model_invoked": False,
        "semantic_executor_invoked": True,
        "read_only": False,
        "phase_io": {
            "resolve_before_output": True,
            "record_inputs": True,
            "revalidate_inputs_before_commit": True,
            "record_artifacts": True,
            "output_prestate_cas": True,
        },
    }


def _projection_triplet(markdown_path: str) -> set[str]:
    path = PurePosixPath(_safe_relative(markdown_path))
    if path.suffix != ".md":
        raise VerifyQueueTransactionError(
            "verify shard manifest must be a markdown path"
        )
    stem = path.as_posix()[:-3]
    return {
        path.as_posix(),
        stem + ".json",
        stem + ".work_items.json",
    }


def classify_verify_queue_transaction_state(
    states: Sequence[str],
) -> str:
    """Return the worst closed state; reject every unknown third state."""

    normalized = tuple(str(value or "").strip() for value in states)
    if not normalized:
        raise ValueError("verify-queue state denominator is empty")
    unknown = sorted(set(normalized) - VERIFY_QUEUE_TERMINAL_STATES)
    if unknown:
        raise ValueError(
            "unknown verify-queue transaction state: "
            + ", ".join(unknown)
        )
    return max(normalized, key=lambda value: _STATE_PRECEDENCE[value])


def resolve_verify_queue_transaction_plan(
    *,
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
    phase_name: str,
    external_inputs: Sequence[str],
    shard_manifests: Sequence[str],
    context_capture: Mapping[str, Any],
) -> dict[str, Any]:
    """Resolve the exact backend-neutral T0..T9 publication DAG."""

    pipeline_n = str(pipeline or "").strip().lower()
    phase_n = str(phase_name or "").strip().lower()
    if pipeline_n not in {"sc", "l1"}:
        raise VerifyQueueTransactionError("pipeline must be sc or l1")
    expected_phase = "sc_verify_queue" if pipeline_n == "sc" else "verify_queue"
    if phase_n != expected_phase:
        raise VerifyQueueTransactionError(
            f"{pipeline_n} queue phase must be {expected_phase}"
        )
    mode_n = str(mode or "").strip().lower()
    ecosystem_n = str(ecosystem or "").strip().lower()
    backend_n = str(backend or "").strip().lower()
    if not mode_n or not ecosystem_n or backend_n not in {"claude", "codex"}:
        raise VerifyQueueTransactionError(
            "mode/ecosystem/backend transaction identity is invalid"
        )
    external = tuple(sorted({_safe_relative(value) for value in external_inputs}))
    required_external = {
        "finding_delivery_successor.json",
        "finding_records.json",
        "findings_inventory.md",
        "preverify_inventory_successor.json",
    }
    if set(external) != required_external:
        raise VerifyQueueTransactionError(
            "verify-queue external input denominator must be the exact "
            "inventory/finding-record/successor authority set"
        )
    manifests = tuple(sorted({_safe_relative(value) for value in shard_manifests}))
    if not manifests:
        raise VerifyQueueTransactionError(
            "verify-queue shard manifest denominator is empty"
        )
    if not isinstance(context_capture, Mapping):
        raise VerifyQueueTransactionError(
            "verification-context dynamic capture specification is absent"
        )
    context_inputs = tuple(sorted({
        str(value).strip().replace("\\", "/")
        for value in context_capture.get("exact_inputs", ())
    }))
    graph_artifacts = tuple(sorted({
        _safe_relative(value)
        for value in context_capture.get("graph_artifacts", ())
    }))
    graph_globs = tuple(sorted({
        _safe_glob(value)
        for value in context_capture.get("graph_globs", ())
    }))
    primary_artifacts = tuple(sorted({
        str(value).strip().replace("\\", "/")
        for value in context_capture.get("primary_artifacts", ())
    }))
    sibling_directories = tuple(sorted({
        str(value).strip().replace("\\", "/")
        for value in context_capture.get("project_sibling_directories", ())
    }))
    if not context_inputs or any(
        not value.startswith("project::") and _safe_relative(value) != value
        for value in context_inputs
    ):
        raise VerifyQueueTransactionError(
            "verification-context exact input denominator is invalid"
        )
    if any(
        not value.startswith("project::")
        for value in primary_artifacts
    ) or any(
        not value.startswith("project::")
        for value in sibling_directories
    ):
        raise VerifyQueueTransactionError(
            "verification-context project capture scopes are invalid"
        )

    children: list[dict[str, Any]] = []
    children.append(_unit(_CHILD_IDS[0], external, _T0_OUTPUTS))
    children.append(_unit(_CHILD_IDS[1], _T0_OUTPUTS, _T1_OUTPUTS))
    children.append(_unit(_CHILD_IDS[2], _T1_OUTPUTS, _T2_OUTPUTS))
    children.append(_unit(
        _CHILD_IDS[3],
        (_T0_OUTPUTS[0], _T2_OUTPUTS[0], _T2_OUTPUTS[2], _STATUS_PATHS[2]),
        _T3_OUTPUTS,
    ))
    children.append(_unit(
        _CHILD_IDS[4],
        (
            _T0_OUTPUTS[0],
            "verify_queue_context_input_status.json",
            _T2_OUTPUTS[0],
            _STATUS_PATHS[2],
        ),
        _T4_OUTPUTS,
        conditional=_T4_CONDITIONAL,
    ))
    compound_unit = _unit(
        _CHILD_IDS[5],
        (
            _T2_OUTPUTS[0],
            "compound_verification_delivery_disposition.json",
            _STATUS_PATHS[4],
        ),
        _T5_OUTPUTS,
    )
    compound_unit["delivery_state_exact_inputs"] = {
        "COMMITTED_APPLIED": [
            "compound_verification_delivery_disposition.json",
            "compound_verification_delivery_receipt.json",
        ],
        "COMMITTED_CLEAN_NOOP": [
            "compound_verification_delivery_disposition.json",
        ],
        "COMPLETED_WITH_DEBT_SAFE_BASE": [
            "compound_verification_delivery_debt.json",
            "compound_verification_delivery_disposition.json",
        ],
    }
    children.append(compound_unit)
    final_work_item_unit = _unit(
        _CHILD_IDS[6],
        (*_T2_OUTPUTS, *_T3_OUTPUTS, *_T5_OUTPUTS),
        _T6_OUTPUTS,
    )
    final_work_item_unit["work_item_merge_sources"] = {
        "base_active": _T2_OUTPUTS[0],
        "mandatory_reverification": _T3_OUTPUTS[0],
        "compound_composition": "compound_verification_work_plan.json",
    }
    children.append(final_work_item_unit)
    context_unit = _unit(
        _CHILD_IDS[7],
        (*_T6_OUTPUTS, *context_inputs),
        _T7_OUTPUTS,
    )
    coverage_invariant = {
        "relation": "EXACT_WORK_ITEM_ID_SET_EQUALITY",
        "denominator": _T6_OUTPUTS[0],
        "context_packets": _T7_OUTPUTS[2],
        "shard_assignments": _T7_OUTPUTS[4],
    }
    context_unit["work_item_denominator_input"] = _T6_OUTPUTS[0]
    context_unit["coverage_invariant"] = coverage_invariant
    context_unit["dynamic_input_capture"] = {
        "content_addressed": True,
        "revalidate_before_commit": True,
        "late_appearance_state": "QUARANTINED_FOREIGN_STATE",
        "exact_inputs": list(context_inputs),
        "enumerates": [
            "graph_artifacts",
            "graph_globs",
            "primary_artifacts",
            "project_sibling_directories",
        ],
        "graph_artifacts": list(graph_artifacts),
        "graph_globs": list(graph_globs),
        "primary_artifacts": list(primary_artifacts),
        "project_sibling_directories": list(sibling_directories),
    }
    children.append(context_unit)
    through_t7 = sorted({
        str(output["path"])
        for child in children
        for output in child["outputs"]
        if output["artifact_class"] != "CONDITIONAL"
    })
    validation_unit = _unit(
        _CHILD_IDS[8], through_t7, _T8_OUTPUTS
    )
    validation_unit["work_item_coverage_validation"] = coverage_invariant
    children.append(validation_unit)
    public_outputs = set(_COMMON_PUBLIC_OUTPUTS)
    for manifest in manifests:
        public_outputs.update(_projection_triplet(manifest))
    children.append(_unit(
        _CHILD_IDS[9], _T8_OUTPUTS, tuple(sorted(public_outputs))
    ))

    parent_inputs = sorted({
        *_STATUS_PATHS,
        _T8_OUTPUTS[0],
        "verify_queue_context_input_status.json",
        "mandatory_reverification_denominator.json",
        "mandatory_reverification_queue_transaction.receipt.json",
        "mandatory_reverification_routing.json",
        "compound_verification_delivery_disposition.json",
        "compound_candidates.json",
        "compound_verification_work_plan.json",
        *public_outputs,
    })
    parent = {
        "work_unit_id": _PARENT_ID,
        "exact_inputs": parent_inputs,
        "outputs": [],
        "model_invoked": False,
        "read_only": True,
        "validates_work_units": list(_CHILD_IDS),
    }
    outer = sorted({
        str(output["path"])
        for child in children
        for output in child["outputs"]
    })
    unsigned: dict[str, Any] = {
        "schema_version": _PLAN_SCHEMA,
        "pipeline": pipeline_n,
        "mode": mode_n,
        "ecosystem": ecosystem_n,
        "backend": backend_n,
        "phase_name": phase_n,
        "external_input_denominator": sorted({
            *external, *context_inputs
        }),
        "upstream_pair_groups": {
            "paired_inventory_projection": [
                "findings_inventory.md",
                "finding_records.json",
            ],
        },
        "shard_manifests": list(manifests),
        "children": children,
        "parent": parent,
        "outer_output_denominator": outer,
    }
    return {**unsigned, "plan_digest": _stable_digest(unsigned)}


def resolve_live_verify_queue_transaction_plan(
    *,
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
    phase_name: str,
    run_id: str,
    upstream_inputs: Sequence[str],
    runtime_authority: Mapping[str, Any],
    shard_manifests: Sequence[str],
    context_capture: Mapping[str, Any],
    preverify_frozen_projection: Mapping[str, Any],
    preverify_chain_pair_projection: Mapping[str, Any] | None = None,
    prearm_input_manifest: Mapping[str, Any] | None = None,
    prearm_resolution: Mapping[str, Any] | None = None,
    prearm_presence: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve the production-semantic, backend-neutral T0..T9 DAG.

    This resolver is deliberately declarative.  It grants no execution or
    publication authority: the live executor must bind every row through
    PhaseIO, and only T9 may publish the immutable T8 bundle into the public
    scratchpad namespace.
    """

    pipeline_n = str(pipeline or "").strip().lower()
    phase_n = str(phase_name or "").strip().lower()
    if pipeline_n not in {"sc", "l1"}:
        raise VerifyQueueTransactionError("pipeline must be sc or l1")
    expected_phase = "sc_verify_queue" if pipeline_n == "sc" else "verify_queue"
    if phase_n != expected_phase:
        raise VerifyQueueTransactionError(
            f"{pipeline_n} queue phase must be {expected_phase}"
        )
    mode_n = str(mode or "").strip().lower()
    ecosystem_n = str(ecosystem or "").strip().lower()
    backend_n = str(backend or "").strip().lower()
    run_id_n = str(run_id or "").strip()
    if (
        not mode_n
        or not ecosystem_n
        or backend_n not in {"claude", "codex"}
        or not run_id_n
    ):
        raise VerifyQueueTransactionError(
            "live mode/ecosystem/backend/run identity is invalid"
        )
    (
        normalized_frozen_projection,
        logical_input_aliases,
        frozen_projection_required,
    ) = _validated_preverify_frozen_projection(
        preverify_frozen_projection,
        run_id=run_id_n,
    )
    (
        normalized_chain_pair_projection,
        chain_pair_aliases,
        chain_pair_required,
    ) = _validated_preverify_chain_pair_projection(
        preverify_chain_pair_projection,
        pipeline=pipeline_n,
        run_id=run_id_n,
    )
    if set(logical_input_aliases) & set(chain_pair_aliases):
        raise VerifyQueueTransactionError(
            "preverify logical input projections collide"
        )
    logical_input_aliases = {
        **logical_input_aliases,
        **chain_pair_aliases,
    }

    branch_presence = (
        _LIVE_SC_PRESENCE_ROSTER
        if pipeline_n == "sc"
        else _LIVE_L1_PRESENCE_ROSTER
    )
    # The SC canonical identity denominator is not a static queue input.  It is
    # admitted only when the content-addressed prearm manifest selects the
    # P0-AF branch and binds its exact bytes.
    branch_required: set[str] = set()
    prearm_manifest: dict[str, Any] | None = None
    normalized_prearm_resolution: dict[str, Any] | None = None
    prearm_sources: tuple[str, ...] = ()
    prearm_required: set[str] = set()
    if prearm_resolution is not None:
        (
            normalized_prearm_resolution,
            prearm_manifest,
            resolution_inputs,
        ) = _validated_prearm_resolution(
            prearm_resolution,
            pipeline=pipeline_n,
            mode=mode_n,
            ecosystem=ecosystem_n,
            backend=backend_n,
            phase_name=phase_n,
            run_id=run_id_n,
        )
        prearm_sources = tuple(
            normalized_prearm_resolution["dynamic_source_paths"]
        )
        prearm_required = set(resolution_inputs)
        if normalized_prearm_resolution["state"] == "RESOLVED":
            prearm_required.add(_live_sc_adapter.CANDIDATE_FILE)
        if prearm_input_manifest is not None and (
            prearm_manifest is None
            or dict(prearm_input_manifest) != prearm_manifest
        ):
            raise VerifyQueueTransactionError(
                "prearm manifest and resolution arguments disagree"
            )
    elif prearm_input_manifest is not None:
        prearm_manifest, prearm_sources = _validated_prearm_input_manifest(
            prearm_input_manifest,
            pipeline=pipeline_n,
            run_id=run_id_n,
        )
        prearm_required = {
            _LIVE_PREARM_INPUT_MANIFEST,
            _LIVE_SC_IDENTITY_DENOMINATOR,
            *prearm_sources,
        }
    expected_upstream = frozenset({
        *_LIVE_REQUIRED_UPSTREAM,
        *branch_required,
        *prearm_required,
        *frozen_projection_required,
        *chain_pair_required,
        *_LIVE_COMMON_PRESENCE_ROSTER,
        *branch_presence,
    })
    normalized_prearm_presence: dict[str, Any] | None = None
    prearm_presence_authority: dict[str, Any] | None = None
    if prearm_presence is not None:
        (
            normalized_prearm_presence,
            prearm_presence_authority,
        ) = _validated_prearm_presence(
            prearm_presence,
            pipeline=pipeline_n,
            mode=mode_n,
            ecosystem=ecosystem_n,
            backend=backend_n,
            phase_name=phase_n,
            run_id=run_id_n,
            expected_roster=set(expected_upstream),
        )
        expected_upstream = frozenset({
            *expected_upstream,
            _live_prearm.PRESENCE_AUTHORITY_FILE,
        })
        prearm_required.add(_live_prearm.PRESENCE_AUTHORITY_FILE)
    upstream = tuple(sorted({
        _safe_relative(value) for value in upstream_inputs
    }))
    if set(upstream) != expected_upstream:
        missing = sorted(expected_upstream - set(upstream))
        unexpected = sorted(set(upstream) - expected_upstream)
        raise VerifyQueueTransactionError(
            "live upstream denominator does not match the exact "
            f"{pipeline_n} authority roster; missing={missing!r}; "
            f"unexpected={unexpected!r}"
        )

    if not isinstance(runtime_authority, Mapping):
        raise VerifyQueueTransactionError("live runtime authority is absent")
    runtime = dict(runtime_authority)
    required_runtime_fields = {
        "audit_snapshot_digest",
        "trusted_queue_code_digest",
        "producer_ledger_digest",
        "methodology_digest",
        "pipeline",
        "mode",
        "ecosystem",
        "backend",
        "run_id",
    }
    if set(runtime) != required_runtime_fields:
        raise VerifyQueueTransactionError(
            "live runtime authority must contain its exact binding denominator"
        )
    expected_runtime_identity = {
        "pipeline": pipeline_n,
        "mode": mode_n,
        "ecosystem": ecosystem_n,
        "backend": backend_n,
        "run_id": run_id_n,
    }
    if any(
        str(runtime.get(key) or "").strip().lower()
        != str(value).strip().lower()
        for key, value in expected_runtime_identity.items()
    ):
        raise VerifyQueueTransactionError(
            "live runtime authority does not bind the requested run tuple"
        )
    for key in (
        "audit_snapshot_digest",
        "trusted_queue_code_digest",
        "producer_ledger_digest",
        "methodology_digest",
    ):
        if not _DIGEST_RE.fullmatch(str(runtime.get(key) or "").strip()):
            raise VerifyQueueTransactionError(
                f"live runtime authority {key} is not a sha256 digest"
            )

    manifests = tuple(sorted({
        _safe_relative(value) for value in shard_manifests
    }))
    if not manifests:
        raise VerifyQueueTransactionError(
            "live verify shard manifest denominator is empty"
        )
    shard_outputs: set[str] = set()
    for manifest in manifests:
        shard_outputs.update(_projection_triplet(manifest))

    if not isinstance(context_capture, Mapping):
        raise VerifyQueueTransactionError(
            "live verification-context capture specification is absent"
        )

    def _context_path(value: Any, *, project_only: bool = False) -> str:
        text = str(value or "").strip().replace("\\", "/")
        if text.startswith("project::"):
            project_relative = _safe_relative(text[len("project::"):])
            return "project::" + project_relative
        if project_only:
            raise VerifyQueueTransactionError(
                f"live project context scope is invalid: {value!r}"
            )
        return _safe_relative(text)

    context_inputs = tuple(sorted({
        _context_path(value)
        for value in context_capture.get("exact_inputs", ())
    }))
    graph_artifacts = tuple(sorted({
        _safe_relative(value)
        for value in context_capture.get("graph_artifacts", ())
    }))
    graph_globs = tuple(sorted({
        _safe_glob(value)
        for value in context_capture.get("graph_globs", ())
    }))
    primary_artifacts = tuple(sorted({
        _context_path(value, project_only=True)
        for value in context_capture.get("primary_artifacts", ())
    }))
    sibling_directories = tuple(sorted({
        _context_path(value, project_only=True)
        for value in context_capture.get("project_sibling_directories", ())
    }))
    methodology_registry = _safe_relative(
        context_capture.get("methodology_registry", "")
    )
    methodology_reachability = _safe_relative(
        context_capture.get("methodology_reachability", "")
    )
    if not context_inputs:
        raise VerifyQueueTransactionError(
            "live verification-context input denominator is empty"
        )
    context_set = set(context_inputs)
    required_context = {
        *graph_artifacts,
        *primary_artifacts,
        methodology_registry,
        methodology_reachability,
    }
    if not required_context <= context_set:
        raise VerifyQueueTransactionError(
            "live context capture scopes are not bound by exact_inputs"
        )

    t4_prefix = f"{_LIVE_PRIVATE_ROOT}/t4"
    if pipeline_n == "sc":
        t4_outputs = (
            f"{t4_prefix}/queue_delta.work_items.json",
            f"{t4_prefix}/composition_disposition.json",
            f"{t4_prefix}/p0af_queue_input.work_items.json",
            f"{t4_prefix}/p0af_delivery_receipt.json",
            f"{t4_prefix}/p0af_delivery_debt.json",
            f"{t4_prefix}/p0af_delivery_status.json",
            _LIVE_STATUS_PATHS[4],
        )
        pipeline_adapter = "p0af_v2_queue_adapter"
        compatibility_outputs = _LIVE_SC_COMPATIBILITY_OUTPUTS
        legacy_journals = frozenset({
            _live_mandatory.QUEUE_TRANSACTION_JOURNAL_FILE,
            _live_sc_composition.JOURNAL_FILE,
        })
    else:
        t4_outputs = (
            f"{t4_prefix}/queue_delta.work_items.json",
            f"{t4_prefix}/composition_disposition.json",
            f"{t4_prefix}/l1_queue_input.work_items.json",
            f"{t4_prefix}/l1_delivery_receipt.json",
            f"{t4_prefix}/l1_delivery_debt.json",
            f"{t4_prefix}/l1_delivery_status.json",
            _LIVE_STATUS_PATHS[4],
        )
        pipeline_adapter = "l1_composition_queue_adapter"
        compatibility_outputs = _LIVE_L1_COMPATIBILITY_OUTPUTS
        legacy_journals = frozenset({
            _live_mandatory.QUEUE_TRANSACTION_JOURNAL_FILE,
            _live_l1_composition.DELIVERY_JOURNAL_NAME,
        })

    public_outputs = frozenset({
        *_LIVE_COMMON_PUBLIC_OUTPUTS,
        *compatibility_outputs,
        *shard_outputs,
    })
    conditional_private = {
        _LIVE_T5_OUTPUTS[4]: (
            "receipt_selected",
            "compound_delivery",
        ),
        _LIVE_T5_OUTPUTS[5]: (
            "debt_selected",
            "compound_delivery",
        ),
    }
    conditional_public = {
        "compound_verification_delivery_receipt.json": (
            "receipt_selected",
            "compound_delivery",
        ),
        "compound_verification_delivery_debt.json": (
            "debt_selected",
            "compound_delivery",
        ),
    }

    children: list[dict[str, Any]] = []
    required_upstream = {
        *_LIVE_REQUIRED_UPSTREAM,
        *branch_required,
        *prearm_required,
        *frozen_projection_required,
        *chain_pair_required,
    }
    t0 = _live_unit(_LIVE_CHILD_IDS[0], upstream, _LIVE_T0_OUTPUTS)
    t0.update({
        "presence_roster": sorted(expected_upstream - required_upstream),
        "required_inputs": sorted(required_upstream),
        "runtime_authority": runtime,
        "logical_input_aliases": dict(sorted(logical_input_aliases.items())),
        "preverify_frozen_projection": normalized_frozen_projection,
        "preverify_chain_pair_projection": (
            normalized_chain_pair_projection
        ),
        "producer_binding_policy": {
            "owner": True,
            "writer": True,
            "run_id": True,
            "contract_digest": True,
            "launch_digest": True,
            "sha256": True,
            "size": True,
            "explicit_absence": True,
        },
    })
    if prearm_manifest is not None:
        t0["prearm_content_addressed_input_manifest"] = prearm_manifest
    if normalized_prearm_resolution is not None:
        t0["prearm_dynamic_input_resolution"] = {
            key: value
            for key, value in normalized_prearm_resolution.items()
            if key != "manifest"
        }
    if normalized_prearm_presence is not None:
        t0["prearm_presence_preparation"] = {
            key: value
            for key, value in normalized_prearm_presence.items()
            if key != "authority"
        }
        t0["prearm_presence_authority"] = prearm_presence_authority
        presence_states = {
            str(row.get("identity") or "")[len("scratchpad:"):]:
                str(row.get("state") or "")
            for row in prearm_presence_authority.get("entries", ())
            if isinstance(row, Mapping)
            and str(row.get("identity") or "").startswith("scratchpad:")
        }
        t0["explicit_absence_roster"] = sorted(
            path
            for path in t0["presence_roster"]
            if presence_states.get(path)
            != "PRESENT_UNAUTHORIZED_QUARANTINED"
        )
    children.append(t0)
    children.append(_live_unit(
        _LIVE_CHILD_IDS[1],
        _LIVE_T0_OUTPUTS,
        _LIVE_T1_OUTPUTS,
    ))
    children.append(_live_unit(
        _LIVE_CHILD_IDS[2],
        (
            *_LIVE_T1_OUTPUTS,
            _LIVE_T0_OUTPUTS[0],
            _LIVE_T0_OUTPUTS[2],
        ),
        _LIVE_T2_OUTPUTS,
    ))
    children.append(_live_unit(
        _LIVE_CHILD_IDS[3],
        (
            _LIVE_T0_OUTPUTS[0],
            _LIVE_T0_OUTPUTS[2],
            _LIVE_T2_OUTPUTS[0],
            _LIVE_T2_OUTPUTS[1],
            _LIVE_STATUS_PATHS[2],
        ),
        _LIVE_T3_OUTPUTS,
    ))
    t4 = _live_unit(
        _LIVE_CHILD_IDS[4],
        (
            _LIVE_T0_OUTPUTS[0],
            _LIVE_T2_OUTPUTS[0],
            _LIVE_STATUS_PATHS[2],
        ),
        t4_outputs,
    )
    t4.update({
        "pipeline_adapter": pipeline_adapter,
        "public_queue_mutation": False,
    })
    children.append(t4)
    t5 = _live_unit(
        _LIVE_CHILD_IDS[5],
        (
            _LIVE_T0_OUTPUTS[0],
            _LIVE_T0_OUTPUTS[2],
            _LIVE_T2_OUTPUTS[0],
            _LIVE_STATUS_PATHS[2],
        ),
        _LIVE_T5_OUTPUTS,
        conditional_outputs=conditional_private,
    )
    t5["conditional_groups"] = {
        "compound_delivery": {
            "selection": "EXACTLY_ONE",
            "receipt": _LIVE_T5_OUTPUTS[4],
            "debt": _LIVE_T5_OUTPUTS[5],
            "disposition": _LIVE_T5_OUTPUTS[3],
            "status": _LIVE_STATUS_PATHS[5],
        },
    }
    children.append(t5)

    t6_inputs = tuple(
        path
        for outputs in (
            _LIVE_T2_OUTPUTS,
            _LIVE_T3_OUTPUTS,
            t4_outputs,
            _LIVE_T5_OUTPUTS,
        )
        for path in outputs
    )
    t6 = _live_unit(
        _LIVE_CHILD_IDS[6],
        t6_inputs,
        _LIVE_T6_OUTPUTS,
    )
    t6["exact_inputs"] = [
        path for path in t6["exact_inputs"]
        if path not in conditional_private
    ]
    t6.update({
        "merge_sources": {
            "policy_active": _LIVE_T2_OUTPUTS[0],
            "policy_excluded": _LIVE_T2_OUTPUTS[1],
            "policy_debt": _LIVE_T2_OUTPUTS[2],
            "mandatory_delta": _LIVE_T3_OUTPUTS[0],
            "pipeline_composition_delta": t4_outputs[0],
            "generic_compound_delta": _LIVE_T5_OUTPUTS[2],
        },
        "identity_invariants": {
            "unique_work_item_ids": True,
            "additive_collision_becomes_visible_debt": True,
            "source_obligation_partition": [
                "ACTIVE",
                "AUTHORIZED_EXCLUDED",
                "VISIBLE_DEBT",
            ],
            "exact_partition": True,
        },
        # ``exact_inputs`` remains the immutable semantic denominator.  The
        # committed T5 conditional state selects which one of these two paths
        # has a physical postimage; the unselected path is still represented
        # by its PhaseIO conditional-output state, never by an absent read.
        "conditional_input_groups": {
            "compound_delivery": {
                "selection": "EXACTLY_ONE",
                "candidates": [
                    _LIVE_T5_OUTPUTS[4],
                    _LIVE_T5_OUTPUTS[5],
                ],
                "disposition": _LIVE_T5_OUTPUTS[3],
                "status": _LIVE_STATUS_PATHS[5],
                "authority_work_unit_id": _LIVE_CHILD_IDS[5],
                "effective_input_policy": (
                    "COMMITTED_PHASEIO_CONDITIONAL_STATE"
                ),
                "bind_selected_output_sha256_size": True,
                "bind_unselected_absence_record": True,
                "status_json_alone_is_authority": False,
            },
        },
    })
    children.append(t6)

    coverage_invariant = {
        "relation": "EXACT_WORK_ITEM_ID_SET_EQUALITY",
        "denominator": _LIVE_T6_OUTPUTS[0],
        "context_packets": _LIVE_T7_OUTPUTS[2],
        "shard_assignments": _LIVE_T7_OUTPUTS[4],
    }
    t7 = _live_unit(
        _LIVE_CHILD_IDS[7],
        (*_LIVE_T6_OUTPUTS, *context_inputs),
        _LIVE_T7_OUTPUTS,
    )
    t7.update({
        "dynamic_input_capture": {
            "content_addressed": True,
            "revalidate_before_commit": True,
            "late_appearance_state": "QUARANTINED_FOREIGN_STATE",
            "exact_inputs": list(context_inputs),
            "enumerates": [
                "graph_artifacts",
                "graph_globs",
                "primary_artifacts",
                "project_sibling_directories",
                "methodology_registry",
                "methodology_reachability",
            ],
            "graph_artifacts": list(graph_artifacts),
            "graph_globs": list(graph_globs),
            "primary_artifacts": list(primary_artifacts),
            "project_sibling_directories": list(sibling_directories),
            "methodology_registry": methodology_registry,
            "methodology_reachability": methodology_reachability,
            "enumerate_every_primary_artifact": True,
            "enumerate_every_project_sibling": True,
        },
        "shard_planner": {
            "pure": True,
            "may_invoke_compound_delivery": False,
        },
        "coverage_invariant": coverage_invariant,
    })
    children.append(t7)

    through_t7 = tuple(
        str(row["path"])
        for unit in children
        for row in unit["outputs"]
    )
    t8 = _live_unit(
        _LIVE_CHILD_IDS[8],
        through_t7,
        _LIVE_T8_OUTPUTS,
    )
    t8["exact_inputs"] = [
        path for path in t8["exact_inputs"]
        if path not in conditional_private
    ]
    t8.update({
        "validates_conditional_groups": ["compound_delivery"],
        "conditional_input_groups": {
            "compound_delivery": {
                "selection": "EXACTLY_ONE",
                "candidates": [
                    _LIVE_T5_OUTPUTS[4],
                    _LIVE_T5_OUTPUTS[5],
                ],
                "disposition": _LIVE_T5_OUTPUTS[3],
                "status": _LIVE_STATUS_PATHS[5],
                "authority_work_unit_id": _LIVE_CHILD_IDS[5],
                "effective_input_policy": (
                    "COMMITTED_PHASEIO_CONDITIONAL_STATE"
                ),
                "bind_selected_output_sha256_size": True,
                "bind_unselected_absence_record": True,
                "status_json_alone_is_authority": False,
            },
        },
        "semantic_replay": True,
        "bundle": {
            "immutable": True,
            "content_addressed": True,
            "public_output_denominator": sorted(public_outputs),
        },
    })
    children.append(t8)

    publication_order = [
        *sorted(public_outputs - {_LIVE_FINAL_RECEIPT}),
        _LIVE_FINAL_RECEIPT,
    ]
    t9_outputs = (*sorted(public_outputs), _LIVE_STATUS_PATHS[9])
    t9 = _live_unit(
        _LIVE_CHILD_IDS[9],
        _LIVE_T8_OUTPUTS,
        t9_outputs,
        conditional_outputs=conditional_public,
    )
    t9.update({
        "semantic_executor_invoked": False,
        "publication": {
            "mode": "RECEIPT_LAST_CAS",
            "source_bundle": _LIVE_T8_OUTPUTS[1],
            "validation_receipt": _LIVE_T8_OUTPUTS[2],
            "output_prestate_cas": True,
            "re_read_every_destination": True,
            "phase_io_commit_before_parent": True,
            "order": publication_order,
        },
    })
    children.append(t9)

    owner_by_path: dict[str, str] = {}
    for unit in children:
        for row in unit["outputs"]:
            path = str(row["path"])
            previous = owner_by_path.setdefault(path, str(unit["work_unit_id"]))
            if previous != unit["work_unit_id"]:
                raise VerifyQueueTransactionError(
                    f"live output authority is not disjoint: {path}"
                )

    parent = {
        "work_unit_id": _LIVE_PARENT_ID,
        "exact_inputs": [
            _LIVE_FINAL_RECEIPT,
            _LIVE_STATUS_PATHS[9],
            _LIVE_T8_OUTPUTS[2],
        ],
        "outputs": [],
        "model_invoked": False,
        "read_only": True,
        "requires_committed_child": _LIVE_CHILD_IDS[9],
        "requires_execution_state": "OUTPUT_COMMITTED",
        "status_json_is_authority": False,
        "validates_work_units": list(_LIVE_CHILD_IDS),
    }
    outer = sorted(owner_by_path)
    unsigned: dict[str, Any] = {
        "schema_version": _LIVE_PLAN_SCHEMA,
        "pipeline": pipeline_n,
        "mode": mode_n,
        "ecosystem": ecosystem_n,
        "backend": backend_n,
        "phase_name": phase_n,
        "run_id": run_id_n,
        "runtime_authority": runtime,
        "external_input_denominator": sorted({
            *upstream,
            *context_inputs,
        }),
        "upstream_pair_groups": {
            "paired_inventory_projection": [
                logical_input_aliases["findings_inventory.md"],
                logical_input_aliases["finding_records.json"],
            ],
            "paired_chain_projection": [
                logical_input_aliases[logical]
                for logical in ("hypotheses.md", "finding_mapping.md")
                if logical in logical_input_aliases
            ],
        },
        "logical_input_aliases": dict(sorted(logical_input_aliases.items())),
        "preverify_frozen_projection": normalized_frozen_projection,
        "preverify_chain_pair_projection": (
            normalized_chain_pair_projection
        ),
        "shard_manifests": list(manifests),
        "public_output_denominator": sorted(public_outputs),
        "outer_output_denominator": outer,
        "non_authorizing_legacy_journals": sorted(legacy_journals),
        "conditional_closure": {
            "compound_delivery": {
                "receipt": "compound_verification_delivery_receipt.json",
                "debt": "compound_verification_delivery_debt.json",
                "disposition": (
                    "compound_verification_delivery_disposition.json"
                ),
                "selection": "EXACTLY_ONE",
            },
            "legacy_journal_can_authorize": False,
        },
        "children": children,
        "parent": parent,
    }
    return {**unsigned, "plan_digest": _stable_digest(unsigned)}


def _status_path(unit: Mapping[str, Any]) -> str:
    paths = [
        str(row.get("path") or "")
        for row in unit.get("outputs", [])
        if str(row.get("path") or "").endswith("/status.json")
    ]
    if len(paths) != 1:
        raise VerifyQueueTransactionError(
            f"{unit.get('work_unit_id')}: expected one child status output"
        )
    return paths[0]


def _read_inputs(
    root: Path,
    project_root: Path,
    paths: Sequence[str],
) -> tuple[dict[str, bytes], dict[str, str]]:
    frozen: dict[str, bytes] = {}
    for relative in paths:
        relative_n = str(relative).strip().replace("\\", "/")
        if relative_n.startswith("project::"):
            project_relative = _safe_relative(
                relative_n[len("project::"):]
            )
            path = project_root / project_relative
        else:
            relative_n = _safe_relative(relative_n)
            path = root / relative_n
        if not path.is_file():
            raise VerifyQueueTransactionError(
                f"required verify-queue input missing: {relative}"
            )
        frozen[str(relative)] = path.read_bytes()
    return frozen, {
        name: _digest_bytes(raw) for name, raw in sorted(frozen.items())
    }


def _effective_input_paths(
    root: Path,
    unit: Mapping[str, Any],
) -> tuple[str, ...]:
    paths = [str(value) for value in unit["exact_inputs"]]
    state_inputs = unit.get("delivery_state_exact_inputs")
    if not isinstance(state_inputs, Mapping):
        return tuple(paths)
    status_path = root / _STATUS_PATHS[4]
    status = _read_status(status_path)
    state = str(status.get("state") or "")
    selected = state_inputs.get(state)
    if not isinstance(selected, list):
        raise VerifyQueueTransactionError(
            f"{unit.get('work_unit_id')}: compound disposition state "
            "has no exact input denominator"
        )
    return tuple(dict.fromkeys([*paths, *(str(value) for value in selected)]))


def _context_roster_digests(
    root: Path,
    project_root: Path,
    unit: Mapping[str, Any],
) -> dict[str, str]:
    capture = unit.get("dynamic_input_capture")
    if not isinstance(capture, Mapping):
        return {}
    rows: dict[str, list[dict[str, Any]]] = {}
    fixed: list[dict[str, Any]] = []
    for relative in capture.get("graph_artifacts", ()):
        relative_n = _safe_relative(relative)
        path = root / relative_n
        fixed.append({
            "path": relative_n,
            "status": "PRESENT" if path.is_file() else "ABSENT",
            "sha256": (
                _digest_bytes(path.read_bytes()) if path.is_file() else None
            ),
        })
    rows["graph_artifacts"] = fixed
    glob_rows: list[dict[str, Any]] = []
    for pattern in capture.get("graph_globs", ()):
        pattern_n = _safe_glob(pattern)
        pure = PurePosixPath(pattern_n)
        directory = root.joinpath(*pure.parts[:-1])
        leaf = pure.parts[-1]
        matches: list[dict[str, Any]] = []
        if directory.is_dir():
            for path in sorted(
                directory.iterdir(), key=lambda value: value.name
            ):
                if fnmatch.fnmatchcase(path.name, leaf):
                    relative = path.relative_to(root).as_posix()
                    matches.append({
                        "path": relative,
                        "kind": "FILE" if path.is_file() else "NON_FILE",
                        "sha256": (
                            _digest_bytes(path.read_bytes())
                            if path.is_file()
                            else None
                        ),
                    })
        glob_rows.append({"pattern": pattern_n, "matches": matches})
    rows["graph_globs"] = glob_rows
    sibling_rows: list[dict[str, Any]] = []
    for value in capture.get("project_sibling_directories", ()):
        token = str(value).strip().replace("\\", "/")
        if not token.startswith("project::"):
            raise VerifyQueueTransactionError(
                "context sibling directory must use project:: scope"
            )
        relative = _safe_relative(token[len("project::"):])
        directory = project_root / relative
        entries: list[dict[str, Any]] = []
        if directory.is_dir():
            for path in sorted(
                directory.iterdir(), key=lambda item: item.name
            ):
                entries.append({
                    "name": path.name,
                    "kind": "FILE" if path.is_file() else "NON_FILE",
                    "sha256": (
                        _digest_bytes(path.read_bytes())
                        if path.is_file()
                        else None
                    ),
                })
        sibling_rows.append({"directory": token, "entries": entries})
    rows["project_sibling_directories"] = sibling_rows
    return {
        "context-roster:" + label: _stable_digest({"rows": values})
        for label, values in sorted(rows.items())
    }


def _atomic_write(path: Path, raw: bytes) -> None:
    # Public queue destinations are an absence/exact-postimage CAS boundary.
    # They may be partially materialized by a prior receipt-last attempt, but
    # a concurrently appearing foreign byte must never be overwritten.  Child
    # private status files still use replace semantics because their
    # PREPARED->COMMITTED projection is not downstream authority.
    public_name = path.name
    public_cas = bool(
        "_verify_queue_transaction" not in path.parts
        and "_live_verify_queue_transaction" not in path.parts
        and (
            public_name.startswith("verification_queue")
            or public_name.startswith("verification_context")
            or public_name.startswith("verification_methodology")
            or public_name.startswith("verify_queue_context")
            or public_name.startswith("mandatory_reverification")
            or public_name.startswith("compound_")
            or public_name.startswith("l1_composition_queue_")
            or public_name.startswith("p0af_v2_queue_")
            or public_name == "verify_queue_transaction.receipt.json"
        )
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    if public_cas:
        try:
            _rooted_io.durable_write_once_bytes(path, raw)
        except FileExistsError as exc:
            raise VerifyQueueTransactionError(
                f"public CAS destination contains foreign bytes: {path.name}"
            ) from exc
        except _rooted_io.RootedPathIOError as exc:
            raise VerifyQueueTransactionError(
                f"public CAS destination cannot be published safely: "
                f"{path.name}: {exc}",
                durability_debt=getattr(exc, "durability_debt", None),
            ) from exc
        return
    with tempfile.NamedTemporaryFile(
        mode="wb",
        dir=path.parent,
        prefix="." + path.name + ".",
        suffix=".tmp",
        delete=False,
    ) as handle:
        temporary = Path(handle.name)
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _status_payload(
    *,
    unit: Mapping[str, Any],
    run_id: str,
    plan_digest: str,
    state: str,
    input_digests: Mapping[str, str],
    output_digests: Mapping[str, str],
    conditional_states: Mapping[str, str],
) -> dict[str, Any]:
    if state not in VERIFY_QUEUE_TERMINAL_STATES:
        raise VerifyQueueTransactionError(
            f"invalid child transaction state: {state}"
        )
    unsigned: dict[str, Any] = {
        "schema_version": _STATUS_SCHEMA,
        "work_unit_id": str(unit["work_unit_id"]),
        "run_id": run_id,
        "plan_digest": plan_digest,
        "state": state,
        "safe_to_consume": state in {
            "COMMITTED_APPLIED",
            "COMMITTED_CLEAN_NOOP",
            "COMPLETED_WITH_DEBT_SAFE_BASE",
        },
        "proof_authority": "NONE",
        "input_digests": dict(sorted(input_digests.items())),
        "output_digests": dict(sorted(output_digests.items())),
        "conditional_states": dict(sorted(conditional_states.items())),
    }
    return {**unsigned, "status_digest": _stable_digest(unsigned)}


def _read_status(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    if not isinstance(payload, dict):
        raise VerifyQueueTransactionError("child status is not an object")
    digest = payload.get("status_digest")
    unsigned = {
        key: value for key, value in payload.items()
        if key != "status_digest"
    }
    if (
        payload.get("schema_version") != _STATUS_SCHEMA
        or digest != _stable_digest(unsigned)
    ):
        raise VerifyQueueTransactionError(
            "child status schema or digest is invalid"
        )
    return payload


def _write_quarantine_status(
    *,
    root: Path,
    unit: Mapping[str, Any],
    run_id: str,
    plan_digest: str,
    input_digests: Mapping[str, str],
    prior: Mapping[str, Any] | None,
) -> dict[str, Any]:
    status = _status_payload(
        unit=unit,
        run_id=run_id,
        plan_digest=plan_digest,
        state="QUARANTINED_FOREIGN_STATE",
        input_digests=input_digests,
        output_digests=(
            prior.get("output_digests", {})
            if isinstance(prior, Mapping)
            else {}
        ),
        conditional_states=(
            prior.get("conditional_states", {})
            if isinstance(prior, Mapping)
            else {}
        ),
    )
    _atomic_write(root / _status_path(unit), _canonical_json_bytes(status))
    return status


def _current_output_digests(
    root: Path,
    unit: Mapping[str, Any],
) -> dict[str, str]:
    status_name = _status_path(unit)
    result: dict[str, str] = {}
    for row in unit["outputs"]:
        relative = str(row["path"])
        if relative == status_name:
            continue
        path = root / relative
        if path.is_file():
            result[relative] = _digest_bytes(path.read_bytes())
    return result


def _validate_committed_status(
    *,
    root: Path,
    unit: Mapping[str, Any],
    status: Mapping[str, Any],
    run_id: str,
    plan_digest: str,
    input_digests: Mapping[str, str],
) -> bool:
    if (
        status.get("work_unit_id") != unit.get("work_unit_id")
        or status.get("run_id") != run_id
        or status.get("plan_digest") != plan_digest
        or status.get("input_digests") != dict(sorted(input_digests.items()))
    ):
        return False
    expected = status.get("output_digests")
    return (
        isinstance(expected, dict)
        and expected == _current_output_digests(root, unit)
    )


def execute_verify_queue_transaction(
    *,
    scratchpad: Path,
    project_root: Path,
    plan: Mapping[str, Any],
    run_id: str,
    child_executor: Callable[..., Mapping[str, Any]],
    failpoint: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Execute/resume the closed child DAG without adopting foreign bytes."""

    from verify_queue_phaseio_authority import (
        arm_transaction_unit,
        commit_transaction_unit,
        validate_transaction_authority,
    )

    root = Path(scratchpad)
    project = Path(project_root)
    root.mkdir(parents=True, exist_ok=True)
    run = str(run_id or "").strip()
    if not run:
        raise VerifyQueueTransactionError("verify-queue run_id is absent")
    if not callable(child_executor):
        raise VerifyQueueTransactionError("child_executor must be callable")
    plan_digest = str(plan.get("plan_digest") or "")
    unsigned_plan = {
        key: value for key, value in plan.items() if key != "plan_digest"
    }
    if (
        plan.get("schema_version") != _PLAN_SCHEMA
        or not _DIGEST_RE.fullmatch(plan_digest)
        or plan_digest != _stable_digest(unsigned_plan)
    ):
        raise VerifyQueueTransactionError(
            "verify-queue transaction plan is malformed or stale"
        )
    children = plan.get("children")
    if (
        not isinstance(children, list)
        or tuple(str(row.get("work_unit_id") or "") for row in children)
        != _CHILD_IDS
    ):
        raise VerifyQueueTransactionError(
            "verify-queue child roster is not exact"
        )

    states: list[str] = []
    for index, unit in enumerate(children):
        work_id = str(unit["work_unit_id"])
        effective_inputs = _effective_input_paths(root, unit)
        frozen, input_digests = _read_inputs(
            root, project, effective_inputs
        )
        input_digests.update(
            _context_roster_digests(root, project, unit)
        )
        (
            phaseio_execute,
            phaseio_issues,
            phaseio_contract,
            phaseio_launch,
        ) = arm_transaction_unit(
            scratchpad=root,
            project_root=project,
            plan=plan,
            unit=unit,
            run_id=run,
            effective_inputs=effective_inputs,
        )
        if phaseio_issues:
            status_path = root / _status_path(unit)
            if status_path.is_file():
                try:
                    prior = _read_status(status_path)
                except Exception:
                    prior = None
                _write_quarantine_status(
                    root=root,
                    unit=unit,
                    run_id=run,
                    plan_digest=plan_digest,
                    input_digests=input_digests,
                    prior=prior,
                )
                states.append("QUARANTINED_FOREIGN_STATE")
                break
            raise VerifyQueueTransactionError(
                f"{work_id}: PhaseIO prebind failed: "
                + "; ".join(phaseio_issues)
            )
        status_path = root / _status_path(unit)
        prior: dict[str, Any] | None = None
        if status_path.is_file():
            try:
                prior = _read_status(status_path)
            except Exception:
                prior = None
                _write_quarantine_status(
                    root=root,
                    unit=unit,
                    run_id=run,
                    plan_digest=plan_digest,
                    input_digests=input_digests,
                    prior=None,
                )
                states.append("QUARANTINED_FOREIGN_STATE")
                break
            prior_state = str(prior.get("state") or "")
            prepared_header_valid = bool(
                prior_state == "PREPARED_NOT_CONSUMABLE"
                and prior.get("work_unit_id") == unit.get("work_unit_id")
                and prior.get("run_id") == run
                and prior.get("plan_digest") == plan_digest
                and prior.get("input_digests")
                == dict(sorted(input_digests.items()))
            )
            if (
                not prepared_header_valid
                and not _validate_committed_status(
                    root=root,
                    unit=unit,
                    status=prior,
                    run_id=run,
                    plan_digest=plan_digest,
                    input_digests=input_digests,
                )
            ):
                _write_quarantine_status(
                    root=root,
                    unit=unit,
                    run_id=run,
                    plan_digest=plan_digest,
                    input_digests=input_digests,
                    prior=prior,
                )
                states.append("QUARANTINED_FOREIGN_STATE")
                break
            if prior_state in {
                "COMMITTED_APPLIED",
                "COMMITTED_CLEAN_NOOP",
                "COMPLETED_WITH_DEBT_SAFE_BASE",
            }:
                states.append(prior_state)
                continue
            if prior_state == "QUARANTINED_FOREIGN_STATE":
                states.append(prior_state)
                break
            # A byte-exact PREPARED child is re-derived below.  Existing bytes
            # are accepted only if the executor reproduces them exactly.
        else:
            foreign = _current_output_digests(root, unit)
            if foreign:
                _write_quarantine_status(
                    root=root,
                    unit=unit,
                    run_id=run,
                    plan_digest=plan_digest,
                    input_digests=input_digests,
                    prior=None,
                )
                states.append("QUARANTINED_FOREIGN_STATE")
                break

        prepared = _status_payload(
            unit=unit,
            run_id=run,
            plan_digest=plan_digest,
            state="PREPARED_NOT_CONSUMABLE",
            input_digests=input_digests,
            output_digests=(
                prior.get("output_digests", {})
                if isinstance(prior, Mapping)
                else {}
            ),
            conditional_states=(
                prior.get("conditional_states", {})
                if isinstance(prior, Mapping)
                else {}
            ),
        )
        _atomic_write(status_path, _canonical_json_bytes(prepared))
        if failpoint is not None:
            failpoint(f"after_t{index}_arm")

        result = child_executor(unit=unit, frozen_inputs=frozen)
        if not isinstance(result, Mapping):
            raise VerifyQueueTransactionError(
                f"{work_id}: child executor returned no mapping"
            )
        state = str(result.get("state") or "")
        if state not in VERIFY_QUEUE_TERMINAL_STATES or state in {
            "PREPARED_NOT_CONSUMABLE",
            "QUARANTINED_FOREIGN_STATE",
        }:
            raise VerifyQueueTransactionError(
                f"{work_id}: child executor returned invalid terminal state"
            )
        outputs = result.get("outputs")
        if not isinstance(outputs, Mapping):
            raise VerifyQueueTransactionError(
                f"{work_id}: child output bundle is malformed"
            )
        conditional_states = result.get("conditional_states") or {}
        if not isinstance(conditional_states, Mapping):
            raise VerifyQueueTransactionError(
                f"{work_id}: conditional-state bundle is malformed"
            )
        declared = {
            str(row["path"]): row for row in unit["outputs"]
            if str(row["path"]) != _status_path(unit)
        }
        normalized_outputs = {
            _safe_relative(path): bytes(raw)
            for path, raw in outputs.items()
            if isinstance(raw, (bytes, bytearray))
        }
        if len(normalized_outputs) != len(outputs):
            raise VerifyQueueTransactionError(
                f"{work_id}: child output bytes are malformed"
            )
        unknown_outputs = set(normalized_outputs) - set(declared)
        if unknown_outputs:
            raise VerifyQueueTransactionError(
                f"{work_id}: undeclared outputs: "
                + ", ".join(sorted(unknown_outputs))
            )
        required = {
            path for path, row in declared.items()
            if row.get("artifact_class") != "CONDITIONAL"
        }
        if not required.issubset(normalized_outputs):
            raise VerifyQueueTransactionError(
                f"{work_id}: required output denominator is incomplete"
            )
        for path, row in declared.items():
            if row.get("artifact_class") != "CONDITIONAL":
                continue
            disposition = str(
                conditional_states.get(path) or ""
            ).strip().upper()
            if disposition not in {"PRODUCED", "NOT_TRIGGERED"}:
                raise VerifyQueueTransactionError(
                    f"{work_id}: conditional output state is incomplete"
                )
            if (path in normalized_outputs) != (disposition == "PRODUCED"):
                raise VerifyQueueTransactionError(
                    f"{work_id}: conditional output bytes/state mismatch"
                )

        materialized_digests: dict[str, str] = {}
        foreign = False
        ordered_outputs = sorted(
            normalized_outputs.items(),
            key=lambda item: (
                1
                if (
                    work_id == _CHILD_IDS[9]
                    and item[0] == "verify_queue_transaction.receipt.json"
                )
                else 0,
                item[0],
            ),
        )
        for relative, raw in ordered_outputs:
            path = root / relative
            if path.is_file() and path.read_bytes() != raw:
                foreign = True
                break
            if not path.is_file():
                _atomic_write(path, raw)
            materialized_digests[relative] = _digest_bytes(raw)
        if foreign:
            _write_quarantine_status(
                root=root,
                unit=unit,
                run_id=run,
                plan_digest=plan_digest,
                input_digests=input_digests,
                prior=prepared,
            )
            states.append("QUARANTINED_FOREIGN_STATE")
            break
        prepared = _status_payload(
            unit=unit,
            run_id=run,
            plan_digest=plan_digest,
            state="PREPARED_NOT_CONSUMABLE",
            input_digests=input_digests,
            output_digests=materialized_digests,
            conditional_states={
                str(key): str(value)
                for key, value in conditional_states.items()
            },
        )
        _atomic_write(status_path, _canonical_json_bytes(prepared))
        if failpoint is not None:
            failpoint(f"after_t{index}_materialize")
        current_context_roster = _context_roster_digests(
            root, project, unit
        )
        if any(
            input_digests.get(key) != value
            for key, value in current_context_roster.items()
        ):
            _write_quarantine_status(
                root=root,
                unit=unit,
                run_id=run,
                plan_digest=plan_digest,
                input_digests={
                    **input_digests,
                    **current_context_roster,
                },
                prior=prepared,
            )
            states.append("QUARANTINED_FOREIGN_STATE")
            break

        committed = _status_payload(
            unit=unit,
            run_id=run,
            plan_digest=plan_digest,
            state=state,
            input_digests=input_digests,
            output_digests=materialized_digests,
            conditional_states={
                str(key): str(value)
                for key, value in conditional_states.items()
            },
        )
        _atomic_write(status_path, _canonical_json_bytes(committed))
        phaseio_commit_issues = commit_transaction_unit(
            scratchpad=root,
            project_root=project,
            contract=phaseio_contract,
            launch=phaseio_launch,
            run_id=run,
            conditional_states={
                str(key): str(value)
                for key, value in conditional_states.items()
            },
        )
        if phaseio_commit_issues:
            raise VerifyQueueTransactionError(
                f"{work_id}: PhaseIO commit failed: "
                + "; ".join(phaseio_commit_issues)
            )
        states.append(state)
        if failpoint is not None:
            failpoint(f"after_t{index}_commit")

    overall = classify_verify_queue_transaction_state(states)
    complete = len(states) == len(_CHILD_IDS) and overall not in {
        "PREPARED_NOT_CONSUMABLE",
        "QUARANTINED_FOREIGN_STATE",
    }
    parent_commit = {
        "work_unit_id": _PARENT_ID,
        "state": "NOT_COMMITTED",
        "outputs": [],
        "read_only": True,
    }
    if complete and failpoint is not None:
        failpoint("before_parent_commit")
    if complete:
        parent = plan.get("parent")
        if not isinstance(parent, Mapping):
            raise VerifyQueueTransactionError(
                "verify-queue parent authority is absent"
            )
        (
            parent_execute,
            parent_issues,
            parent_contract,
            parent_launch,
        ) = arm_transaction_unit(
            scratchpad=root,
            project_root=project,
            plan=plan,
            unit=parent,
            run_id=run,
            effective_inputs=tuple(
                str(value) for value in parent.get("exact_inputs", ())
            ),
        )
        if parent_issues:
            raise VerifyQueueTransactionError(
                "verify-queue parent PhaseIO prebind failed: "
                + "; ".join(parent_issues)
            )
        if parent_execute:
            parent_commit_issues = commit_transaction_unit(
                scratchpad=root,
                project_root=project,
                contract=parent_contract,
                launch=parent_launch,
                run_id=run,
                conditional_states={},
            )
            if parent_commit_issues:
                raise VerifyQueueTransactionError(
                    "verify-queue parent PhaseIO commit failed: "
                    + "; ".join(parent_commit_issues)
                )
        authority_issues = validate_transaction_authority(
            scratchpad=root,
            project_root=project,
            plan=plan,
            run_id=run,
            require_parent_commit=True,
        )
        if authority_issues:
            raise VerifyQueueTransactionError(
                "verify-queue transaction authority invalid: "
                + "; ".join(authority_issues)
            )
        parent_commit["state"] = "OUTPUT_COMMITTED"
    return {
        "schema_version": _RECEIPT_SCHEMA,
        "pipeline": plan["pipeline"],
        "phase_name": plan["phase_name"],
        "ecosystem": plan["ecosystem"],
        "backend": plan["backend"],
        "run_id": run,
        "plan_digest": plan_digest,
        "state": overall,
        "child_states": list(states),
        "parent_commit": parent_commit,
    }


def execute_live_verify_queue_transaction(
    *,
    scratchpad: Path,
    project_root: Path,
    plan: Mapping[str, Any],
    run_id: str,
    semantic_executor: Callable[..., Mapping[str, Any]] | None = None,
    failpoint: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Execute the production-semantic private DAG and T9 publication.

    The live implementation is intentionally separate from the first
    topology scaffold above.  When no executor is supplied the production
    semantic adapter is resolved lazily, keeping plan inspection side-effect
    free and avoiding driver import cycles.
    """

    from live_verify_queue_executor import execute_live_transaction

    selected = semantic_executor
    if selected is None:
        from live_verify_queue_semantics import (
            build_live_verify_queue_semantic_executor,
        )

        selected = build_live_verify_queue_semantic_executor(plan)
    return execute_live_transaction(
        scratchpad=Path(scratchpad),
        project_root=Path(project_root),
        plan=plan,
        run_id=run_id,
        semantic_executor=selected,
        failpoint=failpoint,
    )


def validate_live_verify_queue_publication(
    *,
    scratchpad: Path,
    plan: Mapping[str, Any],
    run_id: str,
    project_root: Path | None = None,
) -> dict[str, Any]:
    """Admit live downstream work only through ledger-backed T9 authority."""

    from live_verify_queue_executor import validate_live_publication

    root = Path(scratchpad)
    return validate_live_publication(
        scratchpad=root,
        project_root=Path(project_root) if project_root is not None else root.parent,
        plan=plan,
        run_id=run_id,
    )


def validate_verify_queue_transaction_authority(
    *,
    scratchpad: Path,
    project_root: Path,
    plan: Mapping[str, Any],
    run_id: str,
    require_parent_commit: bool = True,
) -> list[str]:
    """Validate the first/live transaction through PhaseIO, never status prose."""

    from verify_queue_phaseio_authority import validate_transaction_authority

    return validate_transaction_authority(
        scratchpad=Path(scratchpad),
        project_root=Path(project_root),
        plan=plan,
        run_id=run_id,
        require_parent_commit=require_parent_commit,
    )


__all__ = [
    "VERIFY_QUEUE_TERMINAL_STATES",
    "VerifyQueueInjectedFailure",
    "VerifyQueueTransactionError",
    "classify_verify_queue_transaction_state",
    "execute_live_verify_queue_transaction",
    "execute_verify_queue_transaction",
    "live_verify_queue_base_upstream_roster",
    "live_verify_queue_required_upstream_roster",
    "resolve_live_verify_queue_transaction_plan",
    "resolve_verify_queue_transaction_plan",
    "validate_live_verify_queue_publication",
    "validate_verify_queue_transaction_authority",
]
