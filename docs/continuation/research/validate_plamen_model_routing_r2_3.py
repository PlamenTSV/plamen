#!/usr/bin/env python3
"""Offline conformance validator for Plamen model-routing R2.3 artifacts."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import unicodedata
from pathlib import Path

import jsonschema


HERE = Path(__file__).resolve().parent
SCHEMA_PATH = HERE / "Plamen_Backend_Model_Routing_R2.3_Schemas_2026-07-29.json"
VECTOR_PATH = HERE / "Plamen_Backend_Model_Routing_R2.3_Conformance_Vectors_2026-07-29.json"
MAX_SAFE = 9_007_199_254_740_991
VECTOR_FIELDS = (
    "source_payload_bytes",
    "output_artifact_bytes",
    "turns",
    "retries",
    "wall_time_ms",
    "tool_calls",
    "driver_owned_work_units",
    "currency_micros",
)
SOURCE_ORDER = {
    name: i
    for i, name in enumerate(
        (
            "ENVIRONMENT",
            "CLI_ARGUMENT",
            "SKILL_FRONTMATTER",
            "ROLE_FRONTMATTER",
            "SUBAGENT_FRONTMATTER",
            "SETTINGS_USER",
            "SETTINGS_PROJECT",
            "SETTINGS_LOCAL",
            "CONTROL_REQUEST",
            "SESSION_DEFAULT",
        )
    )
}
THINKING_SOURCES = tuple(SOURCE_ORDER)
THINKING_CONTROLS = (
    "ADAPTIVE_THINKING",
    "MAX_THINKING_TOKENS",
    "ALWAYS_THINKING",
    "MANUAL_THINKING_BUDGET",
)
SELF_DIGEST_FIELDS = {
    "CustomizationDiscoveryAuthorityV1": "discovery_authority_digest",
    "LoadedCustomizationSetV1": "customization_set_digest",
    "ClaudeEffortAuthorityV3": "effort_authority_digest",
    "ClaudeProviderControlVectorV1": "provider_control_vector_digest",
    "ClaudeThinkingAuthorityV1": "thinking_authority_digest",
    "TokenBudgetDerivationV2": "token_derivation_digest",
    "BudgetAuthorityV3": "budget_authority_digest",
    "GenerationResourceEntryV2": "generation_entry_digest",
    "AttemptResourceEntryV2": "attempt_entry_digest",
    "BackendSemanticResourceLedgerV2": "resource_ledger_digest",
    "ResourceLedgerEventV2": "ledger_event_digest",
    "LaunchAuthorityV2": "launch_authority_digest",
    "AttemptLaunchEnvelopeV2": "attempt_launch_digest",
    "ProviderExecutionObservationV4": "observation_digest",
    "ObservedPairResourceComparisonV1": "comparison_digest",
    "ReservedPairResourceComparisonV1": "comparison_digest",
    "ObservedToGrantUtilizationV1": "utilization_digest",
    "CanaryPlanAuthorityV1": "canary_plan_digest",
    "CanaryProofRuleAuthorityV1": "proof_rule_authority_digest",
    "CanaryCaseResultV1": "case_result_digest",
    "CanaryEvidenceManifestV1": "evidence_manifest_digest",
    "CanaryFieldClaimV2": "canary_claim_digest",
    "ProviderCapabilityCanaryReceiptV3": "canary_receipt_digest",
    "RouteDebtV3": "route_debt_digest",
}


class ConformanceError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def reject_duplicate_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ConformanceError("DUPLICATE_OBJECT_MEMBER")
        out[key] = value
    return out


def parse_profile_int(text):
    if text == "-0":
        raise ConformanceError("NEGATIVE_ZERO_FORBIDDEN")
    value = int(text)
    if value < 0 or value > MAX_SAFE:
        raise ConformanceError("INTEGER_OUT_OF_RANGE")
    return value


def reject_float(_text):
    raise ConformanceError("FLOAT_FORBIDDEN")


def reject_constant(_text):
    raise ConformanceError("NON_FINITE_NUMBER_FORBIDDEN")


def parse_json_text(text):
    return json.loads(
        text,
        object_pairs_hook=reject_duplicate_pairs,
        parse_int=parse_profile_int,
        parse_float=reject_float,
        parse_constant=reject_constant,
    )


def load_ascii(path: Path):
    raw = path.read_bytes()
    if any(byte > 127 for byte in raw):
        raise ConformanceError("ARTIFACT_NOT_ASCII")
    if b"\r" in raw:
        raise ConformanceError("ARTIFACT_NOT_LF_ONLY")
    return parse_json_text(raw.decode("ascii"))


def zero_vector():
    return {field: 0 for field in VECTOR_FIELDS}


def make_thinking_controls(spec):
    rows = []
    for source_ordinal, source in enumerate(THINKING_SOURCES):
        for control in THINKING_CONTROLS:
            rows.append(
                {
                    "ordinal": len(rows),
                    "customization_row_ordinal": source_ordinal,
                    "source_kind": source,
                    "source_id": source.lower(),
                    "customization_row_digest": format(source_ordinal, "x") * 64,
                    "control_name": control,
                    "serialized_value": None,
                    "state": "PROVEN_ABSENT",
                }
            )
    mode = spec["mode"]
    target_name = (
        "ADAPTIVE_THINKING"
        if mode == "ADAPTIVE_ON"
        else "MANUAL_THINKING_BUDGET"
    )
    target_value = True if mode == "ADAPTIVE_ON" else spec.get("manual_budget", 64)
    for row in rows:
        if (
            row["source_kind"] == "CONTROL_REQUEST"
            and row["control_name"] == target_name
        ):
            row["serialized_value"] = target_value
            row["state"] = "EXPLICIT"
    if spec.get("manual_conflict"):
        for row in rows:
            if (
                row["source_kind"] == "ENVIRONMENT"
                and row["control_name"] == "MANUAL_THINKING_BUDGET"
            ):
                row["serialized_value"] = 1
                row["state"] = "EXPLICIT"
    omitted = spec.get("omit_source")
    if omitted is not None:
        rows = [row for row in rows if row["source_kind"] != omitted]
        for ordinal, row in enumerate(rows):
            row["ordinal"] = ordinal
    return rows


def make_customization_record(spec):
    rows = [
        {
            "row_digest": "",
            "ordinal": 0,
            "precedence_rank": SOURCE_ORDER["ENVIRONMENT"],
            "source_kind": "ENVIRONMENT",
            "source_id": "env",
            "canonical_realpath_digest": None,
            "content_digest": "1" * 64,
            "loaded": True,
            "declared_effort": "high",
            "thinking_controls_digest": None,
            "scan_result": "PRESENT_EQUAL",
        },
        {
            "row_digest": "",
            "ordinal": 1,
            "precedence_rank": SOURCE_ORDER["SKILL_FRONTMATTER"],
            "source_kind": "SKILL_FRONTMATTER",
            "source_id": "skill-a",
            "canonical_realpath_digest": "2" * 64,
            "content_digest": "3" * 64,
            "loaded": True,
            "declared_effort": "high",
            "thinking_controls_digest": "4" * 64,
            "scan_result": "PRESENT_EQUAL",
        },
    ]
    mode = spec["mode"]
    if mode == "duplicate_source":
        rows[1]["source_id"] = "env"
    elif mode == "path_alias":
        rows.append(
            {
                "row_digest": "",
                "ordinal": 2,
                "precedence_rank": SOURCE_ORDER["ROLE_FRONTMATTER"],
                "source_kind": "ROLE_FRONTMATTER",
                "source_id": "role-a",
                "canonical_realpath_digest": rows[1][
                    "canonical_realpath_digest"
                ],
                "content_digest": "5" * 64,
                "loaded": True,
                "declared_effort": "high",
                "thinking_controls_digest": None,
                "scan_result": "PRESENT_EQUAL",
            }
        )
    elif mode in {"shadowed_valid", "shadowed_loaded_invalid"}:
        rows[1]["scan_result"] = "PRESENT_SHADOWED"
        rows[1]["loaded"] = mode == "shadowed_loaded_invalid"
    for row in rows:
        row["row_digest"] = digest_record(row, "row_digest")
    record = {
        "schema": "plamen.loaded-customization-set.v1",
        "customization_set_version": 1,
        "customization_set_digest": "",
        "resolution_root_digest": "6" * 64,
        "customization_registry_digest": expected_customization_registry_digest(),
        "discovery_authority_digest": "",
        "discovery_manifest_digest": "",
        "expected_row_count": len(rows),
        "rows": rows,
    }
    record["discovery_authority_digest"] = make_discovery_authority(
        record
    )["discovery_authority_digest"]
    record["discovery_manifest_digest"] = customization_discovery_digest(
        record
    )
    record["customization_set_digest"] = digest_record(
        record, "customization_set_digest"
    )
    if mode == "post_scan_mutation":
        record["rows"][0]["content_digest"] = "9" * 64
    return record


def make_attempt_join(spec):
    records = {
        "envelope_attempt": "attempt-a",
        "event_attempt": "attempt-a",
        "entry_attempt": "attempt-a",
        "observation_attempt": "attempt-a",
        "reconciliation_event_attempt": "attempt-a",
        "reconciled_entry_attempt": "attempt-a",
        "envelope_generation": 1,
        "event_generation": 1,
        "entry_generation": 1,
        "observation_generation": 1,
        "reconciliation_event_generation": 1,
        "reconciled_entry_generation": 1,
        "envelope_arm": "a" * 64,
        "event_arm": "a" * 64,
        "entry_arm": "a" * 64,
        "observation_arm": "a" * 64,
        "reconciliation_event_arm": "a" * 64,
        "reconciled_entry_arm": "a" * 64,
        "envelope_reservation_event_digest": "b" * 64,
        "event_digest": "b" * 64,
        "observation_reservation_event_digest": "b" * 64,
        "envelope_entry_digest": "c" * 64,
        "entry_digest": "c" * 64,
        "observation_reserved_entry_digest": "c" * 64,
        "observation_consumed_entry_digest": "4" * 64,
        "launch_consumed_entry_digest": "4" * 64,
        "reconciled_entry_previous_digest": "4" * 64,
        "reconciled_entry_digest": "5" * 64,
        "reconciliation_event_entry_digest": "5" * 64,
        "launch_budget_digest": "d" * 64,
        "event_budget_digest": "d" * 64,
        "entry_budget_digest": "d" * 64,
        "observation_budget_digest": "d" * 64,
        "reconciliation_event_budget_digest": "d" * 64,
        "reconciled_entry_budget_digest": "d" * 64,
        "launch_derivation_digest": "e" * 64,
        "event_derivation_digest": "e" * 64,
        "entry_derivation_digest": "e" * 64,
        "observation_derivation_digest": "e" * 64,
        "reconciliation_event_derivation_digest": "e" * 64,
        "reconciled_entry_derivation_digest": "e" * 64,
        "event_allocation": {**zero_vector(), "turns": 5},
        "entry_allocation": {**zero_vector(), "turns": 5},
        "reconciled_entry_allocation": {**zero_vector(), "turns": 5},
        "reconciliation_event_use": {**zero_vector(), "turns": 4},
        "reconciled_entry_use": {**zero_vector(), "turns": 4},
        "event_post_reservation_ledger": "f" * 64,
        "envelope_post_reservation_ledger": "f" * 64,
        "observation_post_reservation_ledger": "f" * 64,
        "envelope_digest": "1" * 64,
        "consumption_launch_digest": "1" * 64,
        "observation_envelope_digest": "1" * 64,
        "consumption_event_digest": "2" * 64,
        "observation_consumption_event_digest": "2" * 64,
        "post_consumption_ledger": "3" * 64,
        "observation_post_consumption_ledger": "3" * 64,
        "reconciliation_event_launch_digest": "1" * 64,
        "reconciled_entry_launch_digest": "1" * 64,
    }
    mode = spec["mode"]
    mutations = {
        "other_attempt": ("event_attempt", "attempt-b"),
        "stale_generation": ("envelope_generation", 2),
        "wrong_reservation_event": (
            "envelope_reservation_event_digest",
            "4" * 64,
        ),
        "wrong_entry": (
            "observation_reserved_entry_digest",
            "6" * 64,
        ),
        "wrong_consumed_entry": (
            "observation_consumed_entry_digest",
            "6" * 64,
        ),
        "wrong_reservation_ledger": (
            "observation_post_reservation_ledger",
            "4" * 64,
        ),
        "wrong_allocation": (
            "entry_allocation",
            {**zero_vector(), "turns": 4},
        ),
        "wrong_envelope": ("consumption_launch_digest", "4" * 64),
        "wrong_consumption_event": (
            "observation_consumption_event_digest",
            "4" * 64,
        ),
        "wrong_post_consumption_ledger": (
            "observation_post_consumption_ledger",
            "4" * 64,
        ),
        "unrelated_reconciliation_entry": (
            "reconciliation_event_entry_digest",
            "6" * 64,
        ),
        "reconciliation_allocation_mismatch": (
            "reconciled_entry_allocation",
            {**zero_vector(), "turns": 4},
        ),
        "reconciliation_use_mismatch": (
            "reconciled_entry_use",
            {**zero_vector(), "turns": 3},
        ),
        "reconciliation_use_over_allocation": (
            "reconciliation_event_use",
            {**zero_vector(), "turns": 6},
        ),
    }
    if mode != "valid":
        key, value = mutations[mode]
        records[key] = value
        if mode == "reconciliation_use_over_allocation":
            records["reconciled_entry_use"] = copy.deepcopy(value)
    return records


def make_attempt_entry_lifecycle(spec):
    arm = "a" * 64
    attempt = "b" * 64
    budget = "c" * 64
    derivation = "d" * 64
    allocation = {**zero_vector(), "turns": 5}
    use = {**zero_vector(), "turns": 4}
    generation_reserved_entry = {
        "schema": "plamen.generation-resource-entry.v2",
        "generation_entry_version": 2,
        "generation_entry_digest": "",
        "arm_family_digest": arm,
        "generation": 1,
        "budget_authority_digest": budget,
        "previous_generation_entry_digest": None,
        "generation_reservation": {**zero_vector(), "turns": 10},
        "unallocated_reservation": {**zero_vector(), "turns": 10},
        "reconciled_use": zero_vector(),
        "entry_state": "RESERVED",
    }
    generation_reserved_entry["generation_entry_digest"] = digest_record(
        generation_reserved_entry, "generation_entry_digest"
    )
    generation_active_entry = copy.deepcopy(generation_reserved_entry)
    generation_active_entry.update(
        {
            "generation_entry_digest": "",
            "previous_generation_entry_digest": generation_reserved_entry[
                "generation_entry_digest"
            ],
            "unallocated_reservation": {
                **zero_vector(),
                "turns": 5,
            },
            "entry_state": "ACTIVE",
        }
    )
    generation_active_entry["generation_entry_digest"] = digest_record(
        generation_active_entry, "generation_entry_digest"
    )
    reserved_entry = {
        "schema": "plamen.attempt-resource-entry.v2",
        "attempt_entry_version": 2,
        "attempt_entry_digest": "",
        "arm_family_digest": arm,
        "generation": 1,
        "attempt_identity_digest": attempt,
        "generation_entry_digest": generation_active_entry[
            "generation_entry_digest"
        ],
        "budget_authority_digest": budget,
        "token_budget_derivation_digest": derivation,
        "previous_attempt_entry_digest": None,
        "attempt_launch_digest": None,
        "attempt_allocation": copy.deepcopy(allocation),
        "reconciled_use": zero_vector(),
        "entry_state": "RESERVED",
    }
    reserved_entry["attempt_entry_digest"] = digest_record(
        reserved_entry, "attempt_entry_digest"
    )
    reserve_event = {
        "schema": "plamen.resource-ledger-event.v2",
        "ledger_event_version": 2,
        "ledger_event_digest": "",
        "arm_family_digest": arm,
        "event_sequence": 1,
        "previous_event_digest": "e" * 64,
        "expected_ledger_revision": 1,
        "idempotency_key": "1" * 64,
        "event_kind": "RESERVE_ATTEMPT",
        "generation": 1,
        "attempt_identity_digest": attempt,
        "budget_authority_digest": budget,
        "reservation_delta": copy.deepcopy(allocation),
        "reconciliation_delta": zero_vector(),
        "release_delta": zero_vector(),
        "token_budget_derivation_digest": derivation,
        "attempt_resource_entry_digest": reserved_entry[
            "attempt_entry_digest"
        ],
        "attempt_launch_digest": None,
        "event_utc": "2026-07-29T00:00:00Z",
    }
    reserve_event["ledger_event_digest"] = digest_record(
        reserve_event, "ledger_event_digest"
    )
    post_reservation_ledger = {
        "schema": "plamen.backend-semantic-resource-ledger.v2",
        "resource_ledger_version": 2,
        "resource_ledger_id": "ledger:attempt-lifecycle",
        "resource_ledger_digest": "",
        "arm_family_digest": arm,
        "semantic_plan_digest": "0" * 64,
        "common_resource_grant_digest": "1" * 64,
        "currency_code": None,
        "ledger_revision": 2,
        "previous_ledger_digest": "2" * 64,
        "ledger_state": "ACTIVE",
        "grant": {**zero_vector(), "turns": 10},
        "active_reserved": {**zero_vector(), "turns": 10},
        "reconciled": zero_vector(),
        "remaining": zero_vector(),
        "generation_entry_digests": [
            generation_active_entry["generation_entry_digest"]
        ],
        "attempt_entry_digests": [
            reserved_entry["attempt_entry_digest"]
        ],
        "event_digests": semantic_set(
            [
                reserve_event["previous_event_digest"],
                reserve_event["ledger_event_digest"],
            ]
        ),
        "last_event_sequence": reserve_event["event_sequence"],
        "last_event_digest": reserve_event["ledger_event_digest"],
    }
    post_reservation_ledger["resource_ledger_digest"] = digest_record(
        post_reservation_ledger, "resource_ledger_digest"
    )
    envelope = {
        "schema": "plamen.attempt-launch-envelope.v2",
        "attempt_launch_version": 2,
        "attempt_launch_digest": "",
        "attempt_identity_digest": attempt,
        "backend_arm_digest": arm,
        "launch_authority_digest": "2" * 64,
        "attempt_reservation_event_digest": reserve_event[
            "ledger_event_digest"
        ],
        "attempt_resource_entry_digest": reserved_entry[
            "attempt_entry_digest"
        ],
        "resource_ledger_digest_after_attempt_reservation": (
            post_reservation_ledger["resource_ledger_digest"]
        ),
        "materialized_argv_digest": "4" * 64,
        "materialized_environment_digest": "5" * 64,
        "materialized_stdin_prompt_digest": "6" * 64,
        "working_directory_identity_digest": "7" * 64,
        "prepared_utc": "2026-07-29T00:00:00Z",
    }
    envelope["attempt_launch_digest"] = digest_record(
        envelope, "attempt_launch_digest"
    )
    consumed_entry = copy.deepcopy(reserved_entry)
    consumed_entry["previous_attempt_entry_digest"] = reserved_entry[
        "attempt_entry_digest"
    ]
    consumed_entry["attempt_launch_digest"] = envelope[
        "attempt_launch_digest"
    ]
    consumed_entry["entry_state"] = "LAUNCH_CONSUMED"
    consumed_entry["attempt_entry_digest"] = digest_record(
        consumed_entry, "attempt_entry_digest"
    )
    consume_event = copy.deepcopy(reserve_event)
    consume_event.update(
        {
            "ledger_event_digest": "",
            "event_sequence": 2,
            "previous_event_digest": reserve_event["ledger_event_digest"],
            "expected_ledger_revision": 2,
            "idempotency_key": "8" * 64,
            "event_kind": "CONSUME_ATTEMPT_LAUNCH",
            "reservation_delta": zero_vector(),
            "attempt_resource_entry_digest": consumed_entry[
                "attempt_entry_digest"
            ],
            "attempt_launch_digest": envelope["attempt_launch_digest"],
        }
    )
    consume_event["ledger_event_digest"] = digest_record(
        consume_event, "ledger_event_digest"
    )
    post_consumption_ledger = copy.deepcopy(post_reservation_ledger)
    post_consumption_ledger.update(
        {
            "resource_ledger_digest": "",
            "ledger_revision": 3,
            "previous_ledger_digest": post_reservation_ledger[
                "resource_ledger_digest"
            ],
            "attempt_entry_digests": [
                consumed_entry["attempt_entry_digest"]
            ],
            "event_digests": semantic_set(
                [
                    reserve_event["previous_event_digest"],
                    reserve_event["ledger_event_digest"],
                    consume_event["ledger_event_digest"],
                ]
            ),
            "last_event_sequence": consume_event["event_sequence"],
            "last_event_digest": consume_event["ledger_event_digest"],
        }
    )
    post_consumption_ledger["resource_ledger_digest"] = digest_record(
        post_consumption_ledger, "resource_ledger_digest"
    )
    observation = make_observation({"mode": "confirmed"})
    observation.update(
        {
            "observation_digest": "",
            "attempt_identity_digest": attempt,
            "backend_arm_digest": arm,
            "attempt_launch_digest": envelope["attempt_launch_digest"],
            "attempt_reservation_event_digest": reserve_event[
                "ledger_event_digest"
            ],
            "reserved_attempt_resource_entry_digest": reserved_entry[
                "attempt_entry_digest"
            ],
            "consumed_attempt_resource_entry_digest": consumed_entry[
                "attempt_entry_digest"
            ],
            "resource_ledger_digest_after_attempt_reservation": (
                post_reservation_ledger["resource_ledger_digest"]
            ),
            "launch_consumption_event_digest": consume_event[
                "ledger_event_digest"
            ],
            "resource_ledger_digest_after_launch_consumption": (
                post_consumption_ledger["resource_ledger_digest"]
            ),
        }
    )
    observation["observation_digest"] = digest_record(
        observation, "observation_digest"
    )
    generation_reconciled_entry = copy.deepcopy(generation_active_entry)
    generation_reconciled_entry.update(
        {
            "generation_entry_digest": "",
            "previous_generation_entry_digest": generation_active_entry[
                "generation_entry_digest"
            ],
            "unallocated_reservation": {
                **zero_vector(),
                "turns": 6,
            },
            "reconciled_use": copy.deepcopy(use),
            "entry_state": "ACTIVE",
        }
    )
    generation_reconciled_entry["generation_entry_digest"] = digest_record(
        generation_reconciled_entry, "generation_entry_digest"
    )
    reconciled_entry = copy.deepcopy(consumed_entry)
    reconciled_entry["generation_entry_digest"] = generation_reconciled_entry[
        "generation_entry_digest"
    ]
    reconciled_entry["previous_attempt_entry_digest"] = consumed_entry[
        "attempt_entry_digest"
    ]
    reconciled_entry["reconciled_use"] = copy.deepcopy(use)
    reconciled_entry["entry_state"] = "RECONCILED"
    reconciled_entry["attempt_entry_digest"] = digest_record(
        reconciled_entry, "attempt_entry_digest"
    )
    reconcile_event = copy.deepcopy(consume_event)
    reconcile_event.update(
        {
            "ledger_event_digest": "",
            "event_sequence": 3,
            "previous_event_digest": consume_event["ledger_event_digest"],
            "expected_ledger_revision": 3,
            "idempotency_key": "9" * 64,
            "event_kind": "RECONCILE_ATTEMPT",
            "reconciliation_delta": copy.deepcopy(use),
            "attempt_resource_entry_digest": reconciled_entry[
                "attempt_entry_digest"
            ],
        }
    )
    reconcile_event["ledger_event_digest"] = digest_record(
        reconcile_event, "ledger_event_digest"
    )
    post_reconciliation_ledger = copy.deepcopy(post_consumption_ledger)
    post_reconciliation_ledger.update(
        {
            "resource_ledger_digest": "",
            "ledger_revision": 4,
            "previous_ledger_digest": post_consumption_ledger[
                "resource_ledger_digest"
            ],
            "active_reserved": {
                **zero_vector(),
                "turns": 6,
            },
            "reconciled": copy.deepcopy(use),
            "remaining": zero_vector(),
            "generation_entry_digests": [
                generation_reconciled_entry["generation_entry_digest"]
            ],
            "attempt_entry_digests": [
                reconciled_entry["attempt_entry_digest"]
            ],
            "event_digests": semantic_set(
                [
                    reserve_event["previous_event_digest"],
                    reserve_event["ledger_event_digest"],
                    consume_event["ledger_event_digest"],
                    reconcile_event["ledger_event_digest"],
                ]
            ),
            "last_event_sequence": reconcile_event["event_sequence"],
            "last_event_digest": reconcile_event["ledger_event_digest"],
        }
    )
    post_reconciliation_ledger["resource_ledger_digest"] = digest_record(
        post_reconciliation_ledger, "resource_ledger_digest"
    )

    def refresh_post_consumption_snapshot():
        post_consumption_ledger.update(
            {
                "resource_ledger_digest": "",
                "previous_ledger_digest": post_reservation_ledger[
                    "resource_ledger_digest"
                ],
                "attempt_entry_digests": [
                    consumed_entry["attempt_entry_digest"]
                ],
                "event_digests": semantic_set(
                    [
                        reserve_event["previous_event_digest"],
                        reserve_event["ledger_event_digest"],
                        consume_event["ledger_event_digest"],
                    ]
                ),
                "last_event_sequence": consume_event["event_sequence"],
                "last_event_digest": consume_event["ledger_event_digest"],
            }
        )
        post_consumption_ledger["resource_ledger_digest"] = digest_record(
            post_consumption_ledger, "resource_ledger_digest"
        )

    def refresh_post_reconciliation_snapshot():
        post_reconciliation_ledger.update(
            {
                "resource_ledger_digest": "",
                "previous_ledger_digest": post_consumption_ledger[
                    "resource_ledger_digest"
                ],
                "generation_entry_digests": [
                    generation_reconciled_entry[
                        "generation_entry_digest"
                    ]
                ],
                "attempt_entry_digests": [
                    reconciled_entry["attempt_entry_digest"]
                ],
                "event_digests": semantic_set(
                    [
                        reserve_event["previous_event_digest"],
                        reserve_event["ledger_event_digest"],
                        consume_event["ledger_event_digest"],
                        reconcile_event["ledger_event_digest"],
                    ]
                ),
                "last_event_sequence": reconcile_event["event_sequence"],
                "last_event_digest": reconcile_event[
                    "ledger_event_digest"
                ],
            }
        )
        post_reconciliation_ledger["resource_ledger_digest"] = digest_record(
            post_reconciliation_ledger, "resource_ledger_digest"
        )

    mode = spec["mode"]
    if mode == "reserved_post_digest_mutation":
        reserved_entry["attempt_allocation"]["turns"] = 4
    elif mode == "generation_post_digest_mutation":
        generation_active_entry["unallocated_reservation"]["turns"] = 4
    elif mode == "invalid_predecessor":
        reconciled_entry["previous_attempt_entry_digest"] = reserved_entry[
            "attempt_entry_digest"
        ]
        reconciled_entry["attempt_entry_digest"] = digest_record(
            reconciled_entry, "attempt_entry_digest"
        )
        reconcile_event["attempt_resource_entry_digest"] = (
            reconciled_entry["attempt_entry_digest"]
        )
        reconcile_event["ledger_event_digest"] = digest_record(
            reconcile_event, "ledger_event_digest"
        )
    elif mode == "allocation_changed":
        reconciled_entry["attempt_allocation"]["turns"] = 4
        reconciled_entry["attempt_entry_digest"] = digest_record(
            reconciled_entry, "attempt_entry_digest"
        )
        reconcile_event["attempt_resource_entry_digest"] = (
            reconciled_entry["attempt_entry_digest"]
        )
        reconcile_event["ledger_event_digest"] = digest_record(
            reconcile_event, "ledger_event_digest"
        )
    elif mode == "use_over_allocation":
        reconciled_entry["reconciled_use"]["turns"] = 6
        reconciled_entry["attempt_entry_digest"] = digest_record(
            reconciled_entry, "attempt_entry_digest"
        )
        reconcile_event["reconciliation_delta"]["turns"] = 6
        reconcile_event["attempt_resource_entry_digest"] = (
            reconciled_entry["attempt_entry_digest"]
        )
        reconcile_event["ledger_event_digest"] = digest_record(
            reconcile_event, "ledger_event_digest"
        )
    elif mode == "unrelated_generation_entry":
        generation_active_entry["arm_family_digest"] = "f" * 64
        generation_active_entry["generation_entry_digest"] = digest_record(
            generation_active_entry, "generation_entry_digest"
        )
    elif mode == "wrong_generation_predecessor":
        generation_reconciled_entry[
            "previous_generation_entry_digest"
        ] = "f" * 64
        generation_reconciled_entry["generation_entry_digest"] = (
            digest_record(
                generation_reconciled_entry,
                "generation_entry_digest",
            )
        )
        reconciled_entry["generation_entry_digest"] = (
            generation_reconciled_entry["generation_entry_digest"]
        )
        reconciled_entry["attempt_entry_digest"] = digest_record(
            reconciled_entry, "attempt_entry_digest"
        )
        reconcile_event["attempt_resource_entry_digest"] = (
            reconciled_entry["attempt_entry_digest"]
        )
        reconcile_event["ledger_event_digest"] = digest_record(
            reconcile_event, "ledger_event_digest"
        )
        refresh_post_reconciliation_snapshot()
    elif mode == "stale_consume_cas":
        consume_event["expected_ledger_revision"] = 99
        consume_event["ledger_event_digest"] = digest_record(
            consume_event, "ledger_event_digest"
        )
        refresh_post_consumption_snapshot()
        observation["launch_consumption_event_digest"] = consume_event[
            "ledger_event_digest"
        ]
        observation[
            "resource_ledger_digest_after_launch_consumption"
        ] = post_consumption_ledger["resource_ledger_digest"]
        observation["observation_digest"] = digest_record(
            observation, "observation_digest"
        )
        reconcile_event["previous_event_digest"] = consume_event[
            "ledger_event_digest"
        ]
        reconcile_event["ledger_event_digest"] = digest_record(
            reconcile_event, "ledger_event_digest"
        )
    elif mode == "other_attempt_envelope":
        envelope["attempt_identity_digest"] = "f" * 64
        envelope["attempt_launch_digest"] = digest_record(
            envelope, "attempt_launch_digest"
        )
        consumed_entry["attempt_launch_digest"] = envelope[
            "attempt_launch_digest"
        ]
        consumed_entry["attempt_entry_digest"] = digest_record(
            consumed_entry, "attempt_entry_digest"
        )
        consume_event["attempt_resource_entry_digest"] = consumed_entry[
            "attempt_entry_digest"
        ]
        consume_event["attempt_launch_digest"] = envelope[
            "attempt_launch_digest"
        ]
        consume_event["ledger_event_digest"] = digest_record(
            consume_event, "ledger_event_digest"
        )
        observation["attempt_launch_digest"] = envelope[
            "attempt_launch_digest"
        ]
        refresh_post_consumption_snapshot()
        observation["consumed_attempt_resource_entry_digest"] = consumed_entry[
            "attempt_entry_digest"
        ]
        observation["launch_consumption_event_digest"] = consume_event[
            "ledger_event_digest"
        ]
        observation[
            "resource_ledger_digest_after_launch_consumption"
        ] = post_consumption_ledger["resource_ledger_digest"]
        observation["observation_digest"] = digest_record(
            observation, "observation_digest"
        )
        reconciled_entry["previous_attempt_entry_digest"] = consumed_entry[
            "attempt_entry_digest"
        ]
        reconciled_entry["attempt_launch_digest"] = envelope[
            "attempt_launch_digest"
        ]
        reconciled_entry["attempt_entry_digest"] = digest_record(
            reconciled_entry, "attempt_entry_digest"
        )
        reconcile_event["previous_event_digest"] = consume_event[
            "ledger_event_digest"
        ]
        reconcile_event["attempt_resource_entry_digest"] = (
            reconciled_entry["attempt_entry_digest"]
        )
        reconcile_event["attempt_launch_digest"] = envelope[
            "attempt_launch_digest"
        ]
        reconcile_event["ledger_event_digest"] = digest_record(
            reconcile_event, "ledger_event_digest"
        )
    elif mode == "unrelated_consumed_observation_entry":
        observation["consumed_attempt_resource_entry_digest"] = "f" * 64
        observation["observation_digest"] = digest_record(
            observation, "observation_digest"
        )
    elif mode == "wrong_observation_reservation_ledger":
        observation[
            "resource_ledger_digest_after_attempt_reservation"
        ] = "f" * 64
        observation["observation_digest"] = digest_record(
            observation, "observation_digest"
        )
    elif mode == "wrong_observation_consumption_ledger":
        observation[
            "resource_ledger_digest_after_launch_consumption"
        ] = "f" * 64
        observation["observation_digest"] = digest_record(
            observation, "observation_digest"
        )
    elif mode == "wrong_post_consumption_family_totals":
        post_consumption_ledger["active_reserved"]["turns"] = 9
        post_consumption_ledger["remaining"]["turns"] = 1
        post_consumption_ledger["resource_ledger_digest"] = digest_record(
            post_consumption_ledger, "resource_ledger_digest"
        )
        observation[
            "resource_ledger_digest_after_launch_consumption"
        ] = post_consumption_ledger["resource_ledger_digest"]
        observation["observation_digest"] = digest_record(
            observation, "observation_digest"
        )
    elif mode != "valid":
        raise ConformanceError("VECTOR_ATTEMPT_LIFECYCLE_MODE_INVALID")
    return {
        "generation_reserved_entry": generation_reserved_entry,
        "generation_active_entry": generation_active_entry,
        "generation_reconciled_entry": generation_reconciled_entry,
        "reserved_entry": reserved_entry,
        "reserve_event": reserve_event,
        "post_reservation_ledger": post_reservation_ledger,
        "envelope": envelope,
        "consumed_entry": consumed_entry,
        "consume_event": consume_event,
        "post_consumption_ledger": post_consumption_ledger,
        "observation": observation,
        "reconciled_entry": reconciled_entry,
        "reconcile_event": reconcile_event,
        "post_reconciliation_ledger": post_reconciliation_ledger,
    }


def make_customization_join(spec):
    record_mode = (
        "post_scan_mutation"
        if spec["mode"] == "post_scan_mutation"
        else "valid"
    )
    record = make_customization_record({"mode": record_mode})
    authority = make_discovery_authority(record)
    if spec["mode"] == "missing_authority_row":
        record["rows"].pop()
        record["expected_row_count"] = len(record["rows"])
        record["discovery_manifest_digest"] = customization_discovery_digest(
            record
        )
        record["customization_set_digest"] = digest_record(
            record, "customization_set_digest"
        )
    elif spec["mode"] == "extra_authority_row":
        row = {
            "row_digest": "",
            "ordinal": len(record["rows"]),
            "precedence_rank": SOURCE_ORDER["SETTINGS_USER"],
            "source_kind": "SETTINGS_USER",
            "source_id": "settings-user-extra",
            "canonical_realpath_digest": "7" * 64,
            "content_digest": "8" * 64,
            "loaded": True,
            "declared_effort": "high",
            "thinking_controls_digest": None,
            "scan_result": "PRESENT_EQUAL",
        }
        row["row_digest"] = digest_record(row, "row_digest")
        record["rows"].append(row)
        record["expected_row_count"] = len(record["rows"])
        record["discovery_manifest_digest"] = customization_discovery_digest(
            record
        )
        record["customization_set_digest"] = digest_record(
            record, "customization_set_digest"
        )
    digest = record["customization_set_digest"]
    out = {
        "discovery_authority": authority,
        "set_record": record,
        "effort_digest": digest,
        "thinking_digest": digest,
        "launch_digest": digest,
        "thinking_customization_row_count": len(record["rows"]),
        "thinking_projection": [
            {
                "ordinal": row["ordinal"],
                "source_kind": row["source_kind"],
                "source_id": row["source_id"],
                "row_digest": row["row_digest"],
            }
            for row in record["rows"]
        ],
    }
    if spec["mode"] == "launch_mismatch":
        out["launch_digest"] = "9" * 64
    elif spec["mode"] == "thinking_projection_mismatch":
        out["thinking_projection"][1]["source_id"] = "other"
    return out


def make_thinking_launch_join(spec):
    plan_digest = "1" * 64
    argv_digest = "8" * 64
    environment_digest = "9" * 64
    loaded = make_customization_record({"mode": "valid"})
    control_request_row = {
        "row_digest": "",
        "ordinal": len(loaded["rows"]),
        "precedence_rank": SOURCE_ORDER["CONTROL_REQUEST"],
        "source_kind": "CONTROL_REQUEST",
        "source_id": "control-request",
        "canonical_realpath_digest": None,
        "content_digest": "5" * 64,
        "loaded": True,
        "declared_effort": "high",
        "thinking_controls_digest": "6" * 64,
        "scan_result": "PRESENT_EQUAL",
    }
    control_request_row["row_digest"] = digest_record(
        control_request_row, "row_digest"
    )
    loaded["rows"].append(control_request_row)
    loaded["expected_row_count"] = len(loaded["rows"])
    discovery_authority = make_discovery_authority(loaded)
    loaded["discovery_authority_digest"] = discovery_authority[
        "discovery_authority_digest"
    ]
    loaded["discovery_manifest_digest"] = customization_discovery_digest(
        loaded
    )
    loaded["customization_set_digest"] = digest_record(
        loaded, "customization_set_digest"
    )
    controls = []
    for source_row in loaded["rows"]:
        for control_name in THINKING_CONTROLS:
            explicit = (
                source_row["source_kind"] == "CONTROL_REQUEST"
                and control_name == "ADAPTIVE_THINKING"
            )
            controls.append(
                {
                    "ordinal": len(controls),
                    "customization_row_ordinal": source_row["ordinal"],
                    "source_kind": source_row["source_kind"],
                    "source_id": source_row["source_id"],
                    "customization_row_digest": source_row["row_digest"],
                    "control_name": control_name,
                    "serialized_value": True if explicit else None,
                    "state": "EXPLICIT" if explicit else "PROVEN_ABSENT",
                }
            )
    effort = {
        "schema": "plamen.claude-effort-authority.v3",
        "effort_authority_version": 3,
        "effort_authority_digest": "",
        "semantic_plan_digest": plan_digest,
        "exact_model_id": "claude-opus-5",
        "requested_effort": "high",
        "organization_cap_state": "KNOWN_PERMITS_REQUEST",
        "customization_set_digest": loaded["customization_set_digest"],
        "environment_effort": "high",
        "cli_effort": "high",
        "authority_result": "SEALED",
    }
    effort["effort_authority_digest"] = digest_record(
        effort, "effort_authority_digest"
    )
    control = {
        "schema": "plamen.claude-provider-control-vector.v1",
        "provider_control_vector_version": 1,
        "provider_control_vector_digest": "",
        "semantic_plan_digest": plan_digest,
        "exact_model_id": "claude-opus-5",
        "effort_authority_digest": effort["effort_authority_digest"],
        "requested_effort": effort["requested_effort"],
        "requested_thinking_mode": "ADAPTIVE_ON",
        "manual_thinking_budget_tokens": None,
        "materialized_argv_digest": argv_digest,
        "materialized_environment_digest": environment_digest,
    }
    control["provider_control_vector_digest"] = digest_record(
        control, "provider_control_vector_digest"
    )
    thinking = {
        "schema": "plamen.claude-thinking-authority.v1",
        "thinking_authority_version": 1,
        "thinking_authority_digest": "",
        "semantic_plan_digest": plan_digest,
        "exact_model_id": control["exact_model_id"],
        "requested_thinking_mode": control["requested_thinking_mode"],
        "manual_thinking_budget_tokens": control[
            "manual_thinking_budget_tokens"
        ],
        "customization_set_digest": effort["customization_set_digest"],
        "customization_row_count": len(loaded["rows"]),
        "ordered_controls": controls,
        "provider_control_vector_digest": control[
            "provider_control_vector_digest"
        ],
        "authority_result": "SEALED",
    }
    thinking["thinking_authority_digest"] = digest_record(
        thinking, "thinking_authority_digest"
    )
    launch = {
        "schema": "plamen.launch-authority.v2",
        "launch_authority_version": 2,
        "launch_authority_digest": "",
        "semantic_plan_digest": plan_digest,
        "arm_family_digest": "3" * 64,
        "generation": 1,
        "model_route_digest": "4" * 64,
        "budget_authority_digest": "5" * 64,
        "generation_reservation_event_digest": "6" * 64,
        "effort_authority_digest": effort["effort_authority_digest"],
        "thinking_authority_digest": thinking[
            "thinking_authority_digest"
        ],
        "loaded_customization_set_digest": thinking[
            "customization_set_digest"
        ],
        "tool_policy_digest": "a" * 64,
        "child_policy": "DRIVER_ONLY_NO_MODEL_CHILDREN",
        "ordered_argv_template_digest": "b" * 64,
        "transport_policy_digest": "c" * 64,
    }
    launch["launch_authority_digest"] = digest_record(
        launch, "launch_authority_digest"
    )
    envelope = {
        "schema": "plamen.attempt-launch-envelope.v2",
        "attempt_launch_version": 2,
        "attempt_launch_digest": "",
        "attempt_identity_digest": "d" * 64,
        "backend_arm_digest": "e" * 64,
        "launch_authority_digest": launch["launch_authority_digest"],
        "attempt_reservation_event_digest": "f" * 64,
        "attempt_resource_entry_digest": "0" * 64,
        "resource_ledger_digest_after_attempt_reservation": "1" * 64,
        "materialized_argv_digest": argv_digest,
        "materialized_environment_digest": environment_digest,
        "materialized_stdin_prompt_digest": "2" * 64,
        "working_directory_identity_digest": "3" * 64,
        "prepared_utc": "2026-07-29T00:00:00Z",
    }
    envelope["attempt_launch_digest"] = digest_record(
        envelope, "attempt_launch_digest"
    )
    mode = spec["mode"]
    if mode == "wrong_vector":
        thinking["provider_control_vector_digest"] = "f" * 64
        thinking["thinking_authority_digest"] = digest_record(
            thinking, "thinking_authority_digest"
        )
        launch["thinking_authority_digest"] = thinking[
            "thinking_authority_digest"
        ]
        launch["launch_authority_digest"] = digest_record(
            launch, "launch_authority_digest"
        )
        envelope["launch_authority_digest"] = launch[
            "launch_authority_digest"
        ]
        envelope["attempt_launch_digest"] = digest_record(
            envelope, "attempt_launch_digest"
        )
    elif mode == "argv_mismatch":
        envelope["materialized_argv_digest"] = "f" * 64
        envelope["attempt_launch_digest"] = digest_record(
            envelope, "attempt_launch_digest"
        )
    elif mode == "environment_mismatch":
        envelope["materialized_environment_digest"] = "f" * 64
        envelope["attempt_launch_digest"] = digest_record(
            envelope, "attempt_launch_digest"
        )
    elif mode == "debt_launch":
        thinking["authority_result"] = "DEBT"
        thinking["thinking_authority_digest"] = digest_record(
            thinking, "thinking_authority_digest"
        )
        launch["thinking_authority_digest"] = thinking[
            "thinking_authority_digest"
        ]
        launch["launch_authority_digest"] = digest_record(
            launch, "launch_authority_digest"
        )
        envelope["launch_authority_digest"] = launch[
            "launch_authority_digest"
        ]
        envelope["attempt_launch_digest"] = digest_record(
            envelope, "attempt_launch_digest"
        )
    elif mode == "effort_debt_launch":
        effort["authority_result"] = "DEBT"
        effort["effort_authority_digest"] = digest_record(
            effort, "effort_authority_digest"
        )
        control["effort_authority_digest"] = effort[
            "effort_authority_digest"
        ]
        control["provider_control_vector_digest"] = digest_record(
            control, "provider_control_vector_digest"
        )
        thinking["provider_control_vector_digest"] = control[
            "provider_control_vector_digest"
        ]
        thinking["thinking_authority_digest"] = digest_record(
            thinking, "thinking_authority_digest"
        )
        launch["effort_authority_digest"] = effort[
            "effort_authority_digest"
        ]
        launch["thinking_authority_digest"] = thinking[
            "thinking_authority_digest"
        ]
        launch["launch_authority_digest"] = digest_record(
            launch, "launch_authority_digest"
        )
        envelope["launch_authority_digest"] = launch[
            "launch_authority_digest"
        ]
        envelope["attempt_launch_digest"] = digest_record(
            envelope, "attempt_launch_digest"
        )
    elif mode == "effort_projection_mismatch":
        control["requested_effort"] = "medium"
        control["provider_control_vector_digest"] = digest_record(
            control, "provider_control_vector_digest"
        )
        thinking["provider_control_vector_digest"] = control[
            "provider_control_vector_digest"
        ]
        thinking["thinking_authority_digest"] = digest_record(
            thinking, "thinking_authority_digest"
        )
        launch["thinking_authority_digest"] = thinking[
            "thinking_authority_digest"
        ]
        launch["launch_authority_digest"] = digest_record(
            launch, "launch_authority_digest"
        )
        envelope["launch_authority_digest"] = launch[
            "launch_authority_digest"
        ]
        envelope["attempt_launch_digest"] = digest_record(
            envelope, "attempt_launch_digest"
        )
    elif mode == "customization_mismatch":
        launch["loaded_customization_set_digest"] = "f" * 64
        launch["launch_authority_digest"] = digest_record(
            launch, "launch_authority_digest"
        )
        envelope["launch_authority_digest"] = launch[
            "launch_authority_digest"
        ]
        envelope["attempt_launch_digest"] = digest_record(
            envelope, "attempt_launch_digest"
        )
    elif mode in {
        "wrong_source_group",
        "wrong_row_digest",
        "duplicate_source_group",
    }:
        first_group = thinking["ordered_controls"][: len(THINKING_CONTROLS)]
        if mode == "wrong_source_group":
            for row in first_group:
                row["source_kind"] = "CLI_ARGUMENT"
        elif mode == "wrong_row_digest":
            for row in first_group:
                row["customization_row_digest"] = "f" * 64
        else:
            second = thinking["ordered_controls"][
                len(THINKING_CONTROLS): 2 * len(THINKING_CONTROLS)
            ]
            for target, source in zip(first_group, second):
                target["source_kind"] = source["source_kind"]
                target["source_id"] = source["source_id"]
                target["customization_row_digest"] = source[
                    "customization_row_digest"
                ]
        thinking["thinking_authority_digest"] = digest_record(
            thinking, "thinking_authority_digest"
        )
        launch["thinking_authority_digest"] = thinking[
            "thinking_authority_digest"
        ]
        launch["launch_authority_digest"] = digest_record(
            launch, "launch_authority_digest"
        )
        envelope["launch_authority_digest"] = launch[
            "launch_authority_digest"
        ]
        envelope["attempt_launch_digest"] = digest_record(
            envelope, "attempt_launch_digest"
        )
    elif mode != "valid":
        raise ConformanceError("VECTOR_THINKING_LAUNCH_MODE_INVALID")
    return {
        "discovery_authority": discovery_authority,
        "loaded_customization_set": loaded,
        "effort_authority": effort,
        "provider_control_vector": control,
        "thinking_authority": thinking,
        "launch_authority": launch,
        "attempt_launch_envelope": envelope,
    }


def make_canary_chain(spec):
    mode = spec["mode"]
    required_case_ids = ["effort-high", "thinking-adaptive"]
    if mode == "missing_required_case":
        required_case_ids.append("model-exact")
    plan = {
        "schema": "plamen.canary-plan-authority.v1",
        "canary_plan_version": 1,
        "canary_plan_digest": "",
        "required_case_ids": semantic_set(required_case_ids),
    }
    plan["canary_plan_digest"] = digest_record(
        plan, "canary_plan_digest"
    )
    plan_digest = plan["canary_plan_digest"]
    authority = {
        "schema": "plamen.canary-proof-rule-authority.v1",
        "proof_rule_authority_version": 1,
        "proof_rule_authority_digest": "",
        "canary_plan_digest": plan_digest,
        "ordered_field_rules": [
            {
                "manifest_field": "effective_effort",
                "allowed_proof_rule_ids": ["prove-effort"],
            },
            {
                "manifest_field": "observed_thinking_state",
                "allowed_proof_rule_ids": ["prove-thinking"],
            },
        ],
    }
    authority["proof_rule_authority_digest"] = digest_record(
        authority, "proof_rule_authority_digest"
    )
    authority_digest = authority["proof_rule_authority_digest"]
    case_results = []
    for case_id, outcome, raw_digest, proof_rule in (
        ("effort-high", "EXACT_HIGH", "2" * 64, "prove-effort"),
        (
            "thinking-adaptive",
            "ADAPTIVE_ON_CONFIRMED",
            "6" * 64,
            "prove-thinking",
        ),
    ):
        case_result = {
            "schema": "plamen.canary-case-result.v1",
            "case_result_version": 1,
            "case_result_digest": "",
            "canary_plan_digest": plan_digest,
            "proof_rule_authority_digest": authority_digest,
            "case_id": case_id,
            "expected_outcome": outcome,
            "observed_outcome": outcome,
            "raw_artifact_digests": [raw_digest],
            "satisfied_proof_rule_ids": [proof_rule],
            "case_disposition": "PASS",
        }
        case_result["case_result_digest"] = digest_record(
            case_result, "case_result_digest"
        )
        case_results.append(case_result)
    case_results.sort(
        key=lambda row: canonical_bytes(row["case_result_digest"])
    )
    by_id = {row["case_id"]: row for row in case_results}
    effort_result = by_id["effort-high"]
    thinking_result = by_id["thinking-adaptive"]
    result_digests = semantic_set(
        [row["case_result_digest"] for row in case_results]
    )
    raw_digests = semantic_set(
        [
            digest
            for row in case_results
            for digest in row["raw_artifact_digests"]
        ]
    )
    manifest = {
        "schema": "plamen.canary-evidence-manifest.v1",
        "evidence_manifest_version": 1,
        "evidence_manifest_digest": "",
        "canary_plan_digest": plan_digest,
        "proof_rule_authority_digest": authority_digest,
        "case_result_digests": result_digests,
        "raw_artifact_digests": raw_digests,
        "raw_artifact_union_digest": hashlib.sha256(
            canonical_bytes(raw_digests)
        ).hexdigest(),
    }
    manifest["evidence_manifest_digest"] = digest_record(
        manifest, "evidence_manifest_digest"
    )
    claim = {
        "schema": "plamen.canary-field-claim.v2",
        "canary_claim_version": 2,
        "canary_claim_digest": "",
        "canary_plan_digest": plan_digest,
        "proof_rule_authority_digest": authority_digest,
        "evidence_manifest_digest": manifest["evidence_manifest_digest"],
        "manifest_field": "effective_effort",
        "seed_value_digest": "3" * 64,
        "proposed_value_digest": "4" * 64,
        "supporting_case_ids": ["effort-high"],
        "supporting_case_result_digests": [
            effort_result["case_result_digest"]
        ],
        "supporting_proof_rule_ids": ["prove-effort"],
        "claim_result": "PROVEN",
    }
    claim["canary_claim_digest"] = digest_record(
        claim, "canary_claim_digest"
    )
    receipt = {
        "schema": "plamen.provider-capability-canary-receipt.v3",
        "canary_receipt_version": 3,
        "canary_receipt_digest": "",
        "seed_manifest_digest": "5" * 64,
        "canary_plan_digest": plan_digest,
        "proof_rule_authority_digest": authority_digest,
        "evidence_manifest_digest": manifest["evidence_manifest_digest"],
        "executed_case_ids": semantic_set(list(by_id)),
        "passed_case_ids": semantic_set(
            [
                row["case_id"]
                for row in case_results
                if row["case_disposition"] == "PASS"
            ]
        ),
        "field_claim_digests": [claim["canary_claim_digest"]],
        "canary_execution_result": "COMPLETE",
    }
    receipt["canary_receipt_digest"] = digest_record(
        receipt, "canary_receipt_digest"
    )
    if mode == "claim_manifest_mismatch":
        claim["evidence_manifest_digest"] = "9" * 64
    elif mode == "receipt_manifest_mismatch":
        receipt["evidence_manifest_digest"] = "9" * 64
    elif mode == "claim_digest_mutation":
        claim["manifest_field"] = "other"
    elif mode == "wrong_field_rule":
        claim["manifest_field"] = "observed_thinking_state"
        claim["canary_claim_digest"] = digest_record(
            claim, "canary_claim_digest"
        )
        receipt["field_claim_digests"] = [claim["canary_claim_digest"]]
        receipt["canary_receipt_digest"] = digest_record(
            receipt, "canary_receipt_digest"
        )
    elif mode == "receipt_executed_empty":
        receipt["executed_case_ids"] = []
        receipt["canary_receipt_digest"] = digest_record(
            receipt, "canary_receipt_digest"
        )
    elif mode == "claim_wrong_case":
        claim["supporting_case_ids"] = ["other-case"]
        claim["canary_claim_digest"] = digest_record(
            claim, "canary_claim_digest"
        )
        receipt["field_claim_digests"] = [claim["canary_claim_digest"]]
        receipt["canary_receipt_digest"] = digest_record(
            receipt, "canary_receipt_digest"
        )
    elif mode == "swapped_result":
        claim["supporting_case_result_digests"] = [
            thinking_result["case_result_digest"]
        ]
        claim["canary_claim_digest"] = digest_record(
            claim, "canary_claim_digest"
        )
        receipt["field_claim_digests"] = [claim["canary_claim_digest"]]
        receipt["canary_receipt_digest"] = digest_record(
            receipt, "canary_receipt_digest"
        )
    elif mode == "manifest_wrong_raw":
        wrong_raw = "9" * 64
        manifest["raw_artifact_digests"] = [wrong_raw]
        manifest["raw_artifact_union_digest"] = hashlib.sha256(
            canonical_bytes([wrong_raw])
        ).hexdigest()
        manifest["evidence_manifest_digest"] = digest_record(
            manifest, "evidence_manifest_digest"
        )
        claim["evidence_manifest_digest"] = manifest[
            "evidence_manifest_digest"
        ]
        claim["canary_claim_digest"] = digest_record(
            claim, "canary_claim_digest"
        )
        receipt["evidence_manifest_digest"] = manifest[
            "evidence_manifest_digest"
        ]
        receipt["field_claim_digests"] = [claim["canary_claim_digest"]]
        receipt["canary_receipt_digest"] = digest_record(
            receipt, "canary_receipt_digest"
        )
    return {
        "plan": plan,
        "proof_rule_authority": authority,
        "case_results": case_results,
        "manifest": manifest,
        "claim": claim,
        "receipt": receipt,
    }


def make_budget_chain(spec):
    grant = {
        "uncached_input_tokens": 500,
        "cache_write_tokens": 50,
        "cached_input_tokens": 50,
        "output_tokens_including_reasoning": 100,
        "reasoning_tokens_subset": 50,
    }
    derivation = {
        "schema": "plamen.token-budget-derivation.v2",
        "token_derivation_version": 2,
        "token_derivation_digest": "",
        "arm_family_digest": "1" * 64,
        "generation": 1,
        "exact_model_id": "claude-opus-5",
        "tokenizer_authority_digest": "2" * 64,
        "context_budget_digest": "3" * 64,
        "source_payload_digest": "4" * 64,
        "source_payload_bytes": 10000,
        "output_artifact_bytes_reservation": 1000,
        "context_window_tokens": 1000,
        "maximum_input_tokens": 800,
        "maximum_output_tokens": 200,
        "request_input_ceiling_tokens": 700,
        "request_output_ceiling_tokens": 150,
        "reserved_system_tokens": 50,
        "reserved_tool_tokens": 50,
        "reserved_output_tokens": 150,
        "derived_token_grant": copy.deepcopy(grant),
        "derivation_policy_digest": "5" * 64,
        "derivation_method": "PINNED_LOCAL_TOKENIZER",
        "rounding_policy": "EXACT",
    }
    derivation["token_derivation_digest"] = digest_record(
        derivation, "token_derivation_digest"
    )
    budget = {
        "schema": "plamen.budget-authority.v3",
        "budget_authority_version": 3,
        "budget_authority_digest": "",
        "semantic_plan_digest": "6" * 64,
        "common_resource_grant_digest": "7" * 64,
        "context_budget_digest": derivation["context_budget_digest"],
        "arm_family_digest": derivation["arm_family_digest"],
        "resource_ledger_digest_at_compile": "8" * 64,
        "generation": derivation["generation"],
        "provider": "ANTHROPIC",
        "account_mode": "subscription",
        "requested_family_reservation": {
            **zero_vector(),
            "source_payload_bytes": derivation["source_payload_bytes"],
            "output_artifact_bytes": derivation[
                "output_artifact_bytes_reservation"
            ],
            "turns": 10,
            "currency_micros": 1000,
        },
        "token_budget_derivation_digest": derivation[
            "token_derivation_digest"
        ],
        "token_grant": copy.deepcopy(grant),
        "plan_or_price_class": "subscription",
    }
    budget["budget_authority_digest"] = digest_record(
        budget, "budget_authority_digest"
    )
    mode = spec["mode"]
    if mode == "token_mismatch":
        budget["token_grant"]["output_tokens_including_reasoning"] = 101
    elif mode == "derivation_digest_mismatch":
        budget["token_budget_derivation_digest"] = "9" * 64
    elif mode == "budget_digest_mutation":
        budget["account_mode"] = "changed"
    elif mode == "source_bytes_mismatch":
        budget["requested_family_reservation"]["source_payload_bytes"] += 1
        budget["budget_authority_digest"] = digest_record(
            budget, "budget_authority_digest"
        )
    elif mode == "output_bytes_mismatch":
        budget["requested_family_reservation"]["output_artifact_bytes"] += 1
        budget["budget_authority_digest"] = digest_record(
            budget, "budget_authority_digest"
        )
    return {"derivation": derivation, "budget": budget}


def make_budget_ledger_join(spec):
    chain = make_budget_chain({"mode": "valid"})
    derivation = chain["derivation"]
    budget = chain["budget"]
    reservation = copy.deepcopy(budget["requested_family_reservation"])
    prestate = {
        "schema": "plamen.backend-semantic-resource-ledger.v2",
        "resource_ledger_version": 2,
        "resource_ledger_id": "ledger:family-budget",
        "resource_ledger_digest": "",
        "arm_family_digest": budget["arm_family_digest"],
        "semantic_plan_digest": budget["semantic_plan_digest"],
        "common_resource_grant_digest": budget[
            "common_resource_grant_digest"
        ],
        "currency_code": "USD",
        "ledger_revision": 0,
        "previous_ledger_digest": None,
        "ledger_state": "ACTIVE",
        "grant": copy.deepcopy(reservation),
        "active_reserved": zero_vector(),
        "reconciled": zero_vector(),
        "remaining": copy.deepcopy(reservation),
        "generation_entry_digests": [],
        "attempt_entry_digests": [],
        "event_digests": [],
        "last_event_sequence": None,
        "last_event_digest": None,
    }
    prestate["resource_ledger_digest"] = digest_record(
        prestate, "resource_ledger_digest"
    )
    budget["resource_ledger_digest_at_compile"] = prestate[
        "resource_ledger_digest"
    ]
    budget["budget_authority_digest"] = digest_record(
        budget, "budget_authority_digest"
    )
    event = {
        "schema": "plamen.resource-ledger-event.v2",
        "ledger_event_version": 2,
        "ledger_event_digest": "",
        "arm_family_digest": budget["arm_family_digest"],
        "event_sequence": 0,
        "previous_event_digest": None,
        "expected_ledger_revision": 0,
        "idempotency_key": "9" * 64,
        "event_kind": "RESERVE_GENERATION",
        "generation": budget["generation"],
        "attempt_identity_digest": None,
        "budget_authority_digest": budget["budget_authority_digest"],
        "reservation_delta": copy.deepcopy(reservation),
        "reconciliation_delta": zero_vector(),
        "release_delta": zero_vector(),
        "token_budget_derivation_digest": derivation[
            "token_derivation_digest"
        ],
        "attempt_resource_entry_digest": None,
        "attempt_launch_digest": None,
        "event_utc": "2026-07-29T00:00:00Z",
    }
    event["ledger_event_digest"] = digest_record(
        event, "ledger_event_digest"
    )
    mode = spec["mode"]
    if mode == "wrong_delta":
        event["reservation_delta"]["turns"] -= 1
        event["ledger_event_digest"] = digest_record(
            event, "ledger_event_digest"
        )
    elif mode == "stale_ledger":
        budget["resource_ledger_digest_at_compile"] = "f" * 64
        budget["budget_authority_digest"] = digest_record(
            budget, "budget_authority_digest"
        )
        event["budget_authority_digest"] = budget[
            "budget_authority_digest"
        ]
        event["ledger_event_digest"] = digest_record(
            event, "ledger_event_digest"
        )
    elif mode == "wrong_budget":
        event["budget_authority_digest"] = "f" * 64
        event["ledger_event_digest"] = digest_record(
            event, "ledger_event_digest"
        )
    elif mode in {"wrong_plan", "wrong_common_grant"}:
        field = (
            "semantic_plan_digest"
            if mode == "wrong_plan"
            else "common_resource_grant_digest"
        )
        prestate[field] = "f" * 64
        prestate["resource_ledger_digest"] = digest_record(
            prestate, "resource_ledger_digest"
        )
        budget["resource_ledger_digest_at_compile"] = prestate[
            "resource_ledger_digest"
        ]
        budget["budget_authority_digest"] = digest_record(
            budget, "budget_authority_digest"
        )
        event["budget_authority_digest"] = budget[
            "budget_authority_digest"
        ]
        event["ledger_event_digest"] = digest_record(
            event, "ledger_event_digest"
        )
    elif mode == "event_sequence_wrong":
        event["event_sequence"] += 1
        event["ledger_event_digest"] = digest_record(
            event, "ledger_event_digest"
        )
    elif mode == "previous_event_wrong":
        event["previous_event_digest"] = "f" * 64
        event["ledger_event_digest"] = digest_record(
            event, "ledger_event_digest"
        )
    elif mode != "valid":
        raise ConformanceError("VECTOR_BUDGET_LEDGER_MODE_INVALID")
    return {
        "derivation": derivation,
        "budget": budget,
        "prestate": prestate,
        "reservation_event": event,
    }


def make_resource_event(spec):
    kind = spec["kind"]
    record = {
        "schema": "plamen.resource-ledger-event.v2",
        "ledger_event_version": 2,
        "ledger_event_digest": "",
        "arm_family_digest": "1" * 64,
        "event_sequence": 2,
        "previous_event_digest": "2" * 64,
        "expected_ledger_revision": 2,
        "idempotency_key": "3" * 64,
        "event_kind": kind,
        "generation": 1,
        "attempt_identity_digest": "4" * 64,
        "budget_authority_digest": "5" * 64,
        "reservation_delta": zero_vector(),
        "reconciliation_delta": zero_vector(),
        "release_delta": zero_vector(),
        "token_budget_derivation_digest": "6" * 64,
        "attempt_resource_entry_digest": "7" * 64,
        "attempt_launch_digest": None,
        "event_utc": "2026-07-29T00:00:00Z",
    }
    if kind == "RELEASE_ATTEMPT":
        record["release_delta"]["turns"] = 5
    elif kind == "MARK_CONSUMED_ATTEMPT_DEBT":
        record["attempt_launch_digest"] = "8" * 64
    elif kind == "MARK_RESERVED_ATTEMPT_DEBT":
        pass
    else:
        raise ConformanceError("VECTOR_LEDGER_EVENT_KIND_INVALID")
    record["ledger_event_digest"] = digest_record(
        record, "ledger_event_digest"
    )
    if spec.get("launch_on_release"):
        record["attempt_launch_digest"] = "8" * 64
    if spec.get("omit_launch"):
        record["attempt_launch_digest"] = None
    return record


def make_ledger_snapshot(spec):
    record = {
        "schema": "plamen.backend-semantic-resource-ledger.v2",
        "resource_ledger_version": 2,
        "resource_ledger_id": "ledger:family-a",
        "resource_ledger_digest": "",
        "arm_family_digest": "1" * 64,
        "semantic_plan_digest": "2" * 64,
        "common_resource_grant_digest": "3" * 64,
        "currency_code": None,
        "ledger_revision": 1,
        "previous_ledger_digest": "4" * 64,
        "ledger_state": "ACTIVE",
        "grant": {**zero_vector(), "turns": 10},
        "active_reserved": {**zero_vector(), "turns": 5},
        "reconciled": zero_vector(),
        "remaining": {**zero_vector(), "turns": 5},
        "generation_entry_digests": ["5" * 64],
        "attempt_entry_digests": [],
        "event_digests": ["6" * 64],
        "last_event_sequence": 0,
        "last_event_digest": "6" * 64,
    }
    mode = spec["mode"]
    if mode == "previous_null":
        record["previous_ledger_digest"] = None
    elif mode == "last_sequence_wrong":
        record["last_event_sequence"] = 1
    elif mode == "last_not_member":
        record["last_event_digest"] = "7" * 64
    elif mode == "event_count_wrong":
        record["event_digests"] = []
    record["resource_ledger_digest"] = digest_record(
        record, "resource_ledger_digest"
    )
    return record


def make_observation(spec):
    states = {
        "confirmed": "ADAPTIVE_ON_CONFIRMED",
        "unobservable": "UNOBSERVABLE",
        "mismatched": "MISMATCHED",
        "not_applicable": "NOT_APPLICABLE",
        "confirmed_null": "ADAPTIVE_ON_CONFIRMED",
    }
    mode = spec["mode"]
    if mode not in states:
        raise ConformanceError("VECTOR_OBSERVATION_MODE_INVALID")
    evidence = None if mode in {"not_applicable", "confirmed_null"} else "a" * 64
    record = {
        "schema": "plamen.provider-execution-observation.v4",
        "observation_version": 4,
        "observation_digest": "",
        "attempt_identity_digest": "1" * 64,
        "backend_arm_digest": "2" * 64,
        "attempt_launch_digest": "3" * 64,
        "attempt_reservation_event_digest": "4" * 64,
        "reserved_attempt_resource_entry_digest": "5" * 64,
        "consumed_attempt_resource_entry_digest": "d" * 64,
        "resource_ledger_digest_after_attempt_reservation": "6" * 64,
        "launch_consumption_event_digest": "7" * 64,
        "resource_ledger_digest_after_launch_consumption": "8" * 64,
        "observed_effective_model_id": "claude-opus-5",
        "effective_model_state": "EXACT",
        "observed_effective_effort": "high",
        "effective_effort_state": "EXACT",
        "observed_thinking_state": states[mode],
        "thinking_observation_evidence_digest": evidence,
        "provider_terminal_category": "COMPLETED",
        "provider_usage_digest": "b" * 64,
        "raw_stream_digest": "c" * 64,
    }
    record["observation_digest"] = digest_record(record, "observation_digest")
    return record


def make_observation_disposition(spec):
    mode = spec["mode"]
    confirmed = mode in {
        "confirmed_reconcile",
        "wrong_confirmed_mode",
        "wrong_consumption_ledger_state_confirmed",
        "missing_reservation_event_confirmed",
    }
    launch_seal = make_thinking_launch_join({"mode": "valid"})
    effort_authority = launch_seal["effort_authority"]
    thinking_authority = launch_seal["thinking_authority"]
    launch_authority = launch_seal["launch_authority"]
    launch_envelope = launch_seal["attempt_launch_envelope"]
    observation = make_observation(
        {
            "mode": (
                "confirmed"
                if confirmed
                or mode
                in {
                    "model_mismatched_debt",
                    "effort_unobservable_debt",
                }
                else "mismatched"
                if mode == "mismatched_debt"
                else "unobservable"
            )
        }
    )
    observation.update(
        {
            "observation_digest": "",
            "attempt_identity_digest": launch_envelope[
                "attempt_identity_digest"
            ],
            "backend_arm_digest": launch_envelope[
                "backend_arm_digest"
            ],
            "attempt_launch_digest": launch_envelope[
                "attempt_launch_digest"
            ],
            "attempt_reservation_event_digest": launch_envelope[
                "attempt_reservation_event_digest"
            ],
            "reserved_attempt_resource_entry_digest": launch_envelope[
                "attempt_resource_entry_digest"
            ],
            "resource_ledger_digest_after_attempt_reservation": (
                launch_envelope[
                    "resource_ledger_digest_after_attempt_reservation"
                ]
            ),
        }
    )
    if mode == "wrong_confirmed_mode":
        observation["observed_thinking_state"] = "MANUAL_OFF_CONFIRMED"
    elif mode == "model_mismatched_debt":
        observation["observed_effective_model_id"] = "claude-sonnet-5"
        observation["effective_model_state"] = "MISMATCHED"
    elif mode == "effort_unobservable_debt":
        observation["observed_effective_effort"] = None
        observation["effective_effort_state"] = "UNOBSERVABLE"
    generation_active_entry = {
        "schema": "plamen.generation-resource-entry.v2",
        "generation_entry_version": 2,
        "generation_entry_digest": "",
        "arm_family_digest": launch_authority["arm_family_digest"],
        "generation": launch_authority["generation"],
        "budget_authority_digest": launch_authority[
            "budget_authority_digest"
        ],
        "previous_generation_entry_digest": "9" * 64,
        "generation_reservation": {**zero_vector(), "turns": 10},
        "unallocated_reservation": {**zero_vector(), "turns": 5},
        "reconciled_use": zero_vector(),
        "entry_state": "ACTIVE",
    }
    generation_active_entry["generation_entry_digest"] = digest_record(
        generation_active_entry, "generation_entry_digest"
    )
    consumed_entry = {
        "schema": "plamen.attempt-resource-entry.v2",
        "attempt_entry_version": 2,
        "attempt_entry_digest": "",
        "arm_family_digest": launch_authority["arm_family_digest"],
        "generation": launch_authority["generation"],
        "attempt_identity_digest": observation["attempt_identity_digest"],
        "generation_entry_digest": generation_active_entry[
            "generation_entry_digest"
        ],
        "budget_authority_digest": launch_authority[
            "budget_authority_digest"
        ],
        "token_budget_derivation_digest": "d" * 64,
        "previous_attempt_entry_digest": observation[
            "reserved_attempt_resource_entry_digest"
        ],
        "attempt_launch_digest": observation["attempt_launch_digest"],
        "attempt_allocation": {**zero_vector(), "turns": 5},
        "reconciled_use": zero_vector(),
        "entry_state": "LAUNCH_CONSUMED",
    }
    consumed_entry["attempt_entry_digest"] = digest_record(
        consumed_entry, "attempt_entry_digest"
    )
    consume_event = {
        "schema": "plamen.resource-ledger-event.v2",
        "ledger_event_version": 2,
        "ledger_event_digest": "",
        "arm_family_digest": consumed_entry["arm_family_digest"],
        "event_sequence": 2,
        "previous_event_digest": launch_envelope[
            "attempt_reservation_event_digest"
        ],
        "expected_ledger_revision": 2,
        "idempotency_key": "a" * 64,
        "event_kind": "CONSUME_ATTEMPT_LAUNCH",
        "generation": consumed_entry["generation"],
        "attempt_identity_digest": consumed_entry[
            "attempt_identity_digest"
        ],
        "budget_authority_digest": consumed_entry[
            "budget_authority_digest"
        ],
        "reservation_delta": zero_vector(),
        "reconciliation_delta": zero_vector(),
        "release_delta": zero_vector(),
        "token_budget_derivation_digest": consumed_entry[
            "token_budget_derivation_digest"
        ],
        "attempt_resource_entry_digest": consumed_entry[
            "attempt_entry_digest"
        ],
        "attempt_launch_digest": consumed_entry[
            "attempt_launch_digest"
        ],
        "event_utc": "2026-07-29T00:00:00Z",
    }
    consume_event["ledger_event_digest"] = digest_record(
        consume_event, "ledger_event_digest"
    )
    post_consumption_ledger = {
        "schema": "plamen.backend-semantic-resource-ledger.v2",
        "resource_ledger_version": 2,
        "resource_ledger_id": "ledger:observation-disposition",
        "resource_ledger_digest": "",
        "arm_family_digest": consumed_entry["arm_family_digest"],
        "semantic_plan_digest": launch_authority[
            "semantic_plan_digest"
        ],
        "common_resource_grant_digest": "b" * 64,
        "currency_code": None,
        "ledger_revision": 3,
        "previous_ledger_digest": launch_envelope[
            "resource_ledger_digest_after_attempt_reservation"
        ],
        "ledger_state": "ACTIVE",
        "grant": {**zero_vector(), "turns": 10},
        "active_reserved": {**zero_vector(), "turns": 10},
        "reconciled": zero_vector(),
        "remaining": zero_vector(),
        "generation_entry_digests": [
            generation_active_entry["generation_entry_digest"]
        ],
        "attempt_entry_digests": [
            consumed_entry["attempt_entry_digest"]
        ],
        "event_digests": semantic_set(
            [
                "8" * 64,
                launch_envelope["attempt_reservation_event_digest"],
                consume_event["ledger_event_digest"],
            ]
        ),
        "last_event_sequence": consume_event["event_sequence"],
        "last_event_digest": consume_event["ledger_event_digest"],
    }
    post_consumption_ledger["resource_ledger_digest"] = digest_record(
        post_consumption_ledger, "resource_ledger_digest"
    )
    observation["consumed_attempt_resource_entry_digest"] = consumed_entry[
        "attempt_entry_digest"
    ]
    observation["launch_consumption_event_digest"] = consume_event[
        "ledger_event_digest"
    ]
    observation[
        "resource_ledger_digest_after_launch_consumption"
    ] = post_consumption_ledger["resource_ledger_digest"]
    observation["observation_digest"] = digest_record(
        observation, "observation_digest"
    )
    if mode == "wrong_consumption_ledger_state_confirmed":
        post_consumption_ledger["ledger_state"] = "CLOSED"
        post_consumption_ledger["resource_ledger_digest"] = digest_record(
            post_consumption_ledger, "resource_ledger_digest"
        )
        observation[
            "resource_ledger_digest_after_launch_consumption"
        ] = post_consumption_ledger["resource_ledger_digest"]
        observation["observation_digest"] = digest_record(
            observation, "observation_digest"
        )
    elif mode == "missing_reservation_event_confirmed":
        post_consumption_ledger["event_digests"] = semantic_set(
            [
                "8" * 64,
                "6" * 64,
                consume_event["ledger_event_digest"],
            ]
        )
        post_consumption_ledger["resource_ledger_digest"] = digest_record(
            post_consumption_ledger, "resource_ledger_digest"
        )
        observation[
            "resource_ledger_digest_after_launch_consumption"
        ] = post_consumption_ledger["resource_ledger_digest"]
        observation["observation_digest"] = digest_record(
            observation, "observation_digest"
        )
    if confirmed:
        return {
            "observation": observation,
            "generation_active_entry": generation_active_entry,
            "consumed_entry": consumed_entry,
            "consume_event": consume_event,
            "post_consumption_ledger": post_consumption_ledger,
            "thinking_authority": thinking_authority,
            "effort_authority": effort_authority,
            "launch_authority": launch_authority,
            "launch_envelope": launch_envelope,
            "route_debt": None,
            "debt_event": None,
            "generation_debt_entry": None,
            "attempt_debt_entry": None,
            "post_debt_ledger": None,
            "disposition": "RECONCILE",
            "terminal_safe_eligible": True,
        }
    evidence_digest = hashlib.sha256(
        canonical_bytes([observation["observation_digest"]])
    ).hexdigest()
    route_debt = {
        "schema": "plamen.route-debt.v3",
        "route_debt_version": 3,
        "route_debt_id": f"debt:{'d' * 64}",
        "route_debt_digest": "",
        "semantic_plan_digest": launch_authority[
            "semantic_plan_digest"
        ],
        "backend_arm_digest": observation["backend_arm_digest"],
        "attempt_identity_digest": observation[
            "attempt_identity_digest"
        ],
        "stage": "PROVIDER_OBSERVATION",
        "debt_code": (
            "MODEL_MISMATCHED"
            if mode == "model_mismatched_debt"
            else "EFFORT_UNOBSERVABLE"
            if mode == "effort_unobservable_debt"
            else "THINKING_MISMATCHED"
            if mode == "mismatched_debt"
            else "THINKING_UNOBSERVABLE"
        ),
        "evidence_digest_set_digest": evidence_digest,
        "required_operator_action": "REVIEW_PROVIDER_OBSERVABILITY",
    }
    route_debt["route_debt_digest"] = digest_record(
        route_debt, "route_debt_digest"
    )
    generation_debt_entry = copy.deepcopy(generation_active_entry)
    generation_debt_entry.update(
        {
            "generation_entry_digest": "",
            "previous_generation_entry_digest": generation_active_entry[
                "generation_entry_digest"
            ],
            "entry_state": "DEBT",
        }
    )
    generation_debt_entry["generation_entry_digest"] = digest_record(
        generation_debt_entry, "generation_entry_digest"
    )
    attempt_debt_entry = copy.deepcopy(consumed_entry)
    attempt_debt_entry.update(
        {
            "attempt_entry_digest": "",
            "generation_entry_digest": generation_debt_entry[
                "generation_entry_digest"
            ],
            "previous_attempt_entry_digest": consumed_entry[
                "attempt_entry_digest"
            ],
            "entry_state": "DEBT",
        }
    )
    attempt_debt_entry["attempt_entry_digest"] = digest_record(
        attempt_debt_entry, "attempt_entry_digest"
    )
    event = {
        "schema": "plamen.resource-ledger-event.v2",
        "ledger_event_version": 2,
        "ledger_event_digest": "",
        "arm_family_digest": consumed_entry["arm_family_digest"],
        "event_sequence": 3,
        "previous_event_digest": consume_event["ledger_event_digest"],
        "expected_ledger_revision": 3,
        "idempotency_key": "c" * 64,
        "event_kind": "MARK_CONSUMED_ATTEMPT_DEBT",
        "generation": consumed_entry["generation"],
        "attempt_identity_digest": observation[
            "attempt_identity_digest"
        ],
        "budget_authority_digest": consumed_entry[
            "budget_authority_digest"
        ],
        "reservation_delta": zero_vector(),
        "reconciliation_delta": zero_vector(),
        "release_delta": zero_vector(),
        "token_budget_derivation_digest": consumed_entry[
            "token_budget_derivation_digest"
        ],
        "attempt_resource_entry_digest": attempt_debt_entry[
            "attempt_entry_digest"
        ],
        "attempt_launch_digest": consumed_entry[
            "attempt_launch_digest"
        ],
        "event_utc": "2026-07-29T00:00:00Z",
    }
    event["ledger_event_digest"] = digest_record(
        event, "ledger_event_digest"
    )
    post_debt_ledger = copy.deepcopy(post_consumption_ledger)
    post_debt_ledger.update(
        {
            "resource_ledger_digest": "",
            "ledger_revision": 4,
            "previous_ledger_digest": post_consumption_ledger[
                "resource_ledger_digest"
            ],
            "ledger_state": "DEBT",
            "generation_entry_digests": [
                generation_debt_entry["generation_entry_digest"]
            ],
            "attempt_entry_digests": [
                attempt_debt_entry["attempt_entry_digest"]
            ],
            "event_digests": semantic_set(
                post_consumption_ledger["event_digests"]
                + [event["ledger_event_digest"]]
            ),
            "last_event_sequence": event["event_sequence"],
            "last_event_digest": event["ledger_event_digest"],
        }
    )
    post_debt_ledger["resource_ledger_digest"] = digest_record(
        post_debt_ledger, "resource_ledger_digest"
    )
    result = {
        "observation": observation,
        "generation_active_entry": generation_active_entry,
        "consumed_entry": consumed_entry,
        "consume_event": consume_event,
        "post_consumption_ledger": post_consumption_ledger,
        "thinking_authority": thinking_authority,
        "effort_authority": effort_authority,
        "launch_authority": launch_authority,
        "launch_envelope": launch_envelope,
        "route_debt": route_debt,
        "generation_debt_entry": generation_debt_entry,
        "attempt_debt_entry": attempt_debt_entry,
        "debt_event": event,
        "post_debt_ledger": post_debt_ledger,
        "disposition": "DEBT",
        "terminal_safe_eligible": False,
    }
    if mode == "direct_reconcile":
        result["route_debt"] = None
        result["generation_debt_entry"] = None
        result["attempt_debt_entry"] = None
        result["debt_event"] = None
        result["post_debt_ledger"] = None
        result["disposition"] = "RECONCILE"
        result["terminal_safe_eligible"] = True
    elif mode == "wrong_debt_evidence":
        route_debt["evidence_digest_set_digest"] = "f" * 64
        route_debt["route_debt_digest"] = digest_record(
            route_debt, "route_debt_digest"
        )
    elif mode == "wrong_debt_stage":
        route_debt["stage"] = "BUDGET_AUTHORITY"
        route_debt["route_debt_digest"] = digest_record(
            route_debt, "route_debt_digest"
        )
    elif mode == "wrong_event_launch":
        event["attempt_launch_digest"] = "e" * 64
        event["ledger_event_digest"] = digest_record(
            event, "ledger_event_digest"
        )
    elif mode == "wrong_event_family":
        event["arm_family_digest"] = "f" * 64
        event["ledger_event_digest"] = digest_record(
            event, "ledger_event_digest"
        )
    elif mode == "wrong_event_generation":
        event["generation"] = 2
        event["ledger_event_digest"] = digest_record(
            event, "ledger_event_digest"
        )
    elif mode == "stale_debt_cas":
        event["expected_ledger_revision"] = 99
        event["ledger_event_digest"] = digest_record(
            event, "ledger_event_digest"
        )
    elif mode == "wrong_debt_snapshot_state":
        post_debt_ledger["ledger_state"] = "ACTIVE"
        post_debt_ledger["resource_ledger_digest"] = digest_record(
            post_debt_ledger, "resource_ledger_digest"
        )
    elif mode == "wrong_debt_entry_predecessor":
        attempt_debt_entry["previous_attempt_entry_digest"] = (
            launch_envelope["attempt_resource_entry_digest"]
        )
        attempt_debt_entry["attempt_entry_digest"] = digest_record(
            attempt_debt_entry, "attempt_entry_digest"
        )
        event["attempt_resource_entry_digest"] = attempt_debt_entry[
            "attempt_entry_digest"
        ]
        event["ledger_event_digest"] = digest_record(
            event, "ledger_event_digest"
        )
        post_debt_ledger["attempt_entry_digests"] = [
            attempt_debt_entry["attempt_entry_digest"]
        ]
        post_debt_ledger["event_digests"] = semantic_set(
            post_consumption_ledger["event_digests"]
            + [event["ledger_event_digest"]]
        )
        post_debt_ledger["last_event_digest"] = event[
            "ledger_event_digest"
        ]
        post_debt_ledger["resource_ledger_digest"] = digest_record(
            post_debt_ledger, "resource_ledger_digest"
        )
    elif mode == "wrong_ledger_semantic_plan":
        post_consumption_ledger["semantic_plan_digest"] = "f" * 64
        post_consumption_ledger["resource_ledger_digest"] = digest_record(
            post_consumption_ledger, "resource_ledger_digest"
        )
        observation[
            "resource_ledger_digest_after_launch_consumption"
        ] = post_consumption_ledger["resource_ledger_digest"]
        observation["observation_digest"] = digest_record(
            observation, "observation_digest"
        )
        route_debt["evidence_digest_set_digest"] = hashlib.sha256(
            canonical_bytes([observation["observation_digest"]])
        ).hexdigest()
        route_debt["route_debt_digest"] = digest_record(
            route_debt, "route_debt_digest"
        )
        post_debt_ledger["semantic_plan_digest"] = "f" * 64
        post_debt_ledger["previous_ledger_digest"] = (
            post_consumption_ledger["resource_ledger_digest"]
        )
        post_debt_ledger["resource_ledger_digest"] = digest_record(
            post_debt_ledger, "resource_ledger_digest"
        )
    elif mode not in {
        "unobservable_debt",
        "mismatched_debt",
        "model_mismatched_debt",
        "effort_unobservable_debt",
        "confirmed_reconcile",
    }:
        if mode not in {
            "direct_reconcile",
            "wrong_debt_evidence",
            "wrong_debt_stage",
            "wrong_event_launch",
            "wrong_event_family",
            "wrong_event_generation",
            "stale_debt_cas",
            "wrong_debt_snapshot_state",
            "wrong_debt_entry_predecessor",
            "wrong_ledger_semantic_plan",
        }:
            raise ConformanceError(
                "VECTOR_OBSERVATION_DISPOSITION_MODE_INVALID"
            )
    return result


def expand(value):
    if isinstance(value, list):
        return [expand(item) for item in value]
    if not isinstance(value, dict):
        return value
    if set(value) == {"$digest"}:
        char = value["$digest"]
        if not isinstance(char, str) or len(char) != 1 or char not in "0123456789abcdef":
            raise ConformanceError("VECTOR_DIGEST_SHORTHAND_INVALID")
        return char * 64
    if set(value) == {"$vector"}:
        out = zero_vector()
        for key, item in value["$vector"].items():
            if key not in out:
                raise ConformanceError("VECTOR_RESOURCE_FIELD_INVALID")
            out[key] = item
        return out
    if set(value) == {"$thinking_controls"}:
        return make_thinking_controls(value["$thinking_controls"])
    if set(value) == {"$self_digest"}:
        return copy.deepcopy(value)
    if set(value) == {"$customization_record"}:
        return make_customization_record(value["$customization_record"])
    if set(value) == {"$attempt_join"}:
        return make_attempt_join(value["$attempt_join"])
    if set(value) == {"$attempt_entry_lifecycle"}:
        return make_attempt_entry_lifecycle(
            value["$attempt_entry_lifecycle"]
        )
    if set(value) == {"$customization_join"}:
        return make_customization_join(value["$customization_join"])
    if set(value) == {"$thinking_launch_join"}:
        return make_thinking_launch_join(value["$thinking_launch_join"])
    if set(value) == {"$canary_chain"}:
        return make_canary_chain(value["$canary_chain"])
    if set(value) == {"$budget_chain"}:
        return make_budget_chain(value["$budget_chain"])
    if set(value) == {"$budget_ledger_join"}:
        return make_budget_ledger_join(value["$budget_ledger_join"])
    if set(value) == {"$ledger_event"}:
        return make_resource_event(value["$ledger_event"])
    if set(value) == {"$ledger_snapshot"}:
        return make_ledger_snapshot(value["$ledger_snapshot"])
    if set(value) == {"$observation"}:
        return make_observation(value["$observation"])
    if set(value) == {"$observation_disposition"}:
        return make_observation_disposition(
            value["$observation_disposition"]
        )
    return {key: expand(item) for key, item in value.items()}


def digest_record(record, digest_field):
    payload = copy.deepcopy(record)
    payload.pop(digest_field)
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def expected_customization_registry_digest():
    registry = [
        {"source_kind": source, "precedence_rank": rank}
        for source, rank in SOURCE_ORDER.items()
    ]
    return hashlib.sha256(canonical_bytes(registry)).hexdigest()


def customization_source_projection(rows):
    return [
        {
            "ordinal": row["ordinal"],
            "precedence_rank": row["precedence_rank"],
            "source_kind": row["source_kind"],
            "source_id": row["source_id"],
            "canonical_realpath_digest": row[
                "canonical_realpath_digest"
            ],
        }
        for row in rows
    ]


def make_discovery_authority(record):
    authority = {
        "schema": "plamen.customization-discovery-authority.v1",
        "discovery_authority_version": 1,
        "discovery_authority_digest": "",
        "resolution_root_digest": record["resolution_root_digest"],
        "customization_registry_digest": record[
            "customization_registry_digest"
        ],
        "expected_sources": customization_source_projection(record["rows"]),
    }
    authority["discovery_authority_digest"] = digest_record(
        authority, "discovery_authority_digest"
    )
    return authority


def customization_discovery_digest(record):
    projection = {
        "resolution_root_digest": record["resolution_root_digest"],
        "customization_registry_digest": record[
            "customization_registry_digest"
        ],
        "discovery_authority_digest": record[
            "discovery_authority_digest"
        ],
        "expected_row_count": record["expected_row_count"],
        "ordered_sources": [
            {
                "ordinal": row["ordinal"],
                "source_kind": row["source_kind"],
                "source_id": row["source_id"],
                "canonical_realpath_digest": row[
                    "canonical_realpath_digest"
                ],
            }
            for row in record["rows"]
        ],
    }
    return hashlib.sha256(canonical_bytes(projection)).hexdigest()


def materialize_self_digests(value):
    if isinstance(value, list):
        return [materialize_self_digests(item) for item in value]
    if not isinstance(value, dict):
        return value
    if set(value) == {"$self_digest"}:
        return value
    out = {key: materialize_self_digests(item) for key, item in value.items()}
    for key, item in list(out.items()):
        if item == {"$customization_registry_digest": True}:
            out[key] = expected_customization_registry_digest()
    for key, item in list(out.items()):
        if item == {"$customization_discovery_digest": True}:
            out[key] = customization_discovery_digest(out)
    for key, item in list(out.items()):
        if isinstance(item, dict) and item == {"$self_digest": key}:
            out[key] = digest_record(out, key)
    return out


def check_value(value, *, identity=True):
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, int):
        if value < 0 or value > MAX_SAFE:
            raise ConformanceError("INTEGER_OUT_OF_RANGE")
        return
    if isinstance(value, float):
        raise ConformanceError("FLOAT_FORBIDDEN")
    if isinstance(value, str):
        if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise ConformanceError("LONE_SURROGATE_FORBIDDEN")
        if identity and unicodedata.normalize("NFC", value) != value:
            raise ConformanceError("NON_NFC_IDENTITY")
        return
    if isinstance(value, list):
        for item in value:
            check_value(item, identity=identity)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not key.isascii():
                raise ConformanceError("NON_ASCII_MEMBER_NAME")
            check_value(key, identity=True)
            check_value(item, identity=identity)
        return
    raise ConformanceError("JSON_TYPE_FORBIDDEN")


def canonical_bytes(value):
    check_value(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def semantic_set(values):
    encoded = [(canonical_bytes(value), value) for value in values]
    encoded.sort(key=lambda pair: pair[0])
    if any(encoded[i - 1][0] == encoded[i][0] for i in range(1, len(encoded))):
        raise ConformanceError("SEMANTIC_SET_DUPLICATE")
    return [value for _, value in encoded]


def schema_validate(bundle, definition, record):
    check_value(record)
    wrapper = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": bundle["$defs"],
        "$ref": f"#/$defs/{definition}",
    }
    jsonschema.Draft202012Validator(wrapper, format_checker=jsonschema.FormatChecker()).validate(record)


def discovery_authority_invariants(record):
    rows = record["expected_sources"]
    for index, row in enumerate(rows):
        if row["ordinal"] != index:
            raise ConformanceError("DISCOVERY_AUTHORITY_ORDER_INVALID")
        if row["precedence_rank"] != SOURCE_ORDER[row["source_kind"]]:
            raise ConformanceError("DISCOVERY_AUTHORITY_RANK_INVALID")
    expected = sorted(
        rows,
        key=lambda row: (
            row["precedence_rank"],
            SOURCE_ORDER[row["source_kind"]],
            canonical_bytes(row["source_id"]),
        ),
    )
    if rows != expected:
        raise ConformanceError("DISCOVERY_AUTHORITY_ORDER_INVALID")
    ids = [row["source_id"] for row in rows]
    realpaths = [
        row["canonical_realpath_digest"]
        for row in rows
        if row["canonical_realpath_digest"] is not None
    ]
    if len(ids) != len(set(ids)):
        raise ConformanceError("DISCOVERY_AUTHORITY_SOURCE_DUPLICATE")
    if len(realpaths) != len(set(realpaths)):
        raise ConformanceError("DISCOVERY_AUTHORITY_PATH_ALIAS")
    if record["customization_registry_digest"] != (
        expected_customization_registry_digest()
    ):
        raise ConformanceError("DISCOVERY_AUTHORITY_REGISTRY_MISMATCH")


def customization_invariants(record):
    rows = record["rows"]
    if (
        record["customization_registry_digest"]
        != expected_customization_registry_digest()
    ):
        raise ConformanceError("CUSTOMIZATION_REGISTRY_MISMATCH")
    if record["expected_row_count"] != len(rows):
        raise ConformanceError("CUSTOMIZATION_COVERAGE_INVALID")
    for index, row in enumerate(rows):
        if row["ordinal"] != index:
            raise ConformanceError("CUSTOMIZATION_ORDER_INVALID")
        if row["precedence_rank"] != SOURCE_ORDER[row["source_kind"]]:
            raise ConformanceError("CUSTOMIZATION_PRECEDENCE_RANK_INVALID")
    expected = sorted(
        rows,
        key=lambda row: (
            row["precedence_rank"],
            SOURCE_ORDER[row["source_kind"]],
            canonical_bytes(row["source_id"]),
        ),
    )
    if rows != expected:
        raise ConformanceError("CUSTOMIZATION_ORDER_INVALID")
    ids = [row["source_id"] for row in rows]
    realpaths = [
        row["canonical_realpath_digest"]
        for row in rows
        if row["canonical_realpath_digest"] is not None
    ]
    if len(ids) != len(set(ids)):
        raise ConformanceError("CUSTOMIZATION_SOURCE_DUPLICATE")
    if len(realpaths) != len(set(realpaths)):
        raise ConformanceError("CUSTOMIZATION_PATH_ALIAS")
    for row in rows:
        result = row["scan_result"]
        if result in {"ABSENT", "NOT_APPLICABLE"}:
            expected_values = (
                row["loaded"] is False
                and row["canonical_realpath_digest"] is None
                and row["content_digest"] is None
                and row["declared_effort"] is None
                and row["thinking_controls_digest"] is None
            )
            if not expected_values:
                raise ConformanceError("CUSTOMIZATION_ROW_STATE_INVALID")
        elif result == "UNREADABLE":
            if (
                row["loaded"]
                or row["content_digest"] is not None
                or row["declared_effort"] is not None
                or row["thinking_controls_digest"] is not None
            ):
                raise ConformanceError("CUSTOMIZATION_ROW_STATE_INVALID")
        elif result == "PRESENT_SHADOWED":
            if (
                row["loaded"]
                or row["content_digest"] is None
                or (
                    row["declared_effort"] is None
                    and row["thinking_controls_digest"] is None
                )
            ):
                raise ConformanceError("CUSTOMIZATION_ROW_STATE_INVALID")
        else:
            if (
                not row["loaded"]
                or row["content_digest"] is None
                or (
                    row["declared_effort"] is None
                    and row["thinking_controls_digest"] is None
                )
            ):
                raise ConformanceError("CUSTOMIZATION_ROW_STATE_INVALID")
        if row["row_digest"] != digest_record(row, "row_digest"):
            raise ConformanceError("CUSTOMIZATION_ROW_DIGEST_MISMATCH")
    if record["customization_set_digest"] != digest_record(
        record, "customization_set_digest"
    ):
        raise ConformanceError("CUSTOMIZATION_SET_DIGEST_MISMATCH")
    if record["discovery_manifest_digest"] != customization_discovery_digest(
        record
    ):
        raise ConformanceError("CUSTOMIZATION_DISCOVERY_DIGEST_MISMATCH")


def ledger_invariants(record):
    for key in (
        "generation_entry_digests",
        "attempt_entry_digests",
        "event_digests",
    ):
        if record[key] != semantic_set(record[key]):
            raise ConformanceError("LEDGER_SET_ORDER_INVALID")
    summed = {
        field: (
            record["active_reserved"][field]
            + record["reconciled"][field]
            + record["remaining"][field]
        )
        for field in VECTOR_FIELDS
    }
    if summed != record["grant"]:
        raise ConformanceError("LEDGER_CONSERVATION_INVALID")
    currency_values = [
        record[name]["currency_micros"]
        for name in ("grant", "active_reserved", "reconciled", "remaining")
    ]
    if record["currency_code"] is None:
        if any(currency_values):
            raise ConformanceError("LEDGER_CURRENCY_WITHOUT_CODE")
    elif record["grant"]["currency_micros"] == 0:
        raise ConformanceError("LEDGER_CURRENCY_CODE_WITHOUT_GRANT")
    if record["ledger_revision"] == 0:
        expected = {
            "previous_ledger_digest": None,
            "ledger_state": "ACTIVE",
            "active_reserved": zero_vector(),
            "reconciled": zero_vector(),
            "remaining": record["grant"],
            "generation_entry_digests": [],
            "attempt_entry_digests": [],
            "event_digests": [],
            "last_event_sequence": None,
            "last_event_digest": None,
        }
        if any(record[key] != value for key, value in expected.items()):
            raise ConformanceError("LEDGER_GENESIS_INVALID")
    else:
        if record["previous_ledger_digest"] is None:
            raise ConformanceError("LEDGER_PREVIOUS_SNAPSHOT_MISSING")
        if record["last_event_sequence"] != record["ledger_revision"] - 1:
            raise ConformanceError("LEDGER_LAST_SEQUENCE_INVALID")
        if record["last_event_digest"] is None:
            raise ConformanceError("LEDGER_LAST_EVENT_MISSING")
        if len(record["event_digests"]) != record["ledger_revision"]:
            raise ConformanceError("LEDGER_EVENT_COUNT_INVALID")
        if record["last_event_digest"] not in record["event_digests"]:
            raise ConformanceError("LEDGER_LAST_EVENT_NOT_MEMBER")


def generation_entry_invariants(record):
    accounted = vec_add(
        record["unallocated_reservation"],
        record["reconciled_use"],
    )
    if not vec_le(accounted, record["generation_reservation"]):
        raise ConformanceError("GENERATION_ENTRY_ACCOUNTING_INVALID")
    if record["entry_state"] == "RESERVED" and (
        record["unallocated_reservation"]
        != record["generation_reservation"]
        or record["reconciled_use"] != zero_vector()
    ):
        raise ConformanceError("GENERATION_ENTRY_STATE_INVALID")


def safe_sum(values):
    total = 0
    for value in values:
        total += value
        if total > MAX_SAFE:
            raise ConformanceError("TOKEN_ARITHMETIC_OVERFLOW")
    return total


def token_derivation_invariants(record):
    reserved = safe_sum(
        (
            record["reserved_system_tokens"],
            record["reserved_tool_tokens"],
            record["reserved_output_tokens"],
        )
    )
    if reserved > record["context_window_tokens"]:
        raise ConformanceError("TOKEN_CONTEXT_RESERVATION_UNDERFLOW")
    usable_context = record["context_window_tokens"] - reserved
    grant = record["derived_token_grant"]
    input_total = safe_sum(
        (
            grant["uncached_input_tokens"],
            grant["cache_write_tokens"],
            grant["cached_input_tokens"],
        )
    )
    input_limit = min(
        record["maximum_input_tokens"],
        usable_context,
        record["request_input_ceiling_tokens"],
    )
    if input_total > input_limit:
        raise ConformanceError("TOKEN_INPUT_GRANT_EXCEEDS_LIMIT")
    output_limit = min(
        record["maximum_output_tokens"],
        record["request_output_ceiling_tokens"],
        record["reserved_output_tokens"],
    )
    if grant["output_tokens_including_reasoning"] > output_limit:
        raise ConformanceError("TOKEN_OUTPUT_GRANT_EXCEEDS_LIMIT")
    if (
        grant["reasoning_tokens_subset"]
        > grant["output_tokens_including_reasoning"]
    ):
        raise ConformanceError("REASONING_SUBSET_MISMATCH")


def observation_invariants(record):
    evidence = record["thinking_observation_evidence_digest"]
    if record["observed_thinking_state"] == "NOT_APPLICABLE":
        if evidence is not None:
            raise ConformanceError("OBSERVATION_THINKING_EVIDENCE_FORBIDDEN")
    elif evidence is None:
        raise ConformanceError("OBSERVATION_THINKING_EVIDENCE_REQUIRED")


def provider_control_vector_invariants(record):
    mode = record["requested_thinking_mode"]
    manual_budget = record["manual_thinking_budget_tokens"]
    if mode == "ADAPTIVE_ON":
        if record["exact_model_id"] not in {
            "claude-opus-5",
            "claude-sonnet-5",
        }:
            raise ConformanceError("CONTROL_VECTOR_MODEL_MODE_MISMATCH")
        if manual_budget is not None:
            raise ConformanceError("CONTROL_VECTOR_MANUAL_BUDGET_FORBIDDEN")
    elif mode == "MANUAL_ON":
        if record["exact_model_id"] != "claude-haiku-4-5":
            raise ConformanceError("CONTROL_VECTOR_MODEL_MODE_MISMATCH")
        if manual_budget is None:
            raise ConformanceError("CONTROL_VECTOR_MANUAL_BUDGET_REQUIRED")
    else:
        if record["exact_model_id"] != "claude-haiku-4-5":
            raise ConformanceError("CONTROL_VECTOR_MODEL_MODE_MISMATCH")
        if manual_budget is not None:
            raise ConformanceError("CONTROL_VECTOR_MANUAL_BUDGET_FORBIDDEN")


def effort_authority_invariants(record):
    if record["authority_result"] != "SEALED":
        return
    if record["exact_model_id"] in {"claude-opus-5", "claude-sonnet-5"}:
        if record["requested_effort"] == "not_applicable":
            raise ConformanceError("EFFORT_MODEL_REQUEST_MISMATCH")
        if record["organization_cap_state"] != "KNOWN_PERMITS_REQUEST":
            raise ConformanceError("EFFORT_ORGANIZATION_CAP_UNSEALED")
        if (
            record["environment_effort"] != record["requested_effort"]
            or record["cli_effort"] != record["requested_effort"]
        ):
            raise ConformanceError("EFFORT_CONTROL_PROJECTION_MISMATCH")
    elif record["exact_model_id"] == "claude-haiku-4-5":
        if (
            record["requested_effort"] != "not_applicable"
            or record["organization_cap_state"] != "NOT_APPLICABLE"
            or record["environment_effort"] is not None
            or record["cli_effort"] is not None
        ):
            raise ConformanceError("EFFORT_MODEL_REQUEST_MISMATCH")
    else:
        raise ConformanceError("EFFORT_MODEL_REQUEST_MISMATCH")


def proof_rule_authority_invariants(record):
    rows = record["ordered_field_rules"]
    expected = sorted(
        rows, key=lambda row: canonical_bytes(row["manifest_field"])
    )
    if rows != expected:
        raise ConformanceError("CANARY_PROOF_RULE_AUTHORITY_ORDER_INVALID")
    fields = [row["manifest_field"] for row in rows]
    if len(fields) != len(set(fields)):
        raise ConformanceError("CANARY_PROOF_RULE_FIELD_DUPLICATE")
    for row in rows:
        if row["allowed_proof_rule_ids"] != semantic_set(
            row["allowed_proof_rule_ids"]
        ):
            raise ConformanceError("CANARY_PROOF_RULE_SET_ORDER_INVALID")


def canary_plan_invariants(record):
    if record["required_case_ids"] != semantic_set(
        record["required_case_ids"]
    ):
        raise ConformanceError("CANARY_PLAN_REQUIRED_CASE_ORDER_INVALID")


def thinking_authority_invariants(record):
    rows = record["ordered_controls"]
    row_count = record["customization_row_count"]
    expected_pairs = [
        (source_ordinal, control)
        for source_ordinal in range(row_count)
        for control in THINKING_CONTROLS
    ]
    observed_pairs = [
        (row["customization_row_ordinal"], row["control_name"]) for row in rows
    ]
    if observed_pairs != expected_pairs:
        raise ConformanceError("THINKING_CONTROL_COVERAGE_INVALID")
    for ordinal, row in enumerate(rows):
        if row["ordinal"] != ordinal:
            raise ConformanceError("THINKING_CONTROL_ORDER_INVALID")
        expected_source_ordinal = ordinal // len(THINKING_CONTROLS)
        if row["customization_row_ordinal"] != expected_source_ordinal:
            raise ConformanceError("THINKING_CONTROL_SOURCE_JOIN_INVALID")
        group = rows[
            expected_source_ordinal * len(THINKING_CONTROLS):
            (expected_source_ordinal + 1) * len(THINKING_CONTROLS)
        ]
        if any(
            item["source_kind"] != group[0]["source_kind"]
            or item["source_id"] != group[0]["source_id"]
            or item["customization_row_digest"]
            != group[0]["customization_row_digest"]
            for item in group
        ):
            raise ConformanceError("THINKING_CONTROL_SOURCE_JOIN_INVALID")
        if row["state"] == "PROVEN_ABSENT" and row["serialized_value"] is not None:
            raise ConformanceError("THINKING_ABSENCE_VALUE_INVALID")
        if row["state"] == "EXPLICIT" and row["serialized_value"] is None:
            raise ConformanceError("THINKING_EXPLICIT_VALUE_MISSING")
    if record["authority_result"] != "SEALED":
        return
    if any(row["state"] in {"CONFLICT", "UNREADABLE"} for row in rows):
        raise ConformanceError("THINKING_CONTROL_CONFLICT")
    mode = record["requested_thinking_mode"]
    if mode == "ADAPTIVE_ON":
        if record["exact_model_id"] not in {"claude-opus-5", "claude-sonnet-5"}:
            raise ConformanceError("THINKING_MODEL_MODE_INVALID")
        if record["manual_thinking_budget_tokens"] is not None:
            raise ConformanceError("THINKING_MANUAL_BUDGET_FORBIDDEN")
        target = ("CONTROL_REQUEST", "ADAPTIVE_THINKING")
        target_value = True
    elif mode == "MANUAL_ON":
        if record["exact_model_id"] != "claude-haiku-4-5":
            raise ConformanceError("THINKING_MODEL_MODE_INVALID")
        if record["manual_thinking_budget_tokens"] is None:
            raise ConformanceError("THINKING_MANUAL_BUDGET_REQUIRED")
        target = ("CONTROL_REQUEST", "MANUAL_THINKING_BUDGET")
        target_value = record["manual_thinking_budget_tokens"]
    else:
        if record["exact_model_id"] != "claude-haiku-4-5":
            raise ConformanceError("THINKING_MODEL_MODE_INVALID")
        if record["manual_thinking_budget_tokens"] is not None:
            raise ConformanceError("THINKING_MANUAL_BUDGET_FORBIDDEN")
        target = None
        target_value = None
    explicit_targets = [
        row
        for row in rows
        if target is not None
        and (row["source_kind"], row["control_name"]) == target
        and row["state"] == "EXPLICIT"
        and row["serialized_value"] == target_value
    ]
    if target is not None and len(explicit_targets) != 1:
        raise ConformanceError("THINKING_TARGET_CONTROL_INVALID")
    for row in rows:
        if row in explicit_targets:
            continue
        if row["state"] != "PROVEN_ABSENT" or row["serialized_value"] is not None:
            raise ConformanceError("THINKING_COMPETING_CONTROL_PRESENT")


def pair_comparison_invariants(record):
    currency_fields = (
        record["currency_code"],
        record["candidate_pricing_snapshot_digest"],
        record["legacy_pricing_snapshot_digest"],
    )
    if record["metric"] == "CURRENCY_MICROS":
        if any(value is None for value in currency_fields):
            raise ConformanceError("PAIR_CURRENCY_AUTHORITY_MISSING")
        if (
            record["candidate_pricing_snapshot_digest"]
            != record["legacy_pricing_snapshot_digest"]
        ):
            raise ConformanceError("PAIR_PRICING_SNAPSHOT_MISMATCH")
    elif any(value is not None for value in currency_fields):
        raise ConformanceError("PAIR_NONCURRENCY_AUTHORITY_PRESENT")
    ratio_state_invariants(record)


def utilization_invariants(record):
    expected = {
        "ATTEMPT": "ATTEMPT_RESOURCE_ENTRY",
        "GENERATION": "GENERATION_RESOURCE_ENTRY",
        "ARM_FAMILY": "FAMILY_LEDGER",
    }
    if expected[record["aggregation_scope"]] != record["denominator_authority_type"]:
        raise ConformanceError("UTILIZATION_SCOPE_AUTHORITY_MISMATCH")
    ratio_state_invariants(record)


def ratio_state_invariants(record):
    numerator = record["numerator"]
    denominator = record["denominator"]
    state = record["ratio_state"]
    if state == "FINITE" and denominator == 0:
        raise ConformanceError("RATIO_STATE_VALUE_MISMATCH")
    if state == "NO_NUMERATOR_OR_DENOMINATOR_USE" and (
        numerator != 0 or denominator != 0
    ):
        raise ConformanceError("RATIO_STATE_VALUE_MISMATCH")
    if state == "UNBOUNDED_REQUIRES_REVIEW" and (
        numerator == 0 or denominator != 0
    ):
        raise ConformanceError("RATIO_STATE_VALUE_MISMATCH")
    if state == "UNOBSERVABLE" and (numerator != 0 or denominator != 0):
        raise ConformanceError("RATIO_STATE_VALUE_MISMATCH")


def validate_canonical_vectors(vectors):
    count = 0
    for case in vectors["canonical_vectors"]:
        if "semantic_set" in case:
            value = semantic_set(case["semantic_set"])
        else:
            value = case["value"]
        actual = canonical_bytes(value)
        if actual.hex() != case["expected_utf8_hex"]:
            raise ConformanceError(f"CANONICAL_BYTES_MISMATCH:{case['id']}")
        if hashlib.sha256(actual).hexdigest() != case["expected_sha256"]:
            raise ConformanceError(f"CANONICAL_HASH_MISMATCH:{case['id']}")
        count += 1
    for case in vectors["negative_canonical_vectors"]:
        try:
            if "raw_json" in case:
                value = parse_json_text(case["raw_json"])
            else:
                value = case.get("value", case.get("identity_value"))
            check_value(value)
        except ConformanceError as exc:
            if exc.code != case["expected_error"]:
                raise
        else:
            raise ConformanceError(f"NEGATIVE_CANONICAL_ACCEPTED:{case['id']}")
        count += 1
    return count


def classify_schema_error(error):
    if error.validator == "required":
        return "SCHEMA_REQUIRED_FIELD"
    if error.validator in {"additionalProperties", "unevaluatedProperties"}:
        return "SCHEMA_UNKNOWN_FIELD"
    return "SCHEMA_VALIDATION_ERROR"


def validate_schema_vectors(bundle, vectors):
    count = 0
    for case in vectors["schema_vectors"]:
        record = materialize_self_digests(expand(case["record"]))
        try:
            schema_validate(bundle, case["definition"], record)
            if case["definition"] == "LoadedCustomizationSetV1":
                customization_invariants(record)
            if case["definition"] == "CustomizationDiscoveryAuthorityV1":
                discovery_authority_invariants(record)
            if case["definition"] == "BackendSemanticResourceLedgerV2":
                ledger_invariants(record)
            if case["definition"] == "GenerationResourceEntryV2":
                generation_entry_invariants(record)
            if case["definition"] == "TokenBudgetDerivationV2":
                token_derivation_invariants(record)
            if case["definition"] == "ProviderExecutionObservationV4":
                observation_invariants(record)
            if case["definition"] == "ClaudeProviderControlVectorV1":
                provider_control_vector_invariants(record)
            if case["definition"] == "ClaudeEffortAuthorityV3":
                effort_authority_invariants(record)
            if case["definition"] == "ClaudeThinkingAuthorityV1":
                thinking_authority_invariants(record)
            if case["definition"] in {
                "ReservedPairResourceComparisonV1",
                "ObservedPairResourceComparisonV1",
            }:
                pair_comparison_invariants(record)
            if case["definition"] == "ObservedToGrantUtilizationV1":
                utilization_invariants(record)
            if case.get("check_self_digest"):
                field = SELF_DIGEST_FIELDS[case["definition"]]
                if record[field] != digest_record(record, field):
                    raise ConformanceError("RECORD_SELF_DIGEST_MISMATCH")
        except jsonschema.ValidationError as exc:
            code = classify_schema_error(exc)
        except ConformanceError as exc:
            code = exc.code
        else:
            code = None
        if case["valid"] and code is not None:
            raise ConformanceError(f"VALID_SCHEMA_REJECTED:{case['id']}:{code}")
        if not case["valid"] and code != case["expected_error"]:
            raise ConformanceError(
                f"NEGATIVE_SCHEMA_WRONG_RESULT:{case['id']}:{code}"
            )
        count += 1
    return count


def validate_join_vectors(vectors):
    count = 0
    for raw_case in vectors["join_vectors"]:
        case = materialize_self_digests(expand(raw_case))
        code = None
        if case["kind"] == "CUSTOMIZATION_JOIN":
            join = case["records"]
            try:
                schema_validate(
                    load_ascii(SCHEMA_PATH),
                    "CustomizationDiscoveryAuthorityV1",
                    join["discovery_authority"],
                )
                if join["discovery_authority"][
                    "discovery_authority_digest"
                ] != digest_record(
                    join["discovery_authority"],
                    "discovery_authority_digest",
                ):
                    raise ConformanceError(
                        "DISCOVERY_AUTHORITY_DIGEST_MISMATCH"
                    )
                discovery_authority_invariants(
                    join["discovery_authority"]
                )
                customization_invariants(join["set_record"])
            except ConformanceError as exc:
                code = exc.code
            except jsonschema.ValidationError as exc:
                code = classify_schema_error(exc)
            authority = join["discovery_authority"]
            if code is None and (
                join["set_record"]["discovery_authority_digest"]
                != authority["discovery_authority_digest"]
                or join["set_record"]["resolution_root_digest"]
                != authority["resolution_root_digest"]
                or join["set_record"]["customization_registry_digest"]
                != authority["customization_registry_digest"]
                or customization_source_projection(
                    join["set_record"]["rows"]
                )
                != authority["expected_sources"]
            ):
                code = "CUSTOMIZATION_DISCOVERY_AUTHORITY_MISMATCH"
            actual_digest = join["set_record"]["customization_set_digest"]
            if code is None and len(
                {
                    actual_digest,
                    join["effort_digest"],
                    join["thinking_digest"],
                    join["launch_digest"],
                }
            ) != 1:
                code = "CUSTOMIZATION_DIGEST_MISMATCH"
            expected_projection = [
                {
                    "ordinal": row["ordinal"],
                    "source_kind": row["source_kind"],
                    "source_id": row["source_id"],
                    "row_digest": row["row_digest"],
                }
                for row in join["set_record"]["rows"]
            ]
            if code is None and (
                join["thinking_customization_row_count"]
                != len(expected_projection)
                or join["thinking_projection"] != expected_projection
            ):
                code = "THINKING_CUSTOMIZATION_PROJECTION_MISMATCH"
        elif case["kind"] == "TOKEN_BUDGET_JOIN":
            if case["derived"] != case["budget"]:
                code = "TOKEN_BUDGET_DERIVATION_MISMATCH"
            elif case["budget"]["reasoning_tokens_subset"] > case["budget"]["output_tokens_including_reasoning"]:
                code = "REASONING_SUBSET_MISMATCH"
        elif case["kind"] == "GENERATION_RESERVATION_JOIN":
            records = case["records"]
            derivation = records["derivation"]
            budget = records["budget"]
            prestate = records["prestate"]
            event = records["reservation_event"]
            typed = (
                (
                    "TokenBudgetDerivationV2",
                    derivation,
                    "token_derivation_digest",
                ),
                ("BudgetAuthorityV3", budget, "budget_authority_digest"),
                (
                    "BackendSemanticResourceLedgerV2",
                    prestate,
                    "resource_ledger_digest",
                ),
                (
                    "ResourceLedgerEventV2",
                    event,
                    "ledger_event_digest",
                ),
            )
            try:
                for definition, record, digest_field in typed:
                    schema_validate(
                        load_ascii(SCHEMA_PATH), definition, record
                    )
                    if record[digest_field] != digest_record(
                        record, digest_field
                    ):
                        raise ConformanceError(
                            "GENERATION_RESERVATION_RECORD_DIGEST_MISMATCH"
                        )
                token_derivation_invariants(derivation)
                ledger_invariants(prestate)
            except (jsonschema.ValidationError, ConformanceError) as exc:
                code = (
                    exc.code
                    if isinstance(exc, ConformanceError)
                    else classify_schema_error(exc)
                )
            if code is None and (
                budget["token_budget_derivation_digest"]
                != derivation["token_derivation_digest"]
                or budget["token_grant"]
                != derivation["derived_token_grant"]
                or budget["requested_family_reservation"][
                    "source_payload_bytes"
                ]
                != derivation["source_payload_bytes"]
                or budget["requested_family_reservation"][
                    "output_artifact_bytes"
                ]
                != derivation["output_artifact_bytes_reservation"]
            ):
                code = "GENERATION_RESERVATION_DERIVATION_MISMATCH"
            if code is None and (
                event["budget_authority_digest"]
                != budget["budget_authority_digest"]
            ):
                code = "GENERATION_RESERVATION_BUDGET_MISMATCH"
            if code is None and (
                event["token_budget_derivation_digest"]
                != derivation["token_derivation_digest"]
                or event["arm_family_digest"] != budget["arm_family_digest"]
                or event["generation"] != budget["generation"]
                or prestate["arm_family_digest"]
                != budget["arm_family_digest"]
            ):
                code = "GENERATION_RESERVATION_IDENTITY_MISMATCH"
            if code is None and (
                prestate["semantic_plan_digest"]
                != budget["semantic_plan_digest"]
            ):
                code = "GENERATION_RESERVATION_PLAN_MISMATCH"
            if code is None and (
                prestate["common_resource_grant_digest"]
                != budget["common_resource_grant_digest"]
            ):
                code = "GENERATION_RESERVATION_COMMON_GRANT_MISMATCH"
            if code is None and (
                budget["resource_ledger_digest_at_compile"]
                != prestate["resource_ledger_digest"]
                or event["expected_ledger_revision"]
                != prestate["ledger_revision"]
            ):
                code = "GENERATION_RESERVATION_LEDGER_MISMATCH"
            if code is None and (
                event["event_sequence"] != prestate["ledger_revision"]
            ):
                code = "GENERATION_RESERVATION_EVENT_SEQUENCE_MISMATCH"
            if code is None and (
                event["previous_event_digest"]
                != prestate["last_event_digest"]
            ):
                code = "GENERATION_RESERVATION_PREVIOUS_EVENT_MISMATCH"
            if code is None and (
                event["reservation_delta"]
                != budget["requested_family_reservation"]
            ):
                code = "GENERATION_RESERVATION_DELTA_MISMATCH"
            if code is None and not vec_le(
                event["reservation_delta"], prestate["remaining"]
            ):
                code = "GENERATION_RESERVATION_EXCEEDS_REMAINING"
            money = event["reservation_delta"]["currency_micros"]
            if code is None and (
                (prestate["currency_code"] is None and money != 0)
                or (prestate["currency_code"] is not None and money == 0)
            ):
                code = "GENERATION_RESERVATION_CURRENCY_MISMATCH"
        elif case["kind"] == "ATTEMPT_RESERVATION_JOIN":
            row = case["records"]
            if (
                len(
                    {
                        row["envelope_attempt"],
                        row["event_attempt"],
                        row["entry_attempt"],
                        row["observation_attempt"],
                        row["reconciliation_event_attempt"],
                        row["reconciled_entry_attempt"],
                    }
                )
                != 1
                or len(
                    {
                        row["envelope_generation"],
                        row["event_generation"],
                        row["entry_generation"],
                        row["observation_generation"],
                        row["reconciliation_event_generation"],
                        row["reconciled_entry_generation"],
                    }
                )
                != 1
                or len(
                    {
                        row["envelope_arm"],
                        row["event_arm"],
                        row["entry_arm"],
                        row["observation_arm"],
                        row["reconciliation_event_arm"],
                        row["reconciled_entry_arm"],
                    }
                )
                != 1
            ):
                code = "ATTEMPT_RESERVATION_IDENTITY_MISMATCH"
            elif len(
                {
                    row["envelope_reservation_event_digest"],
                    row["event_digest"],
                    row["observation_reservation_event_digest"],
                }
            ) != 1:
                code = "ATTEMPT_RESERVATION_EVENT_MISMATCH"
            elif len(
                {
                    row["envelope_entry_digest"],
                    row["entry_digest"],
                    row["observation_reserved_entry_digest"],
                }
            ) != 1:
                code = "ATTEMPT_RESOURCE_ENTRY_MISMATCH"
            elif (
                row["observation_consumed_entry_digest"]
                != row["launch_consumed_entry_digest"]
            ):
                code = "ATTEMPT_CONSUMED_RESOURCE_ENTRY_MISMATCH"
            elif len(
                {
                    row["launch_budget_digest"],
                    row["event_budget_digest"],
                    row["entry_budget_digest"],
                    row["observation_budget_digest"],
                    row["reconciliation_event_budget_digest"],
                    row["reconciled_entry_budget_digest"],
                }
            ) != 1 or len(
                {
                    row["launch_derivation_digest"],
                    row["event_derivation_digest"],
                    row["entry_derivation_digest"],
                    row["observation_derivation_digest"],
                    row["reconciliation_event_derivation_digest"],
                    row["reconciled_entry_derivation_digest"],
                }
            ) != 1:
                code = "ATTEMPT_BUDGET_DERIVATION_MISMATCH"
            elif row["event_allocation"] != row["entry_allocation"]:
                code = "ATTEMPT_ALLOCATION_MISMATCH"
            elif len(
                {
                    row["event_post_reservation_ledger"],
                    row["envelope_post_reservation_ledger"],
                    row["observation_post_reservation_ledger"],
                }
            ) != 1:
                code = "ATTEMPT_RESERVATION_LEDGER_MISMATCH"
            elif len(
                {
                    row["envelope_digest"],
                    row["consumption_launch_digest"],
                    row["observation_envelope_digest"],
                }
            ) != 1:
                code = "ATTEMPT_LAUNCH_CONSUMPTION_MISMATCH"
            elif (
                row["consumption_event_digest"]
                != row["observation_consumption_event_digest"]
            ):
                code = "ATTEMPT_CONSUMPTION_EVENT_MISMATCH"
            elif (
                row["post_consumption_ledger"]
                != row["observation_post_consumption_ledger"]
            ):
                code = "ATTEMPT_CONSUMPTION_LEDGER_MISMATCH"
            elif (
                row["reconciled_entry_previous_digest"]
                != row["launch_consumed_entry_digest"]
                or row["reconciliation_event_entry_digest"]
                != row["reconciled_entry_digest"]
            ):
                code = "ATTEMPT_RECONCILIATION_ENTRY_MISMATCH"
            elif (
                row["reconciled_entry_allocation"]
                != row["entry_allocation"]
            ):
                code = "ATTEMPT_RECONCILIATION_ALLOCATION_MISMATCH"
            elif (
                row["reconciliation_event_use"]
                != row["reconciled_entry_use"]
            ):
                code = "ATTEMPT_RECONCILIATION_USE_MISMATCH"
            elif not vec_le(
                row["reconciled_entry_use"],
                row["entry_allocation"],
            ):
                code = "ATTEMPT_RECONCILIATION_USE_EXCEEDS_ALLOCATION"
            elif len(
                {
                    row["envelope_digest"],
                    row["reconciliation_event_launch_digest"],
                    row["reconciled_entry_launch_digest"],
                }
            ) != 1:
                code = "ATTEMPT_RECONCILIATION_LAUNCH_MISMATCH"
        elif case["kind"] == "ATTEMPT_ENTRY_LIFECYCLE":
            records = case["records"]
            typed = (
                (
                    "GenerationResourceEntryV2",
                    records["generation_reserved_entry"],
                    "generation_entry_digest",
                ),
                (
                    "GenerationResourceEntryV2",
                    records["generation_active_entry"],
                    "generation_entry_digest",
                ),
                (
                    "GenerationResourceEntryV2",
                    records["generation_reconciled_entry"],
                    "generation_entry_digest",
                ),
                (
                    "AttemptResourceEntryV2",
                    records["reserved_entry"],
                    "attempt_entry_digest",
                ),
                (
                    "ResourceLedgerEventV2",
                    records["reserve_event"],
                    "ledger_event_digest",
                ),
                (
                    "BackendSemanticResourceLedgerV2",
                    records["post_reservation_ledger"],
                    "resource_ledger_digest",
                ),
                (
                    "AttemptLaunchEnvelopeV2",
                    records["envelope"],
                    "attempt_launch_digest",
                ),
                (
                    "AttemptResourceEntryV2",
                    records["consumed_entry"],
                    "attempt_entry_digest",
                ),
                (
                    "ResourceLedgerEventV2",
                    records["consume_event"],
                    "ledger_event_digest",
                ),
                (
                    "BackendSemanticResourceLedgerV2",
                    records["post_consumption_ledger"],
                    "resource_ledger_digest",
                ),
                (
                    "ProviderExecutionObservationV4",
                    records["observation"],
                    "observation_digest",
                ),
                (
                    "AttemptResourceEntryV2",
                    records["reconciled_entry"],
                    "attempt_entry_digest",
                ),
                (
                    "ResourceLedgerEventV2",
                    records["reconcile_event"],
                    "ledger_event_digest",
                ),
                (
                    "BackendSemanticResourceLedgerV2",
                    records["post_reconciliation_ledger"],
                    "resource_ledger_digest",
                ),
            )
            try:
                for definition, record, digest_field in typed:
                    schema_validate(
                        load_ascii(SCHEMA_PATH), definition, record
                    )
                    if record[digest_field] != digest_record(
                        record, digest_field
                    ):
                        raise ConformanceError(
                            "ATTEMPT_ENTRY_RECORD_DIGEST_MISMATCH"
                        )
                observation_invariants(records["observation"])
                for generation_record in (
                    records["generation_reserved_entry"],
                    records["generation_active_entry"],
                    records["generation_reconciled_entry"],
                ):
                    generation_entry_invariants(generation_record)
                ledger_invariants(records["post_reservation_ledger"])
                ledger_invariants(records["post_consumption_ledger"])
                ledger_invariants(records["post_reconciliation_ledger"])
            except (jsonschema.ValidationError, ConformanceError) as exc:
                code = (
                    exc.code
                    if isinstance(exc, ConformanceError)
                    else classify_schema_error(exc)
                )
            reserved = records["reserved_entry"]
            consumed = records["consumed_entry"]
            reconciled = records["reconciled_entry"]
            reserve_event = records["reserve_event"]
            consume_event = records["consume_event"]
            reconcile_event = records["reconcile_event"]
            envelope = records["envelope"]
            observation = records["observation"]
            post_reservation_ledger = records["post_reservation_ledger"]
            post_consumption_ledger = records["post_consumption_ledger"]
            post_reconciliation_ledger = records[
                "post_reconciliation_ledger"
            ]
            generation_reserved = records["generation_reserved_entry"]
            generation_active = records["generation_active_entry"]
            generation_reconciled = records[
                "generation_reconciled_entry"
            ]
            identity_rows = (
                reserved,
                consumed,
                reconciled,
                reserve_event,
                consume_event,
                reconcile_event,
            )
            if code is None and (
                len(
                    {
                        row["arm_family_digest"]
                        for row in identity_rows
                    }
                )
                != 1
                or len({row["generation"] for row in identity_rows}) != 1
                or len(
                    {
                        row["attempt_identity_digest"]
                        for row in identity_rows
                    }
                )
                != 1
                or len(
                    {
                        row["budget_authority_digest"]
                        for row in identity_rows
                    }
                )
                != 1
                or len(
                    {
                        row["token_budget_derivation_digest"]
                        for row in identity_rows
                    }
                )
                != 1
            ):
                code = "ATTEMPT_ENTRY_IDENTITY_MISMATCH"
            if code is None and (
                reserved["generation_entry_digest"]
                != generation_active["generation_entry_digest"]
                or consumed["generation_entry_digest"]
                != generation_active["generation_entry_digest"]
                or reconciled["generation_entry_digest"]
                != generation_reconciled["generation_entry_digest"]
                or any(
                    row["arm_family_digest"]
                    != generation_active["arm_family_digest"]
                    or row["generation"]
                    != generation_active["generation"]
                    or row["budget_authority_digest"]
                    != generation_active["budget_authority_digest"]
                    for row in identity_rows
                )
                or any(
                    generation["arm_family_digest"]
                    != generation_active["arm_family_digest"]
                    or generation["generation"]
                    != generation_active["generation"]
                    or generation["budget_authority_digest"]
                    != generation_active["budget_authority_digest"]
                    for generation in (
                        generation_reserved,
                        generation_reconciled,
                    )
                )
            ):
                code = "ATTEMPT_GENERATION_ENTRY_JOIN_MISMATCH"
            if code is None and (
                generation_reserved["previous_generation_entry_digest"]
                is not None
                or generation_active["previous_generation_entry_digest"]
                != generation_reserved["generation_entry_digest"]
                or generation_reconciled[
                    "previous_generation_entry_digest"
                ]
                != generation_active["generation_entry_digest"]
            ):
                code = "ATTEMPT_GENERATION_ENTRY_PREDECESSOR_MISMATCH"
            if code is None and (
                reserved["previous_attempt_entry_digest"] is not None
                or consumed["previous_attempt_entry_digest"]
                != reserved["attempt_entry_digest"]
                or reconciled["previous_attempt_entry_digest"]
                != consumed["attempt_entry_digest"]
            ):
                code = "ATTEMPT_ENTRY_PREDECESSOR_MISMATCH"
            if code is None and (
                reserved["attempt_allocation"]
                != consumed["attempt_allocation"]
                or reserved["attempt_allocation"]
                != reconciled["attempt_allocation"]
            ):
                code = "ATTEMPT_ENTRY_ALLOCATION_MISMATCH"
            if code is None and (
                reserve_event["reservation_delta"]
                != reserved["attempt_allocation"]
                or reconcile_event["reconciliation_delta"]
                != reconciled["reconciled_use"]
            ):
                code = "ATTEMPT_ENTRY_EVENT_VECTOR_MISMATCH"
            if code is None and not vec_le(
                reconciled["reconciled_use"],
                reserved["attempt_allocation"],
            ):
                code = "ATTEMPT_ENTRY_USE_EXCEEDS_ALLOCATION"
            if code is None and (
                generation_reserved["unallocated_reservation"]
                != generation_reserved["generation_reservation"]
                or generation_reserved["reconciled_use"] != zero_vector()
                or not vec_le(
                    reserved["attempt_allocation"],
                    generation_reserved["unallocated_reservation"],
                )
                or generation_active["unallocated_reservation"]
                != vec_sub(
                    generation_reserved["unallocated_reservation"],
                    reserved["attempt_allocation"],
                )
                or generation_active["reconciled_use"] != zero_vector()
                or generation_reconciled["unallocated_reservation"]
                != vec_add(
                    generation_active["unallocated_reservation"],
                    vec_sub(
                        reconciled["attempt_allocation"],
                        reconciled["reconciled_use"],
                    ),
                )
                or generation_reconciled["reconciled_use"]
                != vec_add(
                    generation_active["reconciled_use"],
                    reconciled["reconciled_use"],
                )
                or generation_active["generation_reservation"]
                != vec_add(
                    vec_add(
                        generation_active["unallocated_reservation"],
                        generation_active["reconciled_use"],
                    ),
                    reserved["attempt_allocation"],
                )
                or generation_reconciled["generation_reservation"]
                != vec_add(
                    generation_reconciled["unallocated_reservation"],
                    generation_reconciled["reconciled_use"],
                )
            ):
                code = "ATTEMPT_GENERATION_ENTRY_ACCOUNTING_MISMATCH"
            if code is None and (
                reserve_event["attempt_resource_entry_digest"]
                != reserved["attempt_entry_digest"]
                or consume_event["attempt_resource_entry_digest"]
                != consumed["attempt_entry_digest"]
                or reconcile_event["attempt_resource_entry_digest"]
                != reconciled["attempt_entry_digest"]
            ):
                code = "ATTEMPT_ENTRY_EVENT_DIGEST_JOIN_MISMATCH"
            if code is None and (
                envelope["attempt_identity_digest"]
                != reserved["attempt_identity_digest"]
            ):
                code = "ATTEMPT_ENTRY_ENVELOPE_IDENTITY_MISMATCH"
            if code is None and (
                envelope["attempt_reservation_event_digest"]
                != reserve_event["ledger_event_digest"]
                or envelope["attempt_resource_entry_digest"]
                != reserved["attempt_entry_digest"]
                or consumed["attempt_launch_digest"]
                != envelope["attempt_launch_digest"]
                or consume_event["attempt_launch_digest"]
                != envelope["attempt_launch_digest"]
                or reconciled["attempt_launch_digest"]
                != envelope["attempt_launch_digest"]
                or reconcile_event["attempt_launch_digest"]
                != envelope["attempt_launch_digest"]
            ):
                code = "ATTEMPT_ENTRY_LAUNCH_JOIN_MISMATCH"
            if code is None and (
                envelope[
                    "resource_ledger_digest_after_attempt_reservation"
                ]
                != post_reservation_ledger["resource_ledger_digest"]
                or post_reservation_ledger["generation_entry_digests"]
                != [generation_active["generation_entry_digest"]]
                or post_reservation_ledger["attempt_entry_digests"]
                != [reserved["attempt_entry_digest"]]
                or post_reservation_ledger["event_digests"]
                != semantic_set(
                    [
                        reserve_event["previous_event_digest"],
                        reserve_event["ledger_event_digest"],
                    ]
                )
                or post_reservation_ledger["last_event_sequence"]
                != reserve_event["event_sequence"]
                or post_reservation_ledger["last_event_digest"]
                != reserve_event["ledger_event_digest"]
            ):
                code = "ATTEMPT_RESERVATION_LEDGER_JOIN_MISMATCH"
            if code is None and (
                post_consumption_ledger["previous_ledger_digest"]
                != post_reservation_ledger["resource_ledger_digest"]
                or post_consumption_ledger["generation_entry_digests"]
                != [generation_active["generation_entry_digest"]]
                or post_consumption_ledger["attempt_entry_digests"]
                != [consumed["attempt_entry_digest"]]
                or post_consumption_ledger["event_digests"]
                != semantic_set(
                    [
                        reserve_event["previous_event_digest"],
                        reserve_event["ledger_event_digest"],
                        consume_event["ledger_event_digest"],
                    ]
                )
                or post_consumption_ledger["last_event_sequence"]
                != consume_event["event_sequence"]
                or post_consumption_ledger["last_event_digest"]
                != consume_event["ledger_event_digest"]
            ):
                code = "ATTEMPT_CONSUMPTION_LEDGER_JOIN_MISMATCH"
            active_projection = vec_add(
                generation_active["unallocated_reservation"],
                reserved["attempt_allocation"],
            )
            if code is None and any(
                snapshot["grant"]
                != generation_active["generation_reservation"]
                or snapshot["active_reserved"] != active_projection
                or snapshot["reconciled"]
                != generation_active["reconciled_use"]
                or snapshot["remaining"] != zero_vector()
                or snapshot["arm_family_digest"]
                != generation_active["arm_family_digest"]
                for snapshot in (
                    post_reservation_ledger,
                    post_consumption_ledger,
                )
            ):
                code = "ATTEMPT_LEDGER_GENERATION_PROJECTION_MISMATCH"
            if code is None and any(
                len({snapshot[field] for snapshot in (
                    post_reservation_ledger,
                    post_consumption_ledger,
                    post_reconciliation_ledger,
                )}) != 1
                for field in (
                    "resource_ledger_id",
                    "arm_family_digest",
                    "semantic_plan_digest",
                    "common_resource_grant_digest",
                    "currency_code",
                )
            ):
                code = "ATTEMPT_LEDGER_IDENTITY_MISMATCH"
            if code is None and (
                observation["attempt_identity_digest"]
                != reserved["attempt_identity_digest"]
                or observation["backend_arm_digest"]
                != envelope["backend_arm_digest"]
                or observation["attempt_launch_digest"]
                != envelope["attempt_launch_digest"]
                or observation["attempt_reservation_event_digest"]
                != reserve_event["ledger_event_digest"]
                or observation["launch_consumption_event_digest"]
                != consume_event["ledger_event_digest"]
            ):
                code = "ATTEMPT_ENTRY_OBSERVATION_JOIN_MISMATCH"
            if code is None and (
                observation["reserved_attempt_resource_entry_digest"]
                != reserved["attempt_entry_digest"]
            ):
                code = "ATTEMPT_ENTRY_OBSERVATION_RESERVED_ENTRY_MISMATCH"
            if code is None and (
                observation["consumed_attempt_resource_entry_digest"]
                != consumed["attempt_entry_digest"]
            ):
                code = "ATTEMPT_ENTRY_OBSERVATION_CONSUMED_ENTRY_MISMATCH"
            if code is None and (
                observation[
                    "resource_ledger_digest_after_attempt_reservation"
                ]
                != post_reservation_ledger["resource_ledger_digest"]
            ):
                code = "ATTEMPT_ENTRY_OBSERVATION_RESERVATION_LEDGER_MISMATCH"
            if code is None and (
                observation[
                    "resource_ledger_digest_after_launch_consumption"
                ]
                != post_consumption_ledger["resource_ledger_digest"]
            ):
                code = "ATTEMPT_ENTRY_OBSERVATION_CONSUMPTION_LEDGER_MISMATCH"
            if code is None and (
                any(
                    event["expected_ledger_revision"]
                    != event["event_sequence"]
                    for event in (
                        reserve_event,
                        consume_event,
                        reconcile_event,
                    )
                )
            ):
                code = "ATTEMPT_ENTRY_CAS_REVISION_MISMATCH"
            if code is None and (
                consume_event["event_sequence"]
                != reserve_event["event_sequence"] + 1
                or consume_event["previous_event_digest"]
                != reserve_event["ledger_event_digest"]
                or reconcile_event["event_sequence"]
                != consume_event["event_sequence"] + 1
                or reconcile_event["previous_event_digest"]
                != consume_event["ledger_event_digest"]
            ):
                code = "ATTEMPT_ENTRY_JOURNAL_LINK_MISMATCH"
            if code is None and (
                post_reconciliation_ledger["previous_ledger_digest"]
                != post_consumption_ledger["resource_ledger_digest"]
                or post_reconciliation_ledger["generation_entry_digests"]
                != [generation_reconciled["generation_entry_digest"]]
                or post_reconciliation_ledger["attempt_entry_digests"]
                != [reconciled["attempt_entry_digest"]]
                or post_reconciliation_ledger["event_digests"]
                != semantic_set(
                    [
                        reserve_event["previous_event_digest"],
                        reserve_event["ledger_event_digest"],
                        consume_event["ledger_event_digest"],
                        reconcile_event["ledger_event_digest"],
                    ]
                )
                or post_reconciliation_ledger["last_event_sequence"]
                != reconcile_event["event_sequence"]
                or post_reconciliation_ledger["last_event_digest"]
                != reconcile_event["ledger_event_digest"]
            ):
                code = "ATTEMPT_RECONCILIATION_LEDGER_JOIN_MISMATCH"
            if code is None and (
                post_reconciliation_ledger["grant"]
                != generation_reconciled["generation_reservation"]
                or post_reconciliation_ledger["active_reserved"]
                != generation_reconciled["unallocated_reservation"]
                or post_reconciliation_ledger["reconciled"]
                != generation_reconciled["reconciled_use"]
                or post_reconciliation_ledger["remaining"] != zero_vector()
                or post_reconciliation_ledger["arm_family_digest"]
                != generation_reconciled["arm_family_digest"]
            ):
                code = "ATTEMPT_LEDGER_GENERATION_PROJECTION_MISMATCH"
        elif case["kind"] == "OBSERVATION_DISPOSITION_JOIN":
            records = case["records"]
            observation = records["observation"]
            generation_active_entry = records[
                "generation_active_entry"
            ]
            consumed_entry = records["consumed_entry"]
            consume_event = records["consume_event"]
            post_consumption_ledger = records[
                "post_consumption_ledger"
            ]
            effort_authority = records["effort_authority"]
            thinking_authority = records["thinking_authority"]
            launch_authority = records["launch_authority"]
            launch_envelope = records["launch_envelope"]
            try:
                for definition, record, digest_field in (
                    (
                        "ProviderExecutionObservationV4",
                        observation,
                        "observation_digest",
                    ),
                    (
                        "GenerationResourceEntryV2",
                        generation_active_entry,
                        "generation_entry_digest",
                    ),
                    (
                        "AttemptResourceEntryV2",
                        consumed_entry,
                        "attempt_entry_digest",
                    ),
                    (
                        "ResourceLedgerEventV2",
                        consume_event,
                        "ledger_event_digest",
                    ),
                    (
                        "BackendSemanticResourceLedgerV2",
                        post_consumption_ledger,
                        "resource_ledger_digest",
                    ),
                    (
                        "ClaudeEffortAuthorityV3",
                        effort_authority,
                        "effort_authority_digest",
                    ),
                    (
                        "ClaudeThinkingAuthorityV1",
                        thinking_authority,
                        "thinking_authority_digest",
                    ),
                    (
                        "LaunchAuthorityV2",
                        launch_authority,
                        "launch_authority_digest",
                    ),
                    (
                        "AttemptLaunchEnvelopeV2",
                        launch_envelope,
                        "attempt_launch_digest",
                    ),
                ):
                    schema_validate(
                        load_ascii(SCHEMA_PATH),
                        definition,
                        record,
                    )
                    if record[digest_field] != digest_record(
                        record, digest_field
                    ):
                        raise ConformanceError(
                            "OBSERVATION_RECORD_DIGEST_MISMATCH"
                        )
                observation_invariants(observation)
                generation_entry_invariants(generation_active_entry)
                ledger_invariants(post_consumption_ledger)
                effort_authority_invariants(effort_authority)
                thinking_authority_invariants(thinking_authority)
            except (jsonschema.ValidationError, ConformanceError) as exc:
                code = (
                    exc.code
                    if isinstance(exc, ConformanceError)
                    else classify_schema_error(exc)
                )
            expected_thinking_state = {
                "ADAPTIVE_ON": "ADAPTIVE_ON_CONFIRMED",
                "MANUAL_ON": "MANUAL_ON_CONFIRMED",
                "MANUAL_OFF": "MANUAL_OFF_CONFIRMED",
            }[thinking_authority["requested_thinking_mode"]]
            if code is None and (
                launch_authority["thinking_authority_digest"]
                != thinking_authority["thinking_authority_digest"]
                or launch_authority["effort_authority_digest"]
                != effort_authority["effort_authority_digest"]
                or effort_authority["exact_model_id"]
                != thinking_authority["exact_model_id"]
                or launch_envelope["launch_authority_digest"]
                != launch_authority["launch_authority_digest"]
                or observation["attempt_identity_digest"]
                != launch_envelope["attempt_identity_digest"]
                or observation["backend_arm_digest"]
                != launch_envelope["backend_arm_digest"]
                or observation["attempt_launch_digest"]
                != launch_envelope["attempt_launch_digest"]
                or observation["attempt_reservation_event_digest"]
                != launch_envelope["attempt_reservation_event_digest"]
                or observation["reserved_attempt_resource_entry_digest"]
                != launch_envelope["attempt_resource_entry_digest"]
                or observation[
                    "resource_ledger_digest_after_attempt_reservation"
                ]
                != launch_envelope[
                    "resource_ledger_digest_after_attempt_reservation"
                ]
                or consumed_entry["arm_family_digest"]
                != launch_authority["arm_family_digest"]
                or consumed_entry["generation"]
                != launch_authority["generation"]
                or consumed_entry["attempt_identity_digest"]
                != launch_envelope["attempt_identity_digest"]
                or consumed_entry["previous_attempt_entry_digest"]
                != launch_envelope["attempt_resource_entry_digest"]
                or consumed_entry["budget_authority_digest"]
                != launch_authority["budget_authority_digest"]
                or consumed_entry["attempt_entry_digest"]
                != observation[
                    "consumed_attempt_resource_entry_digest"
                ]
                or consumed_entry["attempt_launch_digest"]
                != launch_envelope["attempt_launch_digest"]
                or consumed_entry["entry_state"] != "LAUNCH_CONSUMED"
                or generation_active_entry["arm_family_digest"]
                != launch_authority["arm_family_digest"]
                or generation_active_entry["generation"]
                != launch_authority["generation"]
                or generation_active_entry["budget_authority_digest"]
                != launch_authority["budget_authority_digest"]
                or consumed_entry["generation_entry_digest"]
                != generation_active_entry["generation_entry_digest"]
            ):
                code = "OBSERVATION_LAUNCH_AUTHORITY_JOIN_MISMATCH"
            if code is None and (
                consume_event["event_kind"] != "CONSUME_ATTEMPT_LAUNCH"
                or consume_event["event_sequence"] != 2
                or consume_event["expected_ledger_revision"] != 2
                or consume_event["previous_event_digest"]
                != launch_envelope["attempt_reservation_event_digest"]
                or consume_event["arm_family_digest"]
                != consumed_entry["arm_family_digest"]
                or consume_event["generation"]
                != consumed_entry["generation"]
                or consume_event["attempt_identity_digest"]
                != consumed_entry["attempt_identity_digest"]
                or consume_event["budget_authority_digest"]
                != consumed_entry["budget_authority_digest"]
                or consume_event["token_budget_derivation_digest"]
                != consumed_entry["token_budget_derivation_digest"]
                or consume_event["attempt_resource_entry_digest"]
                != consumed_entry["attempt_entry_digest"]
                or consume_event["attempt_launch_digest"]
                != consumed_entry["attempt_launch_digest"]
                or observation["launch_consumption_event_digest"]
                != consume_event["ledger_event_digest"]
            ):
                code = "OBSERVATION_CONSUMPTION_JOIN_MISMATCH"
            if code is None and (
                post_consumption_ledger["previous_ledger_digest"]
                != launch_envelope[
                    "resource_ledger_digest_after_attempt_reservation"
                ]
                or post_consumption_ledger["generation_entry_digests"]
                != [generation_active_entry["generation_entry_digest"]]
                or post_consumption_ledger["attempt_entry_digests"]
                != [consumed_entry["attempt_entry_digest"]]
                or post_consumption_ledger["last_event_sequence"]
                != consume_event["event_sequence"]
                or post_consumption_ledger["last_event_digest"]
                != consume_event["ledger_event_digest"]
                or consume_event["ledger_event_digest"]
                not in post_consumption_ledger["event_digests"]
                or launch_envelope["attempt_reservation_event_digest"]
                not in post_consumption_ledger["event_digests"]
                or post_consumption_ledger["arm_family_digest"]
                != generation_active_entry["arm_family_digest"]
                or post_consumption_ledger["ledger_state"] != "ACTIVE"
                or post_consumption_ledger["semantic_plan_digest"]
                != launch_authority["semantic_plan_digest"]
                or post_consumption_ledger["grant"]
                != generation_active_entry["generation_reservation"]
                or post_consumption_ledger["active_reserved"]
                != vec_add(
                    generation_active_entry[
                        "unallocated_reservation"
                    ],
                    consumed_entry["attempt_allocation"],
                )
                or post_consumption_ledger["reconciled"]
                != generation_active_entry["reconciled_use"]
                or post_consumption_ledger["remaining"] != zero_vector()
                or observation[
                    "resource_ledger_digest_after_launch_consumption"
                ]
                != post_consumption_ledger["resource_ledger_digest"]
            ):
                code = "OBSERVATION_CONSUMPTION_LEDGER_JOIN_MISMATCH"
            model_adverse = (
                observation["effective_model_state"] != "EXACT"
                or observation["observed_effective_model_id"]
                != thinking_authority["exact_model_id"]
            )
            effort_adverse = (
                observation["effective_effort_state"] != "EXACT"
                or observation["observed_effective_effort"]
                != effort_authority["requested_effort"]
            )
            thinking_adverse = observation["observed_thinking_state"] in {
                "UNOBSERVABLE",
                "MISMATCHED",
            }
            adverse = model_adverse or effort_adverse or thinking_adverse
            if (
                code is None
                and not adverse
                and observation["observed_thinking_state"]
                != expected_thinking_state
            ):
                code = "OBSERVATION_THINKING_AUTHORITY_MISMATCH"
            if adverse and code is None:
                route_debt = records["route_debt"]
                generation_debt_entry = records[
                    "generation_debt_entry"
                ]
                attempt_debt_entry = records["attempt_debt_entry"]
                debt_event = records["debt_event"]
                post_debt_ledger = records["post_debt_ledger"]
                if (
                    records["disposition"] != "DEBT"
                    or records["terminal_safe_eligible"]
                    or route_debt is None
                    or generation_debt_entry is None
                    or attempt_debt_entry is None
                    or debt_event is None
                    or post_debt_ledger is None
                ):
                    code = "OBSERVATION_ADVERSE_REQUIRES_DEBT"
                else:
                    try:
                        schema_validate(
                            load_ascii(SCHEMA_PATH),
                            "RouteDebtV3",
                            route_debt,
                        )
                        schema_validate(
                            load_ascii(SCHEMA_PATH),
                            "ResourceLedgerEventV2",
                            debt_event,
                        )
                        schema_validate(
                            load_ascii(SCHEMA_PATH),
                            "GenerationResourceEntryV2",
                            generation_debt_entry,
                        )
                        schema_validate(
                            load_ascii(SCHEMA_PATH),
                            "AttemptResourceEntryV2",
                            attempt_debt_entry,
                        )
                        schema_validate(
                            load_ascii(SCHEMA_PATH),
                            "BackendSemanticResourceLedgerV2",
                            post_debt_ledger,
                        )
                        if route_debt[
                            "route_debt_digest"
                        ] != digest_record(
                            route_debt, "route_debt_digest"
                        ):
                            raise ConformanceError(
                                "OBSERVATION_DEBT_RECORD_DIGEST_MISMATCH"
                            )
                        if debt_event[
                            "ledger_event_digest"
                        ] != digest_record(
                            debt_event, "ledger_event_digest"
                        ):
                            raise ConformanceError(
                                "OBSERVATION_DEBT_EVENT_DIGEST_MISMATCH"
                            )
                        for record, digest_field in (
                            (
                                generation_debt_entry,
                                "generation_entry_digest",
                            ),
                            (
                                attempt_debt_entry,
                                "attempt_entry_digest",
                            ),
                            (
                                post_debt_ledger,
                                "resource_ledger_digest",
                            ),
                        ):
                            if record[digest_field] != digest_record(
                                record, digest_field
                            ):
                                raise ConformanceError(
                                    "OBSERVATION_DEBT_RECORD_DIGEST_MISMATCH"
                                )
                        generation_entry_invariants(
                            generation_debt_entry
                        )
                        ledger_invariants(post_debt_ledger)
                    except (
                        jsonschema.ValidationError,
                        ConformanceError,
                    ) as exc:
                        code = (
                            exc.code
                            if isinstance(exc, ConformanceError)
                            else classify_schema_error(exc)
                        )
                expected_evidence = hashlib.sha256(
                    canonical_bytes([observation["observation_digest"]])
                ).hexdigest()
                if model_adverse:
                    model_state = observation["effective_model_state"]
                    expected_debt_code = (
                        "MODEL_MISMATCHED"
                        if model_state == "EXACT"
                        else f"MODEL_{model_state}"
                    )
                elif effort_adverse:
                    effort_state = observation["effective_effort_state"]
                    expected_debt_code = (
                        "EFFORT_MISMATCHED"
                        if effort_state == "EXACT"
                        else f"EFFORT_{effort_state}"
                    )
                else:
                    expected_debt_code = (
                        "THINKING_MISMATCHED"
                        if observation["observed_thinking_state"]
                        == "MISMATCHED"
                        else "THINKING_UNOBSERVABLE"
                    )
                if code is None and (
                    route_debt["semantic_plan_digest"]
                    != launch_authority["semantic_plan_digest"]
                    or route_debt["stage"] != "PROVIDER_OBSERVATION"
                    or route_debt["backend_arm_digest"]
                    != observation["backend_arm_digest"]
                    or route_debt["attempt_identity_digest"]
                    != observation["attempt_identity_digest"]
                    or route_debt["evidence_digest_set_digest"]
                    != expected_evidence
                    or route_debt["debt_code"] != expected_debt_code
                ):
                    code = "OBSERVATION_ROUTE_DEBT_JOIN_MISMATCH"
                if code is None and (
                    generation_debt_entry[
                        "previous_generation_entry_digest"
                    ]
                    != generation_active_entry["generation_entry_digest"]
                    or generation_debt_entry["arm_family_digest"]
                    != generation_active_entry["arm_family_digest"]
                    or generation_debt_entry["generation"]
                    != generation_active_entry["generation"]
                    or generation_debt_entry["budget_authority_digest"]
                    != generation_active_entry["budget_authority_digest"]
                    or generation_debt_entry["generation_reservation"]
                    != generation_active_entry["generation_reservation"]
                    or generation_debt_entry["unallocated_reservation"]
                    != generation_active_entry["unallocated_reservation"]
                    or generation_debt_entry["reconciled_use"]
                    != generation_active_entry["reconciled_use"]
                    or generation_debt_entry["entry_state"] != "DEBT"
                    or attempt_debt_entry[
                        "previous_attempt_entry_digest"
                    ]
                    != consumed_entry["attempt_entry_digest"]
                    or attempt_debt_entry["generation_entry_digest"]
                    != generation_debt_entry["generation_entry_digest"]
                    or any(
                        attempt_debt_entry[field] != consumed_entry[field]
                        for field in (
                            "arm_family_digest",
                            "generation",
                            "attempt_identity_digest",
                            "budget_authority_digest",
                            "token_budget_derivation_digest",
                            "attempt_launch_digest",
                            "attempt_allocation",
                            "reconciled_use",
                        )
                    )
                    or attempt_debt_entry["entry_state"] != "DEBT"
                ):
                    code = "OBSERVATION_DEBT_ENTRY_JOIN_MISMATCH"
                if code is None and (
                    debt_event["event_kind"]
                    != "MARK_CONSUMED_ATTEMPT_DEBT"
                    or debt_event["arm_family_digest"]
                    != consumed_entry["arm_family_digest"]
                    or debt_event["generation"]
                    != consumed_entry["generation"]
                    or debt_event["attempt_identity_digest"]
                    != consumed_entry["attempt_identity_digest"]
                    or debt_event["budget_authority_digest"]
                    != consumed_entry["budget_authority_digest"]
                    or debt_event["token_budget_derivation_digest"]
                    != consumed_entry["token_budget_derivation_digest"]
                    or debt_event["attempt_resource_entry_digest"]
                    != attempt_debt_entry["attempt_entry_digest"]
                    or debt_event["attempt_launch_digest"]
                    != consumed_entry["attempt_launch_digest"]
                ):
                    code = "OBSERVATION_DEBT_EVENT_JOIN_MISMATCH"
                if code is None and (
                    debt_event["event_sequence"] != 3
                    or debt_event["expected_ledger_revision"] != 3
                    or debt_event["previous_event_digest"]
                    != consume_event["ledger_event_digest"]
                ):
                    code = "OBSERVATION_DEBT_EVENT_CAS_MISMATCH"
                if code is None and (
                    post_debt_ledger["previous_ledger_digest"]
                    != post_consumption_ledger["resource_ledger_digest"]
                    or post_debt_ledger["ledger_state"] != "DEBT"
                    or post_debt_ledger["generation_entry_digests"]
                    != [generation_debt_entry["generation_entry_digest"]]
                    or post_debt_ledger["attempt_entry_digests"]
                    != [attempt_debt_entry["attempt_entry_digest"]]
                    or post_debt_ledger["last_event_sequence"]
                    != debt_event["event_sequence"]
                    or post_debt_ledger["last_event_digest"]
                    != debt_event["ledger_event_digest"]
                    or post_debt_ledger["event_digests"]
                    != semantic_set(
                        post_consumption_ledger["event_digests"]
                        + [debt_event["ledger_event_digest"]]
                    )
                    or any(
                        post_debt_ledger[field]
                        != post_consumption_ledger[field]
                        for field in (
                            "resource_ledger_id",
                            "arm_family_digest",
                            "semantic_plan_digest",
                            "common_resource_grant_digest",
                            "currency_code",
                            "grant",
                            "active_reserved",
                            "reconciled",
                            "remaining",
                        )
                    )
                ):
                    code = "OBSERVATION_DEBT_LEDGER_JOIN_MISMATCH"
            elif not adverse and code is None and (
                records["disposition"] != "RECONCILE"
                or records["route_debt"] is not None
                or records["generation_debt_entry"] is not None
                or records["attempt_debt_entry"] is not None
                or records["debt_event"] is not None
                or records["post_debt_ledger"] is not None
            ):
                code = "OBSERVATION_CONFIRMED_DISPOSITION_INVALID"
        elif case["kind"] == "THINKING_CONTROLS":
            controls = case["controls"]
            if case["requested_mode"] == "ADAPTIVE_ON":
                expected = {
                    "ADAPTIVE_THINKING": "EXPLICIT",
                    "MAX_THINKING_TOKENS": "PROVEN_ABSENT",
                    "ALWAYS_THINKING": "PROVEN_ABSENT",
                    "MANUAL_THINKING_BUDGET": "PROVEN_ABSENT",
                }
                if controls != expected:
                    code = "THINKING_CONTROL_CONFLICT"
        elif case["kind"] == "THINKING_LAUNCH_SEAL":
            records = case["records"]
            discovery = records["discovery_authority"]
            loaded = records["loaded_customization_set"]
            effort = records["effort_authority"]
            control = records["provider_control_vector"]
            thinking = records["thinking_authority"]
            launch = records["launch_authority"]
            envelope = records["attempt_launch_envelope"]
            typed = (
                (
                    "CustomizationDiscoveryAuthorityV1",
                    discovery,
                    "discovery_authority_digest",
                ),
                (
                    "LoadedCustomizationSetV1",
                    loaded,
                    "customization_set_digest",
                ),
                (
                    "ClaudeEffortAuthorityV3",
                    effort,
                    "effort_authority_digest",
                ),
                (
                    "ClaudeProviderControlVectorV1",
                    control,
                    "provider_control_vector_digest",
                ),
                (
                    "ClaudeThinkingAuthorityV1",
                    thinking,
                    "thinking_authority_digest",
                ),
                ("LaunchAuthorityV2", launch, "launch_authority_digest"),
                (
                    "AttemptLaunchEnvelopeV2",
                    envelope,
                    "attempt_launch_digest",
                ),
            )
            try:
                for definition, record, digest_field in typed:
                    schema_validate(
                        load_ascii(SCHEMA_PATH), definition, record
                    )
                    if record[digest_field] != digest_record(
                        record, digest_field
                    ):
                        raise ConformanceError(
                            "THINKING_LAUNCH_RECORD_DIGEST_MISMATCH"
                        )
                provider_control_vector_invariants(control)
                discovery_authority_invariants(discovery)
                customization_invariants(loaded)
                effort_authority_invariants(effort)
                thinking_authority_invariants(thinking)
            except (jsonschema.ValidationError, ConformanceError) as exc:
                code = (
                    exc.code
                    if isinstance(exc, ConformanceError)
                    else classify_schema_error(exc)
                )
            if code is None and (
                thinking["provider_control_vector_digest"]
                != control["provider_control_vector_digest"]
            ):
                code = "THINKING_CONTROL_VECTOR_JOIN_MISMATCH"
            if code is None and (
                loaded["discovery_authority_digest"]
                != discovery["discovery_authority_digest"]
                or loaded["resolution_root_digest"]
                != discovery["resolution_root_digest"]
                or loaded["customization_registry_digest"]
                != discovery["customization_registry_digest"]
                or customization_source_projection(loaded["rows"])
                != discovery["expected_sources"]
            ):
                code = "THINKING_LAUNCH_DISCOVERY_MISMATCH"
            if code is None and thinking["authority_result"] != "SEALED":
                code = "THINKING_AUTHORITY_NOT_SEALED"
            if code is None and effort["authority_result"] != "SEALED":
                code = "EFFORT_AUTHORITY_NOT_SEALED"
            if code is None and (
                thinking["thinking_authority_digest"]
                != launch["thinking_authority_digest"]
                or launch["launch_authority_digest"]
                != envelope["launch_authority_digest"]
            ):
                code = "THINKING_LAUNCH_AUTHORITY_JOIN_MISMATCH"
            if code is None and (
                len(
                    {
                        control["semantic_plan_digest"],
                        effort["semantic_plan_digest"],
                        thinking["semantic_plan_digest"],
                        launch["semantic_plan_digest"],
                    }
                )
                != 1
                or len(
                    {
                        control["exact_model_id"],
                        effort["exact_model_id"],
                        thinking["exact_model_id"],
                    }
                )
                != 1
                or control["effort_authority_digest"]
                != effort["effort_authority_digest"]
                or launch["effort_authority_digest"]
                != effort["effort_authority_digest"]
                or control["requested_effort"]
                != effort["requested_effort"]
                or control["requested_thinking_mode"]
                != thinking["requested_thinking_mode"]
                or control["manual_thinking_budget_tokens"]
                != thinking["manual_thinking_budget_tokens"]
            ):
                code = "THINKING_CONTROL_AUTHORITY_PROJECTION_MISMATCH"
            if code is None and len(
                {
                    effort["customization_set_digest"],
                    thinking["customization_set_digest"],
                    launch["loaded_customization_set_digest"],
                }
            ) != 1:
                code = "THINKING_LAUNCH_CUSTOMIZATION_MISMATCH"
            expected_control_projection = []
            for source_row in loaded["rows"]:
                for control_name in THINKING_CONTROLS:
                    expected_control_projection.append(
                        (
                            source_row["ordinal"],
                            source_row["source_kind"],
                            source_row["source_id"],
                            source_row["row_digest"],
                            control_name,
                        )
                    )
            observed_control_projection = [
                (
                    row["customization_row_ordinal"],
                    row["source_kind"],
                    row["source_id"],
                    row["customization_row_digest"],
                    row["control_name"],
                )
                for row in thinking["ordered_controls"]
            ]
            if code is None and (
                thinking["customization_row_count"] != len(loaded["rows"])
                or observed_control_projection
                != expected_control_projection
            ):
                code = "THINKING_LAUNCH_CONTROL_SOURCE_MISMATCH"
            if code is None and (
                control["materialized_argv_digest"]
                != envelope["materialized_argv_digest"]
            ):
                code = "THINKING_LAUNCH_ARGV_MISMATCH"
            if code is None and (
                control["materialized_environment_digest"]
                != envelope["materialized_environment_digest"]
            ):
                code = "THINKING_LAUNCH_ENVIRONMENT_MISMATCH"
        elif case["kind"] == "CANARY_RECORD_CHAIN":
            chain = case["records"]
            typed = (
                (
                    "CanaryPlanAuthorityV1",
                    chain["plan"],
                    "canary_plan_digest",
                ),
                (
                    "CanaryProofRuleAuthorityV1",
                    chain["proof_rule_authority"],
                    "proof_rule_authority_digest",
                ),
            ) + tuple(
                (
                    "CanaryCaseResultV1",
                    row,
                    "case_result_digest",
                )
                for row in chain["case_results"]
            ) + (
                (
                    "CanaryEvidenceManifestV1",
                    chain["manifest"],
                    "evidence_manifest_digest",
                ),
                ("CanaryFieldClaimV2", chain["claim"], "canary_claim_digest"),
                (
                    "ProviderCapabilityCanaryReceiptV3",
                    chain["receipt"],
                    "canary_receipt_digest",
                ),
            )
            try:
                for definition, record, digest_field in typed:
                    schema_validate(
                        load_ascii(SCHEMA_PATH), definition, record
                    )
                    if record[digest_field] != digest_record(
                        record, digest_field
                    ):
                        raise ConformanceError("CANARY_RECORD_DIGEST_MISMATCH")
                proof_rule_authority_invariants(
                    chain["proof_rule_authority"]
                )
                canary_plan_invariants(chain["plan"])
            except (jsonschema.ValidationError, ConformanceError) as exc:
                code = (
                    exc.code
                    if isinstance(exc, ConformanceError)
                    else classify_schema_error(exc)
                )
            case_results = chain["case_results"]
            members = {
                row["case_result_digest"]: row for row in case_results
            }
            manifest = chain["manifest"]
            claim = chain["claim"]
            receipt = chain["receipt"]
            expected_result_digests = semantic_set(
                [row["case_result_digest"] for row in case_results]
            )
            if code is None and (
                len(members) != len(case_results)
                or manifest["case_result_digests"]
                != expected_result_digests
            ):
                code = "CANARY_CASE_RESULT_JOIN_MISMATCH"
            if code is None and len(
                {
                    chain["manifest"]["evidence_manifest_digest"],
                    chain["claim"]["evidence_manifest_digest"],
                    chain["receipt"]["evidence_manifest_digest"],
                }
            ) != 1:
                code = "CANARY_MANIFEST_JOIN_MISMATCH"
            if code is None and (
                chain["claim"]["canary_claim_digest"]
                not in chain["receipt"]["field_claim_digests"]
            ):
                code = "CANARY_CLAIM_NOT_IN_RECEIPT"
            if code is None and len(
                {
                    chain["proof_rule_authority"][
                        "proof_rule_authority_digest"
                    ],
                    *[
                        row["proof_rule_authority_digest"]
                        for row in case_results
                    ],
                    chain["manifest"]["proof_rule_authority_digest"],
                    chain["claim"]["proof_rule_authority_digest"],
                    chain["receipt"]["proof_rule_authority_digest"],
                }
            ) != 1:
                code = "CANARY_PROOF_RULE_AUTHORITY_JOIN_MISMATCH"
            if code is None and len(
                {
                    chain["plan"]["canary_plan_digest"],
                    chain["proof_rule_authority"]["canary_plan_digest"],
                    *[
                        row["canary_plan_digest"]
                        for row in case_results
                    ],
                    chain["manifest"]["canary_plan_digest"],
                    chain["claim"]["canary_plan_digest"],
                    chain["receipt"]["canary_plan_digest"],
                }
            ) != 1:
                code = "CANARY_PLAN_JOIN_MISMATCH"
            expected_raw = semantic_set(
                [
                    digest
                    for row in case_results
                    for digest in row["raw_artifact_digests"]
                ]
            )
            if code is None and (
                manifest["raw_artifact_digests"] != expected_raw
            ):
                code = "CANARY_RAW_ARTIFACT_UNION_INVALID"
            if code is None and manifest[
                "raw_artifact_union_digest"
            ] != hashlib.sha256(canonical_bytes(expected_raw)).hexdigest():
                code = "CANARY_RAW_ARTIFACT_UNION_DIGEST_MISMATCH"
            case_ids = [row["case_id"] for row in case_results]
            if code is None and len(case_ids) != len(set(case_ids)):
                code = "CANARY_CASE_ID_DUPLICATE"
            expected_executed = semantic_set(case_ids)
            if code is None and (
                receipt["executed_case_ids"] != expected_executed
            ):
                code = "CANARY_EXECUTED_CASE_SET_MISMATCH"
            expected_passed = semantic_set(
                [
                    row["case_id"]
                    for row in case_results
                    if row["case_disposition"] == "PASS"
                ]
            )
            if code is None and (
                receipt["passed_case_ids"] != expected_passed
            ):
                code = "CANARY_PASSED_CASE_SET_MISMATCH"
            if code is None and not set(
                chain["plan"]["required_case_ids"]
            ).issubset(set(receipt["executed_case_ids"])):
                code = "CANARY_REQUIRED_CASE_INCOMPLETE"
            support_lists = (
                claim["supporting_case_ids"],
                claim["supporting_case_result_digests"],
                claim["supporting_proof_rule_ids"],
            )
            if code is None and (
                not support_lists[0]
                or len({len(values) for values in support_lists}) != 1
            ):
                code = "CANARY_CLAIM_SUPPORT_CARDINALITY_MISMATCH"
            if code is None and any(
                values != semantic_set(values) for values in support_lists
            ):
                code = "CANARY_CLAIM_SUPPORT_ORDER_INVALID"
            if code is None:
                for case_id, result_digest, proof_rule in zip(
                    *support_lists
                ):
                    if result_digest not in members:
                        code = "CANARY_CLAIM_EVIDENCE_NOT_MEMBER"
                        break
                    result = members[result_digest]
                    if case_id != result["case_id"]:
                        code = "CANARY_CLAIM_CASE_ID_MISMATCH"
                        break
                    if (
                        result["case_disposition"] != "PASS"
                        or case_id not in receipt["passed_case_ids"]
                    ):
                        code = "CANARY_CLAIM_EVIDENCE_NOT_PASS"
                        break
                    if proof_rule not in result[
                        "satisfied_proof_rule_ids"
                    ]:
                        code = "CANARY_PROOF_RULE_JOIN_MISMATCH"
                        break
                    if not set(
                        result["raw_artifact_digests"]
                    ).issubset(set(manifest["raw_artifact_digests"])):
                        code = "CANARY_RAW_ARTIFACT_NOT_MEMBER"
                        break
            authority_map = {
                row["manifest_field"]: set(row["allowed_proof_rule_ids"])
                for row in chain["proof_rule_authority"][
                    "ordered_field_rules"
                ]
            }
            if code is None and (
                chain["claim"]["manifest_field"] not in authority_map
                or not set(
                    chain["claim"]["supporting_proof_rule_ids"]
                ).issubset(authority_map[chain["claim"]["manifest_field"]])
            ):
                code = "CANARY_FIELD_PROOF_RULE_UNAUTHORIZED"
        elif case["kind"] == "BUDGET_RECORD_CHAIN":
            chain = case["records"]
            derivation = chain["derivation"]
            budget = chain["budget"]
            try:
                schema_validate(
                    load_ascii(SCHEMA_PATH),
                    "TokenBudgetDerivationV2",
                    derivation,
                )
                schema_validate(
                    load_ascii(SCHEMA_PATH), "BudgetAuthorityV3", budget
                )
                token_derivation_invariants(derivation)
                if derivation["token_derivation_digest"] != digest_record(
                    derivation, "token_derivation_digest"
                ):
                    raise ConformanceError("TOKEN_DERIVATION_DIGEST_MISMATCH")
                if budget["budget_authority_digest"] != digest_record(
                    budget, "budget_authority_digest"
                ):
                    raise ConformanceError("BUDGET_AUTHORITY_DIGEST_MISMATCH")
            except (jsonschema.ValidationError, ConformanceError) as exc:
                code = (
                    exc.code
                    if isinstance(exc, ConformanceError)
                    else classify_schema_error(exc)
                )
            if code is None and (
                budget["token_budget_derivation_digest"]
                != derivation["token_derivation_digest"]
            ):
                code = "TOKEN_DERIVATION_DIGEST_JOIN_MISMATCH"
            if code is None and (
                budget["arm_family_digest"] != derivation["arm_family_digest"]
                or budget["generation"] != derivation["generation"]
                or budget["context_budget_digest"]
                != derivation["context_budget_digest"]
            ):
                code = "TOKEN_DERIVATION_IDENTITY_JOIN_MISMATCH"
            if code is None and (
                budget["token_grant"] != derivation["derived_token_grant"]
            ):
                code = "TOKEN_BUDGET_DERIVATION_MISMATCH"
            if code is None and (
                budget["requested_family_reservation"][
                    "source_payload_bytes"
                ]
                != derivation["source_payload_bytes"]
                or budget["requested_family_reservation"][
                    "output_artifact_bytes"
                ]
                != derivation["output_artifact_bytes_reservation"]
            ):
                code = "TOKEN_DERIVATION_BYTE_RESERVATION_MISMATCH"
        else:
            raise ConformanceError("UNKNOWN_JOIN_VECTOR")
        if case["valid"] and code:
            raise ConformanceError(f"VALID_JOIN_REJECTED:{case['id']}:{code}")
        if not case["valid"] and code != case["expected_error"]:
            raise ConformanceError(f"NEGATIVE_JOIN_WRONG_RESULT:{case['id']}:{code}")
        count += 1
    return count


def vec_le(left, right):
    return all(left[key] <= right[key] for key in VECTOR_FIELDS)


def vec_sub(left, right):
    if not vec_le(right, left):
        raise ConformanceError("FAMILY_GRANT_EXHAUSTED")
    return {key: left[key] - right[key] for key in VECTOR_FIELDS}


def vec_add(left, right):
    out = {}
    for key in VECTOR_FIELDS:
        value = left[key] + right[key]
        if value > MAX_SAFE:
            raise ConformanceError("RESOURCE_ARITHMETIC_OVERFLOW")
        out[key] = value
    return out


def vec_is_zero(value):
    return all(value[key] == 0 for key in VECTOR_FIELDS)


def event_fingerprint(event):
    return hashlib.sha256(canonical_bytes(event)).hexdigest()


def replay_transaction(case):
    grant = expand(case["grant"])
    remaining = copy.deepcopy(grant)
    active_reserved = zero_vector()
    reconciled = zero_vector()
    generations = {}
    attempts = {}
    idempotency = {}
    journal = []
    ledger_state = "ACTIVE"
    revision = 0
    replay_count = 0
    for raw_event in case["events"]:
        event = expand(raw_event)
        idem = event.get("idempotency")
        fingerprint = event_fingerprint(event)
        if idem is not None:
            if idem in idempotency:
                if idempotency[idem] != fingerprint:
                    raise ConformanceError("LEDGER_IDEMPOTENCY_CONFLICT")
                replay_count += 1
                continue
        expected_revision = event.get("expected_revision", revision)
        if expected_revision != revision:
            raise ConformanceError("LEDGER_CAS_LOST")
        event_sequence = event.get("event_sequence", len(journal))
        if event_sequence != len(journal):
            raise ConformanceError("LEDGER_EVENT_SEQUENCE_INVALID")
        expected_previous_index = None if not journal else len(journal) - 1
        previous_index = event.get(
            "previous_event_index", expected_previous_index
        )
        if previous_index != expected_previous_index:
            raise ConformanceError("LEDGER_PREVIOUS_DIGEST_INVALID")
        previous_digest = None if previous_index is None else journal[previous_index]
        normalized_event = copy.deepcopy(event)
        normalized_event["expected_revision"] = expected_revision
        normalized_event["event_sequence"] = event_sequence
        normalized_event.pop("previous_event_index", None)
        normalized_event["previous_event_digest"] = previous_digest
        accepted_digest = event_fingerprint(normalized_event)
        kind = event["kind"]
        generation = event.get("generation")
        attempt = event.get("attempt")
        key = (generation, attempt)
        if ledger_state != "ACTIVE":
            raise ConformanceError("FAMILY_STATE_INVALID")
        if kind == "RESERVE_GENERATION":
            if generation in generations:
                raise ConformanceError("GENERATION_ALREADY_RESERVED")
            delta = event["delta"]
            if vec_is_zero(delta):
                raise ConformanceError("ZERO_RESERVATION_INVALID")
            remaining = vec_sub(remaining, delta)
            active_reserved = vec_add(active_reserved, delta)
            generations[generation] = {
                "reservation": copy.deepcopy(delta),
                "unallocated": copy.deepcopy(delta),
                "reconciled": zero_vector(),
                "state": "RESERVED",
            }
        elif kind == "RESERVE_ATTEMPT":
            if generation not in generations:
                raise ConformanceError("GENERATION_RESERVATION_MISSING")
            if key in attempts:
                raise ConformanceError("ATTEMPT_ALREADY_RESERVED")
            if generations[generation]["state"] not in {"RESERVED", "ACTIVE"}:
                raise ConformanceError("GENERATION_STATE_INVALID")
            delta = event["delta"]
            if vec_is_zero(delta):
                raise ConformanceError("ZERO_RESERVATION_INVALID")
            generations[generation]["unallocated"] = vec_sub(
                generations[generation]["unallocated"], delta
            )
            generations[generation]["state"] = "ACTIVE"
            attempts[key] = {
                "allocation": copy.deepcopy(delta),
                "reconciled": zero_vector(),
                "state": "RESERVED",
                "attempt_launch_digest": None,
            }
        elif kind == "CONSUME_ATTEMPT_LAUNCH":
            if key not in attempts:
                raise ConformanceError("ATTEMPT_RESERVATION_MISSING")
            if generations[generation]["state"] != "ACTIVE":
                raise ConformanceError("GENERATION_STATE_INVALID")
            if attempts[key]["state"] == "LAUNCH_CONSUMED":
                raise ConformanceError("ATTEMPT_LAUNCH_ALREADY_CONSUMED")
            if attempts[key]["state"] != "RESERVED":
                raise ConformanceError("ATTEMPT_STATE_INVALID")
            launch_digest = event.get("attempt_launch_digest")
            if launch_digest is None:
                raise ConformanceError("ATTEMPT_LAUNCH_DIGEST_MISSING")
            attempts[key]["state"] = "LAUNCH_CONSUMED"
            attempts[key]["attempt_launch_digest"] = launch_digest
        elif kind == "RECONCILE_ATTEMPT":
            if key not in attempts or attempts[key]["state"] != "LAUNCH_CONSUMED":
                raise ConformanceError("ATTEMPT_NOT_LAUNCHED")
            if (
                event.get("attempt_launch_digest")
                != attempts[key]["attempt_launch_digest"]
            ):
                raise ConformanceError("ATTEMPT_LAUNCH_DIGEST_MISMATCH")
            delta = event["delta"]
            if not vec_le(delta, attempts[key]["allocation"]):
                raise ConformanceError("ATTEMPT_USE_EXCEEDS_ALLOCATION")
            unused = vec_sub(attempts[key]["allocation"], delta)
            generations[generation]["unallocated"] = vec_add(
                generations[generation]["unallocated"], unused
            )
            generations[generation]["reconciled"] = vec_add(
                generations[generation]["reconciled"], delta
            )
            active_reserved = vec_sub(active_reserved, delta)
            reconciled = vec_add(reconciled, delta)
            attempts[key]["reconciled"] = copy.deepcopy(delta)
            attempts[key]["state"] = "RECONCILED"
        elif kind == "RELEASE_ATTEMPT":
            if key not in attempts or attempts[key]["state"] != "RESERVED":
                raise ConformanceError("ATTEMPT_RELEASE_STATE_INVALID")
            delta = event["delta"]
            if delta != attempts[key]["allocation"]:
                raise ConformanceError("ATTEMPT_RELEASE_MISMATCH")
            generations[generation]["unallocated"] = vec_add(
                generations[generation]["unallocated"], delta
            )
            attempts[key]["state"] = "RELEASED"
        elif kind == "MARK_RESERVED_ATTEMPT_DEBT":
            if key not in attempts or attempts[key]["state"] != "RESERVED":
                raise ConformanceError("ATTEMPT_DEBT_STATE_INVALID")
            if event.get("attempt_launch_digest") is not None:
                raise ConformanceError("ATTEMPT_LAUNCH_DIGEST_MISMATCH")
            attempts[key]["state"] = "DEBT"
            generations[generation]["state"] = "DEBT"
            ledger_state = "DEBT"
        elif kind == "MARK_CONSUMED_ATTEMPT_DEBT":
            if key not in attempts or attempts[key]["state"] != "LAUNCH_CONSUMED":
                raise ConformanceError("ATTEMPT_DEBT_STATE_INVALID")
            if (
                event.get("attempt_launch_digest")
                != attempts[key]["attempt_launch_digest"]
            ):
                raise ConformanceError("ATTEMPT_LAUNCH_DIGEST_MISMATCH")
            attempts[key]["state"] = "DEBT"
            generations[generation]["state"] = "DEBT"
            ledger_state = "DEBT"
        elif kind == "RELEASE_UNUSED_GENERATION":
            if generation not in generations:
                raise ConformanceError("GENERATION_RESERVATION_MISSING")
            if any(
                key_generation == generation
                and row["state"] in {"RESERVED", "LAUNCH_CONSUMED"}
                for (key_generation, _), row in attempts.items()
            ):
                raise ConformanceError("GENERATION_HAS_ACTIVE_ATTEMPT")
            delta = event["delta"]
            if delta != generations[generation]["unallocated"]:
                raise ConformanceError("GENERATION_RELEASE_MISMATCH")
            active_reserved = vec_sub(active_reserved, delta)
            remaining = vec_add(remaining, delta)
            generations[generation]["unallocated"] = zero_vector()
            generations[generation]["state"] = (
                "RELEASED"
                if vec_is_zero(generations[generation]["reconciled"])
                else "RECONCILED"
            )
        elif kind == "MARK_GENERATION_DEBT":
            if generation not in generations:
                raise ConformanceError("GENERATION_RESERVATION_MISSING")
            generations[generation]["state"] = "DEBT"
            ledger_state = "DEBT"
        elif kind == "MARK_FAMILY_DEBT":
            ledger_state = "DEBT"
        elif kind == "CLOSE_FAMILY":
            if not vec_is_zero(active_reserved):
                raise ConformanceError("FAMILY_CLOSE_WITH_ACTIVE_RESERVATION")
            ledger_state = "CLOSED"
        else:
            raise ConformanceError("TRACE_EVENT_UNSUPPORTED")
        if idem is not None:
            idempotency[idem] = fingerprint
        journal.append(accepted_digest)
        revision += 1
        if vec_add(vec_add(active_reserved, reconciled), remaining) != grant:
            raise ConformanceError("LEDGER_CONSERVATION_INVALID")
    state = {
        "ledger_state": ledger_state,
        "revision": revision,
        "grant": grant,
        "active_reserved": active_reserved,
        "reconciled": reconciled,
        "remaining": remaining,
        "generations": [
            {"generation": generation, **generations[generation]}
            for generation in sorted(generations)
        ],
        "attempts": [
            {
                "generation": generation,
                "attempt": attempt,
                **attempts[(generation, attempt)],
            }
            for generation, attempt in sorted(attempts)
        ],
        "event_digests": sorted(journal),
        "last_event_digest": None if not journal else journal[-1],
    }
    return replay_count, hashlib.sha256(canonical_bytes(state)).hexdigest()


def validate_transactions(vectors):
    count = 0
    for case in vectors["transaction_vectors"]:
        try:
            replay_count, state_digest = replay_transaction(case)
        except ConformanceError as exc:
            code = exc.code
            replay_count = 0
            state_digest = None
        else:
            code = None
        if case["valid"] and code:
            raise ConformanceError(f"VALID_TRACE_REJECTED:{case['id']}:{code}")
        if not case["valid"] and code != case["expected_error"]:
            raise ConformanceError(f"NEGATIVE_TRACE_WRONG_RESULT:{case['id']}:{code}")
        if case.get("expected_idempotent_replays", replay_count) != replay_count:
            raise ConformanceError(f"IDEMPOTENT_REPLAY_COUNT:{case['id']}")
        if (
            code is None
            and "expected_final_state_sha256" in case
            and case["expected_final_state_sha256"] != state_digest
        ):
            raise ConformanceError(f"FINAL_STATE_DIGEST_MISMATCH:{case['id']}")
        count += 1
    return count


def validate_canary(vectors):
    count = 0
    for case in vectors["canary_vectors"]:
        members = {row["digest"]: row for row in case["manifest_case_results"]}
        receipt_ids = set(case["receipt_case_ids"])
        receipt_passed_ids = set(case["receipt_passed_case_ids"])
        required_ids = set(case["required_case_ids"])
        manifest_raw = set(case["manifest_raw_artifact_digests"])
        claim = case["claim"]
        code = None
        if case["manifest_digest"] != case["receipt_manifest_digest"]:
            code = "CANARY_MANIFEST_DIGEST_MISMATCH"
        elif len(members) != len(case["manifest_case_results"]) or (
            case["manifest_case_results"]
            != sorted(
                case["manifest_case_results"],
                key=lambda row: canonical_bytes(row["digest"]),
            )
        ):
            code = "CANARY_CASE_RESULT_ORDER_INVALID"
        elif (
            len(manifest_raw) != len(case["manifest_raw_artifact_digests"])
            or case["manifest_raw_artifact_digests"]
            != semantic_set(case["manifest_raw_artifact_digests"])
        ):
            code = "CANARY_RAW_ARTIFACT_ORDER_INVALID"
        elif manifest_raw != {
            digest
            for row in case["manifest_case_results"]
            for digest in row["raw_artifact_digests"]
        }:
            code = "CANARY_RAW_ARTIFACT_UNION_INVALID"
        elif case["manifest_raw_artifact_union_digest"] != hashlib.sha256(
            canonical_bytes(case["manifest_raw_artifact_digests"])
        ).hexdigest():
            code = "CANARY_RAW_ARTIFACT_UNION_DIGEST_MISMATCH"
        elif receipt_passed_ids != {
            row["case_id"]
            for row in case["manifest_case_results"]
            if row["disposition"] == "PASS"
        }:
            code = "CANARY_PASSED_CASE_SET_MISMATCH"
        elif not receipt_passed_ids.issubset(receipt_ids):
            code = "CANARY_PASSED_CASE_NOT_EXECUTED"
        elif not required_ids.issubset(receipt_ids):
            code = "CANARY_REQUIRED_CASE_INCOMPLETE"
        elif claim["claim_result"] == "PROVEN":
            result_digests = claim["supporting_case_result_digests"]
            case_ids = claim["supporting_case_ids"]
            proof_rules = claim["supporting_proof_rule_ids"]
            if not result_digests:
                code = "CLAIM_SUPPORT_EMPTY"
            elif not (len(result_digests) == len(case_ids) == len(proof_rules)):
                code = "CLAIM_SUPPORT_CARDINALITY_MISMATCH"
            elif result_digests != semantic_set(result_digests):
                code = "CLAIM_SUPPORT_ORDER_INVALID"
            for digest, case_id, proof_rule in zip(
                result_digests, case_ids, proof_rules
            ):
                if code is not None:
                    break
                if digest not in members:
                    code = "CLAIM_EVIDENCE_NOT_MEMBER"
                    break
                row = members[digest]
                if row["case_id"] != case_id or case_id not in receipt_ids:
                    code = "CLAIM_CASE_ID_MISMATCH"
                    break
                if row["disposition"] != "PASS":
                    code = "CLAIM_EVIDENCE_NOT_PASS"
                    break
                if case_id not in receipt_passed_ids:
                    code = "CLAIM_CASE_NOT_PASSED_IN_RECEIPT"
                    break
                if proof_rule not in row["satisfied_proof_rule_ids"]:
                    code = "CLAIM_PROOF_RULE_NOT_SATISFIED"
                    break
                if not set(row["raw_artifact_digests"]).issubset(manifest_raw):
                    code = "CLAIM_RAW_ARTIFACT_NOT_MEMBER"
                    break
        if case["valid"] and code:
            raise ConformanceError(f"VALID_CANARY_REJECTED:{case['id']}:{code}")
        if not case["valid"] and code != case["expected_error"]:
            raise ConformanceError(f"NEGATIVE_CANARY_WRONG_RESULT:{case['id']}:{code}")
        count += 1
    return count


def main():
    bundle = load_ascii(SCHEMA_PATH)
    vectors = load_ascii(VECTOR_PATH)
    jsonschema.Draft202012Validator.check_schema(bundle)
    counts = {
        "canonical": validate_canonical_vectors(vectors),
        "schema": validate_schema_vectors(bundle, vectors),
        "joins": validate_join_vectors(vectors),
        "transactions": validate_transactions(vectors),
        "canary": validate_canary(vectors),
    }
    total = sum(counts.values())
    print("R2.3_CONFORMANCE=PASS")
    print("TOTAL_VECTORS=" + str(total))
    for key, value in counts.items():
        print(key.upper() + "_VECTORS=" + str(value))
    print("SCHEMA_SHA256=" + hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest())
    print("VECTORS_SHA256=" + hashlib.sha256(VECTOR_PATH.read_bytes()).hexdigest())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ConformanceError, jsonschema.ValidationError, ValueError) as exc:
        print("R2.3_CONFORMANCE=FAIL", file=sys.stderr)
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
