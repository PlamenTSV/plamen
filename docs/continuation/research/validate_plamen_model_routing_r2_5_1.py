from __future__ import annotations

import ast
import copy
import hashlib
import hmac
import importlib.util
import json
import pickle
import subprocess
import sys
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError


HERE = Path(__file__).resolve().parent
SCHEMA_PATH = HERE / "Plamen_Backend_Model_Routing_R2.5.1_Schemas_2026-07-30.json"
VECTORS_PATH = HERE / "Plamen_Backend_Model_Routing_R2.5.1_Conformance_Vectors_2026-07-30.json"
R2_5_VALIDATOR_PATH = HERE / "validate_plamen_model_routing_r2_5.py"
REVIEW_PATH = (
    HERE.parent
    / "plamen-codex-implementation"
    / "review_fixtures"
    / "backend_model_routing_r2_5_independent_review_r1_20260730.md"
)
SCHEMA_SHA256 = "b70488adaef6b653e3915957fca453e5f5ee9e8b4dc66e425a652743a371d8e3"
VECTORS_SHA256 = "e4e3804b86ab4251902ebdbafc99f5acae3d1409bd56255c730b345fb9c6b9e8"
R2_5_VALIDATOR_SHA256 = "d95b245e41615c988ed529f07c1decbd8f3ac2ed1966661609e2c08efe1217e5"
R2_5_EXPECTED_OUTPUT = {
    "R2.5_CONFORMANCE=PASS",
    "R2_3_PRESERVED_VECTORS=186",
    "R2_4_PRESERVED_TOTAL_VECTORS=314",
    "R2_5_NEW_VECTORS=96",
    "TOTAL_EXECUTED_VECTOR_DENOMINATOR=596",
    "SCHEMA_SHA256=2ff6c92d1d965fef45f539b2102a949c7da66652d7ea4288ee17f29d35dd4806",
    "VECTORS_SHA256=51ffcb40264984033f0150f07f737a01a0077733dd4acdf58a3746fc01fda0ac",
    "AUTHOR_DISPOSITION=SELF_VALIDATED_NOT_INDEPENDENT_PASS",
}
REVIEW_WHOLE_SHA256 = "97db9904fd4aa53161d436206bf558b03df86a60ba512675331c9c43b2842cf8"
REVIEW_BODY_SHA256 = "5b0d5e836b9843c9317bdbb2ef714f39970fa964415a21cea54efec8f53f690f"
HISTORICAL_MANIFEST_SHA256 = "61981cac2042e9c7854737e6de759ef6fae2f3fe7ad405f721b431e8dbceabca"
ADJUDICATED_MANIFEST_SHA256 = "fad68edc4f82e09c0eed8d5bc1139e389e32c70f14efa783bb419d93bcbf8f9b"


class ConformanceError(Exception):
    pass


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_ascii_lf(path: Path) -> bytes:
    raw = path.read_bytes()
    if not raw or not raw.endswith(b"\n"):
        raise ConformanceError("FINAL_LF_REQUIRED")
    if b"\r" in raw:
        raise ConformanceError("CR_BYTE_FORBIDDEN")
    if not raw.isascii():
        raise ConformanceError("NON_ASCII_PACKAGE")
    return raw


def import_exact(path: Path, expected: str, name: str) -> Any:
    raw = path.read_bytes()
    if sha256_bytes(raw) != expected:
        raise ConformanceError(f"{name.upper()}_HASH_MISMATCH")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ConformanceError(f"{name.upper()}_IMPORT_FAILED")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def expect_error(call: Callable[[], Any], expected: str) -> None:
    try:
        call()
    except (ConformanceError, Exception) as exc:
        actual = str(exc)
        if isinstance(exc, ConformanceError):
            actual = str(exc)
        elif exc.__class__.__name__ == "ConformanceError":
            actual = str(exc)
        else:
            raise
        if actual != expected:
            raise ConformanceError(f"EXPECTED_{expected}_GOT_{actual}") from exc
        return
    raise ConformanceError(f"EXPECTED_{expected}_BUT_PASSED")


def schema_validate(
    bundle: dict[str, Any],
    r25: Any,
    definition: str,
    record: dict[str, Any],
) -> None:
    schema = {
        "$schema": bundle["$schema"],
        "$defs": bundle["$defs"],
        "$ref": f"#/$defs/{definition}",
    }
    errors = sorted(
        Draft202012Validator(schema).iter_errors(record),
        key=lambda item: (list(item.absolute_path), item.message),
    )
    if errors:
        error = errors[0]
        if error.validator == "required":
            raise ConformanceError("SCHEMA_REQUIRED_FIELD")
        if error.validator == "additionalProperties":
            raise ConformanceError("SCHEMA_UNKNOWN_FIELD")
        raise ConformanceError("SCHEMA_VALIDATION_ERROR")
    r25.check_value(record)


def seal(r25: Any, record: dict[str, Any], field: str) -> dict[str, Any]:
    return r25.seal(record, field)


def verify_seal(r25: Any, record: dict[str, Any], field: str) -> None:
    try:
        r25.verify_seal(record, field)
    except Exception as exc:
        if str(exc) == "RECORD_SELF_DIGEST_MISMATCH":
            raise ConformanceError("RECORD_SELF_DIGEST_MISMATCH") from exc
        raise


_STORE_ISSUER = object()
_TRUST_ANCHOR_ISSUER = object()


class TrustAnchorCapabilityV1:
    __slots__ = (
        "_issuer",
        "_snapshot_digest",
        "_revision",
        "_source_identity",
    )

    def __init__(
        self,
        _token: object,
        snapshot_digest: str,
        revision: int,
        source_identity: str,
    ) -> None:
        if _token is not _TRUST_ANCHOR_ISSUER:
            raise ConformanceError("AUTHORITY_STORE_UNTRUSTED")
        object.__setattr__(self, "_issuer", _TRUST_ANCHOR_ISSUER)
        object.__setattr__(self, "_snapshot_digest", snapshot_digest)
        object.__setattr__(self, "_revision", revision)
        object.__setattr__(self, "_source_identity", source_identity)

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("TrustAnchorCapabilityV1 is immutable")

    def __copy__(self) -> Any:
        raise TypeError("TrustAnchorCapabilityV1 is not copyable")

    def __deepcopy__(self, _memo: Any) -> Any:
        raise TypeError("TrustAnchorCapabilityV1 is not copyable")

    def __reduce__(self) -> Any:
        raise TypeError("TrustAnchorCapabilityV1 is not serializable")


class TrustedAuthorityStoreV1:
    __slots__ = (
        "_issuer",
        "_snapshot",
        "_snapshot_digest",
        "_revision",
        "_anchor",
        "_sealed",
    )

    def __init__(
        self,
        _token: object,
        snapshot: dict[str, dict[str, Any]],
        anchor: TrustAnchorCapabilityV1,
    ) -> None:
        if (
            _token is not _STORE_ISSUER
            or not isinstance(anchor, TrustAnchorCapabilityV1)
            or anchor._issuer is not _TRUST_ANCHOR_ISSUER
        ):
            raise ConformanceError("AUTHORITY_STORE_UNTRUSTED")
        frozen = copy.deepcopy(snapshot)
        digest = sha256_bytes(canonical_store_bytes(frozen))
        if digest != anchor._snapshot_digest:
            raise ConformanceError("AUTHORITY_STORE_UNTRUSTED")
        object.__setattr__(self, "_issuer", _STORE_ISSUER)
        object.__setattr__(self, "_snapshot", MappingProxyType(frozen))
        object.__setattr__(self, "_snapshot_digest", digest)
        object.__setattr__(self, "_revision", anchor._revision)
        object.__setattr__(self, "_anchor", anchor)
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("TrustedAuthorityStoreV1 is immutable")

    def __copy__(self) -> Any:
        raise TypeError("TrustedAuthorityStoreV1 is not copyable")

    def __deepcopy__(self, _memo: Any) -> Any:
        raise TypeError("TrustedAuthorityStoreV1 is not copyable")

    def __reduce__(self) -> Any:
        raise TypeError("TrustedAuthorityStoreV1 is not serializable")

    def __repr__(self) -> str:
        return "TrustedAuthorityStoreV1(<trusted snapshot>)"

    @property
    def revision(self) -> int:
        return self._revision

    @property
    def snapshot_digest(self) -> str:
        return self._snapshot_digest

    def load(self, key: str) -> dict[str, Any]:
        if self._issuer is not _STORE_ISSUER:
            raise ConformanceError("AUTHORITY_STORE_UNTRUSTED")
        try:
            return copy.deepcopy(self._snapshot[key])
        except KeyError as exc:
            raise ConformanceError("AUTHORITY_STORE_KEY_MISMATCH") from exc


def canonical_store_bytes(snapshot: dict[str, dict[str, Any]]) -> bytes:
    return json.dumps(
        snapshot,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _establish_fixture_trust_anchor(
    snapshot: dict[str, dict[str, Any]], revision: int = 1
) -> TrustAnchorCapabilityV1:
    return TrustAnchorCapabilityV1(
        _TRUST_ANCHOR_ISSUER,
        sha256_bytes(canonical_store_bytes(snapshot)),
        revision,
        "OUT_OF_TREE_GOVERNED_PREIMAGE_FIXTURE",
    )


def open_trusted_store(
    snapshot: dict[str, dict[str, Any]],
    anchor: TrustAnchorCapabilityV1,
) -> TrustedAuthorityStoreV1:
    return TrustedAuthorityStoreV1(_STORE_ISSUER, snapshot, anchor)


def _fixture_trusted_store(
    snapshot: dict[str, dict[str, Any]], revision: int = 1
) -> TrustedAuthorityStoreV1:
    anchor = _establish_fixture_trust_anchor(snapshot, revision)
    return open_trusted_store(snapshot, anchor)


def validate_store(store: TrustedAuthorityStoreV1) -> None:
    if (
        not isinstance(store, TrustedAuthorityStoreV1)
        or store._issuer is not _STORE_ISSUER
        or not isinstance(store._anchor, TrustAnchorCapabilityV1)
        or store._anchor._issuer is not _TRUST_ANCHOR_ISSUER
        or store.snapshot_digest != store._anchor._snapshot_digest
        or store.revision != store._anchor._revision
        or sha256_bytes(canonical_store_bytes(dict(store._snapshot)))
        != store.snapshot_digest
    ):
        raise ConformanceError("AUTHORITY_STORE_UNTRUSTED")


def authority_record(
    r25: Any,
    schema: str,
    fields: dict[str, Any],
) -> dict[str, Any]:
    record = {"schema": schema, "version": 1, "authority_digest": r25.d("0")}
    record.update(fields)
    return seal(r25, record, "authority_digest")


def build_persisted_authorities(
    bundle: dict[str, Any],
    r25: Any,
    records: dict[str, Any],
    prior_identity: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    tx = records["transaction"]
    run_id = "r2-5-1-conformance-run"
    generation = tx["generation"]
    attempt_ordinal = records["attempt"]["attempt_ordinal"]
    reservation = authority_record(
        r25,
        "plamen.reservation-parent.v1",
        {
            "run_id": run_id,
            "generation": generation,
            "attempt_ordinal": attempt_ordinal,
            "generation_reservation_event_digest": tx[
                "generation_reservation_event_digest"
            ],
            "attempt_reservation_event_digest": tx[
                "attempt_reservation_event_digest"
            ],
            "attempt_resource_entry_digest": tx[
                "attempt_resource_entry_digest"
            ],
            "resource_ledger_digest_after_attempt_reservation": tx[
                "resource_ledger_digest_after_attempt_reservation"
            ],
        },
    )
    materialization = authority_record(
        r25,
        "plamen.materialization-parent.v1",
        {
            "run_id": run_id,
            "generation": generation,
            "attempt_ordinal": attempt_ordinal,
            "materialized_stdin_prompt_digest": tx[
                "materialized_stdin_prompt_digest"
            ],
            "working_directory_identity_digest": tx[
                "working_directory_identity_digest"
            ],
            "prepared_utc": tx["prepared_utc"],
        },
    )
    consumption = authority_record(
        r25,
        "plamen.consumption-parent.v1",
        {
            "run_id": run_id,
            "generation": generation,
            "attempt_ordinal": attempt_ordinal,
            "launch_consumption_event_digest": tx[
                "launch_consumption_event_digest"
            ],
            "consumed_attempt_resource_entry_digest": tx[
                "consumed_attempt_resource_entry_digest"
            ],
            "resource_ledger_digest_after_launch_consumption": tx[
                "resource_ledger_digest_after_launch_consumption"
            ],
            "consume_cas_revision": tx["consume_cas_revision"],
        },
    )
    reconciliation = authority_record(
        r25,
        "plamen.reconciliation-parent.v1",
        {
            "run_id": run_id,
            "generation": generation,
            "attempt_ordinal": attempt_ordinal,
            "reconciliation_receipt_digest": tx[
                "reconciliation_receipt_digest"
            ],
            "incorporated_output_set_digest": tx[
                "incorporated_output_set_digest"
            ],
        },
    )
    transaction_set = authority_record(
        r25,
        "plamen.transaction-parent-set.v1",
        {
            "store_key": "transaction/current",
            "store_revision": 1,
            "run_id": run_id,
            "generation": generation,
            "attempt_ordinal": attempt_ordinal,
            "work_plan_digest": tx["work_plan_digest"],
            "phase_io_launch_digest": tx["phase_io_launch_digest"],
            "reservation_parent_digest": reservation["authority_digest"],
            "materialization_parent_digest": materialization[
                "authority_digest"
            ],
            "consumption_parent_digest": consumption["authority_digest"],
            "reconciliation_parent_digest": reconciliation[
                "authority_digest"
            ],
        },
    )
    root = authority_record(
        r25,
        "plamen.root-preimage-authority.v1",
        {
            "store_key": "root/current",
            "store_revision": 1,
            "expected_routing_root_digest": records["root"][
                "routing_root_digest"
            ],
        },
    )
    identity = (
        copy.deepcopy(prior_identity)
        if prior_identity is not None
        else r25.resume_identity(records)
    )
    prior = authority_record(
        r25,
        "plamen.prior-resume-identity-authority.v1",
        {
            "store_key": "resume/prior",
            "store_revision": 1,
            "run_id": run_id,
            "generation": generation,
            "attempt_ordinal": attempt_ordinal,
            "identity_vector": identity,
            "identity_vector_digest": identity["identity_vector_digest"],
        },
    )
    rows = []
    for field, rule, kind in (
        ("effective_model_id", "LAUNCH_FRAME_EXACT", "launch"),
        ("effective_effort", "LAUNCH_FRAME_EXACT", "launch"),
        ("thinking_state", "LAUNCH_FRAME_EXACT", "launch"),
        ("fallback_state", "TERMINAL_FRAME_EXACT", "terminal"),
        ("terminal_category", "TERMINAL_FRAME_EXACT", "terminal"),
    ):
        rows.append(
            seal(
                r25,
                {
                    "row_digest": r25.d("0"),
                    "field_name": field,
                    "proof_rule_id": rule,
                    "frame_kind": kind,
                },
                "row_digest",
            )
        )
    rules = authority_record(
        r25,
        "plamen.observation-proof-rule-authority.v1",
        {
            "store_key": "observation/rules",
            "store_revision": 1,
            "row_count": 5,
            "rows": rows,
        },
    )
    snapshot = {
        "root/current": root,
        "transaction/current": transaction_set,
        "transaction/reservation": reservation,
        "transaction/materialization": materialization,
        "transaction/consumption": consumption,
        "transaction/reconciliation": reconciliation,
        "resume/prior": prior,
        "observation/rules": rules,
    }
    validate_persisted_snapshot(bundle, r25, snapshot)
    return snapshot


PERSISTED_SCHEMAS = {
    "root/current": "RootPreimageAuthorityV1",
    "transaction/current": "TransactionParentSetV1",
    "transaction/reservation": "ReservationParentV1",
    "transaction/materialization": "MaterializationParentV1",
    "transaction/consumption": "ConsumptionParentV1",
    "transaction/reconciliation": "ReconciliationParentV1",
    "resume/prior": "PriorResumeIdentityAuthorityV1",
    "observation/rules": "ObservationProofRuleAuthorityV1",
}


def validate_persisted_snapshot(
    bundle: dict[str, Any],
    r25: Any,
    snapshot: dict[str, dict[str, Any]],
) -> None:
    for key, definition in PERSISTED_SCHEMAS.items():
        if key not in snapshot:
            raise ConformanceError("AUTHORITY_STORE_KEY_MISMATCH")
        record = snapshot[key]
        schema_validate(bundle, r25, definition, record)
        verify_seal(r25, record, "authority_digest")
        if definition == "ObservationProofRuleAuthorityV1":
            fields = [row["field_name"] for row in record["rows"]]
            if fields != [
                "effective_model_id",
                "effective_effort",
                "thinking_state",
                "fallback_state",
                "terminal_category",
            ]:
                raise ConformanceError("OBSERVATION_PROOF_RULE_MISMATCH")
            for row in record["rows"]:
                verify_seal(r25, row, "row_digest")


def flatten_transaction_parents(
    bundle: dict[str, Any],
    r25: Any,
    store: TrustedAuthorityStoreV1,
    records: dict[str, Any],
) -> dict[str, Any]:
    validate_store(store)
    current = store.load("transaction/current")
    reservation = store.load("transaction/reservation")
    materialization = store.load("transaction/materialization")
    consumption = store.load("transaction/consumption")
    reconciliation = store.load("transaction/reconciliation")
    for definition, record in (
        ("TransactionParentSetV1", current),
        ("ReservationParentV1", reservation),
        ("MaterializationParentV1", materialization),
        ("ConsumptionParentV1", consumption),
        ("ReconciliationParentV1", reconciliation),
    ):
        schema_validate(bundle, r25, definition, record)
        verify_seal(r25, record, "authority_digest")
    if current["store_revision"] != store.revision:
        raise ConformanceError("TRANSACTION_STALE_PARENT")
    for parent in (reservation, materialization, consumption, reconciliation):
        if (
            parent["run_id"] != current["run_id"]
            or parent["generation"] != current["generation"]
            or parent["attempt_ordinal"] != current["attempt_ordinal"]
        ):
            raise ConformanceError("TRANSACTION_GENERATION_MISMATCH")
    for field, parent in (
        ("reservation_parent_digest", reservation),
        ("materialization_parent_digest", materialization),
        ("consumption_parent_digest", consumption),
        ("reconciliation_parent_digest", reconciliation),
    ):
        if current[field] != parent["authority_digest"]:
            raise ConformanceError("TRANSACTION_STORE_MISMATCH")
    actual_generation = records["launch"]["generation"]
    actual_attempt = records["attempt"]["attempt_ordinal"]
    if (
        current["generation"] != actual_generation
        or current["attempt_ordinal"] != actual_attempt
    ):
        raise ConformanceError("TRANSACTION_GENERATION_MISMATCH")
    expected_children = {
        "work_plan_digest": records["work"]["work_plan_digest"],
        "phase_io_launch_digest": records["phaseio"][
            "phase_io_launch_digest"
        ],
        "prepared_utc": records["envelope"]["prepared_utc"],
        "generation_reservation_event_digest": records["launch"][
            "generation_reservation_event_digest"
        ],
        "attempt_reservation_event_digest": records["envelope"][
            "attempt_reservation_event_digest"
        ],
        "attempt_resource_entry_digest": records["envelope"][
            "attempt_resource_entry_digest"
        ],
        "resource_ledger_digest_after_attempt_reservation": records["envelope"][
            "resource_ledger_digest_after_attempt_reservation"
        ],
        "materialized_stdin_prompt_digest": records["envelope"][
            "materialized_stdin_prompt_digest"
        ],
        "working_directory_identity_digest": records["envelope"][
            "working_directory_identity_digest"
        ],
        "launch_consumption_event_digest": records["consumed"][
            "launch_consumption_event_digest"
        ],
        "consumed_attempt_resource_entry_digest": records["consumed"][
            "consumed_attempt_resource_entry_digest"
        ],
        "resource_ledger_digest_after_launch_consumption": records["consumed"][
            "resource_ledger_digest_after_launch_consumption"
        ],
        "consume_cas_revision": records["consumed"]["consume_cas_revision"],
    }
    actual_parents = {
        "work_plan_digest": current["work_plan_digest"],
        "phase_io_launch_digest": current["phase_io_launch_digest"],
        "prepared_utc": materialization["prepared_utc"],
        "materialized_stdin_prompt_digest": materialization[
            "materialized_stdin_prompt_digest"
        ],
        "working_directory_identity_digest": materialization[
            "working_directory_identity_digest"
        ],
        "generation_reservation_event_digest": reservation[
            "generation_reservation_event_digest"
        ],
        "attempt_reservation_event_digest": reservation[
            "attempt_reservation_event_digest"
        ],
        "attempt_resource_entry_digest": reservation[
            "attempt_resource_entry_digest"
        ],
        "resource_ledger_digest_after_attempt_reservation": reservation[
            "resource_ledger_digest_after_attempt_reservation"
        ],
        "launch_consumption_event_digest": consumption[
            "launch_consumption_event_digest"
        ],
        "consumed_attempt_resource_entry_digest": consumption[
            "consumed_attempt_resource_entry_digest"
        ],
        "resource_ledger_digest_after_launch_consumption": consumption[
            "resource_ledger_digest_after_launch_consumption"
        ],
        "consume_cas_revision": consumption["consume_cas_revision"],
    }
    if actual_parents != expected_children:
        raise ConformanceError("TRANSACTION_STORE_MISMATCH")
    return {
        "work_plan_digest": current["work_plan_digest"],
        "phase_io_launch_digest": current["phase_io_launch_digest"],
        "generation": current["generation"],
        "generation_reservation_event_digest": reservation[
            "generation_reservation_event_digest"
        ],
        "attempt_reservation_event_digest": reservation[
            "attempt_reservation_event_digest"
        ],
        "attempt_resource_entry_digest": reservation[
            "attempt_resource_entry_digest"
        ],
        "resource_ledger_digest_after_attempt_reservation": reservation[
            "resource_ledger_digest_after_attempt_reservation"
        ],
        "launch_consumption_event_digest": consumption[
            "launch_consumption_event_digest"
        ],
        "consumed_attempt_resource_entry_digest": consumption[
            "consumed_attempt_resource_entry_digest"
        ],
        "resource_ledger_digest_after_launch_consumption": consumption[
            "resource_ledger_digest_after_launch_consumption"
        ],
        "consume_cas_revision": consumption["consume_cas_revision"],
        "materialized_stdin_prompt_digest": materialization[
            "materialized_stdin_prompt_digest"
        ],
        "working_directory_identity_digest": materialization[
            "working_directory_identity_digest"
        ],
        "prepared_utc": materialization["prepared_utc"],
        "reconciliation_receipt_digest": reconciliation[
            "reconciliation_receipt_digest"
        ],
        "incorporated_output_set_digest": reconciliation[
            "incorporated_output_set_digest"
        ],
    }


def candidate_closure(records: dict[str, Any]) -> dict[str, Any]:
    candidate = copy.deepcopy(records)
    candidate.pop("frozen_root_digest", None)
    candidate.pop("transaction", None)
    return candidate


def validate_closure_v251(
    bundle: dict[str, Any],
    r25: Any,
    candidate: dict[str, Any],
    store: TrustedAuthorityStoreV1,
) -> dict[str, Any]:
    if "frozen_root_digest" in candidate or "transaction" in candidate:
        raise ConformanceError("CANDIDATE_EMBEDDED_ANCHOR_FORBIDDEN")
    validate_store(store)
    root_preimage = store.load("root/current")
    schema_validate(bundle, r25, "RootPreimageAuthorityV1", root_preimage)
    verify_seal(r25, root_preimage, "authority_digest")
    if root_preimage["store_revision"] != store.revision:
        raise ConformanceError("AUTHORITY_STORE_REVISION_MISMATCH")
    if root_preimage["store_key"] != "root/current":
        raise ConformanceError("AUTHORITY_STORE_KEY_MISMATCH")
    if (
        root_preimage["expected_routing_root_digest"]
        != candidate["root"]["routing_root_digest"]
    ):
        raise ConformanceError("ROOT_PREIMAGE_STORE_MISMATCH")
    records = copy.deepcopy(candidate)
    records["frozen_root_digest"] = root_preimage[
        "expected_routing_root_digest"
    ]
    records["transaction"] = flatten_transaction_parents(
        bundle, r25, store, records
    )
    try:
        r25.validate_closure(bundle, records)
    except Exception as exc:
        raise ConformanceError(str(exc)) from exc
    return records


_PROOF_ISSUER = object()
_SPAWN_ISSUER = object()


class VerifiedSecretProofCapabilityV3:
    __slots__ = (
        "_issuer",
        "_envelope_digest",
        "_predecessor_digest",
        "_policy_digest",
        "_secret_set_digest",
        "_attempt_digest",
        "_consumed_digest",
        "_process_nonce_digest",
        "_object_nonce_digest",
        "_tag",
    )

    def __init__(
        self,
        _token: object,
        *,
        envelope_digest: str,
        predecessor_digest: str,
        policy_digest: str,
        secret_set_digest: str,
        attempt_digest: str,
        consumed_digest: str,
        process_nonce_digest: str,
        object_nonce_digest: str,
        tag: bytes,
    ) -> None:
        if _token is not _PROOF_ISSUER:
            raise ConformanceError("PROOF_CONSTRUCTOR_PRIVATE")
        object.__setattr__(self, "_issuer", _PROOF_ISSUER)
        object.__setattr__(self, "_envelope_digest", envelope_digest)
        object.__setattr__(self, "_predecessor_digest", predecessor_digest)
        object.__setattr__(self, "_policy_digest", policy_digest)
        object.__setattr__(self, "_secret_set_digest", secret_set_digest)
        object.__setattr__(self, "_attempt_digest", attempt_digest)
        object.__setattr__(self, "_consumed_digest", consumed_digest)
        object.__setattr__(self, "_process_nonce_digest", process_nonce_digest)
        object.__setattr__(self, "_object_nonce_digest", object_nonce_digest)
        object.__setattr__(self, "_tag", bytes(tag))

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("VerifiedSecretProofCapabilityV3 is immutable")

    def __copy__(self) -> Any:
        raise ConformanceError("PROOF_COPY_FORBIDDEN")

    def __deepcopy__(self, _memo: Any) -> Any:
        raise ConformanceError("PROOF_COPY_FORBIDDEN")

    def __reduce__(self) -> Any:
        raise TypeError("VerifiedSecretProofCapabilityV3 is not serializable")

    def __repr__(self) -> str:
        return "VerifiedSecretProofCapabilityV3(<redacted>)"


class VerifiedSpawnCapabilityV3:
    __slots__ = ("_issuer", "_proof", "_authority")

    def __init__(
        self,
        _token: object,
        proof: VerifiedSecretProofCapabilityV3,
        authority: dict[str, str],
    ) -> None:
        if _token is not _SPAWN_ISSUER:
            raise ConformanceError("SPAWN_CAPABILITY_CONSTRUCTOR_PRIVATE")
        object.__setattr__(self, "_issuer", _SPAWN_ISSUER)
        object.__setattr__(self, "_proof", proof)
        object.__setattr__(
            self, "_authority", MappingProxyType(copy.deepcopy(authority))
        )

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("VerifiedSpawnCapabilityV3 is immutable")

    def __copy__(self) -> Any:
        raise TypeError("VerifiedSpawnCapabilityV3 is not copyable")

    def __deepcopy__(self, _memo: Any) -> Any:
        raise TypeError("VerifiedSpawnCapabilityV3 is not copyable")

    def __reduce__(self) -> Any:
        raise TypeError("VerifiedSpawnCapabilityV3 is not serializable")

    def __reduce__(self) -> Any:
        raise TypeError("VerifiedSpawnCapabilityV3 is not serializable")


def secret_set_digest(
    r25: Any, policy: dict[str, Any], raw_env: dict[str, str]
) -> str:
    windows = policy["host_family"] == "windows"
    folded = {
        (name.upper() if windows else name): value
        for name, value in raw_env.items()
    }
    rows = []
    for row in policy["rows"]:
        if row["secrecy_class"] != "SECRET":
            continue
        key = row["name"].upper() if windows else row["name"]
        if key not in folded:
            raise ConformanceError("ENVIRONMENT_PRESENCE_MISMATCH")
        rows.append(
            {
                "name": row["name"],
                "value_digest": sha256_bytes(folded[key].encode("utf-8")),
            }
        )
    if not rows:
        raise ConformanceError("SECRET_SET_EMPTY")
    return sha256_bytes(r25.canonical_bytes(rows))


def proof_expected_tag(
    r25: Any,
    envelope: dict[str, Any],
    predecessor: dict[str, Any],
    policy: dict[str, Any],
    raw_env: dict[str, str],
    process_nonce: bytes,
    object_nonce: bytes,
    key: bytes,
) -> bytes:
    if len(key) != 32:
        raise ConformanceError("PROOF_KEY_LENGTH_INVALID")
    try:
        payload = r25.EphemeralSecretProofV2._payload(
            envelope,
            predecessor,
            policy,
            raw_env,
            process_nonce,
            object_nonce,
        )
    except Exception as exc:
        raise ConformanceError(str(exc)) from exc
    return hmac.new(key, payload, hashlib.sha256).digest()


def mint_verified_secret_proof(
    r25: Any,
    envelope: dict[str, Any],
    predecessor: dict[str, Any],
    policy: dict[str, Any],
    raw_env: dict[str, str],
    process_nonce: bytes,
    object_nonce: bytes,
    key: bytes,
    consumed: dict[str, Any],
) -> VerifiedSecretProofCapabilityV3:
    if (
        consumed["attempt_launch_digest"] != envelope["attempt_launch_digest"]
        or consumed["execution_attempt_digest"]
        != envelope["execution_attempt_digest"]
    ):
        raise ConformanceError("SECRET_PROOF_ATTEMPT_MISMATCH")
    secret_digest = secret_set_digest(r25, policy, raw_env)
    tag = proof_expected_tag(
        r25,
        envelope,
        predecessor,
        policy,
        raw_env,
        process_nonce,
        object_nonce,
        key,
    )
    return VerifiedSecretProofCapabilityV3(
        _PROOF_ISSUER,
        envelope_digest=envelope["attempt_launch_digest"],
        predecessor_digest=predecessor["attempt_launch_digest"],
        policy_digest=policy["environment_policy_authority_digest"],
        secret_set_digest=secret_digest,
        attempt_digest=envelope["execution_attempt_digest"],
        consumed_digest=consumed["consumed_launch_digest"],
        process_nonce_digest=sha256_bytes(process_nonce),
        object_nonce_digest=sha256_bytes(object_nonce),
        tag=tag,
    )


def verify_secret_proof_at_sink(
    r25: Any,
    proof: VerifiedSecretProofCapabilityV3,
    envelope: dict[str, Any],
    predecessor: dict[str, Any],
    policy: dict[str, Any],
    raw_env: dict[str, str],
    process_nonce: bytes,
    object_nonce: bytes,
    key: bytes,
    consumed: dict[str, Any],
) -> None:
    if (
        not isinstance(proof, VerifiedSecretProofCapabilityV3)
        or proof._issuer is not _PROOF_ISSUER
    ):
        raise ConformanceError("PROOF_CONSTRUCTOR_PRIVATE")
    if proof._envelope_digest != envelope["attempt_launch_digest"]:
        raise ConformanceError("SECRET_PROOF_ATTEMPT_MISMATCH")
    if proof._predecessor_digest != predecessor["attempt_launch_digest"]:
        raise ConformanceError("SECRET_PROOF_V3_MISMATCH")
    if (
        proof._policy_digest
        != policy["environment_policy_authority_digest"]
    ):
        raise ConformanceError("SECRET_PROOF_POLICY_MISMATCH")
    if (
        proof._attempt_digest != envelope["execution_attempt_digest"]
        or proof._consumed_digest != consumed["consumed_launch_digest"]
        or consumed["attempt_launch_digest"]
        != envelope["attempt_launch_digest"]
    ):
        raise ConformanceError("SECRET_PROOF_ATTEMPT_MISMATCH")
    if (
        proof._process_nonce_digest != sha256_bytes(process_nonce)
        or proof._object_nonce_digest != sha256_bytes(object_nonce)
        or proof._secret_set_digest != secret_set_digest(r25, policy, raw_env)
    ):
        raise ConformanceError("SECRET_PROOF_HMAC_MISMATCH")
    expected = proof_expected_tag(
        r25,
        envelope,
        predecessor,
        policy,
        raw_env,
        process_nonce,
        object_nonce,
        key,
    )
    if not hmac.compare_digest(proof._tag, expected):
        raise ConformanceError("SECRET_PROOF_HMAC_MISMATCH")


def mint_verified_spawn_capability(
    r25: Any,
    proof: VerifiedSecretProofCapabilityV3,
    envelope: dict[str, Any],
    predecessor: dict[str, Any],
    policy: dict[str, Any],
    raw_env: dict[str, str],
    process_nonce: bytes,
    object_nonce: bytes,
    key: bytes,
    consumed: dict[str, Any],
) -> VerifiedSpawnCapabilityV3:
    verify_secret_proof_at_sink(
        r25,
        proof,
        envelope,
        predecessor,
        policy,
        raw_env,
        process_nonce,
        object_nonce,
        key,
        consumed,
    )
    return VerifiedSpawnCapabilityV3(
        _SPAWN_ISSUER,
        proof,
        {
            "attempt_launch_digest": envelope["attempt_launch_digest"],
            "predecessor_digest": predecessor["attempt_launch_digest"],
            "policy_digest": policy["environment_policy_authority_digest"],
            "execution_attempt_digest": envelope[
                "execution_attempt_digest"
            ],
            "consumed_launch_digest": consumed["consumed_launch_digest"],
        },
    )


def validate_verified_spawn_capability(
    r25: Any,
    capability: VerifiedSpawnCapabilityV3,
    envelope: dict[str, Any],
    predecessor: dict[str, Any],
    policy: dict[str, Any],
    raw_env: dict[str, str],
    process_nonce: bytes,
    object_nonce: bytes,
    key: bytes,
    consumed: dict[str, Any],
) -> None:
    if (
        not isinstance(capability, VerifiedSpawnCapabilityV3)
        or capability._issuer is not _SPAWN_ISSUER
    ):
        raise ConformanceError("SPAWN_CAPABILITY_CONSTRUCTOR_PRIVATE")
    verify_secret_proof_at_sink(
        r25,
        capability._proof,
        envelope,
        predecessor,
        policy,
        raw_env,
        process_nonce,
        object_nonce,
        key,
        consumed,
    )
    expected = {
        "attempt_launch_digest": envelope["attempt_launch_digest"],
        "predecessor_digest": predecessor["attempt_launch_digest"],
        "policy_digest": policy["environment_policy_authority_digest"],
        "execution_attempt_digest": envelope["execution_attempt_digest"],
        "consumed_launch_digest": consumed["consumed_launch_digest"],
    }
    if dict(capability._authority) != expected:
        raise ConformanceError("SECRET_PROOF_ATTEMPT_MISMATCH")


def load_prior_resume_identity(
    bundle: dict[str, Any],
    r25: Any,
    store: TrustedAuthorityStoreV1,
    key: str = "resume/prior",
) -> tuple[dict[str, Any], dict[str, Any]]:
    validate_store(store)
    record = store.load(key)
    schema_validate(bundle, r25, "PriorResumeIdentityAuthorityV1", record)
    verify_seal(r25, record, "authority_digest")
    if record["store_key"] != key:
        raise ConformanceError("AUTHORITY_STORE_KEY_MISMATCH")
    if record["store_revision"] != store.revision:
        raise ConformanceError("AUTHORITY_STORE_REVISION_MISMATCH")
    identity = record["identity_vector"]
    try:
        r25.schema_validate(
            bundle, "ResumeIdentityVectorV2", identity
        )
        r25.verify_seal(identity, "identity_vector_digest")
    except Exception as exc:
        raise ConformanceError(str(exc)) from exc
    if record["identity_vector_digest"] != identity["identity_vector_digest"]:
        raise ConformanceError("RESUME_PRIOR_STORE_MISMATCH")
    return record, identity


def validate_resume_v251(
    bundle: dict[str, Any],
    r25: Any,
    authority: dict[str, Any],
    store: TrustedAuthorityStoreV1,
    records: dict[str, Any],
    completed: dict[str, Any] | None,
    ambiguous: dict[str, Any] | None,
    *,
    caller_before: dict[str, Any] | None = None,
    caller_after: dict[str, Any] | None = None,
    prior_key: str = "resume/prior",
) -> None:
    if caller_before is not None or caller_after is not None:
        raise ConformanceError("RESUME_CALLER_VECTOR_FORBIDDEN")
    record, before = load_prior_resume_identity(
        bundle, r25, store, prior_key
    )
    after = r25.resume_identity(records)
    if (
        authority["before_identity_vector_digest"]
        != before["identity_vector_digest"]
    ):
        raise ConformanceError("RESUME_PRIOR_STORE_MISMATCH")
    if (
        authority["after_identity_vector_digest"]
        != after["identity_vector_digest"]
    ):
        raise ConformanceError("RESUME_CURRENT_ACTUAL_MISMATCH")
    if (
        authority["prior_generation"] != record["generation"]
        or authority["prior_attempt_ordinal"] != record["attempt_ordinal"]
    ):
        raise ConformanceError("RESUME_PRIOR_STORE_MISMATCH")
    try:
        r25.validate_resume(
            bundle,
            authority,
            before,
            after,
            records,
            completed,
            ambiguous,
        )
    except Exception as exc:
        raise ConformanceError(str(exc)) from exc


_TRANSPORT_RECEIPT_ISSUER = object()
_PROVIDER_ARTIFACT_ISSUER = object()


class TransportArtifactReceiptCapabilityV1:
    __slots__ = (
        "_issuer",
        "_raw_digest",
        "_attempt_digest",
        "_source_identity",
    )

    def __init__(
        self,
        _token: object,
        raw_digest: str,
        attempt_digest: str,
        source_identity: str,
    ) -> None:
        if _token is not _TRANSPORT_RECEIPT_ISSUER:
            raise ConformanceError("PROVIDER_ARTIFACT_UNTRUSTED")
        object.__setattr__(self, "_issuer", _TRANSPORT_RECEIPT_ISSUER)
        object.__setattr__(self, "_raw_digest", raw_digest)
        object.__setattr__(self, "_attempt_digest", attempt_digest)
        object.__setattr__(self, "_source_identity", source_identity)

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("TransportArtifactReceiptCapabilityV1 is immutable")

    def __copy__(self) -> Any:
        raise TypeError("TransportArtifactReceiptCapabilityV1 is not copyable")

    def __deepcopy__(self, _memo: Any) -> Any:
        raise TypeError("TransportArtifactReceiptCapabilityV1 is not copyable")

    def __reduce__(self) -> Any:
        raise TypeError(
            "TransportArtifactReceiptCapabilityV1 is not serializable"
        )


class ImmutableProviderArtifactBytesV1:
    __slots__ = ("_issuer", "_raw", "_receipt")

    def __init__(
        self,
        _token: object,
        raw: bytes,
        receipt: TransportArtifactReceiptCapabilityV1,
    ) -> None:
        if (
            _token is not _PROVIDER_ARTIFACT_ISSUER
            or not isinstance(receipt, TransportArtifactReceiptCapabilityV1)
            or receipt._issuer is not _TRANSPORT_RECEIPT_ISSUER
            or sha256_bytes(raw) != receipt._raw_digest
        ):
            raise ConformanceError("PROVIDER_ARTIFACT_DIGEST_MISMATCH")
        object.__setattr__(self, "_issuer", _PROVIDER_ARTIFACT_ISSUER)
        object.__setattr__(self, "_raw", bytes(raw))
        object.__setattr__(self, "_receipt", receipt)

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("ImmutableProviderArtifactBytesV1 is immutable")

    def __copy__(self) -> Any:
        raise TypeError("ImmutableProviderArtifactBytesV1 is not copyable")

    def __deepcopy__(self, _memo: Any) -> Any:
        raise TypeError("ImmutableProviderArtifactBytesV1 is not copyable")

    def __reduce__(self) -> Any:
        raise TypeError("ImmutableProviderArtifactBytesV1 is not serializable")

    def __repr__(self) -> str:
        return "ImmutableProviderArtifactBytesV1(<immutable provider bytes>)"


def _establish_fixture_transport_receipt(
    raw: bytes, attempt_digest: str
) -> TransportArtifactReceiptCapabilityV1:
    return TransportArtifactReceiptCapabilityV1(
        _TRANSPORT_RECEIPT_ISSUER,
        sha256_bytes(raw),
        attempt_digest,
        "NEUTRAL_TRANSPORT_SPOOL_FIXTURE",
    )


def ingest_provider_artifact(
    raw: bytes, receipt: TransportArtifactReceiptCapabilityV1
) -> ImmutableProviderArtifactBytesV1:
    return ImmutableProviderArtifactBytesV1(
        _PROVIDER_ARTIFACT_ISSUER, raw, receipt
    )


def _fixture_provider_artifact(
    raw: bytes, attempt_digest: str
) -> ImmutableProviderArtifactBytesV1:
    receipt = _establish_fixture_transport_receipt(raw, attempt_digest)
    return ingest_provider_artifact(raw, receipt)


def validate_provider_artifact_input(
    artifact: ImmutableProviderArtifactBytesV1,
    expected_attempt_digest: str,
) -> bytes:
    if (
        not isinstance(artifact, ImmutableProviderArtifactBytesV1)
        or artifact._issuer is not _PROVIDER_ARTIFACT_ISSUER
        or artifact._receipt._issuer is not _TRANSPORT_RECEIPT_ISSUER
        or sha256_bytes(artifact._raw) != artifact._receipt._raw_digest
    ):
        raise ConformanceError("PROVIDER_ARTIFACT_UNTRUSTED")
    if artifact._receipt._attempt_digest != expected_attempt_digest:
        raise ConformanceError("PROVIDER_ATTEMPT_MISMATCH")
    return artifact._raw


def provider_stream_bytes(
    r25: Any,
    records: dict[str, Any],
    *,
    stream_id: str = "provider-stream-1",
) -> bytes:
    effort = records["route"]["requested_effort"] or "not_applicable"
    launch = {
        "stream_id": stream_id,
        "seq": 0,
        "kind": "launch",
        "attempt_digest": records["attempt"]["execution_attempt_digest"],
        "effective_model_id": records["route"]["exact_requested_model_id"],
        "effective_effort": effort,
        "thinking_state":
            records["route"]["requested_thinking_mode"] + "_CONFIRMED",
    }
    terminal = {
        "stream_id": stream_id,
        "seq": 1,
        "kind": "terminal",
        "attempt_digest": records["attempt"]["execution_attempt_digest"],
        "fallback_state": "NO_FALLBACK_CONFIRMED",
        "terminal_category": "COMPLETED",
        "usage": {"input_tokens": 100, "output_tokens": 20},
    }
    return (
        r25.canonical_bytes(launch)
        + b"\n"
        + r25.canonical_bytes(terminal)
        + b"\n"
    )


def parse_provider_frames(r25: Any, raw: bytes) -> list[dict[str, Any]]:
    if not raw.endswith(b"\n"):
        raise ConformanceError("PROVIDER_FRAME_COUNT_MISMATCH")
    lines = raw[:-1].split(b"\n")
    if len(lines) != 2:
        raise ConformanceError("PROVIDER_FRAME_COUNT_MISMATCH")
    frames = []
    for line in lines:
        try:
            frame = r25.parse_json(line)
        except Exception as exc:
            raise ConformanceError(str(exc)) from exc
        if not isinstance(frame, dict):
            raise ConformanceError("PROVIDER_FRAME_SCHEMA_MISMATCH")
        frames.append(frame)
    if (
        frames[0].get("seq") != 0
        or frames[0].get("kind") != "launch"
        or frames[1].get("seq") != 1
        or frames[1].get("kind") != "terminal"
    ):
        raise ConformanceError("PROVIDER_FRAME_ORDER_MISMATCH")
    expected_keys = (
        {
            "stream_id",
            "seq",
            "kind",
            "attempt_digest",
            "effective_model_id",
            "effective_effort",
            "thinking_state",
        },
        {
            "stream_id",
            "seq",
            "kind",
            "attempt_digest",
            "fallback_state",
            "terminal_category",
            "usage",
        },
    )
    for frame, keys in zip(frames, expected_keys):
        if set(frame) != keys:
            raise ConformanceError("PROVIDER_FRAME_SCHEMA_MISMATCH")
    if frames[0]["stream_id"] != frames[1]["stream_id"]:
        raise ConformanceError("PROVIDER_STREAM_ID_MISMATCH")
    if frames[0]["attempt_digest"] != frames[1]["attempt_digest"]:
        raise ConformanceError("PROVIDER_ATTEMPT_MISMATCH")
    return frames


def load_proof_rules(
    bundle: dict[str, Any],
    r25: Any,
    store: TrustedAuthorityStoreV1,
) -> dict[str, Any]:
    validate_store(store)
    rules = store.load("observation/rules")
    schema_validate(bundle, r25, "ObservationProofRuleAuthorityV1", rules)
    verify_seal(r25, rules, "authority_digest")
    if (
        rules["store_key"] != "observation/rules"
        or rules["store_revision"] != store.revision
    ):
        raise ConformanceError("OBSERVATION_PROOF_RULE_MISMATCH")
    expected = [
        ("effective_model_id", "LAUNCH_FRAME_EXACT", "launch"),
        ("effective_effort", "LAUNCH_FRAME_EXACT", "launch"),
        ("thinking_state", "LAUNCH_FRAME_EXACT", "launch"),
        ("fallback_state", "TERMINAL_FRAME_EXACT", "terminal"),
        ("terminal_category", "TERMINAL_FRAME_EXACT", "terminal"),
    ]
    actual = [
        (row["field_name"], row["proof_rule_id"], row["frame_kind"])
        for row in rules["rows"]
    ]
    if actual != expected:
        raise ConformanceError("OBSERVATION_PROOF_RULE_MISMATCH")
    for row in rules["rows"]:
        verify_seal(r25, row, "row_digest")
    return rules


def derive_neutral_observation(
    bundle: dict[str, Any],
    r25: Any,
    provider_input: ImmutableProviderArtifactBytesV1,
    store: TrustedAuthorityStoreV1,
    expected_attempt_digest: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    raw = validate_provider_artifact_input(
        provider_input, expected_attempt_digest
    )
    frames = parse_provider_frames(r25, raw)
    if frames[0]["attempt_digest"] != expected_attempt_digest:
        raise ConformanceError("PROVIDER_ATTEMPT_MISMATCH")
    rules = load_proof_rules(bundle, r25, store)
    frame_digests = [
        sha256_bytes(r25.canonical_bytes(frame)) for frame in frames
    ]
    usage_digest = sha256_bytes(r25.canonical_bytes(frames[1]["usage"]))
    artifact = authority_record(
        r25,
        "plamen.provider-artifact-authority.v1",
        {
            "stream_id": frames[0]["stream_id"],
            "attempt_digest": frames[0]["attempt_digest"],
            "raw_stream_digest": sha256_bytes(raw),
            "frame_count": 2,
            "ordered_frame_digests": frame_digests,
            "usage_digest": usage_digest,
        },
    )
    schema_validate(bundle, r25, "ProviderArtifactAuthorityV1", artifact)
    values = {
        "effective_model_id": frames[0]["effective_model_id"],
        "effective_effort": frames[0]["effective_effort"],
        "thinking_state": frames[0]["thinking_state"],
        "fallback_state": frames[1]["fallback_state"],
        "terminal_category": frames[1]["terminal_category"],
    }
    claims = []
    for row in rules["rows"]:
        frame_index = 0 if row["frame_kind"] == "launch" else 1
        claim = seal(
            r25,
            {
                "claim_digest": r25.d("0"),
                "field_name": row["field_name"],
                "observed_value_digest": sha256_bytes(
                    r25.canonical_bytes(values[row["field_name"]])
                ),
                "proof_rule_authority_digest": rules["authority_digest"],
                "proof_rule_row_digest": row["row_digest"],
                "proof_rule_id": row["proof_rule_id"],
                "provider_artifact_authority_digest": artifact[
                    "authority_digest"
                ],
                "raw_frame_digest": frame_digests[frame_index],
            },
            "claim_digest",
        )
        schema_validate(bundle, r25, "NeutralObservationClaimV1", claim)
        claims.append(claim)
    evidence = seal(
        r25,
        {
            "schema": "plamen.neutral-observation-evidence.v1",
            "version": 1,
            "evidence_digest": r25.d("0"),
            "provider_artifact_authority_digest": artifact[
                "authority_digest"
            ],
            "proof_rule_authority_digest": rules["authority_digest"],
            "claim_count": 5,
            "claims": claims,
            **values,
        },
        "evidence_digest",
    )
    schema_validate(bundle, r25, "NeutralObservationEvidenceV1", evidence)
    return artifact, evidence


def validate_neutral_observation(
    bundle: dict[str, Any],
    r25: Any,
    provider_input: ImmutableProviderArtifactBytesV1,
    store: TrustedAuthorityStoreV1,
    expected_attempt_digest: str,
    claimed_artifact: dict[str, Any],
    claimed_evidence: dict[str, Any],
) -> None:
    raw = validate_provider_artifact_input(
        provider_input, expected_attempt_digest
    )
    frames = parse_provider_frames(r25, raw)
    if frames[0]["attempt_digest"] != expected_attempt_digest:
        raise ConformanceError("PROVIDER_ATTEMPT_MISMATCH")
    actual_usage = sha256_bytes(r25.canonical_bytes(frames[1]["usage"]))
    if claimed_artifact.get("usage_digest") != actual_usage:
        raise ConformanceError("PROVIDER_USAGE_MISMATCH")
    if claimed_artifact.get("raw_stream_digest") != sha256_bytes(raw):
        raise ConformanceError("PROVIDER_ARTIFACT_DIGEST_MISMATCH")
    artifact, evidence = derive_neutral_observation(
        bundle, r25, provider_input, store, expected_attempt_digest
    )
    schema_validate(
        bundle, r25, "ProviderArtifactAuthorityV1", claimed_artifact
    )
    verify_seal(r25, claimed_artifact, "authority_digest")
    schema_validate(
        bundle, r25, "NeutralObservationEvidenceV1", claimed_evidence
    )
    verify_seal(r25, claimed_evidence, "evidence_digest")
    rules = load_proof_rules(bundle, r25, store)
    actual_rows = {row["field_name"]: row for row in rules["rows"]}
    for claim in claimed_evidence["claims"]:
        row = actual_rows.get(claim["field_name"])
        if (
            row is None
            or claim["proof_rule_id"] != row["proof_rule_id"]
            or claim["proof_rule_row_digest"] != row["row_digest"]
            or claim["proof_rule_authority_digest"]
            != rules["authority_digest"]
        ):
            raise ConformanceError("OBSERVATION_PROOF_RULE_MISMATCH")
    if claimed_artifact != artifact or claimed_evidence != evidence:
        raise ConformanceError("NEUTRAL_OBSERVATION_MISMATCH")


def build_context(
    bundle: dict[str, Any], r25: Any, r23: Any, r24: Any
) -> dict[str, Any]:
    records = r25.build_closure(bundle, r23, r24)
    snapshot = build_persisted_authorities(bundle, r25, records)
    store = _fixture_trusted_store(snapshot)
    candidate = candidate_closure(records)
    reconstructed = validate_closure_v251(
        bundle, r25, candidate, store
    )
    raw_env = records["raw_env"]
    process_nonce = b"p" * 32
    object_nonce = b"o" * 32
    key = b"k" * 32
    proof = mint_verified_secret_proof(
        r25,
        records["envelope"],
        records["predecessor_envelope"],
        records["env_policy"],
        raw_env,
        process_nonce,
        object_nonce,
        key,
        records["consumed"],
    )
    spawn = mint_verified_spawn_capability(
        r25,
        proof,
        records["envelope"],
        records["predecessor_envelope"],
        records["env_policy"],
        raw_env,
        process_nonce,
        object_nonce,
        key,
        records["consumed"],
    )
    provider_raw = provider_stream_bytes(r25, records)
    transport_receipt = _establish_fixture_transport_receipt(
        provider_raw, records["attempt"]["execution_attempt_digest"]
    )
    provider_input = ingest_provider_artifact(
        provider_raw, transport_receipt
    )
    artifact, neutral = derive_neutral_observation(
        bundle,
        r25,
        provider_input,
        store,
        records["attempt"]["execution_attempt_digest"],
    )
    return {
        "records": records,
        "candidate": candidate,
        "reconstructed": reconstructed,
        "snapshot": snapshot,
        "store": store,
        "raw_env": raw_env,
        "process_nonce": process_nonce,
        "object_nonce": object_nonce,
        "key": key,
        "proof": proof,
        "spawn": spawn,
        "provider_raw": provider_raw,
        "provider_input": provider_input,
        "transport_receipt": transport_receipt,
        "artifact": artifact,
        "neutral": neutral,
    }


def forged_proof(
    context: dict[str, Any],
    *,
    tag: bytes | None = None,
) -> VerifiedSecretProofCapabilityV3:
    records = context["records"]
    proof = context["proof"]
    return VerifiedSecretProofCapabilityV3(
        _PROOF_ISSUER,
        envelope_digest=proof._envelope_digest,
        predecessor_digest=proof._predecessor_digest,
        policy_digest=proof._policy_digest,
        secret_set_digest=proof._secret_set_digest,
        attempt_digest=proof._attempt_digest,
        consumed_digest=proof._consumed_digest,
        process_nonce_digest=proof._process_nonce_digest,
        object_nonce_digest=proof._object_nonce_digest,
        tag=b"X" * 32 if tag is None else tag,
    )


def validate_proof_context(
    r25: Any,
    context: dict[str, Any],
    proof: VerifiedSecretProofCapabilityV3 | None = None,
    *,
    envelope: dict[str, Any] | None = None,
    predecessor: dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
    raw_env: dict[str, str] | None = None,
    process_nonce: bytes | None = None,
    object_nonce: bytes | None = None,
    key: bytes | None = None,
    consumed: dict[str, Any] | None = None,
) -> None:
    records = context["records"]
    verify_secret_proof_at_sink(
        r25,
        context["proof"] if proof is None else proof,
        records["envelope"] if envelope is None else envelope,
        (
            records["predecessor_envelope"]
            if predecessor is None
            else predecessor
        ),
        records["env_policy"] if policy is None else policy,
        context["raw_env"] if raw_env is None else raw_env,
        (
            context["process_nonce"]
            if process_nonce is None
            else process_nonce
        ),
        context["object_nonce"] if object_nonce is None else object_nonce,
        context["key"] if key is None else key,
        records["consumed"] if consumed is None else consumed,
    )


def encode_frames(r25: Any, frames: list[dict[str, Any]]) -> bytes:
    return b"".join(r25.canonical_bytes(frame) + b"\n" for frame in frames)


def decode_frames(r25: Any, raw: bytes) -> list[dict[str, Any]]:
    return [r25.parse_json(line) for line in raw[:-1].split(b"\n")]


def store_with_snapshot(
    snapshot: dict[str, dict[str, Any]],
    *,
    revision: int = 1,
) -> TrustedAuthorityStoreV1:
    return _fixture_trusted_store(copy.deepcopy(snapshot), revision)


def run_scenario(
    bundle: dict[str, Any],
    r25: Any,
    r23: Any,
    r24: Any,
    name: str,
) -> None:
    context = build_context(bundle, r25, r23, r24)
    records = context["records"]
    if name == "forged direct proof promoted to spawn capability":
        VerifiedSecretProofCapabilityV3(
            object(),
            envelope_digest=records["envelope"]["attempt_launch_digest"],
            predecessor_digest=records["predecessor_envelope"][
                "attempt_launch_digest"
            ],
            policy_digest=records["env_policy"][
                "environment_policy_authority_digest"
            ],
            secret_set_digest=r25.d("1"),
            attempt_digest=records["attempt"]["execution_attempt_digest"],
            consumed_digest=records["consumed"]["consumed_launch_digest"],
            process_nonce_digest=r25.d("2"),
            object_nonce_digest=r25.d("3"),
            tag=b"X" * 32,
        )
        return
    if name == "arbitrary proof tag":
        validate_proof_context(r25, context, forged_proof(context))
        return
    if name == "wrong V3 predecessor proof binding":
        predecessor = copy.deepcopy(records["predecessor_envelope"])
        predecessor["attempt_launch_digest"] = r25.identity_hash(name)
        validate_proof_context(
            r25, context, predecessor=predecessor
        )
        return
    if name == "wrong proof policy binding":
        policy = copy.deepcopy(records["env_policy"])
        policy["environment_policy_authority_digest"] = r25.identity_hash(name)
        validate_proof_context(r25, context, policy=policy)
        return
    if name == "wrong proof secret set":
        raw_env = copy.deepcopy(context["raw_env"])
        secret_name = next(
            row["name"]
            for row in records["env_policy"]["rows"]
            if row["secrecy_class"] == "SECRET"
        )
        raw_env[secret_name] = "changed-secret"
        validate_proof_context(r25, context, raw_env=raw_env)
        return
    if name == "wrong proof process nonce":
        validate_proof_context(r25, context, process_nonce=b"q" * 32)
        return
    if name == "wrong proof object nonce":
        validate_proof_context(r25, context, object_nonce=b"z" * 32)
        return
    if name == "wrong proof key":
        validate_proof_context(r25, context, key=b"j" * 32)
        return
    if name == "proof replay across attempt":
        consumed = copy.deepcopy(records["consumed"])
        consumed["consumed_launch_digest"] = r25.identity_hash(name)
        validate_proof_context(r25, context, consumed=consumed)
        return
    if name == "forged spawn capability constructor":
        VerifiedSpawnCapabilityV3(
            object(), context["proof"], {"forged": r25.d("1")}
        )
        return
    if name == "proof copy prohibited":
        copy.copy(context["proof"])
        return
    if name == "zero-secret policy while proof required":
        policy = copy.deepcopy(records["env_policy"])
        for row in policy["rows"]:
            row["secrecy_class"] = "PUBLIC"
            seal(r25, row, "policy_row_digest")
        seal(r25, policy, "environment_policy_authority_digest")
        mint_verified_secret_proof(
            r25,
            records["envelope"],
            records["predecessor_envelope"],
            policy,
            context["raw_env"],
            context["process_nonce"],
            context["object_nonce"],
            context["key"],
            records["consumed"],
        )
        return
    if name == "genuine verified proof and spawn":
        validate_verified_spawn_capability(
            r25,
            context["spawn"],
            records["envelope"],
            records["predecessor_envelope"],
            records["env_policy"],
            context["raw_env"],
            context["process_nonce"],
            context["object_nonce"],
            context["key"],
            records["consumed"],
        )
        return

    actual = r25.resume_identity(records)
    if name in {
        "fabricated current resume identity",
        "fabricated prior resume identity",
        "fabricated both resume identities",
    }:
        fake_before = copy.deepcopy(actual)
        fake_after = copy.deepcopy(actual)
        if name != "fabricated current resume identity":
            fake_before["prompt_identity"] = r25.identity_hash(name + ":prior")
            seal(r25, fake_before, "identity_vector_digest")
        if name != "fabricated prior resume identity":
            fake_after["model_identity"] = r25.identity_hash(name + ":current")
            seal(r25, fake_after, "identity_vector_digest")
        authority = r25.resume_authority(
            fake_before,
            fake_after,
            "NEW_GENERATION",
            current_generation=2,
            current_attempt=0,
        )
        validate_resume_v251(
            bundle,
            r25,
            authority,
            context["store"],
            records,
            None,
            None,
        )
        return
    if name == "caller-selected prior vector":
        authority = r25.resume_authority(
            actual, actual, "RETRY_SAME_GENERATION"
        )
        validate_resume_v251(
            bundle,
            r25,
            authority,
            context["store"],
            records,
            None,
            None,
            caller_before=actual,
        )
        return
    if name == "stale prior resume store revision":
        snapshot = copy.deepcopy(context["snapshot"])
        prior = snapshot["resume/prior"]
        prior["store_revision"] = 2
        seal(r25, prior, "authority_digest")
        store = store_with_snapshot(snapshot)
        authority = r25.resume_authority(
            actual, actual, "RETRY_SAME_GENERATION"
        )
        validate_resume_v251(
            bundle, r25, authority, store, records, None, None
        )
        return
    if name == "wrong prior resume store key":
        authority = r25.resume_authority(
            actual, actual, "RETRY_SAME_GENERATION"
        )
        validate_resume_v251(
            bundle,
            r25,
            authority,
            context["store"],
            records,
            None,
            None,
            prior_key="resume/missing",
        )
        return
    if name == "prior resume authority seal tamper":
        snapshot = copy.deepcopy(context["snapshot"])
        snapshot["resume/prior"]["run_id"] = "tampered"
        store = store_with_snapshot(snapshot)
        authority = r25.resume_authority(
            actual, actual, "RETRY_SAME_GENERATION"
        )
        validate_resume_v251(
            bundle, r25, authority, store, records, None, None
        )
        return
    if name in {
        "valid actual single resume change",
        "valid actual multiple resume changes",
    }:
        prior_identity = copy.deepcopy(actual)
        fields = ["model_identity"]
        if name == "valid actual multiple resume changes":
            fields += [
                "effort_identity",
                "thinking_identity",
                "loaded_customization_identity",
            ]
        for field in fields:
            prior_identity[field] = r25.identity_hash(name + ":" + field)
        seal(r25, prior_identity, "identity_vector_digest")
        snapshot = build_persisted_authorities(
            bundle, r25, records, prior_identity
        )
        store = store_with_snapshot(snapshot)
        authority = r25.resume_authority(
            prior_identity,
            actual,
            "NEW_GENERATION",
            current_generation=2,
            current_attempt=0,
        )
        validate_resume_v251(
            bundle, r25, authority, store, records, None, None
        )
        return
    if name == "valid actual retry":
        authority = r25.resume_authority(
            actual, actual, "RETRY_SAME_GENERATION"
        )
        validate_resume_v251(
            bundle,
            r25,
            authority,
            context["store"],
            records,
            None,
            None,
        )
        return
    if name == "valid actual completed no-relaunch":
        completed = r25.completed_evidence(records)
        authority = r25.resume_authority(
            actual,
            actual,
            "NO_RELAUNCH_COMPLETED",
            current_attempt=0,
            completed=completed,
        )
        validate_resume_v251(
            bundle,
            r25,
            authority,
            context["store"],
            records,
            completed,
            None,
        )
        return
    if name == "valid actual ambiguous consumed debt":
        ambiguous = r25.ambiguity_evidence(records)
        authority = r25.resume_authority(
            actual,
            actual,
            "AMBIGUOUS_CONSUMED_DEBT",
            current_attempt=0,
            ambiguous=ambiguous,
        )
        validate_resume_v251(
            bundle,
            r25,
            authority,
            context["store"],
            records,
            None,
            ambiguous,
        )
        return

    artifact = copy.deepcopy(context["artifact"])
    neutral = copy.deepcopy(context["neutral"])
    raw = context["provider_raw"]
    attempt_digest = records["attempt"]["execution_attempt_digest"]
    if name == "caller co-supplied transport receipt":
        TransportArtifactReceiptCapabilityV1(
            object(),
            sha256_bytes(raw),
            attempt_digest,
            "CALLER_SUPPLIED",
        )
        return
    if name == "fully fabricated provider observation manifest":
        neutral["effective_model_id"] = "fabricated-model-20260730"
        seal(r25, neutral, "evidence_digest")
    elif name == "caller-authored observation proof-rule id":
        neutral["claims"][0]["proof_rule_id"] = "TERMINAL_FRAME_EXACT"
        seal(r25, neutral["claims"][0], "claim_digest")
        seal(r25, neutral, "evidence_digest")
    elif name in {
        "provider observation wrong raw bytes",
        "provider observation mixed streams",
        "provider observation omitted frame",
        "provider observation reordered frames",
        "provider observation duplicate sequence",
        "provider observation wrong attempt",
        "provider observation usage tamper",
    }:
        frames = decode_frames(r25, raw)
        if name == "provider observation wrong raw bytes":
            frames[0]["effective_model_id"] = "different-model"
        elif name == "provider observation mixed streams":
            frames[1]["stream_id"] = "other-stream"
        elif name == "provider observation omitted frame":
            frames = frames[:1]
        elif name == "provider observation reordered frames":
            frames = list(reversed(frames))
        elif name == "provider observation duplicate sequence":
            frames[1]["seq"] = 0
        elif name == "provider observation wrong attempt":
            for frame in frames:
                frame["attempt_digest"] = r25.identity_hash(name)
        elif name == "provider observation usage tamper":
            frames[1]["usage"]["output_tokens"] = 21
        raw = encode_frames(r25, frames)
    elif name == "provider observation fallback tamper":
        neutral["fallback_state"] = "FALLBACK_USED"
        seal(r25, neutral, "evidence_digest")
    elif name == "provider observation terminal tamper":
        neutral["terminal_category"] = "FAILED"
        seal(r25, neutral, "evidence_digest")
    if name in {
        "fully fabricated provider observation manifest",
        "caller-authored observation proof-rule id",
        "provider observation wrong raw bytes",
        "provider observation mixed streams",
        "provider observation omitted frame",
        "provider observation reordered frames",
        "provider observation duplicate sequence",
        "provider observation wrong attempt",
        "provider observation usage tamper",
        "provider observation fallback tamper",
        "provider observation terminal tamper",
        "valid neutral provider observation",
    }:
        validate_neutral_observation(
            bundle,
            r25,
            (
                context["provider_input"]
                if raw == context["provider_raw"]
                else (
                    ingest_provider_artifact(
                        raw, context["transport_receipt"]
                    )
                    if name == "provider observation wrong raw bytes"
                    else _fixture_provider_artifact(raw, attempt_digest)
                )
            ),
            context["store"],
            attempt_digest,
            artifact,
            neutral,
        )
        return

    if name == "root and descendants co-rehashed with candidate anchor":
        candidate = copy.deepcopy(context["candidate"])
        candidate["root"]["semantic_plan_digest"] = r25.identity_hash(name)
        seal(r25, candidate["root"], "routing_root_digest")
        for record_name, (_definition, digest_field) in r25.SCHEMA_RECORDS.items():
            record = candidate[record_name]
            if "routing_root_digest" in record:
                record["routing_root_digest"] = candidate["root"][
                    "routing_root_digest"
                ]
                seal(r25, record, digest_field)
        validate_closure_v251(
            bundle, r25, candidate, context["store"]
        )
        return
    if name == "transaction parent and descendants co-rehashed":
        candidate = copy.deepcopy(context["candidate"])
        candidate["envelope"]["prepared_utc"] = "2026-07-30T00:00:01Z"
        seal(r25, candidate["envelope"], "attempt_launch_digest")
        validate_closure_v251(
            bundle, r25, candidate, context["store"]
        )
        return
    if name == "transaction parent unknown raw-secret field":
        parent = copy.deepcopy(context["snapshot"]["transaction/materialization"])
        parent["raw_secret_value"] = "never-durable"
        schema_validate(bundle, r25, "MaterializationParentV1", parent)
        return
    if name == "stale transaction parent":
        snapshot = copy.deepcopy(context["snapshot"])
        current = snapshot["transaction/current"]
        current["store_revision"] = 2
        seal(r25, current, "authority_digest")
        validate_closure_v251(
            bundle,
            r25,
            context["candidate"],
            store_with_snapshot(snapshot),
        )
        return
    if name == "cross-generation transaction parent":
        snapshot = copy.deepcopy(context["snapshot"])
        parent = snapshot["transaction/materialization"]
        parent["generation"] = 2
        seal(r25, parent, "authority_digest")
        validate_closure_v251(
            bundle,
            r25,
            context["candidate"],
            store_with_snapshot(snapshot),
        )
        return
    if name == "transaction parent seal tamper":
        snapshot = copy.deepcopy(context["snapshot"])
        snapshot["transaction/consumption"]["run_id"] = "tampered"
        validate_closure_v251(
            bundle,
            r25,
            context["candidate"],
            store_with_snapshot(snapshot),
        )
        return
    if name == "missing transaction parent":
        snapshot = copy.deepcopy(context["snapshot"])
        del snapshot["transaction/current"]
        validate_closure_v251(
            bundle,
            r25,
            context["candidate"],
            store_with_snapshot(snapshot),
        )
        return
    if name == "root preimage wrong store key":
        snapshot = copy.deepcopy(context["snapshot"])
        root = snapshot["root/current"]
        root["store_key"] = "root/other"
        seal(r25, root, "authority_digest")
        validate_closure_v251(
            bundle,
            r25,
            context["candidate"],
            store_with_snapshot(snapshot),
        )
        return
    if name == "root preimage seal tamper":
        snapshot = copy.deepcopy(context["snapshot"])
        snapshot["root/current"]["store_revision"] = 2
        validate_closure_v251(
            bundle,
            r25,
            context["candidate"],
            store_with_snapshot(snapshot),
        )
        return
    if name == "untrusted authority store capability":
        TrustedAuthorityStoreV1(
            object(),
            context["snapshot"],
            _establish_fixture_trust_anchor(context["snapshot"]),
        )
        return
    if name == "candidate embeds legacy root anchor":
        candidate = copy.deepcopy(context["candidate"])
        candidate["frozen_root_digest"] = candidate["root"][
            "routing_root_digest"
        ]
        validate_closure_v251(
            bundle, r25, candidate, context["store"]
        )
        return
    if name == "valid externally loaded root and transaction parents":
        validate_closure_v251(
            bundle, r25, context["candidate"], context["store"]
        )
        return
    raise ConformanceError("R2_5_1_UNKNOWN_SCENARIO")


def validate_review_binding() -> None:
    raw = read_ascii_lf(REVIEW_PATH)
    if sha256_bytes(raw) != REVIEW_WHOLE_SHA256:
        raise ConformanceError("R2_5_REVIEW_WHOLE_HASH_MISMATCH")
    marker = b"\n## Artifact integrity\n"
    position = raw.rfind(marker)
    if position < 0:
        raise ConformanceError("R2_5_REVIEW_BODY_BOUNDARY_MISSING")
    body = raw[:position]
    if not body.endswith(
        b"End of independent R2.5 blocking review.\n"
    ):
        raise ConformanceError("R2_5_REVIEW_BODY_BOUNDARY_MISMATCH")
    if sha256_bytes(body) != REVIEW_BODY_SHA256:
        raise ConformanceError("R2_5_REVIEW_BODY_HASH_MISMATCH")


def verify_frozen_r25() -> Any:
    r25 = import_exact(
        R2_5_VALIDATOR_PATH, R2_5_VALIDATOR_SHA256, "r25"
    )
    completed = subprocess.run(
        [sys.executable, "-I", str(R2_5_VALIDATOR_PATH)],
        cwd=str(HERE),
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if completed.returncode != 0:
        raise ConformanceError("R2_5_PRESERVATION_EXECUTION_FAILED")
    if set(completed.stdout.splitlines()) != R2_5_EXPECTED_OUTPUT:
        raise ConformanceError("R2_5_PRESERVATION_OUTPUT_MISMATCH")
    return r25


def validate_vector_manifest(
    r25: Any, vectors: dict[str, Any]
) -> list[dict[str, Any]]:
    if (
        vectors.get("schema")
        != "plamen.model-routing-r2.5.1-conformance-vectors.v1"
    ):
        raise ConformanceError("R2_5_1_VECTOR_SCHEMA_MISMATCH")
    review = vectors.get("blocking_review", {})
    if (
        review.get("whole_sha256") != REVIEW_WHOLE_SHA256
        or review.get("body_sha256") != REVIEW_BODY_SHA256
        or review.get("unexpected_accept_count") != 8
        or review.get("blocking_root_cause_count") != 4
    ):
        raise ConformanceError("R2_5_1_REVIEW_BINDING_MISMATCH")
    discrepancy = vectors.get("manifest_discrepancy", {})
    if (
        discrepancy.get("historical_declared_sha256")
        != HISTORICAL_MANIFEST_SHA256
        or discrepancy.get("adjudicated_reproducible_sha256")
        != ADJUDICATED_MANIFEST_SHA256
        or discrepancy.get("restricted_json_bytes") != 2851
        or discrepancy.get("disposition")
        != "REPRODUCIBLE_DIGEST_IS_LABEL_MANIFEST_TRUTH_HISTORICAL_DECLARATION_PRESERVED"
    ):
        raise ConformanceError("R2_5_1_MANIFEST_ADJUDICATION_MISMATCH")
    preserved = vectors.get("preserved_denominator", {})
    if (
        preserved.get("r2_5_validator_sha256")
        != R2_5_VALIDATOR_SHA256
        or preserved.get("r2_5_vectors_sha256")
        != "51ffcb40264984033f0150f07f737a01a0077733dd4acdf58a3746fc01fda0ac"
        or preserved.get("r2_5_executed_total") != 596
    ):
        raise ConformanceError("R2_5_1_PRESERVED_DENOMINATOR_MISMATCH")
    rows = vectors.get("r2_5_1_vectors")
    if not isinstance(rows, list) or len(rows) != 50:
        raise ConformanceError("R2_5_1_VECTOR_COUNT_MISMATCH")
    if [row.get("id") for row in rows] != [
        f"R2.5.1-{number:03d}" for number in range(1, 51)
    ]:
        raise ConformanceError("R2_5_1_VECTOR_ID_MISMATCH")
    if len({row.get("scenario") for row in rows}) != 50:
        raise ConformanceError("R2_5_1_VECTOR_SCENARIO_DUPLICATE")
    expected_blockers = (
        ["B1"] * 13 + ["B2"] * 12 + ["B3"] * 13 + ["B4"] * 12
    )
    if [row.get("blocker") for row in rows] != expected_blockers:
        raise ConformanceError("R2_5_1_VECTOR_BLOCKER_PARTITION_MISMATCH")
    return rows


def validate_positive_boundaries(
    bundle: dict[str, Any], r25: Any, r23: Any, r24: Any
) -> None:
    context = build_context(bundle, r25, r23, r24)
    validate_verified_spawn_capability(
        r25,
        context["spawn"],
        context["records"]["envelope"],
        context["records"]["predecessor_envelope"],
        context["records"]["env_policy"],
        context["raw_env"],
        context["process_nonce"],
        context["object_nonce"],
        context["key"],
        context["records"]["consumed"],
    )
    if "<redacted>" not in repr(context["proof"]):
        raise ConformanceError("PROOF_REPR_LEAK")
    for operation in (
        lambda: copy.copy(context["proof"]),
        lambda: copy.deepcopy(context["proof"]),
        lambda: pickle.dumps(context["proof"]),
        lambda: copy.copy(context["spawn"]),
        lambda: pickle.dumps(context["spawn"]),
        lambda: copy.deepcopy(context["store"]),
        lambda: pickle.dumps(context["store"]),
        lambda: copy.copy(context["store"]._anchor),
        lambda: pickle.dumps(context["store"]._anchor),
        lambda: copy.copy(context["transport_receipt"]),
        lambda: pickle.dumps(context["transport_receipt"]),
        lambda: copy.copy(context["provider_input"]),
        lambda: pickle.dumps(context["provider_input"]),
    ):
        try:
            operation()
        except (TypeError, ConformanceError):
            pass
        else:
            raise ConformanceError("CAPABILITY_COPY_OR_SERIALIZATION_ACCEPTED")
    validate_neutral_observation(
        bundle,
        r25,
        context["provider_input"],
        context["store"],
        context["records"]["attempt"]["execution_attempt_digest"],
        context["artifact"],
        context["neutral"],
    )
    validate_closure_v251(
        bundle, r25, context["candidate"], context["store"]
    )


def main() -> int:
    schema_raw = read_ascii_lf(SCHEMA_PATH)
    vector_raw = read_ascii_lf(VECTORS_PATH)
    if sha256_bytes(schema_raw) != SCHEMA_SHA256:
        raise ConformanceError("R2_5_1_SCHEMA_HASH_MISMATCH")
    if sha256_bytes(vector_raw) != VECTORS_SHA256:
        raise ConformanceError("R2_5_1_VECTORS_HASH_MISMATCH")
    validate_review_binding()
    r25 = verify_frozen_r25()
    try:
        bundle = r25.parse_json(schema_raw)
        vectors = r25.parse_json(vector_raw)
    except Exception as exc:
        raise ConformanceError(str(exc)) from exc
    try:
        Draft202012Validator.check_schema(bundle)
    except SchemaError as exc:
        raise ConformanceError("R2_5_1_META_SCHEMA_INVALID") from exc
    rows = validate_vector_manifest(r25, vectors)
    r23, r24 = r25.verify_frozen_denominators()
    validate_positive_boundaries(bundle, r25, r23, r24)
    for row in rows:
        scenario = row["scenario"]
        expected = row["expected"]
        operation = lambda scenario=scenario: run_scenario(
            bundle, r25, r23, r24, scenario
        )
        if expected == "PASS":
            operation()
        else:
            expect_error(operation, expected)
    print("R2.5.1_CONFORMANCE=PASS")
    print("R2_5_PRESERVED_EXECUTED_DENOMINATOR=596")
    print("R2_5_1_NEW_VECTORS=50")
    print("TOTAL_EXECUTED_VECTOR_DENOMINATOR=646")
    print(f"SCHEMA_SHA256={SCHEMA_SHA256}")
    print(f"VECTORS_SHA256={VECTORS_SHA256}")
    print("BLOCKERS_CLOSED=B1,B2,B3,B4")
    print("AUTHOR_DISPOSITION=SELF_VALIDATED_NOT_INDEPENDENT_PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ConformanceError as exc:
        print(f"R2.5.1_CONFORMANCE=FAIL:{exc}", file=sys.stderr)
        raise SystemExit(1)
