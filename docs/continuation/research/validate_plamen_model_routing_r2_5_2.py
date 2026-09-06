from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import pickle
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError


HERE = Path(__file__).resolve().parent
SCHEMA_PATH = HERE / "Plamen_Backend_Model_Routing_R2.5.2_Schemas_2026-07-30.json"
VECTORS_PATH = HERE / "Plamen_Backend_Model_Routing_R2.5.2_Conformance_Vectors_2026-07-30.json"
R251_PATH = HERE / "validate_plamen_model_routing_r2_5_1.py"
REVIEW_PATH = (
    HERE.parent
    / "plamen-codex-implementation"
    / "review_fixtures"
    / "backend_model_routing_r2_5_1_independent_review_r1_20260730.md"
)
SCHEMA_SHA256 = "23795b1620168ca94a7f9a65ab4136243a33c72027a7bf7a217a1911c14b1e02"
VECTORS_SHA256 = "ecbc628d257b09bc0ec343d2c525be14b6f5864b680e809dc282559eca2845b1"
R251_SHA256 = "48bba3d1b90ebab113064983382f582b749a719728d336accb9a7d4cd115b685"
REVIEW_WHOLE_SHA256 = "255952072991a889bb7119d744eabc1c77570bd9701f5f8ddd22d314663edf9a"
REVIEW_BODY_SHA256 = "c769bf229a2046456a7424457028953edf8256b42b5f098c8bbd839b8e319276"
R251_EXPECTED = {
    "R2.5.1_CONFORMANCE=PASS",
    "R2_5_PRESERVED_EXECUTED_DENOMINATOR=596",
    "R2_5_1_NEW_VECTORS=50",
    "TOTAL_EXECUTED_VECTOR_DENOMINATOR=646",
    "SCHEMA_SHA256=b70488adaef6b653e3915957fca453e5f5ee9e8b4dc66e425a652743a371d8e3",
    "VECTORS_SHA256=e4e3804b86ab4251902ebdbafc99f5acae3d1409bd56255c730b345fb9c6b9e8",
    "BLOCKERS_CLOSED=B1,B2,B3,B4",
    "AUTHOR_DISPOSITION=SELF_VALIDATED_NOT_INDEPENDENT_PASS",
}
ALLOWED_STORE_KEYS = (
    "observation/rules",
    "resume/prior",
    "root/current",
    "run/current",
    "transaction/consumption",
    "transaction/current",
    "transaction/materialization",
    "transaction/reconciliation",
    "transaction/reservation",
)
_CLOSURE_ISSUER = object()
_CLOSURE_REGISTRY: dict[int, tuple[Any, ...]] = {}
_LAUNCH_CLOSURE_ISSUER = object()
_LAUNCH_CLOSURE_REGISTRY: dict[int, tuple[Any, ...]] = {}


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
    if sha256_bytes(path.read_bytes()) != expected:
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
    except Exception as exc:
        if (
            not isinstance(exc, ConformanceError)
            and exc.__class__.__name__ != "ConformanceError"
        ):
            raise
        if str(exc) != expected:
            raise ConformanceError(f"EXPECTED_{expected}_GOT_{exc}") from exc
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
        if error.validator == "additionalProperties":
            raise ConformanceError("SCHEMA_UNKNOWN_FIELD")
        if error.validator == "required":
            raise ConformanceError("SCHEMA_REQUIRED_FIELD")
        raise ConformanceError("SCHEMA_VALIDATION_ERROR")
    r25.check_value(record)


def seal(r25: Any, record: dict[str, Any], field: str) -> dict[str, Any]:
    return r25.seal(record, field)


def verify_seal(r25: Any, record: dict[str, Any], field: str) -> None:
    try:
        r25.verify_seal(record, field)
    except Exception as exc:
        raise ConformanceError(str(exc)) from exc


def authority_record(
    r25: Any, schema: str, fields: dict[str, Any]
) -> dict[str, Any]:
    record = {
        "schema": schema,
        "version": 1,
        "authority_digest": r25.d("0"),
        **fields,
    }
    return seal(r25, record, "authority_digest")


def namespace_digest(r25: Any) -> str:
    return sha256_bytes(r25.canonical_bytes(list(ALLOWED_STORE_KEYS)))


def build_current_run(
    r251: Any, snapshot: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    r25 = r251.import_exact(
        r251.R2_5_VALIDATOR_PATH, r251.R2_5_VALIDATOR_SHA256, "r25_build"
    )
    tx = snapshot["transaction/current"]
    return authority_record(
        r25,
        "plamen.current-run-authority.v1",
        {
            "store_key": "run/current",
            "store_revision": 1,
            "run_id": tx["run_id"],
            "generation": tx["generation"],
            "attempt_ordinal": tx["attempt_ordinal"],
            "root_preimage_authority_digest": snapshot["root/current"][
                "authority_digest"
            ],
            "transaction_parent_set_digest": tx["authority_digest"],
            "prior_resume_authority_digest": snapshot["resume/prior"][
                "authority_digest"
            ],
            "proof_rule_authority_digest": snapshot["observation/rules"][
                "authority_digest"
            ],
            "namespace_digest": namespace_digest(r25),
        },
    )


def scoped_snapshot(
    r251: Any, base: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    snapshot = copy.deepcopy(base)
    snapshot["run/current"] = build_current_run(r251, snapshot)
    return snapshot


def validate_store_scope(
    bundle: dict[str, Any],
    r251: Any,
    store: Any,
) -> dict[str, Any]:
    r25 = r251.import_exact(
        r251.R2_5_VALIDATOR_PATH, r251.R2_5_VALIDATOR_SHA256, "r25_scope"
    )
    try:
        r251.validate_store(store)
    except Exception as exc:
        raise ConformanceError(str(exc)) from exc
    keys = tuple(sorted(dict(store._snapshot)))
    if keys != ALLOWED_STORE_KEYS:
        raise ConformanceError("AUTHORITY_STORE_NAMESPACE_MISMATCH")
    run = store.load("run/current")
    schema_validate(bundle, r25, "CurrentRunAuthorityV1", run)
    verify_seal(r25, run, "authority_digest")
    if (
        run["store_key"] != "run/current"
        or run["namespace_digest"] != namespace_digest(r25)
    ):
        raise ConformanceError("AUTHORITY_STORE_NAMESPACE_MISMATCH")
    if run["store_revision"] != store.revision:
        raise ConformanceError("AUTHORITY_STORE_REVISION_MISMATCH")
    root = store.load("root/current")
    tx = store.load("transaction/current")
    prior = store.load("resume/prior")
    rules = store.load("observation/rules")
    reservation = store.load("transaction/reservation")
    materialization = store.load("transaction/materialization")
    consumption = store.load("transaction/consumption")
    reconciliation = store.load("transaction/reconciliation")
    for definition, record in (
        ("RootPreimageAuthorityV1", root),
        ("TransactionParentSetV1", tx),
        ("ReservationParentV1", reservation),
        ("MaterializationParentV1", materialization),
        ("ConsumptionParentV1", consumption),
        ("ReconciliationParentV1", reconciliation),
        ("PriorResumeIdentityAuthorityV1", prior),
        ("ObservationProofRuleAuthorityV1", rules),
    ):
        schema_validate(bundle, r25, definition, record)
        verify_seal(r25, record, "authority_digest")
    for row in rules["rows"]:
        verify_seal(r25, row, "row_digest")
    for record, key in (
        (root, "root/current"),
        (tx, "transaction/current"),
        (prior, "resume/prior"),
        (rules, "observation/rules"),
    ):
        if record["store_key"] != key:
            raise ConformanceError("AUTHORITY_STORE_KEY_MISMATCH")
        if record["store_revision"] != store.revision:
            raise ConformanceError("AUTHORITY_STORE_REVISION_MISMATCH")
    try:
        r25.schema_validate(
            bundle,
            "ResumeIdentityVectorV2",
            prior["identity_vector"],
        )
        r25.verify_seal(
            prior["identity_vector"], "identity_vector_digest"
        )
    except Exception as exc:
        raise ConformanceError(str(exc)) from exc
    if tx["store_key"] != "transaction/current":
        raise ConformanceError("AUTHORITY_STORE_KEY_MISMATCH")
    joins = (
        (run["root_preimage_authority_digest"], root["authority_digest"]),
        (run["transaction_parent_set_digest"], tx["authority_digest"]),
        (run["prior_resume_authority_digest"], prior["authority_digest"]),
        (run["proof_rule_authority_digest"], rules["authority_digest"]),
    )
    if any(left != right for left, right in joins):
        raise ConformanceError("CURRENT_RUN_AUTHORITY_MISMATCH")
    for record in (
        tx,
        reservation,
        materialization,
        consumption,
        reconciliation,
        prior,
    ):
        if record["run_id"] != run["run_id"]:
            raise ConformanceError("AUTHORITY_STORE_RUN_MISMATCH")
    if (
        tx["generation"] != run["generation"]
        or tx["attempt_ordinal"] != run["attempt_ordinal"]
    ):
        raise ConformanceError("AUTHORITY_STORE_RUN_MISMATCH")
    for parent in (reservation, materialization, consumption, reconciliation):
        if (
            parent["generation"] != run["generation"]
            or parent["attempt_ordinal"] != run["attempt_ordinal"]
        ):
            raise ConformanceError("AUTHORITY_STORE_RUN_MISMATCH")
    if (
        prior["generation"] != run["generation"]
        or prior["attempt_ordinal"] != run["attempt_ordinal"]
    ):
        raise ConformanceError("AUTHORITY_STORE_RUN_MISMATCH")
    for field, parent in (
        ("reservation_parent_digest", reservation),
        ("materialization_parent_digest", materialization),
        ("consumption_parent_digest", consumption),
        ("reconciliation_parent_digest", reconciliation),
    ):
        if tx[field] != parent["authority_digest"]:
            raise ConformanceError("CURRENT_RUN_AUTHORITY_MISMATCH")
    return run


def derive_neutral_v252(
    bundle: dict[str, Any],
    r251: Any,
    r25: Any,
    provider_input: Any,
    store: Any,
    expected_attempt_digest: str,
) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
    raw = r251.validate_provider_artifact_input(
        provider_input, expected_attempt_digest
    )
    frames = r251.parse_provider_frames(r25, raw)
    try:
        schema_validate(bundle, r25, "ProviderUsageV1", frames[1]["usage"])
    except ConformanceError as exc:
        raise ConformanceError("PROVIDER_USAGE_SCHEMA_MISMATCH") from exc
    if (
        not isinstance(frames[0]["effective_model_id"], str)
        or not frames[0]["effective_model_id"]
    ):
        raise ConformanceError("PROVIDER_FRAME_SCHEMA_MISMATCH")
    closed_states = (
        (
            frames[0]["effective_effort"],
            {"low", "medium", "high", "xhigh", "not_applicable"},
        ),
        (
            frames[0]["thinking_state"],
            {
                "ADAPTIVE_ON_CONFIRMED",
                "MANUAL_ON_CONFIRMED",
                "MANUAL_OFF_CONFIRMED",
                "UNKNOWN_ADVERSE",
            },
        ),
        (
            frames[1]["fallback_state"],
            {
                "NO_FALLBACK_CONFIRMED",
                "FALLBACK_USED_CONFIRMED",
                "UNKNOWN_ADVERSE",
            },
        ),
        (
            frames[1]["terminal_category"],
            {
                "COMPLETED",
                "FAILED",
                "CANCELLED",
                "TIMED_OUT",
                "UNKNOWN_ADVERSE",
            },
        ),
    )
    if any(value not in allowed for value, allowed in closed_states):
        raise ConformanceError("NEUTRAL_STATE_GRAMMAR_MISMATCH")
    artifact, v1 = r251.derive_neutral_observation(
        bundle, r25, provider_input, store, expected_attempt_digest
    )
    evidence = {
        **copy.deepcopy(v1),
        "schema": "plamen.neutral-observation-evidence.v2",
        "version": 2,
        "usage_digest": artifact["usage_digest"],
        "raw_stream_digest": artifact["raw_stream_digest"],
    }
    evidence = seal(r25, evidence, "evidence_digest")
    schema_validate(bundle, r25, "NeutralObservationEvidenceV2", evidence)
    verify_seal(r25, evidence, "evidence_digest")
    return raw, artifact, evidence


def project_candidate_to_neutral(
    r25: Any,
    candidate: dict[str, Any],
    artifact: dict[str, Any],
    neutral: dict[str, Any],
) -> dict[str, Any]:
    projected = copy.deepcopy(candidate)
    values = {
        "effective_model": neutral["effective_model_id"],
        "effective_effort": (
            None
            if neutral["effective_effort"] == "not_applicable"
            else neutral["effective_effort"]
        ),
        "thinking_state": neutral["thinking_state"],
        "fallback_state": neutral["fallback_state"],
        "terminal_category": neutral["terminal_category"],
    }
    evidence = r25.evidence_manifest(values)
    claims = {
        row["field_name"]: row for row in evidence["field_claims"]
    }
    observation = copy.deepcopy(projected["observation"])
    observation.update(
        {
            "observed_effective_model_id": values["effective_model"],
            "observed_effective_effort": values["effective_effort"],
            "observed_thinking_state": values["thinking_state"],
            "fallback_observation_state": values["fallback_state"],
            "provider_terminal_category": values["terminal_category"],
            "evidence_manifest_digest": evidence[
                "evidence_manifest_digest"
            ],
            "model_field_claim_digest": claims["effective_model"][
                "field_claim_digest"
            ],
            "effort_field_claim_digest": claims["effective_effort"][
                "field_claim_digest"
            ],
            "thinking_field_claim_digest": claims["thinking_state"][
                "field_claim_digest"
            ],
            "fallback_field_claim_digest": claims["fallback_state"][
                "field_claim_digest"
            ],
            "terminal_field_claim_digest": claims["terminal_category"][
                "field_claim_digest"
            ],
            "thinking_observation_evidence_digest": claims[
                "thinking_state"
            ]["raw_artifact_digests"][0],
            "provider_usage_digest": artifact["usage_digest"],
            "raw_stream_digest": artifact["raw_stream_digest"],
        }
    )
    observation = seal(r25, observation, "observation_digest")
    projected["evidence"] = evidence
    projected["observation"] = observation
    return projected


def validate_legacy_projection(
    r25: Any,
    candidate: dict[str, Any],
    artifact: dict[str, Any],
    neutral: dict[str, Any],
) -> None:
    expected = project_candidate_to_neutral(
        r25, candidate, artifact, neutral
    )
    if (
        candidate.get("evidence") != expected["evidence"]
        or candidate.get("observation") != expected["observation"]
    ):
        raise ConformanceError("MANDATORY_NEUTRAL_OBSERVATION_MISMATCH")


def build_reconciliation(
    bundle: dict[str, Any],
    r25: Any,
    records: dict[str, Any],
    run: dict[str, Any],
    artifact: dict[str, Any],
    neutral: dict[str, Any],
    rules: dict[str, Any],
) -> dict[str, Any]:
    reconciliation = authority_record(
        r25,
        "plamen.neutral-reconciliation-authority.v1",
        {
            "run_id": run["run_id"],
            "generation": run["generation"],
            "attempt_ordinal": run["attempt_ordinal"],
            "routing_root_digest": records["root"][
                "routing_root_digest"
            ],
            "execution_attempt_digest": records["attempt"][
                "execution_attempt_digest"
            ],
            "consumed_launch_digest": records["consumed"][
                "consumed_launch_digest"
            ],
            "provider_artifact_authority_digest": artifact[
                "authority_digest"
            ],
            "neutral_evidence_digest": neutral["evidence_digest"],
            "legacy_observation_digest": records["observation"][
                "observation_digest"
            ],
            "legacy_evidence_manifest_digest": records["evidence"][
                "evidence_manifest_digest"
            ],
            "proof_rule_authority_digest": rules["authority_digest"],
            "usage_digest": artifact["usage_digest"],
            "raw_stream_digest": artifact["raw_stream_digest"],
        },
    )
    schema_validate(
        bundle, r25, "NeutralReconciliationAuthorityV1", reconciliation
    )
    verify_seal(r25, reconciliation, "authority_digest")
    return reconciliation


class ValidatedLaunchClosureCapabilityV2:
    __slots__ = (
        "_issuer",
        "_records_bytes",
        "_records_digest",
        "_store_snapshot_digest",
        "_current_run_digest",
        "_run_id",
        "_generation",
        "_attempt_ordinal",
    )

    def __init__(
        self,
        _token: object,
        *,
        records_bytes: bytes,
        store_snapshot_digest: str,
        current_run_digest: str,
        run_id: str,
        generation: int,
        attempt_ordinal: int,
    ) -> None:
        if _token is not _LAUNCH_CLOSURE_ISSUER:
            raise ConformanceError("VALIDATED_CLOSURE_CONSTRUCTOR_PRIVATE")
        object.__setattr__(self, "_issuer", _LAUNCH_CLOSURE_ISSUER)
        object.__setattr__(self, "_records_bytes", bytes(records_bytes))
        object.__setattr__(
            self, "_records_digest", sha256_bytes(records_bytes)
        )
        object.__setattr__(
            self, "_store_snapshot_digest", store_snapshot_digest
        )
        object.__setattr__(self, "_current_run_digest", current_run_digest)
        object.__setattr__(self, "_run_id", run_id)
        object.__setattr__(self, "_generation", generation)
        object.__setattr__(self, "_attempt_ordinal", attempt_ordinal)
        _LAUNCH_CLOSURE_REGISTRY[id(self)] = self._registry_tuple()

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("ValidatedLaunchClosureCapabilityV2 is immutable")

    def __copy__(self) -> Any:
        raise TypeError(
            "ValidatedLaunchClosureCapabilityV2 is not copyable"
        )

    def __deepcopy__(self, _memo: Any) -> Any:
        raise TypeError(
            "ValidatedLaunchClosureCapabilityV2 is not copyable"
        )

    def __reduce__(self) -> Any:
        raise TypeError(
            "ValidatedLaunchClosureCapabilityV2 is not serializable"
        )

    def __repr__(self) -> str:
        return "ValidatedLaunchClosureCapabilityV2(records=<redacted>)"

    def _registry_tuple(self) -> tuple[Any, ...]:
        return tuple(
            getattr(self, field)
            for field in self.__slots__
            if field != "_issuer"
        )


class ValidatedCurrentClosureCapabilityV2:
    __slots__ = (
        "_issuer",
        "_records_bytes",
        "_records_digest",
        "_artifact_bytes",
        "_artifact_digest",
        "_neutral_bytes",
        "_neutral_digest",
        "_reconciliation_bytes",
        "_reconciliation_digest",
        "_store_snapshot_digest",
        "_current_run_digest",
        "_run_id",
        "_generation",
        "_attempt_ordinal",
    )

    def __init__(
        self,
        _token: object,
        *,
        records_bytes: bytes,
        artifact_bytes: bytes,
        neutral_bytes: bytes,
        reconciliation_bytes: bytes,
        store_snapshot_digest: str,
        current_run_digest: str,
        run_id: str,
        generation: int,
        attempt_ordinal: int,
    ) -> None:
        if _token is not _CLOSURE_ISSUER:
            raise ConformanceError("VALIDATED_CLOSURE_CONSTRUCTOR_PRIVATE")
        object.__setattr__(self, "_issuer", _CLOSURE_ISSUER)
        for name, raw in (
            ("_records_bytes", records_bytes),
            ("_artifact_bytes", artifact_bytes),
            ("_neutral_bytes", neutral_bytes),
            ("_reconciliation_bytes", reconciliation_bytes),
        ):
            object.__setattr__(self, name, bytes(raw))
            object.__setattr__(
                self, name.replace("_bytes", "_digest"), sha256_bytes(raw)
            )
        object.__setattr__(
            self, "_store_snapshot_digest", store_snapshot_digest
        )
        object.__setattr__(self, "_current_run_digest", current_run_digest)
        object.__setattr__(self, "_run_id", run_id)
        object.__setattr__(self, "_generation", generation)
        object.__setattr__(self, "_attempt_ordinal", attempt_ordinal)
        _CLOSURE_REGISTRY[id(self)] = self._registry_tuple()

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("ValidatedCurrentClosureCapabilityV2 is immutable")

    def __copy__(self) -> Any:
        raise TypeError(
            "ValidatedCurrentClosureCapabilityV2 is not copyable"
        )

    def __deepcopy__(self, _memo: Any) -> Any:
        raise TypeError(
            "ValidatedCurrentClosureCapabilityV2 is not copyable"
        )

    def __reduce__(self) -> Any:
        raise TypeError(
            "ValidatedCurrentClosureCapabilityV2 is not serializable"
        )

    def __repr__(self) -> str:
        return (
            "ValidatedCurrentClosureCapabilityV2("
            "records=<redacted>, neutral=<redacted>)"
        )

    def _registry_tuple(self) -> tuple[Any, ...]:
        return tuple(
            getattr(self, field)
            for field in self.__slots__
            if field != "_issuer"
        )


def _decode_capability(
    capability: ValidatedCurrentClosureCapabilityV2,
    r25: Any,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    if (
        not isinstance(capability, ValidatedCurrentClosureCapabilityV2)
        or capability._issuer is not _CLOSURE_ISSUER
        or id(capability) not in _CLOSURE_REGISTRY
    ):
        raise ConformanceError("VALIDATED_CLOSURE_CONSTRUCTOR_PRIVATE")
    registered = _CLOSURE_REGISTRY[id(capability)]
    current = capability._registry_tuple()
    if registered != current:
        differing = {
            field
            for field, before, after in zip(
                (
                    field
                    for field in capability.__slots__
                    if field != "_issuer"
                ),
                registered,
                current,
            )
            if before != after
        }
        if differing & {
            "_artifact_bytes",
            "_artifact_digest",
            "_neutral_bytes",
            "_neutral_digest",
            "_reconciliation_bytes",
            "_reconciliation_digest",
        }:
            raise ConformanceError("VALIDATED_CLOSURE_NEUTRAL_MISMATCH")
        if differing & {
            "_store_snapshot_digest",
            "_current_run_digest",
            "_run_id",
            "_generation",
            "_attempt_ordinal",
        }:
            raise ConformanceError("VALIDATED_CLOSURE_STORE_MISMATCH")
        raise ConformanceError("VALIDATED_CLOSURE_RECORDS_MISMATCH")
    pairs = (
        (
            capability._records_bytes,
            capability._records_digest,
            "VALIDATED_CLOSURE_RECORDS_MISMATCH",
        ),
        (
            capability._artifact_bytes,
            capability._artifact_digest,
            "VALIDATED_CLOSURE_NEUTRAL_MISMATCH",
        ),
        (
            capability._neutral_bytes,
            capability._neutral_digest,
            "VALIDATED_CLOSURE_NEUTRAL_MISMATCH",
        ),
        (
            capability._reconciliation_bytes,
            capability._reconciliation_digest,
            "VALIDATED_CLOSURE_NEUTRAL_MISMATCH",
        ),
    )
    for raw, expected, error in pairs:
        if sha256_bytes(raw) != expected:
            raise ConformanceError(error)
    try:
        values = tuple(
            r25.parse_json(raw)
            for raw in (
                capability._records_bytes,
                capability._artifact_bytes,
                capability._neutral_bytes,
                capability._reconciliation_bytes,
            )
        )
    except Exception as exc:
        raise ConformanceError("VALIDATED_CLOSURE_RECORDS_MISMATCH") from exc
    if not all(isinstance(value, dict) for value in values):
        raise ConformanceError("VALIDATED_CLOSURE_RECORDS_MISMATCH")
    return values  # type: ignore[return-value]


def validate_rooted_post_consume_records(
    bundle: dict[str, Any],
    r251: Any,
    r25: Any,
    candidate: dict[str, Any],
    store: Any,
    *,
    map_observation_errors: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    run = validate_store_scope(bundle, r251, store)
    try:
        records = r251.validate_closure_v251(
            bundle, r25, candidate, store
        )
    except Exception as exc:
        text = str(exc)
        if map_observation_errors and (
            "OBSERVATION" in text
            or "EVIDENCE" in text
            or "PROOF_RULE" in text
        ):
            raise ConformanceError(
                "MANDATORY_NEUTRAL_OBSERVATION_MISMATCH"
            ) from exc
        raise ConformanceError(text) from exc
    if (
        records["root"]["routing_root_digest"]
        != store.load("root/current")["expected_routing_root_digest"]
        or records["attempt"]["generation"] != run["generation"]
        or records["attempt"]["attempt_ordinal"] != run["attempt_ordinal"]
        or store.load("transaction/current")["run_id"] != run["run_id"]
    ):
        raise ConformanceError("CURRENT_RUN_AUTHORITY_MISMATCH")
    try:
        r25.validate_environment(
            bundle,
            records["env_policy"],
            records["public_env"],
            records["raw_env"],
            records["envelope"],
        )
        r25.schema_validate(
            bundle, "ConsumedAttemptLaunchAuthorityV2", records["consumed"]
        )
        r25.verify_seal(records["consumed"], "consumed_launch_digest")
    except Exception as exc:
        raise ConformanceError(str(exc)) from exc
    if records["consumed"]["spawn_state"] != "CONSUMED_NOT_SPAWNED":
        raise ConformanceError("VALIDATED_CLOSURE_CONSUME_MISMATCH")
    return records, run


def validate_launch_capability(
    bundle: dict[str, Any],
    r251: Any,
    r25: Any,
    capability: ValidatedLaunchClosureCapabilityV2,
    store: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if (
        not isinstance(capability, ValidatedLaunchClosureCapabilityV2)
        or capability._issuer is not _LAUNCH_CLOSURE_ISSUER
        or id(capability) not in _LAUNCH_CLOSURE_REGISTRY
        or _LAUNCH_CLOSURE_REGISTRY[id(capability)]
        != capability._registry_tuple()
    ):
        raise ConformanceError("VALIDATED_CLOSURE_CONSTRUCTOR_PRIVATE")
    if sha256_bytes(capability._records_bytes) != capability._records_digest:
        raise ConformanceError("VALIDATED_CLOSURE_RECORDS_MISMATCH")
    run = validate_store_scope(bundle, r251, store)
    if (
        store.snapshot_digest != capability._store_snapshot_digest
        or run["authority_digest"] != capability._current_run_digest
        or (
            run["run_id"],
            run["generation"],
            run["attempt_ordinal"],
        )
        != (
            capability._run_id,
            capability._generation,
            capability._attempt_ordinal,
        )
    ):
        raise ConformanceError("VALIDATED_CLOSURE_STORE_MISMATCH")
    try:
        records = r25.parse_json(capability._records_bytes)
    except Exception as exc:
        raise ConformanceError("VALIDATED_CLOSURE_RECORDS_MISMATCH") from exc
    if not isinstance(records, dict):
        raise ConformanceError("VALIDATED_CLOSURE_RECORDS_MISMATCH")
    return records, run


def validate_and_mint_launch_closure_v252(
    bundle: dict[str, Any],
    r251: Any,
    r25: Any,
    launch_candidate: dict[str, Any],
    store: Any,
) -> ValidatedLaunchClosureCapabilityV2:
    records, run = validate_rooted_post_consume_records(
        bundle,
        r251,
        r25,
        launch_candidate,
        store,
        map_observation_errors=False,
    )
    stored_records = {
        key: copy.deepcopy(records[key])
        for key in (
            "root",
            "attempt",
            "route",
            "envelope",
            "predecessor_envelope",
            "env_policy",
            "public_env",
            "consumed",
        )
    }
    capability = ValidatedLaunchClosureCapabilityV2(
        _LAUNCH_CLOSURE_ISSUER,
        records_bytes=r25.canonical_bytes(stored_records),
        store_snapshot_digest=store.snapshot_digest,
        current_run_digest=run["authority_digest"],
        run_id=run["run_id"],
        generation=run["generation"],
        attempt_ordinal=run["attempt_ordinal"],
    )
    validate_launch_capability(bundle, r251, r25, capability, store)
    return capability


def validate_closure_capability(
    bundle: dict[str, Any],
    r251: Any,
    r25: Any,
    capability: ValidatedCurrentClosureCapabilityV2,
    store: Any,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    records, artifact, neutral, reconciliation = _decode_capability(
        capability, r25
    )
    run = validate_store_scope(bundle, r251, store)
    if store.snapshot_digest != capability._store_snapshot_digest:
        raise ConformanceError("VALIDATED_CLOSURE_STORE_MISMATCH")
    if run["authority_digest"] != capability._current_run_digest:
        raise ConformanceError("VALIDATED_CLOSURE_STORE_MISMATCH")
    if (
        run["run_id"],
        run["generation"],
        run["attempt_ordinal"],
    ) != (
        capability._run_id,
        capability._generation,
        capability._attempt_ordinal,
    ):
        raise ConformanceError("VALIDATED_CLOSURE_STORE_MISMATCH")
    schema_validate(bundle, r25, "ProviderArtifactAuthorityV1", artifact)
    verify_seal(r25, artifact, "authority_digest")
    schema_validate(bundle, r25, "NeutralObservationEvidenceV2", neutral)
    verify_seal(r25, neutral, "evidence_digest")
    schema_validate(
        bundle, r25, "NeutralReconciliationAuthorityV1", reconciliation
    )
    verify_seal(r25, reconciliation, "authority_digest")
    if (
        reconciliation["run_id"] != run["run_id"]
        or reconciliation["generation"] != run["generation"]
        or reconciliation["attempt_ordinal"] != run["attempt_ordinal"]
        or reconciliation["routing_root_digest"]
        != records["root"]["routing_root_digest"]
        or reconciliation["execution_attempt_digest"]
        != records["attempt"]["execution_attempt_digest"]
        or reconciliation["consumed_launch_digest"]
        != records["consumed"]["consumed_launch_digest"]
        or reconciliation["provider_artifact_authority_digest"]
        != artifact["authority_digest"]
        or reconciliation["neutral_evidence_digest"]
        != neutral["evidence_digest"]
        or reconciliation["legacy_observation_digest"]
        != records["observation"]["observation_digest"]
        or reconciliation["legacy_evidence_manifest_digest"]
        != records["evidence"]["evidence_manifest_digest"]
        or reconciliation["proof_rule_authority_digest"]
        != store.load("observation/rules")["authority_digest"]
        or reconciliation["usage_digest"] != artifact["usage_digest"]
        or reconciliation["raw_stream_digest"]
        != artifact["raw_stream_digest"]
    ):
        raise ConformanceError("VALIDATED_CLOSURE_NEUTRAL_MISMATCH")
    return records, artifact, neutral, reconciliation, run


def validate_and_mint_closure_v252(
    bundle: dict[str, Any],
    r251: Any,
    r25: Any,
    candidate: dict[str, Any],
    store: Any,
    provider_input: Any | None,
) -> ValidatedCurrentClosureCapabilityV2:
    if provider_input is None:
        raise ConformanceError("MANDATORY_PROVIDER_ARTIFACT_REQUIRED")
    expected_attempt = candidate["attempt"]["execution_attempt_digest"]
    _raw, artifact, neutral = derive_neutral_v252(
        bundle, r251, r25, provider_input, store, expected_attempt
    )
    validate_legacy_projection(r25, candidate, artifact, neutral)
    records, run = validate_rooted_post_consume_records(
        bundle,
        r251,
        r25,
        candidate,
        store,
        map_observation_errors=True,
    )
    rules = store.load("observation/rules")
    reconciliation = build_reconciliation(
        bundle, r25, records, run, artifact, neutral, rules
    )
    stored_records = copy.deepcopy(records)
    stored_records.pop("raw_env", None)
    capability = ValidatedCurrentClosureCapabilityV2(
        _CLOSURE_ISSUER,
        records_bytes=r25.canonical_bytes(stored_records),
        artifact_bytes=r25.canonical_bytes(artifact),
        neutral_bytes=r25.canonical_bytes(neutral),
        reconciliation_bytes=r25.canonical_bytes(reconciliation),
        store_snapshot_digest=store.snapshot_digest,
        current_run_digest=run["authority_digest"],
        run_id=run["run_id"],
        generation=run["generation"],
        attempt_ordinal=run["attempt_ordinal"],
    )
    validate_closure_capability(
        bundle, r251, r25, capability, store
    )
    return capability


def validate_spawn_inputs_from_capability(
    bundle: dict[str, Any],
    r251: Any,
    r25: Any,
    capability: ValidatedLaunchClosureCapabilityV2,
    store: Any,
    actual_policy: dict[str, Any],
    actual_consumed: dict[str, Any],
    raw_env: dict[str, str],
) -> dict[str, Any]:
    records, _run = validate_launch_capability(
        bundle, r251, r25, capability, store
    )
    try:
        r25.schema_validate(
            bundle, "PublicEnvironmentPolicyAuthorityV2", actual_policy
        )
        r25.verify_seal(
            actual_policy, "environment_policy_authority_digest"
        )
        for row in actual_policy["rows"]:
            r25.schema_validate(bundle, "PublicEnvironmentPolicyRowV2", row)
            r25.verify_seal(row, "policy_row_digest")
    except Exception as exc:
        raise ConformanceError(str(exc)) from exc
    if actual_policy != records["env_policy"]:
        raise ConformanceError("VALIDATED_CLOSURE_POLICY_MISMATCH")
    try:
        r25.validate_environment(
            bundle,
            actual_policy,
            records["public_env"],
            raw_env,
            records["envelope"],
        )
    except Exception as exc:
        raise ConformanceError(str(exc)) from exc
    try:
        r25.verify_seal(
            actual_consumed, "consumed_launch_digest"
        )
    except Exception as exc:
        raise ConformanceError(str(exc)) from exc
    if (
        actual_consumed != records["consumed"]
        or actual_consumed["spawn_state"] != "CONSUMED_NOT_SPAWNED"
    ):
        raise ConformanceError("VALIDATED_CLOSURE_CONSUME_MISMATCH")
    try:
        r25.schema_validate(
            bundle, "ConsumedAttemptLaunchAuthorityV2", actual_consumed
        )
    except Exception as exc:
        raise ConformanceError(str(exc)) from exc
    return records


def mint_proof_from_capability_v252(
    bundle: dict[str, Any],
    r251: Any,
    r25: Any,
    capability: ValidatedLaunchClosureCapabilityV2,
    store: Any,
    actual_policy: dict[str, Any],
    actual_consumed: dict[str, Any],
    raw_env: dict[str, str],
    process_nonce: bytes,
    object_nonce: bytes,
    key: bytes,
) -> Any:
    records = validate_spawn_inputs_from_capability(
        bundle,
        r251,
        r25,
        capability,
        store,
        actual_policy,
        actual_consumed,
        raw_env,
    )
    return r251.mint_verified_secret_proof(
        r25,
        records["envelope"],
        records["predecessor_envelope"],
        actual_policy,
        raw_env,
        process_nonce,
        object_nonce,
        key,
        actual_consumed,
    )


def authenticate_spawn_from_capability_v252(
    bundle: dict[str, Any],
    r251: Any,
    r25: Any,
    capability: ValidatedLaunchClosureCapabilityV2,
    store: Any,
    proof: Any,
    actual_policy: dict[str, Any],
    actual_consumed: dict[str, Any],
    raw_env: dict[str, str],
    process_nonce: bytes,
    object_nonce: bytes,
    key: bytes,
) -> Any:
    records = validate_spawn_inputs_from_capability(
        bundle,
        r251,
        r25,
        capability,
        store,
        actual_policy,
        actual_consumed,
        raw_env,
    )
    spawn = r251.mint_verified_spawn_capability(
        r25,
        proof,
        records["envelope"],
        records["predecessor_envelope"],
        actual_policy,
        raw_env,
        process_nonce,
        object_nonce,
        key,
        actual_consumed,
    )
    r251.validate_verified_spawn_capability(
        r25,
        spawn,
        records["envelope"],
        records["predecessor_envelope"],
        actual_policy,
        raw_env,
        process_nonce,
        object_nonce,
        key,
        actual_consumed,
    )
    return spawn


def validate_resume_v252(
    bundle: dict[str, Any],
    r251: Any,
    r25: Any,
    authority: dict[str, Any],
    capability: ValidatedCurrentClosureCapabilityV2,
    store: Any,
    completed: dict[str, Any] | None,
    ambiguous: dict[str, Any] | None,
    *,
    raw_current_records: dict[str, Any] | None = None,
) -> None:
    if raw_current_records is not None:
        raise ConformanceError("RESUME_VALIDATED_CLOSURE_REQUIRED")
    try:
        records, _artifact, _neutral, _reconciliation, run = (
            validate_closure_capability(
                bundle, r251, r25, capability, store
            )
        )
    except ConformanceError as exc:
        if str(exc) == "AUTHORITY_STORE_RUN_MISMATCH":
            raise ConformanceError("RESUME_RUN_SCOPE_MISMATCH") from exc
        raise
    prior_record, _prior = r251.load_prior_resume_identity(
        bundle, r25, store
    )
    if prior_record["run_id"] != run["run_id"]:
        raise ConformanceError("RESUME_RUN_SCOPE_MISMATCH")
    decision = authority["decision"]
    expected_generation = (
        run["generation"] + 1
        if decision == "NEW_GENERATION"
        else run["generation"]
    )
    expected_attempt = (
        run["attempt_ordinal"] + 1
        if decision == "RETRY_SAME_GENERATION"
        else (0 if decision == "NEW_GENERATION" else run["attempt_ordinal"])
    )
    if (
        authority["prior_generation"] != run["generation"]
        or authority["prior_attempt_ordinal"] != run["attempt_ordinal"]
    ):
        raise ConformanceError("RESUME_PRIOR_STORE_MISMATCH")
    if (
        authority["current_generation"] != expected_generation
        or authority["current_attempt_ordinal"] != expected_attempt
    ):
        raise ConformanceError("RESUME_CURRENT_SCOPE_MISMATCH")
    r251.validate_resume_v251(
        bundle,
        r25,
        authority,
        store,
        records,
        completed,
        ambiguous,
    )


def build_context(
    bundle: dict[str, Any],
    r251: Any,
    r25: Any,
    r23: Any,
    r24: Any,
) -> dict[str, Any]:
    base = r251.build_context(bundle, r25, r23, r24)
    snapshot = scoped_snapshot(r251, base["snapshot"])
    store = r251._fixture_trusted_store(snapshot)
    launch_candidate = copy.deepcopy(base["candidate"])
    launch_closure = validate_and_mint_launch_closure_v252(
        bundle, r251, r25, launch_candidate, store
    )
    launch_records, _launch_run = validate_launch_capability(
        bundle, r251, r25, launch_closure, store
    )
    proof = mint_proof_from_capability_v252(
        bundle,
        r251,
        r25,
        launch_closure,
        store,
        launch_records["env_policy"],
        launch_records["consumed"],
        base["raw_env"],
        base["process_nonce"],
        base["object_nonce"],
        base["key"],
    )
    spawn = authenticate_spawn_from_capability_v252(
        bundle,
        r251,
        r25,
        launch_closure,
        store,
        proof,
        launch_records["env_policy"],
        launch_records["consumed"],
        base["raw_env"],
        base["process_nonce"],
        base["object_nonce"],
        base["key"],
    )
    _raw, artifact, neutral = derive_neutral_v252(
        bundle,
        r251,
        r25,
        base["provider_input"],
        store,
        base["records"]["attempt"]["execution_attempt_digest"],
    )
    candidate = project_candidate_to_neutral(
        r25, base["candidate"], artifact, neutral
    )
    capability = validate_and_mint_closure_v252(
        bundle, r251, r25, candidate, store, base["provider_input"]
    )
    records, _a, _n, _rec, _run = validate_closure_capability(
        bundle, r251, r25, capability, store
    )
    return {
        **base,
        "snapshot": snapshot,
        "store": store,
        "launch_candidate": launch_candidate,
        "launch_records_v252": launch_records,
        "launch_closure": launch_closure,
        "candidate": candidate,
        "records_v252": records,
        "artifact_v252": artifact,
        "neutral_v252": neutral,
        "closure": capability,
        "proof_v252": proof,
        "spawn_v252": spawn,
    }


def store_from_snapshot(
    r251: Any,
    snapshot: dict[str, dict[str, Any]],
    revision: int = 1,
) -> Any:
    return r251._fixture_trusted_store(snapshot, revision)


def resume_authority_for_context(
    r25: Any,
    context: dict[str, Any],
) -> dict[str, Any]:
    records = context["records_v252"]
    identity = r25.resume_identity(records)
    return r25.resume_authority(
        identity,
        identity,
        "RETRY_SAME_GENERATION",
        prior_generation=1,
        current_generation=1,
        prior_attempt=0,
        current_attempt=1,
    )


def provider_with_mutation(
    r251: Any,
    r25: Any,
    context: dict[str, Any],
    frame_index: int,
    field: str,
    value: Any,
) -> Any:
    frames = [
        r25.parse_json(line)
        for line in context["provider_raw"].rstrip(b"\n").split(b"\n")
    ]
    frames[frame_index][field] = value
    raw = b"\n".join(r25.canonical_bytes(frame) for frame in frames) + b"\n"
    return r251._fixture_provider_artifact(
        raw, context["records"]["attempt"]["execution_attempt_digest"]
    )


def rebuild_run_after_snapshot_change(
    r251: Any,
    snapshot: dict[str, dict[str, Any]],
) -> None:
    snapshot["run/current"] = build_current_run(r251, snapshot)


def rebind_transaction_parent(
    r25: Any,
    snapshot: dict[str, dict[str, Any]],
    key: str,
    tx_field: str,
) -> None:
    seal(r25, snapshot[key], "authority_digest")
    snapshot["transaction/current"][tx_field] = snapshot[key][
        "authority_digest"
    ]
    seal(
        r25,
        snapshot["transaction/current"],
        "authority_digest",
    )


def run_scenario(
    bundle: dict[str, Any],
    r251: Any,
    r25: Any,
    r23: Any,
    r24: Any,
    name: str,
) -> None:
    context = build_context(bundle, r251, r25, r23, r24)
    records = context["records_v252"]

    if name in {
        "post-mint secret presence policy mutation",
        "post-mint non-secret source class mutation",
        "policy-row seal mutation at sink",
    }:
        policy = copy.deepcopy(records["env_policy"])
        row_index = (
            0
            if name != "post-mint non-secret source class mutation"
            else 1
        )
        row = policy["rows"][row_index]
        if name == "post-mint secret presence policy mutation":
            row["presence_policy"] = "OPTIONAL"
            seal(r25, row, "policy_row_digest")
            seal(
                r25, policy, "environment_policy_authority_digest"
            )
        elif name == "post-mint non-secret source class mutation":
            row["source_class"] = "HOST_DERIVED_NON_SECRET"
            seal(r25, row, "policy_row_digest")
            seal(
                r25, policy, "environment_policy_authority_digest"
            )
        else:
            row["presence_policy"] = "OPTIONAL"
        authenticate_spawn_from_capability_v252(
            bundle,
            r251,
            r25,
            context["launch_closure"],
            context["store"],
            context["proof_v252"],
            policy,
            records["consumed"],
            context["raw_env"],
            context["process_nonce"],
            context["object_nonce"],
            context["key"],
        )
        return
    if name in {
        "post-mint consumed spawn-state mutation",
        "post-mint consumed CAS mutation",
        "consumed-record seal mutation at sink",
    }:
        consumed = copy.deepcopy(records["consumed"])
        if name == "post-mint consumed spawn-state mutation":
            consumed["spawn_state"] = "SPAWNED"
            seal(r25, consumed, "consumed_launch_digest")
        elif name == "post-mint consumed CAS mutation":
            consumed["consume_cas_revision"] = 999
            seal(r25, consumed, "consumed_launch_digest")
        else:
            consumed["consume_cas_revision"] = 999
        authenticate_spawn_from_capability_v252(
            bundle,
            r251,
            r25,
            context["launch_closure"],
            context["store"],
            context["proof_v252"],
            records["env_policy"],
            consumed,
            context["raw_env"],
            context["process_nonce"],
            context["object_nonce"],
            context["key"],
        )
        return
    if name == "validated closure external mutation is isolated":
        context["launch_candidate"]["env_policy"]["rows"][0][
            "presence_policy"
        ] = "OPTIONAL"
        authenticate_spawn_from_capability_v252(
            bundle,
            r251,
            r25,
            context["launch_closure"],
            context["store"],
            context["proof_v252"],
            records["env_policy"],
            records["consumed"],
            context["raw_env"],
            context["process_nonce"],
            context["object_nonce"],
            context["key"],
        )
        return
    if name == "valid consume-then-proof-then-spawn order":
        proof = mint_proof_from_capability_v252(
            bundle,
            r251,
            r25,
            context["launch_closure"],
            context["store"],
            records["env_policy"],
            records["consumed"],
            context["raw_env"],
            context["process_nonce"],
            context["object_nonce"],
            context["key"],
        )
        authenticate_spawn_from_capability_v252(
            bundle,
            r251,
            r25,
            context["launch_closure"],
            context["store"],
            proof,
            records["env_policy"],
            records["consumed"],
            context["raw_env"],
            context["process_nonce"],
            context["object_nonce"],
            context["key"],
        )
        return

    authority = resume_authority_for_context(r25, context)
    if name == "resume raw current records forbidden":
        validate_resume_v252(
            bundle,
            r251,
            r25,
            authority,
            context["closure"],
            context["store"],
            None,
            None,
            raw_current_records=records,
        )
        return
    if name == "resume cross-run prior authority":
        snapshot = copy.deepcopy(context["snapshot"])
        snapshot["resume/prior"]["run_id"] = "other-run"
        seal(r25, snapshot["resume/prior"], "authority_digest")
        rebuild_run_after_snapshot_change(r251, snapshot)
        validate_resume_v252(
            bundle,
            r251,
            r25,
            authority,
            context["closure"],
            store_from_snapshot(r251, snapshot),
            None,
            None,
        )
        return
    if name == "resume external records mutation is isolated":
        context["candidate"]["root"]["semantic_plan_digest"] = r25.d("a")
        validate_resume_v252(
            bundle,
            r251,
            r25,
            authority,
            context["closure"],
            context["store"],
            None,
            None,
        )
        return
    if name == "forged validated-closure constructor":
        ValidatedCurrentClosureCapabilityV2(
            object(),
            records_bytes=b"{}\n",
            artifact_bytes=b"{}\n",
            neutral_bytes=b"{}\n",
            reconciliation_bytes=b"{}\n",
            store_snapshot_digest=r25.d("1"),
            current_run_digest=r25.d("2"),
            run_id="forged",
            generation=1,
            attempt_ordinal=0,
        )
        return
    if name == "validated closure store snapshot mismatch":
        snapshot = copy.deepcopy(context["snapshot"])
        snapshot["transaction/reconciliation"][
            "incorporated_output_set_digest"
        ] = r25.d("a")
        rebind_transaction_parent(
            r25,
            snapshot,
            "transaction/reconciliation",
            "reconciliation_parent_digest",
        )
        rebuild_run_after_snapshot_change(r251, snapshot)
        validate_closure_capability(
            bundle,
            r251,
            r25,
            context["closure"],
            store_from_snapshot(r251, snapshot),
        )
        return
    if name == "fabricated prior and current closure":
        fabricated = copy.deepcopy(records)
        fabricated["root"]["semantic_plan_digest"] = r25.d("f")
        validate_resume_v252(
            bundle,
            r251,
            r25,
            authority,
            context["closure"],
            context["store"],
            None,
            None,
            raw_current_records=fabricated,
        )
        return
    if name == "resume current generation mismatch":
        authority["current_generation"] = 99
        seal(r25, authority, "resume_authority_digest")
        validate_resume_v252(
            bundle,
            r251,
            r25,
            authority,
            context["closure"],
            context["store"],
            None,
            None,
        )
        return
    if name == "valid resume from immutable closure":
        validate_resume_v252(
            bundle,
            r251,
            r25,
            authority,
            context["closure"],
            context["store"],
            None,
            None,
        )
        return

    if name in {
        "full closure fabricated legacy observation",
        "full closure caller-authored legacy proof rule",
        "neutral claim order mutation",
        "neutral claim count mutation",
        "neutral raw-stream digest mutation",
        "neutral usage digest mutation",
    }:
        candidate = copy.deepcopy(context["candidate"])
        if name == "full closure fabricated legacy observation":
            candidate["observation"]["observed_effective_model_id"] = (
                "fabricated-model"
            )
            seal(
                r25, candidate["observation"], "observation_digest"
            )
        elif name == "full closure caller-authored legacy proof rule":
            claim = candidate["evidence"]["field_claims"][0]
            claim["proof_rule_id"] = "CALLER_ASSERTED"
            seal(r25, claim, "field_claim_digest")
            seal(
                r25,
                candidate["evidence"],
                "evidence_manifest_digest",
            )
        elif name == "neutral claim order mutation":
            candidate["evidence"]["field_claims"].reverse()
            seal(
                r25,
                candidate["evidence"],
                "evidence_manifest_digest",
            )
        elif name == "neutral claim count mutation":
            candidate["evidence"]["claim_count"] = 4
            seal(
                r25,
                candidate["evidence"],
                "evidence_manifest_digest",
            )
        elif name == "neutral raw-stream digest mutation":
            candidate["observation"]["raw_stream_digest"] = r25.d("a")
            seal(
                r25, candidate["observation"], "observation_digest"
            )
        else:
            candidate["observation"]["provider_usage_digest"] = r25.d(
                "a"
            )
            seal(
                r25, candidate["observation"], "observation_digest"
            )
        validate_and_mint_closure_v252(
            bundle,
            r251,
            r25,
            candidate,
            context["store"],
            context["provider_input"],
        )
        return
    if name in {
        "neutral unknown thinking state",
        "neutral unknown fallback state",
        "neutral unknown terminal category",
        "neutral malformed usage object",
    }:
        frame_index, field, value = {
            "neutral unknown thinking state": (
                0,
                "thinking_state",
                "INVENTED_STATE",
            ),
            "neutral unknown fallback state": (
                1,
                "fallback_state",
                "INVENTED_STATE",
            ),
            "neutral unknown terminal category": (
                1,
                "terminal_category",
                "INVENTED_STATE",
            ),
            "neutral malformed usage object": (
                1,
                "usage",
                {
                    "input_tokens": "one",
                    "output_tokens": 20,
                    "private_note": "arbitrary",
                },
            ),
        }[name]
        provider = provider_with_mutation(
            r251, r25, context, frame_index, field, value
        )
        validate_and_mint_closure_v252(
            bundle,
            r251,
            r25,
            context["candidate"],
            context["store"],
            provider,
        )
        return
    if name == "full closure omits provider artifact":
        validate_and_mint_closure_v252(
            bundle,
            r251,
            r25,
            context["candidate"],
            context["store"],
            None,
        )
        return
    if name == "neutral evidence mutated after closure":
        object.__setattr__(
            context["closure"],
            "_neutral_bytes",
            context["closure"]._neutral_bytes + b" ",
        )
        validate_closure_capability(
            bundle,
            r251,
            r25,
            context["closure"],
            context["store"],
        )
        return
    if name == "valid mandatory neutral closure":
        validate_closure_capability(
            bundle,
            r251,
            r25,
            context["closure"],
            context["store"],
        )
        return

    snapshot = copy.deepcopy(context["snapshot"])
    if name == "transaction parent-set internal key mismatch":
        snapshot["transaction/current"]["store_key"] = (
            "transaction/other"
        )
        seal(
            r25,
            snapshot["transaction/current"],
            "authority_digest",
        )
        rebuild_run_after_snapshot_change(r251, snapshot)
    elif name == "cross-run transaction parent set":
        snapshot["transaction/current"]["run_id"] = "other-run"
        seal(
            r25,
            snapshot["transaction/current"],
            "authority_digest",
        )
        rebuild_run_after_snapshot_change(r251, snapshot)
    elif name == "extra untyped store record":
        snapshot["unscoped/extra"] = {
            "schema": "caller.extra.v1",
            "value": "arbitrary",
        }
    elif name == "extra raw-secret store record":
        snapshot["unscoped/raw-secret"] = {
            "schema": "caller.secret.v1",
            "raw_secret": "must-not-enter-trusted-store",
        }
    elif name == "store revision rollback":
        validate_store_scope(
            bundle, r251, store_from_snapshot(r251, snapshot, 2)
        )
        return
    elif name == "cross-run current snapshot":
        snapshot["run/current"]["run_id"] = "other-run"
        seal(r25, snapshot["run/current"], "authority_digest")
    elif name == "current-run authority seal tamper":
        snapshot["run/current"]["run_id"] = "tampered"
    elif name == "current-run root binding mismatch":
        snapshot["run/current"][
            "root_preimage_authority_digest"
        ] = r25.d("a")
        seal(r25, snapshot["run/current"], "authority_digest")
    elif name == "current-run proof-rule binding mismatch":
        snapshot["run/current"]["proof_rule_authority_digest"] = r25.d(
            "a"
        )
        seal(r25, snapshot["run/current"], "authority_digest")
    elif name == "missing current-run namespace member":
        del snapshot["transaction/materialization"]
    elif name == "valid exact run-scoped namespace":
        validate_store_scope(bundle, r251, context["store"])
        return
    else:
        raise ConformanceError(f"UNKNOWN_SCENARIO:{name}")
    validate_store_scope(
        bundle, r251, store_from_snapshot(r251, snapshot)
    )


def validate_review_binding() -> None:
    raw = read_ascii_lf(REVIEW_PATH)
    if sha256_bytes(raw) != REVIEW_WHOLE_SHA256:
        raise ConformanceError("R2_5_1_REVIEW_WHOLE_HASH_MISMATCH")
    marker = b"\n## Artifact integrity\n"
    position = raw.rfind(marker)
    if position < 0:
        raise ConformanceError("R2_5_1_REVIEW_BODY_BOUNDARY_MISSING")
    body = raw[:position]
    if sha256_bytes(body) != REVIEW_BODY_SHA256:
        raise ConformanceError("R2_5_1_REVIEW_BODY_HASH_MISMATCH")


def verify_frozen_r251() -> Any:
    r251 = import_exact(R251_PATH, R251_SHA256, "r251")
    completed = subprocess.run(
        [sys.executable, "-I", str(R251_PATH)],
        cwd=str(HERE),
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    if completed.returncode != 0:
        raise ConformanceError("R2_5_1_PRESERVATION_EXECUTION_FAILED")
    if set(completed.stdout.splitlines()) != R251_EXPECTED:
        raise ConformanceError("R2_5_1_PRESERVATION_OUTPUT_MISMATCH")
    return r251


def validate_vector_manifest(
    vectors: dict[str, Any],
) -> list[dict[str, Any]]:
    if (
        vectors.get("schema")
        != "plamen.model-routing-r2.5.2-conformance-vectors.v1"
        or vectors.get("version") != 1
    ):
        raise ConformanceError("R2_5_2_VECTOR_SCHEMA_MISMATCH")
    review = vectors.get("blocking_review", {})
    if (
        review.get("whole_sha256") != REVIEW_WHOLE_SHA256
        or review.get("body_sha256") != REVIEW_BODY_SHA256
        or review.get("fresh_operations") != 73
        or review.get("unexpected_accepts") != 15
    ):
        raise ConformanceError("R2_5_2_REVIEW_BINDING_MISMATCH")
    preserved = vectors.get("preserved_denominator", {})
    if (
        preserved.get("r2_5_1_validator_sha256") != R251_SHA256
        or preserved.get("r2_5_1_vectors_sha256")
        != "e4e3804b86ab4251902ebdbafc99f5acae3d1409bd56255c730b345fb9c6b9e8"
        or preserved.get("executed_total") != 646
    ):
        raise ConformanceError("R2_5_2_PRESERVED_DENOMINATOR_MISMATCH")
    adjudication = vectors.get("manifest_adjudication", {})
    if (
        adjudication.get("historical_declared_sha256")
        != "61981cac2042e9c7854737e6de759ef6fae2f3fe7ad405f721b431e8dbceabca"
        or adjudication.get("reproducible_truth_sha256")
        != "fad68edc4f82e09c0eed8d5bc1139e389e32c70f14efa783bb419d93bcbf8f9b"
        or adjudication.get("restricted_json_bytes") != 2851
    ):
        raise ConformanceError("R2_5_2_MANIFEST_ADJUDICATION_MISMATCH")
    rows = vectors.get("r2_5_2_vectors")
    if not isinstance(rows, list) or len(rows) != 40:
        raise ConformanceError("R2_5_2_VECTOR_COUNT_MISMATCH")
    if [row.get("id") for row in rows] != [
        f"R2.5.2-{number:03d}" for number in range(1, 41)
    ]:
        raise ConformanceError("R2_5_2_VECTOR_ID_MISMATCH")
    if len({row.get("scenario") for row in rows}) != 40:
        raise ConformanceError("R2_5_2_VECTOR_SCENARIO_DUPLICATE")
    expected_partition = (
        ["B1"] * 8 + ["B2"] * 8 + ["B3"] * 13 + ["B4"] * 11
    )
    if [row.get("blocker") for row in rows] != expected_partition:
        raise ConformanceError("R2_5_2_VECTOR_PARTITION_MISMATCH")
    return rows


def validate_positive_boundaries(
    bundle: dict[str, Any],
    r251: Any,
    r25: Any,
    r23: Any,
    r24: Any,
) -> None:
    context = build_context(bundle, r251, r25, r23, r24)
    validate_closure_capability(
        bundle,
        r251,
        r25,
        context["closure"],
        context["store"],
    )
    launch_records, _launch_run = validate_launch_capability(
        bundle,
        r251,
        r25,
        context["launch_closure"],
        context["store"],
    )
    if set(launch_records) & {
        "observation",
        "evidence",
        "transaction",
        "raw_env",
    }:
        raise ConformanceError(
            "LAUNCH_CAPABILITY_PROVIDER_OUTPUT_CLAIM_FORBIDDEN"
        )
    if (
        "<redacted>" not in repr(context["closure"])
        or "<redacted>" not in repr(context["launch_closure"])
    ):
        raise ConformanceError("VALIDATED_CLOSURE_REPR_LEAK")
    for operation in (
        lambda: copy.copy(context["closure"]),
        lambda: copy.deepcopy(context["closure"]),
        lambda: pickle.dumps(context["closure"]),
        lambda: copy.copy(context["launch_closure"]),
        lambda: copy.deepcopy(context["launch_closure"]),
        lambda: pickle.dumps(context["launch_closure"]),
    ):
        try:
            operation()
        except (TypeError, ConformanceError):
            pass
        else:
            raise ConformanceError(
                "VALIDATED_CLOSURE_COPY_OR_SERIALIZATION_ACCEPTED"
            )
    validate_store_scope(bundle, r251, context["store"])
    validate_resume_v252(
        bundle,
        r251,
        r25,
        resume_authority_for_context(r25, context),
        context["closure"],
        context["store"],
        None,
        None,
    )


def validate_author_hardening(
    bundle: dict[str, Any],
    r251: Any,
    r25: Any,
    r23: Any,
    r24: Any,
) -> int:
    context = build_context(bundle, r251, r25, r23, r24)
    fake_launch = object.__new__(ValidatedLaunchClosureCapabilityV2)
    for slot in ValidatedLaunchClosureCapabilityV2.__slots__:
        object.__setattr__(
            fake_launch, slot, getattr(context["launch_closure"], slot)
        )
    expect_error(
        lambda: validate_launch_capability(
            bundle, r251, r25, fake_launch, context["store"]
        ),
        "VALIDATED_CLOSURE_CONSTRUCTOR_PRIVATE",
    )
    launch_original = context["launch_closure"]._records_bytes
    launch_changed = launch_original + b" "
    object.__setattr__(
        context["launch_closure"], "_records_bytes", launch_changed
    )
    object.__setattr__(
        context["launch_closure"],
        "_records_digest",
        sha256_bytes(launch_changed),
    )
    expect_error(
        lambda: validate_launch_capability(
            bundle,
            r251,
            r25,
            context["launch_closure"],
            context["store"],
        ),
        "VALIDATED_CLOSURE_CONSTRUCTOR_PRIVATE",
    )
    fake = object.__new__(ValidatedCurrentClosureCapabilityV2)
    for slot in ValidatedCurrentClosureCapabilityV2.__slots__:
        object.__setattr__(fake, slot, getattr(context["closure"], slot))
    expect_error(
        lambda: validate_closure_capability(
            bundle, r251, r25, fake, context["store"]
        ),
        "VALIDATED_CLOSURE_CONSTRUCTOR_PRIVATE",
    )
    original = context["closure"]._records_bytes
    changed = original + b" "
    object.__setattr__(context["closure"], "_records_bytes", changed)
    object.__setattr__(
        context["closure"], "_records_digest", sha256_bytes(changed)
    )
    expect_error(
        lambda: validate_closure_capability(
            bundle, r251, r25, context["closure"], context["store"]
        ),
        "VALIDATED_CLOSURE_RECORDS_MISMATCH",
    )
    context = build_context(bundle, r251, r25, r23, r24)
    snapshot = copy.deepcopy(context["snapshot"])
    snapshot["resume/prior"]["generation"] = 2
    seal(r25, snapshot["resume/prior"], "authority_digest")
    rebuild_run_after_snapshot_change(r251, snapshot)
    expect_error(
        lambda: validate_store_scope(
            bundle, r251, store_from_snapshot(r251, snapshot)
        ),
        "AUTHORITY_STORE_RUN_MISMATCH",
    )
    snapshot = copy.deepcopy(context["snapshot"])
    snapshot["transaction/consumption"]["attempt_ordinal"] = 2
    rebind_transaction_parent(
        r25,
        snapshot,
        "transaction/consumption",
        "consumption_parent_digest",
    )
    rebuild_run_after_snapshot_change(r251, snapshot)
    expect_error(
        lambda: validate_store_scope(
            bundle, r251, store_from_snapshot(r251, snapshot)
        ),
        "AUTHORITY_STORE_RUN_MISMATCH",
    )
    snapshot = copy.deepcopy(context["snapshot"])
    snapshot["root/current"]["store_revision"] = 2
    seal(r25, snapshot["root/current"], "authority_digest")
    rebuild_run_after_snapshot_change(r251, snapshot)
    expect_error(
        lambda: validate_store_scope(
            bundle, r251, store_from_snapshot(r251, snapshot)
        ),
        "AUTHORITY_STORE_REVISION_MISMATCH",
    )
    provider = provider_with_mutation(
        r251, r25, context, 0, "effective_effort", "invented"
    )
    expect_error(
        lambda: validate_and_mint_closure_v252(
            bundle,
            r251,
            r25,
            context["candidate"],
            context["store"],
            provider,
        ),
        "NEUTRAL_STATE_GRAMMAR_MISMATCH",
    )

    def invalid_usage_provider(usage: dict[str, Any]) -> Any:
        frames = [
            r25.parse_json(line)
            for line in context["provider_raw"].rstrip(b"\n").split(b"\n")
        ]
        frames[1]["usage"] = usage
        raw = (
            b"\n".join(
                json.dumps(
                    frame,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ).encode("utf-8")
                for frame in frames
            )
            + b"\n"
        )
        return r251._fixture_provider_artifact(
            raw,
            context["records"]["attempt"]["execution_attempt_digest"],
        )

    expect_error(
        lambda: validate_and_mint_closure_v252(
            bundle,
            r251,
            r25,
            context["candidate"],
            context["store"],
            invalid_usage_provider(
                {"input_tokens": True, "output_tokens": 20}
            ),
        ),
        "PROVIDER_USAGE_SCHEMA_MISMATCH",
    )
    expect_error(
        lambda: validate_and_mint_closure_v252(
            bundle,
            r251,
            r25,
            context["candidate"],
            context["store"],
            invalid_usage_provider(
                {"input_tokens": -1, "output_tokens": 20}
            ),
        ),
        "INTEGER_OUT_OF_RANGE",
    )
    policy = copy.deepcopy(context["records_v252"]["env_policy"])
    policy["rows"].append(copy.deepcopy(policy["rows"][1]))
    policy["rows"][-1]["name"] = "OTHER_PATH"
    seal(r25, policy["rows"][-1], "policy_row_digest")
    policy["expected_row_count"] = 3
    seal(r25, policy, "environment_policy_authority_digest")
    expect_error(
        lambda: validate_spawn_inputs_from_capability(
            bundle,
            r251,
            r25,
            context["launch_closure"],
            context["store"],
            policy,
            context["records_v252"]["consumed"],
            context["raw_env"],
        ),
        "VALIDATED_CLOSURE_POLICY_MISMATCH",
    )
    consumed = copy.deepcopy(context["records_v252"]["consumed"])
    consumed["consume_cas_revision"] = 3
    seal(r25, consumed, "consumed_launch_digest")
    expect_error(
        lambda: validate_spawn_inputs_from_capability(
            bundle,
            r251,
            r25,
            context["launch_closure"],
            context["store"],
            context["records_v252"]["env_policy"],
            consumed,
            context["raw_env"],
        ),
        "VALIDATED_CLOSURE_CONSUME_MISMATCH",
    )
    return 12


def main() -> int:
    schema_raw = read_ascii_lf(SCHEMA_PATH)
    vectors_raw = read_ascii_lf(VECTORS_PATH)
    if sha256_bytes(schema_raw) != SCHEMA_SHA256:
        raise ConformanceError("R2_5_2_SCHEMA_HASH_MISMATCH")
    if sha256_bytes(vectors_raw) != VECTORS_SHA256:
        raise ConformanceError("R2_5_2_VECTORS_HASH_MISMATCH")
    validate_review_binding()
    r251 = verify_frozen_r251()
    r25 = r251.verify_frozen_r25()
    try:
        bundle = r25.parse_json(schema_raw)
        vectors = r25.parse_json(vectors_raw)
    except Exception as exc:
        raise ConformanceError(str(exc)) from exc
    try:
        Draft202012Validator.check_schema(bundle)
    except SchemaError as exc:
        raise ConformanceError("R2_5_2_META_SCHEMA_INVALID") from exc
    rows = validate_vector_manifest(vectors)
    r23, r24 = r25.verify_frozen_denominators()
    validate_positive_boundaries(bundle, r251, r25, r23, r24)
    hardening_count = validate_author_hardening(
        bundle, r251, r25, r23, r24
    )
    for row in rows:
        scenario = row["scenario"]
        operation = lambda scenario=scenario: run_scenario(
            bundle, r251, r25, r23, r24, scenario
        )
        if row["expected"] == "PASS":
            operation()
        else:
            expect_error(operation, row["expected"])
    print("R2.5.2_CONFORMANCE=PASS")
    print("R2_5_1_PRESERVED_EXECUTED_DENOMINATOR=646")
    print("R2_5_2_NEW_VECTORS=40")
    print("TOTAL_EXECUTED_VECTOR_DENOMINATOR=686")
    print(f"AUTHOR_HARDENING_PROBES={hardening_count}")
    print(f"SCHEMA_SHA256={SCHEMA_SHA256}")
    print(f"VECTORS_SHA256={VECTORS_SHA256}")
    print("BLOCKERS_CLOSED=B1,B2,B3,B4")
    print("AUTHOR_DISPOSITION=SELF_VALIDATED_NOT_INDEPENDENT_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
