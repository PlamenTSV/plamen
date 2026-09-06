from __future__ import annotations

import copy
import hashlib
import importlib.util
import inspect
import json
import subprocess
import sys
import types
from pathlib import Path
from typing import Any, Callable

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError


HERE = Path(__file__).resolve().parent
PLAN_PATH = (
    HERE
    / "Plamen_Backend_Model_Routing_R2.5.5_RED_Engineering_Plan_2026-07-30.md"
)
SCHEMA_PATH = (
    HERE / "Plamen_Backend_Model_Routing_R2.5.5_RED_Schemas_2026-07-30.json"
)
VECTORS_PATH = (
    HERE
    / "Plamen_Backend_Model_Routing_R2.5.5_RED_Operation_Vectors_2026-07-30.json"
)
R254_PATH = HERE / "validate_plamen_model_routing_r2_5_4_red.py"
R252_PATH = HERE / "validate_plamen_model_routing_r2_5_2.py"
REVIEW_PATH = (
    HERE.parent
    / "plamen-codex-implementation"
    / "review_fixtures"
    / "backend_model_routing_r2_5_4_red_independent_review_r1_20260730.md"
)

PLAN_SHA256 = (
    "0c956c956285735740bc256f04922b78d2a38b4aaf876cbcf85507dced3fa160"
)
SCHEMA_SHA256 = (
    "8c8e1638746592c5914c901a8b7730a6a3117a7ccf97b397d0596a4b91255c4e"
)
VECTORS_SHA256 = (
    "925a3d6eee98bd501801e568bd80af6d84f16a3c2e819070cbf1e89f31ed2f16"
)
R254_SHA256 = (
    "764d3a741cbb195f325794c8c0b03352ef4fc6de1f49cd0a9f4d186fd06cae2d"
)
R252_SHA256 = (
    "54308ee13491bf43ab006d65b11bb4c60e70f620d17eb8b209288ef2ac5a785c"
)
REVIEW_BODY_SHA256 = (
    "25723133c196edd6a94a2e7f677811d3535fd2c65a3fd9364de5c044cf046ebd"
)
REVIEW_WHOLE_SHA256 = (
    "82b0bdb39cca446bacb2bddc596c81562b22cec9e2be0e3c5268a9fb53f4b9c9"
)
R254_EXPECTED = [
    "R2.5.4_RED_DENOMINATOR=PASS",
    "FROZEN_R2_5_3_BASELINE=PASS",
    "PRESERVED_PREDECESSOR_OPERATIONS=15",
    "PRESERVED_ATOMIC_B5_OPERATIONS=14",
    "SOURCE_AUTHORITY_OPERATIONS=43",
    "DERIVED_LIFECYCLE_OPERATIONS=853",
    "DERIVED_GRAPH_OPERATIONS=586",
    "TOTAL_EXECUTED_OPERATIONS=1511",
    (
        "OPERATION_MANIFEST_SHA256="
        "2c13a363f2535693b11f6b9e61d618bb4a5fc37ef9f4348a3fa74dc6c515e84e"
    ),
    (
        "PLAN_SHA256="
        "9fa75435752ccd778cbda7b691d8c3e7295fe62fab4f2a0f96f0fcbc4f9ed303"
    ),
    (
        "SCHEMA_SHA256="
        "fec29bc5b7db5ca4edfe7a7b3ae60a7ce70b7c2960dcd7ee9c37378ea65df2cf"
    ),
    (
        "VECTORS_SHA256="
        "6f3e593bd9ba0e98ad684398629e78d4ffdd89ba0073133ed86b2629bfefa78f"
    ),
    "EXECUTED_FAMILY_COUNT=10",
    "GREEN_IMPLEMENTATION_AUTHORIZED=false",
    "PRODUCTION_INTEGRATION_AUTHORIZED=false",
    "AUTHOR_DISPOSITION=RED_REFERENCE_MODEL_SELF_VALIDATED_ONLY",
]

RUN_ID = "run-r255"
GENERATION = 3
ATTEMPT = 4
ZERO = "0" * 64
LAUNCH_REPLAY = hashlib.sha256(b"launch-replay-r255").hexdigest()
PROCESS = hashlib.sha256(b"process-r255").hexdigest()
TRANSPORT = hashlib.sha256(b"transport-r255").hexdigest()
PROVIDER_FRAME = hashlib.sha256(b"provider-frame-r255").hexdigest()
PROVIDER_TERMINAL = hashlib.sha256(b"provider-terminal-r255").hexdigest()
EVIDENCE = hashlib.sha256(b"governed-evidence-r255").hexdigest()
CONSUMED_CAS = hashlib.sha256(b"consumed-cas-r255").hexdigest()
INTENT_NONCE = hashlib.sha256(b"intent-nonce-r255").hexdigest()

EVENT_SCHEMA_BY_TOKEN = {
    "C": "ConsumedAttemptLaunchAuthorityV2",
    "I": "SpawnIntentAuthorityV1",
    "A": "SpawnAmbiguityAuthorityV1",
    "Q": "SpawnAmbiguityResolutionAuthorityV1",
    "S": "SpawnedAttemptAuthorityV1",
    "T": "TerminalAttemptAuthorityV1",
    "K": "CompletedCurrentAuthorityV1",
}
SPAWNED_TERMINALS = {
    "PROVIDER_TERMINAL",
    "PROCESS_EXIT_NO_PROVIDER_FRAME",
    "TIMEOUT",
    "CANCELLED",
    "TRANSPORT_FAILURE",
    "EMPTY_PROVIDER_OUTPUT",
    "MALFORMED_PROVIDER_OUTPUT",
}
ALL_TERMINALS = SPAWNED_TERMINALS | {
    "SPAWN_FAILED",
    "AMBIGUITY_ABORTED_NOT_SPAWNED",
    "AMBIGUITY_UNRESOLVED_DEBT",
}
VALID_PREFIXES = {
    "C",
    "C,I",
    "C,I,S",
    "C,I,S,T",
    "C,I,S,T,K",
    "C,I,T",
    "C,I,T,K",
    "C,I,A",
    "C,I,A,Q",
    "C,I,A,Q,S",
    "C,I,A,Q,S,T",
    "C,I,A,Q,S,T,K",
    "C,I,A,Q,T",
    "C,I,A,Q,T,K",
}
P15_REGISTRY = {
    "P15-001": {
        "fixture_constructor_id": (
            "post-mint secret presence policy mutation"
        ),
        "target_callable": (
            "validate_plamen_model_routing_r2_5_2."
            "authenticate_spawn_from_capability_v252"
        ),
        "expected_error": "VALIDATED_CLOSURE_POLICY_MISMATCH",
    },
    "P15-002": {
        "fixture_constructor_id": (
            "post-mint non-secret source class mutation"
        ),
        "target_callable": (
            "validate_plamen_model_routing_r2_5_2."
            "authenticate_spawn_from_capability_v252"
        ),
        "expected_error": "VALIDATED_CLOSURE_POLICY_MISMATCH",
    },
    "P15-003": {
        "fixture_constructor_id": (
            "post-mint consumed spawn-state mutation"
        ),
        "target_callable": (
            "validate_plamen_model_routing_r2_5_2."
            "authenticate_spawn_from_capability_v252"
        ),
        "expected_error": "VALIDATED_CLOSURE_CONSUME_MISMATCH",
    },
    "P15-004": {
        "fixture_constructor_id": "post-mint consumed CAS mutation",
        "target_callable": (
            "validate_plamen_model_routing_r2_5_2."
            "authenticate_spawn_from_capability_v252"
        ),
        "expected_error": "VALIDATED_CLOSURE_CONSUME_MISMATCH",
    },
    "P15-005": {
        "fixture_constructor_id": "resume raw current records forbidden",
        "target_callable": (
            "validate_plamen_model_routing_r2_5_2.validate_resume_v252"
        ),
        "expected_error": "RESUME_VALIDATED_CLOSURE_REQUIRED",
    },
    "P15-006": {
        "fixture_constructor_id": "resume cross-run prior authority",
        "target_callable": (
            "validate_plamen_model_routing_r2_5_2.validate_resume_v252"
        ),
        "expected_error": "RESUME_RUN_SCOPE_MISMATCH",
    },
    "P15-007": {
        "fixture_constructor_id": (
            "full closure fabricated legacy observation"
        ),
        "target_callable": (
            "validate_plamen_model_routing_r2_5_2."
            "validate_and_mint_closure_v252"
        ),
        "expected_error": "MANDATORY_NEUTRAL_OBSERVATION_MISMATCH",
    },
    "P15-008": {
        "fixture_constructor_id": (
            "full closure caller-authored legacy proof rule"
        ),
        "target_callable": (
            "validate_plamen_model_routing_r2_5_2."
            "validate_and_mint_closure_v252"
        ),
        "expected_error": "MANDATORY_NEUTRAL_OBSERVATION_MISMATCH",
    },
    "P15-009": {
        "fixture_constructor_id": "neutral unknown thinking state",
        "target_callable": (
            "validate_plamen_model_routing_r2_5_2."
            "validate_and_mint_closure_v252"
        ),
        "expected_error": "NEUTRAL_STATE_GRAMMAR_MISMATCH",
    },
    "P15-010": {
        "fixture_constructor_id": "neutral unknown fallback state",
        "target_callable": (
            "validate_plamen_model_routing_r2_5_2."
            "validate_and_mint_closure_v252"
        ),
        "expected_error": "NEUTRAL_STATE_GRAMMAR_MISMATCH",
    },
    "P15-011": {
        "fixture_constructor_id": "neutral unknown terminal category",
        "target_callable": (
            "validate_plamen_model_routing_r2_5_2."
            "validate_and_mint_closure_v252"
        ),
        "expected_error": "NEUTRAL_STATE_GRAMMAR_MISMATCH",
    },
    "P15-012": {
        "fixture_constructor_id": "neutral malformed usage object",
        "target_callable": (
            "validate_plamen_model_routing_r2_5_2."
            "validate_and_mint_closure_v252"
        ),
        "expected_error": "PROVIDER_USAGE_SCHEMA_MISMATCH",
    },
    "P15-013": {
        "fixture_constructor_id": (
            "transaction parent-set internal key mismatch"
        ),
        "target_callable": (
            "validate_plamen_model_routing_r2_5_2.validate_store_scope"
        ),
        "expected_error": "AUTHORITY_STORE_KEY_MISMATCH",
    },
    "P15-014": {
        "fixture_constructor_id": "cross-run transaction parent set",
        "target_callable": (
            "validate_plamen_model_routing_r2_5_2.validate_store_scope"
        ),
        "expected_error": "AUTHORITY_STORE_RUN_MISMATCH",
    },
    "P15-015": {
        "fixture_constructor_id": "extra raw-secret store record",
        "target_callable": (
            "validate_plamen_model_routing_r2_5_2.validate_store_scope"
        ),
        "expected_error": "AUTHORITY_STORE_NAMESPACE_MISMATCH",
    },
}


class ConformanceError(Exception):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


def read_ascii_lf(path: Path) -> bytes:
    raw = path.read_bytes()
    if not raw or not raw.endswith(b"\n"):
        raise ConformanceError(f"FINAL_LF_REQUIRED:{path.name}")
    if b"\r" in raw:
        raise ConformanceError(f"CR_BYTE_FORBIDDEN:{path.name}")
    if not raw.isascii():
        raise ConformanceError(f"NON_ASCII_PACKAGE:{path.name}")
    return raw


def parse_json_strict(raw: bytes) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise ConformanceError(f"DUPLICATE_JSON_KEY:{key}")
            result[key] = value
        return result

    def constant(value: str) -> Any:
        raise ConformanceError(f"NONFINITE_JSON_NUMBER:{value}")

    try:
        return json.loads(
            raw.decode("ascii"),
            object_pairs_hook=pairs,
            parse_constant=constant,
        )
    except ConformanceError:
        raise
    except Exception as exc:
        raise ConformanceError("STRICT_JSON_INVALID") from exc


def import_exact(path: Path, expected: str, name: str) -> Any:
    if sha256_bytes(path.read_bytes()) != expected:
        raise ConformanceError(f"{name.upper()}_HASH_MISMATCH")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ConformanceError(f"{name.upper()}_IMPORT_FAILED")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_hash(path: Path, expected: str, name: str) -> bytes:
    raw = read_ascii_lf(path)
    if sha256_bytes(raw) != expected:
        raise ConformanceError(f"{name}_HASH_MISMATCH")
    return raw


def seal(record: dict[str, Any], field: str) -> None:
    preimage = copy.deepcopy(record)
    preimage.pop(field, None)
    record[field] = digest(preimage)


def get_path(record: dict[str, Any], path: str) -> Any:
    value: Any = record
    for part in path.split("."):
        value = value[part]
    return value


def set_path(record: dict[str, Any], path: str, value: Any) -> None:
    target: Any = record
    parts = path.split(".")
    for part in parts[:-1]:
        target = target[part]
    target[parts[-1]] = value


def delete_path(record: dict[str, Any], path: str) -> None:
    target: Any = record
    parts = path.split(".")
    for part in parts[:-1]:
        target = target[part]
    del target[parts[-1]]


def operation(
    operation_id: str,
    family: str,
    fixture: str,
    consumer: str,
    mutation: str,
    target: str,
    result: str,
    error: str,
) -> dict[str, str]:
    return {
        "operation_id": operation_id,
        "family": family,
        "fixture_constructor_id": fixture,
        "target_consumer": consumer,
        "mutation_operator": mutation,
        "mutation_target": target,
        "expected_result": result,
        "expected_error": error,
    }


def validate_operation(item: dict[str, Any]) -> None:
    if set(item) != {
        "operation_id",
        "family",
        "fixture_constructor_id",
        "target_consumer",
        "mutation_operator",
        "mutation_target",
        "expected_result",
        "expected_error",
    }:
        raise ConformanceError("OPERATION_FIELD_SET_MISMATCH")
    if item["expected_result"] not in {"PASS", "REJECT"}:
        raise ConformanceError("OPERATION_RESULT_INVALID")
    if (item["expected_result"] == "PASS") != (
        item["expected_error"] == "NONE"
    ):
        raise ConformanceError("OPERATION_RESULT_ERROR_MISMATCH")


def validate_review_binding() -> None:
    raw = read_ascii_lf(REVIEW_PATH)
    if sha256_bytes(raw) != REVIEW_WHOLE_SHA256:
        raise ConformanceError("R2_5_4_REVIEW_WHOLE_HASH_MISMATCH")
    marker = b"\n## Artifact integrity\n"
    position = raw.rfind(marker)
    if position < 0:
        raise ConformanceError("R2_5_4_REVIEW_BODY_BOUNDARY_MISSING")
    body = raw[:position]
    if sha256_bytes(body) != REVIEW_BODY_SHA256:
        raise ConformanceError("R2_5_4_REVIEW_BODY_HASH_MISMATCH")
    required = (
        b"Verdict: **BLOCK**",
        b"R1 offline source-owned replay contract: ACCEPTED",
        b"R2 lifecycle closed-payload contract: FAIL",
        b"R3 P15 evidence-bound execution: FAIL",
        b"R3 total semantic consumer graph: FAIL",
    )
    if any(fragment not in body for fragment in required):
        raise ConformanceError("R2_5_4_REVIEW_EVIDENCE_MISMATCH")


def verify_frozen_r254() -> Any:
    module = import_exact(R254_PATH, R254_SHA256, "r254_frozen")
    completed = subprocess.run(
        [sys.executable, "-I", str(R254_PATH)],
        check=False,
        capture_output=True,
        text=True,
        encoding="ascii",
        timeout=240,
    )
    if completed.returncode != 0:
        raise ConformanceError("FROZEN_R2_5_4_EXECUTION_FAILED")
    if completed.stderr:
        raise ConformanceError("FROZEN_R2_5_4_STDERR_NONEMPTY")
    if completed.stdout.splitlines() != R254_EXPECTED:
        raise ConformanceError("FROZEN_R2_5_4_OUTPUT_MISMATCH")
    return module


def build_schema_validators(
    schema: dict[str, Any],
) -> dict[str, Any]:
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise ConformanceError("R2_5_5_META_SCHEMA_INVALID") from exc
    validators: dict[str, Draft202012Validator] = {}
    for name in schema["$defs"]:
        wrapper = {
            "$schema": schema["$schema"],
            "$defs": schema["$defs"],
            "$ref": f"#/$defs/{name}",
        }
        validators[name] = Draft202012Validator(wrapper)
    contract = schema.get("x-plamen-contract")
    if not isinstance(contract, dict):
        raise ConformanceError("R2_5_5_CONTRACT_MISSING")
    validators["__contract__"] = contract
    return validators


def validate_vectors_header(vectors: dict[str, Any]) -> None:
    if (
        vectors.get("schema")
        != "plamen.model-routing-r2.5.5-red-operation-vectors.v1"
        or vectors.get("version") != 1
        or vectors.get("disposition")
        != "DESIGN_RED_ONLY_INDEPENDENT_ACCEPTANCE_REQUIRED"
    ):
        raise ConformanceError("VECTOR_HEADER_MISMATCH")
    if vectors.get("sealed_r2_5_4_review") != {
        "body_sha256": REVIEW_BODY_SHA256,
        "whole_sha256": REVIEW_WHOLE_SHA256,
        "verdict": "BLOCK",
    }:
        raise ConformanceError("VECTOR_REVIEW_BINDING_MISMATCH")
    p15_specs = vectors.get("p15_evidence_operations", [])
    if len(p15_specs) != 15:
        raise ConformanceError("P15_EVIDENCE_COUNT_MISMATCH")
    seen: set[str] = set()
    for spec in p15_specs:
        if set(spec) != {
            "operation_id",
            "fixture_constructor_id",
            "target_callable",
            "canonical_input_sha256",
            "expected_result",
            "expected_error",
            "invocation_sha256",
        }:
            raise ConformanceError("P15_SPEC_FIELD_SET_MISMATCH")
        operation_id = spec["operation_id"]
        if operation_id in seen or operation_id not in P15_REGISTRY:
            raise ConformanceError("P15_SPEC_REGISTRY_MISMATCH")
        seen.add(operation_id)
        expected = P15_REGISTRY[operation_id]
        if any(spec[field] != expected[field] for field in expected):
            raise ConformanceError("P15_SPEC_REGISTRY_MISMATCH")
        if spec["expected_result"] != "REJECT":
            raise ConformanceError("P15_SPEC_REGISTRY_MISMATCH")
        for field in (
            "canonical_input_sha256",
            "invocation_sha256",
        ):
            value = spec[field]
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(ch not in "0123456789abcdef" for ch in value)
            ):
                raise ConformanceError(f"P15_{field.upper()}_INVALID")
    if seen != set(P15_REGISTRY):
        raise ConformanceError("P15_SPEC_REGISTRY_MISMATCH")
    if vectors.get("authorization") != {
        "green_implementation": False,
        "production_integration": False,
        "provider_calls": False,
        "audit_execution": False,
        "defaults_or_config_changes": False,
        "commit_or_push": False,
    }:
        raise ConformanceError("VECTOR_AUTHORIZATION_MISMATCH")


def schema_name_for_node(
    node_name: str, record: dict[str, Any]
) -> str:
    name = record.get("schema")
    if not isinstance(name, str):
        raise ConformanceError("RECORD_SCHEMA_MISSING")
    return name


def validate_record_schema(
    record: dict[str, Any],
    validators: dict[str, Any],
) -> None:
    name = schema_name_for_node("", record)
    if name not in validators:
        raise ConformanceError("RECORD_SCHEMA_UNKNOWN")
    errors = list(validators[name].iter_errors(record))
    if errors:
        raise ConformanceError("RECORD_SCHEMA_REJECT")


def digest_field(record: dict[str, Any]) -> str:
    return "event_digest" if "event_digest" in record else "record_digest"


def verify_record_digest(record: dict[str, Any]) -> None:
    field = digest_field(record)
    preimage = copy.deepcopy(record)
    claimed = preimage.pop(field, None)
    if not isinstance(claimed, str) or digest(preimage) != claimed:
        raise ConformanceError("RECORD_SELF_DIGEST_MISMATCH")


def make_scoped(schema: str, fields: dict[str, Any]) -> dict[str, Any]:
    record = {
        "schema": schema,
        "version": 1,
        "run_id": RUN_ID,
        "generation": GENERATION,
        "attempt_ordinal": ATTEMPT,
        **fields,
    }
    seal(record, "record_digest")
    return record


def make_event(
    token: str,
    events: list[dict[str, Any]],
    payload: dict[str, Any],
) -> dict[str, Any]:
    event = {
        "schema": EVENT_SCHEMA_BY_TOKEN[token],
        "version": 1,
        "event_kind": token,
        "event_revision": 10 + len(events),
        "cas_revision": 10 + len(events),
        "run_id": RUN_ID,
        "generation": GENERATION,
        "attempt_ordinal": ATTEMPT,
        "launch_replay_digest": LAUNCH_REPLAY,
        "parent_event_digest": (
            events[-1]["event_digest"] if events else ZERO
        ),
        "payload": payload,
    }
    seal(event, "event_digest")
    return event


def terminal_payload(outcome: str, parent: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "terminal_parent_digest": parent["event_digest"],
        "terminal_outcome": outcome,
        "process_identity_digest": (
            PROCESS if parent["event_kind"] == "S" else ZERO
        ),
        "transport_identity_digest": TRANSPORT,
    }
    if outcome == "PROVIDER_TERMINAL":
        payload["provider_terminal_digest"] = PROVIDER_TERMINAL
    return payload


def branch_ids(vectors: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for family, spec in vectors["branch_families"].items():
        for terminal in spec["terminal_outcomes"]:
            result.append(f"{family}::{terminal}")
    return result


def add_edge(
    edges: list[dict[str, str]],
    child: str,
    path: str,
    parent: str,
) -> None:
    edges.append(
        {
            "edge_id": f"{parent}->{child}:{path}",
            "child": child,
            "path": path,
            "parent": parent,
        }
    )


def build_full_graph(branch_id: str) -> dict[str, Any]:
    family, outcome = branch_id.split("::", 1)
    nodes: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    edges: list[dict[str, str]] = []
    event_names: list[str] = []

    def add(name: str, record: dict[str, Any]) -> None:
        nodes[name] = record
        order.append(name)

    root = make_scoped(
        "RoutingRootAuthorityV1",
        {"routing_policy_digest": digest("routing-policy-r255")},
    )
    add("root", root)
    attempt = make_scoped(
        "ExecutionAttemptAuthorityV1",
        {
            "routing_root_digest": root["record_digest"],
            "work_plan_digest": digest("work-plan-r255"),
        },
    )
    add("attempt", attempt)
    add_edge(edges, "attempt", "routing_root_digest", "root")
    route = make_scoped(
        "SelectedRouteAuthorityV1",
        {
            "execution_attempt_digest": attempt["record_digest"],
            "provider_id": "claude",
            "exact_model_id": "claude-opus-r255",
        },
    )
    add("route", route)
    add_edge(edges, "route", "execution_attempt_digest", "attempt")
    v4 = make_scoped(
        "LaunchEnvelopeV4",
        {
            "selected_route_digest": route["record_digest"],
            "request_digest": digest("request-r255"),
        },
    )
    add("launch_envelope_v4", v4)
    add_edge(
        edges,
        "launch_envelope_v4",
        "selected_route_digest",
        "route",
    )
    v3 = make_scoped(
        "PredecessorEnvelopeV3",
        {
            "launch_envelope_v4_digest": v4["record_digest"],
            "projection_digest": digest("projection-r255"),
        },
    )
    add("predecessor_envelope_v3", v3)
    add_edge(
        edges,
        "predecessor_envelope_v3",
        "launch_envelope_v4_digest",
        "launch_envelope_v4",
    )
    env_policy = make_scoped(
        "EnvironmentPolicyAuthorityV1",
        {
            "selected_route_digest": route["record_digest"],
            "public_env_digest": digest("public-env-preimage-r255"),
        },
    )
    add("env_policy", env_policy)
    add_edge(edges, "env_policy", "selected_route_digest", "route")
    public_env = make_scoped(
        "PublicEnvironmentAuthorityV1",
        {
            "env_policy_digest": env_policy["record_digest"],
            "materialized_digest": digest("materialized-env-r255"),
        },
    )
    add("public_env", public_env)
    add_edge(edges, "public_env", "env_policy_digest", "env_policy")

    events: list[dict[str, Any]] = []
    consumed = make_event(
        "C",
        events,
        {
            "spawn_state": "CONSUMED_NOT_SPAWNED",
            "execution_attempt_digest": attempt["record_digest"],
            "consumed_cas_digest": CONSUMED_CAS,
        },
    )
    events.append(consumed)
    add("consumed", consumed)
    event_names.append("consumed")
    add_edge(
        edges,
        "consumed",
        "payload.execution_attempt_digest",
        "attempt",
    )
    intent = make_event(
        "I",
        events,
        {
            "consumed_digest": consumed["event_digest"],
            "launch_replay_digest": LAUNCH_REPLAY,
            "planned_transport_digest": TRANSPORT,
            "intent_nonce_digest": INTENT_NONCE,
        },
    )
    events.append(intent)
    add("intent", intent)
    event_names.append("intent")
    add_edge(edges, "intent", "parent_event_digest", "consumed")
    add_edge(edges, "intent", "payload.consumed_digest", "consumed")

    resolution: dict[str, Any] | None = None
    if family in {
        "OBSERVED_SPAWN",
        "AMBIGUITY_ABORT",
        "AMBIGUITY_DEBT",
    }:
        ambiguity = make_event(
            "A",
            events,
            {
                "intent_digest": intent["event_digest"],
                "recovery_reason": "RESTART_WITHOUT_AUTHENTICATED_OUTCOME",
            },
        )
        events.append(ambiguity)
        add("ambiguity", ambiguity)
        event_names.append("ambiguity")
        add_edge(edges, "ambiguity", "parent_event_digest", "intent")
        add_edge(edges, "ambiguity", "payload.intent_digest", "intent")
        resolution_outcome = {
            "OBSERVED_SPAWN": "OBSERVED_SPAWNED",
            "AMBIGUITY_ABORT": "CONFIRMED_NOT_SPAWNED_ABORT",
            "AMBIGUITY_DEBT": "UNRESOLVED_DEBT",
        }[family]
        resolution_payload = {
            "ambiguity_digest": ambiguity["event_digest"],
            "resolution_outcome": resolution_outcome,
            "governed_evidence_digest": EVIDENCE,
        }
        if family == "OBSERVED_SPAWN":
            resolution_payload.update(
                {
                    "process_identity_digest": PROCESS,
                    "transport_identity_digest": TRANSPORT,
                }
            )
        resolution = make_event("Q", events, resolution_payload)
        events.append(resolution)
        add("resolution", resolution)
        event_names.append("resolution")
        add_edge(edges, "resolution", "parent_event_digest", "ambiguity")
        add_edge(
            edges,
            "resolution",
            "payload.ambiguity_digest",
            "ambiguity",
        )

    spawned: dict[str, Any] | None = None
    if family in {"DIRECT_SPAWN", "OBSERVED_SPAWN"}:
        spawned_payload = {
            "intent_digest": intent["event_digest"],
            "launch_replay_digest": LAUNCH_REPLAY,
            "process_identity_digest": PROCESS,
            "transport_identity_digest": TRANSPORT,
            "resolution_digest": (
                resolution["event_digest"] if resolution else ZERO
            ),
        }
        spawned = make_event("S", events, spawned_payload)
        events.append(spawned)
        add("spawned", spawned)
        event_names.append("spawned")
        add_edge(
            edges,
            "spawned",
            "parent_event_digest",
            "resolution" if resolution else "intent",
        )
        add_edge(edges, "spawned", "payload.intent_digest", "intent")
        if resolution:
            add_edge(
                edges,
                "spawned",
                "payload.resolution_digest",
                "resolution",
            )

    parent_name = (
        "spawned"
        if spawned
        else "resolution"
        if resolution
        else "intent"
    )
    parent = nodes[parent_name]
    terminal = make_event("T", events, terminal_payload(outcome, parent))
    events.append(terminal)
    add("terminal", terminal)
    event_names.append("terminal")
    add_edge(edges, "terminal", "parent_event_digest", parent_name)
    add_edge(
        edges,
        "terminal",
        "payload.terminal_parent_digest",
        parent_name,
    )

    provider_artifact: dict[str, Any] | None = None
    if outcome == "PROVIDER_TERMINAL":
        provider_artifact = make_scoped(
            "ProviderArtifactAuthorityV1",
            {
                "terminal_digest": terminal["event_digest"],
                "provider_frame_digest": PROVIDER_FRAME,
            },
        )
        add("provider_artifact", provider_artifact)
        add_edge(
            edges,
            "provider_artifact",
            "terminal_digest",
            "terminal",
        )
        neutral = make_scoped(
            "NeutralProviderClaimAuthorityV1",
            {
                "terminal_digest": terminal["event_digest"],
                "provider_artifact_digest": provider_artifact[
                    "record_digest"
                ],
                "neutral_state": "PROVIDER_TERMINAL_VALID",
            },
        )
        add("neutral_provider", neutral)
        neutral_name = "neutral_provider"
        add_edge(
            edges,
            neutral_name,
            "terminal_digest",
            "terminal",
        )
        add_edge(
            edges,
            neutral_name,
            "provider_artifact_digest",
            "provider_artifact",
        )
        reconciliation_state = "RECONCILED_PROVIDER"
    else:
        neutral_state = (
            "UNKNOWN_ADVERSE"
            if outcome == "AMBIGUITY_UNRESOLVED_DEBT"
            else "LAUNCHER_FAILURE"
        )
        neutral = make_scoped(
            "NeutralLauncherClaimAuthorityV1",
            {
                "terminal_digest": terminal["event_digest"],
                "neutral_state": neutral_state,
            },
        )
        add("neutral_launcher", neutral)
        neutral_name = "neutral_launcher"
        add_edge(
            edges,
            neutral_name,
            "terminal_digest",
            "terminal",
        )
        reconciliation_state = (
            "RECONCILED_UNKNOWN_ADVERSE"
            if neutral_state == "UNKNOWN_ADVERSE"
            else "RECONCILED_FAILURE"
        )
    reconciliation = make_scoped(
        "NeutralReconciliationAuthorityV1",
        {
            "neutral_claim_digest": neutral["record_digest"],
            "reconciliation_state": reconciliation_state,
        },
    )
    add("reconciliation", reconciliation)
    add_edge(
        edges,
        "reconciliation",
        "neutral_claim_digest",
        neutral_name,
    )
    completed = make_event(
        "K",
        events,
        {
            "terminal_digest": terminal["event_digest"],
            "prefix_digest": digest(
                [event["event_digest"] for event in events]
            ),
            "neutral_reconciliation_digest": reconciliation[
                "record_digest"
            ],
        },
    )
    events.append(completed)
    add("completed_current", completed)
    event_names.append("completed_current")
    add_edge(
        edges,
        "completed_current",
        "parent_event_digest",
        "terminal",
    )
    add_edge(
        edges,
        "completed_current",
        "payload.terminal_digest",
        "terminal",
    )
    add_edge(
        edges,
        "completed_current",
        "payload.neutral_reconciliation_digest",
        "reconciliation",
    )
    prior = make_scoped(
        "PriorResumeIdentityAuthorityV1",
        {
            "prior_identity_digest": digest("prior-identity-r255"),
            "current_digest": completed["event_digest"],
        },
    )
    add("prior_identity", prior)
    add_edge(
        edges,
        "prior_identity",
        "current_digest",
        "completed_current",
    )
    anchors = {
        name: copy.deepcopy(get_path(record, semantic_path(name, record)))
        for name, record in nodes.items()
    }
    return {
        "branch_id": branch_id,
        "nodes": nodes,
        "order": order,
        "edges": edges,
        "event_names": event_names,
        "anchors": anchors,
    }


def semantic_path(name: str, record: dict[str, Any]) -> str:
    mapping = {
        "root": "routing_policy_digest",
        "attempt": "work_plan_digest",
        "route": "exact_model_id",
        "launch_envelope_v4": "request_digest",
        "predecessor_envelope_v3": "projection_digest",
        "env_policy": "public_env_digest",
        "public_env": "materialized_digest",
        "consumed": "payload.spawn_state",
        "intent": "payload.intent_nonce_digest",
        "ambiguity": "payload.recovery_reason",
        "resolution": "payload.resolution_outcome",
        "spawned": "payload.process_identity_digest",
        "terminal": "payload.terminal_outcome",
        "provider_artifact": "provider_frame_digest",
        "neutral_provider": "neutral_state",
        "neutral_launcher": "neutral_state",
        "reconciliation": "reconciliation_state",
        "completed_current": "payload.prefix_digest",
        "prior_identity": "prior_identity_digest",
    }
    if name not in mapping:
        raise ConformanceError(f"SEMANTIC_PATH_UNKNOWN:{name}")
    return mapping[name]


def graph_view(
    branch_id: str, consumer: str
) -> dict[str, Any]:
    full = build_full_graph(branch_id)
    if consumer in {"launch_replay_validator", "proof_mint"}:
        last = "consumed"
    elif consumer == "spawn_authentication":
        last = "intent"
    elif consumer == "provider_spool_acceptance":
        last = "spawned"
    elif consumer in {
        "completed_current_construction",
        "current_replay_validator",
    }:
        last = "completed_current"
    elif consumer == "resume_authorization":
        last = "prior_identity"
    else:
        raise ConformanceError(f"CONSUMER_UNKNOWN:{consumer}")
    if last not in full["order"]:
        raise ConformanceError("BRANCH_CONSUMER_INAPPLICABLE")
    end = full["order"].index(last) + 1
    names = full["order"][:end]
    name_set = set(names)
    full["order"] = names
    full["nodes"] = {
        name: full["nodes"][name] for name in names
    }
    full["edges"] = [
        edge
        for edge in full["edges"]
        if edge["child"] in name_set and edge["parent"] in name_set
    ]
    full["event_names"] = [
        name for name in full["event_names"] if name in name_set
    ]
    full["anchors"] = {
        name: full["anchors"][name] for name in names
    }
    full["consumer"] = consumer
    return full


def validate_lifecycle_events(
    events: list[dict[str, Any]],
    validators: dict[str, Any],
) -> None:
    tokens = ",".join(event.get("event_kind", "") for event in events)
    if tokens not in VALID_PREFIXES:
        raise ConformanceError("LIFECYCLE_PREFIX_INVALID")
    by_kind = {event["event_kind"]: event for event in events}
    previous: dict[str, Any] | None = None
    for index, event in enumerate(events):
        validate_record_schema(event, validators)
        verify_record_digest(event)
        if (
            event["run_id"] != RUN_ID
            or event["generation"] != GENERATION
            or event["attempt_ordinal"] != ATTEMPT
            or event["launch_replay_digest"] != LAUNCH_REPLAY
        ):
            raise ConformanceError("LIFECYCLE_SCOPE_MISMATCH")
        if (
            event["event_revision"] != 10 + index
            or event["cas_revision"] != 10 + index
        ):
            raise ConformanceError("LIFECYCLE_REVISION_MISMATCH")
        expected_parent = previous["event_digest"] if previous else ZERO
        if event["parent_event_digest"] != expected_parent:
            raise ConformanceError("LIFECYCLE_PARENT_MISMATCH")
        previous = event
    consumed = by_kind["C"]
    if (
        consumed["payload"]["spawn_state"] != "CONSUMED_NOT_SPAWNED"
        or consumed["payload"]["consumed_cas_digest"] != CONSUMED_CAS
    ):
        raise ConformanceError("LIFECYCLE_SEMANTIC_MISMATCH")
    if "I" in by_kind:
        intent = by_kind["I"]["payload"]
        if (
            intent["consumed_digest"] != consumed["event_digest"]
            or intent["launch_replay_digest"] != LAUNCH_REPLAY
            or intent["planned_transport_digest"] != TRANSPORT
            or intent["intent_nonce_digest"] != INTENT_NONCE
        ):
            raise ConformanceError("LIFECYCLE_SEMANTIC_MISMATCH")
    if "A" in by_kind:
        if (
            by_kind["A"]["payload"]["intent_digest"]
            != by_kind["I"]["event_digest"]
        ):
            raise ConformanceError("LIFECYCLE_SEMANTIC_MISMATCH")
    resolution_outcome = "NONE"
    if "Q" in by_kind:
        resolution = by_kind["Q"]["payload"]
        resolution_outcome = resolution["resolution_outcome"]
        if (
            resolution["ambiguity_digest"]
            != by_kind["A"]["event_digest"]
            or resolution["governed_evidence_digest"] != EVIDENCE
        ):
            raise ConformanceError("LIFECYCLE_SEMANTIC_MISMATCH")
        if resolution_outcome == "OBSERVED_SPAWNED":
            if (
                resolution["process_identity_digest"] != PROCESS
                or resolution["transport_identity_digest"] != TRANSPORT
            ):
                raise ConformanceError("LIFECYCLE_SEMANTIC_MISMATCH")
    if "S" in by_kind:
        spawned = by_kind["S"]["payload"]
        expected_resolution = by_kind.get("Q", {}).get(
            "event_digest", ZERO
        )
        if (
            spawned["intent_digest"] != by_kind["I"]["event_digest"]
            or spawned["launch_replay_digest"] != LAUNCH_REPLAY
            or spawned["process_identity_digest"] != PROCESS
            or spawned["transport_identity_digest"] != TRANSPORT
            or spawned["resolution_digest"] != expected_resolution
        ):
            raise ConformanceError("LIFECYCLE_SEMANTIC_MISMATCH")
        if "Q" in by_kind and resolution_outcome != "OBSERVED_SPAWNED":
            raise ConformanceError("LIFECYCLE_BRANCH_MISMATCH")
    elif "Q" in by_kind and resolution_outcome == "OBSERVED_SPAWNED":
        if tokens not in {"C,I,A,Q"}:
            raise ConformanceError("LIFECYCLE_BRANCH_MISMATCH")
    if "T" in by_kind:
        terminal = by_kind["T"]
        terminal_index = events.index(terminal)
        parent = events[terminal_index - 1]
        payload = terminal["payload"]
        if payload["terminal_parent_digest"] != parent["event_digest"]:
            raise ConformanceError("LIFECYCLE_SEMANTIC_MISMATCH")
        outcome = payload["terminal_outcome"]
        if parent["event_kind"] == "I":
            allowed = {"SPAWN_FAILED"}
        elif parent["event_kind"] == "S":
            allowed = SPAWNED_TERMINALS
        elif parent["event_kind"] == "Q":
            allowed = {
                "CONFIRMED_NOT_SPAWNED_ABORT": {
                    "AMBIGUITY_ABORTED_NOT_SPAWNED"
                },
                "UNRESOLVED_DEBT": {"AMBIGUITY_UNRESOLVED_DEBT"},
            }.get(resolution_outcome, set())
        else:
            allowed = set()
        if outcome not in allowed:
            raise ConformanceError("LIFECYCLE_BRANCH_MISMATCH")
        expected_process = PROCESS if parent["event_kind"] == "S" else ZERO
        if (
            payload["process_identity_digest"] != expected_process
            or payload["transport_identity_digest"] != TRANSPORT
        ):
            raise ConformanceError("LIFECYCLE_SEMANTIC_MISMATCH")
        if outcome == "PROVIDER_TERMINAL":
            if payload.get("provider_terminal_digest") != PROVIDER_TERMINAL:
                raise ConformanceError("LIFECYCLE_SEMANTIC_MISMATCH")
        elif "provider_terminal_digest" in payload:
            raise ConformanceError("LIFECYCLE_SEMANTIC_MISMATCH")
    if "K" in by_kind:
        current = by_kind["K"]
        index = events.index(current)
        if (
            current["payload"]["terminal_digest"]
            != by_kind["T"]["event_digest"]
            or current["payload"]["prefix_digest"]
            != digest([event["event_digest"] for event in events[:index]])
        ):
            raise ConformanceError("LIFECYCLE_SEMANTIC_MISMATCH")


def expected_graph_layout(branch_id: str, consumer: str) -> tuple[
    list[str], list[tuple[str, str, str]]
]:
    canonical = graph_view(branch_id, consumer)
    return canonical["order"], [
        (edge["child"], edge["path"], edge["parent"])
        for edge in canonical["edges"]
    ]


def validate_semantic_graph(
    graph: dict[str, Any],
    validators: dict[str, Any],
) -> None:
    expected_order, expected_edges = expected_graph_layout(
        graph["branch_id"], graph["consumer"]
    )
    if graph["order"] != expected_order or set(graph["nodes"]) != set(
        expected_order
    ):
        raise ConformanceError("GRAPH_RECORD_SET_MISMATCH")
    for name in graph["order"]:
        record = graph["nodes"][name]
        validate_record_schema(record, validators)
        verify_record_digest(record)
    actual_edges = {
        (edge["child"], edge["path"], edge["parent"])
        for edge in graph["edges"]
    }
    contract = validators["__contract__"]
    catalog = contract["record_catalog"]
    expected_catalog_edges: set[tuple[str, str, str]] = set()
    for child in graph["order"]:
        record = graph["nodes"][child]
        if child not in catalog:
            raise ConformanceError("GRAPH_RECORD_CATALOG_MISMATCH")
        entry = catalog[child]
        if (
            record["schema"] != entry["schema"]
            or digest_field(record) != entry["digest_field"]
            or semantic_path(child, record) != entry["semantic_field"]
        ):
            raise ConformanceError("GRAPH_RECORD_CATALOG_MISMATCH")
        for parent_role, path in entry["parents"].items():
            if parent_role == "resolution_optional":
                if (
                    "resolution" not in graph["nodes"]
                    or get_path(record, path) == ZERO
                ):
                    continue
                parent = "resolution"
            elif parent_role == "terminal_parent":
                terminal_index = graph["event_names"].index("terminal")
                parent = graph["event_names"][terminal_index - 1]
            elif parent_role == "neutral":
                parent = (
                    "neutral_provider"
                    if "neutral_provider" in graph["nodes"]
                    else "neutral_launcher"
                )
            else:
                parent = parent_role
            if parent in graph["nodes"]:
                expected_catalog_edges.add((child, path, parent))
    for index, child in enumerate(graph["event_names"]):
        if index:
            expected_catalog_edges.add(
                (
                    child,
                    "parent_event_digest",
                    graph["event_names"][index - 1],
                )
            )
    if (
        set(expected_edges) != expected_catalog_edges
        or actual_edges != expected_catalog_edges
    ):
        raise ConformanceError("GRAPH_PARENT_SET_MISMATCH")
    for edge in graph["edges"]:
        child = graph["nodes"][edge["child"]]
        parent = graph["nodes"][edge["parent"]]
        if get_path(child, edge["path"]) != parent[digest_field(parent)]:
            raise ConformanceError("GRAPH_PARENT_DIGEST_MISMATCH")
        if (
            child["run_id"] != parent["run_id"]
            or child["generation"] != parent["generation"]
            or child["attempt_ordinal"] != parent["attempt_ordinal"]
        ):
            raise ConformanceError("GRAPH_PARENT_SCOPE_MISMATCH")
    for name in graph["order"]:
        record = graph["nodes"][name]
        if (
            record["run_id"] != RUN_ID
            or record["generation"] != GENERATION
            or record["attempt_ordinal"] != ATTEMPT
        ):
            raise ConformanceError("RECORD_SCOPE_MISMATCH")
        if get_path(record, semantic_path(name, record)) != graph[
            "anchors"
        ][name]:
            raise ConformanceError("RECORD_SEMANTIC_MISMATCH")
    events = [graph["nodes"][name] for name in graph["event_names"]]
    validate_lifecycle_events(events, validators)
    if "completed_current" in graph["nodes"]:
        completed = graph["nodes"]["completed_current"]
        reconciliation = graph["nodes"]["reconciliation"]
        if (
            completed["payload"]["neutral_reconciliation_digest"]
            != reconciliation["record_digest"]
        ):
            raise ConformanceError("CURRENT_RECONCILIATION_MISMATCH")
    if "provider_artifact" in graph["nodes"]:
        if (
            graph["nodes"]["terminal"]["payload"]["terminal_outcome"]
            != "PROVIDER_TERMINAL"
        ):
            raise ConformanceError("PROVIDER_ARTIFACT_BRANCH_MISMATCH")
    elif "terminal" in graph["nodes"] and (
        graph["nodes"]["terminal"]["payload"]["terminal_outcome"]
        == "PROVIDER_TERMINAL"
    ):
        raise ConformanceError("PROVIDER_ARTIFACT_MISSING")


def reseal_graph_from(
    graph: dict[str, Any],
    start_name: str,
    protected: tuple[str, str, str] | None = None,
) -> None:
    start = graph["order"].index(start_name)
    for index in range(start, len(graph["order"])):
        name = graph["order"][index]
        record = graph["nodes"][name]
        for edge in graph["edges"]:
            triple = (edge["child"], edge["path"], edge["parent"])
            if edge["child"] == name and triple != protected:
                parent = graph["nodes"][edge["parent"]]
                set_path(
                    record,
                    edge["path"],
                    parent[digest_field(parent)],
                )
        if name == "completed_current" and (
            protected is None
            or protected[:2] != (
                "completed_current",
                "payload.prefix_digest",
            )
        ):
            event_names = [
                event_name
                for event_name in graph["event_names"]
                if graph["order"].index(event_name) < index
            ]
            record["payload"]["prefix_digest"] = digest(
                [
                    graph["nodes"][event_name]["event_digest"]
                    for event_name in event_names
                ]
            )
        seal(record, digest_field(record))


def mutation_value(value: Any) -> Any:
    if isinstance(value, str):
        return digest(f"mutated:{value}")
    if isinstance(value, int) and not isinstance(value, bool):
        return value + 100
    return "mutated-value"


def required_mutation_path(name: str, record: dict[str, Any]) -> str:
    return semantic_path(name, record)


def protected_graph_path(
    graph: dict[str, Any], name: str, path: str
) -> tuple[str, str, str]:
    return next(
        (
            (edge["child"], edge["path"], edge["parent"])
            for edge in graph["edges"]
            if edge["child"] == name and edge["path"] == path
        ),
        (name, path, ""),
    )


def graph_fixture_matrix(vectors: dict[str, Any]) -> list[tuple[str, str]]:
    branches = branch_ids(vectors)
    provider_branch = "DIRECT_SPAWN::PROVIDER_TERMINAL"
    observed_branch = "OBSERVED_SPAWN::PROVIDER_TERMINAL"
    result = [
        (provider_branch, "launch_replay_validator"),
        (provider_branch, "proof_mint"),
        (provider_branch, "spawn_authentication"),
        (provider_branch, "provider_spool_acceptance"),
        (observed_branch, "provider_spool_acceptance"),
    ]
    for branch in branches:
        result.extend(
            [
                (branch, "completed_current_construction"),
                (branch, "current_replay_validator"),
                (branch, "resume_authorization"),
            ]
        )
    return result


def materialize_graph_operations(
    vectors: dict[str, Any],
) -> list[dict[str, str]]:
    operations: list[dict[str, str]] = []
    for branch_id, consumer in graph_fixture_matrix(vectors):
        fixture = f"{branch_id}::{consumer}"
        graph = graph_view(branch_id, consumer)
        operations.append(
            operation(
                f"GRAPH::{fixture}::POSITIVE",
                "GRAPH_POSITIVE",
                fixture,
                consumer,
                "NONE",
                "complete_semantic_graph",
                "PASS",
                "NONE",
            )
        )
        for name in graph["order"]:
            for mutation in vectors["graph_record_mutations"]:
                operations.append(
                    operation(
                        f"GRAPH::{fixture}::RECORD::{name}::{mutation}",
                        "GRAPH_RECORD_MUTATION",
                        fixture,
                        consumer,
                        mutation,
                        name,
                        "REJECT",
                        "GRAPH_RECORD_MUTATION_REJECT",
                    )
                )
        for edge in graph["edges"]:
            for mutation in vectors["graph_parent_mutations"]:
                operations.append(
                    operation(
                        (
                            f"GRAPH::{fixture}::PARENT::{edge['edge_id']}"
                            f"::{mutation}"
                        ),
                        "GRAPH_PARENT_MUTATION",
                        fixture,
                        consumer,
                        mutation,
                        edge["edge_id"],
                        "REJECT",
                        "GRAPH_PARENT_MUTATION_REJECT",
                    )
                )
    return operations


def lifecycle_fixture_graph(fixture: str) -> tuple[dict[str, Any], str]:
    mapping = {
        "C": ("DIRECT_SPAWN::PROVIDER_TERMINAL", "consumed"),
        "I": ("DIRECT_SPAWN::PROVIDER_TERMINAL", "intent"),
        "A": ("AMBIGUITY_ABORT::AMBIGUITY_ABORTED_NOT_SPAWNED", "ambiguity"),
        "Q_OBSERVED": (
            "OBSERVED_SPAWN::PROVIDER_TERMINAL",
            "resolution",
        ),
        "Q_ABORT": (
            "AMBIGUITY_ABORT::AMBIGUITY_ABORTED_NOT_SPAWNED",
            "resolution",
        ),
        "Q_DEBT": (
            "AMBIGUITY_DEBT::AMBIGUITY_UNRESOLVED_DEBT",
            "resolution",
        ),
        "S_DIRECT": ("DIRECT_SPAWN::PROVIDER_TERMINAL", "spawned"),
        "S_OBSERVED": ("OBSERVED_SPAWN::PROVIDER_TERMINAL", "spawned"),
        "T_PROVIDER": ("DIRECT_SPAWN::PROVIDER_TERMINAL", "terminal"),
        "T_SPAWNED_NO_PROVIDER": ("DIRECT_SPAWN::TIMEOUT", "terminal"),
        "T_SPAWN_FAILED": ("SPAWN_FAILED::SPAWN_FAILED", "terminal"),
        "T_AMBIGUITY_ABORT": (
            "AMBIGUITY_ABORT::AMBIGUITY_ABORTED_NOT_SPAWNED",
            "terminal",
        ),
        "T_AMBIGUITY_DEBT": (
            "AMBIGUITY_DEBT::AMBIGUITY_UNRESOLVED_DEBT",
            "terminal",
        ),
        "K_PROVIDER": (
            "DIRECT_SPAWN::PROVIDER_TERMINAL",
            "completed_current",
        ),
        "K_LAUNCHER": ("DIRECT_SPAWN::TIMEOUT", "completed_current"),
    }
    branch_id, name = mapping[fixture]
    return graph_view(branch_id, "resume_authorization"), name


def materialize_lifecycle_schema_operations(
    vectors: dict[str, Any],
) -> list[dict[str, str]]:
    operations: list[dict[str, str]] = []
    for fixture in vectors["lifecycle_schema_fixtures"]:
        graph, name = lifecycle_fixture_graph(fixture)
        record = graph["nodes"][name]
        operations.append(
            operation(
                f"LCSCHEMA::{fixture}::POSITIVE",
                "LIFECYCLE_SCHEMA_POSITIVE",
                fixture,
                "typed_record_validator",
                "NONE",
                name,
                "PASS",
                "NONE",
            )
        )
        for mutation in vectors["outer_mutations"]:
            operations.append(
                operation(
                    f"LCSCHEMA::{fixture}::OUTER::{mutation}",
                    "LIFECYCLE_SCHEMA_MUTATION",
                    fixture,
                    "typed_record_validator",
                    mutation,
                    name,
                    "REJECT",
                    "LIFECYCLE_SCHEMA_MUTATION_REJECT",
                )
            )
        payload_fields = list(record["payload"])
        operations.append(
            operation(
                f"LCSCHEMA::{fixture}::PAYLOAD::EXTRA_FIELD_RESEALED",
                "LIFECYCLE_SCHEMA_MUTATION",
                fixture,
                "typed_record_validator",
                "EXTRA_FIELD_RESEALED",
                f"{name}:payload",
                "REJECT",
                "LIFECYCLE_SCHEMA_MUTATION_REJECT",
            )
        )
        for field in payload_fields:
            for mutation in (
                "DELETE_FIELD_RESEALED",
                "WRONG_TYPE_RESEALED",
                "REHASHED_VALUE",
            ):
                operations.append(
                    operation(
                        (
                            f"LCSCHEMA::{fixture}::PAYLOAD::{field}"
                            f"::{mutation}"
                        ),
                        "LIFECYCLE_SCHEMA_MUTATION",
                        fixture,
                        "typed_record_validator",
                        mutation,
                        f"{name}:payload.{field}",
                        "REJECT",
                        "LIFECYCLE_SCHEMA_MUTATION_REJECT",
                    )
                )
    return operations


def materialize_branch_operations(
    vectors: dict[str, Any],
) -> list[dict[str, str]]:
    operations: list[dict[str, str]] = []
    resolution_outcomes = [
        "OBSERVED_SPAWNED",
        "CONFIRMED_NOT_SPAWNED_ABORT",
        "UNRESOLVED_DEBT",
        "INVENTED_RESOLUTION",
    ]
    for resolution in resolution_outcomes:
        for next_event in vectors["resolution_next_events"]:
            valid = (
                resolution == "OBSERVED_SPAWNED" and next_event == "S"
            ) or (
                resolution
                in {
                    "CONFIRMED_NOT_SPAWNED_ABORT",
                    "UNRESOLVED_DEBT",
                }
                and next_event == "T"
            )
            operations.append(
                operation(
                    f"BRANCH::Q::{resolution}::NEXT::{next_event}",
                    "BRANCH_RESOLUTION_NEXT",
                    resolution,
                    "restart_state_derivation",
                    next_event,
                    "resolution_next_event",
                    "PASS" if valid else "REJECT",
                    "NONE" if valid else "BRANCH_MATRIX_REJECT",
                )
            )
    outcomes = list(vectors["terminal_outcomes"]) + [
        "INVENTED_TERMINAL"
    ]
    compatibility = {
        "I": {"SPAWN_FAILED"},
        "S": SPAWNED_TERMINALS,
        "Q:CONFIRMED_NOT_SPAWNED_ABORT": {
            "AMBIGUITY_ABORTED_NOT_SPAWNED"
        },
        "Q:UNRESOLVED_DEBT": {"AMBIGUITY_UNRESOLVED_DEBT"},
    }
    for parent in vectors["terminal_parent_classes"]:
        for outcome in outcomes:
            valid = outcome in compatibility[parent]
            operations.append(
                operation(
                    f"BRANCH::T::{parent}::{outcome}",
                    "BRANCH_TERMINAL_MATRIX",
                    parent,
                    "restart_state_derivation",
                    outcome,
                    "terminal_parent_outcome",
                    "PASS" if valid else "REJECT",
                    "NONE" if valid else "BRANCH_MATRIX_REJECT",
                )
            )
    return operations


def p15_invocation_digest(
    spec: dict[str, Any],
    observation: dict[str, str],
    r252: Any,
) -> str:
    return digest(
        {
            "operation_id": spec["operation_id"],
            "fixture_constructor_id": spec["fixture_constructor_id"],
            "target_callable": spec["target_callable"],
            "canonical_input_sha256": observation[
                "canonical_input_sha256"
            ],
            "observed_result": observation["observed_result"],
            "observed_error": observation["observed_error"],
            "r2_5_2_validator_sha256": R252_SHA256,
            "r2_5_2_schema_sha256": r252.SCHEMA_SHA256,
            "r2_5_2_vectors_sha256": r252.VECTORS_SHA256,
        }
    )


def materialize_p15_operations(
    vectors: dict[str, Any],
) -> list[dict[str, str]]:
    operations: list[dict[str, str]] = []
    for spec in vectors["p15_evidence_operations"]:
        operations.append(
            operation(
                spec["operation_id"],
                "P15_EVIDENCE",
                spec["fixture_constructor_id"],
                spec["target_callable"],
                spec["operation_id"],
                "frozen_r2_5_2_fixture",
                spec["expected_result"],
                spec["expected_error"],
            )
        )
    operations.extend(
        [
            operation(
                "P15-INTEGRITY-UNKNOWN-FIXTURE",
                "P15_INTEGRITY",
                "NONEXISTENT_FIXTURE",
                "p15_evidence_adapter",
                "UNKNOWN_FIXTURE",
                "fixture_registry",
                "REJECT",
                "P15_FIXTURE_UNKNOWN",
            ),
            operation(
                "P15-INTEGRITY-FABRICATED-ERROR",
                "P15_INTEGRITY",
                "P15-001",
                "p15_evidence_adapter",
                "FABRICATED_EXPECTED_ERROR",
                "expected_error",
                "REJECT",
                "P15_OBSERVED_ERROR_MISMATCH",
            ),
            operation(
                "P15-INTEGRITY-FABRICATED-INPUT",
                "P15_INTEGRITY",
                "P15-001",
                "p15_evidence_adapter",
                "FABRICATED_INPUT_DIGEST",
                "canonical_input_sha256",
                "REJECT",
                "P15_INPUT_DIGEST_MISMATCH",
            ),
            operation(
                "P15-INTEGRITY-FABRICATED-TARGET",
                "P15_INTEGRITY",
                "P15-001",
                "p15_evidence_adapter",
                "FABRICATED_TARGET_CALLABLE",
                "target_callable",
                "REJECT",
                "P15_TARGET_CALLABLE_MISMATCH",
            ),
        ]
    )
    return operations


def materialize_inherited_operations(
    r254: Any,
    r254_vectors: dict[str, Any],
) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for item in r254_vectors["b5_operations"]:
        copied = copy.deepcopy(item)
        copied["family"] = "INHERITED_B5"
        result.append(copied)
    for item in r254_vectors["source_operations"]:
        copied = copy.deepcopy(item)
        copied["family"] = "INHERITED_SOURCE"
        result.append(copied)
    return result


def materialize_operations(
    vectors: dict[str, Any],
    r254: Any,
    r254_vectors: dict[str, Any],
) -> tuple[list[dict[str, str]], dict[str, int]]:
    groups = {
        "p15": materialize_p15_operations(vectors),
        "inherited": materialize_inherited_operations(r254, r254_vectors),
        "lifecycle_schema": materialize_lifecycle_schema_operations(vectors),
        "branch": materialize_branch_operations(vectors),
        "graph": materialize_graph_operations(vectors),
    }
    operations = [
        item for group in groups.values() for item in group
    ]
    for item in operations:
        validate_operation(item)
    ids = [item["operation_id"] for item in operations]
    if len(ids) != len(set(ids)):
        raise ConformanceError("OPERATION_ID_DUPLICATE")
    return operations, {
        name: len(group) for name, group in groups.items()
    } | {"total": len(operations)}


def build_p15_environment(r252: Any) -> dict[str, Any]:
    r251 = r252.verify_frozen_r251()
    r25 = r251.verify_frozen_r25()
    r23, r24 = r25.verify_frozen_denominators()
    bundle = r25.parse_json(read_ascii_lf(r252.SCHEMA_PATH))
    return {
        "r252": r252,
        "r251": r251,
        "r25": r25,
        "r23": r23,
        "r24": r24,
        "bundle": bundle,
    }


def canonical_p15_input(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, bytes):
        return {
            "type": "bytes",
            "length": len(value),
            "sha256": sha256_bytes(value),
        }
    if isinstance(value, dict):
        return {
            str(key): canonical_p15_input(nested)
            for key, nested in sorted(value.items())
        }
    if isinstance(value, (list, tuple)):
        return [canonical_p15_input(nested) for nested in value]
    if isinstance(value, types.ModuleType):
        module_path = Path(value.__file__).resolve()
        return {
            "type": "frozen_python_module",
            "source_sha256": sha256_bytes(module_path.read_bytes()),
        }
    if hasattr(value, "_snapshot_digest") and hasattr(
        value, "_revision"
    ):
        return {
            "type": type(value).__name__,
            "snapshot_digest": value._snapshot_digest,
            "revision": value._revision,
        }
    slots = getattr(type(value), "__slots__", ())
    if isinstance(slots, str):
        slots = (slots,)
    if slots:
        return {
            "type": type(value).__name__,
            "fields": {
                field: canonical_p15_input(getattr(value, field))
                for field in slots
                if field != "_issuer" and hasattr(value, field)
            },
        }
    raise ConformanceError(
        f"P15_INPUT_TYPE_UNSUPPORTED:{type(value).__name__}"
    )


def invoke_p15_target(
    operation_id: str,
    observation: dict[str, str],
    target: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> Any:
    if operation_id not in P15_REGISTRY:
        raise ConformanceError("P15_FIXTURE_UNKNOWN")
    expected_target = P15_REGISTRY[operation_id]["target_callable"]
    if target.__name__ != expected_target.rsplit(".", 1)[1]:
        raise ConformanceError("P15_TARGET_CALLABLE_MISMATCH")
    if observation:
        raise ConformanceError("P15_MULTIPLE_TARGET_CALLS")
    bound = inspect.signature(target).bind(*args, **kwargs)
    observation["target_callable"] = expected_target
    observation["canonical_input_sha256"] = digest(
        {
            name: canonical_p15_input(value)
            for name, value in bound.arguments.items()
        }
    )
    return target(*args, **kwargs)


def p15_direct_call(
    operation_id: str,
    env: dict[str, Any],
    observation: dict[str, str],
) -> None:
    r252 = env["r252"]
    r251 = env["r251"]
    r25 = env["r25"]
    bundle = env["bundle"]
    context = r252.build_context(
        bundle, r251, r25, env["r23"], env["r24"]
    )
    records = context["records_v252"]

    def spawn(policy: dict[str, Any], consumed: dict[str, Any]) -> None:
        invoke_p15_target(
            operation_id,
            observation,
            r252.authenticate_spawn_from_capability_v252,
            bundle,
            r251,
            r25,
            context["launch_closure"],
            context["store"],
            context["proof_v252"],
            policy,
            consumed,
            context["raw_env"],
            context["process_nonce"],
            context["object_nonce"],
            context["key"],
        )

    def closure(candidate: dict[str, Any], provider: Any) -> None:
        invoke_p15_target(
            operation_id,
            observation,
            r252.validate_and_mint_closure_v252,
            bundle,
            r251,
            r25,
            candidate,
            context["store"],
            provider,
        )

    if operation_id in {"P15-001", "P15-002"}:
        policy = copy.deepcopy(records["env_policy"])
        row = policy["rows"][0 if operation_id == "P15-001" else 1]
        if operation_id == "P15-001":
            row["presence_policy"] = "OPTIONAL"
        else:
            row["source_class"] = "HOST_DERIVED_NON_SECRET"
        r252.seal(r25, row, "policy_row_digest")
        r252.seal(
            r25, policy, "environment_policy_authority_digest"
        )
        spawn(policy, records["consumed"])
        return
    if operation_id in {"P15-003", "P15-004"}:
        consumed = copy.deepcopy(records["consumed"])
        if operation_id == "P15-003":
            consumed["spawn_state"] = "SPAWNED"
        else:
            consumed["consume_cas_revision"] = 999
        r252.seal(r25, consumed, "consumed_launch_digest")
        spawn(records["env_policy"], consumed)
        return
    if operation_id == "P15-005":
        authority = r252.resume_authority_for_context(r25, context)
        invoke_p15_target(
            operation_id,
            observation,
            r252.validate_resume_v252,
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
    if operation_id == "P15-006":
        authority = r252.resume_authority_for_context(r25, context)
        snapshot = copy.deepcopy(context["snapshot"])
        snapshot["resume/prior"]["run_id"] = "other-run"
        r252.seal(r25, snapshot["resume/prior"], "authority_digest")
        r252.rebuild_run_after_snapshot_change(r251, snapshot)
        invoke_p15_target(
            operation_id,
            observation,
            r252.validate_resume_v252,
            bundle,
            r251,
            r25,
            authority,
            context["closure"],
            r252.store_from_snapshot(r251, snapshot),
            None,
            None,
        )
        return
    if operation_id in {"P15-007", "P15-008"}:
        candidate = copy.deepcopy(context["candidate"])
        if operation_id == "P15-007":
            candidate["observation"][
                "observed_effective_model_id"
            ] = "fabricated-model"
            r252.seal(
                r25, candidate["observation"], "observation_digest"
            )
        else:
            claim = candidate["evidence"]["field_claims"][0]
            claim["proof_rule_id"] = "CALLER_ASSERTED"
            r252.seal(r25, claim, "field_claim_digest")
            r252.seal(
                r25,
                candidate["evidence"],
                "evidence_manifest_digest",
            )
        closure(candidate, context["provider_input"])
        return
    provider_mutations = {
        "P15-009": (0, "thinking_state", "INVENTED_STATE"),
        "P15-010": (1, "fallback_state", "INVENTED_STATE"),
        "P15-011": (1, "terminal_category", "INVENTED_STATE"),
        "P15-012": (
            1,
            "usage",
            {
                "input_tokens": "one",
                "output_tokens": 20,
                "private_note": "arbitrary",
            },
        ),
    }
    if operation_id in provider_mutations:
        frame, field, value = provider_mutations[operation_id]
        provider = r252.provider_with_mutation(
            r251, r25, context, frame, field, value
        )
        closure(context["candidate"], provider)
        return
    if operation_id in {"P15-013", "P15-014", "P15-015"}:
        snapshot = copy.deepcopy(context["snapshot"])
        if operation_id == "P15-013":
            snapshot["transaction/current"][
                "store_key"
            ] = "transaction/other"
            r252.seal(
                r25,
                snapshot["transaction/current"],
                "authority_digest",
            )
            r252.rebuild_run_after_snapshot_change(r251, snapshot)
        elif operation_id == "P15-014":
            snapshot["transaction/current"]["run_id"] = "other-run"
            r252.seal(
                r25,
                snapshot["transaction/current"],
                "authority_digest",
            )
            r252.rebuild_run_after_snapshot_change(r251, snapshot)
        else:
            snapshot["unscoped/raw-secret"] = {
                "schema": "caller.secret.v1",
                "raw_secret": "must-not-enter-trusted-store",
            }
        invoke_p15_target(
            operation_id,
            observation,
            r252.validate_store_scope,
            bundle,
            r251,
            r252.store_from_snapshot(r251, snapshot),
        )
        return
    raise ConformanceError("P15_FIXTURE_UNKNOWN")


def observe_p15_actual(
    operation_id: str, env: dict[str, Any]
) -> dict[str, str]:
    observation: dict[str, str] = {}
    observed_error = "NONE"
    try:
        p15_direct_call(operation_id, env, observation)
    except Exception as exc:
        if exc.__class__.__name__ != "ConformanceError":
            raise
        observed_result = "REJECT"
        observed_error = str(exc)
    else:
        observed_result = "PASS"
    if set(observation) != {
        "target_callable",
        "canonical_input_sha256",
    }:
        raise ConformanceError("P15_EVIDENCE_INCOMPLETE")
    return {
        **observation,
        "observed_result": observed_result,
        "observed_error": observed_error,
    }


def execute_p15_actual(
    item: dict[str, Any],
    vectors: dict[str, Any],
    env: dict[str, Any],
) -> None:
    spec_by_id = {
        spec["operation_id"]: spec
        for spec in vectors["p15_evidence_operations"]
    }
    operation_id = item["mutation_operator"]
    if (
        operation_id not in spec_by_id
        or operation_id not in P15_REGISTRY
    ):
        raise ConformanceError("P15_FIXTURE_UNKNOWN")
    spec = spec_by_id[operation_id]
    registry = P15_REGISTRY[operation_id]
    if item["fixture_constructor_id"] != spec["fixture_constructor_id"]:
        raise ConformanceError("P15_FIXTURE_UNKNOWN")
    if (
        item["target_consumer"] != spec["target_callable"]
        or spec["target_callable"] != registry["target_callable"]
    ):
        raise ConformanceError("P15_TARGET_CALLABLE_MISMATCH")
    observation = observe_p15_actual(operation_id, env)
    if observation["target_callable"] != spec["target_callable"]:
        raise ConformanceError("P15_TARGET_CALLABLE_MISMATCH")
    if (
        spec["canonical_input_sha256"]
        != observation["canonical_input_sha256"]
    ):
        raise ConformanceError("P15_INPUT_DIGEST_MISMATCH")
    if observation["observed_result"] != spec["expected_result"]:
        raise ConformanceError("P15_OBSERVED_RESULT_MISMATCH")
    if observation["observed_error"] != spec["expected_error"]:
        raise ConformanceError("P15_OBSERVED_ERROR_MISMATCH")
    if observation["observed_result"] == "PASS":
        return
    raise ConformanceError(observation["observed_error"])


def execute_p15_integrity(
    item: dict[str, Any],
    vectors: dict[str, Any],
    env: dict[str, Any],
) -> None:
    if item["mutation_operator"] == "UNKNOWN_FIXTURE":
        fake = operation(
            "FAKE",
            "P15_EVIDENCE",
            "NONEXISTENT_FIXTURE",
            "nonexistent.target",
            "P15-999",
            "fixture",
            "REJECT",
            "SYNTHETIC",
        )
        try:
            execute_p15_actual(fake, vectors, env)
        except ConformanceError as exc:
            if str(exc) == "P15_FIXTURE_UNKNOWN":
                raise
            raise ConformanceError("P15_INTEGRITY_WRONG_REJECT") from exc
        raise ConformanceError("P15_INTEGRITY_UNEXPECTED_ACCEPT")
    if item["mutation_operator"] == "FABRICATED_EXPECTED_ERROR":
        spec = copy.deepcopy(vectors["p15_evidence_operations"][0])
        spec["expected_error"] = "SYNTHETIC_EXPECTED_ERROR"
        mutated_vectors = copy.deepcopy(vectors)
        mutated_vectors["p15_evidence_operations"][0] = spec
        actual = materialize_p15_operations(mutated_vectors)[0]
        try:
            execute_p15_actual(actual, mutated_vectors, env)
        except ConformanceError as exc:
            if str(exc) == "P15_OBSERVED_ERROR_MISMATCH":
                raise
            raise ConformanceError("P15_INTEGRITY_WRONG_REJECT") from exc
        raise ConformanceError("P15_INTEGRITY_UNEXPECTED_ACCEPT")
    if item["mutation_operator"] == "FABRICATED_INPUT_DIGEST":
        spec = copy.deepcopy(vectors["p15_evidence_operations"][0])
        spec["canonical_input_sha256"] = digest("fabricated-input")
        mutated_vectors = copy.deepcopy(vectors)
        mutated_vectors["p15_evidence_operations"][0] = spec
        actual = materialize_p15_operations(mutated_vectors)[0]
        try:
            execute_p15_actual(actual, mutated_vectors, env)
        except ConformanceError as exc:
            if str(exc) == "P15_INPUT_DIGEST_MISMATCH":
                raise
            raise ConformanceError("P15_INTEGRITY_WRONG_REJECT") from exc
        raise ConformanceError("P15_INTEGRITY_UNEXPECTED_ACCEPT")
    if item["mutation_operator"] == "FABRICATED_TARGET_CALLABLE":
        spec = copy.deepcopy(vectors["p15_evidence_operations"][0])
        spec["target_callable"] = (
            "validate_plamen_model_routing_r2_5_2.nonexistent_target"
        )
        mutated_vectors = copy.deepcopy(vectors)
        mutated_vectors["p15_evidence_operations"][0] = spec
        actual = materialize_p15_operations(mutated_vectors)[0]
        try:
            execute_p15_actual(actual, mutated_vectors, env)
        except ConformanceError as exc:
            if str(exc) == "P15_TARGET_CALLABLE_MISMATCH":
                raise
            raise ConformanceError("P15_INTEGRITY_WRONG_REJECT") from exc
        raise ConformanceError("P15_INTEGRITY_UNEXPECTED_ACCEPT")
    raise ConformanceError("P15_INTEGRITY_OPERATION_UNKNOWN")


def execute_lifecycle_schema_operation(
    item: dict[str, Any],
    validators: dict[str, Any],
) -> None:
    graph, name = lifecycle_fixture_graph(
        item["fixture_constructor_id"]
    )
    if item["family"] == "LIFECYCLE_SCHEMA_POSITIVE":
        validate_semantic_graph(graph, validators)
        return
    record = graph["nodes"][name]
    mutation = item["mutation_operator"]
    target = item["mutation_target"]
    protected: tuple[str, str, str] | None = None
    if mutation == "EXTRA_FIELD_RESEALED":
        if target.endswith(":payload"):
            record["payload"]["unexpected"] = "value"
        else:
            record["unexpected"] = "value"
    elif mutation == "DELETE_REQUIRED_FIELD_RESEALED":
        del record["run_id"]
    elif mutation == "SCHEMA_KIND_MISMATCH_RESEALED":
        record["schema"] = (
            "ConsumedAttemptLaunchAuthorityV2"
            if record["schema"] != "ConsumedAttemptLaunchAuthorityV2"
            else "SpawnIntentAuthorityV1"
        )
    elif mutation == "DELETE_FIELD_RESEALED":
        path = target.split(":", 1)[1]
        delete_path(record, path)
        protected = next(
            (
                (
                    edge["child"],
                    edge["path"],
                    edge["parent"],
                )
                for edge in graph["edges"]
                if edge["child"] == name and edge["path"] == path
            ),
            None,
        )
        if protected is None:
            protected = (name, path, "")
    elif mutation == "WRONG_TYPE_RESEALED":
        path = target.split(":", 1)[1]
        set_path(record, path, ["wrong-type"])
        protected = next(
            (
                (
                    edge["child"],
                    edge["path"],
                    edge["parent"],
                )
                for edge in graph["edges"]
                if edge["child"] == name and edge["path"] == path
            ),
            None,
        )
        if protected is None:
            protected = (name, path, "")
    elif mutation == "REHASHED_VALUE":
        path = target.split(":", 1)[1]
        set_path(record, path, mutation_value(get_path(record, path)))
        protected = next(
            (
                (
                    edge["child"],
                    edge["path"],
                    edge["parent"],
                )
                for edge in graph["edges"]
                if edge["child"] == name and edge["path"] == path
            ),
            None,
        )
        if protected is None:
            protected = (name, path, "")
    else:
        raise ConformanceError("LIFECYCLE_SCHEMA_MUTATION_UNKNOWN")
    reseal_graph_from(graph, name, protected)
    try:
        validate_semantic_graph(graph, validators)
    except ConformanceError as exc:
        raise ConformanceError(
            "LIFECYCLE_SCHEMA_MUTATION_REJECT"
        ) from exc


def build_resolution_next_events(
    resolution: str, next_event: str
) -> list[dict[str, Any]]:
    base = build_full_graph(
        "OBSERVED_SPAWN::PROVIDER_TERMINAL"
        if resolution == "OBSERVED_SPAWNED"
        else "AMBIGUITY_ABORT::AMBIGUITY_ABORTED_NOT_SPAWNED"
    )
    events = [
        copy.deepcopy(base["nodes"][name])
        for name in ("consumed", "intent", "ambiguity", "resolution")
    ]
    q = events[-1]
    q["payload"]["resolution_outcome"] = resolution
    if resolution != "OBSERVED_SPAWNED":
        q["payload"].pop("process_identity_digest", None)
        q["payload"].pop("transport_identity_digest", None)
    seal(q, "event_digest")
    if next_event == "S":
        spawned = make_event(
            "S",
            events,
            {
                "intent_digest": events[1]["event_digest"],
                "launch_replay_digest": LAUNCH_REPLAY,
                "process_identity_digest": PROCESS,
                "transport_identity_digest": TRANSPORT,
                "resolution_digest": q["event_digest"],
            },
        )
        events.append(spawned)
    else:
        outcome = {
            "CONFIRMED_NOT_SPAWNED_ABORT": (
                "AMBIGUITY_ABORTED_NOT_SPAWNED"
            ),
            "UNRESOLVED_DEBT": "AMBIGUITY_UNRESOLVED_DEBT",
        }.get(resolution, "PROVIDER_TERMINAL")
        terminal = make_event(
            "T", events, terminal_payload(outcome, q)
        )
        events.append(terminal)
    return events


def build_terminal_matrix_events(
    parent_class: str, outcome: str
) -> list[dict[str, Any]]:
    if parent_class == "I":
        full = build_full_graph("SPAWN_FAILED::SPAWN_FAILED")
        names = ["consumed", "intent"]
    elif parent_class == "S":
        full = build_full_graph("DIRECT_SPAWN::PROVIDER_TERMINAL")
        names = ["consumed", "intent", "spawned"]
    elif parent_class == "Q:CONFIRMED_NOT_SPAWNED_ABORT":
        full = build_full_graph(
            "AMBIGUITY_ABORT::AMBIGUITY_ABORTED_NOT_SPAWNED"
        )
        names = ["consumed", "intent", "ambiguity", "resolution"]
    else:
        full = build_full_graph(
            "AMBIGUITY_DEBT::AMBIGUITY_UNRESOLVED_DEBT"
        )
        names = ["consumed", "intent", "ambiguity", "resolution"]
    events = [copy.deepcopy(full["nodes"][name]) for name in names]
    terminal = make_event(
        "T", events, terminal_payload(outcome, events[-1])
    )
    events.append(terminal)
    return events


def execute_branch_operation(
    item: dict[str, Any],
    validators: dict[str, Any],
) -> None:
    if item["family"] == "BRANCH_RESOLUTION_NEXT":
        events = build_resolution_next_events(
            item["fixture_constructor_id"],
            item["mutation_operator"],
        )
    else:
        events = build_terminal_matrix_events(
            item["fixture_constructor_id"],
            item["mutation_operator"],
        )
    try:
        validate_lifecycle_events(events, validators)
    except ConformanceError as exc:
        raise ConformanceError("BRANCH_MATRIX_REJECT") from exc


def execute_graph_operation(
    item: dict[str, Any],
    validators: dict[str, Any],
) -> None:
    branch_id, consumer = item["fixture_constructor_id"].rsplit("::", 1)
    graph = graph_view(branch_id, consumer)
    if item["family"] == "GRAPH_POSITIVE":
        validate_semantic_graph(graph, validators)
        return
    if item["family"] == "GRAPH_RECORD_MUTATION":
        name = item["mutation_target"]
        mutation = item["mutation_operator"]
        record = graph["nodes"][name]
        if mutation == "DELETE_RECORD":
            del graph["nodes"][name]
        elif mutation == "CORRUPT_SELF_DIGEST":
            record[digest_field(record)] = digest("corrupt")
        elif mutation == "EXTRA_FIELD_RESEALED":
            record["unexpected"] = "value"
            reseal_graph_from(graph, name)
        elif mutation == "DELETE_REQUIRED_FIELD_RESEALED":
            path = required_mutation_path(name, record)
            delete_path(record, path)
            reseal_graph_from(
                graph, name, protected_graph_path(graph, name, path)
            )
        elif mutation == "WRONG_TYPE_RESEALED":
            path = semantic_path(name, record)
            set_path(
                record,
                path,
                ["wrong-type"],
            )
            reseal_graph_from(
                graph, name, protected_graph_path(graph, name, path)
            )
        elif mutation == "SEMANTIC_FIELD_RESEALED":
            path = semantic_path(name, record)
            set_path(record, path, mutation_value(get_path(record, path)))
            reseal_graph_from(
                graph, name, protected_graph_path(graph, name, path)
            )
        else:
            raise ConformanceError("GRAPH_RECORD_MUTATION_UNKNOWN")
        try:
            validate_semantic_graph(graph, validators)
        except ConformanceError as exc:
            raise ConformanceError(
                "GRAPH_RECORD_MUTATION_REJECT"
            ) from exc
        return
    edge = next(
        value
        for value in graph["edges"]
        if value["edge_id"] == item["mutation_target"]
    )
    protected = (edge["child"], edge["path"], edge["parent"])
    if item["mutation_operator"] == "WRONG_PARENT_DIGEST_RESEALED":
        set_path(
            graph["nodes"][edge["child"]],
            edge["path"],
            digest("wrong-parent"),
        )
        reseal_graph_from(graph, edge["child"], protected)
    elif item["mutation_operator"] == "WRONG_PARENT_SCOPE_RESEALED":
        parent = graph["nodes"][edge["parent"]]
        parent["run_id"] = "run-other"
        reseal_graph_from(graph, edge["parent"])
    else:
        raise ConformanceError("GRAPH_PARENT_MUTATION_UNKNOWN")
    try:
        validate_semantic_graph(graph, validators)
    except ConformanceError as exc:
        raise ConformanceError("GRAPH_PARENT_MUTATION_REJECT") from exc


def execute_operations(
    operations: list[dict[str, Any]],
    vectors: dict[str, Any],
    validators: dict[str, Any],
    r254: Any,
    p15_env: dict[str, Any],
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in operations:
        try:
            family = item["family"]
            if family == "P15_EVIDENCE":
                execute_p15_actual(item, vectors, p15_env)
            elif family == "P15_INTEGRITY":
                execute_p15_integrity(item, vectors, p15_env)
            elif family == "INHERITED_B5":
                r254.execute_b5_operation(item)
            elif family == "INHERITED_SOURCE":
                r254.execute_source_operation(item)
            elif family.startswith("LIFECYCLE_SCHEMA_"):
                execute_lifecycle_schema_operation(item, validators)
            elif family.startswith("BRANCH_"):
                execute_branch_operation(item, validators)
            elif family.startswith("GRAPH_"):
                execute_graph_operation(item, validators)
            else:
                raise ConformanceError(
                    f"OPERATION_FAMILY_UNKNOWN:{family}"
                )
        except Exception as exc:
            if item["expected_result"] != "REJECT":
                raise ConformanceError(
                    f"UNEXPECTED_REJECT:{item['operation_id']}:{str(exc)}"
                ) from exc
            if str(exc) != item["expected_error"]:
                raise ConformanceError(
                    (
                        f"WRONG_OPERATION_ERROR:{item['operation_id']}:"
                        f"{item['expected_error']}:{str(exc)}"
                    )
                ) from exc
        else:
            if item["expected_result"] != "PASS":
                raise ConformanceError(
                    f"UNEXPECTED_ACCEPT:{item['operation_id']}"
                )
        counts[item["family"]] = counts.get(item["family"], 0) + 1
    return counts


def main() -> int:
    plan_raw = verify_hash(PLAN_PATH, PLAN_SHA256, "PLAN")
    schema_raw = verify_hash(SCHEMA_PATH, SCHEMA_SHA256, "SCHEMA")
    vectors_raw = verify_hash(VECTORS_PATH, VECTORS_SHA256, "VECTORS")
    if b"End of R2.5.5 RED engineering plan.\n" not in plan_raw:
        raise ConformanceError("PLAN_END_MARKER_MISSING")
    validate_review_binding()
    schema = parse_json_strict(schema_raw)
    vectors = parse_json_strict(vectors_raw)
    validate_vectors_header(vectors)
    validators = build_schema_validators(schema)
    r254 = verify_frozen_r254()
    r254_vectors = parse_json_strict(read_ascii_lf(r254.VECTORS_PATH))
    r252 = import_exact(R252_PATH, R252_SHA256, "r252_p15")
    p15_env = build_p15_environment(r252)
    observations: dict[str, dict[str, str]] = {}
    for spec in vectors["p15_evidence_operations"]:
        operation_id = spec["operation_id"]
        observation = observe_p15_actual(operation_id, p15_env)
        observations[operation_id] = observation
        if observation["target_callable"] != spec["target_callable"]:
            raise ConformanceError(
                f"P15_TARGET_CALLABLE_MISMATCH:{operation_id}"
            )
        if (
            spec["canonical_input_sha256"]
            != observation["canonical_input_sha256"]
        ):
            raise ConformanceError(
                f"P15_INPUT_DIGEST_MISMATCH:{operation_id}"
            )
        if (
            observation["observed_result"] != spec["expected_result"]
            or observation["observed_error"] != spec["expected_error"]
        ):
            raise ConformanceError(
                f"P15_OBSERVATION_MISMATCH:{operation_id}"
            )
        expected_digest = p15_invocation_digest(
            spec, observation, r252
        )
        if spec["invocation_sha256"] != expected_digest:
            raise ConformanceError(
                f"P15_INVOCATION_HASH_MISMATCH:{spec['operation_id']}"
            )
    operations, derived = materialize_operations(
        vectors, r254, r254_vectors
    )
    operation_sha = sha256_bytes(canonical_bytes(operations))
    p15_evidence = [
        {
            "operation_id": spec["operation_id"],
            "fixture_constructor_id": spec["fixture_constructor_id"],
            **observations[spec["operation_id"]],
            "r2_5_2_validator_sha256": R252_SHA256,
            "r2_5_2_schema_sha256": r252.SCHEMA_SHA256,
            "r2_5_2_vectors_sha256": r252.VECTORS_SHA256,
            "invocation_sha256": p15_invocation_digest(
                spec, observations[spec["operation_id"]], r252
            ),
        }
        for spec in vectors["p15_evidence_operations"]
    ]
    p15_sha = sha256_bytes(canonical_bytes(p15_evidence))
    expected = vectors["expected_expansion"]
    if (
        expected["lifecycle_schema_operations"]
        != derived["lifecycle_schema"]
    ):
        raise ConformanceError("LIFECYCLE_SCHEMA_COUNT_MISMATCH")
    if expected["branch_matrix_operations"] != derived["branch"]:
        raise ConformanceError("BRANCH_MATRIX_COUNT_MISMATCH")
    if expected["semantic_graph_operations"] != derived["graph"]:
        raise ConformanceError("SEMANTIC_GRAPH_COUNT_MISMATCH")
    if expected["total_executed_operations"] != derived["total"]:
        raise ConformanceError("TOTAL_OPERATION_COUNT_MISMATCH")
    if expected["operation_manifest_sha256"] != operation_sha:
        raise ConformanceError("OPERATION_MANIFEST_HASH_MISMATCH")
    if expected["p15_evidence_manifest_sha256"] != p15_sha:
        raise ConformanceError("P15_EVIDENCE_MANIFEST_HASH_MISMATCH")
    counts = execute_operations(
        operations, vectors, validators, r254, p15_env
    )
    print("R2.5.5_RED_DENOMINATOR=PASS")
    print("FROZEN_R2_5_4_BASELINE=PASS")
    print("EVIDENCE_BOUND_P15_OPERATIONS=15")
    print("P15_INTEGRITY_OPERATIONS=4")
    print("PRESERVED_B5_OPERATIONS=14")
    print("PRESERVED_SOURCE_OPERATIONS=43")
    print(
        f"LIFECYCLE_SCHEMA_OPERATIONS={derived['lifecycle_schema']}"
    )
    print(f"BRANCH_MATRIX_OPERATIONS={derived['branch']}")
    print(f"SEMANTIC_GRAPH_OPERATIONS={derived['graph']}")
    print(f"TOTAL_EXECUTED_OPERATIONS={derived['total']}")
    print(f"OPERATION_MANIFEST_SHA256={operation_sha}")
    print(f"P15_EVIDENCE_MANIFEST_SHA256={p15_sha}")
    print(f"PLAN_SHA256={sha256_bytes(plan_raw)}")
    print(f"SCHEMA_SHA256={sha256_bytes(schema_raw)}")
    print(f"VECTORS_SHA256={sha256_bytes(vectors_raw)}")
    print(f"EXECUTED_FAMILY_COUNT={len(counts)}")
    print("GREEN_IMPLEMENTATION_AUTHORIZED=false")
    print("PRODUCTION_INTEGRATION_AUTHORIZED=false")
    print("AUTHOR_DISPOSITION=RED_SEMANTIC_MODEL_SELF_VALIDATED_ONLY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
