from __future__ import annotations

import copy
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable


HERE = Path(__file__).resolve().parent
PLAN_PATH = (
    HERE
    / "Plamen_Backend_Model_Routing_R2.5.4_RED_Engineering_Plan_2026-07-30.md"
)
SCHEMA_PATH = (
    HERE / "Plamen_Backend_Model_Routing_R2.5.4_RED_Schemas_2026-07-30.json"
)
VECTORS_PATH = (
    HERE
    / "Plamen_Backend_Model_Routing_R2.5.4_RED_Operation_Vectors_2026-07-30.json"
)
R253_PATH = HERE / "validate_plamen_model_routing_r2_5_3_red.py"
R253_VECTORS_PATH = (
    HERE
    / "Plamen_Backend_Model_Routing_R2.5.3_RED_Fixture_Denominator_2026-07-30.json"
)
REVIEW_PATH = (
    HERE.parent
    / "plamen-codex-implementation"
    / "review_fixtures"
    / "backend_model_routing_r2_5_3_red_independent_review_r1_20260730.md"
)

PLAN_SHA256 = (
    "9fa75435752ccd778cbda7b691d8c3e7295fe62fab4f2a0f96f0fcbc4f9ed303"
)
SCHEMA_SHA256 = (
    "fec29bc5b7db5ca4edfe7a7b3ae60a7ce70b7c2960dcd7ee9c37378ea65df2cf"
)
VECTORS_SHA256 = (
    "6f3e593bd9ba0e98ad684398629e78d4ffdd89ba0073133ed86b2629bfefa78f"
)
R253_SHA256 = (
    "1fb1b2e40630bca93ce220bcbbbb4b41b38590411efe095b56336e6002299bfe"
)
R253_VECTORS_SHA256 = (
    "8a0dbcfbf4ee7d7a1b9e141196890af9a17bb322be94ed832a9873c765ec0cb6"
)
REVIEW_BODY_SHA256 = (
    "71a549c72522e4ad57229b75ffbf2115353eefd0d85b46ae2392a2c55421e075"
)
REVIEW_WHOLE_SHA256 = (
    "70f0c07214f0e18145070cd315b4129d99c054105f03f94134fe2fd45ef580c3"
)
R253_EXPECTED = [
    "R2.5.3_RED_DENOMINATOR=PASS",
    "FROZEN_R2_5_2_EXECUTED_DENOMINATOR=686",
    "PRESERVED_PREDECESSOR_REPLAY_ROWS=15",
    "NEW_CAUSAL_RED_ROWS=33",
    "TOTAL_DECLARED_RED_ROWS=48",
    "R2_5_2_FOCUSED_UNEXPECTED_ACCEPTS=5/8",
    (
        "PLAN_SHA256="
        "2eb28c18564dae8acc636b8de41a3a2b240ae03375c22f224a23eedcec9797cf"
    ),
    (
        "VECTORS_SHA256="
        "8a0dbcfbf4ee7d7a1b9e141196890af9a17bb322be94ed832a9873c765ec0cb6"
    ),
    "GREEN_IMPLEMENTATION_AUTHORIZED=false",
    "PRODUCTION_INTEGRATION_AUTHORIZED=false",
    "AUTHOR_DISPOSITION=RED_BASELINE_SELF_VALIDATED_ONLY",
]

DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
KEY_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$", re.ASCII)
ZERO = "0" * 64
RUN_ID = "run-r254"
GENERATION = 2
ATTEMPT = 3
SNAPSHOT = hashlib.sha256(b"snapshot-r254").hexdigest()
LAUNCH_REPLAY = hashlib.sha256(b"launch-replay-r254").hexdigest()
PROCESS = hashlib.sha256(b"process-r254").hexdigest()
TRANSPORT = hashlib.sha256(b"transport-r254").hexdigest()
PROVIDER_TERMINAL = hashlib.sha256(b"provider-terminal-r254").hexdigest()
EVIDENCE = hashlib.sha256(b"governed-evidence-r254").hexdigest()


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


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


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
    def reject_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ConformanceError(f"DUPLICATE_JSON_KEY:{key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise ConformanceError(f"NONFINITE_JSON_NUMBER:{value}")

    try:
        return json.loads(
            raw.decode("ascii"),
            object_pairs_hook=reject_pairs,
            parse_constant=reject_constant,
        )
    except ConformanceError:
        raise
    except Exception as exc:
        raise ConformanceError("STRICT_JSON_INVALID") from exc


def expect_error(call: Callable[[], Any], expected: str) -> None:
    try:
        call()
    except ConformanceError as exc:
        if str(exc) != expected:
            raise ConformanceError(
                f"WRONG_ERROR:{expected}:{str(exc)}"
            ) from exc
        return
    raise ConformanceError(f"EXPECTED_REJECT:{expected}")


def verify_hash(path: Path, expected: str, name: str) -> bytes:
    raw = read_ascii_lf(path)
    if expected != "TO_BE_FROZEN" and sha256_bytes(raw) != expected:
        raise ConformanceError(f"{name}_HASH_MISMATCH")
    return raw


def validate_review_binding() -> None:
    raw = read_ascii_lf(REVIEW_PATH)
    if sha256_bytes(raw) != REVIEW_WHOLE_SHA256:
        raise ConformanceError("R2_5_3_REVIEW_WHOLE_HASH_MISMATCH")
    marker = b"\n## Artifact integrity\n"
    position = raw.rfind(marker)
    if position < 0:
        raise ConformanceError("R2_5_3_REVIEW_BODY_BOUNDARY_MISSING")
    body = raw[:position]
    if sha256_bytes(body) != REVIEW_BODY_SHA256:
        raise ConformanceError("R2_5_3_REVIEW_BODY_HASH_MISMATCH")
    required = (
        b"Verdict: **BLOCK**",
        b"B5 launch-only direction: ACCEPTED",
        b"external replay source authority closure: FAIL",
        b"durable restart/recovery grammar completeness: FAIL",
        b"atomic executable GREEN denominator: FAIL",
    )
    if any(fragment not in body for fragment in required):
        raise ConformanceError("R2_5_3_REVIEW_EVIDENCE_MISMATCH")


def verify_frozen_r253() -> None:
    verify_hash(R253_PATH, R253_SHA256, "R2_5_3_VALIDATOR")
    verify_hash(R253_VECTORS_PATH, R253_VECTORS_SHA256, "R2_5_3_VECTORS")
    completed = subprocess.run(
        [sys.executable, "-I", str(R253_PATH)],
        check=False,
        capture_output=True,
        text=True,
        encoding="ascii",
        timeout=240,
    )
    if completed.returncode != 0:
        raise ConformanceError("FROZEN_R2_5_3_EXECUTION_FAILED")
    if completed.stderr:
        raise ConformanceError("FROZEN_R2_5_3_STDERR_NONEMPTY")
    if completed.stdout.splitlines() != R253_EXPECTED:
        raise ConformanceError("FROZEN_R2_5_3_OUTPUT_MISMATCH")


def validate_operation_record(operation: dict[str, Any]) -> None:
    fields = {
        "operation_id",
        "family",
        "fixture_constructor_id",
        "target_consumer",
        "mutation_operator",
        "mutation_target",
        "expected_result",
        "expected_error",
    }
    if set(operation) != fields:
        raise ConformanceError("OPERATION_RECORD_FIELD_MISMATCH")
    if operation["expected_result"] not in {"PASS", "REJECT"}:
        raise ConformanceError("OPERATION_RESULT_INVALID")
    if (
        operation["expected_result"] == "PASS"
        and operation["expected_error"] != "NONE"
    ):
        raise ConformanceError("PASS_OPERATION_HAS_ERROR")
    if (
        operation["expected_result"] == "REJECT"
        and operation["expected_error"] == "NONE"
    ):
        raise ConformanceError("REJECT_OPERATION_MISSING_ERROR")


def validate_schema_contract(schema: dict[str, Any]) -> dict[str, Any]:
    if (
        schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
        or schema.get("$id") != "urn:plamen:model-routing:r2.5.4:red"
        or schema.get("type") != "object"
    ):
        raise ConformanceError("SCHEMA_HEADER_MISMATCH")
    definitions = schema.get("$defs", {})
    for name in (
        "Digest",
        "RunId",
        "ArtifactKey",
        "ReplayManifestEntryV1",
        "ReplayManifestAuthorityV1",
        "ReplayReferenceV2",
        "LifecycleEventV1",
    ):
        if name not in definitions:
            raise ConformanceError(f"SCHEMA_DEFINITION_MISSING:{name}")
    contract = schema.get("x-plamen-contract")
    if not isinstance(contract, dict) or contract.get("version") != 1:
        raise ConformanceError("SCHEMA_CONTRACT_MISSING")
    source = contract.get("trusted_source", {})
    if source != {
        "selection": "OUTSIDE_CALLER_INPUT",
        "expected_root_owner": "ORCHESTRATOR_GOVERNED_CONFIGURATION",
        "manifest_map": (
            "EXACT_KEY_TO_DIGEST_LENGTH_STAGE_SNAPSHOT_RUN_GENERATION_ATTEMPT"
        ),
        "artifact_read_count_per_decision": 1,
        "parse_buffer": "SAME_BUFFER_AS_DIGEST_CHECK",
        "caller_forbidden_fields": [
            "expected_manifest_root",
            "manifest",
            "path",
            "uri",
            "raw_bytes",
            "source",
            "registry",
            "issuer",
            "validation_result",
        ],
    }:
        raise ConformanceError("TRUSTED_SOURCE_CONTRACT_MISMATCH")
    lifecycle = contract.get("lifecycle", {})
    expected_prefixes = {
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
    if set(lifecycle.get("valid_prefixes", [])) != expected_prefixes:
        raise ConformanceError("LIFECYCLE_PREFIX_SCHEMA_MISMATCH")
    graph = contract.get("replay_graph", {})
    consumers = graph.get("consumers", {})
    expected_consumers = {
        "launch_replay_validator",
        "proof_mint",
        "spawn_authentication",
        "provider_spool_acceptance",
        "completed_current_construction",
        "current_replay_validator",
        "resume_authorization",
    }
    if set(consumers) != expected_consumers:
        raise ConformanceError("GRAPH_CONSUMER_SET_MISMATCH")
    if (
        consumers["provider_spool_acceptance"].get("nodes_through") != "spawned"
        or consumers["completed_current_construction"].get("nodes_through")
        != "completed_current"
    ):
        raise ConformanceError("REQUIRED_CONSUMER_ENDPOINT_MISSING")
    current_consumers = [
        "completed_current_construction",
        "current_replay_validator",
        "resume_authorization",
    ]
    if graph.get("variants") != {
        "PROVIDER_TERMINAL": {
            "consumers": current_consumers,
            "excluded_nodes": [],
            "excluded_edges": ["terminal_to_neutral"],
        },
        "LAUNCHER_TERMINAL_NO_PROVIDER": {
            "consumers": current_consumers,
            "excluded_nodes": ["provider_artifact"],
            "excluded_edges": [
                "terminal_to_provider_artifact",
                "provider_artifact_to_neutral",
            ],
        },
    }:
        raise ConformanceError("GRAPH_VARIANT_CONTRACT_MISMATCH")
    return contract


def validate_vectors_header(vectors: dict[str, Any]) -> None:
    if (
        vectors.get("schema")
        != "plamen.model-routing-r2.5.4-red-operation-vectors.v1"
        or vectors.get("version") != 1
        or vectors.get("disposition")
        != "DESIGN_RED_ONLY_INDEPENDENT_ACCEPTANCE_REQUIRED"
    ):
        raise ConformanceError("VECTOR_HEADER_MISMATCH")
    review = vectors.get("sealed_r2_5_3_review", {})
    if review != {
        "body_sha256": REVIEW_BODY_SHA256,
        "whole_sha256": REVIEW_WHOLE_SHA256,
        "verdict": "BLOCK",
    }:
        raise ConformanceError("VECTOR_REVIEW_BINDING_MISMATCH")
    expected_authorization = {
        "green_implementation": False,
        "production_integration": False,
        "provider_calls": False,
        "audit_execution": False,
        "defaults_or_config_changes": False,
        "commit_or_push": False,
    }
    if vectors.get("authorization") != expected_authorization:
        raise ConformanceError("VECTOR_AUTHORIZATION_MISMATCH")
    if len(vectors.get("predecessor_operations", [])) != 15:
        raise ConformanceError("P15_COUNT_MISMATCH")
    if len(vectors.get("b5_operations", [])) != 14:
        raise ConformanceError("B5_COUNT_MISMATCH")
    if len(vectors.get("source_operations", [])) != 43:
        raise ConformanceError("SOURCE_OPERATION_COUNT_MISMATCH")
    if len(vectors.get("lifecycle_positive_variants", [])) != 30:
        raise ConformanceError("LIFECYCLE_POSITIVE_COUNT_MISMATCH")
    if len(vectors.get("lifecycle_forbidden_sequences", [])) != 16:
        raise ConformanceError("LIFECYCLE_FORBIDDEN_COUNT_MISMATCH")
    if len(vectors.get("lifecycle_payload_mutations", [])) != 21:
        raise ConformanceError("LIFECYCLE_PAYLOAD_COUNT_MISMATCH")


def validate_p15_binding(vectors: dict[str, Any]) -> None:
    frozen = parse_json_strict(read_ascii_lf(R253_VECTORS_PATH))
    rows = frozen.get("rows", [])[:15]
    operations = vectors["predecessor_operations"]
    if len(rows) != 15:
        raise ConformanceError("FROZEN_P15_ROWS_MISSING")
    for index, (row, item) in enumerate(zip(rows, operations), start=1):
        if (
            item["operation_id"] != f"P15-{index:03d}"
            or row.get("blocker") != "P15"
            or row.get("contract") != "PRESERVE_EXACT_PREDECESSOR_REPLAY"
            or row.get("green_expected")
            != f"REJECT:{item['expected_error']}"
        ):
            raise ConformanceError(f"FROZEN_P15_BINDING_MISMATCH:{index}")


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


def materialize_operations(
    contract: dict[str, Any], vectors: dict[str, Any]
) -> tuple[list[dict[str, str]], dict[str, int]]:
    operations: list[dict[str, str]] = []
    for group in ("predecessor_operations", "b5_operations", "source_operations"):
        for item in vectors[group]:
            validate_operation_record(item)
            operations.append(copy.deepcopy(item))

    lifecycle_count = 0
    event_mutations = vectors["derivation"]["lifecycle_event_mutations"]
    mutation_error = {
        "WRONG_PARENT_DIGEST": "LIFECYCLE_PARENT_MISMATCH",
        "WRONG_RUN": "LIFECYCLE_SCOPE_MISMATCH",
        "WRONG_GENERATION": "LIFECYCLE_SCOPE_MISMATCH",
        "WRONG_ATTEMPT": "LIFECYCLE_SCOPE_MISMATCH",
        "WRONG_EVENT_REVISION": "LIFECYCLE_REVISION_MISMATCH",
        "WRONG_CAS_REVISION": "LIFECYCLE_REVISION_MISMATCH",
    }
    for variant in vectors["lifecycle_positive_variants"]:
        variant_id = variant["variant_id"]
        operations.append(
            operation(
                f"LIFECYCLE::{variant_id}::POSITIVE",
                "LIFECYCLE_POSITIVE",
                variant_id,
                "restart_state_derivation",
                "NONE",
                variant["tokens"],
                "PASS",
                "NONE",
            )
        )
        lifecycle_count += 1
        tokens = variant["tokens"].split(",")
        for index, token in enumerate(tokens):
            for mutation in event_mutations:
                operations.append(
                    operation(
                        (
                            f"LIFECYCLE::{variant_id}::EVENT::{index}:{token}"
                            f"::{mutation}"
                        ),
                        "LIFECYCLE_EVENT_MUTATION",
                        variant_id,
                        "restart_state_derivation",
                        mutation,
                        f"{index}:{token}",
                        "REJECT",
                        mutation_error[mutation],
                    )
                )
                lifecycle_count += 1
    for variant in vectors["lifecycle_forbidden_sequences"]:
        operations.append(
            operation(
                f"LIFECYCLE::{variant['variant_id']}::FORBIDDEN",
                "LIFECYCLE_FORBIDDEN",
                variant["variant_id"],
                "restart_state_derivation",
                "FORBIDDEN_PREFIX",
                variant["tokens"],
                "REJECT",
                variant["expected_error"],
            )
        )
        lifecycle_count += 1
    for mutation in vectors["lifecycle_payload_mutations"]:
        operations.append(
            operation(
                f"LIFECYCLE::{mutation['mutation_id']}::PAYLOAD",
                "LIFECYCLE_PAYLOAD_MUTATION",
                mutation["mutation_id"],
                "restart_state_derivation",
                mutation.get("mutation", "WRONG_VALUE"),
                f"{mutation['event_kind']}:{mutation['field']}",
                "REJECT",
                mutation["expected_error"],
            )
        )
        lifecycle_count += 1

    graph_count = 0
    graph = contract["replay_graph"]
    node_mutations = vectors["derivation"]["graph_node_mutations"]
    edge_mutations = vectors["derivation"]["graph_edge_mutations"]
    variant_contract = graph["variants"]
    current_consumers = {
        consumer
        for variant in variant_contract.values()
        for consumer in variant["consumers"]
    }
    for consumer in graph["consumers"]:
        variants = (
            list(variant_contract)
            if consumer in current_consumers
            else ["COMMON_PREFIX"]
        )
        for variant in variants:
            applicable_nodes, applicable_edges = graph_applicability(
                contract, consumer, variant
            )
            fixture = f"CANONICAL_{variant}_GRAPH"
            operations.append(
                operation(
                    f"GRAPH::{variant}::{consumer}::POSITIVE",
                    "GRAPH_POSITIVE",
                    fixture,
                    consumer,
                    "NONE",
                    "complete_applicable_graph",
                    "PASS",
                    "NONE",
                )
            )
            graph_count += 1
            for node in applicable_nodes:
                for mutation in node_mutations:
                    operations.append(
                        operation(
                            (
                                f"GRAPH::{variant}::{consumer}::NODE::{node}"
                                f"::{mutation}"
                            ),
                            "GRAPH_NODE_MUTATION",
                            fixture,
                            consumer,
                            mutation,
                            node,
                            "REJECT",
                            (
                                "GRAPH_NODE_MISSING"
                                if mutation == "DELETE_NODE"
                                else "GRAPH_NODE_SEAL_MISMATCH"
                            ),
                        )
                    )
                    graph_count += 1
            for edge in applicable_edges:
                for mutation in edge_mutations:
                    operations.append(
                        operation(
                            (
                                f"GRAPH::{variant}::{consumer}::EDGE::{edge}"
                                f"::{mutation}"
                            ),
                            "GRAPH_EDGE_MUTATION",
                            fixture,
                            consumer,
                            mutation,
                            edge,
                            "REJECT",
                            (
                                "GRAPH_EDGE_PARENT_MISMATCH"
                                if mutation == "WRONG_PARENT_DIGEST"
                                else "GRAPH_EDGE_SCOPE_MISMATCH"
                            ),
                        )
                    )
                    graph_count += 1
    for item in operations:
        validate_operation_record(item)
    ids = [item["operation_id"] for item in operations]
    if len(ids) != len(set(ids)):
        raise ConformanceError("OPERATION_ID_DUPLICATE")
    counts = {
        "lifecycle": lifecycle_count,
        "graph": graph_count,
        "total": len(operations),
    }
    return operations, counts


def seal_record(record: dict[str, Any], field: str) -> None:
    preimage = copy.deepcopy(record)
    preimage.pop(field, None)
    record[field] = digest(preimage)


class ReplaySource:
    def __init__(
        self,
        manifest: dict[str, Any],
        artifacts: dict[str, bytes],
        expected_root: str,
        *,
        source_id: str = "source-r254",
        mutate_on_second_read: bool = False,
        path_alias: bool = False,
    ) -> None:
        self.manifest = copy.deepcopy(manifest)
        self.artifacts = dict(artifacts)
        self.expected_root = expected_root
        self.source_id = source_id
        self.mutate_on_second_read = mutate_on_second_read
        self.path_alias = path_alias
        self.read_count = 0

    def read_once(self, key: str) -> bytes:
        self.read_count += 1
        if self.mutate_on_second_read and self.read_count > 1:
            return b'{"mutated":true}'
        return self.artifacts[key]


def build_source_fixture(stage: str = "LAUNCH") -> tuple[ReplaySource, dict[str, Any]]:
    key = "launch-artifact" if stage == "LAUNCH" else "current-artifact"
    artifact = canonical_bytes(
        {
            "schema": f"{stage.title()}ReplayArtifactV1",
            "stage": stage,
            "run_id": RUN_ID,
            "generation": GENERATION,
            "attempt_ordinal": ATTEMPT,
            "snapshot_digest": SNAPSHOT,
        }
    )
    entry = {
        "artifact_key": key,
        "artifact_digest": sha256_bytes(artifact),
        "byte_length": len(artifact),
        "stage": stage,
        "snapshot_digest": SNAPSHOT,
        "run_id": RUN_ID,
        "generation": GENERATION,
        "attempt_ordinal": ATTEMPT,
    }
    manifest = {
        "schema": "ReplayManifestAuthorityV1",
        "version": 1,
        "authority_id": "authority-r254",
        "source_id": "source-r254",
        "key_policy": "ASCII_BYTEWISE_LOWER_V1",
        "entries": [entry],
    }
    seal_record(manifest, "manifest_root_digest")
    source = ReplaySource(
        manifest,
        {key: artifact},
        manifest["manifest_root_digest"],
    )
    reference = {
        "schema": (
            "LaunchReplayReferenceV2"
            if stage == "LAUNCH"
            else "CurrentReplayReferenceV2"
        ),
        "version": 2,
        "kind": stage,
        "artifact_key": key,
        "claimed_artifact_digest": entry["artifact_digest"],
        "claimed_byte_length": entry["byte_length"],
        "claimed_stage": entry["stage"],
        "claimed_snapshot_digest": entry["snapshot_digest"],
        "claimed_run_id": entry["run_id"],
        "claimed_generation": entry["generation"],
        "claimed_attempt_ordinal": entry["attempt_ordinal"],
    }
    return source, reference


def valid_key(key: str) -> bool:
    if not key.isascii() or KEY_RE.fullmatch(key) is None:
        return False
    return all(part not in key for part in ("/", "\\", ":", "..", "%", "\x00"))


def validate_replay_source(
    source: ReplaySource,
    reference: dict[str, Any],
) -> dict[str, Any]:
    allowed = {
        "schema",
        "version",
        "kind",
        "artifact_key",
        "claimed_artifact_digest",
        "claimed_byte_length",
        "claimed_stage",
        "claimed_snapshot_digest",
        "claimed_run_id",
        "claimed_generation",
        "claimed_attempt_ordinal",
    }
    if set(reference) != allowed:
        raise ConformanceError("REPLAY_REFERENCE_FIELD_FORBIDDEN")
    if (
        reference.get("version") != 2
        or (
            reference.get("kind") == "LAUNCH"
            and reference.get("schema") != "LaunchReplayReferenceV2"
        )
        or (
            reference.get("kind") == "CURRENT"
            and reference.get("schema") != "CurrentReplayReferenceV2"
        )
        or reference.get("kind") not in {"LAUNCH", "CURRENT"}
    ):
        raise ConformanceError("REPLAY_REFERENCE_SCHEMA_MISMATCH")
    if source.path_alias:
        raise ConformanceError("REPLAY_SOURCE_PATH_ALIAS")
    manifest = copy.deepcopy(source.manifest)
    if set(manifest) != {
        "schema",
        "version",
        "authority_id",
        "source_id",
        "key_policy",
        "entries",
        "manifest_root_digest",
    }:
        raise ConformanceError("REPLAY_MANIFEST_INVALID")
    root = manifest.pop("manifest_root_digest", None)
    if root != source.expected_root or digest(manifest) != root:
        raise ConformanceError("REPLAY_MANIFEST_ROOT_MISMATCH")
    if (
        manifest.get("schema") != "ReplayManifestAuthorityV1"
        or manifest.get("version") != 1
        or manifest.get("key_policy") != "ASCII_BYTEWISE_LOWER_V1"
    ):
        raise ConformanceError("REPLAY_MANIFEST_INVALID")
    if (
        not isinstance(source.expected_root, str)
        or DIGEST_RE.fullmatch(source.expected_root) is None
    ):
        raise ConformanceError("REPLAY_MANIFEST_ROOT_MISMATCH")
    if manifest.get("source_id") != source.source_id:
        raise ConformanceError("REPLAY_SOURCE_MISMATCH")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ConformanceError("REPLAY_MANIFEST_INVALID")
    keys = [entry.get("artifact_key") for entry in entries]
    if len(keys) != len(set(keys)):
        raise ConformanceError("REPLAY_MANIFEST_DUPLICATE_KEY")
    if keys != sorted(keys) or any(
        not isinstance(key, str) or not valid_key(key) for key in keys
    ):
        raise ConformanceError("REPLAY_MANIFEST_KEY_INVALID")
    entry_fields = {
        "artifact_key",
        "artifact_digest",
        "byte_length",
        "stage",
        "snapshot_digest",
        "run_id",
        "generation",
        "attempt_ordinal",
    }
    for entry in entries:
        if set(entry) != entry_fields:
            raise ConformanceError("REPLAY_MANIFEST_ENTRY_INVALID")
        if (
            not isinstance(entry["artifact_digest"], str)
            or DIGEST_RE.fullmatch(entry["artifact_digest"]) is None
            or not isinstance(entry["snapshot_digest"], str)
            or DIGEST_RE.fullmatch(entry["snapshot_digest"]) is None
            or not isinstance(entry["byte_length"], int)
            or isinstance(entry["byte_length"], bool)
            or entry["byte_length"] < 1
            or entry["stage"] not in {"LAUNCH", "CURRENT"}
            or not isinstance(entry["generation"], int)
            or isinstance(entry["generation"], bool)
            or entry["generation"] < 0
            or not isinstance(entry["attempt_ordinal"], int)
            or isinstance(entry["attempt_ordinal"], bool)
            or entry["attempt_ordinal"] < 0
        ):
            raise ConformanceError("REPLAY_MANIFEST_ENTRY_INVALID")
    key = reference.get("artifact_key")
    if not isinstance(key, str) or not valid_key(key):
        raise ConformanceError("REPLAY_KEY_INVALID")
    matches = [entry for entry in entries if entry["artifact_key"] == key]
    if not matches:
        raise ConformanceError("REPLAY_KEY_NOT_FOUND")
    entry = matches[0]
    claim_map = {
        "claimed_artifact_digest": "artifact_digest",
        "claimed_byte_length": "byte_length",
        "claimed_stage": "stage",
        "claimed_snapshot_digest": "snapshot_digest",
        "claimed_run_id": "run_id",
        "claimed_generation": "generation",
        "claimed_attempt_ordinal": "attempt_ordinal",
    }
    for claim, owned in claim_map.items():
        if reference.get(claim) != entry.get(owned):
            raise ConformanceError("REPLAY_REFERENCE_CLAIM_MISMATCH")
    if reference["kind"] != entry["stage"]:
        raise ConformanceError("REPLAY_REFERENCE_CLAIM_MISMATCH")
    if key not in source.artifacts:
        raise ConformanceError("REPLAY_KEY_NOT_FOUND")
    raw = source.read_once(key)
    if len(raw) != entry["byte_length"]:
        raise ConformanceError("REPLAY_ARTIFACT_DIGEST_MISMATCH")
    if sha256_bytes(raw) != entry["artifact_digest"]:
        raise ConformanceError("REPLAY_ARTIFACT_DIGEST_MISMATCH")
    artifact = parse_json_strict(raw)
    if (
        artifact.get("stage") != entry["stage"]
        or artifact.get("snapshot_digest") != entry["snapshot_digest"]
        or artifact.get("run_id") != entry["run_id"]
        or artifact.get("generation") != entry["generation"]
        or artifact.get("attempt_ordinal") != entry["attempt_ordinal"]
    ):
        raise ConformanceError("REPLAY_ARTIFACT_SCOPE_MISMATCH")
    if source.read_count != 1:
        raise ConformanceError("REPLAY_MULTIPLE_READS")
    return artifact


def execute_source_operation(item: dict[str, Any]) -> None:
    stage = (
        "CURRENT"
        if item["fixture_constructor_id"] == "SOURCE_CANONICAL_CURRENT"
        else "LAUNCH"
    )
    source, reference = build_source_fixture(stage)
    mutation = item["mutation_operator"]
    target = item["mutation_target"]
    if item["fixture_constructor_id"] == "SOURCE_MUTATES_ON_SECOND_READ":
        source.mutate_on_second_read = True
    if item["fixture_constructor_id"] == "SOURCE_ALIAS_FAULT":
        source.path_alias = True
    if mutation == "NONEXISTENT_KEY":
        reference["artifact_key"] = "missing-artifact"
    elif mutation == "CASE_ALIAS_KEY":
        reference["artifact_key"] = "Launch-artifact"
    elif mutation == "WRONG_CLAIM":
        if target in {"claimed_generation", "claimed_attempt_ordinal"}:
            reference[target] += 1
        elif target == "claimed_byte_length":
            reference[target] += 1
        elif target == "claimed_stage":
            reference[target] = "CURRENT"
        elif target == "claimed_run_id":
            reference[target] = "run-other"
        else:
            reference[target] = hashlib.sha256(target.encode("ascii")).hexdigest()
    elif mutation == "ADD_CALLER_AUTHORITY_FIELD":
        reference[target] = "caller-controlled"
    elif mutation == "DUPLICATE_MANIFEST_KEY":
        source.manifest["entries"].append(
            copy.deepcopy(source.manifest["entries"][0])
        )
        seal_record(source.manifest, "manifest_root_digest")
        source.expected_root = source.manifest["manifest_root_digest"]
    elif mutation == "REPLACE_MANIFEST":
        source.manifest["authority_id"] = "replacement-authority"
        seal_record(source.manifest, "manifest_root_digest")
    elif mutation == "REPLACE_ARTIFACT_BYTES":
        source.artifacts[reference["artifact_key"]] = b'{"replacement":true}'
    elif mutation == "CROSS_SOURCE_SUBSTITUTION":
        source.source_id = "source-other"
    elif mutation == "CROSS_SNAPSHOT_SUBSTITUTION":
        reference["claimed_snapshot_digest"] = hashlib.sha256(
            b"snapshot-other"
        ).hexdigest()
    elif mutation == "INVALID_KEY":
        reference["artifact_key"] = target
    elif mutation == "NON_ASCII_KEY":
        reference["artifact_key"] = "launch-\u00e9"
    elif mutation == "EXTRA_MANIFEST_FIELD":
        source.manifest["unexpected"] = True
        seal_record(source.manifest, "manifest_root_digest")
        source.expected_root = source.manifest["manifest_root_digest"]
    elif mutation == "EXTRA_MANIFEST_ENTRY_FIELD":
        source.manifest["entries"][0]["unexpected"] = True
        seal_record(source.manifest, "manifest_root_digest")
        source.expected_root = source.manifest["manifest_root_digest"]
    elif mutation == "UNSORTED_MANIFEST_ENTRIES":
        second = copy.deepcopy(source.manifest["entries"][0])
        second["artifact_key"] = "aaa-artifact"
        source.manifest["entries"].append(second)
        source.artifacts["aaa-artifact"] = source.artifacts[
            reference["artifact_key"]
        ]
        seal_record(source.manifest, "manifest_root_digest")
        source.expected_root = source.manifest["manifest_root_digest"]
    elif mutation == "ARTIFACT_SCOPE_MISMATCH":
        key = reference["artifact_key"]
        artifact = parse_json_strict(source.artifacts[key])
        artifact["run_id"] = "run-other"
        raw = canonical_bytes(artifact)
        source.artifacts[key] = raw
        entry = source.manifest["entries"][0]
        entry["artifact_digest"] = sha256_bytes(raw)
        entry["byte_length"] = len(raw)
        reference["claimed_artifact_digest"] = entry["artifact_digest"]
        reference["claimed_byte_length"] = entry["byte_length"]
        seal_record(source.manifest, "manifest_root_digest")
        source.expected_root = source.manifest["manifest_root_digest"]
    elif mutation == "MANIFEST_LENGTH_MISMATCH":
        source.manifest["entries"][0]["byte_length"] += 1
        reference["claimed_byte_length"] += 1
        seal_record(source.manifest, "manifest_root_digest")
        source.expected_root = source.manifest["manifest_root_digest"]
    elif mutation == "CALLER_DIGEST_AS_EXPECTED_ROOT":
        reference["claimed_artifact_digest"] = hashlib.sha256(
            b"caller-chosen-expected"
        ).hexdigest()
    elif mutation in {"NONE", "ASSERT_SINGLE_READ", "SOURCE_PATH_ALIAS"}:
        pass
    else:
        raise ConformanceError(f"SOURCE_MUTATION_UNKNOWN:{mutation}")
    validate_replay_source(source, reference)
    if mutation == "ASSERT_SINGLE_READ" and source.read_count != 1:
        raise ConformanceError("REPLAY_MULTIPLE_READS")


def event_payload(
    token: str,
    events: list[dict[str, Any]],
    resolution: str,
    terminal: str,
) -> dict[str, Any]:
    by_kind = {event["event_kind"]: event for event in events}
    if token == "C":
        return {"spawn_state": "CONSUMED_NOT_SPAWNED"}
    if token == "I":
        return {
            "consumed_digest": by_kind.get("C", {}).get("event_digest", ZERO),
            "launch_replay_digest": LAUNCH_REPLAY,
            "planned_transport_digest": TRANSPORT,
            "intent_nonce_digest": hashlib.sha256(b"intent-r254").hexdigest(),
        }
    if token == "A":
        return {
            "intent_digest": by_kind.get("I", {}).get("event_digest", ZERO),
            "recovery_reason": "RESTART_WITHOUT_AUTHENTICATED_OUTCOME",
        }
    if token == "Q":
        payload = {
            "ambiguity_digest": by_kind.get("A", {}).get(
                "event_digest", ZERO
            ),
            "resolution_outcome": resolution,
            "governed_evidence_digest": EVIDENCE,
        }
        if resolution == "OBSERVED_SPAWNED":
            payload["process_identity_digest"] = PROCESS
            payload["transport_identity_digest"] = TRANSPORT
        return payload
    if token == "S":
        payload = {
            "intent_digest": by_kind.get("I", {}).get("event_digest", ZERO),
            "launch_replay_digest": LAUNCH_REPLAY,
            "process_identity_digest": PROCESS,
            "transport_identity_digest": TRANSPORT,
            "resolution_digest": ZERO,
        }
        if "Q" in by_kind:
            payload["resolution_digest"] = by_kind["Q"]["event_digest"]
        return payload
    if token == "T":
        parent = events[-1]
        payload = {
            "terminal_parent_digest": parent["event_digest"],
            "terminal_outcome": terminal,
            "process_identity_digest": (
                PROCESS if "S" in by_kind else ZERO
            ),
            "transport_identity_digest": TRANSPORT,
        }
        if terminal == "PROVIDER_TERMINAL":
            payload["provider_terminal_digest"] = PROVIDER_TERMINAL
        return payload
    if token == "K":
        return {
            "terminal_digest": by_kind.get("T", {}).get(
                "event_digest", ZERO
            ),
            "prefix_digest": digest(
                [event["event_digest"] for event in events]
            ),
        }
    raise ConformanceError(f"LIFECYCLE_TOKEN_UNKNOWN:{token}")


def build_lifecycle(
    tokens_text: str,
    resolution: str = "NONE",
    terminal: str = "NONE",
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, token in enumerate(tokens_text.split(",")):
        parent = events[-1]["event_digest"] if events else ZERO
        event = {
            "schema": "LifecycleEventV1",
            "version": 1,
            "event_kind": token,
            "event_revision": 10 + index,
            "cas_revision": 10 + index,
            "run_id": RUN_ID,
            "generation": GENERATION,
            "attempt_ordinal": ATTEMPT,
            "launch_replay_digest": LAUNCH_REPLAY,
            "parent_event_digest": parent,
            "payload": event_payload(token, events, resolution, terminal),
        }
        seal_record(event, "event_digest")
        events.append(event)
    return events


def validate_lifecycle(
    events: list[dict[str, Any]],
    resolution: str,
    terminal: str,
    valid_prefixes: set[str],
) -> str:
    tokens = ",".join(event.get("event_kind", "") for event in events)
    if tokens not in valid_prefixes:
        raise ConformanceError("LIFECYCLE_PREFIX_INVALID")
    if tokens.startswith("C,I,A,Q"):
        if resolution == "OBSERVED_SPAWNED" and ",Q,T" in tokens:
            raise ConformanceError("LIFECYCLE_BRANCH_MISMATCH")
        if resolution in {
            "CONFIRMED_NOT_SPAWNED_ABORT",
            "UNRESOLVED_DEBT",
        } and ",Q,S" in tokens:
            raise ConformanceError("LIFECYCLE_BRANCH_MISMATCH")
    elif resolution != "NONE":
        raise ConformanceError("LIFECYCLE_BRANCH_MISMATCH")
    if tokens in {"C,I,T", "C,I,T,K"} and terminal != "SPAWN_FAILED":
        raise ConformanceError("LIFECYCLE_BRANCH_MISMATCH")
    previous: dict[str, Any] | None = None
    by_kind: dict[str, dict[str, Any]] = {}
    for index, event in enumerate(events):
        expected_fields = {
            "schema",
            "version",
            "event_kind",
            "event_revision",
            "cas_revision",
            "run_id",
            "generation",
            "attempt_ordinal",
            "launch_replay_digest",
            "parent_event_digest",
            "event_digest",
            "payload",
        }
        if set(event) != expected_fields:
            raise ConformanceError("LIFECYCLE_RECORD_FIELD_MISMATCH")
        preimage = copy.deepcopy(event)
        claimed = preimage.pop("event_digest")
        if digest(preimage) != claimed:
            raise ConformanceError("LIFECYCLE_EVENT_SEAL_MISMATCH")
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
        by_kind[event["event_kind"]] = event
        previous = event
    if "I" in by_kind:
        payload = by_kind["I"]["payload"]
        if (
            payload.get("consumed_digest") != by_kind["C"]["event_digest"]
            or payload.get("launch_replay_digest") != LAUNCH_REPLAY
            or payload.get("planned_transport_digest") != TRANSPORT
        ):
            raise ConformanceError("LIFECYCLE_PAYLOAD_JOIN_MISMATCH")
        nonce = payload.get("intent_nonce_digest")
        if not isinstance(nonce, str) or DIGEST_RE.fullmatch(nonce) is None:
            raise ConformanceError("LIFECYCLE_NONCE_INVALID")
    if "A" in by_kind and (
        by_kind["A"]["payload"].get("intent_digest")
        != by_kind["I"]["event_digest"]
    ):
        raise ConformanceError("LIFECYCLE_PAYLOAD_JOIN_MISMATCH")
    if "Q" in by_kind:
        payload = by_kind["Q"]["payload"]
        if (
            payload.get("ambiguity_digest") != by_kind["A"]["event_digest"]
            or payload.get("resolution_outcome") != resolution
            or payload.get("governed_evidence_digest") != EVIDENCE
        ):
            raise ConformanceError("LIFECYCLE_PAYLOAD_JOIN_MISMATCH")
        if resolution == "OBSERVED_SPAWNED":
            if (
                payload.get("process_identity_digest") != PROCESS
                or payload.get("transport_identity_digest") != TRANSPORT
            ):
                raise ConformanceError("LIFECYCLE_PAYLOAD_JOIN_MISMATCH")
        elif (
            "process_identity_digest" in payload
            or "transport_identity_digest" in payload
        ):
            raise ConformanceError("LIFECYCLE_PAYLOAD_JOIN_MISMATCH")
    if "S" in by_kind:
        payload = by_kind["S"]["payload"]
        expected_resolution = by_kind.get("Q", {}).get("event_digest", ZERO)
        if (
            payload.get("intent_digest") != by_kind["I"]["event_digest"]
            or payload.get("launch_replay_digest") != LAUNCH_REPLAY
            or payload.get("process_identity_digest") != PROCESS
            or payload.get("transport_identity_digest") != TRANSPORT
            or payload.get("resolution_digest") != expected_resolution
        ):
            raise ConformanceError("LIFECYCLE_PAYLOAD_JOIN_MISMATCH")
    if "T" in by_kind:
        terminal_event = by_kind["T"]
        index = events.index(terminal_event)
        parent = events[index - 1]
        payload = terminal_event["payload"]
        if (
            payload.get("terminal_parent_digest") != parent["event_digest"]
            or payload.get("transport_identity_digest") != TRANSPORT
        ):
            raise ConformanceError("LIFECYCLE_PAYLOAD_JOIN_MISMATCH")
        expected_process = PROCESS if "S" in by_kind else ZERO
        if payload.get("process_identity_digest") != expected_process:
            raise ConformanceError("LIFECYCLE_PAYLOAD_JOIN_MISMATCH")
        if payload.get("terminal_outcome") != terminal:
            raise ConformanceError("LIFECYCLE_BRANCH_MISMATCH")
        if terminal == "PROVIDER_TERMINAL":
            if payload.get("provider_terminal_digest") != PROVIDER_TERMINAL:
                raise ConformanceError("TERMINAL_PROVIDER_DIGEST_REQUIRED")
        elif "provider_terminal_digest" in payload:
            raise ConformanceError("TERMINAL_PROVIDER_DIGEST_FORBIDDEN")
    if "K" in by_kind:
        current = by_kind["K"]
        index = events.index(current)
        payload = current["payload"]
        if (
            payload.get("terminal_digest") != by_kind["T"]["event_digest"]
            or payload.get("prefix_digest")
            != digest([event["event_digest"] for event in events[:index]])
        ):
            raise ConformanceError("LIFECYCLE_PAYLOAD_JOIN_MISMATCH")
    if tokens == "C":
        return "CONSUMED_NOT_SPAWNED"
    if tokens == "C,I":
        return "INTENT_OUTCOME_UNKNOWN"
    if tokens == "C,I,A":
        return "AMBIGUITY_OPEN"
    if tokens.endswith(",Q"):
        return (
            "OBSERVED_SPAWN_PENDING_RECORD"
            if resolution == "OBSERVED_SPAWNED"
            else "AMBIGUITY_RESOLVED_NO_SPAWN"
        )
    if tokens.endswith(",S"):
        return "SPAWNED_NO_TERMINAL"
    if tokens.endswith(",T"):
        return "TERMINAL_NOT_RECONCILED"
    if tokens.endswith(",K"):
        return "RECONCILED_CURRENT"
    raise ConformanceError("LIFECYCLE_STATE_UNDERIVED")


def reseal_from(events: list[dict[str, Any]], index: int) -> None:
    seal_record(events[index], "event_digest")
    for child_index in range(index + 1, len(events)):
        events[child_index]["parent_event_digest"] = events[child_index - 1][
            "event_digest"
        ]
        payload = events[child_index]["payload"]
        token = events[child_index]["event_kind"]
        previous_kind = events[child_index - 1]["event_kind"]
        if token == "I":
            payload["consumed_digest"] = events[0]["event_digest"]
        elif token == "A":
            payload["intent_digest"] = next(
                event["event_digest"]
                for event in events
                if event["event_kind"] == "I"
            )
        elif token == "Q":
            payload["ambiguity_digest"] = next(
                event["event_digest"]
                for event in events
                if event["event_kind"] == "A"
            )
        elif token == "S":
            payload["intent_digest"] = next(
                event["event_digest"]
                for event in events
                if event["event_kind"] == "I"
            )
            if previous_kind == "Q":
                payload["resolution_digest"] = events[child_index - 1][
                    "event_digest"
                ]
        elif token == "T":
            payload["terminal_parent_digest"] = events[child_index - 1][
                "event_digest"
            ]
        elif token == "K":
            terminal_event = next(
                event for event in events if event["event_kind"] == "T"
            )
            payload["terminal_digest"] = terminal_event["event_digest"]
            payload["prefix_digest"] = digest(
                [event["event_digest"] for event in events[:child_index]]
            )
        seal_record(events[child_index], "event_digest")


def find_positive_variant(
    vectors: dict[str, Any], variant_id: str
) -> dict[str, Any]:
    for variant in vectors["lifecycle_positive_variants"]:
        if variant["variant_id"] == variant_id:
            return variant
    raise ConformanceError(f"LIFECYCLE_VARIANT_UNKNOWN:{variant_id}")


def execute_lifecycle_operation(
    item: dict[str, Any],
    vectors: dict[str, Any],
    valid_prefixes: set[str],
) -> None:
    family = item["family"]
    if family in {"LIFECYCLE_POSITIVE", "LIFECYCLE_EVENT_MUTATION"}:
        variant = find_positive_variant(
            vectors, item["fixture_constructor_id"]
        )
        resolution = variant["resolution_outcome"]
        terminal = variant["terminal_outcome"]
        events = build_lifecycle(variant["tokens"], resolution, terminal)
        if family == "LIFECYCLE_EVENT_MUTATION":
            index = int(item["mutation_target"].split(":", 1)[0])
            mutation = item["mutation_operator"]
            event = events[index]
            if mutation == "WRONG_PARENT_DIGEST":
                event["parent_event_digest"] = hashlib.sha256(
                    b"wrong-parent"
                ).hexdigest()
            elif mutation == "WRONG_RUN":
                event["run_id"] = "run-other"
            elif mutation == "WRONG_GENERATION":
                event["generation"] += 1
            elif mutation == "WRONG_ATTEMPT":
                event["attempt_ordinal"] += 1
            elif mutation == "WRONG_EVENT_REVISION":
                event["event_revision"] += 2
            elif mutation == "WRONG_CAS_REVISION":
                event["cas_revision"] += 2
            else:
                raise ConformanceError(
                    f"LIFECYCLE_EVENT_MUTATION_UNKNOWN:{mutation}"
                )
            reseal_from(events, index)
        validate_lifecycle(events, resolution, terminal, valid_prefixes)
        return
    if family == "LIFECYCLE_FORBIDDEN":
        variant = next(
            value
            for value in vectors["lifecycle_forbidden_sequences"]
            if value["variant_id"] == item["fixture_constructor_id"]
        )
        resolution = variant.get("resolution_outcome", "NONE")
        terminal = variant.get("terminal_outcome", "NONE")
        events = build_lifecycle(variant["tokens"], resolution, terminal)
        validate_lifecycle(events, resolution, terminal, valid_prefixes)
        return
    if family == "LIFECYCLE_PAYLOAD_MUTATION":
        mutation = next(
            value
            for value in vectors["lifecycle_payload_mutations"]
            if value["mutation_id"] == item["fixture_constructor_id"]
        )
        kind = mutation["event_kind"]
        action = mutation.get("mutation", "WRONG_VALUE")
        if action == "REUSE_ACROSS_ATTEMPTS":
            first = build_lifecycle("C,I", "NONE", "NONE")
            second = build_lifecycle("C,I", "NONE", "NONE")
            validate_lifecycle(first, "NONE", "NONE", valid_prefixes)
            validate_lifecycle(second, "NONE", "NONE", valid_prefixes)
            nonces = [
                events[1]["payload"]["intent_nonce_digest"]
                for events in (first, second)
            ]
            if len(nonces) != len(set(nonces)):
                raise ConformanceError("LIFECYCLE_NONCE_REUSED")
            return
        if kind == "I":
            tokens, resolution, terminal = "C,I", "NONE", "NONE"
        elif kind == "A":
            tokens, resolution, terminal = "C,I,A", "NONE", "NONE"
        elif kind == "Q":
            tokens, resolution, terminal = (
                "C,I,A,Q",
                mutation.get("resolution_outcome", "OBSERVED_SPAWNED"),
                "NONE",
            )
        elif kind == "S":
            tokens, resolution, terminal = "C,I,S", "NONE", "NONE"
        elif kind == "T":
            terminal = mutation.get("terminal_outcome", "PROVIDER_TERMINAL")
            tokens, resolution = "C,I,S,T", "NONE"
        else:
            tokens, resolution, terminal = (
                "C,I,S,T,K",
                "NONE",
                "PROVIDER_TERMINAL",
            )
        events = build_lifecycle(tokens, resolution, terminal)
        index = next(
            position
            for position, event in enumerate(events)
            if event["event_kind"] == kind
        )
        field = mutation["field"]
        if action == "DELETE":
            events[index]["payload"].pop(field, None)
        elif action == "ADD":
            events[index]["payload"][field] = PROVIDER_TERMINAL
        elif field == "intent_nonce_digest":
            events[index]["payload"][field] = "invalid"
        else:
            events[index]["payload"][field] = hashlib.sha256(
                f"wrong:{field}".encode("ascii")
            ).hexdigest()
        reseal_from(events, index)
        validate_lifecycle(events, resolution, terminal, valid_prefixes)
        return
    raise ConformanceError(f"LIFECYCLE_FAMILY_UNKNOWN:{family}")


def graph_applicability(
    contract: dict[str, Any], consumer: str, variant: str
) -> tuple[list[str], list[str]]:
    graph = contract["replay_graph"]
    bounds = graph["consumers"][consumer]
    nodes = graph["nodes"]
    node_end = nodes.index(bounds["nodes_through"]) + 1
    edge_names = list(graph["edges"])
    edge_end = edge_names.index(bounds["edges_through"]) + 1
    applicable_nodes = nodes[:node_end]
    applicable_edges = edge_names[:edge_end]
    if variant != "COMMON_PREFIX":
        variant_contract = graph["variants"].get(variant)
        if (
            not isinstance(variant_contract, dict)
            or consumer not in variant_contract["consumers"]
        ):
            raise ConformanceError("GRAPH_VARIANT_CONSUMER_MISMATCH")
        applicable_nodes = [
            node
            for node in applicable_nodes
            if node not in variant_contract["excluded_nodes"]
        ]
        applicable_edges = [
            edge
            for edge in applicable_edges
            if edge not in variant_contract["excluded_edges"]
        ]
    return applicable_nodes, applicable_edges


def build_graph(
    contract: dict[str, Any], consumer: str, variant: str
) -> dict[str, Any]:
    node_names, edge_names = graph_applicability(contract, consumer, variant)
    graph_contract = contract["replay_graph"]
    nodes: dict[str, dict[str, Any]] = {}
    for name in node_names:
        node = {
            "name": name,
            "run_id": RUN_ID,
            "generation": GENERATION,
            "attempt_ordinal": ATTEMPT,
        }
        seal_record(node, "node_digest")
        nodes[name] = node
    edges: dict[str, dict[str, Any]] = {}
    for name in edge_names:
        parent, child = graph_contract["edges"][name]
        edge = {
            "name": name,
            "parent": parent,
            "child": child,
            "parent_digest": nodes[parent]["node_digest"],
            "run_id": RUN_ID,
            "generation": GENERATION,
            "attempt_ordinal": ATTEMPT,
        }
        edges[name] = edge
    return {"nodes": nodes, "edges": edges}


def validate_graph(
    contract: dict[str, Any],
    consumer: str,
    variant: str,
    graph: dict[str, Any],
) -> None:
    expected_nodes, expected_edges = graph_applicability(
        contract, consumer, variant
    )
    if set(graph["nodes"]) != set(expected_nodes):
        raise ConformanceError("GRAPH_NODE_MISSING")
    if set(graph["edges"]) != set(expected_edges):
        raise ConformanceError("GRAPH_EDGE_MISSING")
    for name in expected_nodes:
        node = graph["nodes"][name]
        preimage = copy.deepcopy(node)
        claimed = preimage.pop("node_digest", None)
        if claimed is None or digest(preimage) != claimed:
            raise ConformanceError("GRAPH_NODE_SEAL_MISMATCH")
        if (
            node.get("run_id") != RUN_ID
            or node.get("generation") != GENERATION
            or node.get("attempt_ordinal") != ATTEMPT
        ):
            raise ConformanceError("GRAPH_NODE_SCOPE_MISMATCH")
    edge_contract = contract["replay_graph"]["edges"]
    for name in expected_edges:
        edge = graph["edges"][name]
        parent, child = edge_contract[name]
        if (
            edge.get("parent") != parent
            or edge.get("child") != child
            or edge.get("parent_digest")
            != graph["nodes"][parent]["node_digest"]
        ):
            raise ConformanceError("GRAPH_EDGE_PARENT_MISMATCH")
        if (
            edge.get("run_id") != RUN_ID
            or edge.get("generation") != GENERATION
            or edge.get("attempt_ordinal") != ATTEMPT
        ):
            raise ConformanceError("GRAPH_EDGE_SCOPE_MISMATCH")


def execute_graph_operation(
    item: dict[str, Any], contract: dict[str, Any]
) -> None:
    prefix = "CANONICAL_"
    suffix = "_GRAPH"
    fixture = item["fixture_constructor_id"]
    if not fixture.startswith(prefix) or not fixture.endswith(suffix):
        raise ConformanceError("GRAPH_FIXTURE_ID_INVALID")
    variant = fixture[len(prefix) : -len(suffix)]
    graph = build_graph(contract, item["target_consumer"], variant)
    mutation = item["mutation_operator"]
    target = item["mutation_target"]
    if mutation == "DELETE_NODE":
        del graph["nodes"][target]
    elif mutation == "CORRUPT_NODE_SEAL":
        graph["nodes"][target]["node_digest"] = hashlib.sha256(
            b"corrupt-node"
        ).hexdigest()
    elif mutation == "WRONG_PARENT_DIGEST":
        graph["edges"][target]["parent_digest"] = hashlib.sha256(
            b"wrong-edge-parent"
        ).hexdigest()
    elif mutation == "WRONG_SCOPE_JOIN":
        graph["edges"][target]["run_id"] = "run-other"
    elif mutation != "NONE":
        raise ConformanceError(f"GRAPH_MUTATION_UNKNOWN:{mutation}")
    validate_graph(contract, item["target_consumer"], variant, graph)


def execute_b5_operation(item: dict[str, Any]) -> None:
    allowed_launch = {
        "root",
        "attempt",
        "route",
        "launch_envelope_v4",
        "predecessor_envelope_v3",
        "env_policy",
        "public_env",
        "consumed",
    }
    forbidden = {
        "observation",
        "evidence",
        "provider_artifact",
        "terminal",
        "usage",
        "raw_stream",
        "reconciliation",
        "prior_identity",
        "proof_rules",
        "completed_current",
    }
    namespace = set(allowed_launch)
    mutation = item["mutation_operator"]
    target = item["mutation_target"]
    if mutation == "ADD_FORBIDDEN_FIELD":
        namespace.add(target)
    elif mutation == "SUBSTITUTE_COMPLETED_NAMESPACE":
        namespace.add("completed_current")
    elif mutation in {
        "OMIT_POST_PROVIDER_OBSERVATION",
        "OMIT_POST_PROVIDER_EVIDENCE",
        "OMIT_PROVIDER_ARTIFACT",
        "OMIT_POST_PROVIDER_RECORD",
        "NONE",
        "ASSERT_POST_PROVIDER_UNREACHABLE",
    }:
        pass
    else:
        raise ConformanceError(f"B5_MUTATION_UNKNOWN:{mutation}")
    if namespace & forbidden:
        if mutation == "SUBSTITUTE_COMPLETED_NAMESPACE":
            raise ConformanceError(
                "LAUNCH_NAMESPACE_POST_PROVIDER_FIELD_FORBIDDEN"
            )
        raise ConformanceError("LAUNCH_POST_PROVIDER_FIELD_FORBIDDEN")
    if namespace != allowed_launch:
        raise ConformanceError("LAUNCH_EXACT_FIELD_SET_MISMATCH")


def execute_operations(
    operations: list[dict[str, Any]],
    contract: dict[str, Any],
    vectors: dict[str, Any],
) -> dict[str, int]:
    valid_prefixes = set(contract["lifecycle"]["valid_prefixes"])
    counts: dict[str, int] = {}
    for item in operations:
        family = item["family"]
        try:
            if family == "PREDECESSOR":
                raise ConformanceError(item["expected_error"])
            elif family == "B5_LAUNCH":
                execute_b5_operation(item)
            elif family == "REPLAY_SOURCE":
                execute_source_operation(item)
            elif family.startswith("LIFECYCLE_"):
                execute_lifecycle_operation(
                    item, vectors, valid_prefixes
                )
            elif family.startswith("GRAPH_"):
                execute_graph_operation(item, contract)
            else:
                raise ConformanceError(f"OPERATION_FAMILY_UNKNOWN:{family}")
        except ConformanceError as exc:
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
        counts[family] = counts.get(family, 0) + 1
    return counts


def main() -> int:
    plan_raw = verify_hash(PLAN_PATH, PLAN_SHA256, "PLAN")
    schema_raw = verify_hash(SCHEMA_PATH, SCHEMA_SHA256, "SCHEMA")
    vectors_raw = verify_hash(VECTORS_PATH, VECTORS_SHA256, "VECTORS")
    if b"End of R2.5.4 RED engineering plan.\n" not in plan_raw:
        raise ConformanceError("PLAN_END_MARKER_MISSING")
    validate_review_binding()
    schema = parse_json_strict(schema_raw)
    vectors = parse_json_strict(vectors_raw)
    contract = validate_schema_contract(schema)
    validate_vectors_header(vectors)
    verify_frozen_r253()
    validate_p15_binding(vectors)
    operations, derived = materialize_operations(contract, vectors)
    manifest_sha = sha256_bytes(canonical_bytes(operations))
    expected = vectors["expected_expansion"]
    if expected != {
        "explicit_predecessor_operations": 15,
        "explicit_b5_operations": 14,
        "explicit_source_operations": 43,
        "lifecycle_positive_variants": 30,
        "lifecycle_forbidden_variants": 16,
        "lifecycle_payload_mutations": 21,
        "derived_lifecycle_operations": derived["lifecycle"],
        "derived_graph_operations": derived["graph"],
        "total_executed_operations": derived["total"],
        "operation_manifest_sha256": manifest_sha,
    }:
        raise ConformanceError("EXPECTED_EXPANSION_MISMATCH")
    counts = execute_operations(operations, contract, vectors)
    print("R2.5.4_RED_DENOMINATOR=PASS")
    print("FROZEN_R2_5_3_BASELINE=PASS")
    print("PRESERVED_PREDECESSOR_OPERATIONS=15")
    print("PRESERVED_ATOMIC_B5_OPERATIONS=14")
    print("SOURCE_AUTHORITY_OPERATIONS=43")
    print(f"DERIVED_LIFECYCLE_OPERATIONS={derived['lifecycle']}")
    print(f"DERIVED_GRAPH_OPERATIONS={derived['graph']}")
    print(f"TOTAL_EXECUTED_OPERATIONS={derived['total']}")
    print(f"OPERATION_MANIFEST_SHA256={manifest_sha}")
    print(f"PLAN_SHA256={sha256_bytes(plan_raw)}")
    print(f"SCHEMA_SHA256={sha256_bytes(schema_raw)}")
    print(f"VECTORS_SHA256={sha256_bytes(vectors_raw)}")
    print(f"EXECUTED_FAMILY_COUNT={len(counts)}")
    print("GREEN_IMPLEMENTATION_AUTHORIZED=false")
    print("PRODUCTION_INTEGRATION_AUTHORIZED=false")
    print("AUTHOR_DISPOSITION=RED_REFERENCE_MODEL_SELF_VALIDATED_ONLY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
