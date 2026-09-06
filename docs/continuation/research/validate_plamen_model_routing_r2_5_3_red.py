from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable


HERE = Path(__file__).resolve().parent
PLAN_PATH = (
    HERE
    / "Plamen_Backend_Model_Routing_R2.5.3_RED_Engineering_Plan_2026-07-30.md"
)
VECTORS_PATH = (
    HERE
    / "Plamen_Backend_Model_Routing_R2.5.3_RED_Fixture_Denominator_2026-07-30.json"
)
R252_PATH = HERE / "validate_plamen_model_routing_r2_5_2.py"
REVIEW_PATH = (
    HERE.parent
    / "plamen-codex-implementation"
    / "review_fixtures"
    / "backend_model_routing_r2_5_2_independent_review_r1_20260730.md"
)
PLAN_SHA256 = (
    "2eb28c18564dae8acc636b8de41a3a2b240ae03375c22f224a23eedcec9797cf"
)
VECTORS_SHA256 = (
    "8a0dbcfbf4ee7d7a1b9e141196890af9a17bb322be94ed832a9873c765ec0cb6"
)
R252_SHA256 = (
    "54308ee13491bf43ab006d65b11bb4c60e70f620d17eb8b209288ef2ac5a785c"
)
REVIEW_BODY_SHA256 = (
    "4a1757a50169d7bd003e20e4a2b03ce085679f35fa6e75c8250d0ec79e8528b9"
)
REVIEW_WHOLE_SHA256 = (
    "0bca91a40d52b14ab2bac0147da599afe45a06d40cc79090cb2bde844aa2db57"
)
R252_EXPECTED = {
    "R2.5.2_CONFORMANCE=PASS",
    "R2_5_1_PRESERVED_EXECUTED_DENOMINATOR=646",
    "R2_5_2_NEW_VECTORS=40",
    "TOTAL_EXECUTED_VECTOR_DENOMINATOR=686",
    "AUTHOR_HARDENING_PROBES=12",
    "SCHEMA_SHA256=23795b1620168ca94a7f9a65ab4136243a33c72027a7bf7a217a1911c14b1e02",
    "VECTORS_SHA256=ecbc628d257b09bc0ec343d2c525be14b6f5864b680e809dc282559eca2845b1",
    "BLOCKERS_CLOSED=B1,B2,B3,B4",
    "AUTHOR_DISPOSITION=SELF_VALIDATED_NOT_INDEPENDENT_PASS",
}


class RedFixtureError(Exception):
    pass


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_ascii_lf(path: Path) -> bytes:
    raw = path.read_bytes()
    if not raw or not raw.endswith(b"\n"):
        raise RedFixtureError("FINAL_LF_REQUIRED")
    if b"\r" in raw:
        raise RedFixtureError("CR_BYTE_FORBIDDEN")
    if not raw.isascii():
        raise RedFixtureError("NON_ASCII_PACKAGE")
    return raw


def parse_json_strict(raw: bytes) -> Any:
    def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise RedFixtureError(f"DUPLICATE_JSON_KEY:{key}")
            result[key] = value
        return result

    def reject_nonfinite_constant(value: str) -> Any:
        raise RedFixtureError(f"NONFINITE_JSON_NUMBER:{value}")

    try:
        return json.loads(
            raw.decode("ascii"),
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_nonfinite_constant,
        )
    except RedFixtureError:
        raise
    except Exception as exc:
        raise RedFixtureError("R2_5_3_RED_VECTOR_JSON_INVALID") from exc


def import_exact(path: Path, expected: str, name: str) -> Any:
    if sha256_bytes(path.read_bytes()) != expected:
        raise RedFixtureError(f"{name.upper()}_HASH_MISMATCH")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RedFixtureError(f"{name.upper()}_IMPORT_FAILED")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_review_binding() -> None:
    raw = read_ascii_lf(REVIEW_PATH)
    if sha256_bytes(raw) != REVIEW_WHOLE_SHA256:
        raise RedFixtureError("R2_5_2_REVIEW_WHOLE_HASH_MISMATCH")
    marker = b"\n## Artifact integrity\n"
    position = raw.rfind(marker)
    if position < 0:
        raise RedFixtureError("R2_5_2_REVIEW_BODY_BOUNDARY_MISSING")
    body = raw[:position]
    if sha256_bytes(body) != REVIEW_BODY_SHA256:
        raise RedFixtureError("R2_5_2_REVIEW_BODY_HASH_MISMATCH")
    required = (
        b"operations = 15\nrejected = 15\nunexpected accepts = 0",
        b"R2.5.2 fresh focused operations: BLOCK (5/8 unexpected accepts)",
        b"causal launch/current separation: FAIL",
        b"authenticated spawned transition: ABSENT",
        b"reflective launch/current capability safety: FAIL",
    )
    if any(fragment not in body for fragment in required):
        raise RedFixtureError("R2_5_2_REVIEW_EVIDENCE_MISMATCH")


def validate_manifest(vectors: dict[str, Any]) -> list[dict[str, Any]]:
    if (
        vectors.get("schema")
        != "plamen.model-routing-r2.5.3-red-fixture-denominator.v1"
        or vectors.get("version") != 1
        or vectors.get("disposition")
        != "RED_PLAN_DENOMINATOR_ONLY_INDEPENDENT_ACCEPTANCE_REQUIRED"
    ):
        raise RedFixtureError("R2_5_3_RED_VECTOR_SCHEMA_MISMATCH")
    review = vectors.get("blocking_review", {})
    if (
        review.get("body_sha256") != REVIEW_BODY_SHA256
        or review.get("whole_sha256") != REVIEW_WHOLE_SHA256
        or review.get("focused_operations") != 8
        or review.get("unexpected_accepts") != 5
        or review.get("root_defects")
        != [
            "B5_FALSE_PRE_PROVIDER_LAUNCH_SEPARATION",
            "B6_NO_AUTHENTICATED_SPAWNED_TRANSITION",
            "B7_REFLECTIVE_ISSUANCE_AND_INCOMPLETE_CONSUMER_VALIDATION",
        ]
    ):
        raise RedFixtureError("R2_5_3_RED_REVIEW_BINDING_MISMATCH")
    frozen = vectors.get("frozen_r2_5_2", {})
    if (
        frozen.get("validator_sha256") != R252_SHA256
        or frozen.get("vectors_sha256")
        != "ecbc628d257b09bc0ec343d2c525be14b6f5864b680e809dc282559eca2845b1"
        or frozen.get("executed_denominator") != 686
    ):
        raise RedFixtureError("R2_5_3_RED_PREDECESSOR_BINDING_MISMATCH")
    denominator = vectors.get("denominator", {})
    if denominator != {
        "preservation": 15,
        "B5": 10,
        "B6": 13,
        "B7": 10,
        "new_causal_rows": 33,
        "total_rows": 48,
    }:
        raise RedFixtureError("R2_5_3_RED_DENOMINATOR_MISMATCH")
    rows = vectors.get("rows")
    if not isinstance(rows, list) or len(rows) != 48:
        raise RedFixtureError("R2_5_3_RED_ROW_COUNT_MISMATCH")
    if [row.get("id") for row in rows] != [
        f"R2.5.3-RED-{number:03d}" for number in range(1, 49)
    ]:
        raise RedFixtureError("R2_5_3_RED_ROW_ID_MISMATCH")
    if len({row.get("scenario") for row in rows}) != 48:
        raise RedFixtureError("R2_5_3_RED_SCENARIO_DUPLICATE")
    blockers = (
        ["P15"] * 15 + ["B5"] * 10 + ["B6"] * 13 + ["B7"] * 10
    )
    if [row.get("blocker") for row in rows] != blockers:
        raise RedFixtureError("R2_5_3_RED_PARTITION_MISMATCH")
    for row in rows:
        if set(row) != {
            "id",
            "blocker",
            "scenario",
            "r2_5_2_observation",
            "green_expected",
            "contract",
        }:
            raise RedFixtureError("R2_5_3_RED_ROW_FIELD_MISMATCH")
    authorizations = vectors.get("authorizations", {})
    if not authorizations or any(authorizations.values()):
        raise RedFixtureError("R2_5_3_RED_AUTHORIZATION_MISMATCH")
    return rows


def verify_frozen_r252() -> Any:
    r252 = import_exact(R252_PATH, R252_SHA256, "r252_red")
    completed = subprocess.run(
        [sys.executable, "-I", str(R252_PATH)],
        cwd=str(HERE),
        check=False,
        capture_output=True,
        text=True,
        timeout=240,
    )
    if completed.returncode != 0:
        raise RedFixtureError("R2_5_2_PRESERVATION_EXECUTION_FAILED")
    if set(completed.stdout.splitlines()) != R252_EXPECTED:
        raise RedFixtureError("R2_5_2_PRESERVATION_OUTPUT_MISMATCH")
    return r252


def expect_reject(
    operation: Callable[[], Any], accepted_errors: tuple[str, ...]
) -> str:
    try:
        operation()
    except Exception as exc:
        text = str(exc)
        if text not in accepted_errors:
            raise RedFixtureError(
                f"UNEXPECTED_BASELINE_REJECTION:{text}"
            ) from exc
        return text
    raise RedFixtureError("BASELINE_UNEXPECTEDLY_PASSED")


def build_context(r252: Any) -> tuple[Any, Any, Any, dict[str, Any]]:
    r251 = r252.import_exact(
        r252.R251_PATH, r252.R251_SHA256, "r251_red"
    )
    r25 = r251.verify_frozen_r25()
    r23, r24 = r25.verify_frozen_denominators()
    bundle = r25.parse_json(r252.SCHEMA_PATH.read_bytes())
    context = r252.build_context(bundle, r251, r25, r23, r24)
    return r251, r25, bundle, context


def forge_launch_with_stale_route(
    r252: Any,
    r25: Any,
    context: dict[str, Any],
) -> Any:
    original = context["launch_closure"]
    records = r25.parse_json(original._records_bytes)
    records["route"]["requested_effort"] = "medium"
    try:
        r25.verify_seal(records["route"], "model_route_digest")
    except Exception as exc:
        if str(exc) != "RECORD_SELF_DIGEST_MISMATCH":
            raise
    else:
        raise RedFixtureError("STALE_LAUNCH_ROUTE_CONTROL_FAILED")
    return r252.ValidatedLaunchClosureCapabilityV2(
        r252._LAUNCH_CLOSURE_ISSUER,
        records_bytes=r25.canonical_bytes(records),
        store_snapshot_digest=original._store_snapshot_digest,
        current_run_digest=original._current_run_digest,
        run_id=original._run_id,
        generation=original._generation,
        attempt_ordinal=original._attempt_ordinal,
    )


def forge_current_with_stale_route(
    r252: Any,
    r25: Any,
    context: dict[str, Any],
) -> tuple[Any, dict[str, Any]]:
    original = context["closure"]
    records = r25.parse_json(original._records_bytes)
    records["route"]["requested_effort"] = "medium"
    try:
        r25.verify_seal(records["route"], "model_route_digest")
    except Exception as exc:
        if str(exc) != "RECORD_SELF_DIGEST_MISMATCH":
            raise
    else:
        raise RedFixtureError("STALE_CURRENT_ROUTE_CONTROL_FAILED")
    capability = r252.ValidatedCurrentClosureCapabilityV2(
        r252._CLOSURE_ISSUER,
        records_bytes=r25.canonical_bytes(records),
        artifact_bytes=original._artifact_bytes,
        neutral_bytes=original._neutral_bytes,
        reconciliation_bytes=original._reconciliation_bytes,
        store_snapshot_digest=original._store_snapshot_digest,
        current_run_digest=original._current_run_digest,
        run_id=original._run_id,
        generation=original._generation,
        attempt_ordinal=original._attempt_ordinal,
    )
    return capability, records


def validate_red_baseline(r252: Any) -> tuple[int, int]:
    r251, r25, bundle, context = build_context(r252)
    launch_without_observation = copy.deepcopy(
        context["launch_candidate"]
    )
    del launch_without_observation["observation"]
    first = expect_reject(
        lambda: r252.validate_and_mint_launch_closure_v252(
            bundle,
            r251,
            r25,
            launch_without_observation,
            context["store"],
        ),
        ("'observation'", "observation"),
    )
    launch_without_evidence = copy.deepcopy(
        context["launch_candidate"]
    )
    del launch_without_evidence["evidence"]
    second = expect_reject(
        lambda: r252.validate_and_mint_launch_closure_v252(
            bundle,
            r251,
            r25,
            launch_without_evidence,
            context["store"],
        ),
        ("'evidence'", "evidence"),
    )
    if not first or not second:
        raise RedFixtureError("B5_BASELINE_REJECTION_MISSING")

    forged_launch = forge_launch_with_stale_route(r252, r25, context)
    r252.validate_launch_capability(
        bundle, r251, r25, forged_launch, context["store"]
    )
    launch_records, _run = r252.validate_launch_capability(
        bundle, r251, r25, forged_launch, context["store"]
    )
    proof = r252.mint_proof_from_capability_v252(
        bundle,
        r251,
        r25,
        forged_launch,
        context["store"],
        launch_records["env_policy"],
        launch_records["consumed"],
        context["raw_env"],
        context["process_nonce"],
        context["object_nonce"],
        context["key"],
    )
    r252.authenticate_spawn_from_capability_v252(
        bundle,
        r251,
        r25,
        forged_launch,
        context["store"],
        proof,
        launch_records["env_policy"],
        launch_records["consumed"],
        context["raw_env"],
        context["process_nonce"],
        context["object_nonce"],
        context["key"],
    )

    forged_current, current_records = forge_current_with_stale_route(
        r252, r25, context
    )
    r252.validate_closure_capability(
        bundle, r251, r25, forged_current, context["store"]
    )
    prior_record, before = r251.load_prior_resume_identity(
        bundle, r25, context["store"]
    )
    after = r25.resume_identity(current_records)
    authority = r25.resume_authority(
        before,
        after,
        "NEW_GENERATION",
        prior_generation=prior_record["generation"],
        current_generation=prior_record["generation"] + 1,
        prior_attempt=prior_record["attempt_ordinal"],
        current_attempt=0,
    )
    r252.validate_resume_v252(
        bundle,
        r251,
        r25,
        authority,
        forged_current,
        context["store"],
        None,
        None,
    )

    spawned = copy.deepcopy(context["records_v252"]["consumed"])
    spawned["spawn_state"] = "SPAWNED"
    r25.seal(spawned, "consumed_launch_digest")
    expect_reject(
        lambda: r25.schema_validate(
            bundle, "ConsumedAttemptLaunchAuthorityV2", spawned
        ),
        ("SCHEMA_VALIDATION_ERROR",),
    )
    return 5, 8


def validate_static_red_shape(r252: Any) -> None:
    source = read_ascii_lf(R252_PATH).decode("ascii")
    required = (
        "_LAUNCH_CLOSURE_ISSUER = object()",
        "_CLOSURE_ISSUER = object()",
        "_LAUNCH_CLOSURE_REGISTRY",
        "_CLOSURE_REGISTRY",
        "records = r251.validate_closure_v251(",
        'records["consumed"]["spawn_state"] != "CONSUMED_NOT_SPAWNED"',
    )
    if any(fragment not in source for fragment in required):
        raise RedFixtureError("R2_5_2_STATIC_RED_SHAPE_MISMATCH")
    forbidden_successor = (
        "class SpawnIntentAuthorityV1",
        "class SpawnedAttemptAuthorityV1",
        "class ReplayAuthoritySource",
        "def validate_launch_replay",
        "def validate_current_replay",
    )
    if any(fragment in source for fragment in forbidden_successor):
        raise RedFixtureError("R2_5_2_UNEXPECTED_GREEN_API_PRESENT")
    if not hasattr(r252, "_LAUNCH_CLOSURE_ISSUER") or not hasattr(
        r252, "_CLOSURE_ISSUER"
    ):
        raise RedFixtureError("R2_5_2_REFLECTIVE_ISSUER_SHAPE_MISMATCH")


def main() -> int:
    plan_raw = read_ascii_lf(PLAN_PATH)
    vectors_raw = read_ascii_lf(VECTORS_PATH)
    if sha256_bytes(plan_raw) != PLAN_SHA256:
        raise RedFixtureError("R2_5_3_RED_PLAN_HASH_MISMATCH")
    if sha256_bytes(vectors_raw) != VECTORS_SHA256:
        raise RedFixtureError("R2_5_3_RED_VECTORS_HASH_MISMATCH")
    validate_review_binding()
    vectors = parse_json_strict(vectors_raw)
    rows = validate_manifest(vectors)
    r252 = verify_frozen_r252()
    validate_static_red_shape(r252)
    accepts, operations = validate_red_baseline(r252)
    if accepts != 5 or operations != 8:
        raise RedFixtureError("R2_5_3_RED_BASELINE_COUNT_MISMATCH")
    print("R2.5.3_RED_DENOMINATOR=PASS")
    print("FROZEN_R2_5_2_EXECUTED_DENOMINATOR=686")
    print("PRESERVED_PREDECESSOR_REPLAY_ROWS=15")
    print("NEW_CAUSAL_RED_ROWS=33")
    print(f"TOTAL_DECLARED_RED_ROWS={len(rows)}")
    print(f"R2_5_2_FOCUSED_UNEXPECTED_ACCEPTS={accepts}/{operations}")
    print(f"PLAN_SHA256={PLAN_SHA256}")
    print(f"VECTORS_SHA256={VECTORS_SHA256}")
    print("GREEN_IMPLEMENTATION_AUTHORIZED=false")
    print("PRODUCTION_INTEGRATION_AUTHORIZED=false")
    print("AUTHOR_DISPOSITION=RED_BASELINE_SELF_VALIDATED_ONLY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
