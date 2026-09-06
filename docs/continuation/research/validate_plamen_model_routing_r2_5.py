from __future__ import annotations

import copy
import hashlib
import hmac
import importlib.util
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError


HERE = Path(__file__).resolve().parent
SCHEMA_PATH = HERE / "Plamen_Backend_Model_Routing_R2.5_Schemas_2026-07-30.json"
VECTORS_PATH = HERE / "Plamen_Backend_Model_Routing_R2.5_Conformance_Vectors_2026-07-30.json"
R2_3_VALIDATOR_PATH = HERE / "validate_plamen_model_routing_r2_3.py"
R2_4_VALIDATOR_PATH = HERE / "validate_plamen_model_routing_r2_4.py"
REVIEW_PATH = (
    HERE.parent
    / "plamen-codex-implementation"
    / "review_fixtures"
    / "backend_model_routing_r2_4_independent_review_r1_20260730.md"
)

SCHEMA_SHA256 = (
    "2ff6c92d1d965fef45f539b2102a949c7da66652d7ea4288ee17f29d35dd4806"
)
VECTORS_SHA256 = (
    "51ffcb40264984033f0150f07f737a01a0077733dd4acdf58a3746fc01fda0ac"
)
REVIEW_DECLARED_MANIFEST_SHA256 = (
    "61981cac2042e9c7854737e6de759ef6fae2f3fe7ad405f721b431e8dbceabca"
)
REVIEW_RECOMPUTED_MANIFEST_SHA256 = (
    "fad68edc4f82e09c0eed8d5bc1139e389e32c70f14efa783bb419d93bcbf8f9b"
)
REVIEW_WHOLE_SHA256 = (
    "40c3468e08a5a615295e93e9189c7a53eb7af668a49f48e45a834aa55c1e06b8"
)
REVIEW_BODY_SHA256 = (
    "0d076d5f78947fdcf9fba9dcd8c451cbf4226d5121fad9323191b30fe9f2f207"
)
R2_3_VALIDATOR_SHA256 = (
    "584fbc05a60929a761a1987928a8d97eb1931593d2c8445c42d3c622eb938581"
)
R2_3_EXPECTED_OUTPUT = {
    "R2.3_CONFORMANCE=PASS",
    "TOTAL_VECTORS=186",
    "CANONICAL_VECTORS=10",
    "SCHEMA_VECTORS=59",
    "JOINS_VECTORS=91",
    "TRANSACTIONS_VECTORS=18",
    "CANARY_VECTORS=8",
    "SCHEMA_SHA256=1da3f14c3e18325e818e3236cd1907a87f3032bbdeca5957fdc6fdfd1c0bedcf",
    "VECTORS_SHA256=6e9e0db8df0727dd37c78483151e62bd041f8951a1ddcf0d7698f367cd37d625",
}
R2_4_FILES = {
    "Plamen_Backend_Model_Routing_Engineering_Guide_R2.4_2026-07-29.md":
        "065d094e562bcc09a1c720ed7a22ffb666bdc4aa015d745c7c2617dc9fe48a17",
    "Plamen_Backend_Model_Routing_R2.4_Schemas_2026-07-29.json":
        "1d8895bbfbda3d44c5dd58acf3df029b700664b9bca9e1986dbc8d83dbcc4381",
    "Plamen_Backend_Model_Routing_R2.4_Conformance_Vectors_2026-07-29.json":
        "e046e589cf830ba31fa608ab0ec2c650e2aff555f1fe2a5698f261f12f2079c9",
    "validate_plamen_model_routing_r2_4.py":
        "47c0d70771abe13713d7bd2cf6e87773ae1ea30eab755da712a789d8ec42ff87",
    "Plamen_Backend_Model_Routing_R2.4_Validation_Receipt_2026-07-29.json":
        "467f64365cd68c5cdf7ca09956d33a0553084e0266a014139c3a4a9184a3e02a",
}
R2_4_EXPECTED_OUTPUT = {
    "R2.4_CONFORMANCE=PASS",
    "R2_3_PRESERVED_VECTORS=186",
    "R2_4_NEW_VECTORS=128",
    "TOTAL_VECTORS=314",
    "SCHEMA_SHA256=1d8895bbfbda3d44c5dd58acf3df029b700664b9bca9e1986dbc8d83dbcc4381",
    "VECTORS_SHA256=e046e589cf830ba31fa608ab0ec2c650e2aff555f1fe2a5698f261f12f2079c9",
    "AUTHOR_DISPOSITION=SELF_VALIDATED_NOT_INDEPENDENT_PASS",
}
MAX_SAFE_INT = 9007199254740991
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
EXACT_MODEL_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*-[0-9]{8}$")
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
PROOF_DOMAIN = b"plamen.ephemeral-secret-proof.v2\x00"
EVIDENCE_FIELD_AUTHORITY_DIGEST = hashlib.sha256(
    b"plamen.provider-evidence-field-authority.v1"
).hexdigest()
SECRET_PROOF_POLICY_DIGEST = hashlib.sha256(
    b"plamen.secret-proof-policy.v1"
).hexdigest()
IDENTITY_FIELDS = [
    "backend_identity",
    "routing_profile_identity",
    "transport_identity",
    "assurance_identity",
    "semantic_plan_identity",
    "arm_family_identity",
    "model_identity",
    "effort_identity",
    "thinking_identity",
    "account_identity",
    "auth_identity",
    "service_identity",
    "fallback_identity",
    "public_environment_identity",
    "environment_policy_identity",
    "source_identity",
    "prompt_identity",
    "methodology_identity",
    "program_facts_identity",
    "tools_identity",
    "profile_semantics_identity",
    "profile_identity",
    "capability_authority_identity",
    "price_authority_identity",
    "context_budget_identity",
    "budget_authority_identity",
    "family_grant_identity",
    "work_plan_identity",
    "phase_io_identity",
    "output_contract_identity",
    "loaded_customization_identity",
    "effort_authority_identity",
    "thinking_authority_identity",
]
IDENTITY_LABELS = {
    field: field.removesuffix("_identity") for field in IDENTITY_FIELDS
}
PROFILE_MATRIX = {
    "adjudication_staged_write": (
        "ADJUDICATION_STAGED_WRITE",
        ["Read", "Write"],
        "DENY",
        "STAGED_WRITE_ASSIGNED_SCOPE",
        "WORKER_FILE_OUTPUTS",
    ),
    "analysis_filesystem": (
        "ANALYSIS_FILESYSTEM",
        ["Bash", "Edit", "Glob", "Grep", "Read", "Write"],
        "PHASE_EXPLICIT_ONLY",
        "ANALYSIS_ASSIGNED_SCOPE",
        "WORKER_FILE_OUTPUTS",
    ),
    "analysis_read_only": (
        "ANALYSIS_READ_ONLY",
        ["Glob", "Grep", "Read"],
        "DENY",
        "READ_ONLY_ASSIGNED_SCOPE",
        "WORKER_FILE_OUTPUTS",
    ),
    "stdout_json_no_tools": (
        "STDOUT_JSON_NO_TOOLS",
        [],
        "DENY",
        "NO_MODEL_FILESYSTEM",
        "CLAUDE_STREAM_RESULT_ASSIGNED_OUTPUT",
    ),
}


class ConformanceError(Exception):
    pass


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def d(ch: str) -> str:
    return ch * 64


def read_ascii_lf(path: Path) -> bytes:
    raw = path.read_bytes()
    if not raw or not raw.endswith(b"\n"):
        raise ConformanceError("FINAL_LF_REQUIRED")
    if b"\r" in raw:
        raise ConformanceError("CR_BYTE_FORBIDDEN")
    if any(byte > 0x7F for byte in raw):
        raise ConformanceError("NON_ASCII_PACKAGE")
    return raw


def parse_json(raw: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ConformanceError("DUPLICATE_OBJECT_MEMBER")
            result[key] = value
        return result

    def integer(text: str) -> int:
        if text == "-0":
            raise ConformanceError("NEGATIVE_ZERO_FORBIDDEN")
        value = int(text)
        if value < 0 or value > MAX_SAFE_INT:
            raise ConformanceError("INTEGER_OUT_OF_RANGE")
        return value

    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ConformanceError("NON_ASCII_PACKAGE") from exc
    return json.loads(
        text,
        object_pairs_hook=pairs,
        parse_int=integer,
        parse_float=lambda _x: (_ for _ in ()).throw(
            ConformanceError("FLOAT_FORBIDDEN")
        ),
        parse_constant=lambda _x: (_ for _ in ()).throw(
            ConformanceError("NON_FINITE_FORBIDDEN")
        ),
    )


def check_value(value: Any) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if value < 0 or value > MAX_SAFE_INT:
            raise ConformanceError("INTEGER_OUT_OF_RANGE")
        return
    if isinstance(value, float):
        raise ConformanceError("FLOAT_FORBIDDEN")
    if isinstance(value, str):
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
            raise ConformanceError("LONE_SURROGATE_FORBIDDEN")
        return
    if isinstance(value, list):
        for item in value:
            check_value(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise ConformanceError("NON_ASCII_MEMBER_NAME")
            check_value(item)
        return
    raise ConformanceError("UNSUPPORTED_CANONICAL_TYPE")


def canonical_bytes(value: Any) -> bytes:
    check_value(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def seal(record: dict[str, Any], field: str) -> dict[str, Any]:
    candidate = copy.deepcopy(record)
    candidate.pop(field, None)
    record[field] = sha256_bytes(canonical_bytes(candidate))
    return record


def verify_seal(record: dict[str, Any], field: str) -> None:
    expected = record.get(field)
    candidate = copy.deepcopy(record)
    candidate.pop(field, None)
    if expected != sha256_bytes(canonical_bytes(candidate)):
        raise ConformanceError("RECORD_SELF_DIGEST_MISMATCH")


def classify_schema_error(error: Any) -> str:
    if error.validator == "required":
        return "SCHEMA_REQUIRED_FIELD"
    if error.validator == "additionalProperties":
        return "SCHEMA_UNKNOWN_FIELD"
    return "SCHEMA_VALIDATION_ERROR"


def schema_validate(
    bundle: dict[str, Any], definition: str, record: dict[str, Any]
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
        raise ConformanceError(classify_schema_error(errors[0]))


def expect_error(call: Callable[[], Any], expected: str) -> None:
    try:
        call()
    except ConformanceError as exc:
        if str(exc) != expected:
            raise ConformanceError(f"EXPECTED_{expected}_GOT_{exc}") from exc
        return
    raise ConformanceError(f"EXPECTED_{expected}_BUT_PASSED")


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


def verify_frozen_denominators() -> tuple[Any, Any]:
    r23 = import_exact(R2_3_VALIDATOR_PATH, R2_3_VALIDATOR_SHA256, "r23")
    for filename, expected in R2_4_FILES.items():
        if sha256_bytes((HERE / filename).read_bytes()) != expected:
            raise ConformanceError(f"R2_4_FROZEN_HASH_MISMATCH:{filename}")
    r24 = import_exact(
        R2_4_VALIDATOR_PATH,
        R2_4_FILES[R2_4_VALIDATOR_PATH.name],
        "r24",
    )
    predecessor = subprocess.run(
        [sys.executable, "-I", str(R2_3_VALIDATOR_PATH)],
        cwd=str(HERE),
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if predecessor.returncode != 0:
        raise ConformanceError("R2_3_PRESERVATION_EXECUTION_FAILED")
    if set(predecessor.stdout.splitlines()) != R2_3_EXPECTED_OUTPUT:
        raise ConformanceError("R2_3_PRESERVATION_OUTPUT_MISMATCH")
    completed = subprocess.run(
        [sys.executable, "-I", str(R2_4_VALIDATOR_PATH)],
        cwd=str(HERE),
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if completed.returncode != 0:
        raise ConformanceError("R2_4_PRESERVATION_EXECUTION_FAILED")
    if set(completed.stdout.splitlines()) != R2_4_EXPECTED_OUTPUT:
        raise ConformanceError("R2_4_PRESERVATION_OUTPUT_MISMATCH")
    return r23, r24


def parse_utc(value: str) -> datetime:
    if not UTC_RE.fullmatch(value):
        raise ConformanceError("UTC_TIMESTAMP_INVALID")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ConformanceError("UTC_TIMESTAMP_INVALID") from exc
    return parsed.replace(tzinfo=timezone.utc)


def length_prefix(raw: bytes) -> bytes:
    return len(raw).to_bytes(8, "big") + raw


def immutable_mapping(value: dict[str, Any]) -> MappingProxyType:
    return MappingProxyType(copy.deepcopy(value))


def profile_semantics_row(profile_id: str) -> dict[str, Any]:
    permission, tools, network, filesystem, output = PROFILE_MATRIX[profile_id]
    record = {
        "semantics_row_digest": d("0"),
        "provider_profile_id": profile_id,
        "permission_mode": permission,
        "builtin_tools": tools,
        "network_policy": network,
        "filesystem_policy": filesystem,
        "subagent_policy": "FORBIDDEN",
        "output_profile": output,
        "environment_policy_set_names": ["base", "ecosystem"],
        "settings_selection_policy": "REVIEWED_SETTINGS_V1",
        "mcp_selection_policy": "PROFILE_SELECTED_MCP_V1",
        "stream_max_bytes": 1048576,
        "stream_max_events": 4096,
        "isolation_policy": "OWNED_PROCESS_SCOPE_V1",
    }
    return seal(record, "semantics_row_digest")


def profile_semantics_authority() -> dict[str, Any]:
    rows = [profile_semantics_row(name) for name in sorted(PROFILE_MATRIX)]
    record = {
        "schema": "plamen.claude-provider-profile-semantics-authority.v2",
        "semantics_authority_version": 2,
        "semantics_authority_digest": d("0"),
        "semantics_id": "PLAMEN_CLAUDE_PROFILE_SEMANTICS_R2_5_V2",
        "row_count": 4,
        "rows": rows,
    }
    return seal(record, "semantics_authority_digest")


def provider_profile(
    semantics: dict[str, Any], profile_id: str = "analysis_filesystem"
) -> dict[str, Any]:
    row = next(
        item for item in semantics["rows"]
        if item["provider_profile_id"] == profile_id
    )
    record = {
        "schema": "plamen.claude-provider-profile.v2",
        "provider_profile_version": 2,
        "provider_profile_digest": d("0"),
        "semantics_authority_digest": semantics["semantics_authority_digest"],
        **copy.deepcopy(row),
        "route_neutrality": "ROUTE_FIELDS_FORBIDDEN",
    }
    record.pop("provider_profile_digest", None)
    record["provider_profile_digest"] = d("0")
    return seal(record, "provider_profile_digest")


def profile_registry(
    semantics: dict[str, Any], profiles: list[dict[str, Any]]
) -> dict[str, Any]:
    ordered = sorted(profiles, key=lambda item: item["provider_profile_id"])
    record = {
        "schema": "plamen.claude-provider-profile-registry.v2",
        "profile_registry_version": 2,
        "profile_registry_digest": d("0"),
        "semantics_authority_digest": semantics["semantics_authority_digest"],
        "profile_ids": [item["provider_profile_id"] for item in ordered],
        "profile_digests": [item["provider_profile_digest"] for item in ordered],
    }
    return seal(record, "profile_registry_digest")


def environment_policy() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for name, source, secrecy, presence, authorities in (
        (
            "ANTHROPIC_API_KEY",
            "SECRET_RUNTIME",
            "SECRET",
            "REQUIRED",
            [d("1"), d("2")],
        ),
        (
            "PLAMEN_TEMP_ROOT",
            "RUNTIME_PATH_NON_SECRET",
            "NON_SECRET",
            "REQUIRED",
            [d("3")],
        ),
    ):
        row = {
            "policy_row_digest": d("0"),
            "name": name,
            "name_comparison": "ASCII_CASE_INSENSITIVE_WINDOWS",
            "source_class": source,
            "secrecy_class": secrecy,
            "presence_policy": presence,
            "classification_authority_digest": d("4"),
            "policy_authority_digests": authorities,
        }
        rows.append(seal(row, "policy_row_digest"))
    record = {
        "schema": "plamen.public-environment-policy-authority.v2",
        "environment_policy_version": 2,
        "environment_policy_authority_digest": d("0"),
        "host_family": "windows",
        "expected_row_count": len(rows),
        "rows": rows,
    }
    return seal(record, "environment_policy_authority_digest")


def public_environment(
    policy: dict[str, Any],
    raw_env: dict[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    if raw_env is None:
        raw_env = {
            "ANTHROPIC_API_KEY": "alpha-secret",
            "PLAMEN_TEMP_ROOT": "C:/Plamen/tmp",
        }
    entries: list[dict[str, Any]] = []
    folded = {key.upper(): (key, value) for key, value in raw_env.items()}
    for row in policy["rows"]:
        match = folded.get(row["name"].upper())
        present = match is not None
        secret = row["secrecy_class"] == "SECRET"
        entry = {
            "projection_row_digest": d("0"),
            "policy_row_digest": row["policy_row_digest"],
            "name": row["name"],
            "source_class": row["source_class"],
            "redaction_marker": (
                "SECRET_VALUE_PRESENT_REDACTED"
                if secret and present
                else "SECRET_VALUE_ABSENT"
                if secret
                else "NON_SECRET_VALUE_INCLUDED"
            ),
            "policy_authority_digests": row["policy_authority_digests"],
            "non_secret_value": None if secret or not present else match[1],
        }
        entries.append(seal(entry, "projection_row_digest"))
    record = {
        "schema": "plamen.public-materialized-environment.v2",
        "public_environment_version": 2,
        "public_materialized_environment_digest": d("0"),
        "environment_policy_authority_digest":
            policy["environment_policy_authority_digest"],
        "entry_count": len(entries),
        "entries": entries,
    }
    return seal(record, "public_materialized_environment_digest"), raw_env


def provider_manifest() -> dict[str, Any]:
    model = {
        "model_row_digest": d("0"),
        "exact_model_id": "claude-opus-5-20260701",
        "model_family": "claude-opus-5",
        "model_kind": "EXACT_VERSION",
        "effort_applicability": "APPLICABLE",
        "supported_efforts": ["high", "low", "medium", "xhigh"],
        "supported_thinking_modes": [
            "ADAPTIVE_ON",
            "MANUAL_OFF",
            "MANUAL_ON",
        ],
    }
    seal(model, "model_row_digest")
    tuples = []
    for account, auth, tier in (
        ("API_KEY", "ANTHROPIC_API_KEY", "api_standard"),
        ("STORED_SUBSCRIPTION", "CLAUDE_CODE_OAUTH", "subscription"),
    ):
        row = {
            "tuple_row_digest": d("0"),
            "account_class": account,
            "auth_route": auth,
            "service_tier": tier,
            "transport": "HEADLESS_PROOF",
            "assurance_class": "TRANSACTIONAL_PROOF_CANDIDATE",
        }
        tuples.append(seal(row, "tuple_row_digest"))
    record = {
        "schema": "plamen.provider-manifest-authority.v2",
        "provider_manifest_version": 2,
        "provider_manifest_authority_digest": d("0"),
        "provider": "claude",
        "model_count": 1,
        "model_rows": [model],
        "tuple_count": 2,
        "route_tuples": sorted(
            tuples,
            key=lambda item: (
                item["account_class"],
                item["auth_route"],
                item["service_tier"],
            ),
        ),
        "observed_utc": "2026-07-30T00:00:00Z",
    }
    return seal(record, "provider_manifest_authority_digest")


def evaluation_time() -> dict[str, Any]:
    return seal(
        {
            "schema": "plamen.evaluation-time-authority.v1",
            "evaluation_time_version": 1,
            "evaluation_time_authority_digest": d("0"),
            "evaluation_utc": "2026-07-30T00:00:00Z",
            "clock_source_authority_digest": d("6"),
        },
        "evaluation_time_authority_digest",
    )


def capability_authority(
    manifest: dict[str, Any], evaluation: dict[str, Any]
) -> dict[str, Any]:
    model = manifest["model_rows"][0]
    route_tuple = next(
        row for row in manifest["route_tuples"]
        if row["account_class"] == "STORED_SUBSCRIPTION"
    )
    return seal(
        {
            "schema": "plamen.provider-route-capability-authority.v2",
            "capability_authority_version": 2,
            "capability_authority_digest": d("0"),
            "provider_manifest_authority_digest":
                manifest["provider_manifest_authority_digest"],
            "model_row_digest": model["model_row_digest"],
            "tuple_row_digest": route_tuple["tuple_row_digest"],
            "evaluation_time_authority_digest":
                evaluation["evaluation_time_authority_digest"],
            "exact_model_id": model["exact_model_id"],
            "effort_applicability": model["effort_applicability"],
            "supported_efforts": model["supported_efforts"],
            "supported_thinking_modes": model["supported_thinking_modes"],
            "valid_from_utc": "2026-07-29T00:00:00Z",
            "valid_until_utc": "2026-08-29T00:00:00Z",
            "canary_field_claim_digest": d("7"),
        },
        "capability_authority_digest",
    )


def price_authority(
    manifest: dict[str, Any], evaluation: dict[str, Any]
) -> dict[str, Any]:
    return seal(
        {
            "schema": "plamen.provider-price-authority.v2",
            "price_authority_version": 2,
            "price_authority_digest": d("0"),
            "provider_manifest_authority_digest":
                manifest["provider_manifest_authority_digest"],
            "model_row_digest": manifest["model_rows"][0]["model_row_digest"],
            "evaluation_time_authority_digest":
                evaluation["evaluation_time_authority_digest"],
            "currency_code": "USD",
            "pricing_snapshot_digest": d("8"),
            "unit_basis": "PER_MILLION_TOKENS",
        },
        "price_authority_digest",
    )


def fallback_authority(manifest: dict[str, Any]) -> dict[str, Any]:
    return seal(
        {
            "schema": "plamen.provider-fallback-authority.v2",
            "fallback_authority_version": 2,
            "fallback_authority_digest": d("0"),
            "provider_manifest_authority_digest":
                manifest["provider_manifest_authority_digest"],
            "policy": "FORBID_IMPLICIT_PROVIDER_FALLBACK",
            "requested_model_count": 1,
            "observed_different_model_disposition": "ROUTE_DEBT",
            "continuation_rule": "NEW_GENERATION_ONLY",
        },
        "fallback_authority_digest",
    )


def route_selection_authority(
    predecessor: dict[str, Any],
    axes: dict[str, Any],
    semantics: dict[str, Any],
    registry: dict[str, Any],
    profile: dict[str, Any],
    public_env: dict[str, Any],
    manifest: dict[str, Any],
    evaluation: dict[str, Any],
    capability: dict[str, Any],
    price: dict[str, Any],
    fallback: dict[str, Any],
) -> dict[str, Any]:
    return seal(
        {
            "schema": "plamen.provider-route-selection-authority.v1",
            "route_selection_version": 1,
            "route_selection_authority_digest": d("0"),
            "execution_axes_digest": axes["execution_axes_digest"],
            "profile_semantics_authority_digest":
                semantics["semantics_authority_digest"],
            "profile_registry_digest": registry["profile_registry_digest"],
            "provider_profile_digest": profile["provider_profile_digest"],
            "semantics_row_digest": profile["semantics_row_digest"],
            "public_materialized_environment_digest":
                public_env["public_materialized_environment_digest"],
            "provider_manifest_authority_digest":
                manifest["provider_manifest_authority_digest"],
            "model_row_digest": capability["model_row_digest"],
            "tuple_row_digest": capability["tuple_row_digest"],
            "evaluation_time_authority_digest":
                evaluation["evaluation_time_authority_digest"],
            "capability_authority_digest":
                capability["capability_authority_digest"],
            "price_authority_digest": price["price_authority_digest"],
            "fallback_authority_digest":
                fallback["fallback_authority_digest"],
            "context_budget_digest": d("a"),
            "budget_authority_digest": d("b"),
            "materialized_argv_digest": d("6"),
            "provider_evidence_field_authority_digest":
                EVIDENCE_FIELD_AUTHORITY_DIGEST,
            "secret_proof_policy_digest": SECRET_PROOF_POLICY_DIGEST,
            "work_plan_digest": d("3"),
            "phase_io_launch_digest": d("4"),
            "exact_requested_model_id": capability["exact_model_id"],
            "effort_applicability": capability["effort_applicability"],
            "requested_effort":
                predecessor["effort"]["requested_effort"],
            "requested_thinking_mode":
                predecessor["thinking"]["requested_thinking_mode"],
            "manual_thinking_budget_tokens":
                predecessor["thinking"]["manual_thinking_budget_tokens"],
            "account_class": "STORED_SUBSCRIPTION",
            "auth_route": "CLAUDE_CODE_OAUTH",
            "service_tier": "subscription",
            "transport": "HEADLESS_PROOF",
            "assurance_class": "TRANSACTIONAL_PROOF_CANDIDATE",
        },
        "route_selection_authority_digest",
    )


def routing_root(
    predecessor: dict[str, Any],
    semantics: dict[str, Any],
    env_policy: dict[str, Any],
    manifest: dict[str, Any],
    evaluation: dict[str, Any],
    selection: dict[str, Any],
) -> dict[str, Any]:
    return seal(
        {
            "schema": "plamen.routing-root-authority.v1",
            "routing_root_version": 1,
            "routing_root_digest": d("0"),
            "semantic_plan_digest": d("c"),
            "arm_family_digest": d("2"),
            "family_grant_authority_digest": d("a"),
            "source_snapshot_authority_digest": d("1"),
            "prompt_authority_digest": d("2"),
            "methodology_authority_digest": d("3"),
            "program_facts_authority_digest": d("4"),
            "tool_policy_authority_digest": d("5"),
            "loaded_customization_set_digest":
                predecessor["loaded"]["customization_set_digest"],
            "effort_authority_digest":
                predecessor["effort"]["effort_authority_digest"],
            "thinking_authority_digest":
                predecessor["thinking"]["thinking_authority_digest"],
            "profile_semantics_authority_digest":
                semantics["semantics_authority_digest"],
            "environment_policy_authority_digest":
                env_policy["environment_policy_authority_digest"],
            "provider_manifest_authority_digest":
                manifest["provider_manifest_authority_digest"],
            "evaluation_time_authority_digest":
                evaluation["evaluation_time_authority_digest"],
            "route_selection_authority_digest":
                selection["route_selection_authority_digest"],
            "work_plan_contract_authority_digest": d("d"),
            "phase_io_contract_digest": d("e"),
            "output_contract_digest": d("f"),
        },
        "routing_root_digest",
    )


def customization_authority(
    root: dict[str, Any],
    predecessor: dict[str, Any],
    public_env: dict[str, Any],
    selection: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    record = seal(
        {
            "schema": "plamen.claude-execution-customization-authority.v2",
            "customization_authority_version": 2,
            "customization_authority_digest": d("0"),
            "routing_root_digest": root["routing_root_digest"],
            "loaded_customization_set_digest":
                predecessor["loaded"]["customization_set_digest"],
            "effort_authority_digest":
                predecessor["effort"]["effort_authority_digest"],
            "thinking_authority_digest":
                predecessor["thinking"]["thinking_authority_digest"],
            "effort_applicability": selection["effort_applicability"],
            "requested_effort": selection["requested_effort"],
            "requested_thinking_mode": selection["requested_thinking_mode"],
            "manual_thinking_budget_tokens":
                selection["manual_thinking_budget_tokens"],
            "materialized_argv_digest":
                selection["materialized_argv_digest"],
            "public_materialized_environment_digest":
                public_env["public_materialized_environment_digest"],
            "provider_evidence_field_authority_digest":
                selection["provider_evidence_field_authority_digest"],
        },
        "customization_authority_digest",
    )
    projection = seal(
        {
            "schema": "plamen.customization-authority-projection.v1",
            "projection_version": 1,
            "projection_digest": d("0"),
            "predecessor_loaded_customization_set_digest":
                predecessor["loaded"]["customization_set_digest"],
            "predecessor_effort_authority_digest":
                predecessor["effort"]["effort_authority_digest"],
            "predecessor_thinking_authority_digest":
                predecessor["thinking"]["thinking_authority_digest"],
            "successor_customization_authority_digest":
                record["customization_authority_digest"],
            "projection_rule": "R2_3_DIGESTS_PRESERVED_VERBATIM",
        },
        "projection_digest",
    )
    return record, projection


def model_route(
    root: dict[str, Any],
    axes: dict[str, Any],
    manifest: dict[str, Any],
    evaluation: dict[str, Any],
    capability: dict[str, Any],
    price: dict[str, Any],
    fallback: dict[str, Any],
    selection: dict[str, Any],
) -> dict[str, Any]:
    return seal(
        {
            "schema": "plamen.model-route.v4",
            "model_route_version": 4,
            "model_route_digest": d("0"),
            "routing_root_digest": root["routing_root_digest"],
            "execution_axes_digest": axes["execution_axes_digest"],
            "route_selection_authority_digest":
                selection["route_selection_authority_digest"],
            "provider_manifest_authority_digest":
                manifest["provider_manifest_authority_digest"],
            "model_row_digest": capability["model_row_digest"],
            "tuple_row_digest": capability["tuple_row_digest"],
            "evaluation_time_authority_digest":
                evaluation["evaluation_time_authority_digest"],
            "capability_authority_digest":
                capability["capability_authority_digest"],
            "price_authority_digest": price["price_authority_digest"],
            "fallback_authority_digest":
                fallback["fallback_authority_digest"],
            "context_budget_digest": selection["context_budget_digest"],
            "budget_authority_digest": selection["budget_authority_digest"],
            "exact_requested_model_id":
                selection["exact_requested_model_id"],
            "effort_applicability": selection["effort_applicability"],
            "requested_effort": selection["requested_effort"],
            "requested_thinking_mode": selection["requested_thinking_mode"],
            "manual_thinking_budget_tokens":
                selection["manual_thinking_budget_tokens"],
            "account_class": selection["account_class"],
            "auth_route": selection["auth_route"],
            "service_tier": selection["service_tier"],
            "transport": selection["transport"],
            "assurance_class": selection["assurance_class"],
        },
        "model_route_digest",
    )


def request_record(
    root: dict[str, Any],
    axes: dict[str, Any],
    semantics: dict[str, Any],
    registry: dict[str, Any],
    profile: dict[str, Any],
    customization: dict[str, Any],
    route: dict[str, Any],
) -> dict[str, Any]:
    return seal(
        {
            "schema": "plamen.claude-headless-execution-request.v3",
            "request_version": 3,
            "request_digest": d("0"),
            "routing_root_digest": root["routing_root_digest"],
            "execution_axes_digest": axes["execution_axes_digest"],
            "routing_profile": axes["routing_profile"],
            "transport": axes["transport"],
            "profile_semantics_authority_digest":
                semantics["semantics_authority_digest"],
            "profile_registry_digest": registry["profile_registry_digest"],
            "provider_profile_digest": profile["provider_profile_digest"],
            "semantics_row_digest": profile["semantics_row_digest"],
            "customization_authority_digest":
                customization["customization_authority_digest"],
            "model_route_digest": route["model_route_digest"],
            "semantic_plan_digest": root["semantic_plan_digest"],
            "arm_family_digest": root["arm_family_digest"],
            "source_snapshot_authority_digest":
                root["source_snapshot_authority_digest"],
            "prompt_authority_digest": root["prompt_authority_digest"],
            "methodology_authority_digest":
                root["methodology_authority_digest"],
            "program_facts_authority_digest":
                root["program_facts_authority_digest"],
            "tool_policy_authority_digest":
                root["tool_policy_authority_digest"],
            "work_plan_contract_authority_digest":
                root["work_plan_contract_authority_digest"],
            "phase_io_contract_digest": root["phase_io_contract_digest"],
            "output_contract_digest": root["output_contract_digest"],
            "context_budget_digest": route["context_budget_digest"],
            "budget_authority_digest": route["budget_authority_digest"],
        },
        "request_digest",
    )


def workplan_record(
    root: dict[str, Any],
    request: dict[str, Any],
    axes: dict[str, Any],
    semantics: dict[str, Any],
    profile: dict[str, Any],
    customization: dict[str, Any],
    route: dict[str, Any],
) -> dict[str, Any]:
    return seal(
        {
            "schema": "plamen.work-plan-routing-binding.v3",
            "work_plan_binding_version": 3,
            "work_plan_binding_digest": d("0"),
            "routing_root_digest": root["routing_root_digest"],
            "work_plan_digest": d("3"),
            "request_digest": request["request_digest"],
            "semantic_plan_digest": root["semantic_plan_digest"],
            "execution_axes_digest": axes["execution_axes_digest"],
            "profile_semantics_authority_digest":
                semantics["semantics_authority_digest"],
            "provider_profile_digest": profile["provider_profile_digest"],
            "customization_authority_digest":
                customization["customization_authority_digest"],
            "model_route_digest": route["model_route_digest"],
            "source_snapshot_authority_digest":
                root["source_snapshot_authority_digest"],
            "methodology_authority_digest":
                root["methodology_authority_digest"],
            "program_facts_authority_digest":
                root["program_facts_authority_digest"],
            "output_contract_digest": root["output_contract_digest"],
        },
        "work_plan_binding_digest",
    )


def phaseio_record(
    root: dict[str, Any],
    request: dict[str, Any],
    work: dict[str, Any],
    customization: dict[str, Any],
    route: dict[str, Any],
) -> dict[str, Any]:
    return seal(
        {
            "schema": "plamen.phase-io-routing-binding.v3",
            "phase_io_binding_version": 3,
            "phase_io_binding_digest": d("0"),
            "routing_root_digest": root["routing_root_digest"],
            "phase_io_contract_digest": root["phase_io_contract_digest"],
            "phase_io_launch_digest": d("4"),
            "work_plan_binding_digest": work["work_plan_binding_digest"],
            "request_digest": request["request_digest"],
            "customization_authority_digest":
                customization["customization_authority_digest"],
            "model_route_digest": route["model_route_digest"],
            "source_snapshot_authority_digest":
                root["source_snapshot_authority_digest"],
            "methodology_authority_digest":
                root["methodology_authority_digest"],
            "program_facts_authority_digest":
                root["program_facts_authority_digest"],
            "output_contract_digest": root["output_contract_digest"],
            "incorporation_policy": "EXACTLY_ONCE_AFTER_RECONCILIATION",
        },
        "phase_io_binding_digest",
    )


def control_record(
    root: dict[str, Any],
    request: dict[str, Any],
    axes: dict[str, Any],
    semantics: dict[str, Any],
    profile: dict[str, Any],
    customization: dict[str, Any],
    route: dict[str, Any],
    public_env: dict[str, Any],
) -> dict[str, Any]:
    return seal(
        {
            "schema": "plamen.claude-provider-control-vector.v3",
            "control_vector_version": 3,
            "control_vector_digest": d("0"),
            "routing_root_digest": root["routing_root_digest"],
            "request_digest": request["request_digest"],
            "semantic_plan_digest": root["semantic_plan_digest"],
            "execution_axes_digest": axes["execution_axes_digest"],
            "profile_semantics_authority_digest":
                semantics["semantics_authority_digest"],
            "provider_profile_digest": profile["provider_profile_digest"],
            "customization_authority_digest":
                customization["customization_authority_digest"],
            "loaded_customization_set_digest":
                root["loaded_customization_set_digest"],
            "effort_authority_digest": root["effort_authority_digest"],
            "thinking_authority_digest": root["thinking_authority_digest"],
            "model_route_digest": route["model_route_digest"],
            "exact_model_id": route["exact_requested_model_id"],
            "effort_applicability": route["effort_applicability"],
            "requested_effort": route["requested_effort"],
            "requested_thinking_mode": route["requested_thinking_mode"],
            "manual_thinking_budget_tokens":
                route["manual_thinking_budget_tokens"],
            "materialized_argv_digest":
                customization["materialized_argv_digest"],
            "public_materialized_environment_digest":
                public_env["public_materialized_environment_digest"],
            "environment_policy_authority_digest":
                root["environment_policy_authority_digest"],
            "secret_proof_policy_digest": SECRET_PROOF_POLICY_DIGEST,
        },
        "control_vector_digest",
    )


def launch_record(
    root: dict[str, Any],
    request: dict[str, Any],
    axes: dict[str, Any],
    semantics: dict[str, Any],
    profile: dict[str, Any],
    customization: dict[str, Any],
    route: dict[str, Any],
    control: dict[str, Any],
    work: dict[str, Any],
    phaseio: dict[str, Any],
) -> dict[str, Any]:
    return seal(
        {
            "schema": "plamen.launch-authority.v4",
            "launch_authority_version": 4,
            "launch_authority_digest": d("0"),
            "routing_root_digest": root["routing_root_digest"],
            "semantic_plan_digest": root["semantic_plan_digest"],
            "arm_family_digest": root["arm_family_digest"],
            "generation": 1,
            "request_digest": request["request_digest"],
            "execution_axes_digest": axes["execution_axes_digest"],
            "profile_semantics_authority_digest":
                semantics["semantics_authority_digest"],
            "provider_profile_digest": profile["provider_profile_digest"],
            "customization_authority_digest":
                customization["customization_authority_digest"],
            "loaded_customization_set_digest":
                root["loaded_customization_set_digest"],
            "effort_authority_digest": root["effort_authority_digest"],
            "thinking_authority_digest": root["thinking_authority_digest"],
            "model_route_digest": route["model_route_digest"],
            "budget_authority_digest": route["budget_authority_digest"],
            "generation_reservation_event_digest": d("8"),
            "control_vector_digest": control["control_vector_digest"],
            "work_plan_binding_digest": work["work_plan_binding_digest"],
            "phase_io_binding_digest": phaseio["phase_io_binding_digest"],
            "tool_policy_digest": root["tool_policy_authority_digest"],
            "child_policy": "DRIVER_ONLY_NO_MODEL_CHILDREN",
        },
        "launch_authority_digest",
    )


def arm_record(
    root: dict[str, Any],
    request: dict[str, Any],
    axes: dict[str, Any],
    semantics: dict[str, Any],
    profile: dict[str, Any],
    customization: dict[str, Any],
    route: dict[str, Any],
    launch: dict[str, Any],
    work: dict[str, Any],
    phaseio: dict[str, Any],
) -> dict[str, Any]:
    return seal(
        {
            "schema": "plamen.backend-arm-execution-identity.v5",
            "backend_arm_version": 5,
            "backend_arm_digest": d("0"),
            "routing_root_digest": root["routing_root_digest"],
            "arm_family_digest": root["arm_family_digest"],
            "generation": launch["generation"],
            "semantic_plan_digest": root["semantic_plan_digest"],
            "request_digest": request["request_digest"],
            "execution_axes_digest": axes["execution_axes_digest"],
            "profile_semantics_authority_digest":
                semantics["semantics_authority_digest"],
            "provider_profile_digest": profile["provider_profile_digest"],
            "customization_authority_digest":
                customization["customization_authority_digest"],
            "model_route_digest": route["model_route_digest"],
            "budget_authority_digest": route["budget_authority_digest"],
            "launch_authority_digest": launch["launch_authority_digest"],
            "work_plan_binding_digest": work["work_plan_binding_digest"],
            "phase_io_binding_digest": phaseio["phase_io_binding_digest"],
        },
        "backend_arm_digest",
    )


def attempt_record(
    root: dict[str, Any],
    request: dict[str, Any],
    semantics: dict[str, Any],
    profile: dict[str, Any],
    customization: dict[str, Any],
    route: dict[str, Any],
    launch: dict[str, Any],
    arm: dict[str, Any],
) -> dict[str, Any]:
    return seal(
        {
            "schema": "plamen.execution-attempt-identity.v4",
            "execution_attempt_version": 4,
            "execution_attempt_digest": d("0"),
            "routing_root_digest": root["routing_root_digest"],
            "backend_arm_digest": arm["backend_arm_digest"],
            "arm_family_digest": root["arm_family_digest"],
            "generation": launch["generation"],
            "attempt_ordinal": 0,
            "request_digest": request["request_digest"],
            "profile_semantics_authority_digest":
                semantics["semantics_authority_digest"],
            "provider_profile_digest": profile["provider_profile_digest"],
            "customization_authority_digest":
                customization["customization_authority_digest"],
            "model_route_digest": route["model_route_digest"],
            "launch_authority_digest": launch["launch_authority_digest"],
        },
        "execution_attempt_digest",
    )


def predecessor_envelope_v3(
    launch: dict[str, Any],
    request: dict[str, Any],
    control: dict[str, Any],
    public_env: dict[str, Any],
    arm: dict[str, Any],
    attempt: dict[str, Any],
) -> dict[str, Any]:
    return seal(
        {
            "schema": "plamen.attempt-launch-envelope.v3",
            "attempt_launch_version": 3,
            "attempt_launch_digest": d("0"),
            "launch_authority_digest": launch["launch_authority_digest"],
            "request_digest": request["request_digest"],
            "provider_control_vector_digest":
                control["control_vector_digest"],
            "attempt_identity_digest": attempt["execution_attempt_digest"],
            "backend_arm_digest": arm["backend_arm_digest"],
            "attempt_reservation_event_digest": d("d"),
            "attempt_resource_entry_digest": d("e"),
            "resource_ledger_digest_after_attempt_reservation": d("f"),
            "materialized_argv_digest": control["materialized_argv_digest"],
            "public_materialized_environment_digest":
                public_env["public_materialized_environment_digest"],
            "environment_policy_set_digest":
                control["environment_policy_authority_digest"],
            "secret_proof_policy_digest":
                control["secret_proof_policy_digest"],
            "secret_proof_required": True,
            "materialized_stdin_prompt_digest": d("1"),
            "working_directory_identity_digest": d("2"),
            "prepared_utc": "2026-07-30T00:00:00Z",
        },
        "attempt_launch_digest",
    )


def envelope_record(
    root: dict[str, Any],
    request: dict[str, Any],
    customization: dict[str, Any],
    control: dict[str, Any],
    launch: dict[str, Any],
    arm: dict[str, Any],
    attempt: dict[str, Any],
    public_env: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    predecessor = predecessor_envelope_v3(
        launch, request, control, public_env, arm, attempt
    )
    record = seal(
        {
            "schema": "plamen.attempt-launch-envelope.v4",
            "attempt_launch_version": 4,
            "attempt_launch_digest": d("0"),
            "predecessor_attempt_launch_v3_digest":
                predecessor["attempt_launch_digest"],
            "routing_root_digest": root["routing_root_digest"],
            "execution_attempt_digest":
                attempt["execution_attempt_digest"],
            "backend_arm_digest": arm["backend_arm_digest"],
            "launch_authority_digest": launch["launch_authority_digest"],
            "request_digest": request["request_digest"],
            "control_vector_digest": control["control_vector_digest"],
            "customization_authority_digest":
                customization["customization_authority_digest"],
            "attempt_reservation_event_digest": d("d"),
            "attempt_resource_entry_digest": d("e"),
            "resource_ledger_digest_after_attempt_reservation": d("f"),
            "materialized_argv_digest": control["materialized_argv_digest"],
            "public_materialized_environment_digest":
                public_env["public_materialized_environment_digest"],
            "environment_policy_authority_digest":
                control["environment_policy_authority_digest"],
            "secret_proof_policy_digest":
                control["secret_proof_policy_digest"],
            "secret_proof_required": True,
            "materialized_stdin_prompt_digest": d("1"),
            "working_directory_identity_digest": d("2"),
            "prepared_utc": "2026-07-30T00:00:00Z",
        },
        "attempt_launch_digest",
    )
    return record, predecessor


def consumed_record(
    envelope: dict[str, Any], attempt: dict[str, Any]
) -> dict[str, Any]:
    return seal(
        {
            "schema": "plamen.consumed-attempt-launch-authority.v2",
            "consumed_launch_version": 2,
            "consumed_launch_digest": d("0"),
            "attempt_launch_digest": envelope["attempt_launch_digest"],
            "predecessor_attempt_launch_v3_digest":
                envelope["predecessor_attempt_launch_v3_digest"],
            "execution_attempt_digest":
                attempt["execution_attempt_digest"],
            "launch_consumption_event_digest": d("3"),
            "consumed_attempt_resource_entry_digest": d("4"),
            "resource_ledger_digest_after_launch_consumption": d("5"),
            "consume_cas_revision": 2,
            "spawn_state": "CONSUMED_NOT_SPAWNED",
        },
        "consumed_launch_digest",
    )


def evidence_claim(
    field_name: str, value: Any, ordinal: int
) -> dict[str, Any]:
    raw_digest = sha256_bytes(
        canonical_bytes(
            {
                "field_name": field_name,
                "ordinal": ordinal,
                "observed_value": value,
            }
        )
    )
    return seal(
        {
            "field_claim_digest": d("0"),
            "field_name": field_name,
            "observed_value_digest": sha256_bytes(canonical_bytes(value)),
            "proof_rule_id": f"R2_5_PROVIDER_FIELD_{ordinal}",
            "raw_artifact_digests": [raw_digest],
        },
        "field_claim_digest",
    )


def evidence_manifest(values: dict[str, Any]) -> dict[str, Any]:
    claims = [
        evidence_claim(field, values[field], ordinal)
        for ordinal, field in enumerate(
            [
                "effective_model",
                "effective_effort",
                "thinking_state",
                "fallback_state",
                "terminal_category",
            ],
            start=1,
        )
    ]
    raw = sorted(
        {
            digest
            for claim in claims
            for digest in claim["raw_artifact_digests"]
        }
    )
    return seal(
        {
            "schema": "plamen.provider-observation-evidence-manifest.v2",
            "evidence_manifest_version": 2,
            "evidence_manifest_digest": d("0"),
            "field_authority_digest": EVIDENCE_FIELD_AUTHORITY_DIGEST,
            "claim_count": len(claims),
            "field_claims": claims,
            "raw_artifact_union_digest": sha256_bytes(canonical_bytes(raw)),
            "raw_artifact_digests": raw,
        },
        "evidence_manifest_digest",
    )


def observation_record(
    root: dict[str, Any],
    request: dict[str, Any],
    axes: dict[str, Any],
    semantics: dict[str, Any],
    profile: dict[str, Any],
    customization: dict[str, Any],
    route: dict[str, Any],
    arm: dict[str, Any],
    attempt: dict[str, Any],
    envelope: dict[str, Any],
    consumed: dict[str, Any],
    public_env: dict[str, Any],
    manifest: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    values = {
        "effective_model": route["exact_requested_model_id"],
        "effective_effort": route["requested_effort"],
        "thinking_state": "ADAPTIVE_ON_CONFIRMED",
        "fallback_state": "NO_FALLBACK_CONFIRMED",
        "terminal_category": "COMPLETED",
    }
    evidence = evidence_manifest(values)
    claims = {
        item["field_name"]: item for item in evidence["field_claims"]
    }
    record = seal(
        {
            "schema": "plamen.provider-execution-observation.v6",
            "observation_version": 6,
            "observation_digest": d("0"),
            "routing_root_digest": root["routing_root_digest"],
            "execution_attempt_digest":
                attempt["execution_attempt_digest"],
            "backend_arm_digest": arm["backend_arm_digest"],
            "request_digest": request["request_digest"],
            "execution_axes_digest": axes["execution_axes_digest"],
            "profile_semantics_authority_digest":
                semantics["semantics_authority_digest"],
            "provider_profile_digest": profile["provider_profile_digest"],
            "customization_authority_digest":
                customization["customization_authority_digest"],
            "loaded_customization_set_digest":
                root["loaded_customization_set_digest"],
            "effort_authority_digest": root["effort_authority_digest"],
            "thinking_authority_digest": root["thinking_authority_digest"],
            "model_route_digest": route["model_route_digest"],
            "attempt_launch_digest": envelope["attempt_launch_digest"],
            "consumed_launch_digest": consumed["consumed_launch_digest"],
            "public_materialized_environment_digest":
                public_env["public_materialized_environment_digest"],
            "observed_effective_model_id": values["effective_model"],
            "observed_effective_effort": values["effective_effort"],
            "observed_thinking_state": values["thinking_state"],
            "fallback_observation_state": values["fallback_state"],
            "provider_terminal_category": values["terminal_category"],
            "evidence_manifest_digest":
                evidence["evidence_manifest_digest"],
            "model_field_claim_digest":
                claims["effective_model"]["field_claim_digest"],
            "effort_field_claim_digest":
                claims["effective_effort"]["field_claim_digest"],
            "thinking_field_claim_digest":
                claims["thinking_state"]["field_claim_digest"],
            "fallback_field_claim_digest":
                claims["fallback_state"]["field_claim_digest"],
            "terminal_field_claim_digest":
                claims["terminal_category"]["field_claim_digest"],
            "thinking_observation_evidence_digest":
                claims["thinking_state"]["raw_artifact_digests"][0],
            "provider_usage_digest": d("8"),
            "raw_stream_digest": d("9"),
        },
        "observation_digest",
    )
    return record, evidence


SCHEMA_RECORDS = {
    "root": ("RoutingRootAuthorityV1", "routing_root_digest"),
    "projection": ("CustomizationAuthorityProjectionV1", "projection_digest"),
    "customization": (
        "ClaudeExecutionCustomizationAuthorityV2",
        "customization_authority_digest",
    ),
    "semantics": (
        "ClaudeProviderProfileSemanticsAuthorityV2",
        "semantics_authority_digest",
    ),
    "profile": ("ClaudeProviderProfileV2", "provider_profile_digest"),
    "registry": (
        "ClaudeProviderProfileRegistryV2",
        "profile_registry_digest",
    ),
    "env_policy": (
        "PublicEnvironmentPolicyAuthorityV2",
        "environment_policy_authority_digest",
    ),
    "public_env": (
        "PublicMaterializedEnvironmentV2",
        "public_materialized_environment_digest",
    ),
    "manifest": (
        "ProviderManifestAuthorityV2",
        "provider_manifest_authority_digest",
    ),
    "evaluation": (
        "EvaluationTimeAuthorityV1",
        "evaluation_time_authority_digest",
    ),
    "capability": (
        "ProviderRouteCapabilityAuthorityV2",
        "capability_authority_digest",
    ),
    "price": ("ProviderPriceAuthorityV2", "price_authority_digest"),
    "fallback": (
        "ProviderFallbackAuthorityV2",
        "fallback_authority_digest",
    ),
    "selection": (
        "ProviderRouteSelectionAuthorityV1",
        "route_selection_authority_digest",
    ),
    "route": ("ModelRouteV4", "model_route_digest"),
    "request": ("ClaudeHeadlessExecutionRequestV3", "request_digest"),
    "work": ("WorkPlanRoutingBindingV3", "work_plan_binding_digest"),
    "phaseio": ("PhaseIORoutingBindingV3", "phase_io_binding_digest"),
    "control": (
        "ClaudeProviderControlVectorV3",
        "control_vector_digest",
    ),
    "launch": ("LaunchAuthorityV4", "launch_authority_digest"),
    "arm": ("BackendArmExecutionIdentityV5", "backend_arm_digest"),
    "attempt": (
        "ExecutionAttemptIdentityV4",
        "execution_attempt_digest",
    ),
    "envelope": ("AttemptLaunchEnvelopeV4", "attempt_launch_digest"),
    "consumed": (
        "ConsumedAttemptLaunchAuthorityV2",
        "consumed_launch_digest",
    ),
    "evidence": (
        "ProviderObservationEvidenceManifestV2",
        "evidence_manifest_digest",
    ),
    "observation": (
        "ProviderExecutionObservationV6",
        "observation_digest",
    ),
}


def validate_profile_semantics(
    bundle: dict[str, Any],
    semantics: dict[str, Any],
    profiles: list[dict[str, Any]],
    registry: dict[str, Any],
) -> None:
    schema_validate(
        bundle, "ClaudeProviderProfileSemanticsAuthorityV2", semantics
    )
    verify_seal(semantics, "semantics_authority_digest")
    rows = semantics["rows"]
    ids = [item["provider_profile_id"] for item in rows]
    if ids != sorted(PROFILE_MATRIX):
        raise ConformanceError("PROFILE_SEMANTICS_ORDER_INVALID")
    if semantics["row_count"] != len(rows) or len(set(ids)) != len(rows):
        raise ConformanceError("PROFILE_SEMANTICS_ORDER_INVALID")
    for row in rows:
        schema_validate(bundle, "ProfileSemanticsRowV2", row)
        verify_seal(row, "semantics_row_digest")
    expected_profiles = sorted(
        profiles, key=lambda item: item["provider_profile_id"]
    )
    for profile in expected_profiles:
        schema_validate(bundle, "ClaudeProviderProfileV2", profile)
        verify_seal(profile, "provider_profile_digest")
        row = next(
            (
                item for item in rows
                if item["provider_profile_id"]
                == profile["provider_profile_id"]
            ),
            None,
        )
        if row is None:
            raise ConformanceError("PROFILE_SEMANTICS_JOIN_MISMATCH")
        for field, value in row.items():
            if profile.get(field) != value:
                raise ConformanceError("PROFILE_SEMANTICS_JOIN_MISMATCH")
        if (
            profile["semantics_authority_digest"]
            != semantics["semantics_authority_digest"]
        ):
            raise ConformanceError("PROFILE_SEMANTICS_JOIN_MISMATCH")
    schema_validate(bundle, "ClaudeProviderProfileRegistryV2", registry)
    verify_seal(registry, "profile_registry_digest")
    if (
        registry["semantics_authority_digest"]
        != semantics["semantics_authority_digest"]
        or registry["profile_ids"]
        != [item["provider_profile_id"] for item in expected_profiles]
        or registry["profile_digests"]
        != [item["provider_profile_digest"] for item in expected_profiles]
    ):
        raise ConformanceError("PROFILE_REGISTRY_ROOT_MISMATCH")


def validate_environment(
    bundle: dict[str, Any],
    policy: dict[str, Any],
    public: dict[str, Any],
    raw_env: dict[str, str],
    envelope: dict[str, Any] | None = None,
) -> None:
    schema_validate(bundle, "PublicEnvironmentPolicyAuthorityV2", policy)
    schema_validate(bundle, "PublicMaterializedEnvironmentV2", public)
    verify_seal(policy, "environment_policy_authority_digest")
    verify_seal(public, "public_materialized_environment_digest")
    if policy["expected_row_count"] != len(policy["rows"]):
        raise ConformanceError("ENVIRONMENT_POLICY_COMPLETENESS_MISMATCH")
    folded: dict[str, str] = {}
    for raw_name in raw_env:
        key = raw_name.upper() if policy["host_family"] == "windows" else raw_name
        if key in folded:
            raise ConformanceError("ENVIRONMENT_NAME_COLLISION")
        folded[key] = raw_name
    policy_names: dict[str, dict[str, Any]] = {}
    for row in policy["rows"]:
        schema_validate(bundle, "PublicEnvironmentPolicyRowV2", row)
        verify_seal(row, "policy_row_digest")
        key = (
            row["name"].upper()
            if row["name_comparison"] == "ASCII_CASE_INSENSITIVE_WINDOWS"
            else row["name"]
        )
        expected_comparison = (
            "ASCII_CASE_INSENSITIVE_WINDOWS"
            if policy["host_family"] == "windows"
            else "BYTE_EXACT_POSIX"
        )
        if row["name_comparison"] != expected_comparison:
            raise ConformanceError("ENVIRONMENT_NAME_COMPARISON_MISMATCH")
        if key in policy_names:
            raise ConformanceError("ENVIRONMENT_NAME_COLLISION")
        policy_names[key] = row
        if (
            row["source_class"] == "SECRET_RUNTIME"
        ) != (row["secrecy_class"] == "SECRET"):
            raise ConformanceError("ENVIRONMENT_CLASSIFICATION_MISMATCH")
    if set(folded) - set(policy_names):
        raise ConformanceError("ENVIRONMENT_POLICY_COMPLETENESS_MISMATCH")
    if (
        public["environment_policy_authority_digest"]
        != policy["environment_policy_authority_digest"]
        or public["entry_count"] != len(public["entries"])
        or len(public["entries"]) != len(policy["rows"])
    ):
        raise ConformanceError("ENVIRONMENT_POLICY_COMPLETENESS_MISMATCH")
    entries: dict[str, dict[str, Any]] = {}
    for entry in public["entries"]:
        schema_validate(bundle, "PublicEnvironmentProjectionRowV2", entry)
        verify_seal(entry, "projection_row_digest")
        key = entry["name"].upper() if policy["host_family"] == "windows" else entry["name"]
        if key in entries:
            raise ConformanceError("ENVIRONMENT_NAME_COLLISION")
        entries[key] = entry
    if set(entries) != set(policy_names):
        raise ConformanceError("ENVIRONMENT_POLICY_COMPLETENESS_MISMATCH")
    for key, row in policy_names.items():
        entry = entries[key]
        present = key in folded
        if row["presence_policy"] == "REQUIRED" and not present:
            raise ConformanceError("ENVIRONMENT_PRESENCE_MISMATCH")
        expected_marker = (
            "SECRET_VALUE_PRESENT_REDACTED"
            if row["secrecy_class"] == "SECRET" and present
            else "SECRET_VALUE_ABSENT"
            if row["secrecy_class"] == "SECRET"
            else "NON_SECRET_VALUE_INCLUDED"
        )
        expected_value = (
            None
            if row["secrecy_class"] == "SECRET" or not present
            else raw_env[folded[key]]
        )
        if (
            entry["policy_row_digest"] != row["policy_row_digest"]
            or entry["source_class"] != row["source_class"]
            or entry["redaction_marker"] != expected_marker
            or entry["policy_authority_digests"]
            != row["policy_authority_digests"]
            or entry["non_secret_value"] != expected_value
        ):
            raise ConformanceError("ENVIRONMENT_POLICY_COMPLETENESS_MISMATCH")
        if (
            row["secrecy_class"] == "SECRET"
            and present
            and envelope is not None
            and not envelope["secret_proof_required"]
        ):
            raise ConformanceError("ENVIRONMENT_POLICY_COMPLETENESS_MISMATCH")


def validate_manifest_route(
    bundle: dict[str, Any],
    manifest: dict[str, Any],
    evaluation: dict[str, Any],
    capability: dict[str, Any],
    price: dict[str, Any],
    fallback: dict[str, Any],
    route: dict[str, Any],
) -> None:
    for name, definition, digest_field in (
        ("manifest", "ProviderManifestAuthorityV2", "provider_manifest_authority_digest"),
        ("evaluation", "EvaluationTimeAuthorityV1", "evaluation_time_authority_digest"),
        ("capability", "ProviderRouteCapabilityAuthorityV2", "capability_authority_digest"),
        ("price", "ProviderPriceAuthorityV2", "price_authority_digest"),
        ("fallback", "ProviderFallbackAuthorityV2", "fallback_authority_digest"),
        ("route", "ModelRouteV4", "model_route_digest"),
    ):
        record = locals()[name]
        schema_validate(bundle, definition, record)
        verify_seal(record, digest_field)
    if manifest["model_count"] != len(manifest["model_rows"]):
        raise ConformanceError("ROUTE_MODEL_MEMBERSHIP_MISMATCH")
    if manifest["tuple_count"] != len(manifest["route_tuples"]):
        raise ConformanceError("ROUTE_TUPLE_JOIN_MISMATCH")
    for row in manifest["model_rows"]:
        schema_validate(bundle, "ProviderManifestModelRowV2", row)
        verify_seal(row, "model_row_digest")
        model = row["exact_model_id"]
        if (
            not EXACT_MODEL_RE.fullmatch(model)
            or model.startswith("provider-default-")
            or model.startswith("auto-")
            or model.startswith("latest-")
        ):
            raise ConformanceError("MODEL_ALIAS_FORBIDDEN")
    for row in manifest["route_tuples"]:
        schema_validate(bundle, "ProviderManifestRouteTupleV2", row)
        verify_seal(row, "tuple_row_digest")
        expected = {
            "API_KEY": ("ANTHROPIC_API_KEY", "api_standard"),
            "STORED_SUBSCRIPTION": ("CLAUDE_CODE_OAUTH", "subscription"),
        }[row["account_class"]]
        if (row["auth_route"], row["service_tier"]) != expected:
            raise ConformanceError("ROUTE_TUPLE_JOIN_MISMATCH")
    manifest_observed = parse_utc(manifest["observed_utc"])
    evaluation_utc = parse_utc(evaluation["evaluation_utc"])
    if manifest_observed > evaluation_utc:
        raise ConformanceError("PROVIDER_MANIFEST_TIME_INVALID")
    model = next(
        (
            row for row in manifest["model_rows"]
            if row["model_row_digest"] == capability["model_row_digest"]
        ),
        None,
    )
    if model is None:
        raise ConformanceError("ROUTE_MODEL_MEMBERSHIP_MISMATCH")
    route_tuple = next(
        (
            row for row in manifest["route_tuples"]
            if row["tuple_row_digest"] == capability["tuple_row_digest"]
        ),
        None,
    )
    if route_tuple is None:
        raise ConformanceError("ROUTE_TUPLE_JOIN_MISMATCH")
    if (
        capability["provider_manifest_authority_digest"]
        != manifest["provider_manifest_authority_digest"]
        or capability["evaluation_time_authority_digest"]
        != evaluation["evaluation_time_authority_digest"]
        or capability["exact_model_id"] != model["exact_model_id"]
        or capability["effort_applicability"]
        != model["effort_applicability"]
        or capability["supported_efforts"] != model["supported_efforts"]
        or capability["supported_thinking_modes"]
        != model["supported_thinking_modes"]
    ):
        raise ConformanceError("ROUTE_MODEL_MEMBERSHIP_MISMATCH")
    valid_from = parse_utc(capability["valid_from_utc"])
    valid_until = parse_utc(capability["valid_until_utc"])
    if valid_from >= valid_until:
        raise ConformanceError("CAPABILITY_INTERVAL_INVALID")
    if evaluation_utc < valid_from:
        raise ConformanceError("CAPABILITY_NOT_YET_VALID")
    if evaluation_utc >= valid_until:
        raise ConformanceError("CAPABILITY_EXPIRED")
    if (
        price["provider_manifest_authority_digest"]
        != manifest["provider_manifest_authority_digest"]
        or price["model_row_digest"] != model["model_row_digest"]
        or price["evaluation_time_authority_digest"]
        != evaluation["evaluation_time_authority_digest"]
        or fallback["provider_manifest_authority_digest"]
        != manifest["provider_manifest_authority_digest"]
    ):
        raise ConformanceError("ROUTE_MODEL_MEMBERSHIP_MISMATCH")
    if route["model_row_digest"] != model["model_row_digest"]:
        raise ConformanceError("ROUTE_MODEL_MEMBERSHIP_MISMATCH")
    if (
        route["tuple_row_digest"] != route_tuple["tuple_row_digest"]
        or route["account_class"] != route_tuple["account_class"]
        or route["auth_route"] != route_tuple["auth_route"]
        or route["service_tier"] != route_tuple["service_tier"]
        or route["transport"] != route_tuple["transport"]
        or route["assurance_class"] != route_tuple["assurance_class"]
    ):
        raise ConformanceError("ROUTE_TUPLE_JOIN_MISMATCH")
    if (
        route["provider_manifest_authority_digest"]
        != manifest["provider_manifest_authority_digest"]
        or route["evaluation_time_authority_digest"]
        != evaluation["evaluation_time_authority_digest"]
        or route["capability_authority_digest"]
        != capability["capability_authority_digest"]
        or route["price_authority_digest"] != price["price_authority_digest"]
        or route["fallback_authority_digest"]
        != fallback["fallback_authority_digest"]
        or route["exact_requested_model_id"] != model["exact_model_id"]
    ):
        raise ConformanceError("ROUTE_MODEL_MEMBERSHIP_MISMATCH")
    applicable = route["effort_applicability"]
    if applicable != capability["effort_applicability"]:
        raise ConformanceError("ROUTE_EFFORT_APPLICABILITY_MISMATCH")
    if applicable == "NOT_APPLICABLE":
        if (
            route["requested_effort"] is not None
            or capability["supported_efforts"] != ["not_applicable"]
        ):
            raise ConformanceError("ROUTE_EFFORT_APPLICABILITY_MISMATCH")
    elif (
        route["requested_effort"] not in capability["supported_efforts"]
        or "not_applicable" in capability["supported_efforts"]
    ):
        raise ConformanceError("ROUTE_EFFORT_APPLICABILITY_MISMATCH")
    if (
        route["requested_thinking_mode"]
        not in capability["supported_thinking_modes"]
    ):
        raise ConformanceError("ROUTE_THINKING_MODE_MISMATCH")
    manual = route["requested_thinking_mode"] == "MANUAL_ON"
    if manual != (route["manual_thinking_budget_tokens"] is not None):
        raise ConformanceError("ROUTE_MANUAL_BUDGET_MISMATCH")


def require_equal(
    actual: Any, expected: Any, error: str
) -> None:
    if actual != expected:
        raise ConformanceError(error)


def validate_customization(
    bundle: dict[str, Any],
    root: dict[str, Any],
    predecessor: dict[str, Any],
    customization: dict[str, Any],
    projection: dict[str, Any],
    public_env: dict[str, Any],
    selection: dict[str, Any],
) -> None:
    schema_validate(
        bundle,
        "ClaudeExecutionCustomizationAuthorityV2",
        customization,
    )
    schema_validate(bundle, "CustomizationAuthorityProjectionV1", projection)
    verify_seal(customization, "customization_authority_digest")
    verify_seal(projection, "projection_digest")
    predecessor_values = (
        predecessor["loaded"]["customization_set_digest"],
        predecessor["effort"]["effort_authority_digest"],
        predecessor["thinking"]["thinking_authority_digest"],
    )
    if (
        projection["predecessor_loaded_customization_set_digest"],
        projection["predecessor_effort_authority_digest"],
        projection["predecessor_thinking_authority_digest"],
    ) != predecessor_values:
        raise ConformanceError("CUSTOMIZATION_PREDECESSOR_JOIN_MISMATCH")
    if (
        customization["loaded_customization_set_digest"],
        customization["effort_authority_digest"],
        customization["thinking_authority_digest"],
    ) != predecessor_values:
        raise ConformanceError("CUSTOMIZATION_PREDECESSOR_JOIN_MISMATCH")
    if (
        projection["successor_customization_authority_digest"]
        != customization["customization_authority_digest"]
        or customization["routing_root_digest"] != root["routing_root_digest"]
        or customization["public_materialized_environment_digest"]
        != public_env["public_materialized_environment_digest"]
    ):
        raise ConformanceError("CUSTOMIZATION_SUCCESSOR_JOIN_MISMATCH")
    for field in (
        "effort_applicability",
        "requested_effort",
        "requested_thinking_mode",
        "manual_thinking_budget_tokens",
        "materialized_argv_digest",
        "public_materialized_environment_digest",
        "provider_evidence_field_authority_digest",
    ):
        if customization[field] != selection[field]:
            raise ConformanceError("CUSTOMIZATION_ROUTE_JOIN_MISMATCH")
    if customization["effort_applicability"] == "NOT_APPLICABLE":
        if customization["requested_effort"] is not None:
            raise ConformanceError("ROUTE_EFFORT_APPLICABILITY_MISMATCH")
    elif customization["requested_effort"] is None:
        raise ConformanceError("ROUTE_EFFORT_APPLICABILITY_MISMATCH")
    manual = customization["requested_thinking_mode"] == "MANUAL_ON"
    if manual != (
        customization["manual_thinking_budget_tokens"] is not None
    ):
        raise ConformanceError("ROUTE_MANUAL_BUDGET_MISMATCH")


def validate_root(records: dict[str, Any]) -> None:
    root = records["root"]
    predecessor = records["predecessor"]
    if root["routing_root_digest"] != records["frozen_root_digest"]:
        raise ConformanceError("ROOT_AUTHORITY_JOIN_MISMATCH")
    expected = (
        (
            "loaded_customization_set_digest",
            predecessor["loaded"]["customization_set_digest"],
        ),
        (
            "effort_authority_digest",
            predecessor["effort"]["effort_authority_digest"],
        ),
        (
            "thinking_authority_digest",
            predecessor["thinking"]["thinking_authority_digest"],
        ),
        (
            "profile_semantics_authority_digest",
            records["semantics"]["semantics_authority_digest"],
        ),
        (
            "environment_policy_authority_digest",
            records["env_policy"]["environment_policy_authority_digest"],
        ),
        (
            "provider_manifest_authority_digest",
            records["manifest"]["provider_manifest_authority_digest"],
        ),
        (
            "evaluation_time_authority_digest",
            records["evaluation"]["evaluation_time_authority_digest"],
        ),
        (
            "route_selection_authority_digest",
            records["selection"]["route_selection_authority_digest"],
        ),
    )
    for field, value in expected:
        if root[field] != value:
            raise ConformanceError("ROOT_AUTHORITY_JOIN_MISMATCH")


def validate_route_selection(records: dict[str, Any]) -> None:
    selection = records["selection"]
    model = next(
        (
            row for row in records["manifest"]["model_rows"]
            if row["model_row_digest"] == selection["model_row_digest"]
        ),
        None,
    )
    route_tuple = next(
        (
            row for row in records["manifest"]["route_tuples"]
            if row["tuple_row_digest"] == selection["tuple_row_digest"]
        ),
        None,
    )
    if model is None:
        raise ConformanceError("ROUTE_MODEL_MEMBERSHIP_MISMATCH")
    if route_tuple is None:
        raise ConformanceError("ROUTE_TUPLE_JOIN_MISMATCH")
    expected = (
        (
            "execution_axes_digest",
            records["axes"]["execution_axes_digest"],
        ),
        (
            "profile_semantics_authority_digest",
            records["semantics"]["semantics_authority_digest"],
        ),
        (
            "profile_registry_digest",
            records["registry"]["profile_registry_digest"],
        ),
        (
            "provider_profile_digest",
            records["profile"]["provider_profile_digest"],
        ),
        (
            "semantics_row_digest",
            records["profile"]["semantics_row_digest"],
        ),
        (
            "public_materialized_environment_digest",
            records["public_env"]["public_materialized_environment_digest"],
        ),
        (
            "provider_manifest_authority_digest",
            records["manifest"]["provider_manifest_authority_digest"],
        ),
        (
            "evaluation_time_authority_digest",
            records["evaluation"]["evaluation_time_authority_digest"],
        ),
        (
            "capability_authority_digest",
            records["capability"]["capability_authority_digest"],
        ),
        ("price_authority_digest", records["price"]["price_authority_digest"]),
        (
            "fallback_authority_digest",
            records["fallback"]["fallback_authority_digest"],
        ),
        (
            "provider_evidence_field_authority_digest",
            EVIDENCE_FIELD_AUTHORITY_DIGEST,
        ),
        ("secret_proof_policy_digest", SECRET_PROOF_POLICY_DIGEST),
        ("work_plan_digest", records["transaction"]["work_plan_digest"]),
        (
            "phase_io_launch_digest",
            records["transaction"]["phase_io_launch_digest"],
        ),
        ("exact_requested_model_id", model["exact_model_id"]),
        ("effort_applicability", model["effort_applicability"]),
        ("account_class", route_tuple["account_class"]),
        ("auth_route", route_tuple["auth_route"]),
        ("service_tier", route_tuple["service_tier"]),
        ("transport", route_tuple["transport"]),
        ("assurance_class", route_tuple["assurance_class"]),
    )
    for field, value in expected:
        if selection[field] != value:
            raise ConformanceError("ROUTE_SELECTION_JOIN_MISMATCH")
    if (
        selection["requested_thinking_mode"]
        not in records["capability"]["supported_thinking_modes"]
    ):
        raise ConformanceError("ROUTE_SELECTION_JOIN_MISMATCH")
    predecessor = records["predecessor"]
    if (
        model["model_family"]
        != predecessor["effort"]["exact_model_id"]
        or model["model_family"]
        != predecessor["thinking"]["exact_model_id"]
        or selection["requested_thinking_mode"]
        != predecessor["thinking"]["requested_thinking_mode"]
        or selection["manual_thinking_budget_tokens"]
        != predecessor["thinking"]["manual_thinking_budget_tokens"]
    ):
        raise ConformanceError("CUSTOMIZATION_PREDECESSOR_JOIN_MISMATCH")
    if selection["effort_applicability"] == "NOT_APPLICABLE":
        if (
            selection["requested_effort"] is not None
            or model["supported_efforts"] != ["not_applicable"]
        ):
            raise ConformanceError("ROUTE_EFFORT_APPLICABILITY_MISMATCH")
    elif (
        selection["requested_effort"] not in model["supported_efforts"]
        or selection["requested_effort"]
        != predecessor["effort"]["requested_effort"]
    ):
        raise ConformanceError("ROUTE_EFFORT_APPLICABILITY_MISMATCH")
    manual = selection["requested_thinking_mode"] == "MANUAL_ON"
    if manual != (
        selection["manual_thinking_budget_tokens"] is not None
    ):
        raise ConformanceError("ROUTE_MANUAL_BUDGET_MISMATCH")


def validate_cross_record(records: dict[str, Any]) -> None:
    root = records["root"]
    axes = records["axes"]
    semantics = records["semantics"]
    registry = records["registry"]
    profile = records["profile"]
    customization = records["customization"]
    route = records["route"]
    request = records["request"]
    work = records["work"]
    phaseio = records["phaseio"]
    control = records["control"]
    launch = records["launch"]
    arm = records["arm"]
    attempt = records["attempt"]
    envelope = records["envelope"]
    predecessor_v3 = records["predecessor_envelope"]
    consumed = records["consumed"]
    observation = records["observation"]
    public_env = records["public_env"]
    secret_policy = records["secret_policy"]
    transaction = records["transaction"]
    selection = records["selection"]

    require_equal(
        route["routing_root_digest"],
        root["routing_root_digest"],
        "ROUTE_ROOT_JOIN_MISMATCH",
    )
    require_equal(
        route["execution_axes_digest"],
        axes["execution_axes_digest"],
        "ROUTE_AXES_JOIN_MISMATCH",
    )
    require_equal(
        route["route_selection_authority_digest"],
        selection["route_selection_authority_digest"],
        "ROUTE_SELECTION_JOIN_MISMATCH",
    )
    for field, expected in (
        (
            "effort_applicability",
            customization["effort_applicability"],
        ),
        ("requested_effort", customization["requested_effort"]),
        (
            "requested_thinking_mode",
            customization["requested_thinking_mode"],
        ),
        (
            "manual_thinking_budget_tokens",
            customization["manual_thinking_budget_tokens"],
        ),
    ):
        require_equal(
            route[field], expected, "CUSTOMIZATION_ROUTE_JOIN_MISMATCH"
        )

    require_equal(
        request["routing_root_digest"],
        root["routing_root_digest"],
        "REQUEST_ROOT_JOIN_MISMATCH",
    )
    require_equal(
        request["execution_axes_digest"],
        axes["execution_axes_digest"],
        "REQUEST_AXES_JOIN_MISMATCH",
    )
    require_equal(
        request["semantic_plan_digest"],
        root["semantic_plan_digest"],
        "REQUEST_SEMANTIC_PLAN_JOIN_MISMATCH",
    )
    require_equal(
        request["profile_semantics_authority_digest"],
        semantics["semantics_authority_digest"],
        "REQUEST_PROFILE_SEMANTICS_JOIN_MISMATCH",
    )
    require_equal(
        request["profile_registry_digest"],
        registry["profile_registry_digest"],
        "REQUEST_PROFILE_REGISTRY_JOIN_MISMATCH",
    )
    require_equal(
        request["provider_profile_digest"],
        profile["provider_profile_digest"],
        "REQUEST_PROFILE_JOIN_MISMATCH",
    )
    require_equal(
        request["semantics_row_digest"],
        profile["semantics_row_digest"],
        "REQUEST_PROFILE_SEMANTICS_JOIN_MISMATCH",
    )
    require_equal(
        request["customization_authority_digest"],
        customization["customization_authority_digest"],
        "REQUEST_CUSTOMIZATION_JOIN_MISMATCH",
    )
    require_equal(
        request["model_route_digest"],
        route["model_route_digest"],
        "REQUEST_ROUTE_JOIN_MISMATCH",
    )
    for field, error in (
        ("arm_family_digest", "REQUEST_ARM_FAMILY_JOIN_MISMATCH"),
        (
            "source_snapshot_authority_digest",
            "REQUEST_SOURCE_JOIN_MISMATCH",
        ),
        ("prompt_authority_digest", "REQUEST_PROMPT_JOIN_MISMATCH"),
        (
            "methodology_authority_digest",
            "REQUEST_METHODOLOGY_JOIN_MISMATCH",
        ),
        (
            "program_facts_authority_digest",
            "REQUEST_PROGRAM_FACTS_JOIN_MISMATCH",
        ),
        (
            "tool_policy_authority_digest",
            "REQUEST_TOOL_POLICY_JOIN_MISMATCH",
        ),
        (
            "work_plan_contract_authority_digest",
            "REQUEST_WORKPLAN_CONTRACT_JOIN_MISMATCH",
        ),
        (
            "phase_io_contract_digest",
            "REQUEST_PHASEIO_CONTRACT_JOIN_MISMATCH",
        ),
        ("output_contract_digest", "REQUEST_OUTPUT_JOIN_MISMATCH"),
    ):
        require_equal(request[field], root[field], error)
    require_equal(
        request["context_budget_digest"],
        route["context_budget_digest"],
        "REQUEST_CONTEXT_BUDGET_JOIN_MISMATCH",
    )
    require_equal(
        request["budget_authority_digest"],
        route["budget_authority_digest"],
        "REQUEST_BUDGET_JOIN_MISMATCH",
    )
    require_equal(
        work["request_digest"],
        request["request_digest"],
        "WORKPLAN_REQUEST_JOIN_MISMATCH",
    )
    require_equal(
        work["semantic_plan_digest"],
        root["semantic_plan_digest"],
        "WORKPLAN_SEMANTIC_PLAN_JOIN_MISMATCH",
    )
    require_equal(
        work["profile_semantics_authority_digest"],
        semantics["semantics_authority_digest"],
        "WORKPLAN_PROFILE_SEMANTICS_JOIN_MISMATCH",
    )
    for field, expected, error in (
        (
            "routing_root_digest",
            root["routing_root_digest"],
            "WORKPLAN_ROOT_JOIN_MISMATCH",
        ),
        (
            "execution_axes_digest",
            axes["execution_axes_digest"],
            "WORKPLAN_AXES_JOIN_MISMATCH",
        ),
        (
            "provider_profile_digest",
            profile["provider_profile_digest"],
            "WORKPLAN_PROFILE_JOIN_MISMATCH",
        ),
        (
            "customization_authority_digest",
            customization["customization_authority_digest"],
            "WORKPLAN_CUSTOMIZATION_JOIN_MISMATCH",
        ),
        (
            "model_route_digest",
            route["model_route_digest"],
            "WORKPLAN_ROUTE_JOIN_MISMATCH",
        ),
        (
            "source_snapshot_authority_digest",
            root["source_snapshot_authority_digest"],
            "WORKPLAN_SOURCE_JOIN_MISMATCH",
        ),
        (
            "methodology_authority_digest",
            root["methodology_authority_digest"],
            "WORKPLAN_METHODOLOGY_JOIN_MISMATCH",
        ),
        (
            "program_facts_authority_digest",
            root["program_facts_authority_digest"],
            "WORKPLAN_PROGRAM_FACTS_JOIN_MISMATCH",
        ),
        (
            "output_contract_digest",
            root["output_contract_digest"],
            "WORKPLAN_OUTPUT_JOIN_MISMATCH",
        ),
    ):
        require_equal(work[field], expected, error)
    require_equal(
        phaseio["request_digest"],
        request["request_digest"],
        "PHASEIO_REQUEST_JOIN_MISMATCH",
    )
    require_equal(
        phaseio["work_plan_binding_digest"],
        work["work_plan_binding_digest"],
        "PHASEIO_WORKPLAN_JOIN_MISMATCH",
    )
    for field, expected, error in (
        (
            "routing_root_digest",
            root["routing_root_digest"],
            "PHASEIO_ROOT_JOIN_MISMATCH",
        ),
        (
            "phase_io_contract_digest",
            root["phase_io_contract_digest"],
            "PHASEIO_CONTRACT_JOIN_MISMATCH",
        ),
        (
            "customization_authority_digest",
            customization["customization_authority_digest"],
            "PHASEIO_CUSTOMIZATION_JOIN_MISMATCH",
        ),
        (
            "model_route_digest",
            route["model_route_digest"],
            "PHASEIO_ROUTE_JOIN_MISMATCH",
        ),
        (
            "source_snapshot_authority_digest",
            root["source_snapshot_authority_digest"],
            "PHASEIO_SOURCE_JOIN_MISMATCH",
        ),
        (
            "methodology_authority_digest",
            root["methodology_authority_digest"],
            "PHASEIO_METHODOLOGY_JOIN_MISMATCH",
        ),
        (
            "program_facts_authority_digest",
            root["program_facts_authority_digest"],
            "PHASEIO_PROGRAM_FACTS_JOIN_MISMATCH",
        ),
        (
            "output_contract_digest",
            root["output_contract_digest"],
            "PHASEIO_OUTPUT_JOIN_MISMATCH",
        ),
    ):
        require_equal(phaseio[field], expected, error)
    for field, expected, error in (
        (
            "routing_root_digest",
            root["routing_root_digest"],
            "CONTROL_ROOT_JOIN_MISMATCH",
        ),
        (
            "request_digest",
            request["request_digest"],
            "CONTROL_REQUEST_JOIN_MISMATCH",
        ),
        (
            "semantic_plan_digest",
            root["semantic_plan_digest"],
            "CONTROL_SEMANTIC_PLAN_JOIN_MISMATCH",
        ),
        (
            "execution_axes_digest",
            axes["execution_axes_digest"],
            "CONTROL_AXES_JOIN_MISMATCH",
        ),
        (
            "profile_semantics_authority_digest",
            semantics["semantics_authority_digest"],
            "CONTROL_PROFILE_SEMANTICS_JOIN_MISMATCH",
        ),
        (
            "provider_profile_digest",
            profile["provider_profile_digest"],
            "CONTROL_PROFILE_JOIN_MISMATCH",
        ),
        (
            "customization_authority_digest",
            customization["customization_authority_digest"],
            "CONTROL_CUSTOMIZATION_JOIN_MISMATCH",
        ),
        (
            "loaded_customization_set_digest",
            root["loaded_customization_set_digest"],
            "CONTROL_CUSTOMIZATION_JOIN_MISMATCH",
        ),
        (
            "effort_authority_digest",
            root["effort_authority_digest"],
            "CONTROL_EFFORT_AUTHORITY_JOIN_MISMATCH",
        ),
        (
            "thinking_authority_digest",
            root["thinking_authority_digest"],
            "CONTROL_THINKING_AUTHORITY_JOIN_MISMATCH",
        ),
        (
            "model_route_digest",
            route["model_route_digest"],
            "CONTROL_ROUTE_JOIN_MISMATCH",
        ),
        (
            "exact_model_id",
            route["exact_requested_model_id"],
            "CONTROL_MODEL_JOIN_MISMATCH",
        ),
        (
            "effort_applicability",
            route["effort_applicability"],
            "CONTROL_EFFORT_JOIN_MISMATCH",
        ),
        (
            "requested_effort",
            route["requested_effort"],
            "CONTROL_EFFORT_JOIN_MISMATCH",
        ),
        (
            "requested_thinking_mode",
            route["requested_thinking_mode"],
            "CONTROL_THINKING_JOIN_MISMATCH",
        ),
        (
            "manual_thinking_budget_tokens",
            route["manual_thinking_budget_tokens"],
            "CONTROL_THINKING_JOIN_MISMATCH",
        ),
        (
            "materialized_argv_digest",
            customization["materialized_argv_digest"],
            "CONTROL_CUSTOMIZATION_JOIN_MISMATCH",
        ),
        (
            "public_materialized_environment_digest",
            records["public_env"]["public_materialized_environment_digest"],
            "CONTROL_ENVIRONMENT_JOIN_MISMATCH",
        ),
        (
            "environment_policy_authority_digest",
            root["environment_policy_authority_digest"],
            "CONTROL_ENVIRONMENT_POLICY_JOIN_MISMATCH",
        ),
        (
            "secret_proof_policy_digest",
            secret_policy["secret_proof_policy_digest"],
            "CONTROL_SECRET_PROOF_POLICY_JOIN_MISMATCH",
        ),
    ):
        require_equal(control[field], expected, error)

    launch_edges = (
        ("routing_root_digest", root["routing_root_digest"], "LAUNCH_ROOT_JOIN_MISMATCH"),
        ("semantic_plan_digest", root["semantic_plan_digest"], "LAUNCH_SEMANTIC_PLAN_JOIN_MISMATCH"),
        ("arm_family_digest", root["arm_family_digest"], "LAUNCH_INPUT_AUTHORITY_JOIN_MISMATCH"),
        ("request_digest", request["request_digest"], "LAUNCH_REQUEST_JOIN_MISMATCH"),
        ("execution_axes_digest", axes["execution_axes_digest"], "LAUNCH_AXES_JOIN_MISMATCH"),
        ("profile_semantics_authority_digest", semantics["semantics_authority_digest"], "LAUNCH_PROFILE_SEMANTICS_JOIN_MISMATCH"),
        ("provider_profile_digest", profile["provider_profile_digest"], "LAUNCH_PROFILE_JOIN_MISMATCH"),
        ("customization_authority_digest", customization["customization_authority_digest"], "LAUNCH_CUSTOMIZATION_JOIN_MISMATCH"),
        ("loaded_customization_set_digest", root["loaded_customization_set_digest"], "LAUNCH_CUSTOMIZATION_JOIN_MISMATCH"),
        ("effort_authority_digest", root["effort_authority_digest"], "LAUNCH_EFFORT_AUTHORITY_JOIN_MISMATCH"),
        ("thinking_authority_digest", root["thinking_authority_digest"], "LAUNCH_THINKING_AUTHORITY_JOIN_MISMATCH"),
        ("model_route_digest", route["model_route_digest"], "LAUNCH_ROUTE_JOIN_MISMATCH"),
        ("budget_authority_digest", route["budget_authority_digest"], "LAUNCH_BUDGET_JOIN_MISMATCH"),
        ("control_vector_digest", control["control_vector_digest"], "LAUNCH_CONTROL_JOIN_MISMATCH"),
        ("work_plan_binding_digest", work["work_plan_binding_digest"], "LAUNCH_WORKPLAN_JOIN_MISMATCH"),
        ("phase_io_binding_digest", phaseio["phase_io_binding_digest"], "LAUNCH_PHASEIO_JOIN_MISMATCH"),
        ("tool_policy_digest", root["tool_policy_authority_digest"], "LAUNCH_TOOL_POLICY_JOIN_MISMATCH"),
    )
    for field, expected, error in launch_edges:
        require_equal(launch[field], expected, error)
    for field, expected, error in (
        (
            "generation_reservation_event_digest",
            transaction["generation_reservation_event_digest"],
            "LAUNCH_GENERATION_RESERVATION_JOIN_MISMATCH",
        ),
        (
            "generation",
            transaction["generation"],
            "LAUNCH_GENERATION_JOIN_MISMATCH",
        ),
    ):
        require_equal(launch[field], expected, error)
    require_equal(
        work["work_plan_digest"],
        transaction["work_plan_digest"],
        "WORKPLAN_PARENT_JOIN_MISMATCH",
    )
    require_equal(
        phaseio["phase_io_launch_digest"],
        transaction["phase_io_launch_digest"],
        "PHASEIO_LAUNCH_JOIN_MISMATCH",
    )
    arm_edges = (
        ("routing_root_digest", root["routing_root_digest"], "ARM_ROOT_JOIN_MISMATCH"),
        ("arm_family_digest", root["arm_family_digest"], "ARM_FAMILY_JOIN_MISMATCH"),
        ("generation", launch["generation"], "ARM_GENERATION_JOIN_MISMATCH"),
        ("semantic_plan_digest", root["semantic_plan_digest"], "ARM_PLAN_JOIN_MISMATCH"),
        ("request_digest", request["request_digest"], "ARM_REQUEST_JOIN_MISMATCH"),
        ("execution_axes_digest", axes["execution_axes_digest"], "ARM_AXES_JOIN_MISMATCH"),
        ("profile_semantics_authority_digest", semantics["semantics_authority_digest"], "ARM_PROFILE_SEMANTICS_JOIN_MISMATCH"),
        ("provider_profile_digest", profile["provider_profile_digest"], "ARM_PROFILE_JOIN_MISMATCH"),
        ("customization_authority_digest", customization["customization_authority_digest"], "ARM_CUSTOMIZATION_JOIN_MISMATCH"),
        ("model_route_digest", route["model_route_digest"], "ARM_ROUTE_JOIN_MISMATCH"),
        ("budget_authority_digest", route["budget_authority_digest"], "ARM_BUDGET_JOIN_MISMATCH"),
        ("launch_authority_digest", launch["launch_authority_digest"], "ARM_LAUNCH_JOIN_MISMATCH"),
        ("work_plan_binding_digest", work["work_plan_binding_digest"], "ARM_WORKPLAN_JOIN_MISMATCH"),
        ("phase_io_binding_digest", phaseio["phase_io_binding_digest"], "ARM_PHASEIO_JOIN_MISMATCH"),
    )
    for field, expected, error in arm_edges:
        require_equal(arm[field], expected, error)
    attempt_edges = (
        ("routing_root_digest", root["routing_root_digest"], "ATTEMPT_ROOT_JOIN_MISMATCH"),
        ("backend_arm_digest", arm["backend_arm_digest"], "ATTEMPT_ARM_JOIN_MISMATCH"),
        ("arm_family_digest", root["arm_family_digest"], "ATTEMPT_FAMILY_JOIN_MISMATCH"),
        ("generation", launch["generation"], "ATTEMPT_GENERATION_JOIN_MISMATCH"),
        ("request_digest", request["request_digest"], "ATTEMPT_REQUEST_JOIN_MISMATCH"),
        ("profile_semantics_authority_digest", semantics["semantics_authority_digest"], "ATTEMPT_PROFILE_SEMANTICS_JOIN_MISMATCH"),
        ("provider_profile_digest", profile["provider_profile_digest"], "ATTEMPT_PROFILE_JOIN_MISMATCH"),
        ("customization_authority_digest", customization["customization_authority_digest"], "ATTEMPT_CUSTOMIZATION_JOIN_MISMATCH"),
        ("model_route_digest", route["model_route_digest"], "ATTEMPT_ROUTE_JOIN_MISMATCH"),
        ("launch_authority_digest", launch["launch_authority_digest"], "ATTEMPT_LAUNCH_JOIN_MISMATCH"),
    )
    for field, expected, error in attempt_edges:
        require_equal(attempt[field], expected, error)
    envelope_edges = (
        ("routing_root_digest", root["routing_root_digest"], "ENVELOPE_ROOT_JOIN_MISMATCH"),
        ("execution_attempt_digest", attempt["execution_attempt_digest"], "ENVELOPE_ATTEMPT_JOIN_MISMATCH"),
        ("backend_arm_digest", arm["backend_arm_digest"], "ENVELOPE_ARM_JOIN_MISMATCH"),
        ("launch_authority_digest", launch["launch_authority_digest"], "ENVELOPE_LAUNCH_JOIN_MISMATCH"),
        ("request_digest", request["request_digest"], "ENVELOPE_REQUEST_JOIN_MISMATCH"),
        ("control_vector_digest", control["control_vector_digest"], "ENVELOPE_CONTROL_JOIN_MISMATCH"),
        ("customization_authority_digest", customization["customization_authority_digest"], "ENVELOPE_CUSTOMIZATION_JOIN_MISMATCH"),
        ("materialized_argv_digest", control["materialized_argv_digest"], "ENVELOPE_ARGV_JOIN_MISMATCH"),
        ("public_materialized_environment_digest", public_env["public_materialized_environment_digest"], "ENVELOPE_ENVIRONMENT_JOIN_MISMATCH"),
        ("environment_policy_authority_digest", root["environment_policy_authority_digest"], "ENVELOPE_ENVIRONMENT_POLICY_JOIN_MISMATCH"),
        ("secret_proof_policy_digest", secret_policy["secret_proof_policy_digest"], "ENVELOPE_SECRET_POLICY_JOIN_MISMATCH"),
    )
    for field, expected, error in envelope_edges:
        require_equal(envelope[field], expected, error)
    for field, expected, error in (
        (
            "attempt_reservation_event_digest",
            transaction["attempt_reservation_event_digest"],
            "ENVELOPE_RESERVATION_EVENT_JOIN_MISMATCH",
        ),
        (
            "attempt_resource_entry_digest",
            transaction["attempt_resource_entry_digest"],
            "ENVELOPE_RESOURCE_ENTRY_JOIN_MISMATCH",
        ),
        (
            "resource_ledger_digest_after_attempt_reservation",
            transaction[
                "resource_ledger_digest_after_attempt_reservation"
            ],
            "ENVELOPE_RESOURCE_LEDGER_JOIN_MISMATCH",
        ),
        (
            "materialized_stdin_prompt_digest",
            transaction["materialized_stdin_prompt_digest"],
            "ENVELOPE_STDIN_JOIN_MISMATCH",
        ),
        (
            "working_directory_identity_digest",
            transaction["working_directory_identity_digest"],
            "ENVELOPE_WORKDIR_JOIN_MISMATCH",
        ),
        (
            "prepared_utc",
            transaction["prepared_utc"],
            "ENVELOPE_PREPARED_TIME_JOIN_MISMATCH",
        ),
    ):
        require_equal(envelope[field], expected, error)
    expected_v3 = predecessor_envelope_v3(
        launch, request, control, public_env, arm, attempt
    )
    if (
        predecessor_v3 != expected_v3
        or envelope["predecessor_attempt_launch_v3_digest"]
        != expected_v3["attempt_launch_digest"]
    ):
        raise ConformanceError("ENVELOPE_PREDECESSOR_PROJECTION_MISMATCH")
    for field, expected, error in (
        ("attempt_launch_digest", envelope["attempt_launch_digest"], "CONSUMED_ENVELOPE_JOIN_MISMATCH"),
        ("predecessor_attempt_launch_v3_digest", envelope["predecessor_attempt_launch_v3_digest"], "CONSUMED_PREDECESSOR_JOIN_MISMATCH"),
        ("execution_attempt_digest", attempt["execution_attempt_digest"], "CONSUMED_ATTEMPT_JOIN_MISMATCH"),
        ("launch_consumption_event_digest", transaction["launch_consumption_event_digest"], "CONSUMED_EVENT_JOIN_MISMATCH"),
        ("consumed_attempt_resource_entry_digest", transaction["consumed_attempt_resource_entry_digest"], "CONSUMED_RESOURCE_ENTRY_JOIN_MISMATCH"),
        ("resource_ledger_digest_after_launch_consumption", transaction["resource_ledger_digest_after_launch_consumption"], "CONSUMED_LEDGER_JOIN_MISMATCH"),
        ("consume_cas_revision", transaction["consume_cas_revision"], "CONSUMED_CAS_JOIN_MISMATCH"),
    ):
        require_equal(consumed[field], expected, error)
    observation_edges = (
        ("routing_root_digest", root["routing_root_digest"], "OBSERVATION_ROOT_JOIN_MISMATCH"),
        ("execution_attempt_digest", attempt["execution_attempt_digest"], "OBSERVATION_ATTEMPT_JOIN_MISMATCH"),
        ("backend_arm_digest", arm["backend_arm_digest"], "OBSERVATION_ARM_JOIN_MISMATCH"),
        ("request_digest", request["request_digest"], "OBSERVATION_REQUEST_JOIN_MISMATCH"),
        ("execution_axes_digest", axes["execution_axes_digest"], "OBSERVATION_AXES_JOIN_MISMATCH"),
        ("profile_semantics_authority_digest", semantics["semantics_authority_digest"], "OBSERVATION_PROFILE_SEMANTICS_JOIN_MISMATCH"),
        ("provider_profile_digest", profile["provider_profile_digest"], "OBSERVATION_PROFILE_JOIN_MISMATCH"),
        ("customization_authority_digest", customization["customization_authority_digest"], "OBSERVATION_CUSTOMIZATION_JOIN_MISMATCH"),
        ("loaded_customization_set_digest", root["loaded_customization_set_digest"], "OBSERVATION_CUSTOMIZATION_JOIN_MISMATCH"),
        ("effort_authority_digest", root["effort_authority_digest"], "OBSERVATION_EFFORT_AUTHORITY_JOIN_MISMATCH"),
        ("thinking_authority_digest", root["thinking_authority_digest"], "OBSERVATION_THINKING_AUTHORITY_JOIN_MISMATCH"),
        ("model_route_digest", route["model_route_digest"], "OBSERVATION_ROUTE_JOIN_MISMATCH"),
        ("attempt_launch_digest", envelope["attempt_launch_digest"], "OBSERVATION_ENVELOPE_JOIN_MISMATCH"),
        ("consumed_launch_digest", consumed["consumed_launch_digest"], "OBSERVATION_CONSUMED_JOIN_MISMATCH"),
        ("public_materialized_environment_digest", public_env["public_materialized_environment_digest"], "OBSERVATION_ENVIRONMENT_JOIN_MISMATCH"),
    )
    for field, expected, error in observation_edges:
        require_equal(observation[field], expected, error)


def validate_observation_evidence(
    bundle: dict[str, Any],
    observation: dict[str, Any],
    evidence: dict[str, Any],
) -> None:
    schema_validate(
        bundle, "ProviderObservationEvidenceManifestV2", evidence
    )
    verify_seal(evidence, "evidence_manifest_digest")
    if (
        observation["evidence_manifest_digest"]
        != evidence["evidence_manifest_digest"]
        or evidence["claim_count"] != len(evidence["field_claims"])
    ):
        raise ConformanceError("OBSERVATION_EVIDENCE_MEMBERSHIP_MISMATCH")
    claims: dict[str, dict[str, Any]] = {}
    for claim in evidence["field_claims"]:
        schema_validate(bundle, "ProviderEvidenceFieldClaimV3", claim)
        verify_seal(claim, "field_claim_digest")
        if claim["field_name"] in claims:
            raise ConformanceError("OBSERVATION_EVIDENCE_MEMBERSHIP_MISMATCH")
        claims[claim["field_name"]] = claim
    expected = {
        "effective_model": (
            observation["observed_effective_model_id"],
            observation["model_field_claim_digest"],
        ),
        "effective_effort": (
            observation["observed_effective_effort"],
            observation["effort_field_claim_digest"],
        ),
        "thinking_state": (
            observation["observed_thinking_state"],
            observation["thinking_field_claim_digest"],
        ),
        "fallback_state": (
            observation["fallback_observation_state"],
            observation["fallback_field_claim_digest"],
        ),
        "terminal_category": (
            observation["provider_terminal_category"],
            observation["terminal_field_claim_digest"],
        ),
    }
    if set(claims) != set(expected):
        raise ConformanceError("OBSERVATION_EVIDENCE_MEMBERSHIP_MISMATCH")
    for field, (value, digest) in expected.items():
        claim = claims[field]
        if (
            claim["field_claim_digest"] != digest
            or claim["observed_value_digest"]
            != sha256_bytes(canonical_bytes(value))
            or not claim["raw_artifact_digests"]
        ):
            raise ConformanceError("OBSERVATION_EVIDENCE_MEMBERSHIP_MISMATCH")
    raw = sorted(
        {
            digest
            for claim in claims.values()
            for digest in claim["raw_artifact_digests"]
        }
    )
    if (
        evidence["raw_artifact_digests"] != raw
        or evidence["raw_artifact_union_digest"]
        != sha256_bytes(canonical_bytes(raw))
        or observation["thinking_observation_evidence_digest"]
        not in claims["thinking_state"]["raw_artifact_digests"]
    ):
        raise ConformanceError("OBSERVATION_EVIDENCE_MEMBERSHIP_MISMATCH")


class EphemeralSecretProofV2:
    __slots__ = ("_envelope_digest", "_predecessor_digest", "_proof")

    def __init__(
        self, envelope_digest: str, predecessor_digest: str, proof: bytes
    ) -> None:
        object.__setattr__(self, "_envelope_digest", envelope_digest)
        object.__setattr__(self, "_predecessor_digest", predecessor_digest)
        object.__setattr__(self, "_proof", bytes(proof))

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("EphemeralSecretProofV2 is immutable")

    def __repr__(self) -> str:
        return "EphemeralSecretProofV2(<redacted>)"

    def __reduce__(self) -> Any:
        raise TypeError("EphemeralSecretProofV2 is not serializable")

    def __copy__(self) -> Any:
        raise TypeError("EphemeralSecretProofV2 is not copyable")

    def __deepcopy__(self, _memo: Any) -> Any:
        raise TypeError("EphemeralSecretProofV2 is not copyable")

    @staticmethod
    def _validate_envelope(
        envelope: dict[str, Any], predecessor: dict[str, Any] | None
    ) -> None:
        if predecessor is None:
            raise ConformanceError("PROOF_ENVELOPE_REQUIRED")
        if (
            envelope.get("schema") != "plamen.attempt-launch-envelope.v4"
            or envelope.get("attempt_launch_version") != 4
        ):
            raise ConformanceError("PROOF_ENVELOPE_VERSION_MISMATCH")
        verify_seal(envelope, "attempt_launch_digest")
        if (
            predecessor.get("schema")
            != "plamen.attempt-launch-envelope.v3"
            or predecessor.get("attempt_launch_version") != 3
        ):
            raise ConformanceError("PROOF_ENVELOPE_VERSION_MISMATCH")
        verify_seal(predecessor, "attempt_launch_digest")
        if (
            envelope.get("predecessor_attempt_launch_v3_digest")
            != predecessor.get("attempt_launch_digest")
        ):
            raise ConformanceError("PROOF_ENVELOPE_MISMATCH")

    @staticmethod
    def _payload(
        envelope: dict[str, Any],
        predecessor: dict[str, Any] | None,
        policy: dict[str, Any],
        raw_env: dict[str, str],
        process_nonce: bytes,
        object_nonce: bytes,
    ) -> bytes:
        EphemeralSecretProofV2._validate_envelope(envelope, predecessor)
        assert predecessor is not None
        if len(process_nonce) != 32 or len(object_nonce) != 32:
            raise ConformanceError("PROOF_NONCE_LENGTH_INVALID")
        pieces = [
            PROOF_DOMAIN,
            length_prefix(canonical_bytes(envelope)),
            length_prefix(canonical_bytes(predecessor)),
            length_prefix(process_nonce),
            length_prefix(object_nonce),
        ]
        windows = policy.get("host_family") == "windows"
        folded: dict[str, tuple[str, str]] = {}
        for name, value in raw_env.items():
            key = name.upper() if windows else name
            if key in folded:
                raise ConformanceError("ENVIRONMENT_NAME_COLLISION")
            folded[key] = (name, value)
        for row in policy["rows"]:
            if row["secrecy_class"] != "SECRET":
                continue
            key = row["name"].upper() if windows else row["name"]
            match = folded.get(key)
            if match is None:
                raise ConformanceError("ENVIRONMENT_PRESENCE_MISMATCH")
            pieces.append(length_prefix(row["name"].encode("utf-8")))
            pieces.append(length_prefix(match[1].encode("utf-8")))
        return b"".join(pieces)

    @classmethod
    def create(
        cls,
        envelope: dict[str, Any] | None,
        predecessor: dict[str, Any] | None,
        policy: dict[str, Any],
        raw_env: dict[str, str],
        process_nonce: bytes,
        object_nonce: bytes,
        key: bytes,
    ) -> "EphemeralSecretProofV2":
        if envelope is None or predecessor is None:
            raise ConformanceError("PROOF_ENVELOPE_REQUIRED")
        if len(key) != 32:
            raise ConformanceError("PROOF_KEY_LENGTH_INVALID")
        payload = cls._payload(
            envelope,
            predecessor,
            policy,
            raw_env,
            process_nonce,
            object_nonce,
        )
        proof = hmac.new(key, payload, hashlib.sha256).digest()
        return cls(
            envelope["attempt_launch_digest"],
            predecessor["attempt_launch_digest"],
            proof,
        )

    def verify(
        self,
        envelope: dict[str, Any],
        predecessor: dict[str, Any],
        policy: dict[str, Any],
        raw_env: dict[str, str],
        process_nonce: bytes,
        object_nonce: bytes,
        key: bytes,
    ) -> None:
        if len(key) != 32:
            raise ConformanceError("PROOF_KEY_LENGTH_INVALID")
        payload = self._payload(
            envelope,
            predecessor,
            policy,
            raw_env,
            process_nonce,
            object_nonce,
        )
        if (
            self._envelope_digest != envelope["attempt_launch_digest"]
            or self._predecessor_digest
            != predecessor["attempt_launch_digest"]
        ):
            raise ConformanceError("PROOF_ENVELOPE_MISMATCH")
        expected = hmac.new(key, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(self._proof, expected):
            raise ConformanceError("EPHEMERAL_SECRET_PROOF_MISMATCH")


class SpawnCapabilityV2:
    __slots__ = ("_authority", "_proof")

    def __init__(
        self,
        envelope: dict[str, Any],
        consumed: dict[str, Any],
        proof: EphemeralSecretProofV2,
    ) -> None:
        authority = {
            "attempt_launch_digest": envelope["attempt_launch_digest"],
            "predecessor_attempt_launch_v3_digest":
                envelope["predecessor_attempt_launch_v3_digest"],
            "consumed_launch_digest": consumed["consumed_launch_digest"],
            "execution_attempt_digest":
                consumed["execution_attempt_digest"],
        }
        object.__setattr__(self, "_authority", immutable_mapping(authority))
        object.__setattr__(self, "_proof", proof)

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("SpawnCapabilityV2 is immutable")

    @property
    def authority(self) -> MappingProxyType:
        return self._authority

    @property
    def proof(self) -> EphemeralSecretProofV2:
        return self._proof


def validate_spawn_capability(
    capability: SpawnCapabilityV2,
    envelope: dict[str, Any],
    consumed: dict[str, Any],
    proof: EphemeralSecretProofV2,
) -> None:
    expected = {
        "attempt_launch_digest": envelope["attempt_launch_digest"],
        "predecessor_attempt_launch_v3_digest":
            envelope["predecessor_attempt_launch_v3_digest"],
        "consumed_launch_digest": consumed["consumed_launch_digest"],
        "execution_attempt_digest": consumed["execution_attempt_digest"],
    }
    if dict(capability.authority) != expected or capability.proof is not proof:
        raise ConformanceError("SPAWN_CAPABILITY_ENVELOPE_MISMATCH")
    if proof._envelope_digest != envelope["attempt_launch_digest"]:
        raise ConformanceError("SPAWN_CAPABILITY_ENVELOPE_MISMATCH")


def identity_hash(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


def resume_identity(records: dict[str, Any]) -> dict[str, Any]:
    root = records["root"]
    axes = records["axes"]
    route = records["route"]
    values = {
        "backend_identity": identity_hash(axes["backend"]),
        "routing_profile_identity": identity_hash(axes["routing_profile"]),
        "transport_identity": identity_hash(axes["transport"]),
        "assurance_identity": identity_hash(axes["assurance_class"]),
        "semantic_plan_identity": root["semantic_plan_digest"],
        "arm_family_identity": root["arm_family_digest"],
        "model_identity": identity_hash(route["exact_requested_model_id"]),
        "effort_identity": identity_hash(route["requested_effort"]),
        "thinking_identity": identity_hash(
            [
                route["requested_thinking_mode"],
                route["manual_thinking_budget_tokens"],
            ]
        ),
        "account_identity": identity_hash(route["account_class"]),
        "auth_identity": identity_hash(route["auth_route"]),
        "service_identity": identity_hash(route["service_tier"]),
        "fallback_identity": route["fallback_authority_digest"],
        "public_environment_identity":
            records["public_env"]["public_materialized_environment_digest"],
        "environment_policy_identity":
            records["env_policy"]["environment_policy_authority_digest"],
        "source_identity": root["source_snapshot_authority_digest"],
        "prompt_identity": root["prompt_authority_digest"],
        "methodology_identity": root["methodology_authority_digest"],
        "program_facts_identity": root["program_facts_authority_digest"],
        "tools_identity": root["tool_policy_authority_digest"],
        "profile_semantics_identity":
            records["semantics"]["semantics_authority_digest"],
        "profile_identity": records["profile"]["provider_profile_digest"],
        "capability_authority_identity":
            records["capability"]["capability_authority_digest"],
        "price_authority_identity":
            records["price"]["price_authority_digest"],
        "context_budget_identity": route["context_budget_digest"],
        "budget_authority_identity": route["budget_authority_digest"],
        "family_grant_identity": root["family_grant_authority_digest"],
        "work_plan_identity": records["work"]["work_plan_binding_digest"],
        "phase_io_identity": records["phaseio"]["phase_io_binding_digest"],
        "output_contract_identity": root["output_contract_digest"],
        "loaded_customization_identity":
            root["loaded_customization_set_digest"],
        "effort_authority_identity": root["effort_authority_digest"],
        "thinking_authority_identity": root["thinking_authority_digest"],
    }
    return seal(
        {
            "schema": "plamen.resume-identity-vector.v2",
            "identity_vector_version": 2,
            "identity_vector_digest": d("0"),
            **values,
        },
        "identity_vector_digest",
    )


def completed_evidence(records: dict[str, Any]) -> dict[str, Any]:
    return seal(
        {
            "schema": "plamen.phase-io-incorporation-evidence.v1",
            "incorporation_evidence_version": 1,
            "incorporation_evidence_digest": d("0"),
            "phase_io_binding_digest":
                records["phaseio"]["phase_io_binding_digest"],
            "execution_attempt_digest":
                records["attempt"]["execution_attempt_digest"],
            "observation_digest":
                records["observation"]["observation_digest"],
            "reconciliation_receipt_digest":
                records["transaction"]["reconciliation_receipt_digest"],
            "incorporated_output_set_digest":
                records["transaction"]["incorporated_output_set_digest"],
            "incorporation_state": "COMPLETED_EXACTLY_ONCE",
        },
        "incorporation_evidence_digest",
    )


def ambiguity_evidence(records: dict[str, Any]) -> dict[str, Any]:
    return seal(
        {
            "schema": "plamen.consumed-ambiguity-evidence.v1",
            "ambiguity_evidence_version": 1,
            "ambiguity_evidence_digest": d("0"),
            "attempt_launch_digest":
                records["envelope"]["attempt_launch_digest"],
            "consumed_launch_digest":
                records["consumed"]["consumed_launch_digest"],
            "execution_attempt_digest":
                records["attempt"]["execution_attempt_digest"],
            "post_consumption_ledger_digest":
                records["consumed"][
                    "resource_ledger_digest_after_launch_consumption"
                ],
            "spawn_observation_state": "AMBIGUOUS_NO_RELAUNCH",
        },
        "ambiguity_evidence_digest",
    )


def resume_authority(
    before: dict[str, Any],
    after: dict[str, Any],
    decision: str,
    *,
    prior_generation: int = 1,
    current_generation: int = 1,
    prior_attempt: int = 0,
    current_attempt: int = 1,
    completed: dict[str, Any] | None = None,
    ambiguous: dict[str, Any] | None = None,
) -> dict[str, Any]:
    changed = [
        IDENTITY_LABELS[field] for field in IDENTITY_FIELDS
        if before[field] != after[field]
    ]
    return seal(
        {
            "schema": "plamen.resume-authority.v2",
            "resume_authority_version": 2,
            "resume_authority_digest": d("0"),
            "before_identity_vector_digest":
                before["identity_vector_digest"],
            "after_identity_vector_digest": after["identity_vector_digest"],
            "prior_generation": prior_generation,
            "current_generation": current_generation,
            "prior_attempt_ordinal": prior_attempt,
            "current_attempt_ordinal": current_attempt,
            "changed_identity_fields": changed,
            "decision": decision,
            "family_grant_authority_digest_before":
                before["family_grant_identity"],
            "family_grant_authority_digest_after":
                after["family_grant_identity"],
            "completed_incorporation_evidence_digest":
                None if completed is None
                else completed["incorporation_evidence_digest"],
            "consumed_ambiguity_evidence_digest":
                None if ambiguous is None
                else ambiguous["ambiguity_evidence_digest"],
        },
        "resume_authority_digest",
    )


def validate_resume(
    bundle: dict[str, Any],
    authority: dict[str, Any],
    before: dict[str, Any],
    after: dict[str, Any],
    records: dict[str, Any],
    completed: dict[str, Any] | None,
    ambiguous: dict[str, Any] | None,
) -> None:
    schema_validate(bundle, "ResumeIdentityVectorV2", before)
    schema_validate(bundle, "ResumeIdentityVectorV2", after)
    schema_validate(bundle, "ResumeAuthorityV2", authority)
    verify_seal(before, "identity_vector_digest")
    verify_seal(after, "identity_vector_digest")
    verify_seal(authority, "resume_authority_digest")
    changed = [
        IDENTITY_LABELS[field] for field in IDENTITY_FIELDS
        if before[field] != after[field]
    ]
    if (
        authority["before_identity_vector_digest"]
        != before["identity_vector_digest"]
        or authority["after_identity_vector_digest"]
        != after["identity_vector_digest"]
        or authority["family_grant_authority_digest_before"]
        != before["family_grant_identity"]
        or authority["family_grant_authority_digest_after"]
        != after["family_grant_identity"]
        or authority["changed_identity_fields"] != changed
    ):
        mismatch_error = {
            "RETRY_SAME_GENERATION": "RESUME_RETRY_IDENTITY_DRIFT",
            "NEW_GENERATION": "RESUME_NEW_GENERATION_UNCHANGED",
            "NO_RELAUNCH_COMPLETED": "RESUME_COMPLETED_EVIDENCE_MISMATCH",
            "AMBIGUOUS_CONSUMED_DEBT":
                "RESUME_AMBIGUITY_EVIDENCE_MISMATCH",
        }[authority["decision"]]
        raise ConformanceError(mismatch_error)
    decision = authority["decision"]
    if decision == "RETRY_SAME_GENERATION":
        if (
            changed
            or authority["prior_generation"]
            != authority["current_generation"]
            or authority["current_attempt_ordinal"]
            != authority["prior_attempt_ordinal"] + 1
            or completed is not None
            or ambiguous is not None
            or authority["completed_incorporation_evidence_digest"] is not None
            or authority["consumed_ambiguity_evidence_digest"] is not None
        ):
            raise ConformanceError("RESUME_RETRY_IDENTITY_DRIFT")
    elif decision == "NEW_GENERATION":
        if (
            not changed
            or authority["current_generation"]
            != authority["prior_generation"] + 1
            or authority["current_attempt_ordinal"] != 0
            or completed is not None
            or ambiguous is not None
        ):
            raise ConformanceError("RESUME_NEW_GENERATION_UNCHANGED")
    elif decision == "NO_RELAUNCH_COMPLETED":
        if (
            changed
            or authority["prior_generation"]
            != authority["current_generation"]
            or authority["prior_attempt_ordinal"]
            != authority["current_attempt_ordinal"]
            or completed is None
            or ambiguous is not None
        ):
            raise ConformanceError("RESUME_COMPLETED_EVIDENCE_MISMATCH")
        schema_validate(bundle, "PhaseIOIncorporationEvidenceV1", completed)
        verify_seal(completed, "incorporation_evidence_digest")
        if (
            authority["completed_incorporation_evidence_digest"]
            != completed["incorporation_evidence_digest"]
            or authority["consumed_ambiguity_evidence_digest"] is not None
            or completed["phase_io_binding_digest"]
            != records["phaseio"]["phase_io_binding_digest"]
            or completed["execution_attempt_digest"]
            != records["attempt"]["execution_attempt_digest"]
            or completed["observation_digest"]
            != records["observation"]["observation_digest"]
            or completed["reconciliation_receipt_digest"]
            != records["transaction"]["reconciliation_receipt_digest"]
            or completed["incorporated_output_set_digest"]
            != records["transaction"]["incorporated_output_set_digest"]
        ):
            raise ConformanceError("RESUME_COMPLETED_EVIDENCE_MISMATCH")
    elif decision == "AMBIGUOUS_CONSUMED_DEBT":
        if (
            changed
            or authority["prior_generation"]
            != authority["current_generation"]
            or authority["prior_attempt_ordinal"]
            != authority["current_attempt_ordinal"]
            or ambiguous is None
            or completed is not None
        ):
            raise ConformanceError("RESUME_AMBIGUITY_EVIDENCE_MISMATCH")
        schema_validate(bundle, "ConsumedAmbiguityEvidenceV1", ambiguous)
        verify_seal(ambiguous, "ambiguity_evidence_digest")
        if (
            authority["consumed_ambiguity_evidence_digest"]
            != ambiguous["ambiguity_evidence_digest"]
            or authority["completed_incorporation_evidence_digest"] is not None
            or ambiguous["attempt_launch_digest"]
            != records["envelope"]["attempt_launch_digest"]
            or ambiguous["consumed_launch_digest"]
            != records["consumed"]["consumed_launch_digest"]
            or ambiguous["execution_attempt_digest"]
            != records["attempt"]["execution_attempt_digest"]
            or ambiguous["post_consumption_ledger_digest"]
            != records["consumed"][
                "resource_ledger_digest_after_launch_consumption"
            ]
        ):
            raise ConformanceError("RESUME_AMBIGUITY_EVIDENCE_MISMATCH")


def artifact_manifest(
    bundle: dict[str, Any], artifacts: dict[str, bytes]
) -> dict[str, Any]:
    rows = [
        sha256_bytes(name.encode("utf-8") + b"\x00" + artifacts[name])
        for name in sorted(artifacts)
    ]
    record = seal(
        {
            "schema": "plamen.neutral-artifact-manifest.v1",
            "artifact_manifest_version": 1,
            "artifact_manifest_digest": d("0"),
            "artifact_count": len(rows),
            "artifact_digests": rows,
        },
        "artifact_manifest_digest",
    )
    schema_validate(bundle, "NeutralArtifactManifestV1", record)
    return record


def codex_parity_receipt(
    before: dict[str, Any],
    after: dict[str, Any],
    before_fixture: bytes,
    after_fixture: bytes,
) -> dict[str, Any]:
    return seal(
        {
            "schema": "plamen.codex-parity-evidence-receipt.v2",
            "codex_parity_version": 2,
            "codex_parity_digest": d("0"),
            "authority_class": "NEUTRAL_COMPUTED_EVIDENCE",
            "neutral_checker_authority_digest": d("c"),
            "before_artifact_manifest_digest":
                before["artifact_manifest_digest"],
            "after_artifact_manifest_digest":
                after["artifact_manifest_digest"],
            "before_fixture_receipt_digest": sha256_bytes(before_fixture),
            "after_fixture_receipt_digest": sha256_bytes(after_fixture),
            "parity_result": "EQUAL",
        },
        "codex_parity_digest",
    )


def validate_codex_parity(
    bundle: dict[str, Any],
    receipt: dict[str, Any],
    before_artifacts: dict[str, bytes],
    after_artifacts: dict[str, bytes],
    before_fixture: bytes,
    after_fixture: bytes,
) -> None:
    schema_validate(bundle, "CodexParityEvidenceReceiptV2", receipt)
    verify_seal(receipt, "codex_parity_digest")
    before = artifact_manifest(bundle, before_artifacts)
    after = artifact_manifest(bundle, after_artifacts)
    expected_equal = (
        before["artifact_digests"] == after["artifact_digests"]
        and before_fixture == after_fixture
    )
    if (
        not expected_equal
        or receipt["neutral_checker_authority_digest"] != d("c")
        or receipt["before_artifact_manifest_digest"]
        != before["artifact_manifest_digest"]
        or receipt["after_artifact_manifest_digest"]
        != after["artifact_manifest_digest"]
        or receipt["before_fixture_receipt_digest"]
        != sha256_bytes(before_fixture)
        or receipt["after_fixture_receipt_digest"]
        != sha256_bytes(after_fixture)
        or receipt["parity_result"] != "EQUAL"
    ):
        raise ConformanceError("CODEX_NEUTRAL_EVIDENCE_MISMATCH")


def downstream_closure(
    states: dict[str, tuple[str, str | None, str | None]]
) -> dict[str, Any]:
    rows = []
    for component in sorted(states):
        state, receipt, postimage = states[component]
        rows.append(
            seal(
                {
                    "row_digest": d("0"),
                    "component": component,
                    "state": state,
                    "independent_receipt_digest": receipt,
                    "frozen_postimage_digest": postimage,
                },
                "row_digest",
            )
        )
    return seal(
        {
            "schema": "plamen.downstream-closure-authority.v2",
            "downstream_closure_version": 2,
            "downstream_closure_digest": d("0"),
            "authority_class": "NEUTRAL_COMPUTED_EVIDENCE",
            "neutral_checker_authority_digest": d("c"),
            "row_count": 7,
            "rows": rows,
            "cutover_authorized": False,
        },
        "downstream_closure_digest",
    )


def validate_downstream(
    bundle: dict[str, Any],
    authority: dict[str, Any],
    independent_evidence: dict[str, tuple[str, str]],
) -> None:
    for row in authority.get("rows", []):
        if row.get("state") == "COMPLETE":
            expected = independent_evidence.get(row.get("component"))
            if (
                expected is None
                or row.get("independent_receipt_digest") != expected[0]
                or row.get("frozen_postimage_digest") != expected[1]
            ):
                raise ConformanceError(
                    "DOWNSTREAM_COMPLETE_EVIDENCE_REQUIRED"
                )
        elif (
            row.get("independent_receipt_digest") is not None
            or row.get("frozen_postimage_digest") is not None
        ):
            raise ConformanceError("DOWNSTREAM_COMPLETE_EVIDENCE_REQUIRED")
    schema_validate(bundle, "DownstreamClosureAuthorityV2", authority)
    verify_seal(authority, "downstream_closure_digest")
    if authority["row_count"] != len(authority["rows"]):
        raise ConformanceError("DOWNSTREAM_COMPLETE_EVIDENCE_REQUIRED")
    if authority["neutral_checker_authority_digest"] != d("c"):
        raise ConformanceError("DOWNSTREAM_COMPLETE_EVIDENCE_REQUIRED")
    components = [row["component"] for row in authority["rows"]]
    if components != sorted(
        ["runtime", "runbundle", "evaluator", "bb", "repair", "packaging", "ci_runtime_closure"]
    ):
        raise ConformanceError("DOWNSTREAM_COMPLETE_EVIDENCE_REQUIRED")
    for row in authority["rows"]:
        schema_validate(bundle, "DownstreamEvidenceRowV2", row)
        verify_seal(row, "row_digest")


def build_closure(
    bundle: dict[str, Any], r23: Any, r24: Any
) -> dict[str, Any]:
    old = r23.make_thinking_launch_join({"mode": "valid"})
    predecessor = {
        "loaded": old["loaded_customization_set"],
        "effort": old["effort_authority"],
        "thinking": old["thinking_authority"],
    }
    base = r24.closure(
        r24.parse_json(
            r24.read_ascii_lf(
                HERE / "Plamen_Backend_Model_Routing_R2.4_Schemas_2026-07-29.json"
            )
        )
    )
    axes = copy.deepcopy(base["axes"])
    semantics = profile_semantics_authority()
    profiles = [
        provider_profile(semantics, profile_id)
        for profile_id in sorted(PROFILE_MATRIX)
    ]
    profile = next(
        item for item in profiles
        if item["provider_profile_id"] == "analysis_filesystem"
    )
    registry = profile_registry(semantics, profiles)
    env_policy = environment_policy()
    public_env, raw_env = public_environment(env_policy)
    manifest = provider_manifest()
    evaluation = evaluation_time()
    capability = capability_authority(manifest, evaluation)
    price = price_authority(manifest, evaluation)
    fallback = fallback_authority(manifest)
    selection = route_selection_authority(
        predecessor,
        axes,
        semantics,
        registry,
        profile,
        public_env,
        manifest,
        evaluation,
        capability,
        price,
        fallback,
    )
    root = routing_root(
        predecessor,
        semantics,
        env_policy,
        manifest,
        evaluation,
        selection,
    )
    customization, projection = customization_authority(
        root, predecessor, public_env, selection
    )
    route = model_route(
        root,
        axes,
        manifest,
        evaluation,
        capability,
        price,
        fallback,
        selection,
    )
    request = request_record(
        root,
        axes,
        semantics,
        registry,
        profile,
        customization,
        route,
    )
    work = workplan_record(
        root,
        request,
        axes,
        semantics,
        profile,
        customization,
        route,
    )
    phaseio = phaseio_record(root, request, work, customization, route)
    control = control_record(
        root,
        request,
        axes,
        semantics,
        profile,
        customization,
        route,
        public_env,
    )
    launch = launch_record(
        root,
        request,
        axes,
        semantics,
        profile,
        customization,
        route,
        control,
        work,
        phaseio,
    )
    arm = arm_record(
        root,
        request,
        axes,
        semantics,
        profile,
        customization,
        route,
        launch,
        work,
        phaseio,
    )
    attempt = attempt_record(
        root,
        request,
        semantics,
        profile,
        customization,
        route,
        launch,
        arm,
    )
    envelope, predecessor_envelope = envelope_record(
        root,
        request,
        customization,
        control,
        launch,
        arm,
        attempt,
        public_env,
    )
    consumed = consumed_record(envelope, attempt)
    observation, evidence = observation_record(
        root,
        request,
        axes,
        semantics,
        profile,
        customization,
        route,
        arm,
        attempt,
        envelope,
        consumed,
        public_env,
        manifest,
    )
    records = {
        "predecessor": predecessor,
        "axes": axes,
        "semantics": semantics,
        "profiles": profiles,
        "profile": profile,
        "registry": registry,
        "env_policy": env_policy,
        "public_env": public_env,
        "raw_env": raw_env,
        "manifest": manifest,
        "evaluation": evaluation,
        "capability": capability,
        "price": price,
        "fallback": fallback,
        "selection": selection,
        "root": root,
        "frozen_root_digest": root["routing_root_digest"],
        "customization": customization,
        "projection": projection,
        "route": route,
        "request": request,
        "work": work,
        "phaseio": phaseio,
        "control": control,
        "secret_policy": {
            "secret_proof_policy_digest": SECRET_PROOF_POLICY_DIGEST
        },
        "transaction": {
            "work_plan_digest": d("3"),
            "phase_io_launch_digest": d("4"),
            "generation": 1,
            "generation_reservation_event_digest": d("8"),
            "attempt_reservation_event_digest": d("d"),
            "attempt_resource_entry_digest": d("e"),
            "resource_ledger_digest_after_attempt_reservation": d("f"),
            "launch_consumption_event_digest": d("3"),
            "consumed_attempt_resource_entry_digest": d("4"),
            "resource_ledger_digest_after_launch_consumption": d("5"),
            "consume_cas_revision": 2,
            "materialized_stdin_prompt_digest": d("1"),
            "working_directory_identity_digest": d("2"),
            "prepared_utc": "2026-07-30T00:00:00Z",
            "reconciliation_receipt_digest": d("a"),
            "incorporated_output_set_digest": d("b"),
        },
        "launch": launch,
        "arm": arm,
        "attempt": attempt,
        "predecessor_envelope": predecessor_envelope,
        "envelope": envelope,
        "consumed": consumed,
        "evidence": evidence,
        "observation": observation,
    }
    validate_closure(bundle, records)
    return records


def validate_closure(bundle: dict[str, Any], records: dict[str, Any]) -> None:
    for name, (definition, digest_field) in SCHEMA_RECORDS.items():
        schema_validate(bundle, definition, records[name])
        verify_seal(records[name], digest_field)
    validate_root(records)
    validate_route_selection(records)
    validate_profile_semantics(
        bundle,
        records["semantics"],
        records["profiles"],
        records["registry"],
    )
    validate_environment(
        bundle,
        records["env_policy"],
        records["public_env"],
        records["raw_env"],
        records["envelope"],
    )
    validate_manifest_route(
        bundle,
        records["manifest"],
        records["evaluation"],
        records["capability"],
        records["price"],
        records["fallback"],
        records["route"],
    )
    validate_customization(
        bundle,
        records["root"],
        records["predecessor"],
        records["customization"],
        records["projection"],
        records["public_env"],
        records["selection"],
    )
    validate_cross_record(records)
    validate_observation_evidence(
        bundle, records["observation"], records["evidence"]
    )
    if (
        records["evidence"]["field_authority_digest"]
        != records["customization"][
            "provider_evidence_field_authority_digest"
        ]
    ):
        raise ConformanceError("OBSERVATION_EVIDENCE_MEMBERSHIP_MISMATCH")


def substitution(name: str) -> str:
    return sha256_bytes(("r2.5-substitution:" + name).encode("ascii"))


def mutate_record(
    records: dict[str, Any], name: str, field: str, value: Any
) -> None:
    records[name][field] = value
    seal(records[name], SCHEMA_RECORDS[name][1])


CROSS_MUTATIONS: dict[str, tuple[str, str, Any]] = {
    "rehashed WorkPlan request substitution": (
        "work", "request_digest", None
    ),
    "rehashed PhaseIO request substitution": (
        "phaseio", "request_digest", None
    ),
    "control cross-record substitution request_digest": (
        "control", "request_digest", None
    ),
    "control cross-record substitution semantic_plan_digest": (
        "control", "semantic_plan_digest", None
    ),
    "control cross-record substitution model_route_digest": (
        "control", "model_route_digest", None
    ),
    "control cross-record substitution requested_effort": (
        "control", "requested_effort", "high"
    ),
    "control cross-record substitution requested_thinking_mode": (
        "control", "requested_thinking_mode", "MANUAL_OFF"
    ),
    "control cross-record substitution environment_policy_set_digest": (
        "control", "environment_policy_authority_digest", None
    ),
    "control cross-record substitution secret_proof_policy_digest": (
        "control", "secret_proof_policy_digest", None
    ),
    "launch cross-record substitution semantic_plan_digest": (
        "launch", "semantic_plan_digest", None
    ),
    "launch cross-record substitution execution_axes_digest": (
        "launch", "execution_axes_digest", None
    ),
    "launch cross-record substitution provider_profile_digest": (
        "launch", "provider_profile_digest", None
    ),
    "launch cross-record substitution input_authority_set_digest": (
        "launch", "arm_family_digest", None
    ),
    "launch cross-record substitution model_route_digest": (
        "launch", "model_route_digest", None
    ),
    "launch cross-record substitution budget_authority_digest": (
        "launch", "budget_authority_digest", None
    ),
    "launch cross-record substitution provider_control_vector_digest": (
        "launch", "control_vector_digest", None
    ),
    "launch cross-record substitution work_plan_routing_binding_digest": (
        "launch", "work_plan_binding_digest", None
    ),
    "launch cross-record substitution tool_policy_digest": (
        "launch", "tool_policy_digest", None
    ),
    "observation cross-record substitution request_digest": (
        "observation", "request_digest", None
    ),
    "observation cross-record substitution execution_axes_digest": (
        "observation", "execution_axes_digest", None
    ),
    "observation cross-record substitution provider_profile_digest": (
        "observation", "provider_profile_digest", None
    ),
    "observation cross-record substitution model_route_digest": (
        "observation", "model_route_digest", None
    ),
    "observation cross-record substitution consumed_launch_authority_digest": (
        "observation", "consumed_launch_digest", None
    ),
    "observation cross-record substitution public_materialized_environment_digest": (
        "observation", "public_materialized_environment_digest", None
    ),
    "control customization authority substitution": (
        "control", "customization_authority_digest", None
    ),
    "request customization authority substitution": (
        "request", "customization_authority_digest", None
    ),
    "phaseio customization authority substitution": (
        "phaseio", "customization_authority_digest", None
    ),
    "envelope customization authority substitution": (
        "envelope", "customization_authority_digest", None
    ),
    "workplan semantic-plan substitution": (
        "work", "semantic_plan_digest", None
    ),
    "workplan profile-semantics substitution": (
        "work", "profile_semantics_authority_digest", None
    ),
    "phaseio workplan-binding substitution": (
        "phaseio", "work_plan_binding_digest", None
    ),
    "control profile-semantics substitution": (
        "control", "profile_semantics_authority_digest", None
    ),
    "launch routing-root substitution": (
        "launch", "routing_root_digest", None
    ),
    "arm request substitution": ("arm", "request_digest", None),
    "arm launch substitution": ("arm", "launch_authority_digest", None),
    "attempt arm substitution": ("attempt", "backend_arm_digest", None),
    "envelope request substitution": (
        "envelope", "request_digest", None
    ),
    "envelope public-environment substitution": (
        "envelope", "public_materialized_environment_digest", None
    ),
    "consumed envelope substitution": (
        "consumed", "attempt_launch_digest", None
    ),
    "observation attempt substitution": (
        "observation", "execution_attempt_digest", None
    ),
}


def prepare_not_applicable(
    records: dict[str, Any], *, mismatch: bool
) -> None:
    model = records["manifest"]["model_rows"][0]
    model["effort_applicability"] = "NOT_APPLICABLE"
    model["supported_efforts"] = ["not_applicable"]
    seal(model, "model_row_digest")
    records["manifest"]["model_rows"] = [model]
    seal(records["manifest"], "provider_manifest_authority_digest")
    cap = records["capability"]
    cap["provider_manifest_authority_digest"] = records["manifest"][
        "provider_manifest_authority_digest"
    ]
    cap["model_row_digest"] = model["model_row_digest"]
    cap["effort_applicability"] = "NOT_APPLICABLE"
    cap["supported_efforts"] = ["not_applicable"]
    seal(cap, "capability_authority_digest")
    records["price"]["provider_manifest_authority_digest"] = records[
        "manifest"
    ]["provider_manifest_authority_digest"]
    records["price"]["model_row_digest"] = model["model_row_digest"]
    seal(records["price"], "price_authority_digest")
    records["fallback"]["provider_manifest_authority_digest"] = records[
        "manifest"
    ]["provider_manifest_authority_digest"]
    seal(records["fallback"], "fallback_authority_digest")
    selection = records["selection"]
    selection["provider_manifest_authority_digest"] = records["manifest"][
        "provider_manifest_authority_digest"
    ]
    selection["model_row_digest"] = model["model_row_digest"]
    selection["capability_authority_digest"] = cap[
        "capability_authority_digest"
    ]
    selection["price_authority_digest"] = records["price"][
        "price_authority_digest"
    ]
    selection["fallback_authority_digest"] = records["fallback"][
        "fallback_authority_digest"
    ]
    selection["effort_applicability"] = "NOT_APPLICABLE"
    selection["requested_effort"] = "xhigh" if mismatch else None
    seal(selection, "route_selection_authority_digest")
    route = records["route"]
    route["provider_manifest_authority_digest"] = records["manifest"][
        "provider_manifest_authority_digest"
    ]
    route["model_row_digest"] = model["model_row_digest"]
    route["capability_authority_digest"] = cap["capability_authority_digest"]
    route["price_authority_digest"] = records["price"][
        "price_authority_digest"
    ]
    route["fallback_authority_digest"] = records["fallback"][
        "fallback_authority_digest"
    ]
    route["route_selection_authority_digest"] = selection[
        "route_selection_authority_digest"
    ]
    route["effort_applicability"] = "NOT_APPLICABLE"
    route["requested_effort"] = "xhigh" if mismatch else None
    seal(route, "model_route_digest")


def proof_material(
    records: dict[str, Any],
    raw_env: dict[str, str] | None = None,
) -> tuple[dict[str, str], bytes, bytes, bytes]:
    return (
        records["raw_env"] if raw_env is None else raw_env,
        b"p" * 32,
        b"o" * 32,
        b"k" * 32,
    )


def run_scenario(
    bundle: dict[str, Any],
    r23: Any,
    r24: Any,
    name: str,
) -> None:
    records = build_closure(bundle, r23, r24)
    if name in CROSS_MUTATIONS:
        record_name, field, value = CROSS_MUTATIONS[name]
        if name == "control cross-record substitution requested_effort":
            current = records[record_name][field]
            value = next(
                effort
                for effort in ("low", "medium", "high", "xhigh")
                if effort != current
            )
        elif (
            name
            == "control cross-record substitution requested_thinking_mode"
        ):
            current = records[record_name][field]
            value = (
                "MANUAL_OFF"
                if current == "ADAPTIVE_ON"
                else "ADAPTIVE_ON"
            )
            if current == "MANUAL_ON":
                records[record_name]["manual_thinking_budget_tokens"] = None
        mutate_record(
            records,
            record_name,
            field,
            substitution(name) if value is None else value,
        )
        validate_closure(bundle, records)
        return
    if name == "requested values plus unjoined arbitrary evidence digests":
        mutate_record(
            records,
            "observation",
            "model_field_claim_digest",
            substitution(name),
        )
        validate_closure(bundle, records)
        return
    if name == "retry identity closure drift with empty changed set":
        before = resume_identity(records)
        after = copy.deepcopy(before)
        after["model_identity"] = substitution(name)
        seal(after, "identity_vector_digest")
        authority = resume_authority(before, before, "RETRY_SAME_GENERATION")
        validate_resume(
            bundle, authority, before, after, records, None, None
        )
        return
    if name == "new generation claims change with identical closure":
        before = resume_identity(records)
        authority = resume_authority(
            before,
            before,
            "NEW_GENERATION",
            current_generation=2,
            current_attempt=0,
        )
        authority["changed_identity_fields"] = ["model"]
        seal(authority, "resume_authority_digest")
        validate_resume(
            bundle, authority, before, before, records, None, None
        )
        return
    if name == "NO_RELAUNCH_COMPLETED arbitrary lifecycle fields":
        identity = resume_identity(records)
        completed = completed_evidence(records)
        completed["reconciliation_receipt_digest"] = substitution(name)
        seal(completed, "incorporation_evidence_digest")
        authority = resume_authority(
            identity,
            identity,
            "NO_RELAUNCH_COMPLETED",
            current_attempt=0,
            completed=completed,
        )
        validate_resume(
            bundle,
            authority,
            identity,
            identity,
            records,
            completed,
            None,
        )
        return
    if name == "AMBIGUOUS_CONSUMED_DEBT arbitrary lifecycle fields":
        identity = resume_identity(records)
        ambiguous = ambiguity_evidence(records)
        ambiguous["post_consumption_ledger_digest"] = substitution(name)
        seal(ambiguous, "ambiguity_evidence_digest")
        authority = resume_authority(
            identity,
            identity,
            "AMBIGUOUS_CONSUMED_DEBT",
            current_attempt=0,
            ambiguous=ambiguous,
        )
        validate_resume(
            bundle,
            authority,
            identity,
            identity,
            records,
            None,
            ambiguous,
        )
        return
    if name == "secret raw environment omitted from public projection and proof disabled":
        public = copy.deepcopy(records["public_env"])
        public["entries"] = [
            row for row in public["entries"]
            if row["name"] != "ANTHROPIC_API_KEY"
        ]
        public["entry_count"] = len(public["entries"])
        seal(public, "public_materialized_environment_digest")
        envelope = copy.deepcopy(records["envelope"])
        envelope["secret_proof_required"] = False
        validate_environment(
            bundle,
            records["env_policy"],
            public,
            records["raw_env"],
            envelope,
        )
        return
    if name == "ephemeral proof API omits AttemptLaunchEnvelopeV3 digest":
        raw, process, obj, key = proof_material(records)
        EphemeralSecretProofV2.create(
            records["envelope"],
            None,
            records["env_policy"],
            raw,
            process,
            obj,
            key,
        )
        return
    if name == "non-256-bit process/object nonce accepted":
        raw, _process, obj, key = proof_material(records)
        EphemeralSecretProofV2.create(
            records["envelope"],
            records["predecessor_envelope"],
            records["env_policy"],
            raw,
            b"p" * 31,
            obj,
            key,
        )
        return
    if name == "spawn capability authority/proof mutation":
        raw, process, obj, key = proof_material(records)
        proof = EphemeralSecretProofV2.create(
            records["envelope"],
            records["predecessor_envelope"],
            records["env_policy"],
            raw,
            process,
            obj,
            key,
        )
        capability = SpawnCapabilityV2(
            records["envelope"], records["consumed"], proof
        )
        envelope = copy.deepcopy(records["envelope"])
        envelope["working_directory_identity_digest"] = substitution(name)
        seal(envelope, "attempt_launch_digest")
        validate_spawn_capability(
            capability, envelope, records["consumed"], proof
        )
        return
    profile_prefix = "policy-stable profile semantic mutation "
    if name.startswith(profile_prefix):
        field = name[len(profile_prefix):]
        values = {
            "environment_policy_set_names": ["base"],
            "settings_selection_policy": "REVIEWED_SETTINGS_V2",
            "mcp_selection_policy": "PROFILE_SELECTED_MCP_V2",
            "stream_max_bytes": 1048577,
            "stream_max_events": 4097,
            "isolation_policy": "OWNED_PROCESS_SCOPE_V2",
        }
        records["profile"][field] = values[field]
        seal(records["profile"], "provider_profile_digest")
        validate_profile_semantics(
            bundle,
            records["semantics"],
            records["profiles"],
            records["registry"],
        )
        return
    if name.startswith("dated forbidden model alias "):
        alias = name.rsplit(" ", 1)[1]
        row = records["manifest"]["model_rows"][0]
        row["exact_model_id"] = alias
        seal(row, "model_row_digest")
        seal(records["manifest"], "provider_manifest_authority_digest")
        validate_manifest_route(
            bundle,
            records["manifest"],
            records["evaluation"],
            records["capability"],
            records["price"],
            records["fallback"],
            records["route"],
        )
        return
    if name.startswith("closed auth mapping mismatch "):
        account, auth = name.rsplit(" ", 1)[1].split("/")
        row = next(
            item for item in records["manifest"]["route_tuples"]
            if item["account_class"] == account
        )
        row["auth_route"] = auth
        seal(row, "tuple_row_digest")
        seal(records["manifest"], "provider_manifest_authority_digest")
        validate_manifest_route(
            bundle,
            records["manifest"],
            records["evaluation"],
            records["capability"],
            records["price"],
            records["fallback"],
            records["route"],
        )
        return
    if name == "capability inverted validity interval":
        records["capability"]["valid_from_utc"] = "2026-09-01T00:00:00Z"
        records["capability"]["valid_until_utc"] = "2026-08-01T00:00:00Z"
        seal(records["capability"], "capability_authority_digest")
        validate_manifest_route(
            bundle,
            records["manifest"],
            records["evaluation"],
            records["capability"],
            records["price"],
            records["fallback"],
            records["route"],
        )
        return
    if name == "capability malformed validity timestamp":
        records["capability"]["valid_from_utc"] = "2026-99-30T00:00:00Z"
        seal(records["capability"], "capability_authority_digest")
        validate_manifest_route(
            bundle,
            records["manifest"],
            records["evaluation"],
            records["capability"],
            records["price"],
            records["fallback"],
            records["route"],
        )
        return
    if name == "fabricated self-consistent Codex parity witness":
        artifacts = {"a.txt": b"same"}
        fixture = b"fixture-pass"
        before = artifact_manifest(bundle, artifacts)
        after = artifact_manifest(bundle, artifacts)
        receipt = codex_parity_receipt(before, after, fixture, fixture)
        receipt["before_artifact_manifest_digest"] = substitution(name)
        receipt["after_artifact_manifest_digest"] = substitution(name)
        seal(receipt, "codex_parity_digest")
        validate_codex_parity(
            bundle, receipt, artifacts, artifacts, fixture, fixture
        )
        return
    if name == "downstream COMPLETE without evidence authorities":
        components = [
            "runtime", "runbundle", "evaluator", "bb", "repair",
            "packaging", "ci_runtime_closure",
        ]
        states = {
            component: ("PENDING", None, None)
            for component in components
        }
        authority = downstream_closure(states)
        row = next(
            item for item in authority["rows"]
            if item["component"] == "runtime"
        )
        row["state"] = "COMPLETE"
        seal(row, "row_digest")
        seal(authority, "downstream_closure_digest")
        validate_downstream(bundle, authority, {})
        return
    if name in {
        "launch missing thinking authority",
        "launch missing loaded customization authority",
    }:
        field = (
            "thinking_authority_digest"
            if "thinking" in name
            else "loaded_customization_set_digest"
        )
        del records["launch"][field]
        schema_validate(bundle, "LaunchAuthorityV4", records["launch"])
        return
    if name.startswith("customization predecessor "):
        field = {
            "customization predecessor loaded-set substitution":
                "predecessor_loaded_customization_set_digest",
            "customization predecessor effort substitution":
                "predecessor_effort_authority_digest",
            "customization predecessor thinking substitution":
                "predecessor_thinking_authority_digest",
        }[name]
        records["projection"][field] = substitution(name)
        seal(records["projection"], "projection_digest")
        validate_customization(
            bundle,
            records["root"],
            records["predecessor"],
            records["customization"],
            records["projection"],
            records["public_env"],
            records["selection"],
        )
        return
    if name in {
        "manual thinking on with null budget",
        "manual thinking off with positive budget",
    }:
        if name == "manual thinking on with null budget":
            records["route"]["requested_thinking_mode"] = "MANUAL_ON"
            records["route"]["manual_thinking_budget_tokens"] = None
        else:
            records["route"]["requested_thinking_mode"] = "MANUAL_OFF"
            records["route"]["manual_thinking_budget_tokens"] = 1024
        seal(records["route"], "model_route_digest")
        schema_validate(bundle, "ModelRouteV4", records["route"])
        return
    if name in {
        "not-applicable effort capability valid",
        "not-applicable effort route mismatch",
    }:
        prepare_not_applicable(
            records, mismatch=name.endswith("route mismatch")
        )
        validate_route_selection(records)
        validate_manifest_route(
            bundle,
            records["manifest"],
            records["evaluation"],
            records["capability"],
            records["price"],
            records["fallback"],
            records["route"],
        )
        return
    if name == "observation thinking claim absent":
        evidence = records["evidence"]
        evidence["field_claims"] = [
            claim for claim in evidence["field_claims"]
            if claim["field_name"] != "thinking_state"
        ]
        evidence["claim_count"] = len(evidence["field_claims"])
        evidence["raw_artifact_digests"] = sorted(
            {
                digest for claim in evidence["field_claims"]
                for digest in claim["raw_artifact_digests"]
            }
        )
        evidence["raw_artifact_union_digest"] = sha256_bytes(
            canonical_bytes(evidence["raw_artifact_digests"])
        )
        seal(evidence, "evidence_manifest_digest")
        records["observation"]["evidence_manifest_digest"] = evidence[
            "evidence_manifest_digest"
        ]
        seal(records["observation"], "observation_digest")
        validate_observation_evidence(
            bundle, records["observation"], evidence
        )
        return
    if name == "resume loaded-customization single-field change":
        before = resume_identity(records)
        after = copy.deepcopy(before)
        after["loaded_customization_identity"] = substitution(name)
        seal(after, "identity_vector_digest")
        authority = resume_authority(
            before,
            after,
            "NEW_GENERATION",
            current_generation=2,
            current_attempt=0,
        )
        validate_resume(
            bundle, authority, before, after, records, None, None
        )
        return
    if name == "observation manifest substitution":
        mutate_record(
            records,
            "observation",
            "evidence_manifest_digest",
            substitution(name),
        )
        validate_observation_evidence(
            bundle, records["observation"], records["evidence"]
        )
        return
    if name == "observation thinking-claim substitution":
        mutate_record(
            records,
            "observation",
            "thinking_field_claim_digest",
            substitution(name),
        )
        validate_observation_evidence(
            bundle, records["observation"], records["evidence"]
        )
        return
    if name == "independent root semantic-plan descendant rehash":
        records["request"]["semantic_plan_digest"] = substitution(name)
        seal(records["request"], "request_digest")
        validate_closure(bundle, records)
        return
    if name == "proof rejects historical V3 as V4":
        raw, process, obj, key = proof_material(records)
        EphemeralSecretProofV2.create(
            records["predecessor_envelope"],
            records["predecessor_envelope"],
            records["env_policy"],
            raw,
            process,
            obj,
            key,
        )
        return
    if name == "proof envelope self-digest tamper":
        envelope = copy.deepcopy(records["envelope"])
        envelope["working_directory_identity_digest"] = substitution(name)
        raw, process, obj, key = proof_material(records)
        EphemeralSecretProofV2.create(
            envelope,
            records["predecessor_envelope"],
            records["env_policy"],
            raw,
            process,
            obj,
            key,
        )
        return
    if name == "proof envelope substitution after construction":
        raw, process, obj, key = proof_material(records)
        proof = EphemeralSecretProofV2.create(
            records["envelope"],
            records["predecessor_envelope"],
            records["env_policy"],
            raw,
            process,
            obj,
            key,
        )
        envelope = copy.deepcopy(records["envelope"])
        envelope["working_directory_identity_digest"] = substitution(name)
        seal(envelope, "attempt_launch_digest")
        proof.verify(
            envelope,
            records["predecessor_envelope"],
            records["env_policy"],
            raw,
            process,
            obj,
            key,
        )
        return
    if name in {
        "proof Unicode boundary unambiguous",
        "proof empty value unambiguous",
    }:
        raw = copy.deepcopy(records["raw_env"])
        raw["ANTHROPIC_API_KEY"] = (
            "\u03b1:\u96ea:\U0001f512"
            if name.startswith("proof Unicode")
            else ""
        )
        raw, process, obj, key = proof_material(records, raw)
        proof = EphemeralSecretProofV2.create(
            records["envelope"],
            records["predecessor_envelope"],
            records["env_policy"],
            raw,
            process,
            obj,
            key,
        )
        proof.verify(
            records["envelope"],
            records["predecessor_envelope"],
            records["env_policy"],
            raw,
            process,
            obj,
            key,
        )
        return
    if name == "proof name-value swap detected":
        raw, process, obj, key = proof_material(records)
        proof = EphemeralSecretProofV2.create(
            records["envelope"],
            records["predecessor_envelope"],
            records["env_policy"],
            raw,
            process,
            obj,
            key,
        )
        swapped = copy.deepcopy(raw)
        swapped["ANTHROPIC_API_KEY"], swapped["PLAMEN_TEMP_ROOT"] = (
            swapped["PLAMEN_TEMP_ROOT"],
            swapped["ANTHROPIC_API_KEY"],
        )
        proof.verify(
            records["envelope"],
            records["predecessor_envelope"],
            records["env_policy"],
            swapped,
            process,
            obj,
            key,
        )
        return
    if name == "public policy omitted row":
        policy = copy.deepcopy(records["env_policy"])
        policy["rows"].pop()
        policy["expected_row_count"] = len(policy["rows"])
        seal(policy, "environment_policy_authority_digest")
        validate_environment(
            bundle, policy, records["public_env"], records["raw_env"]
        )
        return
    if name == "public policy extra raw name":
        raw = {**records["raw_env"], "UNDECLARED_ENV": "x"}
        validate_environment(
            bundle, records["env_policy"], records["public_env"], raw
        )
        return
    if name == "public policy secrecy misclassification":
        policy = copy.deepcopy(records["env_policy"])
        row = next(
            item for item in policy["rows"]
            if item["name"] == "ANTHROPIC_API_KEY"
        )
        row["secrecy_class"] = "NON_SECRET"
        seal(row, "policy_row_digest")
        seal(policy, "environment_policy_authority_digest")
        validate_environment(
            bundle, policy, records["public_env"], records["raw_env"]
        )
        return
    if name == "public policy case collision":
        raw = {
            **records["raw_env"],
            "anthropic_api_key": "second-secret",
        }
        validate_environment(
            bundle, records["env_policy"], records["public_env"], raw
        )
        return
    if name == "public policy present-absent mismatch":
        raw = {"ANTHROPIC_API_KEY": "alpha-secret"}
        validate_environment(
            bundle, records["env_policy"], records["public_env"], raw
        )
        return
    if name == "profile semantics root row reorder":
        semantics = copy.deepcopy(records["semantics"])
        semantics["rows"].reverse()
        seal(semantics, "semantics_authority_digest")
        validate_profile_semantics(
            bundle, semantics, records["profiles"], records["registry"]
        )
        return
    if name == "profile selected semantics row substitution":
        records["profile"]["semantics_row_digest"] = substitution(name)
        seal(records["profile"], "provider_profile_digest")
        validate_profile_semantics(
            bundle,
            records["semantics"],
            records["profiles"],
            records["registry"],
        )
        return
    if name == "profile registry root substitution":
        records["registry"]["semantics_authority_digest"] = substitution(name)
        seal(records["registry"], "profile_registry_digest")
        validate_profile_semantics(
            bundle,
            records["semantics"],
            records["profiles"],
            records["registry"],
        )
        return
    if name == "route model absent from manifest":
        records["route"]["model_row_digest"] = substitution(name)
        seal(records["route"], "model_route_digest")
        validate_manifest_route(
            bundle,
            records["manifest"],
            records["evaluation"],
            records["capability"],
            records["price"],
            records["fallback"],
            records["route"],
        )
        return
    if name == "capability evaluation equals expiry":
        records["capability"]["valid_until_utc"] = records["evaluation"][
            "evaluation_utc"
        ]
        seal(records["capability"], "capability_authority_digest")
        validate_manifest_route(
            bundle,
            records["manifest"],
            records["evaluation"],
            records["capability"],
            records["price"],
            records["fallback"],
            records["route"],
        )
        return
    if name == "capability not yet valid":
        records["capability"]["valid_from_utc"] = "2026-07-31T00:00:00Z"
        seal(records["capability"], "capability_authority_digest")
        validate_manifest_route(
            bundle,
            records["manifest"],
            records["evaluation"],
            records["capability"],
            records["price"],
            records["fallback"],
            records["route"],
        )
        return
    if name == "resume multiple simultaneous changes exact":
        before = resume_identity(records)
        after = copy.deepcopy(before)
        for field in (
            "model_identity",
            "effort_identity",
            "thinking_identity",
            "loaded_customization_identity",
        ):
            after[field] = substitution(name + ":" + field)
        seal(after, "identity_vector_digest")
        authority = resume_authority(
            before,
            after,
            "NEW_GENERATION",
            current_generation=2,
            current_attempt=0,
        )
        validate_resume(
            bundle, authority, before, after, records, None, None
        )
        return
    raise ConformanceError("R2_5_UNKNOWN_SCENARIO")


def validate_review_binding() -> None:
    raw = read_ascii_lf(REVIEW_PATH)
    if sha256_bytes(raw) != REVIEW_WHOLE_SHA256:
        raise ConformanceError("R2_4_REVIEW_WHOLE_HASH_MISMATCH")
    marker = b"\n## Artifact integrity\n"
    position = raw.rfind(marker)
    if position < 0:
        raise ConformanceError("R2_4_REVIEW_BODY_BOUNDARY_MISSING")
    body = raw[:position]
    if not body.endswith(
        b"End of independent R2.4 blocking review.\n"
    ):
        raise ConformanceError("R2_4_REVIEW_BODY_BOUNDARY_MISMATCH")
    if sha256_bytes(body) != REVIEW_BODY_SHA256:
        raise ConformanceError("R2_4_REVIEW_BODY_HASH_MISMATCH")


def validate_vector_manifest(vectors: dict[str, Any]) -> list[dict[str, Any]]:
    if vectors.get("schema") != "plamen.model-routing-r2.5-conformance-vectors.v1":
        raise ConformanceError("R2_5_VECTOR_SCHEMA_MISMATCH")
    review = vectors.get("blocking_review", {})
    if (
        review.get("whole_sha256") != REVIEW_WHOLE_SHA256
        or review.get("body_sha256") != REVIEW_BODY_SHA256
        or review.get("declared_unexpected_accept_manifest_sha256")
        != REVIEW_DECLARED_MANIFEST_SHA256
        or review.get("recomputed_restricted_json_manifest_sha256")
        != REVIEW_RECOMPUTED_MANIFEST_SHA256
        or review.get("unexpected_accept_count") != 48
    ):
        raise ConformanceError("R2_5_VECTOR_REVIEW_BINDING_MISMATCH")
    preserved = vectors.get("preserved_denominators", {})
    if (
        preserved.get("r2_3", {}).get("count") != 186
        or preserved.get("r2_4", {}).get("count") != 314
        or preserved.get("r2_3", {}).get("validator_sha256")
        != R2_3_VALIDATOR_SHA256
        or preserved.get("r2_4", {}).get("validator_sha256")
        != R2_4_FILES[R2_4_VALIDATOR_PATH.name]
    ):
        raise ConformanceError("R2_5_PRESERVED_DENOMINATOR_MISMATCH")
    rows = vectors.get("r2_5_vectors")
    if not isinstance(rows, list) or len(rows) != 96:
        raise ConformanceError("R2_5_VECTOR_COUNT_MISMATCH")
    ids = [row.get("id") for row in rows]
    if ids != [f"R2.5-{number:03d}" for number in range(1, 97)]:
        raise ConformanceError("R2_5_VECTOR_ID_SEQUENCE_MISMATCH")
    if (
        sum(
            row.get("source") == "R2.4_INDEPENDENT_REVIEW_R1"
            for row in rows
        )
        != 48
        or sum(
            row.get("source") == "R2.5_AUTHOR_ADVERSARIAL"
            for row in rows
        )
        != 48
    ):
        raise ConformanceError("R2_5_VECTOR_SOURCE_COUNT_MISMATCH")
    if len({row.get("scenario") for row in rows}) != 96:
        raise ConformanceError("R2_5_VECTOR_SCENARIO_DUPLICATE")
    manifest = {
        "schema": "plamen.r2.4-independent-negative-outcomes.v1",
        "count": 48,
        "outcome": "UNEXPECTED_ACCEPT",
        "labels": [row["review_label"] for row in rows[:48]],
    }
    if sha256_bytes(canonical_bytes(manifest)) != REVIEW_RECOMPUTED_MANIFEST_SHA256:
        raise ConformanceError("R2_5_REVIEW_LABEL_MANIFEST_MISMATCH")
    return rows


def validate_positive_boundaries(
    bundle: dict[str, Any], r23: Any, r24: Any
) -> None:
    records = build_closure(bundle, r23, r24)
    raw, process, obj, key = proof_material(records)
    proof = EphemeralSecretProofV2.create(
        records["envelope"],
        records["predecessor_envelope"],
        records["env_policy"],
        raw,
        process,
        obj,
        key,
    )
    proof.verify(
        records["envelope"],
        records["predecessor_envelope"],
        records["env_policy"],
        raw,
        process,
        obj,
        key,
    )
    capability = SpawnCapabilityV2(
        records["envelope"], records["consumed"], proof
    )
    validate_spawn_capability(
        capability, records["envelope"], records["consumed"], proof
    )
    identity = resume_identity(records)
    retry = resume_authority(identity, identity, "RETRY_SAME_GENERATION")
    validate_resume(
        bundle, retry, identity, identity, records, None, None
    )
    completed = completed_evidence(records)
    no_relaunch = resume_authority(
        identity,
        identity,
        "NO_RELAUNCH_COMPLETED",
        current_attempt=0,
        completed=completed,
    )
    validate_resume(
        bundle,
        no_relaunch,
        identity,
        identity,
        records,
        completed,
        None,
    )
    ambiguous = ambiguity_evidence(records)
    debt = resume_authority(
        identity,
        identity,
        "AMBIGUOUS_CONSUMED_DEBT",
        current_attempt=0,
        ambiguous=ambiguous,
    )
    validate_resume(
        bundle,
        debt,
        identity,
        identity,
        records,
        None,
        ambiguous,
    )
    artifacts = {"receipt.json": b"{\"pass\":true}\n"}
    fixture = b"R2.5_FIXTURE_PASS\n"
    before = artifact_manifest(bundle, artifacts)
    after = artifact_manifest(bundle, artifacts)
    receipt = codex_parity_receipt(before, after, fixture, fixture)
    validate_codex_parity(
        bundle, receipt, artifacts, artifacts, fixture, fixture
    )
    components = [
        "runtime", "runbundle", "evaluator", "bb", "repair",
        "packaging", "ci_runtime_closure",
    ]
    evidence = {
        component: (
            identity_hash("receipt:" + component),
            identity_hash("postimage:" + component),
        )
        for component in components
    }
    authority = downstream_closure(
        {
            component: ("COMPLETE", *evidence[component])
            for component in components
        }
    )
    validate_downstream(bundle, authority, evidence)


def main() -> int:
    schema_raw = read_ascii_lf(SCHEMA_PATH)
    vector_raw = read_ascii_lf(VECTORS_PATH)
    if sha256_bytes(schema_raw) != SCHEMA_SHA256:
        raise ConformanceError("R2_5_SCHEMA_HASH_MISMATCH")
    if sha256_bytes(vector_raw) != VECTORS_SHA256:
        raise ConformanceError("R2_5_VECTORS_HASH_MISMATCH")
    validate_review_binding()
    bundle = parse_json(schema_raw)
    vectors = parse_json(vector_raw)
    try:
        Draft202012Validator.check_schema(bundle)
    except SchemaError as exc:
        raise ConformanceError("R2_5_META_SCHEMA_INVALID") from exc
    rows = validate_vector_manifest(vectors)
    r23, r24 = verify_frozen_denominators()
    validate_positive_boundaries(bundle, r23, r24)
    passed = 0
    for row in rows:
        scenario = row["scenario"]
        expected = row["expected"]
        operation = lambda scenario=scenario: run_scenario(
            bundle, r23, r24, scenario
        )
        if expected == "PASS":
            operation()
        else:
            expect_error(operation, expected)
        passed += 1
    print("R2.5_CONFORMANCE=PASS")
    print("R2_3_PRESERVED_VECTORS=186")
    print("R2_4_PRESERVED_TOTAL_VECTORS=314")
    print("R2_5_NEW_VECTORS=96")
    print("TOTAL_EXECUTED_VECTOR_DENOMINATOR=596")
    print(f"SCHEMA_SHA256={SCHEMA_SHA256}")
    print(f"VECTORS_SHA256={VECTORS_SHA256}")
    print("AUTHOR_DISPOSITION=SELF_VALIDATED_NOT_INDEPENDENT_PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ConformanceError as exc:
        print(f"R2.5_CONFORMANCE=FAIL:{exc}", file=sys.stderr)
        raise SystemExit(1)
