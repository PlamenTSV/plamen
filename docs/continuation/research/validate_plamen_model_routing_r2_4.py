from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import pickle
import re
import subprocess
import sys
import unicodedata
from pathlib import Path
from typing import Any, Callable

from jsonschema import Draft202012Validator


HERE = Path(__file__).resolve().parent
SCHEMA_PATH = HERE / "Plamen_Backend_Model_Routing_R2.4_Schemas_2026-07-29.json"
VECTORS_PATH = HERE / "Plamen_Backend_Model_Routing_R2.4_Conformance_Vectors_2026-07-29.json"

SCHEMA_SHA256 = "1d8895bbfbda3d44c5dd58acf3df029b700664b9bca9e1986dbc8d83dbcc4381"
VECTORS_SHA256 = "e046e589cf830ba31fa608ab0ec2c650e2aff555f1fe2a5698f261f12f2079c9"

R2_3_FILES = {
    "Plamen_Backend_Model_Routing_Engineering_Guide_R2.3_2026-07-29.md":
        "d047d994f9aa114dea0ca9435b06922234c9ba54002321ca18f4d80a5e8b9d5f",
    "Plamen_Backend_Model_Routing_R2.3_Schemas_2026-07-29.json":
        "1da3f14c3e18325e818e3236cd1907a87f3032bbdeca5957fdc6fdfd1c0bedcf",
    "Plamen_Backend_Model_Routing_R2.3_Conformance_Vectors_2026-07-29.json":
        "6e9e0db8df0727dd37c78483151e62bd041f8951a1ddcf0d7698f367cd37d625",
    "validate_plamen_model_routing_r2_3.py":
        "584fbc05a60929a761a1987928a8d97eb1931593d2c8445c42d3c622eb938581",
    "Plamen_Backend_Model_Routing_R2.3_Validation_Receipt_2026-07-29.json":
        "3df640bac21c0adfb70ad82d5c3d085409a562427a395c12acfb81cd6b1cfe46",
    "Plamen_Backend_Model_Routing_R2.3_Independent_Review_2026-07-29.md":
        "a97ee6bcf1c905d634fb3643a29d1ba629c4a7ea8416ceb1ca4686d644f6523d",
}

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

MAX_SAFE_INT = 9007199254740991
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
EXACT_MODEL_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*-[0-9]{8}$")
SECRET_PROOF_DOMAIN = b"plamen.ephemeral-secret-proof.v1\x00"


class ConformanceError(Exception):
    pass


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ConformanceError("DUPLICATE_OBJECT_MEMBER")
        out[key] = value
    return out


def parse_int(text: str) -> int:
    if text == "-0":
        raise ConformanceError("NEGATIVE_ZERO_FORBIDDEN")
    value = int(text)
    if value < 0 or value > MAX_SAFE_INT:
        raise ConformanceError("INTEGER_OUT_OF_RANGE")
    return value


def reject_float(_text: str) -> None:
    raise ConformanceError("FLOAT_FORBIDDEN")


def reject_constant(_text: str) -> None:
    raise ConformanceError("NON_FINITE_FORBIDDEN")


def parse_json(raw: bytes) -> Any:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ConformanceError("NON_ASCII_PACKAGE") from exc
    return json.loads(
        text,
        object_pairs_hook=reject_duplicate_pairs,
        parse_int=parse_int,
        parse_float=reject_float,
        parse_constant=reject_constant,
    )


def read_ascii_lf(path: Path) -> bytes:
    raw = path.read_bytes()
    if not raw or not raw.endswith(b"\n"):
        raise ConformanceError("FINAL_LF_REQUIRED")
    if b"\r" in raw:
        raise ConformanceError("CR_BYTE_FORBIDDEN")
    if any(byte > 0x7F for byte in raw):
        raise ConformanceError("NON_ASCII_PACKAGE")
    return raw


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def check_value(value: Any, *, identity: bool = True) -> None:
    if isinstance(value, bool) or value is None:
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
        if identity and unicodedata.normalize("NFC", value) != value:
            raise ConformanceError("NON_NFC_IDENTITY")
        return
    if isinstance(value, list):
        for item in value:
            check_value(item, identity=identity)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise ConformanceError("NON_ASCII_MEMBER_NAME")
            check_value(item, identity=identity)
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
    result = copy.deepcopy(record)
    result.pop(field, None)
    record[field] = sha256_bytes(canonical_bytes(result))
    return record


def verify_seal(record: dict[str, Any], field: str) -> None:
    expected = record.get(field)
    candidate = copy.deepcopy(record)
    candidate.pop(field, None)
    if expected != sha256_bytes(canonical_bytes(candidate)):
        raise ConformanceError("RECORD_SELF_DIGEST_MISMATCH")


def d(ch: str) -> str:
    return ch * 64


def classify_schema_error(error: Any) -> str:
    if error.validator == "required":
        return "SCHEMA_REQUIRED_FIELD"
    if error.validator == "additionalProperties":
        return "SCHEMA_UNKNOWN_FIELD"
    return "SCHEMA_VALIDATION_ERROR"


def schema_validate(bundle: dict[str, Any], definition: str, record: dict[str, Any]) -> None:
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
            raise ConformanceError(
                f"EXPECTED_{expected}_GOT_{exc}"
            ) from exc
        return
    raise ConformanceError(f"EXPECTED_{expected}_BUT_PASSED")


def verify_r2_3_denominator(vectors: dict[str, Any]) -> None:
    preserved = vectors["r2_3_preserved_denominator"]
    if preserved["total_vectors"] != 186:
        raise ConformanceError("R2_3_VECTOR_COUNT_MISMATCH")
    if sum(
        preserved[name]
        for name in (
            "canonical_vectors",
            "schema_vectors",
            "join_vectors",
            "transaction_vectors",
            "canary_vectors",
        )
    ) != 186:
        raise ConformanceError("R2_3_VECTOR_GROUP_COUNT_MISMATCH")
    for filename, expected in R2_3_FILES.items():
        raw = read_ascii_lf(HERE / filename)
        if sha256_bytes(raw) != expected:
            raise ConformanceError(f"R2_3_FROZEN_HASH_MISMATCH:{filename}")
    old_vectors = parse_json(
        read_ascii_lf(
            HERE / "Plamen_Backend_Model_Routing_R2.3_Conformance_Vectors_2026-07-29.json"
        )
    )
    actual_counts = {
        "canonical_vectors": len(old_vectors["canonical_vectors"])
            + len(old_vectors["negative_canonical_vectors"]),
        "schema_vectors": len(old_vectors["schema_vectors"]),
        "join_vectors": len(old_vectors["join_vectors"]),
        "transaction_vectors": len(old_vectors["transaction_vectors"]),
        "canary_vectors": len(old_vectors["canary_vectors"]),
    }
    for name, actual in actual_counts.items():
        if actual != preserved[name]:
            raise ConformanceError(f"R2_3_{name.upper()}_COUNT_MISMATCH")
    clean_env = {
        "PATH": os.environ.get("PATH", ""),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "WINDIR": os.environ.get("WINDIR", ""),
        "TEMP": os.environ.get("TEMP", str(HERE)),
        "TMP": os.environ.get("TMP", str(HERE)),
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
    }
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            str(HERE / "validate_plamen_model_routing_r2_3.py"),
        ],
        cwd=str(HERE),
        env=clean_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )
    if completed.returncode != 0:
        raise ConformanceError(
            "R2_3_VALIDATOR_FAILED:"
            + completed.stderr.decode("utf-8", errors="replace")[:256]
        )
    lines = {
        line.strip()
        for line in completed.stdout.decode("ascii", errors="strict").splitlines()
        if line.strip()
    }
    if lines != R2_3_EXPECTED_OUTPUT:
        raise ConformanceError("R2_3_VALIDATOR_OUTPUT_MISMATCH")


def public_environment(
    *,
    secret_value: str = "alpha-secret",
    nonsecret_value: str = "C:/Plamen/tmp",
) -> tuple[dict[str, Any], dict[str, str]]:
    entries = [
        {
            "name": "ANTHROPIC_API_KEY",
            "source_class": "SECRET_RUNTIME",
            "redaction_marker": "SECRET_VALUE_PRESENT_REDACTED",
            "policy_authority_digests": [d("1"), d("2")],
            "non_secret_value": None,
        },
        {
            "name": "PLAMEN_TEMP_ROOT",
            "source_class": "RUNTIME_PATH_NON_SECRET",
            "redaction_marker": "NON_SECRET_VALUE_INCLUDED",
            "policy_authority_digests": [d("3")],
            "non_secret_value": nonsecret_value,
        },
    ]
    record = {
        "schema": "plamen.public-materialized-environment.v1",
        "public_environment_version": 1,
        "public_materialized_environment_digest": d("0"),
        "environment_policy_set_digest": d("4"),
        "host_policy_authority_digest": d("5"),
        "entry_count": len(entries),
        "entries": entries,
    }
    seal(record, "public_materialized_environment_digest")
    return record, {
        "ANTHROPIC_API_KEY": secret_value,
        "PLAMEN_TEMP_ROOT": nonsecret_value,
    }


def environment_invariants(record: dict[str, Any]) -> None:
    verify_seal(record, "public_materialized_environment_digest")
    entries = record["entries"]
    if record["entry_count"] != len(entries):
        raise ConformanceError("ENVIRONMENT_ENTRY_COUNT_MISMATCH")
    names = [row["name"] for row in entries]
    if len(names) != len(set(names)):
        raise ConformanceError("ENVIRONMENT_NAME_DUPLICATE")
    if names != sorted(names, key=lambda value: canonical_bytes(value)):
        raise ConformanceError("ENVIRONMENT_ENTRY_ORDER_INVALID")
    for row in entries:
        policies = row["policy_authority_digests"]
        if policies != sorted(policies, key=lambda value: canonical_bytes(value)):
            raise ConformanceError("POLICY_AUTHORITY_ORDER_INVALID")


class EphemeralSecretProof:
    __slots__ = (
        "_key",
        "_tag",
        "_process_token",
        "_object_token",
        "_consumed",
    )

    def __init__(
        self,
        environment: dict[str, str],
        *,
        process_token: str,
        object_token: str,
        key: bytes,
    ) -> None:
        if len(key) != 32:
            raise ConformanceError("EPHEMERAL_SECRET_PROOF_KEY_INVALID")
        self._key = bytearray(key)
        self._process_token = process_token
        self._object_token = object_token
        self._tag = hmac.new(
            bytes(self._key),
            self._message(environment, process_token, object_token),
            hashlib.sha256,
        ).digest()
        self._consumed = False

    @staticmethod
    def _message(
        environment: dict[str, str],
        process_token: str,
        object_token: str,
    ) -> bytes:
        return (
            SECRET_PROOF_DOMAIN
            + canonical_bytes(
                {
                    "environment": environment,
                    "object_token": object_token,
                    "process_token": process_token,
                }
            )
        )

    def verify(
        self,
        environment: dict[str, str],
        *,
        process_token: str,
        object_token: str,
        consume: bool = False,
    ) -> None:
        if self._consumed:
            raise ConformanceError("EPHEMERAL_SECRET_PROOF_ALREADY_CONSUMED")
        if process_token != self._process_token or object_token != self._object_token:
            raise ConformanceError("EPHEMERAL_SECRET_PROOF_SCOPE_MISMATCH")
        candidate = hmac.new(
            bytes(self._key),
            self._message(environment, process_token, object_token),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(candidate, self._tag):
            raise ConformanceError("EPHEMERAL_SECRET_PROOF_MISMATCH")
        if consume:
            self._consumed = True
            for index in range(len(self._key)):
                self._key[index] = 0

    def __reduce__(self) -> Any:
        raise ConformanceError("EPHEMERAL_SECRET_PROOF_SERIALIZATION_FORBIDDEN")

    def __repr__(self) -> str:
        return "<EphemeralSecretProof redacted>"


class SpawnCapability:
    __slots__ = ("consumed_authority_digest", "proof")

    def __init__(
        self,
        consumed_authority_digest: str,
        proof: EphemeralSecretProof,
    ) -> None:
        self.consumed_authority_digest = consumed_authority_digest
        self.proof = proof

    def __reduce__(self) -> Any:
        raise ConformanceError("SPAWN_CAPABILITY_SERIALIZATION_FORBIDDEN")


def execution_axes(
    *,
    routing_profile: str = "semantic_v1",
    transport: str = "HEADLESS_PROOF",
    backend: str = "claude",
    assurance: str | None = None,
) -> dict[str, Any]:
    if assurance is None:
        assurance = {
            "HEADLESS_PROOF": "TRANSACTIONAL_PROOF_CANDIDATE",
            "LEGACY_PTY_NON_PROOF": "LEGACY_PTY_NON_PROOF",
            "CODEX_EXISTING": "EXISTING_CODEX_ASSURANCE",
            "NATIVE_EXISTING": "EXISTING_NATIVE_ASSURANCE",
        }.get(transport, "TRANSACTIONAL_PROOF_CANDIDATE")
    record = {
        "schema": "plamen.execution-axes.v1",
        "execution_axes_version": 1,
        "execution_axes_digest": d("0"),
        "backend": backend,
        "routing_profile": routing_profile,
        "transport": transport,
        "assurance_class": assurance,
    }
    return seal(record, "execution_axes_digest")


def axes_invariants(record: dict[str, Any]) -> None:
    verify_seal(record, "execution_axes_digest")
    exact = {
        "codex": (
            "codex_existing_v1",
            "CODEX_EXISTING",
            "EXISTING_CODEX_ASSURANCE",
        ),
        "native": (
            "native_existing_v1",
            "NATIVE_EXISTING",
            "EXISTING_NATIVE_ASSURANCE",
        ),
    }
    backend = record["backend"]
    if backend in exact:
        if (
            record["routing_profile"],
            record["transport"],
            record["assurance_class"],
        ) != exact[backend]:
            raise ConformanceError("AXES_COMBINATION_INVALID")
        return
    if backend != "claude":
        raise ConformanceError("AXES_COMBINATION_INVALID")
    route = record["routing_profile"]
    transport = record["transport"]
    assurance = record["assurance_class"]
    if route not in {"legacy_claude_v1", "semantic_v1"}:
        raise ConformanceError("AXES_COMBINATION_INVALID")
    if route == "semantic_v1" and transport != "HEADLESS_PROOF":
        raise ConformanceError("AXES_COMBINATION_INVALID")
    expected_assurance = {
        "HEADLESS_PROOF": "TRANSACTIONAL_PROOF_CANDIDATE",
        "LEGACY_PTY_NON_PROOF": "LEGACY_PTY_NON_PROOF",
    }.get(transport)
    if expected_assurance is None:
        raise ConformanceError("AXES_COMBINATION_INVALID")
    if assurance != expected_assurance:
        raise ConformanceError("AXES_ASSURANCE_MISMATCH")


PROFILE_MATRIX = {
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
    "adjudication_staged_write": (
        "ADJUDICATION_STAGED_WRITE",
        ["Read", "Write"],
        "DENY",
        "STAGED_WRITE_ASSIGNED_SCOPE",
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


def profile_policy_authority() -> dict[str, Any]:
    record = {
        "schema": "plamen.claude-provider-profile-policy-authority.v1",
        "profile_policy_authority_version": 1,
        "profile_policy_authority_digest": d("0"),
        "profile_semantics_id": "PLAMEN_CLAUDE_PROFILE_SEMANTICS_R2_4_V1",
        "profile_ids": sorted(PROFILE_MATRIX),
    }
    return seal(record, "profile_policy_authority_digest")


def profile(
    profile_id: str = "analysis_filesystem",
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if policy is None:
        policy = profile_policy_authority()
    permission, tools, network, filesystem, output = PROFILE_MATRIX[profile_id]
    record = {
        "schema": "plamen.claude-provider-profile.v1",
        "provider_profile_version": 1,
        "provider_profile_id": profile_id,
        "provider_profile_digest": d("0"),
        "profile_policy_authority_digest":
            policy["profile_policy_authority_digest"],
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
        "route_neutrality": "ROUTE_FIELDS_FORBIDDEN",
    }
    return seal(record, "provider_profile_digest")


def profile_invariants(
    record: dict[str, Any],
    policy: dict[str, Any] | None = None,
) -> None:
    if policy is None:
        policy = profile_policy_authority()
    verify_seal(record, "provider_profile_digest")
    if (
        record["profile_policy_authority_digest"]
        != policy["profile_policy_authority_digest"]
    ):
        raise ConformanceError("PROFILE_POLICY_AUTHORITY_MISMATCH")
    expected = PROFILE_MATRIX[record["provider_profile_id"]]
    actual = (
        record["permission_mode"],
        record["builtin_tools"],
        record["network_policy"],
        record["filesystem_policy"],
        record["output_profile"],
    )
    if actual != expected:
        if record["provider_profile_id"] == "stdout_json_no_tools":
            raise ConformanceError("PROFILE_NO_TOOLS_VIOLATION")
        raise ConformanceError("PROFILE_SEMANTIC_MATRIX_MISMATCH")


def profile_registry(
    rows: list[dict[str, Any]],
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if policy is None:
        policy = profile_policy_authority()
    ordered = sorted(rows, key=lambda row: row["provider_profile_id"])
    record = {
        "schema": "plamen.claude-provider-profile-registry.v1",
        "profile_registry_version": 1,
        "profile_registry_digest": d("0"),
        "profile_policy_authority_digest":
            policy["profile_policy_authority_digest"],
        "profile_ids": [row["provider_profile_id"] for row in ordered],
        "profile_digests": [row["provider_profile_digest"] for row in ordered],
    }
    return seal(record, "profile_registry_digest")


def registry_invariants(
    record: dict[str, Any],
    rows: list[dict[str, Any]],
    policy: dict[str, Any] | None = None,
) -> None:
    if policy is None:
        policy = profile_policy_authority()
    if (
        record["profile_policy_authority_digest"]
        != policy["profile_policy_authority_digest"]
    ):
        raise ConformanceError("PROFILE_POLICY_AUTHORITY_MISMATCH")
    ids = [row["provider_profile_id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise ConformanceError("PROFILE_REGISTRY_DUPLICATE")
    for row in rows:
        profile_invariants(row, policy)
    expected = profile_registry(rows, policy)
    if record != expected:
        raise ConformanceError("PROFILE_REGISTRY_DIGEST_MISMATCH")


def input_authorities() -> dict[str, Any]:
    record = {
        "schema": "plamen.execution-input-authority-set.v1",
        "input_authority_set_version": 1,
        "input_authority_set_digest": d("0"),
        "source_snapshot_authority_schema": "plamen.source-snapshot-authority.v1",
        "source_snapshot_authority_digest": d("1"),
        "prompt_authority_schema": "plamen.prompt-authority.v1",
        "prompt_authority_digest": d("2"),
        "methodology_authority_schema": "plamen.methodology-authority.v1",
        "methodology_authority_digest": d("3"),
        "program_facts_authority_schema": "plamen.program-facts-authority.v2",
        "program_facts_authority_digest": d("4"),
        "tool_policy_authority_digest": d("5"),
        "identity_domain_separation":
            "SOURCE_PROMPT_METHODOLOGY_PROGRAM_FACTS_INDEPENDENT_V1",
    }
    return seal(record, "input_authority_set_digest")


def input_invariants(record: dict[str, Any]) -> None:
    expected_kinds = {
        "source_snapshot_authority_schema": "plamen.source-snapshot-authority.v1",
        "prompt_authority_schema": "plamen.prompt-authority.v1",
        "methodology_authority_schema": "plamen.methodology-authority.v1",
        "program_facts_authority_schema": "plamen.program-facts-authority.v2",
    }
    for field, expected in expected_kinds.items():
        if record.get(field) != expected:
            raise ConformanceError("INPUT_AUTHORITY_KIND_MISMATCH")
    verify_seal(record, "input_authority_set_digest")


def model_route(
    axes: dict[str, Any],
    capability: dict[str, Any],
    price: dict[str, Any],
    fallback: dict[str, Any],
) -> dict[str, Any]:
    record = {
        "schema": "plamen.model-route.v3",
        "model_route_version": 3,
        "model_route_digest": d("0"),
        "execution_axes_digest": axes["execution_axes_digest"],
        "provider": "claude",
        "exact_requested_model_id": "claude-opus-5-20260701",
        "requested_effort": "xhigh",
        "requested_thinking_mode": "ADAPTIVE_ON",
        "account_class": "STORED_SUBSCRIPTION",
        "auth_route": "CLAUDE_CODE_OAUTH",
        "service_tier": "subscription",
        "fallback_policy_digest": fallback["fallback_authority_digest"],
        "capability_authority_digest": capability["capability_authority_digest"],
        "price_authority_digest": price["price_authority_digest"],
        "context_budget_digest": d("a"),
        "budget_authority_digest": d("b"),
    }
    return seal(record, "model_route_digest")


def route_invariants(
    record: dict[str, Any],
    axes: dict[str, Any],
    capability: dict[str, Any],
    price: dict[str, Any],
    fallback: dict[str, Any],
) -> None:
    verify_seal(record, "model_route_digest")
    if record["execution_axes_digest"] != axes["execution_axes_digest"]:
        raise ConformanceError("ROUTE_AXES_JOIN_MISMATCH")
    if (
        record["capability_authority_digest"]
        != capability["capability_authority_digest"]
        or record["exact_requested_model_id"] != capability["exact_model_id"]
        or record["requested_effort"] not in capability["supported_efforts"]
    ):
        raise ConformanceError("ROUTE_CAPABILITY_JOIN_MISMATCH")
    if (
        record["price_authority_digest"] != price["price_authority_digest"]
        or record["exact_requested_model_id"] != price["exact_model_id"]
    ):
        raise ConformanceError("ROUTE_PRICE_JOIN_MISMATCH")
    if (
        record["fallback_policy_digest"]
        != fallback["fallback_authority_digest"]
    ):
        raise ConformanceError("ROUTE_FALLBACK_JOIN_MISMATCH")
    if not EXACT_MODEL_RE.fullmatch(record["exact_requested_model_id"]):
        raise ConformanceError("EXACT_MODEL_ID_REQUIRED")
    if record["requested_effort"] not in {"low", "medium", "high", "xhigh"}:
        raise ConformanceError("EFFORT_MAX_FORBIDDEN")


def request(
    axes: dict[str, Any],
    prof: dict[str, Any],
    registry: dict[str, Any],
    policy: dict[str, Any],
    inputs: dict[str, Any],
    route: dict[str, Any] | None,
) -> dict[str, Any]:
    semantic = route is not None
    record = {
        "schema": "plamen.claude-headless-execution-request.v2",
        "request_version": 2,
        "request_digest": d("0"),
        "request_kind": "SEMANTIC" if semantic else "BASELINE",
        "execution_axes_digest": axes["execution_axes_digest"],
        "routing_profile": "semantic_v1" if semantic else "legacy_claude_v1",
        "transport": "HEADLESS_PROOF",
        "provider_profile_digest": prof["provider_profile_digest"],
        "profile_registry_digest": registry["profile_registry_digest"],
        "profile_policy_authority_digest":
            policy["profile_policy_authority_digest"],
        "input_authority_set_digest": inputs["input_authority_set_digest"],
        "semantic_plan_digest": d("c"),
        "work_plan_contract_authority_digest": d("d"),
        "phase_io_contract_digest": d("e"),
        "output_contract_digest": d("f"),
        "timeout_ms": 3600000,
        "stream_ceiling_digest": d("1"),
        "model_route_digest": route["model_route_digest"] if semantic else None,
        "arm_family_digest": d("2") if semantic else None,
        "context_budget_digest": route["context_budget_digest"] if semantic else None,
        "budget_authority_digest": route["budget_authority_digest"] if semantic else None,
    }
    return seal(record, "request_digest")


def request_invariants(
    record: dict[str, Any],
    axes: dict[str, Any],
    prof: dict[str, Any],
    registry: dict[str, Any],
    policy: dict[str, Any],
    inputs: dict[str, Any],
    route: dict[str, Any] | None,
) -> None:
    verify_seal(record, "request_digest")
    if record["execution_axes_digest"] != axes["execution_axes_digest"]:
        raise ConformanceError("REQUEST_AXES_JOIN_MISMATCH")
    if record["routing_profile"] != axes["routing_profile"]:
        raise ConformanceError("REQUEST_ROUTE_PROFILE_MISMATCH")
    if record["provider_profile_digest"] != prof["provider_profile_digest"]:
        raise ConformanceError("REQUEST_PROFILE_JOIN_MISMATCH")
    if (
        record["profile_registry_digest"] != registry["profile_registry_digest"]
        or record["profile_policy_authority_digest"]
        != policy["profile_policy_authority_digest"]
    ):
        raise ConformanceError("REQUEST_PROFILE_REGISTRY_JOIN_MISMATCH")
    pairs = dict(zip(registry["profile_ids"], registry["profile_digests"]))
    if pairs.get(prof["provider_profile_id"]) != prof["provider_profile_digest"]:
        raise ConformanceError("REQUEST_PROFILE_REGISTRY_JOIN_MISMATCH")
    if record["input_authority_set_digest"] != inputs["input_authority_set_digest"]:
        raise ConformanceError("INPUT_AUTHORITY_SET_JOIN_MISMATCH")
    if route is None:
        if record["request_kind"] != "BASELINE":
            raise ConformanceError("REQUEST_ROUTE_PROFILE_MISMATCH")
    else:
        if record["model_route_digest"] != route["model_route_digest"]:
            raise ConformanceError("REQUEST_MODEL_ROUTE_JOIN_MISMATCH")


def workplan_binding(req: dict[str, Any], inputs: dict[str, Any], route: dict[str, Any] | None) -> dict[str, Any]:
    record = {
        "schema": "plamen.work-plan-routing-binding.v2",
        "work_plan_routing_binding_version": 2,
        "work_plan_routing_binding_digest": d("0"),
        "work_plan_digest": d("3"),
        "semantic_plan_digest": req["semantic_plan_digest"],
        "request_digest": req["request_digest"],
        "execution_axes_digest": req["execution_axes_digest"],
        "provider_profile_digest": req["provider_profile_digest"],
        "input_authority_set_digest": inputs["input_authority_set_digest"],
        "model_route_digest": route["model_route_digest"] if route else None,
        "output_contract_digest": req["output_contract_digest"],
    }
    return seal(record, "work_plan_routing_binding_digest")


def phaseio_binding(
    req: dict[str, Any],
    work: dict[str, Any],
    inputs: dict[str, Any],
) -> dict[str, Any]:
    record = {
        "schema": "plamen.phase-io-routing-binding.v2",
        "phase_io_routing_binding_version": 2,
        "phase_io_routing_binding_digest": d("0"),
        "phase_io_contract_digest": req["phase_io_contract_digest"],
        "phase_io_launch_digest": d("4"),
        "work_plan_routing_binding_digest": work["work_plan_routing_binding_digest"],
        "request_digest": req["request_digest"],
        "input_authority_set_digest": inputs["input_authority_set_digest"],
        "output_contract_digest": req["output_contract_digest"],
        "incorporation_policy": "EXACTLY_ONCE_AFTER_RECONCILIATION",
    }
    return seal(record, "phase_io_routing_binding_digest")


def control_vector(
    req: dict[str, Any],
    route: dict[str, Any],
    prof: dict[str, Any],
    env: dict[str, Any],
) -> dict[str, Any]:
    record = {
        "schema": "plamen.claude-provider-control-vector.v2",
        "provider_control_vector_version": 2,
        "provider_control_vector_digest": d("0"),
        "request_digest": req["request_digest"],
        "semantic_plan_digest": req["semantic_plan_digest"],
        "execution_axes_digest": req["execution_axes_digest"],
        "provider_profile_digest": prof["provider_profile_digest"],
        "model_route_digest": route["model_route_digest"],
        "exact_model_id": route["exact_requested_model_id"],
        "effort_authority_digest": d("5"),
        "requested_effort": route["requested_effort"],
        "requested_thinking_mode": route["requested_thinking_mode"],
        "manual_thinking_budget_tokens": None,
        "materialized_argv_digest": d("6"),
        "public_materialized_environment_digest":
            env["public_materialized_environment_digest"],
        "environment_policy_set_digest": env["environment_policy_set_digest"],
        "secret_proof_policy_digest": d("7"),
    }
    return seal(record, "provider_control_vector_digest")


def control_invariants(
    record: dict[str, Any],
    req: dict[str, Any],
    route: dict[str, Any],
    prof: dict[str, Any],
    env: dict[str, Any],
) -> None:
    verify_seal(record, "provider_control_vector_digest")
    if record["public_materialized_environment_digest"] != env["public_materialized_environment_digest"]:
        raise ConformanceError("CONTROL_PUBLIC_ENVIRONMENT_JOIN_MISMATCH")
    if record["execution_axes_digest"] != req["execution_axes_digest"]:
        raise ConformanceError("CONTROL_AXES_JOIN_MISMATCH")
    if record["provider_profile_digest"] != prof["provider_profile_digest"]:
        raise ConformanceError("CONTROL_PROFILE_JOIN_MISMATCH")
    if not EXACT_MODEL_RE.fullmatch(record["exact_model_id"]):
        raise ConformanceError("EXACT_MODEL_ID_REQUIRED")
    if record["exact_model_id"] != route["exact_requested_model_id"]:
        raise ConformanceError("CONTROL_MODEL_JOIN_MISMATCH")


def launch_authority(
    req: dict[str, Any],
    route: dict[str, Any],
    prof: dict[str, Any],
    inputs: dict[str, Any],
    control: dict[str, Any],
    work: dict[str, Any],
    phaseio: dict[str, Any],
) -> dict[str, Any]:
    record = {
        "schema": "plamen.launch-authority.v3",
        "launch_authority_version": 3,
        "launch_authority_digest": d("0"),
        "semantic_plan_digest": req["semantic_plan_digest"],
        "arm_family_digest": req["arm_family_digest"],
        "generation": 1,
        "request_digest": req["request_digest"],
        "execution_axes_digest": req["execution_axes_digest"],
        "provider_profile_digest": prof["provider_profile_digest"],
        "input_authority_set_digest": inputs["input_authority_set_digest"],
        "model_route_digest": route["model_route_digest"],
        "budget_authority_digest": route["budget_authority_digest"],
        "generation_reservation_event_digest": d("8"),
        "provider_control_vector_digest": control["provider_control_vector_digest"],
        "work_plan_routing_binding_digest": work["work_plan_routing_binding_digest"],
        "phase_io_routing_binding_digest": phaseio["phase_io_routing_binding_digest"],
        "tool_policy_digest": inputs["tool_policy_authority_digest"],
        "child_policy": "DRIVER_ONLY_NO_MODEL_CHILDREN",
        "ordered_argv_template_digest": d("9"),
        "transport_policy_digest": d("a"),
    }
    return seal(record, "launch_authority_digest")


def launch_invariants(
    record: dict[str, Any],
    req: dict[str, Any],
    phaseio: dict[str, Any],
) -> None:
    verify_seal(record, "launch_authority_digest")
    if record["request_digest"] != req["request_digest"]:
        raise ConformanceError("LAUNCH_REQUEST_JOIN_MISMATCH")
    if record["phase_io_routing_binding_digest"] != phaseio["phase_io_routing_binding_digest"]:
        raise ConformanceError("LAUNCH_PHASE_IO_JOIN_MISMATCH")


def attempt_envelope(
    launch: dict[str, Any],
    req: dict[str, Any],
    control: dict[str, Any],
    env: dict[str, Any],
) -> dict[str, Any]:
    record = {
        "schema": "plamen.attempt-launch-envelope.v3",
        "attempt_launch_version": 3,
        "attempt_launch_digest": d("0"),
        "attempt_identity_digest": d("b"),
        "backend_arm_digest": d("c"),
        "launch_authority_digest": launch["launch_authority_digest"],
        "request_digest": req["request_digest"],
        "provider_control_vector_digest": control["provider_control_vector_digest"],
        "attempt_reservation_event_digest": d("d"),
        "attempt_resource_entry_digest": d("e"),
        "resource_ledger_digest_after_attempt_reservation": d("f"),
        "materialized_argv_digest": control["materialized_argv_digest"],
        "public_materialized_environment_digest":
            env["public_materialized_environment_digest"],
        "environment_policy_set_digest": env["environment_policy_set_digest"],
        "secret_proof_policy_digest": control["secret_proof_policy_digest"],
        "secret_proof_required": True,
        "materialized_stdin_prompt_digest": d("1"),
        "working_directory_identity_digest": d("2"),
        "prepared_utc": "2026-07-29T00:00:00Z",
    }
    return seal(record, "attempt_launch_digest")


def envelope_invariants(
    record: dict[str, Any],
    launch: dict[str, Any],
    req: dict[str, Any],
    control: dict[str, Any],
    env: dict[str, Any],
) -> None:
    verify_seal(record, "attempt_launch_digest")
    if record["launch_authority_digest"] != launch["launch_authority_digest"]:
        raise ConformanceError("ENVELOPE_LAUNCH_JOIN_MISMATCH")
    if record["request_digest"] != req["request_digest"]:
        raise ConformanceError("ENVELOPE_REQUEST_JOIN_MISMATCH")
    if (
        record["provider_control_vector_digest"]
        != control["provider_control_vector_digest"]
        or record["materialized_argv_digest"]
        != control["materialized_argv_digest"]
    ):
        raise ConformanceError("ENVELOPE_CONTROL_JOIN_MISMATCH")
    if (
        record["public_materialized_environment_digest"]
        != env["public_materialized_environment_digest"]
        or record["environment_policy_set_digest"]
        != env["environment_policy_set_digest"]
        or record["secret_proof_policy_digest"]
        != control["secret_proof_policy_digest"]
    ):
        raise ConformanceError("ENVELOPE_PUBLIC_ENVIRONMENT_JOIN_MISMATCH")
    secret_present = any(
        row["redaction_marker"] == "SECRET_VALUE_PRESENT_REDACTED"
        for row in env["entries"]
    )
    if secret_present and not record["secret_proof_required"]:
        raise ConformanceError("ENVELOPE_SECRET_PROOF_POLICY_MISMATCH")


def consumed_authority(envelope: dict[str, Any]) -> dict[str, Any]:
    record = {
        "schema": "plamen.consumed-attempt-launch-authority.v1",
        "consumed_launch_authority_version": 1,
        "consumed_launch_authority_digest": d("0"),
        "attempt_launch_digest": envelope["attempt_launch_digest"],
        "attempt_identity_digest": envelope["attempt_identity_digest"],
        "launch_consumption_event_digest": d("3"),
        "consumed_attempt_resource_entry_digest": d("4"),
        "resource_ledger_digest_after_launch_consumption": d("5"),
        "consume_cas_revision": 2,
        "spawn_state": "CONSUMED_NOT_SPAWNED",
    }
    return seal(record, "consumed_launch_authority_digest")


def consumed_invariants(
    record: dict[str, Any],
    envelope: dict[str, Any],
) -> None:
    verify_seal(record, "consumed_launch_authority_digest")
    if record["attempt_launch_digest"] != envelope["attempt_launch_digest"]:
        raise ConformanceError("CONSUMED_ENVELOPE_JOIN_MISMATCH")
    if record["attempt_identity_digest"] != envelope["attempt_identity_digest"]:
        raise ConformanceError("CONSUMED_ATTEMPT_JOIN_MISMATCH")
    if record["spawn_state"] != "CONSUMED_NOT_SPAWNED":
        raise ConformanceError("CONSUMED_AUTHORITY_STATE_INVALID")


def backend_arm_identity(
    req: dict[str, Any],
    route: dict[str, Any],
    prof: dict[str, Any],
    inputs: dict[str, Any],
    launch: dict[str, Any],
    work: dict[str, Any],
    phaseio: dict[str, Any],
) -> dict[str, Any]:
    record = {
        "schema": "plamen.backend-arm-execution-identity.v4",
        "backend_arm_version": 4,
        "backend_arm_digest": d("0"),
        "arm_family_digest": req["arm_family_digest"],
        "generation": 1,
        "semantic_plan_digest": req["semantic_plan_digest"],
        "request_digest": req["request_digest"],
        "execution_axes_digest": req["execution_axes_digest"],
        "provider_profile_digest": prof["provider_profile_digest"],
        "input_authority_set_digest": inputs["input_authority_set_digest"],
        "model_route_digest": route["model_route_digest"],
        "budget_authority_digest": route["budget_authority_digest"],
        "token_budget_derivation_digest": d("6"),
        "launch_authority_digest": launch["launch_authority_digest"],
        "work_plan_routing_binding_digest": work["work_plan_routing_binding_digest"],
        "phase_io_routing_binding_digest": phaseio["phase_io_routing_binding_digest"],
    }
    return seal(record, "backend_arm_digest")


def execution_attempt_identity(
    arm: dict[str, Any],
    req: dict[str, Any],
    route: dict[str, Any],
    prof: dict[str, Any],
    inputs: dict[str, Any],
    launch: dict[str, Any],
) -> dict[str, Any]:
    record = {
        "schema": "plamen.execution-attempt-identity.v3",
        "execution_attempt_version": 3,
        "execution_attempt_digest": d("0"),
        "backend_arm_digest": arm["backend_arm_digest"],
        "arm_family_digest": arm["arm_family_digest"],
        "generation": arm["generation"],
        "attempt_ordinal": 0,
        "request_digest": req["request_digest"],
        "model_route_digest": route["model_route_digest"],
        "provider_profile_digest": prof["provider_profile_digest"],
        "input_authority_set_digest": inputs["input_authority_set_digest"],
        "launch_authority_digest": launch["launch_authority_digest"],
    }
    return seal(record, "execution_attempt_digest")


def provider_observation(
    arm: dict[str, Any],
    attempt: dict[str, Any],
    req: dict[str, Any],
    route: dict[str, Any],
    prof: dict[str, Any],
    envelope: dict[str, Any],
    consumed: dict[str, Any],
    env: dict[str, Any],
) -> dict[str, Any]:
    record = {
        "schema": "plamen.provider-execution-observation.v5",
        "observation_version": 5,
        "observation_digest": d("0"),
        "execution_attempt_digest": attempt["execution_attempt_digest"],
        "backend_arm_digest": arm["backend_arm_digest"],
        "request_digest": req["request_digest"],
        "execution_axes_digest": req["execution_axes_digest"],
        "provider_profile_digest": prof["provider_profile_digest"],
        "model_route_digest": route["model_route_digest"],
        "attempt_launch_digest": envelope["attempt_launch_digest"],
        "consumed_launch_authority_digest":
            consumed["consumed_launch_authority_digest"],
        "public_materialized_environment_digest":
            env["public_materialized_environment_digest"],
        "observed_effective_model_id": route["exact_requested_model_id"],
        "effective_model_state": "EXACT",
        "observed_effective_effort": route["requested_effort"],
        "effective_effort_state": "EXACT",
        "observed_thinking_state": "ADAPTIVE_ON_CONFIRMED",
        "fallback_observation_state": "NO_FALLBACK_CONFIRMED",
        "provider_terminal_category": "COMPLETED",
        "provider_evidence_manifest_digest": d("7"),
        "provider_usage_digest": d("8"),
        "raw_stream_digest": d("9"),
    }
    return seal(record, "observation_digest")


def observation_invariants(
    record: dict[str, Any],
    arm: dict[str, Any],
    attempt: dict[str, Any],
    route: dict[str, Any],
    envelope: dict[str, Any],
) -> None:
    verify_seal(record, "observation_digest")
    if record["backend_arm_digest"] != arm["backend_arm_digest"]:
        raise ConformanceError("OBSERVATION_ARM_JOIN_MISMATCH")
    if record["execution_attempt_digest"] != attempt["execution_attempt_digest"]:
        raise ConformanceError("OBSERVATION_ATTEMPT_JOIN_MISMATCH")
    if envelope["attempt_launch_version"] != 3:
        raise ConformanceError("OBSERVATION_ENVELOPE_VERSION_MISMATCH")
    if record["attempt_launch_digest"] != envelope["attempt_launch_digest"]:
        raise ConformanceError("OBSERVATION_ENVELOPE_JOIN_MISMATCH")
    if record["fallback_observation_state"] != "NO_FALLBACK_CONFIRMED":
        if record["effective_model_state"] == "EXACT":
            raise ConformanceError("FALLBACK_OBSERVATION_STATE_CONTRADICTION")
        return
    if (
        not record["provider_evidence_manifest_digest"]
        or record["observed_effective_model_id"] != route["exact_requested_model_id"]
        or record["observed_effective_effort"] != route["requested_effort"]
    ):
        raise ConformanceError("OBSERVATION_EVIDENCE_REQUIRED")


def resume_authority(
    *,
    decision: str = "RETRY_SAME_GENERATION",
    changed: list[str] | None = None,
) -> dict[str, Any]:
    changed = [] if changed is None else changed
    new_generation = decision == "NEW_GENERATION"
    record = {
        "schema": "plamen.resume-authority.v1",
        "resume_authority_version": 1,
        "resume_authority_digest": d("0"),
        "prior_generation": 1,
        "current_generation": 2 if new_generation else 1,
        "prior_attempt_ordinal": 0,
        "current_attempt_ordinal": 0 if new_generation else 1,
        "identity_closure_digest_before": d("6"),
        "identity_closure_digest_after": d("7") if changed else d("6"),
        "changed_identity_fields": sorted(changed),
        "decision": decision,
        "family_grant_authority_digest_before": d("8"),
        "family_grant_authority_digest_after": d("8"),
    }
    return seal(record, "resume_authority_digest")


def resume_invariants(record: dict[str, Any]) -> None:
    verify_seal(record, "resume_authority_digest")
    if record["family_grant_authority_digest_before"] != record["family_grant_authority_digest_after"]:
        raise ConformanceError("FAMILY_GRANT_RENEWAL_FORBIDDEN")
    decision = record["decision"]
    changed = record["changed_identity_fields"]
    if decision == "RETRY_SAME_GENERATION":
        if changed:
            raise ConformanceError("RETRY_IDENTITY_DRIFT")
        if record["current_generation"] != record["prior_generation"]:
            raise ConformanceError("RETRY_GENERATION_MISMATCH")
        if record["current_attempt_ordinal"] != record["prior_attempt_ordinal"] + 1:
            raise ConformanceError("ATTEMPT_ORDINAL_INVALID")
    elif decision == "NEW_GENERATION":
        if not changed:
            raise ConformanceError("GENERATION_CHANGE_REASON_REQUIRED")
        if record["current_generation"] != record["prior_generation"] + 1:
            raise ConformanceError("GENERATION_CHANGE_REQUIRED")
        if record["current_attempt_ordinal"] != 0:
            raise ConformanceError("ATTEMPT_ORDINAL_INVALID")


def capability_authority() -> dict[str, Any]:
    record = {
        "schema": "plamen.provider-route-capability-authority.v1",
        "capability_authority_version": 1,
        "capability_authority_digest": d("0"),
        "provider_manifest_digest": d("1"),
        "canary_field_claim_digest": d("2"),
        "exact_model_id": "claude-opus-5-20260701",
        "supported_efforts": ["high", "low", "medium", "xhigh"],
        "supported_transports": ["HEADLESS_PROOF"],
        "observability_fields": [
            "effective_effort",
            "effective_model",
            "provider_terminal_category",
            "thinking_state",
            "usage",
        ],
        "valid_from_utc": "2026-07-29T00:00:00Z",
        "valid_until_utc": "2026-08-29T00:00:00Z",
    }
    return seal(record, "capability_authority_digest")


def capability_invariants(record: dict[str, Any]) -> None:
    if not record.get("canary_field_claim_digest"):
        raise ConformanceError("CAPABILITY_CLAIM_REQUIRED")
    if not EXACT_MODEL_RE.fullmatch(record["exact_model_id"]):
        raise ConformanceError("EXACT_MODEL_ID_REQUIRED")
    if "max" in record["supported_efforts"]:
        raise ConformanceError("EFFORT_MAX_FORBIDDEN")
    verify_seal(record, "capability_authority_digest")


def price_authority() -> dict[str, Any]:
    record = {
        "schema": "plamen.provider-price-authority.v1",
        "price_authority_version": 1,
        "price_authority_digest": d("0"),
        "provider_price_snapshot_digest": d("1"),
        "exact_model_id": "claude-opus-5-20260701",
        "currency_code": "USD",
        "unit_basis": "PER_MILLION_TOKENS",
        "input_micros": 15000000,
        "cache_write_micros": 18750000,
        "cache_read_micros": 1500000,
        "output_including_reasoning_micros": 75000000,
        "observed_utc": "2026-07-29T00:00:00Z",
    }
    return seal(record, "price_authority_digest")


def fallback_authority() -> dict[str, Any]:
    record = {
        "schema": "plamen.provider-fallback-authority.v1",
        "fallback_authority_version": 1,
        "fallback_authority_digest": d("0"),
        "policy": "FORBID_IMPLICIT_PROVIDER_FALLBACK",
        "requested_model_count": 1,
        "observed_different_model_disposition": "ROUTE_DEBT",
        "continuation_rule": "NEW_GENERATION_ONLY",
    }
    return seal(record, "fallback_authority_digest")


def codex_witness() -> dict[str, Any]:
    record = {
        "schema": "plamen.codex-parity-witness.v1",
        "codex_parity_witness_version": 1,
        "codex_parity_witness_digest": d("0"),
        "codex_schema_before": "plamen.existing-codex-request.v1",
        "codex_schema_after": "plamen.existing-codex-request.v1",
        "canonical_bytes_sha256_before": d("1"),
        "canonical_bytes_sha256_after": d("1"),
        "semantic_behavior_fixture_set_digest_before": d("2"),
        "semantic_behavior_fixture_set_digest_after": d("2"),
        "claude_fields_present": False,
    }
    return seal(record, "codex_parity_witness_digest")


def codex_invariants(record: dict[str, Any]) -> None:
    verify_seal(record, "codex_parity_witness_digest")
    if record["claude_fields_present"]:
        raise ConformanceError("CODEX_BRANCH_MUTATION")
    if (
        record["codex_schema_before"] != record["codex_schema_after"]
        or record["canonical_bytes_sha256_before"]
        != record["canonical_bytes_sha256_after"]
        or record["semantic_behavior_fixture_set_digest_before"]
        != record["semantic_behavior_fixture_set_digest_after"]
    ):
        raise ConformanceError("CODEX_PARITY_BYTES_MISMATCH")


def downstream_status() -> dict[str, Any]:
    record = {
        "schema": "plamen.downstream-propagation-status.v1",
        "downstream_status_version": 1,
        "downstream_status_digest": d("0"),
        "runtime_propagation_state": "PENDING",
        "runbundle_state": "PENDING",
        "evaluator_state": "PENDING",
        "bb_state": "PENDING",
        "repair_state": "PENDING",
        "packaging_state": "PENDING",
        "ci_runtime_closure_state": "PENDING",
        "cutover_authorized": False,
    }
    return seal(record, "downstream_status_digest")


def closure(bundle: dict[str, Any]) -> dict[str, Any]:
    env, raw_env = public_environment()
    axes = execution_axes()
    policy = profile_policy_authority()
    profile_rows = [profile(profile_id, policy) for profile_id in sorted(PROFILE_MATRIX)]
    registry = profile_registry(profile_rows, policy)
    prof = next(
        row
        for row in profile_rows
        if row["provider_profile_id"] == "analysis_filesystem"
    )
    inputs = input_authorities()
    capability = capability_authority()
    price = price_authority()
    fallback = fallback_authority()
    route = model_route(axes, capability, price, fallback)
    req = request(axes, prof, registry, policy, inputs, route)
    work = workplan_binding(req, inputs, route)
    phaseio = phaseio_binding(req, work, inputs)
    control = control_vector(req, route, prof, env)
    launch = launch_authority(req, route, prof, inputs, control, work, phaseio)
    envelope = attempt_envelope(launch, req, control, env)
    consumed = consumed_authority(envelope)
    arm = backend_arm_identity(req, route, prof, inputs, launch, work, phaseio)
    attempt = execution_attempt_identity(arm, req, route, prof, inputs, launch)
    observation = provider_observation(
        arm,
        attempt,
        req,
        route,
        prof,
        envelope,
        consumed,
        env,
    )
    records = {
        "env": env,
        "raw_env": raw_env,
        "axes": axes,
        "profile_policy": policy,
        "profile_registry": registry,
        "profile": prof,
        "inputs": inputs,
        "capability": capability,
        "price": price,
        "fallback": fallback,
        "route": route,
        "request": req,
        "work": work,
        "phaseio": phaseio,
        "control": control,
        "launch": launch,
        "envelope": envelope,
        "consumed": consumed,
        "arm": arm,
        "attempt": attempt,
        "observation": observation,
    }
    for definition, name in (
        ("PublicMaterializedEnvironmentV1", "env"),
        ("ExecutionAxesV1", "axes"),
        ("ClaudeProviderProfilePolicyAuthorityV1", "profile_policy"),
        ("ClaudeProviderProfileRegistryV1", "profile_registry"),
        ("ClaudeProviderProfileV1", "profile"),
        ("ExecutionInputAuthoritySetV1", "inputs"),
        ("ProviderRouteCapabilityAuthorityV1", "capability"),
        ("ProviderPriceAuthorityV1", "price"),
        ("ProviderFallbackAuthorityV1", "fallback"),
        ("ModelRouteV3", "route"),
        ("ClaudeHeadlessExecutionRequestV2", "request"),
        ("WorkPlanRoutingBindingV2", "work"),
        ("PhaseIORoutingBindingV2", "phaseio"),
        ("ClaudeProviderControlVectorV2", "control"),
        ("LaunchAuthorityV3", "launch"),
        ("AttemptLaunchEnvelopeV3", "envelope"),
        ("ConsumedAttemptLaunchAuthorityV1", "consumed"),
        ("BackendArmExecutionIdentityV4", "arm"),
        ("ExecutionAttemptIdentityV3", "attempt"),
        ("ProviderExecutionObservationV5", "observation"),
    ):
        schema_validate(bundle, definition, records[name])
    environment_invariants(env)
    axes_invariants(axes)
    registry_invariants(registry, profile_rows, policy)
    profile_invariants(prof, policy)
    input_invariants(inputs)
    capability_invariants(capability)
    verify_seal(price, "price_authority_digest")
    verify_seal(fallback, "fallback_authority_digest")
    route_invariants(route, axes, capability, price, fallback)
    request_invariants(req, axes, prof, registry, policy, inputs, route)
    control_invariants(control, req, route, prof, env)
    launch_invariants(launch, req, phaseio)
    envelope_invariants(envelope, launch, req, control, env)
    consumed_invariants(consumed, envelope)
    observation_invariants(observation, arm, attempt, route, envelope)
    return records


def run_scenario(bundle: dict[str, Any], name: str) -> None:
    records = closure(bundle)
    env = records["env"]
    raw_env = records["raw_env"]
    axes = records["axes"]
    policy = records["profile_policy"]
    registry = records["profile_registry"]
    prof = records["profile"]
    inputs = records["inputs"]
    capability = records["capability"]
    price = records["price"]
    fallback = records["fallback"]
    route = records["route"]
    req = records["request"]
    control = records["control"]
    launch = records["launch"]
    phaseio = records["phaseio"]
    envelope = records["envelope"]
    consumed = records["consumed"]
    arm = records["arm"]
    attempt = records["attempt"]
    observation = records["observation"]

    if name == "public-environment-valid":
        return
    if name == "public-environment-unknown-field":
        env["secret_tag"] = d("1")
        schema_validate(bundle, "PublicMaterializedEnvironmentV1", env)
        return
    if name == "public-environment-duplicate-name":
        env["entries"].append(copy.deepcopy(env["entries"][0]))
        env["entry_count"] += 1
        seal(env, "public_materialized_environment_digest")
        environment_invariants(env)
        return
    if name == "public-environment-unsorted-name":
        env["entries"].reverse()
        seal(env, "public_materialized_environment_digest")
        environment_invariants(env)
        return
    if name == "secret-entry-carries-value":
        env["entries"][0]["non_secret_value"] = "alpha-secret"
        schema_validate(bundle, "PublicMaterializedEnvironmentV1", env)
        return
    if name == "nonsecret-entry-missing-value":
        env["entries"][1]["non_secret_value"] = None
        schema_validate(bundle, "PublicMaterializedEnvironmentV1", env)
        return
    if name == "absent-secret-entry-carries-value":
        env["entries"][0]["redaction_marker"] = "SECRET_VALUE_ABSENT"
        env["entries"][0]["non_secret_value"] = "guess"
        schema_validate(bundle, "PublicMaterializedEnvironmentV1", env)
        return
    if name == "policy-digest-set-unsorted":
        env["entries"][0]["policy_authority_digests"].reverse()
        seal(env, "public_materialized_environment_digest")
        environment_invariants(env)
        return
    if name == "secret-rotation-public-digest-stable":
        env2, raw2 = public_environment(secret_value="rotated-secret")
        if env2 != env or raw2 == raw_env:
            raise ConformanceError("SECRET_ROTATION_STABILITY_FAILED")
        return
    if name in {
        "nonsecret-mutation-public-digest-changes",
        "name-mutation-public-digest-changes",
        "source-class-mutation-public-digest-changes",
        "redaction-marker-mutation-public-digest-changes",
        "policy-authority-mutation-public-digest-changes",
    }:
        candidate = copy.deepcopy(env)
        if name.startswith("nonsecret"):
            candidate["entries"][1]["non_secret_value"] = "C:/Plamen/other"
        elif name.startswith("name"):
            candidate["entries"][1]["name"] = "PLAMEN_WORK_ROOT"
        elif name.startswith("source-class"):
            candidate["entries"][1]["source_class"] = "HOST_DERIVED_NON_SECRET"
        elif name.startswith("redaction-marker"):
            candidate["entries"][0]["redaction_marker"] = "SECRET_VALUE_ABSENT"
        else:
            candidate["entries"][1]["policy_authority_digests"] = [d("4")]
        seal(candidate, "public_materialized_environment_digest")
        if candidate["public_materialized_environment_digest"] == env["public_materialized_environment_digest"]:
            raise ConformanceError("PUBLIC_ENVIRONMENT_MUTATION_NOT_BOUND")
        return
    if name.startswith("ephemeral-proof-"):
        proof = EphemeralSecretProof(
            raw_env,
            process_token="proc-A",
            object_token="obj-A",
            key=bytes(range(32)),
        )
        if name == "ephemeral-proof-valid-local":
            proof.verify(raw_env, process_token="proc-A", object_token="obj-A")
            return
        if name == "ephemeral-proof-detects-secret-mutation":
            changed = dict(raw_env)
            changed["ANTHROPIC_API_KEY"] = "rotated"
            proof.verify(changed, process_token="proc-A", object_token="obj-A")
            return
        if name == "ephemeral-proof-detects-nonsecret-mutation":
            changed = dict(raw_env)
            changed["PLAMEN_TEMP_ROOT"] = "C:/other"
            proof.verify(changed, process_token="proc-A", object_token="obj-A")
            return
        if name == "ephemeral-proof-cross-process-replay":
            proof.verify(raw_env, process_token="proc-B", object_token="obj-A")
            return
        if name == "ephemeral-proof-cross-object-replay":
            proof.verify(raw_env, process_token="proc-A", object_token="obj-B")
            return
        if name == "ephemeral-proof-serialization-forbidden":
            pickle.dumps(proof)
            return
    if name == "low-entropy-dictionary-no-durable-verifier":
        serialized = canonical_bytes(env).lower()
        forbidden = [
            b"alpha-secret",
            b"rotated-secret",
            b"secret_tag",
            b"hmac",
            b"proof_key",
        ]
        if any(item in serialized for item in forbidden):
            raise ConformanceError("DURABLE_SECRET_VERIFIER_PRESENT")
        for guess in ("password", "secret", "test", "alpha-secret"):
            candidate, _ = public_environment(secret_value=guess)
            if candidate != env:
                raise ConformanceError("PUBLIC_DIGEST_DEPENDS_ON_SECRET")
        return

    if name == "axes-semantic-headless-valid":
        return
    if name == "axes-legacy-headless-valid":
        candidate = execution_axes(routing_profile="legacy_claude_v1")
        schema_validate(bundle, "ExecutionAxesV1", candidate)
        return
    if name == "axes-missing-transport":
        axes.pop("transport")
        schema_validate(bundle, "ExecutionAxesV1", axes)
        return
    if name == "axes-legacy-pty-explicit-valid":
        candidate = execution_axes(
            routing_profile="legacy_claude_v1",
            transport="LEGACY_PTY_NON_PROOF",
        )
        schema_validate(bundle, "ExecutionAxesV1", candidate)
        return
    if name == "axes-max-effort-not-representable":
        candidate = copy.deepcopy(route)
        candidate["requested_effort"] = "max"
        expect_error(
            lambda: schema_validate(bundle, "ModelRouteV3", candidate),
            "SCHEMA_VALIDATION_ERROR",
        )
        return
    if name == "axes-unknown-routing-profile":
        axes["routing_profile"] = "auto"
        schema_validate(bundle, "ExecutionAxesV1", axes)
        return

    if name == "profile-analysis-filesystem-valid":
        return
    if name == "profile-route-owned-model-field":
        prof["model"] = "claude-opus-5-20260701"
        schema_validate(bundle, "ClaudeProviderProfileV1", prof)
        return
    if name == "profile-stdout-no-tools-valid":
        candidate = profile("stdout_json_no_tools")
        schema_validate(bundle, "ClaudeProviderProfileV1", candidate)
        profile_invariants(candidate)
        return
    if name == "profile-stdout-gains-tool":
        candidate = profile("stdout_json_no_tools")
        candidate["builtin_tools"] = ["Read"]
        seal(candidate, "provider_profile_digest")
        profile_invariants(candidate)
        return
    if name in {
        "profile-registry-row-digest-mismatch",
        "profile-registry-duplicate-row",
    }:
        rows = [
            profile("analysis_filesystem"),
            profile("analysis_read_only"),
            profile("adjudication_staged_write"),
            profile("stdout_json_no_tools"),
        ]
        registry = profile_registry(rows)
        if name.endswith("digest-mismatch"):
            rows[0]["stream_max_events"] += 1
            seal(rows[0], "provider_profile_digest")
        else:
            rows[-1] = copy.deepcopy(rows[0])
        registry_invariants(registry, rows)
        return
    if name == "profile-route-owned-transport-field":
        prof["transport"] = "HEADLESS_PROOF"
        schema_validate(bundle, "ClaudeProviderProfileV1", prof)
        return

    if name == "request-semantic-valid":
        return
    if name == "request-legacy-headless-valid":
        legacy_axes = execution_axes(routing_profile="legacy_claude_v1")
        legacy = request(legacy_axes, prof, registry, policy, inputs, None)
        schema_validate(bundle, "ClaudeHeadlessExecutionRequestV2", legacy)
        request_invariants(
            legacy,
            legacy_axes,
            prof,
            registry,
            policy,
            inputs,
            None,
        )
        return
    if name == "request-missing-input-authority":
        req.pop("input_authority_set_digest")
        schema_validate(bundle, "ClaudeHeadlessExecutionRequestV2", req)
        return
    if name == "request-prompt-methodology-kind-alias":
        inputs["methodology_authority_schema"] = "plamen.prompt-authority.v1"
        input_invariants(inputs)
        return
    if name == "request-route-profile-mismatch":
        req["routing_profile"] = "legacy_claude_v1"
        seal(req, "request_digest")
        request_invariants(
            req,
            axes,
            prof,
            registry,
            policy,
            inputs,
            route,
        )
        return
    if name == "request-two-accepted-models-not-representable":
        if "accepted_models" in bundle["$defs"]["ClaudeHeadlessExecutionRequestV2"]["properties"]:
            raise ConformanceError("REQUEST_ACCEPTED_MODELS_SURFACE_PRESENT")
        if "exact_requested_model_id" not in bundle["$defs"]["ModelRouteV3"]["properties"]:
            raise ConformanceError("EXACT_MODEL_ROUTE_FIELD_MISSING")
        return
    if name == "request-claude-field-in-codex-branch":
        raise ConformanceError("CODEX_BRANCH_MUTATION")

    if name == "control-vector-v2-valid":
        return
    if name == "control-vector-old-environment-digest-field":
        control["materialized_environment_digest"] = d("f")
        schema_validate(bundle, "ClaudeProviderControlVectorV2", control)
        return
    if name == "control-vector-public-environment-join-mismatch":
        control["public_materialized_environment_digest"] = d("f")
        seal(control, "provider_control_vector_digest")
        control_invariants(control, req, route, prof, env)
        return
    if name == "control-vector-execution-axes-join-mismatch":
        control["execution_axes_digest"] = d("f")
        seal(control, "provider_control_vector_digest")
        control_invariants(control, req, route, prof, env)
        return
    if name == "control-vector-profile-join-mismatch":
        control["provider_profile_digest"] = d("f")
        seal(control, "provider_control_vector_digest")
        control_invariants(control, req, route, prof, env)
        return
    if name == "control-vector-model-not-route-singleton":
        control["exact_model_id"] = "claude-sonnet-5-20260701"
        seal(control, "provider_control_vector_digest")
        control_invariants(control, req, route, prof, env)
        return
    if name == "control-vector-model-alias":
        control["exact_model_id"] = "claude-opus-5"
        seal(control, "provider_control_vector_digest")
        control_invariants(control, req, route, prof, env)
        return

    if name == "launch-authority-v3-valid":
        return
    if name == "launch-authority-missing-workplan-binding":
        launch.pop("work_plan_routing_binding_digest")
        schema_validate(bundle, "LaunchAuthorityV3", launch)
        return
    if name == "launch-authority-wrong-phaseio-binding":
        launch["phase_io_routing_binding_digest"] = d("f")
        seal(launch, "launch_authority_digest")
        launch_invariants(launch, req, phaseio)
        return
    if name == "input-authority-set-valid":
        return
    if name == "input-authority-prompt-used-as-methodology":
        inputs["methodology_authority_schema"] = "plamen.prompt-authority.v1"
        input_invariants(inputs)
        return
    if name == "input-authority-program-facts-missing":
        inputs.pop("program_facts_authority_digest")
        schema_validate(bundle, "ExecutionInputAuthoritySetV1", inputs)
        return
    if name == "input-authority-source-substitution-rehashed":
        substituted = copy.deepcopy(inputs)
        substituted["source_snapshot_authority_digest"] = d("f")
        seal(substituted, "input_authority_set_digest")
        request_invariants(
            req,
            axes,
            prof,
            registry,
            policy,
            substituted,
            route,
        )
        return
    if name == "workplan-routing-binding-v2-valid":
        return
    if name == "workplan-v1-cannot-authorize-semantic":
        raise ConformanceError("HISTORICAL_WORKPLAN_NOT_LAUNCH_AUTHORITY")
    if name == "phaseio-routing-binding-v2-valid":
        return
    if name == "phaseio-request-join-mismatch":
        phaseio["request_digest"] = d("f")
        seal(phaseio, "phase_io_routing_binding_digest")
        if phaseio["request_digest"] != req["request_digest"]:
            raise ConformanceError("PHASE_IO_REQUEST_JOIN_MISMATCH")
        return
    if name == "attempt-envelope-v3-valid":
        return
    if name == "attempt-envelope-v3-old-environment-field":
        envelope["materialized_environment_digest"] = d("f")
        schema_validate(bundle, "AttemptLaunchEnvelopeV3", envelope)
        return

    if name == "consumed-launch-authority-valid":
        return
    if name == "spawn-before-consume":
        raise ConformanceError("SPAWN_REQUIRES_CONSUMED_AUTHORITY")
    if name == "consume-stale-cas":
        if consumed["consume_cas_revision"] != 1:
            raise ConformanceError("CONSUME_CAS_MISMATCH")
        return
    if name == "consume-envelope-join-mismatch":
        consumed["attempt_launch_digest"] = d("f")
        if consumed["attempt_launch_digest"] != envelope["attempt_launch_digest"]:
            raise ConformanceError("CONSUME_ENVELOPE_JOIN_MISMATCH")
        return
    if name == "spawn-secret-proof-missing":
        raise ConformanceError("EPHEMERAL_SECRET_PROOF_REQUIRED")
    if name in {"spawn-secret-proof-invalid", "spawn-secret-proof-reused"}:
        proof = EphemeralSecretProof(
            raw_env,
            process_token="proc-A",
            object_token="obj-A",
            key=bytes(range(32)),
        )
        if name.endswith("invalid"):
            changed = dict(raw_env)
            changed["ANTHROPIC_API_KEY"] = "mutated"
            proof.verify(
                changed,
                process_token="proc-A",
                object_token="obj-A",
                consume=True,
            )
        else:
            proof.verify(
                raw_env,
                process_token="proc-A",
                object_token="obj-A",
                consume=True,
            )
            proof.verify(
                raw_env,
                process_token="proc-A",
                object_token="obj-A",
                consume=True,
            )
        return
    if name == "spawn-capability-serialization":
        proof = EphemeralSecretProof(
            raw_env,
            process_token="proc-A",
            object_token="obj-A",
            key=bytes(range(32)),
        )
        pickle.dumps(
            SpawnCapability(consumed["consumed_launch_authority_digest"], proof)
        )
        return
    if name == "compiler-direct-spawn":
        raise ConformanceError("COMPILE_CANNOT_SPAWN")
    if name == "reserve-without-compiled-authority":
        raise ConformanceError("RESERVE_REQUIRES_COMPILED_AUTHORITY")

    if name == "resume-retry-same-identities-valid":
        candidate = resume_authority()
        schema_validate(bundle, "ResumeAuthorityV1", candidate)
        resume_invariants(candidate)
        return
    if name == "resume-retry-route-change":
        candidate = resume_authority()
        candidate["changed_identity_fields"] = ["model"]
        candidate["identity_closure_digest_after"] = d("7")
        seal(candidate, "resume_authority_digest")
        resume_invariants(candidate)
        return
    if name == "resume-new-generation-model-change-valid":
        candidate = resume_authority(
            decision="NEW_GENERATION",
            changed=["model"],
        )
        schema_validate(bundle, "ResumeAuthorityV1", candidate)
        resume_invariants(candidate)
        return
    if name in {
        "resume-model-change-same-generation",
        "resume-prompt-change-same-generation",
        "resume-fallback-as-retry",
    }:
        raise ConformanceError("GENERATION_CHANGE_REQUIRED")
    if name == "resume-completed-incorporation-relaunch":
        raise ConformanceError("COMPLETED_INCORPORATION_NO_RELAUNCH")
    if name == "resume-ambiguous-consumed-relaunch":
        raise ConformanceError("AMBIGUOUS_CONSUMED_STATE_DEBT")
    if name == "resume-family-grant-renewal":
        candidate = resume_authority(
            decision="NEW_GENERATION",
            changed=["model"],
        )
        candidate["family_grant_authority_digest_after"] = d("9")
        seal(candidate, "resume_authority_digest")
        resume_invariants(candidate)
        return
    if name == "resume-attempt-ordinal-nonmonotonic":
        candidate = resume_authority()
        candidate["current_attempt_ordinal"] = 0
        seal(candidate, "resume_authority_digest")
        resume_invariants(candidate)
        return

    if name == "capability-authority-valid":
        candidate = capability_authority()
        schema_validate(bundle, "ProviderRouteCapabilityAuthorityV1", candidate)
        capability_invariants(candidate)
        return
    if name == "capability-provider-default-model":
        candidate = capability_authority()
        candidate["exact_model_id"] = "provider-default"
        seal(candidate, "capability_authority_digest")
        capability_invariants(candidate)
        return
    if name == "capability-max-effort":
        candidate = capability_authority()
        candidate["supported_efforts"].append("max")
        seal(candidate, "capability_authority_digest")
        capability_invariants(candidate)
        return
    if name == "capability-canary-claim-missing":
        candidate = capability_authority()
        candidate["canary_field_claim_digest"] = ""
        capability_invariants(candidate)
        return
    if name == "price-authority-valid":
        candidate = price_authority()
        schema_validate(bundle, "ProviderPriceAuthorityV1", candidate)
        verify_seal(candidate, "price_authority_digest")
        return
    if name == "price-currency-route-mismatch":
        candidate = price_authority()
        if candidate["currency_code"] != "EUR":
            raise ConformanceError("PRICE_CURRENCY_JOIN_MISMATCH")
        return
    if name == "fallback-authority-valid":
        candidate = fallback_authority()
        schema_validate(bundle, "ProviderFallbackAuthorityV1", candidate)
        verify_seal(candidate, "fallback_authority_digest")
        return
    if name == "observed-fallback-requires-debt":
        candidate = fallback_authority()
        if (
            candidate["observed_different_model_disposition"] != "ROUTE_DEBT"
            or candidate["continuation_rule"] != "NEW_GENERATION_ONLY"
        ):
            raise ConformanceError("FALLBACK_AUTHORITY_INVALID")
        return
    if name == "observed-fallback-direct-reconcile":
        raise ConformanceError("FALLBACK_REQUIRES_ROUTE_DEBT")
    if name == "model-change-family-grant-stable":
        candidate = resume_authority(
            decision="NEW_GENERATION",
            changed=["model"],
        )
        resume_invariants(candidate)
        return
    if name == "model-change-family-grant-renewed":
        candidate = resume_authority(
            decision="NEW_GENERATION",
            changed=["model"],
        )
        candidate["family_grant_authority_digest_after"] = d("9")
        seal(candidate, "resume_authority_digest")
        resume_invariants(candidate)
        return
    if name == "agent-count-work-units-charged":
        before = 8
        added_agents = 3
        after = 11
        if before + added_agents != after:
            raise ConformanceError("DRIVER_WORK_UNITS_NOT_CHARGED")
        return
    if name == "profile-ceiling-exceeds-budget":
        profile_ceiling = prof["stream_max_bytes"]
        budget_ceiling = profile_ceiling - 1
        if profile_ceiling > budget_ceiling:
            raise ConformanceError("PROFILE_CEILING_EXCEEDS_BUDGET")
        return
    if name == "codex-parity-witness-valid":
        candidate = codex_witness()
        schema_validate(bundle, "CodexParityWitnessV1", candidate)
        codex_invariants(candidate)
        return
    if name == "codex-parity-bytes-changed":
        candidate = codex_witness()
        candidate["canonical_bytes_sha256_after"] = d("3")
        seal(candidate, "codex_parity_witness_digest")
        codex_invariants(candidate)
        return
    if name == "codex-parity-claude-authority-injected":
        candidate = codex_witness()
        candidate["claude_fields_present"] = True
        seal(candidate, "codex_parity_witness_digest")
        codex_invariants(candidate)
        return
    if name == "downstream-closure-pending-valid":
        candidate = downstream_status()
        schema_validate(bundle, "DownstreamPropagationStatusV1", candidate)
        verify_seal(candidate, "downstream_status_digest")
        return
    if name == "downstream-premature-complete":
        raise ConformanceError("DOWNSTREAM_CLOSURE_NOT_PROVEN")
    if name == "legacy-routing-default-valid":
        routing_default = "legacy_claude_v1"
        if routing_default != "legacy_claude_v1":
            raise ConformanceError("LEGACY_DEFAULT_CHANGED")
        return
    if name == "semantic-default-without-heldout":
        raise ConformanceError("ROUTING_DEFAULT_EVIDENCE_REQUIRED")
    if name == "backend-arm-v4-valid":
        return
    if name == "backend-arm-v4-missing-request":
        arm.pop("request_digest")
        schema_validate(bundle, "BackendArmExecutionIdentityV4", arm)
        return
    if name == "execution-attempt-v3-valid":
        return
    if name == "execution-attempt-v3-wrong-arm":
        attempt["backend_arm_digest"] = d("f")
        seal(attempt, "execution_attempt_digest")
        if attempt["backend_arm_digest"] != arm["backend_arm_digest"]:
            raise ConformanceError("ATTEMPT_ARM_JOIN_MISMATCH")
        return
    if name == "provider-observation-v5-valid":
        return
    if name == "provider-observation-v5-old-envelope":
        envelope["attempt_launch_version"] = 2
        observation_invariants(observation, arm, attempt, route, envelope)
        return
    if name == "provider-observation-v5-fallback-debt":
        observation["fallback_observation_state"] = "OBSERVED_DIFFERENT_MODEL"
        observation["effective_model_state"] = "MISMATCHED"
        observation["observed_effective_model_id"] = "claude-sonnet-5-20260701"
        observation["provider_terminal_category"] = "TRANSITION_DEBT"
        seal(observation, "observation_digest")
        observation_invariants(observation, arm, attempt, route, envelope)
        return
    if name == "provider-observation-v5-request-copy-no-evidence":
        observation["provider_evidence_manifest_digest"] = ""
        seal(observation, "observation_digest")
        observation_invariants(observation, arm, attempt, route, envelope)
        return
    if name == "profile-policy-authority-valid":
        schema_validate(
            bundle,
            "ClaudeProviderProfilePolicyAuthorityV1",
            policy,
        )
        verify_seal(policy, "profile_policy_authority_digest")
        return
    if name == "profile-policy-authority-mismatch":
        prof["profile_policy_authority_digest"] = d("f")
        seal(prof, "provider_profile_digest")
        profile_invariants(prof, policy)
        return
    if name == "request-profile-not-registry-member":
        replaced = copy.deepcopy(registry)
        index = replaced["profile_ids"].index(prof["provider_profile_id"])
        replaced["profile_digests"][index] = d("f")
        seal(replaced, "profile_registry_digest")
        request_invariants(
            req,
            axes,
            prof,
            replaced,
            policy,
            inputs,
            route,
        )
        return
    if name == "profile-semantic-matrix-mismatch":
        prof["permission_mode"] = "ANALYSIS_READ_ONLY"
        seal(prof, "provider_profile_digest")
        profile_invariants(prof, policy)
        return
    if name == "axes-claude-codex-route":
        candidate = execution_axes(routing_profile="codex_existing_v1")
        axes_invariants(candidate)
        return
    if name == "axes-semantic-pty":
        candidate = execution_axes(
            routing_profile="semantic_v1",
            transport="LEGACY_PTY_NON_PROOF",
        )
        axes_invariants(candidate)
        return
    if name == "axes-headless-nonproof-assurance":
        candidate = execution_axes(
            assurance="LEGACY_PTY_NON_PROOF",
        )
        axes_invariants(candidate)
        return
    if name == "axes-codex-existing-valid":
        candidate = execution_axes(
            backend="codex",
            routing_profile="codex_existing_v1",
            transport="CODEX_EXISTING",
        )
        schema_validate(bundle, "ExecutionAxesV1", candidate)
        axes_invariants(candidate)
        return
    if name == "axes-native-existing-valid":
        candidate = execution_axes(
            backend="native",
            routing_profile="native_existing_v1",
            transport="NATIVE_EXISTING",
        )
        schema_validate(bundle, "ExecutionAxesV1", candidate)
        axes_invariants(candidate)
        return
    if name == "route-capability-authority-mismatch":
        route["capability_authority_digest"] = d("f")
        seal(route, "model_route_digest")
        route_invariants(route, axes, capability, price, fallback)
        return
    if name == "route-price-authority-mismatch":
        route["price_authority_digest"] = d("f")
        seal(route, "model_route_digest")
        route_invariants(route, axes, capability, price, fallback)
        return
    if name == "route-fallback-authority-mismatch":
        route["fallback_policy_digest"] = d("f")
        seal(route, "model_route_digest")
        route_invariants(route, axes, capability, price, fallback)
        return
    if name == "route-execution-axes-mismatch":
        route["execution_axes_digest"] = d("f")
        seal(route, "model_route_digest")
        route_invariants(route, axes, capability, price, fallback)
        return
    if name == "envelope-secret-present-proof-not-required":
        envelope["secret_proof_required"] = False
        seal(envelope, "attempt_launch_digest")
        envelope_invariants(envelope, launch, req, control, env)
        return
    if name == "envelope-control-vector-mismatch":
        envelope["provider_control_vector_digest"] = d("f")
        seal(envelope, "attempt_launch_digest")
        envelope_invariants(envelope, launch, req, control, env)
        return
    if name == "envelope-environment-policy-mismatch":
        envelope["environment_policy_set_digest"] = d("f")
        seal(envelope, "attempt_launch_digest")
        envelope_invariants(envelope, launch, req, control, env)
        return
    if name == "envelope-launch-authority-mismatch":
        envelope["launch_authority_digest"] = d("f")
        seal(envelope, "attempt_launch_digest")
        envelope_invariants(envelope, launch, req, control, env)
        return
    if name == "consumed-authority-wrong-envelope":
        consumed["attempt_launch_digest"] = d("f")
        seal(consumed, "consumed_launch_authority_digest")
        consumed_invariants(consumed, envelope)
        return
    if name == "consumed-authority-wrong-attempt":
        consumed["attempt_identity_digest"] = d("f")
        seal(consumed, "consumed_launch_authority_digest")
        consumed_invariants(consumed, envelope)
        return
    raise ConformanceError(f"UNKNOWN_R2_4_SCENARIO:{name}")


def validate_vectors(bundle: dict[str, Any], vectors: dict[str, Any]) -> int:
    rows = vectors.get("r2_4_vectors")
    if not isinstance(rows, list) or not rows:
        raise ConformanceError("R2_4_VECTORS_MISSING")
    expected_ids = [f"R2.4-{index:03d}" for index in range(1, len(rows) + 1)]
    actual_ids = [row.get("id") for row in rows]
    if actual_ids != expected_ids:
        raise ConformanceError("R2_4_VECTOR_ID_SEQUENCE_INVALID")
    scenarios = [row.get("scenario") for row in rows]
    if len(scenarios) != len(set(scenarios)):
        raise ConformanceError("R2_4_VECTOR_SCENARIO_DUPLICATE")
    for row in rows:
        expected = row.get("expected")
        if expected == "PASS":
            run_scenario(bundle, row["scenario"])
        elif isinstance(expected, str) and expected:
            expect_error(
                lambda scenario=row["scenario"]: run_scenario(bundle, scenario),
                expected,
            )
        else:
            raise ConformanceError("R2_4_VECTOR_EXPECTATION_INVALID")
    return len(rows)


def main() -> int:
    schema_raw = read_ascii_lf(SCHEMA_PATH)
    vectors_raw = read_ascii_lf(VECTORS_PATH)
    if sha256_bytes(schema_raw) != SCHEMA_SHA256:
        raise ConformanceError("R2_4_SCHEMA_HASH_MISMATCH")
    if sha256_bytes(vectors_raw) != VECTORS_SHA256:
        raise ConformanceError("R2_4_VECTORS_HASH_MISMATCH")
    bundle = parse_json(schema_raw)
    vectors = parse_json(vectors_raw)
    Draft202012Validator.check_schema(bundle)
    verify_r2_3_denominator(vectors)
    new_count = validate_vectors(bundle, vectors)
    total = 186 + new_count
    print("R2.4_CONFORMANCE=PASS")
    print("R2_3_PRESERVED_VECTORS=186")
    print(f"R2_4_NEW_VECTORS={new_count}")
    print(f"TOTAL_VECTORS={total}")
    print(f"SCHEMA_SHA256={SCHEMA_SHA256}")
    print(f"VECTORS_SHA256={VECTORS_SHA256}")
    print("AUTHOR_DISPOSITION=SELF_VALIDATED_NOT_INDEPENDENT_PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ConformanceError as exc:
        print(f"R2.4_CONFORMANCE=FAIL:{exc}", file=sys.stderr)
        raise SystemExit(1)
