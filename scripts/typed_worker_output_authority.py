"""Replay provider-authored typed output through WorkerTransaction and PhaseIO.

This is a provenance primitive, not a semantic policy.  It accepts no payload
from its caller.  The only returned payload is parsed from the current
canonical bytes which survived the exact WorkPlan -> provider completion/CAS
-> PhaseIO incorporation chain and the current PhaseIO input receipt.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import sys
from types import MappingProxyType
from typing import Any, Callable, NamedTuple, NoReturn
import unicodedata

import artifact_ledger
from phase_io_contracts import LaunchSpec, PhaseIOContract
from program_facts_types import (
    ProgramFactsTypeError,
    canonical_file_bytes,
    canonical_json_bytes,
    strict_json_loads,
)
import worker_execution_receipts as worker_receipts
import worker_transaction as worker_tx


TYPED_WORKER_OUTPUT_AUTHORITY_SCHEMA = (
    "plamen.typed-worker-output-authority.v1"
)

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_AUTHORITY_KEYS = frozenset(
    {
        "schema",
        "run_id",
        "phase",
        "work_unit_id",
        "generation",
        "work_plan_digest",
        "attempt_id",
        "worker_execution_authority_digest",
        "provider_completion_digest",
        "phase_io_contract_digest",
        "phase_io_launch_digest",
        "phase_io_input_set_digest",
        "canonical_output_identity",
        "output_sha256",
        "output_size",
        "payload_schema",
        "payload_digest",
        "parser_binding",
        "writer_role",
        "principal",
        "authority_digest",
    }
)
_PARSER_BINDING_KEYS = frozenset(
    {
        "identity",
        "source_file",
        "source_sha256",
        "code_sha256",
        "closure_sha256",
    }
)
_PRINCIPAL_KEYS = frozenset({"identity", "invocation_id"})
_INCORPORATION_KEYS = frozenset(
    {
        "schema",
        "run_id",
        "phase",
        "work_unit_id",
        "generation",
        "work_plan_digest",
        "attempt_id",
        "provider_completion_digest",
        "contract_digest",
        "launch_digest",
        "input_set_digest",
        "arm_digest",
        "projection_state",
        "projected_members",
        "incorporation_digest",
    }
)
_INCORPORATION_ARM_KEYS = frozenset(
    {
        "schema",
        "run_id",
        "phase",
        "work_unit_id",
        "generation",
        "work_plan_digest",
        "attempt_id",
        "provider_completion_digest",
        "contract_digest",
        "launch_digest",
        "input_set_digest",
        "members",
        "arm_digest",
    }
)
_INCORPORATION_MEMBER_KEYS = frozenset(
    {
        "schema",
        "arm_digest",
        "index",
        "canonical_identity",
        "sha256",
        "size",
        "member_digest",
    }
)


class TypedWorkerOutputAuthorityError(ValueError):
    """Typed bytes lack exact provider, incorporation, or input provenance."""


STRICT_CANONICAL_JSON_PARSER_ID = "plamen.strict-canonical-json.v1"
FIXTURE_TYPED_OUTPUT_ROLE = "TYPED_OUTPUT_FIXTURE"
METHOD_CARD_PRODUCER_TYPED_ROLE = "METHOD_CARD_PRODUCER"
METHOD_CARD_REVIEWER_TYPED_ROLE = "METHOD_CARD_REVIEWER"
_METHOD_CARD_PRODUCER_SCHEMA = (
    "plamen.method-card-producer-application-typed-output.v2"
)
_METHOD_CARD_REVIEWER_SCHEMA = (
    "plamen.method-card-independent-application-review-typed-output.v2"
)
_METHOD_CARD_PRODUCER_KEYS = frozenset(
    {
        "schema",
        "role",
        "runtime_authority_digest",
        "source_snapshot_digest",
        "runtime_input_identity",
        "snapshot_input_identity",
        "subject_output",
        "source_files",
        "denominator",
        "claims",
    }
)
_METHOD_CARD_REVIEWER_KEYS = frozenset(
    {
        "schema",
        "role",
        "runtime_authority_digest",
        "source_snapshot_digest",
        "runtime_input_identity",
        "snapshot_input_identity",
        "producer_authority_input_identity",
        "producer_typed_output_authority_digest",
        "producer_execution_authority_digest",
        "producer_output_identity",
        "producer_output_sha256",
        "producer_payload_digest",
        "denominator",
        "reviews",
    }
)

_TYPED_JSON_MAX_BYTES = 8 * 1024 * 1024
_TYPED_JSON_MAX_DEPTH = 128
_TYPED_JSON_MAX_ITEMS = 262_144
_TYPED_JSON_MAX_INTEGER_DIGITS = 4_096
_TYPED_JSON_SHA256 = hashlib.sha256
_TYPED_JSON_IS_NORMALIZED = unicodedata.is_normalized


def _typed_json_parse_string(text: str, index: int) -> tuple[str, int]:
    if index >= len(text) or text[index] != '"':
        raise ValueError("canonical JSON string is missing its opening quote")
    index += 1
    segment_start = index
    pieces: list[str] = []
    while index < len(text):
        character = text[index]
        if character == '"':
            pieces.append(text[segment_start:index])
            value = "".join(pieces)
            if "\x00" in value:
                raise ValueError("canonical JSON string contains NUL")
            if not _TYPED_JSON_IS_NORMALIZED("NFC", value):
                raise ValueError("canonical JSON string is not NFC-normalized")
            return value, index + 1
        if character == "\\":
            pieces.append(text[segment_start:index])
            index += 1
            if index >= len(text):
                raise ValueError("canonical JSON string has a truncated escape")
            escaped = text[index]
            if escaped == '"':
                pieces.append('"')
                index += 1
            elif escaped == "\\":
                pieces.append("\\")
                index += 1
            elif escaped == "b":
                pieces.append("\b")
                index += 1
            elif escaped == "t":
                pieces.append("\t")
                index += 1
            elif escaped == "n":
                pieces.append("\n")
                index += 1
            elif escaped == "f":
                pieces.append("\f")
                index += 1
            elif escaped == "r":
                pieces.append("\r")
                index += 1
            elif escaped == "u":
                if index + 5 > len(text):
                    raise ValueError(
                        "canonical JSON string has a truncated Unicode escape"
                    )
                digits = text[index + 1:index + 5]
                if (
                    digits[:2] != "00"
                    or any(
                        character not in "0123456789abcdef"
                        for character in digits
                    )
                ):
                    raise ValueError(
                        "canonical JSON contains a redundant Unicode escape"
                    )
                codepoint = int(digits, 16)
                if codepoint >= 0x20 or codepoint in {
                    0x08,
                    0x09,
                    0x0A,
                    0x0C,
                    0x0D,
                }:
                    raise ValueError(
                        "canonical JSON contains a non-minimal Unicode escape"
                    )
                pieces.append(chr(codepoint))
                index += 5
            else:
                raise ValueError("canonical JSON contains a redundant escape")
            segment_start = index
            continue
        codepoint = ord(character)
        if codepoint < 0x20 or 0xD800 <= codepoint <= 0xDFFF:
            raise ValueError("canonical JSON string contains an invalid scalar")
        index += 1
    raise ValueError("canonical JSON string is unterminated")


def _typed_json_parse_integer(text: str, index: int) -> tuple[int, int]:
    start = index
    if text[index] == "-":
        index += 1
        if index >= len(text) or text[index] == "0":
            raise ValueError("canonical JSON integer has a redundant sign or zero")
    if index >= len(text) or text[index] not in "0123456789":
        raise ValueError("canonical JSON integer is malformed")
    if text[index] == "0":
        index += 1
        if index < len(text) and text[index] in "0123456789":
            raise ValueError("canonical JSON integer has a leading zero")
    else:
        while index < len(text) and text[index] in "0123456789":
            index += 1
    digits = index - start - (1 if text[start] == "-" else 0)
    if digits > _TYPED_JSON_MAX_INTEGER_DIGITS:
        raise ValueError("canonical JSON integer exceeds its digit ceiling")
    if index < len(text) and text[index] in ".eE+":
        raise ValueError("canonical JSON forbids non-integer numbers")
    return int(text[start:index]), index


def _typed_json_parse_value(
    text: str,
    index: int,
    depth: int,
    items: int,
) -> tuple[Any, int, int]:
    if depth > _TYPED_JSON_MAX_DEPTH:
        raise ValueError("canonical JSON exceeds its nesting ceiling")
    items += 1
    if items > _TYPED_JSON_MAX_ITEMS:
        raise ValueError("canonical JSON exceeds its item ceiling")
    if index >= len(text):
        raise ValueError("canonical JSON value is truncated")
    character = text[index]
    if character == '"':
        value, index = _typed_json_parse_string(text, index)
        return value, index, items
    if character == "{":
        result: dict[str, Any] = {}
        index += 1
        if index < len(text) and text[index] == "}":
            return result, index + 1, items
        previous_key = ""
        has_previous_key = False
        while True:
            key, index = _typed_json_parse_string(text, index)
            items += 1
            if items > _TYPED_JSON_MAX_ITEMS:
                raise ValueError("canonical JSON exceeds its item ceiling")
            if has_previous_key and key <= previous_key:
                raise ValueError(
                    "canonical JSON object keys are duplicate or unsorted"
                )
            previous_key = key
            has_previous_key = True
            if index >= len(text) or text[index] != ":":
                raise ValueError("canonical JSON object is missing a colon")
            value, index, items = _typed_json_parse_value(
                text,
                index + 1,
                depth + 1,
                items,
            )
            result[key] = value
            if index >= len(text):
                raise ValueError("canonical JSON object is unterminated")
            delimiter = text[index]
            if delimiter == "}":
                return result, index + 1, items
            if delimiter != ",":
                raise ValueError("canonical JSON object delimiter is malformed")
            index += 1
    if character == "[":
        result_list: list[Any] = []
        index += 1
        if index < len(text) and text[index] == "]":
            return result_list, index + 1, items
        while True:
            value, index, items = _typed_json_parse_value(
                text,
                index,
                depth + 1,
                items,
            )
            result_list.append(value)
            if index >= len(text):
                raise ValueError("canonical JSON array is unterminated")
            delimiter = text[index]
            if delimiter == "]":
                return result_list, index + 1, items
            if delimiter != ",":
                raise ValueError("canonical JSON array delimiter is malformed")
            index += 1
    if text.startswith("true", index):
        return True, index + 4, items
    if text.startswith("false", index):
        return False, index + 5, items
    if text.startswith("null", index):
        return None, index + 4, items
    if character == "-" or character in "0123456789":
        value, index = _typed_json_parse_integer(text, index)
        return value, index, items
    raise ValueError("canonical JSON contains an unsupported value")


def _typed_json_parse_document(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes):
        raise ValueError("canonical JSON input must be exact bytes")
    if not raw or len(raw) > _TYPED_JSON_MAX_BYTES:
        raise ValueError("canonical JSON input violates its byte ceiling")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("canonical JSON forbids a UTF-8 BOM")
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise ValueError("canonical JSON requires exactly one final LF")
    content = raw[:-1]
    if not content:
        raise ValueError("canonical JSON document is empty")
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("canonical JSON is not strict UTF-8") from exc
    value, index, _items = _typed_json_parse_value(text, 0, 0, 0)
    if index != len(text):
        raise ValueError("canonical JSON has trailing or noncanonical bytes")
    if not isinstance(value, dict):
        raise ValueError("registered typed worker output must be an object")
    return value


def _registered_canonical_json_payload(_path: Path, raw: bytes) -> dict[str, Any]:
    return _typed_json_parse_document(raw)


def _registered_canonical_json_parser(path: Path, raw: bytes) -> str:
    _registered_canonical_json_payload(path, raw)
    return _TYPED_JSON_SHA256(raw[:-1]).hexdigest()


class _TypedParserSpec(NamedTuple):
    typed_role: str
    payload_schema: str
    parser_id: str
    payload_keys: frozenset[str]
    code_sha256: str


try:
    _TYPED_PARSER_EXPECTED_MODULE = sys.modules[__name__]
    _TYPED_PARSER_TRUSTED_CLOSURE = (
        worker_receipts._freeze_trusted_callable_closure(
            _registered_canonical_json_parser,
            label="typed output registry parser",
            positional_parameters=2,
        )
    )
    _TYPED_PARSER_CODE_SHA256 = (
        worker_receipts._trusted_module_callable_binding(
            _registered_canonical_json_parser,
            label="typed output registry parser",
            positional_parameters=2,
            expected_module=_TYPED_PARSER_EXPECTED_MODULE,
        )["code_sha256"]
    )
    worker_receipts._replay_trusted_callable_closure(
        _registered_canonical_json_parser,
        _TYPED_PARSER_TRUSTED_CLOSURE,
        label="typed output registry parser",
        positional_parameters=2,
    )
except worker_receipts.WorkerExecutionError as exc:
    raise RuntimeError("typed output parser registry cannot initialize") from exc


def _parser_spec(
    *,
    typed_role: str,
    payload_schema: str,
    parser_id: str,
    payload_keys: frozenset[str],
) -> _TypedParserSpec:
    return _TypedParserSpec(
        typed_role=typed_role,
        payload_schema=payload_schema,
        parser_id=parser_id,
        payload_keys=payload_keys,
        code_sha256=_TYPED_PARSER_CODE_SHA256,
    )


_TYPED_PARSER_REGISTRY = MappingProxyType({
    (
        FIXTURE_TYPED_OUTPUT_ROLE,
        "fixture.typed-worker-output.v1",
        STRICT_CANONICAL_JSON_PARSER_ID,
    ): _parser_spec(
        typed_role=FIXTURE_TYPED_OUTPUT_ROLE,
        payload_schema="fixture.typed-worker-output.v1",
        parser_id=STRICT_CANONICAL_JSON_PARSER_ID,
        payload_keys=frozenset({"schema", "subject_digest", "disposition"}),
    ),
    (
        METHOD_CARD_PRODUCER_TYPED_ROLE,
        _METHOD_CARD_PRODUCER_SCHEMA,
        STRICT_CANONICAL_JSON_PARSER_ID,
    ): _parser_spec(
        typed_role=METHOD_CARD_PRODUCER_TYPED_ROLE,
        payload_schema=_METHOD_CARD_PRODUCER_SCHEMA,
        parser_id=STRICT_CANONICAL_JSON_PARSER_ID,
        payload_keys=_METHOD_CARD_PRODUCER_KEYS,
    ),
    (
        METHOD_CARD_REVIEWER_TYPED_ROLE,
        _METHOD_CARD_REVIEWER_SCHEMA,
        STRICT_CANONICAL_JSON_PARSER_ID,
    ): _parser_spec(
        typed_role=METHOD_CARD_REVIEWER_TYPED_ROLE,
        payload_schema=_METHOD_CARD_REVIEWER_SCHEMA,
        parser_id=STRICT_CANONICAL_JSON_PARSER_ID,
        payload_keys=_METHOD_CARD_REVIEWER_KEYS,
    ),
})


def _registered_parser_spec(
    *,
    typed_role: str,
    payload_schema: str,
    parser_id: str,
) -> _TypedParserSpec:
    if not all(
        isinstance(value, str) and value
        for value in (typed_role, payload_schema, parser_id)
    ):
        _fail("typed output parser registry key is malformed")
    spec = _TYPED_PARSER_REGISTRY.get(
        (typed_role, payload_schema, parser_id)
    )
    if spec is None:
        _fail("typed output role/schema/parser is not registered")
    return spec


def trusted_typed_worker_output_parser(
    *,
    typed_role: str,
    payload_schema: str,
    parser_id: str = STRICT_CANONICAL_JSON_PARSER_ID,
) -> Callable[[Path, bytes], str]:
    """Return only the closed registry parser used to compile a WorkPlan."""

    spec = _registered_parser_spec(
        typed_role=typed_role,
        payload_schema=payload_schema,
        parser_id=parser_id,
    )
    try:
        worker_receipts._replay_trusted_callable_closure(
            _registered_canonical_json_parser,
            _TYPED_PARSER_TRUSTED_CLOSURE,
            label="typed output registry parser construction",
            positional_parameters=2,
        )
    except worker_receipts.WorkerExecutionError as exc:
        _fail(f"typed output parser closure cannot replay: {exc}", exc)
    return _registered_canonical_json_parser


@dataclass(frozen=True)
class TypedWorkerOutputReplayWitness:
    """All current external authorities required to replay one typed output."""

    scratchpad: Path
    project_root: Path
    execution_authority: Mapping[str, Any]
    work_plan: Mapping[str, Any]
    phase_io_contract: PhaseIOContract
    phase_io_launch: LaunchSpec
    run_id: str
    typed_role: str
    payload_schema: str
    parser_id: str
    expected_output_identity: str
    expected_input_sha256: Mapping[str, str]
    expected_writer_role: str = "MODEL"


@dataclass(frozen=True)
class ValidatedTypedWorkerOutput:
    """Closed payload and the authority reconstructed from live provenance."""

    authority: dict[str, Any]
    payload: dict[str, Any]
    raw: bytes
    input_bindings: dict[str, dict[str, Any]]


def _fail(message: str, exc: Exception | None = None) -> NoReturn:
    if exc is None:
        raise TypedWorkerOutputAuthorityError(message)
    raise TypedWorkerOutputAuthorityError(message) from exc


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    actual = set(value)
    if actual == expected:
        return
    _fail(
        f"{label} fields are not closed; "
        f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
    )


def _hex64(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX64_RE.fullmatch(value) is None:
        _fail(f"{label} must be a lowercase SHA-256 digest")
    return value


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{label} must be a nonempty string")
    return value


def _digest(value: Mapping[str, Any]) -> str:
    try:
        return hashlib.sha256(canonical_json_bytes(value)).hexdigest()
    except ProgramFactsTypeError as exc:
        _fail(f"typed output authority is not canonical: {exc}", exc)


def _mapping_input(
    value: Mapping[str, Any] | bytes,
    *,
    label: str,
) -> dict[str, Any]:
    try:
        if isinstance(value, bytes):
            parsed = strict_json_loads(
                value,
                require_final_lf=True,
                require_canonical=True,
            )
        elif isinstance(value, Mapping):
            parsed = strict_json_loads(
                canonical_file_bytes(value),
                require_final_lf=True,
                require_canonical=True,
            )
        else:
            _fail(f"{label} must be an object or canonical bytes")
    except ProgramFactsTypeError as exc:
        _fail(f"{label} is not canonical JSON: {exc}", exc)
    if not isinstance(parsed, dict):
        _fail(f"{label} must be an object")
    return parsed


def _structural_authority(
    value: Mapping[str, Any] | bytes,
) -> dict[str, Any]:
    authority = _mapping_input(value, label="typed worker output authority")
    _exact_keys(authority, _AUTHORITY_KEYS, "typed worker output authority")
    if authority.get("schema") != TYPED_WORKER_OUTPUT_AUTHORITY_SCHEMA:
        _fail("typed worker output authority schema is unsupported")
    for field in (
        "work_plan_digest",
        "worker_execution_authority_digest",
        "provider_completion_digest",
        "phase_io_contract_digest",
        "phase_io_launch_digest",
        "phase_io_input_set_digest",
        "output_sha256",
        "payload_digest",
        "authority_digest",
    ):
        _hex64(authority.get(field), f"typed output {field}")
    for field in (
        "run_id",
        "phase",
        "work_unit_id",
        "attempt_id",
        "canonical_output_identity",
        "payload_schema",
        "writer_role",
    ):
        _nonempty(authority.get(field), f"typed output {field}")
    generation = authority.get("generation")
    output_size = authority.get("output_size")
    if (
        not isinstance(generation, int)
        or isinstance(generation, bool)
        or generation < 0
        or not isinstance(output_size, int)
        or isinstance(output_size, bool)
        or output_size < 0
    ):
        _fail("typed output generation or size is malformed")
    parser = authority.get("parser_binding")
    principal = authority.get("principal")
    if not isinstance(parser, Mapping):
        _fail("typed output parser binding must be an object")
    if not isinstance(principal, Mapping):
        _fail("typed output principal must be an object")
    _exact_keys(parser, _PARSER_BINDING_KEYS, "typed output parser binding")
    _exact_keys(principal, _PRINCIPAL_KEYS, "typed output principal")
    _nonempty(parser.get("identity"), "typed output parser identity")
    _nonempty(parser.get("source_file"), "typed output parser source file")
    _hex64(parser.get("source_sha256"), "typed output parser source digest")
    _hex64(parser.get("code_sha256"), "typed output parser code digest")
    _hex64(parser.get("closure_sha256"), "typed output parser closure digest")
    _nonempty(principal.get("identity"), "typed output principal identity")
    _nonempty(
        principal.get("invocation_id"),
        "typed output principal invocation",
    )
    claimed = authority["authority_digest"]
    unsigned = dict(authority)
    unsigned.pop("authority_digest")
    if claimed != _digest(unsigned):
        _fail("typed worker output authority digest mismatch")
    return authority


def _input_expectations(
    witness: TypedWorkerOutputReplayWitness,
) -> dict[str, str]:
    if not isinstance(witness.expected_input_sha256, Mapping):
        _fail("typed output expected input authority must be a mapping")
    result: dict[str, str] = {}
    for identity, digest in sorted(witness.expected_input_sha256.items()):
        if (
            not isinstance(identity, str)
            or not identity.startswith(("scratchpad:", "project:"))
        ):
            _fail("typed output expected input identity is malformed")
        result[identity] = _hex64(digest, f"typed output input {identity}")
    return result


def _load_provider_principal(
    *,
    scratchpad: Path,
    receipt_path: Path,
    completion: Mapping[str, Any],
) -> dict[str, str]:
    arm_relative = completion.get("arm_relative_path")
    if not isinstance(arm_relative, str) or not arm_relative or "/" in arm_relative:
        _fail("provider completion arm path is malformed")
    try:
        arm_path = worker_tx._safe_relative_file(
            receipt_path.parent,
            arm_relative,
            "provider execution arm",
        )
        arm = worker_tx._read_json(arm_path, "provider execution arm")
    except worker_tx.WorkerTransactionError as exc:
        _fail(f"provider execution arm does not replay: {exc}", exc)
    bindings = arm.get("bindings")
    principal = bindings.get("worker") if isinstance(bindings, Mapping) else None
    if not isinstance(principal, Mapping):
        _fail("provider worker principal binding is absent")
    _exact_keys(principal, _PRINCIPAL_KEYS, "provider worker principal")
    return {
        "identity": _nonempty(principal.get("identity"), "worker identity"),
        "invocation_id": _nonempty(
            principal.get("invocation_id"),
            "worker invocation identity",
        ),
    }


def replay_typed_worker_output(
    witness: TypedWorkerOutputReplayWitness,
) -> ValidatedTypedWorkerOutput:
    """Rebuild one typed authority solely from current incorporated bytes."""

    if type(witness) is not TypedWorkerOutputReplayWitness:
        _fail("typed output witness must be an exact replay witness")
    if type(witness.phase_io_contract) is not PhaseIOContract:
        _fail("typed output PhaseIO contract must be exact")
    if type(witness.phase_io_launch) is not LaunchSpec:
        _fail("typed output PhaseIO launch must be exact")
    parser_spec = _registered_parser_spec(
        typed_role=witness.typed_role,
        payload_schema=witness.payload_schema,
        parser_id=witness.parser_id,
    )
    if witness.expected_writer_role != "MODEL":
        _fail("typed worker output requires the MODEL writer role")

    scratchpad = Path(witness.scratchpad)
    project_root = Path(witness.project_root)
    contract = witness.phase_io_contract
    launch = witness.phase_io_launch
    try:
        plan = worker_tx._validate_compiled_plan(witness.work_plan)
    except worker_tx.WorkerTransactionError as exc:
        _fail(f"typed output WorkPlan does not replay: {exc}", exc)
    if (
        plan.get("run_id") != witness.run_id
        or plan.get("phase") != contract.phase
        or plan.get("work_unit_id") != contract.work_unit_id
        or plan.get("phase_io_contract_digest") != contract.digest
        or plan.get("phase_io_launch_digest") != launch.digest
        or launch.work_unit_key != contract.key
    ):
        _fail("typed output WorkPlan, PhaseIO contract, and launch differ")
    if len(contract.outputs) != 1:
        _fail("typed worker output requires one exact PhaseIO output")
    spec = contract.outputs[0]
    if (
        spec.identity != witness.expected_output_identity
        or spec.writer != witness.expected_writer_role
        or spec.schema_version != parser_spec.payload_schema
        or contract.model_invoked is not True
        or contract.required_commit_actor != witness.expected_writer_role
    ):
        _fail("typed output schema, identity, or writer role differs from PhaseIO")
    members = plan.get("assignment", {}).get("members")
    if not isinstance(members, list) or len(members) != 1:
        _fail("typed output WorkPlan assignment denominator is not singleton")
    member = members[0]
    if member.get("canonical_identity") != spec.identity:
        _fail("typed output WorkPlan assignment differs from PhaseIO output")
    try:
        parser_callback, parser_binding = (
            worker_receipts._resolve_registered_callable(
                _registered_canonical_json_parser,
                member.get("parser_binding"),
                expected_code_sha256=parser_spec.code_sha256,
                label="typed output registry parser",
                positional_parameters=2,
                expected_module=_TYPED_PARSER_EXPECTED_MODULE,
                trusted_closure=_TYPED_PARSER_TRUSTED_CLOSURE,
            )
        )
    except worker_receipts.WorkerExecutionError as exc:
        _fail(f"typed output parser binding cannot replay: {exc}", exc)

    expected_inputs = _input_expectations(witness)
    contract_inputs = set(contract.immutable_inputs) | set(
        contract.bounded_lookup_inputs
    )
    if contract_inputs != set(expected_inputs):
        _fail("typed output exact input denominator differs from PhaseIO")
    try:
        input_issues = artifact_ledger.validate_work_unit_inputs(
            scratchpad,
            project_root,
            contract,
            launch,
            run_id=witness.run_id,
        )
        current_ledger = artifact_ledger.read_artifact_ledger(scratchpad)
    except Exception as exc:
        _fail(f"typed output PhaseIO input authority cannot replay: {exc}", exc)
    if input_issues:
        _fail("typed output PhaseIO input authority is stale: " + "; ".join(input_issues))
    unit = current_ledger.get("work_units", {}).get(contract.key)
    if not isinstance(unit, Mapping):
        _fail("typed output PhaseIO work-unit authority is absent")
    input_bindings = unit.get("input_bindings")
    if not isinstance(input_bindings, Mapping):
        _fail("typed output PhaseIO input bindings are malformed")
    normalized_inputs: dict[str, dict[str, Any]] = {}
    for identity, expected_sha in expected_inputs.items():
        row = input_bindings.get(identity)
        if (
            not isinstance(row, Mapping)
            or row.get("status") != "ACTIVE"
            or row.get("sha256") != expected_sha
        ):
            _fail(f"typed output input {identity} differs from exact authority")
        normalized_inputs[identity] = dict(row)
    if (
        unit.get("semantic_status") != "ACTIVE"
        or unit.get("input_set_digest") != plan["phase_io_input_set_digest"]
        or unit.get("contract_digest") != contract.digest
        or unit.get("launch_digest") != launch.digest
        or unit.get("execution_authority") != witness.execution_authority
    ):
        _fail("typed output active PhaseIO work-unit authority differs from witness")
    commit = unit.get("commit_authority")
    if (
        not isinstance(commit, Mapping)
        or commit.get("actor") != witness.expected_writer_role
        or commit.get("input_set_digest") != plan["phase_io_input_set_digest"]
        or commit.get("execution_authority") != witness.execution_authority
    ):
        _fail("typed output PhaseIO commit writer or execution authority differs")

    try:
        execution = worker_tx.validate_worker_execution_authority(
            scratchpad=scratchpad,
            authority=witness.execution_authority,
            contract=contract,
            launch=launch,
            run_id=witness.run_id,
        )
    except worker_tx.WorkerTransactionError as exc:
        _fail(f"typed output execution/incorporation does not replay: {exc}", exc)
    for field in (
        "run_id",
        "phase",
        "work_unit_id",
        "generation",
        "work_plan_digest",
        "contract_digest",
        "launch_digest",
    ):
        plan_field = {
            "contract_digest": "phase_io_contract_digest",
            "launch_digest": "phase_io_launch_digest",
        }.get(field, field)
        if execution.get(field) != plan.get(plan_field):
            _fail(f"typed output execution {field} differs from WorkPlan")

    try:
        receipt_path = worker_tx._safe_relative_file(
            scratchpad,
            execution["provider_completion_relative_path"],
            "typed output provider completion",
        )
        completion = worker_receipts.validate_staged_execution(
            scratchpad=scratchpad,
            receipt_path=receipt_path,
            parser_digest=parser_callback,
            expected_completion_sha256=execution[
                "provider_completion_digest"
            ],
            trusted_parser_closure=_TYPED_PARSER_TRUSTED_CLOSURE,
        )
    except (
        worker_tx.WorkerTransactionError,
        worker_receipts.WorkerExecutionError,
        KeyError,
    ) as exc:
        _fail(f"typed output provider completion/CAS does not replay: {exc}", exc)
    provider_outputs = completion.get("outputs")
    if not isinstance(provider_outputs, list) or len(provider_outputs) != 1:
        _fail("typed output provider output denominator is not singleton")
    provider_output = provider_outputs[0]
    if (
        not isinstance(provider_output, Mapping)
        or provider_output.get("relative_path")
        != member.get("staged_relative_path")
        or provider_output.get("publish_relative_path")
        != spec.identity.removeprefix("scratchpad:")
    ):
        _fail("typed output provider member differs from WorkPlan and PhaseIO")

    try:
        incorporation_path = worker_tx._safe_relative_file(
            scratchpad,
            execution["incorporation_relative_path"],
            "typed output incorporation",
        )
        incorporation, incorporation_digest = worker_tx._read_digest_bound_json(
            incorporation_path,
            digest_field="incorporation_digest",
            label="typed output incorporation",
        )
    except (worker_tx.WorkerTransactionError, KeyError) as exc:
        _fail(f"typed output PhaseIO incorporation does not replay: {exc}", exc)
    _exact_keys(incorporation, _INCORPORATION_KEYS, "typed output incorporation")
    if incorporation.get("schema") != "plamen.worker_phaseio_incorporation.v1":
        _fail("typed output PhaseIO incorporation schema is unsupported")
    expected_incorporation = {
        "run_id": plan["run_id"],
        "phase": plan["phase"],
        "work_unit_id": plan["work_unit_id"],
        "generation": plan["generation"],
        "work_plan_digest": plan["work_plan_digest"],
        "attempt_id": execution["attempt_id"],
        "provider_completion_digest": execution["provider_completion_digest"],
        "contract_digest": contract.digest,
        "launch_digest": launch.digest,
        "input_set_digest": plan["phase_io_input_set_digest"],
        "projection_state": "COMPLETE",
    }
    if any(incorporation.get(key) != value for key, value in expected_incorporation.items()):
        _fail("typed output PhaseIO incorporation is stale or cross-bound")
    if incorporation_digest != execution["incorporation_digest"]:
        _fail("typed output PhaseIO incorporation differs from execution authority")

    try:
        incorporation_arm, arm_digest = worker_tx._read_digest_bound_json(
            incorporation_path.parent / "arm.json",
            digest_field="arm_digest",
            label="typed output incorporation arm",
        )
        progress, member_digest = worker_tx._read_digest_bound_json(
            incorporation_path.parent / "member-0000.json",
            digest_field="member_digest",
            label="typed output incorporation member",
        )
    except worker_tx.WorkerTransactionError as exc:
        _fail(f"typed output incorporation arm/member does not replay: {exc}", exc)
    _exact_keys(
        incorporation_arm,
        _INCORPORATION_ARM_KEYS,
        "typed output incorporation arm",
    )
    _exact_keys(
        progress,
        _INCORPORATION_MEMBER_KEYS,
        "typed output incorporation member",
    )
    if (
        incorporation.get("arm_digest") != arm_digest
        or progress.get("arm_digest") != arm_digest
        or type(progress.get("index")) is not int
        or progress.get("index") != 0
    ):
        _fail(
            "typed output incorporation index must be the exact integer zero"
        )
    arm_members = incorporation_arm.get("members")
    if not isinstance(arm_members, list) or len(arm_members) != 1:
        _fail("typed output incorporation source denominator is not singleton")
    raw_sha = _hex64(provider_output.get("raw_sha256"), "provider output digest")
    raw_size = provider_output.get("raw_size")
    if not isinstance(raw_size, int) or isinstance(raw_size, bool) or raw_size < 0:
        _fail("provider output size is malformed")
    expected_member = {
        "canonical_identity": spec.identity,
        "projection_mode": member["projection_mode"],
        "canonical_prestate": member["canonical_prestate"],
        "source_sha256": raw_sha,
        "source_size": raw_size,
    }
    projected = {
        "canonical_identity": spec.identity,
        "sha256": raw_sha,
        "size": raw_size,
    }
    if (
        arm_members[0] != expected_member
        or incorporation.get("projected_members") != [projected]
        or {
            "canonical_identity": progress.get("canonical_identity"),
            "sha256": progress.get("sha256"),
            "size": progress.get("size"),
        }
        != projected
    ):
        _fail("typed output provider CAS and PhaseIO projection differ")

    try:
        output_path = worker_tx._projection_destination(scratchpad, spec.identity)
        raw = worker_tx._read_rooted_bytes(output_path)
    except worker_tx.WorkerTransactionError as exc:
        _fail(f"typed output canonical bytes cannot be read: {exc}", exc)
    if len(raw) != raw_size or hashlib.sha256(raw).hexdigest() != raw_sha:
        _fail("typed output canonical bytes differ from provider and incorporation")
    try:
        worker_receipts._replay_trusted_callable_closure(
            parser_callback,
            _TYPED_PARSER_TRUSTED_CLOSURE,
            label="typed output registry parser",
            positional_parameters=2,
        )
        # Interpretation is sealed to the same local function graph whose root
        # produced the persisted parser digest.  Parser registry entries are
        # data-only and cannot inject a runtime decoder.
        payload = _registered_canonical_json_payload(output_path, raw)
        worker_receipts._replay_trusted_callable_closure(
            parser_callback,
            _TYPED_PARSER_TRUSTED_CLOSURE,
            label="typed output registry parser",
            positional_parameters=2,
        )
    except (ProgramFactsTypeError, worker_receipts.WorkerExecutionError) as exc:
        _fail(f"typed output incorporated bytes are not canonical JSON: {exc}", exc)
    if not isinstance(payload, dict):
        _fail("typed output incorporated payload must be an object")
    if set(payload) != set(parser_spec.payload_keys):
        _fail("typed output incorporated payload root is not closed")
    if payload.get("schema") != parser_spec.payload_schema:
        _fail("typed output incorporated payload schema differs")
    try:
        parsed_digest = worker_receipts._invoke_trusted_registered_callable(
            parser_callback,
            _TYPED_PARSER_TRUSTED_CLOSURE,
            (output_path, raw),
            label="typed output registry parser",
            positional_parameters=2,
        )
    except Exception as exc:
        _fail(f"typed output current parser rejected incorporated bytes: {exc}", exc)
    if (
        _hex64(parsed_digest, "typed output parser digest")
        != provider_output.get("parsed_sha256")
    ):
        _fail("typed output parsed payload differs from provider observation")
    principal = _load_provider_principal(
        scratchpad=scratchpad,
        receipt_path=receipt_path,
        completion=completion,
    )

    # The trusted parser is still executable code.  Replay every external
    # authority after its last invocation so a parser exception, side effect,
    # or concurrent drift cannot be hidden behind the earlier validation.
    try:
        post_completion = worker_receipts.validate_staged_execution(
            scratchpad=scratchpad,
            receipt_path=receipt_path,
            parser_digest=parser_callback,
            expected_completion_sha256=execution[
                "provider_completion_digest"
            ],
            trusted_parser_closure=_TYPED_PARSER_TRUSTED_CLOSURE,
        )
        post_execution = worker_tx.validate_worker_execution_authority(
            scratchpad=scratchpad,
            authority=witness.execution_authority,
            contract=contract,
            launch=launch,
            run_id=witness.run_id,
        )
        post_incorporation, post_incorporation_digest = (
            worker_tx._read_digest_bound_json(
                incorporation_path,
                digest_field="incorporation_digest",
                label="post-parser typed output incorporation",
            )
        )
        post_incorporation_arm, post_arm_digest = (
            worker_tx._read_digest_bound_json(
                incorporation_path.parent / "arm.json",
                digest_field="arm_digest",
                label="post-parser typed output incorporation arm",
            )
        )
        post_progress, post_member_digest = worker_tx._read_digest_bound_json(
            incorporation_path.parent / "member-0000.json",
            digest_field="member_digest",
            label="post-parser typed output incorporation member",
        )
        _resolved_parser, post_parser_binding = (
            worker_receipts._resolve_registered_callable(
                _registered_canonical_json_parser,
                member.get("parser_binding"),
                expected_code_sha256=parser_spec.code_sha256,
                label="typed output registry parser",
                positional_parameters=2,
                expected_module=_TYPED_PARSER_EXPECTED_MODULE,
                trusted_closure=_TYPED_PARSER_TRUSTED_CLOSURE,
            )
        )
        post_input_issues = artifact_ledger.validate_work_unit_inputs(
            scratchpad,
            project_root,
            contract,
            launch,
            run_id=witness.run_id,
        )
        post_ledger = artifact_ledger.read_artifact_ledger(scratchpad)
        post_cas_raw = worker_receipts._replay_blob(
            receipt_path.parent,
            provider_output.get("cas_blob"),
            "typed output CAS",
        )
        post_output_raw = worker_tx._read_rooted_bytes(output_path)
    except (
        artifact_ledger.ArtifactLedgerError,
        worker_tx.WorkerTransactionError,
        worker_receipts.WorkerExecutionError,
        OSError,
    ) as exc:
        _fail(f"typed output post-parser provenance does not replay: {exc}", exc)
    post_unit = post_ledger.get("work_units", {}).get(contract.key)
    post_bindings = (
        post_unit.get("input_bindings")
        if isinstance(post_unit, Mapping)
        else None
    )
    if (
        post_completion != completion
        or post_execution != execution
        or post_incorporation != incorporation
        or post_incorporation_digest != incorporation_digest
        or post_incorporation_arm != incorporation_arm
        or post_arm_digest != arm_digest
        or post_progress != progress
        or post_member_digest != member_digest
        or post_parser_binding != parser_binding
        or post_input_issues
        or not isinstance(post_bindings, Mapping)
        or post_output_raw != raw
        or len(post_output_raw) != raw_size
        or hashlib.sha256(post_output_raw).hexdigest() != raw_sha
        or post_cas_raw != raw
        or len(post_cas_raw) != raw_size
        or hashlib.sha256(post_cas_raw).hexdigest() != raw_sha
        or post_unit.get("execution_authority")
        != witness.execution_authority
    ):
        _fail("typed output changed during trusted parser execution")
    for identity, binding in normalized_inputs.items():
        current_binding = post_bindings.get(identity)
        if not isinstance(current_binding, Mapping) or dict(
            current_binding
        ) != binding:
            _fail(f"typed output input {identity} changed after parser execution")
        root_name, relative = identity.split(":", 1)
        input_root = scratchpad if root_name == "scratchpad" else project_root
        try:
            live_path = worker_tx._safe_relative_file(
                input_root,
                relative,
                "typed output post-parser input",
            )
            live_raw = worker_tx._read_rooted_bytes(live_path)
        except worker_tx.WorkerTransactionError as exc:
            _fail(
                f"typed output input {identity} cannot replay after parser",
                exc,
            )
        if (
            hashlib.sha256(live_raw).hexdigest() != binding.get("sha256")
            or len(live_raw) != binding.get("size")
        ):
            _fail(f"typed output input {identity} changed after parser execution")

    # The closed parser proved that ``raw[:-1]`` is already the unique
    # canonical semantic byte representation.  Re-encoding here would reopen
    # the JSONDecoder/JSONEncoder dependency that this authority boundary
    # intentionally excludes.
    payload_digest = parsed_digest
    unsigned = {
        "schema": TYPED_WORKER_OUTPUT_AUTHORITY_SCHEMA,
        "run_id": plan["run_id"],
        "phase": plan["phase"],
        "work_unit_id": plan["work_unit_id"],
        "generation": plan["generation"],
        "work_plan_digest": plan["work_plan_digest"],
        "attempt_id": execution["attempt_id"],
        "worker_execution_authority_digest": execution["authority_digest"],
        "provider_completion_digest": execution["provider_completion_digest"],
        "phase_io_contract_digest": contract.digest,
        "phase_io_launch_digest": launch.digest,
        "phase_io_input_set_digest": plan["phase_io_input_set_digest"],
        "canonical_output_identity": spec.identity,
        "output_sha256": raw_sha,
        "output_size": raw_size,
        "payload_schema": parser_spec.payload_schema,
        "payload_digest": payload_digest,
        "parser_binding": parser_binding,
        "writer_role": witness.expected_writer_role,
        "principal": principal,
    }
    authority = {**unsigned, "authority_digest": _digest(unsigned)}
    _structural_authority(authority)
    try:
        worker_receipts._replay_trusted_callable_closure(
            parser_callback,
            _TYPED_PARSER_TRUSTED_CLOSURE,
            label="typed output pre-publication parser",
            positional_parameters=2,
        )
    except worker_receipts.WorkerExecutionError as exc:
        _fail(f"typed output parser closure changed before publication: {exc}", exc)
    return ValidatedTypedWorkerOutput(
        authority=authority,
        payload=payload,
        raw=raw,
        input_bindings=normalized_inputs,
    )


def canonical_typed_worker_output_authority_bytes(
    value: Mapping[str, Any],
) -> bytes:
    """Serialize one structurally closed authority with one final LF."""

    authority = _structural_authority(value)
    try:
        return canonical_file_bytes(authority)
    except ProgramFactsTypeError as exc:
        _fail(f"typed worker output authority is not canonical: {exc}", exc)


def validate_typed_worker_output_authority(
    value: Mapping[str, Any] | bytes,
    witness: TypedWorkerOutputReplayWitness,
) -> ValidatedTypedWorkerOutput:
    """Compare a persisted authority with the exact current provenance replay."""

    candidate = _structural_authority(value)
    current = replay_typed_worker_output(witness)
    if candidate != current.authority:
        _fail("typed worker output authority differs from exact current replay")
    return current


__all__ = [
    "FIXTURE_TYPED_OUTPUT_ROLE",
    "METHOD_CARD_PRODUCER_TYPED_ROLE",
    "METHOD_CARD_REVIEWER_TYPED_ROLE",
    "STRICT_CANONICAL_JSON_PARSER_ID",
    "TYPED_WORKER_OUTPUT_AUTHORITY_SCHEMA",
    "TypedWorkerOutputAuthorityError",
    "TypedWorkerOutputReplayWitness",
    "ValidatedTypedWorkerOutput",
    "canonical_typed_worker_output_authority_bytes",
    "replay_typed_worker_output",
    "trusted_typed_worker_output_parser",
    "validate_typed_worker_output_authority",
]
