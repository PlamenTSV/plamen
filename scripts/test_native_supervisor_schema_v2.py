"""Focused consistency gates for the immutable native-supervisor v2 schema."""

from __future__ import annotations

import json
from pathlib import Path
import re

import posix_audit_supervisor as supervisor
import posix_backend_execution as backend_execution


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "native" / "darwin" / "native-supervisor-schema-v2.json"
HEADER_PATH = ROOT / "native" / "include" / "plamen_broker_v2.h"
PROTOCOL_PATH = ROOT / "native" / "posix" / "plamen_broker_v2_protocol.c"


def _no_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        assert key not in result, f"duplicate schema key: {key}"
        result[key] = value
    return result


def _schema() -> dict[str, object]:
    raw = SCHEMA_PATH.read_bytes()
    assert raw and raw.endswith(b"\n") and not raw.startswith(b"\xef\xbb\xbf")
    assert b"\x00" not in raw and b"\r" not in raw
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_pairs)
    assert type(value) is dict
    expected = (
        json.dumps(
            value, ensure_ascii=False, sort_keys=True, indent=2,
            separators=(",", ": "), allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    assert raw == expected
    return value


def _macro(source: str, name: str) -> str:
    match = re.search(
        rf"^#define[ \t]+{re.escape(name)}[ \t]+(.+?)(?=\n(?![ \t]))",
        source,
        re.MULTILINE | re.DOTALL,
    )
    assert match is not None, name
    return re.sub(r"\\\n[ \t]*", "", match.group(1)).strip()


def _macro_uint(source: str, name: str) -> int:
    token = _macro(source, name)
    assert re.fullmatch(r"(?:0x[0-9A-Fa-f]+|[0-9]+)U?", token), (name, token)
    return int(token.rstrip("U"), 0)


def _macro_string(source: str, name: str) -> str:
    token = _macro(source, name)
    parts = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', token)
    assert parts
    return bytes("".join(parts), "ascii").decode("unicode_escape")


def _enum(source: str, name: str) -> dict[str, int]:
    match = re.search(
        rf"enum[ \t]+{re.escape(name)}[ \t]*\{{(.*?)\}};",
        source,
        re.DOTALL,
    )
    assert match is not None, name
    result: dict[str, int] = {}
    for item, raw_value in re.findall(
        r"\b(PLAMEN_BROKER_V2_[A-Z0-9_]+)\s*=\s*(0x[0-9A-Fa-f]+|[0-9]+)",
        match.group(1),
    ):
        assert item not in result
        result[item] = int(raw_value, 0)
    assert result
    return result


def _struct_fields(source: str, name: str) -> list[str]:
    match = re.search(
        rf"struct[ \t]+{re.escape(name)}[ \t]*\{{(.*?)\}};",
        source,
        re.DOTALL,
    )
    assert match is not None, name
    body = re.sub(r"/\*.*?\*/", "", match.group(1), flags=re.DOTALL)
    fields: list[str] = []
    for declaration in body.split(";"):
        declaration = declaration.strip()
        if not declaration:
            continue
        found = re.search(r"\b([A-Za-z_]\w*)\s*(?:\[[^]]+\])?\s*$", declaration)
        assert found is not None, (name, declaration)
        fields.append(found.group(1))
    assert len(fields) == len(set(fields)), f"duplicate fields in {name}"
    return fields


def test_schema_is_canonical_and_version_identifiers_match_native_sources() -> None:
    schema = _schema()
    header = HEADER_PATH.read_text(encoding="utf-8")
    versions = schema["version_identifiers"]
    assert schema["schema"] == "plamen.native-supervisor.schema.v2"
    assert versions == {
        "backend_execution_abi_schema": backend_execution.NATIVE_EXECUTION_ABI_SCHEMA,
        "broker_abi_schema": supervisor.NATIVE_ABI_SCHEMA,
        "broker_protocol_version": _macro_uint(header, "PLAMEN_BROKER_V2_VERSION"),
        "darwin_service_name": _macro_string(header, "PLAMEN_BROKER_V2_DARWIN_SERVICE_NAME"),
        "linux_guest_socket": _macro_string(header, "PLAMEN_BROKER_V2_LINUX_GUEST_SOCKET"),
        "linux_service_name": _macro_string(header, "PLAMEN_BROKER_V2_LINUX_SERVICE_NAME"),
        "linux_user_socket_format": _macro_string(header, "PLAMEN_BROKER_V2_LINUX_USER_SOCKET_FORMAT"),
        "projection_schema": _macro_string(header, "PLAMEN_BROKER_V2_REQUEST_PROJECTION_SCHEMA"),
        "supervisor_request_schema": supervisor.SCHEMA,
    }


def test_projection_and_role5_role8_authority_split_are_exact() -> None:
    schema = _schema()
    header = HEADER_PATH.read_text(encoding="utf-8")
    protocol = PROTOCOL_PATH.read_text(encoding="utf-8")
    projection = schema["projection"]
    match = re.search(
        r"projection_audit_fields\[PROJECTION_AUDIT_FIELD_COUNT\]\s*=\s*\{(.*?)\};",
        protocol,
        re.DOTALL,
    )
    assert match is not None
    assert re.findall(r'"([a-z0-9_]+)"', match.group(1)) == projection[
        "audit_request_fields"
    ]
    commitment = _struct_fields(header, "plamen_broker_v2_commitment")
    assert commitment == projection["commitment_fields"]
    assert projection["top_level_fields"] == ["audit_request", "projection_schema"]
    assert projection["source_config"]["fields"] == [
        "authenticated", "canonical_utf8_b64", "retained_source_handle", "sha256",
    ]

    authority = projection["binding_authority"]
    role5 = authority["role5_schema"]
    assert role5 == {
        "fixed_export_allowlist": [
            "project/AUDIT_REPORT.md", "scratch/_plamen.log",
            "scratch/_v2_checkpoint.json",
        ],
        "fixed_export_max_total_bytes": supervisor.MAX_EXPORT_TOTAL_BYTES,
        "fixed_failure_required_artifacts": ["scratch/_plamen.log"],
        "fixed_protocol_policy_identifiers": {
            "audit_request_schema": supervisor.SCHEMA,
            "backend_execution_abi_schema": backend_execution.NATIVE_EXECUTION_ABI_SCHEMA,
            "broker_abi_schema": supervisor.NATIVE_ABI_SCHEMA,
            "broker_protocol_version": backend_execution.NATIVE_BROKER_PROTOCOL_VERSION,
            "projection_schema": "plamen.native_audit_request_projection.v1",
        },
        "fixed_required_artifacts": [
            "project/AUDIT_REPORT.md", "scratch/_v2_checkpoint.json",
        ],
    }
    assert authority["role8_runtime_manifest"] == {
        "request_bindings": [
            "image_closure_sha256", "image_manifest_digest",
            "runtime_layout_sha256", "seccomp_profile_sha256",
        ],
        "runtime_bindings": [
            "baked_toolchain_closure", "outer_entrypoint", "runtime_package_tree",
        ],
        "schema": "plamen.runtime-package-manifest.v2",
    }
    role5_fields = {
        "export_allowlist", "export_max_total_bytes",
        "failure_required_artifacts", "required_artifacts",
    }
    role8_fields = set(authority["role8_runtime_manifest"]["request_bindings"])
    native_fields = set(authority["native_request_observations"])
    assert role5_fields.isdisjoint(role8_fields | native_fields)
    assert role8_fields.isdisjoint(native_fields)


def test_frame_and_service_bootstrap_wire_contract_matches_header() -> None:
    schema = _schema()
    header = HEADER_PATH.read_text(encoding="utf-8")
    frame = schema["frame_protocol"]
    assert frame["header_size"] == _macro_uint(header, "PLAMEN_BROKER_V2_HEADER_SIZE")
    frame_enum = _enum(header, "plamen_broker_v2_frame_type")
    assert {
        f"PLAMEN_BROKER_V2_{row['name']}": row["value"]
        for row in frame["frame_types"]
    } == frame_enum

    service = schema["service_bootstrap"]
    service_enum = _enum(header, "plamen_broker_v2_service_message_type")
    message_names = {
        "READINESS": "READINESS",
        "READY": "READY",
        "REGISTER_INITIAL": "REGISTER_INITIAL",
        "REGISTER_RECOVERY": "REGISTER_RECOVERY",
        "REGISTRATION_ACCEPTED": "REGISTRATION_ACCEPTED",
        "SESSION_LOOKUP": "SESSION_LOOKUP",
        "SESSION_CHALLENGE": "SESSION_CHALLENGE",
        "SESSION_OPEN": "SESSION_OPEN",
        "SESSION_ACCEPTED": "SESSION_ACCEPTED",
        "ERROR": "ERROR",
    }
    messages = {row["name"]: row for row in service["messages"]}
    assert set(messages) == set(message_names)
    for asset_name, enum_suffix in message_names.items():
        assert messages[asset_name]["value"] == service_enum[
            f"PLAMEN_BROKER_V2_SERVICE_{enum_suffix}"
        ]

    struct_names = {
        "READINESS": "plamen_broker_v2_service_readiness",
        "READY": "plamen_broker_v2_service_ready",
        "REGISTER_INITIAL": "plamen_broker_v2_service_registration",
        "REGISTER_RECOVERY": "plamen_broker_v2_service_registration",
        "REGISTRATION_ACCEPTED": "plamen_broker_v2_service_registration_ack",
        "SESSION_LOOKUP": "plamen_broker_v2_service_session_lookup",
        "SESSION_CHALLENGE": "plamen_broker_v2_service_session_challenge",
        "SESSION_OPEN": "plamen_broker_v2_service_session_open",
        "SESSION_ACCEPTED": "plamen_broker_v2_service_session_ack",
        "ERROR": "plamen_broker_v2_service_error",
    }
    size_macros = {
        "READINESS": "PLAMEN_BROKER_V2_SERVICE_READINESS_SIZE",
        "READY": "PLAMEN_BROKER_V2_SERVICE_READY_SIZE",
        "REGISTER_INITIAL": "PLAMEN_BROKER_V2_SERVICE_REGISTRATION_SIZE",
        "REGISTER_RECOVERY": "PLAMEN_BROKER_V2_SERVICE_REGISTRATION_SIZE",
        "REGISTRATION_ACCEPTED": "PLAMEN_BROKER_V2_SERVICE_REGISTRATION_ACK_SIZE",
        "SESSION_LOOKUP": "PLAMEN_BROKER_V2_SERVICE_SESSION_LOOKUP_SIZE",
        "SESSION_CHALLENGE": "PLAMEN_BROKER_V2_SERVICE_SESSION_CHALLENGE_SIZE",
        "SESSION_OPEN": "PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN_SIZE",
        "SESSION_ACCEPTED": "PLAMEN_BROKER_V2_SERVICE_SESSION_ACK_SIZE",
        "ERROR": "PLAMEN_BROKER_V2_SERVICE_ERROR_SIZE",
    }
    for name, row in messages.items():
        assert sorted(_struct_fields(header, struct_names[name])) == row["fields"]
        assert row["payload_size"] == _macro_uint(header, size_macros[name])

    wire_names = service["wire_field_names"]
    assert wire_names == {
        "control_socket": _macro_string(header, "PLAMEN_BROKER_V2_XPC_KEY_CONTROL_SOCKET"),
        "envelope": _macro_string(header, "PLAMEN_BROKER_V2_XPC_KEY_ENVELOPE"),
        "key_pipe_read": _macro_string(header, "PLAMEN_BROKER_V2_XPC_KEY_KEY_PIPE_READ"),
        "request_projection": _macro_string(header, "PLAMEN_BROKER_V2_XPC_KEY_REQUEST_PROJECTION"),
    }


def test_authority_bundles_and_backend_output_contract_are_exact() -> None:
    schema = _schema()
    header = HEADER_PATH.read_text(encoding="utf-8")
    surface = schema["authority_surface"]
    outer = surface["outer_supervisor"]
    assert outer["member_count"] == _macro_uint(
        header, "PLAMEN_BROKER_V2_OUTER_AUTHORITY_MEMBER_COUNT"
    )
    assert [
        (row["name"], tuple(row["methods"])) for row in outer["members"]
    ] == list(supervisor._NATIVE_AUTHORITY_TYPES)
    assert [row["ordinal"] for row in outer["members"]] == list(range(1, 11))
    component_names = {
        "RuntimeImageAuthority": "runtime_image",
        "WorkspaceAuthority": "workspace",
        "BackendContextAuthority": "backend_context",
        "ProviderAuthority": "provider",
        "GuestAdmissionAuthority": "guest_admission",
        "ExtinctionAuthority": "extinction",
        "ArtifactAuthority": "artifact",
        "ExportAuthority": "export",
        "JournalAuthority": "journal",
        "RecoveryAuthority": "recovery",
    }
    rpc = outer["rpc_contract"]
    assert rpc["encoding"] == "CANONICAL_ASCII_JSON_SORTED_KEYS_TRAILING_LF"
    assert rpc["call_document_schema"] == "plamen.native-supervisor-call.v1"
    assert rpc["response_document_schema"] == (
        "plamen.native-supervisor-response.v1"
    )
    assert schema["limits"]["role1_rpc_authenticated_prefix_bytes"] == 176
    assert schema["limits"]["role1_rpc_canonical_bytes"] == 2096976
    expected_rpc_keys = {
        f"{row['ordinal']:02d}.{row['name']}.{method}"
        for row in outer["members"] for method in row["methods"]
    }
    assert set(rpc["methods"]) == expected_rpc_keys
    for member in outer["members"]:
        for method in member["methods"]:
            key = f"{member['ordinal']:02d}.{member['name']}.{method}"
            contract = rpc["methods"][key]
            component = component_names[member["name"]]
            prefix = f"plamen.native-supervisor.role1.{component}.{method}"
            assert contract["request_schema"] == f"{prefix}.request.v2"
            assert contract["response_schema"] == f"{prefix}.response.v2"
            assert contract["request_arity"] == 1
            assert contract["max_request_bytes"] == 2096976
            assert contract["max_request_bytes"] + schema["limits"][
                "role1_rpc_authenticated_prefix_bytes"
            ] == backend_execution.NATIVE_BROKER_MAX_PAYLOAD_BYTES
            if method == "provider_kind":
                assert contract["max_response_bytes"] == supervisor.MAX_TEXT_BYTES
            else:
                assert contract["max_response_bytes"] == 2096976

    backend = surface["backend_execution"]
    assert backend["member_count"] == _macro_uint(
        header, "PLAMEN_BROKER_V2_GUEST_AUTHORITY_MEMBER_COUNT"
    )
    assert tuple(backend["method_order"]) == backend_execution._NATIVE_BACKEND_METHODS
    expected_methods = {
        "prepare": (
            backend_execution.NATIVE_PREPARE_REQUEST_SCHEMA,
            backend_execution._PREPARE_REQUEST_FIELDS,
            backend_execution.NATIVE_PREPARED_RECEIPT_SCHEMA,
            backend_execution._PREPARED_RECEIPT_FIELDS,
        ),
        "start_or_recover": (
            backend_execution.NATIVE_START_REQUEST_SCHEMA,
            backend_execution._START_REQUEST_FIELDS,
            backend_execution.NATIVE_STARTED_RECEIPT_SCHEMA,
            backend_execution._STARTED_RECEIPT_FIELDS,
        ),
        "wait_or_recover": (
            backend_execution.NATIVE_WAIT_REQUEST_SCHEMA,
            backend_execution._WAIT_REQUEST_FIELDS,
            backend_execution.NATIVE_EXITED_RECEIPT_SCHEMA,
            backend_execution._EXITED_RECEIPT_FIELDS,
        ),
        "read_output_or_recover": (
            backend_execution.NATIVE_OUTPUT_REQUEST_SCHEMA,
            backend_execution._OUTPUT_REQUEST_FIELDS,
            backend_execution.NATIVE_OUTPUT_RECEIPT_SCHEMA,
            backend_execution._OUTPUT_RECEIPT_FIELDS,
        ),
        "extinguish_or_recover": (
            backend_execution.NATIVE_EXTINGUISH_REQUEST_SCHEMA,
            backend_execution._EXTINGUISH_REQUEST_FIELDS,
            backend_execution.NATIVE_REVOKED_RECEIPT_SCHEMA,
            backend_execution._REVOKED_RECEIPT_FIELDS,
        ),
        "close_operation": (
            backend_execution.NATIVE_CLOSE_REQUEST_SCHEMA,
            backend_execution._CLOSE_REQUEST_FIELDS,
            backend_execution.NATIVE_FINISHED_RECEIPT_SCHEMA,
            backend_execution._FINISHED_RECEIPT_FIELDS,
        ),
    }
    assert {row["name"] for row in backend["methods"]} == set(expected_methods)
    for row in backend["methods"]:
        request_schema, request_fields, response_schema, response_fields = (
            expected_methods[row["name"]]
        )
        assert row["request_schema"] == request_schema
        assert set(row["request_fields"]) == request_fields
        assert row["response_schema"] == response_schema
        assert set(row["response_fields"]) == response_fields
    output = next(
        row for row in backend["methods"]
        if row["name"] == "read_output_or_recover"
    )
    assert output["request_schema"] == backend_execution.NATIVE_OUTPUT_REQUEST_SCHEMA
    assert output["response_schema"] == backend_execution.NATIVE_OUTPUT_RECEIPT_SCHEMA
    assert set(output["request_fields"]) == backend_execution._OUTPUT_REQUEST_FIELDS
    assert set(output["response_fields"]) == backend_execution._OUTPUT_RECEIPT_FIELDS
    assert schema["limits"]["output_chunk_bytes"] == (
        backend_execution.NATIVE_OUTPUT_CHUNK_MAX_BYTES
    )
    assert schema["limits"]["backend_stream_observed_bytes"] == (
        backend_execution.NATIVE_STREAM_OBSERVED_LIMIT_BYTES
    )
    assert schema["limits"]["backend_stream_retained_bytes"] == (
        backend_execution.NATIVE_STREAM_RETAINED_LIMIT_BYTES
    )
