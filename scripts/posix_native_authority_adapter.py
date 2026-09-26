"""Strict value bridge for the role-1 native supervisor authorities.

The objects wrapped here are already authenticated, non-constructible native
capabilities.  This module does not discover, acquire, duplicate, or create an
authority.  It only turns the typed values used by ``posix_audit_supervisor``
into a bounded canonical request and turns an authenticated native response
back into the supervisor's closed set of dataclass/enum values.

The native extension owns the secret member capability identifier and the
transport operation nonce.  Neither is exposed to Python.  Every opaque member
method accepts exactly one ``bytes`` argument containing the call document.
"""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from enum import Enum
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any
import unicodedata

import posix_audit_supervisor as S


CALL_SCHEMA = "plamen.native-supervisor-call.v1"
RESPONSE_SCHEMA = "plamen.native-supervisor-response.v1"
BROKER_MAX_PAYLOAD_BYTES = 2 * 1024 * 1024
NATIVE_OPERATION_RESPONSE_PREFIX_BYTES = 176
MAX_CALL_BYTES = (
    BROKER_MAX_PAYLOAD_BYTES - NATIVE_OPERATION_RESPONSE_PREFIX_BYTES
)
MAX_RESPONSE_BYTES = MAX_CALL_BYTES
# Compatibility alias for callers that need the overall broker payload bound.
MAX_WIRE_BYTES = BROKER_MAX_PAYLOAD_BYTES
# Two closed 4,096-entry artifact rosters, their tagged field maps, and the
# enclosing census fit below this independent structural ceiling.
MAX_WIRE_NODES = 131072
MAX_WIRE_DEPTH = 64

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class NativeAuthorityAdapterError(S.SupervisorError):
    """A bounded public failure at the typed/native representation boundary."""


_DATACLASS_TYPES = (
    S.AuthenticatedDriverConfig,
    S.AuditRequest,
    S.AuthenticatedRuntimeImageLayout,
    S.TargetLease,
    S.TargetRecensus,
    S.BackendContext,
    S.MutationTicket,
    S.AttemptLayout,
    S.GuestConfig,
    S.ConfigReceipt,
    S.LayoutComponent,
    S.LayoutRecensus,
    S.GuestMount,
    S.GuestCreateSpec,
    S.GuestCreatedReceipt,
    S.GuestObservation,
    S.GuestAdmissionReceipt,
    S.DriverLaunch,
    S.DriverStartReceipt,
    S.DriverExitReceipt,
    S.ExtinctionReceipt,
    S.ArtifactEntry,
    S.ArtifactDisposition,
    S.ArtifactCensus,
    S.ExportReceipt,
    S.DeleteReceipt,
    S.SupervisorCheckpoint,
    S.JournalOpenReceipt,
    S.RecoveryResolution,
)
_DATACLASS_BY_NAME = MappingProxyType(
    {value.__name__: value for value in _DATACLASS_TYPES}
)
_ENUM_TYPES = (
    S.RequestType,
    S.ProviderKind,
    S.MutationOperation,
    S.SupervisorStage,
    S.SupervisorCompletionStatus,
    S.JournalOpenStatus,
    S.RecoveryStatus,
)
_ENUM_BY_NAME = MappingProxyType({value.__name__: value for value in _ENUM_TYPES})

# Arguments in this closed set were issued or durably authenticated by a native
# authority.  They are never reflected back as Python-supplied data; only their
# canonical commitments cross the operation boundary.
_RECEIPT_ARGUMENT_TYPES = frozenset({
    S.AuthenticatedRuntimeImageLayout,
    S.TargetLease,
    S.TargetRecensus,
    S.BackendContext,
    S.MutationTicket,
    S.AttemptLayout,
    S.ConfigReceipt,
    S.LayoutRecensus,
    S.GuestCreatedReceipt,
    S.GuestObservation,
    S.GuestAdmissionReceipt,
    S.DriverStartReceipt,
    S.DriverExitReceipt,
    S.ExtinctionReceipt,
    S.ArtifactCensus,
    S.ExportReceipt,
    S.DeleteReceipt,
    S.SupervisorCheckpoint,
    S.JournalOpenReceipt,
    S.RecoveryResolution,
})


def _json_bytes(value: Any, *, maximum: int = MAX_RESPONSE_BYTES) -> bytes:
    try:
        encoded = (
            json.dumps(
                value,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("ascii", "strict")
    except (TypeError, ValueError, UnicodeError):
        raise NativeAuthorityAdapterError(
            "native supervisor value is not canonical JSON"
        ) from None
    if (type(maximum) is not int or isinstance(maximum, bool) or maximum <= 0
            or not encoded or len(encoded) > maximum):
        raise NativeAuthorityAdapterError(
            "native supervisor message exceeds its bound"
        )
    return encoded


def _parse_int(token: str) -> int:
    if len(token) > 19:
        raise ValueError
    value = int(token)
    if not -(2**63) <= value <= 2**63 - 1:
        raise ValueError
    return value


def _reject_number(_token: str) -> None:
    raise ValueError


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _validate_tree(value: Any, *, depth: int = 0) -> int:
    if depth > MAX_WIRE_DEPTH:
        raise ValueError
    if value is None or type(value) in {bool, int}:
        return 1
    if type(value) is str:
        if (value != unicodedata.normalize("NFC", value)
                or any(ord(character) < 32 for character in value)):
            raise ValueError
        return 1
    if type(value) is list:
        count = 1
        for item in value:
            count += _validate_tree(item, depth=depth + 1)
            if count > MAX_WIRE_NODES:
                raise ValueError
        return count
    if type(value) is dict:
        count = 1
        for key, item in value.items():
            if (type(key) is not str
                    or key != unicodedata.normalize("NFC", key)
                    or any(ord(character) < 32 for character in key)):
                raise ValueError
            count += _validate_tree(item, depth=depth + 1)
            if count > MAX_WIRE_NODES:
                raise ValueError
        return count
    raise ValueError


def _parse_json_bytes(raw: Any) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_RESPONSE_BYTES:
        raise NativeAuthorityAdapterError(
            "native supervisor response is not bounded bytes"
        )
    try:
        value = json.loads(
            raw.decode("ascii", "strict"),
            object_pairs_hook=_pairs,
            parse_int=_parse_int,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
        if type(value) is not dict:
            raise ValueError
        _validate_tree(value)
        if raw != _json_bytes(value):
            raise ValueError
    except NativeAuthorityAdapterError:
        raise
    except (ValueError, UnicodeError, json.JSONDecodeError):
        raise NativeAuthorityAdapterError(
            "native supervisor response is not exact canonical JSON"
        ) from None
    return value


def _wire_value(value: Any) -> Any:
    """Encode a returned typed value without permitting arbitrary objects."""
    if isinstance(value, Enum):
        if type(value) not in _ENUM_TYPES:
            raise NativeAuthorityAdapterError(
                "native supervisor result enum type is unsupported"
            )
        return {"$enum": type(value).__name__, "value": value.value}
    if is_dataclass(value) and not isinstance(value, type):
        if type(value) not in _DATACLASS_TYPES:
            raise NativeAuthorityAdapterError(
                "native supervisor result dataclass type is unsupported"
            )
        return {
            "$type": type(value).__name__,
            "fields": {
                field.name: _wire_value(getattr(value, field.name))
                for field in fields(value)
            },
        }
    if type(value) is tuple:
        return {"$tuple": [_wire_value(item) for item in value]}
    if type(value) is bytes:
        return {"$bytes_hex": value.hex()}
    if value is None or type(value) in {str, int, bool}:
        return value
    raise NativeAuthorityAdapterError(
        "native supervisor result contains an unsupported value"
    )


def _decode_wire_value(value: Any, *, depth: int = 0) -> Any:
    if depth > MAX_WIRE_DEPTH:
        raise NativeAuthorityAdapterError(
            "native supervisor result nesting exceeds its bound"
        )
    if value is None or type(value) in {str, int, bool}:
        return value
    if type(value) is not dict:
        raise NativeAuthorityAdapterError(
            "native supervisor result has an unsupported JSON type"
        )
    keys = frozenset(value)
    if keys == {"$bytes_hex"}:
        token = value["$bytes_hex"]
        if (type(token) is not str or len(token) % 2 != 0
                or any(character not in "0123456789abcdef" for character in token)):
            raise NativeAuthorityAdapterError(
                "native supervisor byte value is noncanonical"
            )
        try:
            return bytes.fromhex(token)
        except ValueError:
            raise NativeAuthorityAdapterError(
                "native supervisor byte value is noncanonical"
            ) from None
    if keys == {"$tuple"}:
        items = value["$tuple"]
        if type(items) is not list:
            raise NativeAuthorityAdapterError(
                "native supervisor tuple value is malformed"
            )
        return tuple(
            _decode_wire_value(item, depth=depth + 1) for item in items
        )
    if keys == {"$enum", "value"}:
        name = value["$enum"]
        token = value["value"]
        enum_type = _ENUM_BY_NAME.get(name) if type(name) is str else None
        if enum_type is None or type(token) is not str:
            raise NativeAuthorityAdapterError(
                "native supervisor enum value is unsupported"
            )
        try:
            return enum_type(token)
        except (TypeError, ValueError):
            raise NativeAuthorityAdapterError(
                "native supervisor enum value is invalid"
            ) from None
    if keys == {"$type", "fields"}:
        name = value["$type"]
        members = value["fields"]
        value_type = _DATACLASS_BY_NAME.get(name) if type(name) is str else None
        if value_type is None or type(members) is not dict:
            raise NativeAuthorityAdapterError(
                "native supervisor typed result is unsupported"
            )
        expected = tuple(field.name for field in fields(value_type))
        if frozenset(members) != frozenset(expected):
            raise NativeAuthorityAdapterError(
                "native supervisor typed result fields are not exact"
            )
        try:
            decoded = {
                name: _decode_wire_value(members[name], depth=depth + 1)
                for name in expected
            }
            return value_type(**decoded)
        except NativeAuthorityAdapterError:
            raise
        except BaseException:
            raise NativeAuthorityAdapterError(
                "native supervisor typed result is invalid"
            ) from None
    raise NativeAuthorityAdapterError(
        "native supervisor result object has nonexact fields"
    )


def _commitment(value: Any) -> str:
    try:
        result = S.canonical_sha256(value)
    except BaseException:
        raise NativeAuthorityAdapterError(
            "native supervisor argument cannot be committed"
        ) from None
    if type(result) is not str or _HEX64.fullmatch(result) is None:
        raise NativeAuthorityAdapterError(
            "native supervisor argument commitment is invalid"
        )
    return result


class _Operation:
    __slots__ = ("argument_names", "argument_types", "result_type")

    def __init__(
        self,
        argument_names: tuple[str, ...],
        argument_types: tuple[type[Any], ...],
        result_type: type[Any],
    ) -> None:
        self.argument_names = argument_names
        self.argument_types = argument_types
        self.result_type = result_type


_OPERATIONS = MappingProxyType({
    ("runtime", "authenticate"): _Operation(
        ("request",), (S.AuditRequest,), S.AuthenticatedRuntimeImageLayout,
    ),
    ("workspace", "admit_target"): _Operation(
        ("request",), (S.AuditRequest,), S.TargetLease,
    ),
    ("workspace", "revalidate_target"): _Operation(
        ("request", "target"), (S.AuditRequest, S.TargetLease), S.TargetRecensus,
    ),
    ("workspace", "prepare_layout"): _Operation(
        ("request", "target", "ticket"),
        (S.AuditRequest, S.TargetLease, S.MutationTicket), S.AttemptLayout,
    ),
    ("workspace", "resume_layout"): _Operation(
        ("request", "layout"), (S.AuditRequest, S.AttemptLayout), S.AttemptLayout,
    ),
    ("workspace", "write_guest_config"): _Operation(
        ("request", "layout", "config", "ticket"),
        (S.AuditRequest, S.AttemptLayout, S.GuestConfig, S.MutationTicket),
        S.ConfigReceipt,
    ),
    ("workspace", "recensus_layout"): _Operation(
        ("request", "target", "layout", "runtime", "backend", "configured", "phase"),
        (S.AuditRequest, S.TargetLease, S.AttemptLayout,
         S.AuthenticatedRuntimeImageLayout, S.BackendContext, S.ConfigReceipt, str),
        S.LayoutRecensus,
    ),
    ("backend", "authenticate"): _Operation(
        ("request",), (S.AuditRequest,), S.BackendContext,
    ),
    ("provider", "provider_kind"): _Operation((), (), S.ProviderKind),
    ("provider", "create_stopped"): _Operation(
        ("spec", "ticket"), (S.GuestCreateSpec, S.MutationTicket),
        S.GuestCreatedReceipt,
    ),
    ("provider", "inspect_stopped"): _Operation(
        ("created",), (S.GuestCreatedReceipt,), S.GuestObservation,
    ),
    ("provider", "resume_guest"): _Operation(
        ("request", "created"), (S.AuditRequest, S.GuestCreatedReceipt),
        S.GuestCreatedReceipt,
    ),
    ("provider", "start_driver"): _Operation(
        ("created", "admission", "launch", "ticket"),
        (S.GuestCreatedReceipt, S.GuestAdmissionReceipt, S.DriverLaunch,
         S.MutationTicket),
        S.DriverStartReceipt,
    ),
    ("provider", "wait_driver"): _Operation(
        ("created", "started", "ticket"),
        (S.GuestCreatedReceipt, S.DriverStartReceipt, S.MutationTicket),
        S.DriverExitReceipt,
    ),
    ("provider", "delete_guest"): _Operation(
        ("created", "terminal", "ticket"),
        (S.GuestCreatedReceipt, S.ExtinctionReceipt, S.MutationTicket),
        S.DeleteReceipt,
    ),
    ("guest_admission", "admit_stopped_guest"): _Operation(
        ("request", "created", "observation", "postcreate", "ticket"),
        (S.AuditRequest, S.GuestCreatedReceipt, S.GuestObservation,
         S.LayoutRecensus, S.MutationTicket),
        S.GuestAdmissionReceipt,
    ),
    ("guest_admission", "resume_admission"): _Operation(
        ("request", "created", "admission"),
        (S.AuditRequest, S.GuestCreatedReceipt, S.GuestAdmissionReceipt),
        S.GuestAdmissionReceipt,
    ),
    ("extinction", "extinguish"): _Operation(
        ("request", "created", "exited", "ticket"),
        (S.AuditRequest, S.GuestCreatedReceipt, S.DriverExitReceipt,
         S.MutationTicket),
        S.ExtinctionReceipt,
    ),
    ("artifacts", "census"): _Operation(
        ("request", "layout", "exited", "terminal", "ticket"),
        (S.AuditRequest, S.AttemptLayout, S.DriverExitReceipt,
         S.ExtinctionReceipt, S.MutationTicket),
        S.ArtifactCensus,
    ),
    ("exporter", "export"): _Operation(
        ("request", "layout", "census", "ticket"),
        (S.AuditRequest, S.AttemptLayout, S.ArtifactCensus, S.MutationTicket),
        S.ExportReceipt,
    ),
    ("journal", "open"): _Operation(
        ("request",), (S.AuditRequest,), S.JournalOpenReceipt,
    ),
    ("journal", "arm"): _Operation(
        ("request", "operation", "before_checkpoint_sha256"),
        (S.AuditRequest, S.MutationOperation, str), S.MutationTicket,
    ),
    ("journal", "commit"): _Operation(
        ("request", "ticket", "checkpoint"),
        (S.AuditRequest, S.MutationTicket, S.SupervisorCheckpoint), bool,
    ),
    ("journal", "resolve"): _Operation(
        ("request", "ticket", "checkpoint"),
        (S.AuditRequest, S.MutationTicket, S.SupervisorCheckpoint), bool,
    ),
    ("journal", "finish"): _Operation(
        ("request", "checkpoint_sha256"), (S.AuditRequest, str), bool,
    ),
    ("recovery", "recover"): _Operation(
        ("request", "ticket", "before"),
        (S.AuditRequest, S.MutationTicket, S.SupervisorCheckpoint),
        S.RecoveryResolution,
    ),
})


def _argument_descriptor(name: str, value: Any) -> dict[str, Any]:
    descriptor: dict[str, Any] = {
        "commitment_sha256": _commitment(value),
        "name": name,
        "type": type(value).__name__,
    }
    if isinstance(value, Enum):
        descriptor["value"] = value.value
    elif type(value) in {str, int, bool} or value is None:
        descriptor["value"] = value
    return descriptor


def _build_call(
    binding: "_Binding", member: str, operation: str, arguments: tuple[Any, ...],
) -> bytes:
    spec = _OPERATIONS.get((member, operation))
    if spec is None or len(arguments) != len(spec.argument_types):
        raise NativeAuthorityAdapterError(
            "native supervisor operation signature is invalid"
        )
    if any(type(value) is not expected for value, expected in zip(
        arguments, spec.argument_types, strict=True
    )):
        raise NativeAuthorityAdapterError(
            "native supervisor operation argument type is invalid"
        )
    for value in arguments:
        if type(value) is S.AuditRequest and value != binding.request:
            raise NativeAuthorityAdapterError(
                "native supervisor operation names a different request"
            )
    descriptors = tuple(
        _argument_descriptor(name, value)
        for name, value in zip(spec.argument_names, arguments, strict=True)
    )
    receipt_commitments = tuple(
        {
            "name": descriptor["name"],
            "sha256": descriptor["commitment_sha256"],
            "type": descriptor["type"],
        }
        for descriptor, value in zip(descriptors, arguments, strict=True)
        if type(value) in _RECEIPT_ARGUMENT_TYPES
    )
    return _json_bytes({
        "arguments": list(descriptors),
        "member": member,
        "operation": operation,
        "receipt_commitments": list(receipt_commitments),
        "request_commitment_sha256": binding.request_commitment_sha256,
        "request_fingerprint_sha256": binding.request_fingerprint_sha256,
        "schema": CALL_SCHEMA,
    }, maximum=MAX_CALL_BYTES)


def _decode_response(
    raw: Any, binding: "_Binding", member: str, operation: str,
    call_bytes: bytes,
) -> Any:
    value = _parse_json_bytes(raw)
    exact_keys = {
        "call_sha256", "member", "operation", "request_fingerprint_sha256",
        "result", "result_commitment_sha256", "schema",
    }
    if frozenset(value) != frozenset(exact_keys):
        raise NativeAuthorityAdapterError(
            "native supervisor response fields are not exact"
        )
    call_sha256 = hashlib.sha256(call_bytes).hexdigest()
    if (
        value["schema"] != RESPONSE_SCHEMA
        or value["member"] != member
        or value["operation"] != operation
        or value["request_fingerprint_sha256"]
        != binding.request_fingerprint_sha256
        or value["call_sha256"] != call_sha256
        or type(value["result_commitment_sha256"]) is not str
        or _HEX64.fullmatch(value["result_commitment_sha256"]) is None
    ):
        raise NativeAuthorityAdapterError(
            "native supervisor response commitment is invalid"
        )
    result = _decode_wire_value(value["result"])
    expected = _OPERATIONS[(member, operation)].result_type
    if type(result) is not expected:
        raise NativeAuthorityAdapterError(
            "native supervisor response type is invalid"
        )
    if _commitment(result) != value["result_commitment_sha256"]:
        raise NativeAuthorityAdapterError(
            "native supervisor result commitment differs"
        )
    return result


class _Binding:
    __slots__ = (
        "request", "request_commitment_sha256", "request_fingerprint_sha256",
    )

    def __init__(self, request: S.AuditRequest) -> None:
        if type(request) is not S.AuditRequest:
            raise NativeAuthorityAdapterError(
                "native supervisor adapter requires one typed request"
            )
        self.request = request
        self.request_commitment_sha256 = _commitment(request)
        self.request_fingerprint_sha256 = request.fingerprint_sha256


class _Member:
    __slots__ = ("_binding", "_member", "_native")

    def __init__(self, binding: _Binding, member: str, native: object) -> None:
        self._binding = binding
        self._member = member
        self._native = native

    def _call(self, operation: str, *arguments: Any) -> Any:
        call_bytes = _build_call(
            self._binding, self._member, operation, tuple(arguments)
        )
        try:
            method = getattr(self._native, operation)
            if not callable(method):
                raise TypeError
            raw = method(call_bytes)
        except BaseException:
            raise NativeAuthorityAdapterError(
                "native supervisor operation failed"
            ) from None
        return _decode_response(
            raw, self._binding, self._member, operation, call_bytes
        )


class _Runtime(_Member):
    def authenticate(self, request: S.AuditRequest) -> S.AuthenticatedRuntimeImageLayout:
        return self._call("authenticate", request)


class _Workspace(_Member):
    def admit_target(self, request: S.AuditRequest) -> S.TargetLease:
        return self._call("admit_target", request)

    def revalidate_target(self, request: S.AuditRequest, target: S.TargetLease) -> S.TargetRecensus:
        return self._call("revalidate_target", request, target)

    def prepare_layout(self, request: S.AuditRequest, target: S.TargetLease, ticket: S.MutationTicket) -> S.AttemptLayout:
        return self._call("prepare_layout", request, target, ticket)

    def resume_layout(self, request: S.AuditRequest, layout: S.AttemptLayout) -> S.AttemptLayout:
        return self._call("resume_layout", request, layout)

    def write_guest_config(self, request: S.AuditRequest, layout: S.AttemptLayout, config: S.GuestConfig, ticket: S.MutationTicket) -> S.ConfigReceipt:
        return self._call("write_guest_config", request, layout, config, ticket)

    def recensus_layout(self, request: S.AuditRequest, target: S.TargetLease, layout: S.AttemptLayout, runtime: S.AuthenticatedRuntimeImageLayout, backend: S.BackendContext, configured: S.ConfigReceipt, phase: str) -> S.LayoutRecensus:
        return self._call(
            "recensus_layout", request, target, layout, runtime, backend,
            configured, phase,
        )


class _Backend(_Member):
    def authenticate(self, request: S.AuditRequest) -> S.BackendContext:
        return self._call("authenticate", request)


class _Provider(_Member):
    def provider_kind(self) -> S.ProviderKind:
        return self._call("provider_kind")

    def create_stopped(self, spec: S.GuestCreateSpec, ticket: S.MutationTicket) -> S.GuestCreatedReceipt:
        return self._call("create_stopped", spec, ticket)

    def inspect_stopped(self, created: S.GuestCreatedReceipt) -> S.GuestObservation:
        return self._call("inspect_stopped", created)

    def resume_guest(self, request: S.AuditRequest, created: S.GuestCreatedReceipt) -> S.GuestCreatedReceipt:
        return self._call("resume_guest", request, created)

    def start_driver(self, created: S.GuestCreatedReceipt, admission: S.GuestAdmissionReceipt, launch: S.DriverLaunch, ticket: S.MutationTicket) -> S.DriverStartReceipt:
        return self._call("start_driver", created, admission, launch, ticket)

    def wait_driver(self, created: S.GuestCreatedReceipt, started: S.DriverStartReceipt, ticket: S.MutationTicket) -> S.DriverExitReceipt:
        return self._call("wait_driver", created, started, ticket)

    def delete_guest(self, created: S.GuestCreatedReceipt, terminal: S.ExtinctionReceipt, ticket: S.MutationTicket) -> S.DeleteReceipt:
        return self._call("delete_guest", created, terminal, ticket)


class _GuestAdmission(_Member):
    def admit_stopped_guest(self, request: S.AuditRequest, created: S.GuestCreatedReceipt, observation: S.GuestObservation, postcreate: S.LayoutRecensus, ticket: S.MutationTicket) -> S.GuestAdmissionReceipt:
        return self._call(
            "admit_stopped_guest", request, created, observation, postcreate,
            ticket,
        )

    def resume_admission(self, request: S.AuditRequest, created: S.GuestCreatedReceipt, admission: S.GuestAdmissionReceipt) -> S.GuestAdmissionReceipt:
        return self._call("resume_admission", request, created, admission)


class _Extinction(_Member):
    def extinguish(self, request: S.AuditRequest, created: S.GuestCreatedReceipt, exited: S.DriverExitReceipt, ticket: S.MutationTicket) -> S.ExtinctionReceipt:
        return self._call("extinguish", request, created, exited, ticket)


class _Artifacts(_Member):
    def census(self, request: S.AuditRequest, layout: S.AttemptLayout, exited: S.DriverExitReceipt, terminal: S.ExtinctionReceipt, ticket: S.MutationTicket) -> S.ArtifactCensus:
        return self._call("census", request, layout, exited, terminal, ticket)


class _Exporter(_Member):
    def export(self, request: S.AuditRequest, layout: S.AttemptLayout, census: S.ArtifactCensus, ticket: S.MutationTicket) -> S.ExportReceipt:
        return self._call("export", request, layout, census, ticket)


class _Journal(_Member):
    def open(self, request: S.AuditRequest) -> S.JournalOpenReceipt:
        return self._call("open", request)

    def arm(self, request: S.AuditRequest, operation: S.MutationOperation, before_checkpoint_sha256: str) -> S.MutationTicket:
        return self._call(
            "arm", request, operation, before_checkpoint_sha256
        )

    def commit(self, request: S.AuditRequest, ticket: S.MutationTicket, checkpoint: S.SupervisorCheckpoint) -> bool:
        return self._call("commit", request, ticket, checkpoint)

    def resolve(self, request: S.AuditRequest, ticket: S.MutationTicket, checkpoint: S.SupervisorCheckpoint) -> bool:
        return self._call("resolve", request, ticket, checkpoint)

    def finish(self, request: S.AuditRequest, checkpoint_sha256: str) -> bool:
        return self._call("finish", request, checkpoint_sha256)


class _Recovery(_Member):
    def recover(self, request: S.AuditRequest, ticket: S.MutationTicket, before: S.SupervisorCheckpoint) -> S.RecoveryResolution:
        return self._call("recover", request, ticket, before)


_WRAPPERS = (
    ("runtime", _Runtime),
    ("workspace", _Workspace),
    ("backend", _Backend),
    ("provider", _Provider),
    ("guest_admission", _GuestAdmission),
    ("extinction", _Extinction),
    ("artifacts", _Artifacts),
    ("exporter", _Exporter),
    ("journal", _Journal),
    ("recovery", _Recovery),
)


def adapt_native_supervisor_authorities(
    request: S.AuditRequest,
    native_members: tuple[object, ...],
    native_member_types: tuple[type[Any], ...],
) -> S.SupervisorAuthorities:
    """Wrap one already-authenticated exact native role-1 member tuple.

    The caller must obtain ``native_members`` from the consumed native bundle
    and ``native_member_types`` from the authenticated extension surface.  No
    duck-typed or subclassed member is admitted.
    """
    if (type(native_members) is not tuple
            or type(native_member_types) is not tuple
            or len(native_members) != len(_WRAPPERS)
            or len(native_member_types) != len(_WRAPPERS)
            or any(type(expected) is not type for expected in native_member_types)
            or any(type(member) is not expected for member, expected in zip(
                native_members, native_member_types, strict=True
            ))):
        raise NativeAuthorityAdapterError(
            "native supervisor member roster is invalid"
        )
    binding = _Binding(request)
    wrappers = tuple(
        wrapper(binding, member_name, native)
        for (member_name, wrapper), native in zip(
            _WRAPPERS, native_members, strict=True
        )
    )
    return S.SupervisorAuthorities(*wrappers)


__all__ = [
    "BROKER_MAX_PAYLOAD_BYTES",
    "CALL_SCHEMA",
    "MAX_CALL_BYTES",
    "MAX_RESPONSE_BYTES",
    "MAX_WIRE_BYTES",
    "NATIVE_MEMBER_CAPABILITY_ID_BYTES",
    "NativeAuthorityAdapterError",
    "RESPONSE_SCHEMA",
    "adapt_native_supervisor_authorities",
]
