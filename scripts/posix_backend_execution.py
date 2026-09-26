"""Consume one authenticated outer-supervisor backend launch on POSIX.

This module defines the narrow bridge between the durable worker-attempt arm
and the final :mod:`worker_execution_receipts` process-creation boundary.  It
does not discover a backend, read ambient credentials, or implement
host-to-guest transport.  Production registration and issuance intentionally
hard-stop until a compiled or out-of-process guest-bootstrap adapter owns the
authority boundary; Python objects are never accepted as a substitute.

The explicit structural-test seam uses a distinct execution type and the
launch policy's distinct TEST_ONLY receipt schema/status.  It cannot make the
production context appear available to the driver or authorize WER's exact
production type check.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import importlib
import importlib.machinery
import json
import os
from pathlib import Path
import re
import stat
import sys
import threading
import time
import types
from types import MappingProxyType
from typing import Any, Mapping, NoReturn, Protocol, Sequence
import uuid
import weakref

if os.name == "nt":  # The imported policy uses POSIX descriptor primitives.
    raise ImportError("posix_backend_execution is unavailable on Windows")

import posix_backend_launch_policy as _launch_policy
from posix_backend_launch_policy import (
    TestOnlyBackendLaunchInvocation,
    TestOnlyBackendLaunchPlan,
    TEST_ONLY_AUTHORITY_CLASS,
    TEST_ONLY_COMPLETION_RECEIPT_SCHEMA,
    TEST_ONLY_PUBLIC_RECEIPT_SCHEMA,
)


OUTER_AUTHORITY_SCHEMA = "plamen.posix_backend_outer_authority.v1"
MATERIALIZATION_SCHEMA = "plamen.posix_backend_materialization.v1"
REVOCATION_SCHEMA = "plamen.posix_backend_revocation.v1"
EXTERNAL_VERIFICATION_SCHEMA = (
    "plamen.posix_backend_external_verification.v1"
)
ARM_BINDING_SCHEMA = "plamen.posix_backend_execution_arm_binding.v1"
NATIVE_EXECUTION_ABI_SCHEMA = "plamen.posix_backend_execution.native.v2"
NATIVE_CODEX_REQUEST_SCHEMA = (
    "plamen.posix_backend_execution.codex_request.v2"
)
NATIVE_CLAUDE_REQUEST_SCHEMA = (
    "plamen.posix_backend_execution.claude_request.v2"
)
NATIVE_BROKER_ABI_SCHEMA = "plamen.native-broker.v2"
NATIVE_BROKER_PROTOCOL_VERSION = 2
NATIVE_BROKER_FRAME_HEADER_SIZE = 196
NATIVE_BROKER_AUTH_OFFSET = 164
NATIVE_BROKER_MAX_PAYLOAD_BYTES = 2 * 1024 * 1024
NATIVE_BROKER_MAX_FDS = 16
NATIVE_BROKER_AUTH_CONSUME = 0x0002
NATIVE_BROKER_AUTH_ACCEPTED = 0x0003
NATIVE_BROKER_START_PREPARE = 0x0020
NATIVE_BROKER_STARTED = 0x0021
NATIVE_BROKER_START_RECOVER = 0x0022
NATIVE_BROKER_WAIT_PREPARE = 0x0030
NATIVE_BROKER_EXITED = 0x0031
NATIVE_BROKER_WAIT_RECOVER = 0x0032
NATIVE_BROKER_REVOKE_PREPARE = 0x0040
NATIVE_BROKER_REVOKED = 0x0041
NATIVE_BROKER_BACKEND_PREPARE = 0x0050
NATIVE_BROKER_BACKEND_PREPARED = 0x0051
NATIVE_BROKER_OUTPUT_READ = 0x0060
NATIVE_BROKER_OUTPUT_CHUNK = 0x0061
NATIVE_BROKER_OPERATION_CLOSE = 0x0070
NATIVE_BROKER_OPERATION_FINISHED = 0x0071
NATIVE_INITIAL_ROLE_GUEST_DRIVER = 2
NATIVE_PROCESS_ROLE_BACKEND_EXECUTION = 3
# Compatibility spelling for callers migrating from the pre-freeze role name.
NATIVE_SPAWNED_ROLE_BACKEND_EXECUTION = NATIVE_PROCESS_ROLE_BACKEND_EXECUTION
NATIVE_BACKEND_ENVELOPE_MAX_BYTES = 64 * 1024
NATIVE_STREAM_OBSERVED_LIMIT_BYTES = 16 * 1024 * 1024
NATIVE_STREAM_RETAINED_LIMIT_BYTES = NATIVE_STREAM_OBSERVED_LIMIT_BYTES
BACKEND_STDOUT_LIMIT_BYTES = _launch_policy.STDOUT_LIMIT_BYTES
BACKEND_STDERR_LIMIT_BYTES = _launch_policy.STDERR_LIMIT_BYTES
NATIVE_OUTPUT_CHUNK_MAX_BYTES = 256 * 1024
NATIVE_BACKEND_TIMEOUT_MAX_SECONDS = 86_400
NATIVE_PREPARE_REQUEST_SCHEMA = (
    "plamen.posix_backend_execution.prepare_request.v2"
)
NATIVE_PREPARED_RECEIPT_SCHEMA = (
    "plamen.posix_backend_execution.prepared_receipt.v2"
)
NATIVE_START_REQUEST_SCHEMA = "plamen.posix_backend_execution.start_request.v2"
NATIVE_STARTED_RECEIPT_SCHEMA = (
    "plamen.posix_backend_execution.started_receipt.v2"
)
NATIVE_WAIT_REQUEST_SCHEMA = "plamen.posix_backend_execution.wait_request.v2"
NATIVE_EXITED_RECEIPT_SCHEMA = (
    "plamen.posix_backend_execution.exited_receipt.v2"
)
NATIVE_OUTPUT_REQUEST_SCHEMA = (
    "plamen.posix_backend_execution.output_request.v2"
)
NATIVE_OUTPUT_RECEIPT_SCHEMA = (
    "plamen.posix_backend_execution.output_receipt.v2"
)
NATIVE_EXTINGUISH_REQUEST_SCHEMA = (
    "plamen.posix_backend_execution.extinguish_request.v2"
)
NATIVE_REVOKED_RECEIPT_SCHEMA = (
    "plamen.posix_backend_execution.revoked_receipt.v2"
)
NATIVE_CLOSE_REQUEST_SCHEMA = "plamen.posix_backend_execution.close_request.v2"
NATIVE_FINISHED_RECEIPT_SCHEMA = (
    "plamen.posix_backend_execution.finished_receipt.v2"
)
MAX_AUTHORITY_LIFETIME_NS = 5 * 60 * 1_000_000_000
MAX_CLOCK_SKEW_NS = 30 * 1_000_000_000

_HEX64_RE = re.compile(r"[0-9a-f]{64}")
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_FORBIDDEN_ARGV = frozenset({
    "--dangerously-bypass-approvals-and-sandbox",
    "--dangerously-skip-permissions",
    "--sandbox",
    "--yolo",
    "--full-auto",
})
_OUTER_FIELDS = frozenset({
    "schema", "attempt_id", "backend", "model",
    "outer_attempt_arm_sha256", "work_plan_sha256",
    "process_scope_identity", "base_argv_sha256",
    "base_environment_sha256", "cwd_identity_sha256", "prompt_sha256",
    "provider_stdout_contract_sha256",
    "plan_receipt_sha256", "provider_context_sha256", "context_nonce",
    "descendant_credential_denial_sha256",
    "issued_at_unix_ns", "expires_at_unix_ns",
})
_MATERIALIZATION_FIELDS = frozenset({
    "schema", "attempt_id", "backend", "inner_arm_sha256",
    "process_scope_identity", "plan_receipt_sha256",
    "outer_authority_receipt_sha256", "environment_names",
    "final_environment_sha256", "cwd_fd_identity_sha256",
    "stdin_fd_identity_sha256", "pass_fds_identity_sha256",
    "retained_fd_count", "materialized_private_state_sha256", "status",
})
_REVOCATION_FIELDS = frozenset({
    "schema", "attempt_id", "backend", "inner_arm_sha256",
    "process_scope_identity", "plan_receipt_sha256",
    "materialization_receipt_sha256", "process_creation_state",
    "process_population_zero_proven", "returncode", "reason_code",
    "status",
})
_POLICY_COMPLETION_FIELDS = frozenset({
    "schema", "attempt_id", "backend", "model",
    "issuance_receipt_sha256", "sealed_content_sha256", "status",
    "completion_evidence_sha256", "fd_state",
})
_SEALED_POLICY_FIELDS = frozenset({
    "codex_profile_sha256", "claude_settings_contract",
    "claude_settings_sha256", "claude_mcp_sha256",
    "codex_permission_profile_status", "credential_isolation_mode",
    "credential_isolation_sha256",
    "codex_config_census_contract",
    "codex_config_census_contract_sha256",
    "codex_config_census_evidence_sha256",
})
_CODEX_CONFIG_CENSUS_CONTRACT = (
    "PRIVATE_HOME_BASE_ABSENT_CONTROL_ANCESTORS_PROJECT_CONFIG_ABSENT_V1"
)
_CODEX_CREDENTIAL_DELIVERY = (
    "SUPERVISOR_MATERIALIZE_EXACT_PRIVATE_CODEX_HOME_CENSUS_THEN_CLOSE"
)
_CODEX_PROFILE_DELIVERY = (
    "SUPERVISOR_MATERIALIZE_EXACT_PROFILE_IN_PRIVATE_CODEX_HOME_THEN_CENSUS"
)
_CLAUDE_CREDENTIAL_DELIVERY = _launch_policy.CLAUDE_CREDENTIAL_DELIVERY

# Numeric purpose values are shared with ``plamen_broker_v2_fd_purpose``.
# They describe the authenticated denominator only; the native receiver must
# still validate exact SCM_RIGHTS count/order/access and descriptor identity.
_FD_WORKING_DIRECTORY = 0x0003
_FD_BACKEND_EXECUTABLE = 0x0010
_FD_STDIN_PROMPT = 0x0011
_FD_SEALED_POLICY = 0x0012
_FD_PUBLIC_CA = 0x0013
_FD_CREDENTIAL = 0x0014
_FD_PROFILE = 0x0015
_FD_SETTINGS = 0x0016
_FD_MCP_CONFIG = 0x0017
_FD_PROXY_AUTH = 0x0018
_FD_CHILD_PASS = 0x0019

_NATIVE_MODULE_NAME = "_plamen_native_supervisor"
_NATIVE_PRODUCTION_ACQUISITION = "AVAILABLE_AUTHENTICATED_NATIVE_SESSION"
_NATIVE_OPERATION_DISPATCH = "AUTHENTICATED_CANONICAL_BYTES_RPC"
_NATIVE_BACKEND_METHODS = (
    "prepare",
    "start_or_recover",
    "wait_or_recover",
    "read_output_or_recover",
    "extinguish_or_recover",
    "close_operation",
)
_STREAM_NAMES = frozenset({"stdout", "stderr"})
_ZERO_SHA256 = "0" * 64
_NATIVE_MANAGED_BOOTSTRAP_INPUTS_SCHEMA = (
    "plamen.native-guest-managed-evm-bootstrap-inputs.v1"
)


class PosixBackendExecutionError(RuntimeError):
    """The authenticated POSIX backend boundary failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _fail(code: str, message: str, exc: BaseException | None = None) -> NoReturn:
    error = PosixBackendExecutionError(code, message)
    if exc is None:
        raise error
    raise error from exc


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            dict(value), ensure_ascii=True, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        _fail("CANONICAL_JSON", "value is not canonical JSON", exc)


def _canonical_operation_request_bytes(value: Mapping[str, Any]) -> bytes:
    """Encode one native OPERATION_REQUEST body with its wire LF sentinel.

    The extension admits only exact 7-bit canonical JSON terminated by one
    line-feed.  Semantic envelopes and service response receipts remain plain
    canonical JSON; the sentinel belongs solely to authenticated RPC request
    bodies and therefore participates in their SHA-256 commitments.
    """

    return canonical_json_bytes(value) + b"\n"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _mapping_sha(value: Mapping[str, Any]) -> str:
    return _sha(canonical_json_bytes(value))


def _argv_sha(argv: Sequence[str]) -> str:
    return _sha(canonical_json_bytes({"argv": list(argv)}))


def _environment_sha(environment: Mapping[str, str]) -> str:
    return _mapping_sha(dict(environment))


def _native_fd_purpose_order(backend: str) -> list[int]:
    """Return the backend-distinct ordered broker-v2 FD denominator."""

    common = [
        _FD_WORKING_DIRECTORY,
        _FD_BACKEND_EXECUTABLE,
        _FD_STDIN_PROMPT,
        _FD_SEALED_POLICY,
        _FD_PUBLIC_CA,
        _FD_CREDENTIAL,
    ]
    backend_specific = (
        [_FD_PROFILE]
        if backend == "codex"
        else [_FD_SETTINGS, _FD_MCP_CONFIG]
    )
    return sorted([*common, *backend_specific, _FD_PROXY_AUTH, _FD_CHILD_PASS])


def native_backend_execution_envelope_v2(
    *, backend: str, model: str, attempt_id: str,
    outer_attempt_arm_sha256: str, work_plan_sha256: str,
    process_scope_identity: str, base_argv: Sequence[str],
    base_environment: Mapping[str, str], cwd_identity_sha256: str,
    prompt_sha256: str, provider_stdout_contract_sha256: str,
    timeout_seconds: int, stdout_limit_bytes: int, stderr_limit_bytes: int,
    backend_install_generation_authority: object | None = None,
) -> bytes:
    """Build the exact non-secret native request denominator for one leaf.

    This is a serialization contract, not an authority issuer.  It deliberately
    contains no credential, pathname, descriptor number, socket, key, or token.
    The native guest broker binds the actual descriptor roster and executable
    identity before spawn and owns the durable start/wait/revoke records.
    """

    if type(backend) is not str or backend not in {"codex", "claude"}:
        _fail("BACKEND", "POSIX backend must be codex or claude")
    try:
        generation = _launch_policy._install_generation_projection(
            backend_install_generation_authority, allow_test_only=True,
        )
    except _launch_policy.PosixBackendLaunchPolicyError as exc:
        _fail("INSTALL_GENERATION_AUTHORITY", "backend install authority is invalid", exc)
    if generation.backend != backend:
        _fail(
            "INSTALL_GENERATION_BACKEND",
            "backend differs from authenticated install generation",
        )
    _identifier(attempt_id, "attempt id")
    _identifier(process_scope_identity, "process scope identity")
    _hex(outer_attempt_arm_sha256, "outer arm")
    _hex(work_plan_sha256, "work plan")
    _hex(cwd_identity_sha256, "cwd identity")
    _hex(prompt_sha256, "prompt")
    _hex(provider_stdout_contract_sha256, "provider stdout contract")
    if (
        type(timeout_seconds) is not int
        or not 1 <= timeout_seconds <= NATIVE_BACKEND_TIMEOUT_MAX_SECONDS
    ):
        _fail("TIMEOUT", "native backend timeout is outside policy bounds")
    if (
        type(stdout_limit_bytes) is not int
        or type(stderr_limit_bytes) is not int
        or stdout_limit_bytes != BACKEND_STDOUT_LIMIT_BYTES
        or stderr_limit_bytes != BACKEND_STDERR_LIMIT_BYTES
    ):
        _fail(
            "STREAM_LIMIT",
            "native backend stream limits differ from the exact shared policy",
        )
    if (
        type(model) is not str
        or not model
        or len(model.encode("utf-8")) > 128
        or "\x00" in model
    ):
        _fail("MODEL", "model is invalid")
    if (
        type(base_argv) not in {list, tuple}
        or not base_argv
        or len(base_argv) > 512
        or any(
            type(item) is not str
            or not item
            or "\x00" in item
            or len(item.encode("utf-8")) > 16 * 1024
            for item in base_argv
        )
        or sum(len(item.encode("utf-8")) for item in base_argv)
        > NATIVE_BACKEND_ENVELOPE_MAX_BYTES
    ):
        _fail("BASE_ARGV", "base argv is invalid or oversized")
    if (
        type(base_environment) is not dict
        or len(base_environment) > 256
        or any(
            type(name) is not str
            or not name
            or "\x00" in name
            or "=" in name
            or type(value) is not str
            or "\x00" in value
            for name, value in base_environment.items()
        )
        or sum(
            len(name.encode("utf-8")) + len(value.encode("utf-8"))
            for name, value in base_environment.items()
        ) > NATIVE_BACKEND_ENVELOPE_MAX_BYTES
    ):
        _fail("BASE_ENVIRONMENT", "base environment is invalid or oversized")

    if backend == "codex":
        schema = NATIVE_CODEX_REQUEST_SCHEMA
        backend_policy = {
            "schema": "plamen.posix_backend_execution.codex_policy.v2",
            "permission_profile_status": (
                _launch_policy.CODEX_PERMISSION_PROFILE_STATUS
            ),
            "config_census_contract": _CODEX_CONFIG_CENSUS_CONTRACT,
            "credential_delivery": _CODEX_CREDENTIAL_DELIVERY,
            "profile_delivery": _CODEX_PROFILE_DELIVERY,
            "ambient_configuration_forbidden": True,
        }
    else:
        schema = NATIVE_CLAUDE_REQUEST_SCHEMA
        backend_policy = {
            "schema": "plamen.posix_backend_execution.claude_policy.v2",
            "settings_contract": _launch_policy.CLAUDE_SETTINGS_CONTRACT,
            "permission_mode": "dontAsk",
            "credential_delivery": _CLAUDE_CREDENTIAL_DELIVERY,
            "profile_delivery": "NONE",
            "ambient_configuration_forbidden": True,
        }

    envelope = {
        "schema": schema,
        "native_execution_abi_schema": NATIVE_EXECUTION_ABI_SCHEMA,
        "native_broker_abi_schema": NATIVE_BROKER_ABI_SCHEMA,
        "native_broker_protocol_version": NATIVE_BROKER_PROTOCOL_VERSION,
        "attempt_id": attempt_id,
        "backend": backend,
        "model": model,
        "outer_attempt_arm_sha256": outer_attempt_arm_sha256,
        "work_plan_sha256": work_plan_sha256,
        "process_scope_identity": process_scope_identity,
        "base_argv_sha256": _argv_sha(tuple(base_argv)),
        "base_executable_argv0_sha256": _sha(base_argv[0].encode("utf-8")),
        "base_environment_sha256": _environment_sha(base_environment),
        "base_environment_names": sorted(base_environment),
        "cwd_identity_sha256": cwd_identity_sha256,
        "prompt_sha256": prompt_sha256,
        "provider_stdout_contract_sha256": provider_stdout_contract_sha256,
        "timeout_seconds": timeout_seconds,
        "backend_executable_contract": {
            "allowed_version": generation.resolved_version,
            "provenance": generation.provenance,
            "executable_sha256": generation.executable_sha256,
            "executable_size": generation.executable_size,
            "runtime_closure_sha256": generation.runtime_closure_sha256,
            "publisher_identity_sha256": generation.publisher_identity_sha256,
            "provenance_receipt_sha256": generation.provenance_receipt_sha256,
            "latest_resolution_receipt_sha256": (
                generation.latest_resolution_receipt_sha256
            ),
            "install_generation_id": generation.install_generation_id,
            "install_generation_sha256": generation.install_generation_sha256,
            "producer_receipt_sha256": generation.producer_receipt_sha256,
            "cli_behavior_contract_sha256": (
                generation.cli_behavior_contract_sha256
            ),
            "cli_conformance_sha256": generation.cli_conformance_sha256,
            "descriptor_purpose": _FD_BACKEND_EXECUTABLE,
            "content_sha256_required": True,
            "identity_sha256_required": True,
            "version_conformance_required": True,
        },
        "backend_policy": backend_policy,
        "fd_roster_contract": {
            "maximum_count": NATIVE_BROKER_MAX_FDS,
            "ordered_purpose_ids": _native_fd_purpose_order(backend),
            "exact_count_order_access_identity_required": True,
            "aliases_forbidden": True,
            "close_on_exec_default": True,
        },
        "stream_contract": {
            "stdout_requested_limit_bytes": stdout_limit_bytes,
            "stderr_requested_limit_bytes": stderr_limit_bytes,
            "stdout_effective_limit_bytes": min(
                stdout_limit_bytes, NATIVE_STREAM_OBSERVED_LIMIT_BYTES,
            ),
            "stderr_effective_limit_bytes": min(
                stderr_limit_bytes, NATIVE_STREAM_OBSERVED_LIMIT_BYTES,
            ),
            "stdout_observed_limit_bytes": NATIVE_STREAM_OBSERVED_LIMIT_BYTES,
            "stderr_observed_limit_bytes": NATIVE_STREAM_OBSERVED_LIMIT_BYTES,
            "stdout_retained_limit_bytes": NATIVE_STREAM_RETAINED_LIMIT_BYTES,
            "stderr_retained_limit_bytes": NATIVE_STREAM_RETAINED_LIMIT_BYTES,
            "read_chunk_max_bytes": NATIVE_OUTPUT_CHUNK_MAX_BYTES,
            "read_streams": ["stderr", "stdout"],
            "read_offset_bound": True,
            "read_recovery_replay_identical": True,
            "full_stream_sha256_required": True,
            "retained_stream_sha256_required": True,
            "overflow_disposition": "REVOKE_WITHOUT_COMPLETION",
        },
        "timeout_contract": {
            "timeout_seconds": timeout_seconds,
            "deadline_clock": "NATIVE_MONOTONIC",
            "deadline_recorded_at": "START",
            "timeout_disposition": "TERMINATE_REAP_DRAIN_AND_REVOKE",
            "python_clock_authority_forbidden": True,
        },
        "lifecycle_contract": {
            # These are the frozen wire operations required by guest execution.
            # The role itself is registered and checked out of band; it is not
            # passed to ``INITIAL_AUTHORITY.consume_once`` by Python.
            "initial_consume_exchange": [
                NATIVE_BROKER_AUTH_CONSUME,
                NATIVE_BROKER_AUTH_ACCEPTED,
            ],
            "role_selection": "NATIVE_REGISTRATION_ONLY",
            "prepare_exchange": [
                NATIVE_BROKER_BACKEND_PREPARE,
                NATIVE_BROKER_BACKEND_PREPARED,
            ],
            "start_exchange": [
                NATIVE_BROKER_START_PREPARE,
                NATIVE_BROKER_STARTED,
                NATIVE_BROKER_START_RECOVER,
            ],
            "wait_exchange": [
                NATIVE_BROKER_WAIT_PREPARE,
                NATIVE_BROKER_EXITED,
                NATIVE_BROKER_WAIT_RECOVER,
            ],
            "revoke_exchange": [
                NATIVE_BROKER_REVOKE_PREPARE,
                NATIVE_BROKER_REVOKED,
            ],
            "output_exchange": [
                NATIVE_BROKER_OUTPUT_READ,
                NATIVE_BROKER_OUTPUT_CHUNK,
            ],
            "close_exchange": [
                NATIVE_BROKER_OPERATION_CLOSE,
                NATIVE_BROKER_OPERATION_FINISHED,
            ],
            "durable_prepare_before_spawn": True,
            "durable_started_before_ack": True,
            "durable_exited_before_ack": True,
            "ack_loss_replays_without_effect": True,
            "output_reads_replay_without_effect": True,
            "process_tree_extinction_required": True,
            "credential_and_egress_revocation_required": True,
            "cli_prepare_forbidden_for_guest_backend_execution": True,
        },
    }
    raw = canonical_json_bytes(envelope)
    if not raw or len(raw) > NATIVE_BACKEND_ENVELOPE_MAX_BYTES:
        _fail("NATIVE_ENVELOPE_BOUNDS", "native request envelope is oversized")
    return raw


def _hex(value: object, label: str) -> str:
    if type(value) is not str or _HEX64_RE.fullmatch(value) is None:
        _fail("BINDING_DIGEST", f"{label} is not an exact sha256")
    return value


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or _ID_RE.fullmatch(value) is None:
        _fail("BINDING_ID", f"{label} is not a canonical identifier")
    return value


def _strict_json(raw: bytes, *, label: str) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > 1024 * 1024:
        _fail("RECEIPT_BOUNDS", f"{label} byte length is invalid")
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                _fail("RECEIPT_DUPLICATE_KEY", f"{label} has duplicate keys")
            result[key] = value
        return result

    def reject_constant(value: str) -> NoReturn:
        _fail("RECEIPT_CONSTANT", f"{label} has unsupported constant {value}")

    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=pairs,
            parse_constant=reject_constant,
        )
    except PosixBackendExecutionError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        _fail("RECEIPT_JSON", f"{label} is not strict JSON", exc)
    if type(value) is not dict or canonical_json_bytes(value) != raw:
        _fail("RECEIPT_CANONICAL", f"{label} is not canonical")
    return value


def _strict_operation_request(raw: bytes, *, label: str) -> dict[str, Any]:
    """Decode one exact native request without normalizing its wire bytes."""

    if type(raw) is not bytes or not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        _fail("NATIVE_REQUEST_CANONICAL", f"{label} lacks one exact trailing LF")
    return _strict_json(raw[:-1], label=label)


def _same_digest(left: str, right: str) -> bool:
    """Compare public commitment digests without data-dependent early exit."""

    return hmac.compare_digest(left.encode("ascii"), right.encode("ascii"))


def _exact_fields(
    value: Mapping[str, Any], fields: frozenset[str], *, label: str,
) -> None:
    if set(value) != fields:
        _fail("NATIVE_RECEIPT_FIELDS", f"{label} fields drifted")


def _uint(value: object, label: str, *, maximum: int | None = None) -> int:
    if type(value) is not int or value < 0 or (
        maximum is not None and value > maximum
    ):
        _fail("NATIVE_RECEIPT_INTEGER", f"{label} is outside its exact bounds")
    return value


def _required_true(value: object, label: str) -> None:
    if value is not True:
        _fail("NATIVE_RECEIPT_PROOF", f"{label} is not proven")


def _canonical_b64(value: object, label: str) -> bytes:
    if type(value) is not str:
        _fail("NATIVE_OUTPUT_ENCODING", f"{label} is not canonical base64")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeError, ValueError) as exc:
        _fail("NATIVE_OUTPUT_ENCODING", f"{label} is not canonical base64", exc)
    if base64.b64encode(raw).decode("ascii") != value:
        _fail("NATIVE_OUTPUT_ENCODING", f"{label} is not canonical base64")
    return raw


_PREPARE_REQUEST_FIELDS = frozenset({
    "schema", "operation_key_sha256", "execution_envelope_sha256",
    "execution_envelope", "timeout_seconds", "stdout_limit_bytes",
    "stderr_limit_bytes",
})
_PREPARED_RECEIPT_FIELDS = frozenset({
    "schema", "status", "operation_key_sha256", "prepare_request_sha256",
    "execution_envelope_sha256", "retained_fd_roster_sha256",
    "preparation_generation_sha256", "timeout_seconds",
    "stdout_requested_limit_bytes", "stderr_requested_limit_bytes",
    "stdout_effective_limit_bytes", "stderr_effective_limit_bytes",
})
_START_REQUEST_FIELDS = frozenset({
    "schema", "operation_key_sha256", "prepare_request_sha256",
    "prepared_receipt_sha256",
})
_PEER_IDENTITY_FIELDS = frozenset({
    "pid", "uid", "gid", "birth_kind", "birth_primary",
    "birth_secondary", "boot_id_sha256",
})
_PROCESS_IDENTITY_FIELDS = frozenset({
    "operation_key_sha256", "start_request_sha256",
    "executable_identity_sha256", "peer", "native_process_handle_sha256",
})
_STARTED_RECEIPT_FIELDS = frozenset({
    "schema", "status", "disposition", "operation_key_sha256",
    "start_request_sha256", "prepared_receipt_sha256", "process_identity",
    "process_identity_sha256",
})
_WAIT_REQUEST_FIELDS = frozenset({
    "schema", "operation_key_sha256", "start_request_sha256",
    "started_receipt_sha256",
})
_EXITED_RECEIPT_FIELDS = frozenset({
    "schema", "status", "disposition", "operation_key_sha256",
    "wait_request_sha256", "started_receipt_sha256",
    "process_identity_sha256", "exit_kind", "returncode", "signal",
    "stdout_size_bytes", "stdout_sha256", "stderr_size_bytes",
    "stderr_sha256", "overflowed_stream", "process_population_zero_proven",
    "credentials_revoked", "egress_revoked", "timed_out", "timeout_seconds",
    "stdout_requested_limit_bytes", "stderr_requested_limit_bytes",
    "stdout_effective_limit_bytes", "stderr_effective_limit_bytes",
})
_OUTPUT_REQUEST_FIELDS = frozenset({
    "schema", "operation_key_sha256", "exited_receipt_sha256", "stream",
    "offset", "max_bytes",
})
_OUTPUT_RECEIPT_FIELDS = frozenset({
    "schema", "status", "operation_key_sha256", "output_request_sha256",
    "exited_receipt_sha256", "stream", "offset", "length", "eof",
    "chunk_base64", "chunk_sha256", "full_stream_sha256",
})
_EXTINGUISH_REQUEST_FIELDS = frozenset({
    "schema", "operation_key_sha256", "prepared_receipt_sha256",
    "latest_lifecycle_receipt_sha256", "reason_code",
})
_REVOKED_RECEIPT_FIELDS = frozenset({
    "schema", "status", "disposition", "operation_key_sha256",
    "extinguish_request_sha256", "prepared_receipt_sha256",
    "latest_lifecycle_receipt_sha256", "process_identity_sha256",
    "reason_code", "process_population_zero_proven", "credentials_revoked",
    "egress_revoked", "output_retention_disposition",
})
_CLOSE_REQUEST_FIELDS = frozenset({
    "schema", "operation_key_sha256", "prepared_receipt_sha256",
    "terminal_receipt_sha256",
})
_FINISHED_RECEIPT_FIELDS = frozenset({
    "schema", "status", "disposition", "operation_key_sha256",
    "close_request_sha256", "terminal_receipt_sha256",
    "retained_descriptors_closed", "retained_output_closed",
})


@dataclass(frozen=True, slots=True)
class NativePreparedReceipt:
    operation_key_sha256: str
    prepare_request_sha256: str
    execution_envelope_sha256: str
    retained_fd_roster_sha256: str
    preparation_generation_sha256: str
    timeout_seconds: int
    stdout_requested_limit_bytes: int
    stderr_requested_limit_bytes: int
    stdout_effective_limit_bytes: int
    stderr_effective_limit_bytes: int
    raw: bytes = field(repr=False, compare=False)

    @property
    def sha256(self) -> str:
        return _sha(self.raw)


@dataclass(frozen=True, slots=True)
class NativeBackendProcessIdentity:
    operation_key_sha256: str
    start_request_sha256: str
    executable_identity_sha256: str
    pid: int
    uid: int
    gid: int
    birth_kind: int
    birth_primary: int
    birth_secondary: int
    boot_id_sha256: str
    native_process_handle_sha256: str
    sha256: str


@dataclass(frozen=True, slots=True)
class NativeStartedReceipt:
    operation_key_sha256: str
    start_request_sha256: str
    prepared_receipt_sha256: str
    disposition: str
    process_identity: NativeBackendProcessIdentity
    timeout_seconds: int
    stdout_requested_limit_bytes: int
    stderr_requested_limit_bytes: int
    stdout_effective_limit_bytes: int
    stderr_effective_limit_bytes: int
    raw: bytes = field(repr=False, compare=False)

    @property
    def sha256(self) -> str:
        return _sha(self.raw)


@dataclass(frozen=True, slots=True)
class NativeExitedReceipt:
    operation_key_sha256: str
    wait_request_sha256: str
    started_receipt_sha256: str
    process_identity_sha256: str
    disposition: str
    status: str
    exit_kind: str
    returncode: int | None
    signal: int | None
    stdout_size_bytes: int
    stdout_sha256: str
    stderr_size_bytes: int
    stderr_sha256: str
    overflowed_stream: str | None
    timed_out: bool
    timeout_seconds: int
    stdout_requested_limit_bytes: int
    stderr_requested_limit_bytes: int
    stdout_effective_limit_bytes: int
    stderr_effective_limit_bytes: int
    raw: bytes = field(repr=False, compare=False)

    @property
    def sha256(self) -> str:
        return _sha(self.raw)


@dataclass(frozen=True, slots=True)
class NativeOutputChunkReceipt:
    operation_key_sha256: str
    output_request_sha256: str
    exited_receipt_sha256: str
    stream: str
    offset: int
    length: int
    eof: bool
    chunk_sha256: str
    full_stream_sha256: str
    chunk: bytes = field(repr=False)
    raw: bytes = field(repr=False, compare=False)

    @property
    def sha256(self) -> str:
        return _sha(self.raw)


@dataclass(frozen=True, slots=True)
class NativeRevokedReceipt:
    operation_key_sha256: str
    extinguish_request_sha256: str
    prepared_receipt_sha256: str
    latest_lifecycle_receipt_sha256: str
    process_identity_sha256: str | None
    disposition: str
    reason_code: str
    raw: bytes = field(repr=False, compare=False)

    @property
    def sha256(self) -> str:
        return _sha(self.raw)


@dataclass(frozen=True, slots=True)
class NativeFinishedReceipt:
    operation_key_sha256: str
    close_request_sha256: str
    terminal_receipt_sha256: str
    disposition: str
    raw: bytes = field(repr=False, compare=False)

    @property
    def sha256(self) -> str:
        return _sha(self.raw)


def _operation_key(execution_envelope: bytes) -> str:
    """Return a non-authoritative semantic correlation key for one process.

    This JSON field is not the broker transport operation key.  Native code
    independently derives that hidden key from the authenticated common
    commitment, a native nonce, method/spec bindings, and its prior durable
    checkpoint.  The transport key is carried only by OPERATION_REQUEST and
    the authenticated frame nonce; Python neither receives nor mints it.
    """

    return _sha(
        b"plamen.posix_backend_execution.operation_key.v2\x00"
        + execution_envelope
    )


def _prepare_request(execution_envelope: bytes) -> tuple[bytes, str]:
    envelope = _strict_json(execution_envelope, label="execution envelope")
    operation_key = _operation_key(execution_envelope)
    value = {
        "schema": NATIVE_PREPARE_REQUEST_SCHEMA,
        "operation_key_sha256": operation_key,
        "execution_envelope_sha256": _sha(execution_envelope),
        "execution_envelope": envelope,
        "timeout_seconds": envelope.get("timeout_seconds"),
        "stdout_limit_bytes": envelope.get("stream_contract", {}).get(
            "stdout_requested_limit_bytes"
        ) if type(envelope.get("stream_contract")) is dict else None,
        "stderr_limit_bytes": envelope.get("stream_contract", {}).get(
            "stderr_requested_limit_bytes"
        ) if type(envelope.get("stream_contract")) is dict else None,
    }
    _uint(
        value["timeout_seconds"], "timeout seconds",
        maximum=NATIVE_BACKEND_TIMEOUT_MAX_SECONDS,
    )
    if value["timeout_seconds"] == 0:
        _fail("TIMEOUT", "native backend timeout must be positive")
    if (
        value["stdout_limit_bytes"] != BACKEND_STDOUT_LIMIT_BYTES
        or value["stderr_limit_bytes"] != BACKEND_STDERR_LIMIT_BYTES
    ):
        _fail("STREAM_LIMIT", "prepare request stream limits drifted")
    _exact_fields(value, _PREPARE_REQUEST_FIELDS, label="prepare request")
    return _canonical_operation_request_bytes(value), operation_key


def parse_native_prepared_receipt(
    raw: bytes, *, operation_key_sha256: str, prepare_request_sha256: str,
    execution_envelope_sha256: str,
    timeout_seconds: int, stdout_limit_bytes: int, stderr_limit_bytes: int,
) -> NativePreparedReceipt:
    expected_timeout = _uint(
        timeout_seconds, "timeout seconds",
        maximum=NATIVE_BACKEND_TIMEOUT_MAX_SECONDS,
    )
    if expected_timeout == 0:
        _fail("TIMEOUT", "native backend timeout must be positive")
    expected_stdout_limit = _uint(
        stdout_limit_bytes, "stdout limit",
        maximum=NATIVE_STREAM_OBSERVED_LIMIT_BYTES,
    )
    expected_stderr_limit = _uint(
        stderr_limit_bytes, "stderr limit",
        maximum=NATIVE_STREAM_OBSERVED_LIMIT_BYTES,
    )
    if (
        expected_stdout_limit != BACKEND_STDOUT_LIMIT_BYTES
        or expected_stderr_limit != BACKEND_STDERR_LIMIT_BYTES
    ):
        _fail("STREAM_LIMIT", "native backend stream limits differ from policy")
    value = _strict_json(raw, label="native PREPARED receipt")
    _exact_fields(value, _PREPARED_RECEIPT_FIELDS, label="PREPARED receipt")
    if value["schema"] != NATIVE_PREPARED_RECEIPT_SCHEMA or value["status"] != "PREPARED":
        _fail("NATIVE_PREPARED_RECEIPT", "PREPARED receipt schema/status drifted")
    for field_name, expected in (
        ("operation_key_sha256", operation_key_sha256),
        ("prepare_request_sha256", prepare_request_sha256),
        ("execution_envelope_sha256", execution_envelope_sha256),
    ):
        observed = _hex(value[field_name], field_name)
        _hex(expected, field_name)
        if not _same_digest(observed, expected):
            _fail("NATIVE_PREPARED_BINDING", f"{field_name} drifted")
    roster = _hex(value["retained_fd_roster_sha256"], "retained FD roster")
    generation = _hex(value["preparation_generation_sha256"], "preparation generation")
    if roster == _ZERO_SHA256 or generation == _ZERO_SHA256:
        _fail("NATIVE_PREPARED_BINDING", "native preparation binding is zero")
    expected_limits = (
        ("timeout_seconds", expected_timeout),
        ("stdout_requested_limit_bytes", expected_stdout_limit),
        ("stderr_requested_limit_bytes", expected_stderr_limit),
        ("stdout_effective_limit_bytes", min(
            expected_stdout_limit, NATIVE_STREAM_OBSERVED_LIMIT_BYTES,
        )),
        ("stderr_effective_limit_bytes", min(
            expected_stderr_limit, NATIVE_STREAM_OBSERVED_LIMIT_BYTES,
        )),
    )
    for field_name, expected in expected_limits:
        maximum = (
            NATIVE_BACKEND_TIMEOUT_MAX_SECONDS
            if field_name == "timeout_seconds"
            else NATIVE_STREAM_OBSERVED_LIMIT_BYTES
        )
        observed = _uint(value[field_name], field_name, maximum=maximum)
        if observed == 0 or observed != expected:
            _fail("NATIVE_PREPARED_LIMIT", f"{field_name} drifted")
    return NativePreparedReceipt(
        operation_key_sha256=operation_key_sha256,
        prepare_request_sha256=prepare_request_sha256,
        execution_envelope_sha256=execution_envelope_sha256,
        retained_fd_roster_sha256=roster,
        preparation_generation_sha256=generation,
        timeout_seconds=expected_timeout,
        stdout_requested_limit_bytes=expected_stdout_limit,
        stderr_requested_limit_bytes=expected_stderr_limit,
        stdout_effective_limit_bytes=expected_stdout_limit,
        stderr_effective_limit_bytes=expected_stderr_limit,
        raw=raw,
    )


def _start_request(prepared: NativePreparedReceipt) -> bytes:
    value = {
        "schema": NATIVE_START_REQUEST_SCHEMA,
        "operation_key_sha256": prepared.operation_key_sha256,
        "prepare_request_sha256": prepared.prepare_request_sha256,
        "prepared_receipt_sha256": prepared.sha256,
    }
    _exact_fields(value, _START_REQUEST_FIELDS, label="start request")
    return _canonical_operation_request_bytes(value)


def _parse_process_identity(
    value: object, *, operation_key_sha256: str, start_request_sha256: str,
    claimed_sha256: object,
) -> NativeBackendProcessIdentity:
    if type(value) is not dict:
        _fail("NATIVE_PROCESS_IDENTITY", "process identity is not an exact object")
    _exact_fields(value, _PROCESS_IDENTITY_FIELDS, label="process identity")
    for field_name, expected in (
        ("operation_key_sha256", operation_key_sha256),
        ("start_request_sha256", start_request_sha256),
    ):
        observed = _hex(value[field_name], field_name)
        if not _same_digest(observed, expected):
            _fail("NATIVE_PROCESS_IDENTITY", f"{field_name} drifted")
    executable = _hex(value["executable_identity_sha256"], "executable identity")
    handle = _hex(value["native_process_handle_sha256"], "native process handle")
    if executable == _ZERO_SHA256 or handle == _ZERO_SHA256:
        _fail("NATIVE_PROCESS_IDENTITY", "process identity contains a zero digest")
    peer = value["peer"]
    if type(peer) is not dict:
        _fail("NATIVE_PROCESS_IDENTITY", "peer identity is not an exact object")
    _exact_fields(peer, _PEER_IDENTITY_FIELDS, label="peer identity")
    pid = _uint(peer["pid"], "peer pid")
    uid = _uint(peer["uid"], "peer uid")
    gid = _uint(peer["gid"], "peer gid")
    birth_kind = _uint(peer["birth_kind"], "peer birth kind", maximum=2)
    birth_primary = _uint(peer["birth_primary"], "peer birth primary")
    birth_secondary = _uint(peer["birth_secondary"], "peer birth secondary")
    boot = _hex(peer["boot_id_sha256"], "peer boot id")
    if pid == 0 or birth_kind not in {1, 2} or birth_primary == 0:
        _fail("NATIVE_PROCESS_IDENTITY", "peer identity is incomplete")
    if birth_kind == 1 and boot != _ZERO_SHA256:
        _fail("NATIVE_PROCESS_IDENTITY", "Darwin peer unexpectedly binds a boot id")
    if birth_kind == 2 and (boot == _ZERO_SHA256 or birth_secondary == 0):
        _fail("NATIVE_PROCESS_IDENTITY", "Linux peer lacks boot/tick identity")
    digest = _hex(claimed_sha256, "process identity")
    calculated = _mapping_sha(value)
    if not _same_digest(digest, calculated):
        _fail("NATIVE_PROCESS_IDENTITY", "process identity digest drifted")
    return NativeBackendProcessIdentity(
        operation_key_sha256=operation_key_sha256,
        start_request_sha256=start_request_sha256,
        executable_identity_sha256=executable,
        pid=pid,
        uid=uid,
        gid=gid,
        birth_kind=birth_kind,
        birth_primary=birth_primary,
        birth_secondary=birth_secondary,
        boot_id_sha256=boot,
        native_process_handle_sha256=handle,
        sha256=digest,
    )


def parse_native_started_receipt(
    raw: bytes, *, prepared: NativePreparedReceipt,
    start_request_sha256: str,
) -> NativeStartedReceipt:
    value = _strict_json(raw, label="native STARTED receipt")
    _exact_fields(value, _STARTED_RECEIPT_FIELDS, label="STARTED receipt")
    if value["schema"] != NATIVE_STARTED_RECEIPT_SCHEMA or value["status"] != "STARTED":
        _fail("NATIVE_STARTED_RECEIPT", "STARTED receipt schema/status drifted")
    if value["disposition"] not in {"STARTED_NEW", "RECOVERED_EXISTING"}:
        _fail("NATIVE_STARTED_RECEIPT", "STARTED disposition is invalid")
    for field_name, expected in (
        ("operation_key_sha256", prepared.operation_key_sha256),
        ("start_request_sha256", start_request_sha256),
        ("prepared_receipt_sha256", prepared.sha256),
    ):
        observed = _hex(value[field_name], field_name)
        if not _same_digest(observed, expected):
            _fail("NATIVE_STARTED_BINDING", f"{field_name} drifted")
    process_identity = _parse_process_identity(
        value["process_identity"],
        operation_key_sha256=prepared.operation_key_sha256,
        start_request_sha256=start_request_sha256,
        claimed_sha256=value["process_identity_sha256"],
    )
    return NativeStartedReceipt(
        operation_key_sha256=prepared.operation_key_sha256,
        start_request_sha256=start_request_sha256,
        prepared_receipt_sha256=prepared.sha256,
        disposition=value["disposition"],
        process_identity=process_identity,
        timeout_seconds=prepared.timeout_seconds,
        stdout_requested_limit_bytes=prepared.stdout_requested_limit_bytes,
        stderr_requested_limit_bytes=prepared.stderr_requested_limit_bytes,
        stdout_effective_limit_bytes=prepared.stdout_effective_limit_bytes,
        stderr_effective_limit_bytes=prepared.stderr_effective_limit_bytes,
        raw=raw,
    )


def _wait_request(started: NativeStartedReceipt) -> bytes:
    value = {
        "schema": NATIVE_WAIT_REQUEST_SCHEMA,
        "operation_key_sha256": started.operation_key_sha256,
        "start_request_sha256": started.start_request_sha256,
        "started_receipt_sha256": started.sha256,
    }
    _exact_fields(value, _WAIT_REQUEST_FIELDS, label="wait request")
    return _canonical_operation_request_bytes(value)


def parse_native_exited_receipt(
    raw: bytes, *, started: NativeStartedReceipt, wait_request_sha256: str,
) -> NativeExitedReceipt:
    """Validate metadata-only EXITED evidence; output bytes use chunk reads."""

    value = _strict_json(raw, label="native EXITED receipt")
    _exact_fields(value, _EXITED_RECEIPT_FIELDS, label="EXITED receipt")
    status = value["status"]
    if value["schema"] != NATIVE_EXITED_RECEIPT_SCHEMA or status not in {
        "EXITED", "TIMED_OUT_REVOKED", "OUTPUT_OVERFLOW_REVOKED",
    }:
        _fail("NATIVE_EXITED_RECEIPT", "EXITED receipt schema/status drifted")
    if value["disposition"] not in {"OBSERVED_NEW", "RECOVERED_EXISTING"}:
        _fail("NATIVE_EXITED_RECEIPT", "EXITED disposition is invalid")
    for field_name, expected in (
        ("operation_key_sha256", started.operation_key_sha256),
        ("wait_request_sha256", wait_request_sha256),
        ("started_receipt_sha256", started.sha256),
        ("process_identity_sha256", started.process_identity.sha256),
    ):
        observed = _hex(value[field_name], field_name)
        if not _same_digest(observed, expected):
            _fail("NATIVE_EXITED_BINDING", f"{field_name} drifted")
    stdout_size = _uint(
        value["stdout_size_bytes"], "stdout size",
        maximum=NATIVE_STREAM_OBSERVED_LIMIT_BYTES + 1,
    )
    stderr_size = _uint(
        value["stderr_size_bytes"], "stderr size",
        maximum=NATIVE_STREAM_OBSERVED_LIMIT_BYTES + 1,
    )
    stdout_sha = _hex(value["stdout_sha256"], "stdout")
    stderr_sha = _hex(value["stderr_sha256"], "stderr")
    for field_name, expected in (
        ("timeout_seconds", started.timeout_seconds),
        ("stdout_requested_limit_bytes", started.stdout_requested_limit_bytes),
        ("stderr_requested_limit_bytes", started.stderr_requested_limit_bytes),
        ("stdout_effective_limit_bytes", started.stdout_effective_limit_bytes),
        ("stderr_effective_limit_bytes", started.stderr_effective_limit_bytes),
    ):
        maximum = (
            NATIVE_BACKEND_TIMEOUT_MAX_SECONDS
            if field_name == "timeout_seconds"
            else NATIVE_STREAM_OBSERVED_LIMIT_BYTES
        )
        observed = _uint(value[field_name], field_name, maximum=maximum)
        if observed == 0 or observed != expected:
            _fail("NATIVE_EXITED_LIMIT", f"{field_name} drifted")
    exit_kind = value["exit_kind"]
    returncode = value["returncode"]
    signal_number = value["signal"]
    overflowed_stream = value["overflowed_stream"]
    timed_out = value["timed_out"]
    if type(timed_out) is not bool:
        _fail("NATIVE_EXIT_SEMANTICS", "timed_out is not an exact boolean")
    if exit_kind == "EXIT_CODE":
        _uint(returncode, "return code", maximum=255)
        valid_exit = (
            signal_number is None and overflowed_stream is None
            and timed_out is False and status == "EXITED"
        )
    elif exit_kind == "SIGNAL":
        _uint(signal_number, "exit signal", maximum=255)
        valid_exit = (
            signal_number != 0 and returncode is None
            and overflowed_stream is None and timed_out is False
            and status == "EXITED"
        )
    elif exit_kind == "TIMEOUT":
        valid_exit = (
            returncode is None and signal_number is None
            and overflowed_stream is None and timed_out is True
            and status == "TIMED_OUT_REVOKED"
        )
    elif exit_kind == "OUTPUT_OVERFLOW":
        valid_exit = (
            returncode is None
            and signal_number is None
            and overflowed_stream in _STREAM_NAMES
            and timed_out is False
            and status == "OUTPUT_OVERFLOW_REVOKED"
            and (
                (
                    overflowed_stream == "stdout"
                    and stdout_size == started.stdout_effective_limit_bytes + 1
                )
                or (
                    overflowed_stream == "stderr"
                    and stderr_size == started.stderr_effective_limit_bytes + 1
                )
            )
        )
    else:
        valid_exit = False
    if not valid_exit:
        _fail("NATIVE_EXIT_SEMANTICS", "exit and overflow metadata conflict")
    if status == "OUTPUT_OVERFLOW_REVOKED":
        other_stream_oversized = (
            overflowed_stream == "stdout"
            and stderr_size > started.stderr_effective_limit_bytes
        ) or (
            overflowed_stream == "stderr"
            and stdout_size > started.stdout_effective_limit_bytes
        )
        if other_stream_oversized:
            _fail(
                "NATIVE_OUTPUT_OVERFLOW",
                "non-overflow stream exceeded its effective limit",
            )
    elif (
        stdout_size > started.stdout_effective_limit_bytes
        or stderr_size > started.stderr_effective_limit_bytes
    ):
        _fail("NATIVE_OUTPUT_OVERFLOW", "oversized output was not terminally revoked")
    for proof in (
        "process_population_zero_proven", "credentials_revoked", "egress_revoked",
    ):
        _required_true(value[proof], proof)
    return NativeExitedReceipt(
        operation_key_sha256=started.operation_key_sha256,
        wait_request_sha256=wait_request_sha256,
        started_receipt_sha256=started.sha256,
        process_identity_sha256=started.process_identity.sha256,
        disposition=value["disposition"],
        status=status,
        exit_kind=exit_kind,
        returncode=returncode,
        signal=signal_number,
        stdout_size_bytes=stdout_size,
        stdout_sha256=stdout_sha,
        stderr_size_bytes=stderr_size,
        stderr_sha256=stderr_sha,
        overflowed_stream=overflowed_stream,
        timed_out=timed_out,
        timeout_seconds=started.timeout_seconds,
        stdout_requested_limit_bytes=started.stdout_requested_limit_bytes,
        stderr_requested_limit_bytes=started.stderr_requested_limit_bytes,
        stdout_effective_limit_bytes=started.stdout_effective_limit_bytes,
        stderr_effective_limit_bytes=started.stderr_effective_limit_bytes,
        raw=raw,
    )


def _output_request(
    exited: NativeExitedReceipt, *, stream: str, offset: int, max_bytes: int,
) -> bytes:
    if type(stream) is not str or stream not in _STREAM_NAMES:
        _fail("NATIVE_OUTPUT_STREAM", "output stream must be stdout or stderr")
    size = (
        exited.stdout_size_bytes if stream == "stdout" else exited.stderr_size_bytes
    )
    _uint(offset, "output offset", maximum=size)
    if type(max_bytes) is not int or not (1 <= max_bytes <= NATIVE_OUTPUT_CHUNK_MAX_BYTES):
        _fail("NATIVE_OUTPUT_CHUNK", "output chunk request is outside bounds")
    value = {
        "schema": NATIVE_OUTPUT_REQUEST_SCHEMA,
        "operation_key_sha256": exited.operation_key_sha256,
        "exited_receipt_sha256": exited.sha256,
        "stream": stream,
        "offset": offset,
        "max_bytes": max_bytes,
    }
    _exact_fields(value, _OUTPUT_REQUEST_FIELDS, label="output request")
    return _canonical_operation_request_bytes(value)


def parse_native_output_receipt(
    raw: bytes, *, exited: NativeExitedReceipt, output_request: bytes,
) -> NativeOutputChunkReceipt:
    request = _strict_operation_request(
        output_request, label="native output request"
    )
    _exact_fields(request, _OUTPUT_REQUEST_FIELDS, label="output request")
    if request["schema"] != NATIVE_OUTPUT_REQUEST_SCHEMA:
        _fail("NATIVE_OUTPUT_REQUEST", "output request schema drifted")
    for field_name, expected in (
        ("operation_key_sha256", exited.operation_key_sha256),
        ("exited_receipt_sha256", exited.sha256),
    ):
        observed = _hex(request[field_name], field_name)
        if not _same_digest(observed, expected):
            _fail("NATIVE_OUTPUT_REQUEST", f"{field_name} drifted")
    if request["stream"] not in _STREAM_NAMES:
        _fail("NATIVE_OUTPUT_REQUEST", "output stream is invalid")
    request_stream_size = (
        exited.stdout_size_bytes
        if request["stream"] == "stdout"
        else exited.stderr_size_bytes
    )
    _uint(request["offset"], "output offset", maximum=request_stream_size)
    request_max = _uint(
        request["max_bytes"], "output max bytes",
        maximum=NATIVE_OUTPUT_CHUNK_MAX_BYTES,
    )
    if request_max == 0:
        _fail("NATIVE_OUTPUT_REQUEST", "output max bytes must be positive")
    value = _strict_json(raw, label="native output receipt")
    _exact_fields(value, _OUTPUT_RECEIPT_FIELDS, label="output receipt")
    if value["schema"] != NATIVE_OUTPUT_RECEIPT_SCHEMA or value["status"] != "OUTPUT_CHUNK":
        _fail("NATIVE_OUTPUT_RECEIPT", "output receipt schema/status drifted")
    expected_bindings = (
        ("operation_key_sha256", exited.operation_key_sha256),
        ("output_request_sha256", _sha(output_request)),
        ("exited_receipt_sha256", exited.sha256),
    )
    for field_name, expected in expected_bindings:
        observed = _hex(value[field_name], field_name)
        if not _same_digest(observed, expected):
            _fail("NATIVE_OUTPUT_BINDING", f"{field_name} drifted")
    if value["stream"] != request["stream"]:
        _fail("NATIVE_OUTPUT_BINDING", "output stream drifted")
    offset = _uint(value["offset"], "output offset")
    length = _uint(
        value["length"], "output length", maximum=NATIVE_OUTPUT_CHUNK_MAX_BYTES,
    )
    if offset != request["offset"] or length > request["max_bytes"]:
        _fail("NATIVE_OUTPUT_BINDING", "output range drifted")
    chunk = _canonical_b64(value["chunk_base64"], "output chunk")
    if len(chunk) != length:
        _fail("NATIVE_OUTPUT_LENGTH", "decoded output length drifted")
    chunk_sha = _hex(value["chunk_sha256"], "output chunk")
    if not _same_digest(chunk_sha, _sha(chunk)):
        _fail("NATIVE_OUTPUT_DIGEST", "output chunk digest drifted")
    stream = value["stream"]
    stream_size = (
        exited.stdout_size_bytes if stream == "stdout" else exited.stderr_size_bytes
    )
    full_sha = exited.stdout_sha256 if stream == "stdout" else exited.stderr_sha256
    claimed_full_sha = _hex(value["full_stream_sha256"], "full output stream")
    if offset + length > stream_size or not _same_digest(claimed_full_sha, full_sha):
        _fail("NATIVE_OUTPUT_BINDING", "full output binding drifted")
    if type(value["eof"]) is not bool or value["eof"] is not (offset + length == stream_size):
        _fail("NATIVE_OUTPUT_EOF", "output EOF marker drifted")
    return NativeOutputChunkReceipt(
        operation_key_sha256=exited.operation_key_sha256,
        output_request_sha256=_sha(output_request),
        exited_receipt_sha256=exited.sha256,
        stream=stream,
        offset=offset,
        length=length,
        eof=value["eof"],
        chunk_sha256=chunk_sha,
        full_stream_sha256=claimed_full_sha,
        chunk=chunk,
        raw=raw,
    )


def _extinguish_request(
    prepared: NativePreparedReceipt, *, latest_lifecycle_receipt_sha256: str,
    reason_code: str,
) -> bytes:
    _hex(latest_lifecycle_receipt_sha256, "latest lifecycle receipt")
    _identifier(reason_code, "extinguish reason")
    value = {
        "schema": NATIVE_EXTINGUISH_REQUEST_SCHEMA,
        "operation_key_sha256": prepared.operation_key_sha256,
        "prepared_receipt_sha256": prepared.sha256,
        "latest_lifecycle_receipt_sha256": latest_lifecycle_receipt_sha256,
        "reason_code": reason_code,
    }
    _exact_fields(value, _EXTINGUISH_REQUEST_FIELDS, label="extinguish request")
    return _canonical_operation_request_bytes(value)


def parse_native_revoked_receipt(
    raw: bytes, *, prepared: NativePreparedReceipt,
    extinguish_request: bytes, expected_process_identity_sha256: str | None,
) -> NativeRevokedReceipt:
    request = _strict_operation_request(
        extinguish_request, label="native extinguish request"
    )
    _exact_fields(request, _EXTINGUISH_REQUEST_FIELDS, label="extinguish request")
    if request["schema"] != NATIVE_EXTINGUISH_REQUEST_SCHEMA:
        _fail("NATIVE_EXTINGUISH_REQUEST", "extinguish request schema drifted")
    for field_name, expected in (
        ("operation_key_sha256", prepared.operation_key_sha256),
        ("prepared_receipt_sha256", prepared.sha256),
    ):
        observed = _hex(request[field_name], field_name)
        if not _same_digest(observed, expected):
            _fail("NATIVE_EXTINGUISH_REQUEST", f"{field_name} drifted")
    _hex(request["latest_lifecycle_receipt_sha256"], "latest lifecycle receipt")
    _identifier(request["reason_code"], "extinguish reason")
    value = _strict_json(raw, label="native REVOKED receipt")
    _exact_fields(value, _REVOKED_RECEIPT_FIELDS, label="REVOKED receipt")
    if value["schema"] != NATIVE_REVOKED_RECEIPT_SCHEMA or value["status"] != "REVOKED":
        _fail("NATIVE_REVOKED_RECEIPT", "REVOKED receipt schema/status drifted")
    if value["disposition"] not in {"REVOKED_NEW", "RECOVERED_EXISTING"}:
        _fail("NATIVE_REVOKED_RECEIPT", "REVOKED disposition is invalid")
    for field_name, expected in (
        ("operation_key_sha256", prepared.operation_key_sha256),
        ("extinguish_request_sha256", _sha(extinguish_request)),
        ("prepared_receipt_sha256", prepared.sha256),
        ("latest_lifecycle_receipt_sha256", request["latest_lifecycle_receipt_sha256"]),
    ):
        observed = _hex(value[field_name], field_name)
        if not _same_digest(observed, expected):
            _fail("NATIVE_REVOKED_BINDING", f"{field_name} drifted")
    if value["reason_code"] != request["reason_code"]:
        _fail("NATIVE_REVOKED_BINDING", "extinguish reason drifted")
    process_identity = value["process_identity_sha256"]
    if expected_process_identity_sha256 is None:
        if process_identity is not None:
            _fail("NATIVE_REVOKED_BINDING", "unstarted operation gained a process identity")
    else:
        process_identity = _hex(process_identity, "process identity")
        if not _same_digest(process_identity, expected_process_identity_sha256):
            _fail("NATIVE_REVOKED_BINDING", "process identity drifted")
    for proof in (
        "process_population_zero_proven", "credentials_revoked", "egress_revoked",
    ):
        _required_true(value[proof], proof)
    if value["output_retention_disposition"] != "DISCARDED":
        _fail("NATIVE_REVOKED_RECEIPT", "revoked output was not discarded")
    return NativeRevokedReceipt(
        operation_key_sha256=prepared.operation_key_sha256,
        extinguish_request_sha256=_sha(extinguish_request),
        prepared_receipt_sha256=prepared.sha256,
        latest_lifecycle_receipt_sha256=request["latest_lifecycle_receipt_sha256"],
        process_identity_sha256=process_identity,
        disposition=value["disposition"],
        reason_code=request["reason_code"],
        raw=raw,
    )


def _close_request(
    prepared: NativePreparedReceipt, *, terminal_receipt_sha256: str,
) -> bytes:
    _hex(terminal_receipt_sha256, "terminal receipt")
    value = {
        "schema": NATIVE_CLOSE_REQUEST_SCHEMA,
        "operation_key_sha256": prepared.operation_key_sha256,
        "prepared_receipt_sha256": prepared.sha256,
        "terminal_receipt_sha256": terminal_receipt_sha256,
    }
    _exact_fields(value, _CLOSE_REQUEST_FIELDS, label="close request")
    return _canonical_operation_request_bytes(value)


def parse_native_finished_receipt(
    raw: bytes, *, prepared: NativePreparedReceipt, close_request: bytes,
) -> NativeFinishedReceipt:
    request = _strict_operation_request(
        close_request, label="native close request"
    )
    _exact_fields(request, _CLOSE_REQUEST_FIELDS, label="close request")
    if request["schema"] != NATIVE_CLOSE_REQUEST_SCHEMA:
        _fail("NATIVE_CLOSE_REQUEST", "close request schema drifted")
    for field_name, expected in (
        ("operation_key_sha256", prepared.operation_key_sha256),
        ("prepared_receipt_sha256", prepared.sha256),
    ):
        observed = _hex(request[field_name], field_name)
        if not _same_digest(observed, expected):
            _fail("NATIVE_CLOSE_REQUEST", f"{field_name} drifted")
    _hex(request["terminal_receipt_sha256"], "terminal receipt")
    value = _strict_json(raw, label="native FINISHED receipt")
    _exact_fields(value, _FINISHED_RECEIPT_FIELDS, label="FINISHED receipt")
    if value["schema"] != NATIVE_FINISHED_RECEIPT_SCHEMA or value["status"] != "FINISHED":
        _fail("NATIVE_FINISHED_RECEIPT", "FINISHED receipt schema/status drifted")
    if value["disposition"] not in {"FINISHED_NEW", "RECOVERED_EXISTING"}:
        _fail("NATIVE_FINISHED_RECEIPT", "FINISHED disposition is invalid")
    for field_name, expected in (
        ("operation_key_sha256", prepared.operation_key_sha256),
        ("close_request_sha256", _sha(close_request)),
        ("terminal_receipt_sha256", request["terminal_receipt_sha256"]),
    ):
        observed = _hex(value[field_name], field_name)
        if not _same_digest(observed, expected):
            _fail("NATIVE_FINISHED_BINDING", f"{field_name} drifted")
    _required_true(value["retained_descriptors_closed"], "retained descriptor closure")
    _required_true(value["retained_output_closed"], "retained output closure")
    return NativeFinishedReceipt(
        operation_key_sha256=prepared.operation_key_sha256,
        close_request_sha256=_sha(close_request),
        terminal_receipt_sha256=request["terminal_receipt_sha256"],
        disposition=value["disposition"],
        raw=raw,
    )


def _fd_binding(fd: int, label: str) -> dict[str, Any]:
    try:
        item = os.fstat(fd)
    except OSError as exc:
        _fail("FD_STAT", f"{label} descriptor is unavailable", exc)
    return {
        "label": label,
        "device": int(item.st_dev),
        "inode": int(item.st_ino),
        "mode": int(item.st_mode),
        "links": int(item.st_nlink),
        "owner": int(item.st_uid),
        "group": int(item.st_gid),
        "size": int(item.st_size),
        "mtime_ns": int(item.st_mtime_ns),
        "ctime_ns": int(item.st_ctime_ns),
    }


class TestOnlyOuterSupervisorConsumer(Protocol):
    """Structural-test consumer; never a production authority.

    Materialization and revocation form one recoverable transaction.  For a
    Codex invocation the materializer must consume the invocation's exact
    ``codex_config_census_contract_bytes()`` and keep that private-home/config
    scope immutable until execve.  A materializer that raises must retain
    enough attempt-bound state for the immediately following revocation call
    to prove that no private state remains, even when no materialization
    receipt was returned.
    """

    def consume_posix_backend_launch(
        self, request: Mapping[str, Any], *, prompt_fd: int,
    ) -> tuple[TestOnlyBackendLaunchPlan, bytes]: ...

    def materialize_posix_backend_launch(
        self, invocation: TestOnlyBackendLaunchInvocation,
        binding: Mapping[str, Any],
    ) -> tuple[Mapping[str, str], bytes]: ...

    def revoke_posix_backend_launch(
        self, materialization_receipt: bytes, binding: Mapping[str, Any],
    ) -> bytes: ...


class TestOnlyOuterReceiptVerifier(Protocol):
    """Structural-test verifier for the stage-specific recheck contract.

    In particular, ``PRE_CREATE`` must freshly prove the Codex private-home and
    control-ancestor config census immediately before process creation; merely
    replaying the earlier receipt is not a valid implementation.
    """

    def verify_posix_backend_receipt(
        self, stage: str, receipt: bytes, expected: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...


def _admitted_native_supervisor_module() -> Any | None:
    """Admit only the production extension and its pre-issued static object.

    Import and static-type validation happen before any caller-supplied launch
    value is touched.  The native launcher/service registration is the
    authority for ``INITIAL_AUTHORITY``; an importable extension without that
    object is deliberately indistinguishable from no production context.
    """

    try:
        module = importlib.import_module(_NATIVE_MODULE_NAME)
        spec = module.__spec__
        loader = getattr(spec, "loader", None)
        origin = getattr(spec, "origin", None)
        consumer_type = module.NativeAuthorityConsumer
        initial = module.INITIAL_AUTHORITY
        required_types = (
            consumer_type,
            module.SupervisorAuthorities,
            module.GuestDriverAuthorities,
            module.RuntimeImageAuthority,
            module.WorkspaceAuthority,
            module.BackendContextAuthority,
            module.ProviderAuthority,
            module.GuestAdmissionAuthority,
            module.ExtinctionAuthority,
            module.ArtifactAuthority,
            module.ExportAuthority,
            module.JournalAuthority,
            module.RecoveryAuthority,
            module.SupervisorAuthority,
            module.ProcessReceiptProjection,
            module.ExitReceiptProjection,
            module.NetworkReceiptProjection,
            module.BackendExecutionAuthority,
            module.BackendInstallGenerationAuthority,
            module.DarwinToolCustodyAuthority,
            module.DarwinToolExecutionLease,
            module.DarwinToolExecutionTerminal,
            module.JSDependencyMaterializerAuthority,
            module.JSDependencyMaterializerSessionLease,
            module.JSDependencyMaterializerExecutionLease,
            module.JSDependencyMaterializerTerminalReplayLease,
            module.ManagedEVMToolchainInitialAuthority,
            module.ManagedEVMToolchainProvisionLease,
            module.ManagedEVMToolchainProvisionTerminal,
        )
        admitted = (
            type(module) is types.ModuleType
            and spec is not None
            and type(loader) is importlib.machinery.ExtensionFileLoader
            and getattr(loader, "name", None) == _NATIVE_MODULE_NAME
            and type(origin) is str
            and any(
                origin.endswith(suffix)
                for suffix in importlib.machinery.EXTENSION_SUFFIXES
            )
            and getattr(module, "__file__", None) == origin
            and module.TEST_ONLY_BUILD is False
            and module.BrokerV2AuthorityConsumer is consumer_type
            and module.BROKER_V2_ABI_SCHEMA == NATIVE_BROKER_ABI_SCHEMA
            and module.BROKER_V2_PROTOCOL_VERSION
            == NATIVE_BROKER_PROTOCOL_VERSION
            and module.BROKER_V2_FRAME_HEADER_SIZE
            == NATIVE_BROKER_FRAME_HEADER_SIZE
            and module.BROKER_V2_AUTH_OFFSET == NATIVE_BROKER_AUTH_OFFSET
            and module.BROKER_V2_MAX_FRAME_PAYLOAD_BYTES
            == NATIVE_BROKER_MAX_PAYLOAD_BYTES
            and module.BROKER_V2_MAX_SCM_RIGHTS_FDS == NATIVE_BROKER_MAX_FDS
            and module.BROKER_V2_INITIAL_AUTHORITY_AVAILABLE is True
            and module.BROKER_V2_PRODUCTION_ACQUISITION
            == _NATIVE_PRODUCTION_ACQUISITION
            and module.BROKER_V2_OPERATION_DISPATCH
            == _NATIVE_OPERATION_DISPATCH
            and all(
                type(native_type) is type
                and native_type.__module__ == _NATIVE_MODULE_NAME
                and native_type.__flags__ & (1 << 9) == 0
                and native_type.__flags__ & (1 << 10) == 0
                for native_type in required_types
            )
            and type(consumer_type.__dict__.get("consume_once"))
            is types.MethodDescriptorType
            and type(consumer_type.__dict__.get("request_projection"))
            is types.MethodDescriptorType
            and type(
                module.GuestDriverAuthorities.__dict__.get("consume_once")
            ) is types.MethodDescriptorType
            and "consume_once" not in module.BackendExecutionAuthority.__dict__
            and all(
                type(module.BackendExecutionAuthority.__dict__.get(name))
                is types.MethodDescriptorType
                for name in _NATIVE_BACKEND_METHODS
            )
            and all(
                type(getattr(module, name, None)) is types.BuiltinFunctionType
                and getattr(getattr(module, name, None), "__module__", None)
                == _NATIVE_MODULE_NAME
                and getattr(getattr(module, name, None), "__name__", None)
                == name
                for name in (
                    "acquire_backend_install_generation",
                    "project_backend_install_generation",
                    "darwin_tool_runtime_identity",
                    "acquire_darwin_tool_custody",
                    "prepare_darwin_tool_execution",
                    "execute_darwin_tool",
                    "project_darwin_tool_execution_terminal",
                    "js_dependency_materializer_runtime_identity",
                    "authenticate_js_dependency_materializer_capability",
                    "prepare_js_dependency_materializer_execution",
                    "execute_js_dependency_materializer",
                    "replay_js_dependency_materializer_terminal",
                    "managed_evm_toolchain_runtime_identity",
                    "prepare_managed_evm_toolchain_provision",
                    "execute_managed_evm_toolchain_provision",
                    "project_managed_evm_toolchain_terminal",
                )
            )
            and type(initial) is consumer_type
            and type(module.JS_DEPENDENCY_MATERIALIZER_INITIAL_AUTHORITY)
            is module.JSDependencyMaterializerAuthority
            and type(module.MANAGED_EVM_TOOLCHAIN_INITIAL_AUTHORITY)
            is module.ManagedEVMToolchainInitialAuthority
        )
    except BaseException:
        return None
    return module if admitted else None


def _require_native_backend_authority_before_request(value: object) -> Any:
    """Admit one exact static role-2 authority before request inspection."""

    module = _admitted_native_supervisor_module()
    if module is None:
        _fail(
            "NATIVE_BRIDGE_UNAVAILABLE",
            "authenticated native broker v2 INITIAL_AUTHORITY is unavailable",
        )
    native_type = module.BackendExecutionAuthority
    if type(value) is not native_type:
        _fail(
            "NATIVE_BACKEND_AUTHORITY",
            "backend authority is not the exact static native role-2 type",
        )
    return value


def _require_native_guest_backend_role_before_request() -> NoReturn:
    """Gate guest backend work before observing a Python launch request.

    Broker v2 freezes guest-driver role 2 and the AUTH_CONSUME exchange.  The
    role is registered and authenticated entirely in native code; Python must
    never select it.  This no-argument gate remains only for WER's obsolete
    Python/Popen launch path; the operation-keyed role-2 adapter does not use
    it.
    """

    if _admitted_native_supervisor_module() is None:
        _fail(
            "NATIVE_BRIDGE_UNAVAILABLE",
            "authenticated native broker v2 INITIAL_AUTHORITY is unavailable",
        )
    _fail(
        "WER_NATIVE_CUSTODY_REQUIRED",
        "legacy Python/Popen execution must migrate to native role-3 custody",
    )


def require_native_posix_backend_execution(
    value: object,
) -> "PosixBackendExecution":
    """Admit one native-backed WER wrapper before inspecting launch values.

    Module/static-type admission is deliberately performed before even taking
    ``type(value)``.  An exact Python wrapper is insufficient on its own: its
    private authority must be the extension's static role-2 type, preventing an
    ``object.__new__`` shell from crossing the first-effect boundary.
    """

    module = _admitted_native_supervisor_module()
    if module is None:
        _fail(
            "NATIVE_BRIDGE_UNAVAILABLE",
            "authenticated native broker v2 INITIAL_AUTHORITY is unavailable",
        )
    if type(value) is not PosixBackendExecution:
        _fail(
            "NATIVE_BACKEND_AUTHORITY",
            "WER requires the exact native-backed POSIX operation wrapper",
        )
    try:
        native = object.__getattribute__(
            value, "_PosixBackendExecution__native_authority",
        )
        prepared = object.__getattribute__(
            value, "_PosixBackendExecution__prepared",
        )
        wer_binding = object.__getattribute__(
            value, "_PosixBackendExecution__wer_binding",
        )
    except BaseException as exc:
        _fail(
            "NATIVE_BACKEND_AUTHORITY",
            "WER POSIX operation wrapper is incomplete",
            exc,
        )
    if (
        type(native) is not module.BackendExecutionAuthority
        or type(prepared) is not NativePreparedReceipt
        or type(wer_binding) is not bytes
    ):
        _fail(
            "NATIVE_BACKEND_AUTHORITY",
            "WER POSIX operation wrapper is not native-backed",
        )
    return value


def require_native_backend_execution_authority(value: object) -> Any:
    """Return one exact service-issued role-2 authority or fail closed.

    This small public admission hook lets the guest driver retain the native
    object in a non-serializable runtime slot without duplicating extension
    provenance or exact-static-type checks.  Native module admission remains
    the first effect; ``value`` is not inspected by Python before that gate.
    """

    return _require_native_backend_authority_before_request(value)


class NativeGuestRuntimeAuthorities:
    """Opaque process-local role-2 backend and snapshot-tool authority pair.

    Instances are issued only after one exact native guest ``INITIAL_AUTHORITY``
    has yielded both its independently retained snapshot-tool custody and its
    backend-execution member.  The Python object is merely an unforgeable-live
    registry key: the two static native capabilities remain private and are
    never serialized, copied, placed in an environment, or projected into the
    audit configuration.
    """

    __slots__ = ("__token", "__weakref__")

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("native guest runtime authorities are native-issued")

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("native guest runtime authorities are immutable")

    def __copy__(self) -> NoReturn:
        raise TypeError("native guest runtime authorities cannot be copied")

    def __deepcopy__(self, _memo: Any) -> NoReturn:
        raise TypeError("native guest runtime authorities cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("native guest runtime authorities cannot be serialized")

    def __repr__(self) -> str:
        return "<NativeGuestRuntimeAuthorities opaque>"


@dataclass(frozen=True, slots=True)
class _NativeGuestRuntimeRecord:
    module: Any = field(repr=False, compare=False)
    initial: Any = field(repr=False, compare=False)
    request: Any = field(repr=False, compare=False)
    backend_execution: Any = field(repr=False, compare=False)
    backend_install_generation: Any = field(repr=False, compare=False)
    tool_custody: Any = field(repr=False, compare=False)
    tool_runtime_identity: bytes = field(repr=False, compare=False)
    js_initial: Any = field(repr=False, compare=False)
    js_runtime_identity: bytes = field(repr=False, compare=False)
    managed_initial: Any = field(repr=False, compare=False)
    managed_runtime_identity: bytes = field(repr=False, compare=False)
    creator_pid: int
    request_fingerprint_sha256: str
    attempt_id: str
    run_id: str
    backend: str


_NATIVE_GUEST_RUNTIME_LOCK = threading.RLock()
_LIVE_NATIVE_GUEST_RUNTIME_AUTHORITIES: weakref.WeakKeyDictionary[
    NativeGuestRuntimeAuthorities, _NativeGuestRuntimeRecord
] = weakref.WeakKeyDictionary()
_LIVE_NATIVE_GUEST_BACKEND_INSTALL_GENERATIONS: weakref.WeakKeyDictionary[
    NativeGuestRuntimeAuthorities, object
] = weakref.WeakKeyDictionary()
_LIVE_NATIVE_GUEST_MANAGED_LEASES: dict[int, tuple[object, object]] = {}
_LIVE_NATIVE_GUEST_MANAGED_TERMINALS: dict[int, tuple[object, object]] = {}
_LIVE_NATIVE_GUEST_JS_SESSIONS: dict[int, tuple[object, object]] = {}
_LIVE_NATIVE_GUEST_JS_EXECUTIONS: dict[int, tuple[object, object, object]] = {}
_LIVE_NATIVE_GUEST_EVM_PROJECTIONS: dict[int, tuple[object, object]] = {}


def _validate_native_tool_runtime_identity(raw: object) -> bytes:
    if type(raw) is not bytes or not raw or len(raw) > 1024 * 1024:
        _fail(
            "NATIVE_TOOL_RUNTIME_IDENTITY",
            "native snapshot-tool runtime identity is unavailable",
        )
    value = _strict_json(raw, label="native snapshot-tool runtime identity")
    expected = {
        "schema", "platform", "extension_path", "extension_sha256",
        "extension_byte_count", "native_deployment_receipt_sha256",
        "runtime_closure_sha256", "broker_peer_identity_sha256",
    }
    if (
        set(value) != expected
        or value.get("schema") != "plamen.darwin-tool-runtime-identity.v1"
        or value.get("platform") not in {"MACOS", "LINUX"}
        or type(value.get("extension_path")) is not str
        or not value["extension_path"].startswith("/")
        or "\x00" in value["extension_path"]
        or type(value.get("extension_byte_count")) is not int
        or not 1 <= value["extension_byte_count"] <= 512 * 1024 * 1024
    ):
        _fail(
            "NATIVE_TOOL_RUNTIME_IDENTITY",
            "native snapshot-tool runtime identity differs",
        )
    for name in (
        "extension_sha256", "native_deployment_receipt_sha256",
        "runtime_closure_sha256", "broker_peer_identity_sha256",
    ):
        _hex(value.get(name), f"native tool runtime {name}")
    return raw


def _validate_native_js_runtime_identity(raw: object) -> bytes:
    """Validate the exact JS materializer identity before INITIAL is consumed."""

    if type(raw) is not bytes or not raw or len(raw) > 64 * 1024:
        _fail(
            "NATIVE_GUEST_JS_CUSTODY",
            "native JavaScript materializer runtime identity is unavailable",
        )
    value = _strict_json(raw, label="native JavaScript materializer runtime identity")
    expected = {
        "anchor_relative_path", "anchor_sha256", "custody_receipt_sha256",
        "install_provenance_sha256", "native_deployment_receipt_sha256",
        "native_extension_sha256", "offline_network_denial_sha256",
        "online_network_admission_sha256", "schema",
        "source_census_sha256", "trust_boundary",
    }
    if (
        set(value) != expected
        or value.get("schema")
        != "plamen.js-dependency-materializer-runtime-identity.v1"
        or value.get("anchor_relative_path")
        != "verification_policy/js_toolchain_bootstrap.v1.json"
        or value.get("trust_boundary")
        != "AUTHENTICATED_INSTALLER_LAUNCHER_BOUNDARY_V1"
    ):
        _fail(
            "NATIVE_GUEST_JS_CUSTODY",
            "native JavaScript materializer runtime identity differs",
        )
    for name in expected:
        if name.endswith("sha256"):
            _hex(value.get(name), f"native JavaScript runtime {name}")
    return raw


def _validate_native_managed_runtime_identity(raw: object) -> bytes:
    """Validate the service-authenticated managed runtime projection exactly.

    Darwin's managed lane additionally carries the immutable Linux-amd64
    interpreter and Apple-container custody inputs.  Other native platforms
    retain the base identity until their providers publish an equivalent
    authenticated guest-execution projection; the narrow bootstrap helper
    below consequently remains unavailable there instead of inventing one.
    """

    if type(raw) is not bytes or not raw or len(raw) > 64 * 1024:
        _fail(
            "NATIVE_GUEST_MANAGED_CUSTODY",
            "native managed-EVM runtime identity is unavailable",
        )
    value = _strict_json(raw, label="native managed-EVM runtime identity")
    base = {
        "schema", "platform", "extension_path", "extension_sha256",
        "extension_byte_count", "native_deployment_receipt_sha256",
        "runtime_closure_sha256", "broker_peer_identity_sha256",
        "managed_toolchain_custody_sha256",
    }
    platform = value.get("platform")
    expected = base | (
        {
            "guest_execution_authority", "managed_python_sha256",
            "managed_python_size", "native_interpreter_probe",
        }
        if platform == "MACOS" else set()
    )
    if (
        set(value) != expected
        or value.get("schema")
        != "plamen.managed-evm-toolchain-runtime-identity.v1"
        or platform not in {"MACOS", "LINUX", "WINDOWS"}
        or type(value.get("extension_path")) is not str
        or not value["extension_path"].startswith("/")
        or "\x00" in value["extension_path"]
        or type(value.get("extension_byte_count")) is not int
        or not 1 <= value["extension_byte_count"] <= 512 * 1024 * 1024
    ):
        _fail(
            "NATIVE_GUEST_MANAGED_CUSTODY",
            "native managed-EVM runtime identity differs",
        )
    for name in (
        "extension_sha256", "native_deployment_receipt_sha256",
        "runtime_closure_sha256", "broker_peer_identity_sha256",
        "managed_toolchain_custody_sha256",
    ):
        _hex(value.get(name), f"native managed runtime {name}")
    if platform != "MACOS":
        return raw

    _hex(value.get("managed_python_sha256"), "managed Python image member")
    managed_python_size = value.get("managed_python_size")
    if (
        type(managed_python_size) is not int
        or not 1 <= managed_python_size <= 512 * 1024 * 1024
    ):
        _fail(
            "NATIVE_GUEST_MANAGED_CUSTODY",
            "managed Python image-member size differs",
        )
    probe = value.get("native_interpreter_probe")
    expected_probe = {
        "base_prefix": "/usr/local/lib/plamen/python",
        "executable": "/usr/local/lib/plamen/python/bin/python3.12",
        "implementation": "CPython",
        "machine": "x86_64",
        "platlib": "/usr/local/lib/plamen/python/lib/python3.12/site-packages",
        "prefix": "/usr/local/lib/plamen/python",
        "purelib": "/usr/local/lib/plamen/python/lib/python3.12/site-packages",
        "sys_platform": "linux",
        "version": "3.12.12",
        "version_info": [3, 12, 12],
    }
    if type(probe) is not dict or probe != expected_probe:
        _fail(
            "NATIVE_GUEST_MANAGED_CUSTODY",
            "managed Python interpreter probe differs",
        )
    guest = value.get("guest_execution_authority")
    guest_fields = {
        "schema", "platform", "architecture", "runtime_image_reference",
        "image_closure_sha256", "provider_admission_sha256",
        "rosetta_required", "rosetta_authority_sha256", "rootfs_readonly",
        "network_policy", "network_isolation_authority_sha256",
        "custody_receipt_sha256", "immutable_launch_authority",
        "population_zero_authority",
    }
    if (
        type(guest) is not dict
        or set(guest) != guest_fields
        or guest.get("schema") != "plamen.apple-container-tool-custody.v1"
        or guest.get("platform") != "linux"
        or guest.get("architecture") != "amd64"
        or guest.get("rosetta_required") is not True
        or guest.get("rootfs_readonly") is not True
        or guest.get("network_policy") != "DENY_ALL"
        or guest.get("immutable_launch_authority")
        != "PRIVATE_IMMUTABLE_PROJECTED_CLOSURE"
        or guest.get("population_zero_authority") is not True
        or type(guest.get("runtime_image_reference")) is not str
        or re.search(
            r"@sha256:[0-9a-f]{64}$", guest["runtime_image_reference"]
        ) is None
        or any(char.isspace() for char in guest["runtime_image_reference"])
    ):
        _fail(
            "NATIVE_GUEST_MANAGED_CUSTODY",
            "Apple guest-execution authority differs",
        )
    for name in (
        "image_closure_sha256", "provider_admission_sha256",
        "rosetta_authority_sha256", "network_isolation_authority_sha256",
        "custody_receipt_sha256",
    ):
        _hex(guest.get(name), f"Apple guest authority {name}")
    return raw


def _native_guest_runtime_record(
    value: object,
) -> _NativeGuestRuntimeRecord:
    """Authenticate one live Python handle before exposing any native member."""

    module = _admitted_native_supervisor_module()
    if module is None:
        _fail(
            "NATIVE_BRIDGE_UNAVAILABLE",
            "authenticated native broker v2 INITIAL_AUTHORITY is unavailable",
        )
    if type(value) is not NativeGuestRuntimeAuthorities:
        _fail(
            "NATIVE_GUEST_RUNTIME_AUTHORITY",
            "native guest runtime authority has the wrong exact type",
        )
    with _NATIVE_GUEST_RUNTIME_LOCK:
        record = _LIVE_NATIVE_GUEST_RUNTIME_AUTHORITIES.get(value)
    if (
        record is None
        or record.module is not module
        or type(record.initial) is not module.NativeAuthorityConsumer
        or type(record.backend_execution) is not module.BackendExecutionAuthority
        or type(record.backend_install_generation)
        is not module.BackendInstallGenerationAuthority
        or type(record.tool_custody) is not module.DarwinToolCustodyAuthority
        or type(record.tool_runtime_identity) is not bytes
        or type(record.js_initial)
        is not module.JSDependencyMaterializerAuthority
        or type(record.js_runtime_identity) is not bytes
        or type(record.managed_initial)
        is not module.ManagedEVMToolchainInitialAuthority
        or type(record.managed_runtime_identity) is not bytes
        or record.creator_pid != os.getpid()
        or record.request_fingerprint_sha256
        != record.request.fingerprint_sha256
        or record.attempt_id != record.request.attempt_id
        or record.run_id != record.request.run_id
        or record.backend != record.request.backend
    ):
        _fail(
            "NATIVE_GUEST_RUNTIME_AUTHORITY",
            "native guest runtime authority is forged, expired, or changed",
        )
    return record


def authenticated_native_guest_request(authority: object) -> Any:
    """Return the authenticated request reference, which carries no authority."""

    return _native_guest_runtime_record(authority).request


def native_guest_backend_execution_authority(authority: object) -> Any:
    """Return the exact private role-2 backend member for driver retention."""

    return _native_guest_runtime_record(authority).backend_execution


def native_guest_backend_install_generation_authority(
    authority: object,
) -> object:
    """Project the request-selected authenticated install generation once.

    The retained native capability performs its final descriptor rejoin before
    this function mints the process-local launch-policy authority.  Subsequent
    calls return that same opaque authority; native projection itself remains
    one-shot and no receipt bytes, descriptor, path, or mapping are exposed.
    """

    record = _native_guest_runtime_record(authority)
    with _NATIVE_GUEST_RUNTIME_LOCK:
        admitted = _LIVE_NATIVE_GUEST_BACKEND_INSTALL_GENERATIONS.get(
            authority
        )
        if admitted is not None:
            return admitted
        try:
            admitted = _launch_policy._issue_native_backend_install_generation(
                record.backend_install_generation,
                expected_backend=record.backend,
            )
        except BaseException as exc:
            _fail(
                "NATIVE_GUEST_BACKEND_INSTALL_GENERATION",
                "native installed backend generation failed closed",
                exc,
            )
        _LIVE_NATIVE_GUEST_BACKEND_INSTALL_GENERATIONS[authority] = admitted
        return admitted


def native_guest_snapshot_tool_runtime_identity(authority: object) -> bytes:
    """Return the pre-consume native runtime projection bound to this pair."""

    return bytes(_native_guest_runtime_record(authority).tool_runtime_identity)


def native_guest_js_materializer_runtime_identity(authority: object) -> bytes:
    """Project the JS runtime identity retained before role-2 consumption."""

    return bytes(_native_guest_runtime_record(authority).js_runtime_identity)


def authenticate_native_guest_js_materializer(
    authority: object, admission: bytes,
) -> object:
    """Consume the private JS INITIAL into one bundle-bound session lease."""

    record = _native_guest_runtime_record(authority)
    _strict_operation_request(
        admission, label="native JavaScript materializer admission",
    )
    with _NATIVE_GUEST_RUNTIME_LOCK:
        if any(owner is authority for _session, owner in (
            value for value in _LIVE_NATIVE_GUEST_JS_SESSIONS.values()
        )):
            _fail(
                "NATIVE_GUEST_JS_SESSION",
                "native JavaScript materializer admission is one-shot",
            )
    try:
        session = record.module.authenticate_js_dependency_materializer_capability(
            record.js_initial, admission,
        )
    except BaseException as exc:
        _fail(
            "NATIVE_GUEST_JS_SESSION",
            "native JavaScript materializer admission failed closed",
            exc,
        )
    if type(session) is not record.module.JSDependencyMaterializerSessionLease:
        _fail(
            "NATIVE_GUEST_JS_SESSION",
            "native JavaScript materializer session has the wrong exact type",
        )
    with _NATIVE_GUEST_RUNTIME_LOCK:
        if id(session) in _LIVE_NATIVE_GUEST_JS_SESSIONS:
            _fail(
                "NATIVE_GUEST_JS_SESSION",
                "native JavaScript materializer session identity replayed",
            )
        _LIVE_NATIVE_GUEST_JS_SESSIONS[id(session)] = (session, authority)
    return session


def _require_native_guest_js_session(
    authority: object, session: object, record: _NativeGuestRuntimeRecord,
) -> None:
    if type(session) is not record.module.JSDependencyMaterializerSessionLease:
        _fail(
            "NATIVE_GUEST_JS_SESSION",
            "native JavaScript materializer session has the wrong exact type",
        )
    with _NATIVE_GUEST_RUNTIME_LOCK:
        issued = _LIVE_NATIVE_GUEST_JS_SESSIONS.get(id(session))
    if issued is None or issued[0] is not session or issued[1] is not authority:
        _fail(
            "NATIVE_GUEST_JS_SESSION",
            "native JavaScript materializer session is foreign or expired",
        )


def prepare_native_guest_js_materializer_execution(
    authority: object,
    session: object,
    request: bytes,
    source_fd: int,
    scratch_fd: int,
    state_fd: int,
    archive_root_fd: int,
) -> object:
    """Issue one descriptor-bound JS execution lease from the opaque bundle."""

    record = _native_guest_runtime_record(authority)
    _require_native_guest_js_session(authority, session, record)
    _strict_operation_request(
        request, label="native JavaScript materializer request",
    )
    try:
        lease = record.module.prepare_js_dependency_materializer_execution(
            record.js_initial, session, request, source_fd, scratch_fd,
            state_fd, archive_root_fd,
        )
    except BaseException as exc:
        _fail(
            "NATIVE_GUEST_JS_PREPARE",
            "native JavaScript materializer execution lease failed closed",
            exc,
        )
    if type(lease) is not record.module.JSDependencyMaterializerExecutionLease:
        _fail(
            "NATIVE_GUEST_JS_PREPARE",
            "native JavaScript materializer execution lease has the wrong exact type",
        )
    with _NATIVE_GUEST_RUNTIME_LOCK:
        if id(lease) in _LIVE_NATIVE_GUEST_JS_EXECUTIONS:
            _fail(
                "NATIVE_GUEST_JS_PREPARE",
                "native JavaScript materializer execution identity replayed",
            )
        _LIVE_NATIVE_GUEST_JS_EXECUTIONS[id(lease)] = (
            lease, session, authority,
        )
    return lease


def execute_native_guest_js_materializer(
    authority: object, session: object, lease: object,
) -> bytes:
    """Consume one same-session JS execution lease and return its exact terminal."""

    record = _native_guest_runtime_record(authority)
    _require_native_guest_js_session(authority, session, record)
    if type(lease) is not record.module.JSDependencyMaterializerExecutionLease:
        _fail(
            "NATIVE_GUEST_JS_EXECUTE",
            "native JavaScript materializer execution has the wrong exact type",
        )
    with _NATIVE_GUEST_RUNTIME_LOCK:
        issued = _LIVE_NATIVE_GUEST_JS_EXECUTIONS.pop(id(lease), None)
    if (
        issued is None or issued[0] is not lease
        or issued[1] is not session or issued[2] is not authority
    ):
        _fail(
            "NATIVE_GUEST_JS_EXECUTE",
            "native JavaScript materializer execution is foreign or consumed",
        )
    try:
        terminal = record.module.execute_js_dependency_materializer(
            record.js_initial, session, lease,
        )
    except BaseException as exc:
        _fail(
            "NATIVE_GUEST_JS_EXECUTE",
            "native JavaScript materializer execution failed closed",
            exc,
        )
    _strict_operation_request(
        terminal, label="native JavaScript materializer terminal",
    )
    return terminal


def replay_native_guest_js_materializer_terminal(
    authority: object,
    session: object,
    request: bytes,
    terminal: bytes,
    source_fd: int,
    scratch_fd: int,
    state_fd: int,
    archive_root_fd: int,
) -> object:
    """Attest one durable JS terminal through its same-bundle session."""

    record = _native_guest_runtime_record(authority)
    _require_native_guest_js_session(authority, session, record)
    _strict_operation_request(
        request, label="native JavaScript materializer replay request",
    )
    _strict_operation_request(
        terminal, label="native JavaScript materializer replay terminal",
    )
    try:
        replay = record.module.replay_js_dependency_materializer_terminal(
            record.js_initial, session, request, terminal, source_fd,
            scratch_fd, state_fd, archive_root_fd,
        )
    except BaseException as exc:
        _fail(
            "NATIVE_GUEST_JS_REPLAY",
            "native JavaScript materializer replay failed closed",
            exc,
        )
    if type(replay) is not record.module.JSDependencyMaterializerTerminalReplayLease:
        _fail(
            "NATIVE_GUEST_JS_REPLAY",
            "native JavaScript materializer replay has the wrong exact type",
        )
    return replay


def native_guest_managed_evm_runtime_identity(authority: object) -> bytes:
    """Project only the authenticated managed-EVM runtime identity bytes."""

    return bytes(_native_guest_runtime_record(authority).managed_runtime_identity)


def native_guest_managed_evm_bootstrap_inputs(authority: object) -> bytes:
    """Project only service-authenticated managed provision bootstrap inputs.

    The opaque bundle and its native custody remain private.  The returned
    canonical bytes are explicitly bound to the complete authenticated runtime
    identity so callers cannot substitute a probe or guest authority from a
    different broker session.
    """

    record = _native_guest_runtime_record(authority)
    raw = _validate_native_managed_runtime_identity(
        record.managed_runtime_identity
    )
    identity = _strict_json(raw, label="native managed-EVM runtime identity")
    if identity.get("platform") != "MACOS":
        _fail(
            "NATIVE_GUEST_MANAGED_BOOTSTRAP",
            "this native provider has no authenticated managed-EVM bootstrap inputs",
        )
    return canonical_json_bytes({
        "guest_execution_authority": identity["guest_execution_authority"],
        "managed_python_sha256": identity["managed_python_sha256"],
        "managed_python_size": identity["managed_python_size"],
        "managed_runtime_identity_sha256": _sha(raw),
        "native_interpreter_probe": identity["native_interpreter_probe"],
        "schema": _NATIVE_MANAGED_BOOTSTRAP_INPUTS_SCHEMA,
    })


def prepare_native_guest_managed_evm_provision(
    authority: object,
    request: bytes,
    policy_fd: int,
    project_fd: int,
    cache_fd: int,
    generations_fd: int,
    acquisition_fd: int,
) -> object:
    """Mint one managed-provision lease without exposing its INITIAL authority."""

    record = _native_guest_runtime_record(authority)
    if type(request) is not bytes or not request or len(request) > 2 * 1024 * 1024:
        _fail("NATIVE_MANAGED_REQUEST", "managed-EVM request bytes are unavailable")
    _strict_json(request, label="native managed-EVM provision request")
    try:
        lease = record.module.prepare_managed_evm_toolchain_provision(
            record.managed_initial,
            request,
            policy_fd,
            project_fd,
            cache_fd,
            generations_fd,
            acquisition_fd,
        )
    except BaseException as exc:
        _fail(
            "NATIVE_MANAGED_PREPARE",
            "native managed-EVM provision lease issuance failed closed",
            exc,
        )
    if type(lease) is not record.module.ManagedEVMToolchainProvisionLease:
        _fail(
            "NATIVE_MANAGED_PREPARE",
            "native managed-EVM provision lease has the wrong exact type",
        )
    with _NATIVE_GUEST_RUNTIME_LOCK:
        if id(lease) in _LIVE_NATIVE_GUEST_MANAGED_LEASES:
            _fail("NATIVE_MANAGED_PREPARE", "managed-EVM lease identity replayed")
        _LIVE_NATIVE_GUEST_MANAGED_LEASES[id(lease)] = (lease, authority)
    return lease


def execute_native_guest_managed_evm_provision(
    authority: object, lease: object,
) -> object:
    """Consume one bundle-bound managed-EVM provision lease exactly once."""

    record = _native_guest_runtime_record(authority)
    if type(lease) is not record.module.ManagedEVMToolchainProvisionLease:
        _fail("NATIVE_MANAGED_LEASE", "managed-EVM lease has the wrong exact type")
    with _NATIVE_GUEST_RUNTIME_LOCK:
        issued = _LIVE_NATIVE_GUEST_MANAGED_LEASES.pop(id(lease), None)
    if issued is None or issued[0] is not lease or issued[1] is not authority:
        _fail("NATIVE_MANAGED_LEASE", "managed-EVM lease is foreign or consumed")
    try:
        terminal = record.module.execute_managed_evm_toolchain_provision(lease)
    except BaseException as exc:
        _fail(
            "NATIVE_MANAGED_EXECUTE",
            "native managed-EVM provision execution failed closed",
            exc,
        )
    if type(terminal) is not record.module.ManagedEVMToolchainProvisionTerminal:
        _fail(
            "NATIVE_MANAGED_TERMINAL",
            "native managed-EVM terminal has the wrong exact type",
        )
    with _NATIVE_GUEST_RUNTIME_LOCK:
        _LIVE_NATIVE_GUEST_MANAGED_TERMINALS[id(terminal)] = (
            terminal, authority,
        )
    return terminal


def project_native_guest_managed_evm_terminal(
    authority: object, terminal: object,
) -> bytes:
    """Consume and project one terminal from the same opaque runtime bundle."""

    record = _native_guest_runtime_record(authority)
    if type(terminal) is not record.module.ManagedEVMToolchainProvisionTerminal:
        _fail("NATIVE_MANAGED_TERMINAL", "managed-EVM terminal has the wrong type")
    with _NATIVE_GUEST_RUNTIME_LOCK:
        issued = _LIVE_NATIVE_GUEST_MANAGED_TERMINALS.pop(id(terminal), None)
    if issued is None or issued[0] is not terminal or issued[1] is not authority:
        _fail(
            "NATIVE_MANAGED_TERMINAL",
            "managed-EVM terminal is foreign or already projected",
        )
    try:
        raw = record.module.project_managed_evm_toolchain_terminal(terminal)
    except BaseException as exc:
        _fail(
            "NATIVE_MANAGED_TERMINAL",
            "native managed-EVM terminal projection failed closed",
            exc,
        )
    if type(raw) is not bytes or not raw or len(raw) > 2 * 1024 * 1024:
        _fail(
            "NATIVE_MANAGED_TERMINAL",
            "native managed-EVM terminal projection is malformed",
        )
    _strict_json(raw, label="native managed-EVM provision terminal")
    return raw


def native_guest_managed_evm_setup_effects(
    authority: object,
    *,
    home: Path,
    project_fd: int,
    project_identity_sha256: str,
) -> object:
    """Construct the audit-time effects facade from native installed custody.

    This is the versioned Python edge of the installed-generation ABI.  The
    native extension must expose one exact static authority type plus the nine
    method-exact callbacks consumed by :class:`NativeManagedEVMSetupEffects`.
    Merely having the managed provisioner/image-member authority is not enough:
    the installed generation receipt and its complete distribution/RECORD tree
    must already have been signed by the cold-install transaction and must be
    re-admitted here.  Until that producer is installed, this API deliberately
    fails before constructing an effects object or touching the filesystem.

    No path, mapping, or Python callback supplied by the audit request can
    substitute for the native authority.  ``home`` is only the explicit
    durable-transaction root; it is not used to discover the generation.
    """

    record = _native_guest_runtime_record(authority)
    if sys.platform not in {"darwin", "linux"}:
        _fail(
            "NATIVE_MANAGED_INSTALLED_PLATFORM_UNSUPPORTED",
            "installed managed-EVM generation readmission is unavailable on "
            "this platform",
        )
    if (
        type(project_fd) is not int
        or project_fd < 0
        or type(project_identity_sha256) is not str
        or _HEX64_RE.fullmatch(project_identity_sha256) is None
    ):
        _fail(
            "NATIVE_MANAGED_INSTALLED_PROJECT",
            "managed-EVM audited-project authority is malformed",
        )
    required = (
        "ManagedEVMInstalledGenerationAuthority",
        "acquire_managed_evm_installed_generation",
        "observe_managed_evm_installed_generation",
        "stage_managed_evm_audit_setup",
        "validate_managed_evm_audit_setup_stage",
        "commit_managed_evm_audit_setup",
        "validate_managed_evm_installed_generation_receipt",
        "rollback_managed_evm_audit_setup",
        "cleanup_managed_evm_audit_setup",
        "require_managed_evm_installed_generation",
    )
    namespace = types.ModuleType.__getattribute__(record.module, "__dict__")
    if any(name not in namespace for name in required):
        _fail(
            "NATIVE_MANAGED_INSTALLED_GENERATION_UNAVAILABLE",
            "the installed native runtime has no signed managed-EVM "
            "generation producer/readmission ABI",
        )
    native_type = namespace[required[0]]
    callbacks = tuple(namespace[name] for name in required[1:])
    if (
        not isinstance(native_type, type)
        or type.__getattribute__(native_type, "__module__")
        != record.module.__name__
        or type.__getattribute__(native_type, "__flags__") & (1 << 9)
        or any(not callable(callback) for callback in callbacks)
    ):
        _fail(
            "NATIVE_MANAGED_INSTALLED_GENERATION_UNAVAILABLE",
            "the installed managed-EVM readmission ABI has the wrong exact type",
        )
    (
        acquire, observe, stage, validate_stage, commit, validate_receipt,
        rollback, cleanup, require,
    ) = callbacks

    def admit_installed(candidate: object) -> object:
        if candidate is not authority:
            _fail(
                "NATIVE_MANAGED_INSTALLED_RUNTIME",
                "managed-EVM setup received a foreign runtime authority",
            )
        try:
            installed = acquire(
                record.managed_initial, project_fd,
                project_identity_sha256.encode("ascii"),
            )
        except BaseException as exc:
            _fail(
                "NATIVE_MANAGED_INSTALLED_GENERATION_UNAVAILABLE",
                "signed managed-EVM generation readmission failed closed",
                exc,
            )
        if type(installed) is not native_type:
            _fail(
                "NATIVE_MANAGED_INSTALLED_GENERATION_UNAVAILABLE",
                "native managed-EVM readmission returned the wrong exact type",
            )
        return installed

    from native_managed_evm_setup_effects import NativeManagedEVMSetupEffects

    return NativeManagedEVMSetupEffects(
        home=home,
        native_runtime=authority,
        project_fd=project_fd,
        project_identity_sha256=project_identity_sha256,
        admit_installed=admit_installed,
        observe_installed=observe,
        stage_setup=stage,
        validate_stage=validate_stage,
        commit_setup=commit,
        validate_receipt=validate_receipt,
        rollback_setup=rollback,
        cleanup_setup=cleanup,
        require_generation=require,
    )


def _native_guest_projection_authority(
    runtime_authority: object, projection_authority: object,
) -> tuple[_NativeGuestRuntimeRecord, object]:
    record = _native_guest_runtime_record(runtime_authority)
    if type(projection_authority) is not record.module.EVMAnalysisProjectionAuthority:
        _fail(
            "NATIVE_EVM_PROJECTION_AUTHORITY",
            "EVM projection authority has the wrong exact native type",
        )
    with _NATIVE_GUEST_RUNTIME_LOCK:
        issued = _LIVE_NATIVE_GUEST_EVM_PROJECTIONS.get(id(projection_authority))
    if (
        issued is None
        or issued[0] is not projection_authority
        or issued[1] is not runtime_authority
    ):
        _fail(
            "NATIVE_EVM_PROJECTION_AUTHORITY",
            "EVM projection authority is foreign, expired, or unbound",
        )
    return record, projection_authority


def commit_native_guest_evm_analysis_projection(
    runtime_authority: object,
    *,
    dependency_materialization_receipt: Mapping[str, Any],
    original_source_scope_sha256: str,
    project_fd: int,
    scratch_fd: int,
    state_fd: int,
    modules_fd: int,
) -> object:
    """Commit one fresh descriptor-only EVM analysis projection.

    The method payload is constructed here from the exact v2 JS receipt and
    the run id retained by the opaque native guest bundle.  The executable and
    compiler authorities are selected by native image-member admission; no
    caller path, PATH value, executable digest, or compiler receipt is accepted.
    """

    record = _native_guest_runtime_record(runtime_authority)
    if not isinstance(dependency_materialization_receipt, Mapping):
        _fail(
            "NATIVE_EVM_PROJECTION_RECEIPT",
            "JavaScript dependency receipt is unavailable",
        )
    receipt = json.loads(canonical_json_bytes(dependency_materialization_receipt))
    stored = receipt.get("receipt_sha256") if type(receipt) is dict else None
    unsigned = dict(receipt) if type(receipt) is dict else {}
    unsigned.pop("receipt_sha256", None)
    modules_tree = receipt.get("modules_tree") if type(receipt) is dict else None
    if (
        type(receipt) is not dict
        or receipt.get("schema")
        != "plamen.js-dependency-materialization-receipt.v2"
        or _HEX64_RE.fullmatch(str(stored or "")) is None
        or stored != _sha(canonical_json_bytes(unsigned))
        or _HEX64_RE.fullmatch(
            str(receipt.get("lock_selection_sha256") or "")
        ) is None
        or type(modules_tree) is not dict
        or modules_tree.get("algorithm")
        != "PLAMEN_CANONICAL_TREE_SHA256_V1"
        or _HEX64_RE.fullmatch(str(modules_tree.get("sha256") or "")) is None
        or type(modules_tree.get("entry_count")) is not int
        or not 0 <= modules_tree["entry_count"] <= 200_000
        or type(modules_tree.get("expanded_bytes")) is not int
        or not 0 <= modules_tree["expanded_bytes"] <= 16 * 1024 * 1024 * 1024
    ):
        _fail(
            "NATIVE_EVM_PROJECTION_RECEIPT",
            "JavaScript dependency receipt v2 is malformed or unauthenticated",
        )
    _hex(original_source_scope_sha256, "EVM projection source scope")
    request = canonical_json_bytes({
        "dependency_materialization_receipt": receipt,
        "original_source_scope_sha256": original_source_scope_sha256,
        "run_id": record.run_id,
        "schema": "plamen.evm-analysis-projection-native-request.v1",
    })
    try:
        projection = record.module.commit_evm_analysis_projection(
            request, project_fd, scratch_fd, state_fd, modules_fd,
        )
    except BaseException as exc:
        _fail(
            "NATIVE_EVM_PROJECTION_COMMIT",
            "native EVM analysis projection commit failed closed",
            exc,
        )
    if type(projection) is not record.module.EVMAnalysisProjectionAuthority:
        _fail(
            "NATIVE_EVM_PROJECTION_AUTHORITY",
            "native projection commit returned the wrong exact type",
        )
    with _NATIVE_GUEST_RUNTIME_LOCK:
        if id(projection) in _LIVE_NATIVE_GUEST_EVM_PROJECTIONS:
            _fail(
                "NATIVE_EVM_PROJECTION_AUTHORITY",
                "native projection identity replayed",
            )
        _LIVE_NATIVE_GUEST_EVM_PROJECTIONS[id(projection)] = (
            projection, runtime_authority,
        )
    return projection


def project_native_guest_evm_analysis_projection_receipt(
    runtime_authority: object, projection_authority: object,
) -> bytes:
    """Project the exact service-replayed native projection custody receipt."""

    record, projection = _native_guest_projection_authority(
        runtime_authority, projection_authority,
    )
    try:
        raw = record.module.project_evm_analysis_projection_receipt(projection)
    except BaseException as exc:
        _fail(
            "NATIVE_EVM_PROJECTION_RECEIPT",
            "native projection receipt replay failed closed",
            exc,
        )
    value = _strict_json(raw, label="native EVM projection custody receipt")
    if (
        type(raw) is not bytes
        or not raw
        or len(raw) > 8 * 1024 * 1024
        or value.get("schema")
        != "plamen.private-analysis-projection-custody.v1"
    ):
        _fail(
            "NATIVE_EVM_PROJECTION_RECEIPT",
            "native projection custody receipt is malformed",
        )
    return raw


def project_native_guest_evm_analysis_projection_lineage(
    runtime_authority: object, projection_authority: object,
) -> bytes:
    """Replay lineage only through the descriptor-retaining native authority."""

    record, projection = _native_guest_projection_authority(
        runtime_authority, projection_authority,
    )
    try:
        raw = record.module.project_evm_analysis_projection_lineage(projection)
    except BaseException as exc:
        _fail(
            "NATIVE_EVM_PROJECTION_LINEAGE",
            "native projection lineage replay failed closed",
            exc,
        )
    value = _strict_json(raw, label="native EVM projection lineage")
    if (
        type(raw) is not bytes
        or not raw
        or len(raw) > 8 * 1024 * 1024
        or value.get("schema") != "plamen.evm-tool-materialization-lineage.v2"
    ):
        _fail(
            "NATIVE_EVM_PROJECTION_LINEAGE",
            "native projection lineage is malformed",
        )
    return raw


def project_native_guest_evm_analysis_projection_workspace_binding(
    runtime_authority: object, projection_authority: object,
) -> bytes:
    """Project a path only together with its retained native descriptor identity."""

    record, projection = _native_guest_projection_authority(
        runtime_authority, projection_authority,
    )
    try:
        raw = record.module.project_evm_analysis_projection_workspace_binding(
            projection
        )
    except BaseException as exc:
        _fail(
            "NATIVE_EVM_PROJECTION_WORKSPACE",
            "native projection workspace binding failed closed",
            exc,
        )
    value = _strict_json(raw, label="native EVM projection workspace binding")
    if (
        type(raw) is not bytes
        or not raw
        or len(raw) > 64 * 1024
        or set(value) != {
            "descriptor_identity_sha256", "projection_receipt_sha256",
            "schema", "workspace_path",
        }
        or value.get("schema")
        != "plamen.evm-analysis-projection-workspace-binding.v1"
        or _HEX64_RE.fullmatch(
            str(value.get("descriptor_identity_sha256") or "")
        ) is None
        or _HEX64_RE.fullmatch(
            str(value.get("projection_receipt_sha256") or "")
        ) is None
        or type(value.get("workspace_path")) is not str
        or not value["workspace_path"].startswith("/")
        or "\x00" in value["workspace_path"]
    ):
        _fail(
            "NATIVE_EVM_PROJECTION_WORKSPACE",
            "native projection workspace binding is malformed",
        )
    return raw


def _snapshot_execution_request_binding(
    raw: object, record: _NativeGuestRuntimeRecord,
) -> bytes:
    if type(raw) is not bytes or not raw or len(raw) > 2 * 1024 * 1024:
        _fail(
            "NATIVE_TOOL_REQUEST",
            "snapshot-tool request bytes are unavailable",
        )
    value = _strict_json(raw, label="native snapshot-tool execution request")
    tool_id = value.get("tool_id")
    mounts = value.get("mounts", ())
    mount_by_id = {
        row.get("mount_id"): row for row in mounts if type(row) is dict
    }
    mount_ids = set(mount_by_id)
    expected_mounts = (
        {"analysis-input", "project", "scratch", "state"}
        if tool_id in {"forge", "opengrep", "slither", "solc"}
        else None
    )
    source = value.get("source_descriptor")
    if (
        value.get("schema")
        != "plamen.snapshot-bound-tool-execution-request.v3"
        or value.get("run_id") != record.run_id
        or _HEX64_RE.fullmatch(str(value.get("audit_snapshot_sha256") or ""))
        is None
        or type(mounts) is not list
        or len(mount_ids) != len(mounts)
        or expected_mounts is None
        or mount_ids != expected_mounts
        or type(source) is not dict
        or source.get("kind") != "directory"
        or _HEX64_RE.fullmatch(str(source.get("descriptor_sha256") or ""))
        is None
        or mount_by_id["analysis-input"].get("source_sha256")
        != source["descriptor_sha256"]
    ):
        _fail(
            "NATIVE_TOOL_REQUEST_BINDING",
            "snapshot-tool request belongs to another run or mount denominator",
        )
    return raw


def prepare_native_guest_snapshot_tool_execution(
    authority: object,
    request: bytes,
    source_fd: int,
    scratch_fd: int,
    state_fd: int,
    project_fd: int,
) -> object:
    """Mint one native one-shot lease bound to run/snapshot and exact mounts."""

    record = _native_guest_runtime_record(authority)
    request = _snapshot_execution_request_binding(request, record)
    try:
        lease = record.module.prepare_darwin_tool_execution(
            record.tool_custody,
            request,
            source_fd,
            scratch_fd,
            state_fd,
            project_fd,
        )
    except BaseException as exc:
        _fail(
            "NATIVE_TOOL_PREPARE",
            "native snapshot-tool lease issuance failed closed",
            exc,
        )
    if type(lease) is not record.module.DarwinToolExecutionLease:
        _fail(
            "NATIVE_TOOL_PREPARE",
            "native snapshot-tool lease has the wrong exact type",
        )
    return lease


def execute_native_guest_snapshot_tool_execution(
    authority: object, lease: object,
) -> object:
    """Consume one exact request-bound native snapshot-tool lease."""

    record = _native_guest_runtime_record(authority)
    if type(lease) is not record.module.DarwinToolExecutionLease:
        _fail("NATIVE_TOOL_LEASE", "snapshot-tool lease has the wrong exact type")
    try:
        terminal = record.module.execute_darwin_tool(record.tool_custody, lease)
    except BaseException as exc:
        _fail(
            "NATIVE_TOOL_EXECUTE",
            "native snapshot-tool execution failed closed",
            exc,
        )
    if type(terminal) is not record.module.DarwinToolExecutionTerminal:
        _fail(
            "NATIVE_TOOL_TERMINAL",
            "native snapshot-tool terminal has the wrong exact type",
        )
    return terminal


def project_native_guest_snapshot_tool_terminal(
    authority: object, terminal: object,
) -> bytes:
    """Project terminal evidence from the exact retained native custody pair."""

    record = _native_guest_runtime_record(authority)
    if type(terminal) is not record.module.DarwinToolExecutionTerminal:
        _fail(
            "NATIVE_TOOL_TERMINAL",
            "native snapshot-tool terminal has the wrong exact type",
        )
    try:
        raw = record.module.project_darwin_tool_execution_terminal(terminal)
    except BaseException as exc:
        _fail(
            "NATIVE_TOOL_TERMINAL",
            "native snapshot-tool terminal projection failed closed",
            exc,
        )
    if type(raw) is not bytes or not raw or len(raw) > 2 * 1024 * 1024:
        _fail(
            "NATIVE_TOOL_TERMINAL",
            "native snapshot-tool terminal projection is malformed",
        )
    return raw


@dataclass(frozen=True)
class _TestOnlyBridge:
    consumer: TestOnlyOuterSupervisorConsumer
    verifier: TestOnlyOuterReceiptVerifier


class NativeOuterSupervisorBridgeCapability:
    """Reserved result of the not-yet-integrated native bridge verifier.

    There is deliberately no Python issuer or registry for this type.  Even
    ``object.__new__`` can therefore create only an unregistered fake, and the
    public registration function remains an unconditional hard stop.
    """

    __slots__ = ("__token",)

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("native outer-supervisor bridges are verifier-created")

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("native outer-supervisor bridge is immutable")

    def __copy__(self) -> NoReturn:
        raise TypeError("native outer-supervisor bridge cannot be copied")

    def __deepcopy__(self, _memo: Any) -> NoReturn:
        raise TypeError("native outer-supervisor bridge cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("native outer-supervisor bridge cannot be serialized")


@dataclass(frozen=True)
class PosixPhysicalLaunch:
    """Exact post-arm values supplied to the physical Popen boundary."""

    argv: tuple[str, ...]
    cwd: str
    stdin_fd: int
    pass_fds: tuple[int, ...]
    environment: Mapping[str, str] = field(repr=False, compare=False)
    materialization_binding: Mapping[str, Any]


@dataclass
class _ExecutionRecord:
    token: str
    generation: str
    creator_pid: int
    interpreter_nonce: str
    authority_ref: weakref.ReferenceType[Any]
    bridge: _TestOnlyBridge
    plan: TestOnlyBackendLaunchPlan
    request: Mapping[str, Any]
    outer_receipt: bytes
    outer: Mapping[str, Any]
    plan_receipt: bytes
    argv: tuple[str, ...] | None = None
    environment: Mapping[str, str] | None = None
    cwd_fd: int | None = None
    stdin_fd: int | None = None
    pass_fds: tuple[int, ...] | None = None
    private_fds: tuple[int, ...] | None = None
    arm_binding: Mapping[str, Any] | None = None
    invocation: TestOnlyBackendLaunchInvocation | None = None
    state: str = "PLAN_PREPARED"
    inner_arm_sha256: str | None = None
    materialization_receipt: bytes | None = None
    materialization_binding: Mapping[str, Any] | None = None
    materialized_environment: Mapping[str, str] | None = None
    policy_completion_receipt: bytes | None = None
    codex_config_census_contract_bytes: bytes | None = None
    process_created: bool = False
    inherited_fds_closed: bool = False
    lifecycle_lock: threading.RLock = field(
        default_factory=threading.RLock, repr=False
    )


@dataclass
class _IssuanceReservation:
    generation: str
    creator_pid: int
    interpreter_nonce: str
    state: str = "IN_PROGRESS"


_LOCK = threading.RLock()
_INTERPRETER_NONCE = os.urandom(32).hex()
_TEST_ONLY_BRIDGE: _TestOnlyBridge | None = None
_TEST_ONLY_CONSUMED_CONTEXTS: set[tuple[str, str, str]] = set()
_TEST_ONLY_EXECUTIONS: dict[int, _ExecutionRecord] = {}
_TEST_ONLY_ISSUANCE_RESERVATIONS: dict[
    tuple[str, str, str], _IssuanceReservation
] = {}


def _assert_issuance_process_context(
    entry_pid: int, entry_interpreter_nonce: str,
    *, policy_object: object | None = None,
) -> None:
    """Reject a callback that returned in a fork child or reset interpreter."""

    if (
        os.getpid() != entry_pid
        or _INTERPRETER_NONCE != entry_interpreter_nonce
    ):
        _close_inherited_test_only_policy_object(policy_object)
        _fail(
            "ISSUANCE_PROCESS_BOUNDARY",
            "test-only POSIX issuance crossed a process boundary",
        )


def _close_inherited_test_only_policy_object(value: object | None) -> None:
    """Drop one exact child-local TEST_ONLY policy object without methods."""

    if type(value) is TestOnlyBackendLaunchPlan:
        registry = _launch_policy._TEST_ONLY_PLANS
    elif type(value) is TestOnlyBackendLaunchInvocation:
        registry = _launch_policy._TEST_ONLY_INVOCATIONS
    else:
        return
    item = registry.pop(id(value), None)
    if item is None or item[0]() is not value:
        return
    retained_fds = {
        *(object.__getattribute__(resource, "fd")
          for resource in object.__getattribute__(item[1], "directories")),
        *(object.__getattribute__(resource, "fd")
          for resource in object.__getattribute__(item[1], "files")),
    }
    for fd in retained_fds:
        try:
            os.close(fd)
        except OSError:
            pass


def _close_inherited_execution_fds(record: _ExecutionRecord) -> None:
    """Close child-local descriptor copies without invoking Python callbacks."""

    if record.inherited_fds_closed:
        return
    record.inherited_fds_closed = True
    for fd in set((record.pass_fds or ()) + (record.private_fds or ())):
        try:
            os.close(fd)
        except OSError:
            pass


def _assert_execution_process_context(
    entry_pid: int,
    entry_interpreter_nonce: str,
    *,
    record: _ExecutionRecord,
    policy_object: object | None = None,
) -> None:
    """Reject a lifecycle callback that returned in a fork child."""

    if (
        os.getpid() != entry_pid
        or _INTERPRETER_NONCE != entry_interpreter_nonce
    ):
        _close_inherited_execution_fds(record)
        _close_inherited_test_only_policy_object(policy_object)
        _fail(
            "EXECUTION_PROCESS_BOUNDARY",
            "test-only POSIX execution crossed a process boundary",
        )


def _reserve_test_only_issuance(
    key: tuple[str, str, str], *, creator_pid: int,
    interpreter_nonce: str,
) -> str:
    """Claim one attempt/arm/process scope before any external callback."""

    generation = os.urandom(32).hex()
    with _LOCK:
        if key in _TEST_ONLY_ISSUANCE_RESERVATIONS:
            _fail(
                "ISSUANCE_REPLAY",
                "test-only POSIX issuance is already reserved or terminal",
            )
        _TEST_ONLY_ISSUANCE_RESERVATIONS[key] = _IssuanceReservation(
            generation=generation,
            creator_pid=creator_pid,
            interpreter_nonce=interpreter_nonce,
        )
    return generation


def _transition_test_only_issuance(
    key: tuple[str, str, str], generation: str, state: str,
) -> None:
    """Generation-bind a reservation transition; never affect a reused key."""

    with _LOCK:
        reservation = _TEST_ONLY_ISSUANCE_RESERVATIONS.get(key)
        if reservation is None or reservation.generation != generation:
            return
        reservation.state = state


def _retire_abandoned_test_only_execution(
    identity: int, generation: str,
) -> None:
    """Retire exactly one dead TEST_ONLY object without outer callbacks."""

    with _LOCK:
        record = _TEST_ONLY_EXECUTIONS.get(identity)
        if (
            record is None
            or record.generation != generation
            or record.authority_ref() is not None
        ):
            return
        _TEST_ONLY_EXECUTIONS.pop(identity, None)
        record.state = "ABANDONED"


def _invalidate_test_only_authorities_after_fork() -> None:
    """Make every inherited Python TEST_ONLY authority unusable in a child.

    The child receives fresh locks and registries without invoking any inherited
    consumer, verifier, plan, or invocation callback.  The authority object also
    retains its creator PID/old interpreter nonce, so it is rejected even if a
    caller retained a reference to the pre-fork registry object.
    """

    # The launch-policy module deliberately has no production Python registry,
    # but its structural TEST_ONLY capabilities do retain descriptors.  Fork
    # must close those child-local copies without calling inherited methods or
    # acquiring locks that another vanished thread may have held.
    retained_fds: set[int] = set()
    for registry_name in (
        "_EXECUTABLES", "_TEST_ONLY_AUTHORITIES", "_TEST_ONLY_PLANS",
        "_TEST_ONLY_INVOCATIONS",
    ):
        registry = object.__getattribute__(_launch_policy, registry_name)
        for item in tuple(registry.values()):
            record = item[1]
            for collection_name in ("directories", "files"):
                for resource in getattr(record, collection_name, ()):
                    retained_fds.add(object.__getattribute__(resource, "fd"))
            for resource_name in ("ca_bundle", "file"):
                resource = getattr(record, resource_name, None)
                if resource is not None:
                    retained_fds.add(
                        object.__getattribute__(resource, "fd")
                    )
        registry.clear()
    _launch_policy._LOCK = threading.RLock()
    for fd in retained_fds:
        try:
            os.close(fd)
        except OSError:
            pass

    global _LOCK, _INTERPRETER_NONCE, _TEST_ONLY_BRIDGE
    global _TEST_ONLY_CONSUMED_CONTEXTS, _TEST_ONLY_EXECUTIONS
    global _TEST_ONLY_ISSUANCE_RESERVATIONS
    _LOCK = threading.RLock()
    _INTERPRETER_NONCE = os.urandom(32).hex()
    _TEST_ONLY_BRIDGE = None
    _TEST_ONLY_CONSUMED_CONTEXTS = set()
    _TEST_ONLY_EXECUTIONS = {}
    _TEST_ONLY_ISSUANCE_RESERVATIONS = {}


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_invalidate_test_only_authorities_after_fork)


def _serialized_test_only_lifecycle(method: Any) -> Any:
    """Serialize one authority lifecycle and make state transitions atomic."""

    def wrapped(self: "TestOnlyPosixBackendExecution", *args: Any, **kwargs: Any) -> Any:
        process_context = (os.getpid(), _INTERPRETER_NONCE)
        record = _record(self)
        _assert_execution_process_context(
            *process_context, record=record,
        )
        with record.lifecycle_lock:
            _assert_execution_process_context(
                *process_context, record=record,
            )
            kwargs["_lifecycle_process_context"] = process_context
            result = method(self, *args, **kwargs)
            _assert_execution_process_context(
                *process_context, record=record,
            )
            return result

    return wrapped


class PosixBackendExecution:
    """Non-authoritative view of one native-custodied backend operation.

    The object holds a strong reference to the single static role-2 native
    authority threaded in by guest startup.  It never exposes that authority,
    descriptor numbers, argv, environment values, credentials, process
    handles, or a Python process object.  All external effects and recovery
    decisions remain in native code and every response is bound to canonical
    request bytes.

    WER's older physical-launch members remain explicit hard stops until WER
    is migrated to consume the receipt methods in this class.
    """

    __slots__ = (
        "__native_authority", "__prepared", "__lock", "__started",
        "__exited", "__revoked", "__finished", "__output_replays",
        "__extinguish_request", "__close_request", "__wer_binding",
    )

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("POSIX backend executions are native-prepare-created")

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise TypeError("POSIX backend authority is immutable")

    def __copy__(self) -> NoReturn:
        raise TypeError("POSIX backend authority cannot be copied")

    def __deepcopy__(self, _memo: Any) -> NoReturn:
        raise TypeError("POSIX backend authority cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("POSIX backend execution cannot be serialized")

    def __repr__(self) -> str:
        try:
            prepared = object.__getattribute__(self, "_PosixBackendExecution__prepared")
            state = self.state
        except BaseException:
            return "<PosixBackendExecution invalid>"
        return (
            "<PosixBackendExecution operation="
            f"{prepared.operation_key_sha256[:12]} state={state}>"
        )

    @property
    def operation_key_sha256(self) -> str:
        return self.__prepared.operation_key_sha256

    @property
    def prepared_receipt(self) -> NativePreparedReceipt:
        return self.__prepared

    @property
    def wer_arm_binding(self) -> Mapping[str, Any]:
        """Return redacted semantic evidence for WER's durable inner arm.

        This is not process authority: it contains no argv, environment,
        credential, descriptor, native transport key, or process handle.  The
        effective native authority remains private and all effects still pass
        through the static C method descriptors.
        """

        raw = self.__wer_binding
        if raw is None:
            _fail(
                "NATIVE_BACKEND_BINDING",
                "native backend execution has no WER arm denominator",
            )
        return MappingProxyType(_strict_json(raw, label="native WER arm binding"))

    @property
    def started_receipt(self) -> NativeStartedReceipt | None:
        return self.__started

    @property
    def exited_receipt(self) -> NativeExitedReceipt | None:
        return self.__exited

    @property
    def revoked_receipt(self) -> NativeRevokedReceipt | None:
        return self.__revoked

    @property
    def finished_receipt(self) -> NativeFinishedReceipt | None:
        return self.__finished

    @property
    def state(self) -> str:
        if self.__finished is not None:
            return "FINISHED"
        if self.__revoked is not None:
            return "REVOKED"
        if self.__exited is not None:
            return self.__exited.status
        if self.__started is not None:
            return "STARTED"
        return "PREPARED"

    def _native_call(self, method_name: str, request: bytes) -> bytes:
        native = self.__native_authority
        descriptor = type(native).__dict__.get(method_name)
        if type(descriptor) is not types.MethodDescriptorType:
            _fail(
                "NATIVE_BACKEND_METHOD",
                f"native backend method {method_name} is not a static descriptor",
            )
        try:
            raw = descriptor(native, request)
        except BaseException as exc:
            _fail(
                "NATIVE_BACKEND_OPERATION",
                f"native backend {method_name} failed closed",
                exc,
            )
        if type(raw) is not bytes or not raw or len(raw) > 1024 * 1024:
            _fail(
                "NATIVE_BACKEND_RESPONSE",
                f"native backend {method_name} returned invalid bytes",
            )
        return raw

    @staticmethod
    def _replay_identical(previous: bytes, current: bytes, label: str) -> None:
        if len(previous) != len(current) or not hmac.compare_digest(previous, current):
            _fail(
                "NATIVE_BACKEND_REPLAY_DIVERGED",
                f"native {label} recovery did not replay identical bytes",
            )

    def start_or_recover(self) -> NativeStartedReceipt:
        with self.__lock:
            if self.__revoked is not None or self.__finished is not None:
                _fail("NATIVE_BACKEND_STATE", "terminal operation cannot start")
            request = _start_request(self.__prepared)
            request_sha = _sha(request)
            raw = self._native_call("start_or_recover", request)
            receipt = parse_native_started_receipt(
                raw, prepared=self.__prepared,
                start_request_sha256=request_sha,
            )
            if self.__started is not None:
                self._replay_identical(self.__started.raw, raw, "STARTED")
                return self.__started
            object.__setattr__(self, "_PosixBackendExecution__started", receipt)
            return receipt

    def wait_or_recover(self) -> NativeExitedReceipt:
        # WAIT may block until the native monotonic deadline.  Do not retain
        # the per-operation Python lock across that call: another coordinator
        # thread must remain able to request native extinction for the same
        # operation.  Native custody and the hidden transport operation key,
        # rather than this lock, serialize the actual effects.
        with self.__lock:
            if self.__started is None:
                _fail("NATIVE_BACKEND_STATE", "operation has not started")
            if self.__revoked is not None or self.__finished is not None:
                _fail("NATIVE_BACKEND_STATE", "terminally revoked operation cannot wait")
            started = self.__started
            request = _wait_request(started)
        raw = self._native_call("wait_or_recover", request)
        receipt = parse_native_exited_receipt(
            raw, started=started, wait_request_sha256=_sha(request),
        )
        with self.__lock:
            if self.__exited is not None:
                self._replay_identical(self.__exited.raw, raw, "EXITED")
                return self.__exited
            if self.__revoked is not None or self.__finished is not None:
                _fail(
                    "NATIVE_BACKEND_STATE",
                    "operation was revoked while native wait was in flight",
                )
            object.__setattr__(self, "_PosixBackendExecution__exited", receipt)
            return receipt

    def read_output_or_recover(
        self, *, stream: str, offset: int,
        max_bytes: int = NATIVE_OUTPUT_CHUNK_MAX_BYTES,
    ) -> NativeOutputChunkReceipt:
        with self.__lock:
            exited = self.__exited
            if exited is None:
                _fail("NATIVE_BACKEND_STATE", "output is unavailable before EXITED")
            if exited.status == "OUTPUT_OVERFLOW_REVOKED":
                _fail("NATIVE_OUTPUT_OVERFLOW", "overflowed output is terminally revoked")
            if self.__revoked is not None or self.__finished is not None:
                _fail("NATIVE_BACKEND_STATE", "closed output cannot be read")
            request = _output_request(
                exited, stream=stream, offset=offset, max_bytes=max_bytes,
            )
            raw = self._native_call("read_output_or_recover", request)
            receipt = parse_native_output_receipt(
                raw, exited=exited, output_request=request,
            )
            key = _sha(request)
            prior = self.__output_replays.get(key)
            if prior is not None:
                self._replay_identical(prior, raw, "OUTPUT")
            else:
                self.__output_replays[key] = raw
            return receipt

    def extinguish_or_recover(self, *, reason_code: str) -> NativeRevokedReceipt:
        with self.__lock:
            if self.__finished is not None:
                _fail("NATIVE_BACKEND_STATE", "finished operation cannot be revoked")
            if self.__extinguish_request is None:
                latest = (
                    self.__exited.sha256 if self.__exited is not None
                    else self.__started.sha256 if self.__started is not None
                    else self.__prepared.sha256
                )
                request = _extinguish_request(
                    self.__prepared,
                    latest_lifecycle_receipt_sha256=latest,
                    reason_code=reason_code,
                )
                object.__setattr__(
                    self, "_PosixBackendExecution__extinguish_request", request,
                )
            else:
                request = self.__extinguish_request
                requested = _strict_operation_request(
                    request, label="native extinguish request"
                )
                if requested["reason_code"] != reason_code:
                    _fail(
                        "NATIVE_BACKEND_REPLAY_CONFLICT",
                        "extinguish replay changed its reason code",
                    )
            raw = self._native_call("extinguish_or_recover", request)
            receipt = parse_native_revoked_receipt(
                raw,
                prepared=self.__prepared,
                extinguish_request=request,
                expected_process_identity_sha256=(
                    None if self.__started is None
                    else self.__started.process_identity.sha256
                ),
            )
            if self.__revoked is not None:
                self._replay_identical(self.__revoked.raw, raw, "REVOKED")
                return self.__revoked
            object.__setattr__(self, "_PosixBackendExecution__revoked", receipt)
            return receipt

    def close_operation(self) -> NativeFinishedReceipt:
        with self.__lock:
            terminal = self.__revoked or self.__exited
            if terminal is None:
                _fail(
                    "NATIVE_BACKEND_STATE",
                    "operation must exit or be revoked before native close",
                )
            if self.__close_request is None:
                request = _close_request(
                    self.__prepared, terminal_receipt_sha256=terminal.sha256,
                )
                object.__setattr__(
                    self, "_PosixBackendExecution__close_request", request,
                )
            else:
                request = self.__close_request
            raw = self._native_call("close_operation", request)
            receipt = parse_native_finished_receipt(
                raw, prepared=self.__prepared, close_request=request,
            )
            if self.__finished is not None:
                self._replay_identical(self.__finished.raw, raw, "FINISHED")
                return self.__finished
            object.__setattr__(self, "_PosixBackendExecution__finished", receipt)
            return receipt

    @staticmethod
    def _unavailable() -> NoReturn:
        _fail(
            "NATIVE_BRIDGE_UNAVAILABLE",
            "native POSIX backend execution authority is not installed",
        )

    @property
    def arm_binding(self) -> Mapping[str, Any]:
        _fail(
            "NATIVE_BRIDGE_UNAVAILABLE",
            "legacy WER arm binding cannot represent native process custody",
        )

    def preview_physical_binding(self) -> Mapping[str, Any]:
        _fail(
            "NATIVE_BRIDGE_UNAVAILABLE",
            "legacy WER preview cannot represent native process custody",
        )

    def materialize_after_inner_arm(
        self, *, inner_arm_sha256: str,
    ) -> PosixPhysicalLaunch:
        _fail(
            "NATIVE_BRIDGE_UNAVAILABLE",
            "legacy WER materialization cannot expose native argv/env/descriptors",
        )

    def revalidate_immediately_before_process_creation(self) -> None:
        _fail(
            "NATIVE_BRIDGE_UNAVAILABLE",
            "legacy WER pre-Popen revalidation cannot represent native custody",
        )

    def mark_process_created(self) -> None:
        _fail(
            "NATIVE_BRIDGE_UNAVAILABLE",
            "legacy WER cannot mark a native-custodied process as Popen-created",
        )

    def revoke_after_scope_close(
        self, *, process_creation_state: str,
        process_population_zero_proven: bool,
        returncode: int | None, reason_code: str,
    ) -> Mapping[str, Any]:
        _fail(
            "NATIVE_BRIDGE_UNAVAILABLE",
            "legacy WER revoke must migrate to extinguish_or_recover",
        )

    def abort_before_process_creation(
        self, *, reason_code: str,
    ) -> Mapping[str, Any]:
        _fail(
            "NATIVE_BRIDGE_UNAVAILABLE",
            "legacy WER abort must migrate to extinguish_or_recover",
        )

    def close(self) -> None:
        _fail(
            "NATIVE_BRIDGE_UNAVAILABLE",
            "legacy WER close must migrate to close_operation",
        )


def _new_native_backend_execution(
    native_authority: Any, prepared: NativePreparedReceipt,
    *, wer_binding: bytes | None = None,
) -> PosixBackendExecution:
    """Create a receipt wrapper; this function does not create authority."""

    value = object.__new__(PosixBackendExecution)
    object.__setattr__(
        value, "_PosixBackendExecution__native_authority", native_authority,
    )
    object.__setattr__(value, "_PosixBackendExecution__prepared", prepared)
    object.__setattr__(value, "_PosixBackendExecution__lock", threading.RLock())
    object.__setattr__(value, "_PosixBackendExecution__started", None)
    object.__setattr__(value, "_PosixBackendExecution__exited", None)
    object.__setattr__(value, "_PosixBackendExecution__revoked", None)
    object.__setattr__(value, "_PosixBackendExecution__finished", None)
    object.__setattr__(value, "_PosixBackendExecution__output_replays", {})
    object.__setattr__(value, "_PosixBackendExecution__extinguish_request", None)
    object.__setattr__(value, "_PosixBackendExecution__close_request", None)
    object.__setattr__(value, "_PosixBackendExecution__wer_binding", wer_binding)
    return value


def _native_prepare(native_authority: Any, request: bytes) -> bytes:
    descriptor = type(native_authority).__dict__.get("prepare")
    if type(descriptor) is not types.MethodDescriptorType:
        _fail("NATIVE_BACKEND_METHOD", "native prepare is not a static descriptor")
    try:
        raw = descriptor(native_authority, request)
    except BaseException as exc:
        _fail("NATIVE_BACKEND_OPERATION", "native backend prepare failed closed", exc)
    if type(raw) is not bytes or not raw or len(raw) > 1024 * 1024:
        _fail("NATIVE_BACKEND_RESPONSE", "native prepare returned invalid bytes")
    return raw


class TestOnlyPosixBackendExecution:
    """One-shot structural-test authority with no production type identity."""

    __slots__ = (
        "__token", "__creator_pid", "__interpreter_nonce", "__weakref__"
    )

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("test-only POSIX backend authorities are issuer-created")

    def __copy__(self) -> NoReturn:
        raise TypeError("test-only POSIX backend authority cannot be copied")

    def __deepcopy__(self, _memo: Any) -> NoReturn:
        raise TypeError("test-only POSIX backend authority cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("test-only POSIX backend authority cannot be serialized")

    @property
    @_serialized_test_only_lifecycle
    def arm_binding(
        self, *, _lifecycle_process_context: tuple[int, str],
    ) -> Mapping[str, Any]:
        record = _record(self)
        if record.arm_binding is None:
            _fail(
                "EXECUTION_STATE",
                "physical invocation must be consumed before the inner arm",
            )
        return MappingProxyType(dict(record.arm_binding))

    @_serialized_test_only_lifecycle
    def preview_physical_binding(
        self, *, _lifecycle_process_context: tuple[int, str],
    ) -> Mapping[str, Any]:
        record = _record(self)
        if record.state != "PLAN_PREPARED":
            _fail("EXECUTION_STATE", "backend invocation is not armable")
        _assert_execution_process_context(
            *_lifecycle_process_context, record=record,
        )
        record.state = "PREVIEW_IN_PROGRESS"
        _consume_invocation_snapshot(
            record, process_context=_lifecycle_process_context,
        )
        _replay_invocation_snapshot(
            record, process_context=_lifecycle_process_context,
        )
        assert record.argv is not None
        assert record.environment is not None
        assert record.cwd_fd is not None
        assert record.stdin_fd is not None
        assert record.pass_fds is not None
        return MappingProxyType({
            "argv": record.argv,
            "environment": MappingProxyType(dict(record.environment)),
            "environment_names": tuple(sorted(record.environment)),
            "cwd": f"/proc/self/fd/{record.cwd_fd}",
            "stdin_fd": record.stdin_fd,
            "pass_fds": record.pass_fds,
        })

    @_serialized_test_only_lifecycle
    def materialize_after_inner_arm(
        self, *, inner_arm_sha256: str,
        _lifecycle_process_context: tuple[int, str],
    ) -> PosixPhysicalLaunch:
        record = _record(self)
        if record.state != "INVOCATION_PREPARED":
            _fail("EXECUTION_STATE", "backend invocation is not prepared")
        inner = _hex(inner_arm_sha256, "inner arm")
        _replay_invocation_snapshot(
            record, process_context=_lifecycle_process_context,
        )
        assert record.invocation is not None
        assert record.environment is not None
        assert record.argv is not None
        assert record.cwd_fd is not None
        assert record.stdin_fd is not None
        assert record.pass_fds is not None
        if record.arm_binding is None:
            _fail("EXECUTION_STATE", "backend invocation lacks its arm binding")
        expected = {
            "attempt_id": record.request["attempt_id"],
            "backend": record.request["backend"],
            "inner_arm_sha256": inner,
            "process_scope_identity": record.request[
                "process_scope_identity"
            ],
            "plan_receipt_sha256": _sha(record.plan_receipt),
            "outer_authority_receipt_sha256": _sha(record.outer_receipt),
        }
        _assert_execution_process_context(
            *_lifecycle_process_context, record=record,
        )
        record.state = "MATERIALIZATION_IN_PROGRESS"
        try:
            result = record.bridge.consumer.materialize_posix_backend_launch(
                record.invocation, MappingProxyType(dict(expected))
            )
            _assert_execution_process_context(
                *_lifecycle_process_context, record=record,
            )
            if type(result) is not tuple or len(result) != 2:
                _fail(
                    "MATERIALIZE",
                    "trusted materializer result is not an exact pair",
                )
            raw_environment, receipt = result
        except BaseException as exc:
            _assert_execution_process_context(
                *_lifecycle_process_context, record=record,
            )
            _cleanup_failed_materialization(
                record,
                inner_arm_sha256=inner,
                materialization_receipt=b"",
                reason_code="MATERIALIZER_RAISED",
                cause=exc,
                process_context=_lifecycle_process_context,
            )
            _fail("MATERIALIZE", "trusted materializer failed", exc)
        materialization_receipt = receipt if type(receipt) is bytes else b""
        try:
            if type(receipt) is not bytes:
                _fail(
                    "MATERIALIZE_RECEIPT",
                    "materialization receipt is not exact bytes",
                )
            environment = _validate_materialized_environment(
                record, raw_environment
            )
            materialization = _strict_json(
                receipt, label="POSIX backend materialization receipt"
            )
            if set(materialization) != _MATERIALIZATION_FIELDS:
                _fail("MATERIALIZE_RECEIPT", "materialization fields drifted")
            required = {
                "schema": MATERIALIZATION_SCHEMA,
                **expected,
                "environment_names": sorted(environment),
                "final_environment_sha256": _environment_sha(environment),
                "cwd_fd_identity_sha256": record.arm_binding[
                    "cwd_fd_identity_sha256"
                ],
                "stdin_fd_identity_sha256": record.arm_binding[
                    "stdin_fd_identity_sha256"
                ],
                "pass_fds_identity_sha256": record.arm_binding[
                    "pass_fds_identity_sha256"
                ],
                "retained_fd_count": record.arm_binding[
                    "retained_fd_count"
                ],
                "status": "MATERIALIZED_AFTER_INNER_ARM",
            }
            if any(
                materialization.get(key) != value
                for key, value in required.items()
            ):
                _fail(
                    "MATERIALIZE_RECEIPT",
                    "materialization binding drifted",
                )
            _hex(
                materialization.get("materialized_private_state_sha256"),
                "materialized private state",
            )
            _verify_external(
                record.bridge, "MATERIALIZED", receipt,
                {
                    **required,
                    "materialized_private_state_sha256": materialization[
                        "materialized_private_state_sha256"
                    ],
                },
                process_context=_lifecycle_process_context,
                record=record,
            )
            # Recheck every retained descriptor after materialization and as
            # close as possible to the caller's Popen boundary.
            _replay_invocation_snapshot(
                record, process_context=_lifecycle_process_context,
            )
        except BaseException as exc:
            _assert_execution_process_context(
                *_lifecycle_process_context, record=record,
            )
            _cleanup_failed_materialization(
                record,
                inner_arm_sha256=inner,
                materialization_receipt=materialization_receipt,
                reason_code="MATERIALIZATION_VALIDATION_FAILED",
                cause=exc,
                process_context=_lifecycle_process_context,
            )
            raise
        _assert_execution_process_context(
            *_lifecycle_process_context, record=record,
        )
        record.inner_arm_sha256 = inner
        record.materialization_receipt = bytes(receipt)
        record.materialization_binding = MappingProxyType({
            **materialization,
            "receipt_sha256": _sha(receipt),
        })
        record.materialized_environment = MappingProxyType(
            dict(environment)
        )
        record.state = "MATERIALIZED"
        return PosixPhysicalLaunch(
            argv=record.argv,
            cwd=f"/proc/self/fd/{record.cwd_fd}",
            stdin_fd=record.stdin_fd,
            pass_fds=record.pass_fds,
            environment=MappingProxyType(environment),
            materialization_binding=record.materialization_binding,
        )

    @_serialized_test_only_lifecycle
    def revalidate_immediately_before_process_creation(
        self, *, _lifecycle_process_context: tuple[int, str],
    ) -> None:
        record = _record(self)
        if record.state != "MATERIALIZED" or record.materialization_receipt is None:
            _fail("EXECUTION_STATE", "backend launch is not materialized")
        _assert_execution_process_context(
            *_lifecycle_process_context, record=record,
        )
        record.state = "PRECREATE_VALIDATING"
        try:
            _replay_materialized_snapshot(
                record, process_context=_lifecycle_process_context,
            )
            _verify_external(
                record.bridge, "PRE_CREATE", record.materialization_receipt,
                dict(record.materialization_binding or {}),
                process_context=_lifecycle_process_context,
                record=record,
            )
        except BaseException as exc:
            _assert_execution_process_context(
                *_lifecycle_process_context, record=record,
            )
            record.state = "PRECREATE_REJECTED"
            raise
        _assert_execution_process_context(
            *_lifecycle_process_context, record=record,
        )
        record.state = "PRECREATE_VALIDATED"

    @_serialized_test_only_lifecycle
    def mark_process_created(
        self, *, _lifecycle_process_context: tuple[int, str],
    ) -> None:
        record = _record(self)
        if record.state != "PRECREATE_VALIDATED":
            _fail("EXECUTION_STATE", "process creation was not authorized")
        # The policy invocation retains its parent descriptors until terminal
        # completion so its own completion receipt can close/revoke them.
        _assert_execution_process_context(
            *_lifecycle_process_context, record=record,
        )
        record.process_created = True
        record.state = "PROCESS_CREATED"

    @_serialized_test_only_lifecycle
    def revoke_after_scope_close(
        self, *, process_creation_state: str,
        process_population_zero_proven: bool,
        returncode: int | None, reason_code: str,
        _lifecycle_process_context: tuple[int, str],
    ) -> Mapping[str, Any]:
        record = _record(self)
        if record.state not in {
            "MATERIALIZED", "PRECREATE_VALIDATED", "PROCESS_CREATED"
        }:
            _fail("EXECUTION_STATE", "backend launch is not revocable")
        if process_population_zero_proven is not True:
            _quarantine(
                record, process_context=_lifecycle_process_context,
            )
            _fail("POPULATION_ZERO", "private state cannot be revoked ambiguously")
        _assert_execution_process_context(
            *_lifecycle_process_context, record=record,
        )
        record.state = "REVOCATION_IN_PROGRESS"
        try:
            receipt = _revoke(
                record,
                process_creation_state=process_creation_state,
                process_population_zero_proven=True,
                returncode=returncode,
                reason_code=reason_code,
                process_context=_lifecycle_process_context,
            )
        except BaseException as exc:
            _assert_execution_process_context(
                *_lifecycle_process_context, record=record,
            )
            if record.state != "QUARANTINED":
                _quarantine(
                    record, process_context=_lifecycle_process_context,
                )
            raise
        _assert_execution_process_context(
            *_lifecycle_process_context, record=record,
        )
        record.state = "REVOKED"
        return MappingProxyType(receipt)

    @_serialized_test_only_lifecycle
    def abort_before_process_creation(
        self, *, reason_code: str,
        _lifecycle_process_context: tuple[int, str],
    ) -> Mapping[str, Any]:
        record = _record(self)
        if record.state == "PLAN_PREPARED":
            _assert_execution_process_context(
                *_lifecycle_process_context, record=record,
            )
            record.state = "ABORT_IN_PROGRESS"
            try:
                record.plan.close()
                _assert_execution_process_context(
                    *_lifecycle_process_context, record=record,
                )
            except BaseException as exc:
                _assert_execution_process_context(
                    *_lifecycle_process_context, record=record,
                )
                record.state = "QUARANTINED"
                raise
            record.state = "CLOSED_UNMATERIALIZED"
            return MappingProxyType({
                "schema": REVOCATION_SCHEMA,
                "status": "CLOSED_BEFORE_MATERIALIZATION",
                "reason_code": _identifier(reason_code, "reason code"),
            })
        if record.state == "INVOCATION_PREPARED":
            _assert_execution_process_context(
                *_lifecycle_process_context, record=record,
            )
            record.state = "ABORT_IN_PROGRESS"
            try:
                receipt = _terminal_policy_revoke(
                    record, process_context=_lifecycle_process_context,
                )
            except BaseException as exc:
                _assert_execution_process_context(
                    *_lifecycle_process_context, record=record,
                )
                _quarantine(
                    record, process_context=_lifecycle_process_context,
                )
                raise
            record.state = "REVOKED"
            return MappingProxyType(receipt)
        if record.state not in {
            "MATERIALIZED", "PRECREATE_REJECTED", "PRECREATE_VALIDATED"
        }:
            _fail("EXECUTION_STATE", "backend launch cannot be aborted")
        _assert_execution_process_context(
            *_lifecycle_process_context, record=record,
        )
        record.state = "ABORT_IN_PROGRESS"
        try:
            receipt = _revoke(
                record,
                process_creation_state="CREATION_FAILED_WITHOUT_PROCESS_OBJECT",
                process_population_zero_proven=True,
                returncode=None,
                reason_code=reason_code,
                process_context=_lifecycle_process_context,
            )
        except BaseException as exc:
            _assert_execution_process_context(
                *_lifecycle_process_context, record=record,
            )
            if record.state != "QUARANTINED":
                _quarantine(
                    record, process_context=_lifecycle_process_context,
                )
            raise
        _assert_execution_process_context(
            *_lifecycle_process_context, record=record,
        )
        record.state = "REVOKED"
        return MappingProxyType(receipt)

    def close(self) -> None:
        process_context = (os.getpid(), _INTERPRETER_NONCE)
        _assert_test_only_creator(self)
        with _LOCK:
            record = _TEST_ONLY_EXECUTIONS.get(id(self))
        if record is None:
            return
        # Validate the full creator/nonce/token binding before treating close as
        # an idempotent terminal cleanup.  Inherited child objects must reject.
        _record(self)
        with record.lifecycle_lock:
            _assert_execution_process_context(
                *process_context, record=record,
            )
            if record.state == "PLAN_PREPARED":
                record.state = "CLOSE_IN_PROGRESS"
                try:
                    record.plan.close()
                    _assert_execution_process_context(
                        *process_context, record=record,
                    )
                except BaseException as exc:
                    _assert_execution_process_context(
                        *process_context, record=record,
                    )
                    record.state = "QUARANTINED"
                    raise
                record.state = "CLOSED_UNMATERIALIZED"
            elif record.state == "INVOCATION_PREPARED":
                record.state = "CLOSE_IN_PROGRESS"
                try:
                    _terminal_policy_revoke(
                        record, process_context=process_context,
                    )
                except BaseException as exc:
                    _assert_execution_process_context(
                        *process_context, record=record,
                    )
                    _quarantine(
                        record, process_context=process_context,
                    )
                    raise
                record.state = "REVOKED"
            _assert_execution_process_context(
                *process_context, record=record,
            )
            if record.state in {
                "CLOSED_UNMATERIALIZED", "REVOKED", "QUARANTINED"
            }:
                with _LOCK:
                    _assert_execution_process_context(
                        *process_context, record=record,
                    )
                    _TEST_ONLY_EXECUTIONS.pop(id(self), None)


def register_trusted_outer_supervisor_bridge(
    authenticated_native_bridge: object,
) -> None:
    """Production hard stop pending the native/out-of-process bridge.

    Same-process Python consumers, verifiers, mappings, receipt hashes, and
    TEST_ONLY objects are never registration authority.  The future adapter
    must consume an exact capability issued by a verifier this module cannot
    mint, then directly supply a production :class:`PosixBackendExecution`.
    """

    _fail(
        "NATIVE_BRIDGE_UNAVAILABLE",
        "native outer-supervisor bridge integration is not installed",
    )


def _register_test_only_outer_supervisor_bridge(
    consumer: TestOnlyOuterSupervisorConsumer,
    verifier: TestOnlyOuterReceiptVerifier,
) -> None:
    """Install a non-production bridge for structural integration tests only."""

    for value, method in (
        (consumer, "consume_posix_backend_launch"),
        (consumer, "materialize_posix_backend_launch"),
        (consumer, "revoke_posix_backend_launch"),
        (verifier, "verify_posix_backend_receipt"),
    ):
        if not callable(getattr(value, method, None)):
            _fail("BRIDGE", f"test-only bridge lacks {method}")
    global _TEST_ONLY_BRIDGE
    with _LOCK:
        if _TEST_ONLY_BRIDGE is not None:
            _fail("BRIDGE_REPLAY", "test-only POSIX bridge is already registered")
        _TEST_ONLY_BRIDGE = _TestOnlyBridge(
            consumer=consumer, verifier=verifier,
        )


def outer_supervisor_context_available() -> bool:
    """Return whether a production native context is registered.

    A TEST_ONLY bridge never changes production backend availability.  This
    observes only whether the extension exposes the exact static, service-
    admitted role-bound ``INITIAL_AUTHORITY`` surface; it does not consume it.
    """

    return _admitted_native_supervisor_module() is not None


def acquire_native_guest_runtime_authorities() -> NativeGuestRuntimeAuthorities:
    """Consume role-2 startup into one explicit backend/tool authority pair.

    The native request projection is read before the one-shot consume, decoded
    through the same strict parser as the installed POSIX front door, and the
    snapshot-tool custody is acquired from that exact still-live role-2 initial
    before it is irreversibly consumed.  The result is process-local and must
    be explicitly threaded by the driver; no module-global authority, ambient
    environment, or serializable request field participates in the handoff.
    """

    module = _admitted_native_supervisor_module()
    if module is None:
        _fail(
            "NATIVE_BRIDGE_UNAVAILABLE",
            "authenticated native broker v2 INITIAL_AUTHORITY is unavailable",
        )
    initial = module.INITIAL_AUTHORITY
    try:
        projection = type(initial).__dict__["request_projection"](initial)
        import posix_audit_entrypoint as entrypoint
        import posix_audit_supervisor as supervisor

        request = entrypoint._decode_request_projection(projection, supervisor)
        if type(request) is not supervisor.AuditRequest:
            _fail(
                "NATIVE_GUEST_REQUEST",
                "native guest request projection has the wrong exact type",
            )
        runtime_identity = _validate_native_tool_runtime_identity(
            module.darwin_tool_runtime_identity(initial)
        )
        backend_install_generation = module.acquire_backend_install_generation(
            initial, request.backend,
        )
        if type(backend_install_generation) is not (
            module.BackendInstallGenerationAuthority
        ):
            _fail(
                "NATIVE_GUEST_BACKEND_INSTALL_GENERATION",
                "native installed backend generation has the wrong exact type",
            )
        js_initial = module.JS_DEPENDENCY_MATERIALIZER_INITIAL_AUTHORITY
        if type(js_initial) is not module.JSDependencyMaterializerAuthority:
            _fail(
                "NATIVE_GUEST_JS_CUSTODY",
                "native JavaScript materializer custody has the wrong exact type",
            )
        js_runtime_identity = _validate_native_js_runtime_identity(
            module.js_dependency_materializer_runtime_identity(js_initial)
        )
        managed_initial = module.MANAGED_EVM_TOOLCHAIN_INITIAL_AUTHORITY
        if type(managed_initial) is not module.ManagedEVMToolchainInitialAuthority:
            _fail(
                "NATIVE_GUEST_MANAGED_CUSTODY",
                "native managed-EVM custody has the wrong exact type",
            )
        managed_runtime_identity = _validate_native_managed_runtime_identity(
            module.managed_evm_toolchain_runtime_identity(managed_initial)
        )
        tool_custody = module.acquire_darwin_tool_custody(initial)
        if type(tool_custody) is not module.DarwinToolCustodyAuthority:
            _fail(
                "NATIVE_GUEST_TOOL_CUSTODY",
                "native guest tool custody has the wrong exact type",
            )
        bundle = type(initial).__dict__["consume_once"](
            initial,
            request.fingerprint_sha256,
            request.attempt_id,
        )
    except BaseException as exc:
        _fail(
            "NATIVE_GUEST_ACQUISITION",
            "native guest request, tool custody, or consume failed closed",
            exc,
        )
    if type(bundle) is not module.GuestDriverAuthorities:
        _fail(
            "NATIVE_GUEST_BUNDLE",
            "native role-2 consume returned the wrong static bundle type",
        )
    try:
        members = type(bundle).__dict__["consume_once"](bundle)
    except BaseException as exc:
        _fail(
            "NATIVE_GUEST_BUNDLE",
            "native guest authority bundle failed closed",
            exc,
        )
    if (
        type(members) is not tuple
        or len(members) != 1
        or type(members[0]) is not module.BackendExecutionAuthority
    ):
        _fail(
            "NATIVE_GUEST_BUNDLE",
            "native guest authority bundle has the wrong exact member roster",
        )
    authority = object.__new__(NativeGuestRuntimeAuthorities)
    object.__setattr__(
        authority, "_NativeGuestRuntimeAuthorities__token", object(),
    )
    record = _NativeGuestRuntimeRecord(
        module=module,
        initial=initial,
        request=request,
        backend_execution=members[0],
        backend_install_generation=backend_install_generation,
        tool_custody=tool_custody,
        tool_runtime_identity=runtime_identity,
        js_initial=js_initial,
        js_runtime_identity=js_runtime_identity,
        managed_initial=managed_initial,
        managed_runtime_identity=managed_runtime_identity,
        creator_pid=os.getpid(),
        request_fingerprint_sha256=request.fingerprint_sha256,
        attempt_id=request.attempt_id,
        run_id=request.run_id,
        backend=request.backend,
    )
    with _NATIVE_GUEST_RUNTIME_LOCK:
        _LIVE_NATIVE_GUEST_RUNTIME_AUTHORITIES[authority] = record
    return authority


def acquire_native_guest_backend_execution_authority() -> tuple[Any, Any]:
    """Compatibility projection of the complete native guest acquisition.

    New driver code must retain :class:`NativeGuestRuntimeAuthorities`; this
    projection intentionally cannot preserve snapshot-tool custody after its
    temporary complete authority is released.
    """

    runtime = acquire_native_guest_runtime_authorities()
    return (
        authenticated_native_guest_request(runtime),
        native_guest_backend_execution_authority(runtime),
    )


def _provider_stdout_contract(
    backend: str,
    configuration: Mapping[str, Any] | None,
    resolved_version: str,
) -> dict[str, Any]:
    """Extract the Claude semantic denominator needed by the launch issuer."""

    if backend == "codex":
        if configuration is not None:
            _fail(
                "PROVIDER_STDOUT_CONTRACT",
                "Codex cannot carry a Claude stdout contract",
            )
        return {}
    fields = {
        "schema", "expected_session_id", "expected_init_contract",
        "max_line_bytes", "max_stream_bytes",
    }
    if not isinstance(configuration, Mapping) or set(configuration) != fields:
        _fail(
            "PROVIDER_STDOUT_CONTRACT",
            "Claude stdout contract is absent or malformed",
        )
    session_id = configuration.get("expected_session_id")
    try:
        canonical_session_id = str(uuid.UUID(str(session_id)))
    except (ValueError, TypeError, AttributeError) as exc:
        _fail(
            "PROVIDER_STDOUT_CONTRACT",
            "Claude stdout session is invalid",
            exc,
        )
    if session_id != canonical_session_id:
        _fail(
            "PROVIDER_STDOUT_CONTRACT",
            "Claude stdout session is not canonical",
        )
    expected_init = configuration.get("expected_init_contract")
    if not isinstance(expected_init, Mapping):
        _fail(
            "PROVIDER_STDOUT_CONTRACT",
            "Claude expected-init contract is absent",
        )
    tools = expected_init.get("allowed_tools")
    if (
        not isinstance(tools, list)
        or any(type(item) is not str or not item for item in tools)
        or tools != sorted(set(tools))
    ):
        _fail(
            "PROVIDER_STDOUT_CONTRACT",
            "Claude tool denominator is not canonical",
        )
    if (
        expected_init.get("claude_code_version") != resolved_version
        or expected_init.get("permission_mode") != "dontAsk"
        or expected_init.get("required_capabilities")
        != ["vendor-restricted-analysis"]
        or expected_init.get("allowed_mcp_servers") != []
        or expected_init.get("required_mcp_servers") != []
        or expected_init.get("allowed_tool_prefixes") != []
    ):
        _fail(
            "PROVIDER_STDOUT_CONTRACT",
            "Claude POSIX launch is outside the reviewed offline lane",
        )
    return {
        "schema": "plamen.posix_backend_provider_stdout_contract.v1",
        "session_id": canonical_session_id,
        "claude_code_version": resolved_version,
        "permission_mode": "dontAsk",
        "claude_tools": list(tools),
        "expected_init_contract_sha256": _mapping_sha(expected_init),
    }


def prepare_posix_backend_execution(
    *, backend: str, model: str, attempt_id: str,
    outer_attempt_arm_sha256: str, work_plan_sha256: str,
    process_scope_identity: str, base_argv: Sequence[str],
    base_environment: Mapping[str, str], cwd: str | Path,
    prompt_path: str | Path, prompt_sha256: str,
    provider_stdout_evidence_configuration: Mapping[str, Any] | None = None,
    native_authority: object, timeout_seconds: int,
    stdout_limit_bytes: int, stderr_limit_bytes: int,
    backend_install_generation_authority: object | None = None,
) -> PosixBackendExecution:
    """Prepare one replayable operation through an explicit native authority.

    Guest startup consumes ``GuestDriverAuthorities`` once and threads its one
    shared ``BackendExecutionAuthority`` into every call.  This function has no
    default/import/cache/registry acquisition path.  Native authority admission
    is the first effect and occurs before any request value or filesystem path
    is inspected.
    """

    native = _require_native_backend_authority_before_request(native_authority)
    if type(backend) is not str or backend not in {"codex", "claude"}:
        _fail("BACKEND", "POSIX backend must be codex or claude")
    try:
        install_generation = _launch_policy.require_backend_install_generation(
            backend_install_generation_authority,
        )
    except _launch_policy.PosixBackendLaunchPolicyError as exc:
        _fail(
            "INSTALL_GENERATION_AUTHORITY",
            "production backend install authority is unavailable",
            exc,
        )
    if install_generation.backend != backend:
        _fail(
            "INSTALL_GENERATION_BACKEND",
            "backend differs from authenticated install generation",
        )
    _identifier(attempt_id, "attempt id")
    _identifier(process_scope_identity, "process scope identity")
    _hex(outer_attempt_arm_sha256, "outer arm")
    _hex(work_plan_sha256, "work plan")
    _hex(prompt_sha256, "prompt")
    provider_stdout_contract = _provider_stdout_contract(
        backend, provider_stdout_evidence_configuration,
        install_generation.resolved_version,
    )
    cwd_locator = Path(cwd)
    prompt_locator = Path(prompt_path)
    if prompt_locator.is_symlink():
        _fail("BOUND_PATH", "prompt path cannot be a symbolic link")
    try:
        root = cwd_locator.resolve(strict=True)
        prompt = prompt_locator.resolve(strict=True)
    except OSError as exc:
        _fail("BOUND_PATH", "cwd or prompt path is unavailable", exc)
    if not root.is_dir() or not prompt.is_file():
        _fail("BOUND_PATH", "cwd or prompt path is unsafe")
    try:
        raw_prompt = prompt.read_bytes()
        cwd_stat = os.stat(root, follow_symlinks=False)
    except OSError as exc:
        _fail("BOUND_PATH", "cwd or prompt could not be measured", exc)
    if not _same_digest(_sha(raw_prompt), prompt_sha256):
        _fail("PROMPT_DRIFT", "attempt prompt changed after the outer arm")
    cwd_identity = _mapping_sha({
        "device": int(cwd_stat.st_dev),
        "inode": int(cwd_stat.st_ino),
        "mode": int(cwd_stat.st_mode),
        "owner": int(cwd_stat.st_uid),
        "group": int(cwd_stat.st_gid),
        "mtime_ns": int(cwd_stat.st_mtime_ns),
        "ctime_ns": int(cwd_stat.st_ctime_ns),
    })
    envelope = native_backend_execution_envelope_v2(
        backend=backend,
        model=model,
        attempt_id=attempt_id,
        outer_attempt_arm_sha256=outer_attempt_arm_sha256,
        work_plan_sha256=work_plan_sha256,
        process_scope_identity=process_scope_identity,
        base_argv=base_argv,
        base_environment=base_environment,
        cwd_identity_sha256=cwd_identity,
        prompt_sha256=prompt_sha256,
        provider_stdout_contract_sha256=_mapping_sha(provider_stdout_contract),
        timeout_seconds=timeout_seconds,
        stdout_limit_bytes=stdout_limit_bytes,
        stderr_limit_bytes=stderr_limit_bytes,
        backend_install_generation_authority=(
            backend_install_generation_authority
        ),
    )
    prepare_request, operation_key = _prepare_request(envelope)
    raw_receipt = _native_prepare(native, prepare_request)
    prepared = parse_native_prepared_receipt(
        raw_receipt,
        operation_key_sha256=operation_key,
        prepare_request_sha256=_sha(prepare_request),
        execution_envelope_sha256=_sha(envelope),
        timeout_seconds=timeout_seconds,
        stdout_limit_bytes=stdout_limit_bytes,
        stderr_limit_bytes=stderr_limit_bytes,
    )
    wer_binding = canonical_json_bytes({
        "schema": "plamen.posix_backend_execution_wer_binding.v2",
        "attempt_id": attempt_id,
        "backend": backend,
        "model": model,
        "outer_attempt_arm_sha256": outer_attempt_arm_sha256,
        "work_plan_sha256": work_plan_sha256,
        "process_scope_identity": process_scope_identity,
        "backend_resolved_version": install_generation.resolved_version,
        "install_generation_sha256": (
            install_generation.install_generation_sha256
        ),
        "cli_behavior_contract_sha256": (
            install_generation.cli_behavior_contract_sha256
        ),
        "cli_conformance_sha256": install_generation.cli_conformance_sha256,
        "operation_key_sha256": operation_key,
        "execution_envelope_sha256": _sha(envelope),
        "prepare_request_sha256": _sha(prepare_request),
        "prepared_receipt_sha256": prepared.sha256,
        "retained_fd_roster_sha256": prepared.retained_fd_roster_sha256,
        "preparation_generation_sha256": (
            prepared.preparation_generation_sha256
        ),
        "provider_stdout_contract": provider_stdout_contract,
        "provider_stdout_contract_sha256": _mapping_sha(
            provider_stdout_contract
        ),
        "timeout_seconds": prepared.timeout_seconds,
        "stdout_requested_limit_bytes": (
            prepared.stdout_requested_limit_bytes
        ),
        "stderr_requested_limit_bytes": (
            prepared.stderr_requested_limit_bytes
        ),
        "stdout_effective_limit_bytes": (
            prepared.stdout_effective_limit_bytes
        ),
        "stderr_effective_limit_bytes": (
            prepared.stderr_effective_limit_bytes
        ),
        "authority_class": "NATIVE_STATIC_ROLE2_OPERATION_RECEIPT_ONLY",
    })
    return _new_native_backend_execution(
        native, prepared, wer_binding=wer_binding,
    )


def _TEST_ONLY_prepare_posix_backend_execution(
    *, backend: str, model: str, attempt_id: str,
    outer_attempt_arm_sha256: str, work_plan_sha256: str,
    process_scope_identity: str, base_argv: Sequence[str],
    base_environment: Mapping[str, str], cwd: str | Path,
    prompt_path: str | Path, prompt_sha256: str,
    provider_stdout_evidence_configuration: Mapping[str, Any] | None = None,
) -> TestOnlyPosixBackendExecution:
    """Reserve and consume one structural-test synthetic outer authority."""

    # These are deliberately the first observations in this entry point.  A
    # consumer or verifier may fork; no authority may then be minted in the
    # child from the interrupted parent call stack.
    entry_pid = os.getpid()
    entry_interpreter_nonce = _INTERPRETER_NONCE
    if type(attempt_id) is not str:
        _fail("BINDING_ID", "attempt id is not a canonical identifier")
    if type(outer_attempt_arm_sha256) is not str:
        _fail("BINDING_DIGEST", "outer arm is not an exact sha256")
    if type(process_scope_identity) is not str:
        _fail(
            "BINDING_ID",
            "process scope identity is not a canonical identifier",
        )
    _identifier(attempt_id, "attempt id")
    _hex(outer_attempt_arm_sha256, "outer arm")
    _identifier(process_scope_identity, "process scope identity")
    issuance_key = (
        attempt_id, outer_attempt_arm_sha256, process_scope_identity,
    )
    generation = _reserve_test_only_issuance(
        issuance_key,
        creator_pid=entry_pid,
        interpreter_nonce=entry_interpreter_nonce,
    )
    try:
        authority = _TEST_ONLY_prepare_reserved_posix_backend_execution(
            backend=backend,
            model=model,
            attempt_id=attempt_id,
            outer_attempt_arm_sha256=outer_attempt_arm_sha256,
            work_plan_sha256=work_plan_sha256,
            process_scope_identity=process_scope_identity,
            base_argv=base_argv,
            base_environment=base_environment,
            cwd=cwd,
            prompt_path=prompt_path,
            prompt_sha256=prompt_sha256,
            provider_stdout_evidence_configuration=(
                provider_stdout_evidence_configuration
            ),
            _entry_pid=entry_pid,
            _entry_interpreter_nonce=entry_interpreter_nonce,
        )
        _assert_issuance_process_context(
            entry_pid, entry_interpreter_nonce
        )
    except BaseException:
        _transition_test_only_issuance(
            issuance_key, generation, "QUARANTINED"
        )
        raise
    _transition_test_only_issuance(issuance_key, generation, "ISSUED")
    return authority


def _TEST_ONLY_prepare_reserved_posix_backend_execution(
    *, backend: str, model: str, attempt_id: str,
    outer_attempt_arm_sha256: str, work_plan_sha256: str,
    process_scope_identity: str, base_argv: Sequence[str],
    base_environment: Mapping[str, str], cwd: str | Path,
    prompt_path: str | Path, prompt_sha256: str,
    provider_stdout_evidence_configuration: Mapping[str, Any] | None,
    _entry_pid: int, _entry_interpreter_nonce: str,
) -> TestOnlyPosixBackendExecution:
    """Consume one already-reserved TEST_ONLY issuance."""

    _assert_issuance_process_context(_entry_pid, _entry_interpreter_nonce)

    if type(backend) is not str or backend not in {"codex", "claude"}:
        _fail("BACKEND", "POSIX backend must be codex or claude")
    _identifier(attempt_id, "attempt id")
    _identifier(process_scope_identity, "process scope identity")
    _hex(outer_attempt_arm_sha256, "outer arm")
    _hex(work_plan_sha256, "work plan")
    _hex(prompt_sha256, "prompt")
    if type(model) is not str or not model or len(model) > 128 or "\x00" in model:
        _fail("MODEL", "model is invalid")
    if (
        not isinstance(base_argv, Sequence)
        or isinstance(base_argv, (str, bytes))
        or not base_argv
        or any(type(item) is not str or not item or "\x00" in item for item in base_argv)
    ):
        _fail("BASE_ARGV", "base argv is invalid")
    if any(type(key) is not str or type(value) is not str
           for key, value in base_environment.items()):
        _fail("BASE_ENVIRONMENT", "base environment is invalid")
    # This explicitly structural lane predates install-generation authority.
    # Preserve only its legacy fixture semantics; production preparation above
    # always supplies the resolved version from authenticated generation
    # custody.  Claude's fixture version is already part of the exact expected
    # init contract, while Codex has no provider-stdout contract.
    fixture_version = ""
    if backend == "claude" and isinstance(
        provider_stdout_evidence_configuration, Mapping
    ):
        expected_init = provider_stdout_evidence_configuration.get(
            "expected_init_contract"
        )
        if isinstance(expected_init, Mapping):
            candidate = expected_init.get("claude_code_version")
            if isinstance(candidate, str):
                fixture_version = candidate
    provider_stdout_contract = _provider_stdout_contract(
        backend, provider_stdout_evidence_configuration, fixture_version,
    )
    root = Path(cwd).resolve(strict=True)
    prompt = Path(prompt_path).resolve(strict=True)
    if not root.is_dir() or not prompt.is_file() or prompt.is_symlink():
        _fail("BOUND_PATH", "cwd or prompt path is unsafe")
    raw_prompt = prompt.read_bytes()
    if _sha(raw_prompt) != prompt_sha256:
        _fail("PROMPT_DRIFT", "attempt prompt changed after the outer arm")
    with _LOCK:
        bridge = _TEST_ONLY_BRIDGE
    if bridge is None:
        _fail(
            "TEST_ONLY_OUTER_SUPERVISOR_REQUIRED",
            "test-only outer-supervisor consumer and verifier are not registered",
        )
    request = {
        "schema": "plamen.posix_backend_execution_request.v1",
        "backend": backend,
        "model": model,
        "attempt_id": attempt_id,
        "outer_attempt_arm_sha256": outer_attempt_arm_sha256,
        "work_plan_sha256": work_plan_sha256,
        "process_scope_identity": process_scope_identity,
        "base_argv_sha256": _argv_sha(tuple(base_argv)),
        "base_environment_sha256": _environment_sha(base_environment),
        "cwd": str(root),
        "cwd_identity_sha256": "",
        "prompt_sha256": prompt_sha256,
        "provider_stdout_contract": provider_stdout_contract,
        "provider_stdout_contract_sha256": _mapping_sha(
            provider_stdout_contract
        ),
    }
    # Re-open via a descriptor immediately before handing the locator to the
    # trusted consumer.  The policy renderer retains and remeasures its own FD.
    plan: object | None = None
    prompt_fd = os.open(prompt, os.O_RDONLY)
    try:
        # Replace the temporary cwd descriptor binding above with a leak-free
        # path observation.  The cwd identity is informational outer binding;
        # the launch policy independently retains its exact control directory.
        cwd_stat = os.stat(root, follow_symlinks=False)
        request["cwd_identity_sha256"] = _mapping_sha({
            "device": int(cwd_stat.st_dev), "inode": int(cwd_stat.st_ino),
            "mode": int(cwd_stat.st_mode), "owner": int(cwd_stat.st_uid),
            "group": int(cwd_stat.st_gid),
            "mtime_ns": int(cwd_stat.st_mtime_ns),
            "ctime_ns": int(cwd_stat.st_ctime_ns),
        })
        try:
            result = bridge.consumer.consume_posix_backend_launch(
                MappingProxyType(dict(request)), prompt_fd=prompt_fd,
            )
            _assert_issuance_process_context(
                _entry_pid, _entry_interpreter_nonce,
                policy_object=(
                    result[0]
                    if type(result) is tuple and len(result) == 2
                    else None
                ),
            )
            if type(result) is not tuple or len(result) != 2:
                _fail("OUTER_CONSUME", "outer consumer result is not an exact pair")
            plan, outer_receipt = result
        except BaseException as exc:
            _assert_issuance_process_context(
                _entry_pid, _entry_interpreter_nonce,
                policy_object=plan,
            )
            if isinstance(exc, PosixBackendExecutionError):
                if type(plan) is TestOnlyBackendLaunchPlan:
                    try:
                        plan.close()
                        _assert_issuance_process_context(
                            _entry_pid, _entry_interpreter_nonce
                        )
                    except BaseException:
                        _assert_issuance_process_context(
                            _entry_pid, _entry_interpreter_nonce
                        )
                        pass
                raise
            _fail("OUTER_CONSUME", "outer supervisor context was rejected", exc)
    finally:
        os.close(prompt_fd)
    if type(plan) is not TestOnlyBackendLaunchPlan:
        _fail("PLAN", "test-only consumer returned a foreign launch plan")
    try:
        plan_receipt = plan.public_receipt_bytes()
        _assert_issuance_process_context(
            _entry_pid, _entry_interpreter_nonce,
            policy_object=plan,
        )
        public = plan.validate_public_receipt(plan_receipt)
        _assert_issuance_process_context(
            _entry_pid, _entry_interpreter_nonce,
            policy_object=plan,
        )
        public_binding_sha256 = plan.public_binding_sha256()
        _assert_issuance_process_context(
            _entry_pid, _entry_interpreter_nonce,
            policy_object=plan,
        )
        sealed_content = public.get("sealed_content_sha256")
        sealed_policy = public.get("sealed_policy")
        policy_identity_valid = (
            public.get("schema") == TEST_ONLY_PUBLIC_RECEIPT_SCHEMA
            and public.get("status")
            == "TEST_ONLY_NOT_ISSUED_FOR_PRODUCTION"
            and public.get("authority_class")
            == TEST_ONLY_AUTHORITY_CLASS
            and public.get("completion_receipt_schema")
            == TEST_ONLY_COMPLETION_RECEIPT_SCHEMA
        )
        if (
            public_binding_sha256 != _sha(plan_receipt)
            or not policy_identity_valid
            or public.get("completion_required") is not True
            or public.get("attempt_id") != attempt_id
            or public.get("backend") != backend
            or public.get("model") != model
            or not isinstance(sealed_content, Mapping)
            or sealed_content.get("prompt") != prompt_sha256
            or not isinstance(sealed_policy, Mapping)
            or set(sealed_policy) != _SEALED_POLICY_FIELDS
        ):
            _fail("PLAN_SUBSTITUTION", "launch plan identity differs")
        isolation_mode = sealed_policy.get("credential_isolation_mode")
        if (
            isolation_mode
            not in {
                "NATIVE_PROCESS_DOMAIN_SPLIT_NO_DESCENDANT_READ_V1",
                "OUT_OF_PROCESS_CREDENTIAL_BROKER_NO_DESCENDANT_READ_V1",
            }
            or _HEX64_RE.fullmatch(
                str(sealed_policy.get("credential_isolation_sha256") or "")
            )
            is None
        ):
            _fail(
                "CREDENTIAL_ISOLATION",
                "launch plan lacks descendant credential denial authority",
            )
        if backend == "codex":
            policy_shape_valid = (
                _HEX64_RE.fullmatch(
                    str(sealed_policy.get("codex_profile_sha256") or "")
                )
                is not None
                and sealed_policy.get("claude_settings_contract") is None
                and sealed_policy.get("claude_settings_sha256") is None
                and sealed_policy.get("claude_mcp_sha256") is None
                and sealed_policy.get("codex_permission_profile_status")
                == "DEFENSE_IN_DEPTH_UNPROVEN_CODEX_0_152_0"
                and sealed_policy.get("codex_config_census_contract")
                == _CODEX_CONFIG_CENSUS_CONTRACT
                and _HEX64_RE.fullmatch(str(sealed_policy.get(
                    "codex_config_census_contract_sha256"
                ) or "")) is not None
                and _HEX64_RE.fullmatch(str(sealed_policy.get(
                    "codex_config_census_evidence_sha256"
                ) or "")) is not None
            )
        else:
            policy_shape_valid = (
                sealed_policy.get("codex_profile_sha256") is None
                and sealed_policy.get("claude_settings_contract")
                == "POSIX_NATIVE_SANDBOX_DONTASK_V1"
                and _HEX64_RE.fullmatch(
                    str(sealed_policy.get("claude_settings_sha256") or "")
                )
                is not None
                and _HEX64_RE.fullmatch(
                    str(sealed_policy.get("claude_mcp_sha256") or "")
                )
                is not None
                and sealed_policy.get("codex_permission_profile_status")
                == "NOT_APPLICABLE"
                and sealed_policy.get("codex_config_census_contract") is None
                and sealed_policy.get(
                    "codex_config_census_contract_sha256"
                ) is None
                and sealed_policy.get(
                    "codex_config_census_evidence_sha256"
                ) is None
            )
        if not policy_shape_valid:
            _fail("PLAN_SUBSTITUTION", "sealed backend policy differs")
        outer = _strict_json(outer_receipt, label="outer authority receipt")
        if set(outer) != _OUTER_FIELDS:
            _fail("OUTER_RECEIPT", "outer authority receipt fields drifted")
        expected = {
            "schema": OUTER_AUTHORITY_SCHEMA,
            "attempt_id": attempt_id,
            "backend": backend,
            "model": model,
            "outer_attempt_arm_sha256": outer_attempt_arm_sha256,
            "work_plan_sha256": work_plan_sha256,
            "process_scope_identity": process_scope_identity,
            "base_argv_sha256": request["base_argv_sha256"],
            "base_environment_sha256": request["base_environment_sha256"],
            "cwd_identity_sha256": request["cwd_identity_sha256"],
            "prompt_sha256": prompt_sha256,
            "provider_stdout_contract_sha256": request[
                "provider_stdout_contract_sha256"
            ],
            "plan_receipt_sha256": _sha(plan_receipt),
        }
        if any(outer.get(key) != value for key, value in expected.items()):
            _fail("OUTER_RECEIPT", "outer authority binding drifted")
        provider_context = _hex(
            outer.get("provider_context_sha256"), "provider context"
        )
        descendant_credential_denial = _hex(
            outer.get("descendant_credential_denial_sha256"),
            "descendant credential denial authority",
        )
        if descendant_credential_denial != sealed_policy[
            "credential_isolation_sha256"
        ]:
            _fail(
                "CREDENTIAL_ISOLATION",
                "outer verifier and launch policy isolation proofs differ",
            )
        nonce = _identifier(outer.get("context_nonce"), "context nonce")
        issued = outer.get("issued_at_unix_ns")
        expires = outer.get("expires_at_unix_ns")
        if (
            type(issued) is not int or type(expires) is not int
            or expires <= issued or expires - issued > MAX_AUTHORITY_LIFETIME_NS
        ):
            _fail("OUTER_TIME", "outer authority lifetime is invalid")
        replay_key = (attempt_id, nonce, provider_context)
        with _LOCK:
            if replay_key in _TEST_ONLY_CONSUMED_CONTEXTS:
                _fail("OUTER_REPLAY", "outer authority was already consumed")
            _TEST_ONLY_CONSUMED_CONTEXTS.add(replay_key)
        now = time.time_ns()
        if issued > now + MAX_CLOCK_SKEW_NS or expires <= now:
            _fail("OUTER_STALE", "outer authority is stale or future-dated")
        _verify_external(
            bridge, "CONSUME", outer_receipt, outer,
            issuance_process_context=(
                _entry_pid, _entry_interpreter_nonce
            ),
        )
    except BaseException:
        _assert_issuance_process_context(
            _entry_pid, _entry_interpreter_nonce
        )
        plan.close()
        _assert_issuance_process_context(
            _entry_pid, _entry_interpreter_nonce
        )
        raise
    _assert_issuance_process_context(_entry_pid, _entry_interpreter_nonce)
    authority = object.__new__(TestOnlyPosixBackendExecution)
    token = os.urandom(32).hex()
    generation = os.urandom(32).hex()
    creator_pid = _entry_pid
    interpreter_nonce = _entry_interpreter_nonce
    object.__setattr__(
        authority,
        "_TestOnlyPosixBackendExecution__token",
        token,
    )
    object.__setattr__(
        authority,
        "_TestOnlyPosixBackendExecution__creator_pid",
        creator_pid,
    )
    object.__setattr__(
        authority,
        "_TestOnlyPosixBackendExecution__interpreter_nonce",
        interpreter_nonce,
    )
    identity = id(authority)
    authority_ref = weakref.ref(
        authority,
        lambda _unused, key=identity, bound_generation=generation,
        retire=_retire_abandoned_test_only_execution:
        retire(key, bound_generation),
    )
    _assert_issuance_process_context(_entry_pid, _entry_interpreter_nonce)
    try:
        with _LOCK:
            _assert_issuance_process_context(
                _entry_pid, _entry_interpreter_nonce
            )
            _TEST_ONLY_EXECUTIONS[identity] = _ExecutionRecord(
                token=token, generation=generation, creator_pid=creator_pid,
                interpreter_nonce=interpreter_nonce,
                authority_ref=authority_ref,
                bridge=bridge, plan=plan,
                request=MappingProxyType(dict(request)),
                outer_receipt=bytes(outer_receipt),
                outer=MappingProxyType(outer),
                plan_receipt=bytes(plan_receipt),
            )
        _assert_issuance_process_context(
            _entry_pid, _entry_interpreter_nonce
        )
    except BaseException:
        _assert_issuance_process_context(
            _entry_pid, _entry_interpreter_nonce
        )
        with _LOCK:
            inserted = _TEST_ONLY_EXECUTIONS.get(identity)
            if (
                inserted is not None
                and inserted.generation == generation
                and inserted.authority_ref() is authority
            ):
                _TEST_ONLY_EXECUTIONS.pop(identity, None)
        plan.close()
        _assert_issuance_process_context(
            _entry_pid, _entry_interpreter_nonce
        )
        raise
    return authority


def _record(value: TestOnlyPosixBackendExecution) -> _ExecutionRecord:
    creator_pid, interpreter_nonce = _assert_test_only_creator(value)
    with _LOCK:
        record = _TEST_ONLY_EXECUTIONS.get(id(value))
    if record is None:
        _fail("EXECUTION", "POSIX backend execution authority is forged or closed")
    if record.authority_ref() is not value:
        _fail(
            "EXECUTION",
            "POSIX backend execution authority object identity drifted",
        )
    try:
        token = object.__getattribute__(
            value, "_TestOnlyPosixBackendExecution__token"
        )
    except AttributeError as exc:
        _fail("EXECUTION", "POSIX backend execution authority is incomplete", exc)
    if (
        type(token) is not str or not token or token != record.token
        or record.creator_pid != creator_pid
        or record.interpreter_nonce != interpreter_nonce
    ):
        _fail("EXECUTION", "POSIX backend execution authority token drifted")
    return record


def _assert_test_only_creator(
    value: TestOnlyPosixBackendExecution,
) -> tuple[int, str]:
    if type(value) is not TestOnlyPosixBackendExecution:
        _fail("EXECUTION", "test-only POSIX execution authority is invalid")
    try:
        creator_pid = object.__getattribute__(
            value, "_TestOnlyPosixBackendExecution__creator_pid"
        )
        interpreter_nonce = object.__getattribute__(
            value, "_TestOnlyPosixBackendExecution__interpreter_nonce"
        )
    except AttributeError as exc:
        _fail("EXECUTION", "POSIX backend execution authority is incomplete", exc)
    if creator_pid != os.getpid() or interpreter_nonce != _INTERPRETER_NONCE:
        _fail(
            "EXECUTION_FORK_REPLAY",
            "POSIX backend execution authority crossed a process boundary",
        )
    return creator_pid, interpreter_nonce


def _validate_safe_argv(argv: Sequence[str]) -> None:
    if not argv or any(type(item) is not str or not item or "\x00" in item for item in argv):
        _fail("FINAL_ARGV", "final backend argv is invalid")
    for item in argv:
        if item in _FORBIDDEN_ARGV or item.startswith("--sandbox="):
            _fail("FINAL_ARGV", f"forbidden POSIX backend flag: {item}")
    if not argv[0].startswith("/proc/self/fd/"):
        _fail("FINAL_ARGV", "backend executable is not descriptor-pinned")


def _consume_invocation_snapshot(
    record: _ExecutionRecord, *, process_context: tuple[int, str],
) -> None:
    if record.state != "PREVIEW_IN_PROGRESS":
        _fail("EXECUTION_STATE", "launch plan is not consumable")
    invocation: TestOnlyBackendLaunchInvocation | None = None
    try:
        invocation = record.plan.consume()
        _assert_execution_process_context(
            *process_context, record=record, policy_object=invocation,
        )
        if type(invocation) is not TestOnlyBackendLaunchInvocation:
            _fail("INVOCATION", "test-only plan returned a foreign invocation")
        issuance_receipt = invocation.issuance_receipt_bytes()
        _assert_execution_process_context(
            *process_context, record=record,
        )
        validated_receipt = invocation.validate_issuance_receipt(
            record.plan_receipt
        )
        _assert_execution_process_context(
            *process_context, record=record,
        )
        if (
            issuance_receipt != record.plan_receipt
            or dict(validated_receipt) != _strict_json(
                record.plan_receipt, label="backend launch issuance receipt"
            )
        ):
            _fail("INVOCATION_SUBSTITUTION", "invocation receipt differs")
        raw_argv = invocation.argv
        _assert_execution_process_context(
            *process_context, record=record,
        )
        argv = tuple(raw_argv)
        raw_environment = invocation.environment
        _assert_execution_process_context(
            *process_context, record=record,
        )
        environment = MappingProxyType(dict(raw_environment))
        cwd_fd = invocation.cwd_fd
        _assert_execution_process_context(
            *process_context, record=record,
        )
        stdin_fd = invocation.stdin_fd
        _assert_execution_process_context(
            *process_context, record=record,
        )
        raw_pass_fds = invocation.pass_fds
        _assert_execution_process_context(
            *process_context, record=record,
        )
        pass_fds = tuple(raw_pass_fds)
        credential_fd = invocation.credential_fd
        _assert_execution_process_context(
            *process_context, record=record,
        )
        codex_profile_fd = invocation.codex_profile_fd
        _assert_execution_process_context(
            *process_context, record=record,
        )
        private_fds = tuple(sorted({
            credential_fd,
            *(() if codex_profile_fd is None else (codex_profile_fd,)),
        }))
        if (
            type(credential_fd) is not int
            or credential_fd < 0
            or (
                codex_profile_fd is not None
                and (type(codex_profile_fd) is not int or codex_profile_fd < 0)
            )
            or set(private_fds) & set(pass_fds)
        ):
            _fail(
                "FD_DENOMINATOR",
                "private materialization descriptors are not isolated",
            )
        _validate_safe_argv(argv)
        if (
            pass_fds != tuple(sorted(set(pass_fds)))
            or cwd_fd not in pass_fds
            or stdin_fd not in pass_fds
        ):
            _fail("FD_DENOMINATOR", "invocation FD denominator is incomplete")
        executable_text = argv[0].removeprefix("/proc/self/fd/")
        if not executable_text.isdecimal() or int(executable_text) not in pass_fds:
            _fail("FD_DENOMINATOR", "executable FD is not inherited")
        fd_rows = [
            _fd_binding(fd, f"retained-{index:03d}")
            for index, fd in enumerate(pass_fds)
        ]
        issuance = _strict_json(
            record.plan_receipt,
            label="backend launch issuance receipt",
        )
        sealed_content = issuance.get("sealed_content_sha256")
        sealed_policy = issuance.get("sealed_policy")
        if (
            not isinstance(sealed_content, Mapping)
            or not sealed_content
            or any(
                type(label) is not str
                or not label
                or type(digest) is not str
                or _HEX64_RE.fullmatch(digest) is None
                for label, digest in sealed_content.items()
            )
        ):
            _fail("INVOCATION_RECEIPT", "sealed content binding is malformed")
        if (
            not isinstance(sealed_policy, Mapping)
            or set(sealed_policy) != _SEALED_POLICY_FIELDS
        ):
            _fail("INVOCATION_RECEIPT", "sealed policy binding is malformed")
        census_bytes = invocation.codex_config_census_contract_bytes()
        _assert_execution_process_context(
            *process_context, record=record,
        )
        if record.request["backend"] == "codex":
            if (
                type(census_bytes) is not bytes
                or not census_bytes
                or _sha(census_bytes) != sealed_policy.get(
                    "codex_config_census_contract_sha256"
                )
            ):
                _fail(
                    "CODEX_CONFIG_CENSUS",
                    "private Codex config census contract differs",
                )
            census = _strict_json(
                census_bytes,
                label="private Codex config census contract",
            )
            if (
                set(census) != {
                    "schema", "phase", "evidence", "postcondition",
                    "private_home", "control_project_config",
                }
                or census.get("schema")
                != "plamen.codex_config_census_contract.v1"
                or census.get("phase")
                != "IMMEDIATELY_BEFORE_BACKEND_EXECVE"
                or census.get("postcondition")
                != "CONFIG_SCOPE_IMMUTABLE_UNTIL_BACKEND_EXECVE"
            ):
                _fail(
                    "CODEX_CONFIG_CENSUS",
                    "private Codex config census contract is malformed",
                )
        elif census_bytes is not None:
            _fail(
                "CODEX_CONFIG_CENSUS",
                "Claude invocation carries a Codex config census contract",
            )
        credential_delivery = invocation.credential_delivery
        _assert_execution_process_context(
            *process_context, record=record,
        )
        profile_delivery = invocation.codex_profile_delivery
        _assert_execution_process_context(
            *process_context, record=record,
        )
        if (
            record.request["backend"] == "codex"
            and (
                credential_delivery != _CODEX_CREDENTIAL_DELIVERY
                or profile_delivery != _CODEX_PROFILE_DELIVERY
            )
        ) or (
            record.request["backend"] == "claude"
            and (
                credential_delivery != _CLAUDE_CREDENTIAL_DELIVERY
                or profile_delivery != "NONE"
            )
        ):
            _fail(
                "MATERIALIZATION_DELIVERY",
                "backend private-state delivery contract differs",
            )
        arm_binding = MappingProxyType({
            "schema": ARM_BINDING_SCHEMA,
            "attempt_id": record.request["attempt_id"],
            "backend": record.request["backend"],
            "model": record.request["model"],
            "outer_attempt_arm_sha256": record.request[
                "outer_attempt_arm_sha256"
            ],
            "work_plan_sha256": record.request["work_plan_sha256"],
            "process_scope_identity": record.request[
                "process_scope_identity"
            ],
            "plan_receipt_sha256": _sha(record.plan_receipt),
            "outer_authority_receipt_sha256": _sha(record.outer_receipt),
            "provider_context_sha256": record.outer[
                "provider_context_sha256"
            ],
            "descendant_credential_denial_sha256": record.outer[
                "descendant_credential_denial_sha256"
            ],
            "final_argv_sha256": _argv_sha(argv),
            "final_environment_sha256": _environment_sha(environment),
            "cwd_fd_identity_sha256": _mapping_sha(
                _fd_binding(cwd_fd, "cwd")
            ),
            "stdin_fd_identity_sha256": _mapping_sha(
                _fd_binding(stdin_fd, "stdin")
            ),
            "pass_fds_identity_sha256": _mapping_sha({"fds": fd_rows}),
            "policy_sealed_content_sha256": dict(sealed_content),
            "policy_sealed_policy": dict(sealed_policy),
            "codex_config_census_contract_sha256": (
                None if census_bytes is None else _sha(census_bytes)
            ),
            "retained_fd_count": len(pass_fds),
            "credential_delivery": credential_delivery,
            "profile_delivery": profile_delivery,
            "status": "PREPARED_AFTER_OUTER_ARM",
        })
    except BaseException:
        _assert_execution_process_context(*process_context, record=record)
        if invocation is not None:
            try:
                invocation.revoke()
                _assert_execution_process_context(
                    *process_context, record=record,
                )
            except BaseException:
                _assert_execution_process_context(
                    *process_context, record=record,
                )
                try:
                    invocation.close()
                    _assert_execution_process_context(
                        *process_context, record=record,
                    )
                except BaseException:
                    _assert_execution_process_context(
                        *process_context, record=record,
                    )
        else:
            record.plan.close()
            _assert_execution_process_context(
                *process_context, record=record,
            )
        _assert_execution_process_context(
            *process_context, record=record,
        )
        record.state = "QUARANTINED"
        raise
    _assert_execution_process_context(
        *process_context, record=record,
    )
    record.invocation = invocation
    record.argv = argv
    record.environment = environment
    record.cwd_fd = cwd_fd
    record.stdin_fd = stdin_fd
    record.pass_fds = pass_fds
    record.private_fds = private_fds
    record.arm_binding = arm_binding
    record.codex_config_census_contract_bytes = census_bytes
    record.state = "INVOCATION_PREPARED"


def _replay_invocation_snapshot(
    record: _ExecutionRecord, *, process_context: tuple[int, str],
) -> None:
    if record.invocation is None:
        _fail("EXECUTION_STATE", "backend invocation is absent")
    raw_argv = record.invocation.argv
    _assert_execution_process_context(*process_context, record=record)
    argv = tuple(raw_argv)
    raw_environment = record.invocation.environment
    _assert_execution_process_context(*process_context, record=record)
    environment = dict(raw_environment)
    cwd_fd = record.invocation.cwd_fd
    _assert_execution_process_context(*process_context, record=record)
    stdin_fd = record.invocation.stdin_fd
    _assert_execution_process_context(*process_context, record=record)
    raw_pass_fds = record.invocation.pass_fds
    _assert_execution_process_context(*process_context, record=record)
    pass_fds = tuple(raw_pass_fds)
    credential_fd = record.invocation.credential_fd
    _assert_execution_process_context(*process_context, record=record)
    codex_profile_fd = record.invocation.codex_profile_fd
    _assert_execution_process_context(*process_context, record=record)
    issuance_receipt = record.invocation.issuance_receipt_bytes()
    _assert_execution_process_context(*process_context, record=record)
    census_bytes = record.invocation.codex_config_census_contract_bytes()
    _assert_execution_process_context(*process_context, record=record)
    if (
        argv != record.argv
        or record.environment is None
        or environment != dict(record.environment)
        or cwd_fd != record.cwd_fd
        or stdin_fd != record.stdin_fd
        or pass_fds != record.pass_fds
        or issuance_receipt != record.plan_receipt
        or census_bytes != record.codex_config_census_contract_bytes
        or tuple(sorted({
            credential_fd,
            *(() if codex_profile_fd is None else (codex_profile_fd,)),
        })) != record.private_fds
    ):
        _fail("PLAN_DRIFT", "retained backend invocation changed")
    if (
        record.arm_binding is None
        or record.cwd_fd is None
        or record.stdin_fd is None
        or record.pass_fds is None
    ):
        _fail("PLAN_DRIFT", "retained backend invocation binding is absent")
    fd_rows = [
        _fd_binding(fd, f"retained-{index:03d}")
        for index, fd in enumerate(record.pass_fds)
    ]
    if (
        _mapping_sha(_fd_binding(record.cwd_fd, "cwd"))
        != record.arm_binding["cwd_fd_identity_sha256"]
        or _mapping_sha(_fd_binding(record.stdin_fd, "stdin"))
        != record.arm_binding["stdin_fd_identity_sha256"]
        or _mapping_sha({"fds": fd_rows})
        != record.arm_binding["pass_fds_identity_sha256"]
    ):
        _fail("PLAN_DRIFT", "retained backend descriptor identity changed")
    _validate_safe_argv(argv)


def _replay_materialized_snapshot(
    record: _ExecutionRecord, *, process_context: tuple[int, str],
) -> None:
    """Rebind the exact post-arm values retained for the final exec boundary."""

    _replay_invocation_snapshot(record, process_context=process_context)
    if (
        record.arm_binding is None
        or record.materialization_binding is None
        or record.materialized_environment is None
    ):
        _fail("MATERIALIZE_DRIFT", "materialized launch binding is absent")
    expected = {
        "final_environment_sha256": _environment_sha(
            record.materialized_environment
        ),
        "cwd_fd_identity_sha256": record.arm_binding[
            "cwd_fd_identity_sha256"
        ],
        "stdin_fd_identity_sha256": record.arm_binding[
            "stdin_fd_identity_sha256"
        ],
        "pass_fds_identity_sha256": record.arm_binding[
            "pass_fds_identity_sha256"
        ],
        "retained_fd_count": record.arm_binding["retained_fd_count"],
    }
    if any(
        record.materialization_binding.get(key) != value
        for key, value in expected.items()
    ):
        _fail(
            "MATERIALIZE_DRIFT",
            "materialized environment or descriptor binding changed",
        )


def _validate_materialized_environment(
    record: _ExecutionRecord, value: Mapping[str, str],
) -> dict[str, str]:
    if type(value) is not dict or any(
        type(key) is not str or type(item) is not str or not key
        or "\x00" in key or "\x00" in item
        for key, item in value.items()
    ):
        _fail("MATERIALIZE_ENV", "materialized environment is invalid")
    result = dict(value)
    base = dict(record.environment)
    if result != base:
        _fail(
            "MATERIALIZE_ENV",
            "backend environment differs from the secret-free policy",
        )
    return result


def _cleanup_failed_materialization(
    record: _ExecutionRecord,
    *,
    inner_arm_sha256: str,
    materialization_receipt: bytes,
    reason_code: str,
    cause: BaseException,
    process_context: tuple[int, str],
) -> None:
    """Require authenticated private-state revocation after any materializer fault."""

    _assert_execution_process_context(*process_context, record=record)
    record.inner_arm_sha256 = inner_arm_sha256
    record.materialization_receipt = bytes(materialization_receipt)
    try:
        _revoke(
            record,
            process_creation_state="MATERIALIZATION_FAILED_BEFORE_PROCESS",
            process_population_zero_proven=True,
            returncode=None,
            reason_code=reason_code,
            process_context=process_context,
        )
    except BaseException as cleanup_exc:
        _assert_execution_process_context(*process_context, record=record)
        _quarantine(record, process_context=process_context)
        _fail(
            "MATERIALIZE_CLEANUP",
            "failed materialization was not provably revoked; "
            f"materializer error was {type(cause).__name__}: {cause}",
            cleanup_exc,
        )
    _assert_execution_process_context(*process_context, record=record)
    record.state = "REVOKED"


def _verify_external(
    bridge: _TestOnlyBridge,
    stage: str,
    receipt: bytes,
    expected: Mapping[str, Any],
    *,
    issuance_process_context: tuple[int, str] | None = None,
    process_context: tuple[int, str] | None = None,
    record: _ExecutionRecord | None = None,
) -> None:
    if process_context is not None:
        if record is None:
            _fail(
                "EXECUTION_STATE",
                "lifecycle verification lacks its execution record",
            )
        _assert_execution_process_context(
            *process_context, record=record,
        )
    try:
        proof = bridge.verifier.verify_posix_backend_receipt(
            stage, bytes(receipt), MappingProxyType(dict(expected))
        )
        if issuance_process_context is not None:
            _assert_issuance_process_context(*issuance_process_context)
        if process_context is not None:
            if record is None:
                _fail(
                    "EXECUTION_STATE",
                    "lifecycle verification lacks its execution record",
                )
            _assert_execution_process_context(
                *process_context, record=record,
            )
    except BaseException as exc:
        if issuance_process_context is not None:
            _assert_issuance_process_context(*issuance_process_context)
        if process_context is not None:
            assert record is not None
            _assert_execution_process_context(
                *process_context, record=record,
            )
        if isinstance(exc, PosixBackendExecutionError):
            raise
        _fail("EXTERNAL_VERIFY", f"external {stage} verification failed", exc)
    required = {
        "schema": EXTERNAL_VERIFICATION_SCHEMA,
        "stage": stage,
        "receipt_sha256": _sha(receipt),
        "expected_sha256": _mapping_sha(expected),
        "valid": True,
    }
    if type(proof) is not dict or proof != required:
        _fail("EXTERNAL_VERIFY", f"external {stage} proof is not exact")


def _revoke(
    record: _ExecutionRecord, *, process_creation_state: str,
    process_population_zero_proven: bool, returncode: int | None,
    reason_code: str,
    process_context: tuple[int, str],
) -> dict[str, Any]:
    if record.materialization_receipt is None or record.inner_arm_sha256 is None:
        _fail("EXECUTION_STATE", "materialization receipt is absent")
    expected = {
        "schema": REVOCATION_SCHEMA,
        "attempt_id": record.request["attempt_id"],
        "backend": record.request["backend"],
        "inner_arm_sha256": record.inner_arm_sha256,
        "process_scope_identity": record.request["process_scope_identity"],
        "plan_receipt_sha256": _sha(record.plan_receipt),
        "materialization_receipt_sha256": _sha(record.materialization_receipt),
        "process_creation_state": _identifier(
            process_creation_state, "process creation state"
        ),
        "process_population_zero_proven": process_population_zero_proven,
        "returncode": returncode,
        "reason_code": _identifier(reason_code, "reason code"),
        "status": "PRIVATE_STATE_REVOKED",
    }
    try:
        receipt = record.bridge.consumer.revoke_posix_backend_launch(
            record.materialization_receipt, MappingProxyType(dict(expected))
        )
        _assert_execution_process_context(*process_context, record=record)
    except BaseException as exc:
        _assert_execution_process_context(*process_context, record=record)
        _quarantine(record, process_context=process_context)
        _fail("REVOKE", "outer supervisor private-state revocation failed", exc)
    parsed = _strict_json(receipt, label="POSIX backend revocation receipt")
    if set(parsed) != _REVOCATION_FIELDS or parsed != expected:
        _quarantine(record, process_context=process_context)
        _fail("REVOKE_RECEIPT", "private-state revocation binding drifted")
    _verify_external(
        record.bridge, "REVOKED", receipt, expected,
        process_context=process_context, record=record,
    )
    if record.process_created:
        policy_status = (
            "EXECUTED_AND_REVOKED"
            if returncode == 0
            else "FAILED_AND_REVOKED"
        )
        completion_evidence_sha256: str | None = _sha(receipt)
    else:
        policy_status = "UNEXECUTED_AND_REVOKED"
        completion_evidence_sha256 = None
    policy_completion = _complete_policy_invocation(
        record,
        status=policy_status,
        completion_evidence_sha256=completion_evidence_sha256,
        process_context=process_context,
    )
    return {
        **parsed,
        "receipt_sha256": _sha(receipt),
        "policy_completion_receipt_sha256": _sha(policy_completion),
        "policy_completion_status": policy_status,
        "policy_completion_evidence_sha256": completion_evidence_sha256,
    }


def _complete_policy_invocation(
    record: _ExecutionRecord,
    *,
    status: str,
    completion_evidence_sha256: str | None,
    process_context: tuple[int, str],
) -> bytes:
    invocation = record.invocation
    if invocation is None or record.policy_completion_receipt is not None:
        _fail("POLICY_COMPLETION", "policy invocation is not terminally completable")
    try:
        receipt = invocation.complete(
            status=status,
            completion_evidence_sha256=completion_evidence_sha256,
        )
        _assert_execution_process_context(*process_context, record=record)
    except BaseException as exc:
        _assert_execution_process_context(*process_context, record=record)
        _fail("POLICY_COMPLETION", "policy invocation completion failed", exc)
    parsed = _strict_json(receipt, label="backend policy completion receipt")
    issuance = _strict_json(
        record.plan_receipt, label="backend launch issuance receipt"
    )
    expected = {
        "schema": TEST_ONLY_COMPLETION_RECEIPT_SCHEMA,
        "attempt_id": record.request["attempt_id"],
        "backend": record.request["backend"],
        "model": record.request["model"],
        "issuance_receipt_sha256": _sha(record.plan_receipt),
        "sealed_content_sha256": issuance.get("sealed_content_sha256"),
        "status": status,
        "completion_evidence_sha256": completion_evidence_sha256,
        "fd_state": "TERMINALLY_REVOKED",
    }
    expected["authority_class"] = TEST_ONLY_AUTHORITY_CLASS
    expected_fields = {*_POLICY_COMPLETION_FIELDS, "authority_class"}
    if set(parsed) != expected_fields or parsed != expected:
        _fail(
            "POLICY_COMPLETION",
            "policy completion receipt differs from its invocation",
        )
    _assert_execution_process_context(*process_context, record=record)
    record.policy_completion_receipt = bytes(receipt)
    return bytes(receipt)


def _terminal_policy_revoke(
    record: _ExecutionRecord, *, process_context: tuple[int, str],
) -> dict[str, Any]:
    if record.invocation is None:
        record.plan.close()
        _assert_execution_process_context(*process_context, record=record)
        return {
            "schema": REVOCATION_SCHEMA,
            "status": "PLAN_CLOSED_BEFORE_INVOCATION",
        }
    receipt = _complete_policy_invocation(
        record,
        status="UNEXECUTED_AND_REVOKED",
        completion_evidence_sha256=None,
        process_context=process_context,
    )
    return {
        "schema": REVOCATION_SCHEMA,
        "status": "UNEXECUTED_AND_REVOKED",
        "policy_completion_receipt_sha256": _sha(receipt),
    }


def _quarantine(
    record: _ExecutionRecord, *, process_context: tuple[int, str],
) -> None:
    _assert_execution_process_context(*process_context, record=record)
    record.state = "QUARANTINED"
    try:
        if record.invocation is not None:
            record.invocation.close()
        else:
            record.plan.close()
        _assert_execution_process_context(*process_context, record=record)
    except BaseException as exc:
        _assert_execution_process_context(*process_context, record=record)
        pass


def _reset_trusted_bridge_for_tests() -> None:
    """Test-only reset; production code must never rotate authority in-process."""

    global _TEST_ONLY_BRIDGE
    with _LOCK:
        if any(record.state not in {
            "CLOSED_UNMATERIALIZED", "REVOKED", "QUARANTINED"
        } for record in _TEST_ONLY_EXECUTIONS.values()):
            _fail("BRIDGE_ACTIVE", "cannot reset with live execution authority")
        _TEST_ONLY_EXECUTIONS.clear()
        _TEST_ONLY_CONSUMED_CONTEXTS.clear()
        _TEST_ONLY_ISSUANCE_RESERVATIONS.clear()
        _TEST_ONLY_BRIDGE = None


__all__ = (
    "ARM_BINDING_SCHEMA", "EXTERNAL_VERIFICATION_SCHEMA",
    "MATERIALIZATION_SCHEMA", "OUTER_AUTHORITY_SCHEMA", "REVOCATION_SCHEMA",
    "NATIVE_EXECUTION_ABI_SCHEMA", "NATIVE_CODEX_REQUEST_SCHEMA",
    "NATIVE_CLAUDE_REQUEST_SCHEMA", "NATIVE_BROKER_ABI_SCHEMA",
    "NATIVE_PREPARE_REQUEST_SCHEMA", "NATIVE_PREPARED_RECEIPT_SCHEMA",
    "NATIVE_START_REQUEST_SCHEMA", "NATIVE_STARTED_RECEIPT_SCHEMA",
    "NATIVE_WAIT_REQUEST_SCHEMA", "NATIVE_EXITED_RECEIPT_SCHEMA",
    "NATIVE_OUTPUT_REQUEST_SCHEMA", "NATIVE_OUTPUT_RECEIPT_SCHEMA",
    "NATIVE_EXTINGUISH_REQUEST_SCHEMA", "NATIVE_REVOKED_RECEIPT_SCHEMA",
    "NATIVE_CLOSE_REQUEST_SCHEMA", "NATIVE_FINISHED_RECEIPT_SCHEMA",
    "NATIVE_BACKEND_TIMEOUT_MAX_SECONDS", "NATIVE_OUTPUT_CHUNK_MAX_BYTES",
    "NATIVE_STREAM_OBSERVED_LIMIT_BYTES", "NATIVE_STREAM_RETAINED_LIMIT_BYTES",
    "BACKEND_STDOUT_LIMIT_BYTES", "BACKEND_STDERR_LIMIT_BYTES",
    "NATIVE_INITIAL_ROLE_GUEST_DRIVER", "NATIVE_PROCESS_ROLE_BACKEND_EXECUTION",
    "NATIVE_SPAWNED_ROLE_BACKEND_EXECUTION",
    "NativeBackendProcessIdentity", "NativeExitedReceipt",
    "NativeFinishedReceipt", "NativeOutputChunkReceipt",
    "NativePreparedReceipt", "NativeRevokedReceipt", "NativeStartedReceipt",
    "NativeGuestRuntimeAuthorities", "NativeOuterSupervisorBridgeCapability",
    "PosixBackendExecution",
    "PosixBackendExecutionError", "PosixPhysicalLaunch",
    "canonical_json_bytes", "native_backend_execution_envelope_v2",
    "parse_native_exited_receipt", "parse_native_finished_receipt",
    "parse_native_output_receipt", "parse_native_prepared_receipt",
    "parse_native_revoked_receipt", "parse_native_started_receipt",
    "outer_supervisor_context_available", "prepare_posix_backend_execution",
    "acquire_native_guest_backend_execution_authority",
    "acquire_native_guest_runtime_authorities",
    "authenticated_native_guest_request",
    "native_guest_backend_install_generation_authority",
    "native_guest_backend_execution_authority",
    "native_guest_snapshot_tool_runtime_identity",
    "native_guest_js_materializer_runtime_identity",
    "authenticate_native_guest_js_materializer",
    "prepare_native_guest_js_materializer_execution",
    "execute_native_guest_js_materializer",
    "replay_native_guest_js_materializer_terminal",
    "native_guest_managed_evm_runtime_identity",
    "native_guest_managed_evm_bootstrap_inputs",
    "prepare_native_guest_managed_evm_provision",
    "execute_native_guest_managed_evm_provision",
    "project_native_guest_managed_evm_terminal",
    "native_guest_managed_evm_setup_effects",
    "commit_native_guest_evm_analysis_projection",
    "project_native_guest_evm_analysis_projection_receipt",
    "project_native_guest_evm_analysis_projection_lineage",
    "project_native_guest_evm_analysis_projection_workspace_binding",
    "prepare_native_guest_snapshot_tool_execution",
    "execute_native_guest_snapshot_tool_execution",
    "project_native_guest_snapshot_tool_terminal",
    "register_trusted_outer_supervisor_bridge",
    "require_native_posix_backend_execution",
)
