"""Purpose-keyed Apple Container translation for the POSIX supervisor.

The production boundary deliberately remains unavailable until the native
supervisor extension supplies a separate, non-constructible adapter
capability.  The ``TEST_ONLY`` functions below validate and render inert
provider request values; they never call a provider and never manufacture a
supervisor receipt.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path, PurePath
import sys
import types
from typing import Any, Callable

import apple_container_provider as A
import posix_audit_supervisor as S


SCHEMA = "plamen.apple-supervisor-adapter.v1"
FUZZ_EXECUTION_AUTHORITY_SCHEMA = "plamen.apple-supervisor.fuzz-execution.v1"
APPLE_FUZZ_SERVICE_ABI_SCHEMA = "plamen.apple-fuzz-service-admission.v1"
_APPLE_FUZZ_SERVICE_TYPES = (
    "AppleFuzzServiceSessionAuthority",
    "AppleFuzzAdmissionContinuationLease",
    "AppleFuzzLifecycleTerminal",
)
_APPLE_FUZZ_SERVICE_FUNCTIONS = (
    "acquire_apple_fuzz_service_session",
    "admit_apple_fuzz_campaign",
    "project_apple_fuzz_secure_receipt",
    "execute_admitted_apple_fuzz_campaign",
    "project_admitted_apple_fuzz_terminal",
)
_COMPONENT_POLICY = (
    ("target-lower", "HOST_OVERLAY_LOWER", "ro"),
    ("project-merged", "/workspace/project", "ro"),
    ("scratch", "/workspace/scratch", "rw"),
    ("state", "/workspace/state", "rw"),
    ("control", "/workspace/control", "ro"),
    ("seccomp", "/run/plamen/seccomp", "ro"),
    ("credentials", "/run/plamen/credentials", "ro"),
    ("backend-context", "/run/plamen/backend", "ro"),
    ("runtime", "/opt/plamen", "ro"),
    ("docs", "/workspace/docs", "ro"),
    ("scope", "/workspace/scope", "ro"),
)
_MOUNT_POLICY = _COMPONENT_POLICY[1:]
class AppleSupervisorAdapterError(RuntimeError):
    """A bounded adapter rejection without caller-controlled diagnostics."""


class AppleSupervisorAdapterUnavailable(AppleSupervisorAdapterError):
    """The authenticated native adapter boundary is not available."""


def _native_apple_fuzz_service_surface() -> tuple[object, ...]:
    """Admit the complete atomic fuzz service ABI before caller inputs.

    The legacy PREPARE/EXECUTE pair is intentionally insufficient: it accepts
    secure-receipt and prepared-contract digests as inputs and therefore
    cannot be their authority.  The replacement surface must issue the
    canonical secure receipt and opaque continuation together, then consume
    that same continuation for lifecycle execution.
    """

    try:
        A._native_provider_surface()
        module = types.ModuleType.__getattribute__(sys, "__dict__")[
            "modules"
        ].get(A.NATIVE_MODULE_NAME)
        if type(module) is not types.ModuleType:
            raise TypeError
        namespace = types.ModuleType.__getattribute__(module, "__dict__")
        if namespace.get("APPLE_FUZZ_SERVICE_ABI_SCHEMA") != (
            APPLE_FUZZ_SERVICE_ABI_SCHEMA
        ):
            raise TypeError
        native_types = tuple(
            namespace.get(name) for name in _APPLE_FUZZ_SERVICE_TYPES
        )
        functions = tuple(
            namespace.get(name) for name in _APPLE_FUZZ_SERVICE_FUNCTIONS
        )
        if any(
            type(native_type) is not type
            or type.__getattribute__(native_type, "__module__")
                != A.NATIVE_MODULE_NAME
            or type.__getattribute__(native_type, "__flags__")
                & ((1 << 9) | (1 << 10))
            for native_type in native_types
        ):
            raise TypeError
        if any(
            type(function) is not types.BuiltinFunctionType
            or getattr(function, "__module__", None) != A.NATIVE_MODULE_NAME
            or getattr(function, "__name__", None) != name
            for name, function in zip(
                _APPLE_FUZZ_SERVICE_FUNCTIONS, functions, strict=True
            )
        ):
            raise TypeError
        return (module, *native_types, *functions)
    except BaseException:
        pass
    raise AppleSupervisorAdapterUnavailable(
        "atomic native Apple fuzz admission service is unavailable"
    )


def apple_fuzz_service_admission_status() -> dict[str, object]:
    """Return a non-authoritative RED/READY integration diagnostic."""

    try:
        _native_apple_fuzz_service_surface()
    except AppleSupervisorAdapterUnavailable:
        return {
            "schema": APPLE_FUZZ_SERVICE_ABI_SCHEMA,
            "status": "UNAVAILABLE",
            "issues": [
                {
                    "code": "APPLE_FUZZ_SERVICE_SESSION_PRODUCER_ABSENT",
                    "detail": "no code-authenticated service session issuer",
                },
                {
                    "code": "APPLE_FUZZ_SECURE_RECEIPT_MINTER_ABSENT",
                    "detail": "no atomic native secure-receipt minter",
                },
                {
                    "code": "APPLE_FUZZ_CONTINUATION_LEASE_PRODUCER_ABSENT",
                    "detail": "no opaque admission-to-execution continuation issuer",
                },
                {
                    "code": "APPLE_FUZZ_LIFECYCLE_TERMINAL_PRODUCER_ABSENT",
                    "detail": "no same-continuation lifecycle terminal projector",
                },
            ],
        }
    return {
        "schema": APPLE_FUZZ_SERVICE_ABI_SCHEMA,
        "status": "READY",
        "issues": [],
    }


def require_apple_fuzz_service_admission(
    value: object, secure_receipt: object,
) -> object:
    """Authenticate an issued continuation and its native receipt projection.

    A diagnostic READY surface is not launch authority.  Only the exact
    non-heap native continuation type returned by atomic admission may cross
    this boundary, and its service projection must equal the supplied durable
    receipt byte-for-byte after canonical decoding.
    """

    surface = _native_apple_fuzz_service_surface()
    lease_type = surface[2]
    project_receipt = surface[6]
    if type(value) is not lease_type or not isinstance(secure_receipt, dict):
        raise AppleSupervisorAdapterUnavailable(
            "native Apple fuzz admission continuation is unavailable"
        )
    try:
        raw = project_receipt(value)
        if type(raw) is not bytes or not raw or len(raw) > 64 * 1024:
            raise TypeError
        projected = json.loads(raw)
        canonical = json.dumps(
            projected, allow_nan=False, ensure_ascii=True,
            separators=(",", ":"), sort_keys=True,
        ).encode("ascii")
        if type(projected) is not dict or canonical != raw:
            raise TypeError
        if projected != secure_receipt:
            raise TypeError
    except BaseException as exc:
        raise AppleSupervisorAdapterUnavailable(
            "native Apple fuzz secure receipt projection differs"
        ) from exc
    return value


@dataclass(frozen=True, slots=True)
class AppleFuzzExecutionAuthority:
    request_sha256: str
    launch_request_sha256: str
    start_receipt_sha256: str
    wait_receipt_sha256: str
    delete_receipt_sha256: str
    stdout_sha256: str
    stderr_sha256: str
    stdout_retained_sha256: str
    stderr_retained_sha256: str
    stop_argv_sha256: str
    stop_stdout_sha256: str
    stop_stderr_sha256: str
    stopped_observation_sha256: str
    guest_population_extinction_sha256: str
    stdout_observed_bytes: int
    stderr_observed_bytes: int
    stdout_retained_bytes: int
    stderr_retained_bytes: int
    stdout_truncated: bool
    stderr_truncated: bool
    exit_code: int
    descendants_extinct: bool
    guest_process_extinct: bool
    backend_egress_revoked: bool
    stop_control_process_reaped: bool
    stop_control_process_group_extinct: bool
    guest_population_zero: bool
    container_vm_stopped: bool
    schema: str = FUZZ_EXECUTION_AUTHORITY_SCHEMA

    def __post_init__(self) -> None:
        if (
            self.schema != FUZZ_EXECUTION_AUTHORITY_SCHEMA
            or type(self.exit_code) is not int
            or not 0 <= self.exit_code <= 255
            or self.descendants_extinct is not True
            or self.guest_process_extinct is not True
            or self.backend_egress_revoked is not True
            or self.stop_control_process_reaped is not True
            or self.stop_control_process_group_extinct is not True
            or self.guest_population_zero is not True
            or self.container_vm_stopped is not True
            or type(self.stdout_observed_bytes) is not int
            or type(self.stderr_observed_bytes) is not int
            or type(self.stdout_retained_bytes) is not int
            or type(self.stderr_retained_bytes) is not int
            or not 0 <= self.stdout_retained_bytes <= self.stdout_observed_bytes
            or not 0 <= self.stderr_retained_bytes <= self.stderr_observed_bytes
            or type(self.stdout_truncated) is not bool
            or type(self.stderr_truncated) is not bool
            or self.stdout_truncated
            is not (self.stdout_observed_bytes != self.stdout_retained_bytes)
            or self.stderr_truncated
            is not (self.stderr_observed_bytes != self.stderr_retained_bytes)
        ):
            raise AppleSupervisorAdapterError(
                "Apple fuzz execution authority is malformed"
            )
        for value in (
            self.request_sha256, self.launch_request_sha256,
            self.start_receipt_sha256, self.wait_receipt_sha256,
            self.delete_receipt_sha256, self.stdout_sha256,
            self.stderr_sha256, self.stdout_retained_sha256,
            self.stderr_retained_sha256, self.stop_argv_sha256,
            self.stop_stdout_sha256, self.stop_stderr_sha256,
            self.stopped_observation_sha256,
            self.guest_population_extinction_sha256,
        ):
            _digest(value, "Apple fuzz execution authority")

    @property
    def authority_sha256(self) -> str:
        return A._canonical_digest(asdict(self))


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or A._HEX64.fullmatch(value) is None:
        raise AppleSupervisorAdapterError(f"{label} is malformed")
    return value


def _ticket(
    ticket: Any, operation: S.MutationOperation, request: S.AuditRequest,
) -> str:
    if type(ticket) is not S.MutationTicket or (
        ticket.operation is not operation
        or ticket.request_fingerprint_sha256 != request.fingerprint_sha256
        or ticket.attempt_id != request.attempt_id
        or ticket.authenticated is not True
    ):
        raise AppleSupervisorAdapterError("mutation ticket binding differs")
    return S.canonical_sha256(ticket)


def _canonical_host_path(value: Any) -> str:
    try:
        if type(value) is not str or value != str(PurePath(value)):
            raise ValueError
        A._validate_absolute_path(value, "resolved component", posix=False)
    except Exception:
        raise AppleSupervisorAdapterError(
            "resolved component path is not canonical"
        ) from None
    return value


@dataclass(frozen=True, slots=True)
class TEST_ONLY_ResolvedComponent:
    purpose: str
    source_handle: str
    source_path: str
    identity_sha256: str
    content_sha256: str
    provider_mount_identity_sha256: str

    def __post_init__(self) -> None:
        if type(self.purpose) is not str or self.purpose not in {
            row[0] for row in _COMPONENT_POLICY
        }:
            raise AppleSupervisorAdapterError("resolved component purpose is invalid")
        _canonical_host_path(self.source_path)
        try:
            S._handle(self.source_handle, "resolved component handle")
        except Exception:
            raise AppleSupervisorAdapterError(
                "resolved component handle is malformed"
            ) from None
        for value, label in (
            (self.identity_sha256, "component identity"),
            (self.content_sha256, "component content"),
            (self.provider_mount_identity_sha256, "provider mount identity"),
        ):
            _digest(value, label)


@dataclass(frozen=True, slots=True)
class TEST_ONLY_ImageClosure:
    image_handle: str
    runtime_handle: str
    runtime_layout_sha256: str
    oci_layout_sha256: str
    image_reference: str
    index_digest: str
    manifest_digest: str
    configuration_sha256: str
    platform_os: str = "linux"
    platform_architecture: str = "arm64"
    immutable: bool = True
    authenticated: bool = True

    def __post_init__(self) -> None:
        try:
            A._validate_oci_reference(self.image_reference)
        except Exception:
            raise AppleSupervisorAdapterError("image reference is not canonical") from None
        if (
            type(self.image_handle) is not str
            or type(self.runtime_handle) is not str
            or self.image_reference.rpartition("@")[2] != self.index_digest
            or A._SHA256.fullmatch(self.index_digest) is None
            or A._SHA256.fullmatch(self.manifest_digest) is None
            or self.index_digest == self.manifest_digest
        ):
            raise AppleSupervisorAdapterError("image closure identity differs")
        try:
            S._handle(self.image_handle, "image closure handle")
            S._handle(self.runtime_handle, "runtime closure handle")
        except Exception:
            raise AppleSupervisorAdapterError("image closure handle is malformed") from None
        for value, label in (
            (self.runtime_layout_sha256, "runtime layout"),
            (self.oci_layout_sha256, "OCI layout"),
            (self.configuration_sha256, "image configuration"),
        ):
            _digest(value, label)
        if (
            self.platform_os != "linux"
            or self.platform_architecture != "arm64"
            or self.immutable is not True
            or self.authenticated is not True
        ):
            raise AppleSupervisorAdapterError("image closure is not immutable linux/arm64")

    @property
    def closure_sha256(self) -> str:
        return S.canonical_sha256(self)


@dataclass(frozen=True, slots=True)
class TEST_ONLY_InitImageClosure:
    image_reference: str
    index_digest: str
    manifest_digest: str
    preflight_postcondition_sha256: str
    platform_os: str = "linux"
    platform_architecture: str = "arm64"
    immutable: bool = True
    authenticated: bool = True

    def __post_init__(self) -> None:
        try:
            A._validate_oci_reference(self.image_reference)
        except Exception:
            raise AppleSupervisorAdapterError(
                "init image reference is not canonical"
            ) from None
        if (
            self.image_reference != A.SUPPORTED_INIT_IMAGE_REFERENCE
            or self.index_digest != A.SUPPORTED_INIT_IMAGE_INDEX_DIGEST
            or self.manifest_digest != A.SUPPORTED_INIT_IMAGE_MANIFEST_DIGEST
            or self.image_reference.rpartition("@")[2] != self.index_digest
            or self.index_digest == self.manifest_digest
            or self.platform_os != "linux"
            or self.platform_architecture != "arm64"
            or self.immutable is not True
            or self.authenticated is not True
        ):
            raise AppleSupervisorAdapterError(
                "init image closure differs from the exact linux/arm64 pin"
            )
        _digest(self.preflight_postcondition_sha256, "init image postcondition")

    @property
    def closure_sha256(self) -> str:
        return S.canonical_sha256(self)


@dataclass(frozen=True, slots=True)
class TEST_ONLY_OverlayRelation:
    attempt_id: str
    lower_handle: str
    upper_handle: str
    work_handle: str
    merged_handle: str
    lower_identity_sha256: str
    lower_content_sha256: str
    merged_identity_sha256: str
    lower_readonly: bool = True
    copy_on_write: bool = True
    attempt_owned: bool = True
    authenticated: bool = True

    def __post_init__(self) -> None:
        try:
            S._identifier(self.attempt_id, "overlay attempt")
            for handle in (
                self.lower_handle, self.upper_handle,
                self.work_handle, self.merged_handle,
            ):
                S._handle(handle, "overlay handle")
        except Exception:
            raise AppleSupervisorAdapterError("overlay identity is malformed") from None
        for value, label in (
            (self.lower_identity_sha256, "overlay lower identity"),
            (self.lower_content_sha256, "overlay lower content"),
            (self.merged_identity_sha256, "overlay merged identity"),
        ):
            _digest(value, label)
        if (
            self.lower_readonly is not True
            or self.copy_on_write is not True
            or self.attempt_owned is not True
            or self.authenticated is not True
        ):
            raise AppleSupervisorAdapterError("overlay relation is insufficient")

    @property
    def relation_sha256(self) -> str:
        return S.canonical_sha256(self)


@dataclass(frozen=True, slots=True)
class TEST_ONLY_CreateStoppedInput:
    provider_spec: A.ContainerSpec
    request_fingerprint_sha256: str
    create_ticket_sha256: str
    config_sha256: str
    supervisor_guest_spec_sha256: str
    supervisor_mount_roster_sha256: str
    runtime_layout_sha256: str
    image_closure_sha256: str
    init_image_closure_sha256: str
    init_image_reference: str
    init_image_index_digest: str
    init_image_manifest_digest: str
    init_image_postcondition_sha256: str
    backend_context_sha256: str
    backend_admission_sha256: str
    credential_bundle_sha256: str
    credential_isolation_sha256: str
    egress_policy_sha256: str
    egress_admission_sha256: str
    precreate_recensus_sha256: str
    host_lower_recensus_sha256: str
    overlay_relation_sha256: str
    semantic_mount_roster_sha256: str
    provider_mount_roster_sha256: str
    cli_executable_sha256: str
    provider_provenance_sha256: str
    host_architecture: str
    rosetta_required: bool
    expected_state: str = "stopped"
    expected_process_count: int = 0
    schema: str = SCHEMA + ".create-stopped.TEST_ONLY"

    def __post_init__(self) -> None:
        if (
            type(self.provider_spec) is not A.ContainerSpec
            or self.schema != SCHEMA + ".create-stopped.TEST_ONLY"
            or self.host_architecture not in {"arm64", "arm64e"}
            or type(self.rosetta_required) is not bool
            or self.provider_spec.rosetta_required is not self.rosetta_required
            or self.provider_spec.request_fingerprint_sha256
               != self.request_fingerprint_sha256
            or self.provider_spec.config_sha256 != self.config_sha256
            or self.provider_spec.runtime_closure_sha256
               != self.runtime_layout_sha256
            or self.provider_spec.image_closure_sha256
               != self.image_closure_sha256
            or self.provider_spec.backend_admission_sha256
               != self.backend_admission_sha256
            or self.provider_spec.credential_isolation_sha256
               != self.credential_isolation_sha256
            or self.provider_spec.egress_admission_sha256
               != self.egress_admission_sha256
            or self.provider_spec.provider_provenance_sha256
               != self.provider_provenance_sha256
            or self.provider_spec.init_image_reference
               != self.init_image_reference
            or self.provider_spec.init_image_digest
               != self.init_image_index_digest
            or self.provider_spec.init_image_manifest_digest
               != self.init_image_manifest_digest
            or self.init_image_reference != A.SUPPORTED_INIT_IMAGE_REFERENCE
            or self.init_image_index_digest
               != A.SUPPORTED_INIT_IMAGE_INDEX_DIGEST
            or self.init_image_manifest_digest
               != A.SUPPORTED_INIT_IMAGE_MANIFEST_DIGEST
            or self.expected_state != "stopped"
            or type(self.expected_process_count) is not int
            or self.expected_process_count != 0
        ):
            raise AppleSupervisorAdapterError("create-stopped input is malformed")
        for value in (
            self.request_fingerprint_sha256, self.create_ticket_sha256,
            self.config_sha256, self.supervisor_guest_spec_sha256,
            self.supervisor_mount_roster_sha256, self.runtime_layout_sha256,
            self.image_closure_sha256, self.init_image_closure_sha256,
            self.init_image_postcondition_sha256, self.backend_context_sha256,
            self.backend_admission_sha256, self.credential_bundle_sha256,
            self.credential_isolation_sha256, self.egress_policy_sha256,
            self.egress_admission_sha256,
            self.precreate_recensus_sha256, self.host_lower_recensus_sha256,
            self.overlay_relation_sha256, self.semantic_mount_roster_sha256,
            self.provider_mount_roster_sha256, self.cli_executable_sha256,
            self.provider_provenance_sha256,
        ):
            _digest(value, "create-stopped input digest")

    @property
    def input_sha256(self) -> str:
        return S.canonical_sha256(self)


@dataclass(frozen=True, slots=True)
class TEST_ONLY_StartInput:
    launch_request: A.DriverLaunchRequest
    create_input_sha256: str
    admission_sha256: str
    supervisor_launch_sha256: str
    start_ticket_sha256: str
    cli_executable_sha256: str
    provider_provenance_sha256: str
    expected_process_count: int = 1
    schema: str = SCHEMA + ".start.TEST_ONLY"

    def __post_init__(self) -> None:
        if (
            type(self.launch_request) is not A.DriverLaunchRequest
            or self.schema != SCHEMA + ".start.TEST_ONLY"
            or type(self.expected_process_count) is not int
            or self.expected_process_count != 1
        ):
            raise AppleSupervisorAdapterError("start input is malformed")
        for value in (
            self.create_input_sha256, self.admission_sha256,
            self.supervisor_launch_sha256, self.start_ticket_sha256,
            self.cli_executable_sha256, self.provider_provenance_sha256,
        ):
            _digest(value, "start input digest")

    @property
    def input_sha256(self) -> str:
        return S.canonical_sha256(self)


@dataclass(frozen=True, slots=True)
class TEST_ONLY_WaitInput:
    launch_request: A.DriverLaunchRequest
    start_input_sha256: str
    provider_start_receipt_sha256: str
    supervisor_start_sha256: str
    supervisor_launch_sha256: str
    wait_ticket_sha256: str
    native_process_id: str
    native_process_handle_sha256: str
    cli_executable_sha256: str
    provider_provenance_sha256: str
    expected_process_count: int = 1
    opaque_process_capability_required: bool = True
    schema: str = SCHEMA + ".wait.TEST_ONLY"

    def __post_init__(self) -> None:
        if (
            type(self.launch_request) is not A.DriverLaunchRequest
            or self.schema != SCHEMA + ".wait.TEST_ONLY"
            or type(self.expected_process_count) is not int
            or self.expected_process_count != 1
            or self.opaque_process_capability_required is not True
        ):
            raise AppleSupervisorAdapterError("wait input is malformed")
        try:
            S._identifier(self.native_process_id, "wait native process")
        except Exception:
            raise AppleSupervisorAdapterError("wait process identity is malformed") from None
        for value in (
            self.start_input_sha256, self.provider_start_receipt_sha256,
            self.supervisor_start_sha256, self.supervisor_launch_sha256,
            self.wait_ticket_sha256, self.native_process_handle_sha256,
            self.cli_executable_sha256, self.provider_provenance_sha256,
        ):
            _digest(value, "wait input digest")

    @property
    def input_sha256(self) -> str:
        return S.canonical_sha256(self)


@dataclass(frozen=True, slots=True)
class TEST_ONLY_DeleteInput:
    container_id: str
    audit_attempt_id: str
    run_identity: str
    wait_input_sha256: str
    provider_wait_receipt_sha256: str
    supervisor_wait_sha256: str
    terminal_sha256: str
    artifact_census_sha256: str
    export_sha256: str
    delete_ticket_sha256: str
    predelete_process_count: int
    exact_predelete_guest_ids: tuple[str, ...]
    postdelete_absence_required: bool = True
    schema: str = SCHEMA + ".delete.TEST_ONLY"

    def __post_init__(self) -> None:
        try:
            S._identifier(self.audit_attempt_id, "delete attempt")
            S._identifier(self.run_identity, "delete run")
        except Exception:
            raise AppleSupervisorAdapterError("delete input identity is malformed") from None
        if (
            self.container_id != f"plamen-{self.audit_attempt_id}"
            or self.schema != SCHEMA + ".delete.TEST_ONLY"
            or type(self.predelete_process_count) is not int
            or self.predelete_process_count != 0
            or self.exact_predelete_guest_ids != (self.container_id,)
            or self.postdelete_absence_required is not True
        ):
            raise AppleSupervisorAdapterError("delete input is malformed")
        for value in (
            self.wait_input_sha256, self.provider_wait_receipt_sha256,
            self.supervisor_wait_sha256, self.terminal_sha256,
            self.artifact_census_sha256,
            self.export_sha256, self.delete_ticket_sha256,
        ):
            _digest(value, "delete input digest")

    @property
    def input_sha256(self) -> str:
        return S.canonical_sha256(self)


def _validate_context(
    request: Any,
    runtime: Any,
    backend: Any,
    layout: Any,
    configured: Any,
    target: Any,
    guest: Any,
    image: Any,
    init_image: Any,
    overlay: Any,
    network: Any,
    version_pin: Any,
    resolutions: Any,
) -> tuple[TEST_ONLY_ResolvedComponent, ...]:
    if (
        type(request) is not S.AuditRequest
        or type(runtime) is not S.AuthenticatedRuntimeImageLayout
        or type(backend) is not S.BackendContext
        or type(layout) is not S.AttemptLayout
        or type(configured) is not S.ConfigReceipt
        or type(target) is not S.TargetRecensus
        or type(guest) is not S.GuestCreateSpec
        or guest.provider_kind is not S.ProviderKind.APPLE_CONTAINER
        or type(image) is not TEST_ONLY_ImageClosure
        or type(init_image) is not TEST_ONLY_InitImageClosure
        or type(overlay) is not TEST_ONLY_OverlayRelation
        or type(network) is not A.NetworkSpec
        or type(version_pin) is not A.AppleContainerVersionPin
        or type(resolutions) is not tuple
        or any(type(row) is not TEST_ONLY_ResolvedComponent for row in resolutions)
    ):
        raise AppleSupervisorAdapterError("typed translation context is incomplete")
    if (
        runtime.runtime_layout_sha256 != request.runtime_layout_sha256
        or runtime.image_manifest_digest != request.image_manifest_digest
        or runtime.image_closure_sha256 != request.image_closure_sha256
        or runtime.docs_sha256 != request.docs_sha256
        or backend.backend != request.backend
        or backend.context_sha256 != request.backend_context_sha256
        or backend.backend_admission_sha256 != request.backend_admission_sha256
        or backend.credential_sha256 != request.credential_bundle_sha256
        or backend.credential_isolation_sha256
           != request.credential_isolation_sha256
        or backend.egress_policy_sha256 != request.egress_policy_sha256
        or backend.egress_admission_sha256 != request.egress_admission_sha256
        or layout.attempt_id != request.attempt_id
        or layout.run_id != request.run_id
        or layout.target_identity_sha256 != request.target_identity_sha256
        or configured.attempt_id != request.attempt_id
        or configured.run_id != request.run_id
        or configured.config_sha256 != request.source_config_sha256
        or configured.source_config_sha256 != request.source_config_sha256
        or configured.startup_decision_receipt_sha256
           != request.startup_decision_receipt_sha256
        or configured.guest_config.retained_source_handle
           != request.source_config.retained_source_handle
        or configured.guest_config.config_sha256 != request.source_config_sha256
        or configured.guest_config.canonical_bytes
           != request.source_config.canonical_bytes
        or target.target_handle != layout.target_lower_handle
        or target.identity_sha256 != request.target_identity_sha256
        or guest.attempt_id != request.attempt_id
        or guest.guest_name != f"plamen-{request.attempt_id}"
        or guest.image_manifest_digest != request.image_manifest_digest
        or guest.image_closure_sha256 != request.image_closure_sha256
        or guest.image_handle != runtime.image_handle
        or guest.config_sha256 != configured.config_sha256
        or guest.precreate_recensus.phase != "PRE_CREATE"
        or guest.egress_policy_sha256 != request.egress_policy_sha256
        or guest.egress_admission_sha256 != request.egress_admission_sha256
        or guest.backend_admission_sha256 != request.backend_admission_sha256
        or guest.credential_isolation_sha256
           != request.credential_isolation_sha256
        or guest.provider_provenance_sha256
           != request.provider_provenance_sha256
        or guest.platform_architecture != runtime.guest_architecture
        or guest.create_stopped is not True
        or guest.initial_process_count != 0
        or guest.inherited_environment != ()
        or image.image_handle != runtime.image_handle
        or image.runtime_handle != runtime.runtime_handle
        or image.runtime_layout_sha256 != runtime.runtime_layout_sha256
        or image.manifest_digest != request.image_manifest_digest
        or image.closure_sha256 != request.image_closure_sha256
        or init_image.image_reference != A.SUPPORTED_INIT_IMAGE_REFERENCE
        or init_image.index_digest != A.SUPPORTED_INIT_IMAGE_INDEX_DIGEST
        or init_image.manifest_digest != A.SUPPORTED_INIT_IMAGE_MANIFEST_DIGEST
        or init_image.image_reference.rpartition("@")[2]
           != init_image.index_digest
        or init_image.platform_os != "linux"
        or init_image.platform_architecture != "arm64"
        or init_image.immutable is not True
        or init_image.authenticated is not True
        or A._HEX64.fullmatch(init_image.preflight_postcondition_sha256) is None
        or version_pin.init_image_reference != init_image.image_reference
        or version_pin.init_image_index_digest != init_image.index_digest
        or version_pin.init_image_manifest_digest != init_image.manifest_digest
        or A._canonical_digest(list(version_pin.provenance))
           != request.provider_provenance_sha256
        or overlay.attempt_id != request.attempt_id
        or overlay.lower_handle != layout.target_lower_handle
        or overlay.upper_handle != layout.upper_handle
        or overlay.work_handle != layout.work_handle
        or overlay.merged_handle != layout.merged_handle
        or overlay.lower_identity_sha256 != target.identity_sha256
        or overlay.lower_content_sha256 != target.content_sha256
        or network.run_identity != request.run_id
        or network.hostname != guest.guest_name
        or network.policy_sha256 != request.egress_policy_sha256
        or network.egress_admission_sha256 != request.egress_admission_sha256
        or network.topology_mode != "hostOnly"
        or network.effective_egress_mode != "VERIFIED_CONNECT_ALLOWLIST"
    ):
        raise AppleSupervisorAdapterError("translation authorities drifted")
    if tuple((row.purpose, row.destination, row.mode) for row in guest.mounts) != _MOUNT_POLICY:
        raise AppleSupervisorAdapterError("guest mount policy differs")
    components = guest.precreate_recensus.components
    if tuple((row.purpose, row.attachment, row.mode) for row in components) != _COMPONENT_POLICY:
        raise AppleSupervisorAdapterError("layout recensus policy differs")
    if (
        guest.precreate_recensus.attempt_id != request.attempt_id
        or guest.precreate_recensus.layout_handle != layout.layout_handle
        or guest.precreate_recensus.target_identity_sha256 != target.identity_sha256
        or guest.precreate_recensus.target_content_sha256 != target.content_sha256
        or components[0].source_handle != target.target_handle
        or components[0].identity_sha256 != target.identity_sha256
        or components[0].content_sha256 != target.content_sha256
        or components[1].source_handle != layout.merged_handle
        or overlay.merged_identity_sha256 != components[1].identity_sha256
    ):
        raise AppleSupervisorAdapterError("lower-to-merged relation drifted")
    expected_handles = (
        layout.target_lower_handle, layout.merged_handle, layout.scratch_handle,
        layout.state_handle, layout.control_handle, layout.seccomp_handle,
        backend.credential_handle, backend.context_handle,
        runtime.runtime_handle, runtime.docs_handle, layout.scope_handle,
    )
    expected_content = (
        target.content_sha256, None, None, None,
        S.canonical_sha256({
            "config_sha256": configured.config_sha256,
            "startup_decision_receipt_sha256":
                request.startup_decision_receipt_sha256,
        }),
        layout.seccomp_sha256, backend.credential_sha256,
        backend.context_sha256, runtime.runtime_layout_sha256,
        runtime.docs_sha256, layout.scope_sha256,
    )
    if tuple(row.source_handle for row in components) != expected_handles or any(
        expected is not None and row.content_sha256 != expected
        for row, expected in zip(components, expected_content, strict=True)
    ):
        raise AppleSupervisorAdapterError("layout authority roster drifted")
    if tuple(row.source_handle for row in guest.mounts) != expected_handles[1:]:
        raise AppleSupervisorAdapterError("guest mounts differ from recensused handles")

    by_purpose: dict[str, TEST_ONLY_ResolvedComponent] = {}
    for row in resolutions:
        if row.purpose in by_purpose:
            raise AppleSupervisorAdapterError("resolved component purpose is duplicated")
        by_purpose[row.purpose] = row
    if set(by_purpose) != {row[0] for row in _COMPONENT_POLICY}:
        raise AppleSupervisorAdapterError("resolved component roster differs")
    if tuple(row.purpose for row in resolutions) != tuple(
        purpose for purpose, _, _ in _COMPONENT_POLICY
    ):
        raise AppleSupervisorAdapterError("resolved component order differs")
    ordered = resolutions
    paths = tuple(row.source_path.casefold() for row in ordered)
    if len(set(paths)) != len(paths):
        raise AppleSupervisorAdapterError("resolved component paths alias")
    parts = tuple(PurePath(row.source_path.casefold()).parts for row in ordered)
    for index, left in enumerate(parts):
        for right in parts[index + 1:]:
            shared = min(len(left), len(right))
            if left[:shared] == right[:shared]:
                raise AppleSupervisorAdapterError("resolved component paths overlap")
    for resolved, recensused in zip(ordered, components, strict=True):
        if (
            resolved.source_handle != recensused.source_handle
            or resolved.identity_sha256 != recensused.identity_sha256
            or resolved.content_sha256 != recensused.content_sha256
            or resolved.provider_mount_identity_sha256
               != recensused.provider_mount_identity_sha256
        ):
            raise AppleSupervisorAdapterError("resolved component facts drifted")
    return ordered


def translate_create_stopped_for_testing(
    request: S.AuditRequest,
    runtime: S.AuthenticatedRuntimeImageLayout,
    backend: S.BackendContext,
    layout: S.AttemptLayout,
    configured: S.ConfigReceipt,
    target: S.TargetRecensus,
    guest: S.GuestCreateSpec,
    image: TEST_ONLY_ImageClosure,
    init_image: TEST_ONLY_InitImageClosure,
    overlay: TEST_ONLY_OverlayRelation,
    network: A.NetworkSpec,
    version_pin: A.AppleContainerVersionPin,
    resolutions: tuple[TEST_ONLY_ResolvedComponent, ...],
    ticket: S.MutationTicket,
    *,
    host_architecture: str,
    rosetta_required: bool,
    cpus: int = 4,
    memory_bytes: int = 8 * 1024 * 1024 * 1024,
) -> TEST_ONLY_CreateStoppedInput:
    ordered = _validate_context(
        request, runtime, backend, layout, configured, target, guest, image,
        init_image, overlay, network, version_pin, resolutions,
    )
    ticket_sha = _ticket(ticket, S.MutationOperation.CREATE_GUEST, request)
    if host_architecture not in {"arm64", "arm64e"}:
        raise AppleSupervisorAdapterError("Apple host architecture is unsupported")
    if type(rosetta_required) is not bool or rosetta_required is not (
        runtime.guest_architecture == "amd64"
    ):
        raise AppleSupervisorAdapterError("Rosetta requirement differs from guest architecture")
    try:
        mounts = tuple(
            A.MountSpec(resolved.source_path, destination, mode == "ro")
            for resolved, (_, destination, mode) in zip(
                ordered[1:], _MOUNT_POLICY, strict=True
            )
        )
    except Exception:
        raise AppleSupervisorAdapterError(
            "Apple mount request is not admissible"
        ) from None
    arguments = (
        "-B", runtime.driver_path, "/workspace/control/config.json",
        "--startup-intent", request.startup_intent,
        "--unattended", "--no-sleep", "--startup-decision-receipt",
        "/workspace/control/startup-decision.json",
    )
    try:
        provider_spec = A.ContainerSpec(
            name=guest.guest_name,
            run_identity=request.run_id,
            audit_attempt_id=request.attempt_id,
            request_fingerprint_sha256=request.fingerprint_sha256,
            config_sha256=configured.config_sha256,
            runtime_closure_sha256=runtime.runtime_layout_sha256,
            image_closure_sha256=image.closure_sha256,
            provider_provenance_sha256=request.provider_provenance_sha256,
            backend_admission_sha256=backend.backend_admission_sha256,
            credential_isolation_sha256=backend.credential_isolation_sha256,
            egress_admission_sha256=backend.egress_admission_sha256,
            image_reference=image.image_reference,
            image_digest=image.index_digest,
            image_manifest_digest=image.manifest_digest,
            image_configuration_sha256=image.configuration_sha256,
            init_image_reference=init_image.image_reference,
            init_image_digest=init_image.index_digest,
            init_image_manifest_digest=init_image.manifest_digest,
            entrypoint=runtime.python_path,
            arguments=arguments,
            working_directory="/workspace/project",
            mounts=mounts,
            expected_environment=(),
            networks=(network,),
            cpus=cpus,
            memory_bytes=memory_bytes,
            uid=guest.uid,
            gid=guest.gid,
            rosetta_required=rosetta_required,
        )
    except Exception:
        raise AppleSupervisorAdapterError(
            "Apple create-stopped request is not admissible"
        ) from None
    semantic = S.canonical_sha256(tuple(
        {
            "purpose": purpose,
            "source_handle": resolved.source_handle,
            "source_path_identity_sha256": resolved.identity_sha256,
            "destination": destination,
            "mode": mode,
            "content_sha256": resolved.content_sha256,
            "provider_mount_identity_sha256":
                resolved.provider_mount_identity_sha256,
        }
        for resolved, (purpose, destination, mode) in zip(
            ordered[1:], _MOUNT_POLICY, strict=True
        )
    ))
    provider_mounts = S.canonical_sha256(tuple(
        (purpose, resolved.provider_mount_identity_sha256)
        for resolved, (purpose, _, _) in zip(
            ordered[1:], _MOUNT_POLICY, strict=True
        )
    ))
    return TEST_ONLY_CreateStoppedInput(
        provider_spec, request.fingerprint_sha256, ticket_sha,
        configured.config_sha256, guest.spec_sha256,
        S.canonical_sha256(guest.mounts), runtime.runtime_layout_sha256,
        image.closure_sha256, init_image.closure_sha256,
        init_image.image_reference, init_image.index_digest,
        init_image.manifest_digest, init_image.preflight_postcondition_sha256,
        backend.context_sha256, backend.backend_admission_sha256,
        backend.credential_sha256, backend.credential_isolation_sha256,
        backend.egress_policy_sha256, backend.egress_admission_sha256,
        guest.precreate_recensus.layout_sha256,
        S.canonical_sha256(target), overlay.relation_sha256,
        semantic, provider_mounts, version_pin.cli_executable_sha256,
        A._canonical_digest(list(version_pin.provenance)), host_architecture,
        rosetta_required,
    )


def translate_start_for_testing(
    request: S.AuditRequest,
    created: TEST_ONLY_CreateStoppedInput,
    admission: S.GuestAdmissionReceipt,
    launch: S.DriverLaunch,
    ticket: S.MutationTicket,
    *,
    launch_policy_sha256: str,
) -> TEST_ONLY_StartInput:
    if (
        type(request) is not S.AuditRequest
        or type(created) is not TEST_ONLY_CreateStoppedInput
        or type(admission) is not S.GuestAdmissionReceipt
        or type(launch) is not S.DriverLaunch
        or created.request_fingerprint_sha256 != request.fingerprint_sha256
        or created.config_sha256 != request.source_config_sha256
        or created.runtime_layout_sha256 != request.runtime_layout_sha256
        or created.backend_context_sha256 != request.backend_context_sha256
        or created.backend_admission_sha256 != request.backend_admission_sha256
        or created.credential_bundle_sha256 != request.credential_bundle_sha256
        or created.credential_isolation_sha256
           != request.credential_isolation_sha256
        or created.egress_policy_sha256 != request.egress_policy_sha256
        or created.egress_admission_sha256 != request.egress_admission_sha256
        or created.provider_spec.name != f"plamen-{request.attempt_id}"
        or created.provider_spec.audit_attempt_id != request.attempt_id
        or created.provider_spec.run_identity != request.run_id
        or created.provider_spec.image_manifest_digest
           != request.image_manifest_digest
        or created.provider_spec.image_closure_sha256
           != request.image_closure_sha256
        or created.provider_spec.init_image_reference
           != A.SUPPORTED_INIT_IMAGE_REFERENCE
        or created.provider_spec.init_image_digest
           != A.SUPPORTED_INIT_IMAGE_INDEX_DIGEST
        or created.provider_spec.init_image_manifest_digest
           != A.SUPPORTED_INIT_IMAGE_MANIFEST_DIGEST
        or created.init_image_reference != created.provider_spec.init_image_reference
        or created.init_image_index_digest != created.provider_spec.init_image_digest
        or created.init_image_manifest_digest
           != created.provider_spec.init_image_manifest_digest
        or created.provider_spec.network_policy_sha256
           != request.egress_policy_sha256
        or created.provider_spec.arguments != (
            "-B", "/opt/plamen/scripts/plamen_driver.py",
            "/workspace/control/config.json", "--startup-intent",
            request.startup_intent, "--unattended", "--no-sleep",
            "--startup-decision-receipt",
            "/workspace/control/startup-decision.json",
        )
        or tuple(
            (mount.target, "ro" if mount.readonly else "rw")
            for mount in created.provider_spec.mounts
        ) != tuple((destination, mode) for _, destination, mode in _MOUNT_POLICY)
        or admission.attempt_id != request.attempt_id
        or admission.guest_id != created.provider_spec.name
        or admission.precreate_recensus.layout_sha256
           != created.precreate_recensus_sha256
        or admission.spec_sha256 != created.supervisor_guest_spec_sha256
        or launch.attempt_id != request.attempt_id
        or launch.guest_id != created.provider_spec.name
        or launch.admission_sha256 != admission.admission_sha256
        or launch.argv != (
            created.provider_spec.entrypoint, *created.provider_spec.arguments
        )
        or launch.cwd != created.provider_spec.working_directory
        or launch.environment != ()
        or launch.stdin != "DEVNULL"
    ):
        raise AppleSupervisorAdapterError("driver start chain differs")
    # Re-evaluate the only permitted post-create delta; this cannot be inferred
    # from a provider receipt or from mount ordering.
    try:
        allowed_delta = S._validate_layout_delta(
            admission.precreate_recensus, admission.postcreate_recensus
        )
    except Exception:
        raise AppleSupervisorAdapterError("guest admission recensus drifted") from None
    if allowed_delta != admission.allowed_delta_sha256:
        raise AppleSupervisorAdapterError("guest admission delta differs")
    _digest(launch_policy_sha256, "launch policy")
    ticket_sha = _ticket(ticket, S.MutationOperation.START_DRIVER, request)
    provider_request = A.DriverLaunchRequest(
        created.provider_spec.name,
        request.attempt_id,
        created.provider_spec.fingerprint,
        launch_policy_sha256,
        A._canonical_digest(list(launch.argv)),
        A._canonical_digest(list(launch.environment)),
        A._canonical_digest(launch.cwd),
        A._canonical_digest(launch.stdin),
        A._canonical_digest([]),
        created.rosetta_required,
    )
    return TEST_ONLY_StartInput(
        provider_request, created.input_sha256, admission.admission_sha256,
        launch.launch_sha256, ticket_sha, created.cli_executable_sha256,
        created.provider_provenance_sha256,
    )


def translate_wait_for_testing(
    request: S.AuditRequest,
    started_input: TEST_ONLY_StartInput,
    provider_start: A.DriverStartReceipt,
    supervisor_start: S.DriverStartReceipt,
    ticket: S.MutationTicket,
) -> TEST_ONLY_WaitInput:
    if (
        type(request) is not S.AuditRequest
        or type(started_input) is not TEST_ONLY_StartInput
        or type(provider_start) is not A.DriverStartReceipt
        or type(supervisor_start) is not S.DriverStartReceipt
        or started_input.launch_request.attempt_id != request.attempt_id
        or started_input.launch_request.container_id
           != f"plamen-{request.attempt_id}"
        or started_input.expected_process_count != 1
        or provider_start.attempt_id != request.attempt_id
        or provider_start.container_id != started_input.launch_request.container_id
        or provider_start.spec_sha256 != started_input.launch_request.spec_sha256
        or provider_start.launch_request_sha256
           != started_input.launch_request.request_sha256
        or provider_start.launch_policy_sha256
           != started_input.launch_request.launch_policy_sha256
        or provider_start.driver_argv_sha256
           != started_input.launch_request.driver_argv_sha256
        or provider_start.driver_environment_sha256
           != started_input.launch_request.driver_environment_sha256
        or provider_start.driver_cwd_sha256
           != started_input.launch_request.driver_cwd_sha256
        or provider_start.driver_stdin_sha256
           != started_input.launch_request.driver_stdin_sha256
        or provider_start.pass_fd_roster_sha256
           != started_input.launch_request.pass_fd_roster_sha256
        or provider_start.cli_executable_sha256
           != started_input.cli_executable_sha256
        or provider_start.provider_provenance_sha256
           != started_input.provider_provenance_sha256
        or provider_start.rosetta_required
           is not started_input.launch_request.rosetta_required
        or supervisor_start.attempt_id != request.attempt_id
        or supervisor_start.guest_id != provider_start.container_id
        or supervisor_start.launch_sha256 != started_input.supervisor_launch_sha256
        or supervisor_start.driver_process_id != provider_start.native_process_id
        or supervisor_start.driver_process_count != 1
    ):
        raise AppleSupervisorAdapterError("driver wait chain differs")
    ticket_sha = _ticket(ticket, S.MutationOperation.WAIT_DRIVER, request)
    return TEST_ONLY_WaitInput(
        started_input.launch_request, started_input.input_sha256,
        provider_start.receipt_sha256, S.canonical_sha256(supervisor_start),
        started_input.supervisor_launch_sha256, ticket_sha,
        provider_start.native_process_id,
        provider_start.native_process_handle_sha256,
        started_input.cli_executable_sha256,
        started_input.provider_provenance_sha256,
    )


def translate_delete_for_testing(
    request: S.AuditRequest,
    layout: S.AttemptLayout,
    wait_input: TEST_ONLY_WaitInput,
    provider_wait: A.DriverWaitReceipt,
    exited: S.DriverExitReceipt,
    terminal: S.ExtinctionReceipt,
    census: S.ArtifactCensus,
    exported: S.ExportReceipt,
    ticket: S.MutationTicket,
    *,
    predelete_process_count: int,
    exact_predelete_guest_ids: tuple[str, ...],
) -> TEST_ONLY_DeleteInput:
    if (
        type(request) is not S.AuditRequest
        or type(layout) is not S.AttemptLayout
        or type(wait_input) is not TEST_ONLY_WaitInput
        or type(provider_wait) is not A.DriverWaitReceipt
        or type(exited) is not S.DriverExitReceipt
        or type(terminal) is not S.ExtinctionReceipt
        or type(census) is not S.ArtifactCensus
        or type(exported) is not S.ExportReceipt
        or wait_input.launch_request.attempt_id != request.attempt_id
        or wait_input.launch_request.container_id != f"plamen-{request.attempt_id}"
        or wait_input.expected_process_count != 1
        or wait_input.opaque_process_capability_required is not True
        or provider_wait.attempt_id != request.attempt_id
        or provider_wait.container_id != wait_input.launch_request.container_id
        or provider_wait.spec_sha256 != wait_input.launch_request.spec_sha256
        or provider_wait.launch_request_sha256
           != wait_input.launch_request.request_sha256
        or provider_wait.start_receipt_sha256
           != wait_input.provider_start_receipt_sha256
        or provider_wait.launch_policy_sha256
           != wait_input.launch_request.launch_policy_sha256
        or provider_wait.driver_argv_sha256
           != wait_input.launch_request.driver_argv_sha256
        or provider_wait.driver_environment_sha256
           != wait_input.launch_request.driver_environment_sha256
        or provider_wait.driver_cwd_sha256
           != wait_input.launch_request.driver_cwd_sha256
        or provider_wait.driver_stdin_sha256
           != wait_input.launch_request.driver_stdin_sha256
        or provider_wait.pass_fd_roster_sha256
           != wait_input.launch_request.pass_fd_roster_sha256
        or provider_wait.native_process_handle_sha256
           != wait_input.native_process_handle_sha256
        or provider_wait.native_process_id != wait_input.native_process_id
        or provider_wait.cli_executable_sha256
           != wait_input.cli_executable_sha256
        or provider_wait.provider_provenance_sha256
           != wait_input.provider_provenance_sha256
        or provider_wait.rosetta_required
           is not wait_input.launch_request.rosetta_required
        or provider_wait.exit_code != exited.exit_code
        or provider_wait.descendants_extinct is not True
        or provider_wait.guest_process_extinct is not True
        or provider_wait.backend_egress_revoked is not True
        or provider_wait.stop_control_process_reaped is not True
        or provider_wait.stop_control_process_group_extinct is not True
        or provider_wait.guest_population_zero is not True
        or provider_wait.container_vm_stopped is not True
        or any(not isinstance(value, str) or A._HEX64.fullmatch(value) is None
               for value in (
                   provider_wait.stop_argv_sha256,
                   provider_wait.stop_stdout_sha256,
                   provider_wait.stop_stderr_sha256,
                   provider_wait.stopped_observation_sha256,
                   provider_wait.guest_population_extinction_sha256,
               ))
        or exited.attempt_id != request.attempt_id
        or exited.guest_id != provider_wait.container_id
        or exited.launch_sha256 != wait_input.supervisor_launch_sha256
        or terminal.attempt_id != request.attempt_id
        or terminal.guest_id != provider_wait.container_id
        or terminal.process_count != 0
        or terminal.cgroup_populated != 0
        or terminal.exact_attempt is not True
        or layout.attempt_id != request.attempt_id
        or layout.run_id != request.run_id
    ):
        raise AppleSupervisorAdapterError("driver cleanup chain differs")
    try:
        S._validate_artifact_census(request, exited, terminal, census)
        expected_manifest = S._expected_export_manifest(request, census)
    except Exception:
        raise AppleSupervisorAdapterError("artifact census is unsafe") from None
    if (
        exported.attempt_id != request.attempt_id
        or exported.run_id != request.run_id
        or exported.census_sha256 != census.census_sha256
        or exported.destination_handle != layout.export_destination_handle
        or exported.destination_identity_sha256
           != request.export_destination_identity_sha256
        or exported.exported_count != len(census.entries)
        or exported.exported_bytes != sum(row.size for row in census.entries)
        or exported.manifest_sha256 != expected_manifest
        or exported.complete is not True
    ):
        raise AppleSupervisorAdapterError("artifact export chain differs")
    if (
        type(predelete_process_count) is not int
        or predelete_process_count != 0
        or type(exact_predelete_guest_ids) is not tuple
        or exact_predelete_guest_ids != (provider_wait.container_id,)
    ):
        raise AppleSupervisorAdapterError("pre-delete residual census differs")
    ticket_sha = _ticket(ticket, S.MutationOperation.DELETE_GUEST, request)
    return TEST_ONLY_DeleteInput(
        provider_wait.container_id, request.attempt_id, request.run_id,
        wait_input.input_sha256, provider_wait.receipt_sha256,
        exited.wait_sha256,
        terminal.terminal_sha256, census.census_sha256,
        exported.export_sha256, ticket_sha, predelete_process_count,
        exact_predelete_guest_ids,
    )


def authenticate_apple_fuzz_execution(
    request: A.AppleFuzzExecutionRequest,
    bundle: A.AppleNativeFuzzExecutionBundle,
) -> AppleFuzzExecutionAuthority:
    """Project a complete provider chain into a bounded consumer authority.

    The native provider remains the issuer.  This adapter only cross-checks its
    typed start/wait/delete receipts and deliberately omits host paths, command
    output, and opaque capabilities from the durable projection.
    """

    try:
        A.validate_apple_native_fuzz_execution_bundle(request, bundle)
        launch = bundle.launch
        wait = bundle.terminal
        deleted = bundle.deleted
        return AppleFuzzExecutionAuthority(
            request_sha256=request.request_sha256,
            launch_request_sha256=launch.launch_request_sha256,
            start_receipt_sha256=launch.start_receipt_sha256,
            wait_receipt_sha256=wait.terminal_receipt_sha256,
            delete_receipt_sha256=deleted.delete_receipt_sha256,
            stdout_sha256=wait.stdout_sha256,
            stderr_sha256=wait.stderr_sha256,
            stdout_retained_sha256=wait.stdout_retained_sha256,
            stderr_retained_sha256=wait.stderr_retained_sha256,
            stop_argv_sha256=wait.stop_argv_sha256,
            stop_stdout_sha256=wait.stop_stdout_sha256,
            stop_stderr_sha256=wait.stop_stderr_sha256,
            stopped_observation_sha256=wait.stopped_observation_sha256,
            guest_population_extinction_sha256=
                wait.guest_population_extinction_sha256,
            stdout_observed_bytes=wait.stdout_observed_bytes,
            stderr_observed_bytes=wait.stderr_observed_bytes,
            stdout_retained_bytes=wait.stdout_retained_bytes,
            stderr_retained_bytes=wait.stderr_retained_bytes,
            stdout_truncated=wait.stdout_truncated,
            stderr_truncated=wait.stderr_truncated,
            exit_code=wait.exit_code,
            descendants_extinct=wait.descendants_extinct,
            guest_process_extinct=wait.guest_process_extinct,
            backend_egress_revoked=wait.backend_egress_revoked,
            stop_control_process_reaped=wait.stop_control_process_reaped,
            stop_control_process_group_extinct=
                wait.stop_control_process_group_extinct,
            guest_population_zero=wait.guest_population_zero,
            container_vm_stopped=wait.container_vm_stopped,
        )
    except A.AppleContainerProviderError as exc:
        raise AppleSupervisorAdapterError(
            "Apple fuzz provider authority differs"
        ) from exc


def translate_apple_provider_inputs(
    native_consumer: object,
    adapter_capability: object,
    *,
    tool_custody: object,
    source_root: Path,
    scratch_root: Path,
    state_root: Path,
    project_root: Path,
) -> Callable[[A.AppleFuzzExecutionRequest], A.AppleNativeFuzzExecutionBundle]:
    """Return the exact extension-backed Forge/Medusa lifecycle callable.

    The four directories are opened as no-follow directory capabilities for
    each one-shot campaign.  The native broker retains them during PREPARE and
    the dedicated FUZZ_CAMPAIGN effect alone performs create/start/wait,
    mandatory stop, delete, and the lossless terminal projection.
    """
    native_surface = None
    try:
        consumer_type, _bundle_type, provider_type, initial = (
            A._native_provider_surface()
        )
        native_surface = (consumer_type, provider_type, initial)
    except BaseException:
        pass
    if native_surface is None:
        raise AppleSupervisorAdapterUnavailable(
            "authenticated native Apple adapter broker is not integrated"
        )
    consumer_type, provider_type, initial = native_surface
    if (type(native_consumer) is not consumer_type
            or native_consumer is not initial
            or type(adapter_capability) is not provider_type):
        raise AppleSupervisorAdapterUnavailable(
            "authenticated native Apple adapter broker is not integrated"
        )
    module = types.ModuleType.__getattribute__(sys, "__dict__")["modules"].get(
        A.NATIVE_MODULE_NAME
    )
    if type(module) is not types.ModuleType:
        raise AppleSupervisorAdapterUnavailable(
            "authenticated native Apple fuzz broker is unavailable"
        )
    namespace = types.ModuleType.__getattribute__(module, "__dict__")
    custody_type = namespace.get("DarwinToolCustodyAuthority")
    lease_type = namespace.get("DarwinToolExecutionLease")
    terminal_type = namespace.get("DarwinToolExecutionTerminal")
    prepare = namespace.get("prepare_darwin_tool_execution")
    project_prepared = namespace.get("project_darwin_fuzz_campaign_prepared")
    execute = namespace.get("execute_darwin_fuzz_campaign")
    project = namespace.get("project_darwin_tool_execution_terminal")
    if (
        type(custody_type) is not type
        or type(lease_type) is not type
        or type(terminal_type) is not type
        or type(tool_custody) is not custody_type
        or not all(type(value) is types.BuiltinFunctionType for value in (
            prepare, project_prepared, execute, project
        ))
    ):
        raise AppleSupervisorAdapterUnavailable(
            "authenticated native Apple fuzz broker is unavailable"
        )

    roots = tuple(Path(value).resolve(strict=True) for value in (
        source_root, scratch_root, state_root, project_root
    ))
    if any(not value.is_dir() for value in roots) or len(set(roots)) != 4:
        raise AppleSupervisorAdapterUnavailable(
            "native Apple fuzz directory capabilities are invalid or aliased"
        )
    open_flags = os.O_RDONLY | os.O_CLOEXEC
    open_flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)

    def apple_native_fuzz_lifecycle(
        request: A.AppleFuzzExecutionRequest,
    ) -> A.AppleNativeFuzzExecutionBundle:
        if type(request) is not A.AppleFuzzExecutionRequest:
            raise AppleSupervisorAdapterUnavailable(
                "native Apple fuzz request has the wrong exact type"
            )
        timeout = float(request.timeout_seconds)
        if not math.isfinite(timeout) or not timeout.is_integer():
            raise AppleSupervisorAdapterUnavailable(
                "native Apple fuzz timeout must be whole seconds"
            )
        native_payload = {
            "attempt_id": request.attempt_id,
            "authority_sha256": request.authority_digest,
            "cli_executable_sha256": request.cli_executable_sha256,
            "container_id": request.container_id,
            "guest_argv": list(request.guest_argv),
            "guest_cwd": request.guest_cwd,
            "guest_environment": list(request.guest_environment),
            "guest_executable_sha256": request.guest_executable_sha256,
            "launch_policy_sha256": request.launch_policy_sha256,
            "operation_key_sha256": request.operation_key_sha256,
            "phase_io_binding_sha256": request.phase_io_binding_digest,
            "prepared_campaign_sha256": request.prepared_campaign_digest,
            "provider_preflight_sha256": request.provider_preflight_sha256,
            "provider_provenance_sha256": request.provider_provenance_sha256,
            "request_sha256": request.request_sha256,
            "rosetta_required": request.rosetta_required,
            "schema": "plamen.apple-fuzz-campaign-native-request.v1",
            "secure_launcher_sha256": request.secure_launcher_digest,
            "spec_sha256": request.spec_sha256,
            "timeout_seconds": int(timeout),
        }
        raw = json.dumps(
            native_payload, allow_nan=False, ensure_ascii=True,
            separators=(",", ":"), sort_keys=True,
        ).encode("ascii")
        descriptors: list[int] = []
        try:
            descriptors = [os.open(value, open_flags) for value in roots]
            lease = prepare(tool_custody, raw, *descriptors)
            if type(lease) is not lease_type:
                raise AppleSupervisorAdapterUnavailable(
                    "native Apple fuzz PREPARE returned the wrong capability"
                )
            prepared_raw = project_prepared(lease)
            if type(prepared_raw) is not bytes:
                raise AppleSupervisorAdapterUnavailable(
                    "native Apple fuzz PREPARE authority is not retained bytes"
                )
            prepared = json.loads(prepared_raw)
            if type(prepared) is not dict or set(prepared) != {
                "guest_executable_sha256", "native_launch_request_sha256",
                "native_mount_roster_sha256",
                "native_provider_admission_sha256",
                "native_provider_provenance_sha256", "native_spec_sha256",
                "request_sha256", "schema",
                "secure_launcher_provider_preflight_sha256",
                "secure_launcher_provider_provenance_sha256",
                "secure_launcher_spec_sha256",
            } or prepared["schema"] != (
                "plamen.apple-fuzz-campaign-native-prepare.v1"
            ) or prepared["request_sha256"] != hashlib.sha256(raw).hexdigest(
                ) or prepared["guest_executable_sha256"] != (
                    request.guest_executable_sha256
                ) or prepared["secure_launcher_provider_preflight_sha256"] != (
                    request.provider_preflight_sha256
                ) or prepared[
                    "secure_launcher_provider_provenance_sha256"
                ] != request.provider_provenance_sha256 or prepared[
                    "secure_launcher_spec_sha256"
                ] != request.spec_sha256:
                raise AppleSupervisorAdapterUnavailable(
                    "native Apple fuzz PREPARE authority differs"
                )
            for field in (
                "native_launch_request_sha256", "native_mount_roster_sha256",
                "native_provider_admission_sha256",
                "native_provider_provenance_sha256", "native_spec_sha256",
            ):
                _digest(prepared[field], "native Apple fuzz PREPARE authority")
            terminal = execute(tool_custody, lease)
            if type(terminal) is not terminal_type:
                raise AppleSupervisorAdapterUnavailable(
                    "native Apple fuzz execution returned the wrong capability"
                )
            terminal_raw = project(terminal)
            if type(terminal_raw) is not bytes:
                raise AppleSupervisorAdapterUnavailable(
                    "native Apple fuzz terminal is not retained bytes"
                )
            document = json.loads(terminal_raw)
            if type(document) is not dict:
                raise ValueError
            stdout = bytes.fromhex(document.pop("stdout_hex"))
            stderr = bytes.fromhex(document.pop("stderr_hex"))
            bundle = A.AppleNativeFuzzExecutionBundle(
                request_sha256=document["request_sha256"],
                launch=A.AppleNativeFuzzLaunchReceipt(**document["launch"]),
                terminal=A.AppleNativeFuzzTerminalReceipt(**document["terminal"]),
                deleted=A.AppleNativeFuzzDeleteReceipt(**document["deleted"]),
                lifecycle_sha256=document["lifecycle_sha256"],
                native_mount_roster_sha256=
                    document["native_mount_roster_sha256"],
                native_provider_admission_sha256=
                    document["native_provider_admission_sha256"],
                native_provider_provenance_sha256=
                    document["native_provider_provenance_sha256"],
                native_spec_sha256=document["native_spec_sha256"],
                stdout=stdout,
                stderr=stderr,
                schema=document["schema"],
            )
            A.validate_apple_native_fuzz_execution_bundle(request, bundle)
            if any((
                prepared["native_mount_roster_sha256"]
                    != bundle.native_mount_roster_sha256,
                prepared["native_provider_admission_sha256"]
                    != bundle.native_provider_admission_sha256,
                prepared["native_provider_provenance_sha256"]
                    != bundle.native_provider_provenance_sha256,
                prepared["native_spec_sha256"] != bundle.native_spec_sha256,
                prepared["native_launch_request_sha256"]
                    != bundle.launch.launch_request_sha256,
            )):
                raise AppleSupervisorAdapterUnavailable(
                    "native Apple fuzz EXECUTE differs from PREPARE authority"
                )
            current = types.ModuleType.__getattribute__(module, "__dict__")
            if (
                current.get("prepare_darwin_tool_execution") is not prepare
                or current.get("project_darwin_fuzz_campaign_prepared")
                    is not project_prepared
                or current.get("execute_darwin_fuzz_campaign") is not execute
                or current.get("project_darwin_tool_execution_terminal")
                    is not project
            ):
                raise AppleSupervisorAdapterUnavailable(
                    "native Apple fuzz broker changed during execution"
                )
            return bundle
        except AppleSupervisorAdapterError:
            raise
        except BaseException as exc:
            raise AppleSupervisorAdapterUnavailable(
                "native Apple fuzz lifecycle failed closed"
            ) from exc
        finally:
            for descriptor in reversed(descriptors):
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    return apple_native_fuzz_lifecycle


__all__ = [
    "APPLE_FUZZ_SERVICE_ABI_SCHEMA",
    "AppleFuzzExecutionAuthority",
    "AppleSupervisorAdapterError", "AppleSupervisorAdapterUnavailable",
    "TEST_ONLY_CreateStoppedInput", "TEST_ONLY_DeleteInput",
    "TEST_ONLY_ImageClosure", "TEST_ONLY_InitImageClosure",
    "TEST_ONLY_OverlayRelation",
    "TEST_ONLY_ResolvedComponent", "TEST_ONLY_StartInput",
    "TEST_ONLY_WaitInput", "apple_fuzz_service_admission_status",
    "authenticate_apple_fuzz_execution",
    "require_apple_fuzz_service_admission",
    "translate_apple_provider_inputs",
    "translate_create_stopped_for_testing", "translate_delete_for_testing",
    "translate_start_for_testing", "translate_wait_for_testing",
]
