#!/usr/bin/env python3
"""Closed translation between the POSIX supervisor and Linux Podman provider.

This module is deliberately not an authority implementation.  It translates
the supervisor's opaque, purpose-keyed attempt description into a canonical
input for a future native adapter. The compiled Linux sources can authenticate
retained provider inputs and durably journal a closed lifecycle state machine,
but deliberately expose no executable lifecycle verb or Python capability.
Production calls remain unavailable until the
unified compiled ``_plamen_native_supervisor`` service exposes the exact Linux
outer-provider lifecycle authority. The guest-driver bundle and backend-process
identity are never promoted into an outer provider authority, and Python
objects and receipts are never promoted into supervisor authority or receipts.

The conspicuous ``TEST_ONLY_*`` entry points exercise structural translation
without opening paths, starting Podman, allocating resources, or issuing
receipts.
"""

from __future__ import annotations

import dataclasses
import hashlib
import importlib
import importlib.machinery
import os
import stat
import sys
import types
from pathlib import Path, PurePosixPath
from typing import Any

import podman_linux_provider as P
import posix_audit_supervisor as S


_NATIVE_EXTENSION_SUFFIXES = tuple(importlib.machinery.EXTENSION_SUFFIXES)


ADAPTER_SCHEMA = "plamen.podman-supervisor-adapter.v1"
STRUCTURAL_AUTHORITY_CLASS = "STRUCTURAL_TRANSLATION_NOT_AUTHORITY"
TEST_ONLY_AUTHORITY_CLASS = "TEST_ONLY_NONAUTHORITATIVE"
NATIVE_MODULE_NAME = "_plamen_native_supervisor"
NATIVE_ABI_SCHEMA = "plamen.native-broker.v2"
NATIVE_PRODUCTION_ACQUISITION = "AVAILABLE_AUTHENTICATED_NATIVE_SESSION"
NATIVE_ADMISSION_SCHEMA = P.NATIVE_ADMISSION_SCHEMA
NATIVE_ADMISSION_STATUS = P.NATIVE_ADMISSION_STATUS
NATIVE_ADMISSION_GRANTS_LIFECYCLE = False
NATIVE_LIFECYCLE_SCHEMA = P.NATIVE_LIFECYCLE_SCHEMA
NATIVE_LIFECYCLE_STATUS = P.NATIVE_LIFECYCLE_STATUS
NATIVE_LIFECYCLE_REQUIRED_RECEIPTS = P.NATIVE_LIFECYCLE_REQUIRED_RECEIPTS
NATIVE_LIFECYCLE_AVAILABLE = False
GUEST_BOOTSTRAP_PATH = "/usr/local/libexec/plamen-guest"
SECCOMP_PROFILE_BASENAME = "profile.json"
SECCOMP_GUEST_PROFILE = "/run/plamen/seccomp/profile.json"

VISIBLE_GUEST_MOUNT_POLICY = (
    ("project-merged", "/workspace/project", "rw"),
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

RECENSUS_COMPONENT_POLICY = (
    ("target-lower", "HOST_OVERLAY_LOWER", "ro"),
    *VISIBLE_GUEST_MOUNT_POLICY,
)

# Order and semantics must equal podman_linux_provider._MOUNT_ROSTER.  The
# seccomp provider input is the ordinary child profile, while the supervisor
# separately requires its parent directory to be one of ten visible mounts.
PROVIDER_MOUNT_POLICY = (
    ("project-lower", "target-lower", "", True, "directory", 8 * 1024**3, ""),
    ("project-upper", "project-upper", "", False, "directory", 8 * 1024**3, ""),
    ("project-work", "project-work", "", False, "directory", 1024**3, ""),
    ("project-merged", "project-merged", "/workspace/project", False, "directory", 8 * 1024**3, ""),
    ("runtime", "runtime", "/opt/plamen", True, "directory", 1024**3, ""),
    ("state", "state", "/workspace/state", False, "directory", 4 * 1024**3, ""),
    ("scratch", "scratch", "/workspace/scratch", False, "directory", 16 * 1024**3, ""),
    ("seccomp", "seccomp", "", True, "regular", 1024**2, SECCOMP_PROFILE_BASENAME),
)

TMPFS_ORDER = ("/tmp", "/run", "/var/tmp", "/dev/shm")
PROVIDER_RELEASE_ROSTER = (
    "namespace-endpoint", "overlay-keeper", "cleanup-authority",
    "execution-lease", "execution-cgroup", "execution-keeper",
)

_HEX64 = P._SHA256_RE
_NATIVE_OUTER_AUTHORITY_METHODS = (
    ("RuntimeImageAuthority", ("authenticate",)),
    ("WorkspaceAuthority", (
        "admit_target", "revalidate_target", "prepare_layout", "resume_layout",
        "write_guest_config", "recensus_layout",
    )),
    ("BackendContextAuthority", ("authenticate",)),
    ("ProviderAuthority", (
        "provider_kind", "create_stopped", "inspect_stopped", "resume_guest",
        "start_driver", "wait_driver", "delete_guest",
    )),
    ("GuestAdmissionAuthority", ("admit_stopped_guest", "resume_admission")),
    ("ExtinctionAuthority", ("extinguish",)),
    ("ArtifactAuthority", ("census",)),
    ("ExportAuthority", ("export",)),
    ("JournalAuthority", ("open", "arm", "commit", "resolve", "finish")),
    ("RecoveryAuthority", ("recover",)),
)
_NATIVE_OUTER_AUTHORITY_TYPE_NAMES = tuple(
    name for name, _methods in _NATIVE_OUTER_AUTHORITY_METHODS
)
class AdapterError(RuntimeError):
    """A bounded adapter error containing no native exception detail."""


class AdapterUnavailableError(AdapterError):
    """The compiled authority boundary is absent or invalid."""


class AdapterContractError(AdapterError):
    """Supervisor/provider inputs do not form one closed attempt."""


class AdapterAmbiguousError(AdapterError):
    """A native mutation returned unproven or incoherent evidence."""


def _digest(value: object, label: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise AdapterContractError(f"{label} is not a SHA-256 digest")
    return value


def _exact(value: object, expected: type[Any], label: str) -> Any:
    if type(value) is not expected:
        raise AdapterContractError(f"{label} has the wrong type")
    try:
        value.__post_init__()
    except Exception:
        raise AdapterContractError(f"{label} is invalid") from None
    return value


def _canonical_sha256(value: object) -> str:
    try:
        return S.canonical_sha256(value)
    except Exception:
        raise AdapterContractError("adapter value is not canonical") from None


def _ticket(
    value: object, closure: "AttemptClosure", operation: S.MutationOperation,
) -> S.MutationTicket:
    ticket = _exact(value, S.MutationTicket, "mutation ticket")
    if (
        ticket.operation is not operation
        or ticket.request_fingerprint_sha256 != closure.request.fingerprint_sha256
        or ticket.attempt_id != closure.request.attempt_id
        or ticket.authenticated is not True
    ):
        raise AdapterContractError("mutation ticket differs from the closed attempt")
    return ticket


def _ticket_sha256(ticket: S.MutationTicket) -> str:
    return _canonical_sha256(ticket)


@dataclasses.dataclass(frozen=True, slots=True)
class TicketProjection:
    operation: str
    request_fingerprint_sha256: str
    attempt_id: str
    before_checkpoint_sha256: str
    sequence: int
    nonce: str
    ticket_sha256: str

    def __post_init__(self) -> None:
        try:
            operation = S.MutationOperation(self.operation)
        except Exception:
            raise AdapterContractError("projected ticket operation is invalid") from None
        for value in (
            self.request_fingerprint_sha256, self.before_checkpoint_sha256,
            self.nonce, self.ticket_sha256,
        ):
            _digest(value, "projected ticket")
        if type(self.attempt_id) is not str or not self.attempt_id:
            raise AdapterContractError("projected ticket attempt is invalid")
        if (type(self.sequence) is not int or isinstance(self.sequence, bool)
                or self.sequence < 1):
            raise AdapterContractError("projected ticket sequence is invalid")
        try:
            source = S.MutationTicket(
                operation, self.request_fingerprint_sha256, self.attempt_id,
                self.before_checkpoint_sha256, self.sequence, self.nonce,
            )
        except Exception:
            raise AdapterContractError("projected ticket is invalid") from None
        if _canonical_sha256(source) != self.ticket_sha256:
            raise AdapterContractError("projected ticket digest changed")


def _ticket_projection(ticket: S.MutationTicket) -> TicketProjection:
    return TicketProjection(
        ticket.operation.value, ticket.request_fingerprint_sha256,
        ticket.attempt_id, ticket.before_checkpoint_sha256,
        ticket.sequence, ticket.nonce, _ticket_sha256(ticket),
    )


_LIFECYCLE_TICKET_OPERATIONS = {
    "start-driver": S.MutationOperation.START_DRIVER,
    "wait-driver": S.MutationOperation.WAIT_DRIVER,
    "extinguish": S.MutationOperation.EXTINGUISH,
    "census-artifacts": S.MutationOperation.CENSUS_ARTIFACTS,
    "export-artifacts": S.MutationOperation.EXPORT_ARTIFACTS,
    "delete-guest": S.MutationOperation.DELETE_GUEST,
    # One supervisor deletion ticket authorizes both deletion and the
    # inseparable release of attempt-owned provider resources.
    "release-attempt": S.MutationOperation.DELETE_GUEST,
}


def _visible_mounts(spec: S.GuestCreateSpec) -> tuple[S.GuestMount, ...]:
    if type(spec.mounts) is not tuple or any(
        type(item) is not S.GuestMount for item in spec.mounts
    ):
        raise AdapterContractError("visible guest mounts are not exact typed values")
    for item in spec.mounts:
        try:
            item.__post_init__()
        except Exception:
            raise AdapterContractError("visible guest mount is invalid") from None
    roster = tuple((item.purpose, item.destination, item.mode) for item in spec.mounts)
    if roster != VISIBLE_GUEST_MOUNT_POLICY:
        raise AdapterContractError("visible guest mount roster changed")
    handles = tuple(item.source_handle for item in spec.mounts)
    if len(set(handles)) != len(handles):
        raise AdapterContractError("visible guest mount handles alias")
    return spec.mounts


def _recensus_components(
    value: S.LayoutRecensus,
) -> tuple[S.LayoutComponent, ...]:
    if type(value.components) is not tuple or any(
        type(item) is not S.LayoutComponent for item in value.components
    ):
        raise AdapterContractError("pre-create recensus components are invalid")
    for item in value.components:
        try:
            item.__post_init__()
        except Exception:
            raise AdapterContractError("pre-create recensus component is invalid") from None
    roster = tuple(
        (item.purpose, item.attachment, item.mode) for item in value.components
    )
    if roster != RECENSUS_COMPONENT_POLICY:
        raise AdapterContractError("pre-create recensus roster changed")
    handles = tuple(item.source_handle for item in value.components)
    identities = tuple(item.identity_sha256 for item in value.components)
    provider_identities = tuple(
        item.provider_mount_identity_sha256 for item in value.components
    )
    if (
        len(set(handles)) != len(handles)
        or len(set(identities)) != len(identities)
        or len(set(provider_identities)) != len(provider_identities)
    ):
        raise AdapterContractError("pre-create recensus identities alias")
    return value.components


@dataclasses.dataclass(frozen=True, slots=True)
class BrokerV2Commitment:
    """Exact common commitment shared by outer lifecycle records."""

    request_fingerprint_sha256: str
    attempt_id: str
    run_identity: str
    config_sha256: str
    runtime_closure_sha256: str
    image_closure_sha256: str
    provider_provenance_sha256: str
    backend_admission_sha256: str
    credential_isolation_sha256: str
    egress_admission_sha256: str

    def __post_init__(self) -> None:
        if type(self.attempt_id) is not str or not self.attempt_id:
            raise AdapterContractError("broker commitment attempt is invalid")
        if type(self.run_identity) is not str or not self.run_identity:
            raise AdapterContractError("broker commitment run is invalid")
        for value in (
            self.request_fingerprint_sha256, self.config_sha256,
            self.runtime_closure_sha256, self.image_closure_sha256,
            self.provider_provenance_sha256, self.backend_admission_sha256,
            self.credential_isolation_sha256, self.egress_admission_sha256,
        ):
            _digest(value, "broker commitment")

    @property
    def digest(self) -> str:
        return _canonical_sha256(self)


@dataclasses.dataclass(frozen=True, slots=True)
class AttemptClosure:
    """Structural closure consumed and authenticated by the native adapter."""

    request: S.AuditRequest
    layout: S.AttemptLayout
    runtime: S.AuthenticatedRuntimeImageLayout
    backend: S.BackendContext
    configured: S.ConfigReceipt
    create_spec: S.GuestCreateSpec
    schema: str = ADAPTER_SCHEMA
    authority_class: str = STRUCTURAL_AUTHORITY_CLASS

    def __post_init__(self) -> None:
        if self.schema != ADAPTER_SCHEMA or self.authority_class != STRUCTURAL_AUTHORITY_CLASS:
            raise AdapterContractError("attempt closure schema is invalid")
        request = _exact(self.request, S.AuditRequest, "audit request")
        layout = _exact(self.layout, S.AttemptLayout, "attempt layout")
        runtime = _exact(
            self.runtime, S.AuthenticatedRuntimeImageLayout, "runtime image layout"
        )
        backend = _exact(self.backend, S.BackendContext, "backend context")
        configured = _exact(self.configured, S.ConfigReceipt, "guest configuration")
        spec = _exact(self.create_spec, S.GuestCreateSpec, "guest create spec")
        visible = _visible_mounts(spec)
        components = _recensus_components(spec.precreate_recensus)

        if (
            layout.attempt_id != request.attempt_id
            or layout.run_id != request.run_id
            or configured.attempt_id != request.attempt_id
            or configured.run_id != request.run_id
            or spec.attempt_id != request.attempt_id
            or spec.guest_name != f"plamen-{request.attempt_id}"
            or spec.precreate_recensus.attempt_id != request.attempt_id
            or spec.precreate_recensus.layout_handle != layout.layout_handle
            or spec.precreate_recensus.phase != "PRE_CREATE"
        ):
            raise AdapterContractError("attempt/run/layout closure changed")
        if (
            runtime.runtime_layout_sha256 != request.runtime_layout_sha256
            or runtime.image_manifest_digest != request.image_manifest_digest
            or runtime.image_closure_sha256 != request.image_closure_sha256
            or runtime.docs_sha256 != request.docs_sha256
            or spec.image_manifest_digest != request.image_manifest_digest
            or spec.image_closure_sha256 != request.image_closure_sha256
            or spec.image_handle != runtime.image_handle
            or spec.platform_os != runtime.guest_os
            or spec.platform_architecture != runtime.guest_architecture
        ):
            raise AdapterContractError("runtime image closure changed")
        if (
            configured.config_sha256 != request.source_config_sha256
            or configured.source_config_sha256 != request.source_config_sha256
            or configured.startup_decision_receipt_sha256
            != request.startup_decision_receipt_sha256
            or configured.guest_config.config_sha256 != configured.config_sha256
            or spec.config_sha256 != configured.config_sha256
        ):
            raise AdapterContractError("configuration closure changed")
        if (
            backend.backend != request.backend
            or backend.context_sha256 != request.backend_context_sha256
            or backend.backend_admission_sha256
               != request.backend_admission_sha256
            or backend.credential_sha256 != request.credential_bundle_sha256
            or backend.credential_isolation_sha256
               != request.credential_isolation_sha256
            or backend.egress_policy_sha256 != request.egress_policy_sha256
            or backend.egress_admission_sha256
               != request.egress_admission_sha256
            or spec.egress_policy_sha256 != request.egress_policy_sha256
            or spec.egress_admission_sha256 != request.egress_admission_sha256
            or spec.backend_admission_sha256
               != request.backend_admission_sha256
            or spec.credential_isolation_sha256
               != request.credential_isolation_sha256
            or spec.provider_provenance_sha256
               != request.provider_provenance_sha256
        ):
            raise AdapterContractError("backend/egress closure changed")
        if (
            layout.target_identity_sha256 != request.target_identity_sha256
            or layout.scope_sha256 != request.scope_sha256
            or layout.seccomp_sha256 != request.seccomp_profile_sha256
            or layout.export_destination_identity_sha256
            != request.export_destination_identity_sha256
            or spec.precreate_recensus.target_identity_sha256
            != request.target_identity_sha256
        ):
            raise AdapterContractError("layout identity closure changed")

        expected_visible_handles = (
            layout.merged_handle, layout.scratch_handle, layout.state_handle,
            layout.control_handle, layout.seccomp_handle,
            backend.credential_handle, backend.context_handle,
            runtime.runtime_handle, runtime.docs_handle, layout.scope_handle,
        )
        if tuple(item.source_handle for item in visible) != expected_visible_handles:
            raise AdapterContractError("visible guest mount handles changed")
        expected_component_handles = (
            layout.target_lower_handle, *expected_visible_handles,
        )
        if tuple(item.source_handle for item in components) != expected_component_handles:
            raise AdapterContractError("host lower or visible recensus handle changed")
        all_overlay_handles = (
            layout.target_lower_handle, layout.upper_handle,
            layout.work_handle, layout.merged_handle,
        )
        if len(set(all_overlay_handles)) != 4:
            raise AdapterContractError("lower/upper/work/merged authorities alias")
        all_source_handles = (
            layout.target_lower_handle, layout.upper_handle,
            layout.work_handle, *expected_visible_handles,
        )
        if len(set(all_source_handles)) != len(all_source_handles):
            raise AdapterContractError("attempt source authorities alias")
        if (
            components[0].content_sha256
            != spec.precreate_recensus.target_content_sha256
            or components[5].content_sha256 != request.seccomp_profile_sha256
        ):
            raise AdapterContractError("host lower or seccomp recensus changed")
        if (
            spec.rootfs_readonly is not True
            or spec.create_stopped is not True
            or spec.initial_process_count != 0
            or spec.inherited_environment != ()
            or spec.network_mode != "NARROW_TRUSTED_PROXY_ONLY"
            or backend.network_mode != spec.network_mode
        ):
            raise AdapterContractError("guest creation authority is too broad")

    @property
    def digest(self) -> str:
        return _canonical_sha256(self)

    @property
    def provider_run_id(self) -> str:
        return "psa-" + _canonical_sha256(
            (self.request.run_id, self.request.attempt_id, self.digest)
        )

    @property
    def broker_v2_commitment(self) -> BrokerV2Commitment:
        request = self.request
        return BrokerV2Commitment(
            request.fingerprint_sha256, request.attempt_id, request.run_id,
            request.source_config_sha256, request.runtime_layout_sha256,
            request.image_closure_sha256,
            request.provider_provenance_sha256,
            request.backend_admission_sha256,
            request.credential_isolation_sha256,
            request.egress_admission_sha256,
        )

    @property
    def visible_mount_authority_sha256(self) -> str:
        """Exact purpose-to-authority roster bound into native consumption."""
        return _canonical_sha256({
            "closure_sha256": self.digest,
            "schema": ADAPTER_SCHEMA + ".visible-mount-authority.v1",
            "mounts": tuple({
                "destination": item.destination,
                "mode": item.mode,
                "purpose": item.purpose,
                "source_handle": item.source_handle,
            } for item in self.create_spec.mounts),
        })

    @property
    def expected_driver_argv(self) -> tuple[str, ...]:
        return (
            self.runtime.python_path, "-B", self.runtime.driver_path,
            "/workspace/control/config.json", "--startup-intent",
            self.request.startup_intent, "--unattended", "--no-sleep",
            "--startup-decision-receipt",
            "/workspace/control/startup-decision.json",
        )

    @property
    def expected_bootstrap_argv(self) -> tuple[str, ...]:
        """Exact provider-facing launcher argv; Python prepends its fixed trio."""
        return (GUEST_BOOTSTRAP_PATH, *self.expected_driver_argv[3:])


@dataclasses.dataclass(frozen=True, slots=True)
class ProviderMountProjection:
    purpose: str
    source_purpose: str
    source_handle: str
    target: str
    readonly: bool
    kind: str
    byte_limit: int
    relative_child: str = ""

    def __post_init__(self) -> None:
        expected = next(
            (row for row in PROVIDER_MOUNT_POLICY if row[0] == self.purpose), None
        )
        actual = (
            self.purpose, self.source_purpose, self.target, self.readonly,
            self.kind, self.byte_limit, self.relative_child,
        )
        if expected is None or actual != expected:
            raise AdapterContractError("provider mount projection changed")
        if type(self.source_handle) is not str or not self.source_handle.startswith("opaque:"):
            raise AdapterContractError("provider mount source handle is invalid")


@dataclasses.dataclass(frozen=True, slots=True)
class VisibleMountProjection:
    purpose: str
    source_handle: str
    destination: str
    mode: str

    def __post_init__(self) -> None:
        if (self.purpose, self.destination, self.mode) not in VISIBLE_GUEST_MOUNT_POLICY:
            raise AdapterContractError("visible mount projection changed")
        if type(self.source_handle) is not str or not self.source_handle.startswith("opaque:"):
            raise AdapterContractError("visible mount source handle is invalid")


@dataclasses.dataclass(frozen=True, slots=True)
class CreateStoppedInput:
    closure_sha256: str
    broker_v2_commitment: BrokerV2Commitment
    ticket: TicketProjection
    request_fingerprint_sha256: str
    attempt_id: str
    run_id: str
    guest_name: str
    provider_run_id: str
    provider_attempt_number: int
    supervisor_spec_sha256: str
    precreate_recensus_sha256: str
    provider_mounts_sha256: str
    visible_mount_authority_sha256: str
    image_reference: str
    image_digest: str
    platform_architecture: str
    image_handle: str
    config_sha256: str
    config_handle: str
    entrypoint: str
    arguments: tuple[str, ...]
    environment: tuple[str, ...]
    network_policy_sha256: str
    seccomp_sha256: str
    seccomp_guest_profile: str
    provider_mounts: tuple[ProviderMountProjection, ...]
    visible_mounts: tuple[VisibleMountProjection, ...]
    tmpfs_order: tuple[str, ...]
    render_order: tuple[str, ...]
    uid: int
    gid: int
    create_stopped: bool
    initial_process_count: int
    schema: str = ADAPTER_SCHEMA
    authority_class: str = STRUCTURAL_AUTHORITY_CLASS

    def __post_init__(self) -> None:
        for value, label in (
            (self.closure_sha256, "closure"),
            (self.request_fingerprint_sha256, "request"),
            (self.supervisor_spec_sha256, "supervisor spec"),
            (self.precreate_recensus_sha256, "pre-create recensus"),
            (self.provider_mounts_sha256, "provider mounts"),
            (self.visible_mount_authority_sha256, "visible mount authority"),
            (self.image_digest, "image"), (self.config_sha256, "config"),
            (self.network_policy_sha256, "network"),
            (self.seccomp_sha256, "seccomp"),
        ):
            _digest(value, label)
        if self.schema != ADAPTER_SCHEMA or self.authority_class != STRUCTURAL_AUTHORITY_CLASS:
            raise AdapterContractError("create translation schema changed")
        if type(self.broker_v2_commitment) is not BrokerV2Commitment:
            raise AdapterContractError("create broker commitment is invalid")
        self.broker_v2_commitment.__post_init__()
        if type(self.ticket) is not TicketProjection:
            raise AdapterContractError("create translation ticket is invalid")
        self.ticket.__post_init__()
        if (
            self.ticket.operation != S.MutationOperation.CREATE_GUEST.value
            or self.ticket.request_fingerprint_sha256
            != self.request_fingerprint_sha256
            or self.ticket.attempt_id != self.attempt_id
            or self.broker_v2_commitment.request_fingerprint_sha256
               != self.request_fingerprint_sha256
            or self.broker_v2_commitment.attempt_id != self.attempt_id
            or self.broker_v2_commitment.run_identity != self.run_id
            or self.broker_v2_commitment.config_sha256 != self.config_sha256
        ):
            raise AdapterContractError("create translation ticket changed")
        if self.provider_attempt_number != 1 or self.environment != ():
            raise AdapterContractError("provider attempt/environment changed")
        if (
            type(self.attempt_id) is not str or not self.attempt_id
            or type(self.run_id) is not str or not self.run_id
            or self.guest_name != f"plamen-{self.attempt_id}"
            or self.provider_run_id != "psa-" + _canonical_sha256(
                (self.run_id, self.attempt_id, self.closure_sha256)
            )
        ):
            raise AdapterContractError("provider attempt identity changed")
        if any(
            type(value) is not str or not value.startswith("opaque:")
            for value in (self.image_handle, self.config_handle)
        ):
            raise AdapterContractError("image/config handle changed")
        if self.platform_architecture not in {"amd64", "arm64"}:
            raise AdapterContractError("provider image architecture changed")
        try:
            P.ImageSpec(
                self.image_reference, self.image_digest,
                architecture=self.platform_architecture,
            ).validate()
        except Exception:
            raise AdapterContractError("provider image admission changed") from None
        if self.create_stopped is not True or self.initial_process_count != 0:
            raise AdapterContractError("create translation can execute workload")
        if (
            self.entrypoint != GUEST_BOOTSTRAP_PATH
            or type(self.arguments) is not tuple
            or len(self.arguments) != 7
            or self.arguments[:2] != (
                "/workspace/control/config.json", "--startup-intent",
            )
            or self.arguments[2] not in {S.START_NEW_RUN, S.RESUME_EXISTING}
            or self.arguments[3:] != (
                "--unattended", "--no-sleep", "--startup-decision-receipt",
                "/workspace/control/startup-decision.json",
            )
        ):
            raise AdapterContractError("guest bootstrap command changed")
        if (
            type(self.uid) is not int or isinstance(self.uid, bool)
            or type(self.gid) is not int or isinstance(self.gid, bool)
            or self.uid <= 0 or self.gid <= 0
        ):
            raise AdapterContractError("driver user identity changed")
        if self.tmpfs_order != TMPFS_ORDER:
            raise AdapterContractError("tmpfs order changed")
        expected_render = tuple(f"tmpfs:{path}" for path in TMPFS_ORDER) + tuple(
            f"bind:{item.destination}" for item in self.visible_mounts
        )
        if self.render_order != expected_render:
            raise AdapterContractError("mount render order changed")
        if self.render_order.index("tmpfs:/run") > min(
            self.render_order.index(f"bind:{destination}")
            for destination in (
                "/run/plamen/seccomp", "/run/plamen/credentials",
                "/run/plamen/backend",
            )
        ):
            raise AdapterContractError("nested /run bind precedes parent tmpfs")
        if (
            type(self.provider_mounts) is not tuple
            or tuple(item.purpose for item in self.provider_mounts)
            != tuple(P._MOUNT_ROSTER)
            or any(type(item) is not ProviderMountProjection for item in self.provider_mounts)
        ):
            raise AdapterContractError("provider mount roster is not canonical")
        for item in self.provider_mounts:
            item.__post_init__()
        if (
            type(self.visible_mounts) is not tuple
            or tuple((item.purpose, item.destination, item.mode)
                     for item in self.visible_mounts) != VISIBLE_GUEST_MOUNT_POLICY
            or any(type(item) is not VisibleMountProjection for item in self.visible_mounts)
        ):
            raise AdapterContractError("visible mount roster is not canonical")
        for item in self.visible_mounts:
            item.__post_init__()
        visible_handles = tuple(item.source_handle for item in self.visible_mounts)
        if len(set(visible_handles)) != len(VISIBLE_GUEST_MOUNT_POLICY):
            raise AdapterContractError("visible mount authorities alias")
        expected_visible_authority = _canonical_sha256({
            "closure_sha256": self.closure_sha256,
            "schema": ADAPTER_SCHEMA + ".visible-mount-authority.v1",
            "mounts": tuple({
                "destination": item.destination,
                "mode": item.mode,
                "purpose": item.purpose,
                "source_handle": item.source_handle,
            } for item in self.visible_mounts),
        })
        if self.visible_mount_authority_sha256 != expected_visible_authority:
            raise AdapterContractError("visible mount authority binding changed")
        visible_by_purpose = {
            item.purpose: item.source_handle for item in self.visible_mounts
        }
        provider_by_purpose = {
            item.purpose: item for item in self.provider_mounts
        }
        if any(
            provider_by_purpose[purpose].source_handle
            != visible_by_purpose[purpose]
            for purpose in ("project-merged", "runtime", "state", "scratch", "seccomp")
        ):
            raise AdapterContractError("visible/provider mount authority changed")
        provider_handles = tuple(
            item.source_handle for item in self.provider_mounts
        )
        if len(set(provider_handles)) != len(provider_handles):
            raise AdapterContractError("provider mount authorities alias")
        intended_shared = {
            visible_by_purpose[purpose]
            for purpose in (
                "project-merged", "runtime", "state", "scratch", "seccomp",
            )
        }
        provider_set = set(provider_handles)
        visible_set = set(visible_handles)
        if (len(intended_shared) != 5
                or provider_set & visible_set != intended_shared
                or len(provider_set | visible_set) != 13):
            raise AdapterContractError(
                "provider/visible mount authority intersection changed"
            )
        if self.seccomp_guest_profile != SECCOMP_GUEST_PROFILE:
            raise AdapterContractError("seccomp child profile changed")

    @property
    def digest(self) -> str:
        return _canonical_sha256(self)


def _lifecycle_claim_sha256(
    operation: str, closure_sha256: str, request_fingerprint_sha256: str,
    attempt_id: str, run_id: str, guest_id: str,
    supervisor_spec_sha256: str, evidence_sha256: str,
    ticket: TicketProjection | None,
    expected_process_count: int | None,
    expected_cgroup_populated: int | None,
    expected_exit_code: int | None,
    artifact_manifest_sha256: str | None,
    artifact_census_sha256: str | None,
    export_destination_handle: str | None,
    release_roster: tuple[str, ...],
    broker_v2_commitment_sha256: str,
) -> str:
    return _canonical_sha256({
        "artifact_census_sha256": artifact_census_sha256,
        "artifact_manifest_sha256": artifact_manifest_sha256,
        "attempt_id": attempt_id,
        "broker_v2_commitment_sha256": broker_v2_commitment_sha256,
        "closure_sha256": closure_sha256,
        "evidence_sha256": evidence_sha256,
        "expected_cgroup_populated": expected_cgroup_populated,
        "expected_exit_code": expected_exit_code,
        "expected_process_count": expected_process_count,
        "export_destination_handle": export_destination_handle,
        "guest_id": guest_id,
        "operation": operation,
        "release_roster": release_roster,
        "request_fingerprint_sha256": request_fingerprint_sha256,
        "run_id": run_id,
        "schema": ADAPTER_SCHEMA + ".lifecycle-claim.v2",
        "supervisor_spec_sha256": supervisor_spec_sha256,
        "ticket_sha256": ticket.ticket_sha256 if ticket is not None else None,
    })


@dataclasses.dataclass(frozen=True, slots=True)
class LifecycleInput:
    operation: str
    closure_sha256: str
    broker_v2_commitment: BrokerV2Commitment
    ticket: TicketProjection | None
    request_fingerprint_sha256: str
    attempt_id: str
    run_id: str
    guest_id: str
    supervisor_spec_sha256: str
    evidence_sha256: str
    claim_sha256: str
    expected_process_count: int | None = None
    expected_cgroup_populated: int | None = None
    expected_exit_code: int | None = None
    artifact_manifest_sha256: str | None = None
    artifact_census_sha256: str | None = None
    export_destination_handle: str | None = None
    release_roster: tuple[str, ...] = ()
    schema: str = ADAPTER_SCHEMA
    authority_class: str = STRUCTURAL_AUTHORITY_CLASS

    def __post_init__(self) -> None:
        if self.schema != ADAPTER_SCHEMA or self.authority_class != STRUCTURAL_AUTHORITY_CLASS:
            raise AdapterContractError("lifecycle translation schema changed")
        if type(self.broker_v2_commitment) is not BrokerV2Commitment:
            raise AdapterContractError("lifecycle broker commitment is invalid")
        self.broker_v2_commitment.__post_init__()
        if (
            type(self.attempt_id) is not str or not self.attempt_id
            or type(self.run_id) is not str or not self.run_id
            or self.guest_id != f"plamen-{self.attempt_id}"
            or self.broker_v2_commitment.request_fingerprint_sha256
               != self.request_fingerprint_sha256
            or self.broker_v2_commitment.attempt_id != self.attempt_id
            or self.broker_v2_commitment.run_identity != self.run_id
        ):
            raise AdapterContractError("lifecycle attempt identity changed")
        if self.operation not in {
            "inspect-stopped", "resume-guest", "start-driver", "wait-driver",
            "extinguish", "census-artifacts", "export-artifacts",
            "delete-guest", "release-attempt",
        }:
            raise AdapterContractError("unknown adapter lifecycle operation")
        for value in (self.closure_sha256, self.request_fingerprint_sha256,
                      self.supervisor_spec_sha256,
                      self.evidence_sha256, self.claim_sha256):
            _digest(value, "lifecycle binding")
        expected_ticket = _LIFECYCLE_TICKET_OPERATIONS.get(self.operation)
        if expected_ticket is None:
            if self.ticket is not None:
                raise AdapterContractError("read-only lifecycle carries a ticket")
        else:
            if type(self.ticket) is not TicketProjection:
                raise AdapterContractError("mutating lifecycle lacks an exact ticket")
            self.ticket.__post_init__()
            if (
                self.ticket.operation != expected_ticket.value
                or self.ticket.request_fingerprint_sha256
                != self.request_fingerprint_sha256
                or self.ticket.attempt_id != self.attempt_id
            ):
                raise AdapterContractError("lifecycle ticket changed")
        if self.expected_process_count is not None and type(self.expected_process_count) is not int:
            raise AdapterContractError("lifecycle process count is invalid")
        if self.expected_cgroup_populated is not None and type(self.expected_cgroup_populated) is not int:
            raise AdapterContractError("lifecycle cgroup state is invalid")
        if self.expected_exit_code is not None and (
            type(self.expected_exit_code) is not int
            or isinstance(self.expected_exit_code, bool)
            or not 0 <= self.expected_exit_code <= 255
        ):
            raise AdapterContractError("lifecycle exit code is invalid")
        artifact_values = (
            self.artifact_manifest_sha256, self.artifact_census_sha256,
            self.export_destination_handle,
        )
        if self.operation == "export-artifacts":
            if artifact_values[2] is None or not artifact_values[2].startswith("opaque:"):
                raise AdapterContractError("export destination handle is invalid")
            _digest(artifact_values[0], "artifact manifest")
            _digest(artifact_values[1], "artifact census")
        elif any(value is not None for value in artifact_values):
            raise AdapterContractError("unexpected artifact export binding")
        # Closed operation grammar: every optional field is required to be
        # exactly present or absent for its operation.  Native code can compare
        # this tuple directly and never silently ignore attacker input.
        expected = {
            "inspect-stopped": (None, None, None, False, ()),
            "resume-guest": (None, None, None, False, ()),
            "start-driver": (1, None, None, False, ()),
            "wait-driver": (1, None, None, False, ()),
            "extinguish": (0, 0, "exit", False, ()),
            "census-artifacts": (0, 0, "exit", False, ()),
            "export-artifacts": (0, 0, "exit", True, ()),
            "delete-guest": (0, 0, None, False, ()),
            "release-attempt": (0, 0, None, False, PROVIDER_RELEASE_ROSTER),
        }[self.operation]
        actual = (
            self.expected_process_count, self.expected_cgroup_populated,
            "exit" if self.expected_exit_code is not None else None,
            all(value is not None for value in artifact_values),
            self.release_roster,
        )
        if actual != expected:
            raise AdapterContractError("lifecycle optional field grammar changed")
        expected_claim = _lifecycle_claim_sha256(
            self.operation, self.closure_sha256,
            self.request_fingerprint_sha256, self.attempt_id, self.run_id,
            self.guest_id, self.supervisor_spec_sha256, self.evidence_sha256,
            self.ticket, self.expected_process_count,
            self.expected_cgroup_populated, self.expected_exit_code,
            self.artifact_manifest_sha256, self.artifact_census_sha256,
            self.export_destination_handle, self.release_roster,
            self.broker_v2_commitment.digest,
        )
        if self.claim_sha256 != expected_claim:
            raise AdapterContractError("lifecycle claim changed")

    @property
    def digest(self) -> str:
        return _canonical_sha256(self)


def _provider_mount_projections(closure: AttemptClosure) -> tuple[ProviderMountProjection, ...]:
    handles = {
        "target-lower": closure.layout.target_lower_handle,
        "project-upper": closure.layout.upper_handle,
        "project-work": closure.layout.work_handle,
        **{item.purpose: item.source_handle for item in closure.create_spec.mounts},
    }
    return tuple(
        ProviderMountProjection(
            purpose, source_purpose, handles[source_purpose], target,
            readonly, kind, limit, relative_child,
        )
        for purpose, source_purpose, target, readonly, kind, limit, relative_child
        in PROVIDER_MOUNT_POLICY
    )


def _visible_projection_roster(
    value: CreateStoppedInput,
) -> tuple[tuple[str, str, str, str], ...]:
    return tuple(
        (item.purpose, item.source_handle, item.destination, item.mode)
        for item in value.visible_mounts
    )


def _authoritative_visible_roster(
    closure: AttemptClosure,
) -> tuple[tuple[str, str, str, str], ...]:
    return tuple(
        (item.purpose, item.source_handle, item.destination, item.mode)
        for item in closure.create_spec.mounts
    )


def _validate_create_against_closure(
    closure: AttemptClosure, value: CreateStoppedInput,
) -> CreateStoppedInput:
    closure = _exact(closure, AttemptClosure, "attempt closure")
    value = _exact(value, CreateStoppedInput, "create translation")
    if (
        value.closure_sha256 != closure.digest
        or value.broker_v2_commitment != closure.broker_v2_commitment
        or value.visible_mount_authority_sha256
           != closure.visible_mount_authority_sha256
        or _visible_projection_roster(value)
           != _authoritative_visible_roster(closure)
    ):
        raise AdapterContractError(
            "create mount projection differs from the authoritative closure"
        )
    return value


def _map_create(
    closure: AttemptClosure, ticket: S.MutationTicket,
) -> CreateStoppedInput:
    _exact(closure, AttemptClosure, "attempt closure")
    ticket = _ticket(ticket, closure, S.MutationOperation.CREATE_GUEST)
    digest = closure.create_spec.image_manifest_digest.split(":", 1)[1]
    visible = tuple(
        VisibleMountProjection(
            item.purpose, item.source_handle, item.destination, item.mode
        )
        for item in closure.create_spec.mounts
    )
    provider_mounts = _provider_mount_projections(closure)
    render_order = tuple(f"tmpfs:{path}" for path in TMPFS_ORDER) + tuple(
        f"bind:{item.destination}" for item in visible
    )
    result = CreateStoppedInput(
        closure.digest, closure.broker_v2_commitment,
        _ticket_projection(ticket),
        closure.request.fingerprint_sha256, closure.request.attempt_id,
        closure.request.run_id, closure.create_spec.guest_name,
        closure.provider_run_id, 1, closure.create_spec.spec_sha256,
        closure.create_spec.precreate_recensus_sha256,
        closure.create_spec.precreate_recensus.provider_mounts_sha256,
        closure.visible_mount_authority_sha256,
        "localhost/plamen/runtime@sha256:" + digest, digest,
        closure.runtime.guest_architecture,
        closure.runtime.image_handle, closure.configured.config_sha256,
        closure.configured.config_handle, closure.expected_bootstrap_argv[0],
        closure.expected_bootstrap_argv[1:], (),
        closure.request.egress_policy_sha256,
        closure.request.seccomp_profile_sha256, SECCOMP_GUEST_PROFILE,
        provider_mounts, visible, TMPFS_ORDER, render_order,
        closure.create_spec.uid, closure.create_spec.gid, True, 0,
    )
    return _validate_create_against_closure(closure, result)


def _created(
    closure: AttemptClosure, value: object,
) -> S.GuestCreatedReceipt:
    created = _exact(value, S.GuestCreatedReceipt, "created guest receipt")
    if (
        created.provider_kind is not S.ProviderKind.PODMAN
        or created.attempt_id != closure.request.attempt_id
        or created.create_spec != closure.create_spec
        or created.guest_id != closure.create_spec.guest_name
        or created.mount_roster_sha256
        != S.canonical_sha256(closure.create_spec.mounts)
        or created.provider_mounts_sha256
        == closure.create_spec.precreate_recensus.provider_mounts_sha256
        or created.state != "CREATED_STOPPED"
        or created.workload_started is not False
    ):
        raise AdapterContractError("created guest differs from the closed attempt")
    return created


def _admission(
    closure: AttemptClosure, created: S.GuestCreatedReceipt, value: object,
) -> S.GuestAdmissionReceipt:
    admission = _exact(value, S.GuestAdmissionReceipt, "guest admission receipt")
    if (
        admission.attempt_id != closure.request.attempt_id
        or admission.guest_id != created.guest_id
        or admission.spec_sha256 != closure.create_spec.spec_sha256
        or admission.precreate_recensus != closure.create_spec.precreate_recensus
        or admission.postcreate_recensus.provider_mounts_sha256
        != created.provider_mounts_sha256
        or admission.workload_nonexecuting is not True
        or admission.replay_consumed is not True
    ):
        raise AdapterContractError("guest admission differs from the stopped guest")
    return admission


def _launch(
    closure: AttemptClosure, created: S.GuestCreatedReceipt,
    admission: S.GuestAdmissionReceipt, value: object,
) -> S.DriverLaunch:
    launch = _exact(value, S.DriverLaunch, "driver launch")
    if (
        launch.attempt_id != closure.request.attempt_id
        or launch.guest_id != created.guest_id
        or launch.admission_sha256 != admission.admission_sha256
        or launch.argv != closure.expected_driver_argv
        or launch.cwd != "/workspace/project"
        or launch.environment != ()
        or launch.stdin != "DEVNULL"
    ):
        raise AdapterContractError("driver launch differs from the closed attempt")
    return launch


def _base_lifecycle(
    operation: str, closure: AttemptClosure, guest_id: str,
    ticket: S.MutationTicket | None, claim: object, **values: object,
) -> LifecycleInput:
    evidence_sha256 = _canonical_sha256(claim)
    projected_ticket = _ticket_projection(ticket) if ticket is not None else None
    expected_process_count = values.get("expected_process_count")
    expected_cgroup_populated = values.get("expected_cgroup_populated")
    expected_exit_code = values.get("expected_exit_code")
    artifact_manifest_sha256 = values.get("artifact_manifest_sha256")
    artifact_census_sha256 = values.get("artifact_census_sha256")
    export_destination_handle = values.get("export_destination_handle")
    release_roster = values.get("release_roster", ())
    claim_sha256 = _lifecycle_claim_sha256(
        operation, closure.digest, closure.request.fingerprint_sha256,
        closure.request.attempt_id, closure.request.run_id, guest_id,
        closure.create_spec.spec_sha256, evidence_sha256, projected_ticket,
        expected_process_count, expected_cgroup_populated, expected_exit_code,
        artifact_manifest_sha256, artifact_census_sha256,
        export_destination_handle, release_roster,
        closure.broker_v2_commitment.digest,
    )
    return LifecycleInput(
        operation, closure.digest, closure.broker_v2_commitment,
        projected_ticket,
        closure.request.fingerprint_sha256,
        closure.request.attempt_id, closure.request.run_id, guest_id,
        closure.create_spec.spec_sha256,
        evidence_sha256, claim_sha256,
        **values,
    )


def _map_inspect(
    closure: AttemptClosure, created: S.GuestCreatedReceipt,
) -> LifecycleInput:
    return _base_lifecycle("inspect-stopped", closure, created.guest_id, None, created)


def _map_resume(
    closure: AttemptClosure, created: S.GuestCreatedReceipt,
) -> LifecycleInput:
    return _base_lifecycle("resume-guest", closure, created.guest_id, None, created)


def _map_start(
    closure: AttemptClosure, created: S.GuestCreatedReceipt,
    admission: S.GuestAdmissionReceipt, launch: S.DriverLaunch,
    ticket: S.MutationTicket,
) -> LifecycleInput:
    ticket = _ticket(ticket, closure, S.MutationOperation.START_DRIVER)
    return _base_lifecycle(
        "start-driver", closure, created.guest_id, ticket,
        (created, admission, launch), expected_process_count=1,
    )


def _started(
    closure: AttemptClosure, created: S.GuestCreatedReceipt,
    launch_sha256: str, value: object,
) -> S.DriverStartReceipt:
    started = _exact(value, S.DriverStartReceipt, "driver start receipt")
    if (
        started.attempt_id != closure.request.attempt_id
        or started.guest_id != created.guest_id
        or started.launch_sha256 != launch_sha256
        or started.driver_process_count != 1
    ):
        raise AdapterContractError("driver start receipt changed")
    return started


def _map_wait(
    closure: AttemptClosure, created: S.GuestCreatedReceipt,
    started: S.DriverStartReceipt, ticket: S.MutationTicket,
) -> LifecycleInput:
    started = _exact(started, S.DriverStartReceipt, "driver start receipt")
    if (
        started.attempt_id != closure.request.attempt_id
        or started.guest_id != created.guest_id
        or started.driver_process_count != 1
    ):
        raise AdapterContractError("driver start receipt changed")
    ticket = _ticket(ticket, closure, S.MutationOperation.WAIT_DRIVER)
    return _base_lifecycle(
        "wait-driver", closure, created.guest_id, ticket,
        (created, started), expected_process_count=1,
    )


def _exited(
    closure: AttemptClosure, created: S.GuestCreatedReceipt,
    started: S.DriverStartReceipt, value: object,
) -> S.DriverExitReceipt:
    exited = _exact(value, S.DriverExitReceipt, "driver exit receipt")
    if (
        exited.attempt_id != closure.request.attempt_id
        or exited.guest_id != created.guest_id
        or exited.launch_sha256 != started.launch_sha256
    ):
        raise AdapterContractError("driver exit receipt changed")
    return exited


def _terminal(
    closure: AttemptClosure, guest_id: str, value: object,
) -> S.ExtinctionReceipt:
    terminal = _exact(value, S.ExtinctionReceipt, "extinction receipt")
    if (
        terminal.attempt_id != closure.request.attempt_id
        or terminal.guest_id != guest_id
        or terminal.cgroup_populated != 0
        or terminal.process_count != 0
        or terminal.exact_attempt is not True
    ):
        raise AdapterContractError("extinction receipt changed")
    return terminal


def _map_extinction(
    closure: AttemptClosure, created: S.GuestCreatedReceipt,
    exited: S.DriverExitReceipt, ticket: S.MutationTicket,
) -> LifecycleInput:
    exited = _exact(exited, S.DriverExitReceipt, "driver exit receipt")
    if (
        exited.attempt_id != closure.request.attempt_id
        or exited.guest_id != created.guest_id
    ):
        raise AdapterContractError("driver exit receipt changed")
    ticket = _ticket(ticket, closure, S.MutationOperation.EXTINGUISH)
    return _base_lifecycle(
        "extinguish", closure, created.guest_id, ticket,
        (created, exited), expected_process_count=0,
        expected_cgroup_populated=0, expected_exit_code=exited.exit_code,
    )


def _validate_census_for_closure(
    closure: AttemptClosure, value: object,
) -> S.ArtifactCensus:
    census = _exact(value, S.ArtifactCensus, "artifact census")
    if (
        census.attempt_id != closure.request.attempt_id
        or census.run_id != closure.request.run_id
        or census.exact is not True
        or census.immutable_lease is not True
    ):
        raise AdapterContractError("artifact census is not terminal-bound")
    allowlist = set(closure.request.export_allowlist)
    if any(item.relative_path not in allowlist for item in census.entries):
        raise AdapterContractError("artifact census exceeds the allowlist")
    if sum(item.size for item in census.entries) > closure.request.export_max_total_bytes:
        raise AdapterContractError("artifact census exceeds its byte ceiling")
    required = set(closure.request.required_artifacts)
    if census.driver_exit_code != 0:
        required.update(closure.request.failure_required_artifacts)
    entries = {item.relative_path: item for item in census.entries}
    dispositions = {item.relative_path: item for item in census.dispositions}
    if set(dispositions) != required or any(
        dispositions[path].status != "PRESENT"
        or path not in entries
        or dispositions[path].entry_sha256 != entries[path].sha256
        for path in required
    ):
        raise AdapterContractError("artifact census omits a required artifact")
    expected = S.canonical_sha256({
        "attempt_id": census.attempt_id, "run_id": census.run_id,
        "terminal_sha256": census.terminal_sha256,
        "driver_exit_code": census.driver_exit_code,
        "census_handle": census.census_handle, "entries": census.entries,
        "dispositions": census.dispositions,
    })
    if census.census_sha256 != expected:
        raise AdapterContractError("artifact census digest changed")
    return census


def _validate_census(
    closure: AttemptClosure, exited: S.DriverExitReceipt,
    terminal: S.ExtinctionReceipt, value: object,
) -> S.ArtifactCensus:
    census = _validate_census_for_closure(closure, value)
    if (
        census.terminal_sha256 != terminal.terminal_sha256
        or census.driver_exit_code != exited.exit_code
    ):
        raise AdapterContractError("artifact census is not terminal-bound")
    return census


def _map_census(
    closure: AttemptClosure, exited: S.DriverExitReceipt,
    terminal: S.ExtinctionReceipt, ticket: S.MutationTicket,
) -> LifecycleInput:
    exited = _exact(exited, S.DriverExitReceipt, "driver exit receipt")
    terminal = _terminal(closure, closure.create_spec.guest_name, terminal)
    if (
        exited.attempt_id != closure.request.attempt_id
        or exited.guest_id != terminal.guest_id
    ):
        raise AdapterContractError("terminal driver exit receipt changed")
    ticket = _ticket(ticket, closure, S.MutationOperation.CENSUS_ARTIFACTS)
    return _base_lifecycle(
        "census-artifacts", closure, terminal.guest_id, ticket,
        (exited, terminal, closure.request.export_allowlist,
         closure.request.required_artifacts,
         closure.request.failure_required_artifacts),
        expected_process_count=0, expected_cgroup_populated=0,
        expected_exit_code=exited.exit_code,
    )


def _manifest(closure: AttemptClosure, census: S.ArtifactCensus) -> str:
    return S.canonical_sha256({
        "attempt_id": closure.request.attempt_id,
        "run_id": closure.request.run_id,
        "census_sha256": census.census_sha256,
        "destination_identity_sha256":
            closure.request.export_destination_identity_sha256,
        "entries": census.entries, "dispositions": census.dispositions,
    })


def _map_export(
    closure: AttemptClosure, census: S.ArtifactCensus,
    ticket: S.MutationTicket,
) -> LifecycleInput:
    census = _validate_census_for_closure(closure, census)
    ticket = _ticket(ticket, closure, S.MutationOperation.EXPORT_ARTIFACTS)
    return _base_lifecycle(
        "export-artifacts", closure, closure.create_spec.guest_name, ticket,
        (census, closure.layout.export_destination_handle),
        expected_process_count=0, expected_cgroup_populated=0,
        expected_exit_code=census.driver_exit_code,
        artifact_manifest_sha256=_manifest(closure, census),
        artifact_census_sha256=census.census_sha256,
        export_destination_handle=closure.layout.export_destination_handle,
    )


def _map_delete(
    closure: AttemptClosure, created: S.GuestCreatedReceipt,
    terminal: S.ExtinctionReceipt, ticket: S.MutationTicket,
) -> LifecycleInput:
    terminal = _terminal(closure, created.guest_id, terminal)
    ticket = _ticket(ticket, closure, S.MutationOperation.DELETE_GUEST)
    return _base_lifecycle(
        "delete-guest", closure, created.guest_id, ticket,
        (created, terminal), expected_process_count=0,
        expected_cgroup_populated=0,
    )


def _map_release(
    closure: AttemptClosure, created: S.GuestCreatedReceipt,
    terminal: S.ExtinctionReceipt, ticket: S.MutationTicket,
) -> LifecycleInput:
    terminal = _terminal(closure, created.guest_id, terminal)
    ticket = _ticket(ticket, closure, S.MutationOperation.DELETE_GUEST)
    return _base_lifecycle(
        "release-attempt", closure, created.guest_id, ticket,
        (created, terminal, PROVIDER_RELEASE_ROSTER),
        expected_process_count=0, expected_cgroup_populated=0,
        release_roster=PROVIDER_RELEASE_ROSTER,
    )


@dataclasses.dataclass(frozen=True, slots=True)
class TEST_ONLY_HandleResolution:
    """Non-authoritative synthetic handle/path relation for translation tests."""

    source_purpose: str
    source_handle: str
    path: Path
    device: int
    inode: int
    kind: str = "directory"
    authority_class: str = TEST_ONLY_AUTHORITY_CLASS

    def __post_init__(self) -> None:
        if self.authority_class != TEST_ONLY_AUTHORITY_CLASS:
            raise AdapterContractError("test-only resolution marker changed")
        if not isinstance(self.path, Path) or not self.path.is_absolute():
            raise AdapterContractError("test-only path is not absolute")
        if self.kind not in {"directory", "regular"}:
            raise AdapterContractError("test-only source kind is invalid")
        if type(self.device) is not int or type(self.inode) is not int or self.device < 0 or self.inode < 1:
            raise AdapterContractError("test-only source identity is invalid")


@dataclasses.dataclass(frozen=True, slots=True)
class TEST_ONLY_SeccompProfileResolution:
    directory_handle: str
    path: Path
    device: int
    inode: int
    content_sha256: str
    mode: int = stat.S_IFREG | 0o400
    nlink: int = 1
    authority_class: str = TEST_ONLY_AUTHORITY_CLASS

    def __post_init__(self) -> None:
        if self.authority_class != TEST_ONLY_AUTHORITY_CLASS:
            raise AdapterContractError("test-only profile marker changed")
        _digest(self.content_sha256, "test-only seccomp profile")
        if (
            not isinstance(self.path, Path) or not self.path.is_absolute()
            or self.path.name != SECCOMP_PROFILE_BASENAME
            or type(self.device) is not int or type(self.inode) is not int
            or self.device < 0 or self.inode < 1
            or self.nlink != 1 or not stat.S_ISREG(self.mode)
            or self.mode & 0o222
        ):
            raise AdapterContractError("test-only seccomp profile is unsafe")


@dataclasses.dataclass(frozen=True, slots=True)
class TEST_ONLY_ResolvedCreate:
    provider_spec: P.ContainerSpec
    visible_bind_sources: tuple[tuple[str, Path, str, str], ...]
    render_order: tuple[str, ...]
    create_input_sha256: str
    authority_class: str = TEST_ONLY_AUTHORITY_CLASS

    def __post_init__(self) -> None:
        if self.authority_class != TEST_ONLY_AUTHORITY_CLASS:
            raise AdapterContractError("resolved translation is not test-only")
        try:
            self.provider_spec.validate()
        except Exception:
            raise AdapterContractError("resolved provider specification is invalid") from None


def TEST_ONLY_translate_create(
    closure: AttemptClosure, ticket: S.MutationTicket,
) -> CreateStoppedInput:
    """Return structural create input; never call a provider or resource API."""
    return _map_create(closure, ticket)


def TEST_ONLY_resolve_create(
    closure: AttemptClosure, create: CreateStoppedInput,
    resolutions: tuple[TEST_ONLY_HandleResolution, ...],
    seccomp_profile: TEST_ONLY_SeccompProfileResolution,
) -> TEST_ONLY_ResolvedCreate:
    """Resolve fake paths solely to prove the accepted Podman model mapping."""
    create = _validate_create_against_closure(closure, create)
    if type(resolutions) is not tuple or any(
        type(item) is not TEST_ONLY_HandleResolution for item in resolutions
    ):
        raise AdapterContractError("test-only resolution roster is invalid")
    expected = tuple(
        dict.fromkeys(item.source_purpose for item in create.provider_mounts)
    ) + tuple(
        item.purpose for item in create.visible_mounts
        if item.purpose not in {
            projection.source_purpose for projection in create.provider_mounts
        }
    )
    if tuple(item.source_purpose for item in resolutions) != expected:
        raise AdapterContractError("test-only resolution roster changed")
    by_purpose = {item.source_purpose: item for item in resolutions}
    expected_handles = {
        item.source_purpose: item.source_handle for item in create.provider_mounts
    }
    expected_handles.update(
        {item.purpose: item.source_handle for item in create.visible_mounts}
    )
    if any(by_purpose[purpose].source_handle != handle
           for purpose, handle in expected_handles.items()):
        raise AdapterContractError("test-only handle resolution changed")
    for item in resolutions:
        item.__post_init__()
    identities = tuple((item.device, item.inode) for item in resolutions)
    paths = tuple(PurePosixPath(os.fspath(item.path)) for item in resolutions)
    if len(set(identities)) != len(identities) or len(set(paths)) != len(paths):
        raise AdapterContractError("test-only resolved sources alias")
    for index, left in enumerate(paths):
        for right in paths[index + 1:]:
            if left in right.parents or right in left.parents:
                raise AdapterContractError("test-only resolved sources overlap")
    seccomp_profile.__post_init__()
    seccomp_dir = by_purpose["seccomp"]
    if (
        seccomp_profile.directory_handle != seccomp_dir.source_handle
        or seccomp_profile.path.parent != seccomp_dir.path
        or seccomp_profile.content_sha256 != create.seccomp_sha256
        or (seccomp_profile.device, seccomp_profile.inode) in set(identities)
    ):
        raise AdapterContractError("seccomp child profile changed")

    provider_mounts: list[P.MountRequest] = []
    for projection in create.provider_mounts:
        resolution = by_purpose[projection.source_purpose]
        source = seccomp_profile.path if projection.relative_child else resolution.path
        actual_kind = "regular" if projection.relative_child else resolution.kind
        if actual_kind != projection.kind:
            raise AdapterContractError("provider source kind changed")
        provider_mounts.append(P.MountRequest(projection.purpose, source))
    provider_spec = P.ContainerSpec(
        run_id=create.provider_run_id,
        attempt_number=create.provider_attempt_number,
        image=P.ImageSpec(
            create.image_reference, create.image_digest,
            architecture=create.platform_architecture,
        ),
        entrypoint=create.entrypoint, arguments=create.arguments,
        environment=create.environment, mounts=tuple(provider_mounts),
        network_policy_sha256=create.network_policy_sha256,
        seccomp_sha256=create.seccomp_sha256,
        uid=create.uid, gid=create.gid,
    )
    visible = tuple(
        (
            item.purpose, by_purpose[item.purpose].path,
            item.destination, item.mode,
        )
        for item in create.visible_mounts
    )
    return TEST_ONLY_ResolvedCreate(
        provider_spec, visible, create.render_order, create.digest
    )


def TEST_ONLY_translate_lifecycle(
    operation: str, closure: AttemptClosure, **values: object,
) -> LifecycleInput:
    """Dispatch an exact fake-only lifecycle translation."""
    _exact(closure, AttemptClosure, "attempt closure")
    if operation not in {
        "inspect-stopped", "resume-guest", "start-driver", "wait-driver",
        "extinguish", "census-artifacts", "export-artifacts",
        "delete-guest", "release-attempt",
    }:
        raise AdapterContractError("unknown test-only lifecycle operation")
    if operation == "inspect-stopped":
        return _map_inspect(closure, _created(closure, values.get("created")))
    if operation == "resume-guest":
        return _map_resume(closure, _created(closure, values.get("created")))
    if operation == "export-artifacts":
        return _map_export(
            closure, values.get("census"), values.get("ticket")
        )
    created = _created(closure, values.get("created"))
    if operation == "start-driver":
        admission = _admission(closure, created, values.get("admission"))
        launch = _launch(closure, created, admission, values.get("launch"))
        return _map_start(closure, created, admission, launch, values.get("ticket"))
    if operation == "wait-driver":
        started = _exact(values.get("started"), S.DriverStartReceipt, "driver start receipt")
        return _map_wait(closure, created, started, values.get("ticket"))
    if operation == "extinguish":
        return _map_extinction(
            closure, created, values.get("exited"), values.get("ticket")
        )
    terminal = _terminal(closure, created.guest_id, values.get("terminal"))
    if operation == "delete-guest":
        return _map_delete(closure, created, terminal, values.get("ticket"))
    if operation == "release-attempt":
        return _map_release(closure, created, terminal, values.get("ticket"))
    exited = _exact(values.get("exited"), S.DriverExitReceipt, "driver exit receipt")
    if operation == "census-artifacts":
        return _map_census(closure, exited, terminal, values.get("ticket"))
    raise AdapterContractError("unknown test-only lifecycle operation")


def _native_types() -> tuple[type[Any], type[Any], type[Any]]:
    """Authenticate the unified role split, then retain the lifecycle hard stop.

    The admission-only C slice returns no Python capability. The role-2 guest
    bundle authorizes only backend execution inside an already admitted guest;
    neither is an outer Podman lifecycle adapter.
    """
    try:
        system_namespace = types.ModuleType.__getattribute__(sys, "__dict__")
        module_table = system_namespace.get("modules")
        if type(module_table) is not dict:
            raise TypeError
        module = module_table.get(NATIVE_MODULE_NAME)
        if type(module) is not types.ModuleType:
            raise TypeError
        namespace = types.ModuleType.__getattribute__(module, "__dict__")
        spec = namespace.get("__spec__")
        if type(namespace) is not dict or type(spec) is not importlib.machinery.ModuleSpec:
            raise TypeError
        spec_namespace = object.__getattribute__(spec, "__dict__")
        loader = spec_namespace.get("loader")
        if type(loader) is not importlib.machinery.ExtensionFileLoader:
            raise TypeError
        loader_namespace = object.__getattribute__(loader, "__dict__")
        type_names = (
            "NativeAuthorityConsumer", "BrokerV2AuthorityConsumer",
            "SupervisorAuthorities", *_NATIVE_OUTER_AUTHORITY_TYPE_NAMES,
            "GuestDriverAuthorities", "BackendExecutionAuthority",
        )
        native_types = tuple(namespace.get(name) for name in type_names)
        metadata = (
            namespace.get("__name__"), namespace.get("__file__"),
            namespace.get("BROKER_V2_ABI_SCHEMA"),
            namespace.get("BROKER_V2_PRODUCTION_ACQUISITION"),
            spec_namespace.get("name"), spec_namespace.get("origin"),
            loader_namespace.get("name"), loader_namespace.get("path"),
        )
        if (any(type(value) is not str for value in metadata)
                or any(not value or len(value) > 4096 or "\x00" in value
                       for value in metadata)):
            raise TypeError
        (module_name, module_file, abi_schema, acquisition, spec_name,
         origin, loader_name, loader_path) = metadata
        if (
            module_name != NATIVE_MODULE_NAME
            or spec_name != NATIVE_MODULE_NAME
            or loader_name != NATIVE_MODULE_NAME
            or abi_schema != NATIVE_ABI_SCHEMA
            or acquisition != NATIVE_PRODUCTION_ACQUISITION
            or module_file != origin or loader_path != origin
            or namespace.get("TEST_ONLY_BUILD") is not False
            or namespace.get("BROKER_V2_INITIAL_AUTHORITY_AVAILABLE") is not True
            or not any(origin.endswith(suffix)
                       for suffix in _NATIVE_EXTENSION_SUFFIXES)
            or any(type(value) is not type for value in native_types)
        ):
            raise TypeError
        (consumer_type, compatibility_consumer_type, outer_bundle_type,
         *outer_authority_types, guest_bundle_type,
         backend_execution_type) = native_types
        if compatibility_consumer_type is not consumer_type:
            raise TypeError
        if len(outer_authority_types) != len(_NATIVE_OUTER_AUTHORITY_TYPE_NAMES):
            raise TypeError
        distinct = (
            consumer_type, outer_bundle_type, *outer_authority_types,
            guest_bundle_type, backend_execution_type,
        )
        if len(set(distinct)) != len(distinct):
            raise TypeError
        for native_type in distinct:
            type_namespace = type.__getattribute__(native_type, "__dict__")
            if (
                type.__getattribute__(native_type, "__module__")
                != NATIVE_MODULE_NAME
                or type.__getattribute__(native_type, "__flags__") & (1 << 9)
                or type(type_namespace) is not types.MappingProxyType
            ):
                raise TypeError
        for native_type in (
            consumer_type, outer_bundle_type, guest_bundle_type,
        ):
            type_namespace = type.__getattribute__(native_type, "__dict__")
            if (type(type_namespace.get("consume_once"))
                    is not types.MethodDescriptorType):
                raise TypeError
        for native_type, (_name, method_names) in zip(
            outer_authority_types, _NATIVE_OUTER_AUTHORITY_METHODS, strict=True,
        ):
            type_namespace = type.__getattribute__(native_type, "__dict__")
            if any(type(type_namespace.get(method_name))
                   is not types.MethodDescriptorType
                   for method_name in method_names):
                raise TypeError
        if type(namespace.get("INITIAL_AUTHORITY")) is not consumer_type:
            raise TypeError
    except BaseException:
        pass
    # The unified extension intentionally has no Podman outer-provider call
    # capability yet.  In particular, never consume a role-2 initial authority
    # here and never recreate the obsolete adapter/call capability pair.
    raise AdapterUnavailableError("native Podman outer provider is unavailable")


class PodmanSupervisorAdapter:
    """Nominal provider protocol shape; production construction is forbidden."""

    __slots__ = ()

    def __new__(cls, *_args: object, **_kwargs: object) -> "PodmanSupervisorAdapter":
        raise TypeError("native adapter factory required")

    def provider_kind(self) -> S.ProviderKind:
        _native_types()
        raise AdapterUnavailableError("native Podman outer provider is unavailable")

    def create_stopped(
        self, spec: S.GuestCreateSpec, ticket: S.MutationTicket,
    ) -> S.GuestCreatedReceipt:
        _native_types()
        raise AdapterUnavailableError("native Podman outer provider is unavailable")

    def inspect_stopped(self, created: S.GuestCreatedReceipt) -> S.GuestObservation:
        _native_types()
        raise AdapterUnavailableError("native Podman outer provider is unavailable")

    def resume_guest(
        self, request: S.AuditRequest, created: S.GuestCreatedReceipt,
    ) -> S.GuestCreatedReceipt:
        _native_types()
        raise AdapterUnavailableError("native Podman outer provider is unavailable")

    def start_driver(
        self, created: S.GuestCreatedReceipt,
        admission: S.GuestAdmissionReceipt, launch: S.DriverLaunch,
        ticket: S.MutationTicket,
    ) -> S.DriverStartReceipt:
        _native_types()
        raise AdapterUnavailableError("native Podman outer provider is unavailable")

    def wait_driver(
        self, created: S.GuestCreatedReceipt, started: S.DriverStartReceipt,
        ticket: S.MutationTicket,
    ) -> S.DriverExitReceipt:
        _native_types()
        raise AdapterUnavailableError("native Podman outer provider is unavailable")

    def extinguish(
        self, request: S.AuditRequest, created: S.GuestCreatedReceipt,
        exited: S.DriverExitReceipt, ticket: S.MutationTicket,
    ) -> S.ExtinctionReceipt:
        _native_types()
        raise AdapterUnavailableError("native Podman outer provider is unavailable")

    def census(
        self, request: S.AuditRequest, layout: S.AttemptLayout,
        exited: S.DriverExitReceipt, terminal: S.ExtinctionReceipt,
        ticket: S.MutationTicket,
    ) -> S.ArtifactCensus:
        _native_types()
        raise AdapterUnavailableError("native Podman outer provider is unavailable")

    def export(
        self, request: S.AuditRequest, layout: S.AttemptLayout,
        census: S.ArtifactCensus, ticket: S.MutationTicket,
    ) -> S.ExportReceipt:
        _native_types()
        raise AdapterUnavailableError("native Podman outer provider is unavailable")

    def delete_guest(
        self, created: S.GuestCreatedReceipt,
        terminal: S.ExtinctionReceipt, ticket: S.MutationTicket,
    ) -> S.DeleteReceipt:
        _native_types()
        raise AdapterUnavailableError("native Podman outer provider is unavailable")


def open_podman_supervisor_adapter(
    closure: AttemptClosure, native_consumer: object,
) -> PodmanSupervisorAdapter:
    """Retain a first-effect hard stop until Linux outer authority exists."""
    # Authenticating the preloaded unified module is the only permitted action.
    # This always raises because role 2 is guest-backend-only and no native
    # Podman outer-provider operational capability exists yet.
    _native_types()
    raise AdapterUnavailableError("native Podman outer provider is unavailable")


__all__ = [
    "ADAPTER_SCHEMA", "AdapterAmbiguousError", "AdapterContractError",
    "AdapterError", "AdapterUnavailableError", "AttemptClosure",
    "BrokerV2Commitment", "CreateStoppedInput", "LifecycleInput",
    "GUEST_BOOTSTRAP_PATH",
    "NATIVE_ABI_SCHEMA", "NATIVE_ADMISSION_GRANTS_LIFECYCLE",
    "NATIVE_ADMISSION_SCHEMA", "NATIVE_ADMISSION_STATUS",
    "NATIVE_LIFECYCLE_AVAILABLE", "NATIVE_LIFECYCLE_REQUIRED_RECEIPTS",
    "NATIVE_LIFECYCLE_SCHEMA", "NATIVE_LIFECYCLE_STATUS",
    "NATIVE_MODULE_NAME", "NATIVE_PRODUCTION_ACQUISITION",
    "PROVIDER_MOUNT_POLICY", "PROVIDER_RELEASE_ROSTER",
    "PodmanSupervisorAdapter", "SECCOMP_GUEST_PROFILE",
    "SECCOMP_PROFILE_BASENAME", "STRUCTURAL_AUTHORITY_CLASS",
    "TMPFS_ORDER", "TicketProjection",
    "VISIBLE_GUEST_MOUNT_POLICY", "open_podman_supervisor_adapter",
]
