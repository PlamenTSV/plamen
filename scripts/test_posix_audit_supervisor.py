"""Fake-only tests for the provider-neutral POSIX audit supervisor."""

from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
from typing import Any

import pytest

import posix_audit_supervisor as S


def _h(index: int) -> str:
    return "opaque:" + f"{index:064x}"


def _d(character: str) -> str:
    return character * 64


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


_COMPONENT_ROSTER = (
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
_APPLE_COMPONENT_ROSTER = _COMPONENT_ROSTER


def _provider_mounts_sha(phase: str) -> str:
    return S.canonical_sha256(
        tuple(
            (purpose, _sha(f"provider-mount:{phase}:{index}"))
            for index, (purpose, _attachment, _mode)
            in enumerate(_COMPONENT_ROSTER)
        )
    )


def _replace_component_content(
    recensus: S.LayoutRecensus, index: int, content_sha256: str,
) -> S.LayoutRecensus:
    components = list(recensus.components)
    components[index] = replace(
        components[index], content_sha256=content_sha256
    )
    stable = {
        "attempt_id": recensus.attempt_id,
        "layout_handle": recensus.layout_handle,
        "target_identity_sha256": recensus.target_identity_sha256,
        "target_content_sha256": recensus.target_content_sha256,
        "components": tuple(
            {
                "purpose": row.purpose,
                "source_handle": row.source_handle,
                "attachment": row.attachment,
                "mode": row.mode,
                "identity_sha256": row.identity_sha256,
                "content_sha256": row.content_sha256,
            }
            for row in components
        ),
    }
    return replace(
        recensus, components=tuple(components),
        layout_sha256=S.canonical_sha256(stable),
    )


class _Crash(BaseException):
    pass


class _World:
    def __init__(self, kind: S.ProviderKind = S.ProviderKind.APPLE_CONTAINER) -> None:
        self.kind = kind
        self.events: list[str] = []
        self.effects: dict[S.MutationOperation, object] = {}
        self.effect_counts = {operation: 0 for operation in S.MutationOperation}
        self.crash_after: set[S.MutationOperation] = set()
        self.unproven: set[S.MutationOperation] = set()
        self.target_files: dict[str, bytes] = {"Contract.sol": b"contract C {}\n"}
        self.target_readonly = True
        self.guest_state = "absent"
        self.driver_starts = 0
        self.driver_exit_code = 0
        self.specs: list[S.GuestCreateSpec] = []
        self.launches: list[S.DriverLaunch] = []
        self.configs: list[S.GuestConfig] = []
        self.exported: list[tuple[S.ArtifactEntry, ...]] = []
        self.artifact_hazard: str | None = None
        self.publication_hazard: str | None = None
        self.layout_hazard: str | None = None
        self.journal = _Journal(self)

    def target_content_sha256(self) -> str:
        source_content = self.source_content_sha256()
        report = self.target_files.get(S.PUBLISHED_REPORT_PATH)
        if report is None:
            return source_content
        return S.canonical_sha256(
            {
                "source_content_sha256": source_content,
                "published_artifact": {
                    "relative_path": S.PUBLISHED_REPORT_PATH,
                    "size": len(report),
                    "sha256": hashlib.sha256(report).hexdigest(),
                },
            }
        )

    def source_content_sha256(self) -> str:
        return S.canonical_sha256(
            tuple(
                sorted(
                    (name, value.hex())
                    for name, value in self.target_files.items()
                    if name != S.PUBLISHED_REPORT_PATH
                )
            )
        )

    def record(
        self, operation: S.MutationOperation, ticket: S.MutationTicket,
        receipt: object,
    ) -> object:
        assert self.journal.pending == ticket
        assert ticket.operation is operation
        self.effects[operation] = receipt
        self.effect_counts[operation] += 1
        self.events.append(f"effect:{operation.value}")
        if operation in self.crash_after:
            self.crash_after.remove(operation)
            raise _Crash(operation.value)
        return receipt


def _request(
    request_type: S.RequestType = S.RequestType.SC_NEW,
    *, attempt: str = "attempt-001", request_id: str = "request-001",
    run_id: str = "run-001", backend: str = "codex",
    language: str | None = None,
    config_options: dict[str, Any] | None = None,
) -> S.AuditRequest:
    pipeline = "l1" if request_type is S.RequestType.L1_NEW else "sc"
    selected_language = language or ("rust" if pipeline == "l1" else "evm")
    config_document: dict[str, Any] = {
        "_run_id": run_id,
        "cli_backend": backend,
        "docs_inputs": ["/workspace/docs/design.md"],
        "docs_path": "/workspace/docs",
        "language": selected_language,
        "mode": "core",
        "pipeline": pipeline,
        "project_root": "/workspace/project",
        "scope_file": "/workspace/scope",
        "scratchpad": "/workspace/scratch",
    }
    if config_options:
        config_document.update(config_options)
    config_bytes = S._canonical_bytes(config_document)
    source_config = S.AuthenticatedDriverConfig(
        _h(90), config_bytes, hashlib.sha256(config_bytes).hexdigest()
    )
    return S.AuditRequest(
        request_type=request_type,
        request_id=request_id,
        attempt_id=attempt,
        run_id=run_id,
        pipeline=pipeline,
        mode="core",
        backend=backend,
        language=selected_language,
        source_config=source_config,
        source_config_sha256=source_config.sha256,
        startup_decision_receipt_sha256=_d("2"),
        target_identity_sha256=_d("3"),
        runtime_layout_sha256=_d("4"),
        image_manifest_digest="sha256:" + _d("5"),
        image_closure_sha256=_d("d"),
        docs_sha256=_d("6"),
        scope_sha256=_d("7"),
        seccomp_profile_sha256=_d("a"),
        credential_bundle_sha256=_d("b"),
        credential_isolation_sha256=_d("e"),
        backend_context_sha256=_d("8"),
        backend_admission_sha256=_d("f"),
        egress_policy_sha256=_d("9"),
        egress_admission_sha256=_d("0"),
        provider_provenance_sha256=_d("1"),
        export_allowlist=(
            "project/AUDIT_REPORT.md",
            "scratch/_plamen.log",
            "scratch/_v2_checkpoint.json",
            "scratch/finding_records.json",
        ),
        required_artifacts=(
            "project/AUDIT_REPORT.md",
            "scratch/_v2_checkpoint.json",
        ),
        failure_required_artifacts=("scratch/_plamen.log",),
        export_destination_identity_sha256=_d("c"),
    )


class _Runtime:
    def __init__(self, architecture: str = "arm64") -> None:
        self.architecture = architecture

    def authenticate(self, request: S.AuditRequest) -> S.AuthenticatedRuntimeImageLayout:
        return S.AuthenticatedRuntimeImageLayout(
            request.runtime_layout_sha256,
            request.image_manifest_digest,
            request.image_closure_sha256,
            request.docs_sha256,
            _h(30), _h(31), _h(32),
            guest_architecture=self.architecture,
        )


class _Workspace:
    def __init__(self, world: _World) -> None:
        self.world = world

    def admit_target(self, request: S.AuditRequest) -> S.TargetLease:
        return S.TargetLease(
            _h(1), request.target_identity_sha256,
            self.world.source_content_sha256(), self.world.target_readonly,
            ".scratchpad" not in self.world.target_files, True,
        )

    def revalidate_target(
        self, _request: S.AuditRequest, target: S.TargetLease,
    ) -> S.TargetRecensus:
        return S.TargetRecensus(
            target.target_handle, target.identity_sha256,
            self.world.target_content_sha256(), self.world.target_readonly,
            ".scratchpad" not in self.world.target_files,
        )

    def prepare_layout(
        self, request: S.AuditRequest, target: S.TargetLease,
        ticket: S.MutationTicket,
    ) -> S.AttemptLayout:
        layout = S.AttemptLayout(
            request.attempt_id, request.run_id,
            _h(10), target.target_handle, _h(11), _h(12), _h(13),
            _h(14), _h(15), _h(16), _h(17), _h(18),
            target.identity_sha256, request.scope_sha256,
            request.seccomp_profile_sha256, _h(19),
            request.export_destination_identity_sha256,
        )
        return self.world.record(S.MutationOperation.PREPARE_LAYOUT, ticket, layout)  # type: ignore[return-value]

    def resume_layout(
        self, _request: S.AuditRequest, layout: S.AttemptLayout,
    ) -> S.AttemptLayout:
        self.world.events.append("resume:layout")
        return layout

    def write_guest_config(
        self, request: S.AuditRequest, _layout: S.AttemptLayout,
        config: S.GuestConfig, ticket: S.MutationTicket,
    ) -> S.ConfigReceipt:
        self.world.configs.append(config)
        receipt = S.ConfigReceipt(
            request.attempt_id, request.run_id, _h(20),
            config.config_sha256, request.source_config_sha256,
            request.startup_decision_receipt_sha256, config,
        )
        return self.world.record(S.MutationOperation.WRITE_CONFIG, ticket, receipt)  # type: ignore[return-value]

    def recensus_layout(
        self, request: S.AuditRequest, target: S.TargetLease,
        layout: S.AttemptLayout,
        runtime: S.AuthenticatedRuntimeImageLayout,
        backend: S.BackendContext, configured: S.ConfigReceipt,
        phase: str,
    ) -> S.LayoutRecensus:
        handles = (
            target.target_handle,
            layout.merged_handle,
            layout.scratch_handle,
            layout.state_handle,
            layout.control_handle,
            layout.seccomp_handle,
            backend.credential_handle,
            backend.context_handle,
            runtime.runtime_handle,
            runtime.docs_handle,
            layout.scope_handle,
        )
        contents = (
            target.content_sha256,
            _sha("merged-content"),
            _sha("scratch-content"),
            _sha("state-content"),
            S._control_content_sha256(request, configured),
            layout.seccomp_sha256,
            backend.credential_sha256,
            backend.context_sha256,
            runtime.runtime_layout_sha256,
            runtime.docs_sha256,
            layout.scope_sha256,
        )
        if phase == "POST_CREATE" and self.world.layout_hazard == "content-drift":
            contents = (contents[0], _sha("replaced-merged"), *contents[2:])
        roster = (
            _APPLE_COMPONENT_ROSTER
            if self.world.kind is S.ProviderKind.APPLE_CONTAINER
            else _COMPONENT_ROSTER
        )
        components = tuple(
            S.LayoutComponent(
                purpose, handle, attachment, mode,
                _sha(f"component-identity:{index}"), contents[index],
                _sha(f"provider-mount:{phase}:{index}"),
            )
            for index, ((purpose, attachment, mode), handle)
            in enumerate(zip(roster, handles, strict=True))
        )
        stable = {
            "attempt_id": request.attempt_id,
            "layout_handle": layout.layout_handle,
            "target_identity_sha256": target.identity_sha256,
            "target_content_sha256": target.content_sha256,
            "components": tuple(
                {
                    "purpose": row.purpose,
                    "source_handle": row.source_handle,
                    "attachment": row.attachment,
                    "mode": row.mode,
                    "identity_sha256": row.identity_sha256,
                    "content_sha256": row.content_sha256,
                }
                for row in components
            ),
        }
        return S.LayoutRecensus(
            request.attempt_id, layout.layout_handle, target.identity_sha256,
            target.content_sha256, components, S.canonical_sha256(stable), phase,
        )


class _Backend:
    def authenticate(self, request: S.AuditRequest) -> S.BackendContext:
        return S.BackendContext(
            request.backend, request.backend_context_sha256,
            request.backend_admission_sha256,
            request.egress_policy_sha256, request.egress_admission_sha256,
            request.credential_bundle_sha256,
            request.credential_isolation_sha256,
            _h(40), _h(41),
        )


class _Provider:
    def __init__(self, world: _World) -> None:
        self.world = world

    def provider_kind(self) -> S.ProviderKind:
        return self.world.kind

    def create_stopped(
        self, spec: S.GuestCreateSpec, ticket: S.MutationTicket,
    ) -> S.GuestCreatedReceipt:
        assert self.world.guest_state == "absent"
        self.world.specs.append(spec)
        self.world.guest_state = "stopped"
        receipt = S.GuestCreatedReceipt(
            self.world.kind, spec.attempt_id, f"guest-{spec.attempt_id}",
            spec, S.canonical_sha256(spec.mounts),
            _provider_mounts_sha("POST_CREATE"),
        )
        return self.world.record(S.MutationOperation.CREATE_GUEST, ticket, receipt)  # type: ignore[return-value]

    def inspect_stopped(self, created: S.GuestCreatedReceipt) -> S.GuestObservation:
        assert self.world.guest_state == "stopped"
        return S.GuestObservation(
            self.world.kind, created.guest_id, created.spec_sha256,
            created.mount_roster_sha256, created.provider_mounts_sha256,
        )

    def resume_guest(
        self, _request: S.AuditRequest, created: S.GuestCreatedReceipt,
    ) -> S.GuestCreatedReceipt:
        assert self.world.guest_state != "absent" or (
            self.world.journal.checkpoint.stage is S.SupervisorStage.DELETED
        )
        self.world.events.append("resume:guest")
        return created

    def start_driver(
        self, created: S.GuestCreatedReceipt,
        _admission: S.GuestAdmissionReceipt, launch: S.DriverLaunch,
        ticket: S.MutationTicket,
    ) -> S.DriverStartReceipt:
        assert self.world.guest_state == "stopped"
        self.world.driver_starts += 1
        self.world.launches.append(launch)
        self.world.guest_state = "running"
        receipt = S.DriverStartReceipt(
            created.attempt_id, created.guest_id, launch.launch_sha256,
            f"driver-{created.attempt_id}", 1,
        )
        return self.world.record(S.MutationOperation.START_DRIVER, ticket, receipt)  # type: ignore[return-value]

    def wait_driver(
        self, created: S.GuestCreatedReceipt, started: S.DriverStartReceipt,
        ticket: S.MutationTicket,
    ) -> S.DriverExitReceipt:
        assert self.world.guest_state == "running"
        self.world.guest_state = "exited"
        receipt = S.DriverExitReceipt(
            created.attempt_id, created.guest_id, started.launch_sha256,
            self.world.driver_exit_code,
            S.canonical_sha256(
                (created.guest_id, started.launch_sha256, self.world.driver_exit_code)
            ),
        )
        return self.world.record(S.MutationOperation.WAIT_DRIVER, ticket, receipt)  # type: ignore[return-value]

    def delete_guest(
        self, created: S.GuestCreatedReceipt, terminal: S.ExtinctionReceipt,
        ticket: S.MutationTicket,
    ) -> S.DeleteReceipt:
        assert self.world.guest_state == "extinct"
        self.world.guest_state = "absent"
        receipt = S.DeleteReceipt(
            self.world.kind, created.attempt_id, created.guest_id,
            terminal.terminal_sha256,
        )
        return self.world.record(S.MutationOperation.DELETE_GUEST, ticket, receipt)  # type: ignore[return-value]


class _Admission:
    def __init__(self, world: _World) -> None:
        self.world = world

    def admit_stopped_guest(
        self, request: S.AuditRequest, created: S.GuestCreatedReceipt,
        observation: S.GuestObservation, postcreate: S.LayoutRecensus,
        ticket: S.MutationTicket,
    ) -> S.GuestAdmissionReceipt:
        assert observation.workload_process_count == 0
        receipt = S.GuestAdmissionReceipt(
            request.attempt_id, created.guest_id, _h(50),
            S.canonical_sha256(
                (
                    request.fingerprint_sha256, created.spec_sha256,
                    created.create_spec.precreate_recensus,
                    postcreate,
                )
            ),
            created.create_spec.precreate_recensus, postcreate,
            S._validate_layout_delta(
                created.create_spec.precreate_recensus, postcreate
            ),
            created.spec_sha256,
        )
        return self.world.record(S.MutationOperation.ADMIT_GUEST, ticket, receipt)  # type: ignore[return-value]

    def resume_admission(
        self, _request: S.AuditRequest, _created: S.GuestCreatedReceipt,
        admission: S.GuestAdmissionReceipt,
    ) -> S.GuestAdmissionReceipt:
        self.world.events.append("resume:admission")
        return admission


class _Extinction:
    def __init__(self, world: _World) -> None:
        self.world = world

    def extinguish(
        self, request: S.AuditRequest, created: S.GuestCreatedReceipt,
        _exited: S.DriverExitReceipt, ticket: S.MutationTicket,
    ) -> S.ExtinctionReceipt:
        assert self.world.guest_state == "exited"
        self.world.guest_state = "extinct"
        receipt = S.ExtinctionReceipt(
            request.attempt_id, created.guest_id,
            S.canonical_sha256((request.attempt_id, created.guest_id, "extinct")),
        )
        return self.world.record(S.MutationOperation.EXTINGUISH, ticket, receipt)  # type: ignore[return-value]


def _forged_entry(
    path: str, size: int, *, kind: str = "regular", symlink: bool = False,
    hardlink_count: int = 1,
) -> S.ArtifactEntry:
    value = object.__new__(S.ArtifactEntry)
    object.__setattr__(value, "relative_path", path)
    object.__setattr__(value, "size", size)
    object.__setattr__(value, "sha256", _d("a"))
    object.__setattr__(value, "object_kind", kind)
    object.__setattr__(value, "symlink", symlink)
    object.__setattr__(value, "hardlink_count", hardlink_count)
    return value


class _Artifacts:
    def __init__(self, world: _World) -> None:
        self.world = world

    def census(
        self, request: S.AuditRequest, _layout: S.AttemptLayout,
        exited: S.DriverExitReceipt, terminal: S.ExtinctionReceipt,
        ticket: S.MutationTicket,
    ) -> S.ArtifactCensus:
        hazard = self.world.artifact_hazard
        if hazard == "traversal":
            entries = (_forged_entry("project/../credentials", 1),)
        elif hazard == "symlink":
            entries = (_forged_entry("project/AUDIT_REPORT.md", 1, symlink=True),)
        elif hazard == "special":
            entries = (_forged_entry("project/AUDIT_REPORT.md", 1, kind="socket"),)
        elif hazard == "oversized":
            entries = (_forged_entry("project/AUDIT_REPORT.md", S.MAX_EXPORT_FILE_BYTES + 1),)
        elif hazard == "hardlink":
            entries = (
                _forged_entry(
                    "project/AUDIT_REPORT.md", 1, hardlink_count=2
                ),
            )
        elif hazard == "case-alias":
            entries = (
                _forged_entry("project/AUDIT_REPORT.md", 1),
                _forged_entry("project/audit_report.md", 1),
            )
        else:
            rows = [
                S.ArtifactEntry(
                    "project/AUDIT_REPORT.md", 7,
                    hashlib.sha256(b"report\n").hexdigest(),
                ),
                S.ArtifactEntry(
                    "scratch/_plamen.log", 4,
                    hashlib.sha256(b"log\n").hexdigest(),
                ),
                S.ArtifactEntry(
                    "scratch/_v2_checkpoint.json", 3,
                    hashlib.sha256(b"{}\n").hexdigest(),
                ),
                S.ArtifactEntry(
                    "scratch/finding_records.json", 3,
                    hashlib.sha256(b"{}\n").hexdigest(),
                ),
            ]
            if hazard == "missing-report":
                rows = [row for row in rows if row.relative_path != "project/AUDIT_REPORT.md"]
            if hazard == "missing-checkpoint":
                rows = [row for row in rows if row.relative_path != "scratch/_v2_checkpoint.json"]
            if hazard == "missing-log":
                rows = [row for row in rows if row.relative_path != "scratch/_plamen.log"]
            entries = tuple(rows)
        required = set(request.required_artifacts)
        if exited.exit_code != 0:
            required.update(request.failure_required_artifacts)
        entries_by_path = {row.relative_path: row for row in entries}
        dispositions = tuple(
            S.ArtifactDisposition(
                path,
                "PRESENT" if path in entries_by_path else "MISSING",
                entries_by_path[path].sha256 if path in entries_by_path else None,
            )
            for path in sorted(required)
        )
        digest = S.canonical_sha256(
            {
                "attempt_id": request.attempt_id,
                "run_id": request.run_id,
                "terminal_sha256": terminal.terminal_sha256,
                "driver_exit_code": exited.exit_code,
                "census_handle": _h(60),
                "entries": entries,
                "dispositions": dispositions,
            }
        )
        census = S.ArtifactCensus(
            request.attempt_id, request.run_id, terminal.terminal_sha256,
            exited.exit_code, _h(60), entries, dispositions, digest,
        )
        return self.world.record(S.MutationOperation.CENSUS_ARTIFACTS, ticket, census)  # type: ignore[return-value]


class _Exporter:
    def __init__(self, world: _World) -> None:
        self.world = world

    def export(
        self, request: S.AuditRequest, layout: S.AttemptLayout,
        census: S.ArtifactCensus, ticket: S.MutationTicket,
    ) -> S.ExportReceipt:
        self.world.exported.append(census.entries)
        if census.driver_exit_code == 0:
            if self.world.publication_hazard != "missing":
                self.world.target_files[S.PUBLISHED_REPORT_PATH] = (
                    b"wrong\n"
                    if self.world.publication_hazard == "wrong-bytes"
                    else b"report\n"
                )
                self.world.events.append("publication:report")
        elif self.world.publication_hazard == "publish-on-failure":
            self.world.target_files[S.PUBLISHED_REPORT_PATH] = b"report\n"
            self.world.events.append("publication:report")
        receipt = S.ExportReceipt(
            request.attempt_id, request.run_id, census.census_sha256,
            layout.export_destination_handle,
            layout.export_destination_identity_sha256,
            len(census.entries), sum(row.size for row in census.entries),
            S._expected_export_manifest(request, census),
            S._expected_export_sha256(request, layout, census),
        )
        return self.world.record(S.MutationOperation.EXPORT_ARTIFACTS, ticket, receipt)  # type: ignore[return-value]


class _Journal:
    def __init__(self, world: _World) -> None:
        self.world = world
        self.owner_request_id: str | None = None
        self.owner_attempt: str | None = None
        self.checkpoint: S.SupervisorCheckpoint | None = None
        self.pending: S.MutationTicket | None = None
        self.complete = False
        self.sequence = 0
        self.arm_crash: set[S.MutationOperation] = set()
        self.commit_crash: set[S.MutationOperation] = set()
        self.armed: list[S.MutationOperation] = []

    def open(self, request: S.AuditRequest) -> S.JournalOpenReceipt:
        if self.owner_request_id is None:
            self.owner_request_id = request.request_id
            self.owner_attempt = request.attempt_id
            self.checkpoint = S.SupervisorCheckpoint(
                request.fingerprint_sha256, request.attempt_id, request.run_id
            )
        if (
            request.request_id != self.owner_request_id
            or request.attempt_id != self.owner_attempt
            or self.checkpoint is None
            or request.fingerprint_sha256
            != self.checkpoint.request_fingerprint_sha256
        ):
            rejected = S.SupervisorCheckpoint(
                request.fingerprint_sha256, request.attempt_id, request.run_id
            )
            return S.JournalOpenReceipt(S.JournalOpenStatus.REJECTED, rejected)
        status = (
            S.JournalOpenStatus.COMPLETE
            if self.complete else S.JournalOpenStatus.READY
        )
        return S.JournalOpenReceipt(status, self.checkpoint, self.pending)

    def arm(
        self, request: S.AuditRequest, operation: S.MutationOperation,
        before_checkpoint_sha256: str,
    ) -> S.MutationTicket:
        assert self.pending is None
        assert self.checkpoint is not None
        assert before_checkpoint_sha256 == self.checkpoint.checkpoint_sha256
        self.sequence += 1
        ticket = S.MutationTicket(
            operation, request.fingerprint_sha256, request.attempt_id,
            before_checkpoint_sha256, self.sequence,
            hashlib.sha256(f"{request.attempt_id}:{self.sequence}".encode()).hexdigest(),
        )
        self.pending = ticket
        self.armed.append(operation)
        self.world.events.append(f"arm:{operation.value}")
        if operation in self.arm_crash:
            self.arm_crash.remove(operation)
            raise _Crash(f"arm:{operation.value}")
        return ticket

    def commit(
        self, _request: S.AuditRequest, ticket: S.MutationTicket,
        checkpoint: S.SupervisorCheckpoint,
    ) -> bool:
        assert self.pending == ticket
        if ticket.operation in self.commit_crash:
            self.commit_crash.remove(ticket.operation)
            raise _Crash(f"commit:{ticket.operation.value}")
        self.checkpoint = checkpoint
        self.pending = None
        self.world.events.append(f"commit:{ticket.operation.value}")
        return True

    def resolve(
        self, _request: S.AuditRequest, ticket: S.MutationTicket,
        checkpoint: S.SupervisorCheckpoint,
    ) -> bool:
        assert self.pending == ticket
        self.checkpoint = checkpoint
        self.pending = None
        self.world.events.append(f"resolve:{ticket.operation.value}")
        return True

    def finish(self, _request: S.AuditRequest, checkpoint_sha256: str) -> bool:
        assert self.checkpoint is not None
        assert checkpoint_sha256 == self.checkpoint.checkpoint_sha256
        self.complete = True
        self.world.events.append("finish")
        return True


class _Recovery:
    def __init__(self, world: _World) -> None:
        self.world = world

    def recover(
        self, _request: S.AuditRequest, ticket: S.MutationTicket,
        before: S.SupervisorCheckpoint,
    ) -> S.RecoveryResolution:
        self.world.events.append(f"recover:{ticket.operation.value}")
        if ticket.operation in self.world.unproven:
            return S.RecoveryResolution(
                S.RecoveryStatus.UNPROVEN, ticket, None, _d("f")
            )
        receipt = self.world.effects.get(ticket.operation)
        if receipt is None:
            return S.RecoveryResolution(
                S.RecoveryStatus.NOT_APPLIED, ticket, before, _d("e")
            )
        return S.RecoveryResolution(
            S.RecoveryStatus.APPLIED, ticket,
            S.advance_checkpoint(before, ticket.operation, receipt), _d("d"),
        )


def _authorities(
    world: _World, *, architecture: str = "arm64",
) -> S.SupervisorAuthorities:
    return S.SupervisorAuthorities(
        runtime=_Runtime(architecture), workspace=_Workspace(world), backend=_Backend(),
        provider=_Provider(world), guest_admission=_Admission(world),
        extinction=_Extinction(world), artifacts=_Artifacts(world),
        exporter=_Exporter(world), journal=world.journal,
        recovery=_Recovery(world),
    )


@pytest.mark.parametrize(
    ("request_type", "pipeline", "intent"),
    [
        (S.RequestType.SC_NEW, "sc", S.START_NEW_RUN),
        (S.RequestType.L1_NEW, "l1", S.START_NEW_RUN),
        (S.RequestType.START_CONFIG, "sc", S.START_NEW_RUN),
        (S.RequestType.RESUME, "sc", S.RESUME_EXISTING),
    ],
)
def test_exact_normalized_routes_launch_one_existing_driver(
    request_type: S.RequestType, pipeline: str, intent: str,
) -> None:
    request = _request(request_type)
    world = _World()
    result = S._supervise_audit_for_testing(request, _authorities(world))

    assert result.guest_absent is True
    assert result.target_unchanged is True
    assert world.driver_starts == 1
    assert len(world.launches) == 1
    assert world.configs == [S._expected_guest_config(request)]
    assert world.configs[0].document["pipeline"] == pipeline
    assert world.configs[0].document["cli_backend"] == "codex"
    assert world.configs[0].document["language"] == request.language
    assert "backend" not in world.configs[0].document
    assert world.launches[0].argv == (
        "/usr/bin/python3", "-B",
        "/opt/plamen/scripts/plamen_driver.py", "/workspace/control/config.json",
        "--startup-intent", intent, "--unattended", "--no-sleep",
        "--startup-decision-receipt",
        "/workspace/control/startup-decision.json",
    )
    assert world.launches[0].environment == ()
    assert not any("phase" in value.casefold() for value in world.launches[0].argv)


@pytest.mark.parametrize(
    ("request_type", "backend"),
    [
        (S.RequestType.START_CONFIG, "codex"),
        (S.RequestType.START_CONFIG, "claude"),
        (S.RequestType.RESUME, "codex"),
        (S.RequestType.RESUME, "claude"),
    ],
)
def test_start_config_and_resume_add_only_authenticated_report_staging_path(
    request_type: S.RequestType, backend: str,
) -> None:
    options = {
        "excluded_paths": ["vendor", "fixtures/large"],
        "model": "frontend-authenticated-model",
        "transport": {"kind": "trusted-proxy", "profile": "audit-v2"},
    }
    request = _request(
        request_type, backend=backend, language="evm",
        config_options=options,
    )
    world = _World()

    S._supervise_audit_for_testing(request, _authorities(world))

    assert len(world.configs) == 1
    expected_document = request.source_config.document
    expected_document[S.REPORT_OUTPUT_CONFIG_KEY] = S.GUEST_REPORT_PATH
    assert world.configs[0].document == expected_document
    assert world.configs[0].config_sha256 != request.source_config.sha256
    assert S.REPORT_OUTPUT_CONFIG_KEY not in request.source_config.document
    assert world.configs[0].document["cli_backend"] == backend
    assert world.configs[0].document["language"] == "evm"
    assert world.configs[0].document["excluded_paths"] == options["excluded_paths"]
    assert world.configs[0].document["model"] == options["model"]
    assert world.configs[0].document["transport"] == options["transport"]


def test_public_entry_rejects_same_process_callable_fakes_before_any_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _World()
    authorities = _authorities(world)

    class _PythonModule:
        __spec__ = None
        NativeAuthorityConsumer = type(authorities)

    monkeypatch.setattr(S.importlib, "import_module", lambda _name: _PythonModule)
    with pytest.raises(
        S.SupervisorError,
        match="native supervisor authority admission is unavailable",
    ) as caught:
        S.supervise_audit(_request(), authorities)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert world.events == []
    assert world.driver_starts == 0


def test_request_rejects_backend_or_language_that_differs_from_config() -> None:
    request = _request(backend="codex", language="evm")
    with pytest.raises(S.SupervisorError, match="config route/run"):
        replace(request, backend="claude")
    with pytest.raises(S.SupervisorError, match="config route/run"):
        replace(request, language="solana")


def test_driver_config_rejects_backend_alias_and_noncanonical_bytes() -> None:
    document = _request().source_config.document
    document["backend"] = document.pop("cli_backend")
    aliased = S._canonical_bytes(document)
    with pytest.raises(S.SupervisorError, match="required keys.*aliased"):
        S.AuthenticatedDriverConfig(
            _h(91), aliased, hashlib.sha256(aliased).hexdigest()
        )

    canonical = _request().source_config.canonical_bytes
    noncanonical = canonical.replace(b'"_run_id"', b'  "_run_id"', 1)
    with pytest.raises(S.SupervisorError, match="not canonical"):
        S.AuthenticatedDriverConfig(
            _h(92), noncanonical, hashlib.sha256(noncanonical).hexdigest()
        )

    injected = _request().source_config.document
    injected[S.REPORT_OUTPUT_CONFIG_KEY] = "/workspace/project/AUDIT_REPORT.md"
    injected_raw = S._canonical_bytes(injected)
    with pytest.raises(S.SupervisorError, match="may not select"):
        S.AuthenticatedDriverConfig(
            _h(94), injected_raw, hashlib.sha256(injected_raw).hexdigest()
        )


@pytest.mark.parametrize(
    "docs_inputs",
    [
        ["/workspace/docs/../../run/plamen/credentials/token"],
        ["/workspace/docs/../project/.git/config"],
        ["/workspace/docs//design.md"],
        ["/workspace/docs\\design.md"],
        [],
        [""],
        ["/workspace/docs/design.md", "/workspace/docs/design.md"],
        ["/workspace/docs/Design.md", "/workspace/docs/design.md"],
        ["/workspace/docs/caf\u00e9.md", "/workspace/docs/cafe\u0301.md"],
    ],
)
def test_driver_config_rejects_noncanonical_or_escaping_docs_inputs(
    docs_inputs: list[str],
) -> None:
    document = _request().source_config.document
    document["docs_inputs"] = docs_inputs
    raw = S._canonical_bytes(document)

    with pytest.raises(S.SupervisorError):
        S.AuthenticatedDriverConfig(
            _h(93), raw, hashlib.sha256(raw).hexdigest()
        )


def test_every_governed_effect_is_armed_and_committed_once() -> None:
    world = _World()
    S._supervise_audit_for_testing(_request(), _authorities(world))
    assert world.journal.armed == list(S.MutationOperation)
    assert world.effect_counts == {operation: 1 for operation in S.MutationOperation}
    for operation in S.MutationOperation:
        arm = world.events.index(f"arm:{operation.value}")
        effect = world.events.index(f"effect:{operation.value}")
        commit = world.events.index(f"commit:{operation.value}")
        assert arm < effect < commit


def test_host_target_source_stays_readonly_and_only_report_is_published() -> None:
    world = _World()
    before = dict(world.target_files)
    S._supervise_audit_for_testing(_request(), _authorities(world))
    assert {
        name: value for name, value in world.target_files.items()
        if name != S.PUBLISHED_REPORT_PATH
    } == before
    assert world.target_files[S.PUBLISHED_REPORT_PATH] == b"report\n"
    assert ".scratchpad" not in world.target_files
    layout = world.effects[S.MutationOperation.PREPARE_LAYOUT]
    assert type(layout) is S.AttemptLayout
    assert layout.target_lower_readonly is True
    assert layout.run_store_outside_target is True
    assert layout.private_attempt_owned is True
    assert layout.merged_handle != layout.target_lower_handle


def test_target_mutation_or_scratchpad_stops_before_next_effect() -> None:
    world = _World()
    authorities = _authorities(world)
    original = authorities.workspace.revalidate_target
    calls = 0

    def mutate_then_revalidate(request: S.AuditRequest, target: S.TargetLease):
        nonlocal calls
        calls += 1
        if calls == 2:
            world.target_files[".scratchpad"] = b"forbidden"
        return original(request, target)

    authorities.workspace.revalidate_target = mutate_then_revalidate  # type: ignore[method-assign]
    with pytest.raises(S.SupervisorError, match="host target recensus failed"):
        S._supervise_audit_for_testing(_request(), authorities)
    assert world.effect_counts[S.MutationOperation.PREPARE_LAYOUT] == 0


def test_exact_mount_roster_keeps_docs_scope_and_secrets_separate() -> None:
    world = _World()
    S._supervise_audit_for_testing(_request(), _authorities(world))
    spec = world.specs[0]
    assert tuple((row.purpose, row.destination, row.mode) for row in spec.mounts) == (
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
    assert spec.rootfs_readonly is True
    assert spec.create_stopped is True
    assert spec.initial_process_count == 0
    assert spec.network_mode == "NARROW_TRUSTED_PROXY_ONLY"
    assert spec.inherited_environment == ()
    assert spec.uid > 0 and spec.gid > 0


def test_post_create_stable_layout_drift_never_reaches_admission_or_start() -> None:
    world = _World()
    world.layout_hazard = "content-drift"

    with pytest.raises(S.SupervisorError, match="layout.*drift"):
        S._supervise_audit_for_testing(_request(), _authorities(world))

    assert world.guest_state == "stopped"
    assert world.effect_counts[S.MutationOperation.ADMIT_GUEST] == 0
    assert world.driver_starts == 0


@pytest.mark.parametrize(
    "operation",
    [
        S.MutationOperation.CREATE_GUEST,
        S.MutationOperation.ADMIT_GUEST,
        S.MutationOperation.START_DRIVER,
        S.MutationOperation.WAIT_DRIVER,
        S.MutationOperation.EXPORT_ARTIFACTS,
        S.MutationOperation.DELETE_GUEST,
    ],
)
def test_crash_after_effect_recovers_without_repeating_mutation(
    operation: S.MutationOperation,
) -> None:
    world = _World()
    request = _request()
    world.crash_after.add(operation)
    with pytest.raises(_Crash):
        S._supervise_audit_for_testing(request, _authorities(world))
    assert world.journal.pending is not None
    result = S._supervise_audit_for_testing(request, _authorities(world))
    assert result.guest_absent is True
    assert world.effect_counts[operation] == 1
    assert world.driver_starts == 1
    assert f"recover:{operation.value}" in world.events
    if operation is S.MutationOperation.DELETE_GUEST:
        assert "resume:guest" not in world.events


def test_recovered_admission_revalidates_live_component_facts_before_start() -> None:
    world = _World()
    request = _request()
    world.crash_after.add(S.MutationOperation.ADMIT_GUEST)
    with pytest.raises(_Crash):
        S._supervise_audit_for_testing(request, _authorities(world))
    assert world.journal.pending is not None
    assert world.driver_starts == 0

    world.layout_hazard = "content-drift"
    with pytest.raises(
        S.SupervisorError,
        match="recovered stopped layout differs from durable admission",
    ):
        S._supervise_audit_for_testing(request, _authorities(world))
    assert world.guest_state == "stopped"
    assert world.driver_starts == 0


def test_recovered_admission_rejects_tampered_postcreate_component() -> None:
    world = _World()
    request = _request()
    world.crash_after.add(S.MutationOperation.ADMIT_GUEST)
    with pytest.raises(_Crash):
        S._supervise_audit_for_testing(request, _authorities(world))
    admission = world.effects[S.MutationOperation.ADMIT_GUEST]
    assert type(admission) is S.GuestAdmissionReceipt
    forged_post = _replace_component_content(
        admission.postcreate_recensus, 1, _sha("recovered-replacement")
    )
    world.effects[S.MutationOperation.ADMIT_GUEST] = replace(
        admission, postcreate_recensus=forged_post
    )

    with pytest.raises(S.SupervisorError, match="checkpoint evidence"):
        S._supervise_audit_for_testing(request, _authorities(world))
    assert world.guest_state == "stopped"
    assert world.driver_starts == 0


def test_crash_after_arm_recovers_not_applied_then_runs_once() -> None:
    world = _World()
    request = _request()
    world.journal.arm_crash.add(S.MutationOperation.CREATE_GUEST)
    with pytest.raises(_Crash):
        S._supervise_audit_for_testing(request, _authorities(world))
    assert world.effect_counts[S.MutationOperation.CREATE_GUEST] == 0
    result = S._supervise_audit_for_testing(request, _authorities(world))
    assert result.guest_absent is True
    assert world.effect_counts[S.MutationOperation.CREATE_GUEST] == 1
    assert world.driver_starts == 1


def test_crash_during_journal_commit_recovers_applied_start_once() -> None:
    world = _World()
    request = _request()
    world.journal.commit_crash.add(S.MutationOperation.START_DRIVER)
    with pytest.raises(_Crash):
        S._supervise_audit_for_testing(request, _authorities(world))
    assert world.driver_starts == 1
    S._supervise_audit_for_testing(request, _authorities(world))
    assert world.driver_starts == 1
    assert "resume:admission" not in world.events


def test_cleanup_recovery_ambiguity_never_authorizes_duplicate_driver() -> None:
    world = _World()
    request = _request()
    world.crash_after.add(S.MutationOperation.START_DRIVER)
    world.unproven.add(S.MutationOperation.START_DRIVER)
    with pytest.raises(_Crash):
        S._supervise_audit_for_testing(request, _authorities(world))
    with pytest.raises(S.SupervisorAmbiguousError, match="unproven"):
        S._supervise_audit_for_testing(request, _authorities(world))
    assert world.driver_starts == 1
    assert world.effect_counts[S.MutationOperation.START_DRIVER] == 1
    assert world.effect_counts[S.MutationOperation.WAIT_DRIVER] == 0
    assert "resume:admission" not in world.events


def test_delete_ambiguity_stays_pending_without_repeating_any_effect() -> None:
    world = _World()
    request = _request()
    world.crash_after.add(S.MutationOperation.DELETE_GUEST)
    world.unproven.add(S.MutationOperation.DELETE_GUEST)
    with pytest.raises(_Crash):
        S._supervise_audit_for_testing(request, _authorities(world))
    assert world.guest_state == "absent"
    with pytest.raises(S.SupervisorAmbiguousError, match="unproven"):
        S._supervise_audit_for_testing(request, _authorities(world))
    assert world.driver_starts == 1
    assert world.effect_counts[S.MutationOperation.DELETE_GUEST] == 1


def test_recovered_start_receipt_is_semantically_revalidated_before_wait() -> None:
    world = _World()
    request = _request()
    world.crash_after.add(S.MutationOperation.START_DRIVER)
    with pytest.raises(_Crash):
        S._supervise_audit_for_testing(request, _authorities(world))
    started = world.effects[S.MutationOperation.START_DRIVER]
    assert type(started) is S.DriverStartReceipt
    world.effects[S.MutationOperation.START_DRIVER] = replace(
        started, launch_sha256=_d("b")
    )
    with pytest.raises(S.SupervisorError, match="checkpoint evidence"):
        S._supervise_audit_for_testing(request, _authorities(world))
    assert world.driver_starts == 1
    assert world.effect_counts[S.MutationOperation.WAIT_DRIVER] == 0


def test_completed_checkpoint_corruption_is_rejected_before_result_reuse() -> None:
    world = _World()
    request = _request()
    S._supervise_audit_for_testing(request, _authorities(world))
    checkpoint = world.journal.checkpoint
    assert checkpoint is not None
    receipts = list(checkpoint.receipts)
    started = receipts[4]
    assert type(started) is S.DriverStartReceipt
    receipts[4] = replace(started, launch_sha256=_d("c"))
    world.journal.checkpoint = replace(checkpoint, receipts=tuple(receipts))
    with pytest.raises(S.SupervisorError, match="checkpoint evidence"):
        S._supervise_audit_for_testing(request, _authorities(world))
    assert world.driver_starts == 1


def test_cross_attempt_replay_is_rejected_without_second_provider_mutation() -> None:
    world = _World()
    first = _request()
    S._supervise_audit_for_testing(first, _authorities(world))
    second = replace(first, attempt_id="attempt-002")
    with pytest.raises(S.SupervisorError, match="replay|cross-attempt"):
        S._supervise_audit_for_testing(second, _authorities(world))
    assert world.driver_starts == 1


def test_resume_preserves_external_run_identity_and_uses_resume_intent() -> None:
    world = _World()
    request = _request(
        S.RequestType.RESUME, attempt="resume-attempt-1", run_id="original-run-9"
    )
    result = S._supervise_audit_for_testing(request, _authorities(world))
    layout = world.effects[S.MutationOperation.PREPARE_LAYOUT]
    config = world.effects[S.MutationOperation.WRITE_CONFIG]
    assert result.run_id == "original-run-9"
    assert type(layout) is S.AttemptLayout and layout.run_id == result.run_id
    assert type(config) is S.ConfigReceipt and config.run_id == result.run_id
    assert S.RESUME_EXISTING in world.launches[0].argv


@pytest.mark.parametrize(
    "hazard",
    ["traversal", "symlink", "special", "oversized", "hardlink", "case-alias"],
)
def test_export_rejects_traversal_symlink_special_and_oversized_artifacts(
    hazard: str,
) -> None:
    world = _World()
    world.artifact_hazard = hazard
    with pytest.raises(S.SupervisorError):
        S._supervise_audit_for_testing(_request(), _authorities(world))
    assert world.effect_counts[S.MutationOperation.EXPORT_ARTIFACTS] == 0
    assert world.exported == []
    assert world.guest_state == "extinct"


@pytest.mark.parametrize("hazard", ["missing-report", "missing-checkpoint"])
def test_missing_required_artifact_retains_extinct_guest_and_pending_recovery(
    hazard: str,
) -> None:
    world = _World()
    world.artifact_hazard = hazard

    with pytest.raises(S.SupervisorError, match="required audit artifact is missing"):
        S._supervise_audit_for_testing(_request(), _authorities(world))

    assert world.guest_state == "extinct"
    assert world.journal.pending is not None
    assert world.journal.pending.operation is S.MutationOperation.CENSUS_ARTIFACTS
    assert world.effect_counts[S.MutationOperation.EXPORT_ARTIFACTS] == 0
    assert world.effect_counts[S.MutationOperation.DELETE_GUEST] == 0


def test_exit23_missing_failure_diagnostic_retains_guest_without_export() -> None:
    world = _World()
    world.driver_exit_code = 23
    world.artifact_hazard = "missing-log"

    with pytest.raises(S.SupervisorError, match="required audit artifact is missing"):
        S._supervise_audit_for_testing(_request(), _authorities(world))

    assert world.guest_state == "extinct"
    assert world.journal.pending is not None
    assert world.effect_counts[S.MutationOperation.EXPORT_ARTIFACTS] == 0
    assert world.effect_counts[S.MutationOperation.DELETE_GUEST] == 0


def test_export_happens_only_after_exact_terminal_extinction_and_census() -> None:
    world = _World()
    S._supervise_audit_for_testing(_request(), _authorities(world))
    extinction = world.events.index("effect:EXTINGUISH")
    census = world.events.index("effect:CENSUS_ARTIFACTS")
    export = world.events.index("effect:EXPORT_ARTIFACTS")
    publication = world.events.index("publication:report")
    deletion = world.events.index("effect:DELETE_GUEST")
    assert extinction < census < publication < export < deletion
    terminal = world.effects[S.MutationOperation.EXTINGUISH]
    assert type(terminal) is S.ExtinctionReceipt
    assert terminal.process_count == 0 and terminal.cgroup_populated == 0

    request = _request()
    layout = world.effects[S.MutationOperation.PREPARE_LAYOUT]
    exported = world.effects[S.MutationOperation.EXPORT_ARTIFACTS]
    assert type(layout) is S.AttemptLayout
    assert type(exported) is S.ExportReceipt
    with pytest.raises(S.SupervisorError, match="exact artifact census"):
        S._validate_export_receipt(
            request,
            layout,
            world.effects[S.MutationOperation.CENSUS_ARTIFACTS],
            replace(exported, export_sha256=_d("f")),
        )


def test_native_guest_config_routes_report_to_exact_scratch_slot() -> None:
    from report_output_routing import resolve_report_output_path

    request = _request()
    guest_config = S._expected_guest_config(request)
    assert guest_config.document[S.REPORT_OUTPUT_CONFIG_KEY] == (
        S.GUEST_REPORT_PATH
    )
    assert resolve_report_output_path(guest_config.document) == Path(
        S.GUEST_REPORT_PATH
    )
    assert resolve_report_output_path(request.source_config.document) == Path(
        "/workspace/project/AUDIT_REPORT.md"
    )


@pytest.mark.parametrize(
    "bad",
    [
        "/workspace/project/AUDIT_REPORT.md",
        "/workspace/scratch/other.md",
        "workspace/scratch/AUDIT_REPORT.md",
    ],
)
def test_driver_rejects_noncanonical_internal_report_output_path(bad: str) -> None:
    from report_output_routing import resolve_report_output_path

    config = S._expected_guest_config(_request()).document
    config[S.REPORT_OUTPUT_CONFIG_KEY] = bad
    with pytest.raises(ValueError, match="exact scratchpad report slot"):
        resolve_report_output_path(config)


def test_nonzero_driver_exit_is_extinguished_but_never_exported_or_published() -> None:
    world = _World()
    world.driver_exit_code = 23
    with pytest.raises(S.SupervisorError, match="publication is withheld"):
        S._supervise_audit_for_testing(_request(), _authorities(world))
    assert world.guest_state == "extinct"
    assert world.exported == []
    assert world.effect_counts[S.MutationOperation.EXPORT_ARTIFACTS] == 0
    assert world.effect_counts[S.MutationOperation.DELETE_GUEST] == 0
    assert S.PUBLISHED_REPORT_PATH not in world.target_files


@pytest.mark.parametrize(
    "exit_code,hazard",
    [(0, "missing"), (0, "wrong-bytes")],
)
def test_publication_postcondition_rejects_missing_wrong_or_failed_run_write(
    exit_code: int, hazard: str,
) -> None:
    world = _World()
    world.driver_exit_code = exit_code
    world.publication_hazard = hazard

    with pytest.raises(S.SupervisorError, match="host target recensus failed"):
        S._supervise_audit_for_testing(_request(), _authorities(world))

    assert world.guest_state == "extinct"
    assert world.effect_counts[S.MutationOperation.EXPORT_ARTIFACTS] == 1
    assert world.effect_counts[S.MutationOperation.DELETE_GUEST] == 0


def test_apple_and_podman_share_lifecycle_but_bind_distinct_mount_authority() -> None:
    observations: list[tuple[S.GuestCreateSpec, S.DriverLaunch, tuple[str, ...]]] = []
    for kind in (S.ProviderKind.APPLE_CONTAINER, S.ProviderKind.PODMAN):
        world = _World(kind)
        result = S._supervise_audit_for_testing(_request(), _authorities(world))
        observations.append(
            (world.specs[0], world.launches[0], tuple(world.events))
        )
        assert result.provider_kind is kind
    apple_spec, apple_launch, apple_events = observations[0]
    podman_spec, podman_launch, podman_events = observations[1]
    assert (
        apple_launch.argv,
        apple_launch.environment,
        apple_launch.cwd,
        apple_launch.stdin,
    ) == (
        podman_launch.argv,
        podman_launch.environment,
        podman_launch.cwd,
        podman_launch.stdin,
    )
    assert apple_launch.admission_sha256 != podman_launch.admission_sha256
    assert apple_events == podman_events
    assert apple_spec.provider_kind is S.ProviderKind.APPLE_CONTAINER
    assert podman_spec.provider_kind is S.ProviderKind.PODMAN
    assert apple_spec.mounts[0].mode == "ro"
    assert podman_spec.mounts[0].mode == "ro"
    assert apple_spec.mounts == podman_spec.mounts


def test_podman_accepts_authenticated_amd64_but_apple_fails_closed() -> None:
    podman = _World(S.ProviderKind.PODMAN)
    result = S._supervise_audit_for_testing(
        _request(), _authorities(podman, architecture="amd64")
    )
    assert result.provider_kind is S.ProviderKind.PODMAN
    assert podman.specs[0].platform_architecture == "amd64"

    apple = _World(S.ProviderKind.APPLE_CONTAINER)
    with pytest.raises(S.SupervisorError, match="linux/arm64"):
        S._supervise_audit_for_testing(
            _request(), _authorities(apple, architecture="amd64")
        )
    assert apple.events == []


def test_absent_native_authority_fails_closed_before_journal_or_provider() -> None:
    world = _World()
    values = _authorities(world)
    with pytest.raises(S.SupervisorError, match="authority is absent"):
        replace(values, extinction=None)  # type: ignore[arg-type]
    assert world.events == []


@pytest.mark.parametrize(
    "bad",
    [
        {"request_type": S.RequestType.SC_NEW, "pipeline": "l1"},
        {"request_type": S.RequestType.L1_NEW, "pipeline": "sc"},
        {"export_allowlist": ("../credentials",)},
        {"export_allowlist": ("control/config.json",)},
        {"export_allowlist": ("project/A", "project/a")},
        {"export_allowlist": ("project/A", "project/A/file")},
        {"image_manifest_digest": _d("5")},
    ],
)
def test_request_constructor_rejects_non_normalized_authority(
    bad: dict[str, Any],
) -> None:
    with pytest.raises(S.SupervisorError):
        replace(_request(), **bad)


def test_injected_exception_is_bounded_and_has_no_secret_context() -> None:
    world = _World()
    authorities = _authorities(world)
    secret = "/Users/alice/.ssh/id_ed25519 --proxy-token secret"

    def broken(_request: S.AuditRequest) -> S.AuthenticatedRuntimeImageLayout:
        raise RuntimeError(secret)

    authorities.runtime.authenticate = broken  # type: ignore[method-assign]
    with pytest.raises(S.SupervisorError, match="runtime/image authentication") as caught:
        S._supervise_audit_for_testing(_request(), authorities)
    assert secret not in str(caught.value)
    assert len(str(caught.value)) < 160
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert world.events == []
