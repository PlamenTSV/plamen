"""Inert translation tests; no Apple CLI, native runner, or provider call."""
from __future__ import annotations

from dataclasses import fields, replace
import hashlib
from pathlib import Path

import pytest

import apple_container_provider as A
import apple_supervisor_adapter as M
import posix_audit_supervisor as S


_ROSTER = (
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


def test_atomic_fuzz_service_boundary_is_red_until_native_producers_exist(
) -> None:
    status = M.apple_fuzz_service_admission_status()
    assert status["schema"] == M.APPLE_FUZZ_SERVICE_ABI_SCHEMA
    assert status["status"] == "UNAVAILABLE"
    assert {row["code"] for row in status["issues"]} == {
        "APPLE_FUZZ_SERVICE_SESSION_PRODUCER_ABSENT",
        "APPLE_FUZZ_SECURE_RECEIPT_MINTER_ABSENT",
        "APPLE_FUZZ_CONTINUATION_LEASE_PRODUCER_ABSENT",
        "APPLE_FUZZ_LIFECYCLE_TERMINAL_PRODUCER_ABSENT",
    }


def test_native_fuzz_admission_abi_breaks_the_digest_cycle() -> None:
    header = (
        Path(__file__).resolve().parents[1]
        / "native" / "darwin" / "plamen_broker_v2_fuzz_campaign.h"
    ).read_text(encoding="utf-8")
    admission = header.split(
        "struct plamen_broker_v2_fuzz_service_admission_request", 1
    )[1].split("};", 1)[0]
    assert "prepared_campaign_sha256" not in admission
    assert "secure_receipt_sha256" not in admission
    assert "admit_and_issue" in header
    assert "execute_and_consume" in header
    assert "struct plamen_broker_v2_fuzz_service_continuation;" in header


def test_mapping_alone_is_never_atomic_fuzz_admission_authority() -> None:
    with pytest.raises(
        M.AppleSupervisorAdapterUnavailable,
        match="atomic native Apple fuzz admission service is unavailable",
    ):
        M.require_apple_fuzz_service_admission(None, {})


def _d(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _h(label: str) -> str:
    return "opaque:" + _d("handle:" + label)


def _forge(value: object, **changes: object) -> object:
    forged = object.__new__(type(value))
    for item in fields(value):
        object.__setattr__(
            forged, item.name,
            changes.get(item.name, getattr(value, item.name)),
        )
    return forged


def _pin() -> A.AppleContainerVersionPin:
    return A.AppleContainerVersionPin(
        cli_version=A.SUPPORTED_APPLE_CONTAINER_VERSION,
        cli_build="release",
        cli_commit=A.SUPPORTED_APPLE_CONTAINER_COMMIT,
        cli_executable_sha256=A.SUPPORTED_CLI_EXECUTABLE_SHA256,
        cli_signing_identifier=A.SUPPORTED_CLI_SIGNING_IDENTIFIER,
        cli_signing_team_id=A.SUPPORTED_RUNTIME_SIGNING_TEAM_ID,
        server_executable_path=str(A.DEFAULT_SERVER_EXECUTABLE),
        server_version=A.SUPPORTED_APPLE_CONTAINER_VERSION,
        server_build="release",
        server_commit=A.SUPPORTED_APPLE_CONTAINER_COMMIT,
        server_banner_commit=A.SUPPORTED_APPLE_CONTAINER_COMMIT[:7],
        server_executable_sha256=A.SUPPORTED_SERVER_EXECUTABLE_SHA256,
        server_signing_identifier=A.SUPPORTED_SERVER_SIGNING_IDENTIFIER,
        server_signing_team_id=A.SUPPORTED_RUNTIME_SIGNING_TEAM_ID,
        containerization_version=A.SUPPORTED_CONTAINERIZATION_VERSION,
        containerization_build="release",
        containerization_commit=A.SUPPORTED_CONTAINERIZATION_COMMIT,
        containerization_binary_sha256=_d("containerization"),
        init_image_reference=A.SUPPORTED_INIT_IMAGE_REFERENCE,
        init_image_index_digest=A.SUPPORTED_INIT_IMAGE_INDEX_DIGEST,
        init_image_manifest_digest=A.SUPPORTED_INIT_IMAGE_MANIFEST_DIGEST,
        plugin_root=str(A.DEFAULT_PLUGIN_ROOT),
        core_images_plugin_sha256=A.SUPPORTED_CORE_IMAGES_PLUGIN_SHA256,
        network_vmnet_plugin_sha256=A.SUPPORTED_NETWORK_VMNET_PLUGIN_SHA256,
        runtime_linux_plugin_sha256=A.SUPPORTED_RUNTIME_LINUX_PLUGIN_SHA256,
        machine_apiserver_plugin_sha256=A.SUPPORTED_MACHINE_APISERVER_PLUGIN_SHA256,
        plugin_signing_team_id=A.SUPPORTED_RUNTIME_SIGNING_TEAM_ID,
        plugin_closure_sha256=A.SUPPORTED_PLUGIN_CLOSURE_SHA256,
        package_identifier=A.SUPPORTED_PACKAGE_IDENTIFIER,
        package_version=A.SUPPORTED_APPLE_CONTAINER_VERSION,
        package_install_location=A.SUPPORTED_PACKAGE_INSTALL_LOCATION,
        package_authorization=A.SUPPORTED_PACKAGE_AUTHORIZATION,
        package_signing_team_id=A.SUPPORTED_INSTALLER_TEAM_ID,
        package_installer_leaf_sha256=A.SUPPORTED_INSTALLER_LEAF_SHA256,
        package_receipt_sha256=_d("package-receipt"),
        package_signed=True,
        package_notarized=True,
        package_timestamped=True,
        kernel_archive_url=A.SUPPORTED_KERNEL_ARCHIVE_URL,
        kernel_archive_sha256=A.SUPPORTED_KERNEL_ARCHIVE_SHA256,
        kernel_archive_size=A.SUPPORTED_KERNEL_ARCHIVE_SIZE,
        kernel_binary_member=A.SUPPORTED_KERNEL_BINARY_MEMBER,
        kernel_binary_sha256=A.SUPPORTED_KERNEL_BINARY_SHA256,
        implicit_kernel_install_disabled=True,
        host_operating_system="Version 26.6.2 (Build 25G83)",
    )


def _ticket(
    operation: S.MutationOperation, request: S.AuditRequest, sequence: int,
) -> S.MutationTicket:
    return S.MutationTicket(
        operation, request.fingerprint_sha256, request.attempt_id,
        _d(f"checkpoint:{sequence}"), sequence, _d(f"nonce:{sequence}"),
    )


def _network(request: S.AuditRequest, guest_name: str) -> A.NetworkSpec:
    name = "plamen-egress-001"
    nonce = _d("network-authority")[:32]
    labels = tuple(sorted({
        "io.plamen.provider": "apple-container-v3",
        "io.plamen.run": request.run_id,
        "io.plamen.network-sha256": request.egress_policy_sha256,
        "io.plamen.egress-admission-sha256": request.egress_admission_sha256,
        "io.plamen.network-role": "governed-egress",
        "io.plamen.network-authority": nonce,
    }.items()))
    values = {
        "attempt_owned": True,
        "authority_nonce": nonce,
        "internal": True,
        "topology_mode": "hostOnly",
        "effective_egress_mode": "VERIFIED_CONNECT_ALLOWLIST",
        "hostname": guest_name,
        "ipv4_gateway": "192.168.250.1",
        "ipv4_address": "192.168.250.2/28",
        "ipv4_subnet": "192.168.250.0/28",
        "ipv6_absent": True,
        "labels": [list(item) for item in labels],
        "mtu": 1280,
        "mac_address": "02:42:ac:11:00:02",
        "attachment_variant": A.SUPPORTED_NETWORK_ATTACHMENT_VARIANT,
        "name": name,
        "no_dns": True,
        "plugin": "container-network-vmnet",
        "policy_sha256": request.egress_policy_sha256,
        "egress_admission_sha256": request.egress_admission_sha256,
        "run_identity": request.run_id,
    }
    return A.NetworkSpec(
        name, guest_name, request.egress_policy_sha256,
        request.egress_admission_sha256,
        A._canonical_digest(values), request.run_id, nonce,
        "192.168.250.0/28", "192.168.250.1", labels,
        mac_address="02:42:ac:11:00:02",
        ipv4_address="192.168.250.2/28",
    )


def _context(
    *, architecture: str = "arm64", attempt_id: str = "dodo-001",
) -> dict[str, object]:
    config_bytes = S._canonical_bytes({
        "_run_id": "run-dodo-001",
        "cli_backend": "codex",
        "docs_inputs": ["/workspace/docs/design.md"],
        "docs_path": "/workspace/docs",
        "language": "evm",
        "mode": "core",
        "pipeline": "sc",
        "project_root": "/workspace/project",
        "scope_file": "/workspace/scope",
        "scratchpad": "/workspace/scratch",
    })
    config_sha = hashlib.sha256(config_bytes).hexdigest()
    source_config = S.AuthenticatedDriverConfig(
        _h("source-config"), config_bytes, config_sha,
    )
    pin = _pin()
    image = M.TEST_ONLY_ImageClosure(
        _h("image"), _h("runtime"), _d("runtime-layout"), _d("oci-layout"),
        "ghcr.io/plamen/runtime@sha256:" + _d("image-index"),
        "sha256:" + _d("image-index"),
        "sha256:" + _d("image-manifest"), _d("image-configuration"),
    )
    request = S.AuditRequest(
        request_type=S.RequestType.SC_NEW, request_id="request-001",
        attempt_id=attempt_id, run_id="run-dodo-001", pipeline="sc",
        mode="core", backend="codex", language="evm",
        source_config=source_config, source_config_sha256=config_sha,
        startup_decision_receipt_sha256=_d("startup-decision"),
        target_identity_sha256=_d("target-identity"),
        runtime_layout_sha256=_d("runtime-layout"),
        image_manifest_digest="sha256:" + _d("image-manifest"),
        image_closure_sha256=image.closure_sha256,
        docs_sha256=_d("docs"), scope_sha256=_d("scope"),
        seccomp_profile_sha256=_d("seccomp"),
        credential_bundle_sha256=_d("credentials"),
        credential_isolation_sha256=_d("credential-isolation"),
        backend_context_sha256=_d("backend-context"),
        backend_admission_sha256=_d("backend-admission"),
        egress_policy_sha256=_d("egress-policy"),
        egress_admission_sha256=_d("egress-admission"),
        provider_provenance_sha256=A._canonical_digest(list(pin.provenance)),
        export_allowlist=(
            "project/AUDIT_REPORT.md", "scratch/_plamen.log",
            "scratch/_v2_checkpoint.json", "scratch/finding_records.json",
        ),
        required_artifacts=(
            "project/AUDIT_REPORT.md", "scratch/_v2_checkpoint.json",
        ),
        failure_required_artifacts=("scratch/_plamen.log",),
        export_destination_identity_sha256=_d("export-destination"),
    )
    runtime = S.AuthenticatedRuntimeImageLayout(
        request.runtime_layout_sha256, request.image_manifest_digest,
        request.image_closure_sha256, request.docs_sha256,
        _h("runtime"), _h("docs"), _h("image"),
        guest_architecture=architecture,
    )
    backend = S.BackendContext(
        request.backend, request.backend_context_sha256,
        request.backend_admission_sha256, request.egress_policy_sha256,
        request.egress_admission_sha256, request.credential_bundle_sha256,
        request.credential_isolation_sha256,
        _h("backend"), _h("credentials"),
    )
    layout = S.AttemptLayout(
        request.attempt_id, request.run_id, _h("layout"), _h("target"),
        _h("upper"), _h("work"), _h("merged"), _h("scratch"),
        _h("state"), _h("control"), _h("seccomp"), _h("scope"),
        request.target_identity_sha256, request.scope_sha256,
        request.seccomp_profile_sha256, _h("export"),
        request.export_destination_identity_sha256,
    )
    guest_config = S.GuestConfig(_h("source-config"), config_bytes, config_sha)
    configured = S.ConfigReceipt(
        request.attempt_id, request.run_id, _h("rendered-config"),
        config_sha, request.source_config_sha256,
        request.startup_decision_receipt_sha256, guest_config,
    )
    target = S.TargetRecensus(
        layout.target_lower_handle, request.target_identity_sha256,
        _d("target-content"), True, True,
    )
    handles = (
        layout.target_lower_handle, layout.merged_handle,
        layout.scratch_handle, layout.state_handle, layout.control_handle,
        layout.seccomp_handle, backend.credential_handle,
        backend.context_handle, runtime.runtime_handle,
        runtime.docs_handle, layout.scope_handle,
    )
    contents = (
        target.content_sha256, _d("merged-content"), _d("scratch-content"),
        _d("state-content"), S.canonical_sha256({
            "config_sha256": configured.config_sha256,
            "startup_decision_receipt_sha256":
                request.startup_decision_receipt_sha256,
        }),
        layout.seccomp_sha256, backend.credential_sha256,
        backend.context_sha256, runtime.runtime_layout_sha256,
        runtime.docs_sha256, layout.scope_sha256,
    )
    components = tuple(
        S.LayoutComponent(
            purpose, handle, attachment, mode,
            (target.identity_sha256 if index == 0
             else _d(f"identity:{purpose}")),
            contents[index],
            _d(f"provider-mount:pre:{purpose}"),
        )
        for index, ((purpose, attachment, mode), handle)
        in enumerate(zip(_ROSTER, handles, strict=True))
    )
    stable = {
        "attempt_id": request.attempt_id,
        "layout_handle": layout.layout_handle,
        "target_identity_sha256": target.identity_sha256,
        "target_content_sha256": target.content_sha256,
        "components": tuple({
            "purpose": row.purpose, "source_handle": row.source_handle,
            "attachment": row.attachment, "mode": row.mode,
            "identity_sha256": row.identity_sha256,
            "content_sha256": row.content_sha256,
        } for row in components),
    }
    precreate = S.LayoutRecensus(
        request.attempt_id, layout.layout_handle, target.identity_sha256,
        target.content_sha256, components, S.canonical_sha256(stable),
        "PRE_CREATE",
    )
    guest_mounts = tuple(
        S.GuestMount(purpose, handle, destination, mode)
        for (purpose, destination, mode), handle
        in zip(_ROSTER[1:], handles[1:], strict=True)
    )
    guest = S.GuestCreateSpec(
        request.attempt_id, request.image_manifest_digest,
        runtime.image_handle, request.image_closure_sha256,
        configured.config_sha256, precreate,
        request.egress_policy_sha256, request.egress_admission_sha256,
        request.backend_admission_sha256, request.credential_isolation_sha256,
        request.provider_provenance_sha256, guest_mounts,
        f"plamen-{request.attempt_id}",
        provider_kind=S.ProviderKind.APPLE_CONTAINER,
        platform_architecture=architecture,
    )
    init_image = M.TEST_ONLY_InitImageClosure(
        A.SUPPORTED_INIT_IMAGE_REFERENCE,
        A.SUPPORTED_INIT_IMAGE_INDEX_DIGEST,
        A.SUPPORTED_INIT_IMAGE_MANIFEST_DIGEST,
        _d("init-image-postcondition"),
    )
    overlay = M.TEST_ONLY_OverlayRelation(
        request.attempt_id, layout.target_lower_handle, layout.upper_handle,
        layout.work_handle, layout.merged_handle, target.identity_sha256,
        target.content_sha256, components[1].identity_sha256,
    )
    resolutions = tuple(
        M.TEST_ONLY_ResolvedComponent(
            row.purpose, row.source_handle,
            f"/private/plamen/adapter/{index:02d}-{row.purpose}",
            row.identity_sha256, row.content_sha256,
            row.provider_mount_identity_sha256,
        )
        for index, row in enumerate(components)
    )
    return {
        "request": request, "runtime": runtime, "backend": backend,
        "layout": layout, "configured": configured, "target": target,
        "guest": guest, "image": image, "init_image": init_image,
        "overlay": overlay,
        "network": _network(request, guest.guest_name), "pin": pin,
        "resolutions": resolutions,
    }


def _create(context: dict[str, object]) -> M.TEST_ONLY_CreateStoppedInput:
    request = context["request"]
    assert isinstance(request, S.AuditRequest)
    return M.translate_create_stopped_for_testing(
        context["request"], context["runtime"], context["backend"],
        context["layout"], context["configured"], context["target"],
        context["guest"], context["image"], context["init_image"],
        context["overlay"],
        context["network"], context["pin"], context["resolutions"],
        _ticket(S.MutationOperation.CREATE_GUEST, request, 3),
        host_architecture="arm64",
        rosetta_required=(
            isinstance(context["runtime"], S.AuthenticatedRuntimeImageLayout)
            and context["runtime"].guest_architecture == "amd64"
        ),
    )


def _postcreate(precreate: S.LayoutRecensus) -> S.LayoutRecensus:
    rows = tuple(
        replace(row, provider_mount_identity_sha256=
                _d(f"provider-mount:post:{row.purpose}"))
        for row in precreate.components
    )
    return S.LayoutRecensus(
        precreate.attempt_id, precreate.layout_handle,
        precreate.target_identity_sha256, precreate.target_content_sha256,
        rows, precreate.layout_sha256, "POST_CREATE",
    )


def _start_chain(
    context: dict[str, object], created: M.TEST_ONLY_CreateStoppedInput,
) -> tuple[M.TEST_ONLY_StartInput, A.DriverStartReceipt, S.DriverStartReceipt]:
    request = context["request"]
    guest = context["guest"]
    assert isinstance(request, S.AuditRequest)
    assert isinstance(guest, S.GuestCreateSpec)
    postcreate = _postcreate(guest.precreate_recensus)
    admission = S.GuestAdmissionReceipt(
        request.attempt_id, created.provider_spec.name, _h("admission"),
        _d("admission"), guest.precreate_recensus, postcreate,
        S._validate_layout_delta(guest.precreate_recensus, postcreate),
        guest.spec_sha256,
    )
    launch = S.DriverLaunch(
        request.attempt_id, created.provider_spec.name,
        admission.admission_sha256,
        (created.provider_spec.entrypoint, *created.provider_spec.arguments),
    )
    started_input = M.translate_start_for_testing(
        request, created, admission, launch,
        _ticket(S.MutationOperation.START_DRIVER, request, 5),
        launch_policy_sha256=_d("launch-policy"),
    )
    provider_start = A.DriverStartReceipt(
        "plamen.apple-container.driver-start.v1",
        created.provider_spec.name, request.attempt_id,
        created.provider_spec.fingerprint,
        started_input.launch_request.request_sha256,
        started_input.launch_request.launch_policy_sha256,
        started_input.launch_request.driver_argv_sha256,
        started_input.launch_request.driver_environment_sha256,
        started_input.launch_request.driver_cwd_sha256,
        started_input.launch_request.driver_stdin_sha256,
        started_input.launch_request.pass_fd_roster_sha256,
        _d("start-nonce")[:32], 1, "native-process-001",
        _d("native-process-handle"), started_input.cli_executable_sha256,
        started_input.provider_provenance_sha256,
        "2026-09-08T01:00:00Z", _d("start-effect"),
        _d("start-checkpoint"), created.rosetta_required,
    )
    supervisor_start = S.DriverStartReceipt(
        request.attempt_id, created.provider_spec.name,
        launch.launch_sha256, provider_start.native_process_id, 1,
    )
    return started_input, provider_start, supervisor_start


def _wait_chain(
    context: dict[str, object], started_input: M.TEST_ONLY_StartInput,
    provider_start: A.DriverStartReceipt,
    supervisor_start: S.DriverStartReceipt,
) -> tuple[M.TEST_ONLY_WaitInput, A.DriverWaitReceipt, S.DriverExitReceipt]:
    request = context["request"]
    assert isinstance(request, S.AuditRequest)
    wait_input = M.translate_wait_for_testing(
        request, started_input, provider_start, supervisor_start,
        _ticket(S.MutationOperation.WAIT_DRIVER, request, 6),
    )
    stdout = b'{"type":"result"}\n'
    stderr = b""
    provider_wait = A.DriverWaitReceipt(
        schema="plamen.apple-container.driver-wait.v2",
        container_id=provider_start.container_id,
        attempt_id=request.attempt_id,
        spec_sha256=provider_start.spec_sha256,
        launch_request_sha256=started_input.launch_request.request_sha256,
        start_receipt_sha256=provider_start.receipt_sha256,
        launch_policy_sha256=provider_start.launch_policy_sha256,
        driver_argv_sha256=provider_start.driver_argv_sha256,
        driver_environment_sha256=provider_start.driver_environment_sha256,
        driver_cwd_sha256=provider_start.driver_cwd_sha256,
        driver_stdin_sha256=provider_start.driver_stdin_sha256,
        pass_fd_roster_sha256=provider_start.pass_fd_roster_sha256,
        start_operation_nonce=provider_start.start_operation_nonce,
        wait_operation_nonce=_d("wait-nonce")[:32], operation_sequence=2,
        native_process_id=provider_start.native_process_id,
        native_process_handle_sha256=provider_start.native_process_handle_sha256,
        cli_executable_sha256=provider_start.cli_executable_sha256,
        provider_provenance_sha256=provider_start.provider_provenance_sha256,
        exit_code=0, stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        stdout_retained_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_retained_sha256=hashlib.sha256(stderr).hexdigest(),
        stdout_observed_bytes=len(stdout), stderr_observed_bytes=0,
        stdout_retained_bytes=len(stdout), stderr_retained_bytes=0,
        stdout_truncated=False, stderr_truncated=False,
        start_timestamp=provider_start.start_timestamp,
        end_timestamp="2026-09-08T01:01:00Z",
        native_process_extinction_sha256=_d("native-extinction"),
        cleanup_sha256=_d("provider-cleanup"),
        stop_argv_sha256=_d("stop-argv"),
        stop_stdout_sha256=_d("stop-stdout"),
        stop_stderr_sha256=_d("stop-stderr"),
        stopped_observation_sha256=_d("stopped-observation"),
        guest_population_extinction_sha256=_d("guest-population-extinction"),
        descendants_extinct=True,
        guest_process_extinct=True, backend_egress_revoked=True,
        stop_control_process_reaped=True,
        stop_control_process_group_extinct=True,
        guest_population_zero=True, container_vm_stopped=True,
        journal_checkpoint_sha256=_d("wait-checkpoint"),
        rosetta_required=provider_start.rosetta_required,
    )
    exited = S.DriverExitReceipt(
        request.attempt_id, provider_wait.container_id,
        supervisor_start.launch_sha256, provider_wait.exit_code,
        _d("supervisor-native-wait-receipt"),
    )
    return wait_input, provider_wait, exited


def _terminal_artifacts(
    context: dict[str, object], provider_wait: A.DriverWaitReceipt,
    exited: S.DriverExitReceipt,
) -> tuple[S.ExtinctionReceipt, S.ArtifactCensus, S.ExportReceipt]:
    request = context["request"]
    layout = context["layout"]
    assert isinstance(request, S.AuditRequest)
    assert isinstance(layout, S.AttemptLayout)
    terminal = S.ExtinctionReceipt(
        request.attempt_id, provider_wait.container_id,
        _d("supervisor-extinction"), 0, 0, True,
    )
    entries = (
        S.ArtifactEntry("project/AUDIT_REPORT.md", 6, _d("report")),
        S.ArtifactEntry("scratch/_v2_checkpoint.json", 3, _d("checkpoint")),
    )
    dispositions = tuple(
        S.ArtifactDisposition(row.relative_path, "PRESENT", row.sha256)
        for row in entries
    )
    census_handle = _h("census")
    census_sha = S.canonical_sha256({
        "attempt_id": request.attempt_id, "run_id": request.run_id,
        "terminal_sha256": terminal.terminal_sha256,
        "driver_exit_code": exited.exit_code,
        "census_handle": census_handle, "entries": entries,
        "dispositions": dispositions,
    })
    census = S.ArtifactCensus(
        request.attempt_id, request.run_id, terminal.terminal_sha256,
        exited.exit_code, census_handle, entries, dispositions, census_sha,
    )
    exported = S.ExportReceipt(
        request.attempt_id, request.run_id, census.census_sha256,
        layout.export_destination_handle,
        request.export_destination_identity_sha256, len(entries),
        sum(row.size for row in entries),
        S._expected_export_manifest(request, census), _d("export-receipt"),
    )
    return terminal, census, exported


def test_create_translation_binds_ten_semantic_mounts_and_run_paths() -> None:
    context = _context()
    created = _create(context)
    request = context["request"]
    guest = context["guest"]
    assert isinstance(request, S.AuditRequest)
    assert isinstance(guest, S.GuestCreateSpec)
    assert created.provider_spec.audit_attempt_id == "dodo-001"
    assert created.provider_spec.run_identity == "run-dodo-001"
    assert created.expected_state == "stopped"
    assert created.expected_process_count == 0
    assert len(created.provider_spec.mounts) == 10
    assert tuple(row.target for row in created.provider_spec.mounts) == tuple(
        destination for _, destination, _ in _ROSTER[1:]
    )
    assert tuple(row.target for row in created.provider_spec.mounts)[4:7] == (
        "/run/plamen/seccomp", "/run/plamen/credentials",
        "/run/plamen/backend",
    )
    assert created.supervisor_mount_roster_sha256 == S.canonical_sha256(
        guest.mounts
    )
    assert created.precreate_recensus_sha256 == guest.precreate_recensus.layout_sha256
    assert created.semantic_mount_roster_sha256 != S.canonical_sha256(tuple(
        sorted(row.target for row in created.provider_spec.mounts)
    ))
    init_image = context["init_image"]
    assert isinstance(init_image, M.TEST_ONLY_InitImageClosure)
    assert created.init_image_closure_sha256 == init_image.closure_sha256
    assert created.init_image_reference == A.SUPPORTED_INIT_IMAGE_REFERENCE
    assert created.init_image_index_digest == A.SUPPORTED_INIT_IMAGE_INDEX_DIGEST
    assert created.init_image_manifest_digest == A.SUPPORTED_INIT_IMAGE_MANIFEST_DIGEST
    assert created.init_image_postcondition_sha256 == (
        init_image.preflight_postcondition_sha256
    )
    assert created.provider_spec.init_image_reference == created.init_image_reference
    pin = context["pin"]
    assert isinstance(pin, A.AppleContainerVersionPin)
    assert created.cli_executable_sha256 == A.SUPPORTED_CLI_EXECUTABLE_SHA256
    assert created.provider_provenance_sha256 == A._canonical_digest(
        list(pin.provenance)
    )
    assert created.image_closure_sha256 == request.image_closure_sha256
    assert created.backend_admission_sha256 == request.backend_admission_sha256
    assert created.credential_isolation_sha256 == (
        request.credential_isolation_sha256
    )
    assert created.egress_admission_sha256 == request.egress_admission_sha256
    assert created.provider_spec.broker_v2_commitment == {
        "request_fingerprint": request.fingerprint_sha256,
        "attempt_id": request.attempt_id,
        "run_identity": request.run_id,
        "config_sha256": request.source_config_sha256,
        "runtime_closure_sha256": request.runtime_layout_sha256,
        "image_closure_sha256": request.image_closure_sha256,
        "provider_provenance_sha256": request.provider_provenance_sha256,
        "backend_admission_sha256": request.backend_admission_sha256,
        "credential_isolation_sha256": request.credential_isolation_sha256,
        "egress_admission_sha256": request.egress_admission_sha256,
    }


@pytest.mark.parametrize("field", [
    "image_closure_sha256", "backend_admission_sha256",
    "credential_isolation_sha256", "egress_admission_sha256",
    "provider_provenance_sha256",
])
def test_create_projection_rejects_broker_commitment_drift(field: str) -> None:
    created = _create(_context())
    with pytest.raises(M.AppleSupervisorAdapterError, match="malformed"):
        replace(created, **{field: _d("projection-drift-" + field)})


@pytest.mark.parametrize("changes", [
    {"image_reference": "ghcr.io/apple/containerization/vminit:0.42.0"},
    {"image_reference": "GHCR.IO/apple/containerization/vminit@"
        + A.SUPPORTED_INIT_IMAGE_INDEX_DIGEST},
    {"image_reference": "ghcr.io/apple/containerization/vminit@sha256:"
        + "9" * 64, "index_digest": "sha256:" + "9" * 64},
    {"manifest_digest": "sha256:" + "8" * 64},
    {"platform_architecture": "amd64"},
    {"immutable": False},
    {"authenticated": False},
])
def test_init_image_closure_rejects_tags_aliases_rebinding_and_platform_drift(
    changes: dict[str, object],
) -> None:
    context = _context()
    closure = context["init_image"]
    assert isinstance(closure, M.TEST_ONLY_InitImageClosure)
    with pytest.raises(M.AppleSupervisorAdapterError, match="init image"):
        replace(closure, **changes)


def test_forged_init_image_closure_cannot_cross_test_translation_boundary() -> None:
    context = _context()
    closure = context["init_image"]
    assert isinstance(closure, M.TEST_ONLY_InitImageClosure)
    context["init_image"] = _forge(
        closure,
        image_reference="ghcr.io/apple/containerization/vminit:0.42.0",
    )
    with pytest.raises(M.AppleSupervisorAdapterError, match="drift"):
        _create(context)


def test_init_image_postcondition_is_part_of_create_request_closure() -> None:
    first_context = _context()
    second_context = _context()
    init_image = second_context["init_image"]
    assert isinstance(init_image, M.TEST_ONLY_InitImageClosure)
    second_context["init_image"] = replace(
        init_image, preflight_postcondition_sha256=_d("changed-init-postcondition")
    )
    first = _create(first_context)
    second = _create(second_context)
    assert first.init_image_closure_sha256 != second.init_image_closure_sha256
    assert first.input_sha256 != second.input_sha256


def test_start_rejects_forged_postcreate_init_image_spec_substitution() -> None:
    context = _context()
    request = context["request"]
    guest = context["guest"]
    assert isinstance(request, S.AuditRequest)
    assert isinstance(guest, S.GuestCreateSpec)
    created = _create(context)
    forged_spec = _forge(
        created.provider_spec,
        init_image_reference="ghcr.io/apple/containerization/vminit:0.42.0",
    )
    forged_created = _forge(created, provider_spec=forged_spec)
    postcreate = _postcreate(guest.precreate_recensus)
    admission = S.GuestAdmissionReceipt(
        request.attempt_id, created.provider_spec.name, _h("admission"),
        _d("admission"), guest.precreate_recensus, postcreate,
        S._validate_layout_delta(guest.precreate_recensus, postcreate),
        guest.spec_sha256,
    )
    launch = S.DriverLaunch(
        request.attempt_id, created.provider_spec.name,
        admission.admission_sha256,
        (created.provider_spec.entrypoint, *created.provider_spec.arguments),
    )
    with pytest.raises(M.AppleSupervisorAdapterError, match="start chain"):
        M.translate_start_for_testing(
            request, forged_created, admission, launch,
            _ticket(S.MutationOperation.START_DRIVER, request, 5),
            launch_policy_sha256=_d("launch-policy"),
        )


@pytest.mark.parametrize("mutation", ["missing", "extra", "duplicate", "reordered"])
def test_resolution_roster_is_exact_and_ordered(mutation: str) -> None:
    context = _context()
    rows = context["resolutions"]
    assert isinstance(rows, tuple)
    if mutation == "missing":
        changed = rows[:-1]
    elif mutation == "extra":
        changed = (*rows, rows[-1])
    elif mutation == "duplicate":
        changed = (rows[0], replace(rows[1], purpose=rows[0].purpose), *rows[2:])
    else:
        changed = (rows[1], rows[0], *rows[2:])
    context["resolutions"] = changed
    with pytest.raises(M.AppleSupervisorAdapterError, match="component|roster|order"):
        _create(context)


@pytest.mark.parametrize("overlap", [False, True])
def test_resolution_paths_reject_alias_and_ancestor_overlap(overlap: bool) -> None:
    context = _context()
    rows = context["resolutions"]
    assert isinstance(rows, tuple)
    base = rows[0].source_path
    second = base + "/child" if overlap else base.upper()
    context["resolutions"] = (rows[0], replace(rows[1], source_path=second), *rows[2:])
    with pytest.raises(M.AppleSupervisorAdapterError, match="alias|overlap"):
        _create(context)


@pytest.mark.parametrize("drift", ["target", "merged", "image", "component"])
def test_create_translation_rejects_authority_drift(drift: str) -> None:
    context = _context()
    if drift == "target":
        context["target"] = replace(
            context["target"], content_sha256=_d("changed-target")
        )
    elif drift == "merged":
        context["overlay"] = replace(
            context["overlay"], merged_identity_sha256=_d("changed-merged")
        )
    elif drift == "image":
        context["image"] = replace(
            context["image"], runtime_layout_sha256=_d("changed-runtime")
        )
    else:
        rows = context["resolutions"]
        assert isinstance(rows, tuple)
        context["resolutions"] = (
            replace(rows[0], identity_sha256=_d("changed-component")),
            *rows[1:],
        )
    with pytest.raises(M.AppleSupervisorAdapterError, match="drift|relation|facts"):
        _create(context)


def test_forged_guest_mount_reordering_is_rejected() -> None:
    context = _context()
    guest = context["guest"]
    assert isinstance(guest, S.GuestCreateSpec)
    context["guest"] = _forge(
        guest, mounts=(guest.mounts[1], guest.mounts[0], *guest.mounts[2:])
    )
    with pytest.raises(M.AppleSupervisorAdapterError, match="mount policy"):
        _create(context)


def test_rosetta_is_bound_to_arm_host_dodo_amd64_lane_only() -> None:
    context = _context(architecture="amd64")
    created = _create(context)
    assert created.rosetta_required is True
    assert created.host_architecture == "arm64"
    assert created.provider_spec.rosetta_required is True

    request = context["request"]
    assert isinstance(request, S.AuditRequest)
    with pytest.raises(M.AppleSupervisorAdapterError, match="host architecture"):
        M.translate_create_stopped_for_testing(
            context["request"], context["runtime"], context["backend"],
            context["layout"], context["configured"], context["target"],
            context["guest"], context["image"], context["init_image"],
            context["overlay"],
            context["network"], context["pin"], context["resolutions"],
            _ticket(S.MutationOperation.CREATE_GUEST, request, 3),
            host_architecture="x86_64", rosetta_required=True,
        )
    with pytest.raises(M.AppleSupervisorAdapterError, match="Rosetta requirement"):
        M.translate_create_stopped_for_testing(
            context["request"], context["runtime"], context["backend"],
            context["layout"], context["configured"], context["target"],
            context["guest"], context["image"], context["init_image"],
            context["overlay"],
            context["network"], context["pin"], context["resolutions"],
            _ticket(S.MutationOperation.CREATE_GUEST, request, 3),
            host_architecture="arm64", rosetta_required=False,
        )

    non_dodo = _context(architecture="amd64", attempt_id="attempt-001")
    with pytest.raises(M.AppleSupervisorAdapterError, match="not admissible"):
        _create(non_dodo)


def test_start_wait_and_delete_bind_distinct_provider_and_supervisor_receipts() -> None:
    context = _context()
    request = context["request"]
    layout = context["layout"]
    assert isinstance(request, S.AuditRequest)
    assert isinstance(layout, S.AttemptLayout)
    created = _create(context)
    started_input, provider_start, supervisor_start = _start_chain(context, created)
    wait_input, provider_wait, exited = _wait_chain(
        context, started_input, provider_start, supervisor_start,
    )
    terminal, census, exported = _terminal_artifacts(
        context, provider_wait, exited,
    )
    deleted = M.translate_delete_for_testing(
        request, layout, wait_input, provider_wait, exited, terminal,
        census, exported,
        _ticket(S.MutationOperation.DELETE_GUEST, request, 10),
        predelete_process_count=0,
        exact_predelete_guest_ids=(provider_wait.container_id,),
    )
    assert started_input.launch_request.attempt_id == request.attempt_id
    assert wait_input.native_process_id == provider_start.native_process_id
    assert wait_input.native_process_handle_sha256 == (
        provider_start.native_process_handle_sha256
    )
    assert deleted.provider_wait_receipt_sha256 == provider_wait.receipt_sha256
    assert deleted.supervisor_wait_sha256 == exited.wait_sha256
    assert deleted.supervisor_wait_sha256 != deleted.provider_wait_receipt_sha256
    assert deleted.exact_predelete_guest_ids == (provider_wait.container_id,)


@pytest.mark.parametrize("field", ["cli", "provenance", "process", "count"])
def test_wait_translation_rejects_start_substitution(field: str) -> None:
    context = _context()
    request = context["request"]
    assert isinstance(request, S.AuditRequest)
    created = _create(context)
    started_input, provider_start, supervisor_start = _start_chain(context, created)
    if field == "cli":
        provider_start = replace(provider_start, cli_executable_sha256=_d("wrong-cli"))
    elif field == "provenance":
        provider_start = replace(
            provider_start, provider_provenance_sha256=_d("wrong-provenance")
        )
    elif field == "process":
        supervisor_start = replace(supervisor_start, driver_process_id="other-process")
    else:
        supervisor_start = _forge(supervisor_start, driver_process_count=2)
    with pytest.raises(M.AppleSupervisorAdapterError, match="wait chain"):
        M.translate_wait_for_testing(
            request, started_input, provider_start, supervisor_start,
            _ticket(S.MutationOperation.WAIT_DRIVER, request, 6),
        )


@pytest.mark.parametrize(
    "hazard", [
        "provider-egress", "provider-vm", "provider-population",
        "provider-stop-proof", "terminal-count", "predelete-count",
        "guest-roster", "artifact", "export",
    ],
)
def test_delete_translation_hard_stops_on_residual_or_artifact_hazard(
    hazard: str,
) -> None:
    context = _context()
    request = context["request"]
    layout = context["layout"]
    assert isinstance(request, S.AuditRequest)
    assert isinstance(layout, S.AttemptLayout)
    created = _create(context)
    started_input, provider_start, supervisor_start = _start_chain(context, created)
    wait_input, provider_wait, exited = _wait_chain(
        context, started_input, provider_start, supervisor_start,
    )
    terminal, census, exported = _terminal_artifacts(context, provider_wait, exited)
    process_count = 0
    guest_ids = (provider_wait.container_id,)
    if hazard == "provider-egress":
        provider_wait = _forge(provider_wait, backend_egress_revoked=False)
    elif hazard == "provider-vm":
        provider_wait = _forge(provider_wait, container_vm_stopped=False)
    elif hazard == "provider-population":
        provider_wait = _forge(provider_wait, guest_population_zero=False)
    elif hazard == "provider-stop-proof":
        provider_wait = _forge(provider_wait, stop_argv_sha256="bad")
    elif hazard == "terminal-count":
        terminal = _forge(terminal, process_count=1)
    elif hazard == "predelete-count":
        process_count = 1
    elif hazard == "guest-roster":
        guest_ids = ()
    elif hazard == "artifact":
        missing = S.ArtifactDisposition(
            "project/AUDIT_REPORT.md", "MISSING", None,
        )
        census = replace(
            census, dispositions=(missing, census.dispositions[1]),
            census_sha256=_d("forged-census"),
        )
    else:
        exported = replace(exported, manifest_sha256=_d("wrong-manifest"))
    with pytest.raises(M.AppleSupervisorAdapterError, match="cleanup|census|export|residual"):
        M.translate_delete_for_testing(
            request, layout, wait_input, provider_wait, exited, terminal,
            census, exported,
            _ticket(S.MutationOperation.DELETE_GUEST, request, 10),
            predelete_process_count=process_count,
            exact_predelete_guest_ids=guest_ids,
        )


def test_wrong_ticket_operation_is_rejected() -> None:
    context = _context()
    request = context["request"]
    assert isinstance(request, S.AuditRequest)
    with pytest.raises(M.AppleSupervisorAdapterError, match="ticket"):
        M.translate_create_stopped_for_testing(
            context["request"], context["runtime"], context["backend"],
            context["layout"], context["configured"], context["target"],
            context["guest"], context["image"], context["init_image"],
            context["overlay"],
            context["network"], context["pin"], context["resolutions"],
            _ticket(S.MutationOperation.START_DRIVER, request, 3),
            host_architecture="arm64", rosetta_required=False,
        )


def test_production_entrypoint_hard_stops_without_touching_provider(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    calls: list[str] = []

    def forbidden(*_args: object, **_kwargs: object) -> None:
        calls.append("provider")
        raise AssertionError("provider call escaped production hardstop")

    monkeypatch.setattr(A.AppleContainerProvider, "create", forbidden)
    monkeypatch.setattr(A.AppleContainerProvider, "start_driver", forbidden)
    monkeypatch.setattr(A.AppleContainerProvider, "wait_driver", forbidden)
    monkeypatch.setattr(A.AppleContainerProvider, "delete", forbidden)
    with pytest.raises(M.AppleSupervisorAdapterUnavailable, match="native|broker"):
        M.translate_apple_provider_inputs(
            object(), object(), tool_custody=object(),
            source_root=tmp_path, scratch_root=tmp_path,
            state_root=tmp_path, project_root=tmp_path,
        )
    assert calls == []


def test_production_missing_native_surface_precedes_input_inspection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class EvilInput:
        def __getattribute__(self, name: str) -> object:
            if name != "__class__":
                events.append(f"INPUT_ATTRIBUTE:{name}")
                raise AssertionError("production input was inspected")
            return object.__getattribute__(self, name)

    consumer = EvilInput()
    adapter = EvilInput()
    path = EvilInput()
    monkeypatch.setattr(
        A, "_native_provider_surface",
        lambda: (_ for _ in ()).throw(RuntimeError("missing")),
    )
    with pytest.raises(M.AppleSupervisorAdapterUnavailable, match="integrated"):
        M.translate_apple_provider_inputs(
            consumer, adapter, tool_custody=path,
            source_root=path, scratch_root=path,
            state_root=path, project_root=path,
        )
    assert events == []
