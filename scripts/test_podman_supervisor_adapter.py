"""Fake-only tests for the POSIX-supervisor to Podman translation boundary."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import os
from pathlib import Path
import stat
import threading

import pytest

import podman_linux_provider as P
import podman_supervisor_adapter as A
import posix_audit_supervisor as S


def _h(number: int) -> str:
    return "opaque:" + f"{number:064x}"


def _d(character: str) -> str:
    return character * 64


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _request(*, architecture: str = "arm64") -> tuple[
    S.AuditRequest, S.AttemptLayout, S.AuthenticatedRuntimeImageLayout,
    S.BackendContext, S.ConfigReceipt, S.GuestCreateSpec,
]:
    config_document = {
        "_run_id": "run-001", "cli_backend": "codex",
        "docs_inputs": ["/workspace/docs/design.md"],
        "docs_path": "/workspace/docs", "language": "evm",
        "mode": "core", "pipeline": "sc",
        "project_root": "/workspace/project",
        "scope_file": "/workspace/scope",
        "scratchpad": "/workspace/scratch",
    }
    raw = S._canonical_bytes(config_document)
    source = S.AuthenticatedDriverConfig(
        _h(90), raw, hashlib.sha256(raw).hexdigest()
    )
    request = S.AuditRequest(
        request_type=S.RequestType.SC_NEW,
        request_id="request-001",
        attempt_id="attempt-001",
        run_id="run-001",
        pipeline="sc",
        mode="core",
        backend="codex",
        language="evm",
        source_config=source,
        source_config_sha256=source.sha256,
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
            "project/AUDIT_REPORT.md", "scratch/_plamen.log",
            "scratch/_v2_checkpoint.json", "scratch/finding_records.json",
        ),
        required_artifacts=(
            "project/AUDIT_REPORT.md", "scratch/_v2_checkpoint.json",
        ),
        failure_required_artifacts=("scratch/_plamen.log",),
        export_destination_identity_sha256=_d("c"),
    )
    runtime = S.AuthenticatedRuntimeImageLayout(
        request.runtime_layout_sha256, request.image_manifest_digest,
        request.image_closure_sha256, request.docs_sha256,
        _h(30), _h(31), _h(32),
        guest_architecture=architecture,
    )
    backend = S.BackendContext(
        backend=request.backend,
        context_sha256=request.backend_context_sha256,
        backend_admission_sha256=request.backend_admission_sha256,
        egress_policy_sha256=request.egress_policy_sha256,
        egress_admission_sha256=request.egress_admission_sha256,
        credential_sha256=request.credential_bundle_sha256,
        credential_isolation_sha256=request.credential_isolation_sha256,
        context_handle=_h(40),
        credential_handle=_h(41),
    )
    layout = S.AttemptLayout(
        request.attempt_id, request.run_id, _h(10), _h(1), _h(11),
        _h(12), _h(13), _h(14), _h(15), _h(16), _h(17), _h(18),
        request.target_identity_sha256, request.scope_sha256,
        request.seccomp_profile_sha256, _h(19),
        request.export_destination_identity_sha256,
    )
    guest_config = S.GuestConfig(_h(90), raw, source.sha256)
    configured = S.ConfigReceipt(
        request.attempt_id, request.run_id, _h(20), source.sha256,
        request.source_config_sha256,
        request.startup_decision_receipt_sha256, guest_config,
    )
    mount_handles = (
        layout.merged_handle, layout.scratch_handle, layout.state_handle,
        layout.control_handle, layout.seccomp_handle,
        backend.credential_handle, backend.context_handle,
        runtime.runtime_handle, runtime.docs_handle, layout.scope_handle,
    )
    mounts = tuple(
        S.GuestMount(purpose, handle, destination, mode)
        for (purpose, destination, mode), handle in zip(
            A.VISIBLE_GUEST_MOUNT_POLICY, mount_handles, strict=True
        )
    )
    component_handles = (layout.target_lower_handle, *mount_handles)
    contents = (
        _sha("target-content"), _sha("merged"), _sha("scratch"),
        _sha("state"), _sha("control"), request.seccomp_profile_sha256,
        request.credential_bundle_sha256, request.backend_context_sha256,
        request.runtime_layout_sha256, request.docs_sha256,
        request.scope_sha256,
    )
    components = tuple(
        S.LayoutComponent(
            purpose, handle, attachment, mode,
            _sha(f"identity:{index}"), contents[index],
            _sha(f"provider:pre:{index}"),
        )
        for index, ((purpose, attachment, mode), handle) in enumerate(
            zip(A.RECENSUS_COMPONENT_POLICY, component_handles, strict=True)
        )
    )
    stable = {
        "attempt_id": request.attempt_id, "layout_handle": layout.layout_handle,
        "target_identity_sha256": request.target_identity_sha256,
        "target_content_sha256": contents[0],
        "components": tuple({
            "purpose": row.purpose, "source_handle": row.source_handle,
            "attachment": row.attachment, "mode": row.mode,
            "identity_sha256": row.identity_sha256,
            "content_sha256": row.content_sha256,
        } for row in components),
    }
    recensus = S.LayoutRecensus(
        request.attempt_id, layout.layout_handle,
        request.target_identity_sha256, contents[0], components,
        S.canonical_sha256(stable), "PRE_CREATE",
    )
    spec = S.GuestCreateSpec(
        attempt_id=request.attempt_id,
        image_manifest_digest=request.image_manifest_digest,
        image_handle=runtime.image_handle,
        image_closure_sha256=request.image_closure_sha256,
        config_sha256=configured.config_sha256,
        precreate_recensus=recensus,
        egress_policy_sha256=request.egress_policy_sha256,
        egress_admission_sha256=request.egress_admission_sha256,
        backend_admission_sha256=request.backend_admission_sha256,
        credential_isolation_sha256=request.credential_isolation_sha256,
        provider_provenance_sha256=request.provider_provenance_sha256,
        mounts=mounts,
        guest_name=f"plamen-{request.attempt_id}",
        platform_architecture=architecture,
    )
    return request, layout, runtime, backend, configured, spec


def _closure(*, architecture: str = "arm64") -> A.AttemptClosure:
    return A.AttemptClosure(*_request(architecture=architecture))


def _ticket(
    closure: A.AttemptClosure, operation: S.MutationOperation, sequence: int = 1,
) -> S.MutationTicket:
    return S.MutationTicket(
        operation, closure.request.fingerprint_sha256,
        closure.request.attempt_id, _sha("checkpoint"), sequence,
        _sha(f"nonce:{operation.value}:{sequence}"),
    )


def _resolutions(create: A.CreateStoppedInput) -> tuple[
    tuple[A.TEST_ONLY_HandleResolution, ...],
    A.TEST_ONLY_SeccompProfileResolution,
]:
    purposes = tuple(dict.fromkeys(
        item.source_purpose for item in create.provider_mounts
    )) + tuple(
        item.purpose for item in create.visible_mounts
        if item.purpose not in {
            projection.source_purpose for projection in create.provider_mounts
        }
    )
    handles = {
        item.source_purpose: item.source_handle for item in create.provider_mounts
    }
    handles.update({item.purpose: item.source_handle for item in create.visible_mounts})
    rows = tuple(
        A.TEST_ONLY_HandleResolution(
            purpose, handles[purpose], Path(f"/srv/plamen/{purpose}"),
            7, index + 100,
        )
        for index, purpose in enumerate(purposes)
    )
    seccomp_dir = next(item for item in rows if item.source_purpose == "seccomp")
    profile = A.TEST_ONLY_SeccompProfileResolution(
        seccomp_dir.source_handle, seccomp_dir.path / A.SECCOMP_PROFILE_BASENAME,
        7, 999, create.seccomp_sha256,
    )
    return rows, profile


def _created_bundle() -> tuple[
    A.AttemptClosure, S.GuestCreatedReceipt, S.GuestAdmissionReceipt,
    S.DriverLaunch, S.DriverStartReceipt, S.DriverExitReceipt,
    S.ExtinctionReceipt, S.ArtifactCensus,
]:
    closure = _closure()
    components = tuple(
        replace(item, provider_mount_identity_sha256=_sha(f"provider:post:{i}"))
        for i, item in enumerate(closure.create_spec.precreate_recensus.components)
    )
    pre = closure.create_spec.precreate_recensus
    post = S.LayoutRecensus(
        pre.attempt_id, pre.layout_handle, pre.target_identity_sha256,
        pre.target_content_sha256, components, pre.layout_sha256,
        "POST_CREATE",
    )
    provider_mounts = post.provider_mounts_sha256
    created = S.GuestCreatedReceipt(
        S.ProviderKind.PODMAN, closure.request.attempt_id,
        closure.create_spec.guest_name, closure.create_spec,
        S.canonical_sha256(closure.create_spec.mounts), provider_mounts,
    )
    delta = S.canonical_sha256(tuple(
        (
            before.purpose, before.provider_mount_identity_sha256,
            after.provider_mount_identity_sha256,
        )
        for before, after in zip(pre.components, post.components, strict=True)
    ))
    admission = S.GuestAdmissionReceipt(
        closure.request.attempt_id, created.guest_id, _h(70), _sha("admission"),
        pre, post, delta, closure.create_spec.spec_sha256,
    )
    launch = S.DriverLaunch(
        closure.request.attempt_id, created.guest_id,
        admission.admission_sha256, closure.expected_driver_argv,
    )
    started = S.DriverStartReceipt(
        closure.request.attempt_id, created.guest_id,
        launch.launch_sha256, "driver-001",
    )
    exited = S.DriverExitReceipt(
        closure.request.attempt_id, created.guest_id,
        launch.launch_sha256, 0, _sha("wait"),
    )
    terminal = S.ExtinctionReceipt(
        closure.request.attempt_id, created.guest_id, _sha("terminal")
    )
    entries = (
        S.ArtifactEntry("project/AUDIT_REPORT.md", 100, _sha("report")),
        S.ArtifactEntry("scratch/_v2_checkpoint.json", 200, _sha("checkpoint")),
    )
    dispositions = tuple(
        S.ArtifactDisposition(item.relative_path, "PRESENT", item.sha256)
        for item in entries
    )
    census_digest = S.canonical_sha256({
        "attempt_id": closure.request.attempt_id,
        "run_id": closure.request.run_id,
        "terminal_sha256": terminal.terminal_sha256,
        "driver_exit_code": exited.exit_code,
        "census_handle": _h(71), "entries": entries,
        "dispositions": dispositions,
    })
    census = S.ArtifactCensus(
        closure.request.attempt_id, closure.request.run_id,
        terminal.terminal_sha256, exited.exit_code, _h(71), entries,
        dispositions, census_digest,
    )
    return closure, created, admission, launch, started, exited, terminal, census


def test_create_translation_has_exact_distinct_topologies_and_closure() -> None:
    closure = _closure()
    create = A.TEST_ONLY_translate_create(
        closure, _ticket(closure, S.MutationOperation.CREATE_GUEST)
    )
    assert tuple(item.purpose for item in create.provider_mounts) == tuple(P._MOUNT_ROSTER)
    assert tuple((item.purpose, item.destination, item.mode)
                 for item in create.visible_mounts) == A.VISIBLE_GUEST_MOUNT_POLICY
    by_purpose = {item.purpose: item for item in create.provider_mounts}
    assert by_purpose["project-lower"].source_handle == closure.layout.target_lower_handle
    assert by_purpose["project-upper"].source_handle == closure.layout.upper_handle
    assert by_purpose["project-work"].source_handle == closure.layout.work_handle
    assert by_purpose["project-merged"].source_handle == closure.layout.merged_handle
    assert len({by_purpose[name].source_handle for name in (
        "project-lower", "project-upper", "project-work", "project-merged"
    )}) == 4
    assert create.image_handle == closure.runtime.image_handle
    assert create.config_handle == closure.configured.config_handle
    assert create.entrypoint == A.GUEST_BOOTSTRAP_PATH
    assert (create.entrypoint, *create.arguments) == closure.expected_bootstrap_argv
    assert closure.expected_driver_argv == (
        "/usr/bin/python3", "-B", "/opt/plamen/scripts/plamen_driver.py",
        *create.arguments,
    )
    assert create.environment == ()
    assert create.initial_process_count == 0 and create.create_stopped is True
    assert create.broker_v2_commitment == closure.broker_v2_commitment
    assert create.broker_v2_commitment == A.BrokerV2Commitment(
        closure.request.fingerprint_sha256,
        closure.request.attempt_id,
        closure.request.run_id,
        closure.request.source_config_sha256,
        closure.request.runtime_layout_sha256,
        closure.request.image_closure_sha256,
        closure.request.provider_provenance_sha256,
        closure.request.backend_admission_sha256,
        closure.request.credential_isolation_sha256,
        closure.request.egress_admission_sha256,
    )


@pytest.mark.parametrize(
    "field",
    (
        "request_fingerprint_sha256", "config_sha256",
        "runtime_closure_sha256", "image_closure_sha256",
        "provider_provenance_sha256", "backend_admission_sha256",
        "credential_isolation_sha256", "egress_admission_sha256",
    ),
)
def test_create_rejects_every_common_commitment_digest_drift(field: str) -> None:
    closure = _closure()
    create = A.TEST_ONLY_translate_create(
        closure, _ticket(closure, S.MutationOperation.CREATE_GUEST)
    )
    changed = replace(
        create.broker_v2_commitment, **{field: _sha("changed:" + field)}
    )
    try:
        changed_create = replace(create, broker_v2_commitment=changed)
    except A.AdapterContractError:
        return
    rows, profile = _resolutions(create)
    with pytest.raises(A.AdapterContractError):
        A.TEST_ONLY_resolve_create(closure, changed_create, rows, profile)


def test_parent_tmpfs_precedes_every_nested_run_bind_and_seccomp_is_child() -> None:
    closure = _closure()
    create = A.TEST_ONLY_translate_create(
        closure, _ticket(closure, S.MutationOperation.CREATE_GUEST)
    )
    run = create.render_order.index("tmpfs:/run")
    assert all(run < create.render_order.index(f"bind:{path}") for path in (
        "/run/plamen/seccomp", "/run/plamen/credentials", "/run/plamen/backend"
    ))
    seccomp = next(item for item in create.provider_mounts if item.purpose == "seccomp")
    assert seccomp.relative_child == A.SECCOMP_PROFILE_BASENAME
    assert create.seccomp_guest_profile == A.SECCOMP_GUEST_PROFILE
    assert next(item for item in create.visible_mounts if item.purpose == "seccomp").destination == "/run/plamen/seccomp"


@pytest.mark.parametrize("architecture", ["amd64", "arm64"])
def test_resolved_create_is_exact_accepted_provider_model(architecture: str) -> None:
    closure = _closure(architecture=architecture)
    create = A.TEST_ONLY_translate_create(
        closure, _ticket(closure, S.MutationOperation.CREATE_GUEST)
    )
    rows, profile = _resolutions(create)
    resolved = A.TEST_ONLY_resolve_create(closure, create, rows, profile)
    resolved.provider_spec.validate()
    assert resolved.provider_spec.image.architecture == architecture
    assert tuple(item.purpose for item in resolved.provider_spec.mounts) == tuple(P._MOUNT_ROSTER)
    assert resolved.provider_spec.mounts[0].source != resolved.provider_spec.mounts[3].source
    assert resolved.provider_spec.mounts[-1].source == profile.path
    assert tuple(item[0] for item in resolved.visible_bind_sources) == tuple(
        row[0] for row in A.VISIBLE_GUEST_MOUNT_POLICY
    )


@pytest.mark.parametrize("mutation", ["missing", "extra", "order", "inode", "path", "ancestor"])
def test_resolution_roster_alias_and_overlap_fail_closed(mutation: str) -> None:
    closure = _closure()
    create = A.TEST_ONLY_translate_create(
        closure, _ticket(closure, S.MutationOperation.CREATE_GUEST)
    )
    rows, profile = _resolutions(create)
    changed = list(rows)
    if mutation == "missing":
        changed.pop()
    elif mutation == "extra":
        changed.append(replace(rows[-1], source_purpose="unexpected", inode=777))
    elif mutation == "order":
        changed[0], changed[1] = changed[1], changed[0]
    elif mutation == "inode":
        changed[1] = replace(changed[1], inode=changed[0].inode)
    elif mutation == "path":
        changed[1] = replace(changed[1], path=changed[0].path)
    else:
        changed[1] = replace(changed[1], path=changed[0].path / "nested")
    with pytest.raises(A.AdapterContractError):
        A.TEST_ONLY_resolve_create(closure, create, tuple(changed), profile)


@pytest.mark.parametrize("mutation", ["parent", "basename", "digest", "writable", "hardlink"])
def test_seccomp_child_profile_fail_closed(mutation: str) -> None:
    closure = _closure()
    create = A.TEST_ONLY_translate_create(
        closure, _ticket(closure, S.MutationOperation.CREATE_GUEST)
    )
    rows, profile = _resolutions(create)
    with pytest.raises(A.AdapterContractError):
        if mutation == "parent":
            profile = replace(profile, directory_handle=_h(999))
        elif mutation == "basename":
            profile = replace(profile, path=profile.path.with_name("other.json"))
        elif mutation == "digest":
            profile = replace(profile, content_sha256=_sha("other"))
        elif mutation == "writable":
            profile = replace(profile, mode=stat.S_IFREG | 0o600)
        else:
            profile = replace(profile, nlink=2)
        A.TEST_ONLY_resolve_create(closure, create, rows, profile)


def _recensus_with(
    pre: S.LayoutRecensus, components: tuple[S.LayoutComponent, ...],
) -> S.LayoutRecensus:
    stable = {
        "attempt_id": pre.attempt_id, "layout_handle": pre.layout_handle,
        "target_identity_sha256": pre.target_identity_sha256,
        "target_content_sha256": pre.target_content_sha256,
        "components": tuple({
            "purpose": row.purpose, "source_handle": row.source_handle,
            "attachment": row.attachment, "mode": row.mode,
            "identity_sha256": row.identity_sha256,
            "content_sha256": row.content_sha256,
        } for row in components),
    }
    return S.LayoutRecensus(
        pre.attempt_id, pre.layout_handle, pre.target_identity_sha256,
        pre.target_content_sha256, components,
        S.canonical_sha256(stable), pre.phase,
    )


@pytest.mark.parametrize("mutation", ["missing", "extra", "order", "duplicate-handle", "lower-merged"])
def test_closure_rejects_component_and_lower_merged_drift(mutation: str) -> None:
    values = list(_request())
    spec = values[-1]
    pre = spec.precreate_recensus
    components = list(pre.components)
    if mutation == "missing":
        components.pop()
    elif mutation == "extra":
        components.append(replace(components[-1], purpose="extra"))
    elif mutation == "order":
        components[0], components[1] = components[1], components[0]
    elif mutation == "duplicate-handle":
        components[1] = replace(components[1], source_handle=components[0].source_handle)
    else:
        mounts = list(spec.mounts)
        mounts[0] = replace(mounts[0], source_handle=values[1].target_lower_handle)
        values[-1] = replace(spec, mounts=tuple(mounts))
        with pytest.raises(A.AdapterContractError):
            A.AttemptClosure(*values)
        return
    values[-1] = replace(spec, precreate_recensus=_recensus_with(pre, tuple(components)))
    with pytest.raises(A.AdapterContractError):
        A.AttemptClosure(*values)


@pytest.mark.parametrize(
    "field",
    (
        "attempt", "run", "config", "image", "image-closure", "egress",
        "egress-admission", "backend-admission", "credential-isolation",
        "provider-provenance", "seccomp",
    ),
)
def test_attempt_run_ticket_config_image_closure_fail_closed(field: str) -> None:
    values = list(_request())
    request, layout, runtime, backend, configured, spec = values
    if field == "attempt":
        values[1] = replace(layout, attempt_id="other")
    elif field == "run":
        values[1] = replace(layout, run_id="other")
    elif field == "config":
        values[4] = replace(configured, config_sha256=_sha("other"))
    elif field == "image":
        values[2] = replace(runtime, image_manifest_digest="sha256:" + _d("e"))
    elif field == "image-closure":
        values[2] = replace(runtime, image_closure_sha256=_sha("other-image"))
    elif field == "egress":
        values[3] = replace(backend, egress_policy_sha256=_d("e"))
    elif field == "egress-admission":
        values[3] = replace(
            backend, egress_admission_sha256=_sha("other-egress-admission")
        )
    elif field == "backend-admission":
        values[3] = replace(
            backend, backend_admission_sha256=_sha("other-backend-admission")
        )
    elif field == "credential-isolation":
        values[3] = replace(
            backend,
            credential_isolation_sha256=_sha("other-credential-isolation"),
        )
    elif field == "provider-provenance":
        values[-1] = replace(
            spec, provider_provenance_sha256=_sha("other-provider-provenance")
        )
    else:
        values[1] = replace(layout, seccomp_sha256=_d("e"))
    with pytest.raises(A.AdapterContractError):
        A.AttemptClosure(*values)


def test_cross_authority_alias_with_upper_or_work_fails_closed() -> None:
    values = list(_request())
    _request_value, layout, runtime, _backend, _configured, spec = values
    changed_runtime = replace(runtime, runtime_handle=layout.upper_handle)
    mounts = list(spec.mounts)
    runtime_index = next(
        index for index, item in enumerate(mounts) if item.purpose == "runtime"
    )
    mounts[runtime_index] = replace(
        mounts[runtime_index], source_handle=layout.upper_handle
    )
    components = list(spec.precreate_recensus.components)
    component_index = next(
        index for index, item in enumerate(components)
        if item.purpose == "runtime"
    )
    components[component_index] = replace(
        components[component_index], source_handle=layout.upper_handle
    )
    values[2] = changed_runtime
    values[-1] = replace(
        spec, mounts=tuple(mounts),
        precreate_recensus=_recensus_with(
            spec.precreate_recensus, tuple(components)
        ),
    )
    with pytest.raises(A.AdapterContractError):
        A.AttemptClosure(*values)


def test_wrong_operation_ticket_never_translates() -> None:
    closure, created, admission, launch, started, exited, terminal, census = _created_bundle()
    with pytest.raises(A.AdapterContractError):
        A.TEST_ONLY_translate_create(
            closure, _ticket(closure, S.MutationOperation.START_DRIVER)
        )
    operations = {
        "start-driver": {
            "created": created, "admission": admission, "launch": launch,
        },
        "wait-driver": {"created": created, "started": started},
        "extinguish": {"created": created, "exited": exited},
        "census-artifacts": {
            "created": created, "exited": exited, "terminal": terminal,
        },
        "export-artifacts": {
            "created": created, "exited": exited, "terminal": terminal,
            "census": census,
        },
        "delete-guest": {
            "created": created, "exited": exited, "terminal": terminal,
            "census": census,
        },
        "release-attempt": {
            "created": created, "exited": exited, "terminal": terminal,
            "census": census,
        },
    }
    for operation, values in operations.items():
        with pytest.raises(A.AdapterContractError):
            A.TEST_ONLY_translate_lifecycle(
                operation, closure, **values,
                ticket=_ticket(closure, S.MutationOperation.CREATE_GUEST),
            )
    with pytest.raises(A.AdapterContractError):
        A.TEST_ONLY_translate_lifecycle("admit-guest", closure)


def test_ticket_projection_binds_every_authenticated_ticket_field() -> None:
    closure = _closure()
    ticket = _ticket(closure, S.MutationOperation.CREATE_GUEST, sequence=19)
    create = A.TEST_ONLY_translate_create(closure, ticket)
    assert create.ticket == A.TicketProjection(
        ticket.operation.value, ticket.request_fingerprint_sha256,
        ticket.attempt_id, ticket.before_checkpoint_sha256,
        ticket.sequence, ticket.nonce, S.canonical_sha256(ticket),
    )
    with pytest.raises(A.AdapterContractError):
        replace(
            create,
            ticket=replace(create.ticket, before_checkpoint_sha256=_sha("other")),
        )
    with pytest.raises(A.AdapterContractError):
        replace(create.ticket, ticket_sha256=_sha("other"))


def test_create_projection_tamper_and_alias_fail_closed() -> None:
    closure = _closure()
    create = A.TEST_ONLY_translate_create(
        closure, _ticket(closure, S.MutationOperation.CREATE_GUEST)
    )
    with pytest.raises(A.AdapterContractError):
        replace(create, provider_run_id="psa-forged")
    with pytest.raises(A.AdapterContractError):
        replace(create, arguments=create.arguments[:-1])
    mounts = list(create.provider_mounts)
    mounts[1] = replace(mounts[1], source_handle=mounts[0].source_handle)
    with pytest.raises(A.AdapterContractError):
        replace(create, provider_mounts=tuple(mounts))
    visible = list(create.visible_mounts)
    visible[0] = replace(visible[0], source_handle=visible[1].source_handle)
    with pytest.raises(A.AdapterContractError):
        replace(create, visible_mounts=tuple(visible))


def test_all_ten_visible_authorities_are_unique_and_purpose_bound() -> None:
    closure = _closure()
    create = A.TEST_ONLY_translate_create(
        closure, _ticket(closure, S.MutationOperation.CREATE_GUEST)
    )
    assert len(create.visible_mounts) == 10
    assert len({item.source_handle for item in create.visible_mounts}) == 10
    assert (
        create.visible_mount_authority_sha256
        == closure.visible_mount_authority_sha256
    )

    # Former PoC: credentials and backend-context are not provider mounts, so
    # their alias used to evade the provider-only uniqueness check.
    aliased = list(create.visible_mounts)
    aliased[5] = replace(
        aliased[5], source_handle=aliased[6].source_handle
    )
    with pytest.raises(A.AdapterContractError, match="visible mount authorities alias"):
        replace(create, visible_mounts=tuple(aliased))

    # A unique transplant is also rejected by the closure-bound roster digest.
    transplanted = list(create.visible_mounts)
    left, right = transplanted[5], transplanted[6]
    transplanted[5] = replace(left, source_handle=right.source_handle)
    transplanted[6] = replace(right, source_handle=left.source_handle)
    with pytest.raises(A.AdapterContractError, match="authority binding"):
        replace(create, visible_mounts=tuple(transplanted))
    with pytest.raises(A.AdapterContractError, match="authority binding"):
        replace(create, visible_mount_authority_sha256=_sha("other"))


def test_recomputed_roster_cannot_replace_nonprovider_authority() -> None:
    closure = _closure()
    create = A.TEST_ONLY_translate_create(
        closure, _ticket(closure, S.MutationOperation.CREATE_GUEST)
    )

    def rebound(
        visible: tuple[A.VisibleMountProjection, ...],
    ) -> A.CreateStoppedInput:
        digest = S.canonical_sha256({
            "closure_sha256": create.closure_sha256,
            "schema": A.ADAPTER_SCHEMA + ".visible-mount-authority.v1",
            "mounts": tuple({
                "destination": item.destination, "mode": item.mode,
                "purpose": item.purpose, "source_handle": item.source_handle,
            } for item in visible),
        })
        return replace(
            create, visible_mounts=visible,
            visible_mount_authority_sha256=digest,
        )

    # Rebinding credentials onto project-upper creates an unauthorized sixth
    # provider/visible intersection and is rejected even with a recomputed hash.
    upper = next(
        item.source_handle for item in create.provider_mounts
        if item.purpose == "project-upper"
    )
    rows = list(create.visible_mounts)
    credentials = next(
        index for index, item in enumerate(rows)
        if item.purpose == "credentials"
    )
    rows[credentials] = replace(rows[credentials], source_handle=upper)
    with pytest.raises(A.AdapterContractError, match="intersection"):
        rebound(tuple(rows))

    # A distinct arbitrary opaque handle preserves set cardinalities and can be
    # structurally represented, but exact closure admission rejects it before
    # path resolution or any provider/native call.
    rows = list(create.visible_mounts)
    rows[credentials] = replace(rows[credentials], source_handle=_h(9999))
    arbitrary = rebound(tuple(rows))
    resolutions, profile = _resolutions(create)
    with pytest.raises(A.AdapterContractError, match="authoritative closure"):
        A.TEST_ONLY_resolve_create(
            closure, arbitrary, resolutions, profile
        )

    # A unique purpose transplant likewise cannot pass the authoritative tuple.
    rows = list(create.visible_mounts)
    backend = next(
        index for index, item in enumerate(rows)
        if item.purpose == "backend-context"
    )
    rows[credentials], rows[backend] = (
        replace(rows[credentials], source_handle=rows[backend].source_handle),
        replace(rows[backend], source_handle=rows[credentials].source_handle),
    )
    transplanted = rebound(tuple(rows))
    with pytest.raises(A.AdapterContractError, match="authoritative closure"):
        A.TEST_ONLY_resolve_create(
            closure, transplanted, resolutions, profile
        )


def test_all_lifecycle_inputs_bind_claim_process_extinction_artifacts_and_release() -> None:
    closure, created, admission, launch, started, exited, terminal, census = _created_bundle()
    operations = {
        "inspect-stopped": {"created": created},
        "resume-guest": {"created": created},
        "start-driver": {
            "created": created, "admission": admission, "launch": launch,
            "ticket": _ticket(closure, S.MutationOperation.START_DRIVER),
        },
        "wait-driver": {
            "created": created, "started": started,
            "ticket": _ticket(closure, S.MutationOperation.WAIT_DRIVER),
        },
        "extinguish": {
            "created": created, "exited": exited,
            "ticket": _ticket(closure, S.MutationOperation.EXTINGUISH),
        },
        "census-artifacts": {
            "created": created, "exited": exited, "terminal": terminal,
            "ticket": _ticket(closure, S.MutationOperation.CENSUS_ARTIFACTS),
        },
        "export-artifacts": {
            "census": census,
            "ticket": _ticket(closure, S.MutationOperation.EXPORT_ARTIFACTS),
        },
        "delete-guest": {
            "created": created, "terminal": terminal,
            "ticket": _ticket(closure, S.MutationOperation.DELETE_GUEST),
        },
        "release-attempt": {
            "created": created, "terminal": terminal,
            "ticket": _ticket(closure, S.MutationOperation.DELETE_GUEST),
        },
    }
    translated = {
        name: A.TEST_ONLY_translate_lifecycle(name, closure, **kwargs)
        for name, kwargs in operations.items()
    }
    assert all(
        plan.broker_v2_commitment == closure.broker_v2_commitment
        for plan in translated.values()
    )
    assert translated["start-driver"].expected_process_count == 1
    for name in (
        "extinguish", "census-artifacts", "export-artifacts",
        "delete-guest", "release-attempt",
    ):
        assert translated[name].expected_process_count == 0
        assert translated[name].expected_cgroup_populated == 0
    assert translated["export-artifacts"].artifact_census_sha256 == census.census_sha256
    assert translated["export-artifacts"].export_destination_handle == closure.layout.export_destination_handle
    assert translated["release-attempt"].release_roster == A.PROVIDER_RELEASE_ROSTER
    assert len({item.claim_sha256 for item in translated.values()}) == len(translated)
    with pytest.raises(A.AdapterContractError):
        replace(translated["start-driver"], claim_sha256=_sha("forged"))
    with pytest.raises(A.AdapterContractError):
        replace(translated["wait-driver"], expected_process_count=True)
    with pytest.raises(A.AdapterContractError):
        replace(
            translated["inspect-stopped"],
            broker_v2_commitment=replace(
                closure.broker_v2_commitment,
                provider_provenance_sha256=_sha("other-provenance"),
            ),
        )


def test_lifecycle_optional_fields_have_an_exact_operation_matrix() -> None:
    closure, created, admission, launch, started, exited, terminal, census = _created_bundle()
    values = {
        "inspect-stopped": {"created": created},
        "resume-guest": {"created": created},
        "start-driver": {
            "created": created, "admission": admission, "launch": launch,
            "ticket": _ticket(closure, S.MutationOperation.START_DRIVER),
        },
        "wait-driver": {
            "created": created, "started": started,
            "ticket": _ticket(closure, S.MutationOperation.WAIT_DRIVER),
        },
        "extinguish": {
            "created": created, "exited": exited,
            "ticket": _ticket(closure, S.MutationOperation.EXTINGUISH),
        },
        "census-artifacts": {
            "created": created, "exited": exited, "terminal": terminal,
            "ticket": _ticket(closure, S.MutationOperation.CENSUS_ARTIFACTS),
        },
        "export-artifacts": {
            "census": census,
            "ticket": _ticket(closure, S.MutationOperation.EXPORT_ARTIFACTS),
        },
        "delete-guest": {
            "created": created, "terminal": terminal,
            "ticket": _ticket(closure, S.MutationOperation.DELETE_GUEST),
        },
        "release-attempt": {
            "created": created, "terminal": terminal,
            "ticket": _ticket(closure, S.MutationOperation.DELETE_GUEST),
        },
    }
    translated = {
        operation: A.TEST_ONLY_translate_lifecycle(
            operation, closure, **arguments
        )
        for operation, arguments in values.items()
    }
    relevant = {
        "inspect-stopped": set(),
        "resume-guest": set(),
        "start-driver": {"expected_process_count"},
        "wait-driver": {"expected_process_count"},
        "extinguish": {
            "expected_process_count", "expected_cgroup_populated",
            "expected_exit_code",
        },
        "census-artifacts": {
            "expected_process_count", "expected_cgroup_populated",
            "expected_exit_code",
        },
        "export-artifacts": {
            "expected_process_count", "expected_cgroup_populated",
            "expected_exit_code", "artifact_manifest_sha256",
            "artifact_census_sha256", "export_destination_handle",
        },
        "delete-guest": {
            "expected_process_count", "expected_cgroup_populated",
        },
        "release-attempt": {
            "expected_process_count", "expected_cgroup_populated",
            "release_roster",
        },
    }
    injected = {
        "expected_process_count": 99,
        "expected_cgroup_populated": 1,
        "expected_exit_code": 17,
        "artifact_manifest_sha256": _sha("injected-manifest"),
        "artifact_census_sha256": _sha("injected-census"),
        "export_destination_handle": _h(999),
        "release_roster": A.PROVIDER_RELEASE_ROSTER,
    }
    for operation, plan in translated.items():
        for field, value in injected.items():
            if field not in relevant[operation]:
                with pytest.raises(A.AdapterContractError):
                    replace(plan, **{field: value})

    # Exact reported PoC formerly passed all three ignored inspect controls.
    with pytest.raises(A.AdapterContractError, match="optional field grammar"):
        replace(
            translated["inspect-stopped"], expected_process_count=99,
            expected_cgroup_populated=1, expected_exit_code=17,
        )


def test_relevant_lifecycle_values_are_part_of_the_pre_effect_claim() -> None:
    closure, created, _admission, _launch, _started, exited, terminal, census = _created_bundle()
    extinguish = A.TEST_ONLY_translate_lifecycle(
        "extinguish", closure, created=created, exited=exited,
        ticket=_ticket(closure, S.MutationOperation.EXTINGUISH),
    )
    census_plan = A.TEST_ONLY_translate_lifecycle(
        "census-artifacts", closure, created=created, exited=exited,
        terminal=terminal,
        ticket=_ticket(closure, S.MutationOperation.CENSUS_ARTIFACTS),
    )
    export = A.TEST_ONLY_translate_lifecycle(
        "export-artifacts", closure, census=census,
        ticket=_ticket(closure, S.MutationOperation.EXPORT_ARTIFACTS),
    )
    for plan in (extinguish, census_plan, export):
        changed_exit = 1 if plan.expected_exit_code == 0 else 0
        with pytest.raises(A.AdapterContractError, match="claim changed"):
            replace(plan, expected_exit_code=changed_exit)
    for field, value in (
        ("artifact_manifest_sha256", _sha("other-manifest")),
        ("artifact_census_sha256", _sha("other-census")),
        ("export_destination_handle", _h(9999)),
    ):
        with pytest.raises(A.AdapterContractError, match="claim changed"):
            replace(export, **{field: value})


def test_launch_admission_and_process_count_substitution_fail_closed() -> None:
    closure, created, admission, launch, started, *_ = _created_bundle()
    with pytest.raises(A.AdapterContractError):
        A.TEST_ONLY_translate_lifecycle(
            "start-driver", closure, created=created, admission=admission,
            launch=replace(launch, admission_sha256=_sha("other")),
            ticket=_ticket(closure, S.MutationOperation.START_DRIVER),
        )
    forged = object.__new__(S.DriverStartReceipt)
    for name, value in (
        ("attempt_id", started.attempt_id), ("guest_id", started.guest_id),
        ("launch_sha256", started.launch_sha256),
        ("driver_process_id", started.driver_process_id),
        ("driver_process_count", 2),
    ):
        object.__setattr__(forged, name, value)
    with pytest.raises(A.AdapterContractError):
        A.TEST_ONLY_translate_lifecycle(
            "wait-driver", closure, created=created, started=forged,
            ticket=_ticket(closure, S.MutationOperation.WAIT_DRIVER),
        )


def test_extinction_and_artifact_release_substitution_fail_closed() -> None:
    closure, created, _admission, _launch, _started_receipt, exited, terminal, census = _created_bundle()
    forged = object.__new__(S.ExtinctionReceipt)
    for name, value in (
        ("attempt_id", terminal.attempt_id), ("guest_id", terminal.guest_id),
        ("terminal_sha256", terminal.terminal_sha256),
        ("cgroup_populated", 1), ("process_count", 0),
        ("exact_attempt", True),
    ):
        object.__setattr__(forged, name, value)
    with pytest.raises(A.AdapterContractError):
        A.TEST_ONLY_translate_lifecycle(
            "census-artifacts", closure, created=created, exited=exited,
            terminal=forged,
            ticket=_ticket(closure, S.MutationOperation.CENSUS_ARTIFACTS),
        )
    incomplete = replace(census, dispositions=(census.dispositions[0],))
    with pytest.raises(A.AdapterContractError):
        A.TEST_ONLY_translate_lifecycle(
            "export-artifacts", closure, created=created, exited=exited,
            terminal=terminal, census=incomplete,
            ticket=_ticket(closure, S.MutationOperation.EXPORT_ARTIFACTS),
        )
    with pytest.raises(A.AdapterContractError):
        replace(
            A.TEST_ONLY_translate_lifecycle(
                "release-attempt", closure, created=created, exited=exited,
                terminal=terminal, census=census,
                ticket=_ticket(closure, S.MutationOperation.DELETE_GUEST),
            ),
            release_roster=A.PROVIDER_RELEASE_ROSTER[:-1],
        )


def test_structural_translation_never_calls_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    class Bomb:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise AssertionError("provider called")

    monkeypatch.setattr(P, "PodmanLinuxProvider", Bomb)
    closure = _closure()
    create = A.TEST_ONLY_translate_create(
        closure, _ticket(closure, S.MutationOperation.CREATE_GUEST)
    )
    rows, profile = _resolutions(create)
    assert A.TEST_ONLY_resolve_create(
        closure, create, rows, profile
    ).authority_class == A.TEST_ONLY_AUTHORITY_CLASS


def test_production_hardstop_precedes_consumer_or_provider_access(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []

    class Evil:
        def __getattribute__(self, name: str) -> object:
            events.append(name)
            raise AssertionError("consumer touched")

    monkeypatch.delitem(A.sys.modules, A.NATIVE_MODULE_NAME, raising=False)
    with pytest.raises(A.AdapterUnavailableError):
        A.open_podman_supervisor_adapter(_closure(), Evil())
    assert events == []


def test_production_hardstop_precedes_every_caller_object_touch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class Evil:
        def __getattribute__(self, name: str) -> object:
            events.append(f"get:{name}")
            raise AssertionError("caller object touched")

        def __ne__(self, _other: object) -> bool:
            events.append("ne")
            raise AssertionError("caller comparison reached")

    monkeypatch.delitem(A.sys.modules, A.NATIVE_MODULE_NAME, raising=False)
    with pytest.raises(A.AdapterUnavailableError):
        A.open_podman_supervisor_adapter(Evil(), Evil())
    assert events == []


def test_object_new_wrapper_and_attacker_selected_capability_type_cannot_unlock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closure, created, *_ = _created_bundle()
    events: list[str] = []

    class FakeCapability:
        def begin_call(self, _operation: str) -> object:
            events.append("begin")
            return object()

        def create_stopped(self, *_values: object) -> S.GuestCreatedReceipt:
            events.append("create")
            return created

    forged = object.__new__(A.PodmanSupervisorAdapter)
    with pytest.raises(AttributeError):
        object.__setattr__(forged, "_closure", closure)
    with pytest.raises(AttributeError):
        object.__setattr__(forged, "_capability", FakeCapability())
    monkeypatch.delitem(A.sys.modules, A.NATIVE_MODULE_NAME, raising=False)
    with pytest.raises(A.AdapterUnavailableError):
        forged.provider_kind()
    with pytest.raises(A.AdapterUnavailableError):
        forged.create_stopped(
            closure.create_spec,
            _ticket(closure, S.MutationOperation.CREATE_GUEST),
        )
    assert events == []


def test_every_public_method_native_hardstops_before_wrapper_or_argument_touch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class Evil:
        def __getattribute__(self, name: str) -> object:
            events.append(f"evil:{name}")
            raise AssertionError("attacker property reached")

        def __ne__(self, _other: object) -> bool:
            events.append("evil:ne")
            raise AssertionError("attacker comparison reached")

    forged = object.__new__(A.PodmanSupervisorAdapter)
    evil = Evil()
    calls = (
        lambda: forged.provider_kind(),
        lambda: forged.create_stopped(evil, evil),
        lambda: forged.inspect_stopped(evil),
        lambda: forged.resume_guest(evil, evil),
        lambda: forged.start_driver(evil, evil, evil, evil),
        lambda: forged.wait_driver(evil, evil, evil),
        lambda: forged.extinguish(evil, evil, evil, evil),
        lambda: forged.census(evil, evil, evil, evil, evil),
        lambda: forged.export(evil, evil, evil, evil),
        lambda: forged.delete_guest(evil, evil, evil),
    )
    monkeypatch.delitem(A.sys.modules, A.NATIVE_MODULE_NAME, raising=False)
    for call in calls:
        with pytest.raises(A.AdapterUnavailableError):
            call()
    assert events == []


def test_forged_wrapper_thread_fork_and_reentry_never_reach_python_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    forged = object.__new__(A.PodmanSupervisorAdapter)
    monkeypatch.delitem(A.sys.modules, A.NATIVE_MODULE_NAME, raising=False)

    failures: list[type[BaseException]] = []

    def invoke() -> None:
        try:
            forged.provider_kind()
        except BaseException as error:
            failures.append(type(error))

    threads = tuple(threading.Thread(target=invoke) for _ in range(8))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert failures == [A.AdapterUnavailableError] * len(threads)

    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            forged.provider_kind()
        except A.AdapterUnavailableError:
            os.write(write_fd, b"blocked")
        else:
            os.write(write_fd, b"unlocked")
        os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    child_result = os.read(read_fd, 16)
    os.close(read_fd)
    waited, status = os.waitpid(child, 0)
    assert waited == child and os.waitstatus_to_exitcode(status) == 0
    assert child_result == b"blocked"
    assert events == []


def test_python_module_and_relabelled_heap_types_cannot_unlock_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class FakeConsumer:
        def consume_once(self, *_args: object) -> object:
            events.append("consume")
            return object()

    fake = type("FakeModule", (), {})()
    fake.__spec__ = None
    fake.NativeAuthorityConsumer = FakeConsumer
    fake.GuestDriverAuthorities = type("GuestDriverAuthorities", (), {})
    fake.BackendExecutionAuthority = type("BackendExecutionAuthority", (), {})
    monkeypatch.setitem(A.sys.modules, A.NATIVE_MODULE_NAME, fake)
    with pytest.raises(A.AdapterUnavailableError):
        A.open_podman_supervisor_adapter(_closure(), FakeConsumer())
    assert events == []


def test_extension_shaped_python_module_and_module_replacement_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class FakeConsumer:
        def consume_once(self, *_args: object) -> object:
            events.append("consume")
            return FakeOuterBundle()

    class FakeOuterBundle:
        def consume_once(self) -> tuple[object, ...]:
            events.append("outer-bundle-consume")
            return ()

    class FakeProvider:
        def consume_once(self) -> None:
            events.append("provider-consume")

    class FakeGuestBundle:
        def consume_once(self) -> tuple[object, ...]:
            events.append("guest-bundle-consume")
            return ()

    class FakeBackendExecution:
        def consume_once(self) -> None:
            events.append("backend-consume")

    outer_types = {
        name: type("Fake" + name, (), {"consume_once": lambda self: None})
        for name in A._NATIVE_OUTER_AUTHORITY_TYPE_NAMES
    }
    outer_types["ProviderAuthority"] = FakeProvider
    fake_types = (
        FakeConsumer, FakeOuterBundle, *outer_types.values(),
        FakeGuestBundle, FakeBackendExecution,
    )
    for fake_type in fake_types:
        fake_type.__module__ = A.NATIVE_MODULE_NAME
    origin = "/tmp/" + A.NATIVE_MODULE_NAME + A.importlib.machinery.EXTENSION_SUFFIXES[0]
    loader = A.importlib.machinery.ExtensionFileLoader(A.NATIVE_MODULE_NAME, origin)
    fake = A.types.ModuleType(A.NATIVE_MODULE_NAME)
    fake.__file__ = origin
    fake.__spec__ = A.importlib.machinery.ModuleSpec(
        A.NATIVE_MODULE_NAME, loader, origin=origin,
    )
    fake.TEST_ONLY_BUILD = False
    fake.BROKER_V2_ABI_SCHEMA = A.NATIVE_ABI_SCHEMA
    fake.BROKER_V2_PRODUCTION_ACQUISITION = A.NATIVE_PRODUCTION_ACQUISITION
    fake.BROKER_V2_INITIAL_AUTHORITY_AVAILABLE = True
    fake.NativeAuthorityConsumer = FakeConsumer
    fake.BrokerV2AuthorityConsumer = FakeConsumer
    fake.SupervisorAuthorities = FakeOuterBundle
    for name, fake_type in outer_types.items():
        setattr(fake, name, fake_type)
    fake.GuestDriverAuthorities = FakeGuestBundle
    fake.BackendExecutionAuthority = FakeBackendExecution
    fake.INITIAL_AUTHORITY = FakeConsumer()
    monkeypatch.setitem(A.sys.modules, A.NATIVE_MODULE_NAME, fake)
    with pytest.raises(A.AdapterUnavailableError):
        A.open_podman_supervisor_adapter(_closure(), FakeConsumer())
    assert events == []


@pytest.mark.parametrize(
    "field",
    (
        "module-name", "module-file", "test-build", "availability", "abi",
        "acquisition", "consumer-type", "compat-consumer-type",
        "outer-bundle-type",
        *("outer-type:" + name for name in A._NATIVE_OUTER_AUTHORITY_TYPE_NAMES),
        "guest-bundle-type",
        "backend-execution-type", "initial-authority", "module-spec",
        "spec-name", "spec-origin", "spec-loader", "loader-name", "loader-path",
    ),
)
@pytest.mark.parametrize("hostile_kind", ("object", "str-subclass"))
def test_hostile_extension_metadata_rejects_without_callbacks(
    field: str, hostile_kind: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class Evil:
        def __getattribute__(self, name: str) -> object:
            if name in {"__class__", "__dict__"}:
                return object.__getattribute__(self, name)
            events.append(f"get:{name}")
            raise AssertionError("metadata callback reached")

        def __eq__(self, _other: object) -> bool:
            events.append("eq")
            raise AssertionError("metadata equality reached")

        def __ne__(self, _other: object) -> bool:
            events.append("ne")
            raise AssertionError("metadata inequality reached")

        def __bool__(self) -> bool:
            events.append("bool")
            raise AssertionError("metadata truth test reached")

        def __len__(self) -> int:
            events.append("len")
            raise AssertionError("metadata length reached")

    class EvilStr(str):
        def __eq__(self, _other: object) -> bool:
            events.append("str-eq")
            raise AssertionError("metadata string equality reached")

        def __ne__(self, _other: object) -> bool:
            events.append("str-ne")
            raise AssertionError("metadata string inequality reached")

        def __len__(self) -> int:
            events.append("str-len")
            raise AssertionError("metadata string length reached")

        def endswith(self, *_args: object, **_kwargs: object) -> bool:
            events.append("str-endswith")
            raise AssertionError("metadata suffix check reached")

    class FakeConsumer:
        def consume_once(self, *_args: object) -> object:
            events.append("consume")
            return object()

    class FakeOuterBundle:
        def consume_once(self) -> tuple[object, ...]:
            events.append("outer-bundle-consume")
            return ()

    class FakeProvider:
        def consume_once(self) -> None:
            events.append("provider-consume")

    class FakeGuestBundle:
        def consume_once(self) -> tuple[object, ...]:
            events.append("guest-bundle-consume")
            return ()

    class FakeBackendExecution:
        def consume_once(self) -> None:
            events.append("backend-consume")

    outer_types = {
        name: type("Fake" + name, (), {"consume_once": lambda self: None})
        for name in A._NATIVE_OUTER_AUTHORITY_TYPE_NAMES
    }
    outer_types["ProviderAuthority"] = FakeProvider
    fake_types = (
        FakeConsumer, FakeOuterBundle, *outer_types.values(),
        FakeGuestBundle, FakeBackendExecution,
    )
    for fake_type in fake_types:
        fake_type.__module__ = A.NATIVE_MODULE_NAME
    origin = "/tmp/" + A.NATIVE_MODULE_NAME + A.importlib.machinery.EXTENSION_SUFFIXES[0]
    loader = A.importlib.machinery.ExtensionFileLoader(A.NATIVE_MODULE_NAME, origin)
    spec = A.importlib.machinery.ModuleSpec(
        A.NATIVE_MODULE_NAME, loader, origin=origin,
    )
    fake = A.types.ModuleType(A.NATIVE_MODULE_NAME)
    namespace = vars(fake)
    namespace.update({
        "__file__": origin,
        "__spec__": spec,
        "TEST_ONLY_BUILD": False,
        "BROKER_V2_ABI_SCHEMA": A.NATIVE_ABI_SCHEMA,
        "BROKER_V2_PRODUCTION_ACQUISITION": A.NATIVE_PRODUCTION_ACQUISITION,
        "BROKER_V2_INITIAL_AUTHORITY_AVAILABLE": True,
        "NativeAuthorityConsumer": FakeConsumer,
        "BrokerV2AuthorityConsumer": FakeConsumer,
        "SupervisorAuthorities": FakeOuterBundle,
        **outer_types,
        "GuestDriverAuthorities": FakeGuestBundle,
        "BackendExecutionAuthority": FakeBackendExecution,
        "INITIAL_AUTHORITY": FakeConsumer(),
    })
    evil = Evil() if hostile_kind == "object" else EvilStr("attacker")
    targets = {
        "module-name": (namespace, "__name__"),
        "module-file": (namespace, "__file__"),
        "test-build": (namespace, "TEST_ONLY_BUILD"),
        "availability": (namespace, "BROKER_V2_INITIAL_AUTHORITY_AVAILABLE"),
        "abi": (namespace, "BROKER_V2_ABI_SCHEMA"),
        "acquisition": (namespace, "BROKER_V2_PRODUCTION_ACQUISITION"),
        "consumer-type": (namespace, "NativeAuthorityConsumer"),
        "compat-consumer-type": (namespace, "BrokerV2AuthorityConsumer"),
        "outer-bundle-type": (namespace, "SupervisorAuthorities"),
        "guest-bundle-type": (namespace, "GuestDriverAuthorities"),
        "backend-execution-type": (namespace, "BackendExecutionAuthority"),
        "initial-authority": (namespace, "INITIAL_AUTHORITY"),
        "module-spec": (namespace, "__spec__"),
        "spec-name": (vars(spec), "name"),
        "spec-origin": (vars(spec), "origin"),
        "spec-loader": (vars(spec), "loader"),
        "loader-name": (vars(loader), "name"),
        "loader-path": (vars(loader), "path"),
    }
    targets.update({
        "outer-type:" + name: (namespace, name)
        for name in A._NATIVE_OUTER_AUTHORITY_TYPE_NAMES
    })
    target, key = targets[field]
    target[key] = evil
    monkeypatch.setitem(A.sys.modules, A.NATIVE_MODULE_NAME, fake)
    with pytest.raises(A.AdapterUnavailableError):
        A.open_podman_supervisor_adapter(_closure(), FakeConsumer())
    assert events == []


def test_authenticated_role2_surface_still_cannot_unlock_outer_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    def authenticated_role2() -> tuple[type[object], ...]:
        events.append("authenticated-role2")
        return (object,)

    monkeypatch.setattr(A, "_native_types", authenticated_role2)
    forged = object.__new__(A.PodmanSupervisorAdapter)
    with pytest.raises(A.AdapterUnavailableError):
        forged.create_stopped(object(), object())
    with pytest.raises(A.AdapterUnavailableError):
        A.open_podman_supervisor_adapter(object(), object())
    assert events == ["authenticated-role2", "authenticated-role2"]


def test_source_has_no_python_authority_or_receipt_registry() -> None:
    source = Path(A.__file__).read_text()
    assert A._NATIVE_OUTER_AUTHORITY_TYPE_NAMES == (
        "RuntimeImageAuthority", "WorkspaceAuthority",
        "BackendContextAuthority", "ProviderAuthority",
        "GuestAdmissionAuthority", "ExtinctionAuthority",
        "ArtifactAuthority", "ExportAuthority", "JournalAuthority",
        "RecoveryAuthority",
    )
    assert "_REGISTRY" not in source
    assert "weakref" not in source
    assert "P.verify_receipt" not in source
    assert "P.ProviderReceipt" not in source
    assert "subprocess" not in source
    assert "begin_call" not in source
    assert "abort_call" not in source
    assert "_capability_type" not in source
    assert A.NATIVE_MODULE_NAME == "_plamen_native_supervisor"
    assert A.NATIVE_ABI_SCHEMA in source
    assert "PodmanSupervisorAdapterCapability" not in source
    assert "PodmanSupervisorCallCapability" not in source
    assert "GuestDriverAuthorities" in source
    assert "BackendExecutionAuthority" in source
    assert all(not name.startswith("TEST_ONLY") for name in A.__all__)
