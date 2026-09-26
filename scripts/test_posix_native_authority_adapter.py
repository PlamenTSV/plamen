"""Focused tests for the role-1 native authority representation bridge."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from typing import Any

import pytest

import posix_audit_supervisor as S
import posix_native_authority_adapter as A


def _d(character: str) -> str:
    return character * 64


def _h(index: int) -> str:
    return "opaque:" + f"{index:064x}"


def _request(*, request_id: str = "request-001") -> S.AuditRequest:
    document = {
        "_run_id": "run-001",
        "cli_backend": "codex",
        "docs_inputs": ["/workspace/docs/design.md"],
        "docs_path": "/workspace/docs",
        "language": "evm",
        "mode": "core",
        "pipeline": "sc",
        "project_root": "/workspace/project",
        "scope_file": "/workspace/scope",
        "scratchpad": "/workspace/scratch",
    }
    config = S._canonical_bytes(document)
    source = S.AuthenticatedDriverConfig(
        _h(90), config, hashlib.sha256(config).hexdigest()
    )
    return S.AuditRequest(
        request_type=S.RequestType.SC_NEW,
        request_id=request_id,
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
            "project/AUDIT_REPORT.md",
            "scratch/_plamen.log",
            "scratch/_v2_checkpoint.json",
        ),
        required_artifacts=(
            "project/AUDIT_REPORT.md", "scratch/_v2_checkpoint.json",
        ),
        failure_required_artifacts=("scratch/_plamen.log",),
        export_destination_identity_sha256=_d("c"),
    )


def _recensus(
    request: S.AuditRequest, layout: S.AttemptLayout, target: S.TargetLease,
    backend: S.BackendContext, runtime: S.AuthenticatedRuntimeImageLayout,
    configured: S.ConfigReceipt, phase: str,
) -> S.LayoutRecensus:
    roster = (
        ("target-lower", target.target_handle, "HOST_OVERLAY_LOWER", "ro", target.content_sha256),
        ("project-merged", layout.merged_handle, "/workspace/project", "rw", _d("1")),
        ("scratch", layout.scratch_handle, "/workspace/scratch", "rw", _d("2")),
        ("state", layout.state_handle, "/workspace/state", "rw", _d("3")),
        ("control", layout.control_handle, "/workspace/control", "ro", _d("4")),
        ("seccomp", layout.seccomp_handle, "/run/plamen/seccomp", "ro", layout.seccomp_sha256),
        ("credentials", backend.credential_handle, "/run/plamen/credentials", "ro", backend.credential_sha256),
        ("backend-context", backend.context_handle, "/run/plamen/backend", "ro", backend.context_sha256),
        ("runtime", runtime.runtime_handle, "/opt/plamen", "ro", runtime.runtime_layout_sha256),
        ("docs", runtime.docs_handle, "/workspace/docs", "ro", runtime.docs_sha256),
        ("scope", layout.scope_handle, "/workspace/scope", "ro", layout.scope_sha256),
    )
    components = tuple(
        S.LayoutComponent(
            purpose, handle, attachment, mode,
            hashlib.sha256(f"identity:{index}".encode()).hexdigest(),
            content,
            hashlib.sha256(f"mount:{phase}:{index}".encode()).hexdigest(),
        )
        for index, (purpose, handle, attachment, mode, content) in enumerate(roster)
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


def _values() -> dict[str, Any]:
    request = _request()
    runtime = S.AuthenticatedRuntimeImageLayout(
        request.runtime_layout_sha256, request.image_manifest_digest,
        request.image_closure_sha256, request.docs_sha256,
        _h(30), _h(31), _h(32),
    )
    target = S.TargetLease(
        _h(1), request.target_identity_sha256, _d("a"), True, True, True
    )
    target_recensus = S.TargetRecensus(
        target.target_handle, target.identity_sha256, target.content_sha256,
        True, True,
    )
    backend = S.BackendContext(
        request.backend, request.backend_context_sha256,
        request.backend_admission_sha256, request.egress_policy_sha256,
        request.egress_admission_sha256, request.credential_bundle_sha256,
        request.credential_isolation_sha256, _h(40), _h(41),
    )
    empty = S.SupervisorCheckpoint(
        request.fingerprint_sha256, request.attempt_id, request.run_id
    )
    ticket = S.MutationTicket(
        S.MutationOperation.PREPARE_LAYOUT, request.fingerprint_sha256,
        request.attempt_id, empty.checkpoint_sha256, 1, _d("b"),
    )
    layout = S.AttemptLayout(
        request.attempt_id, request.run_id,
        *(_h(index) for index in range(2, 12)),
        request.target_identity_sha256, request.scope_sha256,
        request.seccomp_profile_sha256, _h(13),
        request.export_destination_identity_sha256,
    )
    guest_config = S.GuestConfig(
        request.source_config.retained_source_handle,
        request.source_config.canonical_bytes,
        request.source_config.sha256,
    )
    configured = S.ConfigReceipt(
        request.attempt_id, request.run_id, _h(14), guest_config.config_sha256,
        request.source_config_sha256,
        request.startup_decision_receipt_sha256, guest_config,
    )
    precreate = _recensus(
        request, layout, target, backend, runtime, configured, "PRE_CREATE"
    )
    postcreate = _recensus(
        request, layout, target, backend, runtime, configured, "POST_CREATE"
    )
    mounts = tuple(
        S.GuestMount(purpose, handle, destination, mode)
        for (purpose, destination, mode), handle in zip(
            S._APPLE_CONTAINER_MOUNT_POLICY,
            (
                layout.merged_handle, layout.scratch_handle,
                layout.state_handle, layout.control_handle,
                layout.seccomp_handle, backend.credential_handle,
                backend.context_handle, runtime.runtime_handle,
                runtime.docs_handle, layout.scope_handle,
            ),
            strict=True,
        )
    )
    spec = S.GuestCreateSpec(
        request.attempt_id, request.image_manifest_digest,
        runtime.image_handle, request.image_closure_sha256,
        configured.config_sha256, precreate, request.egress_policy_sha256,
        request.egress_admission_sha256, request.backend_admission_sha256,
        request.credential_isolation_sha256,
        request.provider_provenance_sha256, mounts,
        f"plamen-{request.attempt_id}",
        provider_kind=S.ProviderKind.APPLE_CONTAINER,
    )
    created = S.GuestCreatedReceipt(
        S.ProviderKind.APPLE_CONTAINER, request.attempt_id, "guest-001", spec,
        S.canonical_sha256(mounts), postcreate.provider_mounts_sha256,
    )
    observation = S.GuestObservation(
        created.provider_kind, created.guest_id, created.spec_sha256,
        created.mount_roster_sha256, created.provider_mounts_sha256,
    )
    admission = S.GuestAdmissionReceipt(
        request.attempt_id, created.guest_id, _h(60), _d("4"),
        precreate, postcreate, _d("5"), created.spec_sha256,
    )
    launch = S.DriverLaunch(
        request.attempt_id, created.guest_id, admission.admission_sha256,
        (
            runtime.python_path, "-B", runtime.driver_path,
            "/workspace/control/config.json", "--startup-intent",
            request.startup_intent, "--unattended", "--no-sleep",
            "--startup-decision-receipt",
            "/workspace/control/startup-decision.json",
        ),
    )
    started = S.DriverStartReceipt(
        request.attempt_id, created.guest_id, launch.launch_sha256,
        "driver-001",
    )
    exited = S.DriverExitReceipt(
        request.attempt_id, created.guest_id, started.launch_sha256, 0, _d("6")
    )
    terminal = S.ExtinctionReceipt(
        request.attempt_id, created.guest_id, _d("7")
    )
    entries = (
        S.ArtifactEntry("project/AUDIT_REPORT.md", 10, _d("8")),
        S.ArtifactEntry("scratch/_v2_checkpoint.json", 12, _d("9")),
    )
    dispositions = tuple(
        S.ArtifactDisposition(row.relative_path, "PRESENT", row.sha256)
        for row in entries
    )
    census_base = {
        "attempt_id": request.attempt_id,
        "run_id": request.run_id,
        "terminal_sha256": terminal.terminal_sha256,
        "driver_exit_code": exited.exit_code,
        "census_handle": _h(61),
        "entries": entries,
        "dispositions": dispositions,
    }
    census = S.ArtifactCensus(
        request.attempt_id, request.run_id, terminal.terminal_sha256,
        exited.exit_code, census_base["census_handle"], entries, dispositions,
        S.canonical_sha256(census_base),
    )
    exported = S.ExportReceipt(
        request.attempt_id, request.run_id, census.census_sha256,
        layout.export_destination_handle,
        request.export_destination_identity_sha256, len(entries),
        sum(row.size for row in entries), _d("c"), _d("d"),
    )
    deleted = S.DeleteReceipt(
        created.provider_kind, request.attempt_id, created.guest_id,
        terminal.terminal_sha256,
    )
    open_receipt = S.JournalOpenReceipt(S.JournalOpenStatus.READY, empty)
    recovery = S.RecoveryResolution(
        S.RecoveryStatus.NOT_APPLIED, ticket, empty, _d("e")
    )
    return locals()


_RESULT_NAMES = {
    ("runtime", "authenticate"): "runtime",
    ("workspace", "admit_target"): "target",
    ("workspace", "revalidate_target"): "target_recensus",
    ("workspace", "prepare_layout"): "layout",
    ("workspace", "resume_layout"): "layout",
    ("workspace", "write_guest_config"): "configured",
    ("workspace", "recensus_layout"): "precreate",
    ("backend", "authenticate"): "backend",
    ("provider", "provider_kind"): "provider_kind",
    ("provider", "create_stopped"): "created",
    ("provider", "inspect_stopped"): "observation",
    ("provider", "resume_guest"): "created",
    ("provider", "start_driver"): "started",
    ("provider", "wait_driver"): "exited",
    ("provider", "delete_guest"): "deleted",
    ("guest_admission", "admit_stopped_guest"): "admission",
    ("guest_admission", "resume_admission"): "admission",
    ("extinction", "extinguish"): "terminal",
    ("artifacts", "census"): "census",
    ("exporter", "export"): "exported",
    ("journal", "open"): "open_receipt",
    ("journal", "arm"): "ticket",
    ("journal", "commit"): "truth",
    ("journal", "resolve"): "truth",
    ("journal", "finish"): "truth",
    ("recovery", "recover"): "recovery",
}


def _response(call: bytes, result: object) -> bytes:
    request = json.loads(call)
    return A._json_bytes({
        "call_sha256": hashlib.sha256(call).hexdigest(),
        "member": request["member"],
        "operation": request["operation"],
        "request_fingerprint_sha256": request["request_fingerprint_sha256"],
        "result": A._wire_value(result),
        "result_commitment_sha256": S.canonical_sha256(result),
        "schema": A.RESPONSE_SCHEMA,
    })


class _Native:
    def __init__(self, values: dict[str, Any], calls: list[bytes]) -> None:
        self.values = values
        self.calls = calls
        self.rewrite = None

    def __getattr__(self, operation: str):
        def invoke(call: bytes) -> bytes:
            assert type(call) is bytes
            self.calls.append(call)
            document = json.loads(call)
            key = (document["member"], operation)
            result_name = _RESULT_NAMES[key]
            result = (
                S.ProviderKind.APPLE_CONTAINER
                if result_name == "provider_kind"
                else True if result_name == "truth"
                else self.values[result_name]
            )
            response = _response(call, result)
            return self.rewrite(response) if self.rewrite is not None else response

        return invoke


def _authorities(values: dict[str, Any], calls: list[bytes]):
    natives = tuple(_Native(values, calls) for _ in range(10))
    native_types = tuple(type(value) for value in natives)
    return (
        A.adapt_native_supervisor_authorities(
            values["request"], natives, native_types
        ),
        natives,
    )


def test_all_role1_methods_use_one_canonical_bound_bytes_call() -> None:
    v = _values()
    calls: list[bytes] = []
    authorities, _natives = _authorities(v, calls)

    assert authorities.runtime.authenticate(v["request"]) == v["runtime"]
    assert authorities.workspace.admit_target(v["request"]) == v["target"]
    assert authorities.workspace.revalidate_target(v["request"], v["target"]) == v["target_recensus"]
    assert authorities.workspace.prepare_layout(v["request"], v["target"], v["ticket"]) == v["layout"]
    assert authorities.workspace.resume_layout(v["request"], v["layout"]) == v["layout"]
    assert authorities.workspace.write_guest_config(v["request"], v["layout"], v["guest_config"], v["ticket"]) == v["configured"]
    assert authorities.workspace.recensus_layout(v["request"], v["target"], v["layout"], v["runtime"], v["backend"], v["configured"], "PRE_CREATE") == v["precreate"]
    assert authorities.backend.authenticate(v["request"]) == v["backend"]
    assert authorities.provider.provider_kind() is S.ProviderKind.APPLE_CONTAINER
    assert authorities.provider.create_stopped(v["spec"], v["ticket"]) == v["created"]
    assert authorities.provider.inspect_stopped(v["created"]) == v["observation"]
    assert authorities.provider.resume_guest(v["request"], v["created"]) == v["created"]
    assert authorities.provider.start_driver(v["created"], v["admission"], v["launch"], v["ticket"]) == v["started"]
    assert authorities.provider.wait_driver(v["created"], v["started"], v["ticket"]) == v["exited"]
    assert authorities.provider.delete_guest(v["created"], v["terminal"], v["ticket"]) == v["deleted"]
    assert authorities.guest_admission.admit_stopped_guest(v["request"], v["created"], v["observation"], v["postcreate"], v["ticket"]) == v["admission"]
    assert authorities.guest_admission.resume_admission(v["request"], v["created"], v["admission"]) == v["admission"]
    assert authorities.extinction.extinguish(v["request"], v["created"], v["exited"], v["ticket"]) == v["terminal"]
    assert authorities.artifacts.census(v["request"], v["layout"], v["exited"], v["terminal"], v["ticket"]) == v["census"]
    assert authorities.exporter.export(v["request"], v["layout"], v["census"], v["ticket"]) == v["exported"]
    assert authorities.journal.open(v["request"]) == v["open_receipt"]
    assert authorities.journal.arm(v["request"], S.MutationOperation.PREPARE_LAYOUT, v["empty"].checkpoint_sha256) == v["ticket"]
    assert authorities.journal.commit(v["request"], v["ticket"], v["empty"]) is True
    assert authorities.journal.resolve(v["request"], v["ticket"], v["empty"]) is True
    assert authorities.journal.finish(v["request"], v["empty"].checkpoint_sha256) is True
    assert authorities.recovery.recover(v["request"], v["ticket"], v["empty"]) == v["recovery"]

    seen = set()
    for call in calls:
        assert len(call) <= A.MAX_CALL_BYTES
        document = json.loads(call)
        assert call == A._json_bytes(document)
        assert set(document) == {
            "arguments", "member", "operation", "receipt_commitments",
            "request_commitment_sha256", "request_fingerprint_sha256",
            "schema",
        }
        assert document["schema"] == A.CALL_SCHEMA
        assert document["request_fingerprint_sha256"] == v["request"].fingerprint_sha256
        assert document["request_commitment_sha256"] == S.canonical_sha256(v["request"])
        seen.add((document["member"], document["operation"]))
    assert seen == set(A._OPERATIONS)


def test_call_carries_commitments_not_reflected_receipt_data() -> None:
    v = _values()
    calls: list[bytes] = []
    authorities, _natives = _authorities(v, calls)
    authorities.workspace.revalidate_target(v["request"], v["target"])
    document = json.loads(calls[-1])
    target = document["arguments"][1]
    assert target == {
        "commitment_sha256": S.canonical_sha256(v["target"]),
        "name": "target",
        "type": "TargetLease",
    }
    assert document["receipt_commitments"] == [{
        "name": "target",
        "sha256": S.canonical_sha256(v["target"]),
        "type": "TargetLease",
    }]
    assert v["target"].target_handle.encode() not in calls[-1]


def test_request_binding_and_exact_argument_types_fail_before_native_call() -> None:
    v = _values()
    calls: list[bytes] = []
    authorities, _natives = _authorities(v, calls)
    with pytest.raises(A.NativeAuthorityAdapterError, match="different request"):
        authorities.runtime.authenticate(_request(request_id="request-002"))
    with pytest.raises(A.NativeAuthorityAdapterError, match="argument type"):
        authorities.workspace.recensus_layout(
            v["request"], v["target"], v["layout"], v["runtime"],
            v["backend"], v["configured"], 1,
        )
    assert calls == []


@pytest.mark.parametrize(
    "rewrite",
    [
        lambda raw: raw[:-1],
        lambda raw: b" " + raw,
        lambda raw: raw.replace(b'"schema":', b'"extra":1,"schema":', 1),
        lambda raw: A._json_bytes({
            key: value for key, value in json.loads(raw).items()
            if key != "result"
        }),
        lambda raw: raw.replace(b'"call_sha256":', b'"call_sha256":"x","call_sha256":', 1),
        lambda raw: raw.replace(A.RESPONSE_SCHEMA.encode(), b"wrong.schema", 1),
        lambda raw: raw.replace(b'"member":"runtime"', b'"member":"backend"', 1),
        lambda raw: raw.replace(b'"operation":"authenticate"', b'"operation":"open"', 1),
        lambda raw: raw.replace(b'"request_fingerprint_sha256":"', b'"request_fingerprint_sha256":"0', 1),
        lambda raw: raw.replace(b'"result_commitment_sha256":"', b'"result_commitment_sha256":"0', 1),
        lambda raw: bytearray(raw),
    ],
)
def test_noncanonical_extra_duplicate_and_commitment_responses_fail_closed(rewrite) -> None:
    v = _values()
    calls: list[bytes] = []
    authorities, natives = _authorities(v, calls)
    natives[0].rewrite = rewrite
    with pytest.raises(A.NativeAuthorityAdapterError):
        authorities.runtime.authenticate(v["request"])


@pytest.mark.parametrize(
    "mutate",
    [
        lambda result: {**result, "unexpected": 1},
        lambda result: {key: value for key, value in result.items() if key != "fields"},
        lambda result: {**result, "$type": "TargetLease"},
        lambda result: {**result, "fields": {**result["fields"], "immutable": False}},
        lambda result: {**result, "fields": {key: value for key, value in result["fields"].items() if key != "docs_sha256"}},
    ],
)
def test_typed_result_extra_missing_wrong_type_and_semantics_fail_closed(mutate) -> None:
    v = _values()
    call = A._build_call(A._Binding(v["request"]), "runtime", "authenticate", (v["request"],))
    document = json.loads(_response(call, v["runtime"]))
    document["result"] = mutate(document["result"])
    # Recommit the hostile representation where possible: the decoder must
    # reject shape/type/semantics independently of the outer digest.
    raw = A._json_bytes(document)
    with pytest.raises(A.NativeAuthorityAdapterError):
        A._decode_response(raw, A._Binding(v["request"]), "runtime", "authenticate", call)


def test_wrong_top_level_result_type_and_native_failure_are_bounded() -> None:
    v = _values()
    calls: list[bytes] = []
    authorities, natives = _authorities(v, calls)
    natives[0].rewrite = lambda raw: _response(calls[-1], v["target"])
    with pytest.raises(A.NativeAuthorityAdapterError, match="response type"):
        authorities.runtime.authenticate(v["request"])

    def fail(_raw: bytes) -> bytes:
        raise RuntimeError("/secret/path provider diagnostic")

    natives[0].authenticate = fail
    with pytest.raises(A.NativeAuthorityAdapterError) as raised:
        authorities.runtime.authenticate(v["request"])
    assert "/secret" not in str(raised.value)


def test_roster_requires_ten_exact_non_subclassed_native_types() -> None:
    v = _values()
    calls: list[bytes] = []
    native = _Native(v, calls)
    with pytest.raises(A.NativeAuthorityAdapterError, match="roster"):
        A.adapt_native_supervisor_authorities(
            v["request"], (native,) * 9, (type(native),) * 9
        )

    class Child(_Native):
        pass

    members = (Child(v, calls),) + (native,) * 9
    with pytest.raises(A.NativeAuthorityAdapterError, match="roster"):
        A.adapt_native_supervisor_authorities(
            v["request"], members, (type(native),) * 10
        )


def test_response_bound_and_unsupported_json_forms_fail_closed() -> None:
    with pytest.raises(A.NativeAuthorityAdapterError, match="bounded bytes"):
        A._parse_json_bytes(b"x" * (A.MAX_RESPONSE_BYTES + 1))
    with pytest.raises(A.NativeAuthorityAdapterError, match="canonical"):
        A._parse_json_bytes(b'{"x":1.5}\n')
    with pytest.raises(A.NativeAuthorityAdapterError, match="canonical"):
        A._parse_json_bytes(b'{"x":NaN}\n')
    with pytest.raises(A.NativeAuthorityAdapterError):
        A._decode_wire_value({"$bytes_hex": "AA"})
