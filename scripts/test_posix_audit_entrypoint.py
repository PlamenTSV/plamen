"""Focused gates for the fixed POSIX outer-supervisor entrypoint."""

from __future__ import annotations

import ast
import base64
from dataclasses import fields
import hashlib
import importlib.machinery
import json
from pathlib import Path
from typing import Any

import pytest

import posix_audit_entrypoint as E
import posix_audit_supervisor as S


def _digest(character: str) -> str:
    return character * 64


def _request() -> S.AuditRequest:
    config = S._canonical_bytes({
        "_run_id": "run-outer-001",
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
    source = S.AuthenticatedDriverConfig(
        retained_source_handle="opaque:" + _digest("a"),
        canonical_bytes=config,
        sha256=hashlib.sha256(config).hexdigest(),
    )
    return S.AuditRequest(
        request_type=S.RequestType.START_CONFIG,
        request_id="request-outer-001",
        attempt_id="attempt-outer-001",
        run_id="run-outer-001",
        pipeline="sc",
        mode="core",
        backend="codex",
        language="evm",
        source_config=source,
        source_config_sha256=source.sha256,
        startup_decision_receipt_sha256=_digest("1"),
        target_identity_sha256=_digest("2"),
        runtime_layout_sha256=_digest("3"),
        image_manifest_digest="sha256:" + _digest("4"),
        image_closure_sha256=_digest("5"),
        docs_sha256=_digest("6"),
        scope_sha256=_digest("7"),
        seccomp_profile_sha256=_digest("8"),
        credential_bundle_sha256=_digest("9"),
        credential_isolation_sha256=_digest("a"),
        backend_context_sha256=_digest("b"),
        backend_admission_sha256=_digest("c"),
        egress_policy_sha256=_digest("d"),
        egress_admission_sha256=_digest("e"),
        provider_provenance_sha256=_digest("f"),
        export_allowlist=(
            "project/AUDIT_REPORT.md",
            "scratch/_plamen.log",
            "scratch/_v2_checkpoint.json",
        ),
        required_artifacts=(
            "project/AUDIT_REPORT.md",
            "scratch/_v2_checkpoint.json",
        ),
        failure_required_artifacts=("scratch/_plamen.log",),
        export_destination_identity_sha256=_digest("0"),
    )


def _projection_value(request: S.AuditRequest) -> dict[str, Any]:
    audit: dict[str, Any] = {}
    for field in fields(request):
        value = getattr(request, field.name)
        if field.name == "source_config":
            value = {
                "authenticated": True,
                "canonical_utf8_b64": base64.b64encode(
                    request.source_config.canonical_bytes
                ).decode("ascii"),
                "retained_source_handle": (
                    request.source_config.retained_source_handle
                ),
                "sha256": request.source_config.sha256,
            }
        elif field.name == "request_type":
            value = value.value
        elif type(value) is tuple:
            value = list(value)
        audit[field.name] = value
    return {
        "audit_request": audit,
        "projection_schema": E._PROJECTION_SCHEMA,
    }


def _projection_bytes(request: S.AuditRequest | None = None) -> bytes:
    value = _projection_value(request or _request())
    rendered = S._canonical_bytes(value)
    assert rendered.endswith(b"\n")
    return rendered[:-1]


def _result(request: S.AuditRequest, exit_code: int = 0) -> S.SupervisorResult:
    return S.SupervisorResult(
        request.request_id,
        request.attempt_id,
        request.run_id,
        S.ProviderKind.APPLE_CONTAINER,
        _digest("1"),
        _digest("2"),
        3,
        1024,
        exit_code,
        S.SupervisorCompletionStatus.SUCCEEDED
        if exit_code == 0 else S.SupervisorCompletionStatus.DRIVER_FAILED,
        True,
        True,
        True,
    )


def _canonical(value: dict[str, Any]) -> bytes:
    return S._canonical_bytes(value)[:-1]


def test_valid_projection_decodes_to_exact_typed_request() -> None:
    expected = _request()
    actual = E._decode_request_projection(_projection_bytes(expected), S)

    assert type(actual) is S.AuditRequest
    assert actual == expected
    assert actual.fingerprint_sha256 == expected.fingerprint_sha256
    assert actual.source_config.canonical_bytes.endswith(b"\n")


def test_projection_decoder_rejects_noncanonical_and_incomplete_values() -> None:
    valid = _projection_value(_request())
    candidates: list[bytes] = []

    candidates.append(_canonical(valid) + b"\n")
    candidates.append(b" " + _canonical(valid))
    candidates.append(_canonical({**valid, "unknown": True}))
    candidates.append(_canonical({"audit_request": valid["audit_request"]}))

    wrong_schema = json.loads(json.dumps(valid))
    wrong_schema["projection_schema"] = "plamen.native_audit_request_projection.v0"
    candidates.append(_canonical(wrong_schema))

    missing_field = json.loads(json.dumps(valid))
    del missing_field["audit_request"]["docs_sha256"]
    candidates.append(_canonical(missing_field))

    wrong_source_keys = json.loads(json.dumps(valid))
    wrong_source_keys["audit_request"]["source_config"]["extra"] = True
    candidates.append(_canonical(wrong_source_keys))

    unauthenticated = json.loads(json.dumps(valid))
    unauthenticated["audit_request"]["source_config"]["authenticated"] = False
    candidates.append(_canonical(unauthenticated))

    invalid_base64 = json.loads(json.dumps(valid))
    invalid_base64["audit_request"]["source_config"]["canonical_utf8_b64"] = "%%%="
    candidates.append(_canonical(invalid_base64))

    mismatched_config = json.loads(json.dumps(valid))
    mismatched_config["audit_request"]["source_config"]["sha256"] = _digest("0")
    candidates.append(_canonical(mismatched_config))

    wrong_roster = json.loads(json.dumps(valid))
    wrong_roster["audit_request"]["export_allowlist"] = "project/AUDIT_REPORT.md"
    candidates.append(_canonical(wrong_roster))

    floating_bound = json.loads(json.dumps(valid))
    floating_bound["audit_request"]["export_max_total_bytes"] = 1.0
    candidates.append(
        json.dumps(
            floating_bound, ensure_ascii=True, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("ascii")
    )

    unicode_escape = json.loads(json.dumps(valid))
    unicode_escape["audit_request"]["language"] = "\N{LATIN SMALL LETTER E WITH ACUTE}"
    candidates.append(_canonical(unicode_escape))

    duplicate = _canonical(valid).replace(
        b'"attempt_id":"attempt-outer-001"',
        b'"attempt_id":"shadow","attempt_id":"attempt-outer-001"',
        1,
    )
    candidates.append(duplicate)

    for candidate in candidates:
        with pytest.raises(S.SupervisorError):
            E._decode_request_projection(candidate, S)


def test_request_projection_is_observed_before_authority_consumption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    projection = _projection_bytes()

    class Initial:
        def request_projection(self) -> bytes:
            events.append("request_projection")
            return projection

        def consume_once(self, fingerprint: str, attempt: str) -> object:
            events.append(f"consume:{fingerprint}:{attempt}")
            return object()

    initial = Initial()

    def load() -> tuple[Any, object]:
        events.append("load")
        return S, initial

    def supervise(request: S.AuditRequest, consumer: object) -> S.SupervisorResult:
        events.append("supervise")
        assert consumer is initial
        consumer.consume_once(request.fingerprint_sha256, request.attempt_id)  # type: ignore[attr-defined]
        return _result(request)

    monkeypatch.setattr(E, "_load_runtime_surface", load)
    monkeypatch.setattr(S, "supervise_audit", supervise)

    assert E._run() == 0
    assert events[:3] == ["load", "request_projection", "supervise"]
    decoded = E._decode_request_projection(projection, S)
    assert events[3] == (
        f"consume:{decoded.fingerprint_sha256}:{decoded.attempt_id}"
    )
    assert len(decoded.fingerprint_sha256) == 64
    assert decoded.fingerprint_sha256 == decoded.fingerprint_sha256.lower()


def test_projection_failure_never_reaches_consume_or_supervision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class Initial:
        def request_projection(self) -> bytes:
            events.append("request_projection")
            return b"{}"

        def consume_once(self, *_args: object) -> object:
            events.append("consume")
            return object()

    monkeypatch.setattr(E, "_load_runtime_surface", lambda: (S, Initial()))
    monkeypatch.setattr(
        S, "supervise_audit",
        lambda *_args: events.append("supervise"),
    )

    with pytest.raises(S.SupervisorError):
        E._run()
    assert events == ["request_projection"]


def test_main_has_one_bounded_failure_and_propagates_terminal_driver_status(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    class Fatal(BaseException):
        pass

    monkeypatch.setattr(E, "_run", lambda: (_ for _ in ()).throw(Fatal("secret")))
    assert E.main() == E.EXIT_FAIL_CLOSED == 75
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == E.FAIL_CLOSED_DIAGNOSTIC
    assert "secret" not in captured.err

    monkeypatch.setattr(E, "_run", lambda: 23)
    assert E.main() == 23
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_fixed_layout_derivation_selects_no_searchable_or_ambient_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = "/private/var/plamen/generations/" + _digest("a")
    monkeypatch.setattr(
        E, "__file__", root + "/lib/plamen/runtime/scripts/posix_audit_entrypoint.py",
    )
    supervisor, adapter, native = E._fixed_install_paths()
    assert supervisor == root + "/lib/plamen/runtime/scripts/posix_audit_supervisor.py"
    assert adapter == (
        root + "/lib/plamen/runtime/scripts/posix_native_authority_adapter.py"
    )
    assert native == (
        root + "/lib/plamen/_plamen_native_supervisor"
        + importlib.machinery.EXTENSION_SUFFIXES[0]
    )

    monkeypatch.setattr(E, "__file__", "/tmp/posix_audit_entrypoint.py")
    with pytest.raises(RuntimeError):
        E._fixed_install_paths()


def test_entrypoint_has_no_argv_environment_or_process_launch_authority() -> None:
    source_path = Path(E.__file__)
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    assert "sys.argv" not in source
    assert "os.environ" not in source
    assert "getenv(" not in source
    assert not any(
        isinstance(node, (ast.Import, ast.ImportFrom))
        and any(alias.name in {"os", "subprocess"} for alias in node.names)
        for node in ast.walk(tree)
    )
    assert "request_projection()" in source
    assert "supervise_audit(request, initial)" in source
