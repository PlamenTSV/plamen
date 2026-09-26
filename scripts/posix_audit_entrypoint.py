"""Fixed outer-supervisor entrypoint for an authenticated POSIX audit.

The native launcher executes this file with an empty environment under
``python3.12 -I -B``.  Consequently the installed runtime modules are loaded
from their receipt-bound generation paths, not from ``sys.path``.  The only
audit request accepted here is the projection exposed by the pre-issued native
``INITIAL_AUTHORITY``; command-line arguments and environment variables are
neither parsed nor consulted.
"""

from __future__ import annotations

import base64
import binascii
import importlib.machinery
import importlib.util
import sys
import types
from typing import Any
import unicodedata


EXIT_OK = 0
EXIT_FAIL_CLOSED = 75
FAIL_CLOSED_DIAGNOSTIC = "Plamen POSIX audit supervision failed closed.\n"

_NATIVE_MODULE = "_plamen_native_supervisor"
_SUPERVISOR_MODULE = "posix_audit_supervisor"
_ADAPTER_MODULE = "posix_native_authority_adapter"
_PROJECTION_SCHEMA = "plamen.native_audit_request_projection.v1"
_PROJECTION_MAX_BYTES = 1024 * 1024
_ENTRYPOINT_SUFFIX = "/lib/plamen/runtime/scripts/posix_audit_entrypoint.py"
_SUPERVISOR_RELATIVE = "/runtime/scripts/posix_audit_supervisor.py"
_ADAPTER_RELATIVE = "/runtime/scripts/posix_native_authority_adapter.py"

_TOP_LEVEL_KEYS = frozenset(("audit_request", "projection_schema"))
_SOURCE_CONFIG_KEYS = frozenset((
    "authenticated",
    "canonical_utf8_b64",
    "retained_source_handle",
    "sha256",
))
_AUDIT_REQUEST_KEYS = frozenset((
    "attempt_id",
    "backend",
    "backend_admission_sha256",
    "backend_context_sha256",
    "credential_bundle_sha256",
    "credential_isolation_sha256",
    "docs_sha256",
    "egress_admission_sha256",
    "egress_policy_sha256",
    "export_allowlist",
    "export_destination_identity_sha256",
    "export_max_total_bytes",
    "failure_required_artifacts",
    "image_closure_sha256",
    "image_manifest_digest",
    "language",
    "mode",
    "pipeline",
    "provider_provenance_sha256",
    "request_id",
    "request_type",
    "required_artifacts",
    "run_id",
    "runtime_layout_sha256",
    "schema",
    "scope_sha256",
    "seccomp_profile_sha256",
    "source_config",
    "source_config_sha256",
    "startup_decision_receipt_sha256",
    "target_identity_sha256",
))


def _fixed_install_paths() -> tuple[str, str, str]:
    """Derive the installed runtime modules from the fixed generation layout."""

    path = globals().get("__file__")
    if (
        type(path) is not str
        or not path.startswith("/")
        or not path.endswith(_ENTRYPOINT_SUFFIX)
        or path.startswith("//")
        or "\x00" in path
        or "/./" in path
        or "/../" in path
        or path != unicodedata.normalize("NFC", path)
    ):
        raise RuntimeError("fixed installed entrypoint identity is unavailable")
    plamen_library = path[:-len(_ENTRYPOINT_SUFFIX)] + "/lib/plamen"
    suffixes = importlib.machinery.EXTENSION_SUFFIXES
    if type(suffixes) is not list or not suffixes or type(suffixes[0]) is not str:
        raise RuntimeError("fixed native extension ABI suffix is unavailable")
    return (
        plamen_library + _SUPERVISOR_RELATIVE,
        plamen_library + _ADAPTER_RELATIVE,
        plamen_library + "/" + _NATIVE_MODULE + suffixes[0],
    )


def _module_table() -> dict[str, Any]:
    table = types.ModuleType.__getattribute__(sys, "__dict__").get("modules")
    if type(table) is not dict:
        raise RuntimeError("interpreter module table is unavailable")
    return table


def _load_exact_source(
    path: str, name: str = _SUPERVISOR_MODULE,
) -> types.ModuleType:
    table = _module_table()
    if table.get(name) is not None:
        raise RuntimeError("runtime source module was loaded before admission")
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_file_location(
        name, path, loader=loader,
    )
    if spec is None:
        raise RuntimeError("supervisor module specification is unavailable")
    module = importlib.util.module_from_spec(spec)
    if type(module) is not types.ModuleType:
        raise RuntimeError("supervisor module construction failed")
    table[name] = module
    try:
        loader.exec_module(module)
    except BaseException:
        table.pop(name, None)
        raise
    return module


def _load_exact_native(path: str) -> types.ModuleType:
    table = _module_table()
    if table.get(_NATIVE_MODULE) is not None:
        raise RuntimeError("native supervisor was loaded before admission")
    loader = importlib.machinery.ExtensionFileLoader(_NATIVE_MODULE, path)
    spec = importlib.util.spec_from_file_location(
        _NATIVE_MODULE, path, loader=loader,
    )
    if spec is None:
        raise RuntimeError("native supervisor specification is unavailable")
    module = importlib.util.module_from_spec(spec)
    if type(module) is not types.ModuleType:
        raise RuntimeError("native supervisor construction failed")
    table[_NATIVE_MODULE] = module
    try:
        loader.exec_module(module)
    except BaseException:
        table.pop(_NATIVE_MODULE, None)
        raise
    return module


def _load_runtime_surface() -> tuple[types.ModuleType, object]:
    supervisor_path, adapter_path, native_path = _fixed_install_paths()
    supervisor = _load_exact_source(supervisor_path)
    _load_exact_source(adapter_path, _ADAPTER_MODULE)
    native = _load_exact_native(native_path)
    _consumer_type, _bundle_type, _member_types, initial = (
        supervisor._native_supervisor_surface()
    )
    namespace = types.ModuleType.__getattribute__(native, "__dict__")
    if type(namespace) is not dict or namespace.get("INITIAL_AUTHORITY") is not initial:
        raise RuntimeError("native initial authority is unavailable")
    return supervisor, initial


def _roster(value: Any, label: str, supervisor: types.ModuleType) -> tuple[str, ...]:
    if type(value) is not list or not value or any(type(item) is not str for item in value):
        raise supervisor.SupervisorError(f"{label} is malformed")
    return tuple(value)


def _decode_request_projection(raw: Any, supervisor: types.ModuleType) -> Any:
    """Decode one native-validated projection into the supervisor's exact type."""

    if (
        type(raw) is not bytes
        or not raw
        or len(raw) > _PROJECTION_MAX_BYTES
        or raw.endswith(b"\n")
        or b"\x00" in raw
        or b"\\u" in raw
    ):
        raise supervisor.SupervisorError("native audit request projection is invalid")
    try:
        text = raw.decode("ascii", "strict")
        projection = supervisor.json.loads(
            text,
            object_pairs_hook=supervisor._config_pairs,
            parse_int=supervisor._config_int,
            parse_float=supervisor._reject_config_number,
            parse_constant=supervisor._reject_config_number,
        )
    except BaseException:
        raise supervisor.SupervisorError(
            "native audit request projection is invalid"
        ) from None
    if (
        type(projection) is not dict
        or frozenset(projection) != _TOP_LEVEL_KEYS
        or projection.get("projection_schema") != _PROJECTION_SCHEMA
    ):
        raise supervisor.SupervisorError("native audit request projection is invalid")
    try:
        canonical = supervisor._canonical_bytes(projection)
    except BaseException:
        raise supervisor.SupervisorError(
            "native audit request projection is invalid"
        ) from None
    if not canonical.endswith(b"\n") or canonical[:-1] != raw:
        raise supervisor.SupervisorError("native audit request projection is noncanonical")

    audit = projection.get("audit_request")
    if type(audit) is not dict or frozenset(audit) != _AUDIT_REQUEST_KEYS:
        raise supervisor.SupervisorError("native audit request projection is invalid")
    source = audit.get("source_config")
    if (
        type(source) is not dict
        or frozenset(source) != _SOURCE_CONFIG_KEYS
        or source.get("authenticated") is not True
        or type(source.get("canonical_utf8_b64")) is not str
    ):
        raise supervisor.SupervisorError("native audit request projection is invalid")
    encoded_config = source["canonical_utf8_b64"]
    try:
        ascii_config = encoded_config.encode("ascii", "strict")
        config_bytes = base64.b64decode(ascii_config, validate=True)
    except (UnicodeEncodeError, ValueError, binascii.Error):
        raise supervisor.SupervisorError(
            "native audit request projection is invalid"
        ) from None
    if base64.b64encode(config_bytes) != ascii_config:
        raise supervisor.SupervisorError("native audit request projection is noncanonical")

    try:
        source_config = supervisor.AuthenticatedDriverConfig(
            retained_source_handle=source["retained_source_handle"],
            canonical_bytes=config_bytes,
            sha256=source["sha256"],
            authenticated=source["authenticated"],
        )
        return supervisor.AuditRequest(
            request_type=supervisor.RequestType(audit["request_type"]),
            request_id=audit["request_id"],
            attempt_id=audit["attempt_id"],
            run_id=audit["run_id"],
            pipeline=audit["pipeline"],
            mode=audit["mode"],
            backend=audit["backend"],
            language=audit["language"],
            source_config=source_config,
            source_config_sha256=audit["source_config_sha256"],
            startup_decision_receipt_sha256=(
                audit["startup_decision_receipt_sha256"]
            ),
            target_identity_sha256=audit["target_identity_sha256"],
            runtime_layout_sha256=audit["runtime_layout_sha256"],
            image_manifest_digest=audit["image_manifest_digest"],
            image_closure_sha256=audit["image_closure_sha256"],
            docs_sha256=audit["docs_sha256"],
            scope_sha256=audit["scope_sha256"],
            seccomp_profile_sha256=audit["seccomp_profile_sha256"],
            credential_bundle_sha256=audit["credential_bundle_sha256"],
            credential_isolation_sha256=audit["credential_isolation_sha256"],
            backend_context_sha256=audit["backend_context_sha256"],
            backend_admission_sha256=audit["backend_admission_sha256"],
            egress_policy_sha256=audit["egress_policy_sha256"],
            egress_admission_sha256=audit["egress_admission_sha256"],
            provider_provenance_sha256=audit["provider_provenance_sha256"],
            export_allowlist=_roster(
                audit["export_allowlist"], "export allowlist", supervisor,
            ),
            required_artifacts=_roster(
                audit["required_artifacts"], "required artifacts", supervisor,
            ),
            failure_required_artifacts=_roster(
                audit["failure_required_artifacts"],
                "failure-required artifacts",
                supervisor,
            ),
            export_destination_identity_sha256=(
                audit["export_destination_identity_sha256"]
            ),
            export_max_total_bytes=audit["export_max_total_bytes"],
            schema=audit["schema"],
        )
    except supervisor.SupervisorError:
        raise
    except BaseException:
        raise supervisor.SupervisorError(
            "native audit request projection is invalid"
        ) from None


def _run() -> int:
    supervisor, initial = _load_runtime_surface()
    projection = initial.request_projection()
    request = _decode_request_projection(projection, supervisor)
    result = supervisor.supervise_audit(request, initial)
    if type(result) is not supervisor.SupervisorResult:
        raise supervisor.SupervisorError("native audit supervision result is invalid")
    return result.driver_exit_code


def main() -> int:
    try:
        return _run()
    except BaseException:
        try:
            sys.stderr.write(FAIL_CLOSED_DIAGNOSTIC)
            sys.stderr.flush()
        except BaseException:
            pass
        return EXIT_FAIL_CLOSED


if __name__ == "__main__":
    raise SystemExit(main())
