"""Provider-neutral, fail-closed POSIX audit supervisor.

This module is deliberately an orchestration kernel, not a container adapter
or a second Plamen driver.  It consumes authenticated, injected authorities and
starts exactly one existing ``plamen_driver.py`` in an admitted Linux guest.
It never parses ``sys.argv``, reads ambient environment variables, invokes a
container CLI, selects phases, or writes the audited host target.

The protocols below are security contracts.  Their Python shapes do not prove
native isolation, durable persistence, or authenticity.  Production callers
must supply authorities implemented across a trusted process/native boundary;
the included tests use deterministic fakes only.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
import hashlib
import importlib
import importlib.machinery
import json
from pathlib import PurePosixPath
import re
import sys
import types
from types import MappingProxyType
from typing import Any, Callable, Protocol, TypeVar
import unicodedata

from report_output_routing import (
    GUEST_REPORT_PATH,
    PUBLISHED_REPORT_PATH,
    REPORT_OUTPUT_CONFIG_KEY,
    STAGED_REPORT_ARTIFACT,
)


SCHEMA = "plamen.posix_audit_supervisor.v1"
NATIVE_MODULE_NAME = "_plamen_native_supervisor"
NATIVE_ABI_SCHEMA = "plamen.native-broker.v2"
NATIVE_PRODUCTION_ACQUISITION = (
    "AVAILABLE_AUTHENTICATED_NATIVE_SESSION"
)
START_NEW_RUN = "START_NEW_RUN"
RESUME_EXISTING = "RESUME_EXISTING"
MAX_TEXT_BYTES = 4096
MAX_CONFIG_BYTES = 256 * 1024
MAX_CONFIG_NODES = 8192
MAX_CONFIG_DEPTH = 32
MAX_EXPORT_FILES = 4096
MAX_EXPORT_FILE_BYTES = 256 * 1024 * 1024
MAX_EXPORT_TOTAL_BYTES = 2 * 1024 * 1024 * 1024

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_OCI_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_HANDLE = re.compile(r"opaque:[0-9a-f]{64}\Z")
_CONTAINER_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")


class SupervisorError(RuntimeError):
    """A public, bounded supervisor failure with no injected diagnostics."""


class SupervisorAmbiguousError(SupervisorError):
    """A mutation cannot safely be retried until durable recovery succeeds."""


class SupervisorRetryRequired(SupervisorError):
    """Recovery proved no effect; the normalized request may be retried."""


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise SupervisorError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _oci_digest(value: Any, label: str) -> str:
    if type(value) is not str or _OCI_DIGEST.fullmatch(value) is None:
        raise SupervisorError(f"{label} must be an OCI sha256 digest")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise SupervisorError(f"{label} is invalid")
    return value


def _handle(value: Any, label: str) -> str:
    if type(value) is not str or _HANDLE.fullmatch(value) is None:
        raise SupervisorError(f"{label} is not an opaque authority handle")
    return value


def _text(value: Any, label: str, *, maximum: int = MAX_TEXT_BYTES) -> str:
    if type(value) is not str or not value:
        raise SupervisorError(f"{label} must be nonempty text")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise SupervisorError(f"{label} is not valid UTF-8") from None
    if len(encoded) > maximum or value != unicodedata.normalize("NFC", value):
        raise SupervisorError(f"{label} is noncanonical or exceeds its bound")
    if "\x00" in value or any(ord(character) < 32 for character in value):
        raise SupervisorError(f"{label} contains unsupported bytes")
    return value


def _guest_path(value: Any, label: str) -> str:
    path = _text(value, label)
    if (
        not path.startswith("/")
        or path.startswith("//")
        or (path != "/" and path.endswith("/"))
        or "\\" in path
        or any(part in {"", ".", ".."} for part in path.split("/")[1:])
        or str(PurePosixPath(path)) != path
    ):
        raise SupervisorError(f"{label} must be one canonical absolute guest path")
    return path


def _relative_artifact(value: Any, label: str) -> str:
    path = _text(value, label, maximum=1024)
    if (
        path.startswith(("/", "~", "./", "../"))
        or "\\" in path
        or ":" in path
        or path.endswith("/")
        or any(part in {"", ".", ".."} for part in path.split("/"))
        or str(PurePosixPath(path)) != path
    ):
        raise SupervisorError(f"{label} is not a canonical relative artifact path")
    return path


def _bounded_int(value: Any, label: str, low: int, high: int) -> int:
    if type(value) is not int or isinstance(value, bool) or not low <= value <= high:
        raise SupervisorError(f"{label} is outside its domain")
    return value


def _validate_artifact_paths(paths: tuple[str, ...], label: str) -> None:
    if type(paths) is not tuple:
        raise SupervisorError(f"{label} is not a tuple")
    identities = tuple(path.casefold() for path in paths)
    if (
        paths != tuple(sorted(paths))
        or len(set(paths)) != len(paths)
        or len(set(identities)) != len(identities)
    ):
        raise SupervisorError(f"{label} is not sorted, unique, and alias-free")
    split = tuple(tuple(path.casefold().split("/")) for path in paths)
    for index, left in enumerate(split):
        for right in split[index + 1:]:
            shared = min(len(left), len(right))
            if left[:shared] == right[:shared]:
                raise SupervisorError(f"{label} contains ancestor aliases")


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _jsonable(getattr(value, field.name)) for field in fields(value)}
    if type(value) is tuple:
        return [_jsonable(item) for item in value]
    if type(value) is list:
        return [_jsonable(item) for item in value]
    if type(value) is bytes:
        return {"$bytes_hex": value.hex()}
    if type(value) is MappingProxyType:
        if any(type(key) is not str for key in value):
            raise SupervisorError("canonical object keys must be strings")
        return {key: _jsonable(item) for key, item in value.items()}
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise SupervisorError("canonical object keys must be strings")
        return {key: _jsonable(item) for key, item in value.items()}
    if value is None or type(value) in {str, int, bool}:
        return value
    raise SupervisorError("supervisor value cannot be canonically encoded")


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            _jsonable(value), ensure_ascii=True, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _config_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SupervisorError("driver config contains duplicate keys")
        result[key] = value
    return result


def _config_int(token: str) -> int:
    if len(token) > 19:
        raise SupervisorError("driver config integer exceeds its bound")
    value = int(token)
    if not -(2**63) <= value <= 2**63 - 1:
        raise SupervisorError("driver config integer exceeds its domain")
    return value


def _reject_config_number(_token: str) -> None:
    raise SupervisorError("driver config contains an unsupported number")


def _validate_config_tree(value: Any, *, depth: int = 0) -> int:
    if depth > MAX_CONFIG_DEPTH:
        raise SupervisorError("driver config nesting exceeds its bound")
    if value is None or type(value) in {bool, int}:
        return 1
    if type(value) is str:
        try:
            encoded = value.encode("utf-8", "strict")
        except UnicodeEncodeError:
            raise SupervisorError("driver config string is not valid UTF-8") from None
        if (
            len(encoded) > MAX_TEXT_BYTES
            or value != unicodedata.normalize("NFC", value)
            or "\x00" in value
        ):
            raise SupervisorError("driver config string is unsafe or oversized")
        return 1
    if type(value) is list:
        total = 1
        for item in value:
            total += _validate_config_tree(item, depth=depth + 1)
            if total > MAX_CONFIG_NODES:
                raise SupervisorError("driver config tree exceeds its bound")
        return total
    if type(value) is dict:
        total = 1
        for key, item in value.items():
            if not key:
                raise SupervisorError("driver config key is empty")
            _text(key, "driver config key", maximum=256)
            total += _validate_config_tree(item, depth=depth + 1)
            if total > MAX_CONFIG_NODES:
                raise SupervisorError("driver config tree exceeds its bound")
        return total
    raise SupervisorError("driver config contains an unsupported value")


def _parse_canonical_config(raw: Any) -> dict[str, Any]:
    if type(raw) is not bytes or not 2 <= len(raw) <= MAX_CONFIG_BYTES:
        raise SupervisorError("driver config bytes are absent or oversized")
    try:
        text = raw.decode("utf-8", "strict")
        value = json.loads(
            text,
            object_pairs_hook=_config_pairs,
            parse_int=_config_int,
            parse_float=_reject_config_number,
            parse_constant=_reject_config_number,
        )
    except Exception:
        raise SupervisorError("driver config is not canonical bounded JSON") from None
    if type(value) is not dict:
        raise SupervisorError("driver config must be one JSON object")
    _validate_config_tree(value)
    if raw != _canonical_bytes(value):
        raise SupervisorError("driver config bytes are not canonical")
    return value


class RequestType(str, Enum):
    SC_NEW = "SC_NEW"
    L1_NEW = "L1_NEW"
    START_CONFIG = "START_CONFIG"
    RESUME = "RESUME"


class ProviderKind(str, Enum):
    APPLE_CONTAINER = "APPLE_CONTAINER"
    PODMAN = "PODMAN"


class MutationOperation(str, Enum):
    PREPARE_LAYOUT = "PREPARE_LAYOUT"
    WRITE_CONFIG = "WRITE_CONFIG"
    CREATE_GUEST = "CREATE_GUEST"
    ADMIT_GUEST = "ADMIT_GUEST"
    START_DRIVER = "START_DRIVER"
    WAIT_DRIVER = "WAIT_DRIVER"
    EXTINGUISH = "EXTINGUISH"
    CENSUS_ARTIFACTS = "CENSUS_ARTIFACTS"
    EXPORT_ARTIFACTS = "EXPORT_ARTIFACTS"
    DELETE_GUEST = "DELETE_GUEST"


_OPERATIONS = tuple(MutationOperation)


class SupervisorStage(str, Enum):
    EMPTY = "EMPTY"
    LAYOUT_READY = "LAYOUT_READY"
    CONFIG_READY = "CONFIG_READY"
    GUEST_CREATED = "GUEST_CREATED"
    GUEST_ADMITTED = "GUEST_ADMITTED"
    DRIVER_STARTED = "DRIVER_STARTED"
    DRIVER_EXITED = "DRIVER_EXITED"
    EXTINCT = "EXTINCT"
    CENSUSED = "CENSUSED"
    EXPORTED = "EXPORTED"
    DELETED = "DELETED"


_STAGES = tuple(SupervisorStage)


class SupervisorCompletionStatus(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    DRIVER_FAILED = "DRIVER_FAILED"


@dataclass(frozen=True, slots=True)
class AuthenticatedDriverConfig:
    """Frontend-authenticated, canonical, already guest-path-projected config."""

    retained_source_handle: str
    canonical_bytes: bytes
    sha256: str
    authenticated: bool = True

    def __post_init__(self) -> None:
        _handle(self.retained_source_handle, "retained source config handle")
        _digest(self.sha256, "driver config sha256")
        document = _parse_canonical_config(self.canonical_bytes)
        if hashlib.sha256(self.canonical_bytes).hexdigest() != self.sha256:
            raise SupervisorError("driver config bytes differ from their digest")
        required = {
            "project_root", "scratchpad", "language", "mode", "pipeline",
            "cli_backend", "_run_id",
        }
        if not required.issubset(document) or "backend" in document:
            raise SupervisorError("driver config required keys are incomplete or aliased")
        if REPORT_OUTPUT_CONFIG_KEY in document:
            raise SupervisorError(
                "source config may not select the internal report output path"
            )
        if (
            document["project_root"] != "/workspace/project"
            or document["scratchpad"] != "/workspace/scratch"
        ):
            raise SupervisorError("driver config workspace paths are not guest-projected")
        if document.get("docs_path") not in (None, "", "/workspace/docs"):
            raise SupervisorError("driver config docs path is not guest-projected")
        if document.get("scope_file") not in (None, "", "/workspace/scope"):
            raise SupervisorError("driver config scope path is not guest-projected")
        docs_inputs = document.get("docs_inputs")
        if docs_inputs is not None:
            if type(docs_inputs) is not list or not docs_inputs:
                raise SupervisorError("driver config docs inputs are not guest-projected")
            checked: list[str] = []
            for path in docs_inputs:
                canonical = _guest_path(path, "driver config docs input")
                if not canonical.startswith("/workspace/docs/"):
                    raise SupervisorError(
                        "driver config docs inputs are not guest-projected"
                    )
                checked.append(canonical)
            aliases = tuple(path.casefold() for path in checked)
            if len(set(aliases)) != len(aliases):
                raise SupervisorError(
                    "driver config docs inputs contain duplicate aliases"
                )
        if self.authenticated is not True:
            raise SupervisorError("driver config authority is unauthenticated")

    @property
    def document(self) -> dict[str, Any]:
        return _parse_canonical_config(self.canonical_bytes)


@dataclass(frozen=True, slots=True)
class AuditRequest:
    """Already-normalized authority supplied by the future frontend parser."""

    request_type: RequestType
    request_id: str
    attempt_id: str
    run_id: str
    pipeline: str
    mode: str
    backend: str
    language: str
    source_config: AuthenticatedDriverConfig
    source_config_sha256: str
    startup_decision_receipt_sha256: str
    target_identity_sha256: str
    runtime_layout_sha256: str
    image_manifest_digest: str
    image_closure_sha256: str
    docs_sha256: str
    scope_sha256: str
    seccomp_profile_sha256: str
    credential_bundle_sha256: str
    credential_isolation_sha256: str
    backend_context_sha256: str
    backend_admission_sha256: str
    egress_policy_sha256: str
    egress_admission_sha256: str
    provider_provenance_sha256: str
    export_allowlist: tuple[str, ...]
    required_artifacts: tuple[str, ...]
    failure_required_artifacts: tuple[str, ...]
    export_destination_identity_sha256: str
    export_max_total_bytes: int = MAX_EXPORT_TOTAL_BYTES
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA or type(self.request_type) is not RequestType:
            raise SupervisorError("normalized audit request schema/type is invalid")
        _identifier(self.request_id, "request ID")
        _identifier(self.attempt_id, "attempt ID")
        _identifier(self.run_id, "run ID")
        if self.pipeline not in {"sc", "l1"} or self.mode not in {"light", "core", "thorough"}:
            raise SupervisorError("audit pipeline/mode is invalid")
        if self.backend not in {"codex", "claude"}:
            raise SupervisorError("audit backend is invalid")
        _text(self.language, "audit language", maximum=32)
        if type(self.source_config) is not AuthenticatedDriverConfig:
            raise SupervisorError("authenticated driver config is required")
        document = self.source_config.document
        if (
            self.source_config_sha256 != self.source_config.sha256
            or document["pipeline"] != self.pipeline
            or document["mode"] != self.mode
            or document["cli_backend"] != self.backend
            or document["language"] != self.language
            or document["_run_id"] != self.run_id
        ):
            raise SupervisorError("driver config route/run differs from request")
        for label, digest in (
            ("source config", self.source_config_sha256),
            ("startup decision receipt", self.startup_decision_receipt_sha256),
            ("target identity", self.target_identity_sha256),
            ("runtime layout", self.runtime_layout_sha256),
            ("image closure", self.image_closure_sha256),
            ("docs", self.docs_sha256), ("scope", self.scope_sha256),
            ("seccomp profile", self.seccomp_profile_sha256),
            ("credential bundle", self.credential_bundle_sha256),
            ("credential isolation", self.credential_isolation_sha256),
            ("backend context", self.backend_context_sha256),
            ("backend admission", self.backend_admission_sha256),
            ("egress policy", self.egress_policy_sha256),
            ("egress admission", self.egress_admission_sha256),
            ("provider provenance", self.provider_provenance_sha256),
            ("export destination", self.export_destination_identity_sha256),
        ):
            _digest(digest, f"{label} sha256")
        _oci_digest(self.image_manifest_digest, "image manifest digest")
        if self.request_type is RequestType.SC_NEW and self.pipeline != "sc":
            raise SupervisorError("SC new request must select the SC pipeline")
        if self.request_type is RequestType.L1_NEW and self.pipeline != "l1":
            raise SupervisorError("L1 new request must select the L1 pipeline")
        if type(self.export_allowlist) is not tuple or not self.export_allowlist:
            raise SupervisorError("export allowlist is empty or not a tuple")
        normalized = tuple(_relative_artifact(row, "export allowlist entry") for row in self.export_allowlist)
        if len(normalized) > MAX_EXPORT_FILES:
            raise SupervisorError("export allowlist must be sorted, unique, and bounded")
        _validate_artifact_paths(normalized, "export allowlist")
        for row in normalized:
            if not row.startswith(("project/", "scratch/")):
                raise SupervisorError(
                    "export allowlist may name only project or scratch artifacts"
                )
        for roster, label in (
            (self.required_artifacts, "required artifacts"),
            (self.failure_required_artifacts, "failure-required artifacts"),
        ):
            if type(roster) is not tuple or not roster:
                raise SupervisorError(f"{label} are absent")
            checked = tuple(_relative_artifact(row, label) for row in roster)
            _validate_artifact_paths(checked, label)
            if not set(checked).issubset(normalized):
                raise SupervisorError(f"{label} exceed the export allowlist")
        mandatory = {
            STAGED_REPORT_ARTIFACT, "scratch/_v2_checkpoint.json",
        }
        if not mandatory.issubset(self.required_artifacts):
            raise SupervisorError("required artifact denominator omits report/checkpoint")
        if "scratch/_plamen.log" not in self.failure_required_artifacts:
            raise SupervisorError(
                "failure artifact denominator omits the driver diagnostic log"
            )
        _bounded_int(self.export_max_total_bytes, "export total byte ceiling", 1, MAX_EXPORT_TOTAL_BYTES)

    @property
    def startup_intent(self) -> str:
        return RESUME_EXISTING if self.request_type is RequestType.RESUME else START_NEW_RUN

    @property
    def fingerprint_sha256(self) -> str:
        payload = {
            field.name: getattr(self, field.name)
            for field in fields(self)
            if field.name != "source_config"
        }
        payload["source_config"] = {
            "retained_source_handle": self.source_config.retained_source_handle,
            "sha256": self.source_config.sha256,
            "authenticated": self.source_config.authenticated,
        }
        return canonical_sha256(payload)


@dataclass(frozen=True, slots=True)
class AuthenticatedRuntimeImageLayout:
    runtime_layout_sha256: str
    image_manifest_digest: str
    image_closure_sha256: str
    docs_sha256: str
    runtime_handle: str
    docs_handle: str
    image_handle: str
    python_path: str = "/usr/bin/python3"
    driver_path: str = "/opt/plamen/scripts/plamen_driver.py"
    guest_os: str = "linux"
    guest_architecture: str = "arm64"
    immutable: bool = True
    authenticated: bool = True

    def __post_init__(self) -> None:
        _digest(self.runtime_layout_sha256, "runtime layout sha256")
        _oci_digest(self.image_manifest_digest, "image manifest digest")
        _digest(self.image_closure_sha256, "image closure sha256")
        _digest(self.docs_sha256, "docs sha256")
        handles = tuple(_handle(value, "runtime/image handle") for value in (self.runtime_handle, self.docs_handle, self.image_handle))
        if len(set(handles)) != 3:
            raise SupervisorError("runtime/image handles are not distinct")
        if (
            self.python_path != "/usr/bin/python3"
            or self.driver_path != "/opt/plamen/scripts/plamen_driver.py"
            or self.guest_os != "linux"
            or self.guest_architecture not in {"arm64", "amd64"}
            or self.immutable is not True
            or self.authenticated is not True
        ):
            raise SupervisorError("runtime/image layout authority is insufficient")


@dataclass(frozen=True, slots=True)
class TargetLease:
    target_handle: str
    identity_sha256: str
    content_sha256: str
    readonly: bool
    scratchpad_absent: bool
    authenticated: bool

    def __post_init__(self) -> None:
        _handle(self.target_handle, "target handle")
        _digest(self.identity_sha256, "target identity sha256")
        _digest(self.content_sha256, "target content sha256")
        if self.readonly is not True or self.scratchpad_absent is not True or self.authenticated is not True:
            raise SupervisorError("host target is not an authenticated scratchpad-free read-only lower")


@dataclass(frozen=True, slots=True)
class TargetRecensus:
    target_handle: str
    identity_sha256: str
    content_sha256: str
    readonly: bool
    scratchpad_absent: bool

    def __post_init__(self) -> None:
        _handle(self.target_handle, "recensused target handle")
        _digest(self.identity_sha256, "recensused target identity")
        _digest(self.content_sha256, "recensused target content")
        if self.readonly is not True or self.scratchpad_absent is not True:
            raise SupervisorError("host target recensus is unsafe")


@dataclass(frozen=True, slots=True)
class BackendContext:
    backend: str
    context_sha256: str
    backend_admission_sha256: str
    egress_policy_sha256: str
    egress_admission_sha256: str
    credential_sha256: str
    credential_isolation_sha256: str
    context_handle: str
    credential_handle: str
    network_mode: str = "NARROW_TRUSTED_PROXY_ONLY"
    inherited_environment: tuple[str, ...] = ()
    authenticated: bool = True

    def __post_init__(self) -> None:
        if self.backend not in {"codex", "claude"}:
            raise SupervisorError("backend context names an unsupported backend")
        _digest(self.context_sha256, "backend context sha256")
        _digest(self.backend_admission_sha256, "backend admission sha256")
        _digest(self.egress_policy_sha256, "egress policy sha256")
        _digest(self.egress_admission_sha256, "egress admission sha256")
        _digest(self.credential_sha256, "backend credential sha256")
        _digest(self.credential_isolation_sha256, "credential isolation sha256")
        handles = (_handle(self.context_handle, "backend context handle"), _handle(self.credential_handle, "credential handle"))
        if handles[0] == handles[1]:
            raise SupervisorError("backend and credential handles overlap")
        if self.network_mode != "NARROW_TRUSTED_PROXY_ONLY" or self.inherited_environment != () or self.authenticated is not True:
            raise SupervisorError("backend context has excess process/network authority")


@dataclass(frozen=True, slots=True)
class MutationTicket:
    operation: MutationOperation
    request_fingerprint_sha256: str
    attempt_id: str
    before_checkpoint_sha256: str
    sequence: int
    nonce: str
    authenticated: bool = True

    def __post_init__(self) -> None:
        if type(self.operation) is not MutationOperation:
            raise SupervisorError("mutation ticket operation is invalid")
        _digest(self.request_fingerprint_sha256, "ticket request fingerprint")
        _identifier(self.attempt_id, "ticket attempt ID")
        _digest(self.before_checkpoint_sha256, "ticket checkpoint sha256")
        _bounded_int(self.sequence, "ticket sequence", 1, 2**63 - 1)
        _digest(self.nonce, "ticket nonce")
        if self.authenticated is not True:
            raise SupervisorError("mutation ticket is unauthenticated")


@dataclass(frozen=True, slots=True)
class AttemptLayout:
    attempt_id: str
    run_id: str
    layout_handle: str
    target_lower_handle: str
    upper_handle: str
    work_handle: str
    merged_handle: str
    scratch_handle: str
    state_handle: str
    control_handle: str
    seccomp_handle: str
    scope_handle: str
    target_identity_sha256: str
    scope_sha256: str
    seccomp_sha256: str
    export_destination_handle: str
    export_destination_identity_sha256: str
    run_store_outside_target: bool = True
    target_lower_readonly: bool = True
    private_attempt_owned: bool = True

    def __post_init__(self) -> None:
        _identifier(self.attempt_id, "layout attempt ID")
        _identifier(self.run_id, "layout run ID")
        handles = tuple(
            _handle(getattr(self, name), f"layout {name}")
            for name in (
                "layout_handle", "target_lower_handle", "upper_handle", "work_handle",
                "merged_handle", "scratch_handle", "state_handle", "control_handle",
                "seccomp_handle", "scope_handle", "export_destination_handle",
            )
        )
        if len(set(handles)) != len(handles):
            raise SupervisorError("attempt layout handles overlap")
        _digest(self.target_identity_sha256, "layout target identity")
        _digest(self.scope_sha256, "layout scope sha256")
        _digest(self.seccomp_sha256, "layout seccomp sha256")
        _digest(
            self.export_destination_identity_sha256,
            "layout export destination identity",
        )
        if self.run_store_outside_target is not True or self.target_lower_readonly is not True or self.private_attempt_owned is not True:
            raise SupervisorError("attempt layout is not private, external, and lower-read-only")


@dataclass(frozen=True, slots=True)
class GuestConfig:
    retained_source_handle: str
    canonical_bytes: bytes
    config_sha256: str

    def __post_init__(self) -> None:
        _handle(self.retained_source_handle, "guest config source handle")
        _digest(self.config_sha256, "guest config sha256")
        _parse_canonical_config(self.canonical_bytes)
        if hashlib.sha256(self.canonical_bytes).hexdigest() != self.config_sha256:
            raise SupervisorError("guest config bytes differ from their digest")

    @property
    def document(self) -> dict[str, Any]:
        return _parse_canonical_config(self.canonical_bytes)


@dataclass(frozen=True, slots=True)
class ConfigReceipt:
    attempt_id: str
    run_id: str
    config_handle: str
    config_sha256: str
    source_config_sha256: str
    startup_decision_receipt_sha256: str
    guest_config: GuestConfig

    def __post_init__(self) -> None:
        _identifier(self.attempt_id, "config attempt ID")
        _identifier(self.run_id, "config run ID")
        _handle(self.config_handle, "config handle")
        _digest(self.config_sha256, "rendered config sha256")
        _digest(self.source_config_sha256, "source config sha256")
        _digest(self.startup_decision_receipt_sha256, "startup decision receipt sha256")
        if type(self.guest_config) is not GuestConfig:
            raise SupervisorError("config receipt lacks typed guest configuration")


@dataclass(frozen=True, slots=True)
class LayoutComponent:
    purpose: str
    source_handle: str
    attachment: str
    mode: str
    identity_sha256: str
    content_sha256: str
    provider_mount_identity_sha256: str

    def __post_init__(self) -> None:
        _text(self.purpose, "layout component purpose", maximum=64)
        _handle(self.source_handle, "layout component source handle")
        _text(self.attachment, "layout component attachment", maximum=256)
        if self.mode not in {"ro", "rw"}:
            raise SupervisorError("layout component mode is invalid")
        _digest(self.identity_sha256, "layout component identity")
        _digest(self.content_sha256, "layout component content")
        _digest(
            self.provider_mount_identity_sha256,
            "layout component provider mount identity",
        )


@dataclass(frozen=True, slots=True)
class LayoutRecensus:
    attempt_id: str
    layout_handle: str
    target_identity_sha256: str
    target_content_sha256: str
    components: tuple[LayoutComponent, ...]
    layout_sha256: str
    phase: str
    target_lower_readonly: bool = True
    workload_nonexecuting: bool = True

    def __post_init__(self) -> None:
        _identifier(self.attempt_id, "recensus attempt ID")
        _handle(self.layout_handle, "recensus layout handle")
        _digest(self.target_identity_sha256, "recensus target identity")
        _digest(self.target_content_sha256, "recensus target content")
        if (
            type(self.components) is not tuple
            or not self.components
            or any(type(row) is not LayoutComponent for row in self.components)
        ):
            raise SupervisorError("layout recensus components are invalid")
        _digest(self.layout_sha256, "recensus layout sha256")
        expected = canonical_sha256(
            {
                "attempt_id": self.attempt_id,
                "layout_handle": self.layout_handle,
                "target_identity_sha256": self.target_identity_sha256,
                "target_content_sha256": self.target_content_sha256,
                "components": tuple(
                    {
                        "purpose": row.purpose,
                        "source_handle": row.source_handle,
                        "attachment": row.attachment,
                        "mode": row.mode,
                        "identity_sha256": row.identity_sha256,
                        "content_sha256": row.content_sha256,
                    }
                    for row in self.components
                ),
            }
        )
        if self.layout_sha256 != expected:
            raise SupervisorError("layout recensus digest differs from stable facts")
        if self.phase not in {"PRE_CREATE", "POST_CREATE"} or self.target_lower_readonly is not True or self.workload_nonexecuting is not True:
            raise SupervisorError("layout recensus is not a safe nonexecuting observation")

    @property
    def provider_mounts_sha256(self) -> str:
        return canonical_sha256(
            tuple(
                (row.purpose, row.provider_mount_identity_sha256)
                for row in self.components
            )
        )


@dataclass(frozen=True, slots=True)
class GuestMount:
    purpose: str
    source_handle: str
    destination: str
    mode: str

    def __post_init__(self) -> None:
        _text(self.purpose, "guest mount purpose", maximum=64)
        _handle(self.source_handle, "guest mount source")
        _guest_path(self.destination, "guest mount destination")
        if self.mode not in {"ro", "rw"}:
            raise SupervisorError("guest mount mode is invalid")


_LINUX_OVERLAY_MOUNT_POLICY = (
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

_APPLE_CONTAINER_MOUNT_POLICY = _LINUX_OVERLAY_MOUNT_POLICY

# Compatibility name for the explicitly Linux overlay-backed provider lane.
_MOUNT_POLICY = _LINUX_OVERLAY_MOUNT_POLICY

_LINUX_OVERLAY_LAYOUT_COMPONENT_POLICY = (
    ("target-lower", "HOST_OVERLAY_LOWER", "ro"),
    *_LINUX_OVERLAY_MOUNT_POLICY,
)
_APPLE_CONTAINER_LAYOUT_COMPONENT_POLICY = _LINUX_OVERLAY_LAYOUT_COMPONENT_POLICY


def _provider_mount_policy(provider_kind: ProviderKind) -> tuple[tuple[str, str, str], ...]:
    if provider_kind is ProviderKind.APPLE_CONTAINER:
        return _APPLE_CONTAINER_MOUNT_POLICY
    if provider_kind is ProviderKind.PODMAN:
        return _LINUX_OVERLAY_MOUNT_POLICY
    raise SupervisorError("guest provider kind has no mount policy")


@dataclass(frozen=True, slots=True)
class GuestCreateSpec:
    attempt_id: str
    image_manifest_digest: str
    image_handle: str
    image_closure_sha256: str
    config_sha256: str
    precreate_recensus: LayoutRecensus
    egress_policy_sha256: str
    egress_admission_sha256: str
    backend_admission_sha256: str
    credential_isolation_sha256: str
    provider_provenance_sha256: str
    mounts: tuple[GuestMount, ...]
    guest_name: str
    provider_kind: ProviderKind = ProviderKind.PODMAN
    platform_os: str = "linux"
    platform_architecture: str = "arm64"
    network_mode: str = "NARROW_TRUSTED_PROXY_ONLY"
    rootfs_readonly: bool = True
    create_stopped: bool = True
    initial_process_count: int = 0
    uid: int = 1000
    gid: int = 1000
    inherited_environment: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _identifier(self.attempt_id, "guest spec attempt ID")
        _oci_digest(self.image_manifest_digest, "guest image manifest")
        _handle(self.image_handle, "guest image handle")
        _digest(self.image_closure_sha256, "guest image closure sha256")
        _digest(self.config_sha256, "guest config sha256")
        if (
            type(self.precreate_recensus) is not LayoutRecensus
            or self.precreate_recensus.attempt_id != self.attempt_id
            or self.precreate_recensus.phase != "PRE_CREATE"
        ):
            raise SupervisorError("guest spec lacks exact pre-create recensus")
        _digest(self.egress_policy_sha256, "guest egress policy")
        _digest(self.egress_admission_sha256, "guest egress admission")
        _digest(self.backend_admission_sha256, "guest backend admission")
        _digest(self.credential_isolation_sha256, "guest credential isolation")
        _digest(self.provider_provenance_sha256, "guest provider provenance")
        if type(self.provider_kind) is not ProviderKind:
            raise SupervisorError("guest create spec provider kind is invalid")
        expected_mounts = _provider_mount_policy(self.provider_kind)
        if type(self.mounts) is not tuple or tuple((row.purpose, row.destination, row.mode) for row in self.mounts) != expected_mounts:
            raise SupervisorError("guest mount roster differs from the closed policy")
        handles = tuple(row.source_handle for row in self.mounts)
        if len(set(handles)) != len(handles):
            raise SupervisorError("guest mount source authorities overlap")
        if (
            self.guest_name != f"plamen-{self.attempt_id}"
            or self.platform_os != "linux"
            or self.platform_architecture not in {"arm64", "amd64"}
            or self.network_mode != "NARROW_TRUSTED_PROXY_ONLY"
            or self.rootfs_readonly is not True
            or self.create_stopped is not True
            or self.initial_process_count != 0
        ):
            raise SupervisorError("guest is not created stopped with a read-only rootfs")
        if type(self.uid) is not int or type(self.gid) is not int or self.uid <= 0 or self.gid <= 0 or self.inherited_environment != ():
            raise SupervisorError("guest process identity/environment is unsafe")

    @property
    def spec_sha256(self) -> str:
        return canonical_sha256(self)

    @property
    def precreate_recensus_sha256(self) -> str:
        return self.precreate_recensus.layout_sha256


@dataclass(frozen=True, slots=True)
class GuestCreatedReceipt:
    provider_kind: ProviderKind
    attempt_id: str
    guest_id: str
    create_spec: GuestCreateSpec
    mount_roster_sha256: str
    provider_mounts_sha256: str
    state: str = "CREATED_STOPPED"
    workload_started: bool = False

    def __post_init__(self) -> None:
        if type(self.provider_kind) is not ProviderKind:
            raise SupervisorError("created guest provider kind is invalid")
        _identifier(self.attempt_id, "created guest attempt ID")
        if type(self.guest_id) is not str or _CONTAINER_ID.fullmatch(self.guest_id) is None:
            raise SupervisorError("created guest ID is invalid")
        if (
            type(self.create_spec) is not GuestCreateSpec
            or self.create_spec.attempt_id != self.attempt_id
            or self.create_spec.provider_kind is not self.provider_kind
        ):
            raise SupervisorError("created guest lacks its exact typed create specification")
        _digest(self.mount_roster_sha256, "created guest mount roster")
        _digest(self.provider_mounts_sha256, "created guest provider mounts")
        if self.mount_roster_sha256 != canonical_sha256(self.create_spec.mounts):
            raise SupervisorError("created guest mount roster differs from its specification")
        if self.state != "CREATED_STOPPED" or self.workload_started is not False:
            raise SupervisorError("provider did not create a stopped nonexecuting guest")

    @property
    def spec_sha256(self) -> str:
        return self.create_spec.spec_sha256


@dataclass(frozen=True, slots=True)
class GuestObservation:
    provider_kind: ProviderKind
    guest_id: str
    spec_sha256: str
    mount_roster_sha256: str
    provider_mounts_sha256: str
    state: str = "CREATED_STOPPED"
    workload_process_count: int = 0

    def __post_init__(self) -> None:
        if type(self.provider_kind) is not ProviderKind or type(self.guest_id) is not str or _CONTAINER_ID.fullmatch(self.guest_id) is None:
            raise SupervisorError("guest observation identity is invalid")
        _digest(self.spec_sha256, "observed guest spec")
        _digest(self.mount_roster_sha256, "observed guest mounts")
        _digest(self.provider_mounts_sha256, "observed provider mounts")
        if self.state != "CREATED_STOPPED" or self.workload_process_count != 0:
            raise SupervisorError("guest observation is not stopped/nonexecuting")


@dataclass(frozen=True, slots=True)
class GuestAdmissionReceipt:
    attempt_id: str
    guest_id: str
    admission_handle: str
    admission_sha256: str
    precreate_recensus: LayoutRecensus
    postcreate_recensus: LayoutRecensus
    allowed_delta_sha256: str
    spec_sha256: str
    workload_nonexecuting: bool = True
    replay_consumed: bool = True

    def __post_init__(self) -> None:
        _identifier(self.attempt_id, "guest admission attempt ID")
        if type(self.guest_id) is not str or _CONTAINER_ID.fullmatch(self.guest_id) is None:
            raise SupervisorError("guest admission ID is invalid")
        _handle(self.admission_handle, "guest admission handle")
        if (
            type(self.precreate_recensus) is not LayoutRecensus
            or type(self.postcreate_recensus) is not LayoutRecensus
        ):
            raise SupervisorError("guest admission lacks typed layout recensuses")
        for value, label in ((self.admission_sha256, "guest admission"), (self.allowed_delta_sha256, "allowed layout delta"), (self.spec_sha256, "admitted guest spec")):
            _digest(value, f"{label} sha256")
        if self.workload_nonexecuting is not True or self.replay_consumed is not True:
            raise SupervisorError("guest admission did not bind stopped state and replay")

    @property
    def postcreate_recensus_sha256(self) -> str:
        return self.postcreate_recensus.layout_sha256


@dataclass(frozen=True, slots=True)
class DriverLaunch:
    attempt_id: str
    guest_id: str
    admission_sha256: str
    argv: tuple[str, ...]
    cwd: str = "/workspace/project"
    environment: tuple[str, ...] = ()
    stdin: str = "DEVNULL"

    def __post_init__(self) -> None:
        _identifier(self.attempt_id, "driver launch attempt ID")
        if type(self.guest_id) is not str or _CONTAINER_ID.fullmatch(self.guest_id) is None:
            raise SupervisorError("driver launch guest ID is invalid")
        _digest(self.admission_sha256, "driver admission sha256")
        if type(self.argv) is not tuple or not self.argv or any(type(row) is not str or not row for row in self.argv):
            raise SupervisorError("driver argv is invalid")
        if self.cwd != "/workspace/project" or self.environment != () or self.stdin != "DEVNULL":
            raise SupervisorError("driver launch inherited ambient authority")

    @property
    def launch_sha256(self) -> str:
        return canonical_sha256(self)


@dataclass(frozen=True, slots=True)
class DriverStartReceipt:
    attempt_id: str
    guest_id: str
    launch_sha256: str
    driver_process_id: str
    driver_process_count: int = 1

    def __post_init__(self) -> None:
        _identifier(self.attempt_id, "driver start attempt ID")
        if type(self.guest_id) is not str or _CONTAINER_ID.fullmatch(self.guest_id) is None:
            raise SupervisorError("driver start guest ID is invalid")
        _digest(self.launch_sha256, "driver launch sha256")
        _identifier(self.driver_process_id, "driver process ID")
        if self.driver_process_count != 1:
            raise SupervisorError("provider did not start exactly one driver")


@dataclass(frozen=True, slots=True)
class DriverExitReceipt:
    attempt_id: str
    guest_id: str
    launch_sha256: str
    exit_code: int
    wait_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.attempt_id, "driver exit attempt ID")
        if type(self.guest_id) is not str or _CONTAINER_ID.fullmatch(self.guest_id) is None:
            raise SupervisorError("driver exit guest ID is invalid")
        _digest(self.launch_sha256, "waited driver launch")
        _bounded_int(self.exit_code, "driver exit code", 0, 255)
        _digest(self.wait_sha256, "driver wait sha256")


@dataclass(frozen=True, slots=True)
class ExtinctionReceipt:
    attempt_id: str
    guest_id: str
    terminal_sha256: str
    cgroup_populated: int = 0
    process_count: int = 0
    exact_attempt: bool = True

    def __post_init__(self) -> None:
        _identifier(self.attempt_id, "extinction attempt ID")
        if type(self.guest_id) is not str or _CONTAINER_ID.fullmatch(self.guest_id) is None:
            raise SupervisorError("extinction guest ID is invalid")
        _digest(self.terminal_sha256, "terminal proof sha256")
        if self.cgroup_populated != 0 or self.process_count != 0 or self.exact_attempt is not True:
            raise SupervisorError("guest process/cgroup extinction is unproven")


@dataclass(frozen=True, slots=True)
class ArtifactEntry:
    relative_path: str
    size: int
    sha256: str
    object_kind: str = "regular"
    symlink: bool = False
    hardlink_count: int = 1

    def __post_init__(self) -> None:
        _relative_artifact(self.relative_path, "artifact path")
        _bounded_int(self.size, "artifact size", 0, MAX_EXPORT_FILE_BYTES)
        _digest(self.sha256, "artifact sha256")
        if self.object_kind != "regular" or self.symlink is not False or self.hardlink_count != 1:
            raise SupervisorError("artifact is not an ordinary single-link file")


@dataclass(frozen=True, slots=True)
class ArtifactDisposition:
    relative_path: str
    status: str
    entry_sha256: str | None

    def __post_init__(self) -> None:
        _relative_artifact(self.relative_path, "artifact disposition path")
        if self.status not in {"PRESENT", "MISSING"}:
            raise SupervisorError("artifact disposition status is invalid")
        if self.status == "PRESENT":
            _digest(self.entry_sha256, "artifact disposition entry")
        elif self.entry_sha256 is not None:
            raise SupervisorError("missing artifact disposition carries an entry")


@dataclass(frozen=True, slots=True)
class ArtifactCensus:
    attempt_id: str
    run_id: str
    terminal_sha256: str
    driver_exit_code: int
    census_handle: str
    entries: tuple[ArtifactEntry, ...]
    dispositions: tuple[ArtifactDisposition, ...]
    census_sha256: str
    exact: bool = True
    immutable_lease: bool = True

    def __post_init__(self) -> None:
        _identifier(self.attempt_id, "artifact census attempt ID")
        _identifier(self.run_id, "artifact census run ID")
        _digest(self.terminal_sha256, "artifact census terminal")
        _bounded_int(self.driver_exit_code, "artifact census driver exit code", 0, 255)
        _handle(self.census_handle, "artifact census handle")
        if type(self.entries) is not tuple or len(self.entries) > MAX_EXPORT_FILES or any(type(row) is not ArtifactEntry for row in self.entries):
            raise SupervisorError("artifact census is malformed or oversized")
        paths = tuple(row.relative_path for row in self.entries)
        _validate_artifact_paths(paths, "artifact census paths")
        if (
            type(self.dispositions) is not tuple
            or not self.dispositions
            or any(type(row) is not ArtifactDisposition for row in self.dispositions)
        ):
            raise SupervisorError("artifact dispositions are absent or malformed")
        _validate_artifact_paths(
            tuple(row.relative_path for row in self.dispositions),
            "artifact disposition paths",
        )
        _digest(self.census_sha256, "artifact census sha256")
        if self.exact is not True or self.immutable_lease is not True:
            raise SupervisorError("artifact census is not an exact immutable lease")


@dataclass(frozen=True, slots=True)
class ExportReceipt:
    attempt_id: str
    run_id: str
    census_sha256: str
    destination_handle: str
    destination_identity_sha256: str
    exported_count: int
    exported_bytes: int
    manifest_sha256: str
    export_sha256: str
    complete: bool = True

    def __post_init__(self) -> None:
        _identifier(self.attempt_id, "export attempt ID")
        _identifier(self.run_id, "export run ID")
        _digest(self.census_sha256, "export census sha256")
        _handle(self.destination_handle, "export destination handle")
        _digest(self.destination_identity_sha256, "export destination identity")
        _bounded_int(self.exported_count, "export count", 0, MAX_EXPORT_FILES)
        _bounded_int(self.exported_bytes, "export bytes", 0, MAX_EXPORT_TOTAL_BYTES)
        _digest(self.manifest_sha256, "export manifest sha256")
        _digest(self.export_sha256, "export sha256")
        if self.complete is not True:
            raise SupervisorError("artifact export is incomplete")


@dataclass(frozen=True, slots=True)
class DeleteReceipt:
    provider_kind: ProviderKind
    attempt_id: str
    guest_id: str
    terminal_sha256: str
    absent: bool = True

    def __post_init__(self) -> None:
        if type(self.provider_kind) is not ProviderKind:
            raise SupervisorError("delete provider kind is invalid")
        _identifier(self.attempt_id, "delete attempt ID")
        if type(self.guest_id) is not str or _CONTAINER_ID.fullmatch(self.guest_id) is None:
            raise SupervisorError("deleted guest ID is invalid")
        _digest(self.terminal_sha256, "delete terminal sha256")
        if self.absent is not True:
            raise SupervisorError("guest deletion is unproven")


_RECEIPT_TYPES = (
    AttemptLayout, ConfigReceipt, GuestCreatedReceipt, GuestAdmissionReceipt,
    DriverStartReceipt, DriverExitReceipt, ExtinctionReceipt, ArtifactCensus,
    ExportReceipt, DeleteReceipt,
)


@dataclass(frozen=True, slots=True)
class SupervisorCheckpoint:
    request_fingerprint_sha256: str
    attempt_id: str
    run_id: str
    stage: SupervisorStage = SupervisorStage.EMPTY
    receipts: tuple[Any, ...] = ()

    def __post_init__(self) -> None:
        _digest(self.request_fingerprint_sha256, "checkpoint request fingerprint")
        _identifier(self.attempt_id, "checkpoint attempt ID")
        _identifier(self.run_id, "checkpoint run ID")
        if type(self.stage) is not SupervisorStage or type(self.receipts) is not tuple:
            raise SupervisorError("supervisor checkpoint shape is invalid")
        expected_count = _STAGES.index(self.stage)
        if len(self.receipts) != expected_count:
            raise SupervisorError("supervisor checkpoint stage/receipt count differs")
        if any(
            type(row) is not expected
            for row, expected in zip(
                self.receipts, _RECEIPT_TYPES[:expected_count], strict=True
            )
        ):
            raise SupervisorError("supervisor checkpoint receipt sequence is invalid")
        for row in self.receipts:
            if getattr(row, "attempt_id", None) != self.attempt_id:
                raise SupervisorError("checkpoint receipt names a different attempt")
        for row in self.receipts:
            if hasattr(row, "run_id") and getattr(row, "run_id") != self.run_id:
                raise SupervisorError("checkpoint receipt names a different run")

    @property
    def checkpoint_sha256(self) -> str:
        return canonical_sha256(self)

    def receipt(self, receipt_type: type[Any]) -> Any:
        for row in self.receipts:
            if type(row) is receipt_type:
                return row
        raise SupervisorError("required checkpoint receipt is unavailable")


def advance_checkpoint(
    checkpoint: SupervisorCheckpoint,
    operation: MutationOperation,
    receipt: Any,
) -> SupervisorCheckpoint:
    """Validate and append exactly the next operation receipt."""
    if type(checkpoint) is not SupervisorCheckpoint or type(operation) is not MutationOperation:
        raise SupervisorError("checkpoint advancement input is invalid")
    index = _STAGES.index(checkpoint.stage)
    if index >= len(_OPERATIONS) or _OPERATIONS[index] is not operation:
        raise SupervisorError("checkpoint operation is out of order")
    expected_type = _RECEIPT_TYPES[index]
    if type(receipt) is not expected_type:
        raise SupervisorError("mutation returned the wrong typed receipt")
    return SupervisorCheckpoint(
        checkpoint.request_fingerprint_sha256, checkpoint.attempt_id,
        checkpoint.run_id, _STAGES[index + 1], checkpoint.receipts + (receipt,),
    )


class JournalOpenStatus(str, Enum):
    READY = "READY"
    COMPLETE = "COMPLETE"
    REJECTED = "REJECTED"


@dataclass(frozen=True, slots=True)
class JournalOpenReceipt:
    status: JournalOpenStatus
    checkpoint: SupervisorCheckpoint
    pending: MutationTicket | None = None

    def __post_init__(self) -> None:
        if type(self.status) is not JournalOpenStatus or type(self.checkpoint) is not SupervisorCheckpoint:
            raise SupervisorError("durable journal open receipt is invalid")
        if self.pending is not None and type(self.pending) is not MutationTicket:
            raise SupervisorError("durable journal pending ticket is invalid")
        if self.status is JournalOpenStatus.COMPLETE and self.checkpoint.stage is not SupervisorStage.DELETED:
            raise SupervisorError("journal claims completion without deletion")
        if self.status in {JournalOpenStatus.COMPLETE, JournalOpenStatus.REJECTED} and self.pending is not None:
            raise SupervisorError("closed journal unexpectedly has a pending mutation")
        if self.pending is not None:
            index = _STAGES.index(self.checkpoint.stage)
            if (
                index >= len(_OPERATIONS)
                or self.pending.operation is not _OPERATIONS[index]
                or self.pending.before_checkpoint_sha256
                != self.checkpoint.checkpoint_sha256
                or self.pending.request_fingerprint_sha256
                != self.checkpoint.request_fingerprint_sha256
                or self.pending.attempt_id != self.checkpoint.attempt_id
            ):
                raise SupervisorError("pending mutation differs from its durable checkpoint")


class RecoveryStatus(str, Enum):
    APPLIED = "APPLIED"
    NOT_APPLIED = "NOT_APPLIED"
    UNPROVEN = "UNPROVEN"


@dataclass(frozen=True, slots=True)
class RecoveryResolution:
    status: RecoveryStatus
    ticket: MutationTicket
    checkpoint: SupervisorCheckpoint | None
    proof_sha256: str

    def __post_init__(self) -> None:
        if type(self.status) is not RecoveryStatus or type(self.ticket) is not MutationTicket:
            raise SupervisorError("recovery resolution is invalid")
        _digest(self.proof_sha256, "recovery proof sha256")
        if self.status is RecoveryStatus.UNPROVEN:
            if self.checkpoint is not None:
                raise SupervisorError("unproven recovery supplied a checkpoint")
        elif type(self.checkpoint) is not SupervisorCheckpoint:
            raise SupervisorError("proven recovery lacks a checkpoint")


class RuntimeImageAuthority(Protocol):
    def authenticate(self, request: AuditRequest) -> AuthenticatedRuntimeImageLayout: ...


class WorkspaceAuthority(Protocol):
    def admit_target(self, request: AuditRequest) -> TargetLease: ...
    def revalidate_target(self, request: AuditRequest, target: TargetLease) -> TargetRecensus: ...
    def prepare_layout(self, request: AuditRequest, target: TargetLease, ticket: MutationTicket) -> AttemptLayout: ...
    def resume_layout(self, request: AuditRequest, layout: AttemptLayout) -> AttemptLayout: ...
    def write_guest_config(self, request: AuditRequest, layout: AttemptLayout, config: GuestConfig, ticket: MutationTicket) -> ConfigReceipt: ...
    def recensus_layout(self, request: AuditRequest, target: TargetLease, layout: AttemptLayout, runtime: AuthenticatedRuntimeImageLayout, backend: BackendContext, configured: ConfigReceipt, phase: str) -> LayoutRecensus: ...


class BackendContextAuthority(Protocol):
    def authenticate(self, request: AuditRequest) -> BackendContext: ...


class ProviderLifecycle(Protocol):
    def provider_kind(self) -> ProviderKind: ...
    def create_stopped(self, spec: GuestCreateSpec, ticket: MutationTicket) -> GuestCreatedReceipt: ...
    def inspect_stopped(self, created: GuestCreatedReceipt) -> GuestObservation: ...
    def resume_guest(self, request: AuditRequest, created: GuestCreatedReceipt) -> GuestCreatedReceipt: ...
    def start_driver(self, created: GuestCreatedReceipt, admission: GuestAdmissionReceipt, launch: DriverLaunch, ticket: MutationTicket) -> DriverStartReceipt: ...
    def wait_driver(self, created: GuestCreatedReceipt, started: DriverStartReceipt, ticket: MutationTicket) -> DriverExitReceipt: ...
    def delete_guest(self, created: GuestCreatedReceipt, terminal: ExtinctionReceipt, ticket: MutationTicket) -> DeleteReceipt: ...


class OciGuestAdmissionAuthority(Protocol):
    def admit_stopped_guest(self, request: AuditRequest, created: GuestCreatedReceipt, observation: GuestObservation, postcreate: LayoutRecensus, ticket: MutationTicket) -> GuestAdmissionReceipt: ...
    def resume_admission(self, request: AuditRequest, created: GuestCreatedReceipt, admission: GuestAdmissionReceipt) -> GuestAdmissionReceipt: ...


class ExtinctionAuthority(Protocol):
    def extinguish(self, request: AuditRequest, created: GuestCreatedReceipt, exited: DriverExitReceipt, ticket: MutationTicket) -> ExtinctionReceipt: ...


class ArtifactAuthority(Protocol):
    """Issue a durable immutable artifact lease after terminal extinction."""
    def census(self, request: AuditRequest, layout: AttemptLayout, exited: DriverExitReceipt, terminal: ExtinctionReceipt, ticket: MutationTicket) -> ArtifactCensus: ...


class ExportAuthority(Protocol):
    """Publish a successful report through the exact durable census lease.

    The provider maps the census identity ``project/AUDIT_REPORT.md`` to the
    guest-written ``/workspace/scratch/AUDIT_REPORT.md``.  It must publish
    those exact bytes atomically as target ``AUDIT_REPORT.md`` only after a
    zero driver exit and exact extinction, and must never reopen the source by
    ambient path.
    """
    def export(self, request: AuditRequest, layout: AttemptLayout, census: ArtifactCensus, ticket: MutationTicket) -> ExportReceipt: ...


class DurableJournal(Protocol):
    """Authenticated durable CAS journal and cross-process replay authority."""
    def open(self, request: AuditRequest) -> JournalOpenReceipt: ...
    def arm(self, request: AuditRequest, operation: MutationOperation, before_checkpoint_sha256: str) -> MutationTicket: ...
    def commit(self, request: AuditRequest, ticket: MutationTicket, checkpoint: SupervisorCheckpoint) -> bool: ...
    def resolve(self, request: AuditRequest, ticket: MutationTicket, checkpoint: SupervisorCheckpoint) -> bool: ...
    def finish(self, request: AuditRequest, checkpoint_sha256: str) -> bool: ...


class RecoveryAuthority(Protocol):
    """Reconcile a pending ticket without repeating its governed mutation."""
    def recover(self, request: AuditRequest, ticket: MutationTicket, before: SupervisorCheckpoint) -> RecoveryResolution: ...


@dataclass(frozen=True, slots=True)
class SupervisorAuthorities:
    runtime: RuntimeImageAuthority
    workspace: WorkspaceAuthority
    backend: BackendContextAuthority
    provider: ProviderLifecycle
    guest_admission: OciGuestAdmissionAuthority
    extinction: ExtinctionAuthority
    artifacts: ArtifactAuthority
    exporter: ExportAuthority
    journal: DurableJournal
    recovery: RecoveryAuthority

    def __post_init__(self) -> None:
        requirements = (
            (self.runtime, ("authenticate",)),
            (self.workspace, ("admit_target", "revalidate_target", "prepare_layout", "resume_layout", "write_guest_config", "recensus_layout")),
            (self.backend, ("authenticate",)),
            (self.provider, ("provider_kind", "create_stopped", "inspect_stopped", "resume_guest", "start_driver", "wait_driver", "delete_guest")),
            (self.guest_admission, ("admit_stopped_guest", "resume_admission")),
            (self.extinction, ("extinguish",)),
            (self.artifacts, ("census",)),
            (self.exporter, ("export",)),
            (self.journal, ("open", "arm", "commit", "resolve", "finish")),
            (self.recovery, ("recover",)),
        )
        for authority, names in requirements:
            if authority is None:
                raise SupervisorError("a required native/provider authority is absent")
            for name in names:
                failed = False
                try:
                    member = getattr(authority, name)
                except BaseException:
                    failed = True
                    member = None
                if failed or not callable(member):
                    raise SupervisorError("a required native/provider authority is absent")


@dataclass(frozen=True, slots=True)
class SupervisorResult:
    request_id: str
    attempt_id: str
    run_id: str
    provider_kind: ProviderKind
    checkpoint_sha256: str
    export_sha256: str
    artifact_count: int
    artifact_bytes: int
    driver_exit_code: int
    completion_status: SupervisorCompletionStatus
    artifacts_complete: bool
    guest_absent: bool
    target_unchanged: bool

    def __post_init__(self) -> None:
        _identifier(self.request_id, "result request ID")
        _identifier(self.attempt_id, "result attempt ID")
        _identifier(self.run_id, "result run ID")
        if type(self.provider_kind) is not ProviderKind:
            raise SupervisorError("result provider kind is invalid")
        _digest(self.checkpoint_sha256, "result checkpoint")
        _digest(self.export_sha256, "result export")
        _bounded_int(self.artifact_count, "result artifact count", 0, MAX_EXPORT_FILES)
        _bounded_int(self.artifact_bytes, "result artifact bytes", 0, MAX_EXPORT_TOTAL_BYTES)
        _bounded_int(self.driver_exit_code, "result exit code", 0, 255)
        expected_status = (
            SupervisorCompletionStatus.SUCCEEDED
            if self.driver_exit_code == 0
            else SupervisorCompletionStatus.DRIVER_FAILED
        )
        if type(self.completion_status) is not SupervisorCompletionStatus or self.completion_status is not expected_status:
            raise SupervisorError("supervisor result completion status is invalid")
        if (
            self.artifacts_complete is not True
            or self.guest_absent is not True
            or self.target_unchanged is not True
        ):
            raise SupervisorError("supervisor result lacks terminal safety")


def _safe_call(message: str, callback: Callable[[], Any]) -> Any:
    failed = False
    try:
        value = callback()
    except Exception:
        failed = True
        value = None
    if failed:
        # Raised outside the handler so injected paths, argv, credentials, and
        # provider diagnostics are absent from both cause and context.
        raise SupervisorError(message)
    return value


def _require_receipt(condition: bool, message: str) -> None:
    if condition is not True:
        raise SupervisorError(message)


def _target_recensus(
    request: AuditRequest, authorities: SupervisorAuthorities, target: TargetLease,
    *, expected_content_sha256: str | None = None,
) -> TargetRecensus:
    expected_content = (
        target.content_sha256
        if expected_content_sha256 is None
        else _digest(expected_content_sha256, "expected target content")
    )

    def inspect() -> TargetRecensus:
        observed = authorities.workspace.revalidate_target(request, target)
        if type(observed) is not TargetRecensus or (
            observed.target_handle != target.target_handle
            or observed.identity_sha256 != target.identity_sha256
            or observed.content_sha256 != expected_content
            or observed.readonly is not True
            or observed.scratchpad_absent is not True
        ):
            raise SupervisorError("host target recensus is not coherent")
        return observed

    return _safe_call("host target recensus failed", inspect)


def _validate_ticket(
    request: AuditRequest, checkpoint: SupervisorCheckpoint,
    operation: MutationOperation, ticket: Any,
) -> MutationTicket:
    if type(ticket) is not MutationTicket or (
        ticket.operation is not operation
        or ticket.request_fingerprint_sha256 != request.fingerprint_sha256
        or ticket.attempt_id != request.attempt_id
        or ticket.before_checkpoint_sha256 != checkpoint.checkpoint_sha256
        or ticket.authenticated is not True
    ):
        raise SupervisorAmbiguousError("durable journal returned an invalid mutation ticket")
    return ticket


def _validate_recovered_checkpoint(
    before: SupervisorCheckpoint, operation: MutationOperation,
    resolution: RecoveryResolution,
) -> SupervisorCheckpoint:
    if resolution.status is RecoveryStatus.UNPROVEN or resolution.checkpoint is None:
        raise SupervisorAmbiguousError("pending mutation recovery is unproven")
    recovered = resolution.checkpoint
    if recovered.request_fingerprint_sha256 != before.request_fingerprint_sha256 or recovered.attempt_id != before.attempt_id or recovered.run_id != before.run_id:
        raise SupervisorAmbiguousError("pending mutation recovery changed request identity")
    if resolution.status is RecoveryStatus.NOT_APPLIED:
        if recovered != before:
            raise SupervisorAmbiguousError("not-applied recovery changed the checkpoint")
        return recovered
    index = _STAGES.index(before.stage)
    if index >= len(_OPERATIONS) or _OPERATIONS[index] is not operation:
        raise SupervisorAmbiguousError("pending mutation operation is out of order")
    if recovered.stage is not _STAGES[index + 1] or recovered.receipts[:-1] != before.receipts:
        raise SupervisorAmbiguousError("applied recovery did not advance exactly one stage")
    # Re-run the same typed transition validator over recovered evidence.
    if advance_checkpoint(before, operation, recovered.receipts[-1]) != recovered:
        raise SupervisorAmbiguousError("applied recovery checkpoint is not canonical")
    return recovered


def _recover_pending(
    request: AuditRequest, authorities: SupervisorAuthorities,
    before: SupervisorCheckpoint, ticket: MutationTicket,
    validate_receipt: Callable[[Any], None] | None = None,
) -> tuple[SupervisorCheckpoint, RecoveryStatus]:
    if ticket.before_checkpoint_sha256 != before.checkpoint_sha256:
        raise SupervisorAmbiguousError("pending mutation is not bound to its checkpoint")
    failed = False
    try:
        resolution = authorities.recovery.recover(request, ticket, before)
    except Exception:
        failed = True
        resolution = None
    if failed or type(resolution) is not RecoveryResolution or resolution.ticket != ticket:
        raise SupervisorAmbiguousError("pending mutation recovery is unavailable")
    recovered = _validate_recovered_checkpoint(before, ticket.operation, resolution)
    if (
        resolution.status is RecoveryStatus.APPLIED
        and validate_receipt is not None
    ):
        validate_receipt(recovered.receipts[-1])
    resolve_failed = False
    try:
        resolved = authorities.journal.resolve(request, ticket, recovered)
    except Exception:
        resolve_failed = True
        resolved = False
    if resolve_failed or resolved is not True:
        raise SupervisorAmbiguousError("durable recovery commit is unproven")
    return recovered, resolution.status


_R = TypeVar("_R")


def _mutate(
    request: AuditRequest,
    authorities: SupervisorAuthorities,
    target: TargetLease,
    checkpoint: SupervisorCheckpoint,
    operation: MutationOperation,
    effect: Callable[[MutationTicket], _R],
    validate_receipt: Callable[[_R], None] | None = None,
    *, expected_target_content_sha256: str | None = None,
) -> SupervisorCheckpoint:
    _target_recensus(
        request, authorities, target,
        expected_content_sha256=expected_target_content_sha256,
    )
    arm_failed = False
    try:
        ticket_value = authorities.journal.arm(
            request, operation, checkpoint.checkpoint_sha256
        )
    except Exception:
        arm_failed = True
        ticket_value = None
    if arm_failed:
        raise SupervisorAmbiguousError("durable mutation arming failed")
    ticket = _validate_ticket(request, checkpoint, operation, ticket_value)

    effect_failed = False
    try:
        receipt = effect(ticket)
        if validate_receipt is not None:
            validate_receipt(receipt)
        advanced = advance_checkpoint(checkpoint, operation, receipt)
    except Exception:
        effect_failed = True
        advanced = None
    if effect_failed:
        recovered, status = _recover_pending(
            request, authorities, checkpoint, ticket, validate_receipt
        )
        if status is RecoveryStatus.NOT_APPLIED:
            raise SupervisorRetryRequired("mutation was not applied; normalized request may be retried")
        return recovered

    commit_failed = False
    try:
        committed = authorities.journal.commit(request, ticket, advanced)
    except Exception:
        commit_failed = True
        committed = False
    if commit_failed or committed is not True:
        recovered, status = _recover_pending(
            request, authorities, checkpoint, ticket, validate_receipt
        )
        if status is RecoveryStatus.NOT_APPLIED:
            raise SupervisorAmbiguousError("mutation receipt exists but durable recovery denies its effect")
        return recovered
    return advanced


def _cohere_runtime(request: AuditRequest, value: Any) -> AuthenticatedRuntimeImageLayout:
    if type(value) is not AuthenticatedRuntimeImageLayout or (
        value.runtime_layout_sha256 != request.runtime_layout_sha256
        or value.image_manifest_digest != request.image_manifest_digest
        or value.image_closure_sha256 != request.image_closure_sha256
        or value.docs_sha256 != request.docs_sha256
    ):
        raise SupervisorError("authenticated runtime/image layout differs from request")
    return value


def _cohere_target(request: AuditRequest, value: Any) -> TargetLease:
    if type(value) is not TargetLease or value.identity_sha256 != request.target_identity_sha256:
        raise SupervisorError("authenticated target differs from request")
    return value


def _cohere_backend(request: AuditRequest, value: Any) -> BackendContext:
    if type(value) is not BackendContext or (
        value.backend != request.backend
        or value.context_sha256 != request.backend_context_sha256
        or value.backend_admission_sha256 != request.backend_admission_sha256
        or value.egress_policy_sha256 != request.egress_policy_sha256
        or value.egress_admission_sha256 != request.egress_admission_sha256
        or value.credential_sha256 != request.credential_bundle_sha256
        or value.credential_isolation_sha256
           != request.credential_isolation_sha256
    ):
        raise SupervisorError("authenticated backend/egress context differs from request")
    return value


def _mounts(
    runtime: AuthenticatedRuntimeImageLayout,
    layout: AttemptLayout,
    backend: BackendContext,
    provider_kind: ProviderKind,
) -> tuple[GuestMount, ...]:
    sources = (
        layout.merged_handle, layout.scratch_handle, layout.state_handle,
        layout.control_handle, layout.seccomp_handle, backend.credential_handle,
        backend.context_handle, runtime.runtime_handle, runtime.docs_handle,
        layout.scope_handle,
    )
    return tuple(
        GuestMount(purpose, source, destination, mode)
        for (purpose, destination, mode), source in zip(
            _provider_mount_policy(provider_kind), sources, strict=True
        )
    )


def _expected_guest_config(request: AuditRequest) -> GuestConfig:
    document = request.source_config.document
    document[REPORT_OUTPUT_CONFIG_KEY] = GUEST_REPORT_PATH
    rendered = _canonical_bytes(document)
    return GuestConfig(
        request.source_config.retained_source_handle,
        rendered,
        hashlib.sha256(rendered).hexdigest(),
    )


def _control_content_sha256(
    request: AuditRequest, configured: ConfigReceipt,
) -> str:
    return canonical_sha256(
        {
            "config_sha256": configured.config_sha256,
            "startup_decision_receipt_sha256":
                request.startup_decision_receipt_sha256,
        }
    )


def _validate_layout_recensus_value(
    request: AuditRequest, target: TargetLease, layout: AttemptLayout,
    runtime: AuthenticatedRuntimeImageLayout, backend: BackendContext,
    configured: ConfigReceipt, phase: str, value: Any,
    provider_kind: ProviderKind,
) -> LayoutRecensus:
    expected_handles = (
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
    expected_content: tuple[str | None, ...] = (
        target.content_sha256,
        None,
        None,
        None,
        _control_content_sha256(request, configured),
        layout.seccomp_sha256,
        backend.credential_sha256,
        backend.context_sha256,
        runtime.runtime_layout_sha256,
        runtime.docs_sha256,
        layout.scope_sha256,
    )

    if type(value) is not LayoutRecensus or (
        value.attempt_id != request.attempt_id
        or value.layout_handle != layout.layout_handle
        or value.target_identity_sha256 != target.identity_sha256
        or value.target_content_sha256 != target.content_sha256
        or value.phase != phase
        or value.target_lower_readonly is not True
        or value.workload_nonexecuting is not True
    ):
        raise SupervisorError("attempt layout recensus is not coherent")
    roster = tuple(
        (row.purpose, row.attachment, row.mode)
        for row in value.components
    )
    handles = tuple(row.source_handle for row in value.components)
    expected_roster = (
        _APPLE_CONTAINER_LAYOUT_COMPONENT_POLICY
        if provider_kind is ProviderKind.APPLE_CONTAINER
        else _LINUX_OVERLAY_LAYOUT_COMPONENT_POLICY
    )
    if roster != expected_roster or handles != expected_handles:
        raise SupervisorError("layout component roster differs from held authorities")
    if any(
        expected is not None and row.content_sha256 != expected
        for row, expected in zip(
            value.components, expected_content, strict=True
        )
    ):
        raise SupervisorError("layout component content differs from held authorities")
    identities = tuple(row.identity_sha256 for row in value.components)
    mount_identities = tuple(
        row.provider_mount_identity_sha256 for row in value.components
    )
    if (
        len(set(identities)) != len(identities)
        or len(set(mount_identities)) != len(mount_identities)
    ):
        raise SupervisorError("layout component identities overlap")
    return value


def _layout_recensus(
    request: AuditRequest, authorities: SupervisorAuthorities,
    target: TargetLease, layout: AttemptLayout,
    runtime: AuthenticatedRuntimeImageLayout, backend: BackendContext,
    configured: ConfigReceipt, phase: str, provider_kind: ProviderKind,
) -> LayoutRecensus:
    def inspect() -> LayoutRecensus:
        value = authorities.workspace.recensus_layout(
            request, target, layout, runtime, backend, configured, phase
        )
        return _validate_layout_recensus_value(
            request, target, layout, runtime, backend, configured, phase, value,
            provider_kind,
        )

    return _safe_call("attempt layout recensus failed", inspect)


def _validate_layout_delta(
    precreate: LayoutRecensus, postcreate: LayoutRecensus,
) -> str:
    if (
        type(precreate) is not LayoutRecensus
        or type(postcreate) is not LayoutRecensus
        or precreate.phase != "PRE_CREATE"
        or postcreate.phase != "POST_CREATE"
        or precreate.attempt_id != postcreate.attempt_id
        or precreate.layout_handle != postcreate.layout_handle
        or precreate.target_identity_sha256 != postcreate.target_identity_sha256
        or precreate.target_content_sha256 != postcreate.target_content_sha256
        or precreate.layout_sha256 != postcreate.layout_sha256
        or len(precreate.components) != len(postcreate.components)
    ):
        raise SupervisorError("pre/post-create layout stable facts drifted")
    deltas: list[tuple[str, str, str]] = []
    for before, after in zip(
        precreate.components, postcreate.components, strict=True
    ):
        if (
            before.purpose != after.purpose
            or before.source_handle != after.source_handle
            or before.attachment != after.attachment
            or before.mode != after.mode
            or before.identity_sha256 != after.identity_sha256
            or before.content_sha256 != after.content_sha256
        ):
            raise SupervisorError("pre/post-create layout component drifted")
        deltas.append(
            (
                before.purpose,
                before.provider_mount_identity_sha256,
                after.provider_mount_identity_sha256,
            )
        )
    return canonical_sha256(tuple(deltas))


def _validate_artifact_census(
    request: AuditRequest, exited: DriverExitReceipt,
    terminal: ExtinctionReceipt, census: ArtifactCensus,
) -> None:
    if (
        census.attempt_id != request.attempt_id
        or census.run_id != request.run_id
        or census.terminal_sha256 != terminal.terminal_sha256
        or census.driver_exit_code != exited.exit_code
        or census.exact is not True
        or census.immutable_lease is not True
    ):
        raise SupervisorError("artifact census is not terminal/run-bound")
    allowlist = frozenset(request.export_allowlist)
    total = 0
    entries = census.entries
    if (
        type(entries) is not tuple
        or len(entries) > MAX_EXPORT_FILES
        or any(type(entry) is not ArtifactEntry for entry in entries)
    ):
        raise SupervisorError("artifact census entries are malformed or oversized")
    _validate_artifact_paths(
        tuple(entry.relative_path for entry in entries), "artifact census paths"
    )
    for entry in entries:
        _relative_artifact(entry.relative_path, "artifact path")
        _bounded_int(entry.size, "artifact size", 0, MAX_EXPORT_FILE_BYTES)
        _digest(entry.sha256, "artifact sha256")
        if (
            entry.object_kind != "regular"
            or entry.symlink is not False
            or entry.hardlink_count != 1
        ):
            raise SupervisorError("artifact census contains an unsafe filesystem object")
        if entry.relative_path not in allowlist:
            raise SupervisorError("artifact census contains a non-allowlisted path")
        total += entry.size
        if total > request.export_max_total_bytes:
            raise SupervisorError("artifact census exceeds the request byte ceiling")
    required = set(request.required_artifacts)
    if exited.exit_code != 0:
        required.update(request.failure_required_artifacts)
    dispositions = census.dispositions
    if (
        type(dispositions) is not tuple
        or any(type(row) is not ArtifactDisposition for row in dispositions)
        or tuple(row.relative_path for row in dispositions)
        != tuple(sorted(required))
    ):
        raise SupervisorError("artifact dispositions differ from required denominator")
    entries_by_path = {entry.relative_path: entry for entry in entries}
    for disposition in dispositions:
        entry = entries_by_path.get(disposition.relative_path)
        if (
            disposition.status != "PRESENT"
            or entry is None
            or disposition.entry_sha256 != entry.sha256
        ):
            raise SupervisorError("required audit artifact is missing")
    expected = canonical_sha256(
        {
            "attempt_id": census.attempt_id,
            "run_id": census.run_id,
            "terminal_sha256": census.terminal_sha256,
            "driver_exit_code": census.driver_exit_code,
            "census_handle": census.census_handle,
            "entries": census.entries,
            "dispositions": census.dispositions,
        }
    )
    if census.census_sha256 != expected:
        raise SupervisorError("artifact census digest differs from exact entries")


def _expected_export_manifest(
    request: AuditRequest, census: ArtifactCensus,
) -> str:
    if census.driver_exit_code != 0:
        raise SupervisorError(
            "failed driver artifacts cannot enter report publication"
        )
    report = next(
        (
            entry for entry in census.entries
            if entry.relative_path == STAGED_REPORT_ARTIFACT
        ),
        None,
    )
    if type(report) is not ArtifactEntry:
        raise SupervisorError("terminal census lacks the staged audit report")
    return canonical_sha256(
        {
            "attempt_id": request.attempt_id,
            "run_id": request.run_id,
            "census_sha256": census.census_sha256,
            "destination_identity_sha256":
                request.export_destination_identity_sha256,
            "entries": census.entries,
            "dispositions": census.dispositions,
            "report_publication": {
                "status": "PUBLISHED",
                "guest_staging_path": GUEST_REPORT_PATH,
                "census_relative_path": STAGED_REPORT_ARTIFACT,
                "target_relative_path": PUBLISHED_REPORT_PATH,
                "size": report.size,
                "sha256": report.sha256,
            },
        }
    )


def _expected_export_sha256(
    request: AuditRequest, layout: AttemptLayout, census: ArtifactCensus,
) -> str:
    """Bind one export receipt to exact staged bytes and publication policy."""

    return canonical_sha256(
        {
            "attempt_id": request.attempt_id,
            "run_id": request.run_id,
            "terminal_sha256": census.terminal_sha256,
            "driver_exit_code": census.driver_exit_code,
            "census_sha256": census.census_sha256,
            "destination_handle": layout.export_destination_handle,
            "destination_identity_sha256":
                request.export_destination_identity_sha256,
            "exported_count": len(census.entries),
            "exported_bytes": sum(entry.size for entry in census.entries),
            "manifest_sha256": _expected_export_manifest(request, census),
        }
    )


def _expected_target_content_after_export(
    target: TargetLease, census: ArtifactCensus,
) -> str:
    """Expected semantic target census after the publication transaction."""

    if census.driver_exit_code != 0:
        raise SupervisorError(
            "failed driver artifacts cannot enter report publication"
        )
    report = next(
        (
            entry for entry in census.entries
            if entry.relative_path == STAGED_REPORT_ARTIFACT
        ),
        None,
    )
    if type(report) is not ArtifactEntry:
        raise SupervisorError("terminal census lacks the staged audit report")
    return canonical_sha256(
        {
            "source_content_sha256": target.content_sha256,
            "published_artifact": {
                "relative_path": PUBLISHED_REPORT_PATH,
                "size": report.size,
                "sha256": report.sha256,
            },
        }
    )


def _validate_export_receipt(
    request: AuditRequest, layout: AttemptLayout, census: ArtifactCensus,
    exported: Any,
) -> None:
    expected_bytes = sum(row.size for row in census.entries)
    if (
        type(exported) is not ExportReceipt
        or exported.attempt_id != request.attempt_id
        or exported.run_id != request.run_id
        or exported.census_sha256 != census.census_sha256
        or exported.destination_handle != layout.export_destination_handle
        or exported.destination_identity_sha256
        != request.export_destination_identity_sha256
        or exported.exported_count != len(census.entries)
        or exported.exported_bytes != expected_bytes
        or exported.manifest_sha256
        != _expected_export_manifest(request, census)
        or exported.export_sha256
        != _expected_export_sha256(request, layout, census)
        or exported.complete is not True
    ):
        raise SupervisorError("export receipt differs from exact artifact census")


def _expected_target_content_for_checkpoint(
    target: TargetLease, checkpoint: SupervisorCheckpoint,
) -> str:
    if (
        _STAGES.index(checkpoint.stage)
        < _STAGES.index(SupervisorStage.EXPORTED)
    ):
        return target.content_sha256
    return _expected_target_content_after_export(
        target, checkpoint.receipt(ArtifactCensus)
    )


def _validate_checkpoint_evidence(
    request: AuditRequest,
    runtime: AuthenticatedRuntimeImageLayout,
    target: TargetLease,
    backend: BackendContext,
    provider_kind: ProviderKind,
    checkpoint: SupervisorCheckpoint,
) -> SupervisorCheckpoint:
    """Recheck all durable evidence and cross-receipt bindings.

    Dataclass construction is not treated as authentication.  The durable
    journal/recovery boundary supplies authenticity, while this function
    independently checks its entire semantic chain before any next effect.
    """
    if type(checkpoint) is not SupervisorCheckpoint:
        raise SupervisorError("durable checkpoint type is invalid")
    checkpoint.__post_init__()
    if (
        checkpoint.request_fingerprint_sha256 != request.fingerprint_sha256
        or checkpoint.attempt_id != request.attempt_id
        or checkpoint.run_id != request.run_id
    ):
        raise SupervisorError("durable checkpoint differs from request identity")

    stage_index = _STAGES.index(checkpoint.stage)
    if stage_index == 0:
        return checkpoint

    layout = checkpoint.receipt(AttemptLayout)
    if (
        layout.attempt_id != request.attempt_id
        or layout.run_id != request.run_id
        or layout.target_lower_handle != target.target_handle
        or layout.target_identity_sha256 != target.identity_sha256
        or layout.scope_sha256 != request.scope_sha256
        or layout.seccomp_sha256 != request.seccomp_profile_sha256
        or layout.export_destination_identity_sha256
        != request.export_destination_identity_sha256
    ):
        raise SupervisorError("durable layout evidence differs from request/target")
    if stage_index == 1:
        return checkpoint

    expected_config = _expected_guest_config(request)
    configured = checkpoint.receipt(ConfigReceipt)
    if (
        configured.attempt_id != request.attempt_id
        or configured.run_id != request.run_id
        or configured.source_config_sha256 != request.source_config_sha256
        or configured.startup_decision_receipt_sha256
        != request.startup_decision_receipt_sha256
        or configured.guest_config != expected_config
        or configured.config_sha256 != expected_config.config_sha256
    ):
        raise SupervisorError("durable configuration evidence differs from request")
    if stage_index == 2:
        return checkpoint

    created = checkpoint.receipt(GuestCreatedReceipt)
    expected_mounts = _mounts(runtime, layout, backend, provider_kind)
    expected_spec = GuestCreateSpec(
        request.attempt_id,
        request.image_manifest_digest,
        runtime.image_handle,
        request.image_closure_sha256,
        configured.config_sha256,
        created.create_spec.precreate_recensus,
        request.egress_policy_sha256,
        request.egress_admission_sha256,
        request.backend_admission_sha256,
        request.credential_isolation_sha256,
        request.provider_provenance_sha256,
        expected_mounts,
        f"plamen-{request.attempt_id}",
        provider_kind=provider_kind,
        platform_architecture=runtime.guest_architecture,
    )
    if (
        created.provider_kind is not provider_kind
        or created.attempt_id != request.attempt_id
        or created.create_spec != expected_spec
        or created.mount_roster_sha256 != canonical_sha256(expected_mounts)
        or created.state != "CREATED_STOPPED"
        or created.workload_started is not False
    ):
        raise SupervisorError("durable guest evidence differs from exact specification")
    _validate_layout_recensus_value(
        request, target, layout, runtime, backend, configured, "PRE_CREATE",
        created.create_spec.precreate_recensus, provider_kind,
    )
    if stage_index == 3:
        return checkpoint

    admission = checkpoint.receipt(GuestAdmissionReceipt)
    delta_sha256 = _validate_layout_delta(
        admission.precreate_recensus, admission.postcreate_recensus
    )
    if (
        admission.attempt_id != request.attempt_id
        or admission.guest_id != created.guest_id
        or admission.spec_sha256 != created.spec_sha256
        or admission.precreate_recensus != created.create_spec.precreate_recensus
        or admission.allowed_delta_sha256 != delta_sha256
        or admission.postcreate_recensus.provider_mounts_sha256
        != created.provider_mounts_sha256
        or admission.workload_nonexecuting is not True
        or admission.replay_consumed is not True
    ):
        raise SupervisorError("durable admission evidence differs from stopped guest")
    if stage_index == 4:
        return checkpoint

    expected_launch = DriverLaunch(
        request.attempt_id,
        created.guest_id,
        admission.admission_sha256,
        (
            runtime.python_path,
            "-B",
            runtime.driver_path,
            "/workspace/control/config.json",
            "--startup-intent",
            request.startup_intent,
            "--unattended",
            "--no-sleep",
            "--startup-decision-receipt",
            "/workspace/control/startup-decision.json",
        ),
    )
    started = checkpoint.receipt(DriverStartReceipt)
    if (
        started.attempt_id != request.attempt_id
        or started.guest_id != created.guest_id
        or started.launch_sha256 != expected_launch.launch_sha256
        or started.driver_process_count != 1
    ):
        raise SupervisorError("durable start evidence differs from the sole driver launch")
    if stage_index == 5:
        return checkpoint

    exited = checkpoint.receipt(DriverExitReceipt)
    if (
        exited.attempt_id != request.attempt_id
        or exited.guest_id != created.guest_id
        or exited.launch_sha256 != started.launch_sha256
    ):
        raise SupervisorError("durable wait evidence differs from the started driver")
    if stage_index == 6:
        return checkpoint

    terminal = checkpoint.receipt(ExtinctionReceipt)
    if (
        terminal.attempt_id != request.attempt_id
        or terminal.guest_id != created.guest_id
        or terminal.process_count != 0
        or terminal.cgroup_populated != 0
        or terminal.exact_attempt is not True
    ):
        raise SupervisorError("durable extinction evidence differs from the guest attempt")
    if stage_index == 7:
        return checkpoint

    census = checkpoint.receipt(ArtifactCensus)
    _validate_artifact_census(request, exited, terminal, census)
    if stage_index == 8:
        return checkpoint

    exported = checkpoint.receipt(ExportReceipt)
    try:
        _validate_export_receipt(request, layout, census, exported)
    except SupervisorError:
        raise SupervisorError(
            "durable export evidence differs from exact census"
        ) from None
    if stage_index == 9:
        return checkpoint

    deleted = checkpoint.receipt(DeleteReceipt)
    if (
        deleted.provider_kind is not provider_kind
        or deleted.attempt_id != request.attempt_id
        or deleted.guest_id != created.guest_id
        or deleted.terminal_sha256 != terminal.terminal_sha256
        or deleted.absent is not True
    ):
        raise SupervisorError("durable deletion evidence is incomplete")
    return checkpoint


def _result(
    request: AuditRequest, provider_kind: ProviderKind,
    checkpoint: SupervisorCheckpoint,
) -> SupervisorResult:
    exported = checkpoint.receipt(ExportReceipt)
    deleted = checkpoint.receipt(DeleteReceipt)
    exited = checkpoint.receipt(DriverExitReceipt)
    return SupervisorResult(
        request.request_id, request.attempt_id, request.run_id, provider_kind,
        checkpoint.checkpoint_sha256, exported.export_sha256,
        exported.exported_count, exported.exported_bytes, exited.exit_code,
        SupervisorCompletionStatus.SUCCEEDED
        if exited.exit_code == 0
        else SupervisorCompletionStatus.DRIVER_FAILED,
        True, deleted.absent, True,
    )


def _supervise_audit_with_authorities(
    request: AuditRequest,
    authorities: SupervisorAuthorities,
) -> SupervisorResult:
    """Run or recover one normalized audit request to terminal deletion.

    The function intentionally contains no phase loop.  The sole execution
    mutation is ``START_DRIVER`` with the exact existing driver command.
    """
    if type(request) is not AuditRequest or type(authorities) is not SupervisorAuthorities:
        raise SupervisorError("typed normalized request and supervisor authorities are required")

    runtime = _safe_call(
        "runtime/image authentication failed",
        lambda: _cohere_runtime(request, authorities.runtime.authenticate(request)),
    )
    target = _safe_call(
        "host target authentication failed",
        lambda: _cohere_target(request, authorities.workspace.admit_target(request)),
    )
    backend = _safe_call(
        "backend/egress authentication failed",
        lambda: _cohere_backend(request, authorities.backend.authenticate(request)),
    )

    provider_kind = _safe_call(
        "provider identity is unavailable", authorities.provider.provider_kind
    )
    if type(provider_kind) is not ProviderKind:
        raise SupervisorError("provider identity is invalid")
    if (
        provider_kind is ProviderKind.APPLE_CONTAINER
        and runtime.guest_architecture != "arm64"
    ):
        raise SupervisorError("Apple container runtime requires a linux/arm64 image")

    opened = _safe_call(
        "durable journal open failed", lambda: authorities.journal.open(request)
    )
    if type(opened) is not JournalOpenReceipt:
        raise SupervisorError("durable journal open receipt is invalid")
    opened = _safe_call(
        "durable journal open receipt is invalid",
        lambda: (opened.__post_init__(), opened)[1],
    )
    checkpoint = opened.checkpoint
    if (
        checkpoint.request_fingerprint_sha256 != request.fingerprint_sha256
        or checkpoint.attempt_id != request.attempt_id
        or checkpoint.run_id != request.run_id
    ):
        raise SupervisorError("durable journal checkpoint differs from request identity")
    if opened.status is JournalOpenStatus.REJECTED:
        raise SupervisorError("request replay or cross-attempt reuse was rejected")
    if opened.pending is not None:
        checkpoint, _status = _recover_pending(
            request, authorities, checkpoint, opened.pending
        )
    checkpoint = _safe_call(
        "durable checkpoint evidence is invalid",
        lambda: _validate_checkpoint_evidence(
            request, runtime, target, backend, provider_kind, checkpoint
        ),
    )
    _target_recensus(
        request, authorities, target,
        expected_content_sha256=_expected_target_content_for_checkpoint(
            target, checkpoint
        ),
    )
    if opened.status is JournalOpenStatus.COMPLETE:
        if checkpoint.stage is not SupervisorStage.DELETED:
            raise SupervisorError("completed journal lacks terminal checkpoint")
        return _result(request, provider_kind, checkpoint)

    layout: AttemptLayout | None = None
    created: GuestCreatedReceipt | None = None
    admission: GuestAdmissionReceipt | None = None
    if checkpoint.stage not in {SupervisorStage.EMPTY, SupervisorStage.DELETED}:
        stored_layout = checkpoint.receipt(AttemptLayout)
        layout = _safe_call(
            "attempt layout recovery failed",
            lambda: authorities.workspace.resume_layout(request, stored_layout),
        )
        if type(layout) is not AttemptLayout or layout != stored_layout:
            raise SupervisorError("recovered attempt layout differs from journal")
    if (
        _STAGES.index(checkpoint.stage)
        >= _STAGES.index(SupervisorStage.GUEST_CREATED)
        and checkpoint.stage is not SupervisorStage.DELETED
    ):
        stored_created = checkpoint.receipt(GuestCreatedReceipt)
        created = _safe_call(
            "provider guest recovery failed",
            lambda: authorities.provider.resume_guest(request, stored_created),
        )
        if type(created) is not GuestCreatedReceipt or created != stored_created or created.provider_kind is not provider_kind:
            raise SupervisorError("recovered guest differs from journal/provider")
    if checkpoint.stage is SupervisorStage.GUEST_ADMITTED:
        stored_admission = checkpoint.receipt(GuestAdmissionReceipt)
        stored_layout = checkpoint.receipt(AttemptLayout)
        stored_configured = checkpoint.receipt(ConfigReceipt)
        if created is None or layout is None:
            raise SupervisorError("admission checkpoint lacks its created guest")
        live_postcreate = _layout_recensus(
            request, authorities, target, stored_layout, runtime, backend,
            stored_configured, "POST_CREATE", provider_kind,
        )
        if (
            live_postcreate != stored_admission.postcreate_recensus
            or _validate_layout_delta(
                created.create_spec.precreate_recensus, live_postcreate
            ) != stored_admission.allowed_delta_sha256
            or live_postcreate.provider_mounts_sha256
            != created.provider_mounts_sha256
        ):
            raise SupervisorError(
                "recovered stopped layout differs from durable admission"
            )
        live_observation = _safe_call(
            "recovered stopped guest inspection failed",
            lambda: authorities.provider.inspect_stopped(created),
        )
        if type(live_observation) is not GuestObservation or (
            live_observation.provider_kind is not provider_kind
            or live_observation.guest_id != created.guest_id
            or live_observation.spec_sha256 != created.spec_sha256
            or live_observation.mount_roster_sha256
            != created.mount_roster_sha256
            or live_observation.provider_mounts_sha256
            != created.provider_mounts_sha256
            or live_observation.state != "CREATED_STOPPED"
            or live_observation.workload_process_count != 0
        ):
            raise SupervisorError(
                "recovered admission is not bound to the held stopped guest"
            )
        admission = _safe_call(
            "guest admission recovery failed",
            lambda: authorities.guest_admission.resume_admission(
                request, created, stored_admission
            ),
        )
        if type(admission) is not GuestAdmissionReceipt or admission != stored_admission:
            raise SupervisorError("recovered guest admission differs from journal")

    while checkpoint.stage is not SupervisorStage.DELETED:
        checkpoint = _safe_call(
            "durable checkpoint evidence is invalid",
            lambda: _validate_checkpoint_evidence(
                request, runtime, target, backend, provider_kind, checkpoint
            ),
        )
        stage = checkpoint.stage
        if stage is SupervisorStage.EMPTY:
            checkpoint = _mutate(
                request, authorities, target, checkpoint,
                MutationOperation.PREPARE_LAYOUT,
                lambda ticket: authorities.workspace.prepare_layout(request, target, ticket),
                lambda receipt: _require_receipt(
                    type(receipt) is AttemptLayout
                    and receipt.attempt_id == request.attempt_id
                    and receipt.run_id == request.run_id
                    and receipt.target_lower_handle == target.target_handle
                    and receipt.target_identity_sha256 == target.identity_sha256
                    and receipt.scope_sha256 == request.scope_sha256
                    and receipt.seccomp_sha256
                    == request.seccomp_profile_sha256
                    and receipt.export_destination_identity_sha256
                    == request.export_destination_identity_sha256,
                    "prepared attempt layout differs from request/target",
                ),
            )
            layout = checkpoint.receipt(AttemptLayout)
            if (
                layout.attempt_id != request.attempt_id
                or layout.run_id != request.run_id
                or layout.target_lower_handle != target.target_handle
                or layout.target_identity_sha256 != target.identity_sha256
                or layout.scope_sha256 != request.scope_sha256
                or layout.seccomp_sha256 != request.seccomp_profile_sha256
                or layout.export_destination_identity_sha256
                != request.export_destination_identity_sha256
            ):
                raise SupervisorError("prepared attempt layout differs from request/target")
            continue

        if layout is None:
            raise SupervisorError("supervisor stage lacks its attempt layout")
        if stage is SupervisorStage.LAYOUT_READY:
            guest_config = _expected_guest_config(request)
            checkpoint = _mutate(
                request, authorities, target, checkpoint,
                MutationOperation.WRITE_CONFIG,
                lambda ticket: authorities.workspace.write_guest_config(
                    request, layout, guest_config, ticket
                ),
                lambda receipt: _require_receipt(
                    type(receipt) is ConfigReceipt
                    and receipt.attempt_id == request.attempt_id
                    and receipt.run_id == request.run_id
                    and receipt.source_config_sha256 == request.source_config_sha256
                    and receipt.startup_decision_receipt_sha256
                    == request.startup_decision_receipt_sha256
                    and receipt.guest_config == guest_config
                    and receipt.config_sha256 == guest_config.config_sha256,
                    "guest configuration receipt differs from normalized request",
                ),
            )
            configured = checkpoint.receipt(ConfigReceipt)
            if (
                configured.attempt_id != request.attempt_id
                or configured.run_id != request.run_id
                or configured.source_config_sha256 != request.source_config_sha256
                or configured.startup_decision_receipt_sha256 != request.startup_decision_receipt_sha256
                or configured.guest_config != guest_config
                or configured.config_sha256 != guest_config.config_sha256
            ):
                raise SupervisorError("guest configuration receipt differs from normalized request")
            continue

        configured = checkpoint.receipt(ConfigReceipt)
        if stage is SupervisorStage.CONFIG_READY:
            precreate = _layout_recensus(
                request, authorities, target, layout, runtime, backend,
                configured, "PRE_CREATE", provider_kind,
            )
            mount_roster = _mounts(runtime, layout, backend, provider_kind)
            spec = GuestCreateSpec(
                request.attempt_id, request.image_manifest_digest,
                runtime.image_handle, request.image_closure_sha256,
                configured.config_sha256, precreate,
                request.egress_policy_sha256,
                request.egress_admission_sha256,
                request.backend_admission_sha256,
                request.credential_isolation_sha256,
                request.provider_provenance_sha256,
                mount_roster, f"plamen-{request.attempt_id}",
                provider_kind=provider_kind,
                platform_architecture=runtime.guest_architecture,
            )
            checkpoint = _mutate(
                request, authorities, target, checkpoint,
                MutationOperation.CREATE_GUEST,
                lambda ticket: authorities.provider.create_stopped(spec, ticket),
                lambda receipt: _require_receipt(
                    type(receipt) is GuestCreatedReceipt
                    and receipt.provider_kind is provider_kind
                    and receipt.attempt_id == request.attempt_id
                    and receipt.create_spec == spec
                    and receipt.spec_sha256 == spec.spec_sha256
                    and receipt.mount_roster_sha256
                    == canonical_sha256(mount_roster)
                    and receipt.provider_mounts_sha256
                    != precreate.provider_mounts_sha256
                    and receipt.workload_started is False,
                    "created guest differs from exact stopped specification",
                ),
            )
            created = checkpoint.receipt(GuestCreatedReceipt)
            expected_mount_sha = canonical_sha256(mount_roster)
            if (
                created.provider_kind is not provider_kind
                or created.attempt_id != request.attempt_id
                or created.create_spec != spec
                or created.spec_sha256 != spec.spec_sha256
                or created.mount_roster_sha256 != expected_mount_sha
                or created.provider_mounts_sha256
                == precreate.provider_mounts_sha256
                or created.workload_started is not False
            ):
                raise SupervisorError("created guest differs from exact stopped specification")
            continue

        if created is None:
            raise SupervisorError("supervisor stage lacks its created guest")
        if stage is SupervisorStage.GUEST_CREATED:
            postcreate = _layout_recensus(
                request, authorities, target, layout, runtime, backend,
                configured, "POST_CREATE", provider_kind,
            )
            allowed_delta_sha256 = _validate_layout_delta(
                created.create_spec.precreate_recensus, postcreate
            )
            if (
                postcreate.provider_mounts_sha256
                != created.provider_mounts_sha256
            ):
                raise SupervisorError(
                    "post-create layout mount identities differ from provider receipt"
                )
            observation = _safe_call(
                "stopped guest inspection failed",
                lambda: authorities.provider.inspect_stopped(created),
            )
            if type(observation) is not GuestObservation or (
                observation.provider_kind is not provider_kind
                or observation.guest_id != created.guest_id
                or observation.spec_sha256 != created.spec_sha256
                or observation.mount_roster_sha256 != created.mount_roster_sha256
                or observation.provider_mounts_sha256
                != created.provider_mounts_sha256
                or observation.state != "CREATED_STOPPED"
                or observation.workload_process_count != 0
            ):
                raise SupervisorError("post-create guest is not the held stopped guest")
            checkpoint = _mutate(
                request, authorities, target, checkpoint,
                MutationOperation.ADMIT_GUEST,
                lambda ticket: authorities.guest_admission.admit_stopped_guest(
                    request, created, observation, postcreate, ticket
                ),
                lambda receipt: _require_receipt(
                    type(receipt) is GuestAdmissionReceipt
                    and receipt.attempt_id == request.attempt_id
                    and receipt.guest_id == created.guest_id
                    and receipt.precreate_recensus
                    == created.create_spec.precreate_recensus
                    and receipt.postcreate_recensus == postcreate
                    and receipt.allowed_delta_sha256
                    == allowed_delta_sha256
                    and receipt.spec_sha256 == created.spec_sha256,
                    "guest admission differs from stopped recensus",
                ),
            )
            admission = checkpoint.receipt(GuestAdmissionReceipt)
            if (
                admission.attempt_id != request.attempt_id
                or admission.guest_id != created.guest_id
                or admission.precreate_recensus
                != created.create_spec.precreate_recensus
                or admission.postcreate_recensus != postcreate
                or admission.allowed_delta_sha256 != allowed_delta_sha256
                or admission.spec_sha256 != created.spec_sha256
            ):
                raise SupervisorError("guest admission differs from stopped recensus")
            continue

        if stage is SupervisorStage.GUEST_ADMITTED:
            if admission is None:
                raise SupervisorError("supervisor stage lacks guest admission")
            argv = (
                runtime.python_path, "-B", runtime.driver_path,
                "/workspace/control/config.json", "--startup-intent",
                request.startup_intent, "--unattended", "--no-sleep",
                "--startup-decision-receipt",
                "/workspace/control/startup-decision.json",
            )
            launch = DriverLaunch(
                request.attempt_id, created.guest_id,
                admission.admission_sha256, argv,
            )
            checkpoint = _mutate(
                request, authorities, target, checkpoint,
                MutationOperation.START_DRIVER,
                lambda ticket: authorities.provider.start_driver(
                    created, admission, launch, ticket
                ),
                lambda receipt: _require_receipt(
                    type(receipt) is DriverStartReceipt
                    and receipt.attempt_id == request.attempt_id
                    and receipt.guest_id == created.guest_id
                    and receipt.launch_sha256 == launch.launch_sha256
                    and receipt.driver_process_count == 1,
                    "provider start did not bind exactly one driver",
                ),
            )
            started = checkpoint.receipt(DriverStartReceipt)
            if (
                started.attempt_id != request.attempt_id
                or started.guest_id != created.guest_id
                or started.launch_sha256 != launch.launch_sha256
                or started.driver_process_count != 1
            ):
                raise SupervisorError("provider start did not bind exactly one driver")
            continue

        started = checkpoint.receipt(DriverStartReceipt)
        if stage is SupervisorStage.DRIVER_STARTED:
            checkpoint = _mutate(
                request, authorities, target, checkpoint,
                MutationOperation.WAIT_DRIVER,
                lambda ticket: authorities.provider.wait_driver(
                    created, started, ticket
                ),
                lambda receipt: _require_receipt(
                    type(receipt) is DriverExitReceipt
                    and receipt.attempt_id == request.attempt_id
                    and receipt.guest_id == created.guest_id
                    and receipt.launch_sha256 == started.launch_sha256,
                    "driver wait receipt differs from started driver",
                ),
            )
            exited = checkpoint.receipt(DriverExitReceipt)
            if exited.attempt_id != request.attempt_id or exited.guest_id != created.guest_id or exited.launch_sha256 != started.launch_sha256:
                raise SupervisorError("driver wait receipt differs from started driver")
            continue

        exited = checkpoint.receipt(DriverExitReceipt)
        if stage is SupervisorStage.DRIVER_EXITED:
            checkpoint = _mutate(
                request, authorities, target, checkpoint,
                MutationOperation.EXTINGUISH,
                lambda ticket: authorities.extinction.extinguish(
                    request, created, exited, ticket
                ),
                lambda receipt: _require_receipt(
                    type(receipt) is ExtinctionReceipt
                    and receipt.attempt_id == request.attempt_id
                    and receipt.guest_id == created.guest_id
                    and receipt.process_count == 0
                    and receipt.cgroup_populated == 0,
                    "terminal proof differs from the exact guest attempt",
                ),
            )
            terminal = checkpoint.receipt(ExtinctionReceipt)
            if terminal.attempt_id != request.attempt_id or terminal.guest_id != created.guest_id or terminal.process_count != 0 or terminal.cgroup_populated != 0:
                raise SupervisorError("terminal proof differs from the exact guest attempt")
            continue

        terminal = checkpoint.receipt(ExtinctionReceipt)
        if stage is SupervisorStage.EXTINCT:
            checkpoint = _mutate(
                request, authorities, target, checkpoint,
                MutationOperation.CENSUS_ARTIFACTS,
                lambda ticket: authorities.artifacts.census(
                    request, layout, exited, terminal, ticket
                ),
                lambda receipt: _validate_artifact_census(
                    request, exited, terminal, receipt
                ),
            )
            census = checkpoint.receipt(ArtifactCensus)
            _validate_artifact_census(request, exited, terminal, census)
            continue

        census = checkpoint.receipt(ArtifactCensus)
        if stage is SupervisorStage.CENSUSED:
            _validate_artifact_census(request, exited, terminal, census)
            if exited.exit_code != 0:
                raise SupervisorError(
                    "driver failed; report publication is withheld"
                )
            checkpoint = _mutate(
                request, authorities, target, checkpoint,
                MutationOperation.EXPORT_ARTIFACTS,
                lambda ticket: authorities.exporter.export(
                    request, layout, census, ticket
                ),
                lambda receipt: _validate_export_receipt(
                    request, layout, census, receipt
                ),
            )
            exported = checkpoint.receipt(ExportReceipt)
            _validate_export_receipt(request, layout, census, exported)
            continue

        if stage is SupervisorStage.EXPORTED:
            expected_target_content = _expected_target_content_after_export(
                target, census
            )
            checkpoint = _mutate(
                request, authorities, target, checkpoint,
                MutationOperation.DELETE_GUEST,
                lambda ticket: authorities.provider.delete_guest(
                    created, terminal, ticket
                ),
                lambda receipt: _require_receipt(
                    type(receipt) is DeleteReceipt
                    and receipt.provider_kind is provider_kind
                    and receipt.attempt_id == request.attempt_id
                    and receipt.guest_id == created.guest_id
                    and receipt.terminal_sha256 == terminal.terminal_sha256
                    and receipt.absent is True,
                    "guest deletion receipt is incomplete",
                ),
                expected_target_content_sha256=expected_target_content,
            )
            deleted = checkpoint.receipt(DeleteReceipt)
            if deleted.provider_kind is not provider_kind or deleted.attempt_id != request.attempt_id or deleted.guest_id != created.guest_id or deleted.terminal_sha256 != terminal.terminal_sha256 or deleted.absent is not True:
                raise SupervisorError("guest deletion receipt is incomplete")
            continue

        raise SupervisorError("supervisor checkpoint stage is unsupported")

    checkpoint = _safe_call(
        "durable checkpoint evidence is invalid",
        lambda: _validate_checkpoint_evidence(
            request, runtime, target, backend, provider_kind, checkpoint
        ),
    )
    _target_recensus(
        request, authorities, target,
        expected_content_sha256=_expected_target_content_for_checkpoint(
            target, checkpoint
        ),
    )
    finish_failed = False
    try:
        finished = authorities.journal.finish(
            request, checkpoint.checkpoint_sha256
        )
    except Exception:
        finish_failed = True
        finished = False
    if finish_failed or finished is not True:
        raise SupervisorAmbiguousError("durable journal finalization is unproven")
    return _result(request, provider_kind, checkpoint)


def _supervise_audit_for_testing(
    request: AuditRequest, authorities: SupervisorAuthorities,
) -> SupervisorResult:
    """Private fake-only seam; never a production authority boundary."""
    return _supervise_audit_with_authorities(request, authorities)


_NATIVE_AUTHORITY_TYPES = (
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


def _native_supervisor_surface() -> tuple[
    type[Any], type[Any], tuple[type[Any], ...], object,
]:
    """Authenticate a preloaded, static native INITIAL_AUTHORITY surface."""
    try:
        module_table = types.ModuleType.__getattribute__(sys, "__dict__").get(
            "modules"
        )
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
        names = (
            "NativeAuthorityConsumer", "SupervisorAuthorities",
            *(name for name, _methods in _NATIVE_AUTHORITY_TYPES),
        )
        native_types = tuple(namespace.get(name) for name in names)
        metadata = (
            namespace.get("__name__"), namespace.get("__file__"),
            namespace.get("BROKER_V2_ABI_SCHEMA"),
            namespace.get("BROKER_V2_PRODUCTION_ACQUISITION"),
            spec_namespace.get("name"), spec_namespace.get("origin"),
            loader_namespace.get("name"), loader_namespace.get("path"),
        )
        if (any(type(item) is not str for item in metadata)
                or any(not item or len(item) > 4096 or "\x00" in item
                       for item in metadata)):
            raise TypeError
        name, module_file, abi, acquisition, spec_name, origin, loader_name, loader_path = metadata
        if (name != NATIVE_MODULE_NAME or spec_name != NATIVE_MODULE_NAME
                or loader_name != NATIVE_MODULE_NAME or module_file != origin
                or loader_path != origin or abi != NATIVE_ABI_SCHEMA
                or acquisition != NATIVE_PRODUCTION_ACQUISITION
                or namespace.get("TEST_ONLY_BUILD") is not False
                or namespace.get("BROKER_V2_INITIAL_AUTHORITY_AVAILABLE") is not True
                or not any(origin.endswith(suffix)
                           for suffix in importlib.machinery.EXTENSION_SUFFIXES)
                or any(type(item) is not type for item in native_types)):
            raise TypeError
        for native_type in native_types:
            if (type.__getattribute__(native_type, "__module__")
                    != NATIVE_MODULE_NAME
                    or type.__getattribute__(native_type, "__flags__") & (1 << 9)):
                raise TypeError
        consumer_type, bundle_type, *member_types = native_types
        for native_type, required_methods in (
            (consumer_type, ("request_projection", "consume_once")),
            (bundle_type, ("consume_once",)),
        ):
            native_namespace = type.__getattribute__(native_type, "__dict__")
            if (type(native_namespace) is not types.MappingProxyType
                    or any(
                        type(native_namespace.get(method))
                        is not types.MethodDescriptorType
                        for method in required_methods
                    )):
                raise TypeError
        for native_type, (_name, methods) in zip(
            member_types, _NATIVE_AUTHORITY_TYPES, strict=True
        ):
            native_namespace = type.__getattribute__(native_type, "__dict__")
            if (type(native_namespace) is not types.MappingProxyType
                    or any(type(native_namespace.get(method))
                           is not types.MethodDescriptorType
                           for method in methods)):
                raise TypeError
        initial = namespace.get("INITIAL_AUTHORITY")
        if type(initial) is not consumer_type:
            raise TypeError
        return consumer_type, bundle_type, tuple(member_types), initial
    except BaseException:
        pass
    raise SupervisorError(
        "native supervisor authority admission is unavailable"
    )


def supervise_audit(
    request: AuditRequest, native_consumer: object,
) -> SupervisorResult:
    """Consume one native-issued request-bound authority bundle and supervise.

    The trusted Python interpreter remains part of the TCB.  Python object
    shape, callability, module-name spoofing, or opaque-looking strings are not
    authentication.  Production is therefore unavailable until the fixed
    native extension supplies its non-constructible, one-shot consumer type.
    """
    if type(request) is not AuditRequest:
        raise SupervisorError("typed normalized audit request is required")
    native_type, bundle_type, member_types, initial = _native_supervisor_surface()
    if type(native_consumer) is not native_type or native_consumer is not initial:
        raise SupervisorError("native supervisor authority admission is unavailable")

    native_bundle = None
    consumption_failed = False
    try:
        native_bundle = native_consumer.consume_once(
            request.fingerprint_sha256, request.attempt_id
        )
    except BaseException:
        consumption_failed = True
    if consumption_failed or type(native_bundle) is not bundle_type:
        raise SupervisorError("native supervisor authority consumption failed")
    members = None
    consumption_failed = False
    try:
        members = native_bundle.consume_once()
    except BaseException:
        consumption_failed = True
    if (consumption_failed or type(members) is not tuple
            or len(members) != len(member_types)
            or any(type(member) is not expected
                   for member, expected in zip(members, member_types, strict=True))):
        raise SupervisorError("native supervisor authority consumption failed")
    try:
        from posix_native_authority_adapter import (
            adapt_native_supervisor_authorities,
        )
        authorities = adapt_native_supervisor_authorities(
            request, members, member_types,
        )
    except BaseException:
        raise SupervisorError(
            "native supervisor authority adaptation failed"
        ) from None
    return _supervise_audit_with_authorities(request, authorities)


__all__ = [
    "ArtifactAuthority", "ArtifactCensus", "ArtifactDisposition",
    "ArtifactEntry", "AttemptLayout", "AuditRequest",
    "AuthenticatedDriverConfig", "AuthenticatedRuntimeImageLayout", "BackendContext",
    "BackendContextAuthority", "ConfigReceipt", "DeleteReceipt",
    "DriverExitReceipt", "DriverLaunch", "DriverStartReceipt", "DurableJournal",
    "ExportAuthority", "ExportReceipt", "ExtinctionAuthority", "ExtinctionReceipt",
    "GuestAdmissionReceipt", "GuestConfig", "GuestCreateSpec", "GuestCreatedReceipt",
    "GuestMount", "GuestObservation", "JournalOpenReceipt", "JournalOpenStatus",
    "LayoutComponent", "LayoutRecensus", "MAX_EXPORT_FILE_BYTES", "MAX_EXPORT_FILES",
    "MAX_EXPORT_TOTAL_BYTES", "MutationOperation", "MutationTicket",
    "OciGuestAdmissionAuthority", "ProviderKind", "ProviderLifecycle",
    "RecoveryAuthority", "RecoveryResolution", "RecoveryStatus", "RequestType",
    "GUEST_REPORT_PATH", "PUBLISHED_REPORT_PATH", "REPORT_OUTPUT_CONFIG_KEY",
    "RESUME_EXISTING", "RuntimeImageAuthority", "SCHEMA", "STAGED_REPORT_ARTIFACT",
    "START_NEW_RUN",
    "SupervisorAmbiguousError", "SupervisorAuthorities", "SupervisorCheckpoint",
    "SupervisorCompletionStatus", "SupervisorError", "SupervisorResult", "SupervisorRetryRequired",
    "SupervisorStage", "TargetLease", "TargetRecensus", "WorkspaceAuthority",
    "advance_checkpoint", "canonical_sha256", "supervise_audit",
]
