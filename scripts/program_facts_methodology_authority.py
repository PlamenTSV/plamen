"""Installed-methodology authority for the typed Program Facts substrate.

The provider registry is policy, not data supplied by an audited repository.
This module captures that policy from the installed Plamen tree, binds it to
the already-canonical audit snapshot, and emits the exact immutable byte set
registered by ``recon/program_facts_bake`` PhaseIO.

The capture is deliberately one-shot.  Arbitrary registry bytes remain useful
for structural fixtures, but they cannot become production provider authority.
This module performs no environment discovery, dynamic import, subprocess,
network, model, or scratchpad operation.

This capture runs inside the Program Facts trusted computing base: the Python
orchestrator process, interpreter, loaded code objects and closure cells,
deterministic gate implementation, and installed methodology files protected
by deployment access controls.  Repository, worker, provider, model,
configuration, and artifact bytes remain untrusted data and are replayed
before use.

Arbitrary code execution or loaded-code/closure mutation inside that process
is a TCB compromise, not an input forgery this Python module can contain.
Preventing it requires OS process isolation and code/package/file integrity.
Private names, seals, weak registries, and closures are only defensive
programming mechanisms; they are not security boundaries.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import os
from pathlib import Path
import re
import threading
from types import MappingProxyType
from typing import Any, NoReturn
import weakref

from jsonschema import Draft202012Validator

from audit_snapshot import (
    SNAPSHOT_SCHEMA,
    build_methodology_snapshot_component,
)
from program_facts_types import (
    ProgramFactsTypeError,
    canonical_file_bytes,
    canonical_json_bytes,
    strict_json_loads,
)


METHODOLOGY_AUTHORITY_SCHEMA = (
    "plamen.program_facts_installed_methodology_authority.v1"
)
METHODOLOGY_PACKAGE_SCHEMA = (
    "plamen.program_facts_methodology_package.v1"
)
INSTALLED_METHODOLOGY_AUTHORITY = "INSTALLED_METHODOLOGY_AUTHORITY"
DEFAULT_MAX_AUTHORITY_BYTES = 16 * 1024 * 1024

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.ASCII,
)
_SCHEMA_FILENAMES = (
    "mechanical_program_facts.v1.schema.json",
    "mechanical_program_facts_receipt.v1.schema.json",
    "mechanical_program_facts_debt.v1.schema.json",
    "program_facts_provider_registry.v1.schema.json",
    "program_facts_disagreement.v1.schema.json",
    "program_facts_slice.v1.schema.json",
)

PROGRAM_FACTS_METHODOLOGY_INPUT_PATHS = (
    "_program_facts_methodology/program-facts-methodology-package.v1.json",
    "_program_facts_methodology/program-facts-provider-registry.v1.json",
    *tuple(
        f"_program_facts_methodology/schemas/{name}"
        for name in _SCHEMA_FILENAMES
    ),
)

_SNAPSHOT_COMPONENT_KEYS = frozenset(
    {"source_scope", "audit_config", "methodology", "toolchain"}
)
_METHODOLOGY_COMPONENT_KEYS = frozenset(
    {"digest", "path_set_digest", "file_count", "byte_count"}
)


class ProgramFactsMethodologyAuthorityError(ValueError):
    """Installed methodology could not establish exact replay authority."""


def _fail(message: str, exc: Exception | None = None) -> NoReturn:
    if exc is None:
        raise ProgramFactsMethodologyAuthorityError(message)
    raise ProgramFactsMethodologyAuthorityError(message) from exc


def _hex64(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX64_RE.fullmatch(value) is None:
        _fail(f"{label} must be a lowercase 64-hex digest")
    return value


def _schema_references_are_local(value: Any) -> bool:
    if isinstance(value, Mapping):
        reference = value.get("$ref")
        if reference is not None and (
            not isinstance(reference, str) or not reference.startswith("#/")
        ):
            return False
        return all(
            _schema_references_are_local(item) for item in value.values()
        )
    if isinstance(value, list):
        return all(_schema_references_are_local(item) for item in value)
    return True


def _is_reparse(path: Path) -> bool:
    try:
        return path.is_symlink() or bool(
            hasattr(path, "is_junction") and path.is_junction()
        )
    except OSError as exc:
        _fail(f"cannot inspect installed methodology path: {path}", exc)


def _installed_root() -> Path:
    """Derive the only legal root from this installed module location."""

    module_path = Path(__file__).absolute()
    root = module_path.parent.parent
    if _is_reparse(root) or _is_reparse(module_path.parent):
        _fail("installed methodology root is a symlink, junction, or reparse")
    try:
        resolved_root = root.resolve(strict=True)
        resolved_module = module_path.resolve(strict=True)
        resolved_module.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        _fail("installed methodology module/root containment is invalid", exc)
    if not resolved_root.is_dir() or not resolved_module.is_file():
        _fail("installed methodology module/root is unavailable")
    return resolved_root


def _fingerprint(path: Path) -> tuple[int, int, int, int, int]:
    try:
        stat = path.stat()
    except OSError as exc:
        _fail(f"cannot stat installed methodology input: {path}", exc)
    return (
        int(getattr(stat, "st_dev", 0)),
        int(getattr(stat, "st_ino", 0)),
        int(stat.st_size),
        int(stat.st_mtime_ns),
        int(stat.st_ctime_ns),
    )


def _stable_read(root: Path, relative: str, *, max_bytes: int) -> bytes:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        _fail("installed methodology identity must be portable relative text")
    path = root.joinpath(*relative.split("/"))
    if _is_reparse(path):
        _fail(f"installed methodology input is a symlink/reparse: {relative}")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        _fail(f"installed methodology input escapes its root: {relative}", exc)
    if not resolved.is_file():
        _fail(f"installed methodology input is not a regular file: {relative}")
    before = _fingerprint(resolved)
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        _fail(f"cannot read installed methodology input: {relative}", exc)
    after = _fingerprint(resolved)
    if before != after or len(raw) != after[2]:
        _fail(f"installed methodology input changed during capture: {relative}")
    if len(raw) > max_bytes:
        _fail(f"installed methodology input exceeds byte ceiling: {relative}")
    # A second exact read closes same-metadata substitutions on coarse filesystems.
    try:
        replay = resolved.read_bytes()
    except OSError as exc:
        _fail(f"cannot replay installed methodology input: {relative}", exc)
    if replay != raw or _fingerprint(resolved) != after:
        _fail(f"installed methodology input changed during replay: {relative}")
    return raw


def _validate_snapshot_bytes(raw: bytes) -> Mapping[str, Any]:
    try:
        value = strict_json_loads(
            raw,
            require_final_lf=True,
            require_canonical=True,
            max_bytes=DEFAULT_MAX_AUTHORITY_BYTES,
        )
    except ProgramFactsTypeError as exc:
        _fail(f"audit snapshot bytes are not canonical: {exc}", exc)
    if (
        not isinstance(value, Mapping)
        or set(value) != {"schema", "components", "snapshot_digest"}
        or value.get("schema") != SNAPSHOT_SCHEMA
        or not isinstance(value.get("components"), Mapping)
        or set(value["components"]) != _SNAPSHOT_COMPONENT_KEYS
    ):
        _fail("audit snapshot has schema/component drift")
    methodology = value["components"].get("methodology")
    if (
        not isinstance(methodology, Mapping)
        or set(methodology) != _METHODOLOGY_COMPONENT_KEYS
    ):
        _fail("audit snapshot methodology component has schema drift")
    supplied = _hex64(value["snapshot_digest"], "audit snapshot digest")
    unsigned = {
        "schema": value["schema"],
        "components": value["components"],
    }
    if hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest() != supplied:
        _fail("audit snapshot self-digest mismatch")
    return value


def _snapshot_from_checkpoint_bytes(
    checkpoint_raw: bytes,
) -> tuple[bytes, str, str]:
    """Extract the already-bound snapshot from exact checkpoint prestate."""

    try:
        checkpoint = strict_json_loads(
            checkpoint_raw,
            require_final_lf=False,
            require_canonical=False,
            max_bytes=DEFAULT_MAX_AUTHORITY_BYTES,
        )
    except ProgramFactsTypeError as exc:
        _fail(f"checkpoint bytes are invalid: {exc}", exc)
    if not isinstance(checkpoint, Mapping):
        _fail("checkpoint capture input must be an object")
    snapshot = checkpoint.get("audit_snapshot")
    run_id = checkpoint.get("run_id")
    if not isinstance(snapshot, Mapping):
        _fail("checkpoint has no bound audit_snapshot object")
    if not isinstance(run_id, str) or _UUID4_RE.fullmatch(run_id) is None:
        _fail("checkpoint has no canonical run_id authority")
    snapshot_raw = canonical_file_bytes(snapshot)
    _validate_snapshot_bytes(snapshot_raw)
    return (
        snapshot_raw,
        run_id,
        hashlib.sha256(checkpoint_raw).hexdigest(),
    )


def _module_source_identity(module_name: str) -> str:
    if not isinstance(module_name, str) or not re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_.]*", module_name
    ):
        _fail("provider adapter module identity is invalid")
    parts = module_name.split(".")
    if parts[0] == "scripts":
        parts = parts[1:]
    return "scripts/" + "/".join(parts) + ".py"


def _source_rows(
    root: Path,
    registry_value: Mapping[str, Any],
    *,
    max_bytes: int,
) -> tuple[dict[str, Any], ...]:
    identities: set[tuple[str, str]] = {
        ("REGISTRY_VALIDATOR", "scripts/program_facts_provider_registry.py"),
        ("PROVIDER_API", "scripts/program_facts_provider_api.py"),
        (
            "METHODOLOGY_AUTHORITY",
            "scripts/program_facts_methodology_authority.py",
        ),
        (
            "TOOL_AUTHORITY",
            "scripts/program_facts_evm_tool_authority.py",
        ),
        ("TYPE_VALIDATOR", "scripts/program_facts_types.py"),
        (
            "SOURCE_AUTHORITY",
            "scripts/program_facts_source_manifest.py",
        ),
        ("WORKER_ADAPTER", "scripts/program_facts_evm_wtx.py"),
        ("BUNDLE_COMPOSER", "scripts/program_facts_bake.py"),
        ("BOUND_LOADER", "scripts/program_facts_loader.py"),
    }
    expected_digests: dict[tuple[str, str], set[str]] = {}
    providers = registry_value.get("providers")
    if not isinstance(providers, list):
        _fail("installed provider registry providers denominator is invalid")
    for row in providers:
        if not isinstance(row, Mapping):
            _fail("installed provider registry contains a non-object row")
        adapter = row.get("adapter")
        raw_binding = row.get("raw_binding")
        tool_identity = row.get("tool_identity")
        invocation_policy = row.get("invocation_policy")
        if not isinstance(adapter, Mapping) or not isinstance(
            raw_binding, Mapping
        ):
            _fail("installed provider registry adapter/parser binding is invalid")
        if not isinstance(tool_identity, Mapping) or not isinstance(
            invocation_policy, Mapping
        ):
            _fail("installed provider registry tool/config binding is invalid")
        identity = _module_source_identity(str(adapter.get("module") or ""))
        identities.add(("ADAPTER", identity))
        expected_digests.setdefault(("ADAPTER", identity), set()).add(
            str(raw_binding.get("parser_source_digest") or "")
        )
        tool_module = str(tool_identity.get("module") or "")
        if tool_module:
            tool_source_identity = _module_source_identity(tool_module)
            identities.add(("TOOL_MODULE", tool_source_identity))
            expected_digests.setdefault(
                ("TOOL_MODULE", tool_source_identity),
                set(),
            ).add(str(tool_identity.get("module_sha256") or ""))
        configuration_inputs = invocation_policy.get(
            "configuration_inputs"
        )
        if not isinstance(configuration_inputs, list):
            _fail(
                "installed provider registry configuration denominator "
                "is invalid"
            )
        for configuration in configuration_inputs:
            if not isinstance(configuration, Mapping):
                _fail(
                    "installed provider registry configuration binding "
                    "is invalid"
                )
            configuration_identity = str(
                configuration.get("identity") or ""
            )
            if (
                not configuration_identity
                or "\\" in configuration_identity
                or configuration_identity.startswith(("/", "~"))
                or ".." in Path(configuration_identity).parts
            ):
                _fail(
                    "installed provider configuration identity is not "
                    "portable"
                )
            identities.add(
                ("PROVIDER_CONFIGURATION", configuration_identity)
            )
            expected_digests.setdefault(
                ("PROVIDER_CONFIGURATION", configuration_identity),
                set(),
            ).add(str(configuration.get("sha256") or ""))

    rows: list[dict[str, Any]] = []
    bytes_by_identity: dict[str, bytes] = {}
    for role, identity in sorted(identities):
        raw = bytes_by_identity.get(identity)
        if raw is None:
            raw = _stable_read(root, identity, max_bytes=max_bytes)
            bytes_by_identity[identity] = raw
        digest = hashlib.sha256(raw).hexdigest()
        expected = expected_digests.get((role, identity), set())
        if expected:
            if expected and expected != {digest}:
                _fail(
                    "installed provider implementation/configuration digest "
                    "differs from the reviewed registry"
                )
        rows.append(
            {
                "role": role,
                "identity": identity,
                "sha256": digest,
                "size_bytes": len(raw),
            }
        )
    return tuple(rows)


def _package_version(root: Path, *, max_bytes: int) -> tuple[str, str]:
    raw = _stable_read(root, "VERSION", max_bytes=max_bytes)
    try:
        text = raw.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        _fail("installed VERSION is not UTF-8", exc)
    if not text or "\n" in text or "\r" in text:
        _fail("installed VERSION is not one stable line")
    return text, hashlib.sha256(raw).hexdigest()


def _build_capture(
    checkpoint_bytes: bytes,
    *,
    max_bytes: int,
) -> tuple[
    Path,
    Mapping[str, Any],
    Mapping[str, bytes],
    str,
]:
    if (
        isinstance(max_bytes, bool)
        or not isinstance(max_bytes, int)
        or max_bytes <= 0
    ):
        _fail("methodology capture max_bytes must be positive")
    snapshot_bytes, audit_run_id, checkpoint_file_sha256 = (
        _snapshot_from_checkpoint_bytes(checkpoint_bytes)
    )
    snapshot = _validate_snapshot_bytes(snapshot_bytes)
    root = _installed_root()
    current_methodology = build_methodology_snapshot_component(root)
    if dict(snapshot["components"]["methodology"]) != current_methodology:
        _fail(
            "installed methodology differs from canonical audit snapshot "
            "methodology component"
        )

    registry_identity = "rules/program-facts-provider-registry.v1.json"
    registry_raw = _stable_read(root, registry_identity, max_bytes=max_bytes)
    try:
        registry_value = strict_json_loads(
            registry_raw,
            require_final_lf=True,
            require_canonical=True,
            max_bytes=max_bytes,
        )
    except ProgramFactsTypeError as exc:
        _fail(f"installed provider registry is not canonical: {exc}", exc)
    if not isinstance(registry_value, Mapping):
        _fail("installed provider registry must be an object")

    schema_rows: list[dict[str, Any]] = []
    phase_inputs: dict[str, bytes] = {}
    registry_phase_path = (
        "_program_facts_methodology/program-facts-provider-registry.v1.json"
    )
    phase_inputs[registry_phase_path] = registry_raw
    for name in _SCHEMA_FILENAMES:
        identity = f"rules/schemas/{name}"
        raw = _stable_read(root, identity, max_bytes=max_bytes)
        try:
            schema_value = strict_json_loads(
                raw,
                require_final_lf=True,
                require_canonical=False,
                max_bytes=max_bytes,
            )
        except ProgramFactsTypeError as exc:
            _fail(f"installed schema is not canonical: {identity}: {exc}", exc)
        if (
            not isinstance(schema_value, Mapping)
            or schema_value.get("$schema")
            != "https://json-schema.org/draft/2020-12/schema"
            or schema_value.get("additionalProperties") is not False
            or not _schema_references_are_local(schema_value)
        ):
            _fail(f"installed schema is not an independent closed schema: {identity}")
        try:
            Draft202012Validator.check_schema(schema_value)
        except Exception as exc:
            _fail(f"installed schema is invalid: {identity}", exc)
        phase_path = f"_program_facts_methodology/schemas/{name}"
        phase_inputs[phase_path] = raw
        schema_rows.append(
            {
                "installed_identity": identity,
                "phase_io_identity": phase_path,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size_bytes": len(raw),
            }
        )

    source_rows = _source_rows(
        root,
        registry_value,
        max_bytes=max_bytes,
    )
    version, version_file_sha256 = _package_version(
        root, max_bytes=max_bytes
    )
    registry_semantic_digest = hashlib.sha256(
        canonical_json_bytes(registry_value)
    ).hexdigest()
    revision_preimage = {
        "methodology_component_digest": current_methodology["digest"],
        "toolchain_component_digest": snapshot["components"]["toolchain"][
            "digest"
        ],
        "registry_file_sha256": hashlib.sha256(registry_raw).hexdigest(),
        "sources": list(source_rows),
        "schemas": schema_rows,
        "version_file_sha256": version_file_sha256,
    }
    revision_identity = hashlib.sha256(
        canonical_json_bytes(revision_preimage)
    ).hexdigest()
    package_unsigned = {
        "schema_version": METHODOLOGY_PACKAGE_SCHEMA,
        "authority": INSTALLED_METHODOLOGY_AUTHORITY,
        "audit_snapshot": {
            "audit_run_id": audit_run_id,
            "snapshot_digest": snapshot["snapshot_digest"],
            "methodology_component": dict(current_methodology),
            "toolchain_component_digest": snapshot["components"]["toolchain"][
                "digest"
            ],
        },
        "package_identity": {
            "name": "plamen",
            "version": version,
            "version_file_sha256": version_file_sha256,
            "revision_identity": revision_identity,
        },
        "registry": {
            "installed_identity": registry_identity,
            "phase_io_identity": registry_phase_path,
            "document_sha256": registry_semantic_digest,
            "file_sha256": hashlib.sha256(registry_raw).hexdigest(),
            "size_bytes": len(registry_raw),
            "release_state": str(registry_value.get("release_state") or ""),
        },
        "schemas": schema_rows,
        "implementation_sources": list(source_rows),
        "terminal_negative_authority": False,
    }
    package_digest = hashlib.sha256(
        canonical_json_bytes(package_unsigned)
    ).hexdigest()
    package = {**package_unsigned, "package_sha256": package_digest}
    package_raw = canonical_file_bytes(package)
    package_path = (
        "_program_facts_methodology/"
        "program-facts-methodology-package.v1.json"
    )
    ordered_inputs: dict[str, bytes] = {package_path: package_raw}
    for identity in PROGRAM_FACTS_METHODOLOGY_INPUT_PATHS[1:]:
        ordered_inputs[identity] = phase_inputs[identity]
    if tuple(ordered_inputs) != PROGRAM_FACTS_METHODOLOGY_INPUT_PATHS:
        _fail("installed methodology PhaseIO input denominator drift")

    capture_preimage = {
        "schema_version": METHODOLOGY_AUTHORITY_SCHEMA,
        "root_physical_identity": hashlib.sha256(
            os.fsencode(str(root))
        ).hexdigest(),
        "checkpoint_file_sha256": checkpoint_file_sha256,
        "audit_run_id": audit_run_id,
        "snapshot_digest": snapshot["snapshot_digest"],
        "package_sha256": package_digest,
        "phase_io_inputs": [
            {
                "identity": identity,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size_bytes": len(raw),
            }
            for identity, raw in ordered_inputs.items()
        ],
    }
    capture_digest = hashlib.sha256(
        canonical_json_bytes(capture_preimage)
    ).hexdigest()
    return (
        root,
        snapshot,
        MappingProxyType(ordered_inputs),
        capture_digest,
    )


def _make_consumption_registry():
    """Return one-shot replay tracking that is never authority evidence.

    The weak set only prevents accidental reuse of the same carrier object.
    Production authority is established independently by ``_build_capture``
    inside the consuming registry loader.
    """

    lock = threading.RLock()
    consumed: weakref.WeakSet[object] = weakref.WeakSet()

    def consume_once(value: object) -> None:
        with lock:
            if value in consumed:
                _fail(
                    "installed methodology authority is one-shot and consumed"
                )
            # Consume before replay: a failing or adversarial replay cannot
            # reset or reuse the same carrier object.
            consumed.add(value)

    return consume_once


_consume_methodology_carrier_once = _make_consumption_registry()
del _make_consumption_registry


class InstalledMethodologyAuthority:
    """Opaque one-shot capture of the installed Program Facts methodology."""

    __slots__ = (
        "_root",
        "_snapshot_bytes",
        "_checkpoint_bytes",
        "_audit_run_id",
        "_snapshot_digest",
        "_source_scope_digest",
        "_phase_io_inputs",
        "_capture_digest",
        "__weakref__",
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError(
            "InstalledMethodologyAuthority is capture-issued only"
        )

    @property
    def capture_digest(self) -> str:
        return self._capture_digest

    @property
    def snapshot_digest(self) -> str:
        return self._snapshot_digest

    @property
    def audit_run_id(self) -> str:
        return self._audit_run_id

    def _consume_and_replay(
        self,
    ) -> tuple[Mapping[str, bytes], str, str, str, str, bytes]:
        if type(self) is not InstalledMethodologyAuthority:
            _fail("installed methodology authority type is unsupported")
        _consume_methodology_carrier_once(self)
        try:
            checkpoint_bytes = bytes(self._checkpoint_bytes)
            captured_inputs = MappingProxyType(
                {
                    identity: bytes(raw)
                    for identity, raw in self._phase_io_inputs.items()
                }
            )
        except (AttributeError, TypeError, ValueError) as exc:
            _fail("installed methodology capture is incomplete", exc)
        (
            root,
            snapshot,
            replay_inputs,
            replay_capture_digest,
        ) = _build_capture(
            checkpoint_bytes,
            max_bytes=DEFAULT_MAX_AUTHORITY_BYTES,
        )
        replay_snapshot_bytes, replay_run_id, _checkpoint_digest = (
            _snapshot_from_checkpoint_bytes(checkpoint_bytes)
        )
        if (
            root != self._root
            or replay_snapshot_bytes != self._snapshot_bytes
            or snapshot["snapshot_digest"] != self._snapshot_digest
            or replay_run_id != self._audit_run_id
            or snapshot["components"]["source_scope"]["digest"]
            != self._source_scope_digest
            or replay_capture_digest != self._capture_digest
            or tuple(replay_inputs) != tuple(captured_inputs)
            or any(
                replay_inputs[key] != captured_inputs[key]
                for key in replay_inputs
            )
        ):
            _fail(
                "installed methodology authority mutation, substitution, "
                "or capture drift detected"
            )
        return (
            MappingProxyType(
                {
                    identity: bytes(raw)
                    for identity, raw in replay_inputs.items()
                }
            ),
            self._snapshot_digest,
            self._source_scope_digest,
            self._audit_run_id,
            self._capture_digest,
            checkpoint_bytes,
        )

    def __copy__(self):
        raise TypeError("installed methodology authority cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("installed methodology authority cannot be copied")

    def __reduce__(self):
        raise TypeError("installed methodology authority cannot be serialized")


def capture_installed_program_facts_methodology_authority(
    checkpoint_bytes: bytes,
    *,
    max_bytes: int = DEFAULT_MAX_AUTHORITY_BYTES,
) -> InstalledMethodologyAuthority:
    """Capture installed policy against exact current-run checkpoint bytes."""

    if not isinstance(checkpoint_bytes, bytes):
        _fail("checkpoint capture input must be exact bytes")
    root, snapshot, phase_inputs, capture_digest = _build_capture(
        checkpoint_bytes,
        max_bytes=max_bytes,
    )
    snapshot_bytes, audit_run_id, _checkpoint_digest = (
        _snapshot_from_checkpoint_bytes(checkpoint_bytes)
    )
    authority = object.__new__(InstalledMethodologyAuthority)
    object.__setattr__(authority, "_root", root)
    object.__setattr__(authority, "_checkpoint_bytes", bytes(checkpoint_bytes))
    object.__setattr__(authority, "_snapshot_bytes", bytes(snapshot_bytes))
    object.__setattr__(authority, "_audit_run_id", audit_run_id)
    object.__setattr__(
        authority, "_snapshot_digest", str(snapshot["snapshot_digest"])
    )
    object.__setattr__(
        authority,
        "_source_scope_digest",
        str(snapshot["components"]["source_scope"]["digest"]),
    )
    object.__setattr__(
        authority,
        "_phase_io_inputs",
        MappingProxyType(
            {
                identity: bytes(raw)
                for identity, raw in phase_inputs.items()
            }
        ),
    )
    object.__setattr__(authority, "_capture_digest", capture_digest)
    return authority


def replay_installed_program_facts_methodology_capture(
    checkpoint_bytes: bytes,
    *,
    max_bytes: int = DEFAULT_MAX_AUTHORITY_BYTES,
) -> tuple[Mapping[str, bytes], str, str, str, str]:
    """Rebuild installed methodology authority from canonical parent bytes."""

    if not isinstance(checkpoint_bytes, bytes):
        _fail("checkpoint replay input must be exact bytes")
    root, snapshot, phase_inputs, capture_digest = _build_capture(
        checkpoint_bytes,
        max_bytes=max_bytes,
    )
    del root
    _snapshot_bytes, audit_run_id, _checkpoint_digest = (
        _snapshot_from_checkpoint_bytes(checkpoint_bytes)
    )
    return (
        MappingProxyType(
            {
                identity: bytes(raw)
                for identity, raw in phase_inputs.items()
            }
        ),
        str(snapshot["snapshot_digest"]),
        str(snapshot["components"]["source_scope"]["digest"]),
        audit_run_id,
        capture_digest,
    )


__all__ = [
    "DEFAULT_MAX_AUTHORITY_BYTES",
    "INSTALLED_METHODOLOGY_AUTHORITY",
    "InstalledMethodologyAuthority",
    "METHODOLOGY_AUTHORITY_SCHEMA",
    "METHODOLOGY_PACKAGE_SCHEMA",
    "PROGRAM_FACTS_METHODOLOGY_INPUT_PATHS",
    "ProgramFactsMethodologyAuthorityError",
    "capture_installed_program_facts_methodology_authority",
    "replay_installed_program_facts_methodology_capture",
]
