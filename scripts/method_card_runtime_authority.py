"""Closed MethodCard binding authority for later runtime integration.

This module composes already-owned authorities.  It does not launch workers,
register PhaseIO objects, validate method application, interpret evidence, or
issue semantic conclusions.  In particular, an envelope produced here cannot
authorize a finding, a negative conclusion, severity, or report placement.

The binding joins:

* the freshly replayed canonical MethodCard catalog;
* an ordered, version-exact MethodCard selection and its rendered bytes;
* the canonical AuditSnapshot source/methodology identities;
* a replayed WorkerTransaction v2 WorkPlan and its PhaseIO digests; and
* source-derived exact or explicit lower-bound target/relation denominators;
* the independently replayed graph/selector producer binding; and
* the exact required-step denominator selected from the catalog.

All persisted bytes use the repository's compact NFC, float-free canonical
JSON with exactly one final LF.  Physical implementation paths are trusted
boundary inputs and never enter the semantic envelope.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
from pathlib import Path
import re
from typing import Any, NoReturn

from audit_snapshot import (
    MATCH,
    SNAPSHOT_SCHEMA,
    build_methodology_snapshot_component,
    classify_snapshot,
)
from method_card_catalog import (
    MethodCard,
    MethodCardCatalog,
    MethodCardCatalogError,
    load_method_card_catalog,
)
from program_facts_types import (
    ProgramFactsTypeError,
    canonical_file_bytes,
    canonical_json_bytes,
    strict_json_loads,
    validate_portable_path,
)
from worker_transaction import (
    WORKER_WORK_PLAN_SCHEMA_V2,
    WorkerTransactionError,
    compile_worker_plan,
)


AUTHORITY_SCHEMA = "plamen.method-card-runtime-authority.v1"
DENOMINATOR_AUTHORITY_SCHEMA = (
    "plamen.method-card-denominator-authority.v1"
)
DENOMINATOR_SOURCE_SCHEMA = "plamen.method-card-denominator-source.v1"
FRAGMENT_SCHEMA = "plamen.method-card-selected-fragment.v1"
INPUT_BINDING_SCHEMA = "plamen.method-card-runtime-input-binding.v1"
INTEGRATION_SCHEMA = "plamen.method-card-runtime-integration-debt.v1"
ACTIVATED_AUTHORITY_SCHEMA = "plamen.method-card-runtime-authority.v2"
ACTIVATED_DENOMINATOR_AUTHORITY_SCHEMA = (
    "plamen.method-card-denominator-authority.v2"
)
ACTIVATED_DENOMINATOR_SOURCE_SCHEMA = (
    "plamen.method-card-denominator-source.v2"
)
ACTIVATED_INPUT_BINDING_SCHEMA = (
    "plamen.method-card-runtime-input-binding.v2"
)
ACTIVATED_INTEGRATION_SCHEMA = (
    "plamen.method-card-runtime-integration.v2"
)
CATALOG_IDENTITY = "methodology/method-cards-v1.yaml"
FRAGMENT_MEDIA_TYPE = (
    "application/vnd.plamen.method-card-selected-fragment+json"
)

# This tuple is deliberately part of the signed envelope.  Removing an item is
# a schema-visible migration event, not a prose claim that cutover happened.
INTEGRATION_DEBT = (
    "attach_final_envelope_digest_to_worker_transaction_arm",
    "bind_runtime_input_artifact_into_phase_io_input_denominator",
    "compile_final_envelope_before_worker_transaction_arm",
    "consume_selected_fragment_in_runtime_prompt_compiler",
    "join_application_receipts_to_authoritative_runtime_denominators",
    "register_denominator_source_and_authority_in_phase_io",
    "wire_driver_consumer_cutover_and_resume_invalidation",
)

AUTHORITY_LIMITS = {
    "application_completion_authority": False,
    "execution_authority": False,
    "finding_authority": False,
    "negative_authority": False,
    "report_authority": False,
    "semantic_authority": False,
    "severity_authority": False,
}

_AUTHORITY_KEYS = frozenset(
    {
        "schema",
        "catalog_binding",
        "method_binding",
        "audit_snapshot_binding",
        "work_plan_binding",
        "denominators",
        "authority_limits",
        "integration",
        "authority_digest",
    }
)
_SELECTION_KEYS = frozenset({"method_id", "method_version"})
_STEP_KEYS = frozenset({"method_id", "method_version", "step_id"})
_PRODUCER_KEYS = frozenset(
    {"producer_id", "producer_version", "implementation_digest"}
)
_GRAPH_BINDING_KEYS = frozenset({"graph_schema", "graph_digest"})
_DENOMINATOR_SOURCE_KEYS = frozenset(
    {
        "schema",
        "producer",
        "audit_snapshot_digest",
        "source_scope_digest",
        "graph_schema",
        "graph_digest",
        "coverage",
        "nodes",
        "relations",
        "source_digest",
    }
)
_DENOMINATOR_COVERAGE_KEYS = frozenset(
    {"coverage_kind", "unknown_remainder", "limitation_reason"}
)
_DENOMINATOR_NODE_KEYS = frozenset(
    {
        "target_id",
        "node_kind",
        "boundaries",
        "effects",
        "entity_properties",
    }
)
_DENOMINATOR_RELATION_KEYS = frozenset(
    {
        "relation_id",
        "selector",
        "source_target_id",
        "destination_target_id",
    }
)
_SOURCE_FILE_IDENTITY_KEYS = frozenset({"path", "sha256", "size_bytes"})
_ACTIVATED_SOURCE_INPUT_NODE_KEYS = _DENOMINATOR_NODE_KEYS | {
    "source_paths"
}
_ACTIVATED_SOURCE_NODE_KEYS = _DENOMINATOR_NODE_KEYS | {"source_files"}
_ACTIVATED_DENOMINATOR_SOURCE_KEYS = frozenset(
    {
        "schema",
        "producer",
        "audit_snapshot_digest",
        "source_scope_digest",
        "graph_schema",
        "graph_digest",
        "coverage",
        "source_files",
        "nodes",
        "relations",
        "source_digest",
    }
)
_DENOMINATOR_AUTHORITY_KEYS = frozenset(
    {
        "schema",
        "producer",
        "audit_snapshot_digest",
        "source_scope_digest",
        "graph_schema",
        "graph_digest",
        "source_digest",
        "catalog_digest",
        "catalog_source_sha256",
        "selected_methods",
        "selector_digest",
        "selector_inputs_digest",
        "coverage_kind",
        "unknown_remainder",
        "limitation_reason",
        "target_count",
        "relation_count",
        "targets",
        "relations",
        "denominator_authority_digest",
    }
)
_WORK_PLAN_KEYS = frozenset(
    {
        "schema",
        "run_id",
        "phase",
        "work_unit_id",
        "generation",
        "phase_roster_denominator_digest",
        "phase_io_contract_digest",
        "phase_io_launch_digest",
        "phase_io_input_set_digest",
        "prompt_template_sha256",
        "methodology_digests",
        "source_snapshot_digest",
        "provider",
        "assignment",
        "write_scope_template",
        "child_denominator",
        "completion_policy",
        "retry_policy",
        "terminal_debt_policy",
        "work_plan_digest",
    }
)
_SNAPSHOT_COMPONENT_KEYS = frozenset(
    {"source_scope", "audit_config", "methodology", "toolchain"}
)
_METHODOLOGY_COMPONENT_KEYS = frozenset(
    {"digest", "path_set_digest", "file_count", "byte_count"}
)
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_OPAQUE_ID_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$",
    re.ASCII,
)
_SEMVER_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)$",
    re.ASCII,
)
_WINDOWS_REPARSE_ATTRIBUTE = 0x400


class MethodCardRuntimeAuthorityError(ValueError):
    """A runtime MethodCard binding is ambiguous, stale, or unauthorized."""


def _fail(message: str, exc: Exception | None = None) -> NoReturn:
    if exc is None:
        raise MethodCardRuntimeAuthorityError(message)
    raise MethodCardRuntimeAuthorityError(message) from exc


def _exact_keys(
    value: Mapping[str, Any],
    expected: frozenset[str],
    label: str,
) -> None:
    actual = set(value)
    if actual == expected:
        return
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    detail: list[str] = []
    if missing:
        detail.append("missing " + ", ".join(missing))
    if extra:
        detail.append("unexpected " + ", ".join(extra))
    _fail(f"{label} has schema drift: {'; '.join(detail)}")


def _hex64(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX64_RE.fullmatch(value) is None:
        _fail(f"{label} must be a lowercase SHA-256 digest")
    return value


def _opaque_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _OPAQUE_ID_RE.fullmatch(value) is None:
        _fail(f"{label} must be an ASCII opaque non-path identity")
    if (
        "/" in value
        or "\\" in value
        or re.match(r"^[A-Za-z]:", value)
        or value in {".", ".."}
    ):
        _fail(f"{label} must be an ASCII opaque non-path identity")
    return value


def _is_link_or_reparse(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        if hasattr(path, "is_junction") and path.is_junction():
            return True
        attributes = getattr(
            path.stat(follow_symlinks=False),
            "st_file_attributes",
            0,
        )
        return bool(attributes & _WINDOWS_REPARSE_ATTRIBUTE)
    except OSError:
        return True


def _stable_catalog_read(root: Path) -> bytes:
    path = root.joinpath(*CATALOG_IDENTITY.split("/"))
    cursor = root
    for part in CATALOG_IDENTITY.split("/"):
        cursor = cursor / part
        if _is_link_or_reparse(cursor):
            _fail(
                "canonical MethodCard catalog path traverses a link or "
                "reparse point"
            )
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        _fail("canonical MethodCard catalog path is missing or escapes root", exc)
    if not resolved.is_file():
        _fail("canonical MethodCard catalog path is not a regular file")
    try:
        before = resolved.stat()
        raw = resolved.read_bytes()
        after = resolved.stat()
        replay = resolved.read_bytes()
        final = resolved.stat()
    except OSError as exc:
        _fail("canonical MethodCard catalog could not be read", exc)
    before_token = (
        before.st_size,
        before.st_mtime_ns,
        getattr(before, "st_ctime_ns", 0),
    )
    after_token = (
        after.st_size,
        after.st_mtime_ns,
        getattr(after, "st_ctime_ns", 0),
    )
    final_token = (
        final.st_size,
        final.st_mtime_ns,
        getattr(final, "st_ctime_ns", 0),
    )
    if (
        before_token != after_token
        or after_token != final_token
        or len(raw) != after.st_size
        or replay != raw
    ):
        _fail("canonical MethodCard catalog changed during replay")
    return raw


def _current_catalog(
    implementation_root: Path | str,
    expected_catalog: MethodCardCatalog | None,
) -> tuple[Path, MethodCardCatalog]:
    lexical_root = Path(implementation_root).absolute()
    if _is_link_or_reparse(lexical_root):
        _fail("implementation root must not be a link or reparse point")
    try:
        root = lexical_root.resolve(strict=True)
    except OSError as exc:
        _fail("implementation root is missing", exc)
    if not root.is_dir():
        _fail("implementation root must be a directory")

    before = _stable_catalog_read(root)
    source = root.joinpath(*CATALOG_IDENTITY.split("/"))
    try:
        current = load_method_card_catalog(source, repo_root=root)
    except MethodCardCatalogError as exc:
        _fail(f"canonical MethodCard catalog replay failed: {exc}", exc)
    after = _stable_catalog_read(root)
    if before != current.source_bytes or current.source_bytes != after:
        _fail("canonical MethodCard catalog changed during validation")

    if expected_catalog is not None:
        if type(expected_catalog) is not MethodCardCatalog:
            _fail("expected catalog must be an exact MethodCardCatalog")
        try:
            expected_source = expected_catalog.source_path.resolve(strict=True)
            canonical_source = source.resolve(strict=True)
        except OSError as exc:
            _fail("expected MethodCard catalog source is stale", exc)
        if expected_source != canonical_source:
            _fail(
                "expected MethodCard catalog does not name the canonical "
                "catalog location"
            )
        if (
            expected_catalog.digest != current.digest
            or expected_catalog.source_sha256 != current.source_sha256
            or expected_catalog.source_bytes != current.source_bytes
        ):
            _fail("expected MethodCard catalog binding is stale")
    return root, current


def _mapping_input(
    value: Mapping[str, Any] | bytes,
    *,
    label: str,
    require_final_lf: bool,
) -> dict[str, Any]:
    try:
        if isinstance(value, bytes):
            parsed = strict_json_loads(
                value,
                require_final_lf=require_final_lf,
                require_canonical=True,
            )
        elif isinstance(value, Mapping):
            raw = (
                canonical_file_bytes(value)
                if require_final_lf
                else canonical_json_bytes(value)
            )
            parsed = strict_json_loads(
                raw,
                require_final_lf=require_final_lf,
                require_canonical=True,
            )
        else:
            _fail(f"{label} must be a mapping or canonical JSON bytes")
    except ProgramFactsTypeError as exc:
        _fail(f"{label} is not canonical JSON: {exc}", exc)
    if not isinstance(parsed, dict):
        _fail(f"{label} root must be an object")
    return parsed


def _current_snapshot(
    audit_snapshot: Mapping[str, Any] | bytes,
    *,
    implementation_root: Path,
) -> dict[str, Any]:
    snapshot = _mapping_input(
        audit_snapshot,
        label="audit snapshot",
        require_final_lf=True,
    )
    if (
        set(snapshot) != {"schema", "components", "snapshot_digest"}
        or snapshot.get("schema") != SNAPSHOT_SCHEMA
        or not isinstance(snapshot.get("components"), Mapping)
        or set(snapshot["components"]) != _SNAPSHOT_COMPONENT_KEYS
    ):
        _fail("audit snapshot has schema or component drift")
    methodology = snapshot["components"].get("methodology")
    if (
        not isinstance(methodology, Mapping)
        or set(methodology) != _METHODOLOGY_COMPONENT_KEYS
    ):
        _fail("audit snapshot methodology component has schema drift")
    try:
        verdict = classify_snapshot(
            snapshot,
            snapshot,
            has_prior_progress=False,
        )
    except (TypeError, ValueError) as exc:
        _fail(f"audit snapshot is invalid: {exc}", exc)
    if verdict.state != MATCH:
        _fail("audit snapshot did not validate as an exact self-match")
    try:
        current_methodology = build_methodology_snapshot_component(
            implementation_root
        )
    except Exception as exc:
        _fail(f"current methodology snapshot could not be built: {exc}", exc)
    if dict(methodology) != current_methodology:
        _fail(
            "audit snapshot methodology binding is stale and differs from "
            "the current implementation"
        )
    _hex64(snapshot["snapshot_digest"], "audit snapshot digest")
    _hex64(
        snapshot["components"]["source_scope"]["digest"],
        "audit source-scope digest",
    )
    return snapshot


def _replayed_work_plan(
    work_plan: Mapping[str, Any] | bytes,
) -> dict[str, Any]:
    plan = _mapping_input(
        work_plan,
        label="WorkerTransaction WorkPlan",
        require_final_lf=False,
    )
    _exact_keys(plan, _WORK_PLAN_KEYS, "WorkerTransaction WorkPlan v2")
    if plan.get("schema") != WORKER_WORK_PLAN_SCHEMA_V2:
        _fail("WorkerTransaction WorkPlan must use the current v2 schema")
    try:
        replayed = compile_worker_plan(
            run_id=plan["run_id"],
            phase=plan["phase"],
            work_unit_id=plan["work_unit_id"],
            generation=plan["generation"],
            phase_roster_denominator_digest=plan[
                "phase_roster_denominator_digest"
            ],
            phase_io_contract_digest=plan["phase_io_contract_digest"],
            phase_io_launch_digest=plan["phase_io_launch_digest"],
            phase_io_input_set_digest=plan["phase_io_input_set_digest"],
            prompt_template_sha256=plan["prompt_template_sha256"],
            methodology_digests=plan["methodology_digests"],
            source_snapshot_digest=plan["source_snapshot_digest"],
            provider=plan["provider"],
            assignment=plan["assignment"],
            write_scope=plan["write_scope_template"],
            child_denominator=plan["child_denominator"],
            completion_policy=plan["completion_policy"],
            retry_policy=plan["retry_policy"],
            terminal_debt_policy=plan["terminal_debt_policy"],
        )
    except (KeyError, TypeError, WorkerTransactionError) as exc:
        _fail(f"WorkerTransaction WorkPlan replay failed: {exc}", exc)
    if replayed != plan:
        _fail(
            "WorkerTransaction WorkPlan is stale, noncanonical, or has a "
            "work plan digest mismatch"
        )
    return replayed


def _selected_cards(
    catalog: MethodCardCatalog,
    selected_methods: Sequence[Mapping[str, Any]],
) -> tuple[MethodCard, ...]:
    if isinstance(selected_methods, (str, bytes)) or not isinstance(
        selected_methods,
        Sequence,
    ):
        _fail("selected methods must be an ordered sequence")
    if not selected_methods:
        _fail("selected methods must not be empty")
    selected: list[MethodCard] = []
    identities: list[str] = []
    for index, row in enumerate(selected_methods):
        label = f"selected methods[{index}]"
        if not isinstance(row, Mapping):
            _fail(f"{label} must be an object")
        _exact_keys(row, _SELECTION_KEYS, label)
        method_id = _opaque_id(row["method_id"], f"{label}.method_id")
        method_version = row["method_version"]
        if (
            not isinstance(method_version, str)
            or _SEMVER_RE.fullmatch(method_version) is None
        ):
            _fail(f"{label}.method_version must be semantic version X.Y.Z")
        try:
            card = catalog.card(method_id)
        except MethodCardCatalogError as exc:
            _fail(f"unknown MethodCard in selected methods: {method_id}", exc)
        if card.method_version != method_version:
            _fail(
                f"{label}.method_version is stale: expected "
                f"{card.method_version}, observed {method_version}"
            )
        identities.append(method_id)
        selected.append(card)
    if len(identities) != len(set(identities)):
        _fail("selected methods contain a duplicate method_id")
    folded = [identity.casefold() for identity in identities]
    if len(folded) != len(set(folded)):
        _fail("selected methods contain a case-fold duplicate method_id")
    catalog_positions = {
        card.method_id: index for index, card in enumerate(catalog.cards)
    }
    positions = [catalog_positions[identity] for identity in identities]
    if positions != sorted(positions):
        _fail("selected methods must remain in canonical catalog order")
    return tuple(selected)


def _card_fragment_mapping(card: MethodCard) -> dict[str, Any]:
    return {
        "method_id": card.method_id,
        "method_version": card.method_version,
        "title": card.title,
        "semantic_operator": card.semantic_operator,
        "operator_instruction": card.operator_instruction,
        "applies_to": {
            "node_kinds": list(card.node_kinds),
            "required_capabilities": list(card.required_capabilities),
            "optional_capabilities": list(card.optional_capabilities),
            "accepted_fidelity": {
                capability: list(levels)
                for capability, levels in card.accepted_fidelity
            },
        },
        "target_selector": {
            selector: list(values)
            for selector, values in card.target_selector
        },
        "relation_selectors": list(card.relation_selectors),
        "required_steps": [
            {
                "step_id": step.step_id,
                "instruction": step.instruction,
            }
            for step in card.required_steps
        ],
        "required_receipts": list(card.required_receipts),
        "completion_policy": {
            "allow_not_applicable": card.allow_not_applicable,
            "valid_not_applicable_reasons": list(
                card.valid_not_applicable_reasons
            ),
            "material_unresolved_requires_human_review": (
                card.material_unresolved_requires_human_review
            ),
        },
        "prompt_fragment": {
            "path": validate_portable_path(card.prompt_fragment.path),
            "sha256": _hex64(
                card.prompt_fragment.sha256,
                f"{card.method_id} prompt fragment digest",
            ),
        },
    }


def render_selected_method_fragment(
    catalog: MethodCardCatalog,
    selected_methods: Sequence[Mapping[str, Any]],
) -> bytes:
    """Render a complete, deterministic selected-method JSON fragment.

    This fragment is an immutable prompt-compiler input, not proof that any
    current prompt consumes it.  The catalog's reviewed prompt source binding
    remains visible on every rendered card.
    """

    if type(catalog) is not MethodCardCatalog:
        _fail("catalog must be an exact MethodCardCatalog")
    cards = _selected_cards(catalog, selected_methods)
    payload = {
        "schema": FRAGMENT_SCHEMA,
        "catalog_schema": catalog.schema_version,
        "catalog_version": catalog.catalog_version,
        "catalog_digest": _hex64(catalog.digest, "catalog digest"),
        "catalog_source_sha256": _hex64(
            catalog.source_sha256,
            "catalog source digest",
        ),
        "methods": [_card_fragment_mapping(card) for card in cards],
    }
    try:
        return canonical_file_bytes(payload)
    except ProgramFactsTypeError as exc:
        _fail(f"selected MethodCard fragment is not canonical: {exc}", exc)


def _denominator_ids(
    values: Sequence[str],
    *,
    label: str,
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        _fail(f"{label} must be an ordered sequence")
    normalized = tuple(
        _opaque_id(value, f"{label}[{index}]")
        for index, value in enumerate(values)
    )
    if normalized != tuple(sorted(normalized)):
        _fail(f"{label} must be sorted in canonical code-point order")
    if len(normalized) != len(set(normalized)):
        _fail(f"{label} contains duplicate identities")
    folded = [value.casefold() for value in normalized]
    if len(folded) != len(set(folded)):
        _fail(f"{label} contains a case-fold identity collision")
    return normalized


def _semantic_version(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SEMVER_RE.fullmatch(value) is None:
        _fail(f"{label} must be semantic version X.Y.Z")
    return value


def _producer_binding(
    value: Mapping[str, Any] | bytes,
    *,
    label: str,
) -> dict[str, str]:
    producer = _mapping_input(
        value,
        label=label,
        require_final_lf=False,
    )
    _exact_keys(producer, _PRODUCER_KEYS, label)
    return {
        "producer_id": _opaque_id(
            producer["producer_id"],
            f"{label}.producer_id",
        ),
        "producer_version": _semantic_version(
            producer["producer_version"],
            f"{label}.producer_version",
        ),
        "implementation_digest": _hex64(
            producer["implementation_digest"],
            f"{label}.implementation_digest",
        ),
    }


def _graph_binding(
    value: Mapping[str, Any] | bytes,
    *,
    label: str,
) -> dict[str, str]:
    binding = _mapping_input(
        value,
        label=label,
        require_final_lf=False,
    )
    _exact_keys(binding, _GRAPH_BINDING_KEYS, label)
    return {
        "graph_schema": _opaque_id(
            binding["graph_schema"],
            f"{label}.graph_schema",
        ),
        "graph_digest": _hex64(
            binding["graph_digest"],
            f"{label}.graph_digest",
        ),
    }


def _coverage_binding(
    value: Any,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail("denominator source coverage must be an object")
    _exact_keys(
        value,
        _DENOMINATOR_COVERAGE_KEYS,
        "denominator source coverage",
    )
    coverage_kind = value["coverage_kind"]
    unknown_remainder = value["unknown_remainder"]
    reason = value["limitation_reason"]
    if coverage_kind not in {"EXACT", "LOWER_BOUND"}:
        _fail(
            "denominator source coverage_kind must be EXACT or LOWER_BOUND"
        )
    if type(unknown_remainder) is not bool:
        _fail("denominator source unknown_remainder must be a boolean")
    if coverage_kind == "EXACT":
        if unknown_remainder or reason is not None:
            _fail(
                "EXACT denominator source coverage requires a known zero "
                "remainder and no limitation reason"
            )
    else:
        if not unknown_remainder:
            _fail(
                "LOWER_BOUND denominator source coverage requires "
                "unknown_remainder=true"
            )
        if (
            not isinstance(reason, str)
            or not reason
            or reason.strip() != reason
        ):
            _fail(
                "LOWER_BOUND denominator source coverage requires a "
                "nonempty canonical limitation reason"
            )
    return {
        "coverage_kind": coverage_kind,
        "unknown_remainder": unknown_remainder,
        "limitation_reason": reason,
    }


def _denominator_source_nodes(
    values: Any,
) -> tuple[dict[str, Any], ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        _fail("denominator source nodes must be an ordered sequence")
    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(values):
        label = f"denominator source nodes[{index}]"
        if not isinstance(raw, Mapping):
            _fail(f"{label} must be an object")
        _exact_keys(raw, _DENOMINATOR_NODE_KEYS, label)
        normalized.append(
            {
                "target_id": _opaque_id(
                    raw["target_id"],
                    f"{label}.target_id",
                ),
                "node_kind": _opaque_id(
                    raw["node_kind"],
                    f"{label}.node_kind",
                ),
                "boundaries": list(
                    _denominator_ids(
                        raw["boundaries"],
                        label=f"{label}.boundaries",
                    )
                ),
                "effects": list(
                    _denominator_ids(
                        raw["effects"],
                        label=f"{label}.effects",
                    )
                ),
                "entity_properties": list(
                    _denominator_ids(
                        raw["entity_properties"],
                        label=f"{label}.entity_properties",
                    )
                ),
            }
        )
    target_ids = tuple(row["target_id"] for row in normalized)
    _denominator_ids(target_ids, label="denominator source target identities")
    return tuple(normalized)


def _denominator_source_relations(
    values: Any,
    *,
    target_ids: frozenset[str],
) -> tuple[dict[str, str], ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        _fail("denominator source relations must be an ordered sequence")
    normalized: list[dict[str, str]] = []
    for index, raw in enumerate(values):
        label = f"denominator source relations[{index}]"
        if not isinstance(raw, Mapping):
            _fail(f"{label} must be an object")
        _exact_keys(raw, _DENOMINATOR_RELATION_KEYS, label)
        row = {
            "relation_id": _opaque_id(
                raw["relation_id"],
                f"{label}.relation_id",
            ),
            "selector": _opaque_id(
                raw["selector"],
                f"{label}.selector",
            ),
            "source_target_id": _opaque_id(
                raw["source_target_id"],
                f"{label}.source_target_id",
            ),
            "destination_target_id": _opaque_id(
                raw["destination_target_id"],
                f"{label}.destination_target_id",
            ),
        }
        if (
            row["source_target_id"] not in target_ids
            or row["destination_target_id"] not in target_ids
        ):
            _fail(
                f"{label} endpoints must name denominator source node "
                "identities"
            )
        normalized.append(row)
    relation_ids = tuple(row["relation_id"] for row in normalized)
    _denominator_ids(
        relation_ids,
        label="denominator source relation identities",
    )
    return tuple(normalized)


def _source_graph_digest(
    *,
    graph_schema: str,
    coverage: Mapping[str, Any],
    nodes: Sequence[Mapping[str, Any]],
    relations: Sequence[Mapping[str, Any]],
) -> str:
    graph_payload = {
        "graph_schema": graph_schema,
        "coverage": dict(coverage),
        "nodes": [dict(row) for row in nodes],
        "relations": [dict(row) for row in relations],
    }
    return hashlib.sha256(canonical_json_bytes(graph_payload)).hexdigest()


def _denominator_source_value(
    value: Mapping[str, Any] | bytes,
    *,
    snapshot: Mapping[str, Any],
    expected_producer: Mapping[str, Any] | bytes,
    expected_graph: Mapping[str, Any] | bytes,
) -> dict[str, Any]:
    source = _mapping_input(
        value,
        label="MethodCard denominator source",
        require_final_lf=True,
    )
    _exact_keys(
        source,
        _DENOMINATOR_SOURCE_KEYS,
        "MethodCard denominator source",
    )
    if source.get("schema") != DENOMINATOR_SOURCE_SCHEMA:
        _fail("MethodCard denominator source schema is unsupported")
    claimed_digest = _hex64(
        source.get("source_digest"),
        "MethodCard denominator source digest",
    )
    unsigned = dict(source)
    unsigned.pop("source_digest")
    expected_digest = hashlib.sha256(
        canonical_json_bytes(unsigned)
    ).hexdigest()
    if claimed_digest != expected_digest:
        _fail("MethodCard denominator source digest mismatch")

    producer = _producer_binding(
        source["producer"],
        label="denominator source producer",
    )
    expected = _producer_binding(
        expected_producer,
        label="expected denominator producer",
    )
    if producer != expected:
        _fail(
            "denominator source producer identity is stale or differs from "
            "the expected graph/selector producer"
        )
    if (
        _hex64(
            source["audit_snapshot_digest"],
            "denominator source audit snapshot digest",
        )
        != snapshot["snapshot_digest"]
    ):
        _fail(
            "denominator source audit snapshot identity is stale or "
            "mismatched"
        )
    if (
        _hex64(
            source["source_scope_digest"],
            "denominator source source-scope digest",
        )
        != snapshot["components"]["source_scope"]["digest"]
    ):
        _fail(
            "denominator source source-scope identity is stale or mismatched"
        )
    graph_schema = _opaque_id(
        source["graph_schema"],
        "denominator source graph schema",
    )
    coverage = _coverage_binding(source["coverage"])
    nodes = _denominator_source_nodes(source["nodes"])
    relations = _denominator_source_relations(
        source["relations"],
        target_ids=frozenset(row["target_id"] for row in nodes),
    )
    graph_digest = _hex64(
        source["graph_digest"],
        "denominator source graph digest",
    )
    computed_graph_digest = _source_graph_digest(
        graph_schema=graph_schema,
        coverage=coverage,
        nodes=nodes,
        relations=relations,
    )
    if graph_digest != computed_graph_digest:
        _fail(
            "denominator source graph digest does not match the canonical "
            "selector graph payload"
        )
    expected_graph_binding = _graph_binding(
        expected_graph,
        label="expected denominator graph",
    )
    if {
        "graph_schema": graph_schema,
        "graph_digest": graph_digest,
    } != expected_graph_binding:
        _fail(
            "denominator source graph identity is stale or differs from the "
            "expected graph authority"
        )
    normalized = {
        "schema": DENOMINATOR_SOURCE_SCHEMA,
        "producer": producer,
        "audit_snapshot_digest": snapshot["snapshot_digest"],
        "source_scope_digest": snapshot["components"]["source_scope"][
            "digest"
        ],
        "graph_schema": graph_schema,
        "graph_digest": graph_digest,
        "coverage": coverage,
        "nodes": list(nodes),
        "relations": list(relations),
        "source_digest": claimed_digest,
    }
    if normalized != source:
        _fail(
            "MethodCard denominator source is noncanonical or changed during "
            "normalization"
        )
    return normalized


def _selector_binding(
    cards: Sequence[MethodCard],
) -> dict[str, Any]:
    return {
        "selected_methods": [
            {
                "method_id": card.method_id,
                "method_version": card.method_version,
                "node_kinds": list(card.node_kinds),
                "target_selector": {
                    selector: list(values)
                    for selector, values in card.target_selector
                },
                "relation_selectors": list(card.relation_selectors),
            }
            for card in cards
        ]
    }


def _source_derived_denominators(
    *,
    cards: Sequence[MethodCard],
    source: Mapping[str, Any],
) -> tuple[tuple[str, ...], tuple[str, ...], str, str]:
    selector_binding = _selector_binding(cards)
    selector_digest = hashlib.sha256(
        canonical_json_bytes(selector_binding)
    ).hexdigest()
    selector_inputs = {
        "graph_schema": source["graph_schema"],
        "graph_digest": source["graph_digest"],
        "source_digest": source["source_digest"],
        "nodes": source["nodes"],
        "relations": source["relations"],
    }
    selector_inputs_digest = hashlib.sha256(
        canonical_json_bytes(selector_inputs)
    ).hexdigest()

    target_ids: set[str] = set()
    for node in source["nodes"]:
        for card in cards:
            if node["node_kind"] not in card.node_kinds:
                continue
            selectors = dict(card.target_selector)
            if (
                set(node["boundaries"])
                & set(selectors["boundaries_any"])
                or set(node["effects"]) & set(selectors["effects_any"])
                or set(node["entity_properties"])
                & set(selectors["entity_properties_any"])
            ):
                target_ids.add(node["target_id"])
                break

    relation_selectors = {
        selector for card in cards for selector in card.relation_selectors
    }
    relation_ids = {
        row["relation_id"]
        for row in source["relations"]
        if row["selector"] in relation_selectors
    }
    return (
        tuple(sorted(target_ids)),
        tuple(sorted(relation_ids)),
        selector_digest,
        selector_inputs_digest,
    )


def _compile_denominator_authority(
    *,
    catalog: MethodCardCatalog,
    cards: Sequence[MethodCard],
    snapshot: Mapping[str, Any],
    denominator_source: Mapping[str, Any] | bytes,
    expected_denominator_producer: Mapping[str, Any] | bytes,
    expected_graph_binding: Mapping[str, Any] | bytes,
) -> dict[str, Any]:
    source = _denominator_source_value(
        denominator_source,
        snapshot=snapshot,
        expected_producer=expected_denominator_producer,
        expected_graph=expected_graph_binding,
    )
    (
        targets,
        relations,
        selector_digest,
        selector_inputs_digest,
    ) = _source_derived_denominators(cards=cards, source=source)
    coverage = source["coverage"]
    unsigned = {
        "schema": DENOMINATOR_AUTHORITY_SCHEMA,
        "producer": source["producer"],
        "audit_snapshot_digest": snapshot["snapshot_digest"],
        "source_scope_digest": snapshot["components"]["source_scope"][
            "digest"
        ],
        "graph_schema": source["graph_schema"],
        "graph_digest": source["graph_digest"],
        "source_digest": source["source_digest"],
        "catalog_digest": catalog.digest,
        "catalog_source_sha256": catalog.source_sha256,
        "selected_methods": [
            {
                "method_id": card.method_id,
                "method_version": card.method_version,
            }
            for card in cards
        ],
        "selector_digest": selector_digest,
        "selector_inputs_digest": selector_inputs_digest,
        "coverage_kind": coverage["coverage_kind"],
        "unknown_remainder": coverage["unknown_remainder"],
        "limitation_reason": coverage["limitation_reason"],
        "target_count": len(targets),
        "relation_count": len(relations),
        "targets": list(targets),
        "relations": list(relations),
    }
    return {
        **unsigned,
        "denominator_authority_digest": hashlib.sha256(
            canonical_json_bytes(unsigned)
        ).hexdigest(),
    }


def compile_method_card_denominator_authority(
    *,
    implementation_root: Path | str,
    audit_snapshot: Mapping[str, Any] | bytes,
    selected_methods: Sequence[Mapping[str, Any]],
    denominator_source: Mapping[str, Any] | bytes,
    expected_denominator_producer: Mapping[str, Any] | bytes,
    expected_graph_binding: Mapping[str, Any] | bytes,
    expected_catalog: MethodCardCatalog | None = None,
) -> dict[str, Any]:
    """Derive target/relation coverage from a replayed selector source.

    The source producer, graph identity, source snapshot, selected MethodCard
    revisions, selector inputs, completeness state, and ordered result sets are
    all bound before an exact denominator can exist.
    """

    root, catalog = _current_catalog(implementation_root, expected_catalog)
    snapshot = _current_snapshot(
        audit_snapshot,
        implementation_root=root,
    )
    cards = _selected_cards(catalog, selected_methods)
    return _compile_denominator_authority(
        catalog=catalog,
        cards=cards,
        snapshot=snapshot,
        denominator_source=denominator_source,
        expected_denominator_producer=expected_denominator_producer,
        expected_graph_binding=expected_graph_binding,
    )


def _denominator_authority_value(
    value: Mapping[str, Any] | bytes,
) -> dict[str, Any]:
    authority = _mapping_input(
        value,
        label="MethodCard denominator authority",
        require_final_lf=True,
    )
    _exact_keys(
        authority,
        _DENOMINATOR_AUTHORITY_KEYS,
        "MethodCard denominator authority",
    )
    if authority.get("schema") != DENOMINATOR_AUTHORITY_SCHEMA:
        _fail("MethodCard denominator authority schema is unsupported")
    claimed = _hex64(
        authority.get("denominator_authority_digest"),
        "MethodCard denominator authority digest",
    )
    unsigned = dict(authority)
    unsigned.pop("denominator_authority_digest")
    expected = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    if claimed != expected:
        _fail("MethodCard denominator authority digest mismatch")
    return authority


def canonical_denominator_authority_bytes(
    value: Mapping[str, Any],
) -> bytes:
    """Serialize one validated denominator authority with exactly one LF."""

    authority = _denominator_authority_value(value)
    try:
        return canonical_file_bytes(authority)
    except ProgramFactsTypeError as exc:
        _fail(f"MethodCard denominator authority is not canonical: {exc}", exc)


def validate_method_card_denominator_authority(
    value: Mapping[str, Any] | bytes,
    *,
    implementation_root: Path | str,
    audit_snapshot: Mapping[str, Any] | bytes,
    selected_methods: Sequence[Mapping[str, Any]],
    denominator_source: Mapping[str, Any] | bytes,
    expected_denominator_producer: Mapping[str, Any] | bytes,
    expected_graph_binding: Mapping[str, Any] | bytes,
    expected_catalog: MethodCardCatalog | None = None,
) -> dict[str, Any]:
    """Replay a denominator against its current external source authorities."""

    authority = _denominator_authority_value(value)
    rebuilt = compile_method_card_denominator_authority(
        implementation_root=implementation_root,
        audit_snapshot=audit_snapshot,
        selected_methods=selected_methods,
        denominator_source=denominator_source,
        expected_denominator_producer=expected_denominator_producer,
        expected_graph_binding=expected_graph_binding,
        expected_catalog=expected_catalog,
    )
    if rebuilt != authority:
        _fail(
            "MethodCard denominator authority differs from current external "
            "source, selector, graph, producer, or method bindings"
        )
    return rebuilt


def _expected_steps(cards: Sequence[MethodCard]) -> tuple[dict[str, str], ...]:
    return tuple(
        {
            "method_id": card.method_id,
            "method_version": card.method_version,
            "step_id": step.step_id,
        }
        for card in cards
        for step in card.required_steps
    )


def _step_denominator(
    values: Sequence[Mapping[str, Any]],
    *,
    expected: tuple[dict[str, str], ...],
) -> tuple[dict[str, str], ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        _fail("step denominator must be an ordered sequence")
    normalized: list[dict[str, str]] = []
    for index, row in enumerate(values):
        label = f"step denominator[{index}]"
        if not isinstance(row, Mapping):
            _fail(f"{label} must be an object")
        _exact_keys(row, _STEP_KEYS, label)
        normalized.append(
            {
                "method_id": _opaque_id(
                    row["method_id"],
                    f"{label}.method_id",
                ),
                "method_version": (
                    row["method_version"]
                    if isinstance(row["method_version"], str)
                    and _SEMVER_RE.fullmatch(row["method_version"]) is not None
                    else _fail(
                        f"{label}.method_version must be semantic version X.Y.Z"
                    )
                ),
                "step_id": _opaque_id(
                    row["step_id"],
                    f"{label}.step_id",
                ),
            }
        )
    result = tuple(normalized)
    if result != expected:
        _fail(
            "step denominator must exactly equal every required step of the "
            "selected MethodCards in catalog/declaration order"
        )
    return result


def _compile_denominators(
    *,
    denominator_authority: Mapping[str, Any],
    targets: Sequence[str],
    relations: Sequence[str],
    steps: Sequence[Mapping[str, Any]],
    expected_steps: tuple[dict[str, str], ...],
) -> dict[str, Any]:
    target_ids = _denominator_ids(targets, label="target denominator")
    relation_ids = _denominator_ids(
        relations,
        label="relation denominator",
    )
    if target_ids != tuple(denominator_authority["targets"]):
        _fail(
            "target denominator must prove exact set equality against the "
            "source-derived denominator authority"
        )
    if relation_ids != tuple(denominator_authority["relations"]):
        _fail(
            "relation denominator must prove exact set equality against the "
            "source-derived denominator authority"
        )
    step_rows = _step_denominator(steps, expected=expected_steps)
    reason = denominator_authority["limitation_reason"]
    debt = (
        []
        if denominator_authority["coverage_kind"] == "EXACT"
        else [
            {
                "debt_code": "UNKNOWN_DENOMINATOR_REMAINDER",
                "reason": reason,
            }
        ]
    )
    unsigned = {
        "denominator_authority_schema": DENOMINATOR_AUTHORITY_SCHEMA,
        "denominator_authority_digest": denominator_authority[
            "denominator_authority_digest"
        ],
        "denominator_source_digest": denominator_authority["source_digest"],
        "graph_digest": denominator_authority["graph_digest"],
        "selector_digest": denominator_authority["selector_digest"],
        "selector_inputs_digest": denominator_authority[
            "selector_inputs_digest"
        ],
        "coverage_kind": denominator_authority["coverage_kind"],
        "unknown_remainder": denominator_authority["unknown_remainder"],
        "limitation_reason": reason,
        "debt": debt,
        "target_count": len(target_ids),
        "relation_count": len(relation_ids),
        "step_count": len(step_rows),
        "targets": list(target_ids),
        "relations": list(relation_ids),
        "steps": list(step_rows),
    }
    return {
        **unsigned,
        "denominator_digest": hashlib.sha256(
            canonical_json_bytes(unsigned)
        ).hexdigest(),
    }


def _runtime_input_binding(
    *,
    catalog: MethodCardCatalog,
    cards: Sequence[MethodCard],
    rendered_fragment: bytes,
    snapshot: Mapping[str, Any],
    denominators: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the acyclic pre-WorkPlan binding.

    This object intentionally omits every WorkPlan and PhaseIO digest.  Its
    digest can therefore be registered as a PhaseIO input and included in a
    WorkPlan before the final envelope joins that WorkPlan back to the same
    inputs.
    """

    unsigned = {
        "schema": INPUT_BINDING_SCHEMA,
        "catalog_digest": catalog.digest,
        "catalog_source_sha256": catalog.source_sha256,
        "selected_methods": [
            {
                "method_id": card.method_id,
                "method_version": card.method_version,
            }
            for card in cards
        ],
        "rendered_fragment_sha256": hashlib.sha256(
            rendered_fragment
        ).hexdigest(),
        "rendered_fragment_size_bytes": len(rendered_fragment),
        "audit_snapshot_digest": snapshot["snapshot_digest"],
        "methodology_snapshot_digest": snapshot["components"][
            "methodology"
        ]["digest"],
        "source_scope_digest": snapshot["components"]["source_scope"][
            "digest"
        ],
        "denominator_authority_digest": denominators[
            "denominator_authority_digest"
        ],
        "denominator_digest": denominators["denominator_digest"],
    }
    return {
        **unsigned,
        "runtime_input_binding_digest": hashlib.sha256(
            canonical_json_bytes(unsigned)
        ).hexdigest(),
    }


def compile_method_card_runtime_input_binding(
    *,
    implementation_root: Path | str,
    audit_snapshot: Mapping[str, Any] | bytes,
    selected_methods: Sequence[Mapping[str, Any]],
    denominator_source: Mapping[str, Any] | bytes,
    expected_denominator_producer: Mapping[str, Any] | bytes,
    expected_graph_binding: Mapping[str, Any] | bytes,
    target_denominator: Sequence[str],
    relation_denominator: Sequence[str],
    step_denominator: Sequence[Mapping[str, Any]],
    expected_catalog: MethodCardCatalog | None = None,
) -> dict[str, Any]:
    """Compile the acyclic MethodCard input registered before a WorkPlan."""

    root, catalog = _current_catalog(
        implementation_root,
        expected_catalog,
    )
    snapshot = _current_snapshot(
        audit_snapshot,
        implementation_root=root,
    )
    cards = _selected_cards(catalog, selected_methods)
    normalized_selections = [
        {
            "method_id": card.method_id,
            "method_version": card.method_version,
        }
        for card in cards
    ]
    rendered = render_selected_method_fragment(
        catalog,
        normalized_selections,
    )
    denominator_authority = _compile_denominator_authority(
        catalog=catalog,
        cards=cards,
        snapshot=snapshot,
        denominator_source=denominator_source,
        expected_denominator_producer=expected_denominator_producer,
        expected_graph_binding=expected_graph_binding,
    )
    denominators = _compile_denominators(
        denominator_authority=denominator_authority,
        targets=target_denominator,
        relations=relation_denominator,
        steps=step_denominator,
        expected_steps=_expected_steps(cards),
    )
    return _runtime_input_binding(
        catalog=catalog,
        cards=cards,
        rendered_fragment=rendered,
        snapshot=snapshot,
        denominators=denominators,
    )


def integration_debt_output() -> dict[str, Any]:
    """Return the explicit, non-authorizing integration status."""

    return {
        "schema": INTEGRATION_SCHEMA,
        "status": "FOUNDATION_ONLY",
        "driver_cutover": False,
        "phase_io_registered": False,
        "worker_transaction_consumed": False,
        "prompt_consumer_cutover": False,
        "application_receipt_cutover": False,
        "debt": list(INTEGRATION_DEBT),
    }


def compile_method_card_runtime_authority(
    *,
    implementation_root: Path | str,
    audit_snapshot: Mapping[str, Any] | bytes,
    work_plan: Mapping[str, Any] | bytes,
    selected_methods: Sequence[Mapping[str, Any]],
    denominator_source: Mapping[str, Any] | bytes,
    expected_denominator_producer: Mapping[str, Any] | bytes,
    expected_graph_binding: Mapping[str, Any] | bytes,
    target_denominator: Sequence[str],
    relation_denominator: Sequence[str],
    step_denominator: Sequence[Mapping[str, Any]],
    expected_catalog: MethodCardCatalog | None = None,
) -> dict[str, Any]:
    """Compile one closed, non-semantic MethodCard runtime binding."""

    root, catalog = _current_catalog(
        implementation_root,
        expected_catalog,
    )
    snapshot = _current_snapshot(
        audit_snapshot,
        implementation_root=root,
    )
    cards = _selected_cards(catalog, selected_methods)
    normalized_selections = [
        {
            "method_id": card.method_id,
            "method_version": card.method_version,
        }
        for card in cards
    ]
    rendered = render_selected_method_fragment(
        catalog,
        normalized_selections,
    )
    rendered_digest = hashlib.sha256(rendered).hexdigest()
    denominator_authority = _compile_denominator_authority(
        catalog=catalog,
        cards=cards,
        snapshot=snapshot,
        denominator_source=denominator_source,
        expected_denominator_producer=expected_denominator_producer,
        expected_graph_binding=expected_graph_binding,
    )
    denominators = _compile_denominators(
        denominator_authority=denominator_authority,
        targets=target_denominator,
        relations=relation_denominator,
        steps=step_denominator,
        expected_steps=_expected_steps(cards),
    )
    runtime_input = _runtime_input_binding(
        catalog=catalog,
        cards=cards,
        rendered_fragment=rendered,
        snapshot=snapshot,
        denominators=denominators,
    )
    plan = _replayed_work_plan(work_plan)
    if plan["source_snapshot_digest"] != snapshot["snapshot_digest"]:
        _fail(
            "WorkerTransaction WorkPlan source_snapshot_digest does not "
            "match the canonical AuditSnapshot"
        )

    required_methodology_bindings = (
        (
            "current MethodCard catalog",
            catalog.digest,
        ),
        (
            "selected fragment",
            rendered_digest,
        ),
        (
            "audit methodology snapshot",
            snapshot["components"]["methodology"]["digest"],
        ),
        (
            "runtime input binding",
            runtime_input["runtime_input_binding_digest"],
        ),
    )
    required_digests = [digest for _label, digest in required_methodology_bindings]
    if len(required_digests) != len(set(required_digests)):
        _fail("methodology authority dependency digests collide")
    plan_methods = tuple(plan["methodology_digests"])
    missing = [
        label
        for label, digest in required_methodology_bindings
        if digest not in plan_methods
    ]
    if missing:
        _fail(
            "WorkerTransaction WorkPlan methodology_digests omit required "
            "runtime bindings: " + ", ".join(missing)
        )

    unsigned: dict[str, Any] = {
        "schema": AUTHORITY_SCHEMA,
        "catalog_binding": {
            "catalog_identity": CATALOG_IDENTITY,
            "catalog_schema": catalog.schema_version,
            "catalog_version": catalog.catalog_version,
            "catalog_digest": catalog.digest,
            "catalog_source_sha256": catalog.source_sha256,
            "catalog_status": catalog.integration.status,
            "catalog_runtime_authority": catalog.integration.runtime_authority,
        },
        "method_binding": {
            "selection_order": "CATALOG_ORDER",
            "selected_method_count": len(cards),
            "selected_methods": normalized_selections,
            "rendered_fragment_schema": FRAGMENT_SCHEMA,
            "rendered_fragment_media_type": FRAGMENT_MEDIA_TYPE,
            "rendered_fragment_sha256": rendered_digest,
            "rendered_fragment_size_bytes": len(rendered),
            "runtime_input_binding_schema": INPUT_BINDING_SCHEMA,
            "runtime_input_binding_digest": runtime_input[
                "runtime_input_binding_digest"
            ],
        },
        "audit_snapshot_binding": {
            "audit_snapshot_digest": snapshot["snapshot_digest"],
            "methodology_snapshot_digest": snapshot["components"][
                "methodology"
            ]["digest"],
            "source_scope_digest": snapshot["components"]["source_scope"][
                "digest"
            ],
        },
        "work_plan_binding": {
            "work_plan_schema": plan["schema"],
            "run_id": plan["run_id"],
            "phase": plan["phase"],
            "work_unit_id": plan["work_unit_id"],
            "generation": plan["generation"],
            "work_plan_digest": plan["work_plan_digest"],
            "source_snapshot_digest": plan["source_snapshot_digest"],
            "prompt_template_sha256": plan["prompt_template_sha256"],
            "methodology_digests": list(plan_methods),
            "phase_roster_denominator_digest": plan[
                "phase_roster_denominator_digest"
            ],
            "phase_io_contract_digest": plan["phase_io_contract_digest"],
            "phase_io_launch_digest": plan["phase_io_launch_digest"],
            "phase_io_input_set_digest": plan[
                "phase_io_input_set_digest"
            ],
        },
        "denominators": denominators,
        "authority_limits": dict(AUTHORITY_LIMITS),
        "integration": integration_debt_output(),
    }
    try:
        digest = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    except ProgramFactsTypeError as exc:
        _fail(f"runtime authority envelope is not canonical: {exc}", exc)
    return {**unsigned, "authority_digest": digest}


def _authority_value(
    value: Mapping[str, Any] | bytes,
) -> dict[str, Any]:
    authority = _mapping_input(
        value,
        label="MethodCard runtime authority",
        require_final_lf=True,
    )
    _exact_keys(authority, _AUTHORITY_KEYS, "MethodCard runtime authority")
    if authority.get("schema") != AUTHORITY_SCHEMA:
        _fail("MethodCard runtime authority schema is unsupported")
    claimed = _hex64(
        authority.get("authority_digest"),
        "MethodCard runtime authority digest",
    )
    unsigned = dict(authority)
    unsigned.pop("authority_digest")
    expected = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    if claimed != expected:
        _fail("MethodCard runtime authority digest mismatch")
    return authority


def canonical_runtime_authority_bytes(
    value: Mapping[str, Any],
) -> bytes:
    """Serialize a self-consistent envelope with exactly one final LF."""

    authority = _authority_value(value)
    try:
        return canonical_file_bytes(authority)
    except ProgramFactsTypeError as exc:
        _fail(f"MethodCard runtime authority is not canonical: {exc}", exc)


def validate_method_card_runtime_authority(
    value: Mapping[str, Any] | bytes,
    *,
    implementation_root: Path | str,
    audit_snapshot: Mapping[str, Any] | bytes,
    work_plan: Mapping[str, Any] | bytes,
    denominator_source: Mapping[str, Any] | bytes,
    expected_denominator_producer: Mapping[str, Any] | bytes,
    expected_graph_binding: Mapping[str, Any] | bytes,
    expected_catalog: MethodCardCatalog | None = None,
) -> dict[str, Any]:
    """Replay an envelope against every current external authority binding."""

    authority = _authority_value(value)
    if authority.get("authority_limits") != AUTHORITY_LIMITS:
        _fail(
            "MethodCard runtime authority limits cannot confer semantic, "
            "finding, negative, severity, execution, or report authority"
        )
    if authority.get("integration") != integration_debt_output():
        _fail("MethodCard runtime authority integration debt was altered")
    try:
        method_binding = authority["method_binding"]
        denominators = authority["denominators"]
        if not isinstance(method_binding, Mapping) or not isinstance(
            denominators,
            Mapping,
        ):
            _fail("MethodCard runtime authority nested bindings are malformed")
        selected_methods = method_binding["selected_methods"]
        targets = denominators["targets"]
        relations = denominators["relations"]
        steps = denominators["steps"]
    except (KeyError, TypeError) as exc:
        _fail("MethodCard runtime authority binding denominator is malformed", exc)

    rebuilt = compile_method_card_runtime_authority(
        implementation_root=implementation_root,
        audit_snapshot=audit_snapshot,
        work_plan=work_plan,
        selected_methods=selected_methods,
        denominator_source=denominator_source,
        expected_denominator_producer=expected_denominator_producer,
        expected_graph_binding=expected_graph_binding,
        target_denominator=targets,
        relation_denominator=relations,
        step_denominator=steps,
        expected_catalog=expected_catalog,
    )
    if rebuilt != authority:
        _fail(
            "MethodCard runtime authority differs from current external "
            "bindings, work plan identity, or exact denominators"
        )
    return rebuilt


# ---------------------------------------------------------------------------
# Activated v2 authority.  The accepted v1 foundation above intentionally
# remains immutable: v2 is an additive codec with per-MethodCard denominators
# and exact target-to-source identities, but still has no phase/status effect.


def _activated_snapshot_identity(
    audit_snapshot: Mapping[str, Any] | bytes,
) -> dict[str, Any]:
    snapshot = _mapping_input(
        audit_snapshot,
        label="activated MethodCard audit snapshot",
        require_final_lf=True,
    )
    if (
        set(snapshot) != {"schema", "components", "snapshot_digest"}
        or snapshot.get("schema") != SNAPSHOT_SCHEMA
        or not isinstance(snapshot.get("components"), Mapping)
        or set(snapshot["components"]) != _SNAPSHOT_COMPONENT_KEYS
    ):
        _fail("activated MethodCard audit snapshot has schema drift")
    try:
        verdict = classify_snapshot(
            snapshot,
            snapshot,
            has_prior_progress=False,
        )
    except (TypeError, ValueError) as exc:
        _fail(f"activated MethodCard audit snapshot is invalid: {exc}", exc)
    if verdict.state != MATCH:
        _fail("activated MethodCard audit snapshot is not an exact self-match")
    _hex64(snapshot["snapshot_digest"], "activated audit snapshot digest")
    _hex64(
        snapshot["components"]["source_scope"]["digest"],
        "activated audit source-scope digest",
    )
    return snapshot


def _source_file_identity(path: Any, raw: Any, *, label: str) -> dict[str, Any]:
    try:
        portable = validate_portable_path(path)
    except ProgramFactsTypeError as exc:
        _fail(f"{label} path is not portable: {exc}", exc)
    if not isinstance(raw, bytes):
        _fail(f"{label} bytes must be exact bytes")
    return {
        "path": portable,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
    }


def _source_file_identities(
    source_files: Mapping[str, bytes],
) -> tuple[dict[str, Any], ...]:
    if not isinstance(source_files, Mapping) or not source_files:
        _fail("activated denominator source files must be a nonempty mapping")
    rows = tuple(
        sorted(
            (
                _source_file_identity(
                    path,
                    raw,
                    label=f"activated denominator source file {path!r}",
                )
                for path, raw in source_files.items()
            ),
            key=lambda row: row["path"],
        )
    )
    paths = [row["path"] for row in rows]
    if len(paths) != len(set(paths)):
        _fail("activated denominator source file paths are not unique")
    folded = [path.casefold() for path in paths]
    if len(folded) != len(set(folded)):
        _fail("activated denominator source file paths collide by case-fold")
    return rows


def _source_file_identity_value(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{label} must be an object")
    _exact_keys(value, _SOURCE_FILE_IDENTITY_KEYS, label)
    try:
        portable = validate_portable_path(value["path"])
    except ProgramFactsTypeError as exc:
        _fail(f"{label} path is not portable: {exc}", exc)
    size = value["size_bytes"]
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        _fail(f"{label} size_bytes must be a nonnegative integer")
    return {
        "path": portable,
        "sha256": _hex64(value["sha256"], f"{label}.sha256"),
        "size_bytes": size,
    }


def _activated_source_nodes_from_inputs(
    values: Any,
    *,
    coverage: Mapping[str, Any],
    source_identities: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        _fail("activated denominator source nodes must be an ordered sequence")
    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(values):
        label = f"activated denominator source nodes[{index}]"
        if not isinstance(raw, Mapping):
            _fail(f"{label} must be an object")
        _exact_keys(raw, _ACTIVATED_SOURCE_INPUT_NODE_KEYS, label)
        paths = raw["source_paths"]
        if isinstance(paths, (str, bytes)) or not isinstance(paths, Sequence):
            _fail(f"{label}.source_paths must be an ordered sequence")
        normalized_paths: list[str] = []
        for path_index, path in enumerate(paths):
            try:
                portable = validate_portable_path(path)
            except ProgramFactsTypeError as exc:
                _fail(
                    f"{label}.source_paths[{path_index}] is not portable: {exc}",
                    exc,
                )
            if portable not in source_identities:
                _fail(f"{label} names a source path outside the exact source set")
            normalized_paths.append(portable)
        if normalized_paths != sorted(set(normalized_paths)):
            _fail(f"{label}.source_paths must be sorted and unique")
        if coverage["coverage_kind"] == "EXACT" and not normalized_paths:
            _fail(f"{label} requires a source identity under EXACT coverage")
        normalized.append(
            {
                "target_id": _opaque_id(raw["target_id"], f"{label}.target_id"),
                "node_kind": _opaque_id(raw["node_kind"], f"{label}.node_kind"),
                "boundaries": list(
                    _denominator_ids(raw["boundaries"], label=f"{label}.boundaries")
                ),
                "effects": list(
                    _denominator_ids(raw["effects"], label=f"{label}.effects")
                ),
                "entity_properties": list(
                    _denominator_ids(
                        raw["entity_properties"],
                        label=f"{label}.entity_properties",
                    )
                ),
                "source_files": [
                    dict(source_identities[path]) for path in normalized_paths
                ],
            }
        )
    _denominator_ids(
        tuple(row["target_id"] for row in normalized),
        label="activated denominator source target identities",
    )
    return tuple(normalized)


def _activated_source_nodes_value(
    values: Any,
    *,
    coverage: Mapping[str, Any],
    source_identities: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        _fail("activated denominator source nodes must be an ordered sequence")
    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(values):
        label = f"activated denominator source nodes[{index}]"
        if not isinstance(raw, Mapping):
            _fail(f"{label} must be an object")
        _exact_keys(raw, _ACTIVATED_SOURCE_NODE_KEYS, label)
        source_rows = raw["source_files"]
        if isinstance(source_rows, (str, bytes)) or not isinstance(
            source_rows, Sequence
        ):
            _fail(f"{label}.source_files must be an ordered sequence")
        files = [
            _source_file_identity_value(
                row,
                label=f"{label}.source_files[{file_index}]",
            )
            for file_index, row in enumerate(source_rows)
        ]
        if files != sorted(files, key=lambda row: row["path"]):
            _fail(f"{label}.source_files must be in canonical path order")
        if len({row["path"] for row in files}) != len(files):
            _fail(f"{label}.source_files contains duplicate paths")
        if coverage["coverage_kind"] == "EXACT" and not files:
            _fail(f"{label} requires a source identity under EXACT coverage")
        for identity in files:
            if source_identities.get(identity["path"]) != identity:
                _fail(f"{label} source identity is stale or outside the source set")
        normalized.append(
            {
                "target_id": _opaque_id(raw["target_id"], f"{label}.target_id"),
                "node_kind": _opaque_id(raw["node_kind"], f"{label}.node_kind"),
                "boundaries": list(
                    _denominator_ids(raw["boundaries"], label=f"{label}.boundaries")
                ),
                "effects": list(
                    _denominator_ids(raw["effects"], label=f"{label}.effects")
                ),
                "entity_properties": list(
                    _denominator_ids(
                        raw["entity_properties"],
                        label=f"{label}.entity_properties",
                    )
                ),
                "source_files": files,
            }
        )
    _denominator_ids(
        tuple(row["target_id"] for row in normalized),
        label="activated denominator source target identities",
    )
    return tuple(normalized)


def _activated_graph_digest(
    *,
    graph_schema: str,
    coverage: Mapping[str, Any],
    source_files: Sequence[Mapping[str, Any]],
    nodes: Sequence[Mapping[str, Any]],
    relations: Sequence[Mapping[str, Any]],
) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "graph_schema": graph_schema,
                "coverage": dict(coverage),
                "source_files": [dict(row) for row in source_files],
                "nodes": [dict(row) for row in nodes],
                "relations": [dict(row) for row in relations],
            }
        )
    ).hexdigest()


def compile_activated_method_card_denominator_source(
    *,
    audit_snapshot: Mapping[str, Any] | bytes,
    producer: Mapping[str, Any] | bytes,
    graph_schema: str,
    coverage: Mapping[str, Any],
    nodes: Sequence[Mapping[str, Any]],
    relations: Sequence[Mapping[str, Any]],
    source_files: Mapping[str, bytes],
) -> dict[str, Any]:
    """Compile a v2 graph source with exact target-to-file identities."""

    snapshot = _activated_snapshot_identity(audit_snapshot)
    normalized_producer = _producer_binding(
        producer,
        label="activated denominator source producer",
    )
    normalized_graph_schema = _opaque_id(
        graph_schema,
        "activated denominator source graph schema",
    )
    normalized_coverage = _coverage_binding(coverage)
    identities = _source_file_identities(source_files)
    identity_map = {row["path"]: row for row in identities}
    normalized_nodes = _activated_source_nodes_from_inputs(
        nodes,
        coverage=normalized_coverage,
        source_identities=identity_map,
    )
    used_paths = {
        identity["path"]
        for node in normalized_nodes
        for identity in node["source_files"]
    }
    if used_paths != set(identity_map):
        _fail(
            "activated denominator source file set must exactly equal the "
            "target-bound source identity union"
        )
    normalized_relations = _denominator_source_relations(
        relations,
        target_ids=frozenset(row["target_id"] for row in normalized_nodes),
    )
    graph_digest = _activated_graph_digest(
        graph_schema=normalized_graph_schema,
        coverage=normalized_coverage,
        source_files=identities,
        nodes=normalized_nodes,
        relations=normalized_relations,
    )
    unsigned = {
        "schema": ACTIVATED_DENOMINATOR_SOURCE_SCHEMA,
        "producer": normalized_producer,
        "audit_snapshot_digest": snapshot["snapshot_digest"],
        "source_scope_digest": snapshot["components"]["source_scope"]["digest"],
        "graph_schema": normalized_graph_schema,
        "graph_digest": graph_digest,
        "coverage": normalized_coverage,
        "source_files": list(identities),
        "nodes": list(normalized_nodes),
        "relations": list(normalized_relations),
    }
    return {
        **unsigned,
        "source_digest": hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest(),
    }


def _activated_denominator_source_value(
    value: Mapping[str, Any] | bytes,
    *,
    snapshot: Mapping[str, Any],
    expected_producer: Mapping[str, Any] | bytes,
    expected_graph: Mapping[str, Any] | bytes,
    source_files: Mapping[str, bytes],
) -> dict[str, Any]:
    source = _mapping_input(
        value,
        label="activated MethodCard denominator source",
        require_final_lf=True,
    )
    _exact_keys(
        source,
        _ACTIVATED_DENOMINATOR_SOURCE_KEYS,
        "activated MethodCard denominator source",
    )
    if source.get("schema") != ACTIVATED_DENOMINATOR_SOURCE_SCHEMA:
        _fail("activated MethodCard denominator source schema is unsupported")
    claimed = _hex64(source["source_digest"], "activated source digest")
    unsigned = dict(source)
    unsigned.pop("source_digest")
    if hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest() != claimed:
        _fail("activated MethodCard denominator source digest mismatch")
    producer = _producer_binding(
        source["producer"],
        label="activated denominator source producer",
    )
    if producer != _producer_binding(
        expected_producer,
        label="expected activated denominator producer",
    ):
        _fail("activated denominator source producer is stale")
    if source["audit_snapshot_digest"] != snapshot["snapshot_digest"]:
        _fail("activated denominator source snapshot is stale")
    if (
        source["source_scope_digest"]
        != snapshot["components"]["source_scope"]["digest"]
    ):
        _fail("activated denominator source scope is stale")
    coverage = _coverage_binding(source["coverage"])
    expected_identities = list(_source_file_identities(source_files))
    raw_identities = source["source_files"]
    if isinstance(raw_identities, (str, bytes)) or not isinstance(
        raw_identities, Sequence
    ):
        _fail("activated denominator source file identities must be ordered")
    identities = [
        _source_file_identity_value(
            row,
            label=f"activated denominator source file identity[{index}]",
        )
        for index, row in enumerate(raw_identities)
    ]
    if identities != expected_identities:
        _fail("activated denominator source file identity is stale or mismatched")
    identity_map = {row["path"]: row for row in identities}
    nodes = _activated_source_nodes_value(
        source["nodes"],
        coverage=coverage,
        source_identities=identity_map,
    )
    used_paths = {
        identity["path"] for node in nodes for identity in node["source_files"]
    }
    if used_paths != set(identity_map):
        _fail("activated source identity denominator differs from target bindings")
    relations = _denominator_source_relations(
        source["relations"],
        target_ids=frozenset(row["target_id"] for row in nodes),
    )
    graph_schema = _opaque_id(
        source["graph_schema"],
        "activated denominator graph schema",
    )
    graph_digest = _hex64(source["graph_digest"], "activated graph digest")
    if graph_digest != _activated_graph_digest(
        graph_schema=graph_schema,
        coverage=coverage,
        source_files=identities,
        nodes=nodes,
        relations=relations,
    ):
        _fail("activated denominator source graph digest mismatch")
    if {
        "graph_schema": graph_schema,
        "graph_digest": graph_digest,
    } != _graph_binding(expected_graph, label="expected activated graph"):
        _fail("activated denominator graph is stale")
    normalized = {
        "schema": ACTIVATED_DENOMINATOR_SOURCE_SCHEMA,
        "producer": producer,
        "audit_snapshot_digest": snapshot["snapshot_digest"],
        "source_scope_digest": snapshot["components"]["source_scope"]["digest"],
        "graph_schema": graph_schema,
        "graph_digest": graph_digest,
        "coverage": coverage,
        "source_files": identities,
        "nodes": list(nodes),
        "relations": list(relations),
        "source_digest": claimed,
    }
    if normalized != source:
        _fail("activated denominator source is noncanonical")
    return normalized


def _activated_method_denominators(
    *,
    cards: Sequence[MethodCard],
    source: Mapping[str, Any],
) -> tuple[dict[str, Any], ...]:
    nodes_by_id = {row["target_id"]: row for row in source["nodes"]}
    coverage = source["coverage"]
    result: list[dict[str, Any]] = []
    for card in cards:
        selectors = dict(card.target_selector)
        selected_target_ids = {
            node["target_id"]
            for node in source["nodes"]
            if node["node_kind"] in card.node_kinds
            and (
                set(node["boundaries"]) & set(selectors["boundaries_any"])
                or set(node["effects"]) & set(selectors["effects_any"])
                or set(node["entity_properties"])
                & set(selectors["entity_properties_any"])
            )
        }
        selected_relations = [
            dict(row)
            for row in source["relations"]
            if row["selector"] in card.relation_selectors
        ]
        for relation in selected_relations:
            selected_target_ids.add(relation["source_target_id"])
            selected_target_ids.add(relation["destination_target_id"])
        targets = [
            {
                "target_id": target_id,
                "source_files": [
                    dict(identity)
                    for identity in nodes_by_id[target_id]["source_files"]
                ],
            }
            for target_id in sorted(selected_target_ids)
        ]
        selected_relations.sort(key=lambda row: row["relation_id"])
        steps = [
            {
                "method_id": card.method_id,
                "method_version": card.method_version,
                "step_id": step.step_id,
            }
            for step in card.required_steps
        ]
        unsigned = {
            "method_id": card.method_id,
            "method_version": card.method_version,
            "coverage_kind": coverage["coverage_kind"],
            "unknown_remainder": coverage["unknown_remainder"],
            "limitation_reason": coverage["limitation_reason"],
            "target_count": len(targets),
            "relation_count": len(selected_relations),
            "step_count": len(steps),
            "targets": targets,
            "relations": selected_relations,
            "steps": steps,
        }
        result.append(
            {
                **unsigned,
                "method_denominator_digest": hashlib.sha256(
                    canonical_json_bytes(unsigned)
                ).hexdigest(),
            }
        )
    return tuple(result)


def _compile_activated_denominator_authority(
    *,
    catalog: MethodCardCatalog,
    cards: Sequence[MethodCard],
    snapshot: Mapping[str, Any],
    denominator_source: Mapping[str, Any] | bytes,
    expected_denominator_producer: Mapping[str, Any] | bytes,
    expected_graph_binding: Mapping[str, Any] | bytes,
    source_files: Mapping[str, bytes],
) -> dict[str, Any]:
    source = _activated_denominator_source_value(
        denominator_source,
        snapshot=snapshot,
        expected_producer=expected_denominator_producer,
        expected_graph=expected_graph_binding,
        source_files=source_files,
    )
    selector_binding = _selector_binding(cards)
    selector_digest = hashlib.sha256(
        canonical_json_bytes(selector_binding)
    ).hexdigest()
    selector_inputs_digest = hashlib.sha256(
        canonical_json_bytes(
            {
                "graph_schema": source["graph_schema"],
                "graph_digest": source["graph_digest"],
                "source_digest": source["source_digest"],
                "source_files": source["source_files"],
                "nodes": source["nodes"],
                "relations": source["relations"],
            }
        )
    ).hexdigest()
    methods = _activated_method_denominators(cards=cards, source=source)
    coverage = source["coverage"]
    unsigned = {
        "schema": ACTIVATED_DENOMINATOR_AUTHORITY_SCHEMA,
        "producer": source["producer"],
        "audit_snapshot_digest": snapshot["snapshot_digest"],
        "source_scope_digest": snapshot["components"]["source_scope"]["digest"],
        "graph_schema": source["graph_schema"],
        "graph_digest": source["graph_digest"],
        "source_digest": source["source_digest"],
        "catalog_digest": catalog.digest,
        "catalog_source_sha256": catalog.source_sha256,
        "selected_methods": [
            {"method_id": card.method_id, "method_version": card.method_version}
            for card in cards
        ],
        "selector_digest": selector_digest,
        "selector_inputs_digest": selector_inputs_digest,
        "coverage_kind": coverage["coverage_kind"],
        "unknown_remainder": coverage["unknown_remainder"],
        "limitation_reason": coverage["limitation_reason"],
        "method_count": len(methods),
        "methods": list(methods),
    }
    return {
        **unsigned,
        "denominator_authority_digest": hashlib.sha256(
            canonical_json_bytes(unsigned)
        ).hexdigest(),
    }


def _compile_activated_denominators(
    authority: Mapping[str, Any],
) -> dict[str, Any]:
    methods = [dict(row) for row in authority["methods"]]
    debt = (
        []
        if authority["coverage_kind"] == "EXACT"
        else [
            {
                "debt_code": "UNKNOWN_DENOMINATOR_REMAINDER",
                "reason": authority["limitation_reason"],
            }
        ]
    )
    unsigned = {
        "denominator_authority_schema": ACTIVATED_DENOMINATOR_AUTHORITY_SCHEMA,
        "denominator_authority_digest": authority[
            "denominator_authority_digest"
        ],
        "denominator_source_digest": authority["source_digest"],
        "graph_digest": authority["graph_digest"],
        "selector_digest": authority["selector_digest"],
        "selector_inputs_digest": authority["selector_inputs_digest"],
        "coverage_kind": authority["coverage_kind"],
        "unknown_remainder": authority["unknown_remainder"],
        "limitation_reason": authority["limitation_reason"],
        "debt": debt,
        "method_count": len(methods),
        "target_count": sum(row["target_count"] for row in methods),
        "relation_count": sum(row["relation_count"] for row in methods),
        "step_count": sum(row["step_count"] for row in methods),
        "methods": methods,
    }
    return {
        **unsigned,
        "denominator_digest": hashlib.sha256(
            canonical_json_bytes(unsigned)
        ).hexdigest(),
    }


def _activated_runtime_input_binding(
    *,
    catalog: MethodCardCatalog,
    cards: Sequence[MethodCard],
    rendered_fragment: bytes,
    snapshot: Mapping[str, Any],
    denominators: Mapping[str, Any],
) -> dict[str, Any]:
    unsigned = {
        "schema": ACTIVATED_INPUT_BINDING_SCHEMA,
        "catalog_digest": catalog.digest,
        "catalog_source_sha256": catalog.source_sha256,
        "selected_methods": [
            {"method_id": card.method_id, "method_version": card.method_version}
            for card in cards
        ],
        "rendered_fragment_sha256": hashlib.sha256(
            rendered_fragment
        ).hexdigest(),
        "rendered_fragment_size_bytes": len(rendered_fragment),
        "audit_snapshot_digest": snapshot["snapshot_digest"],
        "methodology_snapshot_digest": snapshot["components"]["methodology"][
            "digest"
        ],
        "source_scope_digest": snapshot["components"]["source_scope"]["digest"],
        "denominator_authority_digest": denominators[
            "denominator_authority_digest"
        ],
        "denominator_digest": denominators["denominator_digest"],
        "method_denominator_digests": [
            row["method_denominator_digest"] for row in denominators["methods"]
        ],
    }
    return {
        **unsigned,
        "runtime_input_binding_digest": hashlib.sha256(
            canonical_json_bytes(unsigned)
        ).hexdigest(),
    }


def compile_activated_method_card_runtime_input_binding(
    *,
    implementation_root: Path | str,
    audit_snapshot: Mapping[str, Any] | bytes,
    selected_methods: Sequence[Mapping[str, Any]],
    denominator_source: Mapping[str, Any] | bytes,
    expected_denominator_producer: Mapping[str, Any] | bytes,
    expected_graph_binding: Mapping[str, Any] | bytes,
    source_files: Mapping[str, bytes],
    expected_catalog: MethodCardCatalog | None = None,
) -> dict[str, Any]:
    """Compile the acyclic activated v2 input before a WorkPlan exists."""

    root, catalog = _current_catalog(implementation_root, expected_catalog)
    snapshot = _current_snapshot(audit_snapshot, implementation_root=root)
    cards = _selected_cards(catalog, selected_methods)
    selections = [
        {"method_id": card.method_id, "method_version": card.method_version}
        for card in cards
    ]
    rendered = render_selected_method_fragment(catalog, selections)
    denominator_authority = _compile_activated_denominator_authority(
        catalog=catalog,
        cards=cards,
        snapshot=snapshot,
        denominator_source=denominator_source,
        expected_denominator_producer=expected_denominator_producer,
        expected_graph_binding=expected_graph_binding,
        source_files=source_files,
    )
    denominators = _compile_activated_denominators(denominator_authority)
    return _activated_runtime_input_binding(
        catalog=catalog,
        cards=cards,
        rendered_fragment=rendered,
        snapshot=snapshot,
        denominators=denominators,
    )


def activated_integration_output() -> dict[str, Any]:
    """Return v2 schema activation without claiming production cutover."""

    foundation = integration_debt_output()
    return {
        "schema": ACTIVATED_INTEGRATION_SCHEMA,
        "status": "ACTIVATED_AUTHORITY_NOT_PRODUCTION_INTEGRATED",
        "runtime_authority": True,
        "driver_cutover": False,
        "phase_io_registered": False,
        "worker_transaction_arm_bound": False,
        "application_consumer_cutover": False,
        "phase_status_authority": False,
        "foundation_integration_schema": foundation["schema"],
        "foundation_integration_digest": hashlib.sha256(
            canonical_json_bytes(foundation)
        ).hexdigest(),
    }


def compile_activated_method_card_runtime_authority(
    *,
    implementation_root: Path | str,
    audit_snapshot: Mapping[str, Any] | bytes,
    work_plan: Mapping[str, Any] | bytes,
    selected_methods: Sequence[Mapping[str, Any]],
    denominator_source: Mapping[str, Any] | bytes,
    expected_denominator_producer: Mapping[str, Any] | bytes,
    expected_graph_binding: Mapping[str, Any] | bytes,
    source_files: Mapping[str, bytes],
    expected_catalog: MethodCardCatalog | None = None,
) -> dict[str, Any]:
    """Compile activated per-card authority without production/status power."""

    root, catalog = _current_catalog(implementation_root, expected_catalog)
    snapshot = _current_snapshot(audit_snapshot, implementation_root=root)
    cards = _selected_cards(catalog, selected_methods)
    selections = [
        {"method_id": card.method_id, "method_version": card.method_version}
        for card in cards
    ]
    rendered = render_selected_method_fragment(catalog, selections)
    rendered_digest = hashlib.sha256(rendered).hexdigest()
    denominator_authority = _compile_activated_denominator_authority(
        catalog=catalog,
        cards=cards,
        snapshot=snapshot,
        denominator_source=denominator_source,
        expected_denominator_producer=expected_denominator_producer,
        expected_graph_binding=expected_graph_binding,
        source_files=source_files,
    )
    denominators = _compile_activated_denominators(denominator_authority)
    runtime_input = _activated_runtime_input_binding(
        catalog=catalog,
        cards=cards,
        rendered_fragment=rendered,
        snapshot=snapshot,
        denominators=denominators,
    )
    plan = _replayed_work_plan(work_plan)
    if plan["source_snapshot_digest"] != snapshot["snapshot_digest"]:
        _fail("activated WorkPlan source snapshot is stale")
    required_bindings = (
        ("current MethodCard catalog", catalog.digest),
        ("selected fragment", rendered_digest),
        (
            "audit methodology snapshot",
            snapshot["components"]["methodology"]["digest"],
        ),
        (
            "activated runtime input binding",
            runtime_input["runtime_input_binding_digest"],
        ),
    )
    required_digests = [digest for _label, digest in required_bindings]
    if len(required_digests) != len(set(required_digests)):
        _fail("activated methodology authority dependency digests collide")
    plan_methods = tuple(plan["methodology_digests"])
    missing = [
        label for label, digest in required_bindings if digest not in plan_methods
    ]
    if missing:
        _fail(
            "activated WorkPlan methodology_digests omit required bindings: "
            + ", ".join(missing)
        )
    unsigned = {
        "schema": ACTIVATED_AUTHORITY_SCHEMA,
        "catalog_binding": {
            "catalog_identity": CATALOG_IDENTITY,
            "catalog_schema": catalog.schema_version,
            "catalog_version": catalog.catalog_version,
            "catalog_digest": catalog.digest,
            "catalog_source_sha256": catalog.source_sha256,
            "catalog_status": catalog.integration.status,
            "catalog_runtime_authority": catalog.integration.runtime_authority,
        },
        "method_binding": {
            "selection_order": "CATALOG_ORDER",
            "selected_method_count": len(cards),
            "selected_methods": selections,
            "rendered_fragment_schema": FRAGMENT_SCHEMA,
            "rendered_fragment_media_type": FRAGMENT_MEDIA_TYPE,
            "rendered_fragment_sha256": rendered_digest,
            "rendered_fragment_size_bytes": len(rendered),
            "runtime_input_binding_schema": ACTIVATED_INPUT_BINDING_SCHEMA,
            "runtime_input_binding_digest": runtime_input[
                "runtime_input_binding_digest"
            ],
        },
        "audit_snapshot_binding": {
            "audit_snapshot_digest": snapshot["snapshot_digest"],
            "methodology_snapshot_digest": snapshot["components"]["methodology"][
                "digest"
            ],
            "source_scope_digest": snapshot["components"]["source_scope"][
                "digest"
            ],
        },
        "work_plan_binding": {
            "work_plan_schema": plan["schema"],
            "run_id": plan["run_id"],
            "phase": plan["phase"],
            "work_unit_id": plan["work_unit_id"],
            "generation": plan["generation"],
            "work_plan_digest": plan["work_plan_digest"],
            "source_snapshot_digest": plan["source_snapshot_digest"],
            "prompt_template_sha256": plan["prompt_template_sha256"],
            "methodology_digests": list(plan_methods),
            "phase_roster_denominator_digest": plan[
                "phase_roster_denominator_digest"
            ],
            "phase_io_contract_digest": plan["phase_io_contract_digest"],
            "phase_io_launch_digest": plan["phase_io_launch_digest"],
            "phase_io_input_set_digest": plan["phase_io_input_set_digest"],
        },
        "denominators": denominators,
        "authority_limits": dict(AUTHORITY_LIMITS),
        "integration": activated_integration_output(),
    }
    return {
        **unsigned,
        "authority_digest": hashlib.sha256(
            canonical_json_bytes(unsigned)
        ).hexdigest(),
    }


def _activated_authority_value(
    value: Mapping[str, Any] | bytes,
) -> dict[str, Any]:
    authority = _mapping_input(
        value,
        label="activated MethodCard runtime authority",
        require_final_lf=True,
    )
    _exact_keys(authority, _AUTHORITY_KEYS, "activated MethodCard runtime authority")
    if authority.get("schema") != ACTIVATED_AUTHORITY_SCHEMA:
        _fail("activated MethodCard runtime authority schema is unsupported")
    claimed = _hex64(
        authority.get("authority_digest"),
        "activated MethodCard runtime authority digest",
    )
    unsigned = dict(authority)
    unsigned.pop("authority_digest")
    if hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest() != claimed:
        _fail("activated MethodCard runtime authority digest mismatch")
    if authority.get("authority_limits") != AUTHORITY_LIMITS:
        _fail("activated MethodCard runtime authority limits were altered")
    if authority.get("integration") != activated_integration_output():
        _fail("activated MethodCard integration status was altered")
    return authority


def canonical_activated_runtime_authority_bytes(
    value: Mapping[str, Any],
) -> bytes:
    authority = _activated_authority_value(value)
    try:
        return canonical_file_bytes(authority)
    except ProgramFactsTypeError as exc:
        _fail(f"activated MethodCard runtime authority is not canonical: {exc}", exc)


def validate_activated_method_card_runtime_authority(
    value: Mapping[str, Any] | bytes,
    *,
    implementation_root: Path | str,
    audit_snapshot: Mapping[str, Any] | bytes,
    work_plan: Mapping[str, Any] | bytes,
    denominator_source: Mapping[str, Any] | bytes,
    expected_denominator_producer: Mapping[str, Any] | bytes,
    expected_graph_binding: Mapping[str, Any] | bytes,
    source_files: Mapping[str, bytes],
    expected_catalog: MethodCardCatalog | None = None,
) -> dict[str, Any]:
    """Replay activated v2 authority against every current external input."""

    authority = _activated_authority_value(value)
    try:
        selections = authority["method_binding"]["selected_methods"]
    except (KeyError, TypeError) as exc:
        _fail("activated MethodCard method binding is malformed", exc)
    rebuilt = compile_activated_method_card_runtime_authority(
        implementation_root=implementation_root,
        audit_snapshot=audit_snapshot,
        work_plan=work_plan,
        selected_methods=selections,
        denominator_source=denominator_source,
        expected_denominator_producer=expected_denominator_producer,
        expected_graph_binding=expected_graph_binding,
        source_files=source_files,
        expected_catalog=expected_catalog,
    )
    if rebuilt != authority:
        _fail("activated MethodCard runtime authority is stale or cross-bound")
    return rebuilt


__all__ = [
    "ACTIVATED_AUTHORITY_SCHEMA",
    "ACTIVATED_DENOMINATOR_AUTHORITY_SCHEMA",
    "ACTIVATED_DENOMINATOR_SOURCE_SCHEMA",
    "ACTIVATED_INPUT_BINDING_SCHEMA",
    "ACTIVATED_INTEGRATION_SCHEMA",
    "AUTHORITY_LIMITS",
    "AUTHORITY_SCHEMA",
    "DENOMINATOR_AUTHORITY_SCHEMA",
    "DENOMINATOR_SOURCE_SCHEMA",
    "FRAGMENT_MEDIA_TYPE",
    "FRAGMENT_SCHEMA",
    "INPUT_BINDING_SCHEMA",
    "INTEGRATION_DEBT",
    "INTEGRATION_SCHEMA",
    "MethodCardRuntimeAuthorityError",
    "canonical_denominator_authority_bytes",
    "canonical_activated_runtime_authority_bytes",
    "canonical_runtime_authority_bytes",
    "compile_method_card_denominator_authority",
    "compile_activated_method_card_denominator_source",
    "compile_activated_method_card_runtime_authority",
    "compile_activated_method_card_runtime_input_binding",
    "compile_method_card_runtime_input_binding",
    "compile_method_card_runtime_authority",
    "integration_debt_output",
    "activated_integration_output",
    "render_selected_method_fragment",
    "validate_method_card_denominator_authority",
    "validate_activated_method_card_runtime_authority",
    "validate_method_card_runtime_authority",
]
