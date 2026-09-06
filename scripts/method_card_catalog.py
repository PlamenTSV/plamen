"""Strict, dependency-free loader for the universal MethodCard Catalog R1.

This module is a catalog and validation substrate.  It deliberately has no
driver, PhaseIO, prompt-compilation, provider, or worker-runtime authority.
Those integrations remain explicit catalog debt until separately implemented
and reviewed.

The ``.yaml`` catalog uses the JSON subset of YAML 1.2.  Requiring one
canonical JSON representation avoids parser variation, duplicate-key
ambiguity, and cross-OS digest drift without adding a YAML dependency.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import unicodedata
from typing import Any, Mapping, Sequence


CATALOG_SCHEMA = "plamen.method_card_catalog.v1"
APPLICATION_RECEIPT_SCHEMA = "plamen.method_card_application_receipt.v1"

UNIVERSAL_OPERATOR_IDS = (
    "authority.capability.v1",
    "value.accounting-conservation.v1",
    "state.transition-legality.v1",
    "lifecycle.ordering.v1",
    "boundary.numerical.v1",
    "symmetry.reversibility.v1",
    "identity.domain-separation.v1",
    "external.interaction-assumption.v1",
    "availability.resource-control.v1",
    "configuration.governance-upgrade.v1",
    "composition.shared-state.v1",
    "concurrency.finality-replay.v1",
)

UNIVERSAL_SEMANTIC_OPERATORS = (
    "authority_capability",
    "value_accounting",
    "state_transition",
    "lifecycle_ordering",
    "boundary_numerical",
    "symmetry_reversibility",
    "identity_domain",
    "external_assumption",
    "availability_resources",
    "configuration_governance_upgrade",
    "composition_shared_state",
    "concurrency_finality_replay",
)

NODE_KINDS = frozenset(
    {
        "account",
        "choice",
        "configuration",
        "contract",
        "entrypoint",
        "external_dependency",
        "function",
        "governance_action",
        "instruction",
        "lifecycle_resource",
        "message",
        "module",
        "shared_state",
        "state",
        "storage",
        "transaction",
    }
)

CAPABILITIES = frozenset(
    {
        "boundary_values",
        "call_graph",
        "concurrency",
        "configuration",
        "control_flow",
        "external_interactions",
        "finality",
        "governance",
        "identity_domains",
        "lifecycle",
        "paired_operations",
        "reads",
        "replay",
        "resource_usage",
        "serialization",
        "shared_state",
        "source_locations",
        "state_transitions",
        "storage_layout",
        "symbols",
        "upgrade_paths",
        "value_flow",
        "writes",
    }
)

# Matches the reviewed Program Facts precision vocabulary.  A MethodCard can
# accept weaker fidelity without pretending that weaker evidence is exact.
FIDELITIES = frozenset({"SYNTACTIC", "HEURISTIC", "MAY", "EXACT"})

TARGET_EFFECTS = frozenset(
    {
        "asset_transfer",
        "authorization",
        "balance_write",
        "callback",
        "cleanup",
        "configuration_change",
        "debt_write",
        "external_call",
        "governance_change",
        "identity_binding",
        "initialization",
        "message_processing",
        "progress",
        "resource_consumption",
        "state_write",
        "supply_write",
        "upgrade",
    }
)

TARGET_PROPERTIES = frozenset(
    {
        "accounting",
        "authority",
        "availability",
        "composition",
        "concurrency",
        "domain_separation",
        "external_assumption",
        "finality",
        "lifecycle",
        "ordering",
        "replay",
        "reversibility",
        "state_legality",
    }
)

BOUNDARIES = frozenset(
    {
        "discontinuity",
        "empty",
        "epoch",
        "initial",
        "maximum",
        "minimum",
        "one",
        "overflow_domain",
        "precision_change",
        "rounding",
        "threshold",
        "truncation",
        "zero",
    }
)

RELATION_SELECTORS = frozenset(
    {
        "authorizes",
        "before_after",
        "calls",
        "concurrent_with",
        "crosses_domain",
        "delegates_to",
        "flows_value_to",
        "inverse_of",
        "paired_with",
        "reads_same_state",
        "replay_of",
        "shares_dependency",
        "transitions_to",
        "writes_same_state",
    }
)

REQUIRED_RECEIPTS = (
    "targets_examined",
    "relation_coverage",
    "steps_completed",
    "evidence_locations",
    "outcomes",
    "unresolved_assumptions",
)

_INTEGRATION_DEBT = (
    "bind_catalog_digest_to_run_manifest_phaseio_and_workplan",
    "compile_graph_targets_and_relations_into_obligations",
    "render_or_reference_catalog_methods_from_consumer_prompts",
    "retire_duplicate_normative_method_content_after_parity",
)

_TOP_KEYS = frozenset(
    {"catalog_version", "integration", "methods", "schema_version"}
)
_INTEGRATION_KEYS = frozenset({"debt", "runtime_authority", "status"})
_CARD_KEYS = frozenset(
    {
        "applies_to",
        "completion_policy",
        "method_id",
        "method_version",
        "operator_instruction",
        "prompt_fragment",
        "relation_selectors",
        "required_receipts",
        "required_steps",
        "semantic_operator",
        "target_selector",
        "title",
    }
)
_APPLIES_KEYS = frozenset(
    {
        "accepted_fidelity",
        "node_kinds",
        "optional_capabilities",
        "required_capabilities",
    }
)
_TARGET_KEYS = frozenset(
    {"boundaries_any", "effects_any", "entity_properties_any"}
)
_STEP_KEYS = frozenset({"instruction", "step_id"})
_PROMPT_KEYS = frozenset({"path", "sha256"})
_COMPLETION_KEYS = frozenset(
    {
        "allow_not_applicable",
        "material_unresolved_requires_human_review",
        "valid_not_applicable_reasons",
    }
)
_RECEIPT_KEYS = frozenset(
    {
        "catalog_digest",
        "evidence_locations",
        "method_id",
        "method_version",
        "not_applicable",
        "outcomes",
        "relation_coverage",
        "schema_version",
        "status",
        "steps_completed",
        "targets_examined",
        "unresolved_assumptions",
    }
)
_TARGET_RECEIPT_KEYS = frozenset({"node_kind", "target_id"})
_RELATION_RECEIPT_KEYS = frozenset(
    {"relation_ids", "selector", "status"}
)
_EVIDENCE_KEYS = frozenset({"line_end", "line_start", "path"})
_OUTCOME_KEYS = frozenset({"candidate_ids", "detail", "kind"})
_NOT_APPLICABLE_KEYS = frozenset(
    {"code", "detail", "selector_evidence"}
)

_SEMVER_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$",
    re.ASCII,
)
_METHOD_ID_RE = re.compile(
    r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+\.v[1-9][0-9]*$",
    re.ASCII,
)
_IDENTIFIER_RE = re.compile(
    r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$", re.ASCII
)
_OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$", re.ASCII)
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_FINDING_ID_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:H|M|L|C|I)-0*[1-9][0-9]*(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_CAMEL_TARGET_RE = re.compile(
    r"\b[A-Z][a-z0-9]+(?:[A-Z][A-Za-z0-9]*)+\b"
)
_TARGET_LOCATION_RE = re.compile(
    r"(?:^|[\s(])(?:contracts?|programs?|sources?|crates?)/"
    r"[^\s)]+\.(?:sol|rs|move|go|daml)(?::[0-9]+)?",
    re.IGNORECASE,
)
_MOTIVATING_ANSWER_RE = re.compile(
    r"\b(?:expected|known|motivating|target-specific)\s+"
    r"(?:vulnerab(?:ility|le)|answer|finding|exploit)\b",
    re.IGNORECASE,
)
_ABSOLUTE_PATH_RE = re.compile(
    r"(?:[A-Za-z]:[\\/]|\\\\[^\\\s]+\\[^\\\s]+|"
    r"/(?:home|Users|private|tmp|var)/)"
)
_WINDOWS_REPARSE_ATTRIBUTE = 0x400
_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "AUX",
        "CON",
        "NUL",
        "PRN",
        *(f"COM{index}" for index in range(1, 10)),
        *(f"LPT{index}" for index in range(1, 10)),
    }
)
_FORBIDDEN_PATH_CHARS = frozenset('\x00<>:"|?*')
_MAX_CATALOG_BYTES = 2 * 1024 * 1024
_MAX_PROMPT_BYTES = 4 * 1024 * 1024

_KERNEL_PREFIX = (
    "<!-- PLAMEN_BREADTH_SEMANTIC_KERNEL: BEGIN v1.0.0 -->\n"
    "<!-- GENERATED PROJECTION: method content is owned only by "
    "methodology/method-cards-v1.yaml; do not edit this file directly. -->\n"
    "## Universal Breadth Semantic-Operator Kernel (MANDATORY, v1.0.0)\n"
    "\n"
    "This is the minimum security-reasoning floor for every smart-contract "
    "breadth\n"
    "worker. Apply all twelve operators to the assigned scope; conditional "
    "skills\n"
    "add detail but never replace this pass.\n"
    "\n"
    "For each applicable operator, enumerate the concrete targets and "
    "relations in\n"
    "scope, trace both expected and adversarial paths, compare the result "
    "with\n"
    "source-backed intent, and cite the evidence examined. Emit a candidate "
    "when a\n"
    "safety property may fail. If evidence is missing or contradictory, "
    "record the\n"
    "unresolved assumption instead of assigning the behavior safe. A "
    "restatement of\n"
    "an operator without target-level evidence is not application.\n"
    "\n"
)
_KERNEL_SUFFIX = (
    "<!-- PLAMEN_BREADTH_SEMANTIC_KERNEL: END v1.0.0 -->\n"
)


class MethodCardCatalogError(ValueError):
    """The MethodCard catalog or an application receipt is not trustworthy."""


@dataclass(frozen=True)
class MethodStep:
    step_id: str
    instruction: str


@dataclass(frozen=True)
class PromptFragment:
    path: str
    sha256: str
    content: bytes


@dataclass(frozen=True)
class MethodCard:
    method_id: str
    title: str
    method_version: str
    semantic_operator: str
    operator_instruction: str
    node_kinds: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    optional_capabilities: tuple[str, ...]
    accepted_fidelity: tuple[tuple[str, tuple[str, ...]], ...]
    target_selector: tuple[tuple[str, tuple[str, ...]], ...]
    relation_selectors: tuple[str, ...]
    required_steps: tuple[MethodStep, ...]
    required_receipts: tuple[str, ...]
    allow_not_applicable: bool
    valid_not_applicable_reasons: tuple[str, ...]
    material_unresolved_requires_human_review: bool
    prompt_fragment: PromptFragment


@dataclass(frozen=True)
class CatalogIntegration:
    status: str
    runtime_authority: bool
    debt: tuple[str, ...]


@dataclass(frozen=True)
class MethodCardCatalog:
    schema_version: str
    catalog_version: str
    integration: CatalogIntegration
    cards: tuple[MethodCard, ...]
    digest: str
    source_sha256: str
    source_bytes: bytes
    source_path: Path
    repo_root: Path

    def card(self, method_id: str) -> MethodCard:
        matches = [card for card in self.cards if card.method_id == method_id]
        if not matches:
            raise MethodCardCatalogError(
                f"unknown MethodCard method_id: {method_id!r}"
            )
        return matches[0]

    def to_mapping(self) -> dict[str, Any]:
        return _load_json_subset(self.source_bytes, "loaded MethodCard catalog")


def _fail(message: str) -> None:
    raise MethodCardCatalogError(message)


def canonical_catalog_bytes(value: Any) -> bytes:
    """Return the sole accepted source representation and digest input."""

    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            separators=(",", ": "),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise MethodCardCatalogError(
            f"catalog is not canonical JSON data: {exc}"
        ) from exc
    return (rendered + "\n").encode("utf-8")


def _duplicate_rejecting_pairs(
    pairs: Sequence[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_float(_: str) -> Any:
    _fail("catalog numbers must not use floating-point JSON values")


def _load_json_subset(raw: bytes, label: str) -> dict[str, Any]:
    if len(raw) > _MAX_CATALOG_BYTES:
        _fail(f"{label} exceeds the MethodCard catalog size limit")
    if raw.startswith(b"\xef\xbb\xbf"):
        _fail(f"{label} must not contain a UTF-8 BOM")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_duplicate_rejecting_pairs,
            parse_float=_reject_float,
            parse_constant=lambda token: _fail(
                f"non-finite JSON value is forbidden: {token}"
            ),
        )
    except MethodCardCatalogError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MethodCardCatalogError(
            f"{label} must use the strict JSON subset of YAML 1.2: {exc}"
        ) from exc
    if not isinstance(value, dict):
        _fail(f"{label} root must be an object")
    _validate_nfc(value, label)
    return value


def _validate_nfc(value: Any, label: str) -> None:
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            _fail(f"{label} contains a noncanonical Unicode string")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_nfc(item, f"{label}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _validate_nfc(key, f"{label}.key")
            _validate_nfc(item, f"{label}.{key}")
        return
    if value is not None and not isinstance(value, (bool, int)):
        _fail(f"{label} contains a non-JSON value")


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    return value


def _exact_keys(
    value: Mapping[str, Any], expected: frozenset[str], label: str
) -> None:
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        detail: list[str] = []
        if missing:
            detail.append("missing keys " + ", ".join(missing))
        if extra:
            detail.append("unknown keys " + ", ".join(extra))
        _fail(f"{label} schema drift: {'; '.join(detail)}")


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{label} must be a nonempty string")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        _fail(f"{label} must be boolean")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(f"{label} must be an array")
    return value


def _canonical_id(value: Any, label: str) -> str:
    result = _string(value, label)
    if _IDENTIFIER_RE.fullmatch(result) is None:
        _fail(f"{label} must be a canonical lowercase identity")
    return result


def _sorted_unique_strings(
    value: Any,
    label: str,
    *,
    allowed: frozenset[str] | None = None,
    allow_empty: bool = True,
) -> tuple[str, ...]:
    items = tuple(_string(item, f"{label}[]") for item in _array(value, label))
    if not allow_empty and not items:
        _fail(f"{label} must not be empty")
    if items != tuple(sorted(items)):
        _fail(f"{label} must be sorted canonically")
    if len(items) != len(set(items)):
        _fail(f"{label} contains duplicate values")
    if allowed is not None:
        unknown = sorted(set(items) - allowed)
        if unknown:
            if allowed is CAPABILITIES:
                noun = "capability"
            elif allowed is RELATION_SELECTORS:
                noun = "relation selector"
            else:
                noun = "value"
            _fail(f"{label} contains unknown {noun}: {', '.join(unknown)}")
    return items


def _ordered_unique_strings(
    value: Any, label: str, *, allow_empty: bool = True
) -> tuple[str, ...]:
    items = tuple(_string(item, f"{label}[]") for item in _array(value, label))
    if not allow_empty and not items:
        _fail(f"{label} must not be empty")
    if len(items) != len(set(items)):
        _fail(f"{label} contains duplicate values")
    return items


def _safe_repo_path(value: Any, label: str) -> str:
    path = _string(value, label)
    if "\\" in path or path.startswith(("/", "~")):
        _fail(f"{label} must be a safe repo-relative POSIX path")
    if re.match(r"^[A-Za-z]:", path):
        _fail(f"{label} must be a safe repo-relative POSIX path")
    relative = PurePosixPath(path)
    parts = relative.parts
    if (
        not parts
        or path != relative.as_posix()
        or any(part in {"", ".", ".."} for part in parts)
    ):
        _fail(f"{label} must be a safe repo-relative POSIX path")
    for part in parts:
        if (
            any(character in _FORBIDDEN_PATH_CHARS for character in part)
            or any(ord(character) < 32 for character in part)
            or part.endswith((" ", "."))
            or part.split(".", 1)[0].upper() in _WINDOWS_RESERVED_NAMES
        ):
            _fail(f"{label} must be a safe repo-relative POSIX path")
    return path


def _is_link_or_reparse(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        attributes = getattr(
            path.stat(follow_symlinks=False), "st_file_attributes", 0
        )
        return bool(attributes & _WINDOWS_REPARSE_ATTRIBUTE)
    except OSError:
        return True


def _read_bound_repo_file(
    repo_root: Path, relative_path: str, expected_sha256: str
) -> bytes:
    try:
        root = repo_root.resolve(strict=True)
        candidate = root.joinpath(*PurePosixPath(relative_path).parts)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise MethodCardCatalogError(
            f"prompt fragment path is missing or escapes repo: {relative_path}"
        ) from exc
    cursor = root
    for part in PurePosixPath(relative_path).parts:
        cursor = cursor / part
        if _is_link_or_reparse(cursor):
            _fail(f"prompt fragment path traverses a link/reparse point: {relative_path}")
    if not resolved.is_file():
        _fail(f"prompt fragment is not a regular file: {relative_path}")
    try:
        before = resolved.stat()
        if before.st_size > _MAX_PROMPT_BYTES:
            _fail(f"prompt fragment exceeds size limit: {relative_path}")
        content = resolved.read_bytes()
        after = resolved.stat()
    except OSError as exc:
        raise MethodCardCatalogError(
            f"prompt fragment could not be read: {relative_path}"
        ) from exc
    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or after.st_size != len(content)
    ):
        _fail(f"prompt fragment changed during read: {relative_path}")
    actual = hashlib.sha256(content).hexdigest()
    if actual != expected_sha256:
        _fail(
            f"prompt fragment hash drift for {relative_path}: "
            f"expected {expected_sha256}, observed {actual}"
        )
    return content


def _part0_lint(text: str, label: str) -> None:
    if _FINDING_ID_RE.search(text):
        _fail(f"Part-0 violation in {label}: target finding identifier")
    if _ABSOLUTE_PATH_RE.search(text):
        _fail(f"Part-0 violation in {label}: host or target path")
    if _TARGET_LOCATION_RE.search(text):
        _fail(f"Part-0 violation in {label}: target source location")
    if _MOTIVATING_ANSWER_RE.search(text):
        _fail(f"Part-0 violation in {label}: expected or known answer marker")
    if _CAMEL_TARGET_RE.search(text):
        _fail(f"Part-0 violation in {label}: target-specific name")


def _validate_card(
    raw: Any,
    *,
    index: int,
    repo_root: Path,
) -> MethodCard:
    label = f"methods[{index}]"
    card = _mapping(raw, label)
    _exact_keys(card, _CARD_KEYS, label)

    method_id = _string(card["method_id"], f"{label}.method_id")
    if _METHOD_ID_RE.fullmatch(method_id) is None:
        _fail(f"{label}.method_id must be a stable lowercase versioned identity")
    method_version = _string(
        card["method_version"], f"{label}.method_version"
    )
    if _SEMVER_RE.fullmatch(method_version) is None:
        _fail(f"{label}.method_version must be semantic version X.Y.Z")
    identity_major = int(method_id.rsplit(".v", 1)[1])
    semantic_major = int(method_version.split(".", 1)[0])
    if identity_major != semantic_major:
        _fail(
            f"{label} method_id and method_version major version must agree"
        )
    title = _string(card["title"], f"{label}.title")
    semantic_operator = _canonical_id(
        card["semantic_operator"], f"{label}.semantic_operator"
    )
    operator_instruction = _string(
        card["operator_instruction"], f"{label}.operator_instruction"
    )
    _part0_lint(title, f"{label}.title")
    _part0_lint(operator_instruction, f"{label}.operator_instruction")

    applies = _mapping(card["applies_to"], f"{label}.applies_to")
    _exact_keys(applies, _APPLIES_KEYS, f"{label}.applies_to")
    node_kinds = _sorted_unique_strings(
        applies["node_kinds"],
        f"{label}.applies_to.node_kinds",
        allowed=NODE_KINDS,
        allow_empty=False,
    )
    required_capabilities = _sorted_unique_strings(
        applies["required_capabilities"],
        f"{label}.applies_to.required_capabilities",
        allowed=CAPABILITIES,
        allow_empty=False,
    )
    optional_capabilities = _sorted_unique_strings(
        applies["optional_capabilities"],
        f"{label}.applies_to.optional_capabilities",
        allowed=CAPABILITIES,
    )
    if set(required_capabilities) & set(optional_capabilities):
        _fail(f"{label} required/optional capabilities must be disjoint")
    fidelity_raw = _mapping(
        applies["accepted_fidelity"],
        f"{label}.applies_to.accepted_fidelity",
    )
    all_capabilities = tuple(
        sorted((*required_capabilities, *optional_capabilities))
    )
    if set(fidelity_raw) != set(all_capabilities):
        _fail(
            f"{label}.applies_to.accepted_fidelity must name every and only "
            "declared capability"
        )
    accepted_fidelity: list[tuple[str, tuple[str, ...]]] = []
    for capability in all_capabilities:
        levels = _sorted_unique_strings(
            fidelity_raw[capability],
            f"{label}.applies_to.accepted_fidelity.{capability}",
            allowed=FIDELITIES,
            allow_empty=False,
        )
        accepted_fidelity.append((capability, levels))

    selector = _mapping(card["target_selector"], f"{label}.target_selector")
    _exact_keys(selector, _TARGET_KEYS, f"{label}.target_selector")
    target_selector = (
        (
            "boundaries_any",
            _sorted_unique_strings(
                selector["boundaries_any"],
                f"{label}.target_selector.boundaries_any",
                allowed=BOUNDARIES,
            ),
        ),
        (
            "effects_any",
            _sorted_unique_strings(
                selector["effects_any"],
                f"{label}.target_selector.effects_any",
                allowed=TARGET_EFFECTS,
            ),
        ),
        (
            "entity_properties_any",
            _sorted_unique_strings(
                selector["entity_properties_any"],
                f"{label}.target_selector.entity_properties_any",
                allowed=TARGET_PROPERTIES,
            ),
        ),
    )
    if not any(values for _, values in target_selector):
        _fail(f"{label}.target_selector must contain at least one selector")

    relation_selectors = _sorted_unique_strings(
        card["relation_selectors"],
        f"{label}.relation_selectors",
        allowed=RELATION_SELECTORS,
        allow_empty=False,
    )

    step_rows = _array(card["required_steps"], f"{label}.required_steps")
    if not step_rows:
        _fail(f"{label}.required_steps must not be empty")
    required_steps: list[MethodStep] = []
    seen_steps: set[str] = set()
    for step_index, raw_step in enumerate(step_rows):
        step_label = f"{label}.required_steps[{step_index}]"
        step = _mapping(raw_step, step_label)
        _exact_keys(step, _STEP_KEYS, step_label)
        step_id = _canonical_id(step["step_id"], f"{step_label}.step_id")
        if step_id in seen_steps:
            _fail(f"{label}.required_steps contains duplicate step_id")
        seen_steps.add(step_id)
        instruction = _string(
            step["instruction"], f"{step_label}.instruction"
        )
        _part0_lint(instruction, f"{step_label}.instruction")
        required_steps.append(MethodStep(step_id, instruction))

    required_receipts = _ordered_unique_strings(
        card["required_receipts"],
        f"{label}.required_receipts",
        allow_empty=False,
    )
    if required_receipts != REQUIRED_RECEIPTS:
        _fail(
            f"{label}.required_receipts must equal the R1 completion contract"
        )

    completion = _mapping(
        card["completion_policy"], f"{label}.completion_policy"
    )
    _exact_keys(completion, _COMPLETION_KEYS, f"{label}.completion_policy")
    allow_not_applicable = _boolean(
        completion["allow_not_applicable"],
        f"{label}.completion_policy.allow_not_applicable",
    )
    material_unresolved_requires_human_review = _boolean(
        completion["material_unresolved_requires_human_review"],
        f"{label}.completion_policy."
        "material_unresolved_requires_human_review",
    )
    valid_not_applicable_reasons = _sorted_unique_strings(
        completion["valid_not_applicable_reasons"],
        f"{label}.completion_policy.valid_not_applicable_reasons",
        allow_empty=not allow_not_applicable,
    )
    for reason in valid_not_applicable_reasons:
        if not re.fullmatch(r"[A-Z][A-Z0-9_]+", reason):
            _fail(
                f"{label}.completion_policy valid N/A reason is noncanonical"
            )
    if not allow_not_applicable and valid_not_applicable_reasons:
        _fail(f"{label} forbids N/A but declares N/A reasons")

    fragment = _mapping(
        card["prompt_fragment"], f"{label}.prompt_fragment"
    )
    _exact_keys(fragment, _PROMPT_KEYS, f"{label}.prompt_fragment")
    fragment_path = _safe_repo_path(
        fragment["path"], f"{label}.prompt_fragment.path"
    )
    fragment_sha = _string(
        fragment["sha256"], f"{label}.prompt_fragment.sha256"
    )
    if _HEX64_RE.fullmatch(fragment_sha) is None:
        _fail(f"{label}.prompt_fragment.sha256 must be lowercase 64-hex")
    content = _read_bound_repo_file(repo_root, fragment_path, fragment_sha)

    return MethodCard(
        method_id=method_id,
        title=title,
        method_version=method_version,
        semantic_operator=semantic_operator,
        operator_instruction=operator_instruction,
        node_kinds=node_kinds,
        required_capabilities=required_capabilities,
        optional_capabilities=optional_capabilities,
        accepted_fidelity=tuple(accepted_fidelity),
        target_selector=target_selector,
        relation_selectors=relation_selectors,
        required_steps=tuple(required_steps),
        required_receipts=required_receipts,
        allow_not_applicable=allow_not_applicable,
        valid_not_applicable_reasons=valid_not_applicable_reasons,
        material_unresolved_requires_human_review=(
            material_unresolved_requires_human_review
        ),
        prompt_fragment=PromptFragment(
            path=fragment_path,
            sha256=fragment_sha,
            content=content,
        ),
    )


def load_method_card_catalog(
    path: Path | str | None = None,
    *,
    repo_root: Path | str | None = None,
    require_canonical_source: bool = True,
) -> MethodCardCatalog:
    """Load and fully validate the universal R1 catalog."""

    root = (
        Path(repo_root)
        if repo_root is not None
        else Path(__file__).resolve().parent.parent
    )
    source = (
        Path(path)
        if path is not None
        else root / "methodology" / "method-cards-v1.yaml"
    )
    try:
        source_bytes = source.read_bytes()
    except OSError as exc:
        raise MethodCardCatalogError(
            f"MethodCard catalog could not be read: {source}"
        ) from exc
    raw = _load_json_subset(source_bytes, "MethodCard catalog")
    if require_canonical_source and source_bytes != canonical_catalog_bytes(raw):
        _fail(
            "MethodCard catalog source must use the canonical JSON "
            "representation"
        )
    _exact_keys(raw, _TOP_KEYS, "catalog")
    if raw["schema_version"] != CATALOG_SCHEMA:
        _fail(f"catalog.schema_version must equal {CATALOG_SCHEMA}")
    catalog_version = _string(raw["catalog_version"], "catalog.catalog_version")
    if _SEMVER_RE.fullmatch(catalog_version) is None:
        _fail("catalog.catalog_version must be semantic version X.Y.Z")

    integration_raw = _mapping(raw["integration"], "catalog.integration")
    _exact_keys(integration_raw, _INTEGRATION_KEYS, "catalog.integration")
    status = _string(integration_raw["status"], "catalog.integration.status")
    runtime_authority = _boolean(
        integration_raw["runtime_authority"],
        "catalog.integration.runtime_authority",
    )
    debt = _sorted_unique_strings(
        integration_raw["debt"],
        "catalog.integration.debt",
        allow_empty=False,
    )
    if status != "SUBSTRATE_ONLY" or runtime_authority:
        _fail(
            "R1 catalog must remain SUBSTRATE_ONLY with no runtime authority"
        )
    if debt != _INTEGRATION_DEBT:
        _fail("R1 catalog must expose the exact integration debt boundary")

    method_rows = _array(raw["methods"], "catalog.methods")
    raw_folded: dict[str, str] = {}
    for index, item in enumerate(method_rows):
        candidate = _mapping(item, f"methods[{index}]")
        candidate_id = candidate.get("method_id")
        if isinstance(candidate_id, str) and candidate_id:
            folded_id = candidate_id.casefold()
            if folded_id in raw_folded:
                _fail(
                    "catalog.methods contains a case-fold duplicate method_id: "
                    f"{raw_folded[folded_id]!r}, {candidate_id!r}"
                )
            raw_folded[folded_id] = candidate_id
    cards = tuple(
        _validate_card(
            item,
            index=index,
            repo_root=root,
        )
        for index, item in enumerate(method_rows)
    )
    method_ids = tuple(card.method_id for card in cards)
    folded: dict[str, str] = {}
    for method_id in method_ids:
        key = method_id.casefold()
        if key in folded:
            _fail(
                "catalog.methods contains a case-fold duplicate method_id: "
                f"{folded[key]!r}, {method_id!r}"
            )
        folded[key] = method_id
    if method_ids != UNIVERSAL_OPERATOR_IDS:
        _fail(
            "catalog.methods must contain the exact ordered twelve universal "
            "MethodCard identities"
        )
    operators = tuple(card.semantic_operator for card in cards)
    if operators != UNIVERSAL_SEMANTIC_OPERATORS:
        _fail(
            "catalog.methods must map one-to-one to the exact twelve universal "
            "semantic operators"
        )

    digest = hashlib.sha256(canonical_catalog_bytes(raw)).hexdigest()
    loaded = MethodCardCatalog(
        schema_version=CATALOG_SCHEMA,
        catalog_version=catalog_version,
        integration=CatalogIntegration(
            status=status,
            runtime_authority=runtime_authority,
            debt=debt,
        ),
        cards=cards,
        digest=digest,
        source_sha256=hashlib.sha256(source_bytes).hexdigest(),
        source_bytes=source_bytes,
        source_path=source,
        repo_root=root,
    )
    # The catalog is not a runtime consumer yet, but its normative universal
    # semantics must already render to the exact reviewed legacy fragment.
    render_bound_prompt_fragment(loaded)
    return loaded


def render_bound_prompt_fragment(
    catalog: MethodCardCatalog,
    method_ids: Sequence[str] | None = None,
) -> bytes:
    """Render catalog semantics and prove equality to exact reviewed bytes.

    This is not a claim that runtime prompts have migrated to catalog
    authority.  It is a parity ratchet: the exact universal catalog must render
    byte-for-byte to the existing bound breadth kernel before the substrate is
    accepted.
    """

    selected = (
        catalog.cards
        if method_ids is None
        else tuple(catalog.card(method_id) for method_id in method_ids)
    )
    if tuple(card.method_id for card in selected) != UNIVERSAL_OPERATOR_IDS:
        _fail(
            "R1 bound prompt rendering requires the exact twelve universal "
            "MethodCards in canonical order"
        )
    bindings = {
        (
            card.prompt_fragment.path,
            card.prompt_fragment.sha256,
            card.prompt_fragment.content,
        )
        for card in selected
    }
    if len(bindings) != 1:
        _fail("selected MethodCards do not share one exact prompt fragment")
    path, expected_sha, content = next(iter(bindings))
    if not content:
        content = _read_bound_repo_file(catalog.repo_root, path, expected_sha)
    if hashlib.sha256(content).hexdigest() != expected_sha:
        _fail("bound prompt fragment content no longer matches its digest")
    rendered_text = _KERNEL_PREFIX + "".join(
        f"{index}. **{card.title}:** {card.operator_instruction}\n"
        for index, card in enumerate(selected, start=1)
    ) + _KERNEL_SUFFIX
    rendered = rendered_text.encode("utf-8")
    if rendered != content:
        _fail(
            "catalog universal semantics do not render byte-for-byte to the "
            "bound breadth kernel"
        )
    return rendered


def _receipt_path(value: Any, label: str) -> str:
    return _safe_repo_path(value, label)


def _receipt_strings(
    value: Any,
    label: str,
    *,
    allow_empty: bool = True,
    sorted_required: bool = False,
) -> tuple[str, ...]:
    if sorted_required:
        return _sorted_unique_strings(
            value, label, allow_empty=allow_empty
        )
    return _ordered_unique_strings(value, label, allow_empty=allow_empty)


def validate_application_receipt(
    catalog: MethodCardCatalog,
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate application coverage without asserting finding correctness."""

    row = _mapping(receipt, "application_receipt")
    _exact_keys(row, _RECEIPT_KEYS, "application_receipt")
    if row["schema_version"] != APPLICATION_RECEIPT_SCHEMA:
        _fail(
            "application_receipt.schema_version does not match the R1 contract"
        )
    catalog_digest = _string(
        row["catalog_digest"], "application_receipt.catalog_digest"
    )
    if catalog_digest != catalog.digest:
        _fail("application_receipt.catalog_digest does not match the catalog")
    method_id = _string(row["method_id"], "application_receipt.method_id")
    card = catalog.card(method_id)
    method_version = _string(
        row["method_version"], "application_receipt.method_version"
    )
    if method_version != card.method_version:
        _fail("application_receipt.method_version does not match the MethodCard")
    status = _string(row["status"], "application_receipt.status")
    if status not in {"APPLIED", "NOT_APPLICABLE", "UNRESOLVED"}:
        _fail("application_receipt.status is not a supported application state")

    targets_raw = _array(
        row["targets_examined"], "application_receipt.targets_examined"
    )
    target_ids: list[str] = []
    for index, raw_target in enumerate(targets_raw):
        label = f"application_receipt.targets_examined[{index}]"
        target = _mapping(raw_target, label)
        _exact_keys(target, _TARGET_RECEIPT_KEYS, label)
        target_id = _string(target["target_id"], f"{label}.target_id")
        if _OPAQUE_ID_RE.fullmatch(target_id) is None:
            _fail(f"{label}.target_id must be an opaque non-path identity")
        node_kind = _string(target["node_kind"], f"{label}.node_kind")
        if node_kind not in card.node_kinds:
            _fail(f"{label}.node_kind is outside the MethodCard selector")
        target_ids.append(target_id)
    if len(target_ids) != len(set(target_ids)):
        _fail("application_receipt.targets_examined contains duplicate targets")

    relation_rows = _array(
        row["relation_coverage"], "application_receipt.relation_coverage"
    )
    covered_relations: list[str] = []
    for index, raw_relation in enumerate(relation_rows):
        label = f"application_receipt.relation_coverage[{index}]"
        relation = _mapping(raw_relation, label)
        _exact_keys(relation, _RELATION_RECEIPT_KEYS, label)
        selector = _string(relation["selector"], f"{label}.selector")
        if selector not in card.relation_selectors:
            _fail(f"{label}.selector is not required by the MethodCard")
        if relation["status"] != "EXAMINED":
            _fail(f"{label}.status must be EXAMINED")
        _receipt_strings(
            relation["relation_ids"],
            f"{label}.relation_ids",
            sorted_required=True,
        )
        covered_relations.append(selector)
    if len(covered_relations) != len(set(covered_relations)):
        _fail("application_receipt.relation_coverage contains duplicates")
    expected_relation_order = tuple(
        selector
        for selector in card.relation_selectors
        if selector in set(covered_relations)
    )
    if tuple(covered_relations) != expected_relation_order:
        _fail(
            "application_receipt.relation_coverage is not in MethodCard order"
        )

    completed_steps = _receipt_strings(
        row["steps_completed"], "application_receipt.steps_completed"
    )
    known_steps = tuple(step.step_id for step in card.required_steps)
    if not set(completed_steps).issubset(set(known_steps)):
        _fail("application_receipt.steps_completed contains an unknown step")
    expected_step_order = tuple(
        step for step in known_steps if step in set(completed_steps)
    )
    if completed_steps != expected_step_order:
        _fail("application_receipt.steps_completed is not in MethodCard order")

    evidence_rows = _array(
        row["evidence_locations"], "application_receipt.evidence_locations"
    )
    normalized_evidence_locations: set[str] = set()
    for index, raw_evidence in enumerate(evidence_rows):
        label = f"application_receipt.evidence_locations[{index}]"
        evidence = _mapping(raw_evidence, label)
        _exact_keys(evidence, _EVIDENCE_KEYS, label)
        _receipt_path(evidence["path"], f"{label}.path")
        line_start = evidence["line_start"]
        line_end = evidence["line_end"]
        if (
            isinstance(line_start, bool)
            or not isinstance(line_start, int)
            or line_start < 1
            or isinstance(line_end, bool)
            or not isinstance(line_end, int)
            or line_end < line_start
        ):
            _fail(f"{label} line range is invalid")
        normalized_evidence_locations.add(
            f"{evidence['path']}:{line_start}-{line_end}"
        )

    outcome_rows = _array(row["outcomes"], "application_receipt.outcomes")
    outcome_kinds: list[str] = []
    for index, raw_outcome in enumerate(outcome_rows):
        label = f"application_receipt.outcomes[{index}]"
        outcome = _mapping(raw_outcome, label)
        _exact_keys(outcome, _OUTCOME_KEYS, label)
        kind = _string(outcome["kind"], f"{label}.kind")
        if kind not in {
            "CANDIDATE_PROPOSED",
            "NO_CANDIDATE",
            "NOT_APPLICABLE",
            "UNRESOLVED",
        }:
            _fail(f"{label}.kind is unsupported")
        _string(outcome["detail"], f"{label}.detail")
        candidate_ids = _receipt_strings(
            outcome["candidate_ids"],
            f"{label}.candidate_ids",
            sorted_required=True,
        )
        if kind == "CANDIDATE_PROPOSED" and not candidate_ids:
            _fail(f"{label}.candidate_ids is required for CANDIDATE_PROPOSED")
        if kind != "CANDIDATE_PROPOSED" and candidate_ids:
            _fail(f"{label}.candidate_ids is forbidden for {kind}")
        outcome_kinds.append(kind)

    unresolved = _receipt_strings(
        row["unresolved_assumptions"],
        "application_receipt.unresolved_assumptions",
    )

    not_applicable_raw = row["not_applicable"]
    if not_applicable_raw is None:
        not_applicable = None
    else:
        not_applicable = _mapping(
            not_applicable_raw, "application_receipt.not_applicable"
        )
        _exact_keys(
            not_applicable,
            _NOT_APPLICABLE_KEYS,
            "application_receipt.not_applicable",
        )
        _string(
            not_applicable["detail"],
            "application_receipt.not_applicable.detail",
        )
        selector_evidence = _receipt_strings(
            not_applicable["selector_evidence"],
            "application_receipt.not_applicable.selector_evidence",
            allow_empty=False,
        )
        if not set(selector_evidence).issubset(normalized_evidence_locations):
            _fail(
                "application_receipt.not_applicable.selector_evidence must "
                "bind declared evidence_locations"
            )

    if status == "APPLIED":
        if not targets_raw:
            _fail("APPLIED receipt requires nonempty targets_examined")
        if tuple(covered_relations) != card.relation_selectors:
            _fail(
                "APPLIED receipt relation_coverage must enumerate every "
                "MethodCard relation selector"
            )
        if completed_steps != known_steps:
            _fail(
                "APPLIED receipt steps_completed must cover every MethodCard step"
            )
        if not evidence_rows:
            _fail("APPLIED receipt requires evidence_locations")
        if not outcome_kinds or any(
            kind not in {"CANDIDATE_PROPOSED", "NO_CANDIDATE"}
            for kind in outcome_kinds
        ):
            _fail("APPLIED receipt requires an applied semantic outcome")
        if unresolved:
            _fail(
                "APPLIED receipt with unresolved assumptions must use "
                "UNRESOLVED status"
            )
        if not_applicable is not None:
            _fail("APPLIED receipt must not include not_applicable")
        application_complete = True
        requires_human_review = False
    elif status == "NOT_APPLICABLE":
        if not card.allow_not_applicable:
            _fail("MethodCard completion policy does not allow NOT_APPLICABLE")
        if targets_raw or relation_rows or completed_steps or unresolved:
            _fail(
                "NOT_APPLICABLE receipt cannot claim targets, relations, "
                "steps, or unresolved assumptions"
            )
        if not evidence_rows:
            _fail("NOT_APPLICABLE receipt requires selector evidence locations")
        if outcome_kinds != ["NOT_APPLICABLE"]:
            _fail("NOT_APPLICABLE receipt requires one matching outcome")
        if not_applicable is None:
            _fail("NOT_APPLICABLE receipt requires a typed reason")
        code = _string(
            not_applicable["code"],
            "application_receipt.not_applicable.code",
        )
        if code not in card.valid_not_applicable_reasons:
            _fail("NOT_APPLICABLE reason is not allowed by the MethodCard")
        application_complete = True
        requires_human_review = False
    else:
        if not unresolved:
            _fail("UNRESOLVED receipt requires unresolved_assumptions")
        if not evidence_rows:
            _fail("UNRESOLVED receipt requires evidence_locations")
        if "UNRESOLVED" not in outcome_kinds:
            _fail("UNRESOLVED receipt requires an UNRESOLVED outcome")
        if not_applicable is not None:
            _fail("UNRESOLVED receipt must not include not_applicable")
        application_complete = False
        requires_human_review = (
            card.material_unresolved_requires_human_review
        )

    return {
        "application_complete": application_complete,
        "catalog_digest": catalog.digest,
        "method_id": card.method_id,
        "method_version": card.method_version,
        "requires_human_review": requires_human_review,
        "semantic_outcome": outcome_kinds[0],
        "status": status,
    }


__all__ = [
    "APPLICATION_RECEIPT_SCHEMA",
    "CATALOG_SCHEMA",
    "CAPABILITIES",
    "FIDELITIES",
    "NODE_KINDS",
    "RELATION_SELECTORS",
    "UNIVERSAL_OPERATOR_IDS",
    "UNIVERSAL_SEMANTIC_OPERATORS",
    "CatalogIntegration",
    "MethodCard",
    "MethodCardCatalog",
    "MethodCardCatalogError",
    "MethodStep",
    "PromptFragment",
    "canonical_catalog_bytes",
    "load_method_card_catalog",
    "render_bound_prompt_fragment",
    "validate_application_receipt",
]
