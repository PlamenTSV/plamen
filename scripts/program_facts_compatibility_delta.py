"""Derive and replay out-of-band Program Facts compatibility evidence.

Every claim in the receipt is derived from exact bound bytes. Independent
review authorities are HMAC-authenticated against caller-supplied trusted
keys; the receipt itself grants no execution, composition, or publication
authority.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import hmac
from typing import Any

from program_facts_v2_contracts import (
    ProgramFactsTypeError,
    canonical_json_bytes,
    normalized_document,
    require_exact_keys,
    require_relative_file_path,
    require_sha256,
    validate_signed_payload,
)
from program_facts_types import strict_json_loads


SCHEMA_VERSION = "plamen.program_facts_compatibility_delta.v1"
EVIDENCE_CLASS = "RELEASE_PACKAGING_OUT_OF_BAND"
PRODUCER_PATH = "scripts/program_facts_compatibility_delta.py"
PROVISIONAL_PATH = (
    "review_fixtures/program_facts_compatibility_delta_c4_provisional.v1.json"
)
FINAL_PATH = (
    "review_fixtures/program_facts_compatibility_delta_final_release.v1.json"
)
SEMANTIC_CLASSES = frozenset(
    {
        "METHODOLOGY_COMPONENT",
        "TOOLCHAIN_COMPONENT",
        "TRANSITIVE_AUTHORITY_OR_REUSE_IDENTITY",
        "NEW_PRIVATE_OR_V2_ARTIFACT",
    }
)
_SCHEMA = "program_facts_compatibility_delta.v1.schema.json"
_FINAL_CLOSURE = "FINAL_RUNTIME_QUIESCENT"
_PROVISIONAL_CLOSURE = "COMPONENT_LOCAL_PROVISIONAL_NOT_FINAL_RUNTIME_CLOSURE"
_RECEIPT_PATHS = frozenset({PROVISIONAL_PATH, FINAL_PATH})
_LEGACY_PUBLIC_BASENAMES = frozenset(
    {
        "mechanical_program_facts.v1.json",
        "mechanical_program_facts_receipt.v1.json",
        "mechanical_program_facts_debt.v1.json",
    }
)
_FORBIDDEN_SEMANTIC_PATHS = frozenset(
    {
        "rules/finding-output-format.md",
        "rules/phase4-confidence-scoring.md",
        "rules/phase5-poc-execution.md",
        "rules/phase6-report-prompts.md",
        "rules/report-template.md",
    }
)
_RUNTIME_MANIFEST_KEYS = frozenset(
    {"schema_version", "manifest_class", "paths", "manifest_body_sha256"}
)
_RUNTIME_PATH_KEYS = frozenset({"portable_path", "size", "sha256"})
_AUTHENTICATION_KEYS = frozenset(
    {"authority_key_id", "authority_hmac_sha256"}
)
_COMPARATOR_KEYS = frozenset(
    {"schema_version", "public_comparisons"} | _AUTHENTICATION_KEYS
)
_COMPONENT_REGISTRY_KEYS = frozenset(
    {"schema_version", "registry_id", "rows"} | _AUTHENTICATION_KEYS
)
_ALLOWED_ROSTER_KEYS = frozenset(
    {
        "schema_version",
        "component_registry_id",
        "component_registry_sha256",
        "rows",
    }
    | _AUTHENTICATION_KEYS
)
_SEMANTIC_REVIEW_KEYS = frozenset(
    {
        "schema_version",
        "component_registry_id",
        "component_registry_sha256",
        "rows",
    }
    | _AUTHENTICATION_KEYS
)
_EXCLUSION_KEYS = frozenset(
    {
        "schema_version",
        "compatibility_receipt_paths",
        "execution_authority_paths",
        "composition_authority_paths",
        "compared_runtime_manifest_paths",
    }
    | _AUTHENTICATION_KEYS
)


def _normalize_binding(binding: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    if not isinstance(binding, Mapping):
        raise ProgramFactsTypeError(f"{label} must be an object")
    require_exact_keys(
        binding,
        required=frozenset({"path", "size", "sha256"}),
        label=label,
    )
    path = require_relative_file_path(binding.get("path"), label=f"{label} path")
    size = binding.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise ProgramFactsTypeError(f"{label} size is invalid")
    digest = require_sha256(binding.get("sha256"), label=f"{label} digest")
    return {"path": path, "size": size, "sha256": digest}


def _bind_bytes(path: str, raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes:
        raise ProgramFactsTypeError("bound content must be exact bytes")
    return {
        "path": path,
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _require_bound_bytes(
    raw: bytes,
    binding: Mapping[str, Any],
    *,
    label: str,
) -> dict[str, Any]:
    normalized = _normalize_binding(binding, label=label)
    if type(raw) is not bytes:
        raise ProgramFactsTypeError(f"{label} content must be exact bytes")
    if normalized["size"] != len(raw):
        if label == "pre-R2 boundary manifest":
            raise ProgramFactsTypeError("wrong pre-R2 boundary manifest binding")
        if label == "post-R2 runtime manifest":
            raise ProgramFactsTypeError(
                "delta path/size/digest does not replay: manifest binding diverges"
            )
        raise ProgramFactsTypeError(f"{label} binding diverges from bound bytes")
    if normalized["sha256"] != hashlib.sha256(raw).hexdigest():
        if label == "pre-R2 boundary manifest":
            raise ProgramFactsTypeError("wrong pre-R2 boundary manifest binding")
        if label == "post-R2 runtime manifest":
            raise ProgramFactsTypeError(
                "delta path/size/digest does not replay: manifest binding diverges"
            )
        raise ProgramFactsTypeError(f"{label} binding diverges from bound bytes")
    return normalized


def _parse_canonical_object(raw: bytes, *, label: str) -> dict[str, Any]:
    if type(raw) is not bytes or not raw:
        raise ProgramFactsTypeError(f"{label} bytes are absent")
    document = strict_json_loads(
        raw,
        require_final_lf=True,
        require_canonical=True,
    )
    if not isinstance(document, dict):
        raise ProgramFactsTypeError(f"{label} root must be an object")
    return document


def _validate_portable_path_denominator(
    values: object,
    *,
    label: str,
    allow_empty: bool = False,
) -> list[str]:
    if not isinstance(values, list) or (
        not values and not allow_empty
    ):
        raise ProgramFactsTypeError(f"{label} must be a nonempty array")
    paths = [
        require_relative_file_path(item, label=f"{label} path")
        for item in values
    ]
    folded = [path.casefold() for path in paths]
    if len(folded) != len(set(folded)):
        raise ProgramFactsTypeError(f"{label} must be case-unique")
    return paths


def _parse_runtime_manifest(
    raw: bytes,
    binding: Mapping[str, Any],
    *,
    expected_class: str,
    label: str,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    normalized_binding = _require_bound_bytes(raw, binding, label=label)
    document = _parse_canonical_object(raw, label=label)
    require_exact_keys(
        document,
        required=_RUNTIME_MANIFEST_KEYS,
        label=label,
    )
    if (
        document["schema_version"]
        != "plamen.program_facts_runtime_path_manifest.v1"
        or document["manifest_class"] != expected_class
    ):
        raise ProgramFactsTypeError(f"{label} authority class diverges")
    unsigned = dict(document)
    claimed = unsigned.pop("manifest_body_sha256")
    require_sha256(claimed, label=f"{label} body digest")
    if hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest() != claimed:
        raise ProgramFactsTypeError(f"{label} self-digest diverges")
    rows = document["paths"]
    if not isinstance(rows, list):
        raise ProgramFactsTypeError(f"{label} paths must be an array")
    result: dict[str, dict[str, Any]] = {}
    folded: list[str] = []
    for raw_row in rows:
        if not isinstance(raw_row, Mapping):
            raise ProgramFactsTypeError(f"{label} path row must be an object")
        require_exact_keys(
            raw_row,
            required=_RUNTIME_PATH_KEYS,
            label=f"{label} path row",
        )
        path = require_relative_file_path(
            raw_row["portable_path"], label=f"{label} portable path"
        )
        size = raw_row["size"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ProgramFactsTypeError(f"{label} path size is invalid")
        digest = require_sha256(raw_row["sha256"], label=f"{label} path digest")
        folded.append(path.casefold())
        result[path] = {"size": size, "sha256": digest}
    if len(folded) != len(set(folded)):
        raise ProgramFactsTypeError(f"{label} paths must be case-unique")
    return result, normalized_binding


def _parse_sealed_authority(
    raw: bytes,
    binding: Mapping[str, Any],
    *,
    trusted_review_keys: Mapping[str, bytes],
    exact_keys: frozenset[str],
    schema_version: str,
    label: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    normalized_binding = _require_bound_bytes(raw, binding, label=label)
    document = _parse_canonical_object(raw, label=label)
    require_exact_keys(document, required=exact_keys, label=label)
    if document["schema_version"] != schema_version:
        raise ProgramFactsTypeError(f"{label} schema version diverges")
    if not isinstance(trusted_review_keys, Mapping):
        raise ProgramFactsTypeError("trusted review keys must be a mapping")
    key_id = document["authority_key_id"]
    if not isinstance(key_id, str) or not key_id:
        raise ProgramFactsTypeError(f"{label} key identity is invalid")
    key = trusted_review_keys.get(key_id)
    if type(key) is not bytes or not key:
        raise ProgramFactsTypeError(f"{label} trusted review key is unavailable")
    claimed = require_sha256(
        document["authority_hmac_sha256"],
        label=f"{label} authority HMAC",
    )
    unsigned = dict(document)
    unsigned.pop("authority_hmac_sha256")
    expected = hmac.new(
        key,
        canonical_json_bytes(unsigned),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(claimed, expected):
        raise ProgramFactsTypeError(f"{label} authority HMAC replay failed")
    return document, normalized_binding


def _presence(row: Mapping[str, Any] | None) -> dict[str, Any]:
    if row is None:
        return {"state": "ABSENT"}
    return {"state": "PRESENT", "size": row["size"], "sha256": row["sha256"]}


def _actual_manifest_deltas(
    old: Mapping[str, Mapping[str, Any]],
    new: Mapping[str, Mapping[str, Any]],
) -> tuple[
    dict[str, tuple[dict[str, Any] | None, dict[str, Any] | None]],
    int,
]:
    changes: dict[
        str, tuple[dict[str, Any] | None, dict[str, Any] | None]
    ] = {}
    unchanged = 0
    union = sorted(set(old) | set(new))
    folded = [path.casefold() for path in union]
    if len(folded) != len(set(folded)):
        raise ProgramFactsTypeError(
            "runtime manifest union contains a case-fold path alias"
        )
    for path in union:
        before = old.get(path)
        after = new.get(path)
        if before == after:
            unchanged += 1
        else:
            changes[path] = (before, after)
    return changes, unchanged


def _parse_component_registry(
    raw: bytes,
    binding: Mapping[str, Any],
    *,
    trusted_review_keys: Mapping[str, bytes],
) -> tuple[dict[str, str], str, dict[str, Any]]:
    document, normalized_binding = _parse_sealed_authority(
        raw,
        binding,
        trusted_review_keys=trusted_review_keys,
        exact_keys=_COMPONENT_REGISTRY_KEYS,
        schema_version=(
            "plamen.program_facts_compatibility_component_registry.v1"
        ),
        label="compatibility component registry",
    )
    registry_id = document["registry_id"]
    if not isinstance(registry_id, str) or not registry_id:
        raise ProgramFactsTypeError("component registry identity is invalid")
    rows = document["rows"]
    if not isinstance(rows, list):
        raise ProgramFactsTypeError("component registry rows must be an array")
    registry: dict[str, str] = {}
    ordered_paths: list[str] = []
    folded_paths: list[str] = []
    for raw_row in rows:
        if not isinstance(raw_row, Mapping):
            raise ProgramFactsTypeError(
                "component registry row must be an object"
            )
        require_exact_keys(
            raw_row,
            required=frozenset({"portable_path", "semantic_class"}),
            label="component registry row",
        )
        path = require_relative_file_path(
            raw_row["portable_path"],
            label="component registry portable path",
        )
        semantic_class = raw_row["semantic_class"]
        if semantic_class not in SEMANTIC_CLASSES:
            raise ProgramFactsTypeError(
                "component registry semantic class is unknown"
            )
        ordered_paths.append(path)
        folded_paths.append(path.casefold())
        registry[path] = semantic_class
    if ordered_paths != sorted(ordered_paths, key=str.casefold):
        raise ProgramFactsTypeError("component registry rows are not sorted")
    if (
        len(registry) != len(ordered_paths)
        or len(set(folded_paths)) != len(folded_paths)
    ):
        raise ProgramFactsTypeError(
            "component registry paths must be exact and case-fold unique"
        )
    return registry, registry_id, normalized_binding


def _validate_allowed_path(
    path: str,
    *,
    semantic_class: str,
    component_registry: Mapping[str, str],
) -> None:
    path = require_relative_file_path(path, label="allowed change path")
    basename = path.rsplit("/", 1)[-1]
    if basename in _LEGACY_PUBLIC_BASENAMES:
        raise ProgramFactsTypeError("legacy public Program Facts bytes cannot change")
    if path in _FORBIDDEN_SEMANTIC_PATHS:
        raise ProgramFactsTypeError(
            "finding/report semantics cannot hide as compatibility churn"
        )
    if semantic_class not in SEMANTIC_CLASSES:
        raise ProgramFactsTypeError("unknown compatibility semantic class")
    registered_class = component_registry.get(path)
    if registered_class is None:
        if path.casefold() in {
            registered_path.casefold()
            for registered_path in component_registry
        }:
            raise ProgramFactsTypeError(
                "component registry rejects a case-fold path alias"
            )
        raise ProgramFactsTypeError(
            "component registry has no exact governed path entry"
        )
    if registered_class != semantic_class:
        raise ProgramFactsTypeError(
            "component registry semantic class differs from reviewed class"
        )


def _validate_comparison(
    branch: Mapping[str, Any],
    *,
    compared_output_bytes: Mapping[str, bytes],
    label: str,
) -> set[str]:
    if not isinstance(branch, Mapping):
        raise ProgramFactsTypeError(f"{label} comparison must be an object")
    require_exact_keys(
        branch,
        required=frozenset({"left_files", "right_files", "exact_equal"}),
        label=f"{label} comparison",
    )
    if branch["exact_equal"] is not True:
        raise ProgramFactsTypeError(f"{label} comparator did not assert equality")
    left = branch["left_files"]
    right = branch["right_files"]
    if not isinstance(left, list) or not isinstance(right, list) or len(left) != len(right):
        raise ProgramFactsTypeError(f"{label} comparison cardinality diverges")
    used: set[str] = set()
    for side, rows in (("left", left), ("right", right)):
        folded: list[str] = []
        for row in rows:
            binding = _normalize_binding(row, label=f"{label} {side} file")
            path = binding["path"]
            raw = compared_output_bytes.get(path)
            if type(raw) is not bytes:
                raise ProgramFactsTypeError(
                    f"{label} compared bytes are absent for {path!r}"
                )
            if _bind_bytes(path, raw) != binding:
                raise ProgramFactsTypeError(
                    f"{label} compared output binding diverges"
                )
            used.add(path)
            folded.append(path.casefold())
        if folded != sorted(folded) or len(folded) != len(set(folded)):
            raise ProgramFactsTypeError(
                f"{label} {side} paths must be sorted and unique"
            )
    for left_row, right_row in zip(left, right):
        if compared_output_bytes[left_row["path"]] != compared_output_bytes[
            right_row["path"]
        ]:
            raise ProgramFactsTypeError(f"{label} same-postimage bytes differ")
    return used


def _derive_receipt(
    *,
    state: str,
    producer_bytes: bytes,
    pre_runtime_manifest_bytes: bytes,
    pre_r2_boundary_manifest: Mapping[str, Any],
    post_runtime_manifest_bytes: bytes,
    post_r2_runtime_manifest: Mapping[str, Any],
    comparator_receipt_bytes: bytes,
    comparator_receipt_binding: Mapping[str, Any],
    compared_output_bytes: Mapping[str, bytes],
    component_registry_bytes: bytes,
    component_registry_binding: Mapping[str, Any],
    allowed_change_roster_bytes: bytes,
    allowed_change_roster_binding: Mapping[str, Any],
    semantic_review_bytes: bytes,
    semantic_review_binding: Mapping[str, Any],
    exclusion_authority_bytes: bytes,
    exclusion_authority_binding: Mapping[str, Any],
    trusted_review_keys: Mapping[str, bytes],
    runtime_closure_state: str,
) -> dict[str, Any]:
    if state not in {"COMPONENT_LOCAL_PROVISIONAL_C4", _FINAL_CLOSURE}:
        raise ProgramFactsTypeError("unknown compatibility receipt state")
    if state == _FINAL_CLOSURE and runtime_closure_state != _FINAL_CLOSURE:
        raise ProgramFactsTypeError(
            "provisional runtime closure cannot support a final receipt"
        )
    if state != _FINAL_CLOSURE and runtime_closure_state == _FINAL_CLOSURE:
        raise ProgramFactsTypeError(
            "final closure requires a regenerated final receipt"
        )
    if state != _FINAL_CLOSURE and runtime_closure_state != _PROVISIONAL_CLOSURE:
        raise ProgramFactsTypeError("unknown provisional runtime closure state")
    if type(producer_bytes) is not bytes or not producer_bytes:
        raise ProgramFactsTypeError("compatibility producer bytes are absent")
    producer_binding = _bind_bytes(PRODUCER_PATH, producer_bytes)
    old, pre_binding = _parse_runtime_manifest(
        pre_runtime_manifest_bytes,
        pre_r2_boundary_manifest,
        expected_class="PRE_R2_BOUNDARY",
        label="pre-R2 boundary manifest",
    )
    new, post_binding = _parse_runtime_manifest(
        post_runtime_manifest_bytes,
        post_r2_runtime_manifest,
        expected_class="POST_R2_RUNTIME",
        label="post-R2 runtime manifest",
    )
    comparator, comparator_binding = _parse_sealed_authority(
        comparator_receipt_bytes,
        comparator_receipt_binding,
        trusted_review_keys=trusted_review_keys,
        exact_keys=_COMPARATOR_KEYS,
        schema_version="plamen.program_facts_same_postimage_comparator_receipt.v1",
        label="same-postimage comparator receipt",
    )
    if not isinstance(compared_output_bytes, Mapping):
        raise ProgramFactsTypeError("compared output bytes must be a mapping")
    comparisons = comparator["public_comparisons"]
    if not isinstance(comparisons, Mapping) or set(comparisons) != {
        "legacy_v1",
        "disabled",
        "shadow_raw",
    }:
        raise ProgramFactsTypeError("public comparison branch denominator is not exact")
    used_comparison_paths: set[str] = set()
    for branch_name in ("legacy_v1", "disabled", "shadow_raw"):
        used_comparison_paths.update(
            _validate_comparison(
                comparisons[branch_name],
                compared_output_bytes=compared_output_bytes,
                label=branch_name,
            )
        )
    if set(compared_output_bytes) != used_comparison_paths:
        raise ProgramFactsTypeError("compared output byte denominator is not exact")

    (
        component_registry,
        component_registry_id,
        component_registry_binding_normalized,
    ) = _parse_component_registry(
        component_registry_bytes,
        component_registry_binding,
        trusted_review_keys=trusted_review_keys,
    )
    component_registry_sha256 = hashlib.sha256(
        component_registry_bytes
    ).hexdigest()
    roster, roster_binding = _parse_sealed_authority(
        allowed_change_roster_bytes,
        allowed_change_roster_binding,
        trusted_review_keys=trusted_review_keys,
        exact_keys=_ALLOWED_ROSTER_KEYS,
        schema_version="plamen.program_facts_allowed_change_roster.v1",
        label="allowed-change roster",
    )
    semantic, semantic_binding = _parse_sealed_authority(
        semantic_review_bytes,
        semantic_review_binding,
        trusted_review_keys=trusted_review_keys,
        exact_keys=_SEMANTIC_REVIEW_KEYS,
        schema_version="plamen.program_facts_compatibility_semantic_review.v1",
        label="compatibility semantic review",
    )
    exclusion, exclusion_binding = _parse_sealed_authority(
        exclusion_authority_bytes,
        exclusion_authority_binding,
        trusted_review_keys=trusted_review_keys,
        exact_keys=_EXCLUSION_KEYS,
        schema_version="plamen.program_facts_compatibility_exclusion_authority.v1",
        label="compatibility exclusion authority",
    )
    for authority, label in (
        (roster, "allowed-change roster"),
        (semantic, "compatibility semantic review"),
    ):
        if authority["component_registry_id"] != component_registry_id:
            raise ProgramFactsTypeError(
                f"{label} component registry identity diverges"
            )
        if (
            require_sha256(
                authority["component_registry_sha256"],
                label=f"{label} component registry digest",
            )
            != component_registry_sha256
        ):
            raise ProgramFactsTypeError(
                f"{label} component registry digest diverges"
            )

    changes, unchanged_count = _actual_manifest_deltas(old, new)
    rows = roster["rows"]
    if not isinstance(rows, list):
        raise ProgramFactsTypeError("allowed-change rows must be an array")
    allowances: list[dict[str, Any]] = []
    allowance_by_path: dict[str, dict[str, Any]] = {}
    for raw_row in rows:
        if not isinstance(raw_row, Mapping):
            raise ProgramFactsTypeError("allowed-change row must be an object")
        require_exact_keys(
            raw_row,
            required=frozenset(
                {"portable_path", "semantic_class", "reviewed_reason"}
            ),
            label="allowed-change row",
        )
        row = deepcopy(dict(raw_row))
        _validate_allowed_path(
            row["portable_path"],
            semantic_class=row["semantic_class"],
            component_registry=component_registry,
        )
        if not isinstance(row["reviewed_reason"], str) or not row["reviewed_reason"]:
            raise ProgramFactsTypeError("allowed-change reason is absent")
        if row["portable_path"] in allowance_by_path:
            raise ProgramFactsTypeError("allowed-change path is duplicated")
        allowance_by_path[row["portable_path"]] = row
        allowances.append(row)
    if [row["portable_path"].casefold() for row in allowances] != sorted(
        row["portable_path"].casefold() for row in allowances
    ):
        raise ProgramFactsTypeError("allowed-change roster is not sorted")
    if set(allowance_by_path) != set(changes):
        raise ProgramFactsTypeError(
            "allowed-change roster differs from complete changed-path denominator"
        )

    semantic_rows = semantic["rows"]
    if not isinstance(semantic_rows, list):
        raise ProgramFactsTypeError("semantic-review rows must be an array")
    semantic_by_path: dict[str, dict[str, Any]] = {}
    for raw_row in semantic_rows:
        if not isinstance(raw_row, Mapping):
            raise ProgramFactsTypeError("semantic-review row must be an object")
        require_exact_keys(
            raw_row,
            required=frozenset(
                {"portable_path", "semantic_class", "review_disposition"}
            ),
            label="semantic-review row",
        )
        row = dict(raw_row)
        _validate_allowed_path(
            row["portable_path"],
            semantic_class=row["semantic_class"],
            component_registry=component_registry,
        )
        if row["review_disposition"] != "ALLOWED_RELEASE_DELTA":
            raise ProgramFactsTypeError("semantic review did not allow the delta")
        if row["portable_path"] in semantic_by_path:
            raise ProgramFactsTypeError("semantic-review path is duplicated")
        semantic_by_path[row["portable_path"]] = row
    if set(semantic_by_path) != set(changes):
        raise ProgramFactsTypeError(
            "semantic-review denominator differs from changed paths"
        )
    for path in changes:
        if (
            semantic_by_path[path]["semantic_class"]
            != allowance_by_path[path]["semantic_class"]
        ):
            raise ProgramFactsTypeError(
                "semantic-review and allowed-change classes diverge"
            )

    compatibility_receipt_paths = _validate_portable_path_denominator(
        exclusion["compatibility_receipt_paths"],
        label="compatibility receipt exclusions",
    )
    if set(compatibility_receipt_paths) != _RECEIPT_PATHS:
        raise ProgramFactsTypeError(
            "compatibility receipt exclusion denominator is not exact"
        )
    execution_paths = _validate_portable_path_denominator(
        exclusion["execution_authority_paths"],
        label="execution authority exclusions",
    )
    composition_paths = _validate_portable_path_denominator(
        exclusion["composition_authority_paths"],
        label="composition authority exclusions",
    )
    runtime_paths = _validate_portable_path_denominator(
        exclusion["compared_runtime_manifest_paths"],
        label="compared runtime exclusions",
        allow_empty=not new,
    )
    forbidden = {path.casefold() for path in _RECEIPT_PATHS}
    for path in [*execution_paths, *composition_paths, *runtime_paths]:
        if path.casefold() in forbidden:
            raise ProgramFactsTypeError(
                "compatibility receipt entered the authority it compares"
            )
    if set(runtime_paths) != set(new):
        raise ProgramFactsTypeError(
            "compared-runtime exclusion denominator differs from post manifest"
        )

    actual_deltas = []
    for path in sorted(changes):
        old_row, new_row = changes[path]
        allowance = allowance_by_path[path]
        actual_deltas.append(
            {
                "portable_path": path,
                "old": _presence(old_row),
                "new": _presence(new_row),
                "semantic_class": allowance["semantic_class"],
                "allowed_change_row_digest": hashlib.sha256(
                    canonical_json_bytes(allowance)
                ).hexdigest(),
            }
        )
    receipt: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "evidence_class": EVIDENCE_CLASS,
        "state": state,
        "producer": producer_binding,
        "pre_r2_boundary_manifest": pre_binding,
        "post_r2_runtime_manifest": post_binding,
        "same_postimage_comparator": comparator_binding,
        "component_registry_authority": (
            component_registry_binding_normalized
        ),
        "allowed_change_authority": roster_binding,
        "semantic_review_authority": semantic_binding,
        "exclusion_authority": exclusion_binding,
        "public_comparisons": deepcopy(dict(comparisons)),
        "allowed_change_roster": allowances,
        "actual_deltas": actual_deltas,
        "unchanged_path_count": unchanged_count,
        "changed_path_count": len(changes),
        "authority_exclusion": {
            "included_in_execution_authority": False,
            "included_in_composition_authority": False,
            "included_in_compared_runtime_manifest": False,
        },
        "receipt_body_sha256": "0" * 64,
    }
    unsigned = dict(receipt)
    unsigned.pop("receipt_body_sha256")
    receipt["receipt_body_sha256"] = hashlib.sha256(
        canonical_json_bytes(unsigned)
    ).hexdigest()
    return receipt


def produce_compatibility_delta_v1(
    *,
    state: str,
    producer_bytes: bytes,
    pre_runtime_manifest_bytes: bytes,
    pre_r2_boundary_manifest: Mapping[str, Any],
    post_runtime_manifest_bytes: bytes,
    post_r2_runtime_manifest: Mapping[str, Any],
    comparator_receipt_bytes: bytes,
    comparator_receipt_binding: Mapping[str, Any],
    compared_output_bytes: Mapping[str, bytes],
    component_registry_bytes: bytes,
    component_registry_binding: Mapping[str, Any],
    allowed_change_roster_bytes: bytes,
    allowed_change_roster_binding: Mapping[str, Any],
    semantic_review_bytes: bytes,
    semantic_review_binding: Mapping[str, Any],
    exclusion_authority_bytes: bytes,
    exclusion_authority_binding: Mapping[str, Any],
    trusted_review_keys: Mapping[str, bytes],
    runtime_closure_state: str,
) -> dict[str, Any]:
    receipt = _derive_receipt(
        state=state,
        producer_bytes=producer_bytes,
        pre_runtime_manifest_bytes=pre_runtime_manifest_bytes,
        pre_r2_boundary_manifest=pre_r2_boundary_manifest,
        post_runtime_manifest_bytes=post_runtime_manifest_bytes,
        post_r2_runtime_manifest=post_r2_runtime_manifest,
        comparator_receipt_bytes=comparator_receipt_bytes,
        comparator_receipt_binding=comparator_receipt_binding,
        compared_output_bytes=compared_output_bytes,
        component_registry_bytes=component_registry_bytes,
        component_registry_binding=component_registry_binding,
        allowed_change_roster_bytes=allowed_change_roster_bytes,
        allowed_change_roster_binding=allowed_change_roster_binding,
        semantic_review_bytes=semantic_review_bytes,
        semantic_review_binding=semantic_review_binding,
        exclusion_authority_bytes=exclusion_authority_bytes,
        exclusion_authority_binding=exclusion_authority_binding,
        trusted_review_keys=trusted_review_keys,
        runtime_closure_state=runtime_closure_state,
    )
    return normalized_document(
        receipt,
        schema_name=_SCHEMA,
        label="compatibility delta",
    )


def validate_compatibility_delta_v1(
    document: Mapping[str, Any],
    *,
    producer_bytes: bytes,
    pre_runtime_manifest_bytes: bytes,
    pre_r2_boundary_manifest: Mapping[str, Any],
    post_runtime_manifest_bytes: bytes,
    post_r2_runtime_manifest: Mapping[str, Any],
    comparator_receipt_bytes: bytes,
    comparator_receipt_binding: Mapping[str, Any],
    compared_output_bytes: Mapping[str, bytes],
    component_registry_bytes: bytes,
    component_registry_binding: Mapping[str, Any],
    allowed_change_roster_bytes: bytes,
    allowed_change_roster_binding: Mapping[str, Any],
    semantic_review_bytes: bytes,
    semantic_review_binding: Mapping[str, Any],
    exclusion_authority_bytes: bytes,
    exclusion_authority_binding: Mapping[str, Any],
    trusted_review_keys: Mapping[str, bytes],
    runtime_closure_state: str,
    bound_post_runtime_manifest_digest: str | None = None,
    observed_post_runtime_manifest_digest: str | None = None,
) -> dict[str, Any]:
    receipt = normalized_document(
        document,
        schema_name=_SCHEMA,
        label="compatibility delta",
    )
    validate_signed_payload(receipt, "receipt_body_sha256")
    expected_pre_binding = _normalize_binding(
        pre_r2_boundary_manifest,
        label="expected pre-R2 boundary manifest",
    )
    if receipt["pre_r2_boundary_manifest"] != expected_pre_binding:
        raise ProgramFactsTypeError("wrong pre-R2 boundary manifest")
    expected_post_binding = _normalize_binding(
        post_r2_runtime_manifest,
        label="expected post-R2 runtime manifest",
    )
    if receipt["post_r2_runtime_manifest"] != expected_post_binding:
        raise ProgramFactsTypeError(
            "delta path/size/digest does not replay"
        )
    allowances = receipt["allowed_change_roster"]
    deltas = receipt["actual_deltas"]
    allowance_paths = [row["portable_path"] for row in allowances]
    delta_paths = [row["portable_path"] for row in deltas]
    if (
        len({path.casefold() for path in allowance_paths}) != len(allowance_paths)
        or len({path.casefold() for path in delta_paths}) != len(delta_paths)
    ):
        raise ProgramFactsTypeError(
            "compatibility delta path is duplicated or aliased"
        )
    if set(allowance_paths) != set(delta_paths):
        raise ProgramFactsTypeError(
            "compatibility denominators are not a bijection"
        )
    component_registry, _, _ = _parse_component_registry(
        component_registry_bytes,
        component_registry_binding,
        trusted_review_keys=trusted_review_keys,
    )
    for row in allowances:
        _validate_allowed_path(
            row["portable_path"],
            semantic_class=row["semantic_class"],
            component_registry=component_registry,
        )
    for row in deltas:
        _validate_allowed_path(
            row["portable_path"],
            semantic_class=row["semantic_class"],
            component_registry=component_registry,
        )
    derived = _derive_receipt(
        state=receipt["state"],
        producer_bytes=producer_bytes,
        pre_runtime_manifest_bytes=pre_runtime_manifest_bytes,
        pre_r2_boundary_manifest=pre_r2_boundary_manifest,
        post_runtime_manifest_bytes=post_runtime_manifest_bytes,
        post_r2_runtime_manifest=post_r2_runtime_manifest,
        comparator_receipt_bytes=comparator_receipt_bytes,
        comparator_receipt_binding=comparator_receipt_binding,
        compared_output_bytes=compared_output_bytes,
        component_registry_bytes=component_registry_bytes,
        component_registry_binding=component_registry_binding,
        allowed_change_roster_bytes=allowed_change_roster_bytes,
        allowed_change_roster_binding=allowed_change_roster_binding,
        semantic_review_bytes=semantic_review_bytes,
        semantic_review_binding=semantic_review_binding,
        exclusion_authority_bytes=exclusion_authority_bytes,
        exclusion_authority_binding=exclusion_authority_binding,
        trusted_review_keys=trusted_review_keys,
        runtime_closure_state=runtime_closure_state,
    )
    if receipt["public_comparisons"] != derived["public_comparisons"]:
        raise ProgramFactsTypeError(
            "same-postimage bytes differ from bound comparator evidence"
        )
    if receipt != derived:
        raise ProgramFactsTypeError(
            "compatibility receipt claims differ from bound immutable evidence"
        )
    post_digest = receipt["post_r2_runtime_manifest"]["sha256"]
    if bound_post_runtime_manifest_digest is not None:
        bound = require_sha256(
            bound_post_runtime_manifest_digest,
            label="bound post-runtime manifest digest",
        )
        if bound != post_digest:
            raise ProgramFactsTypeError(
                "compatibility receipt binds another post-runtime manifest"
            )
    if observed_post_runtime_manifest_digest is not None:
        observed = require_sha256(
            observed_post_runtime_manifest_digest,
            label="observed post-runtime manifest digest",
        )
        if observed != post_digest:
            raise ProgramFactsTypeError(
                "later runtime change invalidates the compatibility receipt"
            )
    return receipt


__all__ = [
    "EVIDENCE_CLASS",
    "FINAL_PATH",
    "PRODUCER_PATH",
    "PROVISIONAL_PATH",
    "SCHEMA_VERSION",
    "produce_compatibility_delta_v1",
    "validate_compatibility_delta_v1",
]
