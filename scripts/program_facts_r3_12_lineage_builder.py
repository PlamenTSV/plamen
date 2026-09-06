"""Build the frozen, property-exact R3.12 predecessor lineage fixtures.

The table below is intentionally ordinal-indexed and explicit.  It does not
route by diagnostic keywords and does not collapse predecessor properties into
shared aliases.  Each mutation is applied to a complete successor semantic
model and the full resealed model hash is recorded.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence


REPO = Path(__file__).resolve().parent.parent
PREDECESSOR = REPO / "Temp/program_facts_g3_launcher_r3_11_20260809/r3_11_lineage_recipes.v1.json"
PREDECESSOR_SIZE = 40388
PREDECESSOR_SHA256 = "29dc8afa8c6c5b7550527af2ef41b3fbecbf008126f8a463081a282aeb17d903"
OUTPUT_ROOT = REPO / "Temp/program_facts_g3_launcher_r3_12_20260809"
MODEL_OUTPUT = OUTPUT_ROOT / "r3_12_lineage_model.v1.json"
RECIPE_OUTPUT = OUTPUT_ROOT / "r3_12_lineage_recipes.v1.json"


# (successor JSON pointer, exact precondition, type-preserving mutation value)
# There are exactly 67 entries and their tuple order is the predecessor ordinal.
SUCCESSOR_BINDINGS: tuple[tuple[str, object, object], ...] = (
    ("/scope_deferments/linux_runtime/registered_declaration", "NO_CLAIM_WINDOWS_ONLY", "CLAIMED_WITHOUT_EVIDENCE_00"),
    ("/scope_deferments/linux_runtime/registered_path", "NO_CLAIM_WINDOWS_ONLY", "CLAIMED_WITHOUT_EVIDENCE_01"),
    ("/scope_deferments/linux_runtime/declaration_byte_offset", "NO_CLAIM_WINDOWS_ONLY", "CLAIMED_WITHOUT_EVIDENCE_02"),
    ("/scope_deferments/linux_runtime/declaration_matching_row_count", "NO_CLAIM_WINDOWS_ONLY", "CLAIMED_WITHOUT_EVIDENCE_03"),
    ("/scope_deferments/linux_runtime/declaration_binding_sha256", "NO_CLAIM_WINDOWS_ONLY", "CLAIMED_WITHOUT_EVIDENCE_04"),
    ("/scope_deferments/linux_runtime/x86_64_table_profile", "NO_CLAIM_WINDOWS_ONLY", "CLAIMED_WITHOUT_EVIDENCE_05"),
    ("/scope_deferments/linux_runtime/aarch64_table_profile", "NO_CLAIM_WINDOWS_ONLY", "CLAIMED_WITHOUT_EVIDENCE_06"),
    ("/scope_deferments/linux_runtime/x86_64_numbers_equal", "NO_CLAIM_WINDOWS_ONLY", "CLAIMED_WITHOUT_EVIDENCE_07"),
    ("/scope_deferments/linux_runtime/aarch64_numbers_equal", "NO_CLAIM_WINDOWS_ONLY", "CLAIMED_WITHOUT_EVIDENCE_08"),
    ("/scope_deferments/linux_runtime/declaration_join_profile", "NO_CLAIM_WINDOWS_ONLY", "CLAIMED_WITHOUT_EVIDENCE_09"),
    ("/scope_deferments/linux_runtime/syscall_table_slice_sha256", "NO_CLAIM_WINDOWS_ONLY", "CLAIMED_WITHOUT_EVIDENCE_10"),
    ("/scope_deferments/linux_runtime/uapi_number_slice_sha256", "NO_CLAIM_WINDOWS_ONLY", "CLAIMED_WITHOUT_EVIDENCE_11"),
    ("/scope_deferments/linux_runtime/declaration_slice_sha256", "NO_CLAIM_WINDOWS_ONLY", "CLAIMED_WITHOUT_EVIDENCE_12"),
    ("/scope_deferments/linux_runtime/build_manifest_sha256", "NO_CLAIM_WINDOWS_ONLY", "CLAIMED_WITHOUT_EVIDENCE_13"),
    ("/scope_deferments/linux_runtime/signature_core_row_sha256", "NO_CLAIM_WINDOWS_ONLY", "CLAIMED_WITHOUT_EVIDENCE_14"),
    ("/validation/fresh_child/result_identity_schema", "EXACT_R3_11_RESULT_IDENTITY", "WRONG_RESULT_IDENTITY_SCHEMA_15"),
    ("/validation/fresh_child/result_rows_schema", "EXACT_R3_11_RESULT_ROWS", "WRONG_RESULT_ROWS_SCHEMA_16"),
    ("/validation/fresh_child/equality_operand_count", 2, 3),
    ("/validation/fresh_child/prefix_right_operand_kind", "UTF8_STRING", "INTEGER_18"),
    ("/validation/fresh_child/no_return_term_count", 0, 1),
    ("/publication/rename_request/root_directory_handle_value", None, "NON_NULL_UNRETAINED_HANDLE_20"),
    ("/publication/rename_request/destination_path_kind", "ABSOLUTE_EXTENDED_LENGTH", "RELATIVE_COMPONENT_21"),
    ("/publication/rename_request/filename_excludes_nul", True, False),
    ("/publication/rename_request/reserved_and_tail_zero", True, False),
    ("/publication/post_destination_equality/source_handle_equals_destination_identity", True, False),
    ("/validation/fresh_child/runtime_module_policy", "PYTHON_I_S_STDLIB_PLUS_STAGED_VALIDATOR", "UNPINNED_RUNTIME_MODULE_25"),
    ("/validation/interpreter/identity_source", "BOUNDED_PINNED_PYTHON_EXE_BYTES", "UNPINNED_NTDLL_PATH_26"),
    ("/scope_deferments/linux_durability/filesystem_mount_join", "NO_CLAIM_WINDOWS_ONLY", "CLAIMED_WITHOUT_EVIDENCE_27"),
    ("/validation/interpreter/sha256_bound", True, False),
    ("/validation/interpreter/ordinary_user_windows_native", True, False),
    ("/validation/launcher/sha256_bound", True, False),
    ("/scope_deferments/linux_durability/derivation_inputs_all_satisfied", "NO_CLAIM_WINDOWS_ONLY", "CLAIMED_WITHOUT_EVIDENCE_31"),
    ("/publication/source_open/source_path_matches_retained_handle", True, False),
    ("/publication/destination_anchor/retained_through_post_equality", True, False),
    ("/validation/launcher/executed_production_candidate_bytes", True, False),
    ("/validation/fresh_child/projection_complete", True, False),
    ("/validation/fresh_child/missing_field_ordinals", [], [36]),
    ("/validation/fresh_child/slot_ordinals_exact", True, False),
    ("/validation/fresh_child/present_missing_disjoint", True, False),
    ("/validation/fresh_child/expected_binding_ordinals_exact", True, False),
    ("/validation/fresh_child/actual_binding_ordinals_exact", True, False),
    ("/validation/fresh_child/actual_field_ordinal_exact", True, False),
    ("/validation/fresh_child/actual_value_schema_exact", True, False),
    ("/validation/fresh_child/actual_field_sha256_bound", True, False),
    ("/validation/dependency_closure/source", "15_PINNED_RAW_BYTE_ARTIFACTS", "UNPINNED_SOURCE_44"),
    ("/validation/dependency_closure/value_schema", "PATH_SIZE_SHA256", "PATH_ONLY_45"),
    ("/publication/operation/operation_id", "WINDOWS_CLASS22_NO_REPLACE_PUBLICATION", "WRONG_OPERATION_46"),
    ("/publication/operation/domain", "WINDOWS_PROCESS_CRASH_ONLY", "POWER_LOSS_47"),
    ("/publication/operation/no_return_result_sha256_bound", True, False),
    ("/publication/operation/receipt_sha256_bound", True, False),
    ("/publication/operation/completion_kind", "SUCCESS_PROCESS_CRASH_ONLY", "DIRECTORY_DURABLE_50"),
    ("/publication/operation/uncertain_clone_outcome", "NOT_APPLICABLE_NO_SPAWN", "SPAWN_UNCERTAIN_51"),
    ("/publication/operation/occurrence_count", 1, 2),
    ("/publication/operation/occurrence_ordinals", [0], [0, 1]),
    ("/publication/operation/execution_join_count", 1, 0),
    ("/publication/post_destination_equality/conformance_result_sha256_bound", True, False),
    ("/publication/operation/execution_receipt_present", True, False),
    ("/review_chain/state_operational/disposition", "REPAIR_REQUIRED_PREDECESSOR_INPUT", "UNREVIEWED_57"),
    ("/review_chain/native_contract/subject_identity_bound", True, False),
    ("/review_chain/native_contract/contains_receipt_review", True, False),
    ("/review_chain/evidence_dag/node_count", 5, 4),
    ("/review_chain/evidence_dag/edge_count", 4, 3),
    ("/review_chain/evidence_dag/host_execution_receipt_type", "OWNED_TEMP_ROOT_NATIVE_FIXTURE", "PURE_MODEL_62"),
    ("/review_chain/aggregate/reviewed_profile_count", 2, 1),
    ("/review_chain/aggregate/predecessor_ordinals", list(range(67)), list(range(66))),
    ("/review_chain/aggregate/windows_profile", "ORDINARY_USER_PROTECTED_ROOT_PROCESS_CRASH", "ADMINISTRATOR_OR_POWER_LOSS_65"),
    ("/authority/result_hash_preimage_includes_result_hash", False, True),
)


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _segments(pointer: str) -> tuple[str, ...]:
    if not pointer.startswith("/") or "~" in pointer:
        raise ValueError(f"unsupported JSON pointer: {pointer}")
    return tuple(pointer[1:].split("/"))


def pointer_set(document: dict[str, Any], pointer: str, value: object) -> None:
    current = document
    parts = _segments(pointer)
    for segment in parts[:-1]:
        child = current.setdefault(segment, {})
        if not isinstance(child, dict):
            raise ValueError(f"path collision at {pointer}")
        current = child
    current[parts[-1]] = deepcopy(value)


def pointer_get(document: Mapping[str, Any], pointer: str) -> object:
    current: object = document
    for segment in _segments(pointer):
        if not isinstance(current, Mapping) or segment not in current:
            raise KeyError(pointer)
        current = current[segment]
    return deepcopy(current)


def _pinned_predecessor() -> list[dict[str, Any]]:
    raw = PREDECESSOR.read_bytes()
    if len(raw) != PREDECESSOR_SIZE or sha256_bytes(raw) != PREDECESSOR_SHA256:
        raise RuntimeError("R3.11 lineage predecessor identity mismatch")
    rows = json.loads(raw.decode("utf-8", errors="strict"))
    if not isinstance(rows, list) or len(rows) != len(SUCCESSOR_BINDINGS):
        raise RuntimeError("R3.11 lineage predecessor cardinality mismatch")
    return rows


def build() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    predecessor = _pinned_predecessor()
    model: dict[str, Any] = {}
    for pointer, expected, _mutation in SUCCESSOR_BINDINGS:
        pointer_set(model, pointer, expected)
    model["schema"] = "plamen.program_facts.g3.launcher.r3_12.lineage_model.v1"
    model["candidate_active"] = False
    model["global_authority"] = {
        "native_execution_authority": False,
        "publication_allowed": False,
        "cutover_allowed": False,
    }
    model_sha = sha256_bytes(canonical(model))

    recipes: list[dict[str, Any]] = []
    for ordinal, (source, binding) in enumerate(zip(predecessor, SUCCESSOR_BINDINGS, strict=True)):
        pointer, expected, mutation = binding
        if source["lineage_ordinal"] != ordinal or pointer_get(model, pointer) != expected:
            raise RuntimeError(f"lineage ordinal {ordinal} precondition mismatch")
        mutated = deepcopy(model)
        pointer_set(mutated, pointer, mutation)
        mutated_sha = sha256_bytes(canonical(mutated))
        recipe_core = {
            "lineage_ordinal": ordinal,
            "predecessor_atom_sha256": source["predecessor_atom_sha256"],
            "predecessor_mutation_id": source["predecessor_mutation_id"],
            "predecessor_property": source["predecessor_property"],
            "successor_json_paths": [pointer],
            "precondition": {
                "model_sha256": model_sha,
                "operation": "EXACT_JSON_VALUE",
                "path": pointer,
                "value": expected,
            },
            "mutation_operation": "REPLACE_EXACT_VALUE",
            "mutation_value": mutation,
            "resealed_candidate_sha256": mutated_sha,
            "expected_primary": source["successor_expected_primary"],
            "expected_subcode": source["successor_expected_subcode"],
            "equivalence_rationale": (
                "This ordinal mutates only the explicit R3.12 successor property "
                f"{pointer}; all other successor properties remain byte-canonical."
            ),
        }
        recipe_core["recipe_sha256"] = sha256_bytes(canonical(recipe_core))
        recipes.append(recipe_core)
    return model, recipes


def evaluate_mutation(
    lineage_ordinal: int,
    mutated_model: Mapping[str, Any],
) -> tuple[str, str]:
    """Evaluate one exact mutation without keyword or diagnostic fallback."""

    if type(lineage_ordinal) is not int or not 0 <= lineage_ordinal < len(SUCCESSOR_BINDINGS):
        return "LINEAGE_HARNESS", "ORDINAL_OUT_OF_RANGE"
    model, recipes = build()
    pointer, expected, mutation = SUCCESSOR_BINDINGS[lineage_ordinal]
    candidate = deepcopy(model)
    pointer_set(candidate, pointer, mutation)
    if canonical(mutated_model) != canonical(candidate):
        return "LINEAGE_HARNESS", "CROSS_PROPERTY_OR_MUTATION_DRIFT"
    if pointer_get(mutated_model, pointer) == expected:
        return "LINEAGE_HARNESS", "MUTATION_NOT_APPLIED"
    recipe = recipes[lineage_ordinal]
    return str(recipe["expected_primary"]), str(recipe["expected_subcode"])


def write_outputs() -> None:
    model, recipes = build()
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    MODEL_OUTPUT.write_bytes(canonical(model))
    RECIPE_OUTPUT.write_bytes(canonical(recipes))


if __name__ == "__main__":
    write_outputs()


__all__ = [
    "MODEL_OUTPUT",
    "PREDECESSOR_SHA256",
    "PREDECESSOR_SIZE",
    "RECIPE_OUTPUT",
    "SUCCESSOR_BINDINGS",
    "build",
    "canonical",
    "evaluate_mutation",
    "pointer_get",
    "pointer_set",
    "write_outputs",
]
