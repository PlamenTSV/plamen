"""Pure R2.1 expected-child and terminal-roster authority.

The functions here reconcile caller-supplied plans and ledger rows.  They do
not scan directories, resolve live PhaseIO state, read CAS files, or execute a
WorkerTransaction.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
import hashlib
from types import MappingProxyType
from typing import Any

from program_facts_v2_contracts import (
    ProgramFactsTypeError,
    canonical_file_bytes,
    canonical_json_bytes,
    normalized_document,
    require_exact_keys,
    require_relative_file_path,
    require_sha256,
    require_sorted_unique,
    validate_signed_payload,
)
from program_facts_types import strict_json_loads


EXPECTED_CHILDREN_SCHEMA = (
    "program_facts_evm_expected_wtx_children.v1.schema.json"
)
TERMINAL_ROSTER_SCHEMA = (
    "program_facts_evm_terminal_wtx_roster.v1.schema.json"
)
TERMINAL_ARTIFACT_ROLES = (
    "ATTEMPT_ARM",
    "ATTEMPT_COMPLETION",
    "ATTEMPT_DEBT",
    "RAW_CAS_MANIFEST",
)
_MANIFEST_EXPANSION_ACCEPTED_STATES = frozenset(
    {"ACCEPTED", "FROZEN_ACCEPTED"}
)
_INDEPENDENT_PASS_STATES = frozenset({"PASS", "PASS_WITH_ADVISORIES"})
_PHASE_IO_CONTRACTS = MappingProxyType(
    {
        "recon/program_facts_terminal_wtx_roster_capture_v1": MappingProxyType(
            {
                "model_invoked": False,
                "required_predecessors": (
                    "recon/program_facts_build_plan_capture_v1",
                ),
                "fixed_output": (
                    "_program_facts_inputs/"
                    "evm_terminal_wtx_roster.v1.json"
                ),
                "input_authority": "PREDECLARED_EXPECTED_WTX_CHILDREN_ONLY",
                "dynamic_predecessor_authority": (
                    "EXPECTED_WTX_CHILDREN_V1_PREDECLARED_IDENTITIES"
                ),
            }
        ),
        "recon/program_facts_execution_set_capture_v1": MappingProxyType(
            {
                "model_invoked": False,
                "required_predecessors": (
                    "recon/program_facts_build_plan_capture_v1",
                    "recon/program_facts_terminal_wtx_roster_capture_v1",
                ),
                "fixed_outputs": (
                    "_program_facts_inputs/evm_execution_set.v1.json",
                    "_program_facts_inputs/evm_execution_evidence.v1.pfcas",
                ),
                "input_kind": "MANIFEST_EXPANDED_EXACT_INPUT_SET_V1",
            }
        ),
    }
)
_FROZEN_BUILD_PLAN_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "run_generation",
        "execution_authority_digest",
        "selected_variant_ids",
        "build_plan_digest",
    }
)
_FROZEN_BUILD_PLAN_LEDGER_BINDING_KEYS = frozenset(
    {
        "ledger_state",
        "path",
        "size",
        "sha256",
    }
)
_FROZEN_BUILD_PLAN_PATH = (
    "_program_facts_inputs/evm_frozen_build_plan.v1.json"
)
_RAW_CAS_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "run_generation",
        "producer_work_unit_id",
        "producer_attempt_identity",
        "producer_output_identity",
        "namespace",
        "leaves",
        "manifest_body_sha256",
    }
)
_RAW_CAS_LEAF_KEYS = frozenset(
    {
        "namespace",
        "cas_leaf_id",
        "physical_path",
        "size",
        "sha256",
    }
)


def program_facts_phase_io_contracts_v1() -> dict[str, dict[str, Any]]:
    """Return an isolated declaration, not a registration side effect."""

    return {
        key: {
            field: list(value) if isinstance(value, tuple) else value
            for field, value in row.items()
        }
        for key, row in _PHASE_IO_CONTRACTS.items()
    }


def _tagged_identity(tag: str, binding: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(
        canonical_json_bytes({"tag": tag, **dict(binding)})
    ).hexdigest()
    return f"{tag}-{digest[:24]}"


def _validate_frozen_build_plan_document(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(document, Mapping):
        raise ProgramFactsTypeError("frozen build plan must be an object")
    plan = dict(document)
    require_exact_keys(
        plan,
        required=_FROZEN_BUILD_PLAN_KEYS,
        label="frozen build plan",
    )
    if (
        plan["schema_version"]
        != "plamen.program_facts_evm_frozen_build_plan.v1"
    ):
        raise ProgramFactsTypeError("frozen build-plan schema version diverges")
    if not isinstance(plan["run_id"], str) or not plan["run_id"]:
        raise ProgramFactsTypeError("frozen build-plan run_id is invalid")
    if (
        not isinstance(plan["run_generation"], int)
        or isinstance(plan["run_generation"], bool)
        or plan["run_generation"] < 0
    ):
        raise ProgramFactsTypeError("frozen build-plan generation is invalid")
    require_sha256(
        plan["execution_authority_digest"],
        label="frozen build-plan execution authority",
    )
    selected = plan["selected_variant_ids"]
    if (
        not isinstance(selected, Sequence)
        or isinstance(selected, (str, bytes, bytearray))
        or not all(isinstance(item, str) and item for item in selected)
    ):
        raise ProgramFactsTypeError("frozen build-plan variants are invalid")
    if list(selected) != sorted(selected) or len(selected) != len(set(selected)):
        raise ProgramFactsTypeError(
            "frozen build-plan variants must be sorted and unique"
        )
    require_sha256(plan["build_plan_digest"], label="frozen build-plan digest")
    unsigned = dict(plan)
    claimed = unsigned.pop("build_plan_digest")
    if hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest() != claimed:
        raise ProgramFactsTypeError("build plan digest does not replay")
    return plan


def validate_frozen_build_plan_v1(
    document: Mapping[str, Any],
    *,
    expected_build_plan_digest: str,
    build_plan_ledger_binding: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay a self-digested plan against its external ledger authority."""

    plan = _validate_frozen_build_plan_document(document)
    expected_digest = require_sha256(
        expected_build_plan_digest,
        label="expected build-plan digest",
    )
    if plan["build_plan_digest"] != expected_digest:
        raise ProgramFactsTypeError(
            "build-plan digest diverges from expected authority"
        )
    if (
        not isinstance(build_plan_ledger_binding, Mapping)
        or frozenset(build_plan_ledger_binding)
        != _FROZEN_BUILD_PLAN_LEDGER_BINDING_KEYS
    ):
        raise ProgramFactsTypeError(
            "build-plan ledger binding keys mismatch"
        )
    binding = dict(build_plan_ledger_binding)
    if binding["ledger_state"] != "ACTIVE":
        raise ProgramFactsTypeError(
            "build-plan ledger binding state diverges"
        )
    if binding["path"] != _FROZEN_BUILD_PLAN_PATH:
        raise ProgramFactsTypeError(
            "build-plan ledger binding path diverges"
        )
    raw = canonical_file_bytes(plan)
    if (
        not isinstance(binding["size"], int)
        or isinstance(binding["size"], bool)
        or binding["size"] != len(raw)
    ):
        raise ProgramFactsTypeError(
            "build-plan ledger binding size diverges"
        )
    observed_sha256 = require_sha256(
        binding["sha256"],
        label="build-plan ledger binding sha256",
    )
    if observed_sha256 != hashlib.sha256(raw).hexdigest():
        raise ProgramFactsTypeError(
            "build-plan ledger binding sha256 diverges"
        )
    return plan


def _derive_expected_wtx_children(
    plan: Mapping[str, Any],
) -> dict[str, Any]:
    run_id = plan["run_id"]
    run_generation = plan["run_generation"]
    execution_authority_digest = plan["execution_authority_digest"]
    build_plan_digest = plan["build_plan_digest"]
    selected_ids = list(plan["selected_variant_ids"])
    rows: list[dict[str, Any]] = []
    for variant_id in selected_ids:
        common = {
            "run_id": run_id,
            "run_generation": run_generation,
            "execution_authority_digest": execution_authority_digest,
            "build_plan_digest": build_plan_digest,
            "selected_variant_id": variant_id,
        }
        work_unit_id = _tagged_identity("program-facts-wtx", common)
        attempt_identity = _tagged_identity(
            "attempt", {**common, "work_unit_id": work_unit_id}
        )
        artifacts = []
        for role in TERMINAL_ARTIFACT_ROLES:
            output_identity = _tagged_identity(
                "output",
                {
                    **common,
                    "work_unit_id": work_unit_id,
                    "attempt_identity": attempt_identity,
                    "logical_role": role,
                },
            )
            artifacts.append(
                {
                    "logical_role": role,
                    "producer_output_identity": output_identity,
                    "expected_relative_path": (
                        f"_worker_transactions/{attempt_identity}/"
                        f"{role.lower()}.json"
                    ),
                }
            )
        rows.append(
            {
                "selected_variant_id": variant_id,
                "expected_work_unit_id": work_unit_id,
                "expected_attempt_identity": attempt_identity,
                "terminal_artifacts": artifacts,
            }
        )
    expected: dict[str, Any] = {
        "schema_version": "plamen.program_facts_evm_expected_wtx_children.v1",
        "run_id": run_id,
        "run_generation": run_generation,
        "execution_authority_digest": execution_authority_digest,
        "build_plan_digest": build_plan_digest,
        "expected_child_count": len(rows),
        "expected_wtx_children": rows,
        "children_body_sha256": "0" * 64,
    }
    unsigned = dict(expected)
    unsigned.pop("children_body_sha256")
    expected["children_body_sha256"] = hashlib.sha256(
        canonical_json_bytes(unsigned)
    ).hexdigest()
    return expected


def build_expected_wtx_children_v1(
    *,
    run_id: str,
    run_generation: int,
    execution_authority_digest: str,
    build_plan: Mapping[str, Any],
    expected_build_plan_digest: str,
    build_plan_ledger_binding: Mapping[str, Any],
) -> dict[str, Any]:
    """Derive the complete child denominator before any WTx is launched."""

    plan = validate_frozen_build_plan_v1(
        build_plan,
        expected_build_plan_digest=expected_build_plan_digest,
        build_plan_ledger_binding=build_plan_ledger_binding,
    )
    if (
        run_id != plan["run_id"]
        or run_generation != plan["run_generation"]
        or execution_authority_digest != plan["execution_authority_digest"]
    ):
        raise ProgramFactsTypeError(
            "expected-child arguments differ from frozen build authority"
        )
    document = _derive_expected_wtx_children(plan)
    return validate_expected_wtx_children_v1(
        document,
        build_plan=build_plan,
        expected_build_plan_digest=expected_build_plan_digest,
        build_plan_ledger_binding=build_plan_ledger_binding,
    )


def validate_expected_wtx_children_v1(
    document: Mapping[str, Any],
    *,
    build_plan: Mapping[str, Any],
    expected_build_plan_digest: str,
    build_plan_ledger_binding: Mapping[str, Any],
) -> dict[str, Any]:
    expected = normalized_document(
        document,
        schema_name=EXPECTED_CHILDREN_SCHEMA,
        label="expected WTx children",
    )
    validate_signed_payload(expected, "children_body_sha256")
    plan = validate_frozen_build_plan_v1(
        build_plan,
        expected_build_plan_digest=expected_build_plan_digest,
        build_plan_ledger_binding=build_plan_ledger_binding,
    )
    selected_ids = list(plan["selected_variant_ids"])
    rows = expected["expected_wtx_children"]
    if expected["expected_child_count"] != len(rows):
        raise ProgramFactsTypeError("expected child count does not match rows")
    require_sorted_unique(
        rows,
        label="expected WTx children",
        key="selected_variant_id",
    )
    if [row["selected_variant_id"] for row in rows] != selected_ids:
        raise ProgramFactsTypeError(
            "selected variants and expected children are not a bijection"
        )
    work_ids: set[str] = set()
    attempt_ids: set[str] = set()
    output_ids: set[str] = set()
    paths: set[str] = set()
    for row in rows:
        work_id = row["expected_work_unit_id"]
        attempt_id = row["expected_attempt_identity"]
        if work_id in work_ids or attempt_id in attempt_ids:
            raise ProgramFactsTypeError("child work or attempt identity is duplicated")
        work_ids.add(work_id)
        attempt_ids.add(attempt_id)
        artifacts = row["terminal_artifacts"]
        if tuple(item["logical_role"] for item in artifacts) != TERMINAL_ARTIFACT_ROLES:
            raise ProgramFactsTypeError(
                "terminal artifact role denominator is incomplete or reordered"
            )
        for artifact in artifacts:
            output_id = artifact["producer_output_identity"]
            path_key = artifact["expected_relative_path"].casefold()
            if output_id in output_ids or path_key in paths:
                raise ProgramFactsTypeError(
                    "terminal artifact output identity or path is duplicated"
                )
            output_ids.add(output_id)
            paths.add(path_key)
    derived = _derive_expected_wtx_children(plan)
    if expected != derived:
        raise ProgramFactsTypeError("expected-child derivation diverges")
    return expected


def _ledger_key(row: Mapping[str, Any]) -> tuple[str, str]:
    return (
        str(row.get("producer_work_unit_id", "")),
        str(row.get("producer_output_identity", "")),
    )


def _validate_ledger_denominator(
    *,
    expected: Mapping[str, Any],
    ledger_rows: Sequence[Mapping[str, Any]],
) -> dict[tuple[str, str], dict[str, Any]]:
    if not isinstance(ledger_rows, Sequence) or isinstance(
        ledger_rows, (str, bytes, bytearray)
    ):
        raise ProgramFactsTypeError("ledger rows must be a sequence")
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in ledger_rows:
        if not isinstance(raw, Mapping):
            raise ProgramFactsTypeError("ledger row must be an object")
        row = dict(raw)
        key = _ledger_key(row)
        if not all(key) or key in by_key:
            raise ProgramFactsTypeError("ledger output identity is missing or duplicate")
        if row.get("run_id") != expected["run_id"]:
            raise ProgramFactsTypeError("foreign-run terminal producer")
        if row.get("run_generation") != expected["run_generation"]:
            raise ProgramFactsTypeError("foreign-generation terminal producer")
        if row.get("terminal") is not True:
            raise ProgramFactsTypeError("nonterminal producer cannot enter the roster")
        if (
            not isinstance(row.get("size"), int)
            or isinstance(row.get("size"), bool)
            or row["size"] < 0
        ):
            raise ProgramFactsTypeError("ledger output size is invalid")
        require_sha256(row.get("sha256"), label="ledger output digest")
        require_sha256(
            row.get("ledger_output_row_digest"),
            label="ledger output row digest",
        )
        by_key[key] = row
    return by_key


def validate_terminal_wtx_roster_v1(
    document: Mapping[str, Any],
    *,
    expected_children: Mapping[str, Any],
    ledger_rows: Sequence[Mapping[str, Any]],
    build_plan: Mapping[str, Any],
    expected_build_plan_digest: str,
    build_plan_ledger_binding: Mapping[str, Any],
) -> dict[str, Any]:
    expected = validate_expected_wtx_children_v1(
        expected_children,
        build_plan=build_plan,
        expected_build_plan_digest=expected_build_plan_digest,
        build_plan_ledger_binding=build_plan_ledger_binding,
    )
    roster = normalized_document(
        document,
        schema_name=TERMINAL_ROSTER_SCHEMA,
        label="terminal WTx roster",
    )
    validate_signed_payload(roster, "roster_body_sha256")
    for key in (
        "run_id",
        "run_generation",
        "execution_authority_digest",
        "build_plan_digest",
        "expected_child_count",
    ):
        if roster[key] != expected[key]:
            raise ProgramFactsTypeError(f"roster root field {key!r} diverges")
    if roster["expected_wtx_children_digest"] != expected["children_body_sha256"]:
        raise ProgramFactsTypeError("roster binds a different child plan")
    rows = roster["rows"]
    if roster["terminal_child_count"] != len(rows):
        raise ProgramFactsTypeError("terminal child count does not match rows")
    if len(rows) != expected["expected_child_count"]:
        raise ProgramFactsTypeError("terminal roster is not N-of-N")
    require_sorted_unique(
        rows,
        label="terminal WTx roster",
        key="selected_variant_id",
    )
    expected_by_variant = {
        row["selected_variant_id"]: row for row in expected["expected_wtx_children"]
    }
    if [row["selected_variant_id"] for row in rows] != list(expected_by_variant):
        raise ProgramFactsTypeError("terminal variants differ from child plan")
    ledger_by_key = _validate_ledger_denominator(
        expected=expected,
        ledger_rows=ledger_rows,
    )
    consumed: set[tuple[str, str]] = set()
    for row in rows:
        planned = expected_by_variant[row["selected_variant_id"]]
        if row["producer_work_unit_id"] != planned["expected_work_unit_id"]:
            raise ProgramFactsTypeError("roster work unit was not predeclared")
        if row["producer_attempt_identity"] != planned["expected_attempt_identity"]:
            raise ProgramFactsTypeError("roster attempt was not predeclared")
        planned_artifacts = planned["terminal_artifacts"]
        actual_artifacts = row["terminal_artifacts"]
        if tuple(item["semantic_role"] for item in actual_artifacts) != TERMINAL_ARTIFACT_ROLES:
            raise ProgramFactsTypeError("roster terminal roles are not exact")
        if len(actual_artifacts) != len(planned_artifacts):
            raise ProgramFactsTypeError("roster terminal artifact count diverges")
        for planned_artifact, observed in zip(planned_artifacts, actual_artifacts):
            if observed["semantic_role"] != planned_artifact["logical_role"]:
                raise ProgramFactsTypeError("terminal semantic role diverges")
            if (
                observed["producer_output_identity"]
                != planned_artifact["producer_output_identity"]
            ):
                raise ProgramFactsTypeError("terminal output was not predeclared")
            key = (
                row["producer_work_unit_id"],
                observed["producer_output_identity"],
            )
            ledger = ledger_by_key.get(key)
            if ledger is None:
                raise ProgramFactsTypeError("predeclared terminal output is absent")
            if ledger.get("producer_attempt_identity") != row[
                "producer_attempt_identity"
            ]:
                raise ProgramFactsTypeError("terminal attempt identity diverges")
            expected_fields = {
                "semantic_role": observed["semantic_role"],
                "producer_output_identity": observed[
                    "producer_output_identity"
                ],
                "physical_path": observed["physical_path"],
                "size": observed["size"],
                "sha256": observed["sha256"],
                "ledger_output_row_digest": observed[
                    "ledger_output_row_digest"
                ],
            }
            for field, value in expected_fields.items():
                if ledger.get(field) != value:
                    raise ProgramFactsTypeError(
                        f"terminal ledger field {field!r} diverges"
                    )
            if observed["physical_path"] != planned_artifact["expected_relative_path"]:
                raise ProgramFactsTypeError("terminal path differs from child plan")
            consumed.add(key)
    if consumed != set(ledger_by_key):
        raise ProgramFactsTypeError("ledger denominator contains unplanned outputs")
    return roster


def build_terminal_wtx_roster_v1(
    *,
    expected_children: Mapping[str, Any],
    ledger_rows: Sequence[Mapping[str, Any]],
    build_plan: Mapping[str, Any],
    expected_build_plan_digest: str,
    build_plan_ledger_binding: Mapping[str, Any],
) -> dict[str, Any]:
    expected = validate_expected_wtx_children_v1(
        expected_children,
        build_plan=build_plan,
        expected_build_plan_digest=expected_build_plan_digest,
        build_plan_ledger_binding=build_plan_ledger_binding,
    )
    ledger_by_key = _validate_ledger_denominator(
        expected=expected,
        ledger_rows=ledger_rows,
    )
    rows = []
    for child in expected["expected_wtx_children"]:
        artifacts = []
        for planned in child["terminal_artifacts"]:
            ledger = ledger_by_key.get(
                (
                    child["expected_work_unit_id"],
                    planned["producer_output_identity"],
                )
            )
            if ledger is None:
                raise ProgramFactsTypeError("terminal ledger denominator is incomplete")
            artifacts.append(
                {
                    "semantic_role": ledger["semantic_role"],
                    "producer_output_identity": ledger[
                        "producer_output_identity"
                    ],
                    "physical_path": ledger["physical_path"],
                    "size": ledger["size"],
                    "sha256": ledger["sha256"],
                    "ledger_output_row_digest": ledger[
                        "ledger_output_row_digest"
                    ],
                }
            )
        rows.append(
            {
                "selected_variant_id": child["selected_variant_id"],
                "producer_work_unit_id": child["expected_work_unit_id"],
                "producer_attempt_identity": child["expected_attempt_identity"],
                "terminal_artifacts": artifacts,
            }
        )
    roster: dict[str, Any] = {
        "schema_version": "plamen.program_facts_evm_terminal_wtx_roster.v1",
        "run_id": expected["run_id"],
        "run_generation": expected["run_generation"],
        "execution_authority_digest": expected["execution_authority_digest"],
        "build_plan_digest": expected["build_plan_digest"],
        "expected_wtx_children_digest": expected["children_body_sha256"],
        "expected_child_count": expected["expected_child_count"],
        "terminal_child_count": len(rows),
        "rows": rows,
        "roster_body_sha256": "0" * 64,
    }
    unsigned = dict(roster)
    unsigned.pop("roster_body_sha256")
    roster["roster_body_sha256"] = hashlib.sha256(
        canonical_json_bytes(unsigned)
    ).hexdigest()
    return validate_terminal_wtx_roster_v1(
        roster,
        expected_children=expected,
        ledger_rows=ledger_rows,
        build_plan=build_plan,
        expected_build_plan_digest=expected_build_plan_digest,
        build_plan_ledger_binding=build_plan_ledger_binding,
    )


def _parse_raw_cas_manifest(
    raw: bytes,
    *,
    manifest_output_identity: str,
    expected: Mapping[str, Any],
    planned_child: Mapping[str, Any],
    ledger_row: Mapping[str, Any],
) -> list[dict[str, Any]]:
    if type(raw) is not bytes:
        raise ProgramFactsTypeError("raw-CAS manifest content must be exact bytes")
    if len(raw) != ledger_row["size"] or hashlib.sha256(raw).hexdigest() != ledger_row[
        "sha256"
    ]:
        raise ProgramFactsTypeError("raw-CAS manifest bytes differ from ledger binding")
    document = strict_json_loads(
        raw,
        require_final_lf=True,
        require_canonical=True,
    )
    if not isinstance(document, dict):
        raise ProgramFactsTypeError("raw-CAS manifest root must be an object")
    require_exact_keys(
        document,
        required=_RAW_CAS_MANIFEST_KEYS,
        label="raw-CAS manifest",
    )
    if (
        document["schema_version"]
        != "plamen.program_facts_evm_raw_cas_manifest.v1"
    ):
        raise ProgramFactsTypeError("raw-CAS manifest schema version diverges")
    unsigned = dict(document)
    claimed = unsigned.pop("manifest_body_sha256")
    require_sha256(claimed, label="raw-CAS manifest body digest")
    if hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest() != claimed:
        raise ProgramFactsTypeError("raw-CAS manifest self-digest diverges")
    expected_root = {
        "run_id": expected["run_id"],
        "run_generation": expected["run_generation"],
        "producer_work_unit_id": planned_child["expected_work_unit_id"],
        "producer_attempt_identity": planned_child["expected_attempt_identity"],
        "producer_output_identity": manifest_output_identity,
    }
    for key, value in expected_root.items():
        if document[key] != value:
            raise ProgramFactsTypeError(
                f"raw-CAS manifest {key!r} differs from frozen child authority"
            )
    if not isinstance(document["namespace"], str) or not document["namespace"]:
        raise ProgramFactsTypeError("raw-CAS manifest namespace is invalid")
    leaves = document["leaves"]
    if not isinstance(leaves, list):
        raise ProgramFactsTypeError("raw-CAS manifest leaves must be an array")
    leaf_keys: list[tuple[str, str]] = []
    expanded: list[dict[str, Any]] = []
    for raw_leaf in leaves:
        if not isinstance(raw_leaf, Mapping):
            raise ProgramFactsTypeError("raw-CAS leaf must be an object")
        leaf = dict(raw_leaf)
        require_exact_keys(
            leaf,
            required=_RAW_CAS_LEAF_KEYS,
            label="raw-CAS leaf",
        )
        if leaf["namespace"] != document["namespace"]:
            raise ProgramFactsTypeError("raw-CAS leaf namespace diverges")
        if not isinstance(leaf["cas_leaf_id"], str) or not leaf["cas_leaf_id"]:
            raise ProgramFactsTypeError("raw-CAS leaf identity is invalid")
        require_relative_file_path(
            leaf["physical_path"], label="raw-CAS leaf physical path"
        )
        if (
            not isinstance(leaf["size"], int)
            or isinstance(leaf["size"], bool)
            or leaf["size"] < 0
        ):
            raise ProgramFactsTypeError("raw-CAS leaf size is invalid")
        require_sha256(leaf["sha256"], label="raw-CAS leaf digest")
        leaf_keys.append((leaf["namespace"].casefold(), leaf["cas_leaf_id"].casefold()))
        expanded.append(
            {
                "run_id": expected["run_id"],
                "run_generation": expected["run_generation"],
                "producer_work_unit_id": planned_child["expected_work_unit_id"],
                "producer_attempt_identity": planned_child[
                    "expected_attempt_identity"
                ],
                "producer_output_identity": leaf["cas_leaf_id"],
                "source_manifest_output_identity": manifest_output_identity,
                "semantic_role": "RAW_CAS_LEAF",
                "namespace": leaf["namespace"],
                "cas_leaf_id": leaf["cas_leaf_id"],
                "physical_path": leaf["physical_path"],
                "size": leaf["size"],
                "sha256": leaf["sha256"],
                "terminal": False,
            }
        )
    if leaf_keys != sorted(leaf_keys) or len(leaf_keys) != len(set(leaf_keys)):
        raise ProgramFactsTypeError(
            "raw-CAS leaves must be canonically sorted and unique"
        )
    return expanded


def validate_execution_set_capture_inputs_v1(
    *,
    build_plan: Mapping[str, Any],
    expected_build_plan_digest: str,
    build_plan_ledger_binding: Mapping[str, Any],
    expected_children: Mapping[str, Any],
    terminal_roster: Mapping[str, Any],
    terminal_roster_ledger_state: str,
    terminal_ledger_rows: Sequence[Mapping[str, Any]],
    raw_cas_manifests: Mapping[str, bytes],
    expanded_inputs: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    if terminal_roster_ledger_state != "ACTIVE":
        raise ProgramFactsTypeError("terminal roster is not ACTIVE")
    expected = validate_expected_wtx_children_v1(
        expected_children,
        build_plan=build_plan,
        expected_build_plan_digest=expected_build_plan_digest,
        build_plan_ledger_binding=build_plan_ledger_binding,
    )
    roster = validate_terminal_wtx_roster_v1(
        terminal_roster,
        expected_children=expected,
        ledger_rows=terminal_ledger_rows,
        build_plan=build_plan,
        expected_build_plan_digest=expected_build_plan_digest,
        build_plan_ledger_binding=build_plan_ledger_binding,
    )
    if not isinstance(raw_cas_manifests, Mapping):
        raise ProgramFactsTypeError("raw-CAS manifests must be an exact mapping")
    terminal_by_output = {
        row["producer_output_identity"]: dict(row)
        for row in terminal_ledger_rows
    }
    child_by_manifest: dict[str, Mapping[str, Any]] = {}
    for child in expected["expected_wtx_children"]:
        for artifact in child["terminal_artifacts"]:
            if artifact["logical_role"] == "RAW_CAS_MANIFEST":
                child_by_manifest[artifact["producer_output_identity"]] = child
    if set(raw_cas_manifests) != set(child_by_manifest):
        raise ProgramFactsTypeError("raw-CAS manifest denominator is not exact")
    derived_leaves: list[dict[str, Any]] = []
    for manifest_output_identity in sorted(raw_cas_manifests):
        ledger_row = terminal_by_output.get(manifest_output_identity)
        if ledger_row is None or ledger_row.get("semantic_role") != "RAW_CAS_MANIFEST":
            raise ProgramFactsTypeError(
                "raw-CAS manifest lacks terminal ledger authority"
            )
        derived_leaves.extend(
            _parse_raw_cas_manifest(
                raw_cas_manifests[manifest_output_identity],
                manifest_output_identity=manifest_output_identity,
                expected=expected,
                planned_child=child_by_manifest[manifest_output_identity],
                ledger_row=ledger_row,
            )
        )
    physical_paths = [row["physical_path"] for row in derived_leaves]
    if (
        len(set(physical_paths)) != len(physical_paths)
        or len({path.casefold() for path in physical_paths})
        != len(physical_paths)
    ):
        raise ProgramFactsTypeError(
            "raw CAS physical path alias in authenticated manifest union"
        )
    if not isinstance(expanded_inputs, Sequence) or isinstance(
        expanded_inputs, (str, bytes, bytearray)
    ):
        raise ProgramFactsTypeError("expanded inputs must be a sequence")
    observed_rows = [dict(row) for row in expanded_inputs if isinstance(row, Mapping)]
    if len(observed_rows) != len(expanded_inputs):
        raise ProgramFactsTypeError("expanded inputs contain a non-object")
    expected_rows = [dict(row) for row in terminal_ledger_rows] + derived_leaves
    observed_bytes = sorted(canonical_json_bytes(row) for row in observed_rows)
    expected_bytes = sorted(canonical_json_bytes(row) for row in expected_rows)
    if observed_bytes != expected_bytes:
        raise ProgramFactsTypeError(
            "ledger denominator contains unplanned outputs; raw CAS leaf "
            "denominator differs from the authenticated manifest union"
        )
    terminal_denominator = sorted(
        (dict(row) for row in terminal_ledger_rows),
        key=lambda row: (
            row["producer_work_unit_id"],
            row["producer_output_identity"],
        ),
    )
    raw_denominator = sorted(
        derived_leaves,
        key=lambda row: (
            row["namespace"].casefold(),
            row["cas_leaf_id"].casefold(),
        ),
    )
    return {
        "accepted": True,
        "build_plan_digest": expected["build_plan_digest"],
        "expected_wtx_children_digest": expected["children_body_sha256"],
        "terminal_wtx_roster_digest": roster["roster_body_sha256"],
        "expanded_input_count": len(expected_rows),
        "terminal_artifact_count": len(terminal_denominator),
        "raw_cas_leaf_count": len(raw_denominator),
        "terminal_artifact_denominator_digest": hashlib.sha256(
            canonical_json_bytes(terminal_denominator)
        ).hexdigest(),
        "raw_cas_leaf_denominator_digest": hashlib.sha256(
            canonical_json_bytes(raw_denominator)
        ).hexdigest(),
    }


def authorize_b4_execution_capture_v1(
    *,
    manifest_expansion_state: str,
    independent_b3_review_state: str,
) -> dict[str, Any]:
    if manifest_expansion_state not in _MANIFEST_EXPANSION_ACCEPTED_STATES:
        raise ProgramFactsTypeError("B3 manifest expansion is not accepted")
    if independent_b3_review_state not in _INDEPENDENT_PASS_STATES:
        raise ProgramFactsTypeError("B3 independent review did not pass")
    return {"accepted": True, "checkpoint": "B4"}


def validate_manifest_expansion_reuse_v1(
    *,
    accepted_b3_semantics_digest: str,
    c2_observed_semantics_digest: str,
) -> dict[str, Any]:
    require_sha256(
        accepted_b3_semantics_digest,
        label="accepted B3 manifest-expansion digest",
    )
    require_sha256(
        c2_observed_semantics_digest,
        label="observed C2 manifest-expansion digest",
    )
    if accepted_b3_semantics_digest != c2_observed_semantics_digest:
        raise ProgramFactsTypeError("C2 redefined B3 manifest-expansion semantics")
    return {"accepted": True, "semantics_digest": accepted_b3_semantics_digest}


def validate_b4_evidence_authority_v1(
    *,
    b4_evidence: Mapping[str, Any],
    installed_manifest_expansion_semantics_digest: str,
) -> dict[str, Any]:
    if not isinstance(b4_evidence, Mapping):
        raise ProgramFactsTypeError("B4 evidence must be an object")
    captured = require_sha256(
        b4_evidence.get("manifest_expansion_semantics_digest"),
        label="B4 manifest-expansion digest",
    )
    installed = require_sha256(
        installed_manifest_expansion_semantics_digest,
        label="installed manifest-expansion digest",
    )
    if captured != installed:
        raise ProgramFactsTypeError("B4 evidence is stale after semantics drift")
    return {"accepted": True, "manifest_expansion_semantics_digest": installed}


__all__ = [
    "TERMINAL_ARTIFACT_ROLES",
    "authorize_b4_execution_capture_v1",
    "build_expected_wtx_children_v1",
    "build_terminal_wtx_roster_v1",
    "program_facts_phase_io_contracts_v1",
    "validate_b4_evidence_authority_v1",
    "validate_execution_set_capture_inputs_v1",
    "validate_expected_wtx_children_v1",
    "validate_frozen_build_plan_v1",
    "validate_manifest_expansion_reuse_v1",
    "validate_terminal_wtx_roster_v1",
]
