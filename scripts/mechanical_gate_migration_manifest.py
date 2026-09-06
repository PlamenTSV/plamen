"""Validate the non-authoritative mechanical-gate migration artifacts.

These artifacts are a migration worklist, never runtime authority.  The
validator deliberately rejects any attempt to turn the provisional files into
an activation baseline by self-assertion.  It also binds every observed
definition/callsite to the current Python AST and every cited source file to
exact bytes, so line drift becomes visible migration debt rather than a silent
mis-map.
"""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence
import unicodedata

from mechanical_gate_inventory import compute_source_tree_digest


REGISTRY_PATH = Path("rules/mechanical-gate-registry.provisional.v2.json")
INVENTORY_PATH = Path(
    "rules/mechanical-gate-activation-baseline.provisional.v1.json"
)
EDIT_MANIFEST_PATH = Path(
    "rules/mechanical-gate-migration-edits.provisional.v1.json"
)
SCHEMA_PATHS = (
    Path("rules/schemas/mechanical-gate-registry-provisional.schema.json"),
    Path(
        "rules/schemas/"
        "mechanical-gate-activation-baseline-provisional.schema.json"
    ),
    Path(
        "rules/schemas/"
        "mechanical-gate-migration-edits-provisional.schema.json"
    ),
)

SOURCE_TREE_ALGORITHM = "sha256:plamen-source-tree-v1"
PRODUCTION_ROOTS = ("scripts",)
PRODUCTION_EXCLUDES = ("scripts/conftest.py", "scripts/test_*.py")
PROVISIONAL_STATUS = "PROVISIONAL_UNWRAPPED_UNREVIEWED"
DIGEST_STABILITY = "REGENERATE_AT_TREE_FREEZE"

EXPECTED_GATE_IDS = (
    "supply_chain.pre_input_execution",
    "supply_chain.pre_poc_execution",
    "snapshot.startup_binding",
    "snapshot.interphase_drift",
    "enumeration.graph_health",
    "enumeration.coreference_obligation",
    "enumeration.coreference_gap",
    "enumeration.critical_asset_mover",
    "enumeration.array_uniqueness",
    "enumeration.unbounded_stored_input",
    "enumeration.variant_boundary",
    "enumeration.variant_symmetric",
    "enumeration.committed_invariant",
    "axis.hot_function_gap_matrix",
    "enumgap.exploration_delivery",
    "axis.finding_delivery",
    "promotion.orphan_reopen",
    "inventory.location_exists",
    "inventory.production_scope",
    "inventory.identifier_exists",
    "poc.force_by_default",
    "mechanical_poc.execute",
    "verdict.evidence_integrity",
    "external_assumption.assert_cap",
    "external_assumption.demotion_veto",
    "severity.independent_challenge",
    "external_research.citation_gap",
    "postverify.late_candidate_reopen",
    "report.index_retention_reconcile",
    "report.dedup_lossless_consolidation",
    "report.typed_disposition",
    "report.mandatory_reverification",
    "report.integrity_no_ship",
)
EXPECTED_FORENSIC_IDS = tuple(f"MG-{index:03d}" for index in range(1, 34))

_TOP_COMMON = frozenset(
    {
        "schema_version",
        "status",
        "runtime_authority_granted",
        "authoritative_registry",
        "source_snapshot",
        "independent_review_receipt_sha256",
    }
)
_SOURCE_SNAPSHOT_KEYS = frozenset(
    {
        "source_tree_digest_algorithm",
        "source_tree_digest",
        "digest_stability",
        "git_head",
        "files",
    }
)
_SOURCE_FILE_KEYS = frozenset({"path", "sha256"})
_REGISTRY_TOP = _TOP_COMMON | frozenset(
    {"scope", "gate_count", "gate_records"}
)
_REGISTRY_GATE_KEYS = frozenset(
    {
        "forensic_id",
        "gate_id",
        "display_name",
        "owning_seam",
        "decision_class",
        "direction",
        "candidate_lifecycle_state",
        "activation_ids",
        "component_owner",
        "system_owner",
        "independent_reviewer",
        "admission_evidence_receipt_sha256",
        "part0_status",
    }
)
_INVENTORY_TOP = _TOP_COMMON | frozenset(
    {"gate_count", "activation_count", "activations"}
)
_ACTIVATION_KEYS = frozenset(
    {
        "forensic_id",
        "gate_id",
        "activation_id",
        "owning_seam",
        "applicability",
        "definitions",
        "observed_callsites",
        "wrapper_target",
        "literal_runtime_registration_present",
    }
)
_APPLICABILITY_KEYS = frozenset(
    {
        "pipelines",
        "modes",
        "ecosystems",
        "backends",
        "phase_contexts",
        "status",
    }
)
_DEFINITION_KEYS = frozenset({"module", "symbol", "source_line"})
_CALLSITE_KEYS = frozenset(
    {"module", "enclosing_symbol", "call_symbol", "source_line"}
)
_WRAPPER_KEYS = frozenset({"module", "symbol", "strategy"})
_EDIT_TOP = _TOP_COMMON | frozenset(
    {"gate_count", "edit_entries", "cutover_invariants"}
)
_EDIT_KEYS = frozenset(
    {
        "forensic_id",
        "gate_id",
        "activation_id",
        "runtime_readiness",
        "edit_targets",
        "phase_io_binding",
        "migration_debt_codes",
        "existing_code_edit_authorized",
    }
)
_EDIT_TARGET_KEYS = frozenset(
    {"module", "symbol", "edit_kind", "source_lines"}
)
_PHASE_IO_KEYS = frozenset(
    {
        "status",
        "phase",
        "work_unit_id",
        "owner_key_binding",
        "input_artifact_identities",
        "output_artifact_identities",
    }
)


class MechanicalGateMigrationError(ValueError):
    """The provisional gate migration artifacts are unsafe or inconsistent."""


def _pairs(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MechanicalGateMigrationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_float=lambda _value: (_ for _ in ()).throw(
                MechanicalGateMigrationError("floats are forbidden")
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                MechanicalGateMigrationError("non-finite numbers are forbidden")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MechanicalGateMigrationError(
            f"cannot load provisional artifact: {path.as_posix()}"
        ) from exc
    if not isinstance(value, Mapping):
        raise MechanicalGateMigrationError("provisional artifact must be an object")
    return value


def _closed(value: Any, keys: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or frozenset(value) != keys:
        raise MechanicalGateMigrationError(f"{label} has a non-closed shape")
    return value


def _text(value: Any, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or unicodedata.normalize("NFC", value) != value
    ):
        raise MechanicalGateMigrationError(f"{label} is not canonical text")
    return value


def _sha(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    text = _text(value, label)
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        raise MechanicalGateMigrationError(f"{label} is not SHA-256")
    return text


def _git_oid(value: Any, label: str) -> str:
    text = _text(value, label)
    if len(text) not in {40, 64} or any(
        char not in "0123456789abcdef" for char in text
    ):
        raise MechanicalGateMigrationError(f"{label} is not a Git object ID")
    return text


def _canonical_path(value: Any, label: str) -> str:
    text = _text(value, label)
    pure = PurePosixPath(text)
    if (
        "\\" in text
        or ":" in text
        or text.startswith("/")
        or pure.as_posix() != text
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise MechanicalGateMigrationError(f"{label} is not a canonical path")
    return text


def _sorted_unique_text(
    value: Any, label: str, *, allow_empty: bool = False
) -> tuple[str, ...]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise MechanicalGateMigrationError(f"{label} must be an array")
    parsed = tuple(_text(item, label) for item in value)
    if parsed != tuple(sorted(set(parsed), key=lambda item: item.encode("utf-8"))):
        raise MechanicalGateMigrationError(f"{label} is not sorted and unique")
    return parsed


def _common(
    value: Mapping[str, Any],
    *,
    schema: str,
    expected_keys: frozenset[str],
) -> Mapping[str, str]:
    row = _closed(value, expected_keys, schema)
    if row["schema_version"] != schema:
        raise MechanicalGateMigrationError("provisional schema version mismatch")
    if row["status"] != PROVISIONAL_STATUS:
        raise MechanicalGateMigrationError("provisional status was self-promoted")
    if row["runtime_authority_granted"] is not False:
        raise MechanicalGateMigrationError(
            "provisional artifact cannot grant runtime authority"
        )
    if row["independent_review_receipt_sha256"] is not None:
        raise MechanicalGateMigrationError(
            "provisional artifact cannot self-assert independent review"
        )
    authoritative = _closed(
        row["authoritative_registry"],
        frozenset({"path", "sha256", "schema_version"}),
        "authoritative_registry",
    )
    if authoritative["path"] != "rules/mechanical-gate-registry.json":
        raise MechanicalGateMigrationError("wrong authoritative registry path")
    _sha(authoritative["sha256"], "authoritative_registry.sha256")
    if authoritative["schema_version"] != "plamen.mechanical_gate_registry.v1":
        raise MechanicalGateMigrationError(
            "provisional program must describe the honest v1 migration state"
        )
    source = _closed(
        row["source_snapshot"], _SOURCE_SNAPSHOT_KEYS, "source_snapshot"
    )
    if source["source_tree_digest_algorithm"] != SOURCE_TREE_ALGORITHM:
        raise MechanicalGateMigrationError("source-tree algorithm mismatch")
    _sha(source["source_tree_digest"], "source_snapshot.source_tree_digest")
    if source["digest_stability"] != DIGEST_STABILITY:
        raise MechanicalGateMigrationError(
            "provisional source digest must require regeneration at freeze"
        )
    _git_oid(source["git_head"], "source_snapshot.git_head")
    files = source["files"]
    if not isinstance(files, list) or not files:
        raise MechanicalGateMigrationError("source snapshot files are absent")
    paths: list[str] = []
    hashes: dict[str, str] = {}
    for index, candidate in enumerate(files):
        file_row = _closed(
            candidate, _SOURCE_FILE_KEYS, f"source_snapshot.files[{index}]"
        )
        path = _canonical_path(file_row["path"], "source file path")
        digest = _sha(file_row["sha256"], "source file sha256")
        assert digest is not None
        paths.append(path)
        hashes[path] = digest
    if paths != sorted(set(paths), key=lambda item: item.encode("utf-8")):
        raise MechanicalGateMigrationError(
            "source snapshot paths are not sorted and unique"
        )
    return hashes


def _parsed_ast(
    root: Path,
    module: str,
    cache: dict[
        str,
        tuple[
            frozenset[tuple[str, int]],
            frozenset[tuple[str, str, int]],
        ],
    ],
) -> tuple[
    frozenset[tuple[str, int]],
    frozenset[tuple[str, str, int]],
]:
    existing = cache.get(module)
    if existing is not None:
        return existing
    path = root / module
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise MechanicalGateMigrationError(
            f"cannot parse cited source module: {module}"
        ) from exc
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    definitions = frozenset(
        (node.name, node.lineno)
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )

    def enclosing(node: ast.AST) -> str:
        cursor = node
        while cursor in parents:
            cursor = parents[cursor]
            if isinstance(cursor, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return cursor.name
        return "<module>"

    calls: set[tuple[str, str, int]] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        leaf = (
            node.func.id
            if isinstance(node.func, ast.Name)
            else node.func.attr
            if isinstance(node.func, ast.Attribute)
            else ""
        )
        calls.add((enclosing(node), leaf, node.lineno))
    result = (definitions, frozenset(calls))
    cache[module] = result
    return result


def _node_at(
    root: Path,
    module: str,
    symbol: str,
    source_line: int,
    cache: dict[
        str,
        tuple[
            frozenset[tuple[str, int]],
            frozenset[tuple[str, str, int]],
        ],
    ],
) -> None:
    definitions, _calls = _parsed_ast(root, module, cache)
    if (symbol, source_line) in definitions:
        return
    raise MechanicalGateMigrationError(
        f"definition does not match current AST: {module}:{source_line} {symbol}"
    )


def _call_at(
    root: Path,
    module: str,
    enclosing_symbol: str,
    call_symbol: str,
    source_line: int,
    cache: dict[
        str,
        tuple[
            frozenset[tuple[str, int]],
            frozenset[tuple[str, str, int]],
        ],
    ],
) -> None:
    _definitions, calls = _parsed_ast(root, module, cache)
    if (enclosing_symbol, call_symbol, source_line) in calls:
        return
    raise MechanicalGateMigrationError(
        "callsite does not match current AST: "
        f"{module}:{source_line} {enclosing_symbol}->{call_symbol}"
    )


def _validate_source_snapshot(
    root: Path, hashes: Mapping[str, str], *, validate_source: bool
) -> None:
    if not validate_source:
        return
    for relative, expected in hashes.items():
        try:
            actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        except OSError as exc:
            raise MechanicalGateMigrationError(
                f"cited source file is unavailable: {relative}"
            ) from exc
        if actual != expected:
            raise MechanicalGateMigrationError(
                f"cited source file drifted: {relative}"
            )
    actual_tree = compute_source_tree_digest(
        root,
        production_roots=PRODUCTION_ROOTS,
        production_excludes=PRODUCTION_EXCLUDES,
    )
    # The three artifacts share the same source snapshot; callers compare the
    # value after common validation.
    if not actual_tree:
        raise MechanicalGateMigrationError("source-tree digest is absent")


def validate_provisional_program(
    root: Path | str,
    *,
    validate_source: bool = True,
    validate_tree_digest: bool = False,
) -> dict[str, Any]:
    root_path = Path(root).resolve(strict=True)
    registry = _load(root_path / REGISTRY_PATH)
    inventory = _load(root_path / INVENTORY_PATH)
    edits = _load(root_path / EDIT_MANIFEST_PATH)

    registry_hashes = _common(
        registry,
        schema="plamen.mechanical_gate_registry_candidate.provisional.v1",
        expected_keys=_REGISTRY_TOP,
    )
    inventory_hashes = _common(
        inventory,
        schema=(
            "plamen.mechanical_gate_activation_inventory_candidate."
            "provisional.v1"
        ),
        expected_keys=_INVENTORY_TOP,
    )
    edit_hashes = _common(
        edits,
        schema="plamen.mechanical_gate_migration_edits.provisional.v1",
        expected_keys=_EDIT_TOP,
    )
    if not (registry_hashes == inventory_hashes == edit_hashes):
        raise MechanicalGateMigrationError(
            "provisional artifacts cite different source snapshots"
        )
    snapshots = [
        value["source_snapshot"]["source_tree_digest"]
        for value in (registry, inventory, edits)
    ]
    if len(set(snapshots)) != 1:
        raise MechanicalGateMigrationError(
            "provisional artifacts cite different source-tree digests"
        )
    registry_refs = [
        json.dumps(value["authoritative_registry"], sort_keys=True)
        for value in (registry, inventory, edits)
    ]
    if len(set(registry_refs)) != 1:
        raise MechanicalGateMigrationError(
            "provisional artifacts cite different authoritative registries"
        )

    records = registry["gate_records"]
    activations = inventory["activations"]
    entries = edits["edit_entries"]
    if not all(isinstance(value, list) for value in (records, activations, entries)):
        raise MechanicalGateMigrationError("provisional rows must be arrays")
    if registry["gate_count"] != 33 or len(records) != 33:
        raise MechanicalGateMigrationError("registry candidate must contain 33 gates")
    if (
        inventory["gate_count"] != 33
        or inventory["activation_count"] != 33
        or len(activations) != 33
    ):
        raise MechanicalGateMigrationError(
            "activation candidate must contain one provisional row per gate"
        )
    if edits["gate_count"] != 33 or len(entries) != 33:
        raise MechanicalGateMigrationError("edit manifest must contain 33 gates")

    registry_ids: list[str] = []
    registry_forensic: list[str] = []
    activation_by_gate: dict[str, Mapping[str, Any]] = {}
    edit_by_gate: dict[str, Mapping[str, Any]] = {}
    ast_cache: dict[
        str,
        tuple[
            frozenset[tuple[str, int]],
            frozenset[tuple[str, str, int]],
        ],
    ] = {}

    for index, candidate in enumerate(records):
        row = _closed(candidate, _REGISTRY_GATE_KEYS, f"gate_records[{index}]")
        forensic_id = _text(row["forensic_id"], "forensic_id")
        gate_id = _text(row["gate_id"], "gate_id")
        registry_forensic.append(forensic_id)
        registry_ids.append(gate_id)
        if row["candidate_lifecycle_state"] != "LEGACY_ACTIVE_UNGOVERNED":
            raise MechanicalGateMigrationError(
                "provisional registry cannot promote legacy lifecycle state"
            )
        for key in (
            "component_owner",
            "system_owner",
            "independent_reviewer",
            "admission_evidence_receipt_sha256",
        ):
            if row[key] is not None:
                raise MechanicalGateMigrationError(
                    f"provisional registry invented {key}"
                )
        if row["part0_status"] != "PASS_GENERIC_METADATA_ONLY":
            raise MechanicalGateMigrationError("Part-0 status is not provisional")
        activation_ids = _sorted_unique_text(
            row["activation_ids"], f"{gate_id}.activation_ids"
        )
        if len(activation_ids) != 1:
            raise MechanicalGateMigrationError(
                "provisional slice requires one candidate wrapper per gate"
            )

    if tuple(registry_ids) != EXPECTED_GATE_IDS:
        raise MechanicalGateMigrationError("gate IDs/order differ from forensic baseline")
    if tuple(registry_forensic) != EXPECTED_FORENSIC_IDS:
        raise MechanicalGateMigrationError(
            "forensic IDs/order differ from the 33-gate baseline"
        )

    referenced_modules: set[str] = set()
    for index, candidate in enumerate(activations):
        row = _closed(candidate, _ACTIVATION_KEYS, f"activations[{index}]")
        gate_id = _text(row["gate_id"], "activation gate_id")
        if gate_id in activation_by_gate:
            raise MechanicalGateMigrationError("duplicate activation gate")
        activation_by_gate[gate_id] = row
        if row["forensic_id"] != EXPECTED_FORENSIC_IDS[index]:
            raise MechanicalGateMigrationError("activation forensic order mismatch")
        if row["literal_runtime_registration_present"] is not False:
            raise MechanicalGateMigrationError(
                "unwrapped legacy activation cannot claim literal registration"
            )
        applicability = _closed(
            row["applicability"], _APPLICABILITY_KEYS, "applicability"
        )
        for key in ("pipelines", "modes", "ecosystems", "backends", "phase_contexts"):
            _sorted_unique_text(applicability[key], f"applicability.{key}")
        if applicability["status"] not in {
            "FORENSIC_EXACT",
            "RUNTIME_SELECTOR_REQUIRES_CUTOVER_BINDING",
        }:
            raise MechanicalGateMigrationError("invalid applicability status")
        definitions = row["definitions"]
        callsites = row["observed_callsites"]
        if not isinstance(definitions, list) or not definitions:
            raise MechanicalGateMigrationError("definition set is absent")
        if not isinstance(callsites, list) or not callsites:
            raise MechanicalGateMigrationError("callsite set is absent")
        for def_index, raw in enumerate(definitions):
            definition = _closed(
                raw, _DEFINITION_KEYS, f"{gate_id}.definitions[{def_index}]"
            )
            module = _canonical_path(definition["module"], "definition.module")
            symbol = _text(definition["symbol"], "definition.symbol")
            line = definition["source_line"]
            if type(line) is not int or line < 1:
                raise MechanicalGateMigrationError("definition line is invalid")
            referenced_modules.add(module)
            if validate_source:
                _node_at(root_path, module, symbol, line, ast_cache)
        for call_index, raw in enumerate(callsites):
            callsite = _closed(
                raw, _CALLSITE_KEYS, f"{gate_id}.callsites[{call_index}]"
            )
            module = _canonical_path(callsite["module"], "callsite.module")
            enclosing_symbol = _text(
                callsite["enclosing_symbol"], "callsite.enclosing_symbol"
            )
            call_symbol = _text(callsite["call_symbol"], "callsite.call_symbol")
            line = callsite["source_line"]
            if type(line) is not int or line < 1:
                raise MechanicalGateMigrationError("callsite line is invalid")
            referenced_modules.add(module)
            if validate_source:
                _call_at(
                    root_path, module, enclosing_symbol, call_symbol, line
                    , ast_cache
                )
        wrapper = _closed(row["wrapper_target"], _WRAPPER_KEYS, "wrapper_target")
        referenced_modules.add(
            _canonical_path(wrapper["module"], "wrapper_target.module")
        )
        _text(wrapper["symbol"], "wrapper_target.symbol")
        if wrapper["strategy"] not in {
            "INLINE_AT_EXISTING_CALLSITE",
            "WRAP_EXISTING_SYMBOL_ENTRY",
            "SPLIT_SHARED_VALIDATOR_DECISIONS",
            "WRAP_EXISTING_DRIVER_TRANSACTION",
        }:
            raise MechanicalGateMigrationError("invalid wrapper strategy")

    for index, candidate in enumerate(entries):
        row = _closed(candidate, _EDIT_KEYS, f"edit_entries[{index}]")
        gate_id = _text(row["gate_id"], "edit gate_id")
        if gate_id in edit_by_gate:
            raise MechanicalGateMigrationError("duplicate edit gate")
        edit_by_gate[gate_id] = row
        if row["forensic_id"] != EXPECTED_FORENSIC_IDS[index]:
            raise MechanicalGateMigrationError("edit forensic order mismatch")
        if row["existing_code_edit_authorized"] is not False:
            raise MechanicalGateMigrationError(
                "provisional manifest cannot authorize existing-code edits"
            )
        if row["runtime_readiness"] not in {
            "NEEDS_GATE_RECEIPT_AND_WRAPPER",
            "SUCCESSOR_PHASEIO_EXISTS_NEEDS_GATE_BINDING",
            "SHARED_VALIDATOR_SPLIT_REQUIRED",
            "TARGET_EXECUTION_CIRCUIT_BREAKER_REQUIRED",
            "EXACT_PHASEIO_EXISTS_NEEDS_RUNTIME_WRAPPER",
            "MULTI_STAGE_AUTHORITY_NEEDS_SINGLE_GATE_RECEIPT",
        }:
            raise MechanicalGateMigrationError("invalid runtime readiness")
        targets = row["edit_targets"]
        if not isinstance(targets, list) or not targets:
            raise MechanicalGateMigrationError("edit targets are absent")
        for target_index, raw in enumerate(targets):
            target = _closed(
                raw, _EDIT_TARGET_KEYS, f"{gate_id}.edit_targets[{target_index}]"
            )
            module = _canonical_path(target["module"], "edit target module")
            referenced_modules.add(module)
            _text(target["symbol"], "edit target symbol")
            _text(target["edit_kind"], "edit target kind")
            lines = target["source_lines"]
            if (
                not isinstance(lines, list)
                or not lines
                or any(type(line) is not int or line < 1 for line in lines)
                or lines != sorted(set(lines))
            ):
                raise MechanicalGateMigrationError(
                    "edit target lines are not sorted unique positive integers"
                )
        phase_io = _closed(
            row["phase_io_binding"], _PHASE_IO_KEYS, "phase_io_binding"
        )
        if phase_io["status"] == "ABSENT_DEDICATED_CONTRACT":
            for key in ("phase", "work_unit_id", "owner_key_binding"):
                if phase_io[key] is not None:
                    raise MechanicalGateMigrationError(
                        "absent PhaseIO contract has invented identity"
                    )
            for key in ("input_artifact_identities", "output_artifact_identities"):
                if phase_io[key] != []:
                    raise MechanicalGateMigrationError(
                        "absent PhaseIO contract has invented artifacts"
                    )
        else:
            if phase_io["status"] not in {
                "EXACT_EXISTING_CONTRACT",
                "SUCCESSOR_CONTRACT_ONLY",
                "MULTIPLE_SUCCESSOR_CONTRACTS",
            }:
                raise MechanicalGateMigrationError("invalid PhaseIO status")
            _text(phase_io["phase"], "phase_io.phase")
            _text(phase_io["work_unit_id"], "phase_io.work_unit_id")
            if (
                phase_io["owner_key_binding"]
                != "phase_io_contracts.canonical_work_unit_key(runtime_context)"
            ):
                raise MechanicalGateMigrationError(
                    "PhaseIO owner must bind the exact runtime context"
                )
            for key in ("input_artifact_identities", "output_artifact_identities"):
                identities = _sorted_unique_text(
                    phase_io[key], f"phase_io.{key}", allow_empty=True
                )
                for identity in identities:
                    if not (
                        identity.startswith("scratchpad:")
                        or identity.startswith("project:")
                    ):
                        raise MechanicalGateMigrationError(
                            "PhaseIO artifact identity lacks a canonical root"
                        )
        debts = _sorted_unique_text(
            row["migration_debt_codes"], f"{gate_id}.migration_debt_codes"
        )
        if "LITERAL_RUNTIME_REGISTRATION_ABSENT" not in debts:
            raise MechanicalGateMigrationError(
                "every unwrapped legacy gate must retain literal-registration debt"
            )

    if tuple(activation_by_gate) != EXPECTED_GATE_IDS:
        raise MechanicalGateMigrationError("activation IDs/order mismatch")
    if tuple(edit_by_gate) != EXPECTED_GATE_IDS:
        raise MechanicalGateMigrationError("edit IDs/order mismatch")
    for record in records:
        gate_id = record["gate_id"]
        activation = activation_by_gate[gate_id]
        edit = edit_by_gate[gate_id]
        expected_activation = record["activation_ids"][0]
        if (
            activation["activation_id"] != expected_activation
            or edit["activation_id"] != expected_activation
            or edit["forensic_id"] != record["forensic_id"]
        ):
            raise MechanicalGateMigrationError(
                f"cross-artifact activation mismatch: {gate_id}"
            )

    if not referenced_modules.issubset(registry_hashes):
        missing = sorted(referenced_modules - set(registry_hashes))
        raise MechanicalGateMigrationError(
            "source snapshot omits referenced modules: " + ", ".join(missing)
        )
    _validate_source_snapshot(
        root_path, registry_hashes, validate_source=validate_source
    )
    if validate_source and validate_tree_digest:
        actual_tree = compute_source_tree_digest(
            root_path,
            production_roots=PRODUCTION_ROOTS,
            production_excludes=PRODUCTION_EXCLUDES,
        )
        if actual_tree != snapshots[0]:
            raise MechanicalGateMigrationError(
                "provisional source-tree digest drifted; regenerate at freeze"
            )
    invariants = _sorted_unique_text(
        edits["cutover_invariants"], "cutover_invariants"
    )
    required = {
        "NO_ACTIVE_BEFORE_INDEPENDENT_REVIEW",
        "NO_EXISTING_GATE_OR_DRIVER_EDIT_AUTHORIZED_BY_THIS_MANIFEST",
        "NO_RUNTIME_AUTHORITY_FROM_PROVISIONAL_ARTIFACTS",
        "REGENERATE_ALL_DIGESTS_AT_TREE_FREEZE",
    }
    if not required.issubset(invariants):
        raise MechanicalGateMigrationError("cutover invariants are incomplete")

    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    return {
        "valid": True,
        "gate_count": 33,
        "activation_count": 33,
        "source_tree_digest": snapshots[0],
        "artifact_sha256": {
            REGISTRY_PATH.as_posix(): digest(root_path / REGISTRY_PATH),
            INVENTORY_PATH.as_posix(): digest(root_path / INVENTORY_PATH),
            EDIT_MANIFEST_PATH.as_posix(): digest(root_path / EDIT_MANIFEST_PATH),
            **{
                path.as_posix(): digest(root_path / path)
                for path in SCHEMA_PATHS
            },
        },
    }


__all__ = [
    "DIGEST_STABILITY",
    "EDIT_MANIFEST_PATH",
    "EXPECTED_FORENSIC_IDS",
    "EXPECTED_GATE_IDS",
    "INVENTORY_PATH",
    "MechanicalGateMigrationError",
    "PROVISIONAL_STATUS",
    "REGISTRY_PATH",
    "SCHEMA_PATHS",
    "SOURCE_TREE_ALGORITHM",
    "validate_provisional_program",
]
