#!/usr/bin/env python3
"""Offline validator for the R2.5.6 model-routing GREEN-preparation package.

This validator is deliberately independent of the proposed production adapter.
It validates the current seven source seams, expands the frozen RED denominator,
and can execute a bounded fake-provider/native-Windows test selection.  It never
contacts a provider, runs an audit, or writes inside the repository.
"""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any, Iterable, Mapping

from jsonschema import Draft202012Validator


HERE = Path(__file__).resolve().parent
SCHEMA_PATH = HERE / "Plamen_Backend_Model_Routing_R2.5.6_GREEN_Prep_Schemas_2026-07-30.json"
REGISTRY_PATH = HERE / "Plamen_Backend_Model_Routing_R2.5.6_GREEN_Prep_Source_Registry_2026-07-30.json"
VECTORS_PATH = HERE / "Plamen_Backend_Model_Routing_R2.5.6_GREEN_Prep_RED_Vectors_2026-07-30.json"

EXPECTED_CONSUMERS = (
    "launch_replay_validator",
    "proof_mint",
    "spawn_authentication",
    "provider_spool_acceptance",
    "completed_current_construction",
    "current_replay_validator",
    "resume_authorization",
)
EXPECTED_DIRECT_CALLS = {
    "launch_replay_validator": (
        "_normalize_startup_authority_binding",
        "_normalize_claude_launch_contract",
        "_compile_claude_provider_parent_authority",
        "compile_worker_plan",
    ),
    "proof_mint": ("_promote_backend_capability_receipt",),
    "spawn_authentication": (
        "_validate_compiled_plan",
        "validate_work_plan_phase_roster",
        "_write_absent_json",
        "run_observed_worker",
    ),
    "provider_spool_acceptance": ("validate_completed_execution",),
    "completed_current_construction": (
        "_validate_arm",
        "_validate_attempt_completion",
        "validate_staged_execution",
        "validate_worker_execution_authority",
        "record_work_unit_artifacts",
    ),
    "current_replay_validator": (
        "_read_digest_bound_json",
        "_projection_destination",
        "_artifact_state",
    ),
    "resume_authorization": (
        "_resume_semantic_issues",
        "read_artifact_ledger",
        "_atomic_driver_json_record",
        "checkpoint.save",
    ),
}
EXPECTED_CALLERS = {
    "launch_replay_validator": ("headless_worker_runtime.execute_headless_worker",),
    "proof_mint": (),
    "spawn_authentication": (
        "headless_worker_runtime._execute_prepared_headless_worker",
        "program_facts_evm_wtx.execute_evm_worker_transaction",
    ),
    "provider_spool_acceptance": (
        "isolated_execution_host._execute_wer_provider_from_staged",
        "program_facts_evm_wtx.reconcile_evm_worker_execution",
        "worker_execution_receipts._replay_semantic_executor_completion",
        "worker_execution_receipts.staged_execution_stream_bytes",
        "worker_transaction.incorporate_worker_execution",
    ),
    "completed_current_construction": (
        "headless_worker_runtime._execute_prepared_headless_worker",
    ),
    "current_replay_validator": (
        "artifact_ledger._worker_execution_expected_records",
        "artifact_ledger._record_work_unit_artifacts_unlocked",
        "bb_wrapper_provider_adapter.replay_bb_provider_invocation",
        "worker_transaction.incorporate_worker_execution",
    ),
    "resume_authorization": ("plamen_driver.main",),
}
EXPECTED_ADAPTER_CALLABLES = {
    "launch_replay_validator": "validate_launch_replay",
    "proof_mint": "mint_capability_proof",
    "spawn_authentication": "authenticate_spawn",
    "provider_spool_acceptance": "accept_provider_spool",
    "completed_current_construction": "construct_completed_current",
    "current_replay_validator": "validate_current_replay",
    "resume_authorization": "authorize_resume",
}
EXPECTED_BRANCH_FIXTURES = (
    "DIRECT_SPAWN::PROVIDER_TERMINAL",
    "DIRECT_SPAWN::PROCESS_EXIT_NO_PROVIDER_FRAME",
    "DIRECT_SPAWN::TIMEOUT",
    "DIRECT_SPAWN::CANCELLED",
    "DIRECT_SPAWN::TRANSPORT_FAILURE",
    "DIRECT_SPAWN::EMPTY_PROVIDER_OUTPUT",
    "DIRECT_SPAWN::MALFORMED_PROVIDER_OUTPUT",
    "OBSERVED_SPAWN::PROVIDER_TERMINAL",
    "OBSERVED_SPAWN::PROCESS_EXIT_NO_PROVIDER_FRAME",
    "OBSERVED_SPAWN::TIMEOUT",
    "OBSERVED_SPAWN::CANCELLED",
    "OBSERVED_SPAWN::TRANSPORT_FAILURE",
    "OBSERVED_SPAWN::EMPTY_PROVIDER_OUTPUT",
    "OBSERVED_SPAWN::MALFORMED_PROVIDER_OUTPUT",
    "SPAWN_FAILED::SPAWN_FAILED",
    "AMBIGUITY_ABORT::AMBIGUITY_ABORTED_NOT_SPAWNED",
    "AMBIGUITY_DEBT::AMBIGUITY_UNRESOLVED_DEBT",
)
EXPECTED_REGISTRY_MUTATIONS = (
    "UNKNOWN_CONSUMER",
    "MISSING_CONSUMER",
    "DUPLICATE_CONSUMER",
    "REORDERED_CONSUMERS",
    "EXTRA_TOP_LEVEL_FIELD",
    "EXPECTED_ID_SET_DRIFT",
    "CORRUPT_REGISTRY_DIGEST",
    "RESEALED_UNKNOWN_CONSUMER",
)
EXPECTED_SOURCE_MUTATIONS = (
    "PATH_DRIFT",
    "FILE_HASH_DRIFT",
    "QUALNAME_DRIFT",
    "LINE_DRIFT",
    "END_LINE_DRIFT",
    "SIGNATURE_DRIFT",
    "SEGMENT_HASH_DRIFT",
    "DELETE_REQUIRED_CALL_EDGE",
    "KNOWN_CALLER_SET_DRIFT",
)
EXPECTED_MODEL_VECTORS = (
    "LEGACY_DEFAULT_BACKEND_IS_CLAUDE",
    "LIGHT_CLAUDE_ALL_SONNET",
    "CORE_CLAUDE_TIER_ALIAS_RESOLUTION",
    "THOROUGH_CLAUDE_PROMOTION_MATRIX",
    "CODEX_TIER_MAP_EXACT",
    "CODEX_THOROUGH_DOES_NOT_USE_CLAUDE_PROMOTION_BRANCH",
    "UNKNOWN_CODEX_ALIAS_CURRENTLY_DEFAULTS_TO_SONNET",
    "CODEX_UNAVAILABLE_MODEL_CURRENTLY_MUTATES_PHASE_FALLBACK",
    "BREADTH_OVERRIDE_CURRENTLY_ACCEPTS_ENV_OR_CONFIG",
    "SKEPTIC_BACKEND_OVERRIDE_CURRENTLY_FALLS_BACK",
    "MAX_IS_ABSENT_FROM_ALL_DEFAULT_PHASE_ROUTES",
    "CURRENT_LAUNCHSPEC_BINDS_BARE_BACKEND_AND_MODEL_ONLY",
)
EXPECTED_ORACLE_MUTATIONS = (
    "COLLAPSED_CRASH_REFERENCES",
    "REWRITTEN_CR06_SEMANTICS",
    "ARBITRARY_BRANCH_ROSTER",
    "ARBITRARY_MODEL_ROSTER",
    "DISCONNECTED_CONSUMER_SEMANTICS",
    "PRODUCTION_SOURCE_SCOPE_DRIFT",
    "DUPLICATE_JSON_KEY",
    "NONFINITE_JSON_NUMBER",
    "NESTED_CALL_EDGE_FALSE_POSITIVE",
)
EXPECTED_ADAPTER_CONTRACTS = {
    "launch_replay_validator": {
        "direction": "ENTRYPOINT_CALLS_ADAPTER",
        "pre_landmark": "PHASEIO_LAUNCH_AND_STARTUP_REPLAYED",
        "post_landmark": "COMMAND_AND_WORK_PLAN_CONSTRUCTION",
        "required_records": (
            "RoutingRootAuthorityV1", "ExecutionAttemptAuthorityV1",
            "SelectedRouteAuthorityV1", "LaunchEnvelopeV4",
            "PredecessorEnvelopeV3", "EnvironmentPolicyAuthorityV1",
            "PublicEnvironmentAuthorityV1",
        ),
        "families": (
            "DIRECT_SPAWN", "OBSERVED_SPAWN", "SPAWN_FAILED",
            "AMBIGUITY_ABORT", "AMBIGUITY_DEBT",
        ),
    },
    "proof_mint": {
        "direction": "ADAPTER_CALLS_ENTRYPOINT",
        "pre_landmark": "LAUNCH_AND_NEUTRAL_PROVIDER_OBSERVATION_REPLAYED",
        "post_landmark": "CONSUMED_LAUNCH_OR_SPAWN_INTENT_PUBLICATION",
        "required_records": (
            "RoutingRootAuthorityV1", "ExecutionAttemptAuthorityV1",
            "SelectedRouteAuthorityV1", "LaunchEnvelopeV4",
            "ProviderObservationAuthorityV1",
        ),
        "families": (
            "DIRECT_SPAWN", "OBSERVED_SPAWN", "SPAWN_FAILED",
            "AMBIGUITY_ABORT", "AMBIGUITY_DEBT",
        ),
    },
    "spawn_authentication": {
        "direction": "ENTRYPOINT_CALLS_ADAPTER",
        "pre_landmark": "PLAN_ADAPTER_AND_INPUT_REPLAYED",
        "post_landmark": "ATTEMPT_ARM_OR_PROCESS_CREATION",
        "required_records": (
            "ConsumedAttemptLaunchAuthorityV2", "SpawnIntentAuthorityV1",
            "SelectedRouteAuthorityV1", "LaunchEnvelopeV4",
            "PublicEnvironmentAuthorityV1",
        ),
        "families": (
            "DIRECT_SPAWN", "OBSERVED_SPAWN", "SPAWN_FAILED",
            "AMBIGUITY_ABORT", "AMBIGUITY_DEBT",
        ),
    },
    "provider_spool_acceptance": {
        "direction": "ENTRYPOINT_CALLS_ADAPTER",
        "pre_landmark": "IMMUTABLE_COMPLETED_EXECUTION_VALIDATED",
        "post_landmark": "STAGED_COMPLETION_TO_PHASEIO",
        "required_records": (
            "SpawnedAttemptAuthorityV1", "TerminalAttemptAuthorityV1",
            "ProviderArtifactAuthorityV1", "NeutralProviderClaimAuthorityV1",
            "NeutralLauncherClaimAuthorityV1",
            "NeutralReconciliationAuthorityV1",
        ),
        "families": ("DIRECT_SPAWN", "OBSERVED_SPAWN"),
    },
    "completed_current_construction": {
        "direction": "ENTRYPOINT_CALLS_ADAPTER",
        "pre_landmark": "STAGED_PROVIDER_AND_SEMANTIC_REPLAYED",
        "post_landmark": "PROJECTION_OR_CURRENT_PUBLICATION",
        "required_records": (
            "TerminalAttemptAuthorityV1", "NeutralReconciliationAuthorityV1",
            "CompletedCurrentAuthorityV1",
        ),
        "families": (
            "DIRECT_SPAWN", "OBSERVED_SPAWN", "SPAWN_FAILED",
            "AMBIGUITY_ABORT", "AMBIGUITY_DEBT",
        ),
    },
    "current_replay_validator": {
        "direction": "ENTRYPOINT_CALLS_ADAPTER",
        "pre_landmark": "STRUCTURAL_EXECUTION_AND_INCORPORATION_REPLAYED",
        "post_landmark": "CURRENT_AUTHORITY_RETURNED_TO_CONSUMER",
        "required_records": (
            "CompletedCurrentAuthorityV1", "TerminalAttemptAuthorityV1",
            "NeutralReconciliationAuthorityV1", "SelectedRouteAuthorityV1",
        ),
        "families": (
            "DIRECT_SPAWN", "OBSERVED_SPAWN", "SPAWN_FAILED",
            "AMBIGUITY_ABORT", "AMBIGUITY_DEBT",
        ),
    },
    "resume_authorization": {
        "direction": "ENTRYPOINT_CALLS_ADAPTER",
        "pre_landmark": "WORKER_TRANSACTION_RECOVERY_COMPLETE",
        "post_landmark": "COMPLETED_PHASE_ACCEPTANCE_OR_REWIND",
        "required_records": (
            "PriorResumeIdentityAuthorityV1", "CompletedCurrentAuthorityV1",
            "ExecutionAttemptAuthorityV1", "SelectedRouteAuthorityV1",
        ),
        "families": (
            "DIRECT_SPAWN", "OBSERVED_SPAWN", "SPAWN_FAILED",
            "AMBIGUITY_ABORT", "AMBIGUITY_DEBT",
        ),
    },
}
EXPECTED_CRASH_REFERENCES = {
    "launch_replay_validator": ("CR-01", "CR-02", "CR-03"),
    "proof_mint": ("CR-02", "CR-03", "CR-04"),
    "spawn_authentication": ("CR-04", "CR-05", "CR-06", "CR-07"),
    "provider_spool_acceptance": (
        "CR-06", "CR-07", "CR-08", "CR-09", "CR-10", "CR-11",
    ),
    "completed_current_construction": (
        "CR-11", "CR-12", "CR-13", "CR-14", "CR-15", "CR-16",
    ),
    "current_replay_validator": (
        "CR-12", "CR-13", "CR-14", "CR-15", "CR-16", "CR-17",
    ),
    "resume_authorization": ("CR-15", "CR-16", "CR-17", "CR-18"),
}
EXPECTED_CRASH_VECTORS = (
    ("CR-01", "BEFORE_LAUNCH_REPLAY", "launch_replay_validator", "NO_AUTHORITY", False),
    ("CR-02", "AFTER_LAUNCH_REPLAY_BEFORE_PROOF_MINT", "proof_mint", "NO_AUTHORITY", False),
    ("CR-03", "AFTER_PROOF_MINT_BEFORE_CONSUMED_LAUNCH", "proof_mint", "RETRY_NEW_GENERATION", False),
    ("CR-04", "AFTER_CONSUMED_LAUNCH_BEFORE_SPAWN_INTENT", "spawn_authentication", "RETRY_NEW_GENERATION", False),
    ("CR-05", "AFTER_SPAWN_INTENT_BEFORE_PROCESS_CREATE", "spawn_authentication", "AMBIGUITY_RESOLUTION_REQUIRED", False),
    ("CR-06", "PROCESS_CREATE_MAY_HAVE_RETURNED_BEFORE_SPAWN_AUTHORITY", "spawn_authentication", "AMBIGUITY_RESOLUTION_REQUIRED", True),
    ("CR-07", "AFTER_OBSERVED_SPAWN_BEFORE_SPAWN_AUTHORITY", "spawn_authentication", "RETRY_NEW_GENERATION", True),
    ("CR-08", "AFTER_SPAWN_AUTHORITY_BEFORE_PROVIDER_SPOOL", "provider_spool_acceptance", "TERMINAL_DEBT", True),
    ("CR-09", "AFTER_PROVIDER_SPOOL_BEFORE_TERMINAL_AUTHORITY", "provider_spool_acceptance", "TERMINAL_DEBT", True),
    ("CR-10", "AFTER_LAUNCHER_TERMINAL_BEFORE_TERMINAL_AUTHORITY", "provider_spool_acceptance", "TERMINAL_DEBT", True),
    ("CR-11", "AFTER_TERMINAL_AUTHORITY_BEFORE_RECONCILIATION", "completed_current_construction", "CURRENT_NOT_PUBLISHED", False),
    ("CR-12", "AFTER_RECONCILIATION_BEFORE_COMPLETED_CURRENT", "completed_current_construction", "CURRENT_NOT_PUBLISHED", False),
    ("CR-13", "AFTER_CURRENT_TEMP_FSYNC_BEFORE_REPLACE", "completed_current_construction", "CURRENT_NOT_PUBLISHED", False),
    ("CR-14", "AFTER_CURRENT_REPLACE_BEFORE_DIRECTORY_FSYNC", "current_replay_validator", "CURRENT_REPLAY_REQUIRED", False),
    ("CR-15", "AFTER_CURRENT_PUBLICATION_BEFORE_PHASEIO_ARM", "current_replay_validator", "CURRENT_REPLAY_REQUIRED", False),
    ("CR-16", "DURING_PHASEIO_OR_LEDGER_COMMIT", "current_replay_validator", "CURRENT_REPLAY_REQUIRED", False),
    ("CR-17", "AFTER_INCORPORATION_BEFORE_CHECKPOINT_SAVE", "resume_authorization", "CURRENT_REPLAY_REQUIRED", False),
    ("CR-18", "DURING_PRIOR_RESUME_REPLAY", "resume_authorization", "RESUME_REJECTED", False),
)
EXPECTED_SCOPE_INCLUDE = (
    "*.py", "scripts/**/*.py", "custom-mcp/**/*.py", "plamen_l1/**/*.py",
    "verification_policy/**/*.py", "mcp-packages/**/*.py",
)
EXPECTED_SCOPE_EXCLUDE = (
    "**/__pycache__/**", "**/test_*.py", "**/tests/**", "**/conftest.py",
)
EXPECTED_SCOPE_FILE_COUNT = 284
EXPECTED_SCOPE_MANIFEST_SHA256 = "5371ea308f20a6e7de7b19b16a18f8451725f451835fd7602d1696ed35d252c2"
EXPECTED_OPERATION_MANIFEST_SHA256 = "b81d9309e4aad862c5f18b2845ae34e536896c36a2eedd3fb482781772c8b625"
# Patched only after every normative candidate field above is frozen.
EXPECTED_REGISTRY_DIGEST = "95b487c0bd3b83b4b181be45c34cec3a1bdec9e34263d1f864e047cb6937d949"
MODEL_ENVIRONMENT_KEYS = (
    "PLAMEN_OPUS_MODEL",
    "PLAMEN_SONNET_MODEL",
    "PLAMEN_HAIKU_MODEL",
    "PLAMEN_THOROUGH_OPUS_MODEL",
    "PLAMEN_BREADTH_MODEL_OVERRIDE",
    "PLAMEN_CODEX_OPUS_MODEL",
    "PLAMEN_CODEX_SONNET_MODEL",
    "PLAMEN_CODEX_HAIKU_MODEL",
)


class ValidationError(RuntimeError):
    """Stable, classified validation failure."""

    def __init__(self, error_class: str, detail: str = "") -> None:
        super().__init__(f"{error_class}: {detail}" if detail else error_class)
        self.error_class = error_class


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _strict_json_loads(text: str) -> Any:
    def reject_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValidationError("JSON_DUPLICATE_KEY", key)
            value[key] = item
        return value

    def reject_constant(token: str) -> None:
        raise ValidationError("JSON_NONFINITE_NUMBER", token)

    return json.loads(
        text,
        object_pairs_hook=reject_pairs,
        parse_constant=reject_constant,
    )


def _read_json(path: Path) -> dict[str, Any]:
    value = _strict_json_loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValidationError("JSON_ROOT_NOT_OBJECT", path.name)
    return value


def _schema_validate(schema: Mapping[str, Any], value: Mapping[str, Any]) -> None:
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema).iter_errors(value),
        key=lambda item: tuple(str(part) for part in item.absolute_path),
    )
    if errors:
        first = errors[0]
        path = "/".join(str(part) for part in first.absolute_path)
        raise ValidationError("SCHEMA_REJECTED", f"{path}: {first.message}")


def _is_reparse_or_symlink(path: Path) -> bool:
    info = path.lstat()
    attrs = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(attrs & reparse)


def _safe_regular_file(root: Path, relative: str) -> Path:
    candidate = root / Path(relative)
    resolved_root = root.resolve(strict=True)
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise ValidationError("SOURCE_PATH_ESCAPE", relative) from exc
    if _is_reparse_or_symlink(candidate):
        raise ValidationError("SOURCE_REPARSE_OR_SYMLINK", relative)
    if not candidate.is_file():
        raise ValidationError("SOURCE_NOT_REGULAR_FILE", relative)
    return candidate


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
    )
    if completed.returncode != 0:
        raise ValidationError("GIT_QUERY_FAILED", " ".join(args))
    return completed.stdout.strip()


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _function_node(source: str, qualname: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    tree = ast.parse(source)
    matches = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == qualname
    ]
    if len(matches) != 1:
        raise ValidationError("SOURCE_QUALNAME_DRIFT", f"{qualname}: {len(matches)}")
    return matches[0]


def _normalized_signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    isolated = copy.deepcopy(node)
    isolated.body = [ast.Pass()]
    isolated.decorator_list = []
    header = ast.unparse(isolated).splitlines()[0]
    return header[:-1] if header.endswith(":") else header


def _direct_calls(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    calls: set[str] = set()

    class DirectCallVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, child: ast.FunctionDef) -> None:
            return

        def visit_AsyncFunctionDef(self, child: ast.AsyncFunctionDef) -> None:
            return

        def visit_Lambda(self, child: ast.Lambda) -> None:
            return

        def visit_Call(self, child: ast.Call) -> None:
            name = _call_name(child.func)
            if name:
                calls.add(name)
                calls.add(name.rsplit(".", 1)[-1])
            self.generic_visit(child)

    visitor = DirectCallVisitor()
    for statement in node.body:
        visitor.visit(statement)
    return calls


def _source_observations(root: Path, registry: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    observed: dict[str, dict[str, Any]] = {}
    for row in registry["consumers"]:
        consumer_id = row["consumer_id"]
        binding = row["source"]
        path = _safe_regular_file(root, binding["path"])
        raw = path.read_bytes()
        source = raw.decode("utf-8")
        node = _function_node(source, binding["qualname"])
        segment = ast.get_source_segment(source, node)
        if segment is None:
            raise ValidationError("SOURCE_SEGMENT_UNAVAILABLE", consumer_id)
        observed[consumer_id] = {
            "path": binding["path"],
            "file_sha256": _sha(raw),
            "size": len(raw),
            "qualname": node.name,
            "line": node.lineno,
            "end_line": node.end_lineno,
            "signature": _normalized_signature(node),
            "segment_sha256": _sha(segment.encode("utf-8")),
            "direct_calls": _direct_calls(node),
            "node": node,
        }
    return observed


def _production_source_manifest(root: Path) -> tuple[list[dict[str, Any]], list[Path]]:
    paths: set[Path] = set(root.glob("*.py"))
    for relative in (
        "scripts", "custom-mcp", "plamen_l1", "verification_policy",
        "mcp-packages",
    ):
        directory = root / relative
        if directory.exists():
            paths.update(directory.rglob("*.py"))
    rows: list[dict[str, Any]] = []
    included: list[Path] = []
    for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root)
        if any(part == "__pycache__" or part.startswith(".") for part in relative.parts):
            continue
        if (
            path.name.startswith("test_")
            or path.name == "conftest.py"
            or "tests" in relative.parts
        ):
            continue
        safe = _safe_regular_file(root, relative.as_posix())
        raw = safe.read_bytes()
        rows.append(
            {
                "path": relative.as_posix(),
                "sha256": _sha(raw),
                "size": len(raw),
            }
        )
        included.append(safe)
    return rows, included


def _module_label(root: Path, path: Path) -> str:
    relative = path.relative_to(root)
    if relative.parts[0] == "scripts" and len(relative.parts) == 2:
        return path.stem
    return ".".join(relative.with_suffix("").parts)


def _target_module_names(binding: Mapping[str, Any]) -> set[str]:
    path = Path(binding["path"]).with_suffix("")
    names = {".".join(path.parts), path.stem}
    if path.parts and path.parts[0] == "scripts":
        names.add(".".join(path.parts[1:]))
    return names


def _scan_callers(
    root: Path,
    registry: Mapping[str, Any],
    production_files: Iterable[Path],
) -> dict[str, tuple[str, ...]]:
    target_by_name = {
        row["source"]["qualname"]: {
            "consumer_id": row["consumer_id"],
            "path": row["source"]["path"],
            "modules": _target_module_names(row["source"]),
        }
        for row in registry["consumers"]
    }
    hits: dict[str, set[str]] = {name: set() for name in target_by_name}
    dynamic: list[str] = []

    for path in production_files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeDecodeError) as exc:
            raise ValidationError(
                "CALL_GRAPH_PARSE_FAILED", path.relative_to(root).as_posix()
            ) from exc
        module_imports: dict[str, str] = {}
        for statement in tree.body:
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    module_imports[
                        alias.asname or alias.name.split(".", 1)[0]
                    ] = alias.name
            elif isinstance(statement, ast.ImportFrom) and statement.module:
                for alias in statement.names:
                    module_imports[alias.asname or alias.name] = (
                        f"{statement.module}.{alias.name}"
                    )

        current_relative = path.relative_to(root).as_posix()
        import_stack: list[dict[str, str]] = [module_imports]

        def scoped_imports(
            statements: Iterable[ast.stmt],
            base: Mapping[str, str],
        ) -> dict[str, str]:
            bindings = dict(base)

            class ImportCollector(ast.NodeVisitor):
                def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                    return

                def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                    return

                def visit_Lambda(self, node: ast.Lambda) -> None:
                    return

                def visit_Import(self, node: ast.Import) -> None:
                    for alias in node.names:
                        bindings[
                            alias.asname or alias.name.split(".", 1)[0]
                        ] = alias.name

                def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
                    if not node.module:
                        return
                    for alias in node.names:
                        bindings[alias.asname or alias.name] = (
                            f"{node.module}.{alias.name}"
                        )

            collector = ImportCollector()
            for statement in statements:
                collector.visit(statement)
            return bindings

        def resolve(symbol: ast.AST) -> tuple[str | None, bool]:
            text = _call_name(symbol)
            if not text:
                return None, False
            parts = text.split(".")
            final = parts[-1]
            if final not in target_by_name:
                return None, False
            target = target_by_name[final]
            imports = import_stack[-1]
            if len(parts) == 1:
                imported = imports.get(final, "")
                if imported:
                    module, _, imported_name = imported.rpartition(".")
                    if imported_name == final and module in target["modules"]:
                        return final, False
                if current_relative == target["path"]:
                    return final, False
                return None, True
            base = ".".join(parts[:-1])
            imported_module = imports.get(parts[0], parts[0])
            if len(parts) > 2:
                imported_module = ".".join([imported_module, *parts[1:-1]])
            if imported_module in target["modules"] or base in target["modules"]:
                return final, False
            return None, True

        stack: list[str] = []

        class CallerVisitor(ast.NodeVisitor):
            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                stack.append(node.name)
                import_stack.append(scoped_imports(node.body, import_stack[-1]))
                for statement in node.body:
                    self.visit(statement)
                import_stack.pop()
                stack.pop()

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                stack.append(node.name)
                import_stack.append(scoped_imports(node.body, import_stack[-1]))
                for statement in node.body:
                    self.visit(statement)
                import_stack.pop()
                stack.pop()

            def visit_Lambda(self, node: ast.Lambda) -> None:
                stack.append("<lambda>")
                self.visit(node.body)
                stack.pop()

            def visit_Call(self, node: ast.Call) -> None:
                resolved, ambiguous = resolve(node.func)
                if ambiguous:
                    raise ValidationError(
                        "CALL_GRAPH_AMBIGUOUS_SYMBOL",
                        f"{current_relative}:{getattr(node, 'lineno', 0)}:{_call_name(node.func)}",
                    )
                if resolved and stack:
                    hits[resolved].add(f"{_module_label(root, path)}.{stack[-1]}")
                for argument in node.args:
                    self.visit(argument)
                for keyword in node.keywords:
                    self.visit(keyword.value)

            def visit_Name(self, node: ast.Name) -> None:
                if not isinstance(node.ctx, ast.Load):
                    return
                resolved, ambiguous = resolve(node)
                if ambiguous:
                    raise ValidationError(
                        "CALL_GRAPH_AMBIGUOUS_REFERENCE",
                        f"{current_relative}:{node.lineno}:{node.id}",
                    )
                if resolved:
                    dynamic.append(
                        f"{current_relative}:{node.lineno}:{resolved}"
                    )

            def visit_Attribute(self, node: ast.Attribute) -> None:
                resolved, ambiguous = resolve(node)
                if ambiguous:
                    raise ValidationError(
                        "CALL_GRAPH_AMBIGUOUS_REFERENCE",
                        f"{current_relative}:{node.lineno}:{_call_name(node)}",
                    )
                if resolved:
                    dynamic.append(
                        f"{current_relative}:{node.lineno}:{resolved}"
                    )
                else:
                    self.generic_visit(node)

        CallerVisitor().visit(tree)
    if dynamic:
        raise ValidationError("DYNAMIC_TARGET_REFERENCE_UNDECLARED", repr(dynamic[:8]))
    return {target: tuple(sorted(values)) for target, values in hits.items()}


def _unsigned_registry(registry: Mapping[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(dict(registry))
    value.pop("registry_digest", None)
    return value


def _validate_registry_closed(
    schema: Mapping[str, Any],
    registry: Mapping[str, Any],
    *,
    root: Path,
    observations: Mapping[str, Mapping[str, Any]],
    callers: Mapping[str, tuple[str, ...]],
    validate_digest: bool = True,
) -> None:
    _schema_validate(schema, registry)
    ids = tuple(registry["expected_consumer_ids"])
    row_ids = tuple(row["consumer_id"] for row in registry["consumers"])
    if ids != EXPECTED_CONSUMERS:
        raise ValidationError("EXPECTED_CONSUMER_ROSTER_DRIFT", repr(ids))
    if row_ids != EXPECTED_CONSUMERS:
        raise ValidationError("CONSUMER_ROW_ORDER_OR_SET_DRIFT", repr(row_ids))
    if len(set(row_ids)) != len(row_ids):
        raise ValidationError("DUPLICATE_CONSUMER", repr(row_ids))
    if validate_digest:
        actual = _sha(_canonical(_unsigned_registry(registry)))
        if registry["registry_digest"] != actual:
            raise ValidationError("REGISTRY_DIGEST_MISMATCH", actual)

    scope = registry["production_source_scope"]
    if tuple(scope["include_patterns"]) != EXPECTED_SCOPE_INCLUDE:
        raise ValidationError("PRODUCTION_SOURCE_INCLUDE_POLICY_DRIFT")
    if tuple(scope["exclude_patterns"]) != EXPECTED_SCOPE_EXCLUDE:
        raise ValidationError("PRODUCTION_SOURCE_EXCLUDE_POLICY_DRIFT")
    if (
        scope["file_count"] != EXPECTED_SCOPE_FILE_COUNT
        or scope["manifest_sha256"] != EXPECTED_SCOPE_MANIFEST_SHA256
    ):
        raise ValidationError("PRODUCTION_SOURCE_SCOPE_DECLARATION_DRIFT")

    source_files = {item["path"]: item for item in registry["source_files"]}
    if len(source_files) != len(registry["source_files"]):
        raise ValidationError("DUPLICATE_SOURCE_FILE_ROW")
    for relative, item in source_files.items():
        path = _safe_regular_file(root, relative)
        raw = path.read_bytes()
        if item["sha256"] != _sha(raw) or item["size"] != len(raw):
            raise ValidationError("SOURCE_FILE_SNAPSHOT_DRIFT", relative)

    for row in registry["consumers"]:
        cid = row["consumer_id"]
        binding = row["source"]
        observed = observations.get(cid)
        if observed is None:
            raise ValidationError("SOURCE_OBSERVATION_MISSING", cid)
        for field in (
            "path",
            "file_sha256",
            "qualname",
            "line",
            "end_line",
            "signature",
            "segment_sha256",
        ):
            if binding[field] != observed[field]:
                raise ValidationError(f"SOURCE_{field.upper()}_DRIFT", cid)
        expected_calls = EXPECTED_DIRECT_CALLS[cid]
        if tuple(binding["required_direct_calls"]) != expected_calls:
            raise ValidationError("REQUIRED_CALL_DENOMINATOR_DRIFT", cid)
        missing = [name for name in expected_calls if name not in observed["direct_calls"]]
        if missing:
            raise ValidationError("REQUIRED_SOURCE_CALL_EDGE_MISSING", f"{cid}: {missing}")
        if tuple(binding["known_callers"]) != EXPECTED_CALLERS[cid]:
            raise ValidationError("KNOWN_CALLER_DENOMINATOR_DRIFT", cid)
        source_callers = callers[binding["qualname"]]
        if source_callers != tuple(sorted(EXPECTED_CALLERS[cid])):
            raise ValidationError("KNOWN_CALLER_SET_DRIFT", f"{cid}: {source_callers}")
        adapter = row["adapter_binding"]
        if adapter["callable"] != EXPECTED_ADAPTER_CALLABLES[cid]:
            raise ValidationError("ADAPTER_CALLABLE_DRIFT", cid)
        contract = EXPECTED_ADAPTER_CONTRACTS[cid]
        for field in ("direction", "pre_landmark", "post_landmark"):
            if adapter[field] != contract[field]:
                raise ValidationError(f"ADAPTER_{field.upper()}_DRIFT", cid)
        if tuple(adapter["required_records"]) != contract["required_records"]:
            raise ValidationError("ADAPTER_REQUIRED_RECORDS_DRIFT", cid)
        if tuple(row["applicable_branch_families"]) != contract["families"]:
            raise ValidationError("APPLICABILITY_CONTRACT_DRIFT", cid)
        if tuple(row["crash_vector_ids"]) != EXPECTED_CRASH_REFERENCES[cid]:
            raise ValidationError("CRASH_REFERENCE_MAP_DRIFT", cid)
        if adapter["red_state"] != "ADAPTER_BINDING_ABSENT":
            raise ValidationError("UNEXPECTED_GREEN_CLAIM", cid)
        node_calls = observed["direct_calls"]
        if adapter["callable"] in node_calls:
            raise ValidationError("UNDECLARED_PRODUCTION_BINDING_PRESENT", cid)
    if validate_digest and registry["registry_digest"] != EXPECTED_REGISTRY_DIGEST:
        raise ValidationError(
            "REGISTRY_NORMATIVE_DIGEST_DRIFT", registry["registry_digest"]
        )


def _phase_matrix(root: Path) -> tuple[list[dict[str, str]], str]:
    present = [key for key in MODEL_ENVIRONMENT_KEYS if os.environ.get(key)]
    if present:
        raise ValidationError("MODEL_ENVIRONMENT_OVERRIDE_PRESENT", ",".join(present))
    scripts = str(root / "scripts")
    sys.path.insert(0, scripts)
    try:
        sys.modules.pop("plamen_types", None)
        types = importlib.import_module("plamen_types")
    finally:
        if sys.path and sys.path[0] == scripts:
            sys.path.pop(0)
    rows: list[dict[str, str]] = []
    for pipeline, phases in (("sc", types.SC_PHASES), ("l1", types.L1_PHASES)):
        for mode in ("light", "core", "thorough"):
            for backend in ("claude", "codex"):
                config = {"pipeline": pipeline, "cli_backend": backend}
                for index, phase in enumerate(phases):
                    if mode not in phase.modes:
                        continue
                    rows.append(
                        {
                            "pipeline": pipeline,
                            "mode": mode,
                            "backend": backend,
                            "phase_index": str(index),
                            "phase": phase.name,
                            "declared_tier": phase.model,
                            "effective_model": types.phase_model(phase, mode, config),
                        }
                    )
    return rows, _sha(_canonical(rows))


def _operations(registry: Mapping[str, Any], vectors: Mapping[str, Any]) -> list[dict[str, str]]:
    operations: list[dict[str, str]] = []
    branches = vectors["branch_fixtures"]
    counts = vectors["consumer_branch_counts"]
    rows = {row["consumer_id"]: row for row in registry["consumers"]}
    for cid in EXPECTED_CONSUMERS:
        families = set(rows[cid]["applicable_branch_families"])
        applicable = [
            branch for branch in branches
            if branch.split("::", 1)[0] in families
        ]
        if len(applicable) != counts[cid]:
            raise ValidationError("CONSUMER_BRANCH_COUNT_DRIFT", cid)
        for branch in applicable:
            operations.append(
                {
                    "operation_id": f"BIND::{cid}::{branch}",
                    "expected": "MODEL_ROUTING_PRODUCTION_BINDING_MISSING",
                }
            )
    for cid in EXPECTED_CONSUMERS:
        for mutation in vectors["source_row_mutations"]:
            operations.append(
                {
                    "operation_id": f"SOURCE::{cid}::{mutation}",
                    "expected": "SOURCE_BINDING_REJECTED",
                }
            )
    for mutation in vectors["registry_mutations"]:
        operations.append(
            {
                "operation_id": f"REGISTRY::{mutation}",
                "expected": "REGISTRY_REJECTED",
            }
        )
    for vector in vectors["crash_vectors"]:
        operations.append(
            {
                "operation_id": f"CRASH::{vector['vector_id']}",
                "expected": vector["expected_state"],
            }
        )
    for vector in vectors["model_behavior_vectors"]:
        operations.append(
            {
                "operation_id": f"MODEL::{vector}",
                "expected": "CURRENT_BEHAVIOR_PINNED",
            }
        )
    return sorted(operations, key=lambda item: item["operation_id"])


def _validate_vector_denominator(vectors: Mapping[str, Any]) -> None:
    if tuple(vectors["branch_fixtures"]) != EXPECTED_BRANCH_FIXTURES:
        raise ValidationError("BRANCH_ROSTER_DRIFT")
    if tuple(vectors["registry_mutations"]) != EXPECTED_REGISTRY_MUTATIONS:
        raise ValidationError("REGISTRY_MUTATION_ROSTER_DRIFT")
    if tuple(vectors["source_row_mutations"]) != EXPECTED_SOURCE_MUTATIONS:
        raise ValidationError("SOURCE_MUTATION_ROSTER_DRIFT")
    if tuple(vectors["model_behavior_vectors"]) != EXPECTED_MODEL_VECTORS:
        raise ValidationError("MODEL_VECTOR_ROSTER_DRIFT")
    if tuple(vectors["oracle_blocker_mutations"]) != EXPECTED_ORACLE_MUTATIONS:
        raise ValidationError("ORACLE_MUTATION_ROSTER_DRIFT")
    expected_counts = {
        cid: sum(
            branch.split("::", 1)[0]
            in set(EXPECTED_ADAPTER_CONTRACTS[cid]["families"])
            for branch in EXPECTED_BRANCH_FIXTURES
        )
        for cid in EXPECTED_CONSUMERS
    }
    if vectors["consumer_branch_counts"] != expected_counts:
        raise ValidationError("CONSUMER_BRANCH_COUNT_TABLE_DRIFT")


def _reseal(registry: dict[str, Any]) -> None:
    registry["registry_digest"] = _sha(_canonical(_unsigned_registry(registry)))


def _expect_reject(
    candidate: dict[str, Any],
    *,
    schema: Mapping[str, Any],
    root: Path,
    observations: Mapping[str, Mapping[str, Any]],
    callers: Mapping[str, tuple[str, ...]],
    expected_error: str,
) -> None:
    try:
        _validate_registry_closed(
            schema,
            candidate,
            root=root,
            observations=observations,
            callers=callers,
        )
    except ValidationError as exc:
        if exc.error_class != expected_error:
            raise ValidationError(
                "MUTATION_WRONG_ERROR_CLASS",
                f"expected={expected_error};actual={exc.error_class}",
            ) from exc
        return
    raise ValidationError("MUTATION_UNEXPECTEDLY_ACCEPTED")


def _run_mutation_probes(
    *,
    schema: Mapping[str, Any],
    registry: Mapping[str, Any],
    vectors: Mapping[str, Any],
    root: Path,
    observations: Mapping[str, Mapping[str, Any]],
    callers: Mapping[str, tuple[str, ...]],
) -> int:
    count = 0
    registry_errors = {
        "UNKNOWN_CONSUMER": "SCHEMA_REJECTED",
        "MISSING_CONSUMER": "SCHEMA_REJECTED",
        "DUPLICATE_CONSUMER": "CONSUMER_ROW_ORDER_OR_SET_DRIFT",
        "REORDERED_CONSUMERS": "CONSUMER_ROW_ORDER_OR_SET_DRIFT",
        "EXTRA_TOP_LEVEL_FIELD": "SCHEMA_REJECTED",
        "EXPECTED_ID_SET_DRIFT": "SCHEMA_REJECTED",
        "CORRUPT_REGISTRY_DIGEST": "REGISTRY_DIGEST_MISMATCH",
        "RESEALED_UNKNOWN_CONSUMER": "SCHEMA_REJECTED",
    }
    for mutation in vectors["registry_mutations"]:
        candidate = copy.deepcopy(dict(registry))
        if mutation == "UNKNOWN_CONSUMER":
            candidate["consumers"][0]["consumer_id"] = "unknown_consumer"
        elif mutation == "MISSING_CONSUMER":
            candidate["consumers"].pop()
        elif mutation == "DUPLICATE_CONSUMER":
            candidate["consumers"][-1] = copy.deepcopy(candidate["consumers"][0])
        elif mutation == "REORDERED_CONSUMERS":
            candidate["consumers"][0], candidate["consumers"][1] = (
                candidate["consumers"][1],
                candidate["consumers"][0],
            )
        elif mutation == "EXTRA_TOP_LEVEL_FIELD":
            candidate["unexpected"] = True
        elif mutation == "EXPECTED_ID_SET_DRIFT":
            candidate["expected_consumer_ids"][-1] = candidate["expected_consumer_ids"][0]
        elif mutation == "CORRUPT_REGISTRY_DIGEST":
            candidate["registry_digest"] = "f" * 64
            _expect_reject(
                candidate, schema=schema, root=root,
                observations=observations, callers=callers,
                expected_error=registry_errors[mutation],
            )
            count += 1
            continue
        elif mutation == "RESEALED_UNKNOWN_CONSUMER":
            candidate["consumers"][0]["consumer_id"] = "unknown_consumer"
        else:
            raise ValidationError("UNKNOWN_REGISTRY_MUTATION", mutation)
        _reseal(candidate)
        _expect_reject(
            candidate, schema=schema, root=root,
            observations=observations, callers=callers,
            expected_error=registry_errors[mutation],
        )
        count += 1

    field_by_mutation = {
        "PATH_DRIFT": "path",
        "FILE_HASH_DRIFT": "file_sha256",
        "QUALNAME_DRIFT": "qualname",
        "LINE_DRIFT": "line",
        "END_LINE_DRIFT": "end_line",
        "SIGNATURE_DRIFT": "signature",
        "SEGMENT_HASH_DRIFT": "segment_sha256",
        "DELETE_REQUIRED_CALL_EDGE": "required_direct_calls",
        "KNOWN_CALLER_SET_DRIFT": "known_callers",
    }
    source_errors = {
        "PATH_DRIFT": "SOURCE_PATH_DRIFT",
        "FILE_HASH_DRIFT": "SOURCE_FILE_SHA256_DRIFT",
        "QUALNAME_DRIFT": "SOURCE_QUALNAME_DRIFT",
        "LINE_DRIFT": "SOURCE_LINE_DRIFT",
        "END_LINE_DRIFT": "SOURCE_END_LINE_DRIFT",
        "SIGNATURE_DRIFT": "SOURCE_SIGNATURE_DRIFT",
        "SEGMENT_HASH_DRIFT": "SOURCE_SEGMENT_SHA256_DRIFT",
        "DELETE_REQUIRED_CALL_EDGE": "REQUIRED_CALL_DENOMINATOR_DRIFT",
        "KNOWN_CALLER_SET_DRIFT": "KNOWN_CALLER_DENOMINATOR_DRIFT",
    }
    for row_index, cid in enumerate(EXPECTED_CONSUMERS):
        for mutation in vectors["source_row_mutations"]:
            candidate = copy.deepcopy(dict(registry))
            source = candidate["consumers"][row_index]["source"]
            field = field_by_mutation[mutation]
            if field == "path":
                source[field] = "scripts/plamen_types.py"
            elif field in {"file_sha256", "segment_sha256"}:
                source[field] = "f" * 64
            elif field == "qualname":
                source[field] = f"{source[field]}_drift"
            elif field in {"line", "end_line"}:
                source[field] += 1
            elif field == "signature":
                source[field] += " "
            elif field == "required_direct_calls":
                source[field] = source[field][1:]
            elif field == "known_callers":
                source[field] = list(source[field]) + ["drift.fake_caller"]
            _reseal(candidate)
            expected_error = source_errors[mutation]
            if (
                mutation == "DELETE_REQUIRED_CALL_EDGE"
                and len(registry["consumers"][row_index]["source"]["required_direct_calls"]) == 1
            ):
                expected_error = "SCHEMA_REJECTED"
            _expect_reject(
                candidate, schema=schema, root=root,
                observations=observations, callers=callers,
                expected_error=expected_error,
            )
            count += 1
    if count != 71:
        raise ValidationError("MUTATION_PROBE_COUNT_DRIFT", str(count))
    return count


def _expect_vector_reject(
    candidate: Mapping[str, Any],
    *,
    expected_error: str,
    registry: Mapping[str, Any],
) -> None:
    try:
        _validate_vector_denominator(candidate)
        _validate_crash_vectors(registry, candidate)
    except ValidationError as exc:
        if exc.error_class != expected_error:
            raise ValidationError(
                "ORACLE_MUTATION_WRONG_ERROR_CLASS",
                f"expected={expected_error};actual={exc.error_class}",
            ) from exc
        return
    raise ValidationError("ORACLE_MUTATION_UNEXPECTEDLY_ACCEPTED")


def _run_oracle_blocker_probes(
    *,
    schema: Mapping[str, Any],
    registry: Mapping[str, Any],
    vectors: Mapping[str, Any],
    root: Path,
    observations: Mapping[str, Mapping[str, Any]],
    callers: Mapping[str, tuple[str, ...]],
) -> int:
    if tuple(vectors["oracle_blocker_mutations"]) != EXPECTED_ORACLE_MUTATIONS:
        raise ValidationError("ORACLE_MUTATION_ROSTER_DRIFT")
    count = 0

    collapsed = copy.deepcopy(dict(registry))
    for row in collapsed["consumers"]:
        row["crash_vector_ids"] = ["CR-01"]
    _reseal(collapsed)
    _expect_reject(
        collapsed, schema=schema, root=root, observations=observations,
        callers=callers, expected_error="CRASH_REFERENCE_MAP_DRIFT",
    )
    count += 1

    rewritten_crash = copy.deepcopy(dict(vectors))
    cr06 = rewritten_crash["crash_vectors"][5]
    cr06.update(
        {
            "cutpoint_id": "ARBITRARY_VALID_CUTPOINT",
            "cutpoint": "arbitrary valid cutpoint",
            "consumer": "resume_authorization",
            "expected_state": "NO_AUTHORITY",
            "may_spawn": False,
        }
    )
    _expect_vector_reject(
        rewritten_crash,
        expected_error="CRASH_VECTOR_SEMANTICS_DRIFT",
        registry=registry,
    )
    count += 1

    arbitrary_branches = copy.deepcopy(dict(vectors))
    arbitrary_branches["branch_fixtures"] = [
        *[f"DIRECT_SPAWN::ARBITRARY_{index:02d}" for index in range(7)],
        *[f"OBSERVED_SPAWN::ARBITRARY_{index:02d}" for index in range(7)],
        "SPAWN_FAILED::ARBITRARY_A",
        "AMBIGUITY_ABORT::ARBITRARY_B",
        "AMBIGUITY_DEBT::ARBITRARY_C",
    ]
    _expect_vector_reject(
        arbitrary_branches,
        expected_error="BRANCH_ROSTER_DRIFT",
        registry=registry,
    )
    count += 1

    arbitrary_models = copy.deepcopy(dict(vectors))
    arbitrary_models["model_behavior_vectors"] = [
        f"ARBITRARY_MODEL_VECTOR_{index:02d}" for index in range(12)
    ]
    _expect_vector_reject(
        arbitrary_models,
        expected_error="MODEL_VECTOR_ROSTER_DRIFT",
        registry=registry,
    )
    count += 1

    provider_index = EXPECTED_CONSUMERS.index("provider_spool_acceptance")
    semantic_mutations = (
        ("applicable_branch_families", ["SPAWN_FAILED"], "APPLICABILITY_CONTRACT_DRIFT"),
        (
            "required_records",
            ["BogusAuthorityV99"],
            "ADAPTER_REQUIRED_RECORDS_DRIFT",
        ),
        ("pre_landmark", "ARBITRARY_PRE", "ADAPTER_PRE_LANDMARK_DRIFT"),
    )
    for field, value, expected_error in semantic_mutations:
        disconnected = copy.deepcopy(dict(registry))
        row = disconnected["consumers"][provider_index]
        if field == "applicable_branch_families":
            row[field] = value
        else:
            row["adapter_binding"][field] = value
        _reseal(disconnected)
        _expect_reject(
            disconnected, schema=schema, root=root, observations=observations,
            callers=callers, expected_error=expected_error,
        )
        count += 1

    scope_drift = copy.deepcopy(dict(registry))
    scope_drift["production_source_scope"]["file_count"] -= 1
    _reseal(scope_drift)
    _expect_reject(
        scope_drift, schema=schema, root=root, observations=observations,
        callers=callers,
        expected_error="PRODUCTION_SOURCE_SCOPE_DECLARATION_DRIFT",
    )
    count += 1

    try:
        _strict_json_loads('{"outer":{"key":1,"key":2}}')
    except ValidationError as exc:
        if exc.error_class != "JSON_DUPLICATE_KEY":
            raise
    else:
        raise ValidationError("DUPLICATE_JSON_MUTATION_ACCEPTED")
    count += 1

    try:
        _strict_json_loads('{"value":NaN}')
    except ValidationError as exc:
        if exc.error_class != "JSON_NONFINITE_NUMBER":
            raise
    else:
        raise ValidationError("NONFINITE_JSON_MUTATION_ACCEPTED")
    count += 1

    synthetic = ast.parse(
        "def outer():\n"
        "    def never_called():\n"
        "        validate_launch_replay()\n"
        "    return 1\n"
    ).body[0]
    if "validate_launch_replay" in _direct_calls(synthetic):
        raise ValidationError("NESTED_CALL_EDGE_FALSE_POSITIVE")
    count += 1
    if count != 11:
        raise ValidationError("ORACLE_MUTATION_COUNT_DRIFT", str(count))
    return count


def _validate_crash_vectors(
    registry: Mapping[str, Any], vectors: Mapping[str, Any]
) -> None:
    crash = vectors["crash_vectors"]
    semantics = tuple(
        (
            item["vector_id"],
            item["cutpoint_id"],
            item["consumer"],
            item["expected_state"],
            item["may_spawn"],
        )
        for item in crash
    )
    if semantics != EXPECTED_CRASH_VECTORS:
        raise ValidationError("CRASH_VECTOR_SEMANTICS_DRIFT", repr(semantics))
    by_id = {item["vector_id"]: item for item in crash}
    for row in registry["consumers"]:
        cid = row["consumer_id"]
        references = tuple(row["crash_vector_ids"])
        if references != EXPECTED_CRASH_REFERENCES[cid]:
            raise ValidationError("CRASH_REFERENCE_MAP_DRIFT", cid)
        for vector_id in references:
            if vector_id not in by_id:
                raise ValidationError("UNKNOWN_CRASH_VECTOR_REFERENCE", vector_id)
            owner = by_id[vector_id]["consumer"]
            # Adjacent consumers intentionally reference boundary cutpoints owned
            # by either side.  The complete allowed relation is the normative
            # EXPECTED_CRASH_REFERENCES map, not equality with a single owner.
            if vector_id not in EXPECTED_CRASH_REFERENCES[cid]:
                raise ValidationError(
                    "CRASH_REFERENCE_OWNER_RELATION_DRIFT",
                    f"{cid}:{vector_id}:{owner}",
                )


def _validate_offline_tests(root: Path, vectors: Mapping[str, Any]) -> list[str]:
    nodes: list[str] = []
    source_cache: dict[str, tuple[str, set[str]]] = {}
    for entry in vectors["offline_tests"]:
        node_id = entry["node_id"]
        relative, function = node_id.split("::", 1)
        path = _safe_regular_file(root, relative)
        if relative not in source_cache:
            raw = path.read_bytes()
            tree = ast.parse(raw.decode("utf-8"))
            names = {
                node.name
                for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            source_cache[relative] = (_sha(raw), names)
        digest, names = source_cache[relative]
        if digest != entry["source_sha256"]:
            raise ValidationError("OFFLINE_TEST_SOURCE_DRIFT", relative)
        if function not in names:
            raise ValidationError("OFFLINE_TEST_NODE_MISSING", node_id)
        if entry["network"] or entry["live_provider"]:
            raise ValidationError("OFFLINE_TEST_AUTHORITY_VIOLATION", node_id)
        nodes.append(node_id)
    if len(nodes) != 24 or len(set(nodes)) != 24:
        raise ValidationError("OFFLINE_TEST_ROSTER_DRIFT", str(len(nodes)))
    return nodes


def _run_offline_tests(root: Path, nodes: list[str]) -> str:
    if os.name != "nt":
        raise ValidationError("NATIVE_WINDOWS_REQUIRED", os.name)
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["NO_PROXY"] = "*"
    environment["no_proxy"] = "*"
    command = [
        sys.executable,
        "-B",
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        "--disable-warnings",
        "--maxfail=1",
        *nodes,
    ]
    completed = subprocess.run(
        command,
        cwd=root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=240,
    )
    output = f"{completed.stdout}\n{completed.stderr}"
    if completed.returncode != 0:
        raise ValidationError("OFFLINE_TESTS_FAILED", output[-2000:])
    lowered = output.lower()
    if "35 passed" not in lowered:
        raise ValidationError("OFFLINE_TEST_CASE_COUNT_DRIFT", output[-1000:])
    if any(token in lowered for token in (" failed", " error", " skipped")):
        raise ValidationError("OFFLINE_TEST_NONPASS_RESULT", output[-1000:])
    return "35"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-offline-tests", action="store_true")
    args = parser.parse_args()

    schema = _read_json(SCHEMA_PATH)
    registry = _read_json(REGISTRY_PATH)
    vectors = _read_json(VECTORS_PATH)
    _schema_validate(schema, registry)
    _schema_validate(schema, vectors)
    _validate_vector_denominator(vectors)

    root = Path(registry["repository"]["root"])
    if _is_reparse_or_symlink(root):
        raise ValidationError("REPOSITORY_ROOT_REPARSE_OR_SYMLINK", str(root))
    if _git(root, "branch", "--show-current") != registry["repository"]["branch"]:
        raise ValidationError("REPOSITORY_BRANCH_DRIFT")
    if _git(root, "rev-parse", "HEAD") != registry["repository"]["head"]:
        raise ValidationError("REPOSITORY_HEAD_DRIFT")

    adapter_path = root / "scripts" / "model_routing_runtime_adapter.py"
    if adapter_path.exists():
        raise ValidationError("UNEXPECTED_PRODUCTION_ADAPTER_PRESENT", str(adapter_path))

    observations = _source_observations(root, registry)
    production_manifest, production_files = _production_source_manifest(root)
    production_manifest_digest = _sha(_canonical(production_manifest))
    if (
        len(production_manifest) != EXPECTED_SCOPE_FILE_COUNT
        or production_manifest_digest != EXPECTED_SCOPE_MANIFEST_SHA256
    ):
        raise ValidationError(
            "PRODUCTION_SOURCE_SCOPE_DRIFT",
            f"{len(production_manifest)}:{production_manifest_digest}",
        )
    callers = _scan_callers(root, registry, production_files)
    _validate_registry_closed(
        schema,
        registry,
        root=root,
        observations=observations,
        callers=callers,
    )

    rows, matrix_digest = _phase_matrix(root)
    behavior = registry["current_model_behavior"]
    if len(rows) != behavior["phase_matrix_rows"]:
        raise ValidationError("PHASE_MATRIX_ROW_COUNT_DRIFT", str(len(rows)))
    if matrix_digest != behavior["phase_matrix_sha256"]:
        raise ValidationError("PHASE_MATRIX_DIGEST_DRIFT", matrix_digest)
    models = {row["effective_model"] for row in rows}
    expected_models = {
        "sonnet", "haiku", "claude-opus-4-8",
        "gpt-5.4", "gpt-5.4-mini", "gpt-5.5",
    }
    if models != expected_models:
        raise ValidationError("PHASE_MATRIX_MODEL_SET_DRIFT", repr(sorted(models)))
    if any("max" in model.lower() for model in models) or behavior["max_present"]:
        raise ValidationError("MAX_MODEL_PRESENT")

    operations = _operations(registry, vectors)
    expected_expansion = vectors["expected_expansion"]
    if len(operations) != expected_expansion["operation_count"]:
        raise ValidationError("OPERATION_COUNT_DRIFT", str(len(operations)))
    manifest_digest = _sha(_canonical(operations))
    if manifest_digest != expected_expansion["operation_manifest_sha256"]:
        raise ValidationError("OPERATION_MANIFEST_DIGEST_DRIFT", manifest_digest)
    if manifest_digest != EXPECTED_OPERATION_MANIFEST_SHA256:
        raise ValidationError("OPERATION_NORMATIVE_MANIFEST_DRIFT", manifest_digest)

    mutation_count = _run_mutation_probes(
        schema=schema,
        registry=registry,
        vectors=vectors,
        root=root,
        observations=observations,
        callers=callers,
    )
    oracle_mutation_count = _run_oracle_blocker_probes(
        schema=schema,
        registry=registry,
        vectors=vectors,
        root=root,
        observations=observations,
        callers=callers,
    )
    _validate_crash_vectors(registry, vectors)
    nodes = _validate_offline_tests(root, vectors)
    offline_cases = "NOT_RUN"
    if args.run_offline_tests:
        offline_cases = _run_offline_tests(root, nodes)

    print("R2_5_6_GREEN_PREP=PASS")
    print(f"REPOSITORY_HEAD={registry['repository']['head']}")
    print(f"SOURCE_CONSUMERS={len(EXPECTED_CONSUMERS)}")
    print(f"SOURCE_REGISTRY_SHA256={_sha(REGISTRY_PATH.read_bytes())}")
    print(f"REGISTRY_DIGEST={registry['registry_digest']}")
    print(f"PHASE_MATRIX_ROWS={len(rows)}")
    print(f"PHASE_MATRIX_SHA256={matrix_digest}")
    print(f"RED_OPERATIONS={len(operations)}")
    print(f"RED_OPERATION_MANIFEST_SHA256={manifest_digest}")
    print(f"MUTATION_PROBES={mutation_count}")
    print(f"ORACLE_BLOCKER_PROBES={oracle_mutation_count}")
    print(f"PRODUCTION_SOURCE_FILES={len(production_manifest)}")
    print(f"PRODUCTION_SOURCE_MANIFEST_SHA256={production_manifest_digest}")
    print(f"OFFLINE_TEST_NODE_IDS={len(nodes)}")
    print(f"OFFLINE_TEST_CASES={offline_cases}")
    print("PRODUCTION_ADAPTER_STATE=ABSENT_EXPECTED_RED")
    print("PROVIDER_CALL_OBSERVATION=UNOBSERVED")
    print("NETWORK_CALL_OBSERVATION=UNOBSERVED")
    print("AUDIT_EXECUTIONS=0")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValidationError as exc:
        print(f"R2_5_6_GREEN_PREP=BLOCK:{exc.error_class}", file=sys.stderr)
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
