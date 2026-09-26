"""Committed workspace/WTX/activation authority for Program Facts v2.

Positive composition has no caller-shaped authority parameters.  The shared
workspace, provider WorkerTransaction, raw provider candidate, and activation
authority bundle must already be committed under exact PhaseIO/ArtifactLedger
owners.  The functions in this module derive and replay those authorities and
then invoke the pure composer.  Missing authority is explicit non-terminal
debt; it is never converted into success.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from jsonschema import Draft202012Validator

from artifact_ledger import read_artifact_ledger, validate_work_unit_artifacts
from evm_analysis_workspace_authority import (
    EVMAnalysisWorkspaceAuthorityError,
    load_evm_analysis_workspace_authority,
    require_admitted_workspace_tool,
    workspace_public_reference,
)
from phase_io_contracts import (
    LaunchSpec,
    PhaseIOContract,
    resolve_phase_io_contract,
    resolve_program_facts_registered_launch,
)
from program_facts_evm_environment_authority import (
    validate_activation_permit_v1,
    validate_provider_environment_v1,
)
from program_facts_positive_composer import (
    compose_program_facts_v2_production,
    validate_production_composition_candidate,
)
from program_facts_types import (
    ProgramFactsTypeError,
    canonical_file_bytes,
    canonical_json_bytes,
    strict_json_loads,
    validate_program_facts_v2_representation_v1,
)
from worker_transaction import (
    WorkerTransactionError,
    validate_worker_execution_authority,
)
import rooted_path_io


WORKSPACE_DECISION_SCHEMA = "plamen.program_facts_workspace_v2_decision.v1"
WORKSPACE_CANDIDATE_SCHEMA = "plamen.program_facts_workspace_candidate.v2"
WORKER_OUTPUT_SCHEMA = "plamen.program_facts_v2_worker_output.v1"
ACTIVATION_AUTHORITY_SCHEMA = "plamen.program_facts_v2_activation_authority.v1"
PROGRAM_FACTS_V2_WORKER_OUTPUT_PATH = (
    "_program_facts_provider_raw/program_facts_v2_candidate.json"
)
PROGRAM_FACTS_V2_ACTIVATION_AUTHORITY_PATH = (
    "_program_facts_inputs/program_facts_v2_activation_authority.v1.json"
)
V2_ARTIFACT_IDENTITIES = (
    "mechanical_program_facts.v2.json",
    "mechanical_program_facts_receipt.v2.json",
    "mechanical_program_facts_debt.v2.json",
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_FACT_KEYS = frozenset({
    "fact_id", "capability_id", "relation_kind", "subject_id", "object_id",
    "precision", "fact_sha256",
})
_DEBT_KEYS = frozenset({
    "debt_id", "reason_code", "capability_id",
    "terminal_negative_authority", "debt_sha256",
})
_AUTHORITY_KEYS = frozenset({
    "execution_authority_digest", "composition_authority_digest",
    "methodology_package_digest", "activation_decision_digest",
    "activation_permit_digest", "build_input_snapshot_digest",
    "candidate_universe_digest", "selected_scope_digest",
    "capability_selection_digest", "build_plan_digest",
    "execution_set_digest",
})
_WORKER_OUTPUT_KEYS = frozenset({
    "schema_version", "run_id", "run_generation", "workspace_reference",
    "authority_bindings", "analysis_scope", "coverage",
    "provider_executions", "internal_cells", "public_projection_policy_digest",
    "facts", "debt", "worker_output_sha256",
})
_CANDIDATE_KEYS = frozenset({
    "schema_version", "workspace_reference", "execution_authority",
    "dependency_closure", "artifacts", "candidate_sha256",
})
_PRECISIONS = frozenset({"EXACT", "SYNTACTIC", "HEURISTIC", "MAY"})
_REVIEW_ROLES = ("B", "C", "NATIVE_HOST", "PACKAGE")


def _fail(message: str) -> None:
    raise ProgramFactsTypeError(message)


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        _fail(f"{label} must be lowercase SHA-256")
    return value


def _signed_body(
    value: object,
    *,
    digest_field: str,
    exact_keys: frozenset[str],
    schema: str,
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or frozenset(value) != exact_keys:
        _fail(f"ACTIVATION_AUTHORITY_INVALID:{label} schema")
    row = dict(value)
    if row.get("schema_version") != schema:
        _fail(f"ACTIVATION_AUTHORITY_INVALID:{label} version")
    claimed = _sha(row.pop(digest_field, None), f"{label} digest")
    if _digest(row) != claimed:
        _fail(f"ACTIVATION_AUTHORITY_INVALID:{label} digest")
    return dict(value)


def _decision_debt(
    *, reason_code: str, capability_id: str, tool_id: str,
    tool_row_sha256: str | None,
) -> dict[str, Any]:
    unsigned = {
        "reason_code": reason_code,
        "capability_id": capability_id,
        "tool_id": tool_id,
        "tool_row_sha256": tool_row_sha256,
        "terminal_negative_authority": False,
    }
    digest = _digest(unsigned)
    return {
        "debt_id": f"PFV2D-{digest[:24]}", **unsigned,
        "debt_sha256": digest,
    }


def normalize_dependency_closure_v2(
    value: Mapping[str, Any], *, expected_sha256: str,
) -> dict[str, str]:
    if not isinstance(value, Mapping):
        _fail("dependency closure must be an object")
    if frozenset(value) == {"dependency_closure_sha256"}:
        observed = value["dependency_closure_sha256"]
    elif frozenset(value) == {"dependency_closure_digest"}:
        observed = value["dependency_closure_digest"]
    else:
        _fail("dependency closure schema is ambiguous or has unknown fields")
    digest = _sha(observed, "dependency closure")
    if digest != _sha(expected_sha256, "expected dependency closure"):
        _fail("DEPENDENCY_CLOSURE_DRIFT")
    return {"dependency_closure_sha256": digest}


def _workspace(
    scratchpad: Path, *, expected_run_id: str,
    expected_snapshot_sha256: str, expected_owner_work_unit_key: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        receipt = load_evm_analysis_workspace_authority(
            Path(scratchpad), expected_run_id=expected_run_id,
            expected_snapshot_sha256=expected_snapshot_sha256,
            expected_owner_work_unit_key=expected_owner_work_unit_key,
        )
        reference = workspace_public_reference(receipt)
    except Exception as exc:
        _fail(f"WORKSPACE_AUTHORITY_INVALID:{exc}")
    return receipt, reference


def _tool_rows(
    receipt: Mapping[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, list[dict[str, Any]]]:
    admitted: list[dict[str, Any] | None] = []
    debt: list[dict[str, Any]] = []
    for tool_id in ("slither", "solc"):
        try:
            admitted.append(require_admitted_workspace_tool(receipt, tool_id))
        except EVMAnalysisWorkspaceAuthorityError:
            admitted.append(None)
            rows = [row for row in receipt["tools"] if row.get("tool_id") == tool_id]
            debt.append(_decision_debt(
                reason_code="WORKSPACE_TOOL_UNADMITTED",
                capability_id=(
                    "evm-typed-program-facts-v2" if tool_id == "slither"
                    else "evm-solidity-compilation-v1"
                ),
                tool_id=tool_id,
                tool_row_sha256=(
                    rows[0].get("tool_row_sha256") if len(rows) == 1 else None
                ),
            ))
    return admitted[0], admitted[1], debt


def workspace_program_facts_v2_decision(
    workspace_scratchpad: Path, *, expected_run_id: str,
    expected_snapshot_sha256: str, expected_owner_work_unit_key: str,
) -> dict[str, Any]:
    receipt, reference = _workspace(
        workspace_scratchpad, expected_run_id=expected_run_id,
        expected_snapshot_sha256=expected_snapshot_sha256,
        expected_owner_work_unit_key=expected_owner_work_unit_key,
    )
    slither, solc, debt = _tool_rows(receipt)
    unsigned = {
        "schema_version": WORKSPACE_DECISION_SCHEMA,
        "state": "ADMITTED" if not debt else "TYPED_DEBT",
        "public_status": "WRITTEN" if not debt else "UNAVAILABLE",
        "workspace_reference": reference,
        "slither_tool_row_sha256": (
            slither["tool_row_sha256"] if slither is not None else None
        ),
        "solc_tool_row_sha256": (
            solc["tool_row_sha256"] if solc is not None else None
        ),
        "debt": debt,
        "terminal_negative_authority": False,
    }
    return {**unsigned, "decision_sha256": _digest(unsigned)}


def _committed_output(
    *, scratchpad: Path, project_root: Path, owner_prefix: str,
    work_unit_id: str, output_path: str, actor: str, model_invoked: bool,
    expected_run_id: str,
) -> tuple[dict[str, Any], PhaseIOContract, LaunchSpec, bytes]:
    parts = owner_prefix.split("/")
    if len(parts) != 6:
        _fail("COMMITTED_PHASEIO_INVALID:workspace owner")
    key = "/".join((*parts[:4], "recon", work_unit_id))
    ledger = read_artifact_ledger(Path(scratchpad))
    unit = ledger.get("work_units", {}).get(key)
    if not isinstance(unit, Mapping):
        _fail(f"COMMITTED_AUTHORITY_MISSING:{work_unit_id}")
    try:
        contract = resolve_phase_io_contract(
            pipeline=parts[0], mode=parts[1], ecosystem=parts[2],
            backend=parts[3], phase="recon", work_unit_id=work_unit_id,
            exact_inputs=("evm_analysis_workspace_receipt.v1.json",),
            exact_outputs=(output_path,), exact_writer=actor,
        )
        launch = resolve_program_facts_registered_launch(contract)
    except (TypeError, ValueError) as exc:
        _fail(f"COMMITTED_PHASEIO_INVALID:{work_unit_id}:{exc}")
    if (
        key != contract.key
        or unit.get("run_id") != expected_run_id
        or unit.get("contract_manifest") != contract.to_dict()
        or unit.get("contract_digest") != contract.digest
        or unit.get("launch_manifest") != launch.to_dict()
        or unit.get("launch_digest") != launch.digest
        or contract.phase != "recon"
        or contract.work_unit_id != work_unit_id
        or contract.model_invoked is not model_invoked
        or len(contract.outputs) != 1
        or contract.outputs[0].identity != f"scratchpad:{output_path}"
        or contract.outputs[0].writer != actor
        or contract.outputs[0].write_mode != "CREATE"
    ):
        _fail(f"COMMITTED_PHASEIO_INVALID:{work_unit_id} contract")
    issues = validate_work_unit_artifacts(
        Path(scratchpad), Path(project_root), contract, launch,
        run_id=expected_run_id, actor=actor,
    )
    if issues:
        _fail(f"COMMITTED_PHASEIO_INVALID:{work_unit_id}:" + ";".join(issues))
    try:
        raw = rooted_path_io.read_bytes(
            Path(scratchpad) / output_path,
            label=f"{work_unit_id} output", require_single_link=True,
        )
    except Exception as exc:
        _fail(f"COMMITTED_PHASEIO_INVALID:{work_unit_id}:{exc}")
    return dict(unit), contract, launch, raw


def _validate_activation_bundle(
    raw: bytes, *, run_id: str, run_generation: int,
    execution_digest: str,
) -> tuple[dict[str, Any], Mapping[str, Any], dict[str, Any]]:
    value = strict_json_loads(raw, require_final_lf=True)
    keys = frozenset({
        "schema_version", "run_id", "run_generation", "provider_environment",
        "provider_package_authority", "native_host_authority",
        "composition_authority", "methodology_authority",
        "issuer_policy_authority", "activation_decision_authority",
        "independent_reviews", "activation_permit", "activation_authority_sha256",
    })
    if not isinstance(value, Mapping) or frozenset(value) != keys:
        _fail("ACTIVATION_AUTHORITY_INVALID:bundle schema")
    bundle = dict(value)
    unsigned = dict(bundle)
    claimed = _sha(
        unsigned.pop("activation_authority_sha256"), "activation bundle digest"
    )
    if _digest(unsigned) != claimed:
        _fail("ACTIVATION_AUTHORITY_INVALID:bundle digest")
    if bundle.get("schema_version") != ACTIVATION_AUTHORITY_SCHEMA:
        _fail("ACTIVATION_AUTHORITY_INVALID:bundle version")
    if bundle.get("run_id") != run_id or bundle.get("run_generation") != run_generation:
        _fail("ACTIVATION_AUTHORITY_INVALID:run parent")

    composition = _signed_body(
        bundle["composition_authority"],
        digest_field="composition_authority_digest",
        exact_keys=frozenset({
            "schema_version", "run_id", "execution_authority_digest",
            "composition_authority_digest",
        }),
        schema="plamen.program_facts_composition_authority.v1",
        label="composition authority",
    )
    if composition["run_id"] != run_id or composition[
        "execution_authority_digest"
    ] != execution_digest:
        _fail("ACTIVATION_AUTHORITY_INVALID:composition parent")
    methodology = _signed_body(
        bundle["methodology_authority"],
        digest_field="methodology_package_digest",
        exact_keys=frozenset({
            "schema_version", "run_id", "execution_authority_digest",
            "composition_authority_digest", "methodology_package_digest",
        }),
        schema="plamen.program_facts_methodology_package.v2",
        label="methodology authority",
    )
    if (
        methodology["run_id"] != run_id
        or methodology["execution_authority_digest"] != execution_digest
        or methodology["composition_authority_digest"]
        != composition["composition_authority_digest"]
    ):
        _fail("ACTIVATION_AUTHORITY_INVALID:methodology parent")
    package = _signed_body(
        bundle["provider_package_authority"],
        digest_field="provider_package_digest",
        exact_keys=frozenset({
            "schema_version", "run_id", "provider_id", "provider_package_digest",
        }),
        schema="plamen.program_facts_provider_package_authority.v1",
        label="provider package authority",
    )
    native = _signed_body(
        bundle["native_host_authority"],
        digest_field="native_host_receipt_digest",
        exact_keys=frozenset({
            "schema_version", "run_id", "native_host_receipt_digest",
        }),
        schema="plamen.program_facts_native_host_authority.v1",
        label="native host authority",
    )
    issuer = _signed_body(
        bundle["issuer_policy_authority"],
        digest_field="issuer_policy_digest",
        exact_keys=frozenset({
            "schema_version", "issuer_id", "release_id", "issuer_policy_digest",
        }),
        schema="plamen.program_facts_issuer_policy.v1",
        label="issuer policy authority",
    )
    decision = _signed_body(
        bundle["activation_decision_authority"],
        digest_field="activation_decision_digest",
        exact_keys=frozenset({
            "schema_version", "run_id", "decision", "activation_decision_digest",
        }),
        schema="plamen.program_facts_activation_decision.v1",
        label="activation decision authority",
    )
    if any(row["run_id"] != run_id for row in (package, native, decision)):
        _fail("ACTIVATION_AUTHORITY_INVALID:authority run parent")
    environment = validate_provider_environment_v1(bundle["provider_environment"])
    reviews_value = bundle.get("independent_reviews")
    if not isinstance(reviews_value, Sequence) or isinstance(
        reviews_value, (str, bytes, bytearray)
    ):
        _fail("ACTIVATION_AUTHORITY_INVALID:review denominator")
    reviews: dict[str, str] = {}
    targets = {
        "B": execution_digest,
        "C": composition["composition_authority_digest"],
        "NATIVE_HOST": native["native_host_receipt_digest"],
        "PACKAGE": package["provider_package_digest"],
    }
    for raw_review in reviews_value:
        review = _signed_body(
            raw_review, digest_field="review_sha256",
            exact_keys=frozenset({
                "schema_version", "role", "candidate_digest", "review_sha256",
            }), schema="plamen.program_facts_independent_review.v1",
            label="independent review",
        )
        role = str(review["role"])
        if role not in targets or role in reviews or review[
            "candidate_digest"
        ] != targets[role]:
            _fail("ACTIVATION_AUTHORITY_INVALID:review parent")
        reviews[role] = review["review_sha256"]
    if tuple(sorted(reviews)) != tuple(sorted(_REVIEW_ROLES)):
        _fail("ACTIVATION_AUTHORITY_INVALID:review denominator")

    permit = bundle["activation_permit"]
    if (
        isinstance(permit, Mapping)
        and frozenset(permit) == {"state", "reason"}
        and permit.get("state") == "ABSENT_DENIED"
    ):
        if decision["decision"] != "DENIED":
            _fail("ACTIVATION_AUTHORITY_INVALID:denial decision")
        return bundle, dict(permit), {}
    if decision["decision"] != "PERMITTED":
        _fail("ACTIVATION_AUTHORITY_INVALID:positive decision")
    context = {
        "provider_environment": environment,
        "expected_provider_environment_digest": environment["environment_digest"],
        "expected_provider_package_digest": package["provider_package_digest"],
        "expected_native_host_receipt_digest": native["native_host_receipt_digest"],
        "expected_independent_review_receipts": reviews,
        "expected_issuer_policy_digest": issuer["issuer_policy_digest"],
        "expected_issuer_id": issuer["issuer_id"],
        "expected_release_id": issuer["release_id"],
        "expected_activation_decision_digest": decision[
            "activation_decision_digest"
        ],
    }
    validated = validate_activation_permit_v1(
        permit, expected_run_id=run_id, expected_run_generation=run_generation,
        expected_execution_authority_digest=execution_digest,
        expected_composition_authority_digest=composition[
            "composition_authority_digest"
        ],
        expected_methodology_package_digest=methodology[
            "methodology_package_digest"
        ], **context,
    )
    return bundle, validated, context


def _typed_rows(
    values: object, *, keys: frozenset[str], id_key: str,
    digest_key: str, label: str,
) -> list[dict[str, Any]]:
    if not isinstance(values, Sequence) or isinstance(
        values, (str, bytes, bytearray)
    ):
        _fail(f"{label} must be a sequence")
    rows: list[dict[str, Any]] = []
    for raw in values:
        if not isinstance(raw, Mapping) or frozenset(raw) != keys:
            _fail(f"{label} row schema is not exact")
        unsigned = dict(raw)
        supplied = unsigned.pop(digest_key, None)
        if _digest(unsigned) != _sha(supplied, f"{label} digest"):
            _fail(f"{label} row digest differs")
        rows.append(dict(raw))
    identities = [str(row.get(id_key) or "") for row in rows]
    if identities != sorted(identities) or len(identities) != len(set(identities)):
        _fail(f"{label} rows must be sorted and unique")
    return rows


def _derived_public_authorities(
    *, worker: Mapping[str, Any], reference: Mapping[str, Any],
    activation_permit: Mapping[str, Any], activation_bundle: Mapping[str, Any],
    worker_output: Mapping[str, Any],
) -> dict[str, str]:
    composition = activation_bundle["composition_authority"]
    methodology = activation_bundle["methodology_authority"]
    decision = activation_bundle["activation_decision_authority"]
    permit_digest = (
        _digest(activation_permit)
        if activation_permit.get("state") == "ABSENT_DENIED"
        else str(activation_permit["permit_digest"])
    )
    cells = [
        [row.get("capability_id"), row.get("build_variant_id")]
        for row in worker_output["internal_cells"]
        if isinstance(row, Mapping)
    ]
    return {
        # The provider output is itself an input to the final WTX receipt, so
        # embedding that receipt digest in the output would create a hash
        # cycle.  The immutable WTX work-plan is the pre-execution authority;
        # the enclosing candidate/capture separately binds the final receipt
        # digest and exact output bytes.
        "execution_authority_digest": str(worker["work_plan_digest"]),
        "composition_authority_digest": str(
            composition["composition_authority_digest"]
        ),
        "methodology_package_digest": str(
            methodology["methodology_package_digest"]
        ),
        "activation_decision_digest": str(
            decision["activation_decision_digest"]
        ),
        "activation_permit_digest": permit_digest,
        "build_input_snapshot_digest": str(reference["snapshot_sha256"]),
        "candidate_universe_digest": _digest({
            "workspace_receipt_sha256": reference["receipt_sha256"],
            "provider_id": "evm.slither.typed",
        }),
        "selected_scope_digest": _digest(worker_output["analysis_scope"]),
        "capability_selection_digest": _digest(sorted(cells)),
        "build_plan_digest": _digest({
            "build_variant_sha256": reference["build_variant_sha256"],
            "dependency_closure_sha256": reference["dependency_closure_sha256"],
        }),
        "execution_set_digest": _digest(worker_output["provider_executions"]),
    }


def _validate_worker_output(
    raw: bytes, *, run_id: str, reference: Mapping[str, Any],
    slither: Mapping[str, Any], solc: Mapping[str, Any],
    worker_authority: Mapping[str, Any], activation_permit: Mapping[str, Any],
    activation_bundle: Mapping[str, Any],
) -> dict[str, Any]:
    value = strict_json_loads(raw, require_final_lf=True)
    if not isinstance(value, Mapping) or frozenset(value) != _WORKER_OUTPUT_KEYS:
        _fail("WORKER_OUTPUT_INVALID:schema")
    row = dict(value)
    unsigned = dict(row)
    claimed = _sha(unsigned.pop("worker_output_sha256"), "worker output digest")
    if _digest(unsigned) != claimed:
        _fail("WORKER_OUTPUT_INVALID:digest")
    if row.get("schema_version") != WORKER_OUTPUT_SCHEMA or row.get("run_id") != run_id:
        _fail("WORKER_OUTPUT_INVALID:run parent")
    if row.get("workspace_reference") != reference:
        _fail("WORKER_OUTPUT_INVALID:workspace parent")
    facts = _typed_rows(
        row.get("facts"), keys=_FACT_KEYS, id_key="fact_id",
        digest_key="fact_sha256", label="Program Facts v2 fact",
    )
    for fact in facts:
        if (
            any(not isinstance(fact.get(key), str) or not fact[key] for key in (
                "capability_id", "relation_kind", "subject_id", "object_id"
            ))
            or fact.get("precision") not in _PRECISIONS
        ):
            _fail("WORKER_OUTPUT_INVALID:fact semantics")
    _typed_rows(
        row.get("debt"), keys=_DEBT_KEYS, id_key="debt_id",
        digest_key="debt_sha256", label="Program Facts v2 debt",
    )
    executions = row.get("provider_executions")
    if not isinstance(executions, Sequence) or isinstance(
        executions, (str, bytes, bytearray)
    ) or not executions:
        _fail("WORKER_OUTPUT_INVALID:provider execution denominator")
    expected_edges = {
        "workspace_receipt_sha256": reference["receipt_sha256"],
        "slither_tool_row_sha256": slither["tool_row_sha256"],
        "solc_tool_row_sha256": solc["tool_row_sha256"],
        "build_variant_sha256": reference["build_variant_sha256"],
        "dependency_closure_sha256": reference["dependency_closure_sha256"],
    }
    for execution in executions:
        if not isinstance(execution, Mapping) or any(
            execution.get(key) != expected for key, expected in expected_edges.items()
        ):
            _fail("WORKER_OUTPUT_INVALID:workspace/tool execution edge")
    derived = _derived_public_authorities(
        worker=worker_authority, reference=reference,
        activation_permit=activation_permit, activation_bundle=activation_bundle,
        worker_output=row,
    )
    if row.get("authority_bindings") != derived:
        _fail("WORKER_OUTPUT_INVALID:authority binding divergence")
    return row


@lru_cache(maxsize=3)
def _artifact_schema(identity: str) -> dict[str, Any]:
    path = Path(__file__).resolve().parents[1] / "rules" / "schemas" / (
        identity.removesuffix(".json") + ".schema.json"
    )
    value = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(value)
    return value


def _validate_actual_trio(artifacts: Sequence[tuple[str, bytes]]) -> None:
    if tuple(identity for identity, _raw in artifacts) != V2_ARTIFACT_IDENTITIES:
        _fail("V1_DOWNGRADE_REJECTED")
    values: dict[str, Mapping[str, Any]] = {}
    for identity, raw in artifacts:
        value = strict_json_loads(raw, require_final_lf=True)
        errors = list(Draft202012Validator(_artifact_schema(identity)).iter_errors(value))
        if errors:
            _fail(f"Program Facts v2 artifact schema differs:{identity}:{errors[0].message}")
        values[identity] = value
    receipt = values[V2_ARTIFACT_IDENTITIES[1]]
    receipt_bytes = artifacts[1][1]
    bundle = {
        "schema_version": "plamen.program_facts_public_v2_bundle.v1",
        "payload": values[V2_ARTIFACT_IDENTITIES[0]],
        "receipt": receipt,
        "debt": values[V2_ARTIFACT_IDENTITIES[2]],
        "expected_provider_lineage": receipt["provider_executions"],
        "legacy_projection": {
            "source_snapshot_digest": receipt["authority_bindings"][
                "build_input_snapshot_digest"
            ],
            "provider_id": "evm.slither.typed",
            "status": receipt["status"],
        },
        "ledger_binding": {
            "receipt_full_file_size": len(receipt_bytes),
            "receipt_full_file_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        },
    }
    validate_program_facts_v2_representation_v1(
        bundle, captured_authority=receipt["authority_bindings"],
        current_authority=receipt["authority_bindings"],
    )


def _derive_candidate(
    *, workspace_scratchpad: Path, project_root: Path,
    expected_run_id: str, expected_snapshot_sha256: str,
    expected_owner_work_unit_key: str,
) -> dict[str, Any]:
    receipt, reference = _workspace(
        workspace_scratchpad, expected_run_id=expected_run_id,
        expected_snapshot_sha256=expected_snapshot_sha256,
        expected_owner_work_unit_key=expected_owner_work_unit_key,
    )
    slither, solc, debt = _tool_rows(receipt)
    if debt or slither is None or solc is None:
        return workspace_program_facts_v2_decision(
            workspace_scratchpad, expected_run_id=expected_run_id,
            expected_snapshot_sha256=expected_snapshot_sha256,
            expected_owner_work_unit_key=expected_owner_work_unit_key,
        )
    worker_unit, worker_contract, worker_launch, worker_raw = _committed_output(
        scratchpad=workspace_scratchpad, project_root=project_root,
        owner_prefix=expected_owner_work_unit_key,
        work_unit_id="program_facts_provider",
        output_path=PROGRAM_FACTS_V2_WORKER_OUTPUT_PATH,
        actor="MODEL", model_invoked=True,
        expected_run_id=expected_run_id,
    )
    worker_authority = worker_unit.get("execution_authority")
    if not isinstance(worker_authority, Mapping):
        _fail("WORKER_TRANSACTION_AUTHORITY_INVALID:ledger authority absent")
    try:
        worker_authority = validate_worker_execution_authority(
            scratchpad=workspace_scratchpad, authority=worker_authority,
            contract=worker_contract, launch=worker_launch,
            run_id=expected_run_id,
        )
    except (WorkerTransactionError, OSError, TypeError, ValueError) as exc:
        _fail(f"WORKER_TRANSACTION_AUTHORITY_INVALID:{exc}")
    activation_unit, _activation_contract, _activation_launch, activation_raw = (
        _committed_output(
            scratchpad=workspace_scratchpad, project_root=project_root,
            owner_prefix=expected_owner_work_unit_key,
            work_unit_id="program_facts_v2_activation_authority",
            output_path=PROGRAM_FACTS_V2_ACTIVATION_AUTHORITY_PATH,
            actor="DRIVER", model_invoked=False,
            expected_run_id=expected_run_id,
        )
    )
    preliminary = strict_json_loads(worker_raw, require_final_lf=True)
    generation = preliminary.get("run_generation") if isinstance(
        preliminary, Mapping
    ) else None
    if not isinstance(generation, int) or isinstance(generation, bool):
        _fail("WORKER_OUTPUT_INVALID:generation")
    activation_bundle, permit, context = _validate_activation_bundle(
        activation_raw, run_id=expected_run_id, run_generation=generation,
        execution_digest=str(worker_authority["work_plan_digest"]),
    )
    worker_output = _validate_worker_output(
        worker_raw, run_id=expected_run_id, reference=reference,
        slither=slither, solc=solc, worker_authority=worker_authority,
        activation_permit=permit, activation_bundle=activation_bundle,
    )
    sealed = {
        key: worker_output[key]
        for key in (
            "run_id", "run_generation", "authority_bindings", "analysis_scope",
            "coverage", "provider_executions", "internal_cells",
            "public_projection_policy_digest", "facts", "debt",
        )
    }
    sealed["status"] = (
        "UNAVAILABLE"
        if permit.get("state") == "ABSENT_DENIED"
        else ("DEGRADED" if worker_output["debt"] else "WRITTEN")
    )
    production = compose_program_facts_v2_production(
        sealed, permit,
        expected_run_id=expected_run_id,
        expected_run_generation=generation,
        expected_execution_authority_digest=str(worker_authority["work_plan_digest"]),
        expected_composition_authority_digest=sealed["authority_bindings"][
            "composition_authority_digest"
        ],
        expected_methodology_package_digest=sealed["authority_bindings"][
            "methodology_package_digest"
        ], **context,
    )
    if production.get("authority_class") == "ABSENT_DENIED":
        validated = production
    else:
        validated = validate_production_composition_candidate(
            production, sealed_composition_inputs=sealed,
            activation_permit_document=permit,
            expected_run_id=expected_run_id,
            expected_run_generation=generation,
            expected_execution_authority_digest=str(worker_authority["work_plan_digest"]),
            expected_composition_authority_digest=sealed["authority_bindings"][
                "composition_authority_digest"
            ],
            expected_methodology_package_digest=sealed["authority_bindings"][
                "methodology_package_digest"
            ], **context,
        )
    artifacts = tuple(validated["artifacts"])
    _validate_actual_trio(artifacts)
    execution = {
        "provider_id": "evm.slither.typed",
        "worker_owner_work_unit_key": worker_contract.key,
        "execution_authority_digest": worker_authority["work_plan_digest"],
        "worker_execution_authority_sha256": worker_authority["authority_digest"],
        "worker_output_sha256": hashlib.sha256(worker_raw).hexdigest(),
        "activation_owner_work_unit_key": str(activation_unit["work_unit_key"]),
        "activation_authority_sha256": activation_bundle[
            "activation_authority_sha256"
        ],
        "activation_permit_sha256": hashlib.sha256(
            canonical_json_bytes(permit)
        ).hexdigest(),
        "program_facts_candidate_sha256": validated["candidate_digest"],
        "slither_tool_row_sha256": slither["tool_row_sha256"],
        "solc_tool_row_sha256": solc["tool_row_sha256"],
        "build_variant_sha256": reference["build_variant_sha256"],
        "dependency_closure_sha256": reference["dependency_closure_sha256"],
    }
    closure = {
        "dependency_closure_sha256": reference["dependency_closure_sha256"]
    }
    unsigned = {
        "schema_version": WORKSPACE_CANDIDATE_SCHEMA,
        "workspace_reference": reference,
        "execution_authority": execution,
        "dependency_closure": closure,
        "artifacts": artifacts,
    }
    preimage = {
        **{key: value for key, value in unsigned.items() if key != "artifacts"},
        "artifacts": [
            {"identity": identity, "size": len(raw),
             "sha256": hashlib.sha256(raw).hexdigest()}
            for identity, raw in artifacts
        ],
    }
    return {**unsigned, "candidate_sha256": _digest(preimage)}


def compose_workspace_bound_program_facts_v2(
    *, workspace_scratchpad: Path, project_root: Path,
    expected_run_id: str, expected_snapshot_sha256: str,
    expected_owner_work_unit_key: str,
) -> dict[str, Any]:
    return _derive_candidate(
        workspace_scratchpad=Path(workspace_scratchpad),
        project_root=Path(project_root), expected_run_id=expected_run_id,
        expected_snapshot_sha256=expected_snapshot_sha256,
        expected_owner_work_unit_key=expected_owner_work_unit_key,
    )


def validate_workspace_bound_program_facts_v2(
    candidate: Mapping[str, Any], *, workspace_scratchpad: Path,
    project_root: Path, expected_run_id: str,
    expected_snapshot_sha256: str, expected_owner_work_unit_key: str,
) -> dict[str, Any]:
    if not isinstance(candidate, Mapping) or frozenset(candidate) != _CANDIDATE_KEYS:
        _fail("Program Facts v2 candidate schema is not exact")
    if candidate.get("schema_version") != WORKSPACE_CANDIDATE_SCHEMA:
        _fail("V1_DOWNGRADE_REJECTED")
    expected = _derive_candidate(
        workspace_scratchpad=Path(workspace_scratchpad),
        project_root=Path(project_root), expected_run_id=expected_run_id,
        expected_snapshot_sha256=expected_snapshot_sha256,
        expected_owner_work_unit_key=expected_owner_work_unit_key,
    )
    if expected.get("schema_version") != WORKSPACE_CANDIDATE_SCHEMA:
        _fail("WORKSPACE_TOOL_UNADMITTED")
    if dict(candidate) != expected:
        _fail("Program Facts v2 candidate differs from committed authority replay")
    return dict(candidate)


__all__ = [
    "ACTIVATION_AUTHORITY_SCHEMA",
    "PROGRAM_FACTS_V2_ACTIVATION_AUTHORITY_PATH",
    "PROGRAM_FACTS_V2_WORKER_OUTPUT_PATH",
    "V2_ARTIFACT_IDENTITIES",
    "WORKER_OUTPUT_SCHEMA",
    "WORKSPACE_CANDIDATE_SCHEMA",
    "WORKSPACE_DECISION_SCHEMA",
    "compose_workspace_bound_program_facts_v2",
    "normalize_dependency_closure_v2",
    "validate_workspace_bound_program_facts_v2",
    "workspace_program_facts_v2_decision",
]
