"""Pure Program Facts v2 composition authority boundaries.

No function in this module publishes files, mutates PhaseIO/ArtifactLedger,
launches a provider, or reads ambient configuration.  Production and
structural-test carriers are intentionally not interchangeable.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import ast
from copy import deepcopy
import hashlib
from pathlib import Path
from typing import Any

from program_facts_v2_contracts import (
    ProgramFactsTypeError,
    canonical_file_bytes,
    canonical_json_bytes,
    require_sha256,
)
from program_facts_evm_environment_authority import (
    validate_activation_permit_v1,
)


PRODUCTION_AUTHORITY_CLASS = "PRODUCTION_PERMIT_BOUND"
TEST_AUTHORITY_CLASS = "TEST_ONLY_NONAUTHORITATIVE"
_SEALED_INPUT_KEYS = frozenset(
    {
        "run_id",
        "run_generation",
        "execution_authority_digest",
        "composition_authority_digest",
        "methodology_package_digest",
        "selected_variant_ids",
        "selected_capability_ids",
        "facts",
        "debt",
    }
)
_PUBLIC_SEALED_INPUT_KEYS = frozenset(
    {
        "run_id",
        "run_generation",
        "status",
        "authority_bindings",
        "analysis_scope",
        "coverage",
        "provider_executions",
        "internal_cells",
        "public_projection_policy_digest",
        "facts",
        "debt",
    }
)
_PUBLIC_AUTHORITY_KEYS = frozenset(
    {
        "execution_authority_digest",
        "composition_authority_digest",
        "methodology_package_digest",
        "activation_decision_digest",
        "activation_permit_digest",
        "build_input_snapshot_digest",
        "candidate_universe_digest",
        "selected_scope_digest",
        "capability_selection_digest",
        "build_plan_digest",
        "execution_set_digest",
    }
)
_TEST_MARKERS = frozenset(
    {
        "TEST_ONLY_NONAUTHORITATIVE",
        "STRUCTURAL_TEST_ONLY",
        "TEST_ONLY",
    }
)
_PUBLIC_IDENTITIES = (
    "mechanical_program_facts.v2.json",
    "mechanical_program_facts_receipt.v2.json",
    "mechanical_program_facts_debt.v2.json",
)
_CANDIDATE_SCHEMA = (
    "plamen.program_facts_production_composition_candidate.v1"
)
_CANDIDATE_KEYS = frozenset(
    {
        "schema_version",
        "authority_class",
        "run_id",
        "run_generation",
        "permit_digest",
        "permit_binding_digest",
        "sealed_input_digest",
        "artifacts",
        "candidate_digest",
    }
)


def snapshot_sealed_composition_inputs_v1(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Materialize caller-controlled sealed inputs without a later reread."""

    if not isinstance(value, Mapping):
        raise ProgramFactsTypeError(
            "sealed composition inputs must be an object"
        )

    def snapshot(item: Any) -> Any:
        if isinstance(item, Mapping):
            keys = list(item)
            return {
                deepcopy(key): snapshot(item[key])
                for key in keys
            }
        if isinstance(item, Sequence) and not isinstance(
            item, (str, bytes, bytearray)
        ):
            return [snapshot(child) for child in item]
        return deepcopy(item)

    captured = snapshot(value)
    if not isinstance(captured, dict):
        raise ProgramFactsTypeError(
            "sealed composition inputs must snapshot to an object"
        )
    return captured


def _candidate_preimage(
    *,
    run_id: str,
    run_generation: int,
    permit_digest: str,
    permit_binding_digest: str,
    sealed_input_digest: str,
    artifacts: tuple[tuple[str, bytes], ...],
) -> dict[str, Any]:
    return {
        "schema_version": _CANDIDATE_SCHEMA,
        "authority_class": PRODUCTION_AUTHORITY_CLASS,
        "run_id": run_id,
        "run_generation": run_generation,
        "permit_digest": permit_digest,
        "permit_binding_digest": permit_binding_digest,
        "sealed_input_digest": sealed_input_digest,
        "artifacts": [
            {
                "logical_identity": identity,
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            for identity, content in artifacts
        ],
    }


def _validate_sealed_inputs(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProgramFactsTypeError("sealed composition inputs must be an object")
    keys = frozenset(value)
    if keys not in {_SEALED_INPUT_KEYS, _PUBLIC_SEALED_INPUT_KEYS}:
        raise ProgramFactsTypeError("sealed composition input keys are not exact")
    run_id = value.get("run_id")
    run_generation = value.get("run_generation")
    if not isinstance(run_id, str) or not run_id:
        raise ProgramFactsTypeError("composition run_id must be nonempty")
    if (
        not isinstance(run_generation, int)
        or isinstance(run_generation, bool)
        or run_generation < 0
    ):
        raise ProgramFactsTypeError("composition run_generation is invalid")
    if keys == _SEALED_INPUT_KEYS:
        for key in (
            "execution_authority_digest",
            "composition_authority_digest",
            "methodology_package_digest",
        ):
            require_sha256(value.get(key), label=key)
        for key in ("selected_variant_ids", "selected_capability_ids"):
            rows = value.get(key)
            if (
                not isinstance(rows, Sequence)
                or isinstance(rows, (str, bytes, bytearray))
                or not all(isinstance(item, str) and item for item in rows)
            ):
                raise ProgramFactsTypeError(f"{key} must be a string sequence")
            if list(rows) != sorted(rows) or len(rows) != len(set(rows)):
                raise ProgramFactsTypeError(f"{key} must be sorted and unique")
    else:
        if value.get("status") not in {
            "WRITTEN", "DEGRADED", "UNAVAILABLE", "FAILED", "STALE"
        }:
            raise ProgramFactsTypeError("public composition status is invalid")
        authority = value.get("authority_bindings")
        if not isinstance(authority, Mapping) or frozenset(authority) != (
            _PUBLIC_AUTHORITY_KEYS
        ):
            raise ProgramFactsTypeError("public authority denominator is not exact")
        for key, digest in authority.items():
            require_sha256(digest, label=f"authority_bindings.{key}")
        for key in (
            "analysis_scope", "coverage", "provider_executions", "internal_cells"
        ):
            item = value.get(key)
            if key == "analysis_scope":
                if not isinstance(item, Mapping):
                    raise ProgramFactsTypeError("analysis_scope must be an object")
            elif not isinstance(item, Sequence) or isinstance(
                item, (str, bytes, bytearray)
            ):
                raise ProgramFactsTypeError(f"{key} must be a sequence")
        require_sha256(
            value.get("public_projection_policy_digest"),
            label="public_projection_policy_digest",
        )
    for key in ("facts", "debt"):
        rows = value.get(key)
        if not isinstance(rows, Sequence) or isinstance(
            rows, (str, bytes, bytearray)
        ):
            raise ProgramFactsTypeError(f"{key} must be a sequence")
    return dict(value)


def _derived_legacy_public_model(
    inputs: Mapping[str, Any], permit_digest: str,
) -> dict[str, Any]:
    """Project the historical composer ABI into the documented public ABI.

    This compatibility path remains deterministic for the frozen composer
    corpus.  Production workspace composition supplies the eleven authorities
    directly and never uses these derived compatibility witnesses.
    """

    variants = list(inputs["selected_variant_ids"])
    capabilities = list(inputs["selected_capability_ids"])
    def digest(label: str, value: Any) -> str:
        return hashlib.sha256(
            canonical_json_bytes({"label": label, "value": value})
        ).hexdigest()
    authority = {
        "execution_authority_digest": inputs["execution_authority_digest"],
        "composition_authority_digest": inputs["composition_authority_digest"],
        "methodology_package_digest": inputs["methodology_package_digest"],
        "activation_decision_digest": digest("legacy-activation", permit_digest),
        "activation_permit_digest": permit_digest,
        "build_input_snapshot_digest": digest("legacy-build-input", variants),
        "candidate_universe_digest": digest("legacy-candidates", variants),
        "selected_scope_digest": digest("legacy-scope", variants),
        "capability_selection_digest": digest("legacy-capabilities", capabilities),
        "build_plan_digest": digest("legacy-build-plan", variants),
        "execution_set_digest": digest(
            "legacy-execution-set", [variants, capabilities, inputs["facts"]]
        ),
    }
    pairs = [(capability, variant) for capability in capabilities for variant in variants]
    coverage = [
        {
            "capability_id": capability,
            "build_variant_id": variant,
            "status": "PARTIAL" if inputs["debt"] else "OK",
            "unresolved_debt_ids": [
                str(row.get("debt_id")) for row in inputs["debt"]
                if isinstance(row, Mapping) and row.get("debt_id")
            ],
        }
        for capability, variant in pairs
    ]
    internal = [
        {
            "capability_id": row["capability_id"],
            "build_variant_id": row["build_variant_id"],
            "internal_state": "PARTIAL" if inputs["debt"] else "OK",
            "public_status": row["status"],
        }
        for row in coverage
    ]
    executions = [
        {
            "provider_id": "evm.slither.typed",
            "build_variant_id": variant,
            "capability_id": capability,
            "request_digest": digest("legacy-request", [variant, capability]),
            "request_size": 1,
            "environment_digest": authority["build_input_snapshot_digest"],
            "raw_cas": {
                "namespace": "program-facts-raw-v2",
                "digest": digest("legacy-raw", [variant, capability]),
                "size": 1,
            },
            "execution_set_row_digest": authority["execution_set_digest"],
        }
        for capability, variant in pairs
    ]
    return {
        "run_id": inputs["run_id"],
        "run_generation": inputs["run_generation"],
        "status": "DEGRADED" if inputs["debt"] else "WRITTEN",
        "authority_bindings": authority,
        "analysis_scope": {
            "claim": "EXACT_SELECTED_SCOPE_NOT_PROJECT_COMPLETE",
            "selected_candidate_ids": variants,
            "unresolved_debt_ids": [
                str(row.get("debt_id")) for row in inputs["debt"]
                if isinstance(row, Mapping) and row.get("debt_id")
            ],
        },
        "coverage": coverage,
        "provider_executions": executions,
        "internal_cells": internal,
        "public_projection_policy_digest": digest("legacy-projection", authority),
        "facts": list(inputs["facts"]),
        "debt": list(inputs["debt"]),
    }


def _pure_candidate_artifacts(
    inputs: Mapping[str, Any],
    *,
    authority_class: str,
    permit_digest: str,
) -> dict[str, bytes]:
    """Construct deterministic bytes without publication or discovery."""

    model = (
        dict(inputs)
        if frozenset(inputs) == _PUBLIC_SEALED_INPUT_KEYS
        else _derived_legacy_public_model(inputs, permit_digest)
    )
    debt_rows = list(model["debt"])
    status = str(model["status"])
    authority = dict(model["authority_bindings"])
    payload = {
        "schema_version": "plamen.mechanical_program_facts.v2",
        "status": status,
        "authority_bindings": authority,
        "analysis_scope": dict(model["analysis_scope"]),
        "coverage": list(model["coverage"]),
        "facts": list(model["facts"]),
        "terminal_negative_authority": False,
    }
    debt = {
        "schema_version": "plamen.mechanical_program_facts_debt.v2",
        "status": status,
        "authority_bindings": authority,
        "rows": debt_rows,
        "terminal_negative_authority": False,
    }
    receipt = {
        "schema_version": "plamen.mechanical_program_facts_receipt.v2",
        "run_id": model["run_id"],
        "run_generation": model["run_generation"],
        "status": status,
        "authority_bindings": authority,
        "provider_executions": list(model["provider_executions"]),
        "internal_cells": list(model["internal_cells"]),
        "public_projection_policy_digest": model[
            "public_projection_policy_digest"
        ],
        "receipt_body_sha256": "",
    }
    receipt["receipt_body_sha256"] = hashlib.sha256(
        canonical_json_bytes({
            key: value for key, value in receipt.items()
            if key != "receipt_body_sha256"
        })
    ).hexdigest()
    return {
        _PUBLIC_IDENTITIES[0]: canonical_file_bytes(payload),
        _PUBLIC_IDENTITIES[1]: canonical_file_bytes(receipt),
        _PUBLIC_IDENTITIES[2]: canonical_file_bytes(debt),
    }


def _validated_permit_for_composition(
    activation_permit_document: Mapping[str, Any] | object,
    *,
    provider_environment: Mapping[str, Any] | None,
    expected_run_id: str | None,
    expected_run_generation: int | None,
    expected_execution_authority_digest: str | None,
    expected_composition_authority_digest: str | None,
    expected_methodology_package_digest: str | None,
    expected_provider_environment_digest: str | None,
    expected_provider_package_digest: str | None,
    expected_native_host_receipt_digest: str | None,
    expected_independent_review_receipts: Mapping[str, str] | None,
    expected_issuer_policy_digest: str | None,
    expected_issuer_id: str | None,
    expected_release_id: str | None,
    expected_activation_decision_digest: str | None,
) -> dict[str, Any]:
    if not isinstance(activation_permit_document, Mapping):
        raise ProgramFactsTypeError("activation permit must be a mapping")
    return validate_activation_permit_v1(
        activation_permit_document,
        provider_environment=provider_environment,
        expected_run_id=expected_run_id,
        expected_run_generation=expected_run_generation,
        expected_execution_authority_digest=(
            expected_execution_authority_digest
        ),
        expected_composition_authority_digest=(
            expected_composition_authority_digest
        ),
        expected_methodology_package_digest=(
            expected_methodology_package_digest
        ),
        expected_provider_environment_digest=(
            expected_provider_environment_digest
        ),
        expected_provider_package_digest=expected_provider_package_digest,
        expected_native_host_receipt_digest=(
            expected_native_host_receipt_digest
        ),
        expected_independent_review_receipts=(
            expected_independent_review_receipts
        ),
        expected_issuer_policy_digest=expected_issuer_policy_digest,
        expected_issuer_id=expected_issuer_id,
        expected_release_id=expected_release_id,
        expected_activation_decision_digest=(
            expected_activation_decision_digest
        ),
    )


def _candidate_from_validated_inputs(
    inputs: Mapping[str, Any],
    permit: Mapping[str, Any],
) -> dict[str, Any]:
    if permit["run_id"] != inputs["run_id"]:
        raise ProgramFactsTypeError("production permit belongs to another run")
    if permit["run_generation"] != inputs["run_generation"]:
        raise ProgramFactsTypeError(
            "production permit belongs to another generation"
        )
    for key in (
        "execution_authority_digest",
        "composition_authority_digest",
        "methodology_package_digest",
    ):
        expected = (
            inputs["authority_bindings"][key]
            if frozenset(inputs) == _PUBLIC_SEALED_INPUT_KEYS
            else inputs[key]
        )
        if permit[key] != expected:
            raise ProgramFactsTypeError(
                f"production permit {key!r} differs from sealed inputs"
            )
    if frozenset(inputs) == _PUBLIC_SEALED_INPUT_KEYS:
        authority = inputs["authority_bindings"]
        for permit_key, authority_key in (
            ("activation_decision_digest", "activation_decision_digest"),
            ("permit_digest", "activation_permit_digest"),
        ):
            if permit[permit_key] != authority[authority_key]:
                raise ProgramFactsTypeError(
                    f"production permit {permit_key!r} differs from public authority"
                )
    permit_binding_digest = hashlib.sha256(
        canonical_json_bytes(permit)
    ).hexdigest()
    sealed_input_digest = hashlib.sha256(
        canonical_json_bytes(inputs)
    ).hexdigest()
    artifacts_by_identity = _pure_candidate_artifacts(
        inputs,
        authority_class=PRODUCTION_AUTHORITY_CLASS,
        permit_digest=permit["permit_digest"],
    )
    artifacts = tuple(
        (identity, bytes(artifacts_by_identity[identity]))
        for identity in _PUBLIC_IDENTITIES
    )
    preimage = _candidate_preimage(
        run_id=inputs["run_id"],
        run_generation=inputs["run_generation"],
        permit_digest=permit["permit_digest"],
        permit_binding_digest=permit_binding_digest,
        sealed_input_digest=sealed_input_digest,
        artifacts=artifacts,
    )
    digest = hashlib.sha256(canonical_json_bytes(preimage)).hexdigest()
    return {
        "schema_version": _CANDIDATE_SCHEMA,
        "authority_class": PRODUCTION_AUTHORITY_CLASS,
        "run_id": inputs["run_id"],
        "run_generation": inputs["run_generation"],
        "permit_digest": permit["permit_digest"],
        "permit_binding_digest": permit_binding_digest,
        "sealed_input_digest": sealed_input_digest,
        "artifacts": artifacts,
        "candidate_digest": digest,
    }


def _denied_candidate(
    inputs: Mapping[str, Any], denial: Mapping[str, Any]
) -> dict[str, Any]:
    reason = denial.get("reason")
    if not isinstance(reason, str) or not reason:
        raise ProgramFactsTypeError("denied permit envelope requires a reason")
    denial_digest = hashlib.sha256(canonical_json_bytes(denial)).hexdigest()
    if frozenset(inputs) == _PUBLIC_SEALED_INPUT_KEYS:
        model = deepcopy(dict(inputs))
        model["status"] = "UNAVAILABLE"
        authority = dict(model["authority_bindings"])
        authority["activation_permit_digest"] = denial_digest
        model["authority_bindings"] = authority
        model["facts"] = []
        debt_unsigned = {
            "debt_id": f"PFV2D-{denial_digest[:24]}",
            "reason_code": reason,
            "terminal_negative_authority": False,
        }
        model["debt"] = [debt_unsigned]
    else:
        model = _derived_legacy_public_model(inputs, denial_digest)
        model["status"] = "UNAVAILABLE"
        model["facts"] = []
        model["debt"] = [{
            "debt_id": f"PFV2D-{denial_digest[:24]}",
            "reason_code": reason,
            "terminal_negative_authority": False,
        }]
    sealed_digest = hashlib.sha256(canonical_json_bytes(inputs)).hexdigest()
    artifacts_by_identity = _pure_candidate_artifacts(
        model,
        authority_class="ABSENT_DENIED",
        permit_digest=denial_digest,
    )
    artifacts = tuple(
        (identity, bytes(artifacts_by_identity[identity]))
        for identity in _PUBLIC_IDENTITIES
    )
    preimage = _candidate_preimage(
        run_id=str(inputs["run_id"]),
        run_generation=int(inputs["run_generation"]),
        permit_digest=denial_digest,
        permit_binding_digest=denial_digest,
        sealed_input_digest=sealed_digest,
        artifacts=artifacts,
    )
    preimage["authority_class"] = "ABSENT_DENIED"
    return {
        **preimage,
        "artifacts": artifacts,
        "candidate_digest": hashlib.sha256(
            canonical_json_bytes(preimage)
        ).hexdigest(),
        "status": "UNAVAILABLE",
        "positive_fact_count": 0,
        "positive_node_count": 0,
        "debt": list(model["debt"]),
    }


def compose_program_facts_v2_production(
    sealed_composition_inputs: Mapping[str, Any],
    activation_permit_document: Mapping[str, Any] | object,
    *,
    provider_environment: Mapping[str, Any] | None = None,
    expected_run_id: str | None = None,
    expected_run_generation: int | None = None,
    expected_execution_authority_digest: str | None = None,
    expected_composition_authority_digest: str | None = None,
    expected_methodology_package_digest: str | None = None,
    expected_provider_environment_digest: str | None = None,
    expected_provider_package_digest: str | None = None,
    expected_native_host_receipt_digest: str | None = None,
    expected_independent_review_receipts: Mapping[str, str] | None = None,
    expected_issuer_policy_digest: str | None = None,
    expected_issuer_id: str | None = None,
    expected_release_id: str | None = None,
    expected_activation_decision_digest: str | None = None,
) -> dict[str, Any]:
    sealed_inputs_snapshot = snapshot_sealed_composition_inputs_v1(
        sealed_composition_inputs
    )
    inputs = _validate_sealed_inputs(sealed_inputs_snapshot)
    if (
        isinstance(activation_permit_document, Mapping)
        and frozenset(activation_permit_document)
        == frozenset({"state", "reason"})
        and activation_permit_document.get("state") == "ABSENT_DENIED"
    ):
        return _denied_candidate(inputs, activation_permit_document)
    permit = _validated_permit_for_composition(
        activation_permit_document,
        provider_environment=provider_environment,
        expected_run_id=expected_run_id,
        expected_run_generation=expected_run_generation,
        expected_execution_authority_digest=(
            expected_execution_authority_digest
        ),
        expected_composition_authority_digest=(
            expected_composition_authority_digest
        ),
        expected_methodology_package_digest=(
            expected_methodology_package_digest
        ),
        expected_provider_environment_digest=(
            expected_provider_environment_digest
        ),
        expected_provider_package_digest=expected_provider_package_digest,
        expected_native_host_receipt_digest=(
            expected_native_host_receipt_digest
        ),
        expected_independent_review_receipts=(
            expected_independent_review_receipts
        ),
        expected_issuer_policy_digest=expected_issuer_policy_digest,
        expected_issuer_id=expected_issuer_id,
        expected_release_id=expected_release_id,
        expected_activation_decision_digest=(
            expected_activation_decision_digest
        ),
    )
    return _candidate_from_validated_inputs(inputs, permit)


def _normalize_untrusted_candidate(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProgramFactsTypeError("candidate must be a mapping")
    if frozenset(value) != _CANDIDATE_KEYS:
        raise ProgramFactsTypeError("candidate keys mismatch")
    artifacts_value = value.get("artifacts")
    if not isinstance(artifacts_value, Sequence) or isinstance(
        artifacts_value,
        (str, bytes, bytearray),
    ):
        raise ProgramFactsTypeError(
            "production candidate artifacts must be an ordered sequence"
        )
    artifacts: list[tuple[str, bytes]] = []
    for row in artifacts_value:
        if not isinstance(row, Sequence) or isinstance(
            row,
            (str, bytes, bytearray),
        ) or len(row) != 2:
            raise ProgramFactsTypeError(
                "production candidate artifact row is malformed"
            )
        identity, content = row
        if not isinstance(identity, str) or not identity:
            raise ProgramFactsTypeError(
                "production candidate artifact identity is invalid"
            )
        if type(content) is not bytes:
            raise ProgramFactsTypeError(
                "production candidate artifact content must be exact bytes"
            )
        artifacts.append((identity, content))
    if tuple(identity for identity, _ in artifacts) != _PUBLIC_IDENTITIES:
        raise ProgramFactsTypeError("candidate artifacts diverge")
    require_sha256(
        value.get("permit_digest"),
        label="production candidate permit digest",
    )
    require_sha256(
        value.get("permit_binding_digest"),
        label="production candidate permit binding digest",
    )
    require_sha256(
        value.get("sealed_input_digest"),
        label="production candidate sealed-input digest",
    )
    require_sha256(
        value.get("candidate_digest"),
        label="production candidate digest",
    )
    return {
        "schema_version": value["schema_version"],
        "authority_class": value["authority_class"],
        "run_id": value["run_id"],
        "run_generation": value["run_generation"],
        "permit_digest": value["permit_digest"],
        "permit_binding_digest": value["permit_binding_digest"],
        "sealed_input_digest": value["sealed_input_digest"],
        "artifacts": tuple(artifacts),
        "candidate_digest": value["candidate_digest"],
    }


def validate_production_composition_candidate(
    value: object,
    *,
    sealed_composition_inputs: Mapping[str, Any],
    activation_permit_document: Mapping[str, Any],
    provider_environment: Mapping[str, Any],
    expected_run_id: str,
    expected_run_generation: int,
    expected_execution_authority_digest: str,
    expected_composition_authority_digest: str,
    expected_methodology_package_digest: str,
    expected_provider_environment_digest: str,
    expected_provider_package_digest: str,
    expected_native_host_receipt_digest: str,
    expected_independent_review_receipts: Mapping[str, str],
    expected_issuer_policy_digest: str,
    expected_issuer_id: str,
    expected_release_id: str,
    expected_activation_decision_digest: str,
) -> dict[str, Any]:
    sealed_inputs_snapshot = snapshot_sealed_composition_inputs_v1(
        sealed_composition_inputs
    )
    observed = _normalize_untrusted_candidate(value)
    expected = compose_program_facts_v2_production(
        sealed_inputs_snapshot,
        activation_permit_document,
        provider_environment=provider_environment,
        expected_run_id=expected_run_id,
        expected_run_generation=expected_run_generation,
        expected_execution_authority_digest=(
            expected_execution_authority_digest
        ),
        expected_composition_authority_digest=(
            expected_composition_authority_digest
        ),
        expected_methodology_package_digest=(
            expected_methodology_package_digest
        ),
        expected_provider_environment_digest=(
            expected_provider_environment_digest
        ),
        expected_provider_package_digest=expected_provider_package_digest,
        expected_native_host_receipt_digest=(
            expected_native_host_receipt_digest
        ),
        expected_independent_review_receipts=(
            expected_independent_review_receipts
        ),
        expected_issuer_policy_digest=expected_issuer_policy_digest,
        expected_issuer_id=expected_issuer_id,
        expected_release_id=expected_release_id,
        expected_activation_decision_digest=(
            expected_activation_decision_digest
        ),
    )
    for key in (
        "schema_version",
        "authority_class",
        "run_id",
        "run_generation",
        "sealed_input_digest",
    ):
        if observed[key] != expected[key]:
            raise ProgramFactsTypeError(f"candidate {key} diverges")
    permit_digest_differs = (
        observed["permit_digest"] != expected["permit_digest"]
    )
    permit_binding_differs = (
        observed["permit_binding_digest"]
        != expected["permit_binding_digest"]
    )
    if permit_digest_differs and permit_binding_differs:
        raise ProgramFactsTypeError("candidate permit digest diverges")
    if permit_digest_differs:
        raise ProgramFactsTypeError("candidate permit_digest diverges")
    if permit_binding_differs:
        raise ProgramFactsTypeError(
            "candidate permit_binding_digest diverges"
        )
    if observed["artifacts"] != expected["artifacts"]:
        raise ProgramFactsTypeError("candidate artifacts diverge")
    if observed["candidate_digest"] != expected["candidate_digest"]:
        raise ProgramFactsTypeError("candidate candidate_digest diverges")
    return observed


def validate_test_support_packaging_exclusion_v1(
    *,
    test_support_path: Path,
    runtime_manifest_path: Path,
    entry_point_files: Sequence[Path],
) -> dict[str, Any]:
    support = Path(test_support_path).resolve(strict=True)
    repo_root = Path(__file__).resolve().parents[1]
    expected_root = (repo_root / "review_fixtures" / "program_facts_test_support").resolve()
    try:
        support.relative_to(expected_root)
    except ValueError as exc:
        raise ProgramFactsTypeError("test support is outside review_fixtures") from exc
    portable = support.relative_to(repo_root).as_posix()
    haystacks: list[tuple[str, str]] = []
    runtime = Path(runtime_manifest_path)
    if runtime.is_file():
        haystacks.append(
            (
                runtime.as_posix(),
                runtime.read_text(encoding="utf-8", errors="strict"),
            )
        )
    for raw_path in entry_point_files:
        path = Path(raw_path)
        if path.is_file():
            haystacks.append(
                (path.as_posix(), path.read_text(encoding="utf-8", errors="strict"))
            )
    needles = {
        portable,
        portable.replace("/", "\\"),
        "program_facts_test_support",
        "nonpublishing_composer_v1",
    }
    for source, text in haystacks:
        if any(needle in text for needle in needles):
            raise ProgramFactsTypeError(
                f"structural-test support appears in installed authority: {source}"
            )
    return {"accepted": True, "test_support_path": portable}


def validate_test_support_import_closure_v1(
    support_path: Path,
    *,
    forbidden_modules: set[str],
) -> dict[str, Any]:
    path = Path(support_path).resolve(strict=True)
    source = path.read_text(encoding="utf-8", errors="strict")
    tree = ast.parse(source, filename=str(path))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Call):
            target = node.func
            dynamic = (
                isinstance(target, ast.Name)
                and target.id == "__import__"
            ) or (
                isinstance(target, ast.Attribute)
                and target.attr == "import_module"
            )
            if dynamic:
                raise ProgramFactsTypeError(
                    "dynamic imports are forbidden in structural-test support"
                )
    for module in imported:
        for forbidden in forbidden_modules:
            if module == forbidden or module.startswith(f"{forbidden}."):
                raise ProgramFactsTypeError(
                    f"structural-test support imports forbidden module {module!r}"
                )
    return {"accepted": True, "imports": sorted(imported)}


__all__ = [
    "PRODUCTION_AUTHORITY_CLASS",
    "TEST_AUTHORITY_CLASS",
    "compose_program_facts_v2_production",
    "snapshot_sealed_composition_inputs_v1",
    "validate_production_composition_candidate",
    "validate_test_support_import_closure_v1",
    "validate_test_support_packaging_exclusion_v1",
]
