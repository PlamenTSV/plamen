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
    if frozenset(value) != _SEALED_INPUT_KEYS:
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
    for key in ("facts", "debt"):
        rows = value.get(key)
        if not isinstance(rows, Sequence) or isinstance(
            rows, (str, bytes, bytearray)
        ):
            raise ProgramFactsTypeError(f"{key} must be a sequence")
    return dict(value)


def _pure_candidate_artifacts(
    inputs: Mapping[str, Any],
    *,
    authority_class: str,
    permit_digest: str | None,
) -> dict[str, bytes]:
    """Construct deterministic bytes without publication or discovery."""

    common = {
        "run_id": inputs["run_id"],
        "run_generation": inputs["run_generation"],
        "execution_authority_digest": inputs["execution_authority_digest"],
        "composition_authority_digest": inputs["composition_authority_digest"],
        "methodology_package_digest": inputs["methodology_package_digest"],
        "authority_class": authority_class,
    }
    payload = {
        "schema_version": "plamen.mechanical_program_facts.v2",
        **common,
        "selected_variant_ids": list(inputs["selected_variant_ids"]),
        "selected_capability_ids": list(inputs["selected_capability_ids"]),
        "facts": list(inputs["facts"]),
    }
    debt = {
        "schema_version": "plamen.mechanical_program_facts_debt.v2",
        **common,
        "debt": list(inputs["debt"]),
        "terminal_negative_authority": False,
    }
    payload_bytes = canonical_file_bytes(payload)
    debt_bytes = canonical_file_bytes(debt)
    receipt = {
        "schema_version": "plamen.mechanical_program_facts_receipt.v2",
        **common,
        "permit_digest": permit_digest,
        "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
        "debt_sha256": hashlib.sha256(debt_bytes).hexdigest(),
    }
    return {
        _PUBLIC_IDENTITIES[0]: payload_bytes,
        _PUBLIC_IDENTITIES[1]: canonical_file_bytes(receipt),
        _PUBLIC_IDENTITIES[2]: debt_bytes,
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
        if permit[key] != inputs[key]:
            raise ProgramFactsTypeError(
                f"production permit {key!r} differs from sealed inputs"
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
        reason = activation_permit_document.get("reason")
        if not isinstance(reason, str) or not reason:
            raise ProgramFactsTypeError(
                "denied permit envelope requires a reason"
            )
        return {
            "status": "UNAVAILABLE",
            "authority_class": "ABSENT_DENIED",
            "positive_fact_count": 0,
            "positive_node_count": 0,
            "debt": [
                {
                    "reason": reason,
                    "terminal_negative_authority": False,
                }
            ],
        }
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
