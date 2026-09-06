"""Pure Program Facts v2 publication-evidence and selection validation.

This cut provides the immutable transaction data model and replay laws.  It
does not write a generation, mutate ArtifactLedger, discover directories, or
adopt an unselected generation.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any

from program_facts_positive_composer import (
    validate_production_composition_candidate,
)
from program_facts_v2_contracts import (
    ProgramFactsTypeError,
    canonical_file_bytes,
    canonical_json_bytes,
    normalized_document,
    require_exact_keys,
    require_sha256,
    validate_signed_payload,
)


PUBLIC_IDENTITIES = (
    "mechanical_program_facts.v2.json",
    "mechanical_program_facts_receipt.v2.json",
    "mechanical_program_facts_debt.v2.json",
)
_ARM_SCHEMA = "program_facts_publication_arm.v1.schema.json"
_GENERATION_SCHEMA = "program_facts_public_generation.v1.schema.json"
_SELECTION_KEYS = frozenset(
    {
        "run_id",
        "run_generation",
        "phase",
        "work_unit_id",
        "contract_digest",
        "launch_digest",
        "expanded_input_set_digest",
        "composition_authority_digest",
        "generation_id",
        "prior_active",
        "generation_manifest",
        "publication_transaction",
        "logical_outputs",
    }
)
_PUBLICATION_PREIMAGE_KEYS = frozenset(
    {
        "run_id",
        "run_generation",
        "transaction_nonce",
        "phase",
        "work_unit_id",
        "contract_digest",
        "launch_digest",
        "expanded_input_set_digest",
        "composition_authority_digest",
        "prior_active",
    }
)
_PUBLIC_SCHEMA_BINDINGS = (
    "plamen.mechanical_program_facts.v2",
    "plamen.mechanical_program_facts_receipt.v2",
    "plamen.mechanical_program_facts_debt.v2",
)
_GENERATION_ID_RE = re.compile(r"^pfg-[0-9a-f]{32}$", re.ASCII)
_TRANSACTION_ID_RE = re.compile(r"^pftx-[0-9a-f]{32}$", re.ASCII)
_MANIFEST_BINDING_KEYS = frozenset(
    {"physical_path", "size", "full_file_sha256"}
)
_TRANSACTION_BINDING_KEYS = frozenset(
    {
        "transaction_id",
        "arm_physical_path",
        "arm_body_sha256",
        "arm_file_size",
        "arm_full_file_sha256",
    }
)
_OUTPUT_BINDING_KEYS = frozenset(
    {"logical_identity", "physical_path", "size", "full_file_sha256"}
)


@dataclass(frozen=True, slots=True)
class GenerationManifestBindingV1:
    physical_path: str
    size: int
    full_file_sha256: str


@dataclass(frozen=True, slots=True)
class PublicationTransactionBindingV1:
    transaction_id: str
    arm_physical_path: str
    arm_body_sha256: str
    arm_file_size: int
    arm_full_file_sha256: str


@dataclass(frozen=True, slots=True)
class LogicalOutputBindingV1:
    logical_identity: str
    physical_path: str
    size: int
    full_file_sha256: str


@dataclass(frozen=True, slots=True)
class ImmutableGenerationSelectionEvidenceV1:
    run_id: str
    run_generation: int
    phase: str
    work_unit_id: str
    contract_digest: str
    launch_digest: str
    expanded_input_set_digest: str
    composition_authority_digest: str
    generation_id: str
    prior_active: Mapping[str, Any]
    generation_manifest: GenerationManifestBindingV1
    publication_transaction: PublicationTransactionBindingV1
    logical_outputs: tuple[LogicalOutputBindingV1, ...]


def _validate_prior_active(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProgramFactsTypeError("prior ACTIVE state must be an object")
    normalized = dict(value)
    state = normalized.get("state")
    if state == "ABSENT":
        require_exact_keys(
            normalized,
            required=frozenset({"state"}),
            label="prior ACTIVE absent state",
        )
    elif state == "PRESENT":
        require_exact_keys(
            normalized,
            required=frozenset({"state", "generation_id", "selection_digest"}),
            label="prior ACTIVE present state",
        )
        generation_id = normalized["generation_id"]
        if (
            not isinstance(generation_id, str)
            or _GENERATION_ID_RE.fullmatch(generation_id) is None
        ):
            raise ProgramFactsTypeError("prior ACTIVE generation identity is invalid")
        require_sha256(
            normalized["selection_digest"],
            label="prior ACTIVE selection digest",
        )
    else:
        raise ProgramFactsTypeError("prior ACTIVE prestate diverges")
    return normalized


def _validate_publication_preimage(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProgramFactsTypeError("publication identity preimage must be an object")
    preimage = dict(value)
    require_exact_keys(
        preimage,
        required=_PUBLICATION_PREIMAGE_KEYS,
        label="publication identity preimage",
    )
    for key in ("run_id", "transaction_nonce", "phase", "work_unit_id"):
        if not isinstance(preimage[key], str) or not preimage[key]:
            raise ProgramFactsTypeError(f"publication preimage {key} is invalid")
    if (
        not isinstance(preimage["run_generation"], int)
        or isinstance(preimage["run_generation"], bool)
        or preimage["run_generation"] < 0
    ):
        raise ProgramFactsTypeError("publication preimage generation is invalid")
    if preimage["phase"] != "recon":
        raise ProgramFactsTypeError("publication preimage phase must be recon")
    if preimage["work_unit_id"] != "program_facts_bake_v2":
        raise ProgramFactsTypeError("publication preimage work unit is invalid")
    for key in (
        "contract_digest",
        "launch_digest",
        "expanded_input_set_digest",
        "composition_authority_digest",
    ):
        require_sha256(preimage[key], label=f"publication preimage {key}")
    preimage["prior_active"] = _validate_prior_active(preimage["prior_active"])
    return preimage


def derive_program_facts_publication_identities_v1(
    arm_preimage: Mapping[str, Any],
) -> dict[str, str]:
    """Derive path-safe transaction/generation IDs from the closed arm preimage."""

    preimage = _validate_publication_preimage(arm_preimage)
    generation_digest = hashlib.sha256(
        canonical_json_bytes(
            {
                "identity_class": "PROGRAM_FACTS_PUBLIC_GENERATION_V1",
                "public_schema_bindings": list(_PUBLIC_SCHEMA_BINDINGS),
                "arm_preimage": preimage,
            }
        )
    ).hexdigest()
    generation_id = f"pfg-{generation_digest[:32]}"
    transaction_digest = hashlib.sha256(
        canonical_json_bytes(
            {
                "identity_class": "PROGRAM_FACTS_PUBLICATION_TRANSACTION_V1",
                "public_schema_bindings": list(_PUBLIC_SCHEMA_BINDINGS),
                "arm_preimage": preimage,
                "generation_id": generation_id,
            }
        )
    ).hexdigest()
    return {
        "generation_id": generation_id,
        "transaction_id": f"pftx-{transaction_digest[:32]}",
    }


def _require_file_binding(
    row: Mapping[str, Any],
    *,
    exact_keys: frozenset[str],
    size_key: str,
    digest_key: str,
    label: str,
) -> None:
    require_exact_keys(row, required=exact_keys, label=label)
    size = row.get(size_key)
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise ProgramFactsTypeError(f"{label} size is invalid")
    require_sha256(row.get(digest_key), label=f"{label} digest")


def parse_immutable_generation_selection_v1(
    selection_record: Mapping[str, Any],
) -> ImmutableGenerationSelectionEvidenceV1:
    if not isinstance(selection_record, Mapping):
        raise ProgramFactsTypeError("generation selection must be an object")
    require_exact_keys(
        selection_record,
        required=_SELECTION_KEYS,
        label="generation selection",
    )
    for key in (
        "contract_digest",
        "launch_digest",
        "expanded_input_set_digest",
        "composition_authority_digest",
    ):
        require_sha256(selection_record.get(key), label=key)
    run_generation = selection_record.get("run_generation")
    if (
        not isinstance(run_generation, int)
        or isinstance(run_generation, bool)
        or run_generation < 0
    ):
        raise ProgramFactsTypeError("selection run_generation is invalid")
    for key in ("run_id", "phase", "work_unit_id", "generation_id"):
        if not isinstance(selection_record.get(key), str) or not selection_record[key]:
            raise ProgramFactsTypeError(f"selection {key} is invalid")
    if _GENERATION_ID_RE.fullmatch(selection_record["generation_id"]) is None:
        raise ProgramFactsTypeError("selection generation identity is not path-safe")
    if selection_record["phase"] != "recon":
        raise ProgramFactsTypeError("Program Facts v2 selection phase must be recon")
    if selection_record["work_unit_id"] != "program_facts_bake_v2":
        raise ProgramFactsTypeError(
            "Program Facts v2 selection work unit must be program_facts_bake_v2"
        )
    manifest = selection_record.get("generation_manifest")
    transaction = selection_record.get("publication_transaction")
    outputs = selection_record.get("logical_outputs")
    if not isinstance(manifest, Mapping) or not isinstance(transaction, Mapping):
        raise ProgramFactsTypeError("selection private evidence is missing")
    if not isinstance(outputs, list) or len(outputs) != 3:
        raise ProgramFactsTypeError("selection must bind exactly three outputs")
    _require_file_binding(
        manifest,
        exact_keys=_MANIFEST_BINDING_KEYS,
        size_key="size",
        digest_key="full_file_sha256",
        label="generation manifest binding",
    )
    _require_file_binding(
        transaction,
        exact_keys=_TRANSACTION_BINDING_KEYS,
        size_key="arm_file_size",
        digest_key="arm_full_file_sha256",
        label="publication transaction binding",
    )
    require_sha256(
        transaction.get("arm_body_sha256"),
        label="publication arm body digest",
    )
    if (
        not isinstance(transaction.get("transaction_id"), str)
        or _TRANSACTION_ID_RE.fullmatch(transaction["transaction_id"]) is None
    ):
        raise ProgramFactsTypeError("selection transaction identity is not path-safe")
    prior_active = _validate_prior_active(selection_record["prior_active"])
    parsed_outputs = []
    for index, row in enumerate(outputs):
        if not isinstance(row, Mapping):
            raise ProgramFactsTypeError("logical output binding must be an object")
        _require_file_binding(
            row,
            exact_keys=_OUTPUT_BINDING_KEYS,
            size_key="size",
            digest_key="full_file_sha256",
            label=f"logical output {index}",
        )
        if row.get("logical_identity") != PUBLIC_IDENTITIES[index]:
            raise ProgramFactsTypeError(
                "logical output identities are not the exact public denominator"
            )
        parsed_outputs.append(
            LogicalOutputBindingV1(
                logical_identity=row["logical_identity"],
                physical_path=row["physical_path"],
                size=row["size"],
                full_file_sha256=row["full_file_sha256"],
            )
        )
    return ImmutableGenerationSelectionEvidenceV1(
        run_id=selection_record["run_id"],
        run_generation=run_generation,
        phase=selection_record["phase"],
        work_unit_id=selection_record["work_unit_id"],
        contract_digest=selection_record["contract_digest"],
        launch_digest=selection_record["launch_digest"],
        expanded_input_set_digest=selection_record["expanded_input_set_digest"],
        composition_authority_digest=selection_record[
            "composition_authority_digest"
        ],
        generation_id=selection_record["generation_id"],
        prior_active=MappingProxyType(deepcopy(prior_active)),
        generation_manifest=GenerationManifestBindingV1(
            physical_path=manifest["physical_path"],
            size=manifest["size"],
            full_file_sha256=manifest["full_file_sha256"],
        ),
        publication_transaction=PublicationTransactionBindingV1(
            transaction_id=transaction["transaction_id"],
            arm_physical_path=transaction["arm_physical_path"],
            arm_body_sha256=transaction["arm_body_sha256"],
            arm_file_size=transaction["arm_file_size"],
            arm_full_file_sha256=transaction["arm_full_file_sha256"],
        ),
        logical_outputs=tuple(parsed_outputs),
    )


def _validate_physical_binding(
    *,
    content: bytes,
    size: int,
    digest: str,
    label: str,
) -> None:
    if len(content) != size:
        raise ProgramFactsTypeError(f"{label} size binding mismatch")
    if hashlib.sha256(content).hexdigest() != digest:
        raise ProgramFactsTypeError(f"{label} digest binding mismatch")


def validate_generation_selection_evidence_v1(
    *,
    arm: Mapping[str, Any],
    generation_manifest: Mapping[str, Any],
    logical_outputs: Mapping[str, bytes],
    selection_record: Mapping[str, Any],
) -> ImmutableGenerationSelectionEvidenceV1:
    for field, pattern in (
        ("generation_id", _GENERATION_ID_RE),
        ("transaction_id", _TRANSACTION_ID_RE),
    ):
        raw_identity = arm.get(field) if isinstance(arm, Mapping) else None
        if not isinstance(raw_identity, str) or pattern.fullmatch(raw_identity) is None:
            raise ProgramFactsTypeError(
                f"portable publication identifier {field!r} is invalid"
            )
    arm_value = normalized_document(
        arm,
        schema_name=_ARM_SCHEMA,
        label="publication arm",
    )
    manifest_value = normalized_document(
        generation_manifest,
        schema_name=_GENERATION_SCHEMA,
        label="generation manifest",
    )
    validate_signed_payload(arm_value, "arm_body_sha256")
    validate_signed_payload(manifest_value, "manifest_body_sha256")
    selection = parse_immutable_generation_selection_v1(selection_record)
    preimage = {
        key: deepcopy(arm_value[key]) for key in _PUBLICATION_PREIMAGE_KEYS
    }
    derived_identities = derive_program_facts_publication_identities_v1(preimage)
    if arm_value["generation_id"] != derived_identities["generation_id"]:
        raise ProgramFactsTypeError("derived generation_id diverges")
    if arm_value["transaction_id"] != derived_identities["transaction_id"]:
        raise ProgramFactsTypeError("derived transaction_id diverges")
    if dict(selection.prior_active) != arm_value["prior_active"]:
        raise ProgramFactsTypeError(
            "prior ACTIVE prestate diverges from publication arm"
        )
    expected_manifest_path = (
        f".program_facts_public_generations/{selection.generation_id}/"
        "generation_manifest.v1.json"
    )
    expected_arm_path = (
        ".program_facts_publication_transactions/"
        f"{selection.publication_transaction.transaction_id}/"
        "publication_arm.v1.json"
    )
    if selection.generation_manifest.physical_path != expected_manifest_path:
        raise ProgramFactsTypeError(
            "selection manifest path is not the bound generation path"
        )
    if (
        selection.publication_transaction.arm_physical_path
        != expected_arm_path
    ):
        raise ProgramFactsTypeError(
            "selection arm path is not the bound transaction path"
        )
    root_cross_bindings = {
        "run_id": selection.run_id,
        "run_generation": selection.run_generation,
        "composition_authority_digest": selection.composition_authority_digest,
        "generation_id": selection.generation_id,
    }
    for field, selected in root_cross_bindings.items():
        if arm_value[field] != selected or manifest_value[field] != selected:
            raise ProgramFactsTypeError(
                f"arm/manifest/selection root field {field!r} diverges"
            )
    for field in (
        "phase",
        "work_unit_id",
        "contract_digest",
        "launch_digest",
        "expanded_input_set_digest",
    ):
        if arm_value[field] != getattr(selection, field):
            raise ProgramFactsTypeError(f"arm selection field {field!r} diverges")
    if arm_value["transaction_id"] != manifest_value["transaction_id"]:
        raise ProgramFactsTypeError("arm and manifest transaction IDs diverge")
    if (
        arm_value["transaction_id"]
        != selection.publication_transaction.transaction_id
    ):
        raise ProgramFactsTypeError("selection binds a different transaction")
    if (
        arm_value["arm_body_sha256"]
        != selection.publication_transaction.arm_body_sha256
    ):
        raise ProgramFactsTypeError("selection arm body digest diverges")
    arm_bytes = canonical_file_bytes(arm_value)
    manifest_bytes = canonical_file_bytes(manifest_value)
    _validate_physical_binding(
        content=arm_bytes,
        size=selection.publication_transaction.arm_file_size,
        digest=selection.publication_transaction.arm_full_file_sha256,
        label="publication arm",
    )
    _validate_physical_binding(
        content=manifest_bytes,
        size=selection.generation_manifest.size,
        digest=selection.generation_manifest.full_file_sha256,
        label="generation manifest",
    )
    if not isinstance(logical_outputs, Mapping):
        raise ProgramFactsTypeError("logical output bytes must be a mapping")
    if tuple(logical_outputs) != PUBLIC_IDENTITIES:
        raise ProgramFactsTypeError("logical output byte denominator diverges")
    if tuple(row["logical_identity"] for row in arm_value["logical_outputs"]) != PUBLIC_IDENTITIES:
        raise ProgramFactsTypeError("publication arm output denominator diverges")
    if tuple(
        row["logical_identity"] for row in manifest_value["logical_outputs"]
    ) != PUBLIC_IDENTITIES:
        raise ProgramFactsTypeError("generation output denominator diverges")
    for index, identity in enumerate(PUBLIC_IDENTITIES):
        content = logical_outputs[identity]
        if not isinstance(content, bytes):
            raise ProgramFactsTypeError("logical output content must be bytes")
        arm_row = arm_value["logical_outputs"][index]
        manifest_row = manifest_value["logical_outputs"][index]
        selected_row = selection.logical_outputs[index]
        size = len(content)
        digest = hashlib.sha256(content).hexdigest()
        if (
            arm_row["expected_size"] != size
            or arm_row["expected_sha256"] != digest
            or manifest_row["size"] != size
            or manifest_row["full_file_sha256"] != digest
            or selected_row.size != size
            or selected_row.full_file_sha256 != digest
        ):
            raise ProgramFactsTypeError(
                f"logical output {identity!r} binding diverges"
            )
        if (
            arm_row["candidate_relative_path"] != identity
            or manifest_row["physical_relative_path"] != identity
        ):
            raise ProgramFactsTypeError(
                f"logical output {identity!r} relative path diverges"
            )
        expected_output_path = (
            f".program_facts_public_generations/{selection.generation_id}/"
            f"{identity}"
        )
        if selected_row.physical_path != expected_output_path:
            raise ProgramFactsTypeError(
                f"logical output {identity!r} selection path diverges"
            )
    return selection


def publish_program_facts_v2_candidate(candidate: object, **_: Any) -> None:
    """Enforce the production carrier boundary; publication is a later cut."""

    validate_production_composition_candidate(candidate, **_)
    raise ProgramFactsTypeError(
        "publication integration is unavailable in the isolated R2.1 core cut"
    )


def load_program_facts_v2_from_active_selection(
    *,
    scratchpad: Path,
    active_selection: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Reject absent authority without searching generation directories."""

    if active_selection is None:
        raise ProgramFactsTypeError(
            "ACTIVE selection is required; directory discovery is forbidden"
        )
    selection = parse_immutable_generation_selection_v1(active_selection)
    return {
        "state": "ACTIVE_SELECTION_BOUND",
        "generation_id": selection.generation_id,
        "scratchpad": str(Path(scratchpad)),
    }


def validate_same_generation_idempotence_v1(
    *,
    existing_generation: Mapping[str, Any],
    candidate_generation: Mapping[str, Any],
    selection_record: Mapping[str, Any],
) -> dict[str, Any]:
    existing = normalized_document(
        existing_generation,
        schema_name=_GENERATION_SCHEMA,
        label="existing generation",
    )
    candidate = normalized_document(
        candidate_generation,
        schema_name=_GENERATION_SCHEMA,
        label="candidate generation",
    )
    validate_signed_payload(existing, "manifest_body_sha256")
    validate_signed_payload(candidate, "manifest_body_sha256")
    selection = parse_immutable_generation_selection_v1(selection_record)
    if existing["generation_id"] != candidate["generation_id"]:
        raise ProgramFactsTypeError("generation IDs differ")
    if existing["generation_id"] != selection.generation_id:
        raise ProgramFactsTypeError("selection binds another generation")
    if canonical_file_bytes(existing) != canonical_file_bytes(candidate):
        raise ProgramFactsTypeError(
            "same generation ID has divergent manifest bytes"
        )
    return {"accepted": True, "same_generation_reused": True}


def recover_program_facts_publication_v1(
    *,
    scratchpad: Path,
    active_selection: Mapping[str, Any] | None,
    unselected_arm: Mapping[str, Any] | None = None,
    unselected_generation: Mapping[str, Any] | None = None,
    logical_outputs: Mapping[str, bytes] | None = None,
) -> dict[str, Any]:
    """Return a conservative recovery disposition without adopting bytes."""

    del scratchpad, unselected_arm, unselected_generation, logical_outputs
    if active_selection is None:
        return {
            "state": "QUARANTINED_RECOMPOSE_REQUIRED",
            "selected": False,
            "adopted": False,
        }
    selection = parse_immutable_generation_selection_v1(active_selection)
    return {
        "state": "ACTIVE_SELECTION_REPLAY_REQUIRED",
        "generation_id": selection.generation_id,
        "selected": True,
        "adopted": False,
    }


def validate_publication_digest_graph_v1(
    *,
    arm: Mapping[str, Any],
    generation_manifest: Mapping[str, Any],
    logical_outputs: Mapping[str, bytes],
    selection_record: Mapping[str, Any],
    receipt_precommit_identity: Mapping[str, Any],
) -> dict[str, Any]:
    selection = validate_generation_selection_evidence_v1(
        arm=arm,
        generation_manifest=generation_manifest,
        logical_outputs=logical_outputs,
        selection_record=selection_record,
    )
    if not isinstance(receipt_precommit_identity, Mapping):
        raise ProgramFactsTypeError("receipt precommit identity must be an object")
    if frozenset(receipt_precommit_identity) != frozenset(
        {"transaction_id", "generation_id"}
    ):
        raise ProgramFactsTypeError("receipt precommit identity keys are not exact")
    if (
        receipt_precommit_identity["transaction_id"]
        != selection.publication_transaction.transaction_id
        or receipt_precommit_identity["generation_id"] != selection.generation_id
    ):
        raise ProgramFactsTypeError("receipt precommit identity diverges")
    forbidden_selection_fields = {
        "selection_digest",
        "artifact_ledger_digest",
        "ledger_record_digest",
    }
    if forbidden_selection_fields.intersection(arm) or forbidden_selection_fields.intersection(
        generation_manifest
    ):
        raise ProgramFactsTypeError("publication digest graph contains a cycle")
    return {
        "accepted": True,
        "digest_graph": (
            "receipt_precommit->arm->outputs->manifest->ledger_selection"
        ),
    }


__all__ = [
    "derive_program_facts_publication_identities_v1",
    "GenerationManifestBindingV1",
    "ImmutableGenerationSelectionEvidenceV1",
    "LogicalOutputBindingV1",
    "PUBLIC_IDENTITIES",
    "PublicationTransactionBindingV1",
    "load_program_facts_v2_from_active_selection",
    "parse_immutable_generation_selection_v1",
    "publish_program_facts_v2_candidate",
    "recover_program_facts_publication_v1",
    "validate_generation_selection_evidence_v1",
    "validate_publication_digest_graph_v1",
    "validate_same_generation_idempotence_v1",
]
