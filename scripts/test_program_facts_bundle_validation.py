from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from program_facts_types import (
    ProgramFactsBundle,
    StructuralProgramFactsBundle,
    ProgramFactsTypeError,
    canonical_file_bytes,
    canonical_json_bytes,
    derive_debt_id,
    derive_program_facts_reuse_key,
    derive_source_manifest_digest,
    derive_stable_id,
    signed_payload,
    validate_program_facts_bundle_structural_test_only,
    validate_program_facts_debt,
    validate_program_facts_payload,
)
from audit_snapshot import build_audit_snapshot
from program_facts_source_manifest import (
    build_program_facts_source_manifest,
    capture_program_facts_audit_snapshot_authority,
    replay_program_facts_source_manifest,
)


H0 = "0" * 64


def _source_manifest() -> dict[str, object]:
    value: dict[str, object] = {
        "policy_version": "plamen.program_facts_source_scope.v1",
        "eligible_files": [],
        "excluded_files": [],
        "file_count": 0,
        "byte_count": 0,
        "manifest_digest": H0,
    }
    value["manifest_digest"] = derive_source_manifest_digest(value)
    return value


def _debt_row() -> dict[str, object]:
    variant_id = str(_variant()["build_variant_id"])
    row: dict[str, object] = {
        "debt_id": "PFD-" + "0" * 24,
        "reason": "PROVIDER_UNSUPPORTED_ECOSYSTEM",
        "scope_ids": [variant_id],
        "provider_id": "daml.unsupported.provider",
        "capability_id": "daml.unsupported.program_facts.v1",
        "build_variant_id": variant_id,
        "explanation": "DAML has no Stage-1 semantic Program Facts provider.",
        "evidence_refs": [],
        "retryable": False,
        "blocks_reuse": False,
        "terminal_negative_authority": False,
    }
    row["debt_id"] = derive_debt_id(row)
    return row


def _variant() -> dict[str, object]:
    semantic = {
        "ecosystem": "daml",
        "build_system": "unsupported",
        "build_root_id": "root-0",
        "manifest_digests": [],
        "dependency_closure_digest": H0,
        "compiler_identity_digest": H0,
        "profile": "default",
        "features": [],
        "tags": [],
        "remappings": [],
        "defines": [],
        "target_triples": [],
        "generated_source_policy": "BOUND_EXCLUDED",
    }
    digest = hashlib.sha256(canonical_json_bytes(semantic)).hexdigest()
    return {
        "build_variant_id": f"PFB-{digest[:24]}",
        **semantic,
        "variant_digest": digest,
    }


def _coverage(
    variant_id: str,
    *,
    status: str = "UNSUPPORTED",
    debt_ids: list[str] | None = None,
) -> dict[str, object]:
    semantic = {
        "capability_id": "daml.unsupported.program_facts.v1",
        "build_variant_id": variant_id,
        "status": status,
        "eligible_source_file_ids": [],
        "covered_source_file_ids": [],
        "excluded_source_file_ids": [],
        "unresolved_debt_ids": list(debt_ids or []),
        "denominator_digest": hashlib.sha256(
            canonical_json_bytes(
                {
                    "eligible_source_file_ids": [],
                    "excluded_source_file_ids": [],
                }
            )
        ).hexdigest(),
        "terminal_negative_authority": False,
    }
    return {
        "coverage_id": derive_stable_id("PFC", semantic),
        **semantic,
    }


def _payload(*, status: str = "UNSUPPORTED") -> dict[str, object]:
    variant = _variant()
    unsigned = {
        "schema_version": "plamen.mechanical_program_facts.v1",
        "canonicalization_version": "plamen.canonical_json.v1",
        "authority": {
            "semantic_authority": "ADDITIVE_PROPOSAL_ONLY",
            "terminal_negative_authority": False,
            "can_suppress": False,
            "can_demote": False,
            "can_refute": False,
            "can_mark_examined": False,
            "can_certify_clean": False,
        },
        "snapshot_ref": {
            "snapshot_digest": H0,
            "source_scope_digest": H0,
            "source_manifest_digest": _source_manifest()["manifest_digest"],
        },
        "ecosystem": "daml",
        "build_variants": [variant],
        "source_files": [],
        "provider_capability_refs": ["daml.unsupported.program_facts.v1"],
        "nodes": [],
        "occurrences": [],
        "facts": [],
        "coverage": [
            _coverage(
                str(variant["build_variant_id"]),
                status=status,
                debt_ids=[str(_debt_row()["debt_id"])]
                if status == "UNSUPPORTED"
                else [],
            )
        ],
    }
    return signed_payload(unsigned, "payload_sha256")


def _refresh_coverage_id(row: dict[str, object]) -> None:
    semantic = {key: value for key, value in row.items() if key != "coverage_id"}
    row["coverage_id"] = derive_stable_id("PFC", semantic)


def _debt(*, include_row: bool = True) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    if include_row:
        rows.append(_debt_row())
    unsigned = {
        "schema_version": "plamen.mechanical_program_facts_debt.v1",
        "snapshot_digest": H0,
        "source_manifest_digest": _source_manifest()["manifest_digest"],
        "authority": "MANDATORY_REVIEW_NO_NEGATIVE_INFERENCE",
        "debts": rows,
        "summary": {
            "by_reason": (
                {"PROVIDER_UNSUPPORTED_ECOSYSTEM": 1} if include_row else {}
            ),
            "affected_capabilities": (
                ["daml.unsupported.program_facts.v1"] if include_row else []
            ),
            "affected_source_file_ids": [],
            "has_blocking_reuse_debt": False,
        },
    }
    return signed_payload(unsigned, "debt_sha256")


def _receipt(
    payload: dict[str, object],
    debt: dict[str, object],
) -> dict[str, object]:
    payload_bytes = canonical_file_bytes(payload)
    debt_bytes = canonical_file_bytes(debt)
    unsigned = {
        "schema_version": "plamen.mechanical_program_facts_receipt.v1",
        "run_id": "unsupported-fixture",
        "status": "UNAVAILABLE",
        "audit_snapshot": {
            "snapshot_digest": H0,
            "source_scope_digest": H0,
            "audit_config_digest": H0,
            "methodology_digest": H0,
            "toolchain_digest": H0,
        },
        "source_authority_digest": H0,
        "source_manifest": _source_manifest(),
        "build_attempts": [],
        "provider_runs": [],
        "worker_transaction_refs": [],
        "phase_io": {
            "contract_digest": H0,
            "launch_digest": H0,
            "input_set_digest": H0,
            "work_unit_key": (
                "sc/thorough/daml/claude/recon/program_facts_bake"
            ),
            "ledger_binding_state": "PRECOMMIT",
            "ledger_record_digest": "",
        },
        "artifacts": {
            "facts": {
                "path": "mechanical_program_facts.v1.json",
                "document_sha256": payload["payload_sha256"],
                "file_sha256": hashlib.sha256(payload_bytes).hexdigest(),
                "size": len(payload_bytes),
            },
            "debt": {
                "path": "mechanical_program_facts_debt.v1.json",
                "document_sha256": debt["debt_sha256"],
                "file_sha256": hashlib.sha256(debt_bytes).hexdigest(),
                "size": len(debt_bytes),
            },
        },
        "reuse_key": H0,
    }
    unsigned["reuse_key"] = derive_program_facts_reuse_key(
        payload=payload,
        receipt=unsigned,
    )
    return signed_payload(unsigned, "receipt_sha256")


def _bundle(
    payload: dict[str, object],
    debt: dict[str, object],
) -> StructuralProgramFactsBundle:
    receipt = _receipt(payload, debt)
    return validate_program_facts_bundle_structural_test_only(
        authority_mode="STRUCTURAL_TEST_ONLY",
        payload=payload,
        debt=debt,
        receipt=receipt,
        payload_file_bytes=canonical_file_bytes(payload),
        debt_file_bytes=canonical_file_bytes(debt),
        receipt_file_bytes=canonical_file_bytes(receipt),
        source_bytes_by_id={},
        source_authority_digest=H0,
    )


def test_signed_unsupported_payload_and_debt_validate_as_a_bundle() -> None:
    payload = _payload()
    debt = _debt()
    validate_program_facts_payload(payload, source_bytes_by_id={})
    validate_program_facts_debt(debt)
    bundle = _bundle(payload, debt)
    assert isinstance(bundle, StructuralProgramFactsBundle)
    assert bundle.production_authority_established is False
    assert bundle.authority_state == "STRUCTURAL_TEST_ONLY"
    assert not isinstance(bundle, ProgramFactsBundle)
    with pytest.raises(ProgramFactsTypeError, match="STRUCTURAL_TEST_ONLY"):
        validate_program_facts_bundle_structural_test_only(
            authority_mode="INSTALLED_PRODUCTION_AUTHORITY",
            payload=payload,
            debt=debt,
            receipt=_receipt(payload, debt),
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(
                _receipt(payload, debt)
            ),
            source_bytes_by_id={},
            source_authority_digest=H0,
        )


def test_production_bundle_uses_exact_replayed_source_authority(
    tmp_path,
    monkeypatch,
) -> None:
    import audit_snapshot as snapshot_module
    import program_facts_source_manifest as manifest_module

    monkeypatch.setattr(
        snapshot_module.shutil,
        "which",
        lambda _command: None,
    )
    monkeypatch.setattr(
        manifest_module,
        "_selector_source_digest",
        lambda: "6" * 64,
    )
    project = tmp_path / "empty-project"
    project.mkdir()
    source_path = project / "src" / "Main.daml"
    source_path.parent.mkdir()
    source_path.write_bytes(b"module Main where\n")
    config = {
        "project_root": str(project),
        "scratchpad": str(project / ".scratchpad"),
        "mode": "thorough",
        "pipeline": "sc",
        "language": "daml",
        "cli_backend": "codex",
        "scope_notes": "empty unsupported fixture",
    }
    snapshot = build_audit_snapshot(
        config,
        Path(__file__).resolve().parents[1],
    )
    snapshot_authority = capture_program_facts_audit_snapshot_authority(
        snapshot,
        config=config,
    )
    captured = build_program_facts_source_manifest(
        config,
        snapshot,
        compiled_source_paths=[],
    )
    replayed = replay_program_facts_source_manifest(
        captured.canonical_bytes,
        expected_snapshot_digest=snapshot["snapshot_digest"],
        expected_source_scope_digest=snapshot["components"]["source_scope"][
            "digest"
        ],
        source_bytes_by_id=captured.source_bytes_by_id,
        excluded_source_bytes_by_identity=(
            captured.excluded_source_bytes_by_identity
        ),
        capture_capability=captured.capture_capability,
    )

    payload = _payload()
    authoritative_manifest = json.loads(
        canonical_json_bytes(replayed.record["source_manifest"])
    )
    source_row = authoritative_manifest["eligible_files"][0]
    payload["source_files"] = [source_row]
    payload["coverage"][0]["eligible_source_file_ids"] = [
        source_row["source_file_id"]
    ]
    payload["coverage"][0]["denominator_digest"] = hashlib.sha256(
        canonical_json_bytes(
            {
                "eligible_source_file_ids": [source_row["source_file_id"]],
                "excluded_source_file_ids": [],
            }
        )
    ).hexdigest()
    _refresh_coverage_id(payload["coverage"][0])
    payload["snapshot_ref"].update(
        {
            "snapshot_digest": snapshot["snapshot_digest"],
            "source_scope_digest": snapshot["components"]["source_scope"][
                "digest"
            ],
            "source_manifest_digest": replayed.manifest_digest,
        }
    )
    payload = signed_payload(payload, "payload_sha256")
    debt = _debt()
    debt["snapshot_digest"] = snapshot["snapshot_digest"]
    debt["source_manifest_digest"] = replayed.manifest_digest
    debt = signed_payload(debt, "debt_sha256")
    receipt = _receipt(payload, debt)
    receipt["audit_snapshot"] = {
        "snapshot_digest": snapshot["snapshot_digest"],
        "source_scope_digest": snapshot["components"]["source_scope"][
            "digest"
        ],
        "audit_config_digest": snapshot["components"]["audit_config"][
            "digest"
        ],
        "methodology_digest": snapshot["components"]["methodology"]["digest"],
        "toolchain_digest": snapshot["components"]["toolchain"]["digest"],
    }
    receipt["source_authority_digest"] = replayed.authority_digest
    receipt["source_manifest"] = authoritative_manifest
    receipt["reuse_key"] = derive_program_facts_reuse_key(
        payload=payload,
        receipt=receipt,
    )
    receipt = signed_payload(receipt, "receipt_sha256")

    bundle = __import__("program_facts_types").validate_program_facts_bundle(
        payload=payload,
        debt=debt,
        receipt=receipt,
        payload_file_bytes=canonical_file_bytes(payload),
        debt_file_bytes=canonical_file_bytes(debt),
        receipt_file_bytes=canonical_file_bytes(receipt),
        source_bytes_by_id=captured.source_bytes_by_id,
        source_manifest_authority=replayed,
        audit_snapshot_authority=snapshot_authority,
        source_project_root=project,
        source_config=config,
    )
    assert isinstance(bundle, ProgramFactsBundle)

    with pytest.raises(
        ProgramFactsTypeError,
        match="exact audit-snapshot authority",
    ):
        __import__("program_facts_types").validate_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(receipt),
            source_bytes_by_id=captured.source_bytes_by_id,
            source_manifest_authority=replayed,
            audit_snapshot_authority=None,
            source_project_root=project,
            source_config=config,
        )

    class StatefulConfig(dict):
        def __init__(self, value):
            super().__init__(value)
            self.items_calls = 0

        def items(self):
            self.items_calls += 1
            if self.items_calls == 1:
                return super().items()
            changed = dict(self)
            changed["project_root"] = str(project / "substituted")
            return changed.items()

    stateful_config = StatefulConfig(config)
    assert isinstance(
        __import__("program_facts_types").validate_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(receipt),
            source_bytes_by_id=captured.source_bytes_by_id,
            source_manifest_authority=replayed,
            audit_snapshot_authority=snapshot_authority,
            source_project_root=project,
            source_config=stateful_config,
        ),
        ProgramFactsBundle,
    )
    assert stateful_config.items_calls == 1

    synthetic_registry = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "rules"
            / "program-facts-provider-registry.v1.json"
        ).read_text(encoding="utf-8")
    )
    with pytest.raises(ProgramFactsTypeError, match="exact loaded authority"):
        __import__("program_facts_types").validate_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(receipt),
            source_bytes_by_id=captured.source_bytes_by_id,
            source_manifest_authority=replayed,
            audit_snapshot_authority=snapshot_authority,
            source_project_root=project,
            source_config=config,
            provider_registry=synthetic_registry,
        )

    substituted = deepcopy(receipt)
    substituted["source_authority_digest"] = "f" * 64
    substituted["reuse_key"] = derive_program_facts_reuse_key(
        payload=payload,
        receipt=substituted,
    )
    substituted = signed_payload(substituted, "receipt_sha256")
    with pytest.raises(ProgramFactsTypeError, match="source-authority"):
        __import__("program_facts_types").validate_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=substituted,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(substituted),
            source_bytes_by_id=captured.source_bytes_by_id,
            source_manifest_authority=replayed,
            audit_snapshot_authority=snapshot_authority,
            source_project_root=project,
            source_config=config,
        )

    cross_snapshot = deepcopy(receipt)
    cross_snapshot["audit_snapshot"]["snapshot_digest"] = "f" * 64
    cross_snapshot["reuse_key"] = derive_program_facts_reuse_key(
        payload=payload,
        receipt=cross_snapshot,
    )
    cross_snapshot = signed_payload(cross_snapshot, "receipt_sha256")
    with pytest.raises(ProgramFactsTypeError, match="snapshot"):
        __import__("program_facts_types").validate_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=cross_snapshot,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(cross_snapshot),
            source_bytes_by_id=captured.source_bytes_by_id,
            source_manifest_authority=replayed,
            audit_snapshot_authority=snapshot_authority,
            source_project_root=project,
            source_config=config,
        )

    trusted_component_mutations = {
        "audit_config_digest": {
            "audit_config_digest": "f" * 64,
        },
        "methodology_digest": {
            "methodology_digest": "f" * 64,
        },
        "toolchain_digest": {
            "toolchain_digest": "f" * 64,
        },
        "composed_component_digests": {
            "audit_config_digest": "d" * 64,
            "methodology_digest": "e" * 64,
            "toolchain_digest": "f" * 64,
        },
    }
    unexpectedly_accepted: list[str] = []
    for label, mutations in trusted_component_mutations.items():
        substituted_identity = deepcopy(receipt)
        substituted_identity.pop("receipt_sha256")
        substituted_identity["audit_snapshot"].update(mutations)
        substituted_identity["reuse_key"] = derive_program_facts_reuse_key(
            payload=payload,
            receipt=substituted_identity,
        )
        substituted_identity = signed_payload(
            substituted_identity,
            "receipt_sha256",
        )
        try:
            __import__("program_facts_types").validate_program_facts_bundle(
                payload=payload,
                debt=debt,
                receipt=substituted_identity,
                payload_file_bytes=canonical_file_bytes(payload),
                debt_file_bytes=canonical_file_bytes(debt),
                receipt_file_bytes=canonical_file_bytes(
                    substituted_identity
                ),
                source_bytes_by_id=captured.source_bytes_by_id,
                source_manifest_authority=replayed,
                audit_snapshot_authority=snapshot_authority,
                source_project_root=project,
                source_config=config,
            )
        except ProgramFactsTypeError:
            continue
        unexpectedly_accepted.append(label)
    assert unexpectedly_accepted == []

    with pytest.raises(ProgramFactsTypeError, match="semantic replay"):
        __import__("program_facts_types").validate_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(receipt),
            source_bytes_by_id=captured.source_bytes_by_id,
            source_manifest_authority=replayed,
            audit_snapshot_authority=snapshot_authority,
            source_project_root=project,
            source_config=config,
            expected_source_ledger_binding={},
        )

    source_path.write_bytes(b"module Main where\nchanged = True\n")
    with pytest.raises(ProgramFactsTypeError, match="replay"):
        __import__("program_facts_types").validate_program_facts_bundle(
            payload=payload,
            debt=debt,
            receipt=receipt,
            payload_file_bytes=canonical_file_bytes(payload),
            debt_file_bytes=canonical_file_bytes(debt),
            receipt_file_bytes=canonical_file_bytes(receipt),
            source_bytes_by_id=captured.source_bytes_by_id,
            source_manifest_authority=replayed,
            audit_snapshot_authority=snapshot_authority,
            source_project_root=project,
            source_config=config,
        )


@pytest.mark.parametrize("kind", ["payload", "debt"])
def test_real_document_validator_rejects_self_digest_mismatch(kind: str) -> None:
    payload = _payload()
    debt = _debt()
    if kind == "payload":
        payload["ecosystem"] = "mixed"
    else:
        debt["authority"] = "changed"
    with pytest.raises(ProgramFactsTypeError):
        (
            validate_program_facts_payload(payload, source_bytes_by_id={})
            if kind == "payload"
            else validate_program_facts_debt(debt)
        )


def test_semantic_set_order_is_validated_not_silently_rewritten() -> None:
    payload = _payload()
    payload["provider_capability_refs"] = [
        "z.provider.capability",
        "a.provider.capability",
    ]
    payload = signed_payload(payload, "payload_sha256")
    with pytest.raises(ProgramFactsTypeError, match="sorted"):
        validate_program_facts_payload(payload, source_bytes_by_id={})


def test_duplicate_identity_is_rejected_even_when_rows_are_identical() -> None:
    payload = _payload()
    payload["build_variants"] = [
        deepcopy(payload["build_variants"][0]),
        deepcopy(payload["build_variants"][0]),
    ]
    payload = signed_payload(payload, "payload_sha256")
    with pytest.raises(ProgramFactsTypeError, match="duplicate"):
        validate_program_facts_payload(payload, source_bytes_by_id={})


def test_dangling_coverage_build_and_debt_references_are_rejected() -> None:
    payload = _payload()
    payload["coverage"][0]["build_variant_id"] = "PFB-" + "f" * 24
    _refresh_coverage_id(payload["coverage"][0])
    payload = signed_payload(payload, "payload_sha256")
    with pytest.raises(ProgramFactsTypeError, match="build"):
        validate_program_facts_payload(payload, source_bytes_by_id={})

    payload = _payload()
    debt = _debt(include_row=False)
    with pytest.raises(ProgramFactsTypeError, match="debt"):
        _bundle(payload, debt)


def test_empty_unsupported_bundle_is_never_accepted_as_clean() -> None:
    payload = _payload()
    payload["coverage"] = []
    payload = signed_payload(payload, "payload_sha256")
    with pytest.raises(
        ProgramFactsTypeError,
        match="UNSUPPORTED coverage|coverage accounting",
    ):
        _bundle(payload, _debt())

    with pytest.raises(ProgramFactsTypeError, match="debt"):
        _bundle(_payload(), _debt(include_row=False))


def test_full_coverage_requires_exact_denominator_and_zero_unresolved_debt() -> None:
    payload = _payload(status="FULL")
    payload["coverage"][0]["unresolved_debt_ids"] = ["PFD-unresolved"]
    _refresh_coverage_id(payload["coverage"][0])
    payload = signed_payload(payload, "payload_sha256")
    with pytest.raises(ProgramFactsTypeError, match="FULL coverage"):
        validate_program_facts_payload(payload, source_bytes_by_id={})


def test_debt_summary_must_exactly_replay_rows() -> None:
    debt = _debt()
    debt["summary"]["by_reason"]["PROVIDER_UNSUPPORTED_ECOSYSTEM"] = 2
    debt = signed_payload(debt, "debt_sha256")
    with pytest.raises(ProgramFactsTypeError, match="summary"):
        validate_program_facts_debt(debt)
