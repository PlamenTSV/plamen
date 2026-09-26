"""Adversarial assurance projection for Program Facts public/runtime debt."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import assurance_limitations as assurance
from plamen_types import Checkpoint
from program_facts_types import (
    canonical_file_bytes,
    canonical_json_bytes,
    derive_debt_id,
    derive_program_facts_reuse_key,
    derive_source_manifest_digest,
    derive_stable_id,
    signed_payload,
)


RUN_ID = "fixture-run"
H0 = "0" * 64
H1 = "1" * 64
H2 = "2" * 64


def _write_v1_bundle(tmp_path: Path) -> tuple[Path, Path]:
    variant_semantic = {
        "ecosystem": "evm",
        "build_system": "foundry",
        "build_root_id": "root-0",
        "manifest_digests": [],
        "dependency_closure_digest": H1,
        "compiler_identity_digest": H2,
        "profile": "default",
        "features": [],
        "tags": [],
        "remappings": [],
        "defines": [],
        "target_triples": [],
        "generated_source_policy": "BOUND_INCLUDED",
    }
    variant_digest = hashlib.sha256(
        canonical_json_bytes(variant_semantic)
    ).hexdigest()
    variant_id = f"PFB-{variant_digest[:24]}"
    variant = {
        "build_variant_id": variant_id,
        **variant_semantic,
        "variant_digest": variant_digest,
    }
    source_manifest = {
        "policy_version": "plamen.program_facts_source_scope.v1",
        "eligible_files": [],
        "excluded_files": [],
        "file_count": 0,
        "byte_count": 0,
        "manifest_digest": H0,
    }
    source_manifest["manifest_digest"] = derive_source_manifest_digest(
        source_manifest
    )
    row: dict[str, object] = {
        "debt_id": "PFD-" + "0" * 24,
        "reason": "PROVIDER_UNAVAILABLE",
        "scope_ids": [variant_id],
        "provider_id": "evm.slither.provider",
        "capability_id": "evm.slither.calls.v1",
        "build_variant_id": variant_id,
        "explanation": "Provider execution authority is unavailable.",
        "evidence_refs": [],
        "retryable": True,
        "blocks_reuse": True,
        "terminal_negative_authority": False,
    }
    row["debt_id"] = derive_debt_id(row)
    debt_id = str(row["debt_id"])
    debt = signed_payload(
        {
            "schema_version": "plamen.mechanical_program_facts_debt.v1",
            "snapshot_digest": H0,
            "source_manifest_digest": source_manifest["manifest_digest"],
            "authority": "MANDATORY_REVIEW_NO_NEGATIVE_INFERENCE",
            "debts": [row],
            "summary": {
                "by_reason": {"PROVIDER_UNAVAILABLE": 1},
                "affected_capabilities": ["evm.slither.calls.v1"],
                "affected_source_file_ids": [],
                "has_blocking_reuse_debt": True,
            },
        },
        "debt_sha256",
    )
    coverage_semantic = {
        "capability_id": "evm.slither.calls.v1",
        "build_variant_id": variant_id,
        "status": "UNSUPPORTED",
        "eligible_source_file_ids": [],
        "covered_source_file_ids": [],
        "excluded_source_file_ids": [],
        "unresolved_debt_ids": [debt_id],
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
    coverage = {
        "coverage_id": derive_stable_id("PFC", coverage_semantic),
        **coverage_semantic,
    }
    payload = signed_payload(
        {
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
                "source_scope_digest": H1,
                "source_manifest_digest": source_manifest["manifest_digest"],
            },
            "ecosystem": "evm",
            "build_variants": [variant],
            "source_files": [],
            "provider_capability_refs": ["evm.slither.calls.v1"],
            "nodes": [],
            "occurrences": [],
            "facts": [],
            "coverage": [coverage],
        },
        "payload_sha256",
    )
    payload_bytes = canonical_file_bytes(payload)
    debt_bytes = canonical_file_bytes(debt)
    receipt = {
        "schema_version": "plamen.mechanical_program_facts_receipt.v1",
        "run_id": RUN_ID,
        "status": "UNAVAILABLE",
        "audit_snapshot": {
            "snapshot_digest": H0,
            "source_scope_digest": H1,
            "audit_config_digest": H0,
            "methodology_digest": H1,
            "toolchain_digest": H2,
        },
        "source_authority_digest": H2,
        "source_manifest": source_manifest,
        "build_attempts": [],
        "provider_runs": [],
        "worker_transaction_refs": [],
        "phase_io": {
            "contract_digest": H0,
            "launch_digest": H1,
            "input_set_digest": H2,
            "work_unit_key": "sc/thorough/evm/codex/recon/program_facts_bake",
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
    receipt["reuse_key"] = derive_program_facts_reuse_key(
        payload=payload,
        receipt=receipt,
    )
    receipt = signed_payload(receipt, "receipt_sha256")

    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (scratchpad / "mechanical_program_facts.v1.json").write_bytes(
        canonical_file_bytes(payload)
    )
    (scratchpad / "mechanical_program_facts_receipt.v1.json").write_bytes(
        canonical_file_bytes(receipt)
    )
    (scratchpad / "mechanical_program_facts_debt.v1.json").write_bytes(
        canonical_file_bytes(debt)
    )
    return scratchpad, tmp_path


def _manifest(checkpoint: Checkpoint, scratchpad: Path, project: Path) -> dict:
    return assurance.build_current_assurance_manifest(
        checkpoint, scratchpad, project
    )


def _redigest(value: dict, field: str) -> bytes:
    unsigned = {key: item for key, item in value.items() if key != field}
    value[field] = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    return canonical_file_bytes(value)


def _runtime_debt(scratchpad: Path, issue: str = "provider custody unavailable") -> str:
    payload = {
        "schema_version": "plamen.program_facts_stage2_runtime_debt.v1",
        "run_id": RUN_ID,
        "debt_id": "PROGRAM-FACTS-STAGE2-EMIT-ONLY",
        "issue": issue,
        "consumer_activation": False,
    }
    raw = canonical_file_bytes(payload)
    (scratchpad / "_program_facts_stage2_runtime_debt.json").write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def _write_tool_ledger(
    scratchpad: Path,
    *,
    state: str,
    reason: str = "workspace tool is unadmitted",
    finding_count: int | None = None,
    schema_validated: bool = False,
) -> dict:
    record = {
        "capability_id": "opengrep.static-analysis",
        "tool": "opengrep",
        "state": state,
        "reason": reason,
        "finding_count": finding_count,
        "schema_validated": schema_validated,
        "artifacts": [],
        "provider_ref": "",
    }
    unsigned = {
        "schema": "plamen.tool-coverage-ledger",
        "schema_version": 1,
        "capabilities": {record["capability_id"]: record},
    }
    ledger = {
        **unsigned,
        "ledger_sha256": hashlib.sha256(canonical_file_bytes(unsigned)).hexdigest(),
    }
    # canonical_file_bytes and the assurance encoder share the same sorted,
    # compact JSON + LF canonicalization.
    (scratchpad / "tool_coverage_ledger.json").write_bytes(
        canonical_file_bytes(ledger)
    )
    return record


def _write_tool_debt(scratchpad: Path, record: dict) -> None:
    row = {
        "capability_id": record["capability_id"],
        "tool": record["tool"],
        "state": record["state"],
        "reason": record["reason"],
        "provider_ref_sha256": None,
    }
    unsigned = {
        "schema_version": "plamen.toolchain-coverage-debt.v1",
        "phase": "breadth",
        "unresolved_count": 1,
        "rows": [row],
    }
    payload = {
        **unsigned,
        "debt_sha256": hashlib.sha256(canonical_file_bytes(unsigned)).hexdigest(),
    }
    (scratchpad / "toolchain_coverage_debt.json").write_bytes(
        canonical_file_bytes(payload)
    )


def test_legacy_v1_typed_debt_is_losslessly_projected_with_provenance(
    tmp_path: Path,
) -> None:
    scratchpad, project = _write_v1_bundle(tmp_path)
    checkpoint = Checkpoint(run_id=RUN_ID)
    manifest = _manifest(checkpoint, scratchpad, project)
    debt = json.loads(
        (scratchpad / "mechanical_program_facts_debt.v1.json").read_text()
    )

    assert manifest["row_count"] == len(debt["debts"])
    assert manifest["clean_full_audit_claim_allowed"] is True
    assert {row["gate_class"] for row in manifest["rows"]} == {
        "PROGRAM_FACTS_COVERAGE"
    }
    assert {row["failure_instance_id"] for row in manifest["rows"]}
    assert len({row["failure_instance_id"] for row in manifest["rows"]}) == len(
        debt["debts"]
    )
    projected_ids = {
        row["source_authority"]["debt_id"] for row in manifest["rows"]
    }
    assert projected_ids == {row["debt_id"] for row in debt["debts"]}
    for row in manifest["rows"]:
        assert row["activation_state"] == "INACTIVE_SHADOW"
        assert row["consumer_activation"] is False
        assert row["terminal_success_blocking"] is False
        source = row["source_authority"]
        assert source["status"] == "UNAVAILABLE"
        assert source["public_version"] == 1
        for kind in ("payload", "receipt", "debt"):
            assert len(source[kind]["full_file_sha256"]) == 64
            assert len(source[kind]["document_sha256"]) == 64


def test_v1_tamper_and_partial_bundle_are_fail_visible(tmp_path: Path) -> None:
    scratchpad, project = _write_v1_bundle(tmp_path)
    checkpoint = Checkpoint(run_id=RUN_ID)
    debt_path = scratchpad / "mechanical_program_facts_debt.v1.json"
    debt_path.write_bytes(debt_path.read_bytes() + b" ")

    manifest = _manifest(checkpoint, scratchpad, project)
    assert manifest["row_count"] == 1
    row = manifest["rows"][0]
    assert row["gate_id"] == "program_facts.v1-authority-replay"
    assert row["source_authority"]["files"][debt_path.name]["state"] == "PRESENT"

    debt_path.unlink()
    manifest = _manifest(checkpoint, scratchpad, project)
    assert manifest["row_count"] == 1
    row = manifest["rows"][0]
    assert row["gate_id"] == "program_facts.v1-authority-replay"
    assert row["source_authority"]["files"][debt_path.name] == {
        "state": "ABSENT"
    }


def test_self_consistent_success_label_cannot_conceal_v1_debt(
    tmp_path: Path,
) -> None:
    scratchpad, project = _write_v1_bundle(tmp_path)
    receipt_path = scratchpad / "mechanical_program_facts_receipt.v1.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["status"] = "WRITTEN"
    receipt_path.write_bytes(_redigest(receipt, "receipt_sha256"))

    manifest = _manifest(
        Checkpoint(run_id=RUN_ID), scratchpad, project
    )
    assert manifest["row_count"] == 1
    assert manifest["rows"][0]["gate_id"] == "program_facts.v1-authority-replay"
    assert "conceals debt" in manifest["rows"][0]["message"]


def test_runtime_debt_requires_exact_checkpoint_binding_and_never_activates_consumer(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    receipt_sha = _runtime_debt(scratchpad)
    checkpoint = Checkpoint(
        run_id=RUN_ID,
        runtime_debts={"PROGRAM-FACTS-STAGE2-EMIT-ONLY": receipt_sha},
    )

    first = _manifest(checkpoint, scratchpad, tmp_path)
    second = _manifest(checkpoint, scratchpad, tmp_path)
    assert first == second
    assert first["row_count"] == 1
    row = first["rows"][0]
    assert row["gate_id"] == "program_facts.stage2-runtime"
    assert row["gate_class"] == "PROGRAM_FACTS_RUNTIME"
    assert row["source_authority"]["checkpoint_receipt_sha256"] == receipt_sha
    assert first["clean_full_audit_claim_allowed"] is True
    assert row["activation_state"] == "INACTIVE_SHADOW"
    assert row["terminal_success_blocking"] is False

    # A coherent replacement still differs from the checkpoint's immutable
    # binding and therefore cannot turn the runtime failure into clean state.
    _runtime_debt(scratchpad, issue="replacement tries to clear prior debt")
    tampered = _manifest(checkpoint, scratchpad, tmp_path)
    assert any(
        row["gate_id"] == "program_facts.runtime-debt-replay"
        for row in tampered["rows"]
    )


def test_missing_legacy_receipt_is_invalid_but_current_diagnostic_is_typed(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    checkpoint = Checkpoint(
        run_id=RUN_ID,
        runtime_debts={"PROGRAM-FACTS-STAGE2-EMIT-ONLY": "a" * 64},
    )
    missing = _manifest(checkpoint, scratchpad, tmp_path)
    assert {
        row["gate_id"] for row in missing["rows"]
    } >= {"program_facts.runtime-debt-replay"}

    receipt_sha = _runtime_debt(scratchpad)
    current = _manifest(Checkpoint(run_id=RUN_ID), scratchpad, tmp_path)
    assert current["row_count"] == 1
    row = current["rows"][0]
    assert row["gate_id"] == "program_facts.stage2-runtime"
    assert row["source_authority"]["checkpoint_receipt_sha256"] is None
    assert row["source_authority"]["full_file_sha256"] == receipt_sha
    assert row["activation_state"] == "INACTIVE_SHADOW"
    assert row["terminal_success_blocking"] is False
    assert current["clean_full_audit_claim_allowed"] is True


def test_activation_without_public_bundle_is_debt_and_inputs_are_bound(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    capture = scratchpad / "_program_facts_inputs" / "checkpoint_capture.v1.json"
    capture.parent.mkdir(parents=True)
    capture.write_text("{}\n", encoding="utf-8")

    manifest = _manifest(Checkpoint(run_id=RUN_ID), scratchpad, tmp_path)
    assert manifest["row_count"] == 1
    assert manifest["rows"][0]["gate_id"] == "program_facts.public-bundle-missing"
    paths = assurance.assurance_projection_input_paths(scratchpad)
    assert "_program_facts_inputs/checkpoint_capture.v1.json" in paths


def test_v1_projection_rows_are_sorted_unique_and_deterministic(
    tmp_path: Path,
) -> None:
    scratchpad, project = _write_v1_bundle(tmp_path)
    checkpoint = Checkpoint(run_id=RUN_ID)
    first = _manifest(checkpoint, scratchpad, project)
    second = _manifest(checkpoint, scratchpad, project)
    keys = [
        (
            row["phase"],
            row["work_unit_id"],
            row["gate_id"],
            row["failure_instance_id"],
        )
        for row in first["rows"]
    ]
    assert first == second
    assert keys == sorted(keys)
    assert len(keys) == len(set(keys))


def test_runtime_tool_debt_replays_from_ledger_with_exact_provenance(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    record = _write_tool_ledger(scratchpad, state="UNAVAILABLE")
    _write_tool_debt(scratchpad, record)

    manifest = _manifest(Checkpoint(run_id=RUN_ID), scratchpad, tmp_path)
    assert manifest["row_count"] == 1
    row = manifest["rows"][0]
    assert row["gate_id"] == "toolchain.opengrep.static-analysis"
    assert row["gate_class"] == "TOOLCHAIN_COVERAGE"
    assert set(row["source_authority"]) == {
        "schema_version",
        "ledger",
        "debt",
    }
    assert "tool_coverage_ledger.json" in assurance.assurance_projection_input_paths(
        scratchpad
    )


def test_tool_debt_missing_or_coherently_rewritten_away_from_ledger_fails_visible(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    record = _write_tool_ledger(scratchpad, state="UNAVAILABLE")
    missing = _manifest(Checkpoint(run_id=RUN_ID), scratchpad, tmp_path)
    assert missing["rows"][0]["gate_id"] == "toolchain.coverage-ledger-replay"

    rewritten = dict(record)
    rewritten["reason"] = "self-consistent replacement"
    _write_tool_debt(scratchpad, rewritten)
    mismatch = _manifest(Checkpoint(run_id=RUN_ID), scratchpad, tmp_path)
    assert mismatch["row_count"] == 1
    assert mismatch["rows"][0]["gate_id"] == "toolchain.coverage-ledger-replay"


def test_deceptive_tool_success_is_not_a_clean_assurance_state(tmp_path: Path) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_tool_ledger(
        scratchpad,
        state="SUCCEEDED",
        reason="claims success",
        finding_count=None,
        schema_validated=False,
    )
    manifest = _manifest(Checkpoint(run_id=RUN_ID), scratchpad, tmp_path)
    assert manifest["row_count"] == 1
    assert manifest["rows"][0]["gate_id"] == "toolchain.coverage-ledger-replay"
    assert "deceptive" in manifest["rows"][0]["message"]
