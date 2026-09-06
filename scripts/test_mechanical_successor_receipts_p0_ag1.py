"""Adversarial contract for immutable mechanical verifier successors.

These fixtures intentionally exercise the receipt boundary directly.  The
mechanical executor may append evidence to verifier-authored Markdown only by
creating a digest-bound successor of the original verifier receipt.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest


SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from mechanical_successor_receipts import (  # noqa: E402
    ANNOTATION_SCHEMA_VERSION,
    RECEIPT_SCHEMA_VERSION,
    MechanicalSuccessorError,
    MechanicalSuccessorReceipt,
    apply_mechanical_successor,
    prepare_mechanical_successor,
)
import mechanical_successor_receipts as MSR  # noqa: E402
from queue_work_items import (  # noqa: E402
    OutputOwnership,
    QueueWorkPlan,
    QueueWorkShard,
    VerifierOutputIdentity,
    VerifierOutputReceipt,
)
import mechanical_verify as MV  # noqa: E402


RUN_ID = "11111111-1111-4111-8111-111111111111"
DRIVER_ID = "sha256:" + "d" * 64


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _result(*, status: str = "PASS", duration_s: float = 1.25) -> dict:
    tag = {
        "PASS": "[POC-PASS]",
        "FAIL": "[POC-FAIL]",
        "COMPILE_FAIL": "[CODE-TRACE]",
        "TIMEOUT": "[CODE-TRACE]",
        "NO_TEST_MATCH": "[CODE-TRACE]",
        "NO_TEST_FILE": "[CODE-TRACE]",
    }.get(status, "")
    return {
        "verify_file": "verify_H-01.md",
        "finding_id": "H-01",
        "language": "evm",
        "test_file_resolved": "test/H01.t.sol",
        "test_function": "test_H01",
        "test_command_used": "forge test --match-test test_H01 -vv",
        "status": status,
        "duration_s": duration_s,
        "stdout_tail": "1 passed; 0 failed",
        "recommended_tag": tag,
        "race_mode": False,
    }


def _proposal_bytes() -> bytes:
    value = {
        "schema_version": "plamen.severity_proposal.v1",
        "candidate_id": "H-01",
        "constituent_ids": ["H-01"],
        "impact": {
            "class": "High",
            "harmed_asset": "protected asset",
            "harmed_capability": "asset availability",
            "premise_id": "PREM-I",
            "premise_kind": "INTERNAL",
            "evidence_ids": ["EVID-I"],
            "proof_scope": "IN_SCOPE_EXECUTION",
        },
        "likelihood": {
            "class": "Medium",
            "actor": "unprivileged actor",
            "preconditions": ["reachable state"],
            "premise_id": "PREM-L",
            "premise_kind": "INTERNAL",
            "evidence_ids": ["EVID-L"],
            "proof_scope": "IN_SCOPE_EXECUTION",
        },
        "modifiers": [],
        "proposed_severity": "High",
        "adjustment": None,
        "constituent_premise_outcomes": {
            "H-01": {"impact": "SUPPORTED", "likelihood": "SUPPORTED"}
        },
    }
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _fixture(tmp_path: Path, *, original: bytes | None = None) -> tuple[Path, Path, dict]:
    original = original or (
        b"# Verification: H-01\n\n"
        b"**Verdict**: CONFIRMED\n"
        b"**Evidence Tag**: [CODE-TRACE]\n"
    )
    verify_path = tmp_path / "verify_H-01.md"
    verify_path.write_bytes(original)

    proposal = _proposal_bytes()
    proposal_path = tmp_path / "verify_H-01.severity_proposal.json"
    proposal_path.write_bytes(proposal)
    identity = VerifierOutputIdentity(
        work_item_id="H-01",
        queue_record_digest="a" * 64,
        work_plan_digest="b" * 64,
        shard_id="sc_verify_shard_a",
        expected_output_file="verify_H-01.md",
        expected_output_identity="scratchpad:verify_H-01.md",
    )
    (tmp_path / "verify_H-01.identity.json").write_text(
        json.dumps(identity.to_dict(), sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    verifier_receipt = VerifierOutputReceipt.bind(
        identity,
        original,
        severity_proposal=proposal,
        launch_digest="c" * 64,
        verifier_backend="claude",
    )
    (tmp_path / "verify_H-01.receipt.json").write_text(
        verifier_receipt.to_json(), encoding="utf-8"
    )

    result = _result()
    manifest_path = tmp_path / "mechanical_verify_manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "generated_at": "2026-07-18T12:00:00",
                "counts": {"PASS": 1},
                "results": [result],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return verify_path, manifest_path, result


def _apply(verify_path: Path, manifest_path: Path, result: dict):
    return apply_mechanical_successor(
        verify_path,
        result,
        manifest_path,
        run_identity=RUN_ID,
        driver_identity=DRIVER_ID,
    )


def test_fresh_successor_binds_every_authority_and_preserves_exact_prefix(tmp_path):
    verify_path, manifest_path, result = _fixture(tmp_path)
    original = verify_path.read_bytes()
    original_receipt = (tmp_path / "verify_H-01.receipt.json").read_bytes()
    manifest = manifest_path.read_bytes()

    outcome = _apply(verify_path, manifest_path, result)

    transformed = verify_path.read_bytes()
    assert outcome.transformed_written is True
    assert outcome.receipt_written is True
    assert transformed.startswith(original)
    receipt_path = tmp_path / "verify_H-01.mechanical_successor.receipt.json"
    receipt = MechanicalSuccessorReceipt.from_json(
        receipt_path.read_text(encoding="utf-8")
    )
    assert receipt.schema_version == RECEIPT_SCHEMA_VERSION
    assert receipt.annotation_schema_version == ANNOTATION_SCHEMA_VERSION
    assert receipt.original_verifier_receipt_sha256 == _sha(original_receipt)
    assert receipt.original_verifier_receipt_size_bytes == len(original_receipt)
    assert receipt.original_output_sha256 == _sha(original)
    assert receipt.original_output_size_bytes == len(original)
    assert receipt.transformed_output_sha256 == _sha(transformed)
    assert receipt.transformed_output_size_bytes == len(transformed)
    assert receipt.mechanical_manifest_sha256 == _sha(manifest)
    assert receipt.mechanical_manifest_size_bytes == len(manifest)
    assert receipt.run_identity == RUN_ID
    assert receipt.driver_identity == DRIVER_ID
    assert receipt.executor_identity == "sha256:" + _sha(
        Path(MV.__file__).resolve().read_bytes()
    )
    assert receipt.successor_identity == "sha256:" + _sha(
        Path(MSR.__file__).resolve().read_bytes()
    )
    assert "mechanical-verify-successor" in transformed.decode("utf-8")


def test_longer_finding_id_receipt_is_not_a_variant_of_shorter_id(tmp_path):
    verify_path, manifest_path, result = _fixture(tmp_path)
    (tmp_path / "verify_H-010.receipt.json").write_text("{}", encoding="utf-8")

    outcome = _apply(verify_path, manifest_path, result)

    assert outcome.receipt_written is True


def test_present_work_plan_must_semantically_own_the_verifier_output(tmp_path):
    verify_path, manifest_path, result = _fixture(tmp_path)
    owner = OutputOwnership(
        work_item_id="H-01",
        work_item_digest="a" * 64,
        expected_output_file="verify_H-01.md",
        expected_output_identity="scratchpad:verify_H-01.md",
    )
    shard = QueueWorkShard(
        shard_id="sc_verify_shard_a",
        ordered_work_item_ids=("H-01",),
        shard_record_digest="e" * 64,
        projection_digest="f" * 64,
        output_ownership=(owner,),
    )
    plan = QueueWorkPlan(
        planner_version="test.plan.v1",
        parent_record_set_digest="9" * 64,
        ordered_work_item_ids=("H-01",),
        shards=(shard,),
    )
    (tmp_path / "verification_queue.work_plan.json").write_bytes(
        (plan.to_json() + "\n").encode("utf-8")
    )

    with pytest.raises(MechanicalSuccessorError, match="work plan digest"):
        _apply(verify_path, manifest_path, result)


@pytest.mark.parametrize("target", ["markdown", "receipt", "identity", "proposal"])
def test_original_authority_tampering_rejects_without_mutation(tmp_path, target):
    verify_path, manifest_path, result = _fixture(tmp_path)
    original = verify_path.read_bytes()
    paths = {
        "markdown": verify_path,
        "receipt": tmp_path / "verify_H-01.receipt.json",
        "identity": tmp_path / "verify_H-01.identity.json",
        "proposal": tmp_path / "verify_H-01.severity_proposal.json",
    }
    paths[target].write_bytes(paths[target].read_bytes() + b"tamper")

    with pytest.raises(MechanicalSuccessorError):
        _apply(verify_path, manifest_path, result)

    if target != "markdown":
        assert verify_path.read_bytes() == original
    assert not (tmp_path / "verify_H-01.mechanical_successor.receipt.json").exists()


def test_manifest_must_contain_exactly_one_exact_result_row(tmp_path):
    verify_path, manifest_path, result = _fixture(tmp_path)
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["results"][0]["status"] = "FAIL"
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(MechanicalSuccessorError, match="manifest"):
        _apply(verify_path, manifest_path, result)


def test_manifest_global_counts_must_reconcile_with_all_rows(tmp_path):
    verify_path, manifest_path, result = _fixture(tmp_path)
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["counts"] = {"PASS": 2}
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(MechanicalSuccessorError, match="counts"):
        _apply(verify_path, manifest_path, result)


@pytest.mark.parametrize("sidecar", ["receipt", "identity"])
def test_semantically_equal_but_byte_tampered_original_sidecar_rejects(
    tmp_path, sidecar
):
    verify_path, manifest_path, result = _fixture(tmp_path)
    path = tmp_path / f"verify_H-01.{sidecar}.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")

    with pytest.raises(MechanicalSuccessorError, match="canonical"):
        _apply(verify_path, manifest_path, result)


@pytest.mark.parametrize("field,value", [
    ("run_identity", "22222222-2222-4222-8222-222222222222"),
    ("driver_identity", "sha256:" + "e" * 64),
])
def test_replay_with_different_execution_identity_rejects(tmp_path, field, value):
    verify_path, manifest_path, result = _fixture(tmp_path)
    _apply(verify_path, manifest_path, result)

    kwargs = {"run_identity": RUN_ID, "driver_identity": DRIVER_ID}
    kwargs[field] = value
    with pytest.raises(MechanicalSuccessorError):
        apply_mechanical_successor(verify_path, result, manifest_path, **kwargs)


def test_unbound_run_label_cannot_authorize_a_successor(tmp_path):
    verify_path, manifest_path, result = _fixture(tmp_path)

    with pytest.raises(MechanicalSuccessorError, match="UUIDv4"):
        apply_mechanical_successor(
            verify_path,
            result,
            manifest_path,
            run_identity="test-unbound",
            driver_identity=DRIVER_ID,
        )


def test_exact_replay_is_byte_and_mtime_noop(tmp_path):
    verify_path, manifest_path, result = _fixture(tmp_path)
    first = _apply(verify_path, manifest_path, result)
    receipt_path = first.receipt_path
    before = (
        verify_path.read_bytes(),
        receipt_path.read_bytes(),
        verify_path.stat().st_mtime_ns,
        receipt_path.stat().st_mtime_ns,
    )

    second = _apply(verify_path, manifest_path, result)

    after = (
        verify_path.read_bytes(),
        receipt_path.read_bytes(),
        verify_path.stat().st_mtime_ns,
        receipt_path.stat().st_mtime_ns,
    )
    assert second.transformed_written is False
    assert second.receipt_written is False
    assert after == before


def test_receipt_only_partial_is_repaired_deterministically(tmp_path):
    verify_path, manifest_path, result = _fixture(tmp_path)
    original = verify_path.read_bytes()
    prepared = prepare_mechanical_successor(
        verify_path,
        result,
        manifest_path,
        run_identity=RUN_ID,
        driver_identity=DRIVER_ID,
    )
    prepared.receipt_path.write_bytes(prepared.receipt_bytes)
    assert verify_path.read_bytes() == original

    outcome = _apply(verify_path, manifest_path, result)

    assert outcome.transformed_written is True
    assert outcome.receipt_written is False
    assert verify_path.read_bytes() == prepared.transformed_bytes


def test_transformed_only_partial_is_repaired_deterministically(tmp_path):
    verify_path, manifest_path, result = _fixture(tmp_path)
    prepared = prepare_mechanical_successor(
        verify_path,
        result,
        manifest_path,
        run_identity=RUN_ID,
        driver_identity=DRIVER_ID,
    )
    verify_path.write_bytes(prepared.transformed_bytes)
    assert not prepared.receipt_path.exists()

    outcome = _apply(verify_path, manifest_path, result)

    assert outcome.transformed_written is False
    assert outcome.receipt_written is True
    assert prepared.receipt_path.read_bytes() == prepared.receipt_bytes


def test_crash_after_receipt_write_leaves_only_repairable_partial(
    tmp_path, monkeypatch
):
    verify_path, manifest_path, result = _fixture(tmp_path)
    original = verify_path.read_bytes()
    real_atomic_write = MSR._atomic_write
    monkeypatch.setattr(
        MSR,
        "_atomic_write",
        lambda *_args: (_ for _ in ()).throw(OSError("simulated power loss")),
    )

    with pytest.raises(MechanicalSuccessorError, match="power loss"):
        _apply(verify_path, manifest_path, result)
    receipt_path = tmp_path / "verify_H-01.mechanical_successor.receipt.json"
    assert receipt_path.exists()
    assert verify_path.read_bytes() == original

    monkeypatch.setattr(MSR, "_atomic_write", real_atomic_write)
    repaired = _apply(verify_path, manifest_path, result)
    assert repaired.receipt_written is False
    assert repaired.transformed_written is True


def test_authority_mutation_inside_output_write_guard_never_reaches_markdown(
    tmp_path, monkeypatch
):
    verify_path, manifest_path, result = _fixture(tmp_path)
    original = verify_path.read_bytes()
    proposal_path = tmp_path / "verify_H-01.severity_proposal.json"
    real_atomic_write = MSR._atomic_write

    def mutate_authority_then_write(path: Path, data: bytes) -> None:
        proposal_path.write_bytes(proposal_path.read_bytes() + b" ")
        real_atomic_write(path, data)

    monkeypatch.setattr(MSR, "_atomic_write", mutate_authority_then_write)

    with pytest.raises(MechanicalSuccessorError, match="authority changed"):
        _apply(verify_path, manifest_path, result)
    assert verify_path.read_bytes() == original


def test_corrupt_partial_and_fabricated_self_hash_both_reject(tmp_path):
    verify_path, manifest_path, result = _fixture(tmp_path)
    prepared = prepare_mechanical_successor(
        verify_path,
        result,
        manifest_path,
        run_identity=RUN_ID,
        driver_identity=DRIVER_ID,
    )
    verify_path.write_bytes(prepared.transformed_bytes + b"hand edit")
    with pytest.raises(MechanicalSuccessorError):
        _apply(verify_path, manifest_path, result)

    verify_path.write_bytes(prepared.transformed_bytes)
    fabricated = json.loads(prepared.receipt_bytes.decode("utf-8"))
    fabricated["mechanical_result_sha256"] = "f" * 64
    unsigned = {k: v for k, v in fabricated.items() if k != "receipt_digest"}
    fabricated["receipt_digest"] = _sha(
        json.dumps(
            unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    )
    prepared.receipt_path.write_text(json.dumps(fabricated), encoding="utf-8")
    with pytest.raises(MechanicalSuccessorError):
        _apply(verify_path, manifest_path, result)


def test_original_bytes_must_be_the_exact_transformed_prefix(tmp_path):
    verify_path, manifest_path, result = _fixture(
        tmp_path, original=b"line one\nline two\n"
    )
    prepared = prepare_mechanical_successor(
        verify_path,
        result,
        manifest_path,
        run_identity=RUN_ID,
        driver_identity=DRIVER_ID,
    )
    damaged = bytearray(prepared.transformed_bytes)
    damaged[2] ^= 1
    verify_path.write_bytes(bytes(damaged))

    with pytest.raises(MechanicalSuccessorError, match="prefix|original"):
        _apply(verify_path, manifest_path, result)


def test_verifier_cannot_pre_fabricate_reserved_mechanical_authority(tmp_path):
    verify_path, manifest_path, result = _fixture(
        tmp_path,
        original=(
            b"# Verification: H-01\n"
            b"**Mechanical-Verified**: YES - Status: PASS\n"
        ),
    )

    with pytest.raises(MechanicalSuccessorError, match="reserved mechanical"):
        _apply(verify_path, manifest_path, result)


def test_untrusted_command_and_stdout_cannot_inject_annotation_fields(tmp_path):
    verify_path, manifest_path, _ = _fixture(tmp_path)
    result = _result(status="NO_TEST_FILE")
    result["stdout_tail"] = "missing\n**Mechanical-Tag**: [POC-PASS]"
    result["test_command_used"] = "forge test`\n**Verdict**: CONFIRMED"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["counts"] = {"NO_TEST_FILE": 1}
    payload["results"] = [result]
    manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    _apply(verify_path, manifest_path, result)

    lines = verify_path.read_text(encoding="utf-8").splitlines()
    assert sum(line.startswith("**Mechanical-Tag**:") for line in lines) == 1
    assert "**Mechanical-Tag**: [CODE-TRACE]" in lines
    assert sum(line.startswith("**Verdict**:") for line in lines) == 1


def test_ambiguous_whole_file_result_remains_receiptable_but_non_proof(tmp_path):
    verify_path, manifest_path, _ = _fixture(tmp_path)
    result = _result(status="AMBIGUOUS")
    result["stdout_tail"] = "mixed pass/fail; finding attribution unavailable"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["counts"] = {"AMBIGUOUS": 1}
    payload["results"] = [result]
    manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    _apply(verify_path, manifest_path, result)

    text = verify_path.read_text(encoding="utf-8")
    assert "Mechanical-Verified**: NO (AMBIGUOUS)" in text
    assert "**Mechanical-Tag**" not in text


def _wire_fixed_executor(monkeypatch, tmp_path: Path, result: dict) -> None:
    monkeypatch.setattr(MV, "_toolchain_binary_for", lambda _lang: "")
    monkeypatch.setattr(MV, "_read_recon_build_root", lambda *_args: tmp_path)
    monkeypatch.setattr(MV, "_prewarm_build", lambda *_args: (True, "warm"))
    monkeypatch.setattr(
        MV,
        "_run_test_for_finding",
        lambda *_args, **_kwargs: MV.ExecResult(**result),
    )


def test_live_executor_uses_successor_authority_and_exact_replay(tmp_path, monkeypatch):
    verify_path, manifest_path, result = _fixture(tmp_path)
    manifest_path.unlink()  # the live executor owns this artifact
    original = verify_path.read_bytes()
    _wire_fixed_executor(monkeypatch, tmp_path, result)

    first = MV.run_phase5b_mechanical_verify(
        tmp_path,
        tmp_path,
        "evm",
        run_identity=RUN_ID,
        driver_identity=DRIVER_ID,
    )
    receipt_path = tmp_path / "verify_H-01.mechanical_successor.receipt.json"
    first_state = (
        verify_path.read_bytes(),
        receipt_path.read_bytes(),
        manifest_path.read_bytes(),
        verify_path.stat().st_mtime_ns,
        receipt_path.stat().st_mtime_ns,
        manifest_path.stat().st_mtime_ns,
    )

    second = MV.run_phase5b_mechanical_verify(
        tmp_path,
        tmp_path,
        "evm",
        run_identity=RUN_ID,
        driver_identity=DRIVER_ID,
    )
    second_state = (
        verify_path.read_bytes(),
        receipt_path.read_bytes(),
        manifest_path.read_bytes(),
        verify_path.stat().st_mtime_ns,
        receipt_path.stat().st_mtime_ns,
        manifest_path.stat().st_mtime_ns,
    )
    assert first["files_annotated"] == 1
    assert first["successor_receipts"] == 1
    assert first["authority_rejections"] == 0
    assert second["files_annotated"] == 0
    assert second["successor_receipts"] == 1
    assert second["authority_rejections"] == 0
    assert first_state == second_state
    assert first_state[0].startswith(original)


def test_duration_only_rerun_preserves_each_exact_execution_record(
    tmp_path, monkeypatch
):
    verify_path, manifest_path, first_result = _fixture(tmp_path)
    manifest_path.unlink()
    results = iter((first_result, dict(first_result, duration_s=9.5)))
    monkeypatch.setattr(MV, "_toolchain_binary_for", lambda _lang: "")
    monkeypatch.setattr(MV, "_read_recon_build_root", lambda *_args: tmp_path)
    monkeypatch.setattr(MV, "_prewarm_build", lambda *_args: (True, "warm"))
    monkeypatch.setattr(
        MV,
        "_run_test_for_finding",
        lambda *_args, **_kwargs: MV.ExecResult(**next(results)),
    )

    first = MV.run_phase5b_mechanical_verify(
        tmp_path,
        tmp_path,
        "evm",
        run_identity=RUN_ID,
        driver_identity=DRIVER_ID,
    )
    second = MV.run_phase5b_mechanical_verify(
        tmp_path,
        tmp_path,
        "evm",
        run_identity=RUN_ID,
        driver_identity=DRIVER_ID,
    )

    evidence_files = sorted((tmp_path / "mechanical_execution_evidence").glob("*.json"))
    records = [json.loads(path.read_text(encoding="utf-8")) for path in evidence_files]
    assert first["authority_rejections"] == 0
    assert second["authority_rejections"] == 0
    assert {record["executed_result"]["duration_s"] for record in records} == {
        1.25,
        9.5,
    }
    assert len(records) == 2
    assert verify_path.read_bytes().count(b"mechanical-verify-successor") == 1


def test_live_executor_missing_authority_is_loud_and_non_mutating(tmp_path, monkeypatch):
    verify_path = tmp_path / "verify_H-01.md"
    verify_path.write_text("# verifier output\n", encoding="utf-8")
    original = verify_path.read_bytes()
    result = _result()
    _wire_fixed_executor(monkeypatch, tmp_path, result)

    summary = MV.run_phase5b_mechanical_verify(
        tmp_path,
        tmp_path,
        "evm",
        run_identity=RUN_ID,
        driver_identity=DRIVER_ID,
    )

    assert summary["files_annotated"] == 0
    assert summary["successor_receipts"] == 0
    assert summary["authority_rejections"] == 1
    assert verify_path.read_bytes() == original
    debt = json.loads(
        (tmp_path / "mechanical_successor_authority.json").read_text(
            encoding="utf-8"
        )
    )
    assert debt["status"] == "DEGRADED"
    assert debt["rejected_count"] == 1
    assert debt["rejections"][0]["finding_id"] == "H-01"
