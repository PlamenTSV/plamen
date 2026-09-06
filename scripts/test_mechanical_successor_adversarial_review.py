"""Independent red-team fixtures for the mechanical successor boundary.

These tests are deliberately test-only.  They encode authority properties that
must hold before the successor can be treated as more than a best-effort local
annotation.  A red test is evidence of an unresolved trust seam, not permission
for this reviewer to edit production code.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys

import pytest


SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import mechanical_successor_receipts as MSR  # noqa: E402
import mechanical_verify as MV  # noqa: E402
from mechanical_successor_receipts import (  # noqa: E402
    MechanicalSuccessorError,
    apply_mechanical_successor,
)
from queue_work_items import (  # noqa: E402
    VerifierOutputIdentity,
    VerifierOutputReceipt,
)


RUN_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
DRIVER_ID = "sha256:" + "d" * 64


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _result(*, finding_id: str = "H-01", status: str = "PASS") -> dict:
    tag = {
        "PASS": "[POC-PASS]",
        "FAIL": "[POC-FAIL]",
        "NO_TEST_FILE": "[CODE-TRACE]",
    }.get(status, "")
    return {
        "verify_file": f"verify_{finding_id}.md",
        "finding_id": finding_id,
        "language": "evm",
        "test_file_resolved": "test/H01.t.sol",
        "test_function": "test_H01",
        "test_command_used": "forge test --match-test test_H01 -vv",
        "status": status,
        "duration_s": 1.0,
        "stdout_tail": "1 passed; 0 failed",
        "recommended_tag": tag,
        "race_mode": False,
    }


def _valid_proposal() -> bytes:
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
    return _canonical(value)


def _fixture(
    tmp_path: Path, *, proposal: bytes | None = None, original: bytes | None = None
) -> tuple[Path, Path, dict]:
    output = original or (
        b"# Verification: H-01\n\n"
        b"**Verdict**: CONFIRMED\n"
        b"**Evidence Tag**: [CODE-TRACE]\n"
    )
    verify_path = tmp_path / "verify_H-01.md"
    verify_path.write_bytes(output)
    proposal_bytes = _valid_proposal() if proposal is None else proposal
    (tmp_path / "verify_H-01.severity_proposal.json").write_bytes(proposal_bytes)
    identity = VerifierOutputIdentity(
        work_item_id="H-01",
        queue_record_digest="a" * 64,
        work_plan_digest="b" * 64,
        shard_id="sc_verify_shard_a",
        expected_output_file="verify_H-01.md",
        expected_output_identity="scratchpad:verify_H-01.md",
    )
    (tmp_path / "verify_H-01.identity.json").write_bytes(
        _canonical(identity.to_dict())
    )
    receipt = VerifierOutputReceipt.bind(
        identity,
        output,
        severity_proposal=proposal_bytes,
        launch_digest="c" * 64,
        verifier_backend="claude",
    )
    (tmp_path / "verify_H-01.receipt.json").write_bytes(
        receipt.to_json().encode("utf-8")
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


def test_self_bound_but_schema_invalid_ag1_proposal_cannot_become_authority(tmp_path):
    verify_path, manifest_path, result = _fixture(
        tmp_path, proposal=b'{"level":"High"}\n'
    )

    with pytest.raises(MechanicalSuccessorError, match="proposal"):
        _apply(verify_path, manifest_path, result)

    assert not (tmp_path / "verify_H-01.mechanical_successor.receipt.json").exists()


@pytest.mark.skipif(os.name != "nt", reason="case-only lookup risk is Windows-specific")
@pytest.mark.parametrize(
    "canonical,wrong_case",
    [
        ("verify_H-01.receipt.json", "VERIFY_H-01.RECEIPT.JSON"),
        ("verify_H-01.identity.json", "VERIFY_H-01.IDENTITY.JSON"),
        (
            "verify_H-01.severity_proposal.json",
            "VERIFY_H-01.SEVERITY_PROPOSAL.JSON",
        ),
    ],
)
def test_wrong_case_ag1_sidecar_cannot_own_canonical_name(
    tmp_path, canonical, wrong_case
):
    verify_path, manifest_path, result = _fixture(tmp_path)
    source = tmp_path / canonical
    staging = tmp_path / (canonical + ".case-stage")
    source.replace(staging)
    staging.replace(tmp_path / wrong_case)

    with pytest.raises(MechanicalSuccessorError, match="case|canonical"):
        _apply(verify_path, manifest_path, result)


def test_casefold_duplicate_manifest_identity_is_cross_os_ambiguous(tmp_path):
    verify_path, manifest_path, result = _fixture(tmp_path)
    other = _result(finding_id="h-01")
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["counts"] = {"PASS": 2}
    payload["results"] = [result, other]
    manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    with pytest.raises(MechanicalSuccessorError, match="duplicate|collision|ambiguous"):
        _apply(verify_path, manifest_path, result)


def test_unrecognized_receipt_variant_is_loud_ownership_debt(tmp_path):
    verify_path, manifest_path, result = _fixture(tmp_path)
    (tmp_path / "verify_H-01.fabricated.receipt.json").write_text(
        "{}", encoding="utf-8"
    )

    with pytest.raises(MechanicalSuccessorError, match="receipt|variant|cardinality"):
        _apply(verify_path, manifest_path, result)


@pytest.mark.parametrize("separator", ["\u0085", "\u2028", "\u2029"])
def test_unicode_line_separator_cannot_inject_reserved_markdown_field(
    tmp_path, separator
):
    verify_path, manifest_path, _ = _fixture(tmp_path)
    result = _result(status="NO_TEST_FILE")
    result["stdout_tail"] = (
        "missing" + separator + "**Mechanical-Tag**: [POC-PASS]"
    )
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["counts"] = {"NO_TEST_FILE": 1}
    payload["results"] = [result]
    manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    _apply(verify_path, manifest_path, result)

    reserved = [
        line
        for line in verify_path.read_text(encoding="utf-8").splitlines()
        if line.startswith("**Mechanical-Tag**:")
    ]
    assert reserved == ["**Mechanical-Tag**: [CODE-TRACE]"]


@pytest.mark.parametrize("authority", ["manifest", "receipt", "proposal"])
def test_authority_change_between_prepare_and_receipt_create_is_rejected(
    tmp_path, monkeypatch, authority
):
    verify_path, manifest_path, result = _fixture(tmp_path)
    targets = {
        "manifest": manifest_path,
        "receipt": tmp_path / "verify_H-01.receipt.json",
        "proposal": tmp_path / "verify_H-01.severity_proposal.json",
    }
    target = targets[authority]
    original = verify_path.read_bytes()
    real_create = MSR._atomic_create

    def mutate_then_create(path: Path, data: bytes) -> None:
        target.write_bytes(target.read_bytes() + b" ")
        real_create(path, data)

    monkeypatch.setattr(MSR, "_atomic_create", mutate_then_create)

    with pytest.raises(MechanicalSuccessorError, match="changed|authority|digest"):
        _apply(verify_path, manifest_path, result)

    assert verify_path.read_bytes() == original


def test_output_change_after_last_check_is_not_overwritten(tmp_path, monkeypatch):
    verify_path, manifest_path, result = _fixture(tmp_path)
    real_write = MSR._atomic_write

    def intervene_then_write(path: Path, data: bytes) -> None:
        path.write_bytes(path.read_bytes() + b"concurrent edit")
        real_write(path, data)

    monkeypatch.setattr(MSR, "_atomic_write", intervene_then_write)

    with pytest.raises(MechanicalSuccessorError, match="changed|concurrent"):
        _apply(verify_path, manifest_path, result)


def test_pass_without_execution_attribution_cannot_mint_proof_tag(tmp_path):
    verify_path, manifest_path, _ = _fixture(tmp_path)
    result = _result(status="PASS")
    result.update(
        {
            "test_file_resolved": None,
            "test_function": None,
            "test_command_used": None,
            "stdout_tail": "",
        }
    )
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["results"] = [result]
    manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    with pytest.raises(MechanicalSuccessorError, match="PASS|proof|execution"):
        _apply(verify_path, manifest_path, result)


def _wire_executor(monkeypatch, tmp_path: Path, results: list[dict]) -> None:
    iterator = iter(results)
    monkeypatch.setattr(MV, "_toolchain_binary_for", lambda _lang: "")
    monkeypatch.setattr(MV, "_read_recon_build_root", lambda *_args: tmp_path)
    monkeypatch.setattr(MV, "_prewarm_build", lambda *_args: (True, "warm"))
    monkeypatch.setattr(
        MV,
        "_run_test_for_finding",
        lambda *_args, **_kwargs: MV.ExecResult(**next(iterator)),
    )


def test_equivalent_reexecution_with_volatile_duration_does_not_orphan_receipt(
    tmp_path, monkeypatch
):
    verify_path, manifest_path, first_result = _fixture(tmp_path)
    manifest_path.unlink()
    second_result = dict(first_result, duration_s=2.0)
    _wire_executor(monkeypatch, tmp_path, [first_result, second_result])

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

    assert first["authority_rejections"] == 0
    assert second["authority_rejections"] == 0
    assert second["successor_receipts"] == 1
    assert verify_path.read_bytes().endswith(b"\n")


def test_authority_rejection_is_phase_visible_debt_not_clean_status(
    tmp_path, monkeypatch
):
    verify_path = tmp_path / "verify_H-01.md"
    verify_path.write_text("# unreceipted verifier output\n", encoding="utf-8")
    result = _result()
    _wire_executor(monkeypatch, tmp_path, [result])

    summary = MV.run_phase5b_mechanical_verify(
        tmp_path,
        tmp_path,
        "evm",
        run_identity=RUN_ID,
        driver_identity=DRIVER_ID,
    )

    assert summary["authority_rejections"] == 1
    assert summary["status"] != "ok"
    debt = json.loads(
        (tmp_path / "mechanical_successor_authority.json").read_text(
            encoding="utf-8"
        )
    )
    assert debt["status"] == "DEGRADED"
