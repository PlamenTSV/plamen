"""Red-to-green tests for the skeptic provider authority transaction.

These fixtures deliberately use a real fixture subprocess.  They exercise the
same stdout/provider receipt path as Claude without granting the test process
semantic negative authority.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import pytest

import phase_io_contracts as P
import skeptic_execution_work as S
from test_skeptic_execution_work_provider_v2 import (
    _case,
    assessment_digest,
)


def test_project_and_scratchpad_foreign_writes_are_restored_and_quarantined(
    tmp_path: Path,
) -> None:
    """Trusted reconciliation restores mutations if OS denial is bypassed.

    The production child is write-confined before launch, so a real fixture
    subprocess cannot create these mutations.  Mutate from the trusted parent
    here to exercise the independent defense-in-depth reconciliation path.
    """

    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    project.mkdir()
    scratch.mkdir()
    source = project / "src.sol"
    source.write_text("original source\n", encoding="utf-8")
    rogue = scratch / "verification_queue.md"
    restored_empty = project / "preserve-empty-directory"
    restored_empty.mkdir()
    rogue_empty = scratch / "rogue-empty-directory"
    request, _ = _case(
        scratch,
        project_root=project,
    )

    before = S._capture_boundary(request)
    source.write_text("tampered source\n", encoding="utf-8")
    rogue.write_text("rogue queue\n", encoding="utf-8")
    restored_empty.rmdir()
    rogue_empty.mkdir()
    offenders = S._reconcile_boundary(
        request,
        before,
        provider_ids=(
            request.layout.provider_shard_id,
            request.layout.retry_provider_shard_id,
        ),
        provider_id=request.layout.provider_shard_id,
    )

    assert set(offenders) == {
        "project:preserve-empty-directory",
        "project:src.sol",
        "scratchpad:rogue-empty-directory",
        "scratchpad:verification_queue.md",
    }
    assert source.read_text(encoding="utf-8") == "original source\n"
    assert not rogue.exists()
    assert restored_empty.is_dir()
    assert not rogue_empty.exists()
    assert not request.layout.canonical_output_path.exists()
    assert request.containment_debt_path.is_file()
    containment = json.loads(
        request.containment_debt_path.read_text(encoding="utf-8")
    )
    assert containment["state"] == "CONTAINMENT_VIOLATION"
    assert set(containment["offenders"]) == set(offenders)
    assert containment["failed"] == []
    quarantine = request.scratchpad / ".skeptic_execution_quarantine"
    assert any(path.is_file() for path in quarantine.rglob("*"))


def test_live_child_foreign_writes_are_denied_before_mutation(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    project.mkdir()
    scratch.mkdir()
    source = project / "src.sol"
    source.write_text("original source\n", encoding="utf-8")
    rogue = scratch / "verification_queue.md"
    restored_empty = project / "preserve-empty-directory"
    restored_empty.mkdir()
    rogue_empty = scratch / "rogue-empty-directory"
    raw_script = "\n".join(
        (
            "from pathlib import Path",
            "denied = 0",
            "actions = (",
            f"    lambda: Path({str(source)!r}).write_text("
            "'tampered source\\n', encoding='utf-8'),",
            f"    lambda: Path({str(rogue)!r}).write_text("
            "'rogue queue\\n', encoding='utf-8'),",
            f"    lambda: Path({str(restored_empty)!r}).rmdir(),",
            f"    lambda: Path({str(rogue_empty)!r}).mkdir(),",
            ")",
            "for action in actions:",
            "    try:",
            "        action()",
            "    except PermissionError:",
            "        denied += 1",
            "raise SystemExit(17 if denied == len(actions) else 31)",
        )
    )
    request, _ = _case(
        scratch,
        project_root=project,
        raw_script=raw_script,
    )

    with pytest.raises(S.SkepticExecutionIncomplete) as raised:
        S.execute_or_resume_skeptic_execution(
            request, parser_digest=assessment_digest
        )

    assert raised.value.provider_arm_path is not None
    assert raised.value.provider_debt_path is not None
    assert source.read_text(encoding="utf-8") == "original source\n"
    assert not rogue.exists()
    assert restored_empty.is_dir()
    assert not rogue_empty.exists()
    assert not request.layout.canonical_output_path.exists()
    assert not request.containment_debt_path.exists()
    assert not (
        request.scratchpad / ".skeptic_execution_quarantine"
    ).exists()


def test_success_writes_and_replays_compact_provider_authority_sidecar(
    tmp_path: Path,
) -> None:
    request, output = _case(tmp_path)
    observed = S.execute_or_resume_skeptic_execution(
        request, parser_digest=assessment_digest
    )
    authority = S.validate_skeptic_provider_authority(
        request, observed.authority_sidecar_path,
        parser_digest=assessment_digest,
    )

    assert authority["state"] == "VALIDATED_PROVIDER_PUBLICATION"
    assert authority["request_sha256"] == request.request_digest
    assert authority["packet_sha256"] == hashlib.sha256(
        request.packet_path.read_bytes()
    ).hexdigest()
    assert authority["arm_sha256"] == observed.provider_arm_sha256
    assert authority["completion_sha256"] == observed.provider_completion_sha256
    assert authority["publication_sha256"] == observed.provider_publish_sha256
    assert authority["output_sha256"] == hashlib.sha256(output).hexdigest()
    assert authority["executable_sha256"]
    assert authority["argv_sha256"]
    assert authority["authority_sha256"]

    resumed = S.execute_or_resume_skeptic_execution(
        request, parser_digest=assessment_digest
    )
    assert resumed == observed


def test_one_predecessor_bound_retry_is_allowed_but_never_a_third(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    project.mkdir()
    scratch.mkdir()
    output = b'{"rows":[{"result":"OPEN","work_item_id":"NEG-0001"}]}\n'
    script = "\n".join(
        (
            "from pathlib import Path",
            "import sys",
            f"provider_root = Path({str(scratch)!r}) / "
            "'.worker_execution_receipts'",
            "is_retry = any(",
            "    not debt.parent.name.endswith('-r1')",
            "    for debt in provider_root.glob('*/debt_*.json')",
            ")",
            f"sys.stdout.buffer.write({output!r}) if is_retry else None",
            "sys.stdout.buffer.flush()",
            "raise SystemExit(0 if is_retry else 17)",
        )
    )
    request, _ = _case(
        scratch,
        project_root=project,
        raw_script=script,
    )
    observed = S.execute_or_resume_skeptic_execution(
        request, parser_digest=assessment_digest
    )
    authority = json.loads(
        observed.authority_sidecar_path.read_text(encoding="utf-8")
    )
    assert authority["attempt"] == 2
    assert authority["predecessor_debt_sha256"]
    assert authority["predecessor_arm_sha256"]
    provider_root = scratch / ".worker_execution_receipts"
    assert {path.name for path in provider_root.iterdir() if path.is_dir()} == {
        request.layout.provider_shard_id,
        request.layout.retry_provider_shard_id,
    }
    original = provider_root / request.layout.provider_shard_id
    retry = provider_root / request.layout.retry_provider_shard_id
    assert len(tuple(original.glob("arm_*.json"))) == 1
    assert len(tuple(original.glob("debt_*.json"))) == 1
    assert len(tuple(original.glob("completion_*.json"))) == 0
    assert len(tuple(retry.glob("arm_*.json"))) == 1
    assert len(tuple(retry.glob("debt_*.json"))) == 0
    assert len(tuple(retry.glob("completion_*.json"))) == 1

    always_fail = "raise SystemExit(19)"
    fail_root = tmp_path / "failure" / ".scratchpad"
    fail_root.mkdir(parents=True)
    failed, _ = _case(
        fail_root,
        project_root=fail_root.parent,
        raw_script=always_fail,
    )
    with pytest.raises(S.SkepticExecutionIncomplete):
        S.execute_or_resume_skeptic_execution(
            failed, parser_digest=assessment_digest
        )
    failed_provider_root = fail_root / ".worker_execution_receipts"
    assert {
        path.name for path in failed_provider_root.iterdir() if path.is_dir()
    } == {
        failed.layout.provider_shard_id,
        failed.layout.retry_provider_shard_id,
    }
    for provider_id in (
        failed.layout.provider_shard_id,
        failed.layout.retry_provider_shard_id,
    ):
        attempt = failed_provider_root / provider_id
        assert len(tuple(attempt.glob("arm_*.json"))) == 1
        assert len(tuple(attempt.glob("debt_*.json"))) == 1
        assert len(tuple(attempt.glob("completion_*.json"))) == 0


@pytest.mark.parametrize(
    "workflow,work_unit,output_name",
    (
        (
            "application_skeptic",
            "worker.0001",
            "application_skeptic_assessments_0001.json",
        ),
        (
            "candidate_negative",
            "negative.worker.0001",
            "candidate_negative_skeptic_assessments_0001.json",
        ),
    ),
)
def test_worker_phaseio_owns_exact_provider_authority_publication(
    workflow: str, work_unit: str, output_name: str
) -> None:
    authority = S.skeptic_provider_authority_sidecar_name(
        workflow=workflow, canonical_output=output_name
    )
    with pytest.raises(ValueError, match="provider authority"):
        P.resolve_phase_io_contract(
            pipeline="sc", mode="thorough", ecosystem="evm", backend="claude",
            phase="application_skeptic", work_unit_id=work_unit,
            exact_outputs=(output_name,),
        )
    contract = P.resolve_phase_io_contract(
        pipeline="sc", mode="thorough", ecosystem="evm", backend="claude",
        phase="application_skeptic", work_unit_id=work_unit,
        exact_outputs=(output_name, authority),
    )
    assert {row.path for row in contract.outputs} == {
        output_name, authority,
    }
    expected_plan = (
        "candidate_negative_skeptic_work_plan.json"
        if workflow == "candidate_negative"
        else "application_skeptic_work_plan.json"
    )
    assert P.canonical_artifact_identity(
        "scratchpad", expected_plan
    ) in contract.immutable_inputs


def test_long_work_root_and_durable_canary_receipt_round_trip(tmp_path: Path) -> None:
    root = tmp_path
    # Long enough to exercise compact provider IDs while remaining below the
    # legacy Windows directory-creation ceiling of the pytest temp root.
    for index in range(1):
        root = root / (f"long-segment-{index}-" + "x" * 18)
    request, _ = _case(root)
    observed = S.execute_or_resume_skeptic_execution(
        request, parser_digest=assessment_digest
    )
    receipt = tmp_path / "durable-canary-receipt.json"
    written = S.write_skeptic_live_canary_receipt(
        request, observed, receipt,
        parser_digest=assessment_digest,
        canary_id="fixture-long-path",
    )
    payload = json.loads(written.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert payload["authority_sha256"]
    assert payload["receipt_sha256"]
