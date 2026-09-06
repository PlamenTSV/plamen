"""Adversarial cross-review fixtures for NC-5 and report transactions."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import mandatory_reverification as MR
import plamen_driver as D
import report_mutation_transaction as RT
from finding_producer_registry import canonical_digest, registry_digest


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _denominator() -> dict[str, object]:
    source_sha = "1" * 64
    return MR.build_mandatory_reverification_denominator(
        run_id="run-crossreview",
        source_bindings=[{"artifact": "source.md", "sha256": source_sha}],
        candidates=[
            {
                "obligation_kind": "ADDITIVE_REOPEN",
                "candidate_id": "INV-001",
                "source_candidate_id": "ASKP-1",
                "source_artifact": "source.md",
                "source_artifact_sha256": source_sha,
                "source_proposal_id": "ASP-001",
                "source_obligation_id": "APP-001",
                "candidate_content_sha256": "2" * 64,
                "premise": "A bounded transition needs independent replay.",
                "harm": "A protected state property may be violated.",
                "evidence": "src/Module.sol:10",
            }
        ],
    )


def test_primary_delivery_receipt_rejects_escaping_registered_source(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    inventory = scratch / "findings_inventory.md"
    inventory.write_text("# Findings Inventory\n", encoding="utf-8")
    outside = tmp_path / "outside.md"
    outside.write_text("outside source bytes\n", encoding="utf-8")
    unsigned = {
        "schema_version": "plamen.finding_delivery.v2",
        "registry_digest": registry_digest(),
        "inventory_sha256": "sha256:" + _sha(inventory.read_bytes()),
        "artifacts": [
            {
                "artifact": "../outside.md",
                "sha256": "sha256:" + _sha(outside.read_bytes()),
            }
        ],
        "actions": [],
    }
    payload = {**unsigned, "receipt_digest": canonical_digest(unsigned)}
    (scratch / "finding_delivery_receipt.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )

    with pytest.raises(MR.MandatoryReverificationError, match="safe|escape|symlink"):
        MR._load_current_delivery_receipt(scratch)


def test_completion_replay_rebinds_candidate_packet_and_retry_denominator(
    tmp_path: Path,
) -> None:
    denominator = _denominator()
    candidate = denominator["candidates"][0]
    row_unsigned = {
        "obligation_id": candidate["obligation_id"],
        "candidate_id": "INV-WRONG",
        "candidate_packet_sha256": "f" * 64,
        "assignment_binding_digest": "a" * 64,
        "assigned_work_item_id": "INV-001",
        "completion_state": "EXACTLY_COMPLETED",
        "output_sha256": "b" * 64,
        "receipt_sha256": "c" * 64,
        "terminal_negative_authority": False,
    }
    row = {**row_unsigned, "completion_binding_digest": _digest(row_unsigned)}
    unsigned = {
        "schema_version": MR.COMPLETION_SCHEMA,
        "run_id": denominator["run_id"],
        "denominator_digest": denominator["denominator_digest"],
        "assignment_authority_kind": "PRIMARY_QUEUE_ROSTER",
        "assignment_receipt_digest": "d" * 64,
        "status": "COMPLETED",
        "obligation_count": 1,
        "completed_obligation_count": 1,
        "source_input_debt_count": 0,
        "rows": [row],
        # A completed row cannot also remain in the retry denominator.
        "retry_work_item_ids": ["INV-001"],
        "terminal_negative_authority": False,
    }
    payload = {**unsigned, "completion_receipt_digest": _digest(unsigned)}
    path = tmp_path / MR.COMPLETION_FILE
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(MR.MandatoryReverificationError, match="candidate|retry"):
        MR.load_mandatory_completion(path, denominator=denominator)


def test_queue_transaction_rereads_every_postimage_before_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    denominator = _denominator()
    files = []
    for relative in MR._QUEUE_TRANSACTION_PATHS:
        post = f"post:{relative}\n".encode()
        files.append(
            {
                "path": relative,
                "pre_exists": False,
                "pre_sha256": None,
                "post_sha256": _sha(post),
                "post_b64": __import__("base64").b64encode(post).decode("ascii"),
            }
        )
    unsigned = {
        "schema_version": MR._QUEUE_TRANSACTION_SCHEMA,
        "run_id": denominator["run_id"],
        "denominator_digest": denominator["denominator_digest"],
        "state": "PREPARED",
        "files": files,
    }
    transaction = {**unsigned, "digest": _digest(unsigned)}
    original = MR._replace_mandatory_queue_transaction_file
    calls = 0

    def mutate_after_last_publish(path: Path, raw: bytes) -> None:
        nonlocal calls
        original(path, raw)
        calls += 1
        if calls == len(files):
            (tmp_path / str(files[0]["path"])).write_bytes(b"foreign-after-publish\n")

    monkeypatch.setattr(
        MR, "_replace_mandatory_queue_transaction_file", mutate_after_last_publish
    )
    with pytest.raises(MR.MandatoryReverificationError, match="postimage|foreign"):
        MR._publish_queue_transaction(tmp_path, transaction)


def test_report_transaction_rejects_normalized_sidecar_identity_collision(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    (tmp_path / "AUDIT_REPORT.md").write_bytes(b"before\n")

    with pytest.raises(RT.ReportMutationTransactionError, match="collision"):
        RT.apply_report_mutation_transaction(
            scratchpad=scratch,
            project_root=tmp_path,
            run_id="run-sidecar-collision",
            phase="report_dedup",
            post_report=b"after\n",
            exact_inputs=(),
            sidecars={"nested\\candidate.md": b"one\n", "nested/candidate.md": b"two\n"},
        )
    assert (tmp_path / "AUDIT_REPORT.md").read_bytes() == b"before\n"


def test_public_delivery_projection_revalidates_current_report_bytes(
    tmp_path: Path,
) -> None:
    from report_disposition_authority import reconcile_report_dispositions
    from test_report_disposition_authority_p0_r import RUN_ID, _setup

    scratch, project, _item, _report = _setup(
        tmp_path, status="REFUTED", disposition="BODY"
    )
    (scratch / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Candidate INV-001\n"
        "**Source IDs**: [INV-001]\n"
        "**Severity**: Medium\n"
        "**Location**: src/Vault.sol:10-20\n"
        "**Primary Artifact**: verification_queue.md\n"
        "**Description**: A protected transition remains reachable.\n"
        "**Impact**: A protected state property may be violated.\n",
        encoding="utf-8",
    )
    authority = reconcile_report_dispositions(
        scratch, project, run_id=RUN_ID
    )["authority"]
    assert authority["rows"][0]["mandatory_reverification"] is True
    denominator = MR.compile_report_reopen_denominator(
        scratch, run_id=RUN_ID, project_root=project
    )
    report = project / "AUDIT_REPORT.md"
    report.write_text("# Drifted report with no retained finding\n", encoding="utf-8")

    with pytest.raises(Exception, match="report|delivery|authority|drift") as raised:
        D._mandatory_public_report_routes(
            scratch, denominator, project_root=project
        )
    assert not isinstance(raised.value, TypeError)
