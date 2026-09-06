"""P0-I RED contracts for semantic axis candidate-negative replay.

The typed CLEAR adapter must not turn a merely well-signed application receipt
into a skeptic proposal.  It must replay the application against the immutable
PRE_AXIS canonical-prior pair, the exact execution-evidence authority, and the
current production source denominator.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import axis_canonical_prior as PRIOR
import axis_disposition as AXIS
import candidate_negative_authority as NEG
import plamen_driver as DRIVER
from plamen_types import SC_PHASES
import test_axis_disposition_v2_core_red as FIX


RUN_ID = "run-axis-negative-semantic-replay"
PIPELINE = "sc"
MODE = "thorough"
ECOSYSTEM = "evm"


def _semantic_kwargs(
    project: Path,
    scratchpad: Path,
) -> dict[str, Any]:
    # The immutable authority paths are fixed direct-child artifacts.  The
    # adapter resolves and validates both from the worklist scratchpad.
    assert (scratchpad / PRIOR.SNAPSHOT_NAME).is_file()
    assert (scratchpad / PRIOR.AUTHORITY_NAME).is_file()
    return {
        "project_root": project,
        "expected_pipeline": PIPELINE,
        "expected_mode": MODE,
        "expected_ecosystem": ECOSYSTEM,
    }


def _authorities(
    tmp_path: Path,
    *,
    disposition: str = "CLEAR",
    semantically_invalid_clear: bool = False,
) -> tuple[Path, Path, dict[str, Any], dict[str, Any], dict[str, Any]]:
    project, scratchpad = FIX._seed(tmp_path)
    worklist = FIX._worklist(
        project,
        FIX._matrix(
            [
                FIX._gap(
                    "A.settle(uint256)",
                    "contracts/A.sol",
                    "boundary",
                )
            ]
        ),
        run_id=RUN_ID,
    )
    prior = PRIOR.capture_axis_canonical_prior_authority(
        scratchpad,
        run_id=RUN_ID,
        worklist_hash=worklist["worklist_hash"],
        pipeline=PIPELINE,
        mode=MODE,
        ecosystem=ECOSYSTEM,
        source_paths=(),
    )
    evidence = FIX._zero_evidence(RUN_ID)
    item = worklist["items"][0]
    base_findings = b""
    canonical_ids = prior.aliases
    canonical_digest = prior.authority_digest
    if disposition == "FINDING":
        base_findings = FIX._action(item).encode("utf-8")
        row = {
            "work_item_id": item["work_item_id"],
            "disposition": "FINDING",
            "action_id": item["required_action_id"],
            "evidence": [],
            "rationale": "candidate requires independent verification",
        }
    elif semantically_invalid_clear:
        # This receipt is internally signed and loadable, but it was produced
        # against a different canonical-prior authority than the frozen pair.
        canonical_id = "CID-AAAAAAAAAAAAAAAA"
        canonical_digest = "d" * 64
        canonical_ids = {"OLD-1": canonical_id}
        row = {
            "work_item_id": item["work_item_id"],
            "disposition": "CLEAR",
            "action_id": "",
            "evidence": [
                {
                    "kind": "CANONICAL_PRIOR",
                    "canonical_id": canonical_id,
                    "authority_digest": canonical_digest,
                }
            ],
            "rationale": "the exact prior identity already covers this axis",
        }
    else:
        row = {
            "work_item_id": item["work_item_id"],
            "disposition": "CLEAR",
            "action_id": "",
            "evidence": [FIX._source_clear(item)],
            "rationale": "the exact current source guard closes this axis",
        }
    sidecar = FIX._sidecar(worklist, [row], run_id=RUN_ID)
    initial, plan = AXIS.reconcile_axis_dispositions_initial(
        worklist,
        base_dispositions_raw=sidecar,
        base_findings_raw=base_findings,
        execution_evidence_authority=evidence,
        canonical_prior_ids=canonical_ids,
        canonical_prior_authority_digest=canonical_digest,
        repair_cap=16,
    )
    final = AXIS.reconcile_axis_dispositions_final(
        worklist,
        initial_receipt=initial,
        repair_plan=plan,
        repair_execution_receipt=AXIS.build_axis_repair_execution_receipt(
            plan,
            state="NOT_REQUIRED",
        ),
        base_findings_raw=base_findings,
        execution_evidence_authority=evidence,
        canonical_prior_ids=canonical_ids,
        canonical_prior_authority_digest=canonical_digest,
    )
    AXIS.write_axis_disposition_v2_artifacts(
        scratchpad,
        worklist=worklist,
        execution_evidence_authority=evidence,
        application_receipt=final,
    )
    (scratchpad / "axis_coverage_findings.md").write_bytes(
        base_findings
    )
    return project, scratchpad, item, worklist, final


def _structural_ledger(
    scratchpad: Path,
) -> dict[str, Any]:
    return NEG.build_axis_clear_candidate_negative_ledger(
        worklist_path=scratchpad / AXIS.WORKLIST_NAME,
        application_receipt_path=(
            scratchpad / AXIS.AXIS_APPLICATION_RECEIPT_NAME
        ),
        expected_run_id=RUN_ID,
    )


def _validate_semantically(
    ledger: dict[str, Any],
    *,
    project: Path,
    scratchpad: Path,
) -> dict[str, Any]:
    return NEG.validate_axis_clear_candidate_negative_ledger(
        ledger,
        worklist_path=scratchpad / AXIS.WORKLIST_NAME,
        application_receipt_path=(
            scratchpad / AXIS.AXIS_APPLICATION_RECEIPT_NAME
        ),
        expected_run_id=RUN_ID,
        **_semantic_kwargs(project, scratchpad),
    )


def test_mutable_global_canonical_drift_does_not_revoke_frozen_replay(
    tmp_path: Path,
) -> None:
    project, scratchpad, item, _worklist, _final = _authorities(
        tmp_path
    )
    ledger = _structural_ledger(scratchpad)
    assert ledger["events"][0]["source_item_id"] == item["work_item_id"]

    # This mutable global projection may legitimately change after promotion.
    # The candidate-negative replay is historical and must ignore it.
    (scratchpad / "_canonical_finding_ids.json").write_text(
        json.dumps(
            {
                "schema_version": "mutable-global-fixture",
                "generated_at": "2099-01-01T00:00:00Z",
                "aliases": {"NEW-1": "CID-FFFFFFFFFFFFFFFF"},
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    replay = _validate_semantically(
        ledger,
        project=project,
        scratchpad=scratchpad,
    )
    assert replay == ledger


@pytest.mark.parametrize(
    "artifact_name",
    (PRIOR.SNAPSHOT_NAME, PRIOR.AUTHORITY_NAME),
)
def test_frozen_snapshot_or_authority_tamper_revokes_negative_replay(
    tmp_path: Path,
    artifact_name: str,
) -> None:
    project, scratchpad, _item, _worklist, _final = _authorities(
        tmp_path
    )
    ledger = _structural_ledger(scratchpad)
    path = scratchpad / artifact_name
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["run_id"] = "run-tampered"
    path.write_text(
        json.dumps(payload, sort_keys=True),
        encoding="utf-8",
    )

    with pytest.raises(NEG.CandidateNegativeAuthorityError):
        _validate_semantically(
            ledger,
            project=project,
            scratchpad=scratchpad,
        )


def test_current_production_source_drift_revokes_negative_replay(
    tmp_path: Path,
) -> None:
    project, scratchpad, _item, _worklist, _final = _authorities(
        tmp_path
    )
    ledger = _structural_ledger(scratchpad)
    (project / "contracts" / "A.sol").write_text(
        "contract A { function settle(uint256) external {} }\n",
        encoding="utf-8",
    )

    with pytest.raises(NEG.CandidateNegativeAuthorityError):
        _validate_semantically(
            ledger,
            project=project,
            scratchpad=scratchpad,
        )


def test_signed_but_wrong_external_clear_authority_cannot_emit_negative(
    tmp_path: Path,
) -> None:
    project, scratchpad, _item, _worklist, _final = _authorities(
        tmp_path,
        semantically_invalid_clear=True,
    )
    # Both JSON artifacts are structurally signed and independently loadable.
    # Semantic replay must still reject the pair because the receipt did not
    # use the frozen PRE_AXIS prior.
    worklist = AXIS.load_axis_worklist_v2(
        scratchpad / AXIS.WORKLIST_NAME
    )
    receipt = AXIS.load_axis_disposition_v2_receipt(
        scratchpad / AXIS.AXIS_APPLICATION_RECEIPT_NAME,
        worklist=worklist,
    )
    assert receipt["dispositions"][0]["disposition"] == "CLEAR"

    with pytest.raises(NEG.CandidateNegativeAuthorityError):
        NEG.build_axis_clear_candidate_negative_ledger(
            worklist_path=scratchpad / AXIS.WORKLIST_NAME,
            application_receipt_path=(
                scratchpad / AXIS.AXIS_APPLICATION_RECEIPT_NAME
            ),
            expected_run_id=RUN_ID,
            **_semantic_kwargs(project, scratchpad),
        )


def test_finding_only_application_emits_valid_semantic_zero_ledger(
    tmp_path: Path,
) -> None:
    project, scratchpad, _item, _worklist, _final = _authorities(
        tmp_path,
        disposition="FINDING",
    )
    ledger = NEG.build_axis_clear_candidate_negative_ledger(
        worklist_path=scratchpad / AXIS.WORKLIST_NAME,
        application_receipt_path=(
            scratchpad / AXIS.AXIS_APPLICATION_RECEIPT_NAME
        ),
        expected_run_id=RUN_ID,
        **_semantic_kwargs(project, scratchpad),
    )

    assert ledger["status"] == "CLEAN"
    assert ledger["event_count"] == 0
    assert ledger["events"] == []
    assert _validate_semantically(
        ledger,
        project=project,
        scratchpad=scratchpad,
    ) == ledger


def test_live_axis_negative_harvest_phaseio_binds_full_semantic_denominator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratchpad, _item, _worklist, _final = _authorities(
        tmp_path
    )
    phase = next(row for row in SC_PHASES if row.name == "axis_coverage")
    config: dict[str, Any] = {
        "project_root": str(project),
        "pipeline": PIPELINE,
        "mode": MODE,
        "language": ECOSYSTEM,
        "cli_backend": "claude",
        "_run_id": RUN_ID,
    }
    captured: dict[str, tuple[str, ...]] = {}

    monkeypatch.setattr(
        DRIVER,
        "build_axis_clear_candidate_negative_ledger",
        lambda **_kwargs: {"issues": []},
    )

    def capture_contract(
        *,
        exact_inputs: tuple[str, ...],
        **_kwargs: Any,
    ) -> tuple[object, object]:
        captured["exact_inputs"] = exact_inputs
        return object(), object()

    monkeypatch.setattr(
        DRIVER,
        "_candidate_negative_harvest_contract_and_launch",
        capture_contract,
    )
    monkeypatch.setattr(
        DRIVER,
        "_arm_deterministic_driver_work_unit",
        lambda **_kwargs: (True, []),
    )
    monkeypatch.setattr(
        DRIVER,
        "write_candidate_negative_ledger",
        lambda _root, _ledger: scratchpad
        / "candidate_negative_proposals_axis_coverage.json",
    )
    monkeypatch.setattr(
        DRIVER,
        "_commit_deterministic_driver_work_unit",
        lambda **_kwargs: [],
    )

    assert DRIVER._harvest_axis_clear_candidate_negative(
        phase,
        config,
        scratchpad,
    ) == []
    assert {
        AXIS.WORKLIST_NAME,
        AXIS.AXIS_APPLICATION_RECEIPT_NAME,
        AXIS.AXIS_EXECUTION_EVIDENCE_AUTHORITY_NAME,
        PRIOR.SNAPSHOT_NAME,
        PRIOR.AUTHORITY_NAME,
        "project::contracts/A.sol",
    }.issubset(set(captured["exact_inputs"]))
