"""Independent adversarial acceptance tests for the P1-K live cutover.

These tests deliberately exercise authority boundaries that the happy-path
P1-K fixtures do not cover.  They are red until the report-evidence layer is
fail-closed at the final ship decision and every report writer is bound to the
typed manifest it consumed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import plamen_driver as driver
import report_evidence_authority as report_authority
from artifact_ledger import read_artifact_ledger
from phase_io_contracts import resolve_phase_io_contract
from plamen_types import Checkpoint, SC_PHASES
from report_evidence_authority import (
    ReportEvidenceError,
    finalize_report_evidence_delivery,
    materialize_report_evidence_runtime,
    project_report_evidence_markdown,
)
from test_report_evidence_runtime_p1_k import (
    _body_writer_phase,
    _repair_response_for_active_request,
    _write_inputs,
)
from test_verifier_output_receipt_runtime_p0_aj import _setup_plan
import plamen_mechanical as mechanical


def _config(project: Path, scratchpad: Path, *, run_id: str) -> dict[str, object]:
    return {
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "language": "evm",
        "mode": "thorough",
        "pipeline": "sc",
        "cli_backend": "claude",
        "_run_id": run_id,
    }


@pytest.mark.parametrize(
    "identity",
    ("L1-C-01", "F-L1-C-01", "RUSTSEC-2025-0001"),
)
def test_structured_candidate_identity_is_never_collapsed_to_suffix(
    identity: str,
) -> None:
    assert report_authority._candidate_ids(identity) == [identity]


def test_distinct_compound_candidate_namespaces_do_not_cross_bind() -> None:
    left = report_authority._candidate_ids("L1-C-01")
    right = report_authority._candidate_ids("F-L1-C-01")
    assert left == ["L1-C-01"]
    assert right == ["F-L1-C-01"]
    assert set(left).isdisjoint(right)


def _projected_report(scratchpad: Path, *, extra: str = "") -> str:
    runtime = materialize_report_evidence_runtime(scratchpad)
    report = """### [H-01] Paired accounting state can diverge

**Severity**: High
**Verdict**: CONFIRMED
**Location**: src/Module.sol:L10-L30

**Description**:
One transition updates one accounting leg without its pair.
"""
    if extra:
        report += "\n" + extra.rstrip() + "\n"
    return project_report_evidence_markdown(report, runtime["bundle"])


def test_duplicate_key_source_documents_cannot_collapse_the_report_denominator(
    tmp_path: Path,
) -> None:
    """Last-key-wins JSON must not silently turn a non-empty report into zero."""

    _write_inputs(tmp_path, execution_tag="[STATIC-TRACE]")
    records = json.loads(
        (tmp_path / "report_records.json").read_text(encoding="utf-8")
    )
    manifest_path = (
        tmp_path / "body_manifests" / "report_critical_high.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    # Both documents remain syntactically valid JSON.  A permissive parser
    # keeps only the final duplicate key and constructs an empty authority.
    (tmp_path / "report_records.json").write_text(
        "{"
        '"schema_version":"plamen.report_records.v1",'
        '"source":"report_index.md",'
        f'"active":{json.dumps(records["active"])},'
        '"active":[],"excluded":[],"consolidation_map":[]}'
        "\n",
        encoding="utf-8",
    )
    manifest_path.write_text(
        "{"
        '"shard":"report_critical_high",'
        f'"findings":{json.dumps(manifest["findings"])},'
        '"findings":[]}'
        "\n",
        encoding="utf-8",
    )

    with pytest.raises(ReportEvidenceError, match="duplicate key"):
        materialize_report_evidence_runtime(tmp_path)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("severity", "Low"),
        ("finding_id", "INV-999"),
        ("title", "Unrelated replacement title"),
        ("location", "src/Other.sol:L1-L2"),
    ),
)
def test_conflicting_legacy_dual_write_is_not_normalized_into_new_authority(
    tmp_path: Path, field: str, replacement: str,
) -> None:
    """The active-record/manifest join must be an exact reconcile, not coalesce."""

    _write_inputs(tmp_path, execution_tag="[STATIC-TRACE]")
    manifest_path = (
        tmp_path / "body_manifests" / "report_critical_high.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["findings"][0][field] = replacement
    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )

    with pytest.raises(ReportEvidenceError, match="dual-write|mismatch|conflict"):
        materialize_report_evidence_runtime(tmp_path)


def test_body_writer_has_an_exact_phaseio_consumer_contract_for_typed_evidence() -> None:
    """Producer consumer labels are not authority without a model input receipt."""

    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="report_body",
        work_unit_id="model.report_critical_high",
        exact_inputs=(
            "body_manifests/report_critical_high.json",
            "report_evidence_manifests/report_critical_high.json",
            "verify_INV-001.md",
        ),
        exact_outputs=("report_critical_high.md",),
    )

    assert contract.model_invoked is True
    assert (
        "scratchpad:report_evidence_manifests/report_critical_high.json"
        in contract.immutable_inputs
    )
    assert contract.outputs[0].writer == "MODEL"


def test_pre_body_adapter_rejects_an_unowned_self_consistent_source_tuple(
    tmp_path: Path,
) -> None:
    """Hashing current bytes is not a substitute for upstream producer authority."""

    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    # These bytes are schema-plausible and mutually consistent, but there is no
    # report-index routing work unit or verifier producer in the artifact
    # ledger.  A downstream DRIVER must not make them authoritative merely by
    # recording them as its own current inputs.
    _write_inputs(scratchpad, execution_tag="[STATIC-TRACE]")

    runtime, issues = driver._materialize_report_evidence_pre_body(
        _body_writer_phase(),
        _config(project, scratchpad, run_id="p1-k-adversarial-unowned"),
        scratchpad,
    )

    assert runtime is None
    assert any(
        "producer" in issue.lower()
        or "unowned" in issue.lower()
        or "upstream" in issue.lower()
        for issue in issues
    )
    assert not (scratchpad / "report_evidence_records.json").exists()


def test_driver_vetoes_a_quality_receipt_that_detects_proof_overclaim(
    tmp_path: Path,
) -> None:
    """A red quality receipt must be a ship gate, not write-only telemetry."""

    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    _write_inputs(scratchpad, execution_tag="[STATIC-TRACE]")
    report = _projected_report(
        scratchpad,
        extra=(
            "**Additional analysis**:\n"
            "The PoC proves the harm and exploitability described by this finding."
        ),
    )
    (project / "AUDIT_REPORT.md").write_text(report, encoding="utf-8")

    issues = driver._finalize_report_evidence_quality(
        scratchpad,
        _config(project, scratchpad, run_id="p1-k-adversarial-overclaim"),
    )
    receipt = json.loads(
        (scratchpad / "report_evidence_quality_receipt.json").read_text(
            encoding="utf-8"
        )
    )

    assert receipt["unauthorized_proof_grade_report_ids"] == ["H-01"]
    assert receipt["delivery_state"] == "STRUCTURAL_DELIVERY_INCOMPLETE"
    assert any(
        "unauthorized" in issue.lower()
        or "structural" in issue.lower()
        or "proof" in issue.lower()
        for issue in issues
    )


def test_quality_receipt_tamper_is_rejected_not_reblessed_on_resume(
    tmp_path: Path,
) -> None:
    """A committed final receipt is compare-only on exact resume."""

    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    _write_inputs(scratchpad, execution_tag="[STATIC-TRACE]")
    (project / "AUDIT_REPORT.md").write_text(
        _projected_report(scratchpad), encoding="utf-8"
    )
    config = _config(project, scratchpad, run_id="p1-k-adversarial-resume")

    assert driver._finalize_report_evidence_quality(scratchpad, config) == []
    receipt_path = scratchpad / "report_evidence_quality_receipt.json"
    forged = b'{"forged":true}\n'
    receipt_path.write_bytes(forged)

    issues = driver._finalize_report_evidence_quality(
        scratchpad, config, compare_only=True
    )

    assert issues
    assert receipt_path.read_bytes() == forged


def test_terminal_quality_gate_is_compare_only_and_does_not_mint_retry(
    tmp_path: Path,
) -> None:
    """An exact terminal replay retains the original attempt lineage."""

    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    _write_inputs(scratchpad, execution_tag="[STATIC-TRACE]")
    (project / "AUDIT_REPORT.md").write_text(
        _projected_report(scratchpad), encoding="utf-8"
    )
    config = _config(project, scratchpad, run_id="p1-k-compare-only")

    assert driver._finalize_report_evidence_quality(scratchpad, config) == []
    authority_dir = scratchpad / "_artifact_output_authority_cas"
    before = {path.name for path in authority_dir.glob("*.json")}

    assert driver._finalize_report_evidence_quality(
        scratchpad, config, compare_only=True
    ) == []
    after = {path.name for path in authority_dir.glob("*.json")}
    ledger = json.loads(
        (scratchpad / "_artifact_state.json").read_text(encoding="utf-8")
    )
    unit = ledger["work_units"][
        "sc/thorough/evm/claude/report_floor/evidence_quality"
    ]

    assert after == before
    assert unit["commit_authority"]["attempt_ordinal"] == 1

    receipt_path = scratchpad / "report_evidence_quality_receipt.json"
    receipt_path.unlink()
    issues = driver._finalize_report_evidence_quality(
        scratchpad, config, compare_only=True
    )
    assert issues
    assert not receipt_path.exists()


def test_report_swap_after_compare_only_validation_cannot_be_delivered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The publisher consumes P1-K authority; it cannot hash current bytes."""

    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    run_id = "12345678-1234-4234-8234-123456789abc"
    config = _config(project, scratchpad, run_id=run_id)
    checkpoint = Checkpoint(run_id=run_id)
    checkpoint.save(scratchpad)
    _write_inputs(scratchpad, execution_tag="[STATIC-TRACE]")
    report = project / "AUDIT_REPORT.md"
    report.write_text(_projected_report(scratchpad), encoding="utf-8")

    assert driver._finalize_report_evidence_quality(scratchpad, config) == []
    accepted_report_sha256: list[str] = []
    assert driver._finalize_report_evidence_quality(
        scratchpad,
        config,
        compare_only=True,
        accepted_report_sha256=accepted_report_sha256,
    ) == []
    assert len(accepted_report_sha256) == 1

    # This is the exact disputed interval: terminal validation has returned,
    # but the delivery consumer has not entered yet.
    replacement = b"# Replaced after terminal validation\n"
    report.write_bytes(replacement)

    def forbidden_snapshot(_project_root):
        raise AssertionError("unbound replacement reached snapshot publication")

    monkeypatch.setattr(driver, "_snapshot_report_timestamped", forbidden_snapshot)
    report_str, snapshot_str, no_ship, quarantined = (
        driver._publish_terminal_deliverable_report(
            checkpoint,
            scratchpad,
            config,
            list(SC_PHASES),
            expected_report_sha256=accepted_report_sha256[0],
        )
    )

    assert report_str is None and snapshot_str is None
    assert no_ship is True
    assert quarantined is not None and quarantined.read_bytes() == replacement
    assert driver._checkpoint_has_report_integrity_no_ship(checkpoint)
    assert driver._pipeline_terminal_exit_code(checkpoint) != 0


def test_final_report_evidence_gate_runs_after_the_last_report_projection() -> None:
    """The snapshotted report must still match the terminal P1-K receipt."""

    source = Path(driver.__file__).read_text(encoding="utf-8")
    final_boundary = source.index("newly_synced = _sync_degraded_sentinels")
    terminal_delivery = source.index(
        "_publish_terminal_deliverable_report(", final_boundary
    )
    delivery = source[final_boundary:terminal_delivery]

    last_projection = delivery.rfind("_refresh_assurance_projection(")
    last_p1k_gate = delivery.rfind("_finalize_report_evidence_quality(")
    assert last_projection >= 0
    assert last_p1k_gate > last_projection


def test_exact_resume_preserves_repair_apply_as_current_bundle_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The baseline producer must not steal ownership of repaired bytes."""

    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    _write_inputs(scratchpad, impact="")
    config = _config(project, scratchpad, run_id="p1-k-adversarial-owner")

    def _worker(**_kwargs) -> int:
        response = _repair_response_for_active_request(scratchpad)
        (scratchpad / "report_evidence_repair_response.json").write_text(
            json.dumps(response), encoding="utf-8"
        )
        return 0

    monkeypatch.setattr(
        driver, "_run_one_claude_headless_breadth_worker", _worker
    )
    phase = _body_writer_phase()
    assert driver._ensure_report_evidence_before_body_writer(
        phase, config, scratchpad
    ) == []
    identity = "scratchpad:report_evidence_records.json"
    owner_before = read_artifact_ledger(scratchpad)["artifact_bindings"][
        identity
    ]["owner_key"]
    assert owner_before.endswith("/report_body/evidence_repair.apply")

    assert driver._ensure_report_evidence_before_body_writer(
        phase, config, scratchpad
    ) == []
    owner_after = read_artifact_ledger(scratchpad)["artifact_bindings"][
        identity
    ]["owner_key"]

    assert owner_after == owner_before


def test_initial_projection_partial_write_is_crash_recoverable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An uncommitted torn projection is a recoverable write, not permanent tamper."""

    _write_inputs(tmp_path, execution_tag="[STATIC-TRACE]")
    original = Path.write_bytes
    interrupted = False

    def _tear_projection(path: Path, data: bytes) -> int:
        nonlocal interrupted
        if path.name == "report_evidence_projection.md" and not interrupted:
            interrupted = True
            original(path, data[: max(1, len(data) // 2)])
            raise OSError("simulated torn pre-body projection")
        return original(path, data)

    monkeypatch.setattr(Path, "write_bytes", _tear_projection)
    with pytest.raises(OSError, match="simulated torn"):
        materialize_report_evidence_runtime(tmp_path)
    monkeypatch.setattr(Path, "write_bytes", original)

    # No PhaseIO output commit exists, so exact deterministic replay should
    # repair the one torn derived half and validate the complete transaction.
    materialize_report_evidence_runtime(tmp_path)


def test_writer_cannot_append_untyped_impact_and_still_pass_semantic_parity(
    tmp_path: Path,
) -> None:
    """Substring presence is insufficient to constrain a writer's harm claim."""

    _write_inputs(tmp_path, execution_tag="[STATIC-TRACE]")
    runtime = materialize_report_evidence_runtime(tmp_path)
    typed_impact = runtime["bundle"]["records"][0]["impact"]
    report = project_report_evidence_markdown(
        f"""### [H-01] Paired accounting state can diverge

**Severity**: High
**Verdict**: CONFIRMED
**Location**: src/Module.sol:L10-L30

**Description**:
One transition updates one accounting leg without its pair.

**Impact**:
{typed_impact} Attackers deterministically drain every reserve in the system.
""",
        runtime["bundle"],
    )
    report_path = tmp_path / "AUDIT_REPORT.md"
    report_path.write_text(report, encoding="utf-8")

    receipt = finalize_report_evidence_delivery(
        tmp_path, report_path=report_path
    )

    assert receipt["record_semantic_parity"]["H-01"] is False
    assert receipt["semantically_complete"] is False


def test_every_constituent_semantic_impact_is_in_the_delivery_denominator(
    tmp_path: Path,
) -> None:
    """A consolidated finding must not validate after dropping a sibling impact."""

    _write_inputs(tmp_path, execution_tag="[STATIC-TRACE]")
    records_path = tmp_path / "report_records.json"
    records = json.loads(records_path.read_text(encoding="utf-8"))
    records["active"][0]["absorbed_finding_ids"] = ["INV-002"]
    records_path.write_text(
        json.dumps(records, indent=2) + "\n", encoding="utf-8"
    )
    manifest_path = (
        tmp_path / "body_manifests" / "report_critical_high.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["findings"][0]["verify_files"] = [
        "verify_INV-001.md",
        "verify_INV-002.md",
    ]
    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    sibling_impact = (
        "A distinct finalization branch can permanently strand credited value."
    )
    (tmp_path / "verify_INV-002.md").write_text(
        """**Verdict**: CONFIRMED
**Location**: src/Module.sol:L40-L60
**Evidence Tag**: [STATIC-TRACE]

### Finding Summary
A distinct finalization branch consumes the paired state twice.

### Preconditions
- The finalization branch is reachable.

### Impact
"""
        + sibling_impact
        + """

### Code Trace
The finalization branch consumes the same credit twice.

### Recommendation
Track finalization consumption per branch and assert one-time settlement.
""",
        encoding="utf-8",
    )
    runtime = materialize_report_evidence_runtime(tmp_path)
    record = runtime["bundle"]["records"][0]
    assert sibling_impact not in record["impact"]

    report = project_report_evidence_markdown(
        """### [H-01] Paired accounting state can diverge

**Severity**: High
**Verdict**: CONFIRMED
**Location**: src/Module.sol:L10-L30

**Description**:
One transition updates one accounting leg without its pair.
""",
        runtime["bundle"],
    )
    report_path = tmp_path / "AUDIT_REPORT.md"
    report_path.write_text(report, encoding="utf-8")
    receipt = finalize_report_evidence_delivery(
        tmp_path, report_path=report_path
    )

    assert receipt["record_semantic_parity"]["H-01"] is False


def test_report_source_manifests_have_a_preparse_byte_budget(tmp_path: Path) -> None:
    """A bounded 30-row shard must not be able to consume unbounded memory."""

    _write_inputs(tmp_path, execution_tag="[STATIC-TRACE]")
    manifest = tmp_path / "body_manifests" / "report_critical_high.json"
    # Trailing JSON whitespace is semantically inert and therefore isolates
    # the missing pre-read resource bound from schema validation.
    manifest.write_bytes(manifest.read_bytes() + (b" " * (8 * 1024 * 1024 + 1)))

    with pytest.raises(ReportEvidenceError, match="byte budget"):
        materialize_report_evidence_runtime(tmp_path)


def test_typed_fallback_renderer_has_exact_terminal_delivery_parity(
    tmp_path: Path,
) -> None:
    """The fallback renders the same typed semantics the ship gate consumes."""

    _write_inputs(tmp_path, execution_tag="[STATIC-TRACE]")
    runtime = materialize_report_evidence_runtime(tmp_path)

    rendered = report_authority.render_typed_report_evidence_shard(
        tmp_path, "report_critical_high"
    )
    report_path = tmp_path / "AUDIT_REPORT.md"
    report_path.write_text(rendered, encoding="utf-8")
    receipt = finalize_report_evidence_delivery(
        tmp_path, report_path=report_path
    )

    record = runtime["bundle"]["records"][0]
    assert f"### [{record['report_id']}] {record['title']}" in rendered
    assert "[STUB-RECOVERED]" not in rendered
    assert receipt["record_markdown_parity"] == {"H-01": True}
    assert receipt["record_semantic_parity"] == {"H-01": True}
    assert receipt["typed_manifest_markdown_parity"] is True
    assert receipt["semantically_complete"] is True


def test_typed_fallback_does_not_reconsume_mutated_legacy_sources(
    tmp_path: Path,
) -> None:
    """Late legacy prose drift cannot change bytes at the typed boundary."""

    _write_inputs(tmp_path, execution_tag="[STATIC-TRACE]")
    materialize_report_evidence_runtime(tmp_path)
    before = report_authority.render_typed_report_evidence_shard(
        tmp_path, "report_critical_high"
    )

    (tmp_path / "verification_queue.md").write_text(
        "# late unbound queue rewrite\nH-99 | invented candidate\n",
        encoding="utf-8",
    )
    (tmp_path / "report_index.md").write_text(
        "# late unbound report-index rewrite\nH-99 invented result\n",
        encoding="utf-8",
    )
    (tmp_path / "verify_INV-001.md").write_text(
        "**Verdict**: REFUTED\nlate unbound verifier prose rewrite\n",
        encoding="utf-8",
    )

    after = report_authority.render_typed_report_evidence_shard(
        tmp_path, "report_critical_high"
    )
    assert after.encode("utf-8") == before.encode("utf-8")


@pytest.mark.parametrize("artifact", ("manifest", "record"))
def test_typed_fallback_rejects_tampered_typed_authority(
    tmp_path: Path,
    artifact: str,
) -> None:
    """Neither half of the typed transaction may be locally re-blessed."""

    _write_inputs(tmp_path, execution_tag="[STATIC-TRACE]")
    materialize_report_evidence_runtime(tmp_path)
    if artifact == "manifest":
        path = (
            tmp_path
            / "report_evidence_manifests"
            / "report_critical_high.json"
        )
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["findings"][0]["report_evidence"]["impact"] = (
            "late typed-manifest mutation"
        )
    else:
        path = tmp_path / "report_evidence_records.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["records"][0]["impact"] = "late typed-record mutation"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(ReportEvidenceError):
        report_authority.render_typed_report_evidence_shard(
            tmp_path, "report_critical_high"
        )


@pytest.mark.parametrize(
    "candidate_id",
    ("L1-C-01", "F-L1-C-01", "RUSTSEC-2025-0001"),
)
def test_typed_fallback_preserves_compound_candidate_identity_exactly(
    tmp_path: Path,
    candidate_id: str,
) -> None:
    """Compound namespaces survive source join, typed record, and rendering."""

    _write_inputs(tmp_path, execution_tag="[STATIC-TRACE]")
    records_path = tmp_path / "report_records.json"
    records = json.loads(records_path.read_text(encoding="utf-8"))
    records["active"][0]["finding_id"] = candidate_id
    records_path.write_text(
        json.dumps(records, indent=2) + "\n", encoding="utf-8"
    )
    manifest_path = (
        tmp_path / "body_manifests" / "report_critical_high.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    row = manifest["findings"][0]
    row["finding_id"] = candidate_id
    row["verify_file"] = f"verify_{candidate_id}.md"
    row["verify_files"] = [f"verify_{candidate_id}.md"]
    row["verify_statuses"][0]["file"] = f"verify_{candidate_id}.md"
    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    (tmp_path / "verify_INV-001.md").rename(
        tmp_path / f"verify_{candidate_id}.md"
    )

    runtime = materialize_report_evidence_runtime(tmp_path)
    record = runtime["bundle"]["records"][0]
    rendered = report_authority.render_typed_report_evidence_shard(
        tmp_path, "report_critical_high"
    )

    assert record["candidate_ids"] == [candidate_id]
    assert [
        row["candidate_id"] for row in record["constituent_semantics"]
    ] == [candidate_id]
    assert f"**Constituent {candidate_id}**:" in rendered


def test_typed_fallback_runtime_debt_never_mints_positive_authority(
    tmp_path: Path,
) -> None:
    """A retained candidate remains visibly unresolved through rendering."""

    scratchpad, _phase_name, _items, _plan = _setup_plan(
        tmp_path, "sc", finding_ids=("H-01",)
    )
    driver._retain_dynamic_verification_debt(
        scratchpad,
        {"pipeline": "sc", "_run_id": "P1-K-TYPED-DEBT"},
        ("provider completion unavailable",),
        ("H-01",),
    )
    binding = mechanical._verification_runtime_debt_binding(
        scratchpad, ["H-01"]
    )
    assert binding is not None
    (scratchpad / "body_manifests").mkdir()
    manifest_row = {
        "report_id": "H-1",
        "finding_id": "H-01",
        "severity": "High",
        "title": "Retained candidate",
        "location": "src/Generic.sol:10",
        "evidence_tag": "UNVERIFIED",
        "verify_file": "verify_H-01.md",
        "verify_files": ["verify_H-01.md"],
        "verify_statuses": [{
            "file": "verify_H-01.md",
            "exists": False,
            "evidence_missing": True,
        }],
        "description": (
            "A proposed mechanism remains pending independent verification."
        ),
        "poc_result": "",
        "recommendation": "",
        "report_blocked": True,
        "verification_runtime_debt": binding,
    }
    (scratchpad / "body_manifests" / "report_critical_high.json").write_text(
        json.dumps(
            {"shard": "report_critical_high", "findings": [manifest_row]},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (scratchpad / "report_records.json").write_text(
        json.dumps(
            {
                "schema_version": "plamen.report_records.v1",
                "source": "report_index.md",
                "active": [{
                    "report_id": "H-1",
                    "finding_id": "H-01",
                    "severity": "High",
                    "title": "Retained candidate",
                    "location": "src/Generic.sol:10",
                    "evidence": "UNVERIFIED",
                    "verdict": "UNRESOLVED",
                    "unresolved": True,
                    "severity_adjustments": [],
                    "absorbed_finding_ids": [],
                    "report_blocked": True,
                }],
                "excluded": [],
                "consolidation_map": [],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    runtime = materialize_report_evidence_runtime(scratchpad)
    record = runtime["bundle"]["records"][0]
    rendered = report_authority.render_typed_report_evidence_shard(
        scratchpad, "report_critical_high"
    )

    assert record["verdict"] == "UNRESOLVED"
    assert record["presentation_assurance"] == "EVIDENCE_LIMITED"
    assert record["evidence_authenticity"] == "NOT_EXECUTED"
    assert record["evidence_result"] == "NOT_EXECUTED"
    assert record["proof_scope"] == "NONE"
    assert "**Verdict**: UNRESOLVED" in rendered
    assert "**Confidence**: UNVERIFIED" in rendered
    assert "- Proof scope: NONE" in rendered
    assert "**Verdict**: CONFIRMED" not in rendered
    assert "PROOF_GRADE_HARM" not in rendered
    assert "[POC-PASS]" not in rendered
