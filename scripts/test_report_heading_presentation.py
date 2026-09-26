"""Real assembler headings require exact same-run presentation authority."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path

import pytest

import artifact_ledger as AL
from phase_io_contracts import ArtifactSpec, LaunchSpec, PhaseIOContract, resolve_phase_io_contract
import plamen_mechanical as M
import report_evidence_authority as E
import report_heading_presentation as H
from test_report_evidence_runtime_p1_k import _write_inputs


RUN_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
TITLE = "Paired accounting state can diverge (INV-001)"


def _state(root):
    names = (AL.LEDGER_NAME, "report_index.md", "report_evidence_records.json",
             "report_evidence_quality_receipt.json")
    return {name: ((root / name).read_bytes(), (root / name).stat().st_ino,
                   (root / name).stat().st_mtime_ns)
            if (root / name).exists() else None for name in names}


def _commit(root, project, contract, outputs, *, launch_overrides=None):
    launch_fields = dict(work_unit_key=contract.key, pipeline="sc", mode="core",
                         ecosystem="evm", backend="codex", model="driver", timeout_s=120,
                         exec_mode="python", tool_policy=("filesystem",))
    launch_fields.update(launch_overrides or {})
    launch = LaunchSpec(**launch_fields)
    for identity in contract.immutable_inputs:
        path = root / identity.split(":", 1)[1]
        if not path.exists():
            path.write_text("# Synthetic input\n")
    AL.record_work_unit_inputs(root, project, contract, launch, run_id=RUN_ID)
    for name, raw in outputs.items():
        (root / name).write_bytes(raw)
    AL.record_work_unit_artifacts(root, project, contract, launch, run_id=RUN_ID, actor="DRIVER")


def _case(tmp_path, status="CONTESTED", *, index_launch_overrides=None):
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    _write_inputs(root, execution_tag="[STATIC-TRACE]")
    for name, key in (("report_records.json", "active"),
                      ("body_manifests/report_critical_high.json", "findings")):
        path = root / name
        payload = json.loads(path.read_text())
        payload[key][0]["title"] = TITLE
        path.write_text(json.dumps(payload) + "\n")
    runtime = E.materialize_report_evidence_runtime(root)
    bundle = runtime["bundle"]
    raw_bundle = (root / "report_evidence_records.json").read_bytes()
    (root / "report_evidence_records.json").unlink()
    owner = "sc/core/evm/codex/heading_fixture/evidence"
    source = PhaseIOContract(
        pipeline="sc", mode="core", ecosystem="evm", backend="codex",
        phase="heading_fixture", work_unit_id="evidence",
        outputs=(ArtifactSpec(root="scratchpad", path="report_evidence_records.json",
                              owner_key=owner, artifact_class="DRIVER_GENERATED",
                              writer="DRIVER", write_mode="CREATE"),),
    )
    _commit(root, project, source, {"report_evidence_records.json": raw_bundle})
    index = (
        "# Report Index\n\n## Master Finding Index\n\n"
        "| Report ID | Title | Severity | Location | Verification | Internal |\n"
        "|---|---|---|---|---|---|\n"
        f"| H-01 | {TITLE} | High | src/Module.sol:L10-L30 | {status} | INV-001 |\n"
    ).encode()
    contract = resolve_phase_io_contract(pipeline="sc", mode="core", ecosystem="evm",
                                        backend="codex", phase="report_index", work_unit_id="mechanical")
    _commit(root, project, contract, {"report_index.md": index, "report_coverage.md": b"# Coverage\n"},
            launch_overrides=index_launch_overrides)
    (root / "report_critical_high.md").write_text(E.render_typed_report_evidence_shard(root, "report_critical_high"))
    assert M._assemble_report_python(root, str(project)) is True
    (root / "report_evidence_quality_receipt.json").write_bytes(
        b'{"fixture":"assessment must not adopt or rewrite this receipt"}\n'
    )
    return root, project, bundle


@pytest.mark.parametrize("status", ["CONTESTED", "UNVERIFIED", "CONFIRMED"])
def test_actual_assembler_heading_replays_exact_authenticated_projection(tmp_path, status):
    root, project, bundle = _case(tmp_path, status)
    report = project / "AUDIT_REPORT.md"
    expected = H.public_heading_title(TITLE, status)
    assert f"### [H-01] {expected}" in report.read_text()
    before = _state(root)
    projection = H.load_authenticated_heading_projection(
        root, project_root=project, run_id=RUN_ID, bundle=bundle,
    )
    receipt = E.derive_final_report_evidence_delivery(report.read_bytes(), bundle,
                                                    heading_projection=projection)
    assert receipt["record_semantic_parity"] == {"H-01": True}
    assert E.assess_final_report_evidence_delivery(
        root, report_path=report, project_root=project, run_id=RUN_ID,
    )["record_semantic_parity"] == {"H-01": True}
    assert _state(root) == before
    # The raw-title-only API cannot authorize display labels from prose.
    assert E.derive_final_report_evidence_delivery(report.read_bytes(), bundle)["record_semantic_parity"] == {"H-01": False}
    for changed in (expected.replace("Paired", "Unrelated"), expected.replace(f"[{status}]", "[VERIFIED]")):
        raw = report.read_bytes().replace(expected.encode(), changed.encode())
        assert E.derive_final_report_evidence_delivery(raw, bundle, heading_projection=projection)["record_semantic_parity"] == {"H-01": False}


@pytest.mark.parametrize("fault", ["missing_binding", "forged_receipt", "stale_index", "foreign_run", "unregistered_owner"])
def test_heading_authority_faults_fail_readonly(tmp_path, fault):
    root, project, bundle = _case(tmp_path)
    run_id = RUN_ID
    ledger_path = root / AL.LEDGER_NAME
    ledger = json.loads(ledger_path.read_text())
    identity = "scratchpad:report_index.md"
    owner = ledger["artifact_bindings"][identity]["owner_key"]
    if fault == "missing_binding":
        del ledger["artifact_bindings"][identity]
    elif fault == "forged_receipt":
        ledger["work_units"][owner]["commit_authority"]["receipt_digest"] = "0" * 64
    elif fault == "stale_index":
        with (root / "report_index.md").open("ab") as stream:
            stream.write(b"\nchanged after commit\n")
    elif fault == "foreign_run":
        run_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    else:
        ledger["artifact_bindings"][identity]["owner_key"] = "sc/core/evm/codex/heading_fixture/evidence"
    if fault in {"missing_binding", "forged_receipt", "unregistered_owner"}:
        ledger_path.write_text(json.dumps(ledger) + "\n")
    before = _state(root)
    with pytest.raises(E.ReportEvidenceError):
        E.assess_final_report_evidence_delivery(root, report_path=project / "AUDIT_REPORT.md",
                                               project_root=project, run_id=run_id)
    assert _state(root) == before


def test_heading_projection_cannot_be_forged_or_rebound(tmp_path):
    root, project, bundle = _case(tmp_path)
    projection = H.load_authenticated_heading_projection(root, project_root=project, run_id=RUN_ID, bundle=bundle)
    with pytest.raises(E.ReportEvidenceError):
        E.derive_final_report_evidence_delivery(b"# Report\n", bundle, heading_projection={"H-01": "forged"})
    with pytest.raises(E.ReportEvidenceError):
        E.derive_final_report_evidence_delivery(b"# Report\n", bundle,
                                              heading_projection=replace(projection, titles=(("H-01", "forged"),)))
    altered = deepcopy(bundle["records"][0])
    altered["title"] = "Different retained claim"
    changed = E.build_report_evidence_bundle([E.normalize_report_evidence_record(altered)], expected_report_ids=["H-01"])
    with pytest.raises(E.ReportEvidenceError):
        E.derive_final_report_evidence_delivery(b"# Report\n", changed, heading_projection=projection)


@pytest.mark.parametrize("status", ["VERIFIED / UNVERIFIED", "NOT_VERIFIED", "NOT VERIFIED", "", "VERIFIEDNESS"])
def test_ambiguous_or_noncanonical_index_status_cannot_authorize_heading(status):
    index = "## Master Finding Index\n| Report ID | Title | Verification |\n|---|---|---|\n" + f"| H-01 | Retained claim | {status} |\n"
    with pytest.raises(H.ReportHeadingError):
        H.index_status_map(index)


def test_empty_projection_needs_no_index_status_rows():
    bundle = E.build_report_evidence_bundle([], expected_report_ids=[])
    assert H.index_status_map("# Empty report index\n") == {}
    receipt = E.derive_final_report_evidence_delivery(b"# Empty report\n", bundle)
    assert receipt["record_semantic_parity"] == {}
    assert receipt["structurally_delivered"] is True


def test_heading_assessment_uses_source_root_and_rejects_partial_context(tmp_path):
    root, project, _bundle = _case(tmp_path)
    staged = tmp_path / "delivery" / "AUDIT_REPORT.md"
    staged.parent.mkdir()
    staged.write_bytes((project / "AUDIT_REPORT.md").read_bytes())
    before = _state(root)
    assert E.assess_final_report_evidence_delivery(
        root, report_path=staged, project_root=project, run_id=RUN_ID,
    )["record_semantic_parity"] == {"H-01": True}
    with pytest.raises(E.ReportEvidenceError):
        E.assess_final_report_evidence_delivery(root, report_path=staged, project_root=project)
    assert _state(root) == before


@pytest.mark.parametrize("overrides", [
    {"model": "not-the-driver"},
    {"exec_mode": "codex"},
    {"tool_policy": ("filesystem", "network")},
])
def test_index_launch_must_satisfy_registered_driver_policy(tmp_path, overrides):
    root, project, bundle = _case(tmp_path, index_launch_overrides=overrides)
    before = _state(root)
    with pytest.raises(ValueError, match="DRIVER report-source launch authority differs"):
        H.load_authenticated_heading_projection(root, project_root=project,
                                                run_id=RUN_ID, bundle=bundle)
    assert _state(root) == before


@pytest.mark.parametrize("field,value", [
    ("titles", (("H-01", "Substituted claim [VERIFIED]"),)),
    ("index_sha256", "0" * 64),
    ("producer_receipt_digest", "0" * 64),
    ("run_id", "different-run"),
])
def test_issued_projection_content_is_sealed(tmp_path, field, value):
    root, project, bundle = _case(tmp_path)
    projection = H.load_authenticated_heading_projection(root, project_root=project,
                                                         run_id=RUN_ID, bundle=bundle)
    object.__setattr__(projection, field, value)
    with pytest.raises(E.ReportEvidenceError, match="unbound"):
        E.derive_final_report_evidence_delivery((project / "AUDIT_REPORT.md").read_bytes(),
                                                bundle, heading_projection=projection)
