"""Fixture-first tests for the real-audit RunBundle harvesting/export slice.

These tests intentionally exercise only public runner inputs.  They do not
load ground truth, a private case lock, expected issue counts, or grader data.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest

import runbundle_contracts as C
import runbundle_privacy as P
import test_runbundle_v2_contracts as V2

import runbundle_export as E
import runbundle_harvest as H
import runbundle_sources as S


def _write_fixture_run(root: Path) -> tuple[Path, Path]:
    scratchpad = root / ".scratchpad"
    scratchpad.mkdir(parents=True)
    (scratchpad / "breadth_findings.md").write_text(
        "# Breadth\n\n"
        "## [H-17] Conservation failure\n\n"
        "**Mechanism:** A committed transition omits a conservation check.\n\n"
        "**Impact:** Accounting can diverge.\n\n"
        "**Location:** `src/Vault.sol:42-44`\n\n"
        "## Coverage note\n\nNo other candidate was emitted.\n",
        encoding="utf-8",
        newline="\n",
    )
    (scratchpad / "inventory_reconciliation.json").write_text(
        json.dumps(
            {
                "schema_version": "plamen.inventory-reconciliation.future.v99",
                "records": [{"id": "native-finding-17", "status": "RETAINED"}],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    report = root / "AUDIT_REPORT.md"
    report.write_text(
        "# Audit report\n\n"
        "## High findings\n\n"
        "### [H-17] Conservation failure\n\n"
        "The committed transition omits a conservation check.\n",
        encoding="utf-8",
        newline="\n",
    )
    return scratchpad, report


def _unsigned_user_run_documents() -> tuple[dict[str, object], dict[str, object]]:
    documents = copy.deepcopy(V2._documents())
    lock = V2._public_lock()
    manifest = documents["run_manifest.json"]
    manifest["trust_profile"] = "USER_RUN"
    manifest["run_context_authority"] = None
    manifest["public_launch_receipt"] = None
    manifest["budget"]["measurement_receipt_refs"] = []
    manifest["budget"]["measurement_summary_receipt_ref"] = None
    for event in documents["phase_events.jsonl"]:
        event["source_receipt_id"] = "UNAUTHENTICATED_PARSE"
        event["evidence_quality"] = "UNAUTHENTICATED"
    for candidate in documents["candidate_findings.json"]["candidates"]:
        candidate["audit_severity"]["authority_receipt_id"] = (
            "UNAUTHENTICATED_PARSE"
        )
        candidate["quality"]["evidence_quality"] = "UNAUTHENTICATED"
    for occurrence in documents["candidate_lineage.json"]["occurrences"]:
        occurrence["authority_ref"] = "UNAUTHENTICATED_PARSE"
    documents["raw_outputs.json"]["authority_receipts"] = []
    projection = documents["report_projection.json"]
    projection["report_evidence_quality_receipt_ref"] = "UNAUTHENTICATED_PARSE"
    for disposition in projection["candidate_report_dispositions"]:
        disposition["authority_receipt_id"] = "UNAUTHENTICATED_PARSE"
    reconciliation = documents["harvest_receipt.json"]["record_reconciliation"]
    reconciliation["partition_authority"] = None
    for row in reconciliation["authenticated_nonfinding_records"]:
        row["authority_receipt_id"] = "UNAUTHENTICATED_PARSE"
    documents["harvest_receipt.json"] = C.bind_embedded_sha256(
        {
            key: value
            for key, value in documents["harvest_receipt.json"].items()
            if key != "receipt_sha256"
        },
        "receipt_sha256",
    )
    return documents, lock


def _write_public_export_inputs(
    root: Path,
) -> tuple[Path, Path, Path, Path]:
    scratchpad, report = _write_fixture_run(root)
    lock = V2._public_lock()
    baseline = V2._manifest(lock)
    schedule = {
        "schema_version": E.PUBLIC_SCHEDULE_ROW_SCHEMA,
        "trust_profile": "USER_RUN",
        "run_id": baseline["run_id"],
        "experiment_id": baseline["experiment_id"],
        "cell_id": baseline["cell_id"],
        "repetition_index": baseline["repetition_index"],
        "seed": baseline["seed"],
        "audit_system": "PLAMEN",
        "adapter": baseline["adapter"],
        "experiment_plan_sha256": baseline["experiment_plan_sha256"],
        "campaign_schedule_sha256": baseline["campaign_schedule_sha256"],
        "model_backend": baseline["model_backend"],
        "tool_policy": baseline["tool_policy"],
        "budget": baseline["budget"],
        "resume": baseline["resume"],
        "public_launch_receipt": None,
        "pipeline_kind": "SC",
    }
    lock_path = root / "public-lock.json"
    lock_path.write_bytes(C.canonical_document_bytes(lock))
    schedule_path = root / "schedule.json"
    schedule_path.write_bytes(C.canonical_document_bytes(schedule))
    return scratchpad, report, lock_path, schedule_path


def _materialized_live_fixture(
    root: Path,
) -> tuple[
    Path,
    Path,
    bytes,
    S.SourceInventory,
    dict[str, object],
    dict[str, bytes],
]:
    scratchpad, report, lock_path, schedule_path = (
        _write_public_export_inputs(root)
    )
    lock_raw = lock_path.read_bytes()
    lock = C.strict_json_loads(lock_raw, require_canonical=True)
    schedule = C.strict_json_load(schedule_path, require_canonical=True)
    inventory = S.inventory_run_sources(
        project_root=root,
        scratchpad=scratchpad,
        report=report,
        pipeline_kind=schedule["pipeline_kind"],
    )
    draft = H.build_harvest_draft(
        run_id=schedule["run_id"],
        adapter_id=schedule["adapter"]["adapter_id"],
        inventory=inventory,
        inline_limit=E.INLINE_LIMIT,
    )
    documents, objects = E.materialize_local_documents(
        draft=draft,
        public_case_lock=lock,
        schedule_row=schedule,
    )
    return (
        scratchpad,
        report,
        lock_raw,
        inventory,
        documents,
        objects,
    )


def _write_forged_publication_ready(
    *,
    out: Path,
    verified: C.RunBundleVerificationReceipt,
    source_authority_sha256: str,
) -> Path:
    """Recreate an unkeyed, self-consistent R9 READY without live checks."""

    timestamps = (
        (
            "2026-07-29T00:00:00.000001Z",
            "2026-07-29T00:00:00.000002Z",
        ),
        (
            "2026-07-29T00:00:00.000003Z",
            "2026-07-29T00:00:00.000004Z",
        ),
    )
    observations = []
    for stage, (started, completed) in zip(
        ("POST_PROMOTION", "POST_VERIFY_PRE_READY"),
        timestamps,
        strict=True,
    ):
        observations.append(
            C.bind_embedded_sha256(
                {
                    "schema_version": (
                        "plamen.runbundle-source-stability-observation.v1"
                    ),
                    "stage": stage,
                    "state": "LIVE_SOURCE_MATCHED_AT_OBSERVATION",
                    "source_authority_sha256": source_authority_sha256,
                    "started_at_utc": started,
                    "completed_at_utc": completed,
                    "claim_limitation": (
                        "BOUNDED_POINT_OBSERVATION_NOT_CONTINUOUS_OR_PERPETUAL"
                    ),
                },
                "observation_sha256",
            )
        )
    stability = {
        "state": "LIVE_SOURCE_MATCHED_AT_BOUNDED_CHECKS",
        "source_authority_sha256": source_authority_sha256,
        "observations": observations,
        "observation_set_sha256": C.document_sha256(
            {"observations": observations}
        ),
        "claim_limitation": (
            "BOUNDED_OBSERVATIONS_NOT_CONTINUOUS_OR_PERPETUAL_IMMUTABILITY"
        ),
    }
    ready = C.bind_embedded_sha256(
        {
            "schema_version": E.PUBLICATION_READY_SCHEMA,
            "status": "READY",
            "run_id": verified.run_id,
            "output_name": out.name,
            "bundle_seal_sha256": verified.bundle_seal_sha256,
            "verification_sha256": verified.verification_sha256,
            "public_case_lock_sha256": verified.public_case_lock_sha256,
            "source_stability": stability,
            "source_stability_sha256": C.document_sha256(stability),
            "exporter_code_sha256": E.exporter_code_sha256(),
            "exporter_policy_sha256": E.exporter_policy_sha256(),
        },
        "ready_sha256",
    )
    E.validate_publication_ready(ready)
    path = E.publication_ready_path(out)
    path.write_bytes(C.canonical_document_bytes(ready))
    return path


def _apply_late_source_mutation(
    *,
    mutation: str,
    root: Path,
    scratchpad: Path,
    report: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    breadth = scratchpad / "breadth_findings.md"
    if mutation == "scratch-added":
        (scratchpad / "late.md").write_bytes(b"# late source\n")
    elif mutation == "scratch-removed":
        breadth.unlink()
    elif mutation == "scratch-renamed":
        breadth.rename(scratchpad / "breadth_renamed.md")
    elif mutation == "scratch-replaced-identical":
        replacement = root / "replacement-scratch-r9"
        replacement.write_bytes(breadth.read_bytes())
        replacement.replace(breadth)
    elif mutation == "report-replaced-identical":
        replacement = root / "replacement-report-r9"
        replacement.write_bytes(report.read_bytes())
        replacement.replace(report)
    elif mutation == "report-content-restored-mtime":
        before = report.stat()
        report.write_bytes(report.read_bytes() + b"\nr9 late bytes\n")
        os.utime(
            report,
            ns=(before.st_atime_ns, before.st_mtime_ns),
        )
    elif mutation == "scratch-hardlink":
        target = root / "hardlink-target-r9"
        target.write_bytes(breadth.read_bytes())
        breadth.unlink()
        os.link(target, breadth)
    elif mutation == "scratch-symlink":
        target = root / "symlink-target-r9"
        target.write_bytes(breadth.read_bytes())
        breadth.unlink()
        try:
            breadth.symlink_to(target)
        except OSError:
            pytest.skip("host policy does not permit symlink creation")
    elif mutation == "scratch-reparse":
        original_reparse = P._is_reparse_point
        monkeypatch.setattr(
            P,
            "_is_reparse_point",
            lambda path, row=None: (
                Path(path) == breadth
                or original_reparse(Path(path), row)
            ),
        )
    else:  # pragma: no cover - closed parametrization
        raise AssertionError(mutation)


def test_unsigned_user_run_is_valid_but_same_payload_cannot_claim_b1():
    documents, lock = _unsigned_user_run_documents()
    C.validate_bundle_payload_set(documents, lock)
    assert C.derive_publication_ceiling(documents["run_manifest.json"]) == "USER_RUN"

    b1 = copy.deepcopy(documents)
    b1["run_manifest.json"]["trust_profile"] = "B1_INCOMPLETE"
    with pytest.raises(C.RunBundleContractError, match="B1|authenticated|authority"):
        C.validate_bundle_payload_set(b1, lock)


def test_durable_directory_publication_is_no_replace(
    tmp_path: Path,
):
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    target.mkdir()
    (source / "source.txt").write_bytes(b"source")
    (target / "target.txt").write_bytes(b"target")
    with pytest.raises(E.RunBundleExportError, match="already exists"):
        E._durable_directory_rename_new(source, target)
    assert (source / "source.txt").read_bytes() == b"source"
    assert (target / "target.txt").read_bytes() == b"target"


@pytest.mark.skipif(os.name != "nt", reason="native Windows long-path boundary")
def test_durable_directory_publication_supports_windows_long_paths(
    tmp_path: Path,
):
    parent = tmp_path
    while len(str(parent)) < 235:
        parent = parent / (
            "long-segment-" + str(len(parent.parts)).zfill(3)
        )
    cursor = tmp_path
    for component in parent.relative_to(tmp_path).parts:
        cursor = cursor / component
        os.mkdir(E._native_fs_path(cursor))
    source = parent / ".bundle.0123456789abcdef.staging"
    target = parent / "bundle"
    os.mkdir(E._native_fs_path(source))
    with open(E._native_fs_path(source / "payload.txt"), "wb") as stream:
        stream.write(b"payload")
    E._durable_directory_rename_new(source, target)
    assert not os.path.exists(E._native_fs_path(source))
    with open(E._native_fs_path(target / "payload.txt"), "rb") as stream:
        assert stream.read() == b"payload"


def test_source_registry_is_frozen_exact_and_does_not_prefix_guess_phases():
    first = S.source_registry_preimage()
    second = S.source_registry_preimage()
    assert first == second
    assert S.source_registry_sha256() == C.sha256_bytes(
        C.canonical_json_bytes(first)
    )

    known = S.resolve_source_adapter(
        ".scratchpad/breadth_findings.md", pipeline_kind="SC"
    )
    assert known.phase("SC") == ("breadth", "breadth")
    assert known.parser_id == "plamen-markdown-findings"

    # An almost-matching name must remain explicit opaque CONTROL evidence.
    impostor = S.resolve_source_adapter(
        ".scratchpad/breadth_findings.md.backup", pipeline_kind="SC"
    )
    assert impostor.phase("SC") == (
        "instantiate",
        "CONTROL",
    )
    assert impostor.parser_id == "opaque-preserve"


def test_inventory_and_harvest_conserve_unknown_schema_and_report_sections(
    tmp_path: Path,
):
    scratchpad, report = _write_fixture_run(tmp_path)
    inventory = S.inventory_run_sources(
        project_root=tmp_path,
        scratchpad=scratchpad,
        report=report,
        pipeline_kind="SC",
    )
    assert inventory.stable is True
    assert inventory.before_sha256 == inventory.after_sha256
    assert all(not Path(row.relative_source_path).is_absolute() for row in inventory.artifacts)

    unknown = next(
        row
        for row in inventory.artifacts
        if row.relative_source_path.endswith("inventory_reconciliation.json")
    )
    assert unknown.outcome == "PARSED_WITH_DEBT"
    assert "UNKNOWN_SCHEMA_VERSION" in unknown.debt_codes

    draft = H.build_harvest_draft(
        run_id="run-fixture-001",
        adapter_id="plamen-native",
        inventory=inventory,
    )
    candidate_records = {
        occurrence["record_id"] for occurrence in draft.lineage["occurrences"]
    }
    partitioned_records = (
        candidate_records
        | set(draft.nonfinding_record_ids)
        | set(draft.debt_record_ids)
    )
    assert partitioned_records == {
        record.record_id
        for artifact in inventory.artifacts
        for record in artifact.records
    }
    assert len(draft.candidate_set["candidates"]) == 2
    assert draft.report_projection["report_entries"] == []
    assert len(draft.report_projection["unmapped_finding_sections"]) == 1

    public_payload = {
        "candidate_findings": draft.candidate_set,
        "candidate_lineage": draft.lineage,
        "report_projection": draft.report_projection,
        "source_receipt": draft.source_receipt,
    }
    P.validate_public_payload(public_payload)
    assert str(tmp_path) not in C.canonical_json_bytes(public_payload).decode("utf-8")


def test_harvest_never_unions_candidates_from_prose_similarity(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (scratchpad / "breadth_findings.md").write_text(
        "## [H-1] Same title\n\nFirst independently emitted claim.\n",
        encoding="utf-8",
    )
    (scratchpad / "depth_findings.md").write_text(
        "## [H-1] Same title\n\nSecond independently emitted claim.\n",
        encoding="utf-8",
    )
    report = tmp_path / "AUDIT_REPORT.md"
    report.write_text("# Audit report\n", encoding="utf-8")
    inventory = S.inventory_run_sources(
        project_root=tmp_path,
        scratchpad=scratchpad,
        report=report,
        pipeline_kind="SC",
    )
    draft = H.build_harvest_draft(
        run_id="run-fixture-002",
        adapter_id="plamen-native",
        inventory=inventory,
    )
    assert len(draft.candidate_set["candidates"]) == 2
    assert draft.lineage["edges"] == []
    assert draft.lineage["alias_classes"] == []


def test_materialized_export_is_deterministic_verified_and_refuses_overwrite(
    tmp_path: Path,
):
    documents = V2._documents()
    lock = V2._public_lock()
    lock_bytes = C.canonical_document_bytes(lock)
    first = tmp_path / "first"
    second = tmp_path / "second"

    left = E.export_materialized_payload(
        documents=copy.deepcopy(documents),
        exact_public_lock_bytes=lock_bytes,
        object_bytes={},
        out=first,
    )
    right = E.export_materialized_payload(
        documents=copy.deepcopy(documents),
        exact_public_lock_bytes=lock_bytes,
        object_bytes={},
        out=second,
    )
    assert left.bundle_seal_sha256 == right.bundle_seal_sha256
    assert E.verify_export(first, lock_bytes).bundle_seal_sha256 == left.bundle_seal_sha256
    P.assert_deterministic_exports(first, second)
    with pytest.raises(E.RunBundleExportError, match="exists|fresh"):
        E.export_materialized_payload(
            documents=documents,
            exact_public_lock_bytes=lock_bytes,
            object_bytes={},
            out=first,
        )


def test_real_scratchpad_materializes_and_seals_unsigned_user_run(tmp_path: Path):
    scratchpad, report = _write_fixture_run(tmp_path)
    lock = V2._public_lock()
    baseline = V2._manifest(lock)
    schedule = {
        "schema_version": E.PUBLIC_SCHEDULE_ROW_SCHEMA,
        "trust_profile": "USER_RUN",
        "run_id": baseline["run_id"],
        "experiment_id": baseline["experiment_id"],
        "cell_id": baseline["cell_id"],
        "repetition_index": baseline["repetition_index"],
        "seed": baseline["seed"],
        "audit_system": "PLAMEN",
        "adapter": baseline["adapter"],
        "experiment_plan_sha256": baseline["experiment_plan_sha256"],
        "campaign_schedule_sha256": baseline["campaign_schedule_sha256"],
        "model_backend": baseline["model_backend"],
        "tool_policy": baseline["tool_policy"],
        "budget": baseline["budget"],
        "resume": baseline["resume"],
        "public_launch_receipt": None,
        "pipeline_kind": "SC",
    }
    inventory = S.inventory_run_sources(
        project_root=tmp_path,
        scratchpad=scratchpad,
        report=report,
        pipeline_kind="SC",
    )
    draft = H.build_harvest_draft(
        run_id=baseline["run_id"],
        adapter_id="plamen-native",
        inventory=inventory,
    )
    documents, objects = E.materialize_local_documents(
        draft=draft,
        public_case_lock=lock,
        schedule_row=schedule,
    )
    assert documents["run_manifest.json"]["trust_profile"] == "USER_RUN"
    assert documents["run_manifest.json"]["run_context_authority"] is None
    assert documents["raw_outputs.json"]["authority_receipts"] == []
    assert C.derive_publication_ceiling(
        documents["run_manifest.json"]
    ) == "USER_RUN"

    out = tmp_path / "sealed"
    receipt = E.export_materialized_payload(
        documents=documents,
        exact_public_lock_bytes=C.canonical_document_bytes(lock),
        object_bytes=objects,
        out=out,
    )
    assert receipt.publication_ceiling == "USER_RUN"
    assert C.verify_runbundle_v2(
        out, C.canonical_document_bytes(lock)
    ).bundle_seal_sha256 == receipt.bundle_seal_sha256


def test_export_rechecks_live_source_closure_at_publication_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """S-13: a mutation after inventory capture must not publish stale bytes.

    The wrapper is an exact synchronization point: the first staging
    verification has completed, but publication has not.  No timing or sleep
    assumption is involved.
    """

    scratchpad, report, lock_path, schedule_path = _write_public_export_inputs(
        tmp_path
    )
    original_verify = C.verify_runbundle_v2
    mutated = False

    def mutate_after_staging_verification(bundle, exact_public_lock_bytes):
        nonlocal mutated
        verified = original_verify(bundle, exact_public_lock_bytes)
        if not mutated and Path(bundle).name.endswith(".staging"):
            mutated = True
            report.write_bytes(
                report.read_bytes()
                + b"\n## Late finding\n\nThis source arrived after inventory.\n"
            )
        return verified

    monkeypatch.setattr(
        C, "verify_runbundle_v2", mutate_after_staging_verification
    )
    out = tmp_path / "sealed-after-drift"
    with pytest.raises(
        (E.RunBundleExportError, S.RunBundleSourceError),
        match="MUTATED_DURING_EXPORT|source.*changed|closure",
    ):
        E.export_from_run(
            project_root=tmp_path,
            scratchpad=scratchpad,
            report=report,
            public_case_lock=lock_path,
            schedule_row=schedule_path,
            out=out,
        )
    assert mutated is True
    assert not out.exists()
    mutation_receipts = list(
        tmp_path.glob(".sealed-after-drift.mutation-*.json")
    )
    assert len(mutation_receipts) == 1
    mutation = C.strict_json_load(
        mutation_receipts[0], require_canonical=True
    )
    assert mutation["schema_version"] == E.MUTATION_RECEIPT_SCHEMA
    assert mutation["outcome"] == "MUTATED_DURING_EXPORT"
    assert mutation["stage"] == "PRE_PUBLICATION"
    assert mutation["input_source_authority_sha256"]
    assert str(tmp_path) not in mutation_receipts[0].read_text("utf-8")
    assert not list(tmp_path.glob(".sealed-after-drift.*.staging"))


@pytest.mark.parametrize("rename_window", ["BEFORE_RENAME", "AFTER_RENAME"])
def test_export_rechecks_live_source_closure_across_promotion_rename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    rename_window: str,
):
    """R9 red: rename-synchronized source drift must not remain accepted."""

    scratchpad, report, lock_path, schedule_path = _write_public_export_inputs(
        tmp_path
    )
    out = tmp_path / f"sealed-{rename_window.lower()}"
    original_rename = E._durable_directory_rename_new
    mutated = False

    def mutate_at_promotion_rename(source: Path, target: Path) -> None:
        nonlocal mutated
        is_promotion = (
            not mutated
            and source.name.endswith(".staging")
            and Path(target) == out
        )
        if is_promotion and rename_window == "BEFORE_RENAME":
            report.write_bytes(
                report.read_bytes() + b"\npre-rename source drift\n"
            )
            mutated = True
        original_rename(Path(source), Path(target))
        if is_promotion and rename_window == "AFTER_RENAME":
            report.write_bytes(
                report.read_bytes() + b"\npost-rename source drift\n"
            )
            mutated = True
    monkeypatch.setattr(
        E, "_durable_directory_rename_new", mutate_at_promotion_rename
    )
    with pytest.raises(E.RunBundleExportError, match="MUTATED_DURING_EXPORT"):
        E.export_from_run(
            project_root=tmp_path,
            scratchpad=scratchpad,
            report=report,
            public_case_lock=lock_path,
            schedule_row=schedule_path,
            out=out,
        )
    assert mutated is True
    assert not out.exists()
    assert not list(tmp_path.glob(f".{out.name}.*.staging"))
    receipts = list(tmp_path.glob(f".{out.name}.mutation-*.json"))
    assert len(receipts) == 1
    receipt = C.strict_json_load(receipts[0], require_canonical=True)
    assert receipt["outcome"] == "MUTATED_DURING_EXPORT"
    assert receipt["stage"] == "POST_PROMOTION"


@pytest.mark.parametrize("rename_window", ["BEFORE_RENAME", "AFTER_RENAME"])
def test_recovery_rechecks_live_source_closure_across_promotion_rename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    rename_window: str,
):
    """R9 red: recovered publication has the same late closure as export."""

    (
        scratchpad,
        report,
        lock_raw,
        inventory,
        documents,
        objects,
    ) = _materialized_live_fixture(tmp_path)
    out = tmp_path / f"recovered-{rename_window.lower()}"
    with pytest.raises(E.RunBundleExportInterrupted):
        E.export_materialized_payload(
            documents=documents,
            exact_public_lock_bytes=lock_raw,
            object_bytes=objects,
            out=out,
            _fault_after="INDEX",
            _live_source_authority_sha256=(
                inventory.live_source_authority_sha256
            ),
            _live_source_closure=lambda: S.verify_live_source_closure(
                project_root=tmp_path,
                scratchpad=scratchpad,
                report=report,
                inventory=inventory,
            ),
        )
    journal = next(
        tmp_path.glob(f".{out.name}.*.staging/export.journal.json")
    )
    original_publish = E._durable_directory_rename_new
    mutated = False

    def mutate_at_recovered_promotion(source: Path, target: Path) -> None:
        nonlocal mutated
        is_promotion = (
            not mutated
            and Path(source).name.endswith(".staging")
            and Path(target) == out
        )
        if is_promotion and rename_window == "BEFORE_RENAME":
            report.write_bytes(
                report.read_bytes() + b"\nrecovery pre-rename drift\n"
            )
            mutated = True
        original_publish(Path(source), Path(target))
        if is_promotion and rename_window == "AFTER_RENAME":
            report.write_bytes(
                report.read_bytes() + b"\nrecovery post-rename drift\n"
            )
            mutated = True

    monkeypatch.setattr(
        E, "_durable_directory_rename_new", mutate_at_recovered_promotion
    )
    with pytest.raises(E.RunBundleExportError, match="MUTATED_DURING_EXPORT"):
        E.recover_export(
            journal=journal,
            exact_public_lock_bytes=lock_raw,
            out=out,
            project_root=tmp_path,
            scratchpad=scratchpad,
            report=report,
        )
    assert mutated is True
    assert not out.exists()
    assert not E.publication_ready_path(out).exists()
    receipts = list(tmp_path.glob(f".{out.name}.mutation-*.json"))
    assert len(receipts) == 1
    receipt = C.strict_json_load(receipts[0], require_canonical=True)
    assert receipt["outcome"] == "MUTATED_DURING_EXPORT"
    assert receipt["stage"] == "RECOVERY_POST_PROMOTION"


@pytest.mark.parametrize(
    "mutation",
    [
        "scratch-added",
        "scratch-removed",
        "scratch-renamed",
        "scratch-replaced-identical",
        "report-replaced-identical",
        "report-content-restored-mtime",
        "scratch-hardlink",
        "scratch-symlink",
        "scratch-reparse",
    ],
)
def test_post_promotion_live_closure_rejects_exact_late_drift_matrix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
):
    """R9: the post-rename gate re-enumerates bytes and physical identity."""

    scratchpad, report, lock_path, schedule_path = _write_public_export_inputs(
        tmp_path
    )
    out = tmp_path / f"post-promotion-{mutation}"
    original_publish = E._durable_directory_rename_new
    mutated = False

    def mutate_after_promotion(source: Path, target: Path) -> None:
        nonlocal mutated
        original_publish(Path(source), Path(target))
        if (
            not mutated
            and Path(source).name.endswith(".staging")
            and Path(target) == out
        ):
            mutated = True
            _apply_late_source_mutation(
                mutation=mutation,
                root=tmp_path,
                scratchpad=scratchpad,
                report=report,
                monkeypatch=monkeypatch,
            )

    monkeypatch.setattr(
        E, "_durable_directory_rename_new", mutate_after_promotion
    )
    with pytest.raises(E.RunBundleExportError, match="MUTATED_DURING_EXPORT"):
        E.export_from_run(
            project_root=tmp_path,
            scratchpad=scratchpad,
            report=report,
            public_case_lock=lock_path,
            schedule_row=schedule_path,
            out=out,
        )
    assert mutated is True
    assert not out.exists()
    assert not E.publication_ready_path(out).exists()
    receipts = list(tmp_path.glob(f".{out.name}.mutation-*.json"))
    assert len(receipts) == 1
    receipt = C.strict_json_load(receipts[0], require_canonical=True)
    assert receipt["stage"] == "POST_PROMOTION"


def test_promoted_verification_and_pre_ready_windows_recheck_live_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """R9: mutation during promoted verification is caught before READY."""

    scratchpad, report, lock_path, schedule_path = _write_public_export_inputs(
        tmp_path
    )
    out = tmp_path / "verify-window"
    original_verify = C.verify_runbundle_v2
    mutated = False

    def mutate_during_promoted_verify(bundle, exact_public_lock_bytes):
        nonlocal mutated
        verified = original_verify(bundle, exact_public_lock_bytes)
        if not mutated and Path(bundle) == out:
            mutated = True
            report.write_bytes(
                report.read_bytes() + b"\nmutated during promoted verify\n"
            )
        return verified

    monkeypatch.setattr(
        C, "verify_runbundle_v2", mutate_during_promoted_verify
    )
    with pytest.raises(E.RunBundleExportError, match="MUTATED_DURING_EXPORT"):
        E.export_from_run(
            project_root=tmp_path,
            scratchpad=scratchpad,
            report=report,
            public_case_lock=lock_path,
            schedule_row=schedule_path,
            out=out,
        )
    assert mutated is True
    assert not out.exists()
    receipts = list(tmp_path.glob(f".{out.name}.mutation-*.json"))
    assert len(receipts) == 1
    assert (
        C.strict_json_load(receipts[0], require_canonical=True)["stage"]
        == "POST_VERIFY_PRE_READY"
    )


def test_post_promotion_interruption_is_unready_and_resumable(
    tmp_path: Path,
):
    """R9: a crash prefix after rename has an external recovery authority."""

    (
        scratchpad,
        report,
        lock_raw,
        inventory,
        documents,
        objects,
    ) = _materialized_live_fixture(tmp_path)
    out = tmp_path / "promoted-interruption"
    with pytest.raises(E.RunBundleExportInterrupted):
        E.export_materialized_payload(
            documents=documents,
            exact_public_lock_bytes=lock_raw,
            object_bytes=objects,
            out=out,
            _fault_after="PROMOTED",
            _live_source_authority_sha256=(
                inventory.live_source_authority_sha256
            ),
            _live_source_closure=lambda: S.verify_live_source_closure(
                project_root=tmp_path,
                scratchpad=scratchpad,
                report=report,
                inventory=inventory,
            ),
        )
    journals = list(
        tmp_path.glob(f".{out.name}.*.promotion.json")
    )
    assert out.is_dir()
    assert len(journals) == 1
    assert not E.publication_ready_path(out).exists()
    with pytest.raises(E.RunBundleExportError, match="READY"):
        E.verify_export(out, lock_raw)

    recovered = E.recover_export(
        journal=journals[0],
        exact_public_lock_bytes=lock_raw,
        out=out,
        project_root=tmp_path,
        scratchpad=scratchpad,
        report=report,
    )
    assert recovered.bundle_root == out.resolve()
    assert recovered.publication_ready_path.is_file()
    assert not journals[0].exists()
    assert E.verify_export(
        out, lock_raw
    ).publication_ready_sha256 == recovered.publication_ready_sha256


def test_post_promotion_interruption_with_source_drift_retires_generation(
    tmp_path: Path,
):
    """R9: resumed late drift cannot turn an interrupted target into READY."""

    (
        scratchpad,
        report,
        lock_raw,
        inventory,
        documents,
        objects,
    ) = _materialized_live_fixture(tmp_path)
    out = tmp_path / "promoted-drift"
    with pytest.raises(E.RunBundleExportInterrupted):
        E.export_materialized_payload(
            documents=documents,
            exact_public_lock_bytes=lock_raw,
            object_bytes=objects,
            out=out,
            _fault_after="PROMOTED",
            _live_source_authority_sha256=(
                inventory.live_source_authority_sha256
            ),
            _live_source_closure=lambda: S.verify_live_source_closure(
                project_root=tmp_path,
                scratchpad=scratchpad,
                report=report,
                inventory=inventory,
            ),
        )
    journal = next(tmp_path.glob(f".{out.name}.*.promotion.json"))
    report.write_bytes(report.read_bytes() + b"\ninterrupted drift\n")
    with pytest.raises(E.RunBundleExportError, match="MUTATED_DURING_EXPORT"):
        E.recover_export(
            journal=journal,
            exact_public_lock_bytes=lock_raw,
            out=out,
            project_root=tmp_path,
            scratchpad=scratchpad,
            report=report,
        )
    assert not out.exists()
    assert not E.publication_ready_path(out).exists()
    assert E.publication_retirement_path(out).is_file()


def test_ready_binds_bounded_observations_without_perpetual_claim(
    tmp_path: Path,
):
    """R9: READY proves exact checks, not continuous source immutability."""

    scratchpad, report, lock_path, schedule_path = _write_public_export_inputs(
        tmp_path
    )
    out = tmp_path / "bounded-ready"
    receipt = E.export_from_run(
        project_root=tmp_path,
        scratchpad=scratchpad,
        report=report,
        public_case_lock=lock_path,
        schedule_row=schedule_path,
        out=out,
    )
    ready = C.strict_json_load(
        receipt.publication_ready_path,
        require_canonical=True,
    )
    stability = ready["source_stability"]
    assert stability["state"] == "LIVE_SOURCE_MATCHED_AT_BOUNDED_CHECKS"
    assert stability["source_authority_sha256"]
    assert stability["claim_limitation"] == (
        "BOUNDED_OBSERVATIONS_NOT_CONTINUOUS_OR_PERPETUAL_IMMUTABILITY"
    )
    assert [row["stage"] for row in stability["observations"]] == [
        "POST_PROMOTION",
        "POST_VERIFY_PRE_READY",
    ]
    assert stability["observation_set_sha256"] == C.document_sha256(
        {"observations": stability["observations"]}
    )
    for observation in stability["observations"]:
        C.verify_embedded_sha256(observation, "observation_sha256")
        assert observation["source_authority_sha256"] == (
            stability["source_authority_sha256"]
        )
        assert observation["started_at_utc"] <= (
            observation["completed_at_utc"]
        )


def test_pre_ready_entry_rechecks_live_source_and_emits_typed_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """R9: the READY publisher itself owns its final live observation."""

    scratchpad, report, lock_path, schedule_path = _write_public_export_inputs(
        tmp_path
    )
    out = tmp_path / "pre-ready-entry"
    original_publish_ready = E._publish_publication_ready
    mutated = False

    def mutate_before_ready(**kwargs):
        nonlocal mutated
        if not mutated:
            mutated = True
            report.write_bytes(
                report.read_bytes() + b"\npre-ready entry drift\n"
            )
        return original_publish_ready(**kwargs)

    monkeypatch.setattr(
        E, "_publish_publication_ready", mutate_before_ready
    )
    with pytest.raises(E.RunBundleExportError, match="MUTATED_DURING_EXPORT"):
        E.export_from_run(
            project_root=tmp_path,
            scratchpad=scratchpad,
            report=report,
            public_case_lock=lock_path,
            schedule_row=schedule_path,
            out=out,
        )
    assert mutated is True
    assert not out.exists()
    receipt = C.strict_json_load(
        next(tmp_path.glob(f".{out.name}.mutation-*.json")),
        require_canonical=True,
    )
    assert receipt["stage"] == "POST_VERIFY_PRE_READY"


def test_ready_tamper_before_return_retires_promoted_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """R9: success returns only after re-reading exact on-disk READY bytes."""

    scratchpad, report, lock_path, schedule_path = _write_public_export_inputs(
        tmp_path
    )
    out = tmp_path / "ready-tamper"
    ready_path = E.publication_ready_path(out)
    original_publish_control = E._write_or_load_exact_control
    tampered = False

    def tamper_ready_after_write(
        path: Path,
        raw: bytes,
        *,
        label: str,
    ) -> Path:
        nonlocal tampered
        result = original_publish_control(Path(path), raw, label=label)
        if Path(path) == ready_path and not tampered:
            tampered = True
            Path(path).write_bytes(b"{\"tampered\":true}\n")
        return result

    monkeypatch.setattr(
        E, "_write_or_load_exact_control", tamper_ready_after_write
    )
    with pytest.raises(E.RunBundleExportError, match="READY|retire"):
        E.export_from_run(
            project_root=tmp_path,
            scratchpad=scratchpad,
            report=report,
            public_case_lock=lock_path,
            schedule_row=schedule_path,
            out=out,
        )
    assert tampered is True
    assert not out.exists()
    assert E.publication_retirement_path(out).is_file()
    with pytest.raises(E.RunBundleExportError, match="RETIRED"):
        E.verify_export(out, lock_path.read_bytes())


def test_unready_or_retired_bundle_cannot_be_harvested(
    tmp_path: Path,
):
    """R9 red: a seal alone is never production publication authority."""

    lock_raw = C.canonical_document_bytes(V2._public_lock())
    out = tmp_path / "unready"
    receipt = E.export_materialized_payload(
        documents=V2._documents(),
        exact_public_lock_bytes=lock_raw,
        object_bytes={},
        out=out,
    )
    assert E.verify_export(
        out, lock_raw
    ).bundle_seal_sha256 == receipt.bundle_seal_sha256
    E.publication_ready_path(out).unlink()
    with pytest.raises(E.RunBundleExportError, match="READY"):
        E.verify_export(out, lock_raw)

    retired = E.publication_retirement_path(out)
    retired.write_bytes(
        C.canonical_document_bytes(
            C.bind_embedded_sha256(
                {
                    "schema_version": E.PUBLICATION_RETIREMENT_SCHEMA,
                    "status": "RETIRED",
                    "run_id": receipt.run_id,
                    "output_name": out.name,
                    "control_receipt_name": ".synthetic-control.json",
                    "control_receipt_sha256": "1" * 64,
                    "retired_at_utc": "2026-07-29T00:00:00.000000Z",
                    "retirement_rule": "NO_READY_NO_HARVEST",
                    "exporter_code_sha256": E.exporter_code_sha256(),
                    "exporter_policy_sha256": E.exporter_policy_sha256(),
                },
                "retirement_sha256",
            )
        )
    )
    with pytest.raises(E.RunBundleExportError, match="RETIRED|READY"):
        E.verify_export(out, lock_raw)


def test_failed_post_promotion_retirement_is_loud_and_unharvestable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """R9 red: quarantine failure cannot leave a harvestable sealed target."""

    scratchpad, report, lock_path, schedule_path = _write_public_export_inputs(
        tmp_path
    )
    out = tmp_path / "retirement-failure"
    original_publish = E._durable_directory_rename_new
    promotion_finished = False

    def fail_retirement(source: Path, target: Path) -> None:
        nonlocal promotion_finished
        if Path(source) == out:
            raise OSError("forced quarantine failure")
        original_publish(Path(source), Path(target))
        if Path(target) == out:
            promotion_finished = True
            report.write_bytes(
                report.read_bytes() + b"\npost-promotion cleanup fault\n"
            )

    monkeypatch.setattr(E, "_durable_directory_rename_new", fail_retirement)
    with pytest.raises(
        E.RunBundleExportError,
        match="retire|retirement|quarantine",
    ):
        E.export_from_run(
            project_root=tmp_path,
            scratchpad=scratchpad,
            report=report,
            public_case_lock=lock_path,
            schedule_row=schedule_path,
            out=out,
        )
    assert promotion_finished is True
    assert not E.publication_ready_path(out).exists()
    assert E.publication_retirement_path(out).is_file()
    with pytest.raises(E.RunBundleExportError, match="RETIRED|READY"):
        E.verify_export(out, lock_path.read_bytes())


def test_forged_ready_cannot_upgrade_drifted_interrupted_live_bundle(
    tmp_path: Path,
):
    """R10 red: self-consistent READY cannot replace trusted recovery."""

    (
        scratchpad,
        report,
        lock_raw,
        inventory,
        documents,
        objects,
    ) = _materialized_live_fixture(tmp_path)
    out = tmp_path / "forged-ready"
    with pytest.raises(E.RunBundleExportInterrupted):
        E.export_materialized_payload(
            documents=documents,
            exact_public_lock_bytes=lock_raw,
            object_bytes=objects,
            out=out,
            _fault_after="PROMOTED",
            _live_source_authority_sha256=(
                inventory.live_source_authority_sha256
            ),
            _live_source_closure=lambda: S.verify_live_source_closure(
                project_root=tmp_path,
                scratchpad=scratchpad,
                report=report,
                inventory=inventory,
            ),
        )
    journal = next(tmp_path.glob(f".{out.name}.*.promotion.json"))
    journal_row = C.strict_json_load(journal, require_canonical=True)
    report.write_bytes(report.read_bytes() + b"\nsource drift after crash\n")
    with pytest.raises(S.RunBundleSourceError):
        S.verify_live_source_closure(
            project_root=tmp_path,
            scratchpad=scratchpad,
            report=report,
            inventory=inventory,
        )
    verified = C.verify_runbundle_v2(out, lock_raw)
    _write_forged_publication_ready(
        out=out,
        verified=verified,
        source_authority_sha256=journal_row[
            "live_source_authority_sha256"
        ],
    )
    assert not E.publication_retirement_path(out).exists()
    with pytest.raises(
        E.RunBundleExportError,
        match="READY|authority|observation|RECOVERY|recovery",
    ):
        E.verify_export(out, lock_raw)


@pytest.mark.parametrize("mode", ["direct", "recovery"])
def test_post_ready_promotion_journal_cleanup_failure_is_loud(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
):
    """R10 red: accepted READY plus cleanup debt is not ordinary success."""

    scratchpad, report, lock_raw, inventory, documents, objects = (
        _materialized_live_fixture(tmp_path)
    )
    out = tmp_path / f"cleanup-debt-{mode}"
    if mode == "recovery":
        with pytest.raises(E.RunBundleExportInterrupted):
            E.export_materialized_payload(
                documents=documents,
                exact_public_lock_bytes=lock_raw,
                object_bytes=objects,
                out=out,
                _fault_after="INDEX",
                _live_source_authority_sha256=(
                    inventory.live_source_authority_sha256
                ),
                _live_source_closure=lambda: S.verify_live_source_closure(
                    project_root=tmp_path,
                    scratchpad=scratchpad,
                    report=report,
                    inventory=inventory,
                ),
            )
        recovery_journal = next(
            tmp_path.glob(f".{out.name}.*.staging/export.journal.json")
        )
    original_unlink = Path.unlink
    cleanup_failures = 0

    def fail_post_ready_promotion_cleanup(
        path: Path,
        *args,
        **kwargs,
    ):
        nonlocal cleanup_failures
        if (
            path.name.endswith(".promotion.json")
            and E.publication_ready_path(out).is_file()
        ):
            cleanup_failures += 1
            raise OSError("forced post-READY promotion-journal cleanup debt")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_post_ready_promotion_cleanup)
    with pytest.raises(E.RunBundleExportError, match="cleanup|journal|debt"):
        if mode == "direct":
            E.export_materialized_payload(
                documents=documents,
                exact_public_lock_bytes=lock_raw,
                object_bytes=objects,
                out=out,
                _live_source_authority_sha256=(
                    inventory.live_source_authority_sha256
                ),
                _live_source_closure=lambda: S.verify_live_source_closure(
                    project_root=tmp_path,
                    scratchpad=scratchpad,
                    report=report,
                    inventory=inventory,
                ),
            )
        else:
            E.recover_export(
                journal=recovery_journal,
                exact_public_lock_bytes=lock_raw,
                out=out,
                project_root=tmp_path,
                scratchpad=scratchpad,
                report=report,
            )
    assert cleanup_failures == 1
    assert E.publication_ready_path(out).is_file()
    assert list(tmp_path.glob(f".{out.name}.*.promotion.json"))
    assert E.verify_export(out, lock_raw).run_id == documents[
        "run_manifest.json"
    ]["run_id"]


def test_retirement_quarantine_retry_reuses_durable_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """R10 red: one transient quarantine fault is retry-idempotent."""

    scratchpad, report, lock_path, schedule_path = _write_public_export_inputs(
        tmp_path
    )
    out = tmp_path / "retirement-retry"
    original_publish = E._durable_directory_rename_new
    quarantine_failures = 0

    def fail_first_quarantine(source: Path, target: Path) -> None:
        nonlocal quarantine_failures
        source = Path(source)
        target = Path(target)
        if source == out and quarantine_failures == 0:
            quarantine_failures += 1
            raise OSError("one-time quarantine rename failure")
        original_publish(source, target)
        if target == out:
            report.write_bytes(
                report.read_bytes() + b"\npost-promotion retry drift\n"
            )

    monkeypatch.setattr(
        E, "_durable_directory_rename_new", fail_first_quarantine
    )
    with pytest.raises(
        E.RunBundleExportError,
        match="retire|retirement|quarantine",
    ):
        E.export_from_run(
            project_root=tmp_path,
            scratchpad=scratchpad,
            report=report,
            public_case_lock=lock_path,
            schedule_row=schedule_path,
            out=out,
        )
    assert quarantine_failures == 1
    retirement_path = E.publication_retirement_path(out)
    retirement_before = retirement_path.read_bytes()
    retirement = C.strict_json_loads(
        retirement_before, require_canonical=True
    )
    quarantine = tmp_path / (
        f".{out.name}.retired-{retirement['retirement_sha256'][:16]}"
    )
    promotion_journal = next(
        tmp_path.glob(f".{out.name}.*.promotion.json")
    )
    assert out.is_dir()
    assert not quarantine.exists()
    assert not E.publication_ready_path(out).exists()

    with pytest.raises(E.RunBundleMutationError, match="MUTATED_DURING_EXPORT"):
        E.recover_export(
            journal=promotion_journal,
            exact_public_lock_bytes=lock_path.read_bytes(),
            out=out,
            project_root=tmp_path,
            scratchpad=scratchpad,
            report=report,
        )
    assert not out.exists()
    assert quarantine.is_dir()
    assert retirement_path.read_bytes() == retirement_before
    with pytest.raises(E.RunBundleExportError, match="RETIRED|READY"):
        E.verify_export(out, lock_path.read_bytes())


def test_unsigned_ready_v1_without_journal_is_local_integrity_only(
    tmp_path: Path,
):
    """R10: deleting the journal cannot create authenticated provenance."""

    (
        scratchpad,
        report,
        lock_raw,
        inventory,
        documents,
        objects,
    ) = _materialized_live_fixture(tmp_path)
    out = tmp_path / "unsigned-local-only"
    with pytest.raises(E.RunBundleExportInterrupted):
        E.export_materialized_payload(
            documents=documents,
            exact_public_lock_bytes=lock_raw,
            object_bytes=objects,
            out=out,
            _fault_after="PROMOTED",
            _live_source_authority_sha256=(
                inventory.live_source_authority_sha256
            ),
            _live_source_closure=lambda: S.verify_live_source_closure(
                project_root=tmp_path,
                scratchpad=scratchpad,
                report=report,
                inventory=inventory,
            ),
        )
    journal = next(tmp_path.glob(f".{out.name}.*.promotion.json"))
    journal_row = C.strict_json_load(journal, require_canonical=True)
    report.write_bytes(report.read_bytes() + b"\nlocal marker drift\n")
    verified = C.verify_runbundle_v2(out, lock_raw)
    _write_forged_publication_ready(
        out=out,
        verified=verified,
        source_authority_sha256=journal_row[
            "live_source_authority_sha256"
        ],
    )
    journal.unlink()
    receipt = E.verify_export(
        out,
        lock_raw,
        required_assurance=E.INTEGRITY_ONLY,
    )
    assert receipt.bundle_integrity == "VERIFIED"
    assert receipt.ready_schema == E.PUBLICATION_READY_SCHEMA
    assert receipt.ready_assurance == "UNAUTHENTICATED_LOCAL"
    assert (
        receipt.source_observation_claim
        == "SELF_ASSERTED_NOT_AUTHENTICATED"
    )
    assert receipt.cleanup_state == "COMPLETE"
    assert receipt.publication_ceiling == "USER_RUN"
    with pytest.raises(E.RunBundleAuthorityError, match="unsigned|attestation"):
        E.verify_export(
            out,
            lock_raw,
            required_assurance=E.AUTHENTICATED_EXPORT_ATTESTATION,
        )


def test_missing_cleanup_debt_with_live_journal_requires_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """R10: journal plus READY is not honest cleanup debt without receipt."""

    scratchpad, report, lock_raw, inventory, documents, objects = (
        _materialized_live_fixture(tmp_path)
    )
    out = tmp_path / "missing-cleanup-debt"
    original_unlink = Path.unlink

    def fail_cleanup(path: Path, *args, **kwargs):
        if (
            path.name.endswith(".promotion.json")
            and E.publication_ready_path(out).is_file()
        ):
            raise OSError("forced cleanup failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_cleanup)
    with pytest.raises(E.RunBundleCleanupDebtError):
        E.export_materialized_payload(
            documents=documents,
            exact_public_lock_bytes=lock_raw,
            object_bytes=objects,
            out=out,
            _live_source_authority_sha256=(
                inventory.live_source_authority_sha256
            ),
            _live_source_closure=lambda: S.verify_live_source_closure(
                project_root=tmp_path,
                scratchpad=scratchpad,
                report=report,
                inventory=inventory,
            ),
        )
    E.publication_cleanup_debt_path(out).unlink()
    with pytest.raises(E.RunBundleRecoveryRequiredError, match="RECOVERY"):
        E.verify_export(out, lock_raw)


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("run_id", "run-foreign"),
        ("output_name", "foreign-output"),
        (
            "promotion_journal_name",
            ".foreign-output.0000000000000000.promotion.json",
        ),
    ],
)
def test_cleanup_debt_replay_binding_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    replacement: str,
):
    """R10: debt cannot replay across run, output, or transaction."""

    scratchpad, report, lock_raw, inventory, documents, objects = (
        _materialized_live_fixture(tmp_path)
    )
    out = tmp_path / f"cleanup-binding-{field}"
    original_unlink = Path.unlink

    def fail_cleanup(path: Path, *args, **kwargs):
        if (
            path.name.endswith(".promotion.json")
            and E.publication_ready_path(out).is_file()
        ):
            raise OSError("forced cleanup failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_cleanup)
    with pytest.raises(E.RunBundleCleanupDebtError):
        E.export_materialized_payload(
            documents=documents,
            exact_public_lock_bytes=lock_raw,
            object_bytes=objects,
            out=out,
            _live_source_authority_sha256=(
                inventory.live_source_authority_sha256
            ),
            _live_source_closure=lambda: S.verify_live_source_closure(
                project_root=tmp_path,
                scratchpad=scratchpad,
                report=report,
                inventory=inventory,
            ),
        )
    debt_path = E.publication_cleanup_debt_path(out)
    debt = C.strict_json_load(debt_path, require_canonical=True)
    debt[field] = replacement
    debt = C.bind_embedded_sha256(
        {key: value for key, value in debt.items() if key != "debt_sha256"},
        "debt_sha256",
    )
    debt_path.write_bytes(C.canonical_document_bytes(debt))
    with pytest.raises(E.RunBundleExportError, match="cleanup|debt|bind"):
        E.verify_export(out, lock_raw)


def test_cleanup_only_recovery_preserves_ready_after_later_source_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """R10: genuine READY cleanup does not replay later mutable sources."""

    scratchpad, report, lock_raw, inventory, documents, objects = (
        _materialized_live_fixture(tmp_path)
    )
    out = tmp_path / "cleanup-only-source-drift"
    original_unlink = Path.unlink
    failed_once = False

    def fail_cleanup_once(path: Path, *args, **kwargs):
        nonlocal failed_once
        if (
            not failed_once
            and path.name.endswith(".promotion.json")
            and E.publication_ready_path(out).is_file()
        ):
            failed_once = True
            raise OSError("one-time cleanup failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_cleanup_once)
    with pytest.raises(E.RunBundleCleanupDebtError):
        E.export_materialized_payload(
            documents=documents,
            exact_public_lock_bytes=lock_raw,
            object_bytes=objects,
            out=out,
            _live_source_authority_sha256=(
                inventory.live_source_authority_sha256
            ),
            _live_source_closure=lambda: S.verify_live_source_closure(
                project_root=tmp_path,
                scratchpad=scratchpad,
                report=report,
                inventory=inventory,
            ),
        )
    journal = next(tmp_path.glob(f".{out.name}.*.promotion.json"))
    report.write_bytes(report.read_bytes() + b"\nlater source drift\n")
    recovered = E.recover_export(
        journal=journal,
        exact_public_lock_bytes=lock_raw,
        out=out,
        project_root=tmp_path,
        scratchpad=scratchpad,
        report=report,
    )
    assert recovered.cleanup_state == "COMPLETE"
    assert recovered.ready_assurance == "UNAUTHENTICATED_LOCAL"
    assert E.publication_ready_path(out).is_file()
    assert not E.publication_cleanup_debt_path(out).exists()
    assert not journal.exists()
    assert not E.publication_retirement_path(out).exists()


def test_cleanup_recovery_after_journal_unlink_durability_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """R10: debt survives unlink/fsync split and cleanup resumes exactly."""

    scratchpad, report, lock_raw, inventory, documents, objects = (
        _materialized_live_fixture(tmp_path)
    )
    out = tmp_path / "cleanup-after-unlink"
    original_fsync = E._fsync_directory
    failed_once = False

    def fail_once_after_journal_unlink(path: Path) -> None:
        nonlocal failed_once
        if (
            not failed_once
            and E.publication_ready_path(out).is_file()
            and not list(tmp_path.glob(f".{out.name}.*.promotion.json"))
        ):
            failed_once = True
            raise E.RunBundleExportError(
                "forced post-unlink parent durability failure"
            )
        original_fsync(path)

    monkeypatch.setattr(E, "_fsync_directory", fail_once_after_journal_unlink)
    with pytest.raises(E.RunBundleCleanupDebtError):
        E.export_materialized_payload(
            documents=documents,
            exact_public_lock_bytes=lock_raw,
            object_bytes=objects,
            out=out,
            _live_source_authority_sha256=(
                inventory.live_source_authority_sha256
            ),
            _live_source_closure=lambda: S.verify_live_source_closure(
                project_root=tmp_path,
                scratchpad=scratchpad,
                report=report,
                inventory=inventory,
            ),
        )
    assert failed_once is True
    debt_path = E.publication_cleanup_debt_path(out)
    debt = C.strict_json_load(debt_path, require_canonical=True)
    absent_journal = tmp_path / debt["promotion_journal_name"]
    assert not absent_journal.exists()
    assert E.verify_export(out, lock_raw).cleanup_state == "DEBT"
    recovered = E.recover_export(
        journal=absent_journal,
        exact_public_lock_bytes=lock_raw,
        out=out,
        project_root=tmp_path,
        scratchpad=scratchpad,
        report=report,
    )
    assert recovered.cleanup_state == "COMPLETE"
    assert not debt_path.exists()


def test_ready_v2_shape_never_downgrades_to_unsigned_v1(
    tmp_path: Path,
):
    """R10: an unsupported signed shape is rejected, never reinterpreted."""

    lock_raw = C.canonical_document_bytes(V2._public_lock())
    out = tmp_path / "ready-v2-no-fallback"
    E.export_materialized_payload(
        documents=V2._documents(),
        exact_public_lock_bytes=lock_raw,
        object_bytes={},
        out=out,
    )
    ready_path = E.publication_ready_path(out)
    ready = C.strict_json_load(ready_path, require_canonical=True)
    ready["schema_version"] = "plamen.runbundle-publication-ready.v2"
    ready = C.bind_embedded_sha256(
        {key: value for key, value in ready.items() if key != "ready_sha256"},
        "ready_sha256",
    )
    ready_path.write_bytes(C.canonical_document_bytes(ready))
    with pytest.raises(E.RunBundleExportError, match="READY|invalid|schema"):
        E.verify_export(
            out,
            lock_raw,
            required_assurance=E.AUTHENTICATED_EXPORT_ATTESTATION,
        )
    assert C.strict_json_load(
        ready_path, require_canonical=True
    )["schema_version"].endswith(".v2")


def test_ready_and_retired_conflict_has_retired_precedence(
    tmp_path: Path,
):
    """R10: RETIRED always denies even when a valid local READY survives."""

    lock_raw = C.canonical_document_bytes(V2._public_lock())
    out = tmp_path / "ready-retired-precedence"
    receipt = E.export_materialized_payload(
        documents=V2._documents(),
        exact_public_lock_bytes=lock_raw,
        object_bytes={},
        out=out,
    )
    assert E.publication_ready_path(out).is_file()
    E.publication_retirement_path(out).write_bytes(
        b'{"status":"RETIRED"}\n'
    )
    with pytest.raises(E.RunBundleExportError, match="RETIRED"):
        E.verify_export(out, lock_raw)
    assert receipt.ready_assurance == "UNAUTHENTICATED_LOCAL"


@pytest.mark.parametrize("topology", ["mismatched-receipt", "both-present"])
def test_retirement_retry_rejects_mismatched_persisted_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    topology: str,
):
    """R10: persisted retirement bindings and topology fail closed."""

    scratchpad, report, lock_path, schedule_path = _write_public_export_inputs(
        tmp_path
    )
    out = tmp_path / f"retirement-state-{topology}"
    original_publish = E._durable_directory_rename_new
    failed = False

    def fail_first_quarantine(source: Path, target: Path) -> None:
        nonlocal failed
        source = Path(source)
        target = Path(target)
        if source == out and not failed:
            failed = True
            raise OSError("one-time quarantine failure")
        original_publish(source, target)
        if target == out:
            report.write_bytes(report.read_bytes() + b"\nretire mismatch\n")

    monkeypatch.setattr(
        E, "_durable_directory_rename_new", fail_first_quarantine
    )
    with pytest.raises(E.RunBundleExportError):
        E.export_from_run(
            project_root=tmp_path,
            scratchpad=scratchpad,
            report=report,
            public_case_lock=lock_path,
            schedule_row=schedule_path,
            out=out,
        )
    retirement_path = E.publication_retirement_path(out)
    retirement = C.strict_json_load(retirement_path, require_canonical=True)
    quarantine = tmp_path / (
        f".{out.name}.retired-{retirement['retirement_sha256'][:16]}"
    )
    if topology == "mismatched-receipt":
        retirement["bundle_seal_sha256"] = "0" * 64
        retirement = C.bind_embedded_sha256(
            {
                key: value
                for key, value in retirement.items()
                if key != "retirement_sha256"
            },
            "retirement_sha256",
        )
        retirement_path.write_bytes(C.canonical_document_bytes(retirement))
    else:
        quarantine.mkdir()
    journal = next(tmp_path.glob(f".{out.name}.*.promotion.json"))
    with pytest.raises(E.RunBundleExportError):
        E.recover_export(
            journal=journal,
            exact_public_lock_bytes=lock_path.read_bytes(),
            out=out,
            project_root=tmp_path,
            scratchpad=scratchpad,
            report=report,
        )
    assert out.exists()


def test_retirement_recovery_resumes_after_quarantine_before_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """R10: quarantine completion plus stale journal is retry-idempotent."""

    scratchpad, report, lock_path, schedule_path = _write_public_export_inputs(
        tmp_path
    )
    out = tmp_path / "retired-cleanup-prefix"
    original_publish = E._durable_directory_rename_new
    quarantine_failed = False

    def fail_first_quarantine(source: Path, target: Path) -> None:
        nonlocal quarantine_failed
        source = Path(source)
        target = Path(target)
        if source == out and not quarantine_failed:
            quarantine_failed = True
            raise OSError("one-time quarantine fault")
        original_publish(source, target)
        if target == out:
            report.write_bytes(report.read_bytes() + b"\nretired prefix\n")

    monkeypatch.setattr(
        E, "_durable_directory_rename_new", fail_first_quarantine
    )
    with pytest.raises(E.RunBundleExportError):
        E.export_from_run(
            project_root=tmp_path,
            scratchpad=scratchpad,
            report=report,
            public_case_lock=lock_path,
            schedule_row=schedule_path,
            out=out,
        )
    retirement_path = E.publication_retirement_path(out)
    retirement_raw = retirement_path.read_bytes()
    retirement = C.strict_json_loads(
        retirement_raw, require_canonical=True
    )
    quarantine = tmp_path / (
        f".{out.name}.retired-{retirement['retirement_sha256'][:16]}"
    )
    journal = next(tmp_path.glob(f".{out.name}.*.promotion.json"))
    original_unlink = Path.unlink
    cleanup_failed = False

    def fail_retired_cleanup_once(path: Path, *args, **kwargs):
        nonlocal cleanup_failed
        if path == journal and quarantine.is_dir() and not cleanup_failed:
            cleanup_failed = True
            raise OSError("one-time retired cleanup fault")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_retired_cleanup_once)
    with pytest.raises(
        E.RunBundleExportError,
        match="retired publication cleanup debt",
    ):
        E.recover_export(
            journal=journal,
            exact_public_lock_bytes=lock_path.read_bytes(),
            out=out,
            project_root=tmp_path,
            scratchpad=scratchpad,
            report=report,
        )
    assert cleanup_failed is True
    assert not out.exists()
    assert quarantine.is_dir()
    assert journal.is_file()
    assert retirement_path.read_bytes() == retirement_raw
    with pytest.raises(E.RunBundleMutationError, match="MUTATED_DURING_EXPORT"):
        E.recover_export(
            journal=journal,
            exact_public_lock_bytes=lock_path.read_bytes(),
            out=out,
            project_root=tmp_path,
            scratchpad=scratchpad,
            report=report,
        )
    assert quarantine.is_dir()
    assert not journal.exists()
    assert retirement_path.read_bytes() == retirement_raw


def test_export_rechecks_live_source_closure_after_index_before_seal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """S-13: the required final live read occurs after index, before seal."""

    scratchpad, report, lock_path, schedule_path = _write_public_export_inputs(
        tmp_path
    )
    original_build_index = P.build_bundle_index
    mutated = False

    def mutate_after_index(bundle):
        nonlocal mutated
        index = original_build_index(bundle)
        if not mutated and Path(bundle).name.endswith(".staging"):
            mutated = True
            report.write_bytes(report.read_bytes() + b"\npost-index drift\n")
        return index

    monkeypatch.setattr(P, "build_bundle_index", mutate_after_index)
    out = tmp_path / "sealed-preseal-drift"
    with pytest.raises(E.RunBundleExportError, match="MUTATED_DURING_EXPORT"):
        E.export_from_run(
            project_root=tmp_path,
            scratchpad=scratchpad,
            report=report,
            public_case_lock=lock_path,
            schedule_row=schedule_path,
            out=out,
        )
    assert mutated is True
    assert not out.exists()
    assert not list(tmp_path.glob(".sealed-preseal-drift.*.staging"))
    receipts = list(
        tmp_path.glob(".sealed-preseal-drift.mutation-*.json")
    )
    assert len(receipts) == 1
    row = C.strict_json_load(receipts[0], require_canonical=True)
    assert row["outcome"] == "MUTATED_DURING_EXPORT"
    assert row["stage"] == "PRE_SEAL"


def test_inventory_rejects_mutation_after_first_complete_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    scratchpad, report, _, _ = _write_public_export_inputs(tmp_path)
    breadth = scratchpad / "breadth_findings.md"
    original_capture = P.read_stable_regular_tree_snapshot
    calls = 0

    def mutate_after_first_capture(*args, **kwargs):
        nonlocal calls
        snapshot = original_capture(*args, **kwargs)
        calls += 1
        if calls == 1:
            breadth.write_bytes(breadth.read_bytes() + b"\nfirst-window drift\n")
        return snapshot

    monkeypatch.setattr(
        P,
        "read_stable_regular_tree_snapshot",
        mutate_after_first_capture,
    )
    with pytest.raises(S.RunBundleSourceError, match="MUTATED_DURING_EXPORT"):
        S.inventory_run_sources(
            project_root=tmp_path,
            scratchpad=scratchpad,
            report=report,
            pipeline_kind="SC",
        )


@pytest.mark.parametrize(
    ("fault_point", "mutation"),
    [
        ("HARVEST", "add"),
        ("HARVEST", "remove"),
        ("HARVEST", "rename"),
        ("MATERIALIZATION", "content"),
    ],
)
def test_export_rejects_live_roster_drift_during_harvest_and_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault_point: str,
    mutation: str,
):
    scratchpad, report, lock_path, schedule_path = _write_public_export_inputs(
        tmp_path
    )
    breadth = scratchpad / "breadth_findings.md"

    def mutate() -> None:
        if mutation == "add":
            (scratchpad / "late-during-harvest.md").write_bytes(b"late\n")
        elif mutation == "remove":
            breadth.unlink()
        elif mutation == "rename":
            breadth.rename(scratchpad / "renamed-during-harvest.md")
        else:
            report.write_bytes(report.read_bytes() + b"\nmaterialization drift\n")

    if fault_point == "HARVEST":
        original = H.build_harvest_draft

        def wrapped_harvest(*args, **kwargs):
            draft = original(*args, **kwargs)
            mutate()
            return draft

        monkeypatch.setattr(H, "build_harvest_draft", wrapped_harvest)
    else:
        original = E.materialize_local_documents

        def wrapped_materialize(*args, **kwargs):
            materialized = original(*args, **kwargs)
            mutate()
            return materialized

        monkeypatch.setattr(
            E,
            "materialize_local_documents",
            wrapped_materialize,
        )

    out = tmp_path / f"sealed-{fault_point.lower()}-{mutation}"
    with pytest.raises(E.RunBundleExportError, match="MUTATED_DURING_EXPORT"):
        E.export_from_run(
            project_root=tmp_path,
            scratchpad=scratchpad,
            report=report,
            public_case_lock=lock_path,
            schedule_row=schedule_path,
            out=out,
        )
    assert not out.exists()
    receipts = list(
        tmp_path.glob(f".{out.name}.mutation-*.json")
    )
    assert len(receipts) == 1
    assert (
        C.strict_json_load(receipts[0], require_canonical=True)["stage"]
        == "PRE_SEAL"
    )


def test_mutation_failure_preserves_an_existing_sealed_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    lock_raw = C.canonical_document_bytes(V2._public_lock())
    prior = tmp_path / "prior-generation"
    E.export_materialized_payload(
        documents=V2._documents(),
        exact_public_lock_bytes=lock_raw,
        object_bytes={},
        out=prior,
    )
    frozen_prior = P.read_verified_bundle_snapshot(prior)

    live_root = tmp_path / "live"
    live_root.mkdir()
    scratchpad, report, lock_path, schedule_path = _write_public_export_inputs(
        live_root
    )
    original = E.materialize_local_documents

    def mutate_during_materialization(*args, **kwargs):
        materialized = original(*args, **kwargs)
        report.write_bytes(report.read_bytes() + b"\nlate generation\n")
        return materialized

    monkeypatch.setattr(
        E,
        "materialize_local_documents",
        mutate_during_materialization,
    )
    failed = live_root / "next-generation"
    with pytest.raises(E.RunBundleExportError, match="MUTATED_DURING_EXPORT"):
        E.export_from_run(
            project_root=live_root,
            scratchpad=scratchpad,
            report=report,
            public_case_lock=lock_path,
            schedule_row=schedule_path,
            out=failed,
        )
    assert not failed.exists()
    P.assert_verified_bundle_snapshot_unchanged(prior, frozen_prior)


@pytest.mark.parametrize(
    "mutation",
    [
        "scratch-added",
        "scratch-removed",
        "scratch-renamed",
        "scratch-replaced-identical",
        "report-replaced-identical",
        "report-content-restored-mtime",
        "scratch-hardlink",
        "scratch-symlink",
        "scratch-reparse",
    ],
)
def test_final_live_closure_rejects_membership_identity_and_alias_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
):
    scratchpad, report, lock_path, schedule_path = _write_public_export_inputs(
        tmp_path
    )
    breadth = scratchpad / "breadth_findings.md"
    if mutation == "scratch-symlink":
        probe_target = tmp_path / "symlink-probe-target"
        probe_link = tmp_path / "symlink-probe-link"
        probe_target.write_bytes(b"probe")
        try:
            probe_link.symlink_to(probe_target)
        except OSError:
            pytest.skip("host policy does not permit symlink creation")
        else:
            probe_link.unlink()
            probe_target.unlink()

    original_verify = C.verify_runbundle_v2
    original_reparse = P._is_reparse_point
    mutated = False

    def apply_mutation() -> None:
        if mutation == "scratch-added":
            (scratchpad / "late.md").write_bytes(b"# late source\n")
        elif mutation == "scratch-removed":
            breadth.unlink()
        elif mutation == "scratch-renamed":
            breadth.rename(scratchpad / "breadth_renamed.md")
        elif mutation == "scratch-replaced-identical":
            replacement = tmp_path / "replacement-scratch"
            replacement.write_bytes(breadth.read_bytes())
            replacement.replace(breadth)
        elif mutation == "report-replaced-identical":
            replacement = tmp_path / "replacement-report"
            replacement.write_bytes(report.read_bytes())
            replacement.replace(report)
        elif mutation == "report-content-restored-mtime":
            before = report.stat()
            report.write_bytes(report.read_bytes() + b"\nlate bytes\n")
            os.utime(
                report,
                ns=(before.st_atime_ns, before.st_mtime_ns),
            )
        elif mutation == "scratch-hardlink":
            target = tmp_path / "hardlink-target"
            target.write_bytes(breadth.read_bytes())
            breadth.unlink()
            os.link(target, breadth)
        elif mutation == "scratch-symlink":
            target = tmp_path / "symlink-target"
            target.write_bytes(breadth.read_bytes())
            breadth.unlink()
            breadth.symlink_to(target)
        elif mutation == "scratch-reparse":
            monkeypatch.setattr(
                P,
                "_is_reparse_point",
                lambda path, row=None: (
                    Path(path) == breadth
                    or original_reparse(Path(path), row)
                ),
            )
        else:  # pragma: no cover - closed parametrization
            raise AssertionError(mutation)

    def mutate_after_staging_verification(bundle, exact_public_lock_bytes):
        nonlocal mutated
        verified = original_verify(bundle, exact_public_lock_bytes)
        if not mutated and Path(bundle).name.endswith(".staging"):
            mutated = True
            apply_mutation()
        return verified

    monkeypatch.setattr(
        C, "verify_runbundle_v2", mutate_after_staging_verification
    )
    out = tmp_path / f"sealed-{mutation}"
    with pytest.raises(E.RunBundleExportError, match="MUTATED_DURING_EXPORT"):
        E.export_from_run(
            project_root=tmp_path,
            scratchpad=scratchpad,
            report=report,
            public_case_lock=lock_path,
            schedule_row=schedule_path,
            out=out,
        )
    assert mutated is True
    assert not out.exists()


def test_interrupted_export_recovers_only_when_frozen_inputs_match(tmp_path: Path):
    documents = V2._documents()
    lock_bytes = C.canonical_document_bytes(V2._public_lock())
    out = tmp_path / "bundle"

    with pytest.raises(E.RunBundleExportInterrupted):
        E.export_materialized_payload(
            documents=documents,
            exact_public_lock_bytes=lock_bytes,
            object_bytes={},
            out=out,
            _fault_after="INDEX",
        )
    assert not out.exists()
    journal = next(tmp_path.glob(".bundle.*.staging/export.journal.json"))
    recovered = E.recover_export(
        journal=journal,
        exact_public_lock_bytes=lock_bytes,
        out=out,
    )
    assert recovered.bundle_root == out.resolve()
    assert E.verify_export(out, lock_bytes).bundle_seal_sha256 == recovered.bundle_seal_sha256

    other = C.canonical_document_bytes({**V2._public_lock(), "language": "rust"})
    with pytest.raises(E.RunBundleExportError):
        E.recover_export(
            journal=journal,
            exact_public_lock_bytes=other,
            out=out,
        )


def test_live_export_recovery_requires_matching_late_source_authority(
    tmp_path: Path,
):
    (
        scratchpad,
        report,
        lock_raw,
        inventory,
        documents,
        objects,
    ) = _materialized_live_fixture(tmp_path)

    matching = tmp_path / "matching-live-recovery"
    with pytest.raises(E.RunBundleExportInterrupted):
        E.export_materialized_payload(
            documents=documents,
            exact_public_lock_bytes=lock_raw,
            object_bytes=objects,
            out=matching,
            _fault_after="INDEX",
            _live_source_authority_sha256=(
                inventory.live_source_authority_sha256
            ),
            _live_source_closure=lambda: S.verify_live_source_closure(
                project_root=tmp_path,
                scratchpad=scratchpad,
                report=report,
                inventory=inventory,
            ),
        )
    matching_journal = next(
        tmp_path.glob(
            ".matching-live-recovery.*.staging/export.journal.json"
        )
    )
    with pytest.raises(E.RunBundleExportError, match="source authority|required"):
        E.recover_export(
            journal=matching_journal,
            exact_public_lock_bytes=lock_raw,
            out=matching,
        )
    recovered = E.recover_export(
        journal=matching_journal,
        exact_public_lock_bytes=lock_raw,
        out=matching,
        project_root=tmp_path,
        scratchpad=scratchpad,
        report=report,
    )
    assert recovered.bundle_root == matching.resolve()

    drift_root = tmp_path / "drift"
    drift_root.mkdir()
    (
        drift_scratchpad,
        drift_report,
        drift_lock_raw,
        drift_inventory,
        drift_documents,
        drift_objects,
    ) = _materialized_live_fixture(drift_root)
    drift_out = drift_root / "drifted-live-recovery"
    with pytest.raises(E.RunBundleExportInterrupted):
        E.export_materialized_payload(
            documents=drift_documents,
            exact_public_lock_bytes=drift_lock_raw,
            object_bytes=drift_objects,
            out=drift_out,
            _fault_after="INDEX",
            _live_source_authority_sha256=(
                drift_inventory.live_source_authority_sha256
            ),
            _live_source_closure=lambda: S.verify_live_source_closure(
                project_root=drift_root,
                scratchpad=drift_scratchpad,
                report=drift_report,
                inventory=drift_inventory,
            ),
        )
    drift_journal = next(
        drift_root.glob(
            ".drifted-live-recovery.*.staging/export.journal.json"
        )
    )
    drift_report.write_bytes(drift_report.read_bytes() + b"\nrecovery drift\n")
    with pytest.raises(E.RunBundleExportError, match="MUTATED_DURING_EXPORT"):
        E.recover_export(
            journal=drift_journal,
            exact_public_lock_bytes=drift_lock_raw,
            out=drift_out,
            project_root=drift_root,
            scratchpad=drift_scratchpad,
            report=drift_report,
        )
    assert not drift_out.exists()
    assert not drift_journal.parent.exists()
    mutation_receipts = list(
        drift_root.glob(".drifted-live-recovery.mutation-*.json")
    )
    assert len(mutation_receipts) == 1
    assert (
        C.strict_json_load(
            mutation_receipts[0], require_canonical=True
        )["stage"]
        == "RECOVERY_PRE_SEAL"
    )


@pytest.mark.parametrize("forged_field", ["output_path", "staging_path"])
def test_recovery_rejects_self_consistent_forged_journal_paths(
    tmp_path: Path,
    forged_field: str,
):
    documents = V2._documents()
    lock_bytes = C.canonical_document_bytes(V2._public_lock())
    authorized = tmp_path / f"authorized-{forged_field}"
    with pytest.raises(E.RunBundleExportInterrupted):
        E.export_materialized_payload(
            documents=documents,
            exact_public_lock_bytes=lock_bytes,
            object_bytes={},
            out=authorized,
            _fault_after="PAYLOAD",
        )
    journal = next(
        tmp_path.glob(
            f".authorized-{forged_field}.*.staging/export.journal.json"
        )
    )
    forged = C.strict_json_load(journal, require_canonical=True)
    forged.pop("journal_sha256")
    if forged_field == "output_path":
        forged[forged_field] = str((tmp_path / "victim").resolve())
    else:
        forged[forged_field] = str(
            (tmp_path / ".victim.0123456789abcdef.staging").resolve()
        )
    forged = C.bind_embedded_sha256(forged, "journal_sha256")
    journal.write_bytes(C.canonical_document_bytes(forged))

    with pytest.raises(E.RunBundleExportError, match="authorized recovery topology"):
        E.recover_export(
            journal=journal,
            exact_public_lock_bytes=lock_bytes,
            out=authorized,
        )
    assert not authorized.exists()
    assert not (tmp_path / "victim").exists()


def test_recovery_requires_explicit_output_capability(tmp_path: Path):
    documents = V2._documents()
    lock_bytes = C.canonical_document_bytes(V2._public_lock())
    authorized = tmp_path / "authorized"
    with pytest.raises(E.RunBundleExportInterrupted):
        E.export_materialized_payload(
            documents=documents,
            exact_public_lock_bytes=lock_bytes,
            object_bytes={},
            out=authorized,
            _fault_after="PAYLOAD",
        )
    journal = next(tmp_path.glob(".authorized.*.staging/export.journal.json"))
    with pytest.raises(E.RunBundleExportError, match="authorized recovery topology"):
        E.recover_export(
            journal=journal,
            exact_public_lock_bytes=lock_bytes,
            out=tmp_path / "different-target",
        )


def test_object_bearing_recovery_replays_exact_bytes_and_rejects_object_drift(
    tmp_path: Path,
):
    documents = V2._documents()
    artifact = documents["raw_outputs.json"]["artifacts"][0]
    artifact["storage"] = "OBJECT"
    artifact["object_path"] = f"objects/sha256/{artifact['sha256']}"
    del artifact["content"]
    objects = {artifact["object_path"]: V2.AUTHORITY_RAW}
    lock_bytes = C.canonical_document_bytes(V2._public_lock())

    first = tmp_path / "object-bundle"
    with pytest.raises(E.RunBundleExportInterrupted):
        E.export_materialized_payload(
            documents=documents,
            exact_public_lock_bytes=lock_bytes,
            object_bytes=objects,
            out=first,
            _fault_after="OBJECTS",
        )
    journal = next(tmp_path.glob(".object-bundle.*.staging/export.journal.json"))
    recovered = E.recover_export(
        journal=journal,
        exact_public_lock_bytes=lock_bytes,
        out=first,
    )
    assert recovered.bundle_root == first.resolve()
    assert E.verify_export(first, lock_bytes).bundle_seal_sha256 == (
        recovered.bundle_seal_sha256
    )

    second = tmp_path / "drifted-object-bundle"
    with pytest.raises(E.RunBundleExportInterrupted):
        E.export_materialized_payload(
            documents=documents,
            exact_public_lock_bytes=lock_bytes,
            object_bytes=objects,
            out=second,
            _fault_after="OBJECTS",
        )
    drift_journal = next(
        tmp_path.glob(".drifted-object-bundle.*.staging/export.journal.json")
    )
    staged_object = (
        drift_journal.parent / Path(*artifact["object_path"].split("/"))
    )
    staged_object.write_bytes(b"mutated-after-failpoint")
    with pytest.raises(E.RunBundleExportError, match="changed|fresh export"):
        E.recover_export(
            journal=drift_journal,
            exact_public_lock_bytes=lock_bytes,
            out=second,
        )


@pytest.mark.parametrize(
    "name",
    [
        "PLAMEN_GROUND_TRUTH",
        "PRIVATE_CASE_LOCK_PATH",
        "EXPECTED_ISSUE_COUNT",
        "GRADER_LABELS",
        "ANSWER_KEY",
    ],
)
def test_exporter_rejects_private_or_post_run_environment_inputs(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
):
    monkeypatch.setenv(name, "present")
    with pytest.raises(E.RunBundleExportError, match="forbidden.*environment"):
        E.assert_export_environment_gt_blind()


def test_cli_returns_fail_closed_status_for_invalid_public_contract(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    scratchpad, report = _write_fixture_run(tmp_path)
    invalid_lock = tmp_path / "public-lock.json"
    invalid_lock.write_bytes(b'{"schema_version":"wrong"}\n')
    schedule = tmp_path / "schedule.json"
    schedule.write_bytes(b"{}\n")
    result = E.main(
        [
            "preflight",
            "--project-root",
            str(tmp_path),
            "--scratchpad",
            str(scratchpad),
            "--report",
            str(report),
            "--public-case-lock",
            str(invalid_lock),
            "--schedule-row",
            str(schedule),
        ]
    )
    assert result == 2
    assert "runbundle-export:" in capsys.readouterr().err


def test_cli_prints_explicit_local_assurance_and_rejects_authenticated_mode(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
):
    """R10: CLI assurance is explicit and a stronger request is nonzero."""

    documents, lock = _unsigned_user_run_documents()
    lock_path = tmp_path / "public-lock.json"
    lock_path.write_bytes(C.canonical_document_bytes(lock))
    out = tmp_path / "cli-assurance"
    E.export_materialized_payload(
        documents=documents,
        exact_public_lock_bytes=lock_path.read_bytes(),
        object_bytes={},
        out=out,
    )
    result = E.main(
        [
            "verify",
            str(out),
            "--public-case-lock",
            str(lock_path),
        ]
    )
    assert result == 0
    printed = json.loads(capsysbinary.readouterr().out)
    assert printed["bundle_integrity"] == "VERIFIED"
    assert printed["ready_schema"] == E.PUBLICATION_READY_SCHEMA
    assert printed["ready_assurance"] == "UNAUTHENTICATED_LOCAL"
    assert (
        printed["source_observation_claim"]
        == "SELF_ASSERTED_NOT_AUTHENTICATED"
    )
    assert printed["cleanup_state"] == "COMPLETE"
    assert printed["publication_ceiling"] == "USER_RUN"

    result = E.main(
        [
            "verify",
            str(out),
            "--public-case-lock",
            str(lock_path),
            "--required-assurance",
            E.AUTHENTICATED_EXPORT_ATTESTATION,
        ]
    )
    assert result == 2
    assert b"unsigned local integrity" in capsysbinary.readouterr().err
