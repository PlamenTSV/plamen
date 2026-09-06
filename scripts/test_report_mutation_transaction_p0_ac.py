"""P0-AC report mutation transactions preserve an exact recoverable preimage."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import plamen_driver as D
import plamen_mechanical as M

from report_mutation_transaction import (
    ReportMutationTransactionError,
    apply_report_mutation_transaction,
    capture_report_transaction_inputs,
)


BOUNDARIES = (
    "BACKUP_DURABLE",
    "PAYLOADS_DURABLE",
    "ARMED_DURABLE",
    "SIDECARS_DURABLE",
    "REPORT_REPLACED",
    "COMMIT_DURABLE",
)


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@pytest.mark.parametrize("boundary", BOUNDARIES)
def test_crash_at_every_boundary_recovers_exactly(tmp_path: Path, boundary: str):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    report = tmp_path / "AUDIT_REPORT.md"
    before = b"# Report\n\noriginal bytes\n"
    after = b"# Report\n\ntransactional bytes\n"
    report.write_bytes(before)
    source = scratchpad / "report_dedup_agent_decisions.md"
    source.write_bytes(b"KEEP H-1 H-2\n")
    sidecars = {
        "AUDIT_REPORT.deduped.md": after,
        "report_dedup_mapping.md": b"# Mapping\n\nPASS\n",
    }

    def crash(name: str) -> None:
        if name == boundary:
            raise RuntimeError(f"crash:{name}")

    with pytest.raises(RuntimeError, match="crash"):
        apply_report_mutation_transaction(
            scratchpad=scratchpad,
            project_root=tmp_path,
            run_id="run-1",
            phase="report_dedup",
            post_report=after,
            exact_inputs=("report_dedup_agent_decisions.md",),
            sidecars=sidecars,
            fault_hook=crash,
        )

    transaction_dir = scratchpad / "_report_transactions" / "report_dedup"
    backup = transaction_dir / "AUDIT_REPORT.preimage"
    assert backup.read_bytes() == before
    assert report.read_bytes() in {before, after}

    result = apply_report_mutation_transaction(
        scratchpad=scratchpad,
        project_root=tmp_path,
        run_id="run-1",
        phase="report_dedup",
        post_report=after,
        exact_inputs=("report_dedup_agent_decisions.md",),
        sidecars=sidecars,
    )
    assert result.recovered is True
    assert result.pre_report_sha256 == _sha(before)
    assert result.post_report_sha256 == _sha(after)
    assert report.read_bytes() == after
    assert backup.read_bytes() == before
    for relative, expected in sidecars.items():
        assert (scratchpad / relative).read_bytes() == expected


def test_open_transaction_never_overwrites_preimage_or_ambiguous_report(
    tmp_path: Path,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    report = tmp_path / "AUDIT_REPORT.md"
    before = b"before\n"
    after = b"after\n"
    report.write_bytes(before)

    def crash(name: str) -> None:
        if name == "ARMED_DURABLE":
            raise RuntimeError("crash")

    with pytest.raises(RuntimeError):
        apply_report_mutation_transaction(
            scratchpad=scratchpad,
            project_root=tmp_path,
            run_id="run-1",
            phase="report_floor.external_research",
            post_report=after,
            exact_inputs=(),
            sidecars={"external_research_appendix.candidate.md": after},
            fault_hook=crash,
        )
    backup = (
        scratchpad
        / "_report_transactions"
        / "report_floor.external_research"
        / "AUDIT_REPORT.preimage"
    )
    assert backup.read_bytes() == before

    report.write_bytes(b"neither-before-nor-after\n")
    with pytest.raises(ReportMutationTransactionError, match="outside"):
        apply_report_mutation_transaction(
            scratchpad=scratchpad,
            project_root=tmp_path,
            run_id="run-1",
            phase="report_floor.external_research",
            post_report=after,
            exact_inputs=(),
            sidecars={"external_research_appendix.candidate.md": after},
        )
    assert backup.read_bytes() == before
    assert report.read_bytes() == b"neither-before-nor-after\n"


def test_open_transaction_rejects_input_or_sidecar_tamper(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    report = tmp_path / "AUDIT_REPORT.md"
    report.write_bytes(b"before\n")
    source = scratchpad / "source.json"
    source.write_bytes(b"{}\n")
    sidecars = {"candidate.md": b"candidate\n", "mapping.md": b"map\n"}

    def crash(name: str) -> None:
        if name == "SIDECARS_DURABLE":
            raise RuntimeError("crash")

    with pytest.raises(RuntimeError):
        apply_report_mutation_transaction(
            scratchpad=scratchpad,
            project_root=tmp_path,
            run_id="run-1",
            phase="report_dedup",
            post_report=b"after\n",
            exact_inputs=("source.json",),
            sidecars=sidecars,
            fault_hook=crash,
        )

    source.write_bytes(b'{"tampered":true}\n')
    with pytest.raises(ReportMutationTransactionError, match="input"):
        apply_report_mutation_transaction(
            scratchpad=scratchpad,
            project_root=tmp_path,
            run_id="run-1",
            phase="report_dedup",
            post_report=b"after\n",
            exact_inputs=("source.json",),
            sidecars=sidecars,
        )

    source.write_bytes(b"{}\n")
    (scratchpad / "mapping.md").write_bytes(b"tampered\n")
    with pytest.raises(ReportMutationTransactionError, match="sidecar"):
        apply_report_mutation_transaction(
            scratchpad=scratchpad,
            project_root=tmp_path,
            run_id="run-1",
            phase="report_dedup",
            post_report=b"after\n",
            exact_inputs=("source.json",),
            sidecars=sidecars,
        )


def test_candidate_cannot_bind_inputs_changed_after_computation(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (tmp_path / "AUDIT_REPORT.md").write_bytes(b"before\n")
    source = scratchpad / "source.json"
    source.write_bytes(b'{"version":1}\n')
    snapshot = capture_report_transaction_inputs(
        scratchpad, ("source.json", "optional-missing.json")
    )
    source.write_bytes(b'{"version":2}\n')
    with pytest.raises(ReportMutationTransactionError, match="computation"):
        apply_report_mutation_transaction(
            scratchpad=scratchpad,
            project_root=tmp_path,
            run_id="run-toctou",
            phase="report_dedup",
            post_report=b"after\n",
            exact_inputs=("source.json", "optional-missing.json"),
            expected_inputs=snapshot,
            sidecars={"candidate.md": b"after\n"},
        )
    assert (tmp_path / "AUDIT_REPORT.md").read_bytes() == b"before\n"
    assert not (scratchpad / "_report_transactions").exists()


def test_input_change_after_arm_blocks_canonical_replace(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    report = tmp_path / "AUDIT_REPORT.md"
    report.write_bytes(b"before\n")
    source = scratchpad / "source.json"
    source.write_bytes(b'{"version":1}\n')

    def mutate_after_sidecars(name: str) -> None:
        if name == "SIDECARS_DURABLE":
            source.write_bytes(b'{"version":2}\n')

    with pytest.raises(ReportMutationTransactionError, match="input changed"):
        apply_report_mutation_transaction(
            scratchpad=scratchpad,
            project_root=tmp_path,
            run_id="run-toctou",
            phase="report_dedup",
            post_report=b"after\n",
            exact_inputs=("source.json",),
            sidecars={"candidate.md": b"after\n"},
            fault_hook=mutate_after_sidecars,
        )
    assert report.read_bytes() == b"before\n"
    assert (
        scratchpad
        / "_report_transactions"
        / "report_dedup"
        / "AUDIT_REPORT.preimage"
    ).read_bytes() == b"before\n"


def test_report_tamper_after_replace_cannot_manufacture_commit(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    report = tmp_path / "AUDIT_REPORT.md"
    report.write_bytes(b"before\n")

    def tamper_after_replace(name: str) -> None:
        if name == "REPORT_REPLACED":
            report.write_bytes(b"third-state\n")

    with pytest.raises(ReportMutationTransactionError, match="before transaction"):
        apply_report_mutation_transaction(
            scratchpad=scratchpad,
            project_root=tmp_path,
            run_id="run-tamper",
            phase="report_dedup",
            post_report=b"after\n",
            exact_inputs=(),
            sidecars={"candidate.md": b"after\n"},
            fault_hook=tamper_after_replace,
        )
    transaction = scratchpad / "_report_transactions" / "report_dedup"
    assert (transaction / "AUDIT_REPORT.preimage").read_bytes() == b"before\n"
    assert not (transaction / "receipt.json").exists()


def test_committed_transaction_is_idempotent_and_run_bound(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (tmp_path / "AUDIT_REPORT.md").write_bytes(b"before\n")
    kwargs = dict(
        scratchpad=scratchpad,
        project_root=tmp_path,
        run_id="run-1",
        phase="report_dedup",
        post_report=b"after\n",
        exact_inputs=(),
        sidecars={"candidate.md": b"after\n"},
    )
    first = apply_report_mutation_transaction(**kwargs)
    second = apply_report_mutation_transaction(**kwargs)
    assert first.recovered is False
    assert second.recovered is True
    assert second.receipt_sha256 == first.receipt_sha256

    with pytest.raises(ReportMutationTransactionError, match="run"):
        apply_report_mutation_transaction(**{**kwargs, "run_id": "run-2"})


def test_report_dedup_recovers_after_canonical_replace_without_recompute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    report = tmp_path / "AUDIT_REPORT.md"
    original = b"# Security Audit Report\n\n## Summary\n\nNo findings.\n"
    report.write_bytes(original)
    real_apply = M._apply_report_mutation_transaction

    def crash_apply(**kwargs):
        def crash(name: str) -> None:
            if name == "REPORT_REPLACED":
                raise RuntimeError("crash-after-report-replace")

        return real_apply(**kwargs, fault_hook=crash)

    monkeypatch.setattr(M, "_apply_report_mutation_transaction", crash_apply)
    with pytest.raises(RuntimeError, match="crash-after-report-replace"):
        M._dedup_report_python(
            scratchpad, str(tmp_path), run_id="run-dedup"
        )
    backup = (
        scratchpad
        / "_report_transactions"
        / "report_dedup"
        / "AUDIT_REPORT.preimage"
    )
    assert backup.read_bytes() == original

    monkeypatch.setattr(M, "_apply_report_mutation_transaction", real_apply)
    assert M._dedup_report_python(
        scratchpad, str(tmp_path), run_id="run-dedup"
    )
    assert report.read_bytes() == original
    assert (
        scratchpad
        / "_report_transactions"
        / "report_dedup"
        / "receipt.json"
    ).is_file()


def test_external_research_appendix_is_typed_and_transactional(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    report = tmp_path / "AUDIT_REPORT.md"
    before = b"# Security Audit Report\n\n## Summary\n\nContent.\n"
    report.write_bytes(before)
    (scratchpad / "external_research_gaps.md").write_text(
        "# External-Dependency Research Gaps\n\n"
        "| Finding ID | Dependency | Integration Surface | Reason |\n"
        "|---|---|---|---|\n"
        "| H-09 | external system | `adapter.rs:L10` | uncited premise |\n",
        encoding="utf-8",
    )
    assert D._append_external_research_appendix_note(
        scratchpad, tmp_path, run_id="run-floor"
    ) == 1
    assert report.read_bytes() != before
    authority = scratchpad / "external_research_appendix_authority.json"
    assert authority.is_file()
    transaction = (
        scratchpad
        / "_report_transactions"
        / "report_floor.external_research_appendix"
    )
    assert (transaction / "AUDIT_REPORT.preimage").read_bytes() == before
    assert (transaction / "receipt.json").is_file()
    # A normal idempotent replay performs no second mutation.
    assert D._append_external_research_appendix_note(
        scratchpad, tmp_path, run_id="run-floor"
    ) == 0


def test_untyped_stale_appendix_heading_cannot_suppress_current_gap_rows(
    tmp_path: Path,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    report = tmp_path / "AUDIT_REPORT.md"
    report.write_text(
        "# Report\n\n"
        "## Appendix D: External-Dependency Research Gaps (Advisory)\n\n"
        "Affected finding(s): OLD-01\n\n"
        "## Appendix E: Other retained content\n\nKeep me.\n",
        encoding="utf-8",
    )
    (scratchpad / "external_research_gaps.md").write_text(
        "| Finding ID | Dependency | Integration Surface | Reason |\n"
        "|---|---|---|---|\n"
        "| H-09 | external | `adapter.rs:L10` | uncited |\n",
        encoding="utf-8",
    )

    assert D._append_external_research_appendix_note(
        scratchpad, tmp_path, run_id="run-stale-heading"
    ) == 1
    delivered = report.read_text(encoding="utf-8")
    assert "Affected finding(s): H-09" in delivered
    assert "OLD-01" not in delivered
    assert "## Appendix E: Other retained content" in delivered
    assert "Keep me." in delivered
    assert (scratchpad / "external_research_appendix_authority.json").is_file()
    assert (
        scratchpad
        / "_report_transactions"
        / "report_floor.external_research_appendix"
        / "receipt.json"
    ).is_file()


def test_ambiguous_duplicate_external_appendices_degrade_without_mutation(
    tmp_path: Path,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    report = tmp_path / "AUDIT_REPORT.md"
    before = (
        "# Report\n\n"
        "## Appendix D: External-Dependency Research Gaps (Advisory)\n\nOne.\n\n"
        "## Appendix D: External-Dependency Research Gaps (Advisory)\n\nTwo.\n"
    )
    report.write_text(before, encoding="utf-8")
    (scratchpad / "external_research_gaps.md").write_text(
        "| Finding ID | Dependency | Integration Surface | Reason |\n"
        "|---|---|---|---|\n"
        "| H-09 | external | `adapter.rs:L10` | uncited |\n",
        encoding="utf-8",
    )

    assert D._append_external_research_appendix_note(
        scratchpad, tmp_path, run_id="run-duplicate-heading"
    ) == -1
    assert report.read_text(encoding="utf-8") == before
    assert not (scratchpad / "external_research_appendix_authority.json").exists()


@pytest.mark.parametrize("tampered", ("report", "input", "authority"))
def test_committed_external_appendix_drift_is_visible_debt_not_false_noop(
    tmp_path: Path, tampered: str
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    report = tmp_path / "AUDIT_REPORT.md"
    report.write_text("# Report\n\nContent.\n", encoding="utf-8")
    ledger = scratchpad / "external_research_gaps.md"
    ledger.write_text(
        "| Finding ID | Dependency | Integration Surface | Reason |\n"
        "|---|---|---|---|\n"
        "| H-09 | external | `adapter.rs:L10` | uncited |\n",
        encoding="utf-8",
    )
    assert D._append_external_research_appendix_note(
        scratchpad, tmp_path, run_id="run-floor-drift"
    ) == 1
    authority = scratchpad / "external_research_appendix_authority.json"
    targets = {"report": report, "input": ledger, "authority": authority}
    target = targets[tampered]
    target.write_bytes(target.read_bytes() + b"tamper\n")
    retained = report.read_bytes()

    assert D._append_external_research_appendix_note(
        scratchpad, tmp_path, run_id="run-floor-drift"
    ) == -1
    # Refusal is haltless but never rewrites the third-party mutation.
    assert report.read_bytes() == retained


def test_report_body_shortcuts_use_typed_phase_commit_not_direct_completion():
    source = Path(D.__file__).read_text(encoding="utf-8", errors="strict")
    main = source.index("def main()")
    start = source.index(
        'if phase.name.startswith("report_body_writer_"):', main
    )
    end = source.index('if phase.name == "enumgap_exploration":', start)
    branch = source[start:end]
    assert "_commit_phase_from_disk_debt(" in branch
    assert "RUNTIME_DEBT_REPORT_BODY_RETAINED" in branch
    assert "checkpoint.mark_completed(phase.name)" not in branch


def test_typed_projection_is_a_recoverable_successor_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    report = tmp_path / "AUDIT_REPORT.md"
    before = "# Report\n\n### [H-01] Finding\n\nBody.\n"
    report.write_text(before, encoding="utf-8")
    monkeypatch.setattr(
        D, "validate_report_evidence_runtime", lambda _root: {"bundle": {}}
    )
    monkeypatch.setattr(
        D,
        "project_report_evidence_markdown",
        lambda markdown, _bundle: markdown.rstrip() + "\n\n**Evidence**: typed\n",
    )
    monkeypatch.setattr(D, "_report_evidence_repair_inputs", lambda _root: ())

    changed, issues = D._project_report_evidence_transaction(
        scratchpad,
        tmp_path,
        run_id="run-projection",
        phase="report_dedup.evidence_projection",
    )
    assert changed is True
    assert issues == []
    after = report.read_bytes()
    assert b"**Evidence**: typed" in after
    transaction = (
        scratchpad
        / "_report_transactions"
        / "report_dedup.evidence_projection"
    )
    assert (transaction / "AUDIT_REPORT.preimage").read_text(
        encoding="utf-8"
    ) == before
    assert (transaction / "receipt.json").is_file()

    changed_again, issues_again = D._project_report_evidence_transaction(
        scratchpad,
        tmp_path,
        run_id="run-projection",
        phase="report_dedup.evidence_projection",
    )
    assert changed_again is True
    assert issues_again == []
    assert report.read_bytes() == after
