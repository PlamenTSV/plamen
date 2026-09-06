"""A0 blocking fixtures for the report-index canonical successor.

These fixtures intentionally describe the required ownership boundary rather
than blessing the current live mutation order.  Several are expected to remain
red until report-index canonicalization is one pre-bound DRIVER transaction.

The properties are deliberately backend-neutral:

* exact raw MODEL bytes are attributed before any DRIVER mutation;
* validation is observational and never rewrites report artifacts;
* one canonical successor owns the interacting report-index projections;
* L1 does not commit its mechanical proposal before canonicalization;
* routing consumes only a committed canonical head;
* retry/backups cannot displace a committed prior generation.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    resolve_phase_io_contract,
)
import plamen_driver as D
import plamen_mechanical as M
from plamen_types import L1_PHASES, SC_PHASES
import plamen_validators as V


def _report_index_bytes(
    *,
    medium_summary: int = 1,
    medium_master: int = 2,
) -> bytes:
    rows = [
        (
            f"| M-{ordinal:02d} | finding {ordinal} | Medium | "
            f"src/F.sol:L{ordinal} | VERIFIED | - | H-{ordinal} |"
        )
        for ordinal in range(1, medium_master + 1)
    ]
    # The prose tail keeps the artifact above generic retry-quarantine's
    # substantial-file threshold without changing any parsed report semantics.
    tail = "canonical-generation-retention " * 24
    return (
        "\n".join(
            [
                "# Report Index",
                "",
                "## Summary Counts",
                "",
                "| Severity | Count |",
                "|----------|-------|",
                "| Critical | 0 |",
                "| High | 0 |",
                f"| Medium | {medium_summary} |",
                "| Low | 0 |",
                "| Informational | 0 |",
                f"| Total | {medium_summary} |",
                "",
                "## Master Finding Index",
                "",
                (
                    "| Report ID | Title | Severity | Location | Verification | "
                    "Trust Adj. | Internal Hypothesis |"
                ),
                (
                    "|-----------|-------|----------|----------|--------------|"
                    "------------|---------------------|"
                ),
                *rows,
                "",
                "## Excluded Findings",
                "",
                "| Source ID | Reason |",
                "|-----------|--------|",
                "",
                "## Fixture Padding",
                "",
                tail,
                "",
            ]
        )
        + "\n"
    ).encode("utf-8")


def _coverage_bytes() -> bytes:
    return (
        "# Report Coverage\n\n"
        "## Raw Candidate Ledger\n\n"
        "| Source Artifact | Candidate ID | Disposition |\n"
        "|-----------------|--------------|-------------|\n"
        "| verify_H-1.md | H-1 | PROMOTED M-01 |\n\n"
        + ("coverage-generation-retention " * 24)
        + "\n"
    ).encode("utf-8")


def _phase(*, pipeline: str = "sc"):
    phases = L1_PHASES if pipeline == "l1" else SC_PHASES
    return next(item for item in phases if item.name == "report_index")


def _config(tmp_path: Path, *, pipeline: str = "sc") -> dict:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir(parents=True, exist_ok=True)
    return {
        "pipeline": pipeline,
        # Canonical-successor semantics are mode-independent.  SC uses the
        # production Light-mode R10 clean-zero path so this module retains a
        # real committed report-prework producer without fabricating the much
        # larger verify/inventory/research predecessor graph.
        "mode": "thorough" if pipeline == "l1" else "light",
        "language": "rust" if pipeline == "l1" else "evm",
        "cli_backend": "codex",
        "scratchpad": str(scratchpad),
        "project_root": str(tmp_path),
        "_run_id": f"a0-canonical-{pipeline}",
        "_phase_io_model_attempts": {"report_index": 1},
    }


def _seed_model_inputs(config: dict) -> None:
    root = Path(config["scratchpad"])
    payloads = {
        "verification_queue.md": b"# Verification Queue\n",
        "finding_mapping.md": b"# Finding Mapping\n",
        "dedup_decisions.md": b"# Dedup Decisions\n",
    }
    if config["pipeline"] == "l1":
        payloads.update({
            "report_index_coverage_seed.md": b"# Coverage Seed\n",
            "candidate_semantic_facets.md": b"# Candidate Facets\n",
            "candidate_semantic_facets.json": b"{}\n",
        })
    for name, payload in payloads.items():
        (root / name).write_bytes(payload)
    if config["pipeline"] == "sc":
        # These canonical-successor fixtures exercise a real report consumer,
        # so seed the exact current-run R10 DRIVER producer and then the
        # committed report-prework producer.  The empty queue deliberately
        # yields zero severity floors; no production validation is bypassed.
        if not (root / "external_assumption_undemotion_compute.json").is_file():
            producer_key = (
                f"sc/{config['mode']}/{config['language']}/"
                f"{config['cli_backend']}/verify/canonical_fixture_queue"
            )
            producer = PhaseIOContract(
                pipeline="sc",
                mode=config["mode"],
                ecosystem=config["language"],
                backend=config["cli_backend"],
                phase="verify",
                work_unit_id="canonical_fixture_queue",
                outputs=(ArtifactSpec(
                    root="scratchpad",
                    path="verification_queue.md",
                    owner_key=producer_key,
                    artifact_class="REQUIRED",
                    writer="MODEL",
                    write_mode="REPLACE",
                    schema_version="unstructured.v1",
                ),),
                immutable_inputs=(),
                model_invoked=True,
            )
            producer_launch = LaunchSpec(
                work_unit_key=producer.key,
                pipeline="sc",
                mode=config["mode"],
                ecosystem=config["language"],
                backend=config["cli_backend"],
                model="fixture-model",
                timeout_s=30,
                exec_mode="pty",
            )
            queue = root / "verification_queue.md"
            queue_bytes = queue.read_bytes()
            queue.unlink()
            record_work_unit_inputs(
                root,
                Path(config["project_root"]),
                producer,
                producer_launch,
                run_id=config["_run_id"],
            )
            queue.write_bytes(queue_bytes)
            record_work_unit_artifacts(
                root,
                Path(config["project_root"]),
                producer,
                producer_launch,
                run_id=config["_run_id"],
                actor="MODEL",
            )
            compute, r10_issues = D._write_and_record_r10_phase_io(
                scratchpad=root,
                config=config,
                phase=SimpleNamespace(
                    name="sc_verify_aggregate", base_timeout_s=30
                ),
            )
            assert r10_issues == [], r10_issues
        else:
            compute = json.loads(
                (root / "external_assumption_undemotion_compute.json")
                .read_text(encoding="utf-8", errors="strict")
            )
        assert compute.get("outcome") == "CLEAN_ZERO"
        ready, prework_issues = D._run_report_index_prework_transaction(
            root, config
        )
        assert ready is True, prework_issues
        assert prework_issues == []


def _prepare_model_attempt(config: dict, raw: bytes) -> None:
    root = Path(config["scratchpad"])
    _seed_model_inputs(config)
    assert D._bind_typed_model_phase_inputs(
        _phase(pipeline=config["pipeline"]), root, config
    ) == []
    (root / "report_index.md").write_bytes(raw)
    (root / "report_coverage.md").write_bytes(_coverage_bytes())
    if config["pipeline"] == "l1":
        (root / "report_records.json").write_text(
            '{"active":[],"excluded":[]}\n',
            encoding="utf-8",
        )


def _disable_unrelated_report_index_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Leave the legacy Summary mutation live; neutralize unrelated gates."""

    monkeypatch.setattr(D, "gate_passes", lambda *args, **kwargs: (True, []))
    monkeypatch.setattr(D, "_check_index_completeness", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        D, "_project_report_index_status_with_debt", lambda *args, **kwargs: []
    )
    monkeypatch.setattr(
        D,
        "validate_report_index_canonical_bundle",
        lambda *args, **kwargs: [],
    )
    monkeypatch.setattr(D, "_validate_report_index_inputs", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        D, "_validate_report_coverage_accounting", lambda *args, **kwargs: []
    )
    monkeypatch.setattr(
        D, "_check_report_index_unresolved_authenticity", lambda *args, **kwargs: []
    )
    monkeypatch.setattr(
        D, "_check_speculative_critical_chains", lambda *args, **kwargs: []
    )
    monkeypatch.setattr(
        D, "_validate_consumer_ids_in_ledger", lambda *args, **kwargs: []
    )
    monkeypatch.setattr(
        D, "_write_canonical_finding_identity_map", lambda *args, **kwargs: 0
    )


def test_raw_model_attribution_precedes_every_live_report_index_mutator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """The MODEL ledger record must describe the exact subprocess bytes."""

    config = _config(tmp_path)
    root = Path(config["scratchpad"])
    raw = _report_index_bytes(medium_summary=1, medium_master=2)
    _prepare_model_attempt(config, raw)
    _disable_unrelated_report_index_checks(monkeypatch)

    passed, missing = D._run_phase_validators(
        _phase(),
        config,
        root,
        [_phase()],
        0,
        {},
    )
    assert passed, missing

    # Emulate the current generic post-validator MODEL commit boundary.
    assert D._record_typed_model_phase_artifacts(
        _phase(), root, config
    ) == []
    contract, _launch = D._typed_model_phase_contract_and_launch(
        _phase(), root, config
    )
    assert contract is not None
    ledger = read_artifact_ledger(root)
    unit = ledger.get("work_units", {}).get(contract.key)
    assert unit is not None, (
        "A0: the report-index MODEL work unit was not committed before live "
        "DRIVER mutators ran"
    )
    recorded = unit.get("artifacts", {}).get("scratchpad:report_index.md")
    assert recorded is not None, (
        "A0: exact raw report_index.md bytes have no committed MODEL "
        "attribution at the post-validator boundary"
    )
    assert recorded["sha256"] == hashlib.sha256(raw).hexdigest(), (
        "A0: MODEL ownership was recorded after a DRIVER validator rewrote "
        "report_index.md, retro-blessing the successor bytes as raw MODEL output"
    )
    assert recorded["size"] == len(raw)


def test_legacy_summary_validator_is_observational_only(tmp_path: Path):
    """A function named validate must not repair its input as a side effect."""

    raw = _report_index_bytes(medium_summary=1, medium_master=2)
    path = tmp_path / "report_index.md"
    path.write_bytes(raw)

    V.validate_report_index_summary_master_parity(tmp_path)

    assert path.read_bytes() == raw, (
        "A0: legacy Summary validation mutated the raw/canonical report pointer; "
        "the pure derivation must be published only by the canonical successor"
    )


def test_completeness_validator_does_not_emit_retry_files(tmp_path: Path):
    """Predicate evaluation and retry-control publication are separate owners."""

    (tmp_path / "report_index.md").write_bytes(
        _report_index_bytes(medium_summary=1, medium_master=1)
    )
    (tmp_path / "verify_H-2.md").write_text(
        "# Finding H-2\n\nVerdict: CONFIRMED\n",
        encoding="utf-8",
    )
    before = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }

    issues = V._check_index_completeness(tmp_path)

    assert issues
    after = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    assert after == before, (
        "A0: completeness validation emitted retry control as a hidden side "
        "effect; the retry publisher must be invoked explicitly after validation"
    )


def test_one_driver_successor_contract_owns_the_combined_canonical_bundle():
    """Dropout, severity, status and Summary interact and publish once."""

    try:
        contract = resolve_phase_io_contract(
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="codex",
            phase="report_index",
            work_unit_id="canonicalize",
        )
    except ValueError as exc:
        pytest.fail(
            "A0: report_index/canonicalize contract is absent; isolated "
            f"Summary ownership cannot cover the live mutator chain ({exc})"
        )

    outputs = {item.identity for item in contract.outputs}
    required = {
        "scratchpad:report_index.md",
        "scratchpad:report_coverage.md",
        "scratchpad:report_index_status_projection.json",
        "scratchpad:_severity_override_ledger.json",
        "scratchpad:report_dropout_retention.json",
        "scratchpad:report_index_canonicalization_receipt.json",
    }
    assert required <= outputs, (
        "A0: canonical successor does not own the complete interacting bundle: "
        f"missing {sorted(required - outputs)}"
    )
    assert contract.model_invoked is False
    assert all(item.writer == "DRIVER" for item in contract.outputs)


def test_l1_mechanical_preimage_is_preserved_under_canonical_successor(
    tmp_path: Path,
):
    """L1 proposal history remains exact while the successor owns live bytes."""

    config = _config(tmp_path, pipeline="l1")
    root = Path(config["scratchpad"])
    for name, payload in {
        "verification_queue.md": b"# Verification Queue\n",
        "finding_mapping.md": b"# Finding Mapping\n",
        "dedup_decisions.md": b"# Dedup Decisions\n",
    }.items():
        (root / name).write_bytes(payload)

    execute, issues = D._arm_report_index_mechanical_artifacts(root, config)
    assert execute and not issues
    raw_index = _report_index_bytes(medium_summary=1, medium_master=2)
    raw_coverage = _coverage_bytes()
    raw_records = (
        b'{"active":[{"finding_id":"H-1","report_id":"M-01"},'
        b'{"finding_id":"H-2","report_id":"M-02"}],"excluded":[]}\n'
    )
    (root / "report_index.md").write_bytes(raw_index)
    (root / "report_coverage.md").write_bytes(raw_coverage)
    (root / "report_records.json").write_bytes(raw_records)
    assert D._record_report_index_mechanical_artifacts(root, config) == []

    before = read_artifact_ledger(root)
    mechanical_contract, _launch = (
        D._report_index_mechanical_contract_and_launch(root, config)
    )
    mechanical = before["work_units"][mechanical_contract.key]
    assert mechanical["artifacts"]["scratchpad:report_index.md"]["sha256"] == (
        hashlib.sha256(raw_index).hexdigest()
    )

    assert D._run_report_index_canonicalization_transaction(
        _phase(pipeline="l1"), root, config
    ) == []

    after = read_artifact_ledger(root)
    canonical_contract, _launch = (
        D._report_index_canonical_contract_and_launch(root, config)
    )
    canonical = after["work_units"][canonical_contract.key]
    assert canonical["semantic_status"] == "ACTIVE"
    assert canonical["execution_state"] == "OUTPUT_COMMITTED"
    assert (
        after["work_units"][mechanical_contract.key]["artifacts"]
        ["scratchpad:report_index.md"]["sha256"]
        == hashlib.sha256(raw_index).hexdigest()
    )
    for identity in (
        "scratchpad:report_index.md",
        "scratchpad:report_coverage.md",
        "scratchpad:report_records.json",
    ):
        assert after["artifact_bindings"][identity]["owner_key"] == (
            canonical_contract.key
        )


def test_routing_refuses_unowned_canonical_root(tmp_path: Path):
    """Bare Markdown presence must not create records or executable shards."""

    config = _config(tmp_path)
    root = Path(config["scratchpad"])
    (root / "report_index.md").write_bytes(
        _report_index_bytes(medium_summary=2, medium_master=2)
    )
    (root / "report_coverage.md").write_bytes(_coverage_bytes())

    _planned, issues = D._run_report_index_routing_transaction(root, config)

    assert issues, "routing accepted report roots with no committed owner"
    assert not (root / "report_records.json").exists()
    manifest_dir = root / "body_manifests"
    assert not manifest_dir.exists() or not list(manifest_dir.glob("*.json"))


def test_routing_refuses_stale_committed_canonical_root(tmp_path: Path):
    """A committed owner whose digest no longer matches is not executable."""

    config = _config(tmp_path)
    root = Path(config["scratchpad"])
    _prepare_model_attempt(
        config,
        _report_index_bytes(medium_summary=1, medium_master=2),
    )
    assert D._run_report_index_summary_parity_successor(
        _phase(), root, config
    ) == []

    with (root / "report_index.md").open("ab") as handle:
        handle.write(b"\npost-commit stale mutation\n")

    _planned, issues = D._run_report_index_routing_transaction(root, config)

    assert issues, "routing accepted a canonical root with a stale owner digest"
    assert not (root / "report_records.json").exists()
    manifest_dir = root / "body_manifests"
    assert not manifest_dir.exists() or not list(manifest_dir.glob("*.json"))


def test_sc_resume_never_adopts_latest_unowned_backup(tmp_path: Path):
    """mtime-selected retry backups are control debris, never predecessors."""

    quarantine = tmp_path / "_retry_quarantine" / "report_index"
    quarantine.mkdir(parents=True)
    (quarantine / "report_index.md").write_bytes(
        _report_index_bytes(medium_summary=2, medium_master=2)
    )

    repaired = M._repair_sc_report_index_from_prior(
        tmp_path,
        prepare_body=False,
    )

    assert repaired == 0, (
        "A0: SC resume accepted an unowned latest backup as semantic predecessor"
    )
    assert not (tmp_path / "report_index.md").exists()
    assert not (tmp_path / "report_coverage.md").exists()


def test_failed_retry_preserves_committed_prior_successor_and_history(
    tmp_path: Path,
):
    """A retry writes attempt-scoped raw output; it never moves the live head."""

    config = _config(tmp_path)
    root = Path(config["scratchpad"])
    raw = _report_index_bytes(medium_summary=1, medium_master=2)
    _prepare_model_attempt(config, raw)
    assert D._run_report_index_summary_parity_successor(
        _phase(), root, config
    ) == []
    prior_index = (root / "report_index.md").read_bytes()
    prior_coverage = (root / "report_coverage.md").read_bytes()
    prior_ledger = deepcopy(read_artifact_ledger(root))

    renamed = V._quarantine_stale_on_retry(
        root,
        _phase(),
        [
            "report_index.md failed a retry predicate",
            "report_coverage.md failed a retry predicate",
        ],
    )

    assert renamed == [], (
        "A0: generic retry quarantine displaced the committed canonical head"
    )
    assert (root / "report_index.md").read_bytes() == prior_index
    assert (root / "report_coverage.md").read_bytes() == prior_coverage
    assert read_artifact_ledger(root) == prior_ledger
    assert not (root / "_retry_quarantine" / "report_index").exists()


def _canonical_output_bytes(
    root: Path,
    config: dict,
) -> dict[str, bytes]:
    contract, _launch = D._report_index_canonical_contract_and_launch(
        root, config
    )
    return {
        item.path: (root / item.path).read_bytes()
        for item in contract.outputs
    }


@pytest.mark.parametrize(
    "fault_point",
    (
        "after_canonical_arm",
        "after_optional_reset",
        "after_dropout_projection",
        "after_status_projection",
        "after_severity_projection",
        "after_summary_projection",
        "before_canonical_commit",
    ),
)
def test_canonical_successor_resumes_each_journaled_prefix_byte_exact(
    tmp_path: Path,
    fault_point: str,
):
    phase = _phase()
    raw = _report_index_bytes(medium_summary=1, medium_master=2)

    baseline_config = _config(tmp_path / "baseline")
    baseline_root = Path(baseline_config["scratchpad"])
    _prepare_model_attempt(baseline_config, raw)
    assert D._run_report_index_canonicalization_transaction(
        phase, baseline_root, baseline_config
    ) == []
    baseline = _canonical_output_bytes(
        baseline_root, baseline_config
    )

    recovery_config = _config(tmp_path / "recovery")
    recovery_root = Path(recovery_config["scratchpad"])
    _prepare_model_attempt(recovery_config, raw)

    def inject(point: str) -> None:
        if point == fault_point:
            raise RuntimeError(f"fixture fault at {point}")

    with pytest.raises(RuntimeError, match="fixture fault"):
        D._run_report_index_canonicalization_transaction(
            phase,
            recovery_root,
            recovery_config,
            fault_inject=inject,
        )

    assert D._run_report_index_canonicalization_transaction(
        phase, recovery_root, recovery_config
    ) == []
    recovered = _canonical_output_bytes(recovery_root, recovery_config)
    control_names = {
        "report_index_canonicalization_journal.json",
        "report_index_canonicalization_receipt.json",
    }
    assert {
        name: raw for name, raw in recovered.items()
        if name not in control_names
    } == {
        name: raw for name, raw in baseline.items()
        if name not in control_names
    }
    baseline_journal = json.loads(
        baseline[
            "report_index_canonicalization_journal.json"
        ].decode("utf-8")
    )
    recovered_journal = json.loads(
        recovered[
            "report_index_canonicalization_journal.json"
        ].decode("utf-8")
    )
    assert [
        row["stage"] for row in recovered_journal["states"]
    ] == [
        row["stage"] for row in baseline_journal["states"]
    ]
    baseline_receipt = json.loads(
        baseline[
            "report_index_canonicalization_receipt.json"
        ].decode("utf-8")
    )
    recovered_receipt = json.loads(
        recovered[
            "report_index_canonicalization_receipt.json"
        ].decode("utf-8")
    )
    assert recovered_receipt["transformations"] == (
        baseline_receipt["transformations"]
    )
    for name in recovered_receipt["outputs"]:
        if name != "report_index_canonicalization_journal.json":
            assert recovered_receipt["outputs"][name] == (
                baseline_receipt["outputs"][name]
            )


@pytest.mark.parametrize(
    "fault_point",
    ("after_status_projection", "before_canonical_commit"),
)
def test_canonical_successor_rejects_unjournaled_third_state(
    tmp_path: Path,
    fault_point: str,
):
    config = _config(tmp_path)
    root = Path(config["scratchpad"])
    phase = _phase()
    _prepare_model_attempt(
        config,
        _report_index_bytes(medium_summary=1, medium_master=2),
    )

    def inject(point: str) -> None:
        if point == fault_point:
            raise RuntimeError(f"fixture fault at {point}")

    with pytest.raises(RuntimeError, match="fixture fault"):
        D._run_report_index_canonicalization_transaction(
            phase, root, config, fault_inject=inject
        )
    with (root / "report_index.md").open("ab") as handle:
        handle.write(b"\nUNJOURNALED THIRD STATE\n")
    preserved = (root / "report_index.md").read_bytes()

    issues = D._run_report_index_canonicalization_transaction(
        phase, root, config
    )

    assert any(
        "ARBITRARY_THIRD_STATE" in issue for issue in issues
    ), issues
    assert (root / "report_index.md").read_bytes() == preserved
    contract, _launch = D._report_index_canonical_contract_and_launch(
        root, config
    )
    unit = read_artifact_ledger(root)["work_units"][contract.key]
    assert unit["semantic_status"] == "INPUTS_BOUND"
    assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"


def test_model_retry_supersedes_exact_canonical_generation_without_rewrite(
    tmp_path: Path,
):
    config = _config(tmp_path)
    root = Path(config["scratchpad"])
    phase = _phase()
    first_raw = _report_index_bytes(medium_summary=1, medium_master=2)
    _prepare_model_attempt(config, first_raw)
    assert D._run_report_index_canonicalization_transaction(
        phase, root, config
    ) == []

    first_model, _launch = D._typed_model_phase_contract_and_launch(
        phase, root, config
    )
    first_canonical, _launch = (
        D._report_index_canonical_contract_and_launch(root, config)
    )
    before = read_artifact_ledger(root)
    immutable_model = deepcopy(before["work_units"][first_model.key])
    immutable_canonical = deepcopy(
        before["work_units"][first_canonical.key]
    )

    config["_phase_io_model_attempts"]["report_index"] = 2
    assert D._bind_typed_model_phase_inputs(phase, root, config) == []
    second_model, _launch = D._typed_model_phase_contract_and_launch(
        phase, root, config
    )
    armed = read_artifact_ledger(root)
    for identity in (
        "scratchpad:report_index.md",
        "scratchpad:report_coverage.md",
    ):
        prestate = armed["work_units"][second_model.key][
            "output_prestates"
        ][identity]
        assert prestate["status"] == "ACTIVE_REGISTERED_PREDECESSOR"
        assert prestate["predecessor_owner_key"] == first_canonical.key

    second_raw = _report_index_bytes(medium_summary=1, medium_master=1)
    (root / "report_index.md").write_bytes(second_raw)
    (root / "report_coverage.md").write_bytes(_coverage_bytes())
    _model, issues = D._record_report_index_model_preimage(
        phase, root, config
    )
    assert issues == []
    assert D._run_report_index_canonicalization_transaction(
        phase, root, config
    ) == []

    second_canonical, _launch = (
        D._report_index_canonical_contract_and_launch(root, config)
    )
    after = read_artifact_ledger(root)
    assert after["work_units"][first_model.key] == immutable_model
    assert after["work_units"][first_canonical.key] == immutable_canonical
    assert second_model.key != first_model.key
    assert second_canonical.key != first_canonical.key
    assert after["artifact_bindings"]["scratchpad:report_index.md"][
        "owner_key"
    ] == second_canonical.key
    assert (
        root
        / "report_index_canonicalization_receipt.attempt-0002.json"
    ).is_file()


@pytest.mark.parametrize(
    "invalidate",
    ("input_drift", "missing_receipt", "tampered_journal", "skipped_generation"),
)
def test_model_retry_from_canonical_generation_fails_closed(
    tmp_path: Path,
    invalidate: str,
):
    config = _config(tmp_path)
    root = Path(config["scratchpad"])
    phase = _phase()
    _prepare_model_attempt(
        config,
        _report_index_bytes(medium_summary=1, medium_master=2),
    )
    assert D._run_report_index_canonicalization_transaction(
        phase, root, config
    ) == []

    if invalidate == "input_drift":
        (root / "verification_queue.md").write_bytes(
            b"# Verification Queue\n\nchanged denominator\n"
        )
    elif invalidate == "missing_receipt":
        (root / "report_index_canonicalization_receipt.json").unlink()
    elif invalidate == "tampered_journal":
        with (
            root / "report_index_canonicalization_journal.json"
        ).open("ab") as handle:
            handle.write(b"\nTAMPERED\n")
    elif invalidate == "skipped_generation":
        config["_phase_io_model_attempts"]["report_index"] = 3
    else:  # pragma: no cover
        raise AssertionError(invalidate)
    if invalidate != "skipped_generation":
        config["_phase_io_model_attempts"]["report_index"] = 2

    issues = D._bind_typed_model_phase_inputs(phase, root, config)

    assert issues
    retry, _launch = D._typed_model_phase_contract_and_launch(
        phase, root, config
    )
    unit = read_artifact_ledger(root)["work_units"][retry.key]
    assert unit["semantic_status"] == "INPUT_DEBT"
    assert unit["artifacts"] == {}


def test_canonical_retry_rederives_optional_dropout_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    # This is an optional-output retry isolation test.  Preserve its synthetic
    # report row instead of exercising the independently covered exact-empty
    # denominator projection, which would replace it before dropout repair.
    monkeypatch.setattr(
        D,
        "_ensure_report_index_canonical_zero_row_envelope",
        lambda *_args, **_kwargs: (False, []),
    )
    config = _config(tmp_path)
    root = Path(config["scratchpad"])
    phase = _phase()
    _seed_model_inputs(config)
    (root / "report_index_coverage_seed.md").write_text(
        "\n".join([
            "# Coverage Seed",
            "",
            "| Finding/Hyp ID | Expected Severity |",
            "|----------------|-------------------|",
            "| H-99 | Medium |",
            "",
        ]),
        encoding="utf-8",
    )
    assert D._bind_typed_model_phase_inputs(phase, root, config) == []
    (root / "report_index.md").write_bytes(
        _report_index_bytes(medium_summary=1, medium_master=1)
    )
    (root / "report_coverage.md").write_bytes(_coverage_bytes())
    assert D._run_report_index_canonicalization_transaction(
        phase, root, config
    ) == []
    first_dropout = json.loads(
        (root / "report_dropout_retention.json").read_text(
            encoding="utf-8"
        )
    )
    assert first_dropout["row_count"] == 1
    assert first_dropout["rows"][0]["candidate_id"] == "H-99"

    config["_phase_io_model_attempts"]["report_index"] = 2
    assert D._bind_typed_model_phase_inputs(phase, root, config) == []
    second_raw = _report_index_bytes(
        medium_summary=1, medium_master=1
    ).replace(b"| H-1 |", b"| H-99 |")
    (root / "report_index.md").write_bytes(second_raw)
    (root / "report_coverage.md").write_bytes(_coverage_bytes())
    _model, model_issues = D._record_report_index_model_preimage(
        phase, root, config
    )
    assert model_issues == []
    assert D._run_report_index_canonicalization_transaction(
        phase, root, config
    ) == []

    second_dropout = json.loads(
        (root / "report_dropout_retention.json").read_text(
            encoding="utf-8"
        )
    )
    assert second_dropout["row_count"] == 0
    assert second_dropout["rows"] == []
    assert "No omitted candidate" in (
        root / "report_semantic_report_dropouts.md"
    ).read_text(encoding="utf-8")


def test_severity_override_projection_is_byte_deterministic_on_replay(
    tmp_path: Path,
):
    """Canonical severity authority cannot embed a replay-time clock."""

    repairs = [{
        "report_id": "M-01",
        "internal": "H-1",
        "llm_severity": "Low",
        "upstream_severity": "Medium",
        "action": (
            "applied SEVERITY_OVERRIDE("
            "upstream=Medium, llm=Low, reason=llm-downgrade-no-judge)"
        ),
    }]

    V._write_severity_override_ledger(tmp_path, repairs)
    first = {
        "_severity_override_ledger.json": (
            tmp_path / "_severity_override_ledger.json"
        ).read_bytes(),
        "severity_overrides.md": (
            tmp_path / "severity_overrides.md"
        ).read_bytes(),
    }
    V._write_severity_override_ledger(tmp_path, repairs)
    second = {
        name: (tmp_path / name).read_bytes()
        for name in first
    }

    assert second == first, (
        "A0: deterministic canonical replay changed severity projection "
        "bytes because authority embedded wall-clock time"
    )


def test_reauthored_journal_cannot_bless_arbitrary_canonical_bytes(
    tmp_path: Path,
):
    """A digest over attacker-selected journal content is not provenance."""

    phase = _phase()
    raw = _report_index_bytes(medium_summary=1, medium_master=2)

    baseline_config = _config(tmp_path / "baseline")
    baseline_root = Path(baseline_config["scratchpad"])
    _prepare_model_attempt(baseline_config, raw)
    assert D._run_report_index_canonicalization_transaction(
        phase, baseline_root, baseline_config
    ) == []
    baseline = _canonical_output_bytes(baseline_root, baseline_config)

    recovery_config = _config(tmp_path / "recovery")
    recovery_root = Path(recovery_config["scratchpad"])
    _prepare_model_attempt(recovery_config, raw)

    def inject(point: str) -> None:
        if point == (
            "after_publish:"
            "report_index_canonicalization_journal.json"
        ):
            raise RuntimeError("fixture crash after journal publication")

    with pytest.raises(RuntimeError, match="fixture crash"):
        D._run_report_index_canonicalization_transaction(
            phase,
            recovery_root,
            recovery_config,
            fault_inject=inject,
        )

    with (recovery_root / "report_index.md").open("ab") as handle:
        handle.write(b"\nFORGED JOURNAL-BLESSED REPORT BYTES\n")

    contract, _launch = D._report_index_canonical_contract_and_launch(
        recovery_root, recovery_config
    )
    journal_path = (
        recovery_root / "report_index_canonicalization_journal.json"
    )
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    journal["states"][-1]["artifacts"] = D._report_index_bundle_state(
        recovery_root,
        D._report_index_canonical_state_names(contract),
    )
    journal["journal_digest"] = (
        D._report_index_canonical_journal_digest(journal)
    )
    journal_path.write_bytes(D._canonical_json_bytes(journal))

    issues = D._run_report_index_canonicalization_transaction(
        phase, recovery_root, recovery_config
    )
    assert any("ARBITRARY_THIRD_STATE" in issue for issue in issues), issues
    assert b"FORGED JOURNAL-BLESSED" in (
        recovery_root / "report_index.md"
    ).read_bytes()
    unit = read_artifact_ledger(recovery_root)["work_units"][contract.key]
    assert unit["semantic_status"] == "INPUTS_BOUND"
    assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"


def test_crash_between_mutation_and_journal_write_replays_from_preimage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """The live-write/journal micro-window must remain resumable."""

    config = _config(tmp_path)
    root = Path(config["scratchpad"])
    phase = _phase()
    _prepare_model_attempt(
        config,
        _report_index_bytes(medium_summary=1, medium_master=2),
    )

    original = D._write_report_index_canonical_journal_stage
    raised = False

    def crash_before_optional_journal(*args, **kwargs):
        nonlocal raised
        if kwargs.get("stage") == "OPTIONALS_RESET" and not raised:
            raised = True
            raise RuntimeError("fixture crash before journal durability")
        return original(*args, **kwargs)

    monkeypatch.setattr(
        D,
        "_write_report_index_canonical_journal_stage",
        crash_before_optional_journal,
    )
    with pytest.raises(RuntimeError, match="before journal durability"):
        D._run_report_index_canonicalization_transaction(
            phase, root, config
        )
    monkeypatch.setattr(
        D, "_write_report_index_canonical_journal_stage", original
    )

    assert D._run_report_index_canonicalization_transaction(
        phase, root, config
    ) == []
    contract, launch = D._report_index_canonical_contract_and_launch(
        root, config
    )
    unit = read_artifact_ledger(root)["work_units"][contract.key]
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"


def test_rehashed_uncommitted_receipt_cannot_bless_arbitrary_bundle(
    tmp_path: Path,
):
    """An uncommitted receipt never substitutes for independent replay."""

    config = _config(tmp_path)
    root = Path(config["scratchpad"])
    phase = _phase()
    _prepare_model_attempt(
        config,
        _report_index_bytes(medium_summary=1, medium_master=2),
    )
    contract, _launch = D._report_index_canonical_contract_and_launch(
        root, config
    )
    receipt_name = D._report_index_canonical_receipt_name(contract)

    def inject(point: str) -> None:
        if point == f"after_publish:{receipt_name}":
            raise RuntimeError("fixture crash after receipt publication")

    with pytest.raises(RuntimeError, match="after receipt publication"):
        D._run_report_index_canonicalization_transaction(
            phase, root, config, fault_inject=inject
        )

    with (root / "report_index.md").open("ab") as handle:
        handle.write(b"\nFORGED RECEIPT-BLESSED REPORT BYTES\n")
    journal_path = (
        root / "report_index_canonicalization_journal.json"
    )
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    journal["states"][-1]["artifacts"] = D._report_index_bundle_state(
        root,
        D._report_index_canonical_state_names(contract),
    )
    journal["journal_digest"] = (
        D._report_index_canonical_journal_digest(journal)
    )
    journal_path.write_bytes(D._canonical_json_bytes(journal))

    receipt_path = root / receipt_name
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["outputs"] = D._report_index_bundle_records(
        root,
        [
            item.path for item in contract.outputs
            if item.path != receipt_name
        ],
    )
    unsigned = dict(receipt)
    unsigned.pop("receipt_digest", None)
    receipt["receipt_digest"] = D._stable_payload_digest(unsigned)
    receipt_path.write_bytes(D._canonical_json_bytes(receipt))

    issues = D._run_report_index_canonicalization_transaction(
        phase, root, config
    )

    assert any("ARBITRARY_THIRD_STATE" in issue for issue in issues), issues
    unit = read_artifact_ledger(root)["work_units"][contract.key]
    assert unit["semantic_status"] == "INPUTS_BOUND"
    assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"


@pytest.mark.parametrize(
    ("position", "name"),
    [
        (position, name)
        for name in (
            "report_index.md",
            "report_coverage.md",
            "report_index_status_projection.json",
            "_severity_override_ledger.json",
            "severity_overrides.md",
            "report_dropout_retention.json",
            "report_semantic_report_dropouts.md",
            "report_index_canonicalization_journal.json",
            "report_index_canonicalization_receipt.json",
        )
        for position in ("before", "after")
    ],
)
def test_canonical_publication_resumes_each_per_file_crash(
    tmp_path: Path,
    position: str,
    name: str,
):
    """Every per-file old/target publication prefix is recoverable."""

    config = _config(tmp_path)
    root = Path(config["scratchpad"])
    phase = _phase()
    _prepare_model_attempt(
        config,
        _report_index_bytes(medium_summary=1, medium_master=2),
    )
    contract, _launch = D._report_index_canonical_contract_and_launch(
        root, config
    )
    point = f"{position}_publish:{name}"

    def inject(observed: str) -> None:
        if observed == point:
            raise RuntimeError(f"fixture publication fault: {point}")

    with pytest.raises(RuntimeError, match="publication fault"):
        D._run_report_index_canonicalization_transaction(
            phase, root, config, fault_inject=inject
        )

    staged = (
        D._report_index_canonical_recovery_dir(root, contract)
        / "staged_target"
    )
    expected = {
        item.path: (staged / item.path).read_bytes()
        for item in contract.outputs
    }
    assert D._run_report_index_canonicalization_transaction(
        phase, root, config
    ) == []
    assert {
        item.path: (root / item.path).read_bytes()
        for item in contract.outputs
    } == expected


def test_atomic_driver_publication_fsyncs_file_before_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """Per-file atomicity includes durability of the replacement source."""

    fsynced = False
    replaced = False
    original_fsync = D.os.fsync
    original_replace = D.os.replace

    def observe_fsync(fd: int) -> None:
        nonlocal fsynced
        fsynced = True
        original_fsync(fd)

    def require_fsync_before_replace(source, target) -> None:
        nonlocal replaced
        assert fsynced, "replacement occurred before the temp file was fsynced"
        replaced = True
        original_replace(source, target)

    monkeypatch.setattr(D.os, "fsync", observe_fsync)
    monkeypatch.setattr(D.os, "replace", require_fsync_before_replace)

    target = tmp_path / "durable.json"
    D._atomic_driver_bytes(target, b'{"durable":true}\n')

    assert replaced
    assert target.read_bytes() == b'{"durable":true}\n'
