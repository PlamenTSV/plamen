"""Transactional accepted-depth inventory successor regressions."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

import artifact_ledger as AL
import plamen_driver as D
import plamen_mechanical as M
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
from plamen_types import SC_PHASES
from test_inventory_canonical_aggregate_phaseio_p0_l import (
    _fixture,
    _finding,
)


SUCCESSOR_KEY = (
    "sc/thorough/evm/claude/inventory/additive_depth_finalize"
)


def _seed_canonical(tmp_path: Path) -> tuple[Path, Path, dict]:
    project, scratch, config = _fixture(tmp_path)
    source = project / "src" / "Fixture.sol"
    source.parent.mkdir(parents=True)
    source.write_text("contract Fixture {}\n", encoding="utf-8")
    inventory_raw = (
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Seed\n"
        "**Source IDs**: [BASE-0]\n"
        "**Severity**: Low\n"
        "**Location**: src/Fixture.sol:L1\n"
        "**Description**: retained seed.\n"
    )
    records_raw = D.derive_preverify_finding_records_bytes(
        inventory_raw.encode("utf-8")
    )
    ledger_raw = json.dumps({
        "schema_version": "plamen.id_ledger.v1",
        "allocations": [{
            "id": "INV-001",
            "prefix": "INV-",
            "owner_phase": "inventory",
            "owner_attempt": 1,
            "owning_artifact": "findings_inventory.md",
            "title_hash": D._title_hash("Seed"),
            "title_preview": "Seed",
            "allocated_at": "1970-01-01T00:00:00+00:00",
        }],
    }, sort_keys=True, indent=2) + "\n"
    producer_key = canonical_work_unit_key(
        "sc", "thorough", "evm", "claude", "inventory", "additive_reemit"
    )
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="inventory",
        work_unit_id="additive_reemit",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=name,
                owner_key=producer_key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                consumers=("inventory/additive_depth_finalize",),
            )
            for name in (
                "findings_inventory.md", "finding_records.json", "_id_ledger.json"
            )
        ),
    )
    launch = LaunchSpec(
        work_unit_key=producer_key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        model="driver",
        timeout_s=120,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    AL.record_work_unit_inputs(
        scratch, project, contract, launch, run_id=config["_run_id"]
    )
    (scratch / "findings_inventory.md").write_text(
        inventory_raw, encoding="utf-8"
    )
    (scratch / "finding_records.json").write_bytes(records_raw)
    (scratch / "_id_ledger.json").write_text(ledger_raw, encoding="utf-8")
    AL.record_work_unit_artifacts(
        scratch,
        project,
        contract,
        launch,
        run_id=config["_run_id"],
        actor="DRIVER",
    )
    return project, scratch, config


def _run(scratch: Path, config: dict, **overrides: object) -> dict:
    return D._run_accepted_depth_postprocessors(
        "depth",
        scratch,
        accepted=True,
        recovery_preflight=bool(overrides.pop("recovery_preflight", False)),
        config={**config, **overrides},
    )


def test_depth_additive_ignores_preserved_fenced_source_finding_ids(
    tmp_path: Path,
) -> None:
    """Preserved source headings are prose evidence, not canonical IDs."""

    stage = tmp_path / "stage"
    stage.mkdir()
    inventory = (
        "# Finding Inventory\n\n## Findings\n\n"
        + _finding("INV-001", "canonical candidate", ("B5-1",))
        + "**Preserved Source Block**:\n\n"
        + "````markdown\n"
        + "## Finding [B5-1]: preserved original candidate\n"
        + "**Severity**: Medium\n"
        + "**Location**: src/Fixture.sol:L11\n"
        + "````\n"
    )
    inventory_raw = inventory.encode("utf-8")
    (stage / "findings_inventory.md").write_bytes(inventory_raw)
    (stage / "_id_ledger.json").write_text(
        json.dumps({
            "schema_version": "plamen.id_ledger.v1",
            "allocations": [],
        }),
        encoding="utf-8",
    )

    assert D._depth_additive_identity_set(
        "findings_inventory.md", inventory_raw
    ) == ("INV-001",)
    outputs = D._couple_depth_additive_stage_outputs(stage, set())
    records = json.loads(outputs["finding_records.json"])["records"]
    ledger = json.loads(outputs["_id_ledger.json"])["allocations"]
    assert [row["inventory_id"] for row in records] == ["INV-001"]
    assert [row["id"] for row in ledger] == ["INV-001"]


@pytest.mark.parametrize("ordinal", (1, 2, 3, 4, 5))
def test_depth_additive_every_postimage_boundary_resumes_exactly_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ordinal: int,
) -> None:
    """Every persisted boundary resumes the sealed plan without re-evaluation."""

    _project, scratch, config = _seed_canonical(tmp_path)
    real_evaluate = D._evaluate_depth_additive_proposal
    evaluations = 0

    def counted_evaluate(**kwargs: object):
        nonlocal evaluations
        evaluations += 1
        return real_evaluate(**kwargs)

    monkeypatch.setattr(D, "_evaluate_depth_additive_proposal", counted_evaluate)
    interrupted = _run(
        scratch, config, _depth_additive_failpoint=f"after_output_{ordinal}"
    )
    assert interrupted["status"] == "DEGRADED_HUMAN_REVIEW"
    assert evaluations == 1

    finalization = json.loads(
        (scratch / D._DEPTH_ADDITIVE_FINALIZATION).read_text(encoding="utf-8")
    )
    expected = {
        name: base64.b64decode(
            finalization["canonical_postimages"][name]["content_b64"],
            validate=True,
        )
        for name in D._DEPTH_ADDITIVE_CANONICAL
    }
    resumed = _run(scratch, config, recovery_preflight=True)
    assert resumed["status"] in {"FINALIZED", "DEGRADED_HUMAN_REVIEW"}
    assert "transaction" not in resumed.get("failed_processors", []), (
        resumed.get("transaction_issues")
    )
    assert evaluations == 1
    assert {
        name: (scratch / name).read_bytes()
        for name in D._DEPTH_ADDITIVE_CANONICAL
    } == expected

    unit = AL.read_artifact_ledger(scratch)["work_units"][SUCCESSOR_KEY]
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert unit["commit_authority"]["actor"] == "DRIVER"


def test_depth_additive_partial_resume_rejects_then_recovers_predecessor_drift(
    tmp_path: Path,
) -> None:
    """The armed predecessor CAS rejects drift and remains exactly retryable."""

    _project, scratch, config = _seed_canonical(tmp_path)
    inventory = scratch / "findings_inventory.md"
    predecessor = inventory.read_bytes()
    interrupted = _run(
        scratch, config, _depth_additive_failpoint="after_output_1"
    )
    assert interrupted["status"] == "DEGRADED_HUMAN_REVIEW"

    inventory.write_bytes(predecessor + b"\nCORRUPT-PREDECESSOR\n")
    rejected = _run(scratch, config, recovery_preflight=True)
    assert rejected["status"] == "DEGRADED_HUMAN_REVIEW"
    assert any(
        "historical producer does not replay" in issue
        or "predecessor" in issue.lower()
        for issue in rejected["transaction_issues"]
    )

    inventory.write_bytes(predecessor)
    resumed = _run(scratch, config, recovery_preflight=True)
    assert "transaction" not in resumed.get("failed_processors", [])
    unit = AL.read_artifact_ledger(scratch)["work_units"][SUCCESSOR_KEY]
    assert (unit["semantic_status"], unit["execution_state"]) == (
        "ACTIVE", "OUTPUT_COMMITTED",
    )


def test_depth_additive_capture_is_bounded_allowlist_and_denominator_bound(
    tmp_path: Path,
) -> None:
    """Neither unrelated top-level bytes nor a recursive tree enter staging."""

    _project, scratch, config = _seed_canonical(tmp_path)
    (scratch / "unrelated-private-tree").mkdir()
    (scratch / "unrelated-private-tree" / "payload.bin").write_bytes(b"x" * 4096)
    (scratch / "unrelated.bin").write_bytes(b"not a registered input")
    result = _run(scratch, config)
    assert "transaction" not in result.get("failed_processors", [])

    manifest = json.loads(
        (scratch / D._DEPTH_ADDITIVE_SOURCE_MANIFEST).read_text(encoding="utf-8")
    )
    names = {row["path"] for row in manifest["files"]}
    assert set(D._DEPTH_ADDITIVE_CANONICAL).issubset(names)
    assert "unrelated.bin" not in names
    assert not any("unrelated-private-tree" in name for name in names)
    for row in manifest["files"]:
        raw = base64.b64decode(row["content_b64"], validate=True)
        assert len(raw) == row["size"]
        assert hashlib.sha256(raw).hexdigest() == row["sha256"]
    finalization = json.loads(
        (scratch / D._DEPTH_ADDITIVE_FINALIZATION).read_text(encoding="utf-8")
    )
    for row in finalization["stage_derived_artifacts"]:
        raw = base64.b64decode(row["content_b64"], validate=True)
        assert len(raw) == row["size"]
        assert hashlib.sha256(raw).hexdigest() == row["sha256"]


def test_depth_additive_routes_enumeration_denominator_with_inventory_successor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stage-only obligations must reach the later exploration worklist."""

    _project, scratch, config = _seed_canonical(tmp_path)
    real_evaluate = D._evaluate_depth_additive_proposal
    evaluations = 0

    obligation_bytes = (
        json.dumps({
            "schema": "plamen.enumeration_obligation_set.v2",
            "source": "fixture-graph",
            "input_digests": {},
            "anchors": [],
            "anchor_tail": [],
            "family_cards": [],
            "unresolved_anchor_obligations": [],
            "obligations": [{
                "finding_id": "INV-001",
                "function": "withdraw",
                "symbol": "balances",
                "required_corefs": ["claim"],
            }],
        }, sort_keys=True)
        + "\n"
    ).encode("utf-8")
    markdown_bytes = (
        "# Enumeration Obligations\n\n"
        "| Finding | Function | Symbol | Anchor | Must also address | Tail |\n"
        "|---|---|---|---|---|---|\n"
        "| INV-001 | `withdraw` | `balances` | exact | `claim` | 0 |\n"
    ).encode("utf-8")

    def with_enumeration_projection(**kwargs: object):
        nonlocal evaluations
        evaluations += 1
        canonical, processors, derived, debts = real_evaluate(**kwargs)
        derived = [
            row for row in derived
            if row.get("path") not in D._DEPTH_ADDITIVE_ROUTED_DERIVED
        ]
        for name, raw in (
            ("_enumeration_obligations.json", obligation_bytes),
            ("enumeration_obligations.md", markdown_bytes),
        ):
            derived.append({
                "path": name,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
                "content_b64": base64.b64encode(raw).decode("ascii"),
            })
        return canonical, processors, derived, debts

    monkeypatch.setattr(
        D, "_evaluate_depth_additive_proposal", with_enumeration_projection
    )
    interrupted = _run(
        scratch,
        config,
        _depth_additive_failpoint="after__enumeration_obligations.json",
    )
    assert interrupted["status"] == "DEGRADED_HUMAN_REVIEW"
    assert evaluations == 1

    resumed = _run(scratch, config, recovery_preflight=True)
    assert "transaction" not in resumed.get("failed_processors", [])
    assert evaluations == 1
    assert (scratch / "_enumeration_obligations.json").read_bytes() == obligation_bytes
    assert (scratch / "enumeration_obligations.md").read_bytes() == markdown_bytes
    enumgap_phase = next(
        row for row in SC_PHASES if row.name == "enumgap_exploration"
    )
    worklist, planning_issues = D._prepare_enumgap_disposition_worklist(
        enumgap_phase, config, scratch
    )
    assert planning_issues == []
    assert worklist["count"] == 1

    unit = AL.read_artifact_ledger(scratch)["work_units"][SUCCESSOR_KEY]
    for name in D._DEPTH_ADDITIVE_ROUTED_DERIVED:
        binding = unit["artifacts"][f"scratchpad:{name}"]
        assert binding["status"] == "ACTIVE"
        assert "enumgap_disposition/planning" in binding["consumers"]


def test_depth_additive_source_cas_rejects_mutation_before_successor_arm(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A post-capture canonical mutation cannot be retrospectively blessed."""

    _project, scratch, config = _seed_canonical(tmp_path)
    real_evaluate = D._evaluate_depth_additive_proposal

    def mutate_after_evaluation(**kwargs: object):
        proposal = real_evaluate(**kwargs)
        with (scratch / "findings_inventory.md").open("ab") as handle:
            handle.write(b"\nUNJOURNALED-DODO-MUTATION\n")
        return proposal

    monkeypatch.setattr(
        D, "_evaluate_depth_additive_proposal", mutate_after_evaluation
    )
    result = _run(scratch, config)
    assert result["status"] == "DEGRADED_HUMAN_REVIEW"
    assert "transaction" in result["failed_processors"]
    unit = AL.read_artifact_ledger(scratch)["work_units"].get(SUCCESSOR_KEY)
    assert unit is None or unit.get("semantic_status") != "ACTIVE"


def test_depth_additive_reuses_committed_capture_before_successor_arm(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rejected proposal retries the committed CREATE capture exactly once."""

    _project, scratch, config = _seed_canonical(tmp_path)
    real_evaluate = D._evaluate_depth_additive_proposal
    evaluations = 0

    def fail_once(**kwargs: object):
        nonlocal evaluations
        evaluations += 1
        if evaluations == 1:
            raise RuntimeError("injected proposal rejection")
        return real_evaluate(**kwargs)

    monkeypatch.setattr(D, "_evaluate_depth_additive_proposal", fail_once)
    rejected = _run(scratch, config)
    assert rejected["status"] == "DEGRADED_HUMAN_REVIEW"
    assert "transaction" in rejected["failed_processors"]
    manifest_before = (
        scratch / D._DEPTH_ADDITIVE_SOURCE_MANIFEST
    ).read_bytes()

    resumed = _run(scratch, config)
    assert "transaction" not in resumed.get("failed_processors", []), (
        resumed.get("transaction_issues")
    )
    assert evaluations == 2
    assert (
        scratch / D._DEPTH_ADDITIVE_SOURCE_MANIFEST
    ).read_bytes() == manifest_before


def test_dodo_shaped_niche_addition_keeps_driver_authority_active(
    tmp_path: Path,
) -> None:
    """The Run12-shaped promotion lands before lifecycle and identity mapping."""

    _project, scratch, config = _seed_canonical(tmp_path)
    (scratch / "niche_runtime_findings.md").write_text(
        "## Finding [SC-61]: DODO invariant drift\n"
        "**Severity**: Medium\n"
        "**Location**: src/DODO.sol:L1\n"
        "**Description**: Candidate remains visible.\n"
        "**Impact**: Silent loss reduces recall.\n",
        encoding="utf-8",
    )

    result = _run(scratch, config)
    assert result["added_inventory_ids"] == ["INV-002"]
    assert "SC-61" in (scratch / "findings_inventory.md").read_text(
        encoding="utf-8"
    )
    unit = AL.read_artifact_ledger(scratch)["work_units"][SUCCESSOR_KEY]
    assert (unit["semantic_status"], unit["execution_state"]) == (
        "ACTIVE", "OUTPUT_COMMITTED",
    )

    assert M._write_canonical_finding_identity_map(
        scratch, phase_name="depth", pipeline="sc", mode="thorough"
    ) >= 2
    unit_after = AL.read_artifact_ledger(scratch)["work_units"][SUCCESSOR_KEY]
    assert (unit_after["semantic_status"], unit_after["execution_state"]) == (
        "ACTIVE", "OUTPUT_COMMITTED",
    )


def test_unresolved_niche_candidate_is_retained_in_coupled_debt(
    tmp_path: Path,
) -> None:
    """An unregistrable proposal remains byte-preserved review debt."""

    _project, scratch, config = _seed_canonical(tmp_path)
    (scratch / "niche_unknown_findings.md").write_text(
        "## Finding [ZZQ-7]: unresolved producer identity\n"
        "**Severity**: Medium\n"
        "**Location**: src/DODO.sol:L7\n"
        "**Description**: This candidate must remain visible.\n"
        "**Impact**: Silent loss reduces recall.\n",
        encoding="utf-8",
    )

    result = _run(scratch, config)
    assert result["status"] == "DEGRADED_HUMAN_REVIEW"
    assert result["failed_processors"] == ["niche_promotion"]
    debt = json.loads(
        (scratch / D._DEPTH_ADDITIVE_DEBT).read_text(encoding="utf-8")
    )
    niche_rows = [
        row for row in debt["rows"]
        if row.get("path") == "niche_identity_debt.json"
    ]
    assert len(niche_rows) == 1
    retained = json.loads(
        base64.b64decode(niche_rows[0]["content_b64"], validate=True)
    )
    assert retained["candidate_count"] == 1
    assert retained["candidates"][0]["normalized_local_id"] == "ZZQ-7"
    unit = AL.read_artifact_ledger(scratch)["work_units"][SUCCESSOR_KEY]
    assert (unit["semantic_status"], unit["execution_state"]) == (
        "ACTIVE", "OUTPUT_COMMITTED",
    )
    assert not (scratch / D._DEPTH_FINALIZATION_REVIEW).exists()
    assert D._run_depth_finalization_report_authority_transaction(
        scratch, config, result, phase_name="depth"
    ) == []
    report_authority = json.loads(
        (scratch / "depth_finalization_report_authority.json").read_text(
            encoding="utf-8"
        )
    )
    assert report_authority["review"]["presence"] == "PRESENT"
    assert "niche_promotion" in report_authority["review"]["content"]
