"""RED contracts for transactional L1 supplemental semantic dedup.

The legacy supplemental path is a stateful full-pair sweep that appends to the
model's ``dedup_decisions.md`` and mutates the already-published canonical
inventory.  That shape is incompatible with the direct five-output PhaseIO
RMW successor.

These fixtures specify a proposal/application split instead:

* a separate DRIVER PhaseIO unit deterministically enumerates conservative
  supplemental proposals without mutating canonical or model-owned bytes;
* the authenticated proposal artifact is an exact immutable input to the same
  five-output ``prequeue_apply`` transaction as ``dedup_decisions.md``;
* primary and supplemental transformations are both derived off-canonical and
  form one exact receipt/alias partition before any public output changes; and
* supplemental derivation/application debt degrades to an authenticated empty
  supplemental stage, so primary model decisions still land while every
  unmerged candidate remains active.

No production file is edited by this fixture.
"""
from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path
from typing import Any, Callable, Mapping

import pytest

import plamen_driver as DRIVER
from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
    resolve_phase_io_contract,
)
from preverify_frozen_projection import derive_preverify_finding_records_bytes
import semantic_dedup_authority as AUTHORITY


RUN_ID = "89413063-7f42-4b26-b37f-50aa6b072d45"
PROPOSAL_NAME = "semantic_dedup_supplemental_proposals.json"
PROPOSAL_SCHEMA = "plamen.semantic_dedup_supplemental_proposals.v1"
PROPOSAL_WORK_UNIT = "supplemental_proposals"
APPLY_WORK_UNIT = "prequeue_apply"
SOURCE_NAMES = (
    "findings_inventory.md",
    "dedup_decisions.md",
    "dedup_candidate_pairs.md",
    "dedup_candidate_pairs_full.md",
)
FIVE_OUTPUTS = (
    "findings_inventory.md",
    "finding_records.json",
    "findings_inventory_deduped.md",
    AUTHORITY.PRIMARY_RECEIPT_NAME,
    "dedup_absorbed_map.md",
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _required(name: str) -> Callable[..., Any]:
    value = getattr(DRIVER, name, None)
    assert callable(value), f"required L1 supplemental transaction API is absent: {name}"
    return value


def _finding(
    finding_id: str,
    *,
    title: str,
    location: str,
    source_ids: str,
    root_cause: str,
    severity: str = "High",
) -> str:
    return (
        f"### Finding [{finding_id}]: {title}\n"
        f"**Severity**: {severity}\n"
        f"**Location**: {location}\n"
        f"**Source IDs**: {source_ids}\n"
        f"**Root Cause**: {root_cause}\n"
        "**Description**: The transition admits an invalid security state.\n"
        "**Preconditions**: An untrusted input reaches the transition.\n"
        "**Impact**: The invalid state reaches a security-sensitive consumer.\n"
        "**Recommendation**: Enforce the same invariant at each entry path.\n"
        "**External Premises**: None.\n"
        "**Evidence Scope**: The named transition and direct consumer.\n"
        "[CODE-TRACE]\n\n"
    )


def _inventory() -> bytes:
    return (
        "# Findings Inventory\n\n"
        + _finding(
            "INV-001",
            title="Complete alpha transition omission",
            location="consensus/state.rs:10-50",
            source_ids="A-1, A-2",
            root_cause="Both alpha paths omit the same complete guard.",
        )
        + _finding(
            "INV-002",
            title="Alpha transition boundary variant",
            location="consensus/state.rs:20-25",
            source_ids="A-2",
            root_cause="The alpha boundary path omits the same guard.",
        )
        + _finding(
            "INV-003",
            title="Complete beta authentication omission",
            location="network/auth.rs:70-100",
            source_ids="B-1, B-2",
            root_cause="Both beta paths omit the same complete guard.",
        )
        + _finding(
            "INV-004",
            title="Complete beta authentication omission",
            location="network/auth.rs:75-80",
            source_ids="B-2",
            root_cause="The beta boundary path omits the same guard.",
        )
        + _finding(
            "INV-005",
            title="Independent persistence ordering defect",
            location="storage/write.rs:130-145",
            source_ids="C-1",
            root_cause="Persistence occurs before authentication succeeds.",
        )
    ).encode("utf-8")


def _decisions() -> bytes:
    return (
        "# Semantic Dedup Decisions\n\n"
        "MERGE: INV-001, INV-002\tsame mechanism and repair\n"
        "KEEP: INV-003\n"
        "KEEP: INV-004\n"
        "KEEP: INV-005\n"
    ).encode("utf-8")


def _pairs(*, full: bool) -> bytes:
    rows = [
        "| Finding A | Finding B | Title Score | Signal | Same Sev? |",
        "|---|---|---|---|---|",
        (
            "| INV-001: Complete alpha transition omission | "
            "INV-002: Alpha transition boundary variant | 0.88 | "
            "source-ID subset A-2 | yes |"
        ),
    ]
    if full:
        rows.append(
            "| INV-003: Complete beta authentication omission | "
            "INV-004: Complete beta authentication omission | 1.00 | "
            "location overlap (L75-80 vs L75-80) | yes |"
        )
    return ("# Dedup candidates\n\n" + "\n".join(rows) + "\n").encode("utf-8")


def _claim(
    *,
    scratchpad: Path,
    project: Path,
    phase: str,
    work_unit_id: str,
    outputs: Mapping[str, bytes],
    writer: str,
    model_invoked: bool,
    consumers: tuple[str, ...],
) -> str:
    owner = canonical_work_unit_key(
        "l1",
        "thorough",
        "rust",
        "claude",
        phase,
        work_unit_id,
    )
    contract = PhaseIOContract(
        pipeline="l1",
        mode="thorough",
        ecosystem="rust",
        backend="claude",
        phase=phase,
        work_unit_id=work_unit_id,
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=name,
                owner_key=owner,
                artifact_class=(
                    "REQUIRED" if writer == "MODEL" else "DRIVER_GENERATED"
                ),
                writer=writer,
                write_mode="CREATE",
                schema_version=(
                    "plamen.finding_records.v2"
                    if name == "finding_records.json"
                    else "unstructured.v1"
                ),
                minimum_gate="FIXTURE_EXACT_CURRENT_RUN_PRODUCER",
                consumers=consumers,
            )
            for name in outputs
        ),
        immutable_inputs=(),
        bounded_lookup_inputs=(),
        model_invoked=model_invoked,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="fixture-model" if model_invoked else "driver",
        timeout_s=60,
        exec_mode="pty" if model_invoked else "python",
        tool_policy=("filesystem",) if model_invoked else (),
    )
    record_work_unit_inputs(
        scratchpad, project, contract, launch, run_id=RUN_ID
    )
    for name, raw in outputs.items():
        (scratchpad / name).write_bytes(raw)
    committed = record_work_unit_artifacts(
        scratchpad,
        project,
        contract,
        launch,
        run_id=RUN_ID,
        actor=writer,
    )
    assert committed["semantic_status"] == "ACTIVE"
    return owner


def _seed(project: Path) -> tuple[Path, dict[str, Any], dict[str, bytes]]:
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    inventory = _inventory()
    records = derive_preverify_finding_records_bytes(inventory)
    decisions = _decisions()
    live_pairs = _pairs(full=False)
    full_pairs = _pairs(full=True)
    _claim(
        scratchpad=scratchpad,
        project=project,
        phase="inventory",
        work_unit_id="canonical_aggregate",
        outputs={
            "findings_inventory.md": inventory,
            "finding_records.json": records,
        },
        writer="DRIVER",
        model_invoked=False,
        consumers=(
            "semantic_dedup/supplemental_proposals",
            "semantic_dedup/prequeue_apply",
        ),
    )
    _claim(
        scratchpad=scratchpad,
        project=project,
        phase="semantic_dedup",
        work_unit_id="worker.semantic_dedup",
        outputs={"dedup_decisions.md": decisions},
        writer="MODEL",
        model_invoked=True,
        consumers=(
            "semantic_dedup/supplemental_proposals",
            "semantic_dedup/prequeue_apply",
        ),
    )
    _claim(
        scratchpad=scratchpad,
        project=project,
        phase="semantic_dedup",
        work_unit_id="dedup_pair_candidates",
        outputs={
            "dedup_candidate_pairs.md": live_pairs,
            "dedup_candidate_pairs_full.md": full_pairs,
        },
        writer="DRIVER",
        model_invoked=False,
        consumers=("semantic_dedup/supplemental_proposals",),
    )
    config = {
        "pipeline": "l1",
        "mode": "thorough",
        "language": "rust",
        "ecosystem": "rust",
        "backend": "claude",
        "cli_backend": "claude",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": RUN_ID,
    }
    sources = {
        "findings_inventory.md": inventory,
        "dedup_decisions.md": decisions,
        "dedup_candidate_pairs.md": live_pairs,
        "dedup_candidate_pairs_full.md": full_pairs,
    }
    return scratchpad, config, sources


def _active(scratchpad: Path) -> set[str]:
    return set(
        AUTHORITY.extract_finding_records(
            (scratchpad / "findings_inventory.md").read_text(
                encoding="utf-8", errors="strict"
            )
        )
    )


def _one_generation(scratchpad: Path) -> tuple[Path, Mapping[str, Any]]:
    generations = list((scratchpad / "_sdt").glob("g_*"))
    assert len(generations) == 1
    raw = (generations[0] / "i.json").read_bytes()
    value = json.loads(raw)
    # The transaction core owns its signed-intent framing.  The supplemental
    # contract only requires canonical JSON; do not make this RED suite depend
    # on whether that private framing includes one terminal newline.
    assert raw.rstrip(b"\n") == _canonical(value).rstrip(b"\n")
    return generations[0], value


def _assert_combined_receipt(
    scratchpad: Path,
    *,
    supplemental_state: str,
    supplemental_absorbed: set[str],
) -> Mapping[str, Any]:
    raw = (scratchpad / AUTHORITY.PRIMARY_RECEIPT_NAME).read_bytes()
    receipt = json.loads(raw)
    stages = receipt.get("application_stages")
    assert isinstance(stages, list) and len(stages) == 2
    primary, supplemental = stages
    assert primary["application_kind"] == "PRIMARY"
    assert primary["proposal_artifact"]["path"] == "dedup_decisions.md"
    assert primary["proposal_artifact"]["sha256"] == _sha(_decisions())
    assert set(primary["accepted_absorbed_ids"]) == {"INV-002"}
    assert supplemental["application_kind"] == "SUPPLEMENTAL"
    assert supplemental["state"] == supplemental_state
    assert supplemental["proposal_artifact"]["path"] == PROPOSAL_NAME
    assert set(supplemental["accepted_absorbed_ids"]) == supplemental_absorbed
    assert (
        primary["output_artifact"]["sha256"]
        == supplemental["input_artifact"]["sha256"]
    )
    input_ids = set(receipt["input_artifact"]["finding_ids"])
    output_ids = set(receipt["output_artifact"]["finding_ids"])
    absorbed_ids = set(receipt["accepted_absorbed_ids"])
    assert input_ids == output_ids | absorbed_ids
    assert not output_ids & absorbed_ids
    assert absorbed_ids == {"INV-002"} | supplemental_absorbed
    return receipt


def test_supplemental_proposals_have_a_separate_driver_contract() -> None:
    contract = resolve_phase_io_contract(
        pipeline="l1",
        mode="thorough",
        ecosystem="rust",
        backend="claude",
        phase="semantic_dedup",
        work_unit_id=PROPOSAL_WORK_UNIT,
        exact_inputs=SOURCE_NAMES,
        exact_outputs=(PROPOSAL_NAME,),
    )
    assert contract.model_invoked is False
    assert set(contract.immutable_inputs) == {
        "scratchpad:" + name for name in SOURCE_NAMES
    }
    assert len(contract.outputs) == 1
    output = contract.outputs[0]
    assert output.identity == "scratchpad:" + PROPOSAL_NAME
    assert output.writer == "DRIVER"
    # A stale proposal from an interrupted/pre-apply generation must be
    # refreshable only through this registered deterministic producer.
    assert output.write_mode == "REPLACE"
    assert output.schema_version == PROPOSAL_SCHEMA
    assert "semantic_dedup/prequeue_apply" in output.consumers

    apply = resolve_phase_io_contract(
        pipeline="l1",
        mode="thorough",
        ecosystem="rust",
        backend="claude",
        phase="semantic_dedup",
        work_unit_id=APPLY_WORK_UNIT,
        exact_inputs=("dedup_decisions.md", PROPOSAL_NAME),
        exact_outputs=FIVE_OUTPUTS,
    )
    assert set(apply.immutable_inputs) == {
        "scratchpad:dedup_decisions.md",
        "scratchpad:" + PROPOSAL_NAME,
    }
    assert {row.path for row in apply.outputs} == set(FIVE_OUTPUTS)


def test_pure_supplemental_enumerator_is_typed_conservative_and_deterministic() -> None:
    derive = _required("_derive_l1_supplemental_dedup_proposals")
    kwargs = {
        "inventory_raw": _inventory(),
        "decisions_raw": _decisions(),
        "candidate_pairs_raw": _pairs(full=False),
        "candidate_pairs_full_raw": _pairs(full=True),
        "run_id": RUN_ID,
    }
    first = bytes(derive(**kwargs))
    second = bytes(derive(**kwargs))
    assert first == second
    payload = json.loads(first)
    assert first == _canonical(payload)
    assert payload["schema_version"] == PROPOSAL_SCHEMA
    assert payload["run_id"] == RUN_ID
    assert payload["phase"] == "semantic_dedup"
    assert payload["state"] == "ACTIVE"
    assert payload["proposals"] == [
        {
            "action": "MERGE",
            "absorbed_id": "INV-004",
            "proposal_id": payload["proposals"][0]["proposal_id"],
            "signal_kind": "EXACT_LOCATION_SAME_SEVERITY",
            "source_pair_digest": payload["proposals"][0][
                "source_pair_digest"
            ],
            "survivor_id": "INV-003",
        }
    ]
    assert len(payload["proposals"][0]["proposal_id"]) >= 20
    assert len(payload["proposals"][0]["source_pair_digest"]) == 64
    assert set(payload["source_artifacts"]) == set(SOURCE_NAMES)
    for name, raw in {
        "findings_inventory.md": _inventory(),
        "dedup_decisions.md": _decisions(),
        "dedup_candidate_pairs.md": _pairs(full=False),
        "dedup_candidate_pairs_full.md": _pairs(full=True),
    }.items():
        assert payload["source_artifacts"][name] == {
            "sha256": _sha(raw),
            "size_bytes": len(raw),
        }
    assert len(payload["proposal_set_digest"]) == 64
    assert len(payload["artifact_digest"]) == 64


def test_primary_and_supplemental_are_derived_before_any_publication(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratchpad, config, sources = _seed(project)
    before_pair = {
        name: (scratchpad / name).read_bytes()
        for name in ("findings_inventory.md", "finding_records.json")
    }

    def crash(label: str) -> None:
        if label == "AFTER_GENERATION_DURABLE":
            raise RuntimeError("fixture-crash")

    with pytest.raises(RuntimeError, match="fixture-crash"):
        _required("_run_l1_prequeue_semantic_dedup_transaction")(
            scratchpad=scratchpad,
            project_root=project,
            config=config,
            run_id=RUN_ID,
            fault_hook=crash,
        )
    assert {
        name: (scratchpad / name).read_bytes() for name in before_pair
    } == before_pair
    assert (scratchpad / "dedup_decisions.md").read_bytes() == sources[
        "dedup_decisions.md"
    ]

    generation, intent = _one_generation(scratchpad)
    staged_post = (generation / "a0.bin").read_text(
        encoding="utf-8", errors="strict"
    )
    assert set(AUTHORITY.extract_finding_records(staged_post)) == {
        "INV-001",
        "INV-003",
        "INV-005",
    }
    exact_inputs = {
        str(row["path"]): row for row in intent["exact_inputs"]
    }
    assert {"dedup_decisions.md", PROPOSAL_NAME} <= set(exact_inputs)
    assert exact_inputs["dedup_decisions.md"]["sha256"] == _sha(
        sources["dedup_decisions.md"]
    )
    proposal_raw = (scratchpad / PROPOSAL_NAME).read_bytes()
    assert exact_inputs[PROPOSAL_NAME]["sha256"] == _sha(proposal_raw)

    result = _required("_run_l1_prequeue_semantic_dedup_transaction")(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )
    assert result["safe_to_consume"] is True
    assert _active(scratchpad) == {"INV-001", "INV-003", "INV-005"}
    aliases = AUTHORITY.load_applied_aliases(scratchpad)
    assert {
        key: row["survivor"] for key, row in aliases.items()
    } == {"INV-002": "INV-001", "INV-004": "INV-003"}
    _assert_combined_receipt(
        scratchpad,
        supplemental_state="APPLIED",
        supplemental_absorbed={"INV-004"},
    )


def test_recovery_reports_committed_supplemental_degrade_not_proposal_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Resume metadata must come from the committed receipt, not the proposal."""

    project = tmp_path / "project"
    scratchpad, config, _ = _seed(project)
    import l1_semantic_dedup_supplemental as supplemental

    def fail_application(*args: Any, **kwargs: Any) -> None:
        raise ValueError("injected supplemental application failure")

    monkeypatch.setattr(
        supplemental, "_apply_merges_to_inventory", fail_application
    )

    def crash(label: str) -> None:
        if label == "AFTER_PENDING_STAGED_DURABLE":
            raise RuntimeError("fixture-crash")

    with pytest.raises(RuntimeError, match="fixture-crash"):
        _required("_run_l1_prequeue_semantic_dedup_transaction")(
            scratchpad=scratchpad,
            project_root=project,
            config=config,
            run_id=RUN_ID,
            fault_hook=crash,
        )

    proposal = json.loads((scratchpad / PROPOSAL_NAME).read_bytes())
    assert proposal["state"] == "ACTIVE"

    recovered = _required(
        "_run_l1_prequeue_semantic_dedup_transaction"
    )(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )
    assert recovered["safe_to_consume"] is True
    assert recovered["recovered"] is True
    assert recovered["supplemental_state"] == "DEGRADED_PRIMARY_ONLY"
    assert any(
        "injected supplemental application failure" in str(row)
        for row in recovered["supplemental_debt"]
    )
    _assert_combined_receipt(
        scratchpad,
        supplemental_state="DEGRADED_PRIMARY_ONLY",
        supplemental_absorbed=set(),
    )


def test_supplemental_producer_and_apply_input_have_exact_current_run_authority(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratchpad, config, _ = _seed(project)
    result = _required("_run_l1_prequeue_semantic_dedup_transaction")(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )
    assert result["safe_to_consume"] is True

    ledger = read_artifact_ledger(scratchpad)
    proposal_binding = ledger["artifact_bindings"][
        "scratchpad:" + PROPOSAL_NAME
    ]
    proposal_key = canonical_work_unit_key(
        "l1",
        "thorough",
        "rust",
        "claude",
        "semantic_dedup",
        PROPOSAL_WORK_UNIT,
    )
    assert proposal_binding["owner_key"] == proposal_key
    proposal_unit = ledger["work_units"][proposal_key]
    assert proposal_unit["execution_state"] == "OUTPUT_COMMITTED"
    assert set(proposal_unit["input_bindings"]) == {
        "scratchpad:" + name for name in SOURCE_NAMES
    }

    apply_key = canonical_work_unit_key(
        "l1",
        "thorough",
        "rust",
        "claude",
        "semantic_dedup",
        APPLY_WORK_UNIT,
    )
    apply = ledger["work_units"][apply_key]
    assert apply["execution_state"] == "OUTPUT_COMMITTED"
    assert set(apply["input_bindings"]) == {
        "scratchpad:dedup_decisions.md",
        "scratchpad:" + PROPOSAL_NAME,
    }
    assert (
        apply["input_bindings"]["scratchpad:" + PROPOSAL_NAME]["sha256"]
        == proposal_binding["sha256"]
    )
    generation, intent = _one_generation(scratchpad)
    binding_text = json.dumps(intent["authority_binding"], sort_keys=True)
    assert proposal_key in binding_text
    commit = proposal_unit["commit_authority"]
    assert str(commit["receipt_digest"]) in binding_text
    assert (generation / "a0.bin").read_bytes() == (
        scratchpad / "findings_inventory.md"
    ).read_bytes()


def test_legacy_supplemental_mutator_is_never_called_for_l1(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    scratchpad, config, sources = _seed(project)

    def forbidden(*args: Any, **kwargs: Any) -> int:
        if kwargs.get("supplemental"):
            raise AssertionError("post-publication supplemental mutator called")
        return 0

    monkeypatch.setattr(
        DRIVER, "_apply_mechanical_dedup_from_pairs", forbidden
    )
    result = _required("_run_l1_prequeue_semantic_dedup_transaction")(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )
    assert result["safe_to_consume"] is True
    assert _active(scratchpad) == {"INV-001", "INV-003", "INV-005"}
    assert (scratchpad / "dedup_decisions.md").read_bytes() == sources[
        "dedup_decisions.md"
    ]
    assert not (
        scratchpad / "findings_inventory.md.semantic_dedup.pending"
    ).exists()
    assert not (scratchpad / AUTHORITY.SUPPLEMENTAL_RECEIPT_NAME).exists()

    validator = inspect.getsource(DRIVER._run_phase_validators)
    l1_start = validator.find("# --- semantic_dedup (L1)")
    sc_start = validator.find("# --- sc_semantic_dedup (SC)")
    l1_block = validator[l1_start:sc_start]
    assert "supplemental=True" not in l1_block
    assert "_apply_mechanical_dedup_from_pairs" not in l1_block


def test_supplemental_failure_degrades_to_primary_only_without_candidate_loss(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    scratchpad, config, sources = _seed(project)
    derive = _required("_derive_l1_supplemental_dedup_proposals")

    def fail(*args: Any, **kwargs: Any) -> bytes:
        raise ValueError("injected supplemental derivation failure")

    monkeypatch.setattr(
        DRIVER, "_derive_l1_supplemental_dedup_proposals", fail
    )
    result = _required("_run_l1_prequeue_semantic_dedup_transaction")(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )
    assert result["safe_to_consume"] is True
    assert _active(scratchpad) == {
        "INV-001",
        "INV-003",
        "INV-004",
        "INV-005",
    }
    aliases = AUTHORITY.load_applied_aliases(scratchpad)
    assert {
        key: row["survivor"] for key, row in aliases.items()
    } == {"INV-002": "INV-001"}
    assert set(AUTHORITY.extract_finding_records(
        sources["findings_inventory.md"].decode("utf-8")
    )) == _active(scratchpad) | set(aliases)

    proposal_raw = (scratchpad / PROPOSAL_NAME).read_bytes()
    proposal = json.loads(proposal_raw)
    assert proposal_raw == _canonical(proposal)
    assert proposal["schema_version"] == PROPOSAL_SCHEMA
    assert proposal["state"] == "DEGRADED_PRIMARY_ONLY"
    assert proposal["proposals"] == []
    assert any(
        "injected supplemental derivation failure" in str(row)
        for row in proposal["debt"]
    )
    _assert_combined_receipt(
        scratchpad,
        supplemental_state="DEGRADED_PRIMARY_ONLY",
        supplemental_absorbed=set(),
    )
    assert result.get("supplemental_state") == "DEGRADED_PRIMARY_ONLY"
    assert result.get("supplemental_debt")

    # Keep a live reference so a mistaken implementation that bypasses the
    # monkeypatched pure deriver cannot satisfy this fixture accidentally.
    assert callable(derive)


def test_tampered_supplemental_proposal_cannot_authorize_postimages(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratchpad, config, _ = _seed(project)
    proposal_phase = _required(
        "_run_l1_supplemental_dedup_proposal_phase"
    )
    produced = proposal_phase(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )
    assert produced["state"] in {"ACTIVE", "DEGRADED_PRIMARY_ONLY"}
    original_pair = {
        name: (scratchpad / name).read_bytes()
        for name in ("findings_inventory.md", "finding_records.json")
    }
    proposal_path = scratchpad / PROPOSAL_NAME
    proposal_path.write_bytes(proposal_path.read_bytes() + b"\nTAMPER\n")

    with pytest.raises(
        Exception,
        match="(?i)input|authority|producer|drift|tamper|changed",
    ):
        _required("_run_l1_prequeue_semantic_dedup_transaction")(
            scratchpad=scratchpad,
            project_root=project,
            config=config,
            run_id=RUN_ID,
        )
    assert {
        name: (scratchpad / name).read_bytes() for name in original_pair
    } == original_pair
    assert not (scratchpad / "_sdt").exists() or not any(
        (scratchpad / "_sdt").glob("g_*")
    )


def test_replay_does_not_reapply_supplemental_or_mutate_model_provenance(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    scratchpad, config, sources = _seed(project)
    apply = _required("_run_l1_prequeue_semantic_dedup_transaction")
    first = apply(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )
    snapshot = {
        path.relative_to(scratchpad).as_posix(): path.read_bytes()
        for path in scratchpad.rglob("*")
        if path.is_file()
    }
    second = apply(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=RUN_ID,
    )
    after = {
        path.relative_to(scratchpad).as_posix(): path.read_bytes()
        for path in scratchpad.rglob("*")
        if path.is_file()
    }
    assert first["generation_digest"] == second["generation_digest"]
    assert second["safe_to_consume"] is True
    assert snapshot == after
    assert (scratchpad / "dedup_decisions.md").read_bytes() == sources[
        "dedup_decisions.md"
    ]
    canonical = (scratchpad / "findings_inventory.md").read_text(
        encoding="utf-8", errors="strict"
    )
    assert canonical.count(
        "PLAMEN_DEDUP_PRESERVED_MEMBER_BEGIN id=INV-002"
    ) == 1
    assert canonical.count(
        "PLAMEN_DEDUP_PRESERVED_MEMBER_BEGIN id=INV-004"
    ) == 1
