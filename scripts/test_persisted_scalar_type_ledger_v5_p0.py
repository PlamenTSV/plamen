"""V5 regressions for immutable exact-repair private lineage.

V4 bound a repaired public projection to a signed PRE/POST history, but the
history and its repair-digest projections remained coherently resealable.  A
replacement generation, intent, PhaseIO binding, or transaction receipt could
therefore name private objects which had never existed.  These tests start
from the real production L1 transaction/driver repair and preserve its
semantic commit receipt, attempt, issued output authority, and public bytes.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
from typing import Any, Mapping

import pytest

import artifact_ledger as AL
import plamen_driver as DRIVER
import semantic_dedup_transaction as SDT
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    resolve_phase_io_contract,
)
from test_l1_semantic_dedup_prequeue_transaction_red import (
    RUN_ID as DRIVER_RUN_ID,
)
from test_semantic_dedup_repair_fault_matrix import (
    _driver_repaired_fixture,
    _repair_unit,
)


SC_RUN_ID = "12345678-1234-4234-8234-123456789abc"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _signed(row: Mapping[str, Any]) -> dict[str, Any]:
    unsigned = {
        key: copy.deepcopy(value)
        for key, value in row.items()
        if key != "authority_digest"
    }
    return {**unsigned, "authority_digest": _digest(unsigned)}


def _contract_and_launch(
    unit: Mapping[str, Any],
    config: Mapping[str, Any],
) -> tuple[PhaseIOContract, LaunchSpec]:
    observed_inputs = set(unit["input_bindings"])
    exact_inputs = (
        ("dedup_decisions.md",)
        if observed_inputs == {"scratchpad:dedup_decisions.md"}
        else (
            "dedup_decisions.md",
            DRIVER._L1_SUPPLEMENTAL_PROPOSAL_NAME,
        )
    )
    contract = resolve_phase_io_contract(
        pipeline="l1",
        mode=str(config.get("mode") or "thorough"),
        ecosystem=str(
            config.get("ecosystem") or config.get("language") or "rust"
        ),
        backend=str(
            config.get("cli_backend") or config.get("backend") or "claude"
        ),
        phase="semantic_dedup",
        work_unit_id="prequeue_apply",
        exact_inputs=exact_inputs,
        exact_outputs=tuple(DRIVER.SEMANTIC_DEDUP_TRANSACTION_OUTPUTS),
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=300,
        exec_mode="python",
        tool_policy=(),
    )
    return contract, launch


def _authority_snapshot(unit: Mapping[str, Any]) -> dict[str, Any]:
    commit = unit["commit_authority"]
    return {
        "attempt_ordinal": commit["attempt_ordinal"],
        "commit_receipt_digest": commit["receipt_digest"],
        "output_authority_key": commit["output_authority_key"],
        "output_authority_digest": commit["output_authority_digest"],
        "artifacts": {
            identity: {
                "sha256": row["sha256"],
                "size": row["size"],
            }
            for identity, row in sorted(unit["artifacts"].items())
        },
    }


def _reseal_private_lineage(
    scratchpad: Path,
    *,
    generation: str | None = None,
    intent: str | None = None,
    binding: str | None = None,
    receipt: str | None = None,
) -> None:
    ledger = AL.read_artifact_ledger(scratchpad)
    _key, unit = _repair_unit(ledger)
    row = unit["committed_output_repair_history"][-1]
    arm = copy.deepcopy(row["arm_authority"])
    finalize = copy.deepcopy(row["finalize_authority"])
    if generation is not None:
        arm["generation_digest"] = generation
        finalize["generation_digest"] = generation
    if intent is not None:
        arm["intent_sha256"] = intent
    if binding is not None:
        arm["authority_binding_sha256"] = binding
    if receipt is not None:
        arm["transaction_receipt_sha256"] = receipt
        finalize["transaction_receipt_sha256"] = receipt
    arm = _signed(arm)
    finalize["repair_arm_authority_digest"] = arm["authority_digest"]
    finalize = _signed(finalize)
    unsigned_history = {
        "schema_version": row["schema_version"],
        "state": row["state"],
        "repair_pending_sha256": row["repair_pending_sha256"],
        "arm_authority": arm,
        "finalize_authority": finalize,
    }
    replacement = {
        **unsigned_history,
        "history_digest": _digest(unsigned_history),
    }
    unit["committed_output_repair_history"][-1] = replacement
    repair_digest = finalize["authority_digest"]
    for identity, artifact in unit["artifacts"].items():
        artifact["repair_authority_digest"] = repair_digest
        ledger["artifact_bindings"][identity][
            "repair_authority_digest"
        ] = repair_digest
        relative = identity.split(":", 1)[1]
        ledger["artifacts"][relative][
            "repair_authority_digest"
        ] = repair_digest
    AL.write_artifact_ledger(scratchpad, ledger)


PRIVATE_LINEAGE_SUBSTITUTIONS = (
    ("generation", {"generation": "1" * 64}),
    ("transaction_receipt", {"receipt": "2" * 64}),
    ("intent", {"intent": "3" * 64}),
    ("authority_binding", {"binding": "4" * 64}),
    (
        "all_private_lineage",
        {
            "generation": "5" * 64,
            "intent": "6" * 64,
            "binding": "7" * 64,
            "receipt": "8" * 64,
        },
    ),
)


@pytest.mark.parametrize(
    ("case", "substitution"),
    PRIVATE_LINEAGE_SUBSTITUTIONS,
    ids=[row[0] for row in PRIVATE_LINEAGE_SUBSTITUTIONS],
)
def test_v5_resealed_repair_cannot_name_nonexistent_private_lineage(
    tmp_path: Path,
    case: str,
    substitution: dict[str, str],
) -> None:
    project, scratchpad, config, expected, _repaired = (
        _driver_repaired_fixture(tmp_path)
    )
    _key, before_unit = _repair_unit(AL.read_artifact_ledger(scratchpad))
    authority_before = _authority_snapshot(before_unit)
    _reseal_private_lineage(scratchpad, **substitution)

    ledger = AL.read_artifact_ledger(scratchpad)
    key, unit = _repair_unit(ledger)
    contract, launch = _contract_and_launch(unit, config)
    arm = unit["committed_output_repair_history"][-1]["arm_authority"]
    assert AL._exact_repair_history(unit), case
    assert _authority_snapshot(unit) == authority_before, case
    assert all(
        (scratchpad / relative).read_bytes() == raw
        for relative, raw in expected.items()
    ), case
    if "generation" in substitution:
        assert not (
            scratchpad / "_sdt" / f"g_{arm['generation_digest']}"
        ).exists(), case
        assert not (
            scratchpad / "_sdt" / f"c_{arm['generation_digest']}.json"
        ).exists(), case

    active = AL._active_commit_receipt_is_valid(
        unit,
        work_unit_key=key,
        run_id=DRIVER_RUN_ID,
    )
    final_issues = AL.validate_work_unit_artifacts(
        scratchpad,
        project,
        contract,
        launch,
        run_id=DRIVER_RUN_ID,
        actor="DRIVER",
        require_live_input_authority=False,
    )
    driver_committed = DRIVER._l1_prequeue_apply_is_committed(
        scratchpad,
        config=config,
        run_id=DRIVER_RUN_ID,
    )
    assert (active, bool(final_issues), driver_committed) == (
        False,
        True,
        False,
    ), case


def test_v5_genuine_private_generation_and_repaired_l1_successor_remain_valid(
    tmp_path: Path,
) -> None:
    project, scratchpad, config, expected, _repaired = (
        _driver_repaired_fixture(tmp_path)
    )
    _key, unit = _repair_unit(AL.read_artifact_ledger(scratchpad))
    arm = unit["committed_output_repair_history"][-1]["arm_authority"]
    generation = str(arm["generation_digest"])
    private = scratchpad / "_sdt"
    assert (private / f"g_{generation}" / "i.json").is_file()
    assert (private / f"c_{generation}.json").is_file()
    assert all(
        (scratchpad / relative).read_bytes() == raw
        for relative, raw in expected.items()
    )
    contract, launch = _contract_and_launch(unit, config)
    assert AL._active_commit_receipt_is_valid(
        unit,
        work_unit_key=contract.key,
        run_id=DRIVER_RUN_ID,
    )
    assert not AL.validate_work_unit_artifacts(
        scratchpad,
        project,
        contract,
        launch,
        run_id=DRIVER_RUN_ID,
        actor="DRIVER",
        require_live_input_authority=False,
    )
    assert DRIVER._l1_prequeue_apply_is_committed(
        scratchpad,
        config=config,
        run_id=DRIVER_RUN_ID,
    )


def test_v5_sc_actor_omission_and_legacy_both_hints_remain_valid(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    key = "sc/core/evm/claude/fixture/ledger_v5_control"
    contract = PhaseIOContract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="claude",
        phase="fixture",
        work_unit_id="ledger_v5_control",
        outputs=(ArtifactSpec(
            root="scratchpad",
            path="output.md",
            owner_key=key,
            artifact_class="DRIVER_GENERATED",
            writer="DRIVER",
            write_mode="REPLACE",
        ),),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=30,
        exec_mode="python",
        tool_policy=(),
    )
    AL.record_work_unit_inputs(
        scratchpad, tmp_path, contract, launch, run_id=SC_RUN_ID
    )
    (scratchpad / "output.md").write_bytes(b"x")
    AL.record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=SC_RUN_ID,
        actor=None,
    )
    ledger = AL.read_artifact_ledger(scratchpad)
    unit = ledger["work_units"][contract.key]
    assert unit["commit_authority"]["output_authority_actor"] == "DRIVER"
    assert AL._active_commit_receipt_is_valid(
        unit, work_unit_key=contract.key, run_id=SC_RUN_ID
    )

    commit = unit["commit_authority"]
    commit.pop("output_authority_source")
    commit.pop("output_authority_actor")
    commit["receipt_digest"] = AL._commit_receipt_digest(commit)
    AL.write_artifact_ledger(scratchpad, ledger)
    unit = AL.read_artifact_ledger(scratchpad)["work_units"][contract.key]
    assert AL._active_commit_receipt_is_valid(
        unit, work_unit_key=contract.key, run_id=SC_RUN_ID
    )


def _private_paths(scratchpad: Path) -> tuple[Path, Path]:
    _key, unit = _repair_unit(AL.read_artifact_ledger(scratchpad))
    generation = unit["committed_output_repair_history"][-1][
        "arm_authority"
    ]["generation_digest"]
    return (
        scratchpad / "_sdt" / f"g_{generation}",
        scratchpad / "_sdt" / f"c_{generation}.json",
    )


def _coherently_reseal_equivalent_private_generation(
    scratchpad: Path,
) -> tuple[str, str]:
    """Materialize a producer-valid equivalent generation and receipt.

    Reordering the set-like roles on one exact input does not change any
    input, output, public byte, or transaction authority.  It does change the
    content-addressed generation.  A consumer-captured pre-repair source
    anchor must therefore reject this later physical replacement even though
    the producer's own generation and committed-receipt validators accept it.
    """

    generation_root, receipt_path = _private_paths(scratchpad)
    old_generation = generation_root.name.removeprefix("g_")
    intent = json.loads(
        (generation_root / "i.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    exact_inputs = copy.deepcopy(list(intent["exact_inputs"]))
    assert exact_inputs
    roles = list(exact_inputs[0]["roles"])
    assert len(roles) >= 2
    replacement_roles = list(reversed(roles))
    assert replacement_roles != roles
    exact_inputs[0]["roles"] = replacement_roles
    intent["exact_inputs"] = exact_inputs

    generation_unsigned = copy.deepcopy(intent)
    generation_unsigned.pop("intent_sha256", None)
    generation_unsigned.pop("generation_digest", None)
    new_generation = _digest(generation_unsigned)
    assert new_generation != old_generation
    intent["generation_digest"] = new_generation
    intent_unsigned = copy.deepcopy(intent)
    intent_unsigned.pop("intent_sha256", None)
    intent["intent_sha256"] = _digest(intent_unsigned)

    private = generation_root.parent
    replacement_root = private / f"g_{new_generation}"
    shutil.copytree(generation_root, replacement_root)
    (replacement_root / "i.json").write_bytes(_canonical(intent))
    replayed_intent, _payloads = SDT._validate_generation(
        scratchpad, new_generation
    )
    assert replayed_intent == intent

    receipt = json.loads(
        receipt_path.read_text(encoding="utf-8", errors="strict")
    )
    receipt["generation_digest"] = new_generation
    receipt["intent_sha256"] = intent["intent_sha256"]
    for key in (
        "phaseio_arm",
        "phaseio_commit",
        "mutation_arm",
        "mutation_finalize",
    ):
        attestation = receipt[key]
        attestation["generation_digest"] = new_generation
        attestation_unsigned = copy.deepcopy(attestation)
        attestation_unsigned.pop("authority_digest", None)
        attestation["authority_digest"] = _digest(attestation_unsigned)
    receipt_unsigned = copy.deepcopy(receipt)
    receipt_unsigned.pop("receipt_sha256", None)
    receipt["receipt_sha256"] = _digest(receipt_unsigned)
    replacement_receipt = private / f"c_{new_generation}.json"
    replacement_receipt.write_bytes(_canonical(receipt))
    replayed_receipt = SDT._load_receipt(scratchpad, new_generation)
    assert replayed_receipt == receipt
    SDT._validate_committed_receipt_for_repair(intent, receipt)

    _reseal_private_lineage(
        scratchpad,
        generation=new_generation,
        intent=str(intent["intent_sha256"]),
        receipt=str(receipt["receipt_sha256"]),
    )
    return old_generation, new_generation


def _repair_consumer_tuple(
    scratchpad: Path,
    project: Path,
    config: Mapping[str, Any],
) -> tuple[bool, bool, bool]:
    key, unit = _repair_unit(AL.read_artifact_ledger(scratchpad))
    contract, launch = _contract_and_launch(unit, config)
    run_id = str(unit["run_id"])
    return (
        AL._active_commit_receipt_is_valid(
            unit, work_unit_key=key, run_id=run_id
        ),
        bool(AL.validate_work_unit_artifacts(
            scratchpad,
            project,
            contract,
            launch,
            run_id=run_id,
            actor="DRIVER",
            require_live_input_authority=False,
        )),
        DRIVER._l1_prequeue_apply_is_committed(
            scratchpad, config=config, run_id=run_id
        ),
    )


def test_v5_equivalent_physical_private_lineage_reseal_rejects(
    tmp_path: Path,
) -> None:
    project, scratchpad, config, expected, _repaired = (
        _driver_repaired_fixture(tmp_path)
    )
    _key, before_unit = _repair_unit(AL.read_artifact_ledger(scratchpad))
    authority_before = _authority_snapshot(before_unit)
    old_generation, new_generation = (
        _coherently_reseal_equivalent_private_generation(scratchpad)
    )
    _key, after_unit = _repair_unit(AL.read_artifact_ledger(scratchpad))

    assert old_generation != new_generation
    assert _authority_snapshot(after_unit) == authority_before
    assert all(
        (scratchpad / relative).read_bytes() == raw
        for relative, raw in expected.items()
    )
    assert _repair_consumer_tuple(scratchpad, project, config) == (
        False,
        True,
        False,
    )


def test_v5_identical_receipt_physical_replacement_rejects(
    tmp_path: Path,
) -> None:
    project, scratchpad, config, expected, _repaired = (
        _driver_repaired_fixture(tmp_path)
    )
    _generation_root, receipt = _private_paths(scratchpad)
    original = receipt.read_bytes()
    replacement = receipt.with_name(receipt.name + ".replacement")
    replacement.write_bytes(original)
    os.replace(replacement, receipt)

    assert receipt.read_bytes() == original
    assert all(
        (scratchpad / relative).read_bytes() == raw
        for relative, raw in expected.items()
    )
    assert _repair_consumer_tuple(scratchpad, project, config) == (
        False,
        True,
        False,
    )


def test_v5_private_generation_directory_alias_rejects(
    tmp_path: Path,
) -> None:
    project, scratchpad, config, _expected, _repaired = (
        _driver_repaired_fixture(tmp_path)
    )
    generation_root, _receipt = _private_paths(scratchpad)
    real = generation_root.with_name(generation_root.name + ".real")
    generation_root.rename(real)
    try:
        generation_root.symlink_to(real, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"host does not permit directory symlink: {exc}")
    key, unit = _repair_unit(AL.read_artifact_ledger(scratchpad))
    contract, launch = _contract_and_launch(unit, config)
    active = AL._active_commit_receipt_is_valid(
        unit, work_unit_key=key, run_id=DRIVER_RUN_ID
    )
    final_issues = AL.validate_work_unit_artifacts(
        scratchpad,
        project,
        contract,
        launch,
        run_id=DRIVER_RUN_ID,
        actor="DRIVER",
        require_live_input_authority=False,
    )
    driver_committed = DRIVER._l1_prequeue_apply_is_committed(
        scratchpad, config=config, run_id=DRIVER_RUN_ID
    )
    assert (active, bool(final_issues), driver_committed) == (
        False,
        True,
        False,
    )


def test_v5_private_transaction_receipt_hardlink_alias_rejects(
    tmp_path: Path,
) -> None:
    project, scratchpad, config, _expected, _repaired = (
        _driver_repaired_fixture(tmp_path)
    )
    _generation_root, receipt = _private_paths(scratchpad)
    alias = receipt.with_name(receipt.name + ".alias")
    try:
        os.link(receipt, alias)
    except OSError as exc:
        pytest.skip(f"host does not permit hardlink fixture: {exc}")
    key, unit = _repair_unit(AL.read_artifact_ledger(scratchpad))
    contract, launch = _contract_and_launch(unit, config)
    active = AL._active_commit_receipt_is_valid(
        unit, work_unit_key=key, run_id=DRIVER_RUN_ID
    )
    final_issues = AL.validate_work_unit_artifacts(
        scratchpad,
        project,
        contract,
        launch,
        run_id=DRIVER_RUN_ID,
        actor="DRIVER",
        require_live_input_authority=False,
    )
    driver_committed = DRIVER._l1_prequeue_apply_is_committed(
        scratchpad, config=config, run_id=DRIVER_RUN_ID
    )
    assert (active, bool(final_issues), driver_committed) == (
        False,
        True,
        False,
    )


def test_v5_private_lineage_replay_is_bounded_stable_and_no_follow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project, scratchpad, _config, _expected, _repaired = (
        _driver_repaired_fixture(tmp_path)
    )
    key, unit = _repair_unit(AL.read_artifact_ledger(scratchpad))
    calls: list[tuple[str, int, tuple[int, ...]]] = []
    original = AL._read_stable_regular_bytes

    def observed(
        path: Path,
        *,
        limit: int,
        allowed_link_counts: tuple[int, ...] = (1,),
    ) -> bytes:
        calls.append((Path(path).name, limit, allowed_link_counts))
        return original(
            path,
            limit=limit,
            allowed_link_counts=allowed_link_counts,
        )

    monkeypatch.setattr(AL, "_read_stable_regular_bytes", observed)
    assert AL._active_commit_receipt_is_valid(
        unit, work_unit_key=key, run_id=DRIVER_RUN_ID
    )
    assert "i.json" in {row[0] for row in calls}
    assert any(name.startswith("c_") for name, _limit, _links in calls)
    assert all(limit <= AL._EXACT_REPAIR_ARTIFACT_LIMIT for _, limit, _ in calls)
    assert all(links == (1,) for _, _, links in calls)
