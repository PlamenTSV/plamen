"""RED contracts for haltless L1 dedup-packet producer degradation.

These tests deliberately exercise failures *before* the semantic-dedup model
owns an exact block/pair/focus denominator.  Integrity rejection alone is not
enough: repair-then-degrade must preserve the canonical inventory, retain
visible debt, refuse MODEL authority over incomplete bytes, and terminate via
an inventory-bound DRIVER passthrough.

No production code belongs in this fixture module.
"""
from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any, Mapping

import pytest

from artifact_ledger import read_artifact_ledger, record_work_unit_inputs
from phase_io_contracts import canonical_work_unit_key
import plamen_driver as DRIVER
from plamen_types import L1_PHASES
import test_l1_semantic_dedup_prequeue_transaction_red as BASE


PACKET_NAMES = BASE.PAIR_PACKET_OUTPUT_NAMES


def _model_key() -> str:
    return canonical_work_unit_key(
        "l1",
        "thorough",
        "rust",
        "claude",
        "semantic_dedup",
        "model",
    )


def _assert_model_has_no_packet_authority(
    scratchpad: Path,
    config: dict[str, Any],
) -> None:
    """An unavailable packet may not become a MODEL input denominator."""

    phase = next(row for row in L1_PHASES if row.name == "semantic_dedup")
    issues = DRIVER._bind_typed_model_phase_inputs(
        phase,
        scratchpad,
        config,
    )
    assert issues, (
        "an unowned/incomplete dedup packet was accepted as the model's "
        "semantic denominator"
    )
    unit = read_artifact_ledger(scratchpad).get("work_units", {}).get(
        _model_key()
    )
    assert not (
        isinstance(unit, Mapping)
        and unit.get("semantic_status") in {"INPUTS_BOUND", "ACTIVE"}
        and unit.get("execution_state")
        in {"INPUTS_BOUND_PREEXECUTION", "OUTPUT_COMMITTED"}
    ), "the semantic-dedup MODEL acquired authority over incomplete bytes"


def _assert_visible_packet_debt(scratchpad: Path) -> bytes:
    debt_path = scratchpad / "semantic_dedup.degraded"
    assert debt_path.is_file(), "packet failure did not leave durable debt"
    raw = debt_path.read_bytes()
    assert b"DEDUP_PAIR_CANDIDATE" in raw.upper()
    return raw


def _assert_main_has_prelaunch_veto_for_unresolved_packet_debt() -> None:
    """Preparation debt must terminate this phase before generic MODEL launch."""

    source = inspect.getsource(DRIVER.main)
    start = source.index(
        "_l1_dedup_prepare_issues = "
        "_prepare_l1_semantic_dedup_inventory("
    )
    end = source.index(
        'if phase.name == "sc_semantic_dedup"',
        start,
    )
    boundary = source[start:end]
    replay_call = boundary.find(
        "_run_l1_prequeue_semantic_dedup_transaction("
    )
    replay_validation = boundary.find(
        "_l1_prequeue_apply_is_committed(",
        replay_call + 1,
    )
    veto_set = boundary.find(
        'config["_l1_semantic_dedup_packet_launch_veto"] = True',
        replay_validation + 1,
    )
    veto_consume = boundary.find(
        "if config.pop(",
        veto_set + 1,
    )
    assert (
        "_l1_semantic_dedup_packet_launch_veto"
        in boundary[veto_consume:veto_consume + 200]
    ), "main consumes a different flag at the semantic-dedup launch veto"
    incomplete = boundary.find(
        "_commit_incomplete_phase_attempt(",
        veto_consume + 1,
    )
    stop = boundary.find("continue", incomplete + 1)
    assert (
        0 <= replay_call < replay_validation < veto_set
        < veto_consume < incomplete < stop
    ), (
        "main has no explicit incomplete-with-debt launch veto when packet "
        "preparation and its DRIVER passthrough both fail; generic "
        "semantic_dedup MODEL binding remains reachable"
    )


def _assert_haltless_inventory_passthrough(
    *,
    project: Path,
    scratchpad: Path,
    config: dict[str, Any],
    inventory_raw: bytes,
    reason: str,
) -> None:
    """The failure exit is DRIVER-owned, inventory-bound, and replay-stable."""

    result = DRIVER._run_l1_semantic_dedup_noop_proposal(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=BASE.RUN_ID,
        reason=reason,
    )
    assert result.get("safe_to_consume") is True
    assert (scratchpad / "findings_inventory.md").read_bytes() == inventory_raw
    BASE._assert_exact_records_projection(scratchpad)

    decisions = (scratchpad / "dedup_decisions.md").read_text(
        encoding="utf-8",
        errors="strict",
    )
    normalized = decisions.upper()
    assert "PASSTHROUGH" in normalized
    assert "MERGE:" not in normalized
    assert "DROP:" not in normalized
    assert "NO CANDIDATE DUPLICATE" not in normalized
    assert all(
        finding_id in decisions
        or finding_id in (
            scratchpad / "findings_inventory.md"
        ).read_text(encoding="utf-8", errors="strict")
        for finding_id in ("INV-001", "INV-002", "INV-003")
    )

    ledger = read_artifact_ledger(scratchpad)
    decision_binding = ledger["artifact_bindings"][
        "scratchpad:dedup_decisions.md"
    ]
    owner = ledger["work_units"][decision_binding["owner_key"]]
    assert owner["model_invoked"] is False
    assert owner["semantic_status"] == "ACTIVE"
    assert owner["execution_state"] == "OUTPUT_COMMITTED"
    bound_inputs = set(owner.get("input_bindings", {}))
    assert "scratchpad:findings_inventory.md" in bound_inputs
    assert not {
        "scratchpad:" + name for name in PACKET_NAMES
    } & bound_inputs, (
        "the degraded passthrough consumed the unavailable packet and "
        "retroactively legitimized it"
    )
    assert DRIVER._l1_prequeue_apply_authority_exists(
        scratchpad,
        config=config,
        run_id=BASE.RUN_ID,
    )

    before = {
        name: (scratchpad / name).read_bytes()
        for name in (
            "findings_inventory.md",
            "finding_records.json",
            "dedup_decisions.md",
            DRIVER.SEMANTIC_DEDUP_APPLIED_RECEIPT,
        )
        if (scratchpad / name).is_file()
    }
    replay = DRIVER._run_l1_semantic_dedup_noop_proposal(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=BASE.RUN_ID,
        reason=reason,
    )
    assert replay.get("safe_to_consume") is True
    assert {
        name: (scratchpad / name).read_bytes()
        for name in before
    } == before, "degraded replay changed its inventory successor or receipt"


def _seed_inventory_only_degrade(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, dict[str, Any], Any, bytes, list[str]]:
    """Create the real committed inventory-only packet-failure successor."""

    scratchpad, config, checkpoint, inventory_raw = (
        BASE._seed_candidate_prep_inventory(project)
    )
    BASE._isolate_candidate_prep(monkeypatch)
    (scratchpad / "dedup_blocks.md").write_bytes(
        b"# Unowned dedup block packet\n\nforeign bytes\n"
    )

    def forbidden_builder(_root: Path) -> int:
        raise AssertionError("unowned packet prestate reached the builder")

    monkeypatch.setattr(
        DRIVER,
        "_compute_dedup_candidate_blocks",
        forbidden_builder,
    )
    issues = DRIVER._prepare_l1_semantic_dedup_inventory(
        scratchpad=scratchpad,
        config=config,
        checkpoint=checkpoint,
    )
    assert issues
    assert DRIVER._l1_prequeue_apply_is_committed(
        scratchpad,
        config=config,
        run_id=BASE.RUN_ID,
    )
    assert (scratchpad / "findings_inventory.md").read_bytes() == inventory_raw
    ledger = read_artifact_ledger(scratchpad)
    decision_binding = ledger["artifact_bindings"][
        "scratchpad:dedup_decisions.md"
    ]
    decision_owner = ledger["work_units"][decision_binding["owner_key"]]
    assert set(decision_owner["input_bindings"]) == {
        "scratchpad:findings_inventory.md"
    }
    return scratchpad, config, checkpoint, inventory_raw, issues


def test_unowned_packet_prestate_degrades_without_model_or_halt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pre-arm conflict is debt plus full passthrough, never a later halt."""

    project = tmp_path / "project"
    scratchpad, config, checkpoint, inventory_raw = (
        BASE._seed_candidate_prep_inventory(project)
    )
    BASE._isolate_candidate_prep(monkeypatch)
    foreign_raw = b"# Unowned dedup block packet\n\nforeign bytes\n"
    (scratchpad / "dedup_blocks.md").write_bytes(foreign_raw)

    def forbidden_builder(_root: Path) -> int:
        raise AssertionError("builder ran despite the unowned packet prestate")

    monkeypatch.setattr(
        DRIVER,
        "_compute_dedup_candidate_blocks",
        forbidden_builder,
    )
    issues = DRIVER._prepare_l1_semantic_dedup_inventory(
        scratchpad=scratchpad,
        config=config,
        checkpoint=checkpoint,
    )
    assert issues
    assert (scratchpad / "findings_inventory.md").read_bytes() == inventory_raw
    assert (scratchpad / "dedup_blocks.md").read_bytes() == foreign_raw
    _assert_visible_packet_debt(scratchpad)
    _assert_model_has_no_packet_authority(scratchpad, config)
    _assert_haltless_inventory_passthrough(
        project=project,
        scratchpad=scratchpad,
        config=config,
        inventory_raw=inventory_raw,
        reason=(
            "dedup pair-packet PhaseIO arm failed; signal enumeration is "
            "unavailable and grants no negative conclusion"
        ),
    )


def test_builder_exception_after_fresh_arm_degrades_without_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A deterministic builder fault is bounded debt, not a pipeline crash."""

    project = tmp_path / "project"
    scratchpad, config, checkpoint, inventory_raw = (
        BASE._seed_candidate_prep_inventory(project)
    )
    BASE._isolate_candidate_prep(monkeypatch)
    calls = 0

    def broken_builder(_root: Path) -> int:
        nonlocal calls
        calls += 1
        unit = read_artifact_ledger(scratchpad)["work_units"][
            BASE._pair_candidate_key()
        ]
        assert unit["semantic_status"] == "INPUTS_BOUND"
        assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
        assert unit["artifacts"] == {}
        raise RuntimeError("fixture-deterministic-pair-builder-failure")

    monkeypatch.setattr(
        DRIVER,
        "_compute_dedup_candidate_blocks",
        broken_builder,
    )
    issues = DRIVER._prepare_l1_semantic_dedup_inventory(
        scratchpad=scratchpad,
        config=config,
        checkpoint=checkpoint,
    )
    assert issues
    assert calls >= 1
    assert (scratchpad / "findings_inventory.md").read_bytes() == inventory_raw
    assert all(not (scratchpad / name).exists() for name in PACKET_NAMES)
    debt = _assert_visible_packet_debt(scratchpad)
    assert b"FIXTURE-DETERMINISTIC-PAIR-BUILDER-FAILURE" in debt.upper()
    _assert_model_has_no_packet_authority(scratchpad, config)
    _assert_haltless_inventory_passthrough(
        project=project,
        scratchpad=scratchpad,
        config=config,
        inventory_raw=inventory_raw,
        reason=(
            "dedup pair-packet deterministic builder failed; signal "
            "enumeration is unavailable and grants no negative conclusion"
        ),
    )


def test_resume_of_partial_input_bound_packet_degrades_once_and_terminates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Partial post-arm bytes are never model-bound or endlessly retried."""

    project = tmp_path / "project"
    scratchpad, config, checkpoint, inventory_raw = (
        BASE._seed_candidate_prep_inventory(project)
    )
    BASE._isolate_candidate_prep(monkeypatch)
    contract, launch = DRIVER._l1_dedup_pair_candidate_contract_and_launch(
        config=config
    )
    armed = record_work_unit_inputs(
        scratchpad,
        project,
        contract,
        launch,
        run_id=BASE.RUN_ID,
    )
    assert armed["semantic_status"] == "INPUTS_BOUND"
    assert armed["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    partial_raw = b"# Partial candidate pairs\n\ntruncated post-arm output"
    (scratchpad / "dedup_candidate_pairs.md").write_bytes(partial_raw)

    calls = 0

    def still_broken_builder(_root: Path) -> int:
        nonlocal calls
        calls += 1
        raise RuntimeError("fixture-resume-builder-still-failing")

    monkeypatch.setattr(
        DRIVER,
        "_compute_dedup_candidate_blocks",
        still_broken_builder,
    )
    issues = DRIVER._prepare_l1_semantic_dedup_inventory(
        scratchpad=scratchpad,
        config=config,
        checkpoint=checkpoint,
    )
    assert issues
    assert calls >= 1
    assert (scratchpad / "findings_inventory.md").read_bytes() == inventory_raw
    assert (
        scratchpad / "dedup_candidate_pairs.md"
    ).read_bytes() == partial_raw
    debt = _assert_visible_packet_debt(scratchpad)
    assert b"FIXTURE-RESUME-BUILDER-STILL-FAILING" in debt.upper()
    _assert_model_has_no_packet_authority(scratchpad, config)
    _assert_haltless_inventory_passthrough(
        project=project,
        scratchpad=scratchpad,
        config=config,
        inventory_raw=inventory_raw,
        reason=(
            "incomplete input-bound dedup pair-packet could not recover; "
            "signal enumeration is unavailable and grants no negative "
            "conclusion"
        ),
    )

    before_debt = _assert_visible_packet_debt(scratchpad)

    def forbidden_retry(_root: Path) -> int:
        raise AssertionError(
            "committed degraded successor retried the incomplete packet"
        )

    monkeypatch.setattr(
        DRIVER,
        "_compute_dedup_candidate_blocks",
        forbidden_retry,
    )
    assert DRIVER._prepare_l1_semantic_dedup_inventory(
        scratchpad=scratchpad,
        config=config,
        checkpoint=checkpoint,
    ) == []
    assert _assert_visible_packet_debt(scratchpad) == before_debt
    assert (scratchpad / "findings_inventory.md").read_bytes() == inventory_raw


def test_valid_looking_partial_block_cannot_fall_through_to_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preparation itself closes a partial packet before main can inspect it."""

    project = tmp_path / "project"
    scratchpad, config, checkpoint, inventory_raw = (
        BASE._seed_candidate_prep_inventory(project)
    )
    BASE._isolate_candidate_prep(monkeypatch)

    def partial_builder(root: Path) -> int:
        (root / "dedup_blocks.md").write_text(
            "# Dedup Candidate Blocks\n\n"
            "## Block 1\n\n"
            "- INV-001\n"
            "- INV-002\n",
            encoding="utf-8",
        )
        raise RuntimeError("fixture-valid-looking-partial-block")

    monkeypatch.setattr(
        DRIVER,
        "_compute_dedup_candidate_blocks",
        partial_builder,
    )
    issues = DRIVER._prepare_l1_semantic_dedup_inventory(
        scratchpad=scratchpad,
        config=config,
        checkpoint=checkpoint,
    )

    assert issues
    assert (scratchpad / "findings_inventory.md").read_bytes() == inventory_raw
    _assert_visible_packet_debt(scratchpad)
    _assert_model_has_no_packet_authority(scratchpad, config)
    assert DRIVER._l1_prequeue_apply_authority_exists(
        scratchpad,
        config=config,
        run_id=BASE.RUN_ID,
    ), (
        "preparation left a valid-looking partial block for main() to route "
        "into the semantic-dedup MODEL instead of closing the degraded "
        "inventory passthrough"
    )
    decisions = (scratchpad / "dedup_decisions.md").read_text(
        encoding="utf-8",
        errors="strict",
    ).upper()
    assert "SIGNAL AUTHORITY**: UNAVAILABLE" in decisions
    assert "NO ABSENCE-OF-DUPLICATES" in decisions


def test_tampered_committed_inventory_only_successor_is_not_phase_skippable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ledger status bits alone cannot bless a changed apply successor."""

    project = tmp_path / "project"
    scratchpad, config, checkpoint, inventory_raw, _issues = (
        _seed_inventory_only_degrade(project, monkeypatch)
    )
    committed_outputs = {
        name: (scratchpad / name).read_bytes()
        for name in BASE.ROOT_OUTPUT_NAMES
    }
    assert set(committed_outputs) == set(BASE.ROOT_OUTPUT_NAMES)

    for name, original in committed_outputs.items():
        target = scratchpad / name
        target.write_bytes(original + b"\nFIXTURE-TAMPERED-SUCCESSOR\n")
        assert not DRIVER._l1_prequeue_apply_is_committed(
            scratchpad,
            config=config,
            run_id=BASE.RUN_ID,
        ), (
            f"{name}: committed status bits remained phase-skippable after "
            "the exact registered successor bytes changed"
        )

        # Preparation deliberately leaves an existing apply transaction to
        # its recovery owner.  Exercise the same authenticated replay that
        # main performs before deciding whether the phase is skippable.
        DRIVER._prepare_l1_semantic_dedup_inventory(
            scratchpad=scratchpad,
            config=config,
            checkpoint=checkpoint,
        )
        try:
            replay = DRIVER._run_l1_prequeue_semantic_dedup_transaction(
                scratchpad=scratchpad,
                project_root=project,
                config=config,
                run_id=BASE.RUN_ID,
            )
        except Exception:
            # Main must convert authenticated replay rejection into a launch
            # veto/incomplete phase rather than falling through to MODEL.
            _assert_main_has_prelaunch_veto_for_unresolved_packet_debt()
            target.write_bytes(original)
            assert DRIVER._l1_prequeue_apply_is_committed(
                scratchpad,
                config=config,
                run_id=BASE.RUN_ID,
            )
        else:
            assert replay.get("safe_to_consume") is True
            assert DRIVER._l1_prequeue_apply_is_committed(
                scratchpad,
                config=config,
                run_id=BASE.RUN_ID,
            )
            assert target.read_bytes() == original, (
                f"{name}: recovery declared the apply committed without "
                "restoring its exact registered bytes"
            )

    assert (scratchpad / "findings_inventory.md").read_bytes() == inventory_raw


def test_failed_inventory_passthrough_vetoes_model_before_partial_packet_bind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failure of both packet and passthrough exits as incomplete debt."""

    project = tmp_path / "project"
    scratchpad, config, checkpoint, inventory_raw = (
        BASE._seed_candidate_prep_inventory(project)
    )
    BASE._isolate_candidate_prep(monkeypatch)
    contract, launch = DRIVER._l1_dedup_pair_candidate_contract_and_launch(
        config=config
    )
    armed = record_work_unit_inputs(
        scratchpad,
        project,
        contract,
        launch,
        run_id=BASE.RUN_ID,
    )
    assert armed["semantic_status"] == "INPUTS_BOUND"
    assert armed["execution_state"] == "INPUTS_BOUND_PREEXECUTION"

    pairs = (
        "# Dedup Candidate Pairs\n\n"
        "| A | B |\n"
        "|---|---|\n"
        "| INV-001 | INV-002 |\n"
    ).encode("utf-8")
    partial_packet = {
        "dedup_blocks.md": (
            "# Dedup Candidate Blocks\n\n"
            "2 finding(s) grouped into 1 block(s).\n\n"
            "## Block 1\n- INV-001\n- INV-002\n"
        ).encode("utf-8"),
        "dedup_candidate_pairs.md": pairs,
        "dedup_candidate_pairs_full.md": pairs,
        "dedup_focus_inventory.md": inventory_raw,
    }
    for name, raw in partial_packet.items():
        (scratchpad / name).write_bytes(raw)

    def broken_resume_builder(_root: Path) -> int:
        raise RuntimeError("fixture-packet-resume-failed-before-commit")

    def broken_passthrough(**_kwargs: Any) -> Mapping[str, Any]:
        raise RuntimeError("fixture-inventory-passthrough-failed")

    monkeypatch.setattr(
        DRIVER,
        "_compute_dedup_candidate_blocks",
        broken_resume_builder,
    )
    monkeypatch.setattr(
        DRIVER,
        "_run_l1_semantic_dedup_noop_proposal",
        broken_passthrough,
    )
    issues = DRIVER._prepare_l1_semantic_dedup_inventory(
        scratchpad=scratchpad,
        config=config,
        checkpoint=checkpoint,
    )
    assert any(
        "FIXTURE-PACKET-RESUME-FAILED-BEFORE-COMMIT" in issue.upper()
        for issue in issues
    )
    assert any(
        "FIXTURE-INVENTORY-PASSTHROUGH-FAILED" in issue.upper()
        for issue in issues
    )
    assert (scratchpad / "findings_inventory.md").read_bytes() == inventory_raw
    assert not DRIVER._l1_prequeue_apply_is_committed(
        scratchpad,
        config=config,
        run_id=BASE.RUN_ID,
    )
    packet_unit = read_artifact_ledger(scratchpad)["work_units"][
        BASE._pair_candidate_key()
    ]
    assert packet_unit["semantic_status"] == "INPUTS_BOUND"
    assert packet_unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert packet_unit["artifacts"] == {}
    assert read_artifact_ledger(scratchpad).get("work_units", {}).get(
        _model_key()
    ) is None, "preparation bound semantic_dedup MODEL despite launch debt"
    debt = _assert_visible_packet_debt(scratchpad)
    assert b"L1_DEDUP_PACKET_DEGRADED_PASSTHROUGH" in debt.upper()
    assert b"FIXTURE-INVENTORY-PASSTHROUGH-FAILED" in debt.upper()

    # This structural boundary is the narrow proof that main consumes the
    # runtime debt before either artifact recovery or the generic model
    # prebind/launch code can inspect the plausible-looking packet.
    _assert_main_has_prelaunch_veto_for_unresolved_packet_debt()
