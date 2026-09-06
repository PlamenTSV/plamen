"""Direct acceptance tests for the isolated B3 context-authority provider."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import chain_tail_authority as CTA
from verify_queue_context_authority import (
    COMMITTED_APPLIED,
    COMMITTED_CLEAN_NOOP,
    COMPLETED_WITH_DEBT_SAFE_BASE,
    capture_verify_queue_context_snapshot,
    select_verify_queue_context,
)


APP = "application_skeptic_proposals.md"
NEG = "candidate_negative_skeptic_proposals.md"
HYP = "hypotheses.md"
MAP = "finding_mapping.md"
GROUP = "chain_grouping_relations.json"
ANTI = "chain_anti_absorption_applied_receipt.json"
EQUIV = "chain_equivalence_proposals.json"
COMPOSE = "chain_composition_verification_candidates.json"
CHAIN_HYP = "chain_hypotheses.md"
CURRENT_GENERATION = (2, 3)
CURRENT_GENERATION_ID = "p0002.s0003"


def _write(root: Path, name: str, body: str | None = None) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if body is None:
        body = "{}\n" if path.suffix == ".json" else f"# {path.stem}\n"
    path.write_text(body, encoding="utf-8")


def _owner(
    suffix: str,
    *,
    pipeline: str = "sc",
    mode: str = "thorough",
    ecosystem: str = "evm",
    backend: str = "claude",
) -> str:
    return f"{pipeline}/{mode}/{ecosystem}/{backend}/{suffix}"


def _ledger(
    root: Path,
    owners: dict[str, str],
    *,
    run_id: str = "run-b3",
) -> dict[str, Any]:
    bindings: dict[str, Any] = {}
    units: dict[str, Any] = {}
    for ordinal, (name, owner_key) in enumerate(sorted(owners.items()), 1):
        raw = (root / name).read_bytes()
        identity = f"scratchpad:{name}"
        digest = hashlib.sha256(raw).hexdigest()
        contract_digest = hashlib.sha256(
            f"contract:{owner_key}".encode("utf-8")
        ).hexdigest()
        record = {
            "identity": identity,
            "owner_key": owner_key,
            "status": "ACTIVE",
            "run_id": run_id,
            "contract_digest": contract_digest,
            "sha256": digest,
            "size": len(raw),
            "writer": "DRIVER" if ordinal % 2 else "MODEL",
        }
        bindings[identity] = dict(record)
        unit = units.setdefault(
            owner_key,
            {
                "work_unit_key": owner_key,
                "run_id": run_id,
                "contract_digest": contract_digest,
                "execution_state": "OUTPUT_COMMITTED",
                "semantic_status": "ACTIVE",
                "artifacts": {},
            },
        )
        unit["artifacts"][identity] = dict(record)
    return {
        "version": 2,
        "artifact_bindings": bindings,
        "work_units": units,
    }


def _select(
    root: Path,
    owners: dict[str, str],
    *,
    pipeline: str = "sc",
    mode: str = "thorough",
    ecosystem: str = "evm",
    backend: str = "claude",
    run_id: str = "run-b3",
):
    snapshot = capture_verify_queue_context_snapshot(
        root, _ledger(root, owners, run_id=run_id)
    )
    return select_verify_queue_context(
        snapshot,
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        run_id=run_id,
    )


def _freeze_generation(
    monkeypatch: pytest.MonkeyPatch,
    generation: Any = CURRENT_GENERATION,
) -> None:
    monkeypatch.setattr(
        CTA,
        "chain_tail_control_generation",
        lambda _root: generation,
    )


def test_l1_policy_excludes_every_sc_chain_artifact(tmp_path: Path) -> None:
    owners = {
        HYP: _owner("chain/canonicalize"),
        MAP: _owner("chain/canonicalize"),
        GROUP: _owner("chain/grouping_relation_repair"),
        ANTI: _owner("chain/grouping_relation_repair"),
        EQUIV: _owner("chain/equivalence_adjudicator"),
        COMPOSE: _owner("chain/state_resolution"),
        CHAIN_HYP: _owner("chain_agent2/model"),
    }
    for name in owners:
        _write(tmp_path, name)

    selection = _select(
        tmp_path,
        owners,
        pipeline="l1",
        ecosystem="rust",
    )

    assert selection.accepted_paths == ()
    assert set(selection.not_applicable_paths) == set(owners)
    assert selection.state == COMMITTED_CLEAN_NOOP
    assert selection.safe_base_routing is True


@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_light_policy_marks_application_skeptic_residue_not_applicable(
    tmp_path: Path,
    backend: str,
) -> None:
    for name in (APP, NEG):
        _write(tmp_path, name)
    owners = {
        APP: _owner(
            "application_skeptic/reconcile",
            mode="core",
            backend=backend,
        ),
        NEG: _owner(
            "application_skeptic/negative.reconcile",
            mode="core",
            backend=backend,
        ),
    }

    selection = _select(
        tmp_path, owners, mode="light", backend=backend
    )

    assert selection.accepted_paths == ()
    assert set(selection.not_applicable_paths) == {APP, NEG}
    assert selection.state == COMMITTED_CLEAN_NOOP


def test_arbitrary_active_owner_is_quarantined_but_base_is_safe(
    tmp_path: Path,
) -> None:
    _write(tmp_path, APP)
    selection = _select(
        tmp_path,
        {APP: _owner("application_skeptic/fake_reconcile")},
    )

    assert selection.accepted_paths == ()
    assert selection.state == COMPLETED_WITH_DEBT_SAFE_BASE
    assert selection.safe_base_routing is True
    assert "OWNER_NOT_ALLOWED" in selection.issues[0].codes


def test_unbound_file_is_never_adopted(tmp_path: Path) -> None:
    _write(tmp_path, APP)
    snapshot = capture_verify_queue_context_snapshot(
        tmp_path, {"artifact_bindings": {}, "work_units": {}}
    )

    selection = select_verify_queue_context(
        snapshot,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        run_id="run-b3",
    )

    assert selection.accepted_paths == ()
    assert "BINDING_MISSING" in selection.issues[0].codes
    assert selection.safe_base_routing is True


def test_chain_equivalence_is_closed_policy_excluded(tmp_path: Path) -> None:
    _write(tmp_path, EQUIV)
    selection = _select(
        tmp_path,
        {EQUIV: _owner("chain/equivalence_adjudicator")},
    )

    assert EQUIV not in selection.accepted_paths
    assert selection.state == COMPLETED_WITH_DEBT_SAFE_BASE
    assert "POLICY_EXCLUDED" in selection.issues[0].codes


@pytest.mark.parametrize("present", ((HYP,), (MAP,)))
def test_hypothesis_mapping_pair_is_atomic(
    tmp_path: Path,
    present: tuple[str, ...],
) -> None:
    for name in present:
        _write(tmp_path, name)
    owners = {name: _owner("chain/canonicalize") for name in present}

    selection = _select(tmp_path, owners)

    assert HYP not in selection.accepted_paths
    assert MAP not in selection.accepted_paths
    assert selection.state == COMPLETED_WITH_DEBT_SAFE_BASE
    assert any("PAIR_INCOMPLETE" in issue.codes for issue in selection.issues)


def test_hypothesis_mapping_pair_accepts_one_exact_owner(tmp_path: Path) -> None:
    for name in (HYP, MAP):
        _write(tmp_path, name)
    owner = _owner("chain/canonicalize")

    selection = _select(tmp_path, {HYP: owner, MAP: owner})

    assert {HYP, MAP}.issubset(selection.accepted_paths)
    assert selection.accepted_paths_for("grouping") == (MAP, HYP)
    assert selection.state == COMMITTED_APPLIED


def test_grouping_pair_rejects_mixed_owner_generation(tmp_path: Path) -> None:
    for name in (GROUP, ANTI):
        _write(tmp_path, name)
    selection = _select(
        tmp_path,
        {
            GROUP: _owner("chain/grouping_relation_repair"),
            ANTI: _owner("chain/grouping_relation_repair.other"),
        },
    )

    assert GROUP not in selection.accepted_paths
    assert ANTI not in selection.accepted_paths
    assert selection.state == COMPLETED_WITH_DEBT_SAFE_BASE


@pytest.mark.parametrize(
    ("mode", "suffix"),
    (
        ("light", "chain/state_resolution"),
        ("core", "chain/state_resolution"),
    ),
)
def test_composition_candidates_accept_only_mode_valid_final_producers(
    tmp_path: Path,
    mode: str,
    suffix: str,
) -> None:
    _write(tmp_path, COMPOSE)
    selection = _select(
        tmp_path,
        {COMPOSE: _owner(suffix, mode=mode)},
        mode=mode,
    )

    assert selection.accepted_paths_for("compound") == (COMPOSE,)
    assert selection.state == COMMITTED_APPLIED


def test_thorough_composition_candidates_require_exact_current_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _freeze_generation(monkeypatch)
    _write(tmp_path, COMPOSE)

    selection = _select(
        tmp_path,
        {
            COMPOSE: _owner(
                f"chain_iter2/tail_reconcile.{CURRENT_GENERATION_ID}"
            )
        },
    )

    assert selection.accepted_paths_for("compound") == (COMPOSE,)
    assert selection.state == COMMITTED_APPLIED


@pytest.mark.parametrize(
    "owner_key",
    (
        _owner("chain_iter2/tail_reconcile.p0001.s0003"),
        _owner("chain_iter2/tail_reconcile.p0002.s0002"),
        _owner("chain_iter2/tail_reconcile"),
        _owner("chain_iter2/tail_reconcile.p2.s0003"),
        "evil/sc/thorough/evm/claude/"
        "chain_iter2/tail_reconcile.p0002.s0003",
        "sc/thorough/evm/claude/extra/"
        "chain_iter2/tail_reconcile.p0002.s0003",
        "xsc/thorough/evm/claude/"
        "chain_iter2/tail_reconcile.p0002.s0003",
    ),
)
def test_thorough_composition_candidates_reject_noncurrent_or_lookalike_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    owner_key: str,
) -> None:
    _freeze_generation(monkeypatch)
    _write(tmp_path, COMPOSE)

    selection = _select(tmp_path, {COMPOSE: owner_key})

    assert COMPOSE not in selection.accepted_paths
    assert any(
        "OWNER_NOT_ALLOWED" in issue.codes
        for issue in selection.issues
        if issue.artifact == COMPOSE
    )


@pytest.mark.parametrize(
    "generation",
    (
        (True, 3),
        (2, False),
        (-1, 3),
        (2, 10000),
        ("2", 3),
        (2,),
    ),
)
def test_thorough_generation_authority_rejects_malformed_components(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    generation: Any,
) -> None:
    _freeze_generation(monkeypatch, generation)
    _write(tmp_path, COMPOSE)
    selection = _select(
        tmp_path,
        {
            COMPOSE: _owner(
                f"chain_iter2/tail_reconcile.{CURRENT_GENERATION_ID}"
            )
        },
    )

    assert COMPOSE not in selection.accepted_paths
    assert any(
        "GENERATION_AUTHORITY_INVALID" in issue.codes
        for issue in selection.issues
        if issue.artifact == COMPOSE
    )


def test_core_rejects_thorough_tail_reconcile_owner(tmp_path: Path) -> None:
    _write(tmp_path, COMPOSE)
    selection = _select(
        tmp_path,
        {COMPOSE: _owner("chain_iter2/tail_reconcile", mode="core")},
        mode="core",
    )

    assert COMPOSE not in selection.accepted_paths
    assert "OWNER_NOT_ALLOWED" in selection.issues[0].codes


def test_chain_hypotheses_is_exposed_only_to_actual_sc_children(
    tmp_path: Path,
) -> None:
    _write(tmp_path, CHAIN_HYP)
    selection = _select(
        tmp_path,
        {
            CHAIN_HYP: _owner(
                "chain_agent2/model",
                mode="core",
            )
        },
        mode="core",
    )

    assert selection.accepted_paths_for("compound") == (CHAIN_HYP,)
    assert selection.accepted_paths_for("grouping") == (CHAIN_HYP,)
    assert selection.accepted_paths_for("mandatory_reverification") == ()
    assert selection.accepted_paths_for("routing") == ()


def test_thorough_chain_hypotheses_require_current_driver_merge_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _freeze_generation(monkeypatch)
    _write(tmp_path, CHAIN_HYP)
    selection = _select(
        tmp_path,
        {
            CHAIN_HYP: _owner(
                f"chain_iter2/driver_merge.{CURRENT_GENERATION_ID}"
            )
        },
    )

    assert selection.accepted_paths_for("compound") == (CHAIN_HYP,)
    assert selection.accepted_paths_for("grouping") == (CHAIN_HYP,)


@pytest.mark.parametrize(
    "owner_key",
    (
        _owner("chain_iter2/driver_merge.p0001.s0003"),
        _owner("chain_iter2/driver_merge.p0002.s0002"),
        _owner("chain_iter2/driver_merge"),
        _owner("chain_iter2/driver_merge.p0002.s3"),
        "evil/sc/thorough/evm/claude/"
        "chain_iter2/driver_merge.p0002.s0003",
        "sc/thorough/evm/claude/extra/"
        "chain_iter2/driver_merge.p0002.s0003",
        "xsc/thorough/evm/claude/"
        "chain_iter2/driver_merge.p0002.s0003",
    ),
)
def test_thorough_chain_hypotheses_reject_noncurrent_or_lookalike_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    owner_key: str,
) -> None:
    _freeze_generation(monkeypatch)
    _write(tmp_path, CHAIN_HYP)
    selection = _select(tmp_path, {CHAIN_HYP: owner_key})

    assert CHAIN_HYP not in selection.accepted_paths
    assert any(
        "OWNER_NOT_ALLOWED" in issue.codes
        for issue in selection.issues
        if issue.artifact == CHAIN_HYP
    )


@pytest.mark.parametrize(
    ("target", "value", "code"),
    (
        ("binding.identity", "scratchpad:not-the-artifact.md", "IDENTITY_MISMATCH"),
        ("binding.status", "QUARANTINED", "BINDING_NOT_ACTIVE"),
        ("binding.run_id", "old-run", "RUN_MISMATCH"),
        ("binding.contract_digest", "f" * 64, "CONTRACT_DIGEST_MISMATCH"),
        ("binding.size", 999, "SIZE_MISMATCH"),
        ("binding.sha256", "f" * 64, "HASH_MISMATCH"),
        ("unit.execution_state", "PREPARED", "OWNER_NOT_COMMITTED"),
        ("unit.semantic_status", "QUARANTINED", "OWNER_NOT_ACTIVE"),
        ("unit.run_id", "old-run", "RUN_MISMATCH"),
        ("unit.contract_digest", "not-a-digest", "CONTRACT_DIGEST_INVALID"),
        ("unit.contract_digest", "e" * 64, "CONTRACT_DIGEST_MISMATCH"),
        ("artifact.identity", "scratchpad:not-the-artifact.md", "IDENTITY_MISMATCH"),
        ("artifact.owner_key", "sc/thorough/evm/claude/foreign", "OWNER_KEY_MISMATCH"),
        ("artifact.status", "QUARANTINED", "OWNER_ARTIFACT_NOT_ACTIVE"),
        ("artifact.run_id", "old-run", "RUN_MISMATCH"),
        ("artifact.contract_digest", "d" * 64, "CONTRACT_DIGEST_MISMATCH"),
        ("artifact.size", 998, "SIZE_MISMATCH"),
        ("artifact.sha256", "d" * 64, "HASH_MISMATCH"),
    ),
)
def test_exact_receipt_checks_reject_drift(
    tmp_path: Path,
    target: str,
    value: Any,
    code: str,
) -> None:
    _write(tmp_path, APP)
    owner = _owner("application_skeptic/reconcile")
    ledger = _ledger(tmp_path, {APP: owner})
    identity = f"scratchpad:{APP}"
    scope, field = target.split(".", 1)
    if scope == "binding":
        ledger["artifact_bindings"][identity][field] = value
    elif scope == "artifact":
        ledger["work_units"][owner]["artifacts"][identity][field] = value
    else:
        ledger["work_units"][owner][field] = value
    snapshot = capture_verify_queue_context_snapshot(tmp_path, ledger)

    selection = select_verify_queue_context(
        snapshot,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        run_id="run-b3",
    )

    assert APP not in selection.accepted_paths
    assert any(code in issue.codes for issue in selection.issues)
    assert selection.safe_base_routing is True


@pytest.mark.parametrize(
    ("pipeline", "mode", "ecosystem", "backend"),
    (
        ("l1", "thorough", "evm", "claude"),
        ("sc", "core", "evm", "claude"),
        ("sc", "thorough", "rust", "claude"),
        ("sc", "thorough", "evm", "codex"),
    ),
)
def test_owner_prefix_must_match_exact_runtime_dimensions(
    tmp_path: Path,
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
) -> None:
    _write(tmp_path, APP)
    selection = _select(
        tmp_path,
        {APP: _owner("application_skeptic/reconcile")},
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
    )

    assert APP not in selection.accepted_paths


def test_snapshot_is_immutable_and_selection_never_rereads_disk(
    tmp_path: Path,
) -> None:
    _write(tmp_path, APP, "# original\n")
    owner = _owner("application_skeptic/reconcile")
    ledger = _ledger(tmp_path, {APP: owner})
    snapshot = capture_verify_queue_context_snapshot(tmp_path, ledger)
    (tmp_path / APP).write_text("# changed later\n", encoding="utf-8")
    ledger["artifact_bindings"][f"scratchpad:{APP}"]["status"] = "QUARANTINED"

    frozen = select_verify_queue_context(
        snapshot,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        run_id="run-b3",
    )
    refreshed = select_verify_queue_context(
        capture_verify_queue_context_snapshot(tmp_path, ledger),
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        run_id="run-b3",
    )

    assert APP in frozen.accepted_paths
    assert APP not in refreshed.accepted_paths


def test_status_payload_is_deterministic_always_present_and_proofless(
    tmp_path: Path,
) -> None:
    selection = select_verify_queue_context(
        capture_verify_queue_context_snapshot(
            tmp_path, {"artifact_bindings": {}, "work_units": {}}
        ),
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        run_id="run-b3",
    )

    first = selection.status_payload()
    second = selection.status_payload()

    assert first == second
    assert first["state"] == COMMITTED_CLEAN_NOOP
    assert first["proof_authority"] == "NONE"
    assert first["safe_base_routing"] is True
    assert len(first["receipt_digest"]) == 64
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_provider_never_mutates_supplied_root(tmp_path: Path) -> None:
    _write(tmp_path, APP)
    owner = _owner("application_skeptic/reconcile")
    ledger = _ledger(tmp_path, {APP: owner})
    before = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }

    selection = select_verify_queue_context(
        capture_verify_queue_context_snapshot(tmp_path, ledger),
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        run_id="run-b3",
    )
    selection.status_payload()
    after = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }

    assert after == before
