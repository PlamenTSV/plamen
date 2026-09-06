"""B3 red fixtures for verify-queue optional-context ownership.

These tests describe the production boundary, not the permissive legacy
behavior.  Optional context may improve grouping or restore additive work, but
it must never enter a queue merely because bytes exist or because an arbitrary
work unit labelled them ACTIVE.

The file is intentionally isolated from the implementation so the ownership
cutover can be developed fixture-first.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import chain_tail_authority as CTA
import plamen_driver as D
import plamen_parsers as P


_SC_CHAIN_CONTEXT = (
    "hypotheses.md",
    "finding_mapping.md",
    "chain_grouping_relations.json",
    "chain_anti_absorption_applied_receipt.json",
    "chain_equivalence_proposals.json",
    "chain_composition_verification_candidates.json",
    "chain_hypotheses.md",
)

_APP_CONTEXT = (
    "application_skeptic_proposals.md",
    "candidate_negative_skeptic_proposals.md",
)


def _config(
    root: Path,
    *,
    pipeline: str = "sc",
    mode: str = "thorough",
    backend: str = "claude",
    run_id: str = "b3-current-run",
) -> dict[str, Any]:
    config = {
        "pipeline": pipeline,
        "mode": mode,
        "language": "evm" if pipeline == "sc" else "rust",
        "cli_backend": backend,
        "project_root": str(root.parent),
        "scratchpad": str(root),
        "_run_id": run_id,
    }
    (root / "config.json").write_text(
        json.dumps(config, sort_keys=True),
        encoding="utf-8",
    )
    return config


def _freeze_generation(
    monkeypatch: pytest.MonkeyPatch,
    generation: tuple[int, int] = (2, 3),
) -> None:
    monkeypatch.setattr(
        CTA,
        "chain_tail_control_generation",
        lambda _root: generation,
    )


def _write_context(root: Path, relative: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix == ".json":
        path.write_text("{}\n", encoding="utf-8")
    else:
        path.write_text(f"# {path.stem}\n", encoding="utf-8")


def _active_ledger(
    root: Path,
    *,
    run_id: str,
    owners: dict[str, str],
) -> dict[str, Any]:
    bindings: dict[str, Any] = {}
    units: dict[str, Any] = {}
    for relative, owner_key in owners.items():
        path = root / relative
        raw = path.read_bytes()
        identity = f"scratchpad:{relative}"
        artifact = {
            "identity": identity,
            "owner_key": owner_key,
            "status": "ACTIVE",
            "writer": "DRIVER",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
            "run_id": run_id,
            "contract_digest": "0" * 64,
        }
        bindings[identity] = dict(artifact)
        unit = units.setdefault(
            owner_key,
            {
                "work_unit_key": owner_key,
                "execution_state": "OUTPUT_COMMITTED",
                "semantic_status": "ACTIVE",
                "run_id": run_id,
                "contract_digest": "0" * 64,
                "artifacts": {},
            },
        )
        unit["artifacts"][identity] = dict(artifact)
    return {
        "version": 2,
        "artifact_bindings": bindings,
        "work_units": units,
    }


def _install_ledger(
    monkeypatch: pytest.MonkeyPatch,
    root: Path,
    *,
    run_id: str,
    owners: dict[str, str],
) -> dict[str, Any]:
    ledger = _active_ledger(root, run_id=run_id, owners=owners)
    monkeypatch.setattr(D, "read_artifact_ledger", lambda _root: ledger)
    return ledger


def _terminal_parser_ledger(
    root: Path,
    *,
    semantic_ledger: dict[str, Any],
    owner_key: str = (
        "sc/thorough/evm/claude/chain_iter2/"
        "tail_reconcile.p0002.s0003"
    ),
    snapshot_key: str = (
        "sc/thorough/evm/claude/chain_iter2/"
        "tail_snapshot.p0002.s0003"
    ),
) -> dict[str, Any]:
    """Build the exact two-producer ancestry consumed by the R10 parser."""

    run_id = "b3-parser-current-g"
    source_name = "chain_composition_verification_candidates.json"
    snapshot_name = "chain_tail_terminal_snapshot.json"
    source_path = root / source_name
    snapshot_path = root / snapshot_name
    _write_context(root, source_name)
    snapshot = {
        "schema_version": "plamen.chain_tail.terminal_snapshot.v2",
        "terminal_generation": {
            "pass_index": 2,
            "shard_count": 3,
            "generation_id": "p0002.s0003",
        },
        "semantic_ledger": semantic_ledger,
    }
    snapshot["snapshot_sha256"] = CTA._digest(
        snapshot,
        "snapshot_sha256",
    )
    snapshot_path.write_text(
        json.dumps(snapshot, sort_keys=True),
        encoding="utf-8",
    )
    source_identity = f"scratchpad:{source_name}"
    snapshot_identity = f"scratchpad:{snapshot_name}"
    final_contract = "1" * 64
    snapshot_contract = "2" * 64
    snapshot_launch = "3" * 64
    snapshot_commit = "4" * 64
    source_raw = source_path.read_bytes()
    snapshot_raw = snapshot_path.read_bytes()
    source_record = {
        "identity": source_identity,
        "owner_key": owner_key,
        "status": "ACTIVE",
        "writer": "DRIVER",
        "sha256": hashlib.sha256(source_raw).hexdigest(),
        "size": len(source_raw),
        "run_id": run_id,
        "contract_digest": final_contract,
    }
    snapshot_record = {
        "identity": snapshot_identity,
        "owner_key": snapshot_key,
        "status": "ACTIVE",
        "writer": "DRIVER",
        "sha256": hashlib.sha256(snapshot_raw).hexdigest(),
        "size": len(snapshot_raw),
        "run_id": run_id,
        "contract_digest": snapshot_contract,
    }
    return {
        "version": 2,
        "artifact_bindings": {
            source_identity: dict(source_record),
            snapshot_identity: dict(snapshot_record),
        },
        "work_units": {
            owner_key: {
                "work_unit_key": owner_key,
                "execution_state": "OUTPUT_COMMITTED",
                "semantic_status": "ACTIVE",
                "run_id": run_id,
                "contract_digest": final_contract,
                "artifacts": {
                    source_identity: dict(source_record),
                },
                "input_bindings": {
                    snapshot_identity: {
                        "identity": snapshot_identity,
                        "status": "ACTIVE",
                        "sha256": snapshot_record["sha256"],
                        "size": snapshot_record["size"],
                        "producer_work_unit_key": snapshot_key,
                        "producer_run_id": run_id,
                        "producer_writer": "DRIVER",
                        "producer_contract_digest": snapshot_contract,
                        "producer_launch_digest": snapshot_launch,
                        "producer_commit_receipt_digest": snapshot_commit,
                    },
                },
            },
            snapshot_key: {
                "work_unit_key": snapshot_key,
                "execution_state": "OUTPUT_COMMITTED",
                "semantic_status": "ACTIVE",
                "run_id": run_id,
                "contract_digest": snapshot_contract,
                "launch_digest": snapshot_launch,
                "commit_authority": {
                    "receipt_digest": snapshot_commit,
                },
                "artifacts": {
                    snapshot_identity: dict(snapshot_record),
                },
            },
        },
    }


def test_l1_never_consumes_sc_chain_optional_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even valid-looking same-run SC owners are outside the L1 denominator."""

    for relative in _SC_CHAIN_CONTEXT:
        _write_context(tmp_path, relative)
    run_id = "b3-l1-run"
    owners = {
        "hypotheses.md": (
            "sc/thorough/evm/claude/chain/canonicalize"
        ),
        "finding_mapping.md": (
            "sc/thorough/evm/claude/chain/canonicalize"
        ),
        "chain_grouping_relations.json": (
            "sc/thorough/evm/claude/chain/grouping_relation_repair"
        ),
        "chain_anti_absorption_applied_receipt.json": (
            "sc/thorough/evm/claude/chain/grouping_relation_repair"
        ),
        "chain_equivalence_proposals.json": (
            "sc/thorough/evm/claude/chain/equivalence_adjudicator"
        ),
        "chain_composition_verification_candidates.json": (
            "sc/thorough/evm/claude/chain/state_resolution"
        ),
        "chain_hypotheses.md": (
            "sc/thorough/evm/claude/chain_agent2/model"
        ),
    }
    _install_ledger(
        monkeypatch, tmp_path, run_id=run_id, owners=owners
    )

    included, _issues = D._resolve_verify_queue_optional_context_inputs(
        tmp_path,
        _config(tmp_path, pipeline="l1", run_id=run_id),
    )

    assert included.isdisjoint(_SC_CHAIN_CONTEXT)


@pytest.mark.parametrize("backend", ("claude", "codex"))
def test_light_mode_rejects_application_skeptic_residue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
) -> None:
    """The application-skeptic phase is not a producer in light mode."""

    for relative in _APP_CONTEXT:
        _write_context(tmp_path, relative)
    run_id = f"b3-light-{backend}"
    owners = {
        "application_skeptic_proposals.md": (
            f"sc/core/evm/{backend}/application_skeptic/reconcile"
        ),
        "candidate_negative_skeptic_proposals.md": (
            f"sc/core/evm/{backend}/application_skeptic/negative.reconcile"
        ),
    }
    _install_ledger(
        monkeypatch, tmp_path, run_id=run_id, owners=owners
    )

    included, _issues = D._resolve_verify_queue_optional_context_inputs(
        tmp_path,
        _config(
            tmp_path,
            pipeline="sc",
            mode="light",
            backend=backend,
            run_id=run_id,
        ),
    )

    assert included.isdisjoint(_APP_CONTEXT)


def test_arbitrary_same_run_active_owner_is_not_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    relative = "application_skeptic_proposals.md"
    _write_context(tmp_path, relative)
    run_id = "b3-arbitrary-owner"
    _install_ledger(
        monkeypatch,
        tmp_path,
        run_id=run_id,
        owners={
            relative: (
                "sc/thorough/evm/claude/application_skeptic/fake_reconcile"
            )
        },
    )

    included, _issues = D._resolve_verify_queue_optional_context_inputs(
        tmp_path, _config(tmp_path, run_id=run_id)
    )

    assert relative not in included


def test_chain_equivalence_proposals_is_never_production_consumable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No live producer exists; test helpers must not create production authority."""

    relative = "chain_equivalence_proposals.json"
    _write_context(tmp_path, relative)
    run_id = "b3-orphan-equivalence"
    _install_ledger(
        monkeypatch,
        tmp_path,
        run_id=run_id,
        owners={
            relative: (
                "sc/thorough/evm/claude/chain/equivalence_adjudicator"
            )
        },
    )

    included, _issues = D._resolve_verify_queue_optional_context_inputs(
        tmp_path, _config(tmp_path, run_id=run_id)
    )

    assert relative not in included


@pytest.mark.parametrize("relative", ("hypotheses.md", "finding_mapping.md"))
def test_hypotheses_and_mapping_cannot_be_adopted_independently(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
) -> None:
    """The semantic table and constituent map are one atomic source family."""

    _write_context(tmp_path, relative)
    run_id = f"b3-unpaired-{Path(relative).stem}"
    _install_ledger(
        monkeypatch,
        tmp_path,
        run_id=run_id,
        owners={
            relative: "sc/thorough/evm/claude/chain/canonicalize"
        },
    )

    included, _issues = D._resolve_verify_queue_optional_context_inputs(
        tmp_path, _config(tmp_path, run_id=run_id)
    )

    assert relative not in included


def test_core_composition_candidates_accept_state_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    relative = "chain_composition_verification_candidates.json"
    _write_context(tmp_path, relative)
    run_id = "b3-composition-allowed"
    _install_ledger(
        monkeypatch,
        tmp_path,
        run_id=run_id,
        owners={
            relative: "sc/core/evm/claude/chain/state_resolution"
        },
    )

    included, _issues = D._resolve_verify_queue_optional_context_inputs(
        tmp_path,
        _config(tmp_path, mode="core", run_id=run_id),
    )

    assert relative in included


def test_thorough_composition_candidates_accept_only_current_reconcile_g(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    relative = "chain_composition_verification_candidates.json"
    _write_context(tmp_path, relative)
    _freeze_generation(monkeypatch)
    run_id = "b3-composition-current-g"
    _install_ledger(
        monkeypatch,
        tmp_path,
        run_id=run_id,
        owners={
            relative: (
                "sc/thorough/evm/claude/chain_iter2/"
                "tail_reconcile.p0002.s0003"
            )
        },
    )

    included, issues = D._resolve_verify_queue_optional_context_inputs(
        tmp_path,
        _config(tmp_path, run_id=run_id),
    )

    assert relative in included
    assert issues == []


@pytest.mark.parametrize(
    "owner_key",
    (
        "sc/thorough/evm/claude/chain_iter2/"
        "tail_reconcile.p0001.s0003",
        "sc/thorough/evm/claude/chain_iter2/"
        "tail_reconcile.p0002.s0002",
        "sc/thorough/evm/claude/chain_iter2/tail_reconcile",
        "sc/thorough/evm/claude/chain_iter2/"
        "tail_reconcile.p2.s0003",
        "evil/sc/thorough/evm/claude/chain_iter2/"
        "tail_reconcile.p0002.s0003",
        "sc/thorough/evm/claude/extra/chain_iter2/"
        "tail_reconcile.p0002.s0003",
    ),
)
def test_thorough_composition_candidates_reject_wrong_or_lookalike_g(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    owner_key: str,
) -> None:
    relative = "chain_composition_verification_candidates.json"
    _write_context(tmp_path, relative)
    _freeze_generation(monkeypatch)
    run_id = "b3-composition-wrong-g"
    _install_ledger(
        monkeypatch,
        tmp_path,
        run_id=run_id,
        owners={relative: owner_key},
    )

    included, issues = D._resolve_verify_queue_optional_context_inputs(
        tmp_path,
        _config(tmp_path, run_id=run_id),
    )

    assert relative not in included
    assert any("OWNER_NOT_ALLOWED" in issue for issue in issues)


def test_composition_candidates_reject_other_active_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    relative = "chain_composition_verification_candidates.json"
    _write_context(tmp_path, relative)
    run_id = "b3-composition-fake"
    _install_ledger(
        monkeypatch,
        tmp_path,
        run_id=run_id,
        owners={
            relative: "sc/thorough/evm/claude/chain/fake_composition"
        },
    )

    included, _issues = D._resolve_verify_queue_optional_context_inputs(
        tmp_path, _config(tmp_path, run_id=run_id)
    )

    assert relative not in included


def test_chain_hypotheses_is_bound_when_queue_compound_context_can_read_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The markdown fallback must be in the transaction denominator."""

    relative = "chain_hypotheses.md"
    _write_context(tmp_path, relative)
    run_id = "b3-chain-hypotheses"
    _install_ledger(
        monkeypatch,
        tmp_path,
        run_id=run_id,
        owners={
            relative: "sc/core/evm/claude/chain_agent2/model"
        },
    )
    contract, _launch = D._typed_verify_queue_routing_contract_and_launch(
        "sc_verify_queue",
        tmp_path,
        _config(tmp_path, mode="core", run_id=run_id),
    )

    assert f"scratchpad:{relative}" in set(contract.immutable_inputs)


def test_thorough_chain_hypotheses_bind_only_current_driver_merge_g(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    relative = "chain_hypotheses.md"
    _write_context(tmp_path, relative)
    _freeze_generation(monkeypatch)
    run_id = "b3-chain-hypotheses-current-g"
    _install_ledger(
        monkeypatch,
        tmp_path,
        run_id=run_id,
        owners={
            relative: (
                "sc/thorough/evm/claude/chain_iter2/"
                "driver_merge.p0002.s0003"
            )
        },
    )

    included, issues = D._resolve_verify_queue_optional_context_inputs(
        tmp_path,
        _config(tmp_path, run_id=run_id),
    )

    assert relative in included
    assert issues == []


@pytest.mark.parametrize(
    "owner_key",
    (
        "sc/thorough/evm/claude/chain_iter2/"
        "driver_merge.p0001.s0003",
        "sc/thorough/evm/claude/chain_iter2/"
        "driver_merge.p0002.s0002",
        "sc/thorough/evm/claude/chain_iter2/driver_merge",
        "sc/thorough/evm/claude/chain_iter2/"
        "driver_merge.p0002.s3",
        "evil/sc/thorough/evm/claude/chain_iter2/"
        "driver_merge.p0002.s0003",
        "sc/thorough/evm/claude/extra/chain_iter2/"
        "driver_merge.p0002.s0003",
    ),
)
def test_thorough_chain_hypotheses_reject_wrong_or_lookalike_g(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    owner_key: str,
) -> None:
    relative = "chain_hypotheses.md"
    _write_context(tmp_path, relative)
    _freeze_generation(monkeypatch)
    run_id = "b3-chain-hypotheses-wrong-g"
    _install_ledger(
        monkeypatch,
        tmp_path,
        run_id=run_id,
        owners={relative: owner_key},
    )

    included, issues = D._resolve_verify_queue_optional_context_inputs(
        tmp_path,
        _config(tmp_path, run_id=run_id),
    )

    assert relative not in included
    assert any("OWNER_NOT_ALLOWED" in issue for issue in issues)


def test_chain_hypotheses_digest_drift_is_rejected_by_compound_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hidden markdown read cannot bypass its committed producer binding."""

    relative = "chain_hypotheses.md"
    _write_context(tmp_path, relative)
    run_id = "b3-chain-hypotheses-drift"
    ledger = _active_ledger(
        tmp_path,
        run_id=run_id,
        owners={
            relative: "sc/core/evm/claude/chain_agent2/model"
        },
    )
    binding = ledger["artifact_bindings"][f"scratchpad:{relative}"]
    binding["sha256"] = "f" * 64
    monkeypatch.setattr(P, "read_artifact_ledger", lambda _root: ledger)
    _config(tmp_path, mode="core", run_id=run_id)

    with pytest.raises(ValueError, match="producer|authority|binding|digest"):
        P._write_or_validate_compound_adapter_artifacts(
            tmp_path, (), "sc", mode="core"
        )


@pytest.mark.parametrize(
    "owner_key",
    (
        "sc/thorough/evm/claude/chain_iter2/tail_reconcile",
        "sc/thorough/evm/claude/chain_iter2/"
        "tail_reconcile.p0001.s0003",
        "evil/sc/thorough/evm/claude/chain_iter2/"
        "tail_reconcile.p0002.s0003",
        "sc/thorough/evm/claude/extra/chain_iter2/"
        "tail_reconcile.p0002.s0003",
        "xsc/thorough/evm/claude/chain_iter2/"
        "tail_reconcile.p0002.s0003",
    ),
)
def test_compound_parser_rejects_fixed_prior_or_prefix_lookalike_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    owner_key: str,
) -> None:
    semantic = {
        "schema_version": CTA.LEDGER_SCHEMA,
        "pass_index": 2,
        "shards": [{}, {}, {}],
        "pairs": [],
    }
    semantic["ledger_sha256"] = CTA._digest(
        semantic,
        "ledger_sha256",
    )
    (tmp_path / "chain_tail_disposition_ledger.json").write_text(
        json.dumps(semantic, sort_keys=True),
        encoding="utf-8",
    )
    ledger = _terminal_parser_ledger(
        tmp_path,
        semantic_ledger=semantic,
        owner_key=owner_key,
    )
    monkeypatch.setattr(P, "read_artifact_ledger", lambda _root: ledger)
    _freeze_generation(monkeypatch)
    monkeypatch.setattr(
        CTA,
        "_load_manifest_ledger",
        lambda _root: ({}, semantic),
    )
    rule = P._COMPOUND_FINAL_AUTHORITY_BY_PIPELINE_MODE[
        ("SC", "thorough")
    ]

    with pytest.raises(ValueError, match="authority|ancestry|binding|digest"):
        P._read_committed_compound_final_authority(
            tmp_path,
            rule,
            expected_owner_prefix="sc/thorough/evm/claude/",
        )


def test_compound_parser_accepts_exact_current_reconcile_snapshot_join(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    semantic = {
        "schema_version": CTA.LEDGER_SCHEMA,
        "pass_index": 2,
        "shards": [{}, {}, {}],
        "pairs": [],
    }
    semantic["ledger_sha256"] = CTA._digest(
        semantic,
        "ledger_sha256",
    )
    (tmp_path / "chain_tail_disposition_ledger.json").write_text(
        json.dumps(semantic, sort_keys=True),
        encoding="utf-8",
    )
    ledger = _terminal_parser_ledger(
        tmp_path,
        semantic_ledger=semantic,
    )
    monkeypatch.setattr(P, "read_artifact_ledger", lambda _root: ledger)
    _freeze_generation(monkeypatch)
    monkeypatch.setattr(
        CTA,
        "_load_manifest_ledger",
        lambda _root: ({}, semantic),
    )
    rule = P._COMPOUND_FINAL_AUTHORITY_BY_PIPELINE_MODE[
        ("SC", "thorough")
    ]

    raw = P._read_committed_compound_final_authority(
        tmp_path,
        rule,
        expected_owner_prefix="sc/thorough/evm/claude/",
    )

    assert raw == (
        tmp_path / "chain_composition_verification_candidates.json"
    ).read_bytes()


@pytest.mark.parametrize(
    "snapshot_key",
    (
        "sc/thorough/evm/claude/chain_iter2/tail_snapshot",
        "sc/thorough/evm/claude/chain_iter2/"
        "tail_snapshot.p0001.s0003",
        "evil/sc/thorough/evm/claude/chain_iter2/"
        "tail_snapshot.p0002.s0003",
        "sc/thorough/evm/claude/extra/chain_iter2/"
        "tail_snapshot.p0002.s0003",
    ),
)
def test_compound_parser_rejects_noncurrent_or_lookalike_snapshot_producer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    snapshot_key: str,
) -> None:
    semantic = {
        "schema_version": CTA.LEDGER_SCHEMA,
        "pass_index": 2,
        "shards": [{}, {}, {}],
        "pairs": [],
    }
    semantic["ledger_sha256"] = CTA._digest(
        semantic,
        "ledger_sha256",
    )
    (tmp_path / "chain_tail_disposition_ledger.json").write_text(
        json.dumps(semantic, sort_keys=True),
        encoding="utf-8",
    )
    ledger = _terminal_parser_ledger(
        tmp_path,
        semantic_ledger=semantic,
        snapshot_key=snapshot_key,
    )
    monkeypatch.setattr(P, "read_artifact_ledger", lambda _root: ledger)
    _freeze_generation(monkeypatch)
    monkeypatch.setattr(
        CTA,
        "_load_manifest_ledger",
        lambda _root: ({}, semantic),
    )
    rule = P._COMPOUND_FINAL_AUTHORITY_BY_PIPELINE_MODE[
        ("SC", "thorough")
    ]

    with pytest.raises(ValueError, match="authority|ancestry|binding|digest"):
        P._read_committed_compound_final_authority(
            tmp_path,
            rule,
            expected_owner_prefix="sc/thorough/evm/claude/",
        )


def test_compound_parser_rejects_rebound_snapshot_semantic_drift_at_same_g(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root_semantic = {
        "schema_version": CTA.LEDGER_SCHEMA,
        "pass_index": 2,
        "shards": [{}, {}, {}],
        "pairs": [{"pair_id": "PAIR-ROOT", "evidence": "original"}],
    }
    root_semantic["ledger_sha256"] = CTA._digest(
        root_semantic,
        "ledger_sha256",
    )
    mutated_semantic = json.loads(json.dumps(root_semantic))
    mutated_semantic["pairs"][0]["evidence"] = (
        "mutated while preserving P/S"
    )
    mutated_semantic["ledger_sha256"] = CTA._digest(
        mutated_semantic,
        "ledger_sha256",
    )
    (tmp_path / "chain_tail_disposition_ledger.json").write_text(
        json.dumps(root_semantic, sort_keys=True),
        encoding="utf-8",
    )
    ledger = _terminal_parser_ledger(
        tmp_path,
        semantic_ledger=mutated_semantic,
    )
    monkeypatch.setattr(P, "read_artifact_ledger", lambda _root: ledger)
    _freeze_generation(monkeypatch)
    monkeypatch.setattr(
        CTA,
        "_load_manifest_ledger",
        lambda _root: ({}, root_semantic),
    )
    rule = P._COMPOUND_FINAL_AUTHORITY_BY_PIPELINE_MODE[
        ("SC", "thorough")
    ]

    with pytest.raises(ValueError, match="authority|ancestry|binding|digest"):
        P._read_committed_compound_final_authority(
            tmp_path,
            rule,
            expected_owner_prefix="sc/thorough/evm/claude/",
        )


def test_optional_selection_is_resolved_once_and_frozen_for_arm(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Contract construction must not perform a second filesystem selection."""

    calls = 0

    def _select(_root: Path, _config: dict[str, Any]):
        nonlocal calls
        calls += 1
        return (
            {"hypotheses.md"} if calls == 1 else set(),
            [],
        )

    monkeypatch.setattr(
        D, "_resolve_verify_queue_optional_context_inputs", _select
    )
    monkeypatch.setattr(
        D,
        "_validate_registered_finding_delivery_receipt",
        lambda _root, **_kwargs: [],
    )
    monkeypatch.setattr(
        D,
        "_arm_deterministic_driver_work_unit",
        lambda **_kwargs: (True, []),
    )

    execute, issues = D._arm_typed_verify_queue_routing_artifacts(
        "sc_verify_queue", tmp_path, _config(tmp_path)
    )

    assert execute is True
    assert issues == []
    assert calls == 1


def test_optional_selection_always_writes_typed_status_not_chain_degraded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Debt is data with an owner, not a mutable markdown sentinel slice."""

    monkeypatch.setattr(
        D,
        "_resolve_verify_queue_optional_context_inputs",
        lambda _root, _config: (
            set(),
            ["hypotheses.md: producer authority unavailable"],
        ),
    )
    monkeypatch.setattr(
        D,
        "_validate_registered_finding_delivery_receipt",
        lambda _root, **_kwargs: [],
    )
    monkeypatch.setattr(
        D,
        "_arm_deterministic_driver_work_unit",
        lambda **_kwargs: (True, []),
    )

    execute, issues = D._arm_typed_verify_queue_routing_artifacts(
        "sc_verify_queue", tmp_path, _config(tmp_path)
    )

    assert execute is True
    assert issues == []
    status_path = tmp_path / "verify_queue_context_input_status.json"
    assert status_path.is_file()
    payload = json.loads(status_path.read_text(encoding="utf-8"))
    assert payload.get("state") in {
        "COMMITTED_APPLIED",
        "COMMITTED_CLEAN_NOOP",
        "COMPLETED_WITH_DEBT_SAFE_BASE",
    }
    assert payload.get("proof_authority") == "NONE"
    assert not (tmp_path / "chain.degraded").exists()
