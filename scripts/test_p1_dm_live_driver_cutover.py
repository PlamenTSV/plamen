"""Fixture-first live-driver cutover tests for P1-D and P1-M.

These tests deliberately exercise the driver boundary, not only the isolated
authority modules.  A green authority library with no scheduler/PhaseIO owner
is not a live recall control.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path

import authentication_role_authority as R
import plamen_driver as D
import pytest
import semantic_invariant_authority as S
from artifact_ledger import (
    detect_semantic_input_drift,
    read_artifact_ledger,
    record_work_unit_artifacts,
)
from compound_verification import CompoundCandidate, WorkReadiness, compile_compound_work_plan


RUN_ID = "123e4567-e89b-42d3-a456-426614174000"
SNAPSHOT = "a" * 64
SCOPE = "b" * 64


def _checkpoint(root: Path, *, ecosystem: str = "evm") -> None:
    payload = {
        "run_id": RUN_ID,
        "config": {
            "pipeline": "sc",
            "mode": "thorough",
            "language": ecosystem,
        },
        "audit_snapshot": {
            "snapshot_digest": SNAPSHOT,
            "components": {"source_scope": {"digest": SCOPE}},
        },
    }
    (root / "_v2_checkpoint.json").write_text(
        json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8"
    )


def _graph(root: Path, *, ecosystem: str = "evm") -> None:
    suffix = "sol" if ecosystem == "evm" else "move"
    payload = {
        "schema_version": "plamen.mechanical_graph.v2",
        "source": "fixture",
        "state_symbols": [
            {
                "qualified_name": "Vault.total",
                "declaration_locus": f"src/Vault.{suffix}:L7",
                "write_sites": [f"src/Vault.{suffix}:L20"],
                "state_class": "MUTABLE",
            }
        ],
    }
    (root / "_mechanical_graph.json").write_text(
        json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8"
    )


def _canonical_ids(root: Path, identities: tuple[str, ...] = ()) -> None:
    records = [
        {
            "canonical_id": f"CID-{index:016X}",
            "artifact": "findings_inventory.md",
            "local_id": identity,
            "local_id_raw": identity,
            "referenced_ids": [],
        }
        for index, identity in enumerate(identities, 1)
    ]
    payload = {
        "schema_version": "plamen.canonical_finding_ids.v1",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "last_phase": "depth",
        "pipeline": "sc",
        "mode": "thorough",
        "record_count": len(records),
        "records": records,
    }
    (root / "_canonical_finding_ids.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _config(root: Path, *, ecosystem: str = "evm", backend: str = "claude") -> dict:
    return {
        "pipeline": "sc",
        "mode": "thorough",
        "language": ecosystem,
        "cli_backend": backend,
        "project_root": str(root),
        "_run_id": RUN_ID,
    }


def _phase(name: str):
    return next(row for row in D.SC_PHASES if row.name == name)


def _application_payload(worklist: dict) -> dict:
    state = worklist["states"][0]
    payload = {
        "schema_version": S.APPLICATION_TRACE_SCHEMA,
        "run_binding_digest": worklist["run_binding"]["binding_digest"],
        "authority_digest": worklist["authority_digest"],
        "worklist_digest": worklist["worklist_digest"],
        "producer_operator_digest": "c" * 64,
        "rows": [
            {
                "state_id": state["state_id"],
                "disposition": "DELIVERED",
                "evidence_loci": [state["write_sites"][0]],
                "write_site_status": "COMPLETE",
                "semantic_status": "SEMANTICS_OK",
                "result": "All mechanically enumerated write sites were reviewed.",
            }
        ],
    }
    payload["payload_digest"] = S.payload_digest(payload)
    return payload


def _semantic_markdown(payload: dict) -> str:
    return (
        "# Semantic invariants\n\nTyped enumeration completed.\n\n"
        f"{S.TRACE_BEGIN}\n"
        + json.dumps(payload, indent=2, sort_keys=True)
        + f"\n{S.TRACE_END}\n\n<!-- PLAMEN_STATUS: COMPLETE -->\n"
    )


def _complete_pass2(root: Path, config: dict, *, suffix: str = "") -> None:
    assert D._prepare_semantic_invariant_pass2_boundary(root, config) == []
    assert D._bind_typed_model_phase_inputs(
        _phase("invariants_p2"), root, config
    ) == []
    with (root / "semantic_invariants.md").open("a", encoding="utf-8") as stream:
        stream.write(
            suffix
            or "\n## Pass 2: Recursive Semantic Gap Trace\n\nNo extra gap.\n"
        )
    # Crash/recovery between append and successor commit must reuse the exact
    # frozen PRE instead of rebinding it to the already-appended bytes.
    assert D._prepare_semantic_invariant_pass2_boundary(root, config) == []
    assert D._record_typed_model_phase_artifacts(
        _phase("invariants_p2"), root, config
    ) == []
    assert D._finalize_semantic_invariant_pass2_boundary(root, config) == []


def _bind_pass1(root: Path, config: dict) -> None:
    """Model-output fixtures must bind before simulating model writes."""

    assert D._bind_typed_model_phase_inputs(
        _phase("invariants"), root, config
    ) == []


def test_timeout_fallback_emits_exact_deferred_trace_and_avoids_impossible_retry(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    config = _config(tmp_path, backend="codex")

    assert D._prepare_semantic_invariant_pre_boundary(tmp_path, config) == []
    _bind_pass1(tmp_path, config)
    assert D._write_semantic_invariants_fallback(
        tmp_path, "fixture timeout"
    ) == ["semantic_invariants.md"]

    semantic = (tmp_path / "semantic_invariants.md").read_text(encoding="utf-8")
    payload = S.parse_semantic_invariant_application_trace(semantic)
    worklist = json.loads(
        (tmp_path / S.WORKLIST_FILE).read_text(encoding="utf-8")
    )

    assert {row["state_id"] for row in payload["rows"]} == {
        row["state_id"] for row in worklist["states"]
    }
    assert all(row["disposition"] == "DEFERRED" for row in payload["rows"])
    assert payload["payload_digest"] == S.payload_digest(payload)
    assert D._validate_semantic_invariant_producer_trace(tmp_path, config) == []


def test_invalid_model_invariants_are_replaced_by_governed_fallback(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    config = _config(tmp_path, backend="codex")
    phase = _phase("invariants")

    assert D._prepare_semantic_invariant_pre_boundary(tmp_path, config) == []
    _bind_pass1(tmp_path, config)
    (tmp_path / "semantic_invariants.md").write_text(
        "# Semantic Invariants\n\nModel prose without the typed trace.\n",
        encoding="utf-8",
    )

    written, proposal_issues, fallback_issues = (
        D._run_semantic_invariant_fallback_transaction(
            tmp_path,
            config,
            phase,
            "fixture invalid typed trace",
        )
    )

    assert written == ["semantic_invariants.md"]
    assert proposal_issues == []
    assert fallback_issues == []
    assert D._validate_semantic_invariant_producer_trace(tmp_path, config) == []
    assert D._finalize_semantic_invariant_post_boundary(tmp_path, config) == []

    state = read_artifact_ledger(tmp_path)
    model_key = "sc/thorough/evm/codex/invariants/worker.semantic_invariants"
    fallback_key = (
        "sc/thorough/evm/codex/invariants/semantic_invariants.fallback"
    )
    assert state["work_units"][model_key]["semantic_status"] == "ACTIVE"
    assert state["work_units"][fallback_key]["semantic_status"] == "ACTIVE"
    assert state["artifact_bindings"][
        "scratchpad:semantic_invariants.md"
    ]["owner_key"] == fallback_key


def _role_trace(root: Path) -> dict:
    checkpoint = json.loads((root / "_v2_checkpoint.json").read_text(encoding="utf-8"))
    binding = R.run_binding_digest(
        RUN_ID, SNAPSHOT, SCOPE, "evm", "thorough", "sc"
    )
    evidence = lambda claim, locus: {  # noqa: E731 - compact fixture factory
        "claim": claim,
        "locus": locus,
        "result": f"fixture evidence for {claim}",
    }
    common = {
        "polarity": "POSITIVE",
        "provenance": "IN_SCOPE",
        "external_dependency": "",
        "external_surface": "",
    }
    facts = [
        {
            **common,
            "producer_fact_id": "anchor-1",
            "role": "ANCHOR",
            "trust_domain_id": "evm:auth-domain-1",
            "anchor_identity": "storedVerifier",
            "anchor_default": "ZERO_ADDRESS",
            "derived_identity": "",
            "degenerate_input_domain": "",
            "privileged_effect": "effect:privileged-transition",
            "evidence": [
                evidence("UNARMED_DEFAULT", "src/Auth.sol:L10"),
                evidence("OPERATIONAL_WHILE_UNARMED", "src/Auth.sol:L20"),
                evidence("PRIVILEGED_EFFECT_REACHABLE", "src/Auth.sol:L30"),
            ],
        },
        {
            **common,
            "producer_fact_id": "derived-1",
            "role": "DERIVED_IDENTITY",
            "trust_domain_id": "evm:auth-domain-1",
            "anchor_identity": "",
            "anchor_default": "",
            "derived_identity": "ZERO_ADDRESS",
            "degenerate_input_domain": "zero-length signature",
            "privileged_effect": "effect:privileged-transition",
            "evidence": [
                evidence("DEGENERATE_INPUT_IN_DOMAIN", "src/Verify.sol:L10"),
                evidence("DERIVES_DEFAULT_IDENTITY", "src/Verify.sol:L20"),
                evidence("DEFAULT_IDENTITY_ACCEPTED", "src/Verify.sol:L30"),
                evidence("PRIVILEGED_EFFECT_REACHABLE", "src/Verify.sol:L40"),
            ],
        },
    ]
    payload = {
        "schema_version": R.FACT_TRACE_SCHEMA,
        "run_binding_digest": binding,
        "ecosystem": "evm",
        "operator_id": "arm-before-trust-fixture",
        "operator_digest": hashlib.sha256(b"arm-before-trust-fixture").hexdigest(),
        "facts": facts,
    }
    payload["payload_digest"] = R.trace_payload_digest(payload)
    assert checkpoint["config"]["language"] == "evm"
    return payload


def _pre_transaction_snapshot(root: Path) -> dict[str, tuple[bytes, int]]:
    return {
        path.relative_to(root).as_posix(): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _publish_pre_transaction(root: Path) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    _checkpoint(root)
    _graph(root)
    config = _config(root)
    assert D._prepare_semantic_invariant_pre_boundary(root, config) == []
    return config


def _install_pre_replay_bombs(guard: pytest.MonkeyPatch) -> None:
    def reject(*_args, **_kwargs):
        raise AssertionError("existing PRE replay reached a mutating path")

    guard.setattr(
        S, "materialize_semantic_invariant_compatibility_inputs", reject
    )
    guard.setattr(S, "write_semantic_invariant_authority", reject)
    guard.setattr(D, "_record_p1dm_driver_transaction", reject)
    guard.setattr(D, "record_work_unit_inputs", reject)
    guard.setattr(D, "record_work_unit_artifacts", reject)


PASS2_PRE_KEY = (
    "sc/thorough/evm/claude/invariants_p2/semantic_invariants.pass2_pre"
)


def _ready_for_pass2_pre(root: Path) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    _checkpoint(root)
    _graph(root)
    config = _config(root)
    assert D._prepare_semantic_invariant_pre_boundary(root, config) == []
    _bind_pass1(root, config)
    worklist = json.loads((root / S.WORKLIST_FILE).read_text())
    (root / "semantic_invariants.md").write_text(
        _semantic_markdown(_application_payload(worklist)), encoding="utf-8"
    )
    assert D._finalize_semantic_invariant_post_boundary(root, config) == []
    return config


def _install_pass2_pre_replay_bombs(guard: pytest.MonkeyPatch) -> None:
    def reject(*_args, **_kwargs):
        raise AssertionError("existing Pass-2 PRE replay reached a mutating path")

    guard.setattr(S, "write_semantic_invariant_pass2_pre_authority", reject)
    guard.setattr(D, "_record_p1dm_driver_transaction", reject)
    guard.setattr(D, "record_work_unit_inputs", reject)
    guard.setattr(D, "record_work_unit_artifacts", reject)


def _install_compound_replay_bombs(guard: pytest.MonkeyPatch) -> None:
    record_inputs = D.record_work_unit_inputs
    record_artifacts = D.record_work_unit_artifacts

    def reject(*_args, **_kwargs):
        raise AssertionError("existing compound replay reached a mutating path")

    def reject_compound_inputs(*args, **kwargs):
        if args[2].key == P1M_COMPOUND_KEY:
            reject()
        return record_inputs(*args, **kwargs)

    def reject_compound_artifacts(*args, **kwargs):
        if args[2].key == P1M_COMPOUND_KEY:
            reject()
        return record_artifacts(*args, **kwargs)

    guard.setattr(D, "_build_authentication_compound_work_authority", reject)
    guard.setattr(D, "_record_p1dm_driver_transaction", reject)
    guard.setattr(D, "record_work_unit_inputs", reject_compound_inputs)
    guard.setattr(D, "record_work_unit_artifacts", reject_compound_artifacts)


P1M_COMPOUND_KEY = (
    "sc/thorough/evm/claude/chain/authentication_roles.compound_work"
)


def test_p1d_pre_materializes_missing_only_and_phaseio_binds_exact_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    original = "# Existing state variables\n\nDo not overwrite me.\n"
    (tmp_path / "state_variables.md").write_text(original, encoding="utf-8")

    issues = D._prepare_semantic_invariant_pre_boundary(tmp_path, _config(tmp_path))

    assert issues == []
    assert (tmp_path / "state_variables.md").read_text(encoding="utf-8") == original
    assert "UNAVAILABLE_COMPATIBILITY_INPUT" in (
        tmp_path / "state_write_map.md"
    ).read_text(encoding="utf-8")
    for name in (S.AUTHORITY_FILE, S.WORKLIST_FILE, S.WORKLIST_PROJECTION_FILE):
        assert (tmp_path / name).is_file()
    ledger = read_artifact_ledger(tmp_path)
    key = "sc/thorough/evm/claude/invariants/semantic_invariants.pre"
    unit = ledger["work_units"][key]
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert unit["commit_authority"]["attempt_ordinal"] == 1
    assert unit.get("semantic_reexecution_history", []) == []
    assert unit.get("quarantine_recovery_history", []) == []
    assert set(unit["input_bindings"]) == {
        "scratchpad:_v2_checkpoint.json",
        "scratchpad:_mechanical_graph.json",
        "scratchpad:state_variables.md",
        "scratchpad:state_write_map.md",
    }
    before = _pre_transaction_snapshot(tmp_path)
    with monkeypatch.context() as guard:
        _install_pre_replay_bombs(guard)
        assert D._prepare_semantic_invariant_pre_boundary(
            tmp_path, _config(tmp_path)
        ) == []
    assert _pre_transaction_snapshot(tmp_path) == before
    replayed = read_artifact_ledger(tmp_path)["work_units"][key]
    assert replayed == unit
    assert replayed["commit_authority"]["attempt_ordinal"] == 1
    assert replayed.get("semantic_reexecution_history", []) == []
    assert replayed.get("quarantine_recovery_history", []) == []

    for name in ("state_write_map.md", "state_variables.md"):
        root = tmp_path / f"deleted_{name.removesuffix('.md')}"
        config = _publish_pre_transaction(root)
        deleted = root / name
        deleted.unlink()
        deleted_snapshot = _pre_transaction_snapshot(root)
        deleted_unit = read_artifact_ledger(root)["work_units"][key]
        with monkeypatch.context() as guard:
            _install_pre_replay_bombs(guard)
            issues = D._prepare_semantic_invariant_pre_boundary(root, config)
        assert any(name in issue and "missing" in issue for issue in issues)
        assert not deleted.exists()
        assert _pre_transaction_snapshot(root) == deleted_snapshot
        assert read_artifact_ledger(root)["work_units"][key] == deleted_unit


def test_p1d_invariants_prompt_is_exact_contract_and_requires_typed_trace(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    D._prepare_semantic_invariant_pre_boundary(tmp_path, _config(tmp_path))

    prompt = D._compile_semantic_invariant_model_prompt(
        "legacy methodology prompt", _phase("invariants"), tmp_path, _config(tmp_path)
    )

    assert S.TRACE_BEGIN in prompt and S.TRACE_END in prompt
    assert S.AUTHORITY_FILE in prompt and S.WORKLIST_FILE in prompt
    assert "scratchpad:semantic_invariants.md" in prompt
    assert "legacy methodology prompt" in prompt

    _contract, launch = D._p1dm_contract_and_launch(
        tmp_path,
        _config(tmp_path),
        phase_name="invariants",
        work_unit_id="worker.semantic_invariants",
        phase=_phase("invariants"),
        actor="MODEL",
    )
    assert launch.backend == "claude"
    assert launch.exec_mode == "headless"


def test_p1d_post_missing_trace_is_visible_unmeasurable_not_false_clean(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    config = _config(tmp_path)
    D._prepare_semantic_invariant_pre_boundary(tmp_path, config)
    _bind_pass1(tmp_path, config)
    (tmp_path / "semantic_invariants.md").write_text(
        "# Legacy prose only\n\n<!-- PLAMEN_STATUS: COMPLETE -->\n",
        encoding="utf-8",
    )

    issues = D._finalize_semantic_invariant_post_boundary(tmp_path, config)

    assert issues == []
    receipt = json.loads((tmp_path / S.APPLICATION_RECEIPT_FILE).read_text())
    assert receipt["status"] == "UNMEASURABLE"
    assert receipt["unmeasurable_count"] == receipt["expected_state_count"] == 1
    assert "UNMEASURABLE" in (tmp_path / S.GAPS_PROJECTION_FILE).read_text()
    ledger = read_artifact_ledger(tmp_path)
    key = "sc/thorough/evm/claude/invariants/semantic_invariants.post"
    assert ledger["work_units"][key]["semantic_status"] == "ACTIVE"


def test_p1d_producer_gate_rejects_nonapplication_but_accepts_exact_trace(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    config = _config(tmp_path)
    D._prepare_semantic_invariant_pre_boundary(tmp_path, config)
    semantic = tmp_path / "semantic_invariants.md"
    semantic.write_text(
        "# Prose only\n\n<!-- PLAMEN_STATUS: COMPLETE -->\n", encoding="utf-8"
    )

    issues = D._validate_semantic_invariant_producer_trace(tmp_path, config)

    assert any("typed producer trace invalid" in issue for issue in issues)
    worklist = json.loads((tmp_path / S.WORKLIST_FILE).read_text())
    semantic.write_text(
        _semantic_markdown(_application_payload(worklist)), encoding="utf-8"
    )
    assert D._validate_semantic_invariant_producer_trace(tmp_path, config) == []


def test_p1d_independent_consumer_is_distinct_and_reconciles_after_depth(
    tmp_path: Path, monkeypatch,
) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    config = _config(tmp_path)
    D._prepare_semantic_invariant_pre_boundary(tmp_path, config)
    _bind_pass1(tmp_path, config)
    worklist = json.loads((tmp_path / S.WORKLIST_FILE).read_text())
    producer = _application_payload(worklist)
    (tmp_path / "semantic_invariants.md").write_text(
        _semantic_markdown(producer), encoding="utf-8"
    )
    D._finalize_semantic_invariant_post_boundary(tmp_path, config)
    _complete_pass2(tmp_path, config)

    def fake_execute(**kwargs):
        row = producer["rows"][0]
        payload = {
            "schema_version": S.INDEPENDENT_TRACE_SCHEMA,
            "run_binding_digest": worklist["run_binding"]["binding_digest"],
            "authority_digest": worklist["authority_digest"],
            "worklist_digest": worklist["worklist_digest"],
            "producer_payload_digest": producer["payload_digest"],
            "consumer_kind": "DEPTH_STATE_TRACE",
            "consumer_operator_digest": "d" * 64,
            "rows": [
                {
                    "state_id": row["state_id"],
                    "disposition": "APPLIED",
                    "producer_row_digest": S.producer_row_digest(row),
                    "evidence_loci": row["evidence_loci"],
                    "result": "Independent depth trace confirmed application.",
                }
            ],
        }
        payload["payload_digest"] = S.payload_digest(payload)
        (tmp_path / S.INDEPENDENT_TRACE_FILE).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return 0

    monkeypatch.setattr(D, "_execute_auxiliary_model_work_unit", fake_execute)
    issues = D._run_semantic_invariant_independent_boundary(
        tmp_path, config, _phase("depth")
    )

    assert issues == []
    receipt = json.loads((tmp_path / S.APPLICATION_RECEIPT_FILE).read_text())
    assert receipt["status"] == "APPLIED"
    sealed_prior = json.loads((tmp_path / S.PASS2_PRE_FILE).read_text())[
        "prior_application_receipt"
    ]
    assert sealed_prior["status"] == "DELIVERED"
    assert sealed_prior["receipt_digest"] != receipt["receipt_digest"]
    assert D._semantic_invariant_final_input_issues(tmp_path, config) == []
    assert receipt["producer_operator_digest"] == "c" * 64
    assert receipt["states"][0]["independent_consumer"] == "DEPTH_STATE_TRACE"
    ledger = read_artifact_ledger(tmp_path)
    worker = "sc/thorough/evm/claude/depth/worker.semantic_invariant_independent"
    reconcile = "sc/thorough/evm/claude/depth/semantic_invariants.independent_application"
    assert ledger["work_units"][worker]["semantic_status"] == "ACTIVE"
    assert ledger["work_units"][reconcile]["semantic_status"] == "ACTIVE"
    assert (
        ledger["artifact_bindings"][f"scratchpad:{S.APPLICATION_RECEIPT_FILE}"]["owner_key"]
        == reconcile
    )
    # The typed final-byte successor preserves the old receipt digest, while
    # the live receipt may legitimately advance to independent APPLIED state.
    assert D._resume_phase_contract_issues(
        tmp_path,
        str(tmp_path),
        _phase("invariants_p2"),
        "thorough",
        "evm",
        "sc",
        "claude",
    ) == []
    drift = detect_semantic_input_drift(tmp_path, tmp_path, run_id=RUN_ID)
    assert not [
        key
        for key in drift["stale_work_unit_keys"]
        if "/invariants_p2/" in key
    ]


def test_p1d_post_does_not_consume_out_of_contract_independent_trace(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    config = _config(tmp_path)
    D._prepare_semantic_invariant_pre_boundary(tmp_path, config)
    _bind_pass1(tmp_path, config)
    worklist = json.loads((tmp_path / S.WORKLIST_FILE).read_text())
    producer = _application_payload(worklist)
    (tmp_path / "semantic_invariants.md").write_text(
        _semantic_markdown(producer), encoding="utf-8"
    )
    row = producer["rows"][0]
    independent = {
        "schema_version": S.INDEPENDENT_TRACE_SCHEMA,
        "run_binding_digest": worklist["run_binding"]["binding_digest"],
        "authority_digest": worklist["authority_digest"],
        "worklist_digest": worklist["worklist_digest"],
        "producer_payload_digest": producer["payload_digest"],
        "consumer_kind": "DEPTH_STATE_TRACE",
        "consumer_operator_digest": "d" * 64,
        "rows": [{
            "state_id": row["state_id"],
            "disposition": "APPLIED",
            "producer_row_digest": S.producer_row_digest(row),
            "evidence_loci": row["evidence_loci"],
            "result": "Stale/preexisting consumer trace must not enter POST.",
        }],
    }
    independent["payload_digest"] = S.payload_digest(independent)
    (tmp_path / S.INDEPENDENT_TRACE_FILE).write_text(
        json.dumps(independent, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    assert D._finalize_semantic_invariant_post_boundary(tmp_path, config) == []

    receipt = json.loads((tmp_path / S.APPLICATION_RECEIPT_FILE).read_text())
    assert receipt["status"] == "DELIVERED"
    assert receipt["independent_payload_digest"] == ""
    ledger = read_artifact_ledger(tmp_path)
    key = "sc/thorough/evm/claude/invariants/semantic_invariants.post"
    assert f"scratchpad:{S.INDEPENDENT_TRACE_FILE}" not in (
        ledger["work_units"][key]["input_bindings"]
    )


def test_p1d_pass2_append_cannot_leave_initial_receipt_certifying_old_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pass 2 gets a typed successor; the immutable Pass-1 receipt stays old."""
    _checkpoint(tmp_path)
    _graph(tmp_path)
    config = _config(tmp_path)
    D._prepare_semantic_invariant_pre_boundary(tmp_path, config)
    _bind_pass1(tmp_path, config)
    worklist = json.loads((tmp_path / S.WORKLIST_FILE).read_text())
    semantic = tmp_path / "semantic_invariants.md"
    semantic.write_text(
        _semantic_markdown(_application_payload(worklist)), encoding="utf-8"
    )
    assert D._finalize_semantic_invariant_post_boundary(tmp_path, config) == []

    prior_receipt_bytes = (tmp_path / S.APPLICATION_RECEIPT_FILE).read_bytes()
    prior_receipt = json.loads(prior_receipt_bytes)
    prior_binding = next(
        row
        for row in prior_receipt["input_bindings"]
        if row.get("artifact") == "semantic_invariants.md"
    )
    pre_sha = hashlib.sha256(semantic.read_bytes()).hexdigest()
    assert prior_binding["sha256"] == pre_sha
    record_inputs = D.record_work_unit_inputs
    arm_calls: list[str] = []

    def assert_absent_before_arm(*args, **kwargs):
        contract = args[2]
        if contract.key == PASS2_PRE_KEY:
            assert not (tmp_path / S.PASS2_PRE_FILE).exists()
            arm_calls.append(contract.key)
        return record_inputs(*args, **kwargs)

    monkeypatch.setattr(D, "record_work_unit_inputs", assert_absent_before_arm)
    assert D._prepare_semantic_invariant_pass2_boundary(tmp_path, config) == []
    assert arm_calls == [PASS2_PRE_KEY]
    pre_authority = json.loads((tmp_path / S.PASS2_PRE_FILE).read_text())
    assert pre_authority["prior_application_receipt"] == prior_receipt
    pre_unit = read_artifact_ledger(tmp_path)["work_units"][PASS2_PRE_KEY]
    pre_identity = f"scratchpad:{S.PASS2_PRE_FILE}"
    assert pre_unit["semantic_status"] == "ACTIVE"
    assert pre_unit["output_prestates"][pre_identity]["status"] == "ABSENT"
    assert pre_unit["commit_authority"]["attempt_ordinal"] == 1
    assert pre_unit["commit_authority"]["precommit_issues"] == []
    frozen_pre_tree = _pre_transaction_snapshot(tmp_path)
    with monkeypatch.context() as guard:
        _install_pass2_pre_replay_bombs(guard)
        assert D._prepare_semantic_invariant_pass2_boundary(tmp_path, config) == []
    assert _pre_transaction_snapshot(tmp_path) == frozen_pre_tree
    assert read_artifact_ledger(tmp_path)["work_units"][PASS2_PRE_KEY] == pre_unit
    assert arm_calls == [PASS2_PRE_KEY]
    assert D._bind_typed_model_phase_inputs(
        _phase("invariants_p2"), tmp_path, config
    ) == []

    with semantic.open("a", encoding="utf-8") as stream:
        stream.write("\n## Pass 2: Recursive Semantic Gap Trace\n\nNo extra gap.\n")

    assert D._record_typed_model_phase_artifacts(
        _phase("invariants_p2"), tmp_path, config
    ) == []
    assert D._finalize_semantic_invariant_pass2_boundary(tmp_path, config) == []

    # The original delivery authority is immutable and therefore cannot be
    # mistaken for an authority over the later bytes.
    assert (tmp_path / S.APPLICATION_RECEIPT_FILE).read_bytes() == prior_receipt_bytes
    final = json.loads((tmp_path / S.FINAL_BYTE_AUTHORITY_FILE).read_text())
    assert final["status"] == "VALID_FINAL_BYTES"
    assert final["prior_application_receipt_digest"] == prior_receipt["receipt_digest"]
    assert final["pre_semantic_sha256"] == pre_sha
    assert final["post_semantic_sha256"] == hashlib.sha256(
        semantic.read_bytes()
    ).hexdigest()
    assert final["append_byte_count"] > 0
    assert final["append_producer_work_identity"].endswith(
        "/invariants_p2/worker.semantic_invariants_pass2"
    )
    assert final["reconciliation_work_identity"].endswith(
        "/invariants_p2/semantic_invariants.pass2_reconcile"
    )
    ledger = read_artifact_ledger(tmp_path)
    assert ledger["work_units"][
        "sc/thorough/evm/claude/invariants_p2/worker.semantic_invariants_pass2"
    ]["semantic_status"] == "ACTIVE"
    assert (
        ledger["artifact_bindings"]
        [f"scratchpad:{S.FINAL_BYTE_AUTHORITY_FILE}"]["owner_key"]
        .endswith("/invariants_p2/semantic_invariants.pass2_reconcile")
    )


def test_p1d_pass2_exact_resume_is_idempotent_and_tamper_is_visible_debt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    config = _config(tmp_path)
    D._prepare_semantic_invariant_pre_boundary(tmp_path, config)
    _bind_pass1(tmp_path, config)
    worklist = json.loads((tmp_path / S.WORKLIST_FILE).read_text())
    (tmp_path / "semantic_invariants.md").write_text(
        _semantic_markdown(_application_payload(worklist)), encoding="utf-8"
    )
    D._finalize_semantic_invariant_post_boundary(tmp_path, config)
    _complete_pass2(tmp_path, config)
    frozen = {
        name: (tmp_path / name).read_bytes()
        for name in (
            S.PASS2_PRE_FILE,
            S.FINAL_BYTE_AUTHORITY_FILE,
            S.APPLICATION_RECEIPT_FILE,
            "semantic_invariants.md",
            "_artifact_state.json",
        )
    }

    assert D._prepare_semantic_invariant_pass2_boundary(tmp_path, config) == []
    assert D._finalize_semantic_invariant_pass2_boundary(tmp_path, config) == []
    assert frozen == {name: (tmp_path / name).read_bytes() for name in frozen}
    drift = detect_semantic_input_drift(
        tmp_path, tmp_path, run_id=RUN_ID
    )
    assert not [
        key
        for key in drift["stale_work_unit_keys"]
        if "/invariants_p2/" in key
    ]
    assert D._resume_phase_contract_issues(
        tmp_path,
        str(tmp_path),
        _phase("invariants_p2"),
        "thorough",
        "evm",
        "sc",
        "claude",
    ) == []

    with (tmp_path / "semantic_invariants.md").open("a", encoding="utf-8") as stream:
        stream.write("\nunauthorized post-reconciliation drift\n")
    issues = D._prepare_semantic_invariant_pass2_boundary(tmp_path, config)
    assert any("final semantic bytes drift" in issue for issue in issues)
    assert (tmp_path / S.FINAL_BYTE_AUTHORITY_FILE).read_bytes() == frozen[
        S.FINAL_BYTE_AUTHORITY_FILE
    ]
    resume_issues = D._resume_phase_contract_issues(
        tmp_path,
        str(tmp_path),
        _phase("invariants_p2"),
        "thorough",
        "evm",
        "sc",
        "claude",
    )
    assert any("final semantic bytes drift" in issue for issue in resume_issues)

    tampered_root = tmp_path / "tampered_pre"
    tampered_config = _ready_for_pass2_pre(tampered_root)
    assert D._prepare_semantic_invariant_pass2_boundary(
        tampered_root, tampered_config
    ) == []
    tampered_path = tampered_root / S.PASS2_PRE_FILE
    tampered_path.write_bytes(tampered_path.read_bytes() + b" ")
    tampered_tree = _pre_transaction_snapshot(tampered_root)
    tampered_unit = read_artifact_ledger(tampered_root)["work_units"][PASS2_PRE_KEY]
    with monkeypatch.context() as guard:
        _install_pass2_pre_replay_bombs(guard)
        tampered_issues = D._prepare_semantic_invariant_pass2_boundary(
            tampered_root, tampered_config
        )
    assert tampered_issues
    assert _pre_transaction_snapshot(tampered_root) == tampered_tree
    assert read_artifact_ledger(tampered_root)["work_units"][PASS2_PRE_KEY] == tampered_unit

    receipt_root = tmp_path / "receipt_drift"
    receipt_config = _ready_for_pass2_pre(receipt_root)
    assert D._prepare_semantic_invariant_pass2_boundary(
        receipt_root, receipt_config
    ) == []
    receipt_path = receipt_root / S.APPLICATION_RECEIPT_FILE
    receipt_path.write_bytes(receipt_path.read_bytes() + b"\n")
    receipt_tree = _pre_transaction_snapshot(receipt_root)
    receipt_unit = read_artifact_ledger(receipt_root)["work_units"][PASS2_PRE_KEY]
    with monkeypatch.context() as guard:
        _install_pass2_pre_replay_bombs(guard)
        receipt_issues = D._prepare_semantic_invariant_pass2_boundary(
            receipt_root, receipt_config
        )
    assert any("receipt drifted" in issue for issue in receipt_issues)
    assert _pre_transaction_snapshot(receipt_root) == receipt_tree
    assert read_artifact_ledger(receipt_root)["work_units"][PASS2_PRE_KEY] == receipt_unit

    cross_run_config = dict(receipt_config, _run_id="223e4567-e89b-42d3-a456-426614174000")
    with monkeypatch.context() as guard:
        _install_pass2_pre_replay_bombs(guard)
        cross_run_issues = D._prepare_semantic_invariant_pass2_boundary(
            receipt_root, cross_run_config
        )
    assert cross_run_issues
    assert _pre_transaction_snapshot(receipt_root) == receipt_tree

    unowned_root = tmp_path / "unowned_pre"
    unowned_config = _ready_for_pass2_pre(unowned_root)
    unowned_path = unowned_root / S.PASS2_PRE_FILE
    unowned_path.write_bytes(b"unowned output before arm\n")
    unowned_tree = _pre_transaction_snapshot(unowned_root)
    unowned_ledger = read_artifact_ledger(unowned_root)
    with monkeypatch.context() as guard:
        _install_pass2_pre_replay_bombs(guard)
        unowned_issues = D._prepare_semantic_invariant_pass2_boundary(
            unowned_root, unowned_config
        )
    assert unowned_issues == [
        "Pass-2 PRE output exists without its exact committed work-unit record"
    ]
    assert _pre_transaction_snapshot(unowned_root) == unowned_tree
    assert read_artifact_ledger(unowned_root) == unowned_ledger


def test_p1d_depth_rejects_unowned_live_receipt_drift_after_final_seal(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    config = _config(tmp_path)
    D._prepare_semantic_invariant_pre_boundary(tmp_path, config)
    _bind_pass1(tmp_path, config)
    worklist = json.loads((tmp_path / S.WORKLIST_FILE).read_text())
    (tmp_path / "semantic_invariants.md").write_text(
        _semantic_markdown(_application_payload(worklist)), encoding="utf-8"
    )
    D._finalize_semantic_invariant_post_boundary(tmp_path, config)
    _complete_pass2(tmp_path, config)
    assert D._semantic_invariant_final_input_issues(tmp_path, config) == []

    # Semantically equivalent whitespace is still unowned byte drift. It is
    # neither the exact sealed receipt nor a ledger-bound depth successor.
    with (tmp_path / S.APPLICATION_RECEIPT_FILE).open("a", encoding="utf-8") as stream:
        stream.write("\n")
    issues = D._semantic_invariant_final_input_issues(tmp_path, config)

    assert any("successor" in issue for issue in issues)


def test_p1d_pass2_missing_or_empty_append_cannot_self_certify(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    config = _config(tmp_path)
    D._prepare_semantic_invariant_pre_boundary(tmp_path, config)
    _bind_pass1(tmp_path, config)
    worklist = json.loads((tmp_path / S.WORKLIST_FILE).read_text())
    (tmp_path / "semantic_invariants.md").write_text(
        _semantic_markdown(_application_payload(worklist)), encoding="utf-8"
    )
    D._finalize_semantic_invariant_post_boundary(tmp_path, config)
    assert D._prepare_semantic_invariant_pass2_boundary(tmp_path, config) == []

    issues = D._finalize_semantic_invariant_pass2_boundary(tmp_path, config)

    assert any("append is empty" in issue for issue in issues)
    final = json.loads((tmp_path / S.FINAL_BYTE_AUTHORITY_FILE).read_text())
    assert final["status"] == "UNMEASURABLE"
    assert final["semantic_correctness_proven"] is False
    assert final["append_producer_self_certified"] is False


def test_p1d_pass2_rewrite_is_visible_debt_not_a_successor(tmp_path: Path) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    config = _config(tmp_path)
    D._prepare_semantic_invariant_pre_boundary(tmp_path, config)
    _bind_pass1(tmp_path, config)
    worklist = json.loads((tmp_path / S.WORKLIST_FILE).read_text())
    semantic = tmp_path / "semantic_invariants.md"
    semantic.write_text(
        _semantic_markdown(_application_payload(worklist)), encoding="utf-8"
    )
    D._finalize_semantic_invariant_post_boundary(tmp_path, config)
    assert D._prepare_semantic_invariant_pass2_boundary(tmp_path, config) == []
    semantic.write_text(
        "# rewritten instead of appended\n\n## Pass 2: fake\n", encoding="utf-8"
    )

    issues = D._finalize_semantic_invariant_pass2_boundary(tmp_path, config)

    assert any("did not preserve" in issue for issue in issues)
    final = json.loads((tmp_path / S.FINAL_BYTE_AUTHORITY_FILE).read_text())
    assert final["status"] == "UNMEASURABLE"
    assert final["append_prefix_preserved"] is False


def test_p1d_pass2_missing_prior_receipt_stays_unmeasurable(tmp_path: Path) -> None:
    _checkpoint(tmp_path)
    (tmp_path / "semantic_invariants.md").write_text(
        "# orphan semantic prose\n", encoding="utf-8"
    )
    config = _config(tmp_path)

    pre_issues = D._prepare_semantic_invariant_pass2_boundary(tmp_path, config)
    pre = json.loads((tmp_path / S.PASS2_PRE_FILE).read_text())
    with (tmp_path / "semantic_invariants.md").open("a", encoding="utf-8") as stream:
        stream.write("\n## Pass 2: orphan append\n")
    final_issues = D._finalize_semantic_invariant_pass2_boundary(tmp_path, config)
    final = json.loads((tmp_path / S.FINAL_BYTE_AUTHORITY_FILE).read_text())

    assert pre["status"] == "UNMEASURABLE"
    assert any("receipt" in issue.lower() for issue in pre_issues)
    assert final["status"] == "UNMEASURABLE"
    assert any("pre-authority was not READY" in issue for issue in final_issues)


def test_p1d_pass2_non_thorough_is_a_deterministic_noop(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config["mode"] = "core"

    assert D._prepare_semantic_invariant_pass2_boundary(tmp_path, config) == []
    assert D._finalize_semantic_invariant_pass2_boundary(tmp_path, config) == []
    assert not (tmp_path / S.PASS2_PRE_FILE).exists()
    assert not (tmp_path / S.FINAL_BYTE_AUTHORITY_FILE).exists()


def test_p1d_pass2_phaseio_has_distinct_append_and_successor_owners() -> None:
    common = {
        "pipeline": "sc",
        "mode": "thorough",
        "ecosystem": "evm",
        "backend": "claude",
        "phase": "invariants_p2",
    }
    pre = D.resolve_phase_io_contract(
        **common, work_unit_id="semantic_invariants.pass2_pre"
    )
    worker = D.resolve_phase_io_contract(
        **common, work_unit_id="worker.semantic_invariants_pass2"
    )
    final = D.resolve_phase_io_contract(
        **common, work_unit_id="semantic_invariants.pass2_reconcile"
    )
    depth = D.resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="depth",
        work_unit_id="worker.semantic_invariant_independent",
    )
    depth_reconcile = D.resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="depth",
        work_unit_id="semantic_invariants.independent_application",
    )
    ordinary_depth = D.resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="depth",
        work_unit_id="worker.state_trace",
        exact_outputs=("depth_state_trace_findings.md",),
    )

    assert pre.model_invoked is False
    assert pre.immutable_inputs == ()
    assert worker.model_invoked is True
    assert worker.outputs[0].write_mode == "APPEND"
    assert worker.outputs[0].writer == "MODEL"
    assert worker.immutable_inputs == (f"scratchpad:{S.PASS2_PRE_FILE}",)
    assert final.model_invoked is False
    assert final.outputs[0].path == S.FINAL_BYTE_AUTHORITY_FILE
    assert set(final.immutable_inputs) == {
        f"scratchpad:{S.PASS2_PRE_FILE}",
        "scratchpad:semantic_invariants.md",
    }
    assert len({pre.key, worker.key, final.key}) == 3
    assert f"scratchpad:{S.FINAL_BYTE_AUTHORITY_FILE}" in depth.immutable_inputs
    assert (
        f"scratchpad:{S.FINAL_BYTE_AUTHORITY_FILE}"
        in depth_reconcile.bounded_lookup_inputs
    )
    assert (
        f"scratchpad:{S.FINAL_BYTE_AUTHORITY_FILE}"
        in ordinary_depth.immutable_inputs
    )


def test_p1d_thorough_depth_refuses_stale_pass1_bytes_without_final_authority(
    tmp_path: Path, monkeypatch,
) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    config = _config(tmp_path)
    D._prepare_semantic_invariant_pre_boundary(tmp_path, config)
    worklist = json.loads((tmp_path / S.WORKLIST_FILE).read_text())
    (tmp_path / "semantic_invariants.md").write_text(
        _semantic_markdown(_application_payload(worklist)), encoding="utf-8"
    )
    D._finalize_semantic_invariant_post_boundary(tmp_path, config)
    called = False

    def forbidden(**kwargs):
        nonlocal called
        called = True
        raise AssertionError("depth cannot consume a stale Pass-1-only receipt")

    monkeypatch.setattr(D, "_execute_auxiliary_model_work_unit", forbidden)
    issues = D._run_semantic_invariant_independent_boundary(
        tmp_path, config, _phase("depth")
    )

    assert called is False
    assert any("final-byte authority" in issue for issue in issues)


def test_p1m_non_evm_is_deterministic_not_triggered_without_model_launch(
    tmp_path: Path, monkeypatch,
) -> None:
    _checkpoint(tmp_path, ecosystem="aptos")
    _graph(tmp_path, ecosystem="aptos")
    called = False

    def forbidden(**kwargs):
        nonlocal called
        called = True
        raise AssertionError("non-EVM activation gate must not launch a model")

    monkeypatch.setattr(D, "_execute_auxiliary_model_work_unit", forbidden)
    issues = D._run_authentication_role_boundary(
        tmp_path, _config(tmp_path, ecosystem="aptos"), _phase("depth")
    )

    assert issues == []
    assert called is False
    authority = json.loads((tmp_path / R.AUTHORITY_FILE).read_text())
    composition = json.loads((tmp_path / R.COMPOSITION_FILE).read_text())
    assert authority["status"] == "NOT_TRIGGERED"
    assert authority["activation"]["state"] == "NON_EVM_ACTIVATION_GATE_HELD"
    assert composition["obligations"] == []
    assert not (tmp_path / R.TRACE_FILE).exists()


def test_p1m_evm_typed_worker_stages_disjoint_authority_and_composition(
    tmp_path: Path, monkeypatch,
) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    config = _config(tmp_path, backend="codex")

    def fake_execute(**kwargs):
        (tmp_path / R.TRACE_FILE).write_text(
            json.dumps(_role_trace(tmp_path), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(D, "_execute_auxiliary_model_work_unit", fake_execute)
    issues = D._run_authentication_role_boundary(
        tmp_path, config, _phase("depth")
    )

    assert issues == []
    authority = json.loads((tmp_path / R.AUTHORITY_FILE).read_text())
    composition = json.loads((tmp_path / R.COMPOSITION_FILE).read_text())
    assert authority["status"] == "ACTIVE"
    assert composition["obligation_count"] == 1
    assert composition["obligations"][0]["proof_authority"] == "NONE"
    assert composition["obligations"][0]["route"] == "COMPOUND_ANALYSIS_REQUIRED"
    ledger = read_artifact_ledger(tmp_path)
    worker = "sc/thorough/evm/codex/depth/worker.authentication_role_facts"
    facts = "sc/thorough/evm/codex/depth/authentication_roles.fact_authority"
    composed = "sc/thorough/evm/codex/depth/authentication_roles.composition"
    assert ledger["work_units"][worker]["semantic_status"] == "ACTIVE"
    assert set(ledger["work_units"][facts]["artifacts"]) == {
        f"scratchpad:{R.AUTHORITY_FILE}"
    }
    assert set(ledger["work_units"][composed]["artifacts"]) == {
        f"scratchpad:{R.COMPOSITION_FILE}",
        f"scratchpad:{R.EXTERNAL_RESEARCH_FILE}",
        f"scratchpad:{R.PROJECTION_FILE}",
    }


def test_p1m_transactional_inner_commit_is_not_double_committed(
    tmp_path: Path, monkeypatch,
) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    config = _config(tmp_path, backend="codex")

    def transactional_execute(**kwargs):
        (tmp_path / R.TRACE_FILE).write_text(
            json.dumps(_role_trace(tmp_path), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        record_work_unit_artifacts(
            tmp_path,
            tmp_path,
            kwargs["contract"],
            kwargs["launch"],
            run_id=RUN_ID,
            actor="MODEL",
        )
        return 0

    monkeypatch.setattr(
        D, "_execute_auxiliary_model_work_unit", transactional_execute
    )
    assert D._run_authentication_role_boundary(
        tmp_path, config, _phase("depth")
    ) == []

    ledger = read_artifact_ledger(tmp_path)
    worker = "sc/thorough/evm/codex/depth/worker.authentication_role_facts"
    assert ledger["work_units"][worker]["commit_authority"]["attempt_ordinal"] == 1
    authorities = json.loads(
        (tmp_path / "_artifact_output_authorities.json").read_text(
            encoding="utf-8"
        )
    )["authorities"].values()
    assert sum(row["work_unit_key"] == worker for row in authorities) == 1


def test_p1m_conditional_chain_consumer_has_distinct_output_and_phaseio(
    tmp_path: Path, monkeypatch,
) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    config = _config(tmp_path)

    def execute_role(**kwargs):
        (tmp_path / R.TRACE_FILE).write_text(
            json.dumps(_role_trace(tmp_path), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(D, "_execute_auxiliary_model_work_unit", execute_role)
    assert D._run_authentication_role_boundary(
        tmp_path, config, _phase("depth")
    ) == []
    composition = json.loads((tmp_path / R.COMPOSITION_FILE).read_text())
    authority = json.loads((tmp_path / R.AUTHORITY_FILE).read_text())
    _canonical_ids(tmp_path)

    def execute_chain(**kwargs):
        obligation = composition["obligations"][0]
        payload = {
            "schema_version": "plamen.arm_before_trust_chain_analysis.v1",
            "composition_digest": composition["composition_digest"],
            "operator_digest": "e" * 64,
            "candidates": [
                {
                    "candidate_id": "MZO-CAND-0001",
                    "obligation_id": obligation["obligation_id"],
                    "obligation_digest": obligation["obligation_digest"],
                    "constituent_fact_ids": obligation["constituent_fact_ids"],
                    "disposition": "NOMINATED",
                    "reachability_evidence": ["src/Auth.sol:L30"],
                    "composition_result": "The two typed halves compose in scope.",
                    "harm_result": "Material harm remains for an independent verifier.",
                    "proof_authority": "NONE",
                    "route": "P0_AF_V2_QUEUE_ADAPTER_REQUIRED",
                }
            ],
        }
        payload["payload_digest"] = D._stable_payload_digest(
            {key: value for key, value in payload.items() if key != "payload_digest"}
        )
        (tmp_path / D.ARM_BEFORE_TRUST_CHAIN_ANALYSIS_FILE).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return 0

    monkeypatch.setattr(D, "_execute_auxiliary_model_work_unit", execute_chain)
    issues = D._run_authentication_chain_consumer_boundary(
        tmp_path, config, _phase("chain")
    )

    assert issues == []
    output = tmp_path / D.ARM_BEFORE_TRUST_CHAIN_ANALYSIS_FILE
    assert output.is_file()
    assert output.name not in {
        "chain_hypotheses.md", "chain_composition_candidates.json",
        R.COMPOSITION_FILE,
    }
    payload = json.loads(output.read_text())
    assert payload["candidates"][0]["constituent_fact_ids"] == (
        composition["obligations"][0]["constituent_fact_ids"]
    )
    assert payload["operator_digest"] != authority["operator_digest"]
    ledger = read_artifact_ledger(tmp_path)
    key = "sc/thorough/evm/claude/chain/worker.arm_before_trust"
    assert set(ledger["work_units"][key]["artifacts"]) == {
        f"scratchpad:{D.ARM_BEFORE_TRUST_CHAIN_ANALYSIS_FILE}"
    }
    compound_key = (
        "sc/thorough/evm/claude/chain/"
        "authentication_roles.compound_work"
    )
    assert set(ledger["work_units"][compound_key]["input_bindings"]) == {
        f"scratchpad:{D.ARM_BEFORE_TRUST_CHAIN_ANALYSIS_FILE}",
        f"scratchpad:{R.COMPOSITION_FILE}",
        f"scratchpad:{R.AUTHORITY_FILE}",
        "scratchpad:_canonical_finding_ids.json",
    }
    assert set(ledger["work_units"][compound_key]["artifacts"]) == {
        f"scratchpad:{D.ARM_BEFORE_TRUST_COMPOUND_CANDIDATES_FILE}",
        f"scratchpad:{D.ARM_BEFORE_TRUST_COMPOUND_WORK_PLAN_FILE}",
        f"scratchpad:{D.ARM_BEFORE_TRUST_ROUTE_DEBT_FILE}",
    }
    work_authority = json.loads(
        (tmp_path / D.ARM_BEFORE_TRUST_COMPOUND_WORK_PLAN_FILE).read_text()
    )
    work_plan = work_authority["compound_work_plan"]
    assert work_plan["schema_version"] == "plamen.compound_work_plan.v2"
    work = work_plan["work_items"][0]
    assert WorkReadiness(work["readiness"]) is WorkReadiness.READY
    assert re.fullmatch(r"CH-\d{1,6}", work["subject_id"])
    assert len(work["constituent_authority_bindings"]) == 2
    assert {
        binding["constituent_kind"]
        for binding in work["constituent_authority_bindings"]
    } == {"EVIDENCE_FACT"}
    route_debt = json.loads(
        (tmp_path / D.ARM_BEFORE_TRUST_ROUTE_DEBT_FILE).read_text()
    )
    assert route_debt["status"] == "READY_PENDING_QUEUE_DELIVERY"
    assert route_debt["ordinary_verification_required"] is True
    assert route_debt["proof_authority"] == "NONE"
    assert not (tmp_path / "verification_queue.md").exists()
    assert not list(tmp_path.glob("verify_CH-*.md"))


def test_p1m_chain_consumer_does_not_launch_without_positive_composition(
    tmp_path: Path, monkeypatch,
) -> None:
    _checkpoint(tmp_path, ecosystem="aptos")
    _graph(tmp_path, ecosystem="aptos")
    config = _config(tmp_path, ecosystem="aptos")
    assert D._run_authentication_role_boundary(
        tmp_path, config, _phase("depth")
    ) == []
    called = False

    def forbidden(**kwargs):
        nonlocal called
        called = True
        raise AssertionError("no positive composition must not launch chain consumer")

    monkeypatch.setattr(D, "_execute_auxiliary_model_work_unit", forbidden)
    assert D._run_authentication_chain_consumer_boundary(
        tmp_path, config, _phase("chain")
    ) == []
    assert called is False
    assert not (tmp_path / D.ARM_BEFORE_TRUST_CHAIN_ANALYSIS_FILE).exists()


def test_p1m_compound_identity_collision_is_avoided_and_resume_is_stable(
    tmp_path: Path, monkeypatch,
) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    config = _config(tmp_path)

    def execute_role(**kwargs):
        (tmp_path / R.TRACE_FILE).write_text(
            json.dumps(_role_trace(tmp_path), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(D, "_execute_auxiliary_model_work_unit", execute_role)
    assert D._run_authentication_role_boundary(
        tmp_path, config, _phase("depth")
    ) == []
    composition = json.loads((tmp_path / R.COMPOSITION_FILE).read_text())
    obligation = composition["obligations"][0]
    colliding = D._p1m_compound_chain_id(
        obligation["obligation_id"], obligation["obligation_digest"], set()
    )
    _canonical_ids(tmp_path, (colliding,))

    def execute_chain(**kwargs):
        payload = {
            "schema_version": "plamen.arm_before_trust_chain_analysis.v1",
            "composition_digest": composition["composition_digest"],
            "operator_digest": "e" * 64,
            "candidates": [{
                "candidate_id": "MZO-CAND-COLLISION",
                "obligation_id": obligation["obligation_id"],
                "obligation_digest": obligation["obligation_digest"],
                "constituent_fact_ids": obligation["constituent_fact_ids"],
                "disposition": "NOMINATED",
                "reachability_evidence": ["src/Auth.sol:L30"],
                "composition_result": "Typed composition is reachable.",
                "harm_result": "Material harm requires independent execution.",
                "proof_authority": "NONE",
                "route": "P0_AF_V2_QUEUE_ADAPTER_REQUIRED",
            }],
        }
        payload["payload_digest"] = D._stable_payload_digest(payload)
        (tmp_path / D.ARM_BEFORE_TRUST_CHAIN_ANALYSIS_FILE).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(D, "_execute_auxiliary_model_work_unit", execute_chain)
    assert D._run_authentication_chain_consumer_boundary(
        tmp_path, config, _phase("chain")
    ) == []
    work_authority = json.loads(
        (tmp_path / D.ARM_BEFORE_TRUST_COMPOUND_WORK_PLAN_FILE).read_text()
    )
    work = work_authority["compound_work_plan"]["work_items"][0]
    assert work["readiness"] == "READY"
    assert work["subject_id"] != colliding
    before = {
        name: (tmp_path / name).read_bytes()
        for name in D._ARM_BEFORE_TRUST_COMPOUND_OUTPUTS
    }
    compound_key = P1M_COMPOUND_KEY
    compound_unit = read_artifact_ledger(tmp_path)["work_units"][compound_key]
    assert compound_unit["semantic_status"] == "ACTIVE"
    assert compound_unit["commit_authority"]["attempt_ordinal"] == 1
    assert compound_unit["commit_authority"]["precommit_issues"] == []
    assert compound_unit["commit_authority"][
        "quarantine_recovery_history_count"
    ] == 0
    before_tree = _pre_transaction_snapshot(tmp_path)

    def forbidden(**kwargs):
        raise AssertionError("valid exact resume must not relaunch the model")

    monkeypatch.setattr(D, "_execute_auxiliary_model_work_unit", forbidden)
    semantic_validator = D._validate_authentication_compound_work_authority
    validator_calls = 0

    def count_semantic_validation(root: Path) -> list[str]:
        nonlocal validator_calls
        validator_calls += 1
        return semantic_validator(root)

    monkeypatch.setattr(
        D, "_validate_authentication_compound_work_authority",
        count_semantic_validation,
    )
    with monkeypatch.context() as guard:
        _install_compound_replay_bombs(guard)
        assert D._run_authentication_chain_consumer_boundary(
            tmp_path, config, _phase("chain")
        ) == []
    assert validator_calls == 2
    assert _pre_transaction_snapshot(tmp_path) == before_tree
    assert read_artifact_ledger(tmp_path)["work_units"][compound_key] == compound_unit
    assert before == {
        name: (tmp_path / name).read_bytes()
        for name in D._ARM_BEFORE_TRUST_COMPOUND_OUTPUTS
    }

    for name, original in before.items():
        path = tmp_path / name
        path.write_bytes(original + b"\n")
        tampered_tree = _pre_transaction_snapshot(tmp_path)
        with monkeypatch.context() as guard:
            _install_compound_replay_bombs(guard)
            tamper_issues = D._run_authentication_chain_consumer_boundary(
                tmp_path, config, _phase("chain")
            )
        assert any(
            name in issue
            and (
                "live bytes differ from issued output authority" in issue
                or "content hash changed since work-unit record" in issue
            )
            for issue in tamper_issues
        )
        assert _pre_transaction_snapshot(tmp_path) == tampered_tree
        assert read_artifact_ledger(tmp_path)["work_units"][compound_key] == compound_unit
        path.write_bytes(original)

    input_names = (
        D.ARM_BEFORE_TRUST_CHAIN_ANALYSIS_FILE,
        R.COMPOSITION_FILE,
        R.AUTHORITY_FILE,
        "_canonical_finding_ids.json",
    )
    for name in input_names:
        path = tmp_path / name
        original = path.read_bytes()
        clean_tree = _pre_transaction_snapshot(tmp_path)
        chain_validator = D._validate_authentication_chain_analysis
        chain_validator_calls = 0

        def inject_drift_after_model_replay(root: Path) -> list[str]:
            nonlocal chain_validator_calls
            chain_validator_calls += 1
            issues = chain_validator(root)
            if chain_validator_calls == 2:
                path.write_bytes(original + b"\n")
            return issues

        with monkeypatch.context() as guard:
            _install_compound_replay_bombs(guard)
            guard.setattr(
                D, "_validate_authentication_chain_analysis",
                inject_drift_after_model_replay,
            )
            input_issues = D._run_authentication_chain_consumer_boundary(
                tmp_path, config, _phase("chain")
            )
        assert chain_validator_calls == 2
        assert any(
            name in issue
            and (
                "semantic input hash changed" in issue
                or "producer authority mismatch" in issue
            )
            for issue in input_issues
        )
        drifted_tree = _pre_transaction_snapshot(tmp_path)
        assert set(drifted_tree) == set(clean_tree)
        assert all(
            drifted_tree[identity] == clean_tree[identity]
            for identity in clean_tree
            if identity != name
        )
        assert drifted_tree[name][0] == original + b"\n"
        assert read_artifact_ledger(tmp_path)["work_units"][compound_key] == compound_unit
        path.write_bytes(original)

    cross_run = dict(config)
    cross_run_tree = _pre_transaction_snapshot(tmp_path)
    chain_validator = D._validate_authentication_chain_analysis
    chain_validator_calls = 0

    def inject_foreign_run_after_model_replay(root: Path) -> list[str]:
        nonlocal chain_validator_calls
        chain_validator_calls += 1
        issues = chain_validator(root)
        if chain_validator_calls == 2:
            cross_run["_run_id"] = "223e4567-e89b-42d3-a456-426614174000"
        return issues

    with monkeypatch.context() as guard:
        _install_compound_replay_bombs(guard)
        guard.setattr(
            D, "_validate_authentication_chain_analysis",
            inject_foreign_run_after_model_replay,
        )
        cross_run_issues = D._run_authentication_chain_consumer_boundary(
            tmp_path, cross_run, _phase("chain")
        )
    assert chain_validator_calls == 2
    assert any("run" in issue.lower() for issue in cross_run_issues)
    assert _pre_transaction_snapshot(tmp_path) == cross_run_tree
    assert read_artifact_ledger(tmp_path)["work_units"][compound_key] == compound_unit

    # A later denominator collision cannot silently inherit the frozen READY
    # label. The committed bytes stay immutable, while live validation emits
    # explicit collision/drift debt for the next reviewed invalidation step.
    _canonical_ids(tmp_path, (colliding, work["subject_id"]))
    drift_issues = D._run_authentication_chain_consumer_boundary(
        tmp_path, config, _phase("chain")
    )
    assert any("semantic input hash changed" in issue for issue in drift_issues)
    assert any(
        "identity denominator drift" in issue
        or "identity collision" in issue
        for issue in drift_issues
    )
    assert before == {
        name: (tmp_path / name).read_bytes()
        for name in D._ARM_BEFORE_TRUST_COMPOUND_OUTPUTS
    }


def test_p1m_external_unknown_is_delivered_as_visible_research_debt(
    tmp_path: Path, monkeypatch,
) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    config = _config(tmp_path)

    def execute(**kwargs):
        trace = _role_trace(tmp_path)
        anchor = trace["facts"][0]
        anchor["provenance"] = "EXTERNAL"
        anchor["external_dependency"] = "ExternalVerifier"
        anchor["external_surface"] = "ExternalVerifier.verify"
        for evidence in anchor["evidence"]:
            evidence["locus"] = "https://example.invalid/verifier-spec"
        trace["payload_digest"] = R.trace_payload_digest(trace)
        (tmp_path / R.TRACE_FILE).write_text(
            json.dumps(trace, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return 0

    monkeypatch.setattr(D, "_execute_auxiliary_model_work_unit", execute)
    issues = D._run_authentication_role_boundary(
        tmp_path, config, _phase("depth")
    )

    research = json.loads((tmp_path / R.EXTERNAL_RESEARCH_FILE).read_text())
    assert research["obligation_count"] == 1
    assert any("external research obligation" in issue for issue in issues)
    assert research["obligations"][0]["asserted_external_state"] == "UNKNOWN"


def test_live_main_loop_orders_dm_boundaries_around_model_and_depth_commit() -> None:
    source = Path(D.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    main = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    )

    def call_name(node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    calls = [node for node in ast.walk(main) if isinstance(node, ast.Call)]
    call_lines = lambda name: sorted(
        node.lineno for node in calls if call_name(node) == name
    )
    pre = call_lines("_prepare_semantic_invariant_pre_boundary")[0]
    pass2_pre = call_lines("_prepare_semantic_invariant_pass2_boundary")[0]
    launch = min(
        node.lineno
        for node in ast.walk(main)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "rc"
        and isinstance(node.value, ast.Call)
        and call_name(node.value) == "run_phase"
        and node.value.args
        and isinstance(node.value.args[0], ast.Name)
        and node.value.args[0].id == "phase"
        and any(
            keyword.arg == "attempt"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value == 1
            for keyword in node.value.keywords
        )
    )
    post = min(line for line in call_lines("_finalize_semantic_invariant_post_boundary") if line > launch)
    assignments = [
        node
        for node in ast.walk(main)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "_generic_model_io_issues"
    ]
    assert len(assignments) == 1
    model_assignment = assignments[0]
    model_calls = [
        node
        for node in ast.walk(model_assignment.value)
        if isinstance(node, ast.Call)
        and call_name(node) == "_record_typed_model_phase_artifacts"
    ]
    assert len(model_calls) == 1
    model_call = model_calls[0]
    consumer_loops = [
        node
        for node in ast.walk(main)
        if isinstance(node, ast.For)
        and isinstance(node.target, ast.Name)
        and node.target.id == "_model_io_issue"
        and isinstance(node.iter, ast.Name)
        and node.iter.id == "_generic_model_io_issues"
    ]
    assert len(consumer_loops) == 1
    consumer = consumer_loops[0]
    pass2_final = min(
        line
        for line in call_lines("_finalize_semantic_invariant_pass2_boundary")
        if line > consumer.lineno
    )
    auth = call_lines("_run_authentication_role_boundary")[0]
    independent = min(
        line
        for line in call_lines("_run_semantic_invariant_independent_boundary")
        if line > post
    )
    commit = min(
        line for line in call_lines("_commit_phase_from_disk_debt") if line > independent
    )
    assert pre < launch < post
    assert (
        pass2_pre
        < launch
        < model_assignment.lineno
        <= model_call.lineno
        < consumer.lineno
        < pass2_final
        < commit
    )
    assert auth < launch
    assert post < independent < commit


def test_p1d_light_mode_absence_does_not_launch_unbound_independent_consumer(
    tmp_path: Path, monkeypatch,
) -> None:
    _checkpoint(tmp_path)
    called = False

    def forbidden(**kwargs):
        nonlocal called
        called = True
        raise AssertionError("absent P1-D producer family must not launch a consumer")

    monkeypatch.setattr(D, "_execute_auxiliary_model_work_unit", forbidden)
    config = _config(tmp_path)
    config["mode"] = "light"

    assert D._run_semantic_invariant_independent_boundary(
        tmp_path, config, _phase("depth")
    ) == []
    assert called is False


def test_p1d_committed_pre_input_drift_is_debt_and_not_silently_rebound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    config = _config(tmp_path)
    assert D._prepare_semantic_invariant_pre_boundary(tmp_path, config) == []
    authority_before = (tmp_path / S.AUTHORITY_FILE).read_bytes()
    graph = json.loads((tmp_path / "_mechanical_graph.json").read_text())
    graph["state_symbols"][0]["write_sites"] = ["src/Vault.sol:L99"]
    (tmp_path / "_mechanical_graph.json").write_text(
        json.dumps(graph, sort_keys=True) + "\n", encoding="utf-8"
    )

    issues = D._prepare_semantic_invariant_pre_boundary(tmp_path, config)

    assert any(
        "_mechanical_graph.json: semantic input hash changed" in issue
        for issue in issues
    )
    assert (tmp_path / S.AUTHORITY_FILE).read_bytes() == authority_before

    key = "sc/thorough/evm/claude/invariants/semantic_invariants.pre"
    for name in ("state_write_map.md", "state_variables.md"):
        root = tmp_path / f"modified_{name.removesuffix('.md')}"
        config = _publish_pre_transaction(root)
        path = root / name
        path.write_bytes(path.read_bytes() + b"modified\n")
        modified_snapshot = _pre_transaction_snapshot(root)
        modified_unit = read_artifact_ledger(root)["work_units"][key]
        with monkeypatch.context() as guard:
            _install_pre_replay_bombs(guard)
            issues = D._prepare_semantic_invariant_pre_boundary(root, config)
        assert any(name in issue and "hash changed" in issue for issue in issues)
        assert _pre_transaction_snapshot(root) == modified_snapshot
        assert read_artifact_ledger(root)["work_units"][key] == modified_unit

    for name in (S.AUTHORITY_FILE, S.WORKLIST_FILE, S.WORKLIST_PROJECTION_FILE):
        root = tmp_path / f"tampered_{name.replace('.', '_')}"
        config = _publish_pre_transaction(root)
        path = root / name
        path.write_bytes(path.read_bytes() + b"tampered\n")
        tampered_snapshot = _pre_transaction_snapshot(root)
        tampered_unit = read_artifact_ledger(root)["work_units"][key]
        with monkeypatch.context() as guard:
            _install_pre_replay_bombs(guard)
            issues = D._prepare_semantic_invariant_pre_boundary(root, config)
        assert issues
        assert _pre_transaction_snapshot(root) == tampered_snapshot
        assert read_artifact_ledger(root)["work_units"][key] == tampered_unit


def test_p1m_typed_fact_constituents_are_ready_for_distinct_p0af_verifier() -> None:
    """The P0-AF v2 substrate accepts facts without laundering findings."""
    fact_a = {
        "constituent_id": "MZO-FACT-ANCHOR",
        "constituent_kind": "EVIDENCE_FACT",
        "fact_digest": "a" * 64,
        "authority_digest": "c" * 64,
        "source_artifact": "authentication_role_authority.json",
    }
    fact_b = {
        "constituent_id": "MZO-FACT-DERIVED",
        "constituent_kind": "EVIDENCE_FACT",
        "fact_digest": "b" * 64,
        "authority_digest": "c" * 64,
        "source_artifact": "authentication_role_authority.json",
    }
    candidate = CompoundCandidate.create(
        chain_id="CH-9001",
        constituents=("MZO-FACT-ANCHOR", "MZO-FACT-DERIVED"),
        evidence_constituent_bindings=(fact_a, fact_b),
        severity_upgrade_justified=True,
        ordering_edges=(),
        preconditions=("Typed complementary facts require composition proof.",),
        postconditions=("Reachability and material harm must be verified.",),
        combined_impact_claim="Unverified arm-before-trust composition candidate.",
        proposed_severity="Medium",
        source_lineage=("arm_before_trust_composition_obligations.json",),
        coverage_lineage=("MZO-1", "MZO-FACT-ANCHOR", "MZO-FACT-DERIVED"),
        pipeline="SC",
        mode="thorough",
    )

    plan = compile_compound_work_plan(
        (candidate,),
        known_constituent_identities=(),
        known_evidence_constituents=(fact_a, fact_b),
    )

    assert plan.work_items[0].readiness is WorkReadiness.READY
    assert plan.to_record()["schema_version"] == "plamen.compound_work_plan.v2"
