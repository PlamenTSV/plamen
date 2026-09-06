"""Depth generators finalize durably once, including artifact recovery."""

import json
from pathlib import Path

import enumeration_gate
import plamen_driver as D
import pytest
from plamen_mechanical import (
    promote_niche_to_inventory,
)


def _clean_niche_stub(scratchpad, result, calls=None):
    if calls is not None:
        calls.append("niche")
    # The postprocessor now requires the immutable lifecycle CAS, not a
    # self-authored mutable sidecar.  Exercise the real empty-denominator
    # producer while keeping orchestration counts controlled by ``result``.
    promote_niche_to_inventory(scratchpad)
    return result


def test_failed_depth_attempt_has_no_generator_side_effects(tmp_path, monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(
        D, "promote_niche_to_inventory",
        lambda _sp: calls.append("niche") or (0, 0),
    )
    monkeypatch.setattr(
        D, "promote_blind_spot_to_inventory",
        lambda _sp: calls.append("blind") or (0, 0),
    )
    monkeypatch.setattr(
        enumeration_gate, "run_enumeration_gate",
        lambda _sp: calls.append("enumeration") or {"emitted": 0},
    )
    monkeypatch.setattr(
        D, "_run_gate_v_for_phase",
        lambda _phase, _sp: calls.append("variant"),
    )

    result = D._run_accepted_depth_postprocessors(
        "depth", tmp_path, accepted=False, recovery_preflight=False
    )

    assert result["status"] == "DEFERRED_UNTIL_ACCEPTED"
    assert calls == []


def test_accepted_depth_attempt_runs_each_postprocessor_once(tmp_path, monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(
        D, "promote_niche_to_inventory",
        lambda _sp: _clean_niche_stub(_sp, (2, 0), calls),
    )
    monkeypatch.setattr(
        D, "promote_blind_spot_to_inventory",
        lambda _sp: calls.append("blind") or (1, 0),
    )
    monkeypatch.setattr(
        enumeration_gate, "run_enumeration_gate",
        lambda _sp: calls.append("enumeration")
        or {"obligations": 3, "emitted": 0},
    )
    monkeypatch.setattr(
        D, "_run_gate_v_for_phase",
        lambda _phase, _sp: calls.append("variant"),
    )

    result = D._run_accepted_depth_postprocessors(
        "depth", tmp_path, accepted=True, recovery_preflight=False
    )

    assert result["status"] == "FINALIZED"
    assert calls == ["niche", "blind", "enumeration", "variant"]

    receipt = json.loads(
        (tmp_path / "depth_finalization_receipt.json").read_text(encoding="utf-8")
    )
    assert receipt["status"] == "FINALIZED"
    assert set(receipt["processors"]) == {
        "niche_promotion",
        "blind_spot_recovery",
        "enumeration_gate",
        "variant_gate",
    }
    assert {row["status"] for row in receipt["processors"].values()} == {"COMPLETE"}


def test_driver_passes_canonical_run_dimensions_to_niche_lifecycle(
    tmp_path, monkeypatch
):
    observed: dict = {}

    def niche(scratchpad, **kwargs):
        observed.update(kwargs)
        return promote_niche_to_inventory(scratchpad, **kwargs)

    monkeypatch.setattr(D, "promote_niche_to_inventory", niche)
    monkeypatch.setattr(D, "promote_blind_spot_to_inventory", lambda _sp: (0, 0))
    monkeypatch.setattr(
        enumeration_gate, "run_enumeration_gate", lambda _sp: {"emitted": 0}
    )
    monkeypatch.setattr(
        D, "_run_gate_v_for_phase", lambda _phase, _sp: {"emitted": 0}
    )
    config = {
        "project_root": str(tmp_path),
        "_run_id": "run-r6-driver-integration",
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
    }
    result = D._run_accepted_depth_postprocessors(
        "depth",
        tmp_path,
        accepted=True,
        recovery_preflight=False,
        config=config,
    )

    assert result["status"] == "FINALIZED"
    assert observed == {
        "project_root": tmp_path,
        "run_id": config["_run_id"],
        "pipeline": "sc",
        "mode": "thorough",
        "ecosystem": "evm",
        "backend": "claude",
    }
    attestation = result["processors"]["niche_promotion"]["result"]
    assert attestation["identity_debt_lifecycle_run_id"] == config["_run_id"]
    assert attestation["identity_debt_lifecycle_authority_status"] == "CURRENT"


def _driver_context(root: Path, **overrides) -> dict:
    value = {
        "project_root": str(root),
        "_run_id": "run-r6-context-one",
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
    }
    value.update(overrides)
    return value


def _install_zero_depth_processors(monkeypatch, calls: list[str]) -> None:
    real = promote_niche_to_inventory

    def niche(scratchpad, **kwargs):
        calls.append("niche")
        return real(scratchpad, **kwargs)

    monkeypatch.setattr(D, "promote_niche_to_inventory", niche)
    monkeypatch.setattr(
        D, "promote_blind_spot_to_inventory",
        lambda _sp: calls.append("blind") or (0, 0),
    )
    monkeypatch.setattr(
        enumeration_gate, "run_enumeration_gate",
        lambda _sp: calls.append("enumeration") or {"emitted": 0},
    )
    monkeypatch.setattr(
        D, "_run_gate_v_for_phase",
        lambda _phase, _sp: calls.append("variant") or {"emitted": 0},
    )


def test_depth_finalization_same_typed_context_reuses(tmp_path, monkeypatch):
    calls: list[str] = []
    _install_zero_depth_processors(monkeypatch, calls)
    config = _driver_context(tmp_path)
    first = D._run_accepted_depth_postprocessors(
        "depth", tmp_path, accepted=True, recovery_preflight=False, config=config,
    )
    second = D._run_accepted_depth_postprocessors(
        "depth", tmp_path, accepted=True, recovery_preflight=True, config=config,
    )
    assert first["status"] == second["status"] == "FINALIZED"
    assert second["reused"] is True
    assert calls == ["niche", "blind", "enumeration", "variant"]
    assert second["execution_context_sha256"]
    niche = second["processors"]["niche_promotion"]["result"]
    assert niche["identity_debt_lifecycle_context_sha256"] == second[
        "execution_context_sha256"
    ]


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("_run_id", "run-r6-context-two"),
        ("project_root", "other-project"),
        ("pipeline", "l1"),
        ("mode", "core"),
        ("language", "soroban"),
        ("cli_backend", "codex"),
    ],
)
def test_depth_finalization_never_reuses_across_typed_context(
    tmp_path, monkeypatch, field, replacement
):
    calls: list[str] = []
    _install_zero_depth_processors(monkeypatch, calls)
    first_config = _driver_context(tmp_path)
    first = D._run_accepted_depth_postprocessors(
        "depth", tmp_path, accepted=True, recovery_preflight=False,
        config=first_config,
    )
    assert first["status"] == "FINALIZED"
    second_config = dict(first_config)
    if field == "project_root":
        other = tmp_path / replacement
        other.mkdir()
        second_config[field] = str(other)
    else:
        second_config[field] = replacement
    second = D._run_accepted_depth_postprocessors(
        "depth", tmp_path, accepted=True, recovery_preflight=True,
        config=second_config,
    )
    assert second.get("reused") is not True
    assert second["execution_context_sha256"] != first[
        "execution_context_sha256"
    ]
    assert calls.count("niche") == 2
    assert second["processors"]["niche_promotion"]["status"] != "COMPLETE"


def test_recovery_preflight_finalizes_before_checkpoint_boundary(tmp_path, monkeypatch):
    """Accepted recovered artifacts may not defer the mutating finalizers."""
    (tmp_path / "depth_token_flow_findings.md").write_text(
        "# accepted depth output\n", encoding="utf-8"
    )
    calls: list[str] = []
    monkeypatch.setattr(
        D, "promote_niche_to_inventory",
        lambda _sp: _clean_niche_stub(_sp, (0, 0), calls),
    )
    monkeypatch.setattr(
        D, "promote_blind_spot_to_inventory",
        lambda _sp: calls.append("blind") or (0, 0),
    )
    monkeypatch.setattr(
        enumeration_gate, "run_enumeration_gate",
        lambda _sp: calls.append("enumeration") or {"emitted": 0},
    )
    monkeypatch.setattr(
        D, "_run_gate_v_for_phase",
        lambda _phase, _sp: calls.append("variant") or {"emitted": 0},
    )

    result = D._run_accepted_depth_postprocessors(
        "depth", tmp_path, accepted=True, recovery_preflight=True
    )

    assert result["status"] == "FINALIZED"
    assert calls == ["niche", "blind", "enumeration", "variant"]


def test_matching_receipt_makes_resume_idempotent(tmp_path, monkeypatch):
    (tmp_path / "depth_token_flow_findings.md").write_text(
        "# immutable accepted depth output\n", encoding="utf-8"
    )
    calls: list[str] = []
    monkeypatch.setattr(
        D, "promote_niche_to_inventory",
        lambda _sp: _clean_niche_stub(_sp, (0, 0), calls),
    )
    monkeypatch.setattr(
        D, "promote_blind_spot_to_inventory",
        lambda _sp: calls.append("blind") or (0, 0),
    )
    monkeypatch.setattr(
        enumeration_gate, "run_enumeration_gate",
        lambda _sp: calls.append("enumeration") or {"emitted": 0},
    )
    monkeypatch.setattr(
        D, "_run_gate_v_for_phase",
        lambda _phase, _sp: calls.append("variant") or {"emitted": 0},
    )

    first = D._run_accepted_depth_postprocessors(
        "depth", tmp_path, accepted=True, recovery_preflight=False
    )
    second = D._run_accepted_depth_postprocessors(
        "depth", tmp_path, accepted=True, recovery_preflight=True
    )

    assert first["status"] == "FINALIZED"
    assert second["status"] == "FINALIZED"
    assert second["reused"] is True
    assert calls == ["niche", "blind", "enumeration", "variant"]


def test_changed_accepted_source_invalidates_receipt_and_replays(tmp_path, monkeypatch):
    source = tmp_path / "depth_token_flow_findings.md"
    source.write_text("# accepted depth output v1\n", encoding="utf-8")
    calls: list[str] = []
    monkeypatch.setattr(
        D, "promote_niche_to_inventory",
        lambda _sp: _clean_niche_stub(_sp, (0, 0), calls),
    )
    monkeypatch.setattr(
        D, "promote_blind_spot_to_inventory",
        lambda _sp: calls.append("blind") or (0, 0),
    )
    monkeypatch.setattr(
        enumeration_gate, "run_enumeration_gate",
        lambda _sp: calls.append("enumeration") or {"emitted": 0},
    )
    monkeypatch.setattr(
        D, "_run_gate_v_for_phase",
        lambda _phase, _sp: calls.append("variant") or {"emitted": 0},
    )

    first = D._run_accepted_depth_postprocessors(
        "depth", tmp_path, accepted=True, recovery_preflight=False
    )
    source.write_text("# accepted depth output v2\n", encoding="utf-8")
    second = D._run_accepted_depth_postprocessors(
        "depth", tmp_path, accepted=True, recovery_preflight=True
    )

    assert first["source_digest"] != second["source_digest"]
    assert second["reused"] is False
    assert calls == [
        "niche", "blind", "enumeration", "variant",
        "niche", "blind", "enumeration", "variant",
    ]


def test_partial_matching_receipt_executes_only_missing_processors(tmp_path, monkeypatch):
    (tmp_path / "depth_token_flow_findings.md").write_text(
        "# immutable accepted depth output\n", encoding="utf-8"
    )
    digest, sources = D._depth_finalization_source_digest(tmp_path)
    (tmp_path / "depth_finalization_receipt.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "phase": "depth",
                "source_digest": digest,
                "source_files": sources,
                "status": "IN_PROGRESS",
                "processors": {
                    "niche_promotion": {"status": "COMPLETE", "result": {}},
                },
            }
        ),
        encoding="utf-8",
    )
    calls: list[str] = []
    monkeypatch.setattr(
        D, "promote_niche_to_inventory",
        lambda _sp: _clean_niche_stub(_sp, (0, 0), calls),
    )
    monkeypatch.setattr(
        D, "promote_blind_spot_to_inventory",
        lambda _sp: calls.append("blind") or (0, 0),
    )
    monkeypatch.setattr(
        enumeration_gate, "run_enumeration_gate",
        lambda _sp: calls.append("enumeration") or {"emitted": 0},
    )
    monkeypatch.setattr(
        D, "_run_gate_v_for_phase",
        lambda _phase, _sp: calls.append("variant") or {"emitted": 0},
    )

    result = D._run_accepted_depth_postprocessors(
        "depth", tmp_path, accepted=True, recovery_preflight=True
    )

    assert result["status"] == "FINALIZED"
    # The legacy COMPLETE niche row carries no zero-debt attestation binding,
    # so it is intentionally invalidated and replayed before the missing rows.
    assert calls == ["niche", "blind", "enumeration", "variant"]


def test_processor_exception_is_durable_human_review_not_log_only(tmp_path, monkeypatch):
    (tmp_path / "depth_token_flow_findings.md").write_text(
        "# immutable accepted depth output\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        D, "promote_niche_to_inventory",
        lambda _sp: (_ for _ in ()).throw(RuntimeError("synthetic failure")),
    )
    monkeypatch.setattr(D, "promote_blind_spot_to_inventory", lambda _sp: (0, 0))
    monkeypatch.setattr(
        enumeration_gate, "run_enumeration_gate", lambda _sp: {"emitted": 0}
    )
    monkeypatch.setattr(
        D, "_run_gate_v_for_phase", lambda _phase, _sp: {"emitted": 0}
    )

    result = D._run_accepted_depth_postprocessors(
        "depth", tmp_path, accepted=True, recovery_preflight=True
    )

    assert result["status"] == "DEGRADED_HUMAN_REVIEW"
    receipt = json.loads(
        (tmp_path / "depth_finalization_receipt.json").read_text(encoding="utf-8")
    )
    failed = receipt["processors"]["niche_promotion"]
    assert failed["status"] == "FAILED"
    assert "synthetic failure" in failed["error"]
    review = (tmp_path / "depth_finalization_human_review.md").read_text(
        encoding="utf-8"
    )
    assert "niche_promotion" in review
    assert "synthetic failure" in review


def test_finalized_receipt_replays_when_structural_referent_is_deleted(
    tmp_path, monkeypatch
):
    (tmp_path / "depth_token_flow_findings.md").write_text(
        "# immutable accepted depth output\n", encoding="utf-8"
    )
    inventory = tmp_path / "findings_inventory.md"
    inventory.write_text(
        "# Findings Inventory\n\nDescription mentions NICHE-1 only.\n",
        encoding="utf-8",
    )
    calls: list[str] = []

    def niche(_sp):
        calls.append("niche")
        if "**Source IDs**: NICHE-1" not in inventory.read_text(encoding="utf-8"):
            inventory.write_text(
                inventory.read_text(encoding="utf-8").rstrip()
                + "\n\n## Niche-Promoted Findings\n\n"
                "### Finding [INV-901]: promoted niche row\n"
                "**Source IDs**: NICHE-1\n**Severity**: Medium\n",
                encoding="utf-8",
            )
        _clean_niche_stub(_sp, (0, 0))
        return (1, 1)

    monkeypatch.setattr(D, "promote_niche_to_inventory", niche)
    monkeypatch.setattr(D, "promote_blind_spot_to_inventory", lambda _sp: (0, 0))
    monkeypatch.setattr(
        enumeration_gate, "run_enumeration_gate", lambda _sp: {"emitted": 0}
    )
    monkeypatch.setattr(
        D, "_run_gate_v_for_phase", lambda _phase, _sp: {"emitted": 0}
    )

    first = D._run_accepted_depth_postprocessors(
        "depth", tmp_path, accepted=True, recovery_preflight=False
    )
    assert first["status"] == "FINALIZED"
    # Delete the actual finding block while leaving the raw depth source and
    # finalization receipt unchanged. A prose mention must not satisfy reuse.
    inventory.write_text(
        "# Findings Inventory\n\nDescription mentions NICHE-1 only.\n",
        encoding="utf-8",
    )
    second = D._run_accepted_depth_postprocessors(
        "depth", tmp_path, accepted=True, recovery_preflight=True
    )

    assert second["status"] == "FINALIZED"
    assert second["reused"] is False
    assert calls == ["niche", "niche"]
    assert "**Source IDs**: NICHE-1" in inventory.read_text(encoding="utf-8")


def test_swallowed_error_status_is_failed_and_durable(tmp_path, monkeypatch):
    (tmp_path / "depth_token_flow_findings.md").write_text(
        "# immutable accepted depth output\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        D,
        "promote_niche_to_inventory",
        lambda _sp: _clean_niche_stub(_sp, (0, 0)),
    )
    monkeypatch.setattr(D, "promote_blind_spot_to_inventory", lambda _sp: (0, 0))
    monkeypatch.setattr(
        enumeration_gate,
        "run_enumeration_gate",
        lambda _sp: {"status": "error", "emitted": 0, "error": "swallowed"},
    )
    monkeypatch.setattr(
        D, "_run_gate_v_for_phase", lambda _phase, _sp: {"emitted": 0}
    )

    result = D._run_accepted_depth_postprocessors(
        "depth", tmp_path, accepted=True, recovery_preflight=False
    )

    assert result["status"] == "DEGRADED_HUMAN_REVIEW"
    row = result["processors"]["enumeration_gate"]
    assert row["status"] == "FAILED"
    assert "swallowed" in row["error"]


def test_invalidated_referent_that_helper_does_not_restore_stays_failed(
    tmp_path, monkeypatch
):
    (tmp_path / "depth_token_flow_findings.md").write_text(
        "# immutable accepted depth output\n", encoding="utf-8"
    )
    inventory = tmp_path / "findings_inventory.md"
    inventory.write_text(
        "# Inventory\n\n## Niche-Promoted Findings\n\n"
        "### Finding [INV-990]: niche\n**Source IDs**: NSC-9\n",
        encoding="utf-8",
    )
    # Seed a finalized positive outcome directly; all other processors are
    # zero-output complete rows.
    digest, sources = D._depth_finalization_source_digest(tmp_path)
    processors = {
        name: {
            "status": "COMPLETE",
            "result": ({"appended": 1} if name == "niche_promotion" else {"emitted": 0}),
            "outcome": (
                {"inventory_referents": [{"finding_id": "INV-990", "source_ids": ["NSC-9"]}]}
                if name == "niche_promotion"
                else {"inventory_referents": []}
            ),
        }
        for name in (
            "niche_promotion", "blind_spot_recovery", "enumeration_gate", "variant_gate"
        )
    }
    (tmp_path / "depth_finalization_receipt.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "phase": "depth",
                "source_digest": digest,
                "source_files": sources,
                "status": "FINALIZED",
                "processors": processors,
            }
        ),
        encoding="utf-8",
    )
    inventory.write_text("# Inventory\n\n", encoding="utf-8")
    monkeypatch.setattr(
        D,
        "promote_niche_to_inventory",
        lambda _sp: _clean_niche_stub(_sp, (1, 0)),
    )
    monkeypatch.setattr(D, "promote_blind_spot_to_inventory", lambda _sp: (0, 0))
    monkeypatch.setattr(enumeration_gate, "run_enumeration_gate", lambda _sp: {"emitted": 0})
    monkeypatch.setattr(D, "_run_gate_v_for_phase", lambda _phase, _sp: {"emitted": 0})

    result = D._run_accepted_depth_postprocessors(
        "depth", tmp_path, accepted=True, recovery_preflight=True
    )

    assert result["status"] == "DEGRADED_HUMAN_REVIEW"
    assert result["processors"]["niche_promotion"]["status"] == "FAILED"
    assert "did not restore" in result["processors"]["niche_promotion"]["error"]


def test_source_digest_binds_inventory_base_and_function_summary_only(tmp_path):
    inventory = tmp_path / "findings_inventory.md"
    inventory.write_text(
        "# Inventory\n\n## Findings\n\n"
        "### Finding [INV-001]: base\n**Source IDs**: B-1\n\n"
        "## Niche-Promoted Findings\n\n"
        "### Finding [INV-002]: owned\n**Source IDs**: NSC-1\n",
        encoding="utf-8",
    )
    summary = tmp_path / "function_summary.md"
    summary.write_text("# Functions\nA\n", encoding="utf-8")
    first, sources = D._depth_finalization_source_digest(tmp_path)
    assert "function_summary.md" in sources
    assert "findings_inventory.md#pre-finalization-base" in sources

    inventory.write_text(
        inventory.read_text(encoding="utf-8").replace("owned", "owned changed"),
        encoding="utf-8",
    )
    owned_edit, _ = D._depth_finalization_source_digest(tmp_path)
    assert owned_edit == first

    inventory.write_text(
        inventory.read_text(encoding="utf-8").replace("base", "base changed"),
        encoding="utf-8",
    )
    base_edit, _ = D._depth_finalization_source_digest(tmp_path)
    assert base_edit != first

    summary.write_text("# Functions\nB\n", encoding="utf-8")
    function_edit, _ = D._depth_finalization_source_digest(tmp_path)
    assert function_edit != base_edit


def test_niche_promotion_self_heals_receipt_loss_and_crash_window(tmp_path):
    inventory = tmp_path / "findings_inventory.md"
    inventory.write_text("# Findings Inventory\n", encoding="utf-8")
    (tmp_path / "niche_semantic_findings.md").write_text(
        "### Finding [NSC-1]: structural niche\n"
        "**Severity**: Medium\n"
        "**Location**: contracts/X.sol:10\n"
        "**Description**: semantic drift\n"
        "**Impact**: incorrect accounting\n",
        encoding="utf-8",
    )
    assert promote_niche_to_inventory(tmp_path) == (1, 1)
    receipt = tmp_path / "niche_promotion_receipt.md"
    receipt.unlink()

    # Append landed but receipt did not: inventory structure prevents a dup.
    assert promote_niche_to_inventory(tmp_path) == (1, 0)
    assert inventory.read_text(encoding="utf-8").count("NSC-1") == 1
    assert receipt.exists()
    assert "NSC-1 -> INV-" in receipt.read_text(encoding="utf-8")

    # Receipt exists but append vanished: structure, not stale receipt, causes
    # replay and restores the real finding.
    inventory.write_text("# Findings Inventory\n", encoding="utf-8")
    assert promote_niche_to_inventory(tmp_path) == (1, 1)
    assert "**Source IDs**: NSC-1" in inventory.read_text(encoding="utf-8")


def _write_unknown_niche_identity_debt(tmp_path) -> None:
    (tmp_path / "findings_inventory.md").write_text(
        "# Findings Inventory\n", encoding="utf-8"
    )
    (tmp_path / "niche_unknown_findings.md").write_text(
        "## Finding [ZZQ-7]: unresolved producer identity\n"
        "**Severity**: Medium\n"
        "**Location**: src/Module.sol:L7\n"
        "**Description**: The candidate must remain visible.\n"
        "**Impact**: Silent loss would reduce recall.\n",
        encoding="utf-8",
    )
    assert promote_niche_to_inventory(tmp_path) == (1, 0)


def _seed_complete_depth_finalization_receipt(tmp_path) -> None:
    digest, sources = D._depth_finalization_source_digest(tmp_path)
    processors = {
        name: {
            "status": "COMPLETE",
            "result": {},
            "outcome": {"inventory_referents": []},
        }
        for name in (
            "niche_promotion",
            "blind_spot_recovery",
            "enumeration_gate",
            "variant_gate",
        )
    }
    (tmp_path / "depth_finalization_receipt.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "phase": "depth",
                "source_digest": digest,
                "source_files": sources,
                "status": "FINALIZED",
                "processors": processors,
            }
        ),
        encoding="utf-8",
    )


def test_niche_identity_debt_degrades_accepted_depth_boundary(
    tmp_path, monkeypatch
):
    _write_unknown_niche_identity_debt(tmp_path)
    monkeypatch.setattr(D, "promote_blind_spot_to_inventory", lambda _sp: (0, 0))
    monkeypatch.setattr(
        enumeration_gate, "run_enumeration_gate", lambda _sp: {"emitted": 0}
    )
    monkeypatch.setattr(
        D, "_run_gate_v_for_phase", lambda _phase, _sp: {"emitted": 0}
    )

    result = D._run_accepted_depth_postprocessors(
        "depth", tmp_path, accepted=True, recovery_preflight=False
    )

    assert result["status"] == "DEGRADED_HUMAN_REVIEW"
    failed = result["processors"]["niche_promotion"]
    assert failed["status"] == "FAILED"
    assert failed["result"]["artifact"] == "niche_identity_debt.json"
    assert failed["result"]["blocking_debt_count"] == 1
    assert failed["result"]["required_action"] == "RECONCILE_PRODUCER_IDENTITY"


def test_niche_identity_debt_invalidates_clean_receipt_reuse(
    tmp_path, monkeypatch
):
    _write_unknown_niche_identity_debt(tmp_path)
    _seed_complete_depth_finalization_receipt(tmp_path)
    monkeypatch.setattr(D, "promote_blind_spot_to_inventory", lambda _sp: (0, 0))
    monkeypatch.setattr(
        enumeration_gate, "run_enumeration_gate", lambda _sp: {"emitted": 0}
    )
    monkeypatch.setattr(
        D, "_run_gate_v_for_phase", lambda _phase, _sp: {"emitted": 0}
    )

    result = D._run_accepted_depth_postprocessors(
        "depth", tmp_path, accepted=True, recovery_preflight=True
    )

    assert result["status"] == "DEGRADED_HUMAN_REVIEW"
    assert result["reused"] is False
    assert "niche_promotion" in result["invalidated_processors"]


def test_corrupt_niche_identity_debt_cannot_authorize_clean_reuse(tmp_path):
    _write_unknown_niche_identity_debt(tmp_path)
    sidecar = tmp_path / "niche_identity_debt.json"
    payload = json.loads(sidecar.read_text(encoding="utf-8"))
    payload["artifact_sha256"] = "0" * 64
    sidecar.write_text(json.dumps(payload), encoding="utf-8")
    _seed_complete_depth_finalization_receipt(tmp_path)

    result = D._run_accepted_depth_postprocessors(
        "depth", tmp_path, accepted=True, recovery_preflight=True
    )

    assert result["status"] == "DEGRADED_HUMAN_REVIEW"
    assert result["reused"] is False
    assert "invalid niche_identity_debt.json" in (
        result["processors"]["niche_promotion"]["error"]
    )


def test_clean_niche_run_binds_zero_debt_attestation_and_recreates_if_deleted(
    tmp_path, monkeypatch
):
    (tmp_path / "findings_inventory.md").write_text(
        "# Findings Inventory\n", encoding="utf-8"
    )
    monkeypatch.setattr(D, "promote_blind_spot_to_inventory", lambda _sp: (0, 0))
    monkeypatch.setattr(
        enumeration_gate, "run_enumeration_gate", lambda _sp: {"emitted": 0}
    )
    monkeypatch.setattr(
        D, "_run_gate_v_for_phase", lambda _phase, _sp: {"emitted": 0}
    )

    first = D._run_accepted_depth_postprocessors(
        "depth", tmp_path, accepted=True, recovery_preflight=False
    )
    sidecar = tmp_path / "niche_identity_debt.json"

    assert first["status"] == "FINALIZED"
    assert sidecar.is_file()
    attestation = json.loads(sidecar.read_text(encoding="utf-8"))
    assert attestation["blocking_debt_count"] == 0
    first_result = first["processors"]["niche_promotion"]["result"]
    assert first_result["identity_debt_artifact"] == sidecar.name
    assert first_result["identity_debt_sha256"] == attestation["artifact_sha256"]

    sidecar.unlink()
    second = D._run_accepted_depth_postprocessors(
        "depth", tmp_path, accepted=True, recovery_preflight=True
    )

    assert second["status"] == "FINALIZED"
    assert second["reused"] is False
    assert "niche_promotion" in second["invalidated_processors"]
    assert sidecar.is_file()


def test_niche_reuse_binds_live_snapshot_denominator_and_ordered_action_set(
    tmp_path,
):
    from plamen_mechanical import read_niche_identity_debt_sidecar

    (tmp_path / "findings_inventory.md").write_text(
        "# Findings Inventory\n", encoding="utf-8"
    )
    source = tmp_path / "niche_runtime_findings.md"
    original = (
        "## Finding [SC-61]: runtime-bound action\n"
        "Severity: Medium\n"
        "Location: src/Runtime.sol:L61\n"
        "Description: Clean reuse must bind the exact live action bytes.\n"
    ).encode("utf-8")
    source.write_bytes(original)
    assert promote_niche_to_inventory(tmp_path) == (1, 1)
    sidecar = read_niche_identity_debt_sidecar(tmp_path)
    assert sidecar is not None

    result = {
        "parsed": 1,
        "appended": 0,
        **D._niche_identity_debt_attestation(sidecar),
    }
    row = {
        "status": "COMPLETE",
        "result": result,
        "outcome": {"inventory_referents": []},
    }
    assert D._depth_processor_outcome_valid(tmp_path, "niche_promotion", row) == (
        True,
        "",
    )

    for field in (
        "identity_debt_denominator_complete",
        "identity_debt_action_count",
        "identity_debt_action_set_sha256",
        "identity_debt_live_action_denominator_sha256",
        "identity_debt_source_namespace",
        "identity_debt_source_namespace_sha256",
        "identity_debt_source_snapshots",
        "identity_debt_lifecycle_count",
        "identity_debt_lifecycle_set_sha256",
        "identity_debt_removed_action_count",
        "identity_debt_removed_action_set_sha256",
        "identity_debt_lifecycle_authority_schema",
        "identity_debt_lifecycle_authority_status",
        "identity_debt_lifecycle_audit_instance_id",
        "identity_debt_lifecycle_run_id",
        "identity_debt_lifecycle_pipeline",
        "identity_debt_lifecycle_mode",
        "identity_debt_lifecycle_ecosystem",
        "identity_debt_lifecycle_backend",
        "identity_debt_lifecycle_phase",
        "identity_debt_lifecycle_producer",
        "identity_debt_lifecycle_context_sha256",
        "identity_debt_lifecycle_attempt_ordinal",
        "identity_debt_lifecycle_head_sha256",
        "identity_debt_lifecycle_action_denominator_sha256",
        "identity_debt_lifecycle_transition_set_sha256",
        "identity_debt_lifecycle_history_set_sha256",
        "identity_debt_lifecycle_blocking_count",
        "identity_debt_lifecycle_delivery_record_count",
        "identity_debt_lifecycle_delivery_record_set_sha256",
        "identity_debt_validation_status",
    ):
        stale = json.loads(json.dumps(row))
        stale["result"].pop(field)
        valid, reason = D._depth_processor_outcome_valid(
            tmp_path, "niche_promotion", stale
        )
        assert valid is False
        assert field in reason

    mutated = original.replace(b"Clean", b"Stale")
    assert len(mutated) == len(original)
    source.write_bytes(mutated)
    valid, reason = D._depth_processor_outcome_valid(
        tmp_path, "niche_promotion", row
    )
    assert valid is False
    assert "live source" in reason
