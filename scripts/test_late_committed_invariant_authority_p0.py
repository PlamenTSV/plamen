"""Late committed-invariant authority and failure propagation regressions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import enumeration_gate as E
import late_committed_invariant_authority as L


def _scratchpad(tmp_path: Path) -> Path:
    scratchpad = tmp_path / "project" / ".scratchpad"
    scratchpad.mkdir(parents=True)
    (scratchpad / "findings_inventory.md").write_text(
        "# Findings Inventory\n",
        encoding="utf-8",
    )
    return scratchpad


def _verifier_ci() -> str:
    return (
        "# Verification output\n\n"
        "committed-invariant [CI-V1]\n"
        "Locus: src/Vault.sol:L42\n"
        "Shape: CONSERVATION\n"
        "Assertion: total credited value equals total settled value\n"
        "Falsify Class: conservation\n"
        "Provenance: verifier refuted candidate V-1\n"
    )


def test_verifier_ci_gets_durable_next_run_human_review_authority(
    tmp_path: Path,
) -> None:
    scratchpad = _scratchpad(tmp_path)
    source = scratchpad / "verify_v_1.md"
    text = _verifier_ci()
    source.write_text(text, encoding="utf-8", newline="\n")

    result = E.recover_invariant_assertion_candidates(scratchpad)

    assert isinstance(result, L.LateCommittedInvariantRecoveryResult)
    assert result == 1
    assert result.emitted == 1
    assert len(result.authorities) == 1
    authority = result.authorities[0]
    assert isinstance(authority, L.LateCommittedInvariantAuthority)
    assert authority.authority == "HUMAN_REVIEW_NEXT_RUN"
    assert authority.status == "NEEDS_VERIFICATION"
    assert authority.source_artifact == "verify_v_1.md"
    assert authority.source_artifact_sha256 == hashlib.sha256(
        source.read_bytes()
    ).hexdigest()
    match = E._CI_BLOCK_RE.search(text)
    assert match is not None
    assert authority.committed_invariant_id == "CI-V1"
    assert authority.committed_invariant_sha256 == hashlib.sha256(
        match.group(0).encode("utf-8")
    ).hexdigest()
    assert authority.candidate_key == "INVARIANT:verify_v_1.md:CI-V1"

    payload = json.loads(result.ledger_path.read_text(encoding="utf-8"))
    replayed = L.replay_late_committed_invariant_ledger(payload)
    assert replayed == result.authorities
    assert payload["authority"] == "HUMAN_REVIEW_NEXT_RUN"
    assert payload["status"] == "NEEDS_VERIFICATION"
    assert "VERIFIED" not in result.ledger_path.read_text(encoding="utf-8")
    inventory = (scratchpad / "findings_inventory.md").read_text(
        encoding="utf-8"
    )
    assert "**Verdict**: NEEDS_VERIFICATION" in inventory
    assert "**Verdict**: VERIFIED" not in inventory


def test_compute_surfaces_injected_derivation_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad = _scratchpad(tmp_path)

    def fail_graph(_scratchpad: Path) -> object:
        raise OSError("injected graph failure")

    monkeypatch.setattr(E, "_load_graph", fail_graph)
    with pytest.raises(L.LateCommittedInvariantError) as caught:
        E.compute_invariant_assertion_candidates(scratchpad)
    assert caught.value.stage == "DERIVATION"
    assert caught.value.code == "CI_DERIVATION_FAILED"


def test_preverification_ci_keeps_current_verify_funnel_without_late_authority(
    tmp_path: Path,
) -> None:
    scratchpad = _scratchpad(tmp_path)
    (scratchpad / "exploration_skeptic_findings.md").write_text(
        _verifier_ci(), encoding="utf-8"
    )

    result = E.recover_invariant_assertion_candidates(scratchpad)

    assert result == 1
    assert result.authorities == ()
    payload = json.loads(result.ledger_path.read_text(encoding="utf-8"))
    assert payload["records"] == []
    inventory = (scratchpad / "findings_inventory.md").read_text(
        encoding="utf-8"
    )
    assert "**Verdict**: NEEDS_VERIFICATION" in inventory


def test_recovery_surfaces_injected_authority_persistence_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad = _scratchpad(tmp_path)
    (scratchpad / "verify_v_1.md").write_text(
        _verifier_ci(), encoding="utf-8"
    )

    def fail_persistence(*_args: object, **_kwargs: object) -> Path:
        raise OSError("injected ledger write failure")

    monkeypatch.setattr(
        E,
        "persist_late_committed_invariant_authorities",
        fail_persistence,
    )
    with pytest.raises(L.LateCommittedInvariantError) as caught:
        E.recover_invariant_assertion_candidates(scratchpad)
    assert caught.value.stage == "PERSISTENCE"
    assert caught.value.code == "LATE_CI_LEDGER_FAILED"


def test_recovery_rejects_zero_success_when_candidate_was_not_persisted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad = _scratchpad(tmp_path)
    (scratchpad / "verify_v_1.md").write_text(
        _verifier_ci(), encoding="utf-8"
    )
    monkeypatch.setattr(E, "_emit_candidates", lambda *_args, **_kwargs: 0)

    with pytest.raises(L.LateCommittedInvariantError) as caught:
        E.recover_invariant_assertion_candidates(scratchpad)
    assert caught.value.stage == "EMISSION"
    assert caught.value.code == "CANDIDATE_PERSISTENCE_UNPROVEN"


def test_recovery_wraps_injected_emitter_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad = _scratchpad(tmp_path)
    (scratchpad / "verify_v_1.md").write_text(
        _verifier_ci(), encoding="utf-8"
    )

    def fail_emitter(*_args: object, **_kwargs: object) -> int:
        raise OSError("injected candidate write failure")

    monkeypatch.setattr(E, "_emit_candidates", fail_emitter)
    with pytest.raises(L.LateCommittedInvariantError) as caught:
        E.recover_invariant_assertion_candidates(scratchpad)
    assert caught.value.stage == "EMISSION"
    assert caught.value.code == "CANDIDATE_EMISSION_FAILED"


def test_replay_rejects_current_run_verified_substitution(tmp_path: Path) -> None:
    scratchpad = _scratchpad(tmp_path)
    (scratchpad / "verify_v_1.md").write_text(
        _verifier_ci(), encoding="utf-8"
    )
    result = E.recover_invariant_assertion_candidates(scratchpad)
    changed = result.authorities[0].to_dict()
    changed["status"] = "VERIFIED"
    with pytest.raises(L.LateCommittedInvariantError) as caught:
        L.LateCommittedInvariantAuthority.replay(changed)
    assert caught.value.code == "CURRENT_RUN_AUTHORITY_FORBIDDEN"
