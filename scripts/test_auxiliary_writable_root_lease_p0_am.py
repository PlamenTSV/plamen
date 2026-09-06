from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import auxiliary_writable_root_lease as aux


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _arm(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    tokens: list[str] | None = None,
) -> aux.AuxiliaryWritableRootLease:
    namespace = tmp_path / "provider-runtime"
    monkeypatch.setattr(aux, "_default_runtime_namespace", lambda: namespace)
    if tokens is not None:
        iterator = iter(tokens)
        monkeypatch.setattr(aux.secrets, "token_hex", lambda _size: next(iterator))
    reservation = aux.reserve_auxiliary_writable_root(
        attempt_id="attempt-001",
        purpose="claude-profile",
    )
    assert not hasattr(reservation, "root")
    assert "root" not in reservation.binding
    return reservation.arm(
        attempt_arm_sha256="a" * 64,
        process_scope_identity="scope-attempt-001",
    )


def _closure_token(
    monkeypatch: pytest.MonkeyPatch,
    lease: aux.AuxiliaryWritableRootLease,
) -> aux.ScopeClosureToken:
    class FakeOwnedProcessScope:
        persistent_identity = "scope-attempt-001"
        population_zero_proven = True
        closed = True
        emergency_closed = False

    monkeypatch.setattr(aux, "_owned_process_scope_type", lambda: FakeOwnedProcessScope)
    scope = FakeOwnedProcessScope()
    lease.bind_process_scope(scope)
    return aux.prove_owned_process_scope_closed(lease, scope)


def test_provider_selects_root_and_only_exposes_it_after_arm(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, tokens=["1" * 32])
    assert lease.root.is_dir()
    assert list(lease.root.iterdir()) == []
    assert lease.binding["lifecycle"] == {
        "before": "ABSENT",
        "after": "CREATED_EMPTY",
    }
    assert lease.binding["root"] == str(lease.root)
    assert lease.binding["attempt_arm_sha256"] == "a" * 64
    assert lease.binding["process_scope_identity"] == "scope-attempt-001"
    assert aux.replay_auxiliary_writable_root_binding(lease.binding)["valid"] is True

    with pytest.raises(TypeError):
        aux.reserve_auxiliary_writable_root(  # type: ignore[call-arg]
            attempt_id="attempt-001",
            purpose="claude-profile",
            root=tmp_path / "caller-controlled",
        )


def test_preexisting_sibling_and_case_collision_are_never_selected_or_overwritten(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    namespace = tmp_path / "provider-runtime"
    namespace.mkdir()
    sentinel = namespace / ("root-" + "1" * 32)
    sentinel.mkdir()
    marker = sentinel / "sentinel.txt"
    marker.write_text("do-not-touch", encoding="utf-8")
    case_alias = namespace / ("ROOT-" + "2" * 32)
    case_alias.mkdir()
    case_marker = case_alias / "case-sentinel.txt"
    case_marker.write_text("also-do-not-touch", encoding="utf-8")

    lease = _arm(
        monkeypatch,
        tmp_path,
        tokens=["1" * 32, "2" * 32, "3" * 32],
    )
    assert lease.root.name == "root-" + "3" * 32
    assert marker.read_text(encoding="utf-8") == "do-not-touch"
    assert case_marker.read_text(encoding="utf-8") == "also-do-not-touch"


def test_binding_replay_rejects_root_identity_replacement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, tokens=["4" * 32])
    binding = dict(lease.binding)
    lease.root.rmdir()
    lease.root.mkdir()

    replay = aux.replay_auxiliary_writable_root_binding(binding)
    assert replay["valid"] is False
    assert replay["reason"] == "ROOT_IDENTITY_DRIFT"


def test_revocation_requires_opaque_scope_closure_token(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, tokens=["5" * 32])

    with pytest.raises(TypeError):
        aux.ScopeClosureToken()  # type: ignore[call-arg]
    with pytest.raises(aux.AuxiliaryWritableRootLeaseError, match="closure token"):
        lease.revoke(object())  # type: ignore[arg-type]

    class FakeOwnedProcessScope:
        persistent_identity = "wrong-scope"
        population_zero_proven = True
        closed = True
        emergency_closed = False

    monkeypatch.setattr(aux, "_owned_process_scope_type", lambda: FakeOwnedProcessScope)
    with pytest.raises(aux.AuxiliaryWritableRootLeaseError, match="scope identity"):
        aux.prove_owned_process_scope_closed(lease, FakeOwnedProcessScope())

    FakeOwnedProcessScope.persistent_identity = "scope-attempt-001"
    FakeOwnedProcessScope.population_zero_proven = False
    lease.bind_process_scope(FakeOwnedProcessScope())
    with pytest.raises(aux.AuxiliaryWritableRootLeaseError, match="population-zero"):
        aux.prove_owned_process_scope_closed(lease, FakeOwnedProcessScope())


def test_prelaunch_abort_revokes_only_before_exact_scope_binding(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, tokens=["a" * 32])
    (lease.root / "profile-secret").write_text("secret", encoding="utf-8")
    receipt = lease.abort_before_process_scope(
        attempt_arm_sha256="a" * 64,
        process_scope_identity="scope-attempt-001",
        reason_code="CANCELLED_BEFORE_LAUNCH",
    )
    assert receipt["revocation_mode"] == "PRELAUNCH_ABORT"
    assert receipt["root_absent_after"] is True
    assert not lease.root.exists()
    assert aux.replay_auxiliary_writable_root_revocation(
        lease.binding,
        receipt,
    )["valid"] is True

    second = _arm(monkeypatch, tmp_path, tokens=["b" * 32])

    class FakeOwnedProcessScope:
        persistent_identity = "scope-attempt-001"
        population_zero_proven = False
        closed = False
        emergency_closed = False

    monkeypatch.setattr(
        aux,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    second.bind_process_scope(FakeOwnedProcessScope())
    with pytest.raises(
        aux.AuxiliaryWritableRootLeaseError,
        match="scope lifecycle began",
    ):
        second.abort_before_process_scope(
            attempt_arm_sha256="a" * 64,
            process_scope_identity="scope-attempt-001",
            reason_code="CANCELLED_BEFORE_LAUNCH",
        )


def test_prelaunch_abort_claim_is_typed_exact_and_blocks_bind(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, tokens=["c" * 32])

    class FakeOwnedProcessScope:
        persistent_identity = "scope-attempt-001"

    monkeypatch.setattr(
        aux,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    claim = lease.claim_prelaunch_abort(
        attempt_arm_sha256="a" * 64,
        process_scope_identity="scope-attempt-001",
        reason_code="CANCELLED_BEFORE_LAUNCH",
    )
    repeated = lease.claim_prelaunch_abort(
        attempt_arm_sha256="a" * 64,
        process_scope_identity="scope-attempt-001",
        reason_code="CANCELLED_BEFORE_LAUNCH",
    )

    assert type(claim) is aux.AuxiliaryPrelaunchAbortClaim
    assert repeated is claim
    assert lease.prelaunch_abort_claimed is True
    assert claim.binding["completion_authority"] is False
    assert aux.replay_auxiliary_prelaunch_abort_claim(
        claim.binding
    ) == claim.binding
    with pytest.raises(
        aux.AuxiliaryWritableRootLeaseError,
        match="prelaunch abort.*claimed",
    ):
        lease.bind_process_scope(FakeOwnedProcessScope())
    with pytest.raises(TypeError):
        aux.AuxiliaryPrelaunchAbortClaim()  # type: ignore[call-arg]

    receipt = lease.abort_before_process_scope(
        attempt_arm_sha256="a" * 64,
        process_scope_identity="scope-attempt-001",
        reason_code="CANCELLED_BEFORE_LAUNCH",
        claim=claim,
    )
    assert receipt["prelaunch_abort_claim_sha256"] == (
        claim.binding["claim_sha256"]
    )
    assert lease.abort_before_process_scope(
        attempt_arm_sha256="a" * 64,
        process_scope_identity="scope-attempt-001",
        reason_code="CANCELLED_BEFORE_LAUNCH",
        claim=claim,
    ) == receipt
    with pytest.raises(
        aux.AuxiliaryWritableRootLeaseError,
        match="no matching abort claim|different",
    ):
        lease.claim_prelaunch_abort(
            attempt_arm_sha256="a" * 64,
            process_scope_identity="scope-attempt-001",
            reason_code="DIFFERENT_ABORT",
        )
    assert lease.abort_before_process_scope(
        attempt_arm_sha256="a" * 64,
        process_scope_identity="scope-attempt-001",
        reason_code="OUTER_ROLLBACK_OBSERVATION",
    ) == receipt


def test_prelaunch_abort_claim_rejects_bound_or_cross_lease_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    first = _arm(monkeypatch, tmp_path, tokens=["d" * 32])
    second = _arm(monkeypatch, tmp_path, tokens=["e" * 32])

    class FakeOwnedProcessScope:
        persistent_identity = "scope-attempt-001"

    monkeypatch.setattr(
        aux,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    first.bind_process_scope(FakeOwnedProcessScope())
    with pytest.raises(
        aux.AuxiliaryWritableRootLeaseError,
        match="scope lifecycle began",
    ):
        first.claim_prelaunch_abort(
            attempt_arm_sha256="a" * 64,
            process_scope_identity="scope-attempt-001",
            reason_code="BOUND_ABORT_FORBIDDEN",
        )

    third = _arm(monkeypatch, tmp_path, tokens=["f" * 32])
    second_claim = second.claim_prelaunch_abort(
        attempt_arm_sha256="a" * 64,
        process_scope_identity="scope-attempt-001",
        reason_code="SECOND_ABORT",
    )
    third_claim = third.claim_prelaunch_abort(
        attempt_arm_sha256="a" * 64,
        process_scope_identity="scope-attempt-001",
        reason_code="THIRD_ABORT",
    )
    with pytest.raises(
        aux.AuxiliaryWritableRootLeaseError,
        match="not live",
    ):
        third.abort_before_process_scope(
            attempt_arm_sha256="a" * 64,
            process_scope_identity="scope-attempt-001",
            reason_code="THIRD_ABORT",
            claim=second_claim,
        )
    changed = dict(second_claim.binding)
    changed["reason_code"] = "FORGED"
    with pytest.raises(aux.AuxiliaryWritableRootLeaseError):
        aux.replay_auxiliary_prelaunch_abort_claim(changed)

    second.abort_before_process_scope(
        attempt_arm_sha256="a" * 64,
        process_scope_identity="scope-attempt-001",
        reason_code="SECOND_ABORT",
        claim=second_claim,
    )
    third.abort_before_process_scope(
        attempt_arm_sha256="a" * 64,
        process_scope_identity="scope-attempt-001",
        reason_code="THIRD_ABORT",
        claim=third_claim,
    )


def test_prelaunch_abort_cleanup_failure_retains_claim_and_denies_bind(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, tokens=["1" * 32])
    (lease.root / "profile-secret").write_text(
        "secret",
        encoding="utf-8",
    )

    class FakeOwnedProcessScope:
        persistent_identity = "scope-attempt-001"

    monkeypatch.setattr(
        aux,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    original_scan = aux._scan_cleanup_tree

    def fail_scan(_root: Path) -> object:
        raise aux.AuxiliaryWritableRootLeaseError(
            "fixture cleanup failure"
        )

    monkeypatch.setattr(aux, "_scan_cleanup_tree", fail_scan)
    with pytest.raises(
        aux.AuxiliaryWritableRootLeaseError,
        match="fixture cleanup failure",
    ):
        lease.abort_before_process_scope(
            attempt_arm_sha256="a" * 64,
            process_scope_identity="scope-attempt-001",
            reason_code="CLEANUP_RETRY",
        )
    assert lease.prelaunch_abort_claimed is True
    assert lease.root.exists()
    with pytest.raises(
        aux.AuxiliaryWritableRootLeaseError,
        match="prelaunch abort.*claimed",
    ):
        lease.bind_process_scope(FakeOwnedProcessScope())

    monkeypatch.setattr(aux, "_scan_cleanup_tree", original_scan)
    receipt = lease.abort_before_process_scope(
        attempt_arm_sha256="a" * 64,
        process_scope_identity="scope-attempt-001",
        reason_code="CLEANUP_RETRY",
    )
    assert receipt["revoked"] is True
    assert not lease.root.exists()


def test_no_follow_cleanup_removes_alias_not_target_and_receipt_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, tokens=["6" * 32])
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("survives", encoding="utf-8")
    nested = lease.root / "worker" / "nested"
    nested.mkdir(parents=True)
    (nested / "result.bin").write_bytes(b"worker-result")
    alias = lease.root / "escape"
    try:
        alias.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable")

    token = _closure_token(monkeypatch, lease)
    receipt = lease.revoke(token)
    assert not os.path.lexists(lease.root)
    assert sentinel.read_text(encoding="utf-8") == "survives"
    assert receipt["revoked"] is True
    assert receipt["root_absent_after"] is True
    assert receipt["aliases_unlinked"] == 1
    assert lease.revoke(token) == receipt
    assert aux.replay_auxiliary_writable_root_revocation(
        lease.binding,
        receipt,
    )["valid"] is True


def test_alias_escape_target_survives_even_when_root_is_replaced(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, tokens=["7" * 32])
    outside = tmp_path / "outside-root"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("survives", encoding="utf-8")
    lease.root.rmdir()
    try:
        lease.root.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable")

    token = _closure_token(monkeypatch, lease)
    with pytest.raises(
        aux.AuxiliaryWritableRootLeaseError,
        match="root identity",
    ):
        lease.revoke(token)
    assert sentinel.read_text(encoding="utf-8") == "survives"
    assert lease.root.is_symlink()


def test_bounded_cleanup_fails_closed_without_deleting_outside_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, tokens=["8" * 32])
    for index in range(4):
        (lease.root / f"{index}.txt").write_text(str(index), encoding="utf-8")
    outside = tmp_path / "external.txt"
    outside.write_text("safe", encoding="utf-8")
    monkeypatch.setattr(aux, "MAX_CLEANUP_ENTRIES", 3)

    token = _closure_token(monkeypatch, lease)
    with pytest.raises(aux.AuxiliaryWritableRootLeaseError, match="entry bound"):
        lease.revoke(token)
    assert lease.root.exists()
    assert outside.read_text(encoding="utf-8") == "safe"


def test_binding_and_receipt_digests_are_exact_and_secret_free(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, tokens=["9" * 32])
    binding = dict(lease.binding)
    digest = binding.pop("binding_sha256")
    assert digest == _sha(
        json.dumps(
            binding,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )

    token = _closure_token(monkeypatch, lease)
    receipt = lease.revoke(token)
    receipt_core = dict(receipt)
    receipt_digest = receipt_core.pop("receipt_sha256")
    assert receipt_digest == _sha(
        json.dumps(
            receipt_core,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    assert "token" not in json.dumps(receipt).casefold()
    assert "token" not in json.dumps(binding).casefold()

    caller_copy = lease.binding
    caller_copy["root_identity"]["st_ino"] = -1
    assert lease.binding["root_identity"]["st_ino"] != -1


def test_namespace_alias_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    real = tmp_path / "real-runtime"
    real.mkdir()
    alias = tmp_path / "runtime-alias"
    try:
        alias.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable")
    monkeypatch.setattr(aux, "_default_runtime_namespace", lambda: alias)

    reservation = aux.reserve_auxiliary_writable_root(
        attempt_id="attempt-001",
        purpose="claude-profile",
    )
    with pytest.raises(aux.AuxiliaryWritableRootLeaseError, match="namespace.*alias"):
        reservation.arm(
            attempt_arm_sha256="b" * 64,
            process_scope_identity="scope-attempt-001",
        )


def test_namespace_ancestor_alias_is_rejected_before_child_creation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    real = tmp_path / "external-runtime"
    real.mkdir()
    alias = tmp_path / "aliased-parent"
    try:
        alias.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable")
    requested = alias / "provider" / "auxiliary"
    monkeypatch.setattr(aux, "_default_runtime_namespace", lambda: requested)

    reservation = aux.reserve_auxiliary_writable_root(
        attempt_id="attempt-001",
        purpose="claude-profile",
    )
    with pytest.raises(aux.AuxiliaryWritableRootLeaseError, match="ancestor alias"):
        reservation.arm(
            attempt_arm_sha256="c" * 64,
            process_scope_identity="scope-attempt-001",
        )
    assert list(real.iterdir()) == []
