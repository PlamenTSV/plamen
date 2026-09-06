from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

import auxiliary_writable_root_lease as aux


def _reservation() -> aux.AuxiliaryWritableRootReservation:
    return aux.reserve_auxiliary_writable_root(
        attempt_id="attempt-recovery-001",
        purpose="claude-profile",
    )


def _arm(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    token: str = "1" * 32,
) -> aux.AuxiliaryWritableRootLease:
    monkeypatch.setattr(
        aux,
        "_default_runtime_namespace",
        lambda: tmp_path / "provider-runtime",
    )
    monkeypatch.setattr(aux.secrets, "token_hex", lambda _size: token)
    return _reservation().arm(
        attempt_arm_sha256="a" * 64,
        process_scope_identity="scope-recovery-001",
    )


def _scope(monkeypatch: pytest.MonkeyPatch, lease: aux.AuxiliaryWritableRootLease):
    class FakeOwnedProcessScope:
        persistent_identity = "scope-recovery-001"
        population_zero_proven = True
        closed = True
        emergency_closed = False

    monkeypatch.setattr(
        aux,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    scope = FakeOwnedProcessScope()
    lease.bind_process_scope(scope)
    return scope


def _dead_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        aux,
        "_provider_owner_status",
        lambda _owner: {
            "status": "PROVEN_DEAD",
            "reason": "TEST_PROVIDER_EXITED",
        },
    )


def test_arm_persists_intent_before_creating_or_exposing_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        aux,
        "_default_runtime_namespace",
        lambda: tmp_path / "provider-runtime",
    )
    monkeypatch.setattr(aux.secrets, "token_hex", lambda _size: "2" * 32)
    real_create = aux._create_reserved_empty_root
    observed: dict[str, object] = {}

    def inspect_before_create(namespace: Path, root: Path):
        records = list((namespace / aux.REGISTRY_DIRECTORY_NAME).glob("*.json"))
        assert len(records) == 1
        replay = aux.replay_auxiliary_writable_root_journal(records[0])
        assert replay["valid"] is True
        assert replay["state"] == "INTENT"
        assert replay["root"] == str(root)
        assert not os.path.lexists(root)
        observed["intent"] = True
        return real_create(namespace, root)

    monkeypatch.setattr(aux, "_create_reserved_empty_root", inspect_before_create)
    lease = _reservation().arm(
        attempt_arm_sha256="a" * 64,
        process_scope_identity="scope-recovery-001",
    )
    assert observed == {"intent": True}
    replay = aux.replay_auxiliary_writable_root_journal(lease.journal_path)
    assert replay["valid"] is True
    assert replay["state"] == "ARMED_UNBOUND"
    assert replay["binding_sha256"] == lease.binding["binding_sha256"]


def test_scope_binding_and_terminal_revocation_are_durable_and_idempotent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, token="3" * 32)
    scope = _scope(monkeypatch, lease)
    bound = aux.replay_auxiliary_writable_root_journal(lease.journal_path)
    assert bound["valid"] is True
    assert bound["state"] == "ARMED_BOUND"
    assert bound["process_scope_identity"] == scope.persistent_identity

    token = aux.prove_owned_process_scope_closed(lease, scope)
    receipt = lease.revoke(token)
    terminal = aux.replay_auxiliary_writable_root_journal(lease.journal_path)
    assert terminal["valid"] is True
    assert terminal["state"] == "TERMINAL"
    assert terminal["receipt_sha256"] == receipt["receipt_sha256"]
    assert lease.revoke(token) == receipt

    report = aux.reconcile_auxiliary_writable_root_leases()
    assert report["complete"] is True
    # Normal revocation compacts terminal evidence immediately, so startup
    # reconciliation has no active-registry terminal left to scan.
    assert report["terminal"] == 0
    assert report["recovered"] == 0
    report_core = dict(report)
    report_digest = report_core.pop("report_sha256")
    assert report_digest == aux._digest_mapping(report_core)


def test_dead_owner_recovers_claimed_prelaunch_abort_as_unbound(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, token="b" * 32)
    (lease.root / "credential-copy").write_text(
        "secret",
        encoding="utf-8",
    )
    claim = lease.claim_prelaunch_abort(
        attempt_arm_sha256="a" * 64,
        process_scope_identity="scope-recovery-001",
        reason_code="OWNER_DIED_AFTER_CLAIM",
    )
    journal = aux._load_journal_record(lease.journal_path)
    assert journal["state"] == "ARMED_UNBOUND"
    assert journal["scope_binding"] == {
        "state": "PRELAUNCH_ABORT_CLAIMED",
        "claim_sha256": claim.binding["claim_sha256"],
    }

    _dead_owner(monkeypatch)

    def forbid_scope_recovery(_identity: str) -> dict[str, object]:
        raise AssertionError(
            "claimed prelaunch abort cannot have a bound process scope"
        )

    monkeypatch.setattr(
        aux,
        "_recover_persisted_scope",
        forbid_scope_recovery,
    )
    report = aux.reconcile_auxiliary_writable_root_leases()

    assert report["complete"] is True
    assert report["recovered"] == 1
    assert not lease.root.exists()
    replay = aux.replay_auxiliary_writable_root_journal(
        lease.journal_path
    )
    assert replay["valid"] is True
    assert replay["state"] == "TERMINAL"
    assert replay["prior_state"] == "ARMED_UNBOUND"


def test_terminal_prelaunch_abort_rejects_cross_lease_claim_splice(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    first = _arm(monkeypatch, tmp_path, token="c" * 32)
    second = _arm(monkeypatch, tmp_path, token="d" * 32)
    first_claim = first.claim_prelaunch_abort(
        attempt_arm_sha256="a" * 64,
        process_scope_identity="scope-recovery-001",
        reason_code="TERMINAL_SPLICE_FIXTURE",
    )
    second_claim = second.claim_prelaunch_abort(
        attempt_arm_sha256="a" * 64,
        process_scope_identity="scope-recovery-001",
        reason_code="TERMINAL_SPLICE_FIXTURE",
    )
    first.abort_before_process_scope(
        attempt_arm_sha256="a" * 64,
        process_scope_identity="scope-recovery-001",
        reason_code="TERMINAL_SPLICE_FIXTURE",
        claim=first_claim,
    )
    second.abort_before_process_scope(
        attempt_arm_sha256="a" * 64,
        process_scope_identity="scope-recovery-001",
        reason_code="TERMINAL_SPLICE_FIXTURE",
        claim=second_claim,
    )

    archived = aux._terminal_archive_path_for_logical(
        first.journal_path
    )
    terminal = aux._load_archived_terminal_record(
        first.journal_path,
        archived,
    )
    forged = json.loads(json.dumps(terminal))
    forged["prelaunch_abort_claim"] = second_claim.binding
    forged["scope_binding"]["claim_sha256"] = second_claim.binding[
        "claim_sha256"
    ]
    receipt = forged["terminal"]["receipt"]
    receipt["prelaunch_abort_claim_sha256"] = second_claim.binding[
        "claim_sha256"
    ]
    receipt_core = dict(receipt)
    receipt_core.pop("receipt_sha256")
    receipt["receipt_sha256"] = aux._digest_mapping(receipt_core)
    forged["terminal"]["receipt_sha256"] = receipt["receipt_sha256"]
    terminal_core = dict(forged["terminal"])
    terminal_core.pop("terminal_sha256")
    forged["terminal"]["terminal_sha256"] = aux._digest_mapping(
        terminal_core
    )
    record_core = dict(forged)
    record_core.pop("record_sha256")
    forged["record_sha256"] = aux._digest_mapping(record_core)

    with pytest.raises(
        aux.AuxiliaryWritableRootLeaseError,
        match="terminal claim linkage",
    ):
        aux._validate_journal_record(first.journal_path, forged)


def test_crash_after_intent_without_mkdir_is_reconciled_as_orphan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        aux,
        "_default_runtime_namespace",
        lambda: tmp_path / "provider-runtime",
    )
    monkeypatch.setattr(aux.secrets, "token_hex", lambda _size: "4" * 32)

    def crash(_namespace: Path, _root: Path):
        raise RuntimeError("crash-after-intent")

    monkeypatch.setattr(aux, "_create_reserved_empty_root", crash)
    with pytest.raises(RuntimeError, match="crash-after-intent"):
        _reservation().arm(
            attempt_arm_sha256="a" * 64,
            process_scope_identity="scope-recovery-001",
        )

    _dead_owner(monkeypatch)
    report = aux.reconcile_auxiliary_writable_root_leases()
    assert report["complete"] is True
    assert report["recovered"] == 1
    registry = (
        tmp_path
        / "provider-runtime"
        / aux.REGISTRY_DIRECTORY_NAME
    )
    archived = list(
        (
            tmp_path
            / "provider-runtime"
            / aux.TERMINAL_ARCHIVE_DIRECTORY_NAME
        ).glob("lease-*.json")
    )
    assert len(archived) == 1
    replay = aux.replay_auxiliary_writable_root_journal(
        registry / archived[0].name
    )
    assert replay["valid"] is True
    assert replay["state"] == "TERMINAL"
    assert replay["prior_state"] == "INTENT"


@pytest.mark.integration
def test_real_provider_process_exit_leaves_recoverable_unbound_journal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    namespace = tmp_path / "provider-runtime"
    scripts = Path(aux.__file__).resolve().parent
    program = (
        "import os,pathlib,sys;"
        f"sys.path.insert(0,{str(scripts)!r});"
        "import auxiliary_writable_root_lease as a;"
        f"ns=pathlib.Path({str(namespace)!r});"
        "a._default_runtime_namespace=lambda:ns;"
        "r=a.reserve_auxiliary_writable_root("
        "attempt_id='real-crash-attempt',purpose='claude-profile');"
        "lease=r.arm(attempt_arm_sha256='a'*64,"
        "process_scope_identity='scope-real-crash');"
        "(lease.root/'credential').write_text('secret',encoding='utf-8');"
        "os._exit(23)"
    )
    completed = subprocess.run(
        [sys.executable, "-c", program],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    assert completed.returncode == 23, completed.stderr.decode(
        "utf-8",
        errors="replace",
    )
    monkeypatch.setattr(aux, "_default_runtime_namespace", lambda: namespace)
    report = aux.reconcile_auxiliary_writable_root_leases()
    assert report["complete"] is True
    assert report["recovered"] == 1
    assert not list(namespace.glob("root-*"))


def test_crash_after_mkdir_before_armed_record_removes_only_exact_orphan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        aux,
        "_default_runtime_namespace",
        lambda: tmp_path / "provider-runtime",
    )
    monkeypatch.setattr(aux.secrets, "token_hex", lambda _size: "5" * 32)
    real_transition = aux._transition_journal

    def crash_on_arm(path: Path, expected: str, update: dict[str, object]):
        if update.get("state") == "ARMED_UNBOUND":
            raise RuntimeError("crash-before-armed-record")
        return real_transition(path, expected, update)

    monkeypatch.setattr(aux, "_transition_journal", crash_on_arm)
    with pytest.raises(RuntimeError, match="crash-before-armed-record"):
        _reservation().arm(
            attempt_arm_sha256="a" * 64,
            process_scope_identity="scope-recovery-001",
        )
    root = tmp_path / "provider-runtime" / ("root-" + "5" * 32)
    assert root.is_dir()

    monkeypatch.setattr(aux, "_transition_journal", real_transition)
    _dead_owner(monkeypatch)
    report = aux.reconcile_auxiliary_writable_root_leases()
    assert report["recovered"] == 1
    assert not os.path.lexists(root)


def test_profile_lifecycle_recovery_precedes_outer_orphan_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, token="e" * 32)
    marker = lease.root / "credential"
    marker.write_text("owned", encoding="utf-8")
    events: list[str] = []
    original_cleanup = aux._cleanup_orphaned_journal_root

    def reconcile_profile(_directory: Path) -> dict[str, object]:
        events.append("PROFILE_LIFECYCLE")
        return {
            "directory_present": True,
            "complete": True,
            "reason": "PROFILE_LIFECYCLE_RECONCILED",
            "scanned": 1,
            "recovered": 1,
            "terminal": 1,
            "completion_authority": False,
            "receipt_sha256": "d" * 64,
        }

    def cleanup_outer(record: dict[str, object]) -> dict[str, object]:
        assert events == ["PROFILE_LIFECYCLE"]
        events.append("OUTER_ROOT")
        return original_cleanup(record)

    monkeypatch.setattr(
        aux._owned_directory,
        "reconcile_owned_directory_cleanup_ledgers",
        reconcile_profile,
    )
    monkeypatch.setattr(
        aux,
        "_cleanup_orphaned_journal_root",
        cleanup_outer,
    )
    _dead_owner(monkeypatch)

    report = aux.reconcile_auxiliary_writable_root_leases()

    assert report["complete"] is True
    assert events == ["PROFILE_LIFECYCLE", "OUTER_ROOT"]
    assert not os.path.lexists(marker)


def test_profile_lifecycle_recovery_failure_blocks_outer_orphan_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, token="f" * 32)
    marker = lease.root / "credential"
    marker.write_text("must-remain", encoding="utf-8")
    outer_called = False

    def fail_profile(_directory: Path) -> dict[str, object]:
        raise aux._owned_directory.OwnedDirectoryGuardError(
            "INJECTED_PROFILE_LEDGER_FAILURE",
            "profile cleanup evidence is ambiguous",
        )

    def forbid_outer(_record: dict[str, object]) -> dict[str, object]:
        nonlocal outer_called
        outer_called = True
        raise AssertionError("outer cleanup ran before profile recovery")

    monkeypatch.setattr(
        aux._owned_directory,
        "reconcile_owned_directory_cleanup_ledgers",
        fail_profile,
    )
    monkeypatch.setattr(
        aux,
        "_cleanup_orphaned_journal_root",
        forbid_outer,
    )
    _dead_owner(monkeypatch)

    report = aux.reconcile_auxiliary_writable_root_leases()

    assert report["complete"] is False
    assert report["allocation_disposition"] == "DENY_NEW_LEASES"
    assert report["reason"] == "PROFILE_LIFECYCLE_RECOVERY_UNPROVEN"
    assert outer_called is False
    assert marker.read_text(encoding="utf-8") == "must-remain"


def test_live_or_uncertain_owner_is_quarantined_without_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, token="6" * 32)
    marker = lease.root / "credential"
    marker.write_text("secret", encoding="utf-8")

    monkeypatch.setattr(
        aux,
        "_provider_owner_status",
        lambda _owner: {"status": "EXACT_LIVE", "reason": "TEST_LIVE"},
    )
    live = aux.reconcile_auxiliary_writable_root_leases()
    assert live["live"] == 1
    assert live["recovered"] == 0
    assert marker.read_text(encoding="utf-8") == "secret"

    monkeypatch.setattr(
        aux,
        "_provider_owner_status",
        lambda _owner: {"status": "UNCERTAIN", "reason": "TEST_UNCERTAIN"},
    )
    uncertain = aux.reconcile_auxiliary_writable_root_leases()
    assert uncertain["complete"] is False
    assert uncertain["quarantined"] == 1
    assert marker.read_text(encoding="utf-8") == "secret"


def test_bound_dead_owner_requires_population_zero_recovery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, token="7" * 32)
    _scope(monkeypatch, lease)
    marker = lease.root / "credential"
    marker.write_text("secret", encoding="utf-8")
    _dead_owner(monkeypatch)

    monkeypatch.setattr(
        aux,
        "_recover_persisted_scope",
        lambda identity: {
            "identity": identity,
            "platform": "TEST",
            "population_zero": True,
            "cleanup": "TEST_ZERO",
        },
    )
    recovered = aux.reconcile_auxiliary_writable_root_leases()
    assert recovered["recovered"] == 1
    assert not os.path.lexists(lease.root)

    other = _arm(monkeypatch, tmp_path, token="8" * 32)
    _scope(monkeypatch, other)
    second_marker = other.root / "credential"
    second_marker.write_text("secret", encoding="utf-8")
    monkeypatch.setattr(
        aux,
        "_recover_persisted_scope",
        lambda _identity: (_ for _ in ()).throw(
            RuntimeError("scope recovery unavailable")
        ),
    )
    blocked = aux.reconcile_auxiliary_writable_root_leases()
    assert blocked["complete"] is False
    assert blocked["quarantined"] == 1
    assert second_marker.read_text(encoding="utf-8") == "secret"


def test_crash_after_durable_bind_is_recovered_as_bound_not_unbound(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, token="d" * 32)

    class FakeOwnedProcessScope:
        persistent_identity = "scope-recovery-001"
        population_zero_proven = False
        closed = False
        emergency_closed = False

    monkeypatch.setattr(
        aux,
        "_owned_process_scope_type",
        lambda: FakeOwnedProcessScope,
    )
    real_transition = aux._transition_journal

    def crash_after_publish(path: Path, expected: str, update: dict[str, object]):
        result = real_transition(path, expected, update)
        if update.get("state") == "ARMED_BOUND":
            raise RuntimeError("crash-after-bind-publish")
        return result

    monkeypatch.setattr(aux, "_transition_journal", crash_after_publish)
    with pytest.raises(RuntimeError, match="crash-after-bind-publish"):
        lease.bind_process_scope(FakeOwnedProcessScope())
    replay = aux.replay_auxiliary_writable_root_journal(lease.journal_path)
    assert replay["valid"] is True
    assert replay["state"] == "ARMED_BOUND"

    monkeypatch.setattr(aux, "_transition_journal", real_transition)
    _dead_owner(monkeypatch)
    recovered_identities: list[str] = []

    def recover(identity: str) -> dict[str, object]:
        recovered_identities.append(identity)
        return {
            "identity": identity,
            "platform": "TEST",
            "population_zero": True,
            "cleanup": "TEST_ZERO",
        }

    monkeypatch.setattr(aux, "_recover_persisted_scope", recover)
    report = aux.reconcile_auxiliary_writable_root_leases()
    assert report["recovered"] == 1
    assert recovered_identities == ["scope-recovery-001"]
    assert not os.path.lexists(lease.root)


def test_corrupt_or_partial_journal_never_authorizes_root_removal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, token="9" * 32)
    marker = lease.root / "credential"
    marker.write_text("secret", encoding="utf-8")
    lease.journal_path.write_bytes(b'{"schema":')
    _dead_owner(monkeypatch)

    live_replay = aux.replay_auxiliary_writable_root_binding(lease.binding)
    assert live_replay["valid"] is False
    report = aux.reconcile_auxiliary_writable_root_leases()
    assert report["complete"] is False
    assert report["quarantined"] >= 1
    assert report["legacy_unjournaled"] == 1
    assert marker.read_text(encoding="utf-8") == "secret"


def test_interrupted_terminal_write_can_be_retried_without_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, token="a" * 32)
    scope = _scope(monkeypatch, lease)
    closure = aux.prove_owned_process_scope_closed(lease, scope)
    real_transition = aux._transition_journal
    calls = 0

    def fail_terminal(path: Path, expected: str, update: dict[str, object]):
        nonlocal calls
        if update.get("state") == "TERMINAL":
            calls += 1
            if calls == 1:
                raise RuntimeError("receipt-persist-crash")
        return real_transition(path, expected, update)

    monkeypatch.setattr(aux, "_transition_journal", fail_terminal)
    with pytest.raises(RuntimeError, match="receipt-persist-crash"):
        lease.revoke(closure)
    assert not os.path.lexists(lease.root)

    receipt = lease.revoke(closure)
    assert receipt["root_absent_after"] is True
    replay = aux.replay_auxiliary_writable_root_journal(lease.journal_path)
    assert replay["valid"] is True
    assert replay["state"] == "TERMINAL"


def test_registry_traversal_bound_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, token="b" * 32)
    marker = lease.root / "credential"
    marker.write_text("secret", encoding="utf-8")
    registry = lease.journal_path.parent
    for index in range(3):
        (registry / f"unexpected-{index}").write_text("x", encoding="utf-8")
    monkeypatch.setattr(aux, "MAX_REGISTRY_ENTRIES", 2)
    _dead_owner(monkeypatch)

    report = aux.reconcile_auxiliary_writable_root_leases()
    assert report["complete"] is False
    assert report["reason"] == "ACTIVE_REGISTRY_BOUND_EXCEEDED"
    # Recovery uses the larger hard traversal bound, so a proven-dead valid
    # lease is still repaired before leftover active garbage denies allocation.
    assert report["recovered"] == 1
    assert not marker.exists()
    assert report["allocation_disposition"] == "DENY_NEW_LEASES"


def test_namespace_collision_scan_is_bounded_before_allocation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    namespace = tmp_path / "provider-runtime"
    namespace.mkdir()
    for index in range(3):
        (namespace / f"unrelated-{index}").write_text("x", encoding="utf-8")
    monkeypatch.setattr(
        aux,
        "_default_runtime_namespace",
        lambda: namespace,
    )
    monkeypatch.setattr(aux, "MAX_NAMESPACE_ENTRIES", 2)
    monkeypatch.setattr(aux.secrets, "token_hex", lambda _size: "e" * 32)

    with pytest.raises(aux.AuxiliaryWritableRootLeaseError, match="traversal bound"):
        _reservation().arm(
            attempt_arm_sha256="a" * 64,
            process_scope_identity="scope-recovery-001",
        )
    assert not (namespace / ("root-" + "e" * 32)).exists()
    assert not (namespace / aux.REGISTRY_DIRECTORY_NAME).joinpath(
        "lease-" + "e" * 32 + ".json"
    ).exists()


def test_journal_rejects_duplicate_keys_and_alias_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, token="c" * 32)
    row = json.loads(lease.journal_path.read_text(encoding="utf-8"))
    raw = (
        '{"schema":"x","schema":"y","record_sha256":"'
        + str(row["record_sha256"])
        + '"}'
    )
    lease.journal_path.write_text(raw, encoding="utf-8")
    assert (
        aux.replay_auxiliary_writable_root_journal(lease.journal_path)["valid"]
        is False
    )

    target = tmp_path / "outside.json"
    target.write_text("{}", encoding="utf-8")
    alias = lease.journal_path.parent / ("lease-" + "d" * 32 + ".json")
    try:
        alias.symlink_to(target)
    except OSError:
        pytest.skip("file symlink creation is unavailable")
    report = aux.reconcile_auxiliary_writable_root_leases()
    assert report["complete"] is False
    assert report["quarantined"] >= 1
    assert target.read_text(encoding="utf-8") == "{}"


def test_reconciliation_distinguishes_clean_debt_and_allocation_denial(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    namespace = tmp_path / "provider-runtime"
    monkeypatch.setattr(aux, "_default_runtime_namespace", lambda: namespace)

    clean = aux.reconcile_auxiliary_writable_root_leases()
    assert clean["complete"] is True
    assert clean["allocation_disposition"] == "ALLOW_NEW_LEASES"
    assert clean["runtime_debt"] == {
        "required": False,
        "category": None,
        "reason": None,
    }

    registry = namespace / aux.REGISTRY_DIRECTORY_NAME
    (registry / "unexpected").write_text("not a journal", encoding="utf-8")
    debt = aux.reconcile_auxiliary_writable_root_leases()
    assert debt["complete"] is False
    assert (
        debt["allocation_disposition"]
        == "ALLOW_NEW_LEASES_WITH_RUNTIME_DEBT"
    )
    assert debt["runtime_debt"]["required"] is True
    assert debt["runtime_debt"]["category"] == (
        "AUXILIARY_ROOT_RECONCILIATION_QUARANTINE"
    )

    monkeypatch.setattr(aux, "MAX_REGISTRY_ENTRIES", 0)
    denied = aux.reconcile_auxiliary_writable_root_leases()
    assert denied["complete"] is False
    assert denied["reason"] == "ACTIVE_REGISTRY_BOUND_EXCEEDED"
    assert denied["allocation_disposition"] == "DENY_NEW_LEASES"
    assert denied["runtime_debt"]["required"] is True


def test_terminal_journals_compact_out_of_active_registry_and_still_replay(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, token="f" * 32)
    scope = _scope(monkeypatch, lease)
    closure = aux.prove_owned_process_scope_closed(lease, scope)
    receipt = lease.revoke(closure)

    assert not lease.journal_path.exists()
    archive = (
        tmp_path
        / "provider-runtime"
        / aux.TERMINAL_ARCHIVE_DIRECTORY_NAME
        / lease.journal_path.name
    )
    assert archive.is_file()
    replay = aux.replay_auxiliary_writable_root_journal(lease.journal_path)
    assert replay["valid"] is True
    assert replay["state"] == "TERMINAL"
    assert replay["receipt_sha256"] == receipt["receipt_sha256"]


def test_terminal_compaction_failure_after_move_is_idempotently_recoverable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, token="e" * 32)
    scope = _scope(monkeypatch, lease)
    closure = aux.prove_owned_process_scope_closed(lease, scope)
    real_load = aux._load_archived_terminal_record
    calls = 0

    def fail_first_archive_read(logical: Path, archived: Path):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("crash-after-terminal-archive-move")
        return real_load(logical, archived)

    monkeypatch.setattr(
        aux,
        "_load_archived_terminal_record",
        fail_first_archive_read,
    )
    with pytest.raises(RuntimeError, match="crash-after-terminal-archive-move"):
        lease.revoke(closure)
    assert not lease.journal_path.exists()

    receipt = lease.revoke(closure)
    assert receipt["revoked"] is True
    replay = aux.replay_auxiliary_writable_root_journal(lease.journal_path)
    assert replay["valid"] is True
    assert replay["state"] == "TERMINAL"


def test_archived_terminal_replay_rejects_archive_directory_alias(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, token="0" * 32)
    scope = _scope(monkeypatch, lease)
    lease.revoke(aux.prove_owned_process_scope_closed(lease, scope))
    archive = (
        tmp_path
        / "provider-runtime"
        / aux.TERMINAL_ARCHIVE_DIRECTORY_NAME
    )
    outside = tmp_path / "outside-archive"
    outside.mkdir()
    archived_file = archive / lease.journal_path.name
    archived_file.replace(outside / archived_file.name)
    archive.rmdir()
    try:
        archive.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable")

    replay = aux.replay_auxiliary_writable_root_journal(lease.journal_path)
    assert replay == {
        "valid": False,
        "reason": "JOURNAL_REPLAY_FAILED",
    }
    assert (outside / archived_file.name).is_file()


def test_legacy_terminal_backlog_is_compacted_before_active_bound_is_applied(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    namespace = tmp_path / "provider-runtime"
    monkeypatch.setattr(aux, "_default_runtime_namespace", lambda: namespace)
    tokens = iter(("1" * 32, "2" * 32, "3" * 32))
    monkeypatch.setattr(aux.secrets, "token_hex", lambda _size: next(tokens))
    real_compact = aux._compact_terminal_journal
    monkeypatch.setattr(
        aux,
        "_compact_terminal_journal",
        lambda path, _record: path,
    )
    for index in range(3):
        lease = _reservation().arm(
            attempt_arm_sha256=chr(ord("a") + index) * 64,
            process_scope_identity=f"scope-recovery-00{index + 1}",
        )

        class FakeOwnedProcessScope:
            persistent_identity = f"scope-recovery-00{index + 1}"
            population_zero_proven = True
            closed = True
            emergency_closed = False

        monkeypatch.setattr(
            aux,
            "_owned_process_scope_type",
            lambda: FakeOwnedProcessScope,
        )
        scope = FakeOwnedProcessScope()
        lease.bind_process_scope(scope)
        lease.revoke(aux.prove_owned_process_scope_closed(lease, scope))

    registry = namespace / aux.REGISTRY_DIRECTORY_NAME
    assert len(list(registry.glob("lease-*.json"))) == 3
    monkeypatch.setattr(aux, "_compact_terminal_journal", real_compact)
    monkeypatch.setattr(aux, "MAX_REGISTRY_ENTRIES", 2)
    monkeypatch.setattr(aux, "MAX_REGISTRY_RECOVERY_ENTRIES", 8)

    report = aux.reconcile_auxiliary_writable_root_leases()
    assert report["complete"] is True
    assert report["terminal_compacted"] == 3
    assert report["active_registry_entries"] == 0
    assert report["allocation_disposition"] == "ALLOW_NEW_LEASES"
    assert not list(registry.glob("lease-*.json"))


@pytest.mark.parametrize("payload", [b"", b'{"partial":'])
def test_crash_left_temporary_journal_is_removed_from_active_registry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    payload: bytes,
) -> None:
    namespace = tmp_path / "provider-runtime"
    monkeypatch.setattr(aux, "_default_runtime_namespace", lambda: namespace)
    first = aux.reconcile_auxiliary_writable_root_leases()
    registry = Path(first["registry"])
    temporary = registry / (
        ".tmp-lease-" + "a" * 32 + "-" + "b" * 32
    )
    temporary.write_bytes(payload)

    report = aux.reconcile_auxiliary_writable_root_leases()
    assert report["complete"] is True
    assert report["temporary_quarantined"] == 1
    assert report["allocation_disposition"] == "ALLOW_NEW_LEASES"
    assert not temporary.exists()
    quarantine = (
        namespace
        / aux.ABANDONED_TEMP_DIRECTORY_NAME
        / temporary.name
    )
    assert quarantine.read_bytes() == payload


def test_registry_recovery_byte_bound_denies_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    namespace = tmp_path / "provider-runtime"
    monkeypatch.setattr(aux, "_default_runtime_namespace", lambda: namespace)
    first = aux.reconcile_auxiliary_writable_root_leases()
    registry = Path(first["registry"])
    left = registry / "unexpected-left"
    right = registry / "unexpected-right"
    left.write_bytes(b"a" * 10)
    right.write_bytes(b"b" * 10)
    monkeypatch.setattr(aux, "MAX_REGISTRY_RECOVERY_BYTES", 15)

    report = aux.reconcile_auxiliary_writable_root_leases()
    assert report["complete"] is False
    assert report["reason"] == "REGISTRY_RECOVERY_BYTE_BOUND_EXCEEDED"
    assert report["allocation_disposition"] == "DENY_NEW_LEASES"
    assert report["registry_scan_nominal_bytes"] == 20
    assert left.read_bytes() == b"a" * 10
    assert right.read_bytes() == b"b" * 10


def test_hardlinked_journal_never_authorizes_orphan_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _arm(monkeypatch, tmp_path, token="d" * 32)
    marker = lease.root / "credential"
    marker.write_text("secret", encoding="utf-8")
    outside_link = tmp_path / "outside-journal-link"
    try:
        os.link(lease.journal_path, outside_link)
    except OSError:
        pytest.skip("hard-link creation is unavailable")
    _dead_owner(monkeypatch)

    report = aux.reconcile_auxiliary_writable_root_leases()
    assert report["complete"] is False
    assert report["allocation_disposition"] == (
        "ALLOW_NEW_LEASES_WITH_RUNTIME_DEBT"
    )
    assert marker.read_text(encoding="utf-8") == "secret"
    assert outside_link.is_file()


@pytest.mark.integration
def test_registry_lock_timeout_returns_typed_denial_without_unbounded_wait(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    namespace = tmp_path / "provider-runtime"
    ready = tmp_path / "lock-ready"
    scripts = Path(aux.__file__).resolve().parent
    program = "\n".join(
        [
            "import pathlib,sys,time",
            f"sys.path.insert(0,{str(scripts)!r})",
            "import auxiliary_writable_root_lease as a",
            f"ns=pathlib.Path({str(namespace)!r})",
            "a._default_runtime_namespace=lambda:ns",
            "namespace=a._secure_namespace()",
            "with a._registry_mutation_guard(namespace, timeout_seconds=2.0):",
            f"    pathlib.Path({str(ready)!r}).write_text('ready')",
            "    time.sleep(1.5)",
        ]
    )
    holder = subprocess.Popen(
        [sys.executable, "-c", program],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 5.0
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ready.exists()
        monkeypatch.setattr(aux, "_default_runtime_namespace", lambda: namespace)
        monkeypatch.setattr(aux, "REGISTRY_LOCK_TIMEOUT_SECONDS", 0.10)
        started = time.monotonic()
        report = aux.reconcile_auxiliary_writable_root_leases()
        elapsed = time.monotonic() - started
        assert elapsed < 1.0
        assert report["complete"] is False
        assert report["reason"] == "REGISTRY_LOCK_TIMEOUT"
        assert report["allocation_disposition"] == "DENY_NEW_LEASES"
        assert report["runtime_debt"]["category"] == (
            "AUXILIARY_ROOT_RECONCILIATION_LOCK_TIMEOUT"
        )
    finally:
        stdout, stderr = holder.communicate(timeout=5)
        assert holder.returncode == 0, (
            stdout.decode(errors="replace"),
            stderr.decode(errors="replace"),
        )


@pytest.mark.integration
def test_registry_lock_is_released_by_provider_process_crash(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    namespace = tmp_path / "provider-runtime"
    ready = tmp_path / "crash-lock-ready"
    scripts = Path(aux.__file__).resolve().parent
    program = "\n".join(
        [
            "import os,pathlib,sys",
            f"sys.path.insert(0,{str(scripts)!r})",
            "import auxiliary_writable_root_lease as a",
            f"ns=pathlib.Path({str(namespace)!r})",
            "a._default_runtime_namespace=lambda:ns",
            "with a._registry_mutation_guard("
            "a._secure_namespace(),timeout_seconds=2.0):",
            f"    pathlib.Path({str(ready)!r}).write_text('ready')",
            "    os._exit(29)",
        ]
    )
    crashed = subprocess.run(
        [sys.executable, "-c", program],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    assert crashed.returncode == 29, crashed.stderr.decode(errors="replace")
    assert ready.exists()

    monkeypatch.setattr(aux, "_default_runtime_namespace", lambda: namespace)
    monkeypatch.setattr(aux, "REGISTRY_LOCK_TIMEOUT_SECONDS", 0.50)
    report = aux.reconcile_auxiliary_writable_root_leases()
    assert report["complete"] is True
    assert report["registry_lock"]["acquired"] is True
    assert report["allocation_disposition"] == "ALLOW_NEW_LEASES"


@pytest.mark.integration
def test_two_provider_processes_serialize_recovery_of_one_dead_journal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    namespace = tmp_path / "provider-runtime"
    scripts = Path(aux.__file__).resolve().parent
    crash = "\n".join(
        [
            "import os,pathlib,sys",
            f"sys.path.insert(0,{str(scripts)!r})",
            "import auxiliary_writable_root_lease as a",
            f"ns=pathlib.Path({str(namespace)!r})",
            "a._default_runtime_namespace=lambda:ns",
            "r=a.reserve_auxiliary_writable_root("
            "attempt_id='parallel-crash',purpose='claude-profile')",
            "lease=r.arm(attempt_arm_sha256='a'*64,"
            "process_scope_identity='scope-parallel-crash')",
            "(lease.root/'secret').write_text('x')",
            "os._exit(19)",
        ]
    )
    crashed = subprocess.run(
        [sys.executable, "-c", crash],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
    )
    assert crashed.returncode == 19

    barrier = tmp_path / "go"
    outputs = [tmp_path / "r1.json", tmp_path / "r2.json"]
    children: list[subprocess.Popen[bytes]] = []
    for output in outputs:
        program = "\n".join(
            [
                "import json,pathlib,sys,time",
                f"sys.path.insert(0,{str(scripts)!r})",
                "import auxiliary_writable_root_lease as a",
                f"ns=pathlib.Path({str(namespace)!r})",
                "a._default_runtime_namespace=lambda:ns",
                f"barrier=pathlib.Path({str(barrier)!r})",
                "deadline=time.monotonic()+5",
                "while not barrier.exists() and time.monotonic()<deadline:",
                "    time.sleep(0.01)",
                "result=a.reconcile_auxiliary_writable_root_leases()",
                f"pathlib.Path({str(output)!r}).write_text("
                "json.dumps(result,sort_keys=True))",
            ]
        )
        children.append(
            subprocess.Popen(
                [sys.executable, "-c", program],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        )
    barrier.write_text("go", encoding="utf-8")
    for child in children:
        stdout, stderr = child.communicate(timeout=15)
        assert child.returncode == 0, (
            stdout.decode(errors="replace"),
            stderr.decode(errors="replace"),
        )

    reports = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in outputs
    ]
    assert sum(int(report["recovered"]) for report in reports) == 1
    assert all(report["complete"] is True for report in reports)
    assert all(
        report["allocation_disposition"] == "ALLOW_NEW_LEASES"
        for report in reports
    )
    assert not list(namespace.glob("root-*"))
    assert not list(
        (namespace / aux.REGISTRY_DIRECTORY_NAME).glob("lease-*.json")
    )


def test_owner_platform_mismatch_is_uncertain_never_dead(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = "WINDOWS" if os.name == "nt" else sys.platform.upper()
    other = "LINUX" if current != "LINUX" else "WINDOWS"
    monkeypatch.setattr(
        aux,
        "_process_start_marker",
        lambda _pid: ("DEAD", None),
    )
    status = aux._provider_owner_status(
        {
            "pid": 12345,
            "platform": other,
            "process_start_marker": "marker",
            "provider_instance_nonce": "a" * 32,
        }
    )
    assert status == {
        "status": "UNCERTAIN",
        "reason": "OWNER_PLATFORM_MISMATCH",
    }


def test_reconciliation_report_replay_rejects_digest_and_semantic_tamper(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    namespace = tmp_path / "provider-runtime"
    monkeypatch.setattr(aux, "_default_runtime_namespace", lambda: namespace)
    report = aux.reconcile_auxiliary_writable_root_leases()
    replay = aux.replay_auxiliary_writable_root_reconciliation(report)
    assert replay["valid"] is True
    assert replay["report_sha256"] == report["report_sha256"]

    digest_tamper = json.loads(json.dumps(report))
    digest_tamper["allocation_disposition"] = "DENY_NEW_LEASES"
    assert aux.replay_auxiliary_writable_root_reconciliation(
        digest_tamper
    ) == {
        "valid": False,
        "reason": "RECONCILIATION_REPLAY_FAILED",
    }

    semantic_tamper = json.loads(json.dumps(report))
    semantic_tamper["complete"] = False
    core = dict(semantic_tamper)
    core.pop("report_sha256")
    semantic_tamper["report_sha256"] = aux._digest_mapping(core)
    assert aux.replay_auxiliary_writable_root_reconciliation(
        semantic_tamper
    ) == {
        "valid": False,
        "reason": "RECONCILIATION_REPLAY_FAILED",
    }
