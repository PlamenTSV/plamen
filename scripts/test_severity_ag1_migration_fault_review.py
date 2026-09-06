"""Independent migration/fault review for the AG-1 verifier transaction.

This suite deliberately avoids the already-covered v2 happy path, case
collisions, and ordinary identity/receipt half-transaction repair.  It covers
two upgrade/resume boundaries instead:

* a digest-valid legacy v1 receipt must have a bounded, fail-closed route to
  the current v2 pair binding (Markdown + typed severity proposal); and
* a crash after v2 receipt persistence but before shadow severity projection
  must not let the verifier shard commit CLEAN on resume.

The shadow authority is not report-authoritative yet.  Completeness is still
required so experiments cannot silently compare a partial shadow ledger.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import os
from pathlib import Path
import sys

import pytest


SCRIPTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS_DIR.parent
sys.path.insert(0, str(SCRIPTS_DIR))
sys.path.insert(0, str(REPO_ROOT))

import plamen_driver as D  # noqa: E402
import plamen_validators as V  # noqa: E402
import severity_runtime as SR  # noqa: E402
from plamen_types import Checkpoint, SC_PHASES  # noqa: E402
from queue_work_items import (  # noqa: E402
    VERIFIER_OUTPUT_RECEIPT_SCHEMA_VERSION,
    VerifierOutputIdentity,
    VerifierOutputReceipt,
)
from severity_runtime import (  # noqa: E402
    SHADOW_LEDGER_NAME,
    bind_shadow_severity_for_shard,
    ensure_shadow_severity_for_shard,
    validate_shadow_severity_for_shard,
)
import test_severity_live_sidecar_adversarial_review_p0_ag1 as AG1  # noqa: E402


RUN_ID = "migration-fault-review-run"


def _canonical_digest(value: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _legacy_v1_receipt(
    identity: VerifierOutputIdentity,
    output: bytes,
    *,
    launch_digest: str = AG1.LAUNCH_DIGEST,
    backend: str = "claude",
) -> dict[str, object]:
    """Render the exact pre-AG-1 receipt shape (Markdown binding only)."""

    unsigned: dict[str, object] = {
        "schema_version": "plamen.verifier_output_receipt.v1",
        "identity": identity.to_dict(),
        "output_sha256": hashlib.sha256(output).hexdigest(),
        "output_size_bytes": len(output),
        "launch_digest": launch_digest,
        "verifier_backend": backend,
    }
    return {**unsigned, "receipt_digest": _canonical_digest(unsigned)}


def _seed_legacy_v1_transaction(tmp_path: Path):
    scratchpad, phase_name, items, plan = AG1._setup_plan(tmp_path)
    item = items[0]
    proposal_path = AG1._write_owned_pair(scratchpad, item)
    identity = VerifierOutputIdentity.for_assignment(item, plan, phase_name)
    identity_path = scratchpad / f"verify_{item.work_item_id}.identity.json"
    identity_path.write_text(
        json.dumps(
            identity.to_dict(),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    output = (scratchpad / item.expected_output_file).read_bytes()
    receipt_path = scratchpad / f"verify_{item.work_item_id}.receipt.json"
    receipt_path.write_text(
        json.dumps(
            _legacy_v1_receipt(identity, output),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    return scratchpad, phase_name, item, plan, proposal_path, receipt_path


@pytest.mark.parametrize("legacy_identity_present", (True, False))
def test_digest_valid_v1_receipt_has_a_bounded_upgrade_to_exact_v2_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    legacy_identity_present: bool,
) -> None:
    """A legacy receipt must not create a permanent retry/degrade loop.

    The current pair is independently prevalidated first.  Migration may then
    bind the proposal in v2, but must validate the old v1 digest/output/launch/
    backend authority rather than blindly overwriting an arbitrary old file.
    """

    (
        scratchpad,
        phase_name,
        item,
        plan,
        proposal_path,
        receipt_path,
    ) = _seed_legacy_v1_transaction(tmp_path)
    identity_path = scratchpad / f"verify_{item.work_item_id}.identity.json"
    if not legacy_identity_present:
        # A pre-upgrade crash could leave the self-contained receipt but not
        # its redundant identity projection.  The validated receipt identity
        # is sufficient to reconstruct that projection during migration.
        identity_path.unlink()
    AG1._ignore_poc_gate(monkeypatch)
    assert AG1._prevalidate(scratchpad, phase_name) == []

    V._persist_verifier_output_receipts(
        scratchpad,
        phase_name,
        execution_policy=AG1._policy("sc", AG1.Backend.CLAUDE),
        launch_digest=AG1.LAUNCH_DIGEST,
    )

    migrated = VerifierOutputReceipt.from_json(
        receipt_path.read_text(encoding="utf-8")
    )
    assert identity_path.is_file()
    assert migrated.to_dict()["schema_version"] == (
        VERIFIER_OUTPUT_RECEIPT_SCHEMA_VERSION
    )
    migrated.validate_against(
        item,
        plan,
        (scratchpad / item.expected_output_file).read_bytes(),
        severity_proposal=proposal_path.read_bytes(),
        launch_digest=AG1.LAUNCH_DIGEST,
        verifier_backend="claude",
    )


@pytest.mark.parametrize("mutation", ("output", "launch", "backend"))
def test_invalid_v1_receipt_is_never_reblessed_as_v2(
    tmp_path: Path,
    mutation: str,
) -> None:
    """Version migration is an authority validation, not a reset switch."""

    (
        scratchpad,
        phase_name,
        _item,
        _plan,
        _proposal_path,
        receipt_path,
    ) = _seed_legacy_v1_transaction(tmp_path)
    payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    if mutation == "output":
        payload["output_sha256"] = "0" * 64
    elif mutation == "launch":
        payload["launch_digest"] = "f" * 64
    else:
        payload["verifier_backend"] = "codex"
    # Keep the legacy envelope internally self-consistent.  Migration must
    # still compare its claimed output authority to the actual Markdown bytes;
    # validating only receipt_digest and then rebinding current bytes would be
    # an authority-reset vulnerability.
    unsigned = {key: value for key, value in payload.items() if key != "receipt_digest"}
    payload["receipt_digest"] = _canonical_digest(unsigned)
    receipt_path.write_text(json.dumps(payload), encoding="utf-8")
    before = receipt_path.read_bytes()

    with pytest.raises((TypeError, ValueError, RuntimeError)):
        V._persist_verifier_output_receipts(
            scratchpad,
            phase_name,
            execution_policy=AG1._policy("sc", AG1.Backend.CLAUDE),
            launch_digest=AG1.LAUNCH_DIGEST,
        )
    assert receipt_path.read_bytes() == before


def test_duplicate_key_v1_receipt_is_not_normalized_into_valid_authority(
    tmp_path: Path,
) -> None:
    """Exact-key migration includes the raw JSON encoding, not last-key-wins."""

    (
        scratchpad,
        phase_name,
        _item,
        _plan,
        _proposal_path,
        receipt_path,
    ) = _seed_legacy_v1_transaction(tmp_path)
    raw = receipt_path.read_text(encoding="utf-8")
    assert raw.startswith("{") and '"verifier_backend":"claude"' in raw
    # The retained final value and receipt digest describe a valid semantic
    # mapping.  A permissive json.loads would therefore accept this ambiguous
    # envelope and erase evidence of the duplicate field during v2 migration.
    duplicate = '{"verifier_backend":"codex",' + raw[1:]
    receipt_path.write_text(duplicate, encoding="utf-8")
    before = receipt_path.read_bytes()

    with pytest.raises((TypeError, ValueError, RuntimeError), match="duplicate|schema"):
        V._persist_verifier_output_receipts(
            scratchpad,
            phase_name,
            execution_policy=AG1._policy("sc", AG1.Backend.CLAUDE),
            launch_digest=AG1.LAUNCH_DIGEST,
        )
    assert receipt_path.read_bytes() == before


def test_duplicate_key_identity_projection_is_not_normalized_during_migration(
    tmp_path: Path,
) -> None:
    (
        scratchpad,
        phase_name,
        item,
        _plan,
        _proposal_path,
        receipt_path,
    ) = _seed_legacy_v1_transaction(tmp_path)
    identity_path = scratchpad / f"verify_{item.work_item_id}.identity.json"
    raw = identity_path.read_text(encoding="utf-8")
    assert raw.startswith("{")
    identity_path.write_text(
        '{"work_item_id":"H-01",' + raw[1:], encoding="utf-8"
    )
    before_receipt = receipt_path.read_bytes()

    with pytest.raises((TypeError, ValueError, RuntimeError), match="duplicate|schema"):
        V._persist_verifier_output_receipts(
            scratchpad,
            phase_name,
            execution_policy=AG1._policy("sc", AG1.Backend.CLAUDE),
            launch_digest=AG1.LAUNCH_DIGEST,
        )
    assert receipt_path.read_bytes() == before_receipt


def _seed_v2_receipt_without_shadow(tmp_path: Path):
    scratchpad, phase_name, items, _plan = AG1._setup_plan(tmp_path)
    for item in items:
        AG1._write_owned_pair(scratchpad, item)
    policy = AG1._policy("sc", AG1.Backend.CLAUDE)
    V._persist_verifier_output_receipts(
        scratchpad,
        phase_name,
        execution_policy=policy,
        launch_digest=AG1.LAUNCH_DIGEST,
    )
    phase = next(value for value in SC_PHASES if value.name == phase_name)
    config = {
        "pipeline": "sc",
        "mode": "core",
        "language": "evm",
        "backend": "claude",
        "cli_backend": "claude",
        "scratchpad": str(scratchpad),
        "project_root": str(tmp_path),
        "_run_id": RUN_ID,
    }
    return scratchpad, phase_name, phase, config, policy


def _precommit_with_fixed_launch(
    monkeypatch: pytest.MonkeyPatch,
    scratchpad: Path,
    phase,
    config: dict[str, str],
    policy,
) -> list[str]:
    monkeypatch.setattr(D, "_resolve_config_execution_policy", lambda _c: policy)
    monkeypatch.setattr(
        D,
        "_resolved_phase_launch_digest",
        lambda _phase, _config: AG1.LAUNCH_DIGEST,
    )
    return D._validate_verification_precommit(
        phase, scratchpad, config, [phase]
    )


def test_receipts_without_shadow_projection_cannot_commit_clean_on_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Models a crash immediately after receipt persistence."""

    scratchpad, phase_name, phase, config, policy = (
        _seed_v2_receipt_without_shadow(tmp_path)
    )
    issues = _precommit_with_fixed_launch(
        monkeypatch, scratchpad, phase, config, policy
    )
    assert issues
    assert "severity" in " ".join(issues).casefold()

    _written, shadow_issues = bind_shadow_severity_for_shard(
        scratchpad,
        phase_name,
        backend="claude",
        launch_digest=AG1.LAUNCH_DIGEST,
        run_id=RUN_ID,
    )
    assert shadow_issues == ()
    assert _precommit_with_fixed_launch(
        monkeypatch, scratchpad, phase, config, policy
    ) == []


def test_shadow_precommit_debt_validation_is_side_effect_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, _phase_name, phase, config, policy = (
        _seed_v2_receipt_without_shadow(tmp_path)
    )
    before = {
        path.relative_to(scratchpad).as_posix(): path.read_bytes()
        for path in scratchpad.rglob("*")
        if path.is_file()
    }
    issues = _precommit_with_fixed_launch(
        monkeypatch, scratchpad, phase, config, policy
    )
    after = {
        path.relative_to(scratchpad).as_posix(): path.read_bytes()
        for path in scratchpad.rglob("*")
        if path.is_file()
    }
    assert issues and before == after


@pytest.mark.parametrize("missing", ("decision", "ledger"))
def test_partial_shadow_projection_remains_typed_precommit_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    missing: str,
) -> None:
    """Models crashes between per-item decision and aggregate-ledger renames."""

    scratchpad, phase_name, phase, config, policy = (
        _seed_v2_receipt_without_shadow(tmp_path)
    )
    _written, shadow_issues = bind_shadow_severity_for_shard(
        scratchpad,
        phase_name,
        backend="claude",
        launch_digest=AG1.LAUNCH_DIGEST,
        run_id=RUN_ID,
    )
    assert shadow_issues == ()
    target = (
        scratchpad / "verify_H-01.severity_decision.json"
        if missing == "decision"
        else scratchpad / SHADOW_LEDGER_NAME
    )
    target.unlink()

    issues = _precommit_with_fixed_launch(
        monkeypatch, scratchpad, phase, config, policy
    )
    assert issues
    joined = " ".join(issues).casefold()
    assert "severity" in joined and missing in joined


def test_duplicate_key_decision_projection_is_rejected_as_ambiguous(
    tmp_path: Path,
) -> None:
    scratchpad, phase_name, _phase, _config, _policy = (
        _seed_v2_receipt_without_shadow(tmp_path)
    )
    _written, issues = bind_shadow_severity_for_shard(
        scratchpad,
        phase_name,
        backend="claude",
        launch_digest=AG1.LAUNCH_DIGEST,
        run_id=RUN_ID,
    )
    assert issues == ()
    decision = scratchpad / "verify_H-01.severity_decision.json"
    raw = decision.read_text(encoding="utf-8")
    assert raw.startswith("{")
    decision.write_text(
        '{"candidate_id":"H-01",' + raw[1:], encoding="utf-8"
    )

    validation = validate_shadow_severity_for_shard(
        scratchpad,
        phase_name,
        backend="claude",
        launch_digest=AG1.LAUNCH_DIGEST,
        run_id=RUN_ID,
    )
    assert validation
    assert "duplicate" in " ".join(validation).casefold()


def test_normal_commit_fast_path_repairs_shadow_before_read_only_precommit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, phase_name, phase, config, policy = (
        _seed_v2_receipt_without_shadow(tmp_path)
    )
    monkeypatch.setattr(D, "_resolve_config_execution_policy", lambda _c: policy)
    monkeypatch.setattr(
        D,
        "_resolved_phase_launch_digest",
        lambda _phase, _config: AG1.LAUNCH_DIGEST,
    )
    committed: dict[str, object] = {}

    def fake_commit(*args, **kwargs):
        committed["clean_transients"] = kwargs.get("clean_transients")
        assert validate_shadow_severity_for_shard(
            scratchpad,
            phase_name,
            backend="claude",
            launch_digest=AG1.LAUNCH_DIGEST,
            run_id=RUN_ID,
        ) == ()
        return "COMMITTED"

    monkeypatch.setattr(D, "_commit_phase_from_disk_debt", fake_commit)
    result = D._commit_verification_transaction(
        phase,
        Checkpoint(run_id=RUN_ID),
        scratchpad,
        config,
        [phase],
        clean_transients=True,
    )
    assert result == "COMMITTED"
    assert committed == {"clean_transients": True}
    assert (scratchpad / "verify_H-01.severity_decision.json").is_file()
    assert (scratchpad / SHADOW_LEDGER_NAME).is_file()


@pytest.mark.parametrize("mutation", ("markdown", "proposal"))
def test_shadow_bind_rechecks_exact_v2_pair_at_the_write_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    """The ensure-check/bind interval must not be an authority TOCTOU seam."""

    scratchpad, phase_name, _phase, _config, _policy = (
        _seed_v2_receipt_without_shadow(tmp_path)
    )
    real_bind = SR.bind_shadow_severity_for_shard

    def mutate_then_bind(*args, **kwargs):
        if mutation == "markdown":
            path = scratchpad / "verify_H-01.md"
            path.write_bytes(path.read_bytes() + b"\npost-validation mutation\n")
        else:
            path = scratchpad / "verify_H-01.severity_proposal.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["proposed_severity"] = "Low"
            path.write_text(json.dumps(payload), encoding="utf-8")
        return real_bind(*args, **kwargs)

    monkeypatch.setattr(SR, "bind_shadow_severity_for_shard", mutate_then_bind)
    _written, issues = SR.ensure_shadow_severity_for_shard(
        scratchpad,
        phase_name,
        backend="claude",
        launch_digest=AG1.LAUNCH_DIGEST,
        run_id=RUN_ID,
    )
    assert issues
    joined = " ".join(issues).casefold()
    assert any(token in joined for token in ("sha256", "digest", "binding"))


def test_driver_owned_shadow_failure_does_not_become_model_retry_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verifier workers author proposals; they never repair driver projections."""

    scratchpad, _phase_name, phase, config, policy = (
        _seed_v2_receipt_without_shadow(tmp_path)
    )
    debts: list[tuple[object, ...]] = []
    monkeypatch.setattr(D, "gate_passes", lambda *_a, **_k: (True, []))
    monkeypatch.setattr(D, "_resolve_config_execution_policy", lambda _c: policy)
    monkeypatch.setattr(
        D,
        "_resolved_phase_launch_digest",
        lambda _phase, _config: AG1.LAUNCH_DIGEST,
    )
    monkeypatch.setattr(
        D, "_validate_verifier_outputs_before_receipt", lambda *_a, **_k: []
    )
    monkeypatch.setattr(
        D, "_persist_verifier_output_receipts", lambda *_a, **_k: ()
    )
    monkeypatch.setattr(
        D,
        "bind_shadow_severity_for_shard",
        lambda *_a, **_k: ((), ("synthetic driver projection failure",)),
    )
    monkeypatch.setattr(
        D,
        "ensure_shadow_severity_for_shard",
        lambda *_a, **_k: ((), ("synthetic driver projection failure",)),
    )
    monkeypatch.setattr(D, "_validate_verify_completion", lambda *_a, **_k: [])
    monkeypatch.setattr(D, "_validate_cited_paths_in_verify", lambda *_a, **_k: [])
    monkeypatch.setattr(
        D, "_append_phase_io_debt", lambda *args, **_kwargs: debts.append(args)
    )

    passed, missing = D._run_phase_validators(
        phase,
        config,
        scratchpad,
        [phase],
        0,
        {},
    )
    assert passed is True
    assert not any("driver projection" in value for value in missing)
    assert debts and any(
        "driver projection" in " ".join(str(value) for value in row)
        for row in debts
    )


def test_shadow_repair_paths_have_no_model_or_worker_launch_calls() -> None:
    disallowed = (
        "run_phase(",
        "build_phase_prompt(",
        "spawn_agent(",
        "run_claude",
        "run_codex",
    )
    for function in (
        ensure_shadow_severity_for_shard,
        validate_shadow_severity_for_shard,
        D._commit_verification_transaction,
    ):
        source = inspect.getsource(function)
        assert not any(token in source for token in disallowed), function.__name__


def test_validator_atomic_replace_failure_preserves_prior_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same-directory replace is fail-before-commit on Windows and POSIX."""

    target = tmp_path / "authority.json"
    target.write_text("old-authority", encoding="utf-8")
    real_replace = os.replace

    def sharing_violation(source, destination):
        if Path(destination) == target:
            raise PermissionError("synthetic Windows sharing violation")
        return real_replace(source, destination)

    monkeypatch.setattr(V.os, "replace", sharing_violation)
    with pytest.raises(PermissionError, match="sharing violation"):
        V._atomic_validator_text(target, "new-authority")
    assert target.read_text(encoding="utf-8") == "old-authority"
    assert not list(tmp_path.glob(".authority.json.*.tmp"))
