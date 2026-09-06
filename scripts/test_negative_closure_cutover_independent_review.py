"""Independent adversarial fixtures for the live negative-closure cutover."""

from __future__ import annotations

from pathlib import Path

import application_skeptic as A
import candidate_negative_authority as N
import closure_broker_v2 as C
import compound_verification as CV
import inventory_reconciliation as I
import negative_closure_policy as P
import semantic_dedup_authority as S
import pytest
from test_compound_negative_authority_nc5 import _candidate, _refutation
from test_negative_closure_broker_live_cutover import (
    _applied_alias_receipt,
    _materialize_exhaustive_provider_bundle,
    _work,
)


class _ForgedAuthority:
    def resolve(self, **_kwargs: object) -> dict[str, object]:
        return {
            "status": C.AUTHORIZED,
            "outcome": C.REFUTED_FULL,
            "resolution_digest": "a" * 64,
            "provider_completion_sha256": "b" * 64,
            "provider_publish_sha256": "c" * 64,
        }


def test_loaded_authority_replays_current_files_on_every_resolution(
    tmp_path: Path,
) -> None:
    _materialize_exhaustive_provider_bundle(tmp_path)
    authority = C.write_central_negative_closure_authority(tmp_path)
    assert authority.resolve(
        work_item=_work(), requested_effect=C.REFUTED_FULL
    )["status"] == C.AUTHORIZED

    (tmp_path / "closure-inputs/candidate.bin").write_bytes(b"changed after load")

    reopened = authority.resolve(
        work_item=_work(), requested_effect=C.REFUTED_FULL
    )
    assert reopened["status"] == C.DEBT
    assert reopened["reopen_required"] is True


def test_concurrent_replacement_during_replay_can_only_reopen(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _materialize_exhaustive_provider_bundle(tmp_path)
    authority = C.write_central_negative_closure_authority(tmp_path)
    original = C._build_central_ledger
    calls = 0

    def replace_after_first(root: Path) -> dict[str, object]:
        nonlocal calls
        calls += 1
        ledger = original(root)
        if calls == 1:
            (tmp_path / "closure-inputs/candidate.bin").write_bytes(
                b"concurrent replacement"
            )
        return ledger

    monkeypatch.setattr(C, "_build_central_ledger", replace_after_first)
    reopened = authority.resolve(
        work_item=_work(), requested_effect=C.REFUTED_FULL
    )
    assert reopened["status"] == C.DEBT
    assert reopened["reopen_required"] is True
    assert "CONCURRENT_DENOMINATOR_MUTATION" in reopened["debt_reasons"]


def test_applied_alias_requires_exact_current_absorbed_content(
    tmp_path: Path,
) -> None:
    pre, _post = _applied_alias_receipt(tmp_path)
    absorbed = S.extract_finding_records(pre)["INV-002"]
    authority = C.write_central_negative_closure_authority(tmp_path)

    exact = authority.resolve(
        work_item={
            "candidate_id": "INV-002",
            "work_item_id": "INV-002",
            "candidate_content_sha256": C._sha256(
                str(absorbed["raw"]).strip().encode("utf-8")
            ),
        },
        requested_effect=C.ALIAS_TO_SURVIVOR,
    )
    changed = authority.resolve(
        work_item={
            "candidate_id": "INV-002",
            "work_item_id": "INV-002",
            "candidate_content_sha256": "f" * 64,
        },
        requested_effect=C.ALIAS_TO_SURVIVOR,
    )

    assert exact["status"] == C.AUTHORIZED
    assert changed["status"] == C.DEBT
    assert changed["reopen_required"] is True


def test_policy_rejects_forged_subclass_and_duck_typed_authority() -> None:
    class _ForgedSubclass(C.CentralNegativeClosureAuthority):
        def resolve(self, **_kwargs: object) -> dict[str, object]:
            return {"status": C.AUTHORIZED, "outcome": C.REFUTED_FULL}

    subclass = object.__new__(_ForgedSubclass)
    assessment = {"evidence_basis": "INDEPENDENT_ANALYSIS"}
    assert P.terminal_negative_authorized(
        work_item=_work(), assessment=assessment, closure_authority=subclass
    )[0] is False
    assert P.terminal_negative_authorized(
        work_item=_work(), assessment=assessment,
        closure_authority=_ForgedAuthority(),
    )[0] is False


def test_private_token_plus_forged_ledger_cannot_bypass_root_replay(
    tmp_path: Path,
) -> None:
    forged_decision = {
        "candidate_id": "CAND-1",
        "work_item_id": "WORK-1",
        "candidate_premise_ids": ["PREM-HARM", "PREM-MECHANISM"],
        "candidate_content_sha256": "d" * 64,
        "requested_effect": C.REFUTED_FULL,
        "provider_kind": "CALLER_FORGED",
        "status": C.AUTHORIZED,
        "outcome": C.REFUTED_FULL,
        "resolution_digest": "e" * 64,
    }
    forged = C.CentralNegativeClosureAuthority(
        {"decisions": [forged_decision], "debt": []},
        root=tmp_path,
        _token=C._CENTRAL_CONSTRUCTION_TOKEN,
    )
    accepted = P.terminal_negative_authorized(
        work_item=_work(),
        assessment={"evidence_basis": "INDEPENDENT_ANALYSIS"},
        closure_authority=forged,
    )
    assert accepted[0] is False
    assert forged.resolve(
        work_item=_work(), requested_effect=C.REFUTED_FULL
    )["status"] == C.DEBT


def test_bundle_denominator_ignores_non_registry_entries(tmp_path: Path) -> None:
    bundle_root = tmp_path / C.CENTRAL_BUNDLE_DIR
    bundle_root.mkdir()
    (bundle_root / "untracked-provider-output.txt").write_text(
        "not a registered bundle", encoding="utf-8"
    )
    authority = C.load_central_negative_closure_authority(tmp_path)
    assert authority.ledger["bundle_denominator"] == []
    assert authority.ledger["debt"] == []
    assert authority.resolve(
        work_item=_work(), requested_effect=C.REFUTED_FULL
    )["status"] == C.DEBT
    assert authority.resolve(
        work_item=_work(), requested_effect=C.REFUTED_FULL
    )["debt_reasons"] == ["NO_PROVIDER_AUTHORITY"]


def test_registry_shaped_invalid_bundle_remains_visible_debt(
    tmp_path: Path,
) -> None:
    bundle_root = tmp_path / C.CENTRAL_BUNDLE_DIR
    bundle_root.mkdir()
    (bundle_root / ("bundle-" + "a" * 24 + ".json")).write_text(
        "{}", encoding="utf-8"
    )
    authority = C.load_central_negative_closure_authority(tmp_path)
    assert any(
        row["code"] == "BUNDLE_REPLAY_FAILED"
        for row in authority.ledger["debt"]
    )


def test_bundle_directory_symlink_is_never_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "probe.json").write_text("{}", encoding="utf-8")
    link = tmp_path / C.CENTRAL_BUNDLE_DIR
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this host")
    authority = C.load_central_negative_closure_authority(tmp_path)
    assert authority.ledger["bundle_denominator"] == []
    assert any(
        row["code"] == "BUNDLE_DENOMINATOR_INVALID"
        for row in authority.ledger["debt"]
    )


def test_live_consumers_share_exact_central_resolver_not_duck_typing() -> None:
    work = _work()
    assessment = {
        "work_item_id": work["work_item_id"],
        "outcome": "AGREE_NEGATIVE",
        "evidence_basis": "INDEPENDENT_ANALYSIS",
    }
    # The policy seam is common to both skeptic consumers.
    assert P.terminal_negative_authorized(
        work_item=work,
        assessment=assessment,
        closure_authority=_ForgedAuthority(),
    )[0] is False

    candidate = _candidate()
    evidence = _refutation(candidate)
    plan = CV.compile_compound_work_plan(
        (candidate,), candidate.constituents
    )
    result = CV.evaluate_compound_work_item(
        candidate,
        plan.work_items[0],
        (evidence,),
        {identity: "CONFIRMED" for identity in candidate.constituents},
        closure_authority=_ForgedAuthority(),
    )
    binding = CV.bind_compound_report(
        candidate,
        result,
        evidence=(evidence,),
        closure_authority=_ForgedAuthority(),
    )
    assert "TERMINAL_NEGATIVE_CLOSURE_AUTHORITY_MISSING" in result.debt_codes
    assert binding.disposition is CV.ReportDisposition.HUMAN_REVIEW

    # Source-level ratchet: no live consumer gets a local duck-typed resolve
    # seam.  All calls must pass through the exact-type central resolver.
    for module in (A, N, I, CV):
        source = Path(module.__file__).read_text(encoding="utf-8")
        assert "closure_authority.resolve(" not in source
