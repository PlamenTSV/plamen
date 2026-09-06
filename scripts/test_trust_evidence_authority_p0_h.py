"""P0-H: trust prose is a proposal; only bound independent evidence has authority."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import plamen_parsers as P
import plamen_validators as V
import trust_evidence_authority as T
from trust_evidence_authority import (
    AUTHORIZED_DECISION,
    TRUST_AUTHORITY_FILE,
    canonical_digest,
    resolve_legacy_trust_evidence as resolve_trust_evidence,
)


RUN_ID = "run-p0-h"
FID = "INV-041"
SCOPE = {
    "actor": "governance-timelock",
    "capability": "upgrade-implementation",
        "action_scope": "replace-runtime-code",
        "asset_scope": "protocol-runtime-integrity",
}


def _checkpoint(root: Path, run_id: str = RUN_ID) -> None:
    (root / "_v2_checkpoint.json").write_text(
        json.dumps({"run_id": run_id}) + "\n", encoding="utf-8"
    )


def _verify_text(*, actor: str = SCOPE["actor"], action: str = SCOPE["action_scope"]) -> str:
    return (
        "**Verdict**: CONFIRMED\n"
        "**Severity**: Critical\n"
        "**Impact**: High\n"
        "**Likelihood**: High\n"
        "**Trust**: FULLY_TRUSTED\n"
        f"**Trust Actor**: {actor}\n"
        f"**Trust Capability**: {SCOPE['capability']}\n"
        f"**Trust Action Scope**: {action}\n"
        f"**Trust Asset Scope**: {SCOPE['asset_scope']}\n"
        "**Material Harm**: The authorized actor can permanently brick the runtime.\n"
        "**PoC Class**: structural\n"
    )


def _write_authority(
    root: Path,
    *,
    fid: str = FID,
    source_name: str | None = None,
    source_text: str | None = None,
    scope: dict[str, str] | None = None,
    run_id: str = RUN_ID,
    evidence_text: str = "independent review of the granted capability\n",
    decision: str = AUTHORIZED_DECISION,
    source_provider: str = "verifier-worker-7",
    adjudicator: str = "trust-adjudicator-2",
) -> Path:
    _checkpoint(root)
    source_name = source_name or f"verify_{fid}.md"
    source_text = source_text or _verify_text()
    source = root / source_name
    source.write_text(source_text, encoding="utf-8")
    evidence = root / f"trust_evidence_{fid}.md"
    evidence.write_text(evidence_text, encoding="utf-8")
    row = {
        "finding_id": fid,
        "run_id": run_id,
        "source_artifact": source.name,
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "source_provider_id": source_provider,
        **(scope or SCOPE),
        "evidence_kind": "USER_SCOPE_STATEMENT",
        "evidence_path": evidence.name,
        "evidence_sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
        "evidence_run_id": run_id,
        "decision": decision,
        "adjudicator_id": adjudicator,
        "adjudication_basis_digest": hashlib.sha256(
            b"independent-adjudication-basis"
        ).hexdigest(),
    }
    row["record_digest"] = canonical_digest(row)
    unsigned = {
        "schema_version": "plamen.trust_evidence_authority.v1",
        "authority": "INDEPENDENT_TRUST_ADJUDICATION",
        "run_id": run_id,
        "producer_role": "independent_trust_adjudicator",
        "adjudicator_id": adjudicator,
        "records": [row],
    }
    payload = {**unsigned, "ledger_digest": canonical_digest(unsigned)}
    path = root / TRUST_AUTHORITY_FILE
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return source


def _row(fid: str = FID) -> dict[str, str]:
    return {
        "finding id": fid,
        "severity": "Critical",
        "poc class": "structural",
    }


def test_lexical_or_structured_looking_trust_claim_has_zero_authority(tmp_path: Path) -> None:
    text = _verify_text()
    inputs = P._extract_severity_inputs(text)
    assert inputs["trust_proposal"] is True
    assert P._enforce_severity_matrix(text, _row()) == "Critical"
    assert V._has_fully_trusted_actor_blocker(text) is False
    assert V._has_valid_skip_blocker(text, "Critical") is False
    assert V._poc_contract_required(_row(), "thorough", text) is True
    # The verifier cannot alias the same unadjudicated trust discount through
    # its free Severity field.
    proposed_low = text.replace("**Severity**: Critical", "**Severity**: Low")
    assert P._enforce_severity_matrix(proposed_low, _row()) == "Critical"
    no_axes = proposed_low.replace("**Impact**: High\n", "").replace(
        "**Likelihood**: High\n", ""
    )
    assert P._enforce_severity_matrix(no_axes, _row()) == "Critical"


def test_missing_authority_writes_typed_human_review_debt_without_negative_power(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    source = tmp_path / f"verify_{FID}.md"
    source.write_text(_verify_text(), encoding="utf-8")
    text = source.read_text(encoding="utf-8")
    assert P._enforce_severity_matrix(
        text, _row(), scratchpad=tmp_path, source_artifact=source
    ) == "Critical"
    assert V._poc_contract_required(_row(), "thorough", text, tmp_path) is True
    paths = sorted(tmp_path.glob(f"trust_evidence_debt_{FID}_*.json"))
    assert [path.stem for path in paths] == [
        f"trust_evidence_debt_{FID}_severity_modifier",
        f"trust_evidence_debt_{FID}_verification_exemption",
    ]
    for path in paths:
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["authority"] == "HUMAN_REVIEW_ONLY"
        assert payload["resolution"]["authorized"] is False
        assert payload["resolution"]["debts"] == ["TRUST_AUTHORITY_MISSING"]
        assert "severity_action" not in payload
        assert "verification_action" not in payload
    before = {path.name: path.read_bytes() for path in paths}
    assert P._enforce_severity_matrix(
        text, _row(), scratchpad=tmp_path, source_artifact=source
    ) == "Critical"
    assert before == {path.name: path.read_bytes() for path in paths}


def test_scoped_independent_authority_requires_explicit_legacy_opt_out(
    tmp_path: Path,
) -> None:
    source = _write_authority(tmp_path)
    text = source.read_text(encoding="utf-8")
    resolution = resolve_trust_evidence(
        tmp_path,
        finding_id=FID,
        source_artifact=source,
        run_id=RUN_ID,
        **SCOPE,
    )
    assert resolution.authorized is True
    assert resolution.debts == ()
    # Direct resolution is the isolated legacy/out-of-tree opt-out.  Driver
    # consumers require the deterministic provider receipt and therefore retain
    # the upstream tier / PoC obligation until a live exact provider exists.
    assert P._enforce_severity_matrix(
        text, _row(), scratchpad=tmp_path, source_artifact=source
    ) == "Critical"
    assert V._has_valid_skip_blocker(
        text, "Critical", tmp_path, finding_id=FID, source_artifact=source
    ) is False
    assert V._poc_contract_required(_row(), "thorough", text, tmp_path) is True


def test_authorized_trust_is_exactly_one_tier_not_arbitrary_verifier_discount(
    tmp_path: Path,
) -> None:
    text = _verify_text().replace("**Severity**: Critical", "**Severity**: Low")
    source = _write_authority(tmp_path, source_text=text)
    assert P._enforce_severity_matrix(
        text, _row(), scratchpad=tmp_path, source_artifact=source
    ) == "Critical"


def test_actor_or_action_scope_mismatch_cannot_leak_authority(tmp_path: Path) -> None:
    source = _write_authority(tmp_path)
    text = _verify_text(actor="operations-role", action="withdraw-custody")
    source.write_text(text, encoding="utf-8")
    resolution = resolve_trust_evidence(
        tmp_path,
        finding_id=FID,
        source_artifact=source,
        run_id=RUN_ID,
        actor="operations-role",
        capability=SCOPE["capability"],
        action_scope="withdraw-custody",
        asset_scope=SCOPE["asset_scope"],
    )
    assert resolution.authorized is False
    assert "TRUST_SCOPE_MISMATCH" in resolution.debts
    assert P._enforce_severity_matrix(
        text, _row(), scratchpad=tmp_path, source_artifact=source
    ) == "Critical"
    assert V._poc_contract_required(_row(), "thorough", text, tmp_path) is True


def test_stale_evidence_or_run_retains_upstream_and_poc_obligation(tmp_path: Path) -> None:
    source = _write_authority(tmp_path)
    text = source.read_text(encoding="utf-8")
    (tmp_path / "trust_evidence_INV-041.md").write_text(
        "changed after adjudication\n", encoding="utf-8"
    )
    resolution = resolve_trust_evidence(
        tmp_path, finding_id=FID, source_artifact=source, run_id=RUN_ID, **SCOPE
    )
    assert resolution.authorized is False
    assert "TRUST_EVIDENCE_STALE" in resolution.debts
    assert P._enforce_severity_matrix(
        text, _row(), scratchpad=tmp_path, source_artifact=source
    ) == "Critical"
    assert V._poc_contract_required(_row(), "thorough", text, tmp_path) is True

    _write_authority(tmp_path, run_id="old-run")
    assert resolve_trust_evidence(
        tmp_path, finding_id=FID, source_artifact=source, run_id=RUN_ID, **SCOPE
    ).authorized is False


def test_cross_finding_authority_never_applies(tmp_path: Path) -> None:
    _write_authority(tmp_path, fid="INV-099", source_text=_verify_text())
    source = tmp_path / f"verify_{FID}.md"
    source.write_text(_verify_text(), encoding="utf-8")
    text = source.read_text(encoding="utf-8")
    resolution = resolve_trust_evidence(
        tmp_path, finding_id=FID, source_artifact=source, run_id=RUN_ID, **SCOPE
    )
    assert resolution.authorized is False
    assert "TRUST_FINDING_UNBOUND" in resolution.debts
    assert P._enforce_severity_matrix(
        text, _row(), scratchpad=tmp_path, source_artifact=source
    ) == "Critical"


def test_tamper_and_resume_are_fail_closed_and_idempotent(tmp_path: Path) -> None:
    source = _write_authority(tmp_path)
    first = resolve_trust_evidence(
        tmp_path, finding_id=FID, source_artifact=source, run_id=RUN_ID, **SCOPE
    )
    second = resolve_trust_evidence(
        tmp_path, finding_id=FID, source_artifact=source, run_id=RUN_ID, **SCOPE
    )
    assert first == second and first.authorized

    path = tmp_path / TRUST_AUTHORITY_FILE
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["records"][0]["action_scope"] = "different-action"
    path.write_text(json.dumps(payload), encoding="utf-8")
    tampered = resolve_trust_evidence(
        tmp_path, finding_id=FID, source_artifact=source, run_id=RUN_ID, **SCOPE
    )
    assert tampered.authorized is False
    assert "TRUST_LEDGER_TAMPERED" in tampered.debts


def test_same_authority_contract_handles_l1_scopes_without_language_heuristics(tmp_path: Path) -> None:
    l1_scope = {
        "actor": "validator-governance",
        "capability": "activate-consensus-upgrade",
        "action_scope": "replace-consensus-rules",
        "asset_scope": "chain-safety-and-liveness",
    }
    text = _verify_text(
        actor=l1_scope["actor"], action=l1_scope["action_scope"]
    ).replace(SCOPE["capability"], l1_scope["capability"]).replace(
        SCOPE["asset_scope"], l1_scope["asset_scope"]
    )
    source = _write_authority(tmp_path, source_text=text, scope=l1_scope)
    result = resolve_trust_evidence(
        tmp_path,
        finding_id=FID,
        source_artifact=source,
        run_id=RUN_ID,
        **l1_scope,
    )
    assert result.authorized is True


def test_self_adjudication_and_ambiguous_duplicate_authority_are_rejected(tmp_path: Path) -> None:
    source = _write_authority(
        tmp_path, source_provider="same-worker", adjudicator="same-worker"
    )
    self_decided = resolve_trust_evidence(
        tmp_path, finding_id=FID, source_artifact=source, run_id=RUN_ID, **SCOPE
    )
    assert self_decided.authorized is False
    assert "TRUST_ADJUDICATOR_NOT_INDEPENDENT" in self_decided.debts

    source = _write_authority(tmp_path)
    path = tmp_path / TRUST_AUTHORITY_FILE
    payload = json.loads(path.read_text(encoding="utf-8"))
    duplicate = dict(payload["records"][0])
    duplicate["record_digest"] = canonical_digest(
        {k: v for k, v in duplicate.items() if k != "record_digest"}
    )
    payload["records"].append(duplicate)
    unsigned = {k: v for k, v in payload.items() if k != "ledger_digest"}
    payload["ledger_digest"] = canonical_digest(unsigned)
    path.write_text(json.dumps(payload), encoding="utf-8")
    ambiguous = resolve_trust_evidence(
        tmp_path, finding_id=FID, source_artifact=source, run_id=RUN_ID, **SCOPE
    )
    assert ambiguous.authorized is False
    assert "TRUST_AUTHORITY_AMBIGUOUS" in ambiguous.debts


def test_case_alias_self_adjudication_duplicate_keys_and_unsafe_paths_fail_closed(
    tmp_path: Path,
) -> None:
    source = _write_authority(
        tmp_path, source_provider="Verifier-A", adjudicator="verifier-a"
    )
    case_alias = resolve_trust_evidence(
        tmp_path, finding_id=FID, source_artifact=source, run_id=RUN_ID, **SCOPE
    )
    assert case_alias.authorized is False
    assert "TRUST_ADJUDICATOR_NOT_INDEPENDENT" in case_alias.debts

    source = _write_authority(tmp_path)
    ledger_path = tmp_path / TRUST_AUTHORITY_FILE
    raw = ledger_path.read_text(encoding="utf-8")
    ledger_path.write_text(
        raw.replace('"run_id": "run-p0-h",', '"run_id": "run-p0-h",\n  "run_id": "run-p0-h",', 1),
        encoding="utf-8",
    )
    duplicate_key = resolve_trust_evidence(
        tmp_path, finding_id=FID, source_artifact=source, run_id=RUN_ID, **SCOPE
    )
    assert duplicate_key.authorized is False
    assert "TRUST_LEDGER_TAMPERED" in duplicate_key.debts

    source = _write_authority(tmp_path)
    payload = json.loads(ledger_path.read_text(encoding="utf-8"))
    row = payload["records"][0]
    row["evidence_path"] = "../outside.md"
    row["record_digest"] = canonical_digest(
        {key: value for key, value in row.items() if key != "record_digest"}
    )
    unsigned = {key: value for key, value in payload.items() if key != "ledger_digest"}
    payload["ledger_digest"] = canonical_digest(unsigned)
    ledger_path.write_text(json.dumps(payload), encoding="utf-8")
    unsafe = resolve_trust_evidence(
        tmp_path, finding_id=FID, source_artifact=source, run_id=RUN_ID, **SCOPE
    )
    assert unsafe.authorized is False
    assert "TRUST_LEDGER_TAMPERED" in unsafe.debts


def test_debt_projection_io_failure_is_haltless_and_has_no_negative_authority(
    tmp_path: Path, monkeypatch
) -> None:
    _checkpoint(tmp_path)
    source = tmp_path / f"verify_{FID}.md"
    source.write_text(_verify_text(), encoding="utf-8")
    text = source.read_text(encoding="utf-8")

    def _fail_write(_path: Path, _content: str) -> None:
        raise OSError("synthetic read-only scratchpad")

    monkeypatch.setattr(T, "_atomic_text", _fail_write)
    assert P._enforce_severity_matrix(
        text, _row(), scratchpad=tmp_path, source_artifact=source
    ) == "Critical"
    assert V._poc_contract_required(_row(), "thorough", text, tmp_path) is True
