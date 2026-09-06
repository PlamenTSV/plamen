"""Fixtures for P0-P — blind-first severity is challenge-only.

The verifier assigns a severity INDEPENDENTLY from the code and evidence
alone, BEFORE reconciling with the pre-assigned/claimed severity from the
verification queue. `_apply_independent_severity_caps` retains its legacy name
but now emits direction-neutral, non-authoritative challenge work:

  - Independent LOWER or HIGHER than upstream -> typed adjudication challenge.
  - Independent EQUAL, missing, N/A, or unparseable -> no challenge.
  - No challenge artifact changes report severity; upstream is retained until
    the separate evidence-bound severity ledger explicitly authorizes change.

All fixtures are synthetic/generic (no protocol/token/contract/function names).

Run: pytest scripts/test_independent_severity_cap.py -v
"""
from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path

import pytest

import plamen_driver as D
from artifact_ledger import read_artifact_ledger
from plamen_types import Checkpoint, SC_PHASES

PLAMEN_HOME = Path(__file__).resolve().parent.parent


def _v():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
    if "plamen_validators" in sys.modules:
        del sys.modules["plamen_validators"]
    return importlib.import_module("plamen_validators")


def _scratch(tmp_path: Path) -> Path:
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "config.json").write_text(json.dumps({}), encoding="utf-8")
    return sp


def _queue(sp: Path, rows: list[tuple[str, str, str]]) -> None:
    """rows: (finding_id, severity, poc_class)."""
    out = [
        "| Queue # | Finding ID | Severity | Title | PoC Class |",
        "|---------|------------|----------|-------|-----------|",
    ]
    for i, (fid, sev, pc) in enumerate(rows, start=1):
        out.append(f"| {i} | {fid} | {sev} | example finding | {pc} |")
    (sp / "verification_queue.md").write_text("\n".join(out) + "\n", encoding="utf-8")


def _verify(
    sp: Path,
    fid: str,
    *,
    verdict: str,
    independent: str | None,
    severity: str = "High",
    tag: str = "[CODE-TRACE]",
) -> None:
    """Write a verify_{fid}.md fixture. `independent=None` omits the field
    entirely (missing-field case)."""
    lines = [
        f"**Severity**: {severity}\n\n",
        f"**Verdict**: {verdict}\n\n",
        f"**Evidence Tag**: {tag}\n\n",
    ]
    if independent is not None:
        lines.append(f"**Independent Severity**: {independent}\n\n")
    lines.append(
        "### PoC Attempt\n"
        "- PoC Required: YES\n"
        "- Attempted: NO\n"
        "- PoC Not Attempted Because: N/A\n\n"
        "### Execution Result\n"
        "- Result: NOT_EXECUTED\n"
    )
    (sp / f"verify_{fid}.md").write_text("".join(lines), encoding="utf-8")


# ===========================================================================
# _apply_independent_severity_caps
# ===========================================================================

def test_independent_lower_than_claimed_is_challenge_not_cap(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("F-01", "Critical", "unit")])
    _verify(sp, "F-01", verdict="CONFIRMED", independent="Medium", severity="Critical")
    result = V._apply_independent_severity_caps(sp, "thorough")
    assert len(result) == 1
    rec = result[0]
    assert rec == {
        **rec,
        "finding_id": "F-01",
        "upstream_severity": "Critical",
        "proposed_severity": "Medium",
        "direction": "DOWN",
        "disposition": "REQUIRES_TYPED_ADJUDICATION",
    }
    assert not (sp / "independent_severity_caps.md").exists()
    payload = json.loads(
        (sp / "independent_severity_challenges.json").read_text(encoding="utf-8")
    )
    assert payload["authority"] == "CHALLENGE_ONLY"
    assert payload["report_authoritative"] is False
    assert payload["queue_finding_ids"] == ["F-01"]
    assert V._validate_independent_severity_challenge_receipt(sp) == []


def test_independent_equal_to_claimed_no_cap(tmp_path):
    """Independent EQUAL to claimed -> no cap."""
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("F-02", "High", "unit")])
    _verify(sp, "F-02", verdict="CONFIRMED", independent="High", severity="High")
    result = V._apply_independent_severity_caps(sp, "thorough")
    assert result == []
    payload = json.loads(
        (sp / "independent_severity_challenges.json").read_text(encoding="utf-8")
    )
    assert payload["challenge_count"] == 0
    assert payload["challenges"] == []
    assert V._validate_independent_severity_challenge_receipt(sp) == []


def test_independent_higher_than_claimed_creates_upward_challenge(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("F-03", "Low", "unit")])
    _verify(sp, "F-03", verdict="CONFIRMED", independent="Critical", severity="Low")
    result = V._apply_independent_severity_caps(sp, "thorough")
    assert len(result) == 1
    assert result[0]["direction"] == "UP"
    assert result[0]["upstream_severity"] == "Low"
    assert result[0]["proposed_severity"] == "Critical"


def test_independent_na_no_cap(tmp_path):
    """Independent Severity = N/A -> no cap."""
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("F-04", "High", "unit")])
    _verify(sp, "F-04", verdict="CONFIRMED", independent="N/A", severity="High")
    result = V._apply_independent_severity_caps(sp, "thorough")
    assert result == []


def test_refuted_verdict_disagreement_stays_challenge_only(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("F-05", "High", "unit")])
    _verify(sp, "F-05", verdict="REFUTED", independent="Low", severity="High")
    result = V._apply_independent_severity_caps(sp, "thorough")
    assert len(result) == 1
    assert result[0]["verifier_status"] == "REFUTED"
    assert result[0]["disposition"] == "REQUIRES_TYPED_ADJUDICATION"


def test_missing_independent_field_no_cap(tmp_path):
    """Missing Independent Severity field entirely -> no cap (recall-safe
    fallback to claimed severity)."""
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("F-06", "High", "unit")])
    _verify(sp, "F-06", verdict="CONFIRMED", independent=None, severity="High")
    result = V._apply_independent_severity_caps(sp, "thorough")
    assert result == []
    assert not (sp / "independent_severity_caps.md").exists()


def test_unparseable_independent_field_no_cap(tmp_path):
    """Garbage/unparseable Independent Severity -> no cap (recall-safe)."""
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("F-07", "High", "unit")])
    _verify(sp, "F-07", verdict="CONFIRMED", independent="unclear, need more data", severity="High")
    result = V._apply_independent_severity_caps(sp, "thorough")
    assert result == []


def test_light_mode_skips(tmp_path):
    """Light mode -> no caps applied at all (mirrors poc_demotions light-mode
    skip)."""
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("F-08", "Critical", "unit")])
    _verify(sp, "F-08", verdict="CONFIRMED", independent="Low", severity="Critical")
    result = V._apply_independent_severity_caps(sp, "light")
    assert result == []


def test_multiple_findings_emit_both_challenge_directions(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [
        ("F-09", "Critical", "unit"),
        ("F-10", "Medium", "unit"),
        ("F-11", "Low", "unit"),
    ])
    _verify(sp, "F-09", verdict="CONFIRMED", independent="High", severity="Critical")  # caps
    _verify(sp, "F-10", verdict="CONFIRMED", independent="Medium", severity="Medium")  # no cap
    _verify(sp, "F-11", verdict="CONFIRMED", independent="Critical", severity="Low")  # never raises
    result = V._apply_independent_severity_caps(sp, "thorough")
    by_id = {r["finding_id"]: r for r in result}
    assert set(by_id) == {"F-09", "F-11"}
    assert by_id["F-09"]["direction"] == "DOWN"
    assert by_id["F-11"]["direction"] == "UP"


def test_exact_zero_replaces_stale_nonempty_receipt_and_source_drift_rejects(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("F-15", "High", "unit")])
    _verify(sp, "F-15", verdict="CONFIRMED", independent="Low", severity="High")
    assert V._apply_independent_severity_caps(sp, "thorough")
    _verify(sp, "F-15", verdict="CONFIRMED", independent="High", severity="High")
    assert V._apply_independent_severity_caps(sp, "thorough") == []
    payload = json.loads(
        (sp / "independent_severity_challenges.json").read_text(encoding="utf-8")
    )
    assert payload["challenge_count"] == 0
    assert V._validate_independent_severity_challenge_receipt(sp) == []
    with (sp / "verify_F-15.md").open("a", encoding="utf-8") as handle:
        handle.write("\nchanged after receipt\n")
    # The exact source set is part of the receipt even when no challenge fires.
    assert V._validate_independent_severity_challenge_receipt(sp)


def test_independent_challenge_projection_has_driver_phase_io_contract():
    from phase_io_contracts import resolve_phase_io_contract

    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="sc_verify_aggregate",
        work_unit_id="independent_severity_reconcile",
        exact_inputs=("verification_queue.md", "verify_F-16.md"),
    )
    assert contract.model_invoked is False
    assert {item.identity for item in contract.outputs} == {
        "scratchpad:independent_severity_challenges.json",
        "scratchpad:independent_severity_challenges.md",
    }
    assert set(contract.immutable_inputs) == {
        "scratchpad:verification_queue.md",
        "scratchpad:verify_F-16.md",
    }


def _driver_phaseio_case(
    base: Path,
    *,
    ordinal: int,
    independent: str = "Medium",
) -> tuple[Path, dict[str, str], object, str]:
    run_id = f"{ordinal:08d}-1234-4234-8234-{ordinal:012d}"
    finding_id = f"F-{ordinal}"
    project = base / "project"
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    _queue(sp, [(finding_id, "High", "unit")])
    _verify(
        sp,
        finding_id,
        verdict="CONFIRMED",
        independent=independent,
        severity="High",
    )
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(project),
        "_run_id": run_id,
    }
    Checkpoint(run_id=run_id).save(sp)
    phase = next(
        item for item in SC_PHASES if item.name == "sc_verify_aggregate"
    )
    return sp, config, phase, finding_id


def _file_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_driver_arms_independent_severity_before_projection_and_replays(
    tmp_path: Path,
):
    run_id = "12345678-1234-4234-8234-123456789abc"
    project = tmp_path / "project"
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    _queue(sp, [("F-17", "High", "unit")])
    _verify(
        sp,
        "F-17",
        verdict="CONFIRMED",
        independent="Medium",
        severity="High",
    )
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(project),
        "_run_id": run_id,
    }
    Checkpoint(run_id=run_id).save(sp)
    phase = next(item for item in SC_PHASES if item.name == "sc_verify_aggregate")

    assert D._write_and_record_independent_severity_phase_io(
        scratchpad=sp,
        config=config,
        phase=phase,
    ) == []
    unit = read_artifact_ledger(sp)["work_units"][
        "sc/thorough/evm/claude/sc_verify_aggregate/"
        "independent_severity_reconcile"
    ]
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert set(unit["input_bindings"]) == {
        "scratchpad:verification_queue.md",
        "scratchpad:verify_F-17.md",
    }
    assert set(unit["artifacts"]) == {
        "scratchpad:independent_severity_challenges.json",
        "scratchpad:independent_severity_challenges.md",
    }

    # Byte-current replay is a no-op, not a retroactive second blessing.
    before = _file_bytes(sp)
    assert D._write_and_record_independent_severity_phase_io(
        scratchpad=sp,
        config=config,
        phase=phase,
    ) == []
    assert _file_bytes(sp) == before


def test_independent_severity_postcommit_output_tamper_fails_closed(
    tmp_path: Path,
):
    for offset, (name, delete) in enumerate((
        ("independent_severity_challenges.json", False),
        ("independent_severity_challenges.md", False),
        ("independent_severity_challenges.json", True),
    )):
        sp, config, phase, _finding_id = _driver_phaseio_case(
            tmp_path / str(offset), ordinal=530 + offset
        )
        assert D._write_and_record_independent_severity_phase_io(
            scratchpad=sp, config=config, phase=phase
        ) == []
        path = sp / name
        if delete:
            path.unlink()
            expected = None
        else:
            path.write_bytes(path.read_bytes() + b"\nR53-TAMPER\n")
            expected = path.read_bytes()
        authority_before = {
            relative: value
            for relative, value in _file_bytes(sp).items()
            if relative.startswith("_artifact")
        }
        issues = D._write_and_record_independent_severity_phase_io(
            scratchpad=sp, config=config, phase=phase
        )
        assert issues
        assert (path.read_bytes() if path.is_file() else None) == expected
        assert {
            relative: value
            for relative, value in _file_bytes(sp).items()
            if relative.startswith("_artifact")
        } == authority_before


def test_independent_severity_input_receipt_and_run_tamper_fail_closed(
    tmp_path: Path,
):
    for offset, target in enumerate(("input_receipt", "run_authority")):
        sp, config, phase, _finding_id = _driver_phaseio_case(
            tmp_path / target, ordinal=540 + offset
        )
        assert D._write_and_record_independent_severity_phase_io(
            scratchpad=sp, config=config, phase=phase
        ) == []
        key = (
            "sc/thorough/evm/claude/sc_verify_aggregate/"
            "independent_severity_reconcile"
        )
        original = read_artifact_ledger(sp)["work_units"][key]
        output_before = {
            name: (sp / name).read_bytes()
            for name in (
                "independent_severity_challenges.json",
                "independent_severity_challenges.md",
            )
        }
        path = sp / "_artifact_state.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        if target == "input_receipt":
            first = next(
                iter(payload["work_units"][key]["input_bindings"].values())
            )
            first["sha256"] = "0" * 64
        else:
            payload["work_units"][key]["run_id"] = (
                "99999999-9999-4999-8999-999999999999"
            )
        path.write_text(
            json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8"
        )
        issues = D._write_and_record_independent_severity_phase_io(
            scratchpad=sp, config=config, phase=phase
        )
        assert issues
        assert {
            name: (sp / name).read_bytes() for name in output_before
        } == output_before
        after = read_artifact_ledger(sp)["work_units"][key]
        assert not (
            after["execution_state"] == "OUTPUT_COMMITTED"
            and after["commit_authority"]["attempt_ordinal"]
            > original["commit_authority"]["attempt_ordinal"]
        )


def test_independent_severity_foreign_run_and_launch_drift_fail_closed(
    tmp_path: Path,
    monkeypatch,
):
    sp, config, phase, _finding_id = _driver_phaseio_case(
        tmp_path / "foreign", ordinal=550
    )
    assert D._write_and_record_independent_severity_phase_io(
        scratchpad=sp, config=config, phase=phase
    ) == []
    foreign = dict(config)
    foreign["_run_id"] = "99999999-9999-4999-8999-999999999999"
    Checkpoint(run_id=foreign["_run_id"]).save(sp)
    before = _file_bytes(sp)
    assert D._write_and_record_independent_severity_phase_io(
        scratchpad=sp, config=foreign, phase=phase
    )
    assert _file_bytes(sp) == before

    sp, config, phase, _finding_id = _driver_phaseio_case(
        tmp_path / "launch", ordinal=551
    )
    assert D._write_and_record_independent_severity_phase_io(
        scratchpad=sp, config=config, phase=phase
    ) == []
    original = D._independent_severity_contract_and_launch

    def drifted_launch(**kwargs):
        contract, launch = original(**kwargs)
        return contract, D.LaunchSpec(
            **{**launch.to_dict(), "timeout_s": launch.timeout_s + 1}
        )

    monkeypatch.setattr(
        D, "_independent_severity_contract_and_launch", drifted_launch
    )
    before = _file_bytes(sp)
    assert D._write_and_record_independent_severity_phase_io(
        scratchpad=sp, config=config, phase=phase
    )
    assert _file_bytes(sp) == before


def test_independent_severity_input_refresh_creates_exact_successor(
    tmp_path: Path,
):
    sp, config, phase, finding_id = _driver_phaseio_case(
        tmp_path, ordinal=560
    )
    assert D._write_and_record_independent_severity_phase_io(
        scratchpad=sp, config=config, phase=phase
    ) == []
    key = (
        "sc/thorough/evm/claude/sc_verify_aggregate/"
        "independent_severity_reconcile"
    )
    first = read_artifact_ledger(sp)["work_units"][key]
    first_outputs = {
        name: (sp / name).read_bytes()
        for name in (
            "independent_severity_challenges.json",
            "independent_severity_challenges.md",
        )
    }
    _verify(
        sp,
        finding_id,
        verdict="CONFIRMED",
        independent="Low",
        severity="High",
    )
    assert D._write_and_record_independent_severity_phase_io(
        scratchpad=sp, config=config, phase=phase
    ) == []
    second = read_artifact_ledger(sp)["work_units"][key]
    assert second["execution_state"] == "OUTPUT_COMMITTED"
    assert second["commit_authority"]["attempt_ordinal"] == 2
    assert second["input_set_digest"] != first["input_set_digest"]
    assert second["commit_authority"]["receipt_digest"] != first[
        "commit_authority"
    ]["receipt_digest"]
    assert {
        name: (sp / name).read_bytes() for name in first_outputs
    } != first_outputs


def test_independent_severity_precommit_crash_resumes_exact_prebind(
    tmp_path: Path,
    monkeypatch,
):
    run_id = "22345678-1234-4234-8234-123456789abc"
    project = tmp_path / "project"
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    _queue(sp, [("F-18", "Medium", "unit")])
    _verify(
        sp,
        "F-18",
        verdict="CONFIRMED",
        independent="High",
        severity="Medium",
    )
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(project),
        "_run_id": run_id,
    }
    Checkpoint(run_id=run_id).save(sp)
    phase = next(item for item in SC_PHASES if item.name == "sc_verify_aggregate")
    real_commit = D._commit_deterministic_driver_work_unit
    monkeypatch.setattr(
        D,
        "_commit_deterministic_driver_work_unit",
        lambda **_kwargs: ["simulated crash before output commit"],
    )

    assert D._write_and_record_independent_severity_phase_io(
        scratchpad=sp,
        config=config,
        phase=phase,
    ) == ["simulated crash before output commit"]
    unit = read_artifact_ledger(sp)["work_units"][
        "sc/thorough/evm/claude/sc_verify_aggregate/"
        "independent_severity_reconcile"
    ]
    assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert unit["artifacts"] == {}
    assert (sp / "independent_severity_challenges.json").is_file()

    monkeypatch.setattr(D, "_commit_deterministic_driver_work_unit", real_commit)
    assert D._write_and_record_independent_severity_phase_io(
        scratchpad=sp,
        config=config,
        phase=phase,
    ) == []
    unit = read_artifact_ledger(sp)["work_units"][
        "sc/thorough/evm/claude/sc_verify_aggregate/"
        "independent_severity_reconcile"
    ]
    assert unit["execution_state"] == "OUTPUT_COMMITTED"


# ===========================================================================
# _load_independent_severity_caps — read the ledger back
# ===========================================================================

def test_legacy_independent_cap_loader_ignores_challenge(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("F-12", "Critical", "unit")])
    _verify(sp, "F-12", verdict="CONFIRMED", independent="Low", severity="Critical")
    V._apply_independent_severity_caps(sp, "thorough")
    assert V._load_independent_severity_caps(sp) == {}


def test_legacy_independent_cap_loader_ignores_stale_markdown(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    (sp / "independent_severity_caps.md").write_text(
        "| Finding ID | Final |\n|---|---|\n| F-99 | Low |\n",
        encoding="utf-8",
    )
    assert V._load_independent_severity_caps(sp) == {}


def test_load_independent_severity_caps_missing_file(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    assert V._load_independent_severity_caps(sp) == {}


# ===========================================================================
# _expected_report_index_severities integration — the cap actually lowers
# the driver-computed expected severity for report_index/severity_binding.md
# ===========================================================================

def test_expected_severity_retains_upstream_despite_down_challenge(tmp_path):
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("F-13", "Critical", "unit")])
    _verify(sp, "F-13", verdict="CONFIRMED", independent="Medium", severity="Critical")
    V._apply_independent_severity_caps(sp, "thorough")
    expected = V._expected_report_index_severities(sp)
    assert expected.get("F-13") == "Critical"


def test_expected_severity_unaffected_when_no_cap(tmp_path):
    """No independent_severity_caps.md ledger written -> expected severity is
    unaffected (recall-safe no-op)."""
    V = _v()
    sp = _scratch(tmp_path)
    _queue(sp, [("F-14", "High", "unit")])
    _verify(sp, "F-14", verdict="CONFIRMED", independent="High", severity="High")
    # Deliberately do NOT call _apply_independent_severity_caps — simulates a
    # pre-M4 scratchpad with no ledger at all.
    expected = V._expected_report_index_severities(sp)
    assert expected.get("F-14") == "High"


# ===========================================================================
# _report_index_adjustment_reason_present — INDEPENDENT-MIN token accepted
# ===========================================================================

def test_provenance_allowlist_rejects_legacy_independent_min(tmp_path):
    V = _v()
    assert V._report_index_adjustment_reason_present("INDEPENDENT-MIN(High)") is False
    assert V._report_index_adjustment_reason_present("INDEPENDENT-MIN(Critical)") is False
    # no regression on empty/none
    assert V._report_index_adjustment_reason_present("") is False
    assert V._report_index_adjustment_reason_present("-") is False


# ===========================================================================
# Verifier prompt directive — mandatory Independent Severity field present
# ===========================================================================

@pytest.mark.parametrize("lang", ["evm", "solana", "aptos", "sui", "soroban", "daml"])
def test_verifier_prompt_has_independent_severity_directive(lang):
    path = PLAMEN_HOME / "prompts" / lang / "phase5-verification-prompt.md"
    assert path.exists(), f"missing {path}"
    text = path.read_text(encoding="utf-8")
    assert "INDEPENDENT SEVERITY ASSESSMENT" in text
    assert "MANDATORY" in text.split("INDEPENDENT SEVERITY ASSESSMENT", 1)[1][:200]
    # The mandatory output field itself:
    assert "**Independent Severity**:" in text
    # ignore-pre-assigned-severity directive:
    assert "ignore" in text.lower()
