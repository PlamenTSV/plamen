"""Genuine POSIX report-tail MODEL children for the nonempty handoff fixture.

The executable is deterministic transport scaffolding.  It reads and checks
the complete bound PhaseIO routes, proposes KEEP for every report-dedup pair,
and proposes BODY for every current standalone report ID.  The production
MODEL incorporation, validators, ledger, mechanical dedup and floor remain
authoritative.  This is not semantic model-quality or full-audit proof.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping, Sequence

import pytest

import plamen_driver as D
from artifact_ledger import read_artifact_ledger
from report_dedup_authority import standalone_report_ids
from test_verification_report_tail_same_run_integration import (
    _patch_compat_codex_lookup,
)


_TAIL_PHASES = ("report_dedup_agent", "report_disposition")


def _phase(phases: Sequence[Any], name: str) -> Any:
    return next(item for item in phases if item.name == name)


def _file_state(path: Path) -> tuple[bytes, int, int]:
    observed = os.lstat(path)
    assert stat.S_ISREG(observed.st_mode) and observed.st_nlink == 1
    return path.read_bytes(), observed.st_ino, observed.st_mtime_ns


def _tail_child_source(*, model: str) -> bytes:
    """Return one closed renderer for both exact report-tail MODEL phases."""

    return (
        f"#!{sys.executable} -B\n"
        "import hashlib,json,re,sys\n"
        "from pathlib import Path\n"
        "if sys.argv[1:] == ['--version']:\n"
        " print('codex-cli report-tail-fixture'); raise SystemExit(0)\n"
        "prompt=sys.stdin.read()\n"
        f"sys.stderr.write('OpenAI Codex v0.test\\n--------\\nworkdir: /fixture\\nmodel: {model}\\nprovider: openai\\n--------\\nuser\\n')\n"
        "_request,separator,transport=prompt.partition('\\n# PROVIDER-EFFECTIVE LOCAL PHASEIO ROUTING\\n')\n"
        "assert separator\n"
        "blocks=[json.loads(b) for b in re.findall(r'```json\\s*(.*?)\\s*```',transport,re.S)]\n"
        "routing=next(b for b in blocks if b.get('schema')=='plamen.posix_v2_codex_local_phaseio.v1')\n"
        "bound={}\n"
        "for route in routing['input_routes']:\n"
        " raw=Path(route['path']).read_bytes()\n"
        " assert len(raw)==route['size']\n"
        " assert hashlib.sha256(raw).hexdigest()==route['sha256']\n"
        " assert route['identity'] not in bound\n"
        " bound[route['identity']]=raw\n"
        "routes=routing['output_routes']\n"
        "assert len(routes)==1\n"
        "output_identity=routes[0]['identity']\n"
        "if output_identity=='scratchpad:report_dedup_agent_decisions.md':\n"
        " assert routes[0]['identity']=='scratchpad:report_dedup_agent_decisions.md'\n"
        " expected={'project:AUDIT_REPORT.md','scratchpad:report_index.md','scratchpad:finding_mapping.md','scratchpad:report_dedup_candidate_pairs.json','scratchpad:report_dedup_candidate_pairs.md'}\n"
        " assert set(bound)==expected\n"
        " pairs=json.loads(bound['scratchpad:report_dedup_candidate_pairs.json'])\n"
        " assert pairs['schema_version']=='plamen.report_dedup_candidate_pairs.v1'\n"
        " assert pairs['status']=='COMPLETE'\n"
        " rows=pairs['pairs']\n"
        " assert pairs['total_pairs']==len(rows)\n"
        " keys=[]\n"
        " out=['# Report Consolidation Decisions','','## MERGE Decisions','| Survivor | Absorbed | Same Root Cause | Reason |','|---|---|---|---|','','## Quality Observation Reclassifications','| Report ID | Class | Reason |','|---|---|---|','','## Reviewed - Kept Separate','| Report ID(s) | Reason kept separate |','|---|---|']\n"
        " for row in rows:\n"
        "  ids=row['report_ids']\n"
        "  assert isinstance(ids,list) and len(ids)==2 and ids==sorted(ids) and ids[0]!=ids[1]\n"
        "  key='~'.join(ids)\n"
        "  assert row['pair_key']==key\n"
        "  keys.append(key)\n"
        "  out.append(f'| {ids[0]}, {ids[1]} | distinct unless exact applied-equivalence authority proves otherwise |')\n"
        " assert len(keys)==len(set(keys))\n"
        " output='\\n'.join(out)+'\\n'\n"
        "elif output_identity=='scratchpad:disposition.md':\n"
        " assert routes[0]['identity']=='scratchpad:disposition.md'\n"
        " assert set(bound)=={'project:AUDIT_REPORT.md'}\n"
        " text=bound['project:AUDIT_REPORT.md'].decode('utf-8')\n"
        " ids=[]\n"
        " for match in re.finditer(r'(?im)^#{2,3}\\s*(?:\\[REPORT-BLOCKED[^\\]]*\\]\\s*)?\\[\\s*([CHMLI]-\\d{1,3})\\s*\\]',text):\n"
        "  rid=match.group(1).upper()\n"
        "  assert rid not in ids\n"
        "  ids.append(rid)\n"
        " assert ids\n"
        " out=['# Finding Disposition (BODY / APPENDIX)','','| Report ID | Disposition | Reason |','|---|---|---|']\n"
        " for rid in ids:\n"
        "  out.append(f'| {rid} | BODY | recall-safe retention; authenticated severity and evidence limitations remain visible |')\n"
        " output='\\n'.join(out)+'\\n'\n"
        "else:\n"
        " raise AssertionError(f'unexpected report-tail output: {output_identity}')\n"
        "Path(routes[0]['path']).write_text(output)\n"
        "Path(sys.argv[sys.argv.index('-o')+1]).write_text('complete\\n')\n"
        "print(json.dumps({'type':'turn.completed'}))\n"
    ).encode("utf-8")


@dataclass(frozen=True)
class ReportTailModelObservation:
    launches: list[str]
    binary: Path
    binary_state: tuple[bytes, int, int]

    def assert_transport_stable(self) -> None:
        assert self.launches == list(_TAIL_PHASES)
        assert _file_state(self.binary) == self.binary_state


def install_report_tail_child(
    *, project: Path, config: Mapping[str, Any], phases: Sequence[Any], monkeypatch,
) -> ReportTailModelObservation:
    """Install one immutable executable and observe the real provider calls."""

    if os.name != "posix":
        pytest.skip("deterministic report-tail child requires POSIX compatibility")
    assert D._posix_v2_compat_session_for_launch() is not None
    models = {
        D.phase_model(_phase(phases, name), str(config["mode"]), config)
        for name in _TAIL_PHASES
    }
    assert len(models) == 1
    binary = project.parent / "fixture-codex-nonempty-report-tail"
    assert not binary.exists() and not binary.is_symlink()
    binary.write_bytes(_tail_child_source(model=models.pop()))
    binary.chmod(0o755)
    binary_state = _file_state(binary)
    _patch_compat_codex_lookup(monkeypatch, binary)
    import posix_v2_compat_runtime as compat

    monkeypatch.setattr(
        compat,
        "_load_ambient_codex_auth",
        lambda: ("PRIVATE_AUTH_JSON_COPY", b'{"tokens":{}}\n', "c" * 64),
    )
    launches: list[str] = []
    real_codex_exec = D._run_one_codex_exec
    prompt_sources = {
        "report_dedup_agent": "phase6d-report-dedup-agent.md",
        "report_disposition": "phase6e-disposition.md",
    }

    def observed_codex_exec(*args: Any, **kwargs: Any) -> int:
        label = str(kwargs.get("label") or "")
        if label in _TAIL_PHASES:
            contract = kwargs.get("phase_io_contract")
            assert getattr(contract, "phase", "") == label
            assert getattr(contract, "work_unit_id", "") == "model"
            prompt = kwargs.get("prompt")
            assert isinstance(prompt, str)
            assert (
                "BEGIN STANDALONE V2 PHASE PROMPT "
                f"(`{prompt_sources[label]}`):"
            ) in prompt
            launches.append(label)
        return real_codex_exec(*args, **kwargs)

    monkeypatch.setattr(D, "_run_one_codex_exec", observed_codex_exec)
    return ReportTailModelObservation(launches, binary, binary_state)


def run_report_tail_model_phase(
    *, root: Path, project: Path, config: Mapping[str, Any], checkpoint: Any,
    phases: Sequence[Any], phase_name: str, observation: ReportTailModelObservation,
) -> tuple[Any, tuple[str, ...]]:
    """Execute, validate, commit and replay one registered MODEL proposal."""

    assert phase_name in _TAIL_PHASES
    assert isinstance(config, dict)
    run_id = config.get("_run_id")
    assert isinstance(run_id, str) and run_id
    if phase_name == "report_dedup_agent":
        D._compute_report_dedup_candidate_pairs(root)
        pair_payload = json.loads(
            (root / "report_dedup_candidate_pairs.json").read_text(
                encoding="utf-8", errors="strict",
            )
        )
        assert pair_payload["status"] == "COMPLETE"
        expected = tuple(row["pair_key"] for row in pair_payload["pairs"])
        assert len(expected) == pair_payload["total_pairs"] == len(set(expected))
    else:
        expected = tuple(sorted(standalone_report_ids(
            (project / "AUDIT_REPORT.md").read_text(
                encoding="utf-8", errors="strict",
            )
        )))
        assert expected

    phase = _phase(phases, phase_name)
    contract, launch = D._typed_model_phase_contract_and_launch(phase, root, config)
    assert contract is not None and launch is not None and contract.model_invoked
    assert D._bind_typed_model_phase_inputs(phase, root, config) == []
    before = D._snapshot_file_state(root, project)
    launch_count = len(observation.launches)
    # Enter through the production phase dispatcher.  This builds the real
    # installed methodology prompt, resolves the live model/timeout policy,
    # replays the already-armed monolithic PhaseIO authority, and only then
    # reaches the observed `_run_one_codex_exec` transport leaf.  Calling the
    # leaf directly would fail to cover precisely that admission boundary.
    rc = D._run_phase_once(phase, config, attempt=1)
    assert rc == 0
    assert observation.launches[launch_count:] == [phase_name]
    passed, missing = D._run_phase_validators(
        phase, config, root, phases, rc, before,
    )
    assert passed, missing
    assert missing == []
    assert D._record_typed_model_phase_artifacts(phase, root, config) == []

    output = root / contract.outputs[0].path
    frozen = _file_state(output)
    ledger = read_artifact_ledger(root)
    unit = ledger["work_units"][contract.key]
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["contract_manifest"]["model_invoked"] is True
    authority = unit["execution_authority"]
    assert authority == unit["commit_authority"]["execution_authority"]
    binding = ledger["artifact_bindings"][f"scratchpad:{output.name}"]
    assert binding["owner_key"] == contract.key
    assert binding["writer"] == "MODEL"
    assert binding["run_id"] == run_id
    assert binding["sha256"] == hashlib.sha256(frozen[0]).hexdigest()
    assert binding["size"] == len(frozen[0])

    D._commit_phase_from_disk_debt(
        phase, checkpoint, root, config, phases, clean_transients=True,
    )
    # The ordinary recorder is now a strict committed replay; it must neither
    # launch the child nor replace the accepted output.
    assert D._record_typed_model_phase_artifacts(phase, root, config) == []
    assert len(observation.launches) == launch_count + 1
    assert _file_state(output) == frozen
    return phase, expected


def _assert_report_evidence_retained(
    *, report_path: Path, records: Sequence[Mapping[str, Any]],
) -> None:
    text = report_path.read_text(encoding="utf-8", errors="strict")
    for record in records:
        marker = (
            "<!-- PLAMEN_REPORT_EVIDENCE "
            f"rid={record['report_id']} sha256={record['record_digest']} -->"
        )
        assert text.count(marker) == 1
    assert text.count("<!-- PLAMEN_REPORT_EVIDENCE rid=") == len(records)


def run_nonempty_report_tail(
    *, root: Path, project: Path, config: Mapping[str, Any], checkpoint: Any,
    phases: Sequence[Any], monkeypatch, evidence_records: Sequence[Mapping[str, Any]],
    severity_phase_name: str, severity_debt_before: Mapping[str, Mapping[str, Any]],
) -> ReportTailModelObservation:
    """Run genuine proposals followed by the exact deterministic tail sequence.

    This stops after ``report_floor``.  It proves the scoped report-tail
    contracts and preserves inherited unresolved severity debt; it does not
    stand in for later global terminal publication or a 75-phase run.
    """

    assert isinstance(config, dict)
    run_id = config.get("_run_id")
    assert isinstance(run_id, str) and run_id
    report_path = project / "AUDIT_REPORT.md"
    observation = install_report_tail_child(
        project=project, config=config, phases=phases, monkeypatch=monkeypatch,
    )

    dedup_agent, pair_keys = run_report_tail_model_phase(
        root=root,
        project=project,
        config=config,
        checkpoint=checkpoint,
        phases=phases,
        phase_name="report_dedup_agent",
        observation=observation,
    )
    assert checkpoint.phase_commits[dedup_agent.name].state == "CLEAN"

    dedup = _phase(phases, "report_dedup")
    projection_phase = "report_dedup.evidence_projection"
    assert D.report_mutation_transaction_state(
        scratchpad=root, run_id=run_id, phase=projection_phase,
    ) is None
    assert D._dedup_report_python(root, str(project), run_id=run_id) is True
    _dedup_changed, dedup_projection_issues = (
        D._project_report_evidence_transaction(
            root, project, run_id=run_id, phase=projection_phase,
        )
    )
    assert dedup_projection_issues == []
    D._commit_phase_from_disk_debt(
        dedup, checkpoint, root, config, phases, clean_transients=True,
    )
    assert checkpoint.phase_commits[dedup.name].state == "CLEAN"
    receipt = json.loads(
        (root / "report_dedup_applied_alias_receipt.json").read_text(
            encoding="utf-8", errors="strict",
        )
    )
    assert receipt["schema_version"] == (
        "plamen.report_dedup_applied_alias_receipt.v1"
    )
    # Exact all-pair proposal parity was proved by the production MODEL gate.
    # The applied receipt's candidate roster is independently recomputed from
    # report semantics and need not equal the broader hint ledger.
    assert len(pair_keys) == len(set(pair_keys))
    assert receipt["postconditions"] == {
        "all_candidates_disposed": True,
        "all_survivors_live": True,
        "applied_equals_standalone_identity_delta": True,
        "candidate_loss": [],
        "cycles": [],
    }
    _assert_report_evidence_retained(
        report_path=report_path, records=evidence_records,
    )

    # The disposition child derives this exact roster from the authenticated
    # post-dedup report route, so an independently authorized alias remains
    # losslessly represented but is not incorrectly proposed as standalone.
    post_dedup_ids = tuple(sorted(standalone_report_ids(
        report_path.read_text(encoding="utf-8", errors="strict")
    )))
    disposition, proposed_ids = run_report_tail_model_phase(
        root=root,
        project=project,
        config=config,
        checkpoint=checkpoint,
        phases=phases,
        phase_name="report_disposition",
        observation=observation,
    )
    assert proposed_ids == post_dedup_ids
    proposal = (root / "disposition.md").read_text(
        encoding="utf-8", errors="strict",
    )
    proposal_rows = {
        cells[0]: cells[1]
        for line in proposal.splitlines()
        if line.strip().startswith("|")
        for cells in [[cell.strip() for cell in line.strip().strip("|").split("|")]]
        if len(cells) >= 3 and re.fullmatch(r"[CHMLI]-\d{1,3}", cells[0])
    }
    assert tuple(sorted(proposal_rows)) == proposed_ids
    assert set(proposal_rows.values()) == {"BODY"}
    assert checkpoint.phase_commits[disposition.name].state == "CLEAN"

    floor = _phase(phases, "report_floor")
    surfaced = D._append_external_research_appendix_note(
        root, project, run_id=run_id,
    )
    assert surfaced >= 0
    floor_issues: list[str] = []
    D._refresh_central_negative_closure_authority(root, floor_issues)
    assert floor_issues == []
    disposition_result, disposition_issues = D._run_report_disposition_phase_io(
        scratchpad=root, config=config, phase=floor,
    )
    # All exact current IDs were proposed BODY, so no report section may be
    # relocated.  The typed disposition receipt, not the test, decides this.
    assert disposition_issues == []
    assert disposition_result["moved"] == 0
    assert tuple(sorted(disposition_result["ids"])) in {(), proposed_ids}
    floor_issues.extend(disposition_issues)
    assert D._run_mandatory_report_reverification(root, config) == []
    assert D._write_and_record_chain_grouping_assurance(
        scratchpad=root, config=config, phase=floor,
    ) == []
    severity_projection_issues = D._refresh_severity_report_shadow_projection(
        checkpoint, root, config, stage="POST_REPORT_FLOOR",
    )
    assert severity_projection_issues
    assert all(
        "severity remains unresolved" in issue
        for issue in severity_projection_issues
    )
    assert D._refresh_assurance_projection(
        checkpoint, root, config, allow_legacy_migration=True,
    ) == []
    D._commit_report_phase_success(floor, checkpoint, root, config, phases)
    assert not D._checkpoint_has_report_integrity_no_ship(checkpoint)
    assert D._refresh_assurance_projection(checkpoint, root, config) == []
    floor_changed, floor_projection_issues = (
        D._project_report_evidence_transaction(
            root,
            project,
            run_id=run_id,
            phase="report_floor.evidence_projection",
        )
    )
    assert floor_projection_issues == []
    if floor_changed:
        assert D._refresh_assurance_projection(checkpoint, root, config) == []
        assert D._validate_report_evidence_projection_file(
            root, report_path,
        ) == []
    assert D._finalize_report_evidence_quality(root, config) == []

    assert checkpoint.phase_commits[floor.name].state == "CLEAN"
    assert tuple(sorted(standalone_report_ids(
        report_path.read_text(encoding="utf-8", errors="strict")
    ))) == proposed_ids
    _assert_report_evidence_retained(
        report_path=report_path, records=evidence_records,
    )
    assert {
        key: checkpoint.phase_commits[key].to_dict()
        for key in severity_debt_before
    } == dict(severity_debt_before)
    assert severity_phase_name in checkpoint.degraded
    assert D._pipeline_terminal_exit_code(checkpoint) == D.EXIT_DEGRADED
    observation.assert_transport_stable()
    return observation


__all__ = [
    "ReportTailModelObservation",
    "install_report_tail_child",
    "run_nonempty_report_tail",
    "run_report_tail_model_phase",
]
