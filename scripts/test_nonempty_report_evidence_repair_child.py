"""Deterministic request-bound report-evidence repair child for integration.

The child is a local POSIX transport fixture, not evidence or model-quality
authority.  It reads every exact PhaseIO input route, verifies the sealed
hash/size denominator, derives only the fields named by the active repair
request, and writes only the assigned staged response route.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Mapping

import pytest

import plamen_driver as D
from artifact_ledger import read_artifact_ledger
from report_evidence_authority import validate_report_evidence_runtime
from test_verification_report_tail_same_run_integration import (
    _patch_compat_codex_lookup,
)


_EXPECTED_REPORT_IDS = ("L-01", "L-02", "L-03")
_EXPECTED_MISSING_FIELDS = ("impact", "recommendation")


def _file_state(path: Path) -> tuple[bytes, int, int]:
    observed = os.lstat(path)
    assert stat.S_ISREG(observed.st_mode) and observed.st_nlink == 1
    return path.read_bytes(), observed.st_ino, observed.st_mtime_ns


@dataclass(frozen=True)
class ReportEvidenceRepairObservation:
    """Frozen post-commit state used to prove later gate calls are replay-only."""

    launches: list[str]
    frozen_paths: tuple[tuple[Path, tuple[bytes, int, int]], ...]

    def assert_not_relaunched_or_rewritten(self) -> None:
        assert self.launches == ["report_evidence_repair"]
        assert {
            path: _file_state(path) for path, _state in self.frozen_paths
        } == dict(self.frozen_paths)


def _repair_child_source(*, model: str) -> bytes:
    return (
        f"#!{sys.executable} -B\n"
        "import hashlib,json,re,sys\n"
        "from pathlib import Path\n"
        "if sys.argv[1:] == ['--version']:\n"
        " print('codex-cli report-evidence-repair-fixture'); raise SystemExit(0)\n"
        "prompt=sys.stdin.read()\n"
        f"sys.stderr.write('OpenAI Codex v0.test\\n--------\\nworkdir: /fixture\\nmodel: {model}\\nprovider: openai\\n--------\\nuser\\n')\n"
        "blocks=[json.loads(b) for b in re.findall(r'```json\\s*(.*?)\\s*```',prompt,re.S)]\n"
        "routing=next(b for b in blocks if b.get('schema')=='plamen.posix_v2_codex_local_phaseio.v1')\n"
        "bound={}\n"
        "for route in routing['input_routes']:\n"
        " raw=Path(route['path']).read_bytes()\n"
        " assert len(raw)==route['size']\n"
        " assert hashlib.sha256(raw).hexdigest()==route['sha256']\n"
        " bound[route['identity']]=raw\n"
        "request=json.loads(bound['scratchpad:report_evidence_repair_request.json'])\n"
        "bundle=json.loads(bound['scratchpad:report_evidence_records.json'])\n"
        "records={row['report_id']:row for row in bundle['records']}\n"
        f"assert tuple(item['report_id'] for item in request['items'])=={_EXPECTED_REPORT_IDS!r}\n"
        f"assert all(tuple(item['missing_fields'])=={_EXPECTED_MISSING_FIELDS!r} for item in request['items'])\n"
        "items=[]\n"
        "for item in request['items']:\n"
        " record=records[item['report_id']]\n"
        " assert record['record_digest']==item['record_digest']\n"
        " mechanism=record['mechanism'].strip()\n"
        " location=', '.join(record['affected_locations'])\n"
        " assert mechanism and location\n"
        " delta={\n"
        "  'impact':f'At {location}, the retained mechanism can violate the documented state relationship: {mechanism}',\n"
        "  'recommendation':f'At {location}, enforce the documented state relationship before the affected transition and add a regression test for the retained mechanism.',\n"
        " }\n"
        " assert set(delta)==set(item['missing_fields'])\n"
        " items.append({'report_id':item['report_id'],'record_digest':item['record_digest'],'delta':delta})\n"
        "response={'schema_version':'plamen.report_evidence_repair_response.v1','request_digest':request['request_digest'],'items':items}\n"
        "routes=routing['output_routes']\n"
        "assert len(routes)==1 and routes[0]['identity']=='scratchpad:report_evidence_repair_response.json'\n"
        "Path(routes[0]['path']).write_text(json.dumps(response,sort_keys=True,separators=(',',':'))+'\\n')\n"
        "Path(sys.argv[sys.argv.index('-o')+1]).write_text('complete\\n')\n"
        "print(json.dumps({'type':'turn.completed'}))\n"
    ).encode("utf-8")


def run_nonempty_report_evidence_repair_child(
    *,
    root: Path,
    project: Path,
    config: Mapping[str, Any],
    phase: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> ReportEvidenceRepairObservation:
    """Run the actual one-shot repair gate and authenticate its exact result."""

    if os.name != "posix":
        pytest.skip("deterministic repair child requires POSIX compatibility")
    run_id = config.get("_run_id")
    assert isinstance(run_id, str) and run_id
    assert isinstance(config, dict)
    assert phase.name == "report_body_writer_critical_high"
    assert D._posix_v2_compat_session_for_launch() is not None
    assert not (root / "report_evidence_repair_response.json").exists()
    assert not (root / "report_evidence_repair_receipt.json").exists()

    binary = project.parent / "fixture-codex-report-evidence-repair"
    assert not binary.exists() and not binary.is_symlink()
    model = D.phase_model(phase, str(config["mode"]), config)
    binary.write_bytes(_repair_child_source(model=model))
    binary.chmod(0o755)
    _patch_compat_codex_lookup(monkeypatch, binary)
    import posix_v2_compat_runtime as compat

    monkeypatch.setattr(
        compat,
        "_load_ambient_codex_auth",
        lambda: ("PRIVATE_AUTH_JSON_COPY", b'{"tokens":{}}\n', "c" * 64),
    )
    launches: list[str] = []
    real_codex_exec = D._run_one_codex_exec

    def observed_codex_exec(*args: Any, **kwargs: Any) -> int:
        if kwargs.get("label") == "report_evidence_repair":
            contract = kwargs.get("phase_io_contract")
            assert getattr(contract, "work_unit_id", "") == (
                "evidence_repair.model"
            )
            launches.append("report_evidence_repair")
        return real_codex_exec(*args, **kwargs)

    # This wrapper observes the actual provider entry and delegates unchanged;
    # it is not a worker/validator substitute.
    monkeypatch.setattr(D, "_run_one_codex_exec", observed_codex_exec)
    assert D._ensure_report_evidence_before_body_writer(
        phase, config, root
    ) == []
    assert launches == ["report_evidence_repair"]

    plan = json.loads(
        (root / "report_evidence_repair_apply_plan.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    request = plan["request"]
    assert tuple(item["report_id"] for item in request["items"]) == (
        _EXPECTED_REPORT_IDS
    )
    assert all(
        tuple(item["missing_fields"]) == _EXPECTED_MISSING_FIELDS
        for item in request["items"]
    )
    response = json.loads(
        (root / "report_evidence_repair_response.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    assert response["request_digest"] == request["request_digest"]
    assert tuple(item["report_id"] for item in response["items"]) == (
        _EXPECTED_REPORT_IDS
    )
    assert all(
        set(item["delta"]) == set(_EXPECTED_MISSING_FIELDS)
        for item in response["items"]
    )

    baseline_by_id = {
        row["report_id"]: row for row in plan["baseline_bundle"]["records"]
    }
    repaired_runtime = validate_report_evidence_runtime(root)
    repaired_by_id = {
        row["report_id"]: row
        for row in repaired_runtime["bundle"]["records"]
    }
    assert set(baseline_by_id) == set(repaired_by_id) == set(
        _EXPECTED_REPORT_IDS
    )
    protected_fields = {
        "severity",
        "verdict",
        "mechanism",
        "preconditions",
        "affected_locations",
        "constituent_semantics",
        "evidence_authenticity",
        "evidence_result",
        "proof_scope",
        "capabilities",
        "evidence_sources",
        "presentation_assurance",
    }
    for report_id in _EXPECTED_REPORT_IDS:
        before = baseline_by_id[report_id]
        after = repaired_by_id[report_id]
        assert {field: after[field] for field in protected_fields} == {
            field: before[field] for field in protected_fields
        }
        expected_limitations = sorted(
            limitation
            for limitation in before["limitations"]
            if limitation not in {
                "REPORT_FIELD_MISSING:impact",
                "REPORT_FIELD_MISSING:recommendation",
            }
        )
        assert after["limitations"] == expected_limitations
        assert after["presentation_assurance"] != "PROOF_GRADE_HARM"

    ledger = read_artifact_ledger(root)
    model_matches = [
        (key, unit)
        for key, unit in ledger["work_units"].items()
        if key.endswith("/report_body/evidence_repair.model")
    ]
    assert len(model_matches) == 1
    model_key, model_unit = model_matches[0]
    assert model_unit["execution_state"] == "OUTPUT_COMMITTED"
    assert model_unit["contract_manifest"]["model_invoked"] is True
    response_binding = ledger["artifact_bindings"][
        "scratchpad:report_evidence_repair_response.json"
    ]
    assert response_binding["owner_key"] == model_key
    assert response_binding["writer"] == "MODEL"
    assert response_binding["run_id"] == run_id

    apply_matches = [
        (key, unit)
        for key, unit in ledger["work_units"].items()
        if key.endswith("/report_body/evidence_repair.apply")
    ]
    assert len(apply_matches) == 1
    apply_key, apply_unit = apply_matches[0]
    assert apply_unit["execution_state"] == "OUTPUT_COMMITTED"
    receipt_path = root / "report_evidence_repair_receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8", errors="strict"))
    assert receipt["repair_attempts"] == {
        report_id: 1 for report_id in _EXPECTED_REPORT_IDS
    }
    receipt_binding = ledger["artifact_bindings"][
        "scratchpad:report_evidence_repair_receipt.json"
    ]
    assert receipt_binding["owner_key"] == apply_key
    assert receipt_binding["writer"] == "DRIVER"
    assert receipt_binding["run_id"] == run_id

    frozen_paths = tuple(
        (path, _file_state(path))
        for path in (
            root / "report_evidence_repair_response.json",
            receipt_path,
        )
    )
    return ReportEvidenceRepairObservation(launches, frozen_paths)
