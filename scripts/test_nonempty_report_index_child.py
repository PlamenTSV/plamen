"""Deterministic offline report-index child for the same-run test fixture.

This is transport/lineage test scaffolding, not semantic MODEL or audit
evidence.  It derives its exact denominator and projection fields from the
already authenticated production readers before launching the real POSIX
compatibility child.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence
import os
import sys

import pytest

import plamen_driver as D
import plamen_validators as V
from artifact_ledger import read_artifact_ledger
from test_verification_report_tail_same_run_integration import (
    _patch_compat_codex_lookup,
)
from verifier_work_roster import VerifierWorkRoster


_EXPECTED_IDS = ("INV-1", "INV-2", "INV-3")
_PREFIX = {
    "Critical": "C", "High": "H", "Medium": "M",
    "Low": "L", "Informational": "I",
}


def _operator_application_authority(
    root: Path, *, run_id: str,
) -> dict[str, tuple[bytes, dict[str, Any]]]:
    """Capture the live verifier MODEL applications and their exact owners."""

    roster = VerifierWorkRoster.from_json(
        (root / "verification_runtime_roster.json").read_text(
            encoding="utf-8", errors="strict",
        )
    )
    units = {
        work_id: unit
        for unit in roster.work_units
        for work_id in unit.ordered_work_item_ids
    }
    ledger = read_artifact_ledger(root)
    captured: dict[str, tuple[bytes, dict[str, Any]]] = {}
    for work_id in roster.ordered_work_item_ids:
        unit = units[work_id]
        name = f"verify_{work_id}.operator_application.json"
        identity = f"scratchpad:{name}"
        raw = (root / name).read_bytes()
        binding = ledger["artifact_bindings"][identity]
        owner = str(binding.get("owner_key") or "")
        producer = ledger["work_units"][owner]
        artifact = producer["artifacts"][identity]
        assert owner.endswith(f"/method_model.{unit.work_unit_id}")
        assert binding.get("writer") == "MODEL"
        assert binding.get("status") == "ACTIVE"
        assert binding.get("run_id") == run_id == producer.get("run_id")
        assert binding.get("sha256") == hashlib.sha256(raw).hexdigest()
        assert binding.get("size") == len(raw)
        assert {
            key: artifact.get(key)
            for key in ("owner_key", "sha256", "size", "status")
        } == {
            key: binding.get(key)
            for key in ("owner_key", "sha256", "size", "status")
        }
        captured[name] = (raw, dict(binding))
    return captured


def _exact_outputs(root: Path, *, run_id: str, mode: str) -> dict[str, str]:
    candidates = V._report_candidate_rows_for_validator(root)
    by_id = {str(row.get("finding id") or ""): row for row in candidates}
    if tuple(sorted(by_id)) != _EXPECTED_IDS or len(candidates) != len(by_id):
        raise AssertionError(f"unexpected authenticated report denominator: {sorted(by_id)}")
    severities = V._expected_report_index_severities(
        root, expected_run_id=run_id, expected_mode=mode,
    )
    statuses = V._expected_report_index_statuses(root)
    if set(severities) != set(by_id) or set(statuses) != set(by_id):
        raise AssertionError("report severity/status projection denominator drift")

    counters: Counter[str] = Counter()
    index_rows: list[str] = []
    coverage_rows: list[str] = []
    for candidate_id in _EXPECTED_IDS:
        row = by_id[candidate_id]
        severity = str(severities[candidate_id])
        prefix = _PREFIX.get(severity)
        if prefix is None:
            raise AssertionError(f"unsupported projected severity {severity!r}")
        counters[prefix] += 1
        report_id = f"{prefix}-{counters[prefix]:02d}"
        title = str(row.get("title") or f"Retained {candidate_id}").replace("|", "/")
        location = str(row.get("location") or "src/Unit.sol").replace("|", "/")
        status = str(statuses[candidate_id]).replace("|", "/")
        index_rows.append(
            f"| {report_id} | {title} | {severity} | {location} | "
            f"{status} | - | {candidate_id} |"
        )
        coverage_rows.append(
            f"| {candidate_id} | {report_id} | {severity} | {status} |"
        )

    counts = Counter(severities.values())
    summary = "\n".join(
        f"| {severity} | {counts[severity]} |"
        for severity in ("Critical", "High", "Medium", "Low", "Informational")
    )
    report_index = (
        "# Report Index\n\n## Summary Counts\n\n"
        "| Severity | Count |\n|---|---:|\n" + summary
        + f"\n| Total | {len(index_rows)} |\n\n"
        "## Master Finding Index\n\n"
        "| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |\n"
        "|---|---|---|---|---|---|---|\n"
        + "\n".join(index_rows) + "\n"
    )
    coverage = (
        "# Report Coverage\n\n"
        "Deterministic fixture projection of the authenticated same-run denominator.\n\n"
        "| Candidate ID | Report ID | Severity | Verification |\n"
        "|---|---|---|---|\n" + "\n".join(coverage_rows) + "\n"
    )
    return {"report_index.md": report_index, "report_coverage.md": coverage}


def run_nonempty_report_index_child(
    *,
    root: Path,
    project: Path,
    config: Mapping[str, Any],
    checkpoint: Any,
    phases: Sequence[Any],
    monkeypatch,
):
    """Run actual compatibility transport after real report prework."""
    if os.name != "posix":
        pytest.skip("deterministic report child requires POSIX compatibility")
    run_id = config.get("_run_id")
    assert isinstance(run_id, str) and run_id
    assert getattr(checkpoint, "run_id", None) == run_id
    # The enclosing same-run verifier fixture owns this live session. Runtime
    # launch replay performs the authoritative root/run/session checks.
    assert D._posix_v2_compat_session_for_launch() is not None
    assert D._r10_report_consumer_ready_issues(root, config) == []
    phase = next(row for row in phases if row.name == "report_index")
    contract, launch = D._typed_model_phase_contract_and_launch(
        phase, root, config,
    )
    assert contract is not None and contract.model_invoked
    assert D._bind_typed_model_phase_inputs(phase, root, config) == []
    outputs = _exact_outputs(
        root, run_id=run_id, mode=str(config["mode"]),
    )
    operator_applications = _operator_application_authority(
        root, run_id=run_id,
    )

    binary = project.parent / "fixture-codex-nonempty-report-index"
    binary.write_text(
        f"#!{sys.executable} -B\n"
        "import json,re,sys\nfrom pathlib import Path\n"
        "if sys.argv[1:] == ['--version']:\n"
        " print('codex-cli nonempty-report-fixture'); raise SystemExit(0)\n"
        "prompt=sys.stdin.read()\n"
        f"sys.stderr.write('OpenAI Codex v0.test\\n--------\\nworkdir: /fixture\\nmodel: {launch.model}\\nprovider: openai\\n--------\\nuser\\n')\n"
        "blocks=[json.loads(b) for b in re.findall(r'```json\\s*(.*?)\\s*```',prompt,re.S)]\n"
        "routing=next(b for b in blocks if b.get('schema')=='plamen.posix_v2_codex_local_phaseio.v1')\n"
        f"outputs={outputs!r}\n"
        "for route in routing['output_routes']:\n"
        " target=Path(route['path']); target.write_text(outputs[target.name])\n"
        "Path(sys.argv[sys.argv.index('-o')+1]).write_text('complete\\n')\n"
        "print(json.dumps({'type':'turn.completed'}))\n",
        encoding="utf-8",
    )
    binary.chmod(0o755)
    _patch_compat_codex_lookup(monkeypatch, binary)
    import posix_v2_compat_runtime as compat
    monkeypatch.setattr(
        compat, "_load_ambient_codex_auth",
        lambda: ("PRIVATE_AUTH_JSON_COPY", b'{"tokens":{}}\n', "c" * 64),
    )
    assert D._run_one_codex_exec(
        prompt="Render the already-bound deterministic report-index fixture.\n",
        phase=phase, config=config, scratchpad=root, attempt=1,
        label="report_index", expected_outputs=[spec.path for spec in contract.outputs],
        timeout=float(launch.timeout_s), effective_model=launch.model,
        phase_io_contract=contract, phase_io_launch=launch,
    ) == 0
    assert _operator_application_authority(
        root, run_id=run_id,
    ) == operator_applications
    return phase, contract, launch


def canonicalize_nonempty_report_index(
    *, root: Path, config: Mapping[str, Any], checkpoint: Any,
    phases: Sequence[Any], phase: Any,
) -> None:
    """Exact integration splice immediately following the child."""
    assert D._run_report_index_canonicalization_transaction(
        phase, root, config,
    ) == []
    D._commit_phase_from_disk_debt(
        phase, checkpoint, root, config, phases,
        clean_transients=True,
    )
