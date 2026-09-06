"""P1-G: confidence consensus is typed independent corroboration.

These fixtures deliberately reject the historical ``single observer = 1.0``
shortcut.  Consensus is not evidence quality, skill assignment, location
coincidence, or a producer's own confidence claim.  It is an additive signal
that requires current, separately dispatched observers tied to the same
explicit upstream finding identity.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path

import pytest

import confidence_consensus_authority as C
import methodology_application as A
import plamen_driver as D
from artifact_ledger import read_artifact_ledger
from phase_contract_compiler import prompt_contract_conflicts
from phase_io_contracts import resolve_phase_io_contract
from plamen_types import Checkpoint, SC_PHASES


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _worker_entry(
    sp: Path,
    *,
    worker: str,
    output: str,
    prompt_text: str,
    methodologies: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    entry: dict[str, object] = {
        "worker_id": worker,
        "output": output,
        "prompt_sha256": _sha(prompt_text.encode("utf-8")),
        "prompt_snapshot_required": True,
        "prompt_snapshot_glob": "_prompt_depth_worker_*.attempt*.md",
        "methodologies": methodologies or [],
    }
    entry["dispatch_contract_sha256"] = A.worker_dispatch_contract_sha256(
        "depth", entry
    )
    stem = Path(output).stem
    (sp / f"_prompt_depth_worker_{stem}.attempt1.md").write_text(
        prompt_text, encoding="utf-8"
    )
    return entry


def _finding_body(
    *,
    worker: str,
    output: str,
    contract: str,
    finding_id: str,
    source_ids: str = "INV-001",
    location: str = "src/Module.sol:L42",
    extra: str = "",
) -> str:
    source_line = (
        f"**Source Finding(s)**: {source_ids}\n" if source_ids else ""
    )
    return f"""<!-- PLAMEN_DISPATCH_PHASE: depth -->
<!-- PLAMEN_DISPATCH_WORKER: {worker} -->
<!-- PLAMEN_DISPATCH_OUTPUT: {output} -->
<!-- PLAMEN_DISPATCH_CONTRACT_SHA256: {contract} -->
<!-- PLAMEN_ARTIFACT: {output} -->
<!-- PLAMEN_OWNER: {worker} -->
<!-- PLAMEN_STATUS: IN_PROGRESS -->

### Finding [{finding_id}]: Generic state-transition inconsistency

{source_line}**Verdict**: CONFIRMED
**Severity**: High
**Location**: {location}
**Evidence**: [CODE]
**Depth Evidence**: [BOUNDARY: exact transition boundary]
**Depth Evidence**: [VARIATION: alternate input class]
**Depth Evidence**: [TRACE: entry to state write]
**Root Cause**: A state transition omits one required relation.
{extra}

<!-- PLAMEN_STATUS: COMPLETE -->
"""


def _materialize(
    sp: Path,
    specs: list[dict[str, object]],
) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    jobs: list[dict[str, object]] = []
    for spec in specs:
        worker = str(spec["worker"])
        output = str(spec["output"])
        prompt = str(spec.get("prompt") or f"role={worker}; output={output}")
        entry = _worker_entry(
            sp,
            worker=worker,
            output=output,
            prompt_text=prompt,
            methodologies=list(spec.get("methodologies") or []),
        )
        body = _finding_body(
            worker=worker,
            output=output,
            contract=str(entry["dispatch_contract_sha256"]),
            finding_id=str(spec["finding_id"]),
            source_ids=str(spec.get("source_ids", "INV-001")),
            location=str(spec.get("location", "src/Module.sol:L42")),
            extra=str(spec.get("extra", "")),
        )
        (sp / output).write_text(body, encoding="utf-8")
        entries.append(entry)
        jobs.append(
            {
                "agent_id": worker,
                "role": str(spec.get("role") or worker),
                "output": output,
                "category": "standard",
            }
        )
    phase = A.write_phase_dispatch(
        sp, phase="depth", backend="claude-pty", entries=entries
    )
    (sp / "_depth_worker_pool_contract.json").write_text(
        json.dumps(
            {
                "version": 2,
                "phase": "depth",
                "backend": "claude-pty",
                "pipeline": "sc",
                "mode": "thorough",
                "outputs": [str(row["output"]) for row in jobs],
                "jobs": jobs,
                "skill_dispatch_file": "skill_dispatch.json",
                "skill_dispatch_sha256": phase["dispatch_sha256"],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return entries


def _scores(payload: dict[str, object]) -> dict[tuple[str, str], float]:
    return {
        (str(row["source_artifact"]), str(row["finding_id"])): float(row["score"])
        for row in payload["scores"]
    }


def _identity_debts(
    payload: dict[str, object],
) -> dict[tuple[str, str], dict[str, object]]:
    return {
        (
            str(row["candidate_ref"]["source_artifact"]),
            str(row["candidate_ref"]["finding_id"]),
        ): row
        for row in payload["identity_debts"]
    }


def test_single_observer_has_zero_consensus_even_with_required_skill(tmp_path: Path):
    _materialize(
        tmp_path,
        [
            {
                "worker": "depth-state",
                "output": "depth_state_trace_findings.md",
                "finding_id": "DST-1",
                "methodologies": [
                    {
                        "skill": "STATE_TRANSITION_AUDIT",
                        "path": "skills/state/SKILL.md",
                        "sha256": "1" * 64,
                        "top_level_checklist_step_ids": ["1", "2"],
                    }
                ],
            }
        ],
    )

    payload = C.build_confidence_consensus_authority(tmp_path)

    assert C.validate_confidence_consensus_authority(tmp_path, payload) == []
    assert _scores(payload)[("depth_state_trace_findings.md", "DST-1")] == 0.0
    row = payload["scores"][0]
    assert row["independent_observer_count"] == 1
    assert row["specialized_methodology_bonus"] == 0.0
    assert row["basis"] == "SINGLE_OBSERVER_NO_AGREEMENT"
    assert row["identity_status"] == "EXACT"
    assert row["preservation_required"] is False
    assert payload["identity_debts"] == []


def test_two_current_distinct_workers_can_add_bounded_corroboration(tmp_path: Path):
    _materialize(
        tmp_path,
        [
            {
                "worker": "depth-state",
                "role": "state_trace",
                "output": "depth_state_trace_findings.md",
                "finding_id": "DST-1",
                "source_ids": "INV-007",
                "prompt": "independent state-transition trace",
            },
            {
                "worker": "depth-edge",
                "role": "edge_case",
                "output": "depth_edge_case_findings.md",
                "finding_id": "DEC-2",
                "source_ids": "INV-007",
                "prompt": "independent boundary analysis",
            },
        ],
    )

    payload = C.build_confidence_consensus_authority(tmp_path)
    scores = _scores(payload)

    assert C.validate_confidence_consensus_authority(tmp_path, payload) == []
    assert scores[("depth_state_trace_findings.md", "DST-1")] == 0.5
    assert scores[("depth_edge_case_findings.md", "DEC-2")] == 0.5
    assert {row["independent_observer_count"] for row in payload["scores"]} == {2}
    assert {tuple(row["semantic_anchors"]) for row in payload["scores"]} == {
        ("INV-007",)
    }


def test_same_location_without_explicit_shared_identity_is_not_consensus(tmp_path: Path):
    _materialize(
        tmp_path,
        [
            {
                "worker": "depth-state",
                "output": "depth_state_trace_findings.md",
                "finding_id": "DST-1",
                "source_ids": "INV-007",
            },
            {
                "worker": "depth-edge",
                "output": "depth_edge_case_findings.md",
                "finding_id": "DEC-2",
                "source_ids": "INV-008",
            },
        ],
    )

    payload = C.build_confidence_consensus_authority(tmp_path)

    assert set(_scores(payload).values()) == {0.0}
    assert all(row["basis"] == "SINGLE_OBSERVER_NO_AGREEMENT" for row in payload["scores"])


def test_same_worker_restatement_is_correlated_and_does_not_add_consensus(tmp_path: Path):
    _materialize(
        tmp_path,
        [
            {
                "worker": "depth-state",
                "output": "depth_state_trace_findings.md",
                "finding_id": "DST-1",
                "source_ids": "INV-007",
                "prompt": "same invocation lineage",
            },
            {
                "worker": "depth-state",
                "output": "depth_state_trace_retry_findings.md",
                "finding_id": "DST-2",
                "source_ids": "INV-007",
                "prompt": "same invocation lineage restatement",
            },
        ],
    )

    payload = C.build_confidence_consensus_authority(tmp_path)

    assert set(_scores(payload).values()) == {0.0}
    assert all(row["independent_observer_count"] == 1 for row in payload["scores"])


@pytest.mark.parametrize(
    ("source_ids", "extra", "expected_status", "expected_debt_type"),
    [
        ("", "", "MISSING", "MISSING_UPSTREAM_IDENTITY"),
        (
            "",
            "**Source Finding(s)**: not-a-finding-id\n",
            "MALFORMED",
            "MALFORMED_UPSTREAM_IDENTITY",
        ),
        (
            "INV-001",
            "**Source IDs**: INV-002\n",
            "AMBIGUOUS",
            "AMBIGUOUS_UPSTREAM_IDENTITY",
        ),
    ],
)
def test_unbound_identity_emits_typed_nonnegative_reconciliation_debt(
    tmp_path: Path,
    source_ids: str,
    extra: str,
    expected_status: str,
    expected_debt_type: str,
):
    _materialize(
        tmp_path,
        [
            {
                "worker": "depth-state",
                "output": "depth_state_trace_findings.md",
                "finding_id": "DST-1",
                "source_ids": source_ids,
                "extra": extra,
            }
        ],
    )

    payload = C.build_confidence_consensus_authority(tmp_path)

    observation = payload["observations"][0]
    assert observation["identity_status"] == expected_status
    assert observation["authority_status"] == "UNBOUND"
    score = payload["scores"][0]
    assert score["score"] == 0.0
    assert score["negative_or_drop_authority"] is False
    assert score["preservation_required"] is True
    debt = _identity_debts(payload)[("depth_state_trace_findings.md", "DST-1")]
    assert debt["debt_type"] == expected_debt_type
    assert debt["resolution_status"] == "OPEN"
    assert debt["required_action"] == "RETAIN_PENDING_IDENTITY_RECONCILIATION"
    assert debt["negative_or_drop_authority"] is False
    assert debt["proof_authority"] == "NONE"
    assert debt["candidate_ref"]["claim_block_sha256"] == observation["claim_block_sha256"]
    assert debt["candidate_ref"]["observation_digest"] == observation["observation_digest"]
    assert debt["debt_id"].startswith("CID-DEBT-")


def test_all_unbound_denominator_is_loud_and_preserves_every_candidate(tmp_path: Path):
    _materialize(
        tmp_path,
        [
            {
                "worker": "depth-state",
                "output": "depth_state_trace_findings.md",
                "finding_id": "DST-1",
                "source_ids": "",
            },
            {
                "worker": "depth-edge",
                "output": "depth_edge_case_findings.md",
                "finding_id": "DEC-2",
                "source_ids": "",
                "extra": "**Source Finding(s)**: malformed\n",
            },
        ],
    )

    payload = C.build_confidence_consensus_authority(tmp_path)
    accounting = payload["identity_accounting"]

    assert accounting == {
        "candidate_denominator": 2,
        "exact_bound_count": 0,
        "identity_debt_count": 2,
        "all_unbound": True,
        "authority_state": "RECONCILIATION_REQUIRED",
        "negative_or_drop_authority": False,
    }
    assert payload["authority_debt_codes"] == [
        "CONFIDENCE_CONSENSUS_AUTHORITY_DEBT"
    ]
    assert len(payload["identity_debts"]) == 2
    assert all(row["preservation_required"] for row in payload["scores"])
    assert all(not row["negative_or_drop_authority"] for row in payload["scores"])


def test_identity_debt_is_idempotent_on_retry_reload_and_closes_on_exact_repair(
    tmp_path: Path,
):
    _materialize(
        tmp_path,
        [
            {
                "worker": "depth-state",
                "output": "depth_state_trace_findings.md",
                "finding_id": "DST-1",
                "source_ids": "",
            }
        ],
    )

    first = C.write_confidence_consensus_artifacts(tmp_path)
    first_json = (tmp_path / C.AUTHORITY_NAME).read_bytes()
    first_markdown = (tmp_path / C.MARKDOWN_NAME).read_bytes()
    second = C.write_confidence_consensus_artifacts(tmp_path)

    assert first == second
    assert (tmp_path / C.AUTHORITY_NAME).read_bytes() == first_json
    assert (tmp_path / C.MARKDOWN_NAME).read_bytes() == first_markdown
    assert json.loads(first_json) == first
    assert C.validate_confidence_consensus_artifacts(tmp_path) == []

    finding = tmp_path / "depth_state_trace_findings.md"
    text = finding.read_text(encoding="utf-8")
    finding.write_text(
        text.replace(
            "**Verdict**: CONFIRMED",
            "**Source Finding(s)**: INV-009\n**Verdict**: CONFIRMED",
            1,
        ),
        encoding="utf-8",
    )
    repaired = C.write_confidence_consensus_artifacts(tmp_path)

    assert repaired["identity_debts"] == []
    assert repaired["identity_accounting"]["exact_bound_count"] == 1
    assert repaired["observations"][0]["identity_status"] == "EXACT"
    assert repaired["scores"][0]["preservation_required"] is False
    assert repaired["scores"][0]["score"] == 0.0
    assert C.validate_confidence_consensus_artifacts(tmp_path) == []


@pytest.mark.parametrize("tamper", ["prompt", "dispatch", "artifact"])
def test_stale_or_unbound_observer_cannot_supply_corroboration(
    tmp_path: Path, tamper: str
):
    entries = _materialize(
        tmp_path,
        [
            {
                "worker": "depth-state",
                "output": "depth_state_trace_findings.md",
                "finding_id": "DST-1",
            },
            {
                "worker": "depth-edge",
                "output": "depth_edge_case_findings.md",
                "finding_id": "DEC-2",
            },
        ],
    )
    if tamper == "prompt":
        (tmp_path / "_prompt_depth_worker_depth_edge_case_findings.attempt1.md").write_text(
            "tampered after dispatch", encoding="utf-8"
        )
    elif tamper == "dispatch":
        dispatch = json.loads((tmp_path / "skill_dispatch.json").read_text(encoding="utf-8"))
        dispatch["phases"]["depth"]["entries"][1]["worker_id"] = "forged-worker"
        (tmp_path / "skill_dispatch.json").write_text(
            json.dumps(dispatch), encoding="utf-8"
        )
    else:
        target = tmp_path / "depth_edge_case_findings.md"
        target.write_text(target.read_text(encoding="utf-8") + "\npost-build drift\n", encoding="utf-8")

    payload = C.build_confidence_consensus_authority(tmp_path)

    # The current builder degrades the untrusted observer before scoring.
    assert set(_scores(payload).values()) == {0.0}
    unbound = {
        row["observation_digest"]
        for row in payload["observations"]
        if row["authority_status"] != "CURRENT"
    }
    debt_bound = {
        row["candidate_ref"]["observation_digest"]
        for row in payload["identity_debts"]
    }
    assert unbound
    assert debt_bound == unbound
    assert all(not row["negative_or_drop_authority"] for row in payload["identity_debts"])
    # A later drift after materialization is caught by the independent validator.
    if tamper == "artifact":
        current = C.build_confidence_consensus_authority(tmp_path)
        target = tmp_path / "depth_edge_case_findings.md"
        target.write_text(target.read_text(encoding="utf-8") + "\nsecond drift\n", encoding="utf-8")
        assert C.validate_confidence_consensus_authority(tmp_path, current)


def test_markdown_projection_is_derived_from_typed_authority(tmp_path: Path):
    _materialize(
        tmp_path,
        [
            {
                "worker": "depth-state",
                "output": "depth_state_trace_findings.md",
                "finding_id": "DST-1",
            }
        ],
    )
    payload = C.write_confidence_consensus_artifacts(tmp_path)

    typed = json.loads((tmp_path / "confidence_consensus_authority.json").read_text(encoding="utf-8"))
    markdown = (tmp_path / "consensus_map.md").read_text(encoding="utf-8")
    assert typed == payload
    assert "| DST-1 | depth_state_trace_findings.md | 0.00 |" in markdown
    assert str(payload["authority_digest"]) in markdown
    assert C.validate_confidence_consensus_artifacts(tmp_path) == []


def test_driver_uses_zero_single_observer_consensus_in_thorough(tmp_path: Path):
    _materialize(
        tmp_path,
        [
            {
                "worker": "depth-state",
                "output": "depth_state_trace_findings.md",
                "finding_id": "DST-1",
            }
        ],
    )

    assert D._compute_depth_confidence(tmp_path, "thorough") == 1
    text = (tmp_path / "confidence_scores.md").read_text(encoding="utf-8")
    # evidence=.8, consensus=0, quality=1, RAG=.3 => .56, not historical .81.
    assert "| DST-1 | 0.80 | 0.00 | 1.00 | 0.50 | UNCERTAIN |" in text
    assert (tmp_path / "confidence_consensus_authority.json").is_file()
    assert (tmp_path / "consensus_map.md").is_file()


def test_driver_core_uses_documented_two_axis_formula(tmp_path: Path):
    _materialize(
        tmp_path,
        [
            {
                "worker": "depth-state",
                "output": "depth_state_trace_findings.md",
                "finding_id": "DST-1",
            }
        ],
    )

    assert D._compute_depth_confidence(tmp_path, "core") == 1
    text = (tmp_path / "confidence_scores.md").read_text(encoding="utf-8")
    # Core: evidence=.8 * .5 + quality=1 * .5 = .90; other axes are telemetry.
    assert "| DST-1 | 0.80 | 0.00 | 1.00 | 0.90 | CONFIDENT |" in text
    assert "Mode: CORE_2_AXIS" in text


def test_consensus_authority_has_a_registered_driver_only_phase_io_contract(
    tmp_path: Path,
):
    sp = tmp_path / "scratch"
    sp.mkdir()
    _materialize(
        sp,
        [
            {
                "worker": "depth-state",
                "output": "depth_state_trace_findings.md",
                "finding_id": "DST-1",
            }
        ],
    )
    payload = C.write_confidence_consensus_artifacts(sp)
    (sp / "confidence_scores.md").write_text("# scores\n", encoding="utf-8")
    inputs = tuple(row["path"] for row in payload["input_bindings"])

    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="depth",
        work_unit_id="confidence_consensus",
        exact_inputs=inputs,
    )

    assert contract.model_invoked is False
    assert set(contract.immutable_inputs) == {
        f"scratchpad:{name}" for name in inputs
    }
    assert {item.identity for item in contract.outputs} == {
        "scratchpad:confidence_consensus_authority.json",
        "scratchpad:consensus_map.md",
        "scratchpad:confidence_scores.md",
    }
    assert {item.writer for item in contract.outputs} == {"DRIVER"}


def test_driver_binds_consensus_inputs_outputs_and_resume_detects_drift(
    tmp_path: Path,
):
    run_id = "12345678-1234-4234-8234-123456789abc"
    project = tmp_path / "project"
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    _materialize(
        sp,
        [
            {
                "worker": "depth-state",
                "output": "depth_state_trace_findings.md",
                "finding_id": "DST-1",
            }
        ],
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
    phase = next(item for item in SC_PHASES if item.name == "depth")

    assert D._write_and_record_confidence_consensus_phase_io(
        scratchpad=sp,
        config=config,
        phase=phase,
    ) == []
    assert "DST-1" in (sp / "confidence_scores.md").read_text(encoding="utf-8")
    assert D._validate_confidence_consensus_phase_io(
        scratchpad=sp,
        project_root=project,
        mode="thorough",
        language="evm",
        pipeline="sc",
        backend="claude",
        timeout_s=phase.base_timeout_s,
    ) == []

    ledger = read_artifact_ledger(sp)
    key = "sc/thorough/evm/claude/depth/confidence_consensus"
    unit = ledger["work_units"][key]
    assert set(unit["artifacts"]) == {
        "scratchpad:confidence_consensus_authority.json",
        "scratchpad:consensus_map.md",
        "scratchpad:confidence_scores.md",
    }
    assert "scratchpad:skill_dispatch.json" in unit["input_bindings"]
    assert (
        "scratchpad:_depth_worker_pool_contract.json"
        in unit["input_bindings"]
    )

    source = sp / "depth_state_trace_findings.md"
    source.write_text(
        source.read_text(encoding="utf-8") + "\npost-score drift\n",
        encoding="utf-8",
    )
    issues = D._validate_confidence_consensus_phase_io(
        scratchpad=sp,
        project_root=project,
        mode="thorough",
        language="evm",
        pipeline="sc",
        backend="claude",
        timeout_s=phase.base_timeout_s,
    )
    assert issues
    assert any("stale" in issue.lower() or "drift" in issue.lower() for issue in issues)


def test_methodology_never_directs_model_to_write_driver_confidence_output():
    """Keep source and generated Claude/Codex methodology owner-consistent."""

    repo = Path(__file__).resolve().parents[1]
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="depth",
        work_unit_id="confidence_consensus",
        exact_inputs=("depth_token_flow_findings.md",),
    )
    candidates: list[Path] = []
    for dirname in ("agents", "commands", "prompts", "rules", "codex-adapter"):
        root = repo / dirname
        candidates.extend(root.rglob("*.md"))
        candidates.extend(root.rglob("*.toml"))

    conflicts: list[str] = []
    scanned_refs = 0
    for path in sorted(set(candidates)):
        text = path.read_text(encoding="utf-8", errors="strict")
        if "confidence_scores.md" not in text:
            continue
        scanned_refs += 1
        for issue in prompt_contract_conflicts(
            text,
            contract,
            actor="MODEL",
        ):
            if "DRIVER-owned output" in issue:
                conflicts.append(f"{path.relative_to(repo)}: {issue}")
        for number, line in enumerate(text.splitlines(), 1):
            if (
                "confidence_scores.md" in line
                and re.search(
                    r"(?i)\b(?:confidence\s+scoring|re-?scoring|scoring)\s+agent\b",
                    line,
                )
            ):
                conflicts.append(
                    f"{path.relative_to(repo)}: line {number}: "
                    "MODEL confidence role is named as canonical owner"
                )

    # Prompt fragments constructed inside Python must obey the same owner
    # boundary, without treating the driver's own filesystem code as a prompt.
    for path in (
        repo / "scripts" / "codex_adapter.py",
        repo / "scripts" / "plamen_driver.py",
        repo / "scripts" / "plamen_validators.py",
    ):
        tree = ast.parse(path.read_text(encoding="utf-8", errors="strict"))
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        for node in ast.walk(tree):
            if (
                not isinstance(node, ast.Constant)
                or not isinstance(node.value, str)
                or "confidence_scores.md" not in node.value
            ):
                continue
            parent = parents.get(node)
            grandparent = parents.get(parent)
            if (
                isinstance(parent, ast.Expr)
                and isinstance(
                    grandparent,
                    (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
                )
                and grandparent.body
                and grandparent.body[0] is parent
            ):
                continue
            if (
                isinstance(parent, ast.Call)
                and parent.args
                and parent.args[0] is node
                and isinstance(parent.func, ast.Attribute)
                and parent.func.attr == "replace"
            ):
                # A compatibility search literal is not emitted prompt text.
                continue
            scanned_refs += 1
            for issue in prompt_contract_conflicts(
                node.value,
                contract,
                actor="MODEL",
            ):
                if "DRIVER-owned output" in issue:
                    conflicts.append(
                        f"{path.relative_to(repo)}:{node.lineno}: {issue}"
                    )
            for offset, line in enumerate(node.value.splitlines()):
                if (
                    "confidence_scores.md" in line
                    and re.search(
                        r"(?i)\b(?:confidence\s+scoring|re-?scoring|scoring)\s+agent\b",
                        line,
                    )
                ):
                    conflicts.append(
                        f"{path.relative_to(repo)}:{node.lineno + offset}: "
                        "MODEL confidence role is named as canonical owner"
                    )

    # A non-zero denominator prevents an accidental empty-glob green.
    assert scanned_refs >= 20
    assert conflicts == []
