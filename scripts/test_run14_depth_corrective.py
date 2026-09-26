"""Regressions for the Run14 Depth parser, retry, and niche contracts."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

import candidate_negative_authority as N
import plamen_driver as D
import plamen_validators as V
from plamen_types import Phase


def _candidate_ledger(tmp_path: Path, text: str) -> dict[str, Any]:
    methodology = tmp_path / "finding-output-format.md"
    methodology.write_text("# exact test methodology\n", encoding="utf-8")
    return N.build_candidate_negative_ledger(
        phase="depth",
        artifacts=[
            N.ArtifactInput(
                relative_path="niche_semantic_gap_findings.md",
                content=text.encode("utf-8"),
                producer_identity="NICHE-SEMANTIC-GAP",
                producer_invocation_id="RUN14-REGRESSION",
            )
        ],
        methodology_path=methodology,
    )


def _complete_refutation(finding_id: str, line: int) -> str:
    return (
        f"## Finding [{finding_id}]: exact semantic gap\n"
        "**Verdict**: REFUTATION_PROPOSAL\n"
        f"**Location**: src/Vault.sol:L{line}\n\n"
        "### Precondition Analysis\n"
        "**Missing Precondition**: the stale path is unreachable\n"
        "**Precondition Type**: STATE\n"
        "**Why This Blocks**: every reachable caller refreshes first\n\n"
        f"**Invariant Commitment**: CI:CI-{finding_id}\n\n"
        f"committed-invariant [CI-{finding_id}]\n"
        f"Locus: src/Vault.sol:L{line}\n"
        "Shape: FRESHNESS\n"
        "Assertion: the observed state is current at every reachable use\n"
        "Falsify Class: property\n"
        f"Provenance: {finding_id}\n"
    )


def test_candidate_block_includes_nested_precondition_commitment(
    tmp_path: Path,
) -> None:
    ledger = _candidate_ledger(tmp_path, _complete_refutation("SGI-1", 41))

    assert ledger["status"] == "CLEAN"
    assert ledger["event_count"] == 1
    event = ledger["events"][0]
    assert event["source_item_id"] == "SGI-1"
    assert event["invariant_commitment"]["status"] == "COMPLETE"


def test_adjacent_nested_candidate_cannot_lend_its_commitment(
    tmp_path: Path,
) -> None:
    text = (
        "## Finding [SGI-1]: first candidate\n"
        "**Verdict**: REFUTATION_PROPOSAL\n"
        "**Location**: src/Vault.sol:L40\n\n"
        + _complete_refutation("SGI-2", 42).replace(
            "## Finding [SGI-2]", "### Finding [SGI-2]", 1
        ).replace("### Precondition Analysis", "#### Precondition Analysis", 1)
    )

    ledger = _candidate_ledger(tmp_path, text)
    by_id = {row["source_item_id"]: row for row in ledger["events"]}

    assert ledger["event_count"] == 2
    assert by_id["SGI-1"]["invariant_commitment"]["status"] == "DEBT"
    assert by_id["SGI-2"]["invariant_commitment"]["status"] == "COMPLETE"
    assert "DEPTH_COMMITTED_INVARIANT_DEBT" in {
        issue["code"] for issue in ledger["issues"]
    }


def test_non_candidate_parent_does_not_inherit_child_disposition(
    tmp_path: Path,
) -> None:
    ledger = _candidate_ledger(
        tmp_path,
        "# Audit output\n\n## Findings\n\n"
        "Introductory container prose.\n\n"
        "### Finding [SGI-1]: retained candidate\n"
        "**Verdict**: UNRESOLVED\n"
        "**Location**: src/Vault.sol:L9\n",
    )

    assert ledger["event_count"] == 1
    assert ledger["events"][0]["source_item_id"] == "SGI-1"
    assert ledger["events"][0]["identity_state"] == "EXACT"


def test_semantic_gap_skill_uses_exact_ids_and_producer_states() -> None:
    skill = (
        Path(__file__).resolve().parents[1]
        / "agents"
        / "skills"
        / "niche"
        / "semantic-gap-investigator"
        / "SKILL.md"
    ).read_text(encoding="utf-8")

    assert (
        "| Finding ID | Flag Type | Variable | Location | Disposition |" in skill
    )
    assert "| # | Flag Type |" not in skill
    assert "one unique, stable `SGI-N` ID" in skill
    assert (
        "exactly `REFUTATION_PROPOSAL`, `CANDIDATE`, or `UNRESOLVED`" in skill
    )
    assert "PENDING rows at completion are a workflow violation" in skill
    assert "**Invariant Commitment**: CI:CI-SGI-N" in skill
    assert "Provenance: SGI-N" in skill
    assert "Do not share a commitment between findings" in skill


def test_negated_accumulation_exposure_does_not_trigger_niche(
    tmp_path: Path,
) -> None:
    (tmp_path / "semantic_invariants.md").write_text(
        "# Semantic Invariants\n\n"
        "sync_gaps: 0\n"
        "accumulation_exposures: 0\n"
        "conditional_writes: 0\n"
        "cluster_gaps: 0\n\n"
        "No `ACCUMULATION_EXPOSURE` flags were found.\n",
        encoding="utf-8",
    )

    assert V._semantic_gap_trigger_counts(tmp_path) == {
        "sync_gaps": 0,
        "accumulation_exposures": 0,
        "conditional_writes": 0,
        "cluster_gaps": 0,
    }
    assert V._semantic_gap_required(tmp_path) is False


def test_affirmative_accumulation_exposure_still_triggers_niche(
    tmp_path: Path,
) -> None:
    (tmp_path / "semantic_invariants.md").write_text(
        "# Semantic Invariants\n\n"
        "Confirmed ACCUMULATION_EXPOSURE(input, block.timestamp).\n",
        encoding="utf-8",
    )

    assert V._semantic_gap_trigger_counts(tmp_path)[
        "accumulation_exposures"
    ] == 1
    assert V._semantic_gap_required(tmp_path) is True


def test_depth_transport_attempts_are_disjoint_across_outer_retries() -> None:
    first = {
        D._depth_transport_attempt_ordinal(
            outer_attempt=1, local_attempt=local, continuation_budget=3
        )
        for local in range(1, 6)
    }
    second = {
        D._depth_transport_attempt_ordinal(
            outer_attempt=2, local_attempt=local, continuation_budget=3
        )
        for local in range(1, 6)
    }

    assert first == {1, 2, 3, 4, 5}
    assert second == {6, 7, 8, 9, 10}
    assert first.isdisjoint(second)


def _depth_phase() -> Phase:
    return Phase(
        name="depth",
        section_markers=["Depth"],
        expected_artifacts=["depth_*_findings.md"],
        base_timeout_s=60,
        min_artifact_bytes=1,
    )


def _depth_config(tmp_path: Path, *, backend: str = "codex") -> dict[str, Any]:
    return {
        "cli_backend": backend,
        "mode": "core",
        "pipeline": "sc",
        "language": "evm",
        "scratchpad": str(tmp_path),
        "project_root": str(tmp_path),
        "_run_id": "12345678-1234-4123-8123-123456789abc",
        "pty_continuation_budget": 3,
    }


@pytest.mark.parametrize("backend", ("codex", "claude"))
def test_serial_depth_outer_retry_uses_fresh_leaf_ordinals(
    tmp_path: Path, monkeypatch, backend: str,
) -> None:
    job = {
        "agent_id": "producer",
        "role": "state_trace",
        "output": "depth_state_trace_findings.md",
        "category": "standard",
        "focus": "state",
    }
    attempts: list[int] = []
    monkeypatch.setattr(D, "_depth_worker_jobs", lambda *_a, **_k: [job])
    monkeypatch.setattr(D, "_prepare_depth_fuzz_workspaces", lambda jobs, **_k: jobs)
    monkeypatch.setattr(D, "_depth_worker_output_complete", lambda *_a, **_k: False)
    monkeypatch.setattr(D, "_finalize_depth_fuzz_result_authority", lambda **_k: None)
    monkeypatch.setattr(D, "_synthesize_depth_lifecycle_artifacts", lambda *_a, **_k: None)
    monkeypatch.setattr(D, "_depth_da_job_if_required", lambda *_a, **_k: [])

    def batch(**kwargs):
        attempts.append(int(kwargs["attempt"]))
        return {
            job["output"]: D._DepthSerialLaunchOutcome(
                rc=0, launch_started=True, prelaunch_blocked=False
            )
        }, None

    monkeypatch.setattr(D, "_run_depth_headless_batch", batch)

    assert D._run_depth_codex_fanout(
        phase=_depth_phase(),
        config=_depth_config(tmp_path, backend=backend),
        scratchpad=tmp_path,
        attempt=1,
    ) == 0
    assert D._run_depth_codex_fanout(
        phase=_depth_phase(),
        config=_depth_config(tmp_path, backend=backend),
        scratchpad=tmp_path,
        attempt=2,
    ) == 0
    assert attempts == [1, 2, 6, 7]
    assert len(attempts) == len(set(attempts))


def test_producer_retry_releases_dependent_never_cut_jobs(
    tmp_path: Path, monkeypatch,
) -> None:
    producer = {
        "agent_id": "semantic-gap",
        "role": "semantic_gap_investigator",
        "output": "niche_semantic_gap_findings.md",
        "category": "niche",
        "focus": "semantic gaps",
    }
    perturbation = {
        "agent_id": "perturbation",
        "role": "perturbation",
        "output": "perturbation_findings.md",
        "category": "perturbation",
        "focus": "perturbations",
    }
    checklist = {
        "agent_id": "skill-checklist",
        "role": "skill_execution_checklist",
        "output": "skill_execution_checklist.md",
        "category": "sidecar",
        "focus": "skill execution",
    }
    jobs = [producer, perturbation, checklist]
    complete: set[str] = set()
    waves: list[tuple[int, tuple[str, ...], dict[str, list[str]]]] = []
    prep_calls: list[tuple[str, ...]] = []

    monkeypatch.setattr(D, "_depth_worker_jobs", lambda *_a, **_k: jobs)
    monkeypatch.setattr(D, "_prepare_depth_fuzz_workspaces", lambda rows, **_k: rows)
    monkeypatch.setattr(
        D,
        "_depth_worker_output_complete",
        lambda _sp, _phase, job, **_k: str(job["output"]) in complete,
    )
    monkeypatch.setattr(D, "_record_typed_model_worker_artifact", lambda **_k: [])
    monkeypatch.setattr(D, "_finalize_depth_fuzz_workspace", lambda *_a, **_k: None)
    monkeypatch.setattr(D, "_finalize_depth_fuzz_result_authority", lambda **_k: None)
    monkeypatch.setattr(D, "_synthesize_depth_lifecycle_artifacts", lambda *_a, **_k: None)
    monkeypatch.setattr(D, "_depth_da_job_if_required", lambda *_a, **_k: [])
    monkeypatch.setattr(
        D,
        "_prepare_depth_post_producer_consumers",
        lambda _sp, _phase, rows, _mode: prep_calls.append(
            tuple(str(row["output"]) for row in rows)
        ),
    )

    def batch(**kwargs):
        attempt = int(kwargs["attempt"])
        outputs = tuple(str(row["output"]) for row in kwargs["jobs"])
        reasons = {
            str(key): list(values)
            for key, values in kwargs["retry_reasons_by_output"].items()
        }
        waves.append((attempt, outputs, reasons))
        # The semantic producer is rejected once, then succeeds on its bounded
        # retry.  Its dependent never-cut consumers must run immediately in a
        # second wave under that same fresh transport ordinal.
        if attempt == 2 and outputs == (producer["output"],):
            complete.add(producer["output"])
        elif set(outputs) == {perturbation["output"], checklist["output"]}:
            complete.update(outputs)
        return {
            output: D._DepthSerialLaunchOutcome(
                rc=0, launch_started=True, prelaunch_blocked=False
            )
            for output in outputs
        }, None

    monkeypatch.setattr(D, "_run_depth_headless_batch", batch)

    assert D._run_depth_codex_fanout(
        phase=_depth_phase(),
        config=_depth_config(tmp_path),
        scratchpad=tmp_path,
        attempt=1,
    ) == 0
    assert [row[:2] for row in waves] == [
        (1, (producer["output"],)),
        (2, (producer["output"],)),
        (2, (perturbation["output"], checklist["output"])),
    ]
    # A successful producer retry releases its old rejection reasons before
    # the dependent wave is compiled.
    assert waves[-1][2] == {}
    assert complete == {
        producer["output"], perturbation["output"], checklist["output"]
    }
    assert len(prep_calls) == 1


def test_claude_pty_outer_retry_uses_stride_mapped_ordinals(
    tmp_path: Path, monkeypatch,
) -> None:
    job = {
        "agent_id": "producer",
        "role": "state_trace",
        "output": "depth_state_trace_findings.md",
        "category": "standard",
        "focus": "state",
    }
    attempts: list[int] = []
    config = _depth_config(tmp_path, backend="claude")
    config["pty_continuation_budget"] = 1
    monkeypatch.setattr(D, "_depth_worker_jobs", lambda *_a, **_k: [job])
    monkeypatch.setattr(D, "_prepare_depth_fuzz_workspaces", lambda rows, **_k: rows)
    monkeypatch.setattr(D, "_depth_worker_output_complete", lambda *_a, **_k: False)
    monkeypatch.setattr(
        D,
        "_depth_dispatch_plan",
        lambda **kwargs: [{"job": job, "prompt": "bounded"}],
    )
    monkeypatch.setattr(D, "_write_depth_dispatch_contract", lambda *_a, **_k: None)
    monkeypatch.setattr(D, "gate_passes", lambda *_a, **_k: (False, ["missing"]))
    monkeypatch.setattr(D, "_stub_missing_fuzz_outputs_on_exhaustion", lambda *_a: False)
    monkeypatch.setattr(D, "_stub_missing_sibling_outputs_on_exhaustion", lambda *_a: False)

    def batch(**kwargs):
        attempts.append(int(kwargs["attempt"]))
        return 0, [{"output": job["output"], "status": "incomplete"}]

    monkeypatch.setattr(D, "_run_depth_worker_batch", batch)

    assert D._run_depth_worker_pool_pty(
        scratchpad=tmp_path,
        project_root=str(tmp_path),
        config=config,
        phase=_depth_phase(),
        base_cmd=["claude"],
        env={},
        timeout=1.0,
        quiescence_s=0.1,
        attempt=2,
    ) == -2
    # Leaf ordinals are bound to a durable transport GENERATION, not to the
    # semantic attempt: rate-limit/overload recovery re-dispatches the same
    # semantic attempt on purpose.  Assert the invariant (a fresh, disjoint,
    # stride-mapped band per dispatch), not the old attempt-derived constants.
    assert attempts == [1, 2]

    second: list[int] = []
    monkeypatch.setattr(
        D,
        "_run_depth_worker_batch",
        lambda **kwargs: (second.append(int(kwargs["attempt"])), 0)[1]
        or (0, [{"output": job["output"], "status": "incomplete"}]),
    )
    # Re-dispatch the SAME semantic attempt, as transport recovery does.
    assert D._run_depth_worker_pool_pty(
        scratchpad=tmp_path,
        project_root=str(tmp_path),
        config=config,
        phase=_depth_phase(),
        base_cmd=["claude"],
        env={},
        timeout=1.0,
        quiescence_s=0.1,
        attempt=2,
    ) == -2
    assert second and set(second).isdisjoint(attempts), (
        "re-dispatching the same semantic attempt replayed leaf ordinals; "
        "this is the INVOCATION_REPLAY failure that killed DODO run25"
    )


@pytest.mark.parametrize("backend", ("codex", "claude"))
def test_da_outer_retry_uses_fresh_leaf_ordinals(
    tmp_path: Path, monkeypatch, backend: str,
) -> None:
    ordinary = {
        "agent_id": "ordinary",
        "role": "state_trace",
        "output": "depth_state_trace_findings.md",
        "category": "standard",
        "focus": "state",
    }
    da = {
        "agent_id": "depth-da-iter2",
        "role": "da_iter2",
        "output": "depth_da_iter2_findings.md",
        "category": "da",
        "focus": "adversarial retry",
    }
    attempts: list[int] = []
    # The DA dispatch delta is published as an additive successor over the
    # already-committed shared skill dispatch, so that base artifact must
    # exist.  Production always has it by the time DA is scheduled; without
    # this fixture the DA path returned rc=-2 before any dispatch and the
    # ordinal assertion below silently exercised nothing.
    (tmp_path / "skill_dispatch.json").write_text(
        '{"schema": "plamen.skill-dispatch/v1", "workers": []}\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(D, "_depth_worker_jobs", lambda *_a, **_k: [ordinary])
    monkeypatch.setattr(D, "_prepare_depth_fuzz_workspaces", lambda rows, **_k: rows)
    monkeypatch.setattr(
        D,
        "_depth_worker_output_complete",
        lambda _sp, _phase, job, **_k: job["output"] == ordinary["output"],
    )
    monkeypatch.setattr(D, "_finalize_depth_fuzz_result_authority", lambda **_k: None)
    monkeypatch.setattr(D, "_synthesize_depth_lifecycle_artifacts", lambda *_a, **_k: None)
    monkeypatch.setattr(D, "_depth_da_job_if_required", lambda *_a, **_k: [da])
    def _plan(**kwargs):
        rows = []
        for row in kwargs["jobs"]:
            job = dict(row)
            prompt_sha = hashlib.sha256(
                f"bounded:{job.get('output')}".encode("utf-8")
            ).hexdigest()
            job["prompt_sha256"] = prompt_sha
            rows.append({
                "job": job,
                "prompt": "bounded",
                "prompt_sha256": prompt_sha,
                "dispatch_contract_sha256": hashlib.sha256(
                    f"contract:{job.get('output')}".encode("utf-8")
                ).hexdigest(),
                "methodology_dispatch": [],
            })
        return rows

    monkeypatch.setattr(D, "_depth_dispatch_plan", _plan)
    monkeypatch.setattr(D, "_write_depth_dispatch_contract", lambda *_a, **_k: None)
    monkeypatch.setattr(D, "_quarantine_incomplete_depth_retry_output", lambda *_a: None)
    monkeypatch.setattr(D, "_prepare_typed_model_worker_launch", lambda **_k: [])
    monkeypatch.setattr(D, "_typed_worker_registered_input_paths", lambda **_k: ())
    monkeypatch.setattr(
        D,
        "_compile_depth_worker_staged_gate_context",
        lambda **_k: ({}, ()),
    )
    monkeypatch.setattr(
        D,
        "_run_one_codex_exec",
        lambda **kwargs: attempts.append(int(kwargs["attempt"])) or 0,
    )
    monkeypatch.setattr(
        D,
        "_run_one_claude_headless_breadth_worker",
        lambda **kwargs: attempts.append(int(kwargs["attempt"])) or 0,
    )

    assert D._run_depth_codex_fanout(
        phase=_depth_phase(),
        config=_depth_config(tmp_path, backend=backend),
        scratchpad=tmp_path,
        attempt=2,
    ) == 0
    # See the PTY case above: ordinals follow the durable transport
    # generation, so the first dispatch in a fresh scratchpad uses band 1.
    assert attempts == [1, 2]

    first_band = list(attempts)
    attempts.clear()
    # Transport recovery re-runs the SAME semantic attempt and must still get
    # fresh leaf identities, or every worker is refused as a replay.
    assert D._run_depth_codex_fanout(
        phase=_depth_phase(),
        config=_depth_config(tmp_path, backend=backend),
        scratchpad=tmp_path,
        attempt=2,
    ) == 0
    assert attempts and set(attempts).isdisjoint(first_band)
