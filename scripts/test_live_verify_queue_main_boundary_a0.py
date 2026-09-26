"""Fixture-first A0 acceptance for the driver's live verify-queue boundary.

This is intentionally one layer above
``test_live_verify_queue_driver_adapter_cutover.py``.  The adapter suite proves
the private T0--T9 transaction.  These fixtures prove that the *driver-owned*
phase boundary:

* runs the mature pre-queue producers before the non-injectable adapter;
* invokes one shared SC/L1 boundary and one live transaction;
* admits only an independently valid T9 publication;
* commits the typed phase checkpoint without re-entering legacy queue routing;
* records an incomplete, retryable, visible phase attempt when a producer or
  the adapter fails before safe publication.

Required production seam
------------------------

``plamen_driver._run_live_verify_queue_phase_boundary`` with keyword-only
parameters:

``phase, checkpoint, scratchpad, config, phases, trust_preverify_issues,
failpoint``

The seam is not a dependency-injection surface: it must import/call the real
``run_live_verify_queue_driver_cutover`` itself.  ``failpoint`` is forwarded
unchanged only to the adapter's existing crash/replay test seam.  It returns a
mapping with:

``schema_version == "plamen.live_verify_queue_phase_boundary.v1"``
``state in {"COMMITTED", "INCOMPLETE_WITH_DEBT"}``
``safe_to_continue: bool``
``issues: list[str]``
``cutover_result: mapping | None``

On success it also returns ``active_count`` and ``manifest_count``.  On a
producer/adapter failure it appends a durable phase debt, commits an
``INCOMPLETE_WITH_DEBT`` attempt, and returns without publishing a queue.
``main`` remains responsible for the user-facing diagnosis and degraded exit.

No model, toolchain, network, install, or audit process is launched here.
"""
from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path
import sys
from typing import Any, Callable, Mapping, Sequence
import uuid

import pytest

from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
import p0af_v2_queue_adapter as P0AF_V2
from p0af_v2_queue_runtime import p0af_v2_resume_contract_issues
from phase_io_contracts import ArtifactSpec, LaunchSpec, PhaseIOContract, canonical_work_unit_key
import plamen_driver as DRIVER
from finding_producer_registry import (
    write_application_skeptic_proposal_projection,
)
from security_obligation_authority import (
    AUTHORITY_FILE as SECURITY_OBLIGATION_AUTHORITY_FILE,
)
import security_obligation_authority as SECURITY_AUTHORITY
import security_obligation_lifecycle as SECURITY_LIFECYCLE
import test_live_verify_queue_driver_adapter_cutover as ADAPTER_FIXTURE
import test_live_verify_queue_transaction_semantic_closure as LIVE
from test_security_obligation_lifecycle_p1_c import (
    RUN_ID as SECURITY_LIFECYCLE_RUN_ID,
    _setup as setup_security_obligation_source,
)
from verify_queue_transaction import validate_live_verify_queue_publication


BOUNDARY_NAME = "_run_live_verify_queue_phase_boundary"
BOUNDARY_SCHEMA = "plamen.live_verify_queue_phase_boundary.v1"
P1M_OPTIONAL_OUTPUTS = frozenset({
    P0AF_V2.CANDIDATE_FILE,
    P0AF_V2.WORK_AUTHORITY_FILE,
    P0AF_V2.ROUTE_DEBT_FILE,
})
CHAIN_GROUPING_OPTIONAL_OUTPUTS = frozenset({
    "chain_grouping_relations.json",
    "chain_anti_absorption_applied_receipt.json",
})
EXPECTED_PARAMETERS = (
    "phase",
    "checkpoint",
    "scratchpad",
    "config",
    "phases",
    "trust_preverify_issues",
    "failpoint",
)


def _boundary(*, required: bool = True) -> Callable[..., Mapping[str, Any]] | None:
    candidate = getattr(DRIVER, BOUNDARY_NAME, None)
    if callable(candidate):
        return candidate
    if required:
        pytest.fail(
            "production lacks the fixture-first live queue main-loop seam: "
            f"plamen_driver.{BOUNDARY_NAME}; see this module's docstring for "
            "the exact non-injectable API and outcome contract"
        )
    return None


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _canonical_run_id(pipeline: str) -> str:
    # Stable UUIDv4 values: PhaseCommit rejects informal fixture identifiers.
    return {
        "sc": "92ba4d6b-2ca8-4f45-8b2f-90922821f639",
        "l1": "3517b278-5a27-4513-86d2-bbf0b57cefc7",
    }[pipeline]


def _claim_chain_model_pair(
    *,
    root: Path,
    project: Path,
    config: Mapping[str, Any],
    run_id: str,
) -> None:
    # ``chain/model`` owns one atomic trio in production.  The frozen
    # pre-verification projection consumes the enabler bytes as a transitive
    # source preimage, so a fixture that claims only the older two-file pair
    # is not a faithful current-run producer.
    paths = ("hypotheses.md", "finding_mapping.md", "enabler_results.md")
    owner = canonical_work_unit_key(
        "sc",
        str(config["mode"]),
        str(config["ecosystem"]),
        str(config["backend"]),
        "chain",
        "model",
    )
    postimages = {
        relative: (root / relative).read_bytes()
        for relative in paths
    }
    for relative in paths:
        (root / relative).unlink()
    contract = PhaseIOContract(
        pipeline="sc",
        mode=str(config["mode"]),
        ecosystem=str(config["ecosystem"]),
        backend=str(config["backend"]),
        phase="chain",
        work_unit_id="model",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=relative,
                owner_key=owner,
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="CREATE",
                schema_version="unstructured.v1",
                minimum_gate="FIXTURE_CHAIN_MODEL_PAIR",
                consumers=("sc_verify_queue/preverify_chain_pair",),
            )
            for relative in paths
        ),
        immutable_inputs=(),
        bounded_lookup_inputs=(),
        model_invoked=True,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="fixture-chain",
        timeout_s=60,
        exec_mode="pty",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(root, project, contract, launch, run_id=run_id)
    for relative, raw in postimages.items():
        (root / relative).write_bytes(raw)
    record_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        actor="MODEL",
    )


def _seed(
    project: Path,
    *,
    pipeline: str,
    backend: str = "claude",
    preseed_adapter_successors: bool = True,
) -> tuple[Path, dict[str, Any], str]:
    """Seed the adapter's real current-run authority with a canonical run UUID."""
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    run_id = _canonical_run_id(pipeline)
    config = ADAPTER_FIXTURE._dimensions(
        pipeline=pipeline,
        backend=backend,
        project=project,
        root=root,
        run_id=run_id,
    )
    # Frozen/preverify generations are produced by the real boundary below;
    # pre-seeding LIVE._upstream_inputs() would counterfeit those outputs as
    # ordinary upstream fixture files.  Seed only the pre-projection roots.
    roster = set(LIVE._base_upstream_inputs(pipeline))
    if not preseed_adapter_successors:
        roster -= {
            # These are produced by the real preverify-successor transaction
            # in boundary tests.  The lower-level adapter fixture lists them
            # as required inputs because it begins after that transaction.
            "preverify_inventory_successor.json",
            "finding_delivery_successor.json",
        }
    # The P1-M trio is one registered, atomic chain-phase output family.  This
    # fixture begins at the queue boundary and does not run the authentication
    # role/composition workers, so its faithful no-composition branch leaves
    # the entire optional family absent.  Seeding only the plan/route siblings
    # would create an impossible partial family under a generic fixture owner.
    # This queue-boundary fixture also omits the depth phase.  Its final
    # security-obligation authority is therefore genuinely absent, not a
    # schema-looking file owned by the generic fixture producer.  The report
    # integration publishes the real haltless missing-source lifecycle later.
    absent = frozenset({SECURITY_OBLIGATION_AUTHORITY_FILE}) | (
        P1M_OPTIONAL_OUTPUTS | CHAIN_GROUPING_OPTIONAL_OUTPUTS
        if pipeline == "sc"
        else frozenset()
    )

    (root / "findings_inventory.md").write_text(
        "# Findings Inventory\n", encoding="utf-8"
    )
    write_application_skeptic_proposal_projection(root, [])
    write_application_skeptic_proposal_projection(
        root,
        [],
        projection_name="candidate_negative_skeptic_proposals.md",
    )
    (root / "config.json").write_bytes(_canonical_bytes(config))
    for relative in sorted(roster - absent):
        if relative == "live_verify_queue_methodology_projection.receipt.json":
            # Solely produced from the implementation's authoritative sources.
            continue
        path = root / relative
        if path.exists():
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(
            b"# Current-run main boundary fixture\n"
            if path.suffix == ".md"
            else _canonical_bytes({"artifact": relative})
        )

    # These mutable roots are finalized by mature producers immediately before
    # the queue boundary. Claim them after context seeding so the fixture does
    # not accidentally overwrite its own producer postimage.
    late_producer_roots = {
        "findings_inventory.md",
        "inventory_evidence_validation.md",
        "hypotheses.md",
        "finding_mapping.md",
    }
    present = sorted(
        relative
        for relative in roster
        if (root / relative).is_file()
        and relative not in late_producer_roots
    )
    ADAPTER_FIXTURE._claim_group(
        root=root,
        project=project,
        config=config,
        run_id=run_id,
        paths=present,
        work_unit_id="current_run_upstream",
    )
    for relative in LIVE.CONTEXT_INPUTS:
        if relative.startswith("project::"):
            path = project / relative[len("project::"):]
            raw = b"// bounded main-boundary context\n"
        elif relative in {
            "methodology_registry.json",
            "methodology_reachability_manifest.json",
        }:
            continue
        else:
            path = root / relative
            raw = _canonical_bytes({"artifact": relative})
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    for relative, raw in {
        "inventory_evidence_validation.md":
            b"# Inventory Evidence Validation\n\n",
        # One internally consistent relation row makes this a clean authority
        # fixture.  Header-only tables are deliberately classified as
        # ambiguity debt by the production pair validator.
        "hypotheses.md": (
            b"# Hypotheses\n\n"
            b"| Hypothesis ID | Severity | Title | Constituent Findings |\n"
            b"|---|---|---|---|\n"
            b"| H-1 | Low | Fixture relation | INV-1 |\n"
        ),
        "finding_mapping.md": (
            b"# Finding Mapping\n\n"
            b"| Finding ID | Hypothesis ID | Mapping Status |\n"
            b"|---|---|---|\n"
            b"| INV-1 | H-1 | GROUPED |\n"
        ),
        "enabler_results.md": b"# Enabler Results\n\n",
    }.items():
        path = root / relative
        if pipeline == "sc" or not path.is_file():
            path.write_bytes(raw)
    final_roots = sorted(
        relative
        for relative in late_producer_roots
        if (root / relative).is_file()
        and not (
            pipeline == "sc"
            and relative in {"hypotheses.md", "finding_mapping.md"}
        )
    )
    ADAPTER_FIXTURE._claim_group(
        root=root,
        project=project,
        config=config,
        run_id=run_id,
        paths=final_roots,
        work_unit_id="final_mutable_roots",
    )
    if pipeline == "sc":
        _claim_chain_model_pair(
            root=root,
            project=project,
            config=config,
            run_id=run_id,
        )
    return root, config, run_id


def _phase_and_graph(pipeline: str):
    phases = DRIVER.SC_PHASES if pipeline == "sc" else DRIVER.L1_PHASES
    wanted = "sc_verify_queue" if pipeline == "sc" else "verify_queue"
    return next(phase for phase in phases if phase.name == wanted), phases


def _checkpoint(
    scratchpad: Path,
    config: Mapping[str, Any],
    run_id: str,
) -> Any:
    checkpoint = DRIVER.Checkpoint(
        completed=[],
        degraded=[],
        config=dict(config),
        audit_snapshot=dict(config["_audit_snapshot"]),
        run_id=run_id,
    )
    checkpoint.save(scratchpad)
    return checkpoint


def _public_bytes(root: Path, pipeline: str) -> dict[str, bytes]:
    return {
        relative: (root / relative).read_bytes()
        for relative in LIVE._pipeline_public(pipeline)
        if (root / relative).is_file()
    }


def _patch_prequeue_producers(
    monkeypatch: pytest.MonkeyPatch,
    trace: list[str],
    *,
    pipeline: str,
) -> list[str]:
    """Instrument producer ordering while retaining the real adapter/commit."""
    expected: list[str] = []

    def patch(name: str, label: str, result: Any) -> None:
        expected.append(label)

        def stub(*_args: Any, **_kwargs: Any) -> Any:
            trace.append(label)
            return result

        monkeypatch.setattr(DRIVER, name, stub)

    patch("_inventory_has_usable_findings", "inventory-check", False)
    if pipeline == "sc":
        patch("ensure_findings_inventory_floor", "inventory-floor", (0, 0))
    else:
        monkeypatch.setattr(
            DRIVER,
            "ensure_findings_inventory_floor",
            lambda *_a, **_k: (_ for _ in ()).throw(
                AssertionError(
                    "L1 queue mutated inventory after successor authority"
                )
            ),
        )
    # Both pipelines freeze all additive producers before semantic dedup.
    # Re-running the legacy raw promoter at the queue boundary would be an
    # unauthorized second writer over the canonical inventory generation.
    patch("_validate_inventory_evidence", "inventory-evidence", None)
    patch("_validate_depth_promotion_receipt", "depth-receipt", [])
    if pipeline == "l1":
        patch("_run_l1_composition_live_boundary", "l1-composition", [])
    if pipeline == "sc":
        expected.append("chain-pair-projection")
        original_projection = (
            DRIVER.prepare_preverify_chain_pair_projection
        )

        def observed_projection(*args: Any, **kwargs: Any) -> Any:
            trace.append("chain-pair-projection")
            return original_projection(*args, **kwargs)

        monkeypatch.setattr(
            DRIVER,
            "prepare_preverify_chain_pair_projection",
            observed_projection,
        )
    # The stable successor is now a mandatory frozen-authority provider, not
    # an observational producer that this ordering fixture may replace with a
    # no-op.  Instrument the real implementation so the subsequent live
    # adapter sees the same capability a production run would.
    expected.append("inventory-successors")
    original_successors = DRIVER._finalize_preverify_inventory_successors

    def observed_successors(*args: Any, **kwargs: Any) -> Any:
        trace.append("inventory-successors")
        return original_successors(*args, **kwargs)

    monkeypatch.setattr(
        DRIVER,
        "_finalize_preverify_inventory_successors",
        observed_successors,
    )
    # Registered-delivery validation runs after successor finalization.
    expected.append("registered-delivery")

    def observed_delivery(*_args: Any, **_kwargs: Any) -> list[str]:
        trace.append("registered-delivery")
        return []

    monkeypatch.setattr(
        DRIVER,
        "_validate_registered_finding_delivery_receipt",
        observed_delivery,
    )
    return expected


def _invoke(
    *,
    boundary: Callable[..., Mapping[str, Any]],
    phase: Any,
    checkpoint: Any,
    root: Path,
    config: dict[str, Any],
    phases: Sequence[Any],
    failpoint: Callable[[str], None] | None = None,
) -> Mapping[str, Any]:
    return boundary(
        phase=phase,
        checkpoint=checkpoint,
        scratchpad=root,
        config=config,
        phases=phases,
        trust_preverify_issues=(),
        failpoint=failpoint,
    )


def test_driver_exports_narrow_live_queue_phase_boundary() -> None:
    boundary = _boundary()
    assert boundary is not None
    signature = inspect.signature(boundary)
    assert tuple(signature.parameters) == EXPECTED_PARAMETERS
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in signature.parameters.values()
    )
    assert all(
        forbidden not in signature.parameters
        for forbidden in (
            "adapter",
            "semantic_executor",
            "runtime_authority",
            "upstream_inputs",
            "plan",
        )
    )


def test_main_routes_both_queue_phases_through_one_shared_boundary() -> None:
    if _boundary(required=False) is None:
        pytest.skip("blocked by the required fixture-first boundary seam")
    tree = ast.parse(inspect.getsource(DRIVER.main))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == BOUNDARY_NAME
    ]
    direct_adapter_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (
            (
                isinstance(node.func, ast.Name)
                and node.func.id == "run_live_verify_queue_driver_cutover"
            )
            or (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "run_live_verify_queue_driver_cutover"
            )
        )
    ]
    assert len(calls) == 1
    assert not direct_adapter_calls
    call = calls[0]
    assert {keyword.arg for keyword in call.keywords} >= {
        "phase",
        "checkpoint",
        "scratchpad",
        "config",
        "phases",
        "trust_preverify_issues",
    }


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
def test_real_boundary_orders_producers_commits_t9_without_legacy_remutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline: str,
) -> None:
    boundary = _boundary(required=False)
    if boundary is None:
        pytest.skip("blocked by the required fixture-first boundary seam")
    project = tmp_path / f"{pipeline}-project"
    project.mkdir()
    root, config, run_id = _seed(
        project,
        pipeline=pipeline,
        preseed_adapter_successors=False,
    )
    assert not (root / SECURITY_OBLIGATION_AUTHORITY_FILE).exists()
    assert not (root / SECURITY_OBLIGATION_AUTHORITY_FILE).is_symlink()
    if pipeline == "sc":
        assert all(
            not (root / name).exists() and not (root / name).is_symlink()
            for name in P1M_OPTIONAL_OUTPUTS
        )
        p1m_key = canonical_work_unit_key(
            "sc",
            str(config["mode"]),
            str(config["ecosystem"]),
            str(config["backend"]),
            "chain",
            "authentication_roles.compound_work",
        )
        assert p1m_key not in read_artifact_ledger(root)["work_units"]
    phase, phases = _phase_and_graph(pipeline)
    checkpoint = _checkpoint(root, config, run_id)
    trace: list[str] = []
    expected_producers = _patch_prequeue_producers(
        monkeypatch, trace, pipeline=pipeline
    )
    l1_inventory_before = (
        (root / "findings_inventory.md").read_bytes()
        if pipeline == "l1"
        else b""
    )

    # The live precommit validator must consume T9 authority and must never call
    # the old markdown router after publication.
    def forbidden_legacy_router(*_args: Any, **_kwargs: Any) -> list[str]:
        raise AssertionError("legacy queue routing re-entered after live T9")

    monkeypatch.setattr(
        DRIVER,
        "_record_typed_verify_queue_routing_artifacts",
        forbidden_legacy_router,
    )

    # Instrument, but do not fake, the typed phase commit.  Public bytes must be
    # byte-identical before and after that real commit.
    original_commit = DRIVER._commit_verification_transaction
    commit_observations: list[tuple[dict[str, bytes], dict[str, bytes]]] = []

    def observed_commit(*args: Any, **kwargs: Any) -> Any:
        before = _public_bytes(root, pipeline)
        committed = original_commit(*args, **kwargs)
        after = _public_bytes(root, pipeline)
        commit_observations.append((before, after))
        return committed

    monkeypatch.setattr(
        DRIVER, "_commit_verification_transaction", observed_commit
    )

    failpoints: list[str] = []

    def observe(label: str) -> None:
        failpoints.append(label)
        if label == ADAPTER_FIXTURE.PLAN_FAILPOINT:
            trace.append("adapter-plan-resolved")

    outcome = _invoke(
        boundary=boundary,
        phase=phase,
        checkpoint=checkpoint,
        root=root,
        config=config,
        phases=phases,
        failpoint=observe,
    )

    assert outcome["schema_version"] == BOUNDARY_SCHEMA
    assert outcome["state"] == "COMMITTED"
    assert outcome["safe_to_continue"] is True
    if pipeline == "l1":
        assert outcome["issues"] == [
            "L1 semantic precision phase did not commit; queue T0 consumed "
            "the authenticated upstream recall floor"
        ]
        assert (
            root / "findings_inventory.md"
        ).read_bytes() == l1_inventory_before
    else:
        assert outcome["issues"] == []
    cutover = outcome["cutover_result"]
    assert cutover["safe_to_consume"] is True
    assert failpoints.count(ADAPTER_FIXTURE.PLAN_FAILPOINT) == 1
    assert failpoints.count("after_t0_arm") == 1
    assert failpoints.count("after_t9_commit") == 1
    assert trace[: len(expected_producers)] == expected_producers
    assert trace[len(expected_producers)] == "adapter-plan-resolved"

    assert len(commit_observations) == 1
    before_commit, after_commit = commit_observations[0]
    assert before_commit
    assert before_commit == after_commit
    validation = validate_live_verify_queue_publication(
        scratchpad=root,
        project_root=project,
        plan=cutover["plan"],
        run_id=run_id,
    )
    assert validation["safe_to_consume"] is True
    if pipeline == "sc":
        # The real T0--T9 commit must remain resumable without inventing a
        # P1-M producer for the explicitly absent no-composition branch.
        assert p0af_v2_resume_contract_issues(root, config) == []

    durable = DRIVER.Checkpoint.load(root)
    assert phase.name in durable.completed
    if pipeline == "l1":
        assert phase.name in durable.degraded
        assert (
            durable.phase_commits[phase.name].state
            == "COMPLETED_WITH_DEBT"
        )
    else:
        assert phase.name not in durable.degraded
        assert durable.phase_commits[phase.name].state == "CLEAN"
    assert "_live_verify_queue_cutover_result" not in config


def test_partial_p1m_family_is_not_adopted_as_resume_authority(
    tmp_path: Path,
) -> None:
    project = tmp_path / "partial-p1m-project"
    project.mkdir()
    root, config, _run_id = _seed(
        project,
        pipeline="sc",
        preseed_adapter_successors=False,
    )
    assert all(not (root / name).exists() for name in P1M_OPTIONAL_OUTPUTS)

    # One unowned sibling cannot turn the absent branch into a P1-M producer.
    # This is deliberately malformed adversarial state, not fixture authority.
    (root / P0AF_V2.ROUTE_DEBT_FILE).write_bytes(
        _canonical_bytes({"artifact": P0AF_V2.ROUTE_DEBT_FILE})
    )
    issues = p0af_v2_resume_contract_issues(root, config)
    assert any(
        "P1-M authenticated producer invalid on resume" in issue
        for issue in issues
    )
    assert any("upstream ledger row absent" in issue for issue in issues)


def test_queue_boundary_without_chain_producer_does_not_forge_relation_authority(
    tmp_path: Path,
) -> None:
    project = tmp_path / "absent-chain-grouping-project"
    project.mkdir()
    root, config, _run_id = _seed(
        project,
        pipeline="sc",
        preseed_adapter_successors=False,
    )
    outputs = tuple(root / name for name in CHAIN_GROUPING_OPTIONAL_OUTPUTS)
    assert all(not path.exists() and not path.is_symlink() for path in outputs)

    floor = next(phase for phase in DRIVER.SC_PHASES if phase.name == "report_floor")
    assert DRIVER._write_and_record_chain_grouping_assurance(
        scratchpad=root,
        config=config,
        phase=floor,
    ) == []
    assert all(not path.exists() and not path.is_symlink() for path in outputs)
    assert not (root / "chain_grouping_assurance_reconciliation.json").exists()
    assert not (root / "chain_grouping_assurance_limitations.md").exists()

    # A schema-looking generic fixture blob is not equivalent to absence and
    # must remain explicit integrity debt rather than being silently ignored.
    (root / "chain_grouping_relations.json").write_bytes(
        _canonical_bytes({"artifact": "chain_grouping_relations.json"})
    )
    issues = DRIVER._write_and_record_chain_grouping_assurance(
        scratchpad=root,
        config=config,
        phase=floor,
    )
    assert issues == [
        "chain grouping assurance reconciliation failed: ValueError: "
        "chain grouping relation receipt digest mismatch"
    ]


def test_absent_depth_authority_publishes_registered_report_lifecycle_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Reuse the established genuine inventory/chain producers.  Importing
    # lazily avoids the fixture module's deliberate dependency on this queue
    # boundary module during collection.
    from test_verification_report_tail_same_run_integration import (
        _install_supported_queue_seed,
    )

    project = tmp_path / "missing-depth-authority-project"
    (project / "src").mkdir(parents=True)
    (project / "src" / "Unit.sol").write_text(
        "pragma solidity ^0.8.20; contract Unit { uint256 public value; }\n",
        encoding="utf-8",
    )
    _install_supported_queue_seed(monkeypatch)
    root, config, run_id = _seed(
        project,
        pipeline="sc",
        preseed_adapter_successors=False,
    )
    phase, phases = _phase_and_graph("sc")
    checkpoint = _checkpoint(root, config, run_id)
    _patch_prequeue_producers(monkeypatch, [], pipeline="sc")
    outcome = _invoke(
        boundary=_boundary(),
        phase=phase,
        checkpoint=checkpoint,
        root=root,
        config=config,
        phases=phases,
    )
    assert outcome["state"] == "COMMITTED"
    assert outcome["safe_to_continue"] is True
    candidate_ids = tuple(
        row["finding id"] for row in DRIVER.parse_verification_queue_rows(root)
    )
    assert candidate_ids
    assert not (root / SECURITY_OBLIGATION_AUTHORITY_FILE).exists()
    lifecycle_inputs = SECURITY_LIFECYCLE.security_obligation_lifecycle_input_artifacts(
        root
    )
    assert "_v2_checkpoint.json" not in lifecycle_inputs

    issues = DRIVER._record_security_obligation_lifecycle_phase_io(root, config)
    assert issues == [
        "security-obligation lifecycle retained unresolved/debt aliases "
        "for human review"
    ]
    assert DRIVER._validate_security_obligation_lifecycle_phase_io(
        root, config
    ) == []
    authority = json.loads(
        (root / SECURITY_LIFECYCLE.AUTHORITY_FILE).read_text(
            encoding="utf-8", errors="strict"
        )
    )
    assert authority["status"] == "DEGRADED_HUMAN_REVIEW"
    assert authority["run_id"] == run_id
    assert authority["source_authority_digest"] is None
    assert authority["denominator_complete"] is False
    assert authority["rows"] == []
    assert authority["issues"] == [
        "security_authority: missing, malformed, or digest-mismatched"
    ]

    contract, _launch = DRIVER._security_obligation_lifecycle_contract_and_launch(
        root, config
    )
    ledger = read_artifact_ledger(root)
    row = ledger["work_units"][contract.key]
    identities = {
        f"scratchpad:{SECURITY_LIFECYCLE.AUTHORITY_FILE}",
        f"scratchpad:{SECURITY_LIFECYCLE.PROJECTION_FILE}",
        f"scratchpad:{SECURITY_LIFECYCLE.REPORT_RETENTION_FILE}",
    }
    assert row["semantic_status"] == "ACTIVE"
    assert row["execution_state"] == "OUTPUT_COMMITTED"
    assert set(row["artifacts"]) == identities
    assert "scratchpad:security_obligation_authority.json" not in row[
        "input_bindings"
    ]
    assert "scratchpad:_v2_checkpoint.json" not in row["input_bindings"]
    assert all(
        ledger["artifact_bindings"][identity]["owner_key"] == contract.key
        for identity in identities
    )
    retained = {
        path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
        for path in (
            *(root / identity.split(":", 1)[1] for identity in sorted(identities)),
            root / "_artifact_state.json",
        )
    }

    # A normal atomic checkpoint save may replace the inode even when its
    # semantic bytes are unchanged. Missing-source lifecycle authority is
    # bound to the authenticated driver run, not this unused mutable file.
    checkpoint_path = root / "_v2_checkpoint.json"
    checkpoint_bytes = checkpoint_path.read_bytes()
    checkpoint_inode = checkpoint_path.stat().st_ino
    DRIVER.Checkpoint.load(root).save(root)
    assert checkpoint_path.read_bytes() == checkpoint_bytes
    assert checkpoint_path.stat().st_ino != checkpoint_inode
    assert (
        SECURITY_LIFECYCLE.security_obligation_lifecycle_input_artifacts(root)
        == lifecycle_inputs
    )

    assert DRIVER._record_security_obligation_lifecycle_phase_io(root, config) == []
    assert DRIVER._validate_security_obligation_lifecycle_phase_io(
        root, config
    ) == []
    assert {
        path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
        for path in retained
    } == retained
    assert tuple(
        row["finding id"] for row in DRIVER.parse_verification_queue_rows(root)
    ) == candidate_ids


def test_lifecycle_expected_run_refuses_invalid_or_cross_run_source(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing"
    missing.mkdir()
    for invalid in ("", " ", 7):
        with pytest.raises(
            SECURITY_LIFECYCLE.SecurityObligationLifecycleError,
            match="expected_run_id must be one nonblank trimmed string",
        ):
            SECURITY_LIFECYCLE.build_security_obligation_lifecycle(
                missing, expected_run_id=invalid  # type: ignore[arg-type]
            )

    source_parent = tmp_path / "genuine-source"
    source_parent.mkdir()
    source_root, _aliases = setup_security_obligation_source(
        source_parent, count=1
    )
    assert not (source_root / SECURITY_LIFECYCLE.AUTHORITY_FILE).exists()
    source = json.loads(
        (source_root / SECURITY_OBLIGATION_AUTHORITY_FILE).read_text(
            encoding="utf-8", errors="strict"
        )
    )
    assert source["run_binding"]["run_id"] == SECURITY_LIFECYCLE_RUN_ID
    source_bytes = (source_root / SECURITY_OBLIGATION_AUTHORITY_FILE).read_bytes()
    with pytest.raises(
        SECURITY_LIFECYCLE.SecurityObligationLifecycleError,
        match="security authority run_id differs from expected driver run",
    ):
        SECURITY_LIFECYCLE.write_security_obligation_lifecycle(
            source_root,
            expected_run_id="87654321-4321-4321-8321-cba987654321",
        )
    assert not (source_root / SECURITY_LIFECYCLE.AUTHORITY_FILE).exists()
    assert (
        source_root / SECURITY_OBLIGATION_AUTHORITY_FILE
    ).read_bytes() == source_bytes
    assert SECURITY_LIFECYCLE_RUN_ID != (
        "87654321-4321-4321-8321-cba987654321"
    )

    blank_root = tmp_path / "blank-source-run"
    blank_root.mkdir()
    blank_source = SECURITY_AUTHORITY.write_security_obligation_authority(
        blank_root
    )
    assert blank_source["run_binding"]["run_id"] == ""
    with pytest.raises(
        SECURITY_LIFECYCLE.SecurityObligationLifecycleError,
        match="security authority run_id differs from expected driver run",
    ):
        SECURITY_LIFECYCLE.write_security_obligation_lifecycle(
            blank_root, expected_run_id=SECURITY_LIFECYCLE_RUN_ID
        )
    assert not (blank_root / SECURITY_LIFECYCLE.AUTHORITY_FILE).exists()

    rejected_parent = tmp_path / "digest-rejected-source"
    rejected_parent.mkdir()
    rejected_root, _rejected_aliases = setup_security_obligation_source(
        rejected_parent, count=1
    )
    rejected_source_path = rejected_root / SECURITY_OBLIGATION_AUTHORITY_FILE
    rejected_source = json.loads(
        rejected_source_path.read_text(encoding="utf-8", errors="strict")
    )
    rejected_source["authority_digest"] = "0" * 64
    rejected_source_path.write_bytes(_canonical_bytes(rejected_source))
    assert rejected_source_path.name in (
        SECURITY_LIFECYCLE.security_obligation_lifecycle_input_artifacts(
            rejected_root
        )
    )
    assert "_v2_checkpoint.json" not in (
        SECURITY_LIFECYCLE.security_obligation_lifecycle_input_artifacts(
            rejected_root
        )
    )


def test_adapter_crash_before_t9_records_retryable_debt_without_public_queue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    boundary = _boundary(required=False)
    if boundary is None:
        pytest.skip("blocked by the required fixture-first boundary seam")
    project = tmp_path / "adapter-failure-project"
    project.mkdir()
    pipeline = "sc"
    root, config, run_id = _seed(
        project,
        pipeline=pipeline,
        preseed_adapter_successors=False,
    )
    phase, phases = _phase_and_graph(pipeline)
    checkpoint = _checkpoint(root, config, run_id)
    # Production startup keeps the live config object on the checkpoint.
    # Transient queue-context state must therefore remain JSON-serializable
    # when a failpoint commits retryable debt.
    checkpoint.config = config
    _patch_prequeue_producers(monkeypatch, [], pipeline=pipeline)
    before = _public_bytes(root, pipeline)

    def crash(label: str) -> None:
        if label == "after_t8_commit":
            raise RuntimeError("fixture crash before T9")

    outcome = _invoke(
        boundary=boundary,
        phase=phase,
        checkpoint=checkpoint,
        root=root,
        config=config,
        phases=phases,
        failpoint=crash,
    )

    assert outcome["schema_version"] == BOUNDARY_SCHEMA
    assert outcome["state"] == "INCOMPLETE_WITH_DEBT"
    assert outcome["safe_to_continue"] is False
    assert any(
        "fixture crash before T9" in issue for issue in outcome["issues"]
    ), outcome["issues"]
    assert _public_bytes(root, pipeline) == before
    durable = DRIVER.Checkpoint.load(root)
    assert phase.name not in durable.completed
    assert phase.name in durable.degraded
    assert durable.phase_commits[phase.name].state == "INCOMPLETE_WITH_DEBT"
    debt = (root / f"{phase.name}.degraded").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "LIVE_VERIFY_QUEUE" in debt
    assert "fixture crash before T9" in debt
    assert "_live_verify_queue_cutover_result" not in config


def test_prequeue_producer_failure_is_visible_and_adapter_never_arms(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    boundary = _boundary(required=False)
    if boundary is None:
        pytest.skip("blocked by the required fixture-first boundary seam")
    project = tmp_path / "producer-failure-project"
    project.mkdir()
    pipeline = "sc"
    root, config, run_id = _seed(
        project,
        pipeline=pipeline,
        preseed_adapter_successors=False,
    )
    phase, phases = _phase_and_graph(pipeline)
    checkpoint = _checkpoint(root, config, run_id)
    _patch_prequeue_producers(monkeypatch, [], pipeline=pipeline)

    def fail_inventory_evidence(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("fixture producer failure")

    monkeypatch.setattr(
        DRIVER, "_validate_inventory_evidence", fail_inventory_evidence
    )
    labels: list[str] = []
    outcome = _invoke(
        boundary=boundary,
        phase=phase,
        checkpoint=checkpoint,
        root=root,
        config=config,
        phases=phases,
        failpoint=labels.append,
    )

    assert outcome["state"] == "INCOMPLETE_WITH_DEBT"
    assert outcome["safe_to_continue"] is False
    assert any("fixture producer failure" in issue for issue in outcome["issues"])
    assert ADAPTER_FIXTURE.PLAN_FAILPOINT not in labels
    assert not _public_bytes(root, pipeline)
    durable = DRIVER.Checkpoint.load(root)
    assert phase.name not in durable.completed
    assert durable.phase_commits[phase.name].state == "INCOMPLETE_WITH_DEBT"


def test_boundary_rejects_wrong_phase_pipeline_tuple_before_producers(
    tmp_path: Path,
) -> None:
    boundary = _boundary(required=False)
    if boundary is None:
        pytest.skip("blocked by the required fixture-first boundary seam")
    project = tmp_path / "tuple-drift-project"
    project.mkdir()
    root, config, run_id = _seed(
        project,
        pipeline="sc",
        preseed_adapter_successors=False,
    )
    wrong_phase, phases = _phase_and_graph("l1")
    checkpoint = _checkpoint(root, config, run_id)
    outcome = _invoke(
        boundary=boundary,
        phase=wrong_phase,
        checkpoint=checkpoint,
        root=root,
        config=config,
        phases=phases,
    )
    assert outcome["state"] == "INCOMPLETE_WITH_DEBT"
    assert outcome["safe_to_continue"] is False
    assert any("tuple" in issue.lower() for issue in outcome["issues"])
    assert not _public_bytes(root, "sc")
    durable = DRIVER.Checkpoint.load(root)
    assert wrong_phase.name not in durable.completed
    assert durable.phase_commits[wrong_phase.name].state == (
        "INCOMPLETE_WITH_DEBT"
    )
