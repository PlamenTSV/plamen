"""Executable specification for the real chain post-model driver boundary.

This fixture intentionally crosses the three authority mechanisms involved in
the boundary instead of testing them as independent helpers:

1. the accepted ``chain/model`` PhaseIO receipt owns all model outputs;
2. the hypotheses/mapping pair is replaced by the journaled paired auto-map
   successor; and
3. a chain-only ``EN-N`` candidate is folded into the content-addressed
   pre-verification inventory projection without mutating the canonical root.

The driver must preserve that acyclic order.  Failure paths must retain
candidates and write durable, typed debt; they must never silently certify a
partial pair or make the producer that discovered a candidate stale.

No model, audit, network request, install, or subprocess is launched.
"""
from __future__ import annotations

import ast
import hashlib
import inspect
import json
from pathlib import Path
from typing import Any, Callable, Iterable

import pytest

from artifact_ledger import (
    read_artifact_ledger,
    semantic_import_authority,
    semantic_mutation_events,
)
from chain_pair_auto_map_transaction import (
    PENDING,
    run_chain_pair_auto_map_transaction,
)
from preverify_chain_pair_projection import (
    prepare_preverify_chain_pair_projection,
)
from preverify_frozen_projection import prepare_preverify_frozen_projection
from preverify_projection_authority import (
    PreverifyProjectionAuthorityError,
    resolve_current_preverify_projection,
)
import plamen_driver as DRIVER
import plamen_mechanical as MECHANICAL
import plamen_parsers as PARSERS
import plamen_validators as VALIDATORS
import chain_grouping_assurance as GROUPING_ASSURANCE
import test_chain_driver_boundary_authority_red as CHAIN_FIXTURE


PAIR = ("hypotheses.md", "finding_mapping.md")


def _call_name(node: ast.Call) -> str:
    function = node.func
    if isinstance(function, ast.Name):
        return function.id
    if isinstance(function, ast.Attribute):
        return function.attr
    return ""


def _calls(node: ast.AST, name: str) -> list[ast.Call]:
    return [
        child
        for child in ast.walk(node)
        if isinstance(child, ast.Call) and _call_name(child) == name
    ]


def _phase_chain_test(node: ast.If) -> bool:
    return (
        isinstance(node.test, ast.Compare)
        and isinstance(node.test.left, ast.Attribute)
        and isinstance(node.test.left.value, ast.Name)
        and node.test.left.value.id == "phase"
        and node.test.left.attr == "name"
        and len(node.test.ops) == 1
        and isinstance(node.test.ops[0], ast.Eq)
        and len(node.test.comparators) == 1
        and isinstance(node.test.comparators[0], ast.Constant)
        and node.test.comparators[0].value == "chain"
    )


def _statement_lists(node: ast.AST) -> Iterable[list[ast.stmt]]:
    for _field, value in ast.iter_fields(node):
        if isinstance(value, list) and all(
            isinstance(item, ast.stmt) for item in value
        ):
            yield value
            for item in value:
                yield from _statement_lists(item)
        elif isinstance(value, ast.AST):
            yield from _statement_lists(value)


def _model_outputs(*, include_enabler: bool) -> dict[str, str]:
    hypotheses = (
        "# Hypotheses\n\n"
        "| Hypothesis ID | Severity | Title | Constituent Findings | Location |\n"
        "|---|---|---|---|---|\n"
        "| H-1 | Medium | Existing candidate | INV-1 | src/Fixture.sol:1 |\n"
    )
    mapping = (
        "# Finding Mapping\n\n"
        "| Finding ID | Hypothesis ID | Mapping Status |\n"
        "|---|---|---|\n"
        "| INV-1 | H-1 | GROUPED |\n"
    )
    enablers = (
        "# Enabler Results\n\n"
        "**Status**: MODEL_ANALYZED\n\n"
        "No proof authority; candidates require independent verification.\n"
    )
    if include_enabler:
        hypotheses += (
            "| H-2 | High | Chain-only candidate | EN-1 | "
            "src/Generic.sol:20 |\n"
        )
        mapping += "| EN-1 | H-2 | CHAIN_GENERATED |\n"
        enablers += (
            "\n### Finding [EN-1]: Chain-only candidate\n"
            "**Severity**: High\n"
            "**Location**: src/Generic.sol:20\n"
            "**Description**: A generic chain-discovered precondition path.\n"
            "**Impact**: Requires independent verification before disposition.\n"
        )
    return {
        "hypotheses.md": hypotheses,
        "finding_mapping.md": mapping,
        "enabler_results.md": enablers,
    }


def _accepted_chain_model(
    tmp_path: Path,
    *,
    include_enabler: bool,
    base_inventory_extra: str = "",
) -> tuple[Path, Path, dict[str, Any], DRIVER.Checkpoint]:
    project, scratchpad = CHAIN_FIXTURE._root(tmp_path)
    checkpoint = DRIVER.Checkpoint(run_id=CHAIN_FIXTURE.RUN_ID)
    checkpoint.save(scratchpad)
    CHAIN_FIXTURE._write(
        scratchpad / "findings_inventory.md",
        "# Findings Inventory\n\n"
        "### Finding [INV-1]: Existing candidate\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: Medium\n"
        "**Location**: src/Fixture.sol:1\n"
        "**Description**: Existing mechanism.\n"
        "**Impact**: Existing impact.\n"
        + base_inventory_extra,
    )
    CHAIN_FIXTURE._write(
        scratchpad / "attack_surface.md",
        "# Attack Surface\n\nBounded fixture surface.\n",
    )
    CHAIN_FIXTURE._write(
        scratchpad / "depth_alpha_findings.md",
        "# Depth\n\n"
        "### Finding [DA-2]: Unmapped depth candidate\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: Medium\n"
        "**Location**: src/Depth.sol:2\n"
        "**Description**: Must remain independently addressable.\n"
        "**Impact**: Requires verification.\n\n"
        "## Chain Summary\n\n- DA-2 affects a security-relevant transition.\n",
    )
    CHAIN_FIXTURE._claim_depth_sources(
        project,
        scratchpad,
        ("findings_inventory.md", "depth_alpha_findings.md"),
    )
    config = CHAIN_FIXTURE._config(project)
    assert DRIVER._run_chain_summary_compaction_transaction(
        scratchpad, config
    ) == []
    written, scaffold_issues = DRIVER._run_chain_scaffold_transaction(
        scratchpad, config
    )
    assert scaffold_issues == []
    assert set(written) == {
        "hypotheses.md",
        "finding_mapping.md",
        "enabler_results.md",
    }
    CHAIN_FIXTURE._commit_state_resolution(project, scratchpad, config)

    phase = CHAIN_FIXTURE._chain_phase()
    assert DRIVER._bind_typed_model_phase_inputs(
        phase, scratchpad, config
    ) == []
    for relative, body in _model_outputs(
        include_enabler=include_enabler
    ).items():
        CHAIN_FIXTURE._write(scratchpad / relative, body)
    assert DRIVER._record_typed_model_phase_artifacts(
        phase, scratchpad, config
    ) == []
    for relative in (*PAIR, "enabler_results.md"):
        authority = semantic_import_authority(
            scratchpad,
            project,
            "scratchpad:" + relative,
            run_id=CHAIN_FIXTURE.RUN_ID,
        )
        assert authority["authority_kind"] == "EXACT_PHASE_IO_PRODUCER"
        assert authority["producer_work_unit_key"].endswith("/chain/model")
    return project, scratchpad, config, checkpoint


def _additive_pair_deriver(
    expected_inventory_marker: bytes | None = None,
) -> Callable[[Path], tuple[list[str], dict[str, bytes]]]:
    def derive(root: Path) -> tuple[list[str], dict[str, bytes]]:
        if expected_inventory_marker is not None:
            assert expected_inventory_marker in (
                root / "findings_inventory.md"
            ).read_bytes()
        before = {
            relative: (root / relative).read_bytes() for relative in PAIR
        }
        return ["DA-2"], {
            "hypotheses.md": (
                before["hypotheses.md"]
                + b"| H-3 | Medium | Recovered depth candidate | "
                b"DA-2 | src/Depth.sol:2 |\n"
            ),
            "finding_mapping.md": (
                before["finding_mapping.md"]
                + b"| DA-2 | H-3 | AUTO_MAPPED_DEPTH |\n"
            ),
        }

    return derive


def test_real_main_orders_model_receipt_then_paired_auto_map_without_root_union() -> None:
    """Pin the acyclic main-loop order and forbid a canonical inventory append."""

    tree = ast.parse(inspect.getsource(DRIVER.main))
    main_function = tree.body[0]
    assert isinstance(main_function, (ast.FunctionDef, ast.AsyncFunctionDef))
    chain_blocks = [
        node
        for node in ast.walk(main_function)
        if isinstance(node, ast.If)
        and _phase_chain_test(node)
        and _calls(
            node, "_auto_map_unmapped_depth_findings_with_semantic_authority"
        )
    ]
    assert len(chain_blocks) == 1
    chain_block = chain_blocks[0]
    assert not _calls(
        chain_block, "_promote_chain_candidates_with_semantic_invalidation"
    ), (
        "chain-only candidates must be a typed preverify delta; appending them "
        "to canonical findings_inventory.md invalidates their chain/model "
        "producer before the paired successor can consume it"
    )
    enclosing = next(
        statements
        for statements in _statement_lists(main_function)
        if chain_block in statements
    )
    chain_index = enclosing.index(chain_block)
    model_receipt_statements = [
        statement
        for statement in enclosing[:chain_index]
        if _calls(statement, "_record_typed_model_phase_artifacts")
    ]
    assert model_receipt_statements, (
        "the chain post-model boundary is not preceded by the accepted exact "
        "MODEL artifact receipt in the same main-loop statement list"
    )
    receipt_line = max(statement.lineno for statement in model_receipt_statements)
    auto_map_line = _calls(
        chain_block, "_auto_map_unmapped_depth_findings_with_semantic_authority"
    )[0].lineno
    assert receipt_line < auto_map_line

    validator_tree = ast.parse(
        inspect.getsource(DRIVER._run_phase_validators)
    )
    assert not _calls(
        validator_tree,
        "_auto_map_unmapped_depth_findings_with_semantic_authority",
    )
    assert not _calls(validator_tree, "run_chain_pair_auto_map_transaction")
    validator_source = inspect.getsource(DRIVER._run_phase_validators)
    assert 'config["_chain_post_model_auto_map_issues"]' in validator_source

    main_source = inspect.getsource(DRIVER.main)
    assert '"CHAIN_FINAL_PAIR_MUTATION_DEBT"' in main_source


def test_post_model_pair_then_frozen_delta_preserves_model_and_canonical_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The full intended success path is exact, additive, and acyclic."""

    project, scratchpad, config, checkpoint = _accepted_chain_model(
        tmp_path, include_enabler=True
    )
    before_inventory = (scratchpad / "findings_inventory.md").read_bytes()

    monkeypatch.setattr(
        DRIVER,
        "_derive_auto_map_unmapped_depth_findings",
        _additive_pair_deriver(),
    )
    mapped, auto_map_issues = (
        DRIVER._auto_map_unmapped_depth_findings_with_semantic_authority(
            scratchpad,
            config,
            owner_phase="chain",
            gate_issues=("unmapped DA-2",),
        )
    )
    assert mapped == ["DA-2"], (
        "inventory reconciliation invalidated or otherwise disqualified the "
        "accepted chain/model pair before its registered paired successor; "
        f"issues={auto_map_issues!r}"
    )
    assert auto_map_issues == []

    pair_projection = prepare_preverify_chain_pair_projection(
        scratchpad=scratchpad,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase_name="sc_verify_queue",
        run_id=CHAIN_FIXTURE.RUN_ID,
    )
    assert pair_projection["state"] == "OUTPUT_COMMITTED"
    assert pair_projection["safe_to_consume"] is True
    frozen_projection = prepare_preverify_frozen_projection(
        scratchpad=scratchpad,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase_name="sc_verify_queue",
        run_id=CHAIN_FIXTURE.RUN_ID,
        chain_pair_projection=pair_projection,
    )
    frozen_inventory = (
        scratchpad
        / frozen_projection["logical_to_physical"]["findings_inventory.md"]
    ).read_bytes()
    frozen_records = (
        scratchpad
        / frozen_projection["logical_to_physical"]["finding_records.json"]
    ).read_text(encoding="utf-8", errors="strict")

    bindings = read_artifact_ledger(scratchpad)["artifact_bindings"]
    owners = {
        bindings["scratchpad:" + relative]["owner_key"] for relative in PAIR
    }
    assert len(owners) == 1
    assert next(iter(owners)).startswith(
        "sc/thorough/evm/claude/chain/final_pair_auto_map_apply."
    )
    assert (scratchpad / "findings_inventory.md").read_bytes() == before_inventory
    assert b"Finding [EN-1]" not in before_inventory
    assert b"Finding [EN-1]" in frozen_inventory
    assert '"inventory_id":"EN-1"' in frozen_records
    assert semantic_mutation_events(scratchpad) == []
    assert b"DA-2" in (scratchpad / "hypotheses.md").read_bytes()
    assert b"DA-2" in (scratchpad / "finding_mapping.md").read_bytes()

    successor_issues = DRIVER._finalize_preverify_inventory_successors(
        scratchpad,
        config,
        phase_name="sc_verify_queue",
        frozen_projection=frozen_projection,
    )
    assert successor_issues == []
    delivery_successor = json.loads(
        (scratchpad / "finding_delivery_successor.json").read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    frozen_sha = hashlib.sha256(frozen_inventory).hexdigest()
    canonical_sha = hashlib.sha256(before_inventory).hexdigest()
    assert frozen_sha != canonical_sha
    assert delivery_successor["inventory_sha256"] == frozen_sha
    assert (
        delivery_successor["delivery_payload"]["inventory_sha256"]
        == "sha256:" + frozen_sha
    )
    assert (
        delivery_successor["delivery_payload"]["inventory_sha256"]
        != "sha256:" + canonical_sha
    )
    assert (
        DRIVER._validate_registered_finding_delivery_receipt(
            scratchpad
        )
        == []
    )
    execute, routing_issues = (
        DRIVER._arm_typed_verify_queue_routing_artifacts(
            "sc_verify_queue",
            scratchpad,
            config,
        )
    )
    assert execute is True
    assert routing_issues == []
    authority = resolve_current_preverify_projection(
        scratchpad,
        expected_run_id=CHAIN_FIXTURE.RUN_ID,
        expected_consumer_work_unit_key=(
            "sc/thorough/evm/claude/sc_verify_queue/routing"
        ),
    )
    assert authority["inventory_source_artifact"] == frozen_projection[
        "logical_to_physical"
    ]["findings_inventory.md"]
    assert "Finding [EN-1]" in authority["inventory_text"]
    assert "Finding [EN-1]" not in before_inventory.decode("utf-8")
    records_by_id, _records_by_source = (
        MECHANICAL._load_finding_record_maps(scratchpad)
    )
    assert "EN-1" in records_by_id
    grouping_records, grouping_inventory_sha = (
        GROUPING_ASSURANCE._inventory_records(scratchpad)
    )
    assert "EN-1" in grouping_records
    assert grouping_inventory_sha == frozen_sha

    queue_rows = [
        {
            "queue #": "1",
            "finding id": "INV-1",
            "severity": "Medium",
            "title": "Existing candidate",
            "bug class": "fixture",
            "preferred tag": "CODE-TRACE",
            "location": "src/Fixture.sol:1",
            "primary artifact": "findings_inventory.md",
            "poc class": "structural",
        },
        {
            "queue #": "2",
            "finding id": "EN-1",
            "severity": "High",
            "title": "Chain-only candidate",
            "bug class": "fixture",
            "preferred tag": "CODE-TRACE",
            "location": "src/Generic.sol:20",
            "primary artifact": "enabler_results.md",
            "poc class": "structural",
        },
    ]
    PARSERS._write_queue_subset_manifest(
        scratchpad / "verification_queue.md",
        queue_rows,
    )
    assert VALIDATORS._validate_verification_queue_inventory_parity(
        scratchpad
    ) == []
    # Root Markdown is no longer a resume denominator after successor commit.
    (scratchpad / "findings_inventory.md").write_bytes(
        before_inventory.replace(b"CONFIRMED", b"REFUTED")
    )
    assert VALIDATORS._validate_verification_queue_inventory_parity(
        scratchpad
    ) == []
    PARSERS._write_queue_subset_manifest(
        scratchpad / "verification_queue.md",
        queue_rows[:1],
    )
    dropout = VALIDATORS._validate_verification_queue_inventory_parity(
        scratchpad
    )
    assert any("EN-1" in issue and "dropout" in issue for issue in dropout)
    (scratchpad / "verification_queue.md").unlink()
    (scratchpad / "verification_queue.json").unlink(missing_ok=True)
    empty, reason = VALIDATORS.is_verification_queue_empty(
        scratchpad, "sc"
    )
    assert empty is False
    assert "successor" in reason

    tamper_targets = [
        authority["inventory_source_artifact"],
        authority["records_source_artifact"],
        authority["frozen_receipt_artifact"],
    ]
    if authority["evidence_source_artifact"]:
        tamper_targets.append(authority["evidence_source_artifact"])
    for relative in tamper_targets:
        target = scratchpad / relative
        original = target.read_bytes()
        target.write_bytes(original + b"\nTAMPER")
        with pytest.raises(PreverifyProjectionAuthorityError):
            resolve_current_preverify_projection(
                scratchpad,
                expected_run_id=CHAIN_FIXTURE.RUN_ID,
                expected_consumer_work_unit_key=(
                    "sc/thorough/evm/claude/sc_verify_queue/routing"
                ),
            )
        target.write_bytes(original)
        assert resolve_current_preverify_projection(
            scratchpad,
            expected_run_id=CHAIN_FIXTURE.RUN_ID,
            expected_consumer_work_unit_key=(
                "sc/thorough/evm/claude/sc_verify_queue/routing"
            ),
        )[
            "inventory_source_artifact"
        ] == authority["inventory_source_artifact"]


def test_verify_independently_enabler_is_not_absorbed_by_hypothesis_dedup(
    tmp_path: Path,
) -> None:
    """Composition lineage may guide context but cannot erase a claim."""

    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    CHAIN_FIXTURE._write(
        scratchpad / "findings_inventory.md",
        "# Findings Inventory\n\n"
        "### Finding [EN-1]: Independently assessable chain candidate\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
        "**Severity**: Medium\n"
        "**Location**: src/Generic.sol:20\n"
        "**Source Artifact**: enabler_results.md\n"
        "**Chain Hypothesis**: H-2\n"
        "**Description**: A distinct precondition claim.\n"
        "**Impact**: A distinct harm claim.\n"
        "**Proof Authority**: NONE\n"
        "**Required Disposition**: VERIFY_INDEPENDENTLY\n",
    )
    CHAIN_FIXTURE._write(
        scratchpad / "hypotheses.md",
        "# Hypotheses\n\n"
        "| Hypothesis ID | Severity | Title | Constituent Findings | Location |\n"
        "|---|---|---|---|---|\n"
        "| H-2 | Medium | Composition hypothesis | EN-1 | src/Generic.sol:20 |\n",
    )
    CHAIN_FIXTURE._write(
        scratchpad / "finding_mapping.md",
        "# Finding Mapping\n\n"
        "| Finding ID | Hypothesis ID | Mapping Status |\n"
        "|---|---|---|\n"
        "| EN-1 | H-2 | CHAIN_GENERATED |\n",
    )
    rows, excluded = PARSERS._queue_rows_from_inventory_with_exclusions(
        scratchpad,
        pipeline="sc",
    )
    assert excluded == []
    PARSERS._write_queue_subset_manifest(
        scratchpad / "verification_queue.md",
        rows,
    )

    PARSERS._dedup_queue_by_hypothesis(scratchpad)
    final = PARSERS.parse_verification_queue_rows(scratchpad)
    by_id = {
        str(row.get("finding id") or "").upper(): row
        for row in final
    }

    assert set(by_id) == {"EN-1"}
    assert (
        by_id["EN-1"]["title"]
        == "Independently assessable chain candidate"
    )
    assert by_id["EN-1"]["primary artifact"] == "enabler_results.md"


def test_two_independent_enablers_sharing_hypothesis_both_survive_dedup(
    tmp_path: Path,
) -> None:
    """A shared composition relation is not evidence of claim equivalence."""

    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    blocks = []
    for identity, line in (("EN-1", 20), ("EN-2", 30)):
        blocks.append(
            f"### Finding [{identity}]: Distinct {identity} claim\n"
            "**Verdict**: NEEDS_VERIFICATION\n"
            "**Severity**: Medium\n"
            f"**Location**: src/Generic.sol:{line}\n"
            "**Source Artifact**: enabler_results.md\n"
            "**Chain Hypothesis**: H-2\n"
            f"**Description**: Distinct mechanism for {identity}.\n"
            f"**Impact**: Distinct harm for {identity}.\n"
            "**Proof Authority**: NONE\n"
            "**Required Disposition**: VERIFY_INDEPENDENTLY\n"
        )
    CHAIN_FIXTURE._write(
        scratchpad / "findings_inventory.md",
        "# Findings Inventory\n\n" + "\n".join(blocks),
    )
    CHAIN_FIXTURE._write(
        scratchpad / "hypotheses.md",
        "# Hypotheses\n\n"
        "| Hypothesis ID | Severity | Title | Constituent Findings | Location |\n"
        "|---|---|---|---|---|\n"
        "| H-2 | Medium | Shared composition | EN-1, EN-2 | src/Generic.sol:20 |\n",
    )
    CHAIN_FIXTURE._write(
        scratchpad / "finding_mapping.md",
        "# Finding Mapping\n\n"
        "| Finding ID | Hypothesis ID | Mapping Status |\n"
        "|---|---|---|\n"
        "| EN-1 | H-2 | CHAIN_GENERATED |\n"
        "| EN-2 | H-2 | CHAIN_GENERATED |\n",
    )
    rows, excluded = PARSERS._queue_rows_from_inventory_with_exclusions(
        scratchpad,
        pipeline="sc",
    )
    assert excluded == []
    PARSERS._write_queue_subset_manifest(
        scratchpad / "verification_queue.md",
        rows,
    )

    PARSERS._dedup_queue_by_hypothesis(scratchpad)
    final = PARSERS.parse_verification_queue_rows(scratchpad)
    by_id = {
        str(row.get("finding id") or "").upper(): row
        for row in final
    }

    assert set(by_id) == {"EN-1", "EN-2"}
    assert by_id["EN-1"]["title"] == "Distinct EN-1 claim"
    assert by_id["EN-2"]["title"] == "Distinct EN-2 claim"


def test_paired_apply_interruption_is_visible_and_recoverable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratchpad, config, _checkpoint = _accepted_chain_model(
        tmp_path, include_enabler=False
    )
    before = {
        relative: (scratchpad / relative).read_bytes() for relative in PAIR
    }
    derive = _additive_pair_deriver()

    def interrupt_after_first_member(stage: str) -> None:
        if stage == "after_chain_pair_apply_hypotheses.md":
            raise RuntimeError("fixture interruption after first pair member")

    def crashing_transaction(**kwargs: Any) -> dict[str, Any]:
        return run_chain_pair_auto_map_transaction(
            **{key: value for key, value in kwargs.items() if key != "derive"},
            derive=derive,
            failpoint=interrupt_after_first_member,
        )

    monkeypatch.setattr(
        DRIVER,
        "run_chain_pair_auto_map_transaction",
        crashing_transaction,
    )
    mapped, issues = (
        DRIVER._auto_map_unmapped_depth_findings_with_semantic_authority(
            scratchpad,
            config,
            owner_phase="chain",
            gate_issues=("unmapped DA-2",),
        )
    )
    assert mapped == []
    assert issues
    assert any(
        "fixture interruption after first pair member" in issue
        for issue in issues
    )
    for issue in issues:
        DRIVER._append_phase_io_debt(
            scratchpad,
            "chain",
            "CHAIN_FINAL_PAIR_MUTATION_DEBT",
            issue,
        )
    assert (scratchpad / PENDING).is_file()
    assert (scratchpad / "hypotheses.md").read_bytes() != before["hypotheses.md"]
    assert (scratchpad / "finding_mapping.md").read_bytes() == before[
        "finding_mapping.md"
    ]
    debt = (scratchpad / "chain.degraded").read_text(
        encoding="utf-8", errors="strict"
    )
    assert "[CHAIN_FINAL_PAIR_MUTATION_DEBT]" in debt
    assert "fixture interruption after first pair member" in debt

    replay = run_chain_pair_auto_map_transaction(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=CHAIN_FIXTURE.RUN_ID,
        derive=derive,
    )
    assert replay["state"] == "OUTPUT_COMMITTED"
    assert replay["safe_to_project"] is True
    assert replay["recovered"] is True
    assert replay["mapped_ids"] == ["DA-2"]
    assert not (scratchpad / PENDING).exists()
    assert b"DA-2" in (scratchpad / "hypotheses.md").read_bytes()
    assert b"DA-2" in (scratchpad / "finding_mapping.md").read_bytes()
