"""Fixture-first tests for the MethodCard runtime-authority foundation.

The fixture installs only the reviewed MethodCard catalog and its exact bound
prompt source in an otherwise empty implementation root.  The tests therefore
exercise content identities rather than this checkout's physical path or
unrelated dirty-worktree state.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil

import pytest

from audit_snapshot import (
    SNAPSHOT_SCHEMA,
    build_methodology_snapshot_component,
)
from method_card_catalog import (
    MethodCardCatalog,
    MethodCardCatalogError,
    canonical_catalog_bytes,
    load_method_card_catalog,
)
from method_card_runtime_authority import (
    AUTHORITY_SCHEMA,
    FRAGMENT_SCHEMA,
    INTEGRATION_DEBT,
    MethodCardRuntimeAuthorityError,
    canonical_runtime_authority_bytes,
    compile_method_card_runtime_input_binding,
    compile_method_card_runtime_authority,
    render_selected_method_fragment,
    validate_method_card_runtime_authority,
)
from program_facts_types import (
    canonical_file_bytes,
    canonical_json_bytes,
    strict_json_loads,
)
import worker_transaction as WTx


REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG_SOURCE = REPO_ROOT / "methodology" / "method-cards-v1.yaml"
KERNEL_RELATIVE = (
    Path("prompts")
    / "shared"
    / "v2"
    / "breadth-semantic-operator-kernel.md"
)
KERNEL_SOURCE = REPO_ROOT / KERNEL_RELATIVE


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _producer() -> dict[str, str]:
    return {
        "producer_id": "fixture.graph-selector",
        "producer_version": "1.0.0",
        "implementation_digest": _sha("fixture-graph-selector-v1"),
    }


def _graph_digest(
    *,
    graph_schema: str,
    coverage: dict,
    nodes: list[dict],
    relations: list[dict],
) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "graph_schema": graph_schema,
                "coverage": coverage,
                "nodes": nodes,
                "relations": relations,
            }
        )
    ).hexdigest()


def _denominator_source(snapshot: dict) -> dict:
    graph_schema = "fixture.program-graph.v1"
    coverage = {
        "coverage_kind": "EXACT",
        "unknown_remainder": False,
        "limitation_reason": None,
    }
    nodes = [
        {
            "target_id": "target:alpha",
            "node_kind": "function",
            "boundaries": [],
            "effects": ["authorization"],
            "entity_properties": [],
        },
        {
            "target_id": "target:beta",
            "node_kind": "function",
            "boundaries": [],
            "effects": ["asset_transfer"],
            "entity_properties": [],
        },
    ]
    relations = [
        {
            "relation_id": "relation:alpha",
            "selector": "calls",
            "source_target_id": "target:alpha",
            "destination_target_id": "target:beta",
        }
    ]
    unsigned = {
        "schema": "plamen.method-card-denominator-source.v1",
        "producer": _producer(),
        "audit_snapshot_digest": snapshot["snapshot_digest"],
        "source_scope_digest": snapshot["components"]["source_scope"]["digest"],
        "graph_schema": graph_schema,
        "graph_digest": _graph_digest(
            graph_schema=graph_schema,
            coverage=coverage,
            nodes=nodes,
            relations=relations,
        ),
        "coverage": coverage,
        "nodes": nodes,
        "relations": relations,
    }
    return {
        **unsigned,
        "source_digest": hashlib.sha256(
            canonical_json_bytes(unsigned)
        ).hexdigest(),
    }


def _install_reviewed_methodology(root: Path) -> MethodCardCatalog:
    catalog_path = root / "methodology" / "method-cards-v1.yaml"
    kernel_path = root / KERNEL_RELATIVE
    catalog_path.parent.mkdir(parents=True)
    kernel_path.parent.mkdir(parents=True)
    shutil.copyfile(CATALOG_SOURCE, catalog_path)
    shutil.copyfile(KERNEL_SOURCE, kernel_path)
    return load_method_card_catalog(catalog_path, repo_root=root)


def _audit_snapshot(root: Path, *, source_label: str = "source-a") -> dict:
    components = {
        "source_scope": {
            "digest": _sha(source_label),
            "path_set_digest": _sha(source_label + "-paths"),
            "file_count": 1,
            "byte_count": 37,
            "language": "evm",
            "pipeline": "sc",
            "git_head": "1" * 40,
            "coverage_limitations": [],
        },
        "audit_config": {
            "digest": _sha("config"),
            "field_count": 3,
        },
        "methodology": build_methodology_snapshot_component(root),
        "toolchain": {
            "digest": _sha("toolchain"),
            "path_set_digest": _sha("toolchain-paths"),
            "file_count": 0,
            "byte_count": 0,
        },
    }
    unsigned = {
        "schema": SNAPSHOT_SCHEMA,
        "components": components,
    }
    return {
        **unsigned,
        "snapshot_digest": hashlib.sha256(
            canonical_json_bytes(unsigned)
        ).hexdigest(),
    }


def _provider() -> dict:
    return {
        "backend": "codex",
        "model": "fixture-model",
        "transport": "exec",
        "resolved_executable": "C:/tools/provider.exe",
        "executable_sha256": _sha("provider"),
        "argv": ["C:/tools/provider.exe", "--fixture"],
        "environment_allowlist_digest": _sha("environment"),
        "timeout_seconds": 30,
        "stream_limits": {
            "stdout_bytes": 1024,
            "stderr_bytes": 1024,
            "staged_member_bytes": 4096,
        },
    }


def _assignment() -> dict:
    return {
        "assignment_id": "method-card-output",
        "members": [
            {
                "staged_relative_path": "application.json",
                "canonical_identity": "scratchpad:application.json",
                "parser_binding": {
                    "implementation_sha256": _sha("parser"),
                },
                "projection_mode": "CREATE_ABSENT",
                "canonical_prestate": {
                    "status": "ABSENT",
                    "sha256": "",
                    "size": 0,
                },
            }
        ],
    }


def _work_plan(
    snapshot: dict,
    methodology_digests: tuple[str, ...],
    *,
    prompt_digest: str,
    source_snapshot_digest: str | None = None,
) -> dict:
    denominator = WTx.compile_phase_work_roster_denominator(
        run_id="run-method-card",
        phase="breadth",
        generation=1,
        required_work_unit_ids=("breadth-method-card-001",),
    )
    return WTx.compile_worker_plan(
        run_id="run-method-card",
        phase="breadth",
        work_unit_id="breadth-method-card-001",
        generation=1,
        phase_roster_denominator_digest=denominator[
            "roster_denominator_digest"
        ],
        phase_io_contract_digest=_sha("phase-io-contract"),
        phase_io_launch_digest=_sha("phase-io-launch"),
        phase_io_input_set_digest=_sha("phase-io-inputs"),
        prompt_template_sha256=prompt_digest,
        methodology_digests=methodology_digests,
        source_snapshot_digest=(
            source_snapshot_digest or snapshot["snapshot_digest"]
        ),
        provider=_provider(),
        assignment=_assignment(),
        write_scope={"mode": "ATTEMPT_ONLY", "roots": ["output"]},
        child_denominator={"required": [], "optional": []},
        completion_policy={
            "accepted_signals": [
                "PROCESS_EXIT_ZERO",
                "EXACT_OUTPUT_DENOMINATOR",
            ],
            "canonical_projection": "PHASE_IO_ONLY",
        },
        retry_policy={
            "max_attempts": 1,
            "retry_requires_new_attempt_id": True,
        },
        terminal_debt_policy={
            "safe_authority": False,
            "human_review_on_exhaustion": True,
        },
    )


def _selections(
    catalog: MethodCardCatalog,
    count: int = 2,
) -> tuple[dict[str, str], ...]:
    return tuple(
        {
            "method_id": card.method_id,
            "method_version": card.method_version,
        }
        for card in catalog.cards[:count]
    )


def _steps(
    catalog: MethodCardCatalog,
    selections: tuple[dict[str, str], ...],
) -> tuple[dict[str, str], ...]:
    result: list[dict[str, str]] = []
    for selection in selections:
        card = catalog.card(selection["method_id"])
        result.extend(
            {
                "method_id": card.method_id,
                "method_version": card.method_version,
                "step_id": step.step_id,
            }
            for step in card.required_steps
        )
    return tuple(result)


@dataclass(frozen=True)
class Fixture:
    root: Path
    catalog: MethodCardCatalog
    snapshot: dict
    selections: tuple[dict[str, str], ...]
    steps: tuple[dict[str, str], ...]
    fragment: bytes
    plan: dict
    denominator_source: dict
    denominator_producer: dict[str, str]
    graph_binding: dict[str, str]
    targets: tuple[str, ...] = ("target:alpha", "target:beta")
    relations: tuple[str, ...] = ("relation:alpha",)


@pytest.fixture
def runtime_fixture(tmp_path: Path) -> Fixture:
    root = tmp_path / "implementation"
    catalog = _install_reviewed_methodology(root)
    snapshot = _audit_snapshot(root)
    selections = _selections(catalog)
    steps = _steps(catalog, selections)
    denominator_source = _denominator_source(snapshot)
    denominator_producer = _producer()
    graph_binding = {
        "graph_schema": denominator_source["graph_schema"],
        "graph_digest": denominator_source["graph_digest"],
    }
    fragment = render_selected_method_fragment(catalog, selections)
    fragment_digest = hashlib.sha256(fragment).hexdigest()
    runtime_input = compile_method_card_runtime_input_binding(
        implementation_root=root,
        audit_snapshot=snapshot,
        selected_methods=selections,
        denominator_source=denominator_source,
        expected_denominator_producer=denominator_producer,
        expected_graph_binding=graph_binding,
        target_denominator=("target:alpha", "target:beta"),
        relation_denominator=("relation:alpha",),
        step_denominator=steps,
        expected_catalog=catalog,
    )
    plan = _work_plan(
        snapshot,
        (
            catalog.digest,
            fragment_digest,
            runtime_input["runtime_input_binding_digest"],
            snapshot["components"]["methodology"]["digest"],
        ),
        prompt_digest=_sha("enclosing-prompt"),
    )
    return Fixture(
        root=root,
        catalog=catalog,
        snapshot=snapshot,
        selections=selections,
        steps=steps,
        fragment=fragment,
        plan=plan,
        denominator_source=denominator_source,
        denominator_producer=denominator_producer,
        graph_binding=graph_binding,
    )


def _compile(fixture: Fixture, **overrides: object) -> dict:
    values: dict[str, object] = {
        "implementation_root": fixture.root,
        "audit_snapshot": fixture.snapshot,
        "work_plan": fixture.plan,
        "selected_methods": fixture.selections,
        "denominator_source": fixture.denominator_source,
        "expected_denominator_producer": fixture.denominator_producer,
        "expected_graph_binding": fixture.graph_binding,
        "target_denominator": fixture.targets,
        "relation_denominator": fixture.relations,
        "step_denominator": fixture.steps,
        "expected_catalog": fixture.catalog,
    }
    values.update(overrides)
    return compile_method_card_runtime_authority(**values)  # type: ignore[arg-type]


def test_selected_fragment_is_closed_complete_and_deterministic(
    runtime_fixture: Fixture,
) -> None:
    fragment = runtime_fixture.fragment
    value = strict_json_loads(
        fragment,
        require_final_lf=True,
        require_canonical=True,
    )

    assert value["schema"] == FRAGMENT_SCHEMA
    assert value["catalog_digest"] == runtime_fixture.catalog.digest
    assert [row["method_id"] for row in value["methods"]] == [
        row["method_id"] for row in runtime_fixture.selections
    ]
    assert fragment == render_selected_method_fragment(
        runtime_fixture.catalog,
        runtime_fixture.selections,
    )
    assert value["methods"][0]["required_steps"]
    assert value["methods"][0]["prompt_fragment"]["path"] == (
        KERNEL_RELATIVE.as_posix()
    )


def test_prework_input_binding_is_acyclic_and_denominator_sensitive(
    runtime_fixture: Fixture,
) -> None:
    first = compile_method_card_runtime_input_binding(
        implementation_root=runtime_fixture.root,
        audit_snapshot=runtime_fixture.snapshot,
        selected_methods=runtime_fixture.selections,
        denominator_source=runtime_fixture.denominator_source,
        expected_denominator_producer=runtime_fixture.denominator_producer,
        expected_graph_binding=runtime_fixture.graph_binding,
        target_denominator=runtime_fixture.targets,
        relation_denominator=runtime_fixture.relations,
        step_denominator=runtime_fixture.steps,
        expected_catalog=runtime_fixture.catalog,
    )
    changed_source_unsigned = dict(runtime_fixture.denominator_source)
    changed_source_unsigned.pop("source_digest")
    changed_source_unsigned["nodes"] = [
        *changed_source_unsigned["nodes"],
        {
            "target_id": "target:gamma",
            "node_kind": "function",
            "boundaries": [],
            "effects": ["authorization"],
            "entity_properties": [],
        },
    ]
    changed_source_unsigned["graph_digest"] = _graph_digest(
        graph_schema=changed_source_unsigned["graph_schema"],
        coverage=changed_source_unsigned["coverage"],
        nodes=changed_source_unsigned["nodes"],
        relations=changed_source_unsigned["relations"],
    )
    changed_source = {
        **changed_source_unsigned,
        "source_digest": hashlib.sha256(
            canonical_json_bytes(changed_source_unsigned)
        ).hexdigest(),
    }
    changed = compile_method_card_runtime_input_binding(
        implementation_root=runtime_fixture.root,
        audit_snapshot=runtime_fixture.snapshot,
        selected_methods=runtime_fixture.selections,
        denominator_source=changed_source,
        expected_denominator_producer=runtime_fixture.denominator_producer,
        expected_graph_binding={
            "graph_schema": changed_source["graph_schema"],
            "graph_digest": changed_source["graph_digest"],
        },
        target_denominator=(
            *runtime_fixture.targets,
            "target:gamma",
        ),
        relation_denominator=runtime_fixture.relations,
        step_denominator=runtime_fixture.steps,
        expected_catalog=runtime_fixture.catalog,
    )

    assert first["schema"].endswith("runtime-input-binding.v1")
    assert "work_plan_digest" not in first
    assert not any(key.startswith("phase_io_") for key in first)
    assert first["runtime_input_binding_digest"] != changed[
        "runtime_input_binding_digest"
    ]
    assert first["runtime_input_binding_digest"] in (
        runtime_fixture.plan["methodology_digests"]
    )


def test_envelope_composes_all_required_bindings_without_semantic_authority(
    runtime_fixture: Fixture,
) -> None:
    authority = _compile(runtime_fixture)
    raw = canonical_runtime_authority_bytes(authority)

    assert authority["schema"] == AUTHORITY_SCHEMA
    assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")
    assert authority["catalog_binding"]["catalog_digest"] == (
        runtime_fixture.catalog.digest
    )
    assert authority["method_binding"]["rendered_fragment_sha256"] == (
        hashlib.sha256(runtime_fixture.fragment).hexdigest()
    )
    assert authority["method_binding"]["runtime_input_binding_digest"] in (
        runtime_fixture.plan["methodology_digests"]
    )
    assert authority["audit_snapshot_binding"] == {
        "audit_snapshot_digest": runtime_fixture.snapshot["snapshot_digest"],
        "methodology_snapshot_digest": runtime_fixture.snapshot["components"][
            "methodology"
        ]["digest"],
        "source_scope_digest": runtime_fixture.snapshot["components"][
            "source_scope"
        ]["digest"],
    }
    assert authority["work_plan_binding"]["work_plan_digest"] == (
        runtime_fixture.plan["work_plan_digest"]
    )
    assert authority["work_plan_binding"]["phase_io_contract_digest"] == (
        runtime_fixture.plan["phase_io_contract_digest"]
    )
    assert authority["denominators"]["coverage_kind"] == "EXACT"
    assert authority["denominators"]["unknown_remainder"] is False
    assert authority["denominators"]["steps"] == list(runtime_fixture.steps)
    assert authority["authority_limits"] == {
        "application_completion_authority": False,
        "execution_authority": False,
        "finding_authority": False,
        "negative_authority": False,
        "report_authority": False,
        "semantic_authority": False,
        "severity_authority": False,
    }
    assert authority["integration"]["status"] == "FOUNDATION_ONLY"
    assert authority["integration"]["driver_cutover"] is False
    assert authority["integration"]["phase_io_registered"] is False
    assert tuple(authority["integration"]["debt"]) == INTEGRATION_DEBT

    unsigned = dict(authority)
    claimed = unsigned.pop("authority_digest")
    assert claimed == hashlib.sha256(
        canonical_json_bytes(unsigned)
    ).hexdigest()


def test_validate_replays_every_external_binding(
    runtime_fixture: Fixture,
) -> None:
    authority = _compile(runtime_fixture)

    assert validate_method_card_runtime_authority(
        canonical_runtime_authority_bytes(authority),
        implementation_root=runtime_fixture.root,
        audit_snapshot=canonical_file_bytes(runtime_fixture.snapshot),
        work_plan=canonical_json_bytes(runtime_fixture.plan),
        denominator_source=runtime_fixture.denominator_source,
        expected_denominator_producer=runtime_fixture.denominator_producer,
        expected_graph_binding=runtime_fixture.graph_binding,
        expected_catalog=runtime_fixture.catalog,
    ) == authority


def test_content_identity_is_stable_across_distinct_physical_roots(
    tmp_path: Path,
) -> None:
    fixtures: list[Fixture] = []
    for name in ("windows-host-copy", "posix-host-copy"):
        root = tmp_path / name
        catalog = _install_reviewed_methodology(root)
        snapshot = _audit_snapshot(root)
        selections = _selections(catalog)
        steps = _steps(catalog, selections)
        denominator_source = _denominator_source(snapshot)
        denominator_producer = _producer()
        graph_binding = {
            "graph_schema": denominator_source["graph_schema"],
            "graph_digest": denominator_source["graph_digest"],
        }
        fragment = render_selected_method_fragment(catalog, selections)
        runtime_input = compile_method_card_runtime_input_binding(
            implementation_root=root,
            audit_snapshot=snapshot,
            selected_methods=selections,
            denominator_source=denominator_source,
            expected_denominator_producer=denominator_producer,
            expected_graph_binding=graph_binding,
            target_denominator=("target:alpha", "target:beta"),
            relation_denominator=("relation:alpha",),
            step_denominator=steps,
            expected_catalog=catalog,
        )
        plan = _work_plan(
            snapshot,
            (
                catalog.digest,
                hashlib.sha256(fragment).hexdigest(),
                runtime_input["runtime_input_binding_digest"],
                snapshot["components"]["methodology"]["digest"],
            ),
            prompt_digest=_sha("enclosing-prompt"),
        )
        fixtures.append(
            Fixture(
                root=root,
                catalog=catalog,
                snapshot=snapshot,
                selections=selections,
                steps=steps,
                fragment=fragment,
                plan=plan,
                denominator_source=denominator_source,
                denominator_producer=denominator_producer,
                graph_binding=graph_binding,
            )
        )

    first = _compile(fixtures[0])
    second = _compile(fixtures[1])
    assert canonical_runtime_authority_bytes(first) == (
        canonical_runtime_authority_bytes(second)
    )
    assert first["authority_digest"] == second["authority_digest"]


@pytest.mark.parametrize(
    ("selection_mutator", "match"),
    [
        (
            lambda rows: rows[:-1]
            + (
                {
                    "method_id": "unknown.operator.v1",
                    "method_version": "1.0.0",
                },
            ),
            "unknown MethodCard",
        ),
        (
            lambda rows: rows + (dict(rows[0]),),
            "duplicate",
        ),
        (
            lambda rows: (
                {
                    **rows[0],
                    "method_version": "1.0.1",
                },
                *rows[1:],
            ),
            "method_version",
        ),
        (
            lambda rows: tuple(reversed(rows)),
            "catalog order",
        ),
    ],
)
def test_unknown_duplicate_stale_or_reordered_methods_fail_closed(
    runtime_fixture: Fixture,
    selection_mutator,
    match: str,
) -> None:
    with pytest.raises(MethodCardRuntimeAuthorityError, match=match):
        _compile(
            runtime_fixture,
            selected_methods=selection_mutator(runtime_fixture.selections),
        )


def test_stale_catalog_object_is_replayed_against_canonical_location(
    runtime_fixture: Fixture,
) -> None:
    catalog_path = (
        runtime_fixture.root / "methodology" / "method-cards-v1.yaml"
    )
    catalog_path.write_bytes(catalog_path.read_bytes() + b" ")

    with pytest.raises(
        (MethodCardRuntimeAuthorityError, MethodCardCatalogError),
        match="canonical|stale|changed",
    ):
        _compile(runtime_fixture)


def test_stale_methodology_snapshot_is_rejected(
    runtime_fixture: Fixture,
) -> None:
    new_rule = runtime_fixture.root / "rules" / "new-method-rule.md"
    new_rule.parent.mkdir(parents=True)
    new_rule.write_text("new methodology bytes\n", encoding="utf-8")

    with pytest.raises(
        MethodCardRuntimeAuthorityError,
        match="methodology.*stale|methodology.*differs",
    ):
        _compile(runtime_fixture)


def test_stale_or_malformed_work_plan_is_rejected(
    runtime_fixture: Fixture,
) -> None:
    tampered = dict(runtime_fixture.plan)
    tampered["phase_io_contract_digest"] = _sha("other-contract")
    with pytest.raises(
        MethodCardRuntimeAuthorityError,
        match="WorkPlan|work plan",
    ):
        _compile(runtime_fixture, work_plan=tampered)


def test_work_plan_must_bind_current_audit_snapshot_source_authority(
    runtime_fixture: Fixture,
) -> None:
    stale_source_plan = _work_plan(
        runtime_fixture.snapshot,
        tuple(runtime_fixture.plan["methodology_digests"]),
        prompt_digest=_sha("enclosing-prompt"),
        source_snapshot_digest=_sha("stale-source-snapshot"),
    )
    with pytest.raises(
        MethodCardRuntimeAuthorityError,
        match="source_snapshot_digest",
    ):
        _compile(runtime_fixture, work_plan=stale_source_plan)


def test_work_plan_must_bind_all_method_runtime_dependencies(
    runtime_fixture: Fixture,
) -> None:
    incomplete = _work_plan(
        runtime_fixture.snapshot,
        (
            runtime_fixture.catalog.digest,
            runtime_fixture.snapshot["components"]["methodology"]["digest"],
        ),
        prompt_digest=_sha("enclosing-prompt"),
    )
    with pytest.raises(
        MethodCardRuntimeAuthorityError,
        match="methodology_digests.*selected fragment",
    ):
        _compile(runtime_fixture, work_plan=incomplete)


def test_private_denominator_change_is_rejected_before_work_plan_reuse(
    runtime_fixture: Fixture,
) -> None:
    with pytest.raises(
        MethodCardRuntimeAuthorityError,
        match="source-derived denominator authority",
    ):
        _compile(
            runtime_fixture,
            target_denominator=(
                *runtime_fixture.targets,
                "target:gamma",
            ),
        )


def test_validator_rejects_a_different_but_internally_valid_work_plan(
    runtime_fixture: Fixture,
) -> None:
    authority = _compile(runtime_fixture)
    successor = _work_plan(
        runtime_fixture.snapshot,
        tuple(runtime_fixture.plan["methodology_digests"]),
        prompt_digest=_sha("changed-enclosing-prompt"),
    )

    with pytest.raises(
        MethodCardRuntimeAuthorityError,
        match="external bindings|work plan",
    ):
        validate_method_card_runtime_authority(
            authority,
            implementation_root=runtime_fixture.root,
            audit_snapshot=runtime_fixture.snapshot,
            work_plan=successor,
            denominator_source=runtime_fixture.denominator_source,
            expected_denominator_producer=(
                runtime_fixture.denominator_producer
            ),
            expected_graph_binding=runtime_fixture.graph_binding,
            expected_catalog=runtime_fixture.catalog,
        )


@pytest.mark.parametrize(
    "bad_targets",
    [
        ("../target",),
        ("C:target",),
        ("/absolute",),
        (r"target\child",),
        ("targe\u0301t",),
        ("Target:alpha", "target:alpha"),
        ("target:beta", "target:alpha"),
        ("target:alpha", "target:alpha"),
    ],
)
def test_target_denominator_rejects_path_unicode_casefold_order_and_duplicates(
    runtime_fixture: Fixture,
    bad_targets: tuple[str, ...],
) -> None:
    with pytest.raises(
        MethodCardRuntimeAuthorityError,
        match="target denominator",
    ):
        _compile(runtime_fixture, target_denominator=bad_targets)


@pytest.mark.parametrize(
    "bad_relations",
    [
        ("relation:beta", "relation:alpha"),
        ("relation:alpha", "relation:alpha"),
        ("../relation",),
        ("relatio\u0301n",),
    ],
)
def test_relation_denominator_has_the_same_closed_identity_rules(
    runtime_fixture: Fixture,
    bad_relations: tuple[str, ...],
) -> None:
    with pytest.raises(
        MethodCardRuntimeAuthorityError,
        match="relation denominator",
    ):
        _compile(runtime_fixture, relation_denominator=bad_relations)


def test_step_denominator_must_exactly_equal_selected_catalog_steps(
    runtime_fixture: Fixture,
) -> None:
    missing = runtime_fixture.steps[:-1]
    duplicate = (*runtime_fixture.steps, dict(runtime_fixture.steps[-1]))
    foreign = (
        *runtime_fixture.steps[:-1],
        {
            **runtime_fixture.steps[-1],
            "step_id": "invented_step",
        },
    )

    for value in (missing, duplicate, foreign):
        with pytest.raises(
            MethodCardRuntimeAuthorityError,
            match="step denominator",
        ):
            _compile(runtime_fixture, step_denominator=value)


@pytest.mark.parametrize("encoding_fault", ("duplicate", "pretty", "bom"))
def test_authority_json_ambiguity_is_rejected(
    runtime_fixture: Fixture,
    encoding_fault: str,
) -> None:
    authority = _compile(runtime_fixture)
    raw = canonical_runtime_authority_bytes(authority)
    if encoding_fault == "duplicate":
        marker = f'"schema":"{AUTHORITY_SCHEMA}"'
        text = raw.decode("utf-8")
        bad = text.replace(marker, f"{marker},{marker}", 1).encode("utf-8")
    elif encoding_fault == "pretty":
        bad = (
            json.dumps(
                json.loads(raw),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
    else:
        bad = b"\xef\xbb\xbf" + raw

    with pytest.raises(
        MethodCardRuntimeAuthorityError,
        match="canonical|duplicate|BOM",
    ):
        validate_method_card_runtime_authority(
            bad,
            implementation_root=runtime_fixture.root,
            audit_snapshot=runtime_fixture.snapshot,
            work_plan=runtime_fixture.plan,
            denominator_source=runtime_fixture.denominator_source,
            expected_denominator_producer=(
                runtime_fixture.denominator_producer
            ),
            expected_graph_binding=runtime_fixture.graph_binding,
            expected_catalog=runtime_fixture.catalog,
        )


def test_recomputed_tamper_cannot_confer_negative_or_semantic_authority(
    runtime_fixture: Fixture,
) -> None:
    authority = _compile(runtime_fixture)
    tampered = json.loads(canonical_runtime_authority_bytes(authority))
    tampered["authority_limits"]["negative_authority"] = True
    tampered["authority_limits"]["semantic_authority"] = True
    unsigned = dict(tampered)
    unsigned.pop("authority_digest")
    tampered["authority_digest"] = hashlib.sha256(
        canonical_json_bytes(unsigned)
    ).hexdigest()

    with pytest.raises(
        MethodCardRuntimeAuthorityError,
        match="authority limits|external bindings",
    ):
        validate_method_card_runtime_authority(
            canonical_file_bytes(tampered),
            implementation_root=runtime_fixture.root,
            audit_snapshot=runtime_fixture.snapshot,
            work_plan=runtime_fixture.plan,
            denominator_source=runtime_fixture.denominator_source,
            expected_denominator_producer=(
                runtime_fixture.denominator_producer
            ),
            expected_graph_binding=runtime_fixture.graph_binding,
            expected_catalog=runtime_fixture.catalog,
        )


def test_catalog_writer_remains_canonical_in_fixture() -> None:
    raw = json.loads(CATALOG_SOURCE.read_bytes())
    assert CATALOG_SOURCE.read_bytes() == canonical_catalog_bytes(raw)
