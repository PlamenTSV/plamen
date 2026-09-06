"""Adversarial fixtures for source-derived MethodCard denominators.

These tests define the denominator-authority repair before implementation.  A
caller's target/relation lists are claims only.  The graph/selector source
receipt is replayed independently and owns the frozen lower bound or exact set.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil

import pytest

from audit_snapshot import SNAPSHOT_SCHEMA, build_methodology_snapshot_component
from method_card_catalog import MethodCardCatalog, load_method_card_catalog
from method_card_runtime_authority import (
    DENOMINATOR_AUTHORITY_SCHEMA,
    DENOMINATOR_SOURCE_SCHEMA,
    MethodCardRuntimeAuthorityError,
    canonical_denominator_authority_bytes,
    canonical_runtime_authority_bytes,
    compile_method_card_denominator_authority,
    compile_method_card_runtime_authority,
    compile_method_card_runtime_input_binding,
    render_selected_method_fragment,
    validate_method_card_denominator_authority,
    validate_method_card_runtime_authority,
)
from program_facts_types import canonical_file_bytes, canonical_json_bytes
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


def _install(root: Path) -> MethodCardCatalog:
    catalog_path = root / "methodology" / "method-cards-v1.yaml"
    kernel_path = root / KERNEL_RELATIVE
    catalog_path.parent.mkdir(parents=True)
    kernel_path.parent.mkdir(parents=True)
    shutil.copyfile(CATALOG_SOURCE, catalog_path)
    shutil.copyfile(KERNEL_SOURCE, kernel_path)
    return load_method_card_catalog(catalog_path, repo_root=root)


def _snapshot(root: Path) -> dict:
    components = {
        "source_scope": {
            "digest": _sha("source-scope"),
            "path_set_digest": _sha("source-paths"),
            "file_count": 2,
            "byte_count": 91,
            "language": "evm",
            "pipeline": "sc",
            "git_head": "1" * 40,
            "coverage_limitations": [],
        },
        "audit_config": {"digest": _sha("config"), "field_count": 3},
        "methodology": build_methodology_snapshot_component(root),
        "toolchain": {
            "digest": _sha("toolchain"),
            "path_set_digest": _sha("toolchain-paths"),
            "file_count": 0,
            "byte_count": 0,
        },
    }
    unsigned = {"schema": SNAPSHOT_SCHEMA, "components": components}
    return {
        **unsigned,
        "snapshot_digest": hashlib.sha256(
            canonical_json_bytes(unsigned)
        ).hexdigest(),
    }


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


def _source(
    snapshot: dict,
    *,
    coverage_kind: str = "EXACT",
    reason: str | None = None,
    nodes: list[dict] | None = None,
    relations: list[dict] | None = None,
    producer: dict[str, str] | None = None,
    graph_digest: str | None = None,
) -> dict:
    if nodes is None:
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
            {
                "target_id": "target:nonmatch",
                "node_kind": "function",
                "boundaries": [],
                "effects": ["randomness"],
                "entity_properties": [],
            },
        ]
    if relations is None:
        relations = [
            {
                "relation_id": "relation:alpha",
                "selector": "calls",
                "source_target_id": "target:alpha",
                "destination_target_id": "target:beta",
            },
            {
                "relation_id": "relation:nonmatch",
                "selector": "precedes",
                "source_target_id": "target:alpha",
                "destination_target_id": "target:beta",
            },
        ]
    graph_schema = "fixture.program-graph.v1"
    coverage = {
        "coverage_kind": coverage_kind,
        "unknown_remainder": coverage_kind == "LOWER_BOUND",
        "limitation_reason": reason,
    }
    unsigned = {
        "schema": DENOMINATOR_SOURCE_SCHEMA,
        "producer": producer or _producer(),
        "audit_snapshot_digest": snapshot["snapshot_digest"],
        "source_scope_digest": snapshot["components"]["source_scope"]["digest"],
        "graph_schema": graph_schema,
        "graph_digest": graph_digest
        or _graph_digest(
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


def _selections(catalog: MethodCardCatalog) -> tuple[dict[str, str], ...]:
    return tuple(
        {
            "method_id": card.method_id,
            "method_version": card.method_version,
        }
        for card in catalog.cards[:2]
    )


def _steps(
    catalog: MethodCardCatalog,
    selections: tuple[dict[str, str], ...],
) -> tuple[dict[str, str], ...]:
    return tuple(
        {
            "method_id": card.method_id,
            "method_version": card.method_version,
            "step_id": step.step_id,
        }
        for selection in selections
        for card in (catalog.card(selection["method_id"]),)
        for step in card.required_steps
    )


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
                "parser_binding": {"implementation_sha256": _sha("parser")},
                "projection_mode": "CREATE_ABSENT",
                "canonical_prestate": {
                    "status": "ABSENT",
                    "sha256": "",
                    "size": 0,
                },
            }
        ],
    }


def _plan(snapshot: dict, methodology_digests: tuple[str, ...]) -> dict:
    roster = WTx.compile_phase_work_roster_denominator(
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
        phase_roster_denominator_digest=roster["roster_denominator_digest"],
        phase_io_contract_digest=_sha("phase-io-contract"),
        phase_io_launch_digest=_sha("phase-io-launch"),
        phase_io_input_set_digest=_sha("phase-io-inputs"),
        prompt_template_sha256=_sha("prompt"),
        methodology_digests=methodology_digests,
        source_snapshot_digest=snapshot["snapshot_digest"],
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


@pytest.fixture
def denominator_fixture(tmp_path: Path) -> dict:
    root = tmp_path / "implementation"
    catalog = _install(root)
    snapshot = _snapshot(root)
    selections = _selections(catalog)
    steps = _steps(catalog, selections)
    source = _source(snapshot)
    graph_binding = {
        "graph_schema": source["graph_schema"],
        "graph_digest": source["graph_digest"],
    }
    common = {
        "implementation_root": root,
        "audit_snapshot": snapshot,
        "selected_methods": selections,
        "denominator_source": source,
        "expected_denominator_producer": _producer(),
        "expected_graph_binding": graph_binding,
        "expected_catalog": catalog,
    }
    denominator = compile_method_card_denominator_authority(**common)
    runtime_input = compile_method_card_runtime_input_binding(
        **common,
        target_denominator=("target:alpha", "target:beta"),
        relation_denominator=("relation:alpha",),
        step_denominator=steps,
    )
    fragment = render_selected_method_fragment(catalog, selections)
    plan = _plan(
        snapshot,
        (
            catalog.digest,
            hashlib.sha256(fragment).hexdigest(),
            snapshot["components"]["methodology"]["digest"],
            runtime_input["runtime_input_binding_digest"],
        ),
    )
    return {
        **common,
        "steps": steps,
        "denominator": denominator,
        "runtime_input": runtime_input,
        "plan": plan,
    }


def _runtime(fixture: dict, **changes: object) -> dict:
    args = {
        key: fixture[key]
        for key in (
            "implementation_root",
            "audit_snapshot",
            "selected_methods",
                "denominator_source",
                "expected_denominator_producer",
                "expected_graph_binding",
                "expected_catalog",
        )
    }
    args.update(
        {
            "work_plan": fixture["plan"],
            "target_denominator": ("target:alpha", "target:beta"),
            "relation_denominator": ("relation:alpha",),
            "step_denominator": fixture["steps"],
        }
    )
    args.update(changes)
    return compile_method_card_runtime_authority(**args)


def _resign_source(source: dict) -> dict:
    unsigned = dict(source)
    unsigned.pop("source_digest", None)
    return {
        **unsigned,
        "source_digest": hashlib.sha256(
            canonical_json_bytes(unsigned)
        ).hexdigest(),
    }


def _resign_runtime(authority: dict) -> dict:
    unsigned = dict(authority)
    unsigned.pop("authority_digest", None)
    return {
        **unsigned,
        "authority_digest": hashlib.sha256(
            canonical_json_bytes(unsigned)
        ).hexdigest(),
    }


def test_exact_sets_are_source_derived_and_replayable(
    denominator_fixture: dict,
) -> None:
    authority = denominator_fixture["denominator"]
    assert authority["schema"] == DENOMINATOR_AUTHORITY_SCHEMA
    assert authority["coverage_kind"] == "EXACT"
    assert authority["unknown_remainder"] is False
    assert authority["limitation_reason"] is None
    assert authority["targets"] == ["target:alpha", "target:beta"]
    assert authority["relations"] == ["relation:alpha"]
    assert validate_method_card_denominator_authority(
        canonical_denominator_authority_bytes(authority),
        implementation_root=denominator_fixture["implementation_root"],
        audit_snapshot=denominator_fixture["audit_snapshot"],
        selected_methods=denominator_fixture["selected_methods"],
        denominator_source=canonical_file_bytes(
            denominator_fixture["denominator_source"]
        ),
        expected_denominator_producer=denominator_fixture[
            "expected_denominator_producer"
        ],
        expected_graph_binding=denominator_fixture[
            "expected_graph_binding"
        ],
        expected_catalog=denominator_fixture["expected_catalog"],
    ) == authority


def test_denominator_to_runtime_to_work_plan_hash_chain_is_acyclic(
    denominator_fixture: dict,
) -> None:
    denominator = denominator_fixture["denominator"]
    runtime_input = denominator_fixture["runtime_input"]
    authority = _runtime(denominator_fixture)

    assert "runtime_input_binding_digest" not in denominator
    assert "work_plan_digest" not in denominator
    assert runtime_input["denominator_authority_digest"] == denominator[
        "denominator_authority_digest"
    ]
    assert "work_plan_digest" not in runtime_input
    assert runtime_input["runtime_input_binding_digest"] in (
        denominator_fixture["plan"]["methodology_digests"]
    )
    assert authority["authority_digest"] not in (
        denominator_fixture["plan"]["methodology_digests"]
    )


def test_caller_cannot_omit_or_expand_source_derived_exact_sets(
    denominator_fixture: dict,
) -> None:
    for field, value in (
        ("target_denominator", ("target:alpha",)),
        (
            "target_denominator",
            ("target:alpha", "target:beta", "target:invented"),
        ),
        ("relation_denominator", ()),
        (
            "relation_denominator",
            ("relation:alpha", "relation:invented"),
        ),
    ):
        with pytest.raises(
            MethodCardRuntimeAuthorityError,
            match="source-derived|set equality",
        ):
            _runtime(denominator_fixture, **{field: value})


def test_empty_claim_is_not_exact_without_authoritative_zero(
    denominator_fixture: dict,
) -> None:
    with pytest.raises(
        MethodCardRuntimeAuthorityError,
        match="source-derived|set equality",
    ):
        _runtime(
            denominator_fixture,
            target_denominator=(),
            relation_denominator=(),
        )


def test_authoritative_exact_zero_is_accepted(
    denominator_fixture: dict,
) -> None:
    source = _source(
        denominator_fixture["audit_snapshot"],
        nodes=[],
        relations=[],
    )
    common = {
        "implementation_root": denominator_fixture["implementation_root"],
        "audit_snapshot": denominator_fixture["audit_snapshot"],
        "selected_methods": denominator_fixture["selected_methods"],
        "denominator_source": source,
        "expected_denominator_producer": denominator_fixture[
            "expected_denominator_producer"
        ],
        "expected_graph_binding": {
            "graph_schema": source["graph_schema"],
            "graph_digest": source["graph_digest"],
        },
        "expected_catalog": denominator_fixture["expected_catalog"],
    }
    denominator = compile_method_card_denominator_authority(**common)
    assert denominator["coverage_kind"] == "EXACT"
    assert denominator["targets"] == []
    assert denominator["relations"] == []

    binding = compile_method_card_runtime_input_binding(
        **common,
        target_denominator=(),
        relation_denominator=(),
        step_denominator=denominator_fixture["steps"],
    )
    assert binding["denominator_authority_digest"] == denominator[
        "denominator_authority_digest"
    ]


def test_lower_bound_unknown_and_reason_survive_runtime_and_work_plan_join(
    denominator_fixture: dict,
) -> None:
    source = _source(
        denominator_fixture["audit_snapshot"],
        coverage_kind="LOWER_BOUND",
        reason="graph provider lacks exact dynamic-dispatch closure",
    )
    common = {
        "implementation_root": denominator_fixture["implementation_root"],
        "audit_snapshot": denominator_fixture["audit_snapshot"],
        "selected_methods": denominator_fixture["selected_methods"],
        "denominator_source": source,
        "expected_denominator_producer": denominator_fixture[
            "expected_denominator_producer"
        ],
        "expected_graph_binding": {
            "graph_schema": source["graph_schema"],
            "graph_digest": source["graph_digest"],
        },
        "expected_catalog": denominator_fixture["expected_catalog"],
    }
    binding = compile_method_card_runtime_input_binding(
        **common,
        target_denominator=("target:alpha", "target:beta"),
        relation_denominator=("relation:alpha",),
        step_denominator=denominator_fixture["steps"],
    )
    fragment = render_selected_method_fragment(
        denominator_fixture["expected_catalog"],
        denominator_fixture["selected_methods"],
    )
    plan = _plan(
        denominator_fixture["audit_snapshot"],
        (
            denominator_fixture["expected_catalog"].digest,
            hashlib.sha256(fragment).hexdigest(),
            denominator_fixture["audit_snapshot"]["components"][
                "methodology"
            ]["digest"],
            binding["runtime_input_binding_digest"],
        ),
    )
    authority = compile_method_card_runtime_authority(
        **common,
        work_plan=plan,
        target_denominator=("target:alpha", "target:beta"),
        relation_denominator=("relation:alpha",),
        step_denominator=denominator_fixture["steps"],
    )
    denominator = authority["denominators"]
    assert denominator["coverage_kind"] == "LOWER_BOUND"
    assert denominator["unknown_remainder"] is True
    assert denominator["limitation_reason"] == (
        "graph provider lacks exact dynamic-dispatch closure"
    )
    assert denominator["debt"] == [
        {
            "debt_code": "UNKNOWN_DENOMINATOR_REMAINDER",
            "reason": "graph provider lacks exact dynamic-dispatch closure",
        }
    ]
    assert authority["method_binding"]["runtime_input_binding_digest"] in (
        plan["methodology_digests"]
    )
    assert authority["work_plan_binding"]["phase_io_contract_digest"] == (
        plan["phase_io_contract_digest"]
    )

    promoted = json.loads(canonical_runtime_authority_bytes(authority))
    promoted["denominators"]["coverage_kind"] = "EXACT"
    promoted["denominators"]["unknown_remainder"] = False
    promoted["denominators"]["limitation_reason"] = None
    promoted["denominators"]["debt"] = []
    denominator_unsigned = dict(promoted["denominators"])
    denominator_unsigned.pop("denominator_digest")
    promoted["denominators"]["denominator_digest"] = hashlib.sha256(
        canonical_json_bytes(denominator_unsigned)
    ).hexdigest()
    promoted = _resign_runtime(promoted)
    with pytest.raises(
        MethodCardRuntimeAuthorityError,
        match="external bindings|denominator",
    ):
        validate_method_card_runtime_authority(
            canonical_runtime_authority_bytes(promoted),
            implementation_root=common["implementation_root"],
            audit_snapshot=common["audit_snapshot"],
            work_plan=plan,
            denominator_source=common["denominator_source"],
            expected_denominator_producer=common[
                "expected_denominator_producer"
            ],
            expected_graph_binding=common["expected_graph_binding"],
            expected_catalog=common["expected_catalog"],
        )


@pytest.mark.parametrize(
    ("mutator", "match"),
    [
        (
            lambda value: {
                **value,
                "audit_snapshot_digest": _sha("stale-snapshot"),
            },
            "audit snapshot",
        ),
        (
            lambda value: {
                **value,
                "source_scope_digest": _sha("stale-source-scope"),
            },
            "source.scope|source-scope",
        ),
        (
            lambda value: {
                **value,
                "producer": {
                    **value["producer"],
                    "implementation_digest": _sha("stale-producer"),
                },
            },
            "producer",
        ),
    ],
)
def test_stale_source_and_producer_authority_fail_closed(
    denominator_fixture: dict,
    mutator,
    match: str,
) -> None:
    source = _resign_source(
        mutator(denominator_fixture["denominator_source"])
    )
    with pytest.raises(MethodCardRuntimeAuthorityError, match=match):
        compile_method_card_denominator_authority(
            implementation_root=denominator_fixture["implementation_root"],
            audit_snapshot=denominator_fixture["audit_snapshot"],
            selected_methods=denominator_fixture["selected_methods"],
            denominator_source=source,
            expected_denominator_producer=denominator_fixture[
                "expected_denominator_producer"
            ],
            expected_graph_binding=denominator_fixture[
                "expected_graph_binding"
            ],
            expected_catalog=denominator_fixture["expected_catalog"],
        )


def test_stale_graph_identity_cannot_validate_old_runtime_authority(
    denominator_fixture: dict,
) -> None:
    authority = _runtime(denominator_fixture)
    changed = {
        **denominator_fixture["denominator_source"],
        "nodes": [
            *denominator_fixture["denominator_source"]["nodes"],
            {
                "target_id": "target:zzz",
                "node_kind": "function",
                "boundaries": [],
                "effects": ["randomness"],
                "entity_properties": [],
            },
        ],
    }
    changed["graph_digest"] = _graph_digest(
        graph_schema=changed["graph_schema"],
        coverage=changed["coverage"],
        nodes=changed["nodes"],
        relations=changed["relations"],
    )
    source = _resign_source(changed)
    with pytest.raises(
        MethodCardRuntimeAuthorityError,
        match="external bindings|denominator|runtime input",
    ):
        validate_method_card_runtime_authority(
            canonical_runtime_authority_bytes(authority),
            implementation_root=denominator_fixture["implementation_root"],
            audit_snapshot=denominator_fixture["audit_snapshot"],
            work_plan=denominator_fixture["plan"],
            denominator_source=source,
            expected_denominator_producer=denominator_fixture[
                "expected_denominator_producer"
            ],
            expected_graph_binding=denominator_fixture[
                "expected_graph_binding"
            ],
            expected_catalog=denominator_fixture["expected_catalog"],
        )


def test_selector_or_method_revision_tamper_invalidates_denominator_authority(
    denominator_fixture: dict,
) -> None:
    authority = json.loads(
        canonical_denominator_authority_bytes(
            denominator_fixture["denominator"]
        )
    )
    authority["selector_digest"] = _sha("different-selector")
    unsigned = dict(authority)
    unsigned.pop("denominator_authority_digest")
    authority["denominator_authority_digest"] = hashlib.sha256(
        canonical_json_bytes(unsigned)
    ).hexdigest()
    with pytest.raises(
        MethodCardRuntimeAuthorityError,
        match="source|selector|external",
    ):
        validate_method_card_denominator_authority(
            canonical_file_bytes(authority),
            implementation_root=denominator_fixture["implementation_root"],
            audit_snapshot=denominator_fixture["audit_snapshot"],
            selected_methods=denominator_fixture["selected_methods"],
            denominator_source=denominator_fixture["denominator_source"],
            expected_denominator_producer=denominator_fixture[
                "expected_denominator_producer"
            ],
            expected_graph_binding=denominator_fixture[
                "expected_graph_binding"
            ],
            expected_catalog=denominator_fixture["expected_catalog"],
        )

    stale_methods = list(denominator_fixture["selected_methods"])
    stale_methods[0] = {
        **stale_methods[0],
        "method_version": "1.0.1",
    }
    with pytest.raises(
        MethodCardRuntimeAuthorityError,
        match="method_version",
    ):
        compile_method_card_denominator_authority(
            implementation_root=denominator_fixture["implementation_root"],
            audit_snapshot=denominator_fixture["audit_snapshot"],
            selected_methods=stale_methods,
            denominator_source=denominator_fixture["denominator_source"],
            expected_denominator_producer=denominator_fixture[
                "expected_denominator_producer"
            ],
            expected_graph_binding=denominator_fixture[
                "expected_graph_binding"
            ],
            expected_catalog=denominator_fixture["expected_catalog"],
        )


def test_source_rows_are_order_duplicate_and_casefold_closed(
    denominator_fixture: dict,
) -> None:
    base = denominator_fixture["denominator_source"]
    mutations = [
        {
            **base,
            "nodes": list(reversed(base["nodes"])),
        },
        {
            **base,
            "nodes": [*base["nodes"], dict(base["nodes"][0])],
        },
        {
            **base,
            "nodes": [
                *base["nodes"],
                {
                    **base["nodes"][0],
                    "target_id": "Target:alpha",
                },
            ],
        },
        {
            **base,
            "relations": list(reversed(base["relations"])),
        },
    ]
    for mutation in mutations:
        with pytest.raises(
            MethodCardRuntimeAuthorityError,
            match="order|duplicate|case-fold|source",
        ):
            compile_method_card_denominator_authority(
                implementation_root=denominator_fixture[
                    "implementation_root"
                ],
                audit_snapshot=denominator_fixture["audit_snapshot"],
                selected_methods=denominator_fixture["selected_methods"],
                denominator_source=_resign_source(mutation),
                expected_denominator_producer=denominator_fixture[
                    "expected_denominator_producer"
                ],
                expected_graph_binding=denominator_fixture[
                    "expected_graph_binding"
                ],
                expected_catalog=denominator_fixture["expected_catalog"],
            )


def test_lower_bound_requires_unknown_remainder_and_nonempty_reason(
    denominator_fixture: dict,
) -> None:
    for coverage in (
        {
            "coverage_kind": "LOWER_BOUND",
            "unknown_remainder": False,
            "limitation_reason": "provider incomplete",
        },
        {
            "coverage_kind": "LOWER_BOUND",
            "unknown_remainder": True,
            "limitation_reason": None,
        },
        {
            "coverage_kind": "EXACT",
            "unknown_remainder": True,
            "limitation_reason": "contradiction",
        },
    ):
        source = _resign_source(
            {
                **denominator_fixture["denominator_source"],
                "coverage": coverage,
            }
        )
        with pytest.raises(
            MethodCardRuntimeAuthorityError,
            match="coverage|remainder|reason",
        ):
            compile_method_card_denominator_authority(
                implementation_root=denominator_fixture[
                    "implementation_root"
                ],
                audit_snapshot=denominator_fixture["audit_snapshot"],
                selected_methods=denominator_fixture["selected_methods"],
                denominator_source=source,
                expected_denominator_producer=denominator_fixture[
                    "expected_denominator_producer"
                ],
                expected_graph_binding=denominator_fixture[
                    "expected_graph_binding"
                ],
                expected_catalog=denominator_fixture["expected_catalog"],
            )


def test_later_runtime_receipt_cannot_privately_shrink_or_expand_denominator(
    denominator_fixture: dict,
) -> None:
    authority = _runtime(denominator_fixture)
    for targets in (
        ["target:alpha"],
        ["target:alpha", "target:beta", "target:invented"],
    ):
        tampered = json.loads(canonical_runtime_authority_bytes(authority))
        tampered["denominators"]["targets"] = targets
        tampered["denominators"]["target_count"] = len(targets)
        denominator_unsigned = dict(tampered["denominators"])
        denominator_unsigned.pop("denominator_digest")
        tampered["denominators"]["denominator_digest"] = hashlib.sha256(
            canonical_json_bytes(denominator_unsigned)
        ).hexdigest()
        tampered = _resign_runtime(tampered)
        with pytest.raises(
            MethodCardRuntimeAuthorityError,
            match="external bindings|denominator|source-derived",
        ):
            validate_method_card_runtime_authority(
                canonical_runtime_authority_bytes(tampered),
                implementation_root=denominator_fixture[
                    "implementation_root"
                ],
                audit_snapshot=denominator_fixture["audit_snapshot"],
                work_plan=denominator_fixture["plan"],
                denominator_source=denominator_fixture[
                    "denominator_source"
                ],
                expected_denominator_producer=denominator_fixture[
                    "expected_denominator_producer"
                ],
                expected_graph_binding=denominator_fixture[
                    "expected_graph_binding"
                ],
                expected_catalog=denominator_fixture["expected_catalog"],
            )
