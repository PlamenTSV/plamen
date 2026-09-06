"""P0-AJ: typed queue identity and lossless projection fixtures.

The substrate is intentionally independent of the current queue parser and
driver.  These tests lock the authoritative identity, JSON, Markdown, and
partition contracts before any runtime wiring changes.
"""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import json

import pytest

from queue_work_items import (
    MARKDOWN_HEADERS,
    ExclusionDisposition,
    LineageLink,
    LocationRecord,
    MarkdownProjectionError,
    QueueWorkPlan,
    QueueWorkItem,
    SeverityProposal,
    VerifierOutputIdentity,
    VerifierOutputReceipt,
    build_queue_work_plan,
    build_lineage_index,
    markdown_projection_digest,
    parse_queue_markdown,
    queue_record_set_digest,
    queue_records_from_json,
    queue_records_to_json,
    render_queue_markdown,
    validate_exact_partition,
    validate_queue_work_items,
)


def _item(
    work_item_id: str = "H-22",
    *,
    candidate_identity: str = "INV-041",
    aliases: tuple[str, ...] = ("INV-041",),
    constituents: tuple[str, ...] = (),
    title: str = "External-rate reconciliation can drift",
    locations: tuple[LocationRecord, ...] | None = None,
    queue_priority: int = 10,
    required_disposition: str = "STANDARD",
) -> QueueWorkItem:
    if locations is None:
        locations = (
            LocationRecord(
                artifact="contracts/pool.rs",
                start_line=41,
                end_line=58,
                symbol="Pool::reconcile",
            ),
        )
    return QueueWorkItem(
        candidate_identity=candidate_identity,
        work_item_id=work_item_id,
        lineage=(
            LineageLink(
                identity=candidate_identity,
                relation="ORIGIN",
                source_artifact="findings_inventory.md",
            ),
            LineageLink(
                identity=work_item_id,
                relation="RELABEL",
                parent_identity=candidate_identity,
                source_artifact="verification_queue.json",
            ),
        ),
        aliases=aliases,
        constituents=constituents,
        severity_proposal=SeverityProposal(
            level="High",
            impact="High",
            likelihood="Medium",
            rationale="Material loss if the premise holds.",
        ),
        evidence_class="confirmed-mechanism",
        bug_class="external-state-reconciliation",
        preferred_tag="CODE-TRACE",
        queue_priority=queue_priority,
        location_records=locations,
        primary_artifacts=("depth_economic_findings.md", "invariant_ledger.md"),
        poc_class="integration",
        title=title,
        required_disposition=required_disposition,
    )


def test_current_work_item_id_is_the_only_filename_authority_and_records_are_frozen():
    item = _item()
    assert item.expected_output_file == "verify_H-22.md"
    assert "INV-041" not in item.expected_output_file
    assert item.expected_output_identity == "scratchpad:verify_H-22.md"
    with pytest.raises(FrozenInstanceError):
        item.work_item_id = "INV-041"  # type: ignore[misc]
    with pytest.raises(ValueError):
        _item(work_item_id="../H-22")


def test_strict_json_round_trip_rejects_stale_expected_filename_and_unknown_fields():
    item = _item()
    assert QueueWorkItem.from_json(item.to_json()) == item

    stale = item.to_dict()
    stale["expected_output_file"] = "verify_INV-041.md"
    with pytest.raises(ValueError, match="expected_output_file"):
        QueueWorkItem.from_dict(stale)

    extra = item.to_dict()
    extra["legacy filename"] = "verify_INV-041.md"
    with pytest.raises(ValueError, match="unexpected fields"):
        QueueWorkItem.from_dict(extra)

    missing = item.to_dict()
    del missing["evidence_class"]
    with pytest.raises(ValueError, match="missing fields"):
        QueueWorkItem.from_dict(missing)


def test_bug_class_preferred_tag_and_queue_priority_are_independent_typed_fields():
    item = _item(queue_priority=37)
    assert item.evidence_class == "confirmed-mechanism"
    assert item.bug_class == "external-state-reconciliation"
    assert item.preferred_tag == "CODE-TRACE"
    assert item.queue_priority == 37

    payload = item.to_dict()
    payload["bug_class"] = "accounting"
    payload["preferred_tag"] = "POC-PASS"
    payload["evidence_class"] = "mechanism-only"
    rebuilt = QueueWorkItem.from_dict(payload)
    assert rebuilt.bug_class == "accounting"
    assert rebuilt.preferred_tag == "POC-PASS"
    assert rebuilt.evidence_class == "mechanism-only"

    with pytest.raises(ValueError, match="queue_priority"):
        replace(item, queue_priority=-1)


def test_legacy_inv_to_h_relabel_recomputes_filename_and_preserves_r10_join_alias():
    item = QueueWorkItem.from_legacy_row(
        {
            "finding id": "H-22",
            "source identity": "INV-041",
            "expected output file": "verify_INV-041.md",
            "severity": "High",
            "title": "Relabelled candidate",
            "preferred tag": "code-trace",
            "location": "src/pool.rs:41-58",
            "primary artifact": "depth_economic_findings.md",
            "poc class": "integration",
        }
    )
    assert item.work_item_id == "H-22"
    assert item.candidate_identity == "INV-041"
    assert item.expected_output_file == "verify_H-22.md"
    assert "INV-041" in item.aliases
    assert build_lineage_index((item,)).resolve_all("INV-041") == ("H-22",)


def test_legacy_stale_filename_is_migration_debt_not_candidate_authority():
    item = QueueWorkItem.from_legacy_row(
        {
            "queue #": "12",
            "finding id": "H-22",
            "expected output file": "verify_INV-041.md",
            "severity": "High",
            "bug class": "accounting drift",
            "preferred tag": "CODE-TRACE",
        }
    )
    assert item.candidate_identity == "H-22"
    assert item.queue_priority == 12
    assert item.bug_class == "accounting drift"
    assert item.preferred_tag == "CODE-TRACE"
    assert "INV-041" in item.aliases
    assert any(
        link.identity == "INV-041" and link.relation == "MIGRATION_DEBT"
        for link in item.lineage
    )


def test_many_to_one_grouping_preserves_all_aliases_and_constituents():
    grouped = _item(
        work_item_id="GRP-H-07",
        candidate_identity="CID-007",
        aliases=("INV-007", "INV-008"),
        constituents=("H-07", "H-08"),
    )
    assert grouped.expected_output_file == "verify_GRP-H-07.md"
    index = build_lineage_index((grouped,))
    for identity in ("CID-007", "INV-007", "INV-008", "H-07", "H-08"):
        assert index.resolve_all(identity) == ("GRP-H-07",)


def test_duplicate_work_ids_and_expected_filenames_are_rejected_case_insensitively():
    first = _item()
    duplicate = replace(first, title="same output, different display")
    with pytest.raises(ValueError, match="duplicate work_item_id"):
        validate_queue_work_items((first, duplicate))

    case_collision = _item(work_item_id="h-22")
    with pytest.raises(ValueError, match="output filename collision"):
        validate_queue_work_items((first, case_collision))


def test_markdown_projection_round_trips_all_delimiter_and_path_edge_cases():
    title = (
        "raw | pipe; escaped \\| text; double ||; grep 'a|b'; regex ^(x|y)$; "
        "`code | span`; slash \\; newline\nsecond line; Unicode Δ雪"
    )
    locations = (
        LocationRecord(
            artifact=r"C:\repo\contracts\Pool.sol",
            start_line=7,
            end_line=9,
            symbol="Pool|settle",
            note="Windows | path",
        ),
        LocationRecord(
            artifact="src/contracts/pool.rs",
            symbol="grep a|b",
            note="POSIX\npath",
        ),
    )
    item = _item(title=title, locations=locations)
    projection = render_queue_markdown((item,))
    assert parse_queue_markdown(projection) == (item,)


def test_independent_verification_policy_survives_json_and_markdown_round_trip():
    item = _item(required_disposition="VERIFY_INDEPENDENTLY")

    assert QueueWorkItem.from_json(item.to_json()) == item
    assert queue_records_from_json(
        queue_records_to_json((item,))
    ) == (item,)
    assert parse_queue_markdown(render_queue_markdown((item,))) == (item,)
    assert item.required_disposition == "VERIFY_INDEPENDENTLY"


@pytest.mark.parametrize(
    "row",
    (
        {"required disposition": "VERIFY_INDEPENDENTLY"},
        {"relation kind": "ENABLER_CONSTITUENT"},
    ),
)
def test_legacy_row_promotes_exact_independent_verification_policy(row):
    item = QueueWorkItem.from_legacy_row({
        "finding id": "DA-7",
        "severity": "Medium",
        "bug class": "state-transition",
        "preferred tag": "CODE-TRACE",
        **row,
    })

    assert item.required_disposition == "VERIFY_INDEPENDENTLY"


def test_unknown_required_disposition_is_rejected_not_silently_standardized():
    with pytest.raises(ValueError, match="required_disposition"):
        replace(_item(), required_disposition="DROP_IF_GROUPED")


def test_renderer_emits_exact_ten_column_header_and_data_widths():
    projection = render_queue_markdown((_item(),))
    lines = projection.splitlines()
    assert len(MARKDOWN_HEADERS) == 10
    assert lines[0].count("|") == 11
    parsed = parse_queue_markdown(projection)
    assert parsed == (_item(),)


@pytest.mark.parametrize("width", [11, 30])
def test_malformed_legacy_markdown_width_is_rejected_without_guessing(width: int):
    header = "| " + " | ".join(MARKDOWN_HEADERS) + " |"
    separator = "| " + " | ".join("---" for _ in MARKDOWN_HEADERS) + " |"
    malformed = "| " + " | ".join(f"cell-{i}" for i in range(width)) + " |"
    with pytest.raises(MarkdownProjectionError, match=rf"expected 10 cells, got {width}"):
        parse_queue_markdown("\n".join((header, separator, malformed)) + "\n")


def test_unescaped_pipe_in_legacy_code_span_is_a_width_error_not_shifted_data():
    header = "| " + " | ".join(MARKDOWN_HEADERS) + " |"
    separator = "| " + " | ".join("---" for _ in MARKDOWN_HEADERS) + " |"
    cells = [json.dumps("x") for _ in MARKDOWN_HEADERS]
    cells[8] = json.dumps("`left") + " | " + json.dumps("right`")
    with pytest.raises(MarkdownProjectionError, match="expected 10 cells, got 11"):
        parse_queue_markdown("\n".join((header, separator, "| " + " | ".join(cells) + " |")) + "\n")


def test_record_set_json_is_order_stable_strict_and_digest_bound():
    a = _item("H-22", queue_priority=20)
    b = _item(
        "M-03",
        candidate_identity="INV-003",
        aliases=("INV-003",),
        queue_priority=10,
    )
    encoded = queue_records_to_json((a, b))
    assert encoded == queue_records_to_json((b, a))
    assert queue_records_from_json(encoded) == (b, a)

    payload = json.loads(encoded)
    payload["record_set_digest"] = "0" * 64
    with pytest.raises(ValueError, match="record_set_digest"):
        queue_records_from_json(json.dumps(payload))


def test_exact_partition_conservation_accepts_only_union_equality_and_no_overlap():
    items = (
        _item("H-22"),
        _item("M-03", candidate_identity="INV-003", aliases=("INV-003",)),
        _item("L-09", candidate_identity="INV-009", aliases=("INV-009",)),
    )
    valid = validate_exact_partition(
        items,
        {"high": ("H-22",), "medium": (items[1],), "low": ("L-09",)},
    )
    assert valid.ok
    valid.require_valid()

    invalid = validate_exact_partition(
        items,
        {"a": ("H-22", "M-03"), "b": ("M-03", "EXTRA-1")},
    )
    assert invalid.missing_ids == ("L-09",)
    assert invalid.extra_ids == ("EXTRA-1",)
    assert invalid.duplicate_ids == ("M-03",)
    with pytest.raises(ValueError, match="partition conservation failed"):
        invalid.require_valid()


def test_work_plan_binds_parent_ordered_shards_projection_and_output_ownership():
    high = _item("H-22", queue_priority=20)
    medium = _item(
        "M-03",
        candidate_identity="INV-003",
        aliases=("INV-003",),
        queue_priority=10,
    )
    plan = build_queue_work_plan(
        (high, medium),
        {"verify-high": (high,), "verify-medium": ("M-03",)},
        planner_version="bounded-count-v1",
    )
    assert plan.parent_record_set_digest == queue_record_set_digest((high, medium))
    assert plan.ordered_work_item_ids == ("M-03", "H-22")
    assert QueueWorkPlan.from_json(plan.to_json()) == plan
    assert plan.validate_against((high, medium)) is None

    by_id = {shard.shard_id: shard for shard in plan.shards}
    assert by_id["verify-high"].ordered_work_item_ids == ("H-22",)
    assert by_id["verify-medium"].ordered_work_item_ids == ("M-03",)
    owner = by_id["verify-high"].output_ownership[0]
    assert owner.work_item_id == "H-22"
    assert owner.expected_output_file == "verify_H-22.md"
    assert owner.work_item_digest == high.digest
    assert by_id["verify-high"].projection_digest == markdown_projection_digest(
        render_queue_markdown((high,))
    )


def test_work_plan_rejects_partition_drift_and_semantically_forged_envelopes():
    first = _item("H-22", queue_priority=1)
    second = _item(
        "M-03",
        candidate_identity="INV-003",
        aliases=("INV-003",),
        queue_priority=2,
    )
    with pytest.raises(ValueError, match="partition conservation failed"):
        build_queue_work_plan(
            (first, second),
            {"a": ("H-22", "M-03"), "b": ("M-03",)},
            planner_version="bounded-count-v1",
        )

    plan = build_queue_work_plan(
        (first, second),
        {"a": ("H-22",), "b": ("M-03",)},
        planner_version="bounded-count-v1",
    )
    forged_shard = replace(plan.shards[0], projection_digest="0" * 64)
    forged = replace(plan, shards=(forged_shard, *plan.shards[1:]))
    with pytest.raises(ValueError, match="projection_digest"):
        forged.validate_against((first, second))

    payload = json.loads(plan.to_json())
    payload["shards"][0]["ordered_work_item_ids"][0] = "EXTRA-1"
    with pytest.raises(ValueError, match="work_plan_digest|output_ownership"):
        QueueWorkPlan.from_json(json.dumps(payload))


def test_work_plan_is_deterministic_across_mapping_order_and_one_shot_iterables():
    first = _item("H-22", queue_priority=2)
    second = _item(
        "M-03",
        candidate_identity="INV-003",
        aliases=("INV-003",),
        queue_priority=1,
    )
    expected = build_queue_work_plan(
        (first, second),
        {"a": ("M-03",), "b": ("H-22",)},
        planner_version="bounded-count-v1",
    )
    generated = build_queue_work_plan(
        (second, first),
        {
            "b": (identity for identity in ("H-22",)),
            "a": (identity for identity in ("M-03",)),
        },
        planner_version="bounded-count-v1",
    )
    assert generated.to_json() == expected.to_json()


def test_verifier_output_identity_and_receipt_are_digest_bound():
    item = _item(queue_priority=1)
    plan = build_queue_work_plan(
        (item,),
        {"verify-high": (item,)},
        planner_version="bounded-count-v1",
    )
    output = b"# Verification: H-22\n\n**Verdict**: CONFIRMED\n"
    launch_digest = "a" * 64
    identity = VerifierOutputIdentity.for_assignment(item, plan, "verify-high")
    assert identity.expected_output_file == "verify_H-22.md"
    receipt = VerifierOutputReceipt.bind(
        identity,
        output,
        severity_proposal=b"{}",
        launch_digest=launch_digest,
        verifier_backend="claude",
    )
    assert VerifierOutputReceipt.from_json(receipt.to_json()) == receipt
    assert receipt.validate_against(
        item,
        plan,
        output,
        severity_proposal=b"{}",
        launch_digest=launch_digest,
        verifier_backend="claude",
    ) is None

    with pytest.raises(ValueError, match="output_sha256"):
        receipt.validate_against(
            item,
            plan,
            output + b"tampered",
            severity_proposal=b"{}",
            launch_digest=launch_digest,
            verifier_backend="claude",
        )
    with pytest.raises(ValueError, match="queue_record_digest"):
        receipt.validate_against(
            replace(item, title="changed claim"),
            plan,
            output,
            severity_proposal=b"{}",
            launch_digest=launch_digest,
            verifier_backend="claude",
        )

    tampered = json.loads(receipt.to_json())
    tampered["output_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="receipt_digest"):
        VerifierOutputReceipt.from_json(json.dumps(tampered))

    stale_name = identity.to_dict()
    stale_name["expected_output_file"] = "verify_INV-041.md"
    with pytest.raises(ValueError, match="expected_output_file"):
        VerifierOutputIdentity.from_dict(stale_name)


def test_exclusion_disposition_is_separate_from_active_work_and_strictly_bound():
    exclusion = ExclusionDisposition(
        identity="INV-099",
        status="DEFERRED",
        reason_class="PIPELINE_DROPOUT",
        reason="Independent verification could not be scheduled.",
        authority="verify-aggregate",
        evidence_ids=("queue-reconciliation-1",),
        next_action="RECOVERY_VERIFY",
        public_retention_target="human_review_appendix",
    )
    assert ExclusionDisposition.from_json(exclusion.to_json()) == exclusion
    assert exclusion.digest
    with pytest.raises(FrozenInstanceError):
        exclusion.status = "OUT_OF_SCOPE"  # type: ignore[misc]
    tampered = json.loads(exclusion.to_json())
    tampered["reason"] = "Changed without rebinding."
    with pytest.raises(ValueError, match="disposition_digest"):
        ExclusionDisposition.from_json(json.dumps(tampered))


def test_partition_uses_current_ids_not_aliases_and_never_silently_drops_grouped_rows():
    grouped = _item(
        work_item_id="GRP-H-07",
        candidate_identity="CID-007",
        aliases=("INV-007", "INV-008"),
        constituents=("H-07", "H-08"),
    )
    result = validate_exact_partition((grouped,), {"high": ("INV-007",)})
    assert result.missing_ids == ("GRP-H-07",)
    assert result.extra_ids == ("INV-007",)


def test_frozen_scale_fixture_preserves_174_identities_and_projection_parity():
    items = tuple(
        _item(
            f"H-{i:03d}",
            candidate_identity=f"INV-{i:03d}",
            aliases=(f"INV-{i:03d}",),
            queue_priority=i,
        )
        for i in range(1, 175)
    )
    decoded = parse_queue_markdown(render_queue_markdown(items))
    assert len(decoded) == 174
    assert {item.work_item_id for item in decoded} == {
        item.work_item_id for item in items
    }
    shards = {
        f"shard-{n}": tuple(item.work_item_id for item in items[n::10])
        for n in range(10)
    }
    assert validate_exact_partition(items, shards).ok
    plan = build_queue_work_plan(
        items,
        shards,
        planner_version="bounded-count-v1",
    )
    assert len(plan.ordered_work_item_ids) == 174
    assert len(plan.output_ownership) == 174
    assert plan.validate_against(items) is None


def test_location_and_lineage_nested_json_reject_unknown_or_malformed_fields():
    with pytest.raises(ValueError, match="end_line"):
        LocationRecord(artifact="src/lib.rs", start_line=4, end_line=3)

    data = _item().to_dict()
    data["location_records"][0]["mystery"] = True
    with pytest.raises(ValueError, match="unexpected fields"):
        QueueWorkItem.from_dict(data)
