"""Independent-review fixtures for exact inventory reconciliation hardening."""
from __future__ import annotations

import copy
import inspect
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from inventory_reconciliation import (  # noqa: E402
    InventoryReconciliationError,
    reconcile_inventory,
    validate_inventory_reconciliation,
    write_inventory_reconciliation,
)
import inventory_reemit_authority as reemit_authority  # noqa: E402
import plamen_markdown  # noqa: E402
from operational_markdown import operational_markdown_view  # noqa: E402
from plamen_markdown import (  # noqa: E402
    MarkdownParserContractError,
    REVIEWED_MARKDOWN_IT_VERSION,
    inline_code_source_spans,
    parse_authoritative,
    runtime_markdown_it_version,
)


def _finding(
    finding_id: str,
    *,
    heading_depth: int = 3,
    source_ids: tuple[str, ...] = (),
    mechanism: str = "source mechanism",
    description: str | None = None,
    impact: str = "source material harm",
) -> str:
    description = mechanism if description is None else description
    source_field = (
        f"**Source IDs**: {', '.join(source_ids)}\n" if source_ids else ""
    )
    return (
        f"{'#' * heading_depth} Finding [{finding_id}]: Fixture\n"
        "**Severity**: Medium\n"
        "**Location**: src/Fixture.sol:L10\n"
        f"**Root Cause**: {mechanism}\n"
        f"**Description**: {description}\n"
        f"**Impact**: {impact}\n"
        f"{source_field}"
        "**Verdict**: NEEDS_VERIFICATION\n\n"
    )


def _manifest(root: Path, source: str) -> None:
    (root / "inventory_chunk_a.manifest.md").write_text(
        "# Manifest\n\n"
        "| File | Estimated signals |\n"
        "|------|-------------------|\n"
        f"| {source} | 1 |\n",
        encoding="utf-8",
    )


def _write_pipeline(
    root: Path,
    source_text: str,
    *,
    chunk_text: str,
    inventory_text: str,
) -> None:
    source = "analysis_evm_flow.md"
    (root / source).write_text(source_text, encoding="utf-8")
    _manifest(root, source)
    (root / "findings_inventory_chunk_a.md").write_text(
        "# Inventory Chunk\n\n" + chunk_text,
        encoding="utf-8",
    )
    (root / "findings_inventory.md").write_text(
        "# Finding Inventory\n\n" + inventory_text,
        encoding="utf-8",
    )


def _write_pipeline_bytes(
    root: Path,
    source_text: str,
    *,
    chunk_text: str,
    inventory_text: str,
    newline: str,
) -> None:
    def encoded(value: str) -> bytes:
        return value.replace("\n", newline).encode("utf-8")

    source = "analysis_evm_flow.md"
    (root / source).write_bytes(encoded(source_text))
    (root / "inventory_chunk_a.manifest.md").write_bytes(
        encoded(
            "# Manifest\n\n"
            "| File | Estimated signals |\n"
            "|------|-------------------|\n"
            f"| {source} | 1 |\n"
        )
    )
    (root / "findings_inventory_chunk_a.md").write_bytes(
        encoded("# Inventory Chunk\n\n" + chunk_text)
    )
    (root / "findings_inventory.md").write_bytes(
        encoded("# Finding Inventory\n\n" + inventory_text)
    )


def _hidden(container: str, body: str) -> str:
    if container == "fence":
        return f"```markdown\n{body}```\n"
    if container == "comment":
        return f"<!--\n{body}-->\n"
    raise AssertionError(container)


@pytest.mark.parametrize("container", ["fence", "comment"])
def test_non_operational_source_and_target_blocks_mint_no_retention_authority(
    tmp_path: Path,
    container: str,
) -> None:
    source = _finding("TF-1") + _hidden(container, _finding("TF-999"))
    chunk = _finding("CC-1", source_ids=("TF-1",))
    hidden_target = _hidden(
        container,
        _finding("INV-001", source_ids=("TF-1", "CC-1")),
    )
    _write_pipeline(
        tmp_path,
        source,
        chunk_text=chunk,
        inventory_text=hidden_target,
    )

    receipt = reconcile_inventory(tmp_path)

    assert receipt["denominator_count"] == 1
    assert receipt["summary"] == {
        "AUTHORIZED_MERGE": 0,
        "AUTHORIZED_REFUTATION": 0,
        "HUMAN_REVIEW_DEBT": 1,
        "RETAINED": 0,
        "TOTAL": 1,
    }
    row = receipt["candidates"][0]
    assert row["source_finding_id"] == "TF-1"
    assert row["target_inventory_id"] == ""
    assert row["mandatory_reverification"] is True


def test_non_operational_target_fields_cannot_satisfy_semantic_preservation(
    tmp_path: Path,
) -> None:
    source = _finding("TF-1")
    chunk = _finding("CC-1", source_ids=("TF-1",))
    final = (
        "### Finding [INV-001]: Fixture\n"
        "**Severity**: Medium\n"
        "**Location**: src/Fixture.sol:L10\n"
        "**Description**: a different synthesized mechanism\n"
        "**Source IDs**: TF-1, CC-1\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
        "```markdown\n"
        "**Root Cause**: source mechanism\n"
        "**Example End**: fenced\n"
        "```\n"
        "<!--\n"
        "**Impact**: source material harm\n"
        "**Example End**: commented\n"
        "-->\n"
    )
    _write_pipeline(tmp_path, source, chunk_text=chunk, inventory_text=final)

    row = reconcile_inventory(tmp_path)["candidates"][0]

    assert row["disposition"] == "HUMAN_REVIEW_DEBT"
    assert set(row["required_preservation_axes"]) == {"ROOT_CAUSE", "IMPACT"}
    assert row["mandatory_reverification"] is True


def test_default_ignorable_only_mechanism_and_harm_are_unparseable_debt(
    tmp_path: Path,
) -> None:
    invisible = "\u200b"
    source = _finding(
        "TF-1",
        mechanism=invisible,
        description=invisible,
        impact=invisible,
    )
    chunk = _finding(
        "CC-1",
        source_ids=("TF-1",),
        mechanism=invisible,
        description=invisible,
        impact=invisible,
    )
    final = _finding(
        "INV-001",
        source_ids=("TF-1", "CC-1"),
        mechanism=invisible,
        description=invisible,
        impact=invisible,
    )
    _write_pipeline(tmp_path, source, chunk_text=chunk, inventory_text=final)

    row = reconcile_inventory(tmp_path)["candidates"][0]

    assert row["source_root_cause"] == ""
    assert row["source_impact"] == ""
    assert row["disposition"] == "HUMAN_REVIEW_DEBT"
    assert set(row["required_preservation_axes"]) == {
        "UNPARSEABLE_ROOT_CAUSE",
        "UNPARSEABLE_IMPACT",
    }
    assert row["mandatory_reverification"] is True
    assert row["mandatory_reverification_id_binding"] == {
        "candidate_key": row["candidate_key"],
        "source_block_sha256": row["source_block_sha256"],
    }


def test_legitimate_unicode_prose_is_preserved_while_testing_visibility(
    tmp_path: Path,
) -> None:
    mechanism = "解析\u200d机制"
    impact = "資産が失われる"
    source = _finding("TF-1", mechanism=mechanism, impact=impact)
    chunk = _finding(
        "CC-1", source_ids=("TF-1",), mechanism=mechanism, impact=impact
    )
    final = _finding(
        "INV-001",
        source_ids=("TF-1", "CC-1"),
        mechanism=mechanism,
        impact=impact,
    )
    _write_pipeline(tmp_path, source, chunk_text=chunk, inventory_text=final)

    row = reconcile_inventory(tmp_path)["candidates"][0]

    assert row["source_root_cause"] == mechanism
    assert row["source_impact"] == impact
    assert row["disposition"] == "RETAINED"


def test_assigned_h4_finding_cannot_produce_a_clean_zero_denominator(
    tmp_path: Path,
) -> None:
    source = _finding("TF-4", heading_depth=4)
    chunk = _finding("CC-4", source_ids=("TF-4",))
    final = _finding("INV-004", source_ids=("TF-4", "CC-4"))
    _write_pipeline(tmp_path, source, chunk_text=chunk, inventory_text=final)

    receipt = reconcile_inventory(tmp_path)

    assert receipt["denominator_count"] == 1
    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 1
    assert receipt["summary"]["RETAINED"] == 0
    row = receipt["candidates"][0]
    assert row["source_artifact"] == "analysis_evm_flow.md"
    assert row["source_finding_id"] == "TF-4"
    assert row["reason_code"] == "UNSUPPORTED_FINDING_HEADING_DEPTH"
    assert row["target_inventory_id"] == ""
    assert row["authority_artifact"] == ""
    assert row["mandatory_reverification"] is True
    assert row["mandatory_reverification_id_binding"] == {
        "candidate_key": row["candidate_key"],
        "source_block_sha256": row["source_block_sha256"],
    }


@pytest.mark.parametrize(
    "invisible_entity",
    ("&#8203;", "&#x200B;", "&ZeroWidthSpace;", "&zwnj;", "&#173;"),
)
def test_html_entity_only_material_fields_remain_persisted_debt(
    tmp_path: Path,
    invisible_entity: str,
) -> None:
    source = _finding(
        "TF-1",
        mechanism=invisible_entity,
        description=invisible_entity,
        impact=invisible_entity,
    )
    chunk = _finding(
        "CC-1",
        source_ids=("TF-1",),
        mechanism=invisible_entity,
        description=invisible_entity,
        impact=invisible_entity,
    )
    final = _finding(
        "INV-001",
        source_ids=("TF-1", "CC-1"),
        mechanism=invisible_entity,
        description=invisible_entity,
        impact=invisible_entity,
    )
    _write_pipeline(tmp_path, source, chunk_text=chunk, inventory_text=final)

    receipt = write_inventory_reconciliation(tmp_path)
    row = receipt["candidates"][0]

    assert row["source_root_cause"] == ""
    assert row["source_impact"] == ""
    assert row["disposition"] == "HUMAN_REVIEW_DEBT"
    assert set(row["required_preservation_axes"]) == {
        "UNPARSEABLE_ROOT_CAUSE",
        "UNPARSEABLE_IMPACT",
    }
    assert validate_inventory_reconciliation(tmp_path) == []


def test_additive_reemit_cannot_launder_invisible_entity_source_debt(
    tmp_path: Path,
) -> None:
    invisible = "&ZeroWidthSpace;"
    source = _finding(
        "TF-1", mechanism=invisible, description=invisible, impact=invisible
    )
    chunk = _finding(
        "CC-1",
        source_ids=("TF-1",),
        mechanism=invisible,
        description=invisible,
        impact=invisible,
    )
    final = _finding(
        "INV-001",
        source_ids=("TF-1", "CC-1"),
        mechanism=invisible,
        description=invisible,
        impact=invisible,
    )
    _write_pipeline(tmp_path, source, chunk_text=chunk, inventory_text=final)

    with pytest.raises(
        reemit_authority.InventoryReemitError,
        match="does not replay exact candidate delivery",
    ):
        reemit_authority._apply_inventory_reemit_repair_for_tests(tmp_path)
    replay = write_inventory_reconciliation(tmp_path)

    assert replay["summary"]["HUMAN_REVIEW_DEBT"] == 1
    assert replay["summary"]["RETAINED"] == 0
    assert replay["candidates"][0]["reason_code"] in {
        "REEMIT_UNPARSEABLE_SOURCE_DEBT",
        "FINAL_SEMANTIC_PRESERVATION_DEBT",
    }
    assert replay["candidates"][0]["reason_code"] != (
        "RETAINED_BY_ADDITIVE_REEMIT"
    )
    assert validate_inventory_reconciliation(tmp_path) == []


def test_u180f_is_default_ignorable_but_nondefault_cf_remains_visible(
    tmp_path: Path,
) -> None:
    invisible = "\u180f"
    source = _finding(
        "TF-1", mechanism=invisible, description=invisible, impact=invisible
    )
    chunk = _finding(
        "CC-1",
        source_ids=("TF-1",),
        mechanism=invisible,
        description=invisible,
        impact=invisible,
    )
    final = _finding(
        "INV-001",
        source_ids=("TF-1", "CC-1"),
        mechanism=invisible,
        description=invisible,
        impact=invisible,
    )
    _write_pipeline(tmp_path, source, chunk_text=chunk, inventory_text=final)
    row = reconcile_inventory(tmp_path)["candidates"][0]
    assert row["source_root_cause"] == ""
    assert row["source_impact"] == ""
    assert row["disposition"] == "HUMAN_REVIEW_DEBT"

    visible_cf = "\u0600"
    _write_pipeline(
        tmp_path,
        _finding("TF-1", mechanism=visible_cf, impact=visible_cf),
        chunk_text=_finding(
            "CC-1", source_ids=("TF-1",), mechanism=visible_cf, impact=visible_cf
        ),
        inventory_text=_finding(
            "INV-001",
            source_ids=("TF-1", "CC-1"),
            mechanism=visible_cf,
            impact=visible_cf,
        ),
    )
    visible_row = reconcile_inventory(tmp_path)["candidates"][0]
    assert visible_row["source_root_cause"] == visible_cf
    assert visible_row["source_impact"] == visible_cf
    assert visible_row["disposition"] == "RETAINED"


def test_qualified_source_reference_cannot_synthesize_bare_fallback(
    tmp_path: Path,
) -> None:
    source = _finding("TF-1")
    chunk = _finding(
        "CC-1", source_ids=("analysis_other.md:TF-1",)
    )
    final = _finding(
        "INV-001",
        source_ids=("analysis_other.md:TF-1", "CC-1"),
    )
    _write_pipeline(tmp_path, source, chunk_text=chunk, inventory_text=final)

    receipt = write_inventory_reconciliation(tmp_path)

    assert receipt["summary"]["RETAINED"] == 0
    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 1
    assert receipt["candidates"][0]["reason_code"] == "MISSING_CHUNK_DISPOSITION"
    assert validate_inventory_reconciliation(tmp_path) == []


def test_legacy_bare_reference_requires_one_global_exact_source_action(
    tmp_path: Path,
) -> None:
    source = _finding("TF-1", mechanism="first") + _finding(
        "TF-1", mechanism="second"
    )
    chunk = _finding("CC-1", source_ids=("TF-1",))
    final = _finding("INV-001", source_ids=("TF-1", "CC-1"))
    _write_pipeline(tmp_path, source, chunk_text=chunk, inventory_text=final)

    receipt = reconcile_inventory(tmp_path)

    assert receipt["denominator_count"] == 2
    assert receipt["summary"]["RETAINED"] == 0
    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 2
    assert all(
        row["reason_code"] == "MISSING_CHUNK_DISPOSITION"
        for row in receipt["candidates"]
    )


def test_backtick_in_backtick_fence_info_does_not_mask_live_heading(
    tmp_path: Path,
) -> None:
    source = "```bad`info\n" + _finding("TF-1")
    chunk = _finding("CC-1", source_ids=("TF-1",))
    final = _finding("INV-001", source_ids=("TF-1", "CC-1"))
    _write_pipeline(tmp_path, source, chunk_text=chunk, inventory_text=final)

    receipt = reconcile_inventory(tmp_path)

    assert receipt["denominator_count"] == 1
    assert receipt["summary"]["RETAINED"] == 1


def test_inline_child_provenance_prevents_hidden_refs_from_minting_linkage(
    tmp_path: Path,
) -> None:
    """The reviewed full-pipeline parent-pairing exploit stays non-authority."""

    def with_hidden_refs(finding: str, refs: str) -> str:
        return finding.replace(
            "**Verdict**: NEEDS_VERIFICATION\n",
            'Text <x a="`"> starts code `\n'
            f"**Source IDs**: {refs}\n"
            "**Decoy**: terminates Source IDs field\n"
            "`\n"
            "**Verdict**: NEEDS_VERIFICATION\n",
            1,
        )

    source = _finding("TF-1")
    chunk = with_hidden_refs(_finding("CC-1"), "TF-1")
    final = with_hidden_refs(_finding("INV-1"), "TF-1, CC-1")
    _write_pipeline(tmp_path, source, chunk_text=chunk, inventory_text=final)

    receipt = reconcile_inventory(tmp_path)

    assert receipt["denominator_count"] == 1
    assert receipt["summary"]["RETAINED"] == 0
    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 1
    assert receipt["candidates"][0]["target_inventory_id"] == ""
    assert receipt["candidates"][0]["reason_code"] == "MISSING_CHUNK_DISPOSITION"


@pytest.mark.parametrize("indent", ("    ", "\t"))
def test_indented_code_fields_cannot_satisfy_material_preservation(
    tmp_path: Path,
    indent: str,
) -> None:
    source = _finding("TF-1")
    chunk = _finding("CC-1", source_ids=("TF-1",))
    final = (
        "### Finding [INV-001]: Fixture\n"
        "**Severity**: Medium\n"
        "**Location**: src/Fixture.sol:L10\n"
        "**Description**: a different synthesized mechanism\n"
        "**Source IDs**: TF-1, CC-1\n"
        "\n"
        f"{indent}**Root Cause**: source mechanism\n"
        f"{indent}**Impact**: source material harm\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
    )
    _write_pipeline(tmp_path, source, chunk_text=chunk, inventory_text=final)

    row = reconcile_inventory(tmp_path)["candidates"][0]

    assert row["disposition"] == "HUMAN_REVIEW_DEBT"
    assert set(row["required_preservation_axes"]) == {"ROOT_CAUSE", "IMPACT"}


def test_operational_view_masks_only_commonmark_valid_fences_and_indented_code() -> None:
    live = "```bad`info\n### Finding [TF-1]: live\n"
    assert "Finding [TF-1]" in operational_markdown_view(live)

    valid = "~~~info`allowed\n### Finding [TF-2]: hidden\n~~~\n"
    assert "Finding [TF-2]" not in operational_markdown_view(valid)

    indented = "    ### Finding [TF-3]: hidden\n\t**Impact**: hidden\n"
    view = operational_markdown_view(indented)
    assert "Finding [TF-3]" not in view
    assert "Impact" not in view
    assert len(view) == len(indented)


def test_inline_code_child_spans_are_exact_ordered_and_duplicate_safe() -> None:
    source = "before `same` middle `same` after\n"

    view = operational_markdown_view(source)

    assert inline_code_source_spans(source) == [(7, 13), (21, 27)]
    assert view == "before        middle        after\n"
    assert len(view) == len(source)


@pytest.mark.parametrize(
    "prefix",
    ("- ### Finding [TF-1]: ", "> ### Finding [TF-1]: "),
)
def test_container_heading_inline_code_preserves_live_identity(prefix: str) -> None:
    source = prefix + "`masked title` live\n"

    view = operational_markdown_view(source)

    assert "Finding [TF-1]" in view
    assert "masked title" not in view
    assert view.endswith(" live\n")


def test_multiline_inline_code_span_preserves_container_newlines() -> None:
    source = "> before ``first\n> second`` after\n"

    view = operational_markdown_view(source)

    assert view.startswith("> before ")
    assert view.endswith(" after\n")
    assert "first" not in view and "second" not in view
    assert [char for char in view if char in "\r\n"] == [
        char for char in source if char in "\r\n"
    ]
    assert len(view) == len(source)


def test_table_cells_use_ordered_child_provenance_not_neighbor_backticks() -> None:
    source = (
        "| A | B | C |\n"
        "|---|---|---|\n"
        '| `same` | <x title="`html`"> `same` | text \\| `last` |\n'
    )

    view = operational_markdown_view(source)

    assert view.count("same") == 0
    assert "last" not in view
    assert '`html`' in view
    assert "text \\|" in view
    assert len(view) == len(source)


def test_link_destination_title_and_html_backticks_do_not_move_code_spans() -> None:
    source = (
        '<x title="`html`"> [`label`](<de`st> "`title`") and `real` tail\n'
    )

    view = operational_markdown_view(source)

    assert '`html`' in view
    assert 'de`st' in view
    assert '`title`' in view
    assert "label" not in view
    assert "real" not in view
    assert " tail" in view


def test_escaped_backticks_remain_live_while_real_code_is_masked() -> None:
    source = r"escaped \`not-code\` and `real`" + "\n"

    view = operational_markdown_view(source)

    assert r"\`not-code\`" in view
    assert "real" not in view
    assert len(view) == len(source)


def test_inline_code_mapping_preserves_exact_crlf_offsets() -> None:
    source = "before ``first\r\nsecond`` after\r\n"

    view = operational_markdown_view(source)

    assert inline_code_source_spans(source) == [(7, 24)]
    assert view.startswith("before ") and view.endswith(" after\r\n")
    assert "first" not in view and "second" not in view
    assert view.count("\r\n") == source.count("\r\n") == 2
    assert len(view) == len(source)


def test_ambiguous_inline_child_mapping_fails_closed() -> None:
    # The one-column parser emits one child, but the raw row has two equally
    # valid source occurrences. No first-match source span may be selected.
    source = "| A |\n|---|\n| `same` | `same` |\n"

    with pytest.raises(
        MarkdownParserContractError,
        match="inline child source provenance is ambiguous",
    ):
        operational_markdown_view(source)


def test_caller_cannot_redirect_genuine_child_span_into_html() -> None:
    source = '<x title="`html`"> abcd`code`\n'
    tokens = parse_authoritative(source)
    child = next(
        child
        for token in tokens
        for child in token.children or []
        if child.type == "code_inline"
    )
    assert child.meta["plamen_inline_source_span_v1"] == [23, 29]
    child.meta["plamen_inline_source_span_v1"] = [10, 16]

    with pytest.raises(TypeError, match="unexpected keyword argument 'tokens'"):
        operational_markdown_view(source, tokens=tokens)


def test_deep_copied_same_source_tokens_are_not_an_authority_capability() -> None:
    source = "before `original` after\n"
    tokens = copy.deepcopy(parse_authoritative(source))

    with pytest.raises(TypeError, match="unexpected keyword argument 'tokens'"):
        operational_markdown_view(source, tokens=tokens)


def test_unreviewed_parse_tokens_cannot_bypass_runtime_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = "before `original` after\n"
    tokens = parse_authoritative(source, check_version=False)
    monkeypatch.setattr(
        plamen_markdown, "runtime_markdown_it_version", lambda: "4.0.0"
    )

    with pytest.raises(TypeError, match="unexpected keyword argument 'tokens'"):
        operational_markdown_view(source, tokens=tokens)
    with pytest.raises(MarkdownParserContractError, match="not the reviewed"):
        operational_markdown_view(source)


def test_markdown_authority_apis_expose_no_raw_token_parameter() -> None:
    assert "tokens" not in inspect.signature(operational_markdown_view).parameters
    assert "tokens" not in inspect.signature(inline_code_source_spans).parameters
    assert "tokens" not in inspect.signature(plamen_markdown.mapped_headings).parameters


def test_ambiguous_inline_mapping_cannot_persist_reconciliation_authority(
    tmp_path: Path,
) -> None:
    source = (
        "| A |\n|---|\n| `same` | `same` |\n\n" + _finding("TF-1")
    )
    _write_pipeline(
        tmp_path,
        source,
        chunk_text=_finding("CC-1", source_ids=("TF-1",)),
        inventory_text=_finding("INV-001", source_ids=("TF-1", "CC-1")),
    )

    with pytest.raises(
        InventoryReconciliationError,
        match="source provenance is ambiguous",
    ):
        write_inventory_reconciliation(tmp_path)
    assert not (tmp_path / "inventory_reconciliation.json").exists()


def test_three_space_commonmark_heading_is_in_the_denominator(tmp_path: Path) -> None:
    source = "   " + _finding("TF-1")
    chunk = _finding("CC-1", source_ids=("TF-1",))
    final = _finding("INV-001", source_ids=("TF-1", "CC-1"))
    _write_pipeline(tmp_path, source, chunk_text=chunk, inventory_text=final)

    receipt = reconcile_inventory(tmp_path)

    assert receipt["denominator_count"] == 1
    assert receipt["summary"]["RETAINED"] == 1


def test_nested_list_finding_heading_remains_live(tmp_path: Path) -> None:
    source = "- " + _finding("TF-1").replace("\n", "\n  ").rstrip() + "\n"
    chunk = _finding("CC-1", source_ids=("TF-1",))
    final = _finding("INV-001", source_ids=("TF-1", "CC-1"))
    _write_pipeline(tmp_path, source, chunk_text=chunk, inventory_text=final)

    receipt = reconcile_inventory(tmp_path)

    assert receipt["denominator_count"] == 1
    assert receipt["candidates"][0]["source_finding_id"] == "TF-1"


def test_escaped_html_comment_opener_does_not_hide_live_heading(
    tmp_path: Path,
) -> None:
    source = "\\<!--\n" + _finding("TF-1") + "-->\n"
    chunk = _finding("CC-1", source_ids=("TF-1",))
    final = _finding("INV-001", source_ids=("TF-1", "CC-1"))
    _write_pipeline(tmp_path, source, chunk_text=chunk, inventory_text=final)

    receipt = reconcile_inventory(tmp_path)

    assert receipt["denominator_count"] == 1
    assert receipt["summary"]["RETAINED"] == 1


@pytest.mark.parametrize("container", ("comment", "pre"))
def test_fence_looking_lines_inside_html_blocks_do_not_reopen_markdown(
    container: str,
) -> None:
    body = "```markdown\n### Finding [TF-0]: hidden\n```\n"
    hidden = (
        f"<!--\n{body}-->\n"
        if container == "comment"
        else f"<pre>\n{body}</pre>\n"
    )
    source = hidden + "### Finding [TF-1]: live\n"

    view = operational_markdown_view(source)

    assert "Finding [TF-0]" not in view
    assert "Finding [TF-1]" in view
    assert len(view) == len(source)


def test_list_contained_fence_fields_cannot_satisfy_preservation(
    tmp_path: Path,
) -> None:
    source = _finding("TF-1")
    chunk = _finding("CC-1", source_ids=("TF-1",))
    final = (
        "### Finding [INV-001]: Fixture\n"
        "**Severity**: Medium\n"
        "**Location**: src/Fixture.sol:L10\n"
        "**Description**: a different synthesized mechanism\n"
        "**Source IDs**: TF-1, CC-1\n"
        "- ```markdown\n"
        "  **Root Cause**: source mechanism\n"
        "  **Impact**: source material harm\n"
        "  ```\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
    )
    _write_pipeline(tmp_path, source, chunk_text=chunk, inventory_text=final)

    row = reconcile_inventory(tmp_path)["candidates"][0]

    assert row["disposition"] == "HUMAN_REVIEW_DEBT"
    assert set(row["required_preservation_axes"]) == {"ROOT_CAUSE", "IMPACT"}


@pytest.mark.parametrize("newline", ("\n", "\r\n"))
def test_operational_offsets_and_reconciliation_are_newline_stable(
    tmp_path: Path,
    newline: str,
) -> None:
    source = "   " + _finding("TF-1")
    chunk = _finding("CC-1", source_ids=("TF-1",))
    final = _finding("INV-001", source_ids=("TF-1", "CC-1"))
    _write_pipeline_bytes(
        tmp_path,
        source,
        chunk_text=chunk,
        inventory_text=final,
        newline=newline,
    )

    receipt = write_inventory_reconciliation(tmp_path)

    assert receipt["denominator_count"] == 1
    assert receipt["summary"]["RETAINED"] == 1
    assert validate_inventory_reconciliation(tmp_path) == []


@pytest.mark.parametrize(
    "source_atom",
    (
        "analysis_other.md&#58;TF-1",
        r"analysis_evm_flow\.md:TF-1",
        "analysis_evm_flow.md:TF-1-extra",
    ),
)
def test_malformed_or_wrong_qualified_atom_never_falls_back_to_bare_id(
    tmp_path: Path,
    source_atom: str,
) -> None:
    source = _finding("TF-1")
    # A neighboring valid bare atom cannot launder a malformed/unpermitted
    # qualified atom in the same authority-bearing Source IDs field.
    chunk = _finding("CC-1", source_ids=(source_atom, "TF-1"))
    final = _finding("INV-001", source_ids=("CC-1",))
    _write_pipeline(tmp_path, source, chunk_text=chunk, inventory_text=final)

    receipt = write_inventory_reconciliation(tmp_path)

    assert receipt["summary"]["RETAINED"] == 0
    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 1
    assert receipt["candidates"][0]["reason_code"] == "MISSING_CHUNK_DISPOSITION"
    assert validate_inventory_reconciliation(tmp_path) == []


def test_qualified_basename_collision_is_rejected(tmp_path: Path) -> None:
    for directory, mechanism in (("one", "first"), ("two", "second")):
        source_dir = tmp_path / directory
        source_dir.mkdir()
        (source_dir / "analysis.md").write_text(
            _finding("TF-1", mechanism=mechanism), encoding="utf-8"
        )
    (tmp_path / "inventory_chunk_a.manifest.md").write_text(
        "# Manifest\n\n"
        "| File | Estimated signals |\n"
        "|------|-------------------|\n"
        "| one/analysis.md | 1 |\n"
        "| two/analysis.md | 1 |\n",
        encoding="utf-8",
    )
    (tmp_path / "findings_inventory_chunk_a.md").write_text(
        "# Inventory Chunk\n\n"
        + _finding("CC-1", source_ids=("analysis.md:TF-1",)),
        encoding="utf-8",
    )
    (tmp_path / "findings_inventory.md").write_text(
        "# Finding Inventory\n\n"
        + _finding("INV-001", source_ids=("TF-1", "CC-1")),
        encoding="utf-8",
    )

    receipt = reconcile_inventory(tmp_path)

    assert receipt["denominator_count"] == 2
    assert receipt["summary"]["RETAINED"] == 0
    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 2


@pytest.mark.parametrize(
    "qualified_path", ("one/analysis.md:TF-1", r"one\analysis.md:TF-1")
)
def test_full_relative_qualified_path_resolves_exactly_across_basename_collision(
    tmp_path: Path,
    qualified_path: str,
) -> None:
    for directory, mechanism in (("one", "first"), ("two", "second")):
        source_dir = tmp_path / directory
        source_dir.mkdir()
        (source_dir / "analysis.md").write_text(
            _finding("TF-1", mechanism=mechanism), encoding="utf-8"
        )
    (tmp_path / "inventory_chunk_a.manifest.md").write_text(
        "# Manifest\n\n"
        "| File | Estimated signals |\n"
        "|------|-------------------|\n"
        "| one/analysis.md | 1 |\n"
        "| two/analysis.md | 1 |\n",
        encoding="utf-8",
    )
    (tmp_path / "findings_inventory_chunk_a.md").write_text(
        "# Inventory Chunk\n\n"
        + _finding("CC-1", source_ids=(qualified_path,), mechanism="first"),
        encoding="utf-8",
    )
    (tmp_path / "findings_inventory.md").write_text(
        "# Finding Inventory\n\n"
        + _finding(
            "INV-001",
            source_ids=(qualified_path, "CC-1"),
            mechanism="first",
        ),
        encoding="utf-8",
    )

    receipt = reconcile_inventory(tmp_path)

    assert receipt["denominator_count"] == 2
    assert receipt["summary"]["RETAINED"] == 1
    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 1


def test_parser_contract_failure_cannot_persist_clean_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_pipeline(
        tmp_path,
        _finding("TF-1"),
        chunk_text=_finding("CC-1", source_ids=("TF-1",)),
        inventory_text=_finding("INV-001", source_ids=("TF-1", "CC-1")),
    )
    monkeypatch.setattr(
        plamen_markdown, "runtime_markdown_it_version", lambda: "99.0.0"
    )

    with pytest.raises(InventoryReconciliationError, match="reviewed Markdown grammar"):
        write_inventory_reconciliation(tmp_path)

    assert not (tmp_path / "inventory_reconciliation.json").exists()


def test_runtime_requirement_and_ci_lock_use_one_reviewed_parser_version() -> None:
    root = Path(__file__).resolve().parents[1]
    requirement = next(
        line for line in (root / "requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.startswith("markdown-it-py")
    )
    constraint = next(
        line
        for line in (root / "requirements-ci.constraints").read_text(
            encoding="utf-8"
        ).splitlines()
        if line.startswith("markdown-it-py")
    )
    lock = next(
        line for line in (root / "requirements-ci.lock").read_text(encoding="utf-8").splitlines()
        if line.startswith("markdown-it-py")
    )

    expected = f"markdown-it-py=={REVIEWED_MARKDOWN_IT_VERSION}"
    assert requirement.split()[0] == expected
    assert constraint == expected
    assert lock.rstrip(" \\") == expected


def test_unreviewed_runtime_fails_loudly_before_operational_authority(
    tmp_path: Path,
) -> None:
    runtime = runtime_markdown_it_version()
    if runtime == REVIEWED_MARKDOWN_IT_VERSION:
        assert "Finding [TF-1]" in operational_markdown_view(
            "### Finding [TF-1]: live\n"
        )
        return
    _write_pipeline(
        tmp_path,
        _finding("TF-1"),
        chunk_text=_finding("CC-1", source_ids=("TF-1",)),
        inventory_text=_finding("INV-001", source_ids=("TF-1", "CC-1")),
    )
    with pytest.raises(InventoryReconciliationError, match="not the reviewed"):
        write_inventory_reconciliation(tmp_path)
    assert not (tmp_path / "inventory_reconciliation.json").exists()
