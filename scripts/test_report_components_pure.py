"""Pure presentation tests; not capture authentication or full renderer proof."""
from pathlib import Path

import pytest

import plamen_mechanical as mechanical


def _inputs(**changes):
    return {
        "file_coverage_ledger": "",
        "subsystem_map": "",
        "findings_inventory": "",
        "contract_inventory": "",
        **changes,
    }


@pytest.mark.parametrize(("values", "expected"), (
    (_inputs(), ""),
    (_inputs(contract_inventory=(
        "# Inventory\r\n- `src/É.sol`\r\n- `src/Token.sol`\r\n"
        "## Out-of-Scope\r\n- `test/Mock.sol`\r\n"
    )), (
        "| Component | Source | Status |\n"
        "|-----------|--------|--------|\n"
        "| `É.sol` | `src/É.sol` | In scope |\n"
        "| `Token.sol` | `src/Token.sol` | In scope |"
    )),
    (_inputs(
        subsystem_map="## Rate Limiting (mempool)\n## Gossip Validation\n",
        findings_inventory=(
            "## Finding [H-1]: PRIVATE_TITLE\n"
            "**Severity**: High\n"
            "**Location**: mempool/rate_limiting.rs:L42\n"
        ),
    ), (
        "| Component | Covered (findings) | Coverage Source |\n"
        "|-----------|--------------------|-----------------|\n"
        "| `Rate Limiting (mempool)` | 1 | subsystem_map.md |\n"
        "| `Gossip Validation` | 0 | subsystem_map.md |"
    )),
    (_inputs(file_coverage_ledger=(
        "| File | Status |\n|---|---|\n"
        "| src/A.sol | COVERED |\n| src/B.sol | ACKNOWLEDGED |\n"
        "| src/C.sol | UNREAD |\n| src/D.sol | OTHER |\n"
    )), (
        "| Component | Files Catalogued | Covered | Acknowledged | Leftover |\n"
        "|-----------|------------------|---------|--------------|----------|\n"
        "| `src` | 4 | 1 | 1 | 1 |"
    )),
))
def test_legacy_components_golden_before_and_after_extraction(tmp_path, values, expected):
    # Execute this exact node on the unchanged implementation before applying
    # report-components-pure.patch, then again afterward. No new helper needed.
    for name, value in values.items():
        (tmp_path / f"{name}.md").write_bytes(value.encode("utf-8"))
    before = {
        path.name: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
        for path in tmp_path.iterdir()
    }
    assert mechanical._synthesize_components_audited(tmp_path) == expected
    assert {
        path.name: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
        for path in tmp_path.iterdir()
    } == before


def test_empty_components_and_explicit_input_types():
    derive = mechanical._synthesize_components_audited_from_text
    assert derive(**_inputs()) == ""
    for name in _inputs():
        with pytest.raises(TypeError, match="explicit source strings"):
            derive(**_inputs(**{name: None}))


def test_wrapper_never_probes_fallback_when_ledger_has_rows(tmp_path, monkeypatch):
    (tmp_path / "file_coverage_ledger.md").write_text(
        "| File | Status |\n|---|---|\n| src/A.sol | COVERED |\n",
        encoding="utf-8",
    )
    original = Path.exists
    fallback_names = {
        "subsystem_map.md", "findings_inventory.md", "contract_inventory.md",
    }

    def prohibit_fallback(path):
        if path.parent == tmp_path and path.name in fallback_names:
            raise AssertionError("lower-priority source was probed")
        return original(path)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "exists", prohibit_fallback)
        result = mechanical._synthesize_components_audited(tmp_path)
    assert result == (
        "| Component | Files Catalogued | Covered | Acknowledged | Leftover |\n"
        "|-----------|------------------|---------|--------------|----------|\n"
        "| `src` | 1 | 1 | 0 | 0 |"
    )


def test_wrapper_skips_findings_without_subsystem_headings(tmp_path, monkeypatch):
    (tmp_path / "subsystem_map.md").write_text("No headings\n", encoding="utf-8")
    (tmp_path / "contract_inventory.md").write_text("- `src/A.sol`\n", encoding="utf-8")
    original = Path.exists

    def prohibit_findings(path):
        if path == tmp_path / "findings_inventory.md":
            raise AssertionError("findings source probed without subsystem headings")
        return original(path)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "exists", prohibit_findings)
        result = mechanical._synthesize_components_audited(tmp_path)
    assert result == (
        "| Component | Source | Status |\n"
        "|-----------|--------|--------|\n"
        "| `A.sol` | `src/A.sol` | In scope |"
    )


def test_contract_inventory_scope_and_order_golden(monkeypatch):
    inputs = _inputs(contract_inventory=(
        "# Inventory\r\n## In Scope\r\n"
        "- `src/É.sol`\r\n- `src/Token.sol`\r\n- `src/É.sol`\r\n"
        "## Out-of-Scope\r\n- `test/Mock.sol`\r\n"
    ))

    def forbid(*args, **kwargs):
        raise AssertionError("pure component renderer performed filesystem I/O")

    with monkeypatch.context() as patch:
        for name in ("open", "read_text", "read_bytes", "exists", "stat", "is_file"):
            patch.setattr(Path, name, forbid)
        actual = mechanical._synthesize_components_audited_from_text(**inputs)
    assert actual == (
        "| Component | Source | Status |\n"
        "|-----------|--------|--------|\n"
        "| `É.sol` | `src/É.sol` | In scope |\n"
        "| `Token.sol` | `src/Token.sol` | In scope |"
    )


def test_subsystem_fallback_counts_findings_without_leaking_titles():
    actual = mechanical._synthesize_components_audited_from_text(**_inputs(
        file_coverage_ledger="# No usable rows\n",
        subsystem_map="## Rate Limiting (mempool)\n## Gossip Validation\n",
        findings_inventory=(
            "## Finding [H-1]: PRIVATE_TITLE\n"
            "**Severity**: High\n"
            "**Location**: mempool/rate_limiting.rs:L42\n"
        ),
        contract_inventory="- `fallback.sol`\n",
    ))
    assert actual == (
        "| Component | Covered (findings) | Coverage Source |\n"
        "|-----------|--------------------|-----------------|\n"
        "| `Rate Limiting (mempool)` | 1 | subsystem_map.md |\n"
        "| `Gossip Validation` | 0 | subsystem_map.md |"
    )
    assert "PRIVATE_TITLE" not in actual


def test_ledger_takes_precedence_and_preserves_status_counts():
    actual = mechanical._synthesize_components_audited_from_text(**_inputs(
        file_coverage_ledger=(
            "| File | Status |\n|---|---|\n"
            "| src/A.sol | COVERED |\n"
            "| src/B.sol | ACKNOWLEDGED |\n"
            "| src/C.sol | UNREAD |\n"
            "| src/D.sol | OTHER |\n"
        ),
        subsystem_map="## Should not appear\n",
        contract_inventory="- `fallback.sol`\n",
    ))
    assert "| 4 | 1 | 1 | 1 |" in actual
    assert "Should not appear" not in actual
    assert "fallback.sol" not in actual


@pytest.mark.parametrize("source_name", tuple(_inputs()))
def test_wrapper_matches_explicit_projection_for_stable_sources(tmp_path, source_name):
    # Adapter agreement only. Capture old-wrapper golden bytes BEFORE landing
    # the extraction for independent historical byte-parity evidence.
    values = _inputs(
        subsystem_map="## mempool\n",
        findings_inventory=(
            "## Finding [L-1]: Example\n"
            "**Location**: mempool/a.rs:L2\n"
        ),
        contract_inventory="- `src/Fallback.sol`\n",
    )
    values[source_name] = ""
    for name, value in values.items():
        (tmp_path / f"{name}.md").write_text(value, encoding="utf-8")
    assert mechanical._synthesize_components_audited(tmp_path) == (
        mechanical._synthesize_components_audited_from_text(**values)
    )
