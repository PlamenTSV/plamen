"""P0-I typed hot-function/axis population authority.

These fixtures deliberately distinguish an exact empty denominator from a
provider failure and ensure prose-only coverage hints cannot close work.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

import coverage_shortfalls as CS
import enumeration_gate as E
from enumeration_type_ir import (
    FUNCTION_SIGNATURE_SCHEMA,
    build_function_signature_fact,
)
from state_symbol_authority import GRAPH_SCHEMA


def _project(tmp_path: Path) -> tuple[Path, Path]:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    source = project / "contracts" / "Unit.sol"
    source.parent.mkdir(parents=True)
    source.write_text(
        "contract Unit {\n"
        "  function quiet(uint256 x) external pure returns (uint256) {\n"
        "    return x;\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    return project, scratchpad


def _write_graph(
    scratchpad: Path,
    functions: dict[str, object],
    *,
    var_refs: dict | None = None,
    source: str = "fixture-graph-v1",
) -> None:
    project = scratchpad.parent
    signatures: dict[str, dict] = {}
    normalized_functions: dict[str, object] = {}
    for identity, raw in functions.items():
        if not isinstance(raw, dict):
            normalized_functions[identity] = raw
            continue
        row = dict(raw)
        locus = str(row.get("loc") or "")
        match = re.fullmatch(
            r"(?P<path>.+\.(?:sol|vy|rs|go|move|daml))"
            r"(?::[A-Za-z_]\w*)?:[Ll]?(?P<line>[0-9]+)",
            locus,
            re.IGNORECASE,
        )
        source_path = (
            match.group("path").replace("\\", "/") if match is not None else ""
        )
        source_line = int(match.group("line")) if match is not None else 0
        try:
            source_text = (project / source_path).read_text(
                encoding="utf-8", errors="strict"
            )
            source_sha = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
        except (OSError, UnicodeError):
            source_sha = ""
        fact = build_function_signature_fact(
            ecosystem="sol",
            provider="slither",
            function_identity=identity,
            bare_name=str(row.get("bare") or identity),
            provider_symbol=identity,
            raw_signature=f"function {row.get('bare') or identity}()",
            source_path=source_path,
            source_line=source_line,
            source_sha256=source_sha,
            kind="function",
            authority="COMPILER_PROVIDER",
        )
        row["signature_fact"] = fact
        normalized_functions[identity] = row
        signatures[identity] = fact
    (scratchpad / "_mechanical_graph.json").write_text(
        json.dumps(
            {
                "schema_version": GRAPH_SCHEMA,
                "function_signature_schema": FUNCTION_SIGNATURE_SCHEMA,
                "source": source,
                "state_symbols": [],
                "var_refs": var_refs or {},
                "functions": normalized_functions,
                "function_signatures": signatures,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def _digest_without(payload: dict, field: str) -> str:
    unsigned = {key: value for key, value in payload.items() if key != field}
    return hashlib.sha256(
        json.dumps(
            unsigned,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def test_exact_zero_requires_a_current_successful_typed_provider(
    tmp_path: Path,
) -> None:
    _project_root, scratchpad = _project(tmp_path)
    _write_graph(
        scratchpad,
        {
            "Unit.quiet(uint256)": {
                "bare": "quiet",
                "loc": "contracts/Unit.sol:L2",
                "callers": [],
            }
        },
    )

    result = E.compute_axis_population(scratchpad, run_id="RUN-EXACT-ZERO")

    assert result["schema_version"] == E.AXIS_POPULATION_SCHEMA
    assert result["provider_version"] == E.AXIS_POPULATION_PROVIDER_VERSION
    assert result["run_id"] == "RUN-EXACT-ZERO"
    assert result["denominator_status"] == "EXACT"
    assert result["observed_hot_function_count"] == 0
    assert result["gap_count"] == 0
    assert result["exact_zero_proven"] is True
    assert result["debt"] == []
    assert result["population_digest"] == _digest_without(
        result, "population_digest"
    )


def test_provider_exception_is_unknown_and_never_clean_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project_root, scratchpad = _project(tmp_path)

    def fail(_scratchpad: Path) -> list[dict]:
        raise RuntimeError("provider exploded")

    monkeypatch.setattr(E, "compute_hot_function_set", fail)
    result = E.compute_axis_population(scratchpad, run_id="RUN-FAILED")

    assert result["denominator_status"] == "UNKNOWN"
    assert result["exact_zero_proven"] is False
    assert result["requires_execution"] is True
    assert any("provider exploded" in row for row in result["debt"])
    persisted = json.loads(
        (scratchpad / "_hot_function_axes.json").read_text(encoding="utf-8")
    )
    assert persisted == result


def test_missing_or_malformed_cap_authority_cannot_prove_empty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project_root, scratchpad = _project(tmp_path)
    _write_graph(
        scratchpad,
        {
            "Unit.quiet(uint256)": {
                "bare": "quiet",
                "loc": "contracts/Unit.sol:L2",
                "callers": [],
            }
        },
    )

    def no_receipt(_scratchpad: Path) -> list[dict]:
        (scratchpad / "_hot_function_cap_receipt.json").write_text(
            '{"schema_version":"wrong"}', encoding="utf-8"
        )
        return []

    monkeypatch.setattr(E, "compute_hot_function_set", no_receipt)
    result = E.compute_axis_population(scratchpad, run_id="RUN-BAD-CAP")

    assert result["denominator_status"] == "UNKNOWN"
    assert result["exact_zero_proven"] is False
    assert any("cap receipt" in row for row in result["debt"])


def test_unknown_shortfall_with_zero_rows_is_not_exact_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project_root, scratchpad = _project(tmp_path)
    _write_graph(
        scratchpad,
        {
            "Unit.quiet(uint256)": {
                "bare": "quiet",
                "loc": "contracts/Unit.sol:L2",
                "callers": [],
            }
        },
    )
    real = E.compute_hot_function_set

    def unknown_after_provider(root: Path) -> list[dict]:
        hot = real(root)
        CS.replace_producer_shortfalls(
            root,
            "enumeration.hot_function_set",
            [
                CS.unknown_shortfall(
                    producer="enumeration.hot_function_set",
                    scope="hotset-provider",
                    kind="PROVIDER_STATE_UNKNOWN",
                    detail="provider could not prove its source population",
                )
            ],
        )
        return hot

    monkeypatch.setattr(E, "compute_hot_function_set", unknown_after_provider)
    result = E.compute_axis_population(scratchpad, run_id="RUN-UNKNOWN-ZERO")

    assert result["observed_hot_function_count"] == 0
    assert result["denominator_status"] == "DEGRADED"
    assert result["exact_zero_proven"] is False
    assert result["requires_execution"] is True
    assert any("source population" in item for item in result["debt"])


def test_unregistered_markdown_is_hint_only_and_cannot_close_axis(
    tmp_path: Path,
) -> None:
    _project_root, scratchpad = _project(tmp_path)
    _write_graph(
        scratchpad,
        {
            "Unit.quiet(uint256)": {
                "bare": "quiet",
                "loc": "contracts/Unit.sol:L2",
                "callers": ["a", "b"],
            }
        },
    )
    (scratchpad / "depth_stale_findings.md").write_text(
        "### Finding [D-1]: stale prose\n"
        "**Location**: contracts/Unit.sol:L2\n"
        "**Description**: [BOUNDARY:x=0] [TRACE:path->return] looks safe\n"
        "**Impact**: none\n",
        encoding="utf-8",
    )

    result = E.compute_axis_population(scratchpad, run_id="RUN-NO-PROSE")

    assert result["denominator_status"] == "EXACT"
    row = result["matrix"][0]
    assert row["cells"]["boundary"] == "GAP"
    assert any(
        gap["function_identity"] == row["function_identity"]
        and gap["axis"] == "boundary"
        for gap in result["gaps"]
    )
    assert result["examined_authority"]["status"] == "ABSENT"
    assert result["examined_authority"]["hint_artifacts_consumed"] == []


def test_incomplete_graph_cannot_authorize_na(
    tmp_path: Path,
) -> None:
    _project_root, scratchpad = _project(tmp_path)
    _write_graph(
        scratchpad,
        {
            "Unit.quiet(uint256)": {
                "bare": "quiet",
                "loc": "contracts/Unit.sol:L2",
                "callers": ["a", "b"],
            },
            "malformed": "not-an-object",
        },
    )

    result = E.compute_axis_population(scratchpad, run_id="RUN-PARTIAL")

    assert result["denominator_status"] == "DEGRADED"
    row = result["matrix"][0]
    assert row["cells"]["theft"] == "GAP"
    assert row["cells"]["identity"] == "GAP"
    assert any("graph" in debt.casefold() for debt in result["debt"])


def test_overloads_and_same_locus_keep_distinct_provider_identities(
    tmp_path: Path,
) -> None:
    _project_root, scratchpad = _project(tmp_path)
    _write_graph(
        scratchpad,
        {
            "Unit.quiet(uint256)": {
                "bare": "quiet",
                "loc": "contracts/Unit.sol:L2",
                "callers": ["a", "b"],
            },
            "Unit.quiet(address)": {
                "bare": "quiet",
                "loc": "contracts/Unit.sol:L2",
                "callers": ["a", "b"],
            },
        },
    )

    result = E.compute_axis_population(scratchpad, run_id="RUN-OVERLOAD")

    identities = [row["function_identity"] for row in result["matrix"]]
    assert identities == sorted(
        {"Unit.quiet(uint256)", "Unit.quiet(address)"},
        key=str.casefold,
    )
    assert len(identities) == len(set(identities)) == 2
    gap_identities = {row["function_identity"] for row in result["gaps"]}
    assert gap_identities == set(identities)


def test_graphless_source_fallback_is_degraded_not_exact(
    tmp_path: Path,
) -> None:
    project_root, scratchpad = _project(tmp_path)
    (project_root / "contracts" / "Unit.sol").write_text(
        "contract Unit {\n"
        "  function moveValue(address payable to) external {\n"
        "    to.transfer(1);\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    result = E.compute_axis_population(scratchpad, run_id="RUN-FALLBACK")

    assert result["denominator_status"] == "DEGRADED"
    assert result["exact_zero_proven"] is False
    assert result["observed_hot_function_count"] >= 1
    assert result["requires_execution"] is True
    assert any("graph" in debt.casefold() for debt in result["debt"])


@pytest.mark.parametrize(
    "graph_locus",
    [
        "contracts with space/Unit.sol:L2",
        r"contracts with space\Unit.sol:L2",
    ],
)
def test_source_binding_normalizes_posix_and_windows_relative_loci(
    tmp_path: Path,
    graph_locus: str,
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    source = project / "contracts with space" / "Unit.sol"
    source.parent.mkdir(parents=True)
    source.write_text(
        "contract Unit {\n"
        "  function quiet() external view returns (uint256) { return 1; }\n"
        "}\n",
        encoding="utf-8",
    )
    _write_graph(
        scratchpad,
        {
            "Unit.quiet()": {
                "bare": "quiet",
                "loc": graph_locus,
                "callers": ["a", "b"],
            }
        },
    )

    result = E.compute_axis_population(scratchpad, run_id="RUN-PATH")

    assert result["denominator_status"] == "EXACT"
    assert result["matrix"][0]["source_relpath"] == (
        "contracts with space/Unit.sol"
    )
    assert result["matrix"][0]["source_locus"] == (
        "contracts with space/Unit.sol:L2"
    )
    assert len(result["matrix"][0]["source_sha256"]) == 64


def test_source_path_escape_is_debt_not_a_bound_locus(tmp_path: Path) -> None:
    _project_root, scratchpad = _project(tmp_path)
    _write_graph(
        scratchpad,
        {
            "Unit.quiet()": {
                "bare": "quiet",
                "loc": "../outside/Unit.sol:L2",
                "callers": ["a", "b"],
            }
        },
    )

    result = E.compute_axis_population(scratchpad, run_id="RUN-ESCAPE")

    assert result["denominator_status"] == "DEGRADED"
    assert result["exact_zero_proven"] is False
    assert result["matrix"][0]["source_sha256"] == ""
    assert any("escape" in item.casefold() for item in result["debt"])


def test_current_run_binding_changes_population_digest(tmp_path: Path) -> None:
    _project_root, scratchpad = _project(tmp_path)
    _write_graph(
        scratchpad,
        {
            "Unit.quiet(uint256)": {
                "bare": "quiet",
                "loc": "contracts/Unit.sol:L2",
                "callers": [],
            }
        },
    )

    first = E.compute_axis_population(scratchpad, run_id="RUN-A")
    second = E.compute_axis_population(scratchpad, run_id="RUN-B")

    assert first["run_id"] != second["run_id"]
    assert first["population_digest"] != second["population_digest"]
