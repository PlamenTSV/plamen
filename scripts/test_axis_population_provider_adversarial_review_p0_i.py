"""Independent adversarial RED fixtures for the P0-I population provider.

These tests describe authority claims which must not be accepted as EXACT.
They intentionally do not patch production code.
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


def _project(
    tmp_path: Path,
    *,
    source: str | None = None,
) -> tuple[Path, Path]:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    unit = project / "contracts" / "Unit.sol"
    unit.parent.mkdir(parents=True)
    unit.write_text(
        source
        or (
            "contract Unit {\n"
            "  function quiet(uint256 x) external pure returns (uint256) {\n"
            "    return x;\n"
            "  }\n"
            "}\n"
        ),
        encoding="utf-8",
    )
    return project, scratchpad


def _write_graph(
    scratchpad: Path,
    functions: dict[str, object],
    *,
    var_refs: dict | None = None,
) -> None:
    project = scratchpad.parent
    signatures: dict[str, dict] = {}
    normalized: dict[str, object] = {}
    for identity, raw in functions.items():
        if not isinstance(raw, dict):
            normalized[identity] = raw
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
            match.group("path").replace("\\", "/")
            if match is not None
            else ""
        )
        source_line = int(match.group("line")) if match is not None else 0
        try:
            source_text = (project / source_path).read_text(
                encoding="utf-8",
                errors="strict",
            )
            source_sha = hashlib.sha256(
                source_text.encode("utf-8")
            ).hexdigest()
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
        normalized[identity] = row
        signatures[identity] = fact
    (scratchpad / "_mechanical_graph.json").write_text(
        json.dumps(
            {
                "schema_version": GRAPH_SCHEMA,
                "function_signature_schema": FUNCTION_SIGNATURE_SCHEMA,
                "source": "adversarial-graph-v1",
                "state_symbols": [],
                "var_refs": var_refs or {},
                "functions": normalized,
                "function_signatures": signatures,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def _quiet(
    *,
    callers: tuple[str, ...] = (),
    locus: str = "contracts/Unit.sol:L2",
) -> dict[str, dict]:
    return {
        "Unit.quiet(uint256)": {
            "bare": "quiet",
            "loc": locus,
            "callers": list(callers),
        }
    }


def _digest(payload: dict) -> str:
    return E._axis_population_digest(payload)


def test_graph_subset_cannot_certify_exact_zero_over_production_source(
    tmp_path: Path,
) -> None:
    _project(
        tmp_path,
        source=(
            "contract Unit {\n"
            "  function quiet(uint256 x) external pure returns (uint256) {\n"
            "    return x;\n"
            "  }\n"
            "  function moveValue(address payable to) external {\n"
            "    to.transfer(1);\n"
            "  }\n"
            "}\n"
        ),
    )
    scratchpad = tmp_path / "project" / ".scratchpad"
    # The graph silently omits the source-visible value-moving function.
    _write_graph(scratchpad, _quiet())

    result = E.compute_axis_population(
        scratchpad,
        run_id="RUN-GRAPH-SUBSET",
    )

    assert result["denominator_status"] != "EXACT"
    assert result["exact_zero_proven"] is False
    assert result["requires_execution"] is True
    assert any(
        token in debt.casefold()
        for debt in result["debt"]
        for token in ("graph", "source", "population")
    )


def test_stale_cap_receipt_from_prior_run_cannot_authorize_current_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project(tmp_path)
    scratchpad = tmp_path / "project" / ".scratchpad"
    _write_graph(scratchpad, _quiet())

    first = E.compute_axis_population(scratchpad, run_id="RUN-OLD")
    assert first["exact_zero_proven"] is True
    old_cap = (scratchpad / "_hot_function_cap_receipt.json").read_bytes()

    # Simulate a provider path that returns the retained population without
    # replacing its durable receipt during a resumed/new run.
    monkeypatch.setattr(E, "compute_hot_function_set", lambda _root: [])
    second = E.compute_axis_population(scratchpad, run_id="RUN-NEW")

    assert (scratchpad / "_hot_function_cap_receipt.json").read_bytes() == old_cap
    assert second["denominator_status"] != "EXACT"
    assert second["exact_zero_proven"] is False
    assert any("run" in debt.casefold() for debt in second["debt"])


def test_graph_change_between_cap_derivation_and_population_read_is_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project(tmp_path)
    scratchpad = tmp_path / "project" / ".scratchpad"
    _write_graph(scratchpad, _quiet())
    real = E.compute_hot_function_set

    def mutate_graph_after_cap(root: Path) -> list[dict]:
        retained = real(root)
        _write_graph(root, _quiet(callers=("caller-a", "caller-b")))
        return retained

    monkeypatch.setattr(E, "compute_hot_function_set", mutate_graph_after_cap)
    result = E.compute_axis_population(
        scratchpad,
        run_id="RUN-GRAPH-DRIFT",
    )

    assert result["denominator_status"] != "EXACT"
    assert result["exact_zero_proven"] is False
    assert result["observed_hot_function_count"] >= 1
    assert any("graph" in debt.casefold() for debt in result["debt"])


def test_duplicate_key_cap_receipt_cannot_retain_exact_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project(tmp_path)
    scratchpad = tmp_path / "project" / ".scratchpad"
    _write_graph(scratchpad, _quiet())
    real = E.compute_hot_function_set

    def duplicate_cap_key(root: Path) -> list[dict]:
        retained = real(root)
        path = root / "_hot_function_cap_receipt.json"
        text = path.read_text(encoding="utf-8")
        text = text.replace(
            '"producer": "enumeration.hot_function_set",',
            '"producer": "untrusted-shadow",\n'
            '  "producer": "enumeration.hot_function_set",',
            1,
        )
        path.write_text(text, encoding="utf-8")
        return retained

    monkeypatch.setattr(E, "compute_hot_function_set", duplicate_cap_key)
    result = E.compute_axis_population(
        scratchpad,
        run_id="RUN-DUPLICATE-CAP",
    )

    assert result["denominator_status"] != "EXACT"
    assert result["exact_zero_proven"] is False
    assert any("duplicate" in debt.casefold() for debt in result["debt"])


def test_duplicate_shortfall_key_cannot_hide_unknown_population_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project(tmp_path)
    scratchpad = tmp_path / "project" / ".scratchpad"
    _write_graph(scratchpad, _quiet())
    real = E.compute_hot_function_set

    def hide_shortfall_with_duplicate_key(root: Path) -> list[dict]:
        retained = real(root)
        unknown = CS.unknown_shortfall(
            producer="enumeration.hot_function_set",
            scope="hotset-provider",
            kind="PROVIDER_STATE_UNKNOWN",
            detail="provider population is unknown",
        )
        path = root / "_coverage_shortfalls.json"
        path.write_text(
            '{"schema_version":1,"shortfalls":'
            + json.dumps([unknown])
            + ',"shortfalls":[]}',
            encoding="utf-8",
        )
        return retained

    monkeypatch.setattr(
        E,
        "compute_hot_function_set",
        hide_shortfall_with_duplicate_key,
    )
    result = E.compute_axis_population(
        scratchpad,
        run_id="RUN-DUPLICATE-SHORTFALL",
    )

    assert result["denominator_status"] != "EXACT"
    assert result["exact_zero_proven"] is False
    assert any("duplicate" in debt.casefold() for debt in result["debt"])


def test_fabricated_examined_sidecar_cannot_close_without_replayed_receipt(
    tmp_path: Path,
) -> None:
    _project(tmp_path)
    scratchpad = tmp_path / "project" / ".scratchpad"
    _write_graph(
        scratchpad,
        _quiet(callers=("caller-a", "caller-b")),
    )
    row = {
        "function_identity": "Unit.quiet(uint256)",
        "axis": "boundary",
        "application_receipt": "missing-axis-application-receipt.json",
        "application_row_id": "invented-row",
        "application_row_digest": "0" * 64,
    }
    unsigned = {
        "schema_version": E.AXIS_EXAMINED_AUTHORITY_SCHEMA,
        "run_id": "RUN-FORGED-EXAMINED",
        "row_count": 1,
        "rows": [row],
        "hint_artifacts_consumed": [],
    }
    authority = {
        **unsigned,
        "authority_digest": _digest(unsigned),
    }

    result = E.compute_axis_population(
        scratchpad,
        run_id="RUN-FORGED-EXAMINED",
        examined_authority=authority,
    )

    matrix_row = result["matrix"][0]
    assert matrix_row["cells"]["boundary"] == "GAP"
    assert matrix_row["cell_authority"]["boundary"] == "RECALL_SAFE_DEFAULT"
    assert result["denominator_status"] != "EXACT"
    assert any(
        token in debt.casefold()
        for debt in result["debt"]
        for token in ("receipt", "application", "evidence")
    )


def test_empty_run_identity_cannot_produce_exact_authority(tmp_path: Path) -> None:
    _project(tmp_path)
    scratchpad = tmp_path / "project" / ".scratchpad"
    _write_graph(scratchpad, _quiet())

    result = E.compute_axis_population(scratchpad, run_id="")

    assert result["denominator_status"] != "EXACT"
    assert result["exact_zero_proven"] is False
    assert result["requires_execution"] is True
    assert any("run" in debt.casefold() for debt in result["debt"])


def test_nonexistent_source_line_cannot_be_an_exact_bound_locus(
    tmp_path: Path,
) -> None:
    _project(tmp_path)
    scratchpad = tmp_path / "project" / ".scratchpad"
    _write_graph(
        scratchpad,
        _quiet(
            callers=("caller-a", "caller-b"),
            locus="contracts/Unit.sol:L9999",
        ),
    )

    result = E.compute_axis_population(
        scratchpad,
        run_id="RUN-BAD-LINE",
    )

    assert result["denominator_status"] != "EXACT"
    assert result["matrix"][0]["source_sha256"] == ""
    assert any("line" in debt.casefold() for debt in result["debt"])
