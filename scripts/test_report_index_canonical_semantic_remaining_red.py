"""Remaining RED semantic contracts for canonical report-index publication.

These fixtures are intentionally test-only.  They pin four independently
observable guarantees that the canonical report transaction still needs:

* every non-empty L1 Master row has a canonical internal finding identity;
* L1 report records cannot disagree with the Master row's severity;
* malformed non-empty verification input is not equivalent to an empty audit;
* an exact empty audit has one canonical zero-row representation for SC and L1.

The assertions target semantic outcomes rather than private implementation
steps, leaving the production repair free to use the cleanest architecture.
"""
from __future__ import annotations

import importlib
import ast
import json
from pathlib import Path
import re

import pytest

import plamen_driver as D
import report_index_canonical_validator as C
from report_index_canonical_validator import (
    validate_l1_report_records_denominator,
    validate_report_index_canonical_bundle,
)
import test_report_index_canonical_successor_a0_blocking as BASE


def test_canonical_receipt_requires_and_forwards_expected_severities() -> None:
    """No receipt path may silently fall back to off-live R10 replay."""

    source = Path(D.__file__).read_text(encoding="utf-8", errors="strict")
    tree = ast.parse(source)
    function = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and node.name == "_validate_report_index_canonical_receipt"
    )
    keyword_defaults = dict(zip(
        (argument.arg for argument in function.args.kwonlyargs),
        function.args.kw_defaults,
    ))
    assert "expected_severities" in keyword_defaults
    assert keyword_defaults["expected_severities"] is None, (
        "expected_severities must be a required keyword-only argument"
    )

    receipt_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_validate_report_index_canonical_receipt"
    ]
    assert receipt_calls
    assert all(
        any(
            keyword.arg == "expected_severities"
            and isinstance(keyword.value, ast.Name)
            and keyword.value.id == "expected_severities"
            for keyword in call.keywords
        )
        for call in receipt_calls
    )

    forwarded = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "validate_report_index_canonical_bundle"
    ]
    assert len(forwarded) == 1
    assert any(
        keyword.arg == "expected_severities"
        and isinstance(keyword.value, ast.Name)
        and keyword.value.id == "expected_severities"
        for keyword in forwarded[0].keywords
    )


def _master_index(
    *,
    internal_id: str,
    severity: str = "Medium",
    title: str = "Canonical finding",
) -> str:
    return "\n".join(
        [
            "# Report Index",
            "",
            "## Summary Counts",
            "",
            "| Severity | Count |",
            "|---|---|",
            "| Critical | 0 |",
            "| High | 0 |",
            f"| Medium | {1 if severity == 'Medium' else 0} |",
            f"| Low | {1 if severity == 'Low' else 0} |",
            "| Informational | 0 |",
            "| Total | 1 |",
            "",
            "## Master Finding Index",
            "",
            (
                "| Report ID | Title | Severity | Location | Verification | "
                "Trust Adj. | Internal Hypothesis ID |"
            ),
            "|---|---|---|---|---|---|---|",
            (
                f"| M-01 | {title} | {severity} | src/A.rs:1 | VERIFIED | "
                f"- | {internal_id} |"
            ),
            "",
            "## Excluded Findings",
            "",
            "| Source ID | Reason |",
            "|---|---|",
            "",
        ]
    )


def _write_l1_bundle(
    root: Path,
    *,
    internal_id: str,
    active: list[dict[str, str]],
    severity: str = "Medium",
) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "report_index.md").write_text(
        _master_index(internal_id=internal_id, severity=severity),
        encoding="utf-8",
    )
    (root / "report_records.json").write_text(
        json.dumps(
            {"active": active, "excluded": []},
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    ("internal_id", "active"),
    [
        ("-", []),
        ("NOT_A_VALID_ID", []),
        (
            "THIS-IS-NOT-A-FINDING",
            [
                {
                    "report_id": "M-01",
                    "finding_id": "THIS-IS-NOT-A-FINDING",
                    "severity": "Medium",
                }
            ],
        ),
    ],
    ids=["missing", "underscore-noncanonical", "broad-hyphen-false-positive"],
)
def test_l1_master_rows_require_canonical_internal_finding_ids(
    tmp_path: Path,
    internal_id: str,
    active: list[dict[str, str]],
) -> None:
    """A report row cannot become denominator-free via an invalid identity."""

    _write_l1_bundle(tmp_path, internal_id=internal_id, active=active)

    issues = validate_l1_report_records_denominator(tmp_path)

    assert issues, (
        "non-empty L1 Master row with a missing/noncanonical internal finding "
        f"identity was accepted: {internal_id!r}"
    )
    assert any(
        token in " ".join(issues).casefold()
        for token in ("internal", "finding", "identity", "canonical", "invalid")
    )


def test_l1_report_records_severity_must_equal_master_severity(
    tmp_path: Path,
) -> None:
    """The routing record must not silently override the canonical severity."""

    _write_l1_bundle(
        tmp_path,
        internal_id="H-1",
        severity="Medium",
        active=[
            {
                "report_id": "M-01",
                "finding_id": "H-1",
                "severity": "Low",
                "title": "Different routing title",
                "location": "src/B.rs:2",
            }
        ],
    )

    issues = validate_l1_report_records_denominator(tmp_path)

    assert issues, (
        "L1 report_records severity disagreed with the Master row but passed "
        "canonical denominator validation"
    )
    assert "severity" in " ".join(issues).casefold()


def test_nonempty_malformed_sc_queue_is_not_a_valid_empty_denominator(
    tmp_path: Path,
) -> None:
    """Non-empty unparseable queue bytes must fail closed, not become zero."""

    root = tmp_path / ".scratchpad"
    root.mkdir(parents=True)
    (root / "verification_queue.md").write_text(
        "# Verification Queue\n\n"
        "THIS IS MALFORMED NONEMPTY QUEUE CONTENT\n",
        encoding="utf-8",
    )
    (root / "report_index.md").write_text(
        "\n".join(
            [
                "# Report Index",
                "",
                "## Summary Counts",
                "",
                "| Severity | Count |",
                "|---|---|",
                "| Total | 0 |",
                "",
                "## Master Finding Index",
                "",
                (
                    "| Report ID | Title | Severity | Verification | "
                    "Trust Adj. | Internal Hypothesis ID |"
                ),
                "|---|---|---|---|---|---|",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (root / "report_coverage.md").write_text(
        "# Report Coverage\n\nNo candidates.\n",
        encoding="utf-8",
    )
    D._ensure_empty_report_index_canonical_outputs(
        root,
        reset_optional=True,
    )
    assert D._project_report_index_status_with_debt(root) == []

    issues = validate_report_index_canonical_bundle(
        root,
        pipeline="sc",
        run_id="malformed-nonempty-queue",
    )

    assert issues, (
        "non-empty malformed verification_queue.md was interpreted as an "
        "exact empty candidate denominator"
    )
    assert any(
        token in " ".join(issues).casefold()
        for token in ("queue", "denominator", "parse", "schema", "malformed")
    )


def test_independent_canonical_validation_requires_live_severity_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The off-live validator consumes, but never re-derives, R10 authority."""

    root = tmp_path / ".scratchpad"
    root.mkdir(parents=True)
    runtime_validators = importlib.import_module("plamen_validators")
    (root / "report_index.md").write_text(
        _master_index(internal_id="H-1", severity="Medium"),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        C, "validate_report_candidate_denominator", lambda _root: (1, [])
    )
    monkeypatch.setattr(
        runtime_validators,
        "_validate_report_verification_denominator",
        lambda _root: [],
    )
    monkeypatch.setattr(
        runtime_validators,
        "_validate_report_index_status_authority",
        lambda _root: [],
    )
    monkeypatch.setattr(
        runtime_validators,
        "_report_index_status_projection_debt",
        lambda _root: [],
    )
    monkeypatch.setattr(
        runtime_validators,
        "_validate_report_index_triage_safety",
        lambda _root: [],
    )
    monkeypatch.setattr(
        runtime_validators,
        "_report_index_dropped_ids",
        lambda _root, run_id: [],
    )

    def forbid_stage_r10_replay(*_args, **_kwargs):
        raise AssertionError("off-live R10 replay is forbidden")

    monkeypatch.setattr(
        runtime_validators,
        "_expected_report_index_severities",
        forbid_stage_r10_replay,
    )

    assert validate_report_index_canonical_bundle(
        root,
        pipeline="sc",
        run_id="canonical-live-map",
        expected_severities={"H-1": "Medium"},
    ) == []
    mismatch = validate_report_index_canonical_bundle(
        root,
        pipeline="sc",
        run_id="canonical-live-map",
        expected_severities={"H-1": "High"},
    )
    assert mismatch
    assert "severity" in " ".join(mismatch).casefold()
    absent = validate_report_index_canonical_bundle(
        root,
        pipeline="sc",
        run_id="canonical-live-map",
    )
    assert absent
    assert "off-live r10 replay is forbidden" in " ".join(absent).casefold()


def _prepare_empty_predecessor(
    tmp_path: Path,
    *,
    pipeline: str,
) -> tuple[dict, Path]:
    config = BASE._config(tmp_path, pipeline=pipeline)
    root = Path(config["scratchpad"])
    raw_index = b"# Report Index\n\nNo reportable findings.\n"
    raw_coverage = b"# Report Coverage\n\nNo reportable findings.\n"
    if pipeline == "sc":
        BASE._prepare_model_attempt(config, raw_index)
        (root / "report_coverage.md").write_bytes(raw_coverage)
        _contract, issues = D._record_report_index_model_preimage(
            BASE._phase(pipeline=pipeline),
            root,
            config,
        )
        assert issues == []
    else:
        for name, payload in {
            "verification_queue.md": b"# Verification Queue\n",
            "finding_mapping.md": b"# Finding Mapping\n",
            "dedup_decisions.md": b"# Dedup Decisions\n",
        }.items():
            (root / name).write_bytes(payload)
        execute, issues = D._arm_report_index_mechanical_artifacts(root, config)
        assert execute and issues == []
        (root / "report_index.md").write_bytes(raw_index)
        (root / "report_coverage.md").write_bytes(raw_coverage)
        (root / "report_records.json").write_text(
            '{"active":[],"excluded":[]}\n',
            encoding="utf-8",
        )
        assert D._record_report_index_mechanical_artifacts(root, config) == []
    return config, root


@pytest.mark.parametrize("pipeline", ["sc", "l1"])
def test_exact_empty_audit_publishes_canonical_zero_row_envelope(
    tmp_path: Path,
    pipeline: str,
) -> None:
    """SC and L1 share one clean, explicit representation of exact emptiness."""

    config, root = _prepare_empty_predecessor(
        tmp_path,
        pipeline=pipeline,
    )

    issues = D._run_report_index_canonicalization_transaction(
        BASE._phase(pipeline=pipeline),
        root,
        config,
    )

    assert issues == []
    assert not list(root.rglob("report_index.degraded"))
    text = (root / "report_index.md").read_text(encoding="utf-8")
    assert re.search(
        r"^##\s+Master\s+Finding\s+Index\b",
        text,
        flags=re.IGNORECASE | re.MULTILINE,
    )
    assert re.search(
        r"^\|[^\n]*Report ID[^\n]*Internal (?:Hypothesis|Finding)",
        text,
        flags=re.IGNORECASE | re.MULTILINE,
    )
    assert not re.search(
        r"^\|\s*[CHMLI]-\d+\s*\|",
        text,
        flags=re.IGNORECASE | re.MULTILINE,
    )
    assert re.search(
        r"^\|\s*Total\s*\|\s*0\s*\|",
        text,
        flags=re.IGNORECASE | re.MULTILINE,
    )
    assert (root / "report_index_canonicalization_receipt.json").is_file()
    if pipeline == "l1":
        records = json.loads(
            (root / "report_records.json").read_text(encoding="utf-8")
        )
        assert records["active"] == []
        assert records["excluded"] == []
