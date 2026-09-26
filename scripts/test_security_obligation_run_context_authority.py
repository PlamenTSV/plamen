"""Focused tests for checkpoint-independent P1-C run context authority."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

import security_obligation_authority as A


RUN_ID = "12345678-1234-4234-9234-123456789abc"
SNAPSHOT = "a" * 64
SOURCE_SCOPE = "b" * 64


def _json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True) + "\n", encoding="utf-8"
    )


def _checkpoint(root: Path, *, report_completed: bool = False) -> None:
    _json(
        root / "_v2_checkpoint.json",
        {
            "completed": [
                "recon",
                *(("report_index",) if report_completed else ()),
            ],
            "degraded": [],
            "rate_limited_at": None,
            "run_id": RUN_ID,
            "config": {
                "pipeline": "sc",
                "language": "evm",
                "mode": "thorough",
            },
            "audit_snapshot": {
                "schema": "plamen.audit-input-snapshot.v1",
                "snapshot_digest": SNAPSHOT,
                "components": {
                    "source_scope": {"digest": SOURCE_SCOPE}
                },
            },
        },
    )


def _graph(root: Path, *, suffix: str = "") -> None:
    _json(
        root / "_mechanical_graph.json",
        {
            "schema_version": "plamen.mechanical-graph.v2",
            "source": "evm-source" + suffix,
            "functions": {},
            "var_refs": {},
            "state_symbols": [],
        },
    )


def _context() -> dict[str, str]:
    return A.build_security_obligation_run_context_authority(
        run_id=RUN_ID,
        source_snapshot_digest=SNAPSHOT,
        source_scope_digest=SOURCE_SCOPE,
        ecosystem="evm",
        mode="thorough",
        pipeline="sc",
    )


def test_run_context_codec_is_exact_and_self_digesting() -> None:
    context = _context()
    assert set(context) == {
        "schema_version",
        "run_id",
        "source_snapshot_digest",
        "source_scope_digest",
        "ecosystem",
        "mode",
        "pipeline",
        "authority_digest",
    }
    assert A.validate_security_obligation_run_context_authority(context) == context
    unsigned = dict(context)
    digest = unsigned.pop("authority_digest")
    assert digest == hashlib.sha256(
        json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest().upper()

    corruptions: list[dict[str, object]] = []
    extra = dict(context)
    extra["checkpoint"] = "_v2_checkpoint.json"
    corruptions.append(extra)
    missing = dict(context)
    missing.pop("source_scope_digest")
    corruptions.append(missing)
    uppercase = dict(context)
    uppercase["source_snapshot_digest"] = "A" * 64
    corruptions.append(uppercase)
    wrong_digest = dict(context)
    wrong_digest["authority_digest"] = "0" * 64
    corruptions.append(wrong_digest)
    for malformed in corruptions:
        with pytest.raises(ValueError, match="run context"):
            A.validate_security_obligation_run_context_authority(malformed)


def test_explicit_context_removes_only_checkpoint_and_survives_report_save(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    context = _context()
    legacy = A.security_obligation_input_artifacts(
        tmp_path, stage=A.POST_DEPTH_STAGE
    )
    explicit = A.security_obligation_input_artifacts(
        tmp_path,
        stage=A.POST_DEPTH_STAGE,
        run_context_authority=context,
    )
    assert "_v2_checkpoint.json" in legacy
    assert "_v2_checkpoint.json" not in explicit
    assert set(explicit) == set(legacy) - {"_v2_checkpoint.json"}

    written = A.write_security_obligation_authority(
        tmp_path,
        stage=A.POST_DEPTH_STAGE,
        run_context_authority=context,
    )
    frozen = {
        name: (tmp_path / name).read_bytes()
        for name in (A.FEATURE_FACT_FILE, A.AUTHORITY_FILE, A.PROJECTION_FILE)
    }
    _checkpoint(tmp_path, report_completed=True)
    assert A.validate_security_obligation_authority(
        tmp_path,
        stage=A.POST_DEPTH_STAGE,
        run_context_authority=context,
    ) == []
    assert {
        name: (tmp_path / name).read_bytes() for name in frozen
    } == frozen
    assert written["run_binding"] == {
        "run_id": RUN_ID,
        "source_snapshot_digest": SNAPSHOT,
        "source_scope_digest": SOURCE_SCOPE,
        "ecosystem": "evm",
        "mode": "thorough",
        "pipeline": "sc",
        "binding_digest": written["run_binding"]["binding_digest"],
    }

    _graph(tmp_path, suffix="-changed")
    issues = A.validate_security_obligation_authority(
        tmp_path,
        stage=A.POST_DEPTH_STAGE,
        run_context_authority=context,
    )
    assert any("current inputs" in issue for issue in issues)


def test_explicit_context_cannot_rehabilitate_conflicting_arguments(
    tmp_path: Path,
) -> None:
    _graph(tmp_path)
    context = _context()
    for kwargs in (
        {"run_id": "87654321-4321-4321-8321-cba987654321"},
        {"source_snapshot_digest": "c" * 64},
        {"ecosystem": "solana"},
        {"mode": "core"},
    ):
        with pytest.raises(ValueError, match="differ from run context"):
            A.derive_security_obligation_authority(
                tmp_path,
                stage=A.POST_DEPTH_STAGE,
                run_context_authority=context,
                **kwargs,
            )


def test_explicit_context_is_required_as_a_whole_not_adopted_from_checkpoint(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _graph(tmp_path)
    context = _context()
    malformed = copy.deepcopy(context)
    malformed.pop("authority_digest")
    with pytest.raises(ValueError, match="run context"):
        A.security_obligation_input_artifacts(
            tmp_path,
            stage=A.POST_DEPTH_STAGE,
            run_context_authority=malformed,
        )
    assert "_v2_checkpoint.json" in A.security_obligation_input_artifacts(
        tmp_path, stage=A.POST_DEPTH_STAGE
    )
