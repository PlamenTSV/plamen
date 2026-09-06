"""P0-AM L1 Bake must be a DRIVER transaction, never a model monolith."""
from __future__ import annotations

from pathlib import Path

import pytest

import plamen_driver as D
from artifact_ledger import read_artifact_ledger
from phase_io_contracts import resolve_phase_io_contract


def _config(root: Path, *, language: str = "go") -> dict:
    return {
        "pipeline": "l1",
        "mode": "thorough",
        "language": language,
        "cli_backend": "claude",
        "project_root": str(root),
        "scratchpad": str(root),
        "_run_id": "run-l1-bake",
    }


def test_bake_contract_is_driver_owned_and_model_free() -> None:
    contract = resolve_phase_io_contract(
        pipeline="l1",
        mode="thorough",
        ecosystem="go",
        backend="claude",
        phase="bake",
        work_unit_id="capability_status",
    )
    assert contract.model_invoked is False
    assert [row.identity for row in contract.outputs] == [
        "scratchpad:primitive_status.md"
    ]
    assert all(row.writer == "DRIVER" for row in contract.outputs)


@pytest.mark.parametrize(
    ("language", "available", "expected"),
    [
        (
            "go",
            {"go", "scip-go", "opengrep", "ast-grep"},
            {
                "SCIP_GO_AVAILABLE=true",
                "SCIP_RUST_AVAILABLE=false",
                "OPENGREP_AVAILABLE=true",
                "AST_GREP_AVAILABLE=true",
            },
        ),
        (
            "rust",
            {"rust-analyzer", "semgrep", "sg"},
            {
                "SCIP_GO_AVAILABLE=false",
                "SCIP_RUST_AVAILABLE=true",
                "OPENGREP_AVAILABLE=true",
                "AST_GREP_AVAILABLE=true",
            },
        ),
    ],
)
def test_bake_status_is_a_probe_only_cross_platform_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    language: str,
    available: set[str],
    expected: set[str],
) -> None:
    monkeypatch.setattr(
        D.shutil,
        "which",
        lambda name: str(tmp_path / name) if name in available else None,
    )
    # A capability probe must not invoke a subprocess or model.
    monkeypatch.setattr(
        D.subprocess,
        "Popen",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("Bake capability status invoked a subprocess")
        ),
    )
    config = _config(tmp_path, language=language)
    assert D._run_l1_bake_capability_transaction(tmp_path, config) == []

    status = (tmp_path / "primitive_status.md").read_text(encoding="utf-8")
    assert expected.issubset(set(status.splitlines()))
    assert "BAKE_EXECUTION=DRIVER_CAPABILITY_PROBE_ONLY" in status
    assert "SCIP_PREBAKE_COMPLETE=false" in status
    assert "GRAPH_PROVIDER_DEFERRED_TO_PREBREADTH=true" in status
    ledger = read_artifact_ledger(tmp_path)
    unit = next(
        row
        for key, row in ledger["work_units"].items()
        if key.endswith("/bake/capability_status")
    )
    assert unit["model_invoked"] is False
    assert unit["semantic_status"] == "ACTIVE"


@pytest.mark.parametrize("failpoint", ["after_arm", "after_status"])
def test_bake_status_transaction_recovers_idempotently(
    tmp_path: Path,
    failpoint: str,
) -> None:
    config = _config(tmp_path)
    config["_l1_bake_failpoint"] = failpoint
    issues = D._run_l1_bake_capability_transaction(tmp_path, config)
    assert any(failpoint in issue for issue in issues)

    config.pop("_l1_bake_failpoint")
    assert D._run_l1_bake_capability_transaction(tmp_path, config) == []
    first = (tmp_path / "primitive_status.md").read_bytes()
    assert D._run_l1_bake_capability_transaction(tmp_path, config) == []
    assert (tmp_path / "primitive_status.md").read_bytes() == first


def test_later_graph_probe_cannot_mutate_committed_bake_status(
    tmp_path: Path,
) -> None:
    original = b"SCIP_GO_REUSED=false\n"
    (tmp_path / "primitive_status.md").write_bytes(original)

    D._l1_update_primitive_status_flag(
        tmp_path, "SCIP_GO_REUSED", True
    )

    assert (tmp_path / "primitive_status.md").read_bytes() == original
    runtime = (
        tmp_path / "primitive_status_runtime.md"
    ).read_text(encoding="utf-8")
    assert "SCIP_GO_REUSED=true" in runtime
