"""Regression tests for recon retry/prepass dependency-parity ordering."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_driver as D  # noqa: E402


@pytest.fixture
def recon_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    project.mkdir()
    scratchpad.mkdir()
    config = {
        "_run_id": "recon-retry-parity-ordering",
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
    }
    phase = next(item for item in D.SC_PHASES if item.name == "recon")

    monkeypatch.setattr(D, "_detect_foreign_phase_writes", lambda *_a, **_k: [])
    monkeypatch.setattr(D, "_materialize_sc_slither_flat_files", lambda *_a: [])
    monkeypatch.setattr(D, "_validate_recon_coverage", lambda *_a, **_k: [])
    monkeypatch.setattr(
        D, "_validate_recon_content_structure", lambda *_a, **_k: ([], [])
    )
    monkeypatch.setattr(D, "_skill_manifest_reconciliation_issues", lambda *_a: [])
    monkeypatch.setattr(D, "_selected_skill_manifest_issues", lambda *_a: [])
    monkeypatch.setattr(D, "_validate_injectable_promotion", lambda *_a: [])
    monkeypatch.setattr(
        D, "_materialize_live_skill_selection_boundary", lambda *_a: []
    )
    monkeypatch.setattr(
        D, "_recon_finalization_authority_present", lambda *_a: False
    )
    return phase, config, scratchpad, project


def _run_recon_validators(
    phase, config: dict, scratchpad: Path, project: Path
) -> tuple[bool, list[str]]:
    return D._run_phase_validators(
        phase,
        config,
        scratchpad,
        list(D.SC_PHASES),
        0,
        D._snapshot_file_state(scratchpad, str(project)),
    )


def test_failed_pool_gate_preserves_authenticated_retry_predecessor(
    recon_context, monkeypatch: pytest.MonkeyPatch
):
    phase, config, scratchpad, project = recon_context
    target = scratchpad / "external_dependency_research.md"
    original = b"# Authenticated prepass dependency ledger\n"
    target.write_bytes(original)
    parity_calls: list[str] = []

    monkeypatch.setattr(
        D, "gate_passes", lambda *_a, **_k: (False, ["architecture.md missing"])
    )

    def would_mutate_retry_predecessor(*_args, **_kwargs):
        parity_calls.append("parity")
        target.write_bytes(b"driver-created post-baseline mutation\n")
        return {"researched": 0, "unresolved": 1}

    monkeypatch.setattr(
        D, "_ensure_recon_dependency_parity", would_mutate_retry_predecessor
    )
    monkeypatch.setattr(
        D,
        "_validated_recon_prepass_retry_baseline",
        lambda *_a, **_k: {
            "selected": (target.name,),
            "payloads": {target.name: original},
        },
    )
    monkeypatch.setattr(
        D, "semantic_input_prebind_producer_authority_issues", lambda *_a, **_k: []
    )

    passed, missing = _run_recon_validators(
        phase, config, scratchpad, project
    )

    assert passed is False
    assert "architecture.md missing" in missing
    assert parity_calls == []
    assert target.read_bytes() == original
    assert D._restore_recon_prepass_retry_baseline(scratchpad, config) == []


def test_successful_pool_path_establishes_dependency_parity(
    recon_context, monkeypatch: pytest.MonkeyPatch
):
    phase, config, scratchpad, project = recon_context
    parity_calls: list[tuple[Path, str]] = []
    monkeypatch.setattr(D, "gate_passes", lambda *_a, **_k: (True, []))
    monkeypatch.setattr(
        D,
        "_ensure_recon_dependency_parity",
        lambda root, project_root, _config: (
            parity_calls.append((Path(root), project_root))
            or {"researched": 2, "unresolved": 0}
        ),
    )

    passed, missing = _run_recon_validators(
        phase, config, scratchpad, project
    )

    assert (passed, missing) == (True, [])
    assert parity_calls == [(scratchpad, str(project))]


def test_late_recon_rejection_cannot_mutate_retry_baseline(
    recon_context, monkeypatch: pytest.MonkeyPatch
):
    phase, config, scratchpad, project = recon_context
    parity_calls: list[str] = []
    monkeypatch.setattr(D, "gate_passes", lambda *_a, **_k: (True, []))
    monkeypatch.setattr(
        D,
        "_validate_recon_content_structure",
        lambda *_a, **_k: (["late content rejection"], []),
    )
    monkeypatch.setattr(
        D,
        "_ensure_recon_dependency_parity",
        lambda *_a, **_k: parity_calls.append("parity") or {},
    )

    passed, missing = _run_recon_validators(
        phase, config, scratchpad, project
    )

    assert passed is False
    assert any("late content rejection" in item for item in missing)
    assert parity_calls == []


def test_real_post_baseline_byte_mutation_remains_fail_closed(
    recon_context, monkeypatch: pytest.MonkeyPatch
):
    _phase, config, scratchpad, _project = recon_context
    target = scratchpad / "external_dependency_research.md"
    original = b"# Authenticated prepass dependency ledger\n"
    target.write_bytes(original)
    monkeypatch.setattr(
        D,
        "_validated_recon_prepass_retry_baseline",
        lambda *_a, **_k: {
            "selected": (target.name,),
            "payloads": {target.name: original},
        },
    )
    monkeypatch.setattr(
        D, "semantic_input_prebind_producer_authority_issues", lambda *_a, **_k: []
    )
    target.write_bytes(b"outside mutation after baseline capture\n")

    issues = D._restore_recon_prepass_retry_baseline(scratchpad, config)

    assert issues == [
        "live recon prepass output changed after baseline capture: "
        "external_dependency_research.md"
    ]
