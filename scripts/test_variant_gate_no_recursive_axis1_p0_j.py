"""P0-J: the variant pass owns only boundary and symmetry axes."""
from __future__ import annotations

from pathlib import Path

import enumeration_gate as E


def _candidate(key: str) -> dict[str, str]:
    return {
        "key": key,
        "source_id": "VARGAP",
        "title": key,
        "location": "src/File.sol:L1",
        "mechanism": "typed test candidate",
        "falsify": "bounded test",
    }


def test_variant_pass_never_invokes_axis1_and_preserves_axes_2_and_3(
    tmp_path: Path, monkeypatch,
):
    calls = {"obligations": 0, "coverage": 0}

    def forbidden_obligations(_scratchpad):
        calls["obligations"] += 1
        raise AssertionError("variant pass must not rebuild axis-1 obligations")

    def forbidden_coverage(_scratchpad):
        calls["coverage"] += 1
        raise AssertionError("variant pass must not emit axis-1 candidates")

    monkeypatch.setattr(E, "compute_enumeration_obligations", forbidden_obligations)
    monkeypatch.setattr(E, "validate_enumeration_coverage", forbidden_coverage)
    monkeypatch.setattr(
        E, "compute_boundary_input_candidates",
        lambda _sp: [_candidate("VARGAP-B:BASE-1:fn:zero")],
    )
    monkeypatch.setattr(
        E, "compute_symmetric_operation_candidates",
        lambda _sp: [_candidate("VARGAP-S:BASE-1:BASE-2")],
    )

    emitted_sources: list[str] = []

    def emit(_sp, candidates, _cap, *, source_id, producer):
        assert producer.startswith("enumeration.variant.")
        emitted_sources.append(source_id)
        return len(candidates)

    monkeypatch.setattr(E, "_emit_candidates", emit)
    result = E.compute_variant_gaps(tmp_path)

    assert calls == {"obligations": 0, "coverage": 0}
    assert result["axis1_emitted"] == 0
    assert result["axis2_emitted"] == 1
    assert result["axis3_emitted"] == 1
    assert result["emitted"] == 2
    assert emitted_sources == ["VARGAP", "VARGAP"]


def test_mechanical_candidate_in_inventory_cannot_become_variant_axis1_origin(
    tmp_path: Path, monkeypatch,
):
    (tmp_path / "findings_inventory.md").write_text(
        "### [ENUMGAP-001] generated candidate\n"
        "- **Source IDs**: ENUMGAP, NEEDS_VERIFICATION\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        E, "validate_enumeration_coverage",
        lambda _sp: (_ for _ in ()).throw(
            AssertionError("generated inventory candidates must not seed axis 1")
        ),
    )
    monkeypatch.setattr(
        E, "compute_enumeration_obligations",
        lambda _sp: (_ for _ in ()).throw(
            AssertionError("variant pass must not enumerate axis 1")
        ),
    )
    monkeypatch.setattr(E, "compute_boundary_input_candidates", lambda _sp: [])
    monkeypatch.setattr(E, "compute_symmetric_operation_candidates", lambda _sp: [])

    result = E.compute_variant_gaps(tmp_path)
    assert result["axis1_emitted"] == 0
    assert result["emitted"] == 0
