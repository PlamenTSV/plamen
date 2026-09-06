"""Focused PhaseIO coverage for the dedicated SC R-EXT work unit."""
from __future__ import annotations

import pytest

from phase_io_contracts import resolve_phase_io_contract


_OUTPUT = "recon_external_dependency_research.md"
_OBLIGATIONS = "external_dependency_obligations.json"
_LIGHT_SHARDS = (
    "recon_build_static.md",
    "recon_inventory_surface.md",
)
_FULL_SHARDS = (
    "recon_build_static.md",
    "recon_design_context.md",
    "recon_inventory_surface.md",
    "recon_templates_patterns.md",
)


def _resolve(
    *,
    mode: str,
    work_unit_id: str = "dependency_research",
    exact_inputs: tuple[str, ...] = (),
    exact_outputs: tuple[str, ...] = (),
    pipeline: str = "sc",
    conditional_output_ids: tuple[str, ...] = (),
    condition_id: str = "",
    exact_writer: str | None = None,
):
    return resolve_phase_io_contract(
        pipeline=pipeline,
        mode=mode,
        ecosystem="evm",
        backend="backend-neutral",
        phase="recon",
        work_unit_id=work_unit_id,
        exact_inputs=exact_inputs,
        exact_outputs=exact_outputs,
        conditional_output_ids=conditional_output_ids,
        condition_id=condition_id,
        exact_writer=exact_writer,
    )


@pytest.mark.parametrize(
    ("mode", "expected_shards"),
    (
        ("light", _LIGHT_SHARDS),
        ("core", _FULL_SHARDS),
        ("thorough", _FULL_SHARDS),
    ),
)
@pytest.mark.parametrize(
    "work_unit_id",
    (
        "dependency_research",
        "dependency_research.attempt-0002",
        "dependency_research.attempt-9999",
    ),
)
def test_dependency_research_has_exact_mode_specific_contract(
    mode: str,
    expected_shards: tuple[str, ...],
    work_unit_id: str,
) -> None:
    contract = _resolve(mode=mode, work_unit_id=work_unit_id)

    assert contract.work_unit_id == work_unit_id
    assert contract.model_invoked is True
    assert contract.immutable_inputs == (
        f"scratchpad:{_OBLIGATIONS}",
    )
    assert contract.bounded_lookup_inputs == tuple(
        sorted(f"scratchpad:{path}" for path in expected_shards)
    )
    assert len(contract.outputs) == 1
    output = contract.outputs[0]
    assert output.identity == f"scratchpad:{_OUTPUT}"
    assert output.writer == "MODEL"
    assert output.artifact_class == "CONDITIONAL"
    assert output.condition_id == "external_dependency_obligations_present"
    assert output.minimum_gate == "DEPENDENCY_ROW_PARITY"


@pytest.mark.parametrize("mode", ("light", "core", "thorough"))
def test_dependency_research_accepts_only_its_explicit_registered_sets(
    mode: str,
) -> None:
    shards = _LIGHT_SHARDS if mode == "light" else _FULL_SHARDS
    exact_inputs = (_OBLIGATIONS, *shards)

    contract = _resolve(
        mode=mode,
        exact_inputs=tuple(reversed(exact_inputs)),
        exact_outputs=(_OUTPUT,),
        conditional_output_ids=(_OUTPUT,),
        condition_id="external_dependency_obligations_present",
    )
    assert len(contract.outputs) == 1

    with pytest.raises(ValueError, match="registered exact input denominator"):
        _resolve(mode=mode, exact_inputs=exact_inputs[:-1])
    with pytest.raises(ValueError, match="registered exact input denominator"):
        _resolve(mode=mode, exact_inputs=(*exact_inputs, "unregistered.md"))
    with pytest.raises(ValueError, match="registered exact output denominator"):
        _resolve(mode=mode, exact_outputs=("generic_fallback.md",))


@pytest.mark.parametrize(
    "work_unit_id",
    (
        "dependency_research.attempt-0000",
        "dependency_research.attempt-0001",
        "dependency_research.attempt-2",
        "dependency_research.attempt-10000",
        "dependency_research.attempt-abcd",
        "dependency_research.retry-0002",
        "dependency_research.extra",
    ),
)
def test_dependency_research_rejects_malformed_or_ungoverned_ids(
    work_unit_id: str,
) -> None:
    with pytest.raises(ValueError):
        _resolve(mode="core", work_unit_id=work_unit_id)


@pytest.mark.parametrize(
    ("pipeline", "mode"),
    (("l1", "core"), ("sc", "custom")),
)
def test_dependency_research_rejects_unregistered_pipeline_or_mode(
    pipeline: str,
    mode: str,
) -> None:
    with pytest.raises(ValueError, match="registered only for SC"):
        _resolve(mode=mode, pipeline=pipeline)


def test_dependency_research_rejects_conditional_authority_drift() -> None:
    with pytest.raises(ValueError, match="registered exact input denominator"):
        _resolve(
            mode="core",
            conditional_output_ids=("generic_fallback.md",),
        )
    with pytest.raises(ValueError, match="registered exact input denominator"):
        _resolve(
            mode="core",
            conditional_output_ids=(_OUTPUT, _OUTPUT),
        )
    with pytest.raises(ValueError, match="condition_id differs"):
        _resolve(mode="core", condition_id="generic_fallback")


@pytest.mark.parametrize(
    ("mode", "work_unit_id"),
    (
        ("light", "dependency_research"),
        ("core", "dependency_research"),
        ("thorough", "dependency_research.attempt-0002"),
    ),
)
def test_dependency_research_key_digest_and_owner_are_stable(
    mode: str,
    work_unit_id: str,
) -> None:
    first = _resolve(mode=mode, work_unit_id=work_unit_id)
    second = _resolve(mode=mode, work_unit_id=work_unit_id)

    expected_key = (
        f"sc/{mode}/evm/backend-neutral/recon/{work_unit_id}"
    )
    assert first.key == expected_key
    assert second.key == expected_key
    assert first.digest == second.digest
    assert len(first.digest) == 64
    assert all(output.owner_key == first.key for output in first.outputs)

    if work_unit_id != "dependency_research":
        initial = _resolve(mode=mode)
        assert initial.key != first.key
        assert initial.digest != first.digest


def test_dependency_research_enforces_model_writer_authority() -> None:
    contract = _resolve(mode="core", exact_writer="MODEL")
    assert {output.writer for output in contract.outputs} == {"MODEL"}

    with pytest.raises(ValueError, match="registered writer authority"):
        _resolve(mode="core", exact_writer="DRIVER")


@pytest.mark.parametrize("mode", ("light", "core", "thorough"))
def test_dependency_research_rejects_duplicate_denominators(mode: str) -> None:
    shards = _LIGHT_SHARDS if mode == "light" else _FULL_SHARDS
    inputs = (_OBLIGATIONS, *shards)

    with pytest.raises(ValueError, match="registered exact input denominator"):
        _resolve(mode=mode, exact_inputs=(*inputs, inputs[-1]))
    with pytest.raises(ValueError, match="registered exact output denominator"):
        _resolve(mode=mode, exact_outputs=(_OUTPUT, _OUTPUT))


@pytest.mark.parametrize(
    "malformed",
    (
        "recon\\build_static.md",
        "recon_build_static.md/../recon_build_static.md",
        "recon_build_static.md.",
        "RECON_BUILD_STATIC.md",
    ),
)
def test_dependency_research_rejects_malformed_or_aliased_input_paths(
    malformed: str,
) -> None:
    with pytest.raises(ValueError):
        _resolve(
            mode="light",
            exact_inputs=(
                _OBLIGATIONS,
                malformed,
                "recon_inventory_surface.md",
            ),
        )


def test_dependency_research_does_not_capture_generic_recon_workers() -> None:
    generic = resolve_phase_io_contract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="backend-neutral",
        phase="recon",
        work_unit_id="worker.r-ext",
        exact_outputs=("generic_r_ext_probe.md",),
    )
    dedicated = _resolve(mode="core")

    assert generic.work_unit_id == "worker.r-ext"
    assert generic.key.endswith("/recon/worker.r-ext")
    assert generic.key != dedicated.key
    assert generic.digest != dedicated.digest
    assert tuple(output.path for output in generic.outputs) == (
        "generic_r_ext_probe.md",
    )
    assert generic.outputs[0].artifact_class == "REQUIRED"
    assert (
        "scratchpad:external_dependency_obligations.json"
        not in generic.immutable_inputs
    )
