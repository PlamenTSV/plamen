"""Specialized MODEL proposals commit once before their successors."""
from pathlib import Path


def test_exploration_generic_parent_commit_does_not_rerecord_model() -> None:
    source = (Path(__file__).with_name("plamen_driver.py")).read_text(
        encoding="utf-8"
    )
    dedicated = source.index("# --- exploration_skeptic (Phase 4b.6) ---")
    clear = source.index("_run_exploration_clear_lifecycle(", dedicated)
    first_record = source.index("_record_typed_model_phase_artifacts(", dedicated)
    assert first_record < clear

    generic = source.index("_generic_model_io_issues = (", clear)
    generic_end = source.index("for _model_io_issue in", generic)
    block = source[generic:generic_end]
    assert 'phase.name == "exploration_skeptic"' in block
    assert block.index('phase.name == "exploration_skeptic"') < block.index(
        "else _record_typed_model_phase_artifacts("
    )


def test_enumgap_generic_parent_commit_does_not_rerecord_model() -> None:
    source = (Path(__file__).with_name("plamen_driver.py")).read_text(
        encoding="utf-8"
    )
    dedicated = source.index("# --- enumgap_exploration (Phase 4b.7) ---")
    first_record = source.index("_record_typed_model_phase_artifacts(", dedicated)
    reconcile = source.index("_reconcile_enumgap_dispositions(", first_record)
    promote = source.index("_promote_enumgap_exploration_transaction(", reconcile)
    assert first_record < reconcile < promote

    generic = source.index("_generic_model_io_issues = (", promote)
    generic_end = source.index("for _model_io_issue in", generic)
    block = source[generic:generic_end]
    exclusion = 'phase.name == "enumgap_exploration"'
    assert exclusion in block
    assert block.index(exclusion) < block.index(
        "else _record_typed_model_phase_artifacts("
    )
