"""Program Facts startup debt must retain its actual capture cause."""

from pathlib import Path


def test_program_facts_capture_error_cannot_emit_an_empty_drift_diagnostic() -> None:
    source = (
        Path(__file__).with_name("program_facts_driver_integration.py")
    ).read_text(encoding="utf-8")

    assert '(\",\".join(drift) or \"NONE\")' in source
    assert 'f"{type(exc).__name__}: {exc}"' in source
    assert '"; cause: "' in source
