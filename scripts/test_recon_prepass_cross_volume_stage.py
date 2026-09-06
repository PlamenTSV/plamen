"""Regression coverage for Windows cross-volume recon publication."""

from __future__ import annotations

import inspect
from pathlib import Path

import recon_prepass as RP


def test_recon_prepass_stage_is_created_on_destination_volume() -> None:
    source = inspect.getsource(RP.run_recon_prepass)

    assert 'prefix=".plamen-recon-prepass-"' in source
    assert "dir=scratchpad" in source
    assert 'mkdtemp(prefix="plamen-recon-prepass-")' not in source


def test_every_prepass_publication_replace_uses_the_bound_stage(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "run-scratchpad"
    scratchpad.mkdir()
    stage = Path(
        RP.tempfile.mkdtemp(
            prefix=".plamen-recon-prepass-test-",
            dir=scratchpad,
        )
    )
    try:
        assert stage.parent.resolve() == scratchpad.resolve()
        assert stage.stat().st_dev == scratchpad.stat().st_dev
    finally:
        RP.shutil.rmtree(stage, ignore_errors=False)
