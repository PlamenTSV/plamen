"""Installed driver tool resolution stays inside the managed runtime."""

from __future__ import annotations

import inspect
from pathlib import Path

import plamen_driver as D


def test_installed_driver_pins_runtime_scripts_before_local_imports() -> None:
    source = Path(D.__file__).read_text(encoding="utf-8")
    pin = source.index("\n_pin_installed_runtime_scripts_path()\n")
    local_import = source.index("from plamen_types import *")

    assert pin < local_import
    body = inspect.getsource(D._pin_installed_runtime_scripts_path)
    assert "Path(sys.prefix)" in body
    assert 'os.environ["PATH"]' in body
