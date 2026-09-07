"""Compile regression for every Python version in the supported CI matrix."""

from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "filename",
    ("plamen_driver.py", "plamen_mechanical.py"),
)
def test_supported_python_runtime_compiles_core_scripts(filename: str) -> None:
    path = Path(__file__).with_name(filename)
    compile(path.read_bytes(), str(path), "exec")
