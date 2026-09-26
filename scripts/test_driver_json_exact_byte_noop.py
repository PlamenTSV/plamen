from __future__ import annotations

from pathlib import Path

import plamen_driver as driver


def test_driver_json_republication_preserves_exact_physical_identity(
    tmp_path: Path,
) -> None:
    path = tmp_path / "driver_projection.json"
    payload = {"schema_version": "test.v1", "value": [1, 2, 3]}

    driver._atomic_driver_json(path, payload)
    before = path.stat()
    raw = path.read_bytes()
    driver._atomic_driver_json(path, payload)
    after = path.stat()

    assert path.read_bytes() == raw
    assert (after.st_dev, after.st_ino, after.st_mtime_ns) == (
        before.st_dev,
        before.st_ino,
        before.st_mtime_ns,
    )
