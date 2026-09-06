from pathlib import Path

import pytest

from plamen_parsers import (
    _write_queue_work_item_records_manifest,
    render_verification_queue_work_item_markdown,
)
from queue_work_items import QueueWorkItem


def _item() -> QueueWorkItem:
    return QueueWorkItem.from_legacy_row({
        "finding id": "PARITY-1",
        "severity": "Medium",
        "title": "Canonical production projection",
        "bug class": "STATE_TRANSITION",
        "preferred tag": "CODE-TRACE",
        "location": "src/Parity.sol:10-12",
        "primary artifact": "findings_inventory.md",
        "poc class": "structural",
    })


@pytest.mark.parametrize("items", [(), (_item(),)])
def test_production_markdown_bytes_equal_canonical_renderer(
    tmp_path: Path,
    items: tuple[QueueWorkItem, ...],
) -> None:
    path = tmp_path / "verification_queue.md"

    _write_queue_work_item_records_manifest(path, items)

    expected = render_verification_queue_work_item_markdown(items).encode("utf-8")
    assert path.read_bytes() == expected
    assert b"\r\n" not in expected


def test_existing_platform_newlines_are_rewritten_canonically(
    tmp_path: Path,
) -> None:
    path = tmp_path / "verification_queue.md"
    expected = render_verification_queue_work_item_markdown(()).encode("utf-8")
    path.write_bytes(expected.replace(b"\n", b"\r\n"))

    _write_queue_work_item_records_manifest(path, ())

    assert path.read_bytes() == expected
