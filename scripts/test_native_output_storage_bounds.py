"""Characterize returned-output limits separately from temporary storage."""

import os

import pytest

import owned_process_runner as O

pytestmark = pytest.mark.integration


def test_bounded_returned_tail_does_not_bound_captured_file(tmp_path):
    """Passing characterization is not acceptance of an unbounded spool."""
    path = tmp_path / "synthetic-stdout"
    payload = b"x" * 10000
    with path.open("w+b") as handle:
        handle.write(payload)
        text = O._bounded_text(handle, limit=1024, encoding="utf-8", errors="replace")
        assert "output truncated" in text
        assert text.endswith("x" * 1024)
        assert len(text.encode("utf-8")) < 1200
        assert os.fstat(handle.fileno()).st_size == len(payload)
    assert path.read_bytes() == payload
