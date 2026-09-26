from __future__ import annotations

from pathlib import Path

import chain_grouping_assurance
import chain_grouping_authority
import inventory_reconciliation
import inventory_reemit_authority
import l1_composition_runtime
import l1_composition_queue_runtime
import poc_demotion_scope
import post_verify_candidate_delta
import precedent_finding_fact_provider
import report_mutation_transaction
import sc_semantic_dedup_noop
import security_obligation_authority
import semantic_dedup_transaction
import verify_queue_transaction


def _identity(path: Path) -> tuple[int, int, int, int]:
    row = path.stat()
    return row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns


def test_phase_projection_writers_do_not_replace_identical_bytes(
    tmp_path: Path,
) -> None:
    writers = (
        semantic_dedup_transaction._atomic_bytes,
        report_mutation_transaction._atomic_bytes,
        sc_semantic_dedup_noop._atomic_bytes,
        l1_composition_queue_runtime._atomic_bytes,
        precedent_finding_fact_provider._atomic_write,
        inventory_reconciliation._atomic_write,
        inventory_reemit_authority._atomic_write,
        l1_composition_runtime._atomic_write,
        chain_grouping_authority._atomic_write,
        chain_grouping_assurance._atomic_write,
        security_obligation_authority._atomic_write,
        poc_demotion_scope._atomic_write,
        post_verify_candidate_delta._atomic_write,
        verify_queue_transaction._atomic_write,
    )
    raw = b"content-addressed projection\n"
    for ordinal, writer in enumerate(writers):
        path = tmp_path / f"projection-{ordinal}.json"
        writer(path, raw)
        before = _identity(path)
        writer(path, raw)
        assert path.read_bytes() == raw
        assert _identity(path) == before
