from __future__ import annotations

import json
from pathlib import Path

import pytest

from exploration_clear_lifecycle import (
    CANONICAL_PRIOR_ALIAS_NAME,
    ExplorationClearError,
    derive_canonical_prior_authority,
    load_canonical_prior_authority,
)


def _write_identity_map(root: Path) -> Path:
    path = root / "_canonical_finding_ids.json"
    path.write_text(
        json.dumps({
            "records": [
                {
                    "canonical_id": "CID-0000000000000001",
                    "artifact": "depth_a.md",
                    "local_id": "H-1",
                    "local_id_raw": "H-1",
                },
                {
                    "canonical_id": "CID-0000000000000002",
                    "artifact": "depth_b.md",
                    "local_id": "H-1",
                    "local_id_raw": "H-1",
                },
                {
                    "canonical_id": "CID-0000000000000003",
                    "artifact": "depth_c.md",
                    "local_id": "M-2",
                    "local_id_raw": "M-2",
                },
            ],
            "schema_version": "plamen.canonical_finding_ids.v1",
            "record_count": 3,
        }),
        encoding="utf-8",
    )
    return path


def test_exact_projection_keeps_qualified_aliases_and_excludes_ambiguous_short(
    tmp_path: Path,
) -> None:
    _write_identity_map(tmp_path)
    authority = derive_canonical_prior_authority(
        tmp_path / "_canonical_finding_ids.json"
    )
    (tmp_path / CANONICAL_PRIOR_ALIAS_NAME).write_text(
        json.dumps(authority.payload), encoding="utf-8"
    )

    aliases = load_canonical_prior_authority(tmp_path).aliases

    assert "H-1" not in aliases
    assert aliases["depth_a.md:H-1"] == "CID-0000000000000001"
    assert aliases["M-2"] == "CID-0000000000000003"
    assert aliases["CID-0000000000000001"] == "CID-0000000000000001"


def test_rehashed_extra_alias_has_no_semantic_authority(tmp_path: Path) -> None:
    _write_identity_map(tmp_path)
    payload = derive_canonical_prior_authority(
        tmp_path / "_canonical_finding_ids.json"
    ).payload
    payload["aliases"]["FORGED-1"] = "CID-NOT-IN-MAP"
    unsigned = {
        key: value for key, value in payload.items()
        if key != "alias_receipt_sha256"
    }
    import hashlib
    payload["alias_receipt_sha256"] = hashlib.sha256(
        json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()
    (tmp_path / CANONICAL_PRIOR_ALIAS_NAME).write_text(
        json.dumps(payload), encoding="utf-8"
    )

    with pytest.raises(ExplorationClearError, match="semantic parity"):
        load_canonical_prior_authority(tmp_path)


def test_bound_identity_map_drift_revokes_alias_authority(tmp_path: Path) -> None:
    source = _write_identity_map(tmp_path)
    (tmp_path / CANONICAL_PRIOR_ALIAS_NAME).write_text(
        json.dumps(derive_canonical_prior_authority(source).payload), encoding="utf-8"
    )
    source.write_text(json.dumps({"records": []}), encoding="utf-8")

    with pytest.raises(ExplorationClearError, match="schema or denominator mismatch"):
        load_canonical_prior_authority(tmp_path)


def test_absent_identity_map_has_an_exact_empty_projection(tmp_path: Path) -> None:
    payload = derive_canonical_prior_authority(
        tmp_path / "_canonical_finding_ids.json"
    ).payload
    (tmp_path / CANONICAL_PRIOR_ALIAS_NAME).write_text(
        json.dumps(payload), encoding="utf-8"
    )

    assert load_canonical_prior_authority(tmp_path).aliases == {}
