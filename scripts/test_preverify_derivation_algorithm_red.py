"""RED contracts for versioned preverify derivation authority.

The current providers bind generation identity to the raw bytes of a Python
source file.  That is both too strict (comments and line endings change the
identity) and too weak (imported executable behavior is not covered).  These
test-only fixtures pin the replacement contract:

* receipts select one immutable, known semantic algorithm suite;
* the suite is pinned by a hardcoded golden-vector conformance digest;
* source formatting is not algorithm authority;
* executable behavior cannot drift under an unchanged suite identity;
* inventory union behavior is byte-exact, including order and collisions.

No production artifact, model, network request, or audit is launched.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import pytest

from artifact_ledger import read_artifact_ledger
import preverify_frozen_projection as PROVIDER
from preverify_frozen_projection import PreverifyFrozenProjectionError
from preverify_projection_authority import (
    PreverifyProjectionAuthorityError,
    validate_frozen_projection_receipt,
)
import test_live_verify_queue_driver_adapter_cutover as ADAPTER
import test_preverify_frozen_projection as FROZEN


ALGORITHM_SUITE_ID = "plamen.preverify.frozen_derivation.v1"
FROZEN_RECEIPT_SCHEMA_V2 = (
    "plamen.preverify_frozen_projection_receipt.v2"
)
EXPECTED_CONFORMANCE_SHA256 = (
    "de2cdf47242adbf9eb82bf2fc4dab5156efd9abd78d508741d6c83c6c4d29795"
)


BASE_INVENTORY = (
    b"# Findings Inventory\r\n\r\n"
    b"### Finding [H-2]: Base second\r\n"
    b"**Severity**: Medium\r\n"
    b"**Description**: Keep original byte ordering.  \r\n\r\n"
    b"### Finding [EN-2]: Existing collision\r\n"
    b"**Severity**: Low\r\n"
    b"**Description**: Base version wins.\r\n\r\n"
    b"### Finding [H-1]: Base first\r\n"
    b"**Severity**: High\r\n"
    b"**Description**: Preserve CRLF source bytes.\r\n"
)


def _candidate(
    identity: str,
    title: str,
    severity: str,
) -> dict[str, Any]:
    return {
        "candidate_identity": identity,
        "hypothesis_ids": ["H-9"],
        "relation_kind": "ENABLER_CONSTITUENT",
        "required_disposition": "VERIFY_INDEPENDENTLY",
        "mandatory_verification": True,
        "severity_proposal": severity,
        "title": title,
        "location": "src/F.sol:9",
        "description": "Derived candidate.",
        "impact": "Requires verification.",
        "source_artifact": "enabler_results.md",
        "inventory_block": (
            f"### Finding [{identity}]: {title}\n"
            f"**Severity**: {severity}\n"
            "**Description**: Derived candidate."
        ),
        "proof_authority": "NONE",
    }


DELTA_CANDIDATES = [
    _candidate("EN-1", "Appended first", "Medium"),
    _candidate("EN-2", "Conflicting replacement", "High"),
    _candidate("EN-3", "Appended third", "Low"),
]
CHAIN_DELTA = {
    "candidate_ids": ["EN-1", "EN-2", "EN-3"],
    "candidate_count": 3,
    "candidates": DELTA_CANDIDATES,
}
EXPECTED_DELTA_INVENTORY = (
    b"# Findings Inventory\r\n\r\n"
    b"### Finding [H-2]: Base second\r\n"
    b"**Severity**: Medium\r\n"
    b"**Description**: Keep original byte ordering.  \r\n\r\n"
    b"### Finding [EN-2]: Existing collision\r\n"
    b"**Severity**: Low\r\n"
    b"**Description**: Base version wins.\r\n\r\n"
    b"### Finding [H-1]: Base first\r\n"
    b"**Severity**: High\r\n"
    b"**Description**: Preserve CRLF source bytes.\n\n"
    b"### Finding [EN-1]: Appended first\n"
    b"**Severity**: Medium\n"
    b"**Description**: Derived candidate.\n\n"
    b"### Finding [EN-3]: Appended third\n"
    b"**Severity**: Low\n"
    b"**Description**: Derived candidate.\n"
)
EXPECTED_NO_DELTA_FIXED_POINT = {
    "base_ids": ["EN-2", "H-1", "H-2"],
    "delta_ids": [],
    "frozen_ids": ["EN-2", "H-1", "H-2"],
    "base_union_delta_equals_frozen": True,
    "candidate_records_removed": 0,
}
EXPECTED_DELTA_FIXED_POINT = {
    "base_ids": ["EN-2", "H-1", "H-2"],
    "delta_ids": ["EN-1", "EN-2", "EN-3"],
    "frozen_ids": ["EN-1", "EN-2", "EN-3", "H-1", "H-2"],
    "base_union_delta_equals_frozen": True,
    "candidate_records_removed": 0,
    "identity_collision_ids": ["EN-2"],
}
EXPECTED_COLLISION_DEBT = [
    {
        "reason_code": "CHAIN_CANDIDATE_IDENTITY_COLLISION",
        "candidate_identity": "EN-2",
        "base_block_sha256": (
            "423c19e08503177c7301f9f4e85f49018b75643d0db76f812662e1303f9a2a73"
        ),
        "delta_block_sha256": (
            "06437b34e5dc960d772867ea8acb5cac6c5a09c545f4c9eb511b360cc2fc0477"
        ),
        "candidate": DELTA_CANDIDATES[1],
        "candidate_disposition": "VISIBLE_HUMAN_REVIEW_DEBT",
        "proof_authority": "NONE",
    }
]


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_digest(value: Mapping[str, Any]) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    raw = (raw + "\n").encode("utf-8")
    return _sha(raw)


def _derive_union(
    base: bytes,
    delta: Mapping[str, Any] | None,
) -> tuple[bytes, dict[str, Any], list[dict[str, Any]]]:
    derive = getattr(PROVIDER, "derive_preverify_inventory_union", None)
    assert callable(derive), (
        "preverify frozen provider lacks required public "
        "derive_preverify_inventory_union API"
    )
    value = derive(
        base,
        delta,
    )
    assert isinstance(value, tuple) and len(value) == 3
    raw, fixed_point, collision_debt = value
    assert isinstance(raw, bytes)
    assert isinstance(fixed_point, dict)
    assert isinstance(collision_debt, list)
    return raw, fixed_point, collision_debt


_ENVELOPE_FIELDS = {
    "generation_digest",
    "logical_to_physical",
    "advisory_evidence_path",
    "required_paths",
    "debt",
    "proof_authority",
    "receipt_digest",
}


def _readdress_receipt(
    receipt: dict[str, Any],
    authority: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    upgraded = deepcopy(receipt)

    generation_core = {
        key: value
        for key, value in upgraded.items()
        if key not in _ENVELOPE_FIELDS
    }
    generation_core["schema_version"] = PROVIDER.SCHEMA
    generation = _canonical_digest(generation_core)
    old_root = str(authority["frozen_root"])
    new_root = f"_preverify_frozen/generation_{generation}"
    upgraded["generation_digest"] = generation
    upgraded["logical_to_physical"] = {
        logical: str(physical).replace(old_root, new_root, 1)
        for logical, physical in upgraded["logical_to_physical"].items()
    }
    upgraded["advisory_evidence_path"] = str(
        upgraded["advisory_evidence_path"]
    ).replace(old_root, new_root, 1)
    upgraded["required_paths"] = sorted(
        str(path).replace(old_root, new_root, 1)
        for path in upgraded["required_paths"]
    )
    upgraded["receipt_digest"] = _canonical_digest({
        key: value
        for key, value in upgraded.items()
        if key != "receipt_digest"
    })

    producer_prefix = str(authority["producer_key"]).rsplit(".", 1)[0]
    upgraded_authority = {
        **authority,
        "frozen_root": new_root,
        "frozen_generation": generation,
        "producer_key": f"{producer_prefix}.{generation}",
        "inventory_path": f"{new_root}/findings_inventory.md",
        "records_path": f"{new_root}/finding_records.json",
        "receipt_path": f"{new_root}/receipt.json",
        "evidence_path": (
            f"{new_root}/inventory_evidence_validation.md"
        ),
    }
    return upgraded, upgraded_authority


def _validate_context(
    context: Mapping[str, Any],
    receipt: Mapping[str, Any],
    authority: Mapping[str, Any],
) -> None:
    validate_frozen_projection_receipt(
        receipt,
        authority=authority,
        run_id=str(context["run_id"]),
        evidence_source=str(context["evidence_source"]),
        inventory_raw=bytes(context["inventory_raw"]),
        records_raw=bytes(context["records_raw"]),
        advisory_evidence_raw=bytes(context["evidence_raw"]),
        scratchpad=Path(context["root"]),
        project_root=Path(context["project_root"]),
    )


def _receipt_context(tmp_path: Path) -> dict[str, Any]:
    root, config, run_id = ADAPTER._seed(
        tmp_path,
        pipeline="sc",
        backend="claude",
    )
    FROZEN._split_source_owners(
        root,
        tmp_path,
        config,
        run_id,
    )
    frozen = FROZEN._prepare(
        root,
        tmp_path,
        config,
        run_id,
    )
    ledger = read_artifact_ledger(root)
    producer_key = str(frozen["work_unit_key"])
    producer = ledger["work_units"][producer_key]
    physical = frozen["logical_to_physical"]
    inventory_path = str(physical["findings_inventory.md"])
    frozen_root = str(Path(inventory_path).parent).replace("\\", "/")
    authority = {
        "frozen_generation": str(frozen["generation_digest"]),
        "frozen_root": frozen_root,
        "producer_key": producer_key,
        "producer_contract_digest": str(producer["contract_digest"]),
        "provider_input_bindings": deepcopy(producer["input_bindings"]),
        "source_preimage_rows": {
            identity.rsplit("/_sources/", 1)[1]: {
                "path": identity.removeprefix("scratchpad:"),
                "identity": identity,
                "binding": deepcopy(binding),
            }
            for identity, binding in producer["artifacts"].items()
            if "/_sources/" in identity
        },
        "inventory_path": inventory_path,
        "records_path": str(physical["finding_records.json"]),
        "evidence_path": str(frozen["advisory_evidence_path"]),
        "receipt_path": str(frozen["receipt_path"]),
    }
    receipt = json.loads(
        (root / authority["receipt_path"]).read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    evidence_source = (
        str(receipt["evidence_source"])
        if receipt["evidence_semantic_use"] is True
        else ""
    )
    return {
        "root": root,
        "project_root": tmp_path,
        "run_id": run_id,
        "authority": authority,
        "receipt": receipt,
        "inventory_raw": (root / authority["inventory_path"]).read_bytes(),
        "records_raw": (root / authority["records_path"]).read_bytes(),
        "evidence_source": evidence_source,
        "evidence_raw": (root / authority["evidence_path"]).read_bytes(),
    }


def test_algorithm_identity_and_hardcoded_conformance_digest_are_exact() -> None:
    assert PROVIDER.RECEIPT_SCHEMA == FROZEN_RECEIPT_SCHEMA_V2
    assert PROVIDER.DERIVATION_ALGORITHM == ALGORITHM_SUITE_ID
    assert (
        PROVIDER.DERIVATION_CONFORMANCE_SHA256
        == EXPECTED_CONFORMANCE_SHA256
    )
    assert (
        PROVIDER.derive_preverify_derivation_conformance_sha256()
        == EXPECTED_CONFORMANCE_SHA256
    )
    PROVIDER.validate_preverify_derivation_conformance()


def test_supported_v2_receipt_with_known_algorithm_passes(
    tmp_path: Path,
) -> None:
    context = _receipt_context(tmp_path)
    receipt = deepcopy(context["receipt"])
    authority = deepcopy(context["authority"])
    assert receipt["schema_version"] == FROZEN_RECEIPT_SCHEMA_V2
    assert receipt["derivation_algorithm"] == ALGORITHM_SUITE_ID
    assert (
        receipt["derivation_conformance_sha256"]
        == EXPECTED_CONFORMANCE_SHA256
    )

    _validate_context(context, receipt, authority)


def test_same_v2_schema_with_unknown_algorithm_rejects_specifically(
    tmp_path: Path,
) -> None:
    context = _receipt_context(tmp_path)
    receipt = deepcopy(context["receipt"])
    receipt["derivation_algorithm"] = (
        "plamen.preverify.frozen_derivation.v999"
    )
    receipt, authority = _readdress_receipt(
        receipt,
        context["authority"],
    )

    with pytest.raises(
        PreverifyProjectionAuthorityError,
        match=r"(?i)(unknown|unsupported).*(algorithm|suite)|"
        r"(algorithm|suite).*(unknown|unsupported)",
    ):
        _validate_context(context, receipt, authority)


def test_unknown_receipt_schema_remains_rejected(
    tmp_path: Path,
) -> None:
    context = _receipt_context(tmp_path)
    receipt = deepcopy(context["receipt"])
    receipt["schema_version"] = (
        "plamen.preverify_frozen_projection_receipt.v999"
    )
    receipt, authority = _readdress_receipt(
        receipt,
        context["authority"],
    )

    with pytest.raises(PreverifyProjectionAuthorityError):
        _validate_context(context, receipt, authority)


@pytest.mark.parametrize("change", ["comment", "crlf"])
def test_provider_text_changes_preserve_algorithm_authority_and_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    context = _receipt_context(tmp_path)
    receipt = deepcopy(context["receipt"])
    authority = deepcopy(context["authority"])
    original_identity = (
        PROVIDER.DERIVATION_ALGORITHM,
        PROVIDER.DERIVATION_CONFORMANCE_SHA256,
    )
    original_generation = receipt["generation_digest"]

    original = Path(str(PROVIDER.__file__)).read_bytes()
    if change == "comment":
        changed = original + b"\n# nonsemantic fixture-only comment\n"
    elif b"\r\n" in original:
        changed = original.replace(b"\r\n", b"\n")
    else:
        changed = original.replace(b"\n", b"\r\n")
    assert changed != original
    alternate = tmp_path / f"provider-{change}.py"
    alternate.write_bytes(changed)
    monkeypatch.setattr(PROVIDER, "__file__", str(alternate))

    assert (
        PROVIDER.DERIVATION_ALGORITHM,
        PROVIDER.DERIVATION_CONFORMANCE_SHA256,
    ) == original_identity
    assert receipt["generation_digest"] == original_generation
    _validate_context(context, receipt, authority)


def test_executable_drift_without_id_bump_fails_conformance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    check = PROVIDER.validate_preverify_derivation_conformance
    check()
    original = PROVIDER.derive_preverify_inventory_union

    def drifted(
        base: bytes,
        delta: Mapping[str, Any] | None = None,
    ) -> tuple[bytes, dict[str, Any], list[dict[str, Any]]]:
        raw, fixed_point, debt = original(base, delta)
        return raw + b"\n# silent semantic drift\n", fixed_point, debt

    monkeypatch.setattr(
        PROVIDER,
        "derive_preverify_inventory_union",
        drifted,
    )
    with pytest.raises(
        PreverifyFrozenProjectionError,
        match=r"(?i)algorithm|conformance|golden",
    ):
        check()


def test_no_delta_public_derivation_is_exact_byte_identity() -> None:
    raw, fixed_point, debt = _derive_union(BASE_INVENTORY, None)

    assert raw == BASE_INVENTORY
    assert fixed_point == EXPECTED_NO_DELTA_FIXED_POINT
    assert debt == []


def test_delta_public_derivation_pins_append_collision_and_order() -> None:
    raw, fixed_point, debt = _derive_union(
        BASE_INVENTORY,
        CHAIN_DELTA,
    )

    assert raw == EXPECTED_DELTA_INVENTORY
    assert fixed_point == EXPECTED_DELTA_FIXED_POINT
    assert debt == EXPECTED_COLLISION_DEBT
    assert raw.index(b"Finding [EN-1]") < raw.index(b"Finding [EN-3]")
    assert raw.count(b"Finding [EN-2]") == 1
