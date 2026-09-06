"""RunBundle v2 R5 regressions for bounded canonical structural validation."""

from __future__ import annotations

import copy

import pytest

import runbundle_contracts as C
import test_runbundle_v2_contracts as T


def _authority_template(authority_type: str) -> dict[str, object]:
    if authority_type == "RUN_CONTEXT":
        return T._manifest()["run_context_authority"]
    if authority_type == "RECORD_PARTITION":
        return T._harvest_receipt()["record_reconciliation"][
            "partition_authority"
        ]
    return next(
        row
        for row in T._authority_receipts()
        if row["authority_type"] == authority_type
    )


def _replace_nonfinding_roster(
    documents: dict[str, object],
    record_ids: list[str],
) -> None:
    template = _authority_template("NONFINDING_CLASSIFICATION")
    payload = copy.deepcopy(template["decision_payload"])
    payload["record_ids"] = record_ids
    replacement = T._sign_authority_receipt(
        template["receipt_id"],
        template["authority_type"],
        sorted(set(record_ids)),
        source_artifact_ids=list(template["source_artifact_ids"]),
        decision=template["decision"],
        decision_payload=payload,
    )
    T._replace_authority_receipts(
        documents,
        [replacement],
        resign_nonfinding=False,
    )


@pytest.mark.parametrize(
    ("mutation", "mutate"),
    [
        ("omitted", lambda rows: rows[1:]),
        ("extra", lambda rows: sorted([*rows, "not-a-real-record"])),
        (
            "role-substitution",
            lambda rows: sorted(
                [
                    *rows[1:],
                    "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F",
                ]
            ),
        ),
        ("duplicate", lambda rows: [rows[0], *rows]),
    ],
)
def test_nonfinding_authority_must_bind_exact_reconciliation_partition(
    mutation: str,
    mutate,
) -> None:
    del mutation
    documents = T._documents()
    reconciliation = documents["harvest_receipt.json"]["record_reconciliation"]
    expected = [
        row["record_id"]
        for row in reconciliation["authenticated_nonfinding_records"]
    ]
    _replace_nonfinding_roster(documents, mutate(expected))

    with pytest.raises(
        C.RunBundleContractError,
        match="NONFINDING|nonfinding|subject.*exact|duplicate",
    ):
        C.validate_bundle_payload_set(documents, T._public_lock())


@pytest.mark.parametrize("authority_type", sorted(C._AUTHORITY_TYPES))
@pytest.mark.parametrize(
    ("mutation", "mutate"),
    [
        ("omitted", lambda rows: rows[1:]),
        ("extra", lambda rows: [*rows, "zz-r5-extra-subject"]),
        ("duplicate", lambda rows: [*rows, rows[0]]),
        (
            "role-substitution",
            lambda rows: ["zz-r5-role-substitute", *rows[1:]],
        ),
    ],
)
def test_all_authority_subject_rosters_remain_exact(
    authority_type: str,
    mutation: str,
    mutate,
) -> None:
    del mutation
    template = _authority_template(authority_type)
    replacement = T._sign_authority_receipt(
        f"r5-subject-{authority_type.lower().replace('_', '-')}",
        authority_type,
        mutate(list(template["subject_ids"])),
        source_artifact_ids=list(template["source_artifact_ids"]),
        decision=template["decision"],
        decision_payload=copy.deepcopy(template["decision_payload"]),
    )
    with pytest.raises(
        C.RunBundleContractError,
        match="subject.*exact|duplicate",
    ):
        C._validate_signed_authority_receipt(
            replacement,
            T._public_lock()["audit_authority"],
            context=f"R5 subject roster {authority_type}",
        )


def test_stale_nonfinding_authority_is_rejected_after_partition_growth() -> None:
    documents = T._documents()
    manifest = documents["run_manifest.json"]
    manifest["budget"]["measurement_receipt_refs"].append(
        "measurement-receipt-002"
    )
    T._resign_run_context(manifest)
    replacements, additions = T._signed_measurement_authorities(manifest)
    T._replace_authority_receipts(
        documents,
        replacements,
        additions=additions,
    )
    current = T._current_authority_receipts(documents)
    stale = _authority_template("NONFINDING_CLASSIFICATION")
    T._replace_authority_receipts(
        documents,
        [stale],
        base_receipts=current,
        resign_nonfinding=False,
    )

    with pytest.raises(C.RunBundleContractError, match="nonfinding|subject.*exact"):
        C.validate_bundle_payload_set(documents, T._public_lock())


_DUPLICATE_ROW_FIELDS = {
    "CANDIDATE_EMISSION": "occurrences",
    "LINEAGE_DEBT": "debts",
    "NEGATIVE_DISPOSITION": "dispositions",
    "NONFINDING_CLASSIFICATION": "record_ids",
    "REPORT_DISPOSITION": "rows",
    "REPORT_QUALITY": "report_entries",
    "SEVERITY_DECISION": "rows",
}


@pytest.mark.parametrize(
    ("authority_type", "row_field"),
    sorted(_DUPLICATE_ROW_FIELDS.items()),
)
def test_signed_authority_payload_rejects_exact_duplicate_rows(
    authority_type: str,
    row_field: str,
) -> None:
    template = _authority_template(authority_type)
    payload = copy.deepcopy(template["decision_payload"])
    payload[row_field].append(copy.deepcopy(payload[row_field][0]))
    replacement = T._sign_authority_receipt(
        f"r5-duplicate-{authority_type.lower().replace('_', '-')}",
        authority_type,
        list(template["subject_ids"]),
        source_artifact_ids=list(template["source_artifact_ids"]),
        decision=template["decision"],
        decision_payload=payload,
    )

    with pytest.raises(C.RunBundleContractError, match="duplicate"):
        C._validate_signed_authority_receipt(
            replacement,
            T._public_lock()["audit_authority"],
            context=f"R5 duplicate {authority_type}",
        )


class _EncodingSpoof(str):
    def encode(self, *args, **kwargs) -> bytes:
        del args, kwargs
        return b'{"x":1}\n'


class _ComparisonSpoof(bytes):
    def __ne__(self, other) -> bool:
        del other
        return False


@pytest.mark.parametrize(
    ("loader", "raw"),
    [
        (C.strict_json_loads, _EncodingSpoof('{ "x" : 1 }')),
        (C.strict_json_loads, _ComparisonSpoof(b'{ "x" : 1 }\n')),
        (C.strict_jsonl_loads, _EncodingSpoof('{ "x" : 1 }\n')),
        (C.strict_jsonl_loads, _ComparisonSpoof(b'{ "x" : 1 }\n')),
    ],
)
def test_canonical_json_rejects_text_and_bytes_subclasses_before_dispatch(
    loader,
    raw: str | bytes,
) -> None:
    with pytest.raises(C.RunBundleContractError, match="exact built-in"):
        loader(raw, require_canonical=True)


def _nested_list(depth: int) -> object:
    value: object = 0
    for _ in range(depth):
        value = [value]
    return value


def test_cycles_and_excessive_depth_are_bounded_contract_errors() -> None:
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic
    with pytest.raises(C.RunBundleContractError, match="cycle"):
        C.canonical_json_bytes(cyclic)

    with pytest.raises(C.RunBundleContractError, match="depth"):
        C.canonical_json_bytes(_nested_list(C.MAX_JSON_DEPTH + 1))
    with pytest.raises(C.RunBundleContractError, match="depth"):
        C.canonical_json_bytes(_nested_list(1_500))
    with pytest.raises(C.RunBundleContractError, match="depth"):
        C.strict_json_loads(
            (b"[" * 1_500) + b"0" + (b"]" * 1_500)
        )

    assert C.strict_json_loads(
        C.canonical_json_bytes(_nested_list(C.MAX_JSON_DEPTH - 1))
    )


def test_json_byte_ceiling_and_just_below_boundary() -> None:
    below = b'"' + (b"a" * (C.MAX_JSON_BYTES - 4)) + b'"'
    assert len(below) == C.MAX_JSON_BYTES - 2
    assert len(C.strict_json_loads(below)) == C.MAX_JSON_BYTES - 4

    above = b'"' + (b"a" * C.MAX_JSON_BYTES) + b'"'
    with pytest.raises(C.RunBundleContractError, match="byte"):
        C.strict_json_loads(above)


def test_json_width_ceiling_and_just_below_boundary() -> None:
    C.canonical_json_bytes([0] * (C.MAX_JSON_WIDTH - 1))
    with pytest.raises(C.RunBundleContractError, match="width"):
        C.canonical_json_bytes([0] * (C.MAX_JSON_WIDTH + 1))


def _node_fixture(target_nodes: int) -> list[list[int]]:
    rows: list[list[int]] = []
    remaining = target_nodes - 1
    while remaining:
        width = min(C.MAX_JSON_WIDTH - 1, remaining - 1)
        rows.append(list(range(width)))
        remaining -= width + 1
    return rows


def test_json_node_ceiling_and_just_below_boundary() -> None:
    below = _node_fixture(C.MAX_JSON_NODES - 1)
    C.canonical_json_bytes(below)

    above = copy.deepcopy(below)
    above.append([0, 0])
    with pytest.raises(C.RunBundleContractError, match="node"):
        C.canonical_json_bytes(above)
