"""Fixture-first contracts for the GT-blind real-audit RunBundle profile."""
from __future__ import annotations

import base64
import copy
from dataclasses import FrozenInstanceError
import hashlib
import itertools
import json
import os
from pathlib import Path

import pytest

import runbundle_contracts as C
import runbundle_phase_map as M
import runbundle_privacy as P


H = "1" * 64
CASE_ID = "case-llevgqbmb54aok3o4lii7jpcim-r3awebey"
RUN_ID = "run-fctauq54xqngbk75xue3mj6xfi-erciuwqj"
OTHER_RUN_ID = "run-rsvedgs2w5znxcebhxg43uqsf4-u65el5js"
EXPERIMENT_ID = "experiment-kv4t7nwn73n3du6sctcffikq2e-i6g2ista"
CELL_ID = "cell-tci56iikh5ictkguvlqusr6zfi-f5mq7p7f"
PARITY_ID = "parity-g7xmt4btl4xycn2x2bckz6gmva-7q5uta6m"
NONCE_ID = "nonce-bivf6srodsxed34rtoqdmg7mtm-2wmzh5d5"
DISCOVERY_RAW = b"finding fixture\n"
REPORT_RAW = b"# Final report fixture\n" + (b"R" * 1000)
ALLOCATION_REVEAL_B64 = "Lv3SPZ1RO6wC2gPQDsvWUAUT12mqy7nmp8Bg_yF6wl0"
RSA_N = int(
    "b03a67b178814ed196fb54cdd019e330f958976f08ce9060e4e239184d7f381"
    "a6e0d5cfbd1d059013022a1b9de7e8d9cb9a79a00af8d664a55251b9c9893ed"
    "0f3d4b5872e91e7f7f3d45704c842cb0168c4ba7f108b737efb559dc87cc740"
    "df66f6914af106c64727d093cb56af08d3c79b56c296e98463bb626a7d8a455"
    "f7854c57c160ce1bd226dc7c924cdd2f40960e515a854a4be8f52ba6efcfe560"
    "cd2709d6b1144bf0194b6edc82873b1bcbba0fc2f988415e23a91b42fa4d0fb"
    "11e0caf7c8a4e89995ef7b25ef5ea6810837dad9f146cb0454764cae283409c6"
    "a2e418cb8dcbe4bf5b87368432e6e7769cd673d05d10678d71c3c09e5b8c095"
    "da4e43",
    16,
)
RSA_D = int(
    "181f7690418999cb70da688a5fc11b6b59c679bc363d68600b14b8720e31aaf"
    "15b3d330c397546a9b5f817a144c69805eb17f929bcde23316ba44fba48dc7ee"
    "7c6212933599bd62209b616a032bb97430ee35052db39914b9bcc783692931452"
    "367ff0d7e1eca477538c4f261a446160f4dc13b93c2d55f7d880441b90ab3fdd"
    "620f79f421e1c0581b4fd11159e56f9b960c6cb42b950ac0bb1b1d52b284252"
    "b2723e578a187de58f57660062e7f27422c70c0af20ea80d68a1e93e2c873b3"
    "5564a35627e4bcdb1fe87119beeeed034917d1da87ee228cf4f4db4ded06df2d"
    "686008d4c91601c36f50f7e914e3c2fdc8919b866b76a9396bdfc9b8d98e5df"
    "b69",
    16,
)
RSA_E = 65537
PINNED_PHASE_MAP_SHA256 = {
    "SC": "28779f0e8bfb0358f0b496661b61918f7b837530c05ff1295f63e83d5d5ac9ae",
    "L1": "1eb129d128fc47427b1de2d0502aa82f3162546246f57d6d738090d441c526a6",
}
MEASURED_CONSUMPTION = {
    "token_count": 90_000,
    "wall_time_ms": 3_000_000,
    "tool_calls": 800,
    "model_calls": 80,
}
NEW_RESUME = {
    "mode": "NEW",
    "attempt": 1,
    "parent_state_seal_sha256": None,
}


def _phase_map(pipeline_kind: str = "SC") -> dict[str, object]:
    definitions = {
        "SC": (
            "plamen-sc-macro",
            [
                "recon",
                "breadth",
                "inventory",
                "depth",
                "chain",
                "verify",
                "report",
            ],
        ),
        "L1": (
            "plamen-l1-macro",
            [
                "bake",
                "recon",
                "breadth",
                "graph",
                "inventory",
                "depth",
                "chain",
                "composition",
                "verify",
                "report",
            ],
        ),
    }
    map_id, ordered = definitions[pipeline_kind]
    version = "2"
    return {
        "map_id": map_id,
        "map_version": version,
        "map_sha256": PINNED_PHASE_MAP_SHA256[pipeline_kind],
        "pipeline_kind": pipeline_kind,
    }


def _allocation_authority() -> dict[str, object]:
    reveal = base64.urlsafe_b64decode(ALLOCATION_REVEAL_B64 + "=")
    receipt = {
        "schema_version": "plamen.structural-allocation-reveal.v1",
        "receipt_id": "allocation-receipt-001",
        "authority_type": "STRUCTURAL_ALLOCATION_REVEAL",
        "algorithm": "HMAC_SHA256_FROM_PUBLIC_REVEAL",
        "reveal_bits": 256,
        "allocation_reveal_b64": ALLOCATION_REVEAL_B64,
        "reveal_commitment_sha256": hashlib.sha256(
            b"plamen.real-audit.csp-allocation-reveal.v2\0" + reveal
        ).hexdigest(),
        "allocations": [
            {"kind": kind, "index": index, "opaque_id": opaque_id}
            for index, (kind, opaque_id) in enumerate(
                [
                    ("case", CASE_ID),
                    ("nonce", NONCE_ID),
                    ("run", RUN_ID),
                    ("cell", CELL_ID),
                    ("parity", PARITY_ID),
                    ("experiment", EXPERIMENT_ID),
                ]
            )
        ],
    }
    return C.bind_embedded_sha256(receipt, "receipt_sha256")


def _audit_authority() -> dict[str, object]:
    modulus = RSA_N.to_bytes((RSA_N.bit_length() + 7) // 8, "big")
    return {
        "key_id": hashlib.sha256(modulus).hexdigest(),
        "algorithm": "RSA_PKCS1V15_SHA256",
        "modulus_hex": format(RSA_N, "x"),
        "public_exponent": RSA_E,
    }


def _sign_authority_receipt(
    receipt_id: str,
    authority_type: str,
    subject_ids: list[str],
    *,
    source_artifact_ids: list[str] | None = None,
    decision: str | None = None,
    decision_payload: object | None = None,
) -> dict[str, object]:
    payload = {} if decision_payload is None else decision_payload
    body = {
        "schema_version": "plamen.public-authority-receipt.v1",
        "receipt_id": receipt_id,
        "authority_type": authority_type,
        "subject_ids": sorted(subject_ids),
        "source_artifact_ids": sorted(source_artifact_ids or []),
        "decision": decision,
        "decision_payload": payload,
        "payload_sha256": C.sha256_bytes(C.canonical_json_bytes(payload)),
    }
    digest = hashlib.sha256(C.canonical_document_bytes(body)).digest()
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + digest
    size = (RSA_N.bit_length() + 7) // 8
    encoded = b"\x00\x01" + (b"\xff" * (size - len(digest_info) - 3))
    encoded += b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded, "big"), RSA_D, RSA_N).to_bytes(
        size, "big"
    )
    body["signature_b64"] = base64.urlsafe_b64encode(signature).decode(
        "ascii"
    ).rstrip("=")
    return body


def _phase_output_fixture_payload(
    output_native_phase: str,
    output_macro_phase: str,
) -> dict[str, object]:
    return {
        "event": {
            "schema_version": C.PHASE_EVENT_SCHEMA,
            "event_id": "event-00000001",
            "run_id": RUN_ID,
            "sequence": 1,
            "attempt": 1,
            "native_phase": output_native_phase,
            "macro_phase": output_macro_phase,
            "work_unit_id": "work-breadth-001",
            "event_type": "OUTPUTS_COMMITTED",
            "commit_state": "CLEAN",
            "source_artifact_ids": ["artifact-authorities-001"],
            "input_artifact_ids": [],
            "output_artifact_ids": ["artifact-breadth-001"],
            "artifact_relations": [
                {
                    "artifact_id": "artifact-authorities-001",
                    "relation": "SOURCE",
                },
                {
                    "artifact_id": "artifact-breadth-001",
                    "relation": "OUTPUT",
                },
            ],
            "observed_at": "2026-07-24T12:00:00Z",
            "evidence_quality": "AUTHENTICATED",
        },
        "source_artifacts": [
            {
                "artifact_id": "artifact-authorities-001",
                "native_phase": "recon",
                "macro_phase": "recon",
                "work_unit_id": "work-control-001",
                "commit_state": "CLEAN",
                "source_contract_ref": "typed-authority-fixture.v1",
            }
        ],
        "input_artifacts": [],
        "output_artifacts": [
            {
                "artifact_id": "artifact-breadth-001",
                "native_phase": output_native_phase,
                "macro_phase": output_macro_phase,
                "work_unit_id": "work-breadth-001",
                "commit_state": "CLEAN",
                "source_contract_ref": "finding-output-format.v1",
            }
        ],
        "control_artifacts": [],
    }


def _report_phase_output_fixture_payload() -> dict[str, object]:
    event = {
        "schema_version": C.PHASE_EVENT_SCHEMA,
        "event_id": "event-report-final-001",
        "run_id": RUN_ID,
        "sequence": 2,
        "attempt": 1,
        "native_phase": "report_assemble",
        "macro_phase": "report",
        "work_unit_id": "work-report-001",
        "event_type": "REPORT_FINALIZED",
        "commit_state": "CLEAN",
        "source_artifact_ids": ["artifact-breadth-001"],
        "input_artifact_ids": [],
        "output_artifact_ids": ["artifact-final-report"],
        "artifact_relations": [
            {
                "artifact_id": "artifact-breadth-001",
                "relation": "SOURCE",
            },
            {
                "artifact_id": "artifact-final-report",
                "relation": "OUTPUT",
            },
        ],
        "observed_at": "2026-07-24T12:01:00Z",
        "evidence_quality": "AUTHENTICATED",
    }
    return {
        "event": event,
        "source_artifacts": [
            {
                "artifact_id": "artifact-breadth-001",
                "native_phase": "breadth",
                "macro_phase": "breadth",
                "work_unit_id": "work-breadth-001",
                "commit_state": "CLEAN",
                "source_contract_ref": "finding-output-format.v1",
            }
        ],
        "input_artifacts": [],
        "output_artifacts": [
            {
                "artifact_id": "artifact-final-report",
                "native_phase": "report_assemble",
                "macro_phase": "report",
                "work_unit_id": "work-report-001",
                "commit_state": "CLEAN",
                "source_contract_ref": C.REPORT_PROJECTION_SCHEMA,
            }
        ],
        "control_artifacts": [],
    }


def _measurement_receipt_payload(
    *,
    run_id: str = RUN_ID,
    measured_consumption: dict[str, object] | None = None,
    resume: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "run_id": run_id,
        "measurement_state": "MEASURED",
        "measured_consumption": copy.deepcopy(
            measured_consumption or MEASURED_CONSUMPTION
        ),
        "resume": copy.deepcopy(resume or NEW_RESUME),
    }


def _measurement_summary_payload(
    *,
    run_id: str = RUN_ID,
    measurement_receipt_refs: list[str] | None = None,
    measured_consumption: dict[str, object] | None = None,
    resume: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "run_id": run_id,
        "measurement_state": "MEASURED",
        "measurement_receipt_refs": sorted(
            measurement_receipt_refs or ["measurement-receipt-001"]
        ),
        "measured_consumption": copy.deepcopy(
            measured_consumption or MEASURED_CONSUMPTION
        ),
        "resume": copy.deepcopy(resume or NEW_RESUME),
    }


def _authority_receipts() -> list[dict[str, object]]:
    receipt_ids = [
        "alias-authority-001",
        "measurement-receipt-001",
        "measurement-summary-001",
        "negative-authority-001",
        "nonfinding-authority-001",
        "lineage-debt-001",
        "receipt-breadth-001",
        "receipt-recon-001",
        "receipt-report-event-001",
        "report-debt-001",
        "report-disposition-001",
        "report-omission-001",
        "report-quality-001",
        "severity-receipt-001",
    ]
    nonfinding_ids = sorted(
        receipt_ids + ["evidence-record-001", "report-record-001"]
    )
    return sorted(
        [
            _sign_authority_receipt(
                "alias-authority-001",
                "ALIAS_DECISION",
                [
                    "edge-001",
                    "edge-002",
                    "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F",
                    "C2-8N4LR0WY3P5Q7X9S6U3Z2E1G",
                ],
                decision="AUTHORIZED_ALIAS",
                decision_payload={
                    "edges": [
                        {
                            "edge_id": "edge-001",
                            "edge_type": "AUTHORIZED_ALIAS",
                            "source_candidate_id": "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F",
                            "target_candidate_id": "C2-8N4LR0WY3P5Q7X9S6U3Z2E1G",
                            "survivor_candidate_id": "C2-8N4LR0WY3P5Q7X9S6U3Z2E1G",
                            "direction": "SOURCE_TO_TARGET",
                            "effective": True,
                            "applied": True,
                        },
                        {
                            "edge_id": "edge-002",
                            "edge_type": "AUTHORIZED_ALIAS",
                            "source_candidate_id": "C2-8N4LR0WY3P5Q7X9S6U3Z2E1G",
                            "target_candidate_id": "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F",
                            "survivor_candidate_id": "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F",
                            "direction": "SOURCE_TO_TARGET",
                            "effective": True,
                            "applied": True,
                        },
                    ]
                },
            ),
            _sign_authority_receipt(
                "measurement-receipt-001",
                "RESOURCE_MEASUREMENT",
                [RUN_ID],
                decision="MEASURED",
                decision_payload=_measurement_receipt_payload(),
            ),
            _sign_authority_receipt(
                "measurement-summary-001",
                "RESOURCE_MEASUREMENT_SUMMARY",
                [RUN_ID, "measurement-receipt-001"],
                decision="SUMMARIZED",
                decision_payload=_measurement_summary_payload(),
            ),
            _sign_authority_receipt(
                "negative-authority-001",
                "NEGATIVE_DISPOSITION",
                [
                    "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F",
                    "occurrence-0001",
                    "disposition-001",
                ],
                decision="SAFE",
                decision_payload={
                    "dispositions": [
                        {
                            "disposition_id": "disposition-001",
                            "kind": "SAFE",
                            "candidate_id": "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F",
                            "occurrence_id": "occurrence-0001",
                            "native_phase": "sc_verify_aggregate",
                            "macro_phase": "verify",
                            "terminal": True,
                            "superseding_occurrence_id": None,
                            "ordering_basis": "PINNED_NATIVE_PHASE_MAP",
                        }
                    ]
                },
            ),
            _sign_authority_receipt(
                "nonfinding-authority-001",
                "NONFINDING_CLASSIFICATION",
                nonfinding_ids,
                decision="NONFINDING",
                decision_payload={
                    "classification": "PARTITIONED_NONFINDING",
                    "record_ids": nonfinding_ids,
                },
            ),
            _sign_authority_receipt(
                "lineage-debt-001",
                "LINEAGE_DEBT",
                [
                    "debt-unmapped-001",
                    "C2-8N4LR0WY3P5Q7X9S6U3Z2E1G",
                    "occurrence-0002",
                ],
                decision="UNAUTHENTICATED_PARSE",
                decision_payload={
                    "debts": [
                        {
                            "debt_id": "debt-unmapped-001",
                            "debt_code": "UNAUTHENTICATED_PARSE",
                            "candidate_ids": [
                                "C2-8N4LR0WY3P5Q7X9S6U3Z2E1G"
                            ],
                            "occurrence_ids": ["occurrence-0002"],
                        }
                    ]
                },
            ),
            _sign_authority_receipt(
                "receipt-breadth-001",
                "CANDIDATE_EMISSION",
                [
                    "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F",
                    "C2-8N4LR0WY3P5Q7X9S6U3Z2E1G",
                    "artifact-breadth-001",
                    "occurrence-0001",
                    "occurrence-0002",
                    "record-001",
                ],
                source_artifact_ids=["artifact-breadth-001"],
                decision="POSITIVE",
                decision_payload={
                    "occurrences": [
                        {
                            "candidate_id": "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F",
                            "occurrence_id": "occurrence-0001",
                            "state": "POSITIVE",
                            "artifact_id": "artifact-breadth-001",
                            "record_id": "record-001",
                            "byte_range": {
                                "start": 0,
                                "end": len(DISCOVERY_RAW),
                            },
                            "record_sha256": C.sha256_bytes(DISCOVERY_RAW),
                            "producer_kind": "PLAMEN_AUTHORITY",
                            "source_contract_ref": "finding-output-format.v1",
                        },
                        {
                            "candidate_id": "C2-8N4LR0WY3P5Q7X9S6U3Z2E1G",
                            "occurrence_id": "occurrence-0002",
                            "state": "POSITIVE",
                            "artifact_id": "artifact-breadth-001",
                            "record_id": "record-001",
                            "byte_range": {
                                "start": 0,
                                "end": len(DISCOVERY_RAW),
                            },
                            "record_sha256": C.sha256_bytes(DISCOVERY_RAW),
                            "producer_kind": "PLAMEN_AUTHORITY",
                            "source_contract_ref": "finding-output-format.v1",
                        },
                    ]
                },
            ),
            _sign_authority_receipt(
                "receipt-recon-001",
                "PHASE_OUTPUT",
                ["event-00000001", "work-breadth-001"],
                source_artifact_ids=["artifact-authorities-001"],
                decision="OUTPUTS_COMMITTED",
                decision_payload=_phase_output_fixture_payload(
                    "breadth", "breadth"
                ),
            ),
            _sign_authority_receipt(
                "receipt-report-event-001",
                "PHASE_OUTPUT",
                ["event-report-final-001", "work-report-001"],
                source_artifact_ids=["artifact-breadth-001"],
                decision="REPORT_FINALIZED",
                decision_payload=_report_phase_output_fixture_payload(),
            ),
            _sign_authority_receipt(
                "report-debt-001",
                "REPORT_DISPOSITION",
                ["C2-8N4LR0WY3P5Q7X9S6U3Z2E1G"],
                decision="DEBT",
                decision_payload={
                    "rows": [
                        {
                            "candidate_id": "C2-8N4LR0WY3P5Q7X9S6U3Z2E1G",
                            "report_status": "DEBT",
                        }
                    ]
                },
            ),
            _sign_authority_receipt(
                "report-disposition-001",
                "REPORT_DISPOSITION",
                [
                    "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F",
                    "C2-8N4LR0WY3P5Q7X9S6U3Z2E1G",
                ],
                decision="REPORTED",
                decision_payload={
                    "rows": [
                        {
                            "candidate_id": "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F",
                            "report_status": "REPORTED",
                        },
                        {
                            "candidate_id": "C2-8N4LR0WY3P5Q7X9S6U3Z2E1G",
                            "report_status": "REPORTED",
                        },
                    ]
                },
            ),
            _sign_authority_receipt(
                "report-omission-001",
                "REPORT_DISPOSITION",
                [
                    "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F",
                    "C2-8N4LR0WY3P5Q7X9S6U3Z2E1G",
                ],
                decision="OMITTED_WITH_AUTHORITY",
                decision_payload={
                    "rows": [
                        {
                            "candidate_id": "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F",
                            "report_status": "OMITTED_WITH_AUTHORITY",
                        },
                        {
                            "candidate_id": "C2-8N4LR0WY3P5Q7X9S6U3Z2E1G",
                            "report_status": "OMITTED_WITH_AUTHORITY",
                        },
                    ]
                },
            ),
            _sign_authority_receipt(
                "report-quality-001",
                "REPORT_QUALITY",
                ["artifact-final-report", "report-entry-001"],
                source_artifact_ids=["artifact-final-report"],
                decision="SHIP",
                decision_payload={
                    "final_report_artifact_id": "artifact-final-report",
                    "report_integrity_state": "SHIP",
                    "final_report_artifact": {
                        "artifact_id": "artifact-final-report",
                        "byte_length": len(REPORT_RAW),
                        "sha256": C.sha256_bytes(REPORT_RAW),
                        "producer_kind": "FINAL_REPORT",
                        "source_contract_ref": C.REPORT_PROJECTION_SCHEMA,
                        "record_ids": [
                            "evidence-record-001",
                            "report-record-001",
                        ],
                        "parser_completeness": "COMPLETE_RECORD_ENUMERATION",
                    },
                    "report_entries": [
                        {
                            "entry_id": "report-entry-001",
                            "byte_range": {"start": 0, "end": 8},
                            "byte_range_sha256": C.sha256_bytes(REPORT_RAW[:8]),
                            "candidate_ids": [
                                "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F"
                            ],
                            "projection_kind": "REPORT",
                        },
                        {
                            "entry_id": "report-entry-001",
                            "byte_range": {"start": 0, "end": len(REPORT_RAW)},
                            "byte_range_sha256": C.sha256_bytes(REPORT_RAW),
                            "candidate_ids": [
                                "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F"
                            ],
                            "projection_kind": "REPORT",
                        },
                        {
                            "entry_id": "report-entry-001",
                            "byte_range": {"start": 0, "end": len(REPORT_RAW)},
                            "byte_range_sha256": C.sha256_bytes(REPORT_RAW),
                            "candidate_ids": [
                                "C2-8N4LR0WY3P5Q7X9S6U3Z2E1G"
                            ],
                            "projection_kind": "REPORT",
                        },
                    ],
                    "unmapped_entries": [
                        {
                            "entry_id": "unmapped-entry-001",
                            "byte_range": {
                                "start": 8,
                                "end": len(REPORT_RAW),
                            },
                            "byte_range_sha256": C.sha256_bytes(REPORT_RAW[8:]),
                            "candidate_ids": [
                                "C2-8N4LR0WY3P5Q7X9S6U3Z2E1G"
                            ],
                            "projection_kind": "UNMAPPED",
                        }
                    ],
                    "physical_occurrences": [
                        {
                            "record_id": "evidence-record-001",
                            "artifact_id": "artifact-final-report",
                            "byte_range": {"start": 0, "end": 8},
                            "record_sha256": C.sha256_bytes(REPORT_RAW[:8]),
                            "producer_kind": "FINAL_REPORT",
                            "source_contract_ref": C.REPORT_PROJECTION_SCHEMA,
                        },
                        {
                            "record_id": "report-record-001",
                            "artifact_id": "artifact-final-report",
                            "byte_range": {"start": 8, "end": len(REPORT_RAW)},
                            "record_sha256": C.sha256_bytes(REPORT_RAW[8:]),
                            "producer_kind": "FINAL_REPORT",
                            "source_contract_ref": C.REPORT_PROJECTION_SCHEMA,
                        },
                    ],
                },
            ),
            _sign_authority_receipt(
                "severity-receipt-001",
                "SEVERITY_DECISION",
                [
                    "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F",
                    "C2-8N4LR0WY3P5Q7X9S6U3Z2E1G",
                ],
                decision="HIGH",
                decision_payload={
                    "rows": [
                        {
                            "candidate_id": "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F",
                            "severity": "HIGH",
                        },
                        {
                            "candidate_id": "C2-8N4LR0WY3P5Q7X9S6U3Z2E1G",
                            "severity": "HIGH",
                        },
                    ]
                },
            ),
        ],
        key=lambda row: row["receipt_id"],
    )


def _authority_payload() -> tuple[bytes, list[dict[str, object]]]:
    raw = b""
    bindings: list[dict[str, object]] = []
    for receipt in _authority_receipts():
        start = len(raw)
        record = C.canonical_document_bytes(receipt)
        raw += record
        bindings.append(
            {
                "receipt_id": receipt["receipt_id"],
                "artifact_id": "artifact-authorities-001",
                "byte_range": {"start": start, "end": len(raw)},
                "record_sha256": C.sha256_bytes(record),
            }
        )
    return raw, bindings


AUTHORITY_RAW, AUTHORITY_BINDINGS = _authority_payload()


def _replace_authority_receipts(
    documents: dict[str, object],
    replacements: list[dict[str, object]],
    *,
    additions: list[dict[str, object]] | None = None,
    base_receipts: list[dict[str, object]] | None = None,
    resign_nonfinding: bool = True,
    _skip_rebind: bool = False,
) -> None:
    """Replace signed fixture receipts and replay every physical binding."""

    replacement_by_id = {
        replacement["receipt_id"]: replacement for replacement in replacements
    }
    raw_outputs = documents["raw_outputs.json"]
    prior_authority_ids = {
        binding["receipt_id"] for binding in raw_outputs["authority_receipts"]
    }
    reconciliation = documents["harvest_receipt.json"][
        "record_reconciliation"
    ]
    prior_nonfinding_authority_ids = {
        row["record_id"]
        for row in reconciliation["authenticated_nonfinding_records"]
        if row["artifact_id"] == "artifact-authorities-001"
    }
    receipt_by_id = {
        receipt["receipt_id"]: receipt
        for receipt in (
            _authority_receipts()
            if base_receipts is None
            else copy.deepcopy(base_receipts)
        )
    }
    for addition in additions or []:
        receipt_id = addition["receipt_id"]
        if receipt_id in receipt_by_id:
            raise AssertionError("fixture addition duplicates a receipt")
        receipt_by_id[receipt_id] = addition
    if set(replacement_by_id) - set(receipt_by_id):
        raise AssertionError("fixture replacement names an unknown receipt")
    receipt_by_id.update(replacement_by_id)
    nonfinding_authority_ids = (
        prior_nonfinding_authority_ids & set(receipt_by_id)
    ) | (set(receipt_by_id) - prior_authority_ids)
    retained = [
        row
        for row in reconciliation["authenticated_nonfinding_records"]
        if row["artifact_id"] != "artifact-authorities-001"
    ]
    if resign_nonfinding:
        matches = [
            receipt
            for receipt in receipt_by_id.values()
            if receipt["authority_type"] == "NONFINDING_CLASSIFICATION"
        ]
        if len(matches) != 1:
            raise AssertionError("fixture requires one NONFINDING authority")
        template = matches[0]
        nonfinding_ids = sorted(
            {
                *(row["record_id"] for row in retained),
                *nonfinding_authority_ids,
            }
        )
        receipt_by_id[template["receipt_id"]] = _sign_authority_receipt(
            template["receipt_id"],
            template["authority_type"],
            nonfinding_ids,
            source_artifact_ids=list(template["source_artifact_ids"]),
            decision="NONFINDING",
            decision_payload={
                "classification": "PARTITIONED_NONFINDING",
                "record_ids": nonfinding_ids,
            },
        )
    receipts = list(receipt_by_id.values())

    raw = b""
    bindings: list[dict[str, object]] = []
    for receipt in sorted(receipts, key=lambda row: row["receipt_id"]):
        start = len(raw)
        record = C.canonical_document_bytes(receipt)
        raw += record
        bindings.append(
            {
                "receipt_id": receipt["receipt_id"],
                "artifact_id": "artifact-authorities-001",
                "byte_range": {"start": start, "end": len(raw)},
                "record_sha256": C.sha256_bytes(record),
            }
        )

    raw_outputs["authority_receipts"] = bindings
    artifact = next(
        row
        for row in raw_outputs["artifacts"]
        if row["artifact_id"] == "artifact-authorities-001"
    )
    artifact.update(
        {
            "byte_length": len(raw),
            "sha256": C.sha256_bytes(raw),
            "content": raw.decode("utf-8"),
            "record_ids": sorted(
                binding["receipt_id"] for binding in bindings
            ),
        }
    )

    retained.extend(
        {
            **_physical_record_row(
                record_id=binding["receipt_id"],
                artifact_id="artifact-authorities-001",
                start=binding["byte_range"]["start"],
                end=binding["byte_range"]["end"],
                raw=raw,
                producer_kind="PLAMEN_AUTHORITY",
                source_contract_ref="typed-authority-fixture.v1",
            ),
            "authority_receipt_id": "record-partition-001",
        }
        for binding in bindings
        if binding["receipt_id"] in nonfinding_authority_ids
    )
    reconciliation["authenticated_nonfinding_records"] = sorted(
        retained, key=lambda row: row["record_id"]
    )
    reconciliation["nonfinding_count"] = len(
        reconciliation["authenticated_nonfinding_records"]
    )
    reconciliation["discovered_count"] = (
        reconciliation["emitted_occurrence_count"]
        + reconciliation["nonfinding_count"]
        + reconciliation["debt_count"]
    )
    binding_by_id = {
        binding["receipt_id"]: binding for binding in bindings
    }
    for row in reconciliation["explicit_debt_records"]:
        if row["artifact_id"] != "artifact-authorities-001":
            continue
        binding = binding_by_id[row["record_id"]]
        preserved = {
            key: value
            for key, value in row.items()
            if key in {"debt_id", "authority_receipt_id"}
        }
        row.clear()
        row.update(
            _physical_record_row(
                record_id=binding["receipt_id"],
                artifact_id="artifact-authorities-001",
                start=binding["byte_range"]["start"],
                end=binding["byte_range"]["end"],
                raw=raw,
                producer_kind="PLAMEN_AUTHORITY",
                source_contract_ref="typed-authority-fixture.v1",
            )
        )
        row.update(preserved)
    if not _skip_rebind:
        _rebind_partition_and_harvest(
            documents,
            _nonfinding_current=True,
        )


def _physical_record_row(
    *,
    record_id: str,
    artifact_id: str,
    start: int,
    end: int,
    raw: bytes,
    producer_kind: str,
    source_contract_ref: str,
    occurrence_ids: list[str] | None = None,
) -> dict[str, object]:
    row = {
        "record_id": record_id,
        "artifact_id": artifact_id,
        "byte_range": {"start": start, "end": end},
        "record_sha256": C.sha256_bytes(raw[start:end]),
        "producer_kind": producer_kind,
        "source_contract_ref": source_contract_ref,
    }
    if occurrence_ids is not None:
        row["occurrence_ids"] = sorted(occurrence_ids)
    return row


def _artifact_partition_row(
    *,
    artifact_id: str,
    raw: bytes,
    producer_kind: str,
    source_contract_ref: str,
    record_ids: list[str],
) -> dict[str, object]:
    return {
        "artifact_id": artifact_id,
        "byte_length": len(raw),
        "sha256": C.sha256_bytes(raw),
        "producer_kind": producer_kind,
        "source_contract_ref": source_contract_ref,
        "record_ids": sorted(record_ids),
        "parser_completeness": "COMPLETE_RECORD_ENUMERATION",
    }


def _base_artifact_partition_rows() -> list[dict[str, object]]:
    return sorted(
        [
            _artifact_partition_row(
                artifact_id="artifact-authorities-001",
                raw=AUTHORITY_RAW,
                producer_kind="PLAMEN_AUTHORITY",
                source_contract_ref="typed-authority-fixture.v1",
                record_ids=[
                    binding["receipt_id"] for binding in AUTHORITY_BINDINGS
                ],
            ),
            _artifact_partition_row(
                artifact_id="artifact-breadth-001",
                raw=DISCOVERY_RAW,
                producer_kind="PLAMEN_AUTHORITY",
                source_contract_ref="finding-output-format.v1",
                record_ids=["record-001"],
            ),
            _artifact_partition_row(
                artifact_id="artifact-final-report",
                raw=REPORT_RAW,
                producer_kind="FINAL_REPORT",
                source_contract_ref=C.REPORT_PROJECTION_SCHEMA,
                record_ids=["evidence-record-001", "report-record-001"],
            ),
        ],
        key=lambda row: row["artifact_id"],
    )


def _base_nonfinding_rows() -> list[dict[str, object]]:
    rows = [
        _physical_record_row(
            record_id=binding["receipt_id"],
            artifact_id="artifact-authorities-001",
            start=binding["byte_range"]["start"],
            end=binding["byte_range"]["end"],
            raw=AUTHORITY_RAW,
            producer_kind="PLAMEN_AUTHORITY",
            source_contract_ref="typed-authority-fixture.v1",
        )
        for binding in AUTHORITY_BINDINGS
    ]
    rows.extend(
        [
            _physical_record_row(
                record_id="evidence-record-001",
                artifact_id="artifact-final-report",
                start=0,
                end=8,
                raw=REPORT_RAW,
                producer_kind="FINAL_REPORT",
                source_contract_ref=C.REPORT_PROJECTION_SCHEMA,
            ),
            _physical_record_row(
                record_id="report-record-001",
                artifact_id="artifact-final-report",
                start=8,
                end=len(REPORT_RAW),
                raw=REPORT_RAW,
                producer_kind="FINAL_REPORT",
                source_contract_ref=C.REPORT_PROJECTION_SCHEMA,
            ),
        ]
    )
    return sorted(rows, key=lambda row: row["record_id"])


def _base_occurrence_physical_rows() -> list[dict[str, object]]:
    return [
        _physical_record_row(
            record_id="record-001",
            artifact_id="artifact-breadth-001",
            start=0,
            end=len(DISCOVERY_RAW),
            raw=DISCOVERY_RAW,
            producer_kind="PLAMEN_AUTHORITY",
            source_contract_ref="finding-output-format.v1",
            occurrence_ids=["occurrence-0001"],
        )
    ]


def _partition_authority(
    *,
    artifact_rows: list[dict[str, object]] | None = None,
    occurrence_rows: list[dict[str, object]] | None = None,
    nonfinding_rows: list[dict[str, object]] | None = None,
    debt_rows: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    artifacts = artifact_rows or _base_artifact_partition_rows()
    occurrence = occurrence_rows or _base_occurrence_physical_rows()
    nonfinding = nonfinding_rows or _base_nonfinding_rows()
    debt = debt_rows or []
    subjects = sorted(
        row["record_id"] for row in occurrence + nonfinding + debt
    )
    return _sign_authority_receipt(
        "record-partition-001",
        "RECORD_PARTITION",
        subjects,
        decision="EXACT_PARTITION",
        decision_payload={
            "run_id": RUN_ID,
            "artifacts": artifacts,
            "occurrence_rows": occurrence,
            "nonfinding_rows": nonfinding,
            "debt_rows": debt,
        },
    )


BASE_PARTITION_AUTHORITY = _partition_authority()


def _public_lock() -> dict[str, object]:
    return {
        "schema_version": C.PUBLIC_CASE_LOCK_SCHEMA,
        "case_id": CASE_ID,
        "source_snapshot_sha256": "2" * 64,
        "source_export_receipt_sha256": "3" * 64,
        "language": "evm",
        "build_instructions": ["forge build --offline"],
        "test_instructions": ["forge test --offline"],
        "allowed_public_documentation": [
            {
                "document_id": "doc-public-001",
                "title": "Public protocol documentation",
                "sha256": "4" * 64,
                "relative_path": "docs/protocol.md",
            }
        ],
        "capability_flags": {
            "build_available": True,
            "tests_available": True,
            "network_required": False,
            "rag_allowed": False,
            "fuzz_allowed": True,
        },
        "public_corpus_suite_id": "suite-public-2",
        "public_corpus_suite_version": "2026.07",
        "allocation_nonce": NONCE_ID,
        "allocation_authority": _allocation_authority(),
        "audit_authority": _audit_authority(),
    }


def _manifest(public_lock: dict[str, object] | None = None) -> dict[str, object]:
    lock = public_lock or _public_lock()
    resources = {
        "token_count": 100_000,
        "wall_time_ms": 3_600_000,
        "tool_calls": 1_000,
        "model_calls": 100,
    }
    manifest = {
        "schema_version": C.RUN_MANIFEST_SCHEMA,
        "bundle_profile": C.REAL_AUDIT_V2,
        "trust_profile": "B1_COMPLETE",
        "run_id": RUN_ID,
        "case_id": lock["case_id"],
        "experiment_id": EXPERIMENT_ID,
        "cell_id": CELL_ID,
        "allocation_authority_ref": "allocation-receipt-001",
        "repetition_index": 0,
        "seed": 17,
        "audit_system": "PLAMEN",
        "adapter": {
            "adapter_id": "plamen-native",
            "adapter_version": "2.0.0",
            "adapter_code_sha256": "5" * 64,
            "output_contract": C.CANDIDATE_SET_SCHEMA,
        },
        "public_case_lock_sha256": C.public_case_lock_sha256(lock),
        "experiment_plan_sha256": "6" * 64,
        "campaign_schedule_sha256": "7" * 64,
        "source_snapshot_sha256": lock["source_snapshot_sha256"],
        "phase_map": _phase_map(),
        "model_backend": {
            "model_family": "opaque-family",
            "model_revision": "pinned-revision",
            "provider_class": "REMOTE_API",
            "backend_class": "CLI",
            "context_window_tokens": 200_000,
        },
        "tool_policy": {
            "tool_set_sha256": "9" * 64,
            "network_policy": "DENY_EXCEPT_BACKEND",
            "rag_policy": "DISABLED",
            "mcp_policy": "DISABLED",
        },
        "budget": {
            "regime": "MATCHED_TOTAL",
            "reserved_total": resources,
            "reserved_channels": {
                "discovery": resources,
                "verification": resources,
                "report": resources,
            },
            "measured_consumption": copy.deepcopy(MEASURED_CONSUMPTION),
            "measurement_receipt_refs": ["measurement-receipt-001"],
            "measurement_summary_receipt_ref": "measurement-summary-001",
            "parity_group_id": PARITY_ID,
        },
        "blinding": {
            "ground_truth_available_to_runner": False,
            "prior_report_available_to_runner": False,
            "private_case_lock_available_to_runner": False,
            "grader_labels_available_to_runner": False,
            "rag_exposure": "NONE",
        },
        "resume": copy.deepcopy(NEW_RESUME),
        "completion": {
            "state": "COMPLETE",
            "checkpoint_state": "COMMITTED",
            "final_report_gate_state": "PASSED",
        },
        "exporter": {
            "package": "plamen-runbundle-exporter",
            "version": "2.0.0",
            "code_sha256": "a" * 64,
            "schema_set_sha256": "b" * 64,
            "invocation_policy_sha256": "c" * 64,
        },
        "public_launch_receipt": None,
    }
    manifest["run_context_authority"] = _sign_authority_receipt(
        "run-context-authority-001",
        "RUN_CONTEXT",
        [RUN_ID, lock["case_id"], EXPERIMENT_ID, CELL_ID],
        decision="AUTHORIZED_RUN_CONTEXT",
        decision_payload=C.run_context_commitment_payload(manifest),
    )
    return manifest


def _resign_run_context(manifest: dict[str, object]) -> None:
    manifest["run_context_authority"] = _sign_authority_receipt(
        "run-context-authority-001",
        "RUN_CONTEXT",
        [
            manifest["run_id"],
            manifest["case_id"],
            manifest["experiment_id"],
            manifest["cell_id"],
        ],
        decision="AUTHORIZED_RUN_CONTEXT",
        decision_payload=C.run_context_commitment_payload(manifest),
    )


def _signed_measurement_authorities(
    manifest: dict[str, object],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    budget = manifest["budget"]
    refs = list(budget["measurement_receipt_refs"])
    measured = copy.deepcopy(budget["measured_consumption"])
    resume = copy.deepcopy(manifest["resume"])
    known_ids = {
        receipt["receipt_id"] for receipt in _authority_receipts()
    }
    replacements: list[dict[str, object]] = []
    additions: list[dict[str, object]] = []
    for receipt_id in refs:
        receipt = _sign_authority_receipt(
            receipt_id,
            "RESOURCE_MEASUREMENT",
            [manifest["run_id"]],
            decision="MEASURED",
            decision_payload=_measurement_receipt_payload(
                run_id=manifest["run_id"],
                measured_consumption=measured,
                resume=resume,
            ),
        )
        (replacements if receipt_id in known_ids else additions).append(
            receipt
        )
    replacements.append(
        _sign_authority_receipt(
            budget["measurement_summary_receipt_ref"],
            "RESOURCE_MEASUREMENT_SUMMARY",
            [manifest["run_id"], *refs],
            decision="SUMMARIZED",
            decision_payload=_measurement_summary_payload(
                run_id=manifest["run_id"],
                measurement_receipt_refs=refs,
                measured_consumption=measured,
                resume=resume,
            ),
        )
    )
    return replacements, additions


def _resign_phase_output_authorities(
    documents: dict[str, object],
) -> list[dict[str, object]]:
    artifacts = {
        row["artifact_id"]: row
        for row in documents["raw_outputs.json"]["artifacts"]
    }
    return [
        _sign_authority_receipt(
            event["source_receipt_id"],
            "PHASE_OUTPUT",
            [event["event_id"], event["work_unit_id"]],
            source_artifact_ids=event["source_artifact_ids"],
            decision=event["event_type"],
            decision_payload=C._phase_output_payload(event, artifacts),
        )
        for event in documents["phase_events.jsonl"]
    ]


def _event() -> dict[str, object]:
    return {
        "schema_version": C.PHASE_EVENT_SCHEMA,
        "event_id": "event-00000001",
        "run_id": RUN_ID,
        "sequence": 1,
        "attempt": 1,
        "native_phase": "breadth",
        "macro_phase": "breadth",
        "work_unit_id": "work-breadth-001",
        "event_type": "OUTPUTS_COMMITTED",
        "commit_state": "CLEAN",
        "source_artifact_ids": ["artifact-authorities-001"],
        "input_artifact_ids": [],
        "output_artifact_ids": ["artifact-breadth-001"],
        "artifact_relations": [
            {
                "artifact_id": "artifact-authorities-001",
                "relation": "SOURCE",
            },
            {
                "artifact_id": "artifact-breadth-001",
                "relation": "OUTPUT",
            },
        ],
        "source_receipt_id": "receipt-recon-001",
        "observed_at": "2026-07-24T12:00:00Z",
        "evidence_quality": "AUTHENTICATED",
    }


def _report_event() -> dict[str, object]:
    event = _report_phase_output_fixture_payload()["event"]
    return {
        **event,
        "source_receipt_id": "receipt-report-event-001",
    }


def _candidate_set() -> dict[str, object]:
    return {
        "schema_version": C.CANDIDATE_SET_SCHEMA,
        "run_id": RUN_ID,
        "candidates": [
            {
                "candidate_id": "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F",
                "first_occurrence_id": "occurrence-0001",
                "native_candidate_ids": ["native-finding-001"],
                "producer": {
                    "adapter_id": "plamen-native",
                    "native_phase": "breadth",
                    "work_unit_id": "work-breadth-001",
                    "artifact_id": "artifact-breadth-001",
                    "record_id": "record-001",
                },
                "claim": {
                    "title": "Unchecked accounting transition",
                    "mechanism": "A state update omits a conservation check.",
                    "description": "The exported claim preserves the source wording.",
                    "impact": "Accounting can diverge.",
                    "preconditions": ["The affected transition is reachable."],
                },
                "locations": [
                    {
                        "relative_path": "src/Vault.sol",
                        "function": "settle",
                        "line_start": 42,
                        "line_end": 44,
                        "location_state": "EXACT",
                        "source_record_id": "record-001",
                    }
                ],
                "evidence_refs": ["artifact-breadth-001#record-001"],
                "audit_severity": {
                    "label": "HIGH",
                    "authority_receipt_id": "severity-receipt-001",
                },
                "quality": {
                    "parse_completeness": "COMPLETE",
                    "location_quality": "EXACT",
                    "evidence_quality": "AUTHENTICATED",
                    "debts": [],
                },
                "audit_cluster_id": None,
            }
        ],
    }


def _lineage() -> dict[str, object]:
    location = copy.deepcopy(_candidate_set()["candidates"][0]["locations"])
    return {
        "schema_version": C.CANDIDATE_LINEAGE_SCHEMA,
        "run_id": RUN_ID,
        "occurrences": [
            {
                "occurrence_id": "occurrence-0001",
                "candidate_id": "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F",
                "native_phase": "breadth",
                "macro_phase": "breadth",
                "artifact_id": "artifact-breadth-001",
                "record_id": "record-001",
                "record_sha256": C.sha256_bytes(DISCOVERY_RAW),
                "byte_range": {"start": 0, "end": len(DISCOVERY_RAW)},
                "role": "DISCOVERY",
                "state": "POSITIVE",
                "asserted_severity": "HIGH",
                "location_snapshot": location,
                "evidence_refs": ["artifact-breadth-001#record-001"],
                "authority_ref": "receipt-breadth-001",
            }
        ],
        "edges": [],
        "alias_classes": [],
        "negative_dispositions": [],
        "lineage_debts": [],
    }


def _raw_outputs() -> dict[str, object]:
    return {
        "schema_version": C.RAW_OUTPUT_INDEX_SCHEMA,
        "run_id": RUN_ID,
        "authority_receipts": copy.deepcopy(AUTHORITY_BINDINGS),
        "artifacts": [
            {
                "artifact_id": "artifact-authorities-001",
                "relative_source_path": ".scratchpad/control/authorities.json",
                "native_phase": "recon",
                "macro_phase": "recon",
                "work_unit_id": "work-control-001",
                "producer_kind": "PLAMEN_AUTHORITY",
                "media_type": "application/json",
                "byte_length": len(AUTHORITY_RAW),
                "sha256": C.sha256_bytes(AUTHORITY_RAW),
                "storage": "INLINE_UTF8",
                "content": AUTHORITY_RAW.decode("utf-8"),
                "record_ids": sorted(
                    binding["receipt_id"] for binding in AUTHORITY_BINDINGS
                ),
                "source_contract_ref": "typed-authority-fixture.v1",
                "commit_state": "CLEAN",
                "redactions": [],
            },
            {
                "artifact_id": "artifact-breadth-001",
                "relative_source_path": ".scratchpad/breadth/findings.md",
                "native_phase": "breadth",
                "macro_phase": "breadth",
                "work_unit_id": "work-breadth-001",
                "producer_kind": "PLAMEN_AUTHORITY",
                "media_type": "text/markdown",
                "byte_length": len(DISCOVERY_RAW),
                "sha256": C.sha256_bytes(DISCOVERY_RAW),
                "storage": "INLINE_UTF8",
                "content": DISCOVERY_RAW.decode("utf-8"),
                "record_ids": ["record-001"],
                "source_contract_ref": "finding-output-format.v1",
                "commit_state": "CLEAN",
                "redactions": [],
            },
            {
                "artifact_id": "artifact-final-report",
                "relative_source_path": "AUDIT_REPORT.md",
                "native_phase": "report_assemble",
                "macro_phase": "report",
                "work_unit_id": "work-report-001",
                "producer_kind": "FINAL_REPORT",
                "media_type": "text/markdown",
                "byte_length": len(REPORT_RAW),
                "sha256": C.sha256_bytes(REPORT_RAW),
                "storage": "INLINE_UTF8",
                "content": REPORT_RAW.decode("utf-8"),
                "record_ids": ["evidence-record-001", "report-record-001"],
                "source_contract_ref": C.REPORT_PROJECTION_SCHEMA,
                "commit_state": "CLEAN",
                "redactions": [],
            },
        ],
    }


def _report_projection() -> dict[str, object]:
    return {
        "schema_version": C.REPORT_PROJECTION_SCHEMA,
        "run_id": RUN_ID,
        "final_report_artifact_id": "artifact-final-report",
        "final_report_sha256": C.sha256_bytes(REPORT_RAW),
        "final_report_byte_length": len(REPORT_RAW),
        "delivery_state": "DELIVERED",
        "report_entries": [
            {
                "report_entry_id": "report-entry-001",
                "section_locator": "finding-1",
                "byte_range": {"start": 0, "end": len(REPORT_RAW)},
                "byte_range_sha256": C.sha256_bytes(REPORT_RAW),
                "candidate_ids": ["C2-7M3KQ9VX2N4P6W8R5T2Y1D0F"],
                "audit_alias_class_id": None,
                "asserted_severity": "HIGH",
                "evidence_record_refs": ["evidence-record-001"],
                "report_status": "REPORTED",
            }
        ],
        "appendix_entries": [],
        "unmapped_finding_sections": [],
        "candidate_report_dispositions": [
            {
                "candidate_id": "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F",
                "report_status": "REPORTED",
                "authority_receipt_id": "report-disposition-001",
                "debt_code": None,
            }
        ],
        "report_evidence_quality_receipt_ref": "report-quality-001",
        "report_integrity_state": "SHIP",
    }


def _harvest_receipt() -> dict[str, object]:
    receipt: dict[str, object] = {
        "schema_version": C.HARVEST_RECEIPT_SCHEMA,
        "run_id": RUN_ID,
        "source_snapshot": {
            "source_snapshot_sha256": "2" * 64,
            "before_sha256": "2" * 64,
            "after_sha256": "2" * 64,
            "stable": True,
        },
        "artifact_roster": {
            "count": 3,
            "ids": [
                "artifact-authorities-001",
                "artifact-breadth-001",
                "artifact-final-report",
            ],
        },
        "record_reconciliation": {
            "discovered_count": 1 + len(_base_nonfinding_rows()),
            "emitted_occurrence_count": 1,
            "nonfinding_count": len(_base_nonfinding_rows()),
            "debt_count": 0,
            "balanced": True,
            "occurrence_record_ids": ["record-001"],
            "authenticated_nonfinding_records": [
                {
                    **row,
                    "authority_receipt_id": "record-partition-001",
                }
                for row in _base_nonfinding_rows()
            ],
            "explicit_debt_records": [],
            "partition_authority": copy.deepcopy(BASE_PARTITION_AUTHORITY),
        },
        "candidate_roster": {
            "count": 1,
            "ids": ["C2-7M3KQ9VX2N4P6W8R5T2Y1D0F"],
        },
        "occurrence_roster": {"count": 1, "ids": ["occurrence-0001"]},
        "edge_roster": {"count": 0, "ids": []},
        "report_entry_roster": {"count": 1, "ids": ["report-entry-001"]},
        "redaction_summary": {"count": 0, "entries": []},
        "privacy_scan": {
            "status": "PASSED",
            "issue_count": 0,
            "policy_id": P.PUBLIC_STRUCTURAL_SCAN_POLICY_ID,
            "policy_version": P.PUBLIC_STRUCTURAL_SCAN_POLICY_VERSION,
            "claim_scope": "PUBLIC_STRUCTURAL_EXCLUSION_ONLY",
            "policy_sha256": P.public_structural_scan_policy_sha256(),
        },
        "export_status": {"state": "COMPLETE", "debts": []},
    }
    return C.bind_embedded_sha256(receipt, "receipt_sha256")


def _documents() -> dict[str, object]:
    lock = _public_lock()
    return {
        "run_manifest.json": _manifest(lock),
        "phase_events.jsonl": [_event(), _report_event()],
        "candidate_findings.json": _candidate_set(),
        "candidate_lineage.json": _lineage(),
        "raw_outputs.json": _raw_outputs(),
        "report_projection.json": _report_projection(),
        "harvest_receipt.json": _harvest_receipt(),
    }


def _current_authority_receipts(
    documents: dict[str, object],
) -> list[dict[str, object]]:
    raw_outputs = documents["raw_outputs.json"]
    artifact = next(
        row
        for row in raw_outputs["artifacts"]
        if row["artifact_id"] == "artifact-authorities-001"
    )
    raw = artifact["content"].encode("utf-8")
    return [
        C.strict_json_loads(
            raw[
                binding["byte_range"]["start"] : binding["byte_range"]["end"]
            ],
            require_canonical=True,
        )
        for binding in raw_outputs["authority_receipts"]
    ]


def _rebind_partition_and_harvest(
    documents: dict[str, object],
    *,
    _nonfinding_current: bool = False,
) -> None:
    if not _nonfinding_current:
        _replace_authority_receipts(
            documents,
            [],
            base_receipts=_current_authority_receipts(documents),
            _skip_rebind=True,
        )
    artifacts = {
        row["artifact_id"]: row
        for row in documents["raw_outputs.json"]["artifacts"]
    }
    grouped_occurrences: dict[str, list[dict[str, object]]] = {}
    for occurrence in documents["candidate_lineage.json"]["occurrences"]:
        grouped_occurrences.setdefault(occurrence["record_id"], []).append(
            occurrence
        )
    occurrence_rows = []
    for record_id, occurrences in grouped_occurrences.items():
        first = occurrences[0]
        occurrence_rows.append(
            {
                "record_id": record_id,
                "artifact_id": first["artifact_id"],
                "byte_range": copy.deepcopy(first["byte_range"]),
                "record_sha256": first["record_sha256"],
                "producer_kind": artifacts[first["artifact_id"]][
                    "producer_kind"
                ],
                "source_contract_ref": artifacts[first["artifact_id"]][
                    "source_contract_ref"
                ],
                "occurrence_ids": sorted(
                    occurrence["occurrence_id"]
                    for occurrence in occurrences
                ),
            }
        )
    occurrence_rows.sort(key=lambda row: row["record_id"])
    reconciliation = documents["harvest_receipt.json"]["record_reconciliation"]
    nonfinding_rows = [
        {
            key: value
            for key, value in row.items()
            if key != "authority_receipt_id"
        }
        for row in reconciliation["authenticated_nonfinding_records"]
    ]
    debt_rows = [
        {
            key: value
            for key, value in row.items()
            if key != "authority_receipt_id"
        }
        for row in reconciliation["explicit_debt_records"]
    ]
    reconciliation["partition_authority"] = _partition_authority(
        artifact_rows=sorted(
            [
                {
                    "artifact_id": artifact["artifact_id"],
                    "byte_length": artifact["byte_length"],
                    "sha256": artifact["sha256"],
                    "producer_kind": artifact["producer_kind"],
                    "source_contract_ref": artifact["source_contract_ref"],
                    "record_ids": list(artifact["record_ids"]),
                    "parser_completeness": "COMPLETE_RECORD_ENUMERATION",
                }
                for artifact in artifacts.values()
            ],
            key=lambda row: row["artifact_id"],
        ),
        occurrence_rows=occurrence_rows,
        nonfinding_rows=nonfinding_rows,
        debt_rows=debt_rows,
    )
    for row in (
        reconciliation["authenticated_nonfinding_records"]
        + reconciliation["explicit_debt_records"]
    ):
        row["authority_receipt_id"] = "record-partition-001"
    receipt = documents["harvest_receipt.json"]
    documents["harvest_receipt.json"] = C.bind_embedded_sha256(
        {key: value for key, value in receipt.items() if key != "receipt_sha256"},
        "receipt_sha256",
    )


def _terminal_safe_documents(
    pipeline_kind: str = "SC",
) -> dict[str, object]:
    documents = _documents()
    terminal_native_phase = (
        "sc_verify_aggregate"
        if pipeline_kind == "SC"
        else "verify_aggregate"
    )
    documents["run_manifest.json"]["phase_map"] = _phase_map(pipeline_kind)
    _resign_run_context(documents["run_manifest.json"])
    documents["candidate_lineage.json"]["negative_dispositions"].append(
        {
            "disposition_id": "disposition-001",
            "kind": "SAFE",
            "candidate_id": "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F",
            "occurrence_id": "occurrence-0001",
            "native_phase": terminal_native_phase,
            "macro_phase": "verify",
            "authority_receipt_id": "negative-authority-001",
            "premise": "Terminal safe authority after positive discovery.",
            "evidence_refs": ["artifact-breadth-001#record-001"],
            "terminal": True,
            "superseding_occurrence_id": None,
        }
    )
    documents["report_projection.json"]["report_entries"] = []
    documents["report_projection.json"]["candidate_report_dispositions"][0].update(
        {
            "report_status": "OMITTED_WITH_AUTHORITY",
            "authority_receipt_id": "report-omission-001",
        }
    )
    receipt = documents["harvest_receipt.json"]
    receipt["report_entry_roster"] = {"count": 0, "ids": []}
    if pipeline_kind == "L1":
        _replace_authority_receipts(
            documents,
            [
                _sign_authority_receipt(
                    "negative-authority-001",
                    "NEGATIVE_DISPOSITION",
                    [
                        "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F",
                        "occurrence-0001",
                        "disposition-001",
                    ],
                    decision="SAFE",
                    decision_payload={
                        "dispositions": [
                            {
                                "disposition_id": "disposition-001",
                                "kind": "SAFE",
                                "candidate_id": (
                                    "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F"
                                ),
                                "occurrence_id": "occurrence-0001",
                                "native_phase": terminal_native_phase,
                                "macro_phase": "verify",
                                "terminal": True,
                                "superseding_occurrence_id": None,
                                "ordering_basis": (
                                    "PINNED_NATIVE_PHASE_MAP"
                                ),
                            }
                        ]
                    },
                )
            ],
        )
    _rebind_partition_and_harvest(documents)
    return documents


def _physical_bundle(
    root: Path,
    *,
    documents: dict[str, object] | None = None,
    objectify_authority: bool = True,
    object_payloads: dict[str, bytes] | None = None,
) -> tuple[dict[str, object], bytes]:
    docs = copy.deepcopy(documents or _documents())
    lock_bytes = C.canonical_document_bytes(_public_lock())
    if objectify_authority:
        artifact = docs["raw_outputs.json"]["artifacts"][0]
        artifact["storage"] = "OBJECT"
        artifact["object_path"] = "objects/sha256/" + artifact["sha256"]
        del artifact["content"]
    root.mkdir()
    for relative, document in docs.items():
        raw = (
            C.canonical_jsonl_bytes(document)
            if relative == "phase_events.jsonl"
            else C.canonical_document_bytes(document)
        )
        (root / relative).write_bytes(raw)
    (root / "objects" / "sha256").mkdir(parents=True)
    for artifact in docs["raw_outputs.json"]["artifacts"]:
        if artifact["storage"] != "OBJECT":
            continue
        if object_payloads and artifact["artifact_id"] in object_payloads:
            raw = object_payloads[artifact["artifact_id"]]
        elif artifact["artifact_id"] == "artifact-authorities-001":
            raw = AUTHORITY_RAW
        elif artifact["artifact_id"] == "artifact-breadth-001":
            raw = DISCOVERY_RAW
        elif artifact["artifact_id"] == "artifact-final-report":
            raw = REPORT_RAW
        else:  # pragma: no cover - fixture guard
            raise AssertionError("fixture has no physical bytes for object artifact")
        (root / artifact["object_path"]).write_bytes(raw)
    index = P.build_bundle_index(root)
    (root / "bundle_index.json").write_bytes(P.bundle_index_bytes(index))
    (root / "SEALED.sha256").write_bytes(
        P.bundle_seal_sha256(index).encode("ascii") + b"\n"
    )
    return docs, lock_bytes


@pytest.mark.parametrize(
    ("payload", "validator"),
    [
        (_public_lock(), C.validate_public_case_lock),
        (_manifest(), C.validate_run_manifest),
        (_event(), C.validate_phase_event),
        (_candidate_set(), C.validate_candidate_set),
        (_lineage(), C.validate_candidate_lineage),
        (_raw_outputs(), C.validate_raw_output_index),
        (_report_projection(), C.validate_report_projection),
        (_harvest_receipt(), C.validate_harvest_receipt),
    ],
)
def test_closed_v2_golden_fixtures_validate(payload, validator):
    assert validator(copy.deepcopy(payload)) == payload
    assert C.validate_document(copy.deepcopy(payload)) == payload


def test_strict_json_rejects_duplicate_keys_nonfinite_values_and_invalid_utf8():
    with pytest.raises(C.RunBundleContractError, match="duplicate"):
        C.strict_json_loads('{"schema_version":"x","schema_version":"y"}')
    with pytest.raises(C.RunBundleContractError, match="non-finite"):
        C.strict_json_loads('{"value":NaN}')
    with pytest.raises(C.RunBundleContractError, match="UTF-8"):
        C.strict_json_loads(b'{"value":"\xff"}')

    with pytest.raises(C.RunBundleContractError, match="duplicate"):
        C.strict_jsonl_loads(b'{"event_id":"a","event_id":"b"}\n')


def test_canonical_bytes_are_order_independent_and_canonical_input_is_enforced():
    left = {"z": [3, 2, 1], "a": {"y": False, "x": "é"}}
    right = {"a": {"x": "é", "y": False}, "z": [3, 2, 1]}
    assert C.canonical_json_bytes(left) == C.canonical_json_bytes(right)
    assert C.canonical_document_bytes(left).endswith(b"\n")
    assert C.strict_json_loads(
        C.canonical_document_bytes(left), require_canonical=True
    ) == left
    with pytest.raises(C.RunBundleContractError, match="canonical"):
        C.strict_json_loads(json.dumps(left, indent=2), require_canonical=True)
    rows = [{"z": 1, "a": 2}, {"row": 2}]
    assert C.strict_jsonl_loads(
        C.canonical_jsonl_bytes(rows), require_canonical=True
    ) == rows
    with pytest.raises(C.RunBundleContractError, match="canonical"):
        C.strict_jsonl_loads(b'{"a":2, "z":1}\n', require_canonical=True)


def test_unknown_fields_fail_closed_at_every_nested_level():
    manifest = _manifest()
    manifest["surprise"] = True
    with pytest.raises(C.RunBundleContractError, match="unknown"):
        C.validate_run_manifest(manifest)

    nested = _manifest()
    nested["adapter"]["plugin"] = "implicit"
    with pytest.raises(C.RunBundleContractError, match="unknown"):
        C.validate_run_manifest(nested)


@pytest.mark.parametrize(
    "forbidden_key",
    [
        "gt_issue_id",
        "GroundTruthDigest",
        "expected-count",
        "reference_severity",
        "candidate_match_results",
        "rootCauseId",
        "experiment_outcome",
        "winningCell",
        "post_run_score",
        "answerKey",
        "reviewerResult",
        "truthRoot",
        "knownIssueIdentity",
    ],
)
def test_gt_and_post_run_field_names_or_aliases_are_rejected(forbidden_key: str):
    manifest = _manifest()
    manifest["completion"][forbidden_key] = "leak"
    with pytest.raises(C.RunBundleContractError, match="forbidden public field"):
        C.validate_run_manifest(manifest)


def test_only_fixed_false_blinding_keys_are_allowed():
    for field in (
        "ground_truth_available_to_runner",
        "prior_report_available_to_runner",
        "private_case_lock_available_to_runner",
        "grader_labels_available_to_runner",
    ):
        manifest = _manifest()
        manifest["blinding"][field] = True
        with pytest.raises(C.RunBundleContractError, match="must be false"):
            C.validate_run_manifest(manifest)


def test_public_and_private_case_lock_contracts_cannot_mix():
    private = {
        "schema_version": "plamen.private-case-lock.v2",
        "case_id": CASE_ID,
    }
    with pytest.raises(C.RunBundleContractError, match="private"):
        C.validate_document(private)

    manifest = _manifest()
    manifest["private_case_lock_sha256"] = "0" * 64
    with pytest.raises(C.RunBundleContractError, match="forbidden public field"):
        C.validate_run_manifest(manifest)


def test_public_case_lock_binding_is_exact_and_canonical():
    lock = _public_lock()
    manifest = _manifest(lock)
    assert C.validate_public_case_lock_binding(manifest, lock) == (
        manifest["public_case_lock_sha256"]
    )

    changed = copy.deepcopy(lock)
    changed["test_instructions"].append("forge test --match-test hidden")
    with pytest.raises(C.RunBundleContractError, match="binding"):
        C.validate_public_case_lock_binding(manifest, changed)

    upper = copy.deepcopy(manifest)
    upper["public_case_lock_sha256"] = str(
        upper["public_case_lock_sha256"]
    ).upper()
    with pytest.raises(C.RunBundleContractError, match="lowercase"):
        C.validate_run_manifest(upper)


def test_candidate_and_raw_output_paths_use_safe_relative_posix_form():
    candidate_set = _candidate_set()
    candidate_set["candidates"][0]["locations"][0][
        "relative_path"
    ] = "../private/answer.md"
    with pytest.raises(C.RunBundleContractError, match="relative path"):
        C.validate_candidate_set(candidate_set)

    raw = _raw_outputs()
    raw["artifacts"][0]["relative_source_path"] = "C:/private/answer.md"
    with pytest.raises(
        C.RunBundleContractError, match="relative path|absolute user path"
    ):
        C.validate_raw_output_index(raw)


def test_storage_union_and_conservation_counts_fail_closed():
    raw = _raw_outputs()
    raw["artifacts"][0]["object_path"] = "objects/sha256/" + ("0" * 64)
    with pytest.raises(C.RunBundleContractError, match="storage"):
        C.validate_raw_output_index(raw)

    receipt = _harvest_receipt()
    receipt["record_reconciliation"]["balanced"] = False
    receipt = C.bind_embedded_sha256(
        {k: v for k, v in receipt.items() if k != "receipt_sha256"},
        "receipt_sha256",
    )
    with pytest.raises(C.RunBundleContractError, match="conservation"):
        C.validate_harvest_receipt(receipt)


def test_embedded_receipt_digest_is_verified():
    receipt = _harvest_receipt()
    receipt["export_status"]["state"] = "DEGRADED"
    with pytest.raises(C.RunBundleContractError, match="receipt_sha256"):
        C.validate_harvest_receipt(receipt)


def test_bundle_payload_set_binds_one_run_and_public_lock():
    lock = _public_lock()
    documents = _documents()
    assert C.validate_bundle_payload_set(documents, lock) == documents
    documents["phase_events.jsonl"][0]["run_id"] = OTHER_RUN_ID
    with pytest.raises(C.RunBundleContractError, match="run_id"):
        C.validate_bundle_payload_set(documents, lock)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda manifest: manifest.__setitem__("repetition_index", 1),
        lambda manifest: manifest.__setitem__("seed", 18),
        lambda manifest: manifest.__setitem__("audit_system", "EXTERNAL"),
        lambda manifest: manifest["adapter"].__setitem__(
            "adapter_version", "2.0.1"
        ),
        lambda manifest: manifest.__setitem__(
            "experiment_plan_sha256", "d" * 64
        ),
        lambda manifest: manifest.__setitem__(
            "campaign_schedule_sha256", "e" * 64
        ),
        lambda manifest: manifest["model_backend"].__setitem__(
            "model_family", "cross-arm-relabel"
        ),
        lambda manifest: manifest["model_backend"].__setitem__(
            "provider_class", "LOCAL_SUBSCRIPTION"
        ),
        lambda manifest: manifest["tool_policy"].__setitem__(
            "network_policy", "ALLOW_ALL"
        ),
        lambda manifest: manifest["budget"]["reserved_total"].__setitem__(
            "token_count", 100_001
        ),
        lambda manifest: manifest["exporter"].__setitem__(
            "version", "2.0.1"
        ),
        lambda manifest: manifest.__setitem__(
            "public_launch_receipt", "f" * 64
        ),
    ],
    ids=[
        "repetition",
        "seed",
        "audit-system",
        "adapter",
        "plan",
        "schedule",
        "backend-family",
        "backend-provider",
        "tool-policy",
        "budget-policy",
        "exporter",
        "launch-receipt",
    ],
)
def test_signed_run_context_prevents_cross_arm_and_backend_relabeling(mutate):
    documents = _documents()
    mutate(documents["run_manifest.json"])
    with pytest.raises(C.RunBundleContractError, match="RUN_CONTEXT|run context"):
        C.validate_bundle_payload_set(documents, _public_lock())


@pytest.mark.parametrize(
    "field",
    ["token_count", "wall_time_ms", "tool_calls", "model_calls"],
)
def test_unsigned_measured_consumption_relabel_is_rejected(field: str):
    documents = _documents()
    measured = documents["run_manifest.json"]["budget"][
        "measured_consumption"
    ]
    measured[field] += 1

    with pytest.raises(
        C.RunBundleContractError,
        match="RUN_CONTEXT|run context|measurement receipt|measured consumption",
    ):
        C.validate_bundle_payload_set(documents, _public_lock())


def test_unsigned_measurement_receipt_roster_deletion_is_rejected():
    documents = _documents()
    manifest = documents["run_manifest.json"]
    manifest["budget"]["measurement_receipt_refs"].append(
        "measurement-receipt-002"
    )
    _resign_run_context(manifest)
    replacements, additions = _signed_measurement_authorities(manifest)
    _replace_authority_receipts(
        documents,
        replacements,
        additions=additions,
    )
    assert (
        C.validate_bundle_payload_set(documents, _public_lock())
        == documents
    )

    attacked = copy.deepcopy(documents)
    attacked["run_manifest.json"]["budget"][
        "measurement_receipt_refs"
    ].remove("measurement-receipt-002")
    with pytest.raises(
        C.RunBundleContractError,
        match="RUN_CONTEXT|measurement summary|receipt roster",
    ):
        C.validate_bundle_payload_set(attacked, _public_lock())

    resigned_attack = copy.deepcopy(attacked)
    _resign_run_context(resigned_attack["run_manifest.json"])
    with pytest.raises(
        C.RunBundleContractError,
        match="measurement summary.*payload|receipt roster",
    ):
        C.validate_bundle_payload_set(resigned_attack, _public_lock())


def test_duplicate_measurement_receipt_roster_is_rejected():
    documents = _documents()
    documents["run_manifest.json"]["budget"][
        "measurement_receipt_refs"
    ].append("measurement-receipt-001")
    with pytest.raises(C.RunBundleContractError, match="duplicate"):
        C.validate_bundle_payload_set(documents, _public_lock())


def test_attempt2_cannot_replay_attempt1_measurement_receipt():
    documents = _documents()
    manifest = documents["run_manifest.json"]
    manifest["resume"].update(
        {
            "mode": "SAME_RUN_RESUME",
            "attempt": 2,
            "parent_state_seal_sha256": "d" * 64,
        }
    )
    for event in documents["phase_events.jsonl"]:
        event["attempt"] = 2
    _resign_run_context(manifest)
    measurement_replacements, _ = _signed_measurement_authorities(manifest)
    summary_only = [
        receipt
        for receipt in measurement_replacements
        if receipt["authority_type"] == "RESOURCE_MEASUREMENT_SUMMARY"
    ]
    _replace_authority_receipts(
        documents,
        [
            *_resign_phase_output_authorities(documents),
            *summary_only,
        ],
    )

    with pytest.raises(
        C.RunBundleContractError,
        match="measurement receipt.*resume|measurement receipt.*payload",
    ):
        C.validate_bundle_payload_set(documents, _public_lock())


def test_attempt2_measurement_receipt_cannot_replay_a_different_parent():
    documents = _documents()
    manifest = documents["run_manifest.json"]
    manifest["resume"].update(
        {
            "mode": "SAME_RUN_RESUME",
            "attempt": 2,
            "parent_state_seal_sha256": "d" * 64,
        }
    )
    for event in documents["phase_events.jsonl"]:
        event["attempt"] = 2
    _resign_run_context(manifest)
    measurement_replacements, _ = _signed_measurement_authorities(manifest)
    wrong_parent = copy.deepcopy(manifest["resume"])
    wrong_parent["parent_state_seal_sha256"] = "e" * 64
    receipt_with_wrong_parent = _sign_authority_receipt(
        "measurement-receipt-001",
        "RESOURCE_MEASUREMENT",
        [RUN_ID],
        decision="MEASURED",
        decision_payload=_measurement_receipt_payload(
            measured_consumption=manifest["budget"]["measured_consumption"],
            resume=wrong_parent,
        ),
    )
    _replace_authority_receipts(
        documents,
        [
            *_resign_phase_output_authorities(documents),
            *(
                receipt
                for receipt in measurement_replacements
                if receipt["authority_type"]
                == "RESOURCE_MEASUREMENT_SUMMARY"
            ),
            receipt_with_wrong_parent,
        ],
    )
    with pytest.raises(
        C.RunBundleContractError,
        match="measurement receipt.*payload",
    ):
        C.validate_bundle_payload_set(documents, _public_lock())


@pytest.mark.parametrize(
    "authority_type, extra_subject, source_artifact_ids",
    [
        ("RESOURCE_MEASUREMENT", True, []),
        ("RESOURCE_MEASUREMENT", False, ["artifact-breadth-001"]),
        ("RESOURCE_MEASUREMENT_SUMMARY", True, []),
        (
            "RESOURCE_MEASUREMENT_SUMMARY",
            False,
            ["artifact-breadth-001"],
        ),
    ],
)
def test_measurement_authority_subjects_and_sources_are_exact(
    authority_type: str,
    extra_subject: bool,
    source_artifact_ids: list[str],
):
    documents = _documents()
    if authority_type == "RESOURCE_MEASUREMENT":
        receipt_id = "measurement-receipt-001"
        subjects = [RUN_ID]
        payload = _measurement_receipt_payload()
        decision = "MEASURED"
    else:
        receipt_id = "measurement-summary-001"
        subjects = [RUN_ID, "measurement-receipt-001"]
        payload = _measurement_summary_payload()
        decision = "SUMMARIZED"
    if extra_subject:
        subjects.append(OTHER_RUN_ID)
    replacement = _sign_authority_receipt(
        receipt_id,
        authority_type,
        subjects,
        source_artifact_ids=source_artifact_ids,
        decision=decision,
        decision_payload=payload,
    )
    _replace_authority_receipts(documents, [replacement])
    with pytest.raises(
        C.RunBundleContractError,
        match="measurement summary|measurement receipt|source artifact",
    ):
        C.validate_bundle_payload_set(documents, _public_lock())


@pytest.mark.parametrize(
    "authority_type, receipt_id",
    [
        ("RESOURCE_MEASUREMENT", "measurement-receipt-unreferenced"),
        ("RESOURCE_MEASUREMENT_SUMMARY", "measurement-summary-unreferenced"),
    ],
)
def test_unreferenced_measurement_authority_cross_splice_is_rejected(
    authority_type: str,
    receipt_id: str,
):
    documents = _documents()
    if authority_type == "RESOURCE_MEASUREMENT":
        subjects = [RUN_ID]
        decision = "MEASURED"
        payload = _measurement_receipt_payload()
    else:
        subjects = [RUN_ID, "measurement-receipt-001"]
        decision = "SUMMARIZED"
        payload = _measurement_summary_payload()
    extra = _sign_authority_receipt(
        receipt_id,
        authority_type,
        subjects,
        decision=decision,
        decision_payload=payload,
    )
    _replace_authority_receipts(
        documents,
        [],
        additions=[extra],
    )
    with pytest.raises(
        C.RunBundleContractError,
        match="measurement authority inventory|signed receipt roster",
    ):
        C.validate_bundle_payload_set(documents, _public_lock())


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-summary",
        "stale-summary",
        "cross-run-summary",
        "wrong-parent-receipt",
    ],
)
def test_measurement_summary_and_resume_cross_splices_are_rejected(
    mutation: str,
):
    documents = _documents()
    manifest = documents["run_manifest.json"]
    replacements: list[dict[str, object]] = []
    if mutation == "missing-summary":
        manifest["budget"]["measurement_summary_receipt_ref"] = (
            "measurement-summary-missing"
        )
        _resign_run_context(manifest)
    elif mutation == "stale-summary":
        manifest["budget"]["measured_consumption"]["token_count"] += 1
        _resign_run_context(manifest)
        measurement_replacements, _ = _signed_measurement_authorities(
            manifest
        )
        replacements.extend(
            receipt
            for receipt in measurement_replacements
            if receipt["authority_type"] == "RESOURCE_MEASUREMENT"
        )
    elif mutation == "cross-run-summary":
        replacements.append(
            _sign_authority_receipt(
                "measurement-summary-001",
                "RESOURCE_MEASUREMENT_SUMMARY",
                [OTHER_RUN_ID, "measurement-receipt-001"],
                decision="SUMMARIZED",
                decision_payload=_measurement_summary_payload(
                    run_id=OTHER_RUN_ID,
                ),
            )
        )
    else:
        wrong_resume = {
            "mode": "SAME_RUN_RESUME",
            "attempt": 2,
            "parent_state_seal_sha256": "e" * 64,
        }
        replacements.append(
            _sign_authority_receipt(
                "measurement-receipt-001",
                "RESOURCE_MEASUREMENT",
                [RUN_ID],
                decision="MEASURED",
                decision_payload=_measurement_receipt_payload(
                    resume=wrong_resume,
                ),
            )
        )
    if replacements:
        _replace_authority_receipts(documents, replacements)

    with pytest.raises(
        C.RunBundleContractError,
        match=(
            "measurement summary|measurement receipt|typed authority|"
            "measurement authority inventory"
        ),
    ):
        C.validate_bundle_payload_set(documents, _public_lock())


def test_stale_measurement_summary_signature_is_rejected():
    documents = _documents()
    summary = copy.deepcopy(
        next(
            receipt
            for receipt in _authority_receipts()
            if receipt["receipt_id"] == "measurement-summary-001"
        )
    )
    summary["decision_payload"]["measured_consumption"]["token_count"] += 1
    summary["payload_sha256"] = C.sha256_bytes(
        C.canonical_json_bytes(summary["decision_payload"])
    )
    _replace_authority_receipts(documents, [summary])
    with pytest.raises(C.RunBundleContractError, match="signature"):
        C.validate_bundle_payload_set(documents, _public_lock())


def test_legitimate_multi_receipt_measurement_summary_is_accepted():
    documents = _documents()
    manifest = documents["run_manifest.json"]
    manifest["budget"]["measurement_receipt_refs"].append(
        "measurement-receipt-002"
    )
    _resign_run_context(manifest)
    replacements, additions = _signed_measurement_authorities(manifest)
    _replace_authority_receipts(
        documents,
        replacements,
        additions=additions,
    )
    assert (
        C.validate_bundle_payload_set(documents, _public_lock())
        == documents
    )


def test_legitimate_attempt2_measurement_lineage_is_accepted():
    documents = _documents()
    manifest = documents["run_manifest.json"]
    manifest["resume"].update(
        {
            "mode": "SAME_RUN_RESUME",
            "attempt": 2,
            "parent_state_seal_sha256": "d" * 64,
        }
    )
    for event in documents["phase_events.jsonl"]:
        event["attempt"] = 2
    _resign_run_context(manifest)
    measurement_replacements, additions = (
        _signed_measurement_authorities(manifest)
    )
    _replace_authority_receipts(
        documents,
        [
            *_resign_phase_output_authorities(documents),
            *measurement_replacements,
        ],
        additions=additions,
    )
    assert (
        C.validate_bundle_payload_set(documents, _public_lock())
        == documents
    )


def test_unsigned_rag_exposure_relabel_and_signed_lock_contradiction_are_rejected():
    documents = _documents()
    documents["run_manifest.json"]["blinding"][
        "rag_exposure"
    ] = "PUBLIC_ONLY"
    with pytest.raises(C.RunBundleContractError, match="RUN_CONTEXT|RAG|rag"):
        C.validate_bundle_payload_set(documents, _public_lock())

    documents["run_manifest.json"]["tool_policy"][
        "rag_policy"
    ] = "PUBLIC_ONLY"
    _resign_run_context(documents["run_manifest.json"])
    with pytest.raises(C.RunBundleContractError, match="RAG|rag"):
        C.validate_bundle_payload_set(documents, _public_lock())


def test_unsigned_resume_lineage_relabel_and_same_attempt_resume_are_rejected():
    documents = _documents()
    documents["run_manifest.json"]["resume"].update(
        {
            "mode": "SAME_RUN_RESUME",
            "parent_state_seal_sha256": "d" * 64,
        }
    )
    with pytest.raises(C.RunBundleContractError, match="RUN_CONTEXT|resume"):
        C.validate_bundle_payload_set(documents, _public_lock())

    _resign_run_context(documents["run_manifest.json"])
    with pytest.raises(C.RunBundleContractError, match="attempt|resume"):
        C.validate_bundle_payload_set(documents, _public_lock())


def test_signed_semantic_output_cannot_be_relabelled_as_control():
    documents = _documents()
    candidate = documents["candidate_findings.json"]["candidates"][0]
    candidate["producer"]["native_phase"] = "inventory_prepare"
    artifact = next(
        row
        for row in documents["raw_outputs.json"]["artifacts"]
        if row["artifact_id"] == "artifact-breadth-001"
    )
    artifact["native_phase"] = "inventory_prepare"
    artifact["macro_phase"] = "CONTROL"
    occurrence = documents["candidate_lineage.json"]["occurrences"][0]
    occurrence["native_phase"] = "inventory_prepare"
    occurrence["macro_phase"] = "CONTROL"
    event = documents["phase_events.jsonl"][0]
    event["native_phase"] = "inventory_prepare"
    event["macro_phase"] = "CONTROL"
    _replace_authority_receipts(
        documents,
        [
            _sign_authority_receipt(
                "receipt-recon-001",
                "PHASE_OUTPUT",
                ["event-00000001", "work-breadth-001"],
                source_artifact_ids=["artifact-authorities-001"],
                decision="OUTPUTS_COMMITTED",
                decision_payload=_phase_output_fixture_payload(
                    "inventory_prepare",
                    "CONTROL",
                ),
            ),
            _sign_authority_receipt(
                "receipt-report-event-001",
                "PHASE_OUTPUT",
                ["event-report-final-001", "work-report-001"],
                source_artifact_ids=["artifact-breadth-001"],
                decision="REPORT_FINALIZED",
                decision_payload=C._phase_output_payload(
                    documents["phase_events.jsonl"][1],
                    {
                        row["artifact_id"]: row
                        for row in documents["raw_outputs.json"]["artifacts"]
                    },
                ),
            ),
        ],
    )

    with pytest.raises(C.RunBundleContractError, match="CONTROL|semantic"):
        C.validate_bundle_payload_set(documents, _public_lock())


def test_run_context_commitment_is_exact_and_leaves_schedule_bytes_evaluator_side():
    manifest = _manifest()
    payload = C.run_context_commitment_payload(manifest)
    assert payload["run_context"] == {
        "trust_profile": manifest["trust_profile"],
        "run_id": manifest["run_id"],
        "case_id": manifest["case_id"],
        "experiment_id": manifest["experiment_id"],
        "cell_id": manifest["cell_id"],
        "repetition_index": manifest["repetition_index"],
        "seed": manifest["seed"],
        "audit_system": manifest["audit_system"],
        "source_snapshot_sha256": manifest["source_snapshot_sha256"],
        "adapter": manifest["adapter"],
        "phase_map": manifest["phase_map"],
        "model_backend": manifest["model_backend"],
        "tool_policy": manifest["tool_policy"],
        "budget_policy": {
            "regime": manifest["budget"]["regime"],
            "reserved_total": manifest["budget"]["reserved_total"],
            "reserved_channels": manifest["budget"]["reserved_channels"],
            "measured_consumption": manifest["budget"][
                "measured_consumption"
            ],
            "measurement_receipt_refs": manifest["budget"][
                "measurement_receipt_refs"
            ],
            "measurement_summary_receipt_ref": manifest["budget"][
                "measurement_summary_receipt_ref"
            ],
            "parity_group_id": manifest["budget"]["parity_group_id"],
        },
        "blinding": manifest["blinding"],
        "resume": manifest["resume"],
        "experiment_plan_sha256": manifest["experiment_plan_sha256"],
        "campaign_schedule_sha256": manifest["campaign_schedule_sha256"],
        "campaign_schedule_bytes_verification": (
            "REQUIRED_EVALUATOR_SIDE"
        ),
        "public_launch_receipt": manifest["public_launch_receipt"],
        "exporter": manifest["exporter"],
    }
    assert "campaign_schedule_bytes" not in payload["run_context"]


def test_semantic_artifacts_have_one_exact_committed_phase_event():
    documents = _documents()
    C._validate_semantic_event_coverage(
        documents["run_manifest.json"],
        documents["phase_events.jsonl"],
        documents["candidate_findings.json"],
        documents["candidate_lineage.json"],
        documents["raw_outputs.json"],
        documents["report_projection.json"],
    )

    missing = copy.deepcopy(documents)
    missing["phase_events.jsonl"] = missing["phase_events.jsonl"][1:]
    with pytest.raises(C.RunBundleContractError, match="event coverage|covered"):
        C._validate_semantic_event_coverage(
            missing["run_manifest.json"],
            missing["phase_events.jsonl"],
            missing["candidate_findings.json"],
            missing["candidate_lineage.json"],
            missing["raw_outputs.json"],
            missing["report_projection.json"],
        )

    duplicated = copy.deepcopy(documents)
    extra = copy.deepcopy(duplicated["phase_events.jsonl"][0])
    extra["event_id"] = "event-duplicate-001"
    extra["sequence"] = 99
    duplicated["phase_events.jsonl"].append(extra)
    with pytest.raises(C.RunBundleContractError, match="exactly one|event coverage"):
        C._validate_semantic_event_coverage(
            duplicated["run_manifest.json"],
            duplicated["phase_events.jsonl"],
            duplicated["candidate_findings.json"],
            duplicated["candidate_lineage.json"],
            duplicated["raw_outputs.json"],
            duplicated["report_projection.json"],
        )


@pytest.mark.parametrize(
    "semantic_kind, documents_factory, missing_event_index",
    [
        ("candidate", _documents, 0),
        ("disposition", _terminal_safe_documents, 0),
        ("report", _documents, 1),
    ],
)
def test_candidate_disposition_and_report_artifacts_are_each_event_covered(
    semantic_kind: str,
    documents_factory,
    missing_event_index: int,
):
    documents = documents_factory()
    if semantic_kind == "candidate":
        pass
    elif semantic_kind == "disposition":
        assert documents["candidate_lineage.json"]["negative_dispositions"]
    else:
        assert documents["report_projection.json"]["final_report_artifact_id"]
    del documents["phase_events.jsonl"][missing_event_index]
    with pytest.raises(C.RunBundleContractError, match="exactly one|covered"):
        C._validate_semantic_event_coverage(
            documents["run_manifest.json"],
            documents["phase_events.jsonl"],
            documents["candidate_findings.json"],
            documents["candidate_lineage.json"],
            documents["raw_outputs.json"],
            documents["report_projection.json"],
        )


def test_verification_bearing_occurrence_artifact_is_event_covered():
    documents = _documents()
    documents["candidate_lineage.json"]["occurrences"][0][
        "role"
    ] = "VERIFICATION_RESULT"
    C._validate_semantic_event_coverage(
        documents["run_manifest.json"],
        documents["phase_events.jsonl"],
        documents["candidate_findings.json"],
        documents["candidate_lineage.json"],
        documents["raw_outputs.json"],
        documents["report_projection.json"],
    )
    del documents["phase_events.jsonl"][0]
    with pytest.raises(C.RunBundleContractError, match="exactly one|covered"):
        C._validate_semantic_event_coverage(
            documents["run_manifest.json"],
            documents["phase_events.jsonl"],
            documents["candidate_findings.json"],
            documents["candidate_lineage.json"],
            documents["raw_outputs.json"],
            documents["report_projection.json"],
        )


@pytest.mark.parametrize(
    "field, value",
    [
        ("attempt", 2),
        ("native_phase", "recon"),
        ("macro_phase", "recon"),
        ("work_unit_id", "work-other-001"),
        ("commit_state", "DEGRADED"),
    ],
)
def test_semantic_event_coverage_binds_attempt_phase_work_unit_and_commit(
    field: str,
    value: object,
):
    documents = _documents()
    documents["phase_events.jsonl"][0][field] = value
    with pytest.raises(C.RunBundleContractError, match="event coverage|matching"):
        C._validate_semantic_event_coverage(
            documents["run_manifest.json"],
            documents["phase_events.jsonl"],
            documents["candidate_findings.json"],
            documents["candidate_lineage.json"],
            documents["raw_outputs.json"],
            documents["report_projection.json"],
        )


def test_planning_and_handoff_artifacts_require_explicit_control_relation():
    documents = _documents()
    authority_artifact = documents["raw_outputs.json"]["artifacts"][0]
    authority_artifact["producer_kind"] = "PLAMEN_PLANNING_CONTROL"
    with pytest.raises(C.RunBundleContractError, match="CONTROL"):
        C._validate_semantic_event_coverage(
            documents["run_manifest.json"],
            documents["phase_events.jsonl"],
            documents["candidate_findings.json"],
            documents["candidate_lineage.json"],
            documents["raw_outputs.json"],
            documents["report_projection.json"],
        )

    authority_relation = documents["phase_events.jsonl"][0][
        "artifact_relations"
    ][0]
    authority_relation["relation"] = "CONTROL"
    C._validate_semantic_event_coverage(
        documents["run_manifest.json"],
        documents["phase_events.jsonl"],
        documents["candidate_findings.json"],
        documents["candidate_lineage.json"],
        documents["raw_outputs.json"],
        documents["report_projection.json"],
    )


def test_harvest_public_scan_receipt_binds_exact_evaluator_policy():
    scan = {
        "status": "PASSED",
        "issue_count": 0,
        "policy_id": P.PUBLIC_STRUCTURAL_SCAN_POLICY_ID,
        "policy_version": P.PUBLIC_STRUCTURAL_SCAN_POLICY_VERSION,
        "claim_scope": "PUBLIC_STRUCTURAL_EXCLUSION_ONLY",
        "policy_sha256": P.public_structural_scan_policy_sha256(),
    }
    C._validate_privacy_scan(scan, "fixture public structural scan")
    for field, value in (
        ("policy_id", "exporter-defined-policy"),
        ("policy_version", "999"),
        ("claim_scope", "PRIVATE_CORPUS_ISOLATION"),
        ("policy_sha256", "f" * 64),
    ):
        changed = copy.deepcopy(scan)
        changed[field] = value
        with pytest.raises(C.RunBundleContractError, match="policy|scope"):
            C._validate_privacy_scan(
                changed,
                "fixture public structural scan",
            )


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("case", "case-spectra"),
        ("case", "case-dodo"),
        ("case", "case-issue001"),
        ("cell", "cell-G1A1"),
        ("run", "run-20260724-control"),
    ],
)
def test_opaque_identifiers_require_entropy_and_checksum(kind: str, value: str):
    with pytest.raises(C.RunBundleContractError, match="opaque"):
        C.validate_opaque_id(value, kind)


def test_opaque_identifier_generation_is_checksummed_and_locally_allocated():
    allocation = C.allocate_opaque_id("case")
    assert allocation.authority_type == "LOCAL_OS_RANDOM_ALLOCATION"
    assert allocation.entropy_bits == 128
    assert C.validate_opaque_id(allocation.opaque_id, "case") == allocation.opaque_id
    tampered = allocation.opaque_id[:-1] + (
        "a" if allocation.opaque_id[-1] != "a" else "b"
    )
    with pytest.raises(C.RunBundleContractError, match="checksum"):
        C.validate_opaque_id(tampered, "case")
    with pytest.raises(C.RunBundleContractError, match="allocation"):
        C.derive_opaque_id(
            "case",
            {"allocation_nonce": "public-and-enumerable"},
            domain="case-allocation-v2",
        )
    with pytest.raises(C.RunBundleContractError, match="allocation"):
        C.opaque_id_from_entropy("nonce", b"\0" * 16)
    with pytest.raises((TypeError, C.RunBundleContractError)):
        C.OpaqueIdAllocation(
            opaque_id=CASE_ID,
            kind="case",
            authority_type="LOCAL_OS_RANDOM_ALLOCATION",
            entropy_bits=128,
            nonce_commitment_sha256=H,
        )


def test_case_cell_and_nonce_require_exact_typed_allocation_authority():
    lock = _public_lock()
    del lock["allocation_authority"]
    with pytest.raises(C.RunBundleContractError, match="allocation"):
        C.validate_public_case_lock(lock)

    manifest = _manifest()
    del manifest["allocation_authority_ref"]
    with pytest.raises(C.RunBundleContractError, match="allocation"):
        C.validate_run_manifest(manifest)

    lock = _public_lock()
    lock["allocation_authority"]["allocation_reveal_b64"] = (
        base64.urlsafe_b64encode(b"\0" * 32).decode("ascii").rstrip("=")
    )
    lock["allocation_authority"] = C.bind_embedded_sha256(
        {
            key: value
            for key, value in lock["allocation_authority"].items()
            if key != "receipt_sha256"
        },
        "receipt_sha256",
    )
    with pytest.raises(C.RunBundleContractError, match="commitment|allocation"):
        C.validate_public_case_lock(lock)


def test_run_and_parity_ids_cannot_use_public_deterministic_derivation():
    for kind in ("run", "parity"):
        with pytest.raises(C.RunBundleContractError, match="allocation"):
            C.derive_opaque_id(
                kind,
                {"schedule_row": 1, "public": True},
                domain="enumerable-allocation",
            )


def test_public_case_lock_must_be_loaded_from_exact_canonical_file_bytes(
    tmp_path: Path,
):
    lock = _public_lock()
    canonical = tmp_path / "public-lock.json"
    canonical.write_bytes(C.canonical_document_bytes(lock))
    assert C.load_public_case_lock(canonical) == lock
    assert C.public_case_lock_file_sha256(canonical) == C.public_case_lock_sha256(
        lock
    )

    pretty = tmp_path / "pretty-public-lock.json"
    pretty.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    with pytest.raises(C.RunBundleContractError, match="canonical"):
        C.load_public_case_lock(pretty)


@pytest.mark.parametrize(
    ("label", "mutate"),
    [
            (
                "phase event artifact",
                lambda docs: docs["phase_events.jsonl"][0].update(
                    {
                        "output_artifact_ids": sorted(
                            docs["phase_events.jsonl"][0]["output_artifact_ids"]
                            + ["artifact-orphan"]
                        )
                    }
                ),
        ),
        (
            "candidate producer artifact",
            lambda docs: docs["candidate_findings.json"]["candidates"][0][
                "producer"
            ].update({"artifact_id": "artifact-orphan"}),
        ),
        (
            "candidate producer record",
            lambda docs: docs["candidate_findings.json"]["candidates"][0][
                "producer"
            ].update({"record_id": "record-orphan"}),
        ),
        (
            "occurrence artifact",
            lambda docs: docs["candidate_lineage.json"]["occurrences"][0].update(
                {"artifact_id": "artifact-orphan"}
            ),
        ),
        (
            "report disposition candidate",
            lambda docs: docs["report_projection.json"][
                "candidate_report_dispositions"
            ][0].update({"candidate_id": "candidate-orphan"}),
        ),
        (
            "final report artifact",
            lambda docs: docs["report_projection.json"].update(
                {"final_report_artifact_id": "artifact-orphan"}
            ),
        ),
        (
            "event source receipt",
            lambda docs: docs["phase_events.jsonl"][0].update(
                {"source_receipt_id": "receipt-orphan"}
            ),
        ),
    ],
)
def test_cross_document_orphan_references_fail_closed(label: str, mutate):
    lock = _public_lock()
    documents = _documents()
    mutate(documents)
    with pytest.raises(
        C.RunBundleContractError,
        match="binding|reference|orphan|relation replay",
    ):
        C.validate_bundle_payload_set(documents, lock)


def test_negative_disposition_must_bind_candidate_and_occurrence():
    lock = _public_lock()
    documents = _documents()
    documents["candidate_lineage.json"]["negative_dispositions"].append(
        {
            "disposition_id": "disposition-001",
            "kind": "SAFE",
            "candidate_id": "candidate-orphan",
            "occurrence_id": "occurrence-0001",
            "native_phase": "sc_verify_aggregate",
            "macro_phase": "verify",
            "authority_receipt_id": "negative-authority-001",
            "premise": "Typed negative authority fixture.",
            "evidence_refs": ["artifact-breadth-001#record-001"],
            "terminal": True,
            "superseding_occurrence_id": None,
        }
    )
    with pytest.raises(C.RunBundleContractError, match="disposition.*binding"):
        C.validate_bundle_payload_set(documents, lock)


def test_receipt_counts_are_replayed_from_actual_rows():
    lock = _public_lock()
    documents = _documents()
    receipt = documents["harvest_receipt.json"]
    receipt["record_reconciliation"]["discovered_count"] += 1
    receipt["record_reconciliation"]["debt_count"] += 1
    documents["harvest_receipt.json"] = C.bind_embedded_sha256(
        {key: value for key, value in receipt.items() if key != "receipt_sha256"},
        "receipt_sha256",
    )
    with pytest.raises(C.RunBundleContractError, match="record.*replay|count"):
        C.validate_bundle_payload_set(documents, lock)


def test_record_reconciliation_requires_an_explicit_authenticated_partition():
    lock = _public_lock()
    documents = _documents()
    reconciliation = documents["harvest_receipt.json"]["record_reconciliation"]
    reconciliation["authenticated_nonfinding_records"].pop()
    reconciliation["nonfinding_count"] -= 1
    reconciliation["discovered_count"] -= 1
    documents["harvest_receipt.json"] = C.bind_embedded_sha256(
        {
            key: value
            for key, value in documents["harvest_receipt.json"].items()
            if key != "receipt_sha256"
        },
        "receipt_sha256",
    )
    with pytest.raises(C.RunBundleContractError, match="partition|record"):
        C.validate_bundle_payload_set(documents, lock)


def test_partition_and_report_quality_bind_physical_parser_occurrences():
    lock = _public_lock()
    documents = _documents()
    documents["raw_outputs.json"]["artifacts"][2]["source_contract_ref"] = (
        "unbound-parser-contract.v9"
    )
    with pytest.raises(
        C.RunBundleContractError,
        match=(
            "physical occurrence|partition payload|report quality|"
            "phase event.*payload"
        ),
    ):
        C.validate_bundle_payload_set(documents, lock)


def test_signed_partition_rejects_reclassified_physical_record_coordinates():
    lock = _public_lock()
    documents = _documents()
    row = documents["harvest_receipt.json"]["record_reconciliation"][
        "authenticated_nonfinding_records"
    ][-1]
    row["byte_range"] = {
        "start": row["byte_range"]["start"] + 1,
        "end": row["byte_range"]["end"],
    }
    artifact = next(
        item
        for item in documents["raw_outputs.json"]["artifacts"]
        if item["artifact_id"] == row["artifact_id"]
    )
    raw = artifact["content"].encode("utf-8")
    row["record_sha256"] = C.sha256_bytes(
        raw[row["byte_range"]["start"] : row["byte_range"]["end"]]
    )
    receipt = documents["harvest_receipt.json"]
    documents["harvest_receipt.json"] = C.bind_embedded_sha256(
        {key: value for key, value in receipt.items() if key != "receipt_sha256"},
        "receipt_sha256",
    )
    with pytest.raises(
        C.RunBundleContractError,
        match="partition payload|physical occurrences|report quality|coverage gap",
    ):
        C.validate_bundle_payload_set(documents, lock)


def test_typed_authority_signature_and_exact_range_are_enforced():
    lock = _public_lock()
    documents = _documents()
    artifact = documents["raw_outputs.json"]["artifacts"][0]
    raw = bytearray(artifact["content"].encode("utf-8"))
    binding = documents["raw_outputs.json"]["authority_receipts"][0]
    raw[binding["byte_range"]["end"] - 3] ^= 1
    artifact["content"] = raw.decode("utf-8")
    artifact["byte_length"] = len(raw)
    artifact["sha256"] = C.sha256_bytes(bytes(raw))
    with pytest.raises(C.RunBundleContractError, match="signature|authority"):
        C.validate_bundle_payload_set(documents, lock)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda event: event.update(
            {"source_artifact_ids": ["artifact-breadth-001"]}
        ),
        lambda event: event.update(
            {"source_receipt_id": "severity-receipt-001"}
        ),
    ],
)
def test_phase_source_receipt_is_typed_and_binds_declared_source_artifacts(
    mutate,
):
    lock = _public_lock()
    documents = _documents()
    mutate(documents["phase_events.jsonl"][0])
    with pytest.raises(
        C.RunBundleContractError,
        match="phase.*receipt|source|relation replay",
    ):
        C.validate_bundle_payload_set(documents, lock)


@pytest.mark.parametrize(
    "mutation",
    ["sequence", "input_set", "artifact_phase", "output_phase"],
)
def test_phase_output_authority_commits_canonical_event_and_artifact_facts(
    mutation: str,
):
    lock = _public_lock()
    documents = _documents()
    event = documents["phase_events.jsonl"][0]
    if mutation == "sequence":
        event["sequence"] = 2
    elif mutation == "input_set":
        event["input_artifact_ids"] = ["artifact-breadth-001"]
    elif mutation == "artifact_phase":
        documents["raw_outputs.json"]["artifacts"][0]["work_unit_id"] = (
            "work-unbound-001"
        )
    else:
        documents["raw_outputs.json"]["artifacts"][1]["work_unit_id"] = (
            "work-unbound-001"
        )
        documents["candidate_findings.json"]["candidates"][0]["producer"][
            "work_unit_id"
        ] = "work-unbound-001"
    with pytest.raises(
        C.RunBundleContractError,
        match=(
            "phase.*payload|event.*facts|relation replay|event coverage|"
            "phase events.*sequence"
        ),
    ):
        C.validate_bundle_payload_set(documents, lock)


def test_report_disposition_must_agree_with_actual_projection():
    lock = _public_lock()
    documents = _documents()
    documents["report_projection.json"]["candidate_report_dispositions"][0][
        "report_status"
    ] = "OMITTED_WITH_AUTHORITY"
    with pytest.raises(C.RunBundleContractError, match="report disposition.*projection"):
        C.validate_bundle_payload_set(documents, lock)


def test_record_identities_are_globally_unambiguous():
    lock = _public_lock()
    documents = _documents()
    final_records = documents["raw_outputs.json"]["artifacts"][2]["record_ids"]
    final_records.append("record-001")
    final_records.sort()
    with pytest.raises(C.RunBundleContractError, match="record identity.*duplicated"):
        C.validate_bundle_payload_set(documents, lock)


def test_lineage_debt_references_must_bind_actual_rows():
    lock = _public_lock()
    documents = _documents()
    documents["candidate_lineage.json"]["lineage_debts"].append(
        {
            "debt_id": "debt-001",
            "debt_code": "IDENTITY_CONFLICT",
            "candidate_ids": ["candidate-orphan"],
            "occurrence_ids": ["occurrence-0001"],
            "authority_refs": ["receipt-breadth-001"],
            "detail": "Adversarial orphan fixture.",
        }
    )
    with pytest.raises(C.RunBundleContractError, match="lineage debt.*binding"):
        C.validate_bundle_payload_set(documents, lock)


def test_object_store_index_replays_every_raw_object_reference():
    raw_outputs = _raw_outputs()
    artifact = raw_outputs["artifacts"][0]
    artifact["storage"] = "OBJECT"
    artifact["object_path"] = "objects/sha256/" + artifact["sha256"]
    del artifact["content"]
    index = {
        "schema_version": "plamen.real-audit-bundle-index.v2",
        "bundle_profile": C.REAL_AUDIT_V2,
        "entries": [
            {
                "relative_path": artifact["object_path"],
                "byte_length": artifact["byte_length"],
                "sha256": artifact["sha256"],
            }
        ],
    }
    assert C.validate_bundle_object_bindings(raw_outputs, index) is None

    missing = copy.deepcopy(index)
    missing["entries"] = []
    with pytest.raises(C.RunBundleContractError, match="object.*binding"):
        C.validate_bundle_object_bindings(raw_outputs, missing)

    extra = copy.deepcopy(index)
    extra["entries"].append(
        {
            "relative_path": "objects/sha256/" + ("0" * 64),
            "byte_length": 0,
            "sha256": "0" * 64,
        }
    )
    extra["entries"].sort(key=lambda row: row["relative_path"])
    with pytest.raises(C.RunBundleContractError, match="object.*binding"):
        C.validate_bundle_object_bindings(raw_outputs, extra)


def test_alias_cycle_and_unlisted_applied_edge_fail_closed():
    lock = _public_lock()
    documents = _documents()
    candidate = documents["candidate_findings.json"]["candidates"][0]
    second = copy.deepcopy(candidate)
    second["candidate_id"] = "C2-8N4LR0WY3P5Q7X9S6U3Z2E1G"
    second["first_occurrence_id"] = "occurrence-0002"
    second["native_candidate_ids"] = ["native-finding-002"]
    second["producer"]["record_id"] = "record-001"
    documents["candidate_findings.json"]["candidates"].append(second)

    occurrence = documents["candidate_lineage.json"]["occurrences"][0]
    second_occurrence = copy.deepcopy(occurrence)
    second_occurrence["occurrence_id"] = "occurrence-0002"
    second_occurrence["candidate_id"] = second["candidate_id"]
    second_occurrence["record_id"] = "record-001"
    documents["candidate_lineage.json"]["occurrences"].append(second_occurrence)
    edges = [
        {
            "edge_id": "edge-001",
            "edge_type": "AUTHORIZED_ALIAS",
            "source_candidate_id": candidate["candidate_id"],
            "target_candidate_id": second["candidate_id"],
            "survivor_candidate_id": second["candidate_id"],
            "authority_receipt_id": "alias-authority-001",
            "effective": True,
        },
        {
            "edge_id": "edge-002",
            "edge_type": "AUTHORIZED_ALIAS",
            "source_candidate_id": second["candidate_id"],
            "target_candidate_id": candidate["candidate_id"],
            "survivor_candidate_id": candidate["candidate_id"],
            "authority_receipt_id": "alias-authority-001",
            "effective": True,
        },
    ]
    documents["candidate_lineage.json"]["edges"] = edges
    documents["candidate_lineage.json"]["alias_classes"] = [
        {
            "alias_class_id": C.derive_opaque_id(
                "alias", {"edge_ids": ["edge-001", "edge-002"]}, domain="alias-v1"
            ),
            "survivor_candidate_id": candidate["candidate_id"],
            "candidate_ids": [candidate["candidate_id"], second["candidate_id"]],
            # Deliberately omit edge-002 as well as creating a survivor cycle.
            "applied_edge_ids": ["edge-001"],
        }
    ]
    documents["report_projection.json"]["candidate_report_dispositions"].append(
        {
            "candidate_id": second["candidate_id"],
            "report_status": "OMITTED_WITH_AUTHORITY",
            "authority_receipt_id": "report-omission-001",
            "debt_code": None,
        }
    )
    receipt = documents["harvest_receipt.json"]
    receipt["candidate_roster"] = {
        "count": 2,
        "ids": [candidate["candidate_id"], second["candidate_id"]],
    }
    receipt["occurrence_roster"] = {
        "count": 2,
        "ids": ["occurrence-0001", "occurrence-0002"],
    }
    receipt["edge_roster"] = {"count": 2, "ids": ["edge-001", "edge-002"]}
    receipt["record_reconciliation"].update(
        {
            "discovered_count": 17,
            "emitted_occurrence_count": 1,
            "nonfinding_count": 16,
            "debt_count": 0,
            "balanced": True,
            "occurrence_record_ids": ["record-001"],
        }
    )
    _rebind_partition_and_harvest(documents)
    with pytest.raises(C.RunBundleContractError, match="alias.*cycle|applied.*edge"):
        C.validate_bundle_payload_set(documents, lock)
    documents["candidate_lineage.json"]["alias_classes"][0][
        "applied_edge_ids"
    ] = ["edge-001", "edge-002"]
    with pytest.raises(C.RunBundleContractError, match="alias.*cycle"):
        C.validate_bundle_payload_set(documents, lock)

    documents["candidate_lineage.json"]["edges"] = [edges[0]]
    documents["candidate_lineage.json"]["alias_classes"][0].update(
        {
            "survivor_candidate_id": second["candidate_id"],
            "applied_edge_ids": ["edge-001"],
        }
    )
    alias_class_id = documents["candidate_lineage.json"]["alias_classes"][0][
        "alias_class_id"
    ]
    documents["report_projection.json"]["report_entries"][0].update(
        {
            "candidate_ids": [second["candidate_id"]],
            "audit_alias_class_id": alias_class_id,
        }
    )
    dispositions = documents["report_projection.json"][
        "candidate_report_dispositions"
    ]
    dispositions[0].update(
        {
            "report_status": "OMITTED_WITH_AUTHORITY",
            "authority_receipt_id": "report-omission-001",
        }
    )
    dispositions[1].update(
        {
            "report_status": "REPORTED",
            "authority_receipt_id": "report-disposition-001",
        }
    )
    receipt = documents["harvest_receipt.json"]
    receipt["edge_roster"] = {"count": 1, "ids": ["edge-001"]}
    documents["harvest_receipt.json"] = C.bind_embedded_sha256(
        {key: value for key, value in receipt.items() if key != "receipt_sha256"},
        "receipt_sha256",
    )
    assert C.validate_bundle_payload_set(documents, lock) == documents
    edge = documents["candidate_lineage.json"]["edges"][0]
    edge["source_candidate_id"], edge["target_candidate_id"] = (
        edge["target_candidate_id"],
        edge["source_candidate_id"],
    )
    with pytest.raises(C.RunBundleContractError, match="alias.*payload|direction"):
        C.validate_bundle_payload_set(documents, lock)


def test_cross_document_candidate_phase_severity_and_first_occurrence_replay():
    lock = _public_lock()

    documents = _documents()
    documents["candidate_findings.json"]["candidates"][0][
        "first_occurrence_id"
    ] = "occurrence-0001"
    documents["candidate_lineage.json"]["occurrences"][0][
        "candidate_id"
    ] = "candidate-orphan"
    with pytest.raises(C.RunBundleContractError, match="candidate|occurrence"):
        C.validate_bundle_payload_set(documents, lock)

    documents = _documents()
    documents["candidate_findings.json"]["candidates"][0]["producer"][
        "native_phase"
    ] = "depth"
    with pytest.raises(C.RunBundleContractError, match="producer.*phase"):
        C.validate_bundle_payload_set(documents, lock)

    documents = _documents()
    documents["candidate_lineage.json"]["occurrences"][0]["macro_phase"] = "depth"
    with pytest.raises(C.RunBundleContractError, match="occurrence.*phase"):
        C.validate_bundle_payload_set(documents, lock)

    documents = _documents()
    documents["report_projection.json"]["report_entries"][0][
        "asserted_severity"
    ] = "LOW"
    with pytest.raises(C.RunBundleContractError, match="severity"):
        C.validate_bundle_payload_set(documents, lock)


def test_positive_discovery_can_end_in_terminal_safe_but_not_be_superseded():
    lock = _public_lock()
    documents = _documents()
    safe = {
        "disposition_id": "disposition-001",
        "kind": "SAFE",
        "candidate_id": "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F",
        "occurrence_id": "occurrence-0001",
        "native_phase": "sc_verify_aggregate",
        "macro_phase": "verify",
        "authority_receipt_id": "negative-authority-001",
        "premise": "Terminal safe authority after positive discovery.",
        "evidence_refs": ["artifact-breadth-001#record-001"],
        "terminal": True,
        "superseding_occurrence_id": None,
    }
    documents["candidate_lineage.json"]["negative_dispositions"].append(safe)
    documents["report_projection.json"]["report_entries"] = []
    documents["report_projection.json"]["candidate_report_dispositions"][0].update(
        {
            "report_status": "OMITTED_WITH_AUTHORITY",
            "authority_receipt_id": "report-omission-001",
        }
    )
    receipt = documents["harvest_receipt.json"]
    receipt["report_entry_roster"] = {"count": 0, "ids": []}
    documents["harvest_receipt.json"] = C.bind_embedded_sha256(
        {key: value for key, value in receipt.items() if key != "receipt_sha256"},
        "receipt_sha256",
    )
    assert C.validate_bundle_payload_set(documents, lock) == documents

    safe["superseding_occurrence_id"] = "occurrence-0001"
    with pytest.raises(C.RunBundleContractError, match="terminal SAFE"):
        C.validate_bundle_payload_set(documents, lock)

    reported = _documents()
    reported["candidate_lineage.json"]["negative_dispositions"].append(
        copy.deepcopy({**safe, "superseding_occurrence_id": None})
    )
    with pytest.raises(C.RunBundleContractError, match="terminal SAFE"):
        C.validate_bundle_payload_set(reported, lock)


def test_l1_bake_discovery_precedes_verify_safe_under_pinned_l1_map():
    lock = _public_lock()
    documents = _terminal_safe_documents("L1")
    order = C._pinned_phase_order(documents["run_manifest.json"]["phase_map"])
    assert order["bake"] < order["recon"] < order["breadth"]
    assert C.validate_bundle_payload_set(documents, lock) == documents


def test_phase_map_must_be_evaluator_pinned_and_same_macro_ordering_typed():
    lock = _public_lock()
    documents = _documents()
    documents["run_manifest.json"]["phase_map"]["map_sha256"] = "8" * 64
    with pytest.raises(C.RunBundleContractError, match="phase map|pinned"):
        C.validate_bundle_payload_set(documents, lock)

    documents = _terminal_safe_documents()
    documents["candidate_lineage.json"]["negative_dispositions"][0][
        "native_phase"
    ] = "breadth"
    documents["candidate_lineage.json"]["negative_dispositions"][0][
        "macro_phase"
    ] = "breadth"
    with pytest.raises(C.RunBundleContractError, match="ordering|debt|same native"):
        C.validate_bundle_payload_set(documents, lock)


def test_l1_breadth_discovery_precedes_verify_safe_under_authoritative_map():
    documents = _terminal_safe_documents("L1")
    assert C.validate_bundle_payload_set(documents, _public_lock()) == documents


def test_signed_l1_recon_to_bake_safe_cannot_spoof_macro_order():
    documents = _terminal_safe_documents("L1")

    candidate = documents["candidate_findings.json"]["candidates"][0]
    candidate["producer"]["native_phase"] = "recon"
    artifact = next(
        row
        for row in documents["raw_outputs.json"]["artifacts"]
        if row["artifact_id"] == "artifact-breadth-001"
    )
    artifact["native_phase"] = "recon"
    artifact["macro_phase"] = "recon"
    occurrence = documents["candidate_lineage.json"]["occurrences"][0]
    occurrence["native_phase"] = "recon"
    occurrence["macro_phase"] = "recon"
    event = documents["phase_events.jsonl"][0]
    event["native_phase"] = "recon"
    event["macro_phase"] = "recon"

    disposition = documents["candidate_lineage.json"][
        "negative_dispositions"
    ][0]
    disposition["native_phase"] = "bake"
    # This is the attack: the signed native phase is earlier, while its
    # attacker-selected macro label claims the terminal verifier phase.
    disposition["macro_phase"] = "verify"
    _replace_authority_receipts(
        documents,
        [
            _sign_authority_receipt(
                "receipt-recon-001",
                "PHASE_OUTPUT",
                ["event-00000001", "work-breadth-001"],
                source_artifact_ids=["artifact-authorities-001"],
                decision="OUTPUTS_COMMITTED",
                decision_payload=_phase_output_fixture_payload(
                    "recon", "recon"
                ),
            ),
            _sign_authority_receipt(
                "negative-authority-001",
                "NEGATIVE_DISPOSITION",
                [
                    "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F",
                    "occurrence-0001",
                    "disposition-001",
                ],
                decision="SAFE",
                decision_payload={
                    "dispositions": [
                        {
                            "disposition_id": "disposition-001",
                            "kind": "SAFE",
                            "candidate_id": (
                                "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F"
                            ),
                            "occurrence_id": "occurrence-0001",
                            "native_phase": "bake",
                            "macro_phase": "verify",
                            "terminal": True,
                            "superseding_occurrence_id": None,
                            "ordering_basis": "PINNED_NATIVE_PHASE_MAP",
                        }
                    ]
                },
            ),
        ],
    )

    with pytest.raises(
        C.RunBundleContractError,
        match="native phase|phase ordering|phase map",
    ):
        C.validate_bundle_payload_set(documents, _public_lock())


def test_signed_l1_phase_output_cannot_commit_backward_recon_to_bake():
    documents = _documents()
    documents["run_manifest.json"]["phase_map"] = _phase_map("L1")
    _resign_run_context(documents["run_manifest.json"])
    candidate = documents["candidate_findings.json"]["candidates"][0]
    candidate["producer"]["native_phase"] = "bake"
    artifact = next(
        row
        for row in documents["raw_outputs.json"]["artifacts"]
        if row["artifact_id"] == "artifact-breadth-001"
    )
    artifact["native_phase"] = "bake"
    artifact["macro_phase"] = "bake"
    occurrence = documents["candidate_lineage.json"]["occurrences"][0]
    occurrence["native_phase"] = "bake"
    occurrence["macro_phase"] = "bake"
    event = documents["phase_events.jsonl"][0]
    event["native_phase"] = "bake"
    event["macro_phase"] = "bake"
    _replace_authority_receipts(
        documents,
        [
            _sign_authority_receipt(
                "receipt-recon-001",
                "PHASE_OUTPUT",
                ["event-00000001", "work-breadth-001"],
                source_artifact_ids=["artifact-authorities-001"],
                decision="OUTPUTS_COMMITTED",
                decision_payload=_phase_output_fixture_payload(
                    "bake", "bake"
                ),
            ),
            _sign_authority_receipt(
                "receipt-report-event-001",
                "PHASE_OUTPUT",
                ["event-report-final-001", "work-report-001"],
                source_artifact_ids=["artifact-breadth-001"],
                decision="REPORT_FINALIZED",
                decision_payload=C._phase_output_payload(
                    documents["phase_events.jsonl"][1],
                    {
                        row["artifact_id"]: row
                        for row in documents["raw_outputs.json"]["artifacts"]
                    },
                ),
            ),
        ],
    )

    with pytest.raises(
        C.RunBundleContractError,
        match="phase output.*order|backward|native phase order",
    ):
        C.validate_bundle_payload_set(documents, _public_lock())


def test_complete_sc_bundle_rejects_unknown_native_phase():
    documents = _documents()
    final_artifact = next(
        row
        for row in documents["raw_outputs.json"]["artifacts"]
        if row["artifact_id"] == "artifact-final-report"
    )
    final_artifact["native_phase"] = "future_unpinned_phase"

    with pytest.raises(
        C.RunBundleContractError,
        match="unknown native phase|pinned native phase|completion",
    ):
        C.validate_bundle_payload_set(documents, _public_lock())


def test_unknown_native_phase_requires_explicit_degraded_unmapped_state():
    documents = _documents()
    final_artifact = next(
        row
        for row in documents["raw_outputs.json"]["artifacts"]
        if row["artifact_id"] == "artifact-final-report"
    )
    final_artifact["native_phase"] = "future_unpinned_phase"
    final_artifact["macro_phase"] = "UNMAPPED"
    report_event = documents["phase_events.jsonl"][1]
    report_event["native_phase"] = "future_unpinned_phase"
    report_event["macro_phase"] = "UNMAPPED"
    documents["run_manifest.json"]["completion"].update(
        {
            "state": "DEGRADED",
            "checkpoint_state": "DEGRADED",
            "final_report_gate_state": "DEGRADED",
        }
    )
    documents["report_projection.json"].update(
        {
            "delivery_state": "DEGRADED",
            "report_integrity_state": "DEGRADED",
        }
    )
    documents["harvest_receipt.json"]["export_status"][
        "state"
    ] = "DEGRADED"
    report_quality = next(
        receipt
        for receipt in _authority_receipts()
        if receipt["receipt_id"] == "report-quality-001"
    )
    report_quality_payload = copy.deepcopy(
        report_quality["decision_payload"]
    )
    report_quality_payload["report_integrity_state"] = "DEGRADED"
    _replace_authority_receipts(
        documents,
        [
            _sign_authority_receipt(
                "receipt-report-event-001",
                "PHASE_OUTPUT",
                ["event-report-final-001", "work-report-001"],
                source_artifact_ids=["artifact-breadth-001"],
                decision="REPORT_FINALIZED",
                decision_payload=C._phase_output_payload(
                    report_event,
                    {
                        row["artifact_id"]: row
                        for row in documents["raw_outputs.json"]["artifacts"]
                    },
                ),
            ),
            _sign_authority_receipt(
                "report-quality-001",
                "REPORT_QUALITY",
                list(report_quality["subject_ids"]),
                source_artifact_ids=list(
                    report_quality["source_artifact_ids"]
                ),
                decision="DEGRADED",
                decision_payload=report_quality_payload,
            )
        ],
    )
    assert C.validate_bundle_payload_set(documents, _public_lock()) == documents

    final_artifact["macro_phase"] = "report"
    with pytest.raises(
        C.RunBundleContractError,
        match="unknown native phase.*UNMAPPED",
    ):
        C.validate_bundle_payload_set(documents, _public_lock())


def test_l1_authoritative_map_is_bake_first_and_contains_core_macros():
    phase_map = _phase_map("L1")
    order = C._pinned_phase_order(phase_map)
    assert set(("bake", "recon", "breadth", "inventory", "depth", "verify", "report")) <= set(order)
    assert order["bake"] < order["recon"] < order["breadth"]
    assert order["breadth"] < order["inventory"] < order["depth"]


def test_exact_native_phase_rosters_and_mapping_preimages_are_frozen():
    expected_counts = {"SC": 75, "L1": 59}
    for pipeline_kind, expected_digest in PINNED_PHASE_MAP_SHA256.items():
        preimage = C._pinned_phase_map_preimage(pipeline_kind)
        assert (
            C.sha256_bytes(C.canonical_json_bytes(preimage))
            == expected_digest
        )
        native_rows = preimage["ordered_native_phases"]
        native_names = [row["native_phase"] for row in native_rows]
        assert len(native_rows) == expected_counts[pipeline_kind]
        assert len(native_names) == len(set(native_names))
        assert "verify" not in native_names
        assert "report" not in native_names
        assert native_names.index("recon") < native_names.index("breadth")
        assert native_names.index("report_assemble") < native_names.index(
            "report_floor"
        )
        assert preimage == M.phase_map_preimage(pipeline_kind)
    assert C._pinned_native_phase_order(_phase_map("L1"))["bake"] < (
        C._pinned_native_phase_order(_phase_map("L1"))["recon"]
    )


def test_phase_output_receipt_payload_is_one_exact_event_not_variants():
    with pytest.raises(C.RunBundleContractError, match="event|variant|exact"):
        C._validate_authority_payload_shape(
            "PHASE_OUTPUT",
            {
                "variants": [
                    _phase_output_fixture_payload("breadth", "breadth"),
                    _phase_output_fixture_payload("bake", "bake"),
                ]
            },
            context="phase output red fixture",
        )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda docs: docs["run_manifest.json"]["completion"].update(
            {"state": "INCOMPLETE"}
        ),
        lambda docs: docs["run_manifest.json"]["completion"].update(
            {"checkpoint_state": "UNCOMMITTED"}
        ),
        lambda docs: docs["report_projection.json"].update(
            {"delivery_state": "NOT_DELIVERED"}
        ),
        lambda docs: docs["report_projection.json"].update(
            {"report_integrity_state": "NO_SHIP"}
        ),
        lambda docs: docs["harvest_receipt.json"]["export_status"].update(
            {"state": "DEGRADED"}
        ),
    ],
)
def test_completion_delivery_ship_and_export_states_are_consistent(mutate):
    lock = _public_lock()
    documents = _documents()
    mutate(documents)
    if "receipt_sha256" in documents["harvest_receipt.json"]:
        receipt = documents["harvest_receipt.json"]
        documents["harvest_receipt.json"] = C.bind_embedded_sha256(
            {
                key: value
                for key, value in receipt.items()
                if key != "receipt_sha256"
            },
            "receipt_sha256",
        )
    with pytest.raises(C.RunBundleContractError, match="completion|delivery|SHIP|export"):
        C.validate_bundle_payload_set(documents, lock)


def test_report_section_digest_binds_exact_final_report_byte_range():
    lock = _public_lock()
    documents = _documents()
    entry = documents["report_projection.json"]["report_entries"][0]
    entry["byte_range"] = {"start": 0, "end": 8}
    with pytest.raises(C.RunBundleContractError, match="byte-range"):
        C.validate_bundle_payload_set(documents, lock)
    entry["byte_range_sha256"] = C.sha256_bytes(REPORT_RAW[:8])
    assert C.validate_bundle_payload_set(documents, lock) == documents
    entry["byte_range"] = {"start": 0, "end": 0}
    entry["byte_range_sha256"] = C.sha256_bytes(b"")
    with pytest.raises(C.RunBundleContractError, match="byte_range|byte-range"):
        C.validate_bundle_payload_set(documents, lock)


def test_duplicate_or_overlapping_report_projections_are_rejected():
    lock = _public_lock()
    documents = _documents()
    duplicate = copy.deepcopy(
        documents["report_projection.json"]["report_entries"][0]
    )
    duplicate["report_entry_id"] = "report-entry-002"
    duplicate["byte_range"] = {"start": 1, "end": len(REPORT_RAW)}
    duplicate["byte_range_sha256"] = C.sha256_bytes(REPORT_RAW[1:])
    documents["report_projection.json"]["report_entries"].append(duplicate)
    with pytest.raises(C.RunBundleContractError, match="overlap|duplicate"):
        C.validate_bundle_payload_set(documents, lock)


def test_report_entry_ids_are_globally_unique_across_mapped_and_unmapped():
    report = _report_projection()
    mapped = report["report_entries"][0]
    mapped["byte_range"] = {"start": 0, "end": 8}
    mapped["byte_range_sha256"] = C.sha256_bytes(REPORT_RAW[:8])
    report["unmapped_finding_sections"] = [
        {
            "entry_id": mapped["report_entry_id"],
            "section_locator": "unmapped-finding",
            "byte_range": {"start": 8, "end": len(REPORT_RAW)},
            "byte_range_sha256": C.sha256_bytes(REPORT_RAW[8:]),
            "promoted_candidate_id": "C2-8N4LR0WY3P5Q7X9S6U3Z2E1G",
            "debt_code": "UNAUTHENTICATED_PARSE",
        }
    ]

    with pytest.raises(C.RunBundleContractError, match="duplicate entry IDs"):
        C.validate_report_projection(report)


def test_unmapped_report_section_cannot_reuse_a_mapped_candidate_without_parse_debt():
    lock = _public_lock()
    documents = _documents()
    report = documents["report_projection.json"]
    mapped = report["report_entries"][0]
    mapped["byte_range"] = {"start": 0, "end": 8}
    mapped["byte_range_sha256"] = C.sha256_bytes(REPORT_RAW[:8])
    report["unmapped_finding_sections"] = [
        {
            "entry_id": "unmapped-entry-001",
            "section_locator": "unmapped-finding",
            "byte_range": {"start": 8, "end": len(REPORT_RAW)},
            "byte_range_sha256": C.sha256_bytes(REPORT_RAW[8:]),
            "promoted_candidate_id": mapped["candidate_ids"][0],
            "debt_code": "UNAUTHENTICATED_PARSE",
        }
    ]
    with pytest.raises(
        C.RunBundleContractError,
        match="unmapped.*unique|first occurrence|parse debt|coverage",
    ):
        C.validate_bundle_payload_set(documents, lock)


def test_unmapped_report_section_promotes_unique_parse_debt_with_full_coverage():
    lock = _public_lock()
    documents = _documents()
    first_candidate = documents["candidate_findings.json"]["candidates"][0]
    second_candidate = copy.deepcopy(first_candidate)
    second_candidate["candidate_id"] = "C2-8N4LR0WY3P5Q7X9S6U3Z2E1G"
    second_candidate["first_occurrence_id"] = "occurrence-0002"
    second_candidate["native_candidate_ids"] = ["native-finding-002"]
    second_candidate["producer"].update(
        {
            "native_phase": "report_assemble",
            "work_unit_id": "work-report-001",
            "artifact_id": "artifact-final-report",
            "record_id": "report-record-001",
        }
    )
    second_candidate["locations"][0]["source_record_id"] = "report-record-001"
    second_candidate["evidence_refs"] = [
        "artifact-final-report#report-record-001"
    ]
    second_candidate["quality"]["parse_completeness"] = "PARTIAL"
    second_candidate["quality"]["debts"] = ["UNAUTHENTICATED_PARSE"]
    documents["candidate_findings.json"]["candidates"].append(second_candidate)

    second_occurrence = copy.deepcopy(
        documents["candidate_lineage.json"]["occurrences"][0]
    )
    second_occurrence["occurrence_id"] = "occurrence-0002"
    second_occurrence["candidate_id"] = second_candidate["candidate_id"]
    second_occurrence["native_phase"] = "report_assemble"
    second_occurrence["macro_phase"] = "report"
    second_occurrence["artifact_id"] = "artifact-final-report"
    second_occurrence["record_id"] = "report-record-001"
    second_occurrence["record_sha256"] = C.sha256_bytes(REPORT_RAW[8:])
    second_occurrence["byte_range"] = {"start": 8, "end": len(REPORT_RAW)}
    second_occurrence["role"] = "REPORT_BODY"
    second_occurrence["state"] = "UNKNOWN"
    second_occurrence["authority_ref"] = "UNAUTHENTICATED_PARSE"
    second_occurrence["location_snapshot"][0][
        "source_record_id"
    ] = "report-record-001"
    second_occurrence["evidence_refs"] = [
        "artifact-final-report#report-record-001"
    ]
    documents["candidate_lineage.json"]["occurrences"].append(second_occurrence)
    documents["candidate_lineage.json"]["lineage_debts"] = [
        {
            "debt_id": "debt-unmapped-001",
            "debt_code": "UNAUTHENTICATED_PARSE",
            "candidate_ids": [second_candidate["candidate_id"]],
            "occurrence_ids": ["occurrence-0002"],
            "authority_refs": ["lineage-debt-001"],
            "detail": "Parser-originated candidate promoted from report text.",
        }
    ]
    report = documents["report_projection.json"]
    report["report_entries"][0]["byte_range"] = {"start": 0, "end": 8}
    report["report_entries"][0]["byte_range_sha256"] = C.sha256_bytes(
        REPORT_RAW[:8]
    )
    report["unmapped_finding_sections"] = [
        {
            "entry_id": "unmapped-entry-001",
            "section_locator": "unmapped-finding",
            "byte_range": {"start": 8, "end": len(REPORT_RAW)},
            "byte_range_sha256": C.sha256_bytes(REPORT_RAW[8:]),
            "promoted_candidate_id": second_candidate["candidate_id"],
            "debt_code": "UNAUTHENTICATED_PARSE",
        }
    ]
    report["candidate_report_dispositions"].append(
        {
            "candidate_id": second_candidate["candidate_id"],
            "report_status": "DEBT",
            "authority_receipt_id": "report-debt-001",
            "debt_code": "UNAUTHENTICATED_PARSE",
        }
    )

    receipt = documents["harvest_receipt.json"]
    receipt["candidate_roster"] = {
        "count": 2,
        "ids": [first_candidate["candidate_id"], second_candidate["candidate_id"]],
    }
    receipt["occurrence_roster"] = {
        "count": 2,
        "ids": ["occurrence-0001", "occurrence-0002"],
    }
    receipt["report_entry_roster"] = {
        "count": 2,
        "ids": ["report-entry-001", "unmapped-entry-001"],
    }
    reconciliation = receipt["record_reconciliation"]
    report_occurrence_row = next(
        row
        for row in reconciliation["authenticated_nonfinding_records"]
        if row["record_id"] == "report-record-001"
    )
    reconciliation["authenticated_nonfinding_records"].remove(
        report_occurrence_row
    )
    debt_physical_row = next(
        row
        for row in reconciliation["authenticated_nonfinding_records"]
        if row["record_id"] == "lineage-debt-001"
    )
    reconciliation["authenticated_nonfinding_records"].remove(
        debt_physical_row
    )
    reconciliation["explicit_debt_records"] = [
        {
            **debt_physical_row,
            "debt_id": "debt-unmapped-001",
        }
    ]
    receipt["record_reconciliation"].update(
        {
            "discovered_count": 17,
            "emitted_occurrence_count": 2,
            "nonfinding_count": 14,
            "debt_count": 1,
            "occurrence_record_ids": [
                "record-001",
                "report-record-001",
            ],
        }
    )
    _rebind_partition_and_harvest(documents)
    assert C.validate_bundle_payload_set(documents, lock) == documents


def test_unmapped_candidate_first_occurrence_must_be_the_exact_report_range():
    captured: list[dict[str, object]] = []
    original = C.validate_bundle_payload_set

    def capture(documents, lock, **kwargs):
        result = original(documents, lock, **kwargs)
        captured.append(copy.deepcopy(documents))
        return result

    C.validate_bundle_payload_set = capture
    try:
        test_unmapped_report_section_promotes_unique_parse_debt_with_full_coverage()
    finally:
        C.validate_bundle_payload_set = original
    documents = captured[-1]
    entry = documents["report_projection.json"]["unmapped_finding_sections"][0]
    candidate = next(
        row
        for row in documents["candidate_findings.json"]["candidates"]
        if row["candidate_id"] == entry["promoted_candidate_id"]
    )
    occurrence = next(
        row
        for row in documents["candidate_lineage.json"]["occurrences"]
        if row["occurrence_id"] == candidate["first_occurrence_id"]
    )
    assert occurrence["artifact_id"] == documents["report_projection.json"][
        "final_report_artifact_id"
    ]
    assert occurrence["byte_range"] == entry["byte_range"]
    assert occurrence["record_sha256"] == entry["byte_range_sha256"]
    assert occurrence["role"] in {"REPORT_BODY", "FINAL_REPORT"}


def test_signed_partition_rejects_uncovered_appended_artifact_bytes():
    documents = _documents()
    artifact = next(
        row
        for row in documents["raw_outputs.json"]["artifacts"]
        if row["artifact_id"] == "artifact-final-report"
    )
    raw = artifact["content"].encode("utf-8") + b"\nUNCLASSIFIED RECORD\n"
    artifact["content"] = raw.decode("utf-8")
    artifact["byte_length"] = len(raw)
    artifact["sha256"] = C.sha256_bytes(raw)
    report = documents["report_projection.json"]
    report["final_report_sha256"] = artifact["sha256"]
    report["final_report_byte_length"] = artifact["byte_length"]
    with pytest.raises(
        C.RunBundleContractError,
        match="partition|coverage|artifact|quality",
    ):
        C.validate_bundle_payload_set(documents, _public_lock())


def test_signed_partition_rejects_duplicate_physical_record_rows():
    documents = _documents()
    reconciliation = documents["harvest_receipt.json"]["record_reconciliation"]
    duplicate = copy.deepcopy(
        next(
            row
            for row in reconciliation["authenticated_nonfinding_records"]
            if row["artifact_id"] == "artifact-final-report"
        )
    )
    duplicate["record_id"] = "duplicate-physical-record"
    artifact = next(
        row
        for row in documents["raw_outputs.json"]["artifacts"]
        if row["artifact_id"] == duplicate["artifact_id"]
    )
    artifact["record_ids"].append(duplicate["record_id"])
    artifact["record_ids"].sort()
    reconciliation["authenticated_nonfinding_records"].append(duplicate)
    reconciliation["authenticated_nonfinding_records"].sort(
        key=lambda row: row["record_id"]
    )
    reconciliation["nonfinding_count"] += 1
    reconciliation["discovered_count"] += 1
    _rebind_partition_and_harvest(documents)
    with pytest.raises(
        C.RunBundleContractError,
        match="duplicate|overlap|physical",
    ):
        C.validate_bundle_payload_set(documents, _public_lock())


def test_object_occurrence_requires_exact_physical_bytes_and_range_replay():
    lock = _public_lock()
    documents = _documents()
    artifact = documents["raw_outputs.json"]["artifacts"][1]
    artifact["storage"] = "OBJECT"
    artifact["object_path"] = "objects/sha256/" + artifact["sha256"]
    del artifact["content"]
    with pytest.raises(C.RunBundleContractError, match="physical object"):
        C.validate_bundle_payload_set(documents, lock)
    object_bytes = {artifact["object_path"]: DISCOVERY_RAW}
    assert (
        C.validate_bundle_payload_set(
            documents, lock, object_bytes=object_bytes
        )
        == documents
    )
    object_bytes[artifact["object_path"]] = b"tampered fixture\n"
    with pytest.raises(C.RunBundleContractError, match="object|byte-range"):
        C.validate_bundle_payload_set(
            documents, lock, object_bytes=object_bytes
        )


def test_unified_verifier_scans_referenced_textual_object_bytes(tmp_path: Path):
    documents = _documents()
    leaked = b"finding copied from /app/private/audit.md\n"
    artifact = documents["raw_outputs.json"]["artifacts"][1]
    artifact.update(
        {
            "storage": "OBJECT",
            "object_path": "objects/sha256/" + C.sha256_bytes(leaked),
            "byte_length": len(leaked),
            "sha256": C.sha256_bytes(leaked),
        }
    )
    del artifact["content"]
    occurrence = documents["candidate_lineage.json"]["occurrences"][0]
    occurrence["byte_range"] = {"start": 0, "end": len(leaked)}
    occurrence["record_sha256"] = C.sha256_bytes(leaked)
    root = tmp_path / "text-object-private"
    _, lock_bytes = _physical_bundle(
        root,
        documents=documents,
        object_payloads={"artifact-breadth-001": leaked},
    )
    with pytest.raises(C.RunBundleContractError, match="privacy|path"):
        C.verify_runbundle_v2(root, lock_bytes)


def test_effective_alias_identity_must_survive_into_report_projection():
    lock = _public_lock()
    documents = _documents()
    first_candidate = documents["candidate_findings.json"]["candidates"][0]
    candidate_id = first_candidate["candidate_id"]
    second_candidate = copy.deepcopy(first_candidate)
    second_candidate.update(
        {
            "candidate_id": "C2-8N4LR0WY3P5Q7X9S6U3Z2E1G",
            "first_occurrence_id": "occurrence-0002",
            "native_candidate_ids": ["native-finding-002"],
        }
    )
    second_candidate["producer"]["record_id"] = "record-001"
    documents["candidate_findings.json"]["candidates"].append(second_candidate)
    second_occurrence = copy.deepcopy(
        documents["candidate_lineage.json"]["occurrences"][0]
    )
    second_occurrence.update(
        {
            "occurrence_id": "occurrence-0002",
            "candidate_id": second_candidate["candidate_id"],
            "record_id": "record-001",
        }
    )
    documents["candidate_lineage.json"]["occurrences"].append(second_occurrence)
    documents["candidate_lineage.json"]["edges"] = [
        {
            "edge_id": "edge-001",
            "edge_type": "AUTHORIZED_ALIAS",
            "source_candidate_id": candidate_id,
            "target_candidate_id": second_candidate["candidate_id"],
            "survivor_candidate_id": second_candidate["candidate_id"],
            "authority_receipt_id": "alias-authority-001",
            "effective": True,
        }
    ]
    alias_id = C.derive_opaque_id(
        "alias", {"edge_ids": ["edge-001"]}, domain="alias-v1"
    )
    documents["candidate_lineage.json"]["alias_classes"] = [
        {
            "alias_class_id": alias_id,
            "survivor_candidate_id": second_candidate["candidate_id"],
            "candidate_ids": [candidate_id, second_candidate["candidate_id"]],
            "applied_edge_ids": ["edge-001"],
        }
    ]
    documents["report_projection.json"]["candidate_report_dispositions"].append(
        {
            "candidate_id": second_candidate["candidate_id"],
            "report_status": "OMITTED_WITH_AUTHORITY",
            "authority_receipt_id": "report-omission-001",
            "debt_code": None,
        }
    )
    receipt = documents["harvest_receipt.json"]
    receipt["candidate_roster"] = {
        "count": 2,
        "ids": [candidate_id, second_candidate["candidate_id"]],
    }
    receipt["occurrence_roster"] = {
        "count": 2,
        "ids": ["occurrence-0001", "occurrence-0002"],
    }
    receipt["edge_roster"] = {"count": 1, "ids": ["edge-001"]}
    receipt["record_reconciliation"].update(
        {
            "discovered_count": 17,
            "emitted_occurrence_count": 1,
            "nonfinding_count": 16,
            "debt_count": 0,
            "balanced": True,
            "occurrence_record_ids": ["record-001"],
        }
    )
    _rebind_partition_and_harvest(documents)
    with pytest.raises(C.RunBundleContractError, match="alias.*report"):
        C.validate_bundle_payload_set(documents, lock)


def test_verify_runbundle_v2_validates_physical_bytes_and_returns_frozen_receipt(
    tmp_path: Path,
):
    root = tmp_path / "bundle"
    _, lock_bytes = _physical_bundle(root)
    receipt = C.verify_runbundle_v2(root, lock_bytes)
    assert receipt.bundle_profile == C.REAL_AUDIT_V2
    assert receipt.run_id == RUN_ID
    assert receipt.bundle_seal_sha256 == P.bundle_seal_sha256(
        P.verify_bundle_index(root)
    )
    assert receipt.public_case_lock_sha256 == C.sha256_bytes(lock_bytes)
    assert len(receipt.payload_digests) == 7
    assert len(receipt.object_digests) == 1
    with pytest.raises(FrozenInstanceError):
        receipt.run_id = OTHER_RUN_ID
    with pytest.raises((TypeError, C.RunBundleContractError)):
        C.RunBundleVerificationReceipt(
            bundle_profile=C.REAL_AUDIT_V2,
            run_id=RUN_ID,
            bundle_seal_sha256=H,
            public_case_lock_sha256=H,
            payload_digests=(),
            object_digests=(),
            verification_sha256=H,
        )


def test_verify_runbundle_rejects_sealed_invalid_schema_and_object_only_index(
    tmp_path: Path,
):
    invalid_root = tmp_path / "invalid-schema"
    documents = _documents()
    documents["candidate_findings.json"]["schema_version"] = "unknown.schema.v1"
    _, lock_bytes = _physical_bundle(invalid_root, documents=documents)
    with pytest.raises(C.RunBundleContractError, match="schema"):
        C.verify_runbundle_v2(invalid_root, lock_bytes)

    object_only_root = tmp_path / "object-only"
    _, lock_bytes = _physical_bundle(object_only_root)
    index = P.verify_bundle_index(object_only_root)
    index["entries"] = [
        row for row in index["entries"] if row["relative_path"].startswith("objects/")
    ]
    (object_only_root / "bundle_index.json").write_bytes(P.bundle_index_bytes(index))
    (object_only_root / "SEALED.sha256").write_bytes(
        P.bundle_seal_sha256(index).encode("ascii") + b"\n"
    )
    with pytest.raises(
        (C.RunBundleContractError, P.RunBundlePrivacyError),
        match="index|payload|root",
    ):
        C.verify_runbundle_v2(object_only_root, lock_bytes)

    extra_object_root = tmp_path / "unreferenced-object"
    _, lock_bytes = _physical_bundle(extra_object_root)
    extra = b"valid but unreferenced physical object"
    (extra_object_root / "objects" / "sha256" / C.sha256_bytes(extra)).write_bytes(
        extra
    )
    index = P.build_bundle_index(extra_object_root)
    (extra_object_root / "bundle_index.json").write_bytes(
        P.bundle_index_bytes(index)
    )
    (extra_object_root / "SEALED.sha256").write_bytes(
        P.bundle_seal_sha256(index).encode("ascii") + b"\n"
    )
    with pytest.raises(C.RunBundleContractError, match="object"):
        C.verify_runbundle_v2(extra_object_root, lock_bytes)


def test_verify_runbundle_rejects_noncanonical_lock_duplicate_json_and_privacy(
    tmp_path: Path,
):
    root = tmp_path / "bundle"
    _, lock_bytes = _physical_bundle(root)
    pretty_lock = json.dumps(_public_lock(), indent=2).encode("utf-8") + b"\n"
    with pytest.raises(C.RunBundleContractError, match="canonical"):
        C.verify_runbundle_v2(root, pretty_lock)

    duplicate = tmp_path / "duplicate"
    _, lock_bytes = _physical_bundle(duplicate)
    raw = (duplicate / "run_manifest.json").read_bytes()
    duplicate_raw = raw.replace(
        b'{"adapter":',
        b'{"schema_version":"plamen.real-audit-run-manifest.v2","adapter":',
        1,
    )
    (duplicate / "run_manifest.json").write_bytes(duplicate_raw)
    index = P.build_bundle_index(duplicate)
    (duplicate / "bundle_index.json").write_bytes(P.bundle_index_bytes(index))
    (duplicate / "SEALED.sha256").write_bytes(
        P.bundle_seal_sha256(index).encode("ascii") + b"\n"
    )
    with pytest.raises(C.RunBundleContractError, match="duplicate"):
        C.verify_runbundle_v2(duplicate, lock_bytes)

    private = tmp_path / "private"
    documents = _documents()
    documents["candidate_findings.json"]["candidates"][0]["claim"][
        "preconditions"
    ] = ["sk-proj-", "A" * 30]
    _, lock_bytes = _physical_bundle(private, documents=documents)
    with pytest.raises(
        (C.RunBundleContractError, P.RunBundlePrivacyError),
        match="credential|public payload",
    ):
        C.verify_runbundle_v2(private, lock_bytes)


@pytest.mark.parametrize(
    "token",
    [
        "xox" + "b-123456789012-abcdefghijklmnopqrst",
        "AK" + "IA1234567890ABCDEF",
        "gh" + "p_abcdefghijklmnopqrstuvwxyz123456",
    ],
    ids=["slack", "aws-access-key-id", "github"],
)
def test_sealed_json_rejects_all_canonical_secret_signatures(
    tmp_path: Path,
    token: str,
):
    root = tmp_path / token[:4]
    documents = _documents()
    documents["candidate_findings.json"]["candidates"][0]["claim"][
        "description"
    ] = f"ordinary exported prose {token}"
    _, lock_bytes = _physical_bundle(root, documents=documents)

    with pytest.raises(
        C.RunBundleContractError,
        match="credential|privacy|secret",
    ):
        C.verify_runbundle_v2(root, lock_bytes)


def test_verify_runbundle_stages_then_rereads_and_detects_restored_metadata_mutation(
    tmp_path: Path, monkeypatch
):
    root = tmp_path / "single-read"
    _, lock_bytes = _physical_bundle(root)
    original_read = P.read_stable_regular_bytes
    counts: dict[str, int] = {}

    def counting_read(path, **kwargs):
        relative = Path(path).relative_to(root).as_posix()
        counts[relative] = counts.get(relative, 0) + 1
        return original_read(path, **kwargs)

    monkeypatch.setattr(P, "read_stable_regular_bytes", counting_read)
    C.verify_runbundle_v2(root, lock_bytes)
    assert counts
    assert set(counts.values()) == {2}

    monkeypatch.setattr(P, "read_stable_regular_bytes", original_read)
    original_validate = C.validate_bundle_payload_set

    def mutate_after_validation(*args, **kwargs):
        result = original_validate(*args, **kwargs)
        target = root / "candidate_findings.json"
        before = target.stat()
        raw = target.read_bytes()
        replacement = (
            bytes([raw[0] ^ 1]) + raw[1:]
            if raw
            else raw
        )
        assert len(replacement) == len(raw)
        target.write_bytes(replacement)
        os.utime(
            target,
            ns=(before.st_atime_ns, before.st_mtime_ns),
        )
        return result

    monkeypatch.setattr(C, "validate_bundle_payload_set", mutate_after_validation)
    with pytest.raises(
        (C.RunBundleContractError, P.RunBundlePrivacyError),
        match="changed|mutation",
    ):
        C.verify_runbundle_v2(root, lock_bytes)


def test_double_export_routes_both_trees_through_unified_verifier(
    tmp_path: Path, monkeypatch
):
    lock_bytes = C.canonical_document_bytes(_public_lock())
    calls: list[Path] = []
    original = C.verify_runbundle_v2

    def recording_verify(root, exact_public_lock_bytes):
        calls.append(Path(root))
        return original(root, exact_public_lock_bytes)

    monkeypatch.setattr(C, "verify_runbundle_v2", recording_verify)

    def materialize(root: Path) -> None:
        _physical_bundle(root)

    first = tmp_path / "first-complete"
    second = tmp_path / "second-complete"
    seal = P.prove_deterministic_double_export(
        materialize,
        first,
        second,
        exact_public_lock_bytes=lock_bytes,
    )
    assert calls == [first, second]
    assert seal == original(first, lock_bytes).bundle_seal_sha256


_HIDDEN_AUTHORITY_TYPES = (
    "RESOURCE_MEASUREMENT",
    "RESOURCE_MEASUREMENT_SUMMARY",
    "ALIAS_DECISION",
    "NEGATIVE_DISPOSITION",
    "REPORT_DISPOSITION",
)


def _documents_with_omitted_signed_authority(
    authority_type: str,
) -> dict[str, object]:
    documents = _documents()
    template = next(
        row
        for row in _authority_receipts()
        if row["authority_type"] == authority_type
    )
    hidden_id = "hidden-" + authority_type.lower().replace("_", "-")
    hidden = _sign_authority_receipt(
        hidden_id,
        authority_type,
        list(template["subject_ids"]),
        source_artifact_ids=list(template["source_artifact_ids"]),
        decision=template["decision"],
        decision_payload=copy.deepcopy(template["decision_payload"]),
    )
    raw = C.canonical_document_bytes(hidden)
    artifact = {
        "artifact_id": f"artifact-{hidden_id}",
        "relative_source_path": f".scratchpad/control/{hidden_id}.json",
        "native_phase": "recon",
        "macro_phase": "recon",
        "work_unit_id": f"work-{hidden_id}",
        "producer_kind": "PLAMEN_AUTHORITY",
        "media_type": "application/json",
        "byte_length": len(raw),
        "sha256": C.sha256_bytes(raw),
        "storage": "INLINE_UTF8",
        "content": raw.decode("utf-8"),
        "record_ids": [hidden_id],
        "source_contract_ref": "typed-authority-fixture.v1",
        "commit_state": "CLEAN",
        "redactions": [],
    }
    raw_outputs = documents["raw_outputs.json"]
    raw_outputs["artifacts"].append(artifact)
    raw_outputs["artifacts"].sort(key=lambda row: row["artifact_id"])
    reconciliation = documents["harvest_receipt.json"][
        "record_reconciliation"
    ]
    reconciliation["authenticated_nonfinding_records"].append(
        {
            **_physical_record_row(
                record_id=hidden_id,
                artifact_id=artifact["artifact_id"],
                start=0,
                end=len(raw),
                raw=raw,
                producer_kind=artifact["producer_kind"],
                source_contract_ref=artifact["source_contract_ref"],
            ),
            "authority_receipt_id": "record-partition-001",
        }
    )
    reconciliation["authenticated_nonfinding_records"].sort(
        key=lambda row: row["record_id"]
    )
    reconciliation["nonfinding_count"] = len(
        reconciliation["authenticated_nonfinding_records"]
    )
    reconciliation["discovered_count"] = (
        reconciliation["emitted_occurrence_count"]
        + reconciliation["nonfinding_count"]
        + reconciliation["debt_count"]
    )
    documents["harvest_receipt.json"]["artifact_roster"] = {
        "count": len(raw_outputs["artifacts"]),
        "ids": [row["artifact_id"] for row in raw_outputs["artifacts"]],
    }
    _rebind_partition_and_harvest(documents)
    return documents


@pytest.mark.parametrize("authority_type", _HIDDEN_AUTHORITY_TYPES)
def test_omitted_signed_authority_record_is_rejected_in_memory(
    authority_type: str,
):
    documents = _documents_with_omitted_signed_authority(authority_type)
    with pytest.raises(
        C.RunBundleContractError,
        match="authority.*(index|binding|eligib|coverage)",
    ):
        C.validate_bundle_payload_set(documents, _public_lock())


@pytest.mark.parametrize("authority_type", _HIDDEN_AUTHORITY_TYPES)
def test_omitted_signed_authority_record_is_rejected_physically(
    authority_type: str,
    tmp_path: Path,
):
    documents = _documents_with_omitted_signed_authority(authority_type)
    root = tmp_path / authority_type.lower()
    _, lock_bytes = _physical_bundle(
        root,
        documents=documents,
        objectify_authority=False,
    )
    with pytest.raises(
        C.RunBundleContractError,
        match="authority.*(index|binding|eligib|coverage)",
    ):
        C.verify_runbundle_v2(root, lock_bytes)


def _noncanonical_urlsafe_alias(text: str) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    raw = base64.urlsafe_b64decode(text + ("=" * (-len(text) % 4)))
    for replacement in alphabet:
        candidate = text[:-1] + replacement
        if candidate == text:
            continue
        decoded = base64.urlsafe_b64decode(
            candidate + ("=" * (-len(candidate) % 4))
        )
        if decoded == raw:
            return candidate
    raise AssertionError("fixture has no noncanonical URL-safe Base64 alias")


def test_physical_bundle_rejects_noncanonical_signature_base64(
    tmp_path: Path,
):
    documents = _documents()
    summary = copy.deepcopy(
        next(
            row
            for row in _authority_receipts()
            if row["receipt_id"] == "measurement-summary-001"
        )
    )
    summary["signature_b64"] = _noncanonical_urlsafe_alias(
        summary["signature_b64"]
    )
    _replace_authority_receipts(documents, [summary])
    root = tmp_path / "noncanonical-signature"
    _, lock_bytes = _physical_bundle(
        root,
        documents=documents,
        objectify_authority=False,
    )
    with pytest.raises(C.RunBundleContractError, match="canonical.*signature"):
        C.verify_runbundle_v2(root, lock_bytes)


def test_allocation_reveal_rejects_noncanonical_base64():
    lock = _public_lock()
    allocation = lock["allocation_authority"]
    allocation["allocation_reveal_b64"] = _noncanonical_urlsafe_alias(
        allocation["allocation_reveal_b64"]
    )
    lock["allocation_authority"] = C.bind_embedded_sha256(
        {
            key: value
            for key, value in allocation.items()
            if key != "receipt_sha256"
        },
        "receipt_sha256",
    )
    with pytest.raises(C.RunBundleContractError, match="canonical.*reveal"):
        C.validate_public_case_lock(lock)


def test_physical_bundle_rejects_rsa_representative_at_or_above_modulus(
    tmp_path: Path,
):
    documents = _documents()
    measurement = copy.deepcopy(
        next(
            row
            for row in _authority_receipts()
            if row["receipt_id"] == "measurement-receipt-001"
        )
    )
    signature = base64.urlsafe_b64decode(
        measurement["signature_b64"]
        + ("=" * (-len(measurement["signature_b64"]) % 4))
    )
    representative = int.from_bytes(signature, "big") + RSA_N
    assert representative < 1 << (8 * len(signature))
    measurement["signature_b64"] = base64.urlsafe_b64encode(
        representative.to_bytes(len(signature), "big")
    ).decode("ascii").rstrip("=")
    _replace_authority_receipts(documents, [measurement])
    root = tmp_path / "rsa-out-of-range"
    _, lock_bytes = _physical_bundle(
        root,
        documents=documents,
        objectify_authority=False,
    )
    with pytest.raises(C.RunBundleContractError, match="signature.*range"):
        C.verify_runbundle_v2(root, lock_bytes)


def _documents_with_measurement_receipt_id(
    receipt_id: str,
) -> dict[str, object]:
    documents = _documents()
    manifest = documents["run_manifest.json"]
    manifest["budget"]["measurement_receipt_refs"] = [receipt_id]
    _resign_run_context(manifest)
    retained = [
        copy.deepcopy(row)
        for row in _authority_receipts()
        if row["receipt_id"]
        not in {"measurement-receipt-001", "measurement-summary-001"}
    ]
    retained.extend(
        [
            _sign_authority_receipt(
                receipt_id,
                "RESOURCE_MEASUREMENT",
                [RUN_ID],
                decision="MEASURED",
                decision_payload=_measurement_receipt_payload(),
            ),
            _sign_authority_receipt(
                "measurement-summary-001",
                "RESOURCE_MEASUREMENT_SUMMARY",
                sorted({RUN_ID, receipt_id}),
                decision="SUMMARIZED",
                decision_payload=_measurement_summary_payload(
                    measurement_receipt_refs=[receipt_id]
                ),
            ),
        ]
    )
    _replace_authority_receipts(
        documents,
        [],
        base_receipts=retained,
    )
    return documents


@pytest.mark.parametrize(
    "colliding_id",
    [
        RUN_ID,
        "artifact-breadth-001",
        "record-001",
        "event-00000001",
        "work-breadth-001",
        "C2-7M3KQ9VX2N4P6W8R5T2Y1D0F",
        "debt-unmapped-001",
    ],
    ids=[
        "run",
        "artifact",
        "record",
        "event",
        "work-unit",
        "candidate",
        "debt",
    ],
)
def test_receipt_identity_cannot_collapse_another_typed_namespace(
    colliding_id: str,
):
    documents = _documents_with_measurement_receipt_id(colliding_id)
    with pytest.raises(
        C.RunBundleContractError,
        match="identity namespace|duplicated across artifacts",
    ):
        C.validate_bundle_payload_set(documents, _public_lock())


def test_physical_receipt_id_equal_to_run_id_is_rejected(tmp_path: Path):
    documents = _documents_with_measurement_receipt_id(RUN_ID)
    root = tmp_path / "receipt-run-collision"
    _, lock_bytes = _physical_bundle(
        root,
        documents=documents,
        objectify_authority=False,
    )
    with pytest.raises(C.RunBundleContractError, match="identity namespace"):
        C.verify_runbundle_v2(root, lock_bytes)


def test_verification_receipt_is_explicitly_non_authoritative():
    assert "non-authoritative" in (
        C.RunBundleVerificationReceipt.__doc__ or ""
    ).casefold()
    forged = object.__new__(C.RunBundleVerificationReceipt)
    object.__setattr__(forged, "run_id", "forged")
    assert isinstance(forged, C.RunBundleVerificationReceipt)
    assert forged.run_id == "forged"


def test_public_allocation_receipt_claims_structural_derivation_only():
    allocation = _public_lock()["allocation_authority"]
    combined_claim = " ".join(
        str(allocation[field])
        for field in ("schema_version", "authority_type", "algorithm")
    ).casefold()
    assert "authenticated" not in combined_claim
    assert "csprng" not in combined_claim
    assert "random" not in combined_claim


class _JsonDictSubclass(dict):
    pass


class _JsonListSubclass(list):
    pass


def test_json_collection_subclasses_are_rejected_at_every_ingress():
    documents = _documents()
    with pytest.raises(C.RunBundleContractError, match="exact built-in|JSON"):
        C.validate_bundle_payload_set(
            _JsonDictSubclass(documents),
            _public_lock(),
        )

    documents = _documents()
    documents["run_manifest.json"]["adapter"] = _JsonDictSubclass(
        documents["run_manifest.json"]["adapter"]
    )
    with pytest.raises(C.RunBundleContractError, match="exact built-in|JSON"):
        C.validate_bundle_payload_set(documents, _public_lock())

    documents = _documents()
    documents["phase_events.jsonl"] = _JsonListSubclass(
        documents["phase_events.jsonl"]
    )
    with pytest.raises(C.RunBundleContractError, match="exact built-in|JSON"):
        C.validate_bundle_payload_set(documents, _public_lock())

    manifest = _manifest()
    manifest["budget"]["measurement_receipt_refs"] = _JsonListSubclass(
        manifest["budget"]["measurement_receipt_refs"]
    )
    with pytest.raises(C.RunBundleContractError, match="exact built-in|JSON"):
        C.validate_run_manifest(manifest)


def test_validation_returns_a_fresh_exact_builtin_snapshot():
    source = _manifest()
    validated = C.validate_run_manifest(source)
    assert validated == source
    assert validated is not source
    assert validated["adapter"] is not source["adapter"]
    assert type(validated) is dict
    assert type(validated["adapter"]) is dict
    assert type(validated["budget"]["measurement_receipt_refs"]) is list

    source["adapter"]["adapter_id"] = "mutated-after-validation"
    source["budget"]["measurement_receipt_refs"].append("late-receipt")
    assert validated["adapter"]["adapter_id"] != "mutated-after-validation"
    assert "late-receipt" not in validated["budget"]["measurement_receipt_refs"]

    validated["adapter"]["adapter_id"] = "mutated-result"
    assert source["adapter"]["adapter_id"] != "mutated-result"

    documents = _documents()
    validated_bundle = C.validate_bundle_payload_set(
        documents,
        _public_lock(),
    )
    documents["run_manifest.json"]["adapter"]["adapter_id"] = (
        "late-bundle-mutation"
    )
    assert (
        validated_bundle["run_manifest.json"]["adapter"]["adapter_id"]
        != "late-bundle-mutation"
    )


@pytest.mark.parametrize("authority_type", sorted(C._AUTHORITY_TYPES))
def test_every_typed_authority_rejects_extra_signed_subjects(
    authority_type: str,
):
    if authority_type == "RUN_CONTEXT":
        template = _manifest()["run_context_authority"]
    elif authority_type == "RECORD_PARTITION":
        template = _harvest_receipt()["record_reconciliation"][
            "partition_authority"
        ]
    else:
        template = next(
            row
            for row in _authority_receipts()
            if row["authority_type"] == authority_type
        )
    receipt = _sign_authority_receipt(
        f"extra-subject-{authority_type.lower().replace('_', '-')}",
        authority_type,
        [*template["subject_ids"], "spare-subject"],
        source_artifact_ids=list(template["source_artifact_ids"]),
        decision=template["decision"],
        decision_payload=copy.deepcopy(template["decision_payload"]),
    )
    with pytest.raises(
        C.RunBundleContractError,
        match="subject.*exact",
    ):
        C._validate_signed_authority_receipt(
            receipt,
            _public_lock()["audit_authority"],
            context=f"{authority_type} exact signed subjects",
        )


def test_resigned_severity_authority_rejects_an_extra_subject():
    documents = _documents()
    template = next(
        row
        for row in _authority_receipts()
        if row["receipt_id"] == "severity-receipt-001"
    )
    replacement = _sign_authority_receipt(
        template["receipt_id"],
        template["authority_type"],
        [*template["subject_ids"], "spare-subject-001"],
        source_artifact_ids=list(template["source_artifact_ids"]),
        decision=template["decision"],
        decision_payload=copy.deepcopy(template["decision_payload"]),
    )
    _replace_authority_receipts(documents, [replacement])
    with pytest.raises(
        C.RunBundleContractError,
        match="subject.*exact|typed authority",
    ):
        C.validate_bundle_payload_set(documents, _public_lock())


_TYPED_NAMESPACE_KINDS = (
    "run",
    "receipt",
    "artifact",
    "record",
    "event",
    "work-unit",
    "candidate",
    "occurrence",
    "edge",
    "alias-class",
    "negative-disposition",
    "lineage-debt",
    "report-entry",
)


@pytest.mark.parametrize(
    ("left_kind", "right_kind"),
    list(itertools.combinations(_TYPED_NAMESPACE_KINDS, 2)),
)
def test_every_pairwise_typed_namespace_collision_is_rejected(
    left_kind: str,
    right_kind: str,
):
    namespaces = {
        kind: {f"{kind}-identity"}
        for kind in _TYPED_NAMESPACE_KINDS
    }
    namespaces[left_kind] = {"shared-cross-role-identity"}
    namespaces[right_kind] = {"shared-cross-role-identity"}
    with pytest.raises(C.RunBundleContractError, match="namespace.*collid"):
        C._validate_typed_identity_namespaces(
            namespaces,
            indexed_authority_receipt_ids=frozenset(),
        )


def test_indexed_authority_receipt_record_identity_is_the_only_exception():
    receipt_id = "indexed-authority-receipt"
    namespaces = {
        kind: {f"{kind}-identity"}
        for kind in _TYPED_NAMESPACE_KINDS
    }
    namespaces["receipt"] = {receipt_id}
    namespaces["record"] = {receipt_id}
    C._validate_typed_identity_namespaces(
        namespaces,
        indexed_authority_receipt_ids={receipt_id},
    )

    with pytest.raises(C.RunBundleContractError, match="namespace.*collid"):
        C._validate_typed_identity_namespaces(
            namespaces,
            indexed_authority_receipt_ids=frozenset(),
        )


def test_resigned_artifact_work_unit_namespace_collision_is_rejected():
    documents = _documents()
    artifact_id = "artifact-breadth-001"
    artifact = next(
        row
        for row in documents["raw_outputs.json"]["artifacts"]
        if row["artifact_id"] == artifact_id
    )
    artifact["work_unit_id"] = artifact_id
    for event in documents["phase_events.jsonl"]:
        if artifact_id in event["output_artifact_ids"]:
            event["work_unit_id"] = artifact_id
    for candidate in documents["candidate_findings.json"]["candidates"]:
        if candidate["producer"]["artifact_id"] == artifact_id:
            candidate["producer"]["work_unit_id"] = artifact_id
    _replace_authority_receipts(
        documents,
        _resign_phase_output_authorities(documents),
    )
    with pytest.raises(C.RunBundleContractError, match="namespace.*collid"):
        C.validate_bundle_payload_set(documents, _public_lock())
