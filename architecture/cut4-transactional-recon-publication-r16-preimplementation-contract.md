# Cut-4 transactional recon publication R16 preimplementation contract

Date: 2026-08-10
Status: Part-0 architecture-only repair awaiting independent review
Supersedes: only the four rejected R15 gates
Authority: all orchestration-route, fixture, parser, verifier, model,
implementation, production, provider, ArtifactLedger, G3, audit, commit, push,
install, cutover, release, readiness, and protocol-answer authority is false

## 0. Boundary and authenticated input

R16 creates only this contract and its author receipt. It does not create,
edit, import, collect, or run a root route, architecture review/attestation,
grammar package, parser, verifier, fixture, transcript, model, provider, or
production path.

The complete R15 independent REPAIR review was authenticated and read end to
end before authoring:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `review_fixtures/cut4_transactional_recon_publication_r15_architecture_independent_review_20260810.md` | 25,336 | `edb66350ae83afbc37c1c93df5124314efbf9432d902149dbff8f5796fc1346c` |
| `architecture/cut4-transactional-recon-publication-r15-preimplementation-contract.md` | 81,641 | `9671e76c8739946a78b731abffcd65d4815569fa64eae742a98dc3750b9f39e2` |
| `review_fixtures/cut4_transactional_recon_publication_r15_contract_author_receipt_20260810.md` | 5,788 | `8f652c7dbcc0b2cc3fdcaf9474228e525ccdb2b188bde1a374c3f385a39ca00d` |

The review's four findings are the complete repair boundary. All accepted
R1-R15 provider denominators, ownership, MODEL shards, legacy non-adoption,
canonical-publication ownership, project-root containment, nonempty exhausted
c3, and Part-0 limitations remain unchanged.

## 1. Versioned path registry

Only the contract and author receipt exist in this turn. Every other path is a
future single-writer subject.

```json
{
  "schema": "cut4.r16.path_registry.v1",
  "architecture_contract": "architecture/cut4-transactional-recon-publication-r16-preimplementation-contract.md",
  "architecture_author_receipt": "review_fixtures/cut4_transactional_recon_publication_r16_contract_author_receipt_20260810.md",
  "architecture_design_review": "review_fixtures/cut4_transactional_recon_publication_r16_architecture_independent_review_20260810.md",
  "root_route_receipt": "review_fixtures/cut4_transactional_recon_publication_r16_root_route_receipt.json",
  "architecture_route_attestation": "review_fixtures/cut4_transactional_recon_publication_r16_architecture_route_attestation.json",
  "parser_a_package": "review_fixtures/cut4_transactional_recon_publication_r16_parser_a.py",
  "parser_b_package": "review_fixtures/cut4_transactional_recon_publication_r16_parser_b.py",
  "verifier_package": "review_fixtures/cut4_transactional_recon_publication_r16_independent_verifier.py",
  "red_test": "tests/test_cut4_transactional_recon_publication_r16_preimplementation.py",
  "red_model_absent_transcript": "review_fixtures/cut4_transactional_recon_publication_r16_red_model_absent_20260810.json",
  "red_author_receipt": "review_fixtures/cut4_transactional_recon_publication_r16_red_author_receipt_20260810.json",
  "negative_proof_receipt": "review_fixtures/cut4_transactional_recon_publication_r16_independent_negative_proof_receipt_20260810.json",
  "red_review": "review_fixtures/cut4_transactional_recon_publication_r16_red_independent_review_20260810.md",
  "model": "review_fixtures/cut4_transactional_recon_publication_r16_reference_model.py",
  "green_author_receipt": "review_fixtures/cut4_transactional_recon_publication_r16_green_author_receipt_20260810.json",
  "green_review": "review_fixtures/cut4_transactional_recon_publication_r16_green_independent_review_20260810.md",
  "envelope_directory": "review_fixtures/cut4_transactional_recon_publication_r16_route"
}
```

## 2. Gate O: prospective non-signature orchestration hash route

### 2.1 Claim and two-stage architecture review

R16 removes every public key, fingerprint, signature, and key-registry claim.
SHA-256 below is only deterministic byte addressing inside the root
orchestration workflow. It does not authenticate people, controllers, hosts,
or adversarial independence.

The independent architecture reviewer first reviews this contract/receipt
without any route artifacts. Its subject records its actual orchestration
`review_task_id` and returns ACCEPT or REPAIR. ACCEPT permits the root
orchestrator to create the route receipt prospectively. The same still-live
review task ID then receives a follow-up and writes the sequence-1 architecture
route attestation. That attestation binds the already accepted review bytes,
contract, author receipt, root route, assignments, and no-self-review joins.
No parser/fixture task may start before its envelope validates. REPAIR creates
no route.

This proves only that the orchestrator observed exact bytes from declared task
routes in the declared hash order. It does not prove distinct human agents or
independent control, and it makes no statement about off-path work or wall-clock
time.

### 2.2 Exact prospective route

The root receipt freezes actual nonempty task IDs for nine role labels:
`P_ROOT`, `P_ARCH_REVIEWER`, `P_PARSER_A`, `P_PARSER_B`, `P_VERIFIER`,
`P_RED_AUTHOR`, `P_RED_REVIEWER`, `P_MODEL_IMPLEMENTER`, and
`P_GREEN_REVIEWER`. All nine task-ID strings must be pairwise distinct. This is
a label inequality check, not an independence claim.

```json
{
  "schema": "cut4.r16.route_plan.v1",
  "rows": [
    [1, "ARCHITECTURE_ROUTE_ATTESTATION", "P_ARCH_REVIEWER", "review_fixtures/cut4_transactional_recon_publication_r16_architecture_route_attestation.json", "review_fixtures/cut4_transactional_recon_publication_r16_route/01_architecture_route_attestation.json", []],
    [2, "PARSER_A_PACKAGE", "P_PARSER_A", "review_fixtures/cut4_transactional_recon_publication_r16_parser_a.py", "review_fixtures/cut4_transactional_recon_publication_r16_route/02_parser_a.json", ["ARCHITECTURE_ROUTE_ATTESTATION"]],
    [3, "PARSER_B_PACKAGE", "P_PARSER_B", "review_fixtures/cut4_transactional_recon_publication_r16_parser_b.py", "review_fixtures/cut4_transactional_recon_publication_r16_route/03_parser_b.json", ["ARCHITECTURE_ROUTE_ATTESTATION"]],
    [4, "VERIFIER_PACKAGE", "P_VERIFIER", "review_fixtures/cut4_transactional_recon_publication_r16_independent_verifier.py", "review_fixtures/cut4_transactional_recon_publication_r16_route/04_verifier.json", ["ARCHITECTURE_ROUTE_ATTESTATION"]],
    [5, "RED_TEST", "P_RED_AUTHOR", "tests/test_cut4_transactional_recon_publication_r16_preimplementation.py", "review_fixtures/cut4_transactional_recon_publication_r16_route/05_red_test.json", ["PARSER_A_PACKAGE", "PARSER_B_PACKAGE", "VERIFIER_PACKAGE"]],
    [6, "RED_MODEL_ABSENT_TRANSCRIPT", "P_RED_AUTHOR", "review_fixtures/cut4_transactional_recon_publication_r16_red_model_absent_20260810.json", "review_fixtures/cut4_transactional_recon_publication_r16_route/06_red_model_absent_transcript.json", ["RED_TEST"]],
    [7, "RED_AUTHOR_RECEIPT", "P_RED_AUTHOR", "review_fixtures/cut4_transactional_recon_publication_r16_red_author_receipt_20260810.json", "review_fixtures/cut4_transactional_recon_publication_r16_route/07_red_author_receipt.json", ["PARSER_A_PACKAGE", "PARSER_B_PACKAGE", "VERIFIER_PACKAGE", "RED_TEST", "RED_MODEL_ABSENT_TRANSCRIPT"]],
    [8, "NEGATIVE_PROOF_RECEIPT", "P_VERIFIER", "review_fixtures/cut4_transactional_recon_publication_r16_independent_negative_proof_receipt_20260810.json", "review_fixtures/cut4_transactional_recon_publication_r16_route/08_negative_proof_receipt.json", ["PARSER_A_PACKAGE", "PARSER_B_PACKAGE", "VERIFIER_PACKAGE", "RED_TEST", "RED_MODEL_ABSENT_TRANSCRIPT"]],
    [9, "RED_REVIEW", "P_RED_REVIEWER", "review_fixtures/cut4_transactional_recon_publication_r16_red_independent_review_20260810.md", "review_fixtures/cut4_transactional_recon_publication_r16_route/09_red_review.json", ["ARCHITECTURE_ROUTE_ATTESTATION", "RED_AUTHOR_RECEIPT", "NEGATIVE_PROOF_RECEIPT"]],
    [10, "MODEL", "P_MODEL_IMPLEMENTER", "review_fixtures/cut4_transactional_recon_publication_r16_reference_model.py", "review_fixtures/cut4_transactional_recon_publication_r16_route/10_model.json", ["RED_REVIEW"]],
    [11, "GREEN_AUTHOR_RECEIPT", "P_MODEL_IMPLEMENTER", "review_fixtures/cut4_transactional_recon_publication_r16_green_author_receipt_20260810.json", "review_fixtures/cut4_transactional_recon_publication_r16_route/11_green_author_receipt.json", ["RED_REVIEW", "MODEL", "RED_TEST"]],
    [12, "GREEN_REVIEW", "P_GREEN_REVIEWER", "review_fixtures/cut4_transactional_recon_publication_r16_green_independent_review_20260810.md", "review_fixtures/cut4_transactional_recon_publication_r16_route/12_green_review.json", ["RED_REVIEW", "MODEL", "GREEN_AUTHOR_RECEIPT"]]
  ]
}
```

The plan has exactly 12 subjects and 27 unique forward predecessor edges with
zero Kahn remainder. The root receipt must exist before sequence 1. Subject
writers write only their subject. `P_ROOT` alone writes root observation
envelopes after receiving a subject result from the exact assigned task ID.

### 2.3 Closed hash-envelope schema and formulas

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r16.orchestration_hash_route.schema.v1",
  "oneOf": [
    {"$ref": "#/$defs/RootRouteReceipt"},
    {"$ref": "#/$defs/RouteEnvelope"},
    {"$ref": "#/$defs/ArchitectureRouteAttestation"}
  ],
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "TaskId": {"type": "string", "pattern": "^task_[A-Za-z0-9_-]{8,128}$"},
    "TaskAssignment": {
      "type": "object", "additionalProperties": false,
      "required": ["task_id", "role", "allowed_subjects"],
      "properties": {
        "task_id": {"$ref": "#/$defs/TaskId"},
        "role": {"enum": ["P_ROOT", "P_ARCH_REVIEWER", "P_PARSER_A", "P_PARSER_B", "P_VERIFIER", "P_RED_AUTHOR", "P_RED_REVIEWER", "P_MODEL_IMPLEMENTER", "P_GREEN_REVIEWER"]},
        "allowed_subjects": {"type": "array", "minItems": 1, "uniqueItems": true, "items": {"type": "string", "minLength": 1}}
      }
    },
    "RootRouteReceipt": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "route_id", "root_task_id", "architecture_contract_identity", "architecture_contract_sha256", "author_receipt_identity", "author_receipt_sha256", "architecture_review_identity", "architecture_review_sha256", "architecture_review_task_id", "task_assignments", "route_plan", "route_plan_digest", "root_receipt_digest"],
      "properties": {
        "schema": {"const": "cut4.r16.root_route_receipt.v1"},
        "route_id": {"type": "string", "pattern": "^cut4-r16-[A-Za-z0-9_-]{8,128}$"},
        "root_task_id": {"$ref": "#/$defs/TaskId"},
        "architecture_contract_identity": {"const": "architecture/cut4-transactional-recon-publication-r16-preimplementation-contract.md"},
        "architecture_contract_sha256": {"$ref": "#/$defs/Hex64"},
        "author_receipt_identity": {"const": "review_fixtures/cut4_transactional_recon_publication_r16_contract_author_receipt_20260810.md"},
        "author_receipt_sha256": {"$ref": "#/$defs/Hex64"},
        "architecture_review_identity": {"const": "review_fixtures/cut4_transactional_recon_publication_r16_architecture_independent_review_20260810.md"},
        "architecture_review_sha256": {"$ref": "#/$defs/Hex64"},
        "architecture_review_task_id": {"$ref": "#/$defs/TaskId"},
        "task_assignments": {"type": "array", "minItems": 9, "maxItems": 9, "uniqueItems": true, "items": {"$ref": "#/$defs/TaskAssignment"}},
        "route_plan": {"type": "array", "minItems": 12, "maxItems": 12},
        "route_plan_digest": {"$ref": "#/$defs/Hex64"},
        "root_receipt_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "RouteEnvelope": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "route_id", "sequence_ordinal", "subject_kind", "subject_identity", "subject_bytes_base64", "subject_byte_size", "subject_sha256", "subject_writer_task_id", "subject_writer_role", "envelope_writer_task_id", "orchestrator_result_observation_id", "predecessor_envelope_digests", "root_receipt_digest", "route_plan_digest", "envelope_digest"],
      "properties": {
        "schema": {"const": "cut4.r16.route_envelope.v1"},
        "route_id": {"type": "string", "pattern": "^cut4-r16-[A-Za-z0-9_-]{8,128}$"},
        "sequence_ordinal": {"type": "integer", "minimum": 1, "maximum": 12},
        "subject_kind": {"type": "string", "minLength": 1},
        "subject_identity": {"type": "string", "minLength": 1},
        "subject_bytes_base64": {"type": "string"},
        "subject_byte_size": {"type": "integer", "minimum": 1},
        "subject_sha256": {"$ref": "#/$defs/Hex64"},
        "subject_writer_task_id": {"$ref": "#/$defs/TaskId"},
        "subject_writer_role": {"type": "string", "minLength": 1},
        "envelope_writer_task_id": {"$ref": "#/$defs/TaskId"},
        "orchestrator_result_observation_id": {"type": "string", "pattern": "^obs_[A-Za-z0-9_-]{8,128}$"},
        "predecessor_envelope_digests": {"type": "array", "uniqueItems": true, "items": {"$ref": "#/$defs/Hex64"}},
        "root_receipt_digest": {"$ref": "#/$defs/Hex64"},
        "route_plan_digest": {"$ref": "#/$defs/Hex64"},
        "envelope_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "ArchitectureRouteAttestation": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "review_task_id", "architecture_review_sha256", "review_decision", "root_receipt_digest", "route_plan_digest", "assignment_join_digest", "reviewed_author_task_id", "no_self_review", "attestation_digest"],
      "properties": {
        "schema": {"const": "cut4.r16.architecture_route_attestation.v1"},
        "review_task_id": {"$ref": "#/$defs/TaskId"},
        "architecture_review_sha256": {"$ref": "#/$defs/Hex64"},
        "review_decision": {"const": "ACCEPT"},
        "root_receipt_digest": {"$ref": "#/$defs/Hex64"},
        "route_plan_digest": {"$ref": "#/$defs/Hex64"},
        "assignment_join_digest": {"$ref": "#/$defs/Hex64"},
        "reviewed_author_task_id": {"$ref": "#/$defs/TaskId"},
        "no_self_review": {"const": true},
        "attestation_digest": {"$ref": "#/$defs/Hex64"}
      }
    }
  }
}
```

`CJ` is RFC 8785 canonical JSON after UTF-8/NFC validation; `H` is ordinary
SHA-256; prefixes include the trailing NUL.

```text
route_plan_digest = H(UTF8("cut4.r16.route_plan.v1\0") || CJ(exact rows))
root_receipt_digest = H(UTF8("cut4.r16.root_route_receipt.v1\0") ||
                        CJ(root receipt without root_receipt_digest))
subject_bytes = strict_base64_decode(subject_bytes_base64)
subject_byte_size = len(subject_bytes)
subject_sha256 = H(subject_bytes)
envelope_digest = H(UTF8("cut4.r16.route_envelope.v1\0") ||
                    CJ(envelope without envelope_digest))
attestation_digest = H(UTF8("cut4.r16.arch_route_attestation.v1\0") ||
                       CJ(attestation without attestation_digest))
```

Validation requires exact route row, ordinal, role, assigned subject task ID,
`envelope_writer_task_id = root_task_id`, result observation identity returned
by the orchestrator, root/plan digest, and ordered immediate predecessors. A
subject cannot be inserted retrospectively because every writer task is
started only after its predecessor envelopes validate. Reviews join and reject
the exact reviewed task IDs. The negative receipt contains root, plan, and
already-known predecessor envelope digests only; its sequence-8 envelope later
binds the receipt bytes, so no self-reference exists.

## 3. Gate S: contract-frozen recognition bytes and three package owners

### 3.1 Exact byte blobs

The following bytes are frozen by this contract before any parser/verifier task
is started. Base64 is RFC 4648 with padding. Strict decode must reproduce the
literal byte size and ordinary SHA-256. Decoded bytes are compact canonical
JSON and must reserialize byte-identically. No label, future configuration, or
caller-supplied registry can replace them.

```json
{
  "schema": "cut4.r16.recognition_spec_blobs.v1",
  "specs": [
    ["GRAMMAR_A", "RFC8785_JSON_UTF8", 1585, "7ea9772be20e5d70444a4709ce2b902953b2c367b12fa0c329f97dfb6040c0d2", "eyJieXRlX2NsYXNzZXMiOltbIldTIixbOSwxMCwxMywzMl1dLFsiSURFTlRfU1RBUlQiLFtbNjUsOTBdLFs5NSw5NV0sWzk3LDEyMl1dXSxbIklERU5UX0NPTlRJTlVFIixbWzQ4LDU3XSxbNjUsOTBdLFs5NSw5NV0sWzk3LDEyMl1dXSxbIlFVT1RFIixbMzQsMzksOTZdXSxbIlBVTkNUIixbNDAsNDEsNDQsNDYsNTgsNTksOTEsOTMsMTIzLDEyNV1dXSwiY29tbWVudHMiOltbImFwdG9zIixbIi8vIiwiLyogKi8iXV0sWyJkYW1sIixbIi0tIiwiey0gLX0iXV0sWyJldm0iLFsiLy8iLCIvKiAqLyJdXSxbImdvIixbIi8vIiwiLyogKi8iXV0sWyJydXN0IixbIi8vIiwiLyogKi8iXV0sWyJzb2xhbmEiLFsiLy8iLCIvKiAqLyJdXSxbInNvcm9iYW4iLFsiLy8iLCIvKiAqLyJdXSxbInN1aSIsWyIvLyIsIi8qICovIl1dXSwiZGVjbGFyYXRpb25fa2V5d29yZHMiOltbImFwdG9zIixbImZ1biIsIm1vZHVsZSIsInN0cnVjdCJdXSxbImRhbWwiLFsiZGF0YSIsIm1vZHVsZSIsInRlbXBsYXRlIl1dLFsiZXZtIixbImNvbnRyYWN0IiwiZnVuY3Rpb24iLCJpbnRlcmZhY2UiLCJsaWJyYXJ5Il1dLFsiZ28iLFsiZnVuYyIsInR5cGUiXV0sWyJydXN0IixbImVudW0iLCJmbiIsImltcGwiLCJtb2QiLCJzdHJ1Y3QiLCJ0cmFpdCJdXSxbInNvbGFuYSIsWyJlbnVtIiwiZm4iLCJpbXBsIiwibW9kIiwic3RydWN0IiwidHJhaXQiXV0sWyJzb3JvYmFuIixbImVudW0iLCJmbiIsImltcGwiLCJtb2QiLCJzdHJ1Y3QiLCJ0cmFpdCJdXSxbInN1aSIsWyJmdW4iLCJtb2R1bGUiLCJzdHJ1Y3QiXV1dLCJpbXBvcnRfa2V5d29yZHMiOltbImFwdG9zIixbImZyaWVuZCIsInVzZSJdXSxbImRhbWwiLFsiaW1wb3J0Il1dLFsiZXZtIixbImltcG9ydCIsInVzaW5nIl1dLFsiZ28iLFsiaW1wb3J0Il1dLFsicnVzdCIsWyJleHRlcm4iLCJ1c2UiXV0sWyJzb2xhbmEiLFsiZXh0ZXJuIiwidXNlIl1dLFsic29yb2JhbiIsWyJleHRlcm4iLCJ1c2UiXV0sWyJzdWkiLFsiZnJpZW5kIiwidXNlIl1dXSwicHJvZHVjdGlvbnMiOltbIkEwMDEiLCJERUNMQVJBVElPTiIsIktXX0RFQ0wgSURFTlQiXSxbIkEwMDIiLCJJTVBPUlQiLCJLV19JTVBPUlQgUEFUSCJdLFsiQTAwMyIsIk1FTUJFUl9DQUxMIiwiSURFTlQgRE9UIElERU5UIExQQVJFTiJdLFsiQTAwNCIsIkNBTEwiLCJJREVOVCBMUEFSRU4iXSxbIkEwMDUiLCJQQVRIX0xJVEVSQUwiLCJTVFJJTkcgUEFUSF9DT05URVhUIl0sWyJBMDA2IiwiQ09OVEVOVF9JTlNUUlVDVElPTiIsIlNUUklORyBJTlNUUlVDVElPTl9DT05URVhUIl0sWyJBMDA3IiwiR1JBUEhfRURHRSIsIkJBS0VfR1JBUEhfUk9XIl0sWyJBMDA4IiwiUFJPQkVfRURHRSIsIkJBS0VfUFJPQkVfUk9XIl0sWyJBMDA5IiwiV0hJVEVTUEFDRSIsIldTX1BMVVMiXSxbIkEwMTAiLCJDT01NRU5UIiwiQ09NTUVOVCJdLFsiQTAxMSIsIlBVTkNUVUFUSU9OIiwiUFVOQ1QiXSxbIkEwMTIiLCJOT05SRUZFUkVOQ0VfTElURVJBTCIsIkxJVEVSQUwgTk9UX1JFRkVSRU5DRV9DT05URVhUIl0sWyJBMDEzIiwiSU5WQUxJRF9PUl9VTktOT1dOIiwiUkVNQUlOREVSIl1dLCJzY2hlbWEiOiJjdXQ0LnIxNi5ncmFtbWFyX2EudjEifQ=="],
    ["DFA_B", "RFC8785_JSON_UTF8", 1654, "5b72363f2bde9ea916f6747eaf60d00ea2d833f9cba5819781761abf0edc0358", "eyJhbHBoYWJldCI6W1siYl93cyIsWzksMTAsMTMsMzJdXSxbImJfYWxwaGEiLFtbNjUsOTBdLFs5NSw5NV0sWzk3LDEyMl1dXSxbImJfZGlnaXQiLFtbNDgsNTddXV0sWyJiX3F1b3RlIixbMzQsMzksOTZdXSxbImJfZG90IixbNDZdXSxbImJfbHBhcmVuIixbNDBdXSxbImJfc2xhc2giLFs0N11dLFsiYl9zdGFyIixbNDJdXSxbImJfZGFzaCIsWzQ1XV0sWyJiX2JyYWNlIixbMTIzLDEyNV1dLFsiYl9vdGhlciIsImNvbXBsZW1lbnRfMF8yNTUiXV0sImRlY2xhcmF0aW9uX2tleXdvcmRzIjpbWyJhcHRvcyIsWyJmdW4iLCJtb2R1bGUiLCJzdHJ1Y3QiXV0sWyJkYW1sIixbImRhdGEiLCJtb2R1bGUiLCJ0ZW1wbGF0ZSJdXSxbImV2bSIsWyJjb250cmFjdCIsImZ1bmN0aW9uIiwiaW50ZXJmYWNlIiwibGlicmFyeSJdXSxbImdvIixbImZ1bmMiLCJ0eXBlIl1dLFsicnVzdCIsWyJlbnVtIiwiZm4iLCJpbXBsIiwibW9kIiwic3RydWN0IiwidHJhaXQiXV0sWyJzb2xhbmEiLFsiZW51bSIsImZuIiwiaW1wbCIsIm1vZCIsInN0cnVjdCIsInRyYWl0Il1dLFsic29yb2JhbiIsWyJlbnVtIiwiZm4iLCJpbXBsIiwibW9kIiwic3RydWN0IiwidHJhaXQiXV0sWyJzdWkiLFsiZnVuIiwibW9kdWxlIiwic3RydWN0Il1dXSwiZW1pc3Npb25zIjpbWyJCMDAxIiwiREVDTEFSQVRJT04iXSxbIkIwMDIiLCJJTVBPUlQiXSxbIkIwMDMiLCJNRU1CRVJfQ0FMTCJdLFsiQjAwNCIsIkNBTEwiXSxbIkIwMDUiLCJQQVRIX0xJVEVSQUwiXSxbIkIwMDYiLCJDT05URU5UX0lOU1RSVUNUSU9OIl0sWyJCMDA3IiwiR1JBUEhfRURHRSJdLFsiQjAwOCIsIlBST0JFX0VER0UiXSxbIkIwMDkiLCJXSElURVNQQUNFIl0sWyJCMDEwIiwiQ09NTUVOVCJdLFsiQjAxMSIsIlBVTkNUVUFUSU9OIiwiUFVOQ1RVQVRJT04iXSxbIkIwMTIiLCJOT05SRUZFUkVOQ0VfTElURVJBTCJdLFsiQjAxMyIsIklOVkFMSURfT1JfVU5LTk9XTiJdXSwiaW1wb3J0X2tleXdvcmRzIjpbWyJhcHRvcyIsWyJmcmllbmQiLCJ1c2UiXV0sWyJkYW1sIixbImltcG9ydCJdXSxbImV2bSIsWyJpbXBvcnQiLCJ1c2luZyJdXSxbImdvIixbImltcG9ydCJdXSxbInJ1c3QiLFsiZXh0ZXJuIiwidXNlIl1dLFsic29sYW5hIixbImV4dGVybiIsInVzZSJdXSxbInNvcm9iYW4iLFsiZXh0ZXJuIiwidXNlIl1dLFsic3VpIixbImZyaWVuZCIsInVzZSJdXV0sImtleXdvcmRfdGFibGVzIjoiZW1iZWRkZWRfcGVyX2Vjb3N5c3RlbV9leGFjdGx5X2FzX3Jvd3NfYmVsb3ciLCJzY2hlbWEiOiJjdXQ0LnIxNi5kZmFfYi52MSIsInN0YXRlcyI6WyJTMCIsIklERU5UIiwiU1RSSU5HIiwiTElORV9DT01NRU5UIiwiQkxPQ0tfQ09NTUVOVCIsIkFGVEVSX0RPVCIsIkNBTExfT1BFTiIsIkRFQlQiXSwidHJhbnNpdGlvbnMiOltbIlMwIiwiYl93cyIsIlMwIiwiV0hJVEVTUEFDRSJdLFsiUzAiLCJiX2FscGhhIiwiSURFTlQiLCJCVUZGRVIiXSxbIklERU5UIiwiYl9hbHBoYXxiX2RpZ2l0IiwiSURFTlQiLCJCVUZGRVIiXSxbIklERU5UIiwiYl9kb3QiLCJBRlRFUl9ET1QiLCJCVUZGRVIiXSxbIklERU5UIiwiYl9scGFyZW4iLCJDQUxMX09QRU4iLCJFTUlUX0NBTEwiXSxbIlMwIiwiYl9xdW90ZSIsIlNUUklORyIsIkJVRkZFUiJdLFsiUzAiLCJiX290aGVyIiwiUzAiLCJQVU5DVF9PUl9ERUJUIl1dfQ=="],
    ["RULE_REGISTRY", "RFC8785_JSON_UTF8", 855, "42f5ad5ee4fb4b09f2e009e975dea0d2cde2d700b45b62608b47c7ddd3df0a63", "eyJyb3dzIjpbWyJERUNMQVJBVElPTiIsIk1PREVfQkFTRSIsIkJBU0VfU0VNQU5USUMiLCJOT19XSVRORVNTIl0sWyJJTVBPUlQiLCJNT0RFX1JFRkVSRU5DRSIsIlJFRkVSRU5DRSIsIk5PX1dJVE5FU1MiXSxbIkNBTEwiLCJNT0RFX1JFRkVSRU5DRSIsIlJFRkVSRU5DRSIsIk5PX1dJVE5FU1MiXSxbIk1FTUJFUl9DQUxMIiwiTU9ERV9SRUZFUkVOQ0UiLCJSRUZFUkVOQ0UiLCJOT19XSVRORVNTIl0sWyJQQVRIX0xJVEVSQUwiLCJNT0RFX1JFRkVSRU5DRSIsIlJFRkVSRU5DRSIsIk5PX1dJVE5FU1MiXSxbIkNPTlRFTlRfSU5TVFJVQ1RJT04iLCJNT0RFX1JFRkVSRU5DRSIsIlJFRkVSRU5DRSIsIk5PX1dJVE5FU1MiXSxbIkdSQVBIX0VER0UiLCJNT0RFX0VER0UiLCJFREdFIiwiTk9fV0lUTkVTUyJdLFsiUFJPQkVfRURHRSIsIk1PREVfRURHRSIsIkVER0UiLCJOT19XSVRORVNTIl0sWyJXSElURVNQQUNFIiwiTU9ERV9OT05TRU1BTlRJQyIsIk5PTlNFTUFOVElDX1BST1ZFRCIsIldJVE5FU1NfUkVRVUlSRUQiXSxbIkNPTU1FTlQiLCJNT0RFX05PTlNFTUFOVElDIiwiTk9OU0VNQU5USUNfUFJPVkVEIiwiV0lUTkVTU19SRVFVSVJFRCJdLFsiUFVOQ1RVQVRJT04iLCJNT0RFX05PTlNFTUFOVElDIiwiTk9OU0VNQU5USUNfUFJPVkVEIiwiV0lUTkVTU19SRVFVSVJFRCJdLFsiTk9OUkVGRVJFTkNFX0xJVEVSQUwiLCJNT0RFX05PTlNFTUFOVElDIiwiTk9OU0VNQU5USUNfUFJPVkVEIiwiV0lUTkVTU19SRVFVSVJFRCJdLFsiSU5WQUxJRF9PUl9VTktOT1dOIiwiTU9ERV9ERUJUIiwiVU5SRVNPTFZFRF9ERUJUIiwiTk9fV0lUTkVTUyJdXSwic2NoZW1hIjoiY3V0NC5yMTYucnVsZV9yZWdpc3RyeS52MSJ9"],
    ["VERIFIER_SPEC", "RFC8785_JSON_UTF8", 731, "56264441d1b6caa005a224f2ed9afbd6ad3dc779fe2dcdbc8a437dee98e3e38f", "eyJkaXJlY3RfY2hlY2tzIjpbWyJWMDAxIiwicGFydGl0aW9uX2VhY2hfYnl0ZV9leGFjdGx5X29uY2UiXSxbIlYwMDIiLCJyZWNvbXB1dGVfQV9wcm9kdWN0aW9uX2Zyb21fcmF3X3NwYW5fYW5kX0FfdGFibGUiXSxbIlYwMDMiLCJyZWNvbXB1dGVfQl9lbWlzc2lvbl9mcm9tX3Jhd19zcGFuX2FuZF9CX3RhYmxlIl0sWyJWMDA0IiwiQV9hbmRfQl9wcm9qZWN0ZWRfcm93c19lcXVhbCJdLFsiVjAwNSIsInByb2R1Y3Rpb25fb3JfZW1pc3Npb25fbWFwc190b19leGFjdF9ydWxlIl0sWyJWMDA2Iiwibm9uc2VtYW50aWNfcmVxdWlyZXNfbWF0Y2hpbmdfcmF3X3dpdG5lc3MiXSxbIlYwMDciLCJkZWJ0X29uX2FueV91bmtub3duX29yX2Rpc2FncmVlbWVudCJdLFsiVjAwOCIsIm5lZ2F0aXZlX3Byb29mX2VudW1lcmF0ZXNfYWxsX2NhbmRpZGF0ZXNfZWRnZXNfYW5kX2RlYnRzIl1dLCJmb3JiaWRkZW5faW1wb3J0cyI6WyJwYXJzZXJfYV9wYWNrYWdlIiwicGFyc2VyX2JfcGFja2FnZSIsInJlZF9vcmFjbGVfcGFja2FnZSIsIm1vZGVsX3BhY2thZ2UiXSwiaW5wdXRzIjpbInJhd19zb3VyY2VfYnl0ZXMiLCJncmFtbWFyX2FfYnl0ZXMiLCJkZmFfYl9ieXRlcyIsInJ1bGVfcmVnaXN0cnlfYnl0ZXMiLCJwYXJzZXJfYV9yb3dzIiwicGFyc2VyX2Jfcm93cyIsImJha2Vfcm93cyJdLCJyZXN1bHQiOlsiQUNDRVBUIiwiREVCVCJdLCJzY2hlbWEiOiJjdXQ0LnIxNi52ZXJpZmllcl9zcGVjLnYxIn0="]
  ],
  "common_omission_vector": ["evm", "ZnVuY3Rpb24gZigpeyB0YXJnZXQoKTsgfQ==", 25, "1748ef89f856d71a7cbb64adcf3aa0c61b4a4d4610099d55aa88c5a6be0f0c55", "CALL", "A004", "B004", 14, 21, 3, "DEBT"]
}
```

The spec roster digest is
`H(UTF8("cut4.r16.recognition_specs.v1\0") || CJ(exact displayed rows))`.
Production/witness rows carry exact FKs `(spec_sha256, production_id)` or
`(spec_sha256, emission_id)`; arbitrary nonempty strings are forbidden.

### 3.2 Distinct packages and verifier authority

`P_PARSER_A` alone writes parser A and consumes only GRAMMAR_A and
RULE_REGISTRY. `P_PARSER_B` alone writes parser B and consumes only DFA_B and
RULE_REGISTRY. `P_VERIFIER` alone writes the verifier package and later the
negative receipt. It consumes all four frozen blobs but must not import, call,
copy a source module from, or dynamically load either parser, the RED test, or
the MODEL. An authenticated AST/import manifest must show no direct, dynamic,
indirect, or generated dependency. The three package task IDs and source hashes
must differ. This is distinct orchestration ownership only.

Both parsers independently partition every canonical source byte and emit
candidate, nonsemantic-witness, debt, classification, and edge rows. Equality
after removing only parser-specific IDs is necessary. The verifier separately
reconstructs each production/emission from raw span bytes and the frozen tables
before checking A/B equality. Common wrong output is rejected if raw bytes do
not reproduce both table entries. Unknown input, disagreement, relevant debt,
missing BAKE slot, or acceptance of the frozen common-omission vector prevents
NONSEMANTIC_PROVED and PROVED_NONE.

The negative receipt contains root/plan and its exact immediate sequence-2,
sequence-3, sequence-4, sequence-5, and sequence-6 predecessor envelope
digests, all four spec hashes, all three package hashes,
source/BAKE/parser/proof rosters, verifier result, and receipt digest. It never
contains its own future sequence-8 envelope digest.

## 4. Gate C: complete typed scalar and dependency authority

### 4.1 Frozen scalar-type DSL

Every closed dataclass has common fields `schema:STR_NFC`,
`object_id:ID`, and `object_digest:HEX64`. Each row below is
`[field_name,type_tag,required,neutral,constraint]`. Required is always true in
serialized bytes; conditional absence is represented only by a closed tagged
union with the stated neutral. Arrays are JSON arrays with the named order and
reject duplicates where `UNIQUE` appears. `UINT` is a non-boolean JSON integer
`0..2^63-1`; `INT` is a non-boolean signed 64-bit integer; `BOOL` is an exact
JSON boolean; `B64` is strict RFC-4648; `HEX64` is lowercase; `ID`, `PATH`, and
`STR_NFC` are nonempty UTF-8/NFC strings. `ENUM{x|y}` is literal. Reflection
compares field order, annotation, required/default/neutral value, constraint,
and canonical serializer, not only field names.

The exact expanded Kp fields, in order, are
`private_plan_row_id, semantic_row_id, private_source_identity, provider_id,
consumer_id, flow_instance_id, multiplicity_key, multiplicity_ordinal,
applicability_predicate_id, selection_predicate_id, accept_disposition,
accept_projected_identity`. Kp-bearing types serialize those fields immediately
after `object_id` with tags `ID,ID,PATH,ID,ID,ID,ID,UINT,ID,ID,ID,PATH`.

```json
{
  "schema": "cut4.r16.typed_scalar_registry.v1",
  "types": [
    ["AbortedUnobservedRecord", false, [["record_ordinal","UINT",true,0,"NONZERO"],["reason","ENUM{CRASH_BEFORE_TERMINAL|TIMEOUT_UNOBSERVED|CAS_UNOBSERVED}",true,"CRASH_BEFORE_TERMINAL","CLOSED"]]],
    ["AckPolicy", false, [["policy_id","ID",true,"","NONEMPTY"],["mode","ENUM{DISABLED|REQUIRED}",true,"DISABLED","CLOSED"],["policy_digest","HEX64",true,"","LOWERCASE"]]],
    ["AttemptAllocation", false, [["attempt_id","ID",true,"","NONEMPTY"],["attempt_sequence","UINT",true,0,"NONZERO"],["journal_generation","UINT",true,0,"EXACT_SNAPSHOT_PLUS_ONE"],["allocation_digest","HEX64",true,"","LOWERCASE"]]],
    ["BaseRequestIntent", false, [["query_id","ID",true,"","NONEMPTY"],["query_input_digest","HEX64",true,"","LOWERCASE"],["action","ENUM{START|RESUME|DEGRADE|MARKER_STRIP}",true,"START","CLOSED"],["normalizer_version","STR_NFC",true,"","NONEMPTY"],["source_input_digests","ARRAY<HEX64>",true,[],"DECLARED_ORDER_UNIQUE"],["intent_digest","HEX64",true,"","LOWERCASE"]]],
    ["CommittedPublicationReceipt", false, [["operation_key","STR_NFC",true,"","NONEMPTY"],["contract_digest","HEX64",true,"","LOWERCASE"],["launch_digest","HEX64",true,"","LOWERCASE"],["commit_actor","ENUM{DRIVER}",true,"DRIVER","CLOSED"],["output_count","UINT",true,0,"NONZERO"],["output_roster_digest","HEX64",true,"","LOWERCASE"],["receipt_digest","HEX64",true,"","LOWERCASE"]]],
    ["CompletionReceipt", true, [["completion_status","ENUM{COMPLETE|DEBT}",true,"DEBT","CLOSED"],["ack_state","ENUM{DISABLED|REQUIRED_PENDING|REQUIRED_COMMITTED}",true,"DISABLED","POLICY_JOIN"],["child_roster_digest","HEX64",true,"","LOWERCASE"],["completion_digest","HEX64",true,"","LOWERCASE"]]],
    ["DiffRow", true, [["diff_kind","ENUM{MISSING|SUPERSET|BODY_MISMATCH|BOOLEAN_MISMATCH|INTEGER_MISMATCH|COUNT_MISMATCH|MULTIPLICITY_MISMATCH}",true,"MISSING","CLOSED"],["expected_count","UINT",true,0,"NONBOOLEAN"],["observed_count","UINT",true,0,"NONBOOLEAN"],["count_delta","INT",true,0,"EXACT_OBSERVED_MINUS_EXPECTED"]]],
    ["DiffSide", true, [["side","ENUM{EXPECTED|OBSERVED}",true,"EXPECTED","CLOSED"],["value_type","ENUM{ROW_MULTIPLICITY|BOOLEAN|INTEGER|COUNT}",true,"ROW_MULTIPLICITY","CLOSED"],["source_kind","STR_NFC",true,"","CLOSED_REGISTRY_OR_EMPTY"],["source_schema","STR_NFC",true,"","CLOSED_REGISTRY_OR_EMPTY"],["source_id","ID",true,"empty:id","EMPTY_SENTINEL_ALLOWED"],["source_bytes_base64","B64",true,"","EXACT"],["source_byte_size","UINT",true,0,"MATCH_BYTES"],["source_sha256","HEX64",true,"","MATCH_BYTES"],["boolean_present","BOOL",true,false,"UNION"],["boolean_value","BOOL",true,false,"NEUTRAL_IF_INACTIVE"],["integer_present","BOOL",true,false,"UNION"],["integer_value","INT",true,0,"NEUTRAL_IF_INACTIVE"],["count_present","BOOL",true,false,"UNION"],["count_value","UINT",true,0,"NEUTRAL_IF_INACTIVE"],["multiplicity","UINT",true,0,"NONBOOLEAN"]]],
    ["ExecutionEvidence", false, [["tool_id","ID",true,"","NONEMPTY"],["tool_version","STR_NFC",true,"","NONEMPTY"],["argv_digest","HEX64",true,"","LOWERCASE"],["exit_class","ENUM{SUCCESS|FAILURE|TIMEOUT|MALFORMED}",true,"FAILURE","CLOSED"],["stdout_sha256","HEX64",true,"","LOWERCASE"],["stderr_sha256","HEX64",true,"","LOWERCASE"],["evidence_digest","HEX64",true,"","LOWERCASE"]]],
    ["ExplicitZeroProof", false, [["consumer_row_id","ID",true,"","NONEMPTY"],["query_id","ID",true,"","NONEMPTY"],["query_input_digest","HEX64",true,"","LOWERCASE"],["provider_id","ID",true,"","NONEMPTY"],["enumerated_result_count","UINT",true,0,"CONST_ZERO"],["exhausted_cursor","ID",true,"","NONEMPTY_C3"],["stdout_sha256","HEX64",true,"","LOWERCASE"],["stderr_sha256","HEX64",true,"","LOWERCASE"],["zero_evidence_digest","HEX64",true,"","LOWERCASE"],["zero_receipt_digest","HEX64",true,"","LOWERCASE"]]],
    ["InvalidFactJournalRecord", false, [["record_ordinal","UINT",true,0,"NONZERO"],["record_kind","ENUM{INVALID_FACT_SEAL}",true,"INVALID_FACT_SEAL","CONST"],["record_digest","HEX64",true,"","LOWERCASE"]]],
    ["InvalidFileFact", false, [["fact_id","ID",true,"","NONEMPTY"],["canonical_identity","PATH",true,"","PROJECT_CONTAINED"],["fact_kind","ENUM{TORN_TEMP|ZERO_BYTE|PARTIAL_FINAL|MALFORMED_RECORD|ALIAS_COLLISION}",true,"MALFORMED_RECORD","CLOSED"],["observed_byte_size","UINT",true,0,"EXACT"],["observed_sha256","HEX64",true,"","LOWERCASE"],["detected_generation","UINT",true,0,"EXACT"],["fact_digest","HEX64",true,"","LOWERCASE"]]],
    ["InvocationRecord", false, [["invocation_id","ID",true,"","NONEMPTY"],["provider_id","ID",true,"","NONEMPTY"],["tool_id","ID",true,"","NONEMPTY"],["tool_version","STR_NFC",true,"","NONEMPTY"],["tool_configuration_digest","HEX64",true,"","LOWERCASE"],["argv","ARRAY<STR_NFC>",true,[],"DECLARED_ORDER"],["bounded_limits_digest","HEX64",true,"","LOWERCASE"],["invocation_digest","HEX64",true,"","LOWERCASE"]]],
    ["JournalRecord", false, [["record_ordinal","UINT",true,0,"NONZERO"],["record_kind","ENUM{ATTEMPT_ALLOCATION|INVOCATION|INVALID_FACT_SEAL|ABORTED_UNOBSERVED|TERMINAL|PUBLICATION_ACK}",true,"ATTEMPT_ALLOCATION","CLOSED"],["object_bytes_base64","B64",true,"","EXACT_KIND_SCHEMA"],["object_byte_size","UINT",true,0,"MATCH_BYTES"],["object_sha256","HEX64",true,"","MATCH_BYTES"],["previous_record_digest","HEX64",true,"","GENESIS_SENTINEL_OR_MATCH"],["record_digest","HEX64",true,"","LOWERCASE"]]],
    ["JournalSnapshotAuthority", false, [["namespace","STR_NFC",true,"","EXACT_REGISTERED"],["request_digest_hex","HEX64",true,"","LOWERCASE"],["generation","UINT",true,0,"EXACT"],["state_bytes_base64","B64",true,"","CANONICAL"],["state_byte_size","UINT",true,0,"MATCH_BYTES"],["state_sha256","HEX64",true,"","MATCH_BYTES"],["invalid_fact_roster_digest","HEX64",true,"","LOWERCASE"]]],
    ["JournalState", false, [["namespace","STR_NFC",true,"","EXACT_REGISTERED"],["request_digest_hex","HEX64",true,"","LOWERCASE"],["generation","UINT",true,0,"EXACT_PRIOR_PLUS_ONE"],["prior_state_sha256","HEX64",true,"","MATCH_SNAPSHOT"],["record_count","UINT",true,0,"EXACT"],["record_roster_digest","HEX64",true,"","LOWERCASE"],["invalid_fact_roster_digest","HEX64",true,"","LOWERCASE"],["state_digest","HEX64",true,"","LOWERCASE"]]],
    ["M4", true, [["provider_roster_digest","HEX64",true,"","LOWERCASE"],["normalizer_roster_digest","HEX64",true,"","LOWERCASE"],["normalized_roster_digest","HEX64",true,"","LOWERCASE"],["diff_roster_digest","HEX64",true,"","LOWERCASE"],["public_output_roster_digest","HEX64",true,"","LOWERCASE"],["ack_state","ENUM{DISABLED|REQUIRED_PENDING|REQUIRED_COMMITTED}",true,"DISABLED","POLICY_JOIN"],["manifest_digest","HEX64",true,"","LOWERCASE"]]],
    ["NormalizedSemanticRow", true, [["semantic_kind","STR_NFC",true,"","CLOSED_REGISTRY"],["normalized_identity","PATH",true,"","CANONICAL"],["normalized_fields","ARRAY<STR_NFC>",true,[],"DECLARED_ORDER"],["payload_id","ID",true,"","FK_EQUAL"],["payload_digest","HEX64",true,"","FK_EQUAL"],["provider_receipt_identity","ID",true,"","FK_EQUAL"],["source_snapshot_digest","HEX64",true,"","FK_EQUAL"],["normalizer_evidence_id","ID",true,"","FK_EQUAL"],["normalizer_evidence_digest","HEX64",true,"","FK_EQUAL"]]],
    ["NormalizerExecutionEvidence", true, [["normalizer_id","ID",true,"","NONEMPTY"],["normalizer_version","STR_NFC",true,"","NONEMPTY"],["normalizer_source_sha256","HEX64",true,"","LOWERCASE"],["configuration_digest","HEX64",true,"","LOWERCASE"],["exit_class","ENUM{SUCCESS|REJECTED|DEBT|FAILURE|TIMEOUT|MALFORMED}",true,"FAILURE","CLOSED"],["stdout_sha256","HEX64",true,"","LOWERCASE"],["stderr_sha256","HEX64",true,"","LOWERCASE"],["evidence_digest","HEX64",true,"","LOWERCASE"]]],
    ["NormalizerOutcome", true, [["status","ENUM{ACCEPTED|REJECTED|DEBT|FAILURE|TIMEOUT|MALFORMED}",true,"FAILURE","CLOSED"],["debt_code","STR_NFC",true,"NONE","STATUS_TABLE"],["row_count","UINT",true,0,"STATUS_SHAPE"],["row_roster_digest","HEX64",true,"","LOWERCASE"],["outcome_digest","HEX64",true,"","LOWERCASE"]]],
    ["NormalizerReceipt", true, [["status","ENUM{ACCEPTED|REJECTED|DEBT|FAILURE|TIMEOUT|MALFORMED}",true,"FAILURE","CLOSED"],["debt_code","STR_NFC",true,"NONE","STATUS_TABLE"],["row_count","UINT",true,0,"STATUS_SHAPE"],["row_roster_digest","HEX64",true,"","LOWERCASE"],["receipt_identity","ID",true,"","NONEMPTY"],["receipt_digest","HEX64",true,"","LOWERCASE"]]],
    ["PayloadRecord", false, [["payload_id","ID",true,"","NONEMPTY"],["ordinal","UINT",true,0,"DECLARED_ORDER"],["content_type","STR_NFC",true,"","CLOSED_REGISTRY"],["payload_bytes_base64","B64",true,"","EXACT"],["byte_size","UINT",true,0,"MATCH_BYTES"],["payload_sha256","HEX64",true,"","MATCH_BYTES"],["payload_digest","HEX64",true,"","LOWERCASE"]]],
    ["PhaseIOAuthority", false, [["work_unit_key","STR_NFC",true,"","SIX_PART_CANONICAL"],["artifact_key","STR_NFC",true,"","REGISTERED"],["identity","PATH",true,"","REGISTERED"],["artifact_class","ENUM{DRIVER_GENERATED}",true,"DRIVER_GENERATED","CONST"],["writer","ENUM{DRIVER}",true,"DRIVER","CONST"],["mode","ENUM{REPLACE}",true,"REPLACE","CONST"],["schema_id","STR_NFC",true,"","REGISTERED"],["owner","ENUM{DRIVER}",true,"DRIVER","CONST"],["contract_digest","HEX64",true,"","LOWERCASE"],["launch_digest","HEX64",true,"","LOWERCASE"]]],
    ["PredicateEvidence", false, [["applicability_predicate_id","ID",true,"","NONEMPTY"],["selection_predicate_id","ID",true,"","NONEMPTY"],["applicability_result","BOOL",true,false,"EXACT"],["selection_result","BOOL",true,false,"IMPLIES_APPLICABLE"],["evidence_bytes_base64","B64",true,"","EXACT"],["evidence_sha256","HEX64",true,"","MATCH_BYTES"],["evidence_digest","HEX64",true,"","LOWERCASE"]]],
    ["PriorEnvelope", false, [["prior_identity","PATH",true,"","CANONICAL_OR_GENESIS"],["prior_bytes_base64","B64",true,"","CANONICAL_OR_EMPTY"],["prior_byte_size","UINT",true,0,"MATCH_BYTES"],["prior_sha256","HEX64",true,"","MATCH_BYTES"],["prior_status","ENUM{GENESIS|SUCCESS|SUCCESS_EMPTY|DEBT|FAILURE|TIMEOUT|MALFORMED}",true,"GENESIS","CLOSED"],["prior_cursor","ID",true,"genesis:c3","NONEMPTY"],["prior_receipt_id","ID",true,"genesis:receipt","FK_OR_GENESIS"],["prior_receipt_digest","HEX64",true,"","FK_OR_EMPTY_HASH"]]],
    ["PrivatePlan", true, [["provider_slot","ENUM{source_graph|build_probe|daml_source_graph}",true,"source_graph","FIXED_DENOMINATOR"],["plan_digest","HEX64",true,"","LOWERCASE"]]],
    ["ProviderPrivateV4", true, [["source_snapshot_digest","HEX64",true,"","FK_EQUAL"],["payload_count","UINT",true,0,"EXACT"],["payload_roster_digest","HEX64",true,"","LOWERCASE"]]],
    ["ProviderReceipt", false, [["provider_id","ID",true,"","NONEMPTY"],["status","ENUM{NOT_APPLICABLE|NOT_SELECTED|SUCCESS|SUCCESS_EMPTY|DEBT|FAILURE|TIMEOUT|MALFORMED}",true,"NOT_APPLICABLE","CLOSED"],["debt_code","STR_NFC",true,"NONE","STATUS_TABLE"],["applicability_result","BOOL",true,false,"PREDICATE_JOIN"],["selection_result","BOOL",true,false,"PREDICATE_JOIN"],["payload_count","UINT",true,0,"STATUS_SHAPE"],["payload_roster_digest","HEX64",true,"","LOWERCASE"],["receipt_identity","ID",true,"","NONEMPTY"]]],
    ["PublicOutputBytes", false, [["output_id","ID",true,"","NONEMPTY"],["ordinal","UINT",true,0,"REGISTRY_ORDER"],["canonical_identity","PATH",true,"","PROJECT_CONTAINED"],["schema_id","STR_NFC",true,"","REGISTERED"],["content_type","STR_NFC",true,"application/json","REGISTERED"],["bytes_base64","B64",true,"","NONEMPTY"],["byte_size","UINT",true,0,"NONZERO_MATCH"],["sha256","HEX64",true,"","MATCH_BYTES"],["semantic_digest","HEX64",true,"","LOWERCASE"]]],
    ["PublicationAckJournalRecord", false, [["record_ordinal","UINT",true,0,"NONZERO"],["record_kind","ENUM{PUBLICATION_ACK}",true,"PUBLICATION_ACK","CONST"],["link_digest","HEX64",true,"","FK_EQUAL"],["receipt_digest","HEX64",true,"","FK_EQUAL"],["record_digest","HEX64",true,"","LOWERCASE"]]],
    ["PublicationLink", false, [["terminal_record_digest","HEX64",true,"","FK_EQUAL"],["committed_receipt_digest","HEX64",true,"","FK_EQUAL"],["public_output_roster_digest","HEX64",true,"","FK_EQUAL"],["link_digest","HEX64",true,"","LOWERCASE"]]],
    ["QueryReceipt", false, [["query_id","ID",true,"","NONEMPTY"],["query_input_digest","HEX64",true,"","LOWERCASE"],["status","ENUM{SUCCESS|SUCCESS_EMPTY|DEBT|FAILURE|TIMEOUT|MALFORMED}",true,"FAILURE","CLOSED"],["cursor_out","ID",true,"","NONEMPTY_IF_SUCCESS"],["receipt_digest","HEX64",true,"","LOWERCASE"]]],
    ["R4", true, [["m4_identity","ID",true,"","FK_EQUAL"],["m4_digest","HEX64",true,"","FK_EQUAL"],["repeated_array_digest","HEX64",true,"","EXACT_M4_ARRAYS"],["receipt_digest","HEX64",true,"","LOWERCASE"]]],
    ["RequestDigest", false, [["request_digest_hex","HEX64",true,"","DERIVED_INTENT"]]],
    ["SourceFileBytes", false, [["source_id","ID",true,"","NONEMPTY"],["canonical_identity","PATH",true,"","PROJECT_CONTAINED"],["ordinal","UINT",true,0,"CANONICAL_SORT"],["ecosystem","ENUM{aptos|daml|evm|go|rust|solana|soroban|sui}",true,"evm","PLAN_JOIN"],["bytes_base64","B64",true,"","EXACT"],["byte_size","UINT",true,0,"MATCH_BYTES"],["sha256","HEX64",true,"","MATCH_BYTES"]]],
    ["SourceSnapshot", false, [["project_root_identity","PATH",true,"","CANONICAL_ROOT"],["ecosystem","ENUM{aptos|daml|evm|go|rust|solana|soroban|sui}",true,"evm","PLAN_JOIN"],["language","STR_NFC",true,"","CLOSED_PLAN"],["source_count","UINT",true,0,"EXACT"],["source_roster_digest","HEX64",true,"","LOWERCASE"],["bake_roster_digest","HEX64",true,"","LOWERCASE"],["configuration_digest","HEX64",true,"","LOWERCASE"],["snapshot_digest","HEX64",true,"","LOWERCASE"]]],
    ["TerminalEnvelope", false, [["terminal_status","ENUM{SUCCESS|SUCCESS_EMPTY|DEBT|FAILURE|TIMEOUT|MALFORMED}",true,"FAILURE","CLOSED"],["provider_result_count","UINT",true,0,"EXACT"],["provider_roster_digest","HEX64",true,"","LOWERCASE"],["normalized_row_count","UINT",true,0,"EXACT"],["normalized_roster_digest","HEX64",true,"","LOWERCASE"],["cursor_out","ID",true,"","NONEMPTY_IF_SUCCESS"],["c3_exhausted","ID",true,"","NONEMPTY_IF_EXHAUSTED"],["terminal_bytes_digest","HEX64",true,"","LOWERCASE"]]],
    ["TerminalJournalRecord", false, [["record_ordinal","UINT",true,0,"NONZERO"],["record_kind","ENUM{TERMINAL}",true,"TERMINAL","CONST"],["request_digest_hex","HEX64",true,"","FK_EQUAL"],["attempt_id","ID",true,"","FK_EQUAL"],["terminal_bytes_base64","B64",true,"","CANONICAL"],["terminal_byte_size","UINT",true,0,"NONZERO_MATCH"],["terminal_sha256","HEX64",true,"","MATCH_BYTES"],["record_digest","HEX64",true,"","LOWERCASE"]]]
  ]
}
```

The registry has exactly 38 unique type rows, matching the dependency
projection in section 4.2. Every actual dataclass annotation/default and every
serializer/decoder must equal these frozen rows byte-for-byte. Common
`object_id/object_digest` preimages contain schema, Kp when applicable, every
scalar above, then dependency fields in FrozenContractFields order; the two
self fields are excluded and create no graph edge.

### 4.2 Exact FrozenContractFields construction

The authoritative base is the exact 108-row `cut4.r15.frozen_contract_fields.v1`
root in the authenticated R15 contract (artifact SHA
`9671e76c8739946a78b731abffcd65d4815569fa64eae742a98dc3750b9f39e2`,
canonical root SHA
`721e481bb4da89814c3c9e48b0bae6f095251e1f06038b965d73eaf5d3b67c78`).
R16 appends exactly these 13 rows; no base deletion/relabel/reorder is allowed.
Tuple fields remain `[owner,field,kind,target,cardinality,ordering,surfaces]`.

```json
{
  "schema": "cut4.r16.frozen_contract_fields_extension.v1",
  "base_row_count": 108,
  "additions": [
    ["SourceSnapshot","source_files","ROSTER","SourceFileBytes","MANY","CANONICAL_SORT",["DATACLASS_FIELD","CONSTRUCTOR_PREIMAGE","VALIDATOR_PARAMETER"]],
    ["PrivatePlan","ack_policy","FK","AckPolicy","ONE","SCALAR",["DATACLASS_FIELD","CONSTRUCTOR_PREIMAGE","VALIDATOR_PARAMETER"]],
    ["JournalSnapshotAuthority","invalid_file_facts","ROSTER","InvalidFileFact","MANY","CANONICAL_SORT",["DATACLASS_FIELD","CONSTRUCTOR_PREIMAGE","VALIDATOR_PARAMETER"]],
    ["InvalidFactJournalRecord","journal_snapshot","PREIMAGE","JournalSnapshotAuthority","ONE","SCALAR",["DATACLASS_FIELD","CONSTRUCTOR_PREIMAGE","VALIDATOR_PARAMETER"]],
    ["InvalidFactJournalRecord","invalid_file_fact","EMBEDDED","InvalidFileFact","ONE","SCALAR",["DATACLASS_FIELD","CONSTRUCTOR_PREIMAGE","VALIDATOR_PARAMETER"]],
    ["JournalRecord","invalid_fact_record","EMBEDDED","InvalidFactJournalRecord","ZERO_OR_ONE","SCALAR",["DATACLASS_FIELD","VALIDATOR_PARAMETER"]],
    ["JournalState","invalid_file_facts","ROSTER","InvalidFileFact","MANY","CANONICAL_SORT",["DATACLASS_FIELD","CONSTRUCTOR_PREIMAGE","VALIDATOR_PARAMETER"]],
    ["PublicOutputBytes","phase_io_authority","FK","PhaseIOAuthority","ONE","SCALAR",["DATACLASS_FIELD","CONSTRUCTOR_PREIMAGE","VALIDATOR_PARAMETER"]],
    ["PublicationAckJournalRecord","ack_policy","FK","AckPolicy","ONE","SCALAR",["DATACLASS_FIELD","CONSTRUCTOR_PREIMAGE","VALIDATOR_PARAMETER"]],
    ["M4","ack_policy","FK","AckPolicy","ONE","SCALAR",["DATACLASS_FIELD","CONSTRUCTOR_PREIMAGE","VALIDATOR_PARAMETER"]],
    ["M4","publication_ack","FK","PublicationAckJournalRecord","ZERO_OR_ONE","SCALAR",["DATACLASS_FIELD","CONSTRUCTOR_PREIMAGE","VALIDATOR_PARAMETER"]],
    ["CompletionReceipt","ack_policy","FK","AckPolicy","ONE","SCALAR",["DATACLASS_FIELD","CONSTRUCTOR_PREIMAGE","VALIDATOR_PARAMETER"]],
    ["CompletionReceipt","publication_ack","FK","PublicationAckJournalRecord","ZERO_OR_ONE","SCALAR",["DATACLASS_FIELD","CONSTRUCTOR_PREIMAGE","VALIDATOR_PARAMETER"]]
  ]
}
```

The combined exact denominator has 121 unique rows, 38 unique types, 120
unique projected `target -> owner` edges, and zero Kahn remainder. Future
reflection walks every dataclass field/annotation/default, constructor
signature/preimage decorator, validator signature/dependency decorator, and
self-preimage. Exact equality to both the 121 dependency rows and the typed
scalar registry is required; extra and missing metadata fail.

Invalid-file recovery is append-only: facts sort by `(fact_id,fact_digest)`;
`next_facts = current_facts UNION exactly_new_fact`, with no deletion,
substitution, duplicate, or repeated seal. Sealing one fact consumes one `+1`
CAS and appends exactly one INVALID_FACT_SEAL record; retry allocation consumes
a later separate `+1` CAS.

ACK policy is sealed in PrivatePlan. DISABLED requires no ACK dependency and
completion state DISABLED. REQUIRED permits REQUIRED_PENDING before ACK but no
CompletionReceipt; after one valid ACK record it requires the exact
zero-or-one FKs in M4 and CompletionReceipt and state REQUIRED_COMMITTED.
Required-but-missing, disabled-but-present, wrong-policy, or unjournaled ACK
fails.

PhaseIOAuthority rows freeze the exact work-unit/artifact key, identity,
DRIVER/REPLACE owner, schema, contract, and launch. Each PublicOutputBytes row
contains exact nonempty bytes/size/SHA and that authority FK. The fixture-only
publisher contracts cover journal, committed receipt, link, and every
registry-compiled public output; none is installed in the live resolver or
ArtifactLedger.

## 5. Gate R: honest absent-model RED and post-implementation domain codes

### 5.1 Three separate evidence types

Mutation definitions freeze future behavior before MODEL authorship but contain
no claimed pre-model domain observation. RED observations prove only frozen
tests plus exact MODEL absence/ImportError for model-dependent nodes. GREEN
domain observations, produced only after the distinct implementer writes the
MODEL, bind unchanged definitions to actual case-specific validator results.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "cut4.r16.red_green_evidence.schema.v1",
  "oneOf": [
    {"$ref": "#/$defs/MutationDefinition"},
    {"$ref": "#/$defs/RedObservation"},
    {"$ref": "#/$defs/GreenDomainObservation"}
  ],
  "$defs": {
    "Hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "MutationDefinition": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "case_id", "base_identity", "base_bytes_base64", "base_sha256", "mutation_operation", "mutation_bytes_base64", "mutated_sha256", "expected_model_stage", "expected_model_error_code", "definition_digest"],
      "properties": {
        "schema": {"const": "cut4.r16.mutation_definition.v1"},
        "case_id": {"type": "string", "pattern": "^[a-z0-9_]+(?:\\.[a-z0-9_]+)+$"},
        "base_identity": {"type": "string", "minLength": 1},
        "base_bytes_base64": {"type": "string"},
        "base_sha256": {"$ref": "#/$defs/Hex64"},
        "mutation_operation": {"enum": ["REPLACE_BYTES", "DELETE_BYTES", "INSERT_BYTES", "DUPLICATE_ROW", "SWAP_TYPED_ID", "REBUILD_DESCENDANTS"]},
        "mutation_bytes_base64": {"type": "string"},
        "mutated_sha256": {"$ref": "#/$defs/Hex64"},
        "expected_model_stage": {"enum": ["ORCHESTRATION", "RECOGNITION", "DEPENDENCY_REFLECTION", "JOURNAL_CAS", "PUBLICATION", "PRIVATE_COMPLETION"]},
        "expected_model_error_code": {"type": "string", "pattern": "^R16_[A-Z0-9_]+$"},
        "definition_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "RedObservation": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "case_id", "test_node_id", "test_sha256", "model_identity", "model_exists", "failure_class", "exception_type", "exception_message_digest", "command_argv", "exit_code", "stdout_bytes_base64", "stdout_sha256", "stderr_bytes_base64", "stderr_sha256", "observation_digest"],
      "properties": {
        "schema": {"const": "cut4.r16.red_model_absent_observation.v1"},
        "case_id": {"type": "string", "minLength": 1},
        "test_node_id": {"type": "string", "minLength": 1},
        "test_sha256": {"$ref": "#/$defs/Hex64"},
        "model_identity": {"const": "review_fixtures/cut4_transactional_recon_publication_r16_reference_model.py"},
        "model_exists": {"const": false},
        "failure_class": {"const": "MODEL_ABSENT"},
        "exception_type": {"enum": ["ImportError", "ModuleNotFoundError"]},
        "exception_message_digest": {"$ref": "#/$defs/Hex64"},
        "command_argv": {"type": "array", "minItems": 3, "items": {"type": "string"}},
        "exit_code": {"type": "integer", "not": {"const": 0}},
        "stdout_bytes_base64": {"type": "string"},
        "stdout_sha256": {"$ref": "#/$defs/Hex64"},
        "stderr_bytes_base64": {"type": "string"},
        "stderr_sha256": {"$ref": "#/$defs/Hex64"},
        "observation_digest": {"$ref": "#/$defs/Hex64"}
      }
    },
    "GreenDomainObservation": {
      "type": "object", "additionalProperties": false,
      "required": ["schema", "case_id", "definition_digest", "unchanged_test_sha256", "model_sha256", "model_writer_task_id", "model_invocation_digest", "expected_model_error_code", "observed_model_error_code", "positive_control_result", "test_result", "observation_digest"],
      "properties": {
        "schema": {"const": "cut4.r16.green_domain_observation.v1"},
        "case_id": {"type": "string", "minLength": 1},
        "definition_digest": {"$ref": "#/$defs/Hex64"},
        "unchanged_test_sha256": {"$ref": "#/$defs/Hex64"},
        "model_sha256": {"$ref": "#/$defs/Hex64"},
        "model_writer_task_id": {"type": "string", "pattern": "^task_[A-Za-z0-9_-]{8,128}$"},
        "model_invocation_digest": {"$ref": "#/$defs/Hex64"},
        "expected_model_error_code": {"type": "string", "pattern": "^R16_[A-Z0-9_]+$"},
        "observed_model_error_code": {"type": "string", "pattern": "^R16_[A-Z0-9_]+$"},
        "positive_control_result": {"const": "ACCEPTED"},
        "test_result": {"const": "PASSED"},
        "observation_digest": {"$ref": "#/$defs/Hex64"}
      }
    }
  }
}
```

Each digest is `H(UTF8(schema || "\0") || CJ(object without its terminal
digest))`. Strict base64 bytes reproduce every SHA. The exact final error for
case `g.x` is `R16_` plus uppercase `g.x` with `.` replaced by `_`; this value
is materialized in every frozen MutationDefinition and must equal both GREEN
expected and observed values. It is never a RED observed value.

### 5.2 Exact 128-case denominator

R16 inherits the exact ordered 96 R15 case IDs whose compact canonical array
SHA is `f1d5f09bd96d9760137bb5b23d67637fb81055cd5195b75bdb7f83299257953e`.
They are reauthored as R16 definitions and receive R16 error prefixes; no R15
test/run is authority. The following exact 32 IDs append in displayed order:

```json
{
  "schema": "cut4.r16.mutation_additions.v1",
  "base_count": 96,
  "groups": {
    "route_specs": [
      "route.root_not_prospective",
      "route.envelope_not_root_written",
      "route.writer_task_mismatch",
      "route.review_attestation_missing",
      "route.retrospective_subject_insert",
      "route.predecessor_hash_mismatch",
      "route.negative_receipt_self_reference",
      "route.independence_claim_smuggled",
      "spec.grammar_a_bytes_swap",
      "spec.dfa_b_bytes_swap",
      "spec.rule_bytes_swap",
      "spec.parser_a_role_reused",
      "spec.parser_b_role_reused",
      "spec.verifier_role_reused",
      "spec.verifier_imports_parser",
      "spec.common_omission_vector_accepted"
    ],
    "scalar_red": [
      "scalar.source_snapshot_missing_type",
      "scalar.prior_envelope_missing_type",
      "scalar.phaseio_authority_missing_type",
      "scalar.attempt_invocation_missing_type",
      "scalar.public_output_terminal_missing_type",
      "scalar.journal_invalid_fact_missing",
      "scalar.ack_policy_completion_missing",
      "scalar.annotation_default_mismatch",
      "red.domain_code_claimed_pre_model",
      "red.expected_code_deliberately_raised",
      "red.hidden_model_validator_in_fixture",
      "red.importerror_transcript_missing",
      "red.model_path_present",
      "red.vector_changed_after_red",
      "red.green_code_mismatch",
      "red.implementer_task_reused"
    ]
  },
  "total_count": 128
}
```

Before MODEL authorship the RED author freezes the test and all 128 definitions,
collects every node while importing the MODEL only inside test bodies, proves
the exact MODEL path absent before and after, and captures one MODEL_ABSENT
ImportError observation per model-dependent node. Contract/spec/route/vector
shape checks are oracle-only and must already pass. The fixture AST/import scan
rejects a model-equivalent validator, deliberate expected-code raise,
case-to-code rejection map presented as behavior, hidden generated validator,
or alternate model path. The RED transcript never claims any case-specific
domain rejection.

The independent RED reviewer authenticates unchanged bytes, collection,
absence, ImportError transcript, passing oracle-only checks, and the prohibition
on hidden implementation before ACCEPT. Only then may the distinct
P_MODEL_IMPLEMENTER task start. GREEN evidence contains exactly 128 domain
observations from actual model invocations plus positive controls; expected and
observed codes must equal, test/definition hashes remain unchanged, and the
GREEN reviewer independently reproduces them.

## 6. Exact journal/publication joins retained

R15's accepted acyclic order remains: terminal record commits first; the sole
canonical publisher then emits public bytes, CommittedPublicationReceipt, and
PublicationLink as an external atomic bundle; an optional later ACK may bind
the link, while link validation never requires the future ACK. Every CAS is
exactly `generation+1`, preserves namespace/request/prior SHA and all prior
record bytes, and appends one closed-kind record.

R16's InvalidFileFact and AckPolicy dependencies make every crash/recovery
state decidable. Terminal/no bundle replays terminal bytes; typed temp is
ignored and deterministically retried; partial final output is publication
debt; valid bundle/no ACK is complete only for DISABLED policy; REQUIRED waits
for one ACK CAS; valid bundle/ACK is an exact no-op. Unknown CAS outcome rereads
generation/SHA and validates presence before retry. M4/R4/completion validate
all upstream typed objects, public bytes, PhaseIO authorities, receipt/link,
policy, and required ACK rather than self-consistent aggregate digests.

## 7. Review, validation, and non-goals

The independent architecture reviewer authenticates this contract/receipt and
the exact R15 REPAIR review; parses every JSON root/schema with duplicate-key
and non-finite rejection; validates spec blob bytes/sizes/SHAs; rederives the
12/27 route; reconstructs the 108-row R15 FCF base plus 13 additions and checks
121 rows/38 types/120 edges/zero Kahn remainder; checks exactly 38 scalar type
rows; verifies 96+32=128 unique mutation identities and final-code formula;
checks current references, future-path absence, LF/BOM/fences, and Part-0
ceiling. It returns ACCEPT or REPAIR. ACCEPT alone permits prospective root
creation and the same-task route attestation.

R16 does not prove human, agent, controller, host, task, or cryptographic
independence. It does not prove ecosystem semantic correctness beyond the
frozen specifications and vectors, target-host atomicity where unavailable,
provider availability, target protocol security, live PhaseIO/ArtifactLedger
integration, production cutover, audit completion, release, readiness, or a
protocol answer. No provider denominator, MODEL shard, ArtifactLedger, G3, or
production file changes.

This author receipt is not architecture ACCEPT. Part-0 and all route, fixture,
parser, verifier, model, implementation, production, provider, ArtifactLedger,
G3, audit, commit, push, install, cutover, release, readiness, and
protocol-answer authority remain false.
