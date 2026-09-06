# Program Facts G3-00 admission-lineage Part-0 r7 semantic-successor correction amendment

Status: `CREATE_ONLY_CONTRACT; DOWNSTREAM_ABSENT; ALL_AUTHORITY_FALSE`

This amendment corrects only the two blocking defects proved by the governed r6
review. It creates no roster, review, schema render, validator, harness, GREEN
record, semantic-acceptance record, aggregate manifest, production artifact, or
runtime artifact. It neither repairs nor supersedes any prior byte. A later r7
governed review may authorize only the exact stopped semantic-successor route
defined here. Until that review has a valid PASS record, every post-review path
in section 4 MUST remain absent.

The amendment is Part-0 generic: protocol names are empty, protocol-specific
branching is false, and semantic shortcuts are false. Admission, aggregate
admission, G3-01, production, runtime, native, provider, publication, package,
installation, release, cutover, commit, and push authority are all false.

## 1. Frozen evidence and exact correction boundary

The accepted r5 bytes are immutable parents, not mutable templates:

| Ordinal | Exact path | Bytes | SHA-256 |
|---:|---|---:|---|
| 0 | `architecture/program-facts-g3-00-admission-lineage-r5-ordering-correction-amendment.md` | 52780 | `913553259ef1d89d009bdfb77acde4f123398542ebc3a04a1759c73b8c1f8c47` |
| 1 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_ORDERING_CORRECTION_AUTHOR_RECEIPT.md` | 6721 | `b0e82d3a0ab4d579907794d818ca585c93c36e178243ce8bbc81574344d64c54` |
| 2 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_PROSPECTIVE_BOUND_PRINCIPAL_ROSTER.v1.json` | 5130 | `0b45a0dc8c0ca0c1ebbfb1b78ce3d4f4725b1d6fca7c76f364b0afdaea7799f5` |
| 3 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_ORDERING_INDEPENDENT_GOVERNED_REVIEW.v1.json` | 15437 | `ad3f4b3567d3e7e9f903e9dd649d0e1f9399ed5b8ddb0bc7d64d44d150eb00c3` |
| 4 | `rules/schemas/program_facts_g3_00_admission_lineage_r5_prospective_principal_roster.v1.schema.json` | 7643 | `592cc74f405c42afbc3d95523871640a85675b7374897f2a0a17bd329604cfd4` |
| 5 | `rules/schemas/program_facts_g3_00_admission_lineage_r5_ordering_review.v1.schema.json` | 14721 | `99cac3ef4506a080454e5cc9c43e708903c257b56391025b7bd721023c55f422` |
| 6 | `rules/schemas/program_facts_g3_00_admission_lineage_r5_ordering_red_receipt.v1.schema.json` | 6802 | `6dbdc36b9d3c907bf2088443aecfab800d36aad24a1c1c580f28e2b97f8b5534` |
| 7 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/admission_lineage_r5_ordering_fixture_v1.py` | 9238 | `2b2b8f5f84aae1a02437575d8ed73e929840ec9d2c947df16998892ffe04e119` |
| 8 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/test_admission_lineage_r5_ordering_red_v1.py` | 11505 | `8c0976c1c9490d99364e571598fb7a04f728bb89c4444c7b20081b79f7ca5d98` |
| 9 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_ORDERING_RED_RECEIPT.v1.json` | 7429 | `d8f6a711760b3f52b7be61abb0c9778cdf0260a1283fa15e542984f4a7b5ff26` |

The r5 governed review is exactly 18/18 PASS with empty findings,
`open_findings`, and failure bindings. Its terminal RED is exactly the four
expected `SEMANTIC_SUCCESSOR_ABSENT` failures; it is successful negative
evidence and makes no semantic-acceptance claim.

The complete extant r6 bundle is also byte-frozen historical evidence:

| Ordinal | Exact path | Bytes | SHA-256 | Treatment |
|---:|---|---:|---|---|
| 0 | `architecture/program-facts-g3-00-admission-lineage-r6-semantic-successor-amendment.md` | 49907 | `23168030bfdb7f356f4dbfac7ae77f0c608ffc5c8fa26b5cd4f3e83937dafdd9` | frozen rejected contract |
| 1 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R6_SEMANTIC_SUCCESSOR_AUTHOR_RECEIPT.md` | 5391 | `2b04e7a41eaa68959490a6c0b92af32677e2dd4ae66178f2c4ae908fc729e185` | frozen authorship evidence |
| 2 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R6_BOUND_PRINCIPAL_ROSTER.v1.json` | 4919 | `39aed9b8b5d2e4b72c6324b96647aa40b46541e97a62c1d02ab3e0116a7d8575` | frozen bound-roster evidence |
| 3 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R6_PREIMPLEMENTATION_REVIEW.v1.json` | 17562 | `ed653af7574a0526e1d0b1a5a60f9193896a7da72d566cb67719a8b216ce54fd` | governed REJECTED review |

The r6 review has exactly 17 PASS rows and one FAIL row,
`ALR6-09-ALL-FUTURE-PATHS-ABSENT`. Its exact two `BLOCKING/OPEN` findings are
`ALR6-R6-F001-UNDEFINED-PATH-REGISTRY-PROJECTION` and
`ALR6-R6-F002-REVIEW-STAGE-ABSENCE-CONTRADICTION`; `open_findings` and failure
bindings back-join exactly to that FAIL row. The diagnostic hashes in that
REJECTED record are non-authoritative. R6 grants no render, implementation,
GREEN, acceptance, or aggregate authority.

This r7 amendment fixes those two findings exactly:

1. section 4 supplies one literal, duplicate-free canonical JSON
   `path_registry`, its normalization/order rules, its exact membership
   projection, and reproducible digest/back-join rules; and
2. section 5 replaces the impossible all-future-paths-absent predicate with a
   stage-specific predicate: the bound roster is present and validated before
   review, the review target is absent immediately before its atomic write, and
   only the eight strictly post-review outputs are absent during review.

No other r6 conclusion is converted into PASS. R5 and R6 bytes are never r7
candidate bytes, and no r4 output is permissible evidence. The following exact
r4 roster remains `HISTORICAL_INVALID_PREAUTHORIZATION_NOT_INPUT`:

1. `architecture/program-facts-g3-00-admission-lineage-r4-correction-amendment.md`
2. `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_CORRECTION_AUTHOR_RECEIPT.md`
3. `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_CORRECTION_INDEPENDENT_REVIEW.md`
4. `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_BOUND_PRINCIPAL_ROSTER.v1.json`
5. `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_CORRECTION_INDEPENDENT_REVIEW.v1.json`
6. `rules/schemas/program_facts_g3_00_admission_lineage_r4_correction_review.v1.schema.json`
7. `rules/schemas/program_facts_g3_00_admission_lineage_r4_principal_roster.v1.schema.json`
8. `rules/schemas/program_facts_g3_00_admission_lineage_r4_red_receipt.v1.schema.json`
9. `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/admission_lineage_r4_correction_fixture_v1.py`
10. `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/test_admission_lineage_r4_correction_red_v1.py`
11. `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_RED_RECEIPT.v1.json`

## 2. Preserved lineage, late binding, and authority ceiling

R3.13 launcher contract, handoff, and two independent ACCEPT reviews remain one
typed immutable legacy-reviewed bundle and are not retroactively armed or
completed. V8 pure-control contract and its two ACCEPT reviews remain only an
offline oracle/fixture parent; runtime, native, provider, production, and
cutover meanings remain false. The accepted crosscheck contract/review bundle
retains exactly
`PROTECTED_NAMESPACE_IDENTITY_PRESERVING_MATERIALIZATION`; no other completion
grade is widened. Protected-root integration REPAIR, runtime-cutover contract,
G3-01 construction contract, and accepted ledger V5/T1 chain retain their
existing read-only meanings.

Artifact-ledger and driver identities for construction remain late-bound to the
post-Cut4 accepted state. This amendment pins no current production identity.
Candidates may not import production modules or prior candidate modules, may
not act as production authority, and may not be consumed by production.

The authority ceiling used by every r7 schema is the exact 29-key value:
`active_head_update`, `admission`, `audit`, `canonical_installation`,
`canonical_promotion`, `clean_certification`, `commit`, `confidence`,
`consumer`, `cutover`, `finding`, `install`, `package`, `parity_capture`,
`process_capture`, `production_publication`, `provider`, `provider_launch`,
`push`, `refutation`, `release`, `replay`, `runner`, `runtime`, `severity`,
`suppression`, `terminal_negative`, `three_way_parity`, and
`vector_acceptance`, each exactly `false`.

## 3. New bound principals and value-derived independence

The exact r7 role order is:

0. `R7_AMENDMENT_AUTHOR`
1. `R7_ROSTER_BINDER`
2. `R7_INDEPENDENT_PREIMPLEMENTATION_REVIEWER`
3. `R7_SEMANTIC_SUCCESSOR_IMPLEMENTER`
4. `R7_GREEN_EXECUTOR_FIXTURE_AUTHOR`
5. `R7_INDEPENDENT_SEMANTIC_ACCEPTANCE_REVIEWER`

Ordinal 0 is extracted from this receipt's exact `Author principal:` field and
must equal `Codex:/root/g3_r3_correction_author_short`. Ordinals 1-5 must be
prospectively bound by signed assignments in the r7 roster. No Boolean
`independent` field is accepted. The binder computes independence from the six
principal-ID values, immutable/signed source bindings, and the exact
separation projection.

All 15 unordered internal r7 pairs must be unequal by value. Each prospective
r7 ordinal 1-5 must also be unequal to every value in this exact seven-value
prior-evidence producer roster:

1. `Codex:/root/g3_r3_correction_author_short`
2. `Codex:/root/g3_r5_principal_roster_binder_short`
3. `Codex:/root/g3_r5_ordering_review_short`
4. `Codex:/root/g3_r5_schema_renderer_short`
5. `Codex:/root/g3_r5_fixture_author_short`
6. `Codex:/root/g3_r6_principal_roster_binder_short`
7. `Codex:/root/g3_r6_preimplementation_review_short`

That is exactly 35 prospective cross-version comparisons. The sole declared
continuity is the amendment-author value at r7 ordinal 0; it grants no review,
render, implementation, execution, or acceptance independence. Principal
aliasing, relabeling, ordinal substitution, locator substitution, signature
substitution, or a changed assignment digest is a hard rejection.

All hashes below are lower-case hex. `CJ` has the exact meaning in section 4;
`without only x` removes exactly the named top-level member and no other value.
The deterministic identities and body hashes are:

```text
roster_body_sha256 = SHA256(CJ(roster without only roster_body_sha256))
roster_id = "pfg3alr7pr-" || SHA256(CJ({
  domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_PRINCIPAL_ROSTER_V1",
  roster:<roster without roster_id, binding_signature, roster_body_sha256>
}))[0:32]
for i in [1,2,3,4,5]:
  bindings[i].source.assignment_body_sha256 = SHA256(CJ({
    domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_PRINCIPAL_ASSIGNMENT_V1",
    role:roles[i], principal_ordinal:i, principal_id:principal_ids[i]
  }))
binding_signature.signed_preimage_sha256 = SHA256(CJ({
  domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_PRINCIPAL_BINDING_V1",
  roster:<roster without roster_id, binding_signature, roster_body_sha256>
}))
principal_ids_sha256 = SHA256(CJ(principal_ids))
separation_projection.projection_body_sha256 = SHA256(CJ(
  separation_projection without only projection_body_sha256))

review_body_sha256 = SHA256(CJ(review without only review_body_sha256))
review_id = "pfg3alr7pre-" || SHA256(CJ({
  domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_PREIMPLEMENTATION_REVIEW_V1",
  review:<review without review_id, review_body_sha256>
}))[0:32]
receipt_body_sha256 = SHA256(CJ(receipt without only receipt_body_sha256))
receipt_id = "pfg3alr7green-" || SHA256(CJ({
  domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_SEMANTIC_GREEN_RECEIPT_V1",
  receipt:<receipt without receipt_id, receipt_body_sha256>
}))[0:32]
acceptance_review_body_sha256 = SHA256(CJ(
  acceptance_review without only review_body_sha256))
acceptance_review_id = "pfg3alr7accept-" || SHA256(CJ({
  domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_SEMANTIC_ACCEPTANCE_REVIEW_V1",
  review:<acceptance_review without review_id, review_body_sha256>
}))[0:32]
```

## 4. Canonical path registry and deterministic back-join

The following JSON value, not a conceptual table or implementation-specific
object, is the complete r7 path registry:

```json
{
  "domain":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_PATH_REGISTRY_V1",
  "entries":[
    {"ordinal":0,"stage":"PRE_REVIEW_REQUIRED_INPUT","kind":"BOUND_ROSTER","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_BOUND_PRINCIPAL_ROSTER.v1.json"},
    {"ordinal":1,"stage":"REVIEW_ATOMIC_OUTPUT","kind":"PREIMPLEMENTATION_REVIEW","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_PREIMPLEMENTATION_REVIEW.v1.json"},
    {"ordinal":2,"stage":"POST_REVIEW_OUTPUT","kind":"SCHEMA_RENDER","path":"rules/schemas/program_facts_g3_00_admission_lineage_r7_principal_roster.v1.schema.json"},
    {"ordinal":3,"stage":"POST_REVIEW_OUTPUT","kind":"SCHEMA_RENDER","path":"rules/schemas/program_facts_g3_00_admission_lineage_r7_preimplementation_review.v1.schema.json"},
    {"ordinal":4,"stage":"POST_REVIEW_OUTPUT","kind":"SCHEMA_RENDER","path":"rules/schemas/program_facts_g3_00_admission_lineage_r7_semantic_green_receipt.v1.schema.json"},
    {"ordinal":5,"stage":"POST_REVIEW_OUTPUT","kind":"SCHEMA_RENDER","path":"rules/schemas/program_facts_g3_00_admission_lineage_r7_semantic_acceptance_review.v1.schema.json"},
    {"ordinal":6,"stage":"POST_REVIEW_OUTPUT","kind":"SEMANTIC_VALIDATOR","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/validate_admission_lineage_r5_ordering_semantics_v1.py"},
    {"ordinal":7,"stage":"POST_REVIEW_OUTPUT","kind":"GREEN_HARNESS","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/test_admission_lineage_r7_semantic_successor_green_v1.py"},
    {"ordinal":8,"stage":"POST_REVIEW_OUTPUT","kind":"GREEN_RECEIPT","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_SEMANTIC_GREEN_RECEIPT.v1.json"},
    {"ordinal":9,"stage":"POST_REVIEW_OUTPUT","kind":"SEMANTIC_ACCEPTANCE_REVIEW","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_SEMANTIC_ACCEPTANCE_REVIEW.v1.json"}
  ]
}
```

The governed-review schema embeds that same literal value so candidate
membership is a value back-join, not a digest assertion:

### 4.1 Closed R7 governed-preimplementation review schema

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_r7_preimplementation_review.v1.schema.json","type":"object","additionalProperties":false,
  "required":["schema_version","review_id","subject","author_receipt","principal_roster","reviewer_principal_ordinal","frozen_r5_count","frozen_r6_count","candidate_projection","red_green_denominator","stage_observation","checks","findings","open_findings","failure_bindings","disposition","accepted_scope","rejected_scope","part_0_genericity","authority_ceiling","review_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_r7_preimplementation_review.v1"},"review_id":{"type":"string","pattern":"^pfg3alr7pre-[0-9a-f]{32}$"},
    "subject":{"allOf":[{"$ref":"#/$defs/file"},{"properties":{"path":{"const":"architecture/program-facts-g3-00-admission-lineage-r7-semantic-successor-correction-amendment.md"}}}]},"author_receipt":{"allOf":[{"$ref":"#/$defs/file"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_SEMANTIC_SUCCESSOR_CORRECTION_AUTHOR_RECEIPT.md"}}}]},"principal_roster":{"allOf":[{"$ref":"#/$defs/file"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_BOUND_PRINCIPAL_ROSTER.v1.json"}}}]},
    "reviewer_principal_ordinal":{"const":2},"frozen_r5_count":{"const":10},"frozen_r6_count":{"const":4},"candidate_projection":{"$ref":"#/$defs/candidate"},"red_green_denominator":{"$ref":"#/$defs/denominator"},"stage_observation":{"$ref":"#/$defs/stage"},
    "checks":{"type":"array","minItems":20,"maxItems":20,"prefixItems":[{"$ref":"#/$defs/c01"},{"$ref":"#/$defs/c02"},{"$ref":"#/$defs/c03"},{"$ref":"#/$defs/c04"},{"$ref":"#/$defs/c05"},{"$ref":"#/$defs/c06"},{"$ref":"#/$defs/c07"},{"$ref":"#/$defs/c08"},{"$ref":"#/$defs/c09"},{"$ref":"#/$defs/c10"},{"$ref":"#/$defs/c11"},{"$ref":"#/$defs/c12"},{"$ref":"#/$defs/c13"},{"$ref":"#/$defs/c14"},{"$ref":"#/$defs/c15"},{"$ref":"#/$defs/c16"},{"$ref":"#/$defs/c17"},{"$ref":"#/$defs/c18"},{"$ref":"#/$defs/c19"},{"$ref":"#/$defs/c20"}],"items":false},
    "findings":{"type":"object","propertyNames":{"$ref":"#/$defs/id"},"additionalProperties":{"$ref":"#/$defs/finding"}},"open_findings":{"type":"array","uniqueItems":true,"items":{"$ref":"#/$defs/id"}},"failure_bindings":{"type":"array","maxItems":20,"uniqueItems":true,"items":{"$ref":"#/$defs/failure"}},
    "disposition":{"enum":["PASS_R7_PREIMPLEMENTATION_FOR_EXACT_STOPPED_SEMANTIC_GREEN_ONLY","REJECTED"]},"accepted_scope":{"const":["RENDER_4_R7_SCHEMAS","AUTHOR_RESERVED_SEMANTIC_VALIDATOR","AUTHOR_IMMUTABLE_R7_GREEN_HARNESS","EXECUTE_BOUND_R7_GREEN","AUTHOR_R7_GREEN_RECEIPT","AUTHOR_INDEPENDENT_R7_SEMANTIC_ACCEPTANCE_REVIEW"]},"rejected_scope":{"const":["AGGREGATE_ADMISSION","G3_01","PRODUCTION","RUNTIME","NATIVE","PROVIDER","PUBLICATION","ADMISSION","PACKAGE","INSTALL","RELEASE","CUTOVER","COMMIT","PUSH"]},"part_0_genericity":{"$ref":"#/$defs/part0"},"authority_ceiling":{"$ref":"#/$defs/authority"},"review_body_sha256":{"$ref":"#/$defs/hex"}
  },
  "allOf":[{"if":{"properties":{"disposition":{"const":"PASS_R7_PREIMPLEMENTATION_FOR_EXACT_STOPPED_SEMANTIC_GREEN_ONLY"}}},"then":{"properties":{"checks":{"not":{"contains":{"properties":{"result":{"const":"FAIL"}}}}},"findings":{"additionalProperties":{"not":{"properties":{"status":{"const":"OPEN"}}}}},"open_findings":{"maxItems":0},"failure_bindings":{"maxItems":0}}}},{"if":{"properties":{"disposition":{"const":"REJECTED"}}},"then":{"properties":{"checks":{"contains":{"properties":{"result":{"const":"FAIL"}}},"minContains":1},"findings":{"minProperties":1},"open_findings":{"minItems":1},"failure_bindings":{"minItems":1}}}}],
  "$defs":{
    "hex":{"type":"string","pattern":"^[0-9a-f]{64}$"},"id":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]*$"},"path":{"type":"string","minLength":1,"maxLength":4096,"pattern":"^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[\\\\:\\x00-\\x1f\\x7f])[^/]+(?:/[^/]+)*$"},"file":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"$ref":"#/$defs/path"},"size_bytes":{"type":"integer","minimum":1,"maximum":9007199254740991},"sha256":{"$ref":"#/$defs/hex"}}},
    "registry":{"const":{"domain":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_PATH_REGISTRY_V1","entries":[{"ordinal":0,"stage":"PRE_REVIEW_REQUIRED_INPUT","kind":"BOUND_ROSTER","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_BOUND_PRINCIPAL_ROSTER.v1.json"},{"ordinal":1,"stage":"REVIEW_ATOMIC_OUTPUT","kind":"PREIMPLEMENTATION_REVIEW","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_PREIMPLEMENTATION_REVIEW.v1.json"},{"ordinal":2,"stage":"POST_REVIEW_OUTPUT","kind":"SCHEMA_RENDER","path":"rules/schemas/program_facts_g3_00_admission_lineage_r7_principal_roster.v1.schema.json"},{"ordinal":3,"stage":"POST_REVIEW_OUTPUT","kind":"SCHEMA_RENDER","path":"rules/schemas/program_facts_g3_00_admission_lineage_r7_preimplementation_review.v1.schema.json"},{"ordinal":4,"stage":"POST_REVIEW_OUTPUT","kind":"SCHEMA_RENDER","path":"rules/schemas/program_facts_g3_00_admission_lineage_r7_semantic_green_receipt.v1.schema.json"},{"ordinal":5,"stage":"POST_REVIEW_OUTPUT","kind":"SCHEMA_RENDER","path":"rules/schemas/program_facts_g3_00_admission_lineage_r7_semantic_acceptance_review.v1.schema.json"},{"ordinal":6,"stage":"POST_REVIEW_OUTPUT","kind":"SEMANTIC_VALIDATOR","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/validate_admission_lineage_r5_ordering_semantics_v1.py"},{"ordinal":7,"stage":"POST_REVIEW_OUTPUT","kind":"GREEN_HARNESS","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/test_admission_lineage_r7_semantic_successor_green_v1.py"},{"ordinal":8,"stage":"POST_REVIEW_OUTPUT","kind":"GREEN_RECEIPT","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_SEMANTIC_GREEN_RECEIPT.v1.json"},{"ordinal":9,"stage":"POST_REVIEW_OUTPUT","kind":"SEMANTIC_ACCEPTANCE_REVIEW","path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_SEMANTIC_ACCEPTANCE_REVIEW.v1.json"}]}},
    "membership":{"const":["review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_BOUND_PRINCIPAL_ROSTER.v1.json","review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_PREIMPLEMENTATION_REVIEW.v1.json","rules/schemas/program_facts_g3_00_admission_lineage_r7_principal_roster.v1.schema.json","rules/schemas/program_facts_g3_00_admission_lineage_r7_preimplementation_review.v1.schema.json","rules/schemas/program_facts_g3_00_admission_lineage_r7_semantic_green_receipt.v1.schema.json","rules/schemas/program_facts_g3_00_admission_lineage_r7_semantic_acceptance_review.v1.schema.json","review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/validate_admission_lineage_r5_ordering_semantics_v1.py","review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/test_admission_lineage_r7_semantic_successor_green_v1.py","review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_SEMANTIC_GREEN_RECEIPT.v1.json","review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_SEMANTIC_ACCEPTANCE_REVIEW.v1.json"]},
    "candidate":{"type":"object","additionalProperties":false,"required":["path_registry","path_registry_sha256","path_membership","path_membership_sha256","post_review_paths_sha256","inline_schema_sha256","denominator_sha256","candidate_set_sha256"],"properties":{"path_registry":{"$ref":"#/$defs/registry"},"path_registry_sha256":{"const":"38506903e9ff023972512c26d8ad83c02aa096f548e6363a754a0470888304dc"},"path_membership":{"$ref":"#/$defs/membership"},"path_membership_sha256":{"const":"69e5fcdfa94638a40ef52ce351b95b9d72122d149a0aef3379b1902d788f5537"},"post_review_paths_sha256":{"const":"820c06d86a9005b475c4768665841267d0bd79f9f1530480110f0667fcbfc3c1"},"inline_schema_sha256":{"type":"array","minItems":4,"maxItems":4,"prefixItems":[{"$ref":"#/$defs/hex"},{"$ref":"#/$defs/hex"},{"$ref":"#/$defs/hex"},{"$ref":"#/$defs/hex"}],"items":false},"denominator_sha256":{"const":"ec72cf672f3a71ecb2dbf3c0ad11ed3f36728060e416f506f3eff9c262f7d0f5"},"candidate_set_sha256":{"$ref":"#/$defs/hex"}}},
    "denominator":{"const":{"domain":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_RED_GREEN_DENOMINATOR_V1","inherited_red_receipt":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_ORDERING_RED_RECEIPT.v1.json","size_bytes":7429,"sha256":"d8f6a711760b3f52b7be61abb0c9778cdf0260a1283fa15e542984f4a7b5ff26"},"reserved_successor_path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/validate_admission_lineage_r5_ordering_semantics_v1.py","green_harness_path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/test_admission_lineage_r7_semantic_successor_green_v1.py","controls":["VALID_PASS_REVIEW_ACCEPTED","TRUTHFUL_REJECTED_REVIEW_ACCEPTED","VALID_SIGNED_ROSTER_ACCEPTED"],"mutations":[{"case_id":"ALC-R7-01-HIDDEN-OPEN-BLOCKER","expected_rejection":"PASS_OPEN_FINDING_FORBIDDEN"},{"case_id":"ALC-R7-02-OPEN-ROSTER-MISMATCH","expected_rejection":"FINDING_PROJECTION_MISMATCH"},{"case_id":"ALC-R7-03-PRINCIPAL-ALIAS","expected_rejection":"PRINCIPAL_ALIAS"},{"case_id":"ALC-R7-04-PRINCIPAL-RELABEL","expected_rejection":"PRINCIPAL_BINDING_MISMATCH"},{"case_id":"ALC-R7-05-UNAUTHORIZED-SUCCESSOR","expected_rejection":"UNAUTHORIZED_SEMANTIC_SUCCESSOR"},{"case_id":"ALC-R7-06-FALSE-SEMANTIC-ACCEPTANCE","expected_rejection":"FALSE_SEMANTIC_ACCEPTANCE"},{"case_id":"ALC-R7-07-MISSING-REQUIRED-ROSTER","expected_rejection":"MISSING_REQUIRED_ROSTER"},{"case_id":"ALC-R7-08-EXTRA-PRE-REVIEW-OUTPUT","expected_rejection":"PRE_REVIEW_OUTPUT_PRESENT"},{"case_id":"ALC-R7-09-PATH-REGISTRY-REORDER","expected_rejection":"PATH_REGISTRY_ORDER_MISMATCH"},{"case_id":"ALC-R7-10-PATH-REGISTRY-ALIAS","expected_rejection":"PATH_REGISTRY_ALIAS"},{"case_id":"ALC-R7-11-PATH-REGISTRY-DUPLICATE","expected_rejection":"PATH_REGISTRY_DUPLICATE"},{"case_id":"ALC-R7-12-PATH-REGISTRY-HASH-MISMATCH","expected_rejection":"PATH_REGISTRY_HASH_MISMATCH"}],"green_oracle":{"control_accept_count":3,"mutation_reject_count":12,"unexpected_accept_count":0,"control_failure_count":0,"process_exit":0,"semantic_acceptance_claimed_by_green_receipt":false},"acceptance_stage":"INDEPENDENT_POST_GREEN_REVIEW_ONLY"}},
    "stage":{"type":"object","additionalProperties":false,"required":["roster","review_target","post_review_paths","post_review_absent_count","post_review_paths_sha256"],"properties":{"roster":{"type":"object","additionalProperties":false,"required":["path","state","sha256"],"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_BOUND_PRINCIPAL_ROSTER.v1.json"},"state":{"const":"PRESENT_VALIDATED"},"sha256":{"$ref":"#/$defs/hex"}}},"review_target":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_PREIMPLEMENTATION_REVIEW.v1.json","state":"ABSENT_BEFORE_ATOMIC_WRITE"}},"post_review_paths":{"const":["rules/schemas/program_facts_g3_00_admission_lineage_r7_principal_roster.v1.schema.json","rules/schemas/program_facts_g3_00_admission_lineage_r7_preimplementation_review.v1.schema.json","rules/schemas/program_facts_g3_00_admission_lineage_r7_semantic_green_receipt.v1.schema.json","rules/schemas/program_facts_g3_00_admission_lineage_r7_semantic_acceptance_review.v1.schema.json","review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/validate_admission_lineage_r5_ordering_semantics_v1.py","review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/test_admission_lineage_r7_semantic_successor_green_v1.py","review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_SEMANTIC_GREEN_RECEIPT.v1.json","review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_SEMANTIC_ACCEPTANCE_REVIEW.v1.json"]},"post_review_absent_count":{"const":8},"post_review_paths_sha256":{"const":"820c06d86a9005b475c4768665841267d0bd79f9f1530480110f0667fcbfc3c1"}}},
    "check":{"type":"object","additionalProperties":false,"required":["check_id","result","evidence"],"properties":{"check_id":{"$ref":"#/$defs/id"},"result":{"enum":["PASS","FAIL"]},"evidence":{"type":"array","minItems":1,"maxItems":100,"uniqueItems":true,"items":{"$ref":"#/$defs/file"}}}},
    "c01":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7-01-SUBJECT-RECEIPT-ROSTER-EXACT"}}}]},"c02":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7-02-R5-FROZEN-BUNDLE-EXACT"}}}]},"c03":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7-03-R5-GOVERNED-PASS-EXACT"}}}]},"c04":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7-04-R6-REJECTED-BUNDLE-EXACT"}}}]},"c05":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7-05-HISTORICAL-INVALID-EXCLUDED"}}}]},"c06":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7-06-R7-PRINCIPALS-BOUND"}}}]},"c07":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7-07-R7-15-PAIR-SEPARATION"}}}]},"c08":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7-08-PRIOR-35-CROSS-SEPARATION"}}}]},"c09":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7-09-REVIEW-STAGE-PRESENCE-ABSENCE-EXACT"}}}]},"c10":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7-10-PATH-REGISTRY-CANONICAL-BACKJOIN"}}}]},"c11":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7-11-INLINE-SCHEMAS-VALID"}}}]},"c12":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7-12-RED-GREEN-DENOMINATOR-EXACT"}}}]},"c13":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7-13-HIDDEN-BLOCKER-AND-MISMATCH"}}}]},"c14":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7-14-ALIAS-AND-RELABEL"}}}]},"c15":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7-15-UNAUTHORIZED-AND-FALSE-ACCEPTANCE"}}}]},"c16":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7-16-MISSING-ROSTER-AND-EXTRA-OUTPUT"}}}]},"c17":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7-17-REGISTRY-ADVERSARIAL-CONTROLS"}}}]},"c18":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7-18-REVIEW-BEFORE-RENDER-CODE"}}}]},"c19":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7-19-AUTHORITY-PART0-EXACT"}}}]},"c20":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7-20-STOP-BEFORE-AGGREGATE"}}}]},
    "finding":{"type":"object","additionalProperties":false,"required":["severity","status","failed_checks","description","evidence"],"properties":{"severity":{"enum":["BLOCKING","NONBLOCKING"]},"status":{"enum":["OPEN","CLOSED"]},"failed_checks":{"type":"array","minItems":1,"uniqueItems":true,"items":{"$ref":"#/$defs/id"}},"description":{"type":"string","minLength":1},"evidence":{"type":"array","minItems":1,"uniqueItems":true,"items":{"$ref":"#/$defs/file"}}}},"failure":{"type":"object","additionalProperties":false,"required":["check_id","finding_ids"],"properties":{"check_id":{"$ref":"#/$defs/id"},"finding_ids":{"type":"array","minItems":1,"uniqueItems":true,"items":{"$ref":"#/$defs/id"}}}},
    "part0":{"const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},"authority":{"const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}}
  }
}
```


Canonicalization is RFC 8785 JSON Canonicalization Scheme over UTF-8 after
parsing with duplicate-member rejection. Strings must already be Unicode NFC;
normalization is validation-only and never rewrites a value. Object members are
JCS-sorted, but the `entries` array order is immutable. Each entry has exactly
`ordinal`, `stage`, `kind`, and `path`; ordinals are the integers 0 through 9
in ascending array order. Paths are case-sensitive repo-relative NFC strings,
use `/`, and forbid empty segments, `.`, `..`, backslash, colon, control bytes,
absolute roots, URI encodings, and Unicode-normalization aliases. All ten path
values must be unique before and after NFC validation. Alias resolution,
case-folding, filesystem canonicalization, and symlink substitution are
forbidden.

Let `CJ(x)` be those canonical UTF-8 bytes. The exact digest is:

`path_registry_sha256 = lowercase_hex(SHA256(CJ(path_registry)))`

and equals
`38506903e9ff023972512c26d8ad83c02aa096f548e6363a754a0470888304dc`.
The exact `path_membership` is the ten `path` strings projected from entries in
the same array order. Its digest is
`69e5fcdfa94638a40ef52ce351b95b9d72122d149a0aef3379b1902d788f5537`.
The ordered eight-path suffix projected from ordinals 2-9 has digest
`820c06d86a9005b475c4768665841267d0bd79f9f1530480110f0667fcbfc3c1`.

Every `candidate_projection` must contain the full literal registry, the exact
ten-string membership array, all three digests above, four canonical inline
schema digests in registry ordinal 2-5 order, the denominator digest, and a
candidate-set digest. The candidate-set preimage is exactly:

```text
PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_CANDIDATE_SET_V1\n
path_registry_sha256\n
path_membership_sha256\n
inline_schema_sha256[0]\n
inline_schema_sha256[1]\n
inline_schema_sha256[2]\n
inline_schema_sha256[3]\n
denominator_sha256
```

with the displayed LF separators and no terminal LF. The digest is lower-case
hex SHA-256 of the UTF-8 preimage. Semantic validation reparses the contract
registry, rejects duplicate members, recomputes all digests, derives membership
only from `entries`, and requires value equality for every ordinal/stage/kind/
path tuple and every candidate member. Missing, extra, reordered, aliased,
duplicated, or hash-mismatched registry material rejects; no supplied digest is
self-authenticating.

## 5. Stage-specific presence and absence

At author time all ten registry paths are absent. That author-time observation
is not the governed-review predicate. The exact governed-review transaction is:

1. registry ordinal 0, the r7 bound roster, MUST already exist, validate against
   the exact inline roster schema, authenticate its subject and author receipt,
   and bind the reviewer at principal ordinal 2;
2. registry ordinal 1, the r7 review path, MUST be absent immediately before
   atomic creation of the completed review record; and
3. registry ordinals 2-9, exactly eight strictly post-review outputs, MUST all
   be absent throughout review and at the atomic write boundary.

The reviewer performs stable no-follow reads, records the roster hash, and
checks exact registry membership. Any missing/invalid roster yields
`MISSING_REQUIRED_ROSTER`. Any present ordinal 1 before the atomic operation or
any present ordinal 2-9 yields `PRE_REVIEW_OUTPUT_PRESENT`. The R6 roster had
the same required-pre-review role for the historical r6 review; it is frozen
r6 evidence and cannot satisfy the new r7 roster input.

Only a valid atomic r7 PASS review may authorize unchanged rendering of the
four reviewed schemas and creation of the validator/harness. A REJECTED,
partial, retroactive, or later-edited review authorizes nothing.

## 6. Exact RED-to-GREEN denominator

```json
{
  "domain":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_RED_GREEN_DENOMINATOR_V1",
  "inherited_red_receipt":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_ORDERING_RED_RECEIPT.v1.json","size_bytes":7429,"sha256":"d8f6a711760b3f52b7be61abb0c9778cdf0260a1283fa15e542984f4a7b5ff26"},
  "reserved_successor_path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/validate_admission_lineage_r5_ordering_semantics_v1.py",
  "green_harness_path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/test_admission_lineage_r7_semantic_successor_green_v1.py",
  "controls":["VALID_PASS_REVIEW_ACCEPTED","TRUTHFUL_REJECTED_REVIEW_ACCEPTED","VALID_SIGNED_ROSTER_ACCEPTED"],
  "mutations":[
    {"case_id":"ALC-R7-01-HIDDEN-OPEN-BLOCKER","expected_rejection":"PASS_OPEN_FINDING_FORBIDDEN"},
    {"case_id":"ALC-R7-02-OPEN-ROSTER-MISMATCH","expected_rejection":"FINDING_PROJECTION_MISMATCH"},
    {"case_id":"ALC-R7-03-PRINCIPAL-ALIAS","expected_rejection":"PRINCIPAL_ALIAS"},
    {"case_id":"ALC-R7-04-PRINCIPAL-RELABEL","expected_rejection":"PRINCIPAL_BINDING_MISMATCH"},
    {"case_id":"ALC-R7-05-UNAUTHORIZED-SUCCESSOR","expected_rejection":"UNAUTHORIZED_SEMANTIC_SUCCESSOR"},
    {"case_id":"ALC-R7-06-FALSE-SEMANTIC-ACCEPTANCE","expected_rejection":"FALSE_SEMANTIC_ACCEPTANCE"},
    {"case_id":"ALC-R7-07-MISSING-REQUIRED-ROSTER","expected_rejection":"MISSING_REQUIRED_ROSTER"},
    {"case_id":"ALC-R7-08-EXTRA-PRE-REVIEW-OUTPUT","expected_rejection":"PRE_REVIEW_OUTPUT_PRESENT"},
    {"case_id":"ALC-R7-09-PATH-REGISTRY-REORDER","expected_rejection":"PATH_REGISTRY_ORDER_MISMATCH"},
    {"case_id":"ALC-R7-10-PATH-REGISTRY-ALIAS","expected_rejection":"PATH_REGISTRY_ALIAS"},
    {"case_id":"ALC-R7-11-PATH-REGISTRY-DUPLICATE","expected_rejection":"PATH_REGISTRY_DUPLICATE"},
    {"case_id":"ALC-R7-12-PATH-REGISTRY-HASH-MISMATCH","expected_rejection":"PATH_REGISTRY_HASH_MISMATCH"}
  ],
  "green_oracle":{"control_accept_count":3,"mutation_reject_count":12,"unexpected_accept_count":0,"control_failure_count":0,"process_exit":0,"semantic_acceptance_claimed_by_green_receipt":false},
  "acceptance_stage":"INDEPENDENT_POST_GREEN_REVIEW_ONLY"
}
```

The denominator digest is
`ec72cf672f3a71ecb2dbf3c0ad11ed3f36728060e416f506f3eff9c262f7d0f5`.
The first six mutations preserve the r6 semantic denominator; the last six
prove the r7 corrections. GREEN means all three controls accept, all twelve
mutations reject with their exact codes, no unexpected acceptance/control
failure occurs, and process exit is zero. The GREEN receipt must still record
`semantic_acceptance_confirmed:false`; only the distinct ordinal-5 reviewer may
later issue the stopped semantic-acceptance record.

## 7. Closed inline schemas

Together with section 4.1, these are the only four render candidates. Each is
Draft 2020-12, duplicate-free,
closed at every governed object, and uses only fragment-local references. A
renderer may emit its candidate unchanged only after the governed r7 PASS.

### 7.1 R7 bound-principal roster

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_r7_principal_roster.v1.schema.json",
  "type":"object","additionalProperties":false,
  "required":["schema_version","roster_id","subject","author_receipt","roles","principal_ids","prior_evidence_producer_ids","bindings","binding_signature","separation_projection","part_0_genericity","authority_ceiling","roster_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_r7_principal_roster.v1"},"roster_id":{"type":"string","pattern":"^pfg3alr7pr-[0-9a-f]{32}$"},
    "subject":{"allOf":[{"$ref":"#/$defs/file"},{"properties":{"path":{"const":"architecture/program-facts-g3-00-admission-lineage-r7-semantic-successor-correction-amendment.md"}}}]},
    "author_receipt":{"allOf":[{"$ref":"#/$defs/file"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_SEMANTIC_SUCCESSOR_CORRECTION_AUTHOR_RECEIPT.md"}}}]},
    "roles":{"const":["R7_AMENDMENT_AUTHOR","R7_ROSTER_BINDER","R7_INDEPENDENT_PREIMPLEMENTATION_REVIEWER","R7_SEMANTIC_SUCCESSOR_IMPLEMENTER","R7_GREEN_EXECUTOR_FIXTURE_AUTHOR","R7_INDEPENDENT_SEMANTIC_ACCEPTANCE_REVIEWER"]},
    "principal_ids":{"type":"array","minItems":6,"maxItems":6,"uniqueItems":true,"prefixItems":[{"const":"Codex:/root/g3_r3_correction_author_short"},{"$ref":"#/$defs/prospective"},{"$ref":"#/$defs/prospective"},{"$ref":"#/$defs/prospective"},{"$ref":"#/$defs/prospective"},{"$ref":"#/$defs/prospective"}],"items":false},
    "prior_evidence_producer_ids":{"const":["Codex:/root/g3_r3_correction_author_short","Codex:/root/g3_r5_principal_roster_binder_short","Codex:/root/g3_r5_ordering_review_short","Codex:/root/g3_r5_schema_renderer_short","Codex:/root/g3_r5_fixture_author_short","Codex:/root/g3_r6_principal_roster_binder_short","Codex:/root/g3_r6_preimplementation_review_short"]},
    "bindings":{"type":"array","minItems":6,"maxItems":6,"prefixItems":[{"$ref":"#/$defs/b0"},{"$ref":"#/$defs/b1"},{"$ref":"#/$defs/b2"},{"$ref":"#/$defs/b3"},{"$ref":"#/$defs/b4"},{"$ref":"#/$defs/b5"}],"items":false},
    "binding_signature":{"type":"object","additionalProperties":false,"required":["algorithm","signer_principal_ordinal","public_key_base64","signed_preimage_sha256","signature_base64"],"properties":{"algorithm":{"const":"ED25519"},"signer_principal_ordinal":{"const":1},"public_key_base64":{"type":"string","pattern":"^[A-Za-z0-9+/]{43}=$"},"signed_preimage_sha256":{"$ref":"#/$defs/hex"},"signature_base64":{"type":"string","pattern":"^[A-Za-z0-9+/]{86}==$"}}},
    "separation_projection":{"$ref":"#/$defs/separation"},"part_0_genericity":{"$ref":"#/$defs/part0"},"authority_ceiling":{"$ref":"#/$defs/authority"},"roster_body_sha256":{"$ref":"#/$defs/hex"}
  },
  "$defs":{
    "hex":{"type":"string","pattern":"^[0-9a-f]{64}$"},"path":{"type":"string","minLength":1,"maxLength":4096,"pattern":"^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[\\\\:\\x00-\\x1f\\x7f])[^/]+(?:/[^/]+)*$"},"principal":{"type":"string","minLength":12,"maxLength":256,"pattern":"^[A-Za-z][A-Za-z0-9._-]*:/[A-Za-z0-9._/-]+$"},
    "prospective":{"allOf":[{"$ref":"#/$defs/principal"},{"not":{"enum":["Codex:/root/g3_r3_correction_author_short","Codex:/root/g3_r5_principal_roster_binder_short","Codex:/root/g3_r5_ordering_review_short","Codex:/root/g3_r5_schema_renderer_short","Codex:/root/g3_r5_fixture_author_short","Codex:/root/g3_r6_principal_roster_binder_short","Codex:/root/g3_r6_preimplementation_review_short"]}}]},
    "file":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"$ref":"#/$defs/path"},"size_bytes":{"type":"integer","minimum":1,"maximum":9007199254740991},"sha256":{"$ref":"#/$defs/hex"}}},
    "extracted":{"type":"object","additionalProperties":false,"required":["kind","artifact","locator"],"properties":{"kind":{"const":"IMMUTABLE_ARTIFACT_EXTRACTION"},"artifact":{"$ref":"#/$defs/file"},"locator":{"const":{"syntax":"MARKDOWN_EXACT_LABEL","label":"Author principal:"}}}},
    "signed":{"type":"object","additionalProperties":false,"required":["kind","assignment_domain","assignment_body_sha256"],"properties":{"kind":{"const":"SIGNED_ROSTER_ASSIGNMENT"},"assignment_domain":{"const":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_PRINCIPAL_ASSIGNMENT_V1"},"assignment_body_sha256":{"$ref":"#/$defs/hex"}}},
    "binding":{"type":"object","additionalProperties":false,"required":["role","principal_ordinal","source"],"properties":{"role":{"type":"string"},"principal_ordinal":{"type":"integer","minimum":0,"maximum":5},"source":{"oneOf":[{"$ref":"#/$defs/extracted"},{"$ref":"#/$defs/signed"}]}}},
    "b0":{"allOf":[{"$ref":"#/$defs/binding"},{"properties":{"role":{"const":"R7_AMENDMENT_AUTHOR"},"principal_ordinal":{"const":0},"source":{"$ref":"#/$defs/extracted"}}}]},"b1":{"allOf":[{"$ref":"#/$defs/binding"},{"properties":{"role":{"const":"R7_ROSTER_BINDER"},"principal_ordinal":{"const":1},"source":{"$ref":"#/$defs/signed"}}}]},"b2":{"allOf":[{"$ref":"#/$defs/binding"},{"properties":{"role":{"const":"R7_INDEPENDENT_PREIMPLEMENTATION_REVIEWER"},"principal_ordinal":{"const":2},"source":{"$ref":"#/$defs/signed"}}}]},"b3":{"allOf":[{"$ref":"#/$defs/binding"},{"properties":{"role":{"const":"R7_SEMANTIC_SUCCESSOR_IMPLEMENTER"},"principal_ordinal":{"const":3},"source":{"$ref":"#/$defs/signed"}}}]},"b4":{"allOf":[{"$ref":"#/$defs/binding"},{"properties":{"role":{"const":"R7_GREEN_EXECUTOR_FIXTURE_AUTHOR"},"principal_ordinal":{"const":4},"source":{"$ref":"#/$defs/signed"}}}]},"b5":{"allOf":[{"$ref":"#/$defs/binding"},{"properties":{"role":{"const":"R7_INDEPENDENT_SEMANTIC_ACCEPTANCE_REVIEWER"},"principal_ordinal":{"const":5},"source":{"$ref":"#/$defs/signed"}}}]},
    "separation":{"type":"object","additionalProperties":false,"required":["r7_pair_count","cross_prior_pair_count","declared_continuity_pairs","unexpected_r7_equal_pairs","unexpected_cross_equal_pairs","principal_ids_sha256","projection_body_sha256"],"properties":{"r7_pair_count":{"const":15},"cross_prior_pair_count":{"const":35},"declared_continuity_pairs":{"const":[{"r7_ordinal":0,"prior_producer_ordinal":0,"principal_id":"Codex:/root/g3_r3_correction_author_short"}]},"unexpected_r7_equal_pairs":{"type":"array","maxItems":0},"unexpected_cross_equal_pairs":{"type":"array","maxItems":0},"principal_ids_sha256":{"$ref":"#/$defs/hex"},"projection_body_sha256":{"$ref":"#/$defs/hex"}}},
    "part0":{"const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},"authority":{"const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}}
  }
}
```

### 7.2 R7 semantic GREEN receipt

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_r7_semantic_green_receipt.v1.schema.json","type":"object","additionalProperties":false,
  "required":["schema_version","receipt_id","contract","principal_roster","preimplementation_review","rendered_schemas","semantic_validator","green_harness","actor_projection","path_registry_sha256","denominator_sha256","candidate_set_sha256","controls","mutations","summary","semantic_acceptance_confirmed","scope","part_0_genericity","authority_ceiling","receipt_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_r7_semantic_green_receipt.v1"},"receipt_id":{"type":"string","pattern":"^pfg3alr7green-[0-9a-f]{32}$"},
    "contract":{"allOf":[{"$ref":"#/$defs/file"},{"properties":{"path":{"const":"architecture/program-facts-g3-00-admission-lineage-r7-semantic-successor-correction-amendment.md"}}}]},"principal_roster":{"allOf":[{"$ref":"#/$defs/file"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_BOUND_PRINCIPAL_ROSTER.v1.json"}}}]},"preimplementation_review":{"allOf":[{"$ref":"#/$defs/file"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_PREIMPLEMENTATION_REVIEW.v1.json"}}}]},
    "rendered_schemas":{"type":"array","minItems":4,"maxItems":4,"prefixItems":[{"allOf":[{"$ref":"#/$defs/file"},{"properties":{"path":{"const":"rules/schemas/program_facts_g3_00_admission_lineage_r7_principal_roster.v1.schema.json"}}}]},{"allOf":[{"$ref":"#/$defs/file"},{"properties":{"path":{"const":"rules/schemas/program_facts_g3_00_admission_lineage_r7_preimplementation_review.v1.schema.json"}}}]},{"allOf":[{"$ref":"#/$defs/file"},{"properties":{"path":{"const":"rules/schemas/program_facts_g3_00_admission_lineage_r7_semantic_green_receipt.v1.schema.json"}}}]},{"allOf":[{"$ref":"#/$defs/file"},{"properties":{"path":{"const":"rules/schemas/program_facts_g3_00_admission_lineage_r7_semantic_acceptance_review.v1.schema.json"}}}]}],"items":false},
    "semantic_validator":{"allOf":[{"$ref":"#/$defs/file"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/validate_admission_lineage_r5_ordering_semantics_v1.py"}}}]},"green_harness":{"allOf":[{"$ref":"#/$defs/file"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/test_admission_lineage_r7_semantic_successor_green_v1.py"}}}]},
    "actor_projection":{"const":{"semantic_implementer_ordinal":3,"green_executor_fixture_author_ordinal":4}},"path_registry_sha256":{"const":"38506903e9ff023972512c26d8ad83c02aa096f548e6363a754a0470888304dc"},"denominator_sha256":{"const":"ec72cf672f3a71ecb2dbf3c0ad11ed3f36728060e416f506f3eff9c262f7d0f5"},"candidate_set_sha256":{"$ref":"#/$defs/hex"},
    "controls":{"type":"array","minItems":3,"maxItems":3,"prefixItems":[{"const":{"control_id":"VALID_PASS_REVIEW_ACCEPTED","outcome":"ACCEPTED"}},{"const":{"control_id":"TRUTHFUL_REJECTED_REVIEW_ACCEPTED","outcome":"ACCEPTED"}},{"const":{"control_id":"VALID_SIGNED_ROSTER_ACCEPTED","outcome":"ACCEPTED"}}],"items":false},
    "mutations":{"type":"array","minItems":12,"maxItems":12,"prefixItems":[{"$ref":"#/$defs/m1"},{"$ref":"#/$defs/m2"},{"$ref":"#/$defs/m3"},{"$ref":"#/$defs/m4"},{"$ref":"#/$defs/m5"},{"$ref":"#/$defs/m6"},{"$ref":"#/$defs/m7"},{"$ref":"#/$defs/m8"},{"$ref":"#/$defs/m9"},{"$ref":"#/$defs/m10"},{"$ref":"#/$defs/m11"},{"$ref":"#/$defs/m12"}],"items":false},
    "summary":{"const":{"control_accept_count":3,"mutation_reject_count":12,"unexpected_accept_count":0,"control_failure_count":0,"process_exit":0}},"semantic_acceptance_confirmed":{"const":false},"scope":{"const":"SEMANTIC_GREEN_EVIDENCE_ONLY_PENDING_INDEPENDENT_ACCEPTANCE"},"part_0_genericity":{"$ref":"#/$defs/part0"},"authority_ceiling":{"$ref":"#/$defs/authority"},"receipt_body_sha256":{"$ref":"#/$defs/hex"}
  },
  "$defs":{
    "hex":{"type":"string","pattern":"^[0-9a-f]{64}$"},"file":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"type":"string","minLength":1,"maxLength":4096},"size_bytes":{"type":"integer","minimum":1,"maximum":9007199254740991},"sha256":{"$ref":"#/$defs/hex"}}},
    "mutation":{"type":"object","additionalProperties":false,"required":["case_id","outcome","rejection_code","evidence"],"properties":{"case_id":{"type":"string"},"outcome":{"const":"REJECTED_AS_EXPECTED"},"rejection_code":{"type":"string"},"evidence":{"type":"array","minItems":1,"uniqueItems":true,"items":{"$ref":"#/$defs/file"}}}},
    "m1":{"allOf":[{"$ref":"#/$defs/mutation"},{"properties":{"case_id":{"const":"ALC-R7-01-HIDDEN-OPEN-BLOCKER"},"rejection_code":{"const":"PASS_OPEN_FINDING_FORBIDDEN"}}}]},"m2":{"allOf":[{"$ref":"#/$defs/mutation"},{"properties":{"case_id":{"const":"ALC-R7-02-OPEN-ROSTER-MISMATCH"},"rejection_code":{"const":"FINDING_PROJECTION_MISMATCH"}}}]},"m3":{"allOf":[{"$ref":"#/$defs/mutation"},{"properties":{"case_id":{"const":"ALC-R7-03-PRINCIPAL-ALIAS"},"rejection_code":{"const":"PRINCIPAL_ALIAS"}}}]},"m4":{"allOf":[{"$ref":"#/$defs/mutation"},{"properties":{"case_id":{"const":"ALC-R7-04-PRINCIPAL-RELABEL"},"rejection_code":{"const":"PRINCIPAL_BINDING_MISMATCH"}}}]},"m5":{"allOf":[{"$ref":"#/$defs/mutation"},{"properties":{"case_id":{"const":"ALC-R7-05-UNAUTHORIZED-SUCCESSOR"},"rejection_code":{"const":"UNAUTHORIZED_SEMANTIC_SUCCESSOR"}}}]},"m6":{"allOf":[{"$ref":"#/$defs/mutation"},{"properties":{"case_id":{"const":"ALC-R7-06-FALSE-SEMANTIC-ACCEPTANCE"},"rejection_code":{"const":"FALSE_SEMANTIC_ACCEPTANCE"}}}]},"m7":{"allOf":[{"$ref":"#/$defs/mutation"},{"properties":{"case_id":{"const":"ALC-R7-07-MISSING-REQUIRED-ROSTER"},"rejection_code":{"const":"MISSING_REQUIRED_ROSTER"}}}]},"m8":{"allOf":[{"$ref":"#/$defs/mutation"},{"properties":{"case_id":{"const":"ALC-R7-08-EXTRA-PRE-REVIEW-OUTPUT"},"rejection_code":{"const":"PRE_REVIEW_OUTPUT_PRESENT"}}}]},"m9":{"allOf":[{"$ref":"#/$defs/mutation"},{"properties":{"case_id":{"const":"ALC-R7-09-PATH-REGISTRY-REORDER"},"rejection_code":{"const":"PATH_REGISTRY_ORDER_MISMATCH"}}}]},"m10":{"allOf":[{"$ref":"#/$defs/mutation"},{"properties":{"case_id":{"const":"ALC-R7-10-PATH-REGISTRY-ALIAS"},"rejection_code":{"const":"PATH_REGISTRY_ALIAS"}}}]},"m11":{"allOf":[{"$ref":"#/$defs/mutation"},{"properties":{"case_id":{"const":"ALC-R7-11-PATH-REGISTRY-DUPLICATE"},"rejection_code":{"const":"PATH_REGISTRY_DUPLICATE"}}}]},"m12":{"allOf":[{"$ref":"#/$defs/mutation"},{"properties":{"case_id":{"const":"ALC-R7-12-PATH-REGISTRY-HASH-MISMATCH"},"rejection_code":{"const":"PATH_REGISTRY_HASH_MISMATCH"}}}]},
    "part0":{"const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},"authority":{"const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}}
  }
}
```

### 7.3 R7 independent semantic-acceptance review

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_r7_semantic_acceptance_review.v1.schema.json","type":"object","additionalProperties":false,
  "required":["schema_version","review_id","subject","principal_roster","preimplementation_review","green_receipt","reviewer_principal_ordinal","checks","findings","open_findings","failure_bindings","disposition","aggregate_admission_authorized","part_0_genericity","authority_ceiling","review_body_sha256"],
  "properties":{"schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_r7_semantic_acceptance_review.v1"},"review_id":{"type":"string","pattern":"^pfg3alr7accept-[0-9a-f]{32}$"},"subject":{"allOf":[{"$ref":"#/$defs/file"},{"properties":{"path":{"const":"architecture/program-facts-g3-00-admission-lineage-r7-semantic-successor-correction-amendment.md"}}}]},"principal_roster":{"allOf":[{"$ref":"#/$defs/file"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_BOUND_PRINCIPAL_ROSTER.v1.json"}}}]},"preimplementation_review":{"allOf":[{"$ref":"#/$defs/file"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_PREIMPLEMENTATION_REVIEW.v1.json"}}}]},"green_receipt":{"allOf":[{"$ref":"#/$defs/file"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R7_SEMANTIC_GREEN_RECEIPT.v1.json"}}}]},"reviewer_principal_ordinal":{"const":5},"checks":{"type":"array","minItems":14,"maxItems":14,"prefixItems":[{"$ref":"#/$defs/c1"},{"$ref":"#/$defs/c2"},{"$ref":"#/$defs/c3"},{"$ref":"#/$defs/c4"},{"$ref":"#/$defs/c5"},{"$ref":"#/$defs/c6"},{"$ref":"#/$defs/c7"},{"$ref":"#/$defs/c8"},{"$ref":"#/$defs/c9"},{"$ref":"#/$defs/c10"},{"$ref":"#/$defs/c11"},{"$ref":"#/$defs/c12"},{"$ref":"#/$defs/c13"},{"$ref":"#/$defs/c14"}],"items":false},"findings":{"type":"object","propertyNames":{"$ref":"#/$defs/id"},"additionalProperties":{"$ref":"#/$defs/finding"}},"open_findings":{"type":"array","uniqueItems":true,"items":{"$ref":"#/$defs/id"}},"failure_bindings":{"type":"array","uniqueItems":true,"items":{"$ref":"#/$defs/failure"}},"disposition":{"enum":["PASS_R7_SEMANTIC_SUCCESSOR_FOR_STOPPED_PART0_ONLY","REJECTED"]},"aggregate_admission_authorized":{"const":false},"part_0_genericity":{"$ref":"#/$defs/part0"},"authority_ceiling":{"$ref":"#/$defs/authority"},"review_body_sha256":{"$ref":"#/$defs/hex"}},
  "allOf":[{"if":{"properties":{"disposition":{"const":"PASS_R7_SEMANTIC_SUCCESSOR_FOR_STOPPED_PART0_ONLY"}}},"then":{"properties":{"checks":{"not":{"contains":{"properties":{"result":{"const":"FAIL"}}}}},"findings":{"additionalProperties":{"not":{"properties":{"status":{"const":"OPEN"}}}}},"open_findings":{"maxItems":0},"failure_bindings":{"maxItems":0}}}},{"if":{"properties":{"disposition":{"const":"REJECTED"}}},"then":{"properties":{"checks":{"contains":{"properties":{"result":{"const":"FAIL"}}},"minContains":1},"findings":{"minProperties":1},"open_findings":{"minItems":1},"failure_bindings":{"minItems":1}}}}],
  "$defs":{"hex":{"type":"string","pattern":"^[0-9a-f]{64}$"},"id":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]*$"},"file":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"type":"string","minLength":1,"maxLength":4096},"size_bytes":{"type":"integer","minimum":1,"maximum":9007199254740991},"sha256":{"$ref":"#/$defs/hex"}}},"check":{"type":"object","additionalProperties":false,"required":["check_id","result","evidence"],"properties":{"check_id":{"$ref":"#/$defs/id"},"result":{"enum":["PASS","FAIL"]},"evidence":{"type":"array","minItems":1,"uniqueItems":true,"items":{"$ref":"#/$defs/file"}}}},
    "c1":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7A-01-SUBJECT-ROSTER-REVIEWS-EXACT"}}}]},"c2":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7A-02-PREIMPLEMENTATION-PASS-PRECEDES-CODE"}}}]},"c3":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7A-03-PATH-REGISTRY-BACKJOIN-EXACT"}}}]},"c4":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7A-04-VALIDATOR-HARNESS-BYTES-EXACT"}}}]},"c5":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7A-05-THREE-CONTROLS-ACCEPT"}}}]},"c6":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7A-06-TWELVE-MUTATIONS-REJECT"}}}]},"c7":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7A-07-PASS-REJECTED-TOTALITY-EXACT"}}}]},"c8":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7A-08-PRINCIPAL-SEPARATION-EXACT"}}}]},"c9":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7A-09-STAGE-ORDER-EXACT"}}}]},"c10":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7A-10-R5-R6-FROZEN-EXACT"}}}]},"c11":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7A-11-HISTORICAL-EXCLUSIONS-EXACT"}}}]},"c12":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7A-12-NO-FALSE-ACCEPTANCE"}}}]},"c13":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7A-13-AUTHORITY-PART0-EXACT"}}}]},"c14":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR7A-14-STOP-BEFORE-AGGREGATE"}}}]},
    "finding":{"type":"object","additionalProperties":false,"required":["severity","status","failed_checks","description","evidence"],"properties":{"severity":{"enum":["BLOCKING","NONBLOCKING"]},"status":{"enum":["OPEN","CLOSED"]},"failed_checks":{"type":"array","minItems":1,"uniqueItems":true,"items":{"$ref":"#/$defs/id"}},"description":{"type":"string","minLength":1},"evidence":{"type":"array","minItems":1,"uniqueItems":true,"items":{"$ref":"#/$defs/file"}}}},"failure":{"type":"object","additionalProperties":false,"required":["check_id","finding_ids"],"properties":{"check_id":{"$ref":"#/$defs/id"},"finding_ids":{"type":"array","minItems":1,"uniqueItems":true,"items":{"$ref":"#/$defs/id"}}}},"part0":{"const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},"authority":{"const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}}
  }
}
```

Canonical JSON hashes of the four inline schema objects, in registry ordinal
2-5 order, are exactly:

1. `c10e4016c2b41d1b3d0250ca0fbb3680facb6b0c40380cf048dc024a75d8babf`
2. `cc18c4e2271eb8956d85974720555e37d28c30e1257d34c2023429050c3891ed`
3. `b93372c4221baccc4552b8bb6a48bf58eb31b54af36593943518c209dc96a91b`
4. `081f282cee268af0076212907e5e50b1a9d5ecb665bff95f6f4aa06070ec00aa`

With those four values, the section-4 candidate-set formula yields exactly
`6f938305e78360d32702a0a3c82bda3b1ea1f011353ba8c82293d15ebf0710f2`.
The governed reviewer must record these exact five values; the schemas keep
their hash members syntactically non-self-referential, while semantic
validation supplies the exact equality constraint.

## 8. Semantic totality, exact DAG, and STOP

For either review, define `F` as the ordered set of FAIL check IDs and `O` as
the lexicographically ordered keys of findings whose severity/status is exactly
`BLOCKING/OPEN`. PASS requires every check row PASS, `F=[]`, no OPEN finding,
`O=[]`, `open_findings=[]`, and `failure_bindings=[]`. REJECTED requires
`F` nonempty; every OPEN finding is `BLOCKING/OPEN`; `open_findings == O`; each
member of `O` names a nonempty subset of `F`; failure bindings have domain
exactly `F` and map each failed check to exactly the inverse roster of open
findings naming it. No missing, extra, duplicated, closed, or nonblocking
finding may enter either projection. These equality joins are mandatory
semantic checks; schema validity alone never establishes PASS.

The r7 DAG has exactly 14 nodes and 19 edges:

```text
R7N00 R7_CORRECTION_CONTRACT
R7N01 R7_AUTHOR_RECEIPT
R7N02 R7_BOUND_PRINCIPAL_ROSTER
R7N03 R7_PREIMPLEMENTATION_REVIEW_PASS
R7N04 R7_ROSTER_SCHEMA_RENDER
R7N05 R7_PREIMPLEMENTATION_SCHEMA_RENDER
R7N06 R7_GREEN_RECEIPT_SCHEMA_RENDER
R7N07 R7_ACCEPTANCE_REVIEW_SCHEMA_RENDER
R7N08 RESERVED_SEMANTIC_VALIDATOR
R7N09 IMMUTABLE_R7_GREEN_HARNESS
R7N10 BOUND_R7_GREEN_EXECUTION
R7N11 R7_SEMANTIC_GREEN_RECEIPT
R7N12 INDEPENDENT_R7_SEMANTIC_ACCEPTANCE_REVIEW
R7N13 STOP_BEFORE_G3_00_AGGREGATE_ADMISSION

R7N00->R7N01
R7N00->R7N02
R7N01->R7N02
R7N02->R7N03
R7N03->R7N04
R7N03->R7N05
R7N03->R7N06
R7N03->R7N07
R7N03->R7N08
R7N03->R7N09
R7N04->R7N10
R7N05->R7N10
R7N06->R7N10
R7N07->R7N10
R7N08->R7N10
R7N09->R7N10
R7N10->R7N11
R7N11->R7N12
R7N12->R7N13
```

The roster is the required pre-review input. No render, validator, harness, or
GREEN node precedes the governed PASS. A REJECTED or absent review cannot
satisfy `R7N03`. `R7N13` is terminal with no outgoing edge. Even a valid r7
semantic-acceptance PASS stops before the G3-00 aggregate and authorizes no
aggregate manifest, G3-01 construction, production, runtime, native, provider,
publication, package, installation, release, or cutover action.

## 9. Mandatory author and governed-review validation

Validation MUST:

1. enforce UTF-8 without BOM, LF-only, exactly one final LF, duplicate-free JSON,
   closed member sets, and Draft 2020-12 metaschema validity;
2. resolve every fragment-local `$ref` and reject every external schema ref;
3. authenticate all 10 r5 and 4 r6 rows, the exact r5 PASS/RED meanings, and the
   exact r6 REJECTED 17/18/two-finding equality join;
4. parse the literal registry, enforce its exact 10 entries/order/stages/kinds,
   path syntax, NFC, duplicate-freedom, candidate membership, three fixed
   digests, and candidate-set formula;
5. at governed review require the validated r7 roster present, the review path
   absent before atomic write, and exactly the eight post-review paths absent;
6. validate the four inline schemas, 20 preimplementation check IDs, 14
   acceptance check IDs, three controls, 12 mutations and exact rejection codes;
7. derive 15 internal and 35 prospective cross-prior separations from principal
   values and signed/extracted bindings, never a Boolean assertion;
8. enforce the PASS/REJECTED totality and equality joins above;
9. prove the exact 14-node/19-edge DAG is duplicate-free and acyclic; and
10. verify Part-0, all 29 authority values false, historical exclusions, no
    candidate/production import or authority, and terminal STOP.

This author's bounded validation observes that only this amendment and its
author receipt are authorized now. The next scope is roster binding followed by
one independent governance/schema/RED-structure review. It is not schema
rendering, implementation, test execution, GREEN, semantic acceptance,
aggregate admission, G3-01, production, runtime, provider, native, or cutover.
