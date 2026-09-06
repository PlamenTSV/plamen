# Program Facts G3-00 admission-lineage Part-0 r5 ordering correction amendment

Status: `CONTRACT_ONLY_PENDING_R5_PROSPECTIVE_ROSTER_AND_GOVERNED_REVIEW`

This create-only amendment fixes only the r4 authorization-order deadlock. It
does not repair, accept, import, replay, or retroactively authorize any r4
output. The exact governed r4 JSON review remains `REJECTED`; every artifact
materialized before that governed review is historical-invalid and is not an
r5 input or evidence source.

R5 uses an entirely new namespace and this finite order:

```text
r5 contract + r5 author receipt
  -> signed prospective r5 principal roster
  -> independent governed r5 review PASS
  -> three exact schema renders + exact fixture source
  -> exact fixture test
  -> honest expected-RED receipt
  -> terminal no-GREEN
```

The pre-render governed review validates the embedded schemas, paths, fixture
candidate specification, mutations, and RED oracle structurally. It neither
executes nor requires an absent semantic successor and cannot claim RED
execution or semantic acceptance. All common and inherited V8 authority
members remain false.

## 1. Immutable lineage and exact historical-invalid boundary

The preserved contract/review observations are closed:

| Key | Path | Bytes | SHA-256 | Treatment |
|---|---|---:|---|---|
| `R2_CONTRACT` | `architecture/program-facts-g3-00-admission-lineage-closure-amendment.md` | 166233 | `9136a2b00ca32917e6dabb4023fa145b12daebb0f049601b1b59394408c572eb` | immutable rejected-lineage design only |
| `R2_REVIEW` | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_CLOSURE_R2_INDEPENDENT_REVIEW.v1.json` | 19451 | `47a3e1469e1d1c768499493181282bb778d1dcf248da9bbf07f5b91d65077257` | exact `REJECTED`, never promoted |
| `R3_CONTRACT` | `architecture/program-facts-g3-00-admission-lineage-r3-correction-amendment.md` | 47976 | `517a009f79051092d04e535469c9a116a3f0ae4a4708e02dd9cd5282cf054be1` | immutable inherited contract |
| `R3_REVIEW` | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R3_CORRECTION_INDEPENDENT_REVIEW.md` | 16219 | `37ed1997e8f25608147162d4b57d42bdee4044d9ee2044651c5d3bfcf5060eeb` | exact `REPAIR`, never promoted |
| `R4_CONTRACT` | `architecture/program-facts-g3-00-admission-lineage-r4-correction-amendment.md` | 43429 | `902eaed561a02a604d119e2c6dcd7310c54a0e97edd3a8e30e7259f9597e9a61` | immutable ordering-defective predecessor |
| `R4_AUTHOR_RECEIPT` | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_CORRECTION_AUTHOR_RECEIPT.md` | 5261 | `95d6cabfe088e86a03f01d8e73173505c83cd5dc1d7c864595362b4ec7cd85ad` | authorship only, never acceptance |
| `R4_GOVERNED_REVIEW` | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_CORRECTION_INDEPENDENT_REVIEW.v1.json` | 21347 | `2bfefef8511e71dd72653264c9536d222c757ca1eb2c0f00c77dc8ef1998337f` | exact `REJECTED`, two `BLOCKING/OPEN` findings |

The r4 governed review has exactly 16 checks, 14 `PASS`, and two `FAIL`:

```text
ALR4-13-FOCUSED-RED-DENOMINATOR
  -> ALR4-R4-F001-RED-SEMANTIC-SUCCESSOR-ABSENT
ALR4-14-CREATE-ONLY-REGISTRY-DAG
  -> ALR4-R4-F002-PREPASS-DAG-ORDER-VIOLATION
```

Its finding ledger, `open_findings`, and failure bindings remain exact and
open. A Markdown review that earlier said `ACCEPT` is not the governed JSON
review and has no precedence over the governed rejection.

The exact historical-invalid roster contains nine rows and is closed:

| Ordinal | Path | Bytes | SHA-256 |
|---:|---|---:|---|
| 0 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_CORRECTION_INDEPENDENT_REVIEW.v1.json` | 21347 | `2bfefef8511e71dd72653264c9536d222c757ca1eb2c0f00c77dc8ef1998337f` |
| 1 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_CORRECTION_INDEPENDENT_REVIEW.md` | 17080 | `1f18cfe2094c7ec45dd4876bc69ac1e3ed42fc01013b7037b0b10b3f25314a18` |
| 2 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_BOUND_PRINCIPAL_ROSTER.v1.json` | 5056 | `8ad81918a3f076d28159a90acb1d2127b9d4a93be032065c5504d858c7a93120` |
| 3 | `rules/schemas/program_facts_g3_00_admission_lineage_r4_correction_review.v1.schema.json` | 10816 | `ccb059584b595afcd16fc7a5b2cf86b8d40231a810de1fb67c12a2b841daf63b` |
| 4 | `rules/schemas/program_facts_g3_00_admission_lineage_r4_principal_roster.v1.schema.json` | 7664 | `3f1d98eb5c2f127b0cfc32817871141d1c6cdee3804ea8cf59556be659a7eaf1` |
| 5 | `rules/schemas/program_facts_g3_00_admission_lineage_r4_red_receipt.v1.schema.json` | 5864 | `2b2848c8be9d18058cf815d832d98fd289d9baa711cd6b76ee998bc9963db536` |
| 6 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/admission_lineage_r4_correction_fixture_v1.py` | 21291 | `64537cd0c7ddc585e9e2e95eb65daa95e220076e9933abca00d8a4e4d26e2be8` |
| 7 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/test_admission_lineage_r4_correction_red_v1.py` | 9541 | `28cee9986375c49ace82c5244ef7bc8f3a4773de09b9e3ab1ee67f101f64e9ab` |
| 8 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_RED_RECEIPT.v1.json` | 5579 | `e564690efa19ddf7f02ec5cef1d34f5f6ce9936624cd97432f1724690ac25ef4` |

Every row has the sole treatment
`HISTORICAL_INVALID_PREAUTHORIZATION_NOT_INPUT`. The r4 contract/receipt and
all nine rows are forbidden in every r5 check
`evidence` array. They may not be copied, referenced as parents, used as schema
or fixture candidates, or credited toward any r5 check. This contract records
their immutable identities only to make exclusion mechanically decidable.

## 2. Inherited adoption and authority ceiling

R5 inherits the accepted r3 facts byte-semantically and does not widen them:

1. the R3.13 launcher contract, handoff, state review, and native review remain
   one `IMMUTABLE_LEGACY_REVIEWED_LAUNCHER_R3_13_BUNDLE`, inactive and without
   retroactive arm or completion;
2. the V8 pure control contract and its two independent `ACCEPT` reviews remain
   only `IMMUTABLE_V8_PURE_OFFLINE_ORACLE_FIXTURE_PARENT`, with runtime,
   native, provider, publication, cutover, and candidate-import authority false;
3. the accepted crosscheck contract/review/arm/completion bundle remains
   `IMMUTABLE_ACCEPTED_CROSSCHECK_R2_REVIEWED_PUBLICATION_BUNDLE`, and only that
   bundle has grade
   `PROTECTED_NAMESPACE_IDENTITY_PRESERVING_MATERIALIZATION`; and
4. `scripts/artifact_ledger.py` and `scripts/plamen_driver.py` remain logical
   names whose identities are bound only at
   `POST_CUT4_POSTIMPLEMENTATION_RELEASE_FREEZE`. No current size or hash is a
   construction input.

There is no candidate direct import and no r4 source is a runtime, native,
fixture, schema, or production parent. The common 29-member authority object
and inherited V8 17-member authority object remain entirely false. Part-0 is
exactly
`{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}`.

## 3. Canonical bytes and deterministic identities

`CJ(x)` is RFC-8785 canonical JSON encoded as UTF-8 and `CF(x)=CJ(x)||0x0a`.
All governed JSON rejects duplicate keys, BOM, CR, invalid UTF-8, non-finite
numbers, unsafe integers, noncanonical escapes, unknown members, and trailing
bytes other than exactly one LF. Paths are repository-relative, NFC,
forward-slash separated, exact-case, and contain no empty, dot, dot-dot,
colon, backslash, or control component.

```text
roster_body_sha256 = SHA-256(CJ(roster without only roster_body_sha256))
roster_id = "pfg3alr5pr-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_PROSPECTIVE_ROSTER_V1",
  roster:<roster without roster_id, binding_signature, roster_body_sha256>
}))[0:32]

for i in [1,2,3,4,5]:
  bindings[i].source.assignment_body_sha256 = SHA-256(CJ({
    domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_PRINCIPAL_ASSIGNMENT_V1",
    role:roles[i], principal_ordinal:i, principal_id:principal_ids[i]
  }))

binding_preimage_sha256 = SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_PRINCIPAL_BINDING_V1",
  roster:<roster without roster_id, binding_signature, roster_body_sha256>
}))

principal_ids_sha256 = SHA-256(CJ(principal_ids))
projection_body_sha256 = SHA-256(CJ(
  independence_projection without only projection_body_sha256))
fixture_specification_sha256 = SHA-256(CJ(fixture_specification))
inline_schema_cj_sha256[i] = SHA-256(CJ(inline_schema[i]))
candidate_set_sha256 = SHA-256(CJ({
  fixture_specification:fixture_specification,
  inline_schemas:[roster_schema,review_schema,red_receipt_schema]
}))

review_body_sha256 = SHA-256(CJ(review without only review_body_sha256))
review_id = "pfg3alr5-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_ORDERING_REVIEW_V1",
  review:<review without review_id, review_body_sha256>
}))[0:32]

red_receipt_body_sha256 = SHA-256(CJ(receipt without only receipt_body_sha256))
red_receipt_id = "pfg3alr5red-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_ORDERING_RED_RECEIPT_V1",
  receipt:<receipt without receipt_id, receipt_body_sha256>
}))[0:32]
```

The prospective-roster binder signs the 32 raw bytes named by
`binding_preimage_sha256` using Ed25519. Public key and signature are canonical
Base64. The five signed roles are exact prospective principals, not labels or
placeholders. The semantic validator recomputes every formula.

## 4. Prospective principal binding and total review semantics

The exact ordered role roster is:

```text
0 ORDERING_CORRECTION_AUTHOR
1 PROSPECTIVE_ROSTER_BINDER
2 INDEPENDENT_GOVERNED_REVIEWER
3 SCHEMA_RENDERER
4 RED_FIXTURE_AUTHOR
5 PRODUCTION_IMPLEMENTER
6 R313_STATE_NATIVE_REVIEWER
7 R313_WINDOWS_NATIVE_REVIEWER
```

Ordinal 0 is extracted from the exact r5 author receipt at
`Author principal:`. Ordinals 6 and 7 are extracted at exact label
`- Reviewer:` from the immutable R3.13 state/native reviews at SHA-256
`dce9edb11ec93db0832cb442836639e6f028bd49750a6014c6efb937db894655`
and `7d73204b1c524fc65fcbd9bc3d4831e2828e1e26d80bad65ccd011193effd37b`.
Ordinals 1-5 are prospective exact values committed by their deterministic
assignment digests and the roster signature. All eight values are unique, and
the validator directly compares all 28 unordered pairs. The review contains
only `reviewer_principal_ordinal:2`; no free reviewer principal or Boolean
independence assertion exists.

The renderer is ordinal 3 and the fixture author is ordinal 4. After governed
PASS, they must remain distinct by value and must consume the exact candidate
set committed by the passing review. Renderer output is exactly `CF` of the
three inline schema roots in registry order. Fixture source and test must embed
the exact reviewed fixture specification and digest. Any changed candidate,
role value, assignment, actor value, schema byte, mutation, path, oracle, or
digest rejects. Ordinal 5 is reserved prospectively and receives no production
authority.

R5 retains the r4 totality repair. Findings are an object keyed by finding ID.
After schema validation the validator recomputes, in exact check order:

```text
failed_check_ids = check IDs whose result is FAIL
open_ids = UTF8_SORT(finding IDs whose status is OPEN)
open_blocker_ids = UTF8_SORT(open IDs whose severity is BLOCKING)
require open_findings == open_ids
require failure-binding check IDs == failed_check_ids
require every binding finding ID is an open blocker
require UTF8_SORT(union(binding finding IDs)) == open_blocker_ids
require every open blocker's failed_checks equals its binding back-join

PASS requires:
  failed_check_ids == []
  open_findings == open_ids == open_blocker_ids == []
  failure_bindings == []

REJECTED requires:
  failed_check_ids is nonempty
  open_findings == open_ids == open_blocker_ids and is nonempty
  the exact binding union and back-joins above
```

Thus every one of the exact 18 checks must be `PASS` for PASS. REJECTED may
carry failure evidence only through the exact open-blocker equality join.

## 5. Entirely new create-only registries

The r5 author creates only this contract and:

```text
review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_ORDERING_CORRECTION_AUTHOR_RECEIPT.md
```

The three schema-render paths are:

| Ordinal | Exact future path | Root version |
|---:|---|---|
| 0 | `rules/schemas/program_facts_g3_00_admission_lineage_r5_prospective_principal_roster.v1.schema.json` | `plamen.program_facts_g3_00_admission_lineage_r5_prospective_principal_roster.v1` |
| 1 | `rules/schemas/program_facts_g3_00_admission_lineage_r5_ordering_review.v1.schema.json` | `plamen.program_facts_g3_00_admission_lineage_r5_ordering_review.v1` |
| 2 | `rules/schemas/program_facts_g3_00_admission_lineage_r5_ordering_red_receipt.v1.schema.json` | `plamen.program_facts_g3_00_admission_lineage_r5_ordering_red_receipt.v1` |

The five semantic/output paths are:

| Ordinal | Exact future path | Earliest stage |
|---:|---|---|
| 0 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_PROSPECTIVE_BOUND_PRINCIPAL_ROSTER.v1.json` | after contract and receipt |
| 1 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_ORDERING_INDEPENDENT_GOVERNED_REVIEW.v1.json` | after valid prospective roster |
| 2 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/admission_lineage_r5_ordering_fixture_v1.py` | only after governed PASS |
| 3 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/test_admission_lineage_r5_ordering_red_v1.py` | after three renders and fixture source |
| 4 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_ORDERING_RED_RECEIPT.v1.json` | after exact RED execution |

The deliberately absent semantic successor is not an output registry member:

```text
review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/validate_admission_lineage_r5_ordering_semantics_v1.py
```

It must remain absent throughout the r5 RED stage. The governed review may PASS
without it because its denominator check is structural only. No r4 path may
substitute for any r5 path.

## 6. Exact focused candidate specification

The reviewed fixture candidate specification is exactly:

```json
{
  "candidate_domain":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_FOCUSED_RED_CANDIDATE_V1",
  "review_validation_mode":"STRUCTURAL_CONTRACT_SCHEMA_PATH_MUTATION_ORACLE_ONLY",
  "semantic_successor_path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/validate_admission_lineage_r5_ordering_semantics_v1.py",
  "semantic_successor_state_at_review":"ABSENT_BY_DESIGN",
  "prospective_roster_path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_PROSPECTIVE_BOUND_PRINCIPAL_ROSTER.v1.json",
  "governed_review_path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_ORDERING_INDEPENDENT_GOVERNED_REVIEW.v1.json",
  "rendered_schema_paths":["rules/schemas/program_facts_g3_00_admission_lineage_r5_prospective_principal_roster.v1.schema.json","rules/schemas/program_facts_g3_00_admission_lineage_r5_ordering_review.v1.schema.json","rules/schemas/program_facts_g3_00_admission_lineage_r5_ordering_red_receipt.v1.schema.json"],
  "fixture_source_path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/admission_lineage_r5_ordering_fixture_v1.py",
  "fixture_test_path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/test_admission_lineage_r5_ordering_red_v1.py",
  "red_receipt_path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_ORDERING_RED_RECEIPT.v1.json",
  "cases":[
    {"case_id":"ALC-R5-01-HIDDEN-OPEN-BLOCKER","candidate_kind":"REVIEW","mutation":"PASS plus BLOCKING/OPEN finding while open_findings is empty","structural_expectation":"SCHEMA_REJECT","expected_failure_code":"SEMANTIC_SUCCESSOR_ABSENT","red_oracle":"UNITTEST_MUST_FAIL_BECAUSE_SEMANTIC_SUCCESSOR_IS_ABSENT"},
    {"case_id":"ALC-R5-02-OPEN-ROSTER-MISMATCH","candidate_kind":"REVIEW","mutation":"REJECTED finding ledger open IDs differ from open_findings or failure bindings","structural_expectation":"SCHEMA_ACCEPT_THEN_SEMANTIC_STAGE_REQUIRED","expected_failure_code":"SEMANTIC_SUCCESSOR_ABSENT","red_oracle":"UNITTEST_MUST_FAIL_BECAUSE_SEMANTIC_SUCCESSOR_IS_ABSENT"},
    {"case_id":"ALC-R5-03-PRINCIPAL-ALIAS","candidate_kind":"ROSTER","mutation":"two required roles carry the same principal ID value","structural_expectation":"SCHEMA_REJECT","expected_failure_code":"SEMANTIC_SUCCESSOR_ABSENT","red_oracle":"UNITTEST_MUST_FAIL_BECAUSE_SEMANTIC_SUCCESSOR_IS_ABSENT"},
    {"case_id":"ALC-R5-04-PRINCIPAL-RELABEL","candidate_kind":"ROSTER","mutation":"principal role, ordinal, immutable source locator, or signed assignment is relabeled","structural_expectation":"SCHEMA_REJECT","expected_failure_code":"SEMANTIC_SUCCESSOR_ABSENT","red_oracle":"UNITTEST_MUST_FAIL_BECAUSE_SEMANTIC_SUCCESSOR_IS_ABSENT"}
  ],
  "expected_red_process":{"exit_class":"NONZERO","expected_failure_count":4,"expected_failure_code":"SEMANTIC_SUCCESSOR_ABSENT","semantic_acceptance_confirmed":false,"red_execution_claim_allowed_before_pass":false}
}
```

The governed reviewer validates all four candidate constructions against the
inline schemas and validates exact paths, mutation strings, structural
expectations, and oracle strings. That validation is not RED execution. The
review must record `semantic_successor_executed:false`, `red_executed:false`,
and `semantic_acceptance_confirmed:false`.

Only after PASS may the bound fixture author materialize the unchanged source
and test. The test must exit nonzero through exactly four
`SEMANTIC_SUCCESSOR_ABSENT` failures. That nonzero result is the expected RED
success condition. The later receipt says
`EXPECTED_RED_FAILURES_OBSERVED_NO_SEMANTIC_ACCEPTANCE`; it must never say
`RED_CONFIRMED`, `semantic acceptance`, or zero failures.

## 7. Closed inline schemas

### 7.1 Prospective principal roster

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_r5_prospective_principal_roster.v1.schema.json",
  "$vocabulary":{"https://json-schema.org/draft/2020-12/vocab/core":true,"https://json-schema.org/draft/2020-12/vocab/applicator":true,"https://json-schema.org/draft/2020-12/vocab/validation":true},
  "type":"object","additionalProperties":false,
  "required":["schema_version","roster_id","subject","author_receipt","roles","principal_ids","bindings","binding_signature","part_0_genericity","authority_ceiling","roster_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_r5_prospective_principal_roster.v1"},
    "roster_id":{"type":"string","pattern":"^pfg3alr5pr-[0-9a-f]{32}$"},
    "subject":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"architecture/program-facts-g3-00-admission-lineage-r5-ordering-correction-amendment.md"}}}]},
    "author_receipt":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_ORDERING_CORRECTION_AUTHOR_RECEIPT.md"}}}]},
    "roles":{"const":["ORDERING_CORRECTION_AUTHOR","PROSPECTIVE_ROSTER_BINDER","INDEPENDENT_GOVERNED_REVIEWER","SCHEMA_RENDERER","RED_FIXTURE_AUTHOR","PRODUCTION_IMPLEMENTER","R313_STATE_NATIVE_REVIEWER","R313_WINDOWS_NATIVE_REVIEWER"]},
    "principal_ids":{"type":"array","minItems":8,"maxItems":8,"uniqueItems":true,"prefixItems":[{"const":"Codex:/root/g3_r3_correction_author_short"},{"$ref":"#/$defs/principal_id"},{"$ref":"#/$defs/principal_id"},{"$ref":"#/$defs/principal_id"},{"$ref":"#/$defs/principal_id"},{"$ref":"#/$defs/principal_id"},{"const":"Codex:/root/r3_13_state_short"},{"const":"Codex:/root/r3_13_native_short"}],"items":false},
    "bindings":{"type":"array","minItems":8,"maxItems":8,"prefixItems":[{"$ref":"#/$defs/binding_0"},{"$ref":"#/$defs/binding_1"},{"$ref":"#/$defs/binding_2"},{"$ref":"#/$defs/binding_3"},{"$ref":"#/$defs/binding_4"},{"$ref":"#/$defs/binding_5"},{"$ref":"#/$defs/binding_6"},{"$ref":"#/$defs/binding_7"}],"items":false},
    "binding_signature":{"type":"object","additionalProperties":false,"required":["algorithm","signer_principal_ordinal","public_key_base64","signed_preimage_sha256","signature_base64"],"properties":{"algorithm":{"const":"ED25519"},"signer_principal_ordinal":{"const":1},"public_key_base64":{"type":"string","pattern":"^[A-Za-z0-9+/]{43}=$"},"signed_preimage_sha256":{"$ref":"#/$defs/hex64"},"signature_base64":{"type":"string","pattern":"^[A-Za-z0-9+/]{86}==$"}}},
    "part_0_genericity":{"$ref":"#/$defs/part0"},"authority_ceiling":{"$ref":"#/$defs/authority"},"roster_body_sha256":{"$ref":"#/$defs/hex64"}
  },
  "$defs":{
    "hex64":{"type":"string","pattern":"^[0-9a-f]{64}$"},
    "safe_path":{"type":"string","minLength":1,"maxLength":4096,"pattern":"^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[\\\\:\\x00-\\x1f\\x7f])[^/]+(?:/[^/]+)*$"},
    "principal_id":{"type":"string","minLength":12,"maxLength":256,"pattern":"^[A-Za-z][A-Za-z0-9._-]*:/[A-Za-z0-9._/-]+$"},
    "file_identity":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"$ref":"#/$defs/safe_path"},"size_bytes":{"type":"integer","minimum":1,"maximum":9007199254740991},"sha256":{"$ref":"#/$defs/hex64"}}},
    "extracted":{"type":"object","additionalProperties":false,"required":["kind","artifact","locator"],"properties":{"kind":{"const":"IMMUTABLE_ARTIFACT_EXTRACTION"},"artifact":{"$ref":"#/$defs/file_identity"},"locator":{"type":"object","additionalProperties":false,"required":["syntax","label"],"properties":{"syntax":{"const":"MARKDOWN_EXACT_LABEL"},"label":{"type":"string","minLength":1,"maxLength":128}}}}},
    "signed":{"type":"object","additionalProperties":false,"required":["kind","assignment_domain","assignment_body_sha256"],"properties":{"kind":{"const":"SIGNED_ROSTER_ASSIGNMENT"},"assignment_domain":{"const":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_PRINCIPAL_ASSIGNMENT_V1"},"assignment_body_sha256":{"$ref":"#/$defs/hex64"}}},
    "binding":{"type":"object","additionalProperties":false,"required":["role","principal_ordinal","source"],"properties":{"role":{"type":"string"},"principal_ordinal":{"type":"integer","minimum":0,"maximum":7},"source":{"oneOf":[{"$ref":"#/$defs/extracted"},{"$ref":"#/$defs/signed"}]}}},
    "binding_0":{"allOf":[{"$ref":"#/$defs/binding"},{"properties":{"role":{"const":"ORDERING_CORRECTION_AUTHOR"},"principal_ordinal":{"const":0},"source":{"allOf":[{"$ref":"#/$defs/extracted"},{"properties":{"artifact":{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_ORDERING_CORRECTION_AUTHOR_RECEIPT.md"}}},"locator":{"properties":{"label":{"const":"Author principal:"}}}}}]}}}]},
    "binding_1":{"allOf":[{"$ref":"#/$defs/binding"},{"properties":{"role":{"const":"PROSPECTIVE_ROSTER_BINDER"},"principal_ordinal":{"const":1},"source":{"$ref":"#/$defs/signed"}}}]},
    "binding_2":{"allOf":[{"$ref":"#/$defs/binding"},{"properties":{"role":{"const":"INDEPENDENT_GOVERNED_REVIEWER"},"principal_ordinal":{"const":2},"source":{"$ref":"#/$defs/signed"}}}]},
    "binding_3":{"allOf":[{"$ref":"#/$defs/binding"},{"properties":{"role":{"const":"SCHEMA_RENDERER"},"principal_ordinal":{"const":3},"source":{"$ref":"#/$defs/signed"}}}]},
    "binding_4":{"allOf":[{"$ref":"#/$defs/binding"},{"properties":{"role":{"const":"RED_FIXTURE_AUTHOR"},"principal_ordinal":{"const":4},"source":{"$ref":"#/$defs/signed"}}}]},
    "binding_5":{"allOf":[{"$ref":"#/$defs/binding"},{"properties":{"role":{"const":"PRODUCTION_IMPLEMENTER"},"principal_ordinal":{"const":5},"source":{"$ref":"#/$defs/signed"}}}]},
    "binding_6":{"allOf":[{"$ref":"#/$defs/binding"},{"properties":{"role":{"const":"R313_STATE_NATIVE_REVIEWER"},"principal_ordinal":{"const":6},"source":{"allOf":[{"$ref":"#/$defs/extracted"},{"properties":{"artifact":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_13_STATE_OPERATIONAL_REVIEW_7d1616dedea141ea.md","size_bytes":11434,"sha256":"dce9edb11ec93db0832cb442836639e6f028bd49750a6014c6efb937db894655"}},"locator":{"properties":{"label":{"const":"- Reviewer:"}}}}}]}}}]},
    "binding_7":{"allOf":[{"$ref":"#/$defs/binding"},{"properties":{"role":{"const":"R313_WINDOWS_NATIVE_REVIEWER"},"principal_ordinal":{"const":7},"source":{"allOf":[{"$ref":"#/$defs/extracted"},{"properties":{"artifact":{"const":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_13_NATIVE_CONTRACT_REVIEW_7d1616dedea141ea.md","size_bytes":10204,"sha256":"7d73204b1c524fc65fcbd9bc3d4831e2828e1e26d80bad65ccd011193effd37b"}},"locator":{"properties":{"label":{"const":"- Reviewer:"}}}}}]}}}]},
    "part0":{"type":"object","const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},
    "authority":{"type":"object","const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}}
  }
}
```

### 7.2 Independent governed ordering review

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_r5_ordering_review.v1.schema.json",
  "$vocabulary":{"https://json-schema.org/draft/2020-12/vocab/core":true,"https://json-schema.org/draft/2020-12/vocab/applicator":true,"https://json-schema.org/draft/2020-12/vocab/validation":true},
  "type":"object","additionalProperties":false,
  "required":["schema_version","review_id","subject","principal_roster","reviewer_principal_ordinal","independence_projection","historical_invalid_treatment","candidate_projection","fixture_specification","preauthorization_observations","checks","findings","open_findings","failure_bindings","disposition","accepted_scope","rejected_scope","part_0_genericity","authority_ceiling","review_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_r5_ordering_review.v1"},
    "review_id":{"type":"string","pattern":"^pfg3alr5-[0-9a-f]{32}$"},
    "subject":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"architecture/program-facts-g3-00-admission-lineage-r5-ordering-correction-amendment.md"}}}]},
    "principal_roster":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_PROSPECTIVE_BOUND_PRINCIPAL_ROSTER.v1.json"}}}]},
    "reviewer_principal_ordinal":{"const":2},
    "independence_projection":{"$ref":"#/$defs/independence"},
    "historical_invalid_treatment":{"const":{"registry_count":9,"r4_governed_disposition":"REJECTED","treatment":"HISTORICAL_INVALID_PREAUTHORIZATION_NOT_INPUT","r4_evidence_member_count":0}},
    "candidate_projection":{"type":"object","additionalProperties":false,"required":["fixture_specification_sha256","inline_schema_cj_sha256","candidate_set_sha256"],"properties":{"fixture_specification_sha256":{"$ref":"#/$defs/hex64"},"inline_schema_cj_sha256":{"type":"array","minItems":3,"maxItems":3,"items":{"$ref":"#/$defs/hex64"}},"candidate_set_sha256":{"$ref":"#/$defs/hex64"}}},
    "fixture_specification":{"$ref":"#/$defs/fixture_spec"},
    "preauthorization_observations":{"const":{"semantic_successor_executed":false,"red_executed":false,"semantic_acceptance_confirmed":false,"validation_mode":"STRUCTURAL_CONTRACT_SCHEMA_PATH_MUTATION_ORACLE_ONLY"}},
    "checks":{"type":"array","minItems":18,"maxItems":18,"prefixItems":[{"$ref":"#/$defs/check_01"},{"$ref":"#/$defs/check_02"},{"$ref":"#/$defs/check_03"},{"$ref":"#/$defs/check_04"},{"$ref":"#/$defs/check_05"},{"$ref":"#/$defs/check_06"},{"$ref":"#/$defs/check_07"},{"$ref":"#/$defs/check_08"},{"$ref":"#/$defs/check_09"},{"$ref":"#/$defs/check_10"},{"$ref":"#/$defs/check_11"},{"$ref":"#/$defs/check_12"},{"$ref":"#/$defs/check_13"},{"$ref":"#/$defs/check_14"},{"$ref":"#/$defs/check_15"},{"$ref":"#/$defs/check_16"},{"$ref":"#/$defs/check_17"},{"$ref":"#/$defs/check_18"}],"items":false},
    "findings":{"type":"object","propertyNames":{"$ref":"#/$defs/identifier"},"additionalProperties":{"$ref":"#/$defs/finding"},"maxProperties":10000},
    "open_findings":{"type":"array","maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/identifier"}},
    "failure_bindings":{"type":"array","maxItems":18,"uniqueItems":true,"items":{"$ref":"#/$defs/failure_binding"}},
    "disposition":{"enum":["PASS_R5_ORDERING_FOR_PROSPECTIVE_SCHEMA_RENDER_AND_EXPECTED_RED_ONLY","REJECTED"]},
    "accepted_scope":{"const":["RENDER_EXACT_3_R5_SCHEMAS_AND_AUTHOR_EXACT_R5_EXPECTED_RED_FIXTURES_ONLY"]},
    "rejected_scope":{"const":["ADMISSION","CANDIDATE_IMPORT","COMMIT","CONSTRUCTION","CUTOVER","GREEN_IMPLEMENTATION","INSTALL","NATIVE_EXECUTION","PACKAGE","PRODUCTION_EDIT","PRODUCTION_PUBLICATION","PROVIDER","PUSH","RED_SEMANTIC_ACCEPTANCE","RELEASE","RUNTIME"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},"authority_ceiling":{"$ref":"#/$defs/authority"},"review_body_sha256":{"$ref":"#/$defs/hex64"}
  },
  "allOf":[
    {"if":{"properties":{"disposition":{"const":"PASS_R5_ORDERING_FOR_PROSPECTIVE_SCHEMA_RENDER_AND_EXPECTED_RED_ONLY"}},"required":["disposition"]},"then":{"properties":{"checks":{"not":{"contains":{"properties":{"result":{"const":"FAIL"}},"required":["result"]}}},"findings":{"additionalProperties":{"not":{"properties":{"status":{"const":"OPEN"}},"required":["status"]}}},"open_findings":{"maxItems":0},"failure_bindings":{"maxItems":0}}}},
    {"if":{"properties":{"disposition":{"const":"REJECTED"}},"required":["disposition"]},"then":{"properties":{"checks":{"contains":{"properties":{"result":{"const":"FAIL"}},"required":["result"]},"minContains":1},"findings":{"minProperties":1},"open_findings":{"minItems":1},"failure_bindings":{"minItems":1}}}}
  ],
  "$defs":{
    "hex64":{"type":"string","pattern":"^[0-9a-f]{64}$"},"identifier":{"type":"string","minLength":1,"maxLength":256,"pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]*$"},
    "safe_path":{"type":"string","minLength":1,"maxLength":4096,"pattern":"^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[\\\\:\\x00-\\x1f\\x7f])[^/]+(?:/[^/]+)*$"},
    "forbidden_r4_path":{"enum":["architecture/program-facts-g3-00-admission-lineage-r4-correction-amendment.md","review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_CORRECTION_AUTHOR_RECEIPT.md","review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_CORRECTION_INDEPENDENT_REVIEW.md","review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_BOUND_PRINCIPAL_ROSTER.v1.json","review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_CORRECTION_INDEPENDENT_REVIEW.v1.json","rules/schemas/program_facts_g3_00_admission_lineage_r4_correction_review.v1.schema.json","rules/schemas/program_facts_g3_00_admission_lineage_r4_principal_roster.v1.schema.json","rules/schemas/program_facts_g3_00_admission_lineage_r4_red_receipt.v1.schema.json","review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/admission_lineage_r4_correction_fixture_v1.py","review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/test_admission_lineage_r4_correction_red_v1.py","review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R4_RED_RECEIPT.v1.json"]},
    "file_identity":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"$ref":"#/$defs/safe_path"},"size_bytes":{"type":"integer","minimum":1,"maximum":9007199254740991},"sha256":{"$ref":"#/$defs/hex64"}}},
    "evidence_identity":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"not":{"$ref":"#/$defs/forbidden_r4_path"}}}}]},
    "principal_id":{"type":"string","minLength":12,"maxLength":256,"pattern":"^[A-Za-z][A-Za-z0-9._-]*:/[A-Za-z0-9._/-]+$"},
    "independence":{"type":"object","additionalProperties":false,"required":["roles","principal_ids","principal_ids_sha256","required_separation_pair_count","equal_principal_pairs","projection_body_sha256"],"properties":{"roles":{"const":["ORDERING_CORRECTION_AUTHOR","PROSPECTIVE_ROSTER_BINDER","INDEPENDENT_GOVERNED_REVIEWER","SCHEMA_RENDERER","RED_FIXTURE_AUTHOR","PRODUCTION_IMPLEMENTER","R313_STATE_NATIVE_REVIEWER","R313_WINDOWS_NATIVE_REVIEWER"]},"principal_ids":{"type":"array","minItems":8,"maxItems":8,"uniqueItems":true,"items":{"$ref":"#/$defs/principal_id"}},"principal_ids_sha256":{"$ref":"#/$defs/hex64"},"required_separation_pair_count":{"const":28},"equal_principal_pairs":{"type":"array","maxItems":0},"projection_body_sha256":{"$ref":"#/$defs/hex64"}}},
    "fixture_spec":{"type":"object","const":{"candidate_domain":"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_FOCUSED_RED_CANDIDATE_V1","review_validation_mode":"STRUCTURAL_CONTRACT_SCHEMA_PATH_MUTATION_ORACLE_ONLY","semantic_successor_path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/validate_admission_lineage_r5_ordering_semantics_v1.py","semantic_successor_state_at_review":"ABSENT_BY_DESIGN","prospective_roster_path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_PROSPECTIVE_BOUND_PRINCIPAL_ROSTER.v1.json","governed_review_path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_ORDERING_INDEPENDENT_GOVERNED_REVIEW.v1.json","rendered_schema_paths":["rules/schemas/program_facts_g3_00_admission_lineage_r5_prospective_principal_roster.v1.schema.json","rules/schemas/program_facts_g3_00_admission_lineage_r5_ordering_review.v1.schema.json","rules/schemas/program_facts_g3_00_admission_lineage_r5_ordering_red_receipt.v1.schema.json"],"fixture_source_path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/admission_lineage_r5_ordering_fixture_v1.py","fixture_test_path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/test_admission_lineage_r5_ordering_red_v1.py","red_receipt_path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_ORDERING_RED_RECEIPT.v1.json","cases":[{"case_id":"ALC-R5-01-HIDDEN-OPEN-BLOCKER","candidate_kind":"REVIEW","mutation":"PASS plus BLOCKING/OPEN finding while open_findings is empty","structural_expectation":"SCHEMA_REJECT","expected_failure_code":"SEMANTIC_SUCCESSOR_ABSENT","red_oracle":"UNITTEST_MUST_FAIL_BECAUSE_SEMANTIC_SUCCESSOR_IS_ABSENT"},{"case_id":"ALC-R5-02-OPEN-ROSTER-MISMATCH","candidate_kind":"REVIEW","mutation":"REJECTED finding ledger open IDs differ from open_findings or failure bindings","structural_expectation":"SCHEMA_ACCEPT_THEN_SEMANTIC_STAGE_REQUIRED","expected_failure_code":"SEMANTIC_SUCCESSOR_ABSENT","red_oracle":"UNITTEST_MUST_FAIL_BECAUSE_SEMANTIC_SUCCESSOR_IS_ABSENT"},{"case_id":"ALC-R5-03-PRINCIPAL-ALIAS","candidate_kind":"ROSTER","mutation":"two required roles carry the same principal ID value","structural_expectation":"SCHEMA_REJECT","expected_failure_code":"SEMANTIC_SUCCESSOR_ABSENT","red_oracle":"UNITTEST_MUST_FAIL_BECAUSE_SEMANTIC_SUCCESSOR_IS_ABSENT"},{"case_id":"ALC-R5-04-PRINCIPAL-RELABEL","candidate_kind":"ROSTER","mutation":"principal role, ordinal, immutable source locator, or signed assignment is relabeled","structural_expectation":"SCHEMA_REJECT","expected_failure_code":"SEMANTIC_SUCCESSOR_ABSENT","red_oracle":"UNITTEST_MUST_FAIL_BECAUSE_SEMANTIC_SUCCESSOR_IS_ABSENT"}],"expected_red_process":{"exit_class":"NONZERO","expected_failure_count":4,"expected_failure_code":"SEMANTIC_SUCCESSOR_ABSENT","semantic_acceptance_confirmed":false,"red_execution_claim_allowed_before_pass":false}}},
    "check":{"type":"object","additionalProperties":false,"required":["check_id","result","evidence"],"properties":{"check_id":{"$ref":"#/$defs/identifier"},"result":{"enum":["PASS","FAIL"]},"evidence":{"type":"array","minItems":1,"maxItems":100,"uniqueItems":true,"items":{"$ref":"#/$defs/evidence_identity"}}}},
    "check_01":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR5-01-R5-SUBJECT-AUTHOR-EXACT"}}}]},"check_02":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR5-02-R4-GOVERNED-REJECTION-EXACT"}}}]},"check_03":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR5-03-HISTORICAL-INVALID-EXCLUDED"}}}]},"check_04":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR5-04-R3-ADOPTION-INHERITED-EXACT"}}}]},"check_05":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR5-05-LATE-BINDING-NO-CANDIDATE-IMPORT"}}}]},"check_06":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR5-06-PASS-ALL-CHECKS-NO-OPEN"}}}]},"check_07":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR5-07-REJECTED-BLOCKER-EQUALITY-JOIN"}}}]},"check_08":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR5-08-PROSPECTIVE-ROSTER-BOUND"}}}]},"check_09":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR5-09-ALL-28-SEPARATIONS-DERIVED"}}}]},"check_10":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR5-10-INDEPENDENCE-PROJECTION-RECOMPUTED"}}}]},"check_11":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR5-11-ALL-NEW-PATHS-ABSENT"}}}]},"check_12":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR5-12-INLINE-SCHEMAS-CLOSED-VALID"}}}]},"check_13":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR5-13-FOCUSED-DENOMINATOR-STRUCTURAL"}}}]},"check_14":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR5-14-NO-PRERENDER-EXECUTION-CLAIM"}}}]},"check_15":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR5-15-ORDERING-DAG-EXACT"}}}]},"check_16":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR5-16-POSTPASS-ACTORS-CANDIDATES-BOUND"}}}]},"check_17":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR5-17-AUTHORITY-ALL-FALSE"}}}]},"check_18":{"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR5-18-PART0-GENERICITY"}}}]},
    "finding":{"type":"object","additionalProperties":false,"required":["severity","status","failed_checks","description","evidence"],"properties":{"severity":{"enum":["BLOCKING","NONBLOCKING"]},"status":{"enum":["OPEN","CLOSED"]},"failed_checks":{"type":"array","maxItems":18,"uniqueItems":true,"items":{"$ref":"#/$defs/identifier"}},"description":{"type":"string","minLength":1,"maxLength":8192},"evidence":{"type":"array","minItems":1,"maxItems":100,"uniqueItems":true,"items":{"$ref":"#/$defs/evidence_identity"}}}},
    "failure_binding":{"type":"object","additionalProperties":false,"required":["check_id","finding_ids"],"properties":{"check_id":{"$ref":"#/$defs/identifier"},"finding_ids":{"type":"array","minItems":1,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/identifier"}}}},
    "part0":{"type":"object","const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},
    "authority":{"type":"object","const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}}
  }
}
```

### 7.3 Honest expected-RED receipt

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_r5_ordering_red_receipt.v1.schema.json",
  "$vocabulary":{"https://json-schema.org/draft/2020-12/vocab/core":true,"https://json-schema.org/draft/2020-12/vocab/applicator":true,"https://json-schema.org/draft/2020-12/vocab/validation":true},
  "type":"object","additionalProperties":false,
  "required":["schema_version","receipt_id","contract","principal_roster","governing_review","rendered_schemas","fixture_source","fixture_test","candidate_projection","actor_projection","case_observations","process_observation","scope","part_0_genericity","authority_ceiling","receipt_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_r5_ordering_red_receipt.v1"},"receipt_id":{"type":"string","pattern":"^pfg3alr5red-[0-9a-f]{32}$"},
    "contract":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"architecture/program-facts-g3-00-admission-lineage-r5-ordering-correction-amendment.md"}}}]},
    "principal_roster":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_PROSPECTIVE_BOUND_PRINCIPAL_ROSTER.v1.json"}}}]},
    "governing_review":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R5_ORDERING_INDEPENDENT_GOVERNED_REVIEW.v1.json"}}}]},
    "rendered_schemas":{"type":"array","minItems":3,"maxItems":3,"prefixItems":[{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"rules/schemas/program_facts_g3_00_admission_lineage_r5_prospective_principal_roster.v1.schema.json"}}}]},{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"rules/schemas/program_facts_g3_00_admission_lineage_r5_ordering_review.v1.schema.json"}}}]},{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"rules/schemas/program_facts_g3_00_admission_lineage_r5_ordering_red_receipt.v1.schema.json"}}}]}],"items":false},
    "fixture_source":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/admission_lineage_r5_ordering_fixture_v1.py"}}}]},
    "fixture_test":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/test_admission_lineage_r5_ordering_red_v1.py"}}}]},
    "candidate_projection":{"type":"object","additionalProperties":false,"required":["fixture_specification_sha256","inline_schema_cj_sha256","candidate_set_sha256"],"properties":{"fixture_specification_sha256":{"$ref":"#/$defs/hex64"},"inline_schema_cj_sha256":{"type":"array","minItems":3,"maxItems":3,"items":{"$ref":"#/$defs/hex64"}},"candidate_set_sha256":{"$ref":"#/$defs/hex64"}}},
    "actor_projection":{"type":"object","additionalProperties":false,"required":["schema_renderer","fixture_author"],"properties":{"schema_renderer":{"$ref":"#/$defs/actor_3"},"fixture_author":{"$ref":"#/$defs/actor_4"}}},
    "case_observations":{"type":"array","minItems":4,"maxItems":4,"prefixItems":[{"$ref":"#/$defs/case_1"},{"$ref":"#/$defs/case_2"},{"$ref":"#/$defs/case_3"},{"$ref":"#/$defs/case_4"}],"items":false},
    "process_observation":{"const":{"exit_class":"NONZERO","observed_failure_count":4,"observed_failure_code":"SEMANTIC_SUCCESSOR_ABSENT","outcome":"EXPECTED_RED_FAILURES_OBSERVED_NO_SEMANTIC_ACCEPTANCE","semantic_acceptance_confirmed":false,"unexpected_pass_count":0,"setup_error_count":0}},
    "scope":{"const":"EXPECTED_RED_EXECUTION_ONLY_NO_SEMANTIC_ACCEPTANCE_NO_GREEN"},"part_0_genericity":{"$ref":"#/$defs/part0"},"authority_ceiling":{"$ref":"#/$defs/authority"},"receipt_body_sha256":{"$ref":"#/$defs/hex64"}
  },
  "$defs":{
    "hex64":{"type":"string","pattern":"^[0-9a-f]{64}$"},"safe_path":{"type":"string","minLength":1,"maxLength":4096,"pattern":"^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[\\\\:\\x00-\\x1f\\x7f])[^/]+(?:/[^/]+)*$"},"principal_id":{"type":"string","minLength":12,"maxLength":256,"pattern":"^[A-Za-z][A-Za-z0-9._-]*:/[A-Za-z0-9._/-]+$"},
    "file_identity":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"$ref":"#/$defs/safe_path"},"size_bytes":{"type":"integer","minimum":1,"maximum":9007199254740991},"sha256":{"$ref":"#/$defs/hex64"}}},
    "actor":{"type":"object","additionalProperties":false,"required":["role","principal_ordinal","principal_id"],"properties":{"role":{"type":"string"},"principal_ordinal":{"type":"integer"},"principal_id":{"$ref":"#/$defs/principal_id"}}},
    "actor_3":{"allOf":[{"$ref":"#/$defs/actor"},{"properties":{"role":{"const":"SCHEMA_RENDERER"},"principal_ordinal":{"const":3}}}]},"actor_4":{"allOf":[{"$ref":"#/$defs/actor"},{"properties":{"role":{"const":"RED_FIXTURE_AUTHOR"},"principal_ordinal":{"const":4}}}]},
    "case":{"type":"object","additionalProperties":false,"required":["case_id","red_oracle","outcome","failure_code","semantic_acceptance_confirmed","evidence"],"properties":{"case_id":{"type":"string"},"red_oracle":{"const":"UNITTEST_MUST_FAIL_BECAUSE_SEMANTIC_SUCCESSOR_IS_ABSENT"},"outcome":{"const":"EXPECTED_FAILURE_OBSERVED"},"failure_code":{"const":"SEMANTIC_SUCCESSOR_ABSENT"},"semantic_acceptance_confirmed":{"const":false},"evidence":{"type":"array","minItems":1,"maxItems":10,"uniqueItems":true,"items":{"$ref":"#/$defs/file_identity"}}}},
    "case_1":{"allOf":[{"$ref":"#/$defs/case"},{"properties":{"case_id":{"const":"ALC-R5-01-HIDDEN-OPEN-BLOCKER"}}}]},"case_2":{"allOf":[{"$ref":"#/$defs/case"},{"properties":{"case_id":{"const":"ALC-R5-02-OPEN-ROSTER-MISMATCH"}}}]},"case_3":{"allOf":[{"$ref":"#/$defs/case"},{"properties":{"case_id":{"const":"ALC-R5-03-PRINCIPAL-ALIAS"}}}]},"case_4":{"allOf":[{"$ref":"#/$defs/case"},{"properties":{"case_id":{"const":"ALC-R5-04-PRINCIPAL-RELABEL"}}}]},
    "part0":{"type":"object","const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},
    "authority":{"type":"object","const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}}
  }
}
```

## 8. Exact governed-review checks and ordering DAG

The governed review check order is exactly:

```text
ALR5-01-R5-SUBJECT-AUTHOR-EXACT
ALR5-02-R4-GOVERNED-REJECTION-EXACT
ALR5-03-HISTORICAL-INVALID-EXCLUDED
ALR5-04-R3-ADOPTION-INHERITED-EXACT
ALR5-05-LATE-BINDING-NO-CANDIDATE-IMPORT
ALR5-06-PASS-ALL-CHECKS-NO-OPEN
ALR5-07-REJECTED-BLOCKER-EQUALITY-JOIN
ALR5-08-PROSPECTIVE-ROSTER-BOUND
ALR5-09-ALL-28-SEPARATIONS-DERIVED
ALR5-10-INDEPENDENCE-PROJECTION-RECOMPUTED
ALR5-11-ALL-NEW-PATHS-ABSENT
ALR5-12-INLINE-SCHEMAS-CLOSED-VALID
ALR5-13-FOCUSED-DENOMINATOR-STRUCTURAL
ALR5-14-NO-PRERENDER-EXECUTION-CLAIM
ALR5-15-ORDERING-DAG-EXACT
ALR5-16-POSTPASS-ACTORS-CANDIDATES-BOUND
ALR5-17-AUTHORITY-ALL-FALSE
ALR5-18-PART0-GENERICITY
```

Before deciding check 13, the reviewer constructs the four exact candidates in
memory, validates their expected structural outcomes against the inline schema
roots, compares every fixture-specification field and path, and recomputes all
candidate digests. It does not import a fixture, start unittest, load a semantic
successor, render a schema, or write a path. Check 14 fails if any execution or
semantic-acceptance claim is true.

The exact r5 DAG has 11 nodes and 18 edges:

```text
R5N00 R5_ORDERING_CORRECTION_CONTRACT
R5N01 R5_ORDERING_AUTHOR_RECEIPT
R5N02 R5_BOUND_PROSPECTIVE_ROSTER
R5N03 R5_INDEPENDENT_GOVERNED_REVIEW_PASS
R5N04 R5_PROSPECTIVE_ROSTER_SCHEMA_RENDER
R5N05 R5_ORDERING_REVIEW_SCHEMA_RENDER
R5N06 R5_ORDERING_RED_RECEIPT_SCHEMA_RENDER
R5N07 R5_FIXTURE_SOURCE
R5N08 R5_FIXTURE_TEST
R5N09 R5_EXPECTED_RED_RECEIPT
R5N10 STOP_NO_GREEN

R5N00->R5N01
R5N00->R5N02
R5N01->R5N02
R5N02->R5N03
R5N03->R5N04
R5N03->R5N05
R5N03->R5N06
R5N03->R5N07
R5N04->R5N08
R5N05->R5N08
R5N06->R5N08
R5N07->R5N08
R5N04->R5N09
R5N05->R5N09
R5N06->R5N09
R5N07->R5N09
R5N08->R5N09
R5N09->R5N10
```

`R5N03` means an actually materialized, schema-valid, semantically valid PASS
record at the exact governed review path. A Markdown opinion, absent identity,
REJECTED record, or later-created review cannot satisfy it. No edge reaches an
r4 node. The three schema renders and fixture source are siblings after PASS;
the test requires all four, and the receipt requires the test plus unchanged
render/source identities. `R5N10` is terminal.

## 9. Mandatory validation and terminal condition

Before author handoff and again before the prospective roster, validation MUST:

1. require UTF-8, no BOM, LF-only bytes, and exactly one final LF;
2. parse every JSON fence with duplicate-key rejection, validate all four JSON
   roots (one fixture specification and three schemas), validate the three
   schemas against Draft 2020-12 metaschema, and resolve every local `$ref`;
3. rehash all seven lineage observations and all nine historical-invalid rows;
4. require the r4 governed review at SHA-256 `2bfefef8...98337f` to remain
   `REJECTED` with its exact two FAIL/open-blocker joins;
5. require exactly 3 schema paths, 5 semantic/output paths, 1 absent successor,
   8 roles, 28 separation pairs, 18 checks, 4 fixture cases, 11 DAG nodes, and
   18 DAG edges, all duplicate-free;
6. topologically sort the DAG and reject missing endpoints, a cycle, self-edge,
   duplicate edge, edge leaving `R5N10`, or edge to any r4 node;
7. prove every new path, except this contract and author receipt at their
   permitted stage, is absent and that the semantic successor is absent;
8. reject any r4 path in check/finding evidence and any import, copy, parent,
   hash credit, or candidate substitution from the historical-invalid roster;
9. validate PASS and truthful REJECTED controls plus hidden blocker,
   open-roster mismatch, principal alias, role relabel, actor mismatch,
   candidate mutation, pre-PASS render, and false RED-confirmation attacks; and
10. prove all common and V8 authority members false, Part-0 exact, production
    identities late-bound, no candidate import, and no production edit.

This author turn creates no roster, governed review, rendered schema, fixture,
test, RED receipt, semantic successor, or production artifact. The next allowed
action is only the prospective signed roster. Even a future governed PASS is
bounded to exact schema rendering and expected-RED fixture work; it grants no
GREEN, semantic acceptance, construction, production, native, provider,
publication, admission, package, installation, release, cutover, commit, or
push authority.

Status: `CONTRACT_ONLY_PENDING_R5_PROSPECTIVE_ROSTER_AND_GOVERNED_REVIEW`
