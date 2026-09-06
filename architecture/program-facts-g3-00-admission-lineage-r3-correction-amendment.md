# Program Facts G3-00 admission-lineage Part-0 r3 correction amendment

Status: `CONTRACT_ONLY_PENDING_FRESH_INDEPENDENT_R3_REVIEW`

This create-only Part-0 amendment corrects exactly the four blocking findings in
the rejected r2 admission-lineage review and the two construction-lineage
ambiguities that those findings expose. It does not edit, replace, reinterpret,
or complete any existing artifact. In particular, it grants no implementation,
runtime, native, provider, publication, admission, construction, release,
installation, cutover, commit, push, consumer, audit, finding, severity,
confidence, refutation, suppression, clean-certification, or terminal-negative
authority.

The governing r2 amendment remains immutable design input. Its independent r2
review is an exact `REJECTED` artifact, not a passing parent. Where this
amendment conflicts with r2 sections 15.1, 15.2, 15.3, 15.8, 15.10, 15.11,
15.12, or 15.13, this amendment supplies only the narrow correction stated
here. Every unrelated r2 requirement remains unchanged and non-enabling.

## 1. Exact immutable source registry

Every normative source is an exact byte identity. The registry is closed,
ordered, and has exactly 18 rows. A mutable name, current working-tree hash,
content equality, later file, embedded `PASS`, or author receipt cannot
substitute for a row.

| Ordinal | Registry key | Path | Bytes | SHA-256 | Normative treatment |
|---:|---|---|---:|---|---|
| 0 | `R2_AMENDMENT` | `architecture/program-facts-g3-00-admission-lineage-closure-amendment.md` | 166233 | `9136a2b00ca32917e6dabb4023fa145b12daebb0f049601b1b59394408c572eb` | immutable rejected predecessor design |
| 1 | `R2_REJECTION` | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_CLOSURE_R2_INDEPENDENT_REVIEW.v1.json` | 19451 | `47a3e1469e1d1c768499493181282bb778d1dcf248da9bbf07f5b91d65077257` | exact `REJECTED` review and four blockers |
| 2 | `R313_CONTRACT` | `architecture/program-facts-g3-00-parity-launcher-r3-13-runtime-closure-crash-reconciliation-amendment.md` | 9506 | `7d1616dedea141ea5c7a7e8bd90e3ba0284c5bc4bec49ab6208f554d1671df47` | immutable inactive launcher contract |
| 3 | `R313_HANDOFF` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_13_WINDOWS_NATIVE_HANDOFF_7d1616dedea141ea.v1.json` | 6677 | `69e6452310ed3befc074c7a97b0b233db79be3917d09e1a31361e9fb7b42eabc` | immutable handoff, not a publication completion |
| 4 | `R313_STATE_REVIEW` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_13_STATE_OPERATIONAL_REVIEW_7d1616dedea141ea.md` | 11434 | `dce9edb11ec93db0832cb442836639e6f028bd49750a6014c6efb937db894655` | independent `ACCEPT`, inactive-candidate ceiling |
| 5 | `R313_NATIVE_REVIEW` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_13_NATIVE_CONTRACT_REVIEW_7d1616dedea141ea.md` | 10204 | `7d73204b1c524fc65fcbd9bc3d4831e2828e1e26d80bad65ccd011193effd37b` | independent `ACCEPT`, fixture/process-crash-only ceiling |
| 6 | `V8_PURE_CONTRACT` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/protected_control_root_v8_candidate/PROGRAM_FACTS_G3_00_PROTECTED_CONTROL_ROOT_CONTRACT_V8_CANDIDATE.md` | 5377 | `e42cc0efec2bf32346296c0fdf886ee62de8ed5ccf61e0c45b5d3b7428daffac` | offline pure-model parent only |
| 7 | `V8_SEMANTIC_REVIEW` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_PROTECTED_CONTROL_ROOT_CONTRACT_V8_SEMANTIC_REVIEW.md` | 12268 | `b6eb075fe3051a5e6841fb76b3cb9dab0ed46e2085dc9d3b6dfc33af557067b1` | independent `ACCEPT`, pure/offline/noninstalled only |
| 8 | `V8_PLATFORM_REVIEW` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_PROTECTED_CONTROL_ROOT_CONTRACT_V8_PLATFORM_OPERATIONAL_REVIEW.md` | 13655 | `d5ea9c8c0a9a93e845884fd49ed0be44e736e50c9b0f32456efcd532b2df162d` | independent `ACCEPT`, pure/offline/noninstalled only |
| 9 | `CROSSCHECK_R2_CONTRACT` | `architecture/program-facts-g3-00-stdlib-crosscheck-v3-recovery-amendment.md` | 154471 | `7deaa39309656775b86dcf7cc7952461deec51d0696961bc4447efab948eeafc` | immutable accepted recovery contract |
| 10 | `CROSSCHECK_R2_REVIEW` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_V3_RECOVERY_AMENDMENT_INDEPENDENT_REVIEW.v1.json` | 10245 | `7bb4e25560f643bbda4b215bb36489a297f7552b736ea68ed3fad31352c25f93` | exact passing review payload/final |
| 11 | `CROSSCHECK_R2_REVIEW_ARM` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/.__pfg3xv3r2_01_recovery_review.attempt.00000000000000000000.publish-arm.json` | 6044 | `c6dbe5c8af40d3a52531e35ea16899ba06d6987b1e629746bc7bab7cfefc6ada` | exact prepublication arm |
| 12 | `CROSSCHECK_R2_REVIEW_COMPLETION` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/.__pfg3xv3r2_01_recovery_review.attempt.00000000000000000000.completion.json` | 11606 | `e9c6b711e9c8dedc5cb258c4b07779f4746e52eeb569095dd0885ba6404f92d0` | exact completion and grade |
| 13 | `PROTECTED_ROOT_INTEGRATION_REPAIR` | `review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_PROTECTED_CONTROL_ROOT_INTEGRATION_REVIEW_V1.20260809.md` | 13319 | `4edbd6b4a6bdec2b0379540ffcb8a405e85a2be5bb37330f7dfd70a324c92589` | exact `REPAIR`, non-enabling |
| 14 | `PF_R2_CUTOVER_SPEC` | `architecture/program-facts-runtime-cutover-spec.md` | 238989 | `2f2025cf636ca80df560d7568760f6ebfc114a2c344a895940ea76566c953c79` | preimplementation and release-freeze lifecycle authority |
| 15 | `G3_01_AMENDMENT` | `architecture/program-facts-g3-01-construction-amendment.md` | 22967 | `b1e491f8250ed0927ba446e193dea86e60e2b70b3ed51a2e1cad6e59902266b0` | construction predecessor, narrowly corrected in section 5 |
| 16 | `LEDGER_V5_REVIEW` | `review_fixtures/PERSISTED_JSON_BOOL_INT_LEDGER_V5_INDEPENDENT_REVIEW_R1_20260809.md` | 14013 | `dd2eace1c90a6203d2efa0fd81154db7c319bf3360151b7702a758fe727a8574` | exact accepted historical production evidence only |
| 17 | `LEDGER_T1_REVIEW` | `review_fixtures/PROGRAM_FACTS_SELECTION_INTERPROCESS_CAS_T1_INDEPENDENT_REVIEW_R1_20260809.md` | 13025 | `ae24213111385496a94c8848f440fb9090f0e30ce8a1671ababaab834471a24b` | exact accepted historical production evidence only |

Rows 16 and 17 prove bounded accepted ledger repairs on their reviewed bytes.
They do not freeze a construction-time or current production module identity.
The T1 review expressly consumes the V5 review. Neither review is a cutover or
release freeze.

## 2. Canonical bytes, authority, and identity formulas

`CJ(x)` is RFC-8785 canonical JSON encoded as UTF-8. `CF(x) = CJ(x) || 0x0a`.
Governed JSON rejects duplicate keys, BOM, CR, invalid UTF-8, non-finite
numbers, unsafe integers, noncanonical escapes, unknown members, and trailing
bytes other than the required single LF. Paths are repository-relative,
forward-slash separated, NFC, exact-case, and contain no empty, dot, dot-dot,
control, colon, or backslash component.

For every governed r3 record:

```text
body_sha256 = SHA-256(CJ(object without only the *_body_sha256 member))
review_id = "pfg3alr3-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R3_CORRECTION_REVIEW_V1",
  review:<review object without review_id and review_body_sha256>
}))[0:32]
red_receipt_id = "pfg3alr3red-" || SHA-256(CJ({
  domain:"PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R3_CORRECTION_RED_RECEIPT_V1",
  receipt:<RED receipt without receipt_id and receipt_body_sha256>
}))[0:32]
```

The ID formula excludes the ID and body digest; the body formula excludes only
the body digest and therefore commits the already-derived ID. No artifact
contains, predicts, or blesses its own file size or file hash.

The common `authority_ceiling` is exact and has 29 members, all literal Boolean
false:

```json
{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}
```

`part_0_genericity` is exactly
`{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}`.
No narrower scope string changes either constant.

## 3. Three disjoint normative adoption types

### 3.1 R3.13 immutable legacy-reviewed launcher bundle

The exact R3.13 contract, handoff, and two independent ACCEPT reviews are
adopted together as one typed immutable bundle:

```text
reference_kind = IMMUTABLE_LEGACY_REVIEWED_LAUNCHER_R3_13_BUNDLE
contract       = source row 2
handoff        = source row 3
state_review   = source row 4; verdict ACCEPT
native_review  = source row 5; verdict ACCEPT
review_count   = 2
review_principals = [Codex:/root/r3_13_state_short,Codex:/root/r3_13_native_short]
review_principals_pairwise_distinct = true
candidate_active = false
retroactive_arm_claimed = false
retroactive_completion_claimed = false
accepted_use = LAUNCHER_LINEAGE_CONTRACT_PARENT_ONLY
```

The bundle is indivisible. A contract without the handoff, one review without
the other, a later launcher version, or content-equal bytes at another path is
not the bundle. Neither Markdown review has a publication arm or completion,
and none is fabricated. The accepted ceiling remains inactive-candidate and
fixture/process-crash-only; it is not provider, ledger, installation,
production publication, admission, activation, or cutover approval.

This type replaces r2's incompatible `launcher_review:file_published_ref`
assumption only for this exact launcher parent. It does not change any generic
legacy or published reference type.

### 3.2 V8 pure/offline oracle-and-fixture parent

The exact V8 contract and its two independent ACCEPT reviews are adopted only
as this disjoint parent:

```text
reference_kind = IMMUTABLE_V8_PURE_OFFLINE_ORACLE_FIXTURE_PARENT
contract        = source row 6
semantic_review = source row 7; verdict ACCEPT
platform_review = source row 8; verdict ACCEPT
accepted_use    = OFFLINE_ORACLE_AND_FIXTURE_PARENT_ONLY
consumption_mode = FILE_IDENTITY_AND_REVIEW_DISPOSITION_ONLY
```

Its specific authority ceiling is exact:

```json
{"commit":false,"contract_approval":false,"control_root_provisioning":false,"cutover":false,"edge_regeneration":false,"fixture_execution":false,"governed_edge_execution":false,"install":false,"linux_power_loss":false,"macos_platform":false,"migration":false,"native_prototype":false,"native_publication":false,"operational_approval":false,"provider":false,"push":false,"windows_power_loss":false}
```

No V8 candidate module or entrypoint may be directly imported or called by a
construction, oracle, runtime, provider, driver, ledger, package, or production
path. No candidate directory is placed on `sys.path`, copied into production,
or treated as a registry/plugin source. Governance fixtures may compare only
the exact file identities, review verdicts, constants, and serialized
expectations named here. V8 does not replace the accepted crosscheck contract
or turn the protected-root integration `REPAIR` at source row 13 into PASS.

### 3.3 Exact crosscheck contract/review publication bundle

The accepted crosscheck parent is exactly:

```text
reference_kind = IMMUTABLE_ACCEPTED_CROSSCHECK_R2_REVIEWED_PUBLICATION_BUNDLE
contract       = source row 9
review         = source row 10
attempt_ordinal = 00000000000000000000
publication_arm = source row 11
publication_completion = source row 12
completion_grade = PROTECTED_NAMESPACE_IDENTITY_PRESERVING_MATERIALIZATION
review_disposition = PASS_V3_R2_RECOVERY_CONTRACT_FOR_STRUCTURAL_DEBT_OBSERVATION_AND_FIXTURE_AUTHORSHIP_ONLY
accepted_use = CROSSCHECK_RECOVERY_CONTRACT_PARENT_ONLY
```

The grade is the completion's real serialized value and is accepted only inside
this exact five-field transport join. It is not added to r2's generic
`file_published_ref` enum, does not widen `LIVE_REVIEWED_EXECUTION` or
`CRASH_RECOVERED_UNIQUE_POSTSTATE`, and cannot validate another edge, arm,
completion, review, or future publication. The completion proves the exact
observable transport poststate, not an execution trace, semantic
certification, runtime, provider, publication authority, or cutover.

## 4. Total independent-review semantics

The r3 independent review uses the exact ordered 16-check roster below. Every
row is typed `PASS|FAIL`; evidence is nonempty. `REJECTED` may truthfully
contain any number of `FAIL` rows. The passing disposition is semantically
valid only when all 16 exact rows are `PASS`, there is no open finding, and the
open-finding list equals the ordered IDs of findings whose status is `OPEN`.

```text
ALR3-01-SUBJECT-STABLE
ALR3-02-R2-REJECTION-EXACT
ALR3-03-R313-BUNDLE-EXACT
ALR3-04-R313-NO-RETROACTIVE-TRANSPORT
ALR3-05-V8-OFFLINE-PARENT-ONLY
ALR3-06-CROSSCHECK-BUNDLE-EXACT
ALR3-07-CROSSCHECK-GRADE-EXACT-NONWIDENING
ALR3-08-CHECK-DISPOSITION-TOTALITY
ALR3-09-POST-CUT4-IDENTITIES-LATE-BOUND
ALR3-10-NO-CANDIDATE-IMPORT-AUTHORITY
ALR3-11-EXACT-ACYCLIC-DAG
ALR3-12-CREATE-ONLY-SUCCESSOR
ALR3-13-FIXTURE-FIRST-DENOMINATOR
ALR3-14-INDEPENDENCE-NO-SELF-CERTIFICATION
ALR3-15-AUTHORITY-ALL-FALSE
ALR3-16-PART0-GENERICITY
```

The exact create-only review path is:

```text
review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R3_CORRECTION_INDEPENDENT_REVIEW.v1.json
```

It never overwrites or aliases the r2 rejection. The review's only passing
disposition is
`PASS_G3_00_ADMISSION_LINEAGE_R3_CORRECTION_FOR_GOVERNANCE_RED_AND_SCHEMA_RENDERING_ONLY`.
Its accepted scope is exactly
`AUTHOR_R3_CORRECTION_GOVERNANCE_RED_FIXTURES_AND_RENDER_2_SCHEMAS_ONLY`.
Even a valid PASS grants no GREEN implementation, construction sequence,
candidate import, production edit, runtime, native operation, publication,
admission, release, or cutover authority.

## 5. Post-Cut4 production identities are late-bound

PF-R2 section 14.2 forbids preimplementation contract freeze records from
containing production-module, WTx/Ledger implementation, or installed-runtime
hashes. PF-R2 section 14.3 first binds actual production symbols and
WTx/Ledger identities in the postimplementation release freeze. That lifecycle
wins here.

Therefore the construction representation is exactly:

```text
binding_stage = POST_CUT4_POSTIMPLEMENTATION_RELEASE_FREEZE
construction_pins_forbidden = true
ARTIFACT_LEDGER_PRODUCTION.path = scripts/artifact_ledger.py
ARTIFACT_LEDGER_PRODUCTION.size_bytes member = FORBIDDEN
ARTIFACT_LEDGER_PRODUCTION.sha256 member = FORBIDDEN
RUNTIME_DRIVER_PRODUCTION.path = scripts/plamen_driver.py
RUNTIME_DRIVER_PRODUCTION.size_bytes member = FORBIDDEN
RUNTIME_DRIVER_PRODUCTION.sha256 member = FORBIDDEN
current_worktree_identity_authority = false
```

This narrowly supersedes any reading of G3-01 section 4 that would make its
historical `scripts/artifact_ledger.py` source-evidence hash, either accepted
ledger review's embedded production hash, or a hash of today's
`scripts/artifact_ledger.py` or `scripts/plamen_driver.py` a G3-01 construction
pin. The V5 and T1 reviews remain exact accepted historical evidence and
ordering inputs, but their embedded production identities are not copied into
construction. The current driver is not hashed here at all. Actual post-Cut4
production bytes are late-bound only by the separately reviewed release freeze
and later cutover receipt. No drift at these two mutable logical paths can be
silently accepted or rejected by this amendment.

The old G3-01 `worker_transaction.py` predecessor treatment is not widened or
changed by this narrow correction. No production implementation may begin on
the strength of this document or its review.

## 6. Closed schema and output registries

After, and only after, the create-only r3 review passes against the inline
schema, a separate renderer may create exactly these two schemas:

| Ordinal | Exact path | Exact root `schema_version` |
|---:|---|---|
| 0 | `rules/schemas/program_facts_g3_00_admission_lineage_r3_correction_review.v1.schema.json` | `plamen.program_facts_g3_00_admission_lineage_r3_correction_review.v1` |
| 1 | `rules/schemas/program_facts_g3_00_admission_lineage_r3_correction_red_receipt.v1.schema.json` | `plamen.program_facts_g3_00_admission_lineage_r3_correction_red_receipt.v1` |

The renderer copies the corresponding complete inline root, emits `CF`, and
makes no semantic substitution. The semantic output registry is exact and
ordered:

| Ordinal | Exact create-only path | Producer stage |
|---:|---|---|
| 0 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R3_CORRECTION_INDEPENDENT_REVIEW.v1.json` | fresh independent governance review |
| 1 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/admission_lineage_r3_correction_fixture_v1.py` | post-PASS RED fixture authoring |
| 2 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/test_admission_lineage_r3_correction_red_v1.py` | post-PASS RED fixture authoring |
| 3 | `review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R3_CORRECTION_RED_RECEIPT.v1.json` | RED execution evidence only |

No alias, v2/r2 overwrite, GREEN receipt, implementation handoff, candidate,
production file, manifest, admission record, or additional schema is in either
registry.

### 6.1 Independent r3 correction review schema

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_r3_correction_review.v1.schema.json",
  "$vocabulary":{"https://json-schema.org/draft/2020-12/vocab/core":true,"https://json-schema.org/draft/2020-12/vocab/applicator":true,"https://json-schema.org/draft/2020-12/vocab/validation":true},
  "type":"object",
  "additionalProperties":false,
  "required":["schema_version","review_id","subject","source_registry","launcher_r3_13_bundle","v8_offline_parent","crosscheck_reviewed_bundle","production_identity_binding","no_candidate_imports","reviewer","independence","checks","findings","open_findings","disposition","accepted_scope","rejected_scope","part_0_genericity","authority_ceiling","review_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_r3_correction_review.v1"},
    "review_id":{"type":"string","pattern":"^pfg3alr3-[0-9a-f]{32}$"},
    "subject":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"architecture/program-facts-g3-00-admission-lineage-r3-correction-amendment.md"}}}]},
    "source_registry":{"$ref":"#/$defs/source_registry"},
    "launcher_r3_13_bundle":{"$ref":"#/$defs/launcher_bundle"},
    "v8_offline_parent":{"$ref":"#/$defs/v8_bundle"},
    "crosscheck_reviewed_bundle":{"$ref":"#/$defs/crosscheck_bundle"},
    "production_identity_binding":{"$ref":"#/$defs/production_identity_binding"},
    "no_candidate_imports":{"const":{"candidate_direct_imports":false,"candidate_entrypoint_calls":false,"consumption_mode":"FILE_IDENTITY_AND_REVIEW_DISPOSITION_ONLY","production_callsites":false,"production_imports":false}},
    "reviewer":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"all_adopted_reviewers_separate":true,"no_self_generated_evidence":true,"no_self_review":true,"r2_reviewer_separate":true,"subject_author_separate":true,"workspace_clean":true}},
    "checks":{"type":"array","minItems":16,"maxItems":16,"prefixItems":[
      {"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR3-01-SUBJECT-STABLE"}}}]},
      {"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR3-02-R2-REJECTION-EXACT"}}}]},
      {"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR3-03-R313-BUNDLE-EXACT"}}}]},
      {"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR3-04-R313-NO-RETROACTIVE-TRANSPORT"}}}]},
      {"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR3-05-V8-OFFLINE-PARENT-ONLY"}}}]},
      {"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR3-06-CROSSCHECK-BUNDLE-EXACT"}}}]},
      {"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR3-07-CROSSCHECK-GRADE-EXACT-NONWIDENING"}}}]},
      {"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR3-08-CHECK-DISPOSITION-TOTALITY"}}}]},
      {"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR3-09-POST-CUT4-IDENTITIES-LATE-BOUND"}}}]},
      {"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR3-10-NO-CANDIDATE-IMPORT-AUTHORITY"}}}]},
      {"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR3-11-EXACT-ACYCLIC-DAG"}}}]},
      {"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR3-12-CREATE-ONLY-SUCCESSOR"}}}]},
      {"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR3-13-FIXTURE-FIRST-DENOMINATOR"}}}]},
      {"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR3-14-INDEPENDENCE-NO-SELF-CERTIFICATION"}}}]},
      {"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR3-15-AUTHORITY-ALL-FALSE"}}}]},
      {"allOf":[{"$ref":"#/$defs/check"},{"properties":{"check_id":{"const":"ALR3-16-PART0-GENERICITY"}}}]}
    ],"items":false},
    "findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/finding"}},
    "open_findings":{"type":"array","minItems":0,"maxItems":10000,"uniqueItems":true,"items":{"$ref":"#/$defs/identifier"}},
    "disposition":{"enum":["PASS_G3_00_ADMISSION_LINEAGE_R3_CORRECTION_FOR_GOVERNANCE_RED_AND_SCHEMA_RENDERING_ONLY","REJECTED"]},
    "accepted_scope":{"const":["AUTHOR_R3_CORRECTION_GOVERNANCE_RED_FIXTURES_AND_RENDER_2_SCHEMAS_ONLY"]},
    "rejected_scope":{"const":["ADMISSION","AUDIT","CANDIDATE_IMPORT","COMMIT","CONSTRUCTION","CUTOVER","GREEN_IMPLEMENTATION","INSTALL","NATIVE_EXECUTION","PACKAGE","PRODUCTION_EDIT","PRODUCTION_PUBLICATION","PROVIDER","PUSH","RELEASE","RUNTIME"]},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "review_body_sha256":{"$ref":"#/$defs/hex64"}
  },
  "allOf":[{"if":{"properties":{"disposition":{"const":"PASS_G3_00_ADMISSION_LINEAGE_R3_CORRECTION_FOR_GOVERNANCE_RED_AND_SCHEMA_RENDERING_ONLY"}},"required":["disposition"]},"then":{"properties":{"checks":{"not":{"contains":{"type":"object","required":["result"],"properties":{"result":{"const":"FAIL"}}}}},"open_findings":{"maxItems":0}}}}],
  "$defs":{
    "hex64":{"type":"string","minLength":64,"maxLength":64,"pattern":"^[0-9a-f]{64}$"},
    "identifier":{"type":"string","minLength":1,"maxLength":256,"pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]*$"},
    "safe_path":{"type":"string","minLength":1,"maxLength":4096,"pattern":"^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[\\\\:\\x00-\\x1f\\x7f])[^/]+(?:/[^/]+)*$"},
    "file_identity":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"$ref":"#/$defs/safe_path"},"size_bytes":{"type":"integer","minimum":0,"maximum":9007199254740991},"sha256":{"$ref":"#/$defs/hex64"}}},
    "principal":{"type":"object","additionalProperties":false,"required":["principal_id","organization","role"],"properties":{"principal_id":{"type":"string","minLength":12,"maxLength":256,"pattern":"^reviewer:[a-z0-9-]+/[a-z0-9-]+$"},"organization":{"type":"string","minLength":1,"maxLength":256},"role":{"type":"string","minLength":1,"maxLength":256}}},
    "check":{"type":"object","additionalProperties":false,"required":["check_id","result","evidence"],"properties":{"check_id":{"$ref":"#/$defs/identifier"},"result":{"enum":["PASS","FAIL"]},"evidence":{"type":"array","minItems":1,"maxItems":1000,"uniqueItems":true,"items":{"$ref":"#/$defs/file_identity"}}}},
    "finding":{"type":"object","additionalProperties":false,"required":["finding_id","severity","status","description","evidence"],"properties":{"finding_id":{"$ref":"#/$defs/identifier"},"severity":{"enum":["BLOCKING","NONBLOCKING"]},"status":{"enum":["OPEN","CLOSED"]},"description":{"type":"string","minLength":1,"maxLength":8192},"evidence":{"type":"array","minItems":1,"maxItems":1000,"uniqueItems":true,"items":{"$ref":"#/$defs/file_identity"}}}},
    "part0":{"type":"object","const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},
    "authority":{"type":"object","const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}},
    "source_registry":{"type":"array","const":[
      {"path":"architecture/program-facts-g3-00-admission-lineage-closure-amendment.md","size_bytes":166233,"sha256":"9136a2b00ca32917e6dabb4023fa145b12daebb0f049601b1b59394408c572eb"},
      {"path":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_CLOSURE_R2_INDEPENDENT_REVIEW.v1.json","size_bytes":19451,"sha256":"47a3e1469e1d1c768499493181282bb778d1dcf248da9bbf07f5b91d65077257"},
      {"path":"architecture/program-facts-g3-00-parity-launcher-r3-13-runtime-closure-crash-reconciliation-amendment.md","size_bytes":9506,"sha256":"7d1616dedea141ea5c7a7e8bd90e3ba0284c5bc4bec49ab6208f554d1671df47"},
      {"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_13_WINDOWS_NATIVE_HANDOFF_7d1616dedea141ea.v1.json","size_bytes":6677,"sha256":"69e6452310ed3befc074c7a97b0b233db79be3917d09e1a31361e9fb7b42eabc"},
      {"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_13_STATE_OPERATIONAL_REVIEW_7d1616dedea141ea.md","size_bytes":11434,"sha256":"dce9edb11ec93db0832cb442836639e6f028bd49750a6014c6efb937db894655"},
      {"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_13_NATIVE_CONTRACT_REVIEW_7d1616dedea141ea.md","size_bytes":10204,"sha256":"7d73204b1c524fc65fcbd9bc3d4831e2828e1e26d80bad65ccd011193effd37b"},
      {"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/protected_control_root_v8_candidate/PROGRAM_FACTS_G3_00_PROTECTED_CONTROL_ROOT_CONTRACT_V8_CANDIDATE.md","size_bytes":5377,"sha256":"e42cc0efec2bf32346296c0fdf886ee62de8ed5ccf61e0c45b5d3b7428daffac"},
      {"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_PROTECTED_CONTROL_ROOT_CONTRACT_V8_SEMANTIC_REVIEW.md","size_bytes":12268,"sha256":"b6eb075fe3051a5e6841fb76b3cb9dab0ed46e2085dc9d3b6dfc33af557067b1"},
      {"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_PROTECTED_CONTROL_ROOT_CONTRACT_V8_PLATFORM_OPERATIONAL_REVIEW.md","size_bytes":13655,"sha256":"d5ea9c8c0a9a93e845884fd49ed0be44e736e50c9b0f32456efcd532b2df162d"},
      {"path":"architecture/program-facts-g3-00-stdlib-crosscheck-v3-recovery-amendment.md","size_bytes":154471,"sha256":"7deaa39309656775b86dcf7cc7952461deec51d0696961bc4447efab948eeafc"},
      {"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_V3_RECOVERY_AMENDMENT_INDEPENDENT_REVIEW.v1.json","size_bytes":10245,"sha256":"7bb4e25560f643bbda4b215bb36489a297f7552b736ea68ed3fad31352c25f93"},
      {"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/.__pfg3xv3r2_01_recovery_review.attempt.00000000000000000000.publish-arm.json","size_bytes":6044,"sha256":"c6dbe5c8af40d3a52531e35ea16899ba06d6987b1e629746bc7bab7cfefc6ada"},
      {"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/.__pfg3xv3r2_01_recovery_review.attempt.00000000000000000000.completion.json","size_bytes":11606,"sha256":"e9c6b711e9c8dedc5cb258c4b07779f4746e52eeb569095dd0885ba6404f92d0"},
      {"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_PROTECTED_CONTROL_ROOT_INTEGRATION_REVIEW_V1.20260809.md","size_bytes":13319,"sha256":"4edbd6b4a6bdec2b0379540ffcb8a405e85a2be5bb37330f7dfd70a324c92589"},
      {"path":"architecture/program-facts-runtime-cutover-spec.md","size_bytes":238989,"sha256":"2f2025cf636ca80df560d7568760f6ebfc114a2c344a895940ea76566c953c79"},
      {"path":"architecture/program-facts-g3-01-construction-amendment.md","size_bytes":22967,"sha256":"b1e491f8250ed0927ba446e193dea86e60e2b70b3ed51a2e1cad6e59902266b0"},
      {"path":"review_fixtures/PERSISTED_JSON_BOOL_INT_LEDGER_V5_INDEPENDENT_REVIEW_R1_20260809.md","size_bytes":14013,"sha256":"dd2eace1c90a6203d2efa0fd81154db7c319bf3360151b7702a758fe727a8574"},
      {"path":"review_fixtures/PROGRAM_FACTS_SELECTION_INTERPROCESS_CAS_T1_INDEPENDENT_REVIEW_R1_20260809.md","size_bytes":13025,"sha256":"ae24213111385496a94c8848f440fb9090f0e30ce8a1671ababaab834471a24b"}
    ]},
    "launcher_bundle":{"type":"object","const":{"accepted_use":"LAUNCHER_LINEAGE_CONTRACT_PARENT_ONLY","candidate_active":false,"contract":{"path":"architecture/program-facts-g3-00-parity-launcher-r3-13-runtime-closure-crash-reconciliation-amendment.md","sha256":"7d1616dedea141ea5c7a7e8bd90e3ba0284c5bc4bec49ab6208f554d1671df47","size_bytes":9506},"handoff":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_13_WINDOWS_NATIVE_HANDOFF_7d1616dedea141ea.v1.json","sha256":"69e6452310ed3befc074c7a97b0b233db79be3917d09e1a31361e9fb7b42eabc","size_bytes":6677},"native_review":{"artifact":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_13_NATIVE_CONTRACT_REVIEW_7d1616dedea141ea.md","sha256":"7d73204b1c524fc65fcbd9bc3d4831e2828e1e26d80bad65ccd011193effd37b","size_bytes":10204},"reviewer_principal":"Codex:/root/r3_13_native_short","verdict":"ACCEPT"},"reference_kind":"IMMUTABLE_LEGACY_REVIEWED_LAUNCHER_R3_13_BUNDLE","retroactive_arm_claimed":false,"retroactive_completion_claimed":false,"review_count":2,"review_principals_pairwise_distinct":true,"state_review":{"artifact":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_launcher/PROGRAM_FACTS_G3_00_PARITY_LAUNCHER_R3_13_STATE_OPERATIONAL_REVIEW_7d1616dedea141ea.md","sha256":"dce9edb11ec93db0832cb442836639e6f028bd49750a6014c6efb937db894655","size_bytes":11434},"reviewer_principal":"Codex:/root/r3_13_state_short","verdict":"ACCEPT"}}},
    "v8_bundle":{"type":"object","const":{"accepted_use":"OFFLINE_ORACLE_AND_FIXTURE_PARENT_ONLY","consumption_mode":"FILE_IDENTITY_AND_REVIEW_DISPOSITION_ONLY","contract":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/protected_control_root_v8_candidate/PROGRAM_FACTS_G3_00_PROTECTED_CONTROL_ROOT_CONTRACT_V8_CANDIDATE.md","sha256":"e42cc0efec2bf32346296c0fdf886ee62de8ed5ccf61e0c45b5d3b7428daffac","size_bytes":5377},"platform_review":{"artifact":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_PROTECTED_CONTROL_ROOT_CONTRACT_V8_PLATFORM_OPERATIONAL_REVIEW.md","sha256":"d5ea9c8c0a9a93e845884fd49ed0be44e736e50c9b0f32456efcd532b2df162d","size_bytes":13655},"verdict":"ACCEPT"},"reference_kind":"IMMUTABLE_V8_PURE_OFFLINE_ORACLE_FIXTURE_PARENT","semantic_review":{"artifact":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_PROTECTED_CONTROL_ROOT_CONTRACT_V8_SEMANTIC_REVIEW.md","sha256":"b6eb075fe3051a5e6841fb76b3cb9dab0ed46e2085dc9d3b6dfc33af557067b1","size_bytes":12268},"verdict":"ACCEPT"},"specific_authority_ceiling":{"commit":false,"contract_approval":false,"control_root_provisioning":false,"cutover":false,"edge_regeneration":false,"fixture_execution":false,"governed_edge_execution":false,"install":false,"linux_power_loss":false,"macos_platform":false,"migration":false,"native_prototype":false,"native_publication":false,"operational_approval":false,"provider":false,"push":false,"windows_power_loss":false}}},
    "crosscheck_bundle":{"type":"object","const":{"accepted_use":"CROSSCHECK_RECOVERY_CONTRACT_PARENT_ONLY","attempt_ordinal":"00000000000000000000","completion_grade":"PROTECTED_NAMESPACE_IDENTITY_PRESERVING_MATERIALIZATION","contract":{"path":"architecture/program-facts-g3-00-stdlib-crosscheck-v3-recovery-amendment.md","sha256":"7deaa39309656775b86dcf7cc7952461deec51d0696961bc4447efab948eeafc","size_bytes":154471},"publication_arm":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/.__pfg3xv3r2_01_recovery_review.attempt.00000000000000000000.publish-arm.json","sha256":"c6dbe5c8af40d3a52531e35ea16899ba06d6987b1e629746bc7bab7cfefc6ada","size_bytes":6044},"publication_completion":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/.__pfg3xv3r2_01_recovery_review.attempt.00000000000000000000.completion.json","sha256":"e9c6b711e9c8dedc5cb258c4b07779f4746e52eeb569095dd0885ba6404f92d0","size_bytes":11606},"reference_kind":"IMMUTABLE_ACCEPTED_CROSSCHECK_R2_REVIEWED_PUBLICATION_BUNDLE","review":{"path":"review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/PROGRAM_FACTS_G3_00_STDLIB_CROSSCHECK_V3_RECOVERY_AMENDMENT_INDEPENDENT_REVIEW.v1.json","sha256":"7bb4e25560f643bbda4b215bb36489a297f7552b736ea68ed3fad31352c25f93","size_bytes":10245},"review_disposition":"PASS_V3_R2_RECOVERY_CONTRACT_FOR_STRUCTURAL_DEBT_OBSERVATION_AND_FIXTURE_AUTHORSHIP_ONLY"}},
    "production_identity_binding":{"type":"object","const":{"artifact_ledger":{"logical_role":"ARTIFACT_LEDGER_PRODUCTION","path":"scripts/artifact_ledger.py","sha256_member_forbidden":true,"size_bytes_member_forbidden":true},"binding_stage":"POST_CUT4_POSTIMPLEMENTATION_RELEASE_FREEZE","construction_pins_forbidden":true,"current_worktree_identity_authority":false,"ledger_review_embedded_production_hashes_are_historical_evidence_only":true,"runtime_driver":{"logical_role":"RUNTIME_DRIVER_PRODUCTION","path":"scripts/plamen_driver.py","sha256_member_forbidden":true,"size_bytes_member_forbidden":true}}}
  }
}
```

### 6.2 Governance RED receipt schema

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://plamen.local/schemas/program_facts_g3_00_admission_lineage_r3_correction_red_receipt.v1.schema.json",
  "$vocabulary":{"https://json-schema.org/draft/2020-12/vocab/core":true,"https://json-schema.org/draft/2020-12/vocab/applicator":true,"https://json-schema.org/draft/2020-12/vocab/validation":true},
  "type":"object",
  "additionalProperties":false,
  "required":["schema_version","receipt_id","contract","governing_review","rendered_schemas","fixture_source","fixture_test","cases","summary","executor","independence","scope","part_0_genericity","authority_ceiling","receipt_body_sha256"],
  "properties":{
    "schema_version":{"const":"plamen.program_facts_g3_00_admission_lineage_r3_correction_red_receipt.v1"},
    "receipt_id":{"type":"string","pattern":"^pfg3alr3red-[0-9a-f]{32}$"},
    "contract":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"architecture/program-facts-g3-00-admission-lineage-r3-correction-amendment.md"}}}]},
    "governing_review":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/PROGRAM_FACTS_G3_00_ADMISSION_LINEAGE_R3_CORRECTION_INDEPENDENT_REVIEW.v1.json"}}}]},
    "rendered_schemas":{"type":"array","minItems":2,"maxItems":2,"prefixItems":[{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"rules/schemas/program_facts_g3_00_admission_lineage_r3_correction_review.v1.schema.json"}}}]},{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"rules/schemas/program_facts_g3_00_admission_lineage_r3_correction_red_receipt.v1.schema.json"}}}]}],"items":false},
    "fixture_source":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/admission_lineage_r3_correction_fixture_v1.py"}}}]},
    "fixture_test":{"allOf":[{"$ref":"#/$defs/file_identity"},{"properties":{"path":{"const":"review_fixtures/program_facts_runtime_gate3/g3_00_admission_lineage/test_admission_lineage_r3_correction_red_v1.py"}}}]},
    "cases":{"type":"array","minItems":9,"maxItems":9,"prefixItems":[
      {"$ref":"#/$defs/case_01"},{"$ref":"#/$defs/case_02"},{"$ref":"#/$defs/case_03"},{"$ref":"#/$defs/case_04"},{"$ref":"#/$defs/case_05"},{"$ref":"#/$defs/case_06"},{"$ref":"#/$defs/case_07"},{"$ref":"#/$defs/case_08"},{"$ref":"#/$defs/case_09"}
    ],"items":false},
    "summary":{"const":{"red_confirmed_count":9,"setup_error_count":0,"unexpected_pass_count":0}},
    "executor":{"$ref":"#/$defs/principal"},
    "independence":{"const":{"contract_author_separate":true,"governing_reviewer_separate":true,"no_self_generated_evidence":true,"production_implementer_separate":true,"schema_renderer_separate":true,"workspace_clean":true}},
    "scope":{"const":"GOVERNANCE_RED_EVIDENCE_ONLY_NO_GREEN_NO_IMPLEMENTATION"},
    "part_0_genericity":{"$ref":"#/$defs/part0"},
    "authority_ceiling":{"$ref":"#/$defs/authority"},
    "receipt_body_sha256":{"$ref":"#/$defs/hex64"}
  },
  "$defs":{
    "hex64":{"type":"string","minLength":64,"maxLength":64,"pattern":"^[0-9a-f]{64}$"},
    "safe_path":{"type":"string","minLength":1,"maxLength":4096,"pattern":"^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))(?!.*[\\\\:\\x00-\\x1f\\x7f])[^/]+(?:/[^/]+)*$"},
    "file_identity":{"type":"object","additionalProperties":false,"required":["path","size_bytes","sha256"],"properties":{"path":{"$ref":"#/$defs/safe_path"},"size_bytes":{"type":"integer","minimum":0,"maximum":9007199254740991},"sha256":{"$ref":"#/$defs/hex64"}}},
    "principal":{"type":"object","additionalProperties":false,"required":["principal_id","organization","role"],"properties":{"principal_id":{"type":"string","minLength":12,"maxLength":256,"pattern":"^(executor|validator):[a-z0-9-]+/[a-z0-9-]+$"},"organization":{"type":"string","minLength":1,"maxLength":256},"role":{"type":"string","minLength":1,"maxLength":256}}},
    "case":{"type":"object","additionalProperties":false,"required":["case_id","required_property","red_oracle","evidence"],"properties":{"case_id":{"type":"string"},"required_property":{"type":"string","minLength":1,"maxLength":1024},"red_oracle":{"enum":["RED_CONFIRMED","UNEXPECTED_PASS","SETUP_ERROR"]},"evidence":{"type":"array","minItems":1,"maxItems":100,"uniqueItems":true,"items":{"$ref":"#/$defs/file_identity"}}}},
    "case_01":{"allOf":[{"$ref":"#/$defs/case"},{"properties":{"case_id":{"const":"ALC-R3-01-R313-TYPED-BUNDLE"},"required_property":{"const":"exact R3.13 contract, handoff, and both ACCEPT reviews form one immutable legacy-reviewed bundle"},"red_oracle":{"const":"RED_CONFIRMED"}}}]},
    "case_02":{"allOf":[{"$ref":"#/$defs/case"},{"properties":{"case_id":{"const":"ALC-R3-02-R313-NO-TRANSPORT-BACKFILL"},"required_property":{"const":"R3.13 legacy reviews receive no retroactive arm or completion"},"red_oracle":{"const":"RED_CONFIRMED"}}}]},
    "case_03":{"allOf":[{"$ref":"#/$defs/case"},{"properties":{"case_id":{"const":"ALC-R3-03-V8-OFFLINE-ONLY"},"required_property":{"const":"exact V8 trio is usable only as an offline oracle and fixture parent with all authority false"},"red_oracle":{"const":"RED_CONFIRMED"}}}]},
    "case_04":{"allOf":[{"$ref":"#/$defs/case"},{"properties":{"case_id":{"const":"ALC-R3-04-CROSSCHECK-GRADE-EXACT"},"required_property":{"const":"exact crosscheck review chain accepts only its real protected-namespace identity-preserving materialization grade"},"red_oracle":{"const":"RED_CONFIRMED"}}}]},
    "case_05":{"allOf":[{"$ref":"#/$defs/case"},{"properties":{"case_id":{"const":"ALC-R3-05-REJECTED-CAN-FAIL"},"required_property":{"const":"review checks allow PASS or FAIL while passing disposition requires all sixteen PASS"},"red_oracle":{"const":"RED_CONFIRMED"}}}]},
    "case_06":{"allOf":[{"$ref":"#/$defs/case"},{"properties":{"case_id":{"const":"ALC-R3-06-POST-CUT4-LATE-BOUND"},"required_property":{"const":"construction contains no artifact-ledger or runtime-driver size or hash pin"},"red_oracle":{"const":"RED_CONFIRMED"}}}]},
    "case_07":{"allOf":[{"$ref":"#/$defs/case"},{"properties":{"case_id":{"const":"ALC-R3-07-NO-CANDIDATE-IMPORT"},"required_property":{"const":"candidate direct imports, entrypoint calls, and production authority are absent"},"red_oracle":{"const":"RED_CONFIRMED"}}}]},
    "case_08":{"allOf":[{"$ref":"#/$defs/case"},{"properties":{"case_id":{"const":"ALC-R3-08-ACYCLIC-CREATE-ONLY"},"required_property":{"const":"exact dependency graph is acyclic and every successor path is absent before create-only publication"},"red_oracle":{"const":"RED_CONFIRMED"}}}]},
    "case_09":{"allOf":[{"$ref":"#/$defs/case"},{"properties":{"case_id":{"const":"ALC-R3-09-NO-SELF-CERT-AUTHORITY-PART0"},"required_property":{"const":"independent principals, no self-certification, all-false authority, and Part-0 genericity are exact"},"red_oracle":{"const":"RED_CONFIRMED"}}}]},
    "part0":{"type":"object","const":{"domain":"PART_0_GENERIC_ONLY","protocol_names":[],"protocol_specific_branching":false,"semantic_shortcuts":false}},
    "authority":{"type":"object","const":{"active_head_update":false,"admission":false,"audit":false,"canonical_installation":false,"canonical_promotion":false,"clean_certification":false,"commit":false,"confidence":false,"consumer":false,"cutover":false,"finding":false,"install":false,"package":false,"parity_capture":false,"process_capture":false,"production_publication":false,"provider":false,"provider_launch":false,"push":false,"refutation":false,"release":false,"replay":false,"runner":false,"runtime":false,"severity":false,"suppression":false,"terminal_negative":false,"three_way_parity":false,"vector_acceptance":false}}
  }
}
```

## 7. Exact fixture-first governance denominator

The RED denominator has exactly nine cases, matching schema section 6.2 in the
same order. Cases 1-5 reproduce the four r2 blockers, with the launcher blocker
split into bundle adoption and no-transport-backfill. Cases 6-9 cover the two
construction ambiguities, the create-only DAG, and the required
self-certification/authority/Part-0 ceiling.

Each case has one exact valid control and one single-mutation negative. RED and
control consume byte-identical source-registry inputs. The fixture may parse
schemas and governance records but may not import a candidate or production
module, invoke a candidate entrypoint, mutate a source, or write outside the
four semantic output paths and two schema paths in section 6. Passing RED
evidence requires exactly nine `RED_CONFIRMED`, zero unexpected pass, zero setup
error, duplicate-free canonical JSON, and an empty post-run diff outside those
create-only paths. It grants no GREEN or implementation authority.

Fixture author, schema renderer, RED executor, r3 reviewer, correction author,
and production implementer are distinct principals. An author receipt, schema
metaschema pass, unit-test pass, generated count, or embedded disposition is
never an independent review and cannot satisfy the create-only r3 review path.

## 8. Exact dependency DAG and stop boundary

The node registry has exactly 30 nodes. The edge registry below has exactly 44
directed edges; no implicit edge is permitted.

```text
N00 R2_AMENDMENT
N01 R2_REJECTION
N02 R313_CONTRACT
N03 R313_HANDOFF
N04 R313_STATE_REVIEW
N05 R313_NATIVE_REVIEW
N06 R313_BUNDLE
N07 V8_PURE_CONTRACT
N08 V8_SEMANTIC_REVIEW
N09 V8_PLATFORM_REVIEW
N10 V8_OFFLINE_BUNDLE
N11 CROSSCHECK_R2_CONTRACT
N12 CROSSCHECK_R2_REVIEW
N13 CROSSCHECK_R2_REVIEW_ARM
N14 CROSSCHECK_R2_REVIEW_COMPLETION
N15 CROSSCHECK_REVIEWED_BUNDLE
N16 PROTECTED_ROOT_INTEGRATION_REPAIR
N17 PF_R2_CUTOVER_SPEC
N18 G3_01_AMENDMENT
N19 LEDGER_V5_REVIEW
N20 LEDGER_T1_REVIEW
N21 POST_CUT4_LATE_BINDING_RULE
N22 R3_CORRECTION_CONTRACT
N23 R3_INDEPENDENT_REVIEW
N24 REVIEW_SCHEMA_RENDER
N25 RED_RECEIPT_SCHEMA_RENDER
N26 RED_FIXTURE_SOURCE
N27 RED_FIXTURE_TEST
N28 RED_RECEIPT
N29 STOP_NO_GREEN_IMPLEMENTATION

N02->N03
N02->N04
N03->N04
N02->N05
N03->N05
N04->N06
N05->N06
N07->N08
N07->N09
N08->N10
N09->N10
N11->N12
N12->N13
N13->N14
N12->N14
N11->N15
N12->N15
N13->N15
N14->N15
N17->N18
N19->N20
N17->N21
N18->N21
N19->N21
N20->N21
N00->N22
N01->N22
N06->N22
N10->N22
N15->N22
N16->N22
N21->N22
N22->N23
N23->N24
N23->N25
N23->N26
N24->N27
N25->N27
N26->N27
N24->N28
N25->N28
N26->N28
N27->N28
N28->N29
```

The enumerated registry is authoritative. Any renderer or reviewer that
observes another edge count must FAIL `ALR3-11-EXACT-ACYCLIC-DAG`.

Nodes N06, N10, N15, N21, and N29 are typed logical nodes, not files. N22 is
this document but does not embed its own file identity. N23 is created only
after N22 reaches stable bytes. N24-N28 require a valid N23 PASS. N29 is a hard
stop: no node in this amendment reaches GREEN implementation, G3-01
construction, production mutation, runtime, native execution, publication,
admission, release, or cutover.

## 9. Mandatory mechanical validation and terminal state

Before author handoff and again before independent review, validation MUST:

1. prove this document and every created r3 artifact is UTF-8 without BOM, uses
   LF only, and has no CR;
2. parse every `json` fence with duplicate-key rejection, validate both schema
   roots against Draft 2020-12 metaschema, and prove every `$ref` is local and
   resolves;
3. prove every object schema is closed or exact-`const`, the 29-field common and
   17-field V8-specific authority maps are all false, and both Part-0 constants
   are exact;
4. rehash all 18 source-registry rows and require path/size/hash equality;
5. prove the two schema rows, four semantic output rows, 16 checks, nine RED
   cases, 30 DAG nodes, and 44 DAG edges are exact, unique, and ordered;
6. topologically sort the edge registry and reject a cycle, missing node,
   duplicate edge, self-edge, or edge after N29;
7. prove every successor path was absent before its create-only step and that
   r2, production, fixture, schema, candidate, review, and manifest bytes were
   not edited by authoring this contract; and
8. reject any artifact-ledger or runtime-driver construction size/hash, V8 or
   R3.13 candidate import/call edge, generic completion-grade widening,
   retroactive launcher arm/completion, self-review, true authority bit, or
   protocol-specific Part-0 hint.

Failure creates no successor artifact and grants no authority. The next review
is bounded to governance correctness and, on PASS, authoring the registered RED
fixtures and rendering the two registered schemas. It is explicitly not an
implementation, GREEN, construction, native, runtime, provider, publication,
admission, release, or cutover review.

Status: `CONTRACT_ONLY_PENDING_FRESH_INDEPENDENT_R3_REVIEW`
