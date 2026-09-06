# Program Facts governed runtime, runner, replay, and packaging cutover specification

Revision: R2 candidate
Status: **normative pre-implementation candidate; readiness = false**
Scope: Gate 3 EVM Program Facts producer/publisher in additive `SHADOW` mode
Non-goals: target findings, semantic consumers, finding/severity/confidence/phase authority, non-EVM providers, and macOS/arm64 provider support

The independently blocked prior candidate, SHA-256 `6c32b7c723644e6adadf9c20327e9368b83eb6d770d62efbbd1b8d5410b451be`, is superseded. It MUST NOT be used as a pin. This R2 candidate uses **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, and **MAY** with RFC 2119 meaning. It specifies contracts only; it grants no implementation, runtime, provider, package, publication, review, or cutover authority.

## 1. Authority boundary and hard preconditions

### 1.1 Accepted construction seed, not runtime authority

The only R19 object eligible as construction input is:

| Property | Exact value |
|---|---|
| Path | `review_fixtures/program_facts_runner_v3_post_k_governance_plans/r9/R9_EXECUTABLE_REPAIR_PLAN_R19.json` |
| Bytes | `99,648,564` |
| SHA-256 | `a290e328f47b4802567f5d8f79fd9f6a2cfd4ec99809e4bfe8a300ad6486538e` |
| Schema | `R5ExecutableRepairPlanR19` |
| Counts | 88 definitions; 1,381 exhaustive rows; 111 named rows; 163 recursive-audit rows; 295 inverse runtime preimages; 6 lifecycle witnesses over 2 capabilities |
| Authority | all 15 authority bits false |

Its construction inputs are exactly:

| Path | Bytes | SHA-256 |
|---|---:|---|
| `review_fixtures/program_facts_runner_v3_post_k_governance_plans/r9/generate_r19.py` | 19,059 | `9dd4143b395fc1ffad9375e14590c1a526a12e1b02c8cc6687257614a29532b5` |
| `review_fixtures/program_facts_runner_v3_post_k_governance_plans/r9/test_r19_contract.py` | 9,033 | `0575790555d897aea3d4155c03c173ef1a49d28e2f7eedb78f55ec9939f0009d` |

The seed is only data used to construct and test this contract. Its embedded self identity, lifecycle state, requested next action, predicted receipts, and all generated counts confer no validator, runner, replay, provider, package, review, or cutover authority. The separate r11 R19 plan at `review_fixtures/program_facts_runner_v3_r11/R11_EXECUTABLE_SUCCESSOR_IMPLEMENTATION_PLAN_R19.md`, SHA-256 `667c1459e41cb44ca7d799b51d0ac79e3dbf983dcd932b5e100ccc0c56aabb4d`, remains `BLOCK` and has no authority. [D01] [S04] [S06] [S07]

### 1.2 Absent external seed-acceptance receipt

Before any production runtime implementation, a reviewer independent of the seed author, generator author, and this specification's author MUST create:

`review_fixtures/program_facts_runner_v3_post_k_governance_plans/r9/reviews/R9_EXECUTABLE_REPAIR_PLAN_R19_INDEPENDENT_ACCEPTANCE.v1.json`

under the immutable schema:

`rules/schemas/program_facts_r19_seed_acceptance.v1.schema.json`
`$id = https://plamen.local/schemas/program_facts_r19_seed_acceptance.v1.schema.json`

The closed top-level object has exactly:

```text
schema_version                 const plamen.program_facts_r19_seed_acceptance.v1
receipt_id                     pfr19a-<32 lowercase hex>
subject                        {path, size_bytes, sha256}
construction_inputs            ordered [file_identity]
reviewer                       {principal_id, organization, role}
independence                   six required booleans plus evidence[file_identity]
disposition                    const PASS_FOR_RUNTIME_SPEC_SEED_CONSTRUCTION_ONLY
accepted_scope                 const [SEED_CONSTRUCTION]
rejected_scope                 closed nine-value authority list
authority_bits                 closed object, all 15 const false
review_vectors                 ordered [case_id]
open_findings                  ordered [finding]
completed_at_utc               RFC3339 UTC, nonsemantic
receipt_body_sha256            SHA-256(CJ(object without this field))
```

`independence` requires `seed_author_separate`, `generator_author_separate`, `spec_author_separate`, `production_implementer_separate`, `workspace_clean`, and `no_self_generated_evidence`, all true. `rejected_scope` contains `RUNTIME`, `RUNNER`, `REPLAY`, `PROVIDER`, `PACKAGE`, `PUBLICATION`, `CONSUMER`, `FINDING`, and `CUTOVER`. A blocking open finding invalidates the disposition. The receipt ID is derived from its body digest; the receipt does not bless its own file hash. Its external file identity is pinned later by the preimplementation contract freeze. This artifact is currently absent, so production implementation is blocked. The specification cannot create or self-approve it. [D01]

`review_vectors` is exactly, in this order, `R19-SEED-01-SUBJECT-IDENTITY`, `R19-SEED-02-CONSTRUCTION-INPUTS`, `R19-SEED-03-SCHEMA-AND-SIZE-CENSUS`, `R19-SEED-04-AUTHORITY-ALL-FALSE`, `R19-SEED-05-INDEPENDENCE`, and `R19-SEED-06-NO-SELF-RECEIPT`. Admission requires every vector to pass against the receipt's exact `subject`/`construction_inputs`, the 99,648,564-byte census and schema, all 15 false bits/rejected scopes, the six true independence attestations and evidence, and absence of any embedded/predicted receipt identity. Missing, reordered, duplicated, or unevidenced vectors reject the passing disposition.

#### 1.2.1 Compact seed-admission runtime boundary

The 99,648,564-byte construction seed and its generator/tests are review-only, out-of-band inputs. They MUST NOT be shipped in the Gate-3 runtime/package closure, installed by Gate 3, or opened/read/hashed during audit startup, runner execution, replay, doctor, or rollback. After the section-1.2 acceptance exists, an independent admission reviewer performs the one permitted out-of-band stable read and creates:

```text
rules/program-facts-r19-seed-admission.v1.json
review_fixtures/program_facts_runtime_gate3/seed/PROGRAM_FACTS_R19_COMPACT_SEED_ADMISSION_INDEPENDENT_REVIEW.v1.json
```

The first conforms to `rules/schemas/program_facts_r19_seed_admission.v1.schema.json` and contains exactly:

```text
schema_version                 const plamen.program_facts_r19_seed_admission.v1
admission_id                   pfsa-<32hex>
construction_seed             {path,size_bytes:99648564,sha256:a290e328f47b4802567f5d8f79fd9f6a2cfd4ec99809e4bfe8a300ad6486538e}
construction_inputs            exact ordered two section-1.1 file_identity rows
external_acceptance            exact file_identity plus receipt_id/body digest/disposition
specification                  exact R2 file_identity plus spec-review file_identity
admitted_scope                 const CONTRACT_CONSTRUCTION_LINEAGE_ONLY
runtime_seed_read_forbidden    const true
authority_ceiling              all runtime/provider/publication/consumer/cutover booleans false
admission_body_sha256          SHA-256(CJ(object without admission_body_sha256))
```

The displayed seed hash is the full section-1.1 value, not an abbreviated serialized value; the schema requires exact equality. The review uses `program_facts_independent_review.v1.schema.json`, disposition `PASS_R19_SEED_ADMISSION_FOR_CONTRACT_FREEZE_ONLY`, and pins the compact binding plus the external acceptance. The contract freeze pins both compact artifacts and the exact construction digest linkage, but does not embed or package the 99 MB bytes. At runtime PF-00 reads only the compact binding, its review, and the contract freeze; it verifies their small file identities/cross-links and writes the same canonical admission body to `_program_facts/v3/control/seed_admission.v1.json`. Missing/drifted linkage is `GOVERNANCE_MISSING` or `SEED_IDENTITY_MISMATCH`, blocks all Gate-3 work/provider launch, and never triggers a fallback read of the construction seed.

That compact review admits only when its vector set is exactly `SEED-ADM-01-EXTERNAL-DIGEST-LINK`, `SEED-ADM-02-RUNTIME-READ-FORBIDDEN`, `SEED-ADM-03-AUTHORITY-CEILING`, `SEED-ADM-04-SUBJECT-AND-INPUT-IDENTITIES`, and `SEED-ADM-05-INDEPENDENCE`, all `PASS` with nonempty evidence identities, no open blocking finding, and the exact disposition above. Each vector respectively proves equality to the external receipt/construction digest, exclusion of the construction bytes from runtime/package inputs, every authority bit false, the compact subject/input file identities, and reviewer separation.

### 1.3 Blocked-plan reconciliation

The five r11 R19 review blockers are resolved without executing plan prose:

| Review blocker | Runtime resolution |
|---|---|
| R19-B01 | Section 3.2 defines one root/nested canonical Base64 primitive; JSON Schema regex is not the semantic decoder. |
| R19-B02 | Section 3.6 names exact modules/functions, closed error codes, and vectors. Unknown `VALIDATE_*` names are rejected. |
| R19-B03 | Section 3.5 defines a total validation-error order including branch and detail ordinals. |
| R19-B04 | Section 12 defines a closed denominator, mutation DSL, explicit IDs, exact set census, and no prose recovery identifiers. |
| R19-B05 | Every metamorphic mutation is serialized in the denominator and binds oracle-produced expected bytes. |

The blocked plan may not be substituted for any schema, validator, oracle, or receipt. [S07]

## 2. Required public-contract amendment

### 2.1 Why v1 and existing v2 cannot be cut over

The canonical architecture currently names the three v1 sidecars. Its closed v1 receipt cannot represent `NOT_IMPLEMENTED`, `SHADOW`, the complete authority ceiling, generation-indirected selection, or the required transaction prestate. The checked-in v2 schemas are also closed and omit required Gate-3 state/authority fields; they are unaccepted implementation evidence. Mutating either immutable schema in place or hiding authority in a private file is forbidden. [S01] [S16]

Therefore Gate 3 requires an explicit architecture successor before implementation. The amendment is not approved by this specification. It MUST be created as:

- `architecture/ecosystem-graph-provider-contract.v2.md`;
- `architecture/canonical-requirement-ownership.v2.json`;
- `rules/schemas/mechanical_program_facts.v3.schema.json`;
- `rules/schemas/mechanical_program_facts_receipt.v3.schema.json`;
- `rules/schemas/mechanical_program_facts_debt.v3.schema.json`;
- `rules/schemas/program_facts_public_generation.v2.schema.json`;
- `rules/schemas/program_facts_publication_arm.v2.schema.json`; and
- `rules/schemas/program_facts_active_selection.v1.schema.json`.

An independent architecture review at
`review_fixtures/program_facts_runtime_gate3/architecture/PROGRAM_FACTS_PUBLIC_V3_AMENDMENT_INDEPENDENT_REVIEW.v1.json`
MUST have disposition `PASS_PUBLIC_V3_SHADOW_CONTRACT_ONLY` and pin all eight files. Until then, readiness is false and PhaseIO MUST NOT register the v3 publisher.

Its vector set is exactly `ARCH-V3-01-CLOSED-PUBLIC-SCHEMAS`, `ARCH-V3-02-SOURCE-BINDING-GROUP`, `ARCH-V3-03-PROVIDER-REGISTRY-CROSS-REFERENCES`, `ARCH-V3-04-OWNERSHIP-V1-TO-V2`, `ARCH-V3-05-COMPATIBILITY-DISPATCH`, and `ARCH-V3-06-AUTHORITY-ALL-FALSE`, all `PASS` with nonempty evidence identities, no open blocking finding, exact eight-file subjects, reviewer independence, and the stated disposition. Missing/extra/reordered subject identities, an unresolved ownership conversion vector, or any true semantic/consumer/cutover authority bit rejects admission.

### 2.2 Public logical identities and compatibility

The amended public logical identities are exactly, in order:

```text
mechanical_program_facts.v3.json
mechanical_program_facts_receipt.v3.json
mechanical_program_facts_debt.v3.json
```

They are logical identities resolved through the ArtifactLedger active head; they are not mutable files at the scratchpad root. The v1 triple remains read-only legacy input for the legacy v1 loader. Existing v2 files are experimental, never active, and never migrated in place. A v3 loader accepts only v3. A compatibility dispatcher returns one of `ACTIVE_V3`, `LEGACY_V1`, `NO_SIDECAR`, or `INTEGRITY_BLOCKED`; it MUST NOT merge versions. In Gate-3 `SHADOW`, audit semantics always follow the legacy/no-sidecar path even when `ACTIVE_V3` exists. [D05]

### 2.3 Exact v3 public content contracts

All three v3 schemas are Draft 2020-12, closed at every object, use section 3 primitives, and have immutable `$id` values matching their paths.

`mechanical_program_facts.v3.json` contains exactly:

```text
schema_version                 const plamen.mechanical_program_facts.v3
canonicalization_version       const plamen.canonical_json.v3
run_id                         identifier
snapshot_id                    pfss-<32hex>
generation_id                  pfg-<32hex>
composition_semantic_digest    hex64
payload_semantic_id            pfps-<32hex>
mode                           const SHADOW
status                         public_status
nodes                          sorted unique array
occurrences                    sorted unique array
facts                          sorted unique array
completeness_scopes            sorted unique array
disagreements                  sorted unique array
semantic_authority             const ADDITIVE_PROPOSAL_ONLY
terminal_negative_authority    const false
document_sha256                body digest
```

`mechanical_program_facts_debt.v3.json` contains exactly:

```text
schema_version                 const plamen.mechanical_program_facts_debt.v3
canonicalization_version       const plamen.canonical_json.v3
run_id                         identifier
snapshot_id                    pfss-<32hex>
generation_id                  pfg-<32hex>
composition_semantic_digest    hex64
debt_semantic_id               pfds-<32hex>
mode                           const SHADOW
status                         public_status
debts                          sorted unique array of typed debt
terminal_negative_authority    const false
document_sha256                body digest
```

`mechanical_program_facts_receipt.v3.json` contains exactly:

```text
schema_version                 const plamen.mechanical_program_facts_receipt.v3
canonicalization_version       const plamen.canonical_json.v3
receipt_id                     pfr-<32hex>
receipt_semantic_id            pfrs-<32hex>
composition_semantic_digest    hex64
run_id                         identifier
run_generation                uint64
snapshot_id                    pfss-<32hex>
generation_id                  pfg-<32hex>
transaction_id                 pftx-<32hex>
mode                           const SHADOW
status                         public_status
governance                     governance_binding
source                         source_binding_group
selection                      capability_binding
build                          build_binding
environment                    environment_binding
execution                      execution_binding
composition                    composition_binding
publication                    publication_precommit_binding
replay                         replay_semantic_binding
artifacts                      exactly payload then debt file binding
authority                      authority_ceiling
nonsemantic_transport          transport_binding
receipt_body_sha256            body digest
```

`public_status` is exactly `WRITTEN`, `REUSED`, `DEGRADED`, `UNAVAILABLE`, `NOT_IMPLEMENTED`, `FAILED`, or `STALE`. `authority_ceiling` contains exactly `consumer`, `finding`, `severity`, `confidence`, `phase`, `clean_certification`, `refutation`, `suppression`, and `terminal_negative`; all are const false. `receipt_semantic_id` and `composition_semantic_digest` use only the section-5.3 semantic derivations. Separately, `receipt_id = "pfr-" || H({domain:"PROGRAM_FACTS_FULL_RECEIPT_PROVENANCE_V3",body_without_receipt_id_and_receipt_body_sha256})[0:32]`, then `receipt_body_sha256 = SHA-256(CJ(object without receipt_body_sha256))`; this full ID may vary with truthful provenance and never feeds a semantic ID. A production receipt is the runtime/replay authority envelope only when `governance.kind=RUNTIME`, its non-null release freeze/review/final-cutover lineage validates, it is active-head-selected, and it is ledger-bound. A `FIXTURE_PRE_RELEASE` receipt has only the exact section-12.1 G3-09 authority inside its bound execution root; it is never production authority and never authorizes a consumer. `publication` binds the transaction ID, generation ID, exact logical and physical paths, prior active-head state/digest, static-profile/resolved-contract/launch/expanded-input digests, and durability policy. It MUST NOT contain an arm, manifest, ACTIVE projection, ledger-record, provenance-event, or envelope digest created later.

### 2.4 Ownership amendment

`architecture/canonical-requirement-ownership.v2.json` MUST be a closed object with exactly:

```text
schema_version                 const plamen.canonical_requirement_ownership.v2
predecessor                    exact file_identity of architecture/canonical-requirement-ownership.v1.json
owners                         sorted unique owner rows
requirements                   sorted unique requirement rows
redirects                      sorted unique redirect rows
registry_body_sha256           SHA-256(CJ(object without registry_body_sha256))
```

The row contracts are exact:

```text
owner_row       {owner_key:IdentifierV3,normative_document:file_identity,legacy_normalization_or_null:null|{format:json|markdown|yaml,content_sha256_lf_nfc:hex64},normalized_owner_sha256:hex64,status:INHERITED_V1|CONTRACT_ONLY_PENDING_IMPLEMENTATION}
anchor_ref      {kind:MARKDOWN_ANCHOR,value:IdentifierV3}|{kind:JSON_POINTER,value:rfc6901_pointer}
requirement_row {registry_ordinal:uint32,requirement_id:IdentifierV3,owner_key:IdentifierV3,anchor:anchor_ref,section_ordinal_or_null:uint32>=1|null,status:REPRESENTED_WITH_RESIDUAL|REPRESENTED_WITH_EXTERNAL_RESIDUAL|CONTRACT_ONLY_PENDING_IMPLEMENTATION}
redirect_row    {predecessor_requirement_id:IdentifierV3,predecessor_owner_key:IdentifierV3,successor_owner_key:IdentifierV3,successor_document:file_identity,reason:IdentifierV3}
```

`owners` sorts by UTF-8 `owner_key`; `requirements` sorts by numeric `registry_ordinal`; `redirects` sorts by `(UTF8(predecessor_requirement_id),UTF8(successor_owner_key))`. Every sort key and every `requirement_id` is unique. `rfc6901_pointer` is either the empty string or `/` followed by slash-separated valid-Unicode reference tokens in which every literal `~` occurs only as escape `~0` or `~1`; evaluation unescapes `~1` then `~0`. A JSON Pointer such as `/schema_version` remains a `JSON_POINTER`; it is never coerced to `IdentifierV3` or interpreted as a Markdown anchor.

The only valid OWN-v1 to OWN-v2 conversion is:

1. Stable-read and validate the exact predecessor identity in `predecessor`; its v1 object has five owner properties and exactly 146 requirement array entries.
2. Enumerate v1 owner properties by UTF-8 owner key. For each, stable-read `path` into `normative_document`, copy v1 `format` and `content_sha256_lf_nfc` unchanged into non-null `legacy_normalization_or_null`, copy `content_sha256_lf_nfc` unchanged to `normalized_owner_sha256`, and set status `INHERITED_V1`. Independently normalize the document by decoding strict UTF-8, converting CRLF/CR to LF, applying Unicode NFC, encoding UTF-8 without BOM, and require its SHA-256 to equal that copied digest. A mismatch or missing file blocks conversion.
3. Enumerate the literal v1 `requirements` array in source order. Set `registry_ordinal` to its zero-based array index `0..145`, rename `id` to `requirement_id` and `owner` to `owner_key`, and copy status by the identity map `REPRESENTED_WITH_RESIDUAL -> REPRESENTED_WITH_RESIDUAL` and `REPRESENTED_WITH_EXTERNAL_RESIDUAL -> REPRESENTED_WITH_EXTERNAL_RESIDUAL`; no other predecessor status is accepted. If v1 `anchor` starts with `/`, emit `{kind:JSON_POINTER,value:anchor}` and null section ordinal. Otherwise emit `{kind:MARKDOWN_ANCHOR,value:anchor}` and the one-based encounter ordinal of the unique matching ATX heading in that owner's normative Markdown document. For this legacy resolver only, form the comparison token by trimming ATX/trailing-hash syntax, removing the leading decimal section label matching `^[0-9]+(?:\.[0-9]+)*\.?[ ]+`, lowercasing ASCII, deleting punctuation other than `-` and `_`, replacing each ASCII space with `-`, and retaining repeated `-`; the token must equal v1 `anchor`. Zero or multiple matches blocks conversion.
4. Append exactly `PFR-01..PFR-20` at ordinals `146..165`, owner `program_facts_runtime`, status `CONTRACT_ONLY_PENDING_IMPLEMENTATION`, section ordinal respectively `1..20`, and `MARKDOWN_ANCHOR` values respectively `1-authority-boundary-and-hard-preconditions`, `2-required-public-contract-amendment`, `3-deterministic-primitives`, `4-exact-schemas-and-artifact-paths`, `5-acyclic-identity-construction`, `6-sub-stages-and-exact-ownership`, `7-crash-safe-generation-indirected-publication`, `8-deterministic-runner-and-replay`, `9-ecosystem-host-toolchain-and-package-decisions`, `10-failure-taxonomy`, `11-cache-concurrency-migration-and-rollback`, `12-independent-oracle-and-exact-acceptance-denominator`, `13-security-and-no-self-certification`, `14-governance-freeze-and-independent-review-workflow`, `15-mandatory-gate-3-order`, `16-current-blockers-and-exact-non-cutover-consequences`, `17-source-and-decision-provenance`, `18-eight-residual-implementation-readiness-repair-map`, `19-explicit-invariants-and-assumptions`, and `20-non-goals-and-authority-ceiling`.
5. Add owner `program_facts_runtime` with null `legacy_normalization_or_null`, the exact stable file identity of this specification as `normative_document`, `normalized_owner_sha256 = SHA-256(UTF8(NFC(LF(specification text))))` using the same normalization above, and status `CONTRACT_ONLY_PENDING_IMPLEMENTATION`. Materialize graph-provider moves only as redirect rows to the exact file identity of `architecture/ecosystem-graph-provider-contract.v2.md`; no predecessor row may be deleted, overwritten, reordered, or silently retargeted.

These steps are total: any different count, source order, status mapping, tagged-anchor choice, section ordinal, digest preimage, or appended ordinal is `GOVERNANCE_IDENTITY_MISMATCH`. The v2 schema's conversion vectors include at least the two predecessor statuses, a repeated Markdown anchor resolved within different owner documents, `/schema_version`, `~0`/`~1` JSON-Pointer escaping, missing and ambiguous headings, and ordinals 0, 145, 146, and 165.

The amendment also assigns:

| Concern | Sole normative owner |
|---|---|
| Public v3 semantic schemas and ecosystem semantics | graph contract v2 |
| Runtime identities, stages, runner/replay, publication | this specification |
| Work-unit resolution/publication permission | `scripts/phase_io_contracts.py` through the exact amended contracts in section 6 |
| Staging/process isolation | `scripts/worker_transaction.py` plus v3 WTx protocol |
| Durable commit/CAS evidence | `scripts/artifact_ledger.py` plus v3 ledger record schema |
| Package/runtime closure | `verification_policy/toolchain_runtime_closure.v2.json` |
| Review/cutover | independent receipts in section 14 |

No writer may claim two owners for the same public path. The architecture/ownership representation and complete work-unit/RACI contract are accepted at G3-00. G3-06 only implements and pins the already accepted PhaseIO registrations; it does not amend ownership. The owner-registry v2 identity is a required contract-freeze input.

### 2.5 Common closed v3 types

The v3 schemas define these reusable closed objects; every listed field is required unless explicitly marked nullable. No other null is legal.

| Type | Exact required fields and rules |
|---|---|
| `file_identity` | `{path:portable_path, size_bytes:uint64, sha256:hex64}` |
| `source_binding` | `{source_file_id:pfs-id, root_token:pfrt-id, path:portable_path, start_byte:uint64, end_byte:uint64, start_line:uint32, start_column:uint32, end_line:uint32, end_column:uint32}`; end is exclusive and not before start |
| `tool_identity` | `{name:IdentifierV3, version:string[0..512], executable_or_module:file_identity, version_stdout_sha256:hex64, transitive_closure_sha256:hex64}` |
| `debt_evidence` | `{kind:EVIDENCE_FILE|CONTROL_RECEIPT|PROVIDER_RAW|PROCESS_EVIDENCE, semantic_evidence_id:pfse-<32hex>, content_sha256:hex64}`; postimplementation file/receipt/process identities are forbidden and live only in the provenance envelope |
| `artifact_binding` | `{logical_identity:public_logical_identity, semantic_artifact_id:pfps-<32hex>|pfds-<32hex>, physical_path:portable_path, size_bytes:uint64, full_file_sha256:hex64, document_sha256:hex64}`; role fixes the permitted semantic-ID prefix |
| `authority_ceiling` | nine fields from section 2.3, each const false |

`hex64` is `^[0-9a-f]{64}$`; uint32/uint64 are JSON integers within their unsigned bounds and the section-3 safe-integer ceiling. All arrays described as sets are duplicate-free and sorted by `CJ(element)`. Ordered tuples use the literal order stated below. `semantic_evidence_id = "pfse-" || H({domain:"PROGRAM_FACTS_SEMANTIC_EVIDENCE_V1",kind,content_sha256})[0:32]`; it commits only to the evidence kind and content digest, never to a path, host, tool, process, receipt, attempt, terminal, or containment identity.

### 2.6 Payload node, occurrence, fact, scope, and disagreement

`node` is closed and contains exactly:

```text
node_id                pfn-<32hex>
kind                   CONTRACT|FUNCTION|MODIFIER|STATE_VARIABLE|LOCAL_VARIABLE|PARAMETER|RETURN_VALUE|TYPE|EXTERNAL_SYMBOL|UNKNOWN_TARGET
qualified_name         UTF-8 string 1..4096 bytes
display_name           UTF-8 string 0..4096 bytes
build_variant_id       IdentifierV3
source_binding         source_binding or null; null allowed only for EXTERNAL_SYMBOL/UNKNOWN_TARGET
signature              {canonical:string<=16384, language_specific:closed empty object, signature_fact_ref:IdentifierV3 or null}
attributes             sorted unique IdentifierV3 array
```

`occurrence` is closed and contains exactly:

```text
occurrence_id           pfo-<32hex>
kind                    CALL_SITE|READ_SITE|WRITE_SITE|BRANCH_PREDICATE|RETURN_SITE|SINK_SITE|AUTH_SITE|TRANSFER_SITE|CREATE_SITE
enclosing_node_id       node_id
source_binding          source_binding
ir_binding              null or {compilation_unit_sha256:hex64, block_id:IdentifierV3, instruction_id:IdentifierV3, ir_sha256:hex64}
```

`fact` is closed and contains exactly:

```text
fact_id                 pff-<32hex>
relation_kind           one of the 19 values below
subject_id              node_id
object_id               node_id
occurrence_ids          sorted unique occurrence_id array
build_variant_id        IdentifierV3
provider_id             IdentifierV3
capability_id           IdentifierV3
provenance_origin       COMPILER_IR|SSA|AST|BYTECODE|SOURCE_PARSE|INDEX_REFERENCE
precision               EXACT|MAY|HEURISTIC|SYNTACTIC
coverage_scope          OCCURRENCE|FUNCTION|CONTRACT|PACKAGE|BUILD_VARIANT
structural_confidence   PROVIDER_EXACT|PROVIDER_MAY|SOURCE_FALLBACK|UNKNOWN
context                 fact_context
semantic_authority      const ADDITIVE_PROPOSAL_ONLY
attestation_ids         sorted unique IdentifierV3 array
```

The relation enum is exactly `MAY_REACH_CHA`, `MAY_REACH_RTA`, `MAY_REACH_VTA`, `RESOLVED_STATIC_CALL`, `UNRESOLVED_DYNAMIC_CALL`, `EXACT_CFG_DOMINATES`, `EXACT_CFG_EDGE`, `EXACT_CFG_POST_DOMINATES`, `MAY_DEPENDENCY_CONTRACT`, `MAY_DEPENDENCY_FUNCTION`, `AUTH_CHECK_OCCURRENCE`, `CREATE_OCCURRENCE`, `SYNTACTIC_SINK`, `VALUE_TRANSFER_OCCURRENCE`, `READS_STATE`, `WRITES_STATE`, `CONTAINS`, `DECLARES`, and `INHERITS_OR_IMPLEMENTS`.

`fact_context` is closed and contains exactly `{call_dispatch, analysis_algorithm, root_set_sha256, dominating_predicate_ids, host_semantic_kind}`. `call_dispatch` is `INTERNAL|LIBRARY|INTERFACE|HIGH_LEVEL|LOW_LEVEL|DELEGATE|CREATE|DYNAMIC|UNKNOWN`; `root_set_sha256` is `hex64` or null; dominating IDs are a sorted unique set; other strings are bounded by 1024 UTF-8 bytes.

`completeness_scope` is closed and contains exactly `{scope_id, capability_id, build_variant_id_or_null, source_file_ids, disposition, evidence_ids}`. `disposition` is `COMPLETE_FOR_DECLARED_SCOPE|PARTIAL|UNAVAILABLE|NOT_IMPLEMENTED`; source/evidence arrays are sorted sets, and every `evidence_id` is a `pfse-` semantic evidence ID above. `disagreement` is closed and contains exactly `{disagreement_id, semantic_key_sha256, contribution_ids, build_variant_ids, provider_ids, capability_ids, disposition, debt_id}`; all arrays are nonempty sorted sets, every `contribution_id` is a `pfcs-` contribution-semantic ID defined in section 6.2, and `disposition` is const `PRESERVED_NO_TRUTH_SELECTION`. Every fact `attestation_id` is likewise a `pfse-` semantic evidence ID; a WTx attempt, receipt, terminal, raw-CAS, executable, or containment identity is invalid in any public semantic array.

Payload arrays are ordered `nodes` by node ID, `occurrences` by occurrence ID, `facts` by fact ID, `completeness_scopes` by scope ID, and `disagreements` by disagreement ID. Equal ID with unequal body is blocking; byte-identical duplicates are rejected rather than silently deduplicated.

IDs are full-body semantic hashes: each node/occurrence/fact/scope/disagreement ID is derived from `H({domain:<TYPE_VERSION>, body_without_id})[0:32]`. Run, generation, transaction, absolute path, timestamp, wrapper, and arrival order are absent from those preimages.

### 2.7 Debt and receipt binding objects

`debt` is closed and contains exactly:

```text
debt_id                     pfd-<32hex>
code                        public_debt_code
scope_kind                  RUN|BUILD_VARIANT|CAPABILITY|SOURCE_FILE|WORK_UNIT|GENERATION|PLATFORM
scope_ids                   sorted nonempty IdentifierV3 array
ecosystem                   EVM|GO|RUST|SOLANA|SOROBAN|APTOS|SUI|DAML
provider_id_or_null         IdentifierV3 or null; null only for platform/not-implemented/controller debt
capability_id               IdentifierV3
evidence                    sorted debt_evidence array
retryable                   boolean
reuse_blocking              boolean
completeness_effect         NONE|PARTIAL|UNAVAILABLE|NOT_IMPLEMENTED
message_code                same token as code
terminal_negative_authority const false
```

`public_debt_code` is exactly `PROVIDER_NOT_IMPLEMENTED`, `PLATFORM_ARCH_NOT_ACCEPTED`, `PLATFORM_PROCESS_SCOPE_UNPROVEN`, `PLATFORM_PROFILE_UNKNOWN`, `TOOL_UNAVAILABLE`, `RAW_OUTPUT_MALFORMED`, `PROVIDER_DISAGREEMENT`, `NETWORK_BOUNDARY_DENIED`, `RESOURCE_LIMIT`, `PROVIDER_FAILURE`, `OPTIONAL_SOURCE_UNREADABLE`, or `ROLLBACK_ACTIVE`. Debts sort by debt ID and use `pfd- || H({domain:PROGRAM_FACTS_DEBT_V3, body_without_id})[0:32]`.

Receipt nested objects are closed:

| Binding | Exact fields |
|---|---|
| `governance_binding` | closed tagged union: production `{kind:RUNTIME,contract_freeze:file_identity,release_freeze:file_identity,seed_admission_id,seed_acceptance:file_identity,spec_review:file_identity,architecture_review:file_identity}` or fixture `{kind:FIXTURE_PRE_RELEASE,fixture_execution_authority:file_identity,seed_admission_id,seed_acceptance:file_identity,spec_review:file_identity,architecture_review:file_identity}`; fixture branch forbids contract/release fields |
| `source_binding_group` | `{checkpoint:file_identity, content_pack:file_identity, source_manifest:file_identity, source_authority_sha256:hex64, root_tokens:sorted[{root_token,root_role,portable_label}]}` |
| `capability_binding` | `{registry:file_identity, selection:file_identity, rows:sorted[{ecosystem,capability_id,provider_id,implementation_state,disposition,debt_id_or_null}]}` |
| `build_binding` | `{build_plan:file_identity conforming only to program_facts_evm_build_plan.v2, build_plan_id, input_manifest:file_identity, tool_identities:sorted[tool_identity], transitive_input_sha256:hex64}` |
| `environment_binding` | `{host_profile, containment_evidence:file_identity or null, environment_sha256, network_policy_sha256, resource_policy_sha256, process_policy_sha256}`; null evidence allowed only on no-launch rows |
| `execution_binding` | `{expected_children:file_identity, execution_authority:file_identity, execution_authority_id, attempts:sorted[{attempt_id,expected_child_id,terminal_role,terminal:file_identity,raw_cas:file_identity or null}], terminal_roster:file_identity, execution_set:file_identity}` |
| `composition_binding` | `{composition_semantic_digest:hex64,contribution_semantic_ids:sorted pfcs-id array,contribution_ids:sorted pfc-id array,composition_authority:file_identity,vocabulary:file_identity,normalization_policy:file_identity,disagreement_ids:sorted IdentifierV3 array}`; semantic IDs/digest cross-bind public bodies while full IDs/authority remain provenance-only |
| `publication_precommit_binding` | `{generation_id,transaction_id,arm_locator_id,arm_path,ordered_generation_paths,prior_head_state,phase_io_contract_profile_sha256,resolved_phase_io_contract_sha256,phase_io_launch_sha256,expanded_input_set_sha256,durability_policy}` |
| `replay_semantic_binding` | `{outcome:BUILT|REUSED|REBUILD_REQUIRED,semantic_source:{kind:COMPOSED_CURRENT|REUSED_PRIOR_SEMANTIC_BYTES|NO_PUBLIC_OUTPUT,payload_body_sha256_or_null,debt_body_sha256_or_null}}`; contains no reuse key, component hash, full identity, or provenance digest |
| `transport_binding` | `{invocation_label:NATIVE_DRIVER|LEGACY_CLAUDE_WRAPPER|FUTURE_CODEX_WRAPPER, wrapper_file_identity:file_identity or null}`; null only for native |

The artifact tuple is exactly payload then debt. `replay_semantic_binding` is exact: `BUILT` requires `COMPOSED_CURRENT` and both hashes equal the current provenance-free PF-60 payload/debt body hashes; `REUSED` requires `REUSED_PRIOR_SEMANTIC_BYTES` and both hashes equal both the current semantic bodies and the byte-validated prior provenance-free bodies; `REBUILD_REQUIRED` requires `NO_PUBLIC_OUTPUT` and both hashes null. In a preimplementation fixture these values are fixed only by the reviewed expected outcome and expected payload/debt bytes. No reuse key, component name/hash, replay transaction/event identity, or digest of a runtime, validator, release freeze, build plan/compiler/toolchain, environment/containment, WTx, resolved PhaseIO, Ledger, or runtime/package object is legal in this binding or reachable through either body hash. `prior_head_state` is the closed tagged union `{kind:ABSENT,head_revision:0}`, `{kind:PRESENT_ACTIVE,head_revision:uint64>=1,head_body_sha256:hex64,generation_id:pfg-id,transaction_id:pftx-id}`, or `{kind:PRESENT_DISABLED,head_revision:uint64>=1,head_body_sha256:hex64,disabled_transition_id:pfdt-id}`. No field from one branch is legal in another. The receipt never contains a later arm, manifest, ACTIVE projection, or ledger-postimage digest. Stable-read validation requires every duplicated seed/specification/architecture identity in a runtime branch to equal its contract/release-freeze lineage, and every such identity in a fixture branch to equal the referenced fixture-execution-authority lineage; unequal or dangling cross-references are `GOVERNANCE_IDENTITY_MISMATCH`. The fixture branch is legal for oracle expected bytes and G3-09 actual executions only, with the identical authority identity and exact execution-scope row; it cannot update any path outside that row's execution root. Thus expected/actual authority semantics are compared, not masked, and no release freeze is needed to produce the G3-09 evidence that the later release freeze consumes.

### 2.8 Exact provider registry v2 and placeholders

The registry artifact is `rules/program-facts-provider-registry.v2.json` under `rules/schemas/program_facts_provider_registry.v2.schema.json`. Its top level is exactly `{schema_version, release_state, ecosystems, providers, registry_body_sha256}`. `schema_version` is `plamen.program_facts_provider_registry.v2`; `release_state` is const `CONTRACT_FROZEN_EXECUTION_DISABLED`. This state disables production execution. It has one non-production exception: the exact independently reviewed section-12.1 fixture authority may launch a provider only for scope rows carrying `EVM_PROVIDER_BASELINE` during G3-09, after the contract freeze is proven to pin that authority/scope and the actual host/tool/containment prerequisites validate. The release freeze may later authorize the unchanged registry for reviewed production Gate-3 identities, but no freeze or review mutates this artifact. `ecosystems` is the eight-value ordered roster from section 9.1.

Each provider row is closed and contains exactly:

```text
provider_id
ecosystem
implementation_state          IMPLEMENTED|NOT_IMPLEMENTED
adapter                        null or {module,symbol,module_file_identity}
capabilities                   nonempty ordered capability rows
tool_identity_policy           null or {host_manifest_schema_id,version_policy,network_allowed:false}
authority                      {semantic_authority:ADDITIVE_PROPOSAL_ONLY,terminal_negative_authority:false,can_certify_clean:false,can_demote:false,can_refute:false,can_suppress:false}
```

An implemented adapter/tool policy is non-null; a not-implemented row requires both null. A capability row is exactly `{capability_id,implementation_state,allowed_relation_kinds,allowed_provenance_origins,maximum_precision,host_semantic_authority:false}`. Not-implemented capability arrays for relation/provenance are empty and precision is `NONE`.

The exact provider rows are:

| Ecosystem | Provider ID | Capability IDs | State |
|---|---|---|---|
| EVM | `evm.slither.typed` | the six `evm.slither.*.v1` IDs in section 9.1 | `IMPLEMENTED`; production launch disabled until release freeze/cutover; exact G3-09 fixture-scope exception only |
| GO | `go.placeholder.not_implemented` | `go.program_facts.not_implemented.v1` | `NOT_IMPLEMENTED` |
| RUST | `rust.placeholder.not_implemented` | `rust.program_facts.not_implemented.v1` | `NOT_IMPLEMENTED` |
| SOLANA | `solana.placeholder.not_implemented` | `solana.program_facts.not_implemented.v1` | `NOT_IMPLEMENTED` |
| SOROBAN | `soroban.placeholder.not_implemented` | `soroban.program_facts.not_implemented.v1` | `NOT_IMPLEMENTED` |
| APTOS | `aptos.placeholder.not_implemented` | `aptos.program_facts.not_implemented.v1` | `NOT_IMPLEMENTED` |
| SUI | `sui.placeholder.not_implemented` | `sui.program_facts.not_implemented.v1` | `NOT_IMPLEMENTED` |
| DAML | `daml.placeholder.not_implemented` | `daml.program_facts.not_implemented.v1` | `NOT_IMPLEMENTED` |

The EVM row's adapter is exactly `{module:"program_facts_evm_provider",symbol:"plan_evm_slither",module_file_identity:{path:"scripts/program_facts_evm_provider.py",size_bytes:124515,sha256:"356783aa0cfeac2b7cdd731262dea3748994fc5adec3208d11d6fca6631c4981"}}`. Its tool policy is exactly `{host_manifest_schema_id:"https://plamen.local/schemas/program_facts_host_tool_manifest.v1.schema.json",version_policy:"EXACT_SLITHER_ANALYZER_0_11_5_AND_PER_BUILD_SOLC_FULL_IDENTITY",network_allowed:false}`. The module must export that exact symbol; dynamic import fallback, alternate symbol, module alias, or changed file identity is `GOVERNANCE_IDENTITY_MISMATCH`.

The six EVM capability rows have exactly these semantic ceilings; arrays are in the literal order shown:

| Capability | Allowed relation kinds | Allowed provenance origins | Maximum precision |
|---|---|---|---|
| `evm.slither.calls.v1` | `MAY_REACH_CHA`, `MAY_REACH_RTA`, `MAY_REACH_VTA`, `RESOLVED_STATIC_CALL`, `UNRESOLVED_DYNAMIC_CALL` | `AST`, `BYTECODE`, `COMPILER_IR` | `EXACT` |
| `evm.slither.cfg.v1` | `EXACT_CFG_DOMINATES`, `EXACT_CFG_EDGE`, `EXACT_CFG_POST_DOMINATES` | `COMPILER_IR`, `SSA` | `EXACT` |
| `evm.slither.dependencies.v1` | `MAY_DEPENDENCY_CONTRACT`, `MAY_DEPENDENCY_FUNCTION` | `AST`, `COMPILER_IR`, `SSA` | `MAY` |
| `evm.slither.sinks.v1` | `AUTH_CHECK_OCCURRENCE`, `CREATE_OCCURRENCE`, `SYNTACTIC_SINK`, `VALUE_TRANSFER_OCCURRENCE` | `AST`, `COMPILER_IR`, `SOURCE_PARSE` | `EXACT` |
| `evm.slither.state.v1` | `READS_STATE`, `WRITES_STATE` | `AST`, `COMPILER_IR`, `SSA` | `EXACT` |
| `evm.slither.structure.v1` | `CONTAINS`, `DECLARES`, `INHERITS_OR_IMPLEMENTS` | `AST`, `INDEX_REFERENCE` | `EXACT` |

Cross-reference validation is mandatory: provider IDs in selection/build/child/request/raw/contribution/receipt rows equal the registry row; every requested/emitted capability belongs to that row; every emitted relation kind and provenance origin belongs to the selected capability's arrays and to the section-2 enum; `maximum_precision=MAY` forbids an `EXACT` claim; adapter planning returns only the exact provider/capability/build-variant tuple; raw bytes validate before `scripts/program_facts_evm_provider.py::parse_evm_slither_raw`; normalized rows validate through `scripts/program_facts_evm_provider.py::validate_evm_normalization_outcome`; and both symbols' module file identity equals the adapter identity above. A dangling capability, cross-capability relation, provenance overclaim, precision overclaim, or module/symbol drift is `CONTRIBUTION_INVALID`, never filtered silently.

Placeholder rows are executable selection data only: they deterministically emit debt and cannot be dynamically upgraded. Gate 16 requires a new registry version/review.

## 3. Deterministic primitives

### 3.1 Canonical JSON and file bytes

The canonicalization identifier is `plamen.canonical_json.v3`. `CJ(x)` follows RFC 8785/JCS section 3.2 for object-key ordering and string escaping, with the stricter numeric/profile rules below:

- strict UTF-8 input; no BOM; duplicate keys rejected during parse;
- objects sorted by UTF-16 code-unit order as RFC 8785 requires;
- strings emit `\"`, `\\`, `\b`, `\t`, `\n`, `\f`, `\r`; other U+0000-U+001F characters emit lowercase `\u00xx`; all other scalar values emit their shortest UTF-8 form;
- lone surrogates and invalid UTF-8 are rejected; strings are not Unicode-normalized;
- only integers in `[-9007199254740991, 9007199254740991]` are accepted; floats, exponent forms, negative zero, NaN, and infinities are rejected;
- literals are lowercase and no insignificant whitespace is emitted.

`CJ(x)` has no terminal newline. `CF(x) = CJ(x) || 0x0a`. Object/body digests use `SHA-256(CJ(preimage))`; file identities use raw `CF` bytes. A signed object omits only its named body-digest field from the preimage. No object contains or approves its own external file hash.

The normative implementation symbols to be created are:

```text
scripts/program_facts_runtime_v3_contracts.py::parse_strict_json_v3
scripts/program_facts_runtime_v3_contracts.py::canonical_json_bytes_v3
scripts/program_facts_runtime_v3_contracts.py::canonical_file_bytes_v3
```

Their eventual file identity is frozen after implementation; the independent oracle in section 12 MUST NOT import them.

#### 3.1.1 JSON Schema evaluation and composite normalization

Every governed schema declares exactly `$schema: "https://json-schema.org/draft/2020-12/schema"`, an immutable local `$id`, and `$vocabulary:{"https://json-schema.org/draft/2020-12/vocab/core":true,"https://json-schema.org/draft/2020-12/vocab/applicator":true,"https://json-schema.org/draft/2020-12/vocab/validation":true}`. Core, Applicator, and Validation are the only enabled vocabularies. Allowed schema keywords are exactly `$schema`, `$id`, `$vocabulary`, `$defs`, `$ref`, `type`, `const`, `enum`, `required`, `additionalProperties`, `propertyNames`, `properties`, `dependentRequired`, `prefixItems`, `items`, `contains`, `minContains`, `maxContains`, `minProperties`, `maxProperties`, `minItems`, `maxItems`, `uniqueItems`, `minLength`, `maxLength`, `pattern`, `minimum`, `maximum`, `multipleOf`, `allOf`, `anyOf`, `oneOf`, `not`, `if`, `then`, and `else`. `$ref` targets are same-document fragments or exact `$id` values present in the applicable pre-freeze/contract freeze; remote/network resolution, dynamic anchors/references, unevaluated vocabularies, format vocabularies/assertions, custom keywords, and implementation extensions are forbidden. The production dependency is exactly `jsonschema==4.26.0`, but library error iteration/text is never observable.

The evaluator surface is exactly `scripts/program_facts_runtime_v3_contracts.py::evaluate_json_schema_v1(instance,schema_id,registry)` followed by `scripts/program_facts_runtime_v3_contracts.py::normalize_schema_validation_events_v1(raw_events)`. The evaluator rejects an undeclared vocabulary/keyword or unresolved reference as `SCHEMA_INVALID` before instance validation; the normalizer never exposes library messages/classes and produces only section-3.5 events.

Keyword evaluation/normalization precedence is exact:

```text
000 $ref                 010 type                 020 const
030 enum                 040 required             050 additionalProperties
060 propertyNames        070 properties           080 dependentRequired
090 prefixItems          100 items                110 contains
120 min/maxProperties    130 min/maxItems         140 uniqueItems
150 min/maxLength        160 pattern              170 minimum/maximum
180 multipleOf           190 allOf                200 anyOf
210 oneOf                220 not                  230 if/then/else
```

Object property evaluation follows schema property names in UTF-16/JCS order, then unmatched instance property names in the same order. Array evaluation follows ascending index. Composite normalization is:

- `allOf`: evaluate every branch by literal array index and emit its normalized leaves; no synthetic parent error.
- `anyOf`: if at least one branch is valid, emit nothing; otherwise emit one `ANY_OF_NO_MATCH` event and every normalized branch leaf.
- `oneOf`: exactly one valid branch emits nothing; zero valid emits `ONE_OF_NO_MATCH` plus every branch leaf; multiple valid emits one `ONE_OF_MULTIPLE_MATCH` event whose detail is the sorted matching-index array and emits no branch leaves.
- `not`: a valid child emits one `NOT_FORBIDDEN_MATCH`; an invalid child emits nothing and discards child errors.
- `if/then/else`: errors from `if` are never emitted; a valid `if` evaluates only `then` with branch component 0, otherwise only `else` with branch component 1; absent selected branch emits nothing.
- `contains`: evaluate every item; success emits nothing; failure emits one `CONTAINS_NO_MATCH` plus normalized item leaves.

Every composite descent appends its zero-based branch/item index to `branch_path`. Synthetic events use the composite schema pointer and the branch path of the composite itself. Exact synthetic codes and ordinals are `ANY_OF_NO_MATCH=055`, `ONE_OF_NO_MATCH=056`, `ONE_OF_MULTIPLE_MATCH=057`, `NOT_FORBIDDEN_MATCH=058`, and `CONTAINS_NO_MATCH=059`, between path and stable-read error families. Conformance vectors are `review_fixtures/program_facts_runtime_gate3/primitives/schema_error_normalization.v1.json` under `program_facts_schema_error_vector.v1.schema.json` and cover zero/one/multiple matches, nested composites, property/index order, and equal-pointer tie cases.

Primitive/applicator member emission is closed. Non-synthetic failures use `SCHEMA_INVALID` and one of these exact `detail` objects; keywords marked “descend only” emit only normalized child events:

| Keyword | Exact event detail/emission |
|---|---|
| `$ref` | descend only; unresolved target emits `{keyword:"$ref",ref,reason:"UNRESOLVED"}` before instance evaluation |
| `type` | one `{keyword:"type",expected:sorted type names,actual_type}` |
| `const` | one `{keyword:"const",expected_sha256,actual_sha256}` |
| `enum` | one `{keyword:"enum",allowed_sha256:sorted unique hex64 array,actual_sha256}` |
| `required` | one `{keyword:"required",property}` per missing property, property UTF-16 order |
| `additionalProperties` | one `{keyword:"additionalProperties",property}` per forbidden unmatched property, property UTF-16 order |
| `propertyNames` | descend only at containing-object pointer plus escaped property token; detail descendants add `property_name` |
| `properties` | descend only in schema-property UTF-16 order |
| `dependentRequired` | one `{keyword:"dependentRequired",trigger,property}` per present trigger/missing dependent, trigger then property UTF-16 order |
| `prefixItems`, `items` | descend only in ascending instance index |
| `contains` | success emits none; failure emits `{keyword:"contains",min_contains,max_contains_or_null,match_count}` then item leaves by index |
| `minProperties`, `maxProperties`, `minItems`, `maxItems`, `minLength`, `maxLength` | one `{keyword,bound:uint64,actual:uint64}` for each violated keyword |
| `uniqueItems` | one `{keyword:"uniqueItems",first_index,duplicate_index,item_sha256}` for each later duplicate, paired with its earliest equal index |
| `pattern` | one `{keyword:"pattern",pattern,actual_sha256}` |
| `minimum`, `maximum`, `multipleOf` | one `{keyword,bound_or_divisor:integer,actual:integer}` |
| `allOf` | descend only by branch index |
| `anyOf` | synthetic `{keyword:"anyOf",branch_count}` before branch leaves when none match |
| `oneOf` | synthetic `{keyword:"oneOf",branch_count,matching_indices:sorted uint32 array}`; zero-match also emits branch leaves |
| `not` | synthetic `{keyword:"not"}` only when child matches |
| `if`, `then`, `else` | `if` emits none; selected branch descends with branch component 0 for `then`, 1 for `else` |

`actual_type` is exactly `null|boolean|integer|string|array|object`. Hash members are SHA-256 of `CJ(value)`. Child events retain their own schema pointer; added `property_name` is the only keyword-specific augmentation. Within one keyword, members emit in the order above; keywords follow the precedence table, recursive children follow declared branch/property/index order, and the final total sort remains section 3.5. No aggregate/library error may replace required member events.

### 3.2 Canonical Base64

`Base64BytesV1` is an ASCII JSON string in RFC 4648 section 4 canonical padded form. Its grammar is:

```text
B64      = QUAD* FINAL?
QUAD     = B64CHAR B64CHAR B64CHAR B64CHAR
FINAL    = B64CHAR B64CHAR "==" / B64CHAR B64CHAR B64CHAR "="
B64CHAR  = ALPHA / DIGIT / "+" / "/"
```

The empty string represents zero bytes. Whitespace, URL-safe alphabet, missing/excess padding, nonzero unused pad bits, and any string whose strict decoded bytes do not re-encode byte-for-byte to the input are rejected. The same semantic function validates root and nested values; JSON Schema patterns are only lexical prefilters. Normative symbol: `program_facts_runtime_v3_contracts.py::decode_base64_bytes_v1`.

### 3.3 Portable paths and root tokens

A portable relative path is `/`-separated UTF-8 scalar segments. It is 1-2048 UTF-8 bytes, has no leading `/`, drive/UNC prefix, backslash, colon, NUL/control, empty segment, `.`/`..` segment, trailing slash, or Unicode normalization rewrite. Every path must casefold uniquely within its declared root and resolve through stable physical-identity checks without an unapproved symlink, reparse point, or hardlink alias.

`IdentifierV3` is 1-512 ASCII bytes and matches `^[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}$`. A semantic root token has grammar `^pfrt-[0-9a-f]{64}$` and value `pfrt- || SHA-256(CJ({domain:"PROGRAM_FACTS_ROOT_TOKEN_V1", root_role, root_ordinal, portable_label}))`. `root_role` is one of `REPOSITORY`, `BUILD_INPUT`, `TOOLCHAIN`, `STAGING`, `CAS`, or `PACKAGE`; `root_ordinal` is uint32; `portable_label` is `IdentifierV3`. Absolute host paths appear only in nonsemantic resolver evidence. Normative symbols are `validate_portable_path_v3` and `derive_root_token_v1` in the contracts module.

### 3.4 Limits

The Gate-3 limits are exact:

| Limit | Value |
|---|---:|
| JSON nesting depth | 128 |
| Control/governance/schema document bytes | 16,777,216 |
| Public payload or debt file bytes | 1,073,741,824 |
| Public receipt/arm/manifest/ACTIVE-projection bytes | 67,108,864 |
| String UTF-8 bytes | 16,384 unless a narrower schema bound applies |
| Array items | 10,000,000 unless a narrower schema bound applies |
| Object properties | 4,096 unless a narrower schema bound applies |
| Provider stdin/raw stdout bytes | 67,108,864 each |
| Provider stderr bytes retained | 8,388,608 |
| Provider wall time | 900 seconds |
| Provider memory | 2,147,483,648 bytes |
| Provider process count | 64 |
| Provider concurrency per build variant | 1 |
| Source file bytes | 1,073,741,824 |
| Total admitted source bytes | 68,719,476,736 |

Limit violations use typed codes in section 3.5; they never truncate semantic JSON silently.

### 3.5 Closed ordinals and total error order

Stage ordinals are `PF-00=0`, `PF-10=10`, `PF-20=20`, `PF-30=30`, `PF-40=40`, `PF-50=50`, `PF-60=60`, `PF-70=70`, `PF-80=80`, and `PF-90=90`. WTx artifact-role ordinals are `ATTEMPT_ARM=0`, `ATTEMPT_COMPLETION=10`, `ATTEMPT_DEBT=20`, and `RAW_CAS_MANIFEST=30`. The only Gate-3 child role is `EVM_SLITHER_PROVIDER`, ordinal 10.

Error-code ordinals are closed:

```text
000 SCHEMA_INVALID                 010 NONCANONICAL_JSON
020 DUPLICATE_KEY                  030 INVALID_UTF8_OR_SURROGATE
040 INVALID_NUMBER                 050 INVALID_BASE64
055 ANY_OF_NO_MATCH                056 ONE_OF_NO_MATCH
057 ONE_OF_MULTIPLE_MATCH          058 NOT_FORBIDDEN_MATCH
059 CONTAINS_NO_MATCH
060 INVALID_PATH                   070 ROOT_ESCAPE_OR_ALIAS
080 STABLE_READ_DRIFT              090 GOVERNANCE_MISSING
100 GOVERNANCE_IDENTITY_MISMATCH   110 SELF_CERTIFICATION
120 SEED_IDENTITY_MISMATCH         130 VALIDATOR_UNKNOWN
140 SOURCE_UNDECLARED              150 REGISTRY_AMBIGUOUS
160 TOOL_IDENTITY_MISSING          170 BUILD_PLAN_INVALID
180 CHILD_ROSTER_INVALID           190 EXECUTION_AUTHORITY_MISMATCH
200 WTX_TERMINAL_INVALID           210 RAW_CAS_MISMATCH
220 LIMIT_EXCEEDED                 230 PROVIDER_FAILURE
240 CONTRIBUTION_INVALID           250 COMPOSITION_COLLISION
260 RECEIPT_CROSS_BINDING          270 PUBLICATION_PRESTATE_STALE
280 PUBLICATION_TORN_OR_DRIFTED    290 LEDGER_BINDING_INVALID
300 ACTIVE_PROJECTION_REPAIR_REQUIRED 310 REPLAY_KEY_MISMATCH
320 VERSION_UNSUPPORTED            330 DEBT_PERSISTENCE_FAILED
340 ORACLE_OR_DENOMINATOR_INVALID  350 AUTHORITY_ESCALATION
360 PACKAGE_CLOSURE_MISSING        370 PACKAGE_CLOSURE_COLLISION
380 PACKAGE_CLOSURE_DRIFT          390 PACKAGE_UNINSTALL_SURVIVOR
400 PLATFORM_ARCH_NOT_ACCEPTED     410 PLATFORM_PROCESS_SCOPE_UNPROVEN
420 PLATFORM_PROFILE_UNKNOWN       430 PROVIDER_NOT_IMPLEMENTED
440 TOOL_UNAVAILABLE               450 RAW_OUTPUT_MALFORMED
460 PROVIDER_DISAGREEMENT          470 SECRET_ENVIRONMENT
480 NETWORK_BOUNDARY_DENIED        490 RESOURCE_LIMIT
500 SHELL_INTERPOLATION_FORBIDDEN  510 GROUND_TRUTH_CONTAMINATION
520 CONSUMER_AUTHORITY_FALSE       530 ROLLBACK_ACTIVE
540 INTERNAL_FAILURE
```

Validation errors contain exactly `stage_ordinal`, `instance_pointer`, `schema_id`, `schema_pointer`, `error_code`, `error_code_ordinal`, `branch_path`, `detail_ordinal`, and `detail`. JSON Pointers use RFC 6901 UTF-8. `branch_path` is an array of uint32 components defined by section 3.1.1, empty outside composites. `detail_ordinal` is always 0: one validator event emits one canonical detail object; multiple conditions emit separate events. Errors sort by `(stage_ordinal, UTF8(instance_pointer), UTF8(schema_id), UTF8(schema_pointer), error_code_ordinal, lexicographic_uint32(branch_path), detail_ordinal, CJ(detail))`. Normative symbol: `program_facts_runtime_v3_contracts.py::order_validation_errors_v1`.

### 3.6 Exact production module/function surface and validator freeze

The new orchestration/primitive surface introduced by this cut is exactly:

```text
scripts/program_facts_runtime_v3_contracts.py::parse_strict_json_v3
scripts/program_facts_runtime_v3_contracts.py::canonical_json_bytes_v3
scripts/program_facts_runtime_v3_contracts.py::canonical_file_bytes_v3
scripts/program_facts_runtime_v3_contracts.py::decode_base64_bytes_v1
scripts/program_facts_runtime_v3_contracts.py::validate_portable_path_v3
scripts/program_facts_runtime_v3_contracts.py::derive_root_token_v1
scripts/program_facts_runtime_v3_contracts.py::evaluate_json_schema_v1
scripts/program_facts_runtime_v3_contracts.py::normalize_schema_validation_events_v1
scripts/program_facts_runtime_v3_contracts.py::order_validation_errors_v1
scripts/program_facts_runtime_v3_contracts.py::project_program_facts_receipt_semantics_v1
scripts/program_facts_runtime_v3_contracts.py::validate_program_facts_receipt_provenance_envelope_v1
scripts/program_facts_runtime_v3_identity.py::derive_expected_child_id_v2
scripts/program_facts_runtime_v3_identity.py::derive_execution_authority_id_v2
scripts/program_facts_runtime_v3_identity.py::derive_attempt_id_v2
scripts/program_facts_runtime_v3_identity.py::derive_generation_id_v3
scripts/program_facts_runtime_v3_identity.py::derive_arm_locator_id_v1
scripts/program_facts_runtime_v3_identity.py::derive_transaction_id_v4
scripts/program_facts_runtime_v3_runner.py::run_program_facts_gate3_v1
scripts/program_facts_runtime_v3_runner.py::replay_program_facts_generation_v1
scripts/program_facts_runtime_v3_publication.py::commit_immutable_generation_v2
scripts/program_facts_runtime_v3_publication.py::compare_and_swap_active_head_v1
scripts/program_facts_runtime_v3_publication.py::materialize_active_projection_v1
scripts/program_facts_runtime_v3_publication.py::reopen_active_head_v1
scripts/program_facts_runtime_v3_publication.py::recover_publication_v2
```

The release freeze pins `(module path, size, SHA-256, symbol, input schema IDs, output schema IDs, error-code subset, conformance-vector IDs)` for every symbol. Dynamic import, entry-point discovery, target-provided modules, source evaluation, plan DSL, and unlisted `VALIDATE_*` dispatch are prohibited.

Provider-specific parser/planner symbols and existing PhaseIO/WTx/Ledger entry points are outside this new-symbol list but are permitted only when explicitly named and pinned by the v2 provider registry plus either the exact reviewed G3-09 fixture authority/contract-freeze execution prerequisites or the release freeze. They may not implement or override the section-3 canonical/identity primitives.

## 4. Exact schemas and artifact paths

### 4.1 Schemas that MUST be created and independently reviewed

No listed schema exists by authority merely because it is named here. Each is created red-first, independently reviewed, and pinned by the contract freeze, release freeze, or both according to the section-14 lifecycle:

| Schema path | Exact `$id` suffix and content role |
|---|---|
| `rules/schemas/program_facts_r19_seed_acceptance.v1.schema.json` | seed acceptance receipt in section 1.2 |
| `rules/schemas/program_facts_r19_seed_admission.v1.schema.json` | compact runtime seed-lineage admission in section 1.2.1 |
| `rules/schemas/program_facts_runtime_contract_freeze.v1.schema.json` | preimplementation contract freeze in section 14.2 |
| `rules/schemas/program_facts_runtime_release_freeze.v1.schema.json` | postimplementation release freeze in section 14.3 |
| `rules/schemas/program_facts_independent_review.v1.schema.json` | common independent-review receipt in section 14.4 |
| `rules/schemas/program_facts_runtime_acceptance_denominator.v2.schema.json` | 160/691 denominator in section 12 |
| `rules/schemas/program_facts_runtime_oracle_manifest.v1.schema.json` | independent oracle provenance/expected-byte index |
| `rules/schemas/program_facts_runtime_execution_evidence.v1.schema.json` | 160/691 actual execution evidence |
| `rules/schemas/program_facts_receipt_semantic_projection.v1.schema.json` | preimplementation-knowable receipt result/authority semantics |
| `rules/schemas/program_facts_receipt_postimplementation_provenance_envelope.v1.schema.json` | full-receipt postimplementation provenance validation |
| `rules/schemas/program_facts_runtime_mutation.v1.schema.json` | closed 16-variant mutation union |
| `rules/schemas/program_facts_runtime_mutation_vector.v1.schema.json` | exact 34-vector mutation-union roster |
| `rules/schemas/program_facts_runtime_expected_result.v1.schema.json` | closed expected execution outcome and expected-file identity set |
| `rules/schemas/program_facts_runtime_fixture_manifest.v1.schema.json` | exact 160-case fixture identity/mutation/test-node manifest |
| `rules/schemas/program_facts_pre_freeze_fixture_governance.v1.schema.json` | acyclic synthetic governance binding for oracle expected bytes only |
| `rules/schemas/program_facts_pre_release_fixture_execution_scope.v1.schema.json` | exact 160/691 G3-09 fixture-root operation roster |
| `rules/schemas/program_facts_pre_release_fixture_execution_authority.v1.schema.json` | independently reviewed pre-release G3-09 authority |
| `rules/schemas/program_facts_source_identity_census.v1.schema.json` | exact 42 non-seed plus three seed/construction review census |
| `rules/schemas/program_facts_schema_error_vector.v1.schema.json` | composite-schema error-normalization vectors |
| `rules/schemas/program_facts_phase_io_interface_vector.v1.schema.json` | six-component key, `MODEL|DRIVER`, and static-profile matrix vectors |
| `rules/schemas/program_facts_gate3_shadow_flag.v1.schema.json` | default-off RuntimeDriver flag/coexistence contract |
| `rules/schemas/program_facts_gate3_shadow_flag_vector.v1.schema.json` | exact eight-vector flag/coexistence roster |
| `rules/schemas/program_facts_runtime_cutover_receipt.v1.schema.json` | independent Gate-3 cutover receipt |
| `rules/schemas/program_facts_checkpoint_capture.v1.schema.json` | checkpoint identity and exact roots |
| `rules/schemas/program_facts_source_manifest.v2.schema.json` | portable/physical source census |
| `rules/schemas/program_facts_capability_selection.v2.schema.json` | explicit `NOT_IMPLEMENTED`/host dispositions |
| `rules/schemas/program_facts_evm_build_plan.v2.schema.json` | input-only EVM build-plan v2; no later authority fields |
| `rules/schemas/program_facts_provider_registry.v2.schema.json` | exact EVM plus seven-placeholder provider registry |
| `rules/schemas/program_facts_host_tool_manifest.v1.schema.json` | exact host executable/transitive closure |
| `rules/schemas/program_facts_host_containment_evidence.v1.schema.json` | exact launch/terminal containment evidence |
| `rules/schemas/program_facts_evm_expected_wtx_children.v2.schema.json` | complete input-derived child roster with allocated ordinals/paths |
| `rules/schemas/program_facts_execution_authority.v2.schema.json` | sorted-child execution authority |
| `rules/schemas/program_facts_wtx_attempt_arm.v2.schema.json` | later-bound expected-child/authority attempt arm |
| `rules/schemas/program_facts_wtx_attempt_completion.v2.schema.json` | authenticated successful terminal |
| `rules/schemas/program_facts_wtx_attempt_debt.v2.schema.json` | authenticated debt terminal |
| `rules/schemas/program_facts_wtx_raw_cas_manifest.v2.schema.json` | exact raw-evidence CAS expansion |
| `rules/schemas/program_facts_contribution_set.v1.schema.json` | fixed-path aggregate of normalized private contributions |
| `rules/schemas/program_facts_composition_authority.v1.schema.json` | complete fixed-path composition authority |
| `rules/schemas/program_facts_payload_body.v1.schema.json` | pre-generation semantic payload body |
| `rules/schemas/program_facts_debt_body.v1.schema.json` | pre-generation semantic debt body |
| `rules/schemas/program_facts_runner_request.v1.schema.json` | one native runner request |
| `rules/schemas/program_facts_runner_result.v1.schema.json` | typed runner result, no public authority |
| `rules/schemas/program_facts_runner_receipt.v1.schema.json` | private control trace |
| `rules/schemas/program_facts_replay_receipt.v1.schema.json` | private replay trace |
| `rules/schemas/program_facts_public_generation.v2.schema.json` | immutable v3 output manifest |
| `rules/schemas/program_facts_publication_arm.v2.schema.json` | closed-receipt publication arm |
| `rules/schemas/program_facts_active_head.v1.schema.json` | sole authoritative ArtifactLedger active-head postimage |
| `rules/schemas/program_facts_active_selection.v1.schema.json` | non-authoritative ACTIVE projection |
| `rules/schemas/mechanical_program_facts.v3.schema.json` | v3 payload |
| `rules/schemas/mechanical_program_facts_receipt.v3.schema.json` | v3 public authority envelope |
| `rules/schemas/mechanical_program_facts_debt.v3.schema.json` | v3 typed debt |

Every `$id` is `https://plamen.local/schemas/<filename>`. Every schema is Draft 2020-12, closed, uses section 3 limits, and includes its own conformance vectors. Existing v1 EVM build/raw/roster schemas may be reused only if their exact identity is pinned and their closed content satisfies this contract without mutation; otherwise a new version is required.

### 4.2 Private runtime paths

PhaseIO contracts name every path literally or by a predeclared ID; no glob is permitted:

```text
_program_facts/v3/control/seed_admission.v1.json
_program_facts/v3/inputs/checkpoint_capture.v1.json
_program_facts/v3/inputs/methodology_content_pack.v1.json
_program_facts/v3/inputs/source_manifest.v2.json
_program_facts/v3/inputs/capability_selection.v2.json
_program_facts/v3/inputs/evm_build_plan.v2.json
_program_facts/v3/inputs/expected_wtx_children.v2.json
_program_facts/v3/inputs/execution_authority.v2.json
_program_facts/v3/inputs/terminal_wtx_roster.v1.json
_program_facts/v3/inputs/execution_set.v1.json
_program_facts/v3/private/contribution_set.v1.json
_program_facts/v3/inputs/composition_authority.v1.json
_program_facts/v3/private/payload_body.v1.json
_program_facts/v3/private/debt_body.v1.json
_program_facts/v3/control/runner_receipt.v1.json
_program_facts/v3/control/replay_receipt.v1.json
.program_facts/v3/transactions/<arm_locator_id>/publication_arm.v2.json
.program_facts/v3/generations/<generation_id>/mechanical_program_facts.v3.json
.program_facts/v3/generations/<generation_id>/mechanical_program_facts_receipt.v3.json
.program_facts/v3/generations/<generation_id>/mechanical_program_facts_debt.v3.json
.program_facts/v3/generations/<generation_id>/generation_manifest.v2.json
.program_facts/v3/provenance_events/<provenance_event_id>/mechanical_program_facts_receipt.v3.json
.program_facts/v3/provenance_events/<provenance_event_id>/mechanical_program_facts_receipt.provenance_envelope.v1.json
.program_facts/v3/ACTIVE.v1.json
```

Dynamic IDs are derived before PhaseIO registers their exact paths. Generation/transaction directories and their files are immutable. ArtifactLedger's active-head row is the sole durable selection authority; `ACTIVE.v1.json` is a mutable, non-authoritative projection and is never a semantic fact/debt input.

## 5. Acyclic identity construction

### 5.1 Common identity rules

`H(x)=lowercase_hex(SHA-256(CJ(x)))`. Prefix IDs use the first 32 hex characters unless a full hash is required. Sets are duplicate-free arrays sorted by `CJ(element)`. Missing fields never become empty strings. Run-local IDs do not enter fact/debt semantic IDs.

### 5.2 Expected child, execution authority, and attempt

The old expected-child/execution-authority cycle is forbidden. Construction is exactly:

1. PF-20 writes only `_program_facts/v3/inputs/evm_build_plan.v2.json` under `program_facts_evm_build_plan.v2.schema.json`; the live/legacy `evm_build_plan.v1.json` is neither emitted nor consumed by this contract. Its `build_plan_id = pfbp- || H(build_plan_preimage)[0:32]`, where the preimage is exactly:

```text
domain                              const PROGRAM_FACTS_EVM_BUILD_PLAN_V2
snapshot_id                         pfss-id
source_manifest                     file_identity
source_authority_sha256             hex64
provider_registry                   file_identity
capability_selection                file_identity
provider_id                         const evm.slither.typed
capability_ids                      exact six IDs, sorted UTF-8
host_profile                        windows-amd64|linux-amd64
host_toolchain_manifest             file_identity
build_variants                      sorted nonempty build_variant rows
process_policy_sha256               hex64
resource_policy_sha256              hex64
network_policy_sha256               hex64
```

A build-variant row is exactly `{build_variant_id,compiler:tool_identity,compiler_settings_sha256,source_inputs:sorted unique [file_identity],transitive_dependencies:sorted unique [file_identity]}` and sorts by UTF-8 `build_variant_id`. The closed build-plan document contains exactly `{schema_version:plamen.program_facts_evm_build_plan.v2,build_plan_id,preimage,build_plan_body_sha256}`, where `preimage` is byte-semantically equal to the block above and `build_plan_body_sha256 = SHA-256(CJ(document without build_plan_body_sha256))`. The preimage/document MUST NOT contain `expected_child_id`, child ordinal/role/path, execution-authority ID/digest, attempt/launch ID/digest, WTx/publication path, generation/transaction ID, or any terminal/output identity. Any v1 plan, later-authority member, reordered row, or unequal same-ID body is `BUILD_PLAN_INVALID`.

2. For each planned child, freeze an input-only request digest over the provider request schema, source/build input file identities, provider/capability IDs, and build variant. Derive the child identity before any ordinal or output path exists:

```text
expected_child_id = pfec- || H({
  domain: PROGRAM_FACTS_EXPECTED_CHILD_V2,
  build_plan_id,
  child_role: EVM_SLITHER_PROVIDER,
  child_role_ordinal: 10,
  provider_id,
  sorted_capability_ids,
  build_variant_id,
  provider_request_digest,
  sorted_declared_input_file_identities
})[0:32]
```

The preimage MUST NOT contain `child_ordinal`, any input/output path, execution-authority ID, attempt ID, or launch digest. Duplicate expected-child IDs are blocking; they are not disambiguated by an ordinal.

3. Sort the complete unique planned-child set by `(expected_child_id, build_plan_id, provider_id, build_variant_id)` and allocate `child_ordinal` 0..N-1 in that order.
4. Derive paths only after ordinal assignment; paths MUST NOT feed back into expected-child identity and MUST NOT contain execution-authority IDs:

```text
_wtx/program_facts/v3/<build_plan_id>/<child_ordinal>-<expected_child_id>/attempt_arm.v2.json
_wtx/program_facts/v3/<build_plan_id>/<child_ordinal>-<expected_child_id>/attempt_completion.v2.json
_wtx/program_facts/v3/<build_plan_id>/<child_ordinal>-<expected_child_id>/attempt_debt.v2.json
_wtx/program_facts/v3/<build_plan_id>/<child_ordinal>-<expected_child_id>/raw_cas_manifest.v2.json
```

5. Serialize each roster row as `{expected_child_id, child_ordinal, build_plan_id, provider_id, build_variant_id, input_file_identities, arm_path, completion_path, debt_path, raw_cas_manifest_path}` under `program_facts_evm_expected_wtx_children.v2.schema.json`. That schema has no `execution_authority_id` or `execution_authority_digest` field.

6. Sort the complete roster by expected-child ID and derive:

```text
execution_authority_id = pfea- || H({
  domain: PROGRAM_FACTS_EXECUTION_AUTHORITY_V2,
  run_id, run_generation, snapshot_id,
  sorted_build_plan_ids,
  sorted_complete_child_roster,
  process_policy_digest,
  resource_policy_digest,
  network_policy_digest,
  host_toolchain_manifest_digest
})[0:32]
```

7. Each attempt binds both without feeding back:

```text
attempt_id = pfat- || H({
  domain: PROGRAM_FACTS_ATTEMPT_V2,
  execution_authority_id,
  expected_child_id,
  attempt_ordinal,
  launch_digest
})[0:32]
```

`launch_digest` is computed from typed argv, working-root token, environment/process/resource/network policies, and exact executable/input identities; it excludes expected-child, execution-authority, and attempt IDs. An attempt record with only one parent, a path containing a later ID, or a differently ordered roster is invalid.

The replacement schemas `program_facts_wtx_attempt_arm.v2.schema.json`, `program_facts_wtx_attempt_completion.v2.schema.json`, `program_facts_wtx_attempt_debt.v2.schema.json`, and `program_facts_wtx_raw_cas_manifest.v2.schema.json` bind both expected-child and execution-authority identities because they are created later. No child-planning schema or path requires a later execution-authority field.

### 5.3 Generation, transaction, receipt, arm, manifest, head, and projection

Before any public or publication ID, PF-60 constructs the closed `composition_semantic_preimage` containing exactly:

```text
semantic_contract      {specification_sha256,canonicalization_version,public_schema_ids:ordered exact payload/receipt/debt schema IDs,vocabulary_content_sha256,normalization_policy_content_sha256,provider_registry_semantic_sha256,phase_io_contract_profile_sha256}
run_semantics          {run_id,run_generation,snapshot_id,mode:SHADOW}
authority_semantics    {governance_semantics:{kind:SHADOW_SEMANTIC,seed_admission_id,seed_acceptance_content_sha256,spec_review_content_sha256,architecture_review_content_sha256,fixture_execution_authority_content_sha256_or_null},authority_ceiling,semantic_authority:ADDITIVE_PROPOSAL_ONLY,terminal_negative_authority:false,fixture_authority_id_or_null,fixture_authority_body_sha256_or_null,scope_body_sha256_or_null,scope_row_sha256_or_null,allowed_operations}
source_semantics       {checkpoint_content_sha256,content_pack_content_sha256,source_manifest_content_sha256,source_authority_sha256,root_tokens}
selection_semantics    {rows:exact capability-binding rows without selection file identity}
build_semantics        {build_variants:sorted unique [{build_variant_id,compiler_settings_sha256,source_input_content_sha256:sorted unique [hex64],transitive_dependency_content_sha256:sorted unique [hex64]}]}
environment_semantics  {host_profile,network_policy_sha256,resource_policy_sha256,process_policy_sha256}
execution_semantics    {child_results:sorted unique [{child_role,terminal_role:COMPLETION|DEBT,raw_content_sha256_or_null,contribution_semantic_ids:sorted unique [pfcs-id],debt_codes:sorted unique [public_debt_code]}]}
composition_semantics  {contribution_semantic_ids:sorted unique [pfcs-id],disagreement_ids:sorted unique [IdentifierV3],payload_body_sha256,debt_body_sha256,status:public_status}
publication_semantics  {prior_head_semantics_sha256,ordered_logical_outputs:exact [PAYLOAD,RECEIPT,DEBT],durability_policy}
replay_semantics       exact replay_semantic_binding: {outcome,semantic_source:{kind,payload_body_sha256_or_null,debt_body_sha256_or_null}}
```

`composition_semantic_digest = H({domain:"PROGRAM_FACTS_COMPOSITION_SEMANTIC_V1",preimage:composition_semantic_preimage})`. The object and every nested object are closed; arrays use the displayed order rules. Each content digest is over stable-read canonical semantic bytes after exact root-token substitution. `provider_registry_semantic_sha256` is SHA-256 of `{schema_version,release_state,ecosystems,providers:[{ecosystem,provider_id,implementation_state,capabilities,authority}]}` projected from the registry in its literal order; adapter module/file/symbol, tool-identity policy, and registry body/file digests are forbidden. `payload_body_sha256` and `debt_body_sha256` are the fixed PF-60 bodies before public headers. `prior_head_semantics_sha256` hashes only the closed head state tag, revision, prior semantic generation/transaction IDs, and prior semantic artifact IDs; it excludes the head body/file/ledger/provenance-event digests. `replay_semantics` is copied only from the exact provenance-free binding above; its two optional hashes are null or equal the already-bound PF-60 semantic-body hashes and can never be computed from a reuse key/component. The preimage MUST NOT contain a file identity for a build plan, compiler, tool, host manifest, containment receipt, expected child, execution authority, attempt, terminal, raw CAS, execution set, contribution set, composition authority, receipt, arm, manifest, ledger event, or provenance envelope; it also forbids `reuse_key_sha256`, a reuse component name/value hash, `replay_source_transaction_id_or_null`, and any full-provenance/body digest or derivative of a runtime, validator, release, build/toolchain/environment, WTx, resolved-PhaseIO, Ledger, or runtime/package identity.

Public semantic identities are derived exclusively from that one digest:

```text
generation_id       = "pfg-"  || H({domain:"PROGRAM_FACTS_PUBLIC_GENERATION_SEMANTIC_V3",composition_semantic_digest})[0:32]
transaction_id      = "pftx-" || H({domain:"PROGRAM_FACTS_PUBLIC_TRANSACTION_SEMANTIC_V4",composition_semantic_digest})[0:32]
payload_semantic_id = "pfps-" || H({domain:"PROGRAM_FACTS_PUBLIC_PAYLOAD_SEMANTIC_V1",composition_semantic_digest})[0:32]
debt_semantic_id    = "pfds-" || H({domain:"PROGRAM_FACTS_PUBLIC_DEBT_SEMANTIC_V1",composition_semantic_digest})[0:32]
receipt_semantic_id = "pfrs-" || H({domain:"PROGRAM_FACTS_PUBLIC_RECEIPT_SEMANTIC_V1",composition_semantic_digest})[0:32]
```

No second input is permitted in any of these five preimages. The public payload/debt headers and the semantic receipt projection contain the identical digest and corresponding IDs. Recomputing the digest from their semantic bodies MUST reproduce every ID before any full provenance is consulted.

Publication order is then exact and acyclic:

1. Derive the semantic digest and five IDs above.
2. Freeze the three physical output paths and manifest path under the semantic generation ID; paths do not feed any semantic/public ID.
3. Let `publication_attempt_ordinal` be the explicit uint32 in the PhaseIO request, initially 0 and incremented only by a new ledger-declared publication event. Derive `transaction_nonce = pfnc- || H({domain:PROGRAM_FACTS_TRANSACTION_NONCE_V1,run_id,run_generation,generation_id,publication_attempt_ordinal})[0:32]`; it is event provenance and never enters `transaction_id`.
4. Use the pre-freeze-created, contract-freeze-pinned `phase_io_contract_profile_sha256` already committed in the semantic digest. Derive `arm_locator_id = pfal- || H({domain:PROGRAM_FACTS_ARM_LOCATOR_V1,run_id,run_generation,generation_id,transaction_id,publication_attempt_ordinal,phase_io_contract_profile_sha256,prior_head_revision})[0:32]`. The exact arm path is `.program_facts/v3/transactions/<arm_locator_id>/publication_arm.v2.json`; locator/path are provenance-event identities, not semantic identity inputs.
5. PhaseIO expands the profile with the exact concrete PF-70 tuple, resolves/arms it, and computes `resolved_phase_io_contract_sha256`, `phase_io_launch_sha256`, and `expanded_input_set_sha256`; none feeds the semantic digest or five IDs.
6. Wrap the already-committed semantic payload/debt bodies with the semantic headers and verify their bytes/digests.
7. Construct the full actual receipt. It binds the semantic digest/IDs, the provenance-free replay outcome/source binding, and complete build/execution/composition/publication provenance, but contains no reuse key/component and no later arm/manifest/projection/ledger/provenance-envelope digest.
8. Close the full receipt bytes and compute its external file identity/full `receipt_id`.
9. Construct the provenance envelope/event defined in section 12.1.1, recomputing its full-provenance digest, the exclusive full reuse-key/component preimage, and all anti-substitution checks.
10. Construct the arm; it binds semantic IDs, the event-specific full receipt/envelope identities, event nonce/locator, and expected ledger-head prestate.
11. Construct the generation manifest; it binds semantic identities/bytes and, only for a newly materialized semantic generation, its first immutable receipt/arm/provenance event.
12. Construct ACTIVE from the proposed ledger postimage, commit immutable semantic files plus the append-only provenance event and atomic active-head postimage, then materialize ACTIVE as a non-authoritative projection.

The permitted digest graph is:

```text
preimplementation semantic contract/inputs/results -> composition_semantic_digest
-> generation/transaction/payload/debt/receipt semantic IDs
-> concrete PF-70 path tuple + event nonce/arm locator -> resolved PhaseIO contract/launch/expanded-input digests
-> semantic payload/debt bytes + provenance-free replay outcome/source -> full actual receipt
-> exact full reuse binding/key/components + full execution provenance -> composition_provenance_digest + provenance envelope/event -> arm -> generation manifest
-> atomic ledger active-head postimage -> ACTIVE projection materialization
```

No arrow may point backward. A reuse key/component, replay source transaction/event identity, build-plan/execution-set/composition-authority/receipt/envelope identity, or full provenance digest can never feed `composition_semantic_digest` or any of the five semantic/public ID preimages, directly or through a content/component hash. A resolved PhaseIO contract digest can never be used as a semantic or dynamic-path ID preimage. The full receipt is authoritative only after its provenance event and ledger-head validation; it does not contain later arm, manifest, projection, ledger, or envelope digests. ACTIVE is never an authority node.

## 6. Sub-stages and exact ownership

### 6.1 PhaseIO contract keys

The G3-00 architecture/ownership contract MUST specify, and G3-06 PhaseIO code MUST register, the existing six-argument `scripts/phase_io_contracts.py::canonical_work_unit_key(pipeline, mode, ecosystem, backend, phase, work_unit_id)` without changing order or arity. The only valid pipeline/ecosystem pairs are the existing resolver domain `SC={evm,solana,soroban,aptos,sui}` and `L1={go,rust,daml}`. `mode` is the actual `light`, `core`, or `thorough` audit mode, `backend` is const `native`, `phase` is const `recon`, and `work_unit_id` is one row below. Thus every canonical key is exactly `<pipeline>/<mode>/<ecosystem>/native/recon/<work_unit_id>`:

| Stage | Work-unit ID | SC | L1 | Principal actor |
|---|---|---:|---:|---|
| PF-00 | `program_facts_seed_admission_v1` | yes | yes | PhaseIO driver |
| PF-10 | `program_facts_checkpoint_capture_v3` | yes | yes | PhaseIO driver |
| PF-10 | `program_facts_methodology_capture_v3` | yes | yes | PhaseIO driver |
| PF-20 | `program_facts_plan_v3` | yes | yes | PhaseIO driver/provider planner |
| PF-30 | `program_facts_execution_authority_v3` | EVM only | no launch on L1 | PhaseIO driver |
| PF-40 | `program_facts_execute_v3` | EVM only | no launch on L1 | WorkerTransaction |
| PF-50 | `program_facts_reconcile_v3` | yes | yes | PhaseIO driver |
| PF-60 | `program_facts_compose_v3` | yes | yes | PhaseIO driver/native composer |
| PF-70 | `program_facts_publication_prepare_v3` | yes | yes | PhaseIO driver |
| PF-80 | `program_facts_publish_v3` | yes | yes | PhaseIO invokes ArtifactLedger CAS |
| PF-90 | `program_facts_replay_v3` | yes | yes | PhaseIO loader; private receipt only |

Exact examples are `sc/core/evm/native/recon/program_facts_publish_v3` and `l1/thorough/rust/native/recon/program_facts_publish_v3`; the latter is a typed no-launch/debt path, not Rust execution. `driver` is an ArtifactSpec/ledger actor value, never a seventh key component. At G3-00 the contract review enumerates all `(5 SC + 3 L1) * 3 modes * 11 work units = 264` unique valid keys and proves each equals the current six-argument function result; it also rejects all `(8 invalid pipeline/ecosystem pairs * 3 modes) = 24` invalid pair-mode cells before work-unit expansion. Duplicate, reordered, five-part, seven-part, or invalid-pair keys fail `GOVERNANCE_IDENTITY_MISMATCH`. The pre-freeze matrix is `review_fixtures/program_facts_runtime_gate3/phase_io/canonical_work_unit_key_vectors.v1.json` under `rules/schemas/program_facts_phase_io_interface_vector.v1.schema.json`; in addition to the key/actor vectors it contains exactly one closed static profile and digest for each of the 264 valid keys, sorted by canonical key, and no resolved path/run/generation/transaction/launch/expanded-input member. The synthetic fixture governance pins this matrix before expected bytes; the contract freeze later pins the unchanged matrix.

Each work unit has a static profile digest over its closed templates and policies in that pre-freeze matrix, later pinned unchanged by the contract freeze. A per-run `resolved_phase_io_contract_sha256 = SHA-256(CJ(resolved closed contract definition with exact concrete inputs/outputs))` exists only after all path IDs are independently derived. The launch digest then binds that resolved digest. Missing profile/resolver identities block implementation; missing or mismatched resolved/launch digests block the run. Neither is permission to use the current v1/v2 bake contract.

The PhaseIO amendment MUST replace, not alias, any old `program_facts_bake`/`program_facts_bake_v2` path for v3. Old units remain version-scoped and cannot write v3 paths. The amendment must name every input/output, schema ID, atomic actor, publication operation, and ArtifactLedger operation.

### 6.2 Stage I/O and failure boundary

| Stage | Exact inputs | Exact outputs | Failure class |
|---|---|---|---|
| PF-00 | compact seed admission/review, contract freeze, accepted spec/public-v3 reviews; never the 99 MB seed | `_program_facts/v3/control/seed_admission.v1.json` | blocking |
| PF-10 | checkpoint request, explicit root mappings, runtime/methodology closure | checkpoint, content pack, source manifest | integrity blocking; explicitly optional unreadable root may become debt |
| PF-20 | source/content identities, v2 capability registry, host/tool manifest | capability selection v2 and input-only EVM build plan v2 | ambiguous/invalid blocking; unsupported/unavailable becomes debt |
| PF-30 | build plan, exact child paths/roles, process/resource/network policies | expected-child roster, execution authority | blocking |
| PF-40 | one serialized request per expected child | arm plus exactly one completion/debt and raw-CAS manifest | worker failure is haltless only after valid terminal debt |
| PF-50 | exact roster and predeclared terminal paths | terminal roster and execution set | missing/extra/alias/drift blocking |
| PF-60 | execution set, raw evidence, parser/vocabulary pins | fixed aggregate contribution set, composition authority, payload/debt semantic bodies | integrity blocking; truthful gaps/disagreement become debt |
| PF-70 | semantic bodies, exact authoritative-head prestate, frozen PhaseIO profile, independently derived generation/locator/transaction IDs | resolved/armed concrete contract plus exact staging files in section 6.5 only | blocking |
| PF-80 | validated PF-70 staging set, provenance envelope/event, and expected ledger-head prestate | new semantic-generation files only if absent/byte-identical, one append-only provenance event, atomic ledger active-head postimage, then ACTIVE projection | blocking; prior ledger head remains authoritative |
| PF-90 | exact ledger active head, immutable generation, selected provenance event/envelope, optional ACTIVE projection, current reuse request | in-memory typed load, private key-free replay receipt, and mandatory append-only replay provenance event/envelope when an active generation is compared; repaired projection if needed | corrupt authoritative generation blocking; absent/disabled head is legacy/no-sidecar |

No later stage consumes a planned output. It consumes only a durably committed, reopened, schema-valid predecessor.

PF-60 has no dynamic output paths. Before reading or parsing provider raw bytes, PhaseIO resolves and arms the exact fixed four-output tuple `contribution_set.v1.json`, `composition_authority.v1.json`, `payload_body.v1.json`, and `debt_body.v1.json` shown in section 4.2. The closed aggregate contains exactly `{schema_version:plamen.program_facts_contribution_set.v1,run_id,snapshot_id,execution_set:file_identity,parser_identities:sorted[file_identity],contributions:sorted contribution rows,contribution_set_body_sha256}`. Each contribution row is exactly `{contribution_id,contribution_semantic_id,provider_id,capability_id,build_variant_id,raw_evidence:sorted[file_identity],raw_content_sha256:sorted unique [hex64],nodes,occurrences,facts,completeness_scopes,debts,contribution_semantic_body_sha256,contribution_body_sha256}`. Its closed semantic body is exactly `{provider_id,capability_id,build_variant_id,raw_content_sha256,nodes,occurrences,facts,completeness_scopes,debts}` after every public evidence/attestation reference has been converted to the section-2 semantic evidence ID; `contribution_semantic_body_sha256 = SHA-256(CJ(semantic body))` and `contribution_semantic_id = "pfcs-" || H({domain:"PROGRAM_FACTS_CONTRIBUTION_SEMANTIC_V1",semantic_body})[0:32]`. The full `contribution_id = "pfc-" || H({domain:"PROGRAM_FACTS_CONTRIBUTION_PROVENANCE_V2",body_without_contribution_id_or_contribution_body_sha256})[0:32]` additionally commits every raw-evidence file identity in that row; the enclosing aggregate and composition authority separately commit the execution-set and parser provenance. Rows sort by `(contribution_semantic_id,contribution_id)`. Equal semantic ID with unequal semantic body or equal full ID with unequal full body is blocking.

Parsing happens only inside that already-armed work unit. PhaseIO writes the single aggregate after normalization; both ID kinds are data members, never filenames or late output declarations. Public facts/scopes/disagreements/debts may contain only `pfcs-`/`pfse-` semantic references; `pfc-`, WTx, execution-set, terminal, raw-CAS, tool, compiler, and containment identities are provenance-only.

The closed `composition_authority.v1.json` contains exactly `{schema_version:plamen.program_facts_composition_authority.v1,composition_semantic_digest,composition_semantic_preimage_sha256,build_plans:sorted unique [{identity:file_identity,body_sha256}],execution_set:{identity:file_identity,body_sha256},terminal_roster:{identity:file_identity,body_sha256},contribution_set:{identity:file_identity,body_sha256},composition_semantic_ids:sorted unique [pfcs-id],composition_provenance_ids:sorted unique [pfc-id],parser_identities:sorted unique [file_identity],payload_body:{identity:file_identity,body_sha256},debt_body:{identity:file_identity,body_sha256},composition_authority_body_sha256}`. `composition_semantic_preimage_sha256 = SHA-256(CJ(the exact section-5.3 preimage))`; the body digest omits only itself. The authority proves the exact full build/execution/terminal/raw/parser/contribution lineage for the already-computed semantic commitment but is not itself semantic authority and never feeds that commitment or a public ID. The fixed payload/debt body files omit run/generation/publication headers and all full provenance identities and are wrapped into public v3 files only after the section-5 semantic IDs and concrete PF-70 contract are armed.

### 6.3 WorkerTransaction boundary

Each launched child receives only its exact expected-child record, execution-authority ID, build plan, input file identities, output paths, launch identity, and policies. It writes only its ordinal WTx directory. It MUST NOT write source, scratchpad root, public generation/transaction directories, ACTIVE projection, ledger, registry, schemas, or another child directory.

Every launched child has one `ATTEMPT_ARM` and exactly one terminal `ATTEMPT_COMPLETION` or `ATTEMPT_DEBT`. A valid completion/debt binds its attempt, expected child, execution authority, build plan, and raw-CAS manifest. `NOT_IMPLEMENTED` rows have no expected child and no WTx directory. Process exit without a worker-authored terminal record is unconditionally blocking `WTX_TERMINAL_INVALID`; PhaseIO may record a non-authoritative operational incident outside the WTx directory, but it cannot synthesize, replace, or accept a missing child terminal.

### 6.4 ArtifactLedger and lock order

ArtifactLedger is the sole durable active-head authority and durable recorder. It never discovers files or chooses semantic truth. The lock order is:

```text
audit-run
-> program-facts-generation
-> PhaseIO work-unit
-> WTx children sorted by expected_child_id
-> ArtifactLedger compare-and-swap
```

Locks release in reverse. No later lock may acquire an earlier lock. Abandoned lock recovery requires owner-death and exact-prestate proof; elapsed time is insufficient.

### 6.5 Output-level RACI, staging, and exclusive operations

Responsibility components are `RuntimeDriver`, `PhaseIO`, `WorkerTransaction`, and `ArtifactLedger`; a composite name is never an owner. The existing global `ArtifactSpec.writer` and ArtifactLedger `actor` vocabulary remains exactly `MODEL|DRIVER`; Gate 3 uses only `DRIVER`. `WorkerTransaction` is a driver-owned isolation component, not a third ledger actor: its v2 arm/completion/debt/raw-CAS objects contain `producer_component:WORKER_TRANSACTION`, while their PhaseIO ArtifactSpecs use `artifact_class:DRIVER_GENERATED, writer:DRIVER`, and their ledger commit is authenticated as `actor:DRIVER`. PhaseIO-produced files likewise use `writer:DRIVER`; ArtifactLedger is the internal executor of its active-head operation but records the authenticated caller actor `DRIVER`. No `WORKER_TRANSACTION`, `PHASE_IO`, or `ARTIFACT_LEDGER` token is passed to the current actor enum.

`R` below is the sole physical byte writer/operation executor component, `A` the sole acceptance authority component, `C` a required validator/caller, and `I` an observer:

| Output/operation | RuntimeDriver | PhaseIO | WorkerTransaction | ArtifactLedger |
|---|---|---|---|---|
| PF-00/PF-10/PF-20/PF-30 control artifacts | C | R/A | I | I |
| PF-40 arm/completion/debt/raw-CAS staging | C | A | R | I |
| PF-50/PF-60 reconciliation/composition artifacts | C | R/A | I | I |
| PF-70 publication staging bytes | C | R/A | I | I |
| PF-80 semantic-generation files plus append-only provenance event | I | R/A | I | C |
| PF-80 atomic active-head postimage | I | C | I | R/A |
| `ACTIVE.v1.json` projection | I | R/A | I | C |
| PF-90 replay receipt/append-only replay event/projection repair | C | R/A | I | C |

PF-70 may write only:

```text
_program_facts/v3/publication_staging/<transaction_id>/transaction/<arm_locator_id>/publication_arm.v2.json
_program_facts/v3/publication_staging/<transaction_id>/generation/<generation_id>/mechanical_program_facts.v3.json
_program_facts/v3/publication_staging/<transaction_id>/generation/<generation_id>/mechanical_program_facts_receipt.v3.json
_program_facts/v3/publication_staging/<transaction_id>/generation/<generation_id>/mechanical_program_facts_debt.v3.json
_program_facts/v3/publication_staging/<transaction_id>/generation/<generation_id>/generation_manifest.v2.json
_program_facts/v3/publication_staging/<transaction_id>/provenance_event/<arm_locator_id>/mechanical_program_facts_receipt.provenance_envelope.v1.json
_program_facts/v3/publication_staging/<transaction_id>/ACTIVE.v1.json.candidate
```

PF-70 never writes `.program_facts/v3/`. PF-80 alone performs, in order, `MATERIALIZE_IMMUTABLE_V3` for the five final files, `COMMIT_ACTIVE_HEAD_CAS_V1` through ArtifactLedger, then `MATERIALIZE_ACTIVE_PROJECTION_V1`. WorkerTransaction and RuntimeDriver cannot invoke those operations. PhaseIO cannot synthesize or amend an ArtifactLedger postimage; ArtifactLedger cannot write generation or projection files.

The same PhaseIO interface vector also contains positive `DRIVER` rows for every PF output and negative `MODEL`, `WORKER_TRANSACTION`, `PHASE_IO`, and `ARTIFACT_LEDGER` rows for every Program Facts output. G3-06 implementation must preserve all preexisting canonical-key and `MODEL|DRIVER` actor vectors byte-for-byte. A future distinct worker actor would require a versioned global PhaseIO/ArtifactLedger actor-schema migration plus full registered-contract blast-radius review; this Gate-3 contract neither requires nor permits that migration.

## 7. Crash-safe generation-indirected publication

### 7.1 Immutable physical layout and logical mapping

The three v3 public names are virtual logical identities. The ArtifactLedger active head maps each to one immutable physical file under exactly one generation:

```text
.program_facts/v3/generations/<pfg-id>/mechanical_program_facts.v3.json
.program_facts/v3/generations/<pfg-id>/mechanical_program_facts_receipt.v3.json
.program_facts/v3/generations/<pfg-id>/mechanical_program_facts_debt.v3.json
```

The same generation contains `generation_manifest.v2.json`. Its transaction arm is stored under `.program_facts/v3/transactions/<pfal-id>/publication_arm.v2.json`. No root-level fixed-name copy is authoritative or written. `ACTIVE.v1.json` is a cache/projection of the ledger head, not a selector authority.

### 7.2 Five immutable files, atomic ledger head, and ACTIVE projection

PF-80 first probes ArtifactLedger by semantic generation ID, never by filesystem discovery. For a generation ID not yet recorded, it materializes the existing five immutable final files from PF-70 staging—event arm, payload, first full receipt, debt, and generation manifest—plus the mandatory provenance envelope at its event path. For an already-recorded byte-identical semantic generation, it rewrites none of those generation files and materializes only the new event arm, event-specific full-receipt copy beneath `<execution-or-production-root>/provenance_events/<provenance_event_id>/`, and provenance envelope. PhaseIO stable-reads each candidate twice, validates schemas/cross-bindings, fsyncs every new file, and fsyncs each newly created directory. Their existence is not active authority.

For activation, PhaseIO submits one `COMMIT_ACTIVE_HEAD_CAS_V1` request to ArtifactLedger. The expected preimage is the exact prior-head tagged union. The atomic ledger transaction commits any newly created immutable generation rows, exactly one append-only provenance-event row, its arm/full-receipt/envelope rows, and this closed postimage. A disable transition commits no generation/arm/manifest/output/provenance-event row and uses the separate preimage below.

Immutable collision semantics are exact. ArtifactLedger stores `composition_semantic_digest`, the complete canonical semantic preimage bytes, five derived IDs, payload/debt bytes, semantic projection hash, and generation manifest for each semantic generation. Equal digest or any equal semantic ID is reusable only when the stored semantic preimage, payload body/public bytes, debt body/public bytes, and semantic projection bytes are all byte-identical; a same digest/ID with any unequal semantic byte is `COMPOSITION_COLLISION` and commits nothing. Byte-identical semantic generations share the five semantic IDs and immutable generation files, regardless of later full provenance.

Every successful execution/publication and every PF-90 comparison against an active generation has a `provenance_event_id` and append-only event row distinct from semantic identity. Unequal `composition_provenance_digest`, full receipt bytes, execution-set/composition-authority digest, provider-attempt roster, full reuse binding/key/component preimage, or event ordinal must derive a different event ID and new immutable event paths. An already-recorded event ID is idempotently acknowledged only when the event preimage, arm, full receipt, envelope, and ledger row are byte-identical; equal event ID with unequal bytes is `COMPOSITION_COLLISION`. No event may replace, truncate, relink, or overwrite an earlier event or generation file. A later publication event may advance the active-head revision and selected provenance event while retaining the same semantic generation/transaction IDs and logical payload/debt/receipt semantic identities; a replay-only event appends evidence without changing the active-head postimage or any semantic/public ID.

```text
schema_version                 const plamen.program_facts_active_head.v1
run_id
run_generation
head_revision                  prior revision + 1; first revision is 1
state                          ACTIVE_V3|DISABLED_LEGACY
head_payload                   exactly one state-tagged payload below
selector_projection            complete ACTIVE projection object
selector_body_sha256           SHA-256(CJ(selector_projection without body digest))
prior_head                     exact closed prior-head tagged union
head_body_sha256               body digest
```

For `state=ACTIVE_V3`, `head_payload` is exactly `{kind:ACTIVE_V3,composition_semantic_digest,generation_id,transaction_id,payload_semantic_id,debt_semantic_id,receipt_semantic_id,selected_provenance_event_id,selected_provenance_envelope:file_identity,composition_provenance_digest,arm:file_identity,generation_manifest:file_identity,logical_outputs:ordered three bindings,phase_io_contract_profile_sha256,resolved_phase_io_contract_sha256,phase_io_launch_sha256,expanded_input_set_sha256}`. The semantic digest/IDs select semantic bytes; the event/envelope/provenance digest select the independently validated execution that caused this activation and never alter those semantic IDs. For `state=DISABLED_LEGACY`, `head_payload` is exactly `{kind:DISABLED_LEGACY,disabled_transition_id,reason_code,governance:disable_governance,phase_io_contract_profile_sha256,resolved_phase_io_contract_sha256,phase_io_launch_sha256,expanded_input_set_sha256,logical_outputs:const []}`. `disable_governance` is the closed union `{kind:RUNTIME,flag_contract:file_identity,contract_freeze:file_identity,release_freeze:file_identity}` or `{kind:FIXTURE_PRE_RELEASE,flag_contract:file_identity,fixture_execution_authority:file_identity}`. The fixture branch is legal only for an execution-scope row containing `WRITE_DISABLED_LEGACY`, below that row's execution root, and cannot update a production-workspace head; runtime disable requires the reviewed non-null contract/release identities. Generation, transaction, arm, manifest, composition, provenance-event, and physical-output fields are forbidden in the disabled branch.

The disable identity is derived before its resolved contract and contains no generation/publication path requirement:

```text
disabled_transition_id = pfdt- || H({
  domain: PROGRAM_FACTS_DISABLE_LEGACY_TRANSITION_V1,
  run_id, run_generation,
  next_head_revision,
  prior_head,
  reason_code,
  governance,
  phase_io_contract_profile_sha256
})[0:32]
```

`reason_code` is exactly `ROLLBACK_TRIGGER`, `OPERATOR_REQUEST`, or `CUTOVER_REVOKED`; `governance` is byte-semantically equal to the selected tagged branch above. After the ID exists, PhaseIO resolves/arms the fixed disable contract and binds its resolved/launch/expanded-input digests in the disabled payload. The prior-head union is exactly `{kind:ABSENT,head_revision:0}`, `{kind:PRESENT_ACTIVE,head_revision:uint64>=1,head_body_sha256,generation_id,transaction_id}`, or `{kind:PRESENT_DISABLED,head_revision:uint64>=1,head_body_sha256,disabled_transition_id}`. A re-enable activation consumes `PRESENT_DISABLED`; a repeated disable consumes `PRESENT_DISABLED` and derives a new revision/ID. ArtifactLedger compares the current head branch/revision/body digest to `prior_head` and atomically appends the corresponding activation or disable transition plus replaces its logical active-head record. Failure commits neither. Revision strictly increases; ABA, decrement, same-revision substitution, and cross-run head reuse are rejected.

The closed `selector_projection`/`ACTIVE.v1.json` contains exactly:

```text
schema_version                 const plamen.program_facts_active_selection.v1
head_revision                  same as committed ledger head
run_id
run_generation
state                          ACTIVE_V3|DISABLED_LEGACY
head_payload                   exact copy of committed state-tagged head payload
prior_head                     exact prior-head object
selector_body_sha256           body digest; exactly the digest committed in the ledger postimage
```

The projection never contains a ledger-record digest and cannot feed the ledger postimage cycle. Its state, payload, prior head, revision, run, and generation must equal the ledger postimage exactly.

Only after reopening the committed ledger head does PhaseIO materialize the already-committed projection. The temporary filename is `.program_facts/v3/.ACTIVE.v1.json.tmp.<operation_id>`, where `operation_id` is the selected provenance-event ID for `ACTIVE_V3` or the disabled-transition ID, and is never authoritative. PhaseIO flushes it, performs same-directory atomic replacement, and fsyncs the directory. Windows uses `ReplaceFileW` when prior projection exists and `MoveFileExW(MOVEFILE_WRITE_THROUGH)` when absent; Linux uses `renameat2` after the held head lock and then directory `fsync`. Projection failure leaves the new ledger head authoritative and returns `ACTIVE_PROJECTION_REPAIR_REQUIRED`, not rollback of the committed head.

### 7.3 Loader reopen algorithm

The loader:

1. takes a shared run/generation lock and reads the ArtifactLedger active head by exact run key;
2. stable-validates the head, its atomic transaction rows, monotonic revision chain, and body digest;
3. if head is absent or `DISABLED_LEGACY`, returns separately validated `LEGACY_V1` or `NO_SIDECAR` without consulting ACTIVE;
4. for `ACTIVE_V3`, stable-reads the exact manifest, selected provenance event/envelope/full receipt, and arm named by the head, never a directory listing;
5. independently recomputes the semantic digest/five IDs from semantic bytes, replays the complete full-provenance digest/event ID, and validates the acyclic graph in section 5.3;
6. opens the three exact logical physical files plus selected event files with no-follow semantics, stable-reads twice, and checks head/manifest/arm/semantic/provenance identities;
7. validates all three public schemas, the semantic-projection equality, the provenance envelope/execution-set membership, and every cross-binding;
8. optionally stable-reads `ACTIVE.v1.json`; if missing, malformed, or unequal to the committed projection, asks PhaseIO to rematerialize the exact ledger-stored projection and reopens it; and
9. returns the logical mapping only after authoritative files validate. ACTIVE never changes the chosen generation.

Any ledger-head-selected file absence, mutation, path escape, ledger mismatch, or cross-generation mix is `INTEGRITY_BLOCKED`. The loader never falls back from a corrupt authoritative v3 head to v1. ACTIVE-only corruption is `ACTIVE_PROJECTION_REPAIR_REQUIRED`; failure to repair keeps audit semantics on the already-required shadow legacy path and exposes no v3 payload.

### 7.4 Recovery matrix

| Crash point | Recovery |
|---|---|
| Before arm/generation/event durable | delete only transaction-owned staging after proof; prior ledger head remains |
| After some immutable generation/event files | quarantine generation/transaction/event; never complete by discovery |
| After every required generation/event file, before ledger | quarantine; recomposition/republication required |
| During atomic ledger CAS | ledger exposes complete old or complete new head; reopen determines which |
| After ledger, before ACTIVE projection | new head is authoritative; regenerate exact projection from ledger postimage |
| During ACTIVE temp write/replace | projection ignored/repaired from ledger; head unchanged |
| After projection, before acknowledgement | reopen head and projection; exact transaction is idempotently successful |
| ACTIVE names a generation different from head | ignore/repair ACTIVE; never select its generation |
| Ledger head names invalid generation | integrity block; do not auto-adopt prior/newest generation |

Garbage collection may remove only non-head generations after proving no current/historical ledger or provenance-event reference and after the retention window frozen in the release freeze. Provenance-event rows and their receipt/envelope/arm files are append-only and are not garbage-collected in Gate 3. Directory mtime, lexical newest, ACTIVE contents, and content similarity never confer authority.

## 8. Deterministic runner and replay

### 8.1 Runner order

`run_program_facts_gate3_v1` executes exactly:

1. Validate the accepted spec/architecture receipts, compact seed admission/review, and contract-freeze/release-freeze identities appropriate to the lifecycle; never open the construction seed.
2. Resolve roots without following unapproved symlink/reparse transitions.
3. Capture checkpoint before source content and build the explicit runtime/methodology content pack.
4. Stable-read and census source/build inputs; create root-token mappings.
5. Select the closed ecosystem/capability/host cells.
6. For EVM on eligible hosts, inventory exact Python/helper/Slither/solc/tool dependencies and freeze build plan. For every other cell, create selection debt without a launch.
7. Derive expected children, then execution authority, then attempts as section 5.2.
8. Arm all declared children; launch in expected-child order. Scheduling may overlap only if a future contract-freeze version changes concurrency from 1; completion order never affects output.
9. Reconcile the exact terminal roster and manifest-expanded execution set without directory discovery.
10. Parse hostile raw data with pinned native parsers, validate contributions, preserve disagreements, and create typed debt.
11. Sort contributions by `(contribution_semantic_id,contribution_id)`; compose provenance-free payload/debt bodies once; construct the exact semantic preimage/digest; reject equal-semantic-ID/unequal-semantic-body and equal-full-ID/unequal-full-body collisions.
12. Derive all five semantic/public IDs exclusively from the semantic digest, then create the full receipt, provenance envelope/event, arm, and manifest in section 5.3 order; full build/execution/composition provenance cannot feed backward.
13. Materialize the immutable files, commit the ArtifactLedger active-head CAS, then materialize the ACTIVE projection as section 7 requires.
14. Reopen via the loader before returning a typed runner result.

Locale, timezone, filesystem enumeration, PID, wall clock, process scheduling, provider stdout order, Python dictionary order, and wrapper/model identity do not select facts/debt. Time and wrapper identity are isolated to declared nonsemantic receipt fields.

### 8.2 Replay and reuse

The full input-derived reuse material exists only as `replay_provenance` in the section-12.1.1 postimplementation envelope/event. Its closed `reuse_key_preimage` contains exactly:

```text
schema_identities                 sorted unique [public/private schema file_identity]
runtime_validator_identities      sorted unique [runtime/validator module file_identity]
governance_identities             {kind:RUNTIME,specification,specification_review,architecture,architecture_review,contract_freeze,contract_freeze_review,release_freeze,release_freeze_review} | {kind:FIXTURE_PRE_RELEASE,specification,specification_review,architecture,architecture_review,contract_freeze,contract_freeze_review,fixture_execution_authority,fixture_execution_authority_review}; every member after kind is file_identity
seed_source_identities            {seed_admission,checkpoint,source_manifest,content_pack}; every member is file_identity
provider_selection_identities     {provider_registry,capability_selection,host_selection}; every member is file_identity
build_toolchain_identities        {build_plans:sorted unique [file_identity],toolchain:sorted unique [file_identity],transitive_dependencies:sorted unique [file_identity]}
environment_policy_identities     {environment_authority:file_identity,host_tool_manifest_or_null:file_identity|null,containment_evidence_or_null:file_identity|null,network_policy:file_identity,resource_policy:file_identity,process_policy:file_identity}
semantic_normalization_identities {parsers:sorted unique [file_identity],vocabulary:file_identity,normalization_policy:file_identity}
protocol_identities               {phase_io_contract_profiles:sorted unique [file_identity],worker_transaction_protocol:file_identity,artifact_ledger_protocol:file_identity}
runtime_package_identities        {runtime_closure:file_identity,package_closure:file_identity}
mode                              const SHADOW
```

`reuse_components` is the sorted exact eleven-row array `{name,value_sha256}` with one name equal to each displayed top-level member and `value_sha256 = SHA-256(CJ(reuse_key_preimage[name]))`. `reuse_key_sha256 = H({domain:"PROGRAM_FACTS_REUSE_KEY_PROVENANCE_V1",preimage:reuse_key_preimage})`. The full `reuse_binding` is exactly `{reuse_key_sha256,components:reuse_components,outcome:BUILT|REUSED|REBUILD_REQUIRED,replay_source_transaction_id_or_null}`. It excludes run/attempt IDs, expected-child IDs, terminal results, contributions, composition outputs, prospective generation/transaction IDs, concrete dynamic paths, per-run resolved PhaseIO contract/launch digests, ACTIVE projection, and ledger row IDs. Those resolved/output identities remain separate full-provenance cross-checks, never cache-key or semantic inputs.

Replay resolves the exact ArtifactLedger active head, validates section 7.3 and its selected source provenance envelope, constructs the closed key preimage from the current request, recomputes all eleven components and the key, and compares every component. Equality returns the exact stored payload/debt bytes; inequality returns `REBUILD_REQUIRED` plus the sorted unequal component names. Partial reuse is forbidden. Whenever an active generation is compared, PF-90 creates a new event envelope whose `replay_provenance` contains that complete preimage/binding, the source event/envelope/full execution binding, and the private replay-receipt identity; ArtifactLedger appends the event row without rewriting generation/public files, changing the source generation's canonical semantic preimage, or changing the active-head postimage. The replay event retains the source generation's semantic digest/IDs and its original `replay_semantic_binding`; the current `REUSED|REBUILD_REQUIRED` decision is provenance-only. The private replay receipt contains exactly `{outcome:REUSED|REBUILD_REQUIRED,compared_semantic_ids:{generation_id,transaction_id,payload_semantic_id,debt_semantic_id,receipt_semantic_id},provenance_event_id,receipt_body_sha256}`; reuse keys and component names/hashes are forbidden there. An exact requested transaction not named by the active head is not replay authority.

Legacy Claude and future Codex wrappers serialize the same native request and call the same runner symbol. Neither an LLM response, prompt, model alias, reasoning level, plugin, nested agent, nor backend transport may enter semantic inputs, provider selection, normalization, ordering, or reuse. For the same request, native/Claude/Codex payload and debt bytes are identical; receipt differences are confined to `nonsemantic_transport`.

## 9. Ecosystem, host, toolchain, and package decisions

### 9.1 Ecosystem dispositions

The closed roster is `EVM`, `GO`, `RUST`, `SOLANA`, `SOROBAN`, `APTOS`, `SUI`, `DAML`. Gate 3 implements EVM only. Every requested non-EVM capability has status `NOT_IMPLEMENTED`, debt code `PROVIDER_NOT_IMPLEMENTED`, no expected child, and no provider process. Their implementation is Gate 16. Absence never proves a negative fact. [D03]

EVM capabilities are exactly the six current registry IDs: `evm.slither.calls.v1`, `evm.slither.cfg.v1`, `evm.slither.dependencies.v1`, `evm.slither.sinks.v1`, `evm.slither.state.v1`, and `evm.slither.structure.v1`. The immutable v2 registry retains their additive-only/terminal-negative-false ceilings and remains production-execution-disabled. Its only pre-release execution is the exact reviewed section-12.1 G3-09 fixture-authority baseline roster beneath isolated fixture execution roots; the release freeze and final cutover receipt later provide production authorization only for exact reviewed tool/process/semantic identities.

### 9.2 Host support decisions

The denominator covers exactly `windows-amd64`, `windows-arm64`, `linux-amd64`, `linux-arm64`, `macos-amd64`, and `macos-arm64`.

| Host | Gate-3 provider disposition | Package disposition |
|---|---|---|
| `linux-amd64` | candidate supported, contingent on section 9.3 pins/containment | candidate supported |
| `windows-amd64` | candidate supported only after exact mechanism below passes | candidate supported |
| `linux-arm64` | `NOT_IMPLEMENTED`, `PLATFORM_ARCH_NOT_ACCEPTED` | portable install fixture only; no release claim |
| `windows-arm64` | `NOT_IMPLEMENTED`, `PLATFORM_ARCH_NOT_ACCEPTED` | portable install fixture only; no release claim |
| `macos-amd64` | `NOT_IMPLEMENTED`, `PLATFORM_PROCESS_SCOPE_UNPROVEN` | readiness=false, Gate 17 |
| `macos-arm64` | `NOT_IMPLEMENTED`, `PLATFORM_PROCESS_SCOPE_UNPROVEN` | readiness=false, Gate 17 |

Unknown profiles get `PLATFORM_PROFILE_UNKNOWN` and no launch. Gate-3 cutover may proceed only for the two accepted amd64 cells; it MUST NOT make a general arm64/macOS support claim. [D04]

### 9.3 Exact containment and EVM tool closure

Linux-amd64 provider launch order is exact:

1. Parent opens every approved root with `openat2(RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_SYMLINKS)`, stable-hashes identities, creates the WTx/CAS roots, creates a dedicated cgroup-v2 child with `memory.max=2147483648`, `pids.max=64`, and `cpu.max="200000 100000"`, and opens a `pidfd`/control socket.
2. Parent calls `clone3` with `CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWNET|SIGCHLD`; child blocks on the control socket before any filesystem/provider action.
3. Parent writes `setgroups=deny`, then uid/gid maps mapping namespace uid/gid 0 to the frozen unprivileged audit uid/gid, moves the child to the cgroup, and records namespace/cgroup inode identities.
4. Child calls `setresgid(0,0,0)`, `setresuid(0,0,0)`, and `prctl(PR_SET_NO_NEW_PRIVS,1)`; sets mount propagation `MS_REC|MS_PRIVATE`; creates a tmpfs root; bind-mounts only enumerated source/build inputs read-only, WTx/CAS outputs read-write, and every host-manifest runtime-closure row at its exact sandbox path read-only (`MS_BIND|MS_REC` followed by `MS_REMOUNT|MS_BIND|MS_RDONLY|MS_NOSUID|MS_NODEV`, with `MS_NOEXEC` except rows typed executable or loader). The closure includes the CPython executable, ELF interpreter/dynamic loader, every recursively resolved native shared library, CPython standard library, `lib-dynload`, installed package/Slither RECORD tree, helper/parser modules, and every selected solc executable. It performs `pivot_root`, unmounts the old root, and proves `/proc/self/mountinfo` and stable-opened closure identities equal the plan.
5. Child leaves loopback down in the empty network namespace; clears environment; installs the exact secret-free allowlist; sets Python argv prefix exactly `-I -s`; and closes every descriptor except stdin/stdout/stderr, control socket, and pinned executable/input FDs. Before `execveat`, it calls `prctl(PR_CAP_AMBIENT_CLEAR_ALL)`, calls `prctl(PR_CAPBSET_DROP,n)` for every integer `0..CAP_LAST_CAP` while it still has namespace `CAP_SETPCAP`, then applies a zero inheritable/permitted/effective `capset`; `/proc/self/status` readback MUST show `CapInh=CapPrm=CapEff=CapBnd=CapAmb=0`. It then calls `execveat` on the already-hashed CPython FD with typed bootstrap argv. Before provider import/action, that bootstrap verifies `sys.executable`, `sys.prefix`, ordered `sys.path`, import origins, and loaded native-library paths against the manifest, reports the readback over the control socket, and blocks until the parent accepts it. Failure to remove/prove a capability or to accept the bootstrap readback forbids provider launch.
6. Parent records pidfd, namespace inodes, mount digest, uid/gid maps, cgroup settings/membership, environment/FD census, waits, kills the entire cgroup on timeout, and requires terminal `pids.current=0` before accepting terminal evidence.

Windows-amd64 provider launch order is exact:

1. Stable-open/hash approved roots; apply/read back input read-only and WTx/CAS write-only ACLs for fixed AppContainer profile name `Plamen.ProgramFacts.Gate3`. The read-only roots contain the exact host-manifest CPython executable/DLLs, standard library, `lib-dynload` equivalent, installed package/Slither RECORD tree, helper/parser modules, selected solc executables, and recursively resolved native DLL closure; no loader path outside that closure is permitted.
2. Derive its SID with `DeriveAppContainerSidFromAppContainerName`; create/verify WFP inbound/outbound block filters scoped to that SID before process creation.
3. Create a Job Object and set `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, `JOB_OBJECT_LIMIT_ACTIVE_PROCESS=64`, and `JOB_OBJECT_LIMIT_PROCESS_MEMORY=2147483648`.
4. Create a primary restricted token with `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)`, remove administrator/power-user SIDs, set low-integrity mandatory label, delete or disable every privilege except the unavoidable enabled `SeChangeNotifyPrivilege`, and verify the exact token user/group/privilege readback. Any other enabled privilege forbids launch.
5. Build `STARTUPINFOEX` with exact `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` for the AppContainer SID and an empty capability-SID array, `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` containing only stdin/stdout/stderr/control/CAS handles, and the frozen mitigation-policy value.
6. Call `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32|LOAD_LIBRARY_SEARCH_USER_DIRS)`, add only manifest runtime directories with `AddDllDirectory`, and call `CreateProcessAsUserW` with `CREATE_SUSPENDED|CREATE_UNICODE_ENVIRONMENT|EXTENDED_STARTUPINFO_PRESENT`, `bInheritHandles=TRUE`, Python argv prefix exactly `-I -s`, typed quoted argv from the Windows quoting primitive, and the deny-by-default environment block. The manifest-pinned `python312._pth`/installation layout and boot verifier must produce the exact ordered `sys.path`, import origins, DLL search directories, and loaded-module identities.
7. Before resume, call `AssignProcessToJobObject`; verify job membership, token/AppContainer SID, empty capability array, exact privilege set, handle list, WFP filters, executable image file identity, static runtime-closure/DLL-directory plan, and root ACL digest; terminate on any mismatch.
8. Call `ResumeThread` into the pinned bootstrap. Before provider import/action, the bootstrap reports exact `sys.path`, import origins, DLL search directories, and loaded-module identities over the control handle and blocks; the parent verifies them against the manifest before releasing provider execution. Monitor job accounting, terminate the job on timeout, require `ActiveProcesses=0`, remove WFP filters, and persist the removal receipt before accepting terminal evidence.

A plain subprocess, delayed job assignment, environment inheritance, or best-effort firewall rule is never a fallback. Missing primitive/evidence forbids launch and yields `NOT_IMPLEMENTED`/`PLATFORM_PROCESS_SCOPE_UNPROVEN`.

The exact authority artifacts are:

```text
rules/program-facts-provider-registry.v2.json
rules/schemas/program_facts_provider_registry.v2.schema.json
rules/program-facts-host-tool-manifest.linux-amd64.v1.json
rules/program-facts-host-tool-manifest.windows-amd64.v1.json
rules/schemas/program_facts_host_tool_manifest.v1.schema.json
rules/schemas/program_facts_host_containment_evidence.v1.schema.json
review_fixtures/program_facts_runtime_gate3/host_containment/linux-amd64/evidence.v1.json
review_fixtures/program_facts_runtime_gate3/host_containment/windows-amd64/evidence.v1.json
review_fixtures/program_facts_runtime_gate3/host_containment/linux-amd64/independent_review.v1.json
review_fixtures/program_facts_runtime_gate3/host_containment/windows-amd64/independent_review.v1.json
```

The host-tool-manifest object is closed and contains exactly `{schema_version,host_profile,python,helper,parser,slither_distribution,solc_executables,native_dependencies,runtime_filesystem_closure,loader_policy,version_outputs,install_provenance,manifest_body_sha256}`. `runtime_filesystem_closure` is sorted unique by `(sandbox_path,kind,identity.sha256)` and each row is exactly `{kind:PYTHON_EXECUTABLE|PYTHON_STDLIB|PYTHON_EXTENSION|PYTHON_PACKAGE|SLITHER_RECORD_MEMBER|HELPER|PARSER|SOLC_EXECUTABLE|DYNAMIC_LOADER|NATIVE_LIBRARY,identity:file_identity,sandbox_path:absolute_sandbox_path,access:READ_ONLY|READ_EXECUTE,loader_parent_sha256_or_null:hex64|null}`. Every loader/import edge must terminate in that closed set. `loader_policy` is the tagged platform branch `{kind:LINUX,python_argv_prefix:[-I,-s],sys_executable,sys_prefix,sys_path:ordered[absolute_sandbox_path],elf_interpreter:absolute_sandbox_path,library_search_paths:ordered[absolute_sandbox_path],allowed_import_origins:sorted[absolute_sandbox_path]}` or `{kind:WINDOWS,python_argv_prefix:[-I,-s],sys_executable,sys_prefix,sys_path:ordered[absolute_sandbox_path],python_pth:file_identity,dll_search_flags:uint64,dll_directories:ordered[absolute_sandbox_path],allowed_import_origins:sorted[absolute_sandbox_path]}`. Every executable/library/distribution row is a full file or RECORD-tree identity, solc/version rows sort by executable SHA-256, and no version range confers authority.

Containment evidence is a closed tagged object containing exactly `{schema_version,host_profile,run_id,execution_authority_id,expected_child_id,attempt_id,host_tool_manifest:file_identity,root_plan_digest,runtime_closure_digest,environment_digest,process_start_identity,terminal_state,exit_code_or_null,signal_or_null,terminal_zero,linux_or_null,windows_or_null,evidence_body_sha256}`. Exactly one platform branch is non-null and must match `host_profile`. The Linux branch contains exactly:

```text
{pidfd_identity,user_namespace_inode,mount_namespace_inode,pid_namespace_inode,network_namespace_inode,
 uid_map,gid_map,setgroups_value,cgroup:{path,inode,memory_max,pids_max,cpu_max,membership_pid,pids_current_terminal},
 mounts:sorted[{sandbox_path,source_identity_or_null,flags}],mountinfo_sha256,runtime_rows:sorted[{sandbox_path,observed_identity,access}],
 network:{interfaces:[{name:lo,up:false}],routes:[],loopback_up:false},environment:sorted[{name,value_sha256}],open_fds:sorted[{fd,role}],
 capabilities:{cap_last_cap,dropped_bounding:ordered[uint32],cap_inh,cap_prm,cap_eff,cap_bnd,cap_amb,no_new_privs:true},
 python:{argv,sys_executable,sys_prefix,sys_path,imports:sorted[{module,origin_identity}],loaded_native_libraries:sorted[file_identity]},
 timeout:{wall_ms,kill_scope:CGROUP,terminal_pids_current:0}}
```

`dropped_bounding` is exactly every integer `0..cap_last_cap` once and all five capability bitstrings are canonical zero. The Windows branch contains exactly:

```text
{appcontainer:{profile_name:Plamen.ProgramFacts.Gate3,sid,capability_sids:[]},
 acl_rows:sorted[{path,identity_or_null,access:READ_ONLY|READ_EXECUTE|WRITE_ONLY,acl_sha256}],
 wfp:{filter_ids:sorted[uint64],inbound_block:true,outbound_block:true,scope_sid,removal_receipt_sha256},
 job:{job_identity,kill_on_close:true,active_process_limit:64,process_memory_limit:2147483648,assigned_before_resume:true,active_processes_terminal:0},
 token:{user_sid,integrity:LOW,groups:sorted[{sid,attributes}],privileges:[{name:SeChangeNotifyPrivilege,enabled:true}],token_sha256},
 handles:sorted[{numeric_value,role}],mitigation_policy:uint64,
 loader:{default_dll_flags:uint64,dll_directories,python_pth:file_identity,sys_path,imports:sorted[{module,origin_identity}],loaded_native_libraries:sorted[file_identity]},
 process:{image:file_identity,creation_flags:uint64,resumed_after_all_readbacks:true},timeout:{wall_ms,kill_scope:JOB}}
```

The common schema fixes `schema_version=plamen.program_facts_host_containment_evidence.v1`; IDs use their section-5 grammars; the four digests are `hex64`; `process_start_identity` is exactly `{pid:uint64,start_token:string[1..128],executable:file_identity}`; and `terminal_state` is `EXITED|SIGNALED|TIMEOUT`. `EXITED` requires `exit_code_or_null:uint32` and null signal; `SIGNALED` requires null exit code and `signal_or_null:uint32`; `TIMEOUT` requires both null. `terminal_zero` is true exactly for `EXITED` with code zero. `evidence_body_sha256 = SHA-256(CJ(object without evidence_body_sha256))`. In the Linux branch all PID/FD/inode/counter values are uint64, `uid_map`/`gid_map` are the exact canonical strings `0 <frozen-host-id> 1\n`, `setgroups_value` is const `deny`, mount flags are sorted unique values from `BIND|REC|REMOUNT|RDONLY|NOSUID|NODEV|NOEXEC|RW`, `open_fds.role` is `STDIN|STDOUT|STDERR|CONTROL|PINNED_EXECUTABLE|PINNED_INPUT`, and all capability strings are the single canonical string `0`. In the Windows branch SIDs are canonical strings, ACL/filter/handle/group rows use the shown key and full readback digest, `default_dll_flags=0x00000c00`, `creation_flags=0x00080404`, and dynamic IDs/paths are accepted only when cross-bound to the prelaunch plan and manifest; the mitigation value must equal the contract-frozen host manifest value.

Arrays sort by their displayed primary path/name/numeric key; duplicates are invalid. `runtime_closure_digest` equals the host manifest closure digest, and every observed identity/path/readback must equal that manifest and the fixed constants above. If the read-only CPython/stdlib/package/Slither/solc/native-loader closure, capability removal, empty AppContainer capability list, ACL/WFP/job/token/loader readback, or required platform primitive is unavailable, selection emits the typed no-launch disposition and no process is created; it is never replaced by partial or synthetic containment evidence. Each independent review uses `program_facts_independent_review.v1.schema.json`, executes the corresponding D05/D08 and C-grid host carriers, has no blocking open finding, and disposes `PASS_LINUX_AMD64_GATE3_CONTAINMENT_ONLY` or `PASS_WINDOWS_AMD64_GATE3_CONTAINMENT_ONLY`.

The EVM tool version is fixed to `slither-analyzer 0.11.5`. Accepted distribution candidates are sdist `slither_analyzer-0.11.5.tar.gz` SHA-256 `d90af76b86bdf7ced56fc4c8eea8792cde1ec2c375372d5e70298c2ff998d5e1` and wheel `slither_analyzer-0.11.5-py3-none-any.whl` SHA-256 `3c7cb43651464543ed9152ed2f383dad4e15220b173754878ba6b291698be977`. Helper source is `scripts/program_facts_evm_helper.py`, 2,424 bytes, SHA-256 `c7bec0e79de2551078245e040c188cbac73df2899cd5bf2049da7f44cc7c4a11`; parser source is `scripts/program_facts_evm_provider.py`, 124,515 bytes, SHA-256 `356783aa0cfeac2b7cdd731262dea3748994fc5adec3208d11d6fca6631c4981` in the reviewed tool manifest evidence.

Current tool authority has no accepted executable digest and is `DISABLED_PENDING_SEMANTIC_REVIEW`. The two exact host manifests above MUST pin CPython executable identity; helper/parser identities; installed Slither RECORD-tree digest; every native dependency executable/library; exact version stdout bytes/digest; and every selected solc executable/version/hash. Their reviews must additionally pin the exact registry-v2 identity. Until both pass, EVM execution and Gate-3 cutover remain blocked. No range such as `solc >=0.4,<0.9` is executable authority.

### 9.4 Python, dependencies, packaging, and installation

Gate-3 runtime Python is exactly CPython `3.12.10`. Each supported host pins its executable full-file digest; the observed Windows candidate `python.exe` is 104,952 bytes, SHA-256 `4d6f5f81a4bca11191c4c7c6b43632694d0a4ce74e068619d8fdc161d469859a`, but it is evidence only until host review. Linux executable identity is absent and blocks cutover.

The current `requirements-ci.lock` is dev/CI evidence, not a runtime lock. Gate 3 MUST create hash-locked `requirements-program-facts-gate3.lock` for CPython 3.12.10 and pin its file identity. Installation is offline from a separately hashed wheelhouse closure. Unlocked `requirements.txt` cannot satisfy runtime authority.

The repository remains the distribution; no wheel is assumed. Gate 3 MUST create `verification_policy/toolchain_runtime_closure.v2.json` containing every v3 schema, module, registry, policy, compact seed admission, data file, dependency lock, wheelhouse member, license, installer path, and backend wrapper actually needed. It MUST explicitly exclude the 99 MB construction seed, its generator/tests, oracle sources, and expected files. Source archive, installed legacy-Claude tree, installed future-Codex tree, and doctor MUST recompute identical semantic closure bytes/digest. Backend wrappers are separately pinned nonsemantic transport.

Install verifies source manifest and closure before copy; rejects missing/extra/colliding members; performs no network access; and emits a non-authoritative install receipt. Doctor returns PF-ready only on exact closure/Python/tool/host match. Uninstall removes exactly install-receipt-owned files and proves no closure survivor while preserving user/audit artifacts.

### 9.5 Version and rollout thresholds

The current application `VERSION` is `2.2.4` evidence only. Release owner MUST assign a new application version before release freeze; absence blocks cutover. The Program Facts contract versions are fixed here as public v3, publication/generation v2, active-head v1, ACTIVE-projection v1, and runtime protocol v1.

The default-off coexistence contract is `rules/program-facts-gate3-shadow-v3-flag.v1.json` under `rules/schemas/program_facts_gate3_shadow_flag.v1.schema.json`. It contains exactly:

```text
schema_version                 const plamen.program_facts_gate3_shadow_flag.v1
flag_name                      const program_facts_gate3_shadow_v3
config_key                     const program_facts_gate3_shadow_v3
cli_enable                     const --program-facts-gate3-shadow-v3
cli_disable                    const --no-program-facts-gate3-shadow-v3
default                        const false
owner                          const RUNTIME_DRIVER
semantic_backend              const native
legacy_stage2_symbol           scripts/plamen_driver.py::_ensure_program_facts_stage2_emit_only
gate3_symbol                   scripts/program_facts_runtime_v3_runner.py::run_program_facts_gate3_v1
valid_pipeline_ecosystems      exact five SC plus three L1 pairs from section 6.1
activation_policy              const FINAL_CUTOVER_RECEIPT_REQUIRED
rollback_policy                const DISABLE_HEAD_THEN_FLAG_FALSE
flag_body_sha256               SHA-256(CJ(object without flag_body_sha256))
```

RuntimeDriver exclusively parses/owns the boolean and passes an explicit typed value; absence is false, conflicting CLI forms are invalid, and environment variables, provider output, repository target files, models, plugins, and PhaseIO cannot set it. The preimplementation flag vectors are `review_fixtures/program_facts_runtime_gate3/phase_io/gate3_shadow_flag_vectors.v1.json` under `rules/schemas/program_facts_gate3_shadow_flag_vector.v1.schema.json` and contain exactly: absent-default-false, explicit-false, conflicting-CLI rejection, true-without-cutover rejection, SC/EVM coexistence, seven valid non-EVM no-launch dispositions, invalid pipeline/ecosystem rejection, and rollback ordering.

The config key, CLI switches, contract artifact, and Gate-3 driver seam do not exist today. Their absence is exactly false and a current cutover blocker; no implementer may reinterpret another Program Facts/Stage-2 setting as this flag.

The legacy Stage-2 seam remains a separate predecessor: its existing modules, work-unit identities, v1 public paths, SC/EVM invocation behavior, non-EVM `NOOP_UNSUPPORTED_ECOSYSTEM` behavior, and failure/debt behavior MUST remain byte-for-byte contract compatible. Gate 3 does not rename, replace, gate, or migrate it in place. Runtime order after G3-12 cutover is exact:

1. invoke the existing Stage-2 seam under its existing conditions;
2. if the Gate-3 flag is absent/false, do not resolve any v3 work unit and continue legacy semantics;
3. if true, require the exact release freeze/review/final cutover receipt/package/host identities, otherwise return `GOVERNANCE_MISSING` with no v3 provider launch or active-head change;
4. invoke the new native v3 runner under its separate versioned keys/paths; SC/EVM may launch only under section 9.3, while the other seven valid ecosystem cells publish typed `NOT_IMPLEMENTED` debt with no child/process; and
5. keep all audit consumers on validated legacy-v1/no-sidecar semantics even after a v3 head is committed.

Denominator and soak harnesses invoke the new runner only in isolated evidence roots under the contract/release lifecycle; they do not enable the production flag. Rollback first attempts a reviewed forward `DISABLED_LEGACY` ArtifactLedger head transition and validates its ACTIVE projection, then persists flag false. Emergency inability to write that transition still forces false and blocks the v3 loader while preserving the prior head as evidence; it records operational debt outside Program Facts. Re-enabling requires a new reviewed release/cutover decision. Rollout is:

1. denominator: 691/691 executions, zero skip/xfail/deselection/unexpected result;
2. shadow soak A: 30 frozen synthetic/non-target corpora, zero integrity/authority/secret/network/determinism/debt-persistence failures;
3. shadow soak B: 50 consented non-target internal runs, at least 95% EVM provider completion, every noncompletion durably typed, zero cross-backend payload/debt mismatch;
4. activation limited to reviewed package/host identities; consumers remain false.

Immediate rollback triggers are any authority-bit escalation, secret/network escape, active-head generation integrity error, payload/debt nondeterminism, ACTIVE-projection/ledger-head divergence, untyped provider launch/failure, or debt-persistence failure. Three consecutive runner internal failures or provider completion below 90% over any rolling 20-run window also roll back. Rollback is legacy/no-sidecar; section 11 applies.

## 10. Failure taxonomy

Before a successful active-head CAS, blocking failures preserve the prior ledger head: missing/invalid seed/spec/architecture/freeze review; schema/module/oracle/denominator/tool/package identity drift; noncanonical JSON/Base64/path; source escape/alias/drift; ambiguous registry; unpinned tool; child/authority/WTx/raw-CAS mismatch; contribution/provenance collision; receipt/digest-cycle/cross-binding error; partial immutable commit; ledger/projection mismatch that is not repairable; inability to persist required debt; corrupt active-head generation; self-certification; or authority escalation. After a successful head CAS, projection failure cannot restore the prior head and instead requires projection repair.

Haltless degradations may publish a zero/degraded v3 generation only after durable debt: non-EVM `PROVIDER_NOT_IMPLEMENTED`; unsupported host/arch; missing optional tool; provider timeout/resource/nonzero exit; parseable incomplete raw evidence; unsupported capability; provider disagreement; or explicitly optional unreadable root. Corrupt evidence that cannot truthfully support the classification is blocking. `DEGRADED`, `UNAVAILABLE`, and `NOT_IMPLEMENTED` never imply absence of an underlying property.

## 11. Cache, concurrency, migration, and rollback

Cache hits validate PF-00, all current reuse inputs, the ArtifactLedger active head, immutable files, and any ACTIVE projection; they never bypass governance. Concurrency follows section 6.4 and the ArtifactLedger active-head CAS. Same generation ID with unequal manifest bytes is blocking; equal bytes may be idempotently acknowledged.

Private schema migration is read-old/write-new with a new generation and release-freeze version; no in-place rewrite. v1 remains legacy read-only, v2 experimental ignored, and v3 selected independently. Any future public v4 needs new filenames/schemas/dispatcher/review.

Rollback follows section 9.5: while invocation remains authorized, attempt and validate a forward `DISABLED_LEGACY` active-head transition, then set `program_facts_gate3_shadow_v3=false`; emergency failure of the transition still forces false and blocks all v3 loading. Consumers remain false, ledger/history/quarantine are retained, and audit semantics return to validated legacy-v1 or no-sidecar behavior. Rollback never copies an old generation over a new one, selects by mtime, relaxes validation, or hides active-head corruption as absence. Operational rollback debt is recorded through an already-authorized operational channel if PF publication is disabled.

## 12. Independent oracle and exact acceptance denominator

### 12.1 Independent expected-bytes authority

Expected results are not produced by the production runner. The red-fixture author MUST create:

```text
review_fixtures/program_facts_runtime_gate3/oracle/program_facts_reference_oracle_v1.py
review_fixtures/program_facts_runtime_gate3/oracle/program_facts_oracle_crosscheck_v1.py
review_fixtures/program_facts_runtime_gate3/oracle/program_facts_runtime_oracle_manifest.v1.json
review_fixtures/program_facts_runtime_gate3/oracle/expected/<case_id>/<execution_id>/expected_result.v1.json
review_fixtures/program_facts_runtime_gate3/oracle/expected/<case_id>/<execution_id>/<expected_file>
```

The oracle may import only Python 3.12.10 standard-library `base64`, `hashlib`, `json`, `pathlib`, `struct`, and `typing`. An AST import check rejects `scripts`, any Plamen package/module, production schemas loaded through production helpers, subprocess, network, dynamic import, and `sys.path` mutation. Production code and package closure MUST NOT import or ship the oracle or expected files.

The oracle independently implements section 3 canonicalization/identity and the closed synthetic fixtures. Its author must be separate from every production-module author. `program_facts_runtime_oracle_manifest.v1.json` contains exactly:

```text
schema_version                 const plamen.program_facts_runtime_oracle_manifest.v1
oracle                         file_identity
oracle_author                  {principal_id, organization, role}
independence                   {production_author_separate:true, no_production_imports:true, workspace_clean:true}
python                         {version:3.12.10, executable_file_identity}
specification                  file_identity
synthetic_governance           exact section-12.1 binding file_identity
fixture_execution_scope        exact section-12.1 scope file_identity
fixture_execution_authority    exact section-12.1 authority file_identity
fixture_execution_authority_review exact section-12.1 authority-review file_identity
fixture_manifest               exact section-12.3 fixture-manifest file_identity
semantic_projection_schema     exact program_facts_receipt_semantic_projection.v1 schema file_identity
schema_inputs                  sorted [file_identity]
case_index                     sorted [{case_id, execution_id, expected_result:file_identity, expected_receipt_semantic_projection:file_identity or null, expected_files:[file_identity]}]
case_count                     const 160
execution_count                const 691
manifest_body_sha256           body digest
```

Each `expected_result.v1.json` conforms to `rules/schemas/program_facts_runtime_expected_result.v1.schema.json`, is closed, and contains exactly:

```text
schema_version                    const plamen.program_facts_runtime_expected_result.v1
exit_class                       PASS|BLOCKED|DEGRADED|NOT_IMPLEMENTED|REBUILD_REQUIRED
status                           ADMITTED|ARMED|COMPOSED|DEGRADED|DENIED|FAILED|LEGACY_OR_NO_SIDECAR|NOT_IMPLEMENTED|NOT_READY|ORDERED|PACKAGE_READY|RECONCILED|REUSED|SELECTED|STALE|UNAVAILABLE|VALIDATED|WRITTEN
debt_codes                       sorted unique [section-3.5 error_code]
publication_effect               NONE|PRESERVE_PRIOR|PUBLISH_NEW_SELECTED|REUSE_EXISTING
active_head_generation_relation  NONE|UNCHANGED|NEW_MATCHES_EXPECTED|REUSED_MATCHES_EXPECTED|DISABLED_LEGACY
expected_files                   sorted unique [file_identity]
nonsemantic_masks                sorted unique [/nonsemantic_transport/invocation_label|/nonsemantic_transport/wrapper_file_identity]
expected_result_body_sha256      SHA-256(CJ(object without expected_result_body_sha256))
```

`debt_codes` sort by the numeric section-3.5 ordinal and may contain only codes whose expected durable debt is asserted by the case; an empty array means none. `expected_files` sorts by `(path,size_bytes,sha256)` and pins each expected canonical file beneath that execution's expected directory. For a public-output case it contains the payload, debt, and `mechanical_program_facts_receipt.semantic_projection.v1.json`; it MUST NOT contain or construct a full expected receipt. A case without public output has an empty list and a null `expected_receipt_semantic_projection`. The two receipt-only mask pointers sort by UTF-8 and configure only the separate actual-transport checks defined below; neither pointer is applied to the semantic projection, payload, debt, provenance envelope, or any authority value. Prose suffixes such as “after head-led repair” describe the recovery route and are not enum values. The expected-result file identity and all listed expected-file identities are bound by both the oracle manifest and denominator; disagreement is `ORACLE_OR_DENOMINATOR_INVALID`.

Expected semantic receipt projections cannot bind a contract freeze that is created only after their review. After the stable seed/specification/public-v3 architecture reviews exist and before any oracle output, the fixture custodian creates:

```text
review_fixtures/program_facts_runtime_gate3/governance/program_facts_pre_freeze_fixture_governance.v1.json
review_fixtures/program_facts_runtime_gate3/governance/PROGRAM_FACTS_PRE_FREEZE_FIXTURE_GOVERNANCE_INDEPENDENT_REVIEW.v1.json
```

The first file conforms to `program_facts_pre_freeze_fixture_governance.v1.schema.json` and contains exactly:

```text
schema_version       const plamen.program_facts_pre_freeze_fixture_governance.v1
binding_id           pffg-<32hex>
seed                 {admission:file_identity,admission_review:file_identity,external_acceptance:file_identity}
specification        {document:file_identity,independent_review:file_identity}
architecture         {graph_v2:file_identity,ownership_v2:file_identity,public_v3_schemas:sorted unique [file_identity],independent_review:file_identity}
fixture_contracts    {provider_registry:file_identity,schema_inputs:sorted unique [file_identity],mutation_schema:file_identity,mutation_vectors:file_identity,phase_io_contract_matrix:file_identity,wtx_ledger_protocols:sorted unique [file_identity]}
fixture_root         const review_fixtures/program_facts_runtime_gate3/
allowed_use          const EXPECTED_BYTES_ONLY
authority_ceiling    {runtime:false,provider_launch:false,production_publication:false,active_head_update:false,release:false,cutover:false,consumer:false,finding:false,clean_certification:false}
binding_body_sha256  SHA-256(CJ(object without binding_body_sha256))
```

`binding_id = "pffg-" || SHA-256(CJ({domain:"PROGRAM_FACTS_PRE_FREEZE_FIXTURE_GOVERNANCE_V1",seed,specification,architecture,fixture_contracts,fixture_root,allowed_use,authority_ceiling}))[0:32]`. Its independent review uses subject kind `PRE_FREEZE_FIXTURE_GOVERNANCE`, exact vector IDs `PFFG-01-PREEXISTING-INPUTS`, `PFFG-02-NO-FREEZE-EDGE`, `PFFG-03-FIXTURE-ROOT-ONLY`, `PFFG-04-AUTHORITY-ALL-FALSE`, and `PFFG-05-INDEPENDENCE`, all `PASS`, no open blocking finding, and disposition `PASS_PRE_FREEZE_SYNTHETIC_GOVERNANCE_FOR_EXPECTED_BYTES_ONLY`. This binding remains expected-byte construction lineage only: it cannot launch a provider or publish/update any head.

The representable authority used by both expected and actual G3-09 receipts is created before oracle expected bytes at these exact paths:

```text
review_fixtures/program_facts_runtime_gate3/governance/program_facts_pre_release_fixture_execution_scope.v1.json
review_fixtures/program_facts_runtime_gate3/governance/program_facts_pre_release_fixture_execution_authority.v1.json
review_fixtures/program_facts_runtime_gate3/governance/PROGRAM_FACTS_PRE_RELEASE_FIXTURE_EXECUTION_AUTHORITY_INDEPENDENT_REVIEW.v1.json
```

The scope file conforms to `program_facts_pre_release_fixture_execution_scope.v1.schema.json` and contains exactly:

```text
schema_version       const plamen.program_facts_pre_release_fixture_execution_scope.v1
specification        exact stable specification file_identity
synthetic_governance exact binding/review file identities above
rows                 sorted unique [fixture_execution_scope_row]
case_count           const 160
execution_count      const 691
scope_body_sha256    SHA-256(CJ(object without scope_body_sha256))
```

A row contains exactly `{case_id,execution_id,test_node,input_fixture_root,execution_root,invocation_label,host_profile_or_null,ecosystem_or_null,provider_id_or_null,allowed_operations}`. Rows sort by `(UTF8(case_id),UTF8(execution_id))` and contain exactly the section-12.3 through 12.6 execution-ID set once. `input_fixture_root` is exactly `review_fixtures/program_facts_runtime_gate3/fixtures/<case_id>/`; `execution_root` is exactly `review_fixtures/program_facts_runtime_gate3/execution_roots/<case_id>/<execution_id>/`; and `test_node`/invocation/host/ecosystem values equal the closed denominator rules. `allowed_operations` is a sorted unique subset of `EVM_PROVIDER_BASELINE`, `WRITE_SELECTED_GENERATION`, `READ_SELECTED_GENERATION`, `REPAIR_ACTIVE_PROJECTION`, and `WRITE_DISABLED_LEGACY`.

The privileged roster is exact and is derived only from the literal case tables before any expected artifact exists: `EVM_PROVIDER_BASELINE` occurs only on `C00-T0_BASELINE-{NATIVE,CLAUDE,CODEX}` and `C16-T0_BASELINE-{NATIVE,CLAUDE,CODEX}`, with provider `evm.slither.typed`; `WRITE_SELECTED_GENERATION` occurs exactly where the literal case-table publication is `PUBLISH_NEW_SELECTED`; `READ_SELECTED_GENERATION` occurs exactly where a selected prior/new generation is a literal case-table input or the literal case-table publication is `REUSE_EXISTING`/`PRESERVE_PRIOR`; `REPAIR_ACTIVE_PROJECTION` occurs only on `E10-PRIMARY` and `E11-PRIMARY`; and `WRITE_DISABLED_LEGACY` occurs only on `E15-PRIMARY`. Empty-operation rows may validate/canonicalize fixtures but cannot launch a child or access ArtifactLedger. Containment evidence is a G3-08 prerequisite and grants no row operation. Any roster difference, wildcard, generated row, or authority inferred from an expected-result file is `ORACLE_OR_DENOMINATOR_INVALID`.

The authority file conforms to `program_facts_pre_release_fixture_execution_authority.v1.schema.json` and contains exactly:

```text
schema_version                const plamen.program_facts_pre_release_fixture_execution_authority.v1
authority_id                  pfea-<32hex>
predecessor_governance        {binding:file_identity,independent_review:file_identity}
execution_scope               file_identity plus scope_body_sha256
provider_registry             exact registry-v2 file_identity
phase_io_contract_matrix      exact pre-freeze matrix file_identity
allowed_stage                 const G3_09
allowed_runner                const scripts/program_facts_runtime_v3_runner.py::run_program_facts_gate3_v1
required_actual_prerequisites {contract_freeze_pins_authority_scope:true,contract_freeze_review_passed:true,production_symbol_identities_recorded:true,host_tool_and_containment_reviews_passed:true,package_closure_verified:true,fresh_execution_root:true}
authority_ceiling             {fixture_provider_launch:ROW_SCOPED,fixture_publication:ROW_SCOPED,fixture_active_head:ROW_SCOPED,production_workspace:false,production_publication:false,production_active_head:false,release:false,cutover:false,consumer:false,finding:false,severity:false,confidence:false,clean_certification:false}
authority_body_sha256         SHA-256(CJ(object without authority_body_sha256))
```

`authority_id = "pfea-" || SHA-256(CJ({domain:"PROGRAM_FACTS_PRE_RELEASE_FIXTURE_EXECUTION_AUTHORITY_V1",predecessor_governance,execution_scope,provider_registry,phase_io_contract_matrix,allowed_stage,allowed_runner,required_actual_prerequisites,authority_ceiling}))[0:32]`. Its review uses subject kind `PRE_RELEASE_FIXTURE_EXECUTION_AUTHORITY`, exact vectors `PFEA-01-PREDECESSOR-LINEAGE`, `PFEA-02-SCOPE-160-691`, `PFEA-03-LAUNCH-ROSTER`, `PFEA-04-PUBLICATION-HEAD-ROSTER`, `PFEA-05-FIXTURE-ROOT-CONFINEMENT`, `PFEA-06-ACTUAL-PREREQUISITES`, `PFEA-07-AUTHORITY-CEILING`, and `PFEA-08-INDEPENDENCE`, all `PASS`, no open blocking finding, and disposition `PASS_PRE_RELEASE_FIXTURE_EXECUTION_AUTHORITY_FOR_G3_09_ONLY`. The reviewer is independent of the scope/oracle/production authors.

The authority exists before production but cannot launch by existence alone. At G3-09 the runner must additionally prove that the reviewed contract freeze pins the exact authority, review, scope, registry, schemas, denominator, and oracle tree; that G3-08 production/module/package/host/tool/containment identities validate; that the input and output roots stable-resolve to the scope row with no alias; and that the requested operation is listed in that row. All Program Facts, WTx, CAS, ArtifactLedger, and ACTIVE paths are rooted below `execution_root`; production-workspace paths and consumers are rejected before launch. Each execution uses a fresh isolated ArtifactLedger namespace and cannot observe another row's execution root.

The oracle produces no full expected receipt. It produces the closed semantic receipt projection below, while every G3-09 actual publication retains the complete `mechanical_program_facts_receipt.v3` provenance envelope. Both projection paths use the byte-identical `{kind:FIXTURE_PRE_RELEASE,fixture_execution_authority,...}` governance value and exact scope-row authority semantics. A different governance branch, authority ID/body, scope row/body, operation set, or false-to-true authority change is `AUTHORITY_ESCALATION`; none is maskable or delegated to provenance validation.

#### 12.1.1 Closed semantic receipt projection and full-provenance partition

`rules/schemas/program_facts_receipt_semantic_projection.v1.schema.json` is closed. For every case with a public receipt, the oracle writes `oracle/expected/<case_id>/<execution_id>/mechanical_program_facts_receipt.semantic_projection.v1.json`, containing exactly:

```text
schema_version          const plamen.program_facts_receipt_semantic_projection.v1
receipt_contract        {schema_version:plamen.mechanical_program_facts_receipt.v3,canonicalization_version:plamen.canonical_json.v3}
composition_semantic_digest hex64
public_semantic_ids     {generation_id,transaction_id,payload_semantic_id,debt_semantic_id,receipt_semantic_id}
execution_identity      {run_id,run_generation,snapshot_id,mode:SHADOW}
result                  {status:public_status}
governance_semantics    exact composition preimage authority_semantics.governance_semantics
fixture_authority_semantics {authority_id_or_null,authority_body_sha256_or_null,scope_body_sha256_or_null,scope_row_sha256_or_null,allowed_operations:sorted unique [operation]}
source_semantics        {checkpoint_content_sha256,content_pack_content_sha256,source_manifest_content_sha256,source_authority_sha256,root_tokens}
selection_semantics     {provider_registry_semantic_sha256,rows:exact capability-binding rows without selection file identity}
build_semantics         {build_variants:sorted unique [{build_variant_id,compiler_settings_sha256,source_input_content_sha256:sorted unique [hex64],transitive_dependency_content_sha256:sorted unique [hex64]}]}
environment_semantics   {host_profile,network_policy_sha256,resource_policy_sha256,process_policy_sha256}
execution_semantics     {child_results:sorted unique [{child_role,terminal_role:COMPLETION|DEBT,raw_content_sha256_or_null,contribution_semantic_ids:sorted unique [pfcs-id],debt_codes:sorted unique [public_debt_code]}]}
composition_semantics   {contribution_semantic_ids:sorted unique [pfcs-id],vocabulary_content_sha256,normalization_policy_content_sha256,disagreement_ids:sorted unique [IdentifierV3]}
publication_semantics   {ordered_logical_outputs:exact [PAYLOAD,RECEIPT,DEBT],prior_head_semantics_sha256,phase_io_contract_profile_sha256,durability_policy}
replay_semantics        exact section-5.3 replay_semantic_binding containing only outcome and semantic-source kind/payload-body/debt-body hashes
artifact_semantics      exactly [{role:PAYLOAD,semantic_artifact_id:payload_semantic_id,size_bytes,sha256},{role:DEBT,semantic_artifact_id:debt_semantic_id,size_bytes,sha256}]
authority               exact authority_ceiling
projection_body_sha256  SHA-256(CJ(object without projection_body_sha256))
```

The exact projection function is `scripts/program_facts_runtime_v3_contracts.py::project_program_facts_receipt_semantics_v1(composition_semantic_preimage,semantic_artifact_bytes,fixture_authority,scope_row)`. It accepts no full receipt, reuse binding/key/component, replay transaction/event, build plan, execution set, composition authority, runtime/validator/release/toolchain/environment/WTx/Ledger/package identity or derivative, tool, containment, terminal, raw-CAS file identity, provenance digest, event identity, or physical publication path. It validates the preimage against the exact section-5.3 shape, recomputes `composition_semantic_digest` and all five IDs, validates the authority/scope semantic members, stable-reads the provenance-free payload/debt bytes, and constructs only the object above. Build variants retain compiler settings and every source/transitive semantic content digest but no build-plan/compiler executable/module/toolchain identity or identity-derived component hash; child results retain every terminal role, raw-content digest, semantic contribution ID, and debt code but no attempt/file identity. Replay retains only its outcome and body-hash source relation, with the exact null/equality rules in section 2.7. Empty child results are required when no provider child was launched. `prior_head_semantics_sha256` is recomputed from the section-5.3 semantic-only head projection; no root/path rewriting is permitted or needed.

The projection field set is immutable and has no mask, omit, include, pointer, or extension parameter. Every field other than schema/contract framing, fixture authority cross-checks, artifact byte census, and the body digest is copied from the exact semantic preimage or one of the five exclusive digest derivations. It covers every outcome and authority-semantic value available from the preimplementation fixtures: status; run/snapshot and semantic public identity; complete fixture authority/scope/operations; source content/root semantics; capability dispositions; build semantic inputs/settings; host and policy semantics; provider terminal/raw/semantic-contribution/debt results; composition; logical publication/prestate; provenance-free replay outcome/source relation; payload/debt content; and every public authority bit. The excluded postimplementation provenance carriers are `reuse_key_sha256`, every reuse component name/hash and key input, replay source transaction/event, `receipt_id`, `receipt_body_sha256`, source/selection/build/execution/composition file identities, compiler/tool identities, containment/environment identity, runtime attempt/terminal/raw file identities, resolved PhaseIO/launch/expanded-input digests, event nonce/locator/paths, original physical paths, and `nonsemantic_transport`. Every reuse/execution provenance carrier is mandatory in the envelope below; transport is mandatory in the separate transport check; none can flow back through a content or component digest that includes those identities.

The actual runner writes the full receipt, then writes `<execution_root>/mechanical_program_facts_receipt.semantic_projection.v1.json` by the function above. G3-09 requires raw byte equality of `CF(expected_projection)` and `CF(actual_projection)`, including `projection_body_sha256`; parsing, field deletion, pointer masking, alternative projection, or comparison after mutation is forbidden. This makes all six `C00`/`C16` `T0_BASELINE` executions representable: their expected projection binds exact raw-output/contribution/result semantics, while their later executable, tool-manifest, containment, and terminal file identities remain truthful in the full actual receipt and provenance envelope.

The separate postimplementation artifact is `<execution_root>/provenance_events/<provenance_event_id>/mechanical_program_facts_receipt.provenance_envelope.v1.json` under `program_facts_receipt_postimplementation_provenance_envelope.v1.schema.json`, a closed object containing exactly:

```text
schema_version             const plamen.program_facts_receipt_postimplementation_provenance_envelope.v1
provenance_event_id        pfpv-<32hex>
actual_receipt             exact full-receipt file_identity plus receipt_id/receipt_body_sha256
execution_context          closed union: {kind:RUNTIME,run_id,run_generation,governance:exact RUNTIME governance_binding,operation:PUBLISH_V3|REPLAY_V3} | {kind:FIXTURE_PRE_RELEASE,case_id,execution_id,scope:file_identity,authority:file_identity,independent_review:file_identity,scope_row_sha256,allowed_operations}
semantic_binding           {composition_semantic_digest,generation_id,transaction_id,payload_semantic_id,debt_semantic_id,receipt_semantic_id,semantic_projection_or_null:file_identity|null}
accepted_implementation    {contract_freeze:file_identity,contract_freeze_review:file_identity,production_symbols:sorted unique [file_identity],phase_io_runtime_bindings:sorted unique [file_identity],package_closure:file_identity,provider_registry:file_identity,provider_adapter:{module_file_identity,symbols:exact [plan_evm_slither,parse_evm_slither_raw,validate_evm_normalization_outcome]}}
receipt_binding_sha256      {source,selection,build,environment,execution,composition,publication,replay,artifacts,authority}
replay_provenance          {reuse_key_preimage:exact section-8.2 closed object,reuse_binding:{reuse_key_sha256,components:reuse_components,outcome,replay_source_transaction_id_or_null},source_provenance_event_or_null:{provenance_event_id,event_record:file_identity,envelope:file_identity,composition_provenance_digest,execution_set:file_identity}|null,private_replay_receipt_or_null:file_identity|null}
full_provenance            {composition_provenance_digest,build_plans:sorted unique [{identity:file_identity,body_sha256}],execution_set:{identity:file_identity,body_sha256},terminal_roster:{identity:file_identity,body_sha256},contribution_set:{identity:file_identity,body_sha256},composition_authority:{identity:file_identity,body_sha256},payload:{identity:file_identity,full_file_sha256},debt:{identity:file_identity,full_file_sha256},receipt:{identity:file_identity,full_file_sha256},resolved_phase_io_contract_sha256,phase_io_launch_sha256,expanded_input_set_sha256,publication_attempt_ordinal}
provider_execution         PROVIDER_LAUNCHED|NO_PROVIDER_LAUNCH tagged union below
cross_bindings             {receipt_schema_valid:true,receipt_body_sha256_valid:true,semantic_digest_recomputed_equal:true,semantic_ids_equal:true,semantic_projection_equal:true,replay_semantics_equal:true,reuse_key_replayed_equal:true,reuse_components_replayed_equal:true,replay_source_event_equal:true,replay_no_fresh_execution_claim:true,reuse_provenance_not_semantic_input:true,authority_scope_equal:true,source_bindings_equal:true,provider_registry_equal:true,selection_equal:true,adapter_symbols_equal:true,build_bindings_equal:true,tool_identities_equal:true,containment_identity_equal:true,execution_set_membership_equal:true,execution_terminals_equal:true,composition_bindings_equal:true,full_provenance_digest_replayed_equal:true,phase_io_bindings_equal:true,publication_bindings_equal:true,production_symbols_equal:true,package_closure_equal:true,semantic_digest_is_not_execution_proof:true}
envelope_body_sha256       SHA-256(CJ(object without envelope_body_sha256))
```

Each `receipt_binding_sha256` member is exactly `SHA-256(CJ(actual_receipt.<same-named-member>))`; `artifacts` hashes the ordered payload/debt binding tuple. The fixture context requires non-null `semantic_projection_or_null` equal to that execution's actual projection; the runtime context requires null and recomputes the same projection in memory from semantic bytes. The validator recomputes `replay_provenance.reuse_key_preimage`, all eleven components, and `reuse_key_sha256` from the exact postimplementation identities, while no key/component may occur in the actual receipt or semantic projection. For `operation:PUBLISH_V3`, `reuse_binding.outcome` and `actual_receipt.replay.outcome` are both `BUILT`, and both replay source fields are null. For `operation:REPLAY_V3`, `reuse_binding.outcome` is `REUSED|REBUILD_REQUIRED`, both replay source fields are non-null, that outcome equals the private replay receipt, and `actual_receipt.replay` remains the validated source generation's original semantic binding rather than being rewritten. In the replay branch the replay-source transaction equals the source envelope's semantic transaction, and the source event/envelope, full execution set, semantic artifact bodies, and provider-membership projection validate in both directions. A replay event's `actual_receipt`, build/execution/composition fields, and `provider_execution` identify that validated source execution; `operation:REPLAY_V3` and `replay_no_fresh_execution_claim:true` forbid treating them as a fresh provider launch or a new semantic generation.

`composition_provenance_digest = H({domain:"PROGRAM_FACTS_COMPOSITION_PROVENANCE_V1",semantic_binding_without_semantic_projection_or_null,execution_context,accepted_implementation,receipt_binding_sha256,replay_provenance,full_provenance_without_composition_provenance_digest,provider_execution})`. This preimage contains the exact runtime or fixture execution authority, exclusive complete reuse binding/key/components and replay source, accepted contract/production/PhaseIO/package/registry/adapter identities, receipt-section bindings, full build-plan, execution-set, terminal-roster, contribution-set, composition-authority, public artifact, full receipt, resolved-PhaseIO/launch/expanded-input, provider-attempt, tool, host, and containment identities/digests. `receipt_full_file_sha256` below is exactly `full_provenance.receipt.full_file_sha256`; `provenance_event_id = "pfpv-" || H({domain:"PROGRAM_FACTS_PROVENANCE_EVENT_V1",generation_id,transaction_id,composition_semantic_digest,composition_provenance_digest,receipt_full_file_sha256,publication_attempt_ordinal})[0:32]`. The PF-70 envelope is staged beneath the already-derived `arm_locator_id`; only after the event ID is closed may PF-80 register and materialize the immutable `<provenance_event_id>` path. Neither `replay_provenance`, its key/component hashes, full provenance digest, nor any member reachable only through them may appear in or be reached from the semantic preimage.

`provider_execution` is the closed union `{kind:PROVIDER_LAUNCHED,provider_id,capability_ids,host_tool_manifest:file_identity,host_tool_manifest_review:file_identity,containment_evidence:file_identity,containment_review:file_identity,execution_set:file_identity,launched_attempts:sorted unique [{attempt_id,expected_child_id,terminal:file_identity,raw_cas:file_identity}]}` or `{kind:NO_PROVIDER_LAUNCH,provider_id_or_null,no_launch_disposition:NOT_REQUESTED|FIXTURE_PUBLICATION_ONLY|TOOL_UNAVAILABLE|PLATFORM_ARCH_NOT_ACCEPTED|PLATFORM_PROCESS_SCOPE_UNPROVEN|PROVIDER_NOT_IMPLEMENTED,evidence:sorted nonempty [file_identity],host_tool_manifest_or_null,host_tool_manifest_review_or_null,execution_set:file_identity,child_count:0,containment_evidence:null,containment_review:null}`. `PROVIDER_LAUNCHED` is required exactly for the six scope rows carrying `EVM_PROVIDER_BASELINE`, with provider `evm.slither.typed`, the exact six EVM capability IDs in section 9.1, and the accepted Windows-amd64 or Linux-amd64 manifest/review and containment evidence/review. It is forbidden for every other row. Every launched attempt tuple must occur exactly once in the referenced execution set, and the execution set's provider/capability/build/terminal/raw projections must equal the receipt and composition authority in both directions. In `NO_PROVIDER_LAUNCH`, the execution set must contain zero provider attempts; the two host-tool fields are both non-null exactly for Windows-amd64/Linux-amd64 host rows and both null otherwise; nonempty evidence must prove the literal no-launch disposition, and null containment records that no child existed rather than omitting launched-child provenance.

The exact validator is `scripts/program_facts_runtime_v3_contracts.py::validate_program_facts_receipt_provenance_envelope_v1(receipt,envelope,accepted_inputs,execution_context,scope_row_or_null)`. It stable-reads every identity, recomputes the semantic digest/preimage and five IDs from semantic bodies alone, requires exact equality to the recomputed projection and receipt semantic fields, then independently recomputes the exclusive reuse-key preimage/components, replays `composition_provenance_digest` from every full identity/digest, and verifies `provenance_event_id`. The fixture branch requires the exact reviewed fixture authority and non-null scope row; the runtime branch requires a null scope row, exact equality to the receipt's reviewed runtime governance lineage, and a currently valid cutover admission. Branch or `PUBLISH_V3|REPLAY_V3` operation substitution is invalid. The validator requires exact equality to the contract-frozen registry, requires `accepted_inputs` to equal the accepted production-symbol/PhaseIO/package/host-tool/containment identities (and, for G3-09, the execution-evidence top level), and cross-checks every reuse component/source event, receipt tool, environment, attempt, terminal, raw-CAS, execution-set membership, adapter, capability, source, build, composition, publication, resolved-PhaseIO, launch, and expanded-input reference in both directions. Possession or equality of `composition_semantic_digest` proves only semantic byte identity and can never satisfy reuse-key, provider launch, attempt, execution-set, terminal, containment, or provenance validation. Missing, extra, null-in-launched, substituted, unreviewed, masked, or unequal provenance fails the applicable closed code `GOVERNANCE_IDENTITY_MISMATCH`, `TOOL_IDENTITY_MISSING`, `EXECUTION_AUTHORITY_MISMATCH`, `PLATFORM_PROCESS_SCOPE_UNPROVEN`, `REPLAY_KEY_MISMATCH`, or `RECEIPT_CROSS_BINDING`; a const-true `cross_bindings` flag alone proves nothing. Neither the oracle nor the semantic projection supplies postimplementation reuse or execution provenance.

The separately authored cross-check program imports the same small standard-library allowlist and neither oracle nor production. It recomputes exactly this 56-execution stratified roster:

```text
A00-PRIMARY A01-PRIMARY A15-PRIMARY A19-PRIMARY A22-PRIMARY A24-PRIMARY A26-PRIMARY A27-PRIMARY
B00-PRIMARY B01-PRIMARY B02-PRIMARY B04-PRIMARY B09-PRIMARY B14-PRIMARY B17-PRIMARY B23-PRIMARY B24-PRIMARY B27-PRIMARY B29-PRIMARY B31-PRIMARY
C00-T0_BASELINE-NATIVE C00-T1_TOOL_ABSENT-CLAUDE C00-T2_RAW_MALFORMED-CODEX
C08-T0_BASELINE-CLAUDE C16-T0_BASELINE-CODEX C24-T0_BASELINE-NATIVE
C32-T0_BASELINE-CLAUDE C40-T0_BASELINE-CODEX C01-T0_BASELINE-NATIVE
C18-T2_RAW_MALFORMED-CLAUDE C35-T1_TOOL_ABSENT-CODEX C47-T3_REPLAY-NATIVE
D00-PRIMARY D01-PRIMARY D04-PRIMARY D05-PRIMARY D06-PRIMARY D07-PRIMARY D10-PRIMARY D11-PRIMARY
E00-PRIMARY E03-PRIMARY E05-PRIMARY E08-AFTER_FILE_1 E08-AFTER_FILE_4 E10-PRIMARY E12-PRIMARY E15-PRIMARY
F00-PRIMARY F03-PRIMARY F05-PRIMARY F09-PRIMARY F10-PRIMARY F15-PRIMARY F18-PRIMARY F19-PRIMARY
```

The roster is stratified as 8 seed/governance, 12 primitive/runtime, 12 host/ecosystem/backend, 8 package/host, 8 crash/replay, and 8 security cases. It is selected by this literal roster, not pseudorandom sampling. Cross-check success requires identical expected-result bytes, payload/debt bytes, and semantic receipt projection bytes for all applicable members of the 56; neither cross-check may construct a full expected receipt or postimplementation provenance.

The acyclic lifecycle is exact:

1. the accepted compact seed lineage, stable R2 specification/review, public-v3 architecture/ownership/schemas/review, provider registry, and mutation contracts exist;
2. the fixture custodian creates the pre-freeze synthetic governance binding from only those preexisting identities, and an independent reviewer accepts it with the five fixed vectors above;
3. the fixture custodian creates the exact 160/691 execution-scope artifact from the literal case tables, creates the fixture-execution authority from that scope and the reviewed synthetic predecessor, and an independent reviewer accepts that authority with the eight fixed PFEA vectors; none of these three artifacts names a contract or release freeze;
4. oracle and cross-check authors, before production implementation, create oracle sources, payload/debt bytes and closed semantic receipt projections using that exact fixture-execution authority/scope row, the fixture manifest, denominator, and oracle manifest; they create no full expected receipt and no postimplementation provenance;
5. an independent reviewer executes all oracle self-vectors plus the exact 56 cross-check roster and writes `review_fixtures/program_facts_runtime_gate3/oracle/PROGRAM_FACTS_ORACLE_V1_PREIMPLEMENTATION_REVIEW.v1.json` under `program_facts_independent_review.v1.schema.json`, disposition `PASS_ORACLE_V1_FOR_RED_FIXTURES_ONLY`;
6. the preimplementation contract freeze in section 14 pins the already-reviewed synthetic binding/review, fixture execution scope/authority/review, oracle tree, fixture manifest, and denominator; none points back to that freeze;
7. production is implemented without importing/changing those artifacts, including the exact projection and provenance-validator symbols, and G3-08 records the production symbol, host/tool/containment, and package identities required by the fixture authority;
8. at G3-09, and only after the reviewed contract freeze and all G3-08 prerequisites validate, the runner exercises exactly the fixture-authority rows in fresh isolated execution roots, retains every full actual receipt, writes and validates its semantic projection and provenance envelope, runs the separate transport checks, and writes `review_fixtures/program_facts_runtime_gate3/execution/PROGRAM_FACTS_GATE3_EXECUTION_EVIDENCE.v1.json` under `program_facts_runtime_execution_evidence.v1.schema.json`;
9. the postimplementation release freeze at G3-10 pins the contract freeze, implementation, and completed execution evidence; and
10. final cutover review compares the already-bound actual evidence to the preimplementation expected identities.

The execution-evidence file is a closed object containing exactly:

```text
schema_version                 const plamen.program_facts_runtime_execution_evidence.v1
specification                  exact stable specification file_identity
contract_freeze                {freeze:file_identity,independent_review:file_identity}
fixture_execution              {scope:file_identity,authority:file_identity,independent_review:file_identity}
oracle_manifest                exact oracle-manifest file_identity
denominator                    exact denominator file_identity
production_inputs              {production_symbols:sorted unique [file_identity],phase_io_runtime_bindings:sorted unique [file_identity],package_closure:file_identity,host_toolchains:sorted unique [{manifest:file_identity,independent_review:file_identity}],containments:sorted unique [{evidence:file_identity,independent_review:file_identity}]}
receipt_validation_contracts   {semantic_projection_schema:file_identity,provenance_envelope_schema:file_identity,projector:{module:file_identity,symbol},provenance_validator:{module:file_identity,symbol}}
executions                     sorted unique [runtime_execution_evidence_row]
case_count                     const 160
execution_count                const 691
evidence_body_sha256           SHA-256(CJ(object without evidence_body_sha256))
```

An execution row contains exactly `{case_id,execution_id,test_node,execution_root,scope_row_sha256,actual_result,actual_files,actual_receipt_or_null,actual_semantic_projection_or_null,provenance_envelope_or_null,expected_result,comparison}`. Rows sort by `(UTF8(case_id),UTF8(execution_id))` and equal the denominator and fixture-scope execution-ID set in both directions. `test_node`, `execution_root`, and `scope_row_sha256` equal the exact reviewed scope row; `actual_result` is the file identity of `<execution_root>/actual_result.v1.json`, whose closed body is defined by `program_facts_runtime_execution_evidence.v1.schema.json#/$defs/runtime_actual_result` as exactly `{schema_version,exit_class,status,debt_codes,publication_effect,active_head_generation_relation,actual_files,actual_result_body_sha256}` with the same outcome enums/order rules as the expected-result schema; `actual_files` is the identical sorted unique set of actual public payload/debt/receipt files beneath that execution root; and `expected_result` equals the denominator/oracle identity. The three receipt fields are all non-null exactly when the oracle-manifest row has non-null `expected_receipt_semantic_projection` and that identity occurs in the expected result's file set, and are all null otherwise; partial presence is invalid. Projection/envelope sidecars are evidence, not members of `actual_files`, preventing a self-referential file set.

`comparison` is exactly `{authority_projection_expected_sha256_or_null,authority_projection_actual_sha256_or_null,authority_equal_or_null,semantic_receipt,provenance,transport,artifact_comparisons,result}`. For a receipt-producing row the authority digests are SHA-256 of `{governance_semantics,fixture_authority_semantics,authority}` from the expected and actual semantic projections and `authority_equal_or_null` is const true; for a non-receipt row all three are null. `semantic_receipt` is the closed union `{kind:COMPARED,expected_projection:file_identity,actual_projection:file_identity,expected_cf_sha256,actual_cf_sha256,result}` or `{kind:NOT_APPLICABLE}` and the compared branch passes only when the two `CF` byte strings and hashes are equal. `provenance` is `{kind:VALIDATED,envelope:file_identity,validator_module:file_identity,validator_symbol:validate_program_facts_receipt_provenance_envelope_v1,result}` or `{kind:NOT_APPLICABLE}` and the validated branch passes only on successful stable-read validation against the exact top-level `production_inputs`, fixture authority, and scope row. `transport` is `{kind:CHECKED,invocation_label,wrapper_file_identity_or_null,allowed_pointers:sorted unique [pointer],cross_invocation_vector_id_or_null,result}` or `{kind:NOT_APPLICABLE}`; its pointers equal the expected-result subset of the two closed transport pointers and are used only by the existing invocation/wrapper validation and C-trial cross-invocation equality checks, never to edit either semantic projection or validate provenance. All three applicable branches are mandatory exactly when a semantic receipt projection is expected; otherwise all three must be `NOT_APPLICABLE`.

`artifact_comparisons` is a sorted unique bijection between the expected and actual payload/debt files and each row is exactly `{logical_role,expected:file_identity,actual:file_identity,comparison_mode:EXACT_BYTES,result}`. It requires equal size/hash bytes; paths differ only by their already-bound expected versus execution roots and are paired by the closed payload/debt logical role, never by basename guessing. No full actual receipt is byte-compared to a synthetic or truncated expected receipt. For a receipt-producing row, the row result is `PASS` iff outcome fields match the expected result, authority equality is true, semantic receipt bytes pass, provenance validation passes, transport validation passes, and every payload/debt row passes. For a non-receipt row it is `PASS` iff outcome fields match, all three tagged checks are `NOT_APPLICABLE`, and the expected/actual file sets are both empty. Missing or null required evidence is `FAIL`; no component can be waived by another.

The top-level contract freeze must pin the byte-identical fixture scope/authority/review and both preimplementation schemas named by every row, while `production_inputs` and validator/projector module identities must equal the G3-08 identities used by the actual run. Thus postimplementation provenance remains complete and truthful, the six actual provider baselines are comparable to preimplementation semantics, and this evidence remains the acyclic G3-09 predecessor of G3-10 without production-consumer authority or fixture-root escape.

No oracle semantic projection depends on production or a later freeze. No release freeze is a prerequisite for G3-09, and no release freeze can retroactively change expected bytes. The oracle, manifest, expected bytes/projections, reviews, fixture authority, actual provenance envelopes, and execution evidence are absent today; readiness remains false.

### 12.2 Mutation-operation grammar

Every execution serializes an ordered `mutations` array under `rules/schemas/program_facts_runtime_mutation.v1.schema.json`, `$id=https://plamen.local/schemas/program_facts_runtime_mutation.v1.schema.json`. The schema root is an array whose `items.oneOf` contains exactly the 16 branches below. Every branch is an object with `additionalProperties:false`, requires `op` plus exactly its listed fields, and sets `op` with `const`; therefore zero, multiple, unknown, missing, and extra branches fail. The exact variants are:

| `op` | Exact additional required fields |
|---|---|
| `NONE` | none |
| `REPLACE_BYTES` | `path:portable_path`, `base64_bytes:Base64BytesV1` |
| `DELETE_FILE` | `path:portable_path` |
| `ADD_UNDECLARED_FILE` | `path:portable_path`, `base64_bytes:Base64BytesV1` |
| `SET_JSON` | `path:portable_path`, `json_pointer:string`, `value:canonical_fixture_json_value` |
| `DELETE_JSON` | `path:portable_path`, `json_pointer:string` |
| `DUPLICATE_JSON_KEY` | `path:portable_path`, `object_pointer:string`, `key:string`, `first_value:canonical_fixture_json_value`, `second_value:canonical_fixture_json_value` |
| `FLIP_AUTHORITY_BIT` | `path:portable_path`, `json_pointer:string` |
| `TRUNCATE_FILE` | `path`, `byte_offset:uint64` |
| `ALIAS_PATH` | `path`, `target_path`, `alias_kind:SYMLINK|REPARSE|HARDLINK|CASEFOLD` |
| `DRIFT_AFTER_STABLE_READ` | `path`, `replacement_base64:Base64BytesV1` |
| `SUBSTITUTE_REVIEWER` | `path:portable_path`, `principal_id:IdentifierV3` |
| `SET_HOST_PROFILE` | `host_profile` from the six-value host enum |
| `SET_INVOCATION_LABEL` | `label:NATIVE_DRIVER|LEGACY_CLAUDE_WRAPPER|FUTURE_CODEX_WRAPPER` |
| `CRASH_AFTER` | `marker` from the closed crash-marker enum, `occurrence:uint32` |
| `REPLAY_ACTIVE` | `active_head:file_identity`, `active_projection:file_identity or null` |

The crash-marker enum is exactly `CHECKPOINT_COMMIT`, `CHILD_ARM_COMMIT`, `PROVIDER_LAUNCH`, `PROVIDER_TERMINAL`, `COMPOSITION_COMMIT`, `IMMUTABLE_FILE_COMMIT`, `IMMUTABLE_SET_FSYNC`, `LEDGER_HEAD_CAS`, `ACTIVE_TEMP_FSYNC`, `ACTIVE_REPLACE`, and `CALLER_ACK`.

`canonical_fixture_json_value` is the section-3 canonical JSON value domain only: null, boolean, safe integer, valid-Unicode string, array of such values, or object with unique valid-Unicode keys and such values, all within section-3 limits. Binary floating point, decimal/exponent tokens, negative zero, NaN/infinity, lone surrogates, and duplicate object keys are forbidden in these carriers. Paths are portable fixture-root relative paths. Operations apply in listed order to a fresh fixture copy. JSON pointers use RFC 6901. `NONE` must be the sole mutation. Unknown variants/arguments, invalid tagged branches, or two mutations that target the same `(path,pointer)` without an explicitly ordered metamorphic relation are `ORACLE_OR_DENOMINATOR_INVALID`. Metamorphic cases contain `base_execution_id`, `relation_id`, serialized mutations, and exact expected file-digest relations; in-memory/generated mutations do not count.

Schema vectors are frozen at `review_fixtures/program_facts_runtime_gate3/primitives/mutation_union_vectors.v1.json` under `rules/schemas/program_facts_runtime_mutation_vector.v1.schema.json`. The roster has one positive and one missing/extra/type-invalid vector for each of 16 variants, plus unknown-op and multi-branch rejection: exactly 34 vectors, disposition `PASS_MUTATION_UNION_V1_CONTRACT_ONLY` in the preimplementation review.

### 12.3 Revised denominator and census

The old 148-record/676-execution denominator and the undercounted first R2 draft are rejected. R2 closure keeps exactly **160 case records** and requires **691 executions** because E08's four immutable-file crash occurrences are separate executions:

| Partition | IDs | Records | Executions |
|---|---|---:|---:|
| A seed/governance | `A00`-`A27` | 28 | 28 |
| B canonical/runtime lifecycle | `B00`-`B31` | 32 | 32 |
| C host/ecosystem/backend | `C00`-`C47` | 48 | 576 |
| D package/install/host carriers | `D00`-`D15` | 16 | 16 |
| E reuse/crash/migration/rollback | `E00`-`E15` | 16 | 19 |
| F security/authority | `F00`-`F19` | 20 | 20 |
| **Total** |  | **160** | **691** |

The materialized denominator path is:
`review_fixtures/program_facts_runtime_gate3/program_facts_runtime_acceptance_denominator.v2.json`.
The authoritative fixture-identity path is:
`review_fixtures/program_facts_runtime_gate3/fixtures/program_facts_runtime_fixture_manifest.v1.json`.

That file conforms to `program_facts_runtime_fixture_manifest.v1.schema.json` and contains exactly:

```text
schema_version       const plamen.program_facts_runtime_fixture_manifest.v1
specification        exact stable file_identity of this R2 specification
synthetic_governance exact reviewed section-12.1 binding file_identity
fixture_execution_scope     exact section-12.1 scope file_identity
fixture_execution_authority {authority:file_identity,independent_review:file_identity}
cases                sorted unique [fixture_case]
case_count           const 160
execution_count      const 691
manifest_body_sha256 SHA-256(CJ(object without manifest_body_sha256))
```

Each `fixture_case` contains exactly `{case_id,partition,fixture_root,fixture_files,test_node,executions}`. Cases sort by UTF-8 `case_id`; executions sort by UTF-8 `execution_id`. `fixture_root` is exactly `review_fixtures/program_facts_runtime_gate3/fixtures/<case_id>/`; `fixture_files` is a nonempty array sorted uniquely by `(UTF8(path),size_bytes,sha256)`, every path starts with that exact root, and its identities are the stable pre-mutation bytes. Each fixture execution contains exactly `{execution_id,execution_root,allowed_operations,input_file_identities,mutations,mutation_targets,expected_result}`. Its `execution_root` and sorted unique `allowed_operations` equal the same fields in the exact reviewed fixture-scope row; its input identities are a nonempty subset of `fixture_files` in the same sort order; `mutations` is the literal section-12.2 array; `expected_result` is the exact file identity beneath `oracle/expected/<case_id>/<execution_id>/expected_result.v1.json`; and `mutation_targets` is the unique array sorted by `(UTF8(path),null-before-string,UTF8(json_pointer_or_null))` and derived without prose aliases from the mutation fields: `{path,json_pointer_or_null}` for each `path`, `{target_path,null}` additionally for `ALIAS_PATH`, both replay file-identity paths for `REPLAY_ACTIVE`, and no target for `NONE`, `SET_HOST_PROFILE`, `SET_INVOCATION_LABEL`, or `CRASH_AFTER`. `json_pointer_or_null` is `json_pointer` for `SET_JSON`/`DELETE_JSON`/`FLIP_AUTHORITY_BIT`, `object_pointer` for `DUPLICATE_JSON_KEY`, and null otherwise. Every mutation path must be beneath `fixture_root`; `DELETE_FILE`, byte/JSON mutation, truncate, and drift paths must identify a listed existing file; `ADD_UNDECLARED_FILE` must identify an absent path before that ordered operation; and `ALIAS_PATH.target_path` must identify a listed existing file while `ALIAS_PATH.path` is absent before alias creation. Each JSON Pointer must resolve against the result of all prior operations, except `DELETE_JSON` may target the present member it removes. `fixture_files` equals the sorted union of all execution input identities for that case; no wildcard, directory identity, generated-at-test-time file, or prose path satisfies the manifest.

`test_node` is one exact literal per case and is derived only by this closed partition map:

```text
A -> scripts/test_program_facts_gate3_a_seed_governance.py::test_program_facts_gate3_case[<case_id>]
B -> scripts/test_program_facts_gate3_b_canonical_runtime.py::test_program_facts_gate3_case[<case_id>]
C -> scripts/test_program_facts_gate3_c_host_ecosystem_backend.py::test_program_facts_gate3_case[<case_id>]
D -> scripts/test_program_facts_gate3_d_package_host.py::test_program_facts_gate3_case[<case_id>]
E -> scripts/test_program_facts_gate3_e_reuse_crash_migration.py::test_program_facts_gate3_case[<case_id>]
F -> scripts/test_program_facts_gate3_f_security_authority.py::test_program_facts_gate3_case[<case_id>]
```

`<case_id>` is replaced by the exact row ID, so brackets and case are literal. Collection MUST yield exactly these 160 distinct nodes and each node MUST emit exactly the execution IDs bound to its manifest row.

The denominator conforms to `program_facts_runtime_acceptance_denominator.v2.schema.json` and contains exactly `schema_version`, `specification`, `synthetic_governance`, `fixture_execution_scope`, `fixture_execution_authority`, `oracle_manifest`, `fixture_manifest`, `cases`, `case_count`, `execution_count`, and `denominator_body_sha256`; `fixture_execution_authority` is exactly `{authority:file_identity,independent_review:file_identity}`. Cases are sorted by ID and contain `case_id`, `partition`, `requirement_ids`, `host_profile_or_null`, `ecosystem_or_null`, `test_node`, `fixture_root`, `fixture_files`, and `executions`. Each execution contains `execution_id`, `base_execution_id_or_null`, `relation_id_or_null`, `invocation_label`, `execution_root`, `allowed_operations`, `input_file_identities`, `mutations`, `mutation_targets`, and the exact expected-result file identity. The denominator's governance/authority/scope/manifest/case/test-node/file/mutation/target/execution projections MUST be byte-semantically equal to the fixture manifest and exact fixture-scope rows; either-direction missing/additional content is `ORACLE_OR_DENOMINATOR_INVALID`. Every non-C case except E08 has exactly one execution named `<case_id>-PRIMARY`; E08 has exactly the four execution IDs in section 12.6. C naming remains section 12.5.

Census is mechanical: reject duplicate IDs before set conversion; `missing = declared - executed`; `additional = executed - declared`; pass only when both are empty and counts are 160/691. Skip, xfail, deselection, retry-hidden-first-result, mock-only boundary, or unexpected result fails.

### 12.4 Exact A and B cases

Notation below is `ID | mutation | expected exit/status/debt/publication`. Expected canonical bytes are the oracle files pinned by the denominator.

```text
A00 | NONE with valid external seed receipt | PASS/ADMITTED/[]/NONE
A01 | FLIP /authority/booleans/audit | BLOCKED/FAILED/AUTHORITY_ESCALATION/NONE
A02 | FLIP /authority/booleans/canonical_write | BLOCKED/FAILED/AUTHORITY_ESCALATION/NONE
A03 | FLIP /authority/booleans/commit | BLOCKED/FAILED/AUTHORITY_ESCALATION/NONE
A04 | FLIP /authority/booleans/construction | BLOCKED/FAILED/AUTHORITY_ESCALATION/NONE
A05 | FLIP /authority/booleans/cutover | BLOCKED/FAILED/AUTHORITY_ESCALATION/NONE
A06 | FLIP /authority/booleans/execution | BLOCKED/FAILED/AUTHORITY_ESCALATION/NONE
A07 | FLIP /authority/booleans/merge | BLOCKED/FAILED/AUTHORITY_ESCALATION/NONE
A08 | FLIP /authority/booleans/network | BLOCKED/FAILED/AUTHORITY_ESCALATION/NONE
A09 | FLIP /authority/booleans/package | BLOCKED/FAILED/AUTHORITY_ESCALATION/NONE
A10 | FLIP /authority/booleans/promotion | BLOCKED/FAILED/AUTHORITY_ESCALATION/NONE
A11 | FLIP /authority/booleans/provider | BLOCKED/FAILED/AUTHORITY_ESCALATION/NONE
A12 | FLIP /authority/booleans/recovery | BLOCKED/FAILED/AUTHORITY_ESCALATION/NONE
A13 | FLIP /authority/booleans/release | BLOCKED/FAILED/AUTHORITY_ESCALATION/NONE
A14 | FLIP /authority/booleans/runner | BLOCKED/FAILED/AUTHORITY_ESCALATION/NONE
A15 | FLIP /authority/booleans/runtime | BLOCKED/FAILED/AUTHORITY_ESCALATION/NONE
A16 | REPLACE seed byte, preserve declared hash | BLOCKED/FAILED/SEED_IDENTITY_MISMATCH/NONE
A17 | TRUNCATE seed | BLOCKED/FAILED/SEED_IDENTITY_MISMATCH/NONE
A18 | substitute r11 R19 plan path/bytes | BLOCKED/FAILED/SEED_IDENTITY_MISMATCH/NONE
A19 | DELETE external seed receipt | BLOCKED/FAILED/GOVERNANCE_MISSING/NONE
A20 | SUBSTITUTE_REVIEWER with seed author | BLOCKED/FAILED/SELF_CERTIFICATION/NONE
A21 | SET disposition to runtime acceptance | BLOCKED/FAILED/AUTHORITY_ESCALATION/NONE
A22 | root+nested Base64 matrix including AB, padding, pad bits | PASS/VALIDATED/[]/NONE
A23 | SET validator symbol VALIDATE_OPAQUE | BLOCKED/FAILED/VALIDATOR_UNKNOWN/NONE
A24 | multi-branch errors reversed at carrier input | PASS/ORDERED/[]/NONE
A25 | duplicate then missing/additional denominator IDs | BLOCKED/FAILED/ORACLE_OR_DENOMINATOR_INVALID/NONE
A26 | remove serialized mutation carrier from metamorphic row | BLOCKED/FAILED/ORACLE_OR_DENOMINATOR_INVALID/NONE
A27 | SET embedded self/predicted receipt as acceptance identity | BLOCKED/FAILED/SELF_CERTIFICATION/NONE

B00 | canonical positive document | PASS/VALIDATED/[]/NONE
B01 | DUPLICATE_JSON_KEY | BLOCKED/FAILED/DUPLICATE_KEY/NONE
B02 | REPLACE_BYTES with Base64 `eyJuIjoxLjV9` (valid JSON bytes `{"n":1.5}`, forbidden non-integer profile) | BLOCKED/FAILED/INVALID_NUMBER/NONE
B03 | REPLACE_BYTES invalid UTF-8/lone surrogate | BLOCKED/FAILED/INVALID_UTF8_OR_SURROGATE/NONE
B04 | add BOM/noncanonical escapes/whitespace | BLOCKED/FAILED/NONCANONICAL_JSON/NONE
B05 | SET path ../escape | BLOCKED/FAILED/INVALID_PATH/NONE
B06 | ALIAS_PATH CASEFOLD | BLOCKED/FAILED/ROOT_ESCAPE_OR_ALIAS/NONE
B07 | ALIAS_PATH SYMLINK then REPARSE carrier | BLOCKED/FAILED/ROOT_ESCAPE_OR_ALIAS/NONE
B08 | ALIAS_PATH HARDLINK | BLOCKED/FAILED/ROOT_ESCAPE_OR_ALIAS/NONE
B09 | DRIFT_AFTER_STABLE_READ source | BLOCKED/FAILED/STABLE_READ_DRIFT/NONE
B10 | ADD_UNDECLARED_FILE source | BLOCKED/FAILED/SOURCE_UNDECLARED/NONE
B11 | exact one-provider selection | PASS/SELECTED/[]/NONE
B12 | add equal-priority provider | BLOCKED/FAILED/REGISTRY_AMBIGUOUS/NONE
B13 | delete host executable digest | BLOCKED/FAILED/TOOL_IDENTITY_MISSING/NONE
B14 | exact child roster/derived authority | PASS/ARMED/[]/NONE
B15 | DELETE expected child terminal path | BLOCKED/FAILED/CHILD_ROSTER_INVALID/NONE
B16 | ADD_UNDECLARED_FILE WTx child | BLOCKED/FAILED/CHILD_ROSTER_INVALID/NONE
B17 | duplicate role/ordinal or path | BLOCKED/FAILED/CHILD_ROSTER_INVALID/NONE
B18 | REPLACE raw CAS bytes | BLOCKED/FAILED/RAW_CAS_MISMATCH/NONE
B19 | SET terminal zero true with live child | BLOCKED/FAILED/WTX_TERMINAL_INVALID/NONE
B20 | exact manifest expansion | PASS/RECONCILED/[]/NONE
B21 | add unregistered manifest member | BLOCKED/FAILED/CHILD_ROSTER_INVALID/NONE
B22 | exact contribution normalization | PASS/COMPOSED/[]/NONE
B23 | same fact ID, unequal body | BLOCKED/FAILED/COMPOSITION_COLLISION/NONE
B24 | same `evm.slither.typed` provider emits two provenance-bound contributions for build variants `evm-build-debug` and `evm-build-optimized`, same call-site semantic key but unequal target node IDs and distinct raw-evidence hashes | DEGRADED/DEGRADED/PROVIDER_DISAGREEMENT/PUBLISH_NEW_SELECTED; disagreement preserves both contribution IDs, both build variants, singleton provider/capability sets, and selects no truth
B25 | permute contribution arrival order | PASS/WRITTEN/[]/PUBLISH_NEW_SELECTED; bytes equal base
B26 | exact receipt/tx/prestate binding | PASS/WRITTEN/[]/PUBLISH_NEW_SELECTED
B27 | change payload after receipt close | BLOCKED/FAILED/RECEIPT_CROSS_BINDING/PRESERVE_PRIOR
B28 | change debt after receipt close | BLOCKED/FAILED/RECEIPT_CROSS_BINDING/PRESERVE_PRIOR
B29 | complete five-file+active-head+projection publish | PASS/WRITTEN/[]/PUBLISH_NEW_SELECTED
B30 | CRASH_AFTER immutable file occurrence 3 | BLOCKED/FAILED/PUBLICATION_TORN_OR_DRIFTED/PRESERVE_PRIOR
B31 | REPLAY_ACTIVE exact ArtifactLedger head and equal projection | PASS/REUSED/[]/REUSE_EXISTING
```

### 12.5 Exact C grid

Host order is Windows amd64, Windows arm64, Linux amd64, Linux arm64, macOS amd64, macOS arm64. Ecosystem order is EVM, GO, RUST, SOLANA, SOROBAN, APTOS, SUI, DAML. Pipeline is deterministically SC for EVM/SOLANA/SOROBAN/APTOS/SUI and L1 for GO/RUST/DAML; the denominator never constructs an invalid pipeline/ecosystem pair. `C%02d = host_index*8 + ecosystem_index`; this yields C00-C47 without gaps.

Every C record has trials `T0_BASELINE`, `T1_TOOL_ABSENT`, `T2_RAW_MALFORMED`, and `T3_REPLAY`, each invoked as `NATIVE_DRIVER`, `LEGACY_CLAUDE_WRAPPER`, and `FUTURE_CODEX_WRAPPER`, in that order: 12 executions per record. Execution ID is `<case>-<trial>-<NATIVE|CLAUDE|CODEX>`.

For EVM on Windows-amd64/Linux-amd64, T0 is `PASS/WRITTEN/[]/PUBLISH_NEW_SELECTED`; T1 deletes the frozen host tool and is `DEGRADED/UNAVAILABLE/TOOL_UNAVAILABLE/PUBLISH_NEW_SELECTED`; T2 replaces raw output with the oracle malformed carrier and is `DEGRADED/UNAVAILABLE/RAW_OUTPUT_MALFORMED/PUBLISH_NEW_SELECTED`; T3 replays T0 and is `PASS/REUSED/[]/REUSE_EXISTING`.

For EVM on either arm64 host, T0-T2 are `NOT_IMPLEMENTED/NOT_IMPLEMENTED/PLATFORM_ARCH_NOT_ACCEPTED/PUBLISH_NEW_SELECTED` and do not launch; T3 reuses T0. For EVM on either macOS host, the same rule uses `PLATFORM_PROCESS_SCOPE_UNPROVEN`. For every non-EVM ecosystem on every host, T0-T2 use `PROVIDER_NOT_IMPLEMENTED` and no launch; T3 reuses T0. T1/T2 fixtures for no-launch cells are deliberately unreachable and expected bytes prove they were not consumed.

Within each trial, all three invocation labels have identical payload/debt bytes and semantic receipt projection. Only the two allowed `nonsemantic_transport` pointers differ.

### 12.6 Exact D, E, and F cases

```text
D00 | clean source-archive/runtime closure | PASS/PACKAGE_READY/[]/NONE
D01 | DELETE nested v3 schema | BLOCKED/NOT_READY/PACKAGE_CLOSURE_MISSING/NONE
D02 | ADD_UNDECLARED_FILE colliding module | BLOCKED/NOT_READY/PACKAGE_CLOSURE_COLLISION/NONE
D03 | offline locked-wheelhouse install | PASS/PACKAGE_READY/[]/NONE
D04 | windows-amd64 clean install carrier | PASS/PACKAGE_READY/[]/NONE
D05 | windows-amd64 missing WFP/Job evidence | NOT_IMPLEMENTED/NOT_READY/PLATFORM_PROCESS_SCOPE_UNPROVEN/NONE
D06 | windows-arm64 explicit carrier | NOT_IMPLEMENTED/NOT_READY/PLATFORM_ARCH_NOT_ACCEPTED/NONE
D07 | linux-amd64 clean install/namespace carrier | PASS/PACKAGE_READY/[]/NONE
D08 | linux-amd64 missing cgroup/netns evidence | BLOCKED/NOT_READY/PLATFORM_PROCESS_SCOPE_UNPROVEN/NONE
D09 | linux-arm64 explicit carrier | NOT_IMPLEMENTED/NOT_READY/PLATFORM_ARCH_NOT_ACCEPTED/NONE
D10 | macos-amd64 explicit carrier | NOT_IMPLEMENTED/NOT_READY/PLATFORM_PROCESS_SCOPE_UNPROVEN/NONE
D11 | macos-arm64 explicit carrier | NOT_IMPLEMENTED/NOT_READY/PLATFORM_PROCESS_SCOPE_UNPROVEN/NONE
D12 | legacy-Claude installed semantic closure | PASS/PACKAGE_READY/[]/NONE; digest equals native
D13 | future-Codex installed semantic closure | PASS/PACKAGE_READY/[]/NONE; digest equals native
D14 | doctor with one-byte dependency drift | BLOCKED/NOT_READY/PACKAGE_CLOSURE_DRIFT/NONE
D15 | uninstall then injected owned survivor | BLOCKED/NOT_READY/PACKAGE_UNINSTALL_SURVIVOR/NONE

E00 | exact reuse key/active-head generation | PASS/REUSED/[]/REUSE_EXISTING
E01 | SET one reuse component | REBUILD_REQUIRED/STALE/REPLAY_KEY_MISMATCH/NONE
E02 | replay with public directory read-only | PASS/REUSED/[]/REUSE_EXISTING
E03 | CRASH_AFTER checkpoint before arm | BLOCKED/FAILED/INTERNAL_FAILURE/PRESERVE_PRIOR
E04 | CRASH_AFTER child arm before launch | BLOCKED/FAILED/INTERNAL_FAILURE/PRESERVE_PRIOR
E05 | CRASH_AFTER PROVIDER_LAUNCH occurrence 0, before any terminal record | BLOCKED/FAILED/WTX_TERMINAL_INVALID/PRESERVE_PRIOR
E06 | CRASH_AFTER PROVIDER_TERMINAL occurrence 0 before PF-50 reconcile, with a valid durable terminal | PASS/WRITTEN/[]/PUBLISH_NEW_SELECTED after deterministic PF-50 recovery; reuse the authenticated terminal and do not relaunch the provider
E07 | CRASH_AFTER composition before publication arm | BLOCKED/FAILED/INTERNAL_FAILURE/PRESERVE_PRIOR
E08-AFTER_FILE_1 | CRASH_AFTER IMMUTABLE_FILE_COMMIT occurrence 1 | BLOCKED/FAILED/PUBLICATION_TORN_OR_DRIFTED/PRESERVE_PRIOR
E08-AFTER_FILE_2 | CRASH_AFTER IMMUTABLE_FILE_COMMIT occurrence 2 | BLOCKED/FAILED/PUBLICATION_TORN_OR_DRIFTED/PRESERVE_PRIOR
E08-AFTER_FILE_3 | CRASH_AFTER IMMUTABLE_FILE_COMMIT occurrence 3 | BLOCKED/FAILED/PUBLICATION_TORN_OR_DRIFTED/PRESERVE_PRIOR
E08-AFTER_FILE_4 | CRASH_AFTER IMMUTABLE_FILE_COMMIT occurrence 4 | BLOCKED/FAILED/PUBLICATION_TORN_OR_DRIFTED/PRESERVE_PRIOR
E09 | CRASH_AFTER all required generation/event files before ledger | BLOCKED/FAILED/LEDGER_BINDING_INVALID/PRESERVE_PRIOR
E10 | CRASH_AFTER LEDGER_HEAD_CAS before ACTIVE materialization | PASS/WRITTEN/ACTIVE_PROJECTION_REPAIR_REQUIRED/PUBLISH_NEW_SELECTED after head-led repair
E11 | CRASH_AFTER ACTIVE_TEMP_FSYNC before replace | PASS/WRITTEN/ACTIVE_PROJECTION_REPAIR_REQUIRED/PUBLISH_NEW_SELECTED after head-led repair
E12 | CRASH_AFTER ACTIVE_REPLACE before ack | PASS/WRITTEN/[]/PUBLISH_NEW_SELECTED after head-led reopen
E13 | concurrent transaction changes ledger-head prestate | BLOCKED/STALE/PUBLICATION_PRESTATE_STALE/PRESERVE_PRIOR
E14 | private v1 read-old/write-v2 new-generation migration | PASS/WRITTEN/[]/PUBLISH_NEW_SELECTED
E15 | trigger rollback flag | PASS/LEGACY_OR_NO_SIDECAR/ROLLBACK_ACTIVE/NONE; consumers false

F00 | portable relative root escape | BLOCKED/FAILED/ROOT_ESCAPE_OR_ALIAS/NONE
F01 | symlink/reparse root escape | BLOCKED/FAILED/ROOT_ESCAPE_OR_ALIAS/NONE
F02 | hardlink source alias | BLOCKED/FAILED/ROOT_ESCAPE_OR_ALIAS/NONE
F03 | inject secret-named environment value | BLOCKED/FAILED/SECRET_ENVIRONMENT/NONE
F04 | redaction-digest collision carrier | BLOCKED/FAILED/SECRET_ENVIRONMENT/NONE
F05 | provider network connect fixture | DEGRADED/UNAVAILABLE/NETWORK_BOUNDARY_DENIED/PUBLISH_NEW_SELECTED
F06 | exceed CPU/wall policy | DEGRADED/UNAVAILABLE/RESOURCE_LIMIT/PUBLISH_NEW_SELECTED
F07 | exceed memory/process policy | DEGRADED/UNAVAILABLE/RESOURCE_LIMIT/PUBLISH_NEW_SELECTED
F08 | exceed raw/output size | DEGRADED/UNAVAILABLE/RESOURCE_LIMIT/PUBLISH_NEW_SELECTED
F09 | shell metacharacters in typed argv | BLOCKED/FAILED/SHELL_INTERPOLATION_FORBIDDEN/NONE
F10 | replace executable after inventory | BLOCKED/FAILED/TOOL_IDENTITY_MISSING/NONE
F11 | hostile JSON depth/string/array limits | BLOCKED/FAILED/LIMIT_EXCEEDED/NONE
F12 | provider chooses output path | BLOCKED/FAILED/WTX_TERMINAL_INVALID/NONE
F13 | provider chooses fact/debt ID | BLOCKED/FAILED/CONTRIBUTION_INVALID/NONE
F14 | target supplies module/schema/plugin | BLOCKED/FAILED/VALIDATOR_UNKNOWN/NONE
F15 | inject expected finding/grader truth | BLOCKED/FAILED/GROUND_TRUTH_CONTAMINATION/NONE
F16 | runtime emits its own review receipt | BLOCKED/FAILED/SELF_CERTIFICATION/NONE
F17 | oracle/production/reviewer principal collision | BLOCKED/FAILED/SELF_CERTIFICATION/NONE
F18 | flip any v3 receipt authority ceiling | BLOCKED/FAILED/AUTHORITY_ESCALATION/PRESERVE_PRIOR
F19 | semantic consumer requests v3 facts at Gate 3 | BLOCKED/DENIED/CONSUMER_AUTHORITY_FALSE/NONE
```

Codes used in expected results but not public debt are closed test/control exit codes in the denominator schema. Their exact ordinals are already fixed in section 3.5. Public debt contains only applicable provider/platform conditions; the same token may appear in the control result without thereby becoming semantic authority.

## 13. Security and no-self-certification

Runtime and package enforce enumerated roots, stable physical reads, no-follow opens, path/case/alias collision rejection, deny-by-default environment/handles/network, exact executable/transitive identities, bounded resources, typed argv with no shell, hostile raw-data parsing, no target-supplied code/schema/plugin, and no absolute paths/secrets/prompts/grader truth in semantic artifacts.

Providers cannot choose IDs, paths, ledger records, schemas, or authority. No absence or degraded state certifies clean. The production runner cannot import the oracle; the oracle cannot import production; neither can issue an independent review. CI success, author tests, embedded `PASS`, generated counts, or a model response are diagnostics only.

## 14. Governance, freeze, and independent review workflow

### 14.1 Specification and architecture review before implementation

After this file reaches a stable hash, an independent reviewer creates:

`review_fixtures/program_facts_runtime_gate3/spec_reviews/PROGRAM_FACTS_RUNTIME_CUTOVER_SPEC_R2_INDEPENDENT_REVIEW.v1.json`

Its exact source-pin evidence is `review_fixtures/program_facts_runtime_gate3/spec_reviews/program_facts_runtime_cutover_spec_r2_source_identity_census.v1.json` under `program_facts_source_identity_census.v1.schema.json`, a closed object containing exactly:

```text
schema_version               const plamen.program_facts_source_identity_census.v1
specification                exact stable specification file_identity
non_seed_identities          sorted unique [file_identity]
non_seed_identity_count      const 42
seed_construction_identities sorted unique [file_identity]
seed_construction_count      const 3
all_identities               sorted unique [file_identity]
all_identity_count           const 45
census_body_sha256           SHA-256(CJ(object without census_body_sha256))
```

The three seed/construction identities are exactly the section-1.1 R19 seed, `generate_r19.py`, and `test_r19_contract.py`. The 42 non-seed identities are exactly S01, S02, S03, S06, S07, S08, S09, and S10 (8); the three S11 pins (11 cumulative); S12 and S13 (13); the nine S14 pins (22); S15 (23); the ten S16 pins (33); the eight S17 pins (41); and the ownership-v1 predecessor identity stated after S17 (42). The two arrays are disjoint, `all_identities` equals their exact set union sorted by `(path,size_bytes,sha256)`, and stable reads must match all 45 path/size/hash triples. Duplicate, missing, additional, changed, or cross-class identities reject the census.

The independent review contains the exact specification file identity, reviewer principal/independence, the eight section-18 repair findings and dispositions, the census file identity, open findings, and disposition `PASS_FOR_RED_FIXTURE_AND_IMPLEMENTATION_ONLY`. Its vector set is exactly `SPEC-R2-01-BUILD-PLAN-DAG`, `SPEC-R2-02-RECEIPT-PROVIDER-CROSS-REFERENCES`, `SPEC-R2-03-DISABLED-HEAD-TRANSITION`, `SPEC-R2-04-SCHEMA-EVALUATION-NORMALIZATION`, `SPEC-R2-05-PRE-FREEZE-EXPECTED-BYTES-GOVERNANCE`, `SPEC-R2-06-HOST-RUNTIME-CLOSURE`, `SPEC-R2-07-FIXTURE-160-691`, `SPEC-R2-08-OWNERSHIP-CONVERSION`, `SPEC-R2-09-SOURCE-PINS`, and `SPEC-R2-10-AUTHORITY-CEILING`. Admission requires all ten exactly once and `PASS` with nonempty evidence identities, exactly eight closed repair findings, exact equality to the 45-identity census above, no open blocking finding, reviewer independence, and the exact subject file identity/disposition. The `SPEC-R2-09-SOURCE-PINS` vector's evidence array is exactly the census file identity. The review grants no runtime/cutover authority. Production implementation cannot begin until this receipt, the seed receipt in section 1.2, and the public-v3 architecture receipt in section 2.1 all pass.

### 14.2 Preimplementation contract freeze

After the section-12 oracle preimplementation review passes and before any production file is created or changed for Gate 3, the contract custodian creates `rules/program-facts-runtime-contract-freeze.v1.json` under `rules/schemas/program_facts_runtime_contract_freeze.v1.schema.json`. The closed freeze contains exactly:

```text
schema_version                 const plamen.program_facts_runtime_contract_freeze.v1
freeze_id                      pfcf-<32hex>
lifecycle                      const PREIMPLEMENTATION_CONTRACT_FROZEN
specification                  file_identity plus spec-review file_identity
seed                           compact seed-admission/review identities plus exact out-of-band seed digest linkage
architecture                   graph-v2, ownership-v2, public-v3 schema identities plus architecture review
ownership_and_phase_io         accepted owner rows, work-unit keys, output RACI, operation ordering digests
gate3_stage_order              exact 13-row G3-00 through G3-12 sequence and body digest from section 15
primitive_contracts            section-3 profile/error/schema-vector definitions and schema identities
mutation_contract              mutation schema/vector/independent-review identities
provider_host_contracts        provider-registry-v2 and host-policy/schema definitions only
fixture_execution              {scope:file_identity,authority:file_identity,independent_review:file_identity,allowed_stage:G3_09,authority_ceiling_sha256:hex64}
oracle                         {synthetic_governance:file_identity,synthetic_governance_review:file_identity,fixture_execution_scope:file_identity,fixture_execution_authority:file_identity,fixture_execution_authority_review:file_identity,semantic_projection_schema:file_identity,provenance_envelope_schema:file_identity,oracle:file_identity,crosscheck:file_identity,manifest:file_identity,fixture_manifest:file_identity,preimplementation_review:file_identity,expected_tree_sha256:hex64,expected_members:sorted unique [file_identity]}
denominator                    denominator file_identity, fixture-manifest file_identity, case_count=160, execution_count=691
authority_ceiling              all semantic/consumer/cutover booleans false; implementation_allowed=true only
freeze_body_sha256             SHA-256(CJ(object without freeze_body_sha256))
```

`fixture_execution` exactly duplicates the reviewed authority lineage used by the oracle projections and authorizes no stage other than fixture-root G3-09 execution; its authority-ceiling digest is over the full section-12.1 ceiling object. `expected_members` is exactly the sorted union of all 691 expected-result identities and all expected payload/debt/semantic-projection file identities named by them; a full expected receipt and provenance envelope are forbidden. `expected_tree_sha256 = SHA-256(CJ(expected_members))`. It must equal the oracle manifest/fixture-manifest/denominator bidirectional projection, so the freeze binds the complete expected oracle tree rather than a directory or wildcard. The contract freeze pins both closed comparison schemas but MUST NOT contain production-module hashes, PhaseIO implementation hashes, WTx/Ledger implementation hashes, installed-tool/executable identities, host containment execution evidence, package closure, actual provenance envelopes, denominator execution results, soak results, or a release reviewer. Those bytes do not exist at this lifecycle point. A reviewer then writes `review_fixtures/program_facts_runtime_gate3/governance/PROGRAM_FACTS_RUNTIME_CONTRACT_FREEZE_V1_INDEPENDENT_REVIEW.v1.json` with disposition `PASS_GATE3_CONTRACT_FREEZE_FOR_IMPLEMENTATION_ONLY`. Production implementation is blocked until both artifacts validate. They are immutable; any contract-input change requires a new contract-freeze version and fresh oracle review where expected bytes can change.

### 14.3 Postimplementation release freeze

After production, host evidence, package closure, and the exact 160/691 execution evidence exist, a release custodian creates `rules/program-facts-runtime-release-freeze.v1.json` under `rules/schemas/program_facts_runtime_release_freeze.v1.schema.json`. The closed freeze contains exactly:

```text
schema_version                 const plamen.program_facts_runtime_release_freeze.v1
freeze_id                      pfrf-<32hex>
lifecycle                      const POSTIMPLEMENTATION_RELEASE_FROZEN
contract_freeze                contract-freeze and its independent-review file identities
production_symbols             sorted [module file_identity,symbol,input schemas,output schemas,error codes,vectors]
phase_io_contracts             sorted [key domain,static profile digest,resolver module identity,launch policy,expanded-input policy]; no per-run dynamic path/digest
wtx_and_ledger                 protocol/module/schema identities and exclusive-operation bindings
provider_registry              unchanged contract-frozen registry file_identity plus external release authorization
host_toolchains                exactly windows-amd64 and linux-amd64 manifest/review identities
host_containment               exactly windows-amd64 and linux-amd64 evidence/review identities
host_dispositions              exact six-row section-9 table
package_closure                application version, Python, lock, wheelhouse, install and closure identities
execution_evidence             exact 160/691 evidence file_identity with recomputed semantic digest/five IDs, semantic-projection equality, exclusive full reuse-key/component replay in the provenance event, replayed full-provenance/event digests and execution-set membership, transport checks, and byte-identical contract-freeze/fixture-authority cross-links
rollout                        flag, stages, thresholds, retention, and rollback triggers from sections 7/9
cutover_reviewer               named eligible principal plus organizational-independence attestation
authority_ceiling              all semantic/consumer booleans false; shadow_producer_publisher=true only
release_body_sha256            SHA-256(CJ(object without release_body_sha256))
```

The release freeze cannot replace or weaken its contract-freeze parent and cannot change oracle expected bytes. A reviewer writes `review_fixtures/program_facts_runtime_gate3/governance/PROGRAM_FACTS_RUNTIME_RELEASE_FREEZE_V1_INDEPENDENT_REVIEW.v1.json` with disposition `PASS_GATE3_RELEASE_FREEZE_FOR_CUTOVER_REVIEW_ONLY`. Both files are write-once. Any listed byte change requires a new release-freeze version and review. This specification creates or approves neither freeze.

### 14.4 Common independent-review schema and dependency rule

Every intermediate review named in sections 1, 2, 9, 12, and 14, other than the section-1.2 external seed-acceptance receipt and the final cutover receipt, each of which has its dedicated schema, uses `rules/schemas/program_facts_independent_review.v1.schema.json`, a closed object containing exactly:

```text
schema_version                 const plamen.program_facts_independent_review.v1
review_id                      pfir-<32hex>
subject_kind                   SEED_ADMISSION|SPECIFICATION|ARCHITECTURE|PRE_FREEZE_FIXTURE_GOVERNANCE|PRE_RELEASE_FIXTURE_EXECUTION_AUTHORITY|ORACLE|MUTATION|CONTRACT_FREEZE|HOST_CONTAINMENT|RELEASE_FREEZE|CUTOVER
subjects                       sorted unique [file_identity]
input_artifacts                sorted unique [file_identity]
reviewer                       {principal_id,organization,role}
independence                   {subject_author_separate:true,production_implementer_separate:true,oracle_author_separate:true,workspace_clean:true,no_self_generated_evidence:true}
vectors                        sorted unique [{vector_id,result:PASS|FAIL,evidence:sorted unique [file_identity]}]
findings                       sorted unique [{finding_id,severity:BLOCKING|NONBLOCKING,status:OPEN|CLOSED,description,evidence:sorted unique [file_identity]}]
open_findings                  sorted unique [finding_id]
disposition                    closed passing/rejection enum
review_body_sha256             SHA-256(CJ(object without review_body_sha256))
```

`subjects` and `input_artifacts` sort by `(path,size_bytes,sha256)`, `vectors` by `vector_id`, `findings` by `finding_id`, and `open_findings` by UTF-8 `finding_id`; duplicates are invalid. `open_findings` MUST equal exactly the ordered IDs of findings whose status is `OPEN`. A passing disposition requires no open `BLOCKING` finding and all required vectors `PASS`. The passing enum is exactly `PASS_R19_SEED_ADMISSION_FOR_CONTRACT_FREEZE_ONLY`, `PASS_FOR_RED_FIXTURE_AND_IMPLEMENTATION_ONLY`, `PASS_PUBLIC_V3_SHADOW_CONTRACT_ONLY`, `PASS_PRE_FREEZE_SYNTHETIC_GOVERNANCE_FOR_EXPECTED_BYTES_ONLY`, `PASS_PRE_RELEASE_FIXTURE_EXECUTION_AUTHORITY_FOR_G3_09_ONLY`, `PASS_MUTATION_UNION_V1_CONTRACT_ONLY`, `PASS_ORACLE_V1_FOR_RED_FIXTURES_ONLY`, `PASS_GATE3_CONTRACT_FREEZE_FOR_IMPLEMENTATION_ONLY`, `PASS_LINUX_AMD64_GATE3_CONTAINMENT_ONLY`, `PASS_WINDOWS_AMD64_GATE3_CONTAINMENT_ONLY`, `PASS_GATE3_RELEASE_FREEZE_FOR_CUTOVER_REVIEW_ONLY`, and `PASS_GATE3_V3_SHADOW_PRODUCER_SELECTOR_ONLY`; the only nonpassing value is `REJECTED`. A review receipt may depend only on already-existing subjects and input artifacts. It never names, hashes, or is hashed into a later artifact that it purports to review; a later freeze may pin the completed review, but the review cannot pin that later freeze.

### 14.5 Cutover receipt and reviewer identity rule

The final receipt path is:
`review_fixtures/program_facts_runtime_gate3/PROGRAM_FACTS_RUNTIME_GATE3_INDEPENDENT_CUTOVER_RECEIPT.v1.json`.
Its only passing disposition is `PASS_GATE3_V3_SHADOW_PRODUCER_SELECTOR_ONLY`.

Reviewer `principal_id` grammar is `reviewer:<organization-slug>/<person-or-team-slug>`. The principal must be named in the release freeze, must not author/change the seed, spec, architecture amendment, oracle, denominator, production modules, schemas, host manifests, package closure, or expected bytes, must review from a clean independent checkout, and must not report to the production implementation owner for this release. Evidence contains commit authorship census, workspace identity, and organizational attestation. An unnamed future reviewer cannot pass; until the release freeze names one through its reviewed release inputs, readiness=false.

The cutover receipt pins the release freeze and its completed independent review, source tree/commit, 160/691 census, expected-byte comparison, two supported-host package/containment/tool results, backend equality, soak receipts, and all authority ceilings. It cannot authorize consumers, findings, severity, confidence, clean certification, non-EVM, arm64, or macOS.

## 15. Mandatory Gate-3 order

1. G3-00: independently accept the R19 seed construction receipt and compact seed admission, this stable R2 specification, the public-v3 architecture amendment, ownership-v2 representation, complete PhaseIO work-unit matrix, output RACI, and exclusive-operation order.
2. G3-01: before production, create/review all remaining section-4 private schemas, including the closed semantic-projection and postimplementation provenance-envelope schemas, plus the mutation/schema and PhaseIO static-profile vectors; materialize all 160 red fixture/test nodes; create/review the pre-freeze synthetic fixture-governance binding; then create the exact 160/691 fixture-execution scope and independently reviewed pre-release G3-09 fixture authority; only afterward create the independent oracle/cross-check, authority-bound expected payload/debt/projection bytes, exact fixture manifest, and denominator v2 and complete their preimplementation reviews. A full expected receipt is forbidden.
3. G3-02: create the immutable preimplementation contract freeze and its independent review; no production implementation may precede this point.
4. G3-03: implement canonical primitives, evaluators/validators, identity functions, limits, and error registry against the already-created frozen closed schemas and contract; no frozen schema changes are permitted.
5. G3-04: implement PF-10/PF-20 capture/planning with EVM-only and explicit no-launch dispositions.
6. G3-05: implement PF-30/PF-40 child-authority identities and both host containment boundaries.
7. G3-06: implement PF-50/PF-60 reconciliation/composition, including the exact semantic-contribution/full-contribution split, provenance-free composition semantic digest, and key-free replay outcome/source semantic binding, and implement and pin the already-accepted PhaseIO v3 registrations plus PF-70 private preparation. G3-06 MUST NOT amend owner rows, work-unit/RACI semantics, write final public paths, or feed a reuse key/component or other full provenance into a semantic ID.
8. G3-07: implement PF-80/PF-90 immutable semantic-generation reuse/collision checks, the exclusive exact reuse-key/component preimage inside append-only distinct provenance events, ArtifactLedger active-head CAS, ACTIVE projection, loader, replay, and recovery.
9. G3-08: build exact Python/tool/runtime locks, source archive, installs, doctor, uninstall, containment evidence, and package closure.
10. G3-09: without a release freeze, validate the reviewed contract freeze plus all G3-08 identities, execute exactly 691/691 scoped rows and the supported-host/backend checks under the pre-release fixture authority, retain full actual receipts, recompute the provenance-free semantic digest and five IDs, require raw byte equality of expected/actual semantic projections including authority and key-free replay semantics, independently recompute the exclusive full reuse key/components in each applicable event, replay every full provenance digest/event and exact provider execution-set membership, prove neither semantic equality nor a semantic digest was used as reuse/execution evidence, run the separate closed transport checks, require the conjunction of all checks, write the exact execution evidence, and resolve every unexpected result without changing oracle expectations to match a bug.
11. G3-10: consume that completed execution evidence to create the immutable postimplementation release freeze and its independent review.
12. G3-11: run the two shadow soaks against the exact release freeze.
13. G3-12: run independent cutover review and, only with the final receipt, enable the exact default-off flag for reviewed identities.

Later work cannot consume planned evidence. Gate 16 owns non-EVM implementation; Gate 17 owns macOS provider/package readiness. Consumers require a separate future gate.

## 16. Current blockers and exact non-cutover consequences

At authoring time all of the following are absent or unaccepted:

1. external R19 seed-acceptance receipt, compact seed admission/review, and their schemas;
2. public-v3 graph amendment, v3 schemas, owner-registry v2, and architecture review;
3. R2 specification independent review;
4. pre-freeze synthetic fixture governance/review, exact fixture-execution scope, pre-release G3-09 fixture authority/review, closed semantic-projection/provenance-envelope schemas, oracle, authority-bound expected payload/debt/projection tree, exact fixture manifest, denominator v2, and oracle review;
5. production modules/private schemas/error registry and their pins;
6. PhaseIO/WTx/Ledger v3 contracts and full digests;
7. accepted Windows/Linux containment and host tool manifests, including executable/transitive/solc digests;
8. CPython 3.12.10 Linux identity, runtime dependency lock, offline wheelhouse, application version, and closure v2;
9. preimplementation contract freeze/review, named eligible final reviewer, postimplementation release freeze/review; and
10. exact test evidence with full actual receipts/provenance envelopes and projection/transport comparisons, soak receipts, and cutover receipt.

Consequences are exact: readiness=false; no v3 work-unit registration; no provider launch under this contract; no ArtifactLedger v3 active-head commit or ACTIVE projection creation; feature flag absent/default false; v1 remains legacy read-only; v2 remains experimental/unselected; consumers remain false. These blockers do not make the implementation contract ambiguous.

## 17. Source and decision provenance

Normative decisions D01-D05 are governing task decisions. S01-S07 are canonical/history authorities with the stated ceilings. S08-S17 are identity-pinned design/current-state evidence only: they are not runtime inputs and cannot authorize implementation or cutover. Nothing is incorporated by mutable filename or wildcard. A `historical-corpus:` identifier is a stable, sanitized locator rather than a host filesystem path. The adjacent filename, byte count, and SHA-256 retain the exact identity of the historical evidence reviewed by this specification; they do not claim that a separately sanitized display copy has identical bytes.

| ID | Class | Exact source identity and use |
|---|---|---|
| D01 | Governing decision | r9 R19 accepted for seed construction only; missing independent receipt hard-blocks production implementation; no self-certification. |
| D02 | Superseded governing preference | Preserve public v1 if adequate. Independent review proved it inadequate; section 2 requires an explicit reviewed v3 amendment rather than silently violating v1. |
| D03 | Governing decision | Gate 3 EVM only; other ecosystems typed no-launch debt until Gate 16. |
| D04 | Governing decision | macOS readiness=false until Gate 17; portable fixtures still required. R2 also closes arm64 as no-release-claim. |
| D05 | Governing decision | Shadow producer/publisher only; consumers/finding/severity/confidence/phase authority false; rollback legacy/no-sidecar. |
| S01 | Canonical architecture | `architecture/ecosystem-graph-provider-contract.md`, 16,638 bytes, SHA-256 `2db7f1c77bf1776b7ebc00633e146e13a57ebbabf0675b05a151459a0ccb4342`. Governs until a section-2 successor is independently accepted. |
| S02 | Construction evidence | `review_fixtures/program_facts_runner_v3_r11/R11_EXECUTABLE_SUCCESSOR_IMPLEMENTATION_PLAN_R18.md`, 20,469 bytes, SHA-256 `f2a3a3b3109d113388fde1d396427320531b10bc12dc2049e235e1e1ba5b859f`. |
| S03 | Construction-only review | `review_fixtures/program_facts_runner_v3_r11/reviews/plan_independent_review_r18.json`, 11,819 bytes, SHA-256 `96860380091876d2f9feaf74fd22daa95423587d982196ad1c0f405881dadc0c`; all authority false. |
| S04 | Seed | r9 R19 path in section 1.1, 99,648,564 bytes, SHA-256 `a290e328f47b4802567f5d8f79fd9f6a2cfd4ec99809e4bfe8a300ad6486538e`. |
| S05 | Seed construction | `generate_r19.py` and `test_r19_contract.py` exact identities in section 1.1. |
| S06 | Blocked plan | r11 R19 path in section 1.1, 48,134 bytes, SHA-256 `667c1459e41cb44ca7d799b51d0ac79e3dbf983dcd932b5e100ccc0c56aabb4d`. |
| S07 | Blocking review | `review_fixtures/program_facts_runner_v3_r11/reviews/plan_independent_review_r19.json`, 14,390 bytes, SHA-256 `024a57f3edea4b99575250a0344db96774e6c73e3d722f2f70ea02f2c2e8ad99`. |
| S08 | Design evidence | `historical-corpus:PLAMEN-TYPED-CPG-BLUEPRINT-20260724` (`Plamen_Typed_CPG_Implementation_Blueprint_2026-07-24.md`), 63,282 bytes, SHA-256 `76178d78cadc6aaced63be66c272f85ad97b5320a2a0569369cc85e1c2a2a1bc`. |
| S09 | Blocked handoff evidence | `historical-corpus:PLAMEN-PROGRAM-FACTS-STAGE2-EMIT-ONLY-HANDOFF-20260729` (`Plamen_Program_Facts_Stage2_Emit_Only_Author_Handoff_2026-07-29.md`), 19,102 bytes, SHA-256 `45f2ad28c03724955fd37c5a795a88bf7330d31dfabf21dd6e65f732b8f5d3c4`. |
| S10 | Backend design evidence | `historical-corpus:PLAMEN-CLAUDE-CODEX-BACKEND-PARITY-BLUEPRINT-20260724` (`Plamen_Claude_Codex_Backend_Parity_Implementation_Blueprint_2026-07-24.md`), 80,718 bytes, SHA-256 `5fe66e35cc46a8bdf078b1b24b49889fd559e14c3e508cdf340ba57322a3028d`. |
| S11 | Routing/backend evidence | Three identities in the S11 table below; none is Program Facts runtime authority. |
| S12 | Active-EVM inventory | `review_fixtures/program_facts_stage2_active_evm_checkpoint_inventory_r2_20260730.md`, 36,257 bytes, SHA-256 `296fcaf75bf7e0725c1c7eff41f0eba4478b111e4642bca48153df957928ee0f`. |
| S13 | Checkpoints B/C review | `review_fixtures/program_facts_active_evm_checkpoints_bc_plan_independent_review_r2_1_20260730.md`, 18,247 bytes, SHA-256 `df19a25c36722edad0a2d1ea88bbed2a6a86e43d0228510bed3b5e8fb4a5dc50`. |
| S14 | Current typed boundaries | Nine exact identities in the S14 table below; implementation evidence only. |
| S15 | Current loader | `scripts/program_facts_loader.py`, 6,445 bytes, SHA-256 `76feb8afccfbe8e67ca3d123d436191fb178edfbe19f7c391de97cb293a4ce89`; v1 evidence only. |
| S16 | Experimental v2 mechanics | Ten exact module/schema identities in the S16 table below; unaccepted and never public authority. |
| S17 | Packaging baseline | Eight exact identities in the S17 table below; current-state evidence only. |

S11 exact pins:

| Source identity | Bytes | SHA-256 |
|---|---:|---|
| `historical-corpus:PLAMEN-BACKEND-MODEL-ROUTING-GUIDE-R2.5.2-20260730` (`Plamen_Backend_Model_Routing_Engineering_Guide_R2.5.2_2026-07-30.md`) | 12,645 | `826697b371143bb2ecf79544f30f72815564f4b988a61de66cb8975eb2db56eb` |
| `docs/codex-backend.md` | 5,289 | `98c271e1ed07c9f48e074fa58ae9f4b6d51fb7f234bb8879ffadfce667039a01` |
| `docs/terminal-legacy-claude-audits.md` | 4,590 | `3ee173a0f05460b36b8573d2c19bb32942e0462503d66d713dfd2da81127ce64` |

S14 exact pins:

| Path | Bytes | SHA-256 |
|---|---:|---|
| `scripts/program_facts_types.py` | 121,464 | `bf12bd163004eabc45c3e3d685c2c3d018a26c6e7c91be863f30fc7d4f31d685` |
| `scripts/program_facts_source_manifest.py` | 162,770 | `b534aa20e3a51dfc0f36e4856cd9a514a355687f80dba8e2634427859b63d494` |
| `scripts/program_facts_provider_registry.py` | 72,588 | `d622d2dfa4bfee26dd8d518a5aa2799e9dc948640b3231173f555a347c094041` |
| `scripts/program_facts_provider_api.py` | 160,056 | `ca1b02126bf957238573ea1257afedc0784be41a7c593e58d865534b6a88cf88` |
| `scripts/program_facts_bake.py` | 24,498 | `042ad7b92e4568b7685f8ed302cf5191cb29e7a56f776eee98482fc9fbfc8956` |
| `scripts/program_facts_driver_integration.py` | 26,962 | `0d7826682c72113860df003b9bc52a91131f00031ea382cbf250809e53f229f5` |
| `scripts/phase_io_contracts.py` | 349,682 | `f3d580f5f560c10e3337287dec18e6dac4d2d86289ad34346f7b39477d1ec3af` |
| `scripts/worker_transaction.py` | 150,510 | `47773f533a5e133626f4c3fb580af1fc53fc931832eab7bf07393c4508b52c35` |
| `scripts/artifact_ledger.py` | 523,963 | `baf2998ab5fc57c8a85d2551c61a4df46094ee907c564f652037cbb75ad8be97` |

S16 exact pins:

| Path | Bytes | SHA-256 |
|---|---:|---|
| `scripts/program_facts_publication.py` | 25,036 | `8a5994314d11881777fa27617311fc0fef90ed8ab8ee54e9900552019393be56` |
| `scripts/program_facts_evm_execution_set.py` | 35,281 | `46282f875b8ee64c79585f618db0a3d01349c90a6ccf398369b9ba2736c1a72f` |
| `scripts/program_facts_evm_environment_authority.py` | 15,443 | `54e5f035a41dc0d43fb208d3db1621e9335c2b49578fd1efbcc2af07085c3c8e` |
| `scripts/program_facts_evm_wtx.py` | 22,166 | `a6d476f29aad734c85eb6e181616b37166de7c2bec5bc2391b32757fd2930d70` |
| `scripts/program_facts_evm_provider.py` | 124,515 | `356783aa0cfeac2b7cdd731262dea3748994fc5adec3208d11d6fca6631c4981` |
| `rules/schemas/mechanical_program_facts.v2.schema.json` | 15,949 | `340028255808526e22f219821f081650cda677e7b8b1744fe581ca5c06402a45` |
| `rules/schemas/mechanical_program_facts_receipt.v2.schema.json` | 15,688 | `c6818a973576800b200e7ef7cbcef0f19f98177c4ed715eb4c87e5e16a52f5ef` |
| `rules/schemas/mechanical_program_facts_debt.v2.schema.json` | 5,417 | `98d198bc5b368feb04e561f3a7f04d9284f6714968fb0838d3fb2ba99b8ada91` |
| `rules/schemas/program_facts_public_generation.v1.schema.json` | 2,978 | `1861a5fa4b525c4d26b41caf176dbffa6ea9865cb8e31d5df0e2ef9d0d223f6e` |
| `rules/schemas/program_facts_publication_arm.v1.schema.json` | 4,802 | `5c24b6b35d09ae4a6462ad977914832309633c0ba8882f5d13c7e792a4c7c05f` |

S17 exact pins:

| Path | Bytes | SHA-256 |
|---|---:|---|
| `pyproject.toml` | 1,264 | `722b1322fb81c536e0204e0a9dd51cbad00918d138f0a8ae22bd828e6f893860` |
| `VERSION` | 7 | `8e75cb854a00a2d21cd0ed809fafe873e246841bc48be9e37cda683b1324e56a` |
| `requirements.txt` | 454 | `cb381a7a6d3987a297f31fc655c4c475414932add8fb025e02b36fc855398fe9` |
| `requirements-ci.lock` | 26,241 | `b50b7d11a9572bcde7cf1f12347586990367df25fa18f3ea02b041a95e7db7fc` |
| `scripts/test_public_packaging_freeze.py` | 23,812 | `9704aa5fdecd3d00b72be5ffa62e415342ae5f4c079a48dffff233b0480e0d4d` |
| `plamen.py` | 336,802 | `196e03cde43644fbf8e87201cbc10ad46af1db10e95225485fdc57b70ec6caeb` |
| `.github/workflows/install-smoke.yml` | 6,012 | `a7e97af285c7f222c2bba759e4c56d21ab4bd2305f05dc4c9aaf6ba27cfd3388` |
| `verification_policy/toolchain_runtime_closure.v1.json` | 59,542 | `7ca33afa1609b4e7c7f81ec7ff71c059e53ec7309c3c4f02db55958d4bc41501` |

The currently reviewed ownership registry itself is `architecture/canonical-requirement-ownership.v1.json`, 18,770 bytes, SHA-256 `04f7af72fbe840872ec2c00cfac7f28bb4823a98206e01c083df60f89350ca85`; it is predecessor evidence for the required v2 amendment, not v3 ownership authority.

## 18. Eight-residual implementation-readiness repair map

| Fresh implementation-readiness BLOCK | One-to-one R2 repair |
|---|---|
| 1. Cyclic/live EVM build-plan authority | Sections 4.1 and 5.2 define only `program_facts_evm_build_plan.v2` at its exact private path and freeze its input-only preimage/schema; expected children, ordinals/paths, execution/attempt/publication/generation/terminal fields are forbidden. The already-closed expected-child, execution-authority, and static-profile publication DAG remains downstream and acyclic. |
| 2. Receipt source/provider adapter ambiguity | Sections 2.6-2.8 make receipt `source` the aggregate `source_binding_group`, pin the exact EVM adapter module/symbol/file/tool policy and six capability semantics, require cross-artifact provider/capability/build/child/raw/contribution/receipt equality, and retain exactly seven unchanged typed placeholders. |
| 3. Legacy-disable head under-specified | Sections 2.7 and 7.2 define the exact `DISABLED_LEGACY` transition ID/preimage and a closed `ABSENT|PRESENT_ACTIVE|PRESENT_DISABLED` prior-head union without inventing generation/transaction paths for a disabled head; ArtifactLedger remains sole durable authority and ACTIVE remains projection only. |
| 4. Schema evaluator/mutation ambiguity | Sections 3.1.1, 3.5-3.6, 4.1, and 12.2 freeze Core+Applicator+Validation vocabularies/keywords, exact evaluator/normalizer symbols, keyword-specific normalized details and total order, and canonical-JSON-only mutation value carriers. |
| 5. Expected-receipt/contract-freeze cycle | Sections 2.7, 5.3, 6.2, 7.2, 8.2, 12.1, 14, and 15 retain synthetic governance only as non-launch construction lineage, freeze oracle payload/debt plus a closed preimplementation semantic receipt projection whose replay member contains only outcome and semantic-source body hashes, and derive all semantic/public IDs exclusively from a provenance-free `composition_semantic_digest`. G3-09 requires byte-identical expected/actual semantic projections including authority, separately recomputes the full reuse key/components and complete build/execution/composition provenance digest/envelope plus transport checks, and produces evidence without a release freeze for G3-10, so the split freezes and identity DAG remain closed and acyclic. |
| 6. Host runtime/loader containment incomplete | Section 9.3 defines exact Linux and Windows evidence tagged schemas, read-only CPython/stdlib/package/Slither/solc/native-loader closures inside the boundary, exact loader/import readbacks, Linux zero capabilities and Windows empty AppContainer capabilities/restricted privileges, with typed no-launch on any missing primitive or proof. |
| 7. 160/691 fixture identity and E06 ambiguity | Sections 12.3-12.6 freeze an exact fixture manifest with per-case file identities/test node and per-execution input identities/mutations/targets/expected identity, preserve the 160-record/691-execution census and C/E08 arithmetic, and classify E06 as recovery from a valid durable terminal without provider relaunch. |
| 8. OWN-v1 conversion/review admission incomplete | Sections 1.2, 1.2.1, 2.1, 2.4, and 14.1 fix OWN-v1 to OWN-v2 row conversion, status identity map, source/appended ordinals, tagged Markdown/JSON-Pointer anchors, exact ordering/digest rules, exact seed/spec/architecture vector admission criteria, and an exact disjoint 42 non-seed plus 3 seed/construction identity census whose union is 45. The accepted six-component 264-key PhaseIO matrix, DRIVER representation, PF-60 fixed aggregate, and default-off legacy-compatible v3 seam remain unchanged. |

### 18.1 Final one-item repair map

| Final readiness defect | Exact repair |
|---|---|
| Full reuse-key/component hashes leak postimplementation runtime/release/toolchain/environment/WTx/Ledger/package identities through `replay_semantics` into every semantic/public ID | Sections 2.7, 5.3, 7.2, 8.2, 12.1.1, 14.3, and 15 replace the semantic replay member with only the preimplementation-knowable outcome and provenance-free payload/debt source hashes, forbid reuse keys/components and all identity-derived hashes from the composition semantic preimage and five ID preimages, and place the exact closed reuse-key preimage, eleven component hashes, binding, and source execution event exclusively in the append-only full-provenance envelope. Validation recomputes both partitions independently, cross-binds outcome/source event/semantic IDs/full execution membership, and forbids semantic equality as reuse or execution proof. |

## 19. Explicit invariants and assumptions

The runtime invariants are: one snapshot/build identity; full provider/parser/tool/environment/raw/transitive provenance; WTx staging only; PhaseIO sole immutable-file/projection writer; ArtifactLedger sole durable active-head authority; ACTIVE is projection only; closed schemas; additive-only facts; truthful zero/degraded/debt; absence proves nothing; disagreement remains visible; exact reuse; no ground truth; model-free semantics; backend-portable payload/debt; and receipt authority only through an active-head ledger-bound generation. [S01]

There are no hidden readiness assumptions. SHA-256, CPython 3.12.10, public v3, the two candidate amd64 hosts, EVM-only scope, exact limits, and rollout thresholds are normative choices. Missing executable/tool/package/reviewer identities are explicit blockers in section 16, not placeholders that an implementer may choose differently. A change requires a new spec revision and independent review.

## 20. Non-goals and authority ceiling

This contract does not inspect or report vulnerabilities in an audit target, score or suppress findings, change legacy audit semantics, enable a consumer, certify a clean result, implement non-EVM providers, claim arm64/macOS provider support, authorize network access, or accept any runtime/package. Gate-3 authority, if eventually granted, is limited to the reviewed v3 shadow producer/publisher with ArtifactLedger active-head authority. Every other authority remains false.
