# Plamen GT-Blind RunBundle Evaluator Implementation Blueprint

**Date:** 2026-07-24  
**Status:** Implementation-ready architecture; no implementation or audit execution performed  
**Repositories inspected:**

- `<LOCAL_USER_ROOT>\plamen-codex-implementation`
  - observed HEAD: `67a0f85adc7a8169d79a286908b00bef7adb764a`
  - observed worktree: dirty (532 porcelain entries); this blueprint describes the observed worktree and does not claim a clean-HEAD reconstruction
- `<LOCAL_USER_ROOT>\<PRIVATE_EVALUATOR_REPO>`
  - observed HEAD: `345d016d0c86b6201e90cec908c37c6a66f739c3`
  - observed worktree: clean

No repository files were changed. This document is the only requested output artifact.

## 1. Executive decision

Implement a second, explicitly versioned RunBundle profile for real audit runs and preserve the existing synthetic profile unchanged:

- Existing synthetic profile: `plamen.run-bundle.synthetic.v1`
- New real-audit profile: `plamen.run-bundle.real-audit.v2`

Do not loosen the existing v1 validators to make real scratchpads fit. The current evaluator is a strong synthetic B0 control plane: strict JSON handling, closed schemas, staging and sealing, content-addressed import, independent match adjudication, deterministic scoring, paired case-cluster analysis, and publication gates already exist. The missing bridge is a GT-blind, loss-accounting exporter from real Plamen and comparator outputs into those controls.

The decisive trust split is:

```text
public runner domain                         evaluator-private domain
--------------------                         ------------------------
opaque case_id                               private GT issue/root roster
sanitized source commitment                  expected issue count
experiment/cell/seed                         private case lock
scratchpad and report                        forbidden-input identities
candidate and lineage evidence    ---->      blind matching/adjudication
public launch receipt                        signed isolation receipt
RunBundle seal                               scoring/comparison/publication
```

The public RunBundle must never contain, directly or indirectly:

- a GT path, GT digest, private case-lock digest, case name, expected issue count, expected severity, grader label, or reviewer result;
- a forbidden-input path, forbidden-input content digest, file identity, or private corpus token;
- a candidate-to-GT mapping or a GT root-cause identifier;
- an experiment outcome, winning-cell label, or post-run score.

The current `run_manifest.v1` field `benchmark_case_lock_sha256` cannot be reused for real runs because the present benchmark lock binds private GT material. Real-audit v2 must instead bind `public_case_lock_sha256`. The evaluator binds the corresponding private lock only after the sealed bundle is imported.

## 2. Scope and proof claims

### 2.1 In scope

- Harvest a real Plamen scratchpad and final `AUDIT_REPORT.md` without GT access.
- Preserve raw evidence, candidate occurrences, authorized alias decisions, negative/safety dispositions, verification state, and final-report projection.
- Localize `NEVER_FOUND`, `FOUND_WRONG_SAFE`, `FOUND_LOST`, `REPORT_LOSS`, success, and unobservable/debt states exactly.
- Compare recall, precision, severity, fragmentation, lifecycle retention, report quality, and efficiency.
- Support Plamen, Pashov V3 through a pinned adapter, and later additional systems through the same adapter protocol.
- Preserve previous user-run evidence and make interrupted export/import safely resumable.
- Support <PRIVATE_AUDIT_TARGET> and <PRIVATE_REGRESSION_TARGET> user-run workflows without Codex launching their expensive audits.
- Support multiple seeds, backend blocking, and matched-total or matched-per-channel budget parity.
- Define B0-local versus B1-external responsibilities without overstating either.

### 2.2 Out of scope

- Running <PRIVATE_AUDIT_TARGET>, <PRIVATE_REGRESSION_TARGET>, Pashov, Plamen, or any other audit.
- Creating or modifying GT.
- Treating <PRIVATE_AUDIT_TARGET> or <PRIVATE_REGRESSION_TARGET> as a governed publication corpus.
- Claiming that a filesystem copy plus a path check is an OS security boundary.
- Automatically inferring that two candidates share a root cause.
- Treating the current canonical finding IDs as GT root identities.
- Producing B1 evidence without the externally governed corpus, launcher, authorities, reviewers, keys, and comparator.

### 2.3 Normative language

`MUST`, `MUST NOT`, `SHOULD`, and `MAY` are implementation requirements. Any relaxed behavior must use a new schema/profile version rather than silently changing these meanings.

## 3. Observed baseline and gap

### 3.1 Production-side preparation

`scripts/terminal_audit_launch.py` is deliberately prepare-only:

| Current symbol | Line | Existing value |
|---|---:|---|
| `SEAL_SCHEMA` | 30 | `plamen.prior-audit-evidence-seal.v1` |
| `PREPARATION_SCHEMA` | 31 | `plamen.terminal-audit-preparation.v1` |
| `_forbidden_identity_boundary` | 175 | path/file-identity boundary |
| `_matches_forbidden_identity` | 201 | identity comparison |
| `_assert_no_forbidden_source_aliases` | 224 | source alias rejection |
| `discover_prior_audit_evidence` | 460 | conservative convention-based discovery |
| `_snapshot_evidence_root` | 515 | evidence-root snapshot |
| `_build_prior_evidence_seal` | 578 | prior-evidence seal payload |
| `seal_prior_audit_evidence` | 671 | external seal write |
| `verify_prior_audit_evidence_seal` | 681 | seal verification |
| `_copy_isolated_project` | 728 | fresh project copy excluding prior evidence |
| `_workspace_copy_rows` | 847 | copied-file roster |
| `_workspace_copy_issues` | 915 | copy validation |
| `_validate_preparation_roots` | 965 | root topology validation |
| `prepare_legacy_claude_run` | 989 | prepare fresh workspace/config/argv |
| `verify_preparation_receipt` | 1210 | receipt validation |
| `_main` | 1345 | CLI |

This code usefully seals prior evidence, rejects forbidden aliases, creates a fresh isolated copy, emits start/resume argv, and records `launched=false`. It does not launch a process, establish a separate OS principal/container/VM, deny host paths at the kernel boundary, or perform post-run harvesting. Its public receipt correctly avoids listing forbidden paths and hashes, but its unkeyed content integrity is not a B1 identity or execution attestation.

Preserve this prepare-only behavior for <PRIVATE_AUDIT_TARGET> and <PRIVATE_REGRESSION_TARGET>. A secure B1 launcher is a different authority and executable.

### 3.2 Production evidence already available

The exporter should consume existing authorities instead of reparsing only markdown:

| Evidence source | Existing artifact/API | Export use |
|---|---|---|
| Audit input/config/tool binding | `audit_snapshot.py:build_audit_snapshot` (1740), startup guard near 1913 | source/config/tool commitment |
| Phase definitions and checkpoint | `plamen_types.py`: `SC_PHASES`, `L1_PHASES`, `Phase`, `PhaseCommit`, `Checkpoint` | event order, attempts, commit/degraded state |
| Phase I/O identity | `phase_io_contracts.py:canonical_artifact_identity` (82), `canonical_work_unit_key` (99), `resolve_phase_io_contract` (990) | stable work-unit and artifact references |
| Artifact provenance | `_artifact_state.json`; `artifact_ledger.py:record_work_unit_artifacts` (1390), `record_work_unit_inputs` (2283), validation at 2517/3431 | producer/input/output lineage and drift |
| Discovery reconciliation | `inventory_reconciliation.json`, `inventory_disposition_authority.json`, `inventory_reemit_receipt.json`; `reconcile_inventory` (1047) | raw discovery denominator and retention/merge/refutation debt |
| Semantic alias application | `semantic_dedup_applied_receipt.json`, supplemental receipt; `load_applied_aliases` (899) | applied semantic alias edges only |
| Report alias application | `report_dedup_applied_alias_receipt.json`; `build_receipt` (209), `validate_receipt` (378) | applied report alias edges only |
| Finding lifecycle | embedded `finding_lifecycle` in report/verification authorities; `build_finding_lifecycle` (1205), `advance_finding_lifecycle` (1254), `validate_finding_lifecycle` (1319) | claim state, negative disposition, delivery state, terminal/debt |
| Report disposition | `report_disposition_authority.json`; build at 528, validate at 1274 | retained, refuted, alias, scope, zero-harm, appendix/report disposition |
| Verification routing/delivery | `mandatory_reverification_*.json`; completion/delivery reconciliation | retained-to-verified and reopened-report evidence |
| Security obligation lifecycle | `security_obligation_lifecycle.json`; build at 1256, validate at 2181 | verification states and unresolved debt |
| Method scheduling/application | `skill_dispatch.json`, application receipts/queues; `classify_application_row` (105), `validate_phase_application` (385) | scheduled/applied/invalid/unknown observations |
| Severity authority | severity decision ledger and coverage receipt; report projection at 2902 | final audit severity and decision provenance |
| Report evidence | `report_evidence_records.json`, `report_evidence_quality_receipt.json`; materialize at 1754, validate at 2015 | finding section/evidence quality and final projection |
| Final report | project-root `AUDIT_REPORT.md`; terminal finalization around `plamen_driver.py:51894-51996` | exact delivered report bytes |
| Existing canonical IDs | `_canonical_finding_ids.json`; `_write_canonical_finding_identity_map` in `plamen_mechanical.py` | occurrence aid only, never root identity |

`inventory_reconciliation.py` is especially important: every raw discovery receives a typed disposition (`RETAINED`, authorized merge/refutation, or human-review debt), without a threshold-based disappearance. That exact denominator must be retained.

The canonical finding map currently hashes artifact/local/title/location/root/source material. It can identify a pipeline occurrence, but the same underlying vulnerability can legitimately receive different canonical IDs in different artifacts. It MUST NOT be promoted to a cross-stage or GT root identity.

### 3.3 Current evaluator control plane

The evaluator currently seals exactly:

1. `run_manifest.json`
2. `phase_events.jsonl`
3. `candidate_findings.json`
4. `raw_outputs.json`
5. `harvest_receipt.json`
6. generated `bundle_index.json`
7. generated `SEALED.sha256`

Key current call sites:

| Module | Current call sites |
|---|---|
| `bundle.py` | strict JSONL 31; candidate validation 65; raw index 86; harvest receipt 102; payload validation 136; seal 211; verify 248; import 279 |
| `events.py` | normalize 17; earliest root-cause stage 105 |
| `benchmark.py` | annotation obligations 19; case lock 50/105; stage observations 137/165 |
| `matches.py` | reviewer vote 22; adjudication digest 30; roster 41; bindings 69; lifecycle evidence 132; matches 180 |
| `scoring.py` | isolation bindings 18; lifecycle localizer 60; scorer 103 |
| `analysis.py` | analysis policy 83; case means 105; paired comparisons 116; matrix check 170; evidence validation 198; analysis 263 |
| `campaign.py` | campaign 112; schedule 154; analysis 198 |
| `contracts.py` | semantic validation dispatch 134; document validation 1043 |
| `isolation.py` | signed receipt assessment; validation, not process isolation |
| `publication.py` | derived/frozen/signed publication gates |
| `cli.py` | parser 74; dispatcher 234 |

The control plane is useful as-is for synthetic B0. The real-run gap is not “another score formula”; it is trustworthy production harvesting, identity/alias preservation, negative-disposition localization, a public/private case-lock split, and a real isolation authority.

## 4. Target architecture

```text
                    pre-run, public only
 corpus authority ----------------------------+
       | public case lock                      |
       v                                       v
 secure launcher --> sanitized workspace --> audit system
       | private denial receipt                    |
       |                                           v
       |                                scratchpad + report
       |                                           |
       |                               GT-blind audit exporter
       |                                           |
       +-------------------------------> sealed RunBundle
                                                   |
                                        content-addressed import
                                                   |
                  private GT lock --> blind renderer/adjudication
                                                   |
                                    deterministic score + comparison
                                                   |
                                  signed publication completeness gate
```

The audit exporter is a recorder, not a grader. It may normalize exact production artifacts into a common vocabulary, but it must preserve every source record and any ambiguity. It must never decide that an exported candidate matches a known issue or shares a GT root.

## 5. Real-audit RunBundle v2

### 5.1 Directory contract

The sealed directory is:

```text
RunBundle/
  run_manifest.json
  phase_events.jsonl
  candidate_findings.json
  candidate_lineage.json
  raw_outputs.json
  report_projection.json
  harvest_receipt.json
  objects/
    sha256/
      <64-lowercase-hex>
  bundle_index.json
  SEALED.sha256
```

`objects/sha256` MAY be empty. Every object path is derived from and equal to its content SHA-256. No other root entry is permitted. `bundle_index.json` recursively enumerates every regular file except itself and `SEALED.sha256`, with relative POSIX path, byte length, and SHA-256. `SEALED.sha256` is the SHA-256 of canonical `bundle_index.json` plus a terminal newline.

V1 remains flat and keeps its existing exact file-name check. V2 gets a separate profile validator; it must not weaken v1.

All JSON objects are closed, UTF-8, canonicalizable, duplicate-key rejecting, finite-number only, and schema-versioned. Relative paths reject `..`, drive prefixes, UNC prefixes, NUL, alternate data streams, and non-normalized separators. Bundle entries must be regular files: no symlinks, junctions, reparse points, devices, sparse aliases, or multiple hardlinks.

### 5.2 `run_manifest.json`

Schema: `plamen.real-audit-run-manifest.v2`

Required top-level fields:

```text
schema_version
bundle_profile                    = REAL_AUDIT_V2
run_id                            opaque, nonsemantic
case_id                           opaque, nonsemantic
experiment_id
cell_id                           opaque until unblinding
repetition_index
seed
audit_system                      PLAMEN | EXTERNAL
adapter
public_case_lock_sha256
experiment_plan_sha256
campaign_schedule_sha256
source_snapshot_sha256
phase_map
model_backend
tool_policy
budget
blinding
resume
completion
exporter
public_launch_receipt
```

Nested requirements:

- `adapter`: `adapter_id`, `adapter_version`, `adapter_code_sha256`, `output_contract`.
- `phase_map`: `map_id`, `map_version`, `map_sha256`, `pipeline_kind` (`SC` or `L1` or adapter-defined).
- `model_backend`: normalized model family/revision, provider/backend class, context configuration. No secret endpoint or credential.
- `tool_policy`: tool-set digest, network policy, RAG policy, MCP policy.
- `budget`:
  - `regime`: `MATCHED_TOTAL` or `MATCHED_PER_CHANNEL`;
  - reserved total token/time/tool-call ceilings;
  - per-channel reserved ceilings for discovery, verification, report, and optional RAG/fuzz;
  - measured consumption and measurement-source receipt references;
  - `parity_group_id`.
- `blinding`: all of `ground_truth_available_to_runner`, `prior_report_available_to_runner`, `private_case_lock_available_to_runner`, and `grader_labels_available_to_runner` must be `false`; RAG exposure is explicit rather than inferred.
- `resume`: `mode` (`NEW`, `SAME_RUN_RESUME`, `RECOVERED_EXPORT`), `attempt`, `parent_state_seal_sha256` or null. It must not name a prior case/report.
- `completion`: `COMPLETE`, `DEGRADED`, `INCOMPLETE`, or `FAILED`, plus checkpoint and final-report gate state.
- `exporter`: package/version/code digest, schema-set digest, invocation-policy digest.
- `public_launch_receipt`: null for user-run/B0 or a digest of a public receipt that reveals policy and denial counts but no forbidden identities.

Forbidden key fragments are rejected recursively: `ground_truth`, `expected_issue`, `expected_count`, `answer_key`, `grader_label`, `private_case_lock`, `forbidden_path`, `forbidden_hash`, and configured equivalents. The sole allowed appearances are fixed boolean blinding field names whose values must be false.

`case_id`, `run_id`, `cell_id`, and `parity_group_id` must be randomly allocated opaque identifiers. Their encoded value must not contain repository names, protocol names, issue IDs, severities, experiment factors, or dates that reveal the corpus case.

### 5.3 Public and private case commitments

Create two contracts:

**`plamen.public-case-lock.v2`**, runner-visible:

- opaque `case_id`;
- sanitized source tree digest and source export receipt digest;
- language/build/test instructions and allowed public documentation;
- case capability flags;
- public corpus-suite ID/version;
- allocation nonce;
- no GT digest/count/labels.

**`plamen.private-case-lock.v2`**, evaluator-only:

- digest of the exact public case lock;
- GT annotation-set digest;
- opaque GT issue roster and GT root roster;
- expected reportability and acceptable severity ranges;
- private forbidden-input seal digest;
- corpus-authority signature.

The RunBundle binds only the public lock. Frozen matches and scores bind both after import. The publication record proves that the private lock existed before execution without placing its digest in the runner’s environment: the corpus authority timestamps/signs it privately, and the publication authority later reveals the binding.

### 5.4 `phase_events.jsonl`

Schema per row: `plamen.real-audit-phase-event.v2`

Required fields:

```text
event_id, run_id, sequence, attempt
native_phase, macro_phase, work_unit_id
event_type, commit_state
source_artifact_ids, input_artifact_ids, output_artifact_ids
source_receipt_id
observed_at, evidence_quality
```

`sequence` is exporter-derived from committed checkpoint/ledger order, not blindly from file timestamps. `observed_at` is evidence only. Event types:

`PLANNED`, `STARTED`, `INPUTS_BOUND`, `OUTPUTS_WRITTEN`, `OUTPUTS_COMMITTED`, `DEGRADED`, `FAILED`, `INVALIDATED`, `REEXECUTED`, `RESUMED`, `REPORT_FINALIZED`.

`commit_state` is `CLEAN`, `DEGRADED`, `FAILED`, `UNCOMMITTED`, or `UNKNOWN`. Duplicate or reordered observations normalize idempotently by `(run_id, attempt, work_unit_id, event_type, source_receipt_id)`. Contradictory committed events produce an explicit conflict; normalization must not pick the more favorable event.

The versioned macro phase map is evaluator-owned public protocol data:

- Smart-contract minimum: `recon`, `breadth`, `inventory`, `depth`, `chain`, `verify`, `report`.
- L1 adds `bake` and maps graph/composition phases explicitly.
- Every native phase in the exact `SC_PHASES` or `L1_PHASES` roster must map to one macro phase or to `CONTROL`.
- `CONTROL` artifacts remain harvestable but do not satisfy lifecycle milestones.
- Mapping is by exact native phase name, never prefix/substring heuristics.
- A pipeline phase unknown to the pinned map makes the bundle `DEGRADED` and the affected milestone `UNOBSERVABLE`; it is never silently assigned.

### 5.5 `candidate_findings.json`

Schema: `plamen.real-audit-candidate-set.v2`, containing sorted `candidates`.

Each candidate is one distinct audit claim, not one GT issue:

```text
candidate_id
first_occurrence_id
native_candidate_ids[]
producer
claim
locations[]
evidence_refs[]
audit_severity
quality
audit_cluster_id | null
```

- `candidate_id` is export-local and opaque.
- `native_candidate_ids` preserves inventory, lifecycle, verifier, report, and canonical-map IDs without treating any as GT identity.
- `producer` contains adapter, native phase, work unit, source artifact/record reference.
- `claim` contains title, mechanism, description, impact, and preconditions. Individual fields may be null only with a typed quality debt; the whole claim cannot be empty.
- `locations` may be empty only with `location_state=UNRESOLVED` and a source record proving the unresolved claim. Never invent a file/function/line to satisfy v1.
- `audit_severity` is the audit’s asserted severity plus authority receipt, or `UNASSESSED`.
- `quality` records parse completeness, location quality, evidence quality, and debts.
- `audit_cluster_id` is an audit-authored grouping only. It is not used as GT root identity or final fragmentation truth.

Recommended deterministic candidate ID:

```text
C2-Base32(
  SHA256(canonical_json({
    run_id,
    source_snapshot_sha256,
    first_producer_artifact_id,
    first_source_record_key_hash,
    native_lineage_anchor
  }))
)[0:26]
```

The anchor is an existing exact authority ID when available; otherwise it is the hash of the first record’s byte range and parser version. Claim prose alone is insufficient because wording edits on resume would change identity.

### 5.6 `candidate_lineage.json`

Schema: `plamen.candidate-lineage.v1`

Contains:

```text
occurrences[]
edges[]
alias_classes[]
negative_dispositions[]
lineage_debts[]
```

Each occurrence has:

- `occurrence_id`, `candidate_id`;
- native and macro phase;
- source `artifact_id`, `record_id`, record-byte digest/range;
- role: `DISCOVERY`, `RETAINED`, `VERIFICATION_INPUT`, `VERIFICATION_RESULT`, `REPORT_INDEX`, `REPORT_BODY`, `FINAL_REPORT`, `APPENDIX`;
- state: `POSITIVE`, `CONTESTED`, `NEGATIVE`, `DEFERRED`, `UNKNOWN`;
- asserted severity/location/evidence snapshot;
- exact authority reference or `UNAUTHENTICATED_PARSE`.

Allowed edge types:

- `SAME_CANDIDATE`: exact stable producer lineage.
- `AUTHORIZED_ALIAS`: applied semantic/report/finding-lifecycle authority.
- `REOPENED_AS`: exact recovery/reverification authority.
- `REFUTED_BY`: negative authority.
- `REPORTS_AS`: report projection.
- `PROPOSED_ALIAS`: preserved but never effective.

Effective alias rules:

1. Only `AUTHORIZED_ALIAS` edges from a successfully validated applied receipt may union candidates.
2. A proposal, fuzzy title/location similarity, shared canonical-map ID, or exporter heuristic may not union.
3. Direction and survivor are retained.
4. The effective graph must be acyclic after following survivor edges.
5. The survivor must exist and have a live occurrence.
6. Every union member remains present in `candidate_findings.json` and `occurrences`; aliasing never deletes evidence.
7. Conflicting authorities, cycles, missing survivors, or an alias that crosses incompatible content hashes create `IDENTITY_CONFLICT` debt and no union.
8. External adapters with no signed/applied alias authority emit separate candidates.

`alias_classes` are derived, not trusted input. Each class binds the exact applied edge IDs and has an audit-local opaque ID. The evaluator later assesses whether the class merges multiple GT roots or fragments one root.

Negative dispositions retain:

- disposition kind: `SAFE`, `REFUTED`, `OUT_OF_SCOPE`, `ZERO_HARM`, `NON_EXPLOITABLE`, `DEFERRED`, `CONTESTED`, `OTHER`;
- candidate/occurrence;
- phase and authority receipt;
- premise/evidence basis;
- terminal/nonterminal status;
- superseding positive occurrence, if any.

### 5.7 `raw_outputs.json` and objects

Schema: `plamen.real-audit-raw-output-index.v2`

Every artifact entry includes:

```text
artifact_id
relative_source_path
native_phase
macro_phase
work_unit_id
producer_kind
media_type
byte_length
sha256
storage                     INLINE_UTF8 | OBJECT
content | object_path
record_ids[]
source_contract_ref
commit_state
redactions[]
```

Small UTF-8 artifacts may be inline. Larger or binary artifacts use `objects/sha256/<sha256>`. No object may be omitted after the index references it. Object and total-bundle limits are precommitted in the experiment plan; exceeding a limit creates a failed/degraded export, not silent truncation.

The minimum Plamen harvest set is the final report plus every available typed authority named in section 3.2, checkpoint/config with secrets removed, phase event sources, and every artifact that supplies a candidate, alias, negative disposition, verification state, or report entry. Agent conversational logs may be excluded only by a precommitted retention policy and a receipt proving they supplied no otherwise-unrepresented candidate record. Unparsed or oversized candidate-bearing artifacts are export failures.

### 5.8 `report_projection.json`

Schema: `plamen.final-report-projection.v1`

Fields:

- `final_report_artifact_id`, SHA-256, byte length, delivery state;
- `report_entries[]` with opaque entry ID, section locator, byte-range digest, candidate IDs, effective audit alias class, asserted severity, evidence record refs, and report status;
- `appendix_entries[]`;
- `unmapped_finding_sections[]`;
- `candidate_report_dispositions[]`;
- report evidence-quality receipt reference;
- report integrity/no-ship state.

Every finding-like final report section must be mapped to at least one candidate or listed as `UNMAPPED_REPORT_FINDING`, which is retained as a new candidate with parse debt. Every candidate expected by the audit’s own disposition authority must be reported, appended, or carry the exact omission/debt authority.

The projection is syntactic/audit-authority evidence. It does not say whether a section is a true positive.

### 5.9 `harvest_receipt.json`

Schema: `plamen.real-audit-harvest-receipt.v2`

The receipt proves denominator conservation:

```text
source_snapshot
artifact_roster
record_reconciliation
candidate_roster
occurrence_roster
edge_roster
report_entry_roster
redaction_summary
privacy_scan
export_status
receipt_sha256
```

For each source artifact:

- before/after identity and digest;
- parser ID/version;
- discovered record count;
- emitted candidate/occurrence/edge/report IDs;
- outcome: `EXACT`, `PARSED_WITH_DEBT`, `NO_CANDIDATE_RECORDS`, `UNREADABLE`, `MUTATED_DURING_EXPORT`, `OVERSIZE`;
- typed reason and evidence.

Conservation invariants:

```text
all discovered source records
  = emitted occurrences
  + exact nonfinding records
  + explicit parse/debt records

all final finding sections
  = mapped report entries
  + explicit unmapped entries promoted to candidates

all applied alias decisions
  = emitted effective edges
  + explicit invalid/conflicting authority debt
```

An exporter must never drop a malformed candidate because it cannot satisfy a schema. It emits the minimally parsed candidate plus debt, or fails the export if even an opaque source record cannot be preserved.

## 6. Candidate, root-cause, and alias identity

Maintain four namespaces:

| Namespace | Owner | Meaning | May enter RunBundle? |
|---|---|---|---|
| Native occurrence ID | audit producer | exact record in an artifact | yes |
| Export candidate ID | GT-blind exporter | one distinct audit claim with lineage | yes |
| Audit alias/cluster ID | applied audit authority | audit’s same-claim grouping | yes, explicitly non-GT |
| GT issue/root ID | corpus authority/adjudicator | evaluator truth and root-cause equivalence | no; private only |

Candidate identity answers “is this the same audit claim moving through the pipeline?” Root identity answers “does this claim represent the same underlying material vulnerability as another claim?” The exporter may establish the former from exact lineage; only private adjudication establishes the latter.

Matching is many-to-many:

- one candidate may partially cover multiple GT issues only if adjudicators explicitly assign fractional issue credit;
- multiple candidates may match one GT issue/root;
- a candidate can be `TP`, `PARTIAL`, `FP`, `DUPLICATE_SAME_ROOT`, or `NOVEL_VALID`;
- an audit-authorized alias can still be an incorrect cross-root merge;
- two unaliased candidates can still be GT duplicates.

The frozen match record must preserve candidate-level votes before deriving issue/root aggregates.

## 7. Exact lifecycle localization

### 7.1 Milestones

For each private GT issue, adjudication freezes:

1. `EXPRESSIBLE`: applicable method/check/compiler capability existed.
2. `SCHEDULED`: relevant work was actually scheduled.
3. `APPLIED`: work consumed the target/relation/premise with valid receipt.
4. `DISCOVERED`: at least one exported candidate materially described the issue.
5. `RETAINED`: at least one such candidate survived inventory/dedup into verification input.
6. `VERIFIED`: at least one retained candidate received a positive/contested verification eligible for reporting.
7. `REPORTED`: a final delivered report entry received positive report credit.

Each value is `YES`, `NO`, `UNOBSERVABLE`, or `NOT_APPLICABLE`, and each `YES` or `NO` must cite an exported artifact/occurrence or an evaluator-private applicability record. Absence of evidence is `UNOBSERVABLE`, not `NO`.

### 7.2 Wrong-safe evidence

`WRONG_SAFE` is true only when:

1. a candidate is adjudicated as materially matching a GT-positive issue;
2. an exported applied negative disposition asserted safe/refuted/out-of-scope/zero-harm/non-exploitable;
3. that disposition was terminal for every matching lineage path, or caused its loss;
4. no later positive occurrence superseded it and reached the required final report.

A skeptical proposal, an unauthenticated markdown statement, or an unresolved contest is not automatically wrong-safe. It remains contested/debt.

### 7.3 Mutually exclusive primary result

Evaluate issue/root primary status in this order:

1. `SUCCESS`: at least one matching lineage receives positive final-report credit.
2. `FOUND_WRONG_SAFE`: no success, `DISCOVERED=YES`, and a qualifying wrong-safe disposition terminally eliminated every viable matching lineage.
3. `REPORT_LOSS`: no success/wrong-safe, `VERIFIED=YES`, reportable, and `REPORTED=NO`.
4. `FOUND_LOST_VERIFICATION`: no success/wrong-safe, `RETAINED=YES`, but `VERIFIED=NO`.
5. `FOUND_LOST_RETENTION`: no success/wrong-safe, `DISCOVERED=YES`, but `RETAINED=NO`.
6. `NEVER_FOUND`: `DISCOVERED=NO`.
7. `UNOBSERVABLE`: the decisive milestone is unobservable.

For a nonreportable GT issue, `REPORTED=NOT_APPLICABLE`; it cannot be a report loss.

If one candidate path succeeds and another matching path is wrongly marked safe or lost, primary issue status is `SUCCESS`, while candidate-path secondary counters still record the wrong-safe/loss. This avoids counting a found-and-reported root as missed while retaining pipeline-quality evidence.

### 7.4 Earliest causal substage

The primary status receives the earliest exact substage:

- `NEVER_FOUND`:
  - `METHOD_NOT_EXPRESSIBLE`
  - `COMPILER_NOT_APPLICABLE`
  - `TARGET_OR_RELATION_NOT_IDENTIFIED`
  - `NOT_SCHEDULED`
  - `SCHEDULED_NOT_APPLIED`
  - `APPLIED_NOT_DISCOVERED`
- `FOUND_WRONG_SAFE`:
  - `INVENTORY_REFUTATION`
  - `SEMANTIC_DEDUP_NEGATIVE`
  - `VERIFICATION_SAFE`
  - `REPORT_DISPOSITION_SAFE`
  - `SCOPE_OR_ZERO_HARM`
- `FOUND_LOST_RETENTION`:
  - `INVENTORY_LOSS`
  - `SEMANTIC_DEDUP_LOSS`
  - `CHAIN_TRANSFER_LOSS`
  - `UNKNOWN_PREVERIFY_LOSS`
- `FOUND_LOST_VERIFICATION`:
  - `QUEUE_ROUTING_LOSS`
  - `VERIFIER_APPLICATION_LOSS`
  - `VERIFICATION_DELIVERY_LOSS`
  - `REOPEN_FAILURE`
- `REPORT_LOSS`:
  - `REPORT_INDEX_LOSS`
  - `BODY_WRITER_LOSS`
  - `REPORT_DEDUP_LOSS`
  - `ASSEMBLY_LOSS`
  - `DISPOSITION_OR_FLOOR_LOSS`
  - `FINAL_DELIVERY_LOSS`

Tie-breaking uses the earliest committed macro/native phase sequence whose negative observation is supported. Conflicting evidence yields `UNOBSERVABLE_CONFLICT`, never the more favorable stage.

## 8. Metrics

All denominators and aggregation policies are frozen before unblinding.

### 8.1 Recall and lifecycle

- Raw GT issue recall: GT issues with `DISCOVERED=YES` / applicable GT issues.
- Raw GT root recall: GT roots with any discovered credited issue / applicable GT roots.
- Verified issue/root recall.
- Final report issue/root recall.
- Critical/High issue and root recall.
- Found-to-retained, retained-to-verified, verified-to-report, and found-to-report survival.
- Never-found, wrong-safe, retention-loss, verification-loss, and report-loss rates.
- Method scheduling, application, discovery-given-application, and report-retention rates.
- Candidate identity survival and unresolved identity-debt rate.

Root recall counts one root once regardless of how many candidates or GT issue variants represent it.

### 8.2 Precision and validity

Report three separate measures:

- `known_gt_precision = (TP + partial_credit) / all adjudicated candidate outputs`, with novel valid findings excluded from numerator.
- `all_output_validity = (TP + partial_credit + NOVEL_VALID) / all adjudicated candidate outputs`.
- `report_precision` and `verified_precision` at their respective stages.

Do not relabel novel valid findings as known-GT hits. Unadjudicated outputs remain denominator debt and block a complete publication claim.

### 8.3 Severity

Map `Critical=4`, `High=3`, `Medium=2`, `Low=1`, `Informational=0` only after match adjudication:

- exact severity accuracy;
- within-one accuracy;
- mean absolute error;
- under-severity and over-severity rates;
- Critical/High recall at raw, verified, and report stages;
- catastrophic undercall rate: GT Critical/High reported below Medium;
- audit severity authority coverage and unresolved-severity debt.

Use corpus-authority acceptable ranges when an issue has a legitimate severity interval; publish both exact-label and in-range accuracy.

### 8.4 Fragmentation and merge quality

For each private GT root:

- `reported_alias_classes`;
- `excess_fragments = max(0, reported_alias_classes - 1)`;
- candidate duplication count;
- duplicate report burden (extra words/sections devoted to the same root).

Across roots:

- incorrect merge count: one effective audit alias class matched to more than one incompatible GT root;
- cross-root impurity: credited mass outside the dominant GT root / all credited mass in the alias class;
- alias compression ratio: distinct exported candidates / effective audit alias classes;
- root fragmentation rate: roots with more than one reported alias class / reported roots.

Audit alias classes never substitute for private GT roots in these formulas.

### 8.5 Report quality

For matched report entries:

- mechanism, impact, precondition, location, reproduction/evidence, remediation, and severity-rationale completeness;
- source/evidence citation validity;
- location exactness;
- unsupported-claim and stale-evidence rates;
- unmapped finding section rate;
- report integrity/no-ship debt;
- word count and duplicate-report burden.

Quality scoring must be rubric-driven and blinded to system/cell. Mechanical completeness and human semantic quality are separate fields.

### 8.6 Efficiency and parity

- reserved and consumed tokens, wall time, tool calls, model calls, verification calls, optional RAG/fuzz calls;
- recall and valid findings per one million tokens;
- reportable root recall per hour;
- marginal benefit of CPG/adaptive attention under each budget regime;
- overrun/measurement-debt rate.

No quality metric is divided by cost as the sole headline. Publish quality and cost jointly.

## 9. Multiple seeds, backends, and budget parity

The precommitted launch key is:

```text
(case_id, cell_id, seed, backend_block, budget_regime, repetition_index)
```

Pairs are valid only when case, seed, backend block, and budget regime match. Backend is a blocking variable, not an experimental factor, unless a separate backend experiment is declared.

For the CPG/adaptive 2x2:

| Cell | Typed CPG | Adaptive attention |
|---|---:|---:|
| G0A0 | off | off |
| G1A0 | on | off |
| G0A1 | off | on |
| G1A1 | on | on |

Run the full matrix under:

- `MATCHED_TOTAL`: identical reserved total ceilings before launch; no post-result budget transfer.
- `MATCHED_PER_CHANNEL`: corresponding discovery/verification/report/RAG/fuzz channel ceilings are identical.

Missing backend capability, unmeasured usage, or a budget overrun marks that pair invalid/debt; it is not repaired by post hoc normalization.

Analysis:

1. retain seed-level paired results and publish the completeness table;
2. average repetitions/seeds within case/cell/backend/regime for case-cluster inference;
3. use cases, not seeds, as independent inferential units;
4. report paired effect estimates and precommitted confidence intervals;
5. do not silently drop incomplete pairs;
6. block publication if the required matrix or backend parity set is incomplete.

The current `analysis._case_cluster_means` behavior is compatible with case-level inference but needs pre-aggregation seed/backend/budget parity validation and a retained seed-level audit table.

## 10. Blinded adjudication

### 10.1 Roles

- Corpus authority: freezes/signs public and private locks.
- Launch authority: executes the access boundary and signs private isolation evidence.
- Import authority: verifies/seals/imports without scoring.
- Two match reviewers: independently map candidates to GT issues/roots.
- Lifecycle reviewer(s): judge milestone evidence and negative-disposition causality.
- Novelty reviewer(s): validate non-GT candidates.
- Adjudicator: resolves disagreement.
- Scoring authority: deterministic computation only.
- Publication authority: verifies completeness and signatures.

No person/key may simultaneously act as launch authority and sole adjudicator for B1. Corpus and publication authority keys must be distinct.

### 10.2 Blind rendering

Add a renderer that:

- replaces system, adapter, cell, model, and run labels with random review labels;
- shows opaque candidate and GT labels;
- presents sanitized source context, candidate claim, locations/evidence, raw occurrence lineage, and applicable GT issue text;
- hides scores, peer votes, expected counts, factor settings, budgets, and prior-run outcomes;
- randomizes candidate order per reviewer while binding the permutation digest;
- creates separate match, lifecycle, severity, and report-quality packets.

Reviewers seal votes independently. The adjudicator sees disagreements only after both votes are sealed. Cell/system identities are unblinded only after the match set, lifecycle observations, novelty decisions, and quality rubric results are frozen.

### 10.3 Neutral import and comparison

Sequence:

1. Verify RunBundle schema/index/seal in staging.
2. Import to `imports/sha256/<bundle-seal>` read-only.
3. Verify public case-lock binding and experiment schedule membership.
4. Privately resolve `case_id` to private lock.
5. Run a private leakage scan against corpus tokens.
6. Compile evidence packets; compilation proposes no semantic match.
7. Freeze independent votes and adjudication.
8. Freeze lifecycle stage observations.
9. Deterministically score.
10. Validate seed/backend/budget parity.
11. Compare blinded cell labels.
12. Verify publication completeness/signatures.
13. Unblind labels and render final comparison.

The neutral grader imports a frozen match/observation set. It does not call an LLM, modify a match, or infer aliases during scoring.

## 11. Prior-run preservation and resume

### 11.1 Preparation

Keep current conservative prior-evidence discovery, and add an explicit manifest input:

- `--prior-run-root` repeatable;
- `--prior-discovery-policy <version>`;
- `--prior-seal-out <fresh external path>`.

The explicit roots supplement rather than replace conservative discovery. All identified `.scratchpad*`, archive/snapshot roots, prior audit reports, Medusa/fuzz workspaces, and RCA material are externally content-sealed before workspace creation. The source project is not mutated or cleaned.

### 11.2 Run and resume

- `NEW` requires a fresh workspace and new run ID.
- `SAME_RUN_RESUME` requires exact run ID, source snapshot, config, checkpoint, and prior state-seal match.
- Before resume, snapshot the mutable run state to an external content-addressed store and bind its digest as `parent_state_seal_sha256`.
- A resume may append/reexecute through existing checkpoint/ledger protocols; it may not overwrite the preserved parent snapshot.
- Starting a different audit from an existing scratchpad is forbidden; use a new workspace/run ID.

### 11.3 Export

- Export reads one explicit project root, scratchpad, and report.
- It snapshots all inputs at start, harvests into a fresh staging directory, then re-hashes every input before seal.
- Any mutation yields `MUTATED_DURING_EXPORT` and no accepted seal.
- Re-export of identical inputs is byte-for-byte deterministic.
- Changed inputs create a new bundle generation and preserve the previous sealed bundle.
- Output directories are never overwritten.
- Interrupted staging directories are not accepted as bundles.
- `RECOVERED_EXPORT` may resume only from an exporter journal whose input snapshot and exporter digest still match.

Current unkeyed prior-evidence receipts remain useful integrity records for user runs. B1 additionally requires a signed private preservation receipt.

## 12. Secure launcher and forbidden-input sealing

### 12.1 Two separate launch paths

**User-run path:** `terminal_audit_launch.py` remains prepare-only and emits commands. This is the required <PRIVATE_AUDIT_TARGET>/<PRIVATE_REGRESSION_TARGET> boundary and is labeled `USER_RUN`, never `B1_ISOLATED`.

**Governed B1 path:** a separately deployed launcher runs under a distinct OS principal/container/VM with a deny-by-default mount and network policy. A Python path-check wrapper is not sufficient.

### 12.2 Forbidden input seal

The evaluator-private seal contains exact canonical identities for:

- GT files and ancestor directories;
- private case locks and corpus indexes;
- prior scratchpads/reports and grader outputs;
- control/evaluator repository when not required by the runner;
- local RAG stores and caches;
- `.git` history/objects/refs unless the public case explicitly requires sanitized history;
- user home, Downloads, temp locations, credential stores, SSH/GPG/cloud/API credentials;
- network endpoints and MCP/app connections not preauthorized.

Each entry binds path identity, file/device/inode or Windows file identity, content digest when safe, and alias/link identities. This seal stays evaluator-private. Never place its paths or digests in the runner environment or public bundle.

### 12.3 B1 execution policy

The launcher must provide:

- fresh single-use workspace and OS identity;
- read-only sanitized source mount;
- only the public case lock, public toolchain, fixed model/tool policy, and one-time run token;
- no private corpus/control mount;
- no inherited environment except an allowlist;
- no host home/profile, clipboard, interactive history, or credential agent;
- disabled network by default; explicit endpoint allowlist when the backend requires network;
- no arbitrary MCP, RAG, browser, email, drive, Slack, or repository connectors;
- resource and budget enforcement;
- kernel/hypervisor denial logs;
- one-time nonce bound to schedule row and public case lock;
- destruction/quarantine after sealed export.

### 12.4 Receipts

Two receipts avoid leakage:

- Public launch receipt, bundle-visible: policy ID/version, launcher build digest, nonce commitment, counts of allowed/denied access classes, completion state, and signature ID. No private path/hash.
- Private isolation receipt: exact public receipt digest, RunBundle seal, private forbidden seal, denial-probe transcript, runtime identity, mount/network policy digests, start/end times, measurement receipts, and launch-authority signature.

`plamen_eval/isolation.py` should validate these bindings. The actual launcher and trustworthy denial transcript are external B1 infrastructure.

## 13. <PRIVATE_AUDIT_TARGET> and <PRIVATE_REGRESSION_TARGET> user-run workflow

<PRIVATE_AUDIT_TARGET> and <PRIVATE_REGRESSION_TARGET> remain user-run canaries:

1. Codex tooling prepares the workspace and seals prior evidence.
2. Their GT path and reference-report path are passed as `--forbidden-input`.
3. The preparation receipt records only policy/count, never forbidden identity.
4. Codex returns the exact `START_NEW_RUN`/`RESUME_EXISTING` command.
5. The user runs the expensive audit in their terminal.
6. The user runs the GT-blind exporter with only public case token, project, scratchpad, report, and output.
7. A separate evaluator operator imports the sealed bundle and only then accesses GT.

<PRIVATE_AUDIT_TARGET> is acceptance evidence for the user workflow, not automatically a governed benchmark. <PRIVATE_REGRESSION_TARGET> is regression-only and must never be used for tuning, headline comparative evidence, or a B1 generalization claim. Neither run becomes B1 merely because the bundle schema validates.

## 14. Pashov V3 adapter

The current evaluator contains a Pashov experiment contract/provenance slot but no output adapter. Add:

```text
src/plamen_eval/adapters/__init__.py
src/plamen_eval/adapters/base.py
src/plamen_eval/adapters/pashov_v3.py
schemas/external_adapter_receipt.v1.schema.json
schemas/pashov_v3_parse_receipt.v1.schema.json
```

Adapter interface:

```text
preflight(input_root, public_case_lock, adapter_pin) -> diagnostics
inventory(input_root) -> exact artifact roster
parse_candidates(artifacts) -> candidates + occurrences + debts
parse_events(artifacts) -> phase events
parse_report(artifacts) -> final report projection
build_receipt(...) -> signed/digested adapter receipt
```

Requirements:

- exact public Pashov release/archive digest, provenance URL recorded by the corpus authority, license, parser version, and execution instructions are pinned before launch;
- parsing is offline and deterministic;
- original transcript/output bytes are retained;
- one distinct emitted finding becomes one candidate unless Pashov supplies an exact applied alias authority;
- the adapter does not invent locations, evidence, verification, or provenance;
- native stages map to `discovery`, `verify`, and `report`;
- if the pinned workflow has no separately observable verification stage, `VERIFIED=UNOBSERVABLE/NOT_PROVIDED`, never automatically `YES`, `NO`, or safe;
- final report projection refers to exact output byte ranges;
- parser failures become candidates with parse debt or block export; findings are never silently skipped.

Fairness requires the same sanitized source, public instructions, backend block, seed policy, and declared budget regime. Comparator-specific mandatory overhead remains measured, not erased. A locally implemented adapter can prove format fidelity on fixtures; the exact official release/provenance/license, independent comparator operation, and fair real execution remain B1 external inputs.

## 15. Exact implementation map

### 15.1 `plamen-codex-implementation`

Add:

| New module | Responsibility |
|---|---|
| `scripts/runbundle_contracts.py` | closed v2 data validation, canonicalization, IDs |
| `scripts/runbundle_phase_map.py` | exact versioned `SC_PHASES`/`L1_PHASES` to macro-phase maps |
| `scripts/runbundle_sources.py` | source adapter registry for typed Plamen authorities |
| `scripts/runbundle_harvest.py` | artifact/record inventory, candidate/lineage/report construction, denominator conservation |
| `scripts/runbundle_privacy.py` | secret/path redaction, forbidden-key scan, safe relative paths |
| `scripts/runbundle_export.py` | preflight/export/recover/verify CLI, object store, index/seal |
| `scripts/runbundle_export_ready.py` | optional terminal checkpoint/report readiness marker |
| `scripts/test_runbundle_*.py` | contract, lifecycle, tamper, privacy, fault, resume fixtures |

Consume, do not redefine, the authorities listed in section 3.2. Parsers should be registered by exact schema version and artifact identity. Unknown future versions create debt/failure.

Modify narrowly:

- `terminal_audit_launch.py:discover_prior_audit_evidence` (460): accept explicit prior roots and policy version while preserving conservative discovery.
- `terminal_audit_launch.py:_build_prior_evidence_seal` (578): add chainable parent seal and public/private receipt split without changing current user-run semantics.
- `terminal_audit_launch.py:prepare_legacy_claude_run` (989): optionally bind opaque public case token and exporter policy; never accept GT/private-lock arguments.
- `terminal_audit_launch.py:verify_preparation_receipt` (1210): validate the new optional public bindings.
- `terminal_audit_launch.py:_main` (1345): add explicit preservation options; still never launch.
- `plamen_driver.py:_bind_checkpoint_audit_snapshot` (44254): expose the already-bound source snapshot to an export-ready marker.
- `plamen_driver.py` finalization around 51894-51996: after final report and assurance gates, optionally write a tiny `run_export_ready.json` containing only run/checkpoint/report/artifact-ledger digests. Do not auto-export and do not make audit success depend on evaluator availability.
- `plamen_mechanical.py:_write_canonical_finding_identity_map`: document/export IDs as native occurrence aids only; do not change them into root IDs.

Preferred rollout R1 requires no invasive phase-loop hook. `runbundle_export.py` reconstructs events from checkpoint, phase commits, artifact ledger, and authorities post-run. A later event-stream writer may be added only if reconstruction fixtures expose unobservable gaps.

### 15.2 `<PRIVATE_EVALUATOR_REPO>`

Add schemas:

```text
public_case_lock.v2.schema.json
private_case_lock.v2.schema.json
run_manifest.v2.schema.json
phase_event.v2.schema.json
candidate_finding.v2.schema.json
candidate_lineage.v1.schema.json
raw_output_index.v2.schema.json
final_report_projection.v1.schema.json
harvest_receipt.v2.schema.json
bundle_index.v2.schema.json
public_launch_receipt.v1.schema.json
private_isolation_receipt.v2.schema.json
blind_review_packet.v1.schema.json
lifecycle_adjudication.v2.schema.json
score.v2.schema.json
comparison.v2.schema.json
external_adapter_receipt.v1.schema.json
pashov_v3_parse_receipt.v1.schema.json
```

Add modules:

| New module | Responsibility |
|---|---|
| `profiles.py` | explicit synthetic-v1 versus real-audit-v2 dispatch |
| `objects.py` | recursive object-store validation and caps |
| `lineage.py` | occurrence/edge validation and applied-alias derivation |
| `lifecycle.py` | exact v2 milestone and failure taxonomy |
| `blinding.py` | blind packet creation, label permutations, unblinding |
| `comparison.py` | seed/backend/budget parity and blinded cell comparisons |
| `adapters/base.py` | comparator adapter contract |
| `adapters/pashov_v3.py` | pinned Pashov parser |

Modify:

- `contracts.py:_semantic_validation` (134) and `validate_document` (1043): add v2 schema dispatch and cross-document invariants; leave v1 behavior frozen.
- `bundle.py:_regular_file_names` (52): dispatch to recursive v2 entry validation.
- `bundle.py:_validate_candidates` (65): profile-aware candidate schema.
- `bundle.py:_validate_payload` (136): explicit profile branch, object and reconciliation validation.
- `bundle.py:seal_run_bundle` (211), `verify_run_bundle` (248), `import_sealed_bundle` (279): recursive index, same staging/TOCTOU/content-addressed/read-only guarantees.
- `events.py:normalize_events` (17): v2 attempt/commit conflict rules and exact phase map.
- `benchmark.py:freeze_case_lock` (50): preserve v1; add separate `freeze_public_case_lock_v2` and `freeze_private_case_lock_v2`.
- `benchmark.py:freeze_stage_observations` (137): compile four-state evidence and wrong-safe dispositions.
- `matches.py:_bind_inputs` (69): bind public bundle plus evaluator-private lock post-import.
- `matches.py:_verify_lifecycle_bindings` (132): validate occurrence/authority references and v2 taxonomy.
- `matches.py:freeze_matches` (180): retain candidate-to-issue and candidate-to-root votes, partial credit, novelty, and blinded labels.
- `scoring.py:_localize_earliest_failure` (60): implement section 7 precedence and substage.
- `scoring.py:score_match_set` (103): add v2 metrics while preserving v1 score schema.
- `analysis.py:_case_cluster_means` (105) and `paired_case_comparisons` (116): enforce/publish seed/backend/budget parity before case aggregation.
- `analysis.py:_check_matrix` (170): require exact 2x2 or comparator matrix.
- `campaign.py:build_experiment_campaign` (112) and schedule generation: expand seed/backend/budget launch keys.
- `isolation.py`: accept public/private receipt split and verify exact bundle/lock/schedule bindings.
- `publication.py`: require complete bundle, isolation, reviewer, adjudication, score, parity, corpus, and authority signatures.
- `cli.py:_parser` (74), `main` (234): add commands below.

### 15.3 CLI/workflow

Production/user side:

```text
python scripts/terminal_audit_launch.py prepare ...
python scripts/terminal_audit_launch.py verify-preparation <receipt>

python scripts/runbundle_export.py preflight
  --project-root <workspace>
  --scratchpad <workspace/.scratchpad>
  --report <workspace/AUDIT_REPORT.md>
  --public-case-lock <public-only.json>

python scripts/runbundle_export.py export
  --project-root <workspace>
  --scratchpad <workspace/.scratchpad>
  --report <workspace/AUDIT_REPORT.md>
  --public-case-lock <public-only.json>
  --schedule-row <public-row.json>
  --out <fresh-directory>

python scripts/runbundle_export.py recover --journal <staging/export.journal.json>
python scripts/runbundle_export.py verify <sealed-bundle>
```

There is intentionally no `--ground-truth`, `--private-case-lock`, `--expected-count`, `--grader`, or generic arbitrary-input option. Reject corresponding environment variables too.

Evaluator side, retaining all current commands:

```text
plamen-eval freeze-public-case-v2 ...
plamen-eval freeze-private-case-v2 ...
plamen-eval import-bundle ...
plamen-eval validate-isolation-v2 ...
plamen-eval compile-observations-v2 ...
plamen-eval render-blind-review ...
plamen-eval freeze-review-votes ...
plamen-eval adjudicate-v2 ...
plamen-eval score-v2 ...
plamen-eval compare-v2 ...
plamen-eval publication-gate-v2 ...
plamen-eval harvest-external --adapter pashov-v3 ...
```

Each command writes to a fresh path or content-addressed destination. Mutation commands require explicit output, never in-place rewrite.

## 16. Locally implementable versus external B1 blockers

| Capability | Local implementation status/path | B1 status |
|---|---|---|
| V2 schemas, validators, canonical bytes | implementable in evaluator repo | local |
| Plamen scratchpad/report exporter | implementable in production repo | local |
| Typed source adapters and conservation receipt | implementable | local |
| Recursive object sealing/import | extend current proven mechanics | local |
| Lifecycle/metrics/parity calculations | implementable and fixture-testable | local |
| Blind packet renderer and vote contracts | implementable | local |
| Pashov adapter framework/parser fixtures | implementable | local |
| User-run <PRIVATE_AUDIT_TARGET>/<PRIVATE_REGRESSION_TARGET> preparation/export | implementable; execution remains user-owned | local/user-run |
| Synthetic/canary comparisons | implementable, label B0 or USER_RUN | local |
| Governed unpublished corpus and private GT | requires independent corpus authority | **B1 external blocked** |
| Secure OS/container/VM launcher | requires separately operated infrastructure | **B1 external blocked** |
| Trustworthy denial probes and private isolation signature | requires launch authority/environment | **B1 external blocked** |
| Distinct reviewers/adjudicator/publication authority | requires people/keys/governance | **B1 external blocked** |
| Exact independently pinned Pashov release/provenance/license and fair operation | requires external comparator authority | **B1 external blocked** |
| Backend credentials, provider logs, enforceable budget measurements | requires external provider/authority | **B1 external blocked** |
| Full multi-case/multi-seed execution cost | requires authorized execution | **B1 external blocked** |
| Publication-grade B1 conclusion | requires every external row above | **B1 external blocked** |

Local completion must never auto-promote a result to B1. The publication gate should emit `B0_LOCAL`, `USER_RUN`, `B1_INCOMPLETE`, or `B1_COMPLETE` from authenticated evidence.

## 17. Staged rollout

### R0 — Contract freeze

- Freeze public/private case split, v2 bundle files, identity rules, lifecycle precedence, metrics, phase map, and adapter API.
- Add schema golden examples and invalid examples.
- Prove existing v1 golden tests unchanged.

Exit: v1 byte-for-byte behavior preserved; v2 schemas reject all forbidden fields and ambiguous identities.

### R1 — Plamen harvest

- Implement source registry, phase map, candidate/lineage/report harvest, privacy scan, object index, seal/verify.
- Run only fixture scratchpads, including SC and L1.
- Add optional export-ready marker after finalization.

Exit: exact denominator conservation and deterministic re-export on fixtures.

### R2 — Evaluator import and lifecycle

- Add v2 import, private lock join, blind renderer, adjudication, lifecycle, score v2.
- Validate all failure localizations and fragmentation cases.

Exit: a sealed GT-blind fixture receives the expected private score only after adjudication.

### R3 — Comparator adapter

- Implement Pashov V3 adapter against pinned fixture outputs.
- Validate absent verification as unobservable.
- Demonstrate symmetric source/budget/run-manifest bindings.

Exit: adapter fidelity fixtures; no comparative claim.

### R4 — Factorial and user-run canaries

- Implement seed/backend/budget parity and CPG/adaptive 2x2 schedule validation.
- Exercise <PRIVATE_AUDIT_TARGET>/<PRIVATE_REGRESSION_TARGET> preparation/export only when the user performs the audit.
- <PRIVATE_REGRESSION_TARGET> remains regression-only.

Exit: complete local workflow labeled USER_RUN/B0, with no GT leakage.

### R5 — External B1

- Independent corpus, launcher, authorities, reviewer roster, comparator pin, provider measurement, denial probes, and signatures.
- Execute precommitted cases/seeds/backends/budgets.

Exit: publication gate verifies every required authenticated artifact. Otherwise remain `B1_INCOMPLETE`.

## 18. Acceptance matrix

### 18.1 Functional fixtures

| ID | Fixture | Required result |
|---|---|---|
| F-01 | applicable issue, no candidate | `NEVER_FOUND/APPLIED_NOT_DISCOVERED` |
| F-02 | method never scheduled | `NEVER_FOUND/NOT_SCHEDULED` |
| F-03 | candidate found then valid terminal safe assertion | `FOUND_WRONG_SAFE` |
| F-04 | safe proposal not applied | contested/debt, not wrong-safe |
| F-05 | discovery absent from inventory | `FOUND_LOST_RETENTION/INVENTORY_LOSS` |
| F-06 | applied alias preserves survivor | one effective alias class, all occurrences retained |
| F-07 | proposed alias only | candidates remain distinct |
| F-08 | alias cycle/conflict | identity debt, no union |
| F-09 | retained but queue never delivers | `FOUND_LOST_VERIFICATION` |
| F-10 | verified but absent from report index | `REPORT_LOSS/REPORT_INDEX_LOSS` |
| F-11 | index/body present, removed by report dedup | `REPORT_LOSS/REPORT_DEDUP_LOSS` |
| F-12 | report section with no mapped candidate | new candidate with unmapped parse debt |
| F-13 | one successful and one lost path for same GT root | primary success plus secondary loss counter |
| F-14 | two reports for one root | one root hit plus fragmentation |
| F-15 | one audit alias class spans two GT roots | incorrect merge/cross-root impurity |
| F-16 | no observable verification in external output | `VERIFIED=UNOBSERVABLE` |
| F-17 | unresolved candidate location | candidate retained with location debt |
| F-18 | nonreportable GT issue verified but absent report | no report-loss classification |
| F-19 | novel valid candidate | excluded from known-GT precision numerator, included in all-output validity |
| F-20 | degraded/incomplete run | importable for diagnosis, excluded from complete comparison |

### 18.2 Tamper, privacy, and leakage

| ID | Fault | Required result |
|---|---|---|
| S-01 | mutate payload after index | seal verification fails |
| S-02 | mutate object bytes | digest verification fails |
| S-03 | add unindexed root/object file | verification fails |
| S-04 | duplicate JSON key, NaN/Infinity, invalid UTF-8 | parse fails closed |
| S-05 | symlink/junction/reparse/device entry | export/import fails |
| S-06 | hardlinked bundle entries | fails |
| S-07 | path traversal/UNC/drive/ADS path | fails |
| S-08 | absolute user path in payload | privacy validation fails/redacts before staging |
| S-09 | credential/private-key/API token | privacy scan blocks seal |
| S-10 | GT/private-lock/expected-count key | schema/semantic validation fails |
| S-11 | private GT token appears under innocent key | evaluator-private leakage scan rejects |
| S-12 | forbidden source hardlink/alias into workspace | launcher/preparation rejects |
| S-13 | report or scratchpad mutates during export | no seal; mutation receipt |
| S-14 | exporter/parser digest mismatch schedule | comparison ineligible |
| S-15 | public receipt contains forbidden path/hash | validation fails |

Redaction must remove secret values without publishing their hashes. The receipt records redaction type/count and artifact/field location only.

### 18.3 Fault and resume

| ID | Interruption | Required result |
|---|---|---|
| R-01 | kill before first payload | no accepted bundle; safe cleanup/restart |
| R-02 | kill after objects, before index | staging only; recover if snapshot matches |
| R-03 | kill after index, before seal | not accepted; deterministic seal on recovery |
| R-04 | kill after seal, before import | sealed bundle verifies/imports idempotently |
| R-05 | kill during content-addressed import | no partial accepted destination |
| R-06 | import same bundle twice | same digest destination, no rewrite |
| R-07 | resume same audit after prior export | new generation binds parent state; old bundle preserved |
| R-08 | recover journal after input changed | recovery refuses; fresh export required |
| R-09 | target output already exists | refuse; never overwrite |
| R-10 | checkpoint says committed but artifact ledger disagrees | conflict/degraded, not favorable inference |

### 18.4 Fairness and analysis

| ID | Case | Required result |
|---|---|---|
| A-01 | same case/cell, mismatched seed | not paired |
| A-02 | backend revision differs within parity block | invalid pair |
| A-03 | matched-total reserved ceiling differs | invalid pair |
| A-04 | matched-per-channel verification ceiling differs | invalid pair |
| A-05 | missing 2x2 cell | matrix incomplete/publication blocked |
| A-06 | seed missing only for poor-performing cell | no silent row deletion |
| A-07 | many seeds, one case | inferential case count remains one |
| A-08 | novel findings adjudication incomplete | complete score/publication blocked |
| A-09 | reviewer labels reveal system/cell | blind packet validation fails |
| A-10 | unblinding before sealed adjudication | publication chain invalid |

### 18.5 Clean-install acceptance

- Build/install evaluator wheel in a fresh environment with repository unavailable.
- Build/run production exporter from a pinned installation/source package with no import from sibling evaluator repo.
- Verify all schemas and phase maps are package data with bound digests.
- Run offline fixture suite with empty home/profile and no network.
- Prove no implicit dependency on the current dirty production worktree.
- Prove Windows and POSIX path canonicalization fixtures.
- Verify v1 synthetic golden bundles/scores are unchanged.
- Verify a v2 bundle created on one clean install validates and scores identically on another.

## 19. Definition of done

Local implementation is done when:

1. every real-run payload is GT-blind by construction;
2. all raw candidate-bearing records reconcile to occurrences or explicit debt;
3. only validated applied authorities form audit alias classes;
4. GT issue/root identity appears only after private adjudication;
5. all requested lifecycle outcomes and substages pass fixtures;
6. recall, precision, severity, fragmentation, quality, and efficiency metrics are deterministic;
7. prior runs and interrupted exports/imports are preserved;
8. <PRIVATE_AUDIT_TARGET>/<PRIVATE_REGRESSION_TARGET> stay prepare/user-run/export-only;
9. Pashov parsing is pinned, loss-accounted, and verification-honest;
10. multi-seed/backend/budget parity is fail-closed;
11. v1 behavior remains unchanged;
12. tamper/privacy/leakage/clean-install tests pass.

B1 is done only when the external governed corpus, secure launcher/denial evidence, independent authorities/reviewers, exact comparator pin, provider measurements, and complete precommitted execution matrix are present and authenticated. Until then the correct claim is “local B0/user-run evaluation mechanics complete; B1 externally blocked.”

## 20. Recommended first implementation slice

The lowest-risk vertical slice is:

1. freeze the public/private lock split and v2 schemas;
2. implement a Plamen fixture exporter using `inventory_reconciliation.json`, applied semantic/report dedup receipts, `report_disposition_authority.json`, report evidence, checkpoint/artifact ledger, and `AUDIT_REPORT.md`;
3. extend `bundle.py` with a profile branch and recursive object verification;
4. implement three end-to-end lifecycle fixtures: never-found, wrong-safe, and report-loss;
5. add blind rendering and a manually frozen match fixture;
6. score/import twice and prove deterministic equality;
7. only then add Pashov and the full factorial campaign.

This slice validates the central trust boundary and loss accounting before adding execution cost or external governance.
