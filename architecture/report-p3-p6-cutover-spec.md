# Report P3-P6 Cutover Specification

Status: **IMPLEMENTATION-READY DESIGN CANDIDATE — NO RUNTIME OR CUTOVER AUTHORITY**
Version: `report-cutover-p3-p6.v2`
Date: 2026-08-08
Scope: report rendering, immutable final capture, publication, driver migration, and final assurance
Accepted predecessor: report P0-P2/R5 capture boundary

This specification defines the remaining report cutover. It does not reopen the accepted P0-P2/R5 source-capture design. In this document, `MUST`, `MUST NOT`, `SHOULD`, and `MAY` are normative. “Report P3-P6” names report-cutover stages and is unrelated to similarly named evaluator or methodology phases.

P3 and P4 may be implemented and exercised as candidates before the MethodCard program is complete. They MUST NOT become the production report authority, and their output MUST NOT be accepted as a final cutover, until MethodCard MC4-MC6 and report P5-P6 have passed. In particular, a renderer can project MethodCard assurance but cannot create or upgrade that assurance.

## 1. Outcome and non-goals

The cutover is complete only when all of the following are true:

1. The accepted 43 fixed selectors and five namespace selectors have registered, typed, live PhaseIO producers. The present policy state of 38 permitted and ten blocked selectors has become 48 permitted and zero blocked selectors through reviewed producer registration, not by denominator reduction.
2. P3 renders deterministically from a single committed, in-memory capture value. It performs no live filesystem, clock, environment, network, model, callback, or mutable-ledger read.
3. P3 retains the complete finding, disposition, negative-closure, evidence, source-location, human-review, security-obligation, and methodology-assurance truth supplied by its committed inputs.
4. P4 assembly commits exactly seven scratchpad payload states and a distinct immutable final capture v2. Publication consumes them, installs the client payload plus authenticated PhaseIO publication-ledger head at project root, and confers `SHIPPED` only through its recoverable terminal receipt.
5. P5 makes the captured path the driver authority per explicit compatibility cell. It removes every live report-assembly reread and every post-assembly semantic mutation from the authoritative path.
6. P6 proves semantic, output, crash/retry/resume, backend, ecosystem, mode, and host parity with frozen denominators and independent review.

This specification does not redesign upstream finding adjudication, evidence adjudication, negative closure, root-cause clustering, severity, disposition, source-location recovery, or MethodCard application assurance. Those domains MUST produce typed decisions before source capture. Report code only validates and projects them.

This specification does not add an eighth report output. A machine-readable client export is desirable in the canonical architecture, but it is outside the accepted seven-output PhaseIO contract. Adding it requires an explicit P0-P2 contract revision.

The implementation order is exact: **P3 pure render → P4 final capture/publication candidate → P5A prepare → P6-pre preactivation approval → P5B per-cell switch → P6-final postactivation acceptance**. Candidate work may prepare P3 and P4 before all release dependencies land, but no stage may grant the authority of a later stage, and live project publication cannot bypass the ten-selector landing. The exact activation DAG is `P5A → P6-pre → P5B → P6-final`; it has no optional, reverse, or shortcut edge. P6-pre authorizes only the P5B compare-and-swap; P6-final requires post-switch production evidence and is the only final cutover acceptance.

Mechanical activation graph: `nodes=[P5A,P6-pre,P5B,P6-final]`; `edges=[P5A->P6-pre,P6-pre->P5B,P5B->P6-final]`; sole topological order `[P5A,P6-pre,P5B,P6-final]`. Any additional activation edge is a contract-major change.

## 2. Accepted P0-P2/R5 boundary

### 2.1 Frozen source denominator

The fixed-source denominator is exactly 43:

| # | Fixed selector | Current policy state |
|---:|---|---|
| 1 | `_coverage_shortfalls.json` | BLOCKED |
| 2 | `chain_composition_coverage_gaps.md` | PERMITTED |
| 3 | `contract_inventory.md` | PERMITTED |
| 4 | `depth_finalization_report_authority.json` | PERMITTED |
| 5 | `disposition.md` | PERMITTED |
| 6 | `exact_scope_coverage_authority.json` | BLOCKED |
| 7 | `file_coverage_ledger.md` | BLOCKED |
| 8 | `finding_delivery_receipt.json` | BLOCKED |
| 9 | `finding_delivery_successor.json` | PERMITTED |
| 10 | `findings_inventory.md` | PERMITTED |
| 11 | `mandatory_reverification_assignment.json` | BLOCKED |
| 12 | `mandatory_reverification_completion.json` | BLOCKED |
| 13 | `mandatory_reverification_denominator.json` | PERMITTED |
| 14 | `mandatory_reverification_routing.json` | PERMITTED |
| 15 | `negative_closure_broker_authority.json` | BLOCKED |
| 16 | `preverify_inventory_successor.json` | PERMITTED |
| 17 | `judge_decisions.json` | PERMITTED |
| 18 | `report_critical_high.md` | PERMITTED |
| 19 | `report_evidence_projection.md` | PERMITTED |
| 20 | `report_evidence_records.json` | PERMITTED |
| 21 | `report_human_review_authority.json` | PERMITTED |
| 22 | `report_index.md` | PERMITTED |
| 23 | `report_index_status_projection.json` | PERMITTED |
| 24 | `report_low_info.md` | PERMITTED |
| 25 | `report_low_info_a.md` | PERMITTED |
| 26 | `report_low_info_b.md` | PERMITTED |
| 27 | `report_medium.md` | PERMITTED |
| 28 | `report_medium_a.md` | PERMITTED |
| 29 | `report_medium_b.md` | PERMITTED |
| 30 | `report_records.json` | PERMITTED |
| 31 | `report_source_path_authority.json` | PERMITTED |
| 32 | `report_semantic_retention_risks.md` | PERMITTED |
| 33 | `report_semantic_severity_repairs.md` | PERMITTED |
| 34 | `security_obligation_authority.json` | PERMITTED |
| 35 | `security_obligation_lifecycle.json` | PERMITTED |
| 36 | `security_obligation_report_retention.md` | PERMITTED |
| 37 | `severity_binding.md` | PERMITTED |
| 38 | `skeptic_judge_decisions.md` | PERMITTED |
| 39 | `status_binding.md` | PERMITTED |
| 40 | `subsystem_map.md` | PERMITTED |
| 41 | `verification_queue.work_items.json` | PERMITTED |
| 42 | `verification_queue.work_plan.json` | PERMITTED |
| 43 | `verification_runtime_roster.json` | BLOCKED |

The namespace denominator is exactly five:

| # | Namespace selector | Current policy state |
|---:|---|---|
| 1 | `body_manifests/report_*.json` | PERMITTED |
| 2 | `judge_*.md` | BLOCKED |
| 3 | `negative_closure_provider_bundles/**/*` | BLOCKED |
| 4 | `report_evidence_manifests/*.json` | PERMITTED |
| 5 | `report_semantic_*.md` | PERMITTED |

Thus the accepted denominator is 48 selectors: 38 currently permitted and ten currently blocked. The ten blocked selectors are not optional gaps and their absence at runtime is not producer closure.

### 2.2 Required landing for the ten blocked selectors

Before any live P3/P4 path may acquire project publication authority, each blocked selector MUST have:

1. a unique registered PhaseIO output binding or a typed namespace producer binding;
2. an exact writer class, owner suffix, schema or content contract, and canonical-byte validator;
3. a same-run active work-unit receipt with exact contract, launch, and commit-receipt digests;
4. a producer-policy derivation that is replayed before and after capture construction;
5. positive, malformed, stale-run, impersonation, mutation, and missing-receipt fixtures;
6. a production callsite proving the driver can actually create the authority; and
7. an explicit zero-membership authority for a namespace when it has no members, so “empty” is a typed conclusion rather than an unobserved absence.

`finding_delivery_receipt.json` being described as superseded does not waive this rule. Its producer may author a typed supersession receipt that binds the successor, but the accepted selector cannot silently disappear. Similarly, namespace closure is not satisfied by registering one concrete file name: the namespace policy and every observed member must resolve to permitted typed producers, and the namespace-empty case must be authoritative.

The closure artifact MUST enumerate all 48 selectors, state `PERMITTED` for all 48, bind the source-policy inventory digest, and assert `blocked_count = 0`. Any denominator change is a new P0-P2 design decision and cannot be smuggled into P3.

### 2.3 Capture invariants inherited unchanged

P3-P6 inherit these accepted properties:

- Source capture and final capture are distinct immutable identities.
- Every public capture operation receives an exact `expected_config`; no dimension is inferred from ambient state.
- The adapter builds and verifies the source roster authority. Callers cannot supply or override its digest.
- A present source resolves to one active, committed, same-run producer whose exact contract, launch, schema/content, owner, writer, hash, and size replay successfully.
- Fixed absence and namespace membership are captured decisions. Absence-to-presence, presence-to-absence, namespace gain/loss/replacement, same-size rewrite, or producer-policy drift fails replay.
- Candidate construction cannot self-author circular producer requirements. Every consumer re-derives requirements from the live producer policy before and after replay.
- Final capture binds the committed source-capture identity, content digest, run, work-unit, contract, launch, and receipt.
- The terminal replay holds source capture, final capture, every source member, every namespace member, and the clean output namespace in one retained-handle epoch. Its linearization point is the last successful verification.
- No filesystem, callback, ledger, or producer-policy read occurs after the committed in-memory pair is returned to P3.
- Canonical relative paths are POSIX-form, Unicode-normalized, traversal-free, device-name-safe, and collision-free under case folding and filesystem equivalence. Symlinks, reparse points, hard links, unsafe ancestors, physical-identity drift, oversize files, and aggregate size overflow are rejected.

The accepted P0-P2 implementation boundary is the exact tuple `scripts/report_assembly_capture.py` at SHA-256 `f6453ba40cda5464224f6c007618859a237ecd20c6fce5eb6dc2e1f40ae3a89e`/123,676 bytes, `scripts/report_capture_phaseio_authority.py` at `42bc233ecfcb216f861aa79f8c494b3edab0ef336c39b814a5054131389bb504`/91,732 bytes, and `scripts/phase_io_contracts.py` at `f3d580f5f560c10e3337287dec18e6dac4d2d86289ad34346f7b39477d1ec3af`/349,682 bytes, plus the exact 43-fixed/five-namespace selector inventory and source-policy digest `4e28e1f6925a53cf2b45b7318d8924644f3d92fdc8ad1f05c4107c77ab3704a1`. P3 consumes their committed captured result; it does not reinterpret mutable source files or treat these source-file pins as a live receipt.

The current required defense bounds are: 8,192 sources, 16 MiB per source, 128 MiB total source bytes, 64 outputs, 64 namespaces, 8,192 locations, 64 source paths per location, 1,024-character path/pattern limits, 255-character component limits, and 192 MiB maximum canonical representation. A later tightening requires compatibility evidence; a relaxation requires threat review.

All new report JSON uses one canonicalizer and no fallback: `plamen.report_canonical_json.v1`. `CJ(x)` is the UTF-8 encoding produced by `json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)` after recursive schema validation, Unicode-NFC validation of every string, duplicate-key rejection at parse time, integer-only numeric validation, and canonical set/sequence ordering. `CJF(x) = CJ(x) || 0x0a` is the only on-disk JSON form and has exactly one terminal LF. Semantic/identity preimages hash `CJ`; file identities hash `CJF`. BOM, CRLF, floats, non-NFC strings, duplicate keys, alternate escaping on disk, and parse-then-repair are invalid. This contract is the versioned successor of the accepted `scripts/report_assembly_capture.py::_canonical_json_bytes` behavior and is implemented once in `scripts/report_assembly_capture.py`; every P3-P6 serializer and validator imports that implementation. `JCS`, RFC-8785 fallback, backend-native JSON, and a second report canonicalizer are forbidden.

### 2.4 Final-capture v2 successor and v1 migration

`plamen.report_assembly_final_capture.v1` remains the accepted legacy schema at the P0-P2/R5 boundary. It cannot bind the new P3 render request, render result, semantic projection, renderer policy, selector closure, or physical payload set and therefore cannot authorize the P5B path.

The reviewed successor is `plamen.report_assembly_final_capture.v2`, at the same logical artifact identity `scratchpad:report_assembly_final_capture.json`, produced by `report_assemble/final_capture`. Its exact top-level fields are:

| Field | Required value |
|---|---|
| `schema_version` | exact `plamen.report_assembly_final_capture.v2` |
| `artifact_identity` | exact `scratchpad:report_assembly_final_capture.json` |
| `run_id`, `run_generation_id` | exact generation identity pair |
| `expected_config` | exact pipeline/backend/ecosystem/mode/project/scope/report-date configuration |
| `source_predecessor` | v1 predecessor fields: identity, digest, run, producer work unit, contract, launch, and commit-receipt digests |
| `render_input` | identity, schema, digest, size, producer, contract, launch, and commit-receipt of `report_render_input.json` |
| `render_request` | `render_request_id`, canonical preimage digest, renderer implementation digest, render-policy digest, semantic-registry digest, selector-closure digest |
| `render_result` | `render_result_id`, identity, schema, digest, size, producer, contract, launch, and commit-receipt of `report_render_result.json` |
| `projection` | `report_render_projection_id`, identity, schema, digest, size, producer, contract, launch, and commit-receipt of `report_render_projection.json` |
| `output_policy` | exact seven-role logical roster digest, seven-payload physical roster digest, condition-policy digest, limits digest |
| `outputs` | seven identity-sorted entries with logical destination, physical payload identity, role, presence/typed absence, condition, digest/size/content-type, and assembly receipt binding |
| `output_set_sha256` | digest of the canonical ordered seven-entry `outputs` array |
| `quality` | exact gate-denominator digest, result digest, ship/debt classification, and quality/debt output bindings |
| `capture_digest` | `H(CJ(v2 object with capture_digest omitted))` |

Unknown fields, duplicate keys, missing fields, reordered noncanonical arrays, unrecognized roles, and any v1-only candidate on an authoritative cell are rejected. A v2 canonicalizer validates and reserializes without semantic repair.

Migration is asymmetric and exact:

- Before P5B, readers accept v1 for legacy/shadow replay and v2 for candidate replay; writers continue according to the compatibility-cell state.
- After P5B, the authoritative writer emits only v2. The authoritative assembly/publication consumers accept only v2 for new generations.
- A v1 historical generation is replayable but cannot be relabeled v2. `report_assemble/final_capture_migrate_v1` may request a candidate from the normal `report_assemble/final_capture` v2 producer only after consuming the accepted v1 bytes and receipt plus committed P3 request/result/projection/policy/payload authorities for the same run and generation. Missing P3 bindings yield typed `LEGACY_REPLAY_ONLY`, not invented values.
- Replay validates v1 with its accepted validator and v2 with the v2 validator. Dispatch occurs by exact schema after duplicate-key rejection; there is no permissive common parser.
- Current and immediately previous schemas are retained as defined in Section 6.7. Retirement requires the separate reviewed major-migration authority defined there.

The migration proof is a separate artifact at `scratchpad:report_assembly_final_capture_migration_receipt.json`, schema `plamen.report_assembly_final_capture_migration_receipt.v1`, produced only by `report_assemble/final_capture_migrate_v1`. It is never embedded in, appended to, or treated as an extension field of final-capture v2. Its exact top-level fields are `schema_version`, `artifact_identity`, `receipt_id`, `run_id`, `run_generation_id`, `source_v1`, `predecessor_evidence`, `migration_inputs`, `result_v2`, `field_reconciliation`, `disposition`, `failure_codes`, and `receipt_digest`; undeclared fields at every object depth are rejected. `source_v1` is the closed object `{artifact_identity,schema_version,raw_file_sha256,byte_length,capture_digest,producer_work_unit_id,contract_sha256,launch_sha256,commit_receipt_identity,commit_receipt_sha256}` and requires schema `plamen.report_assembly_final_capture.v1`. `result_v2` has the same fields, requires schema `plamen.report_assembly_final_capture.v2` and producer `report_assemble/final_capture`, and binds the exact candidate bytes rather than a reconstructed summary.

`predecessor_evidence` is the closed object `{generation_ledger_row,source_v1_commit_receipt,render_input_commit_receipt,render_projection_commit_receipt,render_result_commit_receipt,output_policy,assembly_payload_commit_receipts}`; every scalar binding includes identity, schema, raw-file digest, producer, contract, launch, and external ArtifactLedger commit-receipt digest, while `assembly_payload_commit_receipts` is the exact seven-role identity-sorted set. `migration_inputs` repeats no authority: it contains exact references and digests for the committed render input, render projection, render result, output policy, and seven payload receipts and must be byte-equal to the corresponding predecessor-evidence bindings. `field_reconciliation` is an array of exactly 15 rows, in this order: `schema_version`, `artifact_identity`, `run_id`, `run_generation_id`, `expected_config`, `source_predecessor`, `render_input`, `render_request`, `render_result`, `projection`, `output_policy`, `outputs`, `output_set_sha256`, `quality`, `capture_digest`. Each row is exactly `{field_name,source_kind,source_binding_ids,expected_value_sha256,result_value_sha256,state}`, where `source_kind` is one of `V1_DIRECT`, `PREDECESSOR_EVIDENCE`, or `RECOMPUTED`, binding IDs are an identity-sorted nonempty set except for the mechanically recomputed schema constant, and `state` is `PASS|FAIL`.

`disposition` is exactly `MIGRATED`, `LEGACY_REPLAY_ONLY`, or `REJECTED`. `MIGRATED` requires the exact accepted v1 source, exact-valid canonical v2 candidate, all predecessor equality checks, the exact 15-row set with every row `PASS`, and empty `failure_codes`; `LEGACY_REPLAY_ONLY` requires no authoritative v2 claim and at least one typed missing-P3 binding; every other mismatch is `REJECTED`. Let `migration_body` be the receipt with `receipt_id` and `receipt_digest` omitted: `receipt_digest=H(CJ(migration_body))` and `receipt_id="rfcm1_" + receipt_digest`; the on-disk identity hashes `CJF` as usual.

## 3. Shared identity, digest, and epoch model

### 3.1 Exact identity namespaces and canonical preimages

All IDs below are lowercase ASCII, content-addressed except the CAS-allocated generation ordinal, and domain-separated. `CJ(x)` is the sole canonical JSON value encoding in Section 2.3. `H(x)` means lowercase hexadecimal SHA-256. The ID separator is `_`; no path or free-form label participates in namespace selection.

| Identity | Exact value and canonical preimage |
|---|---|
| `run_generation_id` | `rg1_` + `H(CJ({"namespace":"plamen.report.run-generation.v1","run_id":run_id,"ordinal":ordinal,"predecessor_run_generation_id":id-or-null,"generation_ledger_prestate_sha256":digest,"expected_config_sha256":digest}))` |
| `render_request_id` | `rrq1_` + `H(CJ({"namespace":"plamen.report.render-request.v1","run_id":run_id,"run_generation_id":rg,"render_input_sha256":digest,"renderer_implementation_sha256":digest,"render_policy_sha256":digest,"semantic_registry_sha256":digest,"selector_closure_sha256":digest}))` |
| `render_result_id` | `rrs1_` + `H(CJ(render-result-body-without-render_result_id))` where the body includes `render_request_id`, projection digest, seven-output set digest, gate digest, and debt digest |
| `report_render_projection_id` | `rrp1_` + `H(CJ({"namespace":"plamen.report.render-projection.v1","projection":projection-body-without-report_render_projection_id}))` where the projection body contains every semantic denominator, record, placement, alias/root, proof scope, and debt row |
| `publication_transaction_id` | `rpt1_` + `H(CJ({"namespace":"plamen.report.publication-transaction.v1","run_id":run_id,"run_generation_id":rg,"final_capture_sha256":digest,"publication_sequence":uint,"output_prestate_sha256":digest,"immutable_project_prestates_sha256":digest,"predecessor_locator_sha256":digest-or-null,"predecessor_ledger_sha256":digest-or-null}))`, where `immutable_project_prestates_sha256` hashes the ordered A/B `{role,path_template,state:"ABSENT"}` rows using their literal brace-bearing templates plus the exact fixed publication-authority-root prestate tagged union `{state:"ABSENT"}` or `{state:"PRESENT",checkpoint_revision,root_sha256,head_checkpoint_sha256}`; no future authority-root poststate participates, and A/B expansion occurs only after this ID derives |

`run_id` remains the PhaseIO audit-run identity. Artifact identities, report/finding IDs, work-unit keys, receipt IDs, and the five namespaces above are non-interchangeable. `report_render_projection_id` is the P3 projection-envelope identity only. It is not, does not contain, and MUST NOT be accepted as the MethodCard/RunBundle `report_projection` authority field defined by `architecture/method-application-rfc.md#312-reportprojection`; that upstream field is a captured semantic input with its own schema, authority, and digest. Neither identity may be copied into or parsed as the other. A parser MUST reject a valid digest with the wrong prefix or namespace.

`run_generation_id` is allocated through an exact CAS ledger at `scratchpad:report_generation_ledger.json`, schema `plamen.report_generation_ledger.v1`, producer `report_cutover/generation_allocate`. The ledger contains `run_id`, `next_ordinal`, the ordered terminal/nonterminal generation rows, and its predecessor digest. Allocation reads a retained handle, creates exclusively for ordinal zero or compares the full predecessor bytes, appends exactly one ordinal, flushes, and returns the ID. A crash before the ledger commit allocates nothing; a crash after it resumes the same generation. An ordinal is never reused. A retry that changes any canonical render input allocates a new generation; crash recovery of unchanged bytes reuses the recorded one.

The remaining IDs are derived, not allocated. Re-derivation is mandatory at every consumer. Equal IDs with unequal canonical preimages are corruption and fail closed. A publication transaction resumes only when the journal, final capture, prestate, sequence, and transaction ID all rederive exactly; otherwise a new transaction cannot be allocated until the old journal is terminally classified.

### 3.2 Exact control and cutover artifacts

These names, schemas, producers, and direct contracts are fixed; PhaseIO status is exact per row and the sole terminal-transport exception is stated below:

| Artifact identity | Schema | Producer | Exact direct inputs / consumers |
|---|---|---|---|
| `scratchpad:report_generation_ledger.json` | `plamen.report_generation_ledger.v1` | `report_cutover/generation_allocate` | prior ledger bytes or authoritative absence + `expected_config`; consumed by render-input and publication |
| `scratchpad:report_source_selector_closure.json` | `plamen.report_source_selector_closure.v1` | `report_cutover/source_selector_closure` | production contract registry, source-policy inventory, 48-selector semantic registry, ten migration receipts; consumed by render-input, P5A, P6-pre/final |
| `scratchpad:report_render_input.json` | `plamen.report_render_input.v1` | `report_assemble/render_input` | committed source capture, selector closure, generation ledger row, `expected_config`; sole P3 render input |
| `scratchpad:report_render_projection.json` | `plamen.report_render_projection.v1` | `report_assemble/render` | exact render-input receipt + immutable renderer/policy digests; consumed by assembly/final-capture |
| `scratchpad:report_render_result.json` | `plamen.report_render_result.v1` | `report_assemble/render` | same render invocation and projection; consumed by assembly/final-capture |
| `scratchpad:report_assembly_final_capture.json` | `plamen.report_assembly_final_capture.v2` | `report_assemble/final_capture` | source/envelope/P3/seven assembly receipts; consumed by publication and replay |
| `scratchpad:report_assembly_final_capture_migration_receipt.json` | `plamen.report_assembly_final_capture_migration_receipt.v1` | `report_assemble/final_capture_migrate_v1` | exact v1 source/receipt + exact v2 candidate/receipt + complete predecessor evidence and 15-field reconciliation; consumed only by migration compatibility/P6 |
| `scratchpad:report_publication_transaction.json` | `plamen.report_publication_transaction.v1` | `report_assemble/publication` | final capture, seven payloads, P5B, generation, root/fixed-locator/ledger and deterministic A/B/publication-authority-root prestates; mutable recovery control only |
| `project:.plamen/report_publication_receipts/{run_generation_id}/{publication_transaction_id}/report_publication_receipt_archive.v1.json` | `plamen.report_publication_receipt_archive.v1` | `report_assemble/publication_receipt_archive` | final capture, payloads, report install, transaction, and predecessor ledger/locator prestates; singleton PhaseIO output and immutable generation-keyed evidence |
| `project:.plamen/report_publication_receipts/{run_generation_id}/{publication_transaction_id}/artifact_ledger_commit_receipt.v1.json` | `plamen.report_publication_receipt_commit_archive.v1` | `report_assemble/publication_receipt_commit_archive` | committed receipt archive plus its already-issued external ArtifactLedger receipt; distinct singleton PhaseIO successor consumed by locator/ledger |
| `project:.plamen/report_publication_receipt_locator.json` | `plamen.report_publication_receipt_locator.v1` | `report_assemble/publication_locator` | exact archive/commit-archive digests and precommitted project publication-authority root; singleton PhaseIO CAS output selected by the ledger head |
| `project:.plamen/report_publication_ledger.json` | `plamen.report_publication_ledger.v1` | `report_assemble/publication_ledger` | locator commit authority + archive chain + final capture/report/transaction and the same fixed-root prestate/next revision; singleton PhaseIO report selector only when selected by the fixed ArtifactLedger head |
| `project:.plamen/report_publication_authority/_artifact_state.json` | ArtifactLedger v2 enclosing exact current `plamen.artifact-work-unit.v2` records and active checkpoint head | `ArtifactLedger/COMMIT_PUBLICATION_AUTHORITY_CHECKPOINT_CAS_V1` | fixed registered authoritative A-D work-unit, contract/launch, input, artifact, global-binding, output-commit, and append-only checkpoint history validated in place across runs |
| `scratchpad:report_publication_receipt.json` | `plamen.report_publication_receipt.v1` | `report_assemble/publication_finalize` | same-run mirror of the ArtifactLedger-authenticated ledger tuple and terminal journal; consumed by current P6-final only, never by later-run predecessor discovery |
| `scratchpad:report_cutover_support_policy.json` | `plamen.report_cutover_support_policy.v1` | `report_cutover/support_policy` | reviewed product support declaration and exact 96-cell base matrix; consumed by P5A and both P6 stages |
| `scratchpad:report_runtime_asset_closure.json` | `plamen.report_runtime_asset_closure.v1` | `report_cutover/runtime_asset_closure` | exact Section 7.4 runtime-asset set, source/package/install identities, and clean-import results; consumed by P5A and both P6 stages |
| `scratchpad:method_card_report_stage_mapping_instance.json` | `plamen.method-card-report-stage-mapping-instance.v1` | `report_cutover/method_card_mapping_instance` | accepted MethodCard/report-spec pins, attested mapping definition, MC6 assurance/acceptance, three resolved entries; consumed by mapping adoption, P5A, and both P6 stages |
| `scratchpad:method_card_report_stage_mapping_adoption_receipt.json` | `plamen.method-card-report-stage-mapping-adoption-receipt.v1` | `report_cutover/method_card_mapping_adopt` | attested mapping instance, exact ReportInterfaceBinding, report-spec identity/receipt, report acceptor/adoption execution; consumed by P5A and both P6 stages |
| `scratchpad:report_cutover_callsite_denominator.json` | `plamen.report_cutover_callsite_denominator.v1` | `report_cutover/callsite_denominator` | accepted pre-cutover tree + exact AST query/version + every report assembly/mutator call node; consumed by assurance plan/P5A/P6 |
| `scratchpad:report_cutover_assurance_plan.json` | `plamen.report_cutover_assurance_plan.v1` | `report_cutover/assurance_plan` | support policy + frozen 19,200 scenario IDs + 52 crash IDs + fixture/held-out/callsite rules; consumed by P6-pre/final |
| `scratchpad:report_heldout_selection_seed.json` | `plamen.report_heldout_selection_seed.v1` | `report_cutover/heldout_selection_seed` | closed pre-selection code/plan/reviewer/algorithm bindings and content boundary; consumed by held-out selection and P6-pre |
| `scratchpad:report_heldout_selection.json` | `plamen.report_heldout_selection.v1` | `report_cutover/heldout_select` | exact seed/nonce/scores and 1,928 selected IDs, with no result or verdict content; consumed by P6-pre, independent review, and P6-final |
| `scratchpad:report_p5_preparation_authority.json` | `plamen.report_p5_preparation_authority.v1` | `report_cutover/p5a_prepare` | selector closure, support policy, runtime-asset closure, assurance plan, candidate code/contracts/schemas, accepted MethodCard mapping adoption, and ProgramFacts active-runtime binding; consumed by P6-pre |
| `scratchpad:report_p6_preactivation_authority.json` | `plamen.report_p6_preactivation_authority.v1` | `report_cutover/p6_preactivation_review` | P5A, pre-result held-out seed/selection, independent preactivation review, complete preactivation tests; consumed only by P5B |
| `scratchpad:report_p5_activation_receipt.json` | `plamen.report_p5_activation_receipt.v1` | `report_cutover/p5b_activate` | P6-pre + exact compatibility-state prestate; consumed by driver, first production publication, P6-final |
| `scratchpad:report_p5_rollback_receipt.json` | `plamen.report_p5_rollback_receipt.v1` | `report_cutover/p5b_rollback` | activation receipt + exact restored compatibility state + preserved canary; consumed by driver and any later P5A |
| `scratchpad:report_schema_retirement_authority.json` | `plamen.report_schema_retirement_authority.v1` | `report_cutover/schema_retirement` | reviewed current/previous-major retirement evidence; consumed by schema dispatch and later support policy |
| `scratchpad:report_cutover_acceptance_authority.json` | `plamen.report_cutover_acceptance_authority.v1` | `report_cutover/p6_final_acceptance` | P5B receipt + postactivation production publication/replay + held-out review + upstream pins; terminal per-cell cutover acceptance |

The table contains exactly 28 artifact row classes; the two brace-bearing A/B publication paths are deterministic templates, not discovery namespaces or extra rows. Exactly 27 rows are declared PhaseIO artifacts with exact owner suffix, `DRIVER` writer, exact schema, same-run requirement where the artifact is run-scoped, canonical bytes, immutable input set, contract digest, launch digest, and commit receipt. The sole exception is the fixed project publication-authority root: it is not a report-authored artifact or receipt but the registered ArtifactLedger v2 active root changed only by `COMMIT_PUBLICATION_AUTHORITY_CHECKPOINT_CAS_V1` after A-D have committed. Its `_artifact_state.json`, output-authority journal, write-once authority/checkpoint CAS records, lock, and exact current A-D records remain under the live ArtifactLedger interface described in Section 5.1. `report_cutover_support_policy.json` and accepted cross-spec pins may be copied into a run only through a receipt that binds their reviewed package identities; their meaning is not regenerated per run.

`report_source_selector_closure.json` contains exactly 48 identity-sorted selector rows, `fixed_count=43`, `namespace_count=5`, `permitted_count=48`, `blocked_count=0`, policy-inventory digest, semantic-registry digest, and ten explicit migration-receipt bindings. Set inequality, a generic producer, absent namespace-empty authority, or any blocked row prevents P5A and live P3/P4.

### 3.3 Required digest bindings

The P3 request binds the exact generation, expected configuration, render-input receipt/digest, source capture/roster/snapshot/policy digests, selector-closure and semantic-registry digests, renderer implementation and policy digests, and every per-source captured membership/byte/provenance row. The result binds the request, projection ID/digest, all semantic denominators, placements and debts, seven physical payload states, seven logical destination states, output-set digest, and every gate denominator/result.

Final capture v2 binds all of those fields plus the seven assembly payload receipts. The publication journal and same-run receipt bind final capture, all payload receipts, root-report/fixed-locator/cross-run-ledger prestates and poststates, the exact A/B archive tuple, the registered project publication-authority root, OS durability results, and publication transaction preimage. The locator binds A/B logical paths/digests and precommits the constant ArtifactLedger root’s exact prestate and next revision; the ledger binds the A/B/C authority identities and the same fixed-root CAS denominator. After D commits, ArtifactLedger advances an exact A-D authority checkpoint whose live v2 work-unit, contract/launch, input, artifact, global-binding, commit-authority, output-authority-journal, and write-once-CAS records replay in place. Copied receipt hashes are equality projections only and never authority. P5A, P6-pre, P5B, and P6-final each bind all direct predecessor artifact identities, schemas, content digests, producer contracts, launches, and receipts; transitive equality is replayed rather than trusted from copied summary fields.

All structured authority bytes use UTF-8, Unicode NFC, duplicate-key rejection, no floats, deterministic key ordering, and exactly one terminal LF. Markdown bytes use UTF-8/NFC, LF, and deterministic construction from the typed projection.

### 3.4 Epochs and linearization

| Epoch | Owner | Linearization and allowed work |
|---|---|---|
| E0 configuration/generation freeze | driver/PhaseIO | CAS-allocate generation; freeze `expected_config`, selector closure, semantic registry, renderer/policy, support-policy, MC6, and ProgramFacts digests. |
| E1 source/envelope commit | P0-P2 + `render_input` | Commit/replay source capture, build the exact render-input envelope, then replay live producer policy and bytes before returning one in-memory value. |
| E2 pure render | `report_assemble/render` | Transform only the committed in-memory envelope; emit projection and render-result values with no external observation. |
| E3 assembly payload commit | `report_assemble/assembly` | Commit seven scratchpad payload artifacts from exact P3 bytes; no project-root write. |
| E4 final capture v2 | `report_assemble/final_capture` | Commit v2 over source/envelope/request/result/projection/policy and seven assembly receipts; run combined terminal replay. |
| E5 publication arm | `report_assemble/publication` | Pin project report/fixed-locator/publication-ledger prestates, derive transaction/archive identities, create journal and exclusive client staging. |
| E6 project install | publication A-D work units | Install project-root `AUDIT_REPORT.md`, then commit singleton A receipt archive, B commit archive, C fixed locator, and D ledger successor in exact predecessor order; do not modify assembly payloads or semantics. |
| E7 receipt/recovery closure | ArtifactLedger checkpoint/finalize/driver | Install and live-replay the deterministic A-D project authority root, then commit the same-run mirror or terminally abort/roll back/quarantine; P6-final may consume only the closed tuple. |

E4 is the last semantic/source-authority observation. E5/E6 may observe only pinned destination prestates and OS results needed to execute the transaction. Publication cannot re-render, re-run a gate, reread a source, consult a ledger for new semantic meaning, or modify any assembly payload. The seven scratchpad payloads and final capture remain assembly-owned; the journal, singleton A-D artifacts, ArtifactLedger authority root, scratch receipt mirror, and project-root install remain owned by their exact publication/ArtifactLedger operations.

## 4. P3 — Pure report renderer and projection authority

### 4.1 Contract

P3 does **not** assume that the current `CommittedReportSourceInputs` carries generation or per-source producer contract/launch/receipt provenance. That accepted R5 value remains a source-capture replay result only. The new `report_assemble/render_input` work unit converts it into the exact committed successor envelope `scratchpad:report_render_input.json`, schema `plamen.report_render_input.v1`.

The envelope top level is exact:

| Field | Content |
|---|---|
| `schema_version`, `artifact_identity` | exact schema and path |
| `run_id`, `run_generation_id`, `expected_config` | exact run/generation and full configuration |
| `generation_allocation` | ledger identity/digest/prestate/ordinal/receipt |
| `source_capture` | identity/schema/digest/size/producer/contract/launch/commit receipt |
| `source_roster` | authority and snapshot digests; 43+5 counts and exact membership digest |
| `selector_closure` | identity/schema/digest/size/producer/contract/launch/receipt; 48/48 permitted and 0 blocked |
| `semantic_registry` | exact registry version/digest and 48 selector parser-policy rows |
| `render_policy` | renderer implementation, policy, template, quality-gate, limits, and output-roster digests |
| `required_external_authorities` | exact closed `SHADOW_UNAVAILABLE|BOUND` union below; P5A and every later stage require `BOUND` |
| `metadata` | project name, report date, scope, pipeline, backend, ecosystem, and mode copied from `expected_config` |
| `fixed_sources` | exactly 43 selector rows |
| `namespaces` | exactly five namespace rows with an exact ordered member set or typed authoritative empty set |
| `terminal_replay` | replay epoch ID, retained physical identity digest, pre/post policy digests, and replay receipt |
| `aggregate` | source count/bytes, envelope digest basis, and all enforced limit values |

Each fixed-source row has exact fields `selector`, `role`, `state=PRESENT|ABSENT`, `absence_authority` when absent, `artifact_identity`, `content_encoding=UTF-8`, `content_utf8` when present, byte digest/size, physical-identity digest, semantic parser/schema/precedence IDs, and producer work-unit/owner/writer/schema/contract/launch/commit-receipt bindings. Each namespace row carries the same policy fields and an identity-sorted `members` array of complete source rows. Bytes are inline canonical JSON strings after strict UTF-8/NFC validation; no path is a substitute for bytes.

`required_external_authorities.state=SHADOW_UNAVAILABLE` is legal only in P3/P4 isolated candidate generations and contains exactly `method_card_state:UNAVAILABLE`, `program_facts_state:UNAVAILABLE`, `debt_codes:[METHOD_CARD_AUTHORITY_INVALID,PROGRAM_FACTS_AUTHORITY_INVALID]`, `ship_disposition:NO_SHIP`, and an all-false authority ceiling. It renders both domains as provisional unknown/debt, never zero or clean. `state=BOUND` contains exactly: (1) the accepted MethodCard-spec file identity, attested `plamen.method-card-report-stage-mapping.v2` definition, attested `plamen.method-card-report-stage-mapping-instance.v1`, PASS `plamen.method-card-report-stage-mapping-adoption-receipt.v1`, attested `scratchpad:method_card_application_assurance_authority.json`, and PASS MC6 stage-acceptance receipt; and (2) the accepted ProgramFacts-spec file identity, exact `ProgramFactsPublicV3Binding` defined by the MethodCard pin, reviewed release-freeze pair, final Gate-3 cutover receipt, runtime-closure identity, and 160-case/691-execution acceptance-evidence identity. Every leaf is a complete file/candidate/attested/receipt binding, not a copied digest. A transition from `SHADOW_UNAVAILABLE` to `BOUND` changes render input and therefore allocates a new report generation.

The envelope producer performs three live checks: (1) rederive producer requirements and validate source bytes before envelope construction, (2) commit the envelope through PhaseIO and replay every live producer/source plus selector closure against the committed bytes, and (3) immediately before `report_assemble/render` launch, revalidate the envelope receipt and repeat the combined source/envelope terminal replay under retained handles. Only then does the adapter return an immutable in-memory value. Any producer policy, membership, byte, receipt, expected-config, or physical-identity drift fails before P3. P3 itself performs no live revalidation because doing so would violate purity.

`report_assemble/render` has exactly one PhaseIO input, `scratchpad:report_render_input.json`, and exactly two control outputs: `scratchpad:report_render_projection.json` and `scratchpad:report_render_result.json`. The immutable renderer policy is package data whose digest is already in the envelope. The P3 function returns both values in memory; PhaseIO validates and commits them without asking the renderer to reread anything.

The renderer MUST be referentially transparent: the same canonical input and renderer-policy digests produce byte-identical result digests. P3 MUST NOT access:

- the project or scratchpad filesystem;
- `Path`, glob, stat, source files, or report-record recovery paths;
- wall or monotonic clock, locale, environment variables, process state, host name, or current working directory;
- network, model, tool, MCP, or human callbacks;
- mutable work-unit or receipt ledgers; or
- randomness, unordered directory iteration, platform-native line endings, or project basename discovery.

`project_name`, `report_date`, scope, backend, ecosystem, mode, pipeline, and run identity come only from the envelope. Source excerpts and locations come only from inline captured bytes and location decisions. If required information is absent, the result records a closed typed debt or fails the appropriate integrity gate; it never performs a live recovery read.

### 4.2 Exact result

`report_render_projection.json` contains every normalized semantic record, authority/precedence decision, denominator, placement, alias/root relation, evidence/proof scope, human-review/negative/MethodCard/ProgramFacts projection, and debt row. `report_render_result.json` contains:

1. the render request and projection envelope;
2. all reconciliation ledgers and gate results needed to validate retention;
3. an exact seven-role output state map; and
4. for every present output, complete immutable bytes, digest, size, content type, and destination identity; for every absent conditional output, an explicit condition-derived absence reason.

The seven logical roles and assembly-owned physical payloads are exactly:

| Logical destination | Physical assembly payload identity | Role | State rule |
|---|---|---|---|
| `project:AUDIT_REPORT.md` | `scratchpad:report_client_payload.md` | `CLIENT_REPORT` | MUST be present |
| `scratchpad:report_quality.md` | same as destination | `REPORT_QUALITY` | MUST be present |
| `scratchpad:report_traceability_internal.md` | same as destination | `INTERNAL_TRACEABILITY` | present or explicit absence |
| `scratchpad:report_consolidation_internal.md` | same as destination | `INTERNAL_CONSOLIDATION` | present or explicit absence |
| `scratchpad:report_evidence_quality_receipt.json` | same as destination | `REPORT_EVIDENCE_QUALITY` | present or explicit absence |
| `scratchpad:report_assemble_retry_hint.md` | same as destination | `REPORT_RETRY_HINT` | present or explicit absence |
| `scratchpad:report_quality_debt.json` | same as destination | `REPORT_QUALITY_DEBT` | present or explicit absence |

P3 cannot commit any payload and cannot confer final-capture or publication authority. `report_assemble/assembly` consumes the two P3 control outputs and commits the seven physical payload states. Publication never owns or rewrites them; it installs the committed `CLIENT_REPORT` payload at its logical project destination. Only installed `AUDIT_REPORT.md` is client-public. The six other payloads are authoritative downstream PhaseIO contract outputs.

### 4.3 Typed semantic-source registry and precedence

Producer authenticity proves who wrote bytes; it does not prove that the bytes carry typed semantic truth. P3 therefore uses the immutable registry `plamen.report_semantic_source_registry.v1`. The registry is package data, is hashed into render input and selector closure, and has exactly the 48 rows below. Each parser is strict, total over its schema, duplicate-identity rejecting, and emits canonical normalized records plus an explicit denominator. `unstructured.v1` is only the producer transport schema where shown; the named semantic parser remains mandatory.

Precedence is closed:

- `A0` is terminal typed authority for the named domain. Exactly one active A0 decision exists per semantic identity unless the schema explicitly defines a join.
- `A1` is an authoritative typed projection or constituent input. It may add fields within its domain but cannot override an A0 decision.
- `A2` is proposal, fallback, cache, or debt evidence. It can retain an unresolved item but cannot close or alter an A0/A1 record.
- `A3` is presentation prose. It supplies wording/excerpts only after exact identity mapping and cannot supply missing semantic truth.

| # | Selector | Semantic domain | Exact source schema → semantic parser | Precedence |
|---:|---|---|---|---|
| 1 | `_coverage_shortfalls.json` | coverage shortfall/unknown remainder | `plamen.coverage_shortfall_authority.v1` → `json.coverage-shortfall-authority.v1` | A0 |
| 2 | `chain_composition_coverage_gaps.md` | chain coverage debt | `unstructured.v1` → `md.chain-coverage-debt.v1` | A1 |
| 3 | `contract_inventory.md` | component/scope inventory | `unstructured.v1` → `md.contract-inventory.v1` | A1 |
| 4 | `depth_finalization_report_authority.json` | depth completion/unknown remainder | `plamen.depth_finalization_report_authority.v1` → `json.depth-finalization-report-authority.v1` | A0 |
| 5 | `disposition.md` | disposition proposals | `plamen.report_disposition_proposals.v1` → `md.report-disposition-proposals.v1` | A2 |
| 6 | `exact_scope_coverage_authority.json` | exact scope/coverage | `plamen.exact_scope_coverage_authority.v1` → `json.exact-scope-coverage-authority.v1` | A0 |
| 7 | `file_coverage_ledger.md` | file-level coverage | `plamen.file_coverage_ledger.v1` → `md.file-coverage-ledger.v1` | A0 |
| 8 | `finding_delivery_receipt.json` | legacy delivery supersession | `plamen.finding_delivery_supersession_receipt.v1` → `json.finding-delivery-supersession.v1` | A0 |
| 9 | `finding_delivery_successor.json` | finding delivery denominator | `plamen.finding_delivery_successor.v1` → `json.finding-delivery-successor.v1` | A0 |
| 10 | `findings_inventory.md` | candidate context/constituents | `plamen.canonical_finding_inventory.v1|unstructured.v1` → `md.findings-inventory.v1` | A1 |
| 11 | `judge_decisions.json` | terminal judge/disposition decision | `plamen.judge_decisions.v1` → `json.judge-decisions.v1` | A0 |
| 12 | `mandatory_reverification_assignment.json` | reverification assignments | `plamen.mandatory_reverification_assignment.v1` → `json.mandatory-reverification-assignment.v1` | A0 |
| 13 | `mandatory_reverification_completion.json` | reverification completion | `plamen.mandatory_reverification_completion.v1` → `json.mandatory-reverification-completion.v1` | A0 |
| 14 | `mandatory_reverification_denominator.json` | reverification denominator | `plamen.mandatory_reverification_denominator.v1` → `json.mandatory-reverification-denominator.v1` | A0 |
| 15 | `mandatory_reverification_routing.json` | reverification routing | `plamen.mandatory_reverification_routing.v1` → `json.mandatory-reverification-routing.v1` | A0 |
| 16 | `negative_closure_broker_authority.json` | terminal negative closure/unknown | `plamen.negative_closure_broker_authority.v1` → `json.negative-closure-broker-authority.v1` | A0 |
| 17 | `preverify_inventory_successor.json` | preverify denominator/supersession | `plamen.preverify_inventory_successor.v1` → `json.preverify-inventory-successor.v1` | A0 |
| 18 | `report_critical_high.md` | Critical/High finding prose | `plamen.report_finding_bodies.v1` → `md.report-finding-bodies.v1` | A3 |
| 19 | `report_evidence_projection.md` | evidence presentation | `plamen.report_evidence_projection.v1` → `md.report-evidence-projection.v1` | A2 |
| 20 | `report_evidence_records.json` | evidence/proof scope | `plamen.report_evidence_bundle.v1` → `json.report-evidence-bundle.v1` | A0 |
| 21 | `report_human_review_authority.json` | human-review assignments | `plamen.report_human_review_authority.v1` → `json.report-human-review-authority.v1` | A0 |
| 22 | `report_index.md` | index/presentation mapping | `plamen.report_index_projection.v1|unstructured.v1` → `md.report-index.v1` | A2 |
| 23 | `report_index_status_projection.json` | terminal report status/tier projection | `plamen.report_index_status_projection.v1` → `json.report-index-status-projection.v1` | A0 |
| 24 | `report_low_info.md` | Low/Info finding prose | `plamen.report_finding_bodies.v1` → `md.report-finding-bodies.v1` | A3 |
| 25 | `report_low_info_a.md` | Low/Info shard prose | `plamen.report_finding_bodies.v1` → `md.report-finding-bodies.v1` | A3 |
| 26 | `report_low_info_b.md` | Low/Info shard prose | `plamen.report_finding_bodies.v1` → `md.report-finding-bodies.v1` | A3 |
| 27 | `report_medium.md` | Medium finding prose | `plamen.report_finding_bodies.v1` → `md.report-finding-bodies.v1` | A3 |
| 28 | `report_medium_a.md` | Medium shard prose | `plamen.report_finding_bodies.v1` → `md.report-finding-bodies.v1` | A3 |
| 29 | `report_medium_b.md` | Medium shard prose | `plamen.report_finding_bodies.v1` → `md.report-finding-bodies.v1` | A3 |
| 30 | `report_records.json` | canonical report finding/disposition/cluster records | `plamen.report_records.v1` → `json.report-records.v1` | A0 |
| 31 | `report_source_path_authority.json` | source paths/locations | `plamen.report_source_path_authority.v1` → `json.report-source-path-authority.v1` | A0 |
| 32 | `report_semantic_retention_risks.md` | retention review debt | `plamen.report_human_review_markdown.v1` → `md.retention-review-debt.v1` | A2 |
| 33 | `report_semantic_severity_repairs.md` | severity review debt | `plamen.report_human_review_markdown.v1` → `md.severity-review-debt.v1` | A2 |
| 34 | `security_obligation_authority.json` | security-obligation denominator | `plamen.security_obligation_authority.v2` → `json.security-obligation-authority.v2` | A0 |
| 35 | `security_obligation_lifecycle.json` | obligation lifecycle/closure | `plamen.security_obligation_lifecycle.v1` → `json.security-obligation-lifecycle.v1` | A0 |
| 36 | `security_obligation_report_retention.md` | obligation retention cache | `plamen.security_obligation_report_retention.v1` → `md.security-obligation-retention.v1` | A2 |
| 37 | `severity_binding.md` | final severity/adjustments | `unstructured.v1` → `md.severity-binding.v1` | A0 |
| 38 | `skeptic_judge_decisions.md` | skeptic proposals/challenge | `plamen.skeptic_proposal_projection.v1` → `md.skeptic-judge-proposals.v1` | A1 |
| 39 | `status_binding.md` | final verification/status | `unstructured.v1` → `md.status-binding.v1` | A0 |
| 40 | `subsystem_map.md` | subsystem/scope mapping | `unstructured.v1` → `md.subsystem-map.v1` | A1 |
| 41 | `verification_queue.work_items.json` | verification item denominator | `unstructured.v1` → `json.verification-work-items.v1` | A0 |
| 42 | `verification_queue.work_plan.json` | verification plan/assignments | `unstructured.v1` → `json.verification-work-plan.v1` | A0 |
| 43 | `verification_runtime_roster.json` | runtime/verifier provenance | `plamen.verification_runtime_roster.v1` → `json.verification-runtime-roster.v1` | A0 |
| 44 | `body_manifests/report_*.json` | tier-body identity routing | `unstructured.v1` → `json.report-body-manifest.v1` | A1 |
| 45 | `judge_*.md` | legacy judge fallback | `plamen.judge_fallback_projection.v1` → `md.judge-fallback-projection.v1` | A2 |
| 46 | `negative_closure_provider_bundles/**/*` | provider-level negative evidence | `plamen.negative_closure_provider_bundle.v1` → `bundle.negative-closure-provider.v1` | A1 |
| 47 | `report_evidence_manifests/*.json` | evidence manifest/provenance | `plamen.report_evidence_manifest.v1` → `json.report-evidence-manifest.v1` | A1 |
| 48 | `report_semantic_*.md` | typed semantic debt/projection namespace | `plamen.*|unstructured.v1` → `md.report-semantic-namespace.v1` with member-name grammar | A2 |

The ten current blockers land through these exact registered migrations:

| Selector | Producer work unit/owner suffix | Writer | Exact output schema |
|---|---|---|---|
| `_coverage_shortfalls.json` | `report_coverage/shortfall_authority` | DRIVER | `plamen.coverage_shortfall_authority.v1` |
| `exact_scope_coverage_authority.json` | `report_scope/exact_coverage_authority` | DRIVER | `plamen.exact_scope_coverage_authority.v1` |
| `file_coverage_ledger.md` | `report_scope/file_coverage_ledger` | DRIVER | `plamen.file_coverage_ledger.v1` |
| `finding_delivery_receipt.json` | `verify_queue/finding_delivery_legacy_receipt` | DRIVER | `plamen.finding_delivery_supersession_receipt.v1` |
| `mandatory_reverification_assignment.json` | `verify_queue/mandatory_assignment` | DRIVER | `plamen.mandatory_reverification_assignment.v1` |
| `mandatory_reverification_completion.json` | `verify_queue/mandatory_completion` | DRIVER | `plamen.mandatory_reverification_completion.v1` |
| `negative_closure_broker_authority.json` | `negative_closure/broker` | DRIVER | `plamen.negative_closure_broker_authority.v1` |
| `verification_runtime_roster.json` | `verify_queue/runtime_roster` | DRIVER | `plamen.verification_runtime_roster.v1` |
| `judge_*.md` | `skeptic/judge_fallback.<member_id>` plus typed namespace-empty authority | DRIVER | `plamen.judge_fallback_projection.v1` |
| `negative_closure_provider_bundles/**/*` | `negative_closure/provider.<provider_id>` plus typed namespace-empty authority | DRIVER | `plamen.negative_closure_provider_bundle.v1` |

Every producer has an exact positive, malformed, stale-run, wrong-owner/writer/schema, generic-impersonation, mutation, and missing-receipt fixture. Namespace producers additionally prove member-name grammar, member set equality, member producer closure, and an authenticated zero-member state.

Every parser emits `plamen.report_semantic_record.v1` rows with the exact common fields `semantic_key`, `domain`, `subject_id`, `field_name`, `typed_value`, `authority_class`, `source_selector`, `source_member_or_null`, `source_artifact_identity`, `source_sha256`, `parser_id`, `source_schema`, `denominator_id`, and `record_state=VALUE|EXPLICIT_NULL|UNKNOWN|NOT_APPLICABLE`. `semantic_key` is `domain + ":" + subject_id + ":" + field_name`; components are nonempty NFC strings without colon/control characters. `typed_value` is validated by the closed domain union below; unknown domains/fields/enum members are rejected.

| Domain union | Exact required typed fields |
|---|---|
| `FINDING` | candidate/finding ID, lineage IDs, eligible boolean, placement, root ID/null, constituent IDs, disposition, disposition authority/reason, remediation IDs |
| `SEVERITY_STATUS` | finding ID, impact, likelihood, final severity, adjustment enum/reason, verification status, challenge state |
| `EVIDENCE_PROOF` | finding ID, evidence-record IDs, manifest IDs, capability class, proof scope, premises, environment, negative/positive polarity |
| `COVERAGE_SCOPE` | denominator ID, expected IDs/count/digest, observed IDs/count/digest, exact/lower-bound state, unknown remainder/reason, components/files/modes |
| `NEGATIVE_CLOSURE` | broker decision ID, provider denominator/results, searched scope, terminal/nonterminal state, unknown remainder, reviewer/replay bindings |
| `HUMAN_REVIEW` | assignment ID, subject ID, premise/question, original consequence/severity, owner, completion state/evidence |
| `LOCATION` | finding ID, location decision, normalized paths/ranges, provenance source paths, unresolved reason |
| `OBLIGATION` | obligation ID, lifecycle state, candidate/finding links, evidence/premise IDs, report-retention state |
| `METHODOLOGY` | MethodCard/ProgramFacts identity, denominator/application/generation state, debt/unknown/unresolved assignment, upstream authority binding |
| `PRESENTATION` | report/finding/section ID, prose kind, content-present state, sanitized content, cited semantic keys |

Field authority/precedence is exact:

| Semantic fields | Terminal authority/join | Required equality/projection | Non-authoritative fallback |
|---|---|---|---|
| candidate universe and delivery | set-equality join of `finding_delivery_successor.json`, `preverify_inventory_successor.json`, queue items/plan, and legacy supersession receipt | `report_records.json` and index status must contain the exact promoted/subsumed identities | findings inventory supplies context only |
| root/alias/constituent/placement | `report_records.json` | index/status/body manifests set-equal; human-review placement must match its authority | report index and tier prose |
| challenged disposition | `judge_decisions.json`; otherwise terminal disposition in `report_records.json` | index status and report records must copy exact decision | `disposition.md`, skeptic/fallback judge proposals |
| severity | `severity_binding.md` | report records/index status/tier heading exact equality | severity-repair debt cannot rerate |
| verification status | `status_binding.md` | report records/index status/tier tag exact equality | skeptic/prose cannot promote |
| evidence/proof scope | `report_evidence_records.json` | evidence manifests set-equal; projection cites exact records | evidence Markdown wording |
| scope/coverage | lossless join of exact-scope, file-coverage, coverage-shortfall, depth-finalization, chain-debt, contract/subsystem inventories | queue/obligation denominators reconcile to the same scoped IDs | semantic namespace debt retains unknowns |
| negative closure | `negative_closure_broker_authority.json` | provider bundles equal broker provider denominator/results | no fallback may close; missing broker stays unknown |
| human review | `report_human_review_authority.json` | retention/severity debt Markdown set-equal by assignment ID | no prose-only completion |
| location | `report_source_path_authority.json` | finding bodies may cite only normalized bound locations | no live recovery or body-invented path |
| obligation lifecycle | join of obligation authority + lifecycle | retention Markdown set-equal by obligation ID | no cache may close lifecycle |
| methodology | accepted MC6 + ProgramFacts authorities in envelope | report projection set-equal by upstream identity | prompt/template prose has no authority |
| presentation | typed A3 body/index sources after all mappings above | every cited semantic key resolves exactly | missing prose becomes closed shippable debt |

“Join” means every input owns disjoint named fields or must satisfy the stated set/count/digest equality; it never means last-writer wins. The renderer computes expected and observed sets for each union row and stores both in `report_render_projection.json`. This normalized schema and field table, rather than file presence, are the mechanical retention oracle.

For one semantic identity, conflicting A0 records, missing required A0 authority, parser ambiguity, invalid identity mapping, or a lower-precedence record that would change placement/severity/status/disposition/proof/negative closure is `SEMANTIC_AUTHORITY_AMBIGUOUS` and `NO_SHIP`. A2/A3 wording disagreement that cannot affect a typed field becomes visible `OPTIONAL_ENRICHMENT_MISSING` debt and the higher-precedence value is retained. Unknown parser/schema/member names fail closed. An authoritative empty denominator is a parsed A0 record; absent or unread bytes never mean zero.

### 4.4 Content ownership and retention

P3 is a renderer, not an adjudicator. It MUST NOT create, delete, promote, refute, rerate, redisposition, recluster, or close a finding or candidate. For each authoritative domain it MUST select one exact upstream authority, reject contradictory peers, and preserve the upstream record.

The render candidate MUST carry and reconcile these denominators:

- raw candidate and promoted finding identities;
- active report-eligible finding identities;
- excluded, duplicate/alias, false-positive, deferred, unresolved, and human-review identities;
- root-cause roots and all constituent identities;
- severity/status decisions and all adjustment reasons;
- evidence records, evidence manifests, proof-capability and proof-scope decisions;
- negative-closure provider results, broker decisions, unknown remainder, and unsupported/timeout states;
- source-location decisions and all source-path provenance;
- security obligations and lifecycle/report-retention decisions; and
- MethodCard catalog, work-plan, application, assurance, debt, unknown, and assignment identities when supplied by authoritative inputs.

Every report-eligible identity MUST occur exactly once across `BODY`, `APPENDIX`, `EXCLUDED_WITH_REASON`, and `UNRESOLVED_HUMAN_REVIEW`. “Exactly once” applies to placement, not semantic retention: every absorbed member of a consolidated root-cause finding remains present in the typed alias/consolidation map and in the root section’s retained consequences, premises, locations, evidence, proof scopes, status, and remediation distinctions.

Every non-eligible candidate MUST still have one terminal typed disposition or one retained unresolved/debt state. The renderer MUST expose denominator equality:

`candidate identities = rendered placements + alias members + terminal exclusions + retained unresolved/debt identities`

with disjoint terminal identity sets, except for explicitly typed alias membership. A zero denominator MUST be asserted as an authoritative zero and tested; an omitted or unread denominator is not zero.

### 4.5 Root-cause deduplication

P3 may render an upstream root-cause cluster but MUST NOT infer one from text similarity, embeddings, same file, same label, impact wording, or a shared remediation phrase. A cluster is renderable only when a committed cluster/alias authority supplies:

- root identity and every member identity;
- the shared state transition, capability, broken invariant, or causal mechanism;
- the relation between each member’s premise and terminal consequence;
- independent semantic-review disposition; and
- a reversible member-to-root mapping.

The root section MUST preserve every materially distinct exploitability condition, trust boundary, branch, proof scope, consequence, severity/status fact, location, and remediation requirement. If two members require different severities, proof claims, premises, or fixes, P3 MUST preserve those distinctions inside the projection and MUST NOT flatten them merely to simplify prose. Missing cluster authority retains separate findings or a visible unresolved state; it does not authorize disappearance.

### 4.6 Severity, status, evidence, and proof scope

Final severity is the committed typed projection of impact × likelihood plus authorized adjustments and independent challenge. P3 MUST reproduce the exact final severity and adjustment provenance. It cannot use prose, evidence-tag prestige, report tier, model opinion, or “client worthiness” to change severity.

Verification status and proof scope are separate fields. `CONFIRMED`, `VERIFIED`, `UNVERIFIED`, `CONTESTED`, `UNRESOLVED`, and any other allowed state MUST follow the committed status and evidence authorities. A proof demonstrates only the capabilities, premises, path, environment, and consequence that its evidence authority binds. Report prose MUST NOT promote code trace to executable proof, one ecosystem to another, a mock to production, a local invariant to a cross-chain claim, or a sampled path to complete coverage.

Conflicting or stale severity/status/evidence inputs are integrity failures if no unique upstream authority exists. Missing optional enrichment after a unique authoritative decision is visible quality debt. A contested or insufficiently supported finding remains in its authorized body/appendix/unresolved placement with explicit proof limits; it cannot become a false positive by omission.

### 4.7 Negative closure and human review

A negative statement such as “no finding,” “not exploitable,” “covered,” or “no remaining candidate” is renderable as terminal only when the central typed negative-closure broker binds:

- provider roster and expected provider denominator;
- completed, unsupported, timed-out, and unknown provider states;
- exact searched scope and capability limitations;
- candidate/result identities and reconciliation; and
- reviewer/replay authority.

Provider absence, timeout, unsupported tooling, broker absence, stale run, or unknown remainder is not a clean negative. It MUST remain visible as debt, limitation, unresolved coverage, or human-review work. `report_human_review_authority.json` is authoritative for human-review routing. P3 MUST retain every assignment, reason, original severity or consequence, premise to decide, owner, and completion state. A Markdown appendix is a projection of that authority, never its replacement.

### 4.8 Required client-report projection

Within the existing template vocabulary, `AUDIT_REPORT.md` MUST deterministically project the following closed mandatory section set; an added section requires a render-policy/schema successor:

- report identity, project, date, run snapshot, audited scope, repository/commit when captured, pipeline/backend/ecosystem/mode, and explicit limitations;
- executive summary and exact severity/status counts;
- scope, components, exclusions, build/tool constraints, threat model, trust boundaries, assumptions, and security invariants when authoritative;
- methodology and MethodCard coverage with assurance state and debt;
- severity matrix and exact final severity/status/proof-scope meanings;
- one complete section for each body finding and retained appendix entry;
- reversible root-cause/consolidation consequences without exposing forbidden internal implementation identifiers in client prose;
- unresolved/human-review work and material negative-closure limitations;
- priority remediation ordering derived from typed severity/decision data; and
- an explicit report-quality/coverage limitation when any haltless debt remains.

The current PDF corpus shows that title/status/date, scope/commit/platform, overview, methodology, finding summary, severity matrix, finding bodies, remediation, and disclaimer are common client expectations. That observation informs presentation only. It cannot create schema, content authority, severity policy, or a pass threshold.

### 4.9 Pure quality gates

P3 runs quality gates over captured input bytes and its in-memory candidate. Every gate result MUST state a frozen expected denominator, observed denominator, per-item dispositions, failures, warnings, and unknown remainder. A gate with an unintentionally empty denominator cannot pass.

Integrity gates include:

- canonical parsing and byte determinism;
- exact source and seven-output set equality;
- candidate/finding/disposition/negative/human-review/obligation/MethodCard retention;
- unique report IDs and exact summary/body/appendix counts;
- severity, status, proof-scope, premise, source-location, and cluster-member parity;
- no unauthorized addition, deletion, merge, split, rerating, redisposition, or negative closure;
- client-path/privacy rules and internal-ID leakage controls;
- content and aggregate size limits; and
- exact condition-derived presence/absence for the five conditional outputs.

An integrity failure produces no committable final capture and no new canonical publication. The candidate and typed diagnostic MAY be retained in non-authoritative staging for investigation.

The debt taxonomy is closed. The only `SHIP_WITH_LIMITATION` codes are:

| Code | Required condition |
|---|---|
| `OPTIONAL_ENRICHMENT_MISSING` | optional explanatory excerpt/context absent; all typed truth retained |
| `OPTIONAL_TOOL_UNAVAILABLE` | nonmandatory tool/provider unavailable with exact affected scope |
| `SOURCE_LOCATION_UNRESOLVED` | authoritative location decision is `UNRESOLVED`; finding remains visible |
| `COVERAGE_UNKNOWN_RETAINED` | upstream typed unknown remainder retained without clean negative claim |
| `HUMAN_REVIEW_OPEN` | typed human-review assignment remains open and visible |
| `STYLE_DEBT` | deterministic style/body-quality threshold missed without semantic loss |

The only `NO_SHIP` codes are:

| Code | Failure class |
|---|---|
| `SELECTOR_CLOSURE_INVALID` | 48-selector/ten-migration closure invalid |
| `EXPECTED_CONFIG_MISMATCH` | dimension/configuration mismatch |
| `SOURCE_CAPTURE_INVALID` | source capture/roster/snapshot invalid |
| `PRODUCER_REPLAY_INVALID` | producer policy, provenance, or terminal replay invalid |
| `RENDER_INPUT_INVALID` | envelope schema/content/receipt invalid |
| `SEMANTIC_AUTHORITY_AMBIGUOUS` | parser/precedence/authority truth not unique |
| `RETENTION_SET_MISMATCH` | any denominator/identity/constituent lost or added |
| `UNAUTHORIZED_SEMANTIC_MUTATION` | renderer changed an upstream decision |
| `FINAL_CAPTURE_INVALID` | v2 binding/replay invalid |
| `OUTPUT_SET_MISMATCH` | logical or physical seven-role set mismatch |
| `PUBLICATION_PRESTATE_INVALID` | root report/fixed-locator/publication-ledger, deterministic immutable publication path, or fixed ArtifactLedger root prestate/revision not authoritative |
| `PUBLICATION_CAS_FAILED` | generation, report, fixed locator, publication ledger, immutable archive create, project ArtifactLedger checkpoint install, or journal compare-and-swap failed |
| `PUBLICATION_DURABILITY_UNKNOWN` | flush/install result uncertain |
| `PUBLICATION_RECOVERY_AMBIGUOUS` | crash state cannot be uniquely classified |
| `METHOD_CARD_AUTHORITY_INVALID` | accepted MC6 authority missing/stale/mismatched |
| `PROGRAM_FACTS_AUTHORITY_INVALID` | accepted ProgramFacts spec/runtime/cutover authority missing/stale/mismatched |
| `UNSUPPORTED_COMPATIBILITY_CELL` | support-policy cell not approved for activation |
| `INDEPENDENT_REVIEW_BLOCK` | required preactivation/final independent approval absent/failed |
| `ASSURANCE_DENOMINATOR_INCOMPLETE` | frozen case/fixture/held-out denominator incomplete |
| `BACKEND_SEMANTIC_PARITY_BLOCK` | normalized Claude/Codex semantics differ outside allowed fields |
| `SIZE_PATH_IDENTITY_VIOLATION` | bound/path/count/physical-identity defense failed |

An unknown debt code, a missing `ship_disposition`, or conflicting codes is `NO_SHIP`. When any shippable debt exists, `report_quality_debt.json` MUST be present and every row has `code`, semantic `scope_ids`, authority identity/digest, client-safe summary, owner, state, and remediation. With zero debt it MUST be explicitly absent by the final-capture condition.

Client wording is fixed. A clean candidate begins with:

> **Report status: SHIPPED.** All mandatory report integrity and publication gates passed for the declared scope.

A shippable degraded candidate begins with:

> **Report status: SHIPPED WITH LIMITATIONS.** The findings and dispositions below are retained, but `{debt_count}` declared limitation(s) affect evidence, coverage, tooling, location precision, or pending human review. See “Limitations and assurance debt” for exact scope.

Its section heading is exactly `## Limitations and assurance debt`; rows are sorted by `(code, scope_id, authority_identity)` and use exactly `- [{code}] {client_summary} (scope: {scope_id}; authority: {authority_identity}; owner: {owner}; state: {state})`. The section ends with `This report does not claim clean closure for the unresolved items above.`

A no-ship staging candidate begins with:

> **NO SHIP — NOT AN ACCEPTED AUDIT REPORT.** Publication authority failed: `{comma-separated sorted NO_SHIP codes}`. This candidate must not be delivered as the canonical report.

No-ship wording is never installed at project root as a replacement for a previously accepted report. Free-form substitutions, omitted codes, euphemistic “pass with warnings,” and a clean banner alongside nonzero debt are rejected.

Style repair MUST be deterministic and occur before output bytes are finalized. Retry hints may request an upstream new generation, but P3 cannot call a model or mutate a finished candidate. There is no quality/projection/dedup/floor writer between P3 output construction, final-capture commit, and publication.

## 5. P4 — Immutable final capture and crash-safe publication

### 5.1 Exact downstream authority set

The downstream report-acceptance set has distinct byte, installation, and cutover authorities:

| Artifact | Schema | Producer work unit | Sole authority for |
|---|---|---|---|
| `scratchpad:report_assembly_final_capture.json` | `plamen.report_assembly_final_capture.v2` (`v1` legacy-readable) | `report_assemble/final_capture` | immutable P3 request/result/projection/policy and seven-role payload/destination states with exact predecessors |
| `project:.plamen/report_publication_receipts/{run_generation_id}/{publication_transaction_id}/report_publication_receipt_archive.v1.json` | `plamen.report_publication_receipt_archive.v1` | `report_assemble/publication_receipt_archive` | singleton committed generation/transaction publication evidence, excluding every successor selector and verdict |
| `project:.plamen/report_publication_receipts/{run_generation_id}/{publication_transaction_id}/artifact_ledger_commit_receipt.v1.json` | `plamen.report_publication_receipt_commit_archive.v1` | `report_assemble/publication_receipt_commit_archive` | distinct singleton successor containing the already-issued receipt-archive external commit receipt |
| `project:.plamen/report_publication_receipt_locator.json` | `plamen.report_publication_receipt_locator.v1` | `report_assemble/publication_locator` | singleton committed current archive tuple plus precommitted deterministic project ArtifactLedger root; selected by ledger |
| `project:.plamen/report_publication_ledger.json` | `plamen.report_publication_ledger.v1` | `report_assemble/publication_ledger` | singleton committed report/locator/archive selector plus fixed-root prestate/next revision, accepted only when selected by the ArtifactLedger active head |
| `project:.plamen/report_publication_authority/_artifact_state.json` | ArtifactLedger v2 enclosing exact current `plamen.artifact-work-unit.v2` records and active checkpoint head | `ArtifactLedger/COMMIT_PUBLICATION_AUTHORITY_CHECKPOINT_CAS_V1` | fixed-root project-durable live A-D producer authority and append-only checkpoint chain after ledger commit |
| `scratchpad:report_publication_receipt.json` | `plamen.report_publication_receipt.v1` | `report_assemble/publication_finalize` | same-run terminal mirror and P6-final handoff; never cross-run predecessor authority |
| `scratchpad:report_cutover_acceptance_authority.json` | `plamen.report_cutover_acceptance_authority.v1` | `report_cutover/p6_final_acceptance` | P6-final per-cell implementation/parity acceptance over frozen code, contract, upstream, fixture, production, and reviewer digests |

`report_assembly_final_capture.json` remains the final byte and semantic-projection authority. Publication artifacts MUST NOT repeat report bytes as competing authority or permit new semantics; they reference the exact final-capture identity/digest and certify whether those bytes reached the planned destinations. The P6 acceptance authority MUST NOT repeat or replace any runtime artifact; it certifies the implementation/compatibility cell that produced them.

The publication evidence chain uses four exact singleton PhaseIO work units and commit boundaries. Their key suffixes, contract schemas, immutable inputs, and sole outputs are: (A) `report_assemble/publication_receipt_archive`, `plamen.report-publication-receipt-archive-contract.v1`, final-capture/payload/transaction/report-poststate inputs, sole receipt-archive output; (B) `report_assemble/publication_receipt_commit_archive`, `plamen.report-publication-receipt-commit-archive-contract.v1`, A’s committed bytes plus A’s already-issued `plamen.artifact-output-commit.v1` obtained from A’s enclosing source-ledger unit, sole commit-archive output; (C) `report_assemble/publication_locator`, `plamen.report-publication-locator-contract.v1`, committed A/B bytes and their source-ledger authorities plus locator prestate, sole fixed-locator output; and (D) `report_assemble/publication_ledger`, `plamen.report-publication-ledger-contract.v1`, committed A/B/C bytes and their source-ledger authorities plus ledger/root prestates and report poststate, sole publication-ledger output. The full key is `<pipeline>/<mode>/<ecosystem>/<backend>/report/<suffix>`. PhaseIO commits A before B is armed, B before C is armed, and C before D is armed. No contract may declare two of these outputs, inspect its own or a successor commit receipt, or use a later artifact as an immutable input.

After D commits, the live ArtifactLedger interface executes the registered non-PhaseIO operation `COMMIT_PUBLICATION_AUTHORITY_CHECKPOINT_CAS_V1`. It compares the exact fixed-root prestate pinned before A, projects the locked current A-D authority subset into the next checkpoint revision, validates that staged postimage with the same live interface, writes its immutable checkpoint-CAS record, and only then CAS-installs the fixed `_artifact_state.json` active head. `report_assemble/publication_finalize` may create the scratch mirror only after the installed root validates in place. This is the acyclic order `fixed authority-root prestate → A artifact → A commit authority → B artifact → B commit authority → C locator → C commit authority → D ledger → D commit authority → fixed-root ArtifactLedger CAS → scratch mirror`; a combined A/B output contract or a report-authored terminal authenticator is invalid.

The receipt archive has exact top-level fields `schema_version`, `artifact_identity`, `receipt_archive_id`, `run_id`, `run_generation_id`, `publication_transaction_id`, `publication_sequence`, `expected_config`, `final_capture`, `payload_set`, `report_poststate`, `publication_prestate`, `support_policy`, `p5b_activation_receipt`, `producer_binding`, `archive_digest`. `publication_prestate` binds the exact report, ledger, and fixed-locator prestates; `producer_binding` binds work-unit ID, owner, writer, schema, contract, launch, and the requested external ArtifactLedger subject. It deliberately contains no successor ledger bytes/digest, candidate/successor locator bytes/digest, archived external commit receipt, scratch receipt, test result, P6 authority, or review verdict. With `receipt_archive_id` and `archive_digest` omitted, `archive_digest=H(CJ(archive_body))` and `receipt_archive_id="rpa1_" + archive_digest`.

The commit-receipt archive has exact fields `schema_version`, `artifact_identity`, `commit_archive_id`, `receipt_archive_identity`, `receipt_archive_id`, `receipt_archive_sha256`, `external_receipt_schema`, `external_work_unit_key`, `external_receipt_digest`, `external_receipt_bytes_base64`, `external_receipt_sha256`, `external_subject_identity`, `external_subject_sha256`, `producer_contract_sha256`, `producer_launch_sha256`, and `commit_archive_digest`. `external_receipt_schema` is exactly `plamen.artifact-output-commit.v1`; decoded external bytes MUST equal `CJ(the exact A ArtifactLedger commit_authority object)`, `external_receipt_sha256=H(decoded bytes)`, and `external_receipt_digest` MUST equal both the object’s `receipt_digest` and its rederivation after omitting that field. The object’s work-unit key, contract, launch, ACTIVE state, expected-output record, and subject digest/size MUST attest the exact receipt-archive logical identity and bytes. This embedded object is only a deterministic equality projection: consumers confer authority only after it is byte-equal to A’s `commit_authority` inside the selected live project ArtifactLedger root. B is committed as its own singleton PhaseIO output and never contains or predicts B’s receipt. With its ID and digest omitted, `commit_archive_digest=H(CJ(commit_archive_body))` and `commit_archive_id="rpca1_" + commit_archive_digest`.

The fixed locator has exact fields `schema_version`, `artifact_identity`, `locator_id`, `run_id`, `run_generation_id`, `publication_transaction_id`, `publication_sequence`, `receipt_archive_identity`, `receipt_archive_id`, `receipt_archive_sha256`, `commit_archive_identity`, `commit_archive_id`, `commit_archive_sha256`, `publication_authority_root_identity`, `publication_authority_ledger_version`, `publication_authority_operation`, `publication_authority_registry_sha256`, `publication_authority_work_unit_keys`, `publication_authority_prestate`, `publication_authority_target_revision`, `predecessor_locator_sha256`, and `locator_digest`. Its identity is always `project:.plamen/report_publication_receipt_locator.json`; its first two referenced identities MUST be the deterministic archive templates with the same generation and transaction. `publication_authority_root_identity` is always the constant `project:.plamen/report_publication_authority`, version is exactly `2`, operation is exactly `COMMIT_PUBLICATION_AUTHORITY_CHECKPOINT_CAS_V1`, and the keys are the exact ordered A-D full keys from above. `publication_authority_prestate` is the exact transaction-pinned tagged union from Section 3.1 and `publication_authority_target_revision` is `1` for `ABSENT` or prior revision plus one for `PRESENT`. Only that fixed root/interface/registry/key/prestate/target denominator—not the not-yet-created postimage or checkpoint digest—is precommitted. With its ID and digest omitted, `locator_digest=H(CJ(locator_body))` and `locator_id="rpl1_" + locator_digest`. The archive, commit-archive, and locator schemas are closed recursively, reject undeclared fields, and use `CJF` on disk.

`REPORT_PUBLICATION_AUTHORITY_ROOT_V1` is a reviewed, compiled fixed-path registry entry in the already-counted publication module. It binds exactly `{root_identity:"project:.plamen/report_publication_authority",ledger_name:"_artifact_state.json",lock_name:"_artifact_state.lock",output_authority_ledger_name:"_artifact_output_authorities.json",output_authority_cas_directory:"_artifact_output_authority_cas",checkpoint_cas_directory:"_report_publication_checkpoint_cas",ledger_version:2,checkpoint_operation:"COMMIT_PUBLICATION_AUTHORITY_CHECKPOINT_CAS_V1",required_work_unit_suffixes:["publication_receipt_archive","publication_receipt_commit_archive","publication_locator","publication_ledger"],actor:"DRIVER",physical_policy:"LEXICAL_NO_FOLLOW_V1",validator_interfaces:["read_artifact_ledger","validate_report_publication_authority_checkpoint","active_committed_work_unit_authority_issues","validate_work_unit_artifacts"]}`. Its digest is bound by C, D, support/OS policy, P5A, and P6. The exact ArtifactLedger implementation/closure is the existing `EXECUTION_SUBSTRATE_CLOSURE.artifact_ledger` dependency; report code cannot substitute a parser or synthesize a ledger document.

The active checkpoint is a genuine minimal ArtifactLedger v2 state, not a receipt bundle. Its fixed `_artifact_state.json` has the normal exact v2 root fields and contains exactly the current A-D `work_units`, their four current `artifact_bindings`, and their four legacy `artifacts` projections. Every work-unit record remains the complete source `plamen.artifact-work-unit.v2` record, including `run_id`, `semantic_status=ACTIVE`, `execution_state=OUTPUT_COMMITTED`, exact `contract_manifest`/`contract_digest`, exact `launch_manifest`/`launch_digest`, `input_bindings`/`input_set_digest`, output prestates, exact singleton `artifacts`, and `commit_authority`. The companion `_artifact_output_authorities.json` and `_artifact_output_authority_cas/` retain the corresponding ACTIVE issuance records and write-once authority bytes; every current `commit_authority.output_authority_key/output_authority_digest` resolves byte-for-byte there. `_artifact_state.lock` is zero-semantic lock state. Unknown current work-unit/binding/artifact rows, a fifth current work unit, a missing companion, or an unequal source projection invalidates the active checkpoint.

ArtifactLedger v2 adds the closed root field `report_publication_authority`, exactly `{schema:"plamen.report-publication-authority-active-head.v1",root_identity,ledger_version,checkpoint_operation,registry_sha256,checkpoint_revision,run_id,run_generation_id,publication_transaction_id,publication_sequence,required_work_unit_keys,work_unit_set_sha256,prior_checkpoint_sha256,checkpoint_sha256}`. The first five values equal the constant registry, `checkpoint_revision` equals the locator/D target, the identity/sequence tuple equals D, and `work_unit_set_sha256=H(CJ(the exact ordered A-D complete work-unit plus current artifact/global-binding records))`. For genesis, `prior_checkpoint_sha256` is 64 zeroes; otherwise it equals the prestate head. `checkpoint_sha256=H(CJ(the field with checkpoint_sha256 omitted))`. Before active-root replacement, the operation exclusively writes `_report_publication_checkpoint_cas/{checkpoint_sha256}.json` with exact fields `schema`, `checkpoint_head`, `prior_root_sha256`, `root_postimage_sha256`, `root_postimage_bytes_base64`, and `checkpoint_record_sha256`; schema is `plamen.report-publication-authority-checkpoint.v1`, decoded postimage bytes equal the complete canonical next `_artifact_state.json`, their hash equals `root_postimage_sha256`, `prior_root_sha256` is 64 zeroes for genesis or the exact pinned prestate root hash, and `checkpoint_record_sha256=H(CJ(the record with that field omitted))`. The CAS filename/head/postimage/prior-root values all rederive. These checkpoint records are append-only history, not alternate active selectors.

ArtifactLedger alone constructs or advances this root from a locked stable read of the source audit ArtifactLedger after D’s commit. PhaseIO, the publication orchestrator, and the renderer cannot write, filter, repair, or sign any root/checkpoint file. The operation stages the exact next root state and any new journal/CAS bytes, validates the root/head/history with `validate_report_publication_authority_checkpoint`, validates all four units with `read_artifact_ledger` plus `active_committed_work_unit_authority_issues`, compares every current record byte-for-byte to the locked source authority, and calls `validate_work_unit_artifacts(..., require_live_input_authority=false)` for the exact live A-D project outputs. Genesis installs the fully flushed same-parent root directory by absence-CAS. A successor first writes/flushes its new write-once authority/checkpoint-CAS records, then compares the complete pinned `_artifact_state.json` preimage and atomically replaces only that active-root file, finally flushing the root directory. A copied `plamen.artifact-output-commit.v1`, copied hash, or report-authored envelope outside this fixed root has zero authority.

The fixed root is the non-self-issued trust boundary: its active head selects D; D never selects a variable root. Nothing inside the root claims to authenticate `_artifact_state.json` or the directory. Trust bootstraps only from the reviewed constant registry/path, pinned ArtifactLedger substrate, `DRIVER` caller, authoritative `ABSENT` genesis or exact previously validated root prestate, publication/root locks, and the live ArtifactLedger CAS/validation operation. C and D bind only that prestate and next revision; D’s later commit authority is added before the CAS postimage is derived, so no predecessor hashes future root bytes. Every later validation begins at the constant root, holds its exact lock, no-follow stable-reads every required file/CAS record twice, replays the checkpoint chain/head and four units, checks A’s live `commit_authority` byte-equal B’s embedded projection, and verifies current C/D plus immutable A/B bytes against their artifact/global-binding/commit expected-output records.

Every `receipt_archive_sha256`, `commit_archive_sha256`, and `receipt_locator_sha256` means `H(CJF(the complete closed object))`, not the inner semantic digest. Identity, inner digest, and full-file digest must each rederive and agree; they are never interchangeable. The project authority root has no report-authored receipt or self-acceptance field; `checkpoint_sha256` is only an internal integrity/link value, and only ArtifactLedger’s live fixed-root/work-unit/output-authority/CAS replay can accept the active head.

The P4 crash-recovery journal has the exact path `scratchpad:report_publication_transaction.json` and schema `plamen.report_publication_transaction.v1`. It is written only by `report_assemble/publication`. It is mutable control-plane state whose transitions are compare-and-swap and durably journaled; it never confers byte, projection, or shipped authority. A terminal publication receipt closes one journal generation.

The cross-process lock path is exactly `project:.plamen/report_publication.lock`. It is a zero-semantic control file opened without following links and locked exclusively for E5-E7; its physical identity is recorded in the journal. The exact lock order is `project publication lock → source scratch ArtifactLedger lock → fixed publication-authority-root lock`; genesis uses the staged root’s exact lock under the already-held publication lock before absence-install. Locks release in reverse, with no upgrade, inversion, or path reopen. No lock is artifact authority or a substitute for report/ledger/root CAS validation.

The journal, durable A-D/project-ArtifactLedger set, scratch receipt mirror, and cutover acceptance authority are control-plane artifacts, not hidden additions to the renderer’s exact seven payload outputs. They require declared contracts/interfaces, bounded schemas, and no undeclared side effects. The mutable journal is not itself an authority; every accepted project tuple is canonical, producer-registered, live-ledger-bound, and digest-chained.

### 5.2 Final-capture construction

P4 is a cross-work-unit transaction with exclusive ownership:

1. `report_assemble/assembly` consumes exactly committed `report_render_projection.json` and `report_render_result.json`. It validates their request/result/projection/output-set equality and commits the seven physical scratchpad payload states from the immutable P3 bytes. It owns those seven artifacts and no project-root path; the separately committed render input is consumed again only by final capture/replay.
2. `report_assemble/final_capture` consumes the committed source/render input/projection/result and all seven assembly payload receipts. It constructs and commits final capture v2, then runs the combined source/envelope/P3/payload/final terminal replay.
3. `report_assemble/publication` is the journaled transaction orchestrator: it consumes final capture v2, all seven payload receipts, the P5B activation receipt for an authoritative cell, support policy, generation row, and the registered predecessor publication tuple or authoritative first-publication absence; verifies the six scratch outputs; and stages/installs only `AUDIT_REPORT.md`. It then invokes the exact A-D singleton producers, the registered ArtifactLedger checkpoint CAS, and finalize in Section 5.1. Each PhaseIO child owns only its declared sole output; the orchestrator cannot synthesize, co-commit, rewrite, or directly serialize any child artifact or ArtifactLedger root.

Source capture, live tier Markdown, legacy records, v1 final capture on an authoritative generation, or any path reread is rejected as an assembly/publication substitute. Publication cannot create, delete, replace, or “repair” an assembly payload. If a scratch payload changes after assembly, final replay/publication fails `OUTPUT_SET_MISMATCH`.

### 5.3 Prestate and compare-and-swap rules

For first publication, `project:AUDIT_REPORT.md`, `project:.plamen/report_publication_ledger.json`, and `project:.plamen/report_publication_receipt_locator.json` have authoritative `ABSENT` prestates and are created exclusively. One present without the other two is unknown state and blocks a new transaction unless the same transaction journal proves a recoverable first-publication crash. The deterministic archive/authority parents may already contain unselected crash remnants; their presence is neither a predecessor nor a conflict with a different deterministic generation/transaction path. The genesis ledger has `schema_version`, exact project canonical identity, `entry_count=1`, one sequence-zero entry, and `head_entry_sha256`; there is no external cryptographic key. The project ArtifactLedger bootstrap is only the reviewed fixed-path registry plus the pinned live substrate and exact absence-CAS operation in Section 5.1.

For every transaction, its exact A/B paths have pinned `ABSENT` prestates and use exclusive creation. The constant publication-authority root has the exact tagged prestate from Section 3.1: first publication requires the entire registered root path absent, while supersession requires the complete previously live-validated root bytes, revision, and head digest. An already present A/B path is resumable only when the same journal transaction recorded that exact identity and the bytes plus source-ledger authority rederive. Authority-root CAS succeeds only from the pinned prestate to the pinned next revision; an unrecorded root, rollback, skipped revision, same revision with unequal bytes, or current-root mismatch quarantines. Other generation/transaction archive paths are never enumerated or interpreted.

Each ledger entry has exact fields `publication_sequence`, `run_id`, `run_generation_id`, `publication_transaction_id`, `report_sha256`, `report_byte_length`, `final_capture_identity`, `final_capture_schema`, `final_capture_sha256`, `receipt_locator_identity`, `receipt_locator_id`, `receipt_locator_sha256`, `receipt_archive_identity`, `receipt_archive_id`, `receipt_archive_sha256`, `commit_archive_identity`, `commit_archive_id`, `commit_archive_sha256`, `precheckpoint_phaseio_commit_projections`, `publication_authority_root_identity`, `publication_authority_ledger_version`, `publication_authority_operation`, `publication_authority_registry_sha256`, `publication_authority_work_unit_keys`, `publication_authority_prestate`, `publication_authority_target_revision`, `support_policy_sha256`, `p5b_activation_receipt_sha256`, `producer_work_unit_id`, `owner`, `writer`, `schema_sha256`, `contract_sha256`, `launch_sha256`, `predecessor_entry_sha256`, `predecessor_ledger_sha256`, `report_date`, and `entry_sha256`. `precheckpoint_phaseio_commit_projections` is the exact ordered `[RECEIPT_ARCHIVE,COMMIT_ARCHIVE,LOCATOR]` set of A/B/C receipt digests and subjects used during construction, but it is explicitly non-authoritative until each row equals the corresponding enclosing work-unit `commit_authority` in the fixed project ArtifactLedger root. The authority-root fields must equal the locator fields and transaction-pinned fixed-root prestate/next revision but contain no future root/checkpoint bytes or digest. `entry_sha256=H(CJ(entry with entry_sha256 omitted))`. Entries are sequence-ordered and append-only; `entry_count`, head digest, predecessor links, and sequences reconcile exactly. The D artifact necessarily omits D’s later commit authority; the post-D ArtifactLedger CAS encloses D’s complete work unit without creating a back-edge.

Same-run republish and cross-run supersession require the exact registered ledger head and matching report bytes. A later run starts only at the constant registry root: acquire its `_artifact_state.lock`, open `_artifact_state.json` through `read_artifact_ledger`, call `validate_report_publication_authority_checkpoint` to replay its active head/prior link and named write-once checkpoint record, require an exact v2 current state with only the four expected work-unit/output-binding/legacy-artifact rows and valid companion output-authority journal/CAS records, replay each expected full key with `active_committed_work_unit_authority_issues` against the registered singleton contract and launch, and call `validate_work_unit_artifacts(..., require_live_input_authority=false)` for the four exact project outputs. Only after that fixed-root validation may the consumer open the fixed D ledger and C locator as selected candidates; their run/generation/transaction/sequence, root/version/operation/registry/keys, and target revision must equal the ArtifactLedger active head, while their recorded prestate must equal the predecessor root/revision/head rederived from the active checkpoint record and prior-link CAS history. It then requires A’s enclosing `commit_authority` byte-equal B’s embedded projection, requires the A/B/C projections in D equal the corresponding enclosing authorities, uses C’s enclosing authority to authenticate the locator bytes, uses D’s enclosing authority to authenticate the complete ledger bytes/head, and matches the project report bytes/physical identity to that head. Random scratchpad archival or deletion is irrelevant because the authoritative enclosing work units, manifests, bindings, output records, issuance journal, and CAS records are all inside the fixed project ArtifactLedger root.

Directory enumeration, basename search, newest-file choice, scratchpad lookup, journal inference, random UUID lookup, path guessing, a copied receipt bundle, or any non-registry ArtifactLedger root is forbidden. The successor appends sequence `head+1`, binds the prior entry and full-ledger digests, and commits through the same producer contract. An unknown, self-consistent-but-unregistered, truncated, reordered, stale, mutated, hard-linked, symlinked/reparse, multiply linked, locator-divergent, archive-divergent, fixed-root/head/checkpoint-CAS divergent, revision rollback/skip, extra/missing work-unit, or live-ledger-invalid chain fails closed; a valid different-run head does not. Producer/schema/interface revocation occurs through a reviewed support-policy successor and blocks future supersession without rewriting history. Offline operation is complete because validation uses compiled closed report validators plus the pinned live ArtifactLedger interface and local fixed root only.

Before replacing an accepted report, publication creates and flushes private same-directory backups for both the report and fixed locator; their bytes/digests MUST equal the live-ArtifactLedger-authenticated ledger head’s report and locator bindings. The backups have no artifact authority. They are retained through the durable project authority-root checkpoint CAS and `RECEIPTED`, then removed by exact handle. Before ledger installation, a failed transaction restores the predecessor report and predecessor locator by compare-and-swap against the just-installed candidates, or removes the exact unaccepted first-publication candidates; it never moves or deletes an unmatched accepted report. Immutable receipt and commit-receipt archives are never rolled back, overwritten, or adopted after such failure: they remain unselected crash evidence.

Every receipt archive, commit-receipt archive, output-authority CAS record, and publication-checkpoint CAS record named anywhere in retained history is project-durable and immutable for the lifetime of that history. Only the fixed ArtifactLedger active `_artifact_state.json` and output-authority index may advance through their registered CAS operations; version 1 defines no direct root mutation, history garbage collection, or deletion authority. An orphan A/B or write-once CAS record for an interrupted transaction may be inspected only while resuming that exact journal transaction; it never selects a head. A mismatch at an existing immutable path, root prestate/poststate divergence, any physical-identity change during validation, or any live validator failure quarantines the transaction/head and never degrades to copied-receipt validation. Scratchpad archival, cleanup, or restoration behavior remains unchanged for audit-local evidence, but `scratchpad:report_publication_receipt.json`, its scratchpad archive, and the scratch ArtifactLedger are irrelevant to every later-run predecessor proof.

Output parent identities, volume/device identities, path spellings, case-folded forms, and final targets MUST be pinned at arm time. Staging and target MUST be on the same filesystem/volume. Cross-device copy-as-rename is forbidden.

### 5.4 Durable publication protocol

The journal’s closed states are `ARMED`, `CLIENT_STAGED`, `CLIENT_INSTALLED`, `RECEIPT_ARCHIVED`, `LOCATOR_INSTALLED`, `LEDGER_INSTALLED`, `RECEIPTED`, `ABORTED`, `ROLLED_BACK`, and `QUARANTINED`. The exact directed graph is:

```text
ABSENT -> ARMED
ARMED -> CLIENT_STAGED | ABORTED | QUARANTINED
CLIENT_STAGED -> CLIENT_INSTALLED | ABORTED | QUARANTINED
CLIENT_INSTALLED -> RECEIPT_ARCHIVED | ROLLED_BACK | QUARANTINED
RECEIPT_ARCHIVED -> LOCATOR_INSTALLED | ROLLED_BACK | QUARANTINED
LOCATOR_INSTALLED -> LEDGER_INSTALLED | ROLLED_BACK | QUARANTINED
LEDGER_INSTALLED -> RECEIPTED | QUARANTINED
```

`RECEIPTED`, `ABORTED`, `ROLLED_BACK`, and `QUARANTINED` are terminal. No other edge or state is valid. Each transition compares the complete prior journal bytes, rewrites canonically through a same-directory exclusive temp, flushes file and directory, and increments `transition_ordinal` by one.

Publication order is exact:

1. verify final capture v2 and all seven assembly receipts/bytes; live-validate and pin the fixed project publication-authority-root prestate, then pin report, fixed-locator, publication-ledger, and exact A/B prestates; derive the transaction ID and expand only the registered A/B path templates from the generation/transaction IDs; flush `ARMED`;
2. create/flush the exact predecessor report and locator backups when present and create/flush the exact client staging bytes; flush `CLIENT_STAGED`;
3. CAS-install and directory-flush `AUDIT_REPORT.md`; flush `CLIENT_INSTALLED`;
4. arm A, exclusively create/file-flush/directory-flush its sole deterministic receipt-archive output, and commit A into the source scratch ArtifactLedger; only after A’s enclosing work-unit/contract/launch/artifact/binding/commit/output-authority records replay may B embed A’s commit projection, create/flush its sole commit-archive output, and commit separately into that same ledger; after both enclosing units replay flush `RECEIPT_ARCHIVED`;
5. arm C from the live source-ledger A/B enclosing authorities, CAS-install/directory-flush its sole fixed-locator output against pinned absence/predecessor bytes, commit/replay C as its own enclosing unit, and flush `LOCATOR_INSTALLED`;
6. arm D from committed A/B/C and their source-ledger authorities, construct its sole ledger output over the durable locator/archive tuple and precommitted project ArtifactLedger root, CAS-install/directory-flush/commit/replay it, and flush `LEDGER_INSTALLED`;
7. under the exact lock order, invoke ArtifactLedger `COMMIT_PUBLICATION_AUTHORITY_CHECKPOINT_CAS_V1` over the now-complete A-D source-ledger authority subset; stage/live-validate the next fixed-root postimage, write/flush the immutable checkpoint record, perform genesis absence-CAS or exact-prestate successor CAS, flush/reopen the fixed root, and replay its active head plus all four units; only then create/flush/verify the same-run `report_publication_receipt.json` mirror and flush `RECEIPTED`; and
8. delete only the exact private report/locator backup and staging handles and directory-flush cleanup.

The client file can become visible at `CLIENT_INSTALLED`; A/B and the locator are unselected candidates until D installs; the new ledger head is installed but is not a cross-run predecessor until the fixed project ArtifactLedger active head advances to the exact checkpoint revision and all four enclosing authorities replay in place; and the current run may emit the `SHIPPED` label only at `RECEIPTED`. A failure before ledger installation restores the authenticated predecessor report/locator or removes exact unaccepted first-publication candidates and records `ROLLED_BACK`, while leaving immutable archives unselected. A failure after ledger installation must roll forward through the registered fixed-root checkpoint CAS and scratch mirror or quarantine without reversing ledger history, accepting copied receipt hashes, or inventing acceptance.

On Linux/POSIX, publication uses retained directory descriptors, `openat` with `O_CREAT|O_EXCL|O_NOFOLLOW` for staging/backup/immutable archives, file and directory `fsync`, `renameat2(..., RENAME_NOREPLACE)` for first report/locator/ledger install, and `renameat2(..., RENAME_EXCHANGE)` for report/locator/ledger replacement. ArtifactLedger genesis builds the fixed authority root in a same-parent exclusive directory, validates every internal regular file/CAS entry through retained descriptors, `fsync`s files/directories, then installs the entire directory with `RENAME_NOREPLACE`. A successor exclusively writes/fsyncs the new checkpoint/output-authority CAS files inside the locked root, stages the next `_artifact_state.json`, and exchanges it with the fixed active file; the displaced file MUST equal the complete pinned prestate before the root-directory flush, otherwise the operation exchanges back and quarantines. Device/inode checks and the process-wide project publication lock are mandatory.

On Windows, publication uses `CreateFileW(CREATE_NEW)` with reparse-safe flags for staging/backup/immutable archives, retained volume/file identities, `FlushFileBuffers`, `MoveFileExW(..., MOVEFILE_WRITE_THROUGH)` without `MOVEFILE_REPLACE_EXISTING` for first install, and `ReplaceFileW(..., REPLACEFILE_WRITE_THROUGH)` with the verified private backup for replacement. The same exact CAS strategy applies to the fixed locator and publication ledger. ArtifactLedger genesis creates/validates/flushes the whole fixed root in one same-volume exclusive staging directory and installs it non-replacing. A successor creates the checkpoint/output-authority CAS files with `CREATE_NEW`, flushes them, and uses `ReplaceFileW(..., REPLACEFILE_WRITE_THROUGH)` for `_artifact_state.json` while retaining and then byte-verifying the displaced prestate backup; mismatch restores or quarantines before acceptance. All handles deny conflicting write/delete sharing. Delete-then-move, copy-then-delete as install, unchecked path reopen, cross-volume fallback, and an API substitution without a new reviewed publication-schema major are forbidden.

Permissions/ACLs on staging and installed files MUST be no less restrictive than the destination policy. Temporary names MUST be bounded, non-user-controlled, derived exactly from `(publication_transaction_id, role, transition_ordinal)`, and recorded in the journal; random UUIDs and directory-probed suffixes are forbidden. Staging files never acquire artifact authority merely because they contain expected bytes.

### 5.5 Crash, resume, rollback, and quarantine

At restart, the driver resolves the one nonterminal journal for the generation before starting another. Recovery revalidates journal CAS history, final capture/payload/activation receipts, publication ledger, fixed locator, exact deterministic A/B paths, the constant publication-authority-root path/prestate/target revision, report/staging/backup handles, and all expected digests. It uses only identities and paths already recorded in that journal/registry; directory discovery and random recovery IDs are forbidden. The action table is exact:

| State | Exact recovery |
|---|---|
| `ARMED` | if prestates match, resume staging; if no external change and caller cancels, `ABORTED`; otherwise `QUARANTINED` |
| `CLIENT_STAGED` | if stage/prestates match, resume client install; if no install occurred, delete exact staging and non-authoritative backup handles and `ABORTED`; otherwise `QUARANTINED` |
| `CLIENT_INSTALLED` | if candidate and predecessor report/locator backups or first-publication absences match, resume the exact A-then-B singleton commits from their recorded source-ArtifactLedger states or restore the predecessor report and `ROLLED_BACK`; unequal A/B paths or enclosing authorities are `QUARANTINED` |
| `RECEIPT_ARCHIVED` | if exact A/B bytes and their two distinct enclosing source-ArtifactLedger work units replay, arm/commit C and install the candidate locator or restore the predecessor report and `ROLLED_BACK`; mismatch is `QUARANTINED` |
| `LOCATOR_INSTALLED` | if report/archive/locator and all prestates match, install the ledger successor; otherwise restore the predecessor report and locator only when both candidate CAS values still match, else `QUARANTINED` |
| `LEDGER_INSTALLED` | if report/ledger/locator/archive tuple and source A-D enclosing authorities match, invoke the registered fixed-root checkpoint CAS when the pinned target revision is not active or live-replay that already active exact revision; then write/verify the scratch mirror and advance; an unequal root pre/postimage, skipped/rollback revision, missing source authority before CAS, or any live-ledger issue is `QUARANTINED` |
| terminal state | verify terminal invariants and do not transition |

Rollback applies only to uncommitted staging or to a predecessor report/locator protected by verified transaction backup/CAS primitives before ledger installation. It MUST NOT delete immutable archives, move an already accepted `AUDIT_REPORT.md` out of the project root, or rewrite ledger history merely because a later retry failed. The current behavior that quarantines by relocating the canonical report is therefore not valid for the authoritative P4 path.

Semantic/quality debt is haltless after upstream truth is retained: the run may complete with a visibly limited report and debt artifacts. Authority, capture, replay, compare-and-swap, or durability uncertainty is an integrity failure: it prevents a new report from being declared shipped. The driver may still complete the broader audit with debt, but publication status remains `NO_SHIP` and the last accepted report, if any, remains in place.

### 5.6 Mutation and race defenses

P4 MUST reject or safely quarantine:

- stale captures/receipts/prestates/journals/staged files and unauthenticated cross-run predecessors;
- locator/archive/archived-commit projection/authority-root rebinding, combined A/B work-unit output, successor-receipt back-edge, report-authored ledger/root serialization, directory-discovered or newest-file authority selection, random archive/root identity, and adoption of an unselected orphan;
- source/final capture rebinding or digest mismatch;
- fixed/namespace/output roster gain, loss, replacement, or mutation;
- output mutation between arm, stage verification, install, and receipt;
- parent-directory replacement, case-equivalent collision, path traversal, device names, unsafe Unicode/control characters, overlong paths/components, or reserved temporary names;
- symlink, reparse point, hard-link, multi-link, mount/volume change, file-index/inode change, or sharing-mode race;
- per-file, aggregate, output-count, namespace-count, or location-count overflow;
- interrupted/double publication, replay of an old transaction, sequence rollback, immutable archive/checkpoint-CAS overwrite/deletion, unauthorized active-root replacement/deletion, output-authority journal/CAS mutation, producer/interface/policy revocation, or two publishers for one generation; and
- any assembly payload state that does not match final capture and its PhaseIO receipt.

No check may be implemented as a time-of-check/path-reopen sequence when a retained handle or descriptor can carry the verified identity to the operation.

### 5.7 Publication receipt

The terminal receipt MUST enumerate all seven roles, including explicit absences, and bind:

- run/generation/transaction identities;
- configuration and compatibility-cell dimensions;
- renderer, render-policy, source-policy, source roster, source snapshot, projection, source capture, final capture, contract, launch, and commit-receipt digests;
- every seven-role logical/physical payload state, root-report, fixed-locator, and publication-ledger prestate/stage/poststate, digest, size, physical identity, producer/receipt chain, sequence, and install/durability result;
- the exact ledger-selected receipt/commit archives, fixed project ArtifactLedger root/registry/key/prestate/target-revision denominator, active checkpoint/prior-link/root-postimage identities, exact A-D `plamen.artifact-work-unit.v2`/contract/launch/input/artifact/global-binding/commit-authority/output-authority-journal/CAS replay results, and any copied-receipt equality results;
- the client commit point and recovery classification;
- quality/debt state and `NO_SHIP` versus `SHIPPED`; and
- producer and independent replay/reviewer identities when acceptance is claimed.

For the executing run, only a verified `scratchpad:report_publication_receipt.json` in `RECEIPTED` state whose tuple equals the fixed project ArtifactLedger active head and its authenticated D ledger may confer the `SHIPPED` label or satisfy current-run P6-final. For every later run, the sole predecessor proof starts at that constant ArtifactLedger root: its active head/enclosing A-D authorities select and authenticate the fixed D ledger, C locator, exact immutable A/B archives, and report. The scratch receipt, scratch archive, scratch ArtifactLedger, journal, copied receipt hashes, process exit, and directory contents are not consulted. File existence, a successful process exit, a committed final capture, or project-report byte equality without that live-ledger-authenticated project tuple is insufficient.

## 6. P5 — Driver switch, compatibility, and migration

### 6.1 Compatibility states

Each pipeline/backend/ecosystem/mode compatibility cell has one explicit driver state:

| State | Behavior |
|---|---|
| `LEGACY` | Existing renderer remains authoritative; captured path is not armed. |
| `SHADOW` | P3/P4 candidate runs through non-project staging and comparison; it cannot publish `AUDIT_REPORT.md`. |
| `CANDIDATE` | Captured path may exercise the full P4 transaction only in isolated fixtures or designated non-production projects; no production acceptance claim. |
| `PREPARED` | P5A inputs and exact rollback target are committed; no driver switch. |
| `PREACTIVATION_APPROVED` | P6-pre approves one exact P5B CAS and one production canary generation; no final acceptance. |
| `AUTHORITATIVE_PENDING_FINAL` | P5B has switched the cell; exactly one production canary generation may execute, legacy assembly/mutators are unreachable. |
| `AUTHORITATIVE_ACCEPTED` | P6-final accepted postactivation publication/replay/held-out evidence; captured path is the continuing authority. |
| `ROLLED_BACK` | Cell returns to its recorded prior authority under an explicit rollback receipt; candidate artifacts remain non-authoritative evidence. |

The only forward graph is `LEGACY -> SHADOW -> CANDIDATE -> PREPARED -> PREACTIVATION_APPROVED -> AUTHORITATIVE_PENDING_FINAL -> AUTHORITATIVE_ACCEPTED`. `SHADOW` may return to `LEGACY`; `CANDIDATE` may return to `SHADOW`; either authoritative state may transition to `ROLLED_BACK` through `scratchpad:report_p5_rollback_receipt.json`, schema `plamen.report_p5_rollback_receipt.v1`, producer `report_cutover/p5b_rollback`. `ROLLED_BACK` may re-enter only at `SHADOW` under a new generation of P5A/P6-pre evidence. No other transition is valid.

Until the P5B CAS durably commits, the legacy path remains the sole production report authority; SHADOW/CANDIDATE/PREPARED/PREACTIVATION_APPROVED executions cannot suppress, replace, or mutate it. P5B is legal only after P6-pre has accepted the complete shadow/candidate evidence and grants exactly one canary generation. During `AUTHORITATIVE_PENDING_FINAL` there is no dual authoritative writer: the captured path owns the canary and the legacy assembler/mutators are unreachable; failure accepts rollback, not live legacy fallthrough.

P5A emits `report_p5_preparation_authority.json` and records the full compatibility-state prestate and rollback target. P6-pre emits `report_p6_preactivation_authority.json`; it cannot consume a production publication from the not-yet-active path and grants only the single CAS/canary budget. P5B emits `report_p5_activation_receipt.json` while CAS-changing the driver cell to `AUTHORITATIVE_PENDING_FINAL`. P6-final consumes that receipt plus the canary’s live-ArtifactLedger-authenticated A-D project tuple and same-run `report_publication_receipt.json` mirror, then emits `report_cutover_acceptance_authority.json`. This order has no digest cycle. If P6-final does not accept the exact canary evidence, `p5b_rollback` must run before another generation is allowed.

### 6.2 Entry criteria and exact activation contracts

A cell cannot reach `PREACTIVATION_APPROVED` until:

1. all 48 source selectors are permitted with typed producer closure and the ten-blocker repair suite passes;
2. P3 and P4 acceptance denominators pass on real nonempty producer fixtures;
3. the driver production callgraph has the exact render-input → P3 projection/result → seven scratch payloads → final-capture-v2 → publication chain and no ownership inversion;
4. no quality, scope, evidence, assurance, dedup, severity-floor, disposition, location-recovery, or report-record mutator is reachable after P3 candidate creation;
5. crash/retry/resume and hostile path/race suites pass on Windows and POSIX;
6. shadow semantic/output reconciliation has no unexplained identity or field delta;
7. the MC6 assurance authority described below is present and valid;
8. P6-pre independent review approves the exact cell and frozen preactivation evidence; and
9. rollback has been exercised without deleting or reauthoring upstream truth.

`report_p5_preparation_authority.json` binds exact candidate code/package tree, runtime-asset closure, schemas, work-unit contracts, producer/semantic registries, 48-selector closure, support/assurance plans, renderer/template/gate policies, accepted MethodCard mapping instance/adoption and MC6 authority, ProgramFacts active-runtime authority, complete preactivation results, compatibility prestate, and rollback target. `report_p6_preactivation_authority.json` replays those inputs independently and lists each approved cell; an omitted cell is not approved.

`report_p5_activation_receipt.json` contains the P6-pre digest, exact cell, prestate and poststate, CAS physical identity/digest, activation time expressed as the captured activation sequence rather than wall clock, one-canary budget, driver/package digest, rollback target, producer contract/launch/receipt, and activation reviewer identity. `report_p5_rollback_receipt.json` binds the activation receipt, failed/withdrawn acceptance evidence, exact poststate/prestate restoration CAS, preserved canary publication, and no-deletion proof.

### 6.3 Accepted MethodCard and ProgramFacts bindings

The two cross-spec semantic designs are fixed by independently accepted design pins. The MethodCard pin is `architecture/method-card-mc0b-mc6-cutover-spec.md`, 180,744 bytes, 659 LF-terminated lines, SHA-256 `d0bea26280f1315fc9e0c03d583b73a1af30784c3c0053b9215050ae83046a01`. The ProgramFacts pin is `architecture/program-facts-runtime-cutover-spec.md`, 238,989 bytes, 2,011 LF-terminated lines, SHA-256 `2f2025cf636ca80df560d7568760f6ebfc114a2c344a895940ea76566c953c79`. These pins close interface choices; neither is a runtime, active-generation, release, publication, or report-cutover receipt.

#### 6.3.1 MethodCard report handoff

The report interface is the MethodCard pin's exact `ReportInterfaceBinding`: `report_spec_path=architecture/report-p3-p6-cutover-spec.md`, `final_capture_artifact_identity=scratchpad:report_assembly_final_capture.json`, `final_capture_schema=plamen.report_assembly_final_capture.v2`, `producer_work_unit_id=report_assemble/final_capture`, and `phase_io_contract_key_template=<pipeline>/<mode>/<ecosystem>/<backend>/report/report_assemble/final_capture`. P3-P6 MUST NOT substitute final-capture v1, a report projection, a RunBundle `report_projection`, or an assembly/publication receipt for this interface.

The MethodCard-owned definition is `plamen.method-card-report-stage-mapping.v2`, prefix `mc-report-stage-mapping:`, with exactly three ordered entries: ordinal 0 `MC4_CATALOG_WORK_PLAN_CLOSURE` maps `[MC0B,MC1,MC4]`; ordinal 1 `MC5_APPLICATION_EVIDENCE` maps `[MC2,MC3,MC5]`; ordinal 2 `MC6_ASSURANCE` maps `[MC6]`. Their exact schema sets, artifact templates, and receipt-role sets are the MethodCard pin's MCUT-038 table and are consumed by set equality, not re-enumerated or weakened by report code.

Its predecessor core is exactly `plamen.method-card-mc0b-mc6-core-profile.v1`, prefix `mc-core-profile:`, whose requirement set is MCUT-001 through MCUT-097 except MCUT-038 and whose `core_requirement_count=96`; it binds the MethodCard schema package/artifact-work registry and the OWN-v2/public-v3 contract digests but contains no report pin, mapping, adoption, publication, or P6 value. The additive `plamen.method-card-report-stage-mapping.v2` follows that core and precedes the combined 97-row/98-instance requirement registry and MC6. Its three rows are frozen exactly:

| Ordinal / label | Ordered stages | Required schema IDs | Required artifact identities/templates | Required receipt roles |
|---|---|---|---|---|
| 0 / `MC4_CATALOG_WORK_PLAN_CLOSURE` | `[MC0B,MC1,MC4]` | `{plamen.method-card-denominator-authority.v3,plamen.method-card-runtime-input-binding.v3,plamen.method-card-work-plan-envelope.v1,plamen.method-card-runtime-authority.v3,plamen.method-card-consumer-activation.v1,plamen.method-card-consumer-activation-authorization-receipt.v1,plamen.method-card-consumer-activation-enactment-receipt.v1}` | `{scratchpad:method_card/{run_id}/mc0b/{card_id}/denominator_authority.json,scratchpad:method_card/{run_id}/mc1/runtime_input.json,scratchpad:method_card/{run_id}/work/{work_id}/work_plan.json,scratchpad:method_card/{run_id}/work/{work_id}/runtime_authority.json,scratchpad:method_card/{run_id}/mc4/{work_id}/consumer_activation.json,scratchpad:method_card/{run_id}/mc4/{work_id}/consumer_activation_authorization.json,scratchpad:method_card/{run_id}/mc4/{work_id}/consumer_activation_enactment.json}` | `{MC0B_STAGE_ACCEPTANCE,MC1_STAGE_ACCEPTANCE,MC4_ACTIVATION_AUTHORIZATION,MC4_ENACTMENT,MC4_STAGE_ACCEPTANCE}` |
| 1 / `MC5_APPLICATION_EVIDENCE` | `[MC2,MC3,MC5]` | `{plamen.method-card-producer-application-typed-output.v3,plamen.method-card-independent-application-review-typed-output.v3,plamen.method-card-canonical-lineage-map.v1,plamen.method-card-canonical-lineage-acceptance-receipt.v1,plamen.method-card-evidence-validation-record.v1,plamen.obligation-application-evidence-receipt.v1,plamen.method-card-independent-reconciliation.v1,plamen.method-card-application-authority.v4,plamen.method-card-mc5-evidence-authority.v1}` | `{scratchpad:method_card/{run_id}/mc2/{work_id}/producer_output.json,scratchpad:method_card/{run_id}/mc2/{work_id}/review_output.json,scratchpad:method_card/{run_id}/mc2/canonical_lineage_map.json,scratchpad:method_card/{run_id}/mc2/canonical_lineage_acceptance.json,scratchpad:method_card/{run_id}/mc2/{obligation_id}/evidence_validation.json,scratchpad:method_card/{run_id}/mc2/{obligation_id}/application_evidence.json,scratchpad:method_card/{run_id}/mc3/{work_id}/reconciliation.json,scratchpad:method_card/{run_id}/mc3/{card_id}/application_authority.json,scratchpad:method_card/{run_id}/mc5/evidence_authority.json}` | `{PRODUCER_EXECUTION,REVIEW_EXECUTION,LINEAGE_ACCEPTANCE,RECONCILIATION_EXECUTION,MC2_STAGE_ACCEPTANCE,MC3_STAGE_ACCEPTANCE,MC5_STAGE_ACCEPTANCE}` |
| 2 / `MC6_ASSURANCE` | `[MC6]` | `{plamen.method-card-assurance-build-contract.v1,plamen.method-card-assurance-policy.v1,plamen.method-card-application-ledger-map.v1,plamen.method-card-application-assurance-authority.v1}` | `{scratchpad:method_card_application_assurance_authority.json}` | `{MC6_EXECUTION,MC6_ARTIFACT_ATTESTATION,MC6_DETERMINISTIC_GRADER,MC6_BLOCKING_REVIEW,MC6_STAGE_ACCEPTANCE}` |

MC6 first freezes the exact final PASS MC4/MC5 `PredecessorStageAcceptanceSet` into the registered worker input, then binds the byte-identical set into `plamen.method-card-assurance-policy.v1`, `plamen.method-card-application-ledger-map.v1`, and `scratchpad:method_card_application_assurance_authority.json`. That public assurance artifact has schema `plamen.method-card-application-assurance-authority.v1`, producer work kind `method_card_assurance/build`, contract identity `method_card_assurance/build@1`, and contract schema `plamen.method-card-assurance-build-contract.v1`. It binds every roster card's exact/lower-bound denominator, APPLIED/MISSING/INVALID/UNKNOWN partition, unknown remainder, debt, unresolved assignments, normalized dimensions, and producer/reviewer/reconciler/replay principals. Rendering MethodCard assurance as accepted truth is legal only after independent PASS MC6 acceptance; an earlier isolated P3/P4 candidate renders the typed unavailable/debt branch. Report P6 remains a separate later authority and cannot reverse-authorize MC0B-MC6.

After MC6 acceptance, `report_cutover/method_card_mapping_instance` produces `scratchpad:method_card_report_stage_mapping_instance.json`, schema `plamen.method-card-report-stage-mapping-instance.v1`; it binds the attested mapping definition, this report specification's external file identity and independent acceptance receipt, the attested MC6 assurance, the PASS MC6 receipt, and three resolved entries with exact schema/artifact/receipt-role equality. `report_cutover/method_card_mapping_adopt` then produces `scratchpad:method_card_report_stage_mapping_adoption_receipt.json`, the separate PASS `plamen.method-card-report-stage-mapping-adoption-receipt.v1` with prefix `mc-report-stage-mapping-adoption:`; it binds the attested instance, the same `ReportInterfaceBinding`, this report-spec identity/receipt, report acceptor, and adoption execution. Both use the exact validators/schema identities in the accepted MethodCard schema-package dependency; report code does not fork those schemas. P5A requires both objects and exact replay of the MC6 candidate, attestation, acceptance, assurance-policy, application-ledger-map, per-card state/debt/unknown/unresolved dimensions, and final MC4/MC5 receipt union. P3/P4 isolated candidates may use only the typed `SHADOW_UNAVAILABLE` branch in Section 4.1. No MethodCard absence, report prose, prompt presence, or empty denominator can become clean assurance.

#### 6.3.2 ProgramFacts public-v3, Graph-v2, and OWN-v2

The ProgramFacts semantic interface is exactly Graph-v2 plus public-v3 plus OWN-v2. Graph-v2 is `architecture/ecosystem-graph-provider-contract.v2.md`. OWN-v2 is `architecture/canonical-requirement-ownership.v2.json`, schema `plamen.canonical_requirement_ownership.v2`, produced by the accepted v1-to-v2 migration that appends PFR-01 through PFR-20 at ordinals 146 through 165 with owner `program_facts_runtime` and preimplementation status `CONTRACT_ONLY_PENDING_IMPLEMENTATION`. Report code neither owns nor republishes either artifact.

The ordered public logical identities are `mechanical_program_facts.v3.json`, `mechanical_program_facts_receipt.v3.json`, and `mechanical_program_facts_debt.v3.json`, with schemas `plamen.mechanical_program_facts.v3`, `plamen.mechanical_program_facts_receipt.v3`, and `plamen.mechanical_program_facts_debt.v3`. The required schema files are `rules/schemas/mechanical_program_facts.v3.schema.json`, `rules/schemas/mechanical_program_facts_receipt.v3.schema.json`, and `rules/schemas/mechanical_program_facts_debt.v3.schema.json`; generation/publication selection additionally uses `rules/schemas/program_facts_public_generation.v2.schema.json`, `rules/schemas/program_facts_publication_arm.v2.schema.json`, and `rules/schemas/program_facts_active_selection.v1.schema.json`.

The required architecture review is `review_fixtures/program_facts_runtime_gate3/architecture/PROGRAM_FACTS_PUBLIC_V3_AMENDMENT_INDEPENDENT_REVIEW.v1.json` with disposition `PASS_PUBLIC_V3_SHADOW_CONTRACT_ONLY`. Public mode is exactly `SHADOW`, semantic authority is `ADDITIVE_PROPOSAL_ONLY`, terminal-negative is false, and all receipt authority-ceiling bits are false. Runtime receipt status is exactly `WRITTEN|REUSED|DEGRADED|UNAVAILABLE|NOT_IMPLEMENTED|FAILED|STALE`. V1 remains read-only legacy, the current v2 experiment never becomes active, and the v3 loader accepts only v3 bytes.

The report consumes the exact MethodCard `ProgramFactsPublicV3Binding`: attested `graph_v2`, `ownership_v2`, `program_facts_spec`, public-v3 architecture-acceptance receipt, ArtifactLedger-selected active selection, payload, runtime receipt, and debt. The ArtifactLedger active head—not `.program_facts/v3/ACTIVE.v1.json`, a mutable root copy, directory discovery, or report capture—selects one immutable `.program_facts/v3/generations/<pfg-id>/` generation. Loader disposition is exactly `ACTIVE_V3|LEGACY_V1|NO_SIDECAR|INTEGRITY_BLOCKED`; a corrupt authoritative v3 head is never downgraded to absence or v1. In ProgramFacts SHADOW, audit semantics remain validated `LEGACY_V1|NO_SIDECAR` even when an active v3 candidate exists, so report P5A requires the separately accepted runtime/cutover authority before projecting v3.

The postimplementation P5A evidence is exact: the reviewed `rules/program-facts-runtime-release-freeze.v1.json` pair; `verification_policy/toolchain_runtime_closure.v2.json`; the 160-case/691-execution acceptance evidence; and `review_fixtures/program_facts_runtime_gate3/PROGRAM_FACTS_RUNTIME_GATE3_INDEPENDENT_CUTOVER_RECEIPT.v1.json` with passing disposition `PASS_GATE3_V3_SHADOW_PRODUCER_SELECTOR_ONLY`. The receipt must bind the current active-generation payload/receipt/debt triple, exact source/build/provider/tool denominator, current audit snapshot, debt, supported-host package/containment evidence, and active-head selection. Its authority ceiling remains shadow producer/selector only: no finding, severity, confidence, clean, MethodCard, consumer, phase, or report authority. Until those concrete postimplementation receipts and an active generation exist, P5A is blocked even though the design interface is closed.

#### 6.3.3 Report-spec acceptance interface

The independent design-acceptance artifact for this file is exactly `review_fixtures/report_p3_p6/REPORT_P3_P6_SPEC_INDEPENDENT_ACCEPTANCE_RECEIPT.v1.json`, schema `plamen.report_p3_p6_spec_independent_acceptance_receipt.v1`, with only passing disposition `PASS_REPORT_P3_P6_DESIGN_FOR_IMPLEMENTATION_ONLY`. Its closed fields are exactly `schema_version`, `receipt_id`, `specification:file_identity`, `program_facts_pin:file_identity`, `method_card_pin:file_identity`, `pinned_local_sources:sorted unique [file_identity]`, `selector_policy_sha256`, `reviewer:{principal_id,organization,role}`, `independence:{spec_author_separate:true,implementation_owner_separate:true,cross_spec_authors_separate:true,workspace_clean:true,no_self_generated_evidence:true}`, `vectors`, `findings`, `open_finding_ids`, `authority_ceiling:{implementation:false,runtime:false,publication:false,cutover:false,upstream:false}`, `disposition`, and `receipt_digest`. `pinned_local_sources` is exactly `{scripts/report_assembly_capture.py,scripts/report_capture_phaseio_authority.py,scripts/phase_io_contracts.py,scripts/plamen_driver.py,architecture/method-application-rfc.md}` with the five file identities in Section 9; the first three are the accepted P0-P2 capture boundary, while the latter two retain their stated current/design authority ceilings. Each vector row is exactly `{vector_id,result:PASS|FAIL,evidence:sorted unique [file_identity]}`; `vectors` has exactly one identity-sorted row for each ID in `{RPS-01_SOURCE_BOUNDARY,RPS-02_CANONICAL_IDENTITY,RPS-03_P3_PURITY_REGISTRY,RPS-04_RETENTION_QUALITY,RPS-05_P4_OWNERSHIP_PUBLICATION,RPS-06_P5_DAG_ROLLBACK,RPS-07_METHOD_CARD_BINDING,RPS-08_PROGRAM_FACTS_BINDING,RPS-09_PACKAGE_CLOSURE,RPS-10_ASSURANCE_DENOMINATORS,RPS-11_FIXTURE_TRANSITIONS,RPS-12_AUTHORITY_CEILING}`. Findings are identity-sorted closed rows `{finding_id,severity:BLOCKING|NONBLOCKING,status:OPEN|CLOSED,statement,evidence:sorted unique [file_identity]}`; `open_finding_ids` is exact set equality with OPEN findings, and PASS requires every vector PASS plus no OPEN BLOCKING finding. `receipt_digest=H(CJ(object excluding receipt_id and receipt_digest))` and `receipt_id="rpsa1_" || receipt_digest`. The specification does not embed its own hash. Mapping instantiation consumes this completed receipt; the receipt cannot consume its later mapping instance, adoption, implementation, P5A, or P6 artifacts.

The report may project accepted MC6 per-card state/debt and accepted ProgramFacts scope/tool/build limitations. It cannot create or upgrade either authority, alter their denominators, close their debt, select a generation, or use later report acceptance to repair an upstream failure.

### 6.4 Driver changes required by the switch

The authoritative driver path MUST:

- build `expected_config` explicitly and pass it through every capture adapter boundary;
- obtain a committed in-memory source capture pair, call the pure renderer, then call P4;
- declare all seven scratch payloads in assembly, final capture v2 in final capture, and only the journal/root install plus singleton A-D and finalize outputs in their exact PhaseIO contracts; declare the project authority checkpoint only in the registered ArtifactLedger operation;
- prohibit live tier/source globbing and report-record recovery during assembly;
- prohibit direct calls to legacy `_assemble_report_python` and legacy prompt assembler for authoritative cells;
- move evidence, scope, MethodCard, assurance, disposition, severity, status, location, and dedup semantics upstream of capture or into P3 pure projection;
- remove post-assembly report mutation transactions from the authoritative call graph;
- make `SHIPPED` depend on the live-ArtifactLedger-authenticated P4 project tuple plus same-run mirror, not process exit success, copied receipts, or file existence; and
- preserve a prior accepted report on new-generation failure.

After authoritative arm, an integrity failure MUST NOT fall through to the live legacy assembler. The safe fallback is the previously receipted report plus typed no-ship debt, not an uncommitted legacy reconstruction.

#### 6.4.1 Six current integration-red transitions

The six current `@INTEGRATION_RED` nodes in `scripts/test_phaseio_p0_report_cutover_red_20260730.py` transition independently. The marker is removed from one node only after its row's exact target is implemented and its PhaseIO/fixture evidence passes; there is no bulk marker removal, suite-level xfail deletion, or acceptance by renaming.

| Current exact test node | Owning landing | Exact green transition |
|---|---|---|
| `test_driver_assembly_input_enumerator_consumes_only_committed_capture_products` | P5B driver reachability | Replace its legacy one-step expectation with three exact registered boundaries: P3 consumes only `scratchpad:report_render_input.json`; assembly consumes only committed `scratchpad:report_render_projection.json` plus `scratchpad:report_render_result.json`; publication consumes only final capture v2 plus the seven committed payload receipts and pinned destination prestates. No live source path is enumerated. |
| `test_assembly_builder_is_pure_over_captured_inputs` | P3/P4 candidate | Exercise `scripts/report_pure_renderer.py` and `scripts/report_assembly_v2.py`; prove the renderer is pure over the committed render input and assembly is a byte-preserving commit of its P3 result, with every listed legacy glob/recovery/appendix/mutator symbol unreachable. |
| `test_no_quality_or_projection_writer_runs_between_assembly_arm_and_commit` | P5B driver reachability | Move all quality/projection decisions into the committed P3 result and prove zero quality, scope, evidence, assurance, dedup, severity-floor, disposition, location, or recovery writer between P3 commit, seven-payload commit, final capture, and publication. |
| `test_first_report_publication_requires_absent_project_report` | P4 candidate | Implement exclusive first publication: project report, fixed locator, registered publication-ledger head, exact A/B paths, and the fixed registered project authority-root directory have authoritative exclusive-creation `ABSENT` prestates; any foreign/preexisting fixed target blocks before install. |
| `test_report_republication_requires_registered_same_run_predecessor` | P4 candidate | Supersede the same-run-only assertion with the Section 5 authenticated cross-run rule: the fixed project ArtifactLedger active head and exact singleton A-D enclosing work units must select/authenticate the retained report/fixed locator/ledger; a valid prior run may be superseded, while scratch-only, copied-receipt-only, unregistered-root, mutated, ABA, or wrong-head predecessors fail. |
| `test_report_records_recovery_is_removed_from_live_assembly` | P5B driver reachability | Prove `report_records` recovery is absent from both P3/P4 implementations and from the authoritative driver call graph; report-record semantics arrive only through the committed captured source role and registry parser. |

P6-pre requires all six nodes green under their individual target contracts. P6-final additionally replays their production-canary reachability assertions. A fixture whose intended assertion changed, especially same-run supersession, must be versioned in place with its old purpose preserved in test metadata; making an obsolete assertion pass vacuously is forbidden.

### 6.5 Historical-run migration

An in-progress or resumable legacy run without committed source/final captures remains in `LEGACY` or starts a new explicitly recorded report generation. The driver MUST NOT retroactively treat legacy Markdown as a committed final capture.

Legacy artifacts may enter the captured path only through reviewed, typed adapters that bind source bytes, run and generation, provenance, limitations, and reconciliation debt. Parser retirement occurs per consumer only after exact parity, malformed-input rejection, crash/resume recovery, package/install validation, and rollback evidence are accepted.

### 6.6 Claude and Codex parity

Claude and Codex may differ in transport or upstream prose, but they share PhaseIO contracts, producer/semantic registries, capture validators, projection schema, retention rules, publication transaction, and acceptance denominators. Cross-backend byte identity is neither expected nor an acceptance rule because visible backend and backend provenance differ.

Parity is computed over `plamen.report_semantic_normalization.v1`. The normalizer validates the complete output first, then replaces only these enumerated backend-specific fields with typed placeholders:

1. `expected_config.backend` and the visible client `Backend:` value → `BACKEND_UNDER_TEST` while separately requiring the original value to be present and correct;
2. backend/model/provider runtime names and version strings in provenance rows → their semantic capability class;
3. backend-specific work-unit keys, owner IDs, contract/launch/commit-receipt digests → ordered provenance placeholders preserving writer class and same-run relation;
4. nondeliverable transcript/log artifact identities → ordered `TRANSCRIPT_n` placeholders; and
5. presentation-only prose/excerpt bytes already classified A3 → their finding/section identity plus content-present/content-absent state.

No other field is normalized. Candidate/finding/placement/root/alias/constituent identities, severity, status, disposition, premise, evidence class, proof scope, locations, obligations, negative closure, human review, MethodCard/ProgramFacts states, debt codes/scopes, counts, output presence, section order, and remediation semantics must be equal. The normalized canonical JSON digests must match. Backend remains visibly correct in each original report, and attempting to replay a Claude envelope/final capture under Codex `expected_config` or vice versa rejects before normalization.

Legacy Claude and Codex report paths remain compatibility references during shadowing. They are not semantic authorities when they conflict with committed typed decisions. Parity means no semantic loss and explainable presentation deltas, not preservation of a legacy bug.

### 6.7 Frozen schema compatibility and retirement

For every report control schema, readers support exactly the current major and the immediately previous major; writers emit only the current major after the corresponding cell activates. For this cutover, final-capture readers support v2 and v1, authoritative writers emit v2, and no v0/unknown schema is accepted. When v3 is accepted, readers support v3 and v2; v1 remains available only in an explicitly versioned offline archival tool.

Retiring the previous major requires `scratchpad:report_schema_retirement_authority.json`, schema `plamen.report_schema_retirement_authority.v1`, producer `report_cutover/schema_retirement`. It binds the successor spec/schema/package digests, every live consumer and archived-run denominator, migration/replay results, malformed-old/new fixtures, rollback window, independent reviewer, and an exact zero unresolved-consumer remainder. Without it, the current+immediately-previous rule remains mandatory. This is the complete retention rule; duration by release count is not discretionary.

The schema-compatibility fixture denominator is exactly ten: `V1_LEGACY_REPLAY_ACCEPT`, `V1_AUTHORITATIVE_REJECT`, `V1_COMPLETE_MIGRATION_ACCEPT`, `V1_INCOMPLETE_MIGRATION_REJECT`, `V2_AUTHORITATIVE_ACCEPT`, `V2_MALFORMED_REJECT`, `V0_UNKNOWN_REJECT`, `V3_FUTURE_REJECT`, `PREVIOUS_RETIREMENT_AUTHORITY_ABSENT_REJECT`, and `PREVIOUS_RETIREMENT_AUTHORITY_VALID_ACCEPT`.

`V1_COMPLETE_MIGRATION_ACCEPT` passes if and only if the source is exact-valid accepted v1, the result is independently exact-valid canonical v2 with precisely the 15 top-level fields in Section 2.4, and a separate exact-valid `plamen.report_assembly_final_capture_migration_receipt.v1` has `disposition=MIGRATED`, the full ordered 15-row reconciliation with every row `PASS`, and byte-equal predecessor/source/result bindings. An absent, embedded, unknown-field-extended, digest-divergent, incomplete, or non-`MIGRATED` receipt is `V1_INCOMPLETE_MIGRATION_REJECT`; migration metadata inside final-capture v2 is an undeclared-field `V2_MALFORMED_REJECT`, never an acceptance shortcut.

## 7. P6 — Final parity and assurance

### 7.1 Frozen assurance matrix

`report_cutover_support_policy.json` contains exactly 96 base cells. The canonical enum arrays, including case and order, are `ecosystems=["EVM","SOLANA","APTOS","SUI","SOROBAN","DAML","GO","RUST"]`, `modes=["LIGHT","CORE","THOROUGH"]`, `backends=["CLAUDE","CODEX"]`, and `publication_hosts=["WINDOWS_AMD64","LINUX_AMD64"]`. Pipeline is derived without ambiguity: the first six ecosystems map to `"SC"`, while `"GO"` and `"RUST"` map to `"L1"`.

For each Cartesian row, `cell_id="rcell1_" + H(CJ({"namespace":"plamen.report.assurance-cell.v1","pipeline":pipeline,"ecosystem":ecosystem,"mode":mode,"backend":backend,"publication_host":publication_host}))`. Rows are enumerated by `(ecosystem ordinal, mode ordinal, backend ordinal, publication-host ordinal)`, all zero-based in the arrays above; no identity sort or implementation map iteration may replace this order. The proof is `8 ecosystems × 3 modes × 2 backends × 2 hosts = 96` distinct canonical preimages. Each row has exactly `cell_id`, pipeline, ecosystem, mode, backend, publication host, enum ordinals, `SUPPORTED|UNSUPPORTED`, policy reason, owner, activation consequence, and support-policy PhaseIO receipt digest. Duplicate preimages/IDs or row-order disagreement fails `ASSURANCE_DENOMINATOR_INCOMPLETE`. Unsupported rows remain in the 96 denominator and cannot receive P5B approval. macOS is outside the v1 96-cell claim; adding it requires a reviewed support-policy v2 and native evidence, never substitution for Linux/POSIX.

Each base cell has exactly 200 scenario IDs from the Cartesian product:

- `lifecycle=["CLEAN","RETRY","CRASH_BEFORE_CLIENT_INSTALL","CRASH_AFTER_CLIENT_INSTALL","RESUME"]` (5);
- `provider=["AVAILABLE","UNAVAILABLE","TIMEOUT","MALFORMED"]` (4);
- `finding_set=["EMPTY_AUTHORIZED","SINGLETON","THREE_MEMBER_CLUSTER","UNRESOLVED","HIGH_VOLUME_8192"]` (5); and
- `publication_mode=["FIRST_PUBLISH","AUTHENTICATED_SUPERSESSION"]` (2).

The four scenario-axis arrays have exactly the displayed orders. For each base cell and Cartesian row, `scenario_id="rsc1_" + H(CJ({"namespace":"plamen.report.assurance-scenario.v1","cell_id":cell_id,"lifecycle":lifecycle,"provider":provider,"finding_set":finding_set,"publication_mode":publication_mode}))`. The preimage contains the actual four axes plus `cell_id`, not a nonexistent fifth scenario axis. Rows are ordered by `(cell ordinal, lifecycle ordinal, provider ordinal, finding-set ordinal, publication-mode ordinal)`. Each cell has `5 × 4 × 5 × 2 = 200` scenarios and the full denominator is therefore `96 × 200 = 19,200` distinct `rsc1_` IDs. `report_cutover_assurance_plan.json` enumerates all IDs and canonical preimages before execution; duplicate, missing, extra, out-of-order, collision, or regenerated-after-result IDs are `ASSURANCE_DENOMINATOR_INCOMPLETE`.

Publication boundary injection has exactly 13 checkpoints:

| ID / ordinal | Exact event code | Crash immediately after |
|---|---|---|
| C01 / 0 | `JOURNAL_ARMED_DURABLE` | durable `ARMED` journal |
| C02 / 1 | `CLIENT_STAGE_DURABLE` | verified predecessor report/locator backups or first-publication absences and durable client staging bytes |
| C03 / 2 | `JOURNAL_CLIENT_STAGED_DURABLE` | durable `CLIENT_STAGED` journal |
| C04 / 3 | `REPORT_INSTALL_DURABLE` | root-report CAS install and project-directory flush, before the journal advance |
| C05 / 4 | `JOURNAL_CLIENT_INSTALLED_DURABLE` | durable `CLIENT_INSTALLED` journal |
| C06 / 5 | `RECEIPT_ARCHIVE_SET_DURABLE` | A’s singleton commit and external receipt followed by B’s separately armed singleton commit and file/directory flushes; never one output set |
| C07 / 6 | `JOURNAL_RECEIPT_ARCHIVED_DURABLE` | durable `RECEIPT_ARCHIVED` journal |
| C08 / 7 | `LOCATOR_INSTALL_DURABLE` | fixed-locator CAS install and project-directory flush, before the journal advance |
| C09 / 8 | `JOURNAL_LOCATOR_INSTALLED_DURABLE` | durable `LOCATOR_INSTALLED` journal |
| C10 / 9 | `LEDGER_INSTALL_DURABLE` | publication-ledger CAS install and project-directory flush, before the journal advance |
| C11 / 10 | `JOURNAL_LEDGER_INSTALLED_DURABLE` | durable `LEDGER_INSTALLED` journal |
| C12 / 11 | `SCRATCH_RECEIPT_DURABLE` | deterministic project ArtifactLedger authority root already CAS-installed/live-replayed, then same-run scratch receipt file/directory flush before journal advance |
| C13 / 12 | `JOURNAL_RECEIPTED_DURABLE` | durable `RECEIPTED` journal before exact staging/backup cleanup |

The crash-variant arrays are `publication_hosts=["WINDOWS_AMD64","LINUX_AMD64"]` and `publication_modes=["FIRST_PUBLISH","AUTHENTICATED_SUPERSESSION"]` in those orders. `variant_ordinal=publication-host ordinal × 2 + publication-mode ordinal`, and `crash_variant_id="rcv1_" + H(CJ({"namespace":"plamen.report.publication-crash-variant.v1","variant_ordinal":variant_ordinal,"publication_host":publication_host,"publication_mode":publication_mode}))`. For every variant and checkpoint table row, `crash_case_id="rcr1_" + H(CJ({"namespace":"plamen.report.publication-crash-case.v1","variant_id":crash_variant_id,"variant_ordinal":variant_ordinal,"publication_host":publication_host,"publication_mode":publication_mode,"checkpoint_id":checkpoint_id,"checkpoint_ordinal":checkpoint_ordinal,"checkpoint_event":checkpoint_event}))`. Crash cases are ordered by `(variant ordinal, checkpoint ordinal)`, producing exactly `(2 hosts × 2 publication modes) × 13 checkpoints = 4 × 13 = 52` distinct `rcr1_` IDs. The assurance plan enumerates every variant/checkpoint preimage and ID before execution and rejects duplicates, collisions, missing/extra IDs, or a checkpoint-event mismatch.

The combined planned-result sequence is the ordered 19,200 `rsc1_` IDs followed by the ordered 52 `rcr1_` IDs. The prefixes are disjoint and the arithmetic is exactly `19,200 + 52 = 19,252`; no auxiliary fixture is silently included in or substituted for that denominator.

### 7.2 Semantic-normalization and deterministic parity

For every applicable fixture P6 compares:

- candidate/finding/disposition/negative/human-review/obligation/MethodCard denominators;
- identity, alias, root, constituent, placement, severity, status, premise, evidence, proof-scope, source-location, remediation, and debt fields;
- exact client summary/body/appendix counts and every exclusion reason;
- seven output role states and deterministic semantic ordering; exact digests/sizes are compared only for repeat executions of the same backend/configuration;
- source/final capture and fixed-ArtifactLedger-selected durable publication tuple plus same-run receipt-mirror bindings; and
- repeated same-backend clean-render/resumed-render byte equality and cross-backend `plamen.report_semantic_normalization.v1` digest equality.

Legacy comparison must classify every delta as `CAPTURED_PATH_DEFECT`, `LEGACY_DEFECT`, `AUTHORIZED_PRESENTATION_DELTA`, or `UNRESOLVED`. An unresolved semantic delta blocks that cell. A legacy defect does not force reproduction, but requires evidence showing the typed authority and new projection are correct.

### 7.3 Required red and adversarial fixtures

Acceptance starts with red controls that demonstrably fail against the forbidden behavior and pass only after repair. The denominators are exact:

| Suite | Frozen denominator |
|---|---|
| Product/scenario | 19,200 IDs |
| Publication crash boundary | 52 IDs |
| Source selector closure | 154 cases: 48 valid producers + 10 legacy-blocked controls + 48 generic-impersonation controls + 48 stale/mutation controls |
| Renderer semantic fixtures | 64 fixtures: one per 48 selector rows + 16 named composite fixtures below |
| Output-role contract | 28 cases: seven roles × `{EXPECTED_PRESENT, EXPECTED_ABSENT, UNEXPECTED_PRESENT, DIGEST_MUTATION}` |
| Schema compatibility | 10 cases defined in Section 6.7 |
| Package/install | six cases: Windows clean checkout/wheel/resume and Linux source archive/wheel/resume |
| MethodCard/ProgramFacts | every identity in the accepted upstream authorities, with exact denominators copied and set-equal rather than sampled |
| Driver reachability | exact AST-node IDs in the pre-cutover baseline callsite manifest bound by the assurance plan; zero authoritative forbidden nodes after P5B |

The 16 composite semantic fixtures are exactly `AUTHORIZED_EMPTY`, `SINGLETON`, `THREE_MEMBER_CLUSTER`, `MULTI_SEVERITY_CLUSTER`, `HUMAN_REVIEW_OPEN`, `NEGATIVE_UNKNOWN_REMAINDER`, `EVIDENCE_CONFLICT`, `PROOF_SCOPE_NARROW`, `LOCATION_UNRESOLVED`, `SECURITY_OBLIGATION_OPEN`, `METHOD_CARD_DEBT`, `PROGRAM_FACTS_LIMITATION`, `AMBIGUOUS_PRECEDENCE`, `CROSS_BACKEND_NORMALIZATION`, `UNSUPPORTED_CELL`, and `HIGH_VOLUME_8192`.

The red corpus has these exact 16 attack classes, each with the case IDs fixed in the assurance plan:

- blocked/unregistered/generic-producer impersonation for each of the ten repaired selectors;
- missing or dimension-mismatched `expected_config`, source roster, MC6, and ProgramFacts authorities;
- circular/self-authored producer requirements and producer-policy drift before and after replay;
- fixed absence/presence transitions, namespace gain/loss/replacement, same-size rewrites, and output gain/loss;
- malformed/duplicate-key/noncanonical/oversize JSON and Markdown;
- unauthorized finding addition/drop/merge/split/rerating/redisposition/negative closure;
- lost cluster constituent, distinct consequence, premise, proof scope, human-review row, or unknown remainder;
- stale capture/receipt/journal plus unknown/unregistered cross-run ledger, locator/archive/commit-projection divergence, copied-receipt-only acceptance, missing/extra/forged ArtifactLedger root/work-unit/binding/output-authority rows, broken predecessor chain, sequence rollback, and valid live-ledger-authenticated supersession;
- symlink, reparse, hard-link, multi-link, parent swap, inode/file-index swap, device name, traversal, case-fold collision, path/size/count overflow, and cross-volume staging;
- concurrent publisher, mutation at every arm/stage/install/receipt boundary, crash at every journal transition, and resume with partial scratch outputs;
- first publication over a preexisting file and republish over an unregistered or mutated predecessor;
- attempted live filesystem/clock/environment/model/ledger read by P3;
- attempted post-P3 evidence, scope, assurance, quality, dedup, or severity-floor mutation;
- final-capture v1 use on an authoritative generation plus v2 request/result/projection/policy/output-set rebinding;
- cross-backend replay and an attempted semantic-normalization exclusion that hides a severity/proof/debt difference; and
- an empty-denominator false pass for every gate family.

Each test record identifies its assurance-plan case ID, expected failure state, actual failure state, and the mutation that would make the red control unexpectedly green. The 48 valid selector fixtures are real nonempty producer fixtures; namespace-empty behavior has separate authenticated empty rows and cannot replace them.

### 7.4 Package, install, and resume assurance

P6 MUST execute from a clean checkout or source archive and from the supported installed-package layouts. The exact report-owned runtime set is frozen by `scratchpad:report_runtime_asset_closure.json`; no directory glob, editable-source import, implicit package data, or ambient `PYTHONPATH` member may satisfy it. The closure has exact top-level fields `schema_version`, `artifact_identity`, `application_version`, `python_runtime`, `source_archive`, `runtime_modules`, `policy_and_template_assets`, `schema_assets`, `external_package_dependencies`, `install_manifest`, `doctor_receipt`, `uninstall_receipt`, `source_tree_sha256`, `installed_tree_sha256`, `asset_count`, `asset_set_sha256`, `closure_digest`, and PhaseIO producer/contract/launch/commit bindings. Every asset row is a canonical project-relative path, byte length, full-file SHA-256, package destination, import/data role, and required/forbidden state. Counts and the digest are over the exact sorted union below.

| Closure class | Exact required members |
|---|---|
| runtime modules | `scripts/report_assembly_capture.py`; `scripts/report_capture_phaseio_authority.py`; `scripts/phase_io_contracts.py`; `scripts/plamen_driver.py`; `scripts/report_render_input.py`; `scripts/report_semantic_registry.py`; `scripts/report_pure_renderer.py`; `scripts/report_assembly_v2.py`; `scripts/report_assembly_publication.py`; `scripts/report_cutover.py` |
| policy/template assets | `rules/report-template.md`; `rules/phase6-report-prompts.md`; `rules/report-semantic-source-registry.v1.json`; `rules/report-render-policy.v1.json`; `rules/report-output-roster.v1.json`; `rules/report-publication-os-policy.v1.json`; `rules/report-cutover-support-policy.v1.json` |
| schema assets | `rules/schemas/report_generation_ledger.v1.schema.json`; `rules/schemas/report_source_selector_closure.v1.schema.json`; `rules/schemas/report_render_input.v1.schema.json`; `rules/schemas/report_render_projection.v1.schema.json`; `rules/schemas/report_render_result.v1.schema.json`; `rules/schemas/report_assembly_final_capture.v2.schema.json`; `rules/schemas/report_publication_transaction.v1.schema.json`; `rules/schemas/report_publication_ledger.v1.schema.json`; `rules/schemas/report_publication_receipt.v1.schema.json`; `rules/schemas/report_cutover_support_policy.v1.schema.json`; `rules/schemas/report_runtime_asset_closure.v1.schema.json`; `rules/schemas/report_cutover_callsite_denominator.v1.schema.json`; `rules/schemas/report_cutover_assurance_plan.v1.schema.json`; `rules/schemas/report_p5_preparation_authority.v1.schema.json`; `rules/schemas/report_p6_preactivation_authority.v1.schema.json`; `rules/schemas/report_p5_activation_receipt.v1.schema.json`; `rules/schemas/report_p5_rollback_receipt.v1.schema.json`; `rules/schemas/report_schema_retirement_authority.v1.schema.json`; `rules/schemas/report_cutover_acceptance_authority.v1.schema.json`; `rules/schemas/report_semantic_normalization.v1.schema.json`; `rules/schemas/report_p3_p6_spec_independent_acceptance_receipt.v1.schema.json` |
| external package dependencies | row `METHOD_CARD_SCHEMA_PACKAGE` = exact active `scratchpad:method_card/{run_id}/control/schema_package_manifest.json` attestation for `plamen.method-card-schema-package-manifest.v1`; row `PROGRAM_FACTS_RUNTIME_CLOSURE` = exact `verification_policy/toolchain_runtime_closure.v2.json`; row `EXECUTION_SUBSTRATE_CLOSURE` = closed object `{phase_io:file_identity,worker_transaction:file_identity,artifact_ledger:file_identity}` for the installed-package closures used by the bound contracts |

The exact report-owned denominator remains the previously frozen 38 required members: ten runtime modules, seven policy/template assets, and 21 schema assets. External package dependencies are three typed dependency rows and are not duplicated into that 38-member set. `asset_count=38`; missing, extra, path-colliding, digest-mismatched, checkout-only, or dependency-unaccepted members block P5A. Source archive, installed legacy-Claude layout, installed Codex layout, and doctor must recompute the same 38-member semantic set and digest; wrapper and installation paths remain nonsemantic transport fields.

The six paths added by the superseded expanded draft are explicitly not runtime members: `report_assembly_final_capture_migration_receipt.v1.schema.json`, `report_publication_receipt_archive.v1.schema.json`, `report_publication_receipt_commit_archive.v1.schema.json`, `report_publication_receipt_locator.v1.schema.json`, `report_heldout_selection_seed.v1.schema.json`, and `report_heldout_selection.v1.schema.json`. The migration/held-out types are construction and P5/P6 control evidence whose closed field/type/enum/canonical/digest validators are compiled into already-counted `scripts/report_cutover.py`; the three publication types are P4 control evidence whose equivalent closed validators are compiled into already-counted `scripts/report_assembly_publication.py`. The project authority checkpoint uses ArtifactLedger v2/work-unit/output-authority formats; its closed active-head/checkpoint validators are compiled into the pinned external `artifact_ledger` execution-substrate dependency, so none adds a report schema path. Their schema-version tags remain exact dispatch identities and every undeclared field still rejects.

The compiled-validator registry has exactly two identity-sorted rows: `REPORT_CUTOVER_CONTROL_VALIDATORS` over `{plamen.report_assembly_final_capture_migration_receipt.v1,plamen.report_heldout_selection_seed.v1,plamen.report_heldout_selection.v1}` and `REPORT_PUBLICATION_CONTROL_VALIDATORS` over `{plamen.report_publication_receipt_archive.v1,plamen.report_publication_receipt_commit_archive.v1,plamen.report_publication_receipt_locator.v1}`. Each row’s digest is `H(CJ({"registry_id":id,"schema_tags":identity-sorted-tags,"closed_validator_definitions":exact-compiled-field/type/enum/range/additional-properties-rules}))`. The separate `REPORT_PUBLICATION_AUTHORITY_ROOT_V1` registry digest binds the fixed ArtifactLedger path/interface/key profile but is not a schema validator or package-data member. The owning module’s full-file SHA-256 and the external ArtifactLedger substrate digest are already bound by runtime/dependency closure; P5A and both P6 stages additionally bind and execute the two validator digests, root-registry digest, and live ArtifactLedger interface against canonical valid/malformed fixtures. Externalizing any compiled validator or root registry as a package-data file is an extra-member failure until a reviewed runtime-closure major changes the accepted denominator.

Oracle sources, expected-result trees, review fixtures, generated construction schemas, PDFs, audit scratch artifacts, project `AUDIT_REPORT.md`, journals, and receipts are forbidden package members. Install is offline and fail-closed; uninstall removes only install-receipt-owned runtime members and preserves audit/project artifacts.

Resume tests MUST prove transitive digest equality. A retry/resume cannot change model/backend, renderer version, source policy, MethodCard catalog, semantic placement, output bytes, or debt without a new generation and activation decision.

### 7.5 Independent review

The independent reviewer MUST be separate from the P3/P4 implementer and must receive:

- frozen source tree and artifact hashes;
- producer-closure inventory and all ten repair receipts;
- P3/P4/P5/P6 contracts and test denominators;
- full red-control and product-matrix results, including failures and unsupported cells;
- crash journals, recovery receipts, and Windows/POSIX durability evidence;
- semantic delta ledger for Claude/Codex and legacy/captured paths;
- MC6 `method_card_application_assurance_authority.json`; and
- closed debt taxonomy, any explicit policy waivers, and rollback evidence.

Held-out selection is deterministic and exact. Its sole seed authority is `scratchpad:report_heldout_selection_seed.json`, schema `plamen.report_heldout_selection_seed.v1`, produced by `report_cutover/heldout_selection_seed` as the first P6-pre sub-work-unit and committed before any P6-pre scenario/crash execution or review. Its exact top-level fields are `schema_version`, `artifact_identity`, `selection_seed_id`, `candidate_code`, `assurance_plan`, `independent_reviewer_principal_id`, `independent_checkout_commit_sha`, `selection_algorithm_id`, `selection_algorithm_sha256`, `population_counts`, `selection_counts`, `authority_ceiling`, and `seed_digest`. `candidate_code` is exactly the binding to `scratchpad:report_runtime_asset_closure.json`/`plamen.report_runtime_asset_closure.v1`; `assurance_plan` is exactly the binding to `scratchpad:report_cutover_assurance_plan.json`/`plamen.report_cutover_assurance_plan.v1`. Each binding contains exact identity, schema, raw-file digest, producer, contract, launch, and external commit-receipt digest and contains no execution-result binding. `population_counts` is exactly `{base_cells:96,scenarios_per_cell:200,scenario_total:19200,crash_variants:4,checkpoints_per_variant:13,crash_total:52}`; `selection_counts` is exactly `{scenarios_per_cell:20,scenario_total:1920,crashes_per_variant:2,crash_total:8,heldout_total:1928}`; and `authority_ceiling` is exactly `{may_select:true,may_read_results:false,may_modify_plan:false,may_issue_review_verdict:false}`. `selection_algorithm_id` is exactly `plamen.report.heldout-selection.v1` and its digest binds the implementation/policy bytes used below.

The seed has an acyclic pre-selection content boundary. It MUST NOT contain or hash P6-pre/P5B/P6-final, selected scenario/crash IDs, any scenario/crash result or score, execution receipts, review findings, review verdicts, production canary evidence, `report_heldout_selection.json`, or any artifact created after seed commit. Let `seed_body` omit `selection_seed_id` and `seed_digest`: `seed_digest=H(CJ(seed_body))`, `selection_seed_id="rhss1_" + seed_digest`, and `selection_seed_sha256=H(CJF(the complete seed object))`. Unknown fields, result-bearing candidate-code/plan bindings, or a predecessor committed after the seed are invalid. This named seed replaces the prior ambiguous free-form review-artifact input; no free-form review artifact participates in selection. `report_cutover/heldout_select` commits the selection immediately next; only then may P6-pre execute cases, review results, and emit its authority, which binds both pre-result artifacts. This is still the exact stage order P5A → P6-pre → P5B → P6-final, not an added gate.

`report_cutover/heldout_select` consumes the committed seed and frozen assurance plan and writes `scratchpad:report_heldout_selection.json`, schema `plamen.report_heldout_selection.v1`. Its exact fields are `schema_version`, `artifact_identity`, `selection_id`, `seed_binding`, `nonce`, `selection_algorithm_id`, `scenario_selections`, `crash_selections`, `selection_counts`, `selection_set_sha256`, and `selection_digest`. `seed_binding` contains the seed identity, schema, ID, raw-file digest, producer/contract/launch, and commit-receipt digest. The selection artifact contains IDs and scores only; results, execution receipts, findings, and verdicts are undeclared fields. `nonce=H(CJ({"namespace":"plamen.report.heldout-nonce.v1","selection_seed_id":selection_seed_id,"selection_seed_sha256":selection_seed_sha256}))`.

For scenarios, `scenario_score=H(ASCII("plamen.report.heldout-scenario.v1") || 0x00 || ASCII(scenario_id) || 0x00 || ASCII(nonce))`, interpreted as an unsigned big-endian 256-bit integer. Within each of the 96 base cells in canonical Section 7.1 order, score exactly that cell’s 200 frozen `rsc1_` IDs, select the lowest 20, and break an impossible hash tie by ascending ASCII `scenario_id`; selected rows are ordered by `(cell ordinal, score integer, ASCII scenario_id)`. Thus `96 × 20 = 1,920` exact scenario IDs.

For crashes, `crash_score=H(ASCII("plamen.report.heldout-crash.v1") || 0x00 || ASCII(crash_case_id) || 0x00 || ASCII(nonce))`, also unsigned big-endian. Within each of the four canonical `rcv1_` variants, score exactly its 13 frozen `rcr1_` crash-case IDs from the assurance plan, select the lowest two, break ties by ascending ASCII `crash_case_id`, and order rows by `(variant ordinal, score integer, ASCII crash_case_id)`. Thus `4 × 2 = 8` exact crash IDs. `scenario_selections` and `crash_selections` record group ID/ordinal, selected exact case ID, 64-lowercase-hex score, and within-group rank. `selection_set_sha256=H(CJ({"scenario_ids":ordered_1920_ids,"crash_case_ids":ordered_8_ids}))`; with `selection_id` and `selection_digest` omitted, `selection_digest=H(CJ(selection_body))` and `selection_id="rhs1_" + selection_digest`.

The held-out denominator proof is exactly `1,920 + 8 = 1,928`. A selected ID absent from the frozen 19,252 plan, a non-`rcr1_` crash reference, result-aware seed/selection content, changed nonce, score/tie/order mismatch, duplicate, substitution, or any count other than 1,928 blocks P6-final. No signing key or network service is required. The existing independent architecture review is design evidence only and is not cutover approval.

P6-final acceptance is `scratchpad:report_cutover_acceptance_authority.json`, produced by `report_cutover/p6_final_acceptance` under `plamen.report_cutover_acceptance_authority.v1`. It binds exact code, 38-member runtime-asset closure and three external dependency rows, registry, policy, source/render/final/publication schema tags and compiled-validator digests, `REPORT_PUBLICATION_AUTHORITY_ROOT_V1` plus the pinned ArtifactLedger substrate/interface digest and canary root replay, the held-out seed/selection identities and receipts, P5B receipt, MethodCard mapping instance/adoption plus MC6 acceptance, ProgramFacts active-generation/runtime/cutover authorities, all 19,252 planned results, 1,928 exact selected held-out results, production canary publication, compatibility cell, producer, reviewer, and replay digests. Prose approval alone is insufficient.

## 8. Stage gates and deliverables

| Gate | Required deliverables | Authority granted |
|---|---|---|
| P3 candidate | committed render-input envelope, pure projection/result, 48-row semantic registry, exact seven-output value, closed quality/debt gates | candidate values only |
| P4 candidate | seven assembly scratch payloads, final-capture v2, singleton A-D commits, deterministic project ArtifactLedger authority root, journal/scratch mirror, Windows/POSIX crash/race suite | isolated candidate transaction only |
| Ten-selector landing | 48-permitted/zero-blocked registry, typed producer receipts, production callsites, repair tests | eligible to request live P3/P4 arm |
| Upstream MethodCard/ProgramFacts | independently accepted specs, runtime/cutover authorities, MC6 assurance and successor attestation | upstream truth only; report may project it |
| P5A prepare | `report_p5_preparation_authority.json` over exact selector/support/assurance/upstream/code pins | no switch; one exact rollback plan |
| P6-pre | `report_p6_preactivation_authority.json` over complete preactivation evidence | one P5B CAS and one canary generation only |
| P5B switch | `report_p5_activation_receipt.json` and cell CAS | temporary `AUTHORITATIVE_PENDING_FINAL` for the canary |
| P6-final | canary publication, 19,252 planned cases, 1,928 held-out cases, package/resume, independent replay | `AUTHORITATIVE_ACCEPTED` per approved cell |

No earlier gate implies a later one. Green P3/P4 candidates do not authorize project publication; P6-pre does not claim final acceptance; P5B without P6-final is a one-canary state that must accept or roll back. A polished `AUDIT_REPORT.md` proves none of producer closure, MethodCard/ProgramFacts authority, negative closure, publication receipt, or parity completion.

## 9. Source map and claim labels

The labels below prevent design material, historical status, and observational reports from being cited as implementation proof.

| Label | Source | Digest/identity used for this specification | Claims supported |
|---|---|---|---|
| `NORMATIVE-ACCEPTED` | `scripts/report_assembly_capture.py` | SHA-256 `f6453ba40cda5464224f6c007618859a237ecd20c6fce5eb6dc2e1f40ae3a89e`, 123,676 bytes | source/final identities, exact seven outputs, capture/replay/path/size model |
| `NORMATIVE-ACCEPTED` | `scripts/report_capture_phaseio_authority.py` | SHA-256 `42bc233ecfcb216f861aa79f8c494b3edab0ef336c39b814a5054131389bb504`, 91,732 bytes | 43+5 denominator, 38+10 policy, expected-config and producer replay boundary |
| `NORMATIVE-ACCEPTED` | `scripts/phase_io_contracts.py` | SHA-256 `f3d580f5f560c10e3337287dec18e6dac4d2d86289ad34346f7b39477d1ec3af`, 349,682 bytes | final capture as sole assembly input and exact output denominator |
| `NORMATIVE-ACCEPTED` | report P0-P2/R3-R5 tests, especially `test_phaseio_p0_report_cutover_red_20260730.py` | file identities in the source tree; policy inventory expected digest `4e28e1f6925a53cf2b45b7318d8924644f3d92fdc8ad1f05c4107c77ab3704a1` | accepted red boundary, mutations/races, candidate P3/P4 integration expectations |
| `CURRENT-IMPLEMENTATION` | `scripts/plamen_driver.py` | SHA-256 `0f003ac946b3c35797d945c19de95745dcd5ee045c8aafe65580f11ceff4f8ca`, 3,124,519 bytes | legacy live read/mutator/quarantine behavior to remove; not desired authority |
| `NORMATIVE-DESIGN` | `architecture/method-application-rfc.md` | SHA-256 `2778af4391ec5a7f725d908c446bb3d9ebaf105fe13f08a3a46f37cadd0f35b4`, 37,080 bytes at source-map capture | projection, retention, identity, failure, migration, parity, and assurance principles |
| `ACCEPTED-CROSS-SPEC-DESIGN` | `architecture/program-facts-runtime-cutover-spec.md` | SHA-256 `2f2025cf636ca80df560d7568760f6ebfc114a2c344a895940ea76566c953c79`, 238,989 bytes, 2,011 LF-terminated lines | exact public-v3/Graph-v2/OWN-v2 and runtime/cutover evidence interfaces; grants no runtime or active-generation authority |
| `ACCEPTED-CROSS-SPEC-DESIGN` | `architecture/method-card-mc0b-mc6-cutover-spec.md` | SHA-256 `d0bea26280f1315fc9e0c03d583b73a1af30784c3c0053b9215050ae83046a01`, 180,744 bytes, 659 LF-terminated lines | exact MCUT-012/013/038, MC6 assurance, report mapping, and downstream adoption interfaces; grants no MethodCard runtime or report authority |
| `NORMATIVE-METHODOLOGY` | `~/.codex/plamen/rules/report-template.md` and `phase6-report-prompts.md` | SHA-256 `dc3927c3728e9dc26a1662c55ce1cb470be306302ef22dfcba73579923b4f686` (19,022 bytes) and `770fefb0077c169b1102af92bb34c367a74216453143add66545e36c25b8c0d7` (40,104 bytes) at source-map capture | current report content/quality vocabulary; typed authorities in this specification supersede prompt adjudication |
| `HISTORICAL-PLAN` | `Plamen_Canonical_Architecture_Methodology_and_Implementation_Plan_2026-07-15.md` | SHA-256 `4b487c3bf271933e88bcb094c5bdd1268db310a082b2b86f2fb5a83b21030b34`, 112,624 bytes | renderer ownership, reversible root-cause clustering, strangler migration, parity goals |
| `HISTORICAL-HANDOFF` | Claude↔Codex implementation/review handoffs dated 2026-07-15 and 2026-07-16 | SHA-256 `e69831fc4735254ad4cc41a06639a124fc1261b31447a581b5ed7b288794c5ea` and `664def020d68fd26703a7997f0aad5c684dfc7cf0727e4bb15d78458a74fee7f` | prior intent and review context, not current completion |
| `HISTORICAL-STATUS` | Goal Acceptance Ledger 2026-07-17 and Plan Completion Audit 2026-07-24 | SHA-256 `0d05542b851609a1b81565bd69f7824ac8c677b2440ff072d50dd79f4ec66060` and `357e049c1a738d2e8682f1f2e0c339dad77d876172e7cf0f1ddc8bf6d947a5de` | open report degradation, retention, transaction, and evidence-parity work at those dates |
| `HISTORICAL-CROSSWALK` | `Plamen_Architecture_Supersession_Crosswalk_2026-07-24.md` | SHA-256 `e485320fb9b71e64bc676b3208f2531ca41c549fbac439c7d7e1d125b84ec926`, 70,357 bytes | point-in-time supersession mapping; not proof of live consumer cutover |
| `INDEPENDENT-DESIGN-REVIEW` | `review_fixtures/canonical_architecture_independent_review_r3.md` and Claude reviews dated 2026-07-31/2026-08-01 | review digests include `3ba029008c842bb8e514d33038bde58544314c8b177115012061e3b7d8d1934a`, `46c0939d7b373267205dbb842425048c9c35828c63fb82740beadb3d568be12e`, and corpus-capture digest `d236f565580c83444c282fc91a016d520022050484cfed9d2bf2fc6eeb25a337` | design concerns, corpus provenance, and open cutover risks; explicitly not production approval |
| `OBSERVATIONAL-QUALITY-REFERENCE` | 19 report-related PDFs in Downloads, 17 unique digests | complete inventory below | common client presentation patterns only; no authority or acceptance threshold |
| `IMPLEMENTATION-READY-DESIGN` | this file | complete external file identity is recorded only in the Section 6.3.3 independent acceptance receipt, avoiding a self-hash cycle | closed implementation contract for P3-P6; grants no implementation, publication, or cutover authority by itself |

All source-map digests are point-in-time observations, not claims that a mutable worktree remains unchanged. P5 activation MUST re-freeze the exact reviewed inputs. The observational PDF corpus MUST be represented in that manifest by a complete filename/digest inventory if it is used for presentation regression testing.

### 9.1 Observational PDF inventory

All 19 report PDFs inspected for presentation patterns are enumerated here: 17 unique byte digests, with two duplicate pairs intentionally retained as separate source-file identities.

| File | Bytes | SHA-256 |
|---|---:|---|
| `Certora - DFLow - Native Predictions - Final Report (1).pdf` | 284,815 | `efa79b18545a261b2e6385e9c1769a2f780c840ebdad39f1a8303a7a7c5e48e5` |
| `Certora - DFLow - Native Predictions - Final Report.pdf` | 284,815 | `efa79b18545a261b2e6385e9c1769a2f780c840ebdad39f1a8303a7a7c5e48e5` |
| `Certora - Lightcone Pinnochio - Report.pdf` | 658,710 | `69d3746d4a033bd14fdf6f6a1546e7b6484db4a247a6b8a6173a82aec6b69438` |
| `Certora - Lightcone Pinnochio 2 - Final Report (1).pdf` | 394,590 | `39b3ef5de1709b9ccd7f5d6fcea08d531f1ebaf460441f7d1b492f1bd26cee4b` |
| `Certora - Lightcone Pinnochio 2 - Final Report.pdf` | 394,590 | `39b3ef5de1709b9ccd7f5d6fcea08d531f1ebaf460441f7d1b492f1bd26cee4b` |
| `Certora - Royco Day - Draft Report.pdf` | 628,528 | `963184bc68958fcb5ce4d6fc639889c521857ecf5ea4623e2fd48d20d6c080c5` |
| `Certora - Spectra Bridge - Report.pdf` | 441,215 | `42efc46a93ecbf4ad6295aba9cb8cf665dd48681729a7e554afc7f6acb62f4b8` |
| `Certora - Spectra Core - Draft Report (1).pdf` | 748,176 | `87b938b1aa19c277846ef3e70bbd2f4ab97d1966e80b395b6dd507d0d7e8fd18` |
| `Certora - Spectra Core - Draft Report (2).pdf` | 877,196 | `00c7ea5238496bdaa2ca3622d036e45d9f8ce1f69008847690782f23f33034da` |
| `Certora - Spectra Core - Draft Report.pdf` | 801,281 | `660c64968be18a2807596995573d06e3b15c4dd91277cfe3fa607b83750b4c6f` |
| `Certora - Spectra Core - Final Report (1).pdf` | 926,249 | `0d717de907932e2555060dc115301ee2e672b35c7b7fe747267cd7aa91a55135` |
| `Certora - Spectra Core - Final Report.pdf` | 926,257 | `da8fdca0f373b88e5aec8b8cf99fdf4fb0f210125ad86f106504cc7b18b3af2b` |
| `Certora - Spectra Core - Snapshot Draft Report (1).pdf` | 920,174 | `6ed967e8322793d00173c2549e08da98281f2388fa011cb0319297003ce37389` |
| `Certora - Spectra Core - Snapshot Draft Report (2).pdf` | 920,303 | `bb650706f1101e5c8efeda133a3bccf2ecbd4d6a89267ba0a9b0ae62086947f7` |
| `Certora - Spectra Core - Snapshot Draft Report (3).pdf` | 916,744 | `f12414cd60a57be343220c20e6a0bb4bcf94e54944a5dfb3b1b674d809f19dea` |
| `Certora - Spectra Core - Snapshot Draft Report.pdf` | 906,506 | `3e8646524830b34329dd2cb59f4a621cdfeee00fe2a1ec31f7a13c2a2d154ab8` |
| `Certora - Spectra Core Final Report (1).pdf` | 931,180 | `47239ed9d258fd04814ff41c2bb632af37c616393f74907e72f7eae1d352c1b0` |
| `Certora - Spectra Core Final Report (2).pdf` | 930,818 | `307d6deed20a2f692928a9aa0b5d087a64df84c09cd5652e59dd6a62e6fd6b13` |
| `Certora - Spectra Core Final Report.pdf` | 926,334 | `70c654e6ee7693574ed7686de13b1f1e1b76c2ff66fcc5c21a15b37f6daf2b90` |

## 10. Explicit assumptions

| ID | Assumption | Consequence if false |
|---|---|---|
| A1 | The accepted source denominator remains 43 fixed plus five namespaces, and the policy baseline remains 38 permitted plus ten blocked. | Reopen P0-P2 with an independently reviewed denominator migration before implementing P3. |
| A2 | “Live P3/P4” means authority to publish or replace the project-root client report; shadow rendering/staging is not live publication. | Candidate work remains non-authoritative and cannot bypass the ten-selector gate. |
| A3 | The seven logical roles are frozen; v2 materializes all seven under assembly-owned scratch identities and maps the client payload to its project destination. | Revise PhaseIO, capture v2, payload/destination denominators, and publication together. |
| A4 | Only project-root `AUDIT_REPORT.md` is client-public; the six scratchpad outputs are internal but authoritative contract outputs. | Add explicit client privacy and delivery rules for any newly public scratch artifact. |
| A5 | Immutable renderer policy is code/package data whose exact digest is in the render request, not a live file read during P3. | Capture the policy bytes as an additional typed predecessor before P3. |
| A6 | Existing report PDFs are presentation evidence, not semantic truth. | Obtain explicit policy authority before deriving any normative requirement from them. |
| A7 | P3/P4 candidates may precede MC6, while final P5/P6 acceptance may not. | If MC6 is required earlier, candidate fixtures must supply a provisional typed MC6 test authority. |
| A8 | The v1 support claim contains Windows and Linux/POSIX only. | A macOS claim requires reviewed support-policy v2 and native durability/package evidence. |

## 11. Closed implementation decisions

There are no deferred normative identity or denominator choices in this specification. The previously open decisions are closed as follows:

| Topic | Frozen decision |
|---|---|
| P3/control schemas | Exact names, schemas, producers, and direct consumers are in Section 3.2. |
| Final capture | v2 is the unchanged closed authoritative writer schema; v1 is legacy-readable only and migrates by exact replay proven by the separate 15-field migration receipt. |
| Publication primitives | Linux uses the specified `openat`/`fsync`/`renameat2` sequence; Windows uses the specified `CreateFileW`/`MoveFileExW`/`ReplaceFileW`/`FlushFileBuffers` sequence. |
| Cross-run replacement | Only the constant project ArtifactLedger active root whose enclosing A-D authorities replay under the live interface may select/authenticate the D ledger head, digest-bound C locator, and A-B archives for supersession; scratchpad, copied receipts, and discovery never do. |
| Schema retention | Readers retain current + immediately previous major until `report_schema_retirement_authority.json` approves retirement. |
| Host claim | v1 is Windows + Linux/POSIX; macOS requires support-policy v2. |
| Client export | v1 has exactly seven roles and no machine-readable eighth client output. |
| Degraded wording/debt | Section 4.9’s templates and closed six/21 debt-code partition are exact. |
| Assurance | Exact `rcell1_`/`rsc1_`/`rcv1_`/`rcr1_` preimages and order produce 96 base cells, 19,200 scenarios, 52 crash cases, and a pre-result-seeded 1,928-case held-out set. |

The cross-spec semantic choices are closed by the two accepted design pins in Sections 6.3 and 9. Concrete ProgramFacts runtime/active-generation receipts, MethodCard MC0B-MC6 execution/acceptance and report-mapping adoption, report implementation/package receipts, and P5A/P6 evidence remain future artifacts whose paths, schemas, producers, ordering, and authority ceilings are fixed here. Their future byte values cannot be replaced by candidate hashes or prose.

## 12. Definition of done

Report cutover is done only when a P6 acceptance authority proves, for every approved compatibility cell, that:

- all 48 source selectors have typed producer closure and zero are blocked;
- P3 is pure and lossless over committed captured truth;
- P4 assembly commits seven scratch payloads/final capture v2, publication installs the exact client payload through singleton A-D commits and a deterministic post-ledger project ArtifactLedger checkpoint, and recovery preserves/restores the last accepted report/locator without deleting archive/root history;
- P5B makes render input/projection/result the sole assembly chain and final capture v2 the sole publication byte authority, with legacy live assembly/post-mutation unreachable;
- MC6’s exact `method_card_application_assurance_authority.json` and the accepted ProgramFacts authorities are bound and merely projected, not reauthored;
- Claude/Codex, smart-contract/L1, mode, ecosystem, Windows/POSIX, retry/resume, and package/install denominators are reconciled;
- all 19,252 planned cases and exact auxiliary fixture denominators pass/disposition, every red control first fails for the intended reason, and no denominator is empty by omission; and
- an independent reviewer replayed held-out evidence and committed the exact implementation, registry, schema, fixture, and result digests through the P6-final receipt.

Until P6-final, P3/P4 output is candidate evidence, P6-pre grants only one P5B canary switch, and no artifact may claim final report cutover authority.
