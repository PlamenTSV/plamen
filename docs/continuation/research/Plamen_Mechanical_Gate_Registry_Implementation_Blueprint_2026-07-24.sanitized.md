# Plamen Mechanical-Gate Governance v2 - Implementation Blueprint

**Date:** 2026-07-24  
**Repository:** `<LOCAL_USER_ROOT>\plamen-codex-implementation`  
**Inspected revision:** `67a0f85adc7a8169d79a286908b00bef7adb764a` plus the current uncommitted worktree  
**Purpose:** implementation-ready design for R0-8e mechanical-gate governance  
**Change boundary for this document:** architecture only. No repository, audit target, scratchpad, ground-truth input, configuration, test, installation, or runtime state was changed.

## 1. Decision

Implement mechanical-gate governance v2 as a closed, runtime-enforced authority system, not as a populated policy file.

The first accepted v2 baseline has:

- exactly **33 live decision-authority records**;
- every live record in `LEGACY_ACTIVE_UNGOVERNED`;
- no invented M1-M4 evidence, owner, reviewer, false-fire threshold, held-out result, or seam ceiling;
- three non-runtime tombstones for dead or superseded behavior;
- a generated, digest-bound activation inventory;
- literal gate and activation IDs at every production wrapper;
- strict schema and semantic validation;
- PhaseIO-bound, input-digest-bound runtime receipts;
- explicit `UNKNOWN` and durable overflow, never missing-evidence-as-`CLEAR`;
- neutral held-out evaluation as the only authority for false-fire results; and
- staged cutover only after the shared PhaseIO commit-CAS/output-prestate prerequisite is accepted.

The existing v1 state is not a baseline. `rules/mechanical-gate-registry.json`
is empty, is not loaded by production, and is affirmatively locked empty by
`scripts/test_post_audit_gate_budget.py`.

## 2. Evidence and prerequisite boundary

This blueprint reconciles:

- `Plamen_Mechanical_Gate_Registry_Forensic_2026-07-24.md`, SHA-256
  `7D60F798F7E2861B6EFD72201FCA8696234A3E5C0F430B5E9B5BE5520C47309D`;
- `Plamen_Plan_Completion_Audit_2026-07-24.md`, SHA-256
  `357E049C1A738D2E8682F1F2E0C339DAD77D876172E7CF0F1DDC8BF6D947A5DE`;
- `Plamen_Goal_Acceptance_Ledger_2026-07-17.md`, SHA-256
  `0D05542B851609A1B81565BD69F7824AC8C677B2440FF072D50DD79F4EC66060`;
- the current registry and post-audit protocol;
- `PhaseIOContract`, artifact-ledger arm/commit machinery, validators, live gate
  modules, driver call sites, packaging logic, and related tests.

The implementation must respect the program closure order. Runtime mutation
cutover is blocked until the shared PhaseIO boundary proves:

1. exact pre-execution input binding;
2. output-prestate binding for read-modify-write artifacts;
3. compare-and-swap immediately before canonical replacement;
4. quarantine on input, file-set, or prestate drift;
5. no `OUTPUT_COMMITTED`/`ACTIVE` artifact record for bytes outside that
   transaction; and
6. crash and resume recovery for every terminal transaction state.

Schema, inventory, wrappers that only observe, static lint, and shadow receipts
may be built before that prerequisite. A gate must not gain new mutation
authority before it.

## 3. Resolve the M1-M4 contradiction with decision classes

The current protocol says every mechanical gate needs M1-M4, while M4 says a
gate fires only after verification. That cannot admit startup circuit breakers,
pre-verification recall generators, graph-health checks, or telemetry. Do not
weaken M4. Narrow its scope to the class it was written for.

Add this closed decision-class taxonomy:

| Decision class | Admission evidence | Authority boundary |
|---|---|---|
| `RC_AGENT_MECHANIZABLE` | M1 recurring in at least three independent audits; M2 deterministic; M3 generic and Part-0 clean; M4 verify-filtered | The narrow post-audit escape hatch. All four remain mandatory. |
| `RECALL_GENERATOR` | M1-M3; exact or lower-bound denominator; independent downstream verification and delivery; measured cost/noise; no terminal finding authority | May add or reopen only. It cannot clear, remove, demote, or prove a finding. M4 is structurally inapplicable because generation precedes verification. |
| `PIPELINE_INTEGRITY` | Deterministic correctness/safety proof; typed inputs and outputs; fault and resume evidence; fail-closed or recall-open behavior; Part-0 pass | Protects execution, retention, transaction, proof, or ship integrity. Recurrence and verify filtering are not admission predicates. |
| `PRECISION_DISCRIMINATOR` | M2-M3; typed decision evidence; independent review; recall-safe fallback; neutral held-out precision and recall evidence before new destructive authority | May cap, route, consolidate, or otherwise reduce authority only from typed evidence. Missing/invalid authority preserves the upstream state. |
| `TELEMETRY_ONLY` | M2-M3; exact denominator semantics or visible lower-bound debt; typed delivery; Part-0 pass | Cannot change a finding, obligation, severity, proof state, execution decision, or ship state. |

Protocol edits:

- Keep Step 2.5 and Part 3a M1-M4 text unchanged for
  `RC_AGENT_MECHANIZABLE`.
- Change the lifecycle contract from “every record defines M1-M4 evidence” to
  “every record defines class-specific admission evidence.”
- State that all classes independently pass Part 0.
- State that moving a gate to a class with broader authority is a new proposal,
  not a metadata edit.
- Correct the count-set contradiction. The current text requires all three
  sets to be pairwise disjoint and also requires `release_gate_ids` to be a
  subset of `baseline_gate_ids`. The v2 invariant is:

  ```text
  addition_gate_ids ∩ baseline_gate_ids = empty
  addition_gate_ids ∩ release_gate_ids = empty
  release_gate_ids ⊆ baseline_gate_ids
  post_change_gate_ids =
      (baseline_gate_ids - release_gate_ids) ∪ addition_gate_ids
  ```

No current live record is retroactively certified as
`RC_AGENT_MECHANIZABLE`. Classification describes the authority type;
`admission.status = LEGACY_UNASSESSED` records that its evidence has not been
established.

## 4. Frozen registry boundary

### 4.1 Included authority

Register every deterministic decision that independently changes at least one
of:

1. finding or candidate membership;
2. security-obligation membership or lifecycle;
3. finding disposition or report tier;
4. severity;
5. evidence/proof status or successor authority;
6. whether target code, builds, tests, or PoCs may execute;
7. verification routing or mandatory reverification;
8. final ship/no-ship or assurance authority.

“Independently” means the predicate can fire while another predicate in the
same function or dispatcher does not. It therefore receives its own gate ID.
Shared ecosystem adapters for the same semantic decision are activations of one
gate. Independently fireable decisions at different seams are separate gates.

### 4.2 Excluded control families

Freeze these exclusions in `registry_scope.excluded_control_families`:

- structural presence/shape validators that only accept or reject their own
  producer output and do not independently exercise an included authority;
- PhaseIO, artifact-ledger, checkpoint, lock, retry, worker-pool, and
  subprocess-supervision mechanics as mechanics;
- parsers, renderers, serializers, hashing helpers, path normalizers, and
  schema utilities without decision authority;
- static analyzer/tool outputs until a deterministic consumer exercises an
  included authority;
- model judgments and agent verdicts;
- test-only helpers, fixtures, migrations not reachable from production, and
  dead code; and
- post-audit human classification itself.

An excluded validator becomes included as soon as it independently clears,
adds, removes, routes, demotes, blocks, executes, or grants/vetoes authority.
Calling a predicate “validation” is not an exclusion.

This boundary deliberately does not register every function called by
`_run_phase_validators` (`scripts/plamen_driver.py:40766`). That broader
interpretation is materially larger and is rejected for v2. Any future scope
change requires a registry revision, migration inventory, independent review,
and no-scope-loss crosswalk.

## 5. Frozen baseline: 33 live decisions

Abbreviations below: `PI` = `PIPELINE_INTEGRITY`, `RG` =
`RECALL_GENERATOR`, `PD` = `PRECISION_DISCRIMINATOR`, `TEL` =
`TELEMETRY_ONLY`. Every row initially has
`lifecycle_state=LEGACY_ACTIVE_UNGOVERNED` and
`admission.status=LEGACY_UNASSESSED`.

| # | Stable gate ID | Class / seam | Current decision symbol(s) | Current production activation or owner |
|---:|---|---|---|---|
| 1 | `supply_chain.pre_input_execution` | PI / `STARTUP_RESUME` | `scripts/supply_chain_gate.py:189 gate_supply_chain` | `scripts/recon_prepass.py:2211` |
| 2 | `supply_chain.pre_poc_execution` | PI / `POST_VERIFY` | `scripts/supply_chain_gate.py:189 gate_supply_chain` | `scripts/mechanical_verify.py:2209` |
| 3 | `snapshot.startup_binding` | PI / `STARTUP_RESUME` | `scripts/audit_snapshot.py:1913 snapshot_startup_guard` | `scripts/plamen_driver.py:45105` |
| 4 | `snapshot.interphase_drift` | PI / `STARTUP_RESUME` | `scripts/plamen_driver.py:43993 _assert_audit_snapshot_still_bound` | `scripts/plamen_driver.py:40768`, `:45546` |
| 5 | `enumeration.graph_health` | TEL / `POST_DISCOVERY` | `scripts/enumeration_gate.py:526 _graph_health_shortfalls`, `:662 _record_graph_health` | owned by `compute_enumeration_obligations`, calls at `:765`, `:788`, `:804` |
| 6 | `enumeration.coreference_obligation` | RG / `POST_DISCOVERY` | `scripts/enumeration_gate.py:756 compute_enumeration_obligations` | dispatcher `scripts/enumeration_gate.py:4330`; driver wrapper `scripts/plamen_driver.py:17882` |
| 7 | `enumeration.coreference_gap` | RG / `POST_DISCOVERY` | `scripts/enumeration_gate.py:1344 validate_enumeration_coverage` | dispatcher `scripts/enumeration_gate.py:4335` |
| 8 | `enumeration.critical_asset_mover` | RG / `POST_DISCOVERY` | `scripts/enumeration_gate.py:1881 compute_critical_asset_mover_candidates` | `run_enumeration_gate`, `scripts/enumeration_gate.py:4339+` |
| 9 | `enumeration.array_uniqueness` | RG / `POST_DISCOVERY` | `scripts/enumeration_gate.py:2006 compute_array_uniqueness_candidates` | `run_enumeration_gate`, `scripts/enumeration_gate.py:4339+` |
| 10 | `enumeration.unbounded_stored_input` | RG / `POST_DISCOVERY` | `scripts/enumeration_gate.py:2094 compute_unbounded_input_candidates` | `run_enumeration_gate`, `scripts/enumeration_gate.py:4339+` |
| 11 | `enumeration.variant_boundary` | RG / `POST_DISCOVERY` | `scripts/enumeration_gate.py:2312 compute_boundary_input_candidates` | `compute_variant_gaps` call `scripts/enumeration_gate.py:2779`; driver `scripts/plamen_driver.py:17510` |
| 12 | `enumeration.variant_symmetric` | RG / `POST_DISCOVERY` | `scripts/enumeration_gate.py:2645 compute_symmetric_operation_candidates` | `compute_variant_gaps` call `scripts/enumeration_gate.py:2795` |
| 13 | `enumeration.committed_invariant` | RG / `POST_DISCOVERY` | `scripts/enumeration_gate.py:2868 compute_invariant_assertion_candidates`, `:2969 recover_invariant_assertion_candidates` | dispatcher `scripts/enumeration_gate.py:4364` |
| 14 | `axis.hot_function_gap_matrix` | RG / `POST_DISCOVERY` | `scripts/enumeration_gate.py:3576 compute_axis_coverage_gaps` | `scripts/plamen_driver.py:37571` |
| 15 | `enumgap.exploration_delivery` | PI / `POST_DISCOVERY` | `scripts/enumeration_gate.py:4222 promote_enumgap_exploration_to_inventory` | `scripts/plamen_driver.py:41668` |
| 16 | `axis.finding_delivery` | PI / `POST_DISCOVERY` | `scripts/enumeration_gate.py:3753 promote_axis_findings_to_inventory` | `scripts/plamen_driver.py:41694` |
| 17 | `promotion.orphan_reopen` | RG / `POST_DISCOVERY` | `scripts/plamen_mechanical.py:5842 compute_promotion_orphans`, `:6257 route_promotion_orphans` | armed adapter `scripts/plamen_driver.py:18196`; SC/L1 calls `:46143`, `:46330` |
| 18 | `inventory.location_exists` | PD / `PRE_VERIFY` | branch inside `scripts/plamen_validators.py:20600 _validate_inventory_evidence` | driver calls `scripts/plamen_driver.py:42589`, `:45692`, `:45726`, `:45762`, `:46360`, `:46619` |
| 19 | `inventory.production_scope` | PD / `PRE_VERIFY` | independently fireable branch inside `_validate_inventory_evidence` | same driver sites as row 18 |
| 20 | `inventory.identifier_exists` | PD / `PRE_VERIFY` | independently fireable branch inside `_validate_inventory_evidence` | same driver sites as row 18 |
| 21 | `poc.force_by_default` | PI / `PRE_VERIFY` | `scripts/plamen_validators.py:27556 _validate_poc_contract_for_rows` | pre-receipt call `scripts/plamen_validators.py:5228` |
| 22 | `mechanical_poc.execute` | PI / `POST_VERIFY` | `scripts/mechanical_verify.py:2094 run_phase5b_mechanical_verify` | late route `scripts/plamen_driver.py:22114`; ordinary route `:48185` |
| 23 | `verdict.evidence_integrity` | PD / `POST_VERIFY` | `scripts/mechanical_verify.py:1796 _classify_integrity` | verdict-manifest call `scripts/mechanical_verify.py:1911`; manifest chain `:1495`, `:1596` |
| 24 | `external_assumption.assert_cap` | PD / `POST_VERIFY` | `scripts/plamen_validators.py:22705 _external_assumption_cap_applies` | severity-map decision `scripts/plamen_validators.py:23179`; driver consumers include `scripts/plamen_driver.py:17154`, `:47076` |
| 25 | `external_assumption.demotion_veto` | PD / `POST_VERIFY` | `scripts/plamen_validators.py:28944 _apply_external_assumption_undemotions` | `scripts/plamen_driver.py:41415` |
| 26 | `severity.independent_challenge` | PD / `POST_VERIFY` | `scripts/plamen_validators.py:28606 _apply_independent_severity_caps` | `scripts/plamen_driver.py:40134`, `:40152`, `:41393` |
| 27 | `external_research.citation_gap` | TEL / `REPORT_ASSEMBLY` | `scripts/plamen_driver.py:18441 _check_external_research_citation_gaps` | `scripts/plamen_driver.py:47185` |
| 28 | `postverify.late_candidate_reopen` | RG / `POST_VERIFY` | `scripts/post_verify_lifecycle.py:71 promote_post_verify_candidates` | adapter `scripts/plamen_driver.py:22015`, decision call `:22035`, phase call `:42066` |
| 29 | `report.index_retention_reconcile` | PI / `REPORT_ASSEMBLY` | `scripts/plamen_mechanical.py:11132 _write_mechanical_report_index` | `scripts/plamen_driver.py:47339` |
| 30 | `report.dedup_lossless_consolidation` | PI / `REPORT_ASSEMBLY` | `scripts/plamen_mechanical.py:6689 _dedup_report_python`, `:4231 _dedup_data_loss_gate` | `scripts/plamen_driver.py:48444` |
| 31 | `report.typed_disposition` | PD / `REPORT_ASSEMBLY` | `scripts/report_disposition_authority.py:528 build_report_disposition_authority`, `:1288 reconcile_report_dispositions` | driver adapter `scripts/plamen_driver.py:40239`; live call `:48555` |
| 32 | `report.mandatory_reverification` | PI / `REPORT_ASSEMBLY` | denominator/routing/reconciliation in `scripts/mandatory_reverification.py:203`, `:339`, `:719`, `:1052` | driver adapter `scripts/plamen_driver.py:12246`; live call `:48587` |
| 33 | `report.integrity_no_ship` | PI / `REPORT_ASSEMBLY` | `scripts/plamen_driver.py:19694 _commit_report_integrity_no_ship`; clearance in `_commit_report_phase_success` | live failure/clearance sites at `scripts/plamen_driver.py:48399`, `:48658`, `:48704`, `:48720`, `:48745`, `:51522`, `:51546` |

### 5.1 Exact seam-count baseline

The initial seam denominator is:

| Seam | Baseline live gate IDs | Count |
|---|---|---:|
| `STARTUP_RESUME` | rows 1, 3, 4 | 3 |
| `PRE_DISCOVERY` | none | 0 |
| `POST_DISCOVERY` | rows 5-17 | 13 |
| `PRE_VERIFY` | rows 18-21 | 4 |
| `POST_VERIFY` | rows 2, 22-26, 28 | 7 |
| `REPORT_ASSEMBLY` | rows 27, 29-33 | 6 |
| **Total** | all live rows | **33** |

These are measured baseline counts, not approved ceilings. Each initial
`seam_budgets` row must use:

```json
{
  "approval_status": "UNAPPROVED_BASELINE",
  "gate_budget_ceiling": null,
  "approval_revision": null,
  "approver": null,
  "baseline_gate_ids": ["...exact IDs for this seam..."],
  "addition_gate_ids": [],
  "release_gate_ids": [],
  "active_gate_count": 0,
  "activated_or_shadow_additions": 0,
  "approved_slot_releases": 0,
  "post_change_gate_count": 0,
  "exception": null
}
```

The four numeric count fields are populated from the exact sets: for each seam,
`active_gate_count` and `post_change_gate_count` equal the table count; additions
and releases are zero. `gate_budget_ceiling` remains null until a human system
owner approves it in a separate prior revision. While any ceiling is null or
unapproved, all new `SHADOW`, `REPLAY`, or `ACTIVE` transitions are blocked.

## 6. Dead, superseded, and stale behavior

Add non-runtime tombstones to `gate_records`; they do not enter any seam count:

| Tombstone gate ID | State | Required cleanup |
|---|---|---|
| `verdict.integrity_markdown_flip` | `SUNSET` | `scripts/mechanical_verify.py:1878 flip_verdict_on_integrity_downgrade` has no production caller. Remove it and its export at `:2339`, or retain only until tests migrate. Correct `docs/internals.md` and `docs/glossary.md`, which claim the flip is live. |
| `report.material_harm_floor_legacy` | `CONSOLIDATED` | The live final-report authority is typed report disposition. Remove stale final-path claims from `docs/internals.md`; retain code only if a separately inventoried live caller exists. |
| `promotion.orphan_appendix_route_legacy` | `SUNSET` | `_promo_disposition` currently routes active typed cases to `BODY`; historic Appendix A/C branches are unreachable. Remove stale logs/docs and the unreachable branches after characterization fixtures. |

Also:

- preserve `severity.independent_challenge` as challenge/routing only; remove
  prose calling it an automatic “M4 minimum cap”;
- correct all docs saying Gate V still executes co-reference axis 1. G1/G2 own
  axis 1; `compute_variant_gaps` owns boundary and symmetric axes only;
- correct `run_enumeration_gate`’s stated budget from `40 + 3*15` to
  `40 + 4*15 = 100`; the separately invoked two Gate-V pools add 30, making
  the accepted-depth maximum 130 before axis work;
- either remove the unused `_run_gate_p_for_report_index` at
  `scripts/plamen_driver.py:18327` or mark it non-production so the AST
  inventory cannot count it; and
- replace the Part-0-violating commentary at
  `scripts/plamen_validators.py:27155-27158` with generic language such as
  “a prior material-harm under-match” and “custodied asset.”

No tombstone can be reactivated by deleting it. Reactivation requires a new
review, new activation inventory, a gate-budget slot, and current evidence.

## 7. Files and symbols to add or change

### 7.1 New canonical files

1. `rules/mechanical-gate-registry.schema.v2.json`
   - JSON Schema 2020-12;
   - `additionalProperties: false` on every object;
   - closed enums, integer bounds, string patterns, and conditional requirements.

2. `rules/mechanical-gate-registry.json`
   - replace v1 with the populated v2 canonical registry;
   - 33 legacy-live records plus the three tombstones.

3. `rules/mechanical-gate-activation-baseline.v1.json`
   - generated artifact, never hand-edited;
   - canonical wrapper inventory, current source lines as non-authoritative
     evidence, selectors, and code digests.

4. `scripts/mechanical_gate_registry.py`
   - `MechanicalGateRegistryError`;
   - `GateRecord`, `GateActivation`, `SeamBudget`, and
     `MechanicalGateRegistry` frozen dataclasses;
   - `strict_json_loads`;
   - `load_mechanical_gate_registry`;
   - `validate_mechanical_gate_registry`;
   - `mechanical_gate_registry_digest`;
   - `validate_part0_metadata`;
   - `validate_seam_budget_equations`;
   - `resolve_gate_record`.

5. `scripts/mechanical_gate_runtime.py`
   - `GateRuntimeError`;
   - `GateEvaluationContext`, `GateEvaluationResult`, `GateExecutionReceipt`;
   - `evaluate_registered_gate`;
   - `record_registered_gate`;
   - `arm_registered_gate_transaction`;
   - `commit_registered_gate_transaction`;
   - `quarantine_registered_gate_transaction`;
   - `effective_runtime_state`;
   - `compute_gate_evaluation_id`;
   - `consolidate_gate_execution_ledger`.

6. `scripts/mechanical_gate_inventory.py`
   - `ActivationInventoryError`;
   - `discover_literal_activations`;
   - `compute_decision_code_digest`;
   - `build_activation_inventory`;
   - `validate_activation_parity`;
   - `validate_no_direct_call_bypass`;
   - CLI modes `--check` and `--write-baseline`.

7. `scripts/mechanical_gate_neutral_evaluation.py`
   - consumes only evaluator-issued held-out result bundles;
   - `load_neutral_gate_evaluation`;
   - `validate_neutral_evaluator_independence`;
   - `compute_false_fire_measurement`;
   - `validate_false_fire_budget`;
   - never reads audit ground truth in the audit runtime and never allows a
     gate to self-certify.

Add all new runtime modules as literal `!scripts/<name>.py` exceptions in
`.gitignore`; `scripts/test_python_packaging_contracts.py` then ratchets their
visibility.

### 7.2 Existing integration symbols

- `rules/post-audit-improvement-protocol.md`
  - add decision classes;
  - correct count-set math;
  - replace universal M1-M4 with class-specific admission;
  - add `LEGACY_ACTIVE_UNGOVERNED` and expiry behavior.

- `scripts/phase_io_contracts.py`
  - extend `PhaseIOContract` with explicit output-prestate bindings in v2;
  - add `OutputPrestateSpec`;
  - add `resolve_registered_gate_phase_io_contract`;
  - export both new symbols through `__all__`.

- `scripts/artifact_ledger.py`
  - use the existing `record_work_unit_inputs`,
    `validate_work_unit_inputs`, `record_work_unit_artifacts`,
    `arm_semantic_mutation`, and `finalize_semantic_mutation`;
  - add one shared `commit_staged_work_unit_artifacts` CAS primitive rather than
    a gate-only post-hoc commit;
  - add `quarantine_staged_work_unit_artifacts`;
  - make output-prestate, exact input bytes, file-set, run ID, contract digest,
    and registry digest part of the terminal commit authority.

- `scripts/plamen_driver.py`
  - import the loader/runtime;
  - in `main` at `:44910`, load and validate the installed registry after config
    parsing but before folder-trust mutation, ecosystem probing, snapshot
    activation, target tooling, or model launch;
  - write a startup governance-failure receipt after the scratchpad path is
    known and stop before runtime work if the canonical registry is missing,
    malformed, digest-mismatched, or structurally invalid;
  - replace gate calls listed in section 5 with literal wrappers;
  - use the literal registry gate ID in `_commit_report_integrity_no_ship`
    instead of `f"{phase.name}.report_integrity.no_ship"`.

- `scripts/enumeration_gate.py`
  - replace the dynamic deriver loop in `run_enumeration_gate` with explicit
    literal wrapper calls for rows 8-10;
  - wrap rows 5-13 at their independently fireable decision boundaries;
  - repair false-clean behavior in axis graph absence/provider failure and in
    symmetric nonempty-input/zero-parse cases;
  - correct budget comments and docs.

- `scripts/plamen_validators.py`
  - extract `_gate_inventory_location_exists`,
    `_gate_inventory_production_scope`, and
    `_gate_inventory_identifier_exists` from `_validate_inventory_evidence`;
  - extract the force-by-default decision from
    `_validate_poc_contract_for_rows`;
  - wrap the external-assumption and independent-severity decisions;
  - remove the Part-0-specific comments.

- `scripts/mechanical_verify.py`, `scripts/plamen_mechanical.py`,
  `scripts/post_verify_lifecycle.py`, `scripts/report_disposition_authority.py`,
  and `scripts/mandatory_reverification.py`
  - expose a pure or staged implementation symbol for each row;
  - keep canonical mutation inside the common gate transaction;
  - remove or tombstone dead behavior described in section 6.

- `docs/internals.md`, `docs/glossary.md`, `docs/architecture.md`,
  `docs/repository-structure.md`, and `docs/dependencies.md`
  - document v2 authority, receipts, and install layout;
  - remove stale line-number and live-behavior claims.

### 7.3 Packaging

Claude installation already includes `rules/*.json` and the whole `scripts`
tree in `_run_symlink_install` (`plamen.py:2647+`); Codex installation links or
copies the repository tree. Acceptance still requires explicit regressions:

- the v2 registry, schema, baseline manifest, and all new modules exist after a
  clean Claude install;
- the same files exist after Codex link and Windows copy fallback;
- a source archive install includes them;
- clean checkout/import does not rely on untracked files;
- uninstall/reinstall remains idempotent; and
- the driver resolves registry paths from `plamen_home()`, never the process
  working directory or target repository.

## 8. Strict v2 schema

### 8.1 Closed top-level keys

The canonical object has exactly:

```json
{
  "schema_version": "plamen.mechanical_gate_registry.v2",
  "registry_revision": 1,
  "registry_scope": {},
  "migration_status": "BASELINING_EXISTING_ACTIVATIONS",
  "migration": {},
  "activation_inventory": {},
  "seam_taxonomy": [],
  "decision_class_taxonomy": [],
  "direction_taxonomy": [],
  "seam_budgets": [],
  "gate_records": []
}
```

No extensions bag is allowed. A schema change increments the schema version and
reopens review.

`registry_scope` has exactly:

- `scope_version`;
- `included_authorities` containing the eight frozen authorities in section
  4.1;
- `excluded_control_families` containing section 4.2;
- `production_roots`, initially `["scripts"]`;
- `production_excludes`, initially test files, `conftest.py`, and explicitly
  named dev-only tools; and
- `scope_review_receipt_sha256`.

`migration` has exactly:

- `source_tree_digest`;
- `source_tree_digest_algorithm`;
- `baseline_gate_ids`;
- `baseline_live_gate_count`;
- `baseline_review_status`;
- `baseline_reviewer`;
- `baseline_reviewed_at`;
- `baseline_review_receipt_sha256`; and
- `new_runtime_transitions_blocked`.

Unknown, missing, empty-placeholder, or wrongly typed values are errors. The
legacy migration state may use null for reviewer/receipt fields; an enforced
state may not.

### 8.2 Closed gate record

Every gate record has exactly:

```text
gate_id
display_name
lifecycle_state
decision_class
admission
owning_seam
execution_order
activations
purpose
authority
input_contracts
output_contracts
failure_contract
runtime_budget
release_evidence
false_fire_budget
overlap_and_consolidation
ownership
review_and_sunset
part0
```

Stable IDs match `^[a-z][a-z0-9]*(?:[._][a-z0-9]+)+$`. IDs compare
case-sensitively after NFC normalization; two values that collide after
case-folding are rejected for cross-OS safety.

Lifecycle states are:

```text
PROPOSED
FIXTURED
SHADOW
REPLAY
LEGACY_ACTIVE_UNGOVERNED
ACTIVE
EXPIRED_BLOCKED
CONSOLIDATED
SUNSET
```

Runtime-counted states are `SHADOW`, `REPLAY`,
`LEGACY_ACTIVE_UNGOVERNED`, and `ACTIVE`. `EXPIRED_BLOCKED`,
`CONSOLIDATED`, and `SUNSET` never execute the predicate.

Allowed transitions:

```text
PROPOSED -> FIXTURED -> SHADOW|REPLAY -> ACTIVE
LEGACY_ACTIVE_UNGOVERNED -> SHADOW|REPLAY -> ACTIVE
ACTIVE|SHADOW|REPLAY -> EXPIRED_BLOCKED
ACTIVE|SHADOW|REPLAY|LEGACY_ACTIVE_UNGOVERNED -> CONSOLIDATED|SUNSET
EXPIRED_BLOCKED -> PROPOSED
```

A predicate, schema, selector, authority, join rule, or decision-code digest
change reopens at `PROPOSED` or `SHADOW`, as declared by policy; it cannot remain
silently `ACTIVE`.

### 8.3 Activation record

Every activation has exactly:

```text
activation_id
module
wrapper_symbol
implementation_symbols
hook_id
phases
pipelines
modes
ecosystems
backends
runtime_state
code_digest_algorithm
code_digest
```

Line numbers do not appear in the registry. They appear only in the generated
activation inventory. Selectors are nonempty sorted unique arrays drawn from
closed taxonomies. Inapplicable product cells emit an explicit `NOT_APPLICABLE`
receipt; absence of a receipt is not N/A.

`code_digest_algorithm` is
`sha256:plamen-python-decision-closure-ast-v1`. Its canonical input is:

1. the literal wrapper call AST;
2. every declared implementation symbol AST;
3. the transitive repository-local functions, classes, and module constants
   referenced by those symbols;
4. normalized module path and qualified symbol name; and
5. no source locations or comments.

Dynamic local dispatch that prevents construction of this closure is rejected,
or conservatively binds the complete module-byte digest and reopens review on
any module change.

### 8.4 Authority, input, and output contracts

`authority` has closed booleans:

```text
can_add
can_remove
can_lower_severity
can_raise_severity
can_block_execution
can_execute_target
can_clear_debt
can_veto_ship
```

It also requires `direction`, `subject_identity_schema`, `join_rule`,
`monotonicity_claim`, and `invalid_authority_fallback`.

The direction taxonomy is:

```text
GENERATE_ADD_ONLY
REOPEN_ADD_ONLY
RECONCILE_LOSSLESS
CAP_DESTRUCTIVE
FLOOR_RECALL_OPEN
FLAG_TELEMETRY
ROUTE_RECALL_OPEN
CONSOLIDATE_LOSSLESS
BLOCK_EXECUTION
EXECUTE_TARGET
VETO_SHIP
```

Each input contract contains artifact identity/root, schema version,
authoritative producer, `EXACT|BOUNDED_LOOKUP|OPTIONAL_CAPABILITY` role, subject
identity and join rule, freshness rule, and absent/malformed behavior.

Each output contract contains artifact identity/root, schema version, PhaseIO
work-unit ID, writer, write mode, consumers, conditional state if any, and
authority carried. Every runtime record includes the common typed receipt,
governance debt output, and overflow backlog as conditional outputs.

### 8.5 Loader behavior

`strict_json_loads` must:

- read strict UTF-8 with no replacement and no BOM;
- reject duplicate object keys with `object_pairs_hook`;
- reject `NaN`, `Infinity`, and `-Infinity` with `parse_constant`;
- reject floats entirely; budgets and counts are integers;
- reject input larger than 8 MiB;
- reject non-regular files, symlinks/reparse points, path escape, or a registry
  outside the installed Plamen root; and
- canonicalize only after validation with sorted keys, UTF-8, LF, no NaN, and
  compact separators for the registry digest.

JSON Schema validation is necessary but not sufficient. The Python semantic
validator also enforces uniqueness, selector closure, class/authority
compatibility, lifecycle transitions, owner/reviewer independence, expiry,
Part 0, activation parity, baseline digest, count equations, output PhaseIO
coverage, and cross-record relationships.

## 9. Literal wrappers, baseline manifest, and AST ratchet

### 9.1 Wrapper contract

Every governed activation must contain both IDs as source literals:

```python
result = evaluate_registered_gate(
    "enumeration.variant_boundary",
    activation_id="enumeration.variant_boundary.accepted_depth",
    context=context,
    evaluator=_compute_boundary_input_candidates_impl,
)
```

For already-computed deterministic outcomes:

```python
result = record_registered_gate(
    "external_research.citation_gap",
    activation_id="external_research.citation_gap.report_index",
    context=context,
    result=result,
)
```

The gate ID and activation ID may not be variables, f-strings, concatenations,
format calls, constants imported from another module, or values read from the
registry. The wrapper validates the literal against the loaded registry.

Public production entry points should become registered wrappers around private
implementation symbols. Tests may call private pure functions. Production may
not bypass wrappers.

The inventory deriver loop at `scripts/enumeration_gate.py:4339+` must be
expanded to three explicit calls because a `(function, producer)` loop cannot
carry AST-verifiable literal decision identities without hiding independently
fireable predicates.

### 9.2 Generated activation inventory

`build_activation_inventory` walks only the frozen production roots/exclusions
and emits sorted records containing:

- gate and activation IDs;
- module, wrapper symbol, implementation symbols, and hook ID;
- current source line as non-authoritative evidence;
- pipeline, mode, ecosystem, backend, and phase selectors;
- lifecycle/runtime state;
- decision-closure code digest;
- source-tree digest; and
- generator version/digest.

The canonical registry cites the manifest path, SHA-256, source-tree digest,
generator digest, and independent review receipt. A dirty first baseline uses
a deterministic tree digest over normalized relative path, mode, size, and
file SHA-256; a Git commit alone is insufficient.

### 9.3 `validate_activation_parity`

The AST check fails on:

- literal production activation missing from the registry;
- runtime-counted registry activation missing from production;
- duplicate gate or activation ID;
- direct production call to a registered implementation symbol outside its
  named wrapper;
- dynamic gate or activation ID;
- alias, star-import, `getattr`, callback table, or reflection bypass for a
  registered decision symbol;
- wrapper/implementation symbol rename or move;
- decision-code digest drift without reopened review;
- phase, pipeline, mode, ecosystem, or backend selector drift;
- two independently fireable decisions hidden behind one wrapper;
- dead/unreachable functions counted live;
- runtime `ACTIVE`/`SHADOW`/`REPLAY` with missing owner or independent review;
- runtime-expired activation;
- output missing PhaseIO registration;
- Part-0-prohibited metadata; or
- baseline, addition, release, ceiling, or total equation mismatch.

The linter resolves imports and qualified calls. Text grep is not an authority
check.

## 10. PhaseIO-bound runtime execution

### 10.1 Receipt and storage layout

Do not use a shared append-only JSONL file as the primary authority under
concurrency. Write one immutable receipt per evaluation:

```text
scratchpad/_mechanical_gates/
  receipts/<run_id>/<gate_id>/<evaluation_id>.json
  overflow/<gate_id>/<evaluation_id>.json
  quarantine/<gate_id>/<evaluation_id>/
  governance_debt/<gate_id>/<evaluation_id>.json
  gate_execution_ledger.json
  gate_execution_ledger.md
```

`evaluation_id` is a resume-stable SHA-256 over registry digest, run ID, gate
ID, activation ID, input-set digest, exact product selector, and shard ID. A
replay with identical inputs must reuse and validate the byte-identical receipt,
not fire twice.

The consolidated JSON ledger is driver-owned and rebuilt from immutable receipt
files under a lock/CAS transaction. The Markdown file is bounded projection
only.

### 10.2 Receipt schema

Each `plamen.mechanical_gate_execution.v1` receipt contains:

- registry schema/revision/digest;
- activation-manifest digest;
- gate, activation, hook, and evaluation IDs;
- run ID and product selector;
- effective lifecycle/runtime state and expiry;
- exact input identities, bytes, and SHA-256 values;
- PhaseIO contract and input-set digests;
- output-prestate identities/existence/digests;
- denominator kind and all counts from section 11;
- fired subject IDs or a digest-bound sidecar when too large;
- cost counters;
- output identities, digests, and commit authority;
- overflow/backlog identities and digest;
- failure/unknown/debt rows;
- transaction state; and
- receipt digest.

Runtime receipts may report firing rate. They must not contain or claim
`false_fire_count`, `false_fire_rate`, or held-out PASS; those belong only to a
neutral evaluator receipt.

### 10.3 Transaction

`evaluate_registered_gate` executes:

1. resolve the validated registry record and effective state;
2. resolve `PhaseIOContract` through
   `resolve_registered_gate_phase_io_contract`;
3. bind exact inputs and output prestates;
4. persist the arm before the evaluator can write canonical bytes;
5. evaluate into a unique staging directory;
6. enforce count/cost budgets and create overflow/UNKNOWN debt;
7. acquire the shared artifact transaction lock;
8. rehash exact inputs, file set, registry/contract digests, and output
   prestates;
9. atomically replace canonical outputs or quarantine all staged bytes;
10. call the shared artifact-ledger terminal commit;
11. publish the immutable execution receipt; and
12. reconcile downstream invalidation/checkpoint state.

Canonical read-modify-write outputs such as `findings_inventory.md` and
`AUDIT_REPORT.md` require explicit output-prestate binding. They may not be
smuggled into `immutable_inputs`; current `PhaseIOContract` correctly rejects
input/output overlap without an explicit transaction.

Crash recovery has typed states:

```text
UNARMED
INPUTS_BOUND_PREEXECUTION
OUTPUTS_STAGED
OUTPUT_COMMITTED
OUTPUT_QUARANTINED
OUTPUT_SUPERSEDED
```

Only `OUTPUT_COMMITTED` grants downstream authority. Orphan staged output and
an arm without a terminal receipt become visible recovery debt.

## 11. Exact denominator, budget, overflow, and UNKNOWN semantics

### 11.1 Count vocabulary

For every applicable evaluation:

```text
raw_input_row_count =
    unique_subject_count + duplicate_row_count + invalid_row_count

unique_subject_count =
    inapplicable_subject_count + eligible_subject_count

eligible_subject_count =
    evaluated_subject_count + overflow_subject_count

evaluated_subject_count =
    fired_count + no_fire_count + unknown_count
```

All terms are non-negative integers and every displayed equation must balance
exactly.

Definitions:

- `raw_input_row_count`: physical rows read from the declared authoritative
  denominator.
- `duplicate_row_count`: rows whose normalized exact subject identity was
  already counted. Duplicates never enlarge a gate budget.
- `invalid_row_count`: physical rows that cannot yield a valid subject identity.
  They create debt and never count as no-fire.
- `unique_subject_count`: distinct valid identities before applicability.
- `inapplicable_subject_count`: valid identities outside the record’s typed
  predicate domain.
- `eligible_subject_count`: valid applicable identities.
- `evaluated_subject_count`: eligible identities for which the predicate
  reached a terminal fire/no-fire/unknown result.
- `overflow_subject_count`: eligible identities deferred by a count, byte,
  wall-clock, process, worker, or token limit.
- `fired_count`: predicate true with a typed output/effect or staged shadow
  decision.
- `no_fire_count`: predicate deterministically false on complete, fresh,
  non-contradictory evidence.
- `unknown_count`: evaluated identity lacking authority for fire or no-fire.

For an exact denominator, all equations must balance and every overflow
identity is stored. For a lower-bound denominator, the receipt records
`denominator_kind=LOWER_BOUND`, the observed minimum, why exact enumeration was
impossible, and samples/digests. A lower-bound evaluation cannot produce a
coverage-complete or universal no-fire claim.

Legitimate empty exact denominators use:

```text
denominator_kind=EXACT
raw_input_row_count=0
unique_subject_count=0
eligible_subject_count=0
empty_reason=<closed typed reason>
```

Provider absence, parse failure, stale input, or nonempty evidence parsed to
zero is not a legitimate empty denominator.

### 11.2 Runtime budgets

Every record declares integer maxima or an explicitly permitted null during
legacy observation for:

- input bytes;
- input files;
- raw denominator rows;
- unique and eligible subjects;
- retained/fired rows;
- emitted candidates;
- wall-clock milliseconds;
- external process count;
- worker count; and
- token count.

It also declares whether the denominator must be exact, the stable shard
ordering, and overflow action.

Initial legacy records first observe actual values without changing behavior.
Observed maxima are not automatically adopted as policy. Human-approved limits
enter a prior reviewed registry revision, then enforcement is enabled.

The current known constants become observed/declared starting evidence:

- co-reference: five variables per finding, six co-referencers per variable,
  common-symbol threshold over 25, 40 emissions;
- each of four in-dispatcher additional derivers: 15;
- each of two Gate-V derivers: 15;
- axis matrix: 40 hot functions by six axes, maximum 240 cells;
- promotion: 60 feeder files, 12 eligible rows per feeder, 30 per run, 64 MiB
  per feeder;
- mechanical verification: 180-second test timeout, 3x Go-race multiplier,
  5,400-second prewarm, 1,800-second loop budget, practical existing bound at
  least 7,740 seconds.

These values are not silently normalized into one seam ceiling.

### 11.3 Stable overflow

When exact enumeration is possible:

1. normalize and sort exact subject IDs by UTF-8 byte order;
2. resume previously persisted backlog identities first;
3. take the bounded prefix;
4. persist every omitted identity, source digest, reason, and next eligible
   shard;
5. emit `UNKNOWN_OVERFLOW` for the remainder; and
6. project unresolved overflow into assurance limitations.

Adding a new subject may not reshuffle already persisted backlog ordering.
Resume uses the bound backlog, not a newly sampled set.

If the source cannot be enumerated exactly, persist a lower bound and samples.
Timeout during one subject yields `UNKNOWN_TIMEOUT` for that subject and
`UNKNOWN_REMAINDER` for unstarted work. A final test may not silently overrun
the declared phase wall; the executor either receives the remaining timeout or
the row is deferred.

### 11.4 UNKNOWN is authority-bearing debt

Use closed reason codes:

```text
UNKNOWN_INPUT_ABSENT
UNKNOWN_INPUT_MALFORMED
UNKNOWN_INPUT_STALE
UNKNOWN_INPUT_SPLIT
UNKNOWN_INPUT_DUPLICATE_CONFLICT
UNKNOWN_INPUT_CONTRADICTORY
UNKNOWN_PROVIDER_FAILED
UNKNOWN_TIMEOUT
UNKNOWN_OVERFLOW
UNKNOWN_REMAINDER
UNKNOWN_RECEIPT_WRITE
UNKNOWN_INPUT_MUTATED
UNKNOWN_PARTIAL_MUTATION
UNKNOWN_REGISTRY_AUTHORITY
UNKNOWN_EXPIRED
```

An UNKNOWN row:

- is never counted as no-fire;
- cannot clear an obligation, finding, debt, or no-ship state;
- is delivered to a typed backlog or human-review route;
- appears in the gate ledger and final assurance projection; and
- remains open across resume until the same exact identity has a committed
  terminal result or authorized explicit disposition.

Repair the two known false-clean paths accordingly:

- `compute_axis_coverage_gaps` must not return clean `[]` for absent graph,
  failed ranking, or broad exception; and
- nonempty `chain_candidate_pairs.md` parsed to zero symmetric pairs must be
  `UNKNOWN_INPUT_MALFORMED` or typed provider drift, not clean zero.

## 12. Failure and recall-open behavior

The closed per-condition actions are:

```text
HARD_STOP_BEFORE_SIDE_EFFECT
BLOCK_TARGET_EXECUTION
RETAIN_UPSTREAM_AND_FLAG
GENERATE_ADD_ONLY_WITH_DEBT
SHADOW_ONLY_WITH_DEBT
QUARANTINE_AND_RETRY
UNKNOWN_DEBT_CONTINUE
NOT_APPLICABLE
```

Every gate record maps absent, malformed, stale, split, duplicate,
contradictory, provider failure, timeout, budget overflow, receipt failure,
input mutation, and partial-resume conditions to one action.

Global rules:

- missing/malformed canonical registry or manifest digest mismatch hard-stops
  startup before target execution or model launch and writes explicit startup
  governance debt once the scratchpad is known;
- an unknown new activation is non-runtime and fails CI/static lint;
- a destructive or precision gate without valid authority preserves upstream
  severity/disposition/evidence and flags review;
- a lossless consolidation failure retains the original;
- an execution-safety gate failure blocks target execution;
- a ship-integrity failure preserves no-ship;
- an add-only legacy gate may continue only in
  `LEGACY_ACTIVE_UNGOVERNED`, with governance debt and normal downstream
  verification;
- an expired non-legacy gate becomes `EXPIRED_BLOCKED`; it does not execute;
  its absence is visible assurance debt, never a clean no-fire; and
- output or receipt-write failure quarantines staged bytes. Unreceipted
  canonical mutation never gains authority.

## 13. False-fire measurement

Runtime cannot know whether a fire is false. Only a neutral evaluator using a
digest-bound held-out corpus and independent adjudicated outcomes may issue a
`plamen.mechanical_gate_false_fire_evaluation.v1` receipt.

Exact metrics:

```text
adjudicated_fire_count = true_fire_count + false_fire_count
false_fire_rate = false_fire_count / adjudicated_fire_count
```

If `adjudicated_fire_count == 0`, the rate is `UNKNOWN`, not zero. A budget
passes only when:

- corpus ID and digest match the record;
- evaluator build/comparator digests match;
- the evaluator principal is independent of the implementer and gate runtime;
- the observation window matches;
- minimum adjudicated denominator is met;
- every sampled fire required by the evaluation plan is adjudicated;
- both maximum count and maximum rate pass; and
- recall, found-then-lost retention, fragmentation, severity delta, cost, and
  wall-clock are also reported.

The motivating audit is regression-only. It cannot be the sole held-out
evidence. Ground-truth identities and answers do not enter the registry,
activation manifest, runtime receipt, prompt, config, or audit scratchpad.

Budget breach:

- destructive/precision gate: effective state becomes shadow; preserve upstream
  authority and open review;
- add-only generator: retain bounded independent verification and durable
  overflow rather than silently disabling recall;
- telemetry: retain measurement but mark the policy breach;
- permanent disable, narrowing, consolidation, or slot release requires
  independent recall evidence and owner approval.

Initial legacy records use:

```text
false_fire_budget.status = "UNESTABLISHED"
held_out_corpus_id = null
held_out_corpus_sha256 = null
minimum_adjudicated_denominator = null
maximum_false_fire_count = null
maximum_false_fire_rate = null
current_evidence_receipt_sha256 = null
```

They are not falsely PASS.

## 14. Ownership, review, exceptions, and expiry

`ownership` has:

- `component_owner`;
- `system_owner`;
- `implementer`;
- `independent_reviewer`; and
- `assignment_status`.

For initial legacy rows, identities are null and
`assignment_status=UNASSIGNED_MIGRATION_DEBT`. Do not infer identities from Git
history.

For new `SHADOW`, `REPLAY`, or `ACTIVE` transitions:

- component and system owner are nonempty stable principal IDs;
- implementer and independent reviewer are nonempty and different;
- the reviewer attests registry record, code digest, fixtures, PhaseIO
  contract, Part 0, and evidence;
- review date and digest are present; and
- a reviewer cannot approve a seam ceiling in the same proposal that spends
  it.

An exception has exactly:

```text
exception_approver
temporary_ceiling_delta
exception_rationale_code
held_out_evidence_receipt_sha256
review_by
expires_on
```

`review_by` and `expires_on` are distinct UTC instants, with `review_by` earlier
than `expires_on`. At expiry the effective state becomes `EXPIRED_BLOCKED` and
the ordinary seam ceiling must balance. Renewal is a new independently reviewed
decision and cannot rely only on the original motivating evidence.

## 15. Overlap and consolidation

Each record names `overlapping_gate_ids`, `shared_contract_ids`,
`unique_authority`, `consolidation_status`, `retirement_criteria`, and
`recall_parity_receipt_sha256`.

Required relationships:

- G1 obligation and G2 gap remain separate; boundary and symmetric variants
  remain separate; no recursive Gate-V axis-1 activation is allowed.
- Promotion-orphan recovery overlaps the typed producer/lifecycle/report
  machinery but retains unique legacy-Markdown coverage until evidence proves
  otherwise. Add typed attribution for recoveries unavailable from structured
  lifecycle paths before considering retirement.
- Citation-gap telemetry, assert-side cap, and demotion veto remain three
  records.
- Force-by-default, mechanical execution, and evidence-integrity classification
  remain three records.
- Inventory location, production scope, and identifier existence remain three
  records even after extraction from one validator.

A slot release is valid only when:

1. replacement subsumption is mechanically specified;
2. independent held-out replay shows recall parity;
3. the retired gate has zero unique true-positive contribution in the declared
   window; and
4. an independent reviewer and system owner approve the release.

Otherwise `approved_slot_releases=0`, unless the system owner records an
explicit measured recall tradeoff.

## 16. Migration and staged rollout

### Stage 0 - prerequisite and freeze

- Finish and independently accept P0-AE/P0-AC commit-CAS/output-prestate work.
- Freeze a deterministic source-tree digest.
- Approve the scope in section 4.
- No gate behavior change.

Exit: shared transaction faults cannot bless changed or partial bytes.

### Stage 1 - schema and baseline

- Add schema, loader, semantic validator, inventory generator, and Part-0 lint.
- Generate activation inventory from current source.
- Independently reconcile it against driver, gate modules, PhaseIO contracts,
  docs, and the 33-row table.
- Populate 33 `LEGACY_ACTIVE_UNGOVERNED` records and three tombstones.
- Record seam counts; leave ceilings unapproved.
- Delete the v1-empty test.

Exit: exact 33-record baseline and digest, no behavior change, all new runtime
transitions blocked.

### Stage 2 - literal observation wrappers

- Refactor hidden predicates and dynamic dispatch.
- Add literal wrapper calls one seam at a time.
- Emit shadow/legacy observation receipts without changing existing effects.
- Compare pre/post outputs byte-for-byte and decision counts.

Order: `STARTUP_RESUME`, `POST_DISCOVERY`, `PRE_VERIFY`, `POST_VERIFY`,
`REPORT_ASSEMBLY`.

Exit: AST parity and behavior/receipt parity for all product cells.

### Stage 3 - PhaseIO transaction cutover

- Register every input, output, receipt, overflow, and governance-debt artifact.
- Move canonical mutation behind staged checked commit.
- Enable crash/retry/concurrency recovery.

Exit: no post-hoc artifact authority, no double append/fire, quarantine cannot
be consumed.

### Stage 4 - static and runtime enforcement

- Enable AST parity in focused and full CI.
- Have the human system owner approve seam ceilings in a prior revision.
- Observe then approve per-gate runtime budgets.
- Enable count/cost/overflow enforcement.
- Startup validates registry and manifest before runtime work.

Exit: no ungoverned activation and all budget equations balance.

### Stage 5 - evidence promotion

- Fixture and fault evidence;
- independent review;
- neutral held-out false-fire/recall measurement;
- promote records individually from legacy/shadow/replay to active.

Exit: no blanket promotion. Each record has its own evidence and receipt.

### Stage 6 - measured consolidation

- Attribute overlap and unique contribution;
- consolidate or sunset only with section 15 evidence;
- release slots only after the same evidence is approved.

## 17. Test replacement

Delete `scripts/test_post_audit_gate_budget.py`. Do not extend it: its exact
empty-v1 assertions make successful migration fail.

Replace it with:

1. `scripts/test_mechanical_gate_protocol_contract.py`
   - decision classes;
   - corrected set math;
   - prior-revision ceiling/exception rules;
   - class-specific admission.

2. `scripts/test_mechanical_gate_registry_schema.py`
   - strict JSON, closed keys, enums, lifecycle, ownership, expiry, Part 0.

3. `scripts/test_mechanical_gate_activation_parity.py`
   - populated baseline, AST discovery, literal IDs, bypass and digest drift.

4. `scripts/test_mechanical_gate_runtime.py`
   - state behavior, counts, budgets, overflow, UNKNOWN, false-clean
     prevention, expiry, and receipt identity.

5. `scripts/test_mechanical_gate_phase_io.py`
   - arm/stage/CAS/commit/quarantine, input and output-prestate binding,
     downstream authority.

6. `scripts/test_mechanical_gate_migration.py`
   - exact 33 legacy-live set, seam counts 3/0/13/4/7/6, three tombstones,
     new-transition block, behavior parity.

7. `scripts/test_mechanical_gate_neutral_evaluation.py`
   - evaluator independence, held-out digest, zero-denominator UNKNOWN,
     count/rate thresholds, no self-certification.

8. `scripts/test_mechanical_gate_packaging.py`
   - clean checkout, source archive, Claude/Codex install, Windows copy
     fallback, import/path resolution.

## 18. Required fixture and fault matrix

### 18.1 Schema and static parity

- unknown key at every object level;
- duplicate JSON key;
- invalid UTF-8/BOM/nonfinite/float;
- duplicate and case-fold-colliding gate/activation IDs;
- bad seam/class/direction/state;
- invalid transition;
- missing schema on input/output;
- owner equals reviewer;
- active state without owner/review;
- expired active exception;
- bad baseline/addition/release equation;
- release not subset of baseline;
- baseline/addition overlap;
- Part-0 target name, finding ID, target location, or motivating answer;
- code activation missing registry;
- registry runtime record missing code;
- direct-call bypass;
- dynamic ID;
- symbol rename/move;
- selector drift;
- code-digest drift;
- dead function counted live; and
- two hidden independently fireable decisions.

### 18.2 Per-gate semantics

For each of 33 rows:

- positive fire;
- precision no-fire;
- legitimate empty exact denominator;
- absent provider;
- malformed and stale input;
- split, duplicate, and contradictory input;
- identifier-prefix and mixed-case collision;
- provider exception;
- output and receipt write exception;
- input/file-set change during evaluation;
- no false clean;
- selector N/A receipt; and
- byte-identical idempotent replay.

### 18.3 Budget and overflow

- N and N+1 for every count cap;
- all equations balance;
- exact and lower-bound denominator;
- stable shard and persisted omitted IDs;
- backlog-first resume;
- input byte/file cap;
- candidate/retained cap;
- wall timeout including final external test;
- external-process, worker, and token caps;
- overflow delivered to assurance;
- no cap converts remainder to clear.

### 18.4 Crash, resume, and concurrency

- crash before arm;
- after arm;
- after staging;
- between revalidation and replace;
- after replace before artifact receipt;
- after artifact receipt before gate receipt;
- registry digest changes on resume;
- activation-manifest digest changes on resume;
- run-ID mismatch;
- idempotent replay;
- no double fire/candidate append;
- two concurrent gate evaluations touching distinct outputs;
- two touching the same inventory;
- ledger/index concurrent rebuild;
- stale lock and killed process;
- quarantined output cannot become downstream authority; and
- frozen identical resume causes no gate/model re-execution or semantic
  mutation when all receipts are complete.

### 18.5 Cross-OS/filesystem

- Windows drive-relative and mixed separators;
- case-insensitive ID/path collision;
- POSIX case-sensitive siblings;
- symlink and Windows junction;
- non-regular file and alternate data stream where supported;
- long path;
- path escape;
- read-only install;
- Windows no-symlink copy fallback; and
- missing optional dependency.

### 18.6 Product matrix

Exercise:

- SC and L1;
- Light, Core, Thorough;
- EVM, Solana, Aptos, Sui, Soroban, DAML, L1 Go, L1 Rust;
- Claude and Codex;
- toolchain available and unavailable;
- gate applicable and explicit N/A;
- clean and resume paths.

Use pairwise coverage for ordinary selector combinations, but require full
coverage for every destructive, execution-block, target-execution, and no-ship
gate. Backend-neutral decisions must prove identical normalized receipts across
Claude and Codex.

### 18.7 Ecosystem-specific expectations

- EVM/Solana/Aptos/Sui/Soroban/L1 Go/L1 Rust mechanical execution adapters bind
  actual commands, timeouts, output, and toolchain-unavailable debt.
- DAML receives explicit N/A for unsupported current derivers/executors rather
  than absent execution.
- Go race multiplier is inside the registry budget calculation.
- Move and Rust path/case semantics remain exact across Windows and POSIX.
- No ecosystem adapter may broaden a shared gate’s semantic predicate without a
  distinct decision ID or reviewed selector/code-digest update.

### 18.8 Held-out evaluation

- motivating regressions scored regression-only;
- corpus and comparator digest-bound;
- neutral evaluator joins fires to independent outcomes;
- zero adjudicated fires yields UNKNOWN;
- minimum denominator enforced;
- false-fire count and rate both enforced;
- recall, found-then-lost, fragmentation, severity, cost, and wall time
  reported;
- no ground truth reaches runtime inputs, prompts, configs, or registry; and
- no gate self-certification.

## 19. Acceptance criteria

R0-8e is implementation-complete only when all are true:

1. strict v2 loader and schema reject all malformed/unknown forms;
2. the canonical live baseline is exactly the 33 IDs in section 5;
3. seam counts are exactly `3/0/13/4/7/6`, total 33;
4. all 33 are initially legacy-unassessed and no evidence/owner is fabricated;
5. three dead/superseded tombstones are non-runtime and docs are corrected;
6. activation manifest and source-tree digests match;
7. every production activation uses literal IDs and no direct bypass exists;
8. all gate outputs, receipts, debt, and overflow are PhaseIO-registered;
9. checked commit binds exact inputs and output prestates and quarantines drift;
10. exact count equations hold; lower bounds and UNKNOWN never become clear;
11. overflow is stable, durable, resume-safe, and report-visible;
12. false-fire PASS can originate only from the neutral held-out evaluator;
13. owner/reviewer/expiry rules are enforced for every new runtime transition;
14. seam ceilings are separately pre-approved before any slot is spent;
15. focused, full serial, and full xdist suites pass from a clean source tree;
16. fault, migration, resume, concurrency, cross-OS, ecosystem, and backend
    matrices pass;
17. clean/source-archive/Claude/Codex/Windows-copy installs contain and load all
    governance files;
18. a bounded non-ground-truth legacy-Claude canary proves live reachability,
    visible debt, and clean resume; and
19. the final handoff is hash-stamped, unpushed/unmerged/uninstalled, with known
    limitations and independent review boundaries.

Green unit tests, one ecosystem, one backend, one regression repository, or a
populated JSON file do not satisfy this acceptance boundary.

## 20. Recommended implementation order

1. Complete shared PhaseIO commit-CAS/output-prestate authority.
2. Amend protocol decision classes and count math.
3. Add strict schema/loader/Part-0 lint.
4. Generate and independently review the exact 33-gate activation baseline.
5. Populate legacy records and tombstones; keep ceilings unapproved.
6. Add literal observation wrappers and AST parity.
7. Prove behavior/receipt parity.
8. Move mutations behind PhaseIO transactions seam by seam.
9. Approve and enforce runtime and gate-count budgets.
10. Add neutral held-out measurement.
11. Promote individually; then consolidate only with recall-safe evidence.

This order converts the registry from policy prose into executable governance
without hiding migration debt, spending unapproved gate slots, or sacrificing
recall during cutover.
