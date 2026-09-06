# Plamen Axis-Disposition P0-I Production-Integration Design

Date: 2026-07-24  
Status: Implementation design; no repository edits or tests performed  
Scope: Production integration of `scripts/axis_disposition.py`

## Executive verdict

Axis disposition must not be wired in its current v1 form. It would create false-clean authority, ambiguous identity matching, pre-commit side effects, and invisible assurance debt. The production integration should be a schema-v2/PhaseIO change.

The implementation belongs after the active PhaseIO transaction/ownership work has stabilized. It should reuse the final PhaseIO primitives rather than creating a parallel ledger or bespoke mutation protocol.

## Current-state defects and risks

### 1. Failure can be misrepresented as a clean empty denominator

`compute_axis_coverage_gaps()` catches internal errors and returns `[]`. `_axis_coverage_has_no_gaps()` interprets `[]` as “there are no gaps.” A failed provider, malformed input, or unavailable population can therefore skip analysis silently.

The clean-empty state must be proven by an exact provider receipt. It cannot be inferred from an empty Python collection.

### 2. Disposition identity is ambiguous

Current reconciliation keys Markdown rows by `(function.casefold(), axis)`. Overloaded functions, same-named functions in different contracts/modules, and repeated loci collide. One row may match multiple work items, leaving all of them ambiguously unresolved or allowing a disposition to be attributed to the wrong obligation.

Every disposition must bind the exact mechanically issued `work_item_id`.

### 3. Markdown and regex are being asked to carry exact authority

The present parser reads a human-authored `Coverage Record` table and interprets it as the complete enumerate-all disposition. Markdown is suitable for findings and explanations; it is not a safe authority format for exact cardinality, referential integrity, source hashes, or machine-enforced enum values.

The authoritative model output should be strict JSON. Markdown should remain the human-readable action/finding body.

### 4. Promotion can mutate inventory before final phase acceptance

`enumeration_gate.promote_axis_findings_to_inventory()` is called from `_run_phase_validators()`. That function runs during both initial and retry attempts. A failed/retried attempt can therefore append to `findings_inventory.md` before the model output has passed the final accepted PhaseIO boundary.

No axis side effect should occur from `_run_phase_validators()`.

### 5. Promotion is broader than the reconciled disposition set

The existing promoter parses AXIS headings from Markdown and can append them without proving that a valid `FINDING` or `UNRESOLVED` disposition referenced them. Orphan actions may therefore reach inventory, while exact delivery of the intended actions is not proven.

Promotion must be a projection of a validated typed disposition set.

### 6. The repair artifact has no consumer

`axis_repair_work.json` is emitted but no bounded worker consumes it. The claimed repair-then-degrade policy is therefore incomplete: invalid/missing dispositions immediately become residual debt.

The integration needs one bounded targeted repair attempt with distinct PhaseIO-owned inputs and outputs.

### 7. Axis assurance debt is not report-visible

`axis_assurance_debt.json` and `axis_assurance_limitations.md` are not consumed by the unified assurance projection. The pipeline can recognize incomplete application mechanically but fail to disclose it in the final report.

Axis debt must be projected through `scripts/assurance_limitations.py`.

### 8. Input debt can disappear behind zero unresolved rows

The current assurance output is constructed primarily from unresolved work items. A denominator/provider failure with zero rows can produce `COMPLETED_WITH_DEBT` while the assurance collection and limitations text claim zero debt.

Population/input debt must itself create typed assurance rows.

### 9. Wrong-safe dispositions bypass the independent skeptic

`application_skeptic` currently runs before `axis_coverage`. Axis CLEAR decisions therefore never enter the phase designed to challenge unsafe negative conclusions.

Axis coverage should precede application skepticism, and valid CLEARs should be harvested into candidate-negative authority.

### 10. Executed-evidence authority is caller supplied and not production bounded

`reconcile_axis_output()` accepts `executed_evidence_receipts` from its caller, but no production loader proves the complete current-run set of eligible pre-axis execution receipts. Passing `{}` is an unproven absence; scanning the scratchpad risks admitting stale receipts from prior or later verification runs.

The integration needs a deterministic, current-run, PhaseIO-bounded evidence-authority provider. An exact zero receipt is expected in the present phase order, but the zero must be proven.

### 11. Application and delivery authority are coupled

The current disposition receipt includes promotion/inventory hashes. That makes an otherwise immutable application result stale when inventory changes for unrelated downstream reasons.

Application completeness and inventory delivery should be separately validated authorities.

### 12. Resume validation is presence based

`_resume_semantic_issues()` currently delegates axis coverage to `_validate_axis_coverage()`, which is a soft Markdown/presence check. It does not validate the worklist denominator, disposition cardinality, repair condition, promotion delivery, PhaseIO owner, source hashes, or current-run evidence.

Resume must validate the complete authority chain.

## Required schema changes

### Worklist v2

Upgrade `plamen.axis_disposition_worklist.v1` to v2. Each obligation needs an exact immutable identity:

```json
{
  "work_item_id": "AXW-...",
  "function_identity": "...",
  "axis": "...",
  "source_relpath": "...",
  "source_locus": "...",
  "source_hash": "...",
  "matrix_cell_hash": "...",
  "required_action_id": "AXIS-..."
}
```

Add top-level population authority:

```json
{
  "denominator_status": "EXACT | DEGRADED | UNKNOWN",
  "observed_hot_function_count": 0,
  "gap_count": 0,
  "input_debt": [],
  "requires_execution": true
}
```

A clean empty worklist is legal only when:

1. The registered cap provider executed successfully.
2. Its receipt belongs to the current run and provider version.
3. Its source/input hashes match the matrix.
4. It proves an exact zero denominator.
5. No unknown coverage shortfall invalidates completeness.

`DEGRADED` or `UNKNOWN` must never enter the clean no-gap skip path.

### Model disposition sidecar

Add model-owned `axis_coverage_dispositions.json`:

```json
{
  "schema": "plamen.axis_model_dispositions.v1",
  "worklist_hash": "...",
  "items": [
    {
      "work_item_id": "AXW-...",
      "disposition": "FINDING | UNRESOLVED | CLEAR",
      "action_id": "AXIS-...",
      "evidence": [],
      "rationale": "..."
    }
  ]
}
```

Required rules:

- Exactly one row per work-item ID.
- `FINDING` and `UNRESOLVED` require exactly one referenced action.
- `CLEAR` must not reference an action.
- Unknown, missing, or duplicate IDs become repair obligations.
- The sidecar's worklist hash must equal the exact PhaseIO input.
- Markdown remains the human-readable action body, not disposition authority.
- Legacy Markdown tables may be accepted only as degraded repair input, never as clean authority.

### Separate application and delivery authority

Keep two immutable receipts:

- `axis_disposition_receipt.json`: whether every AXW obligation received an admissible disposition.
- `axis_coverage_promotion_receipt.json`: whether every referenced action was delivered into inventory.

Remove promotion/inventory hashes from the application receipt. Promotion failure must not invalidate the underlying action; it creates delivery debt.

Rename or precisely document `methodology_application_proven`: it proves that an obligation received an admissible disposition, not that a semantic CLEAR is correct. `application_record_complete` would be less misleading.

## Exact PhaseIO ownership and execution sequence

### 1. `axis_disposition/planning`

Owner: deterministic driver.

Immutable inputs:

- `_hot_function_axes.json`
- `_hot_function_cap_receipt.json`
- `_coverage_shortfalls.json`
- Every source file/locus read while compiling excerpts
- Relevant upstream graph/provider receipts

Outputs:

- `axis_disposition_worklist.json`
- `axis_execution_evidence_authority.json`

The evidence-authority artifact must prove the complete current-run set of eligible pre-axis execution receipts, including an exact zero set when none exist. Never pass an unexplained `{}`.

The planning contract should dynamically bind the source files enumerated by the matrix/worklist. Source paths must resolve within the project root, with canonical Windows and POSIX normalization.

### 2. `axis_coverage/model`

Add `axis_coverage` to `_typed_model_phase_contract_and_launch()` and the exact-consumer backend boundary.

Immutable inputs:

- Worklist v2 as the authoritative denominator
- Exact prompt-declared upstream artifacts
- Worklist-referenced source files
- No unregistered stale scratch artifacts

Outputs owned exclusively by the base model worker:

- `axis_coverage_findings.md`
- `axis_coverage_dispositions.json`

Update `prompts/shared/v2/phase4b8-axis-coverage.md` to operate by exact `work_item_id`; stop asking the model to reconstruct the denominator from raw matrices.

The Markdown file should contain action blocks and supporting reasoning. A human-readable table may remain as a projection, but it has no authority.

### 3. `axis_disposition/reconcile.initial`

Owner: deterministic driver.

Inputs:

- Worklist
- Base Markdown and disposition JSON
- Canonical-prior authority
- Execution-evidence authority

Outputs:

- `axis_disposition_initial_receipt.json`
- `axis_repair_plan.json`

Canonical priors must come from `exploration_clear_lifecycle.load_canonical_prior_authority()`. It validates `exploration_clear_prior_aliases.json` against `_canonical_finding_ids.json`. Invalid alias authority permits no alias-backed CLEAR and creates `CANONICAL_PRIOR_AUTHORITY_INVALID` debt.

### 4. `axis_coverage/repair.worker.0001`

One bounded targeted repair only.

Inputs:

- `axis_repair_plan.json`
- Original worklist
- Original model outputs
- Exact referenced source inputs

Separate outputs:

- `axis_coverage_repair_findings.md`
- `axis_coverage_repair_dispositions.json`

The repair worker may fill only unresolved IDs. It cannot replace a valid earlier disposition or silently override conflicts. Conflicting base/repair answers remain debt.

Always emit driver-owned `axis_repair_execution_receipt.json` with one of:

- `NOT_REQUIRED`
- `EXECUTED`
- `FAILED`
- `OVERFLOW`

Resume must not infer whether the conditional worker should have existed from file absence.

### 5. `axis_disposition/reconcile.final`

Owner: deterministic driver.

Inputs:

- Worklist and population authority
- Base outputs
- Initial reconciliation
- Repair execution receipt
- Repair outputs when executed
- Canonical-prior authority
- Execution-evidence authority

Outputs:

- `axis_disposition_receipt.json`
- `axis_repair_work.json` for residual obligations
- `axis_assurance_debt.json`
- `axis_assurance_limitations.md`

Debt must include:

- Unknown/degraded denominator
- Input/cap mismatch
- Missing or malformed dispositions
- Invalid CLEAR evidence
- Repair failure or overflow
- Conflicting base/repair answers
- Unresolved work identities

### 6. `axis_disposition/promotion`

Run only after the base and optional repair model outputs have been PhaseIO-committed and final reconciliation has succeeded.

Inputs:

- Final disposition receipt
- Base and repair action Markdown
- Current `findings_inventory.md` prestate

Outputs:

- PhaseIO `MERGE` mutation of `findings_inventory.md`
- `axis_coverage_promotion_receipt.json`
- Optional Markdown projection receipt

Only promote action IDs referenced by valid `FINDING` or `UNRESOLVED` dispositions. Orphan headings must never be promoted.

Inventory merge requires deterministic-driver ownership, a lock, and expected-prestate validation. The JSON receipt must support torn-write recovery without duplicate inventory blocks, analogous to the stronger enumgap delivery validator.

Promotion failure does not erase or demote the action. It produces delivery debt and preserves a recoverable queue item.

### 7. Negative challenge and canonical identity refresh

After promotion:

1. Add `axis_coverage` to `_CANDIDATE_NEGATIVE_BASE_PHASES`.
2. Prefer a typed adapter that harvests valid CLEAR rows directly by AXW ID.
3. Move `axis_coverage` before `application_skeptic` in `SC_PHASES`.
4. Run canonical finding-ID refresh after typed promotion.
5. Commit the parent phase only after deterministic finalization has reached a terminal success-or-debt state.

A valid CLEAR is still only a negative proposal. It remains challengeable and cannot delete or demote a finding by itself.

## Driver and module call-site changes

### `scripts/plamen_driver.py`

Add axis imports beside the existing enumgap imports.

Add helpers beside the enumgap integration:

- `_axis_disposition_contract_and_launch`
- `_axis_disposition_exact_inputs`
- `_axis_execution_evidence_authority`
- `_prepare_axis_disposition_worklist`
- `_compile_axis_coverage_model_prompt`
- `_reconcile_axis_dispositions`
- `_run_axis_disposition_repair`
- `_promote_axis_disposition_actions`
- `_axis_disposition_resume_issues`
- `_finalize_axis_coverage_boundary`

Replace `_axis_coverage_has_no_gaps()` with a worklist-authority check such as `_axis_coverage_has_no_obligations()`. It may skip the model only for exact zero authority.

Remove `promote_axis_findings_to_inventory()` from `_run_phase_validators()`. Keep `_run_phase_validators()` side-effect free for axis attempts.

Call `_finalize_axis_coverage_boundary()` only after `_record_typed_model_phase_artifacts()` has committed the accepted model output. If the generic typed-model commit currently occurs after candidate-negative harvesting, either move the generic commit earlier or add an axis-specific accepted-output commit before deterministic finalization.

Ensure candidate-negative harvesting occurs after final reconciliation, not before model PhaseIO commit.

In `_resume_semantic_issues()`, replace the axis soft validator with `_axis_disposition_resume_issues()`.

Add axis to the existing canonical-identity refresh phase-name set after typed promotion/reconciliation.

### `scripts/phase_io_contracts.py`

Add resolver shapes for:

- `axis_disposition/planning`
- `axis_coverage/model`
- `axis_disposition/reconcile.initial`
- `axis_coverage/repair.worker.0001`
- `axis_disposition/reconcile.final`
- `axis_disposition/promotion`

The promotion unit needs `MERGE` ownership of `findings_inventory.md` with an explicit predecessor/successor owner relationship because the file was originally created by the inventory phase.

No two workers should own the same output. Base and repair outputs remain distinct.

### `scripts/plamen_types.py`

- Move `axis_coverage` before `application_skeptic` in `SC_PHASES`.
- Require both `axis_coverage_findings.md` and `axis_coverage_dispositions.json`.
- Retain the current `modes={"thorough"}` applicability unless a separate expansion is accepted.

### `scripts/enumeration_gate.py`

- Retire the regex-first production promoter or convert it into the receipt-driven promotion implementation.
- Never let `compute_axis_coverage_gaps()` collapse an error into authoritative `[]`.
- Return typed computation status or raise into planning, where the driver can emit `UNKNOWN` population authority and assurance debt.

### `scripts/axis_disposition.py`

- Add worklist v2 and strict disposition-sidecar parsing.
- Reconcile by `work_item_id`.
- Add explicit population/input-debt reconciliation.
- Separate application receipt from delivery receipt.
- Add base/repair merge semantics.
- Update `validate_axis_disposition_authority()`.
- Add `validate_axis_promotion_authority()`.
- Preserve backward parsing only as non-authoritative repair compatibility.

### `scripts/assurance_limitations.py`

- Add `_axis_disposition_assurance_rows()`.
- Include axis authority files in `assurance_projection_input_paths()`.
- Validate/replay `validate_axis_disposition_authority()` before projection.
- Missing or invalid authority must emit discovery-recall/methodology-application debt, never an empty clean projection.
- Project residual identities, denominator debt, repair failure/overflow, and promotion-delivery failure through the unified `assurance_limitations.json/.md` outputs.

Do not directly splice `axis_assurance_limitations.md` into the final report. It should be a source for unified deterministic assurance projection.

### Candidate-negative authority

Add `"axis_coverage"` to `_CANDIDATE_NEGATIVE_BASE_PHASES`.

Prefer a direct typed adapter from valid CLEAR disposition rows to the candidate-negative ledger. A generic Markdown safe-language parser loses AXW identity and may harvest prose that was never an authoritative disposition.

## CLEAR admissibility

A CLEAR may close structural application only when backed by one of:

- A current, in-scope source locus with exact source hash
- A valid canonical-prior identity/alias
- A current-run execution receipt from the exact registered evidence denominator

The following are invalid:

- Favorable external assumptions
- Uncited ecosystem behavior
- Model prose claiming a test ran
- Stale verification artifacts
- Post-axis receipts not in the predeclared evidence denominator
- Generic “not exploitable” or “safe” reasoning

Even an admissible CLEAR must enter candidate-negative/application-skeptic review. This directly targets the wrong-safe half of the observed miss population.

At the present phase order, there may be no eligible executed evidence receipts. The preferred safe options are:

1. Temporarily disallow execution-backed CLEAR until a registered pre-axis provider exists; or
2. Keep the API future-ready but require `axis_execution_evidence_authority.json`, whose expected current result is a proven exact zero set.

Never scan the scratchpad opportunistically for execution receipts.

## Resume and haltless failure contract

Resume must validate:

- PhaseIO owner and current run identity
- Worklist, source, and provider hashes
- Output prestates
- Sidecar schema, cardinality, IDs, and worklist hash
- Canonical-prior authority
- Execution-evidence authority
- Repair conditional receipt
- Final disposition authority
- Promotion delivery authority
- Inventory projection bytes

Crash recovery boundaries should be independently resumable after:

1. Planning commit
2. Base model commit
3. Initial reconciliation
4. Repair model commit
5. Final reconciliation
6. Inventory append before promotion receipt
7. Promotion receipt before parent phase commit

Failure behavior remains haltless:

- Planning/provider failure: `UNKNOWN` denominator and report-visible debt.
- Model failure: bounded repair if possible, otherwise residual debt.
- Repair failure: residual obligations remain visible.
- Promotion failure: delivery debt; action remains recoverable.
- Assurance projection failure: explicit general authority-invalid limitation.
- No failure path is allowed to synthesize a clean zero.

The smallest invalid deterministic unit should be rerun on resume. Model work should be rerun only when its exact owned output is absent or invalid, not because a downstream deterministic receipt is missing.

## Supported path contract

### Smart-contract pipeline

- SC Thorough: fully active.
- SC Light/Core: not scheduled; do not create fake empty axis authority.

### L1 pipeline

- L1 all modes: currently not scheduled and lacks an accepted L1 hot-axis population provider.
- Do not accidentally invoke SC axis code or imply L1 methodology completeness.
- L1 parity should be a separate accepted follow-up after Go/Rust graph and hot-function population authority exists.

### Ecosystems

SC Thorough should be validated for:

- EVM/Solidity
- Solana/Rust
- Aptos/Move
- Sui/Move
- Soroban/Rust

The core work-item schema remains ecosystem-neutral. Ecosystem-specific code should be restricted to BAKE/provider identity and locus construction.

### Backends

- Claude and Codex must receive the same backend-neutral worklist/sidecar contract.
- Prompt snapshots should prove identical obligation semantics.
- Only the launch/PTY adapter should differ.
- Repair workers must use the driver-supervised backend path, never model self-orchestration.

## Minimum red-to-green fixture matrix

### Planning and denominator authority

- Exact nonempty denominator
- Exact zero denominator
- Missing provider receipt
- Provider exception
- Malformed cap receipt
- Matrix/cap count mismatch
- Unknown shortfall with zero rows
- Omitted/capped hot functions remain debt
- Overloads and same-name functions at multiple loci
- Windows path normalization
- POSIX path normalization
- Source path escaping project root is rejected/debt

### Model disposition authority

- Exactly one row per AXW ID
- Missing ID
- Duplicate ID
- Unknown ID
- Wrong worklist hash
- Invalid disposition enum
- FINDING without action
- UNRESOLVED without action
- CLEAR with action
- Orphan AXIS heading
- Two rows referencing one action
- Action references wrong AXW identity
- Valid source-locus CLEAR
- Stale or altered source
- Valid canonical alias
- Missing/invalid canonical authority
- Valid current execution receipt
- Stale execution receipt
- Post-axis execution receipt
- Unregistered execution receipt
- Favorable external-assumption CLEAR
- Legacy Markdown table cannot produce clean authority

### Repair

- No-repair conditional receipt
- Repair fills one unresolved identity
- Repair tries to override valid base row
- Base/repair conflict
- Repair references an identity outside its plan
- Worker timeout
- Worker crash
- Malformed repair sidecar
- Repair cap overflow
- Residual identities remain assurance-visible

### Promotion and delivery

- Only referenced actions delivered
- Orphan actions excluded
- CLEAR has no promoted action
- Idempotent replay
- Crash after append but before receipt
- Stale inventory prestate
- Tampered inventory block
- Tampered promotion receipt
- Duplicate append recovery
- Delivery failure remains assurance-visible
- Unrelated later inventory append does not invalidate application receipt

### Ordering and resume

- Retry attempt produces no inventory mutation
- Accepted sequence is model commit, initial reconcile, bounded repair, final reconcile, promotion, negative harvest, canonical refresh
- Resume after each transaction boundary
- Candidate-negative harvest never precedes axis final reconciliation
- Canonical refresh occurs after promotion
- Application skeptic consumes axis CLEARs
- Invalid downstream receipt does not force an unnecessary model rerun

### Ecosystem and mode coverage

- EVM Solidity identities/loci
- Solana Rust identities/loci
- Aptos Move identities/loci
- Sui Move identities/loci
- Soroban Rust identities/loci
- Claude prompt/contract snapshot
- Codex prompt/contract snapshot
- SC Thorough active
- SC Light/Core explicitly unscheduled
- L1 Light/Core/Thorough explicitly unscheduled

### Assurance projection

- Clean exact zero projects no false limitation
- Unknown zero denominator projects a limitation
- Missing axis authority projects a general debt row
- Invalid receipt projects authority-invalid debt
- Repair failure and overflow project correctly
- Promotion-delivery debt projects without deleting the action
- Unified report assembly preserves the limitation

## Implementation recommendation

Implement this as one P0-I production slice after PhaseIO stabilizes:

1. Schema v2 and standalone deterministic fixtures.
2. Planning and exact-zero population authority.
3. Base typed model contract and prompt.
4. Initial reconcile plus one bounded repair worker.
5. Final reconciliation and assurance projection.
6. Receipt-driven PhaseIO inventory promotion.
7. Candidate-negative/application-skeptic ordering.
8. Resume/crash-boundary and backend/ecosystem fixtures.
9. Full fast-lane/blast-radius validation.

Do not first wire v1 and “harden later.” Its false-clear and pre-acceptance mutation behavior would undermine the exact recall guarantees this integration is intended to add.
