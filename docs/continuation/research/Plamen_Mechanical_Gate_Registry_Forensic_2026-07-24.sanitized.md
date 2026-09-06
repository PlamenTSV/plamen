# Plamen Mechanical-Gate Registry Forensic and Implementation Handoff

**Date:** 2026-07-24  
**Scope:** R0-8e mechanical-gate registry, budget governance, activation parity,
failure contracts, and migration planning  
**Repository inspected:** `<LOCAL_USER_ROOT>\plamen-codex-implementation`  
**Inspected base revision:** `67a0f85adc7a8169d79a286908b00bef7adb764a` plus the
current uncommitted implementation tree  
**Mode:** Read-only forensic. No repository files, audit targets, scratchpads, or
ground-truth material were changed or inspected.

## 1. Executive verdict

R0-8e is not implemented as an enforceable control. The repository has detailed
policy prose, but the canonical registry is empty, no production code loads or
validates it, no runtime activation is bound to it, and its only focused test
positively requires it to remain empty.

The current state is therefore governance theater:

- `rules/mechanical-gate-registry.json` contains no gate records and no seam
  budgets.
- Its migration state is
  `BLOCK_NEW_ACTIVATIONS_PENDING_BASELINE`, but nothing enforces that state.
- No production module reads the registry.
- There is no JSON Schema or strict Python schema validator.
- There is no activation-to-record parity lint.
- There is no runtime state, expiry, budget, overflow, or false-fire
  enforcement.
- There is no owner/reviewer independence validation.
- Most live mechanical gate outputs are outside PhaseIO and the artifact-ledger
  commit boundary.
- `scripts/test_post_audit_gate_budget.py` explicitly locks the registry at:

  ```json
  {
    "schema_version": "plamen.mechanical_gate_registry.v1",
    "migration_status": "BLOCK_NEW_ACTIVATIONS_PENDING_BASELINE",
    "seam_budgets": [],
    "gate_records": []
  }
  ```

The focused test suite passes in this unfinished state:

```text
python -m pytest -q -p no:cacheprovider scripts/test_post_audit_gate_budget.py
.......                                                                  [100%]
7 passed in 0.38s
```

The registry work is worth building, but it must be treated as an authority and
measurement program, not a JSON-population exercise.

## 2. Scope ambiguity that must be resolved first

The post-audit improvement protocol contains an internal contradiction:

1. Every proposed or shipped mechanical gate is said to require M1-M4 evidence.
2. M4 requires the gate to operate after the verification filter.
3. The registry seam taxonomy includes `STARTUP_RESUME`, `PRE_DISCOVERY`, and
   `POST_DISCOVERY`.
4. The advertised mechanical layer includes pre-verification recall generators,
   graph-health checks, source-snapshot guards, and supply-chain circuit
   breakers.

Those mechanisms cannot truthfully satisfy M4. Without a decision-class
distinction, registry authors must either fabricate M4 evidence or omit major
live mechanisms.

The v2 schema should define these admission classes:

| Decision class | Admission evidence |
|---|---|
| `RC_AGENT_MECHANIZABLE` | M1, M2, M3, and M4 are mandatory |
| `RECALL_GENERATOR` | M1-M3 plus mandatory independent verification and delivery |
| `PIPELINE_INTEGRITY` | Deterministic correctness/safety evidence; M4 is not applicable |
| `PRECISION_DISCRIMINATOR` | Typed evidence, no destructive prose authority, recall-safe fallback |
| `TELEMETRY_ONLY` | Exact denominator and visible debt; no finding authority |

Recommended registry boundary:

> Register every deterministic decision that independently changes a finding,
> obligation, disposition, severity, proof status, target-code execution,
> verification routing, or ship/assurance authority.

Ordinary structural phase validators should remain governed by the phase
contract catalog unless they independently exercise one of those authorities.
The registry must encode this boundary explicitly through `registry_scope` and
`excluded_control_families`; otherwise a “complete” baseline cannot be proven.

If the intended scope is instead every deterministic validator invoked by
`_run_phase_validators`, the inventory is materially larger than the 33
decision-authority records below. That runner directly invokes roughly 50
recon, depth, chain, verification, and report validators. The implementation
must not silently choose the narrower interpretation.

## 3. Conservative active production inventory

This is the minimum complete baseline for independently fireable deterministic
decisions that affect findings, obligations, proof, target execution, or report
authority. Shared ecosystem adapters count once when they implement the same
semantic decision. Independent activations at different seams count separately.

### 3.1 Startup and pre-discovery

#### MG-001 — Supply-chain gate before input preparation

- **Proposed stable ID:** `supply_chain.pre_input_execution`
- **Predicate:** `gate_supply_chain`
- **Definition:** `scripts/supply_chain_gate.py:189`
- **Activation:** `scripts/recon_prepass.py:2211`
- **Startup propagation:** `scripts/plamen_driver.py:42441`
- **Seam:** `STARTUP_RESUME`
- **Direction:** target-execution circuit breaker
- **Applicability:** all pipelines and modes when source preparation invokes
  target toolchains; backend-neutral
- **Failure:** hard startup block through `SnapshotInputError`
- **Receipt/budget:** no registry-owned receipt or runtime budget

#### MG-002 — Supply-chain gate before PoC execution

- **Proposed stable ID:** `supply_chain.pre_poc_execution`
- **Predicate:** `gate_supply_chain`
- **Definition:** `scripts/supply_chain_gate.py:189`
- **Activation:** `scripts/mechanical_verify.py:2209`
- **Seam:** `POST_VERIFY`
- **Direction:** target-test execution circuit breaker
- **Applicability:** all supported ecosystems and modes when mechanical verify
  runs; backend-neutral
- **Failure:** aborts the mechanical verification call before target build/test
  execution
- **Why separate from MG-001:** independently fireable, different input state,
  different runtime seam, and different downstream failure effect

#### MG-003 — Startup snapshot binding

- **Proposed stable ID:** `snapshot.startup_binding`
- **Predicate:** `snapshot_startup_guard`
- **Definition:** `scripts/audit_snapshot.py:1913`
- **Activation:** `scripts/plamen_driver.py:43709`
- **Seam:** `STARTUP_RESUME`
- **Direction:** block unsafe startup/resume
- **Failure:** explicit startup decision or snapshot error; never a false clean

#### MG-004 — Inter-phase source drift

- **Proposed stable ID:** `snapshot.interphase_drift`
- **Predicate:** `_assert_audit_snapshot_still_bound`
- **Definition:** `scripts/plamen_driver.py:42597`
- **Activations:** `scripts/plamen_driver.py:39367`, `:44150`
- **Seam:** `STARTUP_RESUME`
- **Direction:** block or invalidate work derived from changed source inputs
- **Failure:** explicit source-drift exception; not haltless by design

### 3.2 Post-discovery recall generators and delivery gates

#### MG-005 — Enumeration graph-health decision

- **Proposed stable ID:** `enumeration.graph_health`
- **Predicates:** `_graph_health_shortfalls`, `_record_graph_health`
- **Definitions:** `scripts/enumeration_gate.py:526`, `:662`
- **Activation owner:** `compute_enumeration_obligations` at
  `scripts/enumeration_gate.py:756`
- **Seam:** `POST_DISCOVERY`
- **Direction:** flag `UNKNOWN`/coverage debt
- **Inputs:** mechanical graph and inventory location denominator
- **Outputs:** shared `_coverage_shortfalls.json` and report projection
- **Failure:** meant to flag unknown rather than clear

#### MG-006 — G1 co-reference obligation enumeration

- **Proposed stable ID:** `enumeration.coreference_obligation`
- **Definition:** `scripts/enumeration_gate.py:756`
- **Dispatcher call:** `scripts/enumeration_gate.py:4330`
- **Driver entry:** `scripts/plamen_driver.py:17077`
- **Accepted-depth activations:** `scripts/plamen_driver.py:41560`, `:41761`
- **Seam:** `POST_DISCOVERY`
- **Direction:** add-only obligation enumeration
- **Applicability:** SC and L1, all modes after an accepted depth boundary,
  backend-neutral

#### MG-007 — G2 co-reference coverage-gap candidate

- **Proposed stable ID:** `enumeration.coreference_gap`
- **Definition:** `scripts/enumeration_gate.py:1344`
- **Dispatcher call:** `scripts/enumeration_gate.py:4335`
- **Driver seam:** same accepted-depth transaction as MG-006
- **Direction:** append low-confidence `ENUMGAP` candidate
- **Downstream:** normal dedup, chain, verification, and reporting

#### MG-008 — Critical-asset-mover candidate

- **Proposed stable ID:** `enumeration.critical_asset_mover`
- **Definition:** `scripts/enumeration_gate.py:1881`
- **Dispatcher:** `run_enumeration_gate`, `scripts/enumeration_gate.py:4339+`
- **Direction:** add-only low-confidence candidate
- **Applicability:** Solidity, Rust, and Move source shapes; intentionally not
  Go node clients or DAML

#### MG-009 — Array-uniqueness candidate

- **Proposed stable ID:** `enumeration.array_uniqueness`
- **Definition:** `scripts/enumeration_gate.py:2006`
- **Dispatcher:** `run_enumeration_gate`
- **Direction:** add-only low-confidence candidate
- **Applicability:** Solidity, Rust, Move, and Go; intentionally not DAML

#### MG-010 — Unbounded stored-input candidate

- **Proposed stable ID:** `enumeration.unbounded_stored_input`
- **Definition:** `scripts/enumeration_gate.py:2094`
- **Dispatcher:** `run_enumeration_gate`
- **Direction:** add-only low-confidence candidate
- **Applicability:** Solidity, Rust, Move, and Go; intentionally not DAML

#### MG-011 — Boundary-variant candidate

- **Proposed stable ID:** `enumeration.variant_boundary`
- **Definition:** `scripts/enumeration_gate.py:2312`
- **Dispatcher:** `compute_variant_gaps`, call at
  `scripts/enumeration_gate.py:2779`
- **Driver entry:** `_run_gate_v_for_phase`,
  `scripts/plamen_driver.py:16685`, invoked at `:17088`
- **Direction:** add-only `VARGAP` candidate
- **Applicability:** SC and L1, all modes, backend-neutral

#### MG-012 — Symmetric-operation variant candidate

- **Proposed stable ID:** `enumeration.variant_symmetric`
- **Definition:** `scripts/enumeration_gate.py:2645`
- **Dispatcher:** `compute_variant_gaps`, call at
  `scripts/enumeration_gate.py:2795`
- **Driver entry:** same as MG-011
- **Direction:** add-only `VARGAP` candidate

#### MG-013 — Committed-invariant falsification candidate

- **Proposed stable ID:** `enumeration.committed_invariant`
- **Definition:** `scripts/enumeration_gate.py:2868`
- **Recovery wrapper:** `scripts/enumeration_gate.py:2969`
- **Dispatcher:** `run_enumeration_gate`, `scripts/enumeration_gate.py:4357+`
- **Direction:** add-only `INVARIANT:CI-n` candidate
- **Inputs:** depth, skeptic, verifier, inventory, and graph artifacts

#### MG-014 — Hot-function × risk-axis gap matrix

- **Proposed stable ID:** `axis.hot_function_gap_matrix`
- **Definition:** `scripts/enumeration_gate.py:3576`
- **Live pre-spawn activation:** `scripts/plamen_driver.py:36341`
- **Skip/phase seam:** `scripts/plamen_driver.py:46253`
- **Seam:** `POST_DISCOVERY`
- **Direction:** enumerate GAP work and conditionally launch an additive worker
- **Applicability:** Thorough only; all ecosystems; backend-neutral
- **Denominator:** up to 40 hot functions × 6 axes = 240 cells

#### MG-015 — Enumgap exploration delivery

- **Proposed stable ID:** `enumgap.exploration_delivery`
- **Definition:** `scripts/enumeration_gate.py:4222`
- **Activation:** `scripts/plamen_driver.py:40272`
- **Direction:** append worker-produced finding as a new verification candidate
- **Applicability:** Core and Thorough SC/L1

#### MG-016 — Axis finding delivery

- **Proposed stable ID:** `axis.finding_delivery`
- **Definition:** `scripts/enumeration_gate.py:3753`
- **Activation:** `scripts/plamen_driver.py:40298`
- **Direction:** append worker-produced `AXISGAP` finding to inventory
- **Applicability:** Thorough only

#### MG-017 — Promotion-orphan reopen

- **Proposed stable ID:** `promotion.orphan_reopen`
- **Definitions:** `compute_promotion_orphans`,
  `scripts/plamen_mechanical.py:5842`; `route_promotion_orphans`, `:6257`
- **Driver transaction:** `scripts/plamen_driver.py:17356-17417`
- **SC activation:** `scripts/plamen_driver.py:44747`
- **L1 activation:** `scripts/plamen_driver.py:44934`
- **Direction:** reopen and append unretained subjects as `NEEDS_VERIFICATION`
- **Applicability:** all modes, SC and L1
- **Important live-state correction:** `_promo_disposition` at
  `scripts/plamen_mechanical.py:5725` now returns `BODY` for typed actions,
  unresolved obligations, alias proposals, shape debt, negative proposals, and
  zero-harm proposals. Historical `APPENDIX_A`/`APPENDIX_C` result branches are
  unreachable and must not be counted as active independent decisions.

### 3.3 Pre-verification and post-verification decisions

#### MG-018 — Inventory location existence

- **Proposed stable ID:** `inventory.location_exists`
- **Owning validator:** `_validate_inventory_evidence`,
  `scripts/plamen_validators.py:20600`
- **Driver activations:** `scripts/plamen_driver.py:41193`, `:44296`, `:44330`,
  `:44366`, `:44964`, `:45196`
- **Direction:** repair/route invalid source locations
- **Count rule:** separate from the two other independently fireable decisions
  hidden in the same validator

#### MG-019 — Inventory production-scope decision

- **Proposed stable ID:** `inventory.production_scope`
- **Owning validator:** `_validate_inventory_evidence`
- **Activation:** same call sites as MG-018
- **Direction:** prevent test/mock/harness-only findings from receiving
  production-body authority; retain review evidence

#### MG-020 — Inventory identifier existence

- **Proposed stable ID:** `inventory.identifier_exists`
- **Alias:** M5a
- **Owning validator:** `_validate_inventory_evidence`
- **Activation:** same call sites as MG-018
- **Direction:** route Low/Info phantom identifiers and flag Medium+ for review

#### MG-021 — Force-by-default PoC obligation

- **Proposed stable ID:** `poc.force_by_default`
- **Definition:** `_validate_poc_contract_for_rows`,
  `scripts/plamen_validators.py:27556`
- **Live pre-receipt call:** `scripts/plamen_validators.py:5228`
- **Direction:** require an executable attempt unless a closed blocker applies
- **Applicability:** verification queue policy across ecosystems; mode-sensitive
- **Failure:** blocks clean verifier completion or creates retry/debt

#### MG-022 — Mechanical PoC execution

- **Proposed stable ID:** `mechanical_poc.execute`
- **Definition:** `run_phase5b_mechanical_verify`,
  `scripts/mechanical_verify.py:2094`
- **Normal driver activation:** `scripts/plamen_driver.py:46733`
- **Late-candidate rerun:** `scripts/plamen_driver.py:21067`
- **Direction:** execute target tests and emit mechanical evidence/successor
  authority
- **Applicability:** EVM, Solana, Aptos, Sui, Soroban, L1 Go, and L1 Rust;
  all modes when enabled

#### MG-023 — Verdict/evidence integrity decision

- **Proposed stable ID:** `verdict.evidence_integrity`
- **Definition:** `_classify_integrity`,
  `scripts/mechanical_verify.py:1796`
- **Live call:** `scripts/mechanical_verify.py:1911`
- **Manifest call chain:** `_write_manifest` invokes `_write_verdict_manifest`
  at `scripts/mechanical_verify.py:1596`
- **Direction:** compute effective evidence tag and successor authority from
  mechanical execution
- **Dead-code correction:** `flip_verdict_on_integrity_downgrade` at
  `scripts/mechanical_verify.py:1878` is not called by production. Documentation
  claiming that live verifier Markdown is flipped is stale.

#### MG-024 — External-assumption assert-side cap

- **Proposed stable ID:** `external_assumption.assert_cap`
- **Definition:** `_external_assumption_cap_applies`,
  `scripts/plamen_validators.py:22705`
- **Consumer:** `_expected_report_index_severities`,
  `scripts/plamen_validators.py:23109`, decision at `:23179`
- **Driver report-index prework:** expected severity map is consumed at sites
  including `scripts/plamen_driver.py:45626`
- **Direction:** destructive cap to Medium
- **Risk:** no gate-specific typed receipt, false-fire measurement, or registry
  record

#### MG-025 — External-assumption demotion veto

- **Proposed stable ID:** `external_assumption.demotion_veto`
- **Alias:** R10/R10.1 demotion-side gate
- **Definition:** `_apply_external_assumption_undemotions`,
  `scripts/plamen_validators.py:28944`
- **Live activation:** `scripts/plamen_driver.py:40014`
- **Direction:** floor to queue severity, stamp unproven-external debt, and
  retain the finding in body
- **Applicability:** Core and Thorough; explicit Light no-op
- **Risk:** no PhaseIO contract or gate registry record

#### MG-026 — Independent-severity challenge

- **Proposed stable ID:** `severity.independent_challenge`
- **Definition:** `_apply_independent_severity_caps`,
  `scripts/plamen_validators.py:28606`
- **Activations:** `scripts/plamen_driver.py:38733`, `:38751`, `:39992`
- **Direction:** flag and route to typed adjudication
- **Documentation correction:** this is no longer an automatic minimum-severity
  cap despite stale “M4 min-cap” prose.

#### MG-027 — External-research citation-gap flag

- **Proposed stable ID:** `external_research.citation_gap`
- **Definition:** `_check_external_research_citation_gaps`,
  `scripts/plamen_driver.py:17636`
- **Live report-index activation:** `scripts/plamen_driver.py:45735`
- **Direction:** telemetry and report-visible Appendix note only
- **PhaseIO:** one of the few related artifacts with a conditional contract,
  `scripts/phase_io_contracts.py:3145+`

#### MG-028 — Post-verify late-candidate reopen

- **Proposed stable ID:** `postverify.late_candidate_reopen`
- **Definition:** `scripts/post_verify_lifecycle.py:71`
- **Activation:** `scripts/plamen_driver.py:20972`
- **Direction:** add candidate and require independent verification/recovery

### 3.4 Report-assembly decisions

#### MG-029 — Mechanical report-index retention reconciliation

- **Proposed stable ID:** `report.index_retention_reconcile`
- **Definition:** `_write_mechanical_report_index`,
  `scripts/plamen_mechanical.py:11132`
- **Activation:** `scripts/plamen_driver.py:45889`
- **Direction:** deterministic finding-retention, status, and severity projection

#### MG-030 — Lossless report deduplication

- **Proposed stable ID:** `report.dedup_lossless_consolidation`
- **Definitions:** `_dedup_report_python`,
  `scripts/plamen_mechanical.py:6689`; `_dedup_data_loss_gate`, `:4231`
- **Activation:** `scripts/plamen_driver.py:46992`
- **Direction:** consolidate aliases only when preservation checks pass
- **Failure:** retain original report when data-loss checks fire

#### MG-031 — Typed report disposition

- **Proposed stable ID:** `report.typed_disposition`
- **Authority build/reconcile:** `scripts/report_disposition_authority.py:528`,
  `:1288`
- **Driver adapter:** `_run_report_disposition_phase_io`,
  `scripts/plamen_driver.py:38838`
- **Live activation:** `scripts/plamen_driver.py:47103`
- **Direction:** typed-only lossless Appendix C relocation
- **Failure:** missing, stale, or tampered authority retains the finding in body

#### MG-032 — Mandatory report reverification

- **Proposed stable ID:** `report.mandatory_reverification`
- **Definitions:** denominator/reconcile/apply in
  `scripts/mandatory_reverification.py:203`, `:719`, `:1052`, `:2330`
- **Driver wrapper:** `scripts/plamen_driver.py:11621`
- **Live activation:** `scripts/plamen_driver.py:47135`
- **Direction:** reopen and require delivery before a final report disposition
  can become clean

#### MG-033 — Report-integrity no-ship authority

- **Proposed stable ID:** `report.integrity_no_ship`
- **Definition:** `_commit_report_integrity_no_ship`,
  `scripts/plamen_driver.py:18889`
- **Clearance path:** `scripts/plamen_driver.py:19060+`
- **Direction:** withhold a clean deliverable while report authority debt remains

## 4. Existing runtime and count budgets

These are code constants, not registry-governed budgets.

### 4.1 Enumeration family

From `scripts/enumeration_gate.py:125-128`:

- Maximum variables per finding: 5
- Maximum co-referencers per variable: 6
- Common-symbol skip threshold: more than 25 referencing functions
- G1/G2 emission cap: 40 candidates per run

From `scripts/enumeration_gate.py:1369`:

- Per-deriver scan/emission cap: 15

Independent 15-candidate pools exist for:

- Critical-asset mover
- Array uniqueness
- Unbounded stored input
- Committed invariant
- Boundary variant
- Symmetric-operation variant

`run_enumeration_gate` claims a bounded sum of `40 + 3×15`, but it also runs
the committed-invariant deriver. Its actual maximum is:

```text
40 + 4×15 = 100
```

The separately invoked boundary and symmetric Gate-V decisions add:

```text
2×15 = 30
```

The accepted-depth deterministic generators can therefore append up to 130
candidates before the M2 axis worker.

### 4.2 Axis matrix

- Hot-function cap: 40
- Risk axes: 6
- Maximum GAP-cell denominator: 240
- There is no registry-owned worker/token budget.
- A `_hot_function_cap_receipt.json` exists, but it is not PhaseIO-bound.

### 4.3 Promotion Gate P

From `scripts/plamen_mechanical.py:5030-5032`:

- Maximum feeder files: 60
- Maximum eligible orphans per feeder: 12
- Maximum eligible orphans per run: 30
- Maximum bytes read per feeder: 64 MiB

Cap hits are written to the shared coverage-shortfall ledger.

### 4.4 Mechanical verification

From `scripts/mechanical_verify.py`:

- Per-test timeout: 180 seconds
- Go race timeout multiplier: 3
- Prewarm build timeout: 5,400 seconds
- Per-finding loop phase budget: 1,800 seconds

The phase budget is not a hard wall:

- Prewarm happens before the phase-loop timer starts.
- The loop checks the budget before starting a test.
- The final test may overrun the remaining budget by up to its own timeout.
- A Go race test can use up to 540 seconds.

A practical bound is therefore at least:

```text
5,400 + 1,800 + 540 = 7,740 seconds
```

No registry-owned aggregate external-process, memory, CPU, or queue-denominator
budget exists.

### 4.5 False-fire budgets

There are no implemented false-fire budgets, named held-out corpora, minimum
denominators, observation windows, breach actions, or adjudicated outcome joins.
The terms occur only in policy prose.

Live runtime can measure firing rate. It cannot determine a false fire without
an independent adjudicated outcome. False-fire compliance must therefore be
computed by the neutral evaluator against held-out decisions, not self-reported
by the gate.

## 5. Failure and degrade behavior

### 5.1 Behavior that is directionally sound

- Enumeration and Gate V generally write `UNKNOWN` or cap-truncation rows to
  `_coverage_shortfalls.json`.
- Accepted-depth postprocessors are journaled and a failed processor writes
  `depth_finalization_human_review.md`.
- Gate P writes provider/cap shortfall records when its seed, feeder, read, or
  harvest path fails.
- Gate P defaults routing errors toward `BODY`.
- Report deduplication retains the original report when preservation fails.
- Typed report disposition retains body findings when authority is missing or
  invalid.

### 5.2 False-clean defects

#### M2 absent graph can become clean zero

`compute_axis_coverage_gaps` at `scripts/enumeration_gate.py:3576`:

- Treats an empty hot-function set as “no gaps.”
- Writes a clean no-hot-functions Markdown stub.
- Returns `[]`.
- Its broad outer exception also returns `[]`.

An absent graph, failed ranking provider, or unhandled parse error can therefore
skip the axis worker as if coverage were complete. This violates the protocol’s
requirement that absent/malformed/failed inputs become `UNKNOWN` or human-review
debt, never `CLEAR`.

#### Symmetric-operation parser drift can become clean zero

The symmetric gate records missing artifacts as provider-unavailable, but a
present non-empty `chain_candidate_pairs.md` that parses zero pairs returns an
empty clean result. This is the zero-harvest-with-nonempty-evidence failure
signature the regex-fragility plan explicitly warns about.

#### Registry failure is currently invisible

Because the registry is never loaded, malformed, missing, expired, or
over-budget records have no runtime effect and produce no debt.

## 6. PhaseIO and authority gaps

Repository searches found no exact PhaseIO contracts for:

- `enumeration_obligations.md`
- `_enumeration_obligations.json`
- `enumeration_gap_receipt.md`
- `_boundary_input_obligations.json`
- `promotion_gate_receipt.md`
- `promotion_routing.md`
- `_hot_function_axes.json`
- `hot_function_axes.md`
- `_hot_function_cap_receipt.json`
- Axis promotion receipts
- Enumgap exploration promotion receipts
- `mechanical_verify_manifest.json`
- `verdict_manifest.json`
- `external_assumption_undemotions.md`
- `_coverage_shortfalls.json`

`material_harm_floor.md` is registered, but the live report path has moved to
typed report-disposition authority. `external_research_gaps.md` has a
conditional report-index prework contract.

Consequences:

- Most mechanical decisions can mutate canonical findings or derived authority
  without the new arm-before-write and checked-commit boundary.
- Gate receipts are not uniformly input-digest-bound.
- Resume can rely on ad hoc Markdown receipts rather than exact typed
  work-unit authority.
- Registry governance cannot prove a gate evaluated the inputs named in its
  record.

The registry implementation must follow the PhaseIO checked-commit repair. A
gate evaluation must arm exact inputs before mutation and commit or quarantine
its outputs atomically.

## 7. Overlap, duplication, and stale architecture

### 7.1 G1 versus Gate V

`compute_variant_gaps` now runs axes 2 and 3 only. G1/G2 exclusively own the
co-reference axis. Documentation still describing the dispatcher as a
three-axis implementation is stale.

Registry treatment:

- G1 obligation and G2 coverage gap are separate records.
- Boundary and symmetric variants are separate records.
- No recursive or duplicate “Gate V axis 1” activation should be registered.

### 7.2 Gate P versus typed lifecycle machinery

Gate P overlaps:

- Finding producer registry
- Inventory reconciliation
- Typed security-obligation lifecycle
- Late-delivery recovery
- Report-index completeness

It still has unique coverage for legacy or unregistered Markdown feeders.
Retiring it now could lose true positives. The safe sequence is:

1. Add typed attribution identifying which Gate-P recoveries were unavailable
   from the structured lifecycle.
2. Replay on held-out runs.
3. Demonstrate zero unique true-positive contribution.
4. Only then consolidate or sunset.

### 7.3 External assumption family

These are three independently fireable decisions:

1. Citation-gap warning
2. Assert-side severity cap
3. Demotion-side R10 floor/veto

They must not be hidden behind a single “Fix B” record.

### 7.4 PoC family

These are distinct:

1. Force-by-default attempt obligation
2. Mechanical execution
3. Evidence-integrity classification

They have different denominators, costs, failure behavior, and authority.

### 7.5 Inventory validator

Location existence, production scope, and identifier existence are three
independently fireable decisions hidden behind one function. They count as three
records.

### 7.6 Dead or superseded gates

- `flip_verdict_on_integrity_downgrade` is not production-active.
- Legacy material-harm-floor logic is superseded on the live final-report path
  by typed report-disposition authority.
- Gate-P Appendix A/C branches are currently unreachable.
- Independent severity is challenge-only, not an automatic cap.

Dead and superseded decisions belong in `SUNSET` or migration notes, not in the
active-gate count.

## 8. Part-0 defect

The predicates reviewed are generally structural and ecosystem-generic.
However, production commentary in
`scripts/plamen_validators.py:27155-27158` contains:

- “the exact <PRIVATE_FINDING_ID> regression”
- “custodied IBT”
- “flagship fund-drain”

This is persisted target/finding-specific post-mortem language. Even though the
executable predicate is generic, it violates Part 0’s prohibition on retaining
specific finding IDs and protocol-specific answer terminology in persistent
methodology/implementation artifacts.

Required remediation:

- Replace with a generic description such as “a prior material-harm
  under-match.”
- Replace the asset-specific term with “custodied asset.”
- Keep fixtures mechanism-generic.
- Registry recurrence evidence must store only aggregate occurrence counts,
  corpus IDs/digests, and review receipts—never finding titles, IDs, locations,
  protocol names, or motivating answers.

## 9. Proposed v2 registry schema

### 9.1 Top-level object

```json
{
  "schema_version": "plamen.mechanical_gate_registry.v2",
  "registry_revision": 1,
  "registry_scope": {
    "included_authorities": [],
    "excluded_control_families": []
  },
  "migration_status": "BASELINING_EXISTING_ACTIVATIONS",
  "activation_inventory": {
    "path": "rules/mechanical-gate-activation-baseline.v1.json",
    "sha256": "<hex>",
    "source_revision": "<revision-or-tree-digest>"
  },
  "seam_taxonomy": [],
  "decision_class_taxonomy": [],
  "direction_taxonomy": [],
  "seam_budgets": [],
  "gate_records": []
}
```

### 9.2 Gate record

Each record should contain:

```json
{
  "gate_id": "stable.dot.separated.id",
  "display_name": "Human-readable generic name",
  "lifecycle_state": "LEGACY_ACTIVE_UNGOVERNED",
  "decision_class": "RECALL_GENERATOR",
  "admission_basis": "RECALL_GENERATOR_M1_M3_VERIFY_DELIVERY",
  "owning_seam": "POST_DISCOVERY",
  "execution_order": 10,
  "activations": [
    {
      "activation_id": "stable.literal.hook",
      "module": "enumeration_gate",
      "symbol": "compute_boundary_input_candidates",
      "hook_id": "accepted_depth.variant_boundary",
      "phases": ["depth"],
      "pipelines": ["sc", "l1"],
      "modes": ["light", "core", "thorough"],
      "ecosystems": ["evm", "solana", "aptos", "sui", "soroban", "daml", "l1_go", "l1_rust"],
      "backends": ["claude", "codex"],
      "runtime_state": "ACTIVE",
      "code_digest": "<hex>"
    }
  ],
  "purpose": {
    "generic_miss_class": "...",
    "part0_result": "PASS"
  },
  "authority": {
    "direction": "GENERATE_ADD_ONLY",
    "can_add": true,
    "can_remove": false,
    "can_lower_severity": false,
    "can_raise_severity": false,
    "can_block_execution": false,
    "monotonicity_claim": "...",
    "invalid_authority_fallback": "RETAIN_AND_FLAG"
  },
  "input_contract": [],
  "output_contract": [],
  "failure_contract": {},
  "runtime_budget": {},
  "release_evidence": {},
  "false_fire_budget": {},
  "overlap_and_consolidation": {},
  "ownership": {},
  "review_and_sunset": {}
}
```

### 9.3 Required activation fields

- Literal activation ID
- Module and symbol
- Stable hook ID
- Owning phase
- Pipeline set
- Mode set
- Ecosystem set
- Backend set
- Runtime state
- Code digest

Use module, symbol, and stable hook ID as identity. Source line numbers belong in
generated evidence, not the durable identity, because harmless edits move them.

### 9.4 Required authority fields

- Direction: generate, reconcile, cap, floor, flag, route, consolidate,
  execution-block, or ship-veto
- Whether it can add, remove, lower, raise, block, or clear
- Monotonicity claim
- Invalid/missing authority fallback
- Exact subject identity and join rules

### 9.5 Required input/output fields

For each input:

- Artifact identity
- Schema version
- Authoritative producer
- Exact/bounded input role
- Identifier/join rule
- Freshness/digest requirement

For each output:

- Artifact identity
- Schema version
- PhaseIO work-unit ID
- Writer authority
- Consumer list
- Conditional-output state when applicable

### 9.6 Failure contract

Every record must state behavior for:

- Absent input
- Malformed input
- Stale input
- Split input
- Duplicate input
- Contradictory input
- Provider failure
- Timeout
- Budget overflow
- Receipt-write failure
- Input mutation during evaluation
- Resume after partial mutation

No condition may convert missing evidence into `CLEAR`.

### 9.7 Runtime budget

Required fields:

- Input bytes
- Input files
- Denominator rows
- Retained rows
- Candidate count
- Wall-clock milliseconds
- External process count
- Worker/token cost, if any
- Overflow action
- Count semantics: exact or lower-bound

### 9.8 False-fire budget

Required fields:

- Metric definition
- Held-out corpus ID and digest
- Minimum adjudicated denominator
- Maximum count
- Maximum rate
- Observation window
- Current evidence receipt
- Breach action

Zero observed fires on one corpus is not a universal zero budget.

### 9.9 Ownership and review

- Component owner
- Implementer
- Independent reviewer
- Reviewer must differ from implementer
- Review date
- Review receipt/digest
- Sunset owner
- Retirement criteria
- Exception approver and hard expiry, when applicable

Existing gates should initially use `LEGACY_ACTIVE_UNGOVERNED`; do not invent
reviewers or M1-M4 evidence.

## 10. Activation parity and static ratchet

Add a strict registry loader and a checked activation manifest.

### 10.1 Production activation API

Every governed call must pass a literal stable ID through a central API, for
example:

```python
evaluate_registered_gate(
    "enumeration.variant_boundary",
    context=...,
    evaluator=...,
)
```

or:

```python
record_registered_gate(
    gate_id="enumeration.variant_boundary",
    result=...,
)
```

Do not allow dynamically constructed IDs.

### 10.2 Static AST lint

The lint must reject:

- Production gate activation with no registry record
- Active/shadow registry record with no production activation
- Direct call to a registered decision symbol outside the wrapper
- Dynamically constructed gate IDs
- Duplicate gate or activation IDs
- Invalid state/seam/mode/ecosystem/backend
- Activation code-digest drift without reopened review
- Output artifacts missing PhaseIO registration
- ACTIVE gate with no owner or independent reviewer
- Expired exception still runtime-active
- Count/baseline/release equation mismatch
- Part-0-prohibited metadata

### 10.3 Static inventory artifact

Generate an immutable activation baseline containing:

- Gate ID
- Activation ID
- Module
- Symbol
- Hook ID
- Current line as non-authoritative evidence
- Pipeline/mode/ecosystem/backend
- Code digest

The canonical registry cites the artifact path, SHA-256, and source-tree
revision/digest.

### 10.4 Why source-text grep is insufficient

One dispatcher can hide many independently fireable predicates, while aliases
and dead functions can make grep overcount. The ratchet must understand literal
activation IDs and decision identity, not filenames or words containing
“gate.”

## 11. Runtime enforcement

### 11.1 Execution receipts

Each evaluation emits a typed receipt containing:

- Registry version and digest
- Gate and activation IDs
- Run ID
- Exact input identities and digests
- Exact or lower-bound denominator
- Eligible count
- Fired count
- No-fire count
- Unknown count
- Truncated count
- Runtime and external-process cost
- Output identities and digests
- State and expiry
- Failure/debt rows

Receipts should be consolidated into a typed gate-execution ledger with bounded
human-readable projection.

### 11.2 Atomic mutation

The gate transaction must:

1. Resolve the PhaseIO contract.
2. Arm and digest exact inputs.
3. Evaluate under the registry budget.
4. Stage outputs.
5. Revalidate inputs.
6. Atomically commit or quarantine outputs.
7. Publish the execution receipt.

This depends on the shared PhaseIO checked-commit repair. Post-hoc validation
followed by unconditional artifact recording is not authority.

### 11.3 Registry corruption

At runtime:

- CI, packaging, and release validation hard-fail an invalid registry.
- Existing grandfathered add-only gates may continue in migration-safe mode,
  but must emit governance debt.
- Destructive gates fail recall-open: preserve upstream severity/disposition
  and flag review.
- Unknown new activations default to non-runtime/shadow.
- Missing registry authority must never become a clean no-fire.

### 11.4 Overflow handling

Where possible:

1. Enumerate and bind the exact denominator.
2. Select a stable bounded shard.
3. Persist all omitted identities in a durable pending backlog.
4. Route the remainder to the next run or human review.

When exact enumeration is not possible, record a lower bound and samples. A cap
or timeout yields `UNKNOWN_REMAINDER`, never `CLEAR`.

### 11.5 False-fire breach

- Precision/destructive gate breach: move to shadow and preserve upstream
  authority.
- Add-only generator breach: retain bounded verification and durable overflow;
  do not silently disable recall.
- Permanent disable or narrowing requires owner approval and measured recall
  tradeoff.

## 12. Migration and baseline sequence

1. Freeze a source-tree digest. The working tree is intentionally dirty, so a
   commit alone is not enough for the first forensic baseline.
2. Approve the registry scope and exclusion boundary.
3. Generate the activation inventory.
4. Have an independent reviewer reconcile the inventory against the driver,
   gate modules, phase contracts, and documentation.
5. Populate existing records as `LEGACY_ACTIVE_UNGOVERNED`.
6. Keep all new ACTIVE/SHADOW transitions blocked.
7. Have the human system owner approve seam ceilings in a separate prior
   revision.
8. Add typed shadow receipts without changing live behavior.
9. Demonstrate receipt and behavior parity.
10. Register PhaseIO work units and move mutations behind checked commit.
11. Wrap activations one seam at a time.
12. Enable activation-parity lint.
13. Enable runtime count/cost/overflow enforcement.
14. Promote records only after fixture-first, independent review, and held-out
    evidence.
15. Consolidate or sunset only with recall-parity, subsumption, and unique-TP
    evidence.

Do not:

- Set seam ceilings equal to the current count and call that prior approval.
- Invent false-fire thresholds.
- Treat the motivating audit as held-out evidence.
- Infer owner/reviewer identities from commit authorship.
- Retire Gate P before proving no unique legacy-Markdown recoveries.

## 13. Fixture and validation matrix

### 13.1 Schema

- Unknown top-level field
- Unknown gate field
- Duplicate JSON keys
- Duplicate gate ID
- Duplicate activation ID
- Invalid/nonfinite numbers
- Invalid seam
- Invalid state transition
- Bad direction/decision class
- Missing input/output schema
- Owner equals reviewer
- Missing independent reviewer for ACTIVE
- Expired exception remains active
- Count equation mismatch
- Baseline/addition/release set overlap
- Release ID absent from baseline
- Part-0-prohibited metadata

### 13.2 Activation parity

- Code activation missing registry record
- Registry ACTIVE record missing code activation
- Direct-call bypass
- Dynamic gate ID
- Symbol renamed
- Hook moved
- Code digest drift
- Mode/ecosystem/backend drift
- Dead function incorrectly counted active
- Two independently fireable decisions hidden behind one dispatcher

### 13.3 Per-gate semantics

For every record:

- Positive fire
- Precision no-fire
- Empty legitimate denominator
- Absent provider
- Malformed input
- Stale input
- Split input
- Duplicate input
- Contradictory input
- Identifier-prefix collision
- Mixed-case identifier collision
- Provider throws
- Output write throws
- No false clean

### 13.4 Budgets

- Exactly N rows
- N+1 overflow
- Exact denominator
- Lower-bound denominator
- Stable retained shard
- Durable omitted backlog
- Input-byte cap
- File-count cap
- Candidate cap
- Wall-clock timeout
- External-process cap
- Worker/token cap
- Overflow appears in assurance report

### 13.5 Transaction and resume

- Crash before arm
- Crash after arm
- Crash after mutation but before receipt
- Crash after receipt staging
- Input bytes change during evaluation
- File-set drift
- Run-ID mismatch
- Registry digest changes on resume
- Idempotent replay
- No double fire
- No double candidate append
- Concurrent inventory writers
- Quarantined output cannot become downstream authority

### 13.6 Product matrix

- SC and L1
- Light, Core, and Thorough
- EVM, Solana, Aptos, Sui, Soroban, DAML, L1 Go, L1 Rust
- Claude and Codex backends
- Toolchain available/unavailable
- Explicit N/A receipt rather than absent execution

### 13.7 Cross-platform and filesystem

- Windows drive-relative path
- Windows case-insensitive collision
- POSIX case-sensitive sibling
- Symlink
- Junction
- Alternate data stream or non-regular file
- Long path
- Path escape
- Clean package install
- Source archive install
- Missing optional dependency

### 13.8 Held-out measurement

- Motivating regression is scored as regression-only
- Independent held-out corpus is digest-bound
- Neutral evaluator joins each fire to adjudicated outcome
- False-fire denominator meets the declared minimum
- Recall and precision are both reported
- Fragmentation and severity deltas are reported
- No gate self-certification

## 14. Required test replacement

`scripts/test_post_audit_gate_budget.py` should be replaced, not merely extended.
Its exact-empty assertions make a successful registry migration fail.

The replacement suite should validate:

- Strict v2 schema
- Populated baseline
- Exact activation parity
- Balanced seam counts
- No ungoverned new activation
- Runtime/shadow state behavior
- Expiry
- Owner/reviewer independence
- Receipt and PhaseIO coverage
- Part-0 cleanliness

## 15. Final recommendation

Build R0-8e after the shared PhaseIO checked-commit boundary is repaired.
Implement it in this order:

1. Scope definition and v2 schema
2. Generated activation baseline
3. Independent baseline review
4. Populated legacy-active records
5. Shadow execution receipts
6. PhaseIO binding and atomic mutation
7. Static activation ratchet
8. Runtime count/cost/overflow budgets
9. Held-out false-fire measurement
10. Measured consolidation

The registry will materially improve robustness, recall preservation, precision,
and anti-bloat only if it governs real activations and real receipts. Populating
the current JSON without activation parity, PhaseIO binding, and runtime
measurement would create a stronger illusion of control without changing the
pipeline.
