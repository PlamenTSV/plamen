# Plamen Exploration / Enumgap PhaseIO Transaction Closure Receipt

Date: 2026-07-24T22:35:11.6393796+03:00  
Repository: `<LOCAL_USER_ROOT>\plamen-codex-implementation`  
Branch: `codex/recall-app-benchmark-r10_1`  
Base commit: `67a0f85adc7a8169d79a286908b00bef7adb764a`  
Wave disposition: **IMPLEMENTATION CLOSED; PINNED AND WIDENED LANES GREEN; SEPARATE INVENTORY INTEGRATION BLOCKER ESCALATED**

## 1. Scope and non-claims

This receipt closes the bounded PhaseIO/transaction wave for:

1. exploration-clear compilation and repair;
2. exploration-skeptic and enumgap MODEL production;
3. enumgap planning, reconciliation, registry consumption, and inventory promotion;
4. crash, stale-output, raw-byte, producer-lineage, CAS, idempotence, and concurrency behavior for those paths.

It does **not** claim:

- that the entire dirty program tree is globally releasable;
- that the deferred unrelated-locus semantic-clear redesign was implemented;
- that the two requested Thorough Claude audits were started;
- that the audit benchmark has measured a recall or precision delta;
- that any commit, merge, push, installation, or cutover was performed.

The two Thorough Claude audit runs remain final-program acceptance tasks. Starting them before all implementation waves and global smoke are green would contaminate the comparison and waste the preserved baselines.

## 2. Closed invariants

### 2.1 Exploration-clear ownership graph

The former retroactive production binder is retired. Production now uses distinct immutable units:

```text
exploration_clear/alias_authority
    -> exploration_clear/initial_compile.clean
       or exploration_clear/initial_compile.repair
    -> exploration_clear/repair_arm
    -> exploration_clear/worker.0001            [MODEL]
    -> exploration_clear/repair_terminal
       or exploration_clear/repair_reconcile
```

The implementation enforces:

- proposal-only treatment for stale or unowned repair artifacts;
- exact same-run AttemptArm plus ACTIVE/OUTPUT_COMMITTED MODEL authority before consuming a repair response;
- visible PhaseIO debt that blocks semantic CLEAR/ADD;
- quarantine of stale attempts, responses, and outputs;
- retryable prelaunch interruption without consuming the attempt;
- strict semantic re-derivation on resume, so re-hashing altered JSON cannot change the result;
- raw-byte binding of project loci that actually exist and are cited by the response;
- idempotent terminal failure and successful reconciliation paths.

`_record_exploration_clear_io` remains only as a retired compatibility definition. There is no live production caller.

### 2.2 Backend-neutral MODEL production

`exploration_skeptic/model` and `enumgap_exploration/model` now use exact prelaunch/commit contracts for both Claude and Codex paths. Tests cover:

- Claude and Codex;
- LF and CRLF source bytes;
- exact raw-byte equality;
- stale and uncommitted proposals;
- an explicitly prebound DRIVER empty-stub path when enumgap has no obligations.

### 2.3 Enumgap planning and reconciliation

Planning and reconciliation now:

- arm before deterministic derivation;
- validate exact inputs immediately before and after writes;
- commit only when the input snapshot remains CAS-clean;
- require an exact MODEL or exact empty-stub producer;
- expose debt instead of consuming a false-complete disposition.

The finding-producer registry now requires the exact ACTIVE producer lineage for the worklist, output, reconciliation receipt, and residual. Deleting ledger units, retaining bytes, or re-hashing artifacts cannot silently dispose of work.

### 2.4 Promotion transaction

Enumgap-to-inventory promotion now has:

- a DRIVER PhaseIO wrapper;
- exact source/reconciliation/residual input bindings;
- an inventory MERGE event with before/after raw digests and structural finding IDs;
- a shared cross-process inventory lock;
- a durable append plan and commit receipt;
- strict UTF-8 decoding;
- exact-prefix proof;
- CAS rejection if the inventory changes outside the armed transaction;
- atomic replacement;
- current-byte validation of output, inventory, promotion receipt, and commit;
- idempotent replay;
- visible debt for lock, decode, lineage, CAS, append, receipt, or finding-record failure.

The low-level promoter is invoked from production only inside `_promote_enumgap_exploration_transaction`.

## 3. Fixture-first evidence

### 3.1 Frozen red checkpoint

Before production implementation, the 12-file pinned lane had:

```text
114 passed, 16 failed
```

The failures represented the intended defects:

- retrobinding/unowned exploration artifacts;
- stale response adoption;
- PhaseIO debt still permitting ADD;
- re-hashed semantic invention;
- prelaunch attempt consumption;
- collapsed exploration unit ownership;
- uncommitted enumgap output consumption;
- absent backend/raw exact MODEL contracts;
- plan/reconcile derive-after-arm drift;
- absent empty-stub producer;
- registry disposal through uncommitted lineage.

### 3.2 Pinned final lane

Exact command:

```powershell
python -m pytest -q scripts/test_exploration_clear_lifecycle_p0_f.py scripts/test_exploration_clear_driver_integration_p0_f.py scripts/test_exploration_alias_authority_p0_f.py scripts/test_enumgap_disposition_p0_fi.py scripts/test_enumgap_driver_integration_p0_fi.py scripts/test_enumgap_registry_adversarial_review_p0_fi.py scripts/test_enumgap_emitted_action_delivery_p0_i.py scripts/test_enumgap_emitted_action_delivery_adversarial_review_p0_i.py scripts/test_finding_producer_registry_p0_012.py scripts/test_exploration_skeptic_wiring.py scripts/test_enumgap_exploration_routing.py scripts/test_enumgap_separator_glue.py
```

Result:

```text
137 passed in 33.78s
```

### 3.3 Widened semantic dependency lane

The widened lane selected every test file referring to `enumeration_gate`, `validated_enumgap`, `exploration_clear`, or `enumgap_exploration`.

Exact selection and command:

```powershell
$files = rg -l "enumeration_gate|validated_enumgap|exploration_clear|enumgap_exploration" scripts -g "test_*.py" | Sort-Object
python -m pytest -q $files
```

Final confirmation result:

```text
494 passed in 212.66s
```

One first-pass red was classified as a fixture migration from the already-landed exact-security-alias change: production retains all mandatory security obligations and now calls the bounded remainder `ATTENTION_OPTIONAL_REPAIR_MAX_ITEMS`. The stale test expected the old truncating caps. Only the assertion was migrated, then the complete 494-test lane was replayed green.

### 3.4 Surrounding PhaseIO, driver, and end-to-end lanes

```text
phase_io_contract_p0_ae                         25/25
phase_io_commit_authority_p0_ae                40/40
phase_commit_controller_p0_ac                  24/24
phase_commit_structural_ratchet +
  arm_before_trust_methodology                  4/4
artifact_ledger_v2_p0_ae                       17/17
runtime_debt_consumption_authority               9/9
worker_prelaunch_matrix                        18/18
worker_execution_receipts                      32/32
driver_failure_scenarios                       74/74
e2e_integration                                19/19
```

The runtime-debt lane initially had three stale positive fixtures that wrote output before input arming. The existing arm-before-trust substrate correctly quarantined those outputs with `INPUT_RECEIPT_NOT_CLEAN` and `OUTPUT_PRESTATE_INVALID`. The positive fixtures were migrated to bind -> write -> commit. Negative unowned/pre-ledger cases were preserved.

Static checks:

```text
python -m py_compile [all wave production and test files]  PASS
git diff --check [all wave production and test files]      PASS
retired exploration retrobinder production callers         0
```

## 4. Separate integration blocker discovered by blast-radius testing

`scripts/test_driver_smoke.py` completed:

```text
4 passed, 7 failed in 352.88s
```

All seven red scenarios were masked at `inventory_chunk_a` by:

```text
InventoryReemitError: findings_inventory.md is missing or unsafe
```

Evidence indicates a product integration regression outside this wave:

- `_record_inventory_reconciliation_phase_io_named()` attempts additive re-emission during chunk reconciliation;
- `inventory_reemit_authority._build_intent()` requires the aggregate `findings_inventory.md`;
- the aggregate does not yet exist at that pre-aggregate chunk boundary.

An additional inventory-owner probe produced:

```text
27 passed, 2 failed
```

The two assurance-refresh failures report:

```text
scratchpad:findings_inventory.md: semantic input binding is PRODUCER_AUTHORITY_MISMATCH
```

Therefore the inventory cutover owner must resolve both:

1. the pre-aggregate re-emission ordering/empty-prestate contract; and
2. the final-refresh producer handoff.

These failures are not attributed to the exploration/enumgap PhaseIO implementation, but they block a truthful global-smoke or release-ready claim.

## 5. Explicit deferred limits

### 5.1 Unrelated-locus negative closure

The current semantic clear logic can still accept a syntactically valid but unrelated `file:L` locus under the existing positive-locus semantics. The parent explicitly removed that redesign from this wave.

A next-wave fixture should prove that:

- a terminal `CLEAR` citing only an unrelated source location cannot close the target denominator;
- the result is visible semantic debt, not a negative finding disposition;
- a matching canonical identity and target/source-fact relationship can close it;
- LF/CRLF and alias spellings cannot change the relationship.

This is a genuine semantic-authority issue, not solved by adding more hashes.

### 5.2 Missing project-locus facts

This wave binds raw bytes for an existing cited project locus. An explicitly absent cited path is prevented from authorizing a clear, but there is not yet a first-class immutable “path absent from exact project snapshot” fact. A future snapshot-manifest binding would make absence replayable without relying on current filesystem state.

### 5.3 Lifecycle-wide transaction plan

The repair plan is durable and the ledger lock serializes the lifecycle. Final multi-output reconciliation is deterministic and replay-checked, but there is no separate lifecycle-wide plan file covering every exploration-clear output as one physical multi-file atomic replace. Current behavior is haltless and resumable rather than physically atomic across all files.

## 6. Source manifest

The hash below is SHA-256 over the UTF-8 manifest lines in the exact order shown, each formatted as `<file-sha256><two spaces><relative-path><LF>`.

Manifest SHA-256:

```text
e617dae8475d98423b6d757dfb8dcded041e984f51b5e85be3e640183cd10492
```

```text
593a0aff2a075ee0ccec004ce23b56d1fb338fb3079560cc25a7e29daa37534b  scripts/phase_io_contracts.py
bfc46a55d19375ef74a078f42bd1b330a989af8a90d0b1761d1eae241393a9c1  scripts/plamen_driver.py
acf419ee4bd3c75285a48cc550df06c85b55520c266f2c78cf4b2d156e48a3fe  scripts/finding_producer_registry.py
0a7a1cd4542a9d0aae11668a874aacf9b426f570df6548345595301cdb9cffed  scripts/enumeration_gate.py
004bfaa32bc636bfbd2cb8da2394b036c14a1492b226e178b8883a448280741e  scripts/test_exploration_clear_driver_integration_p0_f.py
221a9d20f62db9da97579a633b66500924ca561347e4fcd6355ae272fb61caa8  scripts/test_enumgap_driver_integration_p0_fi.py
e61532a7d1295c46c083fc65189ba8e4e6018d7523e6deaef3243713df67358e  scripts/test_enumgap_registry_adversarial_review_p0_fi.py
ea5e16a601a6f0ade1c886e89ee235346d1188318eda262ab73fe53d4b4acf86  scripts/test_enumgap_emitted_action_delivery_p0_i.py
070bf39cdf8f5f949eba9278ae091a3a967d7e6b45599c49b6f2680362b0a3e7  scripts/test_enumgap_emitted_action_delivery_adversarial_review_p0_i.py
5852e9c6c268a42271f3e616742d71366cb5f5e3d05823de5997c402ef5acd19  scripts/test_enumgap_exploration_routing.py
f27615bfd82c669ce114c7e440dafac1dd48aa8c1fe9b5e78fa16088f4800fa6  scripts/test_runtime_debt_consumption_authority.py
081eaf21512486867522aa3734022820bca4b70c3abc3e9d6feeab307b45efa7  scripts/test_coverage_shortfall_receipts.py
```

## 7. Acceptance verdict

The exploration-clear / enumgap / promotion transaction wave is worthy of retention and subsequent adversarial review. Its changes directly address found-then-lost and false-safe application failures by converting semantic consumption from “artifact exists” into exact producer, exact run, exact bytes, exact transition, and replayable transaction authority.

It cannot, by itself, establish a recall improvement. That requires the governed held-out benchmark and the two requested Thorough Claude audits after all global implementation and smoke blockers are closed. No result from the <PRIVATE_REGRESSION_TARGET> regression corpus should be treated as independent recall evidence.

No commit or push was performed.
